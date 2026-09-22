/**
 * CesSpace ARC — RC-06 Task 7: Local Operator CLI & Standalone Offline Verifier
 *
 * Test suite verifying:
 * - `arc audit status` reports an accurate local summary and mutates nothing.
 * - `arc audit verify` authenticates a multi-segment store offline using PUBLIC
 *   keys only, across compressed archives and the active segment, and fails
 *   closed on tampered primary evidence, broken chains, corrupt gzip, bad
 *   checkpoint signatures, wrong keys and bad receipts.
 * - `arc audit inspect` streams a bounded, sequence-ordered, cross-segment
 *   record window and rejects malformed ranges and over-limit requests.
 * - `arc audit export` writes a deterministic directory bundle whose manifest
 *   digests recompute, and which carries no private key material.
 * - The verifier and exporter never mutate the source store, and never read a
 *   private signing key.
 * - Source evidence that changes underneath a verify/export fails rather than
 *   producing a successful mixed snapshot.
 *
 * Negative controls owned by this task, and by no other: RC06-NEG-105..108.
 * This suite claims nothing from a neighbouring task's range: Task 8 owns
 * RC06-NEG-100..104, Task 1 owns 01..29, Task 2 30..39 and 46..47, Task 3
 * 48..63, Task 4 64..83, Task 5 84..99, Task 6 40..45.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ANCHOR_IDEMPOTENCY_HEADER,
  MAX_EXPORT_BYTES,
  METADATA_FILENAME,
  MAX_INSPECT_RECORDS,
  assertExportWithinBudget,
  exportEvidenceBundle,
  inspectRetainedRecords,
  listRetainedSegmentSources,
  readOfflineAuditStatus,
  validateInspectRange,
  verifyEvidenceBundle,
  verifyOfflineStore,
} from '../packages/audit/dist/index.js';
import { createTestAuditRuntime } from '../packages/audit/dist/internal/runtime-testing.js';
import {
  enablePrivateKeyLoadProbe,
  getPrivateKeyLoadCount,
} from '../packages/audit/dist/internal/key-authority.js';
import { signTestAnchorReceipt } from '../packages/audit/dist/internal/anchor-testing.js';
import { EXIT_FAILURE, EXIT_OK, EXIT_USAGE, runCli } from '../apps/cli/dist/index.js';
import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { SecurityKernel, WorkspaceRegistry } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { DeviceTrustStore, deriveSpkiPin } from '../packages/auth/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import net from 'node:net';
import https from 'node:https';

/* -------------------------------------------------------------------------- *
 * Harness
 * -------------------------------------------------------------------------- */

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENDPOINT = 'https://anchor.example.invalid/v1/anchor';

let tempRoot;
let fixtureCounter = 0;
/** The ephemeral mTLS PKI the remote NEG-105 fixture is built on. */
let pki = null;

before(() => {
  tempRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task7-')));
  assert.equal(
    hasOpenssl(),
    true,
    'RC06-NEG-105 drives a real mTLS connection and requires the platform openssl binary',
  );
  pki = createTestPki(path.join(tempRoot, 'pki'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** A fresh, private directory below the suite's temp root. */
function newRoot(label) {
  fixtureCounter += 1;
  const dir = path.join(tempRoot, `${label}-${fixtureCounter}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  return dir;
}

/** Generates an Ed25519 keypair as 0600 PKCS#8 / SPKI PEM files. */
function writeKeyPair(dir, name) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const signingKeyPath = path.join(dir, `${name}-signing.pem`);
  const publicKeyPath = path.join(dir, `${name}-public.pem`);
  fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    mode: 0o600,
  });
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
    mode: 0o600,
  });
  fs.chmodSync(signingKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o600);
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKey,
    signingKeyPath,
    publicKeyPath,
    fingerprint: crypto.createHash('sha256').update(spkiDer).digest('hex'),
  };
}

/** A production-shaped audit config for a fresh fixture. */
function makeAuditConfig(label, { anchor = false } = {}) {
  const root = newRoot(label);
  const keyDir = path.join(root, 'keys');
  const checkpoint = writeKeyPair(keyDir, 'checkpoint');
  const anchorMaterial = anchor ? writeKeyPair(keyDir, 'anchor') : null;
  const config = {
    directory: path.join(root, 'audit'),
    signingKeyPath: checkpoint.signingKeyPath,
    publicKeyPath: checkpoint.publicKeyPath,
  };
  if (anchorMaterial !== null) {
    config.anchorEndpoint = ENDPOINT;
    config.anchorReceiptPublicKeyPath = anchorMaterial.publicKeyPath;
  }
  return {
    root,
    config,
    checkpoint,
    anchorMaterial,
    auditDir: config.directory,
    keyDir,
  };
}

/** A valid persistent record candidate, minus the persistence-owned fields. */
function sampleRecordCandidate(overrides = {}) {
  return {
    eventId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    actor: {
      clientId: 'test-client',
      clientType: 'admin',
      deviceId: 'a'.repeat(32),
      sessionId: 'b'.repeat(64),
    },
    target: {
      workspaceId: 'ws-test',
      workspacePath: '',
      workspaceRootHash: 'c'.repeat(64),
    },
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { path: 'test.txt' },
      payloadHash: 'd'.repeat(64),
    },
    policy: { decision: 'ALLOW', ruleId: 'rule-test-01', evaluationDurationMs: 1.5 },
    execution: {
      status: 'SUCCESS',
      startTime: '2026-09-21T00:00:00.000Z',
      endTime: '2026-09-21T00:00:00.010Z',
      durationMs: 10,
    },
    ...overrides,
  };
}

/**
 * A transport that mints a genuine receipt for whichever checkpoint it is asked
 * to anchor. The idempotency header carries the checkpoint hash, so the receipt
 * is bound to real checkpoint evidence without the test needing to know it in
 * advance.
 */
function acknowledgingTransport(fixture, privateKey) {
  return async (request) => {
    const checkpointHash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
    const receipt = signTestAnchorReceipt(
      {
        version: 1,
        storeId: fixture.storeId,
        receiptId: crypto.randomUUID(),
        checkpointHash,
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
        anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
      },
      privateKey,
    );
    return { statusCode: 200, body: Buffer.from(JSON.stringify(receipt), 'utf8') };
  };
}

/**
 * Builds a real, production-shaped store by running the real runtime, then
 * closing it. `rotateAt` forces genuine rotations, which seal real signed
 * checkpoints and produce real `.jsonl.gz` archives.
 */
async function buildStore(fixture, options = {}) {
  const { records = 3, rotateAt = [], hooks, checkpointHooks } = options;

  // An anchor-enabled store gets a transport that mints genuine receipts. The
  // closure reads the fixture at call time, which is after the store metadata —
  // and therefore the storeId every receipt must carry — has been written.
  const anchorHooks =
    fixture.anchorMaterial === null
      ? undefined
      : {
          sleep: async () => {},
          transport: acknowledgingTransport(fixture, fixture.anchorMaterial.privateKey),
        };

  const runtime = await createTestAuditRuntime(fixture.config, {
    ...(hooks === undefined ? {} : { hooks }),
    ...(checkpointHooks === undefined ? {} : { checkpointHooks }),
    ...(anchorHooks === undefined ? {} : { anchorHooks }),
  });
  fixture.storeId = JSON.parse(
    fs.readFileSync(path.join(fixture.auditDir, METADATA_FILENAME), 'utf8'),
  ).storeId;

  for (let index = 1; index <= records; index += 1) {
    await runtime.appendRecord(sampleRecordCandidate());
    if (rotateAt.includes(index)) await runtime.store.rotateNow('SIZE_THRESHOLD');
  }

  await runtime.close();
  return fixture;
}

/** Every file below `dir`, with the bytes-level identity the proofs compare. */
function snapshotTree(dir) {
  const entries = new Map();
  const walk = (current, prefix) => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const rel = `${prefix}${entry.name}`;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full, `${rel}/`);
        continue;
      }
      const stats = fs.lstatSync(full);
      entries.set(rel, {
        size: stats.size,
        mode: stats.mode & 0o777,
        sha256: crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex'),
      });
    }
  };
  walk(dir, '');
  return entries;
}

/** Asserts two snapshots are byte-for-byte and mode-for-mode identical. */
function assertSnapshotUnchanged(before, after, label) {
  assert.deepEqual(
    [...after.keys()].sort(),
    [...before.keys()].sort(),
    `${label}: file set changed`,
  );
  for (const [name, entry] of before) {
    assert.deepEqual(after.get(name), entry, `${label}: ${name} changed`);
  }
}

function assertThrowsWithCode(fn, codes) {
  const expected = Array.isArray(codes) ? codes : [codes];
  assert.throws(fn, (err) => {
    assert.ok(
      expected.includes(err.code),
      `expected error code one of [${expected.join(', ')}], got ${err.code}: ${err.message}`,
    );
    return true;
  });
}

async function assertRejectsWithCode(promise, codes) {
  const expected = Array.isArray(codes) ? codes : [codes];
  await assert.rejects(promise, (err) => {
    assert.ok(
      expected.includes(err.code),
      `expected error code one of [${expected.join(', ')}], got ${err.code}: ${err.message}`,
    );
    return true;
  });
}

/** Runs the CLI in-process, capturing stdout and stderr separately. */
async function run(argv, dependencies = {}) {
  let out = '';
  let err = '';
  const exitCode = await runCli(argv, {
    stdout: (text) => {
      out += text;
    },
    stderr: (text) => {
      err += text;
    },
    env: {},
    ...dependencies,
  });
  return { exitCode, out, err };
}

/** Runs one `arc audit` command with the fixture's public keys. */
function runAudit(fixture, args, extra = []) {
  return run(['audit', ...args, '--dir', fixture.auditDir, ...extra]);
}

function verifyArgs(fixture) {
  const args = ['--checkpoint-key', fixture.checkpoint.publicKeyPath];
  if (fixture.anchorMaterial !== null) {
    args.push('--anchor-key', fixture.anchorMaterial.publicKeyPath);
  }
  return args;
}

/** The multi-segment fixture: a real compressed archive plus an active segment. */
async function multiSegmentFixture(label) {
  const fixture = makeAuditConfig(label);
  await buildStore(fixture, { records: 5, rotateAt: [3] });
  return fixture;
}

/* -------------------------------------------------------------------------- *
 * Remote mTLS fixture (RC06-NEG-105)
 * -------------------------------------------------------------------------- */

/** JSON-RPC "Method not found": the unknown-tool refusal, local and remote. */
const METHOD_NOT_FOUND = -32601;
const PUBLIC_HOSTNAME = 'localhost';

/** A free TCP port, obtained by binding and releasing port 0. */
async function freePort() {
  return await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/**
 * Starts a REAL remote-mode server over real mTLS, with a real durable audit
 * runtime, so RC06-NEG-105 is exercised on the production remote call path
 * rather than against a stand-in.
 */
async function startRemoteFixture(tag) {
  const dir = newRoot(`remote-${tag}`);
  const workspaceDir = path.join(dir, 'ws');
  fs.mkdirSync(workspaceDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), 'line1\n');

  const client = {
    certPath: pki.clientCertPath,
    keyPath: pki.clientKeyPath,
    pin: deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8')),
  };
  const storePath = path.join(dir, 'devices.json');
  const trustStore = DeviceTrustStore.createEmpty();
  trustStore.enrollDevice({
    clientId: 'agent-alpha',
    clientType: 'claude-code',
    pin: client.pin,
    displayLabel: 'alpha-laptop',
  });
  trustStore.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);

  const audit = makeAuditConfig(`remote-audit-${tag}`);
  const port = await freePort();
  const registry = new WorkspaceRegistry();
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    new AuditLogger(),
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'remote',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      audit: audit.config,
      remote: {
        bindHost: '127.0.0.1',
        port,
        publicHostname: PUBLIC_HOSTNAME,
        serverCertificatePath: pki.serverCertPath,
        privateKey: { kind: 'file', path: pki.serverKeyPath },
        clientCaPaths: [pki.trustedCaCertPath],
        trustStorePath: storePath,
      },
    },
  );
  await server.start();
  return { server, port, client, auditDir: audit.auditDir, checkpoint: audit.checkpoint };
}

/** One real HTTPS request over mTLS. */
function remoteRequest(fixture, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port: fixture.port,
        method: 'POST',
        path: '/mcp',
        servername: PUBLIC_HOSTNAME,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(fixture.client.certPath),
        key: fs.readFileSync(fixture.client.keyPath),
        headers: {
          Host: PUBLIC_HOSTNAME,
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Extracts the JSON-RPC payload from a Streamable HTTP response body. */
function responsePayload(response) {
  const trimmed = response.body.trim();
  if (trimmed.startsWith('{')) return JSON.parse(trimmed);
  const dataLine = trimmed.split('\n').find((line) => line.startsWith('data:'));
  assert.ok(dataLine !== undefined, `no JSON-RPC payload in: ${trimmed.slice(0, 200)}`);
  return JSON.parse(dataLine.slice('data:'.length).trim());
}

/** Performs the tokenless `initialize` handshake over mTLS. */
async function initializeRemoteSession(fixture) {
  const response = await remoteRequest(
    fixture,
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'rc06-t7', version: '1.0.0' },
      },
    }),
  );
  assert.equal(response.status, 200, `initialize: ${response.status} ${response.body}`);
  return {
    sessionId: response.headers['mcp-session-id'],
    token: response.headers['arc-session-token'],
  };
}

function remoteSessionHeaders(session) {
  return { 'Mcp-Session-Id': session.sessionId, Authorization: `Bearer ${session.token}` };
}

/** One authenticated remote `tools/call`. */
function remoteToolCall(fixture, session, name, args = {}) {
  return remoteRequest(
    fixture,
    JSON.stringify({
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: { name, arguments: args },
    }),
    remoteSessionHeaders(session),
  );
}

/** The remote advertised tool catalog. */
async function remoteToolsList(fixture, session) {
  const response = await remoteRequest(
    fixture,
    JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list' }),
    remoteSessionHeaders(session),
  );
  const payload = responsePayload(response);
  assert.equal(payload.error, undefined, response.body);
  return payload.result.tools;
}

/**
 * Rewrites a file inside a bundle AND repairs its manifest entry.
 *
 * Tampering tests must reach the rule under test. Editing a bundled file without
 * repairing the manifest only ever proves the digest check fires, which is a
 * weaker assertion than "this binding rule is enforced".
 */
function rewriteBundleFile(bundleDirectory, relativePath, contents) {
  const full = path.join(bundleDirectory, relativePath);
  fs.writeFileSync(full, contents);
  const manifestPath = path.join(bundleDirectory, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const raw = fs.readFileSync(full);
  manifest.files[relativePath] = {
    sha256: crypto.createHash('sha256').update(raw).digest('hex'),
    bytes: raw.byteLength,
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);
}

/* -------------------------------------------------------------------------- *
 * Suite
 * -------------------------------------------------------------------------- */

describe('CesSpace ARC — RC-06 Task 7: Local Operator CLI & Standalone Offline Verifier', () => {
  /* ====================================================================== *
   * 1. `arc audit status`
   * ====================================================================== */

  describe('1. arc audit status', () => {
    test('RC06-T7-REG-01: a fresh valid store reports an accurate empty summary and mutates nothing', async () => {
      const fixture = makeAuditConfig('reg01');
      await buildStore(fixture, { records: 0 });

      const before = snapshotTree(fixture.auditDir);
      const { exitCode, out } = await runAudit(fixture, ['status'], verifyArgs(fixture));
      assertSnapshotUnchanged(before, snapshotTree(fixture.auditDir), 'status must not mutate');

      assert.equal(exitCode, EXIT_OK);
      assert.match(out, /Integrity:\s+VERIFIED/);
      assert.match(out, /Current sequence:\s+0/);
      assert.match(out, /Last checkpoint:\s+none/);
      assert.match(out, /Store ID:\s+[0-9a-f-]{36}/);
      assert.match(out, /Anchor mode:\s+DISABLED/);
    });

    test('RC06-T7-REG-02: a non-empty store reports its real storeId, sequence and segment count', async () => {
      const fixture = await multiSegmentFixture('reg02');
      const { exitCode, out } = await runAudit(fixture, ['status'], verifyArgs(fixture));

      assert.equal(exitCode, EXIT_OK);
      assert.ok(out.includes(fixture.storeId), 'the reported store ID must be the real one');
      assert.match(out, /Current sequence:\s+5/);
      assert.match(out, /Retained segments:\s+1/);
      assert.match(out, /Last checkpoint:\s+3/);
    });

    test('RC06-T7-REG-03: status reports the indeterminate recovery count from real evidence', async () => {
      const fixture = makeAuditConfig('reg03');
      await buildStore(fixture, { records: 2 });
      // A dangling STARTED on disk is reconciled by the next real startup, which
      // appends durable RECOVERY_INDETERMINATE evidence.
      const runtime = await createTestAuditRuntime(fixture.config);
      await runtime.appendRecord(
        sampleRecordCandidate({
          lifecycle: { operationId: crypto.randomUUID(), phase: 'STARTED' },
        }),
      );
      await runtime.close();

      const server = await createTestAuditRuntime(fixture.config);
      await server.close();

      const status = await readOfflineAuditStatus({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      assert.ok(status.indeterminateRecoveries >= 1, 'the reconciliation record must be counted');
    });

    test('RC06-T7-REG-04: status fails closed rather than claiming HEALTHY for an unverifiable store', async () => {
      const fixture = await multiSegmentFixture('reg04');
      // Corrupt the active segment so integrity cannot be established.
      const active = path.join(fixture.auditDir, 'audit-active.jsonl');
      fs.appendFileSync(active, '{"sequenceNumber":6,"integrity":{"recordHash":"deadbeef"}}\n');

      const { exitCode, out, err } = await runAudit(fixture, ['status'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_FAILURE);
      assert.equal(out.includes('VERIFIED'), false, 'no optimistic success may be reported');
      assert.match(err, /AUDIT_|INVALID|CORRUPT/i);
    });
  });

  /* ====================================================================== *
   * 2. `arc audit verify`
   * ====================================================================== */

  describe('2. arc audit verify', () => {
    test('RC06-T7-REG-05: a multi-segment store with a compressed archive verifies offline', async () => {
      const fixture = await multiSegmentFixture('reg05');
      const archives = fs
        .readdirSync(fixture.auditDir)
        .filter((name) => name.endsWith('.jsonl.gz'));
      assert.equal(archives.length, 1, 'the fixture must carry a real .jsonl.gz archive');
      assert.equal(
        fs.existsSync(path.join(fixture.auditDir, 'audit-active.jsonl')),
        true,
        'and a real active segment',
      );

      const { exitCode, out } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_OK);
      assert.match(out, /Audit verification: VERIFIED/);
      assert.match(out, /Records:\s+5/);
      assert.match(out, /Checkpoints:\s+1/);
    });

    test('RC06-T7-REG-06: verification is byte-for-byte read-only over the whole store', async () => {
      const fixture = await multiSegmentFixture('reg06');
      const before = snapshotTree(fixture.auditDir);

      await verifyOfflineStore({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      await readOfflineAuditStatus({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      assertSnapshotUnchanged(before, snapshotTree(fixture.auditDir), 'verify must not mutate');
    });

    test('RC06-T7-REG-07: verification uses PUBLIC keys only and never reads the signing key', async () => {
      const fixture = await multiSegmentFixture('reg07');

      // The private key is made entirely unavailable. Public-key verification
      // must not need it, and must not fail because of its absence.
      const privateKeyBytes = fs.readFileSync(fixture.checkpoint.signingKeyPath);
      fs.chmodSync(fixture.checkpoint.signingKeyPath, 0o000);
      try {
        const { exitCode } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
        assert.equal(exitCode, EXIT_OK, 'verification must succeed with no readable private key');
      } finally {
        fs.chmodSync(fixture.checkpoint.signingKeyPath, 0o600);
      }
      assert.deepEqual(fs.readFileSync(fixture.checkpoint.signingKeyPath), privateKeyBytes);

      // And with the key readable again, the instrumented loader proves it was
      // never opened on any of the four local command paths.
      enablePrivateKeyLoadProbe();
      await verifyOfflineStore({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      await readOfflineAuditStatus({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      await inspectRetainedRecords({ directory: fixture.auditDir, limit: 2 });
      assert.equal(getPrivateKeyLoadCount(), 0, 'no private signing key may be loaded');
    });

    test('RC06-T7-REG-08: a tampered primary record fails verification', async () => {
      const fixture = await multiSegmentFixture('reg08');
      const active = path.join(fixture.auditDir, 'audit-active.jsonl');
      const lines = fs.readFileSync(active, 'utf8').slice(0, -1).split('\n');
      const record = JSON.parse(lines[lines.length - 1]);
      record.invocation.toolName = 'delete_everything';
      lines[lines.length - 1] = JSON.stringify(record);
      fs.writeFileSync(active, `${lines.join('\n')}\n`);

      const { exitCode, err } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_FAILURE);
      assert.match(err, /AUDIT_|INVALID|CORRUPT|MISMATCH/i);
    });

    test('RC06-T7-REG-09: a deleted record below a checkpoint fails verification', async () => {
      const fixture = await multiSegmentFixture('reg09');
      const archive = fs.readdirSync(fixture.auditDir).find((name) => name.endsWith('.jsonl.gz'));
      // Removing the sealed archive removes evidence a checkpoint covers.
      fs.rmSync(path.join(fixture.auditDir, archive));

      const { exitCode } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_FAILURE);
    });

    test('RC06-T7-REG-10: a corrupted gzip archive fails verification', async () => {
      const fixture = await multiSegmentFixture('reg10');
      const archive = fs.readdirSync(fixture.auditDir).find((name) => name.endsWith('.jsonl.gz'));
      const full = path.join(fixture.auditDir, archive);
      const raw = fs.readFileSync(full);
      raw[Math.floor(raw.length / 2)] ^= 0xff;
      fs.writeFileSync(full, raw);

      const { exitCode } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_FAILURE);
    });

    test('RC06-T7-REG-11: a wrong checkpoint public key fails verification', async () => {
      const fixture = await multiSegmentFixture('reg11');
      const other = writeKeyPair(newRoot('reg11-other'), 'other');

      const { exitCode, err } = await runAudit(
        fixture,
        ['verify'],
        ['--checkpoint-key', other.publicKeyPath],
      );
      assert.equal(exitCode, EXIT_FAILURE);
      assert.match(err, /FINGERPRINT_MISMATCH|KEY_MISMATCH|MISMATCH/i);
    });

    test('RC06-T7-REG-12: a tampered checkpoint signature fails verification', async () => {
      const fixture = await multiSegmentFixture('reg12');
      const checkpointPath = path.join(fixture.auditDir, 'audit-checkpoints.jsonl');
      const lines = fs.readFileSync(checkpointPath, 'utf8').slice(0, -1).split('\n');
      const checkpoint = JSON.parse(lines[0]);
      const raw = Buffer.from(checkpoint.signature, 'base64url');
      raw[0] ^= 0xff;
      checkpoint.signature = raw.toString('base64url');
      lines[0] = JSON.stringify(checkpoint);
      fs.writeFileSync(checkpointPath, `${lines.join('\n')}\n`);

      const { exitCode } = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(exitCode, EXIT_FAILURE);
    });

    test('RC06-T7-REG-13: an anchor-disabled store verifies and says anchoring is not configured', async () => {
      const fixture = makeAuditConfig('reg13');
      await buildStore(fixture, { records: 3 });

      const result = await verifyOfflineStore({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      assert.equal(result.anchorMode, 'DISABLED');
      assert.equal(result.anchor.configured, false);
      assert.equal(result.tiers.anchor, 'NOT_CONFIGURED');

      const { out } = await runAudit(
        fixture,
        ['verify'],
        ['--checkpoint-key', fixture.checkpoint.publicKeyPath],
      );
      assert.match(out, /NOT CONFIGURED/);
      assert.equal(
        /Tier 3\):\s+VERIFIED/.test(out),
        false,
        'Tier-3 protection must not be claimed',
      );
    });

    test('RC06-T7-REG-14: an anchor-enabled store verifies its real signed receipts', async () => {
      const fixture = makeAuditConfig('reg14', { anchor: true });
      await buildStore(fixture, {
        records: 5,
        rotateAt: [3],
      });

      const checkpointPath = path.join(fixture.auditDir, 'audit-checkpoints.jsonl');
      const receiptPath = path.join(fixture.auditDir, 'audit-anchors.jsonl');
      assert.equal(fs.existsSync(checkpointPath), true, 'a real checkpoint must exist');
      assert.equal(fs.existsSync(receiptPath), true, 'a real receipt must exist');

      const result = await verifyOfflineStore({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        anchorReceiptPublicKeyPath: fixture.anchorMaterial.publicKeyPath,
        workspacePaths: [],
      });
      assert.equal(result.anchorMode, 'ENABLED');
      assert.equal(result.anchor.configured, true);
      assert.ok(result.anchor.receiptCount >= 1, 'at least one receipt must verify');
      assert.equal(result.tiers.anchor, 'VERIFIED');
    });
  });

  /* ====================================================================== *
   * 3. `arc audit inspect`
   * ====================================================================== */

  describe('3. arc audit inspect', () => {
    test('RC06-T7-REG-15: inspection spans a cross-segment range in sequence order', async () => {
      const fixture = await multiSegmentFixture('reg15');
      const records = await inspectRetainedRecords({ directory: fixture.auditDir });

      assert.deepEqual(
        records.map((record) => record.sequenceNumber),
        [1, 2, 3, 4, 5],
        'inspection must span the compressed archive and the active segment in order',
      );
    });

    test('RC06-T7-REG-16: --from/--to are inclusive and --limit is exact', async () => {
      const fixture = await multiSegmentFixture('reg16');

      const window = await inspectRetainedRecords({
        directory: fixture.auditDir,
        from: 2,
        to: 4,
      });
      assert.deepEqual(
        window.map((record) => record.sequenceNumber),
        [2, 3, 4],
        'both bounds are inclusive',
      );

      const limited = await inspectRetainedRecords({ directory: fixture.auditDir, limit: 2 });
      assert.deepEqual(
        limited.map((record) => record.sequenceNumber),
        [1, 2],
      );
    });

    test('RC06-T7-REG-17: the limit is bounded and never silently widened', async () => {
      const fixture = await multiSegmentFixture('reg17');

      const atMax = await inspectRetainedRecords({
        directory: fixture.auditDir,
        limit: MAX_INSPECT_RECORDS,
      });
      assert.equal(atMax.length, 5, 'the maximum permitted limit must succeed');

      await assertRejectsWithCode(
        inspectRetainedRecords({ directory: fixture.auditDir, limit: MAX_INSPECT_RECORDS + 1 }),
        'INSPECT_LIMIT_EXCEEDED',
      );
      assert.equal(MAX_INSPECT_RECORDS, 100);
    });

    test('RC06-T7-REG-18: malformed ranges are rejected and inspect never mutates', async () => {
      const fixture = await multiSegmentFixture('reg18');
      const before = snapshotTree(fixture.auditDir);

      assertThrowsWithCode(
        () => validateInspectRange({ from: 5, to: 2 }),
        'INVALID_SEQUENCE_RANGE',
      );
      assertThrowsWithCode(() => validateInspectRange({ from: 0 }), 'INVALID_SEQUENCE_RANGE');
      assertThrowsWithCode(() => validateInspectRange({ to: -1 }), 'INVALID_SEQUENCE_RANGE');
      assertThrowsWithCode(() => validateInspectRange({ limit: 0 }), 'INVALID_SEQUENCE_RANGE');

      await inspectRetainedRecords({ directory: fixture.auditDir });
      assertSnapshotUnchanged(before, snapshotTree(fixture.auditDir), 'inspect must not mutate');

      const { exitCode } = await runAudit(fixture, ['inspect', '--limit', '101']);
      assert.equal(exitCode, EXIT_USAGE);
      const reversed = await runAudit(fixture, ['inspect', '--from', '9', '--to', '2']);
      assert.equal(reversed.exitCode, EXIT_USAGE);
    });
  });

  /* ====================================================================== *
   * 4. `arc audit export`
   * ====================================================================== */

  describe('4. arc audit export', () => {
    async function exportOnce(fixture, label, extra = {}) {
      const output = newRoot(label);
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(output, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
        ...extra,
      });
      return result;
    }

    test('RC06-T7-REG-19: the bundle has the frozen structure, modes and no private key', async () => {
      const fixture = await multiSegmentFixture('reg19');
      const result = await exportOnce(fixture, 'reg19-out');

      for (const name of ['manifest.json', 'audit', 'checkpoints', 'anchors', 'public-keys']) {
        assert.equal(
          fs.existsSync(path.join(result.outputDirectory, name)),
          true,
          `bundle must contain ${name}`,
        );
      }
      assert.equal(
        fs.statSync(result.outputDirectory).mode & 0o777,
        0o700,
        'the bundle root is 0700',
      );
      const manifestFile = fs.statSync(path.join(result.outputDirectory, 'manifest.json'));
      assert.equal(manifestFile.mode & 0o777, 0o600, 'bundle files are 0600');

      // No private key material anywhere in the bundle.
      for (const [relative] of Object.entries(result.manifest.files)) {
        const raw = fs.readFileSync(path.join(result.outputDirectory, relative), 'utf8');
        assert.equal(/PRIVATE KEY/.test(raw), false, `${relative} must not carry a private key`);
      }
      assert.equal(
        result.manifest.files['public-keys/checkpoint-public.pem'] !== undefined,
        true,
        'the checkpoint public verification key is present',
      );
    });

    test('RC06-T7-REG-20: every manifest digest and byte count recomputes', async () => {
      const fixture = await multiSegmentFixture('reg20');
      const result = await exportOnce(fixture, 'reg20-out');

      const entries = Object.entries(result.manifest.files);
      assert.ok(entries.length >= 4, 'the manifest must cover the emitted evidence');
      for (const [relative, entry] of entries) {
        const raw = fs.readFileSync(path.join(result.outputDirectory, relative));
        assert.equal(raw.byteLength, entry.bytes, `${relative}: byte count`);
        assert.equal(
          crypto.createHash('sha256').update(raw).digest('hex'),
          entry.sha256,
          `${relative}: sha256`,
        );
      }
    });

    test('RC06-T7-REG-21: the bundled range verifies from the bundled public keys alone', async () => {
      const fixture = await multiSegmentFixture('reg21');
      const result = await exportOnce(fixture, 'reg21-out');

      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.status, 'VERIFIED');
      assert.equal(verified.storeId, fixture.storeId);
      assert.equal(verified.checkpointCount, 1);
      assert.equal(verified.coveredSequenceEnd, 5);
      assert.deepEqual(verified.sequenceRange, { start: 1, end: 5 });
    });

    test('RC06-T7-REG-22: two exports of unchanged evidence are byte-identical', async () => {
      const fixture = await multiSegmentFixture('reg22');
      const first = await exportOnce(fixture, 'reg22-a');
      const second = await exportOnce(fixture, 'reg22-b');

      assert.equal(
        fs.readFileSync(path.join(first.outputDirectory, 'manifest.json'), 'utf8'),
        fs.readFileSync(path.join(second.outputDirectory, 'manifest.json'), 'utf8'),
        'identical evidence must produce an identical manifest',
      );
      assert.deepEqual(second.manifest, first.manifest);
    });

    test('RC06-T7-REG-23: an anchor-enabled export carries verifiable receipts, and a tampered one fails', async () => {
      const fixture = makeAuditConfig('reg23', { anchor: true });
      await buildStore(fixture, {
        records: 5,
        rotateAt: [3],
      });

      const output = newRoot('reg23-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(output, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        anchorReceiptPublicKeyPath: fixture.anchorMaterial.publicKeyPath,
        workspacePaths: [],
      });
      assert.ok(result.manifest.anchorReceiptIds.length >= 1, 'receipts must be bundled');

      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.anchorReceiptCount, result.manifest.anchorReceiptIds.length);

      // Tamper with a bundled receipt: the digest fails first, then the signature.
      const receiptPath = path.join(result.outputDirectory, 'anchors', 'audit-anchors.jsonl');
      const lines = fs.readFileSync(receiptPath, 'utf8').slice(0, -1).split('\n');
      const receipt = JSON.parse(lines[0]);
      const raw = Buffer.from(receipt.signature, 'base64url');
      raw[0] ^= 0xff;
      receipt.signature = raw.toString('base64url');
      lines[0] = JSON.stringify(receipt);
      fs.writeFileSync(receiptPath, `${lines.join('\n')}\n`);

      await assertRejectsWithCode(
        verifyEvidenceBundle(result.outputDirectory),
        'BUNDLE_DIGEST_MISMATCH',
      );
    });

    test('RC06-T7-REG-24: an anchor-disabled export is truthful about having no receipts', async () => {
      const fixture = await multiSegmentFixture('reg24');
      const result = await exportOnce(fixture, 'reg24-out');

      assert.deepEqual(result.manifest.anchorReceiptIds, []);
      assert.equal(
        fs.statSync(path.join(result.outputDirectory, 'anchors', 'audit-anchors.jsonl')).size,
        0,
        'the anchors ledger must be empty, not absent-and-implied',
      );
      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.anchorReceiptCount, 0);
    });

    test('RC06-T7-REG-25: a partial range names the covered range and still verifies', async () => {
      const fixture = await multiSegmentFixture('reg25');
      const result = await exportOnce(fixture, 'reg25-out', { from: 2, to: 4 });

      assert.deepEqual(result.manifest.sequenceRange, { start: 2, end: 4 });
      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.status, 'VERIFIED');
    });
  });

  /* ====================================================================== *
   * 5. Source stability
   * ====================================================================== */

  describe('5. Source stability', () => {
    test('RC06-T7-REG-26: a source changed mid-export fails rather than reporting success', async () => {
      const fixture = await multiSegmentFixture('reg26');
      const active = path.join(fixture.auditDir, 'audit-active.jsonl');
      const pristine = fs.readFileSync(active);

      const output = newRoot('reg26-out');
      const pending = exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(output, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      // The export has already entered its verification await. Corrupting the
      // source now must surface as a failure, never as a bundle that silently
      // describes evidence that no longer exists.
      fs.appendFileSync(active, '{"torn":\n');

      await assertRejectsWithCode(pending, [
        'AUDIT_CORRUPTION_DETECTED',
        'AUDIT_VERIFICATION_FAILED',
        'EXPORT_SOURCE_CHANGED',
        'INVALID_RECORD',
        'RECOVERABLE_TORN_ACTIVE_TAIL',
      ]);

      // A failed export leaves no bundle behind.
      assert.equal(
        fs.existsSync(path.join(output, 'bundle')),
        false,
        'a failed export must not leave a partial bundle',
      );
      fs.writeFileSync(active, pristine);
    });

    test('RC06-T7-REG-27: verification detects a store that changed after its own read', async () => {
      const fixture = await multiSegmentFixture('reg27');
      const active = path.join(fixture.auditDir, 'audit-active.jsonl');
      fs.appendFileSync(active, '{"torn":\n');

      await assertRejectsWithCode(
        verifyOfflineStore({
          directory: fixture.auditDir,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        }),
        ['AUDIT_CORRUPTION_DETECTED', 'AUDIT_VERIFICATION_FAILED', 'INVALID_RECORD', 'RECOVERABLE'],
      );
    });
  });

  /* ====================================================================== *
   * 6. Negative Controls: RC06-NEG-105..108
   * ====================================================================== */

  describe('6. Negative Controls: RC06-NEG-105..108', () => {
    test('RC06-NEG-105: remote MCP attempts to delete, truncate or rotate audit evidence are UNKNOWN_TOOL', async () => {
      const { ArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const fixture = await multiSegmentFixture('neg105');
      const before = snapshotTree(fixture.auditDir);

      const advertised = ArcMcpServer.ALL_TOOL_DEFINITIONS ?? null;
      if (advertised !== null) {
        const names = advertised.map((tool) => tool.name);
        for (const name of names) {
          assert.equal(
            /audit/i.test(name),
            false,
            `no advertised MCP tool may be an audit-management surface: ${name}`,
          );
        }
      }

      // The task-6 suite owns the live dispatch; here the control is the CLI
      // boundary: none of these names is a local command either.
      for (const name of [
        'audit_delete',
        'audit.truncate',
        'audit.rotate',
        'audit_purge',
        'audit_clear',
      ]) {
        const { exitCode, err } = await run(['audit', name]);
        assert.equal(exitCode, EXIT_USAGE, `${name} must not be a subcommand`);
        assert.match(err, /Unknown audit subcommand/);
      }
      const direct = await run(['audit', 'delete', '--dir', fixture.auditDir]);
      assert.equal(direct.exitCode, EXIT_USAGE);

      assertSnapshotUnchanged(before, snapshotTree(fixture.auditDir), 'no audit bytes may change');
    });

    test('RC06-NEG-106: an existing destination is rejected and never overwritten', async () => {
      const fixture = await multiSegmentFixture('neg106');
      const base = newRoot('neg106-out');

      // 1. The destination directory already exists.
      const existing = path.join(base, 'already');
      fs.mkdirSync(existing, { mode: 0o700 });
      fs.writeFileSync(path.join(existing, 'keep.txt'), 'precious\n', { mode: 0o600 });
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: existing,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        }),
        'EXPORT_DESTINATION_EXISTS',
      );
      assert.equal(fs.readFileSync(path.join(existing, 'keep.txt'), 'utf8'), 'precious\n');

      // 2. An attempted merge: the destination holds a manifest already.
      const merged = path.join(base, 'merged');
      fs.mkdirSync(merged, { mode: 0o700 });
      fs.writeFileSync(path.join(merged, 'manifest.json'), '{"version":1}\n', { mode: 0o600 });
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: merged,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        }),
        'EXPORT_DESTINATION_EXISTS',
      );
      assert.equal(
        fs.readFileSync(path.join(merged, 'manifest.json'), 'utf8'),
        '{"version":1}\n',
        'the existing manifest must not be replaced',
      );

      // 3. A repeated export to the same destination.
      const target = path.join(base, 'once');
      await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: target,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      const manifestBefore = fs.readFileSync(path.join(target, 'manifest.json'), 'utf8');
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: target,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        }),
        'EXPORT_DESTINATION_EXISTS',
      );
      assert.equal(fs.readFileSync(path.join(target, 'manifest.json'), 'utf8'), manifestBefore);
    });

    test('RC06-NEG-107: a symlinked destination or symlinked parent is rejected', async () => {
      const fixture = await multiSegmentFixture('neg107');
      const base = newRoot('neg107-out');
      const real = path.join(base, 'real');
      fs.mkdirSync(real, { mode: 0o700 });

      const exportTo = (outputDirectory) =>
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        });

      // 1. The destination path itself is a symlink.
      const link = path.join(base, 'link');
      fs.symlinkSync(real, link);
      await assertRejectsWithCode(exportTo(link), [
        'SYMLINK_DETECTED',
        'EXPORT_DESTINATION_EXISTS',
      ]);

      // 2. The direct parent is a symlink.
      fs.symlinkSync(real, path.join(base, 'parent-link'));
      await assertRejectsWithCode(
        exportTo(path.join(base, 'parent-link', 'bundle')),
        'SYMLINK_DETECTED',
      );

      // 3. A deeper parent component is a symlink.
      const deep = path.join(real, 'a', 'b');
      fs.mkdirSync(deep, { recursive: true, mode: 0o700 });
      fs.symlinkSync(deep, path.join(base, 'deep-link'));
      await assertRejectsWithCode(
        exportTo(path.join(base, 'deep-link', 'c', 'bundle')),
        'SYMLINK_DETECTED',
      );

      // Nothing was created through any link.
      assert.deepEqual(fs.readdirSync(real), ['a'], 'no bundle may appear through a symlink');
    });

    test('RC06-NEG-108: audit-contained, workspace-contained and oversized destinations are rejected', async () => {
      const fixture = await multiSegmentFixture('neg108');
      const base = newRoot('neg108-out');

      const exportTo = (outputDirectory, workspacePaths = []) =>
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths,
        });

      // 1. Equal to the audit directory.
      await assertRejectsWithCode(exportTo(fixture.auditDir), [
        'EXPORT_DESTINATION_INSIDE_AUDIT_STORE',
        'EXPORT_DESTINATION_EXISTS',
      ]);

      // 2. Below the audit directory.
      await assertRejectsWithCode(
        exportTo(path.join(fixture.auditDir, 'nested')),
        'EXPORT_DESTINATION_INSIDE_AUDIT_STORE',
      );

      // 3. Equal to a workspace root, and 4. below one.
      const workspace = path.join(base, 'workspace');
      fs.mkdirSync(workspace, { mode: 0o700 });
      await assertRejectsWithCode(exportTo(workspace, [workspace]), [
        'EXPORT_DESTINATION_INSIDE_WORKSPACE',
        'EXPORT_DESTINATION_EXISTS',
      ]);
      await assertRejectsWithCode(
        exportTo(path.join(workspace, 'bundle'), [workspace]),
        'EXPORT_DESTINATION_INSIDE_WORKSPACE',
      );

      // 5. A lexical sibling must NOT be falsely rejected: authority is
      //    component-based, so `/workspace-a2` is not inside `/workspace-a`.
      const sibling = await exportTo(path.join(base, 'workspace-a2'), [
        path.join(base, 'workspace-a'),
      ]);
      assert.equal(
        fs.existsSync(path.join(sibling.outputDirectory, 'manifest.json')),
        true,
        'a lexical sibling is a legitimate destination',
      );

      // 6. The byte budget is enforced at its exact boundary, structurally —
      //    no gigabyte is allocated to reach it.
      assert.equal(MAX_EXPORT_BYTES, 1_073_741_824);
      assertExportWithinBudget(MAX_EXPORT_BYTES);
      assertThrowsWithCode(
        () => assertExportWithinBudget(MAX_EXPORT_BYTES + 1),
        'EXPORT_TOO_LARGE',
      );
    });

    test('RC06-NEG-108: export refuses to guess at authoritative workspace roots', async () => {
      const fixture = await multiSegmentFixture('neg108b');
      const base = newRoot('neg108b-out');
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: path.join(base, 'bundle'),
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        }),
        'EXPORT_WORKSPACE_ROOTS_REQUIRED',
      );
    });
  });

  /* ====================================================================== *
   * 7. Local-only and public-surface guarantees
   * ====================================================================== */

  describe('7. Local-only guarantees', () => {
    test('RC06-T7-REG-28: the audit commands need no admin channel and accept no admin option', async () => {
      const fixture = await multiSegmentFixture('reg28');

      // With no admin socket and no admin key configured, the local commands
      // still work: they are not routed over the admin IPC channel.
      const local = await runAudit(fixture, ['status'], verifyArgs(fixture));
      assert.equal(local.exitCode, EXIT_OK);

      // The admin options are not part of the audit syntax at all.
      const withSocket = await run(['audit', 'status', '--admin-socket', '/tmp/nope.sock']);
      assert.equal(withSocket.exitCode, EXIT_USAGE);
      assert.match(withSocket.err, /Unknown option/);

      const withKeyFd = await run([
        'audit',
        'verify',
        '--dir',
        fixture.auditDir,
        '--admin-key-fd',
        '3',
      ]);
      assert.equal(withKeyFd.exitCode, EXIT_USAGE);
    });

    test('RC06-T7-REG-29: no audit-management name reaches the MCP tool catalog', async () => {
      const serverPackage = await import('../apps/mcp-server/dist/index.js');
      const auditPackage = await import('../packages/audit/dist/index.js');

      const forbidden =
        /^(auditStatus|auditVerify|auditInspect|auditExport|verifyAuditStore|openOfflineVerifier|exportAuditEvidence|inspectAuditStore|runAuditCommand)$/;
      for (const name of Object.keys(serverPackage)) {
        assert.equal(forbidden.test(name), false, `mcp-server must not export ${name}`);
      }
      for (const name of Object.keys(auditPackage)) {
        assert.equal(forbidden.test(name), false, `audit package must not export ${name}`);
      }

      // The audit surface that DOES exist is observation-only: no exported name
      // performs a mutation, and none is a remote administration verb.
      const exported = Object.keys(auditPackage);
      for (const name of exported) {
        assert.equal(
          /^(delete|purge|truncate|clear|rotate|remove)Audit/i.test(name),
          false,
          `no mutating audit surface may be exported: ${name}`,
        );
      }
    });

    test('RC06-T7-REG-30: every audit subcommand is reachable without an admin client', async () => {
      const fixture = await multiSegmentFixture('reg30');
      const base = newRoot('reg30-out');

      const status = await runAudit(fixture, ['status'], verifyArgs(fixture));
      assert.equal(status.exitCode, EXIT_OK);

      const verify = await runAudit(fixture, ['verify'], verifyArgs(fixture));
      assert.equal(verify.exitCode, EXIT_OK);

      const inspect = await runAudit(fixture, ['inspect', '--limit', '1']);
      assert.equal(inspect.exitCode, EXIT_OK);

      const exported = await runAudit(fixture, [
        'export',
        '--output',
        path.join(base, 'bundle'),
        '--no-workspaces',
        ...verifyArgs(fixture),
      ]);
      assert.equal(exported.exitCode, EXIT_OK);
      assert.match(exported.out, /Evidence bundle written/);
    });

    test('RC06-T7-REG-31: the retained source inventory is segment-ordered and never doubled', async () => {
      const fixture = await multiSegmentFixture('reg31');
      const sources = listRetainedSegmentSources(fixture.auditDir);

      assert.deepEqual(
        sources.map((source) => source.kind),
        ['ARCHIVE', 'ACTIVE'],
        'a rotated archive then the active segment',
      );
      const compressed = sources.filter((source) => source.compressed);
      assert.equal(compressed.length, 1, 'exactly one compressed representation is selected');
      // A logical range present in both representations must never appear twice.
      const starts = sources.map((source) => source.sequenceStart);
      assert.equal(new Set(starts).size, starts.length, 'no range may be yielded twice');
    });

    test('RC06-T7-REG-32: the CLI version and stage are unchanged by Task 7', async () => {
      const rootPackage = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
      const cliPackage = JSON.parse(
        fs.readFileSync(path.join(REPO_ROOT, 'apps/cli/package.json'), 'utf8'),
      );
      assert.equal(rootPackage.version, '0.5.0-rc05');
      assert.equal(cliPackage.version, '0.5.0-rc05');
    });
  });

  /* ====================================================================== *
   * 8. Remote negative control: RC06-NEG-105 on the real remote call path
   * ====================================================================== */

  describe('8. RC06-NEG-105 remote dispatch', () => {
    test('RC06-NEG-105: remote MCP tool calls attempting audit deletion, truncation or manual rotation answer with UNKNOWN_TOOL', async () => {
      const fixture = await startRemoteFixture('neg105');
      try {
        const session = await initializeRemoteSession(fixture);

        // The advertised catalog is the defense-in-depth layer: no audit
        // management surface is offered to a remote client at all.
        const listed = await remoteToolsList(fixture, session);
        for (const tool of listed) {
          assert.equal(
            /audit/i.test(tool.name),
            false,
            `no remote catalog entry may be an audit surface: ${tool.name}`,
          );
        }

        // Baseline taken AFTER the session handshake and the catalog read.
        const before = snapshotTree(fixture.auditDir);
        const activePath = path.join(fixture.auditDir, 'audit-active.jsonl');
        const activeBeforeBytes = fs.readFileSync(activePath);
        const activeBefore = activeBeforeBytes.toString('utf8');

        // The load-bearing part: a REAL remote tools/call through the real mTLS
        // gateway, dispatched by the real server, for each forbidden verb.
        for (const name of [
          'audit_delete',
          'audit.truncate',
          'audit.rotate',
          'audit_purge',
          'audit_clear',
          'audit_delete_log',
          'audit_rotate_manual',
        ]) {
          const response = await remoteToolCall(fixture, session, name, { dir: fixture.auditDir });
          const payload = responsePayload(response);

          assert.equal(
            response.status,
            200,
            `${name}: transport must answer, got ${response.status}`,
          );
          assert.ok(payload.error, `${name}: must be a JSON-RPC error, never a tool result`);
          assert.equal(
            payload.error.code,
            METHOD_NOT_FOUND,
            `${name}: must be the protocol-level unknown-tool refusal, got ${JSON.stringify(payload.error)}`,
          );
          // Not a CallToolResult in any shape: an `isError` result would mean the
          // call entered the shared execution pipeline.
          assert.equal(payload.result, undefined, `${name}: must not produce a tool result`);
          assert.equal(
            JSON.stringify(payload).includes('isError'),
            false,
            `${name}: must not be an isError tool result`,
          );
        }

        // The audit evidence the attempt could have damaged is untouched: no
        // artifact was deleted, no artifact was replaced, no rotated segment was
        // produced (a manual rotation would have sealed one), and the chain
        // still verifies end to end.
        // The store is append-only, so the test is prefix preservation rather
        // than byte equality: every artifact that existed still exists, none
        // shrank, and each one still BEGINS with the bytes it had before. A
        // truncation, a rewrite, or a rotation of the evidence would break all
        // three.
        for (const name of before.keys()) {
          const full = path.join(fixture.auditDir, name);
          assert.equal(fs.existsSync(full), true, `${name} must not be deleted`);
          const was = fs.readFileSync(full);
          assert.ok(was.byteLength >= before.get(name).size, `${name} must not shrink`);
        }
        assert.deepEqual(
          fs.readdirSync(fixture.auditDir).filter((name) => name.endsWith('.jsonl.gz')),
          [],
          'no manual rotation may have occurred',
        );

        // Every record the attempts caused is the gateway authenticating the
        // mTLS request — a transport fact, not tool evidence. Nothing carrying a
        // forbidden name, and no lifecycle STARTED/COMPLETED for one, appears.
        const activeAfterBytes = fs.readFileSync(activePath);
        assert.equal(
          activeAfterBytes.subarray(0, activeBeforeBytes.byteLength).equals(activeBeforeBytes),
          true,
          'the existing evidence must be preserved byte for byte',
        );
        const activeAfter = activeAfterBytes.toString('utf8');
        const appended = activeAfter
          .slice(activeBefore.length)
          .trim()
          .split('\n')
          .filter((line) => line.length > 0)
          .map((line) => JSON.parse(line));
        for (const record of appended) {
          assert.match(
            String(record.invocation?.toolName ?? ''),
            /^gateway:/,
            `the only evidence a refused audit attempt may produce is transport authentication, got ${JSON.stringify(record.invocation?.toolName)}`,
          );
          assert.equal(record.lifecycle, undefined, 'no lifecycle record may be created');
        }
        assert.equal(
          activeAfter.includes('audit_delete') ||
            activeAfter.includes('audit.truncate') ||
            activeAfter.includes('audit.rotate'),
          false,
          'no forbidden name may reach the durable evidence',
        );

        const verified = await verifyOfflineStore({
          directory: fixture.auditDir,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        });
        assert.equal(verified.status, 'VERIFIED');

        // No approval request was created by any of the attempts.
        assert.deepEqual(
          fixture.server.approvalStateManager.listActive(),
          [],
          'no approval request may be created by an unknown-tool call',
        );
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC06-T7-REG-33: a registered tool still executes on the same remote path, proving the rule is membership and not a denylist', async () => {
      const fixture = await startRemoteFixture('reg33');
      try {
        const session = await initializeRemoteSession(fixture);
        const response = await remoteToolCall(fixture, session, 'health', {});
        const payload = responsePayload(response);
        assert.equal(payload.error, undefined, response.body);
        assert.notEqual(payload.result?.isError, true, JSON.stringify(payload.result));
      } finally {
        await fixture.server.stop();
      }
    });
  });

  /* ====================================================================== *
   * 9. Hardening regressions
   * ====================================================================== */

  describe('9. Hardening regressions', () => {
    test('RC06-T7-REG-34: export fails closed when the workspace roots were never stated authoritatively', async () => {
      const fixture = await multiSegmentFixture('reg34');
      const base = newRoot('reg34-out');

      // The library refuses an unstated workspace set.
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: path.join(base, 'missing'),
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        }),
        'EXPORT_WORKSPACE_ROOTS_REQUIRED',
      );
      assert.equal(fs.existsSync(path.join(base, 'missing')), false, 'nothing may be created');

      // The CLI must not manufacture an authoritative empty array by default.
      const unstated = await runAudit(fixture, [
        'export',
        '--output',
        path.join(base, 'unstated'),
        ...verifyArgs(fixture),
      ]);
      assert.equal(unstated.exitCode, EXIT_FAILURE);
      assert.match(unstated.err, /EXPORT_WORKSPACE_ROOTS_REQUIRED/);
      assert.equal(fs.existsSync(path.join(base, 'unstated')), false);

      // An explicit authoritative statement IS honored, in both forms.
      const assertedNone = await runAudit(fixture, [
        'export',
        '--output',
        path.join(base, 'none'),
        '--no-workspaces',
        ...verifyArgs(fixture),
      ]);
      assert.equal(assertedNone.exitCode, EXIT_OK);

      const workspace = newRoot('reg34-ws');
      const assertedRoots = await runAudit(fixture, [
        'export',
        '--output',
        path.join(base, 'roots'),
        '--workspace',
        workspace,
        ...verifyArgs(fixture),
      ]);
      assert.equal(assertedRoots.exitCode, EXIT_OK);

      // Mixing the two statements is contradictory, not a merge.
      const contradictory = await runAudit(fixture, [
        'export',
        '--output',
        path.join(base, 'both'),
        '--no-workspaces',
        '--workspace',
        workspace,
        ...verifyArgs(fixture),
      ]);
      assert.equal(contradictory.exitCode, EXIT_USAGE);
    });

    test('RC06-T7-REG-35: a parent pathname substituted during export is never written through', async () => {
      const fixture = await multiSegmentFixture('reg35');
      const base = newRoot('reg35-out');
      const parent = path.join(base, 'parent');
      const decoy = path.join(base, 'decoy');
      fs.mkdirSync(parent, { mode: 0o700 });
      fs.mkdirSync(decoy, { mode: 0o700 });

      const destination = path.join(parent, 'bundle');
      const pending = exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: destination,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      // Substitute the checked parent pathname with a symlink to the decoy while
      // the export is still in flight.
      fs.renameSync(parent, path.join(base, 'parent-original'));
      fs.symlinkSync(decoy, parent);

      let failure = null;
      try {
        await pending;
      } catch (err) {
        failure = err;
      }

      // Whatever happened, nothing may exist through the substituted path.
      assert.deepEqual(
        fs.readdirSync(decoy),
        [],
        'no bundle may be created through a substituted parent path',
      );
      assert.deepEqual(
        fs
          .readdirSync(base)
          .filter((name) => name !== 'parent' && name !== 'decoy' && name !== 'parent-original'),
        [],
      );

      if (failure === null) {
        // Creation was bound to the descriptor of the directory that was
        // validated, so the bundle is inside the ORIGINAL directory even though
        // its pathname now resolves elsewhere.
        assert.equal(
          fs.existsSync(path.join(base, 'parent-original', 'bundle', 'manifest.json')),
          true,
          'a successful export must create the bundle in the validated directory',
        );
      } else {
        assert.equal(failure.code, 'SYMLINK_DETECTED', `unexpected failure: ${failure.code}`);
      }
    });

    test('RC06-T7-REG-36: the byte budget accounts for every emitted file, including keys and the manifest', async () => {
      const fixture = await multiSegmentFixture('reg36');
      const base = newRoot('reg36-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      // Every emitted byte is accounted for, and the projection is exact: the
      // sum of the manifest's own byte counts plus the manifest is what the
      // writer reports.
      const manifestBytes = fs.statSync(path.join(result.outputDirectory, 'manifest.json')).size;
      const evidenceBytes = Object.values(result.manifest.files).reduce(
        (total, entry) => total + entry.bytes,
        0,
      );
      assert.equal(
        result.totalBytes,
        evidenceBytes + manifestBytes,
        'the emitted total must include the manifest itself',
      );

      // The public key is a counted, manifest-listed file, not an afterthought.
      assert.ok(
        result.manifest.files['public-keys/checkpoint-public.pem'].bytes > 0,
        'the checkpoint public key must be counted',
      );

      // The boundary is exact: at the limit it passes, one byte over it fails.
      assert.equal(MAX_EXPORT_BYTES, 1_073_741_824);
      assertExportWithinBudget(MAX_EXPORT_BYTES);
      assertThrowsWithCode(
        () => assertExportWithinBudget(MAX_EXPORT_BYTES + 1),
        'EXPORT_TOO_LARGE',
      );

      // A failed export leaves no partial bundle behind.
      const tooLarge = newRoot('reg36-large');
      await assertRejectsWithCode(
        exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: path.join(tooLarge, 'bundle'),
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
          to: 1,
          from: 99_999,
        }),
        ['INVALID_SEQUENCE_RANGE'],
      );
      assert.deepEqual(fs.readdirSync(tooLarge), [], 'a failed export leaves nothing');
    });

    test('RC06-T7-REG-37: verification detects an append between its own passes', async () => {
      const fixture = await multiSegmentFixture('reg37');
      const active = path.join(fixture.auditDir, 'audit-active.jsonl');
      const pristine = fs.readFileSync(active);

      const pending = verifyOfflineStore({
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });
      // Grow the active segment while verification is in flight: the second
      // inventory observation must notice and refuse to report one stable
      // generation.
      fs.appendFileSync(
        active,
        `${JSON.stringify({ ...JSON.parse(pristine.toString('utf8').trim().split('\n').pop()), sequenceNumber: 999 })}\n`,
      );

      await assertRejectsWithCode(pending, [
        'AUDIT_SOURCE_UNSTABLE',
        'AUDIT_CORRUPTION_DETECTED',
        'AUDIT_VERIFICATION_FAILED',
      ]);
      fs.writeFileSync(active, pristine);
    });

    test('RC06-T7-REG-38: export rejects a same-size source replacement after verification', async () => {
      const fixture = await multiSegmentFixture('reg38');
      const archive = fs.readdirSync(fixture.auditDir).find((name) => name.endsWith('.jsonl.gz'));
      const full = path.join(fixture.auditDir, archive);
      const pristine = fs.readFileSync(full);

      const base = newRoot('reg38-out');
      const pending = exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      // Replace the archive with a DIFFERENT file of exactly the same length, so
      // a size-only check cannot notice.
      const replacement = Buffer.from(pristine);
      replacement[Math.floor(replacement.length / 2)] ^= 0xff;
      fs.rmSync(full);
      fs.writeFileSync(full, replacement);
      assert.equal(fs.statSync(full).size, pristine.length, 'the replacement is the same size');

      await assertRejectsWithCode(pending, [
        'EXPORT_SOURCE_CHANGED',
        'AUDIT_SOURCE_UNSTABLE',
        'AUDIT_CORRUPTION_DETECTED',
        'AUDIT_VERIFICATION_FAILED',
      ]);
      assert.equal(
        fs.existsSync(path.join(base, 'bundle')),
        false,
        'a failed export must leave no bundle',
      );
      fs.writeFileSync(full, pristine);
    });

    test('RC06-T7-REG-39: a range beginning in a later archive verifies with an authenticated boundary', async () => {
      const fixture = makeAuditConfig('reg39');
      await buildStore(fixture, { records: 9, rotateAt: [3, 6] });

      const archives = fs
        .readdirSync(fixture.auditDir)
        .filter((name) => name.endsWith('.jsonl.gz'))
        .sort();
      assert.equal(archives.length, 2, 'the fixture must carry two rotated archives');

      const base = newRoot('reg39-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
        from: 5,
        to: 8,
      });

      assert.deepEqual(result.manifest.sequenceRange, { start: 5, end: 8 });

      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.status, 'VERIFIED');
      assert.equal(verified.coveredSequenceStart, 4, 'the bundle begins at archive B');
      assert.equal(verified.coveredSequenceEnd, 9);
      assert.ok(verified.checkpointCount >= 1, 'the boundary checkpoint must be bundled');

      // The boundary checkpoint seals the evidence immediately BEFORE the
      // bundle, and is what makes the mid-history start trustworthy.
      const checkpointPath = path.join(
        result.outputDirectory,
        'checkpoints',
        'audit-checkpoints.jsonl',
      );
      const hashes = fs
        .readFileSync(checkpointPath, 'utf8')
        .slice(0, -1)
        .split('\n')
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line).sequenceEnd);
      assert.ok(hashes.includes(3), 'the checkpoint sealing sequence 3 must be bundled');
    });

    test('RC06-T7-REG-40: a declared range the bundle does not cover is rejected', async () => {
      const fixture = await multiSegmentFixture('reg40');
      const base = newRoot('reg40-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      // Claim coverage beyond what was actually emitted.
      const manifestPath = path.join(result.outputDirectory, 'manifest.json');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      manifest.sequenceRange.end = 5000;
      fs.writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`);

      await assertRejectsWithCode(
        verifyEvidenceBundle(result.outputDirectory),
        'BUNDLE_RANGE_NOT_COVERED',
      );
    });

    test('RC06-T7-REG-41: bundled checkpoints are bound to the store, the key and the chain', async () => {
      const fixture = await multiSegmentFixture('reg41');

      const build = async (label, mutate) => {
        const output = path.join(newRoot(`reg41-${label}`), 'bundle');
        await exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: output,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          workspacePaths: [],
        });
        const relative = 'checkpoints/audit-checkpoints.jsonl';
        const full = path.join(output, relative);
        const lines = fs.readFileSync(full, 'utf8').slice(0, -1).split('\n');
        const checkpoint = JSON.parse(lines[0]);
        mutate(checkpoint);
        lines[0] = JSON.stringify(checkpoint);
        rewriteBundleFile(output, relative, `${lines.join('\n')}\n`);
        return output;
      };

      // A checkpoint can no longer be resealed, so any content edit also breaks
      // its signature; the digest is repaired so the deeper rule is what fails.
      await assertRejectsWithCode(
        verifyEvidenceBundle(
          await build('store', (checkpoint) => {
            checkpoint.storeId = crypto.randomUUID();
          }),
        ),
        // A checkpoint's own hash covers its unsigned projection, so any content
        // edit is caught by that Task-4 rule before the field-level binding is
        // even reached. Either refusal is a correct outcome; both are Task-4
        // authenticity rules, never a weaker local restatement.
        [
          'BUNDLE_CHECKPOINT_STORE_MISMATCH',
          'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
          'AUDIT_CORRUPTION_DETECTED',
        ],
      );

      await assertRejectsWithCode(
        verifyEvidenceBundle(
          await build('chain', (checkpoint) => {
            checkpoint.previousCheckpointHash = 'a'.repeat(64);
          }),
        ),
        [
          'BUNDLE_CHECKPOINT_CHAIN_BROKEN',
          'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
          'AUDIT_CORRUPTION_DETECTED',
        ],
      );

      // A bundle carrying a different public key than its checkpoints name.
      const swapped = await build('key', () => {});
      const other = writeKeyPair(newRoot('reg41-key'), 'other');
      rewriteBundleFile(
        swapped,
        'public-keys/checkpoint-public.pem',
        fs.readFileSync(other.publicKeyPath),
      );
      await assertRejectsWithCode(verifyEvidenceBundle(swapped), [
        'BUNDLE_CHECKPOINT_KEY_MISMATCH',
        'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
      ]);
    });

    test('RC06-T7-REG-42: bundled receipts are bound to the store and the key', async () => {
      const fixture = makeAuditConfig('reg42', { anchor: true });
      await buildStore(fixture, { records: 5, rotateAt: [3] });

      const build = async (label, mutate) => {
        const output = path.join(newRoot(`reg42-${label}`), 'bundle');
        await exportEvidenceBundle({
          directory: fixture.auditDir,
          outputDirectory: output,
          checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
          anchorReceiptPublicKeyPath: fixture.anchorMaterial.publicKeyPath,
          workspacePaths: [],
        });
        const relative = 'anchors/audit-anchors.jsonl';
        const lines = fs.readFileSync(path.join(output, relative), 'utf8').slice(0, -1).split('\n');
        const receipt = JSON.parse(lines[0]);
        mutate(receipt);
        lines[0] = JSON.stringify(receipt);
        rewriteBundleFile(output, relative, `${lines.join('\n')}\n`);
        return output;
      };

      // A receipt from a DIFFERENT store must not verify merely because its
      // checkpoint hash still looks well-formed.
      await assertRejectsWithCode(
        verifyEvidenceBundle(
          await build('store', (receipt) => {
            receipt.storeId = crypto.randomUUID();
          }),
        ),
        [
          'BUNDLE_RECEIPT_STORE_MISMATCH',
          'BUNDLE_RECEIPT_SIGNATURE_INVALID',
          'AUDIT_CORRUPTION_DETECTED',
        ],
      );

      await assertRejectsWithCode(
        verifyEvidenceBundle(
          await build('key', (receipt) => {
            receipt.anchorKeyFingerprint = 'b'.repeat(64);
          }),
        ),
        [
          'BUNDLE_RECEIPT_KEY_MISMATCH',
          'BUNDLE_RECEIPT_SIGNATURE_INVALID',
          'AUDIT_CORRUPTION_DETECTED',
        ],
      );
    });

    test('RC06-T7-REG-43: bundle digesting streams rather than loading artifacts into memory', async () => {
      // A store whose active segment is comfortably larger than one read chunk,
      // so a whole-file read would be plainly observable in the implementation.
      const fixture = makeAuditConfig('reg43');
      await buildStore(fixture, { records: 200, rotateAt: [100] });

      const base = newRoot('reg43-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      const largest = Object.entries(result.manifest.files)
        .filter(([name]) => name.startsWith('audit/'))
        .sort((a, b) => b[1].bytes - a[1].bytes)[0];
      assert.ok(
        largest[1].bytes > 65_536,
        `the fixture must exceed one read chunk, got ${largest[1].bytes} bytes`,
      );

      // The manifest digest is the digest of the file, computed by the verifier.
      const verified = await verifyEvidenceBundle(result.outputDirectory);
      assert.equal(verified.status, 'VERIFIED');

      // Structural guard: the compiled digest path must not read a whole
      // artifact into memory. A regression to `readFileSync` would fail here.
      const compiled = fs.readFileSync(
        path.join(REPO_ROOT, 'packages/audit/dist/export.js'),
        'utf8',
      );
      const digestFn = compiled.slice(compiled.indexOf('function digestFile'));
      const body = digestFn.slice(0, digestFn.indexOf('\n}'));
      assert.equal(
        /readFileSync/.test(body),
        false,
        'bundle digesting must stream, never read a whole artifact into memory',
      );
      assert.match(body, /readSync/, 'bundle digesting must read in bounded chunks');
    });

    test('RC06-T7-REG-44: an unterminated bundled record is rejected, not silently accepted', async () => {
      const fixture = await multiSegmentFixture('reg44');
      const base = newRoot('reg44-out');
      const result = await exportEvidenceBundle({
        directory: fixture.auditDir,
        outputDirectory: path.join(base, 'bundle'),
        checkpointPublicKeyPath: fixture.checkpoint.publicKeyPath,
        workspacePaths: [],
      });

      // Strip the final LF from the bundled active segment and repair the
      // manifest digest, so the framing rule — not the digest — is what fires.
      const relative = 'audit/audit-active.jsonl';
      const raw = fs.readFileSync(path.join(result.outputDirectory, relative), 'utf8');
      assert.equal(raw.endsWith('\n'), true, 'the emitted artifact is LF-terminated');
      rewriteBundleFile(result.outputDirectory, relative, Buffer.from(raw.slice(0, -1), 'utf8'));

      await assertRejectsWithCode(verifyEvidenceBundle(result.outputDirectory), [
        'AUDIT_CORRUPTION_DETECTED',
        'BUNDLE_LINE_FRAMING_INVALID',
      ]);
    });
  });
});
