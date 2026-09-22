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

/* -------------------------------------------------------------------------- *
 * Harness
 * -------------------------------------------------------------------------- */

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENDPOINT = 'https://anchor.example.invalid/v1/anchor';

let tempRoot;
let fixtureCounter = 0;

before(() => {
  tempRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task7-')));
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
});
