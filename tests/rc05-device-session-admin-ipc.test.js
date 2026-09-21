/**
 * CesSpace ARC — RC-05 Task 9: Operator Device and Session Administration
 *
 * Covers the device and session administration methods added to the EXISTING
 * authenticated local admin IPC channel: `devices.list`, `devices.inspect`,
 * `device.revoke`, `device.rename`, `device.pin.add`, `device.pin.remove`,
 * `sessions.list`, and `session.revoke`.
 *
 * Every case drives the REAL composition end to end: a real `ArcMcpServer` in
 * remote mode over a real TLS 1.3 mTLS listener, the REAL Task-8 Streamable HTTP
 * surface, the REAL Task-5 session authority, the REAL Task-1 durable trust
 * store, and the REAL RC-04 Ed25519 challenge-response admin channel. Device
 * administration is asserted against the SAME trust store remote authentication
 * reads, so "the operator changed it" and "the next remote request observes it"
 * are proven by the same fixture.
 *
 * All X.509 material is generated ephemerally by the shared test PKI helper and
 * removed with the temporary directory; no certificate or key is committed and
 * no scanner suppression is used.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { once } from 'node:events';

import {
  ADMIN_MAX_DISPLAY_LABEL_BYTES,
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
import { EnrollmentBootstrap } from '../apps/mcp-server/dist/enrollment-bootstrap.js';
import { GatewayDeviceAdministration } from '../apps/mcp-server/dist/device-administration.js';
import {
  MCP_ADMISSION_ERROR_CODE,
  MCP_POST_REPLY_STATUS,
} from '../apps/mcp-server/dist/remote-execution.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import {
  DeviceTrustStore,
  EnrollmentManager,
  SessionManager,
  deriveSpkiPin,
} from '../packages/auth/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const publicHostname = 'localhost';

let tempRoot;
let workspaceDir;
let pki;
let counter = 0;

before(() => {
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 drives real mTLS connections and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-administration-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# workspace\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** A private 0700 directory, as the admin channel's parent must be. */
function makeSecureDir(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyB64: exportPublicKeyB64(publicKey) };
}

/** Canonical SPKI pin shape, for devices no certificate in this suite holds. */
function syntheticPin(seed) {
  return crypto.createHash('sha256').update(`task9-pin-${seed}`, 'utf8').digest('hex');
}

/**
 * Named mTLS client identities.
 *
 * `primary` is the PKI helper's default client certificate; every other name is
 * issued on demand from the SAME trusted CA, so each one is a genuine,
 * chain-valid mTLS peer whose only distinguishing property is its SPKI pin.
 */
const clientCache = new Map();

function clientFor(name) {
  const cached = clientCache.get(name);
  if (cached !== undefined) {
    return cached;
  }
  const issued =
    name === 'primary'
      ? { certPath: pki.clientCertPath, keyPath: pki.clientKeyPath }
      : pki.issueTrustedClientCert({ commonName: `task9-${name}-${(counter += 1)}` });
  const client = {
    ...issued,
    pin: deriveSpkiPin(fs.readFileSync(issued.certPath, 'utf8')),
  };
  clientCache.set(name, client);
  return client;
}

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
 * Writes a Task-1 trust store holding `entries` and returns its path plus the
 * enrolled records. Entries are `{ pin, clientId, clientType?, displayLabel?,
 * revoked? }`.
 */
function writeTrustStore(tag, entries) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  const records = [];
  for (const entry of entries) {
    const { device } = store.enrollDevice({
      clientId: entry.clientId,
      clientType: entry.clientType ?? 'claude-code',
      pin: entry.pin,
      ...(entry.displayLabel === undefined ? {} : { displayLabel: entry.displayLabel }),
    });
    records.push({ ...device, pin: entry.pin });
  }
  for (const entry of entries) {
    if (entry.revoked === true) {
      store.revokeDevice(records.find((record) => record.pin === entry.pin).deviceId);
    }
  }
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, records };
}

/**
 * Starts a REAL remote-mode `ArcMcpServer` over real mTLS, optionally with the
 * REAL authenticated local admin channel composed in.
 *
 * The server is constructed directly rather than through the factory so a case
 * can inject the Task-5 session authority (to drive the monotonic session clock
 * deterministically). That injection is composition-only: it is unreachable
 * from `ArcServerConfig`, the environment, the CLI, and the network.
 */
async function startRemote({ tag = 'admin', storePath, records, admin = true, sessionClock } = {}) {
  const port = await freePort();
  const registry = new WorkspaceRegistry();
  const audit = new AuditLogger();
  const adminSocketDir = admin ? makeSecureDir(`${tag}-admin`) : undefined;
  const endpoint = admin ? path.join(adminSocketDir, 'admin.sock') : undefined;
  const operator = admin ? generateOperator() : undefined;

  const adminIpcServer = admin
    ? new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: new ApprovalStateManager(),
        auditLogger: audit,
      })
    : undefined;

  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    audit,
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'remote',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      // RC-06 Task 6: `start()` binds no transport until the durable audit
      // runtime has reached startup step 12.
      audit: createAuditConfig(tempRoot, `device-session-${tag}`),
      remote: {
        bindHost: '127.0.0.1',
        port,
        publicHostname,
        serverCertificatePath: pki.serverCertPath,
        privateKey: { kind: 'file', path: pki.serverKeyPath },
        clientCaPaths: [pki.trustedCaCertPath],
        trustStorePath: storePath,
      },
    },
    undefined,
    undefined,
    new ApprovalStateManager(),
    adminIpcServer,
    undefined,
    sessionClock === undefined
      ? undefined
      : new SessionManager({ getMonotonicTime: () => BigInt(sessionClock.now) * 1_000_000n }),
  );
  await server.start();
  return { server, port, endpoint, operator, adminIpcServer, audit, records, storePath };
}

/** One real HTTPS request over mTLS, as `client`. */
function request(port, client, { method = 'POST', headers = {}, body, requestPath = '/mcp' } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(client.certPath),
        key: fs.readFileSync(client.keyPath),
        headers: { Host: publicHostname, ...headers },
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
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

const MCP_POST_HEADERS = {
  Accept: 'application/json, text/event-stream',
  'Content-Type': 'application/json',
};

/** A JSON-RPC tool call for the shared-pipeline `health` tool. */
function toolCallBody(id) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: 'health', arguments: {} },
  });
}

/**
 * Extracts the JSON-RPC payload from a Streamable HTTP response body.
 *
 * The transport answers a POST either as a bare JSON document or as one SSE
 * `data:` frame, so both are accepted and the payload is what is asserted on.
 */
function payloadOf(body) {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed);
  }
  const dataLine = trimmed.split('\n').find((line) => line.startsWith('data:'));
  assert.ok(dataLine !== undefined, `no JSON-RPC payload in: ${trimmed.slice(0, 200)}`);
  return JSON.parse(dataLine.slice('data:'.length).trim());
}

/** Asserts an MCP-framed refusal with a specific Arc error code (§25 framing). */
function assertMcpRefusal(res, label, arcCode) {
  assert.equal(res.status, MCP_POST_REPLY_STATUS, `${label}: ${res.status} ${res.body}`);
  assert.equal(res.headers['content-type'], 'application/json', label);
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.jsonrpc, '2.0', label);
  assert.equal(parsed.error.code, MCP_ADMISSION_ERROR_CODE, label);
  assert.equal(parsed.error.data.code, arcCode, label);
  return parsed;
}

/** Performs the tokenless `initialize` handshake and returns its credentials. */
async function initializeSession(port, client) {
  const res = await request(port, client, {
    method: 'POST',
    headers: MCP_POST_HEADERS,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'rc05-task9-test', version: '1.0.0' },
      },
    }),
  });
  return {
    res,
    status: res.status,
    sessionId: res.headers['mcp-session-id'],
    token: res.headers['arc-session-token'],
  };
}

/** One authenticated `tools/call` with the dual session headers. */
function authenticatedCall(port, client, sessionId, token, id = 2) {
  return request(port, client, {
    method: 'POST',
    headers: {
      ...MCP_POST_HEADERS,
      'Mcp-Session-Id': sessionId,
      Authorization: `Bearer ${token}`,
    },
    body: toolCallBody(id),
  });
}

/** Waits for a condition, so a release is observed rather than slept through. */
async function waitFor(predicate, budgetMs = 3000) {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    if (predicate()) {
      return true;
    }
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

// ---------------------------------------------------------------------------
// Admin channel client (the SAME protocol the operator CLI speaks)
// ---------------------------------------------------------------------------

function readOneFrame(socket, maxBytes) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > maxBytes) {
        cleanup();
        reject(new Error('frame exceeded bound'));
        return;
      }
      const idx = buffer.indexOf(0x0a);
      if (idx !== -1) {
        cleanup();
        resolve(buffer.subarray(0, idx));
      }
    };
    const onEnd = () => {
      cleanup();
      reject(new Error('connection ended before a frame arrived'));
    };
    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('end', onEnd);
      socket.removeListener('error', onEnd);
    };
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onEnd);
  });
}

/** One-shot authenticated admin request. */
async function adminRequest(endpoint, privateKey, method, params = {}) {
  const socket = net.createConnection(endpoint);
  await once(socket, 'connect');
  const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));
  const payloadBytes = Buffer.from(
    encodeAdminPayload({
      protocol: ADMIN_PROTOCOL_VERSION,
      challengeId: challenge.challengeId,
      method,
      params,
    }),
    'utf8',
  );
  const signature = signAdminPayload(
    privateKey,
    challenge.challengeId,
    challenge.nonce,
    payloadBytes,
  );
  socket.write(
    `${JSON.stringify({
      payload: payloadBytes.toString('base64'),
      signature: signature.toString('base64'),
    })}\n`,
  );
  const frame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(frame.toString('utf8'));
}

/** The on-disk trust store, read directly, for durability assertions. */
function readStoreFile(storePath) {
  return JSON.parse(fs.readFileSync(storePath, 'utf8'));
}

function deviceOnDisk(storePath, deviceId) {
  return readStoreFile(storePath).devices.find((device) => device.deviceId === deviceId);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

describe('CesSpace ARC — RC-05 Task 9: Device and session administration', () => {
  /**
   * The standard two-device fixture: `primary` is device A (the default client
   * certificate), `secondary` is device B. Both are enrolled and unrevoked.
   */
  async function twoDeviceFixture(tag) {
    const a = clientFor('primary');
    const b = clientFor('secondary');
    const { storePath, records } = writeTrustStore(tag, [
      { pin: a.pin, clientId: 'agent-alpha', displayLabel: 'alpha-laptop' },
      { pin: b.pin, clientId: 'agent-beta', displayLabel: 'beta-desktop' },
    ]);
    const started = await startRemote({ tag, storePath, records });
    return { ...started, a, b, deviceA: records[0], deviceB: records[1] };
  }

  // =========================================================================
  // devices.list / devices.inspect
  // =========================================================================

  describe('devices.list and devices.inspect', () => {
    test('RC05-T9-01: the authenticated operator lists every enrolled device without pins', async () => {
      const fixture = await twoDeviceFixture('list');
      try {
        const response = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'devices.list',
        );
        assert.equal(response.ok, true, JSON.stringify(response));
        assert.deepEqual(Object.keys(response).sort(), ['ok', 'result']);
        assert.deepEqual(Object.keys(response.result).sort(), ['devices']);

        const devices = response.result.devices;
        assert.equal(devices.length, 2);
        for (const device of devices) {
          assert.deepEqual(Object.keys(device).sort(), [
            'activePinCount',
            'clientId',
            'clientType',
            'deviceId',
            'displayLabel',
            'enrolledAt',
            'revoked',
          ]);
          assert.equal(device.activePinCount, 1);
          assert.equal(device.revoked, false);
          assert.match(device.deviceId, /^[0-9a-f]{32}$/);
        }
        assert.deepEqual(devices.map((device) => device.clientId).sort(), [
          'agent-alpha',
          'agent-beta',
        ]);

        // The list view discloses no pin, in any form.
        const serialized = JSON.stringify(response);
        assert.ok(!serialized.includes(fixture.a.pin), 'the list must not disclose a pin');
        assert.ok(!serialized.includes(fixture.b.pin), 'the list must not disclose a pin');
        assert.ok(!serialized.includes('pins'), 'the list has no pins field');

        // Nothing internal leaks either.
        for (const leaked of ['operatorId', 'secret', 'token', 'sessionId', 'privateKey', 'cert']) {
          assert.ok(!serialized.includes(leaked), `${leaked} must not appear in a device list`);
        }
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-02: inspect reports the active public SPKI pins and the revoked state truthfully', async () => {
      const a = clientFor('primary');
      const { storePath, records } = writeTrustStore('inspect', [
        { pin: a.pin, clientId: 'agent-alpha', displayLabel: 'alpha-laptop' },
        { pin: syntheticPin('gone'), clientId: 'agent-retired', revoked: true },
      ]);
      const fixture = await startRemote({ tag: 'inspect', storePath, records });
      try {
        const active = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'devices.inspect',
          { deviceId: records[0].deviceId },
        );
        assert.equal(active.ok, true, JSON.stringify(active));
        assert.deepEqual(Object.keys(active.result).sort(), [
          'activePinCount',
          'clientId',
          'clientType',
          'deviceId',
          'displayLabel',
          'enrolledAt',
          'pins',
          'revoked',
        ]);
        assert.equal(active.result.revoked, false);
        assert.deepEqual(active.result.pins, [a.pin]);

        const revoked = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'devices.inspect',
          { deviceId: records[1].deviceId },
        );
        assert.equal(revoked.ok, true, JSON.stringify(revoked));
        assert.equal(revoked.result.revoked, true);
        assert.deepEqual(revoked.result.pins, [syntheticPin('gone')]);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-03: unknown and malformed device identifiers are bounded refusals', async () => {
      const fixture = await twoDeviceFixture('badid');
      try {
        // Well-formed but unknown: the same bounded code an absent device gets.
        const unknown = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'devices.inspect',
          { deviceId: '0'.repeat(32) },
        );
        assert.equal(unknown.ok, false);
        assert.equal(unknown.error.code, 'NOT_FOUND_OR_NOT_PENDING');
        assert.equal(unknown.result, undefined);
        assert.deepEqual(Object.keys(unknown.error), ['code'], 'no detail may be disclosed');

        // Malformed identifiers are a schema rejection, not a lookup.
        for (const deviceId of ['A'.repeat(32), 'a'.repeat(31), 'a'.repeat(33), '', 'zz']) {
          const malformed = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            'devices.inspect',
            { deviceId },
          );
          assert.equal(malformed.ok, false, deviceId);
          assert.equal(malformed.error.code, 'INVALID_ADMIN_REQUEST', deviceId);
        }
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-04: an unauthenticated caller cannot list devices and state is untouched', async () => {
      const fixture = await twoDeviceFixture('unauth');
      try {
        const attacker = generateOperator();
        const before = readStoreFile(fixture.storePath);

        for (const method of ['devices.list', 'sessions.list']) {
          const response = await adminRequest(fixture.endpoint, attacker.privateKey, method);
          assert.equal(response.ok, false, method);
          assert.equal(response.error.code, 'AUTHENTICATION_FAILED', method);
          assert.equal(response.result, undefined, method);
        }

        assert.deepEqual(readStoreFile(fixture.storePath), before, 'the trust store is unchanged');
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 0);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-05: with no authoritative composition, administration fails closed', async () => {
      // A channel composed WITHOUT a remote trust-store authority — the stdio /
      // no-remote composition. It must refuse rather than load a second store.
      const dir = makeSecureDir('no-authority');
      const endpoint = path.join(dir, 'admin.sock');
      const operator = generateOperator();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: new ApprovalStateManager(),
        auditLogger: new AuditLogger(),
      });
      await server.start();
      try {
        assert.equal(server.getDeviceAdministration(), undefined);

        const before = fs.readdirSync(dir).sort();
        const methods = [
          ['devices.list', {}],
          ['devices.inspect', { deviceId: 'a'.repeat(32) }],
          ['device.revoke', { deviceId: 'a'.repeat(32) }],
          ['device.rename', { deviceId: 'a'.repeat(32), displayLabel: 'x' }],
          ['device.pin.add', { deviceId: 'a'.repeat(32), spkiPin: 'b'.repeat(64) }],
          ['device.pin.remove', { deviceId: 'a'.repeat(32), spkiPin: 'b'.repeat(64) }],
          ['sessions.list', {}],
          ['session.revoke', { sessionId: 'c'.repeat(64) }],
        ];
        for (const [method, params] of methods) {
          const response = await adminRequest(endpoint, operator.privateKey, method, params);
          assert.equal(response.ok, false, method);
          assert.equal(response.error.code, 'ADMINISTRATION_UNAVAILABLE', method);
          assert.equal(response.result, undefined, method);
        }

        // No trust store was created, read, or written anywhere near the channel.
        assert.deepEqual(fs.readdirSync(dir).sort(), before, 'no file may be created');
      } finally {
        await server.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // =========================================================================
  // device.rename
  // =========================================================================

  describe('device.rename', () => {
    test('RC05-T9-06: a rename is durable and survives a restart', async () => {
      const fixture = await twoDeviceFixture('rename');
      const deviceId = fixture.deviceA.deviceId;
      try {
        const renamed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId, displayLabel: 'alpha-renamed' },
        );
        assert.equal(renamed.ok, true, JSON.stringify(renamed));
        assert.deepEqual(Object.keys(renamed.result).sort(), ['deviceId', 'displayLabel']);
        assert.equal(renamed.result.displayLabel, 'alpha-renamed');

        // Durable on disk, through the Task-1 atomic persistence path.
        assert.equal(deviceOnDisk(fixture.storePath, deviceId).displayLabel, 'alpha-renamed');
      } finally {
        await fixture.server.stop();
      }

      // A fresh process over the SAME file reproduces the successful state.
      const restarted = await startRemote({
        tag: 'rename-restart',
        storePath: fixture.storePath,
        records: fixture.records,
      });
      try {
        const inspected = await adminRequest(
          restarted.endpoint,
          restarted.operator.privateKey,
          'devices.inspect',
          { deviceId },
        );
        assert.equal(inspected.ok, true);
        assert.equal(inspected.result.displayLabel, 'alpha-renamed');
      } finally {
        await restarted.server.stop();
      }
    });

    test('RC05-T9-07: the display label is bounded at 64 UTF-8 bytes and NUL is refused', async () => {
      const fixture = await twoDeviceFixture('rename-bounds');
      const deviceId = fixture.deviceA.deviceId;
      try {
        // Exactly 64 ASCII bytes: accepted.
        const atLimit = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId, displayLabel: 'x'.repeat(ADMIN_MAX_DISPLAY_LABEL_BYTES) },
        );
        assert.equal(atLimit.ok, true, JSON.stringify(atLimit));
        assert.equal(atLimit.result.displayLabel.length, 64);

        // 64 UTF-8 bytes across multi-byte characters: also accepted.
        const multiByte = 'é'.repeat(32);
        assert.equal(Buffer.byteLength(multiByte, 'utf8'), 64);
        const accepted = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId, displayLabel: multiByte },
        );
        assert.equal(accepted.ok, true, JSON.stringify(accepted));

        const before = readStoreFile(fixture.storePath);
        for (const displayLabel of [
          'x'.repeat(ADMIN_MAX_DISPLAY_LABEL_BYTES + 1),
          'é'.repeat(33),
          'nul\u0000label',
        ]) {
          const refused = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            'device.rename',
            { deviceId, displayLabel },
          );
          assert.equal(refused.ok, false, JSON.stringify(displayLabel));
          assert.equal(refused.error.code, 'INVALID_ADMIN_REQUEST', JSON.stringify(displayLabel));
        }
        assert.deepEqual(readStoreFile(fixture.storePath), before, 'state must be unchanged');
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-08: a rename changes no identity, binding, pin, or live session', async () => {
      const fixture = await twoDeviceFixture('rename-safe');
      const deviceId = fixture.deviceA.deviceId;
      try {
        const session = await initializeSession(fixture.port, fixture.a);
        assert.equal(session.status, 200, session.res.body);
        const before = deviceOnDisk(fixture.storePath, deviceId);

        const renamed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId, displayLabel: 'renamed-in-place' },
        );
        assert.equal(renamed.ok, true, JSON.stringify(renamed));

        const after = deviceOnDisk(fixture.storePath, deviceId);
        assert.equal(after.deviceId, before.deviceId);
        assert.equal(after.clientId, before.clientId);
        assert.equal(after.clientType, before.clientType);
        assert.deepEqual(after.pins, before.pins);
        assert.equal(after.enrolledAt, before.enrolledAt);
        assert.equal(after.revoked, before.revoked);

        // The live session is unaffected: renaming is not an authorization event.
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 1);
        const call = await authenticatedCall(
          fixture.port,
          fixture.a,
          session.sessionId,
          session.token,
        );
        assert.equal(call.status, 200, `${call.status} ${call.body}`);
        assert.equal(payloadOf(call.body).error, undefined, call.body);
      } finally {
        await fixture.server.stop();
      }
    });
  });

  // =========================================================================
  // device.pin.add / device.pin.remove — the §7 P-7 rotation overlap window
  // =========================================================================

  describe('pin overlap window', () => {
    test('RC05-T9-09: a second pin joins the overlap window and BOTH authenticate', async () => {
      const fixture = await twoDeviceFixture('pin-add');
      const deviceId = fixture.deviceA.deviceId;
      const rotation = clientFor('rotation');
      try {
        // Before: the rotation certificate is unknown to the gateway.
        const refusedBefore = await initializeSession(fixture.port, rotation);
        assert.equal(refusedBefore.status, 200, refusedBefore.res.body);
        assert.equal(payloadOf(refusedBefore.res.body).error.data.code, 'UNAUTHENTICATED');
        assert.equal(refusedBefore.sessionId, undefined);

        const added = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId, spkiPin: rotation.pin },
        );
        assert.equal(added.ok, true, JSON.stringify(added));
        assert.deepEqual(Object.keys(added.result).sort(), ['activePinCount', 'deviceId']);
        assert.equal(added.result.activePinCount, 2);

        // Durable immediately.
        assert.deepEqual(deviceOnDisk(fixture.storePath, deviceId).pins, [
          fixture.a.pin,
          rotation.pin,
        ]);

        // Both pins authenticate during the overlap.
        for (const client of [fixture.a, rotation]) {
          const session = await initializeSession(fixture.port, client);
          assert.equal(session.status, 200, `${session.res.body}`);
          assert.equal(payloadOf(session.res.body).error, undefined, session.res.body);
          assert.match(session.sessionId, /^[0-9a-f]{64}$/);
        }
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 2);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-10: a third pin is refused and existing pins are untouched', async () => {
      const fixture = await twoDeviceFixture('pin-ceiling');
      const deviceId = fixture.deviceA.deviceId;
      try {
        const first = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId, spkiPin: clientFor('ceiling-a').pin },
        );
        assert.equal(first.ok, true, JSON.stringify(first));
        const full = readStoreFile(fixture.storePath);

        const third = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId, spkiPin: clientFor('ceiling-b').pin },
        );
        assert.equal(third.ok, false);
        assert.equal(third.error.code, 'RESOURCE_EXHAUSTED');
        assert.deepEqual(readStoreFile(fixture.storePath), full, 'state must be unchanged');
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-11: a pin already bound to another device is refused', async () => {
      const fixture = await twoDeviceFixture('pin-collision');
      try {
        const before = readStoreFile(fixture.storePath);
        const collision = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId: fixture.deviceA.deviceId, spkiPin: fixture.b.pin },
        );
        assert.equal(collision.ok, false);
        assert.equal(collision.error.code, 'INVALID_ADMIN_REQUEST');
        assert.deepEqual(readStoreFile(fixture.storePath), before, 'state must be unchanged');

        // Re-adding a pin the device already holds is a safe no-op.
        const idempotent = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId: fixture.deviceA.deviceId, spkiPin: fixture.a.pin },
        );
        assert.equal(idempotent.ok, true, JSON.stringify(idempotent));
        assert.equal(idempotent.result.activePinCount, 1);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-12: removing the rotation pin closes the window immediately', async () => {
      const fixture = await twoDeviceFixture('pin-remove');
      const deviceId = fixture.deviceA.deviceId;
      const rotation = clientFor('retire');
      try {
        const added = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.add',
          { deviceId, spkiPin: rotation.pin },
        );
        assert.equal(added.ok, true, JSON.stringify(added));

        // The rotation certificate works while the overlap is open.
        const duringOverlap = await initializeSession(fixture.port, rotation);
        assert.equal(payloadOf(duringOverlap.res.body).error, undefined, duringOverlap.res.body);

        const removed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.remove',
          { deviceId, spkiPin: fixture.a.pin },
        );
        assert.equal(removed.ok, true, JSON.stringify(removed));
        assert.equal(removed.result.activePinCount, 1);
        assert.deepEqual(deviceOnDisk(fixture.storePath, deviceId).pins, [rotation.pin]);

        // The REMOVED pin no longer authenticates on the very next request.
        const retired = await initializeSession(fixture.port, fixture.a);
        const refusal = assertMcpRefusal(retired.res, 'removed pin', 'UNAUTHENTICATED');
        assert.equal(refusal.id, 1);
        assert.equal(retired.sessionId, undefined);

        // The RETAINED pin still does.
        const retained = await initializeSession(fixture.port, rotation);
        assert.equal(retained.status, 200, retained.res.body);
        assert.match(retained.sessionId, /^[0-9a-f]{64}$/);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-13: removing the final pin is refused and nothing changes', async () => {
      const fixture = await twoDeviceFixture('pin-final');
      const deviceId = fixture.deviceA.deviceId;
      try {
        const before = readStoreFile(fixture.storePath);
        const refused = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.remove',
          { deviceId, spkiPin: fixture.a.pin },
        );
        assert.equal(refused.ok, false);
        assert.equal(refused.error.code, 'INVALID_ADMIN_REQUEST');
        assert.deepEqual(readStoreFile(fixture.storePath), before, 'state must be unchanged');

        // The sole pin still authenticates, because the device never went to zero.
        const session = await initializeSession(fixture.port, fixture.a);
        assert.equal(session.status, 200, session.res.body);
        assert.match(session.sessionId, /^[0-9a-f]{64}$/);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-14: pin administration refuses a malformed pin or an unknown device', async () => {
      const fixture = await twoDeviceFixture('pin-bad');
      const deviceId = fixture.deviceA.deviceId;
      try {
        const before = readStoreFile(fixture.storePath);
        for (const spkiPin of ['A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), '', 'zz']) {
          const malformed = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            'device.pin.add',
            { deviceId, spkiPin },
          );
          assert.equal(malformed.ok, false, spkiPin);
          assert.equal(malformed.error.code, 'INVALID_ADMIN_REQUEST', spkiPin);
        }

        for (const method of ['device.pin.add', 'device.pin.remove']) {
          const unknown = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            method,
            {
              deviceId: '0'.repeat(32),
              spkiPin: syntheticPin('unknown-device'),
            },
          );
          assert.equal(unknown.ok, false, method);
          assert.equal(unknown.error.code, 'NOT_FOUND_OR_NOT_PENDING', method);
        }
        assert.deepEqual(readStoreFile(fixture.storePath), before, 'state must be unchanged');
      } finally {
        await fixture.server.stop();
      }
    });
  });

  // =========================================================================
  // device.revoke
  // =========================================================================

  describe('device.revoke', () => {
    test('RC05-T9-15: revocation is durable, revokes every session for the device, and spares others', async () => {
      const fixture = await twoDeviceFixture('revoke');
      const deviceId = fixture.deviceA.deviceId;
      try {
        // One live session per device.
        const alpha = await initializeSession(fixture.port, fixture.a);
        const beta = await initializeSession(fixture.port, fixture.b);
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 2);
        assert.match(alpha.sessionId, /^[0-9a-f]{64}$/);
        assert.match(beta.sessionId, /^[0-9a-f]{64}$/);

        const revoked = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.revoke',
          { deviceId },
        );
        assert.equal(revoked.ok, true, JSON.stringify(revoked));
        assert.deepEqual(Object.keys(revoked.result).sort(), [
          'deviceId',
          'revoked',
          'sessionsRevoked',
          'transportsClosed',
        ]);
        assert.equal(revoked.result.revoked, true);
        assert.equal(revoked.result.sessionsRevoked, 1);
        assert.equal(revoked.result.transportsClosed, 1);

        // Durable, and it survives a restart.
        assert.equal(deviceOnDisk(fixture.storePath, deviceId).revoked, true);

        // The revoked device's session is gone; the other device's is not.
        assert.equal(fixture.server.sessionManager.hasSession(alpha.sessionId), false);
        assert.equal(fixture.server.sessionManager.hasSession(beta.sessionId), true);

        // The old credential is refused, with or without its session ID.
        for (const headers of [
          { 'Mcp-Session-Id': alpha.sessionId, Authorization: `Bearer ${alpha.token}` },
          { Authorization: `Bearer ${alpha.token}` },
        ]) {
          const stale = await request(fixture.port, fixture.a, {
            method: 'POST',
            headers: { ...MCP_POST_HEADERS, ...headers },
            body: toolCallBody(7),
          });
          assertMcpRefusal(stale, 'revoked device credential', 'INVALID_SESSION_TOKEN');
        }

        // Fresh authentication from the revoked device is generically refused.
        const fresh = await initializeSession(fixture.port, fixture.a);
        assertMcpRefusal(fresh.res, 'revoked device fresh auth', 'UNAUTHENTICATED');
        assert.equal(fresh.sessionId, undefined);
        assert.equal(fresh.token, undefined);

        // The OTHER device is entirely unaffected.
        const survivor = await authenticatedCall(
          fixture.port,
          fixture.b,
          beta.sessionId,
          beta.token,
        );
        assert.equal(survivor.status, 200, `${survivor.status} ${survivor.body}`);
        assert.equal(payloadOf(survivor.body).error, undefined, survivor.body);
      } finally {
        await fixture.server.stop();
      }

      const restarted = await startRemote({
        tag: 'revoke-restart',
        storePath: fixture.storePath,
        records: fixture.records,
      });
      try {
        assert.equal(deviceOnDisk(restarted.storePath, deviceId).revoked, true);
        const afterRestart = await initializeSession(restarted.port, fixture.a);
        assertMcpRefusal(afterRestart.res, 'revoked device after restart', 'UNAUTHENTICATED');
      } finally {
        await restarted.server.stop();
      }
    });

    test('RC05-T9-16: revoking an unknown device mutates nothing and revokes no session', async () => {
      const fixture = await twoDeviceFixture('revoke-unknown');
      try {
        const session = await initializeSession(fixture.port, fixture.a);
        const before = readStoreFile(fixture.storePath);

        const refused = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.revoke',
          { deviceId: '0'.repeat(32) },
        );
        assert.equal(refused.ok, false);
        assert.equal(refused.error.code, 'NOT_FOUND_OR_NOT_PENDING');

        assert.deepEqual(readStoreFile(fixture.storePath), before, 'the trust store is unchanged');
        assert.equal(
          fixture.server.sessionManager.hasSession(session.sessionId),
          true,
          'no session may be revoked for a revocation that never committed',
        );
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-17: revoking a device closes its live Task-8 SSE transport immediately', async () => {
      const fixture = await twoDeviceFixture('revoke-stream');
      try {
        const session = await initializeSession(fixture.port, fixture.a);
        assert.match(session.sessionId, /^[0-9a-f]{64}$/);

        // Open the real server-to-client SSE stream for that session.
        const stream = await new Promise((resolve, reject) => {
          const req = https.request(
            {
              host: '127.0.0.1',
              port: fixture.port,
              method: 'GET',
              path: '/mcp',
              servername: publicHostname,
              ca: [fs.readFileSync(pki.trustedCaCertPath)],
              cert: fs.readFileSync(fixture.a.certPath),
              key: fs.readFileSync(fixture.a.keyPath),
              headers: {
                Host: publicHostname,
                Accept: 'text/event-stream',
                'Mcp-Session-Id': session.sessionId,
                Authorization: `Bearer ${session.token}`,
              },
            },
            (res) => {
              const state = { ended: false };
              res.on('data', () => {});
              res.on('end', () => {
                state.ended = true;
              });
              res.on('close', () => {
                state.ended = true;
              });
              resolve({ req, state, status: res.statusCode });
            },
          );
          req.on('error', reject);
          req.end();
        });
        assert.equal(stream.status, 200, 'the authenticated stream must open');
        assert.equal(stream.state.ended, false, 'the stream is live before revocation');

        const revoked = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.revoke',
          { deviceId: fixture.deviceA.deviceId },
        );
        assert.equal(revoked.ok, true, JSON.stringify(revoked));
        assert.equal(revoked.result.transportsClosed, 1);

        // The SDK transport object is closed as part of the revocation, not on
        // the client's next request: the open stream ends by itself.
        assert.equal(
          await waitFor(() => stream.state.ended),
          true,
          'the revoked device transport must be closed immediately',
        );
        stream.req.destroy();
      } finally {
        await fixture.server.stop();
      }
    });
  });

  // =========================================================================
  // sessions.list / session.revoke
  // =========================================================================

  describe('sessions.list and session.revoke', () => {
    test('RC05-T9-18: listing reports only live sessions and discloses no credential', async () => {
      const fixture = await twoDeviceFixture('sessions-list');
      try {
        const empty = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'sessions.list',
        );
        assert.equal(empty.ok, true, JSON.stringify(empty));
        assert.deepEqual(empty.result, { sessions: [] });

        const alpha = await initializeSession(fixture.port, fixture.a);
        const beta = await initializeSession(fixture.port, fixture.b);

        const listed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'sessions.list',
        );
        assert.equal(listed.ok, true, JSON.stringify(listed));
        assert.deepEqual(Object.keys(listed.result).sort(), ['sessions']);
        assert.equal(listed.result.sessions.length, 2);
        for (const session of listed.result.sessions) {
          assert.deepEqual(Object.keys(session).sort(), [
            'clientId',
            'clientType',
            'deviceId',
            'issuedAt',
            'sessionId',
            'state',
          ]);
          assert.equal(session.state, 'ACTIVE');
          assert.match(session.sessionId, /^[0-9a-f]{64}$/);
          assert.match(session.deviceId, /^[0-9a-f]{32}$/);
        }
        assert.deepEqual(listed.result.sessions.map((session) => session.clientId).sort(), [
          'agent-alpha',
          'agent-beta',
        ]);

        // Neither the raw one-time token nor any other credential material is
        // disclosed, in any form.
        const serialized = JSON.stringify(listed);
        for (const secret of [alpha.token, beta.token]) {
          assert.ok(!serialized.includes(secret), 'a session token must never be listed');
          assert.ok(
            !serialized.includes(crypto.createHash('sha256').update(secret, 'utf8').digest('hex')),
            'a session token digest must never be listed',
          );
        }
        for (const leaked of [
          'Authorization',
          'Bearer',
          'spkiPin',
          'token',
          'digest',
          'lastAuthMonotonic',
          'createdMonotonic',
          'limiterKey',
          'certificate',
        ]) {
          assert.ok(!serialized.includes(leaked), `${leaked} must not appear in a session list`);
        }
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-19: revoking one session affects exactly that session', async () => {
      const fixture = await twoDeviceFixture('session-revoke');
      try {
        // Two live sessions on the SAME device, so the only thing distinguishing
        // them is the session identifier itself.
        const first = await initializeSession(fixture.port, fixture.a);
        const second = await initializeSession(fixture.port, fixture.a);
        assert.notEqual(first.sessionId, second.sessionId);

        const revoked = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: first.sessionId },
        );
        assert.equal(revoked.ok, true, JSON.stringify(revoked));
        assert.deepEqual(Object.keys(revoked.result).sort(), [
          'sessionId',
          'state',
          'transportClosed',
        ]);
        assert.equal(revoked.result.sessionId, first.sessionId);
        assert.equal(revoked.result.state, 'REVOKED');
        assert.equal(revoked.result.transportClosed, true);

        // The revoked credential fails; the other one is untouched.
        const stale = await authenticatedCall(
          fixture.port,
          fixture.a,
          first.sessionId,
          first.token,
        );
        assertMcpRefusal(stale, 'revoked session', 'INVALID_SESSION_TOKEN');

        const survivor = await authenticatedCall(
          fixture.port,
          fixture.a,
          second.sessionId,
          second.token,
        );
        assert.equal(survivor.status, 200, `${survivor.status} ${survivor.body}`);
        assert.equal(payloadOf(survivor.body).error, undefined, survivor.body);

        assert.equal(fixture.server.sessionManager.hasSession(first.sessionId), false);
        assert.equal(fixture.server.sessionManager.hasSession(second.sessionId), true);
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 1);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-20: an unknown, malformed, or already-revoked session is one bounded refusal', async () => {
      const fixture = await twoDeviceFixture('session-revoke-bad');
      try {
        const session = await initializeSession(fixture.port, fixture.a);

        // Unknown: the same bounded code an absent session gets.
        const unknown = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: '0'.repeat(64) },
        );
        assert.equal(unknown.ok, false);
        assert.equal(unknown.error.code, 'NOT_FOUND_OR_NOT_PENDING');
        assert.deepEqual(Object.keys(unknown.error), ['code'], 'no detail may be disclosed');

        // Malformed identifiers never reach the session authority.
        for (const sessionId of ['A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), '', 'zz']) {
          const malformed = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            'session.revoke',
            { sessionId },
          );
          assert.equal(malformed.ok, false, sessionId);
          assert.equal(malformed.error.code, 'INVALID_ADMIN_REQUEST', sessionId);
        }

        // The target session survived every one of those.
        assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);

        // Already revoked: the same bounded refusal, and still no cross-session
        // mutation.
        const first = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: session.sessionId },
        );
        assert.equal(first.ok, true, JSON.stringify(first));
        const again = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: session.sessionId },
        );
        assert.equal(again.ok, false);
        assert.equal(again.error.code, 'NOT_FOUND_OR_NOT_PENDING');
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 0);
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-21: revoking a session closes its Task-8 SSE transport immediately', async () => {
      const fixture = await twoDeviceFixture('session-stream');
      try {
        const session = await initializeSession(fixture.port, fixture.a);
        const stream = await new Promise((resolve, reject) => {
          const req = https.request(
            {
              host: '127.0.0.1',
              port: fixture.port,
              method: 'GET',
              path: '/mcp',
              servername: publicHostname,
              ca: [fs.readFileSync(pki.trustedCaCertPath)],
              cert: fs.readFileSync(fixture.a.certPath),
              key: fs.readFileSync(fixture.a.keyPath),
              headers: {
                Host: publicHostname,
                Accept: 'text/event-stream',
                'Mcp-Session-Id': session.sessionId,
                Authorization: `Bearer ${session.token}`,
              },
            },
            (res) => {
              const state = { ended: false };
              res.on('data', () => {});
              res.on('end', () => {
                state.ended = true;
              });
              res.on('close', () => {
                state.ended = true;
              });
              resolve({ req, state, status: res.statusCode });
            },
          );
          req.on('error', reject);
          req.end();
        });
        assert.equal(stream.status, 200);
        assert.equal(stream.state.ended, false);

        const revoked = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: session.sessionId },
        );
        assert.equal(revoked.ok, true, JSON.stringify(revoked));
        assert.equal(revoked.result.transportClosed, true);
        assert.equal(
          await waitFor(() => stream.state.ended),
          true,
          'the revoked session transport must be closed immediately',
        );
        stream.req.destroy();
      } finally {
        await fixture.server.stop();
      }
    });

    test('RC05-T9-22: expired sessions are absent from the listing', async () => {
      const sessionClock = { now: 1_000_000 };
      const a = clientFor('primary');
      const { storePath, records } = writeTrustStore('expiry', [
        { pin: a.pin, clientId: 'agent-alpha' },
      ]);
      const fixture = await startRemote({ tag: 'expiry', storePath, records, sessionClock });
      try {
        const session = await initializeSession(fixture.port, a);
        assert.match(session.sessionId, /^[0-9a-f]{64}$/);

        const listed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'sessions.list',
        );
        assert.equal(listed.ok, true);
        assert.equal(listed.result.sessions.length, 1);

        // Past the idle timeout, the session is no longer live and Task 5's own
        // purge removes it, so it cannot appear in an operator listing.
        sessionClock.now += 301_000;
        assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 0);

        const expired = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'sessions.list',
        );
        assert.equal(expired.ok, true);
        assert.deepEqual(expired.result, { sessions: [] });

        const revokeExpired = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'session.revoke',
          { sessionId: session.sessionId },
        );
        assert.equal(revokeExpired.ok, false);
        assert.equal(revokeExpired.error.code, 'NOT_FOUND_OR_NOT_PENDING');
      } finally {
        await fixture.server.stop();
      }
    });
  });

  // =========================================================================
  // Closed per-method parameter schema
  // =========================================================================

  describe('closed per-method schema', () => {
    test('RC05-T9-23: administration parameters are refused on approval and enrollment methods', async () => {
      const fixture = await twoDeviceFixture('cross-params');
      try {
        const deviceId = fixture.deviceA.deviceId;
        const session = await initializeSession(fixture.port, fixture.a);
        const crossParams = {
          deviceId,
          sessionId: session.sessionId,
          spkiPin: fixture.a.pin,
          displayLabel: 'nope',
        };

        for (const [method, params] of [
          ['devices.list', { deviceId }],
          ['devices.inspect', { deviceId, sessionId: session.sessionId }],
          ['session.revoke', { sessionId: session.sessionId, deviceId }],
          ['device.revoke', { deviceId, spkiPin: fixture.a.pin }],
          ['device.rename', { deviceId, displayLabel: 'ok', reason: 'no' }],
          ['device.pin.add', { deviceId, spkiPin: fixture.a.pin, displayLabel: 'no' }],
        ]) {
          const response = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            method,
            params,
          );
          assert.equal(response.ok, false, method);
          assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST', method);
        }

        // Approval methods reject the new keys too.
        for (const method of ['approvals.list', 'approvals.inspect']) {
          const response = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            method,
            { requestId: 'a'.repeat(32), ...crossParams },
          );
          assert.equal(response.ok, false, method);
          assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST', method);
        }

        // The single live session survived all of it.
        assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
      } finally {
        await fixture.server.stop();
      }
    });
  });

  // =========================================================================
  // Persistence failure, rollback, and the fail-closed latch
  // =========================================================================

  describe('durable write failure', () => {
    /**
     * A channel wired to a REAL `EnrollmentBootstrap` over a REAL trust-store
     * file, with the Task-1 persistence primitive replaced by an injected one.
     *
     * The injection point is `EnrollmentBootstrapOptions.trustStoreStorageForTests`,
     * which is `@internal`, is absent from `ArcServerConfig`, `RemoteConfig`, the
     * environment, the CLI, and every network-reachable surface, and is already
     * used by the Task-4 bootstrap suite. No Task-9 seam is added.
     */
    async function failingStorageFixture({ corruptDestination = false, twoPins = false } = {}) {
      const dir = makeSecureDir('storage');
      const endpoint = path.join(dir, 'admin.sock');
      const operator = generateOperator();
      const a = clientFor('primary');
      const sparePin = syntheticPin('spare');

      counter += 1;
      const storePath = path.join(tempRoot, `devices-storage-${counter}.json`);
      const initial = DeviceTrustStore.createEmpty();
      const { device } = initial.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: a.pin,
        displayLabel: 'alpha',
      });
      if (twoPins) {
        initial.addPinToDevice(device.deviceId, sparePin);
      }
      initial.saveToFile(storePath);
      fs.chmodSync(storePath, 0o600);
      const records = [{ ...device, pin: a.pin }];

      const real = DeviceTrustStore.loadFromFile(storePath);
      let failSaves = true;
      let saveAttempts = 0;
      const storage = {
        save: (store, filePath) => {
          saveAttempts += 1;
          if (failSaves) {
            throw new Error('injected durable write failure');
          }
          store.saveToFile(filePath);
        },
        load: (filePath) =>
          corruptDestination
            ? DeviceTrustStore.createEmpty()
            : DeviceTrustStore.loadFromFile(filePath),
      };

      const bootstrap = new EnrollmentBootstrap(new EnrollmentManager(), real, storePath, {
        trustStoreStorageForTests: storage,
      });
      const sessionManager = new SessionManager();
      let teardowns = 0;
      const surfaceStub = {
        async revokeDeviceSessionsForAdmin() {
          teardowns += 1;
          return { sessionsRevoked: 0, transportsClosed: 0 };
        },
        async revokeSessionForAdmin() {
          teardowns += 1;
          return { revoked: false, transportClosed: false };
        },
      };

      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: new ApprovalStateManager(),
        auditLogger: new AuditLogger(),
      });
      server.attachDeviceAdministration(
        new GatewayDeviceAdministration(bootstrap, sessionManager, () => surfaceStub),
      );
      await server.start();

      return {
        server,
        endpoint,
        operator,
        bootstrap,
        storePath,
        deviceId: records[0].deviceId,
        pin: a.pin,
        sparePin,
        dir,
        saveAttempts: () => saveAttempts,
        teardowns: () => teardowns,
        restoreStorage: () => {
          failSaves = false;
        },
        stillFailing: () => failSaves,
      };
    }

    test('RC05-T9-24: a failed durable write is never reported as success', async () => {
      const fixture = await failingStorageFixture();
      try {
        const before = readStoreFile(fixture.storePath);
        const mutations = [
          ['device.rename', { deviceId: fixture.deviceId, displayLabel: 'never-applied' }],
          ['device.pin.add', { deviceId: fixture.deviceId, spkiPin: syntheticPin('unwritten') }],
          ['device.revoke', { deviceId: fixture.deviceId }],
        ];
        for (const [method, params] of mutations) {
          const response = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            method,
            params,
          );
          assert.equal(response.ok, false, method);
          assert.equal(response.error.code, 'ADMINISTRATION_UNAVAILABLE', method);
          assert.equal(response.result, undefined, method);
        }

        // Disk and the authoritative in-memory store both still hold the ORIGINAL
        // state: the operator was never told a mutation happened.
        assert.deepEqual(readStoreFile(fixture.storePath), before, 'disk must be unchanged');
        const device = fixture.bootstrap.snapshotDeviceRecords()[0];
        assert.equal(device.revoked, false);
        assert.equal(device.displayLabel, 'alpha');
        assert.deepEqual(device.pins, [fixture.pin]);

        // The device still authenticates: a revocation that did not commit must
        // not have been half-applied to the running trust root.
        assert.notEqual(fixture.bootstrap.resolveActiveDeviceIdentity(fixture.pin), undefined);

        // ...and no session was revoked for that non-committed revocation.
        assert.equal(fixture.teardowns(), 0, 'a non-durable revocation revokes nothing');
      } finally {
        await fixture.server.stop();
        fs.rmSync(fixture.dir, { recursive: true, force: true });
      }
    });

    test('RC05-T9-24b: a failed durable pin removal leaves BOTH pins installed', async () => {
      const fixture = await failingStorageFixture({ twoPins: true });
      try {
        // A domain-valid removal (the device still holds a spare pin), so the
        // refusal that follows can only come from the failed durable write.
        const before = readStoreFile(fixture.storePath);
        assert.deepEqual(deviceOnDisk(fixture.storePath, fixture.deviceId).pins, [
          fixture.pin,
          fixture.sparePin,
        ]);

        const refused = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.pin.remove',
          { deviceId: fixture.deviceId, spkiPin: fixture.sparePin },
        );
        assert.equal(refused.ok, false);
        assert.equal(refused.error.code, 'ADMINISTRATION_UNAVAILABLE');

        assert.deepEqual(readStoreFile(fixture.storePath), before, 'disk must be unchanged');
        assert.deepEqual(fixture.bootstrap.snapshotDeviceRecords()[0].pins, [
          fixture.pin,
          fixture.sparePin,
        ]);
        // The pin that was NOT durably removed still resolves, so nothing is
        // half-removed from the running trust root.
        assert.notEqual(fixture.bootstrap.resolveActiveDeviceIdentity(fixture.sparePin), undefined);
      } finally {
        await fixture.server.stop();
        fs.rmSync(fixture.dir, { recursive: true, force: true });
      }
    });

    test('RC05-T9-25: a cleanly reconciled failure leaves storage usable and does not latch', async () => {
      const fixture = await failingStorageFixture();
      try {
        const refused = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId: fixture.deviceId, displayLabel: 'first-attempt' },
        );
        assert.equal(refused.ok, false);
        assert.equal(refused.error.code, 'ADMINISTRATION_UNAVAILABLE');
        assert.equal(fixture.bootstrap.isStorageFailureLatched(), false, 'no latch is warranted');

        // The destination was proven unchanged, so the operation is cleanly
        // retryable: with persistence restored it commits.
        fixture.restoreStorage();
        const retried = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.rename',
          { deviceId: fixture.deviceId, displayLabel: 'second-attempt' },
        );
        assert.equal(retried.ok, true, JSON.stringify(retried));
        assert.equal(retried.result.displayLabel, 'second-attempt');
        assert.equal(
          deviceOnDisk(fixture.storePath, fixture.deviceId).displayLabel,
          'second-attempt',
        );
      } finally {
        await fixture.server.stop();
        fs.rmSync(fixture.dir, { recursive: true, force: true });
      }
    });

    test('RC05-T9-26: an unprovable rollback latches storage closed rather than continuing', async () => {
      const fixture = await failingStorageFixture({ corruptDestination: true });
      try {
        const first = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'device.revoke',
          { deviceId: fixture.deviceId },
        );
        assert.equal(first.ok, false);
        assert.equal(first.error.code, 'ADMINISTRATION_UNAVAILABLE');
        assert.equal(
          fixture.bootstrap.isStorageFailureLatched(),
          true,
          'an unprovable rollback must latch the storage closed',
        );
        assert.equal(fixture.teardowns(), 0, 'a non-durable revocation revokes nothing');

        // Every later mutation is refused WITHOUT touching storage again: the
        // gateway does not keep administering an authentication root whose
        // installed state cannot be proven.
        const attemptsAfterLatch = fixture.saveAttempts();
        for (const [method, params] of [
          ['device.rename', { deviceId: fixture.deviceId, displayLabel: 'x' }],
          ['device.revoke', { deviceId: fixture.deviceId }],
        ]) {
          const refused = await adminRequest(
            fixture.endpoint,
            fixture.operator.privateKey,
            method,
            params,
          );
          assert.equal(refused.ok, false, method);
          assert.equal(refused.error.code, 'ADMINISTRATION_UNAVAILABLE', method);
        }
        assert.equal(fixture.saveAttempts(), attemptsAfterLatch, 'no further write is attempted');

        // Reads still report the running trust root truthfully.
        const listed = await adminRequest(
          fixture.endpoint,
          fixture.operator.privateKey,
          'devices.list',
        );
        assert.equal(listed.ok, true, JSON.stringify(listed));
        assert.equal(listed.result.devices.length, 1);
        assert.equal(listed.result.devices[0].revoked, false);
      } finally {
        await fixture.server.stop();
        fs.rmSync(fixture.dir, { recursive: true, force: true });
      }
    });
  });
});
