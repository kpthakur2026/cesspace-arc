/**
 * CesSpace ARC — RC-05 Positive Acceptance Flows Integration Suite
 *
 * Exercises all eleven frozen positive flows defined in
 * docs/architecture/rc05-scope-acceptance.md §36:
 *
 * 1. Server startup in stdio-only mode
 * 2. Remote gateway startup with zero enrolled devices
 * 3. Remote gateway startup with enrolled devices
 * 4. First-device local enrollment initiation & remote completion
 * 5. Session bootstrap via tokenless initialize
 * 6. Subsequent authenticated tool request with dual headers
 * 7. Ordinary read-only MCP tool invocation
 * 8. Policy REQUIRE_APPROVAL invocation
 * 9. Approval redemption from same authenticated session/device
 * 10. Session expiration and re-authentication
 * 11. Durable device revocation & immediate session teardown
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * shared test PKI helper and removed with it; no certificate or key is
 * committed and no scanner suppression is used.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
import {
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import {
  DeviceTrustStore,
  EnrollmentManager,
  SessionManager,
  deriveSpkiPin,
} from '../packages/auth/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

const publicHostname = 'localhost';
let tempRoot;
let workspaceDir;
let pki;
let counter = 0;

before(() => {
  assert.equal(hasOpenssl(), true, 'RC-05 drives real mTLS connections and requires openssl');
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-pos-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# positive flows\n');
  fs.writeFileSync(path.join(workspaceDir, 'data.txt'), 'hello positive flows\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function clientPin() {
  return deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8'));
}

function makeSecureDir(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyB64: exportPublicKeyB64(publicKey) };
}

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

function createTrustStoreFile(tag, pinCount = 0) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-pos-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  const records = [];
  for (let index = 0; index < pinCount; index += 1) {
    const pin = index === 0 ? clientPin() : `${String(index).repeat(64)}`.slice(0, 64);
    const { device } = store.enrollDevice({
      clientId: `agent-${tag}-${index}`,
      clientType: 'claude-code',
      pin,
      displayLabel: `label-${tag}-${index}`,
    });
    records.push({ ...device, pin });
  }
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, records, store };
}

async function startRemoteServer({
  tag = 'pos',
  pinCount = 1,
  enrollmentManager,
  sessionManager,
  policy,
  approvalStateManager,
  storePath: customStorePath,
  records: customRecords,
  admin = true,
} = {}) {
  const port = await freePort();
  const { storePath, records, store } = customStorePath
    ? { storePath: customStorePath, records: customRecords ?? [], store: null }
    : createTrustStoreFile(tag, pinCount);
  const registry = new WorkspaceRegistry();
  const audit = new AuditLogger();
  const approvals = approvalStateManager ?? new ApprovalStateManager();
  const manager = enrollmentManager ?? new EnrollmentManager();

  const adminSocketDir = admin ? makeSecureDir(`${tag}-admin`) : undefined;
  const endpoint = admin ? path.join(adminSocketDir, 'admin.sock') : undefined;
  const operator = admin ? generateOperator() : undefined;
  const adminIpcServer = admin
    ? new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: approvals,
        auditLogger: audit,
        enrollmentManager: manager,
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
      ...(policy === undefined ? {} : { policy }),
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
    approvals,
    adminIpcServer,
    manager,
    sessionManager,
  );
  await server.start();
  return {
    server,
    port,
    storePath,
    records,
    store,
    audit,
    approvals,
    registry,
    endpoint,
    operator,
    adminIpcServer,
    enrollmentManager: manager,
  };
}

function request(
  port,
  { method = 'POST', requestPath = '/mcp', headers = {}, body, cert, key } = {},
) {
  return new Promise((resolve, reject) => {
    const defaultHeaders = {
      Host: publicHostname,
      ...(method === 'POST' ? { Accept: 'application/json, text/event-stream' } : {}),
      ...(method === 'POST' && body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    };
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: cert ?? fs.readFileSync(pki.clientCertPath),
        key: key ?? fs.readFileSync(pki.clientKeyPath),
        headers: { ...defaultHeaders, ...headers },
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

function parseMcpPayload(body) {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed);
  }
  const dataLine = trimmed.split('\n').find((line) => line.startsWith('data:'));
  assert.ok(dataLine !== undefined, `no JSON-RPC payload in: ${trimmed.slice(0, 200)}`);
  return JSON.parse(dataLine.slice('data:'.length).trim());
}

async function getHealth(server) {
  const res = await server.dispatchToolCall('health', {});
  return JSON.parse(res.content[0].text);
}

describe('CesSpace ARC — RC-05 Eleven Positive Acceptance Flows', () => {
  test('Flow 1: Server startup in stdio-only mode', async () => {
    const registry = new WorkspaceRegistry();
    const audit = new AuditLogger();
    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      audit,
      new FilesystemSubsystem(),
      new GitSubsystem(),
      {
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: workspaceDir }],
        defaultWorkspaceId: 'ws',
      },
    );

    await server.start();
    try {
      const health = await getHealth(server);
      assert.equal(health.status, 'HEALTHY');
      assert.equal(health.version, '0.5.0-rc05');
      assert.equal(health.stage, 'RC-05');
      assert.equal(health.transportMode, 'stdio');
      assert.equal(health.remoteGatewayActive, false);
      assert.equal(health.authenticationActive, false);
      assert.equal(health.activeSessionsCount, 0);
    } finally {
      await server.stop();
    }
  });

  test('Flow 2: Remote gateway startup with zero enrolled devices', async () => {
    const { server, port } = await startRemoteServer({ tag: 'flow2-zero', pinCount: 0 });
    try {
      const health = await getHealth(server);
      assert.equal(health.status, 'HEALTHY');
      assert.equal(health.transportMode, 'remote');
      assert.equal(health.remoteGatewayActive, true);
      assert.equal(health.authenticationActive, true);
      assert.equal(health.enrolledDevicesCount, 0);

      // Ordinary initialize from unenrolled device is refused
      const res = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'zero-device-client', version: '1.0' },
          },
        }),
      });
      assert.equal(res.status, 200);
      const payload = parseMcpPayload(res.body);
      assert.equal(payload.error.data.code, 'UNAUTHENTICATED');
    } finally {
      await server.stop();
    }
  });

  test('Flow 3: Remote gateway startup with enrolled devices', async () => {
    const { server } = await startRemoteServer({ tag: 'flow3-enrolled', pinCount: 2 });
    try {
      const health = await getHealth(server);
      assert.equal(health.status, 'HEALTHY');
      assert.equal(health.transportMode, 'remote');
      assert.equal(health.remoteGatewayActive, true);
      assert.equal(health.authenticationActive, true);
      assert.equal(health.enrolledDevicesCount, 2);
    } finally {
      await server.stop();
    }
  });

  test('Flow 4: First-device local enrollment initiation & remote completion', async () => {
    const { server, port, endpoint, operator, storePath } = await startRemoteServer({
      tag: 'flow4-enroll',
      pinCount: 0,
    });

    try {
      // 1. Authenticated local operator initiates pending enrollment via admin IPC
      const enrollRes = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'first-device',
        clientType: 'claude-code',
        spkiPin: clientPin(),
      });
      assert.equal(
        enrollRes.ok,
        true,
        `admin enrollment.create failed: ${JSON.stringify(enrollRes)}`,
      );
      const secret = enrollRes.result.secret;
      const pending = enrollRes.result.enrollment;
      assert.ok(secret);
      assert.match(secret, /^[0-9a-f]{64}$/);
      assert.equal(pending.clientId, 'first-device');
      assert.equal(pending.spkiPin, clientPin());

      // 2. Client completes enrollment over mTLS
      const completeRes = await request(port, {
        method: 'POST',
        requestPath: '/enroll/complete',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret }),
      });
      assert.equal(completeRes.status, 200);

      // Verify health reports 1 enrolled device
      const health = await getHealth(server);
      assert.equal(health.enrolledDevicesCount, 1);

      // Verify durable enrolled device exists
      const storeOnDisk = JSON.parse(fs.readFileSync(storePath, 'utf8'));
      const enrolledDevice = storeOnDisk.devices.find((d) => d.clientId === 'first-device');
      assert.ok(enrolledDevice, 'durable enrolled device must exist');
      assert.equal(enrolledDevice.pins.includes(clientPin()), true);
      assert.equal(enrolledDevice.revoked, false);

      // Verify audit contains both DEVICE_ENROLLMENT_REQUESTED and DEVICE_ENROLLED
      const records = server.auditLogger.getRecords();
      assert.ok(
        records.some((r) => r.gateway?.eventType === 'DEVICE_ENROLLMENT_REQUESTED'),
        'DEVICE_ENROLLMENT_REQUESTED must be audited',
      );
      assert.ok(
        records.some((r) => r.gateway?.eventType === 'DEVICE_ENROLLED'),
        'DEVICE_ENROLLED must be audited',
      );
    } finally {
      await server.stop();
    }
  });

  test('Flow 5: Session bootstrap via tokenless initialize', async () => {
    const { server, port } = await startRemoteServer({ tag: 'flow5-init', pinCount: 1 });
    try {
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow5-client', version: '1.0' },
          },
        }),
      });

      assert.equal(initRes.status, 200);
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];
      assert.ok(sessionId, 'Mcp-Session-Id must be set');
      assert.ok(sessionToken, 'Arc-Session-Token must be set');
      assert.match(sessionToken, /^[0-9a-f]{64}$/);

      const records = server.auditLogger.getRecords();
      const issued = records.find((r) => r.gateway?.eventType === 'SESSION_ISSUED');
      assert.ok(issued, 'SESSION_ISSUED must be audited');
      assert.equal(issued.gateway.mcpSessionId, sessionId);
    } finally {
      await server.stop();
    }
  });

  test('Flow 6: Subsequent authenticated tool request with dual headers', async () => {
    const { server, port } = await startRemoteServer({ tag: 'flow6-dual', pinCount: 1 });
    try {
      // 1. Initialize
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow6-client', version: '1.0' },
          },
        }),
      });
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];

      // 2. Dual-header tool request
      const listRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      });
      assert.equal(listRes.status, 200);
      const listPayload = parseMcpPayload(listRes.body);
      assert.ok(Array.isArray(listPayload.result.tools));
    } finally {
      await server.stop();
    }
  });

  test('Flow 7: Ordinary read-only MCP tool invocation', async () => {
    const { server, port } = await startRemoteServer({ tag: 'flow7-read', pinCount: 1 });
    try {
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow7-client', version: '1.0' },
          },
        }),
      });
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];

      // Call read_file
      const callRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'data.txt' },
          },
        }),
      });
      assert.equal(callRes.status, 200);
      const payload = parseMcpPayload(callRes.body);
      assert.ok(payload.result.content[0].text.includes('hello positive flows'));

      // Audit records invocation with server-derived actor fields
      const records = server.auditLogger.getRecords();
      const toolRecord = records.find((r) => r.invocation.toolName === 'read_file');
      assert.ok(toolRecord);
      assert.equal(toolRecord.actor.sessionId, sessionId);
      assert.ok(toolRecord.actor.deviceId);
      assert.equal(toolRecord.actor.clientType, 'claude-code');
    } finally {
      await server.stop();
    }
  });

  test('Flow 8: Policy REQUIRE_APPROVAL invocation', async () => {
    const { server, port } = await startRemoteServer({
      tag: 'flow8-policy',
      pinCount: 1,
    });
    try {
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow8-client', version: '1.0' },
          },
        }),
      });
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];

      // Mutation create_file unconditionally requires approval under Layer 1
      const writeRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: { path: 'new.txt', content: 'requires approval' },
          },
        }),
      });

      assert.equal(writeRes.status, 200);
      const payload = parseMcpPayload(writeRes.body);
      const bodyObj = JSON.parse(payload.result.content[0].text);
      assert.equal(bodyObj.code, 'APPROVAL_REQUIRED');
      assert.ok(bodyObj.details.approvalRequestId);
      // No token is returned to the MCP client
      assert.equal(bodyObj.token, undefined);
      assert.equal(bodyObj.details.token, undefined);
    } finally {
      await server.stop();
    }
  });

  test('Flow 9: Authenticated local operator approval + same-session redemption', async () => {
    const { server, port, endpoint, operator } = await startRemoteServer({
      tag: 'flow9-redeem',
      pinCount: 1,
    });

    try {
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow9-client', version: '1.0' },
          },
        }),
      });
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];

      // 1. Initial write request requires approval
      const firstRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: { path: 'approved.txt', content: 'approved content' },
          },
        }),
      });
      const firstPayload = parseMcpPayload(firstRes.body);
      const firstBody = JSON.parse(firstPayload.result.content[0].text);
      assert.equal(firstBody.code, 'APPROVAL_REQUIRED');
      const requestId = firstBody.details.approvalRequestId;
      assert.ok(requestId);

      // 2. Authenticated local Ed25519 operator approval via admin IPC
      const approveRes = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
        requestId,
      });
      assert.equal(approveRes.ok, true, `approval.approve failed: ${JSON.stringify(approveRes)}`);
      assert.equal(approveRes.result.state, 'APPROVED');
      assert.equal(approveRes.result.requestId, requestId);
      // Prove the approval token came from the authenticated local admin channel
      const token = approveRes.result.token;
      assert.ok(token);
      assert.match(token, /^[0-9a-f]{64}$/);

      // 3. Client redeems from same session using the token received from the admin channel
      const redeemRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: {
              path: 'approved.txt',
              content: 'approved content',
              _arcApproval: { requestId, token },
            },
          },
        }),
      });

      assert.equal(redeemRes.status, 200);
      const redeemPayload = parseMcpPayload(redeemRes.body);
      assert.notEqual(redeemPayload.result.isError, true);
      assert.equal(fs.existsSync(path.join(workspaceDir, 'approved.txt')), true);
    } finally {
      await server.stop();
    }
  });

  test('Flow 10: Session expiration and re-authentication', async () => {
    let now = 1_000_000;
    const sessionManager = new SessionManager({
      getMonotonicTime: () => BigInt(now) * 1_000_000n,
    });
    const { server, port } = await startRemoteServer({
      tag: 'flow10-expiry',
      pinCount: 1,
      sessionManager,
    });

    try {
      // 1. Authenticate session 1
      const initRes1 = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow10-client', version: '1.0' },
          },
        }),
      });
      const sessionId1 = initRes1.headers['mcp-session-id'];
      const token1 = initRes1.headers['arc-session-token'];

      // Verify active
      const ping1 = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId1,
          Authorization: `Bearer ${token1}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' }),
      });
      assert.equal(ping1.status, 200);

      // Advance monotonic clock past idle timeout (300 seconds = 300,000 ms)
      now += 400 * 1000;

      // Old token no longer works
      const pingExpired = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId1,
          Authorization: `Bearer ${token1}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }),
      });
      assert.equal(pingExpired.status, 200);
      const pingExpiredPayload = parseMcpPayload(pingExpired.body);
      assert.equal(pingExpiredPayload.error.data.code, 'INVALID_SESSION_TOKEN');

      // Re-authentication issues new session
      const initRes2 = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow10-client', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes2.status, 200);
      const sessionId2 = initRes2.headers['mcp-session-id'];
      const token2 = initRes2.headers['arc-session-token'];
      assert.notEqual(sessionId1, sessionId2);
      assert.notEqual(token1, token2);

      // New token works
      const ping2 = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId2,
          Authorization: `Bearer ${token2}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'ping' }),
      });
      assert.equal(ping2.status, 200);
    } finally {
      await server.stop();
    }
  });

  test('Flow 11: Durable device revocation & immediate session teardown', async () => {
    const { server, port, records, endpoint, operator, storePath } = await startRemoteServer({
      tag: 'flow11-revoke',
      pinCount: 1,
    });
    const deviceId = records[0].deviceId;

    try {
      // 1. Establish session
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow11-client', version: '1.0' },
          },
        }),
      });
      const sessionId = initRes.headers['mcp-session-id'];
      const token = initRes.headers['arc-session-token'];
      assert.ok(sessionId);
      assert.ok(token);

      // Verify session works
      const pingBefore = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' }),
      });
      assert.equal(pingBefore.status, 200);

      // 2. Authenticated local operator calls device.revoke via admin IPC
      const revokeRes = await adminRequest(endpoint, operator.privateKey, 'device.revoke', {
        deviceId,
      });
      assert.equal(revokeRes.ok, true, `device.revoke failed: ${JSON.stringify(revokeRes)}`);
      assert.equal(revokeRes.result.deviceId, deviceId);
      assert.equal(revokeRes.result.revoked, true);
      assert.equal(revokeRes.result.sessionsRevoked, 1);
      assert.equal(revokeRes.result.transportsClosed, 1);

      // Verify Task-9 candidate mutation is durably persisted
      const diskStore = JSON.parse(fs.readFileSync(storePath, 'utf8'));
      const diskDevice = diskStore.devices.find((d) => d.deviceId === deviceId);
      assert.equal(diskDevice.revoked, true, 'device mutation must be durably persisted');

      // 3. Existing session immediately returns INVALID_SESSION_TOKEN
      const pingAfter = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }),
      });
      assert.equal(pingAfter.status, 200);
      const payload = parseMcpPayload(pingAfter.body);
      assert.equal(payload.error.data.code, 'INVALID_SESSION_TOKEN');

      // 4. Fresh tokenless initialize from revoked device returns UNAUTHENTICATED
      const freshInit = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow11-client', version: '1.0' },
          },
        }),
      });
      assert.equal(freshInit.status, 200);
      const freshPayload = parseMcpPayload(freshInit.body);
      assert.equal(freshPayload.error.data.code, 'UNAUTHENTICATED');
    } finally {
      await server.stop();
    }

    // 5. Prove DURABILITY:
    // Start a fresh server instance using the same persisted trust store
    const restarted = await startRemoteServer({
      tag: 'flow11-restart',
      storePath,
      records,
    });

    try {
      // Inspect through normal public composition: health reports 0 active enrolled devices
      const health = await getHealth(restarted.server);
      assert.equal(health.enrolledDevicesCount, 0);

      // Device is still revoked: inspect through admin IPC
      const inspectRes = await adminRequest(
        restarted.endpoint,
        restarted.operator.privateKey,
        'devices.inspect',
        { deviceId },
      );
      assert.equal(inspectRes.ok, true);
      assert.equal(inspectRes.result.revoked, true);

      // Device cannot establish a new MCP session
      const postRestartInit = await request(restarted.port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 5,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'flow11-client-after-restart', version: '1.0' },
          },
        }),
      });
      assert.equal(postRestartInit.status, 200);
      const postRestartPayload = parseMcpPayload(postRestartInit.body);
      assert.equal(postRestartPayload.error.data.code, 'UNAUTHENTICATED');
      assert.equal(postRestartInit.headers['mcp-session-id'], undefined);
      assert.equal(postRestartInit.headers['arc-session-token'], undefined);
    } finally {
      await restarted.server.stop();
    }
  });
});
