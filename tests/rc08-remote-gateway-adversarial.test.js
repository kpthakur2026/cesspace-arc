/**
 * CesSpace ARC — RC-08 Task 3: Remote Gateway Adversarial / Pen Tests.
 *
 * Every case is loopback-only and uses ephemeral TLS material and temporary
 * workspaces. The suite drives the existing RC-05 gateway, Streamable HTTP MCP
 * surface, session authority, authority validator, request bounds, and Layer-C
 * limiter. It creates no alternate authentication or dispatch implementation.
 */

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { RemoteGateway } from '../apps/mcp-server/dist/remote-gateway.js';
import {
  createAuthenticatedRequestLimiter,
  MCP_ADMISSION_ERROR_CODE,
  sessionRateLimitKey,
} from '../apps/mcp-server/dist/remote-execution.js';
import {
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
} from '../apps/mcp-server/dist/remote-resource-limits.js';
import {
  MAX_REMOTE_BODY_BYTES,
  getActiveBodyReadDeadlineCountForTests,
} from '../apps/mcp-server/dist/remote-request-bounds.js';
import { HOST_REFUSED_BODY } from '../apps/mcp-server/dist/remote-request-authority.js';
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
  SESSION_IDLE_TIMEOUT_SECONDS,
  SessionManager,
  deriveSpkiPin,
} from '../packages/auth/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import { createEmptyTrustStore, createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

const PUBLIC_HOSTNAME = 'localhost';
const MCP_HEADERS = {
  Accept: 'application/json, text/event-stream',
  'Content-Type': 'application/json',
};
const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'rc08-task3', version: '1.0.0' },
  },
});

let tempRoot;
let pki;
let counter = 0;

before(() => {
  assert.equal(hasOpenssl(), true, 'Task 3 requires the platform openssl binary');
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-remote-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
});

after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

function makeClock(start = 1_000_000) {
  let now = start;
  return {
    now: () => now,
    advance: (milliseconds) => {
      now += milliseconds;
      return now;
    },
  };
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return predicate();
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function clientMaterial(certPath = pki.clientCertPath, keyPath = pki.clientKeyPath) {
  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  };
}

function writeTrustStore(tag, enrolledCertPath = pki.clientCertPath) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  const { device } = store.enrollDevice({
    clientId: `client-${tag}`,
    clientType: 'rc08-test',
    pin: deriveSpkiPin(fs.readFileSync(enrolledCertPath, 'utf8')),
    displayLabel: `RC08 ${tag}`,
  });
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, store, device };
}

async function startRemote({ tag, sessionClock, layerClock } = {}) {
  counter += 1;
  const label = tag ?? `remote-${counter}`;
  const port = await freePort();
  const workspaceDir = path.join(tempRoot, `workspace-${label}-${counter}`);
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  const { storePath, device } = writeTrustStore(label);
  const registry = new WorkspaceRegistry();
  const audit = new AuditLogger();
  const sessionManager =
    sessionClock === undefined
      ? new SessionManager()
      : new SessionManager({ getMonotonicTime: () => BigInt(sessionClock.now()) * 1_000_000n });
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    audit,
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'remote',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: createAuditConfig(tempRoot, `task3-${label}-${counter}`),
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
    undefined,
    undefined,
    new ApprovalStateManager(),
    undefined,
    undefined,
    sessionManager,
  );

  if (layerClock !== undefined) {
    // TypeScript `private readonly` is deliberately observable in the compiled
    // JS tests (the RC-05 suites already inspect it). Replace it before start,
    // so the real surface and bridge are both composed over this one production
    // limiter with frozen constants and only its monotonic clock injected.
    server.authenticatedRequestLimiter = createAuthenticatedRequestLimiter({
      getMonotonicTimeMs: layerClock.now,
    });
  }

  await server.start();
  return { server, port, workspaceDir, audit, device, storePath };
}

async function startGateway({ tag, options = {}, enrolled = false } = {}) {
  counter += 1;
  const label = tag ?? `gateway-${counter}`;
  const port = await freePort();
  const storePath = enrolled
    ? writeTrustStore(label).storePath
    : createEmptyTrustStore(tempRoot, `empty-${label}-${counter}.json`);
  const admitted = [];
  const refused = [];
  const gateway = new RemoteGateway(
    {
      bindHost: '127.0.0.1',
      port,
      publicHostname: PUBLIC_HOSTNAME,
      serverCertificatePath: pki.serverCertPath,
      privateKey: { kind: 'file', path: pki.serverKeyPath },
      clientCaPaths: [pki.trustedCaCertPath],
      trustStorePath: storePath,
    },
    {
      onAdmitted: (context) => admitted.push(context),
      onRefused: (reason) => refused.push(reason),
      ...options,
    },
  );
  await gateway.start();
  return { gateway, port, admitted, refused, storePath };
}

function request(
  port,
  {
    method = 'POST',
    requestPath = '/mcp',
    headers = {},
    body,
    certPath = pki.clientCertPath,
    keyPath = pki.clientKeyPath,
    rejectUnauthorized = true,
  } = {},
) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: PUBLIC_HOSTNAME,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(certPath, keyPath),
        rejectUnauthorized,
        minVersion: 'TLSv1.3',
        headers: { Host: PUBLIC_HOSTNAME, ...headers },
      },
      (res) => {
        const chunks = [];
        const protocol = res.socket.getProtocol();
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            protocol,
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

function payloadOf(body) {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) return JSON.parse(trimmed);
  const line = trimmed.split('\n').find((value) => value.startsWith('data:'));
  assert.ok(line, `missing MCP payload: ${trimmed.slice(0, 200)}`);
  return JSON.parse(line.slice('data:'.length).trim());
}

async function initialize(port) {
  const response = await request(port, {
    headers: MCP_HEADERS,
    body: INITIALIZE_BODY,
  });
  assert.equal(response.status, 200, response.body);
  const payload = payloadOf(response.body);
  assert.equal(payload.error, undefined, response.body);
  const sessionId = response.headers['mcp-session-id'];
  const token = response.headers['arc-session-token'];
  assert.match(sessionId, /^[0-9a-f]{64}$/);
  assert.match(token, /^[0-9a-f]{64}$/);
  return { response, sessionId, token };
}

function sessionHeaders(sessionId, token) {
  return { 'Mcp-Session-Id': sessionId, Authorization: `Bearer ${token}` };
}

function rpcBody(id, method = 'ping', params = {}) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params });
}

function toolBody(id, name, args) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name, arguments: args },
  });
}

function assertMcpArcError(response, arcCode, id) {
  assert.equal(response.status, 200, response.body);
  assert.notEqual(response.status, 429);
  const payload = payloadOf(response.body);
  assert.equal(payload.jsonrpc, '2.0');
  assert.equal(payload.id, id);
  assert.equal(payload.error.code, MCP_ADMISSION_ERROR_CODE);
  assert.deepEqual(payload.error.data, { code: arcCode });
  assert.deepEqual(Object.keys(payload.error).sort(), ['code', 'data', 'message']);
  return payload;
}

function workRecords(audit) {
  return audit.getRecords().filter((record) => record.gateway === undefined);
}

function tlsHttpProbe(port, { certPath, keyPath, minVersion, maxVersion } = {}) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port,
      servername: PUBLIC_HOSTNAME,
      ca: [fs.readFileSync(pki.trustedCaCertPath)],
      ...(certPath && keyPath ? clientMaterial(certPath, keyPath) : {}),
      rejectUnauthorized: true,
      ...(minVersion ? { minVersion } : {}),
      ...(maxVersion ? { maxVersion } : {}),
    });
    let secure = false;
    let bytes = Buffer.alloc(0);
    let settled = false;
    const finish = (extra = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ secure, bytes, ...extra });
    };
    socket.on('secureConnect', () => {
      secure = true;
      socket.write(
        'POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
      );
    });
    socket.on('data', (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
    });
    socket.on('error', (error) => finish({ error }));
    socket.on('close', () => finish({ closed: true }));
    const timer = setTimeout(() => finish({ timedOut: true }), 2_000);
    timer.unref();
  });
}

async function assertNoLiveGatewayResources(gateway) {
  assert.equal(
    await waitFor(() => {
      const status = gateway.getStatus();
      return status.liveConnections === 0 && status.inFlightHandshakes === 0;
    }),
    true,
  );
}

test('RC08-NEG-026: untrusted client CA fails at TLS with no HTTP, MCP, session, policy, or subsystem activity', async () => {
  const harness = await startRemote({ tag: 'neg026-untrusted-ca' });
  try {
    let admittedConnections = 0;
    harness.server.remoteGateway.options.onAdmitted = () => {
      admittedConnections += 1;
    };
    const before = workRecords(harness.audit).length;
    const outcome = await tlsHttpProbe(harness.port, {
      certPath: pki.unknownCaClientCertPath,
      keyPath: pki.unknownCaClientKeyPath,
    });
    assert.equal(outcome.bytes.length, 0, 'no HTTP or MCP response exists');
    assert.equal(outcome.bytes.toString().includes('HTTP/'), false);
    assert.equal(admittedConnections, 0, 'the server never completed TLS admission');
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(harness.server.remoteGateway.mcpSurface.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
    await assertNoLiveGatewayResources(harness.server.remoteGateway);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-027: trusted-CA certificate with matching CN/SAN but unenrolled SPKI is generic UNAUTHENTICATED', async () => {
  const other = pki.issueTrustedClientCert({
    commonName: 'client-valid',
    san: 'DNS:localhost,IP:127.0.0.1',
  });
  const harness = await startRemote({ tag: 'neg027-unenrolled' });
  try {
    const enrolledPin = deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8'));
    const otherPin = deriveSpkiPin(fs.readFileSync(other.certPath, 'utf8'));
    assert.notEqual(otherPin, enrolledPin);
    const before = workRecords(harness.audit).length;
    const response = await request(harness.port, {
      certPath: other.certPath,
      keyPath: other.keyPath,
      headers: MCP_HEADERS,
      body: INITIALIZE_BODY,
    });
    assert.equal(response.protocol, 'TLSv1.3', 'the trusted chain completed real TLS 1.3');
    const payload = assertMcpArcError(response, 'UNAUTHENTICATED', 1);
    assert.equal(payload.error.message, 'Authentication failed');
    for (const forbidden of [
      otherPin,
      enrolledPin,
      harness.device.deviceId,
      harness.device.clientId,
      'client-valid',
      'localhost',
      'near-match',
      'not enrolled',
      'unknown device',
    ]) {
      assert.equal(response.body.includes(forbidden), false, `refusal leaked ${forbidden}`);
    }
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-028: expired client certificate fails at TLS before HTTP or MCP processing', async () => {
  const harness = await startRemote({ tag: 'neg028-expired' });
  try {
    let admittedConnections = 0;
    harness.server.remoteGateway.options.onAdmitted = () => {
      admittedConnections += 1;
    };
    const before = workRecords(harness.audit).length;
    const outcome = await tlsHttpProbe(harness.port, {
      certPath: pki.expiredClientCertPath,
      keyPath: pki.expiredClientKeyPath,
    });
    assert.equal(outcome.bytes.length, 0, 'TLS failure has no ARC application body');
    assert.equal(admittedConnections, 0, 'the server never completed TLS admission');
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
    await assertNoLiveGatewayResources(harness.server.remoteGateway);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-029: TLS 1.2 downgrade cannot negotiate or reach HTTP/MCP', async () => {
  const harness = await startRemote({ tag: 'neg029-tls12' });
  try {
    const before = workRecords(harness.audit).length;
    const outcome = await tlsHttpProbe(harness.port, {
      certPath: pki.clientCertPath,
      keyPath: pki.clientKeyPath,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    });
    assert.equal(outcome.secure, false, 'TLS 1.2 never completes secureConnect');
    assert.equal(outcome.bytes.length, 0);
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-030: cleartext HTTP to the TLS listener closes with no valid HTTP/MCP response', async () => {
  const harness = await startRemote({ tag: 'neg030-cleartext' });
  try {
    const before = workRecords(harness.audit).length;
    const outcome = await new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port: harness.port });
      const chunks = [];
      let settled = false;
      const finish = (extra = {}) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve({ data: Buffer.concat(chunks), ...extra });
      };
      socket.on('connect', () =>
        socket.write('POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n'),
      );
      socket.on('data', (chunk) => chunks.push(chunk));
      socket.on('error', () => finish({ closed: true }));
      socket.on('close', () => finish({ closed: true }));
      const timer = setTimeout(() => finish({ timedOut: true }), 2_000);
      timer.unref();
    });
    const raw = outcome.data.toString('utf8');
    assert.equal(outcome.closed, true);
    assert.equal(raw.startsWith('HTTP/'), false);
    assert.equal(raw.includes('jsonrpc'), false);
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-031: Host mismatch returns only fixed HTTP 403 Forbidden before MCP work', async () => {
  const harness = await startRemote({ tag: 'neg031-host' });
  try {
    const hostileHost = 'attacker.example.invalid';
    const before = workRecords(harness.audit).length;
    const response = await request(harness.port, {
      headers: { ...MCP_HEADERS, Host: hostileHost },
      body: INITIALIZE_BODY,
    });
    assert.equal(response.status, 403);
    assert.equal(response.body, HOST_REFUSED_BODY);
    assert.equal(response.body, '{"error":"Forbidden"}');
    assert.equal(response.body.includes(hostileHost), false);
    assert.equal(response.body.includes('jsonrpc'), false);
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-032: refused Origin is indistinguishable from Host refusal and grants no CORS/MCP access', async () => {
  const harness = await startRemote({ tag: 'neg032-origin' });
  try {
    const hostileOrigin = 'https://attacker.example.invalid';
    const before = workRecords(harness.audit).length;
    const origin = await request(harness.port, {
      headers: { ...MCP_HEADERS, Origin: hostileOrigin },
      body: INITIALIZE_BODY,
    });
    const host = await request(harness.port, {
      headers: { ...MCP_HEADERS, Host: 'wrong.example.invalid' },
      body: INITIALIZE_BODY,
    });
    assert.equal(origin.status, 403);
    assert.equal(origin.body, '{"error":"Forbidden"}');
    assert.equal(origin.body, host.body);
    assert.equal(origin.body.includes(hostileOrigin), false);
    assert.equal(origin.headers['access-control-allow-origin'], undefined);
    assert.equal(origin.body.includes('jsonrpc'), false);
    assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    assert.equal(workRecords(harness.audit).length, before);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-033: malformed and forged session tokens are uniform MCP INVALID_SESSION_TOKEN refusals', async () => {
  const harness = await startRemote({ tag: 'neg033-forged-token' });
  try {
    const init = await initialize(harness.port);
    const before = workRecords(harness.audit).length;
    const responses = [];
    for (const token of ['malformed-token', 'f'.repeat(64)]) {
      responses.push(
        await request(harness.port, {
          headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, token) },
          body: rpcBody(333),
        }),
      );
    }
    for (const response of responses) {
      const payload = assertMcpArcError(response, 'INVALID_SESSION_TOKEN', 333);
      assert.equal(payload.error.message, 'Invalid or expired session token');
      for (const forbidden of [
        init.token,
        init.sessionId,
        crypto.createHash('sha256').update(init.token).digest('hex'),
        'malformed-token',
        'digest',
        'mismatch',
        'revoked',
      ]) {
        assert.equal(response.body.includes(forbidden), false, `refusal leaked ${forbidden}`);
      }
    }
    assert.equal(responses[0].body, responses[1].body, 'token causes are not an oracle');
    assert.equal(workRecords(harness.audit).length, before);
    assert.equal(harness.server.sessionManager.hasSession(init.sessionId), true);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-034: expired and revoked session replays are identical INVALID_SESSION_TOKEN and reclaim transports', async () => {
  const bodies = [];

  const sessionClock = makeClock(5_000_000);
  const expired = await startRemote({ tag: 'neg034-expired', sessionClock });
  try {
    const init = await initialize(expired.port);
    sessionClock.advance((SESSION_IDLE_TIMEOUT_SECONDS + 1) * 1_000);
    const response = await request(expired.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(334),
    });
    assertMcpArcError(response, 'INVALID_SESSION_TOKEN', 334);
    bodies.push(response.body);
    assert.equal(expired.server.sessionManager.hasSession(init.sessionId), false);
    assert.equal(
      await waitFor(() => expired.server.remoteGateway.mcpSurface.getActiveSessionCount() === 0),
      true,
    );
  } finally {
    await expired.server.stop();
  }

  const revoked = await startRemote({ tag: 'neg034-revoked' });
  try {
    const init = await initialize(revoked.port);
    assert.equal(revoked.server.sessionManager.revokeSession(init.sessionId), true);
    const response = await request(revoked.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(334),
    });
    assertMcpArcError(response, 'INVALID_SESSION_TOKEN', 334);
    bodies.push(response.body);
    assert.equal(revoked.server.sessionManager.hasSession(init.sessionId), false);
    assert.equal(
      await waitFor(() => revoked.server.remoteGateway.mcpSurface.getActiveSessionCount() === 0),
      true,
    );
  } finally {
    await revoked.server.stop();
  }

  assert.equal(bodies[0], bodies[1]);
  assert.equal(bodies[0].includes('SESSION_EXPIRED'), false);
  assert.equal(bodies[0].includes('SESSION_REVOKED'), false);
});

test('RC08-NEG-035: slow-trickle authenticated TLS body times out, executes nothing, and releases socket/deadline', async () => {
  const harness = await startGateway({
    tag: 'neg035-slowloris',
    enrolled: true,
    options: { bodyReadTimeoutMsForTests: 60, totalRequestTimeoutMsForTests: 1_000 },
  });
  const trustBefore = fs.readFileSync(harness.storePath);
  try {
    const outcome = await new Promise((resolve) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: harness.port,
          method: 'POST',
          path: '/enroll/complete',
          servername: PUBLIC_HOSTNAME,
          ca: [fs.readFileSync(pki.trustedCaCertPath)],
          ...clientMaterial(),
          minVersion: 'TLSv1.3',
          headers: { Host: PUBLIC_HOSTNAME, 'Content-Length': '64' },
        },
        (res) => resolve({ answered: true, status: res.statusCode }),
      );
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req.destroy();
        resolve(value);
      };
      req.on('socket', (socket) => socket.once('secureConnect', () => req.write('{"se')));
      req.on('error', (error) => finish({ answered: false, error }));
      req.on('close', () => finish({ answered: false, closed: true }));
      const timer = setTimeout(() => finish({ budgetExpired: true }), 2_000);
      timer.unref();
    });
    assert.equal(outcome.budgetExpired, undefined, 'the production deadline settled the request');
    assert.notEqual(outcome.answered, true, 'no partial request was answered or executed');
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
    assert.equal(await waitFor(() => harness.gateway.getStatus().liveConnections === 0), true);
    assert.deepEqual(fs.readFileSync(harness.storePath), trustBefore, 'trust state is untouched');
    assert.equal(harness.admitted.length, 1, 'real mTLS admission completed before body timeout');
  } finally {
    await harness.gateway.stop();
  }
});

test('RC08-NEG-036: real Layer-C exhaustion is MCP RATE_LIMIT_EXCEEDED and identity is server-derived', async () => {
  const clock = makeClock();
  const harness = await startRemote({ tag: 'neg036-layer-c', layerClock: clock });
  try {
    assert.equal(LAYER_C_REQUESTS_PER_MINUTE, 300);
    assert.equal(LAYER_C_BURST, 60);
    assert.equal(MAX_LAYER_C_KEYS, 1024);
    assert.equal(MAX_OUTSTANDING_REQUESTS_PER_SESSION, 4);

    const init = await initialize(harness.port);
    const limiter = harness.server.authenticatedRequestLimiter;
    const expectedKey = sessionRateLimitKey({
      deviceId: harness.device.deviceId,
      sessionId: init.sessionId,
    });

    const badHost = await request(harness.port, {
      headers: { ...MCP_HEADERS, Host: 'switch.example.invalid' },
      body: rpcBody(360),
    });
    const badOrigin = await request(harness.port, {
      headers: { ...MCP_HEADERS, Origin: 'https://switch.example.invalid' },
      body: rpcBody(361),
    });
    assert.equal(badHost.status, 403);
    assert.equal(badOrigin.status, 403);
    assert.deepEqual(limiter.getRetainedKeysForTests(), []);

    const admitted = await request(harness.port, {
      headers: {
        ...MCP_HEADERS,
        ...sessionHeaders(init.sessionId, init.token),
        'X-Forwarded-For': '203.0.113.200',
        'X-Real-IP': '198.51.100.200',
        'X-Forwarded-Host': 'forged.example.invalid',
      },
      body: rpcBody(362),
    });
    assert.equal(payloadOf(admitted.body).error, undefined, admitted.body);

    const shaped = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(363, 'arc/unknown', {
        deviceId: 'client-controlled',
        sessionId: 'client-controlled',
        host: 'client-controlled',
        origin: 'client-controlled',
      }),
    });
    assert.equal(payloadOf(shaped.body).error.code, -32601);
    assert.deepEqual(limiter.getRetainedKeysForTests(), [expectedKey]);

    while (limiter.consume(expectedKey).consumed) {
      // Exhaust the exact production table without opening enough connections
      // to trip the intentionally tighter Layer-A connection budget.
    }
    const before = workRecords(harness.audit).length;
    const refused = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: toolBody(364, 'health', {}),
    });
    assertMcpArcError(refused, 'RATE_LIMIT_EXCEEDED', 364);
    assert.notEqual(refused.status, 429);
    assert.equal(limiter.getBucket(expectedKey).tokens < 1, true, 'rate, not concurrency');
    assert.equal(limiter.getHolderCount(expectedKey), 0);
    assert.equal(
      workRecords(harness.audit).length,
      before,
      'policy and subsystems were not reached',
    );
    assert.deepEqual(limiter.getRetainedKeysForTests(), [expectedKey]);
  } finally {
    await harness.server.stop();
  }
});

function exactSizedJsonRpc(bytes) {
  const prefix = '{"jsonrpc":"2.0","id":370,"method":"';
  const suffix = '"}';
  assert.ok(bytes > Buffer.byteLength(prefix + suffix));
  const result = `${prefix}${'x'.repeat(bytes - Buffer.byteLength(prefix + suffix))}${suffix}`;
  assert.equal(Buffer.byteLength(result), bytes);
  return result;
}

function chunkedOverflow(port, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/mcp',
        servername: PUBLIC_HOSTNAME,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(),
        minVersion: 'TLSv1.3',
        headers: { Host: PUBLIC_HOSTNAME, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    const chunk = Buffer.alloc(1024 * 1024, 0x61);
    req.write(chunk);
    req.write(chunk);
    req.write(chunk);
    req.write(chunk);
    req.end(Buffer.from('b'));
  });
}

test('RC08-NEG-037: exact 4 MiB reaches parsing while declared and chunked overflow return HTTP 413 before dispatch', async () => {
  assert.equal(MAX_REMOTE_BODY_BYTES, 4_194_304);
  const clock = makeClock();
  const harness = await startRemote({ tag: 'neg037-body-limit', layerClock: clock });
  try {
    const init = await initialize(harness.port);
    const authHeaders = { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) };
    const exact = await request(harness.port, {
      headers: authHeaders,
      body: exactSizedJsonRpc(MAX_REMOTE_BODY_BYTES),
    });
    assert.notEqual(exact.status, 413, 'exactly 4 MiB passed the body reader');
    assert.equal(
      payloadOf(exact.body).error.code,
      -32601,
      'the parsed request reached method lookup',
    );

    const limiter = harness.server.authenticatedRequestLimiter;
    const key = sessionRateLimitKey({
      deviceId: harness.device.deviceId,
      sessionId: init.sessionId,
    });
    const tokensBefore = limiter.getBucket(key).tokens;
    const workBefore = workRecords(harness.audit).length;

    const declared = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: harness.port,
          method: 'POST',
          path: '/mcp',
          servername: PUBLIC_HOSTNAME,
          ca: [fs.readFileSync(pki.trustedCaCertPath)],
          ...clientMaterial(),
          minVersion: 'TLSv1.3',
          headers: {
            Host: PUBLIC_HOSTNAME,
            ...authHeaders,
            'Content-Length': String(MAX_REMOTE_BODY_BYTES + 1),
          },
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () =>
            resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }),
          );
        },
      );
      req.on('error', reject);
      req.flushHeaders();
    });
    assert.equal(declared.status, 413);
    assert.equal(declared.body, '{"error":"Payload too large"}');
    assert.equal(declared.body.includes('jsonrpc'), false);
    assert.equal(limiter.getBucket(key).tokens, tokensBefore, 'JSON/admission was never reached');
    assert.equal(workRecords(harness.audit).length, workBefore);

    const chunked = await chunkedOverflow(harness.port, authHeaders);
    assert.equal(chunked.status, 413);
    assert.equal(chunked.body, '{"error":"Payload too large"}');
    assert.equal(chunked.body.includes('jsonrpc'), false);
    assert.equal(limiter.getBucket(key).tokens, tokensBefore, 'chunk overflow never reached JSON');
    assert.equal(workRecords(harness.audit).length, workBefore);
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-FLOW-07: real TLS 1.3 mTLS session executes production read_file over Streamable HTTP', async () => {
  const harness = await startRemote({ tag: 'flow07-read-file' });
  const expected = 'RC08 remote gateway exact file content\n';
  fs.writeFileSync(path.join(harness.workspaceDir, 'remote.txt'), expected);
  try {
    const init = await initialize(harness.port);
    assert.equal(init.response.protocol, 'TLSv1.3');
    const response = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: toolBody(807, 'read_file', { path: 'remote.txt', workspaceId: 'workspace' }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.protocol, 'TLSv1.3');
    assert.equal(response.headers['transfer-encoding'], 'chunked');
    const payload = payloadOf(response.body);
    assert.equal(payload.error, undefined, response.body);
    const result = JSON.parse(payload.result.content[0].text);
    assert.equal(result.content, expected);
    const record = harness.audit
      .getRecords()
      .find((entry) => entry.invocation?.toolName === 'read_file');
    assert.ok(record, 'the shared policy/filesystem pipeline recorded read_file');
    assert.equal(record.actor.deviceId, harness.device.deviceId);
    assert.equal(record.actor.sessionId, init.sessionId);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-FLOW-08: real authenticated Layer-C tokens exhaust, refill on injected monotonic time, and succeed', async () => {
  const clock = makeClock();
  const harness = await startRemote({ tag: 'flow08-refill', layerClock: clock });
  try {
    const init = await initialize(harness.port);
    const limiter = harness.server.authenticatedRequestLimiter;
    const key = sessionRateLimitKey({
      deviceId: harness.device.deviceId,
      sessionId: init.sessionId,
    });

    const first = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(808),
    });
    assert.equal(payloadOf(first.body).error, undefined);
    assert.equal(limiter.getBucket(key).tokens, LAYER_C_BURST - 1);

    while (limiter.consume(key).consumed) {
      // Same frozen table; only the monotonic clock is injected.
    }
    const refused = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(809),
    });
    assertMcpArcError(refused, 'RATE_LIMIT_EXCEEDED', 809);
    assert.notEqual(refused.status, 429);

    const refillMs = 60_000 / LAYER_C_REQUESTS_PER_MINUTE;
    clock.advance(refillMs);
    const recovered = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(810),
    });
    assert.equal(payloadOf(recovered.body).error, undefined, recovered.body);
    assert.equal(limiter.getBucket(key).tokens, 0, 'exactly one refilled token was consumed');

    clock.advance(60_000 * 10);
    const capped = await request(harness.port, {
      headers: { ...MCP_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
      body: rpcBody(811),
    });
    assert.equal(payloadOf(capped.body).error, undefined, capped.body);
    assert.equal(limiter.getBucket(key).tokens, LAYER_C_BURST - 1, 'refill capped at burst');
  } finally {
    await harness.server.stop();
  }
});
