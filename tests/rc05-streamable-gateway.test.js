/**
 * CesSpace ARC — RC-05 Task 8: Streamable HTTP Gateway Composition and Health
 *
 * Covers the frozen Task-8 contract (rc05-scope-acceptance.md §5.3, §5.4, §6,
 * §7, §10, §11, §12, §13, §16, §17, §19, §21, §25.1, §29) and the Task-8
 * negative controls RC05-NEG-02, 03, 04, 06, 70.
 *
 * Everything here is a REAL integration test: a real `ArcMcpServer` in remote
 * mode, a real TLS 1.3 listener, a real mTLS client certificate, and real HTTPS
 * requests. Where a source-level assertion is used it is because the property is
 * structural (which module composes a transport), never as a substitute for a
 * behavioural test.
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * test PKI helper and removed with it; no certificate or key is committed and no
 * scanner suppression is used.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { DeviceTrustStore, deriveSpkiPin } from '../packages/auth/dist/index.js';
import { createEmptyTrustStore, createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

let tempRoot;
let pki;
let workspaceDir;
let counter = 0;

before(() => {
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 Task 8 generates ephemeral certificates and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-task8-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  workspaceDir = fs.mkdtempSync(path.join(tempRoot, 'ws-'));
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# workspace\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** The SPKI pin the gateway will derive for the always-used client certificate. */
function clientSpkiPin() {
  return deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8'));
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
 * Builds a durable device trust store holding the test client certificate's own
 * SPKI pin, so the mTLS peer that connects IS the enrolled device.
 */
function trustStoreForClient(tag) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  store.enrollDevice({
    clientId: `agent-${tag}`,
    clientType: 'claude-code',
    pin: clientSpkiPin(),
  });
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return storePath;
}

/**
 * Starts a REAL remote-mode ArcMcpServer over real mTLS.
 *
 * By default the connecting client certificate's own SPKI pin is enrolled, so
 * the peer that connects IS the enrolled device. `enrolled: false` composes the
 * zero-device state instead, which is also valid.
 */
async function startRemote({
  tag = 'remote',
  trustStorePath,
  enrolled = true,
  extraRemote = {},
  config = {},
} = {}) {
  const port = await freePort();
  const resolvedStorePath =
    trustStorePath ??
    (enrolled
      ? trustStoreForClient(tag)
      : createEmptyTrustStore(tempRoot, `empty-${tag}-${++counter}.json`));
  const server = createArcMcpServer({
    transport: 'remote',
    authorizedRoots: [{ id: 'ws', path: workspaceDir }],
    defaultWorkspaceId: 'ws',
    ...config,
    remote: {
      bindHost: '127.0.0.1',
      port,
      publicHostname: 'localhost',
      serverCertificatePath: pki.serverCertPath,
      privateKey: { kind: 'file', path: pki.serverKeyPath },
      clientCaPaths: [pki.trustedCaCertPath],
      trustStorePath: resolvedStorePath,
      ...extraRemote,
    },
  });
  await server.start();
  return { server, port };
}

/**
 * One real HTTPS request over mTLS.
 *
 * `Host` is set explicitly because Node otherwise sends `127.0.0.1:<port>`,
 * which is not the configured public hostname — the very mismatch §10 refuses.
 */
function request(port, { method = 'GET', requestPath = '/mcp', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: 'localhost',
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
        headers: { Host: 'localhost', ...headers },
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

/** The headers every POST /mcp must carry for the SDK to consider it valid. */
const MCP_POST_HEADERS = {
  Accept: 'application/json, text/event-stream',
  'Content-Type': 'application/json',
};

/** Parses the JSON-RPC payloads out of a Streamable HTTP SSE-framed response. */
function sseMessages(body) {
  const messages = [];
  for (const line of body.split('\n')) {
    if (line.startsWith('data:')) {
      const payload = line.slice(5).trim();
      if (payload.length > 0) {
        messages.push(JSON.parse(payload));
      }
    }
  }
  return messages;
}

/** Parses a response body that is either bare JSON or SSE-framed JSON. */
function responseMessages(res) {
  if ((res.headers['content-type'] ?? '').includes('text/event-stream')) {
    return sseMessages(res.body);
  }
  return res.body.length > 0 ? [JSON.parse(res.body)] : [];
}

const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'rc05-task8-test', version: '1.0.0' },
  },
});

const INITIALIZED_NOTIFICATION = JSON.stringify({
  jsonrpc: '2.0',
  method: 'notifications/initialized',
});

/**
 * Performs the tokenless `initialize` handshake and returns everything a client
 * legitimately obtains: the server-issued session ID and the one-time raw token.
 */
async function initializeSession(port, headers = {}) {
  const res = await request(port, {
    method: 'POST',
    headers: { ...MCP_POST_HEADERS, ...headers },
    body: INITIALIZE_BODY,
  });
  return {
    res,
    sessionId: res.headers['mcp-session-id'],
    token: res.headers['arc-session-token'],
  };
}

/** The dual-header pair every ordinary authenticated request must present. */
function sessionHeaders(sessionId, token) {
  return { 'Mcp-Session-Id': sessionId, Authorization: `Bearer ${token}` };
}

/** Wraps an SSE content `[type, text]` pair into one MCP tool result object. */
function toolCallResult(messages) {
  const response = messages.find((message) => message.result !== undefined);
  assert.ok(response, `expected a JSON-RPC result, got ${JSON.stringify(messages).slice(0, 300)}`);
  return JSON.parse(response.result.content[0].text);
}

describe('CesSpace ARC — RC-05 Task 8: Streamable HTTP Gateway', () => {
  // =========================================================================
  // §4 routing and the negative path controls
  // =========================================================================

  test('RC05-NEG-02: a non-configured path is 404 and reaches no MCP parsing or session', async () => {
    const { server, port } = await startRemote({ tag: 'neg02' });
    try {
      for (const requestPath of ['/admin', '/mcp/extra', '/', '/mcp/']) {
        const res = await request(port, {
          method: 'POST',
          requestPath,
          headers: MCP_POST_HEADERS,
          body: INITIALIZE_BODY,
        });
        assert.equal(res.status, 404, `${requestPath}: ${res.status} ${res.body}`);
        assert.equal(res.headers['mcp-session-id'], undefined, requestPath);
        assert.equal(res.headers['arc-session-token'], undefined, requestPath);
      }
      // A body that looks exactly like a valid initialize changed nothing: no
      // session, no reservation, no transport.
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(server.sessionManager.getReservedSessionIdCount(), 0);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-03: a legacy SSE probe is 404 and mints no session', async () => {
    const { server, port } = await startRemote({ tag: 'neg03' });
    try {
      // The deprecated legacy SSE transport used two endpoints. Neither exists,
      // and no compatibility path was added for either.
      for (const requestPath of ['/sse', '/messages', '/events', '/stream', '/sse/message']) {
        for (const method of ['GET', 'POST']) {
          const res = await request(port, {
            method,
            requestPath,
            headers: MCP_POST_HEADERS,
            ...(method === 'POST' ? { body: INITIALIZE_BODY } : {}),
          });
          assert.equal(res.status, 404, `${method} ${requestPath}: ${res.status} ${res.body}`);
          assert.equal(res.headers['mcp-session-id'], undefined);
        }
      }
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-04: an unsupported method on /mcp is 405 and mutates nothing', async () => {
    const { server, port } = await startRemote({ tag: 'neg04' });
    try {
      const { res: init, sessionId, token } = await initializeSession(port);
      assert.equal(init.status, 200, `${init.status} ${init.body}`);
      assert.ok(sessionId, 'initialize must issue a server session');
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);

      // Every method outside {GET, POST, DELETE} is refused, authenticated or
      // not, and the session is untouched.
      for (const method of ['PUT', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']) {
        const res = await request(port, {
          method,
          headers: MCP_POST_HEADERS,
          requestPath: '/mcp',
        });
        assert.equal(res.status, 405, `${method}: ${res.status} ${res.body}`);
        assert.equal(res.headers.allow, 'GET, POST, DELETE', method);
        assert.equal(res.headers['mcp-session-id'], undefined, method);
      }
      assert.equal(server.sessionManager.getActiveSessionCount(), 1, 'the session must survive');
      assert.equal(server.sessionManager.hasSession(sessionId), true);
      void token;

      // /enroll/complete stays POST-only.
      const enrollGet = await request(port, { method: 'GET', requestPath: '/enroll/complete' });
      assert.equal(enrollGet.status, 405);
      assert.equal(enrollGet.headers.allow, 'POST');
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §10 Host validation and §11 Origin default-deny
  // =========================================================================

  test('RC05-NEG-02: a Host that is not the configured public hostname is refused before MCP', async () => {
    const { server, port } = await startRemote({ tag: 'host' });
    try {
      for (const host of [
        'evil.test',
        'localhost.evil.test',
        '127.0.0.1',
        'localhost:abc',
        'local host',
        'localhost, evil.test',
        'evil.test:443',
      ]) {
        const res = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, Host: host },
          body: INITIALIZE_BODY,
        });
        assert.equal(res.status, 403, `Host=${JSON.stringify(host)}: ${res.status} ${res.body}`);
        assert.equal(res.headers['mcp-session-id'], undefined, host);
        assert.equal(res.headers['arc-session-token'], undefined, host);
      }
      // A forwarded-host header can never substitute for the real Host: ARC has
      // no reverse-proxy trust model.
      const forwarded = await request(port, {
        method: 'POST',
        headers: {
          ...MCP_POST_HEADERS,
          Host: 'evil.test',
          'X-Forwarded-Host': 'localhost',
        },
        body: INITIALIZE_BODY,
      });
      assert.equal(forwarded.status, 403);

      // The correct hostname is accepted, with or without a port. The port is
      // deliberately NOT part of the comparison: §10 makes the PUBLIC HOSTNAME
      // the authority, and a port grants no identity — it is the same reasoning
      // that makes hostname-only comparison correct for DNS-rebinding defence.
      for (const host of ['localhost', `localhost:${port}`, 'LOCALHOST', 'localhost:1']) {
        const ok = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, Host: host },
          body: INITIALIZE_BODY,
        });
        assert.equal(ok.status, 200, `Host=${host}: ${ok.status} ${ok.body}`);
        assert.ok(ok.headers['mcp-session-id'], host);
      }
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: any Origin is refused by default and no CORS header is ever emitted', async () => {
    const { server, port } = await startRemote({ tag: 'origin' });
    try {
      for (const origin of ['https://evil.test', 'null', 'http://localhost']) {
        const res = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, Origin: origin },
          body: INITIALIZE_BODY,
        });
        assert.equal(res.status, 403, `Origin=${origin}: ${res.status} ${res.body}`);
        assert.equal(res.headers['access-control-allow-origin'], undefined, origin);
        assert.equal(res.headers['mcp-session-id'], undefined, origin);
      }
      // The success path emits no CORS header either: nothing is wildcarded,
      // reflected, or credentialed.
      const ok = await initializeSession(port);
      assert.equal(ok.res.status, 200);
      assert.equal(ok.res.headers['access-control-allow-origin'], undefined);
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §6 tokenless initialize
  // =========================================================================

  test('RC05-NEG-02: tokenless initialize issues a server session and a one-time token', async () => {
    const { server, port } = await startRemote({ tag: 'init' });
    try {
      const { res, sessionId, token } = await initializeSession(port);

      assert.equal(res.status, 200, `${res.status} ${res.body}`);
      // The session ID is the SERVER's, generated through the Task-5 authority.
      assert.match(sessionId, /^[0-9a-f]{64}$/);
      assert.match(token, /^[0-9a-f]{64}$/);
      assert.equal(server.sessionManager.hasSession(sessionId), true);

      // The raw token is delivered as a header and NOWHERE else: it is not in
      // the JSON-RPC body, and it is not the session ID.
      assert.equal(res.body.includes(token), false, 'the token must never be in the body');
      assert.notEqual(token, sessionId);

      // The server cannot hand the token out again: it retained only a digest.
      const again = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: INITIALIZED_NOTIFICATION,
      });
      assert.equal(again.headers['arc-session-token'], undefined);

      // The response adopted a server-issued ID even though the client supplied
      // its own well-formed `Mcp-Session-Id` — a client ID is never adopted.
      const forged = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, 'Mcp-Session-Id': 'a'.repeat(64) },
        body: INITIALIZE_BODY,
      });
      assert.equal(forged.status, 200, `${forged.status} ${forged.body}`);
      assert.notEqual(forged.headers['mcp-session-id'], 'a'.repeat(64));
      assert.match(forged.headers['mcp-session-id'], /^[0-9a-f]{64}$/);
      assert.equal(server.sessionManager.hasSession('a'.repeat(64)), false);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: a tokenless ORDINARY request is refused and mints nothing', async () => {
    const { server, port } = await startRemote({ tag: 'ordinary' });
    try {
      // Not an initialize, no session, no credential: generic UNAUTHENTICATED.
      const res = await request(port, {
        method: 'POST',
        headers: MCP_POST_HEADERS,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      });
      assert.equal(res.status, 401, `${res.status} ${res.body}`);
      assert.deepEqual(JSON.parse(res.body), {
        code: 'UNAUTHENTICATED',
        message: 'Authentication failed',
      });
      assert.equal(res.headers['mcp-session-id'], undefined);
      assert.equal(res.headers['arc-session-token'], undefined);
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(server.sessionManager.getReservedSessionIdCount(), 0);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §7 dual-header enforcement on ordinary requests
  // =========================================================================

  test('RC05-NEG-02: an ordinary request needs BOTH the session ID and the bearer token', async () => {
    const { server, port } = await startRemote({ tag: 'dual' });
    try {
      const { sessionId, token } = await initializeSession(port);
      const call = JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'health', arguments: {} },
      });

      const cases = [
        ['no headers', {}],
        ['session id only', { 'Mcp-Session-Id': sessionId }],
        ['token only', { Authorization: `Bearer ${token}` }],
        ['wrong token', { ...sessionHeaders(sessionId, 'b'.repeat(64)) }],
        ['malformed bearer', { 'Mcp-Session-Id': sessionId, Authorization: token }],
        ['unknown session id', { ...sessionHeaders('c'.repeat(64), token) }],
      ];

      for (const [label, headers] of cases) {
        const res = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, ...headers },
          body: call,
        });
        assert.equal(res.status, 401, `${label}: ${res.status} ${res.body}`);
        const parsed = JSON.parse(res.body);
        assert.equal(
          parsed.code === 'UNAUTHENTICATED' || parsed.code === 'INVALID_SESSION_TOKEN',
          true,
          `${label}: ${res.body}`,
        );
      }

      // The real pair works.
      const ok = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: call,
      });
      assert.equal(ok.status, 200, `${ok.status} ${ok.body}`);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §8/§22 the shared execution pipeline
  // =========================================================================

  test('RC05-NEG-02: an authenticated tool call reaches the ONE shared pipeline', async () => {
    const { server, port } = await startRemote({ tag: 'pipeline' });
    try {
      const { sessionId, token } = await initializeSession(port);
      const res = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      });
      assert.equal(res.status, 200, `${res.status} ${res.body}`);
      const health = toolCallResult(responseMessages(res));
      // The tool result is the SHARED pipeline's, produced by the same code path
      // stdio uses — not a remote-only response.
      assert.equal(typeof health.policyEngineActive, 'boolean');
      assert.equal(health.transportMode, 'remote');
      assert.equal(health.remoteGatewayActive, true);
      assert.equal(
        server.sessionManager.getActiveSessionCount(),
        1,
        'exactly one session, the one that made the call',
      );
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: authentication does NOT imply authorization', async () => {
    const { server, port } = await startRemote({ tag: 'authz' });
    try {
      const { sessionId, token } = await initializeSession(port);
      const res = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: { name: 'read_file', arguments: { path: '/etc/shadow' } },
        }),
      });
      // The call is fully authenticated and still refused: the EXISTING policy
      // engine decided, not the transport, and its verdict is unchanged.
      assert.equal(res.status, 200, `${res.status} ${res.body}`);
      const messages = responseMessages(res);
      const response = messages.find((message) => message.result !== undefined);
      assert.ok(response, JSON.stringify(messages).slice(0, 300));
      assert.equal(response.result.isError, true, JSON.stringify(response.result).slice(0, 300));
      const refusal = JSON.parse(response.result.content[0].text);
      assert.equal(refusal.code, 'POLICY_DENIED');
      assert.equal(refusal.category, 'AUTHORIZATION');
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §12 GET stream and §13 DELETE termination
  // =========================================================================

  test('RC05-NEG-02: GET opens a stream only for an authenticated session', async () => {
    const { server, port } = await startRemote({ tag: 'get' });
    try {
      // Unauthenticated GET: no stream, generic refusal.
      const anon = await request(port, { method: 'GET' });
      assert.equal(anon.status, 401, `${anon.status} ${anon.body}`);
      assert.deepEqual(JSON.parse(anon.body), {
        code: 'UNAUTHENTICATED',
        message: 'Authentication failed',
      });

      const { sessionId, token } = await initializeSession(port);

      // Authenticated GET: the Streamable HTTP server-to-client SSE stream.
      const streamed = await new Promise((resolve, reject) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port,
            method: 'GET',
            path: '/mcp',
            servername: 'localhost',
            ca: [fs.readFileSync(pki.trustedCaCertPath)],
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
            headers: {
              Host: 'localhost',
              Accept: 'text/event-stream',
              ...sessionHeaders(sessionId, token),
            },
          },
          (res) => resolve({ res, req }),
        );
        req.on('error', reject);
        req.end();
      });
      assert.equal(streamed.res.statusCode, 200, `${streamed.res.statusCode}`);
      assert.match(streamed.res.headers['content-type'] ?? '', /text\/event-stream/);
      streamed.req.destroy();
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: DELETE tears down exactly that session and its credentials', async () => {
    const { server, port } = await startRemote({ tag: 'delete' });
    try {
      const first = await initializeSession(port);
      const second = await initializeSession(port);
      assert.equal(server.sessionManager.getActiveSessionCount(), 2);

      const deleted = await request(port, {
        method: 'DELETE',
        headers: sessionHeaders(first.sessionId, first.token),
      });
      assert.equal(deleted.status, 200, `${deleted.status} ${deleted.body}`);
      assert.equal(server.sessionManager.hasSession(first.sessionId), false);

      // The OTHER session is untouched.
      assert.equal(server.sessionManager.hasSession(second.sessionId), true);
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);

      // The torn-down credentials no longer work, with or without the ID.
      for (const headers of [
        sessionHeaders(first.sessionId, first.token),
        { Authorization: `Bearer ${first.token}` },
      ]) {
        const res = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, ...headers },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 6,
            method: 'tools/call',
            params: { name: 'health', arguments: {} },
          }),
        });
        assert.equal(res.status, 401, `${res.status} ${res.body}`);
      }

      // The surviving session still works.
      const ok = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(second.sessionId, second.token) },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 7,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      });
      assert.equal(ok.status, 200, `${ok.status} ${ok.body}`);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §14/§16/§17 health
  // =========================================================================

  test('RC05-NEG-02: zero enrolled devices is healthy, not a listener failure', async () => {
    const { server, port } = await startRemote({ tag: 'zero', enrolled: false });
    try {
      const gatewayStatus = server.getRemoteGatewayStatus();
      assert.equal(gatewayStatus.listenerActive, true);
      assert.equal(gatewayStatus.activeAndServing, true);

      // The enrollment bootstrap is reachable without any device enrolled.
      const enroll = await request(port, {
        method: 'POST',
        requestPath: '/enroll/complete',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'd'.repeat(64) }),
      });
      // No device is enrolled and no challenge exists, so the uniform unenrolled
      // failure is returned — which proves the endpoint is operational.
      assert.equal(enroll.status, 400, `${enroll.status} ${enroll.body}`);
      assert.deepEqual(JSON.parse(enroll.body), { error: 'Enrollment failed' });

      // An unenrolled device cannot bootstrap a session, and cannot create a
      // device through MCP either.
      const init = await initializeSession(port);
      assert.equal(init.res.status, 401, `${init.res.status} ${init.res.body}`);
      assert.equal(init.sessionId, undefined);
      assert.equal(init.token, undefined);
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: health reports the completed Task-8 fields with counts only', async () => {
    const storePath = trustStoreForClient('health');
    const { server, port } = await startRemote({ tag: 'health', trustStorePath: storePath });
    try {
      const { sessionId, token } = await initializeSession(port);
      const res = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 8,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      });
      const health = toolCallResult(responseMessages(res));

      assert.equal(health.transportMode, 'remote');
      assert.equal(health.remoteGatewayActive, true);
      assert.equal(health.authenticationActive, true);
      assert.equal(health.enrolledDevicesCount, 1);
      assert.equal(health.activeSessionsCount, 1);
      assert.equal(health.status, 'HEALTHY');
      assert.equal(health.degradedReason, undefined);

      // Counts are acceptable; material is not. Nothing in the payload names a
      // certificate, a key, a path, a pin, a token, a peer, or a device.
      const serialized = JSON.stringify(health);
      for (const forbidden of [
        'BEGIN CERTIFICATE',
        'PRIVATE KEY',
        pki.serverCertPath,
        storePath,
        token,
        sessionId,
        clientSpkiPin(),
        '127.0.0.1',
      ]) {
        assert.equal(
          serialized.includes(forbidden),
          false,
          `health must not disclose ${forbidden}`,
        );
      }
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-02: stdio mode reports no remote authentication and no sessions', async () => {
    const server = createArcMcpServer({ transport: 'stdio', authorizedRoots: [] });
    try {
      const health = await server.dispatchToolCall('health', {});
      const parsed = JSON.parse(health.content[0].text);
      assert.equal(parsed.transportMode, 'stdio');
      assert.equal(parsed.remoteGatewayActive, false);
      assert.equal(parsed.authenticationActive, false);
      assert.equal(parsed.enrolledDevicesCount, 0);
      assert.equal(parsed.activeSessionsCount, 0);
      assert.equal(server.getRemoteGatewayStatus(), undefined);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §15 stdio and remote are mutually exclusive
  // =========================================================================

  test('RC05-NEG-02: remote mode composes no stdio listener and gains no stdio surface', async () => {
    const { server, port } = await startRemote({ tag: 'exclusive' });
    try {
      assert.equal(server.getTransportMode(), 'remote');
      assert.ok(server.getRemoteGatewayStatus(), 'remote mode binds the TLS listener');

      // The process serves MCP over TLS only. There is no second, plain
      // listener: the only port the composition opened is the TLS one, and it
      // refuses a client that presents no certificate.
      const plaintext = await new Promise((resolve) => {
        const socket = net.connect({ host: '127.0.0.1', port });
        socket.once('connect', () => {
          socket.write('GET /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n');
        });
        socket.once('data', (chunk) => {
          socket.destroy();
          resolve(chunk.toString('utf8'));
        });
        socket.once('error', () => resolve(''));
        socket.once('close', () => resolve(''));
        setTimeout(() => {
          socket.destroy();
          resolve('');
        }, 2000).unref();
      });
      // A plaintext HTTP request never yields an HTTP response: the TLS listener
      // cannot speak it, and no cleartext fallback exists.
      assert.equal(plaintext.includes('HTTP/1.1 200'), false);
    } finally {
      await server.stop();
    }

    const stdio = createArcMcpServer({ transport: 'stdio', authorizedRoots: [] });
    try {
      await stdio.start();
      assert.equal(stdio.getTransportMode(), 'stdio');
      // Stdio mode composes no remote gateway, so no TLS listener, no device
      // trust store, no sessions, and no Host/Origin validation exist at all.
      assert.equal(stdio.getRemoteGatewayStatus(), undefined);
      assert.equal(stdio.getRemoteExecutionBridge(), undefined);
      assert.equal(stdio.sessionManager.getActiveSessionCount(), 0);
    } finally {
      await stdio.stop();
    }
  });

  // =========================================================================
  // §5/RC05-NEG-06 stateful mode is mandatory
  // =========================================================================

  test('RC05-NEG-06: the stateful session-ID generator is always supplied', () => {
    // Structural: the transport is constructed in exactly one place and always
    // receives a real generator, so stateless mode is unreachable in production.
    const source = fs.readFileSync(
      new URL('../apps/mcp-server/src/remote-mcp-surface.ts', import.meta.url),
      'utf8',
    );
    // Comments are stripped first, so the module may DOCUMENT the options it
    // refuses without the documentation itself satisfying the check.
    const code = source
      .split('\n')
      .filter((line) => !/^\s*(\*|\/\/|\/\*)/.test(line))
      .join('\n');

    assert.equal(code.includes('new StreamableHTTPServerTransport({'), true);
    assert.equal(code.includes('sessionIdGenerator:'), true);
    // No event store: resumability and replay are out of scope (§3).
    assert.equal(code.includes('eventStore'), false);
    // The deprecated SDK rebinding options are not ARC's security boundary.
    assert.equal(code.includes('allowedHosts'), false);
    assert.equal(code.includes('allowedOrigins'), false);
    assert.equal(code.includes('enableDnsRebindingProtection'), false);
    // No stateless escape hatch.
    assert.equal(code.includes('sessionIdGenerator: undefined'), false);
  });

  test('RC05-NEG-06: a gateway with an unusable session authority fails closed with no listener', async () => {
    const port = await freePort();
    const server = createArcMcpServer({
      transport: 'remote',
      authorizedRoots: [],
      remote: {
        bindHost: '127.0.0.1',
        port,
        publicHostname: 'localhost',
        serverCertificatePath: pki.serverCertPath,
        privateKey: { kind: 'file', path: pki.serverKeyPath },
        clientCaPaths: [pki.trustedCaCertPath],
        trustStorePath: createEmptyTrustStore(tempRoot, `neg06-${++counter}.json`),
      },
    });

    // Break the session authority BEFORE start, so the surface cannot obtain its
    // generator. Startup must fail rather than silently compose a stateless or
    // session-less transport.
    const broken = server;
    broken.sessionManager.createSessionIdGenerator = () => undefined;
    await assert.rejects(() => broken.start(), /session ID generator/i);
    await broken.stop();

    // Nothing is bound: the port is free for another listener.
    await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen({ host: '127.0.0.1', port }, () => probe.close(() => resolve()));
    });
  });

  // =========================================================================
  // §18/§29 RC05-NEG-70 restart invalidation
  // =========================================================================

  test('RC05-NEG-70: a restart invalidates every session, token, and reservation', async () => {
    const storePath = trustStoreForClient('restart');
    const first = await startRemote({ tag: 'restart', trustStorePath: storePath });
    let sessionId;
    let token;
    try {
      const init = await initializeSession(first.port);
      sessionId = init.sessionId;
      token = init.token;
      assert.ok(sessionId);
      assert.ok(token);
      assert.equal(first.server.sessionManager.getActiveSessionCount(), 1);
    } finally {
      // Stop the listener: every live connection, transport, and session goes
      // with it. Only the client-side credentials are retained.
      await first.server.stop();
    }

    // A NEW composition over the SAME trust store file and the same config.
    const second = await startRemote({ tag: 'restart-2', trustStorePath: storePath });
    try {
      // 1. The persisted device enrollment SURVIVES the restart.
      assert.equal(second.server.getRemoteGatewayStatus().activeAndServing, true);

      // 2. Every pre-restart session is gone and no reservation is retained.
      assert.equal(second.server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(second.server.sessionManager.getReservedSessionIdCount(), 0);
      assert.equal(second.server.sessionManager.hasSession(sessionId), false);

      // 3. The pre-restart credentials are unusable against the new process.
      for (const headers of [
        sessionHeaders(sessionId, token),
        { 'Mcp-Session-Id': sessionId },
        { Authorization: `Bearer ${token}` },
      ]) {
        const res = await request(second.port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, ...headers },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 9,
            method: 'tools/call',
            params: { name: 'health', arguments: {} },
          }),
        });
        assert.equal(res.status, 401, `${JSON.stringify(headers)}: ${res.status} ${res.body}`);
        assert.equal(res.headers['mcp-session-id'], undefined);
      }

      // 4. No pre-restart SDK transport or session registry survived: the new
      //    process starts with an empty remote surface and hands out a DIFFERENT
      //    session ID for a fresh initialize.
      const fresh = await initializeSession(second.port);
      assert.equal(fresh.res.status, 200, `${fresh.res.status} ${fresh.res.body}`);
      assert.ok(fresh.sessionId);
      assert.notEqual(fresh.sessionId, sessionId);
      assert.notEqual(fresh.token, token);
      assert.equal(second.server.sessionManager.getActiveSessionCount(), 1);

      // 5. Approval state did not become persistent: the new process has none.
      assert.equal(second.server.approvalStateManager.listActive().length, 0);
    } finally {
      await second.server.stop();
    }
  });
});
