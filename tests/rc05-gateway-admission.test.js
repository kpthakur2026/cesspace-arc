/**
 * CesSpace ARC — RC-05 Task 8 correction: Streamable Gateway Admission Gaps
 *
 * Covers the four defects closed by `fix(rc-05): close streamable gateway
 * admission gaps`, each against the frozen contract:
 *
 * 1. §21.1 Layer C / §26 C-3 — the authenticated rate limiter and the
 *    per-session concurrency bound apply to EVERY authenticated MCP request
 *    (`tools/call`, `tools/list`, `ping`, GET SSE, and DELETE alike), on the ONE
 *    process-wide table, with a `tools/call` charged exactly ONCE.
 * 2. §11/§26 C-2 — the transport registry is reconciled against the
 *    authoritative Task-5 session manager, so an expired or revoked session's
 *    registry entry (and its SDK objects) is reclaimed and the frozen global
 *    capacity becomes reusable without a process restart.
 * 3. §19 — health reports the count of NON-REVOKED enrolled devices.
 * 4. §10/§11 — the Host and Origin authority checks run at the GATEWAY boundary
 *    for both configured remote endpoints, including `/enroll/complete`, and an
 *    unknown path stays a uniform 404.
 *
 * Every case drives the REAL composition: a real `ArcMcpServer` in remote mode,
 * a real TLS 1.3 listener with real mTLS client certificates, real HTTPS
 * requests, and the real Task-5 session authority, Task-4 enrollment authority,
 * and Task-7 resource limits. Where the SDK's own limits make a scenario
 * unreachable over the wire (the SDK permits ONE standalone SSE stream per
 * session), that is stated in the case and the same frozen table is driven
 * directly rather than inventing a weaker composition.
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * shared test PKI helper and removed with it; no certificate or key is
 * committed and no scanner suppression is used.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import {
  MCP_ADMISSION_ERROR_CODE,
  MCP_INVALID_REQUEST_ERROR_CODE,
  MCP_POST_REPLY_STATUS,
  MCP_STREAM_REPLY_STATUS,
  remoteRateLimitFailure,
} from '../apps/mcp-server/dist/remote-execution.js';
import {
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
} from '../apps/mcp-server/dist/remote-resource-limits.js';
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
  MAX_ACTIVE_SESSIONS_GLOBAL,
  SESSION_ABSOLUTE_TTL_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  SessionManager,
  deriveSpkiPin,
} from '../packages/auth/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** The configured public hostname. The single accepted `Host` value (§10). */
const publicHostname = 'localhost';

/** One Layer C token refills per this many milliseconds (300 requests/minute). */
const LAYER_C_REFILL_MS = 60_000 / LAYER_C_REQUESTS_PER_MINUTE;

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
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-admission-'));
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

/** The SPKI pin the gateway derives for the always-used client certificate. */
function clientPin() {
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
 * Writes a trust store holding `pins`, with the LAST `revokedCount` of them
 * marked revoked, and returns its path plus the records.
 *
 * `clientEnrolled` places the test client certificate's OWN SPKI pin at index 0.
 * Setting it false leaves the store non-empty but the connecting peer unknown —
 * the "recognized store, unrecognized SPKI" shape, which must be refused exactly
 * like an empty store.
 */
function trustStore(tag, pinCount, revokedCount = 0, clientEnrolled = true) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  const records = [];
  for (let index = 0; index < pinCount; index += 1) {
    const pin =
      index === 0 && clientEnrolled ? clientPin() : `${String(index).repeat(64)}`.slice(0, 64);
    const { device } = store.enrollDevice({
      clientId: `agent-${tag}-${index}`,
      clientType: 'claude-code',
      pin,
      displayLabel: `label-${tag}-${index}`,
    });
    records.push({ ...device, pin });
  }
  for (const record of records.slice(pinCount - revokedCount)) {
    store.revokeDevice(record.deviceId);
  }
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, records, store };
}

/**
 * Starts a REAL remote-mode `ArcMcpServer` over real mTLS.
 *
 * The server is constructed directly rather than through the factory so a case
 * can inject the Task-5 session authority (to drive the monotonic session clock
 * deterministically) and the Task-4 enrollment authority (to create a real
 * pending challenge without an admin IPC channel). Both injections are
 * composition-only: neither is reachable from `ArcServerConfig`, the
 * environment, the CLI, or the network.
 */
async function startRemote({
  tag = 'admission',
  pinCount = 1,
  revokedCount = 0,
  clientEnrolled = true,
  sessionClock,
  enrollmentManager,
} = {}) {
  const port = await freePort();
  const { storePath, records, store } = trustStore(tag, pinCount, revokedCount, clientEnrolled);
  const registry = new WorkspaceRegistry();
  const audit = new AuditLogger();
  const sessionManager =
    sessionClock === undefined
      ? undefined
      : new SessionManager({ getMonotonicTime: () => BigInt(sessionClock.now) * 1_000_000n });
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
      // RC-06 Task 6: `start()` refuses to bind any transport until the durable
      // audit runtime has reached startup step 12, so every started server is
      // composed over a real store.
      audit: createAuditConfig(tempRoot, `admission-${tag}`),
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
    undefined,
    enrollmentManager,
    sessionManager,
  );
  await server.start();
  return { server, port, storePath, records, store, audit };
}

/** One real HTTPS request over mTLS. */
function request(port, { method = 'POST', requestPath = '/mcp', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
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

/**
 * Asserts an MCP response carries a successful `result` for `id`.
 *
 * A request that was admitted and then failed inside the pipeline also spends a
 * token, so a token measurement alone cannot tell "executed once" from "refused
 * once". The result is therefore asserted alongside every charge measurement.
 */
function assertSucceeded(res, id, label) {
  assert.equal(res.status, 200, `${label}: ${res.status} ${res.body}`);
  const payload = payloadOf(res.body);
  assert.equal(payload.jsonrpc, '2.0', label);
  assert.equal(payload.id, id, label);
  assert.equal(payload.error, undefined, `${label}: ${res.body.slice(0, 200)}`);
  assert.ok(payload.result !== undefined, `${label}: ${res.body.slice(0, 200)}`);
  assert.notEqual(payload.result.isError, true, `${label}: ${res.body.slice(0, 200)}`);
  return payload.result;
}

/** The headers every POST /mcp must carry for the SDK to consider it valid. */
const MCP_POST_HEADERS = {
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
    clientInfo: { name: 'rc05-admission-test', version: '1.0.0' },
  },
});

/** A non-tool JSON-RPC request: it exercises Layer C without a tool call. */
function nonToolBody(id, method = 'tools/list') {
  return JSON.stringify({ jsonrpc: '2.0', id, method });
}

/** A JSON-RPC tool call for the shared-pipeline `health` tool. */
function toolCallBody(id) {
  return JSON.stringify({
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: 'health', arguments: {} },
  });
}

/** Performs the tokenless `initialize` handshake. */
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

/** Opens a real authenticated GET SSE stream and resolves on its response head. */
function openStream(port, sessionId, token) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method: 'GET',
        path: '/mcp',
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
        headers: {
          Host: publicHostname,
          Accept: 'text/event-stream',
          ...sessionHeaders(sessionId, token),
        },
      },
      (res) => resolve({ req, res }),
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * One authenticated GET whose response is read with a bound.
 *
 * A refused GET ends immediately, but an ADMITTED one is a live SSE stream that
 * never ends on its own, so the read is bounded and the socket destroyed rather
 * than left to hang a case that is asserting a refusal.
 */
function getBounded(port, sessionId, token, waitMs = 1500) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method: 'GET',
        path: '/mcp',
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
        headers: {
          Host: publicHostname,
          Accept: 'text/event-stream',
          ...sessionHeaders(sessionId, token),
        },
      },
      (res) => {
        const chunks = [];
        let settled = false;
        const finish = () => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          req.destroy();
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        };
        const timer = setTimeout(finish, waitMs);
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', finish);
        res.on('close', finish);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/** Waits for a condition, so a release is observed rather than slept through. */
async function waitFor(predicate, budgetMs = 2000) {
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

/** The ONE process-wide Layer C table behind an authenticated remote server. */
function layerC(server) {
  return server.authenticatedRequestLimiter;
}

/** The session's Layer C key, which only server-derived values may build. */
function keyFor(record, sessionId) {
  return `${record.deviceId}:${sessionId}`;
}

/**
 * Audit records that describe actual control-plane WORK.
 *
 * RC-05 Task 10 commits gateway LIFECYCLE transitions — a session transition, an
 * authentication outcome, an admission refusal — into the same append-only chain
 * that already carries ordinary MCP tool records and RC-04 approval lifecycle
 * records (§24). A lifecycle record describes the refusal itself; it is not
 * evidence that a policy evaluation, an approval transition, a tool dispatch, or
 * a subsystem call was reached.
 *
 * Counting those records out keeps an assertion about "nothing else ran" exactly
 * about the property it names, rather than about the total size of a chain that
 * legitimately also holds the refusal's own lifecycle record. It does not widen
 * what the case tolerates: every record that is NOT a gateway lifecycle record
 * — every tool record, policy decision, and approval transition — still has to
 * be absent for the count to be unchanged.
 */
function workRecords(audit) {
  return audit.getRecords().filter((record) => record.gateway === undefined);
}

/** The only retained key of a single-session case, asserted to be the expected one. */
function onlyKey(limiter, expected) {
  assert.deepEqual(limiter.getRetainedKeysForTests(), [expected]);
  return expected;
}

/**
 * The session's EFFECTIVE Layer C token count.
 *
 * `getBucket` reports the value as of the last `consume`; the limiter accrues
 * lazily on the next one. This applies the limiter's own documented formula so a
 * case can measure a token delta without sleeping for a refill.
 */
function effectiveTokens(limiter, key) {
  const bucket = limiter.getBucket(key);
  assert.ok(bucket, `the session key ${key} must be retained`);
  const elapsed = performance.now() - bucket.lastRefillMs;
  return Math.min(LAYER_C_BURST, bucket.tokens + elapsed / LAYER_C_REFILL_MS);
}

/**
 * Empties one session's Layer C rate budget through the SAME primitive the
 * admission authority uses, and returns how many tokens were available.
 *
 * The production composition exposes no clock seam for the Layer C table — the
 * frozen bounds are deliberately not parameterized — so the budget is exhausted
 * directly rather than by 300 real requests. The loop is synchronous and
 * completes in well under one refill interval.
 */
function drainBudget(limiter, key) {
  let drained = 0;
  while (limiter.consume(key).consumed) {
    drained += 1;
    assert.ok(drained <= LAYER_C_BURST, 'the drained budget must not exceed one burst');
  }
  return drained;
}

/**
 * Asserts one response is an MCP JSON-RPC error envelope carrying `arcCode`.
 *
 * §25 orders the error model by LAYER. The transport layers own status-only
 * refusals — Layer A drops the connection, Layer B answers `429` with no MCP
 * body, and 404/405/413 stay transport-level — while every refusal that happens
 * once a session is in play on `/mcp` is an MCP JSON-RPC error. So the shape is
 * asserted exactly: the JSON-RPC envelope, the MCP-channel error code, and the
 * ARC semantic code in `error.data.code`, with NOTHING else in the error object.
 *
 * A bare `429` is asserted against explicitly, because that is precisely the
 * Layer B transport model this refusal must not be confused with.
 */
function assertMcpRefusal(res, label, { status, arcCode, jsonRpcCode = MCP_ADMISSION_ERROR_CODE }) {
  assert.equal(res.status, status, `${label}: ${res.status} ${res.body}`);
  assert.notEqual(res.status, 429, `${label}: this is not the Layer B transport refusal`);
  assert.equal(res.headers['content-type'], 'application/json', label);
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.jsonrpc, '2.0', label);
  assert.deepEqual(Object.keys(parsed).sort(), ['error', 'id', 'jsonrpc'], label);
  assert.equal(parsed.error.code, jsonRpcCode, label);
  assert.equal(parsed.error.data.code, arcCode, label);
  // The refusal carries the frozen code and message and nothing else: no limiter
  // key, token count, retry-after, session identifier, or peer identity.
  assert.deepEqual(Object.keys(parsed.error).sort(), ['code', 'data', 'message'], label);
  assert.deepEqual(Object.keys(parsed.error.data), ['code'], label);
  assert.equal(typeof parsed.error.message, 'string', label);
  // No browser origin is ever granted access.
  assert.equal(res.headers['access-control-allow-origin'], undefined, label);
  return parsed;
}

/**
 * Asserts the frozen `RATE_LIMIT_EXCEEDED` refusal (§21.1 Layer C, §26 C-3).
 *
 * The observable semantic code is unchanged; only its framing is: Layer C runs
 * after authentication, so it answers on the MCP application channel and must
 * not reuse Layer B's bare status-and-body transport refusal.
 */
function assertRateLimited(res, label, { id, status = MCP_POST_REPLY_STATUS } = {}) {
  const parsed = assertMcpRefusal(res, label, { status, arcCode: 'RATE_LIMIT_EXCEEDED' });
  // The id is stated by every call site: a POST carries a JSON-RPC request the
  // reply must answer by id, and a GET/DELETE carries none and must use `null`.
  assert.equal(parsed.id, id, label);
  assert.equal(parsed.error.message, remoteRateLimitFailure().message, label);
  // A computed retry delay would disclose how full the bucket is.
  assert.equal(res.headers['retry-after'], undefined, label);
  return parsed;
}

/** Asserts the ONE uniform Host/Origin refusal (§10/§11). */
function assertAuthorityRefused(res, label) {
  assert.equal(res.status, 403, `${label}: ${res.status} ${res.body}`);
  assert.deepEqual(JSON.parse(res.body), { error: 'Forbidden' }, label);
  assert.equal(res.headers['access-control-allow-origin'], undefined, label);
  assert.equal(res.headers['mcp-session-id'], undefined, label);
  assert.equal(res.headers['arc-session-token'], undefined, label);
}

// ===========================================================================

describe('CesSpace ARC — RC-05 Task 8 correction: gateway admission gaps', () => {
  // =========================================================================
  // §21.1 Layer C: EVERY authenticated MCP request, on the ONE table
  // =========================================================================

  test('RC05-NEG-56: every authenticated MCP request is charged on the ONE process-wide Layer C table', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-every' });
    try {
      const limiter = layerC(server);

      // ONE limiter and ONE admission authority, shared by the transport and the
      // execution bridge. A second limiter would halve the effective budget and
      // halve the effective concurrency, so this identity is asserted, not
      // assumed.
      assert.equal(server.remoteExecutionBridge.authenticatedLimiter, limiter);
      assert.equal(server.remoteExecutionBridge.admission.authenticatedLimiter, limiter);
      assert.equal(
        server.remoteGateway.mcpSurface.deps.admission,
        server.remoteExecutionBridge.admission,
      );

      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      // A NON-tool request is admitted by the same authority: it is keyed on the
      // server-derived device and session identifiers, and it consumes budget.
      const list = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(2, 'tools/list'),
      });
      const listed = assertSucceeded(list, 2, 'tools/list');
      assert.ok(Array.isArray(listed.tools), 'the non-tool request really ran');
      onlyKey(limiter, key);

      // Token accounting is measured on the same table the tool path uses. The
      // bucket is taken below its cap first, so no accrual is clamped.
      const beforeList = effectiveTokens(limiter, key);
      const ping = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(3, 'ping'),
      });
      assertSucceeded(ping, 3, 'ping');
      const afterPing = effectiveTokens(limiter, key);
      const pingSpent = beforeList - afterPing;
      assert.ok(
        Math.abs(pingSpent - 1) <= 0.25,
        `a non-tool authenticated request spends ONE token, spent ${pingSpent}`,
      );
      onlyKey(limiter, key);

      // ...and a GET is charged on exactly the same key, not a stream-specific
      // one, so the stream shares the request budget rather than escaping it.
      const streamed = await openStream(port, sessionId, token);
      assert.equal(streamed.res.statusCode, 200);
      const afterStream = effectiveTokens(limiter, key);
      const streamSpent = afterPing - afterStream;
      assert.ok(
        Math.abs(streamSpent - 1) <= 0.25,
        `an authenticated GET SSE request spends ONE token, spent ${streamSpent}`,
      );
      onlyKey(limiter, key);
      streamed.req.destroy();
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: an exhausted session budget refuses the next request of EVERY kind', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-refuse' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      const first = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(2, 'tools/list'),
      });
      assert.equal(first.status, 200, `${first.status} ${first.body}`);
      onlyKey(limiter, key);

      // The refill is one token per 200 ms, so a request issued immediately after
      // the budget is emptied cannot have received a token. A request that
      // legitimately arrives after a refill interval is retried rather than
      // asserted, which keeps the case deterministic on a loaded machine without
      // weakening the property under test.
      // The first drain must find budget: a refusal only means something if
      // there was something to spend.
      const firstDrain = drainBudget(limiter, key);
      assert.ok(firstDrain > 0, 'the session starts with a spendable budget');

      const refusedKinds = [
        ['tools/list POST', { method: 'POST', body: nonToolBody(3, 'tools/list') }, 3],
        ['ping POST', { method: 'POST', body: nonToolBody(4, 'ping') }, 4],
        ['tools/call POST', { method: 'POST', body: toolCallBody(5) }, 5],
        // A GET carries no JSON-RPC request, so its refusal cannot echo an id.
        ['GET SSE', { method: 'GET' }, null],
      ];

      for (const [label, shape, expectedId] of refusedKinds) {
        for (let attempt = 0; ; attempt += 1) {
          drainBudget(limiter, key);
          // Measured from the moment the budget was emptied: a token can only
          // have been granted if a whole refill interval has passed since then.
          const drainedAt = performance.now();
          const res =
            shape.method === 'GET'
              ? await getBounded(port, sessionId, token)
              : await request(port, {
                  method: shape.method,
                  headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
                  body: shape.body,
                });
          const elapsed = performance.now() - drainedAt;
          // Layer C is refused on the MCP channel, so the refusal is recognised
          // by its JSON-RPC error code rather than by an HTTP status.
          if (res.body.includes('RATE_LIMIT_EXCEEDED')) {
            assertRateLimited(res, label, {
              id: expectedId,
              status: shape.method === 'GET' ? MCP_STREAM_REPLY_STATUS : MCP_POST_REPLY_STATUS,
            });
            break;
          }
          assert.ok(
            elapsed >= LAYER_C_REFILL_MS - 20,
            `${label}: only a refill may explain a ${res.status} after ${elapsed}ms`,
          );
          assert.ok(attempt < 4, `${label}: the budget must refuse the request`);
        }
      }

      // A rate refusal is not a session failure: the session, its token, and the
      // device binding all survive it.
      assert.equal(server.sessionManager.hasSession(sessionId), true);
      assert.equal(limiter.getRetainedKeyCount(), 1, 'the key stays retained, bounded at one');
      assert.ok(limiter.getRetainedKeyCount() <= MAX_LAYER_C_KEYS);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a tool call is charged exactly ONE token, never two', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-tool-token' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      // Warm-up, so the measured requests start below the burst cap and no
      // accrual is clamped.
      const warm = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(2, 'tools/list'),
      });
      assertSucceeded(warm, 2, 'warm-up');

      const before = effectiveTokens(limiter, key);
      const call = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: toolCallBody(3),
      });
      // The tool call must have EXECUTED: a rejected call would also spend one
      // token, so the charge and the execution are asserted together.
      const result = assertSucceeded(call, 3, 'tools/call');
      const health = JSON.parse(result.content[0].text);
      assert.equal(health.enrolledDevicesCount, 1, 'the shared pipeline really ran');
      const spent = before - effectiveTokens(limiter, key);

      // Exactly one: zero would mean the transport bypassed Layer C for a tool
      // call, and two would mean the call was charged once at the transport and
      // again inside the bridge.
      assert.ok(Math.abs(spent - 1) <= 0.25, `a tool call spends ONE token, spent ${spent}`);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: an outstanding GET SSE stream holds ONE concurrency slot until it closes', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-stream-slot' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      const streamed = await openStream(port, sessionId, token);
      assert.equal(streamed.res.statusCode, 200, `${streamed.res.statusCode}`);
      assert.match(streamed.res.headers['content-type'] ?? '', /text\/event-stream/);
      assert.equal(limiter.getHolderCount(key), 1, 'the open stream holds one slot');

      // The stream holds the SAME slot table the §26 C-3 bound counts against:
      // while it is open, the session has three slots left, not four.
      const simultaneous = await Promise.all([
        openStream(port, sessionId, token),
        openStream(port, sessionId, token),
        openStream(port, sessionId, token),
      ]);
      for (const extra of simultaneous) {
        // The SDK itself refuses a second standalone SSE stream for a session,
        // and every such refusal still releases the slot it was admitted with.
        assert.notEqual(extra.res.statusCode, 200, `${extra.res.statusCode}`);
        extra.req.destroy();
      }
      assert.equal(
        await waitFor(() => limiter.getHolderCount(key) === 1),
        true,
        'a refused stream releases its slot rather than leaking it',
      );

      streamed.req.destroy();
      assert.equal(
        await waitFor(() => limiter.getHolderCount(key) === 0),
        true,
        'closing the stream returns its slot',
      );
      assert.equal(server.remoteGateway.mcpSurface.liveAdmissions.size, 0);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: the fifth outstanding request of a session is refused immediately', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-concurrency' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      // One slot is held by a REAL open SSE stream. §26 C-3 bounds a session at
      // four OUTSTANDING requests, and the SDK permits only one standalone SSE
      // stream, so the remaining slots are taken on the same table the surface
      // consults rather than by inventing a second, weaker composition.
      const streamed = await openStream(port, sessionId, token);
      assert.equal(streamed.res.statusCode, 200);
      const bucket = limiter.getBucket(key);
      assert.ok(bucket, 'the stream created the session key');
      const holds = [];
      for (let index = 1; index < MAX_OUTSTANDING_REQUESTS_PER_SESSION; index += 1) {
        const hold = limiter.tryHold(bucket);
        assert.equal(hold.held, true, `slot ${index} must be available`);
        holds.push(hold);
      }
      assert.equal(limiter.getHolderCount(key), MAX_OUTSTANDING_REQUESTS_PER_SESSION);

      for (const [label, shape, expectedId] of [
        // A GET carries no JSON-RPC request, so its refusal cannot echo an id.
        ['GET SSE', { method: 'GET' }, null],
        ['tools/list POST', { method: 'POST', body: nonToolBody(2, 'tools/list') }, 2],
        ['tools/call POST', { method: 'POST', body: toolCallBody(3) }, 3],
      ]) {
        const startedAt = performance.now();
        const res =
          shape.method === 'GET'
            ? await getBounded(port, sessionId, token)
            : await request(port, {
                method: shape.method,
                headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
                body: shape.body,
              });
        const elapsed = performance.now() - startedAt;
        assertRateLimited(res, label, {
          id: expectedId,
          status: shape.method === 'GET' ? MCP_STREAM_REPLY_STATUS : MCP_POST_REPLY_STATUS,
        });
        // Refused, never queued: the refusal is immediate, so no work is
        // retained behind the session.
        assert.ok(elapsed < 1000, `${label}: refuse immediately, took ${elapsed}ms`);
        assert.equal(
          limiter.getHolderCount(key),
          MAX_OUTSTANDING_REQUESTS_PER_SESSION,
          `${label}: a refusal holds nothing`,
        );
      }

      // Releasing one outstanding slot makes the session admissible again: the
      // freed slot is immediately reusable, and a completed request returns the
      // slot it took.
      holds[0].release();
      assert.equal(limiter.getHolderCount(key), MAX_OUTSTANDING_REQUESTS_PER_SESSION - 1);
      const reusable = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(4, 'tools/list'),
      });
      assertSucceeded(reusable, 4, 'a released slot is immediately reusable');
      assert.equal(
        await waitFor(
          () => limiter.getHolderCount(key) === MAX_OUTSTANDING_REQUESTS_PER_SESSION - 1,
        ),
        true,
      );

      for (const hold of holds.slice(1)) {
        hold.release();
      }
      streamed.req.destroy();
      assert.equal(await waitFor(() => limiter.getHolderCount(key) === 0), true);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: sessions are independent in both rate and concurrency', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-independent' });
    try {
      const limiter = layerC(server);
      const first = await initializeSession(port);
      const second = await initializeSession(port);
      const firstKey = keyFor(records[0], first.sessionId);
      const secondKey = keyFor(records[0], second.sessionId);

      assert.equal(firstKey === secondKey, false, 'each session is its own key');
      assert.equal(second.res.status, 200, `${second.res.status} ${second.res.body}`);

      // Exhaust the FIRST session completely.
      drainBudget(limiter, firstKey);
      const refused = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(first.sessionId, first.token) },
        body: nonToolBody(2, 'tools/list'),
      });
      assertRateLimited(refused, 'the first session is refused', { id: 2 });

      // The SECOND session is untouched: it keeps its own budget, and its own
      // concurrency, and the first session's state is invisible to it.
      const allowed = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(second.sessionId, second.token) },
        body: nonToolBody(3, 'tools/list'),
      });
      assertSucceeded(allowed, 3, 'the second session is untouched');
      const secondBucket = limiter.getBucket(secondKey);
      assert.equal(secondBucket.holders, 0);

      // The first session's saturation holds only for the first session.
      const firstBucket = limiter.getBucket(firstKey);
      const holds = [];
      for (let index = 0; index < MAX_OUTSTANDING_REQUESTS_PER_SESSION; index += 1) {
        holds.push(limiter.tryHold(firstBucket));
      }
      assert.equal(limiter.getHolderCount(firstKey), MAX_OUTSTANDING_REQUESTS_PER_SESSION);
      const stillAllowed = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(second.sessionId, second.token) },
        body: nonToolBody(4, 'ping'),
      });
      assertSucceeded(stillAllowed, 4, 'the second session keeps its own concurrency');
      for (const hold of holds) {
        hold.release();
      }
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: every terminal path returns its Layer C slot', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-release' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);
      const holders = () => limiter.getHolderCount(key);
      const drained = () =>
        waitFor(() => holders() === 0 && server.remoteGateway.mcpSurface.liveAdmissions.size === 0);

      // 1. A successful tool call.
      const ok = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: toolCallBody(2),
      });
      assertSucceeded(ok, 2, 'a successful tool call');
      assert.equal(await drained(), true, 'a successful call returns its slot');

      // 2. A pipeline refusal: the actor/transport field guard rejects the call
      // before any subsystem runs, and the slot is still returned.
      const injection = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'health', arguments: { deviceId: 'spoofed' } },
        }),
      });
      assert.equal(injection.status, 200, `${injection.status} ${injection.body}`);
      assert.match(injection.body, /isError/);
      assert.equal(await drained(), true, 'a refused call returns its slot');

      // 3. A protocol error: a malformed JSON body never reaches a handler, and
      // the transport answers with a JSON-RPC parse error.
      const malformed = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: '{"jsonrpc":"2.0",',
      });
      assert.equal(malformed.status, 400, `${malformed.status} ${malformed.body}`);
      assert.equal(await drained(), true, 'a protocol error returns its slot');

      // 4. A rate refusal itself.
      drainBudget(limiter, key);
      const refused = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(4, 'tools/list'),
      });
      assertRateLimited(refused, 'a rate refusal', { id: 4 });
      assert.equal(await drained(), true, 'a refusal returns its slot');

      // The refusal above emptied the budget on purpose, so the remaining steps
      // wait for a refill rather than measuring a rate limit instead of a slot.
      assert.equal(
        await waitFor(() => effectiveTokens(limiter, key) >= 4.05, 5000),
        true,
        'the session budget refills',
      );

      // 5. A closed stream.
      const streamed = await openStream(port, sessionId, token);
      assert.equal(streamed.res.statusCode, 200);
      assert.equal(holders(), 1, 'the stream is outstanding');
      streamed.req.destroy();
      assert.equal(await drained(), true, 'a closed stream returns its slot');

      // 6. DELETE: the terminating request is charged like any other and returns
      // its slot as the session goes.
      const deleted = await request(port, {
        method: 'DELETE',
        headers: sessionHeaders(sessionId, token),
      });
      assert.equal(deleted.status, 200, `${deleted.status} ${deleted.body}`);
      assert.equal(server.sessionManager.hasSession(sessionId), false);
      assert.equal(await drained(), true, 'DELETE returns its slot');

      // 7. Shutdown with a stream still open: `closeAll()` is the drain
      // `gateway.stop()` performs, and it releases slots whose response listeners
      // a hard stop may never deliver.
      const second = await initializeSession(port);
      const secondKey = keyFor(records[0], second.sessionId);
      const live = await openStream(port, second.sessionId, second.token);
      assert.equal(live.res.statusCode, 200);
      assert.equal(limiter.getHolderCount(secondKey), 1);
      await server.remoteGateway.mcpSurface.closeAll();
      assert.equal(limiter.getHolderCount(secondKey), 0, 'shutdown releases held slots');
      assert.equal(server.remoteGateway.mcpSurface.liveAdmissions.size, 0);
      assert.equal(server.remoteGateway.mcpSurface.getActiveSessionCount(), 0);
      live.req.destroy();
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §11/§26 C-2: the transport registry is reconciled with the session authority
  // =========================================================================

  /** Installs a closure observer on a registry entry's SDK transport. */
  function observeClose(entry) {
    const previous = entry.transport.onclose;
    const observed = { closed: 0 };
    entry.transport.onclose = () => {
      observed.closed += 1;
      previous?.();
    };
    return observed;
  }

  test('RC05-NEG-56: an expired session is reaped from the registry and its SDK objects close, with no restart', async () => {
    const clock = { now: 1_000_000 };
    const { server, port, records } = await startRemote({
      tag: 'reap-expired',
      sessionClock: clock,
    });
    try {
      const surface = server.remoteGateway.mcpSurface;

      // 1. A live session exists in BOTH the authority and the registry.
      const first = await initializeSession(port);
      assert.match(first.sessionId, /^[0-9a-f]{64}$/);
      assert.equal(server.sessionManager.hasSession(first.sessionId), true);
      assert.equal(surface.getActiveSessionCount(), 1);
      const entry = surface.sessions.get(first.sessionId);
      assert.ok(entry, 'the registry holds the transport for the live session');
      const observed = observeClose(entry);

      // 2. The injected monotonic clock advances past the idle expiry.
      clock.now += (SESSION_IDLE_TIMEOUT_SECONDS + 1) * 1000;

      // 3-4. Expiry is made observable: the authority no longer holds the
      // session, which is the ONLY condition that may reclaim a registry entry.
      assert.equal(server.sessionManager.hasSession(first.sessionId), false);
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);

      // 5-7. A fresh tokenless initialize reconciles the registry BEFORE its
      // occupancy is used as a capacity decision, so the dead entry is reclaimed
      // and its SDK server and transport are closed — and a NEW session is
      // established in the same process, with a different identity.
      const second = await initializeSession(port);
      assert.equal(second.res.status, 200, `${second.res.status} ${second.res.body}`);
      assert.notEqual(second.sessionId, first.sessionId);
      assert.equal(surface.sessions.has(first.sessionId), false, 'the dead entry is reclaimed');
      assert.equal(observed.closed, 1, 'the dead transport was closed');
      assert.equal(
        surface.getActiveSessionCount(),
        1,
        'the reclaimed entry did not pin capacity: exactly one live session remains',
      );
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);

      // The fresh session is fully usable, and it is keyed on its OWN identity:
      // the reaped session left nothing behind on the shared Layer C table.
      const usable = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(second.sessionId, second.token) },
        body: nonToolBody(2, 'tools/list'),
      });
      assert.equal(usable.status, 200, `${usable.status} ${usable.body}`);
      const keys = layerC(server).getRetainedKeysForTests();
      assert.equal(
        keys.includes(keyFor(records[0], first.sessionId)),
        false,
        'the reaped session holds no Layer C key',
      );
      assert.equal(keys.includes(keyFor(records[0], second.sessionId)), true);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a revoked session is reaped when it is next presented', async () => {
    const { server, port } = await startRemote({ tag: 'reap-revoked' });
    try {
      const surface = server.remoteGateway.mcpSurface;
      const { sessionId, token } = await initializeSession(port);
      const entry = surface.sessions.get(sessionId);
      assert.ok(entry);
      const observed = observeClose(entry);

      // Revocation is a Task-5 authority decision; the registry must follow it.
      assert.equal(server.sessionManager.revokeSession(sessionId), true);

      const presented = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(2, 'tools/list'),
      });
      const refusal = assertMcpRefusal(presented, 'a reaped session', {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'INVALID_SESSION_TOKEN',
      });
      assert.equal(refusal.id, 2, 'the refusal answers the request it refused');
      assert.equal(surface.sessions.has(sessionId), false, 'the revoked entry is reclaimed');
      assert.equal(observed.closed, 1, 'its SDK transport was closed');
      assert.equal(surface.getActiveSessionCount(), 0);

      // Capacity is immediately reusable without a restart.
      const fresh = await initializeSession(port);
      assert.equal(fresh.res.status, 200, `${fresh.res.status} ${fresh.res.body}`);
      assert.equal(surface.getActiveSessionCount(), 1);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a wrong token for a LIVE session never destroys that session', async () => {
    const { server, port, records } = await startRemote({ tag: 'reap-safety' });
    try {
      const surface = server.remoteGateway.mcpSurface;
      const { sessionId, token } = await initializeSession(port);
      const entry = surface.sessions.get(sessionId);
      assert.ok(entry);
      const observed = observeClose(entry);

      // A wrong bearer token is an authentication failure, not evidence that the
      // session is gone. Reaping on that basis would let any caller destroy a
      // legitimate session by presenting a bad credential.
      for (const [label, shape, expectedId, expectedStatus] of [
        [
          'POST with a wrong token',
          {
            method: 'POST',
            headers: sessionHeaders(sessionId, 'b'.repeat(64)),
            body: nonToolBody(2, 'tools/list'),
          },
          2,
          MCP_POST_REPLY_STATUS,
        ],
        [
          'GET with a wrong token',
          { method: 'GET', headers: sessionHeaders(sessionId, 'c'.repeat(64)) },
          null,
          MCP_STREAM_REPLY_STATUS,
        ],
        [
          'DELETE with a wrong token',
          { method: 'DELETE', headers: sessionHeaders(sessionId, 'd'.repeat(64)) },
          null,
          MCP_STREAM_REPLY_STATUS,
        ],
      ]) {
        const res = await request(port, {
          method: shape.method,
          headers: {
            ...(shape.method === 'POST' ? MCP_POST_HEADERS : {}),
            ...shape.headers,
          },
          ...(shape.body === undefined ? {} : { body: shape.body }),
        });
        // §25: a wrong token is a post-session admission failure, so it is
        // MCP-framed and never discloses which of the several possible causes it
        // was. The session itself must survive it.
        const refusal = assertMcpRefusal(res, label, {
          status: expectedStatus,
          arcCode: 'INVALID_SESSION_TOKEN',
        });
        assert.equal(refusal.id, expectedId, label);
        assert.equal(res.body.includes(token), false, `${label}: no credential is echoed`);
        assert.equal(surface.sessions.has(sessionId), true, `${label}: the entry must survive`);
        assert.equal(
          server.sessionManager.hasSession(sessionId),
          true,
          `${label}: the session lives`,
        );
        assert.equal(observed.closed, 0, `${label}: the transport must not be closed`);
        assert.equal(surface.getActiveSessionCount(), 1, label);
      }

      // The legitimate credential still works, and its slot is returned.
      const ok = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(3, 'tools/list'),
      });
      assert.equal(ok.status, 200, `${ok.status} ${ok.body}`);
      assert.equal(
        await waitFor(() => layerC(server).getHolderCount(keyFor(records[0], sessionId)) === 0),
        true,
        'the surviving session returns its slot',
      );
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: registry capacity pinned by dead entries is reclaimed at the frozen cap', async () => {
    const { server, port } = await startRemote({ tag: 'reap-capacity' });
    try {
      const surface = server.remoteGateway.mcpSurface;

      // Simulate what leaked entries look like: registry entries whose sessions
      // the authoritative manager has never held (expired or revoked sessions
      // are removed from the authority first, so their entries are exactly this:
      // present in the registry, absent from the authority).
      let closedServers = 0;
      let closedTransports = 0;
      for (let index = 0; index < MAX_ACTIVE_SESSIONS_GLOBAL; index += 1) {
        const fakeId = `${index.toString(16).padStart(8, '0')}${'0'.repeat(56)}`;
        surface.sessions.set(fakeId, {
          sessionId: fakeId,
          server: {
            close: async () => {
              closedServers += 1;
            },
          },
          transport: {
            close: async () => {
              closedTransports += 1;
            },
          },
        });
      }
      assert.equal(surface.getActiveSessionCount(), MAX_ACTIVE_SESSIONS_GLOBAL);

      // At the cap, the ONLY thing that can admit a new session is the
      // reconciliation — and it must be a limit on ACTIVE sessions, not a
      // lifetime count of every session the process ever created.
      const fresh = await initializeSession(port);
      assert.equal(fresh.res.status, 200, `${fresh.res.status} ${fresh.res.body}`);
      assert.equal(surface.getActiveSessionCount(), 1, 'the dead entries were reclaimed');
      assert.equal(closedServers, MAX_ACTIVE_SESSIONS_GLOBAL, 'every dead server was closed');
      assert.equal(closedTransports, MAX_ACTIVE_SESSIONS_GLOBAL, 'every dead transport was closed');
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);
      assert.equal(server.sessionManager.getReservedSessionIdCount(), 0);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §19 health: non-revoked enrolled devices only
  // =========================================================================

  test('RC05-NEG-56: health counts only non-revoked enrolled devices', async () => {
    const cases = [
      { tag: 'health-zero', pinCount: 0, revokedCount: 0, expected: 0 },
      { tag: 'health-one', pinCount: 1, revokedCount: 0, expected: 1 },
      { tag: 'health-mixed', pinCount: 2, revokedCount: 1, expected: 1 },
      { tag: 'health-all-revoked', pinCount: 2, revokedCount: 2, expected: 0 },
    ];

    for (const shape of cases) {
      const { server } = await startRemote({
        tag: shape.tag,
        pinCount: shape.pinCount,
        revokedCount: shape.revokedCount,
      });
      try {
        const health = JSON.parse((await server.dispatchToolCall('health', {})).content[0].text);
        assert.equal(
          health.enrolledDevicesCount,
          shape.expected,
          `${shape.tag}: ${shape.pinCount} records, ${shape.revokedCount} revoked`,
        );
        assert.equal(health.authenticationActive, true, shape.tag);

        // The count is what the gateway is actually serving, so it agrees with
        // the gateway's own view of the trust root.
        assert.equal(server.remoteGateway.getEnrolledDeviceCount(), shape.expected, shape.tag);
      } finally {
        await server.stop();
      }
    }
  });

  test('RC05-NEG-56: health exposes counts only, never the trust-store records', async () => {
    const { server, storePath, records } = await startRemote({
      tag: 'health-leak',
      pinCount: 3,
      revokedCount: 2,
    });
    try {
      const health = JSON.parse((await server.dispatchToolCall('health', {})).content[0].text);
      assert.equal(health.enrolledDevicesCount, 1);

      const serialized = JSON.stringify(health);
      for (const record of records) {
        assert.equal(serialized.includes(record.deviceId), false, 'no device identifier escapes');
        assert.equal(serialized.includes(record.pin), false, 'no SPKI pin escapes');
        assert.equal(serialized.includes(record.displayLabel), false, 'no device label escapes');
      }
      assert.equal(serialized.includes(storePath), false, 'no trust-store path escapes');
      assert.equal(health.devices, undefined, 'the records themselves are never reported');
      assert.equal(health.revokedDevicesCount, undefined, 'only the enrolled count is reported');
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §10/§11 gateway boundary authority, including /enroll/complete
  // =========================================================================

  /** One server whose trust store is empty and whose pending table is ours. */
  async function startWithChallenge(tag) {
    const enrollmentManager = new EnrollmentManager();
    const harness = await startRemote({ tag, pinCount: 0, enrollmentManager });
    const { enrollment, secret } = enrollmentManager.create({
      clientId: 'agent-alpha',
      clientType: 'claude-code',
      spkiPin: clientPin(),
      operatorId: 'a'.repeat(64),
    });
    return {
      ...harness,
      enrollmentManager,
      enrollment,
      secret,
      trustState: () =>
        JSON.stringify(harness.server.remoteGateway.bootstrap.authoritativeTrustStore.toData()),
    };
  }

  /** One `POST /enroll/complete` carrying the one-time secret. */
  function complete(port, secret, headers = {}) {
    return request(port, {
      method: 'POST',
      requestPath: '/enroll/complete',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify({ secret }),
    });
  }

  test('RC05-ENR-176: an Origin is refused on /enroll/complete before the body, and changes nothing', async () => {
    const harness = await startWithChallenge('enroll-origin');
    const { server, port } = harness;
    try {
      const trustBefore = harness.trustState();
      assert.equal(harness.enrollmentManager.getPendingCount(), 1);

      // Three refused attempts carrying a WRONG secret. If these requests
      // reached the enrollment manager they would each count against the
      // attempt lockout, so the correct secret below would fail — which is what
      // makes "no attempt counter mutation" observable rather than assumed.
      for (const origin of ['https://evil.test', 'null', 'http://localhost']) {
        const res = await complete(port, 'f'.repeat(64), { Origin: origin });
        assertAuthorityRefused(res, `Origin=${origin}`);
        assert.equal(res.headers['content-type'], 'application/json', origin);
      }

      // The refused requests touched no state at all.
      assert.equal(harness.enrollmentManager.getPendingCount(), 1, 'the challenge is untouched');
      assert.equal(harness.trustState(), trustBefore, 'the trust store is untouched');
      assert.equal(server.remoteGateway.getEnrolledDeviceCount(), 0);
      const stillPending = harness.enrollmentManager.get(harness.enrollment.enrollmentId);
      assert.ok(stillPending, 'the challenge is still pending');
      assert.equal(stillPending.spkiPin, clientPin());

      // The one-time secret is STILL VALID: nothing consumed it, and nothing
      // counted a failed attempt against its lockout.
      const enrolled = await complete(port, harness.secret);
      assert.equal(enrolled.status, 200, `${enrolled.status} ${enrolled.body}`);
      assert.deepEqual(JSON.parse(enrolled.body), { status: 'enrolled' });
      assert.equal(enrolled.headers['access-control-allow-origin'], undefined);
      assert.equal(server.remoteGateway.getEnrolledDeviceCount(), 1);

      // The endpoint is still exactly as reachable as before.
      assert.equal(server.remoteGateway.getStatus().activeAndServing, true);
    } finally {
      harness.enrollmentManager.clear();
      await server.stop();
    }
  });

  test('RC05-ENR-176: a bad secret still counts, so the refusal above is not a vacuous pass', async () => {
    const harness = await startWithChallenge('enroll-lockout');
    const { port } = harness;
    try {
      // A presented-but-wrong secret with the CORRECT Host and no Origin reaches
      // the enrollment manager and is counted. After the frozen three attempts
      // the challenge locks out, and the correct secret can no longer complete
      // it — which is exactly the outcome the refused requests must avoid.
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const res = await complete(port, 'f'.repeat(64));
        assert.equal(res.status, 400, `attempt ${attempt}: ${res.status} ${res.body}`);
      }
      const lockedOut = await complete(port, harness.secret);
      assert.equal(lockedOut.status, 400, `${lockedOut.status} ${lockedOut.body}`);
      assert.deepEqual(JSON.parse(lockedOut.body), { error: 'Enrollment failed' });
      assert.equal(harness.server.remoteGateway.getEnrolledDeviceCount(), 0);
      assert.equal(harness.enrollmentManager.get(harness.enrollment.enrollmentId), undefined);
    } finally {
      harness.enrollmentManager.clear();
      await harness.server.stop();
    }
  });

  test('RC05-ENR-176: a wrong or malformed Host fails closed on /enroll/complete before any verification', async () => {
    const harness = await startWithChallenge('enroll-host');
    const { port } = harness;
    try {
      const trustBefore = harness.trustState();
      const refusedHosts = [
        'evil.test',
        'evil.test:443',
        '192.0.2.10',
        'local host',
        'localhost, evil.test',
        'localhost:abc',
        '[2001:db8::1]',
        '',
      ];

      // Each carries the CORRECT secret: a request that reached verification
      // would enroll the device, so a 403 with an unchanged trust store proves
      // the refusal precedes verification.
      for (const host of refusedHosts) {
        const res = await complete(port, harness.secret, { Host: host });
        assertAuthorityRefused(res, `Host=${host}`);
      }

      assert.equal(harness.trustState(), trustBefore, 'no candidate store was ever written');
      assert.equal(harness.enrollmentManager.getPendingCount(), 1);
      assert.equal(harness.server.remoteGateway.getEnrolledDeviceCount(), 0);

      // Forwarding headers grant nothing: the real `Host` is the only authority.
      const forwarded = await complete(port, harness.secret, {
        Host: 'evil.test',
        'X-Forwarded-Host': publicHostname,
        'X-Forwarded-For': '192.0.2.11',
        Forwarded: `host=${publicHostname}`,
      });
      assertAuthorityRefused(forwarded, 'X-Forwarded-Host');
      assert.equal(harness.server.remoteGateway.getEnrolledDeviceCount(), 0);

      // ...and they neither block nor grant on the real host: the challenge is
      // still completable exactly once, with the real authority.
      const enrolled = await complete(port, harness.secret, {
        'X-Forwarded-Host': 'evil.test',
        'X-Forwarded-For': '192.0.2.12',
      });
      assert.equal(enrolled.status, 200, `${enrolled.status} ${enrolled.body}`);
      assert.equal(harness.server.remoteGateway.getEnrolledDeviceCount(), 1);
    } finally {
      harness.enrollmentManager.clear();
      await harness.server.stop();
    }
  });

  test('RC05-ENR-176: the authority refusal is written before the body is read', async () => {
    const harness = await startWithChallenge('enroll-prebody');
    const { port } = harness;
    try {
      // A request head that declares a body it never finishes. If the refusal
      // were decided AFTER the body read, this request would stall until the
      // body-read deadline; answering it at once proves the decision is made on
      // the head alone.
      for (const [label, head] of [
        ['Origin', `Origin: https://evil.test\r\n`],
        ['Host', ''],
      ]) {
        const hostLine = head === '' ? 'Host: evil.test\r\n' : `Host: ${publicHostname}\r\n`;
        const socket = tls.connect({
          host: '127.0.0.1',
          port,
          servername: publicHostname,
          ca: [fs.readFileSync(pki.trustedCaCertPath)],
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
          rejectUnauthorized: false,
        });
        await new Promise((resolve) => socket.once('secureConnect', resolve));

        const observed = new Promise((resolve) => {
          let received = '';
          socket.on('data', (chunk) => {
            received += chunk.toString('utf8');
          });
          socket.on('close', () => resolve(received));
          socket.on('error', () => resolve(received));
        });

        const startedAt = performance.now();
        socket.write(
          `POST /enroll/complete HTTP/1.1\r\n${hostLine}${head}Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n{"secret":`,
        );
        const response = await observed;
        const elapsed = performance.now() - startedAt;
        socket.destroy();

        assert.match(response, /^HTTP\/1\.1 403 /, `${label}: ${response.slice(0, 80)}`);
        assert.equal(
          response.includes('Enrollment failed'),
          false,
          `${label}: the router must not have run`,
        );
        // The body was never completed, so a prompt answer can only come from a
        // decision taken before the read.
        assert.ok(elapsed < 3000, `${label}: answered in ${elapsed}ms`);
      }

      assert.equal(harness.enrollmentManager.getPendingCount(), 1);
    } finally {
      harness.enrollmentManager.clear();
      await harness.server.stop();
    }
  });

  test('RC05-ENR-176: an unknown path stays a uniform 404 whatever the Host or Origin', async () => {
    const harness = await startWithChallenge('enroll-404');
    const { port } = harness;
    try {
      const shapes = [
        ['plain', {}],
        ['origin', { Origin: 'https://evil.test' }],
        ['wrong host', { Host: 'evil.test' }],
        ['wrong host and origin', { Host: 'evil.test', Origin: 'https://evil.test' }],
        ['forwarded host', { Host: 'evil.test', 'X-Forwarded-Host': publicHostname }],
      ];

      for (const requestPath of ['/admin', '/', '/mcp/extra', '/enroll']) {
        const observed = [];
        for (const [label, headers] of shapes) {
          const res = await request(port, {
            method: 'POST',
            requestPath,
            headers: { 'Content-Type': 'application/json', ...headers },
            body: JSON.stringify({ secret: 'f'.repeat(64) }),
          });
          // Moving the authority check to the gateway must not turn every
          // unknown-path probe into a Host/Origin oracle: the answer is the same
          // 404 for every shape.
          assert.equal(res.status, 404, `${requestPath} ${label}: ${res.status} ${res.body}`);
          assert.deepEqual(JSON.parse(res.body), { error: 'Not found' }, `${requestPath} ${label}`);
          assert.equal(
            res.headers['access-control-allow-origin'],
            undefined,
            `${requestPath} ${label}`,
          );
          observed.push(`${res.status}|${res.body}`);
        }
        assert.equal(new Set(observed).size, 1, `${requestPath} must answer identically`);
      }

      // The unknown-path probes reached no state at all.
      assert.equal(harness.enrollmentManager.getPendingCount(), 1);
      assert.equal(harness.server.remoteGateway.getEnrolledDeviceCount(), 0);
      assert.equal(harness.server.sessionManager.getActiveSessionCount(), 0);
    } finally {
      harness.enrollmentManager.clear();
      await harness.server.stop();
    }
  });

  test('RC05-ENR-176: both configured endpoints share ONE authority validator', async () => {
    const { server, port } = await startRemote({ tag: 'authority-shared' });
    try {
      // Behaviourally: the same bad Host and the same Origin produce the SAME
      // bounded refusal on both endpoints, so neither can drift.
      const refusals = [];
      for (const shape of [
        { requestPath: '/mcp', Host: 'evil.test' },
        { requestPath: '/enroll/complete', Host: 'evil.test' },
        { requestPath: '/mcp', Origin: 'https://evil.test' },
        { requestPath: '/enroll/complete', Origin: 'https://evil.test' },
      ]) {
        const res = await request(port, {
          method: 'POST',
          requestPath: shape.requestPath,
          headers: { 'Content-Type': 'application/json', ...shape },
          body: JSON.stringify({ secret: 'f'.repeat(64) }),
        });
        assertAuthorityRefused(res, `${shape.requestPath} ${JSON.stringify(shape)}`);
        assert.equal(res.headers['content-type'], 'application/json');
        refusals.push(`${res.status}|${res.body}|${res.headers.connection}`);
      }
      assert.equal(new Set(refusals).size, 1, 'one refusal, byte for byte, on both endpoints');

      // Structurally: both endpoints import the ONE validator, and no other
      // module in the application reads a Host or Origin header at all.
      const sourceDir = path.join(process.cwd(), 'apps', 'mcp-server', 'src');
      const authorityModule = 'remote-request-authority.ts';
      for (const file of ['remote-gateway.ts', 'remote-mcp-surface.ts']) {
        const source = fs.readFileSync(path.join(sourceDir, file), 'utf8');
        assert.match(source, /from '\.\/remote-request-authority\.js'/, file);
        assert.match(source, /checkRequestAuthority\(/, file);
      }

      const headerRead = /headers\s*(\.\s*(host|origin)\b|\[\s*['"](host|origin)['"]\s*\])/;
      for (const file of fs.readdirSync(sourceDir)) {
        if (!file.endsWith('.ts') || file === authorityModule) {
          continue;
        }
        assert.equal(
          headerRead.test(fs.readFileSync(path.join(sourceDir, file), 'utf8')),
          false,
          `${file} must not read a Host or Origin header outside the shared validator`,
        );
      }

      // §10/§11 hold for the session-bound methods too, before any session work.
      for (const method of ['GET', 'DELETE']) {
        const res = await request(port, {
          method,
          headers: { Origin: 'https://evil.test', 'Mcp-Session-Id': 'a'.repeat(64) },
        });
        assertAuthorityRefused(res, `${method} with Origin`);
      }
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
    } finally {
      await server.stop();
    }
  });

  test('RC05-ENR-176: a session that has reached its absolute TTL is reaped like an idle one', async () => {
    const clock = { now: 5_000_000 };
    const { server, port } = await startRemote({ tag: 'reap-absolute', sessionClock: clock });
    try {
      const surface = server.remoteGateway.mcpSurface;
      const { sessionId } = await initializeSession(port);
      assert.equal(surface.getActiveSessionCount(), 1);

      // The absolute TTL is the harder of the two expiries: it applies even to a
      // session that has been used continuously.
      clock.now += (SESSION_ABSOLUTE_TTL_SECONDS + 1) * 1000;
      assert.equal(server.sessionManager.hasSession(sessionId), false);

      const fresh = await initializeSession(port);
      assert.equal(fresh.res.status, 200, `${fresh.res.status} ${fresh.res.body}`);
      assert.equal(surface.sessions.has(sessionId), false);
      assert.equal(surface.getActiveSessionCount(), 1);
      assert.equal(server.sessionManager.getActiveSessionCount(), 1);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §21.1 Layer C / §26 C-3: a JSON-RPC batch cannot amortize one admission
  // =========================================================================

  /** A JSON-RPC batch of `count` tool calls — removed from MCP in `2025-06-18`. */
  function batchBody(count) {
    const messages = [];
    for (let index = 0; index < count; index += 1) {
      messages.push({
        jsonrpc: '2.0',
        id: index + 1,
        method: 'tools/call',
        params: { name: 'health', arguments: {} },
      });
    }
    return JSON.stringify(messages);
  }

  /** Asserts one POST /mcp body was refused AS A BATCH, before anything ran. */
  function assertBatchRefused(res, label) {
    // A batch is not ONE Request object, so it is refused as a malformed Request
    // (`-32600`), not as an admission refusal (`-32000`).
    const parsed = assertMcpRefusal(res, label, {
      status: MCP_POST_REPLY_STATUS,
      arcCode: 'INVALID_REQUEST_SCHEMA',
      jsonRpcCode: MCP_INVALID_REQUEST_ERROR_CODE,
    });
    // A batch is not one Request, so there is no request to answer by id.
    assert.equal(parsed.id, null, label);
    assert.equal(res.headers['mcp-session-id'], undefined, label);
    assert.equal(res.headers['arc-session-token'], undefined, label);
    return parsed;
  }

  /**
   * Establishes a session AND spends the first authenticated request.
   *
   * A tokenless `initialize` is bounded pre-session and takes no Layer C key, so
   * the session's bucket comes into existence on its first AUTHENTICATED request.
   * Measuring Layer C requires that request to have happened.
   */
  async function warmSession(port, sessionId, token) {
    const warm = await request(port, {
      method: 'POST',
      headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
      body: nonToolBody(99, 'tools/list'),
    });
    assertSucceeded(warm, 99, 'the warm-up request');
  }

  test('RC05-NEG-56: an authenticated batch of two tool calls is refused as one malformed Request', async () => {
    const { server, port, records, audit } = await startRemote({ tag: 'batch-two' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);
      await warmSession(port, sessionId, token);

      const auditBefore = audit.getRecords().length;
      const res = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: batchBody(2),
      });
      assertBatchRefused(res, 'a batch of two tool calls');

      // The SDK would have invoked its handler ONCE PER MEMBER. Neither member
      // reached the tool catalog, the shared RC-04 pipeline, policy, approval, or
      // a subsystem — the audit chain proves it, since a single accepted call on
      // this same composition writes to it (asserted at the end of this case).
      assert.equal(audit.getRecords().length, auditBefore, 'no member was dispatched');
      assert.equal(res.body.includes('"result"'), false, 'no member produced a result');
      assert.equal(limiter.getHolderCount(key), 0, 'the batch held no concurrency slot');

      // The single request that follows proves the audit chain is live and that
      // the batch was refused rather than the composition being inert.
      const single = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: toolCallBody(9),
      });
      assertSucceeded(single, 9, 'the following single tool call');
      assert.ok(
        audit.getRecords().length > auditBefore,
        'an accepted tool call on this composition does write to the audit chain',
      );
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a batch of 60 requests is refused before any tool, policy, or subsystem work', async () => {
    const { server, port, records, audit } = await startRemote({ tag: 'batch-many' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);
      await warmSession(port, sessionId, token);

      const auditBefore = audit.getRecords().length;
      const tokensBefore = effectiveTokens(limiter, key);
      const res = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: batchBody(60),
      });
      assertBatchRefused(res, 'a batch of 60 requests');
      assert.equal(audit.getRecords().length, auditBefore, 'nothing was dispatched or audited');

      // ONE HTTP request must not be able to carry 60 MCP requests on a single
      // admission. The refusal happens BEFORE the admission authority runs, so
      // the batch did not even spend the ONE token it would otherwise have been
      // charged: the accounting is not "one token for many requests", it is
      // "no requests at all".
      const tokensAfter = effectiveTokens(limiter, key);
      assert.ok(
        tokensAfter >= tokensBefore,
        `a refused batch spends no Layer C token, ${tokensBefore} -> ${tokensAfter}`,
      );
      assert.equal(limiter.getHolderCount(key), 0, 'a refused batch holds no concurrency slot');
      assert.equal(
        limiter.getRetainedKeysForTests().includes(key),
        true,
        'the session key is intact',
      );
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-41: a batch carrying initialize is refused and mints no session', async () => {
    const { server, port } = await startRemote({ tag: 'batch-init' });
    try {
      const res = await request(port, {
        method: 'POST',
        headers: MCP_POST_HEADERS,
        body: JSON.stringify([
          {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
              protocolVersion: '2025-06-18',
              capabilities: {},
              clientInfo: { name: 'rc05-batch-test', version: '1.0.0' },
            },
          },
          { jsonrpc: '2.0', id: 2, method: 'tools/list' },
        ]),
      });
      assertBatchRefused(res, 'a batch carrying initialize');

      // No session, no reservation, no registry entry, and no token.
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(server.sessionManager.getReservedSessionIdCount(), 0);
      assert.equal(server.remoteGateway.mcpSurface.getActiveSessionCount(), 0);

      // A normal tokenless initialize on the same composition still works, so the
      // refusal above is a decision about the batch and not a broken composition.
      const init = await initializeSession(port);
      assert.equal(init.res.status, 200, `${init.res.status} ${init.res.body}`);
      assert.ok(init.sessionId, 'the following single initialize mints a session');
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a refused batch leaves Layer C at zero holders and the session untouched', async () => {
    const { server, port, records } = await startRemote({ tag: 'batch-side-effects' });
    try {
      const surface = server.remoteGateway.mcpSurface;
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);
      const entry = surface.sessions.get(sessionId);
      assert.ok(entry);
      const observed = observeClose(entry);
      await warmSession(port, sessionId, token);
      const keysBefore = limiter.getRetainedKeysForTests();

      for (const [label, body] of [
        ['two tool calls', batchBody(2)],
        ['sixty tool calls', batchBody(60)],
        ['a member with no method', JSON.stringify([{ jsonrpc: '2.0', id: 1 }])],
      ]) {
        const res = await request(port, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
          body,
        });
        assertBatchRefused(res, label);
      }

      // The refusal is a decision about the request, not about the session: the
      // session, its registry entry, its SDK transport, and its Layer C key all
      // survive it exactly as they were.
      assert.equal(surface.sessions.has(sessionId), true, 'the registry entry survives');
      assert.equal(server.sessionManager.hasSession(sessionId), true, 'the session survives');
      assert.equal(observed.closed, 0, 'the SDK transport was not closed');
      assert.equal(surface.getActiveSessionCount(), 1);
      assert.equal(surface.liveAdmissions.size, 0, 'no admission was left outstanding');
      assert.equal(limiter.getHolderCount(key), 0);
      assert.deepEqual(limiter.getRetainedKeysForTests(), keysBefore, 'no key was created or lost');

      // ...and the session is still fully usable afterwards.
      const ok = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: nonToolBody(4, 'tools/list'),
      });
      assertSucceeded(ok, 4, 'the session still serves normal single messages');
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §25 error model: Layer C is MCP-framed, Layer B stays transport-level
  // =========================================================================

  test('RC05-NEG-56: the Layer C refusal is an MCP JSON-RPC error, never the Layer B transport model', async () => {
    const { server, port, records, audit } = await startRemote({ tag: 'layer-c-framing' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);
      drainBudget(limiter, key);

      const auditBefore = workRecords(audit).length;
      const refused = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: toolCallBody(7),
      });

      // The frozen observable semantic code is unchanged; the framing is not a
      // bare HTTP 429 with a `{code, message}` body, which is the Layer B model
      // and would let a client confuse a post-session refusal with the
      // pre-session transport limit.
      const parsed = assertRateLimited(refused, 'the Layer C refusal', { id: 7 });
      assert.equal(
        parsed.error.message,
        'Request rate or concurrency limit exceeded for this session.',
      );
      assert.equal(refused.body.includes('retryable'), false, 'no extra fields are emitted');

      // The refusal happened BEFORE the tool call existed: no policy, approval,
      // or subsystem work, and no record of any of it. The refusal's OWN
      // lifecycle record is written, and is the only new record there is.
      assert.equal(
        workRecords(audit).length,
        auditBefore,
        'policy and subsystems stayed unreachable',
      );
      assert.equal(
        await waitFor(
          () =>
            audit.getRecords().filter((r) => r.gateway?.eventType === 'RATE_LIMITED').length === 1,
        ),
        true,
        'the Layer C refusal is itself recorded exactly once',
      );
      assert.equal(refused.body.includes('"result"'), false, 'no tool ran');

      // The session survives the refusal, and its slot is returned.
      assert.equal(server.sessionManager.hasSession(sessionId), true);
      assert.equal(server.remoteGateway.mcpSurface.sessions.has(sessionId), true);
      assert.equal(
        await waitFor(() => limiter.getHolderCount(key) === 0),
        true,
        'a refusal returns its slot',
      );

      // Only a REFILL may make the session admissible again, and then the very
      // same request succeeds — proving the refusal was about budget, not state.
      assert.equal(
        await waitFor(() => effectiveTokens(limiter, key) >= 1.05, 5000),
        true,
        'the session budget refills',
      );
      const recovered = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(sessionId, token) },
        body: toolCallBody(8),
      });
      assertSucceeded(recovered, 8, 'the session recovers after a refill');
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-56: a Layer C refusal on GET and DELETE is MCP-framed with a null id', async () => {
    const { server, port, records } = await startRemote({ tag: 'layer-c-stream-framing' });
    try {
      const limiter = layerC(server);
      const { sessionId, token } = await initializeSession(port);
      const key = keyFor(records[0], sessionId);

      // A GET and a DELETE carry no JSON-RPC request, so the envelope's id is
      // `null`; the ARC semantic code still travels in `error.data.code`.
      const refusedGet = await getBounded(port, sessionId, token);
      assert.equal(refusedGet.status, 200, `${refusedGet.status} ${refusedGet.body}`);
      drainBudget(limiter, key);
      const refusedGet2 = await getBounded(port, sessionId, token);
      assertRateLimited(refusedGet2, 'a rate-refused GET', {
        id: null,
        status: MCP_STREAM_REPLY_STATUS,
      });
      refusedGet.req?.destroy();

      const refusedDelete = await request(port, {
        method: 'DELETE',
        headers: sessionHeaders(sessionId, token),
      });
      assertRateLimited(refusedDelete, 'a rate-refused DELETE', {
        id: null,
        status: MCP_STREAM_REPLY_STATUS,
      });

      // A refused DELETE must NOT have terminated the session: the refusal is
      // about budget, and §13 termination requires a proven credential.
      assert.equal(server.sessionManager.hasSession(sessionId), true);
      assert.equal(server.remoteGateway.mcpSurface.sessions.has(sessionId), true);
      assert.equal(limiter.getHolderCount(key), 0, 'neither refusal leaked a slot');
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-55: the pre-session transport layers are untouched by the MCP framing', async () => {
    const { server, port } = await startRemote({ tag: 'layer-a-unchanged' });
    try {
      // Layer A (60 connections/minute, burst 20) is STRICTLY tighter than Layer B
      // (120 requests/minute, burst 30) and is evaluated first, so a single peer
      // can never reach Layer B over the wire — Layer A drops the connection
      // instead. That ordering is a frozen property of §21.1 and is asserted here,
      // because it is what makes the framing change safe: nothing the MCP layer
      // now emits can be confused with a transport refusal a client never sees.
      //
      // Layer B's own 429 — a bare status with a `text/plain` body and NO JSON-RPC
      // frame — is exercised with the gateway's Layer B seam in
      // `rc05-resource-bounds.test.js` (`RC05-NEG-55: Layer B refuses a peer before
      // routing with a sanitized 429`), which this change does not touch.
      let dropped = false;
      for (let attempt = 0; attempt < 60 && !dropped; attempt += 1) {
        try {
          await request(port, {
            method: 'POST',
            headers: MCP_POST_HEADERS,
            body: nonToolBody(attempt + 1, 'tools/list'),
          });
        } catch (err) {
          // Layer A's model is a DROPPED connection, never an MCP reply.
          assert.match(String(err.code), /ECONNRESET|EPIPE|ECONNREFUSED/, String(err));
          dropped = true;
        }
      }
      assert.equal(dropped, true, 'Layer A must still drop before Layer B is reachable');

      // No session, no credential, and no MCP message was ever involved.
      assert.equal(server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(server.remoteGateway.mcpSurface.getActiveSessionCount(), 0);
    } finally {
      await server.stop();
    }
  });

  // =========================================================================
  // §25 error model: /mcp admission failures are MCP-framed and anti-oracle
  // =========================================================================

  /**
   * Runs one ordinary authenticated request shape against one composition and
   * returns the refusal response plus the secrets that must not appear in it.
   */
  async function refusalCase(tag, shape) {
    const harness = await startRemote({ ...shape.start, tag });
    const { server, port } = harness;
    try {
      const res = await request(port, shape.request(port, harness));
      const forbidden = [
        ...(shape.forbidden?.(harness) ?? []),
        // No raw token, session identifier, SPKI pin, or device identifier may
        // appear in any refusal body.
        'Authorization',
        'Bearer',
      ];
      for (const secret of forbidden.filter((value) => typeof value === 'string' && value.length)) {
        assert.equal(res.body.includes(secret), false, `${tag}: the refusal leaks ${secret}`);
      }
      return { res, server, harness };
    } finally {
      await server.stop();
    }
  }

  test('RC05-NEG-39/41: every pre-session device failure is the SAME MCP UNAUTHENTICATED error', async () => {
    const shapes = [
      [
        'zero enrolled devices',
        {
          start: { pinCount: 0 },
          request: () => ({ headers: MCP_POST_HEADERS, body: toolCallBody(11) }),
        },
      ],
      [
        'the store has devices but not this SPKI',
        {
          start: { pinCount: 1, clientEnrolled: false },
          request: () => ({ headers: MCP_POST_HEADERS, body: toolCallBody(11) }),
        },
      ],
      [
        'the device behind this SPKI is revoked',
        {
          start: { pinCount: 1, revokedCount: 1 },
          request: () => ({ headers: MCP_POST_HEADERS, body: toolCallBody(11) }),
        },
      ],
      [
        'a tokenless initialize from an unknown device',
        {
          start: { pinCount: 0 },
          request: () => ({ headers: MCP_POST_HEADERS, body: INITIALIZE_BODY }),
        },
      ],
    ];

    const bodies = [];
    for (const [label, shape] of shapes) {
      const { res } = await refusalCase(`pre-${bodies.length}`, shape);
      assertMcpRefusal(res, label, {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'UNAUTHENTICATED',
      });
      assert.equal(JSON.parse(res.body).error.message, 'Authentication failed', label);
      bodies.push(res.body.replace(/"id":\d+/, '"id":0'));
    }

    // Anti-oracle: whether a device exists, whether it is revoked, whether the
    // SPKI is recognized, or whether a session ever existed is NOT observable —
    // all four produce the same bytes.
    for (const body of bodies) {
      assert.equal(body, bodies[0], 'every pre-session device failure is indistinguishable');
    }
  });

  test('RC05-NEG-63: a tokenless initialize from a REVOKED device is UNAUTHENTICATED and discloses nothing', async () => {
    // The two causes differ ONLY in the trust store: the same certificate, the
    // same SPKI pin, the same network path, the same request. One device is
    // enrolled and revoked; the other was never enrolled at all.
    const revoked = await startRemote({
      tag: 'neg63-revoked',
      pinCount: 1,
      revokedCount: 1,
    });
    const unknown = await startRemote({
      tag: 'neg63-unknown',
      pinCount: 0,
    });

    try {
      const revokedRes = await request(revoked.port, {
        method: 'POST',
        headers: MCP_POST_HEADERS,
        body: INITIALIZE_BODY,
      });
      const unknownRes = await request(unknown.port, {
        method: 'POST',
        headers: MCP_POST_HEADERS,
        body: INITIALIZE_BODY,
      });

      assertMcpRefusal(revokedRes, 'a revoked device', {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'UNAUTHENTICATED',
      });
      assertMcpRefusal(unknownRes, 'an unknown device', {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'UNAUTHENTICATED',
      });

      // Anti-oracle: revocation status is not observable. The refused peer cannot
      // tell that it was ever enrolled, so the control is not a membership test.
      assert.equal(
        revokedRes.body.replace(/"id":\d+/, '"id":0'),
        unknownRes.body.replace(/"id":\d+/, '"id":0'),
        'revocation status is not disclosed',
      );

      // The refusal is PRE-session: nothing was reserved, minted, or registered,
      // and no raw token or session identifier exists to be leaked.
      assert.equal(revoked.server.sessionManager.getActiveSessionCount(), 0);
      assert.equal(revoked.server.sessionManager.getReservedSessionIdCount(), 0);
      assert.equal(revoked.server.remoteGateway.mcpSurface.getActiveSessionCount(), 0);
      assert.equal(revokedRes.headers['arc-session-token'], undefined);
      assert.equal(revokedRes.body.includes(revoked.records[0].deviceId), false);
      assert.equal(revokedRes.body.includes(clientPin()), false);

      // The refusal is recorded as an authentication failure — generic, and no
      // more of an oracle than the wire response is.
      await waitFor(() =>
        revoked.audit.getRecords().some((record) => record.gateway?.eventType === 'AUTH_FAILED'),
      );
      const failure = revoked.audit
        .getRecords()
        .find((record) => record.gateway?.eventType === 'AUTH_FAILED');
      assert.equal(JSON.stringify(failure).includes(revoked.records[0].deviceId), false);
      assert.equal(JSON.stringify(failure).includes(clientPin()), false);
    } finally {
      await revoked.server.stop();
      await unknown.server.stop();
    }
  });

  test('RC05-NEG-40: every post-session failure is the SAME MCP INVALID_SESSION_TOKEN error', async () => {
    // Each shape builds a real session first, then presents credentials that must
    // fail — for a different reason in every case.
    const shapes = [
      [
        'missing token on a known session',
        {
          request: async (port, harness) => {
            const init = await initializeSession(port);
            harness.sessionId = init.sessionId;
            harness.token = init.token;
            return {
              headers: { ...MCP_POST_HEADERS, 'Mcp-Session-Id': init.sessionId },
              body: toolCallBody(11),
            };
          },
        },
      ],
      [
        'wrong token for a live session',
        {
          request: async (port, harness) => {
            const init = await initializeSession(port);
            harness.sessionId = init.sessionId;
            harness.token = init.token;
            return {
              headers: { ...MCP_POST_HEADERS, ...sessionHeaders(init.sessionId, 'e'.repeat(64)) },
              body: toolCallBody(11),
            };
          },
        },
      ],
      [
        'unknown session id with a real token',
        {
          request: async (port, harness) => {
            const init = await initializeSession(port);
            harness.sessionId = init.sessionId;
            harness.token = init.token;
            return {
              headers: {
                ...MCP_POST_HEADERS,
                ...sessionHeaders('f'.repeat(64), init.token),
              },
              body: toolCallBody(11),
            };
          },
        },
      ],
      [
        'expired session',
        {
          start: { sessionClock: { now: 9_000_000 } },
          request: async (port, harness) => {
            const init = await initializeSession(port);
            harness.sessionId = init.sessionId;
            harness.token = init.token;
            // Past the idle timeout: the authority expires it before the surface
            // ever sees the request.
            harness.server.sessionManager.expireIdleSessions?.();
            harness.clock.now += (SESSION_IDLE_TIMEOUT_SECONDS + 1) * 1000;
            return {
              headers: { ...MCP_POST_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
              body: toolCallBody(11),
            };
          },
        },
      ],
    ];

    const bodies = [];
    for (const [label, shape] of shapes) {
      const clock = shape.start?.sessionClock;
      const harness = await startRemote({ ...shape.start, tag: `post-${bodies.length}` });
      const { server, port } = harness;
      try {
        const requestShape = await shape.request(port, { ...harness, clock });
        const res = await request(port, { method: 'POST', ...requestShape });
        assertMcpRefusal(res, label, {
          status: MCP_POST_REPLY_STATUS,
          arcCode: 'INVALID_SESSION_TOKEN',
        });
        assert.equal(JSON.parse(res.body).error.message, 'Invalid or expired session token', label);
        assert.equal(
          res.body.includes(harness.sessionId ?? '\u0000'),
          false,
          `${label}: no session id`,
        );
        assert.equal(res.body.includes(harness.token ?? '\u0000'), false, `${label}: no token`);
        bodies.push(res.body.replace(/"id":\d+/, '"id":0'));
      } finally {
        await server.stop();
      }
    }

    for (const body of bodies) {
      assert.equal(body, bodies[0], 'every post-session failure is indistinguishable');
    }
  });

  test('RC05-NEG-40: an identity mismatch is refused exactly like a bad token', async () => {
    const { server, port, records, audit } = await startRemote({ tag: 'identity-mismatch' });
    try {
      const init = await initializeSession(port);
      assert.equal(init.res.status, 200, `${init.res.status} ${init.res.body}`);

      // Cause 1: a WRONG token for a live session.
      const wrongToken = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(init.sessionId, 'e'.repeat(64)) },
        body: toolCallBody(11),
      });
      assertMcpRefusal(wrongToken, 'a wrong token', {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'INVALID_SESSION_TOKEN',
      });
      assert.equal(wrongToken.body.includes(init.token), false, 'no credential is echoed');

      // Cause 2: the device behind the SAME SPKI stops resolving to an active
      // identity — the certificate is unchanged and the session is live, but the
      // identity the request resolves to no longer matches the session's device.
      // This is the out-of-band revocation the surface must observe, resolved from
      // the CURRENT trust store on every request.
      const auditBefore = workRecords(audit).length;
      const lifecyclesBefore = audit.getRecords().filter((r) => r.gateway !== undefined).length;
      const authoritative = server.remoteGateway.bootstrap.authoritativeTrustStore;
      authoritative.revokeDevice(records[0].deviceId);
      assert.equal(
        server.remoteGateway.getEnrolledDeviceCount(),
        0,
        'the device really is revoked in the authoritative store',
      );

      const mismatched = await request(port, {
        method: 'POST',
        headers: { ...MCP_POST_HEADERS, ...sessionHeaders(init.sessionId, init.token) },
        body: toolCallBody(11),
      });

      // Anti-oracle: the two DIFFERENT causes produce the SAME bytes. The refusal
      // discloses neither the device, nor the SPKI, nor the session, nor which of
      // the two things went wrong.
      assert.equal(mismatched.body, wrongToken.body, 'the two causes are indistinguishable');
      assertMcpRefusal(mismatched, 'an identity mismatch', {
        status: MCP_POST_REPLY_STATUS,
        arcCode: 'INVALID_SESSION_TOKEN',
      });
      assert.equal(mismatched.body.includes(records[0].deviceId), false, 'no device id escapes');
      assert.equal(mismatched.body.includes(clientPin()), false, 'no SPKI pin escapes');
      // The refusal is recorded as an authentication lifecycle event and nothing
      // else: no policy evaluation, no approval transition, no tool dispatch, and
      // no subsystem call was reached. The record is deliberately generic — it
      // names neither the device nor the SPKI, so the audit chain is no more of
      // an oracle than the wire response is.
      assert.equal(
        workRecords(audit).length,
        auditBefore,
        'no policy or subsystem work was reached',
      );
      assert.equal(
        await waitFor(
          () => audit.getRecords().filter((r) => r.gateway !== undefined).length > lifecyclesBefore,
        ),
        true,
        'the refusal is recorded as a gateway lifecycle event',
      );
      const failure = audit
        .getRecords()
        .filter((r) => r.gateway !== undefined)
        .at(-1);
      assert.equal(failure.gateway.eventType, 'AUTH_FAILED');
      assert.equal(
        JSON.stringify(failure).includes(records[0].deviceId),
        false,
        'the failure record is not a device oracle',
      );
      assert.equal(
        JSON.stringify(failure).includes(clientPin()),
        false,
        'the failure record is not a pin oracle',
      );
    } finally {
      await server.stop();
    }
  });
});
