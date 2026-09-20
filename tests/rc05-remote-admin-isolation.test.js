/**
 * CesSpace ARC — RC-05 Task 9: Remote Administration Isolation
 *
 * Covers RC05-NEG-74 through RC05-NEG-79: administration stays LOCAL. No
 * administrative capability is reachable from a remote mTLS MCP actor by any
 * route.
 *
 * These cases deliberately do NOT test fake MCP handlers that deny these names.
 * A deny-handler would mean the names EXIST on the MCP tool surface, which is
 * exactly what the controls forbid. Instead every case drives the REAL remote
 * catalog and the REAL remote call path over real mTLS and asserts:
 *
 *   1. `tools/list` does not contain the administrative name at all, so there
 *      is no tool to call;
 *   2. an attempted `tools/call` naming it is answered with EXACTLY JSON-RPC
 *      `-32601` Method not found — a protocol-level unknown-tool refusal, not a
 *      `CallToolResult` carrying `isError: true`. The weaker `isError` shape
 *      would mean the call entered the shared execution pipeline and was only
 *      rejected there, which is what these controls forbid;
 *   3. a direct JSON-RPC request naming it as a top-level METHOD returns the
 *      transport's own `-32601`, which is only possible because NO handler is
 *      registered for it anywhere in the composition;
 *   4. every piece of local state those actions would have touched is
 *      unchanged afterwards;
 *   5. the rule producing (2) is GENERIC — membership in the one registered
 *      `ALL_TOOL_DEFINITIONS` catalog — and not a denylist of administrative
 *      names. Proven both ways: arbitrary unregistered names are refused, and
 *      every registered name still executes normally through the same handler.
 *
 * A same-fixture LOCAL admin channel is composed alongside, so each case can
 * also prove the capability genuinely EXISTS locally and is withheld remotely
 * rather than simply absent.
 *
 * All X.509 material is generated ephemerally by the shared test PKI helper and
 * removed with the temporary directory.
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
  ADMIN_METHODS,
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { ArcMcpServer, ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
import {
  MCP_ADMISSION_ERROR_CODE,
  MCP_INVALID_REQUEST_ERROR_CODE,
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
import { DeviceTrustStore, deriveSpkiPin } from '../packages/auth/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** JSON-RPC "Method not found": the transport's answer when no handler exists. */
const METHOD_NOT_FOUND = -32601;

const publicHostname = 'localhost';

let tempRoot;
let workspaceDir;
let pki;
let counter = 0;

before(() => {
  assert.equal(hasOpenssl(), true, 'RC-05 drives real mTLS connections and requires openssl');
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-admin-isolation-'));
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

function makeSecureDir(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyB64: exportPublicKeyB64(publicKey) };
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

/** The default mTLS client certificate, which the trust store enrolls. */
function primaryClient() {
  return {
    certPath: pki.clientCertPath,
    keyPath: pki.clientKeyPath,
    pin: deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8')),
  };
}

/**
 * Starts a REAL remote-mode server with BOTH a live LOCAL admin channel and a
 * live remote MCP surface, over ONE trust store.
 *
 * Returns the live handles a case needs to prove nothing moved: the approval
 * state manager the server actually serves from, the policy engine it actually
 * evaluates with, the trust-store file, and the single session authority.
 */
async function startIsolated({ tag }) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const client = primaryClient();
  const store = DeviceTrustStore.createEmpty();
  const { device } = store.enrollDevice({
    clientId: 'agent-alpha',
    clientType: 'claude-code',
    pin: client.pin,
    displayLabel: 'alpha-laptop',
  });
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);

  const port = await freePort();
  const dir = makeSecureDir(`${tag}-admin`);
  const endpoint = path.join(dir, 'admin.sock');
  const operator = generateOperator();
  const approvals = new ApprovalStateManager();
  const audit = new AuditLogger();
  const registry = new WorkspaceRegistry();

  const adminIpcServer = new AdminIpcServer({
    endpoint,
    operatorPublicKeyB64: operator.publicKeyB64,
    approvalStateManager: approvals,
    auditLogger: audit,
  });

  // The SAME approval authority is handed to BOTH the admin channel and the
  // server, so "no approval moved" is an assertion about the live state the
  // remote pipeline itself reads.
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
    undefined,
    undefined,
  );
  await server.start();
  return {
    server,
    port,
    endpoint,
    operator,
    approvals,
    audit,
    storePath,
    device,
    clientPin: client.pin,
    client,
    adminIpcServer,
  };
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

function sessionHeaders(sessionId, token) {
  return { 'Mcp-Session-Id': sessionId, Authorization: `Bearer ${token}` };
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

/** Performs the tokenless `initialize` handshake. */
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
        clientInfo: { name: 'rc05-neg-test', version: '1.0.0' },
      },
    }),
  });
  assert.equal(res.status, 200, `initialize: ${res.status} ${res.body}`);
  return { sessionId: res.headers['mcp-session-id'], token: res.headers['arc-session-token'] };
}

/** One authenticated remote MCP request with the dual session headers. */
function remoteMcp(fixture, session, body) {
  return request(fixture.port, fixture.client, {
    method: 'POST',
    headers: {
      ...MCP_POST_HEADERS,
      ...sessionHeaders(session.sessionId, session.token),
    },
    body,
  });
}

/** `tools/list` over an authenticated remote session. */
async function listRemoteTools(fixture, session) {
  const res = await remoteMcp(
    fixture,
    session,
    JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list' }),
  );
  assert.equal(res.status, 200, `tools/list: ${res.status} ${res.body}`);
  const payload = payloadOf(res.body);
  assert.equal(payload.error, undefined, res.body);
  return payload.result.tools;
}

/**
 * Runs one ordinary policy-evaluated tool call and returns its result.
 *
 * Used to prove the policy ENGINE still evaluates exactly as before: the same
 * call must produce the same decision whether or not an administrative
 * modification was attempted.
 */
async function remoteReadFile(fixture, session, targetPath) {
  const res = await remoteMcp(
    fixture,
    session,
    JSON.stringify({
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: targetPath, workspaceId: 'ws' } },
    }),
  );
  assert.equal(res.status, MCP_POST_REPLY_STATUS, `read_file: ${res.status} ${res.body}`);
  const payload = payloadOf(res.body);
  assert.equal(payload.error, undefined, res.body);
  return payload.result;
}

/** The live policy engine's fingerprint, read from the server itself. */
function policyHashOf(fixture) {
  assert.ok(fixture.server.effectivePolicyEngine !== undefined, 'a policy engine is composed');
  return fixture.server.effectivePolicyEngine.getPolicyHash();
}

/** Attempts one remote `tools/call` naming `name` and returns the response. */
function remoteToolCall(fixture, session, name, args = {}) {
  return remoteMcp(
    fixture,
    session,
    JSON.stringify({
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: { name, arguments: args },
    }),
  );
}

/** Attempts one direct remote JSON-RPC request naming `method`. */
function remoteDirectMethod(fixture, session, method, params = {}) {
  return remoteMcp(fixture, session, JSON.stringify({ jsonrpc: '2.0', id: 21, method, params }));
}

/** The exact bytes of the trust store, for a byte-level unchanged assertion. */
function trustStoreBytes(storePath) {
  return fs.readFileSync(storePath);
}

/** The on-disk trust store, parsed. */
function readStoreFile(storePath) {
  return JSON.parse(fs.readFileSync(storePath, 'utf8'));
}

/**
 * Asserts an attempted administrative remote `tools/call` is answered with
 * EXACTLY JSON-RPC `-32601` (Method not found).
 *
 * This is deliberately strict. A `CallToolResult` carrying `isError: true` is
 * NOT acceptable here: that shape means the call entered the shared execution
 * pipeline, was schema-rejected by the internal tool lookup, and came back as
 * an ordinary tool error — policy was evaluated and an approval may have been
 * considered. The controls require the call to be refused at the protocol
 * boundary, as an unknown tool, with the pipeline never entered.
 *
 * The response must therefore be a JSON-RPC error object and nothing else:
 * no `result` member in any form, and no Arc admission envelope.
 */
function assertUnknownTool(res, label) {
  assert.equal(res.status, MCP_POST_REPLY_STATUS, `${label}: ${res.status} ${res.body}`);
  const payload = payloadOf(res.body);
  assert.equal(payload.jsonrpc, '2.0', label);
  assert.notEqual(payload.error, undefined, `${label} must be a JSON-RPC error: ${res.body}`);
  assert.equal(payload.error.code, METHOD_NOT_FOUND, `${label}: ${res.body}`);
  // Not a tool result, and specifically not the weaker `isError` admission.
  assert.equal(payload.result, undefined, `${label} must not return a CallToolResult`);
  assert.equal('data' in payload.error, false, `${label}: ${res.body}`);
  return payload;
}

// ---------------------------------------------------------------------------
// Local admin channel client (the SAME protocol the operator CLI speaks)
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

/** One-shot authenticated LOCAL admin request over the real Unix socket. */
async function localAdminRequest(endpoint, privateKey, method, params = {}) {
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

// ---------------------------------------------------------------------------
// The forbidden administrative surface
// ---------------------------------------------------------------------------

/**
 * Administrative names that must NEVER become remote MCP tools (§15).
 *
 * Each entry is `[name, arguments]`. The argument sets are the ones a real
 * administrative call would carry, so a case cannot pass merely because it sent
 * an unusable request.
 */
const FORBIDDEN_REMOTE_ADMIN_TOOLS = [
  ['approve', { requestId: 'a'.repeat(32) }],
  ['reject', { requestId: 'a'.repeat(32) }],
  ['approvals.list', {}],
  ['approvals.inspect', { requestId: 'a'.repeat(32) }],
  ['devices.list', {}],
  ['devices.inspect', { deviceId: 'b'.repeat(32) }],
  ['device.revoke', { deviceId: 'b'.repeat(32) }],
  ['device.rename', { deviceId: 'b'.repeat(32), displayLabel: 'pwned' }],
  ['device.pin.add', { deviceId: 'b'.repeat(32), spkiPin: 'c'.repeat(64) }],
  ['device.pin.remove', { deviceId: 'b'.repeat(32), spkiPin: 'c'.repeat(64) }],
  ['sessions.list', {}],
  ['session.revoke', { sessionId: 'd'.repeat(64) }],
  ['admin', {}],
  ['admin.devices.list', {}],
  ['policy.set', { policy: 'allow-everything' }],
  ['policy.update', { policy: 'allow-everything' }],
  ['policy.reload', {}],
];

const FORBIDDEN_NAMES = FORBIDDEN_REMOTE_ADMIN_TOOLS.map(([name]) => name);

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

describe('CesSpace ARC — RC-05 Task 9: Remote administration isolation', () => {
  test('RC05-NEG-74..79: the remote MCP catalog exposes no administrative tool', async () => {
    const fixture = await startIsolated({ tag: 'catalog' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);
      const tools = await listRemoteTools(fixture, session);
      assert.ok(tools.length > 0, 'the remote catalog is a real catalog');

      const names = new Set(tools.map((tool) => tool.name));
      for (const forbidden of FORBIDDEN_NAMES) {
        assert.equal(names.has(forbidden), false, `${forbidden} must not be a remote MCP tool`);
      }
      // No administrative NAMESPACE is exposed either.
      for (const name of names) {
        assert.equal(name.startsWith('admin'), false, `${name} must not be in an admin namespace`);
        assert.equal(name.includes('policy.'), false, `${name} must not expose policy control`);
      }

      // The catalog is the SAME closed catalog the local server defines, so
      // "remote cannot expose a tool the local catalog lacks" is a structural
      // property of the composition rather than an observation about a fixture.
      assert.deepEqual([...names].sort(), ALL_TOOL_DEFINITIONS.map((tool) => tool.name).sort());

      // ...and the LOCAL channel genuinely CAN administer, so the isolation is
      // a withheld capability rather than an absent one.
      const local = await localAdminRequest(
        fixture.endpoint,
        fixture.operator.privateKey,
        'devices.list',
      );
      assert.equal(local.ok, true, JSON.stringify(local));
      assert.equal(local.result.devices.length, 1);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: no administrative name is reachable through the remote call path', async () => {
    const fixture = await startIsolated({ tag: 'callpath' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);
      const storeBefore = trustStoreBytes(fixture.storePath);
      const policyHashBefore = policyHashOf(fixture);

      for (const [name, args] of FORBIDDEN_REMOTE_ADMIN_TOOLS) {
        const res = await remoteToolCall(fixture, session, name, args);
        assertUnknownTool(res, name);

        // Nothing administrative is disclosed, in any framing.
        for (const leaked of [
          fixture.device.deviceId,
          fixture.clientPin,
          'alpha-laptop',
          'enrolledAt',
          'activePinCount',
          'displayLabel',
          'revoked',
        ]) {
          assert.equal(
            res.body.includes(leaked),
            false,
            `${name} must not disclose ${leaked}: ${res.body.slice(0, 300)}`,
          );
        }

        // The caller's own session survives the attempt.
        assert.equal(
          fixture.server.sessionManager.hasSession(session.sessionId),
          true,
          `${name} must not disturb the caller's own session`,
        );
      }

      // No administrative state moved.
      assert.deepEqual(trustStoreBytes(fixture.storePath), storeBefore, 'trust store unchanged');
      assert.deepEqual(fixture.approvals.listActive(), [], 'no approval was created or changed');
      assert.equal(policyHashOf(fixture), policyHashBefore, 'the policy engine is unchanged');
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: every covered control category returns exact -32601 on the real tools/call path', async () => {
    const fixture = await startIsolated({ tag: 'per-control' });
    try {
      // A REAL pending approval exists, so a pipeline-reached `approve` would
      // have something to act on, and a REAL second live session exists, so a
      // pipeline-reached `session.revoke` would have something to destroy.
      const pending = fixture.approvals.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'agent-alpha', clientType: 'claude-code' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        },
        reviewMaterial: '--- a/secret.txt\n+++ b/secret.txt\n@@ -1 +1 @@\n-old\n+new\n',
      });
      const session = await initializeSession(fixture.port, fixture.client);
      const other = await initializeSession(fixture.port, fixture.client);

      const approvalsBefore = JSON.stringify(fixture.approvals.listActive());
      const storeBefore = trustStoreBytes(fixture.storePath);
      const policyHashBefore = policyHashOf(fixture);
      const decisionBefore = await remoteReadFile(fixture, session, 'README.md');
      const sessionsBefore = fixture.server.sessionManager.getActiveSessionCount();

      // The six control categories, each with the argument set a real
      // administrative call would carry.
      const CATEGORIES = [
        ['RC05-NEG-74', [['approve', { requestId: pending.requestId, reason: 'remote override' }]]],
        ['RC05-NEG-75', [['reject', { requestId: pending.requestId, reason: 'remote override' }]]],
        [
          'RC05-NEG-76',
          [
            ['approvals.list', {}],
            ['approvals.inspect', { requestId: pending.requestId }],
          ],
        ],
        [
          'RC05-NEG-77',
          [
            ['enrollment.create', { clientId: 'attacker', clientType: 'claude-code' }],
            ['devices.list', {}],
            ['devices.inspect', { deviceId: fixture.device.deviceId }],
            ['device.revoke', { deviceId: fixture.device.deviceId }],
            ['device.rename', { deviceId: fixture.device.deviceId, displayLabel: 'pwned' }],
            ['device.pin.add', { deviceId: fixture.device.deviceId, spkiPin: 'e'.repeat(64) }],
            [
              'device.pin.remove',
              { deviceId: fixture.device.deviceId, spkiPin: fixture.clientPin },
            ],
          ],
        ],
        [
          'RC05-NEG-78',
          [
            ['policy.set', { policy: { rules: [{ effect: 'ALLOW', tool: '*' }] } }],
            ['policy.update', { policy: { rules: [] } }],
            ['policy.reload', {}],
          ],
        ],
        [
          'RC05-NEG-79',
          [
            ['sessions.list', {}],
            ['session.revoke', { sessionId: other.sessionId }],
          ],
        ],
      ];

      for (const [control, attempts] of CATEGORIES) {
        for (const [name, args] of attempts) {
          const res = await remoteToolCall(fixture, session, name, args);
          assertUnknownTool(res, `${control} ${name}`);

          // Nothing administrative and no review material is disclosed.
          for (const leaked of [
            fixture.device.deviceId,
            fixture.clientPin,
            'alpha-laptop',
            'secret.txt',
            pending.requestId,
            other.sessionId,
            other.token,
            'reviewMaterial',
          ]) {
            assert.equal(
              res.body.includes(leaked),
              false,
              `${control} ${name} disclosed ${leaked}`,
            );
          }
        }
      }

      // RC05-NEG-74/75: approval state unchanged, no token ever minted.
      assert.equal(JSON.stringify(fixture.approvals.listActive()), approvalsBefore);
      assert.equal(fixture.approvals.getRequest(pending.requestId).state, 'PENDING');
      assert.equal(fixture.approvals.getRequest(pending.requestId).token, undefined);

      // RC05-NEG-77: the trust store is byte-for-byte unchanged on disk.
      assert.deepEqual(trustStoreBytes(fixture.storePath), storeBefore, 'trust store unchanged');
      const onDisk = readStoreFile(fixture.storePath);
      assert.equal(onDisk.devices.length, 1);
      assert.equal(onDisk.devices[0].revoked, false);
      assert.equal(onDisk.devices[0].displayLabel, 'alpha-laptop');
      assert.deepEqual(onDisk.devices[0].pins, [fixture.clientPin]);

      // RC05-NEG-78: the policy engine was never reached by an admin action and
      // still evaluates normally.
      assert.equal(policyHashOf(fixture), policyHashBefore, 'the policy is unchanged');
      assert.deepEqual(
        await remoteReadFile(fixture, session, 'README.md'),
        decisionBefore,
        'policy evaluation is unchanged',
      );

      // RC05-NEG-79: the target session is untouched and still usable.
      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), sessionsBefore);
      assert.equal(fixture.server.sessionManager.hasSession(other.sessionId), true);
      assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
      const stillLive = await remoteMcp(
        fixture,
        other,
        JSON.stringify({ jsonrpc: '2.0', id: 31, method: 'tools/list' }),
      );
      assert.equal(stillLive.status, 200, stillLive.body);
      assert.equal(payloadOf(stillLive.body).error, undefined, stillLive.body);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: the unknown-tool rule is generic catalog membership, not a name denylist', async () => {
    const fixture = await startIsolated({ tag: 'generic' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);

      // Names that appear NOWHERE in the implementation, including a real
      // registered name with padding, an object-prototype key, and a
      // case-variant. A denylist of administrative names could not refuse these;
      // a catalog-membership test refuses them all identically.
      const arbitrary = [
        'totally-made-up-tool',
        'devices',
        'session',
        'DEVICES.LIST',
        'read_file ',
        'read_file\u0000',
        '__proto__',
        'constructor',
      ];
      for (const name of arbitrary) {
        const res = await remoteToolCall(fixture, session, name, {});
        assertUnknownTool(res, `unregistered:${JSON.stringify(name)}`);
      }

      // Conversely, registered tools spanning all THREE contributing catalogs
      // are NOT refused as unknown: the rule admits the catalog rather than
      // denying a subset of it. Each may still fail for its OWN reasons
      // (missing required arguments, policy, filesystem), but never as -32601.
      //
      // The whole-catalog direction is covered structurally as well: the
      // `tools/list` case above asserts the advertised catalog is exactly
      // `ALL_TOOL_DEFINITIONS`, which is the same list the gate is derived from,
      // so there is no registered name the gate does not admit and no admitted
      // name that is not advertised.
      for (const name of ['read_file', 'system_status', 'run_command']) {
        assert.equal(
          ALL_TOOL_DEFINITIONS.some((tool) => tool.name === name),
          true,
          `${name} is a registered tool`,
        );
        const res = await remoteToolCall(fixture, session, name, {});
        const payload = payloadOf(res.body);
        assert.notEqual(
          payload.error?.code,
          METHOD_NOT_FOUND,
          `registered tool ${name} must not be refused as unknown: ${res.body}`,
        );
      }

      // Nothing moved while probing either way.
      assert.deepEqual(fixture.approvals.listActive(), []);
      const onDisk = readStoreFile(fixture.storePath);
      assert.equal(onDisk.devices.length, 1);
      assert.equal(onDisk.devices[0].revoked, false);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: registered tools still execute normally through the same handler', async () => {
    const fixture = await startIsolated({ tag: 'non-vacuity' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);

      // The gate admits the catalog: a real side-effect-free tool runs the full
      // pipeline and returns an ordinary successful tool result, so the -32601
      // assertions above are not passing because every call fails.
      const health = await remoteMcp(
        fixture,
        session,
        JSON.stringify({
          jsonrpc: '2.0',
          id: 60,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      );
      assert.equal(health.status, MCP_POST_REPLY_STATUS, health.body);
      const healthPayload = payloadOf(health.body);
      assert.equal(healthPayload.error, undefined, health.body);
      assert.notEqual(healthPayload.result.isError, true, health.body);
      const report = JSON.parse(healthPayload.result.content[0].text);
      assert.equal(report.transportMode, 'remote');
      assert.equal(report.remoteGatewayActive, true);
      assert.equal(report.activeSessionsCount, 1);

      // A real filesystem tool executes through the SAME handler and returns
      // real content.
      const readResult = await remoteReadFile(fixture, session, 'README.md');
      assert.notEqual(readResult.isError, true, JSON.stringify(readResult));
      assert.equal(
        readResult.content[0].text.includes('# workspace'),
        true,
        JSON.stringify(readResult),
      );

      // A REGISTERED tool with invalid arguments is still handled by the shared
      // pipeline — a tool error or a policy/admission refusal, never -32601 —
      // which is the behavior the gate must not alter.
      const badArgs = await remoteToolCall(fixture, session, 'read_file', { path: 42 });
      const badPayload = payloadOf(badArgs.body);
      assert.notEqual(badPayload.error?.code, METHOD_NOT_FOUND, badArgs.body);
      assert.ok(
        badPayload.error !== undefined || badPayload.result?.isError === true,
        `a registered tool with bad args is not an unknown tool: ${badArgs.body}`,
      );

      // The session continues to work after all of it.
      assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: the stdio/local tools/call boundary applies the same -32601 gate', async () => {
    const fixture = await startIsolated({ tag: 'stdio-gate' });
    try {
      // The SDK `Server` is where BOTH `CallToolRequestSchema` handlers live, and
      // `server.server` is the constructed SDK object. The registered handler is
      // read directly for the same reason `rc04-mcp-approval.test.js` reads
      // `_serverInfo`: exposing a production accessor solely for a test would
      // widen the server's surface. Invoking it calls the exact function the SDK
      // would call for a real `tools/call`.
      const sdkServer = fixture.server.server;
      const callToolsCall = (name, args) =>
        sdkServer._requestHandlers.get('tools/call')(
          { method: 'tools/call', params: { name, arguments: args } },
          {},
        );

      // An unregistered tool is a JSON-RPC -32601 at the LOCAL boundary too, so
      // stdio and remote cannot disagree about what "unknown tool" means.
      for (const [name, args] of FORBIDDEN_REMOTE_ADMIN_TOOLS) {
        await assert.rejects(
          () => callToolsCall(name, args),
          (err) => {
            assert.equal(err.code, METHOD_NOT_FOUND, `${name}: ${err.message}`);
            assert.equal(err.name, 'McpError', name);
            // Not a tool result in any shape.
            assert.equal(err.message.includes('isError'), false, name);
            return true;
          },
          `${name} must be refused as an unknown tool locally`,
        );
      }

      // ...and a registered tool is NOT refused: the same gate admits the
      // catalog on the local boundary.
      const localHealth = await callToolsCall('health', {});
      assert.notEqual(localHealth.isError, true, JSON.stringify(localHealth));
      const report = JSON.parse(localHealth.content[0].text);
      assert.equal(report.transportMode, 'remote');
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: a direct remote JSON-RPC request to an admin method is -32601', async () => {
    const fixture = await startIsolated({ tag: 'direct' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);
      const storeBefore = trustStoreBytes(fixture.storePath);

      // Every name the LOCAL channel answers to, plus the administrative verbs
      // the controls name explicitly, attempted as first-class remote methods.
      const methods = [
        ...ADMIN_METHODS,
        'admin',
        'admin.devices.list',
        'admin.requests.list',
        'policy.set',
        'policy.reload',
        'approvals.reject',
      ];
      for (const method of methods) {
        const res = await remoteDirectMethod(fixture, session, method);
        assert.equal(res.status, 200, `${method}: ${res.status} ${res.body}`);
        const parsed = payloadOf(res.body);
        assert.equal(parsed.jsonrpc, '2.0', method);
        // -32601 is the transport's OWN answer for "no handler is registered".
        // It is not an administrative decision and carries no administrative
        // detail, which is what makes the admin surface unobservable.
        assert.equal(parsed.error.code, METHOD_NOT_FOUND, `${method}: ${res.body}`);
        assert.equal(parsed.result, undefined, method);
        assert.equal(res.body.includes('deviceId'), false, method);
        assert.equal(res.body.includes(fixture.device.deviceId), false, method);
      }

      assert.deepEqual(trustStoreBytes(fixture.storePath), storeBefore, 'trust store unchanged');
      assert.deepEqual(fixture.approvals.listActive(), []);
      assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
    } finally {
      await fixture.server.stop();
    }
  });

  // =========================================================================
  // Per-control evidence
  // =========================================================================

  test('RC05-NEG-74/75: remote approval action and rejection reach no approval handler', async () => {
    const fixture = await startIsolated({ tag: 'neg74' });
    try {
      // A REAL pending approval exists, so a working handler would have
      // something to act on.
      const pending = fixture.approvals.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'agent-alpha', clientType: 'claude-code' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        },
        reviewMaterial: '--- a/secret.txt\n+++ b/secret.txt\n@@ -1 +1 @@\n-old\n+new\n',
      });
      assert.equal(fixture.approvals.getRequest(pending.requestId).state, 'PENDING');

      const session = await initializeSession(fixture.port, fixture.client);
      for (const name of ['approve', 'reject', 'approval.approve', 'approval.reject']) {
        const res = await remoteToolCall(fixture, session, name, {
          requestId: pending.requestId,
          reason: 'remote override',
        });
        assertUnknownTool(res, name);

        // No review material, no approval token, no request identifier.
        assert.equal(res.body.includes('secret.txt'), false, `${name} leaked review material`);
        assert.equal(res.body.includes(pending.requestId), false, `${name} leaked the request ID`);
      }

      // The approval is exactly as it was: still pending, never approved, and
      // no approval token was ever minted through the remote path.
      const after = fixture.approvals.getRequest(pending.requestId);
      assert.equal(after.state, 'PENDING');
      assert.equal(after.token, undefined);
      assert.equal(fixture.approvals.listActive().length, 1);

      // The LOCAL channel can still act, so the capability exists and is
      // withheld remotely.
      const local = await localAdminRequest(
        fixture.endpoint,
        fixture.operator.privateKey,
        'approvals.list',
      );
      assert.equal(local.ok, true, JSON.stringify(local));
      assert.equal(local.result.approvals.length, 1);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-76: remote approval listing and inspection disclose no review material', async () => {
    const fixture = await startIsolated({ tag: 'neg76' });
    try {
      const pending = fixture.approvals.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'agent-alpha', clientType: 'claude-code' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        },
        reviewMaterial: '--- a/classified.txt\n+++ b/classified.txt\n@@ -1 +1 @@\n-old\n+new\n',
      });

      const session = await initializeSession(fixture.port, fixture.client);
      for (const name of ['approvals.list', 'approvals.inspect', 'approvals']) {
        const res = await remoteToolCall(fixture, session, name, {
          requestId: pending.requestId,
        });
        assertUnknownTool(res, name);
        for (const secret of [
          'classified.txt',
          pending.requestId,
          'reviewMaterial',
          'reviewSummary',
          'executionPayloadHash',
        ]) {
          assert.equal(res.body.includes(secret), false, `${name} disclosed ${secret}`);
        }
      }

      assert.equal(fixture.approvals.getRequest(pending.requestId).state, 'PENDING');

      const local = await localAdminRequest(
        fixture.endpoint,
        fixture.operator.privateKey,
        'approvals.inspect',
        { requestId: pending.requestId },
      );
      assert.equal(local.ok, true, JSON.stringify(local));
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-77: remote device administration reaches no trust-store handler', async () => {
    const fixture = await startIsolated({ tag: 'neg77' });
    try {
      const storeBefore = trustStoreBytes(fixture.storePath);
      const session = await initializeSession(fixture.port, fixture.client);

      const deviceNames = FORBIDDEN_REMOTE_ADMIN_TOOLS.filter(
        ([name]) =>
          name.startsWith('device') || name.startsWith('devices') || name === 'enrollment.create',
      );
      assert.ok(deviceNames.length >= 5, 'the device-administration names are all covered');

      for (const [name, args] of deviceNames) {
        const res = await remoteToolCall(fixture, session, name, {
          ...args,
          clientId: 'attacker',
          clientType: 'claude-code',
          spkiPin: 'e'.repeat(64),
        });
        assertUnknownTool(res, name);
        for (const secret of [
          fixture.device.deviceId,
          fixture.clientPin,
          'alpha-laptop',
          'deviceId',
          'spkiPin',
        ]) {
          assert.equal(res.body.includes(secret), false, `${name} disclosed ${secret}`);
        }
      }

      // The trust store is byte-for-byte unchanged: no device was enrolled,
      // renamed, re-pinned, or revoked.
      assert.deepEqual(trustStoreBytes(fixture.storePath), storeBefore, 'trust store unchanged');
      const onDisk = readStoreFile(fixture.storePath);
      assert.equal(onDisk.devices.length, 1);
      assert.equal(onDisk.devices[0].revoked, false);
      assert.deepEqual(onDisk.devices[0].pins, [fixture.clientPin]);

      // Local administration still works: the capability exists and is merely
      // withheld remotely.
      const local = await localAdminRequest(
        fixture.endpoint,
        fixture.operator.privateKey,
        'devices.inspect',
        { deviceId: fixture.device.deviceId },
      );
      assert.equal(local.ok, true, JSON.stringify(local));
      assert.equal(local.result.deviceId, fixture.device.deviceId);
      assert.deepEqual(local.result.pins, [fixture.clientPin]);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-78: remote policy modification reaches no policy handler', async () => {
    const fixture = await startIsolated({ tag: 'neg78' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);
      const policyHashBefore = policyHashOf(fixture);
      const decisionBefore = await remoteReadFile(fixture, session, 'README.md');
      assert.notEqual(decisionBefore.isError, true, JSON.stringify(decisionBefore));

      for (const name of [
        'policy.set',
        'policy.update',
        'policy.reload',
        'policy.write',
        'policy.disable',
        'policy',
      ]) {
        const res = await remoteToolCall(fixture, session, name, {
          policy: { version: 1, rules: [{ effect: 'ALLOW', tool: '*' }] },
          effect: 'ALLOW',
        });
        assertUnknownTool(res, name);
      }

      // The policy document is unchanged: the same fingerprint ...
      assert.equal(policyHashOf(fixture), policyHashBefore, 'the policy document is unchanged');
      // ... and evaluation still runs normally, reaching the same decision for
      // the same call, so no administrative action diverted, reloaded, or
      // disabled the engine.
      const decisionAfter = await remoteReadFile(fixture, session, 'README.md');
      assert.deepEqual(decisionAfter, decisionBefore, 'policy evaluation is unchanged');
      assert.equal(fixture.server.effectivePolicyEngine !== undefined, true);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-79: remote session administration cannot touch another session', async () => {
    const fixture = await startIsolated({ tag: 'neg79' });
    try {
      // TWO live sessions on the same device: the target and the attacker's.
      const target = await initializeSession(fixture.port, fixture.client);
      const attacker = await initializeSession(fixture.port, fixture.client);
      assert.match(target.sessionId, /^[0-9a-f]{64}$/);
      assert.notEqual(target.sessionId, attacker.sessionId);

      for (const name of ['sessions.list', 'session.revoke', 'sessions.revoke', 'session.list']) {
        const res = await remoteToolCall(fixture, attacker, name, {
          sessionId: target.sessionId,
        });
        assertUnknownTool(res, name);

        // No session identifier, device identifier, or token is disclosed.
        for (const secret of [target.sessionId, target.token, fixture.device.deviceId]) {
          assert.equal(res.body.includes(secret), false, `${name} disclosed a session or device`);
        }
      }

      // The target session is untouched and still fully usable.
      assert.equal(fixture.server.sessionManager.hasSession(target.sessionId), true);
      assert.equal(fixture.server.sessionManager.hasSession(attacker.sessionId), true);
      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 2);

      const stillLive = await remoteMcp(
        fixture,
        target,
        JSON.stringify({ jsonrpc: '2.0', id: 30, method: 'tools/list' }),
      );
      assert.equal(stillLive.status, 200, stillLive.body);
      assert.equal(payloadOf(stillLive.body).error, undefined, stillLive.body);

      // ...and the LOCAL channel CAN revoke it: the withheld capability.
      const local = await localAdminRequest(
        fixture.endpoint,
        fixture.operator.privateKey,
        'session.revoke',
        { sessionId: target.sessionId },
      );
      assert.equal(local.ok, true, JSON.stringify(local));
      assert.equal(local.result.state, 'REVOKED');
      assert.equal(fixture.server.sessionManager.hasSession(target.sessionId), false);
      // Revoking one session left the other alone.
      assert.equal(fixture.server.sessionManager.hasSession(attacker.sessionId), true);
      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 1);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: the local admin channel is not reachable through the remote listener', async () => {
    const fixture = await startIsolated({ tag: 'no-bridge' });
    try {
      // The local admin protocol is NOT a remote endpoint: neither the socket
      // protocol version nor a local admin method can be spoken over HTTPS.
      const session = await initializeSession(fixture.port, fixture.client);
      for (const requestPath of ['/admin', '/admin-ipc', '/enroll/complete', '/mcp/admin']) {
        const res = await request(fixture.port, fixture.client, {
          method: 'POST',
          headers: { ...MCP_POST_HEADERS, ...sessionHeaders(session.sessionId, session.token) },
          body: JSON.stringify({ protocol: ADMIN_PROTOCOL_VERSION, method: 'devices.list' }),
          requestPath,
        });
        assert.ok([400, 404, 405].includes(res.status), `${requestPath}: ${res.status}`);
        assert.equal(res.body.includes('alpha-laptop'), false, requestPath);
        assert.equal(res.body.includes(fixture.device.deviceId), false, requestPath);
        assert.equal(res.headers['mcp-session-id'], undefined, requestPath);
      }

      // The session and the trust store are unaffected by all of it.
      assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 1);
      const onDisk = readStoreFile(fixture.storePath);
      assert.equal(onDisk.devices.length, 1);
      assert.equal(onDisk.devices[0].revoked, false);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: an unauthenticated remote caller reaches no administrative surface', async () => {
    const fixture = await startIsolated({ tag: 'unauth' });
    try {
      // No session, no credential: every request is refused before any handler.
      for (const [name, args] of FORBIDDEN_REMOTE_ADMIN_TOOLS) {
        const res = await request(fixture.port, fixture.client, {
          method: 'POST',
          headers: MCP_POST_HEADERS,
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 40,
            method: 'tools/call',
            params: { name, arguments: args },
          }),
        });
        assert.equal(res.status, MCP_POST_REPLY_STATUS, `${name}: ${res.status} ${res.body}`);
        const parsed = JSON.parse(res.body);
        assert.equal(parsed.jsonrpc, '2.0', name);
        // The generic admission refusal: the same answer an unknown caller gets
        // for ANY request. An admin-specific answer would itself disclose that
        // the administrative name exists.
        assert.equal(parsed.error.code, MCP_ADMISSION_ERROR_CODE, name);
        assert.equal(parsed.error.data.code, 'UNAUTHENTICATED', name);
      }

      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 0);
      const onDisk = readStoreFile(fixture.storePath);
      assert.equal(onDisk.devices.length, 1);
      assert.equal(onDisk.devices[0].revoked, false);
    } finally {
      await fixture.server.stop();
    }
  });

  test('RC05-NEG-74..79: a malformed remote request reaches no administrative surface', async () => {
    const fixture = await startIsolated({ tag: 'malformed' });
    try {
      const session = await initializeSession(fixture.port, fixture.client);
      const storeBefore = trustStoreBytes(fixture.storePath);

      const bodies = [
        // Truncated mid-document.
        '{"jsonrpc":"2.0","id":50,"method":"device.revoke"',
        // `params` of the wrong JSON type.
        JSON.stringify({
          jsonrpc: '2.0',
          id: 51,
          method: 'device.revoke',
          params: 'not-an-object',
        }),
        // An administrative tool call with no `arguments` member.
        JSON.stringify({
          jsonrpc: '2.0',
          id: 52,
          method: 'tools/call',
          params: { name: 'device.revoke' },
        }),
        // A JSON-RPC batch, refused before any member is dispatched.
        JSON.stringify([{ jsonrpc: '2.0', id: 53, method: 'device.revoke' }]),
      ];

      for (const body of bodies) {
        const res = await remoteMcp(fixture, session, body);
        const label = body.slice(0, 60);

        // Whatever the framing, it is never a successful administrative result
        // and it discloses nothing about the trust store.
        assert.equal(res.body.includes(fixture.device.deviceId), false, label);
        assert.equal(res.body.includes(fixture.clientPin), false, label);
        assert.equal(res.body.includes('alpha-laptop'), false, label);

        if (res.status === MCP_POST_REPLY_STATUS) {
          const parsed = payloadOf(res.body);
          assert.equal(parsed.jsonrpc, '2.0', label);
          assert.ok(
            parsed.error !== undefined || parsed.result?.isError === true,
            `${label}: ${res.body}`,
          );
          if (parsed.error !== undefined) {
            // Only transport-level framing codes: a malformed request is
            // answered by the JSON-RPC envelope, never by an administrative
            // decision about the name it happened to carry.
            assert.ok(
              [MCP_ADMISSION_ERROR_CODE, MCP_INVALID_REQUEST_ERROR_CODE, METHOD_NOT_FOUND].includes(
                parsed.error.code,
              ),
              `${label}: ${res.body}`,
            );
            assert.equal(parsed.result, undefined, label);
          }
        } else {
          // A transport-level refusal: bad framing never creates an MCP session
          // and never reaches a handler.
          assert.ok(res.status >= 400, `${label}: ${res.status}`);
        }
      }

      // The refused JSON-RPC batch is refused as ONE malformed Request, so it
      // carries the framing code rather than anything administrative.
      const batch = await remoteMcp(fixture, session, JSON.stringify([{ jsonrpc: '2.0', id: 54 }]));
      assert.equal(batch.status, MCP_POST_REPLY_STATUS, batch.body);
      assert.equal(payloadOf(batch.body).error.code, MCP_INVALID_REQUEST_ERROR_CODE, batch.body);

      assert.deepEqual(trustStoreBytes(fixture.storePath), storeBefore, 'trust store unchanged');
      assert.equal(readStoreFile(fixture.storePath).devices[0].revoked, false);
      assert.equal(fixture.server.sessionManager.hasSession(session.sessionId), true);
      assert.equal(fixture.server.sessionManager.getActiveSessionCount(), 1);
    } finally {
      await fixture.server.stop();
    }
  });
});
