/** RC-08 Task 7 — Cross-Client & Cross-Workspace Isolation. */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { ALL_TOOL_DEFINITIONS, createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { createProductionDeterministicRegistry } from '../apps/mcp-server/dist/composite-framework.js';
import { sessionRateLimitKey } from '../apps/mcp-server/dist/remote-execution.js';
import { ACTIVE_SEGMENT_FILENAME, verifyOfflineStore } from '../packages/audit/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import {
  RawJsonRpcStdioClient,
  makeRawHttpsRequest,
  spawnArcStdioServerProcess,
  startTestRemoteServer,
} from './helpers/rc08-mcp-client-harness.mjs';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-task7-'));
const A = {
  clientId: 'client-a',
  clientType: 'agent',
  sessionId: 'session-a',
  deviceId: 'device-a',
  authenticated: true,
};
const B = {
  clientId: 'client-b',
  clientType: 'agent',
  sessionId: 'session-b',
  deviceId: 'device-b',
  authenticated: true,
};
let pki;
before(() => {
  assert.equal(hasOpenssl(), true);
  pki = createTestPki(path.join(tempRoot, 'pki'));
});
after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

const body = (response) => JSON.parse(response.content[0].text);
function payload(text) {
  const value = text.trim();
  if (value.startsWith('{')) return JSON.parse(value);
  const line = value.split('\n').find((entry) => entry.startsWith('data:'));
  assert.ok(line);
  return JSON.parse(line.slice(5).trim());
}
async function waitFor(predicate, timeout = 5_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return predicate();
}
function ws(label, content = label) {
  const root = path.join(tempRoot, label);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'sentinel.txt'), `${content}\n`);
  return root;
}
function local(label, roots, durable = false) {
  const processStateDir = path.join(tempRoot, `${label}-state`);
  const audit = durable ? createAuditConfig(tempRoot, `${label}-audit`) : undefined;
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: roots,
    defaultWorkspaceId: roots[0].id,
    processStateDir,
    ...(audit ? { audit } : {}),
  });
  return { server, processStateDir, audit };
}
async function approved(server, actor, tool, args, options) {
  const first = await server.executeAuthenticatedToolCall(actor, tool, args);
  const request = body(first);
  assert.equal(request.code, 'APPROVAL_REQUIRED');
  const grant = server.approvalStateManager.approve(request.details.approvalRequestId);
  return server.executeAuthenticatedToolCall(
    actor,
    tool,
    { ...args, _arcApproval: { requestId: request.details.approvalRequestId, token: grant.token } },
    options,
  );
}
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}
async function remoteCall(harness, material, headers, rpc) {
  const { promise } = makeRawHttpsRequest({
    port: harness.port,
    caPath: pki.trustedCaCertPath,
    certPath: material.certPath,
    keyPath: material.keyPath,
    headers,
    body: JSON.stringify(rpc),
  });
  return promise;
}
async function initialize(harness, material, id) {
  const response = await remoteCall(
    harness,
    material,
    {},
    {
      jsonrpc: '2.0',
      id,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'task7', version: '1' },
      },
    },
  );
  assert.equal(payload(response.body).error, undefined);
  return {
    sessionId: response.headers['mcp-session-id'],
    token: response.headers['arc-session-token'],
  };
}
const auth = (session) => ({
  'Mcp-Session-Id': session.sessionId,
  Authorization: `Bearer ${session.token}`,
});

test('RC08-NEG-071: Session A cannot read Workspace B through the real public tool path', async () => {
  const rootA = ws('neg071-a', 'A-ONLY-071');
  const rootB = ws('neg071-b', 'B-CONFIDENTIAL-071');
  const serverA = local('neg071-a', [{ id: 'workspace-a', path: rootA }]).server;
  const serverB = local('neg071-b', [{ id: 'workspace-b', path: rootB }]).server;
  const denied = await serverA.executeAuthenticatedToolCall(A, 'read_file', {
    workspaceId: 'workspace-b',
    path: 'sentinel.txt',
  });
  assert.equal(denied.isError, true);
  assert.match(body(denied).code, /^(WORKSPACE_NOT_FOUND|ACCESS_DENIED|POLICY_DENIED)$/);
  assert.equal(denied.content[0].text.includes('B-CONFIDENTIAL-071'), false);
  assert.equal(
    body(
      await serverA.executeAuthenticatedToolCall(A, 'read_file', {
        workspaceId: 'workspace-a',
        path: 'sentinel.txt',
      }),
    ).content,
    'A-ONLY-071\n',
  );
  assert.equal(
    body(
      await serverB.executeAuthenticatedToolCall(B, 'read_file', {
        workspaceId: 'workspace-b',
        path: 'sentinel.txt',
      }),
    ).content,
    'B-CONFIDENTIAL-071\n',
  );
});

test('RC08-NEG-072: process status and output remain opaque across client/session ownership', async () => {
  const root = ws('neg072');
  fs.writeFileSync(
    path.join(root, 'hold.test.js'),
    "import test from 'node:test';test('hold',async()=>new Promise(()=>{}));\n",
  );
  const { server } = local('neg072', [{ id: 'workspace-a', path: root }]);
  const execution = approved(server, A, 'arc_test', {
    workspaceId: 'workspace-a',
    testPath: 'hold.test.js',
    maxDurationMs: 60_000,
  });
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 1), true);
  const record = server.processRegistry.getActiveProcesses()[0];
  for (const tool of ['process_status', 'process_output']) {
    const denied = await server.executeAuthenticatedToolCall(B, tool, {
      processId: record.processId,
      workspaceId: 'workspace-a',
    });
    assert.equal(body(denied).code, 'POLICY_DENIED');
    assert.equal(denied.content[0].text.includes(String(record._pid)), false);
    assert.equal(denied.content[0].text.includes('hold.test.js'), false);
  }
  assert.equal(
    body(
      await server.executeAuthenticatedToolCall(A, 'process_status', {
        processId: record.processId,
        workspaceId: 'workspace-a',
      }),
    ).processId,
    record.processId,
  );
  await server.executeAuthenticatedToolCall(A, 'terminate_process', {
    processId: record.processId,
    workspaceId: 'workspace-a',
    signal: 'SIGTERM',
  });
  await execution;
});

test('RC08-NEG-073: cross-session terminate_process emits no signal and owner retains control', async () => {
  const root = ws('neg073');
  fs.writeFileSync(
    path.join(root, 'hold.test.js'),
    "import test from 'node:test';test('hold',async()=>new Promise(()=>{}));\n",
  );
  const { server, processStateDir } = local('neg073', [{ id: 'workspace-a', path: root }]);
  const events = [];
  server.processRegistry.registerLifecycleSink({ onProcessEvent: (event) => events.push(event) });
  const execution = approved(server, A, 'arc_test', {
    workspaceId: 'workspace-a',
    testPath: 'hold.test.js',
    maxDurationMs: 60_000,
  });
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 1), true);
  const record = server.processRegistry.getActiveProcesses()[0];
  const before = events.length;
  assert.equal(
    body(
      await server.executeAuthenticatedToolCall(B, 'terminate_process', {
        processId: record.processId,
        workspaceId: 'workspace-a',
        signal: 'SIGTERM',
      }),
    ).code,
    'POLICY_DENIED',
  );
  assert.equal(alive(record._pid), true);
  assert.equal(
    events.slice(before).some((event) => /SIGTERM|SIGKILL|TERMINATION/.test(event.eventType)),
    false,
  );
  await server.executeAuthenticatedToolCall(A, 'terminate_process', {
    processId: record.processId,
    workspaceId: 'workspace-a',
    signal: 'SIGTERM',
  });
  await execution;
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 0), true);
  assert.equal(
    await waitFor(
      () => !fs.existsSync(processStateDir) || fs.readdirSync(processStateDir).length === 0,
    ),
    true,
  );
});

test('RC08-NEG-074: workspace-bound process policy decisions remain isolated under interleaving', async () => {
  const rootA = ws('neg074-a');
  const rootB = ws('neg074-b');
  fs.writeFileSync(
    path.join(rootA, 'hold.test.js'),
    "import test from 'node:test';test('hold',async()=>new Promise(()=>{}));\n",
  );
  const { server } = local('neg074', [
    { id: 'workspace-a', path: rootA },
    { id: 'workspace-b', path: rootB },
  ]);
  const execution = approved(server, A, 'arc_test', {
    workspaceId: 'workspace-a',
    testPath: 'hold.test.js',
    maxDurationMs: 60_000,
  });
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 1), true);
  const processId = server.processRegistry.getActiveProcesses()[0].processId;
  const [allow1, deny, allow2] = await Promise.all([
    server.executeAuthenticatedToolCall(A, 'process_status', {
      processId,
      workspaceId: 'workspace-a',
    }),
    server.executeAuthenticatedToolCall(A, 'process_status', {
      processId,
      workspaceId: 'workspace-b',
    }),
    server.executeAuthenticatedToolCall(A, 'process_status', {
      processId,
      workspaceId: 'workspace-a',
    }),
  ]);
  assert.equal(allow1.isError, undefined);
  assert.equal(body(deny).code, 'POLICY_DENIED');
  assert.equal(allow2.isError, undefined);
  await server.executeAuthenticatedToolCall(A, 'terminate_process', {
    processId,
    workspaceId: 'workspace-a',
    signal: 'SIGTERM',
  });
  await execution;
});

test('RC08-NEG-075: Device A session credentials cannot move to enrolled Device B', async () => {
  const deviceB = pki.issueTrustedClientCert({ commonName: 'task7-device-b' });
  const harness = await startTestRemoteServer({
    tempDir: tempRoot,
    pki,
    tag: 'neg075',
    enrolledClientCertPaths: [pki.clientCertPath, deviceB.certPath],
  });
  const materialA = { certPath: pki.clientCertPath, keyPath: pki.clientKeyPath };
  const materialB = { certPath: deviceB.certPath, keyPath: deviceB.keyPath };
  try {
    const sessionA = await initialize(harness, materialA, 751);
    const mismatch = payload(
      (
        await remoteCall(harness, materialB, auth(sessionA), {
          jsonrpc: '2.0',
          id: 752,
          method: 'ping',
          params: {},
        })
      ).body,
    );
    assert.equal(mismatch.error.data.code, 'INVALID_SESSION_TOKEN');
    assert.equal(
      payload(
        (
          await remoteCall(harness, materialA, auth(sessionA), {
            jsonrpc: '2.0',
            id: 753,
            method: 'ping',
            params: {},
          })
        ).body,
      ).error,
      undefined,
    );
    assert.equal(harness.server.processRegistry.listProcesses().length, 0);
  } finally {
    await harness.cleanup();
  }
});

test('RC08-NEG-076: durable audit records minimize and isolate workspace confidential data', async () => {
  const secretA = 'CONFIDENTIAL-A-076-NOT-FOR-B';
  const secretB = 'CONFIDENTIAL-B-076-NOT-FOR-A';
  const rootA = ws('neg076-a', secretA);
  const rootB = ws('neg076-b', secretB);
  const parts = local(
    'neg076',
    [
      { id: 'workspace-a', path: rootA },
      { id: 'workspace-b', path: rootB },
    ],
    true,
  );
  await parts.server.start();
  await parts.server.executeAuthenticatedToolCall(A, 'read_file', {
    workspaceId: 'workspace-a',
    path: 'sentinel.txt',
  });
  await parts.server.executeAuthenticatedToolCall(B, 'read_file', {
    workspaceId: 'workspace-b',
    path: 'sentinel.txt',
  });
  await parts.server.stop();
  const ledger = fs.readFileSync(path.join(parts.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8');
  const records = ledger.trim().split('\n').map(JSON.parse);
  assert.ok(records.some((record) => record.target.workspaceId === 'workspace-a'));
  assert.ok(records.some((record) => record.target.workspaceId === 'workspace-b'));
  for (const forbidden of [secretA, secretB, rootA, rootB])
    assert.equal(ledger.includes(forbidden), false);
  assert.equal(
    (
      await verifyOfflineStore({
        directory: parts.audit.directory,
        checkpointPublicKeyPath: parts.audit.publicKeyPath,
      })
    ).status,
    'VERIFIED',
  );
});

test('RC08-NEG-077: AbortSignal cancellation of arc_verify stops its supervised child', async () => {
  const root = ws('neg077');
  fs.mkdirSync(path.join(root, 'test'));
  fs.writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name: 'neg077', type: 'module' }),
  );
  fs.writeFileSync(
    path.join(root, 'test', 'hold.test.js'),
    "import test from 'node:test';test('hold',async()=>new Promise(()=>{}));\n",
  );
  const parts = local('neg077', [{ id: 'workspace-a', path: root }], true);
  const events = [];
  parts.server.processRegistry.registerLifecycleSink({
    onProcessEvent: (event) => events.push(event),
  });
  await parts.server.start();
  const controller = new AbortController();
  const execution = approved(
    parts.server,
    A,
    'arc_verify',
    { workspaceId: 'workspace-a', suite: 'test' },
    { signal: controller.signal },
  );
  assert.equal(await waitFor(() => parts.server.processRegistry.countRunning() === 1), true);
  const record = parts.server.processRegistry.getActiveProcesses()[0];
  const pid = record._pid;
  controller.abort();
  await execution;
  assert.equal(
    await waitFor(() => !alive(pid) && parts.server.processRegistry.countRunning() === 0),
    true,
  );
  assert.ok(
    events.some(
      (event) => event.processId === record.processId && event.eventType === 'PROCESS_SIGTERM_SENT',
    ),
  );
  assert.equal(
    await waitFor(
      () =>
        !fs.existsSync(parts.processStateDir) || fs.readdirSync(parts.processStateDir).length === 0,
      3_000,
    ),
    true,
  );
  await parts.server.stop();
  assert.equal(
    fs
      .readFileSync(path.join(parts.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8')
      .includes('"phase":"FAILED"'),
    false,
  );
});

test('RC08-NEG-078: real remote arc_test disconnect stops the runner and releases admission', async () => {
  const stateDir = path.join(tempRoot, 'neg078-state');
  const harness = await startTestRemoteServer({
    tempDir: tempRoot,
    pki,
    tag: 'neg078',
    enrolledClientCertPaths: [pki.clientCertPath],
    config: { processStateDir: stateDir },
  });
  const material = { certPath: pki.clientCertPath, keyPath: pki.clientKeyPath };
  fs.writeFileSync(
    path.join(harness.workspaceDir, 'hold.test.js'),
    "import test from 'node:test';test('hold',async()=>new Promise(()=>{}));\n",
  );
  try {
    const session = await initialize(harness, material, 781);
    const challengeWire = await remoteCall(harness, material, auth(session), {
      jsonrpc: '2.0',
      id: 782,
      method: 'tools/call',
      params: { name: 'arc_test', arguments: { testPath: 'hold.test.js', maxDurationMs: 60_000 } },
    });
    const challenge = JSON.parse(payload(challengeWire.body).result.content[0].text);
    const grant = harness.server.approvalStateManager.approve(challenge.details.approvalRequestId);
    const raw = makeRawHttpsRequest({
      port: harness.port,
      caPath: pki.trustedCaCertPath,
      certPath: material.certPath,
      keyPath: material.keyPath,
      headers: auth(session),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 783,
        method: 'tools/call',
        params: {
          name: 'arc_test',
          arguments: {
            testPath: 'hold.test.js',
            maxDurationMs: 60_000,
            _arcApproval: { requestId: challenge.details.approvalRequestId, token: grant.token },
          },
        },
      }),
    });
    raw.promise.catch(() => {});
    assert.equal(await waitFor(() => harness.server.processRegistry.countRunning() === 1), true);
    const record = harness.server.processRegistry.getActiveProcesses()[0];
    const pid = record._pid;
    const enrolledDeviceId = JSON.parse(fs.readFileSync(harness.storePath, 'utf8')).devices[0]
      .deviceId;
    const key = sessionRateLimitKey({ deviceId: enrolledDeviceId, sessionId: session.sessionId });
    assert.equal(harness.server.authenticatedRequestLimiter.getHolderCount(key), 1);
    raw.req.destroy();
    assert.equal(
      await waitFor(() => !alive(pid) && harness.server.processRegistry.countRunning() === 0),
      true,
    );
    assert.equal(
      await waitFor(() => harness.server.authenticatedRequestLimiter.getHolderCount(key) === 0),
      true,
    );
    assert.equal(
      await waitFor(() => !fs.existsSync(stateDir) || fs.readdirSync(stateDir).length === 0, 3_000),
      true,
    );
  } finally {
    await harness.cleanup();
  }
});

test('RC08-NEG-079: concurrent supervised executions retain workspace cwd and output isolation', async () => {
  const rootA = ws('neg079-a', 'ENV-A-079');
  const rootB = ws('neg079-b', 'ENV-B-079');
  const source =
    "import fs from 'node:fs';import test from 'node:test';test('identity',()=>console.log('CWD='+process.cwd()+' SENTINEL='+fs.readFileSync('sentinel.txt','utf8').trim()));\n";
  fs.writeFileSync(path.join(rootA, 'identity.test.js'), source);
  fs.writeFileSync(path.join(rootB, 'identity.test.js'), source);
  const { server } = local('neg079', [
    { id: 'workspace-a', path: rootA },
    { id: 'workspace-b', path: rootB },
  ]);
  const [resA, resB] = await Promise.all([
    approved(server, A, 'arc_test', { workspaceId: 'workspace-a', testPath: 'identity.test.js' }),
    approved(server, B, 'arc_test', { workspaceId: 'workspace-b', testPath: 'identity.test.js' }),
  ]);
  const outA = body(resA).outputExcerpt;
  const outB = body(resB).outputExcerpt;
  assert.ok(outA.includes('ENV-A-079'));
  assert.ok(outB.includes('ENV-B-079'));
  assert.equal(outA.includes('ENV-B-079'), false);
  assert.equal(outB.includes('ENV-A-079'), false);
  const records = server.processRegistry.listProcesses();
  assert.ok(
    records.some(
      (record) =>
        record.workspaceId === 'workspace-a' &&
        record.actor.sessionId === 'session-a' &&
        record.cwd === rootA,
    ),
  );
  assert.ok(
    records.some(
      (record) =>
        record.workspaceId === 'workspace-b' &&
        record.actor.sessionId === 'session-b' &&
        record.cwd === rootB,
    ),
  );
});

test('RC08-NEG-080: real stdio and authenticated remote tools/call preserve blocked schema semantics', async () => {
  const stdio = spawnArcStdioServerProcess({ tempDir: tempRoot, label: 'neg080' });
  const client = new RawJsonRpcStdioClient(stdio.proc);
  const remote = await startTestRemoteServer({
    tempDir: tempRoot,
    pki,
    tag: 'neg080',
    enrolledClientCertPaths: [pki.clientCertPath],
  });
  const material = { certPath: pki.clientCertPath, keyPath: pki.clientKeyPath };
  try {
    await client.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'stdio', version: '1' },
    });
    client.notify('notifications/initialized', {});
    const stdioResult = await client.request('tools/call', {
      name: 'read_file',
      arguments: { path: 42 },
    });
    const stdioError = JSON.parse(stdioResult.result.content[0].text);
    const session = await initialize(remote, material, 801);
    const remoteWire = await remoteCall(remote, material, auth(session), {
      jsonrpc: '2.0',
      id: 802,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: 42 } },
    });
    const remoteResult = payload(remoteWire.body).result;
    const remoteError = JSON.parse(remoteResult.content[0].text);
    assert.equal(stdioResult.result.isError, true);
    assert.equal(remoteResult.isError, true);
    assert.equal(stdioError.code, 'INVALID_REQUEST_SCHEMA');
    assert.equal(remoteError.code, stdioError.code);
    assert.deepEqual(Object.keys(remoteError).sort(), Object.keys(stdioError).sort());
  } finally {
    client.close();
    await stdio.cleanup();
    await remote.cleanup();
  }
});

test('RC08-FLOW-15: concurrent cross-workspace read-only workflow preserves state and durable audit isolation', async () => {
  const rootA = ws('flow15-a', 'FLOW15-A');
  const rootB = ws('flow15-b', 'FLOW15-B');
  const parts = local(
    'flow15',
    [
      { id: 'workspace-a', path: rootA },
      { id: 'workspace-b', path: rootB },
    ],
    true,
  );
  await parts.server.start();
  const operations = [
    ['read_file', { path: 'sentinel.txt' }],
    ['list_directory', { path: '.' }],
    ['search_files', { pattern: 'sentinel.txt' }],
  ];
  const calls = [];
  for (const [workspaceId, actor] of [
    ['workspace-a', A],
    ['workspace-b', B],
  ])
    for (const [tool, args] of operations)
      calls.push(parts.server.executeAuthenticatedToolCall(actor, tool, { workspaceId, ...args }));
  const results = await Promise.all(calls);
  assert.equal(results.length, 6);
  assert.equal(
    results.every((result) => result.isError !== true),
    true,
  );
  const texts = results.map((result) => result.content[0].text);
  assert.equal(texts.filter((text) => text.includes('FLOW15-A')).length, 1);
  assert.equal(texts.filter((text) => text.includes('FLOW15-B')).length, 1);
  assert.equal(parts.server.processRegistry.listProcesses().length, 0);
  await parts.server.stop();
  assert.equal(
    (
      await verifyOfflineStore({
        directory: parts.audit.directory,
        checkpointPublicKeyPath: parts.audit.publicKeyPath,
      })
    ).status,
    'VERIFIED',
  );
});

test('RC08-FLOW-16: owner termination produces SIGTERM-only clean terminal process state', async () => {
  const root = ws('flow16');
  fs.writeFileSync(
    path.join(root, 'cooperative.test.js'),
    "import test from 'node:test';process.on('SIGTERM',()=>process.exit(0));test('hold',async()=>new Promise(()=>{}));\n",
  );
  const { server, processStateDir } = local('flow16', [{ id: 'workspace-a', path: root }]);
  const events = [];
  server.processRegistry.registerLifecycleSink({ onProcessEvent: (event) => events.push(event) });
  const execution = approved(server, A, 'arc_test', {
    workspaceId: 'workspace-a',
    testPath: 'cooperative.test.js',
    maxDurationMs: 60_000,
  });
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 1), true);
  const record = server.processRegistry.getActiveProcesses()[0];
  assert.equal(
    (
      await server.executeAuthenticatedToolCall(A, 'terminate_process', {
        processId: record.processId,
        workspaceId: 'workspace-a',
        signal: 'SIGTERM',
      })
    ).isError,
    undefined,
  );
  await execution;
  await new Promise((resolve) => setTimeout(resolve, 1_100));
  const types = events
    .filter((event) => event.processId === record.processId)
    .map((event) => event.eventType);
  assert.ok(types.includes('PROCESS_TERMINATION_REQUESTED'));
  assert.ok(types.includes('PROCESS_SIGTERM_SENT'));
  assert.equal(types.includes('PROCESS_SIGKILL_ESCALATED'), false);
  assert.match(
    body(
      await server.executeAuthenticatedToolCall(A, 'process_status', {
        processId: record.processId,
        workspaceId: 'workspace-a',
      }),
    ).state,
    /^(TERMINATED|COMPLETED|FAILED)$/,
  );
  assert.deepEqual(fs.existsSync(processStateDir) ? fs.readdirSync(processStateDir) : [], []);
});

test('RC08-FLOW-17: production read-only engineering composites preserve repository state and zero-network boundary', async () => {
  const root = ws('flow17');
  git(root, ['init', '-b', 'main']);
  git(root, ['config', 'user.email', 'task7@example.invalid']);
  git(root, ['config', 'user.name', 'Task 7']);
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(
    path.join(root, '.github', 'workflows', 'ci.yml'),
    'name: CI\non: [push]\njobs: {}\n',
  );
  fs.writeFileSync(path.join(root, 'safe.txt'), 'before\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'safe.txt'), 'after\n');
  fs.writeFileSync(path.join(root, '.env'), 'CONFIDENTIAL_FLOW17=hidden\n');
  const before = {
    head: git(root, ['rev-parse', 'HEAD']),
    index: git(root, ['diff', '--cached', '--binary']),
    worktree: git(root, ['diff', '--binary']),
  };
  const { server } = local('flow17', [{ id: 'workspace-a', path: root }]);
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('network forbidden');
  };
  let results;
  try {
    results = await Promise.all(
      ['arc_repo_status', 'arc_worktree_status', 'arc_review_diff', 'arc_ci_status'].map((tool) =>
        server.executeAuthenticatedToolCall(A, tool, { workspaceId: 'workspace-a' }),
      ),
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(
    results.every((result) => result.isError !== true),
    true,
  );
  assert.equal(fetchCalls, 0);
  const wire = results.map((result) => result.content[0].text).join('\n');
  assert.ok(wire.includes('safe.txt'));
  assert.equal(wire.includes('CONFIDENTIAL_FLOW17'), false);
  assert.equal(wire.includes('.env'), false);
  assert.equal(server.processRegistry.countRunning(), 0);
  assert.equal(git(root, ['rev-parse', 'HEAD']), before.head);
  assert.equal(git(root, ['diff', '--cached', '--binary']), before.index);
  assert.equal(git(root, ['diff', '--binary']), before.worktree);
  assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
  assert.equal(createProductionDeterministicRegistry().listEntryIds().length, 5);
});
