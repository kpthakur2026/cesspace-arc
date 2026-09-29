/**
 * RC-08 Task 6 — Concurrency, Resource Exhaustion & Robustness.
 *
 * All stress is bounded, local, and driven through existing production seams.
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
import { spawn } from 'node:child_process';

import { ArcMcpServer, createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { sessionRateLimitKey } from '../apps/mcp-server/dist/remote-execution.js';
import { MAX_OUTSTANDING_REQUESTS_PER_SESSION } from '../apps/mcp-server/dist/remote-resource-limits.js';
import {
  ACTIVE_SEGMENT_FILENAME,
  AuditLogger,
  SEGMENT_SIZE_THRESHOLD,
  openAuditRuntime,
  verifyOfflineStore,
  verifyRetainedPrimaryHistory,
} from '../packages/audit/dist/index.js';
import { DeviceTrustStore, deriveSpkiPin } from '../packages/auth/dist/index.js';
import { FilesystemSubsystem, MAX_SEARCH_RESULTS } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import {
  APPROVAL_TTL_SECONDS,
  ApprovalStateManager,
  MAX_ACTIVE_APPROVALS_GLOBAL,
  MAX_ACTIVE_APPROVALS_PER_ACTOR,
  MAX_REVIEW_BYTES_PER_ACTOR,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import {
  CONCURRENCY_LIMITS,
  MAX_OUTPUT_READ_BYTES,
  MAX_PROCESS_BUFFER_BYTES,
  ProcessRegistry,
  getProcessStatInfo,
  sweepOrphanProcesses,
} from '../packages/processes/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-task6-'));
const ACTOR = {
  clientId: 'rc08-task6',
  clientType: 'agent',
  sessionId: 'task6-session',
  deviceId: 'task6-device',
  authenticated: true,
};
const PUBLIC_HOSTNAME = 'localhost';
const MCP_HEADERS = {
  Accept: 'application/json, text/event-stream',
  'Content-Type': 'application/json',
};
let pki;
let fixtureCounter = 0;

before(() => {
  assert.equal(hasOpenssl(), true);
  pki = createTestPki(path.join(tempRoot, 'pki'));
});

after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

function responseBody(response) {
  return JSON.parse(response.content[0].text);
}

function payloadOf(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) return JSON.parse(trimmed);
  const data = trimmed.split('\n').find((line) => line.startsWith('data:'));
  assert.ok(data, `missing MCP data frame: ${trimmed.slice(0, 160)}`);
  return JSON.parse(data.slice(5).trim());
}

async function waitFor(predicate, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return predicate();
}

function makeWorkspace(label) {
  const root = path.join(tempRoot, label);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'README.md'), `# ${label}\n`);
  return root;
}

function makeProcessServer(label, workspaceCount = 1) {
  const roots = Array.from({ length: workspaceCount }, (_, index) => {
    const id = `ws-${index}`;
    const root = makeWorkspace(`${label}-${id}`);
    fs.writeFileSync(
      path.join(root, 'hold.test.js'),
      "import test from 'node:test';\ntest('hold', async () => new Promise(() => {}));\n",
    );
    return { id, path: root };
  });
  const processStateDir = path.join(tempRoot, `${label}-process-state`);
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: roots,
    defaultWorkspaceId: roots[0].id,
    processStateDir,
  });
  return { server, roots, processStateDir };
}

async function startApprovedTest(server, actor, args) {
  const challenge = await server.executeAuthenticatedToolCall(actor, 'arc_test', args);
  const pending = responseBody(challenge);
  assert.equal(pending.code, 'APPROVAL_REQUIRED');
  const grant = server.approvalStateManager.approve(pending.details.approvalRequestId);
  return server.executeAuthenticatedToolCall(actor, 'arc_test', {
    ...args,
    _arcApproval: { requestId: pending.details.approvalRequestId, token: grant.token },
  });
}

async function stopAllProcesses(server) {
  const active = server.processRegistry.getActiveProcesses();
  await Promise.all(
    active.map((record) =>
      server.processRegistry.terminateProcess(record.processId, 'SIGKILL', {
        clientId: record.actor.clientId,
        sessionId: record.actor.sessionId,
        workspaceId: record.workspaceId,
      }),
    ),
  );
  assert.equal(await waitFor(() => server.processRegistry.countRunning() === 0), true);
}

function createDurableServer(label, roots) {
  const registry = new WorkspaceRegistry();
  for (const root of roots) registry.registerWorkspace(root.id, root.path);
  const processRegistry = new ProcessRegistry();
  const approvals = new ApprovalStateManager();
  const config = createAuditConfig(tempRoot, label);
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry, processRegistry),
    new AuditLogger(),
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'stdio',
      authorizedRoots: roots,
      defaultWorkspaceId: roots[0].id,
      audit: config,
    },
    undefined,
    processRegistry,
    approvals,
  );
  return { server, processRegistry, approvals, config };
}

function readJsonLines(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').trim();
  return text === '' ? [] : text.split('\n').map((line) => JSON.parse(line));
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

function writeTrustStore(label) {
  const storePath = path.join(tempRoot, `${label}-devices.json`);
  const store = DeviceTrustStore.createEmpty();
  const { device } = store.enrollDevice({
    clientId: label,
    clientType: 'rc08-test',
    pin: deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8')),
  });
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, device };
}

async function startRemote(label) {
  fixtureCounter += 1;
  const port = await freePort();
  const root = makeWorkspace(`${label}-${fixtureCounter}`);
  const { storePath, device } = writeTrustStore(`${label}-${fixtureCounter}`);
  const registry = new WorkspaceRegistry();
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    new AuditLogger(),
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'remote',
      authorizedRoots: [{ id: 'ws', path: root }],
      defaultWorkspaceId: 'ws',
      audit: createAuditConfig(tempRoot, `${label}-${fixtureCounter}`),
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
  );
  await server.start();
  return { server, port, root, device };
}

function remoteRequest(port, { method = 'POST', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        host: '127.0.0.1',
        port,
        path: '/mcp',
        method,
        servername: PUBLIC_HOSTNAME,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
        minVersion: 'TLSv1.3',
        headers: { Host: PUBLIC_HOSTNAME, ...headers },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
        response.on('error', reject);
      },
    );
    request.on('error', reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

async function initializeRemote(port) {
  const response = await remoteRequest(port, {
    headers: MCP_HEADERS,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'task6', version: '1' },
      },
    }),
  });
  assert.equal(response.status, 200, response.body);
  assert.equal(payloadOf(response.body).error, undefined);
  return {
    sessionId: response.headers['mcp-session-id'],
    token: response.headers['arc-session-token'],
  };
}

function sessionHeaders(session) {
  return {
    ...MCP_HEADERS,
    'Mcp-Session-Id': session.sessionId,
    Authorization: `Bearer ${session.token}`,
  };
}

function rpc(id, method = 'ping', params = {}) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params });
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

test('RC08-NEG-061: per-workspace process concurrency refuses the fifth real supervised child', async () => {
  const { server, processStateDir } = makeProcessServer('neg061');
  const launches = [];
  try {
    for (let index = 0; index < CONCURRENCY_LIMITS.maxPerWorkspaceRunning; index += 1) {
      const actor = { ...ACTOR, sessionId: `neg061-session-${index}` };
      launches.push(
        startApprovedTest(server, actor, {
          workspaceId: 'ws-0',
          testPath: 'hold.test.js',
          maxDurationMs: 60_000,
        }),
      );
    }
    assert.equal(
      await waitFor(() => server.processRegistry.countRunning({ workspaceId: 'ws-0' }) === 4),
      true,
    );
    const recordsBefore = server.processRegistry.listProcesses().length;
    const fifthActor = { ...ACTOR, sessionId: 'neg061-session-fifth' };
    const fifth = await startApprovedTest(server, fifthActor, {
      workspaceId: 'ws-0',
      testPath: 'hold.test.js',
      maxDurationMs: 60_000,
    });
    assert.equal(fifth.isError, true);
    assert.equal(responseBody(fifth).code, 'CONCURRENCY_EXCEEDED');
    assert.equal(server.processRegistry.countRunning({ workspaceId: 'ws-0' }), 4);
    assert.equal(
      server.processRegistry.listProcesses().length,
      recordsBefore,
      'no fifth record or PID',
    );
  } finally {
    await stopAllProcesses(server);
    await Promise.allSettled(launches);
  }
  assert.deepEqual(fs.existsSync(processStateDir) ? fs.readdirSync(processStateDir) : [], []);
});

test('RC08-NEG-062: global process concurrency caps ten real children and never queues process eleven', async () => {
  const { server, roots, processStateDir } = makeProcessServer('neg062', 3);
  const launches = [];
  try {
    for (let index = 0; index < CONCURRENCY_LIMITS.maxGlobalRunning; index += 1) {
      const workspaceId = roots[index % roots.length].id;
      launches.push(
        startApprovedTest(
          server,
          { ...ACTOR, clientId: `neg062-${index}`, sessionId: `neg062-session-${index}` },
          { workspaceId, testPath: 'hold.test.js', maxDurationMs: 60_000 },
        ),
      );
    }
    assert.equal(await waitFor(() => server.processRegistry.countRunning() === 10), true);
    const before = server.processRegistry.listProcesses().length;
    const eleventh = await startApprovedTest(
      server,
      { ...ACTOR, clientId: 'neg062-eleventh', sessionId: 'neg062-session-eleventh' },
      { workspaceId: 'ws-1', testPath: 'hold.test.js', maxDurationMs: 60_000 },
    );
    assert.equal(eleventh.isError, true);
    assert.equal(responseBody(eleventh).code, 'RESOURCE_EXHAUSTED');
    assert.equal(server.processRegistry.countRunning(), 10);
    assert.equal(
      server.processRegistry.listProcesses().length,
      before,
      'no record or hidden queue',
    );
  } finally {
    await stopAllProcesses(server);
    await Promise.allSettled(launches);
  }
  assert.equal(server.processRegistry.countRunning(), 0);
  assert.deepEqual(fs.existsSync(processStateDir) ? fs.readdirSync(processStateDir) : [], []);
});

test('RC08-NEG-063: concurrent durable audit appends preserve one contiguous hash chain', async () => {
  const root = makeWorkspace('neg063');
  const parts = createDurableServer('neg063', [{ id: 'ws', path: root }]);
  await parts.server.start();
  const operationCount = 24;
  const results = await Promise.all(
    Array.from({ length: operationCount }, () =>
      parts.server.dispatchToolCall('read_file', { workspaceId: 'ws', path: 'README.md' }),
    ),
  );
  assert.equal(
    results.every((result) => result.isError !== true),
    true,
  );
  await parts.server.stop();
  const records = readJsonLines(path.join(parts.config.directory, ACTIVE_SEGMENT_FILENAME));
  assert.equal(records.length, operationCount * 2);
  assert.deepEqual(
    records.map((record) => record.sequenceNumber),
    Array.from({ length: 48 }, (_, i) => i + 1),
  );
  for (let index = 1; index < records.length; index += 1) {
    assert.equal(
      records[index].integrity.previousRecordHash,
      records[index - 1].integrity.recordHash,
    );
  }
  const verified = await verifyOfflineStore({
    directory: parts.config.directory,
    checkpointPublicKeyPath: parts.config.publicKeyPath,
  });
  assert.equal(verified.status, 'VERIFIED');
});

test('RC08-NEG-064: bounded TLS connect/disconnect storm releases gateway resources and remains healthy', async () => {
  const harness = await startRemote('neg064');
  try {
    const baseline = harness.server.remoteGateway.getStatus();
    assert.equal(baseline.activeAndServing, true);
    assert.equal(baseline.liveConnections, 0);
    assert.equal(baseline.inFlightHandshakes, 0);
    const secure = Array.from(
      { length: 8 },
      () =>
        new Promise((resolve) => {
          const socket = tls.connect({
            host: '127.0.0.1',
            port: harness.port,
            servername: PUBLIC_HOSTNAME,
            ca: [fs.readFileSync(pki.trustedCaCertPath)],
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
            minVersion: 'TLSv1.3',
          });
          socket.once('secureConnect', () => socket.destroy());
          socket.once('close', resolve);
          socket.once('error', () => resolve());
        }),
    );
    const incomplete = Array.from(
      { length: 8 },
      () =>
        new Promise((resolve) => {
          const socket = net.connect({ host: '127.0.0.1', port: harness.port }, () =>
            socket.write(Buffer.from([0x16, 0x03])),
          );
          socket.once('close', resolve);
          socket.once('error', () => resolve());
          setImmediate(() => socket.destroy());
        }),
    );
    await Promise.all([...secure, ...incomplete]);
    assert.equal(
      await waitFor(() => {
        const status = harness.server.remoteGateway.getStatus();
        return status.liveConnections === 0 && status.inFlightHandshakes === 0;
      }),
      true,
    );
    const session = await initializeRemote(harness.port);
    const healthy = await remoteRequest(harness.port, {
      headers: sessionHeaders(session),
      body: rpc(2),
    });
    assert.equal(healthy.status, 200);
    assert.equal(payloadOf(healthy.body).error, undefined);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-065: massive search set stops at the frozen 200-result ceiling and remains usable', async () => {
  const root = makeWorkspace('neg065');
  for (let index = 0; index < 260; index += 1) {
    fs.writeFileSync(
      path.join(root, `candidate-${String(index).padStart(3, '0')}.txt`),
      'needle\n',
    );
  }
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: root }],
    defaultWorkspaceId: 'ws',
  });
  const response = await server.dispatchToolCall('search_files', {
    workspaceId: 'ws',
    pattern: 'candidate-*.txt',
    maxResults: MAX_SEARCH_RESULTS,
  });
  const parsed = responseBody(response);
  assert.equal(parsed.matches.length, 200);
  assert.equal(parsed.totalMatches, 200);
  assert.ok(Buffer.byteLength(response.content[0].text) < 128 * 1024);
  const read = await server.dispatchToolCall('read_file', {
    workspaceId: 'ws',
    path: 'candidate-259.txt',
  });
  assert.equal(responseBody(read).content, 'needle\n');
});

test('RC08-NEG-066: concurrent continuous output floods remain independently and aggregately bounded', async (t) => {
  const { server, roots } = makeProcessServer('neg066');
  fs.writeFileSync(
    path.join(roots[0].path, 'flood.test.js'),
    "import test from 'node:test';\ntest('flood',async()=>{process.stdout.write('é'.repeat(700000));await new Promise(()=>{});});\n",
  );
  const launches = Array.from({ length: 3 }, (_, index) =>
    startApprovedTest(
      server,
      { ...ACTOR, sessionId: `neg066-${index}` },
      {
        workspaceId: 'ws-0',
        testPath: 'flood.test.js',
        maxDurationMs: 60_000,
      },
    ),
  );
  try {
    assert.equal(
      await waitFor(() => {
        const records = server.processRegistry.getActiveProcesses();
        return records.length === 3 && records.every((record) => record.truncated);
      }, 10_000),
      true,
    );
    const records = server.processRegistry.getActiveProcesses();
    let aggregate = 0;
    const retainedByProcess = [];
    for (const record of records) {
      const retained = record.totalStdoutBytes + record.totalStderrBytes;
      aggregate += retained;
      retainedByProcess.push(retained);
      assert.ok(retained >= MAX_PROCESS_BUFFER_BYTES - 3);
      assert.ok(retained <= MAX_PROCESS_BUFFER_BYTES);
      assert.equal(record.truncated, true);
      const output = server.processRegistry.getProcessOutput(
        record.processId,
        { maxBytes: MAX_OUTPUT_READ_BYTES },
        undefined,
        {
          clientId: record.actor.clientId,
          sessionId: record.actor.sessionId,
          workspaceId: record.workspaceId,
        },
      );
      assert.ok(
        Buffer.byteLength(output.stdoutChunk + output.stderrChunk) <= MAX_OUTPUT_READ_BYTES,
      );
    }
    assert.ok(aggregate >= 3 * (MAX_PROCESS_BUFFER_BYTES - 3));
    assert.ok(aggregate <= 3 * MAX_PROCESS_BUFFER_BYTES);
    t.diagnostic(`retained bytes=${retainedByProcess.join(',')} aggregate=${aggregate}`);
    assert.equal(
      server.processRegistry.countRunning(),
      3,
      'registry remains responsive during floods',
    );
  } finally {
    await stopAllProcesses(server);
    await Promise.allSettled(launches);
  }
});

test('RC08-NEG-067: approval pressure respects quotas and monotonic expiry reclaims count and review bytes', () => {
  let mono = 20_000_000_000n;
  let wall = 1_800_000_000_000;
  const manager = new ApprovalStateManager({
    getMonotonicTime: () => mono,
    getWallTime: () => wall,
  });
  const actor = {
    clientId: 'approval-pressure',
    clientType: 'agent',
    sessionId: 's',
    deviceId: 'd',
  };
  const binding = {
    actor,
    workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
    policyHash: 'a'.repeat(64),
  };
  const material = 'r'.repeat(1024);
  const ids = [];
  for (let index = 0; index < MAX_ACTIVE_APPROVALS_PER_ACTOR; index += 1) {
    ids.push(
      manager.createOrReusePending({
        toolName: 'arc_test',
        executionPayloadHash: crypto.createHash('sha256').update(String(index)).digest('hex'),
        binding,
        reviewMaterial: material,
      }).requestId,
    );
  }
  assert.equal(manager.listActive().length, 64);
  assert.ok(64 * 1024 < MAX_REVIEW_BYTES_PER_ACTOR);
  const duplicate = manager.createOrReusePending({
    toolName: 'arc_test',
    executionPayloadHash: crypto.createHash('sha256').update('0').digest('hex'),
    binding,
    reviewMaterial: material,
  });
  assert.equal(duplicate.requestId, ids[0]);
  assert.equal(manager.listActive().length, 64);
  assert.throws(
    () =>
      manager.createOrReusePending({
        toolName: 'arc_test',
        executionPayloadHash: 'f'.repeat(64),
        binding,
        reviewMaterial: material,
      }),
    (error) => error.code === 'RESOURCE_EXHAUSTED',
  );
  assert.ok(manager.listActive().length < MAX_ACTIVE_APPROVALS_GLOBAL);
  mono += BigInt(APPROVAL_TTL_SECONDS + 1) * 1_000_000_000n;
  wall += (APPROVAL_TTL_SECONDS + 1) * 1000;
  assert.equal(manager.purgeExpired(), 64);
  assert.equal(manager.listActive().length, 0);
  for (const id of ids) {
    const expired = manager.getRequest(id);
    assert.equal(expired.state, 'EXPIRED');
    assert.equal(expired.reviewMaterialBytes, 0);
  }
  const admitted = manager.createOrReusePending({
    toolName: 'arc_test',
    executionPayloadHash: 'e'.repeat(64),
    binding,
    reviewMaterial: material,
  });
  assert.equal(admitted.state, 'PENDING');
});

test('RC08-NEG-068: audit size pressure rotates at the unchanged threshold with verified continuity', async (t) => {
  const config = createAuditConfig(tempRoot, 'neg068');
  const runtime = await openAuditRuntime(config);
  let appended = 0;
  while (runtime.store.getLastRotation() === null && appended < 400) {
    const instant = new Date(1_800_000_000_000 + appended).toISOString();
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: instant,
      actor: { clientId: 'task6', clientType: 'agent', deviceId: 'd', sessionId: 's' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: { blob: 'x'.repeat(60_000) },
        payloadHash: 'a'.repeat(64),
      },
      policy: { decision: 'ALLOW', ruleId: 'task6', evaluationDurationMs: 0 },
      execution: { status: 'SUCCESS', startTime: instant, endTime: instant, durationMs: 0 },
    });
    appended += 1;
  }
  const rotation = runtime.store.getLastRotation();
  assert.ok(rotation);
  assert.equal(rotation.reason, 'SIZE_THRESHOLD');
  assert.ok(rotation.sourceByteLength >= SEGMENT_SIZE_THRESHOLD);
  assert.equal(rotation.boundary.sequenceStart, 1);
  assert.equal(rotation.boundary.sequenceEnd, appended);
  const nextInstant = new Date(1_800_000_100_000).toISOString();
  const next = await runtime.appendRecord({
    eventId: crypto.randomUUID(),
    timestamp: nextInstant,
    actor: { clientId: 'task6', clientType: 'agent', deviceId: 'd', sessionId: 's' },
    target: { workspaceId: 'ws', workspacePath: '' },
    invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
    policy: { decision: 'ALLOW', ruleId: 'task6', evaluationDurationMs: 0 },
    execution: { status: 'SUCCESS', startTime: nextInstant, endTime: nextInstant, durationMs: 0 },
  });
  assert.equal(next.sequenceNumber, appended + 1);
  assert.equal(next.integrity.previousRecordHash, rotation.boundary.terminalRecordHash);
  await runtime.close();
  const history = await verifyRetainedPrimaryHistory(config.directory, process.getuid());
  assert.equal(history.status, 'VERIFIED');
  assert.equal(history.recordCount, appended + 1);
  assert.ok(
    fs.statSync(path.join(config.directory, ACTIVE_SEGMENT_FILENAME)).size < SEGMENT_SIZE_THRESHOLD,
  );
  t.diagnostic(
    `threshold=${SEGMENT_SIZE_THRESHOLD} source=${rotation.sourceByteLength} archive=${rotation.archiveByteLength} boundary=1-${appended}`,
  );
  const offline = await verifyOfflineStore({
    directory: config.directory,
    checkpointPublicKeyPath: config.publicKeyPath,
  });
  assert.equal(offline.status, 'VERIFIED');
});

test('RC08-NEG-069: abrupt SSE socket destruction releases admission exactly once and permits recovery', async () => {
  const harness = await startRemote('neg069');
  try {
    const session = await initializeRemote(harness.port);
    const surface = harness.server.remoteGateway.mcpSurface;
    const limiter = harness.server.authenticatedRequestLimiter;
    const key = sessionRateLimitKey({
      deviceId: harness.device.deviceId,
      sessionId: session.sessionId,
    });
    const opened = await new Promise((resolve, reject) => {
      const request = https.request(
        {
          host: '127.0.0.1',
          port: harness.port,
          path: '/mcp',
          method: 'GET',
          servername: PUBLIC_HOSTNAME,
          ca: [fs.readFileSync(pki.trustedCaCertPath)],
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
          minVersion: 'TLSv1.3',
          headers: { Host: PUBLIC_HOSTNAME, ...sessionHeaders(session) },
        },
        (response) => resolve({ request, response }),
      );
      request.on('error', reject);
      request.end();
    });
    assert.equal(opened.response.statusCode, 200);
    assert.equal(await waitFor(() => surface.liveAdmissions.size === 1), true);
    assert.equal(limiter.getHolderCount(key), 1);
    assert.ok(surface.liveAdmissions.size <= MAX_OUTSTANDING_REQUESTS_PER_SESSION);
    opened.response.destroy();
    opened.request.destroy();
    assert.equal(
      await waitFor(() => surface.liveAdmissions.size === 0 && limiter.getHolderCount(key) === 0),
      true,
    );
    assert.equal(surface.getActiveSessionCount(), 1);
    const recovered = await remoteRequest(harness.port, {
      headers: sessionHeaders(session),
      body: rpc(3),
    });
    assert.equal(recovered.status, 200);
    assert.equal(payloadOf(recovered.body).error, undefined);
  } finally {
    await harness.server.stop();
  }
});

test('RC08-NEG-070: persisted process restart sweep reaps a matching orphan and safely skips PID reuse', async () => {
  if (process.platform !== 'linux') return;
  const stateDir = path.join(tempRoot, 'neg070-state');
  const child = spawn(
    process.execPath,
    ['-e', "process.on('SIGTERM',()=>{});process.stdout.write('READY');setInterval(()=>{},60000)"],
    {
      detached: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    },
  );
  assert.ok(child.pid);
  await new Promise((resolve, reject) => {
    child.stdout.once('data', resolve);
    child.once('error', reject);
  });
  const registry = new ProcessRegistry();
  registry.setProcessStateDir(stateDir);
  const record = registry.registerProcess({
    workspaceId: 'ws',
    actor: ACTOR,
    executable: process.execPath,
    sanitizedArgs: [],
    cwd: tempRoot,
    startedAt: new Date().toISOString(),
    state: 'RUNNING',
    timedOut: false,
  });
  assert.equal(registry.persistProcessState(record, child.pid), true);
  const persistedPath = path.join(stateDir, `${record.processId}.json`);
  const persisted = JSON.parse(fs.readFileSync(persistedPath, 'utf8'));
  assert.equal(persisted.pid, child.pid);
  assert.match(persisted.statStartTime, /^\d+$/);
  assert.equal(alive(child.pid), true);
  const report = await sweepOrphanProcesses(stateDir, { gracePeriodMs: 50 });
  assert.equal(report.swept.length, 1);
  assert.equal(report.swept[0].processId, record.processId);
  assert.equal(report.swept[0].terminationSignal, 'SIGKILL');
  assert.equal(await waitFor(() => !alive(child.pid)), true);
  assert.equal(fs.existsSync(persistedPath), false);
  assert.deepEqual((await sweepOrphanProcesses(stateDir, { gracePeriodMs: 0 })).swept, []);
  assert.equal(new ProcessRegistry().countRunning(), 0);

  const selfStat = getProcessStatInfo(process.pid);
  assert.ok(selfStat);
  const stalePath = path.join(stateDir, 'arc-proc-stale.json');
  fs.writeFileSync(
    stalePath,
    JSON.stringify({
      processId: 'arc-proc-stale',
      pid: process.pid,
      pgid: selfStat.pgrp,
      sid: selfStat.session,
      statStartTime: `${selfStat.starttime}9`,
      executable: process.execPath,
      startedAt: new Date().toISOString(),
      workspaceId: 'ws',
    }),
  );
  const stale = await sweepOrphanProcesses(stateDir, { gracePeriodMs: 0 });
  assert.equal(stale.swept.length, 0);
  assert.equal(stale.skipped.length, 1);
  assert.equal(alive(process.pid), true);
});

test('RC08-FLOW-14: ten concurrent read-only operations remain bounded, isolated, and durably ordered', async () => {
  const roots = ['alpha', 'beta'].map((name) => {
    const root = makeWorkspace(`flow014-${name}`);
    fs.writeFileSync(path.join(root, 'identity.txt'), `${name}-only\n`);
    return { id: name, path: root };
  });
  const parts = createDurableServer('flow014', roots);
  await parts.server.start();
  const calls = [];
  for (const root of roots) {
    calls.push(
      parts.server.dispatchToolCall('read_file', { workspaceId: root.id, path: 'identity.txt' }),
      parts.server.dispatchToolCall('read_file', { workspaceId: root.id, path: 'README.md' }),
      parts.server.dispatchToolCall('read_file', { workspaceId: root.id, path: 'identity.txt' }),
      parts.server.dispatchToolCall('list_directory', { workspaceId: root.id, path: '.' }),
      parts.server.dispatchToolCall('search_files', {
        workspaceId: root.id,
        pattern: 'identity.txt',
      }),
    );
  }
  const results = await Promise.race([
    Promise.all(calls),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('bounded flow deadline exceeded')), 5_000),
    ),
  ]);
  assert.equal(results.length, 10);
  assert.equal(
    results.every((result) => result.isError !== true),
    true,
  );
  const texts = results.map((result) => result.content[0].text);
  assert.equal(texts.filter((text) => text.includes('alpha-only')).length, 2);
  assert.equal(texts.filter((text) => text.includes('beta-only')).length, 2);
  for (const text of texts) {
    assert.equal(text.includes(roots[0].path), false);
    assert.equal(text.includes(roots[1].path), false);
  }
  assert.equal(parts.processRegistry.listProcesses().length, 0);
  assert.equal(parts.approvals.listActive().length, 0);
  await parts.server.stop();
  const records = readJsonLines(path.join(parts.config.directory, ACTIVE_SEGMENT_FILENAME));
  assert.deepEqual(
    records.map((record) => record.sequenceNumber),
    Array.from({ length: 20 }, (_, i) => i + 1),
  );
  const verified = await verifyOfflineStore({
    directory: parts.config.directory,
    checkpointPublicKeyPath: parts.config.publicKeyPath,
  });
  assert.equal(verified.status, 'VERIFIED');
});
