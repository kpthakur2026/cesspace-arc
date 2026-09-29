/**
 * RC-08 Task 5 — Process, Approval & Audit Adversarial Tests.
 *
 * Every test drives an existing production boundary. Test-only capabilities are
 * limited to the established RC-06 durable-write fault seam.
 */
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  ArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  createArcMcpServer,
} from '../apps/mcp-server/dist/index.js';
import { createProductionDeterministicRegistry } from '../apps/mcp-server/dist/composite-framework.js';
import {
  ACTIVE_SEGMENT_FILENAME,
  CHECKPOINT_FILENAME,
  AuditLogger,
  openAuditRuntime,
  verifyActiveStream,
  verifyOfflineStore,
} from '../packages/audit/dist/index.js';
import { createTestAuditRuntime } from '../packages/audit/dist/internal/runtime-testing.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  getApprovalFailureReason,
} from '../packages/policy/dist/index.js';
import {
  MAX_PROCESS_BUFFER_BYTES,
  MAX_OUTPUT_READ_BYTES,
  ProcessRegistry,
  getProcessStatInfo,
  sweepOrphanProcesses,
} from '../packages/processes/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-task5-'));
const resources = [];
const ACTOR_A = {
  clientId: 'rc08-task5-a',
  clientType: 'agent',
  sessionId: 'rc08-task5-session-a',
  deviceId: 'rc08-task5-device-a',
  authenticated: true,
};

after(async () => {
  for (const resource of resources.reverse()) {
    try {
      await resource.stop?.();
      await resource.close?.();
    } catch {
      // Best-effort fixture cleanup only.
    }
  }
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

function workspace(label) {
  const root = path.join(tempRoot, label);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'README.md'), '# Task 5\n');
  return root;
}

function body(response) {
  return JSON.parse(response.content[0].text);
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForDead(pid, attempts = 40) {
  for (let index = 0; index < attempts; index += 1) {
    if (!alive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return !alive(pid);
}

class FilesystemSpy extends FilesystemSubsystem {
  constructor() {
    super();
    this.reads = 0;
    this.mutations = 0;
  }
  async readFile(root, request) {
    this.reads += 1;
    return super.readFile(root, request);
  }
  async createFile(root, request) {
    this.mutations += 1;
    return super.createFile(root, request);
  }
}

class DurabilityServer extends ArcMcpServer {
  constructor(parts, runtimeOptions) {
    super(
      parts.registry,
      parts.kernel,
      parts.audit,
      parts.filesystem,
      parts.git,
      parts.config,
      parts.terminal,
      parts.processRegistry,
      parts.approvals,
    );
    this.runtimeOptions = runtimeOptions;
  }
  async openAuditRuntimeForProcess(config) {
    return this.runtimeOptions === undefined
      ? super.openAuditRuntimeForProcess(config)
      : createTestAuditRuntime(config, this.runtimeOptions);
  }
}

function makeServer(label, { durable = false, runtimeOptions } = {}) {
  const root = workspace(label);
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', root);
  const processRegistry = new ProcessRegistry();
  const filesystem = new FilesystemSpy();
  const approvals = new ApprovalStateManager();
  const parts = {
    registry,
    processRegistry,
    kernel: new SecurityKernel(registry, processRegistry),
    audit: new AuditLogger(),
    filesystem,
    git: new GitSubsystem(),
    terminal: new ControlledProcessRunner(processRegistry),
    approvals,
    config: {
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: root }],
      defaultWorkspaceId: 'ws',
      ...(durable ? { audit: createAuditConfig(tempRoot, `task5-${label}`) } : {}),
    },
  };
  const server = new DurabilityServer(parts, runtimeOptions);
  return { ...parts, server, root };
}

async function requestApproval(parts, params, actor = ACTOR_A) {
  const first = await parts.server.dispatchToolCall('create_file', params, actor);
  const parsed = body(first);
  assert.equal(parsed.code, 'APPROVAL_REQUIRED');
  const grant = parts.approvals.approve(parsed.details.approvalRequestId);
  return { requestId: parsed.details.approvalRequestId, token: grant.token };
}

function internalRedemption(parts, requestId, token, overrides = {}) {
  const snapshot = parts.approvals.getRequest(requestId);
  assert.ok(snapshot);
  return {
    requestId,
    token,
    executionPayloadHash: snapshot.executionPayloadHash,
    actor: snapshot.binding.actor,
    workspace: snapshot.binding.workspace,
    policyHash: snapshot.binding.policyHash,
    ...overrides,
  };
}

function makeArcTestServer(label) {
  const root = workspace(label);
  const processStateDir = path.join(tempRoot, `${label}-process-state`);
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: root }],
    defaultWorkspaceId: 'ws',
    processStateDir,
  });
  return { server, root, processStateDir };
}

async function approvedArcTest(server, args) {
  const first = await server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', args);
  const firstBody = body(first);
  assert.equal(firstBody.code, 'APPROVAL_REQUIRED');
  const grant = server.approvalStateManager.approve(firstBody.details.approvalRequestId);
  return server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', {
    ...args,
    _arcApproval: { requestId: firstBody.details.approvalRequestId, token: grant.token },
  });
}

function recordCandidate(index, extras = {}) {
  const instant = new Date(1_800_000_000_000 + index).toISOString();
  return {
    eventId: crypto.randomUUID(),
    timestamp: instant,
    actor: {
      clientId: 'task5-client',
      clientType: 'agent',
      deviceId: 'task5-device',
      sessionId: 'task5-session',
    },
    target: { workspaceId: 'ws', workspacePath: '' },
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { path: '[WORKSPACE]/README.md' },
      payloadHash: crypto.createHash('sha256').update(String(index)).digest('hex'),
    },
    policy: { decision: 'ALLOW', ruleId: 'task5', evaluationDurationMs: 0 },
    execution: {
      status: 'SUCCESS',
      startTime: instant,
      endTime: instant,
      durationMs: 0,
    },
    ...extras,
  };
}

test('RC08-NEG-049: shell-shaped argv cannot trigger shell expansion or a second child', async () => {
  const parts = makeServer('neg049');
  const marker = path.join(tempRoot, 'neg049-marker');
  for (const argument of [
    `--version;touch ${marker}`,
    `--version|touch ${marker}`,
    `--version&touch ${marker}`,
    `$(touch ${marker})`,
    `\`touch ${marker}\``,
    `--version>${marker}`,
  ]) {
    const response = await parts.server.dispatchToolCall('run_command', {
      executable: 'node',
      args: [argument],
    });
    assert.equal(response.isError, true);
    assert.match(body(response).code, /^(POLICY_DENIED|INVALID_REQUEST_SCHEMA)$/);
  }
  assert.equal(parts.processRegistry.listProcesses().length, 0, 'no shell or child was spawned');
  assert.equal(fs.existsSync(marker), false);
});

test('RC08-NEG-050: executable paths and traversal never reach the trusted spawn boundary', async () => {
  const parts = makeServer('neg050');
  const attacker = path.join(parts.root, 'node');
  fs.writeFileSync(attacker, '#!/bin/sh\nexit 99\n', { mode: 0o755 });
  for (const executable of ['../../bin/sh', '../node', './node', 'foo/bar', 'foo\\bar', attacker]) {
    const response = await parts.server.dispatchToolCall('run_command', {
      executable,
      args: ['--version'],
    });
    assert.equal(response.isError, true);
    assert.match(body(response).code, /^(POLICY_DENIED|INVALID_REQUEST_SCHEMA|FORBIDDEN_COMMAND)$/);
    assert.equal(response.content[0].text.includes(tempRoot), false, 'host path must be sanitized');
  }
  assert.equal(parts.processRegistry.listProcesses().length, 0);
});

test('RC08-NEG-051: PATH, HOME, and runtime environment poisoning cannot select a fake binary', async () => {
  const parts = makeServer('neg051');
  const poison = path.join(tempRoot, 'poison-bin');
  const marker = path.join(tempRoot, 'neg051-marker');
  fs.mkdirSync(poison);
  fs.writeFileSync(path.join(poison, 'node'), `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
  for (const env of [
    { PATH: poison },
    { HOME: poison },
    { NODE_OPTIONS: `--require=${path.join(poison, 'inject.js')}` },
  ]) {
    const response = await parts.server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
      env,
    });
    assert.equal(response.isError, true);
    assert.match(body(response).code, /^(POLICY_DENIED|INVALID_REQUEST_SCHEMA)$/);
  }
  assert.equal(fs.existsSync(marker), false);
  assert.equal(parts.processRegistry.listProcesses().length, 0);
});

test('RC08-NEG-052: stubborn child records ordered SIGTERM then SIGKILL and leaves terminal state', async () => {
  const { server, root, processStateDir } = makeArcTestServer('neg052');
  const events = [];
  server.processRegistry.registerLifecycleSink({ onProcessEvent: (event) => events.push(event) });
  fs.writeFileSync(
    path.join(root, 'stubborn.test.js'),
    `import test from 'node:test';\nprocess.on('SIGTERM',()=>{});\ntest('hang',async()=>new Promise(()=>{}));\n`,
  );
  const response = await approvedArcTest(server, {
    testPath: 'stubborn.test.js',
    maxDurationMs: 1200,
  });
  const parsed = body(response);
  assert.equal(parsed.status, 'TIMED_OUT');
  const record = server.processRegistry.getProcess(parsed.processId);
  assert.ok(record?._pid);
  assert.equal(await waitForDead(record._pid), true);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const types = events
    .filter((event) => event.processId === parsed.processId)
    .map((e) => e.eventType);
  assert.ok(types.includes('PROCESS_TERMINATION_REQUESTED') || types.includes('PROCESS_TIMEOUT'));
  assert.ok(types.indexOf('PROCESS_SIGTERM_SENT') >= 0);
  assert.ok(types.indexOf('PROCESS_SIGKILL_ESCALATED') > types.indexOf('PROCESS_SIGTERM_SENT'));
  assert.match(record.state, /^(TIMED_OUT|TERMINATED)$/);
  assert.equal(record._killTimer, undefined);
  assert.deepEqual(fs.existsSync(processStateDir) ? fs.readdirSync(processStateDir) : [], []);
});

test('RC08-NEG-053: process-group cleanup reaps a stubborn descendant and PID reuse is skipped', async () => {
  const { server, root, processStateDir } = makeArcTestServer('neg053');
  fs.writeFileSync(
    path.join(root, 'tree.test.js'),
    `import test from 'node:test';\nimport {spawn} from 'node:child_process';\n` +
      `test('tree',async()=>{const c=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});process.stdout.write('DESC:'+process.pid+'\\\\n');setInterval(()=>{},60000)"],{stdio:['ignore','inherit','ignore']});await new Promise(()=>{});});\n`,
  );
  const response = await approvedArcTest(server, { testPath: 'tree.test.js', maxDurationMs: 1200 });
  const parsed = body(response);
  assert.equal(parsed.status, 'TIMED_OUT');
  const descendantMatch = /DESC:(\d+)/.exec(parsed.outputExcerpt);
  assert.ok(descendantMatch, 'descendant PID must be observed before cleanup');
  const descendantPid = Number(descendantMatch[1]);
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal(await waitForDead(descendantPid), true, 'no descendant may survive escalation');
  assert.deepEqual(fs.existsSync(processStateDir) ? fs.readdirSync(processStateDir) : [], []);

  if (process.platform === 'linux') {
    const stateDir = path.join(tempRoot, 'neg053-reused-state');
    fs.mkdirSync(stateDir);
    const stat = getProcessStatInfo(process.pid);
    assert.ok(stat);
    fs.writeFileSync(
      path.join(stateDir, 'arc-proc-reused.json'),
      JSON.stringify({
        processId: 'arc-proc-reused',
        pid: process.pid,
        pgid: stat.pgrp,
        sid: stat.session,
        statStartTime: `${stat.starttime}-stale`,
        executable: process.execPath,
        startedAt: new Date().toISOString(),
        workspaceId: 'ws',
      }),
    );
    const report = await sweepOrphanProcesses(stateDir, { gracePeriodMs: 0 });
    assert.equal(report.swept.length, 0);
    assert.equal(report.skipped.length, 1);
    assert.match(report.skipped[0].reason, /PID recycled|start time mismatch/i);
    assert.equal(alive(process.pid), true, 'unrelated reused PID must never receive a signal');
  }
});

test('RC08-NEG-054: oversized process output is retained at 512 KiB and returned at 128 KiB', async () => {
  const { server, root } = makeArcTestServer('neg054');
  fs.writeFileSync(
    path.join(root, 'volume.test.js'),
    `import test from 'node:test';\n` +
      `test('volume',()=>{const token='ghp_'+'x'.repeat(36);process.stdout.write(token+'\\n'+'é'.repeat(700000));});\n`,
  );
  const response = await approvedArcTest(server, { testPath: 'volume.test.js' });
  const parsed = body(response);
  const record = server.processRegistry.getProcess(parsed.processId);
  assert.ok(record);
  assert.ok(record.totalStdoutBytes + record.totalStderrBytes <= MAX_PROCESS_BUFFER_BYTES);
  assert.ok(record.totalStdoutBytes + record.totalStderrBytes >= MAX_PROCESS_BUFFER_BYTES - 3);
  assert.equal(record.truncated, true);
  const output = server.processRegistry.getProcessOutput(
    parsed.processId,
    { maxBytes: MAX_OUTPUT_READ_BYTES },
    undefined,
    { clientId: ACTOR_A.clientId, sessionId: ACTOR_A.sessionId, workspaceId: 'ws' },
  );
  const returned = output.stdoutChunk + output.stderrChunk;
  assert.ok(Buffer.byteLength(returned, 'utf8') <= MAX_OUTPUT_READ_BYTES);
  assert.equal(Buffer.from(returned, 'utf8').toString('utf8'), returned);
  assert.equal(returned.includes('ghp_' + 'x'.repeat(36)), false);
  assert.match(record.state, /^(COMPLETED|FAILED)$/);

  // Deterministically force the final byte ceiling through the middle of "é".
  // The retained count is exact and demonstrates the production cap discards
  // the incomplete final code point rather than returning replacement text.
  const boundaryRegistry = new ProcessRegistry();
  const boundaryRecord = boundaryRegistry.registerProcess({
    workspaceId: 'ws',
    actor: ACTOR_A,
    executable: 'node',
    sanitizedArgs: ['--version'],
    cwd: root,
    startedAt: new Date().toISOString(),
    state: 'RUNNING',
    timedOut: false,
  });
  boundaryRegistry.appendOutput(
    boundaryRecord.processId,
    'stdout',
    Buffer.from('x'.repeat(41) + 'é'.repeat(700_000), 'utf8'),
  );
  assert.equal(boundaryRecord.totalStdoutBytes, MAX_PROCESS_BUFFER_BYTES - 1);
  assert.doesNotThrow(() =>
    new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(boundaryRecord._stdoutChunks)),
  );
});

test('RC08-NEG-055: actor-bound approval rejects another actor with generic external semantics', async () => {
  const parts = makeServer('neg055');
  const params = { path: 'actor.txt', content: 'owner-only', workspaceId: 'ws' };
  const grant = await requestApproval(parts, params);
  const actorB = { ...ACTOR_A, clientId: 'rc08-task5-b' };
  const response = await parts.server.dispatchToolCall(
    'create_file',
    { ...params, _arcApproval: grant },
    actorB,
  );
  assert.equal(body(response).code, 'APPROVAL_REJECTED');
  assert.equal(parts.filesystem.mutations, 0);
  assert.equal(fs.existsSync(path.join(parts.root, params.path)), false);
  assert.equal(parts.approvals.getRequest(grant.requestId).state, 'APPROVED');
  assert.throws(
    () =>
      parts.approvals.redeemAndConsume(
        internalRedemption(parts, grant.requestId, grant.token, {
          actor: {
            ...parts.approvals.getRequest(grant.requestId).binding.actor,
            clientId: actorB.clientId,
          },
        }),
      ),
    (error) => getApprovalFailureReason(error) === 'ACTOR_BINDING_MISMATCH',
  );
});

test('RC08-NEG-056: changed business parameters fail plan binding before privileged execution', async () => {
  const { server, root } = makeArcTestServer('neg056');
  fs.writeFileSync(
    path.join(root, 'plan.test.js'),
    "import test from 'node:test';test('ok',()=>{});\n",
  );
  const params = { testPath: 'plan.test.js', maxDurationMs: 1000 };
  const first = await server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', params);
  const requestId = body(first).details.approvalRequestId;
  const token = server.approvalStateManager.approve(requestId).token;
  const snapshot = server.approvalStateManager.getRequest(requestId);
  assert.match(snapshot.reviewSummary.planHash, /^[0-9a-f]{64}$/);
  const response = await server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', {
    ...params,
    maxDurationMs: 1100,
    _arcApproval: { requestId, token },
  });
  assert.equal(body(response).code, 'APPROVAL_REJECTED');
  assert.equal(server.processRegistry.listProcesses().length, 0);
  assert.equal(server.approvalStateManager.getRequest(requestId).state, 'APPROVED');
  assert.throws(
    () =>
      server.approvalStateManager.redeemAndConsume(
        internalRedemption({ approvals: server.approvalStateManager }, requestId, token, {
          executionPayloadHash: '0'.repeat(64),
        }),
      ),
    (error) => getApprovalFailureReason(error) === 'PAYLOAD_BINDING_MISMATCH',
  );
});

test('RC08-NEG-057: consumed approval token executes once and replay cannot duplicate lifecycle', async () => {
  const parts = makeServer('neg057', { durable: true });
  await parts.server.start();
  resources.push(parts.server);
  const params = { path: 'once.txt', content: 'exactly-once', workspaceId: 'ws' };
  const grant = await requestApproval(parts, params);
  const first = await parts.server.dispatchToolCall(
    'create_file',
    { ...params, _arcApproval: grant },
    ACTOR_A,
  );
  assert.equal(first.isError, undefined);
  assert.equal(parts.filesystem.mutations, 1);
  assert.equal(parts.approvals.getRequest(grant.requestId).state, 'CONSUMED');
  const replay = await parts.server.dispatchToolCall(
    'create_file',
    { ...params, _arcApproval: grant },
    ACTOR_A,
  );
  assert.equal(body(replay).code, 'APPROVAL_REJECTED');
  assert.equal(parts.filesystem.mutations, 1, 'replay must execute privileged work zero times');
  assert.throws(
    () => parts.approvals.redeemAndConsume(internalRedemption(parts, grant.requestId, grant.token)),
    (error) => getApprovalFailureReason(error) === 'ALREADY_CONSUMED',
  );
  assert.equal(fs.readFileSync(path.join(parts.root, params.path), 'utf8'), params.content);
  const ledger = fs
    .readFileSync(path.join(parts.config.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8')
    .trim()
    .split('\n')
    .map(JSON.parse)
    .filter((record) => record.invocation.toolName === 'create_file');
  assert.deepEqual(
    ledger
      .map((record) => record.lifecycle?.phase)
      .filter((phase) => phase === 'STARTED' || phase === 'COMPLETED'),
    ['STARTED', 'COMPLETED'],
  );
});

test('RC08-NEG-058: persisted audit field tampering breaks the authoritative hash-chain verifier', async () => {
  const config = createAuditConfig(tempRoot, 'task5-neg058');
  const runtime = await openAuditRuntime(config);
  await runtime.appendRecord(recordCandidate(1));
  await runtime.appendRecord(recordCandidate(2));
  await runtime.close();
  const active = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
  const lines = fs.readFileSync(active, 'utf8').trimEnd().split('\n');
  const first = JSON.parse(lines[0]);
  first.invocation.toolName = 'tampered_without_rehash';
  lines[0] = JSON.stringify(first);
  fs.writeFileSync(active, `${lines.join('\n')}\n`, { mode: 0o600 });
  assert.throws(
    () => verifyActiveStream(active, process.getuid()),
    (error) => {
      assert.equal(error.code, 'AUDIT_CORRUPTION_DETECTED');
      assert.equal(error.message.includes(tempRoot), false);
      assert.equal(error.message.includes('task5-session'), false);
      return true;
    },
  );
});

test('RC08-NEG-059: partial persistent audit line is detected as a recoverable torn tail, not verified clean', async () => {
  const config = createAuditConfig(tempRoot, 'task5-neg059');
  const runtime = await openAuditRuntime(config);
  await runtime.appendRecord(recordCandidate(1));
  await runtime.appendRecord(recordCandidate(2));
  await runtime.close();
  const active = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
  const original = fs.readFileSync(active);
  fs.truncateSync(active, original.length - 19);
  const verification = verifyActiveStream(active, process.getuid());
  assert.equal(verification.status, 'RECOVERABLE_TORN_ACTIVE_TAIL');
  assert.ok(verification.tornBytes.length > 0);
  assert.ok(verification.lastVerifiedByteOffset < original.length);
  assert.notEqual(verification.status, 'VERIFIED');
});

test('RC08-NEG-060: failed durable STARTED append blocks execution and latches fail-closed ordering', async () => {
  const parts = makeServer('neg060', {
    durable: true,
    runtimeOptions: { hooks: { failAppendPhase: 'STARTED' } },
  });
  await parts.server.start();
  resources.push(parts.server);
  const response = await parts.server.dispatchToolCall('read_file', {
    path: 'README.md',
    workspaceId: 'ws',
  });
  assert.equal(body(response).code, 'INTERNAL_ERROR');
  assert.equal(parts.filesystem.reads, 0, 'STARTED persistence precedes subsystem execution');
  assert.equal(parts.processRegistry.listProcesses().length, 0);
  const active = path.join(parts.config.audit.directory, ACTIVE_SEGMENT_FILENAME);
  const records = fs.readFileSync(active, 'utf8').trim();
  assert.equal(records.includes('"phase":"STARTED"'), false);
  assert.equal(records.includes('"phase":"FAILED"'), false);
  const second = await parts.server.dispatchToolCall('read_file', {
    path: 'README.md',
    workspaceId: 'ws',
  });
  assert.equal(body(second).code, 'INTERNAL_ERROR');
  assert.equal(parts.filesystem.reads, 0);
});

test('RC08-FLOW-11: public controlled process supervision captures status, output, and clean completion', async () => {
  const parts = makeServer('flow011');
  const events = [];
  parts.processRegistry.registerLifecycleSink({ onProcessEvent: (event) => events.push(event) });
  const response = await parts.server.dispatchToolCall(
    'run_command',
    { executable: 'node', args: ['--version'] },
    ACTOR_A,
  );
  assert.equal(response.isError, undefined);
  const result = body(response);
  assert.match(result.processId, /^arc-proc-/);
  assert.equal(result.state, 'COMPLETED');
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.match(result.stdout, /^v\d+/);
  const status = await parts.server.dispatchToolCall(
    'process_status',
    { processId: result.processId },
    ACTOR_A,
  );
  const output = await parts.server.dispatchToolCall(
    'process_output',
    { processId: result.processId },
    ACTOR_A,
  );
  assert.equal(body(status).state, 'COMPLETED');
  assert.match(body(output).stdoutChunk, /^v\d+/);
  const eventTypes = events
    .filter((event) => event.processId === result.processId)
    .map((e) => e.eventType);
  assert.deepEqual(eventTypes.slice(0, 2), ['PROCESS_SPAWN_SUCCEEDED', 'PROCESS_EXITED']);
  assert.equal(parts.processRegistry.getProcess(result.processId)._killTimer, undefined);
});

test('RC08-FLOW-12: interactive approval redemption executes once with complete durable lifecycle', async () => {
  const root = workspace('flow012');
  fs.writeFileSync(
    path.join(root, 'approved.test.js'),
    "import test from 'node:test';test('approved',()=>{});\n",
  );
  const audit = createAuditConfig(tempRoot, 'task5-flow012');
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: root }],
    defaultWorkspaceId: 'ws',
    audit,
  });
  await server.start();
  resources.push(server);
  const params = { testPath: 'approved.test.js', maxDurationMs: 5000 };
  const first = await server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', params);
  assert.equal(body(first).code, 'APPROVAL_REQUIRED');
  const requestId = body(first).details.approvalRequestId;
  const token = server.approvalStateManager.approve(requestId).token;
  const grant = { requestId, token };
  assert.equal(Buffer.byteLength(grant.token, 'utf8') >= 32, true);
  const snapshot = server.approvalStateManager.getRequest(grant.requestId);
  assert.equal(snapshot.toolName, 'arc_test');
  assert.equal(snapshot.binding.workspace.workspaceId, 'ws');
  assert.equal(snapshot.binding.actor.clientId, ACTOR_A.clientId);
  assert.match(snapshot.binding.policyHash, /^[0-9a-f]{64}$/);
  assert.match(snapshot.executionPayloadHash, /^[0-9a-f]{64}$/);
  assert.match(snapshot.reviewSummary.planHash, /^[0-9a-f]{64}$/);
  const response = await server.executeAuthenticatedToolCall(ACTOR_A, 'arc_test', {
    ...params,
    _arcApproval: grant,
  });
  assert.equal(response.isError, undefined);
  assert.equal(body(response).status, 'PASSED');
  assert.equal(server.processRegistry.listProcesses().length, 1);
  const ledger = fs.readFileSync(path.join(audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8');
  assert.equal(ledger.includes(grant.token), false, 'raw approval token must never be durable');
  const operationRecords = ledger
    .trim()
    .split('\n')
    .map(JSON.parse)
    .filter((record) => record.invocation.toolName === 'arc_test');
  assert.deepEqual(
    operationRecords
      .map((record) => record.lifecycle?.phase)
      .filter((phase) => phase === 'STARTED' || phase === 'COMPLETED'),
    ['STARTED', 'COMPLETED'],
  );
});

test('RC08-FLOW-13: durable ledger rotates, checkpoints, verifies, and reopens from disk', async () => {
  const config = createAuditConfig(tempRoot, 'task5-flow013');
  const runtime = await openAuditRuntime(config);
  const appended = [];
  for (let index = 1; index <= 4; index += 1) {
    appended.push(await runtime.appendRecord(recordCandidate(index)));
  }
  assert.deepEqual(
    appended.map((record) => record.sequenceNumber),
    [1, 2, 3, 4],
  );
  for (let index = 1; index < appended.length; index += 1) {
    assert.equal(
      appended[index].integrity.previousRecordHash,
      appended[index - 1].integrity.recordHash,
    );
  }
  await runtime.store.rotateNow('SIZE_THRESHOLD');
  await runtime.close();
  assert.equal(fs.existsSync(path.join(config.directory, CHECKPOINT_FILENAME)), true);
  const verified = await verifyOfflineStore({
    directory: config.directory,
    checkpointPublicKeyPath: config.publicKeyPath,
  });
  assert.equal(verified.status, 'VERIFIED');
  const diskText = fs
    .readdirSync(config.directory)
    .filter((name) => name.endsWith('.jsonl'))
    .map((name) => fs.readFileSync(path.join(config.directory, name), 'utf8'))
    .join('\n');
  assert.equal(diskText.includes('task5-session'), false, 'central redaction removes session IDs');
  assert.equal(diskText.includes(tempRoot), false, 'absolute host path must not enter the ledger');
  const reopened = await openAuditRuntime(config);
  resources.push(reopened);
  assert.equal(reopened.getNextSequence(), 5);
  assert.equal(reopened.getLastCheckpointSequence(), 4);

  assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
  assert.equal(createProductionDeterministicRegistry().listEntryIds().length, 5);
});
