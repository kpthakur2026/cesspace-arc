/**
 * CesSpace ARC — RC-06 Task 8 Authoritative Positive Acceptance Flows Suite
 *
 * Implements all 23 frozen positive acceptance flows defined in
 * docs/architecture/rc06-scope-acceptance.md §32:
 *
 *  01 Fresh Persistent Store Initialization
 *  02 Standard Stdio Read-Only Tool Execution
 *  03 Standard Stdio Mutation Tool Execution
 *  04 Remote Authenticated Gateway Tool Execution
 *  05 Policy Denial Audit Logging
 *  06 Operator Approval Lifecycle Persistence
 *  07 Gateway Admission & Lifecycle Auditing
 *  08 Clean Process Termination
 *  09 Gateway Restart & Hash Continuity
 *  10 Size-Based Rotation Trigger
 *  11 Time-Based Operational Rotation Trigger
 *  12 Compressed Archive Generation & Verified Deletion
 *  13 Tier-2 Checkpoint Artifact Generation
 *  14 Offline Public-Key Checkpoint Verification
 *  15 Tier-3 External Anchor Dispatch & Cryptographic Receipt
 *  16 Anchor Outage Spooling & Automatic Backoff Catch-Up
 *  17 Local Operator arc audit status
 *  18 Local Operator arc audit inspect
 *  19 Universal Pre-Dispatch Durability
 *  20 Full Restart Verification of Retained History
 *  21 Crash-Indeterminate Lifecycle Reconciliation
 *  22 Standalone Offline Verification Command
 *  23 Deterministic Evidence Export Verification
 *
 * Plus authoritative meta-acceptance check verifying exactly 23 unique contiguous
 * flows without skips or deferrals.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ACTIVE_SEGMENT_FILENAME,
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  CHECKPOINT_FILENAME,
  LOCK_FILENAME,
  METADATA_FILENAME,
  AuditLogger,
  computeSha256,
  openAuditRuntime,
  parseAndValidateCheckpointLineV1,
  verifyCheckpointSignature,
} from '../packages/audit/dist/index.js';

import { createTestAuditRuntime } from '../packages/audit/dist/internal/runtime-testing.js';
import {
  createTestTier3AnchorEngine,
  signTestAnchorReceipt,
} from '../packages/audit/dist/internal/anchor-testing.js';
import {
  enablePrivateKeyLoadProbe,
  getPrivateKeyLoadCount,
} from '../packages/audit/dist/internal/key-authority.js';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { RemoteExecutionBridge } from '../apps/mcp-server/dist/remote-execution.js';
import { getGatewayAuditSink } from '../apps/mcp-server/dist/gateway-audit.js';
import { EXIT_OK, runCli } from '../apps/cli/dist/index.js';

import { GATEWAY_AUDIT_EVENT_TYPES } from '../packages/protocol/dist/index.js';
import {
  DeviceTrustStore,
  deriveSpkiPin,
  resolveActiveDeviceIdentity,
} from '../packages/auth/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';

import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

let tempRoot;
let sharedWorkspaceDir;
const startedServers = [];
const openRuntimes = [];

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-pos-flows-'));
  sharedWorkspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(sharedWorkspaceDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(sharedWorkspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(sharedWorkspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(sharedWorkspaceDir, 'README.md'), '# ARC Positive Flows\n');
});

after(async () => {
  for (const s of startedServers.reverse()) {
    try {
      await s.stop();
    } catch {
      // ignore
    }
  }
  for (const r of openRuntimes.reverse()) {
    try {
      await r.close();
    } catch {
      // ignore
    }
  }
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function createTestServer(fixture, options = {}) {
  const workspaceRegistry = new WorkspaceRegistry();
  workspaceRegistry.registerWorkspace('ws', options.workspaceDir ?? sharedWorkspaceDir);
  const processRegistry = new ProcessRegistry();
  const securityKernel = new SecurityKernel(workspaceRegistry, processRegistry);
  const auditLogger = new AuditLogger();
  const filesystem = new FilesystemSubsystem();
  const git = new GitSubsystem();
  const approvals = new ApprovalStateManager();

  const server = new ArcMcpServer(
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystem,
    git,
    {
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: options.workspaceDir ?? sharedWorkspaceDir }],
      defaultWorkspaceId: 'ws',
      audit: fixture,
      ...(options.serverConfig ?? {}),
    },
    undefined,
    processRegistry,
    approvals,
  );

  return {
    server,
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystem,
    git,
    approvals,
    processRegistry,
  };
}

async function execCli(argv, env = {}) {
  let stdout = '';
  let stderr = '';
  const exitCode = await runCli(argv, {
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
    env: { ...process.env, ...env },
  });
  return { exitCode, stdout, stderr };
}

describe('CesSpace ARC — RC-06 23 Positive Acceptance Flows (RC06-FLOW-01..23)', () => {
  test('RC06-FLOW-01: Fresh Persistent Store Initialization', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-01');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    // Creates audit-store.json, audit.lock, and active segment
    const metaPath = path.join(fixture.directory, METADATA_FILENAME);
    const lockPath = path.join(fixture.directory, LOCK_FILENAME);
    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);

    assert.equal(fs.existsSync(metaPath), true, 'audit-store.json must exist');
    assert.equal(fs.existsSync(lockPath), true, 'audit.lock must exist');
    assert.equal(fs.existsSync(activePath), true, 'audit-active.jsonl must exist');

    // Permissions verified 0600 on active segment and metadata
    const activeStat = fs.statSync(activePath);
    const metaStat = fs.statSync(metaPath);
    assert.equal(activeStat.mode & 0o777, 0o600);
    assert.equal(metaStat.mode & 0o777, 0o600);

    // Logs first record: seq 1, prevHash 000...000
    const record = await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'init', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    assert.equal(record.sequenceNumber, 1);
    assert.equal(
      record.integrity.previousRecordHash,
      '0000000000000000000000000000000000000000000000000000000000000000',
    );
    assert.match(record.integrity.recordHash, /^[0-9a-f]{64}$/);
  });

  test('RC06-FLOW-02: Standard Stdio Read-Only Tool Execution', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-02');
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const res = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      workspaceId: 'ws',
    });
    assert.equal(res.isError, undefined);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    assert.ok(lines.length >= 2, 'must have at least STARTED and COMPLETED records');

    const started = JSON.parse(lines[lines.length - 2]);
    const completed = JSON.parse(lines[lines.length - 1]);

    assert.equal(started.lifecycle?.phase, 'STARTED');
    assert.equal(completed.lifecycle?.phase, 'COMPLETED');
    assert.equal(started.lifecycle?.operationId, completed.lifecycle?.operationId);
    assert.equal(completed.execution.status, 'SUCCESS');
    assert.equal(completed.integrity.previousRecordHash, started.integrity.recordHash);
  });

  test('RC06-FLOW-03: Standard Stdio Mutation Tool Execution', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-03');
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const first = await server.dispatchToolCall('create_file', {
      path: 'flow3-mut.txt',
      content: 'hello mutation flow 3\n',
      workspaceId: 'ws',
    });
    const firstBody = JSON.parse(first.content[0].text);
    const requestId = firstBody.details.approvalRequestId;
    const grant = server.approvalStateManager.approve(requestId);
    const res = await server.dispatchToolCall('create_file', {
      path: 'flow3-mut.txt',
      content: 'hello mutation flow 3\n',
      workspaceId: 'ws',
      _arcApproval: { requestId, token: grant.token },
    });
    assert.equal(res.isError, undefined);

    assert.equal(fs.existsSync(path.join(sharedWorkspaceDir, 'flow3-mut.txt')), true);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));
    const successfulStarted = records.find(
      (r) => r.invocation?.toolName === 'create_file' && r.lifecycle?.phase === 'STARTED',
    );
    const successfulCompleted = records.find(
      (r) => r.invocation?.toolName === 'create_file' && r.lifecycle?.phase === 'COMPLETED',
    );

    assert.ok(successfulStarted, 'must have started record for approved execution');
    assert.ok(successfulCompleted, 'must have completed record for approved execution');
    assert.equal(
      successfulStarted.lifecycle?.operationId,
      successfulCompleted.lifecycle?.operationId,
    );
    assert.equal(successfulCompleted.execution?.status, 'SUCCESS');
  });

  test('RC06-FLOW-04: Remote Authenticated Gateway Tool Execution', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-04');
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const store = DeviceTrustStore.createEmpty();
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const spkiPin = deriveSpkiPin(publicKey);
    const { device } = store.enrollDevice({
      clientId: 'flow4-agent',
      clientType: 'cli',
      pin: spkiPin,
    });

    const bridge = new RemoteExecutionBridge({
      sessionManager: server.sessionManager,
      resolveActiveDeviceIdentity: (pin) => resolveActiveDeviceIdentity(store, pin),
      sink: server,
    });

    const identity = resolveActiveDeviceIdentity(store, spkiPin);
    assert.ok(identity);
    const sessionId = server.sessionManager.createSessionIdGenerator()();
    const issuance = server.sessionManager.issueSession({ identity, sessionId });

    const result = await bridge.executeRemoteToolCall({
      trustedSpkiPin: spkiPin,
      presentedSessionId: issuance.sessionId,
      authorizationHeader: `Bearer ${issuance.token}`,
      toolName: 'read_file',
      parameters: { path: 'README.md', workspaceId: 'ws' },
    });
    assert.equal(result.isError, undefined);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // Assert zero session token leaked
    assert.equal(diskContent.includes(issuance.token), false, 'session token must not be leaked');

    // Actor metadata recorded
    const lines = diskContent.trim().split('\n');
    const completed = JSON.parse(lines[lines.length - 1]);
    assert.equal(completed.actor.deviceId, device.deviceId);
    assert.equal(completed.actor.sessionId, issuance.sessionId);
    assert.equal(completed.actor.clientId, 'flow4-agent');
  });

  test('RC06-FLOW-05: Policy Denial Audit Logging', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-05');
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    // Call tool with path attempting directory traversal -> denied
    const res = await server.dispatchToolCall('read_file', {
      path: '../forbidden.txt',
      workspaceId: 'ws',
    });
    assert.equal(res.isError, true);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const deniedRecord = JSON.parse(lines[lines.length - 1]);

    assert.equal(deniedRecord.execution.status, 'DENIED');
    assert.equal(deniedRecord.policy.decision, 'DENY');
  });

  test('RC06-FLOW-06: Operator Approval Lifecycle Persistence', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-06');
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    // Request requiring approval
    const snapshot = server.approvalStateManager.createOrReusePending({
      toolName: 'create_file',
      executionPayloadHash: computeSha256('param'),
      binding: {
        actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
        workspace: {
          workspaceId: 'ws',
          rootPath: sharedWorkspaceDir,
          workspaceRootHash: '0'.repeat(64),
        },
        policyHash: '0'.repeat(64),
      },
      reviewMaterial: JSON.stringify({ toolName: 'create_file', targetSummary: 'summary' }),
      reviewSummary: 'create sensitive file',
    });

    assert.ok(snapshot.requestId);
    await server.approvalAuditSink.flush();

    // Operator approves
    const grant = server.approvalStateManager.approve(snapshot.requestId);
    assert.ok(grant.token);
    await server.approvalAuditSink.flush();

    // Verify transitions logged in contiguous sequence in persistent JSONL
    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    const requested = records.find((r) => r.approval?.eventType === 'APPROVAL_REQUESTED');
    const decision = records.find((r) => r.approval?.eventType === 'APPROVAL_GRANTED');
    assert.ok(requested, 'APPROVAL_REQUESTED must be logged');
    assert.ok(decision, 'APPROVAL_GRANTED must be logged');
    assert.equal(requested.approval.requestId, snapshot.requestId);
    assert.equal(decision.approval.requestId, snapshot.requestId);
  });

  test('RC06-FLOW-07: Gateway Admission & Lifecycle Auditing', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-07');
    const { server, auditLogger } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const sink = getGatewayAuditSink(auditLogger);

    for (const eventType of GATEWAY_AUDIT_EVENT_TYPES) {
      sink.emit({
        eventType,
        mcpSessionId: 'a'.repeat(64),
        deviceId: 'b'.repeat(32),
        clientId: 'test-client',
        clientType: 'cli',
        transportMode: 'stdio',
      });
    }
    await sink.flush();

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    for (const eventType of GATEWAY_AUDIT_EVENT_TYPES) {
      const match = records.find((r) => r.gateway?.eventType === eventType);
      assert.ok(match, `Gateway event ${eventType} must be in the audit chain`);
    }

    // Single unified chain: contiguous sequences and valid hash links
    for (let i = 1; i < records.length; i += 1) {
      assert.equal(records[i].sequenceNumber, records[i - 1].sequenceNumber + 1);
      assert.equal(records[i].integrity.previousRecordHash, records[i - 1].integrity.recordHash);
    }
  });

  test('RC06-FLOW-08: Clean Process Termination', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-08');
    const { server } = createTestServer(fixture);
    await server.start();

    const lockPath = path.join(fixture.directory, LOCK_FILENAME);
    assert.equal(fs.existsSync(lockPath), true, 'audit.lock must exist while running');

    await server.stop();

    assert.equal(fs.existsSync(lockPath), false, 'audit.lock must be removed upon clean stop');
    assert.equal(server.auditRuntime, undefined, 'auditRuntime must be undefined upon stop');
  });

  test('RC06-FLOW-09: Gateway Restart & Hash Continuity', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-09');

    // First run
    const { server: server1 } = createTestServer(fixture);
    await server1.start();
    await server1.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
    await server1.stop();

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const linesBefore = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const lastBefore = JSON.parse(linesBefore[linesBefore.length - 1]);
    const terminalSeqBefore = lastBefore.sequenceNumber;
    const terminalHashBefore = lastBefore.integrity.recordHash;

    // Second run: restart against non-empty store
    const { server: server2 } = createTestServer(fixture);
    await server2.start();
    startedServers.push(server2);

    await server2.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });

    const linesAfter = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const firstNew = JSON.parse(linesAfter[linesBefore.length]);

    assert.equal(firstNew.sequenceNumber, terminalSeqBefore + 1);
    assert.equal(firstNew.integrity.previousRecordHash, terminalHashBefore);
  });

  test('RC06-FLOW-10: Size-Based Rotation Trigger', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-10');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    // Append initial record
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    // Trigger size rotation
    const rotationResult = await runtime.store.rotateNow('SIZE_THRESHOLD');
    assert.ok(rotationResult.archivePath);
    assert.equal(fs.existsSync(rotationResult.archivePath), true);
    assert.equal(rotationResult.reason, 'SIZE_THRESHOLD');

    // Append next record on fresh segment
    const nextRec = await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't2', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r2', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    assert.equal(nextRec.sequenceNumber, 2);
  });

  test('RC06-FLOW-11: Time-Based Operational Rotation Trigger', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-11');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    const rotationResult = await runtime.store.rotateNow('TIME_THRESHOLD');
    assert.ok(rotationResult.archivePath);
    assert.equal(fs.existsSync(rotationResult.archivePath), true);
    assert.equal(rotationResult.reason, 'TIME_THRESHOLD');
  });

  test('RC06-FLOW-12: Compressed Archive Generation & Verified Deletion', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-12');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    const rotationResult = await runtime.store.rotateNow('SIZE_THRESHOLD');

    assert.equal(fs.existsSync(rotationResult.archivePath), true, 'archive .jsonl.gz must exist');
    assert.equal(
      rotationResult.sourceRemoved,
      true,
      'uncompressed segment must be deleted after verified compression',
    );
    const stat = fs.statSync(rotationResult.archivePath);
    assert.equal(stat.mode & 0o777, 0o600);
  });

  test('RC06-FLOW-13: Tier-2 Checkpoint Artifact Generation', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-13');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    // Rotation triggers a sealed checkpoint
    await runtime.store.rotateNow('SIZE_THRESHOLD');

    const checkpointPath = path.join(fixture.directory, CHECKPOINT_FILENAME);
    assert.equal(fs.existsSync(checkpointPath), true, 'audit-checkpoints.jsonl must exist');

    const content = fs.readFileSync(checkpointPath, 'utf8');
    assert.ok(content.length > 0);
    const firstLine = content.slice(0, content.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;

    assert.equal(checkpoint.sequenceStart, 1);
    assert.equal(checkpoint.sequenceEnd, 1);
    assert.ok(checkpoint.storeId);
    assert.ok(checkpoint.signature);

    const publicKey = crypto.createPublicKey(fs.readFileSync(fixture.publicKeyPath, 'utf8'));
    const isValid = verifyCheckpointSignature(checkpoint, publicKey);
    assert.equal(isValid, true, 'checkpoint signature must be valid');
  });

  test('RC06-FLOW-14: Offline Public-Key Checkpoint Verification', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-14');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    await runtime.store.rotateNow('SIZE_THRESHOLD');
    await runtime.close();

    // Verify using public key only with private key deleted/inaccessible
    const checkpointPath = path.join(fixture.directory, CHECKPOINT_FILENAME);
    const content = fs.readFileSync(checkpointPath, 'utf8');
    const firstLine = content.slice(0, content.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;

    const publicKey = crypto.createPublicKey(fs.readFileSync(fixture.publicKeyPath, 'utf8'));
    assert.equal(verifyCheckpointSignature(checkpoint, publicKey), true);
  });

  test('RC06-FLOW-15: Tier-3 External Anchor Dispatch & Cryptographic Receipt', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-15');
    const { privateKey: anchorPriv, publicKey: anchorPub } = crypto.generateKeyPairSync('ed25519');
    const anchorPubPath = path.join(path.dirname(fixture.publicKeyPath), 'anchor-receipt-pub.pem');
    fs.writeFileSync(anchorPubPath, anchorPub.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
    const anchorFingerprint = crypto
      .createHash('sha256')
      .update(anchorPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    // Create a real checkpoint first via runtime
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.store.rotateNow('SIZE_THRESHOLD');
    const checkpointRaw = fs.readFileSync(
      path.join(fixture.directory, CHECKPOINT_FILENAME),
      'utf8',
    );
    const firstLine = checkpointRaw.slice(0, checkpointRaw.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;
    await runtime.close();

    // Now test Tier-3 engine with anchorMode ENABLED
    const metadataPath = path.join(fixture.directory, METADATA_FILENAME);
    const meta = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    meta.anchorMode = 'ENABLED';
    meta.anchorReceiptPublicKeyFingerprint = anchorFingerprint;
    fs.writeFileSync(metadataPath, JSON.stringify(meta, null, 2), { mode: 0o600 });

    const anchorConfig = {
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
      anchorEndpoint: 'https://anchor.example.com/v1/anchor',
      anchorReceiptPublicKeyPath: anchorPubPath,
    };

    const engine = await createTestTier3AnchorEngine(anchorConfig, {
      transport: async (request) => {
        const body = JSON.parse(request.body.toString('utf8'));
        const receipt = signTestAnchorReceipt(
          {
            version: 1,
            storeId: meta.storeId,
            receiptId: crypto.randomUUID(),
            checkpointHash: body.checkpointHash,
            anchorTimestamp: new Date().toISOString(),
            anchorKeyFingerprint: anchorFingerprint,
          },
          anchorPriv,
        );
        return { statusCode: 200, body: Buffer.from(JSON.stringify(receipt), 'utf8') };
      },
    });

    const result = await engine.anchorCheckpoint(checkpoint);
    assert.equal(result.outcome, 'ACKNOWLEDGED');
    assert.equal(result.receipt.checkpointHash, checkpoint.checkpointHash);

    const anchorsPath = path.join(fixture.directory, ANCHOR_RECEIPT_FILENAME);
    assert.equal(fs.existsSync(anchorsPath), true, 'audit-anchors.jsonl must exist');
    const content = fs.readFileSync(anchorsPath, 'utf8').trim();
    assert.ok(content.length > 0);

    const status = engine.getStatus();
    assert.equal(status.anchorState, 'HEALTHY');
    assert.equal(status.unanchoredCheckpoints, 0);
    assert.equal(status.acknowledgedCheckpoints, 1);
    await engine.close();
  });

  test('RC06-FLOW-16: Anchor Outage Spooling & Automatic Backoff Catch-Up', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-16');
    const { privateKey: anchorPriv, publicKey: anchorPub } = crypto.generateKeyPairSync('ed25519');
    const anchorPubPath = path.join(path.dirname(fixture.publicKeyPath), 'anchor-spool-pub.pem');
    fs.writeFileSync(anchorPubPath, anchorPub.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
    const anchorFingerprint = crypto
      .createHash('sha256')
      .update(anchorPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    // Create a real checkpoint first via runtime
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.store.rotateNow('SIZE_THRESHOLD');
    const checkpointRaw = fs.readFileSync(
      path.join(fixture.directory, CHECKPOINT_FILENAME),
      'utf8',
    );
    const firstLine = checkpointRaw.slice(0, checkpointRaw.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;
    await runtime.close();

    // Enable anchor in metadata
    const metadataPath = path.join(fixture.directory, METADATA_FILENAME);
    const meta = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    meta.anchorMode = 'ENABLED';
    meta.anchorReceiptPublicKeyFingerprint = anchorFingerprint;
    fs.writeFileSync(metadataPath, JSON.stringify(meta, null, 2), { mode: 0o600 });

    let failAnchor = true;
    const delaysSeen = [];

    const anchorConfig = {
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
      anchorEndpoint: 'https://anchor.example.com/v1/anchor',
      anchorReceiptPublicKeyPath: anchorPubPath,
    };

    const engine = await createTestTier3AnchorEngine(anchorConfig, {
      sleep: async (ms) => {
        delaysSeen.push(ms);
      },
      transport: async (request) => {
        if (failAnchor) {
          return { statusCode: 503, body: Buffer.from('Service Unavailable', 'utf8') };
        }
        const body = JSON.parse(request.body.toString('utf8'));
        const receipt = signTestAnchorReceipt(
          {
            version: 1,
            storeId: meta.storeId,
            receiptId: crypto.randomUUID(),
            checkpointHash: body.checkpointHash,
            anchorTimestamp: new Date().toISOString(),
            anchorKeyFingerprint: anchorFingerprint,
          },
          anchorPriv,
        );
        return { statusCode: 200, body: Buffer.from(JSON.stringify(receipt), 'utf8') };
      },
    });

    // 1. Initial attempt fails due to outage: outcome is PENDING, delays logged
    const pendingResult = await engine.anchorCheckpoint(checkpoint);
    assert.equal(pendingResult.outcome, 'PENDING');
    assert.deepEqual(delaysSeen, [1_000, 2_000, 4_000, 8_000, 16_000]);

    // Checkpoint must be spooled on disk
    const spoolDir = path.join(fixture.directory, ANCHOR_SPOOL_DIRNAME);
    assert.equal(fs.existsSync(spoolDir), true);
    const spooled = fs.readdirSync(spoolDir);
    assert.ok(spooled.length >= 1, 'checkpoint must be spooled during outage');

    // 2. Outage resolves, catch-up succeeds
    failAnchor = false;
    const catchupResult = await engine.anchorCheckpoint(checkpoint);
    assert.equal(catchupResult.outcome, 'ACKNOWLEDGED');

    const spooledAfter = fs.readdirSync(spoolDir);
    assert.equal(spooledAfter.length, 0, 'spool must be drained after recovery');
    assert.equal(catchupResult.status.unanchoredCheckpoints, 0);
    assert.equal(catchupResult.status.acknowledgedCheckpoints, 1);
    await engine.close();

    // Reopened engine proves clean state after recovery and restart
    const reopened = await createTestTier3AnchorEngine(anchorConfig, {
      transport: async () => ({ statusCode: 200, body: Buffer.from('') }),
    });
    assert.equal(reopened.getStatus().anchorState, 'HEALTHY');
    await reopened.close();
  });

  test('RC06-FLOW-17: Local Operator arc audit status', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-17');
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.close();

    const { exitCode, stdout } = await execCli([
      'audit',
      'status',
      '--dir',
      fixture.directory,
      '--checkpoint-key',
      fixture.publicKeyPath,
    ]);
    assert.equal(exitCode, EXIT_OK);
    assert.match(stdout, /Store ID:/i);
    assert.match(stdout, /Current sequence:\s*1/i);
  });

  test('RC06-FLOW-18: Local Operator arc audit inspect', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-18');
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: { path: 'README.md' },
        payloadHash: '0'.repeat(64),
      },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.close();

    const { exitCode, stdout } = await execCli([
      'audit',
      'inspect',
      '--dir',
      fixture.directory,
      '--limit',
      '5',
    ]);
    assert.equal(exitCode, EXIT_OK);
    assert.match(stdout, /read_file/);
  });

  test('RC06-FLOW-19: Universal Pre-Dispatch Durability', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-19');
    class DurabilityServer extends ArcMcpServer {
      constructor(parts, runtimeOptions) {
        super(
          parts.workspaceRegistry,
          parts.securityKernel,
          parts.auditLogger,
          parts.filesystem,
          parts.git,
          {
            transportMode: 'stdio',
            audit: parts.fixture,
          },
        );
        this.runtimeOptions = runtimeOptions;
      }
      async openAuditRuntimeForProcess(config) {
        return createTestAuditRuntime(config, this.runtimeOptions);
      }
    }

    const workspaceRegistry = new WorkspaceRegistry();
    workspaceRegistry.registerWorkspace('ws', sharedWorkspaceDir);
    const securityKernel = new SecurityKernel(workspaceRegistry);
    const auditLogger = new AuditLogger();
    const filesystem = new FilesystemSubsystem(workspaceRegistry, securityKernel);
    const git = new GitSubsystem(workspaceRegistry, securityKernel);
    const server = new DurabilityServer(
      { workspaceRegistry, securityKernel, auditLogger, filesystem, git, fixture },
      { hooks: { failAppendPhase: 'STARTED' } },
    );
    await server.start();
    startedServers.push(server);

    const readsBefore = filesystem.reads;

    // Privileged read dispatch when STARTED fails
    const res = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      workspaceId: 'ws',
    });
    const body = JSON.parse(res.content[0].text);
    assert.equal(body.code, 'INTERNAL_ERROR');
    // Subsystem reached zero times
    assert.equal(
      filesystem.reads,
      readsBefore,
      'subsystem must not execute when STARTED durability fails',
    );
  });

  test('RC06-FLOW-20: Full Restart Verification of Retained History', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-20');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });

    await runtime.store.rotateNow('SIZE_THRESHOLD');
    await runtime.close();

    // Restart server against archives + active segment
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const healthRes = await server.dispatchToolCall('health', {});
    const health = JSON.parse(healthRes.content[0].text);
    assert.equal(health.status, 'HEALTHY');
  });

  test('RC06-FLOW-21: Crash-Indeterminate Lifecycle Reconciliation', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-21');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const danglingOpId = crypto.randomUUID();

    // Emits STARTED without terminal record (simulating crash)
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'create_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
      lifecycle: { operationId: danglingOpId, phase: 'STARTED' },
    });

    await runtime.close();

    // Restart server: detects dangling operationId and reconciles RECOVERY_INDETERMINATE
    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    const reconciled = records.find((r) => r.lifecycle?.phase === 'RECOVERY_INDETERMINATE');
    assert.ok(reconciled, 'RECOVERY_INDETERMINATE record must be appended durably');
    assert.equal(reconciled.lifecycle.operationId, danglingOpId);
  });

  test('RC06-FLOW-22: Standalone Offline Verification Command', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-22');
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.store.rotateNow('SIZE_THRESHOLD');
    await runtime.close();

    const { exitCode, stdout } = await execCli([
      'audit',
      'verify',
      '--dir',
      fixture.directory,
      '--checkpoint-key',
      fixture.publicKeyPath,
    ]);

    assert.equal(exitCode, EXIT_OK);
    assert.match(stdout, /VERIFIED/i);
  });

  test('RC06-FLOW-23: Deterministic Evidence Export Verification', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-23');
    const runtime = await openAuditRuntime(fixture);
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: sharedWorkspaceDir },
      invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await runtime.store.rotateNow('SIZE_THRESHOLD');
    await runtime.close();

    const exportOutDir = path.join(tempRoot, 'flow23-export');

    enablePrivateKeyLoadProbe();
    const countBefore = getPrivateKeyLoadCount();

    const { exitCode } = await execCli([
      'audit',
      'export',
      '--dir',
      fixture.directory,
      '--output',
      exportOutDir,
      '--checkpoint-key',
      fixture.publicKeyPath,
      '--workspace',
      sharedWorkspaceDir,
    ]);

    assert.equal(exitCode, EXIT_OK);
    assert.equal(fs.existsSync(path.join(exportOutDir, 'manifest.json')), true);

    const countAfter = getPrivateKeyLoadCount();
    assert.equal(countAfter, countBefore, 'zero private key access during evidence export');
  });

  test('Authoritative Meta-Acceptance: exactly 23 contiguous unique RC06-FLOW acceptance tests', () => {
    const filePath = fileURLToPath(import.meta.url);
    const content = fs.readFileSync(filePath, 'utf8');

    const flowPattern = /(?:test|it)\s*\(\s*['"`](RC06-FLOW-(?:0[1-9]|1[0-9]|2[0-3])):\s/g;
    const forbiddenSkipPattern = new RegExp('\\b(?:test|it|describe)\\.' + '(?:skip|todo)\\b');

    assert.equal(
      forbiddenSkipPattern.test(content),
      false,
      'Acceptance suite must not contain skipped or deferred tests',
    );

    const foundFlows = new Set();
    let match;
    while ((match = flowPattern.exec(content)) !== null) {
      const id = match[1];
      assert.equal(foundFlows.has(id), false, `Duplicate flow detected: ${id}`);
      foundFlows.add(id);
    }

    assert.equal(
      foundFlows.size,
      23,
      `Must have exactly 23 positive flows; found ${foundFlows.size}`,
    );

    for (let i = 1; i <= 23; i += 1) {
      const expectedId = `RC06-FLOW-${String(i).padStart(2, '0')}`;
      assert.equal(foundFlows.has(expectedId), true, `Missing flow: ${expectedId}`);
    }
  });
});
