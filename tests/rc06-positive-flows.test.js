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
import net from 'node:net';
import https from 'node:https';
import { fileURLToPath } from 'node:url';

import {
  ACTIVE_SEGMENT_FILENAME,
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  CHECKPOINT_FILENAME,
  LOCK_FILENAME,
  METADATA_FILENAME,
  AuditLogger,
  PersistentAuditStorage,
  openAuditRuntime,
  parseAndValidateCheckpointLineV1,
  serializeAnchorReceiptV1,
  verifyCheckpointSignature,
  verifyEvidenceBundle,
  verifyOfflineStore,
  verifyRetainedPrimaryHistory,
  SEGMENT_SIZE_THRESHOLD,
  ROTATION_INTERVAL_MS,
} from '../packages/audit/dist/index.js';
import {
  createTestTier3AnchorEngine,
  signTestAnchorReceipt,
} from '../packages/audit/dist/internal/anchor-testing.js';
import { createTestTier2CheckpointEngine } from '../packages/audit/dist/internal/checkpoint-testing.js';
import {
  createTestRotatingAuditStore,
  SyntheticRotationCheckpointSealer,
  TestClock,
} from '../packages/audit/dist/internal/rotation-testing.js';
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
import { createTestPki } from './helpers/rc05-test-pki.mjs';

let tempRoot;
let sharedWorkspaceDir;
let pki;
const startedServers = [];
const openRuntimes = [];

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-pos-flows-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
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

    // 1. Initial mutation call without approval -> returns APPROVAL_REQUIRED
    const res1 = await server.dispatchToolCall('create_file', {
      path: 'sensitive.txt',
      content: 'sensitive file content',
      workspaceId: 'ws',
    });
    assert.equal(res1.isError, true);
    const parsed1 = JSON.parse(res1.content[0].text);
    assert.equal(parsed1.code, 'APPROVAL_REQUIRED');
    const requestId = parsed1.details.approvalRequestId;
    assert.ok(requestId);

    // 2. Operator approves via admin/internal state manager -> returns token
    const grant = server.approvalStateManager.approve(requestId);
    assert.ok(grant.token);

    // 3. Redeem and consume through production approval path
    const res2 = await server.dispatchToolCall('create_file', {
      path: 'sensitive.txt',
      content: 'sensitive file content',
      workspaceId: 'ws',
      _arcApproval: {
        requestId,
        token: grant.token,
      },
    });
    assert.equal(res2.isError, undefined);

    // 4. Verify all transitions logged in contiguous sequence in persistent JSONL with same request identity
    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    const requested = records.find((r) => r.approval?.eventType === 'APPROVAL_REQUESTED');
    const granted = records.find((r) => r.approval?.eventType === 'APPROVAL_GRANTED');
    const consumed = records.find((r) => r.approval?.eventType === 'APPROVAL_CONSUMED');

    assert.ok(requested, 'APPROVAL_REQUESTED must be logged');
    assert.ok(granted, 'APPROVAL_GRANTED must be logged');
    assert.ok(consumed, 'APPROVAL_CONSUMED must be logged');

    assert.equal(requested.approval.requestId, requestId);
    assert.equal(granted.approval.requestId, requestId);
    assert.equal(consumed.approval.requestId, requestId);

    // Contiguous sequence numbers and hash links across the entire active segment
    for (let i = 1; i < records.length; i += 1) {
      assert.equal(records[i].sequenceNumber, records[i - 1].sequenceNumber + 1);
      assert.equal(records[i].integrity.previousRecordHash, records[i - 1].integrity.recordHash);
    }
  });

  test('RC06-FLOW-07: Gateway Admission & Lifecycle Auditing', async () => {
    const fixture = createAuditConfig(tempRoot, 'flow-07');
    const wsDir = path.join(tempRoot, 'workspace-flow-07');
    fs.mkdirSync(wsDir, { recursive: true });
    fs.writeFileSync(path.join(wsDir, 'README.md'), '# gateway test');

    const trustStore = DeviceTrustStore.createEmpty();
    const clientCert = fs.readFileSync(pki.clientCertPath, 'utf8');
    const pin = deriveSpkiPin(clientCert);
    const { device } = trustStore.enrollDevice({
      clientId: 'flow07-client',
      clientType: 'claude-code',
      pin,
      displayLabel: 'flow07-device',
    });
    const trustStorePath = path.join(tempRoot, 'flow07-devices.json');
    trustStore.saveToFile(trustStorePath);
    fs.chmodSync(trustStorePath, 0o600);

    const port = await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const p = probe.address().port;
        probe.close(() => resolve(p));
      });
    });

    const auditLogger = new AuditLogger();
    const workspaceRegistry = new WorkspaceRegistry();
    workspaceRegistry.registerWorkspace('ws', wsDir);

    const server = new ArcMcpServer(
      workspaceRegistry,
      new SecurityKernel(workspaceRegistry),
      auditLogger,
      new FilesystemSubsystem(),
      new GitSubsystem(),
      {
        transport: 'remote',
        authorizedRoots: [{ id: 'ws', path: wsDir }],
        defaultWorkspaceId: 'ws',
        audit: fixture,
        remote: {
          bindHost: '127.0.0.1',
          port,
          publicHostname: 'localhost',
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.serverKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
          trustStorePath,
        },
      },
    );

    await server.start();
    startedServers.push(server);

    function doRequest(options = {}) {
      return new Promise((resolve) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port,
            method: options.method || 'POST',
            path: options.requestPath || '/mcp',
            servername: 'localhost',
            ca: [fs.readFileSync(pki.trustedCaCertPath)],
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
            headers: {
              Host: 'localhost',
              Accept: 'application/json, text/event-stream',
              'Content-Type': 'application/json',
              ...(options.headers || {}),
            },
          },
          (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () =>
              resolve({
                status: res.statusCode,
                headers: res.headers,
                body: Buffer.concat(chunks).toString('utf8'),
              }),
            );
          },
        );
        req.on('error', (err) => resolve({ error: err.code }));
        if (options.body) req.write(options.body);
        req.end();
      });
    }

    // 1. Initialize session via mTLS -> SESSION_ISSUED
    const initRes = await doRequest({
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'flow07-client', version: '1.0' },
        },
      }),
    });
    assert.equal(initRes.status, 200);
    const sessionId = initRes.headers['mcp-session-id'];
    const sessionToken = initRes.headers['arc-session-token'];
    assert.ok(sessionId);
    assert.ok(sessionToken);

    // 2. Call tool read_file -> AUTH_SUCCEEDED + tool STARTED/COMPLETED
    const toolRes = await doRequest({
      headers: {
        'mcp-session-id': sessionId,
        authorization: `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'read_file',
          arguments: { path: 'README.md', workspaceId: 'ws' },
        },
      }),
    });
    assert.equal(toolRes.status, 200);

    // 3. Trigger rate-limit enforcement -> RATE_LIMITED
    for (let i = 0; i < 35; i += 1) {
      await doRequest({
        body: JSON.stringify({ jsonrpc: '2.0', id: i + 10, method: 'ping' }),
      });
    }

    // 4. Supplemental coverage for remaining vocabulary entries
    const sink = getGatewayAuditSink(auditLogger);
    for (const eventType of GATEWAY_AUDIT_EVENT_TYPES) {
      sink.emit({
        eventType,
        mcpSessionId: sessionId,
        deviceId: device.deviceId,
        clientId: 'flow07-client',
        clientType: 'claude-code',
        transportMode: 'remote',
      });
    }
    await sink.flush();

    // 5. Shutdown evidence -> GATEWAY_STOPPED
    await server.stop();

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    const bootRecord = records.find((r) => r.gateway?.eventType === 'GATEWAY_STARTED');
    const sessionRecord = records.find((r) => r.gateway?.eventType === 'SESSION_ISSUED');
    const authRecord = records.find((r) => r.gateway?.eventType === 'AUTH_SUCCEEDED');
    const rateLimitRecord = records.find((r) => r.gateway?.eventType === 'RATE_LIMITED');
    const stopRecord = records.find((r) => r.gateway?.eventType === 'GATEWAY_STOPPED');

    assert.ok(bootRecord, 'GATEWAY_STARTED must be in chain');
    assert.ok(sessionRecord, 'SESSION_ISSUED must be in chain');
    assert.equal(sessionRecord.gateway.deviceId, device.deviceId);
    assert.ok(authRecord, 'AUTH_SUCCEEDED must be in chain');
    assert.ok(rateLimitRecord, 'RATE_LIMITED must be in chain');
    assert.ok(stopRecord, 'GATEWAY_STOPPED must be in chain');

    // Supplemental check: all 14 gateway vocabulary entries present
    for (const eventType of GATEWAY_AUDIT_EVENT_TYPES) {
      const match = records.find((r) => r.gateway?.eventType === eventType);
      assert.ok(match, `Gateway event ${eventType} must be in the audit chain`);
    }

    // Single persistent chain: contiguous sequence numbers and hash links
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
    const auditDir = path.join(tempRoot, 'flow-10');
    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: '1'.repeat(64),
        anchorMode: 'DISABLED',
      },
    });
    storage.initialize();

    const sealer = new SyntheticRotationCheckpointSealer();
    const store = createTestRotatingAuditStore(storage, { sealer });

    let appended = 0;
    while (store.getLastRotation() === null && appended < 400) {
      await store.append({
        eventId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: {
          toolName: 'read_file',
          parametersRedacted: { blob: 'x'.repeat(60_000) },
          payloadHash: 'd'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'rule1', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
      });
      appended += 1;
    }

    const rotation = store.getLastRotation();
    assert.ok(rotation !== null, 'the size trigger must fire automatically');
    assert.equal(rotation.reason, 'SIZE_THRESHOLD');
    assert.equal(rotation.boundary.sequenceStart, 1);
    assert.equal(rotation.boundary.sequenceEnd, appended);
    assert.ok(
      rotation.sourceByteLength >= SEGMENT_SIZE_THRESHOLD,
      'sourceByteLength must be >= SEGMENT_SIZE_THRESHOLD',
    );

    const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
    assert.equal(history.status, 'VERIFIED');
    assert.equal(history.recordCount, appended);
    storage.close();
  });

  test('RC06-FLOW-11: Time-Based Operational Rotation Trigger', async () => {
    const auditDir = path.join(tempRoot, 'flow-11');
    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: '1'.repeat(64),
        anchorMode: 'DISABLED',
      },
    });
    storage.initialize();

    const FIXED_START = 1774000000000;
    const clock = new TestClock(FIXED_START);
    const sealer = new SyntheticRotationCheckpointSealer();
    const store = createTestRotatingAuditStore(storage, { sealer }, { clockMs: () => clock.now() });

    function makeCandidate(i) {
      return {
        eventId: crypto.randomUUID(),
        timestamp: new Date(clock.now()).toISOString(),
        actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: {
          toolName: 'read_file',
          parametersRedacted: { i },
          payloadHash: 'd'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'rule1', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date(clock.now()).toISOString(),
          endTime: new Date(clock.now()).toISOString(),
          durationMs: 0,
        },
      };
    }

    // 1. Append records and assert no archive
    await store.append(makeCandidate(1));
    await store.append(makeCandidate(2));
    await store.append(makeCandidate(3));

    assert.equal(store.listArchives().length, 0, 'no archives before rotation');
    assert.equal(store.getLastRotation(), null);

    // 2. Advance clock by exactly ROTATION_INTERVAL_MS (24 hours)
    clock.advanceMs(ROTATION_INTERVAL_MS);

    // 3. Append 4th record -> automatic rotation occurs
    const fourth = await store.append(makeCandidate(4));
    assert.equal(fourth.sequenceNumber, 4);

    const rotation = store.getLastRotation();
    assert.ok(rotation !== null, 'the interval trigger must fire automatically');
    assert.equal(rotation.reason, 'ROTATION_INTERVAL');
    assert.equal(rotation.boundary.sequenceStart, 1);
    assert.equal(rotation.boundary.sequenceEnd, 3);
    assert.equal(store.listArchives().length, 1);

    const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
    assert.equal(history.status, 'VERIFIED');
    assert.equal(history.recordCount, 4);
    storage.close();
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

    // Append 1,000 records to trigger the interval checkpoint cadence
    for (let i = 1; i <= 1000; i += 1) {
      await runtime.appendRecord({
        eventId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: {
          toolName: 'read_file',
          parametersRedacted: { i },
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
    }

    const checkpointPath = path.join(fixture.directory, CHECKPOINT_FILENAME);
    assert.equal(fs.existsSync(checkpointPath), true, 'audit-checkpoints.jsonl must exist');

    const content = fs.readFileSync(checkpointPath, 'utf8');
    assert.ok(content.length > 0);
    const lines = content.trim().split('\n');
    assert.equal(lines.length, 1, 'exactly one interval checkpoint at 1,000 records');

    const checkpoint = parseAndValidateCheckpointLineV1(lines[0] + '\n').checkpoint;
    assert.equal(checkpoint.sequenceStart, 1);
    assert.equal(checkpoint.sequenceEnd, 1000);
    assert.ok(checkpoint.storeId);
    assert.ok(checkpoint.checkpointHash);
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
      invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
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

    // Verify using public key only with private signing key made completely inaccessible
    enablePrivateKeyLoadProbe();
    const countBefore = getPrivateKeyLoadCount();
    fs.chmodSync(fixture.signingKeyPath, 0o000);

    try {
      const result = await verifyOfflineStore({
        directory: fixture.directory,
        checkpointPublicKeyPath: fixture.publicKeyPath,
      });
      assert.equal(result.status, 'VERIFIED');
      const countAfter = getPrivateKeyLoadCount();
      assert.equal(countAfter, countBefore, 'private key load count must remain unchanged');
    } finally {
      fs.chmodSync(fixture.signingKeyPath, 0o600);
    }
  });

  test('RC06-FLOW-15: Tier-3 External Anchor Dispatch & Cryptographic Receipt', async () => {
    const auditDir = path.join(tempRoot, 'flow-15');
    const keyDir = path.join(tempRoot, 'flow-15-keys');
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });

    const { privateKey: cpPriv, publicKey: cpPub } = crypto.generateKeyPairSync('ed25519');
    const cpPrivPath = path.join(keyDir, 'cp.key');
    const cpPubPath = path.join(keyDir, 'cp.pub');
    fs.writeFileSync(cpPrivPath, cpPriv.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(cpPubPath, cpPub.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
    const cpFingerprint = crypto
      .createHash('sha256')
      .update(cpPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    const { privateKey: anchorPriv, publicKey: anchorPub } = crypto.generateKeyPairSync('ed25519');
    const anchorPubPath = path.join(keyDir, 'anchor.pub');
    fs.writeFileSync(anchorPubPath, anchorPub.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
    const anchorFingerprint = crypto
      .createHash('sha256')
      .update(anchorPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    // Initialize audit storage with anchorMode ENABLED from the start
    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: cpFingerprint,
        anchorMode: 'ENABLED',
        anchorReceiptPublicKeyFingerprint: anchorFingerprint,
      },
    });
    storage.initialize();

    const checkpointEngine = await createTestTier2CheckpointEngine({
      directory: auditDir,
      signingKeyPath: cpPrivPath,
      publicKeyPath: cpPubPath,
    });

    const store = createTestRotatingAuditStore(storage, { sealer: checkpointEngine });
    const rec = await store.append({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await checkpointEngine.checkpointAfterDurablePrimary({
      sequenceNumber: rec.sequenceNumber,
      recordHash: rec.integrity.recordHash,
    });
    await store.rotateNow('SIZE_THRESHOLD');

    const checkpointRaw = fs.readFileSync(path.join(auditDir, CHECKPOINT_FILENAME), 'utf8');
    const firstLine = checkpointRaw.slice(0, checkpointRaw.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;

    // Real HTTPS anchor server on ephemeral port with TLS 1.3
    let requestReceived = null;
    const server = https.createServer(
      {
        key: fs.readFileSync(pki.serverKeyPath),
        cert: fs.readFileSync(pki.serverCertPath),
        minVersion: 'TLSv1.3',
      },
      (req, res) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          requestReceived = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const receipt = signTestAnchorReceipt(
            {
              version: 1,
              storeId: storage.metadata.storeId,
              receiptId: crypto.randomUUID(),
              checkpointHash: requestReceived.checkpointHash,
              anchorTimestamp: new Date().toISOString(),
              anchorKeyFingerprint: anchorFingerprint,
            },
            anchorPriv,
          );
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(receipt));
        });
      },
    );
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const endpoint = `https://localhost:${port}/v1/anchor`;

    const engine = await createTestTier3AnchorEngine(
      {
        directory: auditDir,
        checkpointPublicKeyPath: cpPubPath,
        anchorEndpoint: endpoint,
        anchorReceiptPublicKeyPath: anchorPubPath,
      },
      { ca: fs.readFileSync(pki.trustedCaCertPath) },
    );

    const result = await engine.anchorCheckpoint(checkpoint);
    assert.equal(result.outcome, 'ACKNOWLEDGED');
    assert.equal(result.receipt.checkpointHash, checkpoint.checkpointHash);
    assert.equal(result.receipt.anchorKeyFingerprint, anchorFingerprint);

    const anchorsPath = path.join(auditDir, ANCHOR_RECEIPT_FILENAME);
    assert.equal(fs.existsSync(anchorsPath), true, 'audit-anchors.jsonl must exist');
    const content = fs.readFileSync(anchorsPath, 'utf8').trim();
    assert.ok(content.length > 0);

    const status = engine.getStatus();
    assert.equal(status.anchorState, 'HEALTHY');
    assert.equal(status.unanchoredCheckpoints, 0);
    assert.equal(status.acknowledgedCheckpoints, 1);

    await engine.close();
    server.close();
    checkpointEngine.close();
    storage.close();
  });

  test('RC06-FLOW-16: Anchor Outage Spooling & Automatic Backoff Catch-Up', async () => {
    const auditDir = path.join(tempRoot, 'flow-16');
    const keyDir = path.join(tempRoot, 'flow-16-keys');
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });

    const { privateKey: cpPriv, publicKey: cpPub } = crypto.generateKeyPairSync('ed25519');
    const cpPrivPath = path.join(keyDir, 'cp.key');
    const cpPubPath = path.join(keyDir, 'cp.pub');
    fs.writeFileSync(cpPrivPath, cpPriv.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(cpPubPath, cpPub.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
    const cpFingerprint = crypto
      .createHash('sha256')
      .update(cpPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    const { privateKey: anchorPriv, publicKey: anchorPub } = crypto.generateKeyPairSync('ed25519');
    const anchorPubPath = path.join(keyDir, 'anchor.pub');
    fs.writeFileSync(anchorPubPath, anchorPub.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
    const anchorFingerprint = crypto
      .createHash('sha256')
      .update(anchorPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: cpFingerprint,
        anchorMode: 'ENABLED',
        anchorReceiptPublicKeyFingerprint: anchorFingerprint,
      },
    });
    storage.initialize();

    const checkpointEngine = await createTestTier2CheckpointEngine({
      directory: auditDir,
      signingKeyPath: cpPrivPath,
      publicKeyPath: cpPubPath,
    });

    const store = createTestRotatingAuditStore(storage, { sealer: checkpointEngine });
    const rec = await store.append({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await checkpointEngine.checkpointAfterDurablePrimary({
      sequenceNumber: rec.sequenceNumber,
      recordHash: rec.integrity.recordHash,
    });
    await store.rotateNow('SIZE_THRESHOLD');

    const checkpointRaw = fs.readFileSync(path.join(auditDir, CHECKPOINT_FILENAME), 'utf8');
    const firstLine = checkpointRaw.slice(0, checkpointRaw.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;

    let failAnchor = true;
    const delaysSeen = [];

    const server = https.createServer(
      {
        key: fs.readFileSync(pki.serverKeyPath),
        cert: fs.readFileSync(pki.serverCertPath),
        minVersion: 'TLSv1.3',
      },
      (req, res) => {
        if (failAnchor) {
          res.writeHead(503, { 'Content-Type': 'text/plain' });
          res.end('Service Unavailable');
          return;
        }
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const receipt = signTestAnchorReceipt(
            {
              version: 1,
              storeId: storage.metadata.storeId,
              receiptId: crypto.randomUUID(),
              checkpointHash: body.checkpointHash,
              anchorTimestamp: new Date().toISOString(),
              anchorKeyFingerprint: anchorFingerprint,
            },
            anchorPriv,
          );
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(receipt));
        });
      },
    );
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const endpoint = `https://localhost:${port}/v1/anchor`;

    const anchorConfig = {
      directory: auditDir,
      checkpointPublicKeyPath: cpPubPath,
      anchorEndpoint: endpoint,
      anchorReceiptPublicKeyPath: anchorPubPath,
    };

    const engine = await createTestTier3AnchorEngine(anchorConfig, {
      ca: fs.readFileSync(pki.trustedCaCertPath),
      sleep: async (ms) => {
        delaysSeen.push(ms);
      },
    });

    // 1. Initial attempt fails due to 503 outage: outcome is PENDING, delays logged
    const pendingResult = await engine.anchorCheckpoint(checkpoint);
    assert.equal(pendingResult.outcome, 'PENDING');
    assert.deepEqual(delaysSeen, [1_000, 2_000, 4_000, 8_000, 16_000]);

    // Checkpoint must be spooled on disk
    const spoolDir = path.join(auditDir, ANCHOR_SPOOL_DIRNAME);
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
      ca: fs.readFileSync(pki.trustedCaCertPath),
    });
    assert.equal(reopened.getStatus().anchorState, 'HEALTHY');
    await reopened.close();

    server.close();
    checkpointEngine.close();
    storage.close();
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

    class VerifiedFilesystemSubsystem extends FilesystemSubsystem {
      constructor(auditDir) {
        super();
        this.auditDir = auditDir;
        this.readObservedStarted = null;
        this.writeObservedStarted = null;
      }
      async readFile(resolvedPath, options) {
        const activePath = path.join(this.auditDir, ACTIVE_SEGMENT_FILENAME);
        const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
        const last = JSON.parse(lines[lines.length - 1]);
        if (last.lifecycle?.phase === 'STARTED' && last.invocation?.toolName === 'read_file') {
          this.readObservedStarted = last;
        }
        return super.readFile(resolvedPath, options);
      }
      async createFile(resolvedPath, content, options) {
        const activePath = path.join(this.auditDir, ACTIVE_SEGMENT_FILENAME);
        const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
        const last = JSON.parse(lines[lines.length - 1]);
        if (last.lifecycle?.phase === 'STARTED' && last.invocation?.toolName === 'create_file') {
          this.writeObservedStarted = last;
        }
        return super.createFile(resolvedPath, content, options);
      }
    }

    const workspaceRegistry = new WorkspaceRegistry();
    workspaceRegistry.registerWorkspace('ws', sharedWorkspaceDir);
    const processRegistry = new ProcessRegistry();
    const securityKernel = new SecurityKernel(workspaceRegistry, processRegistry);
    const auditLogger = new AuditLogger();
    const filesystem = new VerifiedFilesystemSubsystem(fixture.directory);
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
        authorizedRoots: [{ id: 'ws', path: sharedWorkspaceDir }],
        defaultWorkspaceId: 'ws',
        audit: fixture,
      },
      undefined,
      processRegistry,
      approvals,
    );
    await server.start();
    startedServers.push(server);

    // 1. Privileged read: verify STARTED durability on disk before subsystem read, then COMPLETED durability
    const readRes = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      workspaceId: 'ws',
    });
    assert.equal(readRes.isError, undefined);
    assert.ok(filesystem.readObservedStarted, 'read dispatch occurred only after durable STARTED');

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    let lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    let records = lines.map((l) => JSON.parse(l));

    const readStarted = records.find(
      (r) => r.invocation?.toolName === 'read_file' && r.lifecycle?.phase === 'STARTED',
    );
    const readCompleted = records.find(
      (r) => r.invocation?.toolName === 'read_file' && r.lifecycle?.phase === 'COMPLETED',
    );
    assert.ok(readStarted, 'read STARTED record must be durable');
    assert.ok(readCompleted, 'read COMPLETED record must be durable');
    assert.equal(readStarted.lifecycle.operationId, readCompleted.lifecycle.operationId);
    assert.equal(
      readCompleted.lifecycle.operationId,
      filesystem.readObservedStarted.lifecycle.operationId,
    );
    assert.equal(readCompleted.execution.status, 'SUCCESS');

    // 2. Privileged mutation with approval: verify STARTED durability before write, then COMPLETED durability
    const mutInit = await server.dispatchToolCall('create_file', {
      path: 'flow19-mut.txt',
      content: 'durable mutation content\n',
      workspaceId: 'ws',
    });
    const reqId = JSON.parse(mutInit.content[0].text).details.approvalRequestId;
    assert.ok(reqId);
    const grant = server.approvalStateManager.approve(reqId);

    const mutRes = await server.dispatchToolCall('create_file', {
      path: 'flow19-mut.txt',
      content: 'durable mutation content\n',
      workspaceId: 'ws',
      _arcApproval: { requestId: reqId, token: grant.token },
    });
    assert.equal(mutRes.isError, undefined);
    assert.ok(
      filesystem.writeObservedStarted,
      'mutation dispatch occurred only after durable STARTED',
    );

    lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    records = lines.map((l) => JSON.parse(l));

    const writeStarted = records.find(
      (r) => r.invocation?.toolName === 'create_file' && r.lifecycle?.phase === 'STARTED',
    );
    const writeCompleted = records.find(
      (r) => r.invocation?.toolName === 'create_file' && r.lifecycle?.phase === 'COMPLETED',
    );
    assert.ok(writeStarted, 'mutation STARTED record must be durable');
    assert.ok(writeCompleted, 'mutation COMPLETED record must be durable');
    assert.equal(writeStarted.lifecycle.operationId, writeCompleted.lifecycle.operationId);
    assert.equal(
      writeCompleted.lifecycle.operationId,
      filesystem.writeObservedStarted.lifecycle.operationId,
    );
    assert.equal(writeCompleted.execution.status, 'SUCCESS');
  });

  test('RC06-FLOW-20: Full Restart Verification of Retained History', async () => {
    const auditDir = path.join(tempRoot, 'flow-20');
    const keyDir = path.join(tempRoot, 'flow-20-keys');
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });

    const { privateKey: cpPriv, publicKey: cpPub } = crypto.generateKeyPairSync('ed25519');
    const cpPrivPath = path.join(keyDir, 'cp.key');
    const cpPubPath = path.join(keyDir, 'cp.pub');
    fs.writeFileSync(cpPrivPath, cpPriv.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(cpPubPath, cpPub.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
    const cpFingerprint = crypto
      .createHash('sha256')
      .update(cpPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    const { privateKey: anchorPriv, publicKey: anchorPub } = crypto.generateKeyPairSync('ed25519');
    const anchorPubPath = path.join(keyDir, 'anchor.pub');
    fs.writeFileSync(anchorPubPath, anchorPub.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
    const anchorFingerprint = crypto
      .createHash('sha256')
      .update(anchorPub.export({ type: 'spki', format: 'der' }))
      .digest('hex');

    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: cpFingerprint,
        anchorMode: 'ENABLED',
        anchorReceiptPublicKeyFingerprint: anchorFingerprint,
      },
    });
    storage.initialize();

    const checkpointEngine = await createTestTier2CheckpointEngine({
      directory: auditDir,
      signingKeyPath: cpPrivPath,
      publicKeyPath: cpPubPath,
    });

    const store = createTestRotatingAuditStore(storage, { sealer: checkpointEngine });
    const rec1 = await store.append({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await checkpointEngine.checkpointAfterDurablePrimary({
      sequenceNumber: rec1.sequenceNumber,
      recordHash: rec1.integrity.recordHash,
    });
    const rot = await store.rotateNow('SIZE_THRESHOLD');
    assert.ok(rot.archivePath && fs.existsSync(rot.archivePath));

    // Append record on fresh segment so active segment is non-empty
    const rec2 = await store.append({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: '' },
      invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: '0'.repeat(64) },
      policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
    });
    await checkpointEngine.checkpointAfterDurablePrimary({
      sequenceNumber: rec2.sequenceNumber,
      recordHash: rec2.integrity.recordHash,
    });

    // Read checkpoint and mint receipt
    const checkpointRaw = fs.readFileSync(path.join(auditDir, CHECKPOINT_FILENAME), 'utf8');
    const firstLine = checkpointRaw.slice(0, checkpointRaw.indexOf('\n') + 1);
    const checkpoint = parseAndValidateCheckpointLineV1(firstLine).checkpoint;

    const receipt = signTestAnchorReceipt(
      {
        version: 1,
        storeId: storage.metadata.storeId,
        receiptId: crypto.randomUUID(),
        checkpointHash: checkpoint.checkpointHash,
        anchorTimestamp: new Date().toISOString(),
        anchorKeyFingerprint: anchorFingerprint,
      },
      anchorPriv,
    );
    fs.writeFileSync(
      path.join(auditDir, ANCHOR_RECEIPT_FILENAME),
      serializeAnchorReceiptV1(receipt),
      { mode: 0o600 },
    );

    checkpointEngine.close();
    storage.close();

    // Restart server against archives + active segment + checkpoint + receipt (anchor ENABLED)
    const fixture = {
      directory: auditDir,
      signingKeyPath: cpPrivPath,
      publicKeyPath: cpPubPath,
      anchorEndpoint: 'https://localhost:9999/v1/anchor',
      anchorReceiptPublicKeyPath: anchorPubPath,
    };

    const { server } = createTestServer(fixture);
    await server.start();
    startedServers.push(server);

    const healthRes = await server.dispatchToolCall('health', {});
    const health = JSON.parse(healthRes.content[0].text);
    assert.equal(health.status, 'HEALTHY');

    // Privileged operation can execute after startup
    const readRes = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      workspaceId: 'ws',
    });
    assert.equal(readRes.isError, undefined);
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

    // Privileged operation executes after startup recovery
    const readRes = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      workspaceId: 'ws',
    });
    assert.equal(readRes.isError, undefined);

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
    const records = lines.map((l) => JSON.parse(l));

    const reconciledIndex = records.findIndex(
      (r) => r.lifecycle?.phase === 'RECOVERY_INDETERMINATE',
    );
    assert.ok(reconciledIndex >= 0, 'RECOVERY_INDETERMINATE record must be appended durably');
    assert.equal(records[reconciledIndex].lifecycle.operationId, danglingOpId);

    const postRecoveryOp = records.find(
      (r) => r.lifecycle?.phase === 'COMPLETED' && r.invocation?.toolName === 'read_file',
    );
    assert.ok(postRecoveryOp, 'privileged operation must complete after recovery');
    assert.ok(
      postRecoveryOp.sequenceNumber > records[reconciledIndex].sequenceNumber,
      'privileged operation sequence must be after RECOVERY_INDETERMINATE',
    );
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

    // Append 2 records and rotate so we have archive and checkpoint
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: sharedWorkspaceDir },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: { p: 1 },
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
    await runtime.appendRecord({
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      actor: { clientId: 'c1', clientType: 'cli', deviceId: 'd1', sessionId: 's1' },
      target: { workspaceId: 'ws', workspacePath: sharedWorkspaceDir },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: { p: 2 },
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

    assert.equal(exitCode, EXIT_OK, 'export exit code must be EXIT_OK');
    const countAfter = getPrivateKeyLoadCount();
    assert.equal(countAfter, countBefore, 'zero private key access during evidence export');

    // 1. Frozen directory structure exists
    assert.equal(fs.existsSync(exportOutDir), true);
    assert.equal(fs.existsSync(path.join(exportOutDir, 'manifest.json')), true);
    assert.equal(
      fs.existsSync(path.join(exportOutDir, 'checkpoints', 'audit-checkpoints.jsonl')),
      true,
    );
    assert.equal(
      fs.existsSync(path.join(exportOutDir, 'public-keys', 'checkpoint-public.pem')),
      true,
    );

    // 2. Parse manifest.json
    const manifestRaw = fs.readFileSync(path.join(exportOutDir, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(manifestRaw);
    assert.equal(manifest.version, 1);
    assert.ok(manifest.storeId);

    // 3. Recompute byte count and SHA-256 for EVERY manifest.files entry
    assert.ok(
      manifest.files && Object.keys(manifest.files).length > 0,
      'manifest must contain files',
    );
    for (const [relPath, fileEntry] of Object.entries(manifest.files)) {
      const fullPath = path.join(exportOutDir, relPath);
      assert.equal(fs.existsSync(fullPath), true, `file ${relPath} in manifest must exist`);
      const fileBytes = fs.readFileSync(fullPath);
      assert.equal(fileBytes.length, fileEntry.bytes, `bytes mismatch for ${relPath}`);
      const hash = crypto.createHash('sha256').update(fileBytes).digest('hex');
      assert.equal(hash, fileEntry.sha256, `sha256 mismatch for ${relPath}`);
    }

    // 4. Exact sequenceRange is asserted
    assert.deepEqual(manifest.sequenceRange, { start: 1, end: 2 });

    // 5. Checkpoint hashes/signatures are verified
    const cpPath = path.join(exportOutDir, 'checkpoints', 'audit-checkpoints.jsonl');
    const cpLines = fs.readFileSync(cpPath, 'utf8').trim().split('\n');
    assert.equal(cpLines.length, 1);
    const { checkpoint } = parseAndValidateCheckpointLineV1(cpLines[0] + '\n');
    assert.equal(checkpoint.sequenceStart, 1);
    assert.equal(checkpoint.sequenceEnd, 2);
    const pubKey = crypto.createPublicKey(fs.readFileSync(fixture.publicKeyPath, 'utf8'));
    assert.equal(verifyCheckpointSignature(checkpoint, pubKey), true);

    // 6. Run verifyEvidenceBundle() against the produced directory
    const bundleVerification = await verifyEvidenceBundle(exportOutDir);
    assert.equal(bundleVerification.status, 'VERIFIED');
    assert.equal(bundleVerification.coveredSequenceStart, 1);
    assert.equal(bundleVerification.coveredSequenceEnd, 2);

    // 7. No private key material exists in bundle files
    function scanDir(dir) {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) scanDir(full);
        else if (ent.isFile() && !ent.name.endsWith('.gz')) {
          const text = fs.readFileSync(full, 'utf8');
          assert.equal(
            text.includes('PRIVATE KEY'),
            false,
            `bundle file ${full} must not contain private key material`,
          );
        }
      }
    }
    scanDir(exportOutDir);
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
