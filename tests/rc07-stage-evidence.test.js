/**
 * CesSpace ARC — RC-07 Task 7 Authoritative Test Suite
 *
 * Covers:
 * - Negative Controls: RC07-NEG-054 through RC07-NEG-061
 * - Positive Acceptance Flows: RC07-FLOW-14 and RC07-FLOW-15
 * - Invariant Regressions: Tool count (25), anti-fabrication invariants,
 *   read-only non-execution, built-in policy ALLOW, external policy DENY override,
 *   512 KiB payload ceiling, and static boundaries (no child_process or direct fs in composite module).
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import {
  createArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  TOOL_SCHEMAS,
} from '../apps/mcp-server/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';
import { DeclarativePolicyEngine, WorkspaceRegistry } from '../packages/policy/dist/index.js';
import {
  CHECKPOINT_FILENAME,
  computeCheckpointHash,
  listRetainedSegmentSources,
  parseAndValidateCheckpointLineV1,
  serializeCheckpointV1,
  streamRetainedRecords,
  verifyCheckpointHistory,
  verifyOfflineStore,
} from '../packages/audit/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import {
  MAX_STAGE_EVIDENCE_RESPONSE_BYTES,
  STAGE_EVIDENCE_DISCLAIMER,
  handleArcStageEvidence,
} from '../apps/mcp-server/dist/internal/stage-evidence.js';

function makeSafeActor() {
  return {
    clientId: 'test-client-task7',
    clientType: 'agent',
    sessionId: 'sess-task7-1',
    deviceId: 'dev-task7-1',
    authenticated: true,
  };
}

function runGit(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Alice Engineer',
      GIT_AUTHOR_EMAIL: 'alice@example.com',
      GIT_COMMITTER_NAME: 'Alice Engineer',
      GIT_COMMITTER_EMAIL: 'alice@example.com',
    },
  }).trim();
}

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
}

describe('CesSpace ARC — RC-07 Task 7: arc_stage_evidence Test Suite', () => {
  let tempRoot;
  let workspaceDir;
  let auditConfig;
  let server;
  const safeActor = makeSafeActor();

  before(async () => {
    tempRoot = mkdtempSync(join(tmpdir(), 'arc-task7-test-'));
    workspaceDir = join(tempRoot, 'workspace');
    mkdirSync(workspaceDir, { recursive: true });

    // Initialize git repository
    runGit(['init', '-b', 'feat/rc-07-evidence'], workspaceDir);
    runGit(['config', 'user.name', 'Alice Engineer'], workspaceDir);
    runGit(['config', 'user.email', 'alice@example.com'], workspaceDir);

    writeFileSync(join(workspaceDir, 'README.md'), '# ARC Test Workspace Task 7\n');
    mkdirSync(join(workspaceDir, 'scripts'), { recursive: true });
    // Add scripts/verify-rc06.sh as a tracked file, but do NOT add scripts/verify-rc07.sh
    writeFileSync(join(workspaceDir, 'scripts', 'verify-rc06.sh'), '#!/bin/bash\nexit 0\n');
    runGit(['add', 'README.md', 'scripts/verify-rc06.sh'], workspaceDir);
    runGit(['commit', '-m', 'Initial commit with rc06 verify script'], workspaceDir);

    auditConfig = createAuditConfig(tempRoot, 'task7-main');

    server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws-task7', path: workspaceDir }],
      defaultWorkspaceId: 'ws-task7',
      audit: auditConfig,
    });
    await server.start();
  });

  after(async () => {
    try {
      await server?.stop();
    } catch {
      // ignore
    }
    try {
      rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // =========================================================================
  // 1. Negative Controls (RC07-NEG-054 .. RC07-NEG-061)
  // =========================================================================

  describe('RC-07 Task 7: Negative Controls (RC07-NEG-054..061)', () => {
    test('RC07-NEG-054: arc_stage_evidence fabricates stage approval when audit ledger has zero evidence. Rejected with EVIDENCE_NOT_MET', async () => {
      // Create a separate server with NO audit runtime configured
      const noAuditServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-no-audit', path: workspaceDir }],
        defaultWorkspaceId: 'ws-no-audit',
      });

      const res = await noAuditServer.executeAuthenticatedToolCall(
        safeActor,
        'arc_stage_evidence',
        { targetStage: 'RC-06' },
      );
      assert.ok(res.isError);
      const err = parseResponse(res);
      assert.equal(err.code, 'EVIDENCE_NOT_MET');

      // Also verify when audit runtime exists with a REAL persistent audit store with ZERO records before invocation
      const emptyAuditConfig = createAuditConfig(tempRoot, 'empty-audit');
      const emptyServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-empty-audit', path: workspaceDir }],
        defaultWorkspaceId: 'ws-empty-audit',
        audit: emptyAuditConfig,
      });
      await emptyServer.start();

      try {
        // Assert store has 0 records before invocation
        assert.equal(emptyServer.auditRuntime.getNextSequence(), 1);

        // Production MCP execution must fail closed with EVIDENCE_NOT_MET
        const mcpRes = await emptyServer.executeAuthenticatedToolCall(
          safeActor,
          'arc_stage_evidence',
          { targetStage: 'RC-06' },
        );
        assert.equal(mcpRes.isError, true);
        const mcpErr = parseResponse(mcpRes);
        assert.equal(mcpErr.code, 'EVIDENCE_NOT_MET');

        // Prove the failed call still produces the correct root STARTED -> COMPLETED audit lifecycle
        const sources = listRetainedSegmentSources(emptyAuditConfig.directory);
        const records = [];
        for await (const rec of streamRetainedRecords(sources)) {
          records.push(rec);
        }

        assert.equal(records.length, 2, 'Failed invocation must record root STARTED and COMPLETED');
        const [startedRec, completedRec] = records;
        assert.equal(startedRec.lifecycle.phase, 'STARTED');
        assert.equal(completedRec.lifecycle.phase, 'COMPLETED');
        assert.equal(startedRec.lifecycle.operationId, completedRec.lifecycle.operationId);
        assert.equal(startedRec.invocation.payloadHash, completedRec.invocation.payloadHash);
        assert.equal(completedRec.execution.status, 'ERROR');
        assert.equal(completedRec.error?.code, 'EVIDENCE_NOT_MET');

        // Cryptographic verification of the resulting 2-record store
        const verification = await verifyOfflineStore({
          directory: emptyAuditConfig.directory,
          checkpointPublicKeyPath: emptyAuditConfig.publicKeyPath,
        });
        assert.equal(verification.status, 'VERIFIED');
      } finally {
        await emptyServer.stop();
      }
    });

    test('RC07-NEG-055: arc_stage_evidence treats a single green test execution as sufficient for stage approval. Prohibited by anti-fabrication invariant', async () => {
      // Create a tiny passing Node test file
      const passingTest = join(workspaceDir, 'passing-neg055.test.js');
      writeFileSync(
        passingTest,
        'const test = require("node:test"); test("neg055 pass", () => {});\n',
      );

      try {
        // Run full approval lifecycle for real arc_test
        // 1. call arc_test
        const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_test', {
          testPath: 'passing-neg055.test.js',
        });
        assert.equal(reqRes.isError, true);
        const reqBody = parseResponse(reqRes);
        assert.equal(reqBody.code, 'APPROVAL_REQUIRED');
        const requestId = reqBody.details.approvalRequestId;
        assert.ok(requestId);

        // 2. approve through real ApprovalStateManager
        const approval = server.approvalStateManager.approve(requestId);

        // 3. redeem approval and run child process
        const execRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_test', {
          testPath: 'passing-neg055.test.js',
          _arcApproval: {
            requestId,
            token: approval.token,
          },
        });
        assert.ok(!execRes.isError);
        const testResult = parseResponse(execRes);
        assert.equal(testResult.status, 'PASSED');
        const childProcessId = testResult.processId;
        assert.equal(typeof childProcessId, 'string');

        // 4. Then call arc_stage_evidence
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
          targetStage: 'RC-06',
        });
        assert.ok(!res.isError);
        const body = parseResponse(res);

        // Anti-fabrication invariant: one green test is NOT stage approval
        assert.equal(body.verification.verifiedLocally, false);
        assert.equal(body.acceptanceMet, false);
        assert.equal(body.disclaimer, STAGE_EVIDENCE_DISCLAIMER);
      } finally {
        rmSync(passingTest, { force: true });
      }
    });

    test('RC07-NEG-056: arc_stage_evidence attempts to read an unverified, tampered audit ledger. Invariant check halts; reports integrity: FAILED', async () => {
      // Create dedicated server with its own audit dir
      const tamperedAuditConfig = createAuditConfig(tempRoot, 'tampered-audit');
      const tamperedServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-tampered', path: workspaceDir }],
        defaultWorkspaceId: 'ws-tampered',
        audit: tamperedAuditConfig,
      });
      await tamperedServer.start();

      try {
        // Execute a tool to have durable records
        await tamperedServer.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {});

        // Tamper with the active segment on disk
        const activeSegmentPath = join(tamperedAuditConfig.directory, 'audit-active.jsonl');
        const originalContent = readFileSync(activeSegmentPath, 'utf8');
        // Modify a record hash to invalidate hash chain
        const tamperedContent = originalContent.replace(
          /"recordHash":"[a-f0-9]{64}"/,
          '"recordHash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"',
        );
        writeFileSync(activeSegmentPath, tamperedContent);

        // Query stage evidence
        const res = await tamperedServer.executeAuthenticatedToolCall(
          safeActor,
          'arc_stage_evidence',
          { targetStage: 'RC-06' },
        );
        assert.ok(!res.isError);
        const body = parseResponse(res);

        // Must report integrity FAILED
        assert.equal(body.auditLedger.integrity, 'FAILED');
        assert.equal(body.acceptanceMet, false);
        assert.equal(body.references.checkpointHash, undefined, 'checkpointHash must be omitted');
      } finally {
        await tamperedServer.stop();
      }
    });

    test('RC07-NEG-057: arc_stage_evidence embeds uncompressed multi-megabyte audit segment into response. Prohibited; hashes referenced only', async () => {
      // Create dedicated server with real audit config
      const largeAuditConfig = createAuditConfig(tempRoot, 'large-audit');
      const largeServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-large', path: workspaceDir }],
        defaultWorkspaceId: 'ws-large',
        audit: largeAuditConfig,
      });
      await largeServer.start();

      try {
        // Populate valid persistent audit history >= 2 MiB using existing audit authorities
        // Each record ~45 KiB payload. 50 records * 45 KiB > 2.25 MiB.
        const chunk = 'x'.repeat(45 * 1024);
        for (let i = 0; i < 50; i++) {
          await largeServer.auditRuntime.appendRecord({
            eventId: randomUUID(),
            timestamp: new Date().toISOString(),
            actor: {
              clientId: safeActor.clientId,
              clientType: safeActor.clientType,
              sessionId: safeActor.sessionId,
              deviceId: safeActor.deviceId,
            },
            target: { workspaceId: 'ws-large', workspacePath: workspaceDir },
            invocation: {
              toolName: 'git_status',
              parametersRedacted: { chunk, index: i },
              payloadHash: '0000000000000000000000000000000000000000000000000000000000000000',
            },
            policy: { decision: 'ALLOW', ruleId: 'builtin-allow', evaluationDurationMs: 0 },
            execution: {
              status: 'SUCCESS',
              startTime: new Date().toISOString(),
              endTime: new Date().toISOString(),
              durationMs: 1,
            },
          });
        }

        // Verify the store is physically >= 2 MiB
        const activePath = join(largeAuditConfig.directory, 'audit-active.jsonl');
        const storeBytes = statSync(activePath).size;
        assert.ok(
          storeBytes >= 2 * 1024 * 1024,
          `Expected store >= 2 MiB, got ${storeBytes} bytes`,
        );

        // The large store must successfully verify through packages/audit
        const verifyResult = await verifyOfflineStore({
          directory: largeAuditConfig.directory,
          checkpointPublicKeyPath: largeAuditConfig.publicKeyPath,
        });
        assert.equal(verifyResult.status, 'VERIFIED');
        assert.equal(verifyResult.primary.recordCount, 50);

        // Call arc_stage_evidence
        const res = await largeServer.executeAuthenticatedToolCall(
          safeActor,
          'arc_stage_evidence',
          {
            targetStage: 'RC-06',
          },
        );
        assert.ok(!res.isError);
        const body = parseResponse(res);

        // Prove audit verification succeeds
        assert.equal(body.auditLedger.integrity, 'VERIFIED');

        // Prove only bounded references are returned
        assert.ok(body.references, 'references object must be present');
        assert.ok(body.references.auditStoreId, 'auditStoreId reference must be present');
        assert.ok(
          body.references.terminalRecordHash,
          'terminalRecordHash reference must be present',
        );

        // Prohibited: No raw ledger lines or segments embedded
        assert.equal(body.records, undefined);
        assert.equal(body.segments, undefined);
        assert.equal(body.rawLog, undefined);
        assert.equal(body.content, undefined);
        assert.equal(body.checkpoints, undefined);
        assert.equal(body.receipts, undefined);

        // Prove exact MCP response < 524288 bytes and does not scale with audit-history size (< 4 KiB)
        const serialized = JSON.stringify(body, null, 2);
        const byteLen = Buffer.byteLength(serialized, 'utf8');
        assert.ok(byteLen < 524288, `Must be under 512 KiB cap, got ${byteLen}`);
        assert.ok(byteLen < 4096, `Expected compact bounded response (<4 KiB), got ${byteLen}`);
      } finally {
        await largeServer.stop();
      }
    });

    test('RC07-NEG-058: arc_stage_evidence reports success on a dirty Git working tree. Must accurately report isClean: false', async () => {
      // Create a dirty working tree by adding an unstaged file
      const dirtyFilePath = join(workspaceDir, 'dirty-untracked.txt');
      writeFileSync(dirtyFilePath, 'dirty content\n');

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
          targetStage: 'RC-06',
        });
        assert.ok(!res.isError);
        const body = parseResponse(res);

        assert.equal(body.repository.isClean, false, 'Must accurately report isClean: false');
        assert.equal(body.acceptanceMet, false);
      } finally {
        rmSync(dirtyFilePath, { force: true });
      }
    });

    test('RC07-NEG-059: arc_stage_evidence reports success on an unverified checkpoint signature. Invariant violation; reports unverified / FAILED', async () => {
      // 1. Create a REAL valid signed checkpoint using existing RC-06 checkpoint authority/helpers
      const cpAuditConfig = createAuditConfig(tempRoot, 'cp-corrupt-audit');
      const cpServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-cp', path: workspaceDir }],
        defaultWorkspaceId: 'ws-cp',
        audit: cpAuditConfig,
      });
      await cpServer.start();

      try {
        // Execute an operation to establish durable records
        await cpServer.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {});

        // Seal a real signed checkpoint via segment rotation authority
        await cpServer.auditRuntime.store.rotateNow('SIZE_THRESHOLD');

        // 2. Prove the untouched store verifies successfully
        const untouchedResult = await verifyOfflineStore({
          directory: cpAuditConfig.directory,
          checkpointPublicKeyPath: cpAuditConfig.publicKeyPath,
        });
        assert.equal(untouchedResult.status, 'VERIFIED');
        assert.ok(untouchedResult.checkpoints.checkpointCount >= 1);

        // 3. Tamper ONLY the signature or another signature-bound byte while preserving valid checkpoint schema
        const checkpointFile = join(cpAuditConfig.directory, CHECKPOINT_FILENAME);
        const rawLines = readFileSync(checkpointFile, 'utf8').trim().split('\n').filter(Boolean);
        assert.ok(rawLines.length >= 1);

        const { checkpoint } = parseAndValidateCheckpointLineV1(`${rawLines[0]}\n`);

        // Create a well-formed 64-byte signature that fails Ed25519 verification,
        // with the checkpointHash recomputed so the artifact schema and hash preimage match
        const wrongSignature = Buffer.alloc(64, 0x5a).toString('base64url');
        const tamperedCheckpoint = {
          ...checkpoint,
          signature: wrongSignature,
        };
        tamperedCheckpoint.checkpointHash = computeCheckpointHash(tamperedCheckpoint);
        const tamperedLine = serializeCheckpointV1(tamperedCheckpoint);
        writeFileSync(checkpointFile, tamperedLine);

        // Prove packages/audit rejected the checkpoint through genuine signature verification
        await assert.rejects(
          async () => {
            await verifyCheckpointHistory({
              directory: cpAuditConfig.directory,
              publicKeyPath: cpAuditConfig.publicKeyPath,
            });
          },
          (err) => err.code === 'AUDIT_CHECKPOINT_SIGNATURE_INVALID',
        );

        // 4. Invoke arc_stage_evidence
        const res = await cpServer.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
          targetStage: 'RC-06',
        });
        assert.ok(!res.isError);
        const body = parseResponse(res);

        assert.equal(body.auditLedger.integrity, 'FAILED');
        assert.equal(body.acceptanceMet, false);
        assert.equal(body.references.checkpointHash, undefined);
      } finally {
        await cpServer.stop();
      }
    });

    test('RC07-NEG-060: arc_stage_evidence requested for nonexistent stage name. Rejected with STAGE_NOT_FOUND', async () => {
      for (const invalidStage of ['RC-99', 'RC-08', 'RC-UNKNOWN', 'rc-06', 'stage-1']) {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
          targetStage: invalidStage,
        });
        assert.equal(res.isError, true);
        const body = parseResponse(res);
        assert.equal(body.code, 'STAGE_NOT_FOUND', `Expected STAGE_NOT_FOUND for ${invalidStage}`);
      }
    });

    test('RC07-NEG-061: arc_stage_evidence output exceeds 512 KiB cap. Strict truncation enforced', async () => {
      assert.equal(MAX_STAGE_EVIDENCE_RESPONSE_BYTES, 524288);

      // Verify that exceeding the cap triggers PAYLOAD_TOO_LARGE
      const mockGit = {
        getStatus: async () => ({
          branch: 'b'.repeat(600 * 1024), // 600 KiB branch name
          commitHash: 'a'.repeat(40),
          isClean: true,
        }),
        getLog: async () => ({ commits: [{ hash: 'a'.repeat(40) }] }),
        isTrackedFileAtHead: async () => true,
      };

      const mockAuditRuntime = {
        inspectStageEvidence: async () => ({
          storeId: 'store-1',
          sequence: 1,
          integrity: 'VERIFIED',
          terminalRecordHash: 'hash-1',
          lastCheckpointSequence: null,
        }),
      };

      await assert.rejects(
        async () => {
          await handleArcStageEvidence({
            targetWorkspace: { workspaceId: 'ws-1', rootPath: workspaceDir, isGitRepo: true },
            validatedParams: { targetStage: 'RC-06' },
            gitSubsystem: mockGit,
            auditRuntime: mockAuditRuntime,
          });
        },
        (err) => {
          return err instanceof ArcError && err.code === 'PAYLOAD_TOO_LARGE';
        },
      );
    });
  });

  // =========================================================================
  // 2. Positive Acceptance Flows (RC07-FLOW-14, RC07-FLOW-15)
  // =========================================================================

  describe('RC-07 Task 7: Positive Acceptance Flows (RC07-FLOW-14..15)', () => {
    test('RC07-FLOW-14: Stage Evidence Aggregation (arc_stage_evidence)', async () => {
      // 1. Query evidence for RC-06 (where scripts/verify-rc06.sh is tracked at HEAD)
      const res06 = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
        targetStage: 'RC-06',
      });
      assert.ok(!res06.isError);
      const body06 = parseResponse(res06);

      assert.equal(body06.stage, 'RC-06');
      assert.ok(typeof body06.timestamp === 'string');
      assert.equal(body06.repository.branch, 'feat/rc-07-evidence');
      assert.equal(body06.repository.isClean, true);
      assert.equal(body06.repository.headSha.length, 40);

      assert.equal(body06.auditLedger.integrity, 'VERIFIED');
      assert.ok(body06.auditLedger.sequence > 0);
      assert.ok(body06.auditLedger.storeId.length > 0);

      assert.equal(body06.verification.scriptPresent, true);
      assert.equal(body06.verification.scriptPath, 'scripts/verify-rc06.sh');
      assert.equal(body06.verification.verifiedLocally, false);

      assert.equal(body06.acceptanceMet, false);
      assert.equal(body06.references.auditStoreId, body06.auditLedger.storeId);
      assert.equal(body06.references.terminalRecordHash.length, 64);
      assert.equal(body06.disclaimer, STAGE_EVIDENCE_DISCLAIMER);

      // 2. Query evidence for RC-07 (where scripts/verify-rc07.sh does NOT exist yet at HEAD)
      const res07 = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
        targetStage: 'RC-07',
      });
      assert.ok(!res07.isError);
      const body07 = parseResponse(res07);

      assert.equal(body07.stage, 'RC-07');
      assert.equal(body07.verification.scriptPresent, false);
      assert.equal(body07.verification.scriptPath, undefined);
      assert.equal(body07.verification.verifiedLocally, false);
      assert.equal(body07.acceptanceMet, false);
    });

    test('RC07-FLOW-15: Composite Audit Evidence & Step Tracking', async () => {
      // Tiny passing Node test file
      const flowTestFile = join(workspaceDir, 'flow15.test.js');
      writeFileSync(
        flowTestFile,
        'const test = require("node:test"); test("flow15 test", () => {});\n',
      );

      try {
        // Execute full approval lifecycle for real arc_test
        // 1. arc_test request
        const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_test', {
          testPath: 'flow15.test.js',
        });
        assert.equal(reqRes.isError, true);
        const reqPayload = parseResponse(reqRes);
        assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
        const requestId = reqPayload.details.approvalRequestId;
        assert.ok(requestId);

        // 2. ApprovalStateManager approval
        const approval = server.approvalStateManager.approve(requestId);

        // 3. redemption & real child execution
        const execRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_test', {
          testPath: 'flow15.test.js',
          _arcApproval: {
            requestId,
            token: approval.token,
          },
        });
        assert.ok(!execRes.isError);
        const execBody = parseResponse(execRes);
        assert.equal(execBody.status, 'PASSED');

        // 4. Capture returnedProcessId
        const returnedProcessId = execBody.processId;
        assert.ok(returnedProcessId, 'arc_test must return processId');

        // 5. Establish cryptographic ledger verification through packages/audit
        const verification = await verifyOfflineStore({
          directory: auditConfig.directory,
          checkpointPublicKeyPath: auditConfig.publicKeyPath,
        });
        assert.equal(verification.status, 'VERIFIED');

        // Stream verified records across the persistent ledger
        const sources = listRetainedSegmentSources(auditConfig.directory);
        const verifiedRecords = [];
        for await (const rec of streamRetainedRecords(sources)) {
          verifiedRecords.push(rec);
        }

        // ROOT LIFECYCLE:
        const arcTestStarted = verifiedRecords.filter(
          (r) =>
            r.invocation?.toolName === 'arc_test' &&
            r.lifecycle?.phase === 'STARTED' &&
            r.approval?.requestId === requestId,
        );
        const arcTestCompleted = verifiedRecords.filter(
          (r) =>
            r.invocation?.toolName === 'arc_test' &&
            r.lifecycle?.phase === 'COMPLETED' &&
            r.approval?.requestId === requestId,
        );

        assert.equal(
          arcTestStarted.length,
          1,
          'Exactly one root STARTED record for this invocation',
        );
        assert.equal(
          arcTestCompleted.length,
          1,
          'Exactly one root COMPLETED record for this invocation',
        );

        const startedRec = arcTestStarted[0];
        const completedRec = arcTestCompleted[0];

        assert.equal(
          startedRec.lifecycle.operationId,
          completedRec.lifecycle.operationId,
          'STARTED and COMPLETED must share identical lifecycle.operationId',
        );
        assert.equal(
          startedRec.invocation.payloadHash,
          completedRec.invocation.payloadHash,
          'STARTED and COMPLETED must share identical invocation.payloadHash',
        );
        assert.equal(
          completedRec.execution.status,
          'SUCCESS',
          'COMPLETED.execution.status must be truthful SUCCESS',
        );
        assert.ok(
          !startedRec.lifecycle.parentOperationId,
          'Root invocation must have no parentOperationId',
        );
        assert.ok(
          !completedRec.lifecycle.parentOperationId,
          'Root invocation must have no parentOperationId',
        );

        // No root lifecycle phase FAILED
        const rootFailed = verifiedRecords.filter(
          (r) =>
            r.lifecycle?.operationId === startedRec.lifecycle.operationId &&
            r.lifecycle?.phase === 'FAILED',
        );
        assert.equal(rootFailed.length, 0, 'No root lifecycle phase FAILED must exist');

        // PROCESS EVIDENCE:
        const procRecords = verifiedRecords.filter(
          (r) => r.invocation?.parametersRedacted?.processId === returnedProcessId,
        );
        assert.ok(
          procRecords.length >= 2,
          'Durable process lifecycle records must be present for processId',
        );

        for (const pr of procRecords) {
          assert.equal(
            pr.invocation.parametersRedacted.processId,
            returnedProcessId,
            'Durable process record processId must match returnedProcessId',
          );
          assert.notEqual(
            pr.lifecycle?.operationId,
            startedRec.lifecycle.operationId,
            'Process evidence is a separate audit record from root lifecycle',
          );
        }

        const procEventTypes = procRecords.map((r) => r.invocation.toolName);
        assert.ok(
          procEventTypes.includes('PROCESS_SPAWN_SUCCEEDED'),
          'Must contain PROCESS_SPAWN_SUCCEEDED event for the child process',
        );
        assert.ok(
          procEventTypes.includes('PROCESS_EXITED'),
          'Must contain PROCESS_EXITED event for the child process',
        );

        // STAGE EVIDENCE INTEGRATION:
        const stageRes = await server.executeAuthenticatedToolCall(
          safeActor,
          'arc_stage_evidence',
          {
            targetStage: 'RC-06',
          },
        );
        assert.ok(!stageRes.isError);
        const stageBody = parseResponse(stageRes);
        assert.equal(stageBody.verification.verifiedLocally, false);
        assert.equal(stageBody.acceptanceMet, false);
      } finally {
        rmSync(flowTestFile, { force: true });
      }
    });
  });

  // =========================================================================
  // 3. Invariants, Discovery & Quality Regressions
  // =========================================================================

  describe('RC-07 Task 7: Invariants, Discovery & Quality Regressions', () => {
    test('Discovery: Production tool count is exactly 25 (including arc_stage_evidence)', () => {
      assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
      const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);

      assert.ok(names.includes('arc_stage_evidence'), 'arc_stage_evidence must be advertised');
      assert.ok(names.includes('arc_ci_status'));
      assert.ok(names.includes('arc_test'));
      assert.ok(names.includes('arc_verify'));
      assert.ok(names.includes('arc_review_diff'));
      assert.ok(names.includes('arc_repo_status'));
      assert.ok(names.includes('arc_worktree_status'));

      // Exactly 25 unique names
      const uniqueNames = new Set(names);
      assert.equal(uniqueNames.size, 25);
    });

    test('Discovery: arc_stage_evidence is present in TOOL_SCHEMAS with strict validation', () => {
      assert.ok(TOOL_SCHEMAS.arc_stage_evidence !== undefined);

      // Valid input
      const valid = TOOL_SCHEMAS.arc_stage_evidence.safeParse({
        targetStage: 'RC-06',
        workspaceId: 'ws-1',
      });
      assert.equal(valid.success, true);

      // Missing targetStage rejected
      const missingStage = TOOL_SCHEMAS.arc_stage_evidence.safeParse({
        workspaceId: 'ws-1',
      });
      assert.equal(missingStage.success, false);

      // Extra properties rejected
      const extraProps = TOOL_SCHEMAS.arc_stage_evidence.safeParse({
        targetStage: 'RC-06',
        forbiddenField: 'disallowed',
      });
      assert.equal(extraProps.success, false);
    });

    test('Policy: Built-in declarative policy evaluates arc_stage_evidence as ALLOW', async () => {
      const reg = new WorkspaceRegistry();
      reg.registerWorkspace('ws-task7', workspaceDir);
      const engine = DeclarativePolicyEngine.builtIn(reg);

      const decision = await engine.evaluate({
        toolName: 'arc_stage_evidence',
        workspaceId: 'ws-task7',
      });

      assert.equal(decision.effect, 'ALLOW');
      assert.equal(decision.matchingRuleId, 'builtin-allow-rc07-read-only');
    });

    test('Policy: External declarative policy DENY rule overrides and refuses arc_stage_evidence', async () => {
      const reg = new WorkspaceRegistry();
      reg.registerWorkspace('ws-task7', workspaceDir);

      const denyPolicyYaml = `
version: "1.0"
workspaces:
  - id: ws-task7
rules:
  - id: deny-stage-evidence
    effect: DENY
    tools:
      - arc_stage_evidence
`;
      const engine = DeclarativePolicyEngine.fromExternalText(reg, denyPolicyYaml.trim(), 'yaml');
      const decision = await engine.evaluate({
        toolName: 'arc_stage_evidence',
        workspaceId: 'ws-task7',
      });

      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, 'deny-stage-evidence');
    });

    test('Security: Request with arbitrary parameters rejected with INVALID_REQUEST_SCHEMA', async () => {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
        targetStage: 'RC-06',
        arbitraryField: 'attack-vector',
      });
      assert.equal(res.isError, true);
      const body = parseResponse(res);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('Security: Unregistered workspaceId rejected with WORKSPACE_UNREGISTERED', async () => {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_stage_evidence', {
        targetStage: 'RC-06',
        workspaceId: 'unregistered-workspace-id',
      });
      assert.equal(res.isError, true);
      const body = parseResponse(res);
      assert.equal(body.code, 'WORKSPACE_UNREGISTERED');
    });

    test('Security: Non-git directory rejected with GIT_REPOSITORY_NOT_FOUND', async () => {
      const nonGitDir = join(tempRoot, 'non-git-dir');
      mkdirSync(nonGitDir, { recursive: true });

      const nongitAuditConfig = createAuditConfig(tempRoot, 'nongit-audit');
      const nonGitServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-non-git', path: nonGitDir }],
        defaultWorkspaceId: 'ws-non-git',
        audit: nongitAuditConfig,
      });
      await nonGitServer.start();

      try {
        const res = await nonGitServer.executeAuthenticatedToolCall(
          safeActor,
          'arc_stage_evidence',
          { targetStage: 'RC-06' },
        );
        assert.equal(res.isError, true);
        const body = parseResponse(res);
        assert.equal(body.code, 'GIT_REPOSITORY_NOT_FOUND');
      } finally {
        await nonGitServer.stop();
      }
    });

    test('Static Architecture: stage-evidence.ts contains zero direct child_process or fs imports', () => {
      const source = readFileSync(
        join(process.cwd(), 'apps/mcp-server/src/internal/stage-evidence.ts'),
        'utf8',
      );

      assert.ok(
        !source.includes("from 'child_process'"),
        'Must not import child_process directly in stage-evidence.ts',
      );
      assert.ok(
        !source.includes("from 'node:child_process'"),
        'Must not import node:child_process directly in stage-evidence.ts',
      );
      assert.ok(!source.includes("from 'fs'"), 'Must not import fs directly in stage-evidence.ts');
      assert.ok(
        !source.includes("from 'node:fs'"),
        'Must not import node:fs directly in stage-evidence.ts',
      );
      assert.ok(
        !source.includes("from 'fs/promises'"),
        'Must not import fs/promises directly in stage-evidence.ts',
      );
      assert.ok(
        !source.includes("from 'node:fs/promises'"),
        'Must not import node:fs/promises directly in stage-evidence.ts',
      );
    });
  });
});
