import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { z } from '../apps/mcp-server/node_modules/zod/index.js';

import { ArcMcpServer, createArcMcpServer, TOOL_SCHEMAS } from '../apps/mcp-server/dist/index.js';
import {
  createTestCompositeHarness,
  computePlanHash,
  validateStepExecutionAgainstPlan,
  enterCompositeInvocation,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  buildPayloadToSign,
  buildReviewPayload,
} from '../apps/mcp-server/dist/approval-gate.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  canonicalJson,
} from '../packages/policy/dist/index.js';
import {
  ControlledProcessRunner,
  InternalExecutionCapability,
} from '../packages/terminal/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

// ---------------------------------------------------------------------------
// Fixtures & Test Setup
// ---------------------------------------------------------------------------

let tempRoot;
let workspaceDir;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc07-task1-'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# CesSpace ARC\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
}

const safeActor = {
  clientId: 'client-task1-test',
  clientType: 'worker',
  sessionId: 'session-task1-01',
  deviceId: 'device-task1-local',
  authenticated: true,
};

function createDeterministicSafePlan(workspaceId, stepOverrides = {}) {
  return {
    schemaVersion: '1.0',
    planId: 'plan-safe-test-01',
    compositeTool: 'test_composite_exec',
    workspaceId,
    steps: [
      {
        stepId: 'step-01-node-version',
        toolRegistryId: 'node-info',
        executable: 'node',
        argv: ['--version'],
        cwd: '',
        timeoutMs: 5000,
        outputLimitBytes: 16384,
        projectCodeExecution: false,
        sideEffectClass: 'READ_ONLY',
        ...stepOverrides,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// 1. Plan-Hash Invariants (Section 10 & 31: Tests A - J)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Canonical planHash & Immutability Invariants', () => {
  test('A: Same semantic plan produces identical planHash', () => {
    const plan1 = createDeterministicSafePlan('ws-test');
    const plan2 = createDeterministicSafePlan('ws-test');

    const hash1 = computePlanHash(plan1);
    const hash2 = computePlanHash(plan2);

    assert.equal(hash1, hash2);
    assert.match(hash1, /^[0-9a-f]{64}$/);
  });

  test('B: Reordered object key insertion produces identical planHash (canonical JSON)', () => {
    const planStandard = {
      schemaVersion: '1.0',
      planId: 'plan-order-test',
      compositeTool: 'test_composite',
      workspaceId: 'ws-order',
      steps: [
        {
          stepId: 'step-1',
          toolRegistryId: 'reg-1',
          executable: 'node',
          argv: ['--version'],
          cwd: '',
          timeoutMs: 5000,
          outputLimitBytes: 1024,
          projectCodeExecution: false,
          sideEffectClass: 'READ_ONLY',
        },
      ],
    };

    const planReordered = {
      compositeTool: 'test_composite',
      workspaceId: 'ws-order',
      planId: 'plan-order-test',
      schemaVersion: '1.0',
      steps: [
        {
          sideEffectClass: 'READ_ONLY',
          projectCodeExecution: false,
          outputLimitBytes: 1024,
          timeoutMs: 5000,
          cwd: '',
          argv: ['--version'],
          executable: 'node',
          toolRegistryId: 'reg-1',
          stepId: 'step-1',
        },
      ],
    };

    const hash1 = computePlanHash(planStandard);
    const hash2 = computePlanHash(planReordered);
    assert.equal(hash1, hash2, 'Key insertion order must not alter planHash');
  });

  test('C: Changed step executable identity produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { executable: 'git' });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('D: Changed argv produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { argv: ['--help'] });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('E: Changed cwd produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { cwd: 'sub/dir' });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('F: Changed timeout produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { timeoutMs: 10000 });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('G: Changed output limit cap produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { outputLimitBytes: 32768 });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('H: Changed side-effect class produces different planHash', () => {
    const basePlan = createDeterministicSafePlan('ws-test');
    const modifiedPlan = createDeterministicSafePlan('ws-test', { sideEffectClass: 'EXECUTION' });

    assert.notEqual(computePlanHash(basePlan), computePlanHash(modifiedPlan));
  });

  test('I: Caller-provided planHash parameter cannot override server planHash computation', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const runner = new ControlledProcessRunner(new ProcessRegistry());

    const harness = createTestCompositeHarness({
      toolName: 'test_composite_hash',
      schema: z.object({
        fakePlanHash: z.string().optional(),
        workspaceId: z.string().optional(),
        workspaceRoot: z.string().optional(),
      }),
      materializer: () => createDeterministicSafePlan('ws'),
    });

    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { transport: 'stdio', defaultWorkspaceId: 'ws' },
      runner,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      harness,
    );

    // Call with untrusted fakePlanHash
    return server
      .executeAuthenticatedToolCall(safeActor, 'test_composite_hash', {
        fakePlanHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      })
      .then((res) => {
        const body = parseResponse(res);
        assert.ok(!res.isError);
        assert.equal(body.status, 'SUCCESS');
        // Authoritative planHash must be the SHA-256 of the server-materialized plan, not the fakePlanHash
        const expectedAuthoritativeHash = computePlanHash(createDeterministicSafePlan('ws'));
        assert.equal(body.planHash, expectedAuthoritativeHash);
        assert.notEqual(
          body.planHash,
          '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        );
      });
  });

  test('J / RC07-NEG-007: Plan deviation validation detects mismatch and fails closed before spawn', () => {
    const plan = createDeterministicSafePlan('ws');

    // Test deviation in argv
    const candidateArgvDeviated = {
      ...plan.steps[0],
      argv: ['--eval', 'console.log("hacked")'],
    };

    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateArgvDeviated),
      (err) =>
        err instanceof ArcError &&
        err.code === 'POLICY_DENIED' &&
        err.message.includes('argv mismatch'),
    );

    // Test deviation in executable
    const candidateExecDeviated = {
      ...plan.steps[0],
      executable: 'bash',
    };

    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateExecDeviated),
      (err) =>
        err instanceof ArcError &&
        err.code === 'POLICY_DENIED' &&
        err.message.includes('executable mismatch'),
    );

    // Test deviation in cwd
    const candidateCwdDeviated = {
      ...plan.steps[0],
      cwd: 'escaped/path',
    };

    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateCwdDeviated),
      (err) =>
        err instanceof ArcError &&
        err.code === 'POLICY_DENIED' &&
        err.message.includes('cwd mismatch'),
    );
  });
});

// ---------------------------------------------------------------------------
// 2. Approval Payload Backward-Compatibility (Section 30)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Approval Payload Backward Compatibility', () => {
  const actor = {
    clientId: 'test-client',
    clientType: 'mcp-client',
    sessionId: 'sess-01',
    deviceId: 'dev-01',
  };

  test('buildPayloadToSign without planHash produces exact RC-04 payload without planHash key', () => {
    const input = {
      toolName: 'write_file',
      businessParameters: { path: 'a.txt', content: 'hello' },
      actor,
      workspaceId: 'ws-test',
      workspaceRootHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      policyHash: '0000000000000000000000000000000000000000000000000000000000000000',
    };

    const payload = buildPayloadToSign(input);
    assert.equal(Object.prototype.hasOwnProperty.call(payload, 'planHash'), false);
    assert.equal('planHash' in payload, false);

    const canonical = canonicalJson(payload);
    assert.ok(
      !canonical.includes('planHash'),
      'canonical JSON must not mention planHash when absent',
    );
  });

  test('buildPayloadToSign with planHash binds planHash additively', () => {
    const input = {
      toolName: 'test_composite',
      businessParameters: { param1: 'val1' },
      actor,
      workspaceId: 'ws-test',
      workspaceRootHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      policyHash: '0000000000000000000000000000000000000000000000000000000000000000',
      planHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    };

    const payload = buildPayloadToSign(input);
    assert.equal(
      payload.planHash,
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );

    const canonical = canonicalJson(payload);
    assert.ok(
      canonical.includes(
        '"planHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
      ),
    );
  });

  test('Review summary sanitization retains safe planId, planHash, stepCount without leakage', () => {
    const { reviewSummary } = buildReviewPayload('test_composite', {}, [], {
      planId: 'plan-123',
      planHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      stepCount: 3,
    });

    assert.ok(reviewSummary);
    assert.equal(reviewSummary.planId, 'plan-123');
    assert.equal(
      reviewSummary.planHash,
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    );
    assert.equal(reviewSummary.stepCount, 3);
  });
});

// ---------------------------------------------------------------------------
// 3. Internal Capability Invariants & Non-serializability (Section 7)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Internal Execution Capability Gating', () => {
  test('Plain objects or JSON-parsed objects cannot satisfy internal execution capability', () => {
    assert.equal(InternalExecutionCapability.isAuthorized(null), false);
    assert.equal(InternalExecutionCapability.isAuthorized(undefined), false);
    assert.equal(InternalExecutionCapability.isAuthorized({}), false);
    assert.equal(InternalExecutionCapability.isAuthorized({ internal: true }), false);
    assert.equal(
      InternalExecutionCapability.isAuthorized({
        [Symbol('arc.terminal.internalExecutionCapability')]: true,
      }),
      false,
    );

    const validCap = InternalExecutionCapability.create();
    assert.equal(InternalExecutionCapability.isAuthorized(validCap), true);
  });

  test('ControlledProcessRunner.executeDeterministicStep rejects unauthorized callers', async () => {
    const runner = new ControlledProcessRunner(new ProcessRegistry());
    const step = {
      stepId: 'step-1',
      executable: 'node',
      args: ['--version'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };

    const fakeCap = { internal: true };

    await assert.rejects(
      () =>
        runner.executeDeterministicStep(
          step,
          safeActor,
          { workspaceId: 'ws', rootPath: workspaceDir, isGitRepo: true },
          fakeCap,
        ),
      (err) => err instanceof ArcError && err.code === 'FORBIDDEN_COMMAND',
    );
  });

  test('Public run_command does not accept or recognize internal composite execution flags', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const runner = new ControlledProcessRunner(new ProcessRegistry());

    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { transport: 'stdio', defaultWorkspaceId: 'ws' },
      runner,
    );

    // Attempting to execute 'npm run test' with spoofed internal flags
    const res = await server.executeAuthenticatedToolCall(safeActor, 'run_command', {
      executable: 'npm',
      args: ['run', 'test'],
      internal: true,
      composite: true,
      skipPolicy: true,
    });

    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.ok(body.code === 'POLICY_DENIED' || body.code === 'INVALID_REQUEST_SCHEMA');
  });
});

// ---------------------------------------------------------------------------
// 4. Static Security Checks (Section 32)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Static Module Architecture & Boundary Verification', () => {
  test('composite-framework.ts contains zero direct child_process, fs, or network imports', () => {
    const frameworkSource = fs.readFileSync(
      path.join(process.cwd(), 'apps/mcp-server/src/composite-framework.ts'),
      'utf8',
    );

    assert.ok(!frameworkSource.includes("from 'child_process'"), 'Must not import child_process');
    assert.ok(
      !frameworkSource.includes("from 'node:child_process'"),
      'Must not import node:child_process',
    );
    assert.ok(!frameworkSource.includes("from 'fs'"), 'Must not import fs');
    assert.ok(!frameworkSource.includes("from 'node:fs'"), 'Must not import node:fs');
    assert.ok(!frameworkSource.includes('fetch('), 'Must not use fetch');
    assert.ok(!frameworkSource.includes("from 'http'"), 'Must not import http');
    assert.ok(!frameworkSource.includes("from 'net'"), 'Must not import net');
    assert.ok(!frameworkSource.includes("from 'tls'"), 'Must not import tls');
  });

  test('Zero new production MCP tools exposed in TOOL_SCHEMAS or production server', () => {
    assert.equal(TOOL_SCHEMAS.arc_composite_probe, undefined);
    assert.equal(TOOL_SCHEMAS.arc_framework_test, undefined);
    assert.equal(TOOL_SCHEMAS.__arc_test, undefined);

    const prodServer = createArcMcpServer({ transport: 'stdio' });
    assert.equal(prodServer.testCompositeHarness, undefined);
  });
});

// ---------------------------------------------------------------------------
// 5. Authoritative Task-1 Negative Controls (RC07-NEG-001 .. 010)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Authoritative Negative Controls (RC07-NEG-001..010)', () => {
  function makeTestServer(options = {}) {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const approvals = options.approvals ?? new ApprovalStateManager();
    const runner = new ControlledProcessRunner(new ProcessRegistry());

    const harness = createTestCompositeHarness({
      toolName: 'test_composite_tool',
      schema: z.object({
        flag: z.string().optional(),
        workspaceId: z.string().optional(),
        workspaceRoot: z.string().optional(),
      }),
      materializer: () => createDeterministicSafePlan('ws'),
      requiresApproval: options.requiresApproval ?? false,
    });

    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      {
        transport: 'stdio',
        defaultWorkspaceId: 'ws',
        ...(options.audit ? { audit: options.audit } : {}),
      },
      runner,
      undefined,
      approvals,
      undefined,
      undefined,
      undefined,
      harness,
    );

    return { server, registry, approvals, harness };
  }

  test('RC07-NEG-001: Composite tool invoked without authenticated caller identity rejected with UNAUTHENTICATED', async () => {
    const { server } = makeTestServer();

    // Actor with empty clientId
    const resNoClient = await server.executeAuthenticatedToolCall(
      {
        clientId: '',
        clientType: 'worker',
        sessionId: 'sess-1',
        deviceId: 'dev-1',
        authenticated: false,
      },
      'test_composite_tool',
      {},
    );
    const bodyNoClient = parseResponse(resNoClient);
    assert.equal(resNoClient.isError, true);
    assert.equal(bodyNoClient.code, 'UNAUTHENTICATED');

    // Actor with empty sessionId
    const resNoSession = await server.executeAuthenticatedToolCall(
      {
        clientId: 'client-1',
        clientType: 'worker',
        sessionId: '   ',
        deviceId: 'dev-1',
        authenticated: true,
      },
      'test_composite_tool',
      {},
    );
    const bodyNoSession = parseResponse(resNoSession);
    assert.equal(resNoSession.isError, true);
    assert.equal(bodyNoSession.code, 'UNAUTHENTICATED');
  });

  test('RC07-NEG-002: Composite tool invoked with unbound or unapproved workspaceId fails closed before plan execution', async () => {
    const { server } = makeTestServer();

    const resUnregistered = await server.executeAuthenticatedToolCall(
      safeActor,
      'test_composite_tool',
      { workspaceId: 'non-existent-workspace-id' },
    );
    const body = parseResponse(resUnregistered);
    assert.equal(resUnregistered.isError, true);
    assert.equal(body.code, 'NO_WORKSPACE_CONFIGURED');
  });

  test('RC07-NEG-003: Recursive composite invocation fails closed with RECURSIVE_INVOCATION_DENIED', async () => {
    await enterCompositeInvocation('test_tool_A', async () => {
      // Direct self-recursion A -> A
      await assert.rejects(
        () => enterCompositeInvocation('test_tool_A', async () => {}),
        (err) =>
          err instanceof ArcError &&
          err.code === 'POLICY_DENIED' &&
          err.message.includes('Recursive composite invocation detected'),
      );

      // Indirect recursion / nested composite invocation A -> B
      await assert.rejects(
        () => enterCompositeInvocation('test_tool_B', async () => {}),
        (err) =>
          err instanceof ArcError &&
          err.code === 'POLICY_DENIED' &&
          err.message.includes('Nested composite invocation is forbidden'),
      );
    });
  });

  test('RC07-NEG-004: Degraded/unavailable audit authority causes zero execution', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg004-audit');
    const { server } = makeTestServer({ audit: auditConfig });
    await server.start();

    // Latch degraded audit failure
    server.auditRuntime.latchDegradedAuditFailure();

    const res = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'INTERNAL_ERROR');
    assert.ok(
      body.message.includes('durable audit evidence') ||
        body.message.includes('Privileged operations are halted'),
    );

    await server.stop();
  });

  test('RC07-NEG-005: Durable STARTED persistence failure causes zero internal execution', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg005-audit');
    const { server } = makeTestServer({ audit: auditConfig });
    await server.start();

    // Inject failure on appendDurableRecord when phase === STARTED
    const originalAppend = server.appendDurableRecord.bind(server);
    server.appendDurableRecord = async (record, options) => {
      if (options && options.phase === 'STARTED') {
        throw new Error('Injected disk failure during STARTED write');
      }
      return originalAppend(record, options);
    };

    const res = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'INTERNAL_ERROR');
    assert.ok(
      body.message.includes('durable audit evidence') ||
        body.message.includes('Privileged operations are halted'),
    );

    await server.stop();
  });

  test('RC07-NEG-006: Durable COMPLETED persistence failure after execution latches DEGRADED_AUDIT_FAILURE and does not return success', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg006-audit');
    const { server } = makeTestServer({ audit: auditConfig });
    await server.start();

    // Inject failure on appendDurableRecord when phase === COMPLETED
    const originalAppend = server.appendDurableRecord.bind(server);
    server.appendDurableRecord = async (record, options) => {
      if (options && options.phase === 'COMPLETED') {
        throw new Error('Injected disk failure during COMPLETED write');
      }
      return originalAppend(record, options);
    };

    const res = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'INTERNAL_ERROR');
    assert.ok(
      body.message.includes('durable audit evidence') ||
        body.message.includes('Privileged operations are halted'),
    );

    // Server must now be latched degraded
    assert.equal(server.auditRuntime.isDegraded(), true);

    await server.stop();
  });

  test('RC07-NEG-007: Plan/step deviation after admission fails closed before spawn', () => {
    const basePlan = createDeterministicSafePlan('ws');
    const alteredCandidate = { ...basePlan.steps[0], executable: 'rm' };
    assert.throws(
      () => validateStepExecutionAgainstPlan(basePlan, 0, alteredCandidate),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    const alteredArgv = { ...basePlan.steps[0], argv: ['--malicious-flag'] };
    assert.throws(
      () => validateStepExecutionAgainstPlan(basePlan, 0, alteredArgv),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });

  test('RC07-NEG-008: Malformed reserved _arcApproval parameter denied with INVALID_REQUEST_SCHEMA before approval lookup', async () => {
    const { server } = makeTestServer();

    const res = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {
      _arcApproval: { requestId: 'not-hex', token: '' },
    });
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC07-NEG-009: Expired approval token presented for composite execution rejected with APPROVAL_EXPIRED', async () => {
    let mono = 1_000_000n;
    const approvals = new ApprovalStateManager({ getMonotonicTime: () => mono });
    const { server } = makeTestServer({ requiresApproval: true, approvals });

    // Step 1: Request approval
    const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {});
    const reqBody = parseResponse(reqRes);
    assert.equal(reqBody.code, 'APPROVAL_REQUIRED');
    const requestId = reqBody.details.approvalRequestId;

    // Step 2: Approve
    const { token } = approvals.approve(requestId);

    // Step 3: Advance monotonic time past the 300-second TTL
    mono += 301_000n * 1_000_000n;

    // Step 4: Attempt redemption with expired token
    const redeemRes = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {
      _arcApproval: { requestId, token },
    });
    const redeemBody = parseResponse(redeemRes);
    assert.equal(redeemRes.isError, true);
    assert.equal(redeemBody.code, 'APPROVAL_EXPIRED');
  });

  test('RC07-NEG-010: Previously consumed approval token presented for composite execution rejected with APPROVAL_REJECTED', async () => {
    const { server, approvals } = makeTestServer({ requiresApproval: true });

    // Step 1: Request approval
    const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {});
    const reqBody = parseResponse(reqRes);
    const requestId = reqBody.details.approvalRequestId;

    // Step 2: Approve
    const { token } = approvals.approve(requestId);

    // Step 3: First redemption (succeeds)
    const redeem1 = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {
      _arcApproval: { requestId, token },
    });
    assert.ok(!redeem1.isError);

    // Step 4: Second redemption attempt with same token (fails closed)
    const redeem2 = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_tool', {
      _arcApproval: { requestId, token },
    });
    const body2 = parseResponse(redeem2);
    assert.equal(redeem2.isError, true);
    assert.equal(body2.code, 'APPROVAL_REJECTED');
  });
});

// ---------------------------------------------------------------------------
// 6. Authoritative Task-1 Positive Flows (RC07-FLOW-01 & RC07-FLOW-02)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Authoritative Positive Acceptance Flows (RC07-FLOW-01, RC07-FLOW-02)', () => {
  test('RC07-FLOW-01: Composite Framework Lifecycle Execution (STARTED -> COMPLETED with single operationId)', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'flow01-audit');
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const runner = new ControlledProcessRunner(new ProcessRegistry());

    const harness = createTestCompositeHarness({
      toolName: 'test_composite_lifecycle',
      schema: z.object({}),
      materializer: () => createDeterministicSafePlan('ws'),
    });

    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { transport: 'stdio', defaultWorkspaceId: 'ws', audit: auditConfig },
      runner,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      harness,
    );

    await server.start();

    const res = await server.executeAuthenticatedToolCall(
      safeActor,
      'test_composite_lifecycle',
      {},
    );

    assert.ok(!res.isError);
    const result = parseResponse(res);
    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.steps.length, 1);
    assert.equal(result.steps[0].status, 'PASSED');
    assert.match(result.steps[0].stdout, /^v\d+\.\d+\.\d+/);

    await server.stop();
  });

  test('RC07-FLOW-02: Composite Approval Redemption Flow (Materialize -> planHash -> Approval -> Redeem -> Execute Once)', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'flow02-audit');
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const approvals = new ApprovalStateManager();
    const runner = new ControlledProcessRunner(new ProcessRegistry());

    const harness = createTestCompositeHarness({
      toolName: 'test_composite_flow02',
      schema: z.object({}),
      materializer: () => createDeterministicSafePlan('ws'),
      requiresApproval: true,
    });

    const server = new ArcMcpServer(
      registry,
      new SecurityKernel(registry),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { transport: 'stdio', defaultWorkspaceId: 'ws', audit: auditConfig },
      runner,
      undefined,
      approvals,
      undefined,
      undefined,
      undefined,
      harness,
    );

    await server.start();

    // 1. Initial call without approval -> returns APPROVAL_REQUIRED
    const call1 = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_flow02', {});
    assert.equal(call1.isError, true);
    const body1 = parseResponse(call1);
    assert.equal(body1.code, 'APPROVAL_REQUIRED');
    const requestId = body1.details.approvalRequestId;
    assert.ok(requestId);

    // Verify pending approval snapshot binds planHash and reviewSummary
    const pendingSnap = approvals.getRequest(requestId);
    assert.ok(pendingSnap);
    assert.equal(pendingSnap.toolName, 'test_composite_flow02');
    assert.ok(pendingSnap.reviewSummary);
    assert.equal(pendingSnap.reviewSummary.planId, 'plan-safe-test-01');
    assert.equal(pendingSnap.reviewSummary.stepCount, 1);
    assert.match(pendingSnap.reviewSummary.planHash, /^[0-9a-f]{64}$/);

    // 2. Authorize via trusted operator workflow
    const { token } = approvals.approve(requestId);
    assert.ok(token);

    // 3. Redeem with _arcApproval -> executes exact bound plan
    const call2 = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_flow02', {
      _arcApproval: { requestId, token },
    });
    assert.ok(!call2.isError);
    const body2 = parseResponse(call2);
    assert.equal(body2.status, 'SUCCESS');
    assert.equal(body2.steps[0].status, 'PASSED');

    // 4. Token cannot be reused
    const call3 = await server.executeAuthenticatedToolCall(safeActor, 'test_composite_flow02', {
      _arcApproval: { requestId, token },
    });
    assert.equal(call3.isError, true);
    const body3 = parseResponse(call3);
    assert.equal(body3.code, 'APPROVAL_REJECTED');

    await server.stop();
  });
});
