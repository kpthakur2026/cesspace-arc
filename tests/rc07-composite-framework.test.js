import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { z } from '../apps/mcp-server/node_modules/zod/index.js';

import {
  ArcMcpServer,
  createArcMcpServer,
  TOOL_SCHEMAS,
  ALL_TOOL_DEFINITIONS,
} from '../apps/mcp-server/dist/index.js';
import {
  computePlanHash,
  deepFreezePlan,
  validateStepExecutionAgainstPlan,
  validateStepAgainstRegistry,
  enterCompositeInvocation,
  createProductionDeterministicRegistry,
  DeterministicExecutionRegistry,
  executeCompositePlan,
  isAuthorizedDeterministicExecutor,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  createTestCompositeHarness,
  createTestDeterministicRegistry,
  TEST_NODE_VERSION_REGISTRY_ID,
  attachTestCompositeHarness,
  getInternalExecutorForTest,
  getDeterministicRegistryForTest,
} from '../apps/mcp-server/dist/internal/composite-testing.js';
import { createServerDeterministicExecutor } from '../apps/mcp-server/dist/internal/execution-authority.js';
import { SERVER_INTERNAL_ACCESS } from '../apps/mcp-server/dist/internal/server-seam.js';
import { buildPayloadToSign, buildReviewPayload } from '../apps/mcp-server/dist/approval-gate.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  canonicalJson,
  RC07_COMPOSITE_TOOLS,
} from '../packages/policy/dist/index.js';
import {
  ControlledProcessRunner,
  InternalExecutionCapability,
} from '../packages/terminal/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import {
  ArcError,
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPrivateKeyB64,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
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
    compositeTool: 'arc_verify',
    workspaceId,
    steps: [
      {
        stepId: 'step-01-node-version',
        toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
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

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    publicKeyB64: exportPublicKeyB64(publicKey),
    privateKeyB64: exportPrivateKeyB64(privateKey),
  };
}

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
      reject(new Error('connection ended before frame arrived'));
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

async function adminRequest(endpoint, privateKey, method, params = {}) {
  const socket = net.createConnection(endpoint);
  await new Promise((resolve) => socket.once('connect', resolve));
  const challengeFrame = await readOneFrame(socket, 4096);
  const challenge = JSON.parse(challengeFrame.toString('utf8'));

  const canonical = encodeAdminPayload({
    protocol: ADMIN_PROTOCOL_VERSION,
    challengeId: challenge.challengeId,
    method,
    params,
  });
  const payloadBytes = Buffer.from(canonical, 'utf8');
  const signature = signAdminPayload(
    privateKey,
    challenge.challengeId,
    challenge.nonce,
    payloadBytes,
  );
  const envelope = {
    payload: payloadBytes.toString('base64'),
    signature: signature.toString('base64'),
  };

  socket.write(`${JSON.stringify(envelope)}\n`);
  const responseFrame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(responseFrame.toString('utf8'));
}

function makeTestServer(options = {}) {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', workspaceDir);
  const approvals = options.approvals ?? new ApprovalStateManager();
  const processRegistry = new ProcessRegistry();
  const processEvents = [];
  processRegistry.registerLifecycleSink({
    onProcessEvent(evt) {
      processEvents.push(evt);
    },
  });
  const terminalSubsystem = new ControlledProcessRunner(processRegistry);
  const internalExecutor = createServerDeterministicExecutor(terminalSubsystem);

  const policyEffect = options.policyEffect ?? 'ALLOW';
  const policyRuleId = options.policyRuleId ?? 'test-rule-verify';
  const policyConfig = options.policyConfig ?? {
    format: 'json',
    sourceText: JSON.stringify({
      version: '1.0',
      workspaces: [{ id: 'ws' }],
      rules: [
        {
          id: policyRuleId,
          description: `Test policy for arc_verify (${policyEffect})`,
          effect: policyEffect,
          tools: ['arc_verify'],
        },
      ],
    }),
  };

  const harness = createTestCompositeHarness({
    toolName: options.toolName ?? 'arc_verify',
    schema:
      options.schema ??
      z.object({
        flag: z.string().optional(),
        workspaceId: z.string().optional(),
        workspaceRoot: z.string().optional(),
        fakePlanHash: z.string().optional(),
      }),
    materializer: options.materializer ?? (() => createDeterministicSafePlan('ws')),
    registry: options.deterministicRegistry,
    testPostAdmissionMutationHook: options.testPostAdmissionMutationHook,
  });

  const auditLogger = new AuditLogger();

  let adminIpcServer = options.adminIpcServer;
  if (!adminIpcServer && options.adminSocket && options.operatorPublicKeyB64) {
    adminIpcServer = new AdminIpcServer({
      endpoint: options.adminSocket,
      operatorPublicKeyB64: options.operatorPublicKeyB64,
      approvalStateManager: approvals,
      auditLogger,
    });
  }

  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry, processRegistry),
    auditLogger,
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'stdio',
      defaultWorkspaceId: 'ws',
      policy: policyConfig,
      ...(options.audit ? { audit: options.audit } : {}),
      ...(options.admin ? { admin: options.admin } : {}),
    },
    terminalSubsystem,
    processRegistry,
    approvals,
    adminIpcServer,
    undefined,
    undefined,
  );

  if (!options.omitHarness) {
    attachTestCompositeHarness(server, harness);
  }
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!options.omitInternalExecutor) {
    access?.setInternalDeterministicExecutor(internalExecutor);
  } else {
    access?.setInternalDeterministicExecutor(undefined);
  }
  if (options.deterministicRegistry) {
    access?.setDeterministicRegistry(options.deterministicRegistry);
  }

  return {
    server,
    registry,
    approvals,
    harness,
    processRegistry,
    processEvents,
    terminalSubsystem,
    internalExecutor,
    auditLogger,
    adminIpcServer,
  };
}

// ---------------------------------------------------------------------------
// 1. Plan-Hash Invariants & Immutability (Section 10 & 31: Tests A - J)
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
      compositeTool: 'arc_verify',
      workspaceId: 'ws-order',
      steps: [
        {
          stepId: 'step-1',
          toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
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
      compositeTool: 'arc_verify',
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
          toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
          stepId: 'step-1',
        },
      ],
    };

    const hash1 = computePlanHash(planStandard);
    const hash2 = computePlanHash(planReordered);

    assert.equal(hash1, hash2);
  });

  test('C: Step field mutation changes planHash', () => {
    const basePlan = createDeterministicSafePlan('ws');
    const baseHash = computePlanHash(basePlan);

    // Mutation 1: stepId
    const mutatedStepId = createDeterministicSafePlan('ws', { stepId: 'step-altered' });
    assert.notEqual(computePlanHash(mutatedStepId), baseHash);

    // Mutation 2: toolRegistryId
    const mutatedRegistryId = createDeterministicSafePlan('ws', { toolRegistryId: 'diff-reg' });
    assert.notEqual(computePlanHash(mutatedRegistryId), baseHash);

    // Mutation 3: executable
    const mutatedExec = createDeterministicSafePlan('ws', { executable: '/custom/node' });
    assert.notEqual(computePlanHash(mutatedExec), baseHash);

    // Mutation 4: argv
    const mutatedArgv = createDeterministicSafePlan('ws', { argv: ['-v'] });
    assert.notEqual(computePlanHash(mutatedArgv), baseHash);

    // Mutation 5: cwd
    const mutatedCwd = createDeterministicSafePlan('ws', { cwd: 'subdir' });
    assert.notEqual(computePlanHash(mutatedCwd), baseHash);

    // Mutation 6: timeoutMs
    const mutatedTimeout = createDeterministicSafePlan('ws', { timeoutMs: 9999 });
    assert.notEqual(computePlanHash(mutatedTimeout), baseHash);

    // Mutation 7: outputLimitBytes
    const mutatedOutput = createDeterministicSafePlan('ws', { outputLimitBytes: 32768 });
    assert.notEqual(computePlanHash(mutatedOutput), baseHash);

    // Mutation 8: projectCodeExecution
    const mutatedProjectCode = createDeterministicSafePlan('ws', { projectCodeExecution: true });
    assert.notEqual(computePlanHash(mutatedProjectCode), baseHash);

    // Mutation 9: sideEffectClass
    const mutatedSideEffect = createDeterministicSafePlan('ws', { sideEffectClass: 'EXECUTION' });
    assert.notEqual(computePlanHash(mutatedSideEffect), baseHash);
  });

  test('D: Step order mutation changes planHash', () => {
    const stepA = {
      stepId: 'step-A',
      toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
      executable: 'node',
      argv: ['--version'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };
    const stepB = {
      stepId: 'step-B',
      toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
      executable: 'node',
      argv: ['--version'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };

    const planAB = {
      schemaVersion: '1.0',
      planId: 'plan-order',
      compositeTool: 'arc_verify',
      workspaceId: 'ws',
      steps: [stepA, stepB],
    };

    const planBA = {
      schemaVersion: '1.0',
      planId: 'plan-order',
      compositeTool: 'arc_verify',
      workspaceId: 'ws',
      steps: [stepB, stepA],
    };

    assert.notEqual(computePlanHash(planAB), computePlanHash(planBA));
  });

  test('E: Step addition/removal changes planHash', () => {
    const base = createDeterministicSafePlan('ws');
    const baseHash = computePlanHash(base);

    const withSecondStep = {
      ...base,
      steps: [
        base.steps[0],
        {
          ...base.steps[0],
          stepId: 'step-02',
        },
      ],
    };

    assert.notEqual(computePlanHash(withSecondStep), baseHash);
  });

  test('F: Non-plan ambient parameters (PATH, process.env) do NOT enter planHash', () => {
    const originalPath = process.env.PATH;
    const plan = createDeterministicSafePlan('ws');
    const hash1 = computePlanHash(plan);

    try {
      process.env.PATH = '/tmp/fake/bin:' + originalPath;
      process.env.CESSPACE_INJECTED_TEST_ENV = 'secret';
      const hash2 = computePlanHash(plan);
      assert.equal(hash1, hash2, 'planHash must be invariant to ambient process.env');
    } finally {
      process.env.PATH = originalPath;
      delete process.env.CESSPACE_INJECTED_TEST_ENV;
    }
  });

  test('G: Canonical plan preserves deep immutability (deepFreezePlan)', () => {
    const plan = createDeterministicSafePlan('ws');
    const frozen = deepFreezePlan(plan);

    assert.throws(() => {
      frozen.planId = 'mutated';
    }, TypeError);

    assert.throws(() => {
      frozen.steps.push({ ...frozen.steps[0], stepId: 'step-injected' });
    }, TypeError);

    assert.throws(() => {
      frozen.steps[0].argv.push('--injected');
    }, TypeError);
  });

  test('H: Plan verification matches identical valid candidate without error', () => {
    const plan = createDeterministicSafePlan('ws');
    assert.doesNotThrow(() => {
      validateStepExecutionAgainstPlan(plan, 0, plan.steps[0]);
    });
  });

  test('I / Section 8 & 33F: Caller-supplied fakePlanHash is ignored; server derives authoritative planHash', async () => {
    const { server } = makeTestServer();

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      fakePlanHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });

    const body = parseResponse(res);
    assert.ok(!res.isError);
    assert.equal(body.status, 'SUCCESS');
    const expectedAuthoritativeHash = computePlanHash(createDeterministicSafePlan('ws'));
    assert.equal(body.planHash, expectedAuthoritativeHash);
    assert.notEqual(
      body.planHash,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    );
  });

  test('J / RC07-NEG-007: Plan deviation validation detects mismatch and fails closed', () => {
    const plan = createDeterministicSafePlan('ws');

    // Test deviation in argv
    const candidateArgvDeviated = {
      ...plan.steps[0],
      argv: ['--eval', 'console.log("hacked")'],
    };
    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateArgvDeviated),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    // Test deviation in executable
    const candidateExecDeviated = {
      ...plan.steps[0],
      executable: 'bash',
    };
    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateExecDeviated),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    // Test deviation in cwd
    const candidateCwdDeviated = {
      ...plan.steps[0],
      cwd: 'escaped/path',
    };
    assert.throws(
      () => validateStepExecutionAgainstPlan(plan, 0, candidateCwdDeviated),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });
});

// ---------------------------------------------------------------------------
// 2. Approval Payload Backward-Compatibility (Section 17 & 30)
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
      toolName: 'arc_verify',
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
    const { reviewSummary } = buildReviewPayload('arc_verify', {}, [], {
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
// 3. Internal Capability Invariants & Non-serializability (Section 3 & 34)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Internal Execution Capability Gating', () => {
  test('Plain objects, null, undefined, or spoofed symbols cannot satisfy internal execution capability', () => {
    assert.equal(isAuthorizedDeterministicExecutor(null), false);
    assert.equal(isAuthorizedDeterministicExecutor(undefined), false);
    assert.equal(isAuthorizedDeterministicExecutor({}), false);
    assert.equal(isAuthorizedDeterministicExecutor({ internal: true }), false);
    assert.equal(
      isAuthorizedDeterministicExecutor({
        [Symbol.for('arc.terminal.internalExecutionCapability')]: true,
      }),
      false,
    );
  });

  test('Ordinary caller cannot invoke internal executor through public terminal API', () => {
    const runner = new ControlledProcessRunner(new ProcessRegistry());
    assert.equal(typeof runner.getInternalExecutionCapability, 'undefined');
    assert.equal(typeof runner.executeDeterministicStep, 'undefined');
    assert.equal(typeof runner._executeInternalStepCore, 'undefined');
    assert.equal(typeof ControlledProcessRunner.prototype._executeInternalStepCore, 'undefined');
  });

  test('InternalExecutionCapability possesses no public .create() and constructor throws TypeError', () => {
    assert.equal(typeof InternalExecutionCapability.create, 'undefined');
    assert.throws(() => {
      new InternalExecutionCapability();
    }, TypeError);
  });

  test('Serialized/deserialized values fail authority check', () => {
    const runner = new ControlledProcessRunner(new ProcessRegistry());
    const internalExecutor = createServerDeterministicExecutor(runner);
    assert.equal(isAuthorizedDeterministicExecutor(internalExecutor), true);

    const serialized = JSON.stringify(internalExecutor);
    const parsed = JSON.parse(serialized);
    assert.equal(isAuthorizedDeterministicExecutor(parsed), false);
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
// 4. Closed Deterministic Execution Registry (Section 7, 8, 33)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Closed Deterministic Execution Registry', () => {
  test('A: Unknown registryId fails closed before spawn', () => {
    const registry = createTestDeterministicRegistry();
    const badStep = {
      stepId: 'step-bad',
      toolRegistryId: 'unregistered-registry-id',
      executable: 'node',
      argv: ['--version'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };

    assert.throws(
      () => validateStepAgainstRegistry(badStep, registry),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });

  test('B: Executable mismatch against registry fails closed before spawn', () => {
    const registry = createTestDeterministicRegistry();
    const badStep = {
      stepId: 'step-exec-mismatch',
      toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
      executable: '/bin/sh',
      argv: ['--version'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };

    assert.throws(
      () => validateStepAgainstRegistry(badStep, registry),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });

  test('C: Argv mismatch against registry fails closed before spawn', () => {
    const registry = createTestDeterministicRegistry();
    const badStep = {
      stepId: 'step-argv-mismatch',
      toolRegistryId: TEST_NODE_VERSION_REGISTRY_ID,
      executable: 'node',
      argv: ['-e', 'process.exit(1)'],
      cwd: '',
      timeoutMs: 5000,
      outputLimitBytes: 1024,
      projectCodeExecution: false,
      sideEffectClass: 'READ_ONLY',
    };

    assert.throws(
      () => validateStepAgainstRegistry(badStep, registry),
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });

  test('D & E: Client-supplied executable and argv parameters cannot override registry', async () => {
    const { server, processRegistry } = makeTestServer();

    // Caller attempts to supply malicious executable and args in client parameters
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      executable: '/bin/bash',
      args: ['-c', 'id'],
    });

    const body = parseResponse(res);
    assert.ok(!res.isError);
    assert.equal(body.status, 'SUCCESS');
    // Executed step was the registry-derived node version, NOT /bin/bash
    assert.equal(body.steps[0].toolRegistryId, TEST_NODE_VERSION_REGISTRY_ID);
    assert.match(body.steps[0].stdout, /^v\d+\.\d+\.\d+/);

    const procs = processRegistry.listProcesses();
    assert.equal(procs.length, 1);
    assert.equal(procs[0].executable, 'node');
    assert.deepEqual(procs[0].sanitizedArgs, ['--version']);
  });

  test('F: Workspace contents / package.json cannot define a new executable registry entry', () => {
    const pkgPath = path.join(workspaceDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify({ scripts: { malicious: 'rm -rf /' } }));

    const prodRegistry = createProductionDeterministicRegistry();
    assert.equal(prodRegistry.getEntry('malicious'), undefined);
    assert.equal(prodRegistry.getEntry('npm:malicious'), undefined);
  });

  test('Production registry contains zero Task-4/Task-5 project execution entries at Task 1', () => {
    const prodRegistry = createProductionDeterministicRegistry();
    assert.equal(prodRegistry.getEntry('npm-test'), undefined);
    assert.equal(prodRegistry.getEntry('pnpm-test'), undefined);
    assert.equal(prodRegistry.getEntry('node-test'), undefined);
  });
});

// ---------------------------------------------------------------------------
// 5. Real Policy Integration (Section 11, 13, 14, 18, 20, 36)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Real Policy Integration (SecurityKernel & DeclarativePolicyEngine)', () => {
  test('1: SecurityKernel is actually invoked for composite parent admission', async () => {
    let kernelInvoked = false;
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws', workspaceDir);
    const kernel = new SecurityKernel(registry);
    const origEvaluateComposite = kernel.evaluateComposite.bind(kernel);
    kernel.evaluateComposite = async (ctx, facts) => {
      kernelInvoked = true;
      return origEvaluateComposite(ctx, facts);
    };

    const runner = new ControlledProcessRunner(new ProcessRegistry());
    const harness = createTestCompositeHarness({
      toolName: 'arc_verify',
      schema: z.object({}),
      materializer: () => createDeterministicSafePlan('ws'),
    });

    const server = new ArcMcpServer(
      registry,
      kernel,
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      {
        transport: 'stdio',
        defaultWorkspaceId: 'ws',
        policy: {
          format: 'json',
          sourceText: JSON.stringify({
            version: '1.0',
            workspaces: [{ id: 'ws' }],
            rules: [{ id: 'r1', effect: 'ALLOW', tools: ['arc_verify'] }],
          }),
        },
      },
      runner,
    );
    attachTestCompositeHarness(server, harness);

    await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    assert.equal(kernelInvoked, true, 'SecurityKernel.evaluateComposite must be invoked');
  });

  test('2: SecurityKernel Layer-1 DENY results in zero execution', async () => {
    const { server, processRegistry, processEvents } = makeTestServer();

    // Call without authentication -> Layer 1 DENY
    const res = await server.executeAuthenticatedToolCall(
      { ...safeActor, authenticated: false },
      'arc_verify',
      {},
    );

    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'POLICY_DENIED');
    assert.equal(processRegistry.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('3: Real DeclarativePolicyEngine ALLOW works', async () => {
    const { server, processRegistry } = makeTestServer({
      policyEffect: 'ALLOW',
      policyRuleId: 'rule-allow-verify',
    });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const body = parseResponse(res);
    assert.ok(!res.isError);
    assert.equal(body.status, 'SUCCESS');
    assert.equal(processRegistry.listProcesses().length, 1);
  });

  test('4: Real DeclarativePolicyEngine REQUIRE_APPROVAL works', async () => {
    const { server, processRegistry } = makeTestServer({
      policyEffect: 'REQUIRE_APPROVAL',
      policyRuleId: 'rule-require-approval-verify',
    });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'APPROVAL_REQUIRED');
    assert.ok(body.details.approvalRequestId);
    assert.equal(processRegistry.listProcesses().length, 0);
  });

  test('5: Real DeclarativePolicyEngine DENY works', async () => {
    const { server, processRegistry } = makeTestServer({
      policyEffect: 'DENY',
      policyRuleId: 'rule-deny-verify',
    });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'POLICY_DENIED');
    assert.equal(processRegistry.listProcesses().length, 0);
  });

  test('6: DENY outranks REQUIRE_APPROVAL in declarative policy', async () => {
    const policyConfig = {
      format: 'json',
      sourceText: JSON.stringify({
        version: '1.0',
        workspaces: [{ id: 'ws' }],
        rules: [
          {
            id: 'rule-require-approval',
            effect: 'REQUIRE_APPROVAL',
            tools: ['arc_verify'],
          },
          {
            id: 'rule-deny',
            effect: 'DENY',
            tools: ['arc_verify'],
          },
        ],
      }),
    };

    const { server, processRegistry } = makeTestServer({ policyConfig });
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'POLICY_DENIED');
    assert.equal(processRegistry.listProcesses().length, 0);
  });

  test('7 / Section 18 & 20: A valid approval token cannot override a current DENY', async () => {
    const approvals = new ApprovalStateManager();

    // 1. Initial server under REQUIRE_APPROVAL
    const srv1 = makeTestServer({
      policyEffect: 'REQUIRE_APPROVAL',
      policyRuleId: 'rule-require-approval-verify',
      approvals,
    });

    const reqRes = await srv1.server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const reqBody = parseResponse(reqRes);
    assert.equal(reqBody.code, 'APPROVAL_REQUIRED');
    const requestId = reqBody.details.approvalRequestId;
    assert.ok(requestId);

    // 2. Approve request
    const { token } = approvals.approve(requestId);
    assert.ok(token);

    // 3. New server under DENY policy sharing the same approvals and workspace
    const srv2 = makeTestServer({
      policyEffect: 'DENY',
      policyRuleId: 'rule-deny-verify-override',
      approvals,
    });

    // 4. Attempt redemption with valid token while current policy resolves DENY
    const redeemRes = await srv2.server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      _arcApproval: { requestId, token },
    });

    const redeemBody = parseResponse(redeemRes);
    assert.equal(redeemRes.isError, true);
    assert.equal(redeemBody.code, 'POLICY_DENIED');

    // 5. Assert token was NOT consumed and zero execution occurred
    const snap = approvals.getRequest(requestId);
    assert.equal(snap.state, 'APPROVED', 'Token must remain unconsumed after DENY');
    assert.equal(srv2.processRegistry.listProcesses().length, 0, 'Zero execution on DENY');
  });
});

// ---------------------------------------------------------------------------
// 6. Static Architecture & Boundary Verification (Section 16 & 35)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Static Architecture & Boundary Verification', () => {
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
    assert.ok(!frameworkSource.includes('spawn('), 'Must not call spawn directly');
    assert.ok(!frameworkSource.includes('execFile('), 'Must not call execFile directly');
  });

  test('No requiresApproval test-policy shortcut exists in production framework', () => {
    const frameworkSource = fs.readFileSync(
      path.join(process.cwd(), 'apps/mcp-server/src/composite-framework.ts'),
      'utf8',
    );
    assert.ok(
      !frameworkSource.includes('requiresApproval'),
      'requiresApproval must not exist in composite-framework.ts',
    );
  });

  test('No synthetic allow-composite-framework Layer-1 bypass remains in MCP server', () => {
    const mcpSource = fs.readFileSync(
      path.join(process.cwd(), 'apps/mcp-server/src/index.ts'),
      'utf8',
    );
    assert.ok(
      !mcpSource.includes('allow-composite-framework'),
      'allow-composite-framework must not exist in apps/mcp-server/src/index.ts',
    );
  });

  test('Zero unowned RC-07 composite tools exposed in TOOL_SCHEMAS or production server list (Task 2: count 20)', async () => {
    // None of the 5 remaining RC-07 composite tools should be in TOOL_SCHEMAS
    const unownedTools = RC07_COMPOSITE_TOOLS.filter(
      (t) => t !== 'arc_repo_status' && t !== 'arc_worktree_status',
    );
    for (const tool of unownedTools) {
      assert.equal(TOOL_SCHEMAS[tool], undefined, `${tool} must not be exposed in TOOL_SCHEMAS`);
    }

    // None in ALL_TOOL_DEFINITIONS
    const toolNames = ALL_TOOL_DEFINITIONS.map((t) => t.name);
    for (const tool of unownedTools) {
      assert.equal(toolNames.includes(tool), false, `${tool} must not be in ALL_TOOL_DEFINITIONS`);
    }

    // Exact count in Task 2 is 20 (18 base + 2 Task 2 tools)
    assert.equal(ALL_TOOL_DEFINITIONS.length, 20);

    const prodServer = createArcMcpServer({ transport: 'stdio' });
    assert.equal(prodServer.testCompositeHarness, undefined);
  });
});

// ---------------------------------------------------------------------------
// 7. Authoritative Task-1 Negative Controls (RC07-NEG-001 .. RC07-NEG-010)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Authoritative Negative Controls (RC07-NEG-001..010)', () => {
  test('RC07-NEG-001: Composite tool invoked without authenticated caller identity rejected with UNAUTHENTICATED', async () => {
    const { server, processRegistry, processEvents } = makeTestServer();

    // Actor with empty clientId
    const resNoClient = await server.executeAuthenticatedToolCall(
      {
        clientId: '',
        clientType: 'worker',
        sessionId: 'sess-1',
        deviceId: 'dev-1',
        authenticated: false,
      },
      'arc_verify',
      {},
    );
    const bodyNoClient = parseResponse(resNoClient);
    assert.equal(resNoClient.isError, true);
    assert.equal(bodyNoClient.code, 'UNAUTHENTICATED');

    // Actor with whitespace sessionId
    const resNoSession = await server.executeAuthenticatedToolCall(
      {
        clientId: 'client-1',
        clientType: 'worker',
        sessionId: '   ',
        deviceId: 'dev-1',
        authenticated: true,
      },
      'arc_verify',
      {},
    );
    const bodyNoSession = parseResponse(resNoSession);
    assert.equal(resNoSession.isError, true);
    assert.equal(bodyNoSession.code, 'UNAUTHENTICATED');

    assert.equal(processRegistry.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('RC07-NEG-002: Composite tool invoked with unbound or unapproved workspaceId fails closed before plan execution', async () => {
    const { server, processRegistry, processEvents } = makeTestServer();

    const resUnregistered = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      workspaceId: 'non-existent-workspace-id',
    });
    const body = parseResponse(resUnregistered);
    assert.equal(resUnregistered.isError, true);
    assert.equal(body.code, 'NO_WORKSPACE_CONFIGURED');

    assert.equal(processRegistry.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('RC07-NEG-003: Recursive composite invocation fails closed with POLICY_DENIED', async () => {
    await enterCompositeInvocation('arc_verify', async () => {
      // Direct self-recursion A -> A
      await assert.rejects(
        () => enterCompositeInvocation('arc_verify', async () => {}),
        (err) =>
          err instanceof ArcError &&
          err.code === 'POLICY_DENIED' &&
          err.message.includes('Recursive composite invocation detected'),
      );

      // Indirect recursion / nested composite invocation A -> B
      await assert.rejects(
        () => enterCompositeInvocation('arc_test', async () => {}),
        (err) =>
          err instanceof ArcError &&
          err.code === 'POLICY_DENIED' &&
          err.message.includes('Nested composite invocation is forbidden'),
      );
    });

    // Subsequent independent call must succeed
    const { server, processRegistry } = makeTestServer();
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    assert.ok(!res.isError);
    assert.equal(processRegistry.listProcesses().length, 1);
  });

  test('RC07-NEG-004: Degraded/unavailable audit authority causes zero execution', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg004-audit');
    const { server, processRegistry, processEvents } = makeTestServer({ audit: auditConfig });
    await server.start();

    try {
      // Latch degraded audit failure
      server.auditRuntime.latchDegradedAuditFailure();

      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
      const body = parseResponse(res);
      assert.equal(res.isError, true);
      assert.equal(body.code, 'INTERNAL_ERROR');

      assert.equal(processRegistry.listProcesses().length, 0);
      assert.equal(processEvents.length, 0);
    } finally {
      await server.stop();
    }
  });

  test('RC07-NEG-005: Durable STARTED persistence failure causes zero internal execution', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg005-audit');
    const { server, processRegistry, processEvents } = makeTestServer({ audit: auditConfig });
    await server.start();

    try {
      // Inject failure on appendDurableRecord when phase === STARTED
      const originalAppend = server.appendDurableRecord.bind(server);
      server.appendDurableRecord = async (record, options) => {
        if (options && options.phase === 'STARTED') {
          throw new Error('Injected disk failure during STARTED write');
        }
        return originalAppend(record, options);
      };

      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
      const body = parseResponse(res);
      assert.equal(res.isError, true);
      assert.equal(body.code, 'INTERNAL_ERROR');

      assert.equal(processRegistry.listProcesses().length, 0);
      assert.equal(processEvents.length, 0);
    } finally {
      await server.stop();
    }
  });

  test('RC07-NEG-006: Durable COMPLETED persistence failure after execution latches DEGRADED_AUDIT_FAILURE and does not return success', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'neg006-audit');
    const { server, processRegistry } = makeTestServer({ audit: auditConfig });
    await server.start();

    try {
      // Inject failure on appendDurableRecord when phase === COMPLETED
      const originalAppend = server.appendDurableRecord.bind(server);
      server.appendDurableRecord = async (record, options) => {
        if (options && options.phase === 'COMPLETED') {
          throw new Error('Injected disk failure during COMPLETED write');
        }
        return originalAppend(record, options);
      };

      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
      const body = parseResponse(res);
      assert.equal(res.isError, true);
      assert.equal(body.code, 'INTERNAL_ERROR');

      // Process DID execute once before COMPLETED record write failed
      assert.equal(processRegistry.listProcesses().length, 1);

      // Server must now be latched degraded
      assert.equal(server.auditRuntime.isDegraded(), true);

      // Subsequent privileged invocation fails closed
      const res2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
      assert.equal(res2.isError, true);
      assert.equal(parseResponse(res2).code, 'INTERNAL_ERROR');
    } finally {
      try {
        await server.stop();
      } catch {
        // stop may report flush failure on degraded runtime
      }
    }
  });

  test('RC07-NEG-007: Plan/step deviation after admission fails closed before spawn', async () => {
    // Integrated test using testPostAdmissionMutationHook
    const { server, processRegistry, processEvents } = makeTestServer({
      testPostAdmissionMutationHook: (admittedPlan) => {
        return {
          ...admittedPlan,
          steps: [
            {
              ...admittedPlan.steps[0],
              argv: ['--eval', 'console.log("tampered")'],
            },
          ],
        };
      },
    });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'POLICY_DENIED');
    assert.ok(body.message.includes('Plan execution deviation'));

    assert.equal(processRegistry.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('RC07-NEG-008: Malformed reserved _arcApproval parameter denied with INVALID_REQUEST_SCHEMA before approval lookup', async () => {
    const approvals = new ApprovalStateManager();
    const { server, processRegistry, processEvents } = makeTestServer({ approvals });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      _arcApproval: { requestId: 'not-hex', token: '' },
    });
    const body = parseResponse(res);
    assert.equal(res.isError, true);
    assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');

    assert.equal(approvals.listActive().length, 0);
    assert.equal(processRegistry.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('RC07-NEG-009: Expired approval token presented for composite execution rejected with APPROVAL_EXPIRED', async () => {
    let mono = 1_000_000n;
    const approvals = new ApprovalStateManager({ getMonotonicTime: () => mono });
    const { server, processRegistry } = makeTestServer({
      policyEffect: 'REQUIRE_APPROVAL',
      approvals,
    });

    // Step 1: Request approval
    const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const reqBody = parseResponse(reqRes);
    assert.equal(reqBody.code, 'APPROVAL_REQUIRED');
    const requestId = reqBody.details.approvalRequestId;

    // Step 2: Approve
    const { token } = approvals.approve(requestId);

    // Step 3: Advance monotonic time past the 300-second TTL
    mono += 301_000n * 1_000_000n;

    // Step 4: Attempt redemption with expired token
    const redeemRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      _arcApproval: { requestId, token },
    });
    const redeemBody = parseResponse(redeemRes);
    assert.equal(redeemRes.isError, true);
    assert.equal(redeemBody.code, 'APPROVAL_EXPIRED');

    assert.equal(processRegistry.listProcesses().length, 0);
  });

  test('RC07-NEG-010: Previously consumed approval token presented for composite execution rejected with APPROVAL_REJECTED', async () => {
    const approvals = new ApprovalStateManager();
    const { server, processRegistry } = makeTestServer({
      policyEffect: 'REQUIRE_APPROVAL',
      approvals,
    });

    // Step 1: Request approval
    const reqRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    const reqBody = parseResponse(reqRes);
    const requestId = reqBody.details.approvalRequestId;

    // Step 2: Approve
    const { token } = approvals.approve(requestId);

    // Step 3: First redemption (succeeds)
    const redeem1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      _arcApproval: { requestId, token },
    });
    assert.ok(!redeem1.isError);
    assert.equal(processRegistry.listProcesses().length, 1);

    // Step 4: Second redemption attempt with same token (fails closed)
    const redeem2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      _arcApproval: { requestId, token },
    });
    const body2 = parseResponse(redeem2);
    assert.equal(redeem2.isError, true);
    assert.equal(body2.code, 'APPROVAL_REJECTED');

    // Process execution count remains 1 (zero additional execution)
    assert.equal(processRegistry.listProcesses().length, 1);
  });
});

// ---------------------------------------------------------------------------
// 8. Authoritative Task-1 Positive Flows (RC07-FLOW-01 & RC07-FLOW-02)
// ---------------------------------------------------------------------------

describe('RC-07 Task 1: Authoritative Positive Acceptance Flows (RC07-FLOW-01, RC07-FLOW-02)', () => {
  test('RC07-FLOW-01: Composite Framework Lifecycle Execution (STARTED -> COMPLETED with single operationId)', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'flow01-audit');
    const { server, processRegistry } = makeTestServer({ audit: auditConfig });

    await server.start();

    try {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});

      assert.ok(!res.isError);
      const result = parseResponse(res);
      assert.equal(result.status, 'SUCCESS');
      assert.equal(result.steps.length, 1);
      assert.equal(result.steps[0].status, 'PASSED');
      assert.match(result.steps[0].stdout, /^v\d+\.\d+\.\d+/);

      assert.equal(processRegistry.listProcesses().length, 1);
    } finally {
      await server.stop();
    }

    // Verify durable JSONL audit records
    const files = fs.readdirSync(auditConfig.directory).filter((f) => f.endsWith('.jsonl'));
    assert.ok(files.length > 0, 'Audit records must be persisted');
    const records = [];
    for (const f of files) {
      const content = fs.readFileSync(path.join(auditConfig.directory, f), 'utf8');
      for (const line of content.trim().split('\n')) {
        if (line.trim().length > 0) {
          records.push(JSON.parse(line));
        }
      }
    }

    const startedRecords = records.filter(
      (r) => r.lifecycle?.phase === 'STARTED' && r.invocation?.toolName === 'arc_verify',
    );
    const completedRecords = records.filter(
      (r) => r.lifecycle?.phase === 'COMPLETED' && r.invocation?.toolName === 'arc_verify',
    );

    assert.equal(startedRecords.length, 1);
    assert.equal(completedRecords.length, 1);
    assert.equal(
      startedRecords[0].lifecycle.operationId,
      completedRecords[0].lifecycle.operationId,
    );
    assert.equal(
      startedRecords[0].invocation.payloadHash,
      completedRecords[0].invocation.payloadHash,
    );

    // Verify cryptographic hash chain continuity
    for (let i = 1; i < records.length; i++) {
      assert.equal(
        records[i].integrity.previousRecordHash,
        records[i - 1].integrity.recordHash,
        `Hash chain broken at index ${i}`,
      );
    }
  });

  test('RC07-FLOW-02: Composite Approval Redemption Flow (Materialize -> planHash -> Signed Admin IPC -> Redeem -> Execute Once)', async () => {
    const auditConfig = createAuditConfig(tempRoot, 'flow02-audit');
    const approvals = new ApprovalStateManager();
    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'flow02-admin.sock');

    const { server, processRegistry } = makeTestServer({
      policyEffect: 'REQUIRE_APPROVAL',
      approvals,
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
      audit: auditConfig,
    });

    await server.start();

    try {
      // 1. Initial call without approval -> returns APPROVAL_REQUIRED
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
      assert.equal(call1.isError, true);
      const body1 = parseResponse(call1);
      assert.equal(body1.code, 'APPROVAL_REQUIRED');
      const requestId = body1.details.approvalRequestId;
      assert.ok(requestId);

      // Zero execution before approval
      assert.equal(processRegistry.listProcesses().length, 0);

      // Verify pending approval snapshot binds planHash and reviewSummary
      const pendingSnap = approvals.getRequest(requestId);
      assert.ok(pendingSnap);
      assert.equal(pendingSnap.toolName, 'arc_verify');
      assert.ok(pendingSnap.reviewSummary);
      assert.equal(pendingSnap.reviewSummary.planId, 'plan-safe-test-01');
      assert.equal(pendingSnap.reviewSummary.stepCount, 1);
      assert.match(pendingSnap.reviewSummary.planHash, /^[0-9a-f]{64}$/);

      // 2. Authorize via signed Admin IPC request
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });
      assert.equal(adminRes.ok, true, 'Admin IPC approve must succeed');
      assert.ok(adminRes.result && adminRes.result.token);
      const token = adminRes.result.token;

      // 3. Redeem with _arcApproval -> executes exact bound plan
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        _arcApproval: { requestId, token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);
      assert.equal(body2.status, 'SUCCESS');
      assert.equal(body2.steps[0].status, 'PASSED');

      // Executed exactly ONCE
      assert.equal(processRegistry.listProcesses().length, 1);

      // 4. Token cannot be reused (consumed)
      const call3 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        _arcApproval: { requestId, token },
      });
      assert.equal(call3.isError, true);
      const body3 = parseResponse(call3);
      assert.equal(body3.code, 'APPROVAL_REJECTED');

      // Zero additional execution
      assert.equal(processRegistry.listProcesses().length, 1);
    } finally {
      await server.stop();
    }

    // 5. Inspect durable audit JSONL records for approval lifecycle + execution
    const files = fs.readdirSync(auditConfig.directory).filter((f) => f.endsWith('.jsonl'));
    assert.ok(files.length > 0);
    const records = [];
    for (const f of files) {
      const content = fs.readFileSync(path.join(auditConfig.directory, f), 'utf8');
      for (const line of content.trim().split('\n')) {
        if (line.trim().length > 0) {
          records.push(JSON.parse(line));
        }
      }
    }

    const requested = records.find((r) => r.approval?.eventType === 'APPROVAL_REQUESTED');
    const granted = records.find((r) => r.approval?.eventType === 'APPROVAL_GRANTED');
    const consumed = records.find((r) => r.approval?.eventType === 'APPROVAL_CONSUMED');
    const started = records.find((r) => r.lifecycle?.phase === 'STARTED');
    const completed = records.find((r) => r.lifecycle?.phase === 'COMPLETED');

    assert.ok(requested, 'APPROVAL_REQUESTED record must exist');
    assert.ok(granted, 'APPROVAL_GRANTED record must exist');
    assert.ok(consumed, 'APPROVAL_CONSUMED record must exist');
    assert.ok(started, 'STARTED record must exist');
    assert.ok(completed, 'COMPLETED record must exist');

    assert.equal(started.lifecycle.operationId, completed.lifecycle.operationId);

    // Verify hash chain
    for (let i = 1; i < records.length; i++) {
      assert.equal(
        records[i].integrity.previousRecordHash,
        records[i - 1].integrity.recordHash,
        `Hash chain broken at index ${i}`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 8. Forward Security Corrections: Proofs A through O
// ---------------------------------------------------------------------------

describe('RC-07 Task 1 Forward Security Corrections (Proofs A through O)', () => {
  test('Proof A: Importing the public @cesspace-arc/terminal production surface cannot mint or retrieve an authorized deterministic executor', async () => {
    const terminalModule = await import('../packages/terminal/dist/index.js');
    assert.equal(terminalModule.createControlledProcessExecution, undefined);
    assert.equal(terminalModule.isAuthorizedDeterministicExecutor, undefined);
    assert.equal(terminalModule.INTERNAL_EXEC_BRAND, undefined);

    const runner = new terminalModule.ControlledProcessRunner(new ProcessRegistry());
    assert.equal(isAuthorizedDeterministicExecutor(runner), false);
    for (const key of Object.keys(terminalModule)) {
      assert.equal(
        typeof terminalModule[key] === 'function' &&
          terminalModule[key].name === 'createControlledProcessExecution',
        false,
      );
    }
  });

  test('Proof B: The old createControlledProcessExecution-style authority minting route is no longer publicly usable', async () => {
    const terminalModule = await import('../packages/terminal/dist/index.js');
    assert.equal(typeof terminalModule.createControlledProcessExecution, 'undefined');
    assert.throws(() => {
      // Calling nonexistent minting function
      terminalModule.createControlledProcessExecution();
    }, TypeError);
  });

  test('Proof C: Plain objects, symbols, serialization/deserialization, prototype tricks, or structurally matching objects still fail authority checks', () => {
    assert.equal(isAuthorizedDeterministicExecutor(null), false);
    assert.equal(isAuthorizedDeterministicExecutor(undefined), false);
    assert.equal(isAuthorizedDeterministicExecutor({}), false);
    assert.equal(
      isAuthorizedDeterministicExecutor({ executeDeterministicStep: async () => ({}) }),
      false,
    );
    assert.equal(isAuthorizedDeterministicExecutor(Object.create(null)), false);
    assert.equal(
      isAuthorizedDeterministicExecutor(
        Object.create({ executeDeterministicStep: async () => ({}) }),
      ),
      false,
    );
    assert.equal(
      isAuthorizedDeterministicExecutor({
        [Symbol.for('arc.terminal.internalExecutionBrand')]: true,
      }),
      false,
    );
    assert.equal(
      isAuthorizedDeterministicExecutor({ [Symbol('arc.terminal.internalExecutionBrand')]: true }),
      false,
    );

    const runner = new ControlledProcessRunner(new ProcessRegistry());
    const validExecutor = createServerDeterministicExecutor(runner);
    assert.equal(isAuthorizedDeterministicExecutor(validExecutor), true);

    const deserialized = JSON.parse(JSON.stringify(validExecutor));
    assert.equal(isAuthorizedDeterministicExecutor(deserialized), false);
  });

  test('Proof D: Arbitrary production importers cannot construct a custom deterministic registry and invoke privileged execution outside executeToolCallPipeline', async () => {
    // 1. Constructing registry with unapproved entry throws POLICY_DENIED
    assert.throws(
      () => {
        new DeterministicExecutionRegistry([
          {
            registryId: 'unauthorized-tool',
            executable: 'bash',
            permittedArgvTemplate: ['-c', 'id'],
            sideEffectClass: 'READ_ONLY',
            projectCodeExecution: false,
            timeoutCeilingMs: 5000,
            maxOutputBytesCeiling: 1024,
            allowCwdSubdirectory: false,
          },
        ]);
      },
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    // 2. Direct executeCompositePlan call outside executeToolCallPipeline throws POLICY_DENIED
    const procReg = new ProcessRegistry();
    const runner = new ControlledProcessRunner(procReg);
    const executor = createServerDeterministicExecutor(runner);
    const reg = createTestDeterministicRegistry();
    const safePlan = createDeterministicSafePlan('ws');
    const planHash = computePlanHash(safePlan);

    await assert.rejects(
      async () => {
        await executeCompositePlan({
          plan: safePlan,
          admittedPlanHash: planHash,
          actor: safeActor,
          targetWorkspace: { workspaceId: 'ws', rootPath: workspaceDir },
          internalExecutor: executor,
          registry: reg,
        });
      },
      (err) =>
        err instanceof ArcError &&
        err.code === 'POLICY_DENIED' &&
        err.message.includes('outside authoritative pipeline'),
    );
  });

  test('Proof E: A direct attempt to invoke any remaining exported composite helper without trusted server-owned authority performs ZERO ProcessRegistry registration and ZERO spawn', async () => {
    const procReg = new ProcessRegistry();
    const processEvents = [];
    procReg.registerLifecycleSink({
      onProcessEvent(evt) {
        processEvents.push(evt);
      },
    });

    const runner = new ControlledProcessRunner(procReg);
    const executor = createServerDeterministicExecutor(runner);
    const safePlan = createDeterministicSafePlan('ws');
    const planHash = computePlanHash(safePlan);

    // Initial count
    assert.equal(procReg.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);

    // Direct invocation without admission context fails closed
    await assert.rejects(
      async () => {
        await executeCompositePlan({
          plan: safePlan,
          admittedPlanHash: planHash,
          actor: safeActor,
          targetWorkspace: { workspaceId: 'ws', rootPath: workspaceDir },
          internalExecutor: executor,
          registry: createTestDeterministicRegistry(),
        });
      },
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    // Must perform ZERO process registration and ZERO spawn
    assert.equal(procReg.listProcesses().length, 0);
    assert.equal(processEvents.length, 0);
  });

  test('Proof F: Test-only harness construction/injection is not reachable from the production-importable surface', async () => {
    const mcpModule = await import('../apps/mcp-server/dist/index.js');
    assert.equal(mcpModule.TEST_COMPOSITE_HARNESS_TOKEN, undefined);
    assert.equal(mcpModule.createTestCompositeHarness, undefined);
    assert.equal(mcpModule.createTestDeterministicRegistry, undefined);
    assert.equal(mcpModule.attachTestCompositeHarness, undefined);
    assert.equal(mcpModule.SERVER_INTERNAL_ACCESS, undefined);
    assert.equal(mcpModule.isAuthorizedDeterministicExecutor, undefined);
    assert.equal(mcpModule.executeCompositePlan, undefined);

    // ArcMcpServer constructor has arity that does not accept harness
    const reg = new WorkspaceRegistry();
    reg.registerWorkspace('ws', workspaceDir);
    const server = new mcpModule.ArcMcpServer(
      reg,
      new SecurityKernel(reg),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { transport: 'stdio', defaultWorkspaceId: 'ws' },
      new ControlledProcessRunner(new ProcessRegistry()),
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      // Attempting to pass harness as 13th arg
      { fakeHarness: true },
    );
    // Server does NOT install fake harness
    const fakeResp = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    assert.equal(fakeResp.isError, true);
  });

  test('Proof G: Production createArcMcpServer still constructs and holds exactly the intended execution authority internally and uses createProductionDeterministicRegistry()', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
    });

    const reg = getDeterministicRegistryForTest(server);
    assert.ok(reg instanceof DeterministicExecutionRegistry);
    assert.equal(reg.listEntryIds().length, 0); // Task 1 production registry has 0 entries

    const executor = getInternalExecutorForTest(server);
    assert.ok(executor);
    assert.equal(isAuthorizedDeterministicExecutor(executor), true);
  });

  test('Proof H: Production factory never installs the test registry/harness', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
    });

    // The test node entry must NOT be present
    const reg = getDeterministicRegistryForTest(server);
    assert.equal(reg.hasEntry(TEST_NODE_VERSION_REGISTRY_ID), false);

    // Harness must not exist
    const access = SERVER_INTERNAL_ACCESS.get(server);
    assert.equal(access.getTestCompositeHarness(), undefined);
  });

  test('Proof I: ControlledProcessRunner caller-supplied authority path and public callable _executeInternalStepCore are eliminated (direct runtime bypass regression)', async () => {
    const procReg = new ProcessRegistry();
    // 1. Caller passing 4th argument to ControlledProcessRunner constructor establishes no authority path
    const fakeBrand = Symbol('fakeBrand');
    const runner = new ControlledProcessRunner(procReg, undefined, undefined, fakeBrand);
    assert.equal(runner._executeInternalStepCore, undefined);
    assert.equal(ControlledProcessRunner.prototype._executeInternalStepCore, undefined);
    assert.equal(Object.getOwnPropertySymbols(runner).length, 0);

    // 2. Direct runtime bypass attempt on ServerDeterministicExecutor without admission ticket fails closed
    const executor = createServerDeterministicExecutor(runner);
    assert.ok(isAuthorizedDeterministicExecutor(executor));

    await assert.rejects(
      async () => {
        await executor.executeDeterministicStep(
          {
            stepId: 'step-bypass',
            executable: 'node',
            args: ['-v'],
            sideEffectClass: 'READ_ONLY',
            projectCodeExecution: false,
          },
          safeActor,
          { workspaceId: 'ws', rootPath: workspaceDir },
        );
      },
      (err) =>
        err instanceof ArcError &&
        err.code === 'POLICY_DENIED' &&
        err.message.includes('requires active server admission ticket'),
    );

    // ZERO processes registered in ProcessRegistry on direct execution bypass attempt
    assert.equal(procReg.listProcesses().length, 0);
  });

  test('Proof J: No RC-07 composite production module imports node:child_process, child_process, spawn, exec, execFile, or fork', () => {
    const compositeFiles = [
      'apps/mcp-server/src/composite-framework.ts',
      'apps/mcp-server/src/internal/execution-authority.ts',
    ];

    for (const relPath of compositeFiles) {
      const src = fs.readFileSync(path.join(process.cwd(), relPath), 'utf8');
      assert.ok(
        !src.includes("from 'child_process'"),
        `${relPath} must not import from 'child_process'`,
      );
      assert.ok(
        !src.includes("from 'node:child_process'"),
        `${relPath} must not import from 'node:child_process'`,
      );
      assert.ok(
        !src.includes('require("child_process")'),
        `${relPath} must not require child_process`,
      );
      assert.ok(
        !src.includes('require("node:child_process")'),
        `${relPath} must not require node:child_process`,
      );
      assert.ok(!/\bspawn\s*\(/.test(src), `${relPath} must not invoke spawn() directly`);
      assert.ok(!/\bexec\s*\(/.test(src), `${relPath} must not invoke exec() directly`);
      assert.ok(!/\bexecFile\s*\(/.test(src), `${relPath} must not invoke execFile() directly`);
      assert.ok(!/\bfork\s*\(/.test(src), `${relPath} must not invoke fork() directly`);
    }
  });

  test('Proof K: apps/mcp-server/src/internal/execution-authority.ts does not directly spawn processes', () => {
    const src = fs.readFileSync(
      path.join(process.cwd(), 'apps/mcp-server/src/internal/execution-authority.ts'),
      'utf8',
    );
    assert.ok(
      !src.includes('child_process'),
      'execution-authority.ts must not reference child_process',
    );
    assert.ok(!src.includes('spawn'), 'execution-authority.ts must not reference spawn');
    assert.ok(
      !src.includes('registerProcess'),
      'execution-authority.ts must not call registerProcess directly',
    );
  });

  test('Proof L: No RC-07 composite production module imports node:fs or node:fs/promises for workspace execution validation', () => {
    const compositeFiles = [
      'apps/mcp-server/src/composite-framework.ts',
      'apps/mcp-server/src/internal/execution-authority.ts',
    ];

    for (const relPath of compositeFiles) {
      const src = fs.readFileSync(path.join(process.cwd(), relPath), 'utf8');
      assert.ok(!src.includes("from 'fs'"), `${relPath} must not import from 'fs'`);
      assert.ok(!src.includes("from 'node:fs'"), `${relPath} must not import from 'node:fs'`);
      assert.ok(
        !src.includes("from 'fs/promises'"),
        `${relPath} must not import from 'fs/promises'`,
      );
      assert.ok(
        !src.includes("from 'node:fs/promises'"),
        `${relPath} must not import from 'node:fs/promises'`,
      );
      assert.ok(!src.includes('existsSync'), `${relPath} must not use existsSync`);
      assert.ok(!src.includes('realpathSync'), `${relPath} must not use realpathSync`);
    }
  });

  test('Proof M: Deterministic execution still reaches ProcessRegistry through lower-level terminal machinery', async () => {
    const testRegistry = createTestDeterministicRegistry();
    const { server, processRegistry } = makeTestServer({
      deterministicRegistry: testRegistry,
      materializer: () => createDeterministicSafePlan('ws'),
    });

    // Run safe composite flow through full authoritative pipeline
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {});
    assert.ok(!res.isError, 'Execution through server pipeline must succeed');

    const body = parseResponse(res);
    assert.equal(body.status, 'SUCCESS');
    assert.ok(body.steps && body.steps.length === 1);
    assert.equal(body.steps[0].stepId, 'step-01-node-version');
    assert.equal(body.steps[0].status, 'PASSED');
    assert.match(body.steps[0].stdout, /^v\d+\.\d+\.\d+/);

    // ProcessRegistry was invoked through terminal machinery
    const processes = processRegistry.listProcesses();
    assert.equal(processes.length, 1);
    assert.equal(processes[0].executable, 'node');
    assert.equal(processes[0].state, 'COMPLETED');
    assert.equal(processes[0].exitCode, 0);
  });

  test('Proof N: Package boundary: @cesspace-arc/terminal exports map contains zero internal privileged subpaths and blocks unexported deep imports', async () => {
    // 1. Verify packages/terminal/package.json exports map contains strictly only "."
    const terminalPkg = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), 'packages/terminal/package.json'), 'utf8'),
    );
    assert.deepEqual(Object.keys(terminalPkg.exports), ['.']);
    assert.equal(terminalPkg.exports['./internal/execution-seam'], undefined);

    // 2. Package-level import of @cesspace-arc/terminal/internal/execution-seam fails with ERR_PACKAGE_PATH_NOT_EXPORTED
    const requireFromMcp = createRequire(path.join(process.cwd(), 'apps/mcp-server/package.json'));
    assert.throws(
      () => {
        requireFromMcp.resolve('@cesspace-arc/terminal/internal/execution-seam');
      },
      (err) => err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    );

    const testImportScript = (specifier) => {
      try {
        execFileSync(
          process.execPath,
          ['--input-type=module', '-e', `await import(${JSON.stringify(specifier)});`],
          {
            cwd: path.join(process.cwd(), 'apps/mcp-server'),
            encoding: 'utf8',
            stdio: 'pipe',
          },
        );
        return { success: true };
      } catch (err) {
        return {
          success: false,
          code: err.stderr?.includes('ERR_PACKAGE_PATH_NOT_EXPORTED')
            ? 'ERR_PACKAGE_PATH_NOT_EXPORTED'
            : err.code,
          stderr: err.stderr,
        };
      }
    };

    const resSeam = testImportScript('@cesspace-arc/terminal/internal/execution-seam');
    assert.equal(resSeam.success, false);
    assert.equal(resSeam.code, 'ERR_PACKAGE_PATH_NOT_EXPORTED');

    // 3. Test that equivalent deep package imports cannot retrieve execution seam token or process machinery
    const deepImports = [
      '@cesspace-arc/terminal/dist/internal/execution-seam.js',
      '@cesspace-arc/terminal/internal/execution-seam.js',
      '@cesspace-arc/terminal/internal/process-machinery',
      '@cesspace-arc/terminal/dist/internal/process-machinery.js',
    ];
    for (const specifier of deepImports) {
      assert.throws(
        () => {
          requireFromMcp.resolve(specifier);
        },
        (err) => err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
        `Deep import '${specifier}' must be blocked by package exports map`,
      );

      const subRes = testImportScript(specifier);
      assert.equal(subRes.success, false, `Import '${specifier}' must fail`);
      assert.equal(subRes.code, 'ERR_PACKAGE_PATH_NOT_EXPORTED');
    }

    // 4. Public @cesspace-arc/terminal root exports no privileged tokens or execution functions
    const terminalModule = await import('../packages/terminal/dist/index.js');
    assert.equal(terminalModule.TERMINAL_EXECUTION_SEAM_TOKEN, undefined);
    assert.equal(terminalModule.executeDeterministicStepCore, undefined);
    assert.equal(terminalModule.spawnAndControlProcess, undefined);
    assert.equal(terminalModule.createControlledProcessExecution, undefined);
    assert.equal(
      terminalModule.ControlledProcessRunner.prototype._executeInternalStepCore,
      undefined,
    );
  });

  test('Proof O: Previously possible pipeline-bypass attack is impossible through the production package API', async () => {
    // Attack model:
    // Attacker constructs ControlledProcessRunner and tries to import executeDeterministicStepCore
    // and TERMINAL_EXECUTION_SEAM_TOKEN to invoke the low-level process core directly.
    const terminalModule = await import('../packages/terminal/dist/index.js');
    const runner = new terminalModule.ControlledProcessRunner(new ProcessRegistry());
    assert.ok(runner);
    assert.equal(runner._executeInternalStepCore, undefined);

    // The privileged seam import itself MUST be impossible through the package API
    let attackSucceeded = false;
    try {
      execFileSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `
          import { ControlledProcessRunner } from '@cesspace-arc/terminal';
          import {
            executeDeterministicStepCore,
            TERMINAL_EXECUTION_SEAM_TOKEN
          } from '@cesspace-arc/terminal/internal/execution-seam';
          `,
        ],
        {
          cwd: path.join(process.cwd(), 'apps/mcp-server'),
          encoding: 'utf8',
          stdio: 'pipe',
        },
      );
      attackSucceeded = true;
    } catch (err) {
      assert.ok(
        err.stderr?.includes('ERR_PACKAGE_PATH_NOT_EXPORTED'),
        'Must fail with ERR_PACKAGE_PATH_NOT_EXPORTED',
      );
    }
    assert.equal(
      attackSucceeded,
      false,
      'Privileged seam import attack must be completely impossible',
    );
  });
});
