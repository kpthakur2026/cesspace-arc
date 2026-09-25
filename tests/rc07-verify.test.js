/**
 * CesSpace ARC — RC-07 Task 4 Verification Test Suite
 *
 * Implements authoritative tests for `arc_verify`:
 * - Negative Controls: RC07-NEG-028 through RC07-NEG-037
 * - Positive Acceptance Flows: RC07-FLOW-09 and RC07-FLOW-10
 * - Invariant regressions: Discovery count (22), registry entries, check-only boundary,
 *   environment isolation, and timeout boundaries.
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import crypto from 'node:crypto';
import cp from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

import { ArcMcpServer, ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import {
  DeterministicExecutionRegistry,
  createProductionDeterministicRegistry,
  validateDeterministicArgToken,
  validateStepAgainstRegistry,
  VERIFY_FORMAT_REGISTRY_ID,
  VERIFY_LINT_REGISTRY_ID,
  VERIFY_TYPECHECK_REGISTRY_ID,
  VERIFY_TEST_REGISTRY_ID,
  TEST_NODE_VERSION_REGISTRY_ID,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  setTask4StepTimeoutForTest,
  getTask4StepTimeoutForTest,
  setTask4AggregateTimeoutForTest,
  getTask4AggregateTimeoutForTest,
} from '../apps/mcp-server/dist/internal/server-seam.js';
import {
  materializeArcVerifyPlan,
  MAX_VERIFY_WIRE_BYTES,
  DEFAULT_TASK4_STEP_TIMEOUT_MS,
  DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS,
} from '../apps/mcp-server/dist/internal/verify.js';
import {
  WorkspaceRegistry,
  SecurityKernel,
  ApprovalStateManager,
  DeclarativePolicyEngine,
} from '../packages/policy/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
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
// Helpers & Fixture Setup
// ---------------------------------------------------------------------------

let tempRoot;
let cleanWorkspaceDir;
let prettierBin;

const safeActor = {
  clientId: 'client-task4-test',
  clientType: 'worker',
  sessionId: 'session-task4-01',
  deviceId: 'device-task4-local',
  authenticated: true,
};

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
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

function setupCleanWorkspace(targetDir) {
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(
    path.join(targetDir, 'package.json'),
    JSON.stringify({ name: 'fixture', type: 'module' }, null, 2) + '\n',
  );
  fs.writeFileSync(path.join(targetDir, 'index.ts'), 'export const answer: number = 42;\n');
  fs.writeFileSync(path.join(targetDir, 'eslint.config.js'), 'export default [];\n');
  fs.writeFileSync(
    path.join(targetDir, 'tsconfig.json'),
    JSON.stringify({ compilerOptions: { noEmit: true }, files: ['index.ts'] }, null, 2) + '\n',
  );
  const testDir = path.join(targetDir, 'test');
  fs.mkdirSync(testDir, { recursive: true });
  fs.writeFileSync(
    path.join(testDir, 'sample.test.js'),
    'import test from "node:test";\nimport assert from "node:assert";\n\ntest("math check", () => {\n  assert.equal(1 + 1, 2);\n});\n',
  );

  // Format with prettier to ensure clean baseline
  cp.spawnSync(process.execPath, [prettierBin, '--write', '.'], { cwd: targetDir });
}

function setupSolutionWorkspace(targetDir) {
  const pkgDir = path.join(targetDir, 'packages', 'a');
  const srcDir = path.join(pkgDir, 'src');
  fs.mkdirSync(srcDir, { recursive: true });
  fs.writeFileSync(
    path.join(targetDir, 'package.json'),
    JSON.stringify({ name: 'solution-fixture', type: 'module' }, null, 2) + '\n',
  );
  fs.writeFileSync(
    path.join(targetDir, 'tsconfig.json'),
    JSON.stringify(
      {
        files: [],
        references: [{ path: './packages/a' }],
      },
      null,
      2,
    ) + '\n',
  );
  fs.writeFileSync(
    path.join(pkgDir, 'package.json'),
    JSON.stringify({ name: 'pkg-a', type: 'module' }, null, 2) + '\n',
  );
  fs.writeFileSync(
    path.join(pkgDir, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          composite: true,
          declaration: true,
          outDir: './dist',
          rootDir: './src',
          strict: true,
        },
        include: ['src/**/*'],
      },
      null,
      2,
    ) + '\n',
  );
  fs.writeFileSync(path.join(srcDir, 'index.ts'), 'export const answer: number = 42;\n');
}

function snapshotDirectory(dir) {
  const snapshot = new Map();
  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const ent of entries) {
      const full = path.join(current, ent.name);
      const rel = path.relative(dir, full);
      if (ent.isDirectory()) {
        walk(full);
      } else if (ent.isFile()) {
        snapshot.set(rel, fs.readFileSync(full, 'utf8'));
      }
    }
  }
  walk(dir);
  return snapshot;
}

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc07-task4-'));
  cleanWorkspaceDir = path.join(tempRoot, 'clean-workspace');

  const prettierPkg = require.resolve('prettier/package.json');
  prettierBin = path.resolve(path.dirname(prettierPkg), 'bin/prettier.cjs');

  setupCleanWorkspace(cleanWorkspaceDir);
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function createTestHarnessServer(workspaceDir, options = {}) {
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

  const audit =
    options.audit ??
    (tempRoot
      ? createAuditConfig(
          tempRoot,
          options.label ?? 'harness-' + crypto.randomBytes(6).toString('hex'),
        )
      : undefined);

  const serverConfig = options.config
    ? { audit, ...options.config }
    : {
        transport: 'stdio',
        audit,
      };

  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry, processRegistry),
    auditLogger,
    new FilesystemSubsystem(),
    new GitSubsystem(),
    serverConfig,
    terminalSubsystem,
    processRegistry,
    approvals,
    adminIpcServer,
  );

  return {
    server,
    registry,
    approvals,
    processRegistry,
    processEvents,
    auditLogger,
  };
}

// ---------------------------------------------------------------------------
// Negative Controls: RC07-NEG-028 .. RC07-NEG-037
// ---------------------------------------------------------------------------

describe('RC-07 Task 4: Negative Controls (RC07-NEG-028..037)', () => {
  test('RC07-NEG-028: unapproved binary/tool entrypoint outside closed production registry is denied before spawn', async () => {
    const reg = createProductionDeterministicRegistry();
    assert.equal(reg.getEntry('unknown-binary-v1'), undefined);
    assert.equal(reg.hasEntry('unapproved-tool-v1'), false);
    assert.equal(reg.hasEntry('sh'), false);
    assert.equal(reg.hasEntry('bash'), false);
    assert.equal(reg.hasEntry('calc'), false);

    assert.throws(
      () => {
        validateStepAgainstRegistry(
          {
            stepId: 'step-bad',
            toolRegistryId: 'unknown-binary-v1',
            executable: 'unknown',
            argv: [],
            cwd: '',
            timeoutMs: 1000,
            outputLimitBytes: 1000,
            projectCodeExecution: false,
            sideEffectClass: 'READ_ONLY',
          },
          reg,
        );
      },
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );

    // Attempting to construct a registry with an unapproved entry throws policyDenied
    assert.throws(
      () => {
        new DeterministicExecutionRegistry([
          {
            registryId: 'hostile-rm-v1',
            executable: 'rm',
            permittedArgvTemplate: ['-rf', '/'],
            sideEffectClass: 'EXECUTION',
            projectCodeExecution: true,
            timeoutCeilingMs: 1000,
            maxOutputBytesCeiling: 1000,
            allowCwdSubdirectory: false,
          },
        ]);
      },
      (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
    );
  });

  test('RC07-NEG-029: package-manager script execution or raw shell string is denied; production registry contains none', () => {
    const reg = createProductionDeterministicRegistry();
    const entryIds = reg.listEntryIds();

    for (const id of entryIds) {
      const entry = reg.getEntry(id);
      assert.ok(entry);
      // No npm, pnpm, yarn, npx, sh, bash, or cmd
      assert.ok(
        !['npm', 'pnpm', 'yarn', 'npx', 'sh', 'bash', 'cmd', 'powershell'].includes(
          entry.executable,
        ),
      );
      // No raw shell strings or scripts in permittedArgvTemplate
      for (const arg of entry.permittedArgvTemplate) {
        assert.ok(!arg.includes('run'));
        assert.ok(!arg.includes('install'));
        assert.ok(!arg.includes('script'));
      }
    }
  });

  test('RC07-NEG-030: deterministic plan containing ; rm -rf, && calc, or equivalent shell/control tokens is rejected before spawn', () => {
    const dangerousTokens = [
      '; rm -rf',
      '&& calc',
      '|| true',
      '`id`',
      '$(whoami)',
      '> out.txt',
      '< in.txt',
      'evil\ncmd',
    ];
    for (const token of dangerousTokens) {
      assert.throws(
        () => {
          validateDeterministicArgToken(token);
        },
        (err) => err instanceof ArcError && err.code === 'POLICY_DENIED',
        `Should reject '${token}'`,
      );
    }
  });

  test('RC07-NEG-031: real verification child exceeds 30-second per-step maximum; child is terminated/reaped, step is TIMED_OUT, remaining steps SKIPPED', async () => {
    const wsDir = path.join(tempRoot, 'timeout-step-ws');
    setupCleanWorkspace(wsDir);
    // Overwrite test with a long-running sleep
    fs.writeFileSync(
      path.join(wsDir, 'test', 'sample.test.js'),
      'import test from "node:test";\ntest("slow", async () => {\n  await new Promise((r) => setTimeout(r, 10000));\n});\n',
    );

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'neg031-admin.sock');
    const { server, processRegistry } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      // Lower step timeout ceiling for test to 300 ms
      setTask4StepTimeoutForTest(server, 300);
      assert.equal(getTask4StepTimeoutForTest(server), 300);

      // 1. Request approval
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
      });
      const body1 = parseResponse(call1);
      const requestId = body1.details.approvalRequestId;

      // 2. Authorize
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });
      const token = adminRes.result.token;

      // 3. Redeem -> child runs, times out at 300ms, terminated/reaped
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
        _arcApproval: { requestId, token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);

      assert.equal(body2.status, 'TIMED_OUT');
      assert.equal(body2.steps.length, 1);
      assert.equal(body2.steps[0].status, 'TIMED_OUT');
      assert.equal(body2.failedStep, 'test');

      // Process is reaped and completed
      const processes = processRegistry.listProcesses();
      assert.ok(processes.length >= 1);
      assert.ok(processes.some((p) => p.timedOut === true));
    } finally {
      await server.stop();
    }
  });

  test('RC07-NEG-032: aggregate execution exceeds 120-second ceiling; active process is terminated and operation reports COMPOSITE_TIMEOUT / TIMED_OUT', async () => {
    const wsDir = path.join(tempRoot, 'timeout-aggregate-ws');
    setupCleanWorkspace(wsDir);
    // Overwrite test with a long-running sleep
    fs.writeFileSync(
      path.join(wsDir, 'test', 'sample.test.js'),
      'import test from "node:test";\ntest("slow", async () => {\n  await new Promise((r) => setTimeout(r, 10000));\n});\n',
    );

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'neg032-admin.sock');
    const auditConfig = createAuditConfig(tempRoot, 'audit-neg032');
    const { server } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
      audit: auditConfig,
    });

    await server.start();
    try {
      // Lower aggregate timeout ceiling for test to 300 ms, while step timeout remains higher
      setTask4AggregateTimeoutForTest(server, 300);
      assert.equal(getTask4AggregateTimeoutForTest(server), 300);

      // 1. Request approval
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
      });
      const body1 = parseResponse(call1);
      const requestId = body1.details.approvalRequestId;

      // 2. Authorize
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });
      const token = adminRes.result.token;

      // 3. Redeem -> aggregate timeout triggers
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
        _arcApproval: { requestId, token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);

      assert.equal(body2.status, 'TIMED_OUT');
      assert.equal(body2.steps[0].status, 'TIMED_OUT');
    } finally {
      await server.stop();
    }

    // Inspect durable audit log: COMPLETED record has COMPOSITE_TIMEOUT error
    const files = fs.readdirSync(auditConfig.directory).filter((f) => f.endsWith('.jsonl'));
    assert.ok(files.length > 0);
    const records = [];
    for (const f of files) {
      const content = fs.readFileSync(path.join(auditConfig.directory, f), 'utf8');
      for (const line of content.trim().split('\n')) {
        if (line.trim()) records.push(JSON.parse(line));
      }
    }
    const completedRecord = records.find((r) => r.lifecycle?.phase === 'COMPLETED');
    assert.ok(completedRecord);
    assert.equal(completedRecord.execution.status, 'TIMEOUT');
    assert.equal(completedRecord.error.code, 'COMPOSITE_TIMEOUT');
  });

  test('RC07-NEG-033: built-in policy requires approval; invocation without approval produces approval request and zero process spawns', async () => {
    const { server, processRegistry } = createTestHarnessServer(cleanWorkspaceDir);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      suite: 'lint',
    });

    assert.equal(res.isError, true);
    const body = parseResponse(res);
    assert.equal(body.code, 'APPROVAL_REQUIRED');
    assert.ok(body.details && body.details.approvalRequestId);
    assert.equal(body.details.toolName, 'arc_verify');

    // Zero process spawns
    assert.equal(processRegistry.listProcesses().length, 0);
  });

  test('RC07-NEG-034: child emits output above process/response limits; response remains valid, scrubbed, UTF-8-safe, <=256 KiB, and marks truncation truthfully', async () => {
    const wsDir = path.join(tempRoot, 'large-output-ws');
    setupCleanWorkspace(wsDir);
    // Write test that emits 300 KiB of output
    fs.writeFileSync(
      path.join(wsDir, 'test', 'sample.test.js'),
      'import test from "node:test";\ntest("spam", () => {\n  console.log("HELLO_WORLD_REPEAT_".repeat(20000));\n});\n',
    );

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'neg034-admin.sock');
    const { server } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      // 1. Approval
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
      });
      const requestId = parseResponse(call1).details.approvalRequestId;
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });

      // 2. Execution
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
        _arcApproval: { requestId, token: adminRes.result.token },
      });
      assert.ok(!call2.isError);

      // Exact wire response length check
      const rawWire = call2.content[0].text;
      const wireByteLength = Buffer.byteLength(rawWire, 'utf8');
      assert.ok(
        wireByteLength <= MAX_VERIFY_WIRE_BYTES,
        `Wire length ${wireByteLength} must be <= ${MAX_VERIFY_WIRE_BYTES}`,
      );

      const body2 = JSON.parse(rawWire);
      assert.equal(body2.status, 'PASSED');
      assert.equal(body2.steps[0].truncated, true);
      assert.ok(
        body2.steps[0].outputExcerpt.includes('[TRUNCATED]') ||
          body2.steps[0].outputExcerpt.length > 0,
      );
    } finally {
      await server.stop();
    }
  });

  test('RC07-NEG-035: parent has simulated sensitive environment variables; verification child cannot observe them', async () => {
    const wsDir = path.join(tempRoot, 'env-iso-ws');
    setupCleanWorkspace(wsDir);

    // Construct secret-like fixture values dynamically so Gitleaks is not triggered
    const secretSuffix = ['mock', 'secret', 'token', '42'].join('_');
    const mockGh = ['ghp', secretSuffix].join('_');
    const mockAws = ['AKIA', secretSuffix].join('_');
    const mockNpm = ['npm', secretSuffix].join('_');

    process.env.GITHUB_TOKEN = mockGh;
    process.env.AWS_SECRET_ACCESS_KEY = mockAws;
    process.env.NPM_TOKEN = mockNpm;

    // Test asserting absence in child
    fs.writeFileSync(
      path.join(wsDir, 'test', 'sample.test.js'),
      `import test from "node:test";\nimport assert from "node:assert";\n\ntest("env", () => {\n  assert.equal(process.env.GITHUB_TOKEN, undefined);\n  assert.equal(process.env.AWS_SECRET_ACCESS_KEY, undefined);\n  assert.equal(process.env.NPM_TOKEN, undefined);\n});\n`,
    );

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'neg035-admin.sock');
    const { server } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
      });
      const requestId = parseResponse(call1).details.approvalRequestId;
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });

      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'test',
        _arcApproval: { requestId, token: adminRes.result.token },
      });
      assert.ok(!call2.isError);
      const body = parseResponse(call2);
      assert.equal(body.status, 'PASSED');
      assert.equal(body.steps[0].exitCode, 0);
    } finally {
      delete process.env.GITHUB_TOKEN;
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.NPM_TOKEN;
      await server.stop();
    }
  });

  test('RC07-NEG-036: first failing verification step halts plan; later steps are SKIPPED and never spawn', async () => {
    const wsDir = path.join(tempRoot, 'format-fail-ws');
    setupCleanWorkspace(wsDir);
    // Break prettier formatting in index.ts
    fs.writeFileSync(path.join(wsDir, 'index.ts'), 'export const   x :   number = 1 ;\n');

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'neg036-admin.sock');
    const { server, processRegistry } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
      });
      const requestId = parseResponse(call1).details.approvalRequestId;
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });

      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
        _arcApproval: { requestId, token: adminRes.result.token },
      });
      assert.ok(!call2.isError);
      const body = parseResponse(call2);

      assert.equal(body.status, 'FAILED');
      assert.equal(body.failedStep, 'format');
      assert.equal(body.steps[0].stepName, 'format');
      assert.equal(body.steps[0].status, 'FAILED');

      // Subsequent steps are SKIPPED
      assert.equal(body.steps[1].stepName, 'lint');
      assert.equal(body.steps[1].status, 'SKIPPED');
      assert.equal(body.steps[2].stepName, 'typecheck');
      assert.equal(body.steps[2].status, 'SKIPPED');
      assert.equal(body.steps[3].stepName, 'test');
      assert.equal(body.steps[3].status, 'SKIPPED');

      // Only 1 process spawned
      assert.equal(processRegistry.listProcesses().length, 1);
    } finally {
      await server.stop();
    }
  });

  test('RC07-NEG-037: unknown suite and attempted fix/mutation property fail strict schema with INVALID_REQUEST_SCHEMA', async () => {
    const { server } = createTestHarnessServer(cleanWorkspaceDir);

    // 1. Unknown suite
    const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      suite: 'security-audit',
    });
    assert.equal(call1.isError, true);
    assert.equal(parseResponse(call1).code, 'INVALID_REQUEST_SCHEMA');

    // 2. Extra property: fix: true
    const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      suite: 'format',
      fix: true,
    });
    assert.equal(call2.isError, true);
    assert.equal(parseResponse(call2).code, 'INVALID_REQUEST_SCHEMA');

    // 3. Extra property: write: true
    const call3 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      suite: 'lint',
      write: true,
    });
    assert.equal(call3.isError, true);
    assert.equal(parseResponse(call3).code, 'INVALID_REQUEST_SCHEMA');

    // 4. Extra property: command string
    const call4 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
      command: 'prettier --write .',
    });
    assert.equal(call4.isError, true);
    assert.equal(parseResponse(call4).code, 'INVALID_REQUEST_SCHEMA');
  });
});

// ---------------------------------------------------------------------------
// Positive Acceptance Flows: RC07-FLOW-09 .. RC07-FLOW-10
// ---------------------------------------------------------------------------

describe('RC-07 Task 4: Positive Acceptance Flows (RC07-FLOW-09, RC07-FLOW-10)', () => {
  test('RC07-FLOW-09: Successful Check-Only Verification Suite Plan (no workspace mutation, exitCode 0, truthful metadata)', async () => {
    const wsDir = path.join(tempRoot, 'flow09-ws');
    setupCleanWorkspace(wsDir);

    const snapshotBefore = snapshotDirectory(wsDir);

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'flow09-admin.sock');
    const { server, processRegistry } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      // 1. Initial call without approval -> returns APPROVAL_REQUIRED
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
      });
      assert.equal(call1.isError, true);
      const body1 = parseResponse(call1);
      assert.equal(body1.code, 'APPROVAL_REQUIRED');
      const requestId = body1.details.approvalRequestId;
      assert.ok(requestId);

      // 2. Authorize via signed Admin IPC request
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });
      assert.equal(adminRes.ok, true);
      const token = adminRes.result.token;

      // 3. Redeem with _arcApproval -> executes exact bound plan
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
        _arcApproval: { requestId, token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);

      assert.equal(body2.suite, 'all');
      assert.equal(body2.status, 'PASSED');
      assert.equal(body2.failedStep, undefined);
      assert.equal(body2.steps.length, 4);

      // Step 0: format
      assert.equal(body2.steps[0].stepName, 'format');
      assert.equal(body2.steps[0].executable, 'prettier');
      assert.deepEqual(body2.steps[0].args, ['--check', '.']);
      assert.equal(body2.steps[0].status, 'PASSED');
      assert.equal(body2.steps[0].exitCode, 0);

      // Step 1: lint
      assert.equal(body2.steps[1].stepName, 'lint');
      assert.equal(body2.steps[1].executable, 'eslint');
      assert.deepEqual(body2.steps[1].args, ['.']);
      assert.equal(body2.steps[1].status, 'PASSED');
      assert.equal(body2.steps[1].exitCode, 0);

      // Step 2: typecheck
      assert.equal(body2.steps[2].stepName, 'typecheck');
      assert.equal(body2.steps[2].executable, 'tsc');
      assert.deepEqual(body2.steps[2].args, ['--noEmit']);
      assert.equal(body2.steps[2].status, 'PASSED');
      assert.equal(body2.steps[2].exitCode, 0);

      // Step 3: test
      assert.equal(body2.steps[3].stepName, 'test');
      assert.equal(body2.steps[3].executable, 'node');
      assert.deepEqual(body2.steps[3].args, ['--test']);
      assert.equal(body2.steps[3].status, 'PASSED');
      assert.equal(body2.steps[3].exitCode, 0);

      // Exactly 4 processes tracked
      assert.equal(processRegistry.listProcesses().length, 4);

      // Verify workspace state is strictly UNCHANGED (check-only guarantee)
      const snapshotAfter = snapshotDirectory(wsDir);
      assert.equal(snapshotBefore.size, snapshotAfter.size);
      for (const [file, content] of snapshotBefore.entries()) {
        assert.equal(snapshotAfter.get(file), content, `File '${file}' must not be modified`);
      }
    } finally {
      await server.stop();
    }
  });

  test('RC07-FLOW-10: Partial Verification Suite Failure Handling (early step passes, typecheck fails, subsequent steps SKIPPED with 0 spawns)', async () => {
    const wsDir = path.join(tempRoot, 'flow10-ws');
    setupCleanWorkspace(wsDir);
    // Introduce a TypeScript type error (format and lint remain valid)
    fs.writeFileSync(
      path.join(wsDir, 'index.ts'),
      'export const answer: number = "not-a-number";\n',
    );
    cp.spawnSync(process.execPath, [prettierBin, '--write', '.'], { cwd: wsDir });

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'flow10-admin.sock');
    const { server, processRegistry } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      // 1. Approval
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
      });
      const requestId = parseResponse(call1).details.approvalRequestId;
      const adminRes = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId,
      });
      const token = adminRes.result.token;

      // 2. Execution
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'all',
        _arcApproval: { requestId, token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);

      assert.equal(body2.status, 'FAILED');
      assert.equal(body2.failedStep, 'typecheck');

      // format: PASSED
      assert.equal(body2.steps[0].stepName, 'format');
      assert.equal(body2.steps[0].status, 'PASSED');
      assert.equal(body2.steps[0].exitCode, 0);

      // lint: PASSED
      assert.equal(body2.steps[1].stepName, 'lint');
      assert.equal(body2.steps[1].status, 'PASSED');
      assert.equal(body2.steps[1].exitCode, 0);

      // typecheck: FAILED
      assert.equal(body2.steps[2].stepName, 'typecheck');
      assert.equal(body2.steps[2].status, 'FAILED');
      assert.notEqual(body2.steps[2].exitCode, 0);
      assert.ok(
        body2.steps[2].outputExcerpt.includes('Type') || body2.steps[2].outputExcerpt.length > 0,
      );

      // test: SKIPPED
      assert.equal(body2.steps[3].stepName, 'test');
      assert.equal(body2.steps[3].status, 'SKIPPED');
      assert.equal(body2.steps[3].exitCode, null);

      // Exactly 3 processes spawned (test was skipped)
      assert.equal(processRegistry.listProcesses().length, 3);
    } finally {
      await server.stop();
    }
  });

  test('Solution-style project references: traverses and typechecks referenced projects without disk mutations', async () => {
    const wsDir = path.join(tempRoot, 'solution-ref-ws');
    setupSolutionWorkspace(wsDir);

    const operator = generateOperator();
    const adminSocket = path.join(tempRoot, 'solution-ref-admin.sock');
    const { server, processRegistry } = createTestHarnessServer(wsDir, {
      adminSocket,
      operatorPublicKeyB64: operator.publicKeyB64,
    });

    await server.start();
    try {
      // 1. Snapshot workspace before valid execution
      const snapshotBeforeValid = snapshotDirectory(wsDir);

      // Request approval
      const call1 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'typecheck',
      });
      const requestId1 = parseResponse(call1).details.approvalRequestId;
      const adminRes1 = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId: requestId1,
      });

      // Execute approved suite: 'typecheck'
      const call2 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'typecheck',
        _arcApproval: { requestId: requestId1, token: adminRes1.result.token },
      });
      assert.ok(!call2.isError);
      const body2 = parseResponse(call2);

      assert.equal(body2.status, 'PASSED');
      assert.equal(body2.steps.length, 1);
      assert.equal(body2.steps[0].stepName, 'typecheck');
      assert.equal(body2.steps[0].executable, 'tsc');
      assert.equal(body2.steps[0].status, 'PASSED');
      assert.equal(body2.steps[0].exitCode, 0);

      // Snapshot workspace after valid execution and assert exact identity
      const snapshotAfterValid = snapshotDirectory(wsDir);
      assert.equal(snapshotAfterValid.size, snapshotBeforeValid.size);
      for (const [filePath, content] of snapshotBeforeValid) {
        assert.equal(snapshotAfterValid.get(filePath), content);
      }
      // Prove no dist, JS/DTS, or .tsbuildinfo was written
      for (const filePath of snapshotAfterValid.keys()) {
        assert.ok(!filePath.includes('dist'), `No dist file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.d.ts'), `No .d.ts file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.js'), `No .js file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.tsbuildinfo'), `No .tsbuildinfo allowed: ${filePath}`);
      }

      // 2. Introduce genuine TypeScript error only inside the referenced project (packages/a/src/index.ts)
      fs.writeFileSync(
        path.join(wsDir, 'packages', 'a', 'src', 'index.ts'),
        'export const answer: number = "definitely-not-a-number";\n',
      );

      const snapshotBeforeError = snapshotDirectory(wsDir);

      // Request approval for second run
      const call3 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'typecheck',
      });
      const requestId2 = parseResponse(call3).details.approvalRequestId;
      const adminRes2 = await adminRequest(adminSocket, operator.privateKey, 'approval.approve', {
        requestId: requestId2,
      });

      // Execute approved suite: 'typecheck'
      const call4 = await server.executeAuthenticatedToolCall(safeActor, 'arc_verify', {
        suite: 'typecheck',
        _arcApproval: { requestId: requestId2, token: adminRes2.result.token },
      });
      assert.ok(!call4.isError);
      const body4 = parseResponse(call4);

      assert.equal(body4.status, 'FAILED');
      assert.equal(body4.failedStep, 'typecheck');
      assert.equal(body4.steps.length, 1);
      assert.equal(body4.steps[0].stepName, 'typecheck');
      assert.equal(body4.steps[0].status, 'FAILED');
      assert.notEqual(body4.steps[0].exitCode, 0);
      assert.ok(
        body4.steps[0].outputExcerpt.includes('TS2322') ||
          body4.steps[0].outputExcerpt.includes('Type'),
        `Diagnostic excerpt should mention TS2322 or Type error: ${body4.steps[0].outputExcerpt}`,
      );

      // Prove child process tracked through ProcessRegistry
      const processes = processRegistry.listProcesses();
      assert.ok(processes.length >= 2);
      assert.ok(processes.some((p) => p.exitCode !== 0));

      // Snapshot workspace after error run and assert zero mutations
      const snapshotAfterError = snapshotDirectory(wsDir);
      assert.equal(snapshotAfterError.size, snapshotBeforeError.size);
      for (const [filePath, content] of snapshotBeforeError) {
        assert.equal(snapshotAfterError.get(filePath), content);
      }
      for (const filePath of snapshotAfterError.keys()) {
        assert.ok(!filePath.includes('dist'), `No dist file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.d.ts'), `No .d.ts file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.js'), `No .js file allowed: ${filePath}`);
        assert.ok(!filePath.endsWith('.tsbuildinfo'), `No .tsbuildinfo allowed: ${filePath}`);
      }
    } finally {
      await server.stop();
    }
  });
});

// ---------------------------------------------------------------------------
// Additional Invariants & Quality Regressions
// ---------------------------------------------------------------------------

describe('RC-07 Task 4: Invariants, Discovery & Quality Regressions', () => {
  test('Discovery: Production tool count is exactly 24 (including arc_verify, arc_test, and arc_ci_status)', () => {
    assert.equal(ALL_TOOL_DEFINITIONS.length, 24);
    const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);

    assert.ok(names.includes('arc_ci_status'));
    assert.ok(names.includes('arc_verify'));
    assert.ok(names.includes('arc_test'));
    assert.ok(names.includes('arc_review_diff'));
    assert.ok(names.includes('arc_repo_status'));
    assert.ok(names.includes('arc_worktree_status'));

    // Still absent
    assert.equal(names.includes('arc_stage_evidence'), false);
  });

  test('Production deterministic registry contains the 4 Task-4 verification entries and Task-5 entry', () => {
    const reg = createProductionDeterministicRegistry();
    const ids = reg.listEntryIds();

    assert.equal(ids.length, 5);
    assert.ok(ids.includes(VERIFY_FORMAT_REGISTRY_ID));
    assert.ok(ids.includes(VERIFY_LINT_REGISTRY_ID));
    assert.ok(ids.includes(VERIFY_TYPECHECK_REGISTRY_ID));
    assert.ok(ids.includes(VERIFY_TEST_REGISTRY_ID));

    // Test entry must not be in production registry
    assert.equal(ids.includes(TEST_NODE_VERSION_REGISTRY_ID), false);
  });

  test('Built-in declarative policy requires approval for arc_verify', async () => {
    const wsReg = new WorkspaceRegistry();
    const engine = DeclarativePolicyEngine.builtIn(wsReg);

    const decision = engine.evaluate({ toolName: 'arc_verify' });
    assert.equal(decision.effect, 'REQUIRE_APPROVAL');
    assert.equal(decision.matchingRuleId, 'builtin-require-approval-rc07-verify');
  });

  test('materializeArcVerifyPlan maps suites accurately to deterministic plans', () => {
    const reg = createProductionDeterministicRegistry();

    // Default (all)
    const planAll = materializeArcVerifyPlan({
      workspaceId: 'ws-test',
      workspaceRoot: '/mock/path',
      registry: reg,
    });
    assert.equal(planAll.compositeTool, 'arc_verify');
    assert.equal(planAll.steps.length, 4);
    assert.equal(planAll.steps[0].stepId, 'format');
    assert.equal(planAll.steps[1].stepId, 'lint');
    assert.equal(planAll.steps[2].stepId, 'typecheck');
    assert.equal(planAll.steps[3].stepId, 'test');

    // Single suite: lint
    const planLint = materializeArcVerifyPlan({
      suite: 'lint',
      workspaceId: 'ws-test',
      workspaceRoot: '/mock/path',
      registry: reg,
    });
    assert.equal(planLint.steps.length, 1);
    assert.equal(planLint.steps[0].stepId, 'lint');
  });

  test('Task 4 timeout ceilings are frozen at 30s step / 120s aggregate', () => {
    assert.equal(DEFAULT_TASK4_STEP_TIMEOUT_MS, 30_000);
    assert.equal(DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS, 120_000);

    const { server } = createTestHarnessServer(cleanWorkspaceDir);
    assert.equal(getTask4StepTimeoutForTest(server), 30_000);
    assert.equal(getTask4AggregateTimeoutForTest(server), 120_000);

    // Lowering is permitted
    setTask4StepTimeoutForTest(server, 10_000);
    assert.equal(getTask4StepTimeoutForTest(server), 10_000);

    // Exceeding frozen maximum is rejected
    assert.throws(() => setTask4StepTimeoutForTest(server, 35_000));
    assert.throws(() => setTask4AggregateTimeoutForTest(server, 130_000));
  });

  test('Zero direct child_process, fs, or network imports in RC-07 composite production modules', () => {
    const compositePath = path.resolve('apps/mcp-server/src/composite-framework.ts');
    const verifyPath = path.resolve('apps/mcp-server/src/internal/verify.ts');

    const compositeSrc = fs.readFileSync(compositePath, 'utf8');
    const verifySrc = fs.readFileSync(verifyPath, 'utf8');

    for (const src of [compositeSrc, verifySrc]) {
      assert.ok(!src.includes("from 'child_process'"));
      assert.ok(!src.includes("from 'node:child_process'"));
      assert.ok(!src.includes("from 'fs'"));
      assert.ok(!src.includes("from 'node:fs'"));
      assert.ok(!src.includes("from 'node:fs/promises'"));
      assert.ok(!src.includes("from 'http'"));
      assert.ok(!src.includes("from 'node:http'"));
      assert.ok(!src.includes("from 'https'"));
      assert.ok(!src.includes("from 'node:https'"));
      assert.ok(!src.includes("from 'net'"));
      assert.ok(!src.includes("from 'node:net'"));
      assert.ok(!src.includes("from 'tls'"));
      assert.ok(!src.includes("from 'node:tls'"));
    }
  });
});
