/**
 * CesSpace ARC — RC-07 Task 5 Authoritative Test Suite
 *
 * Covers:
 * - Negative Controls: RC07-NEG-038 through RC07-NEG-046
 * - Positive Acceptance Flows: RC07-FLOW-11 and RC07-FLOW-12
 * - Invariant Regressions: Tool count (23), Registry entries (5), Built-in policy approval
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createArcMcpServer, ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import {
  createProductionDeterministicRegistry,
  ARC_TEST_NODE_REGISTRY_ID,
  VERIFY_FORMAT_REGISTRY_ID,
  VERIFY_LINT_REGISTRY_ID,
  VERIFY_TYPECHECK_REGISTRY_ID,
  VERIFY_TEST_REGISTRY_ID,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  materializeArcTestPlan,
  validateTestFilter,
  boundArcTestResponse,
  MAX_TEST_WIRE_BYTES,
} from '../apps/mcp-server/dist/internal/test.js';
import { DeclarativePolicyEngine, WorkspaceRegistry } from '../packages/policy/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

function makeSafeActor() {
  return {
    clientId: 'test-client',
    clientType: 'agent',
    sessionId: 'sess-task5-1',
    deviceId: 'dev-1',
    authenticated: true,
  };
}

describe('CesSpace ARC — RC-07 Task 5: arc_test Test Suite', () => {
  let tempRoot;
  let workspaceDir;
  let server;

  before(async () => {
    tempRoot = mkdtempSync(join(tmpdir(), 'arc-task5-test-'));
    workspaceDir = join(tempRoot, 'workspace');
    mkdirSync(workspaceDir, { recursive: true });

    server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws-task5', path: workspaceDir }],
      defaultWorkspaceId: 'ws-task5',
    });
  });

  after(() => {
    try {
      rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // =========================================================================
  // 1. Negative Controls (RC07-NEG-038 .. RC07-NEG-046)
  // =========================================================================

  describe('RC-07 Task 5: Negative Controls (RC07-NEG-038..046)', () => {
    test('RC07-NEG-038: outside-workspace testPath fails closed with PATH_OUTSIDE_WORKSPACE and zero spawn', async () => {
      const fsSubsystem = new FilesystemSubsystem();

      // Traversal attempt (../../outside.test.js)
      await assert.rejects(
        async () => {
          await fsSubsystem.validateTestPath(workspaceDir, '../../outside.test.js');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // Absolute escape attempt
      await assert.rejects(
        async () => {
          await fsSubsystem.validateTestPath(workspaceDir, '/etc/passwd');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // Symlink escape attempt
      const outsideFile = join(tempRoot, 'outside.test.js');
      writeFileSync(outsideFile, 'console.log("outside");');
      const escapingSymlink = join(workspaceDir, 'symlink-escape.test.js');
      try {
        symlinkSync(outsideFile, escapingSymlink);
      } catch {
        // ignore if symlinks restricted
      }

      if (escapingSymlink) {
        await assert.rejects(
          async () => {
            await fsSubsystem.validateTestPath(workspaceDir, 'symlink-escape.test.js');
          },
          (err) => {
            assert.ok(err instanceof ArcError);
            assert.equal(err.code, 'SYMLINK_ESCAPE_DETECTED');
            return true;
          },
        );
      }

      // Sensitive path attempt (.env)
      const envPath = join(workspaceDir, '.env');
      writeFileSync(envPath, 'SECRET=123');
      await assert.rejects(
        async () => {
          await fsSubsystem.validateTestPath(workspaceDir, '.env');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'ACCESS_DENIED');
          return true;
        },
      );

      // MCP call directly targeting traversal
      const res = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: '../../outside.test.js',
      });
      assert.equal(res.isError, true);
      const errPayload = JSON.parse(res.content[0].text);
      assert.equal(errPayload.code, 'PATH_OUTSIDE_WORKSPACE');
    });

    test('RC07-NEG-039: malicious filter containing shell controls or traversal is rejected before spawn', async () => {
      const maliciousFilters = [
        '; rm -rf /',
        '&& calc',
        '| cat /etc/passwd',
        '`whoami`',
        '$(id)',
        '> output.txt',
        '< input.txt',
        'test\nmalicious',
        'test\rmalicious',
        '../traversal',
        '..\\traversal',
        'null\0byte',
      ];

      for (const filter of maliciousFilters) {
        assert.throws(
          () => {
            validateTestFilter(filter);
          },
          (err) => {
            assert.ok(err instanceof ArcError);
            assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
            return true;
          },
        );

        // Through MCP dispatch
        const res = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
          filter,
        });
        assert.equal(res.isError, true);
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
      }
    });

    test('RC07-NEG-040: unapproved test runner or package-manager script cannot enter closed registry or spawn', async () => {
      // Direct schema validation rejects testRunner !== 'node'
      const unapprovedRunners = ['jest', 'mocha', 'vitest', 'npm', 'pnpm', 'npx'];
      for (const runner of unapprovedRunners) {
        const res = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
          testRunner: runner,
        });
        assert.equal(res.isError, true);
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
      }

      // Materializer rejects non-node testRunner
      assert.throws(
        () => {
          materializeArcTestPlan({
            testRunner: 'jest',
            workspaceId: 'ws-task5',
            workspaceRoot: workspaceDir,
            registry: createProductionDeterministicRegistry(),
          });
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
          return true;
        },
      );
    });

    test('RC07-NEG-041: real test exceeds requested/default timeout; process is terminated/reaped and response is TIMED_OUT', async () => {
      const slowTestFile = join(workspaceDir, 'slow.test.js');
      writeFileSync(
        slowTestFile,
        `
const test = require('node:test');
test('slow test that hangs', async () => {
  await new Promise((resolve) => setTimeout(resolve, 10000));
});
`,
      );

      // Invoke without approval -> get approval request
      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'slow.test.js',
        maxDurationMs: 400,
      });
      assert.equal(reqRes.isError, true);
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      // Approve
      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      // Execute with approval token
      const execRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'slow.test.js',
        maxDurationMs: 400,
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      assert.equal(execRes.isError, undefined);
      const body = JSON.parse(execRes.content[0].text);
      assert.equal(body.status, 'TIMED_OUT');
      assert.ok(body.processId);
      assert.equal(body.target, 'slow.test.js');
    });

    test('RC07-NEG-042: maxDurationMs > 60000 and < 100 rejected strictly by schema; zero spawn', async () => {
      const invalidTimeouts = [60001, 100000, 99, 0, -100];
      for (const maxDurationMs of invalidTimeouts) {
        const res = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
          maxDurationMs,
        });
        assert.equal(res.isError, true);
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
      }
    });

    test('RC07-NEG-043: fifth concurrent workspace test beyond limit 4 spawns zero process and returns CONCURRENCY_EXCEEDED', async () => {
      const procRegistry = server.processRegistry;
      assert.ok(procRegistry);

      // Create 4 active processes in the workspace to reach maxPerWorkspaceRunning = 4
      const activeIds = [];
      for (let i = 0; i < 4; i++) {
        const record = procRegistry.registerProcess({
          workspaceId: 'ws-task5',
          actor: {
            clientId: 'test-client',
            clientType: 'agent',
            sessionId: `sess-concurrency-${i}`,
            deviceId: 'dev-1',
          },
          executable: 'node',
          sanitizedArgs: ['--version'],
          cwd: workspaceDir,
          startedAt: new Date().toISOString(),
          state: 'RUNNING',
          timedOut: false,
        });
        activeIds.push(record.processId);
      }

      assert.equal(procRegistry.countRunning({ workspaceId: 'ws-task5' }), 4);

      // Create a test file for the 5th attempt
      const dummyTest = join(workspaceDir, 'dummy.test.js');
      writeFileSync(dummyTest, `const test = require('node:test'); test('quick', () => {});`);

      // Request approval
      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'dummy.test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      // 5th execution attempt must fail closed with CONCURRENCY_EXCEEDED
      const fifthRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'dummy.test.js',
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      assert.equal(fifthRes.isError, true);
      const fifthPayload = JSON.parse(fifthRes.content[0].text);
      assert.equal(fifthPayload.code, 'CONCURRENCY_EXCEEDED');

      // Still exactly 4 running processes; zero 5th process spawned
      assert.equal(procRegistry.countRunning({ workspaceId: 'ws-task5' }), 4);

      // Clean up the 4 registered active processes
      for (const id of activeIds) {
        procRegistry.markCompleted(id, 0, null);
      }
    });

    test('RC07-NEG-044: child and grandchild process cannot survive composite timeout; orphan cleanup enforced', async () => {
      const orphanTestFile = join(workspaceDir, 'orphan.test.js');
      writeFileSync(
        orphanTestFile,
        `
const { spawn } = require('node:child_process');
const test = require('node:test');
const fs = require('node:fs');

test('spawns SIGTERM-resistant descendant process then hangs', async () => {
  const descendantScript = \`
    const fs = require('node:fs');
    process.on('SIGTERM', () => {
      // Explicitly ignore SIGTERM so process only dies upon SIGKILL escalation
    });
    fs.writeSync(1, 'DESCENDANT_PID:' + process.pid + '\\\\n');
    setInterval(() => {}, 10000);
  \`;
  const descendant = spawn(process.execPath, ['-e', descendantScript], {
    stdio: ['ignore', 'inherit', 'ignore'],
  });
  await new Promise((resolve) => setTimeout(resolve, 10000));
});
`,
      );

      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'orphan.test.js',
        maxDurationMs: 1200,
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      const execRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'orphan.test.js',
        maxDurationMs: 1200,
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      const body = JSON.parse(execRes.content[0].text);
      assert.equal(body.status, 'TIMED_OUT');
      assert.ok(body.processId, 'Response must include processId');

      // Assert the root ProcessRegistry record is terminal and timedOut === true
      const procRegistry = server.processRegistry;
      const procRecord = procRegistry.processes?.get(body.processId);
      assert.ok(procRecord, 'ProcessRegistry must retain record for timed out execution');
      assert.equal(procRecord.state, 'TIMED_OUT', 'Root record must be terminal TIMED_OUT');
      assert.equal(procRecord.timedOut, true, 'Record timedOut must be true');

      // Capture descendant PID deterministically; assertion MUST NOT be conditional
      const match = /DESCENDANT_PID:(\d+)/.exec(body.outputExcerpt);
      assert.ok(match, 'Must capture descendant PID deterministically from test output excerpt');
      const descendantPid = parseInt(match[1], 10);
      assert.ok(
        Number.isInteger(descendantPid) && descendantPid > 0,
        'Descendant PID must be a valid positive integer',
      );

      // Wait beyond the 1000ms SIGKILL escalation grace period
      await new Promise((r) => setTimeout(r, 1300));

      // Assert descendant process was forcefully reaped by SIGKILL escalation
      let descendantAlive = true;
      try {
        process.kill(descendantPid, 0);
      } catch (err) {
        if (err && err.code === 'ESRCH') {
          descendantAlive = false;
        }
      }
      assert.equal(
        descendantAlive,
        false,
        `SIGTERM-resistant descendant PID ${descendantPid} must not survive SIGKILL escalation`,
      );

      // Assert no RUNNING or TERMINATING ProcessRegistry record remains for the operation
      const runningRecords = procRegistry.listProcesses({ state: 'RUNNING' });
      const terminatingRecords = procRegistry.listProcesses({ state: 'TERMINATING' });
      assert.equal(
        runningRecords.some((r) => r.processId === body.processId),
        false,
      );
      assert.equal(
        terminatingRecords.some((r) => r.processId === body.processId),
        false,
      );
      assert.equal(procRecord.state, 'TIMED_OUT');
    });

    test('RC07-NEG-045: process output containing simulated private key/tokens is redacted in MCP response', async () => {
      const secretTestFile = join(workspaceDir, 'secret.test.js');
      // Construct dynamic secret tokens so Gitleaks does not trigger on test source
      const pemHeader = '-----BEGIN ' + 'PRIVATE KEY-----';
      const pemFooter = '-----END ' + 'PRIVATE KEY-----';
      const fakeToken = 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz';
      const fakeOpenAi = 'sk-' + 'abcdefghijklmnopqrstuvwxyz1234567890';

      writeFileSync(
        secretTestFile,
        `
const test = require('node:test');
test('prints secrets', () => {
  console.log('${pemHeader}\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\\n${pemFooter}');
  console.log('GitHub Token: ${fakeToken}');
  console.log('OpenAI Token: ${fakeOpenAi}');
});
`,
      );

      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'secret.test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      const execRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'secret.test.js',
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      const wireText = execRes.content[0].text;
      assert.ok(
        !wireText.includes(fakeToken),
        'Raw simulated GitHub token must not appear on wire',
      );
      assert.ok(
        !wireText.includes(fakeOpenAi),
        'Raw simulated OpenAI token must not appear on wire',
      );
      assert.ok(wireText.includes('[REDACTED_SECRET]'), 'Redaction marker must be present');
    });

    test('RC07-NEG-046: invocation without approval creates approval request with zero process spawns', async () => {
      const dummyTest = join(workspaceDir, 'sample-unit.test.js');
      writeFileSync(dummyTest, `const test = require('node:test'); test('ok', () => {});`);

      const procRegistry = server.processRegistry;
      const beforeRunning = procRegistry.countRunning({ workspaceId: 'ws-task5' });

      const res = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'sample-unit.test.js',
      });

      assert.equal(res.isError, true);
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED');
      assert.ok(body.details.approvalRequestId);

      const afterRunning = procRegistry.countRunning({ workspaceId: 'ws-task5' });
      assert.equal(afterRunning, beforeRunning, 'Zero processes spawned when approval required');
    });
  });

  // =========================================================================
  // 2. Positive Acceptance Flows (RC07-FLOW-11, RC07-FLOW-12)
  // =========================================================================

  describe('RC-07 Task 5: Positive Acceptance Flows (RC07-FLOW-11..12)', () => {
    test('RC07-FLOW-11: Controlled Test Execution (exact counts, exitCode, targeted path, and name filter)', async () => {
      const suiteFile = join(workspaceDir, 'suite.test.js');
      writeFileSync(
        suiteFile,
        `
const test = require('node:test');
test('math: addition passes', () => {});
test('math: subtraction passes', () => {});
test('io: fails on purpose', () => { throw new Error('intentional failure'); });
test('ui: skipped test', (t) => { t.skip('skipped'); });
`,
      );

      // Part 1: Full targeted suite execution
      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'suite.test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      const execRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'suite.test.js',
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      assert.equal(execRes.isError, undefined);
      const body = JSON.parse(execRes.content[0].text);

      assert.equal(body.testRunner, 'node');
      assert.equal(body.target, 'suite.test.js');
      assert.equal(body.status, 'FAILED');
      assert.equal(body.exitCode, 1);
      assert.equal(body.passedCount, 2);
      assert.equal(body.failedCount, 1);
      assert.equal(body.skippedCount, 1);
      assert.ok(body.processId);
      assert.equal(body.truncated, false);
      assert.ok(body.outputExcerpt.length > 0);

      // Part 2: Safe filter selecting only 'math' tests (both pass -> status PASSED)
      const reqRes2 = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'suite.test.js',
        filter: 'math',
      });
      const reqPayload2 = JSON.parse(reqRes2.content[0].text);
      assert.equal(reqPayload2.code, 'APPROVAL_REQUIRED');

      const approval2 = approvalManager.approve(reqPayload2.details.approvalRequestId);

      const execRes2 = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'suite.test.js',
        filter: 'math',
        _arcApproval: {
          requestId: reqPayload2.details.approvalRequestId,
          token: approval2.token,
        },
      });

      assert.equal(execRes2.isError, undefined);
      const body2 = JSON.parse(execRes2.content[0].text);
      assert.equal(body2.status, 'PASSED');
      assert.equal(body2.exitCode, 0);
      assert.equal(body2.passedCount, 2);
      assert.equal(body2.failedCount, 0);
      assert.equal(body2.skippedCount, 0);
    });

    test('RC07-FLOW-12: Test Timeout and Stubborn Child Cleanup via SIGKILL Escalation', async () => {
      const stubbornTest = join(workspaceDir, 'stubborn.test.js');
      writeFileSync(
        stubbornTest,
        `
const { spawn } = require('node:child_process');
const test = require('node:test');
const fs = require('node:fs');

test('stubborn test requiring SIGKILL escalation', async () => {
  const childScript = \`
    const fs = require('node:fs');
    process.on('SIGTERM', () => {
      // Ignore SIGTERM to require SIGKILL escalation
    });
    fs.writeSync(1, 'STUBBORN_PID:' + process.pid + '\\\\n');
    setInterval(() => {}, 10000);
  \`;
  const child = spawn(process.execPath, ['-e', childScript], {
    stdio: ['ignore', 'inherit', 'ignore'],
  });
  await new Promise((resolve) => setTimeout(resolve, 10000));
});
`,
      );

      // Register lifecycle sink on server.processRegistry to truthfully observe lifecycle events
      const lifecycleEvents = [];
      const procRegistry = server.processRegistry;
      procRegistry.registerLifecycleSink({
        onProcessEvent(evt) {
          lifecycleEvents.push(evt);
        },
      });

      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'stubborn.test.js',
        maxDurationMs: 1200,
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(reqPayload.details.approvalRequestId);

      const execRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'stubborn.test.js',
        maxDurationMs: 1200,
        _arcApproval: {
          requestId: reqPayload.details.approvalRequestId,
          token: approval.token,
        },
      });

      assert.equal(execRes.isError, undefined);
      const body = JSON.parse(execRes.content[0].text);
      assert.equal(body.status, 'TIMED_OUT');
      assert.ok(body.processId);

      // Deterministically capture stubborn child PID
      const match = /STUBBORN_PID:(\d+)/.exec(body.outputExcerpt);
      assert.ok(match, 'Must capture stubborn process PID from output excerpt');
      const stubbornPid = parseInt(match[1], 10);
      assert.ok(Number.isInteger(stubbornPid) && stubbornPid > 0);

      // Wait beyond the 1000ms SIGKILL escalation grace period
      await new Promise((resolve) => setTimeout(resolve, 1300));

      // Assert stubborn process was forcefully reaped by SIGKILL escalation
      let stubbornAlive = true;
      try {
        process.kill(stubbornPid, 0);
      } catch (err) {
        if (err && err.code === 'ESRCH') {
          stubbornAlive = false;
        }
      }
      assert.equal(
        stubbornAlive,
        false,
        `Stubborn child PID ${stubbornPid} must be reaped by SIGKILL escalation`,
      );

      // Verify truthful lifecycle events recorded through ProcessRegistry
      const opEvents = lifecycleEvents.filter((e) => e.processId === body.processId);
      const eventTypes = opEvents.map((e) => e.eventType);
      assert.ok(
        eventTypes.includes('PROCESS_TIMEOUT'),
        `Lifecycle events must contain PROCESS_TIMEOUT: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.includes('PROCESS_SIGTERM_SENT'),
        `Lifecycle events must contain PROCESS_SIGTERM_SENT: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.includes('PROCESS_SIGKILL_ESCALATED'),
        `Lifecycle events must contain PROCESS_SIGKILL_ESCALATED: ${JSON.stringify(eventTypes)}`,
      );

      // Verify ProcessRegistry has reaped the process into terminal TIMED_OUT state
      const procRecord = procRegistry.processes?.get(body.processId);
      assert.ok(procRecord);
      assert.equal(procRecord.state, 'TIMED_OUT');
      assert.equal(procRecord.timedOut, true);

      // Verify no active records remain
      const runningRecords = procRegistry.listProcesses({ state: 'RUNNING' });
      const terminatingRecords = procRegistry.listProcesses({ state: 'TERMINATING' });
      assert.equal(
        runningRecords.some((r) => r.processId === body.processId),
        false,
      );
      assert.equal(
        terminatingRecords.some((r) => r.processId === body.processId),
        false,
      );
    });
  });

  // =========================================================================
  // 3. Invariants, Discovery & Quality Regressions
  // =========================================================================

  describe('RC-07 Task 5: Invariants, Discovery & Quality Regressions', () => {
    test('Discovery: Production tool count is exactly 25 (including arc_test, arc_ci_status, and arc_stage_evidence)', () => {
      assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
      const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);

      assert.ok(names.includes('arc_ci_status'), 'arc_ci_status must be advertised');
      assert.ok(names.includes('arc_test'), 'arc_test must be advertised');
      assert.ok(names.includes('arc_verify'));
      assert.ok(names.includes('arc_review_diff'));
      assert.ok(names.includes('arc_repo_status'));
      assert.ok(names.includes('arc_worktree_status'));

      // Task 7 tool is present
      assert.equal(
        names.includes('arc_stage_evidence'),
        true,
        'arc_stage_evidence must be advertised',
      );
    });

    test('Production deterministic registry contains exactly 5 entries (4 Task-4 + 1 Task-5)', () => {
      const reg = createProductionDeterministicRegistry();
      const ids = reg.listEntryIds();

      assert.equal(ids.length, 5);
      assert.ok(ids.includes(VERIFY_FORMAT_REGISTRY_ID));
      assert.ok(ids.includes(VERIFY_LINT_REGISTRY_ID));
      assert.ok(ids.includes(VERIFY_TYPECHECK_REGISTRY_ID));
      assert.ok(ids.includes(VERIFY_TEST_REGISTRY_ID));
      assert.ok(ids.includes(ARC_TEST_NODE_REGISTRY_ID));
    });

    test('Built-in declarative policy requires approval for arc_test', async () => {
      const wsReg = new WorkspaceRegistry();
      wsReg.registerWorkspace('ws-p', workspaceDir);
      const engine = DeclarativePolicyEngine.builtIn(wsReg);

      const decision = engine.evaluate({
        toolName: 'arc_test',
        actor: { clientId: 'client', sessionId: 'sess', deviceId: 'dev' },
        targetWorkspace: { workspaceId: 'ws-p', rootPath: workspaceDir },
        businessParameters: {},
      });

      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'builtin-require-approval-rc07-test');
    });

    test('Final MCP response wire size never exceeds 262,144 bytes', () => {
      const largeOutput = 'X'.repeat(500_000);
      const bounded = boundArcTestResponse(
        {
          testRunner: 'node',
          target: 'large.test.js',
          status: 'PASSED',
          exitCode: 0,
          durationMs: 100,
          outputExcerpt: largeOutput,
          truncated: false,
          processId: 'arc-proc-large',
        },
        MAX_TEST_WIRE_BYTES,
      );

      const serialized = JSON.stringify(bounded, null, 2);
      const byteLen = Buffer.byteLength(serialized, 'utf8');
      assert.ok(
        byteLen <= MAX_TEST_WIRE_BYTES,
        `Serialized response byteLength ${byteLen} must be <= ${MAX_TEST_WIRE_BYTES}`,
      );
      assert.equal(bounded.truncated, true);
    });

    test('PlanHash binding: modifying parameters between request and redemption invalidates approval', async () => {
      const testFile = join(workspaceDir, 'bind.test.js');
      writeFileSync(testFile, 'const test = require("node:test"); test("ok", () => {});');

      const reqRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'bind.test.js',
        maxDurationMs: 5000,
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const requestId = reqPayload.details.approvalRequestId;

      const approvalManager = server.approvalStateManager;
      const approval = approvalManager.approve(requestId);

      // Attempt redemption with different filter
      const tamperedRes = await server.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'bind.test.js',
        filter: 'changedFilter',
        maxDurationMs: 5000,
        _arcApproval: {
          requestId,
          token: approval.token,
        },
      });

      assert.equal(tamperedRes.isError, true);
      const tamperedPayload = JSON.parse(tamperedRes.content[0].text);
      assert.equal(tamperedPayload.code, 'APPROVAL_REJECTED');
    });
  });
});
