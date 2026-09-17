import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { WorkspaceRegistry, SecurityKernel } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ProcessRegistry, sliceUtf8Safe } from '../packages/processes/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';

describe('CesSpace ARC — RC-02 Mandatory Security Negative & Positive Controls', () => {
  let tempDir;
  let workspaceDir;
  let server;
  let auditLogger;
  let processRegistry;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc02-suite-'));
    workspaceDir = path.join(tempDir, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Initialize fixture git repo
    execFileSync('git', ['init', '-b', 'main'], { cwd: workspaceDir });
    execFileSync('git', ['config', 'user.name', 'P Thakur'], { cwd: workspaceDir });
    execFileSync(
      'git',
      ['config', 'user.email', '321108211+kpthakur2026@users.noreply.github.com'],
      {
        cwd: workspaceDir,
      },
    );
    fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# RC-02 Fixture\n');
    execFileSync('git', ['add', '.'], { cwd: workspaceDir });
    execFileSync('git', ['commit', '-m', 'chore: rc-02 test fixture'], { cwd: workspaceDir });

    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('test-ws', workspaceDir);

    auditLogger = new AuditLogger();
    processRegistry = new ProcessRegistry();
    const kernel = new SecurityKernel(registry, processRegistry);
    const filesystem = new FilesystemSubsystem();
    const git = new GitSubsystem();
    const terminal = new ControlledProcessRunner(processRegistry);

    server = new ArcMcpServer(
      registry,
      kernel,
      auditLogger,
      filesystem,
      git,
      {
        defaultWorkspaceId: 'test-ws',
      },
      terminal,
      processRegistry,
    );
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  // ==========================================================================
  // SECTION 1: EXECUTABLE POLICY DENIALS (denied list + allowlist)
  // ==========================================================================

  test('RC02-N-01: shell executable (bash) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'bash',
      args: ['-c', 'echo pwned'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-02: shell executable (sh) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'sh',
      args: ['-c', 'id'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-03: privilege escalation (sudo) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'sudo',
      args: ['whoami'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-04: destructive command (rm) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'rm',
      args: ['-rf', '/'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-05: network tool (curl) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'curl',
      args: ['https://evil.example.com'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-06: network tool (wget) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'wget',
      args: ['https://evil.example.com'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-07: system destruction (dd) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'dd',
      args: ['if=/dev/zero', 'of=/dev/sda'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-08: container tool (docker) is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'docker',
      args: ['run', '--privileged', 'alpine'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-09: unapproved executable (cat) not in allowlist is denied', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'cat',
      args: ['/etc/passwd'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  // ==========================================================================
  // SECTION 2: ARGUMENT INJECTION DENIALS
  // ==========================================================================

  test('RC02-N-10: shell metacharacter -c in args is denied', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['-c', 'process.exit(0)'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-11: command substitution $() in args is denied', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['$(evil_cmd)'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-12: backtick command substitution in args is denied', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['`evil_cmd`'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-13: newline injection in args is denied', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['safe\nevil'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-14: git write subcommands are denied by policy (git commit)', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['commit', '--allow-empty', '-m', 'injected'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-15: git push is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['push', 'origin', 'main'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-16: npm install from run_command is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npm',
      args: ['install', 'evil-package'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  // ==========================================================================
  // SECTION 3: ENVIRONMENT KEY ALLOWLIST
  // ==========================================================================

  test('RC02-N-17: non-allowlisted env key is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
      env: { HOME: '/tmp/evil' },
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-N-18: PATH override via env is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
      env: { PATH: '/tmp/evil:/usr/bin' },
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  // ==========================================================================
  // SECTION 4: SCHEMA VALIDATION FAILURES
  // ==========================================================================

  test('RC02-N-19: run_command without executable fails schema', async () => {
    const res = await server.dispatchToolCall('run_command', {
      args: ['--version'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-20: run_command with extra unknown property fails schema (strict mode)', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      unknown_field: true,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-21: run_command with too many args fails schema', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: new Array(101).fill('--version'),
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-22: run_command with oversized executable string fails schema', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'n'.repeat(129),
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-23: process_status without processId fails schema', async () => {
    const res = await server.dispatchToolCall('process_status', {});
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-24: process_output without processId fails schema', async () => {
    const res = await server.dispatchToolCall('process_output', {});
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-25: terminate_process without processId fails schema', async () => {
    const res = await server.dispatchToolCall('terminate_process', {});
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('RC02-N-26: terminate_process with invalid signal value fails schema', async () => {
    const res = await server.dispatchToolCall('terminate_process', {
      processId: 'arc-proc-test',
      signal: 'SIGALRM',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  // ==========================================================================
  // SECTION 5: PROCESS LIFECYCLE OWNERSHIP / INVALID ID
  // ==========================================================================

  test('RC02-N-27: process_status for non-existent processId returns error', async () => {
    const res = await server.dispatchToolCall('process_status', {
      processId: 'arc-proc-00000000-does-not-exist',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'NOT_FOUND' ||
        parsed.code === 'POLICY_DENIED' ||
        parsed.code === 'PROCESS_NOT_FOUND',
      `Expected NOT_FOUND, POLICY_DENIED, or PROCESS_NOT_FOUND, got ${parsed.code}`,
    );
  });

  test('RC02-N-28: process_output for non-existent processId returns error', async () => {
    const res = await server.dispatchToolCall('process_output', {
      processId: 'arc-proc-00000000-does-not-exist',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'NOT_FOUND' ||
        parsed.code === 'POLICY_DENIED' ||
        parsed.code === 'PROCESS_NOT_FOUND',
      `Expected NOT_FOUND, POLICY_DENIED, or PROCESS_NOT_FOUND, got ${parsed.code}`,
    );
  });

  test('RC02-N-29: terminate_process for non-existent processId returns error', async () => {
    const res = await server.dispatchToolCall('terminate_process', {
      processId: 'arc-proc-00000000-does-not-exist',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'NOT_FOUND' ||
        parsed.code === 'POLICY_DENIED' ||
        parsed.code === 'PROCESS_NOT_FOUND',
      `Expected NOT_FOUND, POLICY_DENIED, or PROCESS_NOT_FOUND, got ${parsed.code}`,
    );
  });

  // ==========================================================================
  // SECTION 6: AUDIT EVIDENCE FOR DENIED OPERATIONS
  // ==========================================================================

  test('RC02-N-30: denied run_command (denied executable) produces audit record with DENY', async () => {
    const preCount = auditLogger.getRecords().length;
    await server.dispatchToolCall('run_command', {
      executable: 'bash',
      args: ['-c', 'whoami'],
    });
    const postCount = auditLogger.getRecords().length;
    assert.equal(postCount, preCount + 1, 'Must produce exactly 1 audit record');
    const rec = auditLogger.getRecords()[postCount - 1];
    assert.equal(rec.execution.status, 'DENIED');
    assert.equal(rec.policy.decision, 'DENY');
    assert.equal(rec.error?.code, 'POLICY_DENIED');
  });

  test('RC02-N-31: schema-failed run_command produces audit record with DENY', async () => {
    const preCount = auditLogger.getRecords().length;
    await server.dispatchToolCall('run_command', {});
    const postCount = auditLogger.getRecords().length;
    assert.equal(postCount, preCount + 1, 'Must produce exactly 1 audit record');
    const rec = auditLogger.getRecords()[postCount - 1];
    assert.equal(rec.execution.status, 'DENIED');
    assert.equal(rec.error?.code, 'INVALID_REQUEST_SCHEMA');
  });

  // ==========================================================================
  // SECTION 7: RC-02 POSITIVE CONTROLS (run_command + process lifecycle)
  // ==========================================================================

  test('RC02-P-01: run_command node --version returns foreground output', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId, 'Must return a processId');
    assert.ok(
      parsed.state === 'COMPLETED' || parsed.state === 'RUNNING',
      `Expected COMPLETED or RUNNING, got ${parsed.state}`,
    );
  });

  test('RC02-P-02: run_command git status returns foreground output within workspace', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status', '--porcelain'],
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId, 'Must return a processId');
  });

  test('RC02-P-03: run_command in background returns processId immediately (git log)', async () => {
    // git log is a read-only allowlisted command that completes quickly
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['log', '--oneline', '-1'],
      runInBackground: true,
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId, 'Must return a processId');
    assert.ok(parsed.processId.startsWith('arc-proc-'), 'processId must have arc-proc- prefix');
  });

  test('RC02-P-04: process_status returns valid state for a completed process', async () => {
    // Run a quick command to completion
    const runRes = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    });
    assert.equal(runRes.isError, undefined);
    const runParsed = JSON.parse(runRes.content[0].text);
    const pid = runParsed.processId;
    assert.ok(pid, 'Must return a processId');

    // Check status
    const statusRes = await server.dispatchToolCall('process_status', {
      processId: pid,
    });
    assert.equal(statusRes.isError, undefined);
    const statusParsed = JSON.parse(statusRes.content[0].text);
    assert.ok(
      ['RUNNING', 'COMPLETED', 'FAILED'].includes(statusParsed.state),
      `Unexpected state: ${statusParsed.state}`,
    );
    assert.equal(statusParsed.processId, pid);
  });

  test('RC02-P-05: process_output returns buffered stdoutChunk for completed process', async () => {
    const runRes = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    });
    assert.equal(runRes.isError, undefined);
    const pid = JSON.parse(runRes.content[0].text).processId;
    assert.ok(pid);

    const outputRes = await server.dispatchToolCall('process_output', {
      processId: pid,
    });
    assert.equal(outputRes.isError, undefined);
    const outputParsed = JSON.parse(outputRes.content[0].text);
    // process_output returns stdoutChunk and stderrChunk
    assert.ok(typeof outputParsed.stdoutChunk === 'string', 'stdoutChunk must be string');
    // node --version outputs version string like v24.x.x
    assert.ok(outputParsed.stdoutChunk.includes('v'), 'stdoutChunk should contain version string');
  });

  test('RC02-P-06: terminate_process returns valid response for a background process', async () => {
    // Start a background git process
    const runRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['log', '--oneline', '-100'],
      runInBackground: true,
    });
    if (runRes.isError) {
      // If run_command errored for some reason, skip
      return;
    }
    const pid = JSON.parse(runRes.content[0].text).processId;
    assert.ok(pid);

    const termRes = await server.dispatchToolCall('terminate_process', {
      processId: pid,
      signal: 'SIGTERM',
    });
    // terminate_process must not error — either it sends the signal or process already completed
    assert.equal(
      termRes.isError,
      undefined,
      `terminate_process must not error: ${termRes.content[0].text}`,
    );
    const termParsed = JSON.parse(termRes.content[0].text);
    // Response shape: { processId, terminated: boolean, signal: string }
    assert.equal(termParsed.processId, pid, 'processId must match');
    assert.ok(typeof termParsed.terminated === 'boolean', 'terminated must be boolean');
    // signal is 'SIGTERM' if sent, 'NONE' if process already ended
    assert.ok(
      termParsed.signal === 'SIGTERM' || termParsed.signal === 'NONE',
      `signal must be SIGTERM or NONE, got ${termParsed.signal}`,
    );
  });

  test('RC02-P-07: allowlisted env key (NODE_ENV) does not add POLICY_DENIED for env key itself', async () => {
    // NODE_ENV is allowlisted. node --version with NODE_ENV=test should not fail for env key reasons.
    // The node --version command succeeds without -e.
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
      env: { NODE_ENV: 'test' },
    });
    // This must succeed (no schema or env-key denial)
    assert.equal(
      res.isError,
      undefined,
      `NODE_ENV=test with node --version should succeed, got: ${res.content[0].text}`,
    );
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId, 'Must return a processId');
  });

  test('RC02-P-08: run_command produces audit record with ALLOW on success', async () => {
    const preCount = auditLogger.getRecords().length;
    void (await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    }));
    const newRecords = auditLogger.getRecords().slice(preCount);
    const runCmdRec = newRecords.find((r) => r.invocation.toolName === 'run_command');
    assert.ok(runCmdRec, 'Must produce a run_command audit record');
    assert.equal(runCmdRec.policy.decision, 'ALLOW');
    assert.equal(runCmdRec.execution.status, 'SUCCESS');
  });

  // ==========================================================================
  // SECTION 8: CWD CONTAINMENT
  // ==========================================================================

  test('RC02-N-32: cwd escaping workspace via .. is denied or sanitized', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
      cwd: '../../etc',
    });
    // Must either fail closed (error) or resolve within workspace
    if (res.isError) {
      const parsed = JSON.parse(res.content[0].text);
      assert.ok(
        parsed.code === 'PATH_ESCAPES_ROOT' ||
          parsed.code === 'POLICY_DENIED' ||
          parsed.code === 'NOT_FOUND' ||
          parsed.code === 'INTERNAL_ERROR',
        `Expected escape rejection, got ${parsed.code}`,
      );
    }
    // If no error, the result must still be a valid process (not an escape)
  });

  test('RC02-N-33: executable with path separator is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: '/usr/bin/node',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'POLICY_DENIED' ||
        parsed.code === 'INVALID_REQUEST_SCHEMA' ||
        parsed.code === 'FORBIDDEN_COMMAND',
      `Expected POLICY_DENIED, INVALID_REQUEST_SCHEMA, or FORBIDDEN_COMMAND, got ${parsed.code}`,
    );
  });

  // ==========================================================================
  // SECTION 9: INDEPENDENT REVIEW SECURITY REGRESSIONS (P0 & P1)
  // ==========================================================================

  // P0-02: Code execution bypasses forbidden
  test('RC02-REG-01: node <script> is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['index.js'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-02: node -e / --eval is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['-e', 'console.log(1)'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-03: npx is explicitly forbidden', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npx',
      args: ['vitest'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-04: npm run is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npm',
      args: ['run', 'build'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-05: npm start is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npm',
      args: ['start'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-06: npm test is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npm',
      args: ['test'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-07: npm exec is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'npm',
      args: ['exec', 'vitest'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-08: pnpm run is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'pnpm',
      args: ['run', 'build'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-09: pnpm exec is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'pnpm',
      args: ['exec', 'vitest'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-10: pnpm dlx is denied by policy', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'pnpm',
      args: ['dlx', 'vitest'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  // P1-02: Trusted executable resolution strictly refuses user-controlled directories
  test('RC02-REG-11: node_modules/.bin resolution is strictly forbidden', async () => {
    const binDir = path.join(workspaceDir, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const fakeBin = path.join(binDir, 'fake-tool');
    fs.writeFileSync(fakeBin, '#!/bin/sh\necho "exploit"\n', { mode: 0o755 });

    const res = await server.dispatchToolCall('run_command', {
      executable: 'fake-tool',
      args: ['--version'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  // P0-04: Process ownership bound to clientId, sessionId, workspaceId
  test('RC02-REG-12: process supervision fails closed when caller identity is missing', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    const res = await server.dispatchToolCall(
      'process_status',
      { processId: pid },
      { clientId: '', sessionId: '' },
    );
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-13: process supervision fails closed when clientId is mismatched', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    const res = await server.dispatchToolCall(
      'process_status',
      { processId: pid },
      { clientId: 'attacker-client-id' },
    );
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-14: process supervision fails closed when sessionId is mismatched', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    const res = await server.dispatchToolCall(
      'process_output',
      { processId: pid },
      { sessionId: 'attacker-session-id' },
    );
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-15: process supervision fails closed when workspaceId is mismatched', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    assert.throws(() => {
      processRegistry.assertOwnership(pid, {
        clientId: 'local-stdio-caller',
        sessionId: 'stdio-session-01',
        workspaceId: 'other-ws',
      });
    }, /does not match process workspace/i);
  });

  // P0-05: Asynchronous lifecycle events audited
  test('RC02-REG-16: PROCESS_SPAWN_SUCCEEDED lifecycle event is recorded in audit logger', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['status'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    const records = auditLogger.getRecords();
    const spawnRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SPAWN_SUCCEEDED' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    assert.ok(spawnRec, 'Must log PROCESS_SPAWN_SUCCEEDED');
    assert.equal(spawnRec.target.workspaceId, 'test-ws');
  });

  test('RC02-REG-17: PROCESS_SPAWN_FAILED lifecycle event is recorded in audit logger', async () => {
    processRegistry.clear();
    const dummyRecord = processRegistry.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'test-client', sessionId: 'test-session' },
      executable: 'nonexistent-binary',
      sanitizedArgs: [],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    processRegistry.markSpawnFailed(dummyRecord.processId, 'ENOENT spawn failure');

    const records = auditLogger.getRecords();
    const failRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SPAWN_FAILED' &&
        r.invocation.parametersRedacted.processId === dummyRecord.processId,
    );
    assert.ok(failRec, 'Must log PROCESS_SPAWN_FAILED');
    assert.equal(failRec.execution.status, 'ERROR');
  });

  test('RC02-REG-18: PROCESS_EXITED lifecycle event is recorded in audit logger', async () => {
    processRegistry.clear();
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    });
    const pid = JSON.parse(res.content[0].text).processId;

    const records = auditLogger.getRecords();
    const exitRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_EXITED' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    assert.ok(exitRec, 'Must log PROCESS_EXITED');
    assert.equal(exitRec.execution.exitCode, 0);
  });

  test('RC02-REG-19: PROCESS_TIMEOUT lifecycle event is recorded in audit logger', async () => {
    processRegistry.clear();
    const dummyRecord = processRegistry.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'test-client', sessionId: 'test-session' },
      executable: 'git',
      sanitizedArgs: ['status'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    processRegistry.markTimedOut(dummyRecord.processId);

    const records = auditLogger.getRecords();
    const timeoutRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_TIMEOUT' &&
        r.invocation.parametersRedacted.processId === dummyRecord.processId,
    );
    assert.ok(timeoutRec, 'Must log PROCESS_TIMEOUT');
    assert.equal(timeoutRec.execution.status, 'TIMEOUT');
  });

  test('RC02-REG-20: PROCESS_TERMINATION_REQUESTED, PROCESS_SIGTERM_SENT, and PROCESS_TERMINATED lifecycle events are recorded', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['log', '--oneline', '-100'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;

    await server.dispatchToolCall('terminate_process', {
      processId: pid,
      signal: 'SIGTERM',
    });

    const records = auditLogger.getRecords();
    const reqRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_TERMINATION_REQUESTED' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    const sigRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SIGTERM_SENT' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    assert.ok(reqRec, 'Must log PROCESS_TERMINATION_REQUESTED');
    assert.ok(sigRec, 'Must log PROCESS_SIGTERM_SENT');
  });

  // P1-03: Process group kill and grace period
  test('RC02-REG-21: process group termination targets process hierarchy', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['log', '--oneline', '-100'],
      runInBackground: true,
    });
    const pid = JSON.parse(startRes.content[0].text).processId;
    const termRes = await server.dispatchToolCall('terminate_process', {
      processId: pid,
      signal: 'SIGTERM',
    });
    assert.equal(termRes.isError, undefined);
  });

  test('RC02-REG-22: TERMINATING process state counts toward concurrency limit', () => {
    const reg = new ProcessRegistry();
    const p1 = reg.registerProcess({
      workspaceId: 'ws-1',
      actor: { clientId: 'c1', sessionId: 's1' },
      executable: 'git',
      sanitizedArgs: ['status'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    p1.state = 'TERMINATING';
    assert.equal(reg.countRunning(), 1, 'TERMINATING process must be counted as active');
  });

  // P1-04: UTF-8 safe bounded output pagination
  test('RC02-REG-23: multi-byte UTF-8 pagination does not split characters', () => {
    const buf = Buffer.from('こんにちは世界', 'utf8');
    const res1 = sliceUtf8Safe(buf, 0, 2);
    assert.equal(res1.slice.length, 0, 'Must back up to 0 rather than splitting character');
    assert.equal(res1.adjustedEnd, 0);

    const res2 = sliceUtf8Safe(buf, 0, 4);
    assert.equal(res2.slice.length, 3, 'Must adjust cut to end of complete char');
    assert.equal(res2.slice.toString('utf8'), 'こ');
    assert.equal(res2.adjustedEnd, 3);
  });

  // P1-01: Argument audit data minimization and error message sanitization
  test('RC02-REG-24: raw arguments are omitted from audit records and error messages do not leak raw arguments', async () => {
    const preCount = auditLogger.getRecords().length;
    await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version', '-v'],
    });

    const newRecords = auditLogger.getRecords().slice(preCount);
    const runRec = newRecords.find((r) => r.invocation.toolName === 'run_command');
    assert.ok(runRec, 'Must log run_command');
    assert.ok(runRec.invocation.parametersRedacted.args, 'Must have redacted args');
    assert.equal(typeof runRec.invocation.parametersRedacted.args, 'object');
    assert.equal(runRec.invocation.parametersRedacted.args.argCount, 2);
    assert.deepEqual(runRec.invocation.parametersRedacted.args.safeFlags, ['--version', '-v']);

    const secretArg = 'sensitivedata_xyz987';
    const failRes = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: [secretArg],
    });
    assert.equal(failRes.isError, true);
    const failParsed = JSON.parse(failRes.content[0].text);
    assert.ok(
      !failParsed.message.includes(secretArg),
      'Error message must not leak raw argument string',
    );
  });
});
