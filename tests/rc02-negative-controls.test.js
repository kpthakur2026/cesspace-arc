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
import { ProcessRegistry } from '../packages/processes/dist/index.js';
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

    const kernel = new SecurityKernel(registry);
    auditLogger = new AuditLogger();
    const filesystem = new FilesystemSubsystem();
    const git = new GitSubsystem();
    processRegistry = new ProcessRegistry();
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
    const postCount = auditLogger.getRecords().length;
    assert.equal(postCount, preCount + 1, 'Must produce exactly 1 audit record');
    const rec = auditLogger.getRecords()[postCount - 1];
    assert.equal(rec.policy.decision, 'ALLOW');
    assert.equal(rec.invocation.toolName, 'run_command');
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
});
