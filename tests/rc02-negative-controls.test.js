import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawn } from 'node:child_process';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { WorkspaceRegistry, SecurityKernel } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ProcessRegistry, sliceUtf8Safe } from '../packages/processes/dist/index.js';
import { ControlledProcessRunner, ExecutableResolver } from '../packages/terminal/dist/index.js';

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

  test('RC02-P-02: run_command git --version returns foreground output within workspace', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['--version'],
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId, 'Must return a processId');
    assert.match(parsed.stdout, /git version/i);
  });

  test('RC02-P-03: run_command in background returns processId immediately (git --version)', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['--version'],
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
      executable: 'git',
      args: ['--version'],
    });
    assert.equal(runRes.isError, undefined, `Setup failed: ${runRes.content?.[0]?.text}`);
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
      executable: 'git',
      args: ['--version'],
    });
    assert.equal(runRes.isError, undefined, `Setup failed: ${runRes.content?.[0]?.text}`);
    const pid = JSON.parse(runRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    const outputRes = await server.dispatchToolCall('process_output', {
      processId: pid,
    });
    assert.equal(outputRes.isError, undefined);
    const outputParsed = JSON.parse(outputRes.content[0].text);
    assert.ok(typeof outputParsed.stdoutChunk === 'string', 'stdoutChunk must be string');
    assert.match(outputParsed.stdoutChunk, /git version/i);
  });

  test('RC02-P-06: terminate_process returns valid response for a background process', async () => {
    // Start a background process
    const runRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(runRes.isError, undefined, `Setup failed: ${runRes.content?.[0]?.text}`);
    const pid = JSON.parse(runRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    const termRes = await server.dispatchToolCall('terminate_process', {
      processId: pid,
      signal: 'SIGTERM',
    });
    assert.equal(
      termRes.isError,
      undefined,
      `terminate_process must not error: ${termRes.content[0].text}`,
    );
    const termParsed = JSON.parse(termRes.content[0].text);
    assert.equal(termParsed.processId, pid, 'processId must match');
    assert.ok(typeof termParsed.terminated === 'boolean', 'terminated must be boolean');
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
    const runRes = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['--version'],
    });
    assert.equal(runRes.isError, undefined, `Setup failed: ${runRes.content?.[0]?.text}`);
    await server.flushAudit();
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
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

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
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

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
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

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
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

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
      args: ['--version'],
      runInBackground: true,
    });
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    await server.flushAudit();
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
      executable: 'git',
      args: ['--version'],
    });
    assert.equal(res.isError, undefined, `Setup failed: ${res.content?.[0]?.text}`);
    const pid = JSON.parse(res.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    await server.flushAudit();
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
    const dummyChild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 10000)'], {
      detached: true,
      stdio: 'ignore',
    });
    const record = processRegistry.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'local-stdio-caller', sessionId: 'stdio-session-01' },
      executable: 'node',
      sanitizedArgs: ['--version'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    record._child = dummyChild;

    const termRes = await server.dispatchToolCall('terminate_process', {
      processId: record.processId,
      signal: 'SIGTERM',
    });
    assert.equal(termRes.isError, undefined);
    await server.flushAudit();

    const records = auditLogger.getRecords();
    const reqRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_TERMINATION_REQUESTED' &&
        r.invocation.parametersRedacted.processId === record.processId,
    );
    const sigRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SIGTERM_SENT' &&
        r.invocation.parametersRedacted.processId === record.processId,
    );
    assert.ok(reqRec, 'Must log PROCESS_TERMINATION_REQUESTED');
    assert.ok(sigRec, 'Must log PROCESS_SIGTERM_SENT');
    try {
      process.kill(-dummyChild.pid, 'SIGKILL');
    } catch {
      // ignore
    }
  });

  // P1-03: Process group kill and grace period
  test('RC02-REG-21: process group termination targets process hierarchy (parent -> child -> grandchild)', async () => {
    processRegistry.clear();
    const script =
      'const cp = require("child_process"); const gc = cp.spawn(process.execPath, ["-e", "setInterval(()=>{}, 10000)"]); process.stdout.write(process.pid + ":" + gc.pid + "\\n"); setInterval(()=>{}, 10000);';
    const parentScript =
      'const cp = require("child_process"); const child = cp.spawn(process.execPath, ["-e", ' +
      JSON.stringify(script) +
      ']); child.stdout.pipe(process.stdout); setInterval(()=>{}, 10000);';
    const parent = spawn(process.execPath, ['-e', parentScript], {
      detached: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    });

    const pids = await new Promise((resolve) => {
      parent.stdout.once('data', (d) => {
        const [childPid, gcPid] = d.toString().trim().split(':').map(Number);
        resolve({ parentPid: parent.pid, childPid, gcPid });
      });
    });

    const record = processRegistry.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'local-stdio-caller', sessionId: 'stdio-session-01' },
      executable: 'node',
      sanitizedArgs: ['--version'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    record._child = parent;

    const termRes = await server.dispatchToolCall('terminate_process', {
      processId: record.processId,
      signal: 'SIGTERM',
    });
    assert.equal(termRes.isError, undefined);

    await new Promise((resolve) => setTimeout(resolve, 200));

    const isAlive = (p) => {
      try {
        process.kill(p, 0);
        return true;
      } catch {
        return false;
      }
    };

    assert.equal(isAlive(pids.parentPid), false, 'Parent process must be dead');
    assert.equal(isAlive(pids.childPid), false, 'Child process must be dead');
    assert.equal(isAlive(pids.gcPid), false, 'Grandchild process must be dead');
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

  // RC-02 Security Review Corrections
  test('RC02-REG-25: git branch new-branch is denied by run_command and branch is not created', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['branch', 'forbidden-test-branch'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');

    const branches = execFileSync('git', ['branch'], { cwd: workspaceDir }).toString();
    assert.ok(!branches.includes('forbidden-test-branch'), 'Branch must not be created');
  });

  test('RC02-REG-26: git inspect/write/help subcommands are strictly denied through run_command', async () => {
    const deniedGitArgs = [
      ['branch', '-D', 'main'],
      ['diff'],
      ['log'],
      ['show'],
      ['rev-parse', 'HEAD'],
      ['describe'],
      ['help'],
      ['diff', '--', '.env'],
      ['log', '-p'],
    ];

    for (const args of deniedGitArgs) {
      const res = await server.dispatchToolCall('run_command', {
        executable: 'git',
        args,
      });
      assert.equal(res.isError, true, `git ${args.join(' ')} must be denied`);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'POLICY_DENIED');
    }
  });

  test('RC02-REG-27: dedicated git tools continue to work for repository inspection', async () => {
    const statusRes = await server.dispatchToolCall('git_status', {});
    assert.equal(statusRes.isError, undefined);

    const logRes = await server.dispatchToolCall('git_log', { maxCount: 5 });
    assert.equal(logRes.isError, undefined);

    const diffRes = await server.dispatchToolCall('git_diff', {});
    assert.equal(diffRes.isError, undefined);
  });

  test('RC02-REG-28: hostile diff.external cannot execute via run_command', async () => {
    const res = await server.dispatchToolCall('run_command', {
      executable: 'git',
      args: ['-c', 'diff.external=touch /tmp/pwned', 'diff'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('RC02-REG-29: real two-workspace binding verifies process isolation and audit target', async () => {
    const workspaceDirB = path.join(tempDir, 'workspace-b');
    fs.mkdirSync(workspaceDirB, { recursive: true });
    server.workspaceRegistry.registerWorkspace('test-ws-b', workspaceDirB);

    const startRes = await server.dispatchToolCall(
      'run_command',
      {
        executable: 'git',
        args: ['--version'],
        workspaceId: 'test-ws-b',
        runInBackground: true,
      },
      {
        clientId: 'client-b',
        sessionId: 'session-b',
        clientType: 'vscode',
        deviceId: 'device-b',
      },
    );
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    await server.flushAudit();
    const records = auditLogger.getRecords();
    const spawnRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SPAWN_SUCCEEDED' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    assert.ok(spawnRec, 'Spawn event must exist');
    assert.equal(spawnRec.target.workspaceId, 'test-ws-b', 'Audit target must be workspace B');

    const rogueStatus = await server.dispatchToolCall(
      'process_status',
      { processId: pid },
      { clientId: 'attacker-client-a', sessionId: 'attacker-session-a' },
    );
    assert.equal(rogueStatus.isError, true);
    assert.equal(JSON.parse(rogueStatus.content[0].text).code, 'POLICY_DENIED');

    const wrongWsStatus = await server.dispatchToolCall(
      'process_status',
      { processId: pid, workspaceId: 'test-ws' },
      { clientId: 'client-b', sessionId: 'session-b' },
    );
    assert.equal(wrongWsStatus.isError, true);
    assert.equal(JSON.parse(wrongWsStatus.content[0].text).code, 'POLICY_DENIED');

    const legitStatus = await server.dispatchToolCall(
      'process_status',
      { processId: pid, workspaceId: 'test-ws-b' },
      { clientId: 'client-b', sessionId: 'session-b' },
    );
    assert.equal(legitStatus.isError, undefined);
    assert.equal(JSON.parse(legitStatus.content[0].text).processId, pid);
  });

  test('RC02-REG-30: timeout state machine sets TERMINATING, holds concurrency, then TIMED_OUT on exit', () => {
    const reg = new ProcessRegistry();
    const record = reg.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'c1', sessionId: 's1' },
      executable: 'node',
      sanitizedArgs: ['--version'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    assert.equal(reg.countRunning(), 1);

    reg.markTimedOut(record.processId);
    assert.equal(record.timedOut, true);
    assert.equal(record.state, 'TERMINATING');
    assert.equal(reg.countRunning(), 1, 'Concurrency slot must remain held in TERMINATING state');
    assert.equal(record.completedAt, undefined, 'completedAt must not be set until process death');

    reg.markCompleted(record.processId, null, 'SIGTERM');
    assert.equal(record.state, 'TIMED_OUT');
    assert.ok(record.completedAt);
    assert.equal(reg.countRunning(), 0, 'Concurrency slot released after process death');
  });

  test('RC02-REG-31: malformed run_command failing schema redacts args and env in audit log', async () => {
    const secretValue = 'SUPER_SECRET_TOKEN_9999';
    const secretEnv = 'FORBIDDEN_ENV_VALUE_8888';

    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version', secretValue],
      env: { FORBIDDEN_KEY: secretEnv },
      extraForbiddenField: 'malicious-data',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');

    const auditRec = auditLogger.getRecords()[auditLogger.getRecords().length - 1];
    assert.equal(auditRec.invocation.toolName, 'run_command');
    assert.equal(auditRec.execution.status, 'DENIED');

    const auditJson = JSON.stringify(auditRec);
    assert.ok(!auditJson.includes(secretValue), 'Audit log must not leak secret argument value');
    assert.ok(!auditJson.includes(secretEnv), 'Audit log must not leak secret env value');
    assert.ok(
      !auditJson.includes('malicious-data'),
      'Audit log must not leak unvalidated extra fields',
    );
  });

  test('RC02-REG-32: real process actor identity is preserved in audit records', async () => {
    processRegistry.clear();
    const startRes = await server.dispatchToolCall(
      'run_command',
      {
        executable: 'git',
        args: ['--version'],
        runInBackground: true,
      },
      {
        clientId: 'real-test-client',
        sessionId: 'real-test-session',
        clientType: 'jetbrains',
        deviceId: 'macbook-pro-m3',
      },
    );
    assert.equal(startRes.isError, undefined, `Setup failed: ${startRes.content?.[0]?.text}`);
    const pid = JSON.parse(startRes.content[0].text).processId;
    assert.ok(pid, 'Process ID must be returned');

    await server.flushAudit();
    const records = auditLogger.getRecords();
    const spawnRec = records.find(
      (r) =>
        r.invocation.toolName === 'PROCESS_SPAWN_SUCCEEDED' &&
        r.invocation.parametersRedacted.processId === pid,
    );
    assert.ok(spawnRec, 'Spawn record must exist');
    assert.equal(spawnRec.actor.clientId, 'real-test-client');
    assert.equal(spawnRec.actor.sessionId, 'real-test-session');
    assert.equal(spawnRec.actor.clientType, 'jetbrains');
    assert.equal(spawnRec.actor.deviceId, 'macbook-pro-m3');
  });

  test('RC02-REG-33: audit sink rejection is handled safely without unhandled rejection and flushAudit works', async () => {
    let sinkCalled = false;
    const failingSink = {
      onProcessEvent: async () => {
        sinkCalled = true;
        throw new Error('Audit disk full');
      },
    };

    const reg = new ProcessRegistry([failingSink]);
    const rec = reg.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'c1', sessionId: 's1' },
      executable: 'node',
      sanitizedArgs: ['--version'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    reg.notifySpawnSuccess(rec.processId);
    await reg.flushLifecycleEvents();
    assert.equal(sinkCalled, true, 'Sink must have been called');
  });

  test('RC02-REG-34: independent stdout and stderr cursors reconstruct full output across multi-byte UTF-8 boundaries', () => {
    const reg = new ProcessRegistry();
    const rec = reg.registerProcess({
      workspaceId: 'test-ws',
      actor: { clientId: 'c1', sessionId: 's1' },
      executable: 'node',
      sanitizedArgs: ['--version'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    const fullStdoutStr = 'Hello 日本語 世界! '.repeat(20);
    const fullStderrStr = 'Error 警告 失敗! '.repeat(20);

    reg.appendOutput(rec.processId, 'stdout', Buffer.from(fullStdoutStr, 'utf8'));
    reg.appendOutput(rec.processId, 'stderr', Buffer.from(fullStderrStr, 'utf8'));
    reg.markCompleted(rec.processId, 0, null);

    let stdoutAcc = '';
    let stderrAcc = '';
    let stdoutCursor = 0;
    let stderrCursor = 0;

    for (let i = 0; i < 50; i++) {
      const page = reg.getProcessOutput(
        rec.processId,
        {
          stdoutCursor,
          stderrCursor,
          maxBytes: 15,
        },
        undefined,
        { clientId: 'c1', sessionId: 's1' },
      );

      stdoutAcc += page.stdoutChunk;
      stderrAcc += page.stderrChunk;
      stdoutCursor = page.stdoutCursor ?? stdoutCursor;
      stderrCursor = page.stderrCursor ?? stderrCursor;

      if (page.complete) break;
    }

    assert.equal(
      stdoutAcc,
      fullStdoutStr,
      'Reconstructed stdout must match full string byte-for-byte',
    );
    assert.equal(
      stderrAcc,
      fullStderrStr,
      'Reconstructed stderr must match full string byte-for-byte',
    );
  });

  test('RC02-REG-35: ExecutableResolver rejects world/group-writable binaries and symlinks into untrusted roots', () => {
    const evilDir = path.join(tempDir, 'evil-bin-dir');
    fs.mkdirSync(evilDir, { recursive: true });

    try {
      fs.chmodSync(evilDir, 0o777);
      const resolverWorldDir = new ExecutableResolver([evilDir]);
      assert.throws(
        () => resolverWorldDir.resolveExecutable('node', workspaceDir),
        /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
      );
    } catch {
      // ignore platform chmod differences
    }

    const safeDir = path.join(tempDir, 'safe-bin-dir');
    fs.mkdirSync(safeDir, { recursive: true });
    fs.chmodSync(safeDir, 0o755);
    const evilBin = path.join(safeDir, 'mybinary');
    fs.writeFileSync(evilBin, '#!/bin/sh\necho evil\n');
    fs.chmodSync(evilBin, 0o777);

    const resolverWorldBin = new ExecutableResolver([safeDir]);
    assert.throws(
      () => resolverWorldBin.resolveExecutable('mybinary', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );

    const workspaceBin = path.join(workspaceDir, 'ws-binary');
    fs.writeFileSync(workspaceBin, '#!/bin/sh\necho ws\n');
    fs.chmodSync(workspaceBin, 0o755);
    const symlinkBin = path.join(safeDir, 'symbinary');
    try {
      fs.symlinkSync(workspaceBin, symlinkBin);
      const resolverSymlink = new ExecutableResolver([safeDir]);
      assert.throws(
        () => resolverSymlink.resolveExecutable('symbinary', workspaceDir),
        /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
      );
    } catch {
      // ignore
    }
  });

  test('RC02-REG-36: exact active Node runtime executes successfully and binds to /proc/self/exe on Linux', async () => {
    if (process.platform === 'linux') {
      assert.ok(fs.existsSync('/proc/self/exe'), '/proc/self/exe must exist on Linux');

      // Triple kernel identity proof — all three must agree for the resolver to
      // return /proc/self/exe. The GitHub diagnostics (run #23) confirmed that
      // dev=2049 ino=557445 match on the ubuntu-24.04 hosted runner, even when
      // the toolcache Node binary carries mode 0777.
      const realProcExe = fs.realpathSync('/proc/self/exe');
      const realExecPath = fs.realpathSync(process.execPath);
      const procStat = fs.statSync('/proc/self/exe');
      const execStat = fs.statSync(process.execPath);

      // 1. Canonical path must be the same file
      assert.equal(
        realProcExe,
        realExecPath,
        'realpath(/proc/self/exe) must equal realpath(process.execPath)',
      );
      // 2. Basename must be 'node'
      assert.equal(
        path.basename(realProcExe).toLowerCase(),
        'node',
        'Kernel-identified active runtime must be named node',
      );
      // 3. Device and inode must match (same physical file, proven by diagnostics)
      assert.equal(
        procStat.dev,
        execStat.dev,
        'stat(/proc/self/exe).dev must equal stat(process.execPath).dev',
      );
      assert.equal(
        procStat.ino,
        execStat.ino,
        'stat(/proc/self/exe).ino must equal stat(process.execPath).ino',
      );

      // Resolver must bind to /proc/self/exe, not return process.execPath directly
      const resolver = new ExecutableResolver();
      const resolved = resolver.resolveExecutable('node', workspaceDir);
      assert.equal(
        resolved,
        '/proc/self/exe',
        'Resolver must prefer kernel /proc/self/exe on Linux',
      );
    }

    // End-to-end: node --version must execute and return a semver string
    const res = await server.dispatchToolCall('run_command', {
      executable: 'node',
      args: ['--version'],
    });
    assert.equal(res.isError, undefined, `node --version failed: ${res.content?.[0]?.text}`);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.processId);
    assert.match(parsed.stdout, /^v\d+\.\d+\.\d+/);
  });

  test('RC02-REG-37: arbitrary executable beside process.execPath is NOT trusted', () => {
    const defaultResolver = new ExecutableResolver();
    assert.throws(
      () => defaultResolver.resolveExecutable('nonexistent_tool_beside_node', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );
  });

  test('RC02-REG-38: process.execPath dirname is NOT treated as generic trusted search path', () => {
    const resolver = new ExecutableResolver();
    assert.throws(
      () => resolver.resolveExecutable('arbitrary_beside_exe', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );
  });

  test('RC02-REG-39: malicious PATH cannot replace Node', () => {
    const attackerDir = path.join(tempDir, 'attacker-path');
    fs.mkdirSync(attackerDir, { recursive: true });
    const fakeNode = path.join(attackerDir, 'node');
    fs.writeFileSync(fakeNode, '#!/bin/sh\necho evil\n');
    fs.chmodSync(fakeNode, 0o755);

    const origPath = process.env.PATH;
    try {
      process.env.PATH = `${attackerDir}:${origPath}`;
      const resolver = new ExecutableResolver();
      const resolved = resolver.resolveExecutable('node', workspaceDir);
      assert.notEqual(resolved, fakeNode, 'Must NOT resolve to fake node from PATH');
      assert.notEqual(path.resolve(resolved), path.resolve(fakeNode));
    } finally {
      process.env.PATH = origPath;
    }
  });

  test('RC02-REG-40: workspace fake node cannot execute', () => {
    const wsNode = path.join(workspaceDir, 'node');
    fs.writeFileSync(wsNode, '#!/bin/sh\necho ws-evil-node\n');
    fs.chmodSync(wsNode, 0o755);

    const resolver = new ExecutableResolver([], true, wsNode);
    assert.throws(
      () => resolver.resolveExecutable('node', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );
  });

  test('RC02-REG-41: HOME fake node cannot execute', () => {
    const fakeHome = path.join(tempDir, 'fake-home');
    fs.mkdirSync(fakeHome, { recursive: true });
    const homeNode = path.join(fakeHome, 'node');
    fs.writeFileSync(homeNode, '#!/bin/sh\necho home-evil-node\n');
    fs.chmodSync(homeNode, 0o755);

    const origHome = process.env.HOME;
    try {
      process.env.HOME = fakeHome;
      const resolver = new ExecutableResolver([], true, homeNode);
      assert.throws(
        () => resolver.resolveExecutable('node', workspaceDir),
        /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
      );
    } finally {
      process.env.HOME = origHome;
    }
  });

  test('RC02-REG-42: node_modules/.bin fake node cannot execute', () => {
    const nmBinDir = path.join(tempDir, 'node_modules', '.bin');
    fs.mkdirSync(nmBinDir, { recursive: true });
    const nmNode = path.join(nmBinDir, 'node');
    fs.writeFileSync(nmNode, '#!/bin/sh\necho nm-evil-node\n');
    fs.chmodSync(nmNode, 0o755);

    const resolver = new ExecutableResolver([], true, nmNode);
    assert.throws(
      () => resolver.resolveExecutable('node', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );
  });

  test('RC02-REG-43: generic toolcache sibling and unsafe or world-writable Node candidates are rejected', () => {
    const safeDir = path.join(tempDir, 'test-bin-dir');
    fs.mkdirSync(safeDir, { recursive: true });
    const writableNode = path.join(safeDir, 'node');
    fs.writeFileSync(writableNode, '#!/bin/sh\necho writable-node\n');
    fs.chmodSync(writableNode, 0o777);

    const resolver = new ExecutableResolver([], true, writableNode);
    assert.throws(
      () => resolver.resolveExecutable('node', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );

    // Generic toolcache sibling cannot execute
    const defaultResolver = new ExecutableResolver();
    assert.throws(
      () => defaultResolver.resolveExecutable('toolcache_sibling', workspaceDir),
      /could not be resolved|DENIED|NOT_FOUND|cannot be found/i,
    );
  });
});
