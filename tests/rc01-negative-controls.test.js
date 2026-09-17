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

describe('CesSpace ARC — RC-01 Mandatory Security Negative & Positive Controls', () => {
  let tempDir;
  let workspaceDir;
  let externalDir;
  let server;
  let auditLogger;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc01-suite-'));
    workspaceDir = path.join(tempDir, 'workspace');
    externalDir = path.join(tempDir, 'external');

    fs.mkdirSync(workspaceDir, { recursive: true });
    fs.mkdirSync(externalDir, { recursive: true });

    // Initialize fixture git repo inside workspace
    execFileSync('git', ['init', '-b', 'main'], { cwd: workspaceDir });
    execFileSync('git', ['config', 'user.name', 'P Thakur'], { cwd: workspaceDir });
    execFileSync(
      'git',
      ['config', 'user.email', '321108211+kpthakur2026@users.noreply.github.com'],
      { cwd: workspaceDir },
    );

    // Create fixture files
    fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# Fixture Workspace\nSample readme.\n');
    fs.mkdirSync(path.join(workspaceDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(workspaceDir, 'src', 'app.js'),
      'console.log("Hello CesSpace ARC");\nconst token = "public-demo-data";\n',
    );

    // Commit initial state
    execFileSync('git', ['add', '.'], { cwd: workspaceDir });
    execFileSync('git', ['commit', '-m', 'chore: initial test fixture commit'], {
      cwd: workspaceDir,
    });

    // Create uncommitted file for git_status and git_diff tests
    fs.writeFileSync(path.join(workspaceDir, 'dirty.txt'), 'uncommitted modification\n');

    // Create external target file
    const externalTarget = path.join(externalDir, 'external-secret.txt');
    fs.writeFileSync(externalTarget, 'TOP_SECRET_EXTERNAL_DATA\n');

    // Create symlink inside workspace escaping to external target
    try {
      fs.symlinkSync(externalTarget, path.join(workspaceDir, 'escaping-symlink.txt'));
    } catch {
      // Symlinks might require special perms on some environments
    }

    // Create sensitive dummy files inside workspace to test blacklist
    fs.writeFileSync(path.join(workspaceDir, '.env'), 'DATABASE_SECRET=do-not-read\n');
    fs.mkdirSync(path.join(workspaceDir, '.ssh'), { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, '.ssh', 'id_rsa'), 'DUMMY_PRIVATE_KEY_CONTENT\n');

    // Initialize server
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('test-ws', workspaceDir);

    const kernel = new SecurityKernel(registry);
    auditLogger = new AuditLogger();
    const filesystem = new FilesystemSubsystem();
    const git = new GitSubsystem();

    server = new ArcMcpServer(registry, kernel, auditLogger, filesystem, git, {
      defaultWorkspaceId: 'test-ws',
    });
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  // ==========================================================================
  // MANDATORY SECURITY NEGATIVE CONTROLS (16 scenarios)
  // ==========================================================================

  test('Negative 1: ../../../../etc/passwd -> PATH_ESCAPES_ROOT', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: '../../../../etc/passwd',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'PATH_ESCAPES_ROOT');
  });

  test('Negative 2: workspace symlink to external target -> PATH_ESCAPES_ROOT', async () => {
    const symlinkPath = path.join(workspaceDir, 'escaping-symlink.txt');
    if (fs.existsSync(symlinkPath)) {
      const res = await server.dispatchToolCall('read_file', {
        path: 'escaping-symlink.txt',
      });
      assert.equal(res.isError, true);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'PATH_ESCAPES_ROOT');
    }
  });

  test('Negative 3: .env access -> ACCESS_DENIED', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: '.env',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'ACCESS_DENIED' || parsed.code === 'POLICY_DENIED',
      `Expected ACCESS_DENIED or POLICY_DENIED, got ${parsed.code}`,
    );
  });

  test('Negative 4: .ssh/id_rsa access -> ACCESS_DENIED', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: '.ssh/id_rsa',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'ACCESS_DENIED' || parsed.code === 'POLICY_DENIED',
      `Expected ACCESS_DENIED or POLICY_DENIED, got ${parsed.code}`,
    );
  });

  test('Negative 5: unapproved absolute workspace -> rejected', async () => {
    const res = await server.dispatchToolCall('list_directory', {
      workspaceId: 'unapproved-workspace-id-999',
      path: externalDir,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'POLICY_DENIED' ||
        parsed.code === 'PATH_ESCAPES_ROOT' ||
        parsed.code === 'NO_WORKSPACE_CONFIGURED',
      `Expected rejection, got: ${parsed.code}`,
    );
  });

  test('Negative 6: 50 MB read request -> PAYLOAD_TOO_LARGE', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      length: 50 * 1024 * 1024, // 50 MB
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'PAYLOAD_TOO_LARGE');
  });

  test('Negative 7: run_command invocation -> POLICY_DENIED', async () => {
    const res = await server.dispatchToolCall('run_command', {
      command: 'echo',
      args: ['forbidden'],
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('Negative 8: unknown tool invocation -> POLICY_DENIED', async () => {
    const res = await server.dispatchToolCall('unknown_backdoor_tool', {
      action: 'hack',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('Negative 9: git revision option injection -> INVALID_REQUEST_SCHEMA or POLICY_DENIED', async () => {
    const res = await server.dispatchToolCall('git_log', {
      revision: '--output=/tmp/pwned',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(
      parsed.code === 'INVALID_REQUEST_SCHEMA' || parsed.code === 'POLICY_DENIED',
      `Expected INVALID_REQUEST_SCHEMA or POLICY_DENIED, got ${parsed.code}`,
    );
  });

  test('Negative 10: read_file cannot exceed configured bounds or accept negative offset/length', async () => {
    const resNegOffset = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      offset: -10,
    });
    assert.equal(resNegOffset.isError, true);
    const parsedOffset = JSON.parse(resNegOffset.content[0].text);
    assert.equal(parsedOffset.code, 'INVALID_REQUEST_SCHEMA');

    const resNegLength = await server.dispatchToolCall('read_file', {
      path: 'README.md',
      length: -5,
    });
    assert.equal(resNegLength.isError, true);
    const parsedLength = JSON.parse(resNegLength.content[0].text);
    assert.equal(parsedLength.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Negative 11: recursive listing cannot exceed depth limit (maxDepth > 5)', async () => {
    const res = await server.dispatchToolCall('list_directory', {
      maxDepth: 10,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Negative 12: searches cannot traverse blocked paths (.git, .env, .ssh)', async () => {
    const fileSearchRes = await server.dispatchToolCall('search_files', {
      pattern: '*.env*',
    });
    assert.equal(fileSearchRes.isError, undefined);
    const fileParsed = JSON.parse(fileSearchRes.content[0].text);
    assert.equal(fileParsed.matches.length, 0, 'Must not return blacklisted .env in search_files');

    const textSearchRes = await server.dispatchToolCall('search_text', {
      query: 'do-not-read',
    });
    assert.equal(textSearchRes.isError, undefined);
    const textParsed = JSON.parse(textSearchRes.content[0].text);
    assert.equal(textParsed.matches.length, 0, 'Must not return .env content in search_text');
  });

  test('Negative 13: denied operations still generate audit evidence', async () => {
    const preCount = auditLogger.getRecords().length;
    await server.dispatchToolCall('run_command', { command: 'ls' });
    const postCount = auditLogger.getRecords().length;
    assert.equal(postCount, preCount + 1, 'Denied operation must produce exactly 1 audit record');

    const lastRecord = auditLogger.getRecords()[postCount - 1];
    assert.equal(lastRecord.execution.status, 'DENIED');
    assert.equal(lastRecord.policy.decision, 'DENY');
    assert.equal(lastRecord.error?.code, 'POLICY_DENIED');
  });

  test('Negative 14: allowed operations generate matching audit evidence', async () => {
    const preCount = auditLogger.getRecords().length;
    await server.dispatchToolCall('health', {});
    const postCount = auditLogger.getRecords().length;
    assert.equal(postCount, preCount + 1, 'Allowed operation must produce exactly 1 audit record');

    const lastRecord = auditLogger.getRecords()[postCount - 1];
    assert.equal(lastRecord.execution.status, 'SUCCESS');
    assert.equal(lastRecord.policy.decision, 'ALLOW');
    assert.equal(lastRecord.invocation.toolName, 'health');
  });

  test('Negative 15: no RC-01 tool can mutate a fixture repository/workspace', async () => {
    const getHeadCommit = () =>
      execFileSync('git', ['rev-parse', 'HEAD'], { cwd: workspaceDir }).toString().trim();
    const getFileListing = () =>
      execFileSync('find', ['.', '-maxdepth', '3'], { cwd: workspaceDir }).toString().trim();

    const initialCommit = getHeadCommit();
    const initialFiles = getFileListing();

    // Call all 9 read-only tools
    await server.dispatchToolCall('health', {});
    await server.dispatchToolCall('list_directory', { path: '.' });
    await server.dispatchToolCall('read_file', { path: 'README.md' });
    await server.dispatchToolCall('search_files', { pattern: '*.js' });
    await server.dispatchToolCall('search_text', { query: 'Hello' });
    await server.dispatchToolCall('git_status', {});
    await server.dispatchToolCall('git_diff', {});
    await server.dispatchToolCall('git_log', { maxCount: 5 });
    await server.dispatchToolCall('system_status', {});

    const finalCommit = getHeadCommit();
    const finalFiles = getFileListing();

    assert.equal(
      finalCommit,
      initialCommit,
      'Commit hash must remain unchanged after read-only tools',
    );
    assert.equal(
      finalFiles,
      initialFiles,
      'Filesystem layout must remain unchanged after read-only tools',
    );
  });

  test('Negative 16: malformed tool schemas fail closed', async () => {
    // Missing required path parameter for read_file
    const resNoPath = await server.dispatchToolCall('read_file', {});
    assert.equal(resNoPath.isError, true);
    const parsedNoPath = JSON.parse(resNoPath.content[0].text);
    assert.equal(parsedNoPath.code, 'INVALID_REQUEST_SCHEMA');

    // Null byte in path
    const resNullByte = await server.dispatchToolCall('read_file', {
      path: 'README.md\0.secret',
    });
    assert.equal(resNullByte.isError, true);
    const parsedNullByte = JSON.parse(resNullByte.content[0].text);
    assert.equal(parsedNullByte.code, 'INVALID_PATH_CHARS');
  });

  // ==========================================================================
  // POSITIVE CONTROLS (All 9 Tools)
  // ==========================================================================

  test('Positive 1: health returns HEALTHY and RC-01 stage metadata', async () => {
    const res = await server.dispatchToolCall('health', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.status, 'HEALTHY');
    assert.equal(parsed.stage, 'RC-01');
    assert.equal(parsed.policyEngineActive, true);
    assert.equal(parsed.auditActive, true);
    assert.ok(parsed.authorizedWorkspacesCount >= 1);
  });

  test('Positive 2: list_directory returns entries in authorized workspace', async () => {
    const res = await server.dispatchToolCall('list_directory', {
      path: '.',
      recursive: true,
      maxDepth: 2,
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.entries.length > 0);
    const names = parsed.entries.map((e) => e.name);
    assert.ok(names.includes('README.md'));
    assert.ok(names.includes('src'));
  });

  test('Positive 3: read_file returns content and metadata', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: 'README.md',
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.content.includes('# Fixture Workspace'));
    assert.ok(parsed.bytesRead > 0);
    assert.equal(parsed.truncated, false);
  });

  test('Positive 4: search_files finds matching files', async () => {
    const res = await server.dispatchToolCall('search_files', {
      pattern: '*.md',
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.matches.includes('README.md'));
  });

  test('Positive 5: search_text finds text occurrences', async () => {
    const res = await server.dispatchToolCall('search_text', {
      query: 'Sample readme',
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.matches.length >= 1);
    assert.equal(parsed.matches[0].path, 'README.md');
    assert.equal(parsed.matches[0].lineNumber, 2);
  });

  test('Positive 6: git_status returns branch and dirty status', async () => {
    const res = await server.dispatchToolCall('git_status', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.branch, 'main');
    assert.ok(parsed.untrackedFiles.includes('dirty.txt'));
    assert.equal(parsed.isClean, false);
  });

  test('Positive 7: git_diff returns uncommitted differences', async () => {
    const res = await server.dispatchToolCall('git_diff', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(typeof parsed.diff, 'string');
    assert.equal(parsed.truncated, false);
  });

  test('Positive 8: git_log returns recent commits', async () => {
    const res = await server.dispatchToolCall('git_log', {
      maxCount: 5,
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(parsed.commits.length >= 1);
    assert.equal(
      parsed.commits[0].author,
      'P Thakur <321108211+kpthakur2026@users.noreply.github.com>',
    );
    assert.equal(parsed.commits[0].message, 'chore: initial test fixture commit');
  });

  test('Positive 9: system_status returns safe host metrics', async () => {
    const res = await server.dispatchToolCall('system_status', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.ok(['linux', 'darwin', 'win32'].includes(parsed.os));
    assert.ok(parsed.cpuCount > 0);
    assert.ok(parsed.memoryTotalBytes > 0);
    assert.ok(parsed.memoryFreeBytes > 0);
    assert.equal(parsed.hostname, undefined, 'Must NOT leak hostname');
    assert.equal(parsed.ip, undefined, 'Must NOT leak IP addresses');
  });

  test('Audit log hash chain integrity verification', async () => {
    const isValid = await auditLogger.verifyIntegrity();
    assert.equal(isValid, true, 'Audit log sequential hash chain must be valid and intact');
  });
});
