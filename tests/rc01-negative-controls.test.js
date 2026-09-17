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
import { GitSubsystem, truncateUtf8ToByteLimit } from '../packages/git/dist/index.js';

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

  // ==========================================================================
  // INDEPENDENT SECURITY REVIEW REGRESSION CONTROLS
  // ==========================================================================

  test('P1-01: External workspaceRoot in git_status is rejected (cannot bypass workspace binding)', async () => {
    const res = await server.dispatchToolCall('git_status', {
      workspaceRoot: externalDir,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('P1-01: Invalid explicit workspaceId fails closed without falling back to default', async () => {
    const res = await server.dispatchToolCall('read_file', {
      workspaceId: 'non-existent-workspace-id',
      path: 'README.md',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('P1-01: Conflicting workspaceId and workspaceRoot selectors fail closed with DENY', async () => {
    // Register a secondary workspace in registry
    const secondaryWsDir = path.join(tempDir, 'secondary-ws');
    fs.mkdirSync(secondaryWsDir, { recursive: true });
    server.workspaceRegistry.registerWorkspace('second-ws', secondaryWsDir);

    const res = await server.dispatchToolCall('git_status', {
      workspaceId: 'test-ws',
      workspaceRoot: secondaryWsDir,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('P1-02: Schema validation fails closed on extra unknown properties for all 9 tools', async () => {
    const toolNames = [
      'health',
      'system_status',
      'list_directory',
      'read_file',
      'search_files',
      'search_text',
      'git_status',
      'git_diff',
      'git_log',
    ];

    for (const name of toolNames) {
      const baseParams = {};
      if (name === 'read_file') baseParams.path = 'README.md';
      if (name === 'search_files') baseParams.pattern = '*.md';
      if (name === 'search_text') baseParams.query = 'test';

      const res = await server.dispatchToolCall(name, {
        ...baseParams,
        __unexpected_extra_field__: 'malicious_payload',
      });
      assert.equal(res.isError, true, `Tool '${name}' must reject unknown extra property`);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
    }
  });

  test('P1-02: Schema validation fails closed on wrong parameter types and emits audit record', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: 12345, // invalid type, string expected
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');

    const records = auditLogger.getRecords();
    const lastRecord = records[records.length - 1];
    assert.equal(lastRecord.policy.decision, 'DENY');
    assert.equal(lastRecord.error?.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('P1-03: Git execution hardening: diff.external helper in .git/config is never executed', async () => {
    const markerFile = path.join(tempDir, 'evil-marker-should-never-exist');
    if (fs.existsSync(markerFile)) {
      fs.unlinkSync(markerFile);
    }

    // Configure evil external diff script in workspace's .git/config
    execFileSync('git', ['config', 'diff.external', `touch ${markerFile}`], {
      cwd: workspaceDir,
    });

    const res = await server.dispatchToolCall('git_diff', {});
    assert.equal(res.isError, undefined);

    assert.equal(
      fs.existsSync(markerFile),
      false,
      'External diff command must NEVER be executed by git_diff',
    );

    // Clean up config
    execFileSync('git', ['config', '--unset', 'diff.external'], { cwd: workspaceDir });
  });

  test('P1-04: Git secret exclusion: tracked .env or private key diffs are purged and not disclosed', async () => {
    // Create a tracked dummy secret file and commit it
    const trackedSecret = path.join(workspaceDir, 'dummy.key');
    fs.writeFileSync(trackedSecret, 'PRIVATE_KEY_SUPER_SECRET_VALUE\n');
    execFileSync('git', ['add', 'dummy.key'], { cwd: workspaceDir });
    execFileSync('git', ['commit', '-m', 'chore: commit tracked key'], { cwd: workspaceDir });

    // Modify the tracked secret
    fs.writeFileSync(trackedSecret, 'PRIVATE_KEY_SUPER_SECRET_MODIFIED\n');

    const res = await server.dispatchToolCall('git_diff', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);

    assert.ok(
      !parsed.diff.includes('PRIVATE_KEY_SUPER_SECRET_MODIFIED'),
      'git_diff must NEVER disclose private key content',
    );
  });

  test('P1-04: Git secret exclusion: sensitive files (.env, .ssh) are filtered from git_status', async () => {
    const res = await server.dispatchToolCall('git_status', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);

    const allStatusFiles = [
      ...parsed.stagedFiles,
      ...parsed.unstagedFiles,
      ...parsed.untrackedFiles,
    ];

    for (const f of allStatusFiles) {
      assert.ok(!f.includes('.env'), `git_status must not list .env (${f})`);
      assert.ok(!f.includes('.ssh'), `git_status must not list .ssh (${f})`);
      assert.ok(!f.endsWith('.key'), `git_status must not list .key (${f})`);
    }
  });

  test('P1-05: Server with no configured workspaces fails closed for workspace operations', async () => {
    const emptyServer = new ArcMcpServer(
      new WorkspaceRegistry(),
      new SecurityKernel(new WorkspaceRegistry()),
      new AuditLogger(),
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { authorizedRoots: [] },
    );

    const res = await emptyServer.dispatchToolCall('list_directory', {});
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'POLICY_DENIED');
  });

  test('P2: WorkspaceRegistry rejects non-existent workspace root registration', () => {
    const reg = new WorkspaceRegistry();
    assert.throws(
      () => {
        reg.registerWorkspace('nonexistent', '/path/that/definitely/does/not/exist/arc-test');
      },
      /does not exist/,
      'Must reject non-existent workspace root',
    );
  });

  test('P2: Multi-byte UTF-8 diff truncation respects byte bounds without breaking', async () => {
    const multiByteString = '✨'.repeat(200000); // 3 bytes per emoji (0xE2 0x9C 0xA8)
    const buf = Buffer.from(multiByteString, 'utf8');
    assert.ok(buf.length > 512 * 1024);

    const { text, truncated } = truncateUtf8ToByteLimit(multiByteString, 512 * 1024);
    assert.equal(truncated, true);
    assert.ok(Buffer.byteLength(text, 'utf8') <= 512 * 1024);
    assert.ok(
      !text.includes('\uFFFD'),
      'Must not produce replacement characters due to cut codepoints',
    );
  });

  test('P2: search_text filePattern filters files correctly', async () => {
    const res = await server.dispatchToolCall('search_text', {
      query: 'Hello CesSpace ARC',
      filePattern: '*.md',
    });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.matches.length, 0, 'Must not match app.js when filePattern is *.md');

    const resMatch = await server.dispatchToolCall('search_text', {
      query: 'Hello CesSpace ARC',
      filePattern: '*.js',
    });
    assert.equal(resMatch.isError, undefined);
    const parsedMatch = JSON.parse(resMatch.content[0].text);
    assert.ok(parsedMatch.matches.length >= 1, 'Must match app.js when filePattern is *.js');
  });

  test('P2: search_text rejects ReDoS nested quantifiers with INVALID_REQUEST_SCHEMA', async () => {
    const res = await server.dispatchToolCall('search_text', {
      query: '(a+)+$',
      isRegex: true,
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Audit log hash chain integrity verification', async () => {
    const isValid = await auditLogger.verifyIntegrity();
    assert.equal(isValid, true, 'Audit log sequential hash chain must be valid and intact');
  });
});
