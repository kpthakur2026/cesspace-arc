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

  test('Negative 1: ../../../../etc/passwd is denied (RC-04 Layer 2 fail-closed target admission)', async () => {
    const res = await server.dispatchToolCall('read_file', {
      path: '../../../../etc/passwd',
    });
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    // RC-04 adds Layer-2 policy evaluation ahead of the subsystem. A path that
    // is not already a safe normalized workspace-relative target fails closed in
    // the policy matcher, so the traversal is denied earlier than the
    // filesystem layer would have denied it. The filesystem-level
    // PATH_ESCAPES_ROOT control remains directly covered in the RC-03
    // filesystem suites.
    assert.equal(parsed.code, 'POLICY_DENIED');
    assert.ok(!JSON.stringify(parsed).includes('etc/passwd'), 'target path must not be echoed');
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

  test('Negative 7: run_command with denied executable -> POLICY_DENIED', async () => {
    // rm is explicitly forbidden. Schema passes, policy must deny.
    const res = await server.dispatchToolCall('run_command', {
      executable: 'rm',
      args: ['-rf', '/'],
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
    // rm is explicitly forbidden — schema passes, policy denies with POLICY_DENIED
    await server.dispatchToolCall('run_command', { executable: 'rm', args: ['-rf', '/'] });
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

    // Null byte in path. Denied fail-closed by RC-04 Layer-2 target admission
    // before the subsystem is reached; the filesystem INVALID_PATH_CHARS control
    // remains directly covered in the RC-03 filesystem suites.
    const resNullByte = await server.dispatchToolCall('read_file', {
      path: 'README.md\0.secret',
    });
    assert.equal(resNullByte.isError, true);
    const parsedNullByte = JSON.parse(resNullByte.content[0].text);
    assert.equal(parsedNullByte.code, 'POLICY_DENIED');
  });

  // ==========================================================================
  // POSITIVE CONTROLS (All 9 Tools)
  // ==========================================================================

  test('Positive 1: health returns HEALTHY and RC-07 stage metadata', async () => {
    const res = await server.dispatchToolCall('health', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.status, 'HEALTHY');
    assert.equal(parsed.stage, 'RC-07');
    assert.equal(parsed.policyEngineActive, true);
    assert.equal(parsed.auditActive, true);
    assert.ok(parsed.authorizedWorkspacesCount >= 1);
  });

  test('Positive 2: list_directory returns entries in authorized workspace', async () => {
    // An explicit workspace-root selector must keep working under the built-in
    // compatibility policy: Layer 2 falls back to the tool-only base target for
    // a safely proven root selector.
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

  // ==========================================================================
  // FINAL PRE-PR HARDENING REGRESSION TESTS
  // ==========================================================================

  test('Hardening: Hostile core.worktree pointing outside workspace is rejected with ACCESS_DENIED', async () => {
    // Configure core.worktree in workspaceDir to point to externalDir
    execFileSync('git', ['config', 'core.worktree', externalDir], { cwd: workspaceDir });
    try {
      const res = await server.dispatchToolCall('git_status', {});
      assert.equal(res.isError, true);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'ACCESS_DENIED');
    } finally {
      // Revert core.worktree configuration
      execFileSync('git', ['config', '--unset', 'core.worktree'], { cwd: workspaceDir });
    }
  });

  test('Hardening: External .git gitdir redirection is rejected with ACCESS_DENIED', async () => {
    const maliciousWsDir = path.join(tempDir, 'malicious-gitdir-ws');
    fs.mkdirSync(maliciousWsDir, { recursive: true });
    fs.writeFileSync(
      path.join(maliciousWsDir, '.git'),
      `gitdir: ${path.join(workspaceDir, '.git')}\n`,
    );

    const reg = new WorkspaceRegistry();
    reg.registerWorkspace('malicious-ws', maliciousWsDir);
    const kernel = new SecurityKernel(reg);
    const malServer = new ArcMcpServer(
      reg,
      kernel,
      auditLogger,
      new FilesystemSubsystem(),
      new GitSubsystem(),
      { defaultWorkspaceId: 'malicious-ws' },
    );

    const res = await malServer.dispatchToolCall('git_status', {});
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.equal(parsed.code, 'ACCESS_DENIED');
  });

  test('Hardening: git_status, git_diff, and git_log do not create optional lock/index writes (GIT_OPTIONAL_LOCKS=0)', async () => {
    const indexPath = path.join(workspaceDir, '.git', 'index');

    // Make .git/index read-only
    fs.chmodSync(indexPath, 0o444);

    try {
      const resStatus = await server.dispatchToolCall('git_status', {});
      assert.equal(resStatus.isError, undefined, 'git_status must succeed with read-only index');

      const resDiff = await server.dispatchToolCall('git_diff', {});
      assert.equal(resDiff.isError, undefined, 'git_diff must succeed with read-only index');

      const resLog = await server.dispatchToolCall('git_log', { maxCount: 5 });
      assert.equal(resLog.isError, undefined, 'git_log must succeed with read-only index');

      // Verify no lock file remains
      assert.equal(fs.existsSync(path.join(workspaceDir, '.git', 'index.lock')), false);
    } finally {
      // Restore write permissions to index
      fs.chmodSync(indexPath, 0o644);
    }
  });

  test('Hardening: Whitespace-only workspaceId and workspaceRoot fail closed with INVALID_REQUEST_SCHEMA', async () => {
    const resWsId = await server.dispatchToolCall('list_directory', {
      workspaceId: '   ',
    });
    assert.equal(resWsId.isError, true);
    const parsedWsId = JSON.parse(resWsId.content[0].text);
    assert.equal(parsedWsId.code, 'INVALID_REQUEST_SCHEMA');

    const resWsRoot = await server.dispatchToolCall('git_status', {
      workspaceRoot: '   \t  ',
    });
    assert.equal(resWsRoot.isError, true);
    const parsedWsRoot = JSON.parse(resWsRoot.content[0].text);
    assert.equal(parsedWsRoot.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Hardening: Input bounds enforcement rejects oversized string selectors', async () => {
    // workspaceId > 128 chars
    const resId = await server.dispatchToolCall('read_file', {
      workspaceId: 'w'.repeat(129),
      path: 'README.md',
    });
    assert.equal(resId.isError, true);
    assert.equal(JSON.parse(resId.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // path > 1024 chars
    const resPath = await server.dispatchToolCall('read_file', {
      path: 'p'.repeat(1025),
    });
    assert.equal(resPath.isError, true);
    assert.equal(JSON.parse(resPath.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // query > 500 chars
    const resQuery = await server.dispatchToolCall('search_text', {
      query: 'q'.repeat(501),
    });
    assert.equal(resQuery.isError, true);
    assert.equal(JSON.parse(resQuery.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // pattern > 256 chars
    const resPattern = await server.dispatchToolCall('search_files', {
      pattern: 'x'.repeat(257),
    });
    assert.equal(resPattern.isError, true);
    assert.equal(JSON.parse(resPattern.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // revision > 128 chars
    const resRev = await server.dispatchToolCall('git_log', {
      revision: 'r'.repeat(129),
    });
    assert.equal(resRev.isError, true);
    assert.equal(JSON.parse(resRev.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Hardening: Oversized padded selectors fail closed (max length enforced on original input)', async () => {
    // 10,000 spaces + "x" for query
    const resQuery = await server.dispatchToolCall('search_text', {
      query: ' '.repeat(10000) + 'x',
    });
    assert.equal(resQuery.isError, true);
    assert.equal(JSON.parse(resQuery.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // 10,000 spaces + workspaceId
    const resWsId = await server.dispatchToolCall('read_file', {
      workspaceId: ' '.repeat(10000) + 'test-ws',
      path: 'README.md',
    });
    assert.equal(resWsId.isError, true);
    assert.equal(JSON.parse(resWsId.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // oversized padded path
    const resPath = await server.dispatchToolCall('read_file', {
      path: ' '.repeat(10000) + 'README.md',
    });
    assert.equal(resPath.isError, true);
    assert.equal(JSON.parse(resPath.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // oversized padded revision
    const resRev = await server.dispatchToolCall('git_log', {
      revision: ' '.repeat(10000) + 'HEAD',
    });
    assert.equal(resRev.isError, true);
    assert.equal(JSON.parse(resRev.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // oversized padded target
    const resTarget = await server.dispatchToolCall('git_diff', {
      target: ' '.repeat(10000) + 'HEAD',
    });
    assert.equal(resTarget.isError, true);
    assert.equal(JSON.parse(resTarget.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

    // oversized padded pattern
    const resPattern = await server.dispatchToolCall('search_files', {
      pattern: ' '.repeat(10000) + '*.js',
    });
    assert.equal(resPattern.isError, true);
    assert.equal(JSON.parse(resPattern.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Hardening: Valid bounded inputs are normalized by Zod and passed to execution', async () => {
    // path with leading/trailing spaces within bounds is trimmed and read successfully
    const res = await server.dispatchToolCall('read_file', {
      path: '  README.md  ',
    });
    assert.equal(res.isError, undefined);
    const content = JSON.parse(res.content[0].text);
    assert.ok(content.content.includes('# Fixture Workspace'));
    assert.ok(content.bytesRead > 0);

    // workspaceId with leading/trailing spaces within bounds is trimmed and bound successfully
    const resDir = await server.dispatchToolCall('list_directory', {
      workspaceId: '  test-ws  ',
    });
    assert.equal(resDir.isError, undefined);
  });

  test('Hardening: Host paths and usernames are absent from returned client errors', async () => {
    const errorScenarios = [
      await server.dispatchToolCall('read_file', { path: 'nonexistent-file.txt' }),
      await server.dispatchToolCall('read_file', { path: '../../../../etc/shadow' }),
      await server.dispatchToolCall('read_file', { path: 'src' }),
      await server.dispatchToolCall('git_status', { workspaceRoot: externalDir }),
    ];

    const currentUsername = process.env.USER || process.env.USERNAME || '';

    for (const res of errorScenarios) {
      assert.equal(res.isError, true);
      const text = res.content[0].text;

      // Must not leak host paths
      assert.ok(!text.includes('/home/'), `Error must not contain /home/ host path: ${text}`);
      assert.ok(!text.includes('/tmp/'), `Error must not contain /tmp/ host path: ${text}`);

      // Must not leak active username
      if (currentUsername.length > 2) {
        assert.ok(!text.includes(currentUsername), `Error must not leak username: ${text}`);
      }
    }
  });

  test('Hardening: Dedicated tracked .env fake secret is never disclosed in git_diff without path', async () => {
    // Commit a tracked .env fixture into workspace
    const trackedEnv = path.join(workspaceDir, '.env.production');
    fs.writeFileSync(trackedEnv, 'APP_SECRET_TOKEN=initial_seed_unmodified_secret_xyz789\n');
    execFileSync('git', ['add', '.env.production'], { cwd: workspaceDir });
    execFileSync('git', ['commit', '-m', 'chore: commit tracked production env'], {
      cwd: workspaceDir,
    });

    // Modify the tracked secret
    fs.writeFileSync(
      trackedEnv,
      'APP_SECRET_TOKEN=TOP_SECRET_MODIFIED_PAYLOAD_DO_NOT_DISCLOSE_9999\n',
    );

    // Invoke git_diff without path parameter
    const res = await server.dispatchToolCall('git_diff', {});
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content[0].text);

    assert.ok(
      !parsed.diff.includes('TOP_SECRET_MODIFIED_PAYLOAD_DO_NOT_DISCLOSE_9999'),
      'git_diff without path must NEVER disclose modified secret in .env file',
    );
    assert.ok(
      !parsed.diff.includes('initial_seed_unmodified_secret_xyz789'),
      'git_diff without path must NEVER disclose original secret in .env file',
    );
  });

  test('Hardening: Fake git binary in workspace and malicious inherited PATH cannot be executed by ARC', async () => {
    const maliciousBinDir = path.join(workspaceDir, 'bin');
    fs.mkdirSync(maliciousBinDir, { recursive: true });
    const fakeGitScript = path.join(maliciousBinDir, 'git');
    const markerFile = path.join(tempDir, 'fake-git-was-executed');

    // Create a fake executable git script that writes a marker file and exits with error
    fs.writeFileSync(fakeGitScript, `#!/bin/sh\necho "MALICIOUS_GIT" > "${markerFile}"\nexit 99\n`);
    fs.chmodSync(fakeGitScript, 0o755);

    // Pollute process.env.PATH with the workspace bin directory as highest priority
    const originalPath = process.env.PATH;
    process.env.PATH = `${maliciousBinDir}:${originalPath}`;

    try {
      // Execute git_status through ARC server
      const res = await server.dispatchToolCall('git_status', {});
      assert.equal(res.isError, undefined, 'git_status must succeed using trusted system binary');
      const parsed = JSON.parse(res.content[0].text);
      assert.ok(parsed.branch, 'git_status must return valid repository branch');

      // Assert the malicious fake git in workspace was NEVER executed
      assert.equal(
        fs.existsSync(markerFile),
        false,
        'Malicious fake git in workspace must NEVER be executed',
      );
    } finally {
      // Restore process.env.PATH
      process.env.PATH = originalPath;
      try {
        fs.unlinkSync(fakeGitScript);
        fs.rmdirSync(maliciousBinDir);
        if (fs.existsSync(markerFile)) fs.unlinkSync(markerFile);
      } catch {
        // ignore cleanup errors
      }
    }
  });
});
