/**
 * CesSpace ARC — RC-07 Task 3 Acceptance Test Suite
 * Review Diff Tool (arc_review_diff)
 *
 * Negative Controls: RC07-NEG-019 through RC07-NEG-027
 * Positive Flows: RC07-FLOW-06 through RC07-FLOW-08
 * Additional Required Tests: Tool discovery, schema validation, wire bounds, timeout, etc.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

import { ArcMcpServer, ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import {
  setTask3TimeoutForTest,
  getTask3TimeoutForTest,
} from '../apps/mcp-server/dist/internal/server-seam.js';
import {
  WorkspaceRegistry,
  SecurityKernel,
  ApprovalStateManager,
  DeclarativePolicyEngine,
} from '../packages/policy/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';

// ---------------------------------------------------------------------------
// Test Fixtures & Setup
// ---------------------------------------------------------------------------

let tempDir;
let mainRepoDir;
let nonGitDir;
let secretsRepoDir;
let hugeRepoDir;
let hugeRepoDir2;
let renameRepoDir;
let renameRepoDir2;
let server;
let workspaceRegistry;
let securityKernel;
let auditLogger;
let filesystemSubsystem;
let gitSubsystem;

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
}

const secretPassKey = ['GENERIC_', 'PASSWORD'].join('');
const secretPassVal = ['s3', 'cr', '3t'].join('');

const safeActor = {
  clientId: 'client-task3-test',
  clientType: 'worker',
  sessionId: 'session-task3-01',
  deviceId: 'device-task3-local',
  authenticated: true,
};

function runGit(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Alice Engineer',
      GIT_AUTHOR_EMAIL: 'alice@example.com',
      GIT_COMMITTER_NAME: 'Alice Engineer',
      GIT_COMMITTER_EMAIL: 'alice@example.com',
    },
  }).trim();
}

before(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc07-task3-'));

  // 1. Main Git fixture
  mainRepoDir = path.join(tempDir, 'main_repo');
  fs.mkdirSync(mainRepoDir, { recursive: true });
  runGit(['init', '-b', 'main'], mainRepoDir);
  fs.writeFileSync(path.join(mainRepoDir, 'file1.txt'), 'line 1\nline 2\nline 3\n');
  fs.writeFileSync(path.join(mainRepoDir, 'file2.txt'), 'alpha\nbeta\ngamma\n');
  fs.writeFileSync(path.join(mainRepoDir, 'to_delete.txt'), 'will be deleted\n');
  runGit(['add', '.'], mainRepoDir);
  runGit(['commit', '-m', 'initial commit'], mainRepoDir);

  // 2. Non-Git directory
  nonGitDir = path.join(tempDir, 'non_git');
  fs.mkdirSync(nonGitDir, { recursive: true });
  fs.writeFileSync(path.join(nonGitDir, 'plain.txt'), 'not a repo');

  // 3. Secrets Git fixture
  secretsRepoDir = path.join(tempDir, 'secrets_repo');
  fs.mkdirSync(secretsRepoDir, { recursive: true });
  runGit(['init', '-b', 'main'], secretsRepoDir);
  fs.writeFileSync(path.join(secretsRepoDir, 'app.ts'), 'console.log("hello");\n');
  runGit(['add', '.'], secretsRepoDir);
  runGit(['commit', '-m', 'initial commit'], secretsRepoDir);

  // 4. Huge repo for wire-size tests (> 512 KiB but < 4 MiB)
  hugeRepoDir = path.join(tempDir, 'huge_repo');
  fs.mkdirSync(hugeRepoDir, { recursive: true });
  runGit(['init', '-b', 'main'], hugeRepoDir);
  fs.writeFileSync(path.join(hugeRepoDir, 'big.txt'), 'line 0\n');
  runGit(['add', '.'], hugeRepoDir);
  runGit(['commit', '-m', 'initial commit'], hugeRepoDir);

  // 5. Very large repo for overflow-marker tests (> 4 MiB raw diff)
  hugeRepoDir2 = path.join(tempDir, 'huge_repo2');
  fs.mkdirSync(hugeRepoDir2, { recursive: true });
  runGit(['init', '-b', 'main'], hugeRepoDir2);
  fs.writeFileSync(path.join(hugeRepoDir2, 'seed.txt'), 'initial\n');
  runGit(['add', '.'], hugeRepoDir2);
  runGit(['commit', '-m', 'initial commit'], hugeRepoDir2);

  // 6. Rename regression repo
  renameRepoDir = path.join(tempDir, 'rename_repo');
  fs.mkdirSync(renameRepoDir, { recursive: true });
  runGit(['init', '-b', 'main'], renameRepoDir);
  // Commit initial files: .env with secret content, and notes.txt with safe content
  fs.writeFileSync(
    path.join(renameRepoDir, '.env'),
    `${secretPassKey}=${secretPassVal}\nDB_URL=postgres://localhost/db\n`,
  );
  fs.writeFileSync(path.join(renameRepoDir, 'notes.txt'), 'safe note content\n');
  fs.writeFileSync(path.join(renameRepoDir, 'README.md'), '# Test\n');
  runGit(['add', '.'], renameRepoDir);
  runGit(['commit', '-m', 'initial commit'], renameRepoDir);

  // 7. Rename regression repo 2 (for testing reverse direction notes.txt -> .env without existing .env)
  renameRepoDir2 = path.join(tempDir, 'rename_repo2');
  fs.mkdirSync(renameRepoDir2, { recursive: true });
  runGit(['init', '-b', 'main'], renameRepoDir2);
  fs.writeFileSync(path.join(renameRepoDir2, 'notes.txt'), 'safe note content to become env\n');
  fs.writeFileSync(path.join(renameRepoDir2, 'README.md'), '# Test 2\n');
  runGit(['add', '.'], renameRepoDir2);
  runGit(['commit', '-m', 'initial commit'], renameRepoDir2);

  // Subsystems & Server setup
  workspaceRegistry = new WorkspaceRegistry();
  workspaceRegistry.registerWorkspace('ws-main', mainRepoDir);
  workspaceRegistry.registerWorkspace('ws-non-git', nonGitDir);
  workspaceRegistry.registerWorkspace('ws-secrets', secretsRepoDir);
  workspaceRegistry.registerWorkspace('ws-huge', hugeRepoDir);
  workspaceRegistry.registerWorkspace('ws-huge2', hugeRepoDir2);
  workspaceRegistry.registerWorkspace('ws-rename', renameRepoDir);
  workspaceRegistry.registerWorkspace('ws-rename2', renameRepoDir2);

  const procReg = new ProcessRegistry();
  const terminal = new ControlledProcessRunner(procReg);
  auditLogger = new AuditLogger(path.join(tempDir, 'audit.log'));
  securityKernel = new SecurityKernel(workspaceRegistry, procReg);
  filesystemSubsystem = new FilesystemSubsystem();
  gitSubsystem = new GitSubsystem();

  server = new ArcMcpServer(
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystemSubsystem,
    gitSubsystem,
    { transport: 'stdio' },
    terminal,
    procReg,
    new ApprovalStateManager(),
  );
});

after(() => {
  try {
    fs.rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

// ---------------------------------------------------------------------------
// Negative Controls: RC07-NEG-019 through RC07-NEG-027
// ---------------------------------------------------------------------------

describe('RC-07 Task 3 Negative Controls (RC07-NEG-019..027)', () => {
  test('RC07-NEG-019: Target revision contains shell metacharacters rejected before Git execution', async () => {
    const maliciousRevisions = [
      'HEAD; rm -rf /',
      'main | cat /etc/passwd',
      'feature & echo hello',
      'rev`id`',
      'rev$(whoami)',
      'rev>out',
      'rev<in',
      'rev\nnewline',
    ];

    for (const rev of maliciousRevisions) {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
        workspaceId: 'ws-main',
        mode: 'target',
        targetRevision: rev,
      });

      assert.strictEqual(res.isError, true);
      const parsed = parseResponse(res);
      assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
    }
  });

  test('RC07-NEG-020: Target revision starting with hyphen rejected with exact INVALID_GIT_ARGUMENT', async () => {
    const flagInjections = ['--exec=id', '-p', '--no-index', '--help', '-v', '--output=/tmp/pwn'];

    for (const flag of flagInjections) {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
        workspaceId: 'ws-main',
        mode: 'target',
        targetRevision: flag,
      });

      assert.strictEqual(res.isError, true, `Expected error for targetRevision ${flag}`);
      const parsed = parseResponse(res);
      assert.strictEqual(
        parsed.code,
        'INVALID_GIT_ARGUMENT',
        `Expected INVALID_GIT_ARGUMENT for flag ${flag}`,
      );
    }
  });

  test('RC07-NEG-021: Directory traversal in path throws PATH_OUTSIDE_WORKSPACE', async () => {
    const traversalPaths = ['../../etc/passwd', '../outside', 'foo/../../bar', '/etc/passwd', '..'];

    for (const p of traversalPaths) {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
        workspaceId: 'ws-main',
        path: p,
      });

      assert.strictEqual(res.isError, true);
      const parsed = parseResponse(res);
      assert.strictEqual(
        parsed.code,
        'PATH_OUTSIDE_WORKSPACE',
        `Expected PATH_OUTSIDE_WORKSPACE for path ${p}`,
      );
    }
  });

  test('RC07-NEG-022: Diff contains simulated API key / secret token (masked, count truthful)', async () => {
    const tokenFile = path.join(secretsRepoDir, 'tokens.txt');
    const secretApiKey = 'ghp_' + 'A'.repeat(36);
    const secretAws = ['AKIA', '1234', '5678', '9012', '3456'].join('');
    const secretOpenAi = ['sk-', '1234567890', 'abcdef', '1234567890'].join('');
    const secretBearer = 'Bearer ' + 'secret-bearer-token-12345';

    fs.writeFileSync(
      tokenFile,
      `export const KEY = "${secretApiKey}";\nexport const AWS = "${secretAws}";\nexport const OPENAI = "${secretOpenAi}";\nexport const AUTH = "${secretBearer}";\n`,
    );

    runGit(['add', 'tokens.txt'], secretsRepoDir);
    runGit(['commit', '-m', 'add tokens'], secretsRepoDir);
    fs.appendFileSync(tokenFile, `// Extra comment\nexport const EXTRA = "${secretApiKey}";\n`);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-secrets',
      path: 'tokens.txt',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const rawText = res.content[0].text;
    const parsed = parseResponse(res);

    // Assert raw secret tokens are completely absent from full response text
    assert.strictEqual(
      rawText.includes(secretApiKey),
      false,
      'Original GitHub token must not appear',
    );
    assert.strictEqual(rawText.includes(secretAws), false, 'Original AWS key must not appear');
    assert.strictEqual(
      rawText.includes(secretOpenAi),
      false,
      'Original OpenAI key must not appear',
    );
    assert.strictEqual(
      rawText.includes(secretBearer),
      false,
      'Original Bearer token must not appear',
    );

    // Assert redaction marker is present
    assert.ok(parsed.diff.includes('[REDACTED_SECRET]'), 'Redaction marker must appear in diff');
    assert.ok(parsed.sensitiveBlocksMasked > 0, 'sensitiveBlocksMasked must be > 0');

    // Cleanup modification
    runGit(['checkout', 'HEAD', '--', 'tokens.txt'], secretsRepoDir);
  });

  test('RC07-NEG-023: Diff contains simulated SSH/TLS private-key block (masked, count truthful)', async () => {
    const keyFile = path.join(secretsRepoDir, 'keys.ts');
    const fakeOpenSshKey = [
      '-----' + 'BEGIN OPENSSH PRIVATE ' + 'KEY-----',
      'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn',
      'NhAAAAAwEAAQAAAYEA0eLd4V39jKlS...fakeKeyMaterialHere...1234567890',
      '-----' + 'END OPENSSH PRIVATE ' + 'KEY-----',
    ].join('\n');

    const fakeRsaKey = [
      '-----' + 'BEGIN RSA PRIVATE ' + 'KEY-----',
      'MIIEowIBAAKCAQEA0Y9kKjL...fakeRsaMaterialHere...9876543210',
      '-----' + 'END RSA PRIVATE ' + 'KEY-----',
    ].join('\n');

    fs.writeFileSync(keyFile, '// Key configuration file\n');
    runGit(['add', 'keys.ts'], secretsRepoDir);
    runGit(['commit', '-m', 'initial keys setup'], secretsRepoDir);

    // Reviewable change adds the simulated private key blocks
    fs.appendFileSync(keyFile, `\n${fakeOpenSshKey}\n\n${fakeRsaKey}\n`);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-secrets',
      path: 'keys.ts',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const rawText = res.content[0].text;
    const parsed = parseResponse(res);

    // Private key material must not occur anywhere in the response
    assert.strictEqual(rawText.includes('fakeKeyMaterialHere'), false);
    assert.strictEqual(rawText.includes('fakeRsaMaterialHere'), false);

    // Redaction marker must be present
    assert.ok(parsed.diff.includes('[REDACTED_SECRET]'));
    assert.ok(parsed.sensitiveBlocksMasked > 0);

    // Cleanup
    runGit(['checkout', 'HEAD', '--', 'keys.ts'], secretsRepoDir);
  });

  test('RC07-NEG-024: Diff exceeds 512 KiB including well above 1 MiB old intermediate buffer (wire response <= 524,288 bytes, truncated === true)', async () => {
    const bigFile = path.join(hugeRepoDir, 'big.txt');
    // Produce a diff of ~2 MiB: 'content line with lots of padding text here\n' is ~47 bytes;
    // 50000 repetitions = ~2.35 MiB, well above the old MAX_DIFF_BYTES*2 (1 MiB) ceiling.
    const largeContent = 'content line with lots of padding text here\n'.repeat(50000);
    fs.writeFileSync(bigFile, largeContent);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-huge',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed even for diffs well above 1 MiB');
    const rawText = res.content[0].text;
    const wireBytes = Buffer.byteLength(rawText, 'utf8');

    assert.ok(
      wireBytes <= 524288,
      `Actual wire response (${wireBytes} bytes) must be <= 524288 bytes`,
    );

    const parsed = JSON.parse(rawText);
    assert.strictEqual(parsed.truncated, true);
    assert.strictEqual(typeof parsed.diff, 'string');
    assert.strictEqual(parsed.bytes, Buffer.byteLength(parsed.diff, 'utf8'));

    // UTF-8 validity assertion: no replacement character
    assert.strictEqual(parsed.diff.includes('\uFFFD'), false);

    // Cleanup
    runGit(['checkout', 'HEAD', '--', 'big.txt'], hugeRepoDir);
  });

  test('RC07-NEG-025: Invalid mode rejected with strict schema INVALID_REQUEST_SCHEMA', async () => {
    const invalidModes = ['invalid', 'cached', 'all', '', 123, null];

    for (const m of invalidModes) {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
        workspaceId: 'ws-main',
        mode: m,
      });

      assert.strictEqual(res.isError, true);
      const parsed = parseResponse(res);
      assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
    }
  });

  test('RC07-NEG-026: Explicit sensitive credential path rejected with ACCESS_DENIED', async () => {
    const sensitivePaths = [
      '.env',
      '.env.production',
      '.env.local',
      'id_rsa',
      'id_ed25519',
      'server.pem',
      'private.key',
      '.ssh/id_rsa',
      '.aws/credentials',
    ];

    for (const sp of sensitivePaths) {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
        workspaceId: 'ws-main',
        path: sp,
      });

      assert.strictEqual(res.isError, true);
      const parsed = parseResponse(res);
      assert.strictEqual(
        parsed.code,
        'ACCESS_DENIED',
        `Expected ACCESS_DENIED for sensitive path ${sp}`,
      );
    }
  });

  test('RC07-NEG-027: Non-Git workspace returns GIT_REPOSITORY_NOT_FOUND', async () => {
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-non-git',
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'GIT_REPOSITORY_NOT_FOUND');
  });
});

// ---------------------------------------------------------------------------
// Task 3 Regression Tests: Defect A (sensitive rename) & Defect B (large buffer)
// ---------------------------------------------------------------------------

describe('RC-07 Task 3 Regressions: Sensitive Rename and Large Diff', () => {
  test('REG-A1: rename .env -> notes.txt does not leak sensitive origin content or filename in diff or fileSummaries', async () => {
    // Commit: .env contains generic secret content (not matching token regex), notes.txt exists
    // Stage: rename .env -> renamed_notes.txt using git mv
    runGit(['mv', '.env', 'renamed_notes.txt'], renameRepoDir);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename',
      mode: 'staged',
    });

    assert.ok(!res.isError, 'Tool must succeed for rename involving sensitive origin');
    const rawText = res.content[0].text;
    const parsed = JSON.parse(rawText);

    // .env must NOT appear in fileSummaries
    const hasDotEnv = parsed.fileSummaries.some(
      (s) => s.path.includes('.env') || (s.oldPath && s.oldPath.includes('.env')),
    );
    assert.strictEqual(
      hasDotEnv,
      false,
      '.env must not appear in fileSummaries (rename origin leak)',
    );

    // Neither generic secret key nor value in raw wire text
    assert.strictEqual(
      rawText.includes(secretPassKey),
      false,
      'Secret key must not appear in wire response',
    );
    assert.strictEqual(
      rawText.includes(secretPassVal),
      false,
      'Secret value must not appear in wire response',
    );
    assert.strictEqual(
      rawText.includes('.env'),
      false,
      '.env path must not appear in wire response (origin leak via rename)',
    );

    // The non-sensitive destination file renamed_notes.txt should also be suppressed
    // because it is part of a rename from a sensitive source
    const hasRenamedNotes = parsed.fileSummaries.some((s) => s.path === 'renamed_notes.txt');
    assert.strictEqual(
      hasRenamedNotes,
      false,
      'Rename destination must be suppressed when origin is sensitive',
    );

    // Restore: unstage and revert the rename
    runGit(['reset', 'HEAD', '.'], renameRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir);
    try {
      fs.unlinkSync(path.join(renameRepoDir, 'renamed_notes.txt'));
    } catch {
      /* ignore */
    }
  });

  test('REG-A2: rename notes.txt -> .env (reverse direction) does not leak sensitive destination or source in diff or fileSummaries', async () => {
    // Stage: rename notes.txt -> .env in a repo where .env is not in HEAD
    runGit(['mv', 'notes.txt', '.env'], renameRepoDir2);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename2',
      mode: 'staged',
    });

    assert.ok(!res.isError, 'Tool must succeed for rename involving sensitive destination .env');
    const rawText = res.content[0].text;
    const parsed = JSON.parse(rawText);

    // .env must NOT appear in fileSummaries
    const hasDotEnv = parsed.fileSummaries.some(
      (s) => s.path.includes('.env') || (s.oldPath && s.oldPath.includes('.env')),
    );
    assert.strictEqual(hasDotEnv, false, '.env must not appear in fileSummaries');

    // notes.txt (rename source) must also be suppressed since destination is sensitive
    const hasNotes = parsed.fileSummaries.some((s) => s.path === 'notes.txt');
    assert.strictEqual(
      hasNotes,
      false,
      'Rename source (notes.txt) must be suppressed when destination is sensitive',
    );

    // .env path must not appear in wire text
    assert.strictEqual(
      rawText.includes('.env'),
      false,
      '.env path must not appear in wire response (destination leak)',
    );

    // Restore
    runGit(['reset', 'HEAD', '.'], renameRepoDir2);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir2);
    try {
      fs.unlinkSync(path.join(renameRepoDir2, '.env'));
    } catch {
      /* ignore */
    }
  });

  test('REG-A3: rename notes.txt -> .env.production does not leak sensitive destination content or filename in diff or fileSummaries', async () => {
    // Stage: rename notes.txt -> .env.production (a sensitive destination pattern)
    runGit(['mv', 'notes.txt', '.env.production'], renameRepoDir);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename',
      mode: 'staged',
    });

    assert.ok(!res.isError, 'Tool must succeed for rename involving sensitive destination pattern');
    const rawText = res.content[0].text;
    const parsed = JSON.parse(rawText);

    // .env.production must NOT appear in fileSummaries
    const hasDotEnvProd = parsed.fileSummaries.some(
      (s) => s.path.includes('.env') || (s.oldPath && s.oldPath.includes('.env')),
    );
    assert.strictEqual(hasDotEnvProd, false, '.env.production must not appear in fileSummaries');

    // notes.txt (rename source) should also be suppressed since it's a rename into a sensitive file
    const hasNotes = parsed.fileSummaries.some((s) => s.path === 'notes.txt');
    assert.strictEqual(
      hasNotes,
      false,
      'Rename source (notes.txt) must be suppressed when destination is sensitive',
    );

    // .env path must not appear in wire text
    assert.strictEqual(
      rawText.includes('.env'),
      false,
      '.env path must not appear in wire response (destination leak)',
    );

    // Restore
    runGit(['reset', 'HEAD', '.'], renameRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir);
    try {
      fs.unlinkSync(path.join(renameRepoDir, '.env.production'));
    } catch {
      /* ignore */
    }
  });

  test('REG-A4: path-filtered review diff targeting rename destination suppresses sensitive origin and does not leak content', async () => {
    // Stage: rename .env -> renamed_notes.txt
    runGit(['mv', '.env', 'renamed_notes.txt'], renameRepoDir);

    // Call arc_review_diff specifically targeting the non-sensitive destination path
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename',
      mode: 'staged',
      path: 'renamed_notes.txt',
    });

    assert.ok(!res.isError, 'Tool must succeed for path-filtered rename query');
    const rawText = res.content[0].text;
    const parsed = JSON.parse(rawText);

    // Prove: call does not expose .env
    assert.strictEqual(
      rawText.includes('.env'),
      false,
      '.env path must not appear in wire response',
    );
    // Prove: call does not expose GENERIC_PASSWORD
    assert.strictEqual(
      rawText.includes(secretPassKey),
      false,
      'Secret key must not appear in wire response',
    );
    // Prove: call does not expose s3cr3t
    assert.strictEqual(
      rawText.includes(secretPassVal),
      false,
      'Secret value must not appear in wire response',
    );
    // Prove: renamed_notes.txt is not leaked through fileSummaries
    assert.strictEqual(
      parsed.fileSummaries.length,
      0,
      'fileSummaries must be empty for suppressed rename destination',
    );
    // Prove: no sensitive-origin content appears anywhere in content[0].text
    assert.strictEqual(
      parsed.diff,
      '',
      'diff must be empty string when targeted file is suppressed sensitive origin',
    );
    assert.strictEqual(parsed.totalFilesChanged, 0, 'totalFilesChanged must be 0');

    // Restore: unstage and revert the rename
    runGit(['reset', 'HEAD', '.'], renameRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir);
    try {
      fs.unlinkSync(path.join(renameRepoDir, 'renamed_notes.txt'));
    } catch {
      /* ignore */
    }
  });

  test('REG-A5: symmetric path-filtered review diff targeting rename source (notes.txt -> .env) suppresses both sides', async () => {
    // Stage: rename notes.txt -> .env in a repo where .env is not in HEAD
    runGit(['mv', 'notes.txt', '.env'], renameRepoDir2);

    // Call arc_review_diff specifically targeting the source path
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename2',
      mode: 'staged',
      path: 'notes.txt',
    });

    assert.ok(!res.isError, 'Tool must succeed for symmetric path-filtered rename query');
    const rawText = res.content[0].text;
    const parsed = JSON.parse(rawText);

    // Prove: call does not expose .env
    assert.strictEqual(
      rawText.includes('.env'),
      false,
      '.env path must not appear in wire response',
    );
    // Prove: notes.txt is not leaked through fileSummaries
    assert.strictEqual(
      parsed.fileSummaries.length,
      0,
      'fileSummaries must be empty for suppressed rename source',
    );
    // Prove: diff is empty
    assert.strictEqual(
      parsed.diff,
      '',
      'diff must be empty string when source of sensitive rename is targeted',
    );
    assert.strictEqual(parsed.totalFilesChanged, 0, 'totalFilesChanged must be 0');

    // Restore
    runGit(['reset', 'HEAD', '.'], renameRepoDir2);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir2);
    try {
      fs.unlinkSync(path.join(renameRepoDir2, '.env'));
    } catch {
      /* ignore */
    }
  });

  test('REG-A6: failure in sensitive-identity discovery fails closed and does not fall through to diff with protection disabled', async () => {
    class FailingDiscoveryGitSubsystem extends GitSubsystem {
      async runGit(workspaceRoot, args, maxBuffer, options) {
        // Intercept the whole-repo name-status discovery call:
        // fullNameStatusArgs includes '--name-status', '-z', '-M', '--', '.'
        if (args.includes('--name-status') && args.includes('.')) {
          throw ArcError.internalError('Simulated failure during sensitive identity discovery');
        }
        return super.runGit(workspaceRoot, args, maxBuffer, options);
      }
    }

    const pr = new ProcessRegistry();
    const tr = new ControlledProcessRunner(pr);
    const testServer = new ArcMcpServer(
      workspaceRegistry,
      securityKernel,
      auditLogger,
      filesystemSubsystem,
      new FailingDiscoveryGitSubsystem(),
      { transport: 'stdio' },
      tr,
      pr,
      new ApprovalStateManager(),
    );

    // Stage rename .env -> renamed_notes.txt
    runGit(['mv', '.env', 'renamed_notes.txt'], renameRepoDir);

    const res = await testServer.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-rename',
      mode: 'staged',
      path: 'renamed_notes.txt',
    });

    // Must fail closed (isError: true), NOT succeed and return an unprotected diff
    assert.strictEqual(res.isError, true, 'Tool call must fail closed when discovery fails');
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'INTERNAL_ERROR');

    // Wire response must NEVER expose the sensitive password or content
    const rawText = res.content[0].text;
    assert.strictEqual(rawText.includes(secretPassKey), false);
    assert.strictEqual(rawText.includes(secretPassVal), false);

    // Restore
    runGit(['reset', 'HEAD', '.'], renameRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], renameRepoDir);
    try {
      fs.unlinkSync(path.join(renameRepoDir, 'renamed_notes.txt'));
    } catch {
      /* ignore */
    }
  });

  test('REG-B2: diff raw output exceeding 4 MiB capture ceiling returns structured response with truncated=true and safe overflow marker', async () => {
    // Produce a file whose diff will exceed the 4 MiB RAW_DIFF_CAPTURE_BYTES ceiling.
    // Modify tracked file seed.txt with ~5 MiB of new lines:
    const seedFile = path.join(hugeRepoDir2, 'seed.txt');
    const lineContent = 'X'.repeat(100) + '\n';
    const hugeContent = lineContent.repeat(50000);
    fs.writeFileSync(seedFile, hugeContent);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-huge2',
    });

    assert.ok(!res.isError, 'Tool must succeed even when raw diff exceeds 4 MiB capture ceiling');
    const rawText = res.content[0].text;
    const wireBytes = Buffer.byteLength(rawText, 'utf8');

    assert.ok(
      wireBytes <= 524288,
      `Wire response (${wireBytes} bytes) must be <= 524288 bytes even for overflow case`,
    );

    const parsed = JSON.parse(rawText);
    assert.strictEqual(parsed.truncated, true, 'truncated must be true for overflow case');
    assert.strictEqual(typeof parsed.diff, 'string', 'diff field must be a string');

    // bytes field must accurately reflect the returned diff size
    assert.strictEqual(
      parsed.bytes,
      Buffer.byteLength(parsed.diff, 'utf8'),
      'bytes field must equal actual UTF-8 byte size of returned diff',
    );

    // No replacement character (valid UTF-8)
    assert.strictEqual(parsed.diff.includes('\uFFFD'), false, 'Diff must be valid UTF-8');

    // No secret leakage in response (overflow marker is safe text only)
    assert.ok(
      !rawText.includes(secretPassKey) && !rawText.includes(secretPassVal),
      'No secret content may appear in overflow response',
    );

    // Cleanup
    try {
      runGit(['checkout', 'HEAD', '--', 'seed.txt'], hugeRepoDir2);
    } catch {
      /* ignore */
    }
  });
});
// ---------------------------------------------------------------------------
// Positive Flows: RC07-FLOW-06 through RC07-FLOW-08
// ---------------------------------------------------------------------------

describe('RC-07 Task 3 Positive Flows (RC07-FLOW-06..08)', () => {
  test('RC07-FLOW-06: Bounded Review Diff Generation (Unstaged mode)', async () => {
    const file1 = path.join(mainRepoDir, 'file1.txt');
    const file2 = path.join(mainRepoDir, 'file2.txt');
    const deleteFile = path.join(mainRepoDir, 'to_delete.txt');

    // Modify file1.txt: add 2 lines, delete 1 line
    fs.writeFileSync(file1, 'line 1\nline 2 modified\nline 3\nline 4 added\n');
    // Modify file2.txt: add 1 line
    fs.appendFileSync(file2, 'delta added\n');
    // Delete to_delete.txt
    if (fs.existsSync(deleteFile)) {
      fs.unlinkSync(deleteFile);
    }

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      // mode omitted: defaults to 'unstaged'
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const parsed = parseResponse(res);

    assert.strictEqual(parsed.mode, 'unstaged');
    assert.strictEqual(parsed.targetRevision, undefined);
    assert.strictEqual(parsed.truncated, false);
    assert.strictEqual(parsed.bytes, Buffer.byteLength(parsed.diff, 'utf8'));
    assert.strictEqual(parsed.totalFilesChanged, 3);
    assert.strictEqual(parsed.fileSummaries.length, 3);

    // Verify file summaries
    const s1 = parsed.fileSummaries.find((s) => s.path === 'file1.txt');
    assert.ok(s1);
    assert.strictEqual(s1.status, 'modified');
    assert.strictEqual(s1.insertions, 2);
    assert.strictEqual(s1.deletions, 1);

    const s2 = parsed.fileSummaries.find((s) => s.path === 'file2.txt');
    assert.ok(s2);
    assert.strictEqual(s2.status, 'modified');
    assert.strictEqual(s2.insertions, 1);
    assert.strictEqual(s2.deletions, 0);

    const sd = parsed.fileSummaries.find((s) => s.path === 'to_delete.txt');
    assert.ok(sd);
    assert.strictEqual(sd.status, 'deleted');
    assert.strictEqual(sd.insertions, 0);
    assert.strictEqual(sd.deletions, 1);

    // Verify diff content contains the changes
    assert.ok(parsed.diff.includes('+line 4 added'));
    assert.ok(parsed.diff.includes('-line 2'));
    assert.ok(parsed.diff.includes('+delta added'));
    assert.ok(parsed.diff.includes('-will be deleted'));

    // Zero repository mutation: git status still shows the exact unstaged changes
    const statusOut = runGit(['status', '--porcelain'], mainRepoDir);
    assert.ok(statusOut.includes('M file1.txt'));
    assert.ok(statusOut.includes('M file2.txt'));
    assert.ok(statusOut.includes('D to_delete.txt'));

    // Restore working tree
    runGit(['checkout', 'HEAD', '--', '.'], mainRepoDir);
  });

  test('RC07-FLOW-07: Staged Review Diff with Target Revision (HEAD)', async () => {
    const file1 = path.join(mainRepoDir, 'file1.txt');
    const file2 = path.join(mainRepoDir, 'file2.txt');

    // Stage changes in file1.txt
    fs.writeFileSync(file1, 'line 1 staged\nline 2 staged\nline 3\n');
    runGit(['add', 'file1.txt'], mainRepoDir);

    // Make unstaged changes in file2.txt (must NOT be included in staged review diff)
    fs.writeFileSync(file2, 'unstaged file2 modification\n');

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      mode: 'staged',
      targetRevision: 'HEAD',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const parsed = parseResponse(res);

    assert.strictEqual(parsed.mode, 'staged');
    assert.strictEqual(parsed.targetRevision, 'HEAD');
    assert.strictEqual(parsed.truncated, false);
    assert.strictEqual(parsed.totalFilesChanged, 1);
    assert.strictEqual(parsed.fileSummaries.length, 1);

    const summary = parsed.fileSummaries[0];
    assert.strictEqual(summary.path, 'file1.txt');
    assert.strictEqual(summary.status, 'modified');
    assert.strictEqual(summary.insertions, 2);
    assert.strictEqual(summary.deletions, 2);

    // Unstaged change in file2.txt is NOT in the diff
    assert.strictEqual(parsed.diff.includes('unstaged file2 modification'), false);
    assert.ok(parsed.diff.includes('+line 1 staged'));

    // Cleanup
    runGit(['reset', 'HEAD', '.'], mainRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], mainRepoDir);
  });

  test('RC07-FLOW-08: Automated Secret Redaction with Safe Context Preservation', async () => {
    const testFile = path.join(secretsRepoDir, 'flow08.ts');
    const secret = 'ghp_' + 'B'.repeat(36);
    fs.writeFileSync(
      testFile,
      `// Configuration file\nexport const SAFE_CONFIG = "safe-setting";\nexport const API_TOKEN = "${secret}";\nexport const RETRY_COUNT = 3;\n`,
    );

    // Stage and review
    runGit(['add', 'flow08.ts'], secretsRepoDir);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-secrets',
      mode: 'staged',
      path: 'flow08.ts',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const rawText = res.content[0].text;
    const parsed = parseResponse(res);

    // Raw credential completely absent
    assert.strictEqual(rawText.includes(secret), false);

    // Redaction marker present and count truthful
    assert.ok(parsed.diff.includes('[REDACTED_SECRET]'));
    assert.strictEqual(parsed.sensitiveBlocksMasked, 1);

    // Safe surrounding context preserved
    assert.ok(parsed.diff.includes('SAFE_CONFIG'));
    assert.ok(parsed.diff.includes('RETRY_COUNT'));

    // Cleanup
    runGit(['reset', 'HEAD', '.'], secretsRepoDir);
    runGit(['checkout', 'HEAD', '--', '.'], secretsRepoDir);
    try {
      fs.unlinkSync(testFile);
    } catch {
      // ignore
    }
  });
});

// ---------------------------------------------------------------------------
// Additional Required Regressions
// ---------------------------------------------------------------------------

describe('RC-07 Task 3 Additional Regressions', () => {
  test('Production tool discovery advertises exactly 21 tools', () => {
    assert.strictEqual(ALL_TOOL_DEFINITIONS.length, 21);
    const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);

    assert.ok(names.includes('arc_review_diff'));
    assert.ok(names.includes('arc_repo_status'));
    assert.ok(names.includes('arc_worktree_status'));

    // Verify unadvertised tools remain absent
    assert.strictEqual(names.includes('arc_verify'), false);
    assert.strictEqual(names.includes('arc_test'), false);
    assert.strictEqual(names.includes('arc_ci_status'), false);
    assert.strictEqual(names.includes('arc_stage_evidence'), false);
  });

  test('Strict schema rejects unknown properties on arc_review_diff', async () => {
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      unknownProperty: 'disallowed',
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Target mode without targetRevision fails closed', async () => {
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      mode: 'target',
      // targetRevision omitted
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Unstaged mode with targetRevision fails closed', async () => {
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      mode: 'unstaged',
      targetRevision: 'HEAD',
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Caller cannot set maxBytes above 512 KiB', async () => {
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      maxBytes: 524289,
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'INVALID_REQUEST_SCHEMA');
  });

  test('Caller may request smaller maxBytes and receives truncated output', async () => {
    const file1 = path.join(mainRepoDir, 'file1.txt');
    fs.writeFileSync(file1, 'modified line 1\nmodified line 2\nmodified line 3\n');

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      maxBytes: 40,
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.truncated, true);
    assert.ok(parsed.bytes <= 40, `Diff bytes (${parsed.bytes}) must be <= 40`);

    runGit(['checkout', 'HEAD', '--', '.'], mainRepoDir);
  });

  test('Path targeting deleted tracked file succeeds and returns deletion diff', async () => {
    const deleteFile = path.join(mainRepoDir, 'to_delete.txt');
    if (!fs.existsSync(deleteFile)) {
      fs.writeFileSync(deleteFile, 'will be deleted\n');
      runGit(['add', 'to_delete.txt'], mainRepoDir);
      runGit(['commit', '-m', 'restore to_delete'], mainRepoDir);
    }
    fs.unlinkSync(deleteFile);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      path: 'to_delete.txt',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.totalFilesChanged, 1);
    assert.strictEqual(parsed.fileSummaries[0].status, 'deleted');

    runGit(['checkout', 'HEAD', '--', '.'], mainRepoDir);
  });

  test('Sensitive files never appear in fileSummaries metadata', async () => {
    const envFile = path.join(mainRepoDir, '.env');
    fs.writeFileSync(envFile, 'SECRET=12345\n');
    runGit(['add', '-f', '.env'], mainRepoDir);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
      mode: 'staged',
    });

    assert.ok(!res.isError, 'Tool invocation must succeed');
    const parsed = parseResponse(res);

    // .env must NOT be in fileSummaries
    const hasEnvSummary = parsed.fileSummaries.some((s) => s.path.includes('.env'));
    assert.strictEqual(hasEnvSummary, false, 'Sensitive .env must not appear in fileSummaries');

    // Cleanup
    runGit(['rm', '-f', '.env'], mainRepoDir);
    runGit(['reset', 'HEAD', '.'], mainRepoDir);
  });

  test('Built-in DeclarativePolicyEngine returns ALLOW for arc_review_diff', () => {
    const engine = DeclarativePolicyEngine.builtIn(workspaceRegistry);
    const decision = engine.evaluate({
      toolName: 'arc_review_diff',
      workspaceId: 'ws-main',
      pathTargets: [],
    });

    assert.strictEqual(decision.effect, 'ALLOW');
    assert.strictEqual(decision.matchingRuleId, 'builtin-allow-rc07-read-only');
  });

  test('Task-3 timeout ceiling is frozen at 15 seconds and internal seam can lower it', async () => {
    // 1. Verify default timeout is 15,000 ms
    assert.strictEqual(getTask3TimeoutForTest(server), 15000);

    // 2. Seam rejects > 15,000 ms
    assert.throws(
      () => setTask3TimeoutForTest(server, 20000),
      /cannot exceed frozen maximum of 15000 ms/,
    );

    // 3. Seam rejects invalid / non-positive numbers
    assert.throws(() => setTask3TimeoutForTest(server, -1), /Task-3 timeout must be > 0 ms/);
    assert.throws(() => setTask3TimeoutForTest(server, NaN), /must be a finite number/);

    // 4. Seam can lower timeout for test
    setTask3TimeoutForTest(server, 1);
    assert.strictEqual(getTask3TimeoutForTest(server), 1);

    // Immediate invocation with 1ms timeout triggers timeout cancellation
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_review_diff', {
      workspaceId: 'ws-main',
    });

    assert.strictEqual(res.isError, true);
    const parsed = parseResponse(res);
    assert.strictEqual(parsed.code, 'EXECUTION_TIMEOUT');

    // Restore timeout to 15,000 ms
    setTask3TimeoutForTest(server, 15000);
    assert.strictEqual(getTask3TimeoutForTest(server), 15000);
  });
});
