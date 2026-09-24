/**
 * CesSpace ARC — RC-07 Task 2 Acceptance Test Suite
 * Repository Status (arc_repo_status) & Worktree Status (arc_worktree_status)
 *
 * Negative Controls: RC07-NEG-011 through RC07-NEG-018
 * Positive Flows: RC07-FLOW-03 through RC07-FLOW-05
 * Additional Required Tests: Tool discovery, schema validation, zero-bypass, etc.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

import { ArcMcpServer, ALL_TOOL_DEFINITIONS, TOOL_SCHEMAS } from '../apps/mcp-server/dist/index.js';
import {
  WorkspaceRegistry,
  SecurityKernel,
  ApprovalStateManager,
} from '../packages/policy/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

// ---------------------------------------------------------------------------
// Test Fixtures & Setup
// ---------------------------------------------------------------------------

let tempDir;
let mainRepoDir;
let linkedWtDir;
let lockedWtDir;
let detachedWtDir;
let nonGitDir;
let protectedMainDir;
let protectedMasterDir;
let protectedReleaseDir;
let symlinkGitDir;
let hugeMessageRepoDir;

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
}

const safeActor = {
  clientId: 'client-task2-test',
  clientType: 'worker',
  sessionId: 'session-task2-01',
  deviceId: 'device-task2-local',
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
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc07-task2-'));

  // 1. Clean feature repo
  mainRepoDir = path.join(tempDir, 'main_repo');
  fs.mkdirSync(mainRepoDir, { recursive: true });
  runGit(['init', '-b', 'feat/clean-branch'], mainRepoDir);
  fs.writeFileSync(path.join(mainRepoDir, 'file.txt'), 'hello world\n');
  runGit(['add', 'file.txt'], mainRepoDir);
  runGit(['commit', '-m', 'initial commit'], mainRepoDir);

  // 2. Linked worktree
  linkedWtDir = path.join(tempDir, 'linked_wt');
  runGit(['worktree', 'add', '-b', 'feat/worktree-branch', linkedWtDir], mainRepoDir);

  // 3. Locked worktree
  lockedWtDir = path.join(tempDir, 'locked_wt');
  runGit(['worktree', 'add', '-b', 'feat/locked-branch', lockedWtDir], mainRepoDir);
  runGit(['worktree', 'lock', '--reason', 'Maintenance in progress', lockedWtDir], mainRepoDir);

  // 4. Detached worktree
  detachedWtDir = path.join(tempDir, 'detached_wt');
  runGit(['worktree', 'add', '--detach', detachedWtDir], mainRepoDir);

  // 5. Non-git directory
  nonGitDir = path.join(tempDir, 'non_git');
  fs.mkdirSync(nonGitDir, { recursive: true });
  fs.writeFileSync(path.join(nonGitDir, 'some_file.txt'), 'not a git repo\n');

  // 6. Protected branches: main, master, release/*
  protectedMainDir = path.join(tempDir, 'protected_main');
  fs.mkdirSync(protectedMainDir, { recursive: true });
  runGit(['init', '-b', 'main'], protectedMainDir);
  fs.writeFileSync(path.join(protectedMainDir, 'f.txt'), 'main\n');
  runGit(['add', 'f.txt'], protectedMainDir);
  runGit(['commit', '-m', 'main commit'], protectedMainDir);

  protectedMasterDir = path.join(tempDir, 'protected_master');
  fs.mkdirSync(protectedMasterDir, { recursive: true });
  runGit(['init', '-b', 'master'], protectedMasterDir);
  fs.writeFileSync(path.join(protectedMasterDir, 'f.txt'), 'master\n');
  runGit(['add', 'f.txt'], protectedMasterDir);
  runGit(['commit', '-m', 'master commit'], protectedMasterDir);

  protectedReleaseDir = path.join(tempDir, 'protected_release');
  fs.mkdirSync(protectedReleaseDir, { recursive: true });
  runGit(['init', '-b', 'release/1.0'], protectedReleaseDir);
  fs.writeFileSync(path.join(protectedReleaseDir, 'f.txt'), 'release\n');
  runGit(['add', 'f.txt'], protectedReleaseDir);
  runGit(['commit', '-m', 'release commit'], protectedReleaseDir);

  // 7. Symlink escape fixture: .git symlink pointing outside workspace
  symlinkGitDir = path.join(tempDir, 'symlink_git_ws');
  fs.mkdirSync(symlinkGitDir, { recursive: true });
  fs.writeFileSync(path.join(symlinkGitDir, 'readme.txt'), 'symlink escape test\n');
  const externalGit = path.join(tempDir, 'external_dotgit');
  fs.mkdirSync(externalGit, { recursive: true });
  fs.writeFileSync(path.join(externalGit, 'HEAD'), 'ref: refs/heads/main\n');
  fs.symlinkSync(externalGit, path.join(symlinkGitDir, '.git'));

  // 8. Huge commit message repo (> 70 KiB commit message)
  hugeMessageRepoDir = path.join(tempDir, 'huge_message_repo');
  fs.mkdirSync(hugeMessageRepoDir, { recursive: true });
  runGit(['init', '-b', 'feat/huge-msg'], hugeMessageRepoDir);
  fs.writeFileSync(path.join(hugeMessageRepoDir, 'data.txt'), 'large commit\n');
  runGit(['add', 'data.txt'], hugeMessageRepoDir);
  const hugeMessage = 'A'.repeat(75 * 1024); // 75 KiB message
  runGit(['commit', '-m', hugeMessage], hugeMessageRepoDir);
});

after(() => {
  try {
    fs.rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function createTestServer(workspaces = [], options = {}) {
  const registry = new WorkspaceRegistry();
  for (const ws of workspaces) {
    registry.registerWorkspace(ws.id, ws.rootPath);
  }
  const procReg = new ProcessRegistry();
  const terminal = new ControlledProcessRunner(procReg);
  const audit = new AuditLogger();
  const kernel = new SecurityKernel(registry, procReg);
  const fsSub = new FilesystemSubsystem();
  const gitSub = new GitSubsystem();

  const server = new ArcMcpServer(
    registry,
    kernel,
    audit,
    fsSub,
    gitSub,
    {
      transport: 'stdio',
      ...(options.audit ? { audit: options.audit } : {}),
      ...(options.policy ? { policy: options.policy } : {}),
    },
    terminal,
    procReg,
    new ApprovalStateManager(),
  );

  return { server, registry, audit, gitSub, fsSub, procReg };
}

// ---------------------------------------------------------------------------
// Negative Controls (RC07-NEG-011 through RC07-NEG-018)
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Negative Controls (RC07-NEG-011..018)', () => {
  test('RC07-NEG-011: arc_repo_status on a non-git workspace fails with GIT_REPOSITORY_NOT_FOUND', async () => {
    const { server } = createTestServer([{ id: 'non-git-ws', rootPath: nonGitDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'non-git-ws',
    });

    assert.equal(res.isError, true, 'arc_repo_status must fail on non-git workspace');
    const err = parseResponse(res);
    assert.equal(err.code, 'GIT_REPOSITORY_NOT_FOUND');
    assert.ok(err.message.includes('not a valid Git repository'));
  });

  test('RC07-NEG-012: arc_repo_status never executes mutating Git commands (substantive repo-state proof)', async () => {
    // Create dirty state in a dedicated repo
    const mutateTestDir = path.join(tempDir, 'mutate_test_repo');
    fs.mkdirSync(mutateTestDir, { recursive: true });
    runGit(['init', '-b', 'feat/test-mutation'], mutateTestDir);
    fs.writeFileSync(path.join(mutateTestDir, 'tracked.txt'), 'initial content\n');
    runGit(['add', 'tracked.txt'], mutateTestDir);
    runGit(['commit', '-m', 'initial'], mutateTestDir);

    // Add unstaged modification and untracked file
    fs.writeFileSync(path.join(mutateTestDir, 'tracked.txt'), 'modified unstaged\n');
    fs.writeFileSync(path.join(mutateTestDir, 'untracked.txt'), 'untracked content\n');

    const headBefore = runGit(['rev-parse', 'HEAD'], mutateTestDir);
    const branchBefore = runGit(['rev-parse', '--abbrev-ref', 'HEAD'], mutateTestDir);
    const statusBefore = runGit(['status', '--porcelain=v1'], mutateTestDir);
    const trackedContentBefore = fs.readFileSync(path.join(mutateTestDir, 'tracked.txt'), 'utf8');
    const untrackedContentBefore = fs.readFileSync(
      path.join(mutateTestDir, 'untracked.txt'),
      'utf8',
    );

    const { server } = createTestServer([{ id: 'mutate-ws', rootPath: mutateTestDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'mutate-ws',
    });

    assert.equal(res.isError, undefined, 'arc_repo_status must succeed');

    // Substantive proof: verify repository state is completely untouched
    const headAfter = runGit(['rev-parse', 'HEAD'], mutateTestDir);
    const branchAfter = runGit(['rev-parse', '--abbrev-ref', 'HEAD'], mutateTestDir);
    const statusAfter = runGit(['status', '--porcelain=v1'], mutateTestDir);
    const trackedContentAfter = fs.readFileSync(path.join(mutateTestDir, 'tracked.txt'), 'utf8');
    const untrackedContentAfter = fs.readFileSync(
      path.join(mutateTestDir, 'untracked.txt'),
      'utf8',
    );

    assert.equal(headAfter, headBefore, 'HEAD SHA must not mutate');
    assert.equal(branchAfter, branchBefore, 'Branch must not mutate');
    assert.equal(statusAfter, statusBefore, 'Git status porcelain output must remain identical');
    assert.equal(trackedContentAfter, trackedContentBefore, 'Tracked file must not mutate');
    assert.equal(untrackedContentAfter, untrackedContentBefore, 'Untracked file must not mutate');
  });

  test('RC07-NEG-013: arc_repo_status bounds serialized output to 64 KiB with truncated: true', async () => {
    const { server } = createTestServer([{ id: 'huge-msg-ws', rootPath: hugeMessageRepoDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'huge-msg-ws',
    });

    assert.equal(res.isError, undefined, 'arc_repo_status must succeed with bounded response');
    const body = parseResponse(res);

    // Validate 64 KiB bound (65,536 bytes)
    const jsonBytes = Buffer.byteLength(JSON.stringify(body), 'utf8');
    assert.ok(
      jsonBytes <= 64 * 1024,
      `Response size (${jsonBytes} bytes) must be <= 64 KiB (65,536 bytes)`,
    );

    // Explicit acceptance requirement from RC07-NEG-013
    assert.equal(body.truncated, true, 'Response must carry truncated: true');
    assert.ok(
      body.headCommit.message.includes('[TRUNCATED]'),
      'Commit message must show truncation mark',
    );
    assert.equal(body.branch, 'feat/huge-msg');
    assert.ok(body.headCommit.hash.length === 40);
  });

  test('RC07-NEG-014: arc_worktree_status targeting path outside workspace fails with PATH_OUTSIDE_WORKSPACE', async () => {
    const { server } = createTestServer([{ id: 'wt-ws', rootPath: linkedWtDir }]);

    // Attempt to target an external path outside canonical workspace root
    const outsidePath = path.join(tempDir, 'outside_workspace');
    fs.mkdirSync(outsidePath, { recursive: true });

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'wt-ws',
      workspaceRoot: outsidePath,
    });

    assert.equal(res.isError, true, 'arc_worktree_status must reject outside path');
    const err = parseResponse(res);
    assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
  });

  test('RC07-NEG-015: arc_worktree_status encounters symlinked .git resolving outside workspace fails with SYMLINK_ESCAPE_DETECTED', async () => {
    const { server } = createTestServer([{ id: 'symlink-ws', rootPath: symlinkGitDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'symlink-ws',
    });

    assert.equal(res.isError, true, 'arc_worktree_status must reject symlink escape');
    const err = parseResponse(res);
    assert.equal(err.code, 'SYMLINK_ESCAPE_DETECTED');
    assert.ok(err.message.includes('Symlinked .git metadata resolves outside'));
  });

  test('RC07-NEG-016: arc_worktree_status invoked with directory traversal argument (../) rejected before resolution', async () => {
    const { server } = createTestServer([{ id: 'wt-ws', rootPath: linkedWtDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'wt-ws',
      workspaceRoot: '../traversal_attempt',
    });

    assert.equal(res.isError, true, 'arc_worktree_status must reject traversal argument');
    const err = parseResponse(res);
    assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
    assert.ok(err.message.includes('Directory traversal'));
  });

  test('RC07-NEG-017: arc_repo_status on protected branches (main, master, release/*) flags isProtectedBranch === true', async () => {
    const { server } = createTestServer([
      { id: 'ws-main', rootPath: protectedMainDir },
      { id: 'ws-master', rootPath: protectedMasterDir },
      { id: 'ws-release', rootPath: protectedReleaseDir },
      { id: 'ws-clean', rootPath: mainRepoDir },
    ]);

    // 1. main
    const resMain = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-main',
    });
    assert.equal(parseResponse(resMain).isProtectedBranch, true, 'main must be protected');

    // 2. master
    const resMaster = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-master',
    });
    assert.equal(parseResponse(resMaster).isProtectedBranch, true, 'master must be protected');

    // 3. release/*
    const resRelease = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-release',
    });
    assert.equal(parseResponse(resRelease).isProtectedBranch, true, 'release/* must be protected');

    // 4. normal feature branch must be false
    const resClean = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-clean',
    });
    assert.equal(
      parseResponse(resClean).isProtectedBranch,
      false,
      'feature branch must not be protected',
    );
  });

  test('RC07-NEG-018: Unregistered workspace selector supplied to arc_worktree_status fails with WORKSPACE_UNREGISTERED', async () => {
    const { server } = createTestServer([{ id: 'registered-ws', rootPath: mainRepoDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'completely-unregistered-workspace-id',
    });

    assert.equal(res.isError, true, 'Unregistered workspace selector must fail closed');
    const err = parseResponse(res);
    assert.equal(err.code, 'WORKSPACE_UNREGISTERED');
  });
});

// ---------------------------------------------------------------------------
// Positive Flows (RC07-FLOW-03 through RC07-FLOW-05)
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Positive Acceptance Flows (RC07-FLOW-03..05)', () => {
  test('RC07-FLOW-03: Repository Status Query on clean feature branch', async () => {
    const { server } = createTestServer([{ id: 'clean-ws', rootPath: mainRepoDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'clean-ws',
    });

    assert.equal(res.isError, undefined, 'arc_repo_status should succeed');
    const data = parseResponse(res);

    assert.equal(data.branch, 'feat/clean-branch');
    assert.ok(/^[0-9a-f]{40}$/i.test(data.headCommit.hash), 'HEAD hash must be 40-hex SHA');
    assert.equal(data.headCommit.shortHash, data.headCommit.hash.slice(0, 7));
    assert.equal(data.headCommit.message, 'initial commit');
    assert.ok(data.headCommit.author.includes('Alice Engineer'));
    assert.ok(data.headCommit.date.length > 0);
    assert.equal(data.isClean, true);
    assert.equal(data.isProtectedBranch, false);
    assert.deepEqual(data.counts, { staged: 0, unstaged: 0, untracked: 0 });
  });

  test('RC07-FLOW-04: Dirty Repository Status Detection with staged, unstaged, and untracked counts', async () => {
    // Create dirty repo fixture
    const dirtyRepoDir = path.join(tempDir, 'dirty_repo');
    fs.mkdirSync(dirtyRepoDir, { recursive: true });
    runGit(['init', '-b', 'feat/dirty-branch'], dirtyRepoDir);
    fs.writeFileSync(path.join(dirtyRepoDir, 'base.txt'), 'base\n');
    runGit(['add', 'base.txt'], dirtyRepoDir);
    runGit(['commit', '-m', 'base commit'], dirtyRepoDir);

    // Staged change
    fs.writeFileSync(path.join(dirtyRepoDir, 'staged.txt'), 'staged content\n');
    runGit(['add', 'staged.txt'], dirtyRepoDir);

    // Unstaged change
    fs.writeFileSync(path.join(dirtyRepoDir, 'base.txt'), 'modified unstaged content\n');

    // Untracked files (2 untracked files)
    fs.writeFileSync(path.join(dirtyRepoDir, 'untracked1.txt'), 'untracked 1\n');
    fs.writeFileSync(path.join(dirtyRepoDir, 'untracked2.txt'), 'untracked 2\n');

    const { server } = createTestServer([{ id: 'dirty-ws', rootPath: dirtyRepoDir }]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'dirty-ws',
    });

    assert.equal(res.isError, undefined, 'arc_repo_status must succeed');
    const data = parseResponse(res);

    assert.equal(data.branch, 'feat/dirty-branch');
    assert.equal(data.isClean, false, 'isClean must be false for dirty repo');
    assert.equal(data.counts.staged, 1, 'Staged count must be exactly 1');
    assert.equal(data.counts.unstaged, 1, 'Unstaged count must be exactly 1');
    assert.equal(data.counts.untracked, 2, 'Untracked count must be exactly 2');
  });

  test('RC07-FLOW-05: Worktree Status Verification on real linked Git worktree', async () => {
    const { server } = createTestServer([
      { id: 'main-ws', rootPath: mainRepoDir },
      { id: 'linked-wt-ws', rootPath: linkedWtDir },
      { id: 'locked-wt-ws', rootPath: lockedWtDir },
      { id: 'detached-wt-ws', rootPath: detachedWtDir },
    ]);

    // 1. Linked worktree check
    const resLinked = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'linked-wt-ws',
    });
    assert.equal(resLinked.isError, undefined);
    const dataLinked = parseResponse(resLinked);

    assert.equal(dataLinked.isWorktree, true, 'isWorktree must be true for linked worktree');
    assert.equal(dataLinked.workspaceId, 'linked-wt-ws');
    assert.equal(dataLinked.worktreePath, fs.realpathSync(linkedWtDir));
    assert.equal(dataLinked.mainRepoPath, fs.realpathSync(mainRepoDir));
    assert.equal(dataLinked.branch, 'feat/worktree-branch');
    assert.equal(dataLinked.isDetached, false);
    assert.ok(/^[0-9a-f]{40}$/i.test(dataLinked.headSha));
    assert.equal(dataLinked.locked, false);

    // 2. Locked worktree check
    const resLocked = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'locked-wt-ws',
    });
    assert.equal(resLocked.isError, undefined);
    const dataLocked = parseResponse(resLocked);
    assert.equal(dataLocked.isWorktree, true);
    assert.equal(dataLocked.locked, true);
    assert.equal(dataLocked.lockReason, 'Maintenance in progress');

    // 3. Detached worktree check
    const resDetached = await server.executeAuthenticatedToolCall(
      safeActor,
      'arc_worktree_status',
      {
        workspaceId: 'detached-wt-ws',
      },
    );
    assert.equal(resDetached.isError, undefined);
    const dataDetached = parseResponse(resDetached);
    assert.equal(dataDetached.isWorktree, true);
    assert.equal(dataDetached.isDetached, true);
    assert.ok(/^[0-9a-f]{40}$/i.test(dataDetached.headSha));

    // 4. Main repository check (not a linked worktree)
    const resMain = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'main-ws',
    });
    assert.equal(resMain.isError, undefined);
    const dataMain = parseResponse(resMain);
    assert.equal(dataMain.isWorktree, false, 'Main repository must have isWorktree === false');
    assert.equal(dataMain.worktreePath, fs.realpathSync(mainRepoDir));
    assert.equal(dataMain.mainRepoPath, fs.realpathSync(mainRepoDir));
    assert.equal(dataMain.branch, 'feat/clean-branch');
    assert.equal(dataMain.locked, false);
  });
});

// ---------------------------------------------------------------------------
// Additional Required Tests
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Discovery, Schema & Security Controls', () => {
  test('1 & 2: Production discovery tool count is exactly 20, advertising only 2 Task-2 RC-07 tools', () => {
    assert.equal(
      ALL_TOOL_DEFINITIONS.length,
      20,
      'ALL_TOOL_DEFINITIONS must have exactly 20 tools',
    );

    const toolNames = ALL_TOOL_DEFINITIONS.map((t) => t.name);
    assert.ok(
      toolNames.includes('arc_repo_status'),
      'arc_repo_status must be in production tools/list',
    );
    assert.ok(
      toolNames.includes('arc_worktree_status'),
      'arc_worktree_status must be in production tools/list',
    );

    // Remaining 5 tools must NOT be in production list
    assert.ok(
      !toolNames.includes('arc_review_diff'),
      'arc_review_diff must remain absent from tools/list',
    );
    assert.ok(!toolNames.includes('arc_verify'), 'arc_verify must remain absent from tools/list');
    assert.ok(!toolNames.includes('arc_test'), 'arc_test must remain absent from tools/list');
    assert.ok(
      !toolNames.includes('arc_ci_status'),
      'arc_ci_status must remain absent from tools/list',
    );
    assert.ok(
      !toolNames.includes('arc_stage_evidence'),
      'arc_stage_evidence must remain absent from tools/list',
    );
  });

  test('3: Task-2 tool schemas strictly reject extra properties', () => {
    // arc_repo_status
    assert.ok(TOOL_SCHEMAS.arc_repo_status, 'TOOL_SCHEMAS.arc_repo_status must exist');
    const validRepo = TOOL_SCHEMAS.arc_repo_status.safeParse({ workspaceId: 'ws-1' });
    assert.equal(validRepo.success, true);
    const invalidRepo = TOOL_SCHEMAS.arc_repo_status.safeParse({
      workspaceId: 'ws-1',
      extraProperty: 'forbidden',
    });
    assert.equal(
      invalidRepo.success,
      false,
      'Extra properties must be rejected on arc_repo_status',
    );

    // arc_worktree_status
    assert.ok(TOOL_SCHEMAS.arc_worktree_status, 'TOOL_SCHEMAS.arc_worktree_status must exist');
    const validWt = TOOL_SCHEMAS.arc_worktree_status.safeParse({ workspaceId: 'ws-1' });
    assert.equal(validWt.success, true);
    const invalidWt = TOOL_SCHEMAS.arc_worktree_status.safeParse({
      workspaceId: 'ws-1',
      extraProperty: 'forbidden',
    });
    assert.equal(
      invalidWt.success,
      false,
      'Extra properties must be rejected on arc_worktree_status',
    );
  });

  test('4: Conflicting workspaceId/workspaceRoot selectors fail closed', async () => {
    const { server } = createTestServer([
      { id: 'ws-1', rootPath: mainRepoDir },
      { id: 'ws-2', rootPath: linkedWtDir },
    ]);

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-1',
      workspaceRoot: linkedWtDir, // belongs to ws-2
    });

    assert.equal(res.isError, true, 'Conflicting selectors must fail closed');
    const err = parseResponse(res);
    assert.equal(err.code, 'NO_WORKSPACE_CONFIGURED');
  });

  test('5: Unauthenticated Task-2 invocation satisfies RC07-NEG-001 (rejected with UNAUTHENTICATED)', async () => {
    const { server } = createTestServer([{ id: 'ws-clean', rootPath: mainRepoDir }]);

    const unauthActor = {
      clientId: '',
      clientType: 'worker',
      sessionId: '',
      deviceId: 'device-test',
      authenticated: false,
    };

    const res = await server.executeAuthenticatedToolCall(unauthActor, 'arc_repo_status', {
      workspaceId: 'ws-clean',
    });

    assert.equal(res.isError, true, 'Unauthenticated caller must be denied');
    const err = parseResponse(res);
    assert.equal(err.code, 'UNAUTHENTICATED');
  });

  test('6: Audit-unavailable/degraded state prevents composite execution', async () => {
    const auditConfig = createAuditConfig(tempDir, 'task2-audit-degraded');
    const { server } = createTestServer([{ id: 'ws-clean', rootPath: mainRepoDir }], {
      audit: auditConfig,
    });
    await server.start();

    try {
      // Latch degraded audit failure
      server.auditRuntime.latchDegradedAuditFailure();

      // Invocation should fail closed
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
        workspaceId: 'ws-clean',
      });

      assert.equal(res.isError, true, 'Degraded audit state must cause refusal');
    } finally {
      await server.stop();
    }
  });

  test('7: Read-only tools allow default execution but respect external declarative policy rules', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-policy', mainRepoDir);
    const procReg = new ProcessRegistry();
    const terminal = new ControlledProcessRunner(procReg);
    const audit = new AuditLogger();
    const kernel = new SecurityKernel(registry, procReg);

    const server = new ArcMcpServer(
      registry,
      kernel,
      audit,
      new FilesystemSubsystem(),
      new GitSubsystem(),
      {
        transport: 'stdio',
        policy: {
          format: 'json',
          sourceText: JSON.stringify({
            version: '1.0',
            workspaces: [{ id: 'ws-policy' }],
            rules: [
              {
                id: 'deny-repo-status-rule',
                effect: 'DENY',
                tools: ['arc_repo_status'],
              },
            ],
          }),
        },
      },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-policy',
    });

    assert.equal(res.isError, true, 'External declarative policy DENY must be honored');
    const err = parseResponse(res);
    assert.equal(err.code, 'POLICY_DENIED');
  });

  test('8: No direct child_process import/use in Task-2 production implementation', () => {
    const filePath = path.resolve('apps/mcp-server/src/internal/repo-worktree-status.ts');
    const content = fs.readFileSync(filePath, 'utf8');

    assert.ok(
      !content.includes('child_process'),
      'repo-worktree-status.ts must not import child_process',
    );
    assert.ok(!content.includes('exec('), 'repo-worktree-status.ts must not invoke exec()');
    assert.ok(!content.includes('execFile('), 'repo-worktree-status.ts must not invoke execFile()');
    assert.ok(!content.includes('spawn('), 'repo-worktree-status.ts must not invoke spawn()');
    assert.ok(!content.includes('fork('), 'repo-worktree-status.ts must not invoke fork()');
  });

  test('9: No direct fs/fs-promises import/use in Task-2 production implementation', () => {
    const filePath = path.resolve('apps/mcp-server/src/internal/repo-worktree-status.ts');
    const content = fs.readFileSync(filePath, 'utf8');

    assert.ok(!content.includes("'node:fs'"), "repo-worktree-status.ts must not import 'node:fs'");
    assert.ok(!content.includes('"node:fs"'), 'repo-worktree-status.ts must not import "node:fs"');
    assert.ok(!content.includes("'fs'"), "repo-worktree-status.ts must not import 'fs'");
    assert.ok(
      !content.includes('fs/promises'),
      'repo-worktree-status.ts must not import fs/promises',
    );
  });
});
