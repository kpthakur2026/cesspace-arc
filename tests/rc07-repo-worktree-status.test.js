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

import {
  ArcMcpServer,
  createArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  TOOL_SCHEMAS,
} from '../apps/mcp-server/dist/index.js';
import { SERVER_INTERNAL_ACCESS } from '../apps/mcp-server/dist/internal/server-seam.js';
import {
  WorkspaceRegistry,
  SecurityKernel,
  ApprovalStateManager,
  DeclarativePolicyEngine,
  RC07_TASK2_READ_ONLY_TOOLS,
} from '../packages/policy/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import {
  DEFAULT_TASK2_TIMEOUT_MS,
  truncateStringBytes,
  boundRepoStatusResponse,
  boundWorktreeStatusResponse,
  getMcpPayloadByteLength,
} from '../apps/mcp-server/dist/internal/repo-worktree-status.js';

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
    const actualMcpText = res.content[0].text;
    const actualMcpBytes = Buffer.byteLength(actualMcpText, 'utf8');

    // Required acceptance: Buffer.byteLength(res.content[0].text, 'utf8') <= 65536
    assert.ok(
      actualMcpBytes <= 64 * 1024,
      `Actual MCP response byte length (${actualMcpBytes} bytes) must be <= 64 KiB (65,536 bytes)`,
    );

    const body = JSON.parse(actualMcpText);

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
  test('1 & 2: Production discovery tool count includes Task-2 tools and remaining 4 RC-07 tools remain absent', () => {
    assert.ok(
      ALL_TOOL_DEFINITIONS.length >= 20,
      'ALL_TOOL_DEFINITIONS must include all registered tools',
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

    // Remaining 2 unowned RC-07 tools must NOT be in production list
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

// ---------------------------------------------------------------------------
// Defect 1: Declarative Policy Integration & No-Bypass Invariants
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Declarative Policy Integration & No-Bypass Invariants', () => {
  test('built-in DeclarativePolicyEngine itself returns ALLOW for arc_repo_status', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-test', mainRepoDir);
    const engine = DeclarativePolicyEngine.builtIn(registry);

    const decision = engine.evaluate({ toolName: 'arc_repo_status' });
    assert.equal(decision.effect, 'ALLOW');
    assert.equal(decision.matchingRuleId, 'builtin-allow-rc07-read-only');
  });

  test('built-in DeclarativePolicyEngine itself returns ALLOW for arc_worktree_status', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-test', mainRepoDir);
    const engine = DeclarativePolicyEngine.builtIn(registry);

    const decision = engine.evaluate({ toolName: 'arc_worktree_status' });
    assert.equal(decision.effect, 'ALLOW');
    assert.equal(decision.matchingRuleId, 'builtin-allow-rc07-read-only');
  });

  test('RC07_TASK2_READ_ONLY_TOOLS contains exactly arc_repo_status and arc_worktree_status', () => {
    assert.deepEqual(RC07_TASK2_READ_ONLY_TOOLS, ['arc_repo_status', 'arc_worktree_status']);
  });

  test('MCP server contains no tool-name-specific hard-coded ALLOW branch for Task 2', () => {
    const mcpIndexPath = path.resolve('apps/mcp-server/src/index.ts');
    const content = fs.readFileSync(mcpIndexPath, 'utf8');

    // Assert that the old Layer 2 bypass branch was completely eliminated
    assert.ok(
      !content.includes("policyMode === 'BUILTIN' &&"),
      "apps/mcp-server/src/index.ts must not special-case policyMode === 'BUILTIN'",
    );
    assert.ok(
      !content.includes("matchingRuleId: 'builtin-allow-rc07-read-only'"),
      'apps/mcp-server/src/index.ts must not synthesize builtin-allow-rc07-read-only directly',
    );
  });

  test('an external DENY still denies arc_repo_status and arc_worktree_status', async () => {
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
                id: 'deny-rc07-status-tools',
                effect: 'DENY',
                tools: ['arc_repo_status', 'arc_worktree_status'],
              },
            ],
          }),
        },
      },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const resRepo = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-policy',
    });
    assert.equal(resRepo.isError, true);
    assert.equal(parseResponse(resRepo).code, 'POLICY_DENIED');

    const resWt = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'ws-policy',
    });
    assert.equal(resWt.isError, true);
    assert.equal(parseResponse(resWt).code, 'POLICY_DENIED');
  });

  test('an external REQUIRE_APPROVAL rule participates normally', async () => {
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
                id: 'approval-required-repo-status',
                effect: 'REQUIRE_APPROVAL',
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

    assert.equal(res.isError, true, 'REQUIRE_APPROVAL rule must require approval');
    const err = parseResponse(res);
    assert.equal(err.code, 'APPROVAL_REQUIRED');
  });

  test('DENY precedence outranks REQUIRE_APPROVAL and ALLOW', async () => {
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
                id: 'allow-status',
                effect: 'ALLOW',
                tools: ['arc_repo_status'],
              },
              {
                id: 'require-approval-status',
                effect: 'REQUIRE_APPROVAL',
                tools: ['arc_repo_status'],
              },
              {
                id: 'deny-status',
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

    assert.equal(res.isError, true, 'DENY must outrank all other rules');
    const err = parseResponse(res);
    assert.equal(err.code, 'POLICY_DENIED');
  });
});

// ---------------------------------------------------------------------------
// Defect 2: 15-Second Aggregate Timeout & Immediate Subprocess Cancellation
// ---------------------------------------------------------------------------

class FakeSlowGitSubsystem extends GitSubsystem {
  getStatusCalls = 0;
  getLogCalls = 0;
  operationsAfterCancellation = 0;
  slowDelayMs = 200;

  constructor() {
    super();
  }

  async getStatus(workspaceRoot, request, options) {
    this.getStatusCalls++;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, this.slowDelayMs);
      if (options?.signal) {
        options.signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(ArcError.executionTimeout('Command execution exceeded configured timeout.'));
        });
      }
    });
    return super.getStatus(workspaceRoot, request, options);
  }

  async getLog(workspaceRoot, request, options) {
    if (options?.signal?.aborted) {
      this.operationsAfterCancellation++;
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }
    this.getLogCalls++;
    return super.getLog(workspaceRoot, request, options);
  }
}

describe('RC-07 Task 2: 15-Second Aggregate Timeout & Cancellation Invariants', () => {
  test('DEFAULT_TASK2_TIMEOUT_MS === 15000', () => {
    assert.equal(
      DEFAULT_TASK2_TIMEOUT_MS,
      15000,
      'Default Task-2 timeout ceiling must be exactly 15,000 ms',
    );
  });

  test('Production ArcServerConfig has no Task-2 timeout override', () => {
    const indexTs = fs.readFileSync(path.resolve('apps/mcp-server/src/index.ts'), 'utf8');
    const configMatch = indexTs.match(/export\s+interface\s+ArcServerConfig\s*\{([\s\S]*?)\}/);
    assert.ok(
      configMatch,
      'ArcServerConfig interface must be defined in apps/mcp-server/src/index.ts',
    );
    assert.ok(
      !configMatch[1].includes('task2TimeoutMs'),
      'ArcServerConfig must not expose task2TimeoutMs property',
    );
  });

  test('createArcMcpServer({ task2TimeoutMs: 60000 } as any) cannot increase the effective Task-2 ceiling', () => {
    const auditConfig = createAuditConfig(tempDir, 'prod-cfg-bypass');
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws-prod', path: mainRepoDir }],
      audit: auditConfig,
      task2TimeoutMs: 60000,
    });
    const seam = SERVER_INTERNAL_ACCESS.get(server);
    assert.ok(seam, 'Internal test seam must exist on created server');
    assert.equal(
      seam.getTask2TimeoutMs(),
      15000,
      'Task-2 timeout must remain DEFAULT_TASK2_TIMEOUT_MS (15000) and ignore config.task2TimeoutMs',
    );
  });

  test('Direct new ArcMcpServer(..., { task2TimeoutMs: 60000 } as any, ...) cannot increase it either', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-direct', mainRepoDir);
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
        task2TimeoutMs: 60000,
      },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const seam = SERVER_INTERNAL_ACCESS.get(server);
    assert.ok(seam, 'Internal test seam must exist on created server');
    assert.equal(
      seam.getTask2TimeoutMs(),
      15000,
      'Task-2 timeout must remain DEFAULT_TASK2_TIMEOUT_MS (15000) and ignore config.task2TimeoutMs',
    );
  });

  test('The package-internal test seam can reduce the timeout to 50 ms', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-seam', mainRepoDir);
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
      { transport: 'stdio' },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const seam = SERVER_INTERNAL_ACCESS.get(server);
    assert.ok(seam, 'Internal test seam must be available');
    assert.equal(seam.getTask2TimeoutMs(), 15000, 'Initial timeout must be 15000 ms');

    seam.setTask2TimeoutMs(50);
    assert.equal(
      seam.getTask2TimeoutMs(),
      50,
      'Internal seam must be able to lower timeout to 50 ms',
    );
  });

  test('The internal seam rejects/clamps attempts above 15000', () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-seam-reject', mainRepoDir);
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
      { transport: 'stdio' },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const seam = SERVER_INTERNAL_ACCESS.get(server);
    assert.ok(seam, 'Internal test seam must be available');

    // 1. Attempts above 15000 are rejected
    assert.throws(
      () => seam.setTask2TimeoutMs(60000),
      /RangeError/,
      'Attempts to set timeout > 15000 must be rejected',
    );
    assert.equal(seam.getTask2TimeoutMs(), 15000);

    // 2. Non-finite values are rejected
    assert.throws(() => seam.setTask2TimeoutMs(NaN), /TypeError/);
    assert.throws(() => seam.setTask2TimeoutMs(Infinity), /TypeError/);
    assert.throws(() => seam.setTask2TimeoutMs(-Infinity), /TypeError/);

    // 3. Zero / negative values are rejected
    assert.throws(() => seam.setTask2TimeoutMs(0), /RangeError/);
    assert.throws(() => seam.setTask2TimeoutMs(-100), /RangeError/);

    // 4. Malformed runtime values are rejected
    assert.throws(() => seam.setTask2TimeoutMs('50'), /TypeError/);
    assert.throws(() => seam.setTask2TimeoutMs(null), /TypeError/);
    assert.throws(() => seam.setTask2TimeoutMs({}), /TypeError/);

    // Effective timeout never exceeded 15000
    assert.ok(seam.getTask2TimeoutMs() <= 15000);
    assert.equal(seam.getTask2TimeoutMs(), 15000);
  });

  test('The aggregate AbortController/Git cancellation test still passes', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-timeout', mainRepoDir);
    const procReg = new ProcessRegistry();
    const terminal = new ControlledProcessRunner(procReg);
    const audit = new AuditLogger();
    const kernel = new SecurityKernel(registry, procReg);
    const fakeSlowGit = new FakeSlowGitSubsystem();

    const server = new ArcMcpServer(
      registry,
      kernel,
      audit,
      new FilesystemSubsystem(),
      fakeSlowGit,
      {
        transport: 'stdio',
      },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    // Set 50ms timeout via internal test seam
    const seam = SERVER_INTERNAL_ACCESS.get(server);
    assert.ok(seam, 'SERVER_INTERNAL_ACCESS must be available for internal test');
    seam.setTask2TimeoutMs(50);
    assert.equal(seam.getTask2TimeoutMs(), 50);

    const startTime = Date.now();
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-timeout',
    });
    const elapsed = Date.now() - startTime;

    // 1. Total execution time bounded by configured ceiling
    assert.ok(
      elapsed < 1000,
      `Tool execution should terminate near the 50ms deadline, took ${elapsed}ms`,
    );

    // 2. Timeout produces frozen sanitized timeout outcome
    assert.equal(res.isError, true, 'Timeout must produce error outcome');
    const err = parseResponse(res);
    assert.equal(err.code, 'EXECUTION_TIMEOUT');
    assert.equal(err.message, 'Command execution exceeded configured timeout.');

    // 3. No later Git operation continues after cancellation
    assert.equal(
      fakeSlowGit.getLogCalls,
      0,
      'gitSubsystem.getLog must NEVER be called after cancellation',
    );
    assert.equal(
      fakeSlowGit.operationsAfterCancellation,
      0,
      'Zero operations should occur after cancellation',
    );

    // 4. Durable lifecycle remains truthful: execution status is 'TIMEOUT'
    const records = audit.getRecords();
    const terminalRecord = records[records.length - 1];
    assert.ok(terminalRecord, 'Audit record must be logged');
    assert.equal(
      terminalRecord.execution.status,
      'TIMEOUT',
      'Truthful audit lifecycle status must be TIMEOUT',
    );
  });
});

// ---------------------------------------------------------------------------
// Defect 3: Exact MCP Payload Byte-Bounding (<= 65,536 bytes) & Multibyte Handling
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Response Bounding & Serialization Invariants', () => {
  test('oversized commit message: actual res.content[0].text <= 65536 and truncated: true', async () => {
    const { server } = createTestServer([{ id: 'ws-huge-msg', rootPath: hugeMessageRepoDir }]);
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-huge-msg',
    });

    assert.equal(res.isError, undefined);
    const mcpText = res.content[0].text;
    const byteLength = Buffer.byteLength(mcpText, 'utf8');

    assert.ok(
      byteLength <= 65536,
      `Actual MCP response byte length (${byteLength}) must be <= 65,536 bytes`,
    );

    const data = JSON.parse(mcpText);
    assert.equal(data.truncated, true);
    assert.ok(data.headCommit.message.includes('[TRUNCATED]'));
  });

  test('oversized author field: actual res.content[0].text <= 65536 and truncated: true', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-author', mainRepoDir);
    const procReg = new ProcessRegistry();
    const terminal = new ControlledProcessRunner(procReg);
    const audit = new AuditLogger();
    const kernel = new SecurityKernel(registry, procReg);

    class HugeAuthorGitSubsystem extends GitSubsystem {
      async getLog(workspaceRoot, request, options) {
        const res = await super.getLog(workspaceRoot, request, options);
        if (res.commits.length > 0) {
          res.commits[0].author = 'Alice Engineer '.repeat(6000); // ~90 KiB author field
        }
        return res;
      }
    }

    const server = new ArcMcpServer(
      registry,
      kernel,
      audit,
      new FilesystemSubsystem(),
      new HugeAuthorGitSubsystem(),
      { transport: 'stdio' },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-author',
    });

    assert.equal(res.isError, undefined);
    const mcpText = res.content[0].text;
    const byteLength = Buffer.byteLength(mcpText, 'utf8');

    assert.ok(
      byteLength <= 65536,
      `Actual MCP response byte length (${byteLength}) must be <= 65,536 bytes`,
    );

    const data = JSON.parse(mcpText);
    assert.equal(data.truncated, true);
    assert.ok(data.headCommit.author.includes('[TRUNCATED]'));
  });

  test('oversized worktree lockReason: actual res.content[0].text <= 65536 and truncated: true', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-locked', lockedWtDir);
    const procReg = new ProcessRegistry();
    const terminal = new ControlledProcessRunner(procReg);
    const audit = new AuditLogger();
    const kernel = new SecurityKernel(registry, procReg);

    class HugeLockReasonGitSubsystem extends GitSubsystem {
      async getWorktreeMetadata(workspaceRoot, options) {
        const meta = await super.getWorktreeMetadata(workspaceRoot, options);
        meta.lockReason = 'Deployment lock in progress: '.repeat(4000); // ~120 KiB lockReason
        return meta;
      }
    }

    const server = new ArcMcpServer(
      registry,
      kernel,
      audit,
      new FilesystemSubsystem(),
      new HugeLockReasonGitSubsystem(),
      { transport: 'stdio' },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_worktree_status', {
      workspaceId: 'ws-locked',
    });

    assert.equal(res.isError, undefined);
    const mcpText = res.content[0].text;
    const byteLength = Buffer.byteLength(mcpText, 'utf8');

    assert.ok(
      byteLength <= 65536,
      `Actual MCP response byte length (${byteLength}) must be <= 65,536 bytes`,
    );

    const data = JSON.parse(mcpText);
    assert.equal(data.truncated, true);
    assert.ok(data.lockReason.includes('[TRUNCATED]'));
  });

  test('multibyte UTF-8 boundary truncation safety', () => {
    // 4-byte emojis, 3-byte Japanese characters, and 2-byte accented characters
    const complexString = '🚀🌟🔥日本語テストéàü'.repeat(100);

    for (let maxBytes = 1; maxBytes <= 200; maxBytes++) {
      const truncated = truncateStringBytes(complexString, maxBytes);
      const actualBytes = Buffer.byteLength(truncated, 'utf8');

      assert.ok(
        actualBytes <= maxBytes,
        `Truncated byte length (${actualBytes}) must not exceed maxBytes (${maxBytes})`,
      );
      assert.ok(
        !truncated.includes('\uFFFD'),
        'Truncated string must never contain UTF-8 replacement character \\uFFFD',
      );
    }
  });

  test('boundRepoStatusResponse, boundWorktreeStatusResponse, and getMcpPayloadByteLength invariants', () => {
    const rawRepo = {
      workspaceId: 'ws-1',
      branch: 'main',
      headCommit: {
        hash: 'abc',
        message: 'hello',
        author: 'dev',
        date: '2026-01-01',
      },
      workingTree: {
        clean: true,
        staged: [],
        unstaged: [],
        untracked: [],
      },
      isClean: true,
    };
    const boundedRepo = boundRepoStatusResponse(rawRepo);
    assert.equal(boundedRepo.isClean, true);
    assert.ok(getMcpPayloadByteLength(boundedRepo) <= 65536);

    const rawWt = {
      workspaceId: 'ws-1',
      worktreePath: '/tmp/wt',
      headHash: 'abc',
      branch: 'main',
      isBare: false,
      isLocked: false,
      lockReason: null,
      isPrunable: false,
    };
    const boundedWt = boundWorktreeStatusResponse(rawWt);
    assert.equal(boundedWt.isBare, false);
    assert.ok(getMcpPayloadByteLength(boundedWt) <= 65536);
  });
});

// ---------------------------------------------------------------------------
// Truthfulness Hardening: Git Failure Handling
// ---------------------------------------------------------------------------

describe('RC-07 Task 2: Truthful Git-Log & Repository Failure Handling', () => {
  test('genuine empty repository condition produces clean status with empty HEAD metadata', async () => {
    const emptyRepoDir = path.join(tempDir, 'empty_repo');
    fs.mkdirSync(emptyRepoDir, { recursive: true });
    runGit(['init', '-b', 'main'], emptyRepoDir);

    const { server } = createTestServer([{ id: 'ws-empty', rootPath: emptyRepoDir }]);
    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-empty',
    });

    assert.equal(res.isError, undefined, 'arc_repo_status should succeed on empty repository');
    const data = parseResponse(res);
    assert.equal(data.headCommit.hash, '', 'Empty repo must have blank commit hash');
    assert.equal(data.headCommit.message, '', 'Empty repo must have blank commit message');
    assert.equal(data.headCommit.author, '', 'Empty repo must have blank commit author');
    assert.equal(data.isClean, true);
  });

  test('GitSubsystem failure during getLog when commit exists is NOT swallowed and fails closed', async () => {
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('ws-corrupt', mainRepoDir);
    const procReg = new ProcessRegistry();
    const terminal = new ControlledProcessRunner(procReg);
    const audit = new AuditLogger();
    const kernel = new SecurityKernel(registry, procReg);

    class FailingLogGitSubsystem extends GitSubsystem {
      async getLog(_workspaceRoot, _request, _options) {
        throw ArcError.internalError('Corrupted Git commit object database.');
      }
    }

    const server = new ArcMcpServer(
      registry,
      kernel,
      audit,
      new FilesystemSubsystem(),
      new FailingLogGitSubsystem(),
      { transport: 'stdio' },
      terminal,
      procReg,
      new ApprovalStateManager(),
    );

    const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_repo_status', {
      workspaceId: 'ws-corrupt',
    });

    assert.equal(
      res.isError,
      true,
      'GitSubsystem failure during getLog must fail closed and NOT be swallowed',
    );
    const err = parseResponse(res);
    assert.equal(err.code, 'INTERNAL_ERROR');
    assert.ok(err.message.includes('Corrupted Git commit object database'));
  });
});
