/**
 * CesSpace ARC — RC-08 Task 4: Filesystem, Git & Workspace Adversarial Tests.
 *
 * Fixtures are confined to one temporary root. Production filesystem and Git
 * subsystems remain the security authorities; injectable filesystem operations
 * are used only to place deterministic races at documented commit boundaries.
 */

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  FilesystemSubsystem,
  NodeFilesystemOps,
  ProcessWideLockManager,
  computeSha256,
} from '../packages/filesystem/dist/index.js';
import {
  GitSubsystem,
  MAX_DIFF_BYTES,
  TRUSTED_GIT_LOCATIONS,
  resolveTrustedGitBinary,
} from '../packages/git/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { ALL_TOOL_DEFINITIONS, ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { createProductionDeterministicRegistry } from '../apps/mcp-server/dist/composite-framework.js';

let tempRoot;
let workspace;
let outside;
let filesystem;
let sequence = 0;

const actor = {
  clientId: 'rc08-task4-client',
  clientType: 'worker',
  sessionId: 'rc08-task4-session',
  deviceId: 'rc08-task4-device',
  authenticated: true,
};

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-task4-'));
  workspace = path.join(tempRoot, 'workspace');
  outside = path.join(tempRoot, 'outside');
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  filesystem = new FilesystemSubsystem();
});

after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

function runGit(args, cwd, env = {}) {
  return execFileSync(resolveTrustedGitBinary(), args, {
    cwd,
    encoding: 'utf8',
    env: {
      PATH: '/usr/bin:/bin:/usr/local/bin',
      HOME: '/dev/null',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      GIT_AUTHOR_NAME: 'RC08 Fixture',
      GIT_AUTHOR_EMAIL: 'rc08@example.invalid',
      GIT_COMMITTER_NAME: 'RC08 Fixture',
      GIT_COMMITTER_EMAIL: 'rc08@example.invalid',
      ...env,
    },
  }).trim();
}

function makeRepo(tag) {
  sequence += 1;
  const repo = path.join(tempRoot, `${tag}-${sequence}`);
  fs.mkdirSync(repo, { recursive: true });
  runGit(['init', '-b', 'main'], repo);
  return repo;
}

function commitAll(repo, message) {
  runGit(['add', '-A'], repo);
  runGit(['commit', '-m', message], repo);
}

function makeServer(root, workspaceId = 'workspace') {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace(workspaceId, root);
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    new AuditLogger(),
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'stdio',
      authorizedRoots: [{ id: workspaceId, path: root }],
      defaultWorkspaceId: workspaceId,
    },
    undefined,
    undefined,
    new ApprovalStateManager(),
  );
  return { server, workspaceId };
}

function parseToolResult(result) {
  assert.ok(result.content?.[0]?.text, 'tool response must contain bounded JSON text');
  return JSON.parse(result.content[0].text);
}

async function expectArcError(action, expectedCodes) {
  const codes = Array.isArray(expectedCodes) ? expectedCodes : [expectedCodes];
  try {
    await action();
    assert.fail(`expected one of ${codes.join(', ')}`);
  } catch (error) {
    assert.ok(error instanceof ArcError, `unexpected error: ${String(error)}`);
    assert.ok(codes.includes(error.code), `unexpected ArcError code ${error.code}`);
    return error;
  }
}

function assertSanitized(error, forbidden = []) {
  const serialized = JSON.stringify({
    code: error.code,
    message: error.message,
    details: error.details,
  });
  for (const value of [tempRoot, os.homedir(), os.userInfo().username, ...forbidden]) {
    if (value) assert.equal(serialized.includes(value), false, `error leaked ${value}`);
  }
}

function arcTemps(root) {
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.name.startsWith('.arc-tmp-')) found.push(full);
      if (entry.isDirectory() && entry.name !== '.git') visit(full);
    }
  };
  visit(root);
  return found;
}

function writeExecutable(file, marker, label) {
  fs.writeFileSync(file, `#!/bin/sh\nprintf '%s' '${label}' > '${marker}'\n`, { mode: 0o700 });
  fs.chmodSync(file, 0o700);
}

test('RC08-NEG-038: absolute symlink escape is rejected for read and mutation without outside disclosure', async () => {
  const secret = path.join(outside, 'absolute-secret.txt');
  const link = path.join(workspace, 'absolute-link.txt');
  fs.writeFileSync(secret, 'outside-absolute-sentinel');
  fs.symlinkSync(secret, link);

  const readError = await expectArcError(
    () => filesystem.readFile(workspace, { path: 'absolute-link.txt' }),
    ['PATH_ESCAPES_ROOT', 'PATH_OUTSIDE_WORKSPACE', 'SYMLINK_ESCAPE_DETECTED'],
  );
  assertSanitized(readError, ['outside-absolute-sentinel']);

  const mutationError = await expectArcError(
    () =>
      filesystem.writeFile(workspace, {
        path: 'absolute-link.txt',
        content: 'attacker replacement',
        expectedHash: computeSha256('outside-absolute-sentinel'),
        overwrite: true,
      }),
    'UNSAFE_SYMLINK',
  );
  assertSanitized(mutationError, ['outside-absolute-sentinel']);
  assert.equal(fs.readFileSync(secret, 'utf8'), 'outside-absolute-sentinel');
});

test('RC08-NEG-039: multi-hop relative symlink chain cannot read or mutate outside targets', async () => {
  const chainOutside = path.join(outside, 'relative-chain');
  fs.mkdirSync(path.join(chainOutside, 'nested'), { recursive: true });
  fs.writeFileSync(path.join(chainOutside, 'secret.txt'), 'relative-secret-sentinel');
  fs.writeFileSync(path.join(chainOutside, 'nested', 'info.txt'), 'nested-outside-sentinel');
  fs.symlinkSync('b', path.join(workspace, 'a'));
  fs.symlinkSync(path.relative(workspace, chainOutside), path.join(workspace, 'b'));

  for (const requestPath of ['a/secret.txt', 'a/./nested/info.txt']) {
    await expectArcError(
      () => filesystem.readFile(workspace, { path: requestPath }),
      ['PATH_ESCAPES_ROOT', 'PATH_OUTSIDE_WORKSPACE', 'SYMLINK_ESCAPE_DETECTED'],
    );
  }
  await expectArcError(
    () =>
      filesystem.writeFile(workspace, {
        path: 'a/secret.txt',
        content: 'must-not-land',
        expectedHash: computeSha256('relative-secret-sentinel'),
        overwrite: true,
      }),
    'UNSAFE_SYMLINK',
  );
  assert.equal(
    fs.readFileSync(path.join(chainOutside, 'secret.txt'), 'utf8'),
    'relative-secret-sentinel',
  );
  assert.equal(
    fs.readFileSync(path.join(chainOutside, 'nested', 'info.txt'), 'utf8'),
    'nested-outside-sentinel',
  );
});

test('RC08-NEG-040: deterministic target swap between capture and commit fails identity verification and cleans state', async () => {
  const raceDir = path.join(workspace, 'toctou');
  fs.mkdirSync(raceDir, { recursive: true });
  const target = path.join(raceDir, 'target.txt');
  const replacementTemp = path.join(raceDir, 'attacker-replacement.tmp');
  const outsideSentinel = path.join(outside, 'toctou-outside.txt');
  fs.writeFileSync(target, 'legitimate-original');
  fs.writeFileSync(outsideSentinel, 'outside-untouched');
  const expectedHash = computeSha256('legitimate-original');
  let replacementIdentity;
  let swapped = false;

  class DeterministicSwapOps extends NodeFilesystemOps {
    open(file, flags, mode) {
      if (!swapped && path.basename(file).startsWith('.arc-tmp-')) {
        fs.writeFileSync(replacementTemp, 'attacker-owned-replacement');
        replacementIdentity = fs.lstatSync(replacementTemp);
        fs.renameSync(replacementTemp, target);
        swapped = true;
      }
      return super.open(file, flags, mode);
    }
  }

  const locks = new ProcessWideLockManager();
  const raced = new FilesystemSubsystem(undefined, new DeterministicSwapOps(), locks);
  const error = await expectArcError(
    () =>
      raced.writeFile(raceDir, {
        path: 'target.txt',
        content: 'arc-must-not-commit',
        expectedHash,
        overwrite: true,
      }),
    'CONFLICT_PRECONDITION_FAILED',
  );

  assert.equal(swapped, true, 'the deterministic swap seam was not reached');
  const installed = fs.lstatSync(target);
  assert.equal(installed.dev, replacementIdentity.dev);
  assert.equal(installed.ino, replacementIdentity.ino);
  assert.equal(fs.readFileSync(target, 'utf8'), 'attacker-owned-replacement');
  assert.equal(fs.readFileSync(outsideSentinel, 'utf8'), 'outside-untouched');
  assert.equal(locks.activeLockCount, 0);
  assert.deepEqual(arcTemps(raceDir), []);
  assertSanitized(error, ['legitimate-original', 'attacker-owned-replacement']);
});

test('RC08-NEG-041: sensitive system-shaped paths are refused without content or host-path leakage', async () => {
  const controlled = [
    ['etc', 'shadow'],
    ['proc', 'kcore'],
    ['root', 'private.txt'],
    ['dev', 'device.txt'],
    ['sys', 'kernel.txt'],
    ['~/.ssh', 'id_rsa'],
  ];
  for (const [directory, file] of controlled) {
    const dir = path.join(workspace, directory);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, file), `controlled-${directory}-sentinel`);
  }

  const attempts = [
    '/etc/shadow',
    '/proc/kcore',
    '/root/private',
    '/dev/null',
    '/sys/kernel',
    'etc/shadow',
    'proc/kcore',
    'root/private.txt',
    'dev/device.txt',
    'sys/kernel.txt',
    '~/.ssh/id_rsa',
  ];
  for (const attemptedPath of attempts) {
    const error = await expectArcError(
      () => filesystem.readFile(workspace, { path: attemptedPath }),
      ['ACCESS_DENIED', 'PATH_ESCAPES_ROOT', 'PATH_OUTSIDE_WORKSPACE'],
    );
    assertSanitized(error, ['controlled-', attemptedPath]);
  }
});

test('RC08-NEG-042: NUL paths fail before read or mutation and never target the truncated prefix', async () => {
  const prefix = path.join(workspace, 'file.txt');
  fs.writeFileSync(prefix, 'nul-prefix-sentinel');
  const injected = 'file.txt\0.js';

  for (const action of [
    () => filesystem.readFile(workspace, { path: injected }),
    () => filesystem.createFile(workspace, { path: injected, content: 'must-not-create' }),
  ]) {
    const error = await expectArcError(action, 'INVALID_PATH_CHARS');
    assert.equal(error.message.includes('ERR_INVALID_ARG'), false);
    assertSanitized(error, ['nul-prefix-sentinel']);
  }
  assert.equal(fs.readFileSync(prefix, 'utf8'), 'nul-prefix-sentinel');
  assert.equal(fs.existsSync(path.join(workspace, 'file.txt.js')), false);
});

test('RC08-NEG-043: missing parents and restricted mutation targets leave no file, directory, or temp artifact', async () => {
  const missingParent = path.join(workspace, 'missing-parent');
  const missingError = await expectArcError(
    () =>
      filesystem.createFile(workspace, {
        path: 'missing-parent/child/file.txt',
        content: 'must-not-create',
      }),
    'PARENT_NOT_FOUND',
  );
  assertSanitized(missingError);
  assert.equal(fs.existsSync(missingParent), false);

  for (const restricted of ['.git/config.new', '.ssh/id_test', '.env.local']) {
    const error = await expectArcError(
      () => filesystem.createFile(workspace, { path: restricted, content: 'restricted' }),
      'ACCESS_DENIED',
    );
    assertSanitized(error);
    assert.equal(fs.existsSync(path.join(workspace, restricted)), false);
  }
  assert.deepEqual(arcTemps(workspace), []);
});

test('RC08-NEG-044: Git option injection is INVALID_GIT_ARGUMENT before any Git side effect', async () => {
  const repo = makeRepo('option-injection');
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'safe\n');
  commitAll(repo, 'initial');
  const marker = path.join(tempRoot, 'option-marker');
  const git = new GitSubsystem();
  const cases = [
    () => git.getDiff(repo, { target: `--output=${marker}` }),
    () => git.getDiff(repo, { path: '--upload-pack=attacker' }),
    () => git.getLog(repo, { revision: '-oInjected' }),
    () => git.getLog(repo, { revision: '--exec=attacker' }),
  ];
  for (const action of cases) await expectArcError(action, 'INVALID_GIT_ARGUMENT');

  const { server, workspaceId } = makeServer(repo, 'option-repo');
  const publicResult = await server.executeAuthenticatedToolCall(actor, 'arc_review_diff', {
    workspaceId,
    mode: 'target',
    targetRevision: `--output=${marker}`,
  });
  assert.equal(publicResult.isError, true);
  assert.equal(parseToolResult(publicResult).code, 'INVALID_GIT_ARGUMENT');
  assert.equal(fs.existsSync(marker), false);
});

test('RC08-NEG-045: shell-shaped Git arguments remain data and are rejected without expansion', async () => {
  const repo = makeRepo('shell-injection');
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'safe\n');
  commitAll(repo, 'initial');
  const marker = path.join(tempRoot, 'shell-marker');
  const git = new GitSubsystem();
  const values = [
    '$(whoami)',
    `$(touch ${marker})`,
    `\`touch ${marker}\``,
    `HEAD;touch ${marker}`,
    `HEAD|touch ${marker}`,
    `HEAD&&touch ${marker}`,
  ];
  for (const value of values) {
    await expectArcError(() => git.getDiff(repo, { target: value }), 'INVALID_GIT_ARGUMENT');
    await expectArcError(() => git.getLog(repo, { revision: value }), 'INVALID_GIT_ARGUMENT');
  }
  assert.equal(fs.existsSync(marker), false);
  assert.equal(fs.readFileSync(path.join(repo, 'safe.txt'), 'utf8'), 'safe\n');
});

test('RC08-NEG-046: mutating Git operations are unreachable through the exact 25-tool public catalog', async () => {
  const repo = makeRepo('readonly-catalog');
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'safe\n');
  commitAll(repo, 'initial');
  const { server } = makeServer(repo, 'readonly-repo');
  const names = ALL_TOOL_DEFINITIONS.map((tool) => tool.name);
  assert.equal(names.length, 25);
  assert.deepEqual(names.filter((name) => name.startsWith('git_')).sort(), [
    'git_diff',
    'git_log',
    'git_status',
  ]);

  const forbidden = [
    'git_commit',
    'git_push',
    'git_checkout',
    'git_reset',
    'git_config',
    'git_branch',
  ];
  const sdkServer = server.server;
  const callTool = sdkServer._requestHandlers.get('tools/call');
  assert.equal(typeof callTool, 'function');
  for (const name of forbidden) {
    await assert.rejects(
      () => callTool({ method: 'tools/call', params: { name, arguments: {} } }, {}),
      (error) => error?.code === -32601 && error?.name === 'McpError',
    );
  }
  assert.equal(runGit(['status', '--porcelain=v1'], repo), '');
});

test('RC08-NEG-047: staged sensitive renames are absent from whole-workspace and destination-filtered review responses', async () => {
  const repo = makeRepo('sensitive-renames');
  const renames = [
    ['.env', 'notes.txt', 'controlled-env-material'],
    ['id_rsa', 'harmless-name.txt', 'controlled-rsa-material'],
    ['secret.pem', 'ordinary.txt', 'controlled-pem-material'],
  ];
  for (const [source, , content] of renames)
    fs.writeFileSync(path.join(repo, source), `${content}\n`);
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'safe-before\n');
  commitAll(repo, 'initial sensitive fixtures');

  for (const [source, destination] of renames) {
    fs.renameSync(path.join(repo, source), path.join(repo, destination));
  }
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'safe-after-visible\n');
  runGit(['add', '-A'], repo);

  const { server, workspaceId } = makeServer(repo, 'rename-repo');
  const wholeResult = await server.executeAuthenticatedToolCall(actor, 'arc_review_diff', {
    workspaceId,
    mode: 'staged',
  });
  assert.equal(wholeResult.isError, undefined);
  const wholeText = wholeResult.content[0].text;
  const whole = parseToolResult(wholeResult);
  assert.ok(whole.diff.includes('safe-after-visible'));
  assert.ok(whole.fileSummaries.some((entry) => entry.path === 'safe.txt'));
  assert.ok(whole.sensitiveBlocksMasked >= 3);

  for (const [source, destination, content] of renames) {
    assert.equal(wholeText.includes(source), false);
    assert.equal(wholeText.includes(destination), false);
    assert.equal(wholeText.includes(content), false);

    const filteredResult = await server.executeAuthenticatedToolCall(actor, 'arc_review_diff', {
      workspaceId,
      mode: 'staged',
      path: destination,
    });
    assert.equal(filteredResult.isError, undefined);
    const filteredText = filteredResult.content[0].text;
    const filtered = parseToolResult(filteredResult);
    assert.equal(filteredText.includes(source), false);
    assert.equal(filteredText.includes(content), false);
    assert.equal(filtered.diff.includes(destination), false);
    assert.equal(
      filtered.fileSummaries.some((entry) => entry.path === destination),
      false,
    );
    assert.equal(filtered.totalFilesChanged, 0);
  }
});

test('RC08-NEG-048: malicious local and inherited Git helpers never execute under protected inspections', async () => {
  const repo = makeRepo('malicious-config');
  const markerDir = path.join(tempRoot, `markers-${sequence}`);
  const helperDir = path.join(tempRoot, `helpers-${sequence}`);
  const hookDir = path.join(repo, '.git', 'attacker-hooks');
  const evilHome = path.join(tempRoot, `evil-home-${sequence}`);
  const fakeBin = path.join(tempRoot, `fake-bin-${sequence}`);
  for (const directory of [markerDir, helperDir, hookDir, evilHome, fakeBin]) {
    fs.mkdirSync(directory, { recursive: true });
  }

  const helperKinds = ['external', 'textconv', 'command', 'fsmonitor', 'pager', 'hook', 'fake-git'];
  const markers = new Map();
  for (const kind of helperKinds) {
    const marker = path.join(markerDir, `${kind}.marker`);
    const executable =
      kind === 'hook' ? path.join(hookDir, 'post-checkout') : path.join(helperDir, kind);
    markers.set(kind, marker);
    writeExecutable(executable, marker, kind);
  }
  writeExecutable(path.join(fakeBin, 'git'), markers.get('fake-git'), 'fake-git');

  fs.writeFileSync(path.join(repo, '.gitattributes'), 'safe.txt diff=attack\n');
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'before\n');
  commitAll(repo, 'initial');
  runGit(['config', 'core.hooksPath', hookDir], repo);
  runGit(['config', 'diff.external', path.join(helperDir, 'external')], repo);
  runGit(['config', 'diff.attack.command', path.join(helperDir, 'command')], repo);
  runGit(['config', 'diff.attack.textconv', path.join(helperDir, 'textconv')], repo);
  runGit(['config', 'core.fsmonitor', path.join(helperDir, 'fsmonitor')], repo);
  runGit(['config', 'core.pager', path.join(helperDir, 'pager')], repo);
  fs.writeFileSync(
    path.join(evilHome, '.gitconfig'),
    `[diff]\n\texternal = ${path.join(helperDir, 'external')}\n[core]\n\tfsmonitor = ${path.join(helperDir, 'fsmonitor')}\n`,
  );
  fs.writeFileSync(path.join(repo, 'safe.txt'), 'after-visible\n');

  const before = {
    head: fs.readFileSync(path.join(repo, '.git', 'HEAD')),
    index: fs.readFileSync(path.join(repo, '.git', 'index')),
    worktree: fs.readFileSync(path.join(repo, 'safe.txt')),
  };
  const originalPath = process.env.PATH;
  const originalHome = process.env.HOME;
  try {
    process.env.PATH = `${fakeBin}:${originalPath ?? ''}`;
    process.env.HOME = evilHome;
    const git = new GitSubsystem();
    const trusted = resolveTrustedGitBinary();
    assert.ok(TRUSTED_GIT_LOCATIONS.includes(trusted) || trusted.startsWith('/usr/bin/'));
    const status = await git.getStatus(repo, {});
    const diff = await git.getDiff(repo, {});
    const log = await git.getLog(repo, { maxCount: 5 });
    const review = await git.getReviewDiff(repo, { mode: 'unstaged', maxBytes: MAX_DIFF_BYTES });
    assert.equal(status.branch, 'main');
    assert.ok(diff.diff.includes('after-visible'));
    assert.ok(log.commits.length >= 1);
    assert.ok(review.diff.includes('after-visible'));
  } finally {
    process.env.PATH = originalPath;
    process.env.HOME = originalHome;
  }

  for (const [kind, marker] of markers) {
    assert.equal(fs.existsSync(marker), false, `${kind} executed`);
  }
  assert.deepEqual(fs.readFileSync(path.join(repo, '.git', 'HEAD')), before.head);
  assert.deepEqual(fs.readFileSync(path.join(repo, '.git', 'index')), before.index);
  assert.deepEqual(fs.readFileSync(path.join(repo, 'safe.txt')), before.worktree);
  assert.equal(fs.existsSync(path.join(repo, '.git', 'index.lock')), false);
});

test('RC08-FLOW-09: canonical read and list traverse internal symlinks while external links and mutation traversal remain blocked', async () => {
  const flowRoot = path.join(workspace, 'flow09');
  const realDir = path.join(flowRoot, 'nested', 'real');
  fs.mkdirSync(realDir, { recursive: true });
  fs.writeFileSync(path.join(realDir, 'inside.txt'), 'canonical-inside-content');
  fs.symlinkSync('nested/real', path.join(flowRoot, 'internal-link'));
  const externalFile = path.join(outside, 'flow09-external.txt');
  fs.writeFileSync(externalFile, 'external-must-stay-hidden');
  fs.symlinkSync(externalFile, path.join(flowRoot, 'external-link'));

  const read = await filesystem.readFile(flowRoot, { path: 'internal-link/inside.txt' });
  assert.equal(read.content, 'canonical-inside-content');
  const listing = await filesystem.listDirectory(flowRoot, {
    path: 'internal-link',
    recursive: true,
    maxDepth: 2,
  });
  assert.ok(listing.entries.some((entry) => entry.name === 'inside.txt'));
  const resolved = await filesystem.resolveSecurePath(flowRoot, 'internal-link/inside.txt');
  assert.ok(resolved.startsWith(fs.realpathSync(flowRoot) + path.sep));

  await expectArcError(
    () => filesystem.readFile(flowRoot, { path: 'external-link' }),
    ['PATH_ESCAPES_ROOT', 'PATH_OUTSIDE_WORKSPACE', 'SYMLINK_ESCAPE_DETECTED'],
  );
  await expectArcError(
    () =>
      filesystem.writeFile(flowRoot, {
        path: 'internal-link/inside.txt',
        content: 'mutation-must-not-follow-link',
        expectedHash: computeSha256('canonical-inside-content'),
        overwrite: true,
      }),
    'UNSAFE_SYMLINK',
  );
  assert.equal(fs.readFileSync(externalFile, 'utf8'), 'external-must-stay-hidden');
});

test('RC08-FLOW-10: protected public Git inspection is structured, redacted, bounded, and read-only', async () => {
  const repo = makeRepo('protected-workflow');
  const marker = path.join(tempRoot, `flow10-helper-${sequence}.marker`);
  const helper = path.join(tempRoot, `flow10-helper-${sequence}`);
  writeExecutable(helper, marker, 'flow10-helper');

  fs.writeFileSync(path.join(repo, 'tracked.txt'), 'commit-one\n');
  fs.writeFileSync(path.join(repo, 'unstaged.txt'), 'base\n');
  fs.writeFileSync(path.join(repo, 'delete-me.txt'), 'delete later\n');
  fs.writeFileSync(path.join(repo, '.env'), 'FLOW10_CONTROLLED_SECRET\n');
  commitAll(repo, 'first commit');
  fs.writeFileSync(path.join(repo, 'history.txt'), 'second commit\n');
  commitAll(repo, 'second commit');

  fs.writeFileSync(path.join(repo, 'tracked.txt'), 'staged-safe-change\n');
  fs.rmSync(path.join(repo, 'delete-me.txt'));
  runGit(['add', 'tracked.txt', 'delete-me.txt'], repo);
  fs.writeFileSync(path.join(repo, 'unstaged.txt'), 'unstaged-safe-change\n');
  fs.writeFileSync(path.join(repo, '.env'), 'FLOW10_SECRET_MUST_NOT_APPEAR\n');
  runGit(['config', 'diff.external', helper], repo);

  const before = {
    head: fs.readFileSync(path.join(repo, '.git', 'HEAD')),
    index: fs.readFileSync(path.join(repo, '.git', 'index')),
    tracked: fs.readFileSync(path.join(repo, 'tracked.txt')),
    unstaged: fs.readFileSync(path.join(repo, 'unstaged.txt')),
    sensitive: fs.readFileSync(path.join(repo, '.env')),
  };
  const { server, workspaceId } = makeServer(repo, 'flow10-repo');
  const statusResult = await server.executeAuthenticatedToolCall(actor, 'git_status', {
    workspaceId,
  });
  const logResult = await server.executeAuthenticatedToolCall(actor, 'git_log', {
    workspaceId,
    maxCount: 10,
  });
  const stagedResult = await server.executeAuthenticatedToolCall(actor, 'git_diff', {
    workspaceId,
    cached: true,
  });
  const unstagedResult = await server.executeAuthenticatedToolCall(actor, 'git_diff', {
    workspaceId,
  });
  const reviewResult = await server.executeAuthenticatedToolCall(actor, 'arc_review_diff', {
    workspaceId,
    mode: 'unstaged',
  });

  for (const result of [statusResult, logResult, stagedResult, unstagedResult, reviewResult]) {
    assert.equal(result.isError, undefined, result.content?.[0]?.text);
    assert.ok(Buffer.byteLength(result.content[0].text, 'utf8') <= 524_288);
    assert.equal(result.content[0].text.includes('FLOW10_SECRET_MUST_NOT_APPEAR'), false);
    assert.equal(result.content[0].text.includes('.env'), false);
  }
  const status = parseToolResult(statusResult);
  assert.equal(status.branch, 'main');
  assert.ok(status.stagedFiles.includes('tracked.txt'));
  assert.ok(status.stagedFiles.includes('delete-me.txt'));
  assert.ok(status.unstagedFiles.includes('unstaged.txt'));
  const log = parseToolResult(logResult);
  assert.ok(log.commits.length >= 2);
  assert.ok(parseToolResult(stagedResult).diff.includes('staged-safe-change'));
  assert.ok(parseToolResult(unstagedResult).diff.includes('unstaged-safe-change'));
  assert.ok(parseToolResult(reviewResult).diff.includes('unstaged-safe-change'));

  assert.deepEqual(fs.readFileSync(path.join(repo, '.git', 'HEAD')), before.head);
  assert.deepEqual(fs.readFileSync(path.join(repo, '.git', 'index')), before.index);
  assert.deepEqual(fs.readFileSync(path.join(repo, 'tracked.txt')), before.tracked);
  assert.deepEqual(fs.readFileSync(path.join(repo, 'unstaged.txt')), before.unstaged);
  assert.deepEqual(fs.readFileSync(path.join(repo, '.env')), before.sensitive);
  assert.equal(fs.existsSync(path.join(repo, '.git', 'index.lock')), false);
  assert.equal(fs.existsSync(marker), false);

  assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
  assert.equal(createProductionDeterministicRegistry().listEntryIds().length, 5);
  const health = parseToolResult(await server.executeAuthenticatedToolCall(actor, 'health', {}));
  assert.equal(health.version, '0.7.0-rc07');
  assert.equal(health.stage, 'RC-07');
});
