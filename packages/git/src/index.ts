import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { realpathSync, existsSync, lstatSync, readFileSync } from 'node:fs';
import { resolve, sep, dirname } from 'node:path';
import {
  ArcError,
  type GitStatusRequest,
  type GitStatusResponse,
  type GitDiffRequest,
  type GitDiffResponse,
  type GitLogRequest,
  type GitLogResponse,
  type GitCommitItem,
} from '@cesspace-arc/protocol';

const execFileAsync = promisify(execFile);

/**
 * Maximum diff payload size: 512 KiB (524,288 bytes).
 */
export const MAX_DIFF_BYTES = 512 * 1024;

/**
 * Safe bounded raw diff capture ceiling: 4 MiB.
 * Large enough to handle multi-MiB diffs while bounding subprocess memory.
 * If this ceiling is exceeded, a safe truncation marker is substituted.
 */
export const RAW_DIFF_CAPTURE_BYTES = 4 * 1024 * 1024;

/**
 * Placeholder emitted when the raw diff exceeds the capture ceiling.
 * The overall response still succeeds with truncated === true.
 */
const RAW_DIFF_OVERFLOW_MARKER =
  '[DIFF TOO LARGE TO CAPTURE — raw output exceeded safe intermediate buffer limit; showing file summaries only]';

/**
 * Maximum git_log commit count: 100.
 */
export const MAX_LOG_COUNT = 100;

/**
 * Protected branches that cannot be directly mutated.
 */
export const PROTECTED_BRANCHES = ['main', 'master', 'release/*'];

/**
 * Checks whether a branch matches any protected branch pattern.
 */
export function isProtectedBranch(branch: string): boolean {
  if (!branch) {
    return false;
  }
  const normalized = branch.replace(/^refs\/heads\//, '').trim();
  for (const protectedPattern of PROTECTED_BRANCHES) {
    if (protectedPattern.endsWith('/*')) {
      const prefix = protectedPattern.slice(0, -2);
      if (normalized === prefix || normalized.startsWith(prefix + '/')) {
        return true;
      }
    } else if (normalized === protectedPattern) {
      return true;
    }
  }
  return false;
}

/**
 * Validates that a git parameter (target, revision, or path) is not an option flag.
 */
export function validateGitArgument(paramName: string, value: string | undefined): void {
  if (!value) {
    return;
  }
  const trimmed = value.trim();
  if (trimmed.startsWith('-')) {
    throw ArcError.invalidRequestSchema(
      `Parameter '${paramName}' must not begin with '-' (option flag injection prevention).`,
      'Provide a valid revision name or path without leading dashes.',
    );
  }
  // Disallow shell metacharacters
  if (/[;&|`$><]/.test(trimmed)) {
    throw ArcError.invalidRequestSchema(`Parameter '${paramName}' contains forbidden characters.`);
  }
}

/**
 * Mask sensitive tokens and private-key PEM blocks in diff output.
 */
export function maskSensitiveDiff(diff: string): string {
  return maskSensitiveDiffWithCount(diff).diff;
}

/**
 * Mask sensitive tokens and private-key PEM blocks in diff output,
 * returning the sanitized diff and the count of masked blocks/tokens.
 */
export function maskSensitiveDiffWithCount(diff: string): { diff: string; maskedCount: number } {
  let maskedCount = 0;

  // 1. Mask private key blocks (RSA, EC, OPENSSH, PGP, PKCS, DSA, etc.)
  // Matches both bare key blocks and git diff hunks with leading +/- markers
  const privateKeyPattern =
    /(?:^[+-]?\s*)?-----BEGIN\s+(?:[A-Z0-9_ -]+\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+(?:[A-Z0-9_ -]+\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/gm;
  let masked = diff.replace(privateKeyPattern, () => {
    maskedCount++;
    return '[REDACTED_SECRET]';
  });

  // 2. Mask sensitive API tokens, secret keys, and Bearer credentials
  const tokenPattern =
    /(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|sk-[a-zA-Z0-9_-]{20,}|Bearer\s+[a-zA-Z0-9._-]+)/g;
  masked = masked.replace(tokenPattern, () => {
    maskedCount++;
    return '[REDACTED_SECRET]';
  });

  return { diff: masked, maskedCount };
}

/**
 * Checks if a path is considered sensitive and forbidden from git inspection.
 */
export function isSensitiveGitPath(filePath: string): boolean {
  const sensitivePatterns = [
    /(^|[/\\])\.env($|\..*)/i,
    /(^|[/\\])\.ssh([/\\]|$)/i,
    /(^|[/\\])\.aws([/\\]|$)/i,
    /(^|[/\\])\.gnupg([/\\]|$)/i,
    /(^|[/\\])\.kube([/\\]|$)/i,
    /(^|[/\\])\.git[/\\]config$/i,
    /(^|[/\\])\.git[/\\]hooks([/\\]|$)/i,
    /(^|[/\\])id_rsa/i,
    /(^|[/\\])id_ed25519/i,
    /\.(pem|key|p12|pfx)$/i,
  ];
  return sensitivePatterns.some((pattern) => pattern.test(filePath));
}

/**
 * Purges file diff hunks belonging to sensitive files (even if tracked in git).
 * @param diff - raw diff string
 * @param extraSensitivePaths - optional additional paths to suppress (e.g. rename origins)
 */
export function purgeSensitiveDiffBlocks(diff: string, extraSensitivePaths?: Set<string>): string {
  return purgeSensitiveDiffBlocksWithCount(diff, extraSensitivePaths).diff;
}

/**
 * Purges file diff hunks belonging to sensitive files (even if tracked in git),
 * returning the sanitized diff and the count of suppressed file hunks.
 *
 * Accepts an optional set of extra sensitive paths (e.g. rename/copy origins
 * detected from a full --name-status pass without pathspec excludes) so that
 * renames involving sensitive paths are suppressed even when Git pathspec excludes
 * already hid the sensitive side, potentially presenting only the non-sensitive side.
 */
export function purgeSensitiveDiffBlocksWithCount(
  diff: string,
  extraSensitivePaths?: Set<string>,
): {
  diff: string;
  suppressedCount: number;
} {
  const sensitivePatterns = [
    /(^|[/\\])\.env($|\..*)/i,
    /(^|[/\\])\.ssh([/\\]|$)/i,
    /(^|[/\\])\.aws([/\\]|$)/i,
    /(^|[/\\])\.gnupg([/\\]|$)/i,
    /(^|[/\\])\.kube([/\\]|$)/i,
    /(^|[/\\])\.git[/\\]config$/i,
    /(^|[/\\])\.git[/\\]hooks([/\\]|$)/i,
    /(^|[/\\])id_rsa/i,
    /(^|[/\\])id_ed25519/i,
    /\.(pem|key|p12|pfx)$/i,
  ];

  const blocks = diff.split(/(?=diff --git )/);
  const sanitizedBlocks: string[] = [];
  let suppressedCount = 0;

  for (const block of blocks) {
    if (!block.startsWith('diff --git ')) {
      sanitizedBlocks.push(block);
      continue;
    }

    const firstLine = block.split('\n', 1)[0];
    let isSensitive = false;

    // 1. Extract paths from diff --git a/<pathA> b/<pathB>
    const rest = firstLine.slice('diff --git '.length);
    const bIndex = rest.lastIndexOf(' b/');
    if (bIndex > 2 && rest.startsWith('a/')) {
      const pathA = rest.slice(2, bIndex);
      const pathB = rest.slice(bIndex + 3);
      if (isSensitiveGitPath(pathA) || isSensitiveGitPath(pathB)) {
        isSensitive = true;
      }
      if (!isSensitive && extraSensitivePaths && extraSensitivePaths.size > 0) {
        if (extraSensitivePaths.has(pathA) || extraSensitivePaths.has(pathB)) {
          isSensitive = true;
        }
      }
    }

    // 2. Fallback pattern match against first line
    if (!isSensitive) {
      isSensitive = sensitivePatterns.some((pattern) => pattern.test(firstLine));
    }

    // 3. Check rename headers in block
    if (!isSensitive) {
      const headerLines = block.split('\n').slice(0, 10);
      for (const hLine of headerLines) {
        if (hLine.startsWith('---') || hLine.startsWith('+++') || hLine.startsWith('@@')) {
          break;
        }
        if (hLine.startsWith('rename from ')) {
          const p = hLine.slice(12).trim();
          if (isSensitiveGitPath(p) || (extraSensitivePaths && extraSensitivePaths.has(p))) {
            isSensitive = true;
            break;
          }
        } else if (hLine.startsWith('rename to ')) {
          const p = hLine.slice(10).trim();
          if (isSensitiveGitPath(p) || (extraSensitivePaths && extraSensitivePaths.has(p))) {
            isSensitive = true;
            break;
          }
        }
      }
    }

    // 4. Check extraSensitivePaths substring match in first line
    if (!isSensitive && extraSensitivePaths && extraSensitivePaths.size > 0) {
      for (const sensPath of extraSensitivePaths) {
        if (firstLine.includes(sensPath)) {
          isSensitive = true;
          break;
        }
      }
    }

    if (isSensitive) {
      suppressedCount++;
      // Completely drop the sensitive hunk so no sensitive filename or content is emitted
    } else {
      sanitizedBlocks.push(block);
    }
  }

  return {
    diff: sanitizedBlocks.join(''),
    suppressedCount,
  };
}
export function truncateUtf8ToByteLimit(
  str: string,
  maxBytes: number,
): { text: string; truncated: boolean } {
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) {
    return { text: str, truncated: false };
  }

  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }

  if (end > 0) {
    const lead = buf[end];
    let charLen = 1;
    if ((lead & 0xe0) === 0xc0) charLen = 2;
    else if ((lead & 0xf0) === 0xe0) charLen = 3;
    else if ((lead & 0xf8) === 0xf0) charLen = 4;

    if (end + charLen <= maxBytes) {
      end += charLen;
    }
  }

  return {
    text: buf.subarray(0, end).toString('utf8'),
    truncated: true,
  };
}

/**
 * Trusted system locations for the Git binary in supported Linux environments.
 * Fixed deterministic paths that cannot resolve into user-controlled directories,
 * workspace paths, or HOME.
 */
export const TRUSTED_GIT_LOCATIONS = ['/usr/bin/git', '/bin/git', '/usr/local/bin/git'] as const;

/**
 * Fixed trusted system PATH for subprocess execution.
 * Prevents execution of user-controlled binaries from workspace, cwd, or HOME.
 */
export const TRUSTED_SYSTEM_PATH = '/usr/bin:/bin:/usr/local/bin';

/**
 * Resolves a trusted system Git executable without using a shell or inherited PATH.
 */
export function resolveTrustedGitBinary(): string {
  for (const candidate of TRUSTED_GIT_LOCATIONS) {
    if (existsSync(candidate)) {
      try {
        const canonical = realpathSync(candidate);
        // Verify canonical path resides strictly in an approved system binary directory
        if (
          canonical === '/usr/bin/git' ||
          canonical === '/bin/git' ||
          canonical === '/usr/local/bin/git' ||
          canonical.startsWith('/usr/bin/') ||
          canonical.startsWith('/bin/')
        ) {
          return canonical;
        }
      } catch {
        // continue
      }
    }
  }
  throw ArcError.internalError(
    'Trusted system Git executable not found in approved system locations.',
  );
}

/**
 * Bounded worktree metadata for isolated agent environments.
 */
export interface WorktreeMetadata {
  isWorktree: boolean;
  worktreePath: string;
  mainRepoPath: string;
  branch: string;
  locked: boolean;
  lockReason?: string;
  isDetached: boolean;
  headSha: string;
}

/**
 * Options for Sandboxed Git Subsystem execution, supporting cancellation and deadlines.
 */
export interface GitExecutionOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface GitReviewDiffOptions {
  mode: 'staged' | 'unstaged' | 'target';
  targetRevision?: string;
  path?: string;
  maxBytes?: number;
}

export interface GitReviewDiffFileSummary {
  path: string;
  status: 'modified' | 'added' | 'deleted' | 'renamed';
  insertions: number;
  deletions: number;
}

export interface GitReviewDiffResult {
  diff: string;
  truncated: boolean;
  totalFilesChanged: number;
  fileSummaries: GitReviewDiffFileSummary[];
  sensitiveBlocksMasked: number;
}

/**
 * Interface definition for Sandboxed Git Subsystem.
 */
export interface IGitSubsystem {
  getStatus(
    workspaceRoot: string,
    request?: GitStatusRequest,
    options?: GitExecutionOptions,
  ): Promise<GitStatusResponse>;
  getDiff(
    workspaceRoot: string,
    request: GitDiffRequest,
    options?: GitExecutionOptions,
  ): Promise<GitDiffResponse>;
  getLog(
    workspaceRoot: string,
    request: GitLogRequest,
    options?: GitExecutionOptions,
  ): Promise<GitLogResponse>;
  assertBranchWritable(workspaceRoot: string, targetBranch: string): Promise<void>;
  getWorktreeMetadata(
    workspaceRoot: string,
    options?: GitExecutionOptions,
  ): Promise<WorktreeMetadata>;
  getReviewDiff(
    workspaceRoot: string,
    options: GitReviewDiffOptions,
    execOptions?: GitExecutionOptions,
  ): Promise<GitReviewDiffResult>;
}

/**
 * Sandboxed Git Subsystem implementation.
 * Guarantees read-only subprocess invocation via argument arrays, shell=false,
 * and a trusted system Git executable.
 */
export class GitSubsystem implements IGitSubsystem {
  private readonly trustedGitBinary: string;

  constructor(customGitBinary?: string) {
    this.trustedGitBinary = customGitBinary || resolveTrustedGitBinary();
  }

  private async runRawGit(
    cwd: string,
    args: string[],
    maxBuffer: number = 1024 * 1024,
    options?: GitExecutionOptions,
  ): Promise<{ stdout: string; stderr: string }> {
    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const safeEnv: NodeJS.ProcessEnv = {
      PATH: TRUSTED_SYSTEM_PATH,
      HOME: '/dev/null',
      LC_ALL: 'C',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
      GIT_EXTERNAL_DIFF: '',
      GIT_DIFF_OPTS: '',
      GIT_PAGER: 'cat',
      PAGER: 'cat',
      GIT_SSH_COMMAND: '',
      GIT_ASKPASS: '',
      SSH_ASKPASS: '',
    };

    const safeGlobalArgs = [
      '-c',
      'core.hooksPath=/dev/null',
      '-c',
      'diff.external=',
      '-c',
      'diff.textconv=',
      '-c',
      'core.fsmonitor=false',
    ];

    try {
      const result = await execFileAsync(this.trustedGitBinary, [...safeGlobalArgs, ...args], {
        cwd,
        shell: false,
        timeout: options?.timeoutMs ?? 10000,
        maxBuffer,
        env: safeEnv,
        signal: options?.signal,
      });
      return { stdout: result.stdout, stderr: result.stderr };
    } catch (err: unknown) {
      if (options?.signal?.aborted) {
        throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
      }
      const execErr = err as {
        code?: string | number;
        name?: string;
        message?: string;
        stderr?: string;
        killed?: boolean;
        signal?: string;
      };
      if (execErr.name === 'AbortError' || execErr.code === 'ABORT_ERR') {
        throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
      }
      if (execErr.code === 'ETIMEDOUT' || (execErr.killed && execErr.signal === 'SIGTERM')) {
        throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
      }
      if (execErr.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
        throw ArcError.payloadTooLarge('Git command output exceeded maximum buffer limit.');
      }
      throw ArcError.internalError('Git command execution failed.');
    }
  }

  private async verifyRepositoryBoundary(
    canonicalRoot: string,
    options?: GitExecutionOptions,
  ): Promise<void> {
    const dotGit = resolve(canonicalRoot, '.git');
    const isGit = existsSync(dotGit) || existsSync(resolve(canonicalRoot, 'HEAD'));

    if (!isGit) {
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }

    if (existsSync(dotGit)) {
      const dotGitStat = lstatSync(dotGit);
      if (dotGitStat.isSymbolicLink()) {
        let symlinkTarget: string;
        try {
          symlinkTarget = realpathSync(dotGit);
        } catch {
          throw ArcError.symlinkEscapeDetected(
            'Symlinked .git metadata resolves outside authorized workspace boundary.',
          );
        }
        if (symlinkTarget !== canonicalRoot && !symlinkTarget.startsWith(canonicalRoot + sep)) {
          throw ArcError.symlinkEscapeDetected(
            'Symlinked .git metadata resolves outside authorized workspace boundary.',
          );
        }
      }
    }

    try {
      const { stdout } = await this.runRawGit(
        canonicalRoot,
        ['rev-parse', '--show-toplevel', '--git-dir', '--git-common-dir'],
        undefined,
        options,
      );
      const lines = stdout
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0);

      if (lines.length < 3) {
        throw ArcError.accessDenied('Git repository topology could not be verified.');
      }

      const [topLevelRaw, gitDirRaw, gitCommonDirRaw] = lines;

      let resolvedTopLevel = '';
      try {
        resolvedTopLevel = realpathSync(resolve(canonicalRoot, topLevelRaw));
      } catch {
        throw ArcError.accessDenied('Git repository toplevel path could not be resolved.');
      }

      if (resolvedTopLevel !== canonicalRoot) {
        throw ArcError.accessDenied(
          'Git repository toplevel does not match canonical authorized workspace root.',
        );
      }

      let resolvedGitDir = '';
      try {
        resolvedGitDir = realpathSync(resolve(canonicalRoot, gitDirRaw));
      } catch {
        throw ArcError.accessDenied('Git directory path could not be resolved.');
      }

      let resolvedGitCommonDir = '';
      try {
        resolvedGitCommonDir = realpathSync(resolve(canonicalRoot, gitCommonDirRaw));
      } catch {
        throw ArcError.accessDenied('Git common directory path could not be resolved.');
      }

      // Check if this is a verified linked worktree
      let isLinkedWorktree = false;
      if (existsSync(dotGit)) {
        const dotGitStat = lstatSync(dotGit);
        if (dotGitStat.isFile()) {
          const dotGitContent = readFileSync(dotGit, 'utf8').trim();
          if (dotGitContent.startsWith('gitdir:')) {
            const rawWorktreeGitDir = dotGitContent.slice(7).trim();
            let resolvedWtGitDir = '';
            try {
              resolvedWtGitDir = realpathSync(resolve(canonicalRoot, rawWorktreeGitDir));
            } catch {
              // ignore
            }
            if (resolvedWtGitDir && resolvedWtGitDir === resolvedGitDir) {
              const backlinkFile = resolve(resolvedGitDir, 'gitdir');
              if (existsSync(backlinkFile)) {
                const backlink = readFileSync(backlinkFile, 'utf8').trim();
                let resolvedBacklink = '';
                try {
                  resolvedBacklink = realpathSync(resolve(resolvedGitDir, backlink));
                } catch {
                  // ignore
                }
                if (resolvedBacklink === realpathSync(dotGit)) {
                  isLinkedWorktree = true;
                }
              }
            }
          }
        }
      }

      if (!isLinkedWorktree) {
        if (resolvedGitDir !== canonicalRoot && !resolvedGitDir.startsWith(canonicalRoot + sep)) {
          throw ArcError.accessDenied('Git directory is outside authorized workspace boundary.');
        }

        if (
          resolvedGitCommonDir !== canonicalRoot &&
          !resolvedGitCommonDir.startsWith(canonicalRoot + sep)
        ) {
          throw ArcError.accessDenied(
            'Git common directory is outside authorized workspace boundary.',
          );
        }
      }
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        throw err;
      }
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }
  }

  private async runGit(
    workspaceRoot: string,
    args: string[],
    maxBuffer: number = 1024 * 1024,
    options?: GitExecutionOptions,
  ): Promise<{ stdout: string; stderr: string }> {
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.fileNotFound('Workspace directory not found.');
    }
    await this.verifyRepositoryBoundary(canonicalRoot, options);
    return this.runRawGit(canonicalRoot, args, maxBuffer, options);
  }

  public async getStatus(
    workspaceRoot: string,
    _request?: GitStatusRequest,
    options?: GitExecutionOptions,
  ): Promise<GitStatusResponse> {
    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }
    // Non-bypassable: execution subsystems MUST receive only the canonical workspace root
    // Caller parameters must never override the execution root after policy authorization.
    const targetRoot = workspaceRoot;

    // Get current branch
    let branch = 'unknown';
    try {
      const branchRes = await this.runGit(
        targetRoot,
        ['rev-parse', '--abbrev-ref', 'HEAD'],
        undefined,
        options,
      );
      branch = branchRes.stdout.trim();
    } catch (err: unknown) {
      if (
        err instanceof ArcError &&
        (err.code === 'EXECUTION_TIMEOUT' || err.code === 'PAYLOAD_TOO_LARGE')
      ) {
        throw err;
      }
      // Empty repo or detached HEAD
    }

    // Get commit hash
    let commitHash = 'unknown';
    try {
      const commitRes = await this.runGit(targetRoot, ['rev-parse', 'HEAD'], undefined, options);
      commitHash = commitRes.stdout.trim();
    } catch (err: unknown) {
      if (
        err instanceof ArcError &&
        (err.code === 'EXECUTION_TIMEOUT' || err.code === 'PAYLOAD_TOO_LARGE')
      ) {
        throw err;
      }
      // Empty repo
    }

    // Status porcelain
    const statusRes = await this.runGit(
      targetRoot,
      ['status', '--porcelain=v1', '-uall'],
      undefined,
      options,
    );

    const lines = statusRes.stdout.split('\n').filter((l) => l.length > 0);

    const stagedFiles: string[] = [];
    const unstagedFiles: string[] = [];
    const untrackedFiles: string[] = [];

    for (const line of lines) {
      const indexStatus = line[0];
      const workTreeStatus = line[1];
      const filePath = line.substring(3).trim();

      // Filter out blacklisted/sensitive file paths
      if (isSensitiveGitPath(filePath)) {
        continue;
      }

      if (indexStatus === '?' && workTreeStatus === '?') {
        untrackedFiles.push(filePath);
      } else {
        if (indexStatus !== ' ' && indexStatus !== '?') {
          stagedFiles.push(filePath);
        }
        if (workTreeStatus !== ' ' && workTreeStatus !== '?') {
          unstagedFiles.push(filePath);
        }
      }
    }

    const isClean =
      stagedFiles.length === 0 && unstagedFiles.length === 0 && untrackedFiles.length === 0;

    return {
      branch,
      commitHash,
      isClean,
      stagedFiles,
      unstagedFiles,
      untrackedFiles,
    };
  }

  public async getDiff(
    workspaceRoot: string,
    request: GitDiffRequest,
    options?: GitExecutionOptions,
  ): Promise<GitDiffResponse> {
    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }
    validateGitArgument('target', request.target);
    validateGitArgument('path', request.path);

    if (request.path && isSensitiveGitPath(request.path)) {
      throw ArcError.accessDenied(
        'Target diff path matches sensitive credential or system blacklist pattern.',
      );
    }

    // Git hardening: disable external diff helpers, textconv, and hooks
    const args = ['diff', '--no-ext-diff', '--no-textconv'];

    if (request.cached) {
      args.push('--cached');
    }

    if (request.target) {
      args.push(request.target.trim());
    }

    // Negative pathspecs to exclude sensitive secrets from diff
    const secretExcludes = [
      ':(exclude)*.env*',
      ':(exclude)*.pem',
      ':(exclude)*.key',
      ':(exclude)*.p12',
      ':(exclude)*.pfx',
      ':(exclude)*id_rsa*',
      ':(exclude)*id_ed25519*',
      ':(exclude).ssh/**',
      ':(exclude).aws/**',
      ':(exclude).gnupg/**',
      ':(exclude).kube/**',
    ];

    if (request.path) {
      args.push('--', request.path.trim(), ...secretExcludes);
    } else {
      args.push('--', '.', ...secretExcludes);
    }

    const { stdout } = await this.runGit(workspaceRoot, args, MAX_DIFF_BYTES * 2, options);

    // Defense-in-depth: purge any diff hunks mentioning sensitive files
    let diffText = purgeSensitiveDiffBlocks(stdout);
    diffText = maskSensitiveDiff(diffText);

    // Enforce safe byte-level UTF-8 truncation without splitting multi-byte characters
    const { text, truncated } = truncateUtf8ToByteLimit(diffText, MAX_DIFF_BYTES);

    return {
      diff: text,
      truncated,
    };
  }

  public async getLog(
    workspaceRoot: string,
    request: GitLogRequest,
    options?: GitExecutionOptions,
  ): Promise<GitLogResponse> {
    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }
    validateGitArgument('revision', request.revision);
    validateGitArgument('path', request.path);

    const maxCount = request.maxCount !== undefined ? request.maxCount : 10;
    if (typeof maxCount !== 'number' || maxCount < 1 || maxCount > MAX_LOG_COUNT) {
      throw ArcError.invalidRequestSchema(
        `maxCount must be an integer between 1 and ${MAX_LOG_COUNT}.`,
      );
    }

    const format = '%H%x1f%an <%ae>%x1f%aI%x1f%s';
    const args = ['log', `-n`, String(maxCount), `--format=${format}`];

    if (request.revision) {
      args.push(request.revision.trim());
    }

    if (request.path) {
      args.push('--', request.path.trim());
    }

    const { stdout } = await this.runGit(workspaceRoot, args, undefined, options);
    const lines = stdout.split('\n').filter((l) => l.trim().length > 0);

    const commits: GitCommitItem[] = [];

    for (const line of lines) {
      const parts = line.split('\x1f');
      if (parts.length >= 4) {
        commits.push({
          hash: parts[0],
          author: parts[1],
          date: parts[2],
          message: parts[3],
        });
      }
    }

    return {
      commits,
    };
  }

  public async assertBranchWritable(_workspaceRoot: string, targetBranch: string): Promise<void> {
    validateGitArgument('targetBranch', targetBranch);
    const branch = targetBranch.replace(/^refs\/heads\//, '');

    for (const protectedPattern of PROTECTED_BRANCHES) {
      if (protectedPattern.endsWith('/*')) {
        const prefix = protectedPattern.slice(0, -2);
        if (branch.startsWith(prefix)) {
          throw new ArcError({
            code: 'PROTECTED_BRANCH_DENIED',
            category: 'AUTHORIZATION',
            message: `Direct mutation of protected branch '${branch}' is strictly forbidden.`,
            retryable: false,
            remediationHint: 'Work on a dedicated feature branch.',
          });
        }
      } else if (branch === protectedPattern) {
        throw new ArcError({
          code: 'PROTECTED_BRANCH_DENIED',
          category: 'AUTHORIZATION',
          message: `Direct mutation of protected branch '${branch}' is strictly forbidden.`,
          retryable: false,
          remediationHint: 'Work on a dedicated feature branch.',
        });
      }
    }
  }

  public async getWorktreeMetadata(
    workspaceRoot: string,
    options?: GitExecutionOptions,
  ): Promise<WorktreeMetadata> {
    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.fileNotFound('Workspace directory not found.');
    }

    const dotGitPath = resolve(canonicalRoot, '.git');
    const hasDotGit = existsSync(dotGitPath);
    const hasHead = existsSync(resolve(canonicalRoot, 'HEAD'));

    if (!hasDotGit && !hasHead) {
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }

    let isWorktree = false;
    let mainRepoPath = canonicalRoot;
    let branch = 'unknown';
    let isDetached = false;
    let headSha = 'unknown';
    let locked = false;
    let lockReason: string | undefined = undefined;

    if (hasDotGit) {
      const dotGitStat = lstatSync(dotGitPath);
      if (dotGitStat.isSymbolicLink()) {
        let symlinkTarget: string;
        try {
          symlinkTarget = realpathSync(dotGitPath);
        } catch {
          throw ArcError.symlinkEscapeDetected(
            'Symlinked .git metadata resolves outside authorized workspace boundary.',
          );
        }
        if (symlinkTarget !== canonicalRoot && !symlinkTarget.startsWith(canonicalRoot + sep)) {
          throw ArcError.symlinkEscapeDetected(
            'Symlinked .git metadata resolves outside authorized workspace boundary.',
          );
        }
      } else if (dotGitStat.isFile()) {
        const dotGitContent = readFileSync(dotGitPath, 'utf8').trim();
        if (!dotGitContent.startsWith('gitdir:')) {
          throw ArcError.gitRepositoryNotFound('Invalid .git worktree pointer.');
        }
        const rawGitDir = dotGitContent.slice(7).trim();
        let canonicalGitDir: string;
        try {
          canonicalGitDir = realpathSync(resolve(canonicalRoot, rawGitDir));
        } catch {
          throw ArcError.gitRepositoryNotFound('Git worktree directory could not be resolved.');
        }

        const backlinkFile = resolve(canonicalGitDir, 'gitdir');
        if (!existsSync(backlinkFile)) {
          throw ArcError.gitRepositoryNotFound('Git worktree backlink missing.');
        }
        const backlink = readFileSync(backlinkFile, 'utf8').trim();
        let resolvedBacklink: string;
        try {
          resolvedBacklink = realpathSync(resolve(canonicalGitDir, backlink));
        } catch {
          throw ArcError.gitRepositoryNotFound('Git worktree backlink could not be resolved.');
        }
        if (resolvedBacklink !== realpathSync(dotGitPath)) {
          throw ArcError.gitRepositoryNotFound(
            'Git worktree bidirectional link verification failed.',
          );
        }

        isWorktree = true;

        // Resolve main repo path via commondir
        const commondirFile = resolve(canonicalGitDir, 'commondir');
        if (existsSync(commondirFile)) {
          const commondirRel = readFileSync(commondirFile, 'utf8').trim();
          let mainGitDir: string;
          try {
            mainGitDir = realpathSync(resolve(canonicalGitDir, commondirRel));
          } catch {
            mainGitDir = resolve(canonicalGitDir, commondirRel);
          }
          mainRepoPath = dirname(mainGitDir);
        }

        // Check lock status
        const lockedFile = resolve(canonicalGitDir, 'locked');
        if (existsSync(lockedFile)) {
          locked = true;
          const reason = readFileSync(lockedFile, 'utf8').trim();
          if (reason.length > 0) {
            lockReason = reason;
          }
        }

        // Check HEAD
        const headFile = resolve(canonicalGitDir, 'HEAD');
        if (existsSync(headFile)) {
          const headContent = readFileSync(headFile, 'utf8').trim();
          if (headContent.startsWith('ref: refs/heads/')) {
            branch = headContent.replace('ref: refs/heads/', '').trim();
            isDetached = false;
          } else {
            branch = headContent;
            isDetached = true;
            headSha = headContent;
          }
        }
      }
    }

    if (options?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    // Resolve HEAD commit hash if not already known
    if (headSha === 'unknown' || !isDetached) {
      try {
        const { stdout } = await this.runRawGit(
          canonicalRoot,
          ['rev-parse', 'HEAD'],
          undefined,
          options,
        );
        headSha = stdout.trim();
      } catch (err: unknown) {
        if (
          err instanceof ArcError &&
          (err.code === 'EXECUTION_TIMEOUT' || err.code === 'PAYLOAD_TOO_LARGE')
        ) {
          throw err;
        }
        // Empty repo
      }
    }

    // If not a linked worktree, resolve branch and detached status from rev-parse
    if (!isWorktree) {
      try {
        const { stdout: branchOut } = await this.runRawGit(
          canonicalRoot,
          ['rev-parse', '--abbrev-ref', 'HEAD'],
          undefined,
          options,
        );
        branch = branchOut.trim();
        if (branch === 'HEAD') {
          isDetached = true;
        }
      } catch (err: unknown) {
        if (
          err instanceof ArcError &&
          (err.code === 'EXECUTION_TIMEOUT' || err.code === 'PAYLOAD_TOO_LARGE')
        ) {
          throw err;
        }
        // Empty repo
      }
    }

    return {
      isWorktree,
      worktreePath: canonicalRoot,
      mainRepoPath,
      branch,
      locked,
      lockReason,
      isDetached,
      headSha,
    };
  }

  private parseFileSummaries(
    nameStatusRaw: string,
    numstatRaw: string,
  ): GitReviewDiffFileSummary[] {
    const nameEntries: Array<{
      status: 'modified' | 'added' | 'deleted' | 'renamed';
      path: string;
      oldPath?: string;
    }> = [];

    const nsTokens = nameStatusRaw.split('\0');
    let i = 0;
    while (i < nsTokens.length) {
      const token = nsTokens[i];
      if (!token) {
        i++;
        continue;
      }
      const code = token.trim();
      if (code.startsWith('R') || code.startsWith('C')) {
        const oldPath = nsTokens[i + 1] || '';
        const newPath = nsTokens[i + 2] || '';
        nameEntries.push({
          status: code.startsWith('R') ? 'renamed' : 'added',
          oldPath,
          path: newPath,
        });
        i += 3;
      } else {
        const path = nsTokens[i + 1] || '';
        let status: 'modified' | 'added' | 'deleted' | 'renamed';
        if (code.startsWith('A')) {
          status = 'added';
        } else if (code.startsWith('D')) {
          status = 'deleted';
        } else {
          status = 'modified';
        }
        nameEntries.push({ status, path });
        i += 2;
      }
    }

    const numMap = new Map<string, { ins: number; dels: number }>();
    const numTokens = numstatRaw.split('\0');
    let j = 0;
    while (j < numTokens.length) {
      const token = numTokens[j];
      if (!token) {
        j++;
        continue;
      }
      const tabParts = token.split('\t');
      if (tabParts.length >= 2) {
        const ins = tabParts[0] === '-' ? 0 : parseInt(tabParts[0], 10) || 0;
        const dels = tabParts[1] === '-' ? 0 : parseInt(tabParts[1], 10) || 0;
        if (tabParts.length >= 3 && tabParts[2] !== '') {
          const path = tabParts.slice(2).join('\t');
          numMap.set(path, { ins, dels });
          j++;
        } else {
          // Rename or copy: next two tokens are oldPath and newPath
          const newPath = numTokens[j + 2] || '';
          numMap.set(newPath, { ins, dels });
          j += 3;
        }
      } else {
        j++;
      }
    }

    const summaries: GitReviewDiffFileSummary[] = [];
    for (const entry of nameEntries) {
      if (!entry.path) continue;
      // Filter out sensitive files so they never leak in metadata
      if (isSensitiveGitPath(entry.path) || (entry.oldPath && isSensitiveGitPath(entry.oldPath))) {
        continue;
      }
      const counts = numMap.get(entry.path) ?? { ins: 0, dels: 0 };
      summaries.push({
        path: entry.path,
        status: entry.status,
        insertions: counts.ins,
        deletions: counts.dels,
      });
    }

    return summaries;
  }

  public async getReviewDiff(
    workspaceRoot: string,
    options: GitReviewDiffOptions,
    execOptions?: GitExecutionOptions,
  ): Promise<GitReviewDiffResult> {
    if (execOptions?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    validateGitArgument('targetRevision', options.targetRevision);
    validateGitArgument('path', options.path);

    if (options.path && isSensitiveGitPath(options.path)) {
      throw ArcError.accessDenied(
        'Target diff path matches sensitive credential or system blacklist pattern.',
      );
    }

    const baseArgs = ['diff', '--no-ext-diff', '--no-textconv'];
    const mode = options.mode;

    if (mode === 'staged') {
      baseArgs.push('--cached');
      if (options.targetRevision) {
        baseArgs.push(options.targetRevision.trim());
      }
    } else if (mode === 'target') {
      if (!options.targetRevision) {
        throw ArcError.invalidRequestSchema("targetRevision is required in 'target' mode.");
      }
      baseArgs.push(options.targetRevision.trim());
    } else if (mode === 'unstaged') {
      if (options.targetRevision) {
        throw ArcError.invalidRequestSchema(
          "targetRevision is not supported in 'unstaged' mode.",
          "Omit targetRevision for unstaged mode, or specify mode as 'staged' or 'target'.",
        );
      }
    } else {
      throw ArcError.invalidRequestSchema(`Unsupported mode: ${String(mode)}`);
    }

    const secretExcludes = [
      ':(exclude)*.env*',
      ':(exclude)*.pem',
      ':(exclude)*.key',
      ':(exclude)*.p12',
      ':(exclude)*.pfx',
      ':(exclude)*id_rsa*',
      ':(exclude)*id_ed25519*',
      ':(exclude).ssh/**',
      ':(exclude).aws/**',
      ':(exclude).gnupg/**',
      ':(exclude).kube/**',
    ];

    const pathFilter = options.path ? options.path.trim() : '.';

    // 1. Discover all rename/copy pairs WITHOUT pathspec excludes so we can
    //    detect sensitive origins/destinations that might be hidden by excludes.
    //    Example: `.env -> notes.txt` rename -- Git with :(exclude)*.env* will show
    //    only `notes.txt` in the filtered diff. We need to know it came from `.env`.
    const fullNameStatusArgs = [...baseArgs, '--name-status', '-z', '-M', '--', pathFilter];
    let renameSensitivePaths: Set<string> | undefined;
    try {
      const { stdout: fullNameStatusStdout } = await this.runGit(
        workspaceRoot,
        fullNameStatusArgs,
        undefined,
        execOptions,
      );
      // Parse rename/copy entries; collect any path where EITHER side is sensitive.
      renameSensitivePaths = new Set<string>();
      const nsTokensFull = fullNameStatusStdout.split('\0');
      let nsIdx = 0;
      while (nsIdx < nsTokensFull.length) {
        const tok = nsTokensFull[nsIdx];
        if (!tok) {
          nsIdx++;
          continue;
        }
        const code = tok.trim();
        if (code.startsWith('R') || code.startsWith('C')) {
          const srcPath = nsTokensFull[nsIdx + 1] || '';
          const dstPath = nsTokensFull[nsIdx + 2] || '';
          if (isSensitiveGitPath(srcPath) || isSensitiveGitPath(dstPath)) {
            // Suppress both sides: either may appear in pathspec-filtered diff output
            if (srcPath) renameSensitivePaths.add(srcPath);
            if (dstPath) renameSensitivePaths.add(dstPath);
          }
          nsIdx += 3;
        } else {
          nsIdx += 2;
        }
      }
    } catch {
      // If this auxiliary call fails, proceed without rename-origin detection.
      // The standard pathspec excludes and purgeSensitiveDiffBlocks remain active.
      renameSensitivePaths = undefined;
    }

    if (execOptions?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    // 2. Run git diff for full diff output using RAW_DIFF_CAPTURE_BYTES ceiling.
    //    If the raw diff exceeds the ceiling, substitute a safe truncation marker
    //    so the structured response remains successful with truncated === true.
    const diffArgs = [...baseArgs, '--', pathFilter, ...secretExcludes];
    let rawDiffStdout: string;
    let rawDiffExceededCeiling = false;
    try {
      const { stdout } = await this.runGit(
        workspaceRoot,
        diffArgs,
        RAW_DIFF_CAPTURE_BYTES,
        execOptions,
      );
      rawDiffStdout = stdout;
    } catch (err: unknown) {
      if (err instanceof ArcError && err.code === 'PAYLOAD_TOO_LARGE') {
        // Raw diff exceeds safe capture ceiling -- return a structured truncation marker.
        rawDiffStdout = RAW_DIFF_OVERFLOW_MARKER;
        rawDiffExceededCeiling = true;
      } else {
        throw err;
      }
    }

    if (execOptions?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    // 3. Run git diff --name-status -z -M and --numstat -z -M for structured file summaries
    const nameStatusArgs = [
      ...baseArgs,
      '--name-status',
      '-z',
      '-M',
      '--',
      pathFilter,
      ...secretExcludes,
    ];
    const { stdout: nameStatusStdout } = await this.runGit(
      workspaceRoot,
      nameStatusArgs,
      undefined,
      execOptions,
    );

    if (execOptions?.signal?.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const numstatArgs = [...baseArgs, '--numstat', '-z', '-M', '--', pathFilter, ...secretExcludes];
    const { stdout: numstatStdout } = await this.runGit(
      workspaceRoot,
      numstatArgs,
      undefined,
      execOptions,
    );

    // 4. Parse name-status -z and numstat -z
    const rawFileSummaries = this.parseFileSummaries(nameStatusStdout, numstatStdout);

    // Post-filter: also remove any entry whose path appears in renameSensitivePaths.
    // This handles the case where the pathspec-excluded name-status emits the non-sensitive
    // rename destination as an add (e.g. `.env -> renamed_notes.txt` appears as `A renamed_notes.txt`).
    const fileSummaries =
      renameSensitivePaths && renameSensitivePaths.size > 0
        ? rawFileSummaries.filter((s) => !renameSensitivePaths!.has(s.path))
        : rawFileSummaries;

    // 5. Defense-in-depth: purge sensitive file diff hunks (including rename origin/destination
    //    paths discovered in step 1) and mask sensitive tokens/keys
    const { diff: purgedDiff, suppressedCount } = purgeSensitiveDiffBlocksWithCount(
      rawDiffStdout,
      renameSensitivePaths,
    );
    const { diff: maskedDiff, maskedCount } = maskSensitiveDiffWithCount(purgedDiff);
    const sensitiveBlocksMasked = suppressedCount + maskedCount;

    // 6. Enforce requested maxBytes (bounded by MAX_DIFF_BYTES)
    const maxBudget =
      options.maxBytes !== undefined ? Math.min(options.maxBytes, MAX_DIFF_BYTES) : MAX_DIFF_BYTES;

    const { text: boundedDiff, truncated } = truncateUtf8ToByteLimit(maskedDiff, maxBudget);

    return {
      diff: boundedDiff,
      truncated: truncated || rawDiffExceededCeiling,
      totalFilesChanged: fileSummaries.length,
      fileSummaries,
      sensitiveBlocksMasked,
    };
  }
}
