import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { realpathSync, existsSync } from 'node:fs';
import { resolve, sep } from 'node:path';
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
 * Maximum git_log commit count: 100.
 */
export const MAX_LOG_COUNT = 100;

/**
 * Protected branches that cannot be directly mutated.
 */
export const PROTECTED_BRANCHES = ['main', 'master', 'release/*'];

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
 * Mask sensitive tokens in diff output.
 */
export function maskSensitiveDiff(diff: string): string {
  return diff.replace(
    /(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9._-]+)/g,
    '[REDACTED_SECRET]',
  );
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
 */
export function purgeSensitiveDiffBlocks(diff: string): string {
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

  for (const block of blocks) {
    if (!block.startsWith('diff --git ')) {
      sanitizedBlocks.push(block);
      continue;
    }

    const firstLine = block.split('\n', 1)[0];
    const isSensitive = sensitivePatterns.some((pattern) => pattern.test(firstLine));

    if (isSensitive) {
      sanitizedBlocks.push(`${firstLine}\n[SENSITIVE FILE DIFF SUPPRESSED]\n`);
    } else {
      sanitizedBlocks.push(block);
    }
  }

  return sanitizedBlocks.join('');
}

/**
 * Truncates a UTF-8 string to a maximum byte limit without splitting multi-byte characters.
 */
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
 * Interface definition for Sandboxed Git Subsystem.
 */
export interface IGitSubsystem {
  getStatus(workspaceRoot: string, request?: GitStatusRequest): Promise<GitStatusResponse>;
  getDiff(workspaceRoot: string, request: GitDiffRequest): Promise<GitDiffResponse>;
  getLog(workspaceRoot: string, request: GitLogRequest): Promise<GitLogResponse>;
  assertBranchWritable(workspaceRoot: string, targetBranch: string): Promise<void>;
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
  ): Promise<{ stdout: string; stderr: string }> {
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
        timeout: 10000,
        maxBuffer,
        env: safeEnv,
      });
      return { stdout: result.stdout, stderr: result.stderr };
    } catch (err: unknown) {
      const execErr = err as { code?: string | number; message?: string; stderr?: string };
      if (execErr.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
        throw ArcError.payloadTooLarge('Git command output exceeded maximum buffer limit.');
      }
      throw ArcError.internalError('Git command execution failed.');
    }
  }

  private async verifyRepositoryBoundary(canonicalRoot: string): Promise<void> {
    const isGit =
      existsSync(resolve(canonicalRoot, '.git')) || existsSync(resolve(canonicalRoot, 'HEAD'));

    if (!isGit) {
      throw ArcError.fileNotFound('Directory is not a valid Git repository.');
    }

    try {
      const { stdout } = await this.runRawGit(canonicalRoot, [
        'rev-parse',
        '--show-toplevel',
        '--git-dir',
        '--git-common-dir',
      ]);
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

      if (resolvedGitDir !== canonicalRoot && !resolvedGitDir.startsWith(canonicalRoot + sep)) {
        throw ArcError.accessDenied('Git directory is outside authorized workspace boundary.');
      }

      let resolvedGitCommonDir = '';
      try {
        resolvedGitCommonDir = realpathSync(resolve(canonicalRoot, gitCommonDirRaw));
      } catch {
        throw ArcError.accessDenied('Git common directory path could not be resolved.');
      }

      if (
        resolvedGitCommonDir !== canonicalRoot &&
        !resolvedGitCommonDir.startsWith(canonicalRoot + sep)
      ) {
        throw ArcError.accessDenied(
          'Git common directory is outside authorized workspace boundary.',
        );
      }
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        throw err;
      }
      throw ArcError.fileNotFound('Directory is not a valid Git repository.');
    }
  }

  private async runGit(
    workspaceRoot: string,
    args: string[],
    maxBuffer: number = 1024 * 1024,
  ): Promise<{ stdout: string; stderr: string }> {
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.fileNotFound('Workspace directory not found.');
    }
    await this.verifyRepositoryBoundary(canonicalRoot);
    return this.runRawGit(canonicalRoot, args, maxBuffer);
  }

  public async getStatus(
    workspaceRoot: string,
    _request?: GitStatusRequest,
  ): Promise<GitStatusResponse> {
    // Non-bypassable: execution subsystems MUST receive only the canonical workspace root
    // Caller parameters must never override the execution root after policy authorization.
    const targetRoot = workspaceRoot;

    // Get current branch
    let branch = 'unknown';
    try {
      const branchRes = await this.runGit(targetRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);
      branch = branchRes.stdout.trim();
    } catch {
      // Empty repo or detached HEAD
    }

    // Get commit hash
    let commitHash = 'unknown';
    try {
      const commitRes = await this.runGit(targetRoot, ['rev-parse', 'HEAD']);
      commitHash = commitRes.stdout.trim();
    } catch {
      // Empty repo
    }

    // Status porcelain
    const statusRes = await this.runGit(targetRoot, ['status', '--porcelain=v1', '-uall']);

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

  public async getDiff(workspaceRoot: string, request: GitDiffRequest): Promise<GitDiffResponse> {
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

    const { stdout } = await this.runGit(workspaceRoot, args, MAX_DIFF_BYTES * 2);

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

  public async getLog(workspaceRoot: string, request: GitLogRequest): Promise<GitLogResponse> {
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

    const { stdout } = await this.runGit(workspaceRoot, args);
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
}
