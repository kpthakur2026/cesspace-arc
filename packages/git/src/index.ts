import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { realpathSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
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
 * Interface definition for Sandboxed Git Subsystem.
 */
export interface IGitSubsystem {
  getStatus(workspaceRoot: string, request: GitStatusRequest): Promise<GitStatusResponse>;
  getDiff(workspaceRoot: string, request: GitDiffRequest): Promise<GitDiffResponse>;
  getLog(workspaceRoot: string, request: GitLogRequest): Promise<GitLogResponse>;
  assertBranchWritable(workspaceRoot: string, targetBranch: string): Promise<void>;
}

/**
 * Sandboxed Git Subsystem implementation.
 * Guarantees read-only subprocess invocation via argument arrays and shell=false.
 */
export class GitSubsystem implements IGitSubsystem {
  private async runGit(
    workspaceRoot: string,
    args: string[],
    maxBuffer: number = 1024 * 1024,
  ): Promise<{ stdout: string; stderr: string }> {
    const canonicalRoot = realpathSync(resolve(workspaceRoot));

    const isGit =
      existsSync(resolve(canonicalRoot, '.git')) || existsSync(resolve(canonicalRoot, 'HEAD'));

    if (!isGit) {
      throw ArcError.fileNotFound(`Directory '${workspaceRoot}' is not a valid Git repository.`);
    }

    try {
      const result = await execFileAsync('git', args, {
        cwd: canonicalRoot,
        shell: false,
        timeout: 10000,
        maxBuffer,
        env: {
          ...process.env,
          // Neutralize localized git output
          LC_ALL: 'C',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_TERMINAL_PROMPT: '0',
        },
      });
      return { stdout: result.stdout, stderr: result.stderr };
    } catch (err: unknown) {
      const execErr = err as { code?: number; message?: string; stderr?: string };
      throw ArcError.internalError(
        `Git command failed: ${execErr.stderr || execErr.message || 'Unknown error'}`,
      );
    }
  }

  public async getStatus(
    workspaceRoot: string,
    request: GitStatusRequest,
  ): Promise<GitStatusResponse> {
    const targetRoot = request.workspaceRoot || workspaceRoot;

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

    const args = ['diff'];

    if (request.cached) {
      args.push('--cached');
    }

    if (request.target) {
      args.push(request.target.trim());
    }

    if (request.path) {
      args.push('--', request.path.trim());
    }

    const { stdout } = await this.runGit(workspaceRoot, args, MAX_DIFF_BYTES * 2);

    let diffText = maskSensitiveDiff(stdout);
    let truncated = false;

    if (Buffer.byteLength(diffText, 'utf8') > MAX_DIFF_BYTES) {
      diffText = diffText.slice(0, MAX_DIFF_BYTES);
      truncated = true;
    }

    return {
      diff: diffText,
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
