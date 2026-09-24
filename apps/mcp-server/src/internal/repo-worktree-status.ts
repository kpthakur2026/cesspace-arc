import {
  ArcError,
  type ArcRepoStatusResponse,
  type ArcWorktreeStatusResponse,
} from '@cesspace-arc/protocol';
import { type GitSubsystem, isProtectedBranch } from '@cesspace-arc/git';
import { type FilesystemSubsystem } from '@cesspace-arc/filesystem';

/**
 * Maximum serialized response size for RC-07 read-only status tools: 64 KiB (65,536 bytes).
 */
export const MAX_STATUS_RESPONSE_BYTES = 64 * 1024;

export interface RepoStatusHandlerParams {
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  gitSubsystem: GitSubsystem;
  filesystemSubsystem: FilesystemSubsystem;
}

export interface WorktreeStatusHandlerParams {
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  validatedParams: Record<string, unknown>;
  gitSubsystem: GitSubsystem;
  filesystemSubsystem: FilesystemSubsystem;
}

/**
 * Bounds a UTF-8 string to a maximum byte length without splitting multi-byte characters.
 */
function truncateStringBytes(str: string, maxBytes: number): string {
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) {
    return str;
  }
  let end = maxBytes;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }
  return buf.subarray(0, end).toString('utf8');
}

/**
 * Enforces the 64 KiB maximum response size for arc_repo_status.
 * If the serialized JSON payload exceeds 64 KiB, bounds headCommit.message
 * to bring the response within limits, and sets truncated: true (RC07-NEG-013).
 */
export function boundRepoStatusResponse(response: ArcRepoStatusResponse): ArcRepoStatusResponse {
  const initialJson = JSON.stringify(response);
  const initialBytes = Buffer.byteLength(initialJson, 'utf8');

  if (initialBytes <= MAX_STATUS_RESPONSE_BYTES) {
    return response;
  }

  // Response exceeds 64 KiB cap: bound message and mark truncated: true
  const excess = initialBytes - MAX_STATUS_RESPONSE_BYTES + 64; // safety margin for keys
  const currentMsgBytes = Buffer.byteLength(response.headCommit.message, 'utf8');
  const targetMsgBytes = Math.max(0, currentMsgBytes - excess);

  const boundedMessage =
    targetMsgBytes > 32
      ? `${truncateStringBytes(response.headCommit.message, targetMsgBytes - 16)}... [TRUNCATED]`
      : '[TRUNCATED]';

  const boundedResponse: ArcRepoStatusResponse = {
    ...response,
    headCommit: {
      ...response.headCommit,
      message: boundedMessage,
    },
    truncated: true,
  };

  // Defense-in-depth: if still too large, clamp author/branch if needed
  const finalJson = JSON.stringify(boundedResponse);
  if (Buffer.byteLength(finalJson, 'utf8') > MAX_STATUS_RESPONSE_BYTES) {
    boundedResponse.headCommit.message = '[TRUNCATED]';
  }

  return boundedResponse;
}

/**
 * Enforces the 64 KiB maximum response size for arc_worktree_status.
 */
export function boundWorktreeStatusResponse(
  response: ArcWorktreeStatusResponse,
): ArcWorktreeStatusResponse {
  const initialJson = JSON.stringify(response);
  const initialBytes = Buffer.byteLength(initialJson, 'utf8');

  if (initialBytes <= MAX_STATUS_RESPONSE_BYTES) {
    return response;
  }

  const boundedResponse: ArcWorktreeStatusResponse = {
    ...response,
    lockReason: response.lockReason
      ? `${truncateStringBytes(response.lockReason, 256)}... [TRUNCATED]`
      : undefined,
    truncated: true,
  };

  return boundedResponse;
}

/**
 * Handler for arc_repo_status tool.
 * Composes GitSubsystem.getStatus and GitSubsystem.getLog.
 * Read-only; zero mutation, zero process spawning, zero raw fs in MCP layer.
 */
export async function handleArcRepoStatus(
  params: RepoStatusHandlerParams,
): Promise<ArcRepoStatusResponse> {
  const { targetWorkspace, gitSubsystem } = params;

  // RC07-NEG-011: target workspace must be a valid Git repository
  if (!targetWorkspace.isGitRepo) {
    throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
  }

  let statusRes;
  try {
    statusRes = await gitSubsystem.getStatus(targetWorkspace.rootPath);
  } catch (err: unknown) {
    if (err instanceof ArcError) {
      if (err.code === 'GIT_REPOSITORY_NOT_FOUND' || err.code === 'FILE_NOT_FOUND') {
        throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
      }
      throw err;
    }
    throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
  }

  // Retrieve HEAD commit metadata via getLog
  let headHash = statusRes.commitHash || '';
  let shortHash = headHash.length >= 7 ? headHash.slice(0, 7) : headHash;
  let commitMessage = '';
  let author = '';
  let commitDate = '';

  try {
    const logRes = await gitSubsystem.getLog(targetWorkspace.rootPath, { maxCount: 1 });
    if (logRes.commits && logRes.commits.length > 0) {
      const topCommit = logRes.commits[0];
      headHash = topCommit.hash;
      shortHash = topCommit.hash.slice(0, 7);
      commitMessage = topCommit.message;
      author = topCommit.author;
      commitDate = topCommit.date;
    }
  } catch {
    // Empty repository with no commits yet
  }

  const isProtected = isProtectedBranch(statusRes.branch);

  const rawResponse: ArcRepoStatusResponse = {
    branch: statusRes.branch,
    headCommit: {
      hash: headHash,
      shortHash,
      message: commitMessage,
      author,
      date: commitDate,
    },
    isClean: statusRes.isClean,
    isProtectedBranch: isProtected,
    counts: {
      staged: statusRes.stagedFiles.length,
      unstaged: statusRes.unstagedFiles.length,
      untracked: statusRes.untrackedFiles.length,
    },
  };

  return boundRepoStatusResponse(rawResponse);
}

/**
 * Handler for arc_worktree_status tool.
 * Composes FilesystemSubsystem containment checks and GitSubsystem worktree metadata.
 * Read-only; zero mutation, zero process spawning, zero raw fs in MCP layer.
 */
export async function handleArcWorktreeStatus(
  params: WorktreeStatusHandlerParams,
): Promise<ArcWorktreeStatusResponse> {
  const { targetWorkspace, validatedParams, gitSubsystem, filesystemSubsystem } = params;

  // RC07-NEG-014 & RC07-NEG-016: If workspaceRoot parameter was explicitly provided,
  // validate containment and traversal rejection through FilesystemSubsystem
  if (
    typeof validatedParams.workspaceRoot === 'string' &&
    validatedParams.workspaceRoot.trim().length > 0
  ) {
    await filesystemSubsystem.validateWorkspaceContainment(
      targetWorkspace.rootPath,
      validatedParams.workspaceRoot,
    );
  }

  // Obtain bounded worktree metadata from GitSubsystem
  const meta = await gitSubsystem.getWorktreeMetadata(targetWorkspace.rootPath);

  const rawResponse: ArcWorktreeStatusResponse = {
    workspaceId: targetWorkspace.workspaceId,
    isWorktree: meta.isWorktree,
    worktreePath: meta.worktreePath,
    mainRepoPath: meta.mainRepoPath,
    branch: meta.branch,
    locked: meta.locked,
    lockReason: meta.lockReason,
    isDetached: meta.isDetached,
    headSha: meta.headSha,
  };

  return boundWorktreeStatusResponse(rawResponse);
}
