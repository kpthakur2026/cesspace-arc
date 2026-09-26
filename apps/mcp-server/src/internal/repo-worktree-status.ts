import {
  ArcError,
  type ArcRepoStatusResponse,
  type ArcWorktreeStatusResponse,
} from '@cesspace-arc/protocol';
import { type GitSubsystem, isProtectedBranch, type GitExecutionOptions } from '@cesspace-arc/git';
import { type FilesystemSubsystem } from '@cesspace-arc/filesystem';

/**
 * Maximum serialized response size for RC-07 read-only status tools: 64 KiB (65,536 bytes).
 */
export const MAX_STATUS_RESPONSE_BYTES = 64 * 1024;

/**
 * Frozen aggregate composite execution ceiling for Task-2 read-only tools: 15 seconds.
 */
export const DEFAULT_TASK2_TIMEOUT_MS = 15000;

export interface RepoStatusHandlerParams {
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  gitSubsystem: GitSubsystem;
  filesystemSubsystem: FilesystemSubsystem;
  timeoutMs?: number;
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
  timeoutMs?: number;
}

/**
 * Formats a response object exactly as the production MCP layer emits it:
 * JSON.stringify(result, null, 2)
 */
export function formatMcpPayloadText(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}

/**
 * Calculates the UTF-8 byte length of the actual serialized MCP response text.
 */
export function getMcpPayloadByteLength(obj: unknown): number {
  return Buffer.byteLength(formatMcpPayloadText(obj), 'utf8');
}

/**
 * Bounds a UTF-8 string to a maximum byte length without splitting multi-byte characters
 * or producing invalid UTF-8 replacement characters (\uFFFD).
 */
export function truncateStringBytes(str: string, maxBytes: number): string {
  if (maxBytes <= 0) {
    return '';
  }
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) {
    return str;
  }
  let end = maxBytes;
  // Step backward past any UTF-8 continuation bytes (10xxxxxx)
  while (end > 0 && (buf[end] & 0xc0) === 0x80) {
    end--;
  }
  // If end lands on a multi-byte sequence start byte whose full sequence exceeds maxBytes, step back
  if (end > 0) {
    const lead = buf[end - 1];
    let seqLen = 0;
    if ((lead & 0xe0) === 0xc0) seqLen = 2;
    else if ((lead & 0xf0) === 0xe0) seqLen = 3;
    else if ((lead & 0xf8) === 0xf0) seqLen = 4;
    if (seqLen > 0 && end - 1 + seqLen > maxBytes) {
      end = end - 1;
    }
  }
  return buf.subarray(0, end).toString('utf8');
}

/**
 * Enforces the 64 KiB maximum response size on the actual serialized MCP payload
 * for arc_repo_status.
 *
 * If the serialized JSON payload (with 2-space indentation) exceeds 64 KiB:
 * 1. Sets additive truncated: true.
 * 2. Systematically bounds headCommit.message, headCommit.author, branch, and upstreamBranch.
 * 3. Asserts that the final serialized response text byte length is <= 65,536 bytes.
 */
export function boundRepoStatusResponse(response: ArcRepoStatusResponse): ArcRepoStatusResponse {
  if (getMcpPayloadByteLength(response) <= MAX_STATUS_RESPONSE_BYTES) {
    return response;
  }

  const boundedResponse: ArcRepoStatusResponse = {
    ...response,
    headCommit: {
      ...response.headCommit,
    },
    truncated: true,
  };

  // Step 1: Bound headCommit.message
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.headCommit.message, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.headCommit.message =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.headCommit.message, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 2: Bound headCommit.author if still oversized
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.headCommit.author, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.headCommit.author =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.headCommit.author, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 3: Bound branch if still oversized
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.branch, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.branch =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.branch, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 4: Bound upstreamBranch if present and still oversized
  if (
    boundedResponse.upstreamBranch &&
    getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES
  ) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.upstreamBranch, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.upstreamBranch =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.upstreamBranch, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 5: Clamping fallback
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    boundedResponse.headCommit.message = '[TRUNCATED]';
    boundedResponse.headCommit.author = '[TRUNCATED]';
    boundedResponse.branch = '[TRUNCATED]';
    if (boundedResponse.upstreamBranch) {
      boundedResponse.upstreamBranch = '[TRUNCATED]';
    }
  }

  // Final serialization-size assertion against exact MCP formatting
  const finalBytes = getMcpPayloadByteLength(boundedResponse);
  if (finalBytes > MAX_STATUS_RESPONSE_BYTES) {
    throw ArcError.payloadTooLarge(
      'Response payload exceeded 64 KiB ceiling after maximum truncation.',
    );
  }

  return boundedResponse;
}

/**
 * Enforces the 64 KiB maximum response size on the actual serialized MCP payload
 * for arc_worktree_status.
 */
export function boundWorktreeStatusResponse(
  response: ArcWorktreeStatusResponse,
): ArcWorktreeStatusResponse {
  if (getMcpPayloadByteLength(response) <= MAX_STATUS_RESPONSE_BYTES) {
    return response;
  }

  const boundedResponse: ArcWorktreeStatusResponse = {
    ...response,
    truncated: true,
  };

  // Step 1: Bound lockReason if present
  if (
    boundedResponse.lockReason &&
    getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES
  ) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.lockReason, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.lockReason =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.lockReason, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 2: Bound branch if still oversized
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.branch, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.branch =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.branch, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 3: Bound worktreePath if still oversized
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.worktreePath, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.worktreePath =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.worktreePath, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 4: Bound mainRepoPath if still oversized
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    const excess = getMcpPayloadByteLength(boundedResponse) - MAX_STATUS_RESPONSE_BYTES;
    const currentBytes = Buffer.byteLength(boundedResponse.mainRepoPath, 'utf8');
    const targetBytes = Math.max(0, currentBytes - excess - 64);
    boundedResponse.mainRepoPath =
      targetBytes > 16
        ? `${truncateStringBytes(boundedResponse.mainRepoPath, targetBytes)}... [TRUNCATED]`
        : '[TRUNCATED]';
  }

  // Step 5: Clamping fallback
  if (getMcpPayloadByteLength(boundedResponse) > MAX_STATUS_RESPONSE_BYTES) {
    if (boundedResponse.lockReason) boundedResponse.lockReason = '[TRUNCATED]';
    boundedResponse.branch = '[TRUNCATED]';
    boundedResponse.worktreePath = '[TRUNCATED]';
    boundedResponse.mainRepoPath = '[TRUNCATED]';
  }

  // Final serialization-size assertion against exact MCP formatting
  const finalBytes = getMcpPayloadByteLength(boundedResponse);
  if (finalBytes > MAX_STATUS_RESPONSE_BYTES) {
    throw ArcError.payloadTooLarge(
      'Response payload exceeded 64 KiB ceiling after maximum truncation.',
    );
  }

  return boundedResponse;
}

/**
 * Handler for arc_repo_status tool.
 * Composes GitSubsystem.getStatus and GitSubsystem.getLog.
 * Read-only; zero mutation, zero process spawning, zero raw fs in MCP layer.
 * Enforces an aggregate 15-second deadline with immediate subprocess cancellation.
 */
export async function handleArcRepoStatus(
  params: RepoStatusHandlerParams,
): Promise<ArcRepoStatusResponse> {
  const { targetWorkspace, gitSubsystem } = params;
  const timeoutMs = params.timeoutMs ?? DEFAULT_TASK2_TIMEOUT_MS;

  const abortController = new AbortController();
  const timer = setTimeout(() => {
    abortController.abort(
      ArcError.executionTimeout('Command execution exceeded configured timeout.'),
    );
  }, timeoutMs);
  timer.unref?.();

  try {
    // RC07-NEG-011: target workspace must be a valid Git repository
    if (!targetWorkspace.isGitRepo) {
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const execOptions: GitExecutionOptions = {
      signal: abortController.signal,
      timeoutMs,
    };

    let statusRes;
    try {
      statusRes = await gitSubsystem.getStatus(targetWorkspace.rootPath, undefined, execOptions);
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        if (err.code === 'EXECUTION_TIMEOUT') {
          throw err;
        }
        if (err.code === 'GIT_REPOSITORY_NOT_FOUND' || err.code === 'FILE_NOT_FOUND') {
          throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
        }
        throw err;
      }
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    // Retrieve HEAD commit metadata via getLog only when a commit exists
    let headHash = statusRes.commitHash || '';
    let shortHash = headHash.length >= 7 ? headHash.slice(0, 7) : headHash;
    let commitMessage = '';
    let author = '';
    let commitDate = '';

    if (headHash && headHash !== 'unknown') {
      const logRes = await gitSubsystem.getLog(
        targetWorkspace.rootPath,
        { maxCount: 1 },
        execOptions,
      );
      if (logRes.commits && logRes.commits.length > 0) {
        const topCommit = logRes.commits[0];
        headHash = topCommit.hash;
        shortHash = topCommit.hash.slice(0, 7);
        commitMessage = topCommit.message;
        author = topCommit.author;
        commitDate = topCommit.date;
      }
    } else {
      // Genuine empty repository condition: no commits exist yet
      headHash = '';
      shortHash = '';
      commitMessage = '';
      author = '';
      commitDate = '';
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
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Handler for arc_worktree_status tool.
 * Composes FilesystemSubsystem containment checks and GitSubsystem worktree metadata.
 * Read-only; zero mutation, zero process spawning, zero raw fs in MCP layer.
 * Enforces an aggregate 15-second deadline with immediate subprocess cancellation.
 */
export async function handleArcWorktreeStatus(
  params: WorktreeStatusHandlerParams,
): Promise<ArcWorktreeStatusResponse> {
  const { targetWorkspace, validatedParams, gitSubsystem, filesystemSubsystem } = params;
  const timeoutMs = params.timeoutMs ?? DEFAULT_TASK2_TIMEOUT_MS;

  const abortController = new AbortController();
  const timer = setTimeout(() => {
    abortController.abort(
      ArcError.executionTimeout('Command execution exceeded configured timeout.'),
    );
  }, timeoutMs);
  timer.unref?.();

  try {
    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

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

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const execOptions: GitExecutionOptions = {
      signal: abortController.signal,
      timeoutMs,
    };

    // Obtain bounded worktree metadata from GitSubsystem
    const meta = await gitSubsystem.getWorktreeMetadata(targetWorkspace.rootPath, execOptions);

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
  } finally {
    clearTimeout(timer);
  }
}
