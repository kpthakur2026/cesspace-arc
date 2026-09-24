import {
  ArcError,
  type ArcReviewDiffResponse,
  type ArcReviewDiffFileSummary,
} from '@cesspace-arc/protocol';
import { type GitSubsystem, type GitExecutionOptions, MAX_DIFF_BYTES } from '@cesspace-arc/git';
import { type FilesystemSubsystem } from '@cesspace-arc/filesystem';

/**
 * Maximum serialized response size for RC-07 review diff tool: 512 KiB (524,288 bytes).
 */
export const MAX_REVIEW_DIFF_WIRE_BYTES = 512 * 1024;

/**
 * Frozen aggregate composite execution ceiling for Task-3 read-only tools: 15 seconds.
 */
export const DEFAULT_TASK3_TIMEOUT_MS = 15000;

export interface ReviewDiffHandlerParams {
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
 * Bounds the final serialized MCP response payload to <= 512 KiB (524,288 bytes),
 * ensuring the formatted JSON wire payload obeys the ceiling while maintaining valid UTF-8.
 */
export function boundReviewDiffResponse(
  baseResponse: {
    mode: 'staged' | 'unstaged' | 'target';
    targetRevision?: string;
    pathFilter?: string;
    totalFilesChanged: number;
    fileSummaries: ArcReviewDiffFileSummary[];
    sensitiveBlocksMasked: number;
  },
  rawDiff: string,
  requestedMaxBytes?: number,
  initialTruncated: boolean = false,
): ArcReviewDiffResponse {
  const diffBudget =
    requestedMaxBytes !== undefined
      ? Math.min(requestedMaxBytes, MAX_REVIEW_DIFF_WIRE_BYTES)
      : MAX_REVIEW_DIFF_WIRE_BYTES;

  let currentDiff = rawDiff;
  let truncated = initialTruncated;

  const currentDiffBytes = Buffer.byteLength(currentDiff, 'utf8');
  if (currentDiffBytes > diffBudget) {
    currentDiff = truncateStringBytes(currentDiff, diffBudget);
    truncated = true;
  }

  function makeResponse(diffText: string, isTrunc: boolean): ArcReviewDiffResponse {
    return {
      mode: baseResponse.mode,
      ...(baseResponse.targetRevision !== undefined
        ? { targetRevision: baseResponse.targetRevision }
        : {}),
      ...(baseResponse.pathFilter !== undefined ? { pathFilter: baseResponse.pathFilter } : {}),
      diff: diffText,
      bytes: Buffer.byteLength(diffText, 'utf8'),
      truncated: isTrunc,
      totalFilesChanged: baseResponse.totalFilesChanged,
      fileSummaries: baseResponse.fileSummaries,
      sensitiveBlocksMasked: baseResponse.sensitiveBlocksMasked,
    };
  }

  const candidate = makeResponse(currentDiff, truncated);
  if (getMcpPayloadByteLength(candidate) <= MAX_REVIEW_DIFF_WIRE_BYTES) {
    return candidate;
  }

  // Binary search for the maximum diff payload that fits within MAX_REVIEW_DIFF_WIRE_BYTES
  const fullBuf = Buffer.from(currentDiff, 'utf8');
  let low = 0;
  let high = fullBuf.length;
  let bestDiff = '';

  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const candidateText = truncateStringBytes(fullBuf.toString('utf8'), mid);
    const trialResp = makeResponse(candidateText, true);
    if (getMcpPayloadByteLength(trialResp) <= MAX_REVIEW_DIFF_WIRE_BYTES) {
      bestDiff = candidateText;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  const finalResponse = makeResponse(bestDiff, true);
  if (getMcpPayloadByteLength(finalResponse) > MAX_REVIEW_DIFF_WIRE_BYTES) {
    throw ArcError.payloadTooLarge(
      'Response payload exceeded 512 KiB ceiling after maximum truncation.',
    );
  }

  return finalResponse;
}

/**
 * Handler for arc_review_diff tool.
 * Composes GitSubsystem.getReviewDiff and FilesystemSubsystem.validateReviewDiffPath.
 * Read-only; zero mutation, zero child_process, zero raw node:fs in MCP layer.
 * Enforces an aggregate 15-second deadline with immediate subprocess cancellation.
 */
export async function handleArcReviewDiff(
  params: ReviewDiffHandlerParams,
): Promise<ArcReviewDiffResponse> {
  const { targetWorkspace, validatedParams, gitSubsystem, filesystemSubsystem } = params;
  const timeoutMs = params.timeoutMs ?? DEFAULT_TASK3_TIMEOUT_MS;

  const abortController = new AbortController();
  const timer = setTimeout(() => {
    abortController.abort(
      ArcError.executionTimeout('Command execution exceeded configured timeout.'),
    );
  }, timeoutMs);
  timer.unref?.();

  try {
    // RC07-NEG-027: target workspace must be a valid Git repository
    if (!targetWorkspace.isGitRepo) {
      throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
    }

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    // 1. Target revision validation
    let targetRevision: string | undefined = undefined;
    if (validatedParams.targetRevision !== undefined) {
      const rawRev = String(validatedParams.targetRevision).trim();
      // RC07-NEG-020: Target revision starts with a hyphen
      if (rawRev.startsWith('-')) {
        throw ArcError.invalidGitArgument(
          "Parameter 'targetRevision' must not begin with '-' (option flag injection prevention).",
          'Provide a valid revision name without leading dashes.',
        );
      }
      // RC07-NEG-019: Shell metacharacters in target revision
      if (/[;&|`$><\r\n]/.test(rawRev)) {
        throw ArcError.invalidRequestSchema(
          "Parameter 'targetRevision' contains forbidden shell metacharacters.",
          'Provide a valid revision name without shell metacharacters.',
        );
      }
      targetRevision = rawRev;
    }

    // 2. Mode validation & defaults
    const mode = (validatedParams.mode as 'staged' | 'unstaged' | 'target') ?? 'unstaged';
    if (mode !== 'staged' && mode !== 'unstaged' && mode !== 'target') {
      throw ArcError.invalidRequestSchema(
        `Invalid mode '${String(mode)}'. Must be 'staged', 'unstaged', or 'target'.`,
      );
    }

    // Contradictory input combination checks
    if (mode === 'unstaged' && targetRevision !== undefined) {
      throw ArcError.invalidRequestSchema(
        "targetRevision is not supported in 'unstaged' mode.",
        "Omit targetRevision for unstaged mode, or specify mode as 'staged' or 'target'.",
      );
    }
    if (mode === 'target' && !targetRevision) {
      throw ArcError.invalidRequestSchema(
        "targetRevision is required in 'target' mode.",
        "Provide a targetRevision when using 'target' mode.",
      );
    }

    // 3. Path validation through FilesystemSubsystem (RC07-NEG-021, RC07-NEG-026)
    let pathFilter: string | undefined = undefined;
    if (typeof validatedParams.path === 'string' && validatedParams.path.trim().length > 0) {
      pathFilter = await filesystemSubsystem.validateReviewDiffPath(
        targetWorkspace.rootPath,
        validatedParams.path,
      );
    }

    // 4. maxBytes validation (finite positive integer up to MAX_DIFF_BYTES)
    let requestedMaxBytes: number | undefined = undefined;
    if (validatedParams.maxBytes !== undefined) {
      const mb = Number(validatedParams.maxBytes);
      if (!Number.isInteger(mb) || mb <= 0 || mb > MAX_DIFF_BYTES) {
        throw ArcError.invalidRequestSchema(
          `maxBytes must be an integer between 1 and ${MAX_DIFF_BYTES}.`,
        );
      }
      requestedMaxBytes = mb;
    }

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const execOptions: GitExecutionOptions = {
      signal: abortController.signal,
      timeoutMs,
    };

    const gitResult = await gitSubsystem.getReviewDiff(
      targetWorkspace.rootPath,
      {
        mode,
        targetRevision,
        path: pathFilter,
        maxBytes: requestedMaxBytes,
      },
      execOptions,
    );

    if (abortController.signal.aborted) {
      throw ArcError.executionTimeout('Command execution exceeded configured timeout.');
    }

    const baseResponse = {
      mode,
      ...(targetRevision !== undefined ? { targetRevision } : {}),
      ...(pathFilter !== undefined ? { pathFilter } : {}),
      totalFilesChanged: gitResult.totalFilesChanged,
      fileSummaries: gitResult.fileSummaries,
      sensitiveBlocksMasked: gitResult.sensitiveBlocksMasked,
    };

    return boundReviewDiffResponse(
      baseResponse,
      gitResult.diff,
      requestedMaxBytes,
      gitResult.truncated,
    );
  } finally {
    clearTimeout(timer);
  }
}
