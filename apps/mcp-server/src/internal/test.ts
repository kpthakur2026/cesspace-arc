/**
 * Package-internal execution logic and response projection for arc_test (RC-07 Task 5).
 * STRICTLY package-internal and NEVER exported from public package root or exports map.
 * @internal
 */

import { ArcError, type ArcTestResponse } from '@cesspace-arc/protocol';
import { scrubOutput, sliceUtf8Safe } from '@cesspace-arc/processes';
import {
  type CanonicalCompositePlan,
  type CanonicalPlanStep,
  type CompositeExecutionResult,
  type DeterministicExecutionRegistry,
  ARC_TEST_NODE_REGISTRY_ID,
} from '../composite-framework.js';

export const MAX_TEST_WIRE_BYTES = 256 * 1024; // 262,144 bytes
export const DEFAULT_TASK5_TIMEOUT_MS = 60_000;
export const MAX_TASK5_TIMEOUT_MS = 60_000;
export const MIN_TASK5_TIMEOUT_MS = 100;

/**
 * Validates test filter string against shell operators, control characters,
 * null bytes, and traversal tokens (RC07-NEG-039).
 */
export function validateTestFilter(filter: string): void {
  if (typeof filter !== 'string') {
    throw ArcError.invalidRequestSchema('Filter must be a string.');
  }

  if (filter.length === 0 || filter.trim().length === 0) {
    throw ArcError.invalidRequestSchema('Filter parameter must not be empty.');
  }

  if (filter.length > 512 || Buffer.byteLength(filter, 'utf8') > 512) {
    throw ArcError.invalidRequestSchema(
      'Filter parameter exceeds maximum allowed length of 512 bytes.',
    );
  }

  if (filter.includes('\0')) {
    throw ArcError.invalidRequestSchema('Filter contains invalid null byte.');
  }

  if (/[;&|`$><\r\n]/.test(filter) || filter.includes('$(')) {
    throw ArcError.invalidRequestSchema(
      'Filter contains forbidden shell control tokens or metacharacters.',
    );
  }

  if (filter.includes('../') || filter.includes('..\\') || filter.includes('..')) {
    throw ArcError.invalidRequestSchema('Filter contains forbidden directory traversal pattern.');
  }
}

export function materializeArcTestPlan(params: {
  testPath?: string;
  filter?: string;
  testRunner?: 'node';
  maxDurationMs?: number;
  workspaceId: string;
  workspaceRoot: string;
  registry: DeterministicExecutionRegistry;
}): CanonicalCompositePlan {
  const runner = params.testRunner ?? 'node';
  if (runner !== 'node') {
    throw ArcError.invalidRequestSchema(
      `Unsupported test runner: '${runner}'. Only 'node' is supported.`,
    );
  }

  const timeoutMs = Math.min(
    Math.max(MIN_TASK5_TIMEOUT_MS, params.maxDurationMs ?? DEFAULT_TASK5_TIMEOUT_MS),
    MAX_TASK5_TIMEOUT_MS,
  );

  const argv: string[] = ['--test', '--test-reporter=tap'];
  if (params.filter) {
    validateTestFilter(params.filter);
    argv.push(`--test-name-pattern=${params.filter}`);
  }
  if (params.testPath) {
    argv.push(params.testPath);
  }

  const steps: CanonicalPlanStep[] = [
    {
      stepId: 'test',
      toolRegistryId: ARC_TEST_NODE_REGISTRY_ID,
      executable: 'node',
      argv,
      cwd: '',
      timeoutMs,
      outputLimitBytes: MAX_TEST_WIRE_BYTES,
      projectCodeExecution: true,
      sideEffectClass: 'EXECUTION',
    },
  ];

  return {
    schemaVersion: '1.0',
    planId: `arc-test-node-${params.workspaceId}`,
    compositeTool: 'arc_test',
    workspaceId: params.workspaceId,
    steps,
  };
}

export function parseTapCounts(output: string): {
  passedCount?: number;
  failedCount?: number;
  skippedCount?: number;
} {
  if (!output) {
    return {};
  }

  const passMatch = /^# pass (\d+)$/m.exec(output);
  const failMatch = /^# fail (\d+)$/m.exec(output);
  const skipMatch = /^# (?:skipped|skip) (\d+)$/m.exec(output);

  if (!passMatch && !failMatch && !skipMatch) {
    return {};
  }

  return {
    ...(passMatch ? { passedCount: parseInt(passMatch[1], 10) } : {}),
    ...(failMatch ? { failedCount: parseInt(failMatch[1], 10) } : {}),
    ...(skipMatch ? { skippedCount: parseInt(skipMatch[1], 10) } : {}),
  };
}

export function sanitizeTestOutput(text: string): string {
  if (!text) return '';
  let sanitized = scrubOutput(text);

  // Redact absolute host paths
  sanitized = sanitized.replace(
    /(?:\/(?:home|tmp|root|Users|var|private|opt|etc|usr|bin|lib)[^\s'",;:]*)/gi,
    '[REDACTED_PATH]',
  );
  sanitized = sanitized.replace(/[a-zA-Z]:\\[^\s'",;:]*/g, '[REDACTED_PATH]');

  // Redact active username
  const user = process.env.USER || process.env.USERNAME;
  if (user && user.length > 1) {
    const userRegex = new RegExp(`\\b${user}\\b`, 'g');
    sanitized = sanitized.replace(userRegex, '[REDACTED_USER]');
  }

  return sanitized;
}

export function boundArcTestResponse(
  response: ArcTestResponse,
  maxBytes: number = MAX_TEST_WIRE_BYTES,
): ArcTestResponse {
  let serialized = JSON.stringify(response, null, 2);
  const currentByteLength = Buffer.byteLength(serialized, 'utf8');

  if (currentByteLength <= maxBytes) {
    return response;
  }

  const cloned: ArcTestResponse = { ...response };
  let budget = maxBytes - 1024;
  while (budget > 0) {
    const buf = Buffer.from(cloned.outputExcerpt, 'utf8');
    if (buf.length > budget) {
      const { slice } = sliceUtf8Safe(buf, 0, budget);
      cloned.outputExcerpt = slice.toString('utf8') + '\n[TRUNCATED]';
      cloned.truncated = true;
    }
    serialized = JSON.stringify(cloned, null, 2);
    if (Buffer.byteLength(serialized, 'utf8') <= maxBytes) {
      break;
    }
    budget = Math.floor(budget / 2);
  }

  if (Buffer.byteLength(JSON.stringify(cloned, null, 2), 'utf8') > maxBytes) {
    cloned.outputExcerpt = '[TRUNCATED]';
    cloned.truncated = true;
  }

  return cloned;
}

export function projectArcTestResponse(
  compositeResult: CompositeExecutionResult,
  target: string,
): ArcTestResponse {
  const step = compositeResult.steps[0];
  const isTimedOut =
    compositeResult.status === 'TIMED_OUT' ||
    Boolean(compositeResult.aggregateTimedOut) ||
    step?.status === 'TIMED_OUT';

  const isFailed =
    !isTimedOut && (compositeResult.status === 'FAILED' || step?.status === 'FAILED');

  const status: 'PASSED' | 'FAILED' | 'TIMED_OUT' = isTimedOut
    ? 'TIMED_OUT'
    : isFailed
      ? 'FAILED'
      : 'PASSED';

  const exitCode: number | null = isTimedOut
    ? null
    : (step?.exitCode ?? (status === 'PASSED' ? 0 : 1));

  const processId = step?.processId ?? 'unknown';
  const durationMs = compositeResult.totalDurationMs;

  const rawCombinedOutput = [step?.stdout, step?.stderr, step?.errorMessage]
    .filter(Boolean)
    .join('\n')
    .trim();

  const isTruncated = Boolean(step?.truncated);
  const scrubbed = sanitizeTestOutput(rawCombinedOutput);
  let outputExcerpt = scrubbed;
  if (isTruncated && !outputExcerpt.includes('[TRUNCATED]')) {
    outputExcerpt = outputExcerpt ? `${outputExcerpt}\n[TRUNCATED]` : '[TRUNCATED]';
  }

  // Parse truthful counts only when execution completed without timeout or truncation
  let counts: { passedCount?: number; failedCount?: number; skippedCount?: number } | undefined;
  if (!isTimedOut && !isTruncated) {
    counts = parseTapCounts(rawCombinedOutput);
  }

  const rawResponse: ArcTestResponse = {
    testRunner: 'node',
    target: target || '.',
    status,
    exitCode,
    durationMs,
    ...(counts?.passedCount !== undefined ? { passedCount: counts.passedCount } : {}),
    ...(counts?.failedCount !== undefined ? { failedCount: counts.failedCount } : {}),
    ...(counts?.skippedCount !== undefined ? { skippedCount: counts.skippedCount } : {}),
    outputExcerpt,
    truncated: isTruncated,
    processId,
  };

  return boundArcTestResponse(rawResponse, MAX_TEST_WIRE_BYTES);
}
