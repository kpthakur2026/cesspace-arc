/**
 * Package-internal execution logic and response projection for arc_verify (RC-07 Task 4).
 * STRICTLY package-internal and NEVER exported from public package root or exports map.
 * @internal
 */

import { ArcError, type ArcVerifyResponse, type ArcVerifyStepResult } from '@cesspace-arc/protocol';
import { scrubOutput, sliceUtf8Safe } from '@cesspace-arc/processes';
import {
  type CanonicalCompositePlan,
  type CanonicalPlanStep,
  type CompositeExecutionResult,
  type DeterministicExecutionRegistry,
  VERIFY_FORMAT_REGISTRY_ID,
  VERIFY_LINT_REGISTRY_ID,
  VERIFY_TYPECHECK_REGISTRY_ID,
  VERIFY_TEST_REGISTRY_ID,
} from '../composite-framework.js';

export const MAX_VERIFY_WIRE_BYTES = 256 * 1024; // 262,144 bytes
export const DEFAULT_TASK4_STEP_TIMEOUT_MS = 30_000;
export const DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS = 120_000;

export interface VerifyStepDefinition {
  stepId: 'format' | 'lint' | 'typecheck' | 'test';
  toolRegistryId: string;
  executable: string;
  argv: string[];
}

export const VERIFY_STEP_DEFINITIONS: readonly VerifyStepDefinition[] = Object.freeze([
  {
    stepId: 'format',
    toolRegistryId: VERIFY_FORMAT_REGISTRY_ID,
    executable: 'prettier',
    argv: ['--check', '.'],
  },
  {
    stepId: 'lint',
    toolRegistryId: VERIFY_LINT_REGISTRY_ID,
    executable: 'eslint',
    argv: ['.'],
  },
  {
    stepId: 'typecheck',
    toolRegistryId: VERIFY_TYPECHECK_REGISTRY_ID,
    executable: 'tsc',
    argv: ['--noEmit'],
  },
  {
    stepId: 'test',
    toolRegistryId: VERIFY_TEST_REGISTRY_ID,
    executable: 'node',
    argv: ['--test'],
  },
]);

export function materializeArcVerifyPlan(params: {
  suite?: string;
  workspaceId: string;
  workspaceRoot: string;
  registry: DeterministicExecutionRegistry;
  stepTimeoutMs?: number;
}): CanonicalCompositePlan {
  const suite = params.suite || 'all';
  if (!['all', 'format', 'lint', 'typecheck', 'test'].includes(suite)) {
    throw ArcError.invalidRequestSchema(`Unknown verification suite: '${suite}'.`);
  }

  const stepTimeout = Math.min(
    params.stepTimeoutMs ?? DEFAULT_TASK4_STEP_TIMEOUT_MS,
    DEFAULT_TASK4_STEP_TIMEOUT_MS,
  );

  const selectedStepDefs =
    suite === 'all'
      ? VERIFY_STEP_DEFINITIONS
      : VERIFY_STEP_DEFINITIONS.filter((s) => s.stepId === suite);

  const steps: CanonicalPlanStep[] = selectedStepDefs.map((def) => ({
    stepId: def.stepId,
    toolRegistryId: def.toolRegistryId,
    executable: def.executable,
    argv: [...def.argv],
    cwd: '',
    timeoutMs: stepTimeout,
    outputLimitBytes: 65_536,
    projectCodeExecution: true,
    sideEffectClass: 'READ_ONLY',
  }));

  return {
    schemaVersion: '1.0',
    planId: `arc-verify-${suite}-${params.workspaceId}`,
    compositeTool: 'arc_verify',
    workspaceId: params.workspaceId,
    steps,
  };
}

export function sanitizeVerificationOutput(text: string): string {
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

export function boundArcVerifyResponse(
  response: ArcVerifyResponse,
  maxBytes: number = MAX_VERIFY_WIRE_BYTES,
): ArcVerifyResponse {
  let serialized = JSON.stringify(response, null, 2);
  const currentByteLength = Buffer.byteLength(serialized, 'utf8');

  if (currentByteLength <= maxBytes) {
    return response;
  }

  // Deep clone to safely mutate outputExcerpts
  const cloned: ArcVerifyResponse = {
    ...response,
    steps: response.steps.map((s) => ({ ...s })),
  };

  // Find steps that have outputExcerpts to truncate
  const stepsWithOutput = cloned.steps.filter((s) => s.outputExcerpt.length > 0);
  if (stepsWithOutput.length === 0) {
    return cloned;
  }

  // Iteratively reduce output excerpts until JSON serialized length is <= maxBytes
  let budgetPerStep = Math.floor(maxBytes / (stepsWithOutput.length * 2));
  while (budgetPerStep > 0) {
    for (const step of stepsWithOutput) {
      const buf = Buffer.from(step.outputExcerpt, 'utf8');
      if (buf.length > budgetPerStep) {
        const { slice } = sliceUtf8Safe(buf, 0, budgetPerStep);
        step.outputExcerpt = slice.toString('utf8') + '\n[TRUNCATED]';
        step.truncated = true;
      }
    }
    serialized = JSON.stringify(cloned, null, 2);
    if (Buffer.byteLength(serialized, 'utf8') <= maxBytes) {
      break;
    }
    budgetPerStep = Math.floor(budgetPerStep / 2);
  }

  // If still slightly over, clear excerpts completely to guarantee the invariant
  if (Buffer.byteLength(JSON.stringify(cloned, null, 2), 'utf8') > maxBytes) {
    for (const step of stepsWithOutput) {
      step.outputExcerpt = '[TRUNCATED]';
      step.truncated = true;
    }
  }

  return cloned;
}

export function projectArcVerifyResponse(
  compositeResult: CompositeExecutionResult,
  suite: 'all' | 'format' | 'lint' | 'typecheck' | 'test',
): ArcVerifyResponse {
  let overallStatus: 'PASSED' | 'FAILED' | 'TIMED_OUT' = 'PASSED';
  if (compositeResult.status === 'TIMED_OUT') {
    overallStatus = 'TIMED_OUT';
  } else if (compositeResult.status === 'FAILED') {
    overallStatus = 'FAILED';
  }

  let failedStep: string | undefined;

  const steps: ArcVerifyStepResult[] = compositeResult.steps.map((s) => {
    if ((s.status === 'FAILED' || s.status === 'TIMED_OUT') && !failedStep) {
      failedStep = s.stepId;
    }

    let logicalExecutable = s.toolRegistryId;
    let logicalArgs: string[] = [];

    if (s.stepId === 'format') {
      logicalExecutable = 'prettier';
      logicalArgs = ['--check', '.'];
    } else if (s.stepId === 'lint') {
      logicalExecutable = 'eslint';
      logicalArgs = ['.'];
    } else if (s.stepId === 'typecheck') {
      logicalExecutable = 'tsc';
      logicalArgs = ['--noEmit'];
    } else if (s.stepId === 'test') {
      logicalExecutable = 'node';
      logicalArgs = ['--test'];
    }

    const rawCombinedOutput = [s.stdout, s.stderr].filter(Boolean).join('\n').trim();
    const scrubbed = sanitizeVerificationOutput(rawCombinedOutput);
    const isTruncated = Boolean(s.truncated);
    let outputExcerpt = scrubbed;
    if (isTruncated && !outputExcerpt.includes('[TRUNCATED]')) {
      outputExcerpt = outputExcerpt ? `${outputExcerpt}\n[TRUNCATED]` : '[TRUNCATED]';
    }

    return {
      stepName: s.stepId,
      executable: logicalExecutable,
      args: logicalArgs,
      status: s.status,
      exitCode: s.exitCode,
      durationMs: s.durationMs,
      outputExcerpt,
      truncated: isTruncated,
    };
  });

  const rawResponse: ArcVerifyResponse = {
    suite,
    status: overallStatus,
    totalDurationMs: compositeResult.totalDurationMs,
    steps,
    ...(failedStep ? { failedStep } : {}),
  };

  return boundArcVerifyResponse(rawResponse, MAX_VERIFY_WIRE_BYTES);
}
