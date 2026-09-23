/**
 * CesSpace ARC — RC-07 Task 1
 * Shared Composite Framework & Internal Deterministic Execution Capability
 *
 * Implements the shared architecture for higher-level engineering-aware tools:
 * - Canonical deterministic plan representation and materialization
 * - Authoritative planHash computation via canonicalJson + SHA-256
 * - Deterministic plan validation and deviation detection (RC07-NEG-007)
 * - Request-local recursion prevention via AsyncLocalStorage (RC07-NEG-003)
 * - Capability-gated deterministic step execution over ControlledProcessRunner
 * - Test-only framework integration harness (RC07-FLOW-01, RC07-FLOW-02)
 *
 * Security Invariants:
 * - ZERO direct imports of node:child_process, child_process, node:fs, or node:fs/promises.
 * - ZERO network primitives (no fetch, http.request, https.request, net.connect, tls.connect).
 * - Client NEVER provides raw executable, raw argv, shell strings, or arbitrary planHash.
 * - All subprocess execution is mediated by ControlledProcessRunner / ProcessRegistry.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { z } from 'zod';

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import type { CompleteActor } from './remote-execution.js';
import { canonicalJson, sha256Hex } from '@cesspace-arc/policy';
import {
  type DeterministicExecutionStep,
  type DeterministicStepResult,
  type ITerminalSubsystem,
  ControlledProcessRunner,
} from '@cesspace-arc/terminal';

// ---------------------------------------------------------------------------
// 1. Deterministic Composite Plan Model
// ---------------------------------------------------------------------------

export type SideEffectClass = 'READ_ONLY' | 'EXECUTION';

export interface CanonicalPlanStep {
  stepId: string;
  toolRegistryId: string;
  executable: string;
  argv: string[];
  cwd: string; // Normalized workspace-relative path (e.g. "" or "sub/dir")
  timeoutMs: number;
  outputLimitBytes: number;
  projectCodeExecution: boolean;
  sideEffectClass: SideEffectClass;
}

export interface CanonicalCompositePlan {
  schemaVersion: '1.0';
  planId: string;
  compositeTool: string;
  workspaceId: string;
  steps: CanonicalPlanStep[];
}

/**
 * Computes authoritative planHash = SHA-256(canonicalJson(canonicalPlan)).
 *
 * Deterministic independent of object key insertion order.
 * Any plan-field modification changes planHash.
 * Ambient PATH, process.env, raw secrets, and absolute paths are excluded.
 */
export function computePlanHash(plan: CanonicalCompositePlan): string {
  return sha256Hex(canonicalJson(plan));
}

// ---------------------------------------------------------------------------
// 2. Plan Deviation Detection (RC07-NEG-007)
// ---------------------------------------------------------------------------

/**
 * Validates an in-memory execution step candidate against the authoritative plan.
 * If any deviation or unexpected parameter is detected, fails closed before spawn.
 */
export function validateStepExecutionAgainstPlan(
  plan: CanonicalCompositePlan,
  stepIndex: number,
  candidate: CanonicalPlanStep,
): void {
  if (stepIndex < 0 || stepIndex >= plan.steps.length) {
    throw ArcError.policyDenied(
      `Plan execution deviation: step index ${stepIndex} out of bounds for plan '${plan.planId}' (total steps: ${plan.steps.length}).`,
    );
  }

  const expected = plan.steps[stepIndex];

  if (expected.stepId !== candidate.stepId) {
    throw ArcError.policyDenied(
      `Plan execution deviation: stepId mismatch at index ${stepIndex} (expected '${expected.stepId}', got '${candidate.stepId}').`,
    );
  }

  if (expected.toolRegistryId !== candidate.toolRegistryId) {
    throw ArcError.policyDenied(
      `Plan execution deviation: toolRegistryId mismatch at step '${expected.stepId}' (expected '${expected.toolRegistryId}', got '${candidate.toolRegistryId}').`,
    );
  }

  if (expected.executable !== candidate.executable) {
    throw ArcError.policyDenied(
      `Plan execution deviation: executable mismatch at step '${expected.stepId}' (expected '${expected.executable}', got '${candidate.executable}').`,
    );
  }

  if (
    expected.argv.length !== candidate.argv.length ||
    expected.argv.some((arg, idx) => arg !== candidate.argv[idx])
  ) {
    throw ArcError.policyDenied(
      `Plan execution deviation: argv mismatch at step '${expected.stepId}'.`,
    );
  }

  if (expected.cwd !== candidate.cwd) {
    throw ArcError.policyDenied(
      `Plan execution deviation: cwd mismatch at step '${expected.stepId}' (expected '${expected.cwd}', got '${candidate.cwd}').`,
    );
  }

  if (expected.timeoutMs !== candidate.timeoutMs) {
    throw ArcError.policyDenied(
      `Plan execution deviation: timeoutMs mismatch at step '${expected.stepId}'.`,
    );
  }

  if (expected.outputLimitBytes !== candidate.outputLimitBytes) {
    throw ArcError.policyDenied(
      `Plan execution deviation: outputLimitBytes mismatch at step '${expected.stepId}'.`,
    );
  }

  if (expected.projectCodeExecution !== candidate.projectCodeExecution) {
    throw ArcError.policyDenied(
      `Plan execution deviation: projectCodeExecution mismatch at step '${expected.stepId}'.`,
    );
  }

  if (expected.sideEffectClass !== candidate.sideEffectClass) {
    throw ArcError.policyDenied(
      `Plan execution deviation: sideEffectClass mismatch at step '${expected.stepId}'.`,
    );
  }
}

// ---------------------------------------------------------------------------
// 3. Recursion & Fan-out Guard (RC07-NEG-003)
// ---------------------------------------------------------------------------

interface CompositeCallContext {
  activeCompositeTools: string[];
}

const compositeContextStorage = new AsyncLocalStorage<CompositeCallContext>();

/**
 * Runs a composite tool execution within an isolated request-local call context.
 * Detects and blocks recursive self-invocation (A -> A) and call cycles (A -> B -> A).
 */
export async function enterCompositeInvocation<T>(
  toolName: string,
  fn: () => Promise<T>,
): Promise<T> {
  const currentContext = compositeContextStorage.getStore();
  const stack = currentContext ? [...currentContext.activeCompositeTools] : [];

  if (stack.includes(toolName)) {
    throw ArcError.policyDenied(
      `Recursive composite invocation detected for tool '${toolName}'. Call cycle is forbidden.`,
    );
  }

  if (stack.length > 0) {
    throw ArcError.policyDenied(
      `Nested composite invocation is forbidden: '${toolName}' invoked within '${stack.join(' -> ')}'.`,
    );
  }

  stack.push(toolName);
  return compositeContextStorage.run({ activeCompositeTools: stack }, fn);
}

// ---------------------------------------------------------------------------
// 4. Closed Plan Materialization Interface
// ---------------------------------------------------------------------------

export interface PlanMaterializerContext {
  compositeTool: string;
  businessParameters: Record<string, unknown>;
  workspaceId: string;
  workspaceRoot: string;
}

export type PlanMaterializer = (context: PlanMaterializerContext) => CanonicalCompositePlan;

// ---------------------------------------------------------------------------
// 5. Test-Only Integration Harness (Section 3 & 23)
// ---------------------------------------------------------------------------

export const TEST_COMPOSITE_HARNESS_TOKEN = Symbol('arc.test.composite.framework.harness');

/**
 * Test-only harness allowing Task-1 integration tests to exercise the framework
 * without registering any synthetic tool in production schemas or route tables.
 */
export interface TestCompositeHarness {
  readonly [TEST_COMPOSITE_HARNESS_TOKEN]: true;
  readonly toolName: string;
  readonly schema: z.ZodTypeAny;
  readonly materializer: PlanMaterializer;
  readonly requiresApproval?: boolean;
}

/**
 * Creates an in-process test harness instance.
 * Production server factory never invokes this.
 */
export function createTestCompositeHarness(options: {
  toolName: string;
  schema: z.ZodTypeAny;
  materializer: PlanMaterializer;
  requiresApproval?: boolean;
}): TestCompositeHarness {
  return {
    [TEST_COMPOSITE_HARNESS_TOKEN]: true,
    toolName: options.toolName,
    schema: options.schema,
    materializer: options.materializer,
    requiresApproval: options.requiresApproval ?? false,
  };
}

// ---------------------------------------------------------------------------
// 6. Composite Plan Execution Engine
// ---------------------------------------------------------------------------

export interface CompositeStepExecutionResult {
  stepId: string;
  toolRegistryId: string;
  status: 'PASSED' | 'FAILED' | 'SKIPPED';
  durationMs: number;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  processId?: string;
  errorMessage?: string;
}

export interface CompositeExecutionResult {
  toolName: string;
  planId: string;
  planHash: string;
  status: 'SUCCESS' | 'FAILED';
  totalDurationMs: number;
  steps: CompositeStepExecutionResult[];
}

export async function executeCompositePlan(options: {
  plan: CanonicalCompositePlan;
  actor: CompleteActor;
  targetWorkspace: PolicyEvaluationContext['targetWorkspace'];
  terminalSubsystem?: ITerminalSubsystem;
}): Promise<CompositeExecutionResult> {
  const { plan, actor, targetWorkspace, terminalSubsystem } = options;
  const startMs = Date.now();
  const stepResults: CompositeStepExecutionResult[] = [];
  let overallFailed = false;

  if (!terminalSubsystem) {
    throw ArcError.internalError('Terminal subsystem is required for composite execution.');
  }

  if (!(terminalSubsystem instanceof ControlledProcessRunner)) {
    throw ArcError.internalError(
      'Terminal subsystem must be a ControlledProcessRunner to execute deterministic steps.',
    );
  }

  const capability = terminalSubsystem.getInternalExecutionCapability();
  const planHash = computePlanHash(plan);

  for (let i = 0; i < plan.steps.length; i++) {
    const step = plan.steps[i];

    if (overallFailed) {
      stepResults.push({
        stepId: step.stepId,
        toolRegistryId: step.toolRegistryId,
        status: 'SKIPPED',
        durationMs: 0,
        exitCode: null,
        signal: null,
        stdout: '',
        stderr: '',
      });
      continue;
    }

    // Verify step against plan (RC07-NEG-007)
    validateStepExecutionAgainstPlan(plan, i, step);

    const stepStart = Date.now();
    try {
      const stepExecution: DeterministicExecutionStep = {
        stepId: step.stepId,
        executable: step.executable,
        args: step.argv,
        cwd: step.cwd,
        timeoutMs: step.timeoutMs,
        outputLimitBytes: step.outputLimitBytes,
        projectCodeExecution: step.projectCodeExecution,
        sideEffectClass: step.sideEffectClass,
      };

      const result: DeterministicStepResult = await terminalSubsystem.executeDeterministicStep(
        stepExecution,
        actor,
        targetWorkspace,
        capability,
      );

      const stepPassed = result.exitCode === 0 && !result.timedOut;
      if (!stepPassed) {
        overallFailed = true;
      }

      stepResults.push({
        stepId: step.stepId,
        toolRegistryId: step.toolRegistryId,
        status: stepPassed ? 'PASSED' : 'FAILED',
        durationMs: Date.now() - stepStart,
        exitCode: result.exitCode,
        signal: result.signal,
        stdout: result.stdout,
        stderr: result.stderr,
        processId: result.processId,
        errorMessage: result.timedOut
          ? 'Process execution timed out.'
          : result.exitCode !== 0
            ? `Process exited with code ${result.exitCode}.`
            : undefined,
      });
    } catch (stepErr: unknown) {
      overallFailed = true;
      const errMsg = stepErr instanceof Error ? stepErr.message : String(stepErr);
      stepResults.push({
        stepId: step.stepId,
        toolRegistryId: step.toolRegistryId,
        status: 'FAILED',
        durationMs: Date.now() - stepStart,
        exitCode: null,
        signal: null,
        stdout: '',
        stderr: '',
        errorMessage: errMsg,
      });
    }
  }

  return {
    toolName: plan.compositeTool,
    planId: plan.planId,
    planHash,
    status: overallFailed ? 'FAILED' : 'SUCCESS',
    totalDurationMs: Date.now() - startMs,
    steps: stepResults,
  };
}
