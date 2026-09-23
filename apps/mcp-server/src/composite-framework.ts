/**
 * CesSpace ARC — RC-07 Task 1
 * Shared Composite Framework & Internal Deterministic Execution Capability
 *
 * Implements the shared architecture for higher-level engineering-aware tools:
 * - Closed server-owned deterministic execution registry (Section 7, 8, 9)
 * - Canonical deterministic plan representation and materialization
 * - Authoritative planHash computation via canonicalJson + SHA-256
 * - Deterministic plan validation and deviation detection (RC07-NEG-007)
 * - Request-local recursion prevention via AsyncLocalStorage (RC07-NEG-003)
 * - Capability-gated deterministic step execution via IInternalDeterministicExecutor
 * - Test-only framework integration harness (RC07-FLOW-01, RC07-FLOW-02)
 *
 * Security Invariants:
 * - ZERO direct imports of node:child_process, child_process, node:fs, or node:fs/promises.
 * - ZERO network primitives (no fetch, http.request, https.request, net.connect, tls.connect).
 * - Client NEVER provides raw executable, raw argv, shell strings, or arbitrary planHash.
 * - All subprocess execution is mediated by IInternalDeterministicExecutor / ProcessRegistry.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { z } from 'zod';

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import type { CompleteActor } from './remote-execution.js';
import { canonicalJson, sha256Hex } from '@cesspace-arc/policy';
import {
  type DeterministicExecutionStep,
  type DeterministicStepResult,
  type IInternalDeterministicExecutor,
  isAuthorizedDeterministicExecutor,
} from '@cesspace-arc/terminal';

// ---------------------------------------------------------------------------
// 1. Closed Server-Owned Deterministic Execution Registry (Section 7, 8, 9)
// ---------------------------------------------------------------------------

export type SideEffectClass = 'READ_ONLY' | 'EXECUTION';

export interface DeterministicRegistryEntry {
  readonly registryId: string;
  readonly executable: string;
  readonly permittedArgvTemplate: readonly string[];
  readonly sideEffectClass: SideEffectClass;
  readonly projectCodeExecution: boolean;
  readonly timeoutCeilingMs: number;
  readonly maxOutputBytesCeiling: number;
  readonly allowCwdSubdirectory: boolean;
}

export class DeterministicExecutionRegistry {
  private readonly entries = new Map<string, DeterministicRegistryEntry>();

  constructor(initialEntries: readonly DeterministicRegistryEntry[] = []) {
    for (const entry of initialEntries) {
      this.entries.set(entry.registryId, Object.freeze({ ...entry }));
    }
  }

  public getEntry(registryId: string): DeterministicRegistryEntry | undefined {
    return this.entries.get(registryId);
  }

  public hasEntry(registryId: string): boolean {
    return this.entries.has(registryId);
  }

  public listEntryIds(): string[] {
    return Array.from(this.entries.keys());
  }
}

/**
 * Fixed test-only registry entry executing active Node --version.
 * Harmless, deterministic, zero network, zero mutation.
 */
export const TEST_NODE_VERSION_REGISTRY_ID = 'test-node-version-v1';

export const TEST_NODE_VERSION_ENTRY: DeterministicRegistryEntry = Object.freeze({
  registryId: TEST_NODE_VERSION_REGISTRY_ID,
  executable: 'node',
  permittedArgvTemplate: Object.freeze(['--version']),
  sideEffectClass: 'READ_ONLY',
  projectCodeExecution: false,
  timeoutCeilingMs: 10_000,
  maxOutputBytesCeiling: 65_536,
  allowCwdSubdirectory: false,
});

/**
 * Creates the production deterministic execution registry.
 * In Task 1, contains zero Task-4/Task-5 project execution entries.
 */
export function createProductionDeterministicRegistry(): DeterministicExecutionRegistry {
  return new DeterministicExecutionRegistry([]);
}

/**
 * Creates a test-only deterministic execution registry populated with the test node entry.
 */
export function createTestDeterministicRegistry(
  extraEntries: readonly DeterministicRegistryEntry[] = [],
): DeterministicExecutionRegistry {
  return new DeterministicExecutionRegistry([TEST_NODE_VERSION_ENTRY, ...extraEntries]);
}

/**
 * Validates a plan step candidate against the authoritative closed execution registry.
 * Fails closed if executable, argv, side effect class, cwd, or ceilings mismatch.
 */
export function validateStepAgainstRegistry(
  step: CanonicalPlanStep,
  registry: DeterministicExecutionRegistry,
): void {
  const entry = registry.getEntry(step.toolRegistryId);
  if (!entry) {
    throw ArcError.policyDenied(
      `Registry violation: unknown execution registry entry '${step.toolRegistryId}'.`,
    );
  }
  if (step.executable !== entry.executable) {
    throw ArcError.policyDenied(
      `Registry violation: executable '${step.executable}' does not match registry entry '${entry.registryId}' ('${entry.executable}').`,
    );
  }
  if (
    step.argv.length !== entry.permittedArgvTemplate.length ||
    step.argv.some((arg, idx) => arg !== entry.permittedArgvTemplate[idx])
  ) {
    throw ArcError.policyDenied(
      `Registry violation: argv does not match permitted template for registry entry '${entry.registryId}'.`,
    );
  }
  if (step.sideEffectClass !== entry.sideEffectClass) {
    throw ArcError.policyDenied(
      `Registry violation: sideEffectClass mismatch for '${entry.registryId}'.`,
    );
  }
  if (step.projectCodeExecution !== entry.projectCodeExecution) {
    throw ArcError.policyDenied(
      `Registry violation: projectCodeExecution mismatch for '${entry.registryId}'.`,
    );
  }
  if (step.timeoutMs > entry.timeoutCeilingMs) {
    throw ArcError.policyDenied(
      `Registry violation: timeoutMs ${step.timeoutMs} exceeds ceiling ${entry.timeoutCeilingMs} for '${entry.registryId}'.`,
    );
  }
  if (step.outputLimitBytes > entry.maxOutputBytesCeiling) {
    throw ArcError.policyDenied(
      `Registry violation: outputLimitBytes ${step.outputLimitBytes} exceeds ceiling ${entry.maxOutputBytesCeiling} for '${entry.registryId}'.`,
    );
  }
  if (!entry.allowCwdSubdirectory && step.cwd !== '') {
    throw ArcError.policyDenied(
      `Registry violation: cwd subdirectory '${step.cwd}' not permitted for '${entry.registryId}'.`,
    );
  }
}

// ---------------------------------------------------------------------------
// 2. Deterministic Composite Plan Model & Immutability (Section 10)
// ---------------------------------------------------------------------------

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
 * Clones a plan deeply to protect against external mutation.
 */
export function clonePlan(plan: CanonicalCompositePlan): CanonicalCompositePlan {
  return {
    schemaVersion: plan.schemaVersion,
    planId: plan.planId,
    compositeTool: plan.compositeTool,
    workspaceId: plan.workspaceId,
    steps: plan.steps.map((s) => ({
      ...s,
      argv: [...s.argv],
    })),
  };
}

/**
 * Deep freezes an admitted plan so in-memory mutations are blocked.
 */
export function deepFreezePlan(plan: CanonicalCompositePlan): CanonicalCompositePlan {
  const cloned = clonePlan(plan);
  cloned.steps.forEach((step) => {
    Object.freeze(step.argv);
    Object.freeze(step);
  });
  Object.freeze(cloned.steps);
  return Object.freeze(cloned);
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
  registry: DeterministicExecutionRegistry;
}

export type PlanMaterializer = (context: PlanMaterializerContext) => CanonicalCompositePlan;

// ---------------------------------------------------------------------------
// 5. Test-Only Integration Harness (Section 9, 14, 15)
// ---------------------------------------------------------------------------

export const TEST_COMPOSITE_HARNESS_TOKEN = Symbol('arc.test.composite.framework.harness');

/**
 * Test-only harness allowing Task-1 integration tests to exercise the framework
 * without registering any synthetic tool in production schemas or route tables.
 * Policy authorization is governed exclusively by DeclarativePolicyEngine (Section 14).
 */
export interface TestCompositeHarness {
  readonly [TEST_COMPOSITE_HARNESS_TOKEN]: true;
  readonly toolName: string;
  readonly schema: z.ZodTypeAny;
  readonly materializer: PlanMaterializer;
  readonly registry: DeterministicExecutionRegistry;
  readonly testPostAdmissionMutationHook?: (
    plan: CanonicalCompositePlan,
  ) => CanonicalCompositePlan | void;
}

/**
 * Creates an in-process test harness instance.
 * Production server factory never invokes this.
 */
export function createTestCompositeHarness(options: {
  toolName: string;
  schema: z.ZodTypeAny;
  materializer: PlanMaterializer;
  registry?: DeterministicExecutionRegistry;
  testPostAdmissionMutationHook?: (plan: CanonicalCompositePlan) => CanonicalCompositePlan | void;
}): TestCompositeHarness {
  return {
    [TEST_COMPOSITE_HARNESS_TOKEN]: true,
    toolName: options.toolName,
    schema: options.schema,
    materializer: options.materializer,
    registry: options.registry ?? createTestDeterministicRegistry(),
    testPostAdmissionMutationHook: options.testPostAdmissionMutationHook,
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
  admittedPlanHash: string;
  actor: CompleteActor;
  targetWorkspace: PolicyEvaluationContext['targetWorkspace'];
  internalExecutor?: IInternalDeterministicExecutor;
  registry: DeterministicExecutionRegistry;
  testPostAdmissionMutationHook?: (plan: CanonicalCompositePlan) => CanonicalCompositePlan | void;
}): Promise<CompositeExecutionResult> {
  const {
    admittedPlanHash,
    actor,
    targetWorkspace,
    internalExecutor,
    registry,
    testPostAdmissionMutationHook,
  } = options;
  let plan = options.plan;
  const startMs = Date.now();
  const stepResults: CompositeStepExecutionResult[] = [];
  let overallFailed = false;

  if (!internalExecutor || !isAuthorizedDeterministicExecutor(internalExecutor)) {
    throw ArcError.internalError('Privileged internal execution authority is unavailable.');
  }

  // TEST-ONLY in-process seam: attempt post-admission alteration before execution
  if (testPostAdmissionMutationHook) {
    const mutated = testPostAdmissionMutationHook(plan);
    if (mutated) {
      plan = mutated;
    }
  }

  // Post-admission deviation resistance (Section 10 & 28)
  const recomputedPlanHash = computePlanHash(plan);
  if (recomputedPlanHash !== admittedPlanHash) {
    throw ArcError.policyDenied(
      `Plan execution deviation: recomputed plan hash '${recomputedPlanHash}' does not match admitted plan hash '${admittedPlanHash}'.`,
    );
  }

  // Pre-validate all steps against closed registry before any execution
  for (const step of plan.steps) {
    validateStepAgainstRegistry(step, registry);
  }

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

    // Verify step against plan
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

      const result: DeterministicStepResult = await internalExecutor.executeDeterministicStep(
        stepExecution,
        actor,
        targetWorkspace,
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
    planHash: admittedPlanHash,
    status: overallFailed ? 'FAILED' : 'SUCCESS',
    totalDurationMs: Date.now() - startMs,
    steps: stepResults,
  };
}
