/**
 * Package-internal test entry point for the RC-06 Task-6 audit runtime.
 *
 * This module is the ONLY way a test can reach the Task-6 composition with
 * deterministic seams. It is never exported from the package root, it is not in
 * the package's `exports` map, and every export here is `@internal`, so it
 * disappears from the published declarations under `stripInternal`.
 *
 * It exists to keep the capability-token boundaries exactly where each Task put
 * them: `startup.ts` never imports `CHECKPOINT_TEST_TOKEN` or `ANCHOR_TEST_TOKEN`
 * and so can never be handed a test engine through a production code path. Here,
 * in a module production code does not import, the tokens are used to build the
 * engine factories the caller may pass as `AuditRuntimeCompositionSeams`.
 *
 * Nothing here can weaken a security property. A substitute engine is still a
 * real `Tier2CheckpointEngine` / `Tier3AnchorEngine` constructed through its own
 * capability-gated path, and the seams change only which hooks that engine got —
 * never what a verified store is, what a checkpoint covers, or what a receipt
 * proves.
 *
 * @internal
 */

import type { AuditCheckpointV1 } from '../checkpoint.js';
import { openAuditRuntimeInternal, type AuditConfig, type AuditRuntime } from '../startup.js';
import { createTestTier2CheckpointEngine } from './checkpoint-testing.js';
import { createTestTier3AnchorEngine } from './anchor-testing.js';
import {
  AUDIT_RUNTIME_TEST_TOKEN,
  type AuditRuntimeCompositionSeams,
  type AuditRuntimeTestHooks,
} from './runtime-capability.js';
import type { CheckpointTestHooks } from './checkpoint-capability.js';
import type { AnchorTestHooks } from './anchor-capability.js';

export { AUDIT_RUNTIME_TEST_TOKEN } from './runtime-capability.js';
export type { AuditRuntimeCompositionSeams, AuditRuntimeTestHooks } from './runtime-capability.js';

/** Deterministic seam options for {@link createTestAuditRuntime}. */
export interface AuditRuntimeTestOptions {
  /** Startup and runtime observation/fault seams. */
  hooks?: AuditRuntimeTestHooks;
  /** Task-4 hooks applied to the checkpoint engine the runtime composes. */
  checkpointHooks?: CheckpointTestHooks;
  /** Task-5 hooks applied to the anchor engine the runtime composes. */
  anchorHooks?: AnchorTestHooks;
  /**
   * A full substitute engine factory pair.
   *
   * Supplied when a regression needs an engine this module would not build, such
   * as an anchor engine with a fake transport. When omitted, the real engines
   * are constructed through their capability-gated test factories with the hooks
   * above.
   */
  seams?: AuditRuntimeCompositionSeams;
}

/**
 * Opens the production audit runtime with deterministic seams.
 *
 * The returned object is the same runtime production gets: every stage runs in
 * the same order, against the same code, with the same fail-closed behavior. The
 * seams change observation and fault injection only.
 *
 * @internal
 */
export async function createTestAuditRuntime(
  config: AuditConfig,
  options: AuditRuntimeTestOptions = {},
): Promise<AuditRuntime> {
  const seams: AuditRuntimeCompositionSeams =
    options.seams ??
    ({
      createCheckpointEngine: (checkpointConfig) =>
        createTestTier2CheckpointEngine(checkpointConfig, options.checkpointHooks ?? {}),
      createAnchorEngine: (anchorConfig) =>
        createTestTier3AnchorEngine(anchorConfig, options.anchorHooks ?? {}),
    } satisfies AuditRuntimeCompositionSeams);

  return openAuditRuntimeInternal(config, options.hooks ?? {}, AUDIT_RUNTIME_TEST_TOKEN, seams);
}

/**
 * The durable-completion handoff, exposed so a regression can assert the exact
 * order "checkpoint durable, then anchor" without reaching into the engine.
 *
 * @internal
 */
export type { AuditCheckpointV1 };
