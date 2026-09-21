/**
 * Package-internal capability token and deterministic seams for the RC-06 Task-6
 * production audit runtime.
 *
 * Mirrors `checkpoint-capability.ts`, `rotation-capability.ts` and
 * `anchor-capability.ts`: the seams below are reachable ONLY through the
 * unforgeable symbols declared here, this module is never exported from the
 * package root, and it is not listed in the package's `exports` map. A
 * production caller — and therefore anything reachable from `ArcServerConfig`,
 * the environment, the CLI, an MCP parameter, a remote header or a request body
 * — cannot supply a stage observer, a stage fault, a recovery fault, or a
 * substitute checkpoint/anchor engine.
 *
 * Nothing here can weaken a security property. The hooks change only WHEN a
 * value is observed and WHETHER a step is forced to fail; they cannot change
 * what a verified store is, what a checkpoint covers, what a receipt proves, or
 * what a startup stage has already done before it is observed.
 *
 * @internal
 */

import type { AnchorTestHooks } from './anchor-capability.js';
import type { CheckpointTestHooks } from './checkpoint-capability.js';
import type { RecoveryTestHooks } from './recovery-testing.js';
import type { AuditStartupStage } from '../startup.js';
import type { Tier2CheckpointEngine, Tier2CheckpointEngineConfig } from '../checkpoint.js';
import type { Tier3AnchorEngine, Tier3AnchorEngineConfig } from '../anchor.js';

export const AUDIT_RUNTIME_TEST_TOKEN = Symbol('AUDIT_RUNTIME_TEST_TOKEN');

/**
 * Deterministic seams for the Task-6 startup and runtime regressions.
 *
 * @internal
 */
export interface AuditRuntimeTestHooks {
  /**
   * Observes each startup stage at the moment it is entered, in the order the
   * runtime really executes them.
   *
   * This is the observation the §39 exact-order regression reads. It cannot
   * reorder anything: it is called from inside the sequence, and returning from
   * it does not advance the sequence.
   */
  onStartupStage?: (stage: AuditStartupStage) => void;

  /**
   * Forces the named stage to fail closed BEFORE it performs its work.
   *
   * Used to prove that every authority boundary halts startup with no
   * privileged service exposed, and that the acquisition made so far is
   * released without deleting historical evidence.
   */
  failStartupStage?: AuditStartupStage;

  /** Forces the append of the Nth recovery record to fail. */
  failRecoveryAppendAtIndex?: number;

  /**
   * Forces the durable append of a record in this lifecycle phase to fail.
   *
   * The seam is keyed on the record's own frozen `lifecycle.phase`, not on a
   * call index, because that is what the security properties are stated in:
   * "the subsystem receives ZERO calls when STARTED persistence fails" (§11,
   * §12, §13) and "a failed terminal append latches `DEGRADED_AUDIT_FAILURE`"
   * (§15, §16, §17). Keying on the phase makes those provable without the
   * regression having to predict how many approval, policy or denial records an
   * invocation happens to write before it.
   *
   * It counts only {@link AuditRuntime.appendRecord} calls — the runtime's own
   * durable writes, never the stage-10 recovery appends, which are a startup
   * operation rather than a runtime one.
   *
   * This seam can only make a write fail. It cannot fabricate a record, skip
   * verification, advance a cursor, or weaken a boundary.
   */
  failAppendPhase?: 'STARTED' | 'COMPLETED' | 'DENIED';

  /**
   * The error code the forced append failure carries. Defaults to
   * `AUDIT_APPEND_FAILED`. Bounded to the coded-error vocabulary.
   */
  failAppendErrorCode?: string;

  /** Task-2 torn-tail seams, forwarded to the ONE Task-2 repair implementation. */
  recoveryHooks?: RecoveryTestHooks;
}

/**
 * Deterministic engine construction seams.
 *
 * The production composition constructs its checkpoint and anchor engines
 * through the supported production factories. A regression that needs a fake
 * anchor transport supplies a substitute factory here instead of reaching into
 * the engines' own capability tokens, so the token boundaries stay exactly where
 * each Task put them.
 *
 * `createAnchorEngineForStartup` is not interchangeable with the standalone
 * `openTier3AnchorEngine` factory: the runtime's stage 6 is receipt verification
 * and its stage 7 is spool reconciliation, so the engine stage 6 opens must
 * arrive verified and *unreconciled*. A substitute that reconciled on the way in
 * would make the frozen stage order unobservable.
 *
 * @internal
 */
export interface AuditRuntimeCompositionSeams {
  createCheckpointEngine?: (
    config: Tier2CheckpointEngineConfig,
    hooks?: CheckpointTestHooks,
  ) => Promise<Tier2CheckpointEngine>;
  createAnchorEngineForStartup?: (
    config: Tier3AnchorEngineConfig,
    hooks?: AnchorTestHooks,
  ) => Promise<Tier3AnchorEngine>;
}
