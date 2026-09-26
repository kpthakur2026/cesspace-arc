/**
 * RC-06 Task 6 — the production audit runtime composition.
 *
 * This module is the ONE place where the Task-1..5 primitives are composed into
 * the authoritative production startup and runtime path frozen by
 * `docs/architecture/rc06-scope-acceptance.md` §22.1:
 *
 * ```text
 *  1 platform security primitives
 *  2 single-writer audit.lock
 *  3 audit-store metadata + pinned trust roots
 *  4 retained primary history verification
 *  5 checkpoint artifact chain + Ed25519 signatures
 *  6 anchor receipt verification (Tier 3 enabled only)
 *  7 anchor spool reconciliation (States A..F)
 *  8 recoverable torn active tail repair
 *  9 dangling STARTED operation detection
 * 10 RECOVERY_INDETERMINATE append + fdatasync durability
 * 11 runtime cursors and cache
 * 12 privileged MCP tool service  (owned by the caller, never by this module)
 * ```
 *
 * Three properties motivate the shape of this file rather than a helper-by-
 * helper call list:
 *
 *  - **One lock, one storage instance, one chain.** `audit.lock` is acquired
 *    once, at stage 2, and is held across every later stage and for the whole
 *    process lifetime. Nothing here verifies the store unlocked, releases a
 *    lock, or opens a second `PersistentAuditStorage` for the same directory.
 *    The single storage is handed over through the unforgeable
 *    `RECOVERY_HANDOFF_TOKEN`, exactly as Task-2 restart recovery hands it over,
 *    so no caller can manufacture a "verified" storage.
 *
 *  - **Reuse, never re-implementation.** Every stage delegates to the primitive
 *    that already owns it: Task-1 platform/directory/descriptor authority,
 *    Task-2 torn-tail repair and canonical recovery-record construction, Task-3
 *    retained-history verification and rotation, Task-4 checkpoint engine and
 *    trust-root pinning, Task-5 anchor engine and reconciliation. No
 *    cryptographic, filesystem or serialization logic is duplicated here.
 *
 *  - **Fail closed before stage 12.** Any error at any stage propagates. The
 *    partially acquired resources are released in reverse acquisition order
 *    without deleting a single byte of historical evidence, and no privileged
 *    service exists to be reached.
 *
 * The composition differs from `recoverPersistentAuditStorage()` in exactly one
 * deliberate way, and it is not a reordering: that entry point verifies the
 * ACTIVE segment alone, which is the correct Task-2 contract for restart
 * recovery of a store whose active segment begins at sequence 1, but is not the
 * full-history verification §22.1 step 4 requires of a store that has rotated.
 * Task 6 therefore drives `verifyRetainedPrimaryHistory()` (Task 3) for stages 4
 * and 8. The torn-tail sidecar/truncate/fsync sequence is NOT re-implemented:
 * both callers drive `repairTornActiveTailInternal()`, and both construct
 * recovery evidence with `buildRecoveryIndeterminateRecord()`.
 *
 * @packageDocumentation
 */

import fs from 'node:fs';
import fsConstants from 'node:constants';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  ArcError,
  type AuditStoreMetadataV1,
  type PersistentAuditRecordV1,
} from '@cesspace-arc/protocol';

import {
  ACTIVE_SEGMENT_FILENAME,
  DEFAULT_AUDIT_DIR,
  PersistentAuditStorage,
  createCodedError,
  getProcessUid,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  validatePlatformCapabilities,
  type PersistentAuditStorageConfig,
} from './storage.js';
import { acquireWriterLock, type AuditLockAcquisition } from './lock.js';
import {
  createStoreMetadataFile,
  loadStoreMetadataFile,
  normalizeStoreMetadataConfig,
  validateStoreMetadataConsistency,
} from './metadata.js';
import {
  RotatingAuditStore,
  assertArchiveCapacityAvailable,
  assertAuditStorageCapacity,
  verifyRetainedPrimaryHistory,
  type RetainedPrimaryHistoryVerificationResult,
} from './rotation.js';
import {
  CHECKPOINT_FILENAME,
  Tier2CheckpointEngine,
  computeCheckpointPublicKeyFingerprint,
  openTier2CheckpointEngine,
  parseAndValidateCheckpointLineV1,
  type AuditCheckpointV1,
} from './checkpoint.js';
import {
  Tier3AnchorEngine,
  computeAnchorReceiptPublicKeyFingerprint,
  openTier3AnchorEngineForStartup,
  validateAnchorEndpoint,
  type AnchorState,
} from './anchor.js';
import { RECOVERY_HANDOFF_TOKEN } from './internal/recovery-capability.js';
import { buildRecoveryIndeterminateRecord, repairTornActiveTailInternal } from './recovery.js';
import {
  listRetainedSegmentSources,
  streamLedgerLines,
  streamRetainedRecords,
  verifyOfflineStore,
} from './verify.js';
import {
  AUDIT_RUNTIME_TEST_TOKEN,
  type AuditRuntimeCompositionSeams,
  type AuditRuntimeTestHooks,
} from './internal/runtime-capability.js';

/* -------------------------------------------------------------------------- *
 * Frozen production configuration (rc06 §24.2)
 * -------------------------------------------------------------------------- */

/**
 * The frozen production audit configuration model.
 *
 * Auditing is MANDATORY in production: there is deliberately no
 * `enabled: boolean`. A process either has a durable audit chain or it does not
 * serve privileged work.
 *
 * Every field is trusted launch configuration. The checkpoint signing key is
 * supplied ONLY as a filesystem path, and that path is never derivable from a
 * command-line argument, an environment variable, an MCP parameter, a remote
 * header or a request body. No environment variable carries `signingKeyPath`,
 * PEM bytes, private key bytes, or any equivalent secret material: the object is
 * built by the process that launches the server, and the only thing that ever
 * reads the key is the hardened Task-4 loader.
 */
export interface AuditConfig {
  /**
   * Storage directory. Defaults to the frozen default when omitted.
   *
   * The default is never surfaced to a client: health metadata reports audit
   * STATE, never the directory.
   */
  directory?: string;
  /** Absolute path to the Ed25519 PKCS#8 private key that signs checkpoints. */
  signingKeyPath: string;
  /** Absolute path to the Ed25519 SPKI public key the checkpoints verify under. */
  publicKeyPath: string;
  /** Required when the store records `anchorMode: ENABLED`; refused otherwise. */
  anchorEndpoint?: string;
  /** Required when the store records `anchorMode: ENABLED`; refused otherwise. */
  anchorReceiptPublicKeyPath?: string;
}

/* -------------------------------------------------------------------------- *
 * Startup stages
 * -------------------------------------------------------------------------- */

/**
 * The frozen startup stages, in the exact normative order.
 *
 * The identifiers are an observable contract: a regression reads the stages the
 * runtime actually recorded while it ran, so the order is checked by behavior
 * rather than by reading this file.
 */
export type AuditStartupStage =
  | 'PLATFORM_SECURITY_PRIMITIVES'
  | 'SINGLE_WRITER_LOCK'
  | 'STORE_METADATA_AND_TRUST_ROOTS'
  | 'PRIMARY_HISTORY_VERIFICATION'
  | 'CHECKPOINT_CHAIN_VERIFICATION'
  | 'ANCHOR_RECEIPT_VERIFICATION'
  | 'ANCHOR_SPOOL_RECONCILIATION'
  | 'TORN_TAIL_RECOVERY'
  | 'DANGLING_OPERATION_DETECTION'
  | 'RECOVERY_APPEND_DURABILITY'
  | 'RUNTIME_CURSORS';

/** The canonical stage order, as a declaration. */
export const AUDIT_STARTUP_STAGE_ORDER: readonly AuditStartupStage[] = Object.freeze([
  'PLATFORM_SECURITY_PRIMITIVES',
  'SINGLE_WRITER_LOCK',
  'STORE_METADATA_AND_TRUST_ROOTS',
  'PRIMARY_HISTORY_VERIFICATION',
  'CHECKPOINT_CHAIN_VERIFICATION',
  'ANCHOR_RECEIPT_VERIFICATION',
  'ANCHOR_SPOOL_RECONCILIATION',
  'TORN_TAIL_RECOVERY',
  'DANGLING_OPERATION_DETECTION',
  'RECOVERY_APPEND_DURABILITY',
  'RUNTIME_CURSORS',
] as const);

/* -------------------------------------------------------------------------- *
 * Bounded health metadata (rc06 §22.2, §31)
 * -------------------------------------------------------------------------- */

/**
 * The closed, non-sensitive audit health block.
 *
 * It carries STATE and COUNTS only. It never carries the audit directory, a
 * checkpoint key path, an anchor key path, private key material, a public key
 * body, an anchor endpoint, a receipt body, a spool filename or hash, or any
 * other host path.
 */
export interface AuditHealthMetadata {
  persistence: 'ACTIVE' | 'DEGRADED' | 'FAILED';
  integrity: 'VERIFIED' | 'FAILED';
  sequence: number;
  lastCheckpointSequence: number | null;
  unanchoredCheckpoints: number;
  anchorState: 'DISABLED' | 'HEALTHY' | 'DEGRADED' | 'FULL';
  indeterminateRecoveries: number;
}

/**
 * Bounded audit evidence summary for stage evidence inspection (RC-07 Task 7).
 */
export interface BoundedAuditEvidenceSummary {
  storeId: string;
  sequence: number;
  integrity: 'VERIFIED' | 'FAILED';
  terminalRecordHash: string;
  lastCheckpointSequence: number | null;
  checkpointHash?: string;
}

/**
 * Options for stage evidence inspection (RC-07 Task 7).
 */
export interface StageEvidenceInspectionOptions {
  /**
   * The operationId of the current arc_stage_evidence invocation's STARTED record,
   * which must be excluded from pre-existing evidence calculations.
   */
  excludeOperationId?: string;
}

/* -------------------------------------------------------------------------- *
 * Runtime surface
 * -------------------------------------------------------------------------- */

/**
 * The production audit runtime: one durable chain, one writer, one lock.
 *
 * Everything a privileged operation needs from the audit layer goes through
 * this object. It is deliberately narrow — there is no cursor setter, no way to
 * supply a record hash, no way to select a checkpoint, and no way to clear the
 * degraded latch.
 */
export interface AuditRuntime {
  /** The authoritative durable primary store for this process. */
  readonly store: RotatingAuditStore;
  /** The directory the store lives in. Never surfaced to a client. */
  readonly auditDir: string;

  /**
   * Appends one durable primary record and drives the checkpoint cadence.
   *
   * The record is durable — written and `fdatasync`ed — before this resolves,
   * and any checkpoint the cadence implies is durable and handed to Tier 3
   * before it resolves too.
   */
  appendRecord(
    record: Omit<PersistentAuditRecordV1, 'sequenceNumber' | 'integrity' | 'schemaVersion'>,
  ): Promise<PersistentAuditRecordV1>;

  /**
   * The single fail-closed gate every privileged dispatch passes first.
   *
   * Refuses when the process-wide degraded latch is set, when the Tier-3 anchor
   * is at its spool or integrity ceiling, and when the frozen archive or byte
   * budget is exhausted. It executes nothing and mutates nothing.
   */
  assertPrivilegedOperationsAllowed(): void;

  /**
   * Latches the process-wide `DEGRADED_AUDIT_FAILURE` state.
   *
   * Called when post-dispatch audit durability became uncertain. Once latched it
   * is never cleared in-process: recovery requires a restart and a successful
   * frozen startup verification.
   */
  latchDegradedAuditFailure(): void;

  /** True once the process-wide degraded latch is set. */
  isDegraded(): boolean;

  /** The bounded, non-sensitive health block. */
  getHealth(): AuditHealthMetadata;

  /** The next sequence number a primary append will carry. */
  getNextSequence(): number;

  /** The `recordHash` the next primary append will reference. */
  getLastRecordHash(): string;

  /** The last durable checkpoint sequence, or null when there is none. */
  getLastCheckpointSequence(): number | null;

  /** Checkpoints that are durable but not yet acknowledged by the anchor. */
  getUnanchoredCheckpointCount(): number;

  /** Records recovered as `RECOVERY_INDETERMINATE` during this startup. */
  getIndeterminateRecoveryCount(): number;

  /** True when the anchor engine is enabled for this store. */
  isAnchorEnabled(): boolean;

  /** Closes every resource in one deterministic order. Idempotent. */
  close(): Promise<void>;

  /**
   * Performs an authoritative, machine-verifiable inspection of the persistent audit ledger
   * for stage evidence aggregation (RC-07 Task 7).
   */
  inspectStageEvidence(
    options?: StageEvidenceInspectionOptions,
  ): Promise<BoundedAuditEvidenceSummary>;

  /**
   * The startup stages this runtime actually executed, in order.
   *
   * @internal Removed from declarations under `stripInternal`: it exists so a
   * regression can observe the real sequence instead of reading source text.
   */
  _getStartupStages(): readonly AuditStartupStage[];

  /**
   * True once startup reached the end of stage 11.
   *
   * @internal See {@link AuditRuntime._getStartupStages}.
   */
  _isStartupComplete(): boolean;
}

/* -------------------------------------------------------------------------- *
 * Internals
 * -------------------------------------------------------------------------- */

/** Runs an async cleanup step, ignoring a failure to release. */
async function closeQuietly(operation: () => Promise<void> | undefined): Promise<void> {
  try {
    await operation();
  } catch {
    // A resource that is already gone is not a shutdown failure.
  }
}

/** Runs a synchronous cleanup step, ignoring a failure to release. */
function closeQuietlySync(operation: () => void): void {
  try {
    operation();
  } catch {
    // See above.
  }
}

/** fsyncs a directory so a create inside it is durable. */
function syncDirectory(dir: string): void {
  const fd = fs.openSync(dir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function assertNonEmptyString(value: unknown, field: string): void {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw createCodedError('AUDIT_CONFIG_INVALID', `audit configuration requires a ${field}`);
  }
}

/**
 * Maps the Task-5 anchor state onto the frozen §31 health vocabulary.
 *
 * `FAILED` maps onto the bounded `DEGRADED` label because the §31 set has no
 * separate entry for it; the distinction is preserved by `persistence`, which
 * reports `DEGRADED` for a failed engine. No state is ever reported as `HEALTHY`
 * unless it is.
 */
function toHealthAnchorState(state: AnchorState): AuditHealthMetadata['anchorState'] {
  switch (state) {
    case 'DISABLED':
      return 'DISABLED';
    case 'HEALTHY':
      return 'HEALTHY';
    case 'DEGRADED':
      return 'DEGRADED';
    case 'FULL':
      return 'FULL';
    case 'FAILED':
      return 'DEGRADED';
  }
}

class AuditRuntimeImpl implements AuditRuntime {
  public readonly store: RotatingAuditStore;
  public readonly auditDir: string;

  private readonly expectedUid: number;
  private readonly lock: AuditLockAcquisition;
  private readonly storage: PersistentAuditStorage;
  private readonly checkpoints: Tier2CheckpointEngine;
  private readonly anchor: Tier3AnchorEngine | null;
  private readonly stages: AuditStartupStage[];
  private readonly indeterminateRecoveries: number;
  private readonly publicKeyPath: string;
  private readonly anchorReceiptPublicKeyPath?: string;

  /**
   * The runtime append fault seam, or `undefined` in production.
   *
   * @internal Carried as the two resolved values rather than the hooks object,
   * so the runtime holds no reference to a caller-supplied accumulator.
   */
  private readonly failAppendPhase: 'STARTED' | 'COMPLETED' | 'DENIED' | undefined;
  private readonly failAppendErrorCode: string;

  /**
   * Durable checkpoints awaiting the Tier-3 handoff, oldest first.
   *
   * The checkpoint engine pushes here from its durable-completion hook, which
   * fires inside its serialized section strictly after the artifact and its
   * `fdatasync` have both succeeded. The queue is drained by
   * {@link appendRecord} once the durable-primary operation that produced the
   * checkpoint has fully completed — including any rotation it triggered.
   *
   * That deferral is load-bearing, not a convenience. A ROTATION-triggered
   * checkpoint is sealed before Task 3's physical critical section runs, so at
   * the instant it becomes durable the archived segment does not exist yet and
   * the checkpoint's coverage is not yet an observable boundary of the retained
   * primary history. Handing it to Tier 3 there would be refused as a checkpoint
   * at a sequence the frozen cadence does not require. By the time this queue is
   * drained, the rotation has completed and the boundary is real.
   */
  private readonly checkpointQueue: AuditCheckpointV1[];

  /**
   * Serializes the whole durable-primary operation: the append, the durable
   * checkpoint cadence, and the Tier-3 handoff of everything that cadence
   * produced.
   *
   * The store already serializes the write itself, but "one strict global
   * sequence" (rc06 §43) has to cover the handoff too: a checkpoint may not be
   * handed to Tier 3 while another invocation's rotation is still in flight, and
   * no second checkpoint may be emitted before this one has been handed over.
   * Chaining the whole operation is what provides both.
   */
  private appendChain: Promise<unknown> = Promise.resolve();

  private degraded = false;
  private closed = false;
  /**
   * Always true, because an `AuditRuntimeImpl` is only ever constructed as the
   * LAST act of `executeStartup`, after stage 11 has completed.
   *
   * Keeping it as a field rather than deleting it is deliberate: it is the
   * observable that makes "no privileged dispatch before step 12" checkable at
   * the runtime boundary, and there is no setter anywhere that could make it
   * true on a runtime that had not reached that point.
   */
  private readonly startupComplete = true;
  /**
   * Set when a durable checkpoint could not be handed to the anchor engine.
   *
   * It is not the process-wide `DEGRADED_AUDIT_FAILURE` latch: the primary
   * record and the checkpoint are both durable, so no audit durability is in
   * doubt and a restart is not required. It is backpressure, answered the way
   * the frozen Task-5 `FULL` state is answered — by refusing the next privileged
   * dispatch. In practice the anchor engine's own state is already `FULL` or
   * `FAILED` and its gate refuses first; this flag covers the residual window
   * where the engine still reported a healthy state but the dispatch failed.
   */
  private anchorHandoffFailure = false;

  public constructor(init: {
    store: RotatingAuditStore;
    auditDir: string;
    expectedUid: number;
    lock: AuditLockAcquisition;
    storage: PersistentAuditStorage;
    checkpoints: Tier2CheckpointEngine;
    anchor: Tier3AnchorEngine | null;
    stages: AuditStartupStage[];
    indeterminateRecoveries: number;
    /** The queue the checkpoint engine hands durable checkpoints to. */
    checkpointQueue: AuditCheckpointV1[];
    publicKeyPath: string;
    anchorReceiptPublicKeyPath?: string;
    failAppendPhase?: 'STARTED' | 'COMPLETED' | 'DENIED';
    failAppendErrorCode?: string;
  }) {
    this.store = init.store;
    this.auditDir = init.auditDir;
    this.expectedUid = init.expectedUid;
    this.lock = init.lock;
    this.storage = init.storage;
    this.checkpoints = init.checkpoints;
    this.anchor = init.anchor;
    this.stages = init.stages;
    this.indeterminateRecoveries = init.indeterminateRecoveries;
    this.checkpointQueue = init.checkpointQueue;
    this.publicKeyPath = init.publicKeyPath;
    this.anchorReceiptPublicKeyPath = init.anchorReceiptPublicKeyPath;
    this.failAppendPhase = init.failAppendPhase;
    this.failAppendErrorCode = init.failAppendErrorCode ?? 'AUDIT_APPEND_FAILED';
  }

  /** @internal */
  public _getStartupStages(): readonly AuditStartupStage[] {
    return [...this.stages];
  }

  /** @internal */
  public _isStartupComplete(): boolean {
    return this.startupComplete;
  }

  /**
   * Records that a durable checkpoint could not be handed to Tier 3.
   *
   * Declared with a real `#` private name rather than a TypeScript `private`
   * modifier: `private` erases to a plain prototype member, so it would remain
   * reachable — and callable — from outside the class at runtime. This is a
   * runtime latch that gates privileged dispatch, so nothing outside the runtime
   * may be able to set it.
   */
  #noteAnchorHandoffFailure(): void {
    this.anchorHandoffFailure = true;
  }

  public appendRecord(
    record: Omit<PersistentAuditRecordV1, 'sequenceNumber' | 'integrity' | 'schemaVersion'>,
  ): Promise<PersistentAuditRecordV1> {
    if (this.closed) {
      throw createCodedError('AUDIT_RUNTIME_CLOSED', 'audit runtime is closed');
    }
    if (this.degraded) {
      throw createCodedError(
        'AUDIT_RUNTIME_DEGRADED',
        'audit durability is degraded; no further durable record may be written',
      );
    }

    // One strict global sequence (rc06 §43). The chain is extended BEFORE the
    // operation runs, so two callers that reach this method in a given order are
    // durably written, checkpointed and handed off in exactly that order,
    // whatever `await` boundaries lie between them. The chain itself never
    // rejects: each caller receives its own promise, and a failure propagates to
    // that caller alone.
    const run = this.appendChain.then(() => this.appendSerialized(record));
    this.appendChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * One durable-primary operation, from the append to the Tier-3 handoff.
   *
   * The frozen order is: primary record durable, then the durable-primary
   * checkpoint cadence, then the Tier-3 handoff of everything that cadence
   * produced. Nothing here calls the checkpoint engine before the primary
   * record's `fdatasync()` — `store.append` resolving IS that proof.
   */
  private async appendSerialized(
    record: Omit<PersistentAuditRecordV1, 'sequenceNumber' | 'integrity' | 'schemaVersion'>,
  ): Promise<PersistentAuditRecordV1> {
    if (this.failAppendPhase !== undefined && record.lifecycle?.phase === this.failAppendPhase) {
      throw createCodedError(
        this.failAppendErrorCode,
        'the durable primary append did not complete',
      );
    }

    const appended = await this.store.append(record);

    // A rotation the append triggered has already sealed a checkpoint at this
    // exact sequence, and `checkpointAfterDurablePrimary` recognises that
    // (covered === 0) without writing a second artifact or reporting a cadence
    // violation.
    //
    // A failure here is an audit integrity failure. The primary record is
    // durable, so it propagates: the caller must not continue privileged
    // dispatch, and the checkpoint engine has already latched its own `failed`
    // state, which {@link assertPrivilegedOperationsAllowed} refuses on.
    await this.checkpoints.checkpointAfterDurablePrimary({
      sequenceNumber: appended.sequenceNumber,
      recordHash: appended.integrity.recordHash,
    });

    // Only now, with any rotation complete and this invocation's checkpoint
    // durable and observable, is a checkpoint handed to Tier 3 — one at a time,
    // in emission order, before any later append can produce another.
    await this.drainCheckpointQueue();

    return appended;
  }

  /**
   * Hands every durable, not-yet-dispatched checkpoint to Tier 3, in order.
   *
   * A handoff failure is backpressure, not uncertain durability: the checkpoint
   * and the primary record it covers are both already on disk, and a restart
   * reconstructs the missing spool entry from the durable checkpoint artifact.
   * So the failure is recorded and the anchor gate refuses the next privileged
   * dispatch; no evidence is deleted to make room.
   */
  private async drainCheckpointQueue(): Promise<void> {
    while (this.checkpointQueue.length > 0) {
      const checkpoint = this.checkpointQueue.shift() as AuditCheckpointV1;
      const engine = this.anchor;
      if (engine === null) continue;
      try {
        await engine.anchorCheckpoint(checkpoint);
      } catch {
        this.#noteAnchorHandoffFailure();
      }
    }
  }

  public assertPrivilegedOperationsAllowed(): void {
    if (this.closed) {
      throw createCodedError('AUDIT_RUNTIME_CLOSED', 'audit runtime is closed');
    }
    if (this.degraded) {
      throw createCodedError(
        'AUDIT_RUNTIME_DEGRADED',
        'audit durability is degraded; privileged operations are halted until restart',
      );
    }
    // The Tier-2 checkpoint authority is checked first, because a checkpoint
    // that failed closed is an audit integrity failure in its own right (rc06
    // §24) even when the anchor is disabled and has nothing to say about it.
    if (this.checkpoints.getCheckpointState().failed) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID_STATE',
        'the checkpoint engine is failed closed; privileged operations are halted',
      );
    }
    // Tier-3 backpressure and integrity, through the Task-5 authority. A
    // DISABLED store returns immediately and claims nothing.
    this.anchor?.assertPrivilegedOperationsAllowed();
    if (this.anchorHandoffFailure) {
      throw createCodedError(
        'ANCHOR_SPOOL_FULL',
        'a durable checkpoint could not be handed to the anchor engine',
      );
    }
    // Frozen storage ceilings. Never deletes, never reclaims, never wraps.
    assertArchiveCapacityAvailable(this.auditDir, this.expectedUid);
    assertAuditStorageCapacity(this.auditDir, this.expectedUid, 0);
  }

  public latchDegradedAuditFailure(): void {
    this.degraded = true;
  }

  public isDegraded(): boolean {
    return this.degraded;
  }

  public getNextSequence(): number {
    return this.storage.getCurrentSequence();
  }

  public getLastRecordHash(): string {
    return this.storage.getLastRecordHash();
  }

  public getLastCheckpointSequence(): number | null {
    return this.checkpoints.getCheckpointState().lastCheckpointSequence;
  }

  public getUnanchoredCheckpointCount(): number {
    return this.anchor?.getStatus().unanchoredCheckpoints ?? 0;
  }

  public getIndeterminateRecoveryCount(): number {
    return this.indeterminateRecoveries;
  }

  public isAnchorEnabled(): boolean {
    return this.anchor !== null && this.anchor.getStatus().anchorMode === 'ENABLED';
  }

  public getHealth(): AuditHealthMetadata {
    const anchorStatus = this.anchor?.getStatus();
    const checkpointState = this.checkpoints.getCheckpointState();
    const anchorFailed = anchorStatus?.anchorState === 'FAILED';
    const integrityFailed = anchorFailed || checkpointState.failed;

    return {
      persistence: this.degraded || anchorFailed ? 'DEGRADED' : 'ACTIVE',
      integrity: integrityFailed ? 'FAILED' : 'VERIFIED',
      sequence: this.storage.getCurrentSequence(),
      lastCheckpointSequence: checkpointState.lastCheckpointSequence,
      unanchoredCheckpoints: anchorStatus?.unanchoredCheckpoints ?? 0,
      anchorState:
        anchorStatus === undefined ? 'DISABLED' : toHealthAnchorState(anchorStatus.anchorState),
      indeterminateRecoveries: this.indeterminateRecoveries,
    };
  }

  public async inspectStageEvidence(
    options?: StageEvidenceInspectionOptions,
  ): Promise<BoundedAuditEvidenceSummary> {
    const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const storeId = this.storage.getMetadata()?.storeId ?? 'unknown';

    if (
      this.storage.getCurrentSequence() <= 1 &&
      this.storage.getLastRecordHash() === genesisHash
    ) {
      throw ArcError.evidenceNotMet('Audit store contains zero durable records.');
    }

    try {
      const verification = await verifyOfflineStore({
        directory: this.auditDir,
        checkpointPublicKeyPath: this.publicKeyPath,
        anchorReceiptPublicKeyPath: this.anchorReceiptPublicKeyPath,
        expectedUid: this.expectedUid,
      });

      if (verification.primary.recordCount === 0) {
        throw ArcError.evidenceNotMet('Audit store contains zero durable records.');
      }

      if (options?.excludeOperationId) {
        const recent = this.store.getRecentRecords();
        let startedRecord = recent.find(
          (r) =>
            r.lifecycle?.operationId === options.excludeOperationId &&
            r.lifecycle?.phase === 'STARTED',
        );

        if (!startedRecord) {
          const sources = listRetainedSegmentSources(this.auditDir, this.expectedUid);
          for await (const rec of streamRetainedRecords(sources, {
            expectedUid: this.expectedUid,
          })) {
            if (
              rec.lifecycle?.operationId === options.excludeOperationId &&
              rec.lifecycle?.phase === 'STARTED'
            ) {
              startedRecord = rec;
              break;
            }
          }
        }

        if (startedRecord) {
          if (startedRecord.sequenceNumber <= 1) {
            throw ArcError.evidenceNotMet(
              'Audit store contains zero durable records prior to this invocation.',
            );
          }

          const precedingSequence = startedRecord.sequenceNumber - 1;
          const precedingHash = startedRecord.integrity.previousRecordHash;

          let precedingCpSequence: number | null = null;
          let precedingCpHash: string | undefined = undefined;

          const cpPath = path.join(this.auditDir, CHECKPOINT_FILENAME);
          if (fs.existsSync(cpPath)) {
            for await (const line of streamLedgerLines(
              cpPath,
              CHECKPOINT_FILENAME,
              this.expectedUid,
            )) {
              try {
                const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
                if (checkpoint.sequenceEnd < startedRecord.sequenceNumber) {
                  precedingCpSequence = checkpoint.sequenceEnd;
                  precedingCpHash = checkpoint.checkpointHash;
                }
              } catch {
                // Ignore line parsing errors here; verifyOfflineStore would have failed if invalid
              }
            }
          }

          return {
            storeId: verification.storeId,
            sequence: precedingSequence,
            integrity: 'VERIFIED',
            terminalRecordHash: precedingHash,
            lastCheckpointSequence: precedingCpSequence,
            ...(precedingCpHash ? { checkpointHash: precedingCpHash } : {}),
          };
        }
      }

      return {
        storeId: verification.storeId,
        sequence: verification.primary.terminalSequence,
        integrity: 'VERIFIED',
        terminalRecordHash: verification.primary.terminalRecordHash,
        lastCheckpointSequence: verification.checkpoints.lastCheckpointSequence,
        ...(verification.checkpoints.lastCheckpointHash
          ? { checkpointHash: verification.checkpoints.lastCheckpointHash }
          : {}),
      };
    } catch (err: unknown) {
      if (err instanceof ArcError && err.code === 'EVIDENCE_NOT_MET') {
        throw err;
      }
      const seq = Math.max(0, this.storage.getCurrentSequence() - 1);
      const lastHash = this.storage.getLastRecordHash();
      const lastCpSeq = this.checkpoints.getCheckpointState().lastCheckpointSequence;

      return {
        storeId,
        sequence: seq,
        integrity: 'FAILED',
        terminalRecordHash: lastHash,
        lastCheckpointSequence: lastCpSeq,
      };
    }
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    // Deterministic ownership order: reverse of acquisition. Every step is
    // individually guarded so one failing resource cannot strand the lock or the
    // active descriptor, and nothing here deletes historical evidence.
    await closeQuietly(() => this.anchor?.close());
    closeQuietlySync(() => this.checkpoints.close());
    closeQuietlySync(() => this.storage.close());
    // Idempotent, and explicit: the writer lock is released even if closing the
    // storage threw before it could release it itself.
    closeQuietlySync(() => this.lock.release());
  }
}

/* -------------------------------------------------------------------------- *
 * Composition entry point
 * -------------------------------------------------------------------------- */

/**
 * Executes the frozen startup sequence and returns the composed runtime.
 *
 * Stage 12 — binding a transport and serving privileged MCP tool calls — is
 * deliberately NOT part of this function. The caller owns it and must not begin
 * it until this promise resolves; that separation is what makes "no privileged
 * dispatch before step 12" checkable rather than assumed.
 *
 * On any failure every resource acquired so far is released in reverse order and
 * the original error propagates unchanged. No historical evidence is deleted.
 */
export async function openAuditRuntime(config: AuditConfig): Promise<AuditRuntime> {
  return executeStartup(config, {}, undefined, {});
}

/**
 * Package-internal composition entry point carrying deterministic seams.
 *
 * @internal
 */
export async function openAuditRuntimeInternal(
  config: AuditConfig,
  hooks: AuditRuntimeTestHooks = {},
  token?: symbol,
  seams: AuditRuntimeCompositionSeams = {},
): Promise<AuditRuntime> {
  if (token !== AUDIT_RUNTIME_TEST_TOKEN) {
    throw createCodedError(
      'AUDIT_RUNTIME_CAPABILITY_REQUIRED',
      'audit runtime test seams require the package-internal capability token',
    );
  }
  return executeStartup(config, hooks, token, seams);
}

async function executeStartup(
  config: AuditConfig,
  hooks: AuditRuntimeTestHooks,
  token: symbol | undefined,
  seams: AuditRuntimeCompositionSeams,
): Promise<AuditRuntime> {
  if (config === null || typeof config !== 'object') {
    throw createCodedError('AUDIT_CONFIG_INVALID', 'audit configuration is required');
  }
  assertNonEmptyString(config.signingKeyPath, 'signingKeyPath');
  assertNonEmptyString(config.publicKeyPath, 'publicKeyPath');

  const auditDir = config.directory ?? DEFAULT_AUDIT_DIR;
  const expectedUid = getProcessUid();
  const stages: AuditStartupStage[] = [];

  const enter = (stage: AuditStartupStage): void => {
    if (token !== undefined && hooks.failStartupStage === stage) {
      throw createCodedError(
        'AUDIT_RUNTIME_STAGE_FAILED',
        `simulated startup stage failure at ${stage}`,
      );
    }
    stages.push(stage);
    if (token !== undefined) hooks.onStartupStage?.(stage);
  };

  // Resources acquired so far, released in reverse order on any failure.
  let lock: AuditLockAcquisition | null = null;
  let storage: PersistentAuditStorage | null = null;
  let checkpoints: Tier2CheckpointEngine | null = null;
  let anchor: Tier3AnchorEngine | null = null;

  const releaseAll = async (): Promise<void> => {
    await closeQuietly(() => anchor?.close());
    closeQuietlySync(() => checkpoints?.close());
    closeQuietlySync(() => storage?.close());
    closeQuietlySync(() => lock?.release());
  };

  try {
    // ------------------------------------------------------------------ 1 ---
    enter('PLATFORM_SECURITY_PRIMITIVES');
    validatePlatformCapabilities();

    // ------------------------------------------------------------------ 2 ---
    enter('SINGLE_WRITER_LOCK');
    // Directory authority is a precondition of creating `audit.lock` inside it,
    // not a separate stage: the lock is never written into a directory whose
    // ownership, mode, symlink status or workspace overlap has not been proven.
    validateAuditDirectory(auditDir, { createIfMissing: true, expectedUid });
    lock = acquireWriterLock({ auditDir, expectedUid });

    // ------------------------------------------------------------------ 3 ---
    enter('STORE_METADATA_AND_TRUST_ROOTS');
    // The checkpoint trust root is pinned from the configured public key file
    // with no private-key involvement, then compared against the store's durable
    // pin. This runs BEFORE the checkpoint engine loads a signing key, so an
    // operator who pointed a store at the wrong trust root learns it before any
    // private key is read.
    const checkpointFingerprint = computeCheckpointPublicKeyFingerprint(config.publicKeyPath, {
      expectedUid,
    });
    // The pinned anchor trust root is resolved from trusted launch configuration
    // in this same stage, and BEFORE the store is loaded, so an existing store
    // is compared against the configuration that will actually be used rather
    // than against an assumed default. Both fingerprints are public trust roots
    // read without any private-key involvement.
    const metadata = loadOrCreateStoreMetadata(
      auditDir,
      expectedUid,
      checkpointFingerprint,
      resolveConfiguredAnchorTrust(config),
    );
    resolveAnchorTrustRoot(config, metadata);

    // ------------------------------------------------------------------ 4 ---
    enter('PRIMARY_HISTORY_VERIFICATION');
    // The classification is recorded, NOT acted on: §22.1.1 defers every tail
    // mutation to stage 8, and no byte of the store is touched here. The slot
    // exists because stage 8 replaces the result with the re-verified one.
    const primarySlot: { current: RetainedPrimaryHistoryVerificationResult } = {
      current: await verifyRetainedPrimaryHistory(auditDir, expectedUid),
    };
    const tornTailClassified = primarySlot.current.status === 'RECOVERABLE_TORN_ACTIVE_TAIL';

    // ------------------------------------------------------------------ 5 ---
    enter('CHECKPOINT_CHAIN_VERIFICATION');
    const handoffSlot: { anchor: Tier3AnchorEngine | null } = { anchor: null };

    // Durable checkpoints awaiting the Tier-3 handoff, oldest first.
    //
    // The engine hands each checkpoint here from its durable-completion hook,
    // which runs inside its serialized section strictly after the artifact and
    // its `fdatasync` both succeeded. The queue is drained by the runtime at the
    // end of the durable-primary operation that produced the checkpoint — after
    // any rotation it triggered has completed — so a rotation-triggered
    // checkpoint is only ever offered to Tier 3 once its coverage is an
    // observable boundary of the retained primary history (rc06 §25).
    const checkpointQueue: AuditCheckpointV1[] = [];

    const checkpointConfig = {
      directory: auditDir,
      signingKeyPath: config.signingKeyPath,
      publicKeyPath: config.publicKeyPath,
      onDurableCheckpoint: async (checkpoint: AuditCheckpointV1): Promise<void> => {
        checkpointQueue.push(checkpoint);
      },
    };
    checkpoints =
      seams.createCheckpointEngine === undefined
        ? await openTier2CheckpointEngine(checkpointConfig)
        : await seams.createCheckpointEngine(checkpointConfig);

    // ------------------------------------------------------------------ 6 ---
    enter('ANCHOR_RECEIPT_VERIFICATION');
    if (metadata.anchorMode === 'ENABLED') {
      const anchorConfig = {
        directory: auditDir,
        anchorEndpoint: config.anchorEndpoint,
        anchorReceiptPublicKeyPath: config.anchorReceiptPublicKeyPath,
        checkpointPublicKeyPath: config.publicKeyPath,
      };
      // The engine arrives verified and *unreconciled*: this stage's authority is
      // the receipt ledger and its bindings to the verified checkpoint history,
      // not the spool. Opening a reconciled engine here would make stage 6 the
      // first point at which a State C reconstruction, a State D removal or the
      // spool directory itself can appear, which is stage 7's authority.
      anchor =
        seams.createAnchorEngineForStartup === undefined
          ? await openTier3AnchorEngineForStartup(anchorConfig)
          : await seams.createAnchorEngineForStartup(anchorConfig);
      handoffSlot.anchor = anchor;
      // Read-only verification of the ledger and its checkpoint bindings. It
      // creates nothing and removes nothing, so the spool directory and every
      // entry in it are exactly as the store left them when this returns.
      await anchor.verifyAnchorEvidence();
      if (anchor.getStatus().anchorState === 'FAILED') {
        throw createCodedError(
          'ANCHOR_ENGINE_FAILED',
          'anchor engine reported an integrity failure during startup verification',
        );
      }
    }

    // ------------------------------------------------------------------ 7 ---
    enter('ANCHOR_SPOOL_RECONCILIATION');
    if (anchor !== null) {
      // States A..F: pending entries retained, missing entries reconstructed
      // from the durable checkpoint artifact, stale entries removed only on the
      // authority of a durable receipt. This is the first operation in the
      // startup sequence with the authority to create, change or remove a spool
      // artifact, and it applies only the plan stage 6 verified — an engine that
      // staged nothing refuses rather than reconciling on an unverified basis.
      await anchor.applyAnchorReconciliation();
      if (anchor.getStatus().anchorState === 'FAILED') {
        throw createCodedError(
          'ANCHOR_ENGINE_FAILED',
          'anchor reconciliation reported an integrity failure',
        );
      }
    }

    // ------------------------------------------------------------------ 8 ---
    enter('TORN_TAIL_RECOVERY');
    if (tornTailClassified) {
      const active = primarySlot.current.active;
      if (active === null || active.tornBytes === null) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          'torn-tail classification without a torn active segment',
        );
      }
      const lastVerifiedByteOffset = active.physicalByteLength - active.tornBytes.length;
      if (lastVerifiedByteOffset < 0) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          'torn tail exceeds the active segment length',
        );
      }

      await repairTornActiveTailInternal(
        auditDir,
        expectedUid,
        {
          lastVerifiedByteOffset,
          tornBytes: active.tornBytes,
          activeIdentity: active.identity,
        },
        // §22.1.1: the repaired active segment MUST be re-verified, and the
        // whole retained history is re-verified because that is the only
        // re-verification that is correct for a store with archives.
        async () => {
          const reverified = await verifyRetainedPrimaryHistory(auditDir, expectedUid);
          if (reverified.status !== 'VERIFIED') {
            throw createCodedError(
              'AUDIT_RECOVERY_FAILED',
              're-verification of the retained history failed after torn tail truncation',
            );
          }
          primarySlot.current = reverified;
        },
        token === undefined ? undefined : hooks.recoveryHooks,
      );
    }

    // ------------------------------------------------------------------ 9 ---
    enter('DANGLING_OPERATION_DETECTION');
    const danglingOperations = primarySlot.current.danglingOperations;

    // ----------------------------------------------------------------- 10 ---
    enter('RECOVERY_APPEND_DURABILITY');
    storage = acquireVerifiedStorage(auditDir, expectedUid, metadata, lock, primarySlot.current);

    let indeterminateRecoveries = 0;
    for (let index = 0; index < danglingOperations.length; index++) {
      const danglingOp = danglingOperations[index];
      const recoveryTimestamp = new Date().toISOString();
      const recoveryRecord = buildRecoveryIndeterminateRecord(danglingOp, recoveryTimestamp);

      if (token !== undefined && hooks.failRecoveryAppendAtIndex === index) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          `simulated recovery append failure at index ${index}`,
        );
      }

      try {
        await storage.append(recoveryRecord);
        indeterminateRecoveries++;
      } catch (cause) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          `failed to append recovery record for dangling operation ${danglingOp.operationId}`,
          { cause },
        );
      }
    }

    // ----------------------------------------------------------------- 11 ---
    enter('RUNTIME_CURSORS');
    const store = new RotatingAuditStore(storage, { sealer: checkpoints });

    const runtime = new AuditRuntimeImpl({
      store,
      auditDir,
      expectedUid,
      lock,
      storage,
      checkpoints,
      anchor,
      stages,
      indeterminateRecoveries,
      checkpointQueue,
      publicKeyPath: config.publicKeyPath,
      anchorReceiptPublicKeyPath: config.anchorReceiptPublicKeyPath,
      ...(token === undefined
        ? {}
        : {
            ...(hooks.failAppendPhase === undefined
              ? {}
              : { failAppendPhase: hooks.failAppendPhase }),
            ...(hooks.failAppendErrorCode === undefined
              ? {}
              : { failAppendErrorCode: hooks.failAppendErrorCode }),
          }),
    });

    // Stage 12 — binding a transport and serving privileged MCP tool calls — is
    // the caller's, and this runtime is only ever reachable once stages 1..11
    // have completed. There is no setter: `_isStartupComplete()` cannot be made
    // true on a runtime that did not reach this point.

    // Ownership transfers to the runtime: a failure after this point must not
    // close resources the returned object now owns.
    lock = null;
    storage = null;
    checkpoints = null;
    anchor = null;

    return runtime;
  } catch (err) {
    await releaseAll();
    throw err;
  }
}

/**
 * Loads `audit-store.json`, creating it for a fresh store.
 *
 * A store with no metadata file but a NON-EMPTY active segment is a store whose
 * authority record was removed; creating a fresh one would adopt evidence ARC
 * never committed to. That is refused rather than repaired — which is the same
 * rule Task-1's loader already applies, re-applied here because the create path
 * is what makes it necessary.
 */
function loadOrCreateStoreMetadata(
  auditDir: string,
  expectedUid: number,
  checkpointFingerprint: string,
  anchorTrust: ConfiguredAnchorTrust,
): AuditStoreMetadataV1 {
  const normalized = normalizeStoreMetadataConfig({
    checkpointPublicKeyFingerprint: checkpointFingerprint,
    ...(anchorTrust.anchorMode === 'ENABLED'
      ? {
          anchorMode: 'ENABLED' as const,
          anchorReceiptPublicKeyFingerprint: anchorTrust.anchorReceiptPublicKeyFingerprint,
        }
      : {}),
  });

  let loaded: AuditStoreMetadataV1;
  try {
    loaded = loadStoreMetadataFile(auditDir, expectedUid);
  } catch (err: unknown) {
    if ((err as { code?: string })?.code !== 'METADATA_MISSING') throw err;
    const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
    if (fs.existsSync(activePath) && fs.lstatSync(activePath).size > 0) {
      throw createCodedError('METADATA_MISSING', 'audit-store.json missing on non-empty store');
    }
    const fresh: AuditStoreMetadataV1 = {
      version: 1,
      storeId: randomUUID(),
      createdAt: new Date().toISOString(),
      checkpointPublicKeyFingerprint: normalized.checkpointPublicKeyFingerprint,
      anchorMode: normalized.anchorMode,
      ...(normalized.anchorReceiptPublicKeyFingerprint === undefined
        ? {}
        : {
            anchorReceiptPublicKeyFingerprint: normalized.anchorReceiptPublicKeyFingerprint,
          }),
    };
    createStoreMetadataFile(auditDir, fresh, expectedUid);
    return fresh;
  }

  validateStoreMetadataConsistency(loaded, {
    checkpointPublicKeyFingerprint: normalized.checkpointPublicKeyFingerprint,
    anchorMode: normalized.anchorMode,
    ...(normalized.anchorReceiptPublicKeyFingerprint === undefined
      ? {}
      : { anchorReceiptPublicKeyFingerprint: normalized.anchorReceiptPublicKeyFingerprint }),
  });

  // Pinned trust roots (rc06 §22.1 step 3). The checkpoint pin is compared
  // against the CONFIGURED trust root here, before any key is loaded, and the
  // Task-4 engine enforces the same rule again on the descriptor it opens. A
  // disagreement is fatal.
  if (loaded.checkpointPublicKeyFingerprint !== checkpointFingerprint) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_KEY_MISMATCH',
      'configured checkpoint public key does not match audit-store.json.checkpointPublicKeyFingerprint',
    );
  }
  return loaded;
}

/**
 * Validates the Tier-3 launch configuration against the store's durable pin.
 *
 * A DISABLED store handed anchor configuration, or an ENABLED store missing any
 * of it, is refused: the store's durable record and the launch configuration
 * must agree. The receipt trust root is pinned here, before the anchor engine
 * reads anything.
 */
/**
 * Resolves the anchor trust root implied by trusted launch configuration.
 *
 * Tier 3 is ENABLED exactly when the launch configuration supplied BOTH an
 * anchor endpoint and an anchor receipt public key. A partial configuration
 * never enables it: it resolves to `DISABLED` here and is then refused by
 * {@link resolveAnchorTrustRoot}, which reports the partial configuration
 * rather than silently ignoring half of it.
 *
 * This reads a PUBLIC trust root only. No private key is involved, no anchor
 * key material is loaded, and nothing here can enable anchoring that the store
 * did not already record — the store's durable `anchorMode` pin is compared
 * against this value and a disagreement in either direction fails closed.
 */
type ConfiguredAnchorTrust =
  | { readonly anchorMode: 'DISABLED' }
  | { readonly anchorMode: 'ENABLED'; readonly anchorReceiptPublicKeyFingerprint: string };

function resolveConfiguredAnchorTrust(config: AuditConfig): ConfiguredAnchorTrust {
  if (config.anchorEndpoint === undefined || config.anchorReceiptPublicKeyPath === undefined) {
    return { anchorMode: 'DISABLED' };
  }
  return {
    anchorMode: 'ENABLED',
    anchorReceiptPublicKeyFingerprint: computeAnchorReceiptPublicKeyFingerprint(
      config.anchorReceiptPublicKeyPath,
    ),
  };
}

function resolveAnchorTrustRoot(config: AuditConfig, metadata: AuditStoreMetadataV1): void {
  const supplied = [config.anchorEndpoint, config.anchorReceiptPublicKeyPath].filter(
    (value) => value !== undefined,
  ).length;

  if (metadata.anchorMode === 'DISABLED') {
    if (supplied > 0) {
      throw createCodedError(
        'ANCHOR_CONFIG_INVALID',
        'anchor configuration was supplied for a store whose metadata records anchorMode DISABLED',
      );
    }
    return;
  }

  if (config.anchorEndpoint === undefined || config.anchorReceiptPublicKeyPath === undefined) {
    throw createCodedError(
      'ANCHOR_CONFIG_INVALID',
      'anchorMode ENABLED requires an anchor endpoint and an anchor receipt public key',
    );
  }
  validateAnchorEndpoint(config.anchorEndpoint);

  const pinned = computeAnchorReceiptPublicKeyFingerprint(config.anchorReceiptPublicKeyPath);
  if (
    metadata.anchorReceiptPublicKeyFingerprint === undefined ||
    metadata.anchorReceiptPublicKeyFingerprint !== pinned
  ) {
    throw createCodedError(
      'ANCHOR_RECEIPT_KEY_MISMATCH',
      'configured anchor receipt public key does not match audit-store.json.anchorReceiptPublicKeyFingerprint',
    );
  }
}

/**
 * Activates the single verified `PersistentAuditStorage` for this process.
 *
 * The append descriptor is opened once, after the tail is settled, and its
 * identity and length are re-proved against the VERIFIED digest immediately
 * before the handoff. The handoff token is the same unforgeable symbol Task-2
 * restart recovery uses, so nothing outside this package can manufacture a
 * "verified" storage.
 */
function acquireVerifiedStorage(
  auditDir: string,
  expectedUid: number,
  metadata: AuditStoreMetadataV1,
  lock: AuditLockAcquisition,
  verified: RetainedPrimaryHistoryVerificationResult,
): PersistentAuditStorage {
  const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);

  // A verified EMPTY store has no active segment yet. Creating it here — with
  // `O_EXCL` and a directory fsync — is the creation the verification
  // authorized: `verifyRetainedPrimaryHistory` proved the whole retained history
  // is empty and consistent, so there is nothing to adopt and nothing to
  // overwrite.
  if (!fs.existsSync(activePath)) {
    try {
      const initFd = fs.openSync(
        activePath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
      fs.closeSync(initFd);
    } catch (err: unknown) {
      if ((err as { code?: string })?.code === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
      }
      throw err;
    }
    syncDirectory(auditDir);
  }

  let activeFd: number;
  try {
    activeFd = fs.openSync(
      activePath,
      fsConstants.O_APPEND | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch (err: unknown) {
    if ((err as { code?: string })?.code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
    }
    throw err;
  }

  try {
    const stats = validateFileDescriptorAuthority(activeFd, 0o600, expectedUid);
    const verifiedIdentity = verified.active?.identity ?? null;
    if (
      verifiedIdentity !== null &&
      (stats.dev !== verifiedIdentity.dev || stats.ino !== verifiedIdentity.ino)
    ) {
      throw createCodedError(
        'AUDIT_RECOVERY_FAILED',
        'active file replacement detected between verification and activation',
      );
    }
    const verifiedLength = verified.active?.physicalByteLength ?? 0;
    if (stats.size !== verifiedLength) {
      throw createCodedError(
        'AUDIT_RECOVERY_FAILED',
        'active file length changed between verification and activation',
      );
    }

    const storageConfig: PersistentAuditStorageConfig = {
      directory: auditDir,
      metadata: {
        checkpointPublicKeyFingerprint: metadata.checkpointPublicKeyFingerprint,
        anchorMode: metadata.anchorMode,
        ...(metadata.anchorReceiptPublicKeyFingerprint === undefined
          ? {}
          : { anchorReceiptPublicKeyFingerprint: metadata.anchorReceiptPublicKeyFingerprint }),
      },
      createIfMissing: false,
      expectedUid,
    };

    return PersistentAuditStorage._fromVerifiedRecovery(RECOVERY_HANDOFF_TOKEN, storageConfig, {
      lock,
      metadata,
      activeFd,
      terminalSequence: verified.terminalSequence,
      terminalRecordHash: verified.terminalRecordHash,
      verifiedActiveIdentity: { dev: stats.dev, ino: stats.ino },
    });
  } catch (err) {
    closeQuietlySync(() => fs.closeSync(activeFd));
    throw err;
  }
}
