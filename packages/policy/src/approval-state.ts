import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import {
  ArcError,
  type ApprovalState,
  type ApprovalActorBinding,
  type ApprovalBinding,
  type ApprovalRequestSnapshot,
  type ApprovalGrant,
  type ApprovalRedemptionInput,
  type ApprovalConsumptionResult,
  type ApprovalReviewSummary,
  type ApprovalLifecycleEvent,
  type ApprovalAuditEventType,
  type ApprovalFailureReasonCode,
  APPROVAL_TTL_SECONDS,
  MAX_ACTIVE_APPROVALS_GLOBAL,
  MAX_ACTIVE_APPROVALS_PER_ACTOR,
  MAX_REVIEW_BYTES_PER_RECORD,
  MAX_REVIEW_BYTES_PER_ACTOR,
  MAX_REVIEW_BYTES_GLOBAL,
  MAX_REVIEW_SUMMARY_PATHS,
  MAX_REVIEW_SUMMARY_PATH_LENGTH,
  MAX_REVIEW_SUMMARY_STRING_LENGTH,
  MAX_TOKEN_BYTES,
  TERMINAL_APPROVAL_STATES,
} from '@cesspace-arc/protocol';

/**
 * Narrow lifecycle observer contract.
 *
 * Implementations MUST NOT retain the event object beyond the call, and MUST NOT
 * expect delivery to be anything other than a synchronous, bounded hand-off.
 * packages/policy deliberately does NOT depend on packages/audit.
 */
export interface IApprovalLifecycleSink {
  onApprovalLifecycleEvent(event: ApprovalLifecycleEvent): void;
}

/**
 * Internal redemption diagnostic reasons.
 *
 * These are held OUT OF BAND from the ArcError so they can never be serialized
 * into a client response, `details`, or `toJSON()`. The MCP client-facing result
 * stays generic (anti-oracle, rc04 §13).
 */
const approvalFailureReasons = new WeakMap<object, ApprovalFailureReasonCode>();

/** Attaches an internal diagnostic reason to an error, non-serializably. */
export function attachApprovalFailureReason<T extends object>(
  error: T,
  reason: ApprovalFailureReasonCode,
): T {
  approvalFailureReasons.set(error, reason);
  return error;
}

/** Reads the internal diagnostic reason for an error, if one was attached. */
export function getApprovalFailureReason(error: unknown): ApprovalFailureReasonCode | undefined {
  if (error === null || typeof error !== 'object') {
    return undefined;
  }
  return approvalFailureReasons.get(error);
}

export {
  APPROVAL_TTL_SECONDS,
  MAX_ACTIVE_APPROVALS_GLOBAL,
  MAX_ACTIVE_APPROVALS_PER_ACTOR,
  MAX_REVIEW_BYTES_PER_RECORD,
  MAX_REVIEW_BYTES_PER_ACTOR,
  MAX_REVIEW_BYTES_GLOBAL,
  MAX_TOKEN_BYTES,
  TERMINAL_APPROVAL_STATES,
};

/**
 * Input for creating or reusing a pending approval request.
 */
export interface CreatePendingApprovalInput {
  toolName: string;
  executionPayloadHash: string;
  binding: ApprovalBinding;
  reviewMaterial?: string;
  /**
   * Safe bounded metadata describing the request. This is NOT raw review
   * material and does not count against review byte quotas.
   */
  reviewSummary?: ApprovalReviewSummary;
}

/**
 * Copies and bounds a caller-supplied review summary.
 *
 * Only known fields with the expected primitive types survive; targetPaths is
 * capped and every string is length-bounded. Unknown properties are dropped, so
 * no arbitrary object can be stored.
 */
function sanitizeReviewSummary(input: unknown): ApprovalReviewSummary | undefined {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return undefined;
  }
  const source = input as Record<string, unknown>;
  const out: ApprovalReviewSummary = {};

  if (Array.isArray(source.targetPaths)) {
    const paths: string[] = [];
    for (const entry of source.targetPaths) {
      if (paths.length >= MAX_REVIEW_SUMMARY_PATHS) break;
      if (typeof entry !== 'string' || entry.length === 0) continue;
      // Paths use the business path bound, not the generic string bound.
      if (entry.length > MAX_REVIEW_SUMMARY_PATH_LENGTH) continue;
      paths.push(entry);
    }
    if (paths.length > 0) out.targetPaths = paths;
  }

  const numberFields: ReadonlyArray<keyof ApprovalReviewSummary> = [
    'contentBytes',
    'patchBytes',
    'fuzz',
    'argumentCount',
    'insertions',
    'deletions',
    'stepCount',
  ];
  for (const field of numberFields) {
    const value = source[field];
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
      (out as Record<string, unknown>)[field] = value;
    }
  }

  const hashFields: ReadonlyArray<keyof ApprovalReviewSummary> = [
    'contentHash',
    'patchHash',
    'expectedHash',
    'expectedSourceHash',
    'planHash',
  ];
  for (const field of hashFields) {
    const value = source[field];
    if (typeof value === 'string' && HEX_64_REGEX.test(value)) {
      (out as Record<string, unknown>)[field] = value;
    }
  }

  const booleanFields: ReadonlyArray<keyof ApprovalReviewSummary> = ['overwrite', 'dryRun'];
  for (const field of booleanFields) {
    const value = source[field];
    if (typeof value === 'boolean') {
      (out as Record<string, unknown>)[field] = value;
    }
  }

  const executable = source.executable;
  if (
    typeof executable === 'string' &&
    executable.length > 0 &&
    executable.length <= MAX_REVIEW_SUMMARY_STRING_LENGTH
  ) {
    out.executable = executable;
  }

  const planId = source.planId;
  if (
    typeof planId === 'string' &&
    planId.length > 0 &&
    planId.length <= MAX_REVIEW_SUMMARY_STRING_LENGTH
  ) {
    out.planId = planId;
  }

  return Object.keys(out).length > 0 ? out : undefined;
}

/** Deep-copies a stored review summary so callers cannot mutate stored state. */
function cloneReviewSummary(
  summary: ApprovalReviewSummary | undefined,
): ApprovalReviewSummary | undefined {
  if (summary === undefined) return undefined;
  const clone: ApprovalReviewSummary = { ...summary };
  if (summary.targetPaths !== undefined) {
    clone.targetPaths = [...summary.targetPaths];
  }
  return clone;
}

/**
 * Options for configuring ApprovalStateManager.
 * Injected limits may be stricter than production defaults, but must never exceed them.
 */
export interface ApprovalStateManagerOptions {
  getMonotonicTime?: () => bigint;
  getWallTime?: () => number;
  maxActiveApprovalsGlobal?: number;
  maxActiveApprovalsPerActor?: number;
  maxReviewBytesPerRecord?: number;
  maxReviewBytesPerActor?: number;
  maxReviewBytesGlobal?: number;
}

/**
 * Internal approval record stored in volatile memory.
 */
interface InternalApprovalRecord {
  requestId: string;
  state: ApprovalState;
  toolName: string;
  executionPayloadHash: string;
  binding: {
    actor: {
      clientId: string;
      clientType: string;
      sessionId?: string;
      deviceId?: string;
    };
    workspace: {
      workspaceId: string;
      workspaceRootHash: string;
    };
    policyHash: string;
  };
  createdAtWall: number;
  createdAtIso: string;
  expiresAtIso: string;
  monotonicDeadline: bigint;
  tokenDigest?: Buffer; // strictly 32-byte Buffer
  reviewMaterial?: string;
  reviewBytes: number;
  reviewSummary?: ApprovalReviewSummary;
  actorQuotaKey: string;
}

const HEX_64_REGEX = /^[0-9a-f]{64}$/;
const REQ_ID_REGEX = /^[0-9a-f]{32}$/;

/**
 * Isolated in-memory Approval State Manager (RC-04).
 * Manages the approval state machine, token generation, 32-byte digest verification,
 * resource quotas, deduplication, and monotonic TTL enforcement.
 */
export class ApprovalStateManager {
  private readonly getMonotonicTime: () => bigint;
  private readonly getWallTime: () => number;

  private readonly maxActiveApprovalsGlobal: number;
  private readonly maxActiveApprovalsPerActor: number;
  private readonly maxReviewBytesPerRecord: number;
  private readonly maxReviewBytesPerActor: number;
  private readonly maxReviewBytesGlobal: number;

  /** Synchronous lifecycle observers. Bounded, no duplicates. */
  private readonly lifecycleSinks: IApprovalLifecycleSink[] = [];

  private readonly recordsByRequestId = new Map<string, InternalApprovalRecord>();
  private readonly requestIdByDedupKey = new Map<string, string>();
  private readonly activeRequestIds = new Set<string>();

  private activeCountGlobal = 0;
  private readonly activeCountByActor = new Map<string, number>();
  private reviewBytesGlobal = 0;
  private readonly reviewBytesByActor = new Map<string, number>();

  /**
   * Registers a lifecycle observer. Duplicate registration is ignored.
   *
   * The event object handed to the sink is freshly constructed and defensively
   * copied, so a sink can neither observe nor mutate internal approval state.
   */
  public registerLifecycleSink(sink: IApprovalLifecycleSink): void {
    if (sink === null || typeof sink !== 'object') {
      return;
    }
    if (this.lifecycleSinks.includes(sink)) {
      return;
    }
    this.lifecycleSinks.push(sink);
  }

  /**
   * Emits a lifecycle event AFTER the state transition is committed in memory
   * (rc04 §37). A sink failure must never roll the state machine backward, so
   * observer exceptions are contained here (rc04 §38).
   */
  private emitLifecycleEvent(
    record: InternalApprovalRecord,
    eventType: ApprovalAuditEventType,
    reasonCode?: ApprovalFailureReasonCode,
    operatorReasonProvided?: boolean,
  ): void {
    if (this.lifecycleSinks.length === 0) {
      return;
    }
    // Defensively construct a fresh, bounded event. No token, digest, review
    // material, or monotonic deadline is ever included.
    for (const sink of this.lifecycleSinks) {
      const event: ApprovalLifecycleEvent = {
        eventType,
        requestId: record.requestId,
        state: record.state,
        toolName: record.toolName,
        actor: {
          clientId: record.binding.actor.clientId,
          clientType: record.binding.actor.clientType,
          ...(record.binding.actor.sessionId === undefined
            ? {}
            : { sessionId: record.binding.actor.sessionId }),
          ...(record.binding.actor.deviceId === undefined
            ? {}
            : { deviceId: record.binding.actor.deviceId }),
        },
        workspaceId: record.binding.workspace.workspaceId,
        workspaceRootHash: record.binding.workspace.workspaceRootHash,
        policyHash: record.binding.policyHash,
        occurredAt: new Date(this.getWallTime()).toISOString(),
        ...(reasonCode === undefined ? {} : { reasonCode }),
        ...(operatorReasonProvided === undefined ? {} : { operatorReasonProvided }),
      };
      try {
        sink.onApprovalLifecycleEvent(event);
      } catch {
        // Contained: audit delivery failure is handled by the control plane,
        // which fails closed for critical boundaries. State truth is preserved.
      }
    }
  }

  private validateLimit(name: string, value: unknown, max: number): number {
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      !Number.isInteger(value) ||
      value < 0 ||
      value > max
    ) {
      throw new Error(
        `${name} cannot exceed production maximum of ${max} and must be an integer between 0 and ${max}`,
      );
    }
    return value;
  }

  constructor(options: ApprovalStateManagerOptions = {}) {
    this.getMonotonicTime = options.getMonotonicTime ?? (() => process.hrtime.bigint());
    this.getWallTime = options.getWallTime ?? (() => Date.now());

    this.maxActiveApprovalsGlobal =
      options.maxActiveApprovalsGlobal !== undefined
        ? this.validateLimit(
            'maxActiveApprovalsGlobal',
            options.maxActiveApprovalsGlobal,
            MAX_ACTIVE_APPROVALS_GLOBAL,
          )
        : MAX_ACTIVE_APPROVALS_GLOBAL;

    this.maxActiveApprovalsPerActor =
      options.maxActiveApprovalsPerActor !== undefined
        ? this.validateLimit(
            'maxActiveApprovalsPerActor',
            options.maxActiveApprovalsPerActor,
            MAX_ACTIVE_APPROVALS_PER_ACTOR,
          )
        : MAX_ACTIVE_APPROVALS_PER_ACTOR;

    this.maxReviewBytesPerRecord =
      options.maxReviewBytesPerRecord !== undefined
        ? this.validateLimit(
            'maxReviewBytesPerRecord',
            options.maxReviewBytesPerRecord,
            MAX_REVIEW_BYTES_PER_RECORD,
          )
        : MAX_REVIEW_BYTES_PER_RECORD;

    this.maxReviewBytesPerActor =
      options.maxReviewBytesPerActor !== undefined
        ? this.validateLimit(
            'maxReviewBytesPerActor',
            options.maxReviewBytesPerActor,
            MAX_REVIEW_BYTES_PER_ACTOR,
          )
        : MAX_REVIEW_BYTES_PER_ACTOR;

    this.maxReviewBytesGlobal =
      options.maxReviewBytesGlobal !== undefined
        ? this.validateLimit(
            'maxReviewBytesGlobal',
            options.maxReviewBytesGlobal,
            MAX_REVIEW_BYTES_GLOBAL,
          )
        : MAX_REVIEW_BYTES_GLOBAL;
  }

  /**
   * Generates a deterministic, collision-safe canonical tuple encoding for actor identity.
   * Uses JSON array encoding to prevent delimiter concatenation collisions.
   */
  private getActorQuotaKey(actor: ApprovalActorBinding): string {
    return JSON.stringify([
      actor.clientId,
      actor.clientType,
      actor.sessionId === undefined ? null : actor.sessionId,
      actor.deviceId === undefined ? null : actor.deviceId,
    ]);
  }

  /**
   * Deep copies binding data defensively to prevent caller mutation from altering state.
   */
  private cloneBinding(binding: ApprovalBinding): ApprovalBinding {
    return {
      actor: {
        clientId: binding.actor.clientId,
        clientType: binding.actor.clientType,
        ...(binding.actor.sessionId !== undefined ? { sessionId: binding.actor.sessionId } : {}),
        ...(binding.actor.deviceId !== undefined ? { deviceId: binding.actor.deviceId } : {}),
      },
      workspace: {
        workspaceId: binding.workspace.workspaceId,
        workspaceRootHash: binding.workspace.workspaceRootHash,
      },
      policyHash: binding.policyHash,
    };
  }

  /**
   * Safely formats an internal record as a public ApprovalRequestSnapshot.
   */
  private toSnapshot(record: InternalApprovalRecord): ApprovalRequestSnapshot {
    const nowMono = this.getMonotonicTime();
    const remainingNanos = record.monotonicDeadline - nowMono;
    const remainingSeconds =
      remainingNanos <= 0n ? 0 : Math.ceil(Number(remainingNanos) / 1_000_000_000);

    return {
      requestId: record.requestId,
      state: record.state,
      toolName: record.toolName,
      executionPayloadHash: record.executionPayloadHash,
      binding: this.cloneBinding(record.binding),
      createdAt: record.createdAtIso,
      expiresAt: record.expiresAtIso,
      remainingSeconds,
      reviewMaterialBytes: record.reviewBytes,
      reviewSummary: cloneReviewSummary(record.reviewSummary),
    };
  }

  /**
   * Checks monotonic deadline and lazily transitions active records to EXPIRED if time elapsed.
   */
  private checkLazyExpiry(record: InternalApprovalRecord): boolean {
    if (record.state === 'EXPIRED') {
      return true;
    }
    if (
      record.state === 'REJECTED' ||
      record.state === 'CONSUMED' ||
      record.state === 'INVALIDATED'
    ) {
      return false;
    }
    const nowMono = this.getMonotonicTime();
    if (nowMono >= record.monotonicDeadline) {
      this.transitionToTerminal(record, 'EXPIRED');
      return true;
    }
    return false;
  }

  /**
   * Transitions an active record to a terminal state atomically, releasing dedup and quotas.
   * Internal invariant: Only active PENDING and APPROVED records can perform accounting release.
   */
  private transitionToTerminal(
    record: InternalApprovalRecord,
    terminalState: 'REJECTED' | 'EXPIRED' | 'CONSUMED' | 'INVALIDATED',
    reasonCode?: ApprovalFailureReasonCode,
    operatorReasonProvided?: boolean,
  ): void {
    if (record.state !== 'PENDING' && record.state !== 'APPROVED') {
      // Already terminal: no second lifecycle event (rc04 §9).
      return;
    }

    record.state = terminalState;
    this.activeRequestIds.delete(record.requestId);

    // Release deduplication slot
    if (this.requestIdByDedupKey.get(record.executionPayloadHash) === record.requestId) {
      this.requestIdByDedupKey.delete(record.executionPayloadHash);
    }

    // Decrement active counts
    this.activeCountGlobal--;
    const actorActive = this.activeCountByActor.get(record.actorQuotaKey);
    if (actorActive !== undefined) {
      if (actorActive <= 1) {
        this.activeCountByActor.delete(record.actorQuotaKey);
      } else {
        this.activeCountByActor.set(record.actorQuotaKey, actorActive - 1);
      }
    }

    // Drop review material if still retained
    this.dropReviewMaterial(record);

    // Emitted only after the transition and all accounting are committed.
    const eventType: ApprovalAuditEventType =
      terminalState === 'EXPIRED'
        ? 'APPROVAL_EXPIRED'
        : terminalState === 'REJECTED'
          ? 'APPROVAL_REJECTED'
          : terminalState === 'CONSUMED'
            ? 'APPROVAL_CONSUMED'
            : 'APPROVAL_INVALIDATED';
    this.emitLifecycleEvent(record, eventType, reasonCode, operatorReasonProvided);
  }

  /**
   * Drops raw review material buffer and decrements byte quota counters.
   */
  private dropReviewMaterial(record: InternalApprovalRecord): void {
    const bytes = record.reviewBytes;
    if (bytes > 0) {
      this.reviewBytesGlobal -= bytes;
      const currentActorBytes = this.reviewBytesByActor.get(record.actorQuotaKey);
      if (currentActorBytes !== undefined) {
        const remaining = currentActorBytes - bytes;
        if (remaining <= 0) {
          this.reviewBytesByActor.delete(record.actorQuotaKey);
        } else {
          this.reviewBytesByActor.set(record.actorQuotaKey, remaining);
        }
      }
      record.reviewMaterial = undefined;
      record.reviewBytes = 0;
    }
  }

  /**
   * Synchronously transitions all due active records to EXPIRED before new admissions.
   * Bounded to at most the active-record population.
   */
  private reclaimExpiredActiveRecords(): void {
    const nowMono = this.getMonotonicTime();
    for (const reqId of Array.from(this.activeRequestIds)) {
      const record = this.recordsByRequestId.get(reqId);
      if (record && nowMono >= record.monotonicDeadline) {
        this.transitionToTerminal(record, 'EXPIRED');
      }
    }
  }

  /**
   * Creates a new pending approval record or reuses an existing active record for the same execution payload.
   */
  public createOrReusePending(input: CreatePendingApprovalInput): ApprovalRequestSnapshot {
    if (!input || typeof input !== 'object') {
      throw ArcError.invalidRequestSchema('Invalid approval request input: expected object.');
    }

    const { toolName, executionPayloadHash, binding, reviewMaterial } = input;

    if (typeof toolName !== 'string' || toolName.trim().length === 0) {
      throw ArcError.invalidRequestSchema('toolName must be a non-empty string.');
    }
    if (typeof executionPayloadHash !== 'string' || !HEX_64_REGEX.test(executionPayloadHash)) {
      throw ArcError.invalidRequestSchema(
        'executionPayloadHash must be a 64-character lowercase hexadecimal string.',
      );
    }
    if (!binding || typeof binding !== 'object') {
      throw ArcError.invalidRequestSchema('binding must be an object.');
    }
    if (!binding.actor || typeof binding.actor !== 'object') {
      throw ArcError.invalidRequestSchema('binding.actor must be an object.');
    }
    if (typeof binding.actor.clientId !== 'string' || binding.actor.clientId.trim().length === 0) {
      throw ArcError.invalidRequestSchema('binding.actor.clientId must be a non-empty string.');
    }
    if (
      typeof binding.actor.clientType !== 'string' ||
      binding.actor.clientType.trim().length === 0
    ) {
      throw ArcError.invalidRequestSchema('binding.actor.clientType must be a non-empty string.');
    }
    if (
      binding.actor.sessionId !== undefined &&
      (typeof binding.actor.sessionId !== 'string' || binding.actor.sessionId.trim().length === 0)
    ) {
      throw ArcError.invalidRequestSchema(
        'binding.actor.sessionId must be a non-empty string when provided.',
      );
    }
    if (
      binding.actor.deviceId !== undefined &&
      (typeof binding.actor.deviceId !== 'string' || binding.actor.deviceId.trim().length === 0)
    ) {
      throw ArcError.invalidRequestSchema(
        'binding.actor.deviceId must be a non-empty string when provided.',
      );
    }
    if (!binding.workspace || typeof binding.workspace !== 'object') {
      throw ArcError.invalidRequestSchema('binding.workspace must be an object.');
    }
    if (
      typeof binding.workspace.workspaceId !== 'string' ||
      binding.workspace.workspaceId.trim().length === 0
    ) {
      throw ArcError.invalidRequestSchema(
        'binding.workspace.workspaceId must be a non-empty string.',
      );
    }
    if (
      typeof binding.workspace.workspaceRootHash !== 'string' ||
      !HEX_64_REGEX.test(binding.workspace.workspaceRootHash)
    ) {
      throw ArcError.invalidRequestSchema(
        'binding.workspace.workspaceRootHash must be a 64-character lowercase hexadecimal string.',
      );
    }
    if (typeof binding.policyHash !== 'string' || !HEX_64_REGEX.test(binding.policyHash)) {
      throw ArcError.invalidRequestSchema(
        'binding.policyHash must be a 64-character lowercase hexadecimal string.',
      );
    }
    if (reviewMaterial !== undefined && typeof reviewMaterial !== 'string') {
      throw ArcError.invalidRequestSchema('reviewMaterial must be a string when provided.');
    }

    // Synchronously reclaim any expired active records before dedup and quota evaluation
    this.reclaimExpiredActiveRecords();

    const dedupKey = executionPayloadHash;

    // Check for deduplication of active PENDING or APPROVED records
    if (this.requestIdByDedupKey.has(dedupKey)) {
      const existingId = this.requestIdByDedupKey.get(dedupKey)!;
      const existingRecord = this.recordsByRequestId.get(existingId);
      if (existingRecord) {
        const isExpired = this.checkLazyExpiry(existingRecord);
        if (
          !isExpired &&
          (existingRecord.state === 'PENDING' || existingRecord.state === 'APPROVED')
        ) {
          return this.toSnapshot(existingRecord);
        }
      }
    }

    // Quota validation
    const reviewBytes = reviewMaterial ? Buffer.byteLength(reviewMaterial, 'utf8') : 0;
    if (reviewBytes > this.maxReviewBytesPerRecord) {
      throw ArcError.resourceExhausted(
        `Review material exceeds maximum per-record limit of ${this.maxReviewBytesPerRecord} bytes.`,
      );
    }

    const actorQuotaKey = this.getActorQuotaKey(binding.actor);

    if (this.activeCountGlobal + 1 > this.maxActiveApprovalsGlobal) {
      throw ArcError.resourceExhausted(
        `Global active approval quota exceeded (${this.maxActiveApprovalsGlobal}).`,
      );
    }

    const currentActorActive = this.activeCountByActor.get(actorQuotaKey) ?? 0;
    if (currentActorActive + 1 > this.maxActiveApprovalsPerActor) {
      throw ArcError.resourceExhausted(
        `Per-actor active approval quota exceeded (${this.maxActiveApprovalsPerActor}).`,
      );
    }

    if (this.reviewBytesGlobal + reviewBytes > this.maxReviewBytesGlobal) {
      throw ArcError.resourceExhausted(
        `Global review material byte quota exceeded (${this.maxReviewBytesGlobal} bytes).`,
      );
    }

    const currentActorBytes = this.reviewBytesByActor.get(actorQuotaKey) ?? 0;
    if (currentActorBytes + reviewBytes > this.maxReviewBytesPerActor) {
      throw ArcError.resourceExhausted(
        `Per-actor review material byte quota exceeded (${this.maxReviewBytesPerActor} bytes).`,
      );
    }

    // Admission succeeded - create record
    const requestId = randomBytes(16).toString('hex'); // exactly 32 lowercase hex chars
    const nowWall = this.getWallTime();
    const nowMono = this.getMonotonicTime();
    const createdAtIso = new Date(nowWall).toISOString();
    const expiresAtIso = new Date(nowWall + APPROVAL_TTL_SECONDS * 1000).toISOString();
    const monotonicDeadline = nowMono + BigInt(APPROVAL_TTL_SECONDS) * 1_000_000_000n;

    const record: InternalApprovalRecord = {
      requestId,
      state: 'PENDING',
      toolName,
      executionPayloadHash,
      binding: this.cloneBinding(binding),
      createdAtWall: nowWall,
      createdAtIso,
      expiresAtIso,
      monotonicDeadline,
      reviewMaterial: reviewMaterial ? String(reviewMaterial) : undefined,
      reviewBytes,
      reviewSummary: sanitizeReviewSummary(input.reviewSummary),
      actorQuotaKey,
    };

    this.recordsByRequestId.set(requestId, record);
    this.requestIdByDedupKey.set(dedupKey, requestId);
    this.activeRequestIds.add(requestId);

    // Increment resource accounting counters
    this.activeCountGlobal++;
    this.activeCountByActor.set(actorQuotaKey, currentActorActive + 1);
    if (reviewBytes > 0) {
      this.reviewBytesGlobal += reviewBytes;
      this.reviewBytesByActor.set(actorQuotaKey, currentActorBytes + reviewBytes);
    }

    // A lifecycle REQUEST was actually created. Deduplicated reuse returns
    // earlier and therefore never reaches this point (rc04 §8).
    this.emitLifecycleEvent(record, 'APPROVAL_REQUESTED');

    return this.toSnapshot(record);
  }

  /**
   * Approves a PENDING request, generating and returning the raw 256-bit token once.
   */
  public approve(requestId: string): ApprovalGrant {
    if (typeof requestId !== 'string') {
      throw ArcError.approvalRejected();
    }

    const record = this.recordsByRequestId.get(requestId);
    if (!record) {
      throw ArcError.approvalRejected();
    }

    if (this.checkLazyExpiry(record)) {
      throw ArcError.approvalExpired();
    }

    if (record.state !== 'PENDING') {
      throw ArcError.approvalRejected();
    }

    // Generate 256-bit cryptographic token (64 lowercase hex chars)
    const tokenText = randomBytes(32).toString('hex');
    const tokenDigest = createHash('sha256').update(tokenText, 'utf8').digest();

    record.tokenDigest = tokenDigest;
    record.state = 'APPROVED';

    // Drop review material immediately upon approval
    this.dropReviewMaterial(record);

    // Emitted after the state change is committed (rc04 §37).
    this.emitLifecycleEvent(record, 'APPROVAL_GRANTED');

    return {
      token: tokenText,
      snapshot: this.toSnapshot(record),
    };
  }

  /**
   * Rejects a PENDING request.
   */
  public reject(requestId: string, reason?: string): ApprovalRequestSnapshot {
    if (typeof requestId !== 'string') {
      throw ArcError.approvalRejected();
    }

    const record = this.recordsByRequestId.get(requestId);
    if (!record) {
      throw ArcError.approvalRejected();
    }

    if (this.checkLazyExpiry(record)) {
      throw ArcError.approvalExpired();
    }

    if (record.state !== 'PENDING') {
      throw ArcError.approvalRejected();
    }

    // The operator-supplied reason text is NEVER stored, audited, or logged: it
    // can contain secrets or host paths. Only its presence is retained.
    this.transitionToTerminal(record, 'REJECTED', undefined, reason !== undefined);

    return this.toSnapshot(record);
  }

  /**
   * Validates redemption credentials and atomically transitions APPROVED -> CONSUMED.
   */
  public redeemAndConsume(input: ApprovalRedemptionInput): ApprovalConsumptionResult {
    if (!input || typeof input !== 'object') {
      throw ArcError.invalidRequestSchema('Redemption input must be an object.');
    }

    const { requestId, token, executionPayloadHash, actor, workspace, policyHash } = input;

    if (
      typeof token !== 'string' ||
      token.length === 0 ||
      Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES
    ) {
      throw ArcError.invalidRequestSchema(
        `Approval token must be a non-empty string of at most ${MAX_TOKEN_BYTES} UTF-8 bytes.`,
      );
    }

    if (typeof requestId !== 'string' || !REQ_ID_REGEX.test(requestId)) {
      throw ArcError.invalidRequestSchema('Invalid approval request ID format.');
    }

    const record = this.recordsByRequestId.get(requestId);
    if (!record) {
      throw ArcError.approvalRejected();
    }

    if (this.checkLazyExpiry(record)) {
      throw ArcError.approvalExpired();
    }

    // State handling
    if (record.state === 'PENDING') {
      // If policy hash mismatches, transition to INVALIDATED
      if (record.binding.policyHash !== policyHash) {
        this.transitionToTerminal(record, 'INVALIDATED', 'POLICY_BINDING_MISMATCH');
        throw attachApprovalFailureReason(ArcError.approvalRejected(), 'POLICY_BINDING_MISMATCH');
      }
      throw ArcError.approvalRequired();
    }

    if (record.state === 'INVALIDATED') {
      throw ArcError.approvalRejected();
    }

    if (record.state === 'REJECTED') {
      throw ArcError.approvalRejected();
    }

    if (record.state === 'EXPIRED') {
      throw ArcError.approvalExpired();
    }

    if (record.state === 'CONSUMED') {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'ALREADY_CONSUMED');
    }

    if (record.state !== 'APPROVED') {
      throw ArcError.approvalRejected();
    }

    // Policy Binding Check: Mismatch permanently invalidates approval
    if (record.binding.policyHash !== policyHash) {
      this.transitionToTerminal(record, 'INVALIDATED', 'POLICY_BINDING_MISMATCH');
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'POLICY_BINDING_MISMATCH');
    }

    // Execution Payload Binding Check
    if (record.executionPayloadHash !== executionPayloadHash) {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'PAYLOAD_BINDING_MISMATCH');
    }

    // Actor Binding Check
    if (!actor || typeof actor !== 'object') {
      throw ArcError.approvalRejected();
    }
    if (
      record.binding.actor.clientId !== actor.clientId ||
      record.binding.actor.clientType !== actor.clientType ||
      record.binding.actor.sessionId !== actor.sessionId ||
      record.binding.actor.deviceId !== actor.deviceId
    ) {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'ACTOR_BINDING_MISMATCH');
    }

    // Workspace Binding Check
    if (!workspace || typeof workspace !== 'object') {
      throw ArcError.approvalRejected();
    }
    if (
      record.binding.workspace.workspaceId !== workspace.workspaceId ||
      record.binding.workspace.workspaceRootHash !== workspace.workspaceRootHash
    ) {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'WORKSPACE_BINDING_MISMATCH');
    }

    // Token Verification via 32-byte constant-time digest comparison
    if (!record.tokenDigest) {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'TOKEN_MISMATCH');
    }

    const candidateDigest = createHash('sha256').update(token, 'utf8').digest();
    const isValid = timingSafeEqual(record.tokenDigest, candidateDigest);
    if (!isValid) {
      throw attachApprovalFailureReason(ArcError.approvalRejected(), 'TOKEN_MISMATCH');
    }

    // Atomic Consumption
    this.transitionToTerminal(record, 'CONSUMED');

    return {
      consumed: true,
      requestId: record.requestId,
      toolName: record.toolName,
      executionPayloadHash: record.executionPayloadHash,
      consumedAt: new Date(this.getWallTime()).toISOString(),
    };
  }

  /**
   * Internal inspection method for local operators to view raw review material.
   * Only accessible while state is PENDING and unexpired.
   */
  public inspectPending(requestId: string): string | undefined {
    if (typeof requestId !== 'string') {
      return undefined;
    }
    const record = this.recordsByRequestId.get(requestId);
    if (!record) {
      return undefined;
    }
    if (this.checkLazyExpiry(record)) {
      return undefined;
    }
    if (record.state !== 'PENDING') {
      return undefined;
    }
    return record.reviewMaterial;
  }

  /**
   * Returns a safe snapshot of an approval request by ID.
   */
  public getRequest(requestId: string): ApprovalRequestSnapshot | undefined {
    if (typeof requestId !== 'string') {
      return undefined;
    }
    const record = this.recordsByRequestId.get(requestId);
    if (!record) {
      return undefined;
    }
    this.checkLazyExpiry(record);
    return this.toSnapshot(record);
  }

  /**
   * Lists all currently active (PENDING or APPROVED) approval request snapshots.
   * Sorted deterministically by createdAt ascending, then requestId ascending.
   */
  public listActive(): ApprovalRequestSnapshot[] {
    const active: InternalApprovalRecord[] = [];
    for (const record of this.recordsByRequestId.values()) {
      const isExpired = this.checkLazyExpiry(record);
      if (!isExpired && (record.state === 'PENDING' || record.state === 'APPROVED')) {
        active.push(record);
      }
    }

    active.sort((a, b) => {
      if (a.createdAtWall !== b.createdAtWall) {
        return a.createdAtWall - b.createdAtWall;
      }
      return a.requestId.localeCompare(b.requestId);
    });

    return active.map((r) => this.toSnapshot(r));
  }

  /**
   * Actively purges expired requests and releases their quota slots.
   */
  public purgeExpired(): number {
    let purged = 0;
    const nowMono = this.getMonotonicTime();
    for (const reqId of Array.from(this.activeRequestIds)) {
      const record = this.recordsByRequestId.get(reqId);
      if (record && nowMono >= record.monotonicDeadline) {
        this.transitionToTerminal(record, 'EXPIRED');
        purged++;
      }
    }
    return purged;
  }

  /**
   * Resets all manager state in volatile memory (simulates clean process restart).
   */
  public clear(): void {
    this.recordsByRequestId.clear();
    this.requestIdByDedupKey.clear();
    this.activeRequestIds.clear();
    this.activeCountGlobal = 0;
    this.activeCountByActor.clear();
    this.reviewBytesGlobal = 0;
    this.reviewBytesByActor.clear();
  }
}
