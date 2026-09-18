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
  APPROVAL_TTL_SECONDS,
  MAX_ACTIVE_APPROVALS_GLOBAL,
  MAX_ACTIVE_APPROVALS_PER_ACTOR,
  MAX_REVIEW_BYTES_PER_RECORD,
  MAX_REVIEW_BYTES_PER_ACTOR,
  MAX_REVIEW_BYTES_GLOBAL,
  MAX_TOKEN_BYTES,
  TERMINAL_APPROVAL_STATES,
} from '@cesspace-arc/protocol';

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

  private readonly recordsByRequestId = new Map<string, InternalApprovalRecord>();
  private readonly requestIdByDedupKey = new Map<string, string>();
  private readonly activeRequestIds = new Set<string>();

  private activeCountGlobal = 0;
  private readonly activeCountByActor = new Map<string, number>();
  private reviewBytesGlobal = 0;
  private readonly reviewBytesByActor = new Map<string, number>();

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
  ): void {
    const previousState = record.state;
    if (previousState !== 'PENDING' && previousState !== 'APPROVED') {
      record.state = terminalState;
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

    return {
      token: tokenText,
      snapshot: this.toSnapshot(record),
    };
  }

  /**
   * Rejects a PENDING request.
   */
  public reject(requestId: string, _reason?: string): ApprovalRequestSnapshot {
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

    this.transitionToTerminal(record, 'REJECTED');

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
        this.transitionToTerminal(record, 'INVALIDATED');
        throw ArcError.approvalRejected();
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
      throw ArcError.approvalRejected();
    }

    if (record.state !== 'APPROVED') {
      throw ArcError.approvalRejected();
    }

    // Policy Binding Check: Mismatch permanently invalidates approval
    if (record.binding.policyHash !== policyHash) {
      this.transitionToTerminal(record, 'INVALIDATED');
      throw ArcError.approvalRejected();
    }

    // Execution Payload Binding Check
    if (record.executionPayloadHash !== executionPayloadHash) {
      throw ArcError.approvalRejected();
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
      throw ArcError.approvalRejected();
    }

    // Workspace Binding Check
    if (!workspace || typeof workspace !== 'object') {
      throw ArcError.approvalRejected();
    }
    if (
      record.binding.workspace.workspaceId !== workspace.workspaceId ||
      record.binding.workspace.workspaceRootHash !== workspace.workspaceRootHash
    ) {
      throw ArcError.approvalRejected();
    }

    // Token Verification via 32-byte constant-time digest comparison
    if (!record.tokenDigest) {
      throw ArcError.approvalRejected();
    }

    const candidateDigest = createHash('sha256').update(token, 'utf8').digest();
    const isValid = timingSafeEqual(record.tokenDigest, candidateDigest);
    if (!isValid) {
      throw ArcError.approvalRejected();
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
