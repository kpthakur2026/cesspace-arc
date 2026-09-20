/**
 * CesSpace ARC — RC-05 Task 2 Pending Enrollment Lifecycle
 *
 * Pure domain/state logic for operator-mediated device enrollment
 * (docs/architecture/rc05-scope-acceptance.md §9, E-1..E-12, §9.2).
 *
 * This module performs NO network I/O, NO filesystem I/O, and NO trust-store
 * mutation. It owns exactly one thing: the bounded, volatile table of pending
 * enrollment challenges and the transitions over it.
 *
 * Task 2 ends here. Remote completion (`POST /enroll/complete`), mTLS proof of
 * possession, and atomic activation into the persistent trust store are Task 4.
 * The consume primitive below is written for Task 4 to call; nothing in Task 2
 * calls it.
 *
 * State held per pending enrollment is deliberately non-secret: the raw
 * one-time secret exists only in the return value of `create()` and is never
 * retained. Only its SHA-256 digest is kept.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';
import {
  isValidSpkiPin,
  validateClientId,
  validateClientType,
  validateDisplayLabel,
} from './device-identity.js';

/** Enrollment challenge TTL in seconds (§9.2). Enforced monotonically. */
export const ENROLLMENT_TTL_SECONDS = 300;

/** Maximum pending enrollments globally (§9.2). */
export const MAX_PENDING_ENROLLMENTS_GLOBAL = 16;

/** Maximum pending enrollments per authenticated operator (§9.2). */
export const MAX_PENDING_ENROLLMENTS_PER_OPERATOR = 4;

/** Maximum failed one-time-secret submissions before immediate purge (§9.2, E-12). */
export const MAX_FAILED_SECRET_ATTEMPTS = 3;

/** Server-generated enrollment identifier: 16 random bytes as 32 lowercase hex. */
export const ENROLLMENT_ID_HEX_LENGTH = 32;
export const ENROLLMENT_ID_REGEX = /^[0-9a-f]{32}$/;

/** One-time secret: 32 random bytes as exactly 64 lowercase hex characters (§9.1). */
export const ENROLLMENT_SECRET_HEX_LENGTH = 64;
export const ENROLLMENT_SECRET_REGEX = /^[0-9a-f]{64}$/;

/** Canonical operator identifier: SHA-256 of the operator SPKI public key. */
export const OPERATOR_ID_REGEX = /^[0-9a-f]{64}$/;

/** Maximum serialized size of one bounded enrollment view payload. */
export const MAX_ENROLLMENT_METADATA_BYTES = 512;

/** Injectable monotonic clock. Authorization decisions never use wall time. */
export interface EnrollmentManagerOptions {
  /** Monotonic clock in nanoseconds. Defaults to process.hrtime.bigint(). */
  getMonotonicTime?: () => bigint;
  /** Wall clock in milliseconds, used ONLY for human-readable display fields. */
  getWallTime?: () => number;
}

/**
 * Bounded operator-safe view of a pending enrollment.
 *
 * Never contains the one-time secret, its digest, the operator key, or the
 * internal monotonic deadline.
 */
export interface PendingEnrollmentView {
  enrollmentId: string;
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel: string;
  /** Wall-clock ISO display time. Never used for TTL decisions. */
  createdAt: string;
  /** Wall-clock ISO display time derived at creation. Display only. */
  expiresAt: string;
  /** Remaining lifetime in seconds, derived from the monotonic clock. */
  remainingSeconds: number;
  /** Failed one-time-secret submissions so far, bounded by the lockout limit. */
  failedAttempts: number;
}

/**
 * Successful challenge creation.
 *
 * `secret` is the ONLY place the raw one-time secret exists. The caller
 * (authenticated local admin IPC) discloses it exactly once to the operator and
 * must not retain, log, persist, or audit it.
 */
export interface CreatedEnrollment {
  enrollment: PendingEnrollmentView;
  secret: string;
}

/** Operator-supplied creation inputs. Everything else is server-derived. */
export interface CreateEnrollmentInput {
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel?: string;
  /**
   * Authenticated operator identity, derived server-side from the verified
   * operator public key. Never accepted from request parameters.
   */
  operatorId: string;
}

/**
 * Internal outcome of a one-time-secret consumption attempt.
 *
 * This is a DIAGNOSTIC for ARC-internal callers (Task 4 maps every value to a
 * single uniform external failure response). It is never exposed to a remote
 * client, and it is not exposed over the admin IPC either.
 */
export type ConsumeOutcome =
  | { ok: true; enrollment: PendingEnrollmentView }
  | {
      ok: false;
      reason:
        | 'UNKNOWN_ENROLLMENT'
        | 'EXPIRED'
        | 'SECRET_MISMATCH'
        | 'LOCKED_OUT'
        /** Proof was correct but durable activation failed; nothing was consumed. */
        | 'ACTIVATION_FAILED';
      /** True when this attempt was counted against the lockout. */
      counted: boolean;
    };

interface InternalPendingEnrollment {
  enrollmentId: string;
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel: string;
  operatorId: string;
  createdAtWall: number;
  createdAtIso: string;
  expiresAtIso: string;
  monotonicDeadline: bigint;
  failedAttempts: number;
  /** SHA-256 verifier of the one-time secret. The raw secret is not retained. */
  secretDigest: Buffer;
  /**
   * True while a verified proof is inside its activation commit.
   *
   * A record in this state is no longer SELECTABLE: the challenge has been
   * proven once and is being activated, so a nested lookup (which only a
   * re-entrant commit callback could produce) must not find it. Without this a
   * synchronous re-entry could observe the same challenge as live and produce a
   * second success for one single-use secret.
   */
  committing: boolean;
}

/**
 * Fixed 32-byte dummy used as the comparison operand when a submitted secret is
 * malformed. It is not derived from any secret and grants nothing; it exists so
 * the malformed path performs the same constant-time comparison as every other
 * mismatch rather than a visibly separate branch.
 */
const DUMMY_SECRET_DIGEST = Buffer.alloc(32, 0);

function sha256Bytes(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Bounded, volatile pending-enrollment table.
 *
 * All state transitions are synchronous. In a single-threaded event loop no
 * other task can interleave inside a transition, so the lockout counter, the
 * quota check, and the consume step are each atomic with respect to other
 * requests. This is what makes the "at most 3 attempts" and "at most one
 * consumption" guarantees hold without locks.
 */
export class EnrollmentManager {
  private readonly getMonotonicTime: () => bigint;
  private readonly getWallTime: () => number;
  private readonly pendingById = new Map<string, InternalPendingEnrollment>();

  constructor(options: EnrollmentManagerOptions = {}) {
    this.getMonotonicTime = options.getMonotonicTime ?? (() => process.hrtime.bigint());
    this.getWallTime = options.getWallTime ?? (() => Date.now());
  }

  /** Current pending-enrollment count after purging expired records. */
  public getPendingCount(): number {
    this.purgeExpired();
    return this.pendingById.size;
  }

  /** Pending-enrollment count for one authenticated operator. */
  public getPendingCountForOperator(operatorId: string): number {
    this.purgeExpired();
    let count = 0;
    for (const record of this.pendingById.values()) {
      if (record.operatorId === operatorId) {
        count += 1;
      }
    }
    return count;
  }

  /**
   * Purges every pending enrollment whose monotonic deadline has been reached.
   *
   * Expiry is authoritative and irreversible: a purged challenge cannot be
   * revived, and its one-time secret is permanently unusable.
   */
  public purgeExpired(): number {
    const now = this.getMonotonicTime();
    let purged = 0;
    for (const [enrollmentId, record] of this.pendingById) {
      if (now >= record.monotonicDeadline) {
        this.pendingById.delete(enrollmentId);
        purged += 1;
      }
    }
    return purged;
  }

  /**
   * Creates a pending enrollment challenge.
   *
   * Quota admission happens BEFORE any state mutation: a rejected creation
   * leaves the pending table and the (untouched) trust store exactly as they
   * were apart from the expired-record purge, which releases quota rather than
   * consuming it.
   */
  public create(input: CreateEnrollmentInput): CreatedEnrollment {
    if (typeof input !== 'object' || input === null) {
      throw ArcError.invalidRequestSchema('Enrollment input must be an object.');
    }

    // Shared with the persistent trust-store schema, so an accepted challenge
    // can always be serialized as an enrolled device later.
    const clientId = validateClientId(input.clientId);
    const clientType = validateClientType(input.clientType);
    if (!isValidSpkiPin(input.spkiPin)) {
      throw ArcError.invalidRequestSchema(
        'spkiPin must be exactly 64 lowercase hexadecimal characters.',
      );
    }
    const displayLabel = validateDisplayLabel(input.displayLabel ?? '');
    const operatorId = input.operatorId;
    if (typeof operatorId !== 'string' || !OPERATOR_ID_REGEX.test(operatorId)) {
      // Server-derived only. A missing or malformed operator identity is an
      // internal composition error, never a caller-supplied value.
      throw ArcError.invalidRequestSchema(
        'operatorId must be a server-derived 64-character lowercase hexadecimal digest.',
      );
    }

    // Expired records must never keep consuming quota (§9.2, E-7) or hold an
    // SPKI, so expiry is applied before either uniqueness or quota is judged.
    this.purgeExpired();

    // A live canonical SPKI identifies AT MOST ONE pending challenge, because
    // the frozen completion flow selects the challenge by the presented SPKI
    // and never transmits an enrollment identifier (§9.1). Two live challenges
    // for one pin would make that selection ambiguous, so it fails closed here,
    // before any quota accounting or state mutation.
    if (this.findLiveBySpki(input.spkiPin) !== undefined) {
      throw ArcError.invalidRequestSchema('A pending enrollment already exists for this SPKI pin.');
    }

    if (this.pendingById.size + 1 > MAX_PENDING_ENROLLMENTS_GLOBAL) {
      throw ArcError.resourceExhausted(
        `Global pending enrollment quota exceeded (${MAX_PENDING_ENROLLMENTS_GLOBAL}).`,
      );
    }
    if (this.getPendingCountForOperator(operatorId) + 1 > MAX_PENDING_ENROLLMENTS_PER_OPERATOR) {
      throw ArcError.resourceExhausted(
        `Per-operator pending enrollment quota exceeded (${MAX_PENDING_ENROLLMENTS_PER_OPERATOR}).`,
      );
    }

    // Server-generated, never caller-supplied (§1, §8).
    const enrollmentId = randomBytes(16).toString('hex');
    const secret = randomBytes(32).toString('hex');

    const nowWall = this.getWallTime();
    const nowMono = this.getMonotonicTime();
    const record: InternalPendingEnrollment = {
      enrollmentId,
      clientId,
      clientType,
      spkiPin: input.spkiPin,
      displayLabel,
      operatorId,
      createdAtWall: nowWall,
      createdAtIso: new Date(nowWall).toISOString(),
      expiresAtIso: new Date(nowWall + ENROLLMENT_TTL_SECONDS * 1000).toISOString(),
      monotonicDeadline: nowMono + BigInt(ENROLLMENT_TTL_SECONDS) * 1_000_000_000n,
      failedAttempts: 0,
      secretDigest: sha256Bytes(secret),
      committing: false,
    };

    this.pendingById.set(enrollmentId, record);

    return { enrollment: this.toView(record), secret };
  }

  /** Returns a bounded view of a pending enrollment, or undefined. */
  public get(enrollmentId: string): PendingEnrollmentView | undefined {
    this.purgeExpired();
    const record = this.pendingById.get(enrollmentId);
    return record === undefined ? undefined : this.toView(record);
  }

  /** Bounded list of pending enrollments. Never contains secret material. */
  public list(): PendingEnrollmentView[] {
    this.purgeExpired();
    return [...this.pendingById.values()].map((record) => this.toView(record));
  }

  /**
   * Cancels a pending enrollment.
   *
   * Returns true only when a live pending record was removed. An unknown,
   * expired, or already-consumed identifier returns false, and the caller maps
   * that to the existing bounded NOT_FOUND_OR_NOT_PENDING admin result. The
   * outcome is deliberately identical for all three cases so cancellation is
   * not an existence oracle for consumed or expired challenges.
   */
  public cancel(enrollmentId: string): boolean {
    if (typeof enrollmentId !== 'string' || !ENROLLMENT_ID_REGEX.test(enrollmentId)) {
      return false;
    }
    this.purgeExpired();
    return this.pendingById.delete(enrollmentId);
  }

  /**
   * Finds the single live pending challenge bound to a canonical SPKI pin.
   *
   * A linear scan over a table bounded at 16 live records is used deliberately
   * instead of a secondary index: a derived index could drift out of step with
   * the records, whereas a scan cannot. Combined with the admission rule in
   * {@link create}, this yields 0 or 1 match, never more.
   */
  private findLiveBySpki(spkiPin: string): InternalPendingEnrollment | undefined {
    if (typeof spkiPin !== 'string' || !isValidSpkiPin(spkiPin)) {
      return undefined;
    }
    for (const record of this.pendingById.values()) {
      // A record already inside its activation commit is not selectable: its
      // single-use secret has been spent, and only the outer transaction may
      // still observe it.
      if (record.spkiPin === spkiPin && !record.committing) {
        return record;
      }
    }
    return undefined;
  }

  /** Bounded view of the live challenge for a pin, or undefined. */
  public getBySpki(spkiPin: string): PendingEnrollmentView | undefined {
    this.purgeExpired();
    const record = this.findLiveBySpki(spkiPin);
    return record === undefined ? undefined : this.toView(record);
  }

  /**
   * Verifies and atomically consumes a one-time secret, selected by the
   * presented canonical SPKI pin.
   *
   * This is the frozen Task-4 entry point: the remote completion request carries
   * ONLY the secret, and ARC derives the pin from the authenticated mTLS
   * certificate. The pin is therefore the trusted selector, and the submitted
   * secret is the only attacker-controlled input.
   *
   * Ordering matters: monotonic expiry is evaluated BEFORE the secret is
   * examined, so an expired challenge can never be consumed and its secret can
   * never be replayed.
   *
   * On return the caller receives the bounded enrollment metadata needed for
   * atomic activation. This method performs NO trust-store mutation and NO
   * network I/O; Task 4 owns activation.
   */
  public completeBySpki(
    spkiPin: string,
    secret: unknown,
    commit: (challenge: PendingEnrollmentView) => void,
  ): ConsumeOutcome {
    // A malformed or unknown pin is indistinguishable from an unknown challenge.
    if (typeof spkiPin !== 'string' || !isValidSpkiPin(spkiPin)) {
      return { ok: false, reason: 'UNKNOWN_ENROLLMENT', counted: false };
    }

    const record = this.findLiveBySpki(spkiPin);
    if (record === undefined) {
      return { ok: false, reason: 'UNKNOWN_ENROLLMENT', counted: false };
    }
    if (this.getMonotonicTime() >= record.monotonicDeadline) {
      // Expiry wins over every other check, including a correct secret.
      this.pendingById.delete(record.enrollmentId);
      return { ok: false, reason: 'EXPIRED', counted: false };
    }

    // Constant-time comparison over equal-length digest material on EVERY path.
    //
    // A malformed secret is still hashed and still compared against a fixed
    // dummy digest, so the malformed path costs the same and follows the same
    // code as a well-formed wrong secret. A malformed submission is counted as
    // a failed attempt, exactly like any other mismatch.
    const submitted = typeof secret === 'string' ? secret : '';
    const candidateDigest = sha256Bytes(submitted);
    const wellFormed = ENROLLMENT_SECRET_REGEX.test(submitted);
    const expectedDigest = wellFormed ? record.secretDigest : DUMMY_SECRET_DIGEST;
    const digestMatches = timingSafeEqual(candidateDigest, expectedDigest);
    const secretMatches = wellFormed && digestMatches;

    if (!secretMatches) {
      record.failedAttempts += 1;
      if (record.failedAttempts >= MAX_FAILED_SECRET_ATTEMPTS) {
        // Third failure: immediate purge. The challenge cannot be revived, its
        // secret is permanently unusable, and its SPKI is released.
        this.pendingById.delete(record.enrollmentId);
        return { ok: false, reason: 'LOCKED_OUT', counted: true };
      }
      return { ok: false, reason: 'SECRET_MISMATCH', counted: true };
    }

    // The proof is correct, but NOTHING is consumed yet.
    //
    // `commit` performs durable activation and MUST run to completion first. If
    // it throws, the challenge stays live with its failed-attempt count
    // untouched, so the device can simply retry once the persistence problem is
    // resolved. Consumption and activation are therefore one synchronous step
    // from the caller's perspective, and this API cannot express
    // "consume now, persist later".
    const view = this.toView(record);
    // Withdraw the challenge from selection for the duration of the commit, so
    // even a synchronous re-entry from inside the callback cannot observe the
    // same single-use secret as still available.
    record.committing = true;
    try {
      commit(view);
    } catch {
      // Activation failed: the challenge becomes selectable again, with its
      // failed-attempt count and deadline untouched, so the device can retry
      // once the persistence problem is resolved.
      record.committing = false;
      return { ok: false, reason: 'ACTIVATION_FAILED', counted: false };
    }

    // Single-use: removal happens in the same synchronous step that observed the
    // successful commit, so no second caller can observe it as live.
    this.pendingById.delete(record.enrollmentId);
    return { ok: true, enrollment: view };
  }

  /** Removes every pending enrollment. Used only by restart/tests. */
  public clear(): void {
    this.pendingById.clear();
  }

  private toView(record: InternalPendingEnrollment): PendingEnrollmentView {
    const nowMono = this.getMonotonicTime();
    const remainingNanos = record.monotonicDeadline - nowMono;
    const remainingSeconds =
      remainingNanos <= 0n ? 0 : Number((remainingNanos + 999_999_999n) / 1_000_000_000n);
    return {
      enrollmentId: record.enrollmentId,
      clientId: record.clientId,
      clientType: record.clientType,
      spkiPin: record.spkiPin,
      displayLabel: record.displayLabel,
      createdAt: record.createdAtIso,
      expiresAt: record.expiresAtIso,
      remainingSeconds,
      failedAttempts: record.failedAttempts,
    };
  }
}

/**
 * Derives the stable internal operator identifier from a verified operator
 * public key.
 *
 * The identifier is a SHA-256 digest of the canonical DER SPKI encoding, so the
 * raw public key is never stored, logged, returned, or audited.
 */
export function deriveOperatorId(publicKey: {
  export(options: { format: 'der'; type: 'spki' }): Buffer | string;
}): string {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return createHash('sha256').update(der).digest('hex');
}
