/**
 * Package-internal Tier-3 anchor capability token and deterministic seams
 * (RC-06 Task 5, §29, §90).
 *
 * The token and these types are NEVER exported from the root package index, are
 * NOT listed in the package's `exports` map, and are not reachable from
 * ArcServerConfig, the environment, the CLI or any MCP request. The unforgeable
 * symbol is what authorizes the seams below — exactly as `CHECKPOINT_TEST_TOKEN`
 * authorizes Task-4 hooks and `STORAGE_TEST_TOKEN` authorizes Task-1 hooks.
 *
 * Every seam here exists so a security property can be *proved* deterministically
 * rather than argued: an anchor that never answers so the five-second budget can
 * be observed without waiting five seconds, an injected backoff clock so the
 * frozen `1s, 2s, 4s, 8s, 16s` vector can be read rather than timed, a spool
 * write that fails after the checkpoint was already durable, a receipt append
 * that fails after the signature verified, and a CA root so a real TLS 1.3
 * session can be established against an ephemeral test PKI.
 *
 * None of these can change what an anchor acknowledgement *means*. They cannot
 * alter the receipt preimage, the signature, the store binding, the checkpoint
 * hash binding, the spool filename, the backpressure ceilings, or the ordering
 * of the durable transitions. They change only whether a step completes, when a
 * timer fires, and which socket a request is written to.
 *
 * @internal
 */

import type { CodedError } from './errors.js';

/** The unforgeable authorization for the seams in this module. */
export const ANCHOR_TEST_TOKEN = Symbol('ANCHOR_TEST_TOKEN');

/** The exact HTTP envelope the anchor contract is defined over (rc06 §14.3). */
export interface AnchorTransportRequest {
  /** The validated endpoint, exactly as configured. */
  endpoint: string;
  /** Always `POST`. There is no method negotiation. */
  method: 'POST';
  /** `Content-Type`, `Content-Length`, `Idempotency-Key` and `Host`. */
  headers: Readonly<Record<string, string>>;
  /** Canonical JSON of the pending checkpoint, and nothing else. */
  body: Buffer;
  /**
   * Trust roots for certificate verification.
   *
   * Absent in production, where the platform trust store applies. Present only
   * through {@link AnchorTestHooks.ca}, so the suite can reach an ephemeral PKI
   * without weakening certificate verification: `rejectUnauthorized` and the
   * TLS 1.3 floor are not configurable and never move.
   */
  ca?: string | Buffer | readonly (string | Buffer)[];
}

/** The bounded response surface one attempt observes. */
export interface AnchorTransportResponse {
  statusCode: number;
  /** The response body. The production transport never returns more than 2 KiB. */
  body: Buffer;
}

/**
 * One network attempt.
 *
 * Implementations MUST honour `signal`: the attempt budget is enforced by
 * aborting the attempt, not by racing a promise, so a transport that ignores the
 * signal would make the timeout unenforceable. The default transport destroys
 * the request when the signal aborts.
 */
export type AnchorTransport = (
  request: AnchorTransportRequest,
  signal: AbortSignal,
) => Promise<AnchorTransportResponse>;

/** One observed dispatch of a pending checkpoint to the anchor. */
export interface AnchorNetworkObservation {
  /** The `Idempotency-Key`, which is the `checkpointHash` (rc06 §14.3). */
  idempotencyKey: string;
  /** 1-based attempt index within the current retry cycle. */
  attempt: number;
  /** The exact canonical JSON byte length that was or would be transmitted. */
  bodyBytes: number;
}

/** A transport failure classified for the retry machinery. */
export interface AnchorTransportFailure {
  kind: 'network' | 'timeout';
  cause: CodedError;
}

/** Deterministic seams for Task-5 security tests. @internal */
export interface AnchorTestHooks {
  /**
   * The real UID every durable anchor artifact is expected to be owned by.
   *
   * Lets the ownership rule be exercised without a privileged `chown`. The
   * production factory never reads this and always uses the process real UID.
   */
  expectedUid?: number;

  /**
   * Replaces the network attempt.
   *
   * The substitute receives the same request envelope the production transport
   * would, including the `Idempotency-Key` and the exact body bytes, and the
   * same abort signal. It cannot be reached from configuration.
   */
  transport?: AnchorTransport;

  /** Trust roots for certificate verification, for an ephemeral test PKI. */
  ca?: string | Buffer | readonly (string | Buffer)[];

  /**
   * Schedules the per-attempt timeout callback and returns a handle.
   *
   * The default is `setTimeout`. A test replaces it to observe the requested
   * budget and to fire the timeout deterministically, which is what proves the
   * budget is 5,000 ms without spending it.
   */
  setAttemptTimer?: (callback: () => void, ms: number) => unknown;

  /** Cancels a handle returned by {@link setAttemptTimer}. Default `clearTimeout`. */
  clearAttemptTimer?: (handle: unknown) => void;

  /**
   * Sleeps for the fixed backoff delay between attempts.
   *
   * The default is a real timer. A test replaces it to read the frozen
   * `1s, 2s, 4s, 8s, 16s` vector without waiting thirty-one seconds for it.
   */
  sleep?: (ms: number) => Promise<void>;

  /** Observes each dispatched attempt, after the spool entry is durable. */
  networkObserver?: (observation: AnchorNetworkObservation) => void;

  /**
   * Runs after the spool entry's bytes are written and immediately before the
   * entry and its directory are `fsync`ed.
   *
   * This is the window that decides whether a checkpoint may be transmitted:
   * if the sync fails, the network must never be reached and the engine must
   * fail closed rather than transmit on an uncertain spool.
   */
  beforeSpoolSync?: (filePath: string) => void;

  /**
   * Forces the spool entry write to fail.
   *
   * `zero` reports a write of zero bytes, `partial` writes a strict prefix and
   * then reports zero, and `error` throws from the write itself. All three model
   * an uncertain persistence outcome, which must fail closed without
   * transmitting.
   */
  spoolWriteFault?: 'error' | 'partial' | 'zero';

  /** Forces the spool entry `fsync` to fail after a complete write. */
  spoolFileSyncFault?: boolean;

  /** Forces the spool directory `fsync` to fail after a complete entry sync. */
  spoolDirectorySyncFault?: boolean;

  /**
   * Runs immediately before the receipt append is validated and written.
   *
   * Lets a test substitute the receipt pathname, replace the verified inode, or
   * grow the verified file in the window between the descriptor being
   * established and the next receipt being committed. The revalidation runs
   * after it and fails closed, so it cannot make an unauthorized append succeed.
   */
  beforeReceiptAppend?: (filePath: string) => void;

  /**
   * Runs after the ledger history has been read to EOF and verified, and
   * immediately before the artifact identity is re-established.
   *
   * Lets a test grow, shrink, replace or detach the verified ledger in the
   * window between "the bytes were consumed" and "the bytes are still what the
   * artifact contains".
   */
  beforeReceiptVerificationIdentityCheck?: (filePath: string) => void;

  /** Forces the receipt write to fail, with the same three fault shapes. */
  receiptWriteFault?: 'error' | 'partial' | 'zero';

  /** Forces the receipt `fdatasync` to fail after a complete write. */
  receiptDataSyncFault?: boolean;

  /**
   * Wall clock in milliseconds since the epoch.
   *
   * Drives nothing that is signed: `anchorTimestamp` is the *anchor's* claim,
   * never ARC's, so a manipulated clock cannot manufacture an acknowledgement.
   * It exists only so a test can make an out-of-order timestamp observable.
   */
  clockMs?: () => number;
}
