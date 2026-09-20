/**
 * CesSpace ARC — RC-05 Task 3 Layer A Admission Limiter
 *
 * TCP/TLS connection admission, evaluated before and during the TLS handshake so
 * a flood is dropped before it can consume handshake CPU.
 * Authoritative contract: §21.1 Layer A, §21.2 (Layer A row), §21.3, §26 C-1.
 *
 * Task 7 completed the peer table this module was built around: peer keys are
 * now CANONICAL NETWORK identities rather than raw socket strings, and the
 * retained-key table is the shared bounded implementation in
 * `remote-resource-limits.ts` (access-ordered LRU reclamation, fail-closed
 * saturation). The connection-state lifecycle, the counters, and every frozen
 * production value are unchanged from the approved Task-3 baseline.
 *
 * Scope boundary: this is Layer A only. Layers B (secure HTTP pre-session) and C
 * (authenticated session) are separate instances of the same bounded table,
 * owned by the gateway and the remote execution bridge respectively.
 *
 * Rate model: a MONOTONIC TOKEN BUCKET, not a fixed window. The frozen pair
 * "60 attempts / min (burst 20)" is a refill rate of one token per second with a
 * bucket that holds at most 20. A fixed window would admit 60 + 20 = 80
 * immediate attempts, which is not a burst capacity of 20, so it is not used.
 *
 * Keying: the key handed to {@link AdmissionLimiter.admit} MUST already be a
 * canonical peer-network key. The gateway derives it with
 * `normalizePeerNetwork()`, which unmaps IPv4-mapped IPv6 peers and groups IPv6
 * peers by `/64` so rotating an interface identifier cannot buy a second bucket.
 */

import {
  BoundedRequestLimiter,
  MAX_LAYER_A_KEYS,
  type RateRefusalReason,
} from './remote-resource-limits.js';

/** Frozen Layer A rate window, in milliseconds. */
export const LAYER_A_WINDOW_MS = 60_000;

/** Frozen Layer A refill rate, in connection-attempt tokens per minute, per peer. */
export const LAYER_A_ATTEMPTS_PER_MINUTE = 60;

/** Frozen Layer A burst capacity: the maximum tokens the bucket may hold. */
export const LAYER_A_BURST = 20;

/** Refill interval implied by the frozen rate: one token per second. */
export const LAYER_A_REFILL_MS = 60_000 / LAYER_A_ATTEMPTS_PER_MINUTE;

/** Frozen maximum concurrent live connections per peer. */
export const MAX_LIVE_CONNECTIONS_PER_PEER = 32;

/** Frozen maximum concurrent live connections globally. */
export const MAX_LIVE_CONNECTIONS_GLOBAL = 512;

/** Frozen maximum concurrent in-flight TLS handshakes globally. */
export const MAX_IN_FLIGHT_HANDSHAKES = 64;

/** Frozen maximum retained peer keys (§21.2 Layer A row). */
export const MAX_LAYER_A_PEER_KEYS = MAX_LAYER_A_KEYS;

/** Frozen idle eviction timeout for a peer key, in milliseconds. */
export const LAYER_A_IDLE_EVICTION_MS = 60_000;

/** Why a connection was refused at Layer A. Bounded and non-secret. */
export type AdmissionRefusalReason =
  | 'RATE_LIMIT'
  | 'PEER_CONNECTION_CAP'
  | 'GLOBAL_CONNECTION_CAP'
  | 'HANDSHAKE_CAP'
  | 'PEER_TABLE_SATURATED'
  | 'PEER_KEY_INVALID';

/** Outcome of an admission decision. */
export type AdmissionDecision =
  { admitted: true; release: () => void } | { admitted: false; reason: AdmissionRefusalReason };

/** Injectable clock and counters for deterministic tests. */
export interface AdmissionLimiterOptions {
  /** Monotonic clock in milliseconds. */
  getMonotonicTimeMs?: () => number;
  /** Overridable bounds; defaults are the frozen values. */
  attemptsPerMinute?: number;
  burst?: number;
  maxLivePerPeer?: number;
  maxLiveGlobal?: number;
  maxInFlightHandshakes?: number;
  maxPeerKeys?: number;
  idleEvictionMs?: number;
}

/**
 * Layer A admission limiter.
 *
 * All transitions are synchronous, so a decision and its counter effects are
 * atomic with respect to other connections on the event loop.
 */
export class AdmissionLimiter {
  private readonly peers: BoundedRequestLimiter;
  private readonly maxLivePerPeer: number;
  private readonly maxLiveGlobal: number;
  private readonly maxInFlightHandshakes: number;

  private liveGlobal = 0;
  private inFlightHandshakes = 0;

  constructor(options: AdmissionLimiterOptions = {}) {
    this.maxLivePerPeer = options.maxLivePerPeer ?? MAX_LIVE_CONNECTIONS_PER_PEER;
    this.maxLiveGlobal = options.maxLiveGlobal ?? MAX_LIVE_CONNECTIONS_GLOBAL;
    this.maxInFlightHandshakes = options.maxInFlightHandshakes ?? MAX_IN_FLIGHT_HANDSHAKES;
    this.peers = new BoundedRequestLimiter({
      requestsPerMinute: options.attemptsPerMinute ?? LAYER_A_ATTEMPTS_PER_MINUTE,
      burst: options.burst ?? LAYER_A_BURST,
      maxKeys: options.maxPeerKeys ?? MAX_LAYER_A_PEER_KEYS,
      idleEvictionMs: options.idleEvictionMs ?? LAYER_A_IDLE_EVICTION_MS,
      ...(options.getMonotonicTimeMs === undefined
        ? {}
        : { getMonotonicTimeMs: options.getMonotonicTimeMs }),
    });
  }

  /** Live connection count across all peers. */
  public getLiveConnectionCount(): number {
    return this.liveGlobal;
  }

  /** In-flight TLS handshake count. */
  public getInFlightHandshakeCount(): number {
    return this.inFlightHandshakes;
  }

  /** Retained peer keys. Exposed so bound tests can assert the ceiling holds. */
  public getRetainedPeerKeyCount(): number {
    return this.peers.getRetainedKeyCount();
  }

  /** Live connection count for one peer. */
  public getLiveConnectionCountForPeer(peerKey: string): number {
    return this.peers.getHolderCount(peerKey);
  }

  /**
   * The retained peer keys, in access order (oldest first).
   *
   * @internal Test-only observation of the exact keys Layer A bucketed on, used
   * to prove canonical peer normalization at the transport boundary. Never part
   * of a response, a log line, or a status object.
   */
  public getRetainedPeerKeysForTests(): string[] {
    return this.peers.getRetainedKeysForTests();
  }

  /**
   * Decides admission for one incoming TCP connection.
   *
   * On admission the caller receives a `release` function that MUST be invoked
   * exactly once when the connection ends by any path — handshake failure,
   * handshake success then close, socket error, timeout, or shutdown.
   */
  public admit(peerKey: string): AdmissionDecision {
    // Saturation is decided before anything is allocated, and the attempt is
    // rate-accounted only once a bucket exists for the peer.
    const consumed = this.peers.consume(peerKey);
    if (!consumed.consumed) {
      return { admitted: false, reason: refusalReasonFor(consumed.reason) };
    }
    const bucket = consumed.bucket;

    // Concurrency bounds are evaluated after rate accounting, so their refusal
    // reasons stay precise and the token cost of the attempt is still recorded.
    if (this.liveGlobal + 1 > this.maxLiveGlobal) {
      return { admitted: false, reason: 'GLOBAL_CONNECTION_CAP' };
    }
    if (this.inFlightHandshakes + 1 > this.maxInFlightHandshakes) {
      return { admitted: false, reason: 'HANDSHAKE_CAP' };
    }
    if (bucket.holders + 1 > this.maxLivePerPeer) {
      return { admitted: false, reason: 'PEER_CONNECTION_CAP' };
    }

    // The live slot is accounted on the retained bucket itself, so the release
    // closure acts on the SAME entry the per-peer cap is measured against. A
    // bucket with a live connection is never reclaimable, so the closure can
    // never outlive its entry and be applied to a replacement key.
    bucket.holders += 1;
    this.liveGlobal += 1;
    this.inFlightHandshakes += 1;

    let released = false;
    return {
      admitted: true,
      release: () => {
        if (released) {
          return;
        }
        released = true;
        // The handshake counter is released by the caller when the handshake
        // settles, so it is not decremented here.
        bucket.holders -= 1;
        this.liveGlobal -= 1;
      },
    };
  }

  /**
   * Records that a handshake settled (succeeded or failed), releasing the
   * in-flight handshake slot exactly once.
   */
  public releaseHandshake(): void {
    if (this.inFlightHandshakes > 0) {
      this.inFlightHandshakes -= 1;
    }
  }

  /** Drops all state. Used on shutdown. */
  public reset(): void {
    this.peers.reset();
    this.liveGlobal = 0;
    this.inFlightHandshakes = 0;
  }
}

/** Maps a shared bucket refusal onto the Layer-A refusal vocabulary. */
function refusalReasonFor(reason: RateRefusalReason): AdmissionRefusalReason {
  return reason === 'RATE_LIMIT' ? 'RATE_LIMIT' : 'PEER_TABLE_SATURATED';
}
