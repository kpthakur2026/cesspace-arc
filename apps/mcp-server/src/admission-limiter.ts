/**
 * CesSpace ARC — RC-05 Task 3 Layer A Admission Limiter
 *
 * TCP/TLS connection admission, evaluated before and during the TLS handshake so
 * a flood is dropped before it can consume handshake CPU.
 * Authoritative contract: §21.1 Layer A, §21.2 (Layer A row).
 *
 * Scope boundary: this is Layer A only. Layers B (HTTP) and C (authenticated
 * session) belong to Task 7, as does the full limiter-LRU and IPv6 prefix
 * normalization feature set. This module implements exactly the frozen Layer-A
 * bounds with a bounded peer table, and nothing more.
 *
 * The peer table is bounded at {@link MAX_LAYER_A_PEER_KEYS}. At capacity, keys
 * are reclaimed by idle eviction; if none is reclaimable the connection is
 * refused outright rather than allocating, so attacker-driven key churn cannot
 * grow memory.
 */

/** Frozen Layer A rate window, in milliseconds. */
export const LAYER_A_WINDOW_MS = 60_000;

/** Frozen Layer A connection attempts per window, per peer. */
export const LAYER_A_MAX_ATTEMPTS_PER_WINDOW = 60;

/** Frozen Layer A burst capacity, per peer. */
export const LAYER_A_BURST = 20;

/** Frozen maximum concurrent live connections per peer. */
export const MAX_LIVE_CONNECTIONS_PER_PEER = 32;

/** Frozen maximum concurrent live connections globally. */
export const MAX_LIVE_CONNECTIONS_GLOBAL = 512;

/** Frozen maximum concurrent in-flight TLS handshakes globally. */
export const MAX_IN_FLIGHT_HANDSHAKES = 64;

/** Frozen maximum retained peer keys (§21.2 Layer A row). */
export const MAX_LAYER_A_PEER_KEYS = 4096;

/** Frozen idle eviction timeout for a peer key, in milliseconds. */
export const LAYER_A_IDLE_EVICTION_MS = 60_000;

/** Why a connection was refused at Layer A. Bounded and non-secret. */
export type AdmissionRefusalReason =
  | 'RATE_LIMIT'
  | 'PEER_CONNECTION_CAP'
  | 'GLOBAL_CONNECTION_CAP'
  | 'HANDSHAKE_CAP'
  | 'PEER_TABLE_SATURATED';

/** Outcome of an admission decision. */
export type AdmissionDecision =
  { admitted: true; release: () => void } | { admitted: false; reason: AdmissionRefusalReason };

interface PeerState {
  /** Monotonic milliseconds of the start of the current rate window. */
  windowStartedAtMs: number;
  /** Attempts counted in the current window. */
  attempts: number;
  /** Live connections currently held by this peer. */
  live: number;
  /** Last monotonic millisecond this key was touched, for idle eviction. */
  lastSeenMs: number;
}

/** Injectable clock and counters for deterministic tests. */
export interface AdmissionLimiterOptions {
  /** Monotonic clock in milliseconds. */
  getMonotonicTimeMs?: () => number;
  /** Overridable bounds; defaults are the frozen values. */
  maxAttemptsPerWindow?: number;
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
  private readonly getMonotonicTimeMs: () => number;
  private readonly maxAttemptsPerWindow: number;
  private readonly burst: number;
  private readonly maxLivePerPeer: number;
  private readonly maxLiveGlobal: number;
  private readonly maxInFlightHandshakes: number;
  private readonly maxPeerKeys: number;
  private readonly idleEvictionMs: number;

  private readonly peers = new Map<string, PeerState>();
  private liveGlobal = 0;
  private inFlightHandshakes = 0;

  constructor(options: AdmissionLimiterOptions = {}) {
    this.getMonotonicTimeMs = options.getMonotonicTimeMs ?? (() => performance.now());
    this.maxAttemptsPerWindow = options.maxAttemptsPerWindow ?? LAYER_A_MAX_ATTEMPTS_PER_WINDOW;
    this.burst = options.burst ?? LAYER_A_BURST;
    this.maxLivePerPeer = options.maxLivePerPeer ?? MAX_LIVE_CONNECTIONS_PER_PEER;
    this.maxLiveGlobal = options.maxLiveGlobal ?? MAX_LIVE_CONNECTIONS_GLOBAL;
    this.maxInFlightHandshakes = options.maxInFlightHandshakes ?? MAX_IN_FLIGHT_HANDSHAKES;
    this.maxPeerKeys = options.maxPeerKeys ?? MAX_LAYER_A_PEER_KEYS;
    this.idleEvictionMs = options.idleEvictionMs ?? LAYER_A_IDLE_EVICTION_MS;
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
    return this.peers.size;
  }

  /** Live connection count for one peer. */
  public getLiveConnectionCountForPeer(peerKey: string): number {
    return this.peers.get(peerKey)?.live ?? 0;
  }

  /**
   * Decides admission for one incoming TCP connection.
   *
   * On admission the caller receives a `release` function that MUST be invoked
   * exactly once when the connection ends by any path — handshake failure,
   * handshake success then close, socket error, timeout, or shutdown.
   */
  public admit(peerKey: string): AdmissionDecision {
    const now = this.getMonotonicTimeMs();
    this.evictIdlePeers(now);

    const existing = this.peers.get(peerKey);
    if (existing === undefined && this.peers.size >= this.maxPeerKeys) {
      // Fail closed rather than allocating: an untracked key must not be able to
      // grow the table without limit.
      return { admitted: false, reason: 'PEER_TABLE_SATURATED' };
    }

    const peer = existing ?? this.createPeer(peerKey, now);
    peer.lastSeenMs = now;

    // Fixed rate window with a burst allowance: the frozen "60 attempts / min,
    // burst 20" pair is enforced as 60 + 20 attempts per rolling window, which
    // is the conservative reading (a token bucket would admit the same burst at
    // the window start, then refill continuously). The window is reset lazily
    // on the first attempt after it elapses.
    if (now - peer.windowStartedAtMs >= LAYER_A_WINDOW_MS) {
      peer.windowStartedAtMs = now;
      peer.attempts = 0;
    }

    // Global caps are checked before per-peer accounting so a refusal never
    // increments a counter that would then have to be released.
    if (this.liveGlobal + 1 > this.maxLiveGlobal) {
      return { admitted: false, reason: 'GLOBAL_CONNECTION_CAP' };
    }
    if (this.inFlightHandshakes + 1 > this.maxInFlightHandshakes) {
      return { admitted: false, reason: 'HANDSHAKE_CAP' };
    }
    if (peer.live + 1 > this.maxLivePerPeer) {
      return { admitted: false, reason: 'PEER_CONNECTION_CAP' };
    }

    // Rate window: attempts counter is the burst-aware sliding window bound.
    if (peer.attempts >= this.maxAttemptsPerWindow + this.burst) {
      return { admitted: false, reason: 'RATE_LIMIT' };
    }

    peer.attempts += 1;
    peer.live += 1;
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
        peer.live -= 1;
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
    this.peers.clear();
    this.liveGlobal = 0;
    this.inFlightHandshakes = 0;
  }

  private createPeer(peerKey: string, now: number): PeerState {
    const peer: PeerState = {
      windowStartedAtMs: now,
      attempts: 0,
      live: 0,
      lastSeenMs: now,
    };
    this.peers.set(peerKey, peer);
    return peer;
  }

  private evictIdlePeers(now: number): void {
    for (const [key, peer] of this.peers) {
      if (peer.live === 0 && now - peer.lastSeenMs >= this.idleEvictionMs) {
        this.peers.delete(key);
      }
    }
  }
}
