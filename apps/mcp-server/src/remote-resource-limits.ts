/**
 * CesSpace ARC — RC-05 Task 7 Multi-Layer Resource Bounds
 *
 * The single implementation of every frozen RC-05 ADMISSION bound: canonical
 * peer-network normalization (§21.3) and the bounded token-bucket tables behind
 * Layers A, B, and C with their per-session concurrency slots (§21, §21.2,
 * §26 C-1, §26 C-3).
 *
 * Authoritative contract: §21 Layer B, §21 Layer C, §21.2, §21.3, §26 C-1 and
 * C-3, and the Task-7 row of §38 (controls RC05-NEG-55..61).
 *
 * Scope boundary — BOUNDS ONLY:
 * - Nothing here makes a policy decision, evaluates a rule, redeems an approval,
 *   or calls a subsystem. Every question answered is "is this within bound".
 * - Nothing here speaks MCP or composes an SDK transport; the `/mcp` network
 *   route stays deny-only until Task 8.
 * - Every production number is a module constant. None of them is reachable
 *   from `ArcServerConfig`, `RemoteConfig`, the environment, the CLI, HTTP, MCP,
 *   or JSON: a launch configuration cannot weaken a frozen bound.
 * - This module is PURE COMPUTATION over in-memory state. It opens no socket,
 *   reads no file, arms no timer, and buffers no request: the request-level
 *   ceilings and deadlines live in `remote-request-bounds.ts`. The remote
 *   execution bridge depends on this module and nothing else, so the bridge and
 *   its whole dependency closure stay free of transport or I/O machinery.
 *
 * Clock discipline: rate authorization is driven ONLY by a monotonic clock.
 * `Date.now()` is never consulted for a rate, concurrency, or eviction decision,
 * so a wall-clock correction can neither mint budget nor expire an entry.
 */

import * as net from 'node:net';

// ---------------------------------------------------------------------------
// §21 Layer B — secure HTTP pre-session limiter
// ---------------------------------------------------------------------------

/** Frozen Layer B refill rate: 120 requests/minute, per normalized peer. */
export const LAYER_B_REQUESTS_PER_MINUTE = 120;

/** Frozen Layer B burst capacity: the most tokens the bucket may hold. */
export const LAYER_B_BURST = 30;

/** Frozen Layer B retained-key ceiling (§21.2). */
export const MAX_LAYER_B_KEYS = 2048;

// ---------------------------------------------------------------------------
// §21 Layer C — authenticated session/device limiter
// ---------------------------------------------------------------------------

/** Frozen Layer C refill rate: 300 requests/minute, per session. */
export const LAYER_C_REQUESTS_PER_MINUTE = 300;

/** Frozen Layer C burst capacity: the most tokens the bucket may hold. */
export const LAYER_C_BURST = 60;

/** Frozen Layer C retained-key ceiling (§21.2). */
export const MAX_LAYER_C_KEYS = 1024;

// ---------------------------------------------------------------------------
// §21.2 — shared memory bounds
// ---------------------------------------------------------------------------

/**
 * Frozen idle eviction timeout, shared by every layer: 60 s of monotonic time.
 *
 * A key untouched for this long becomes reclaimable. The value is at or above
 * the time each layer needs to refill an empty bucket to its burst
 * (Layer A 20 s, Layer B 15 s, Layer C 12 s), so reclaiming an idle entry can
 * never hand a key more budget than the bucket it replaces would already hold.
 */
export const RATE_LIMITER_IDLE_EVICTION_MS = 60_000;

/**
 * Frozen Layer A retained-key ceiling (§21.2).
 *
 * Stated here with its two siblings so the §21.2 ceilings are readable in one
 * place; the Layer-A module re-exports it under its own name. The literal is the
 * approved Task-3 production value and is unchanged.
 */
export const MAX_LAYER_A_KEYS = 4096;

// ---------------------------------------------------------------------------
// §26 C-3 — per-session request concurrency
// ---------------------------------------------------------------------------

/** Frozen maximum outstanding MCP requests per authenticated session. */
export const MAX_OUTSTANDING_REQUESTS_PER_SESSION = 4;

// ---------------------------------------------------------------------------
// §21.3 — peer network normalization
// ---------------------------------------------------------------------------

/**
 * The single fail-closed bucket shared by every connection whose socket peer
 * address is unavailable.
 *
 * A missing peer address cannot become an attacker-controlled key: every such
 * connection lands in this ONE bucket. The literal is deliberately not
 * address-shaped, so it can never collide with a normalized peer key.
 */
export const UNKNOWN_PEER_KEY = 'unknown-peer';

/** A canonical dotted-quad from four octets. */
function dottedQuad(octets: readonly number[]): string {
  return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
}

/**
 * Parses a canonical dotted quad into octets, or returns null.
 *
 * Leading zeros are rejected (`192.000.002.001`), as are hex and octal forms and
 * out-of-range octets. `net.isIPv4` performs the same validation; this parser
 * exists because an IPv4 literal can also appear as the tail of an IPv6 address,
 * where the platform helper cannot be used on the fragment.
 */
function parseIpv4Octets(text: string): number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4) {
    return null;
  }
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) {
      return null;
    }
    const value = Number(part);
    if (value > 255) {
      return null;
    }
    octets.push(value);
  }
  return octets;
}

/**
 * Parses one colon-separated run of hextets, allowing an embedded IPv4 tail.
 *
 * Returns null for anything malformed. An empty run is only valid on the side of
 * a `::` compression, which the caller handles before calling this.
 */
function parseHextetRun(text: string): number[] | null {
  if (text.length === 0) {
    return [];
  }
  const parts = text.split(':');
  const groups: number[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part.length === 0) {
      return null;
    }
    if (part.includes('.')) {
      // An embedded IPv4 literal is only legal as the final component.
      if (index !== parts.length - 1) {
        return null;
      }
      const octets = parseIpv4Octets(part);
      if (octets === null) {
        return null;
      }
      groups.push((octets[0] << 8) | octets[1]);
      groups.push((octets[2] << 8) | octets[3]);
      continue;
    }
    if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) {
      return null;
    }
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

/**
 * Parses an IPv6 literal into exactly eight 16-bit groups, or returns null.
 *
 * Handles upper/lower case, any number of zero-compression variants, and both
 * spellings of an IPv4-mapped tail. A zone index (`fe80::1%eth0`) is dropped:
 * the interface identifier is a local label, is never part of the network
 * identity, and is discarded by `/64` grouping in every case anyway.
 */
function parseIpv6Groups(address: string): number[] | null {
  let text = address;
  const zoneIndex = text.indexOf('%');
  if (zoneIndex !== -1) {
    if (zoneIndex === 0) {
      return null;
    }
    text = text.slice(0, zoneIndex);
  }

  const compressionIndex = text.indexOf('::');
  if (compressionIndex !== -1 && text.indexOf('::', compressionIndex + 1) !== -1) {
    // At most one zero-compression is allowed in an IPv6 literal.
    return null;
  }

  const headText = compressionIndex === -1 ? text : text.slice(0, compressionIndex);
  const tailText = compressionIndex === -1 ? '' : text.slice(compressionIndex + 2);

  const head = parseHextetRun(headText);
  const tail = parseHextetRun(tailText);
  if (head === null || tail === null) {
    return null;
  }

  if (compressionIndex === -1) {
    return head.length === 8 ? head : null;
  }

  // `::` must stand for at least one omitted group.
  const omitted = 8 - head.length - tail.length;
  if (omitted < 1) {
    return null;
  }
  return [...head, ...new Array<number>(omitted).fill(0), ...tail];
}

/** Index and length of the longest run of zero groups, leftmost on a tie. */
function longestZeroRun(groups: readonly number[]): { start: number; length: number } {
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  let runLength = 0;
  for (let index = 0; index < groups.length; index += 1) {
    if (groups[index] === 0) {
      if (runStart === -1) {
        runStart = index;
      }
      runLength += 1;
      if (runLength > bestLength) {
        bestLength = runLength;
        bestStart = runStart;
      }
    } else {
      runStart = -1;
      runLength = 0;
    }
  }
  // A single zero group is written as `0`, never compressed.
  return bestLength >= 2 ? { start: bestStart, length: bestLength } : { start: -1, length: 0 };
}

/** Canonical lowercase zero-compressed form of eight 16-bit groups. */
function formatIpv6Groups(groups: readonly number[]): string {
  const run = longestZeroRun(groups);
  if (run.start === -1) {
    return groups.map((group) => group.toString(16)).join(':');
  }
  const head = groups
    .slice(0, run.start)
    .map((group) => group.toString(16))
    .join(':');
  const tail = groups
    .slice(run.start + run.length)
    .map((group) => group.toString(16))
    .join(':');
  return `${head}::${tail}`;
}

/** True when the address is the IPv4-mapped `::ffff:0:0/96` form. */
function isIpv4Mapped(groups: readonly number[]): boolean {
  for (let index = 0; index < 5; index += 1) {
    if (groups[index] !== 0) {
      return false;
    }
  }
  return groups[5] === 0xffff;
}

/** Dotted quad for the trailing 32 bits of an IPv4-mapped address. */
function mappedIpv4(groups: readonly number[]): string {
  const high = groups[6];
  const low = groups[7];
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

/**
 * THE canonical peer-network normalizer (§21.3), shared by Layer A and Layer B.
 *
 * Only the socket peer address is authoritative. `X-Forwarded-For`, `Forwarded`,
 * `X-Real-IP`, `Host`, and every request parameter are ignored by construction:
 * this function is given an address and can read nothing else.
 *
 * Returns:
 * - a canonical dotted quad for IPv4 (`192.0.2.1` → `192.0.2.1`);
 * - the same dotted quad for an IPv4-mapped IPv6 peer, in either spelling
 *   (`::ffff:192.0.2.1` and `::ffff:c000:201` → `192.0.2.1`), so an IPv4 limit
 *   cannot be bypassed by presenting the mapped form;
 * - a canonical lowercase zero-compressed `/64` network for IPv6
 *   (`2001:0db8:ABCD:0012::1` → `2001:db8:abcd:12::/64`), so rotating the
 *   interface identifier inside one subnet shares one bucket;
 * - {@link UNKNOWN_PEER_KEY} when no peer address is available at all — ONE
 *   bounded bucket, never an unbounded family of unique keys;
 * - `null` for a malformed address, which callers treat as fail-closed refusal.
 *   A string that is not an address never becomes a limiter key.
 */
export function normalizePeerNetwork(address: unknown): string | null {
  if (address === undefined || address === null) {
    return UNKNOWN_PEER_KEY;
  }
  if (typeof address !== 'string') {
    return null;
  }
  if (address.length === 0) {
    return UNKNOWN_PEER_KEY;
  }

  // IPv4: `net.isIPv4` accepts exactly the canonical dotted quad, rejecting
  // leading zeros, hex/octal octets, and out-of-range values.
  if (net.isIPv4(address)) {
    const octets = parseIpv4Octets(address);
    return octets === null ? null : dottedQuad(octets);
  }

  if (net.isIPv6(address)) {
    const groups = parseIpv6Groups(address);
    if (groups === null) {
      return null;
    }
    if (isIpv4Mapped(groups)) {
      return mappedIpv4(groups);
    }
    // Everything below bit 64 is discarded, so every address in one /64 subnet
    // — and every spelling of it — produces this one key.
    const network = [...groups.slice(0, 4), 0, 0, 0, 0];
    return `${formatIpv6Groups(network)}/64`;
  }

  return null;
}

// ---------------------------------------------------------------------------
// §21.2 — bounded token-bucket table
// ---------------------------------------------------------------------------

/** One retained limiter entry. */
export interface RateBucket {
  /** Token level. Never exceeds the burst capacity. */
  tokens: number;
  /** Monotonic millisecond of the last refill, for lazy accrual. */
  lastRefillMs: number;
  /** Last monotonic millisecond this key was touched, for idle eviction. */
  lastSeenMs: number;
  /**
   * Live holders of this key: admitted connections for Layer A, admitted
   * in-flight requests for Layer C. A key with a holder is never reclaimable,
   * so a release closure can never act on a reclaimed entry.
   */
  holders: number;
}

/** Why a bounded table refused an attempt. Bounded and non-secret. */
export type RateRefusalReason = 'RATE_LIMIT' | 'TABLE_SATURATED';

/** Why a bounded table refused an outstanding-work slot. Bounded and non-secret. */
export type HolderRefusalReason = 'CONCURRENCY_LIMIT';

/** Outcome of one token decision. */
export type ConsumeDecision =
  { consumed: true; bucket: RateBucket } | { consumed: false; reason: RateRefusalReason };

/** Outcome of one outstanding-work slot decision. */
export type HoldDecision =
  { held: true; release: () => void } | { held: false; reason: HolderRefusalReason };

/** Bounds for one bounded table. All production values are frozen constants. */
export interface BoundedRequestLimiterOptions {
  /** Refill rate, in tokens per minute. */
  requestsPerMinute: number;
  /** Maximum tokens the bucket may hold. */
  burst: number;
  /** Frozen retained-key ceiling (§21.2). */
  maxKeys: number;
  /** Idle eviction timeout. Defaults to the frozen 60 s. */
  idleEvictionMs?: number;
  /** Monotonic clock. Production uses `performance.now()`. */
  getMonotonicTimeMs?: () => number;
  /**
   * Maximum outstanding holders per key.
   *
   * Omitted for layers with no per-key concurrency bound (Layers A and B), in
   * which case the returned `release` is a no-op.
   */
  maxOutstandingPerKey?: number;
}

/**
 * A token-bucket rate table with a hard key ceiling (§21.1, §21.2).
 *
 * Memory model:
 * - `entries.size` never exceeds `maxKeys`, at any instant.
 * - When a NEW key arrives at capacity, the table first reclaims entries that
 *   are idle past the eviction timeout AND hold nothing. Reclamation is
 *   deterministic: the map is kept in access order, so the least recently used
 *   reclaimable entry goes first.
 * - A non-expired entry, or one with a live holder, is NEVER silently evicted to
 *   admit a new attacker key. If nothing is reclaimable the new key is REFUSED
 *   without being allocated, which is what stops source-key churn from growing
 *   memory.
 * - There is no auxiliary array, set, queue, tombstone, or history anywhere in
 *   this class: the map is the whole state.
 *
 * Rate model: a MONOTONIC TOKEN BUCKET, not a fixed window. "120 requests / min
 * (burst 30)" is a refill of one token per 500 ms into a bucket that holds at
 * most 30. A fixed window would admit 150 immediate requests, which is not a
 * burst capacity of 30, so it is not used.
 *
 * Two primitives, so each layer composes exactly the bounds it owns:
 * {@link BoundedRequestLimiter.consume} for the rate budget, and
 * {@link BoundedRequestLimiter.tryHold} for outstanding-work concurrency.
 *
 * All transitions are synchronous, so a decision and its counter effects are
 * atomic with respect to other work on the event loop.
 */
export class BoundedRequestLimiter {
  private readonly getMonotonicTimeMs: () => number;
  private readonly refillMs: number;
  private readonly burst: number;
  private readonly maxKeys: number;
  private readonly idleEvictionMs: number;
  private readonly maxOutstandingPerKey?: number;

  /** Retained keys, in access order (oldest first). The whole state. */
  private readonly entries = new Map<string, RateBucket>();

  constructor(options: BoundedRequestLimiterOptions) {
    this.getMonotonicTimeMs = options.getMonotonicTimeMs ?? (() => performance.now());
    this.refillMs = 60_000 / options.requestsPerMinute;
    this.burst = options.burst;
    this.maxKeys = options.maxKeys;
    this.idleEvictionMs = options.idleEvictionMs ?? RATE_LIMITER_IDLE_EVICTION_MS;
    this.maxOutstandingPerKey = options.maxOutstandingPerKey;
  }

  /** Retained keys. Exposed so bound tests can assert the ceiling holds. */
  public getRetainedKeyCount(): number {
    return this.entries.size;
  }

  /** Live holders for one key. */
  public getHolderCount(key: string): number {
    return this.entries.get(key)?.holders ?? 0;
  }

  /** The bucket for one key, if retained. */
  public getBucket(key: string): RateBucket | undefined {
    return this.entries.get(key);
  }

  /**
   * The retained keys, oldest first.
   *
   * @internal Test-only observation of the exact keys a layer bucketed on. It is
   * never part of a response, a log line, or a status object.
   */
  public getRetainedKeysForTests(): string[] {
    return [...this.entries.keys()];
  }

  /**
   * Consumes one token for `key`, if the table can do so within its bounds.
   *
   * Returns the retained bucket on success so the caller can account for the
   * work it is about to admit. `holders` is deliberately NOT touched here: each
   * layer decides its own holder semantics, so a token refusal, a holder
   * refusal, and a global cap can each keep a precise refusal reason.
   *
   * A `RATE_LIMIT` refusal still records the access, because the key really was
   * used; only `TABLE_SATURATED` leaves the table completely untouched, which is
   * what makes source-key churn unable to grow memory.
   */
  public consume(key: string): ConsumeDecision {
    const now = this.getMonotonicTimeMs();
    this.evictIdle(now);

    const existing = this.entries.get(key);
    if (existing === undefined && this.entries.size >= this.maxKeys) {
      // Fail closed rather than allocating: an untracked key must not be able to
      // grow the table without limit.
      return { consumed: false, reason: 'TABLE_SATURATED' };
    }

    const bucket = existing ?? this.createBucket(key, now);
    if (existing !== undefined) {
      // Move to the most-recently-used end. Map iteration order is the LRU
      // order, so this is the only bookkeeping the ordering needs.
      this.entries.delete(key);
      this.entries.set(key, bucket);
    }
    bucket.lastSeenMs = now;

    // Lazily accrue tokens at the frozen rate, capped at the burst capacity so a
    // long idle period can never bank more than one burst.
    const elapsedMs = now - bucket.lastRefillMs;
    if (elapsedMs > 0) {
      bucket.tokens = Math.min(this.burst, bucket.tokens + elapsedMs / this.refillMs);
      bucket.lastRefillMs = now;
    }

    if (bucket.tokens < 1) {
      return { consumed: false, reason: 'RATE_LIMIT' };
    }
    bucket.tokens -= 1;
    return { consumed: true, bucket };
  }

  /**
   * Takes one outstanding-work slot on `bucket`, if one is available.
   *
   * The fifth simultaneous request of a session at the frozen bound is refused
   * IMMEDIATELY — the work is never queued, so no unbounded backlog can
   * accumulate behind a session. When no `maxOutstandingPerKey` is configured
   * the slot is always granted and `release` is a no-op, so every caller has one
   * uniform contract.
   */
  public tryHold(bucket: RateBucket): HoldDecision {
    if (this.maxOutstandingPerKey !== undefined && bucket.holders + 1 > this.maxOutstandingPerKey) {
      return { held: false, reason: 'CONCURRENCY_LIMIT' };
    }
    bucket.holders += 1;

    let released = false;
    return {
      held: true,
      release: () => {
        if (released) {
          return;
        }
        released = true;
        bucket.holders -= 1;
      },
    };
  }

  /** Drops all state. Used on shutdown: limiter state is volatile and never persisted. */
  public reset(): void {
    this.entries.clear();
  }

  private createBucket(key: string, now: number): RateBucket {
    const bucket: RateBucket = {
      // A fresh key starts with a full burst available.
      tokens: this.burst,
      lastRefillMs: now,
      lastSeenMs: now,
      holders: 0,
    };
    this.entries.set(key, bucket);
    return bucket;
  }

  /** Reclaims every entry that is idle past the timeout and holds nothing. */
  private evictIdle(now: number): void {
    for (const [key, bucket] of this.entries) {
      if (bucket.holders === 0 && now - bucket.lastSeenMs >= this.idleEvictionMs) {
        this.entries.delete(key);
      }
    }
  }
}
