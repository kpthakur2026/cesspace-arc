/**
 * CesSpace ARC — RC-05 Task 5 Secure Session Lifecycle
 *
 * The gateway session domain: server-generated session identity, opaque session
 * token issuance, digest-only retention, binding, monotonic expiry, revocation,
 * active-session quotas, and the PURE wire-admission decisions that Task 8 will
 * later connect to the Streamable HTTP transport.
 *
 * Authoritative contract: §5.3, §5.4, §11, §25.1, §26 C-2/C-4, and the Task-5
 * row of §38 (controls RC05-NEG-39..47, RC05-NEG-69).
 *
 * Deliberate boundaries:
 * - No network I/O, no filesystem I/O, no HTTP server, no MCP SDK transport.
 * - No policy evaluation, no approval redemption, no subsystem, no tool dispatch.
 * - No actor-context derivation: Task 6 owns that, and the trusted session result
 *   here is the input it will consume, not the final ActorContext.
 *
 * The RC-05 session model is NOT the legacy `AuthTokenClaims` interface: these
 * tokens are opaque, carry zero structured claims, and hold no client-readable
 * identity. The raw token is 32 CSPRNG bytes rendered as 64 lowercase hex
 * characters, and the server retains only its SHA-256 digest.
 */

import crypto from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';
import {
  isValidDeviceId,
  isValidSpkiPin,
  validateClientId,
  validateClientType,
} from './device-identity.js';
import type { DeviceTrustStore } from './trust-store.js';

// ---------------------------------------------------------------------------
// Frozen bounds (§11, §26 C-2)
// ---------------------------------------------------------------------------

/** Session IDs and session tokens are both 256 bits rendered as lowercase hex. */
export const SESSION_HEX_LENGTH = 64;

/** Server-issued `Mcp-Session-Id` shape. Opaque and server-generated. */
export const SESSION_ID_REGEX = /^[0-9a-f]{64}$/;

/** Session token shape. Opaque and server-generated, independent of the ID. */
export const SESSION_TOKEN_REGEX = /^[0-9a-f]{64}$/;

/**
 * Maximum UTF-8 byte length of a PRESENTED session token (§11).
 *
 * Checked before any decoding or hashing, so an oversized credential is refused
 * without an unbounded allocation and without touching session state.
 */
export const MAX_SESSION_TOKEN_INPUT_BYTES = 128;

/** Absolute session lifetime, enforced on the monotonic clock (§11). */
export const SESSION_ABSOLUTE_TTL_SECONDS = 3600;

/** Idle lifetime since the last SUCCESSFULLY authenticated request (§11). */
export const SESSION_IDLE_TIMEOUT_SECONDS = 300;

/** Maximum live sessions for one device (§26 C-2). */
export const MAX_ACTIVE_SESSIONS_PER_DEVICE = 8;

/** Maximum live sessions for one client (§26 C-2). */
export const MAX_ACTIVE_SESSIONS_PER_CLIENT = 64;

/** Maximum live sessions in the process (§26 C-2). */
export const MAX_ACTIVE_SESSIONS_GLOBAL = 1024;

/**
 * Bounded retries when a generated session ID collides with a live session.
 *
 * A collision means the CSPRNG produced an ID already in use. The generator
 * never overwrites the live session; it draws again, and gives up fail-closed
 * after this many attempts rather than looping forever.
 */
export const MAX_SESSION_ID_GENERATION_ATTEMPTS = 8;

/** Response header carrying the raw session token exactly once (§5.3 F). */
export const ARC_SESSION_TOKEN_HEADER = 'Arc-Session-Token';

/** Request/response header carrying the server-issued session identity (§5.4). */
export const MCP_SESSION_ID_HEADER = 'Mcp-Session-Id';

/** The only recognized Authorization scheme for the session credential. */
export const SESSION_AUTH_SCHEME = 'Bearer';

/**
 * Maximum useful length of a session `Authorization` header.
 *
 * `Bearer` + one separator + a 128-byte token is the only accepted syntax, so a
 * longer value cannot be a valid credential. The parser checks this length FIRST
 * and refuses anything above it before slicing or splitting, so a peer cannot
 * make ARC allocate proportionally to an arbitrarily large header. The global
 * 16 KiB HTTP header bound is Task 7's; this is Task 5's own credential bound.
 */
export const MAX_SESSION_AUTHORIZATION_HEADER_BYTES =
  SESSION_AUTH_SCHEME.length + 1 + MAX_SESSION_TOKEN_INPUT_BYTES;

/**
 * How long an unused session-ID reservation survives before being reclaimed.
 *
 * This is INTERNAL housekeeping, not a wire contract: a reservation exists only
 * for the round trip between ID generation and `initialize` completion, and an
 * abandoned one must not pin capacity forever. It reuses the idle window because
 * that is the same order of magnitude as a bootstrap exchange.
 */
export const SESSION_ID_RESERVATION_TTL_SECONDS = SESSION_IDLE_TIMEOUT_SECONDS;

// ---------------------------------------------------------------------------
// Trusted inputs and results
// ---------------------------------------------------------------------------

/**
 * Server-derived session identity.
 *
 * This is NOT parsed from remote JSON. It is produced by ARC from the
 * authenticated mTLS certificate and the enrolled device trust store, and it is
 * the only identity a session can be bound to or verified against.
 */
export interface TrustedSessionIdentity {
  deviceId: string;
  clientId: string;
  clientType: string;
  /** Canonical SPKI SHA-256 pin of the verified mTLS peer certificate. */
  spkiPin: string;
}

/** The request kind a transport can distinguish without parsing MCP. */
export type SessionRequestKind = 'initialize' | 'ordinary';

/** Everything a transport must supply for one admission decision. */
export interface SessionRequestContext {
  kind: SessionRequestKind;
  /**
   * True when the request arrived on a connection that already recognized a
   * server session context (an existing or prior server-issued `Mcp-Session-Id`).
   */
  hasExistingSessionContext: boolean;
  /** Presented `Mcp-Session-Id`, if any. Never trusted as an issuance authority. */
  presentedSessionId?: string | null;
  /** Presented `Authorization` header value, verbatim, if any. */
  authorizationHeader?: string | null;
  /**
   * Server-derived identity, or `undefined` when the mTLS identity resolves to
   * no ACTIVE enrolled device.
   *
   * Absence is representable on purpose: an unknown SPKI or a revoked device is
   * a real admission outcome (RC05-NEG-41), not a precondition the caller must
   * settle before asking. A caller can never substitute a fabricated identity
   * object, because the value must come from `resolveActiveDeviceIdentity`.
   */
  identity?: TrustedSessionIdentity | undefined;
}

/** Trusted, internal result of a successful session authentication. */
export interface TrustedSessionResult {
  sessionId: string;
  deviceId: string;
  clientId: string;
  clientType: string;
  /** Canonical SPKI pin the session is bound to. */
  spkiPin: string;
  /** Wall-clock issue time. Display and audit only; never an authorization input. */
  issuedAt: string;
}

/**
 * Bounded, safe view for future administrative surfaces. No credential material.
 *
 * Every listed session is live: expiry removes a record and revocation removes a
 * record, so there is no retained revoked or expired state to report and no
 * tombstone table.
 */
export interface SessionView {
  sessionId: string;
  deviceId: string;
  clientId: string;
  clientType: string;
  issuedAt: string;
  state: 'ACTIVE';
}

/** One-time issuance result. The raw token exists only in this object. */
export interface SessionIssuance {
  sessionId: string;
  /** Raw 64-lowercase-hex token. Returned exactly once and never retained. */
  token: string;
  issuedAt: string;
}

/**
 * Pure admission decision. The transport maps this to a wire response; this
 * module performs no I/O and produces no response body.
 */
export type SessionAdmissionDecision =
  | { outcome: 'BOOTSTRAP_TOKENLESS'; identity: TrustedSessionIdentity }
  | { outcome: 'AUTHENTICATED'; session: TrustedSessionResult }
  | { outcome: 'UNAUTHENTICATED' }
  | { outcome: 'INVALID_SESSION_TOKEN' };

// ---------------------------------------------------------------------------
// Internal seams
// ---------------------------------------------------------------------------

/**
 * @internal Internal options. These exist for deterministic tests and are NOT
 * reachable from production configuration, the environment, launch options, or
 * any network input.
 */
export interface SessionManagerOptions {
  /** Monotonic clock. Production uses `process.hrtime.bigint()`. */
  getMonotonicTime?: () => bigint;
  /** Wall clock, for the display-only issue timestamp. */
  getWallTime?: () => number;
  /** Cryptographic randomness source. Production uses `crypto.randomBytes`. */
  randomBytes?: (size: number) => Buffer;
}

interface SessionRecord {
  sessionId: string;
  deviceId: string;
  clientId: string;
  clientType: string;
  spkiPin: string;
  /** SHA-256 of the raw session token. The raw token is not retained. */
  tokenDigest: Buffer;
  createdMonotonic: bigint;
  lastAuthMonotonic: bigint;
  issuedAt: string;
  revoked: boolean;
}

/** Fixed 32-byte all-zero digest used on the malformed-token path. */
const DUMMY_TOKEN_DIGEST = Buffer.alloc(32, 0);

function sha256Bytes(value: string): Buffer {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Constant-time comparison of two 32-byte digests.
 *
 * A length difference can only arise from a programming error, never from peer
 * input, because both operands are always 32-byte digests.
 */
function digestsEqual(left: Buffer, right: Buffer): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// Trusted device resolution
// ---------------------------------------------------------------------------

/**
 * Resolves an ACTIVE enrolled device from the trust store by canonical SPKI pin.
 *
 * Pure: reads the trust store, mutates nothing. Returns undefined for an unknown
 * pin, a revoked device, or a malformed pin. The caller must treat undefined as
 * the generic `UNAUTHENTICATED`; `DEVICE_NOT_ENROLLED` is an internal diagnostic
 * and is never a remote-facing result (§25.1).
 */
export function resolveActiveDeviceIdentity(
  trustStore: DeviceTrustStore,
  spkiPin: string,
): TrustedSessionIdentity | undefined {
  if (!isValidSpkiPin(spkiPin)) {
    return undefined;
  }
  const device = trustStore.findDeviceByPin(spkiPin);
  if (device === undefined || device.revoked) {
    return undefined;
  }
  return {
    deviceId: device.deviceId,
    clientId: device.clientId,
    clientType: device.clientType,
    spkiPin,
  };
}

/**
 * Parses an `Authorization` header into a session credential.
 *
 * Accepts exactly one intended form: `Bearer <token>` with a non-empty token and
 * nothing else. Basic credentials, multiple credentials, comma lists, empty
 * tokens, and any extra field are refused. The header value is never included in
 * an error message, and the result is a plain string the caller must treat as a
 * secret.
 */
export function parseBearerCredential(header: unknown): string | null {
  if (typeof header !== 'string') {
    return null;
  }

  // Length FIRST, before any slicing or splitting. `split(' ')` on a
  // peer-controlled value of unbounded length would allocate proportional to the
  // input; this single comparison makes every later step operate on at most
  // MAX_SESSION_AUTHORIZATION_HEADER_BYTES characters.
  if (header.length > MAX_SESSION_AUTHORIZATION_HEADER_BYTES) {
    return null;
  }

  const schemeLength = SESSION_AUTH_SCHEME.length;
  // Need at least `scheme` + one separator + one token character.
  if (header.length < schemeLength + 2) {
    return null;
  }
  // Exactly one space separator at the scheme boundary: positioned indexing
  // rather than a split, so the parse is O(1) in the number of separators.
  if (header.charCodeAt(schemeLength) !== 0x20) {
    return null;
  }
  const scheme = header.slice(0, schemeLength);
  if (scheme.toLowerCase() !== SESSION_AUTH_SCHEME.toLowerCase()) {
    return null;
  }

  const token = header.slice(schemeLength + 1);
  if (token.length === 0) {
    return null;
  }
  // No second credential, no trailing field, no comma list.
  if (token.includes(' ')) {
    return null;
  }
  if (token.includes(',')) {
    return null;
  }
  return token;
}

/**
 * True only for the canonical server session-ID shape.
 *
 * The length check runs BEFORE the regular expression so an arbitrarily large
 * presented identifier is rejected by one integer comparison and never becomes
 * a Map lookup key or a hashing input.
 */
export function isWellFormedSessionId(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length === SESSION_HEX_LENGTH && SESSION_ID_REGEX.test(value)
  );
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/**
 * Volatile gateway session authority.
 *
 * Sessions are process-local and are never persisted (§23): a fresh manager
 * after a restart holds zero sessions and rejects every pre-restart token.
 */
export class SessionManager {
  private readonly getMonotonicTime: () => bigint;
  private readonly getWallTime: () => number;
  private readonly randomBytes: (size: number) => Buffer;
  /**
   * THE authoritative session table, keyed by server-issued `Mcp-Session-Id`.
   *
   * It is the only collection holding session state, so expiry, revocation, and
   * quota accounting cannot drift apart.
   */
  private readonly sessions = new Map<string, SessionRecord>();
  /**
   * Server-issued session IDs that have been generated but not yet activated,
   * mapped to the monotonic time of reservation.
   *
   * This is what makes "server-issued" a STRUCTURAL property rather than a
   * syntactic one: the generator is the only way to obtain a reservable ID, and
   * `issueSession` accepts only a currently reserved one. A caller that invents a
   * well-formed 64-hex string cannot activate it, because it was never reserved.
   *
   * Bounded two ways, so abandoned reservations can never accumulate: the count
   * is capped together with active sessions at the frozen global capacity, and
   * each reservation expires after the reservation window.
   */
  private readonly reservedSessionIds = new Map<string, bigint>();

  constructor(options: SessionManagerOptions = {}) {
    this.getMonotonicTime = options.getMonotonicTime ?? (() => process.hrtime.bigint());
    this.getWallTime = options.getWallTime ?? (() => Date.now());
    this.randomBytes = options.randomBytes ?? ((size: number) => crypto.randomBytes(size));
  }

  /**
   * Builds the cryptographically secure `sessionIdGenerator` Task 8 will hand
   * to the SDK's stateful transport.
   *
   * Each call GENERATES AND RESERVES a fresh 256-bit identifier synchronously
   * before returning it. A reserved ID cannot be produced again, cannot collide
   * with a live session, and is the only kind of value `issueSession` will
   * activate. Collisions are retried a bounded number of times and then fail
   * closed, so a broken randomness source can never overwrite a live session,
   * reuse a reservation, or spin forever.
   */
  public createSessionIdGenerator(): () => string {
    return () => this.reserveSessionId();
  }

  /**
   * Releases an UNUSED session-ID reservation.
   *
   * The primitive Task 8 uses when `initialize` processing aborts before
   * issuance, so an abandoned reservation does not sit until its window expires.
   *
   * - an unknown or malformed ID is a harmless `false`;
   * - an ACTIVE session ID is never touched, because active sessions are not in
   *   the reservation table;
   * - only an unused reservation is removed.
   */
  public releaseSessionIdReservation(sessionId: string): boolean {
    if (!isWellFormedSessionId(sessionId)) {
      return false;
    }
    return this.reservedSessionIds.delete(sessionId);
  }

  /**
   * Issues a gateway session bound to a RESERVED server-issued session ID.
   *
   * The caller (Task 8, after the SDK has completed `initialize`) supplies the ID
   * returned by the generator plus the trusted device identity. The raw token is
   * minted here, returned exactly once, and otherwise discarded: only its
   * SHA-256 digest is retained.
   *
   * Issuance CONSUMES the reservation exactly once — including when it fails for
   * a quota reason — so a failed initialize must obtain a new server session ID
   * rather than retrying with a reservation that has already been spent.
   */
  public issueSession(input: {
    sessionId: string;
    identity: TrustedSessionIdentity;
  }): SessionIssuance {
    const { sessionId, identity } = input;

    if (!isWellFormedSessionId(sessionId)) {
      throw ArcError.invalidRequestSchema(
        'Session identifier must be 64 lowercase hexadecimal characters issued by the server.',
      );
    }
    if (typeof identity !== 'object' || identity === null) {
      throw ArcError.invalidRequestSchema(
        'Session identity must be a trusted server-derived object.',
      );
    }

    const deviceId = identity.deviceId;
    const spkiPin = identity.spkiPin;
    if (!isValidDeviceId(deviceId)) {
      throw ArcError.invalidRequestSchema('Session identity carries an invalid device identifier.');
    }
    if (!isValidSpkiPin(spkiPin)) {
      throw ArcError.invalidRequestSchema('Session identity carries an invalid SPKI pin.');
    }
    const clientId = validateClientId(identity.clientId);
    const clientType = validateClientType(identity.clientType);

    // Deterministic accounting before quota evaluation: an expired session must
    // never consume an active slot.
    this.purgeExpired();

    // §26 C-4: a duplicate session ID is refused, never overwritten. This is
    // checked before any quota work so an attacker cannot trade a live session
    // for a quota error.
    if (this.sessions.has(sessionId)) {
      throw ArcError.conflictPreconditionFailed(
        'Session identifier is already active and can never be reassigned.',
      );
    }

    // Structural server-issuance check: only a currently reserved generator
    // output is activatable. A syntactically perfect caller-chosen ID fails here.
    if (!this.reservedSessionIds.has(sessionId)) {
      throw ArcError.invalidRequestSchema(
        'Session identifier was not issued and reserved by this server.',
      );
    }

    // Consume the reservation BEFORE quota evaluation, so every later failure
    // leaves no stale reservation behind. One server ID is good for exactly one
    // issuance attempt.
    this.reservedSessionIds.delete(sessionId);

    this.assertQuotaAvailable(deviceId, clientId);

    const token = this.generateToken();
    const now = this.getMonotonicTime();
    const record: SessionRecord = {
      sessionId,
      deviceId,
      clientId,
      clientType,
      spkiPin,
      tokenDigest: sha256Bytes(token),
      createdMonotonic: now,
      lastAuthMonotonic: now,
      issuedAt: new Date(this.getWallTime()).toISOString(),
      revoked: false,
    };
    this.sessions.set(sessionId, record);

    // The raw token leaves this method exactly once. It is not stored, not
    // derivable from the record, and not reachable from any getter or view.
    return { sessionId, token, issuedAt: record.issuedAt };
  }

  /**
   * Pure wire-admission decision for one `/mcp` request.
   *
   * Implements §5.3 C/H exactly:
   * - a tokenless initial `initialize` from a device with no recognized session
   *   context is eligible for session bootstrap;
   * - every tokenless ordinary request is generic `UNAUTHENTICATED`;
   * - every request carrying a recognized or presented session context requires
   *   BOTH a valid `Mcp-Session-Id` and a valid bearer session credential, and
   *   anything short of that is generic `INVALID_SESSION_TOKEN`.
   *
   * No session is minted here. Issuance happens only through `issueSession`,
   * after the transport has actually processed `initialize`.
   */
  public admitRequest(context: SessionRequestContext): SessionAdmissionDecision {
    const presentedId = context.presentedSessionId ?? null;
    const hasPresentedId = presentedId !== null;
    const rawCredential = parseBearerCredential(context.authorizationHeader ?? null);

    // Shape check BEFORE any Map lookup or hashing. Only a canonical 64-lowercase-
    // hex identifier can name a server session, so a huge or malformed value is
    // rejected by one integer comparison and never becomes a lookup key.
    const wellFormedId = isWellFormedSessionId(presentedId) ? presentedId : null;
    // Only a well-formed ID the server ACTUALLY has live counts as RECOGNIZED. A
    // client-selected, unknown, expired, or malformed value is never adopted and
    // never becomes an issuance authority (RC05-NEG-40, §26 C-4).
    const recognizedId =
      wellFormedId !== null && this.sessions.has(wellFormedId) ? wellFormedId : null;

    // Session-context domain (§5.3 H).
    //
    // An ORDINARY request that presents ANY `Mcp-Session-Id` — known, unknown,
    // expired, malformed, or client-chosen — is attempting session-context
    // authentication, so it owes the full dual-header invariant and every failure
    // is uniformly INVALID_SESSION_TOKEN. Presence of the header is classified by
    // the header itself, never by the transport's own context flag.
    //
    // `initialize` is the deliberate exception only in the TOKENLESS, no-context
    // case below: a real server session ID, or a recognized context, still forces
    // the dual-header path, so calling a request `initialize` grants nothing.
    const requiresSessionContext =
      context.hasExistingSessionContext ||
      recognizedId !== null ||
      (context.kind === 'ordinary' && hasPresentedId);

    if (requiresSessionContext) {
      if (recognizedId === null || rawCredential === null) {
        return { outcome: 'INVALID_SESSION_TOKEN' };
      }
      const session = this.authenticate({
        sessionId: recognizedId,
        token: rawCredential,
        identity: context.identity,
      });
      if (session === undefined) {
        return { outcome: 'INVALID_SESSION_TOKEN' };
      }
      return { outcome: 'AUTHENTICATED', session };
    }

    // Pre-session domain. A credential with no server session to bind to has
    // nothing to authenticate against.
    if (rawCredential !== null) {
      return { outcome: 'INVALID_SESSION_TOKEN' };
    }

    if (context.kind === 'initialize') {
      // RC05-NEG-41: bootstrap requires an ACTIVE resolved device identity. An
      // identity that resolved to nothing — unknown SPKI, or a revoked device —
      // can never bootstrap, and no reservation, session, or token is minted.
      if (context.identity === undefined || context.identity === null) {
        return { outcome: 'UNAUTHENTICATED' };
      }
      // Eligible for bootstrap. A client-supplied ID, if any, is simply NOT USED:
      // the transport replaces it with a freshly reserved server ID and the
      // session is minted only after `initialize` is actually processed.
      return { outcome: 'BOOTSTRAP_TOKENLESS', identity: context.identity };
    }

    // RC05-NEG-39: a tokenless ordinary request never bootstraps a session.
    return { outcome: 'UNAUTHENTICATED' };
  }

  /**
   * Verifies a session ID plus raw token against a trusted identity.
   *
   * Returns undefined for every failure. A failure never mutates anything: no
   * last-auth update, no idle refresh, no revocation change, no quota release.
   */
  public authenticate(input: {
    sessionId: string;
    token: unknown;
    identity: TrustedSessionIdentity | undefined;
  }): TrustedSessionResult | undefined {
    const { sessionId, identity } = input;

    // No active resolved identity means there is nothing the session could be
    // bound to, so no presented credential can authenticate. This is the
    // RC05-NEG-41 post-session outcome and it is deliberately indistinguishable
    // from a wrong token.
    if (identity === undefined || identity === null) {
      return undefined;
    }

    if (!isWellFormedSessionId(sessionId)) {
      // An unknown or malformed ID is generic: the caller learns nothing about
      // whether the session ever existed.
      return undefined;
    }

    const record = this.sessions.get(sessionId);
    if (record === undefined || record.revoked) {
      return undefined;
    }

    // Bound the presented credential BEFORE hashing it, so an oversized value
    // costs one length check rather than a large digest.
    const submitted = typeof input.token === 'string' ? input.token : '';
    if (Buffer.byteLength(submitted, 'utf8') > MAX_SESSION_TOKEN_INPUT_BYTES) {
      return undefined;
    }

    // Constant-time path on every input: a malformed token is still hashed and
    // still compared against a fixed dummy digest, so the malformed branch costs
    // the same and reveals nothing by timing.
    const wellFormed = SESSION_TOKEN_REGEX.test(submitted);
    const candidateDigest = sha256Bytes(submitted);
    const expectedDigest = wellFormed ? record.tokenDigest : DUMMY_TOKEN_DIGEST;
    const digestMatches = digestsEqual(candidateDigest, expectedDigest);
    const tokenMatches = wellFormed && digestMatches;
    if (!tokenMatches) {
      return undefined;
    }

    // Expiry is evaluated AFTER a correct credential, so an expired session is
    // indistinguishable from a wrong token, and so a failed credential can never
    // be used to probe lifetime.
    if (this.isExpired(record)) {
      this.sessions.delete(record.sessionId);
      return undefined;
    }

    // §5.4 binding: the session is unusable from any other identity. The token
    // is not portable across devices, clients, or TLS identities.
    if (
      record.deviceId !== identity.deviceId ||
      record.clientId !== identity.clientId ||
      record.clientType !== identity.clientType ||
      record.spkiPin !== identity.spkiPin
    ) {
      return undefined;
    }

    // Only a fully successful authentication refreshes the idle deadline.
    record.lastAuthMonotonic = this.getMonotonicTime();

    return {
      sessionId: record.sessionId,
      deviceId: record.deviceId,
      clientId: record.clientId,
      clientType: record.clientType,
      spkiPin: record.spkiPin,
      issuedAt: record.issuedAt,
    };
  }

  /**
   * Revokes one session immediately and irreversibly.
   *
   * The record is removed, which releases its quota slot; a later request
   * presenting the same ID is the generic `INVALID_SESSION_TOKEN` because the ID
   * is simply no longer recognized. Returns false when nothing was revoked.
   */
  public revokeSession(sessionId: string): boolean {
    if (typeof sessionId !== 'string') {
      return false;
    }
    const record = this.sessions.get(sessionId);
    if (record === undefined) {
      return false;
    }
    if (this.isExpired(record)) {
      // An already-expired session was not revoked by this call. The dead
      // record is still dropped, and the answer is truthful.
      this.sessions.delete(sessionId);
      return false;
    }
    return this.sessions.delete(sessionId);
  }

  /**
   * Revokes every session bound to a device.
   *
   * Task 9 composes this with device revocation; Task 5 owns only the primitive.
   * Only live sessions are counted: already-expired records are simply dropped.
   */
  public revokeSessionsForDevice(deviceId: string): number {
    if (typeof deviceId !== 'string' || deviceId.length === 0) {
      return 0;
    }
    this.purgeExpired();
    let revoked = 0;
    for (const [sessionId, record] of this.sessions) {
      if (record.deviceId === deviceId) {
        this.sessions.delete(sessionId);
        revoked += 1;
      }
    }
    return revoked;
  }

  /**
   * Closes a session, the primitive behind a future `DELETE /mcp` (§5.4).
   *
   * Identical in effect to revocation for the credential, but named for the wire
   * semantic the transport will implement. Closing an unknown, expired, or
   * already-revoked session is a safe no-op that touches nothing else.
   */
  public closeSession(sessionId: string): boolean {
    return this.revokeSession(sessionId);
  }

  /**
   * Removes every session AND every unused reservation.
   *
   * Both collections are volatile state, so a shutdown-style clear must leave
   * the manager indistinguishable from a fresh one.
   */
  public clear(): void {
    this.sessions.clear();
    this.reservedSessionIds.clear();
  }

  /** Outstanding unused session-ID reservations. */
  public getReservedSessionIdCount(): number {
    this.pruneReservations();
    return this.reservedSessionIds.size;
  }

  public getActiveSessionCount(): number {
    this.purgeExpired();
    return this.sessions.size;
  }

  public getActiveSessionCountForDevice(deviceId: string): number {
    this.purgeExpired();
    let count = 0;
    for (const record of this.sessions.values()) {
      if (record.deviceId === deviceId) {
        count += 1;
      }
    }
    return count;
  }

  public getActiveSessionCountForClient(clientId: string): number {
    this.purgeExpired();
    let count = 0;
    for (const record of this.sessions.values()) {
      if (record.clientId === clientId) {
        count += 1;
      }
    }
    return count;
  }

  /** True when the session currently exists and is not expired or revoked. */
  public hasSession(sessionId: string): boolean {
    if (typeof sessionId !== 'string') {
      return false;
    }
    const record = this.sessions.get(sessionId);
    if (record === undefined || record.revoked) {
      return false;
    }
    if (this.isExpired(record)) {
      this.sessions.delete(record.sessionId);
      return false;
    }
    return true;
  }

  /**
   * Bounded, safe session views. Never expose the token or its digest.
   *
   * Retained for the future administrative surface (Task 9); remote response
   * models are a separate concern.
   */
  public listSessions(): readonly SessionView[] {
    this.purgeExpired();
    return Object.freeze(
      Array.from(this.sessions.values()).map((record) => ({
        sessionId: record.sessionId,
        deviceId: record.deviceId,
        clientId: record.clientId,
        clientType: record.clientType,
        issuedAt: record.issuedAt,
        state: 'ACTIVE' as const,
      })),
    );
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /**
   * Absolute or idle expiry on the MONOTONIC clock.
   *
   * Both boundaries are inclusive. Wall-clock movement cannot extend or shorten
   * a session: the wall clock is recorded for display only and never participates
   * in this decision.
   */
  private isExpired(record: SessionRecord, now = this.getMonotonicTime()): boolean {
    const absoluteDeadline =
      record.createdMonotonic + BigInt(SESSION_ABSOLUTE_TTL_SECONDS) * 1_000_000_000n;
    if (now >= absoluteDeadline) {
      return true;
    }
    const idleDeadline =
      record.lastAuthMonotonic + BigInt(SESSION_IDLE_TIMEOUT_SECONDS) * 1_000_000_000n;
    return now >= idleDeadline;
  }

  /** Deterministically drops every expired session so quotas count only live ones. */
  private purgeExpired(): void {
    const now = this.getMonotonicTime();
    for (const [sessionId, record] of this.sessions) {
      if (this.isExpired(record, now)) {
        this.sessions.delete(sessionId);
      }
    }
  }

  /**
   * Generates AND synchronously reserves a fresh server session ID.
   *
   * Capacity is charged against active sessions PLUS outstanding reservations,
   * so a caller cannot convert ID generation into an unbounded reservation
   * table: the frozen global session capacity bounds both collections together.
   */
  private reserveSessionId(): string {
    this.pruneReservations();
    if (this.sessions.size + this.reservedSessionIds.size >= MAX_ACTIVE_SESSIONS_GLOBAL) {
      throw ArcError.resourceExhausted(
        `Cannot reserve a session identifier: at most ${MAX_ACTIVE_SESSIONS_GLOBAL} sessions and reservations may be outstanding at once.`,
      );
    }
    for (let attempt = 0; attempt < MAX_SESSION_ID_GENERATION_ATTEMPTS; attempt += 1) {
      const candidate = this.randomBytes(32).toString('hex');
      if (!isWellFormedSessionId(candidate)) {
        continue;
      }
      // Never reuse a live session ID and never hand out a still-reserved one.
      if (this.sessions.has(candidate) || this.reservedSessionIds.has(candidate)) {
        continue;
      }
      this.reservedSessionIds.set(candidate, this.getMonotonicTime());
      return candidate;
    }
    // Exhaustion fails closed. No session is created, no reservation is made,
    // no ID is reused, and no live session is disturbed.
    throw ArcError.resourceExhausted(
      'Could not generate a unique session identifier within the bounded attempt limit.',
    );
  }

  /** Drops reservations that were never consumed within their window. */
  private pruneReservations(now = this.getMonotonicTime()): void {
    if (this.reservedSessionIds.size === 0) {
      return;
    }
    const deadline = now - BigInt(SESSION_ID_RESERVATION_TTL_SECONDS) * 1_000_000_000n;
    for (const [sessionId, reservedAt] of this.reservedSessionIds) {
      if (reservedAt <= deadline) {
        this.reservedSessionIds.delete(sessionId);
      }
    }
  }

  private assertQuotaAvailable(deviceId: string, clientId: string): void {
    if (this.sessions.size >= MAX_ACTIVE_SESSIONS_GLOBAL) {
      throw ArcError.resourceExhausted(
        `Active session limit reached: at most ${MAX_ACTIVE_SESSIONS_GLOBAL} sessions may be active at once.`,
      );
    }
    let deviceCount = 0;
    let clientCount = 0;
    for (const record of this.sessions.values()) {
      if (record.deviceId === deviceId) {
        deviceCount += 1;
      }
      if (record.clientId === clientId) {
        clientCount += 1;
      }
    }
    if (deviceCount >= MAX_ACTIVE_SESSIONS_PER_DEVICE) {
      throw ArcError.resourceExhausted(
        `Active session limit reached for this device: at most ${MAX_ACTIVE_SESSIONS_PER_DEVICE} sessions may be active at once.`,
      );
    }
    if (clientCount >= MAX_ACTIVE_SESSIONS_PER_CLIENT) {
      throw ArcError.resourceExhausted(
        `Active session limit reached for this client: at most ${MAX_ACTIVE_SESSIONS_PER_CLIENT} sessions may be active at once.`,
      );
    }
  }

  /**
   * Mints a fresh 256-bit session token.
   *
   * Drawn independently of the session ID and of every other identifier: no
   * token is derived from a session ID, a device ID, a client ID, or an SPKI pin.
   */
  private generateToken(): string {
    return this.randomBytes(32).toString('hex');
  }
}
