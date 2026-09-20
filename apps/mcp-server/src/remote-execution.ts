/**
 * CesSpace ARC — RC-05 Task 6 Remote Actor Pipeline Bridge
 *
 * Application composition only. This module turns an AUTHENTICATED remote
 * request into the exact trusted actor and hands it to the ONE existing RC-04
 * execution pipeline. It parses no HTTP, no raw JSON-RPC bytes, and connects no
 * MCP SDK transport: Task 8 owns the transport, and this module is the seam it
 * will call.
 *
 * Authoritative contract: §3, §13, §14, §25, §27, §28 X-7, and the Task-6 row of
 * §38 (controls RC05-NEG-48..52 and RC05-NEG-62..68).
 *
 * Architecture:
 *
 *   trusted SPKI (Task 3 TLS)
 *     → CURRENT DeviceTrustStore resolution   (every request, never cached)
 *     → Task-5 SessionManager admission       (dual-header, monotonic TTLs)
 *     → Layer C authenticated rate limit      (server-derived device/session)
 *     → per-session request concurrency       (never queues; §26 C-3)
 *     → exact remote actor derivation         (clientId, clientType, deviceId,
 *                                              sessionId = Mcp-Session-Id)
 *     → remote actor-field spoofing guard     (bounded, cycle-safe)
 *     → EXISTING shared RC-04 pipeline        (schema → workspace → Layer 1 →
 *                                              Layer 2 → mutation floor →
 *                                              approval → subsystem → audit)
 *
 * Ordering is a security property. Authentication is an ADMISSION PREREQUISITE,
 * not a policy decision: nothing below the guard runs unless Task-5 admission
 * returned AUTHENTICATED, and Layer C cannot run before it either — its key is
 * derived from the authenticated session result, so there is nothing to key on
 * until admission has succeeded.
 */

import { ArcError } from '@cesspace-arc/protocol';
import type { SessionManager, TrustedSessionIdentity } from '@cesspace-arc/auth';
import {
  BoundedRequestLimiter,
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
} from './remote-resource-limits.js';

/**
 * A fully populated actor: every authorization-relevant field is present.
 *
 * Both transports construct one of these — stdio from its local defaults, remote
 * from an authenticated Task-5 session — and the shared pipeline accepts nothing
 * less. There is no partial form, so no caller can leave a field to be filled in
 * later by policy, approval, or audit code.
 */
export interface CompleteActor {
  clientId: string;
  clientType: string;
  deviceId: string;
  sessionId: string;
  authenticated: boolean;
}

/** The complete, server-derived actor for an authenticated remote request. */
export interface RemoteActor extends CompleteActor {
  /** Exactly the server-issued `Mcp-Session-Id` (§5.4). No second identifier. */
  sessionId: string;
  /** Always true by construction: admission already succeeded. */
  authenticated: true;
}

/** Result shape of one tool invocation, identical to the shared pipeline's. */
export interface RemoteToolCallResult {
  isError?: boolean;
  content: Array<{ type: 'text'; text: string }>;
}

/**
 * The shared RC-04 pipeline, reached only with a COMPLETE trusted actor.
 *
 * The remote bridge cannot express a partial actor, a default, or a merge: the
 * actor it passes is fully derived, so no later transport can inject an actor
 * field through this seam.
 */
export interface AuthenticatedToolSink {
  executeAuthenticatedToolCall(
    actor: CompleteActor,
    toolName: string,
    parameters: Record<string, unknown>,
  ): Promise<RemoteToolCallResult>;
}

/** Composition inputs for one bridge. */
export interface RemoteExecutionDeps {
  /** The ONE process-local session authority (§2). Never a second instance. */
  sessionManager: SessionManager;
  /**
   * Resolves the CURRENT active device for a trusted SPKI pin.
   *
   * Called on EVERY remote request against the current authoritative trust
   * store, and deliberately never cached: a resolver-minted identity stays a
   * valid Task-5 capability object after the device is revoked, so retaining one
   * would let a revoked device keep authenticating.
   */
  resolveActiveDeviceIdentity(spkiPin: string): TrustedSessionIdentity | undefined;
  /** The shared pipeline. */
  sink: AuthenticatedToolSink;
  /**
   * The ONE process-local Layer C limiter and per-session concurrency state.
   *
   * Production composition (`ArcMcpServer.start()`) supplies a single
   * process-wide instance and resets it on shutdown, so rate and concurrency
   * state is volatile and never persisted. When omitted, the bridge creates its
   * own with the frozen production bounds — never a weaker or configurable set.
   */
  authenticatedLimiter?: BoundedRequestLimiter;
}

/** One remote tool call, as the future transport will supply it. */
export interface RemoteToolCallInput {
  /**
   * Canonical SPKI pin derived from the verified mTLS peer certificate by
   * Task-3 admission. INTERNAL trusted transport input: it is never read from
   * JSON-RPC parameters, headers, or a body.
   */
  trustedSpkiPin: string;
  /** Presented `Mcp-Session-Id`, verbatim. */
  presentedSessionId?: string | null;
  /** Presented `Authorization` header value, verbatim. */
  authorizationHeader?: string | null;
  /**
   * True when the transport already recognized a server session context for
   * this request. The session context is ALSO classified from the presented
   * header itself, so this can only widen the post-session domain.
   */
  hasExistingSessionContext?: boolean;
  toolName: string;
  parameters: Record<string, unknown>;
}

/**
 * Reserved parameter names that may never carry trusted actor/transport context.
 *
 * These are exactly the fields §13 derives server-side plus the transport
 * identity fields a caller might try to assert. They are refused as a SCHEMA
 * error rather than stripped or ignored, so a client cannot believe it supplied
 * identity and cannot use a rejected field as a probe.
 */
export const REMOTE_ACTOR_FIELD_NAMES: readonly string[] = Object.freeze([
  'clientId',
  'clientType',
  'deviceId',
  'sessionId',
  'authenticated',
  'spkiPin',
  'actor',
  'operatorId',
]);

/**
 * Bounds for the actor-field traversal.
 *
 * The traversal is applied to already-parsed JSON supplied by a transport, so
 * these bounds exist to keep the scan itself cheap and non-recursive rather than
 * to limit request size (Task 7 owns HTTP/body bounds).
 */
const MAX_TRAVERSAL_NODES = 8192;
const MAX_TRAVERSAL_DEPTH = 32;

/**
 * Finds a reserved actor/transport field anywhere inside remote tool parameters.
 *
 * The scan is ITERATIVE (no recursion, so a deeply nested payload cannot exhaust
 * the stack), CYCLE-SAFE (a direct JavaScript object graph with a cycle is
 * detected and refused rather than looping), and BOUNDED (node and depth caps
 * fail closed). Only property KEYS are inspected; string CONTENTS are never
 * scanned, so this is not a content filter.
 *
 * Returns the dotted path of the first offending key, or null when the
 * parameters are acceptable.
 */
export function findActorFieldInjection(parameters: unknown): string | null {
  const reserved = new Set(REMOTE_ACTOR_FIELD_NAMES);
  const seen = new WeakSet<object>();
  const stack: Array<{ value: unknown; path: string; depth: number }> = [
    { value: parameters, path: '', depth: 0 },
  ];
  let visited = 0;

  while (stack.length > 0) {
    const current = stack.pop() as { value: unknown; path: string; depth: number };
    visited += 1;
    if (visited > MAX_TRAVERSAL_NODES) {
      // Fail closed: an input too large to prove clean is not proven clean.
      return '<traversal-budget>';
    }
    if (current.depth > MAX_TRAVERSAL_DEPTH) {
      return '<traversal-depth>';
    }

    const value = current.value;
    if (typeof value !== 'object' || value === null) {
      continue;
    }
    if (seen.has(value)) {
      // A cycle in a direct JavaScript object graph cannot come from parsed
      // JSON, so the input is not JSON and is refused.
      return `${current.path}<cycle>`;
    }
    seen.add(value);

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        stack.push({ value: value[i], path: `${current.path}[${i}]`, depth: current.depth + 1 });
      }
      continue;
    }

    for (const key of Object.keys(value as Record<string, unknown>)) {
      const childPath = current.path === '' ? key : `${current.path}.${key}`;
      if (reserved.has(key)) {
        return childPath;
      }
      stack.push({
        value: (value as Record<string, unknown>)[key],
        path: childPath,
        depth: current.depth + 1,
      });
    }
  }

  return null;
}

/**
 * Builds the exact remote actor from an AUTHENTICATED Task-5 session result.
 *
 * Every field comes from the trusted result. There is no fallback, no default,
 * and no merge with request data, and the session identifier is the server-issued
 * `Mcp-Session-Id` itself — never `stdio-session-01`, never a second generated
 * identifier, never a caller value.
 */
export function deriveRemoteActor(session: {
  sessionId: string;
  deviceId: string;
  clientId: string;
  clientType: string;
}): RemoteActor {
  return {
    clientId: session.clientId,
    clientType: session.clientType,
    deviceId: session.deviceId,
    sessionId: session.sessionId,
    authenticated: true,
  };
}

/** The single client-facing pre-session failure (§25.1 rule 1). */
export function remoteAuthenticationFailure(): ArcError {
  return ArcError.unauthenticated();
}

/** The single client-facing post-session failure (§25.1 rule 3). */
export function remoteSessionFailure(): ArcError {
  return ArcError.invalidSessionToken();
}

/**
 * Builds a Layer C limiter with the frozen production bounds (§21.1 Layer C).
 *
 * 300 requests/minute with a burst of 60, at most 1024 retained session keys,
 * and at most {@link MAX_OUTSTANDING_REQUESTS_PER_SESSION} outstanding requests
 * per key. The `getMonotonicTimeMs` seam exists so a test can drive the clock;
 * every numeric bound is a module constant and is not parameterized.
 */
export function createAuthenticatedRequestLimiter(
  options: {
    getMonotonicTimeMs?: () => number;
  } = {},
): BoundedRequestLimiter {
  return new BoundedRequestLimiter({
    requestsPerMinute: LAYER_C_REQUESTS_PER_MINUTE,
    burst: LAYER_C_BURST,
    maxKeys: MAX_LAYER_C_KEYS,
    maxOutstandingPerKey: MAX_OUTSTANDING_REQUESTS_PER_SESSION,
    ...(options.getMonotonicTimeMs === undefined
      ? {}
      : { getMonotonicTimeMs: options.getMonotonicTimeMs }),
  });
}

/**
 * THE Layer C limiter key.
 *
 * Built ONLY from the server-derived `deviceId` and `sessionId` of a successful
 * Task-5 admission. Neither is client-supplied, and the raw session token is
 * never used as a key — the token is not even retained in a usable form by the
 * session manager, and keying on a credential would put it in limiter memory.
 */
export function sessionRateLimitKey(session: { deviceId: string; sessionId: string }): string {
  return `${session.deviceId}:${session.sessionId}`;
}

/**
 * The single client-facing rate/concurrency refusal (§21.1 Layer C, §26 C-3).
 *
 * One bounded error for every resource bound this layer enforces, so a client
 * cannot use the response to tell a rate refusal from a concurrency refusal, and
 * gains no signal about remaining budget. Nothing about the key, the bucket, or
 * the session is included.
 */
export function remoteRateLimitFailure(): ArcError {
  return new ArcError({
    code: 'RATE_LIMIT_EXCEEDED',
    category: 'RESOURCE',
    message: 'Request rate or concurrency limit exceeded for this session.',
    retryable: true,
  });
}

/**
 * The composition-ready remote execution entry point.
 *
 * Task 8 will call `executeRemoteToolCall` from the SDK transport once a request
 * has been fully parsed and its peer identity derived. Nothing here performs
 * network I/O, and nothing here is reachable from the network in Task 6.
 */
export class RemoteExecutionBridge {
  private readonly authenticatedLimiter: BoundedRequestLimiter;

  constructor(private readonly deps: RemoteExecutionDeps) {
    this.authenticatedLimiter = deps.authenticatedLimiter ?? createAuthenticatedRequestLimiter();
  }

  /**
   * Authenticates one remote request and, only on success, runs it through the
   * EXISTING shared RC-04 pipeline.
   *
   * Throws the canonical anti-oracle ArcError for every admission failure; the
   * transport turns that into the wire response. Nothing below this method runs
   * unless admission returned AUTHENTICATED.
   */
  public async executeRemoteToolCall(input: RemoteToolCallInput): Promise<RemoteToolCallResult> {
    // 1. Resolve the CURRENT device identity from the authoritative trust store.
    //    Never cached across requests: revocation has to take effect on the very
    //    next call, even while an old session record still exists.
    const identity = this.deps.resolveActiveDeviceIdentity(input.trustedSpkiPin);
    const sessionIdPresented = input.presentedSessionId ?? null;
    const credentialPresented = input.authorizationHeader ?? null;

    // 2. Task-5 admission. An ordinary request with no session context and no
    //    credential is UNAUTHENTICATED; anything carrying a session ID or a
    //    credential is judged in the post-session domain.
    const decision = this.deps.sessionManager.admitRequest({
      kind: 'ordinary',
      hasExistingSessionContext:
        input.hasExistingSessionContext === true ||
        sessionIdPresented !== null ||
        credentialPresented !== null,
      presentedSessionId: sessionIdPresented,
      authorizationHeader: credentialPresented,
      identity,
    });

    // 3. Stop on any admission failure, before any rate accounting, schema,
    //    policy, or approval. Layer C is unreachable without authentication.
    if (decision.outcome !== 'AUTHENTICATED') {
      throw this.failureFor(decision.outcome, sessionIdPresented, credentialPresented);
    }

    const session = decision.session;

    // 4. Layer C: the authenticated session/device rate budget, keyed on the
    //    server-derived device and session identifiers only (§21.1 Layer C).
    const budget = this.authenticatedLimiter.consume(sessionRateLimitKey(session));
    if (!budget.consumed) {
      // Rate refusals and saturation share ONE client-facing error, so the
      // refusal is not a probe for whether a key exists or how full a bucket is.
      throw remoteRateLimitFailure();
    }

    // 5. Per-session concurrency (§26 C-3). A request beyond the bound is
    //    refused immediately and is NEVER queued, so no unbounded backlog can
    //    accumulate behind a session.
    const slot = this.authenticatedLimiter.tryHold(budget.bucket);
    if (!slot.held) {
      throw remoteRateLimitFailure();
    }

    // The slot is released on EVERY exit path below — success, actor-field
    // refusal, policy denial, approval requirement, approval rejection,
    // subsystem error, and any thrown internal error — so a failed request can
    // never leak a concurrency slot.
    try {
      // 6. Derive the exact actor from the trusted session result.
      const actor = deriveRemoteActor(session);

      // 7. Refuse any attempt to supply actor or transport identity in
      //    parameters. Checked before the pipeline so no policy evaluation,
      //    approval lookup, or subsystem call can observe a spoofing attempt.
      const injection = findActorFieldInjection(input.parameters);
      if (injection !== null) {
        throw ArcError.invalidRequestSchema(
          `Invalid parameters for tool '${input.toolName}': reserved actor or transport identity field is not permitted in remote request parameters.`,
        );
      }

      // 8. The ONE shared RC-04 pipeline, with a COMPLETE trusted actor.
      return await this.deps.sink.executeAuthenticatedToolCall(
        actor,
        input.toolName,
        input.parameters,
      );
    } finally {
      slot.release();
    }
  }

  /**
   * Maps an admission outcome to the canonical anti-oracle error.
   *
   * The distinction is purely pre- versus post-session, and it is decided by
   * what the request PRESENTED — not by which internal check failed. No device,
   * revocation, expiry, digest, or binding detail is ever disclosed.
   */
  private failureFor(
    outcome: 'UNAUTHENTICATED' | 'INVALID_SESSION_TOKEN' | 'BOOTSTRAP_TOKENLESS',
    presentedSessionId: string | null,
    credentialPresented: string | null,
  ): ArcError {
    if (outcome === 'INVALID_SESSION_TOKEN') {
      return remoteSessionFailure();
    }
    // A session ID or credential was presented but admission still says
    // pre-session only when nothing session-shaped was supplied at all. In every
    // other case the request belongs to the post-session domain.
    if (presentedSessionId !== null || credentialPresented !== null) {
      return remoteSessionFailure();
    }
    if (outcome === 'BOOTSTRAP_TOKENLESS') {
      // An ordinary tool call never bootstraps: this can only mean a transport
      // mislabelled the request, and the safe answer is the pre-session failure.
      return remoteAuthenticationFailure();
    }
    return remoteAuthenticationFailure();
  }
}
