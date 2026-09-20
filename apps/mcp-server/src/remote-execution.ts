/**
 * CesSpace ARC — RC-05 Task 6/7/8 Remote Admission and Execution Seam
 *
 * Application composition only. This module owns TWO boundaries, deliberately
 * separated so that admission happens exactly ONCE per authenticated remote MCP
 * request and tool execution never re-authenticates or re-charges:
 *
 *   1. `RemoteRequestAdmission` — authenticated remote-request ADMISSION
 *      trusted SPKI (Task 3 TLS)
 *        → CURRENT DeviceTrustStore resolution   (every request, never cached)
 *        → Task-5 SessionManager admission       (dual-header, monotonic TTLs)
 *        → Layer C authenticated rate limit      (server-derived device/session)
 *        → per-session request concurrency       (never queues; §26 C-3)
 *        → one server-created, unforgeable admission lease
 *
 *   2. `RemoteExecutionBridge` — admitted TOOL EXECUTION
 *      admission lease
 *        → exact remote actor derivation         (clientId, clientType, deviceId,
 *                                                 sessionId = Mcp-Session-Id)
 *        → remote actor-field spoofing guard     (bounded, cycle-safe)
 *        → EXISTING shared RC-04 pipeline        (schema → workspace → Layer 1 →
 *                                                 Layer 2 → mutation floor →
 *                                                 approval → subsystem → audit)
 *
 * The split exists because Layer C (§21.1) and the §26 C-3 concurrency bound are
 * per-REQUEST controls, not per-tool-call controls. Task 8 hands the transport
 * EVERY authenticated MCP request — `initialize` aside, that is POST, GET SSE,
 * DELETE, `tools/list`, `ping`, and `tools/call` alike — so admission belongs to
 * the transport boundary, and execution takes the admission it was given. A
 * `tools/call` therefore spends exactly ONE rate token and ONE outstanding slot:
 * the surface admits, and the bridge executes what was admitted.
 *
 * The lease is a runtime CAPABILITY, not a shape. Only this module can mint one,
 * and it is registered in a module-private `WeakSet`, so a structurally perfect
 * object built anywhere else is refused exactly like an absent one.
 *
 * Authoritative contract: §3, §5.4, §13, §14, §21.1 Layer C, §25, §26 C-3, §27,
 * §28 X-7, and the Task-6/7/8 rows of §38 (controls RC05-NEG-48..52, 56, 62..68).
 *
 * Ordering is a security property. Authentication is an ADMISSION PREREQUISITE,
 * not a policy decision: nothing below the guard runs unless Task-5 admission
 * returned AUTHENTICATED, and Layer C cannot run before it either — its key is
 * derived from the authenticated session result, so there is nothing to key on
 * until admission has succeeded.
 */

import { ArcError } from '@cesspace-arc/protocol';
import type {
  SessionManager,
  TrustedSessionIdentity,
  TrustedSessionResult,
} from '@cesspace-arc/auth';
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

/**
 * The server-created admission lease for ONE authenticated remote MCP request.
 *
 * It is the ONLY thing that proves a request was authenticated, rate-authorized,
 * and granted a concurrency slot, and it carries the trusted Task-5 session
 * result that the actor is derived from — never a request value.
 *
 * The lease is bound to the request it was issued for, so replaying one onto a
 * different request (or a different peer) is refused rather than silently
 * granting admission. `release` is idempotent: the transport arms it on every
 * terminal path of the HTTP exchange, and releasing twice frees one slot.
 */
export interface AdmittedRemoteRequest {
  /** The trusted Task-5 session result. The actor is derived from this alone. */
  readonly session: TrustedSessionResult;
  /** The gateway-derived SPKI pin THIS admission was granted on. */
  readonly spkiPin: string;
  /** Releases the Layer C outstanding slot. Idempotent; safe on every path. */
  release(): void;
}

/**
 * Issued leases.
 *
 * A `WeakSet` is used deliberately: it holds no strong reference, needs no
 * cleanup, is not enumerable, and is not reachable from outside this module, so
 * admission cannot be claimed by shape, by a cast, or by copying the fields of a
 * real lease into a new object.
 */
const ADMITTED_REQUESTS = new WeakSet<object>();

/**
 * Mints the ONE admission lease for a request that has just been admitted.
 *
 * @internal Called only by {@link RemoteRequestAdmission}, immediately after
 * authentication, the Layer C token, and the concurrency slot have all been
 * granted. It is exported so the admission authority and the executor can live in
 * separate modules without the executor trusting an object it did not mint.
 */
export function createAdmittedRemoteRequest(input: {
  session: TrustedSessionResult;
  spkiPin: string;
  release: () => void;
}): AdmittedRemoteRequest {
  let released = false;
  const lease: AdmittedRemoteRequest = {
    session: input.session,
    spkiPin: input.spkiPin,
    release: () => {
      if (released) {
        return;
      }
      released = true;
      input.release();
    },
  };
  ADMITTED_REQUESTS.add(lease);
  return lease;
}

/** True only for a lease minted by {@link createAdmittedRemoteRequest}. */
export function isAdmittedRemoteRequest(value: unknown): value is AdmittedRemoteRequest {
  return typeof value === 'object' && value !== null && ADMITTED_REQUESTS.has(value);
}

/** One request asking to be admitted to the authenticated remote surface. */
export interface RemoteAdmissionInput {
  /**
   * Canonical SPKI pin derived from the verified mTLS peer certificate. INTERNAL
   * trusted transport input: never read from JSON-RPC parameters or a body.
   */
  trustedSpkiPin: string;
  /**
   * The CURRENT enrolled device behind that pin, or undefined.
   *
   * Resolved by the caller on EVERY request from the current authoritative trust
   * store, and deliberately never cached: a resolver-minted identity stays a
   * valid Task-5 capability object after the device is revoked, so retaining one
   * would let a revoked device keep authenticating.
   */
  identity: TrustedSessionIdentity | undefined;
  /** Presented `Mcp-Session-Id`, verbatim. */
  presentedSessionId: string | null;
  /** Presented `Authorization` header value, verbatim. */
  authorizationHeader: string | null;
  /** True when the transport already recognized a server session context. */
  hasExistingSessionContext: boolean;
  /** `initialize` is the ONLY request kind that may bootstrap a session. */
  kind: 'initialize' | 'ordinary';
}

/**
 * The outcome of one admission attempt.
 *
 * `ADMITTED` is the only outcome that carries a lease. The others are refusals
 * (or the tokenless bootstrap case) and carry nothing at all: no session, no
 * device, no bucket, no reason — the bootstrap case carries only the
 * resolver-minted identity the transport needs to establish a session.
 */
export type RemoteAdmissionResult =
  | { readonly outcome: 'ADMITTED'; readonly admission: AdmittedRemoteRequest }
  | { readonly outcome: 'BOOTSTRAP_TOKENLESS'; readonly identity: TrustedSessionIdentity }
  | { readonly outcome: 'UNAUTHENTICATED' }
  | { readonly outcome: 'INVALID_SESSION_TOKEN' }
  | { readonly outcome: 'RATE_LIMITED' };

/**
 * THE authenticated remote-request admission authority.
 *
 * It performs, in the frozen order, device/session authentication → Layer C rate
 * token → per-session outstanding slot, and returns either one lease or one
 * refusal. It is the ONLY place any of those three steps happens, so the
 * transport cannot forget one of them and a tool call cannot be charged twice.
 */
export class RemoteRequestAdmission {
  private readonly sessionManager: SessionManager;
  private readonly authenticatedLimiter: BoundedRequestLimiter;

  constructor(deps: {
    /** The ONE process-local session authority (§2). Never a second instance. */
    sessionManager: SessionManager;
    /**
     * The ONE process-local Layer C limiter and per-session concurrency state.
     *
     * Production composition (`ArcMcpServer.start()`) supplies the single
     * process-wide instance and resets it on shutdown, so rate and concurrency
     * state is volatile and never persisted. When omitted, this authority creates
     * its own with the frozen production bounds — never a weaker set.
     */
    authenticatedLimiter?: BoundedRequestLimiter;
  }) {
    this.sessionManager = deps.sessionManager;
    this.authenticatedLimiter = deps.authenticatedLimiter ?? createAuthenticatedRequestLimiter();
  }

  /**
   * Admits ONE remote request, or refuses it.
   *
   * Every refusal is decided BEFORE any schema, policy, approval, subsystem, or
   * audit work exists for the request, and before any MCP message is parsed.
   */
  public admit(input: RemoteAdmissionInput): RemoteAdmissionResult {
    // 1. Task-5 admission. An ordinary request with no session context and no
    //    credential is UNAUTHENTICATED; anything carrying a session ID or a
    //    credential is judged in the post-session domain.
    const decision = this.sessionManager.admitRequest({
      kind: input.kind,
      hasExistingSessionContext: input.hasExistingSessionContext,
      presentedSessionId: input.presentedSessionId,
      authorizationHeader: input.authorizationHeader,
      identity: input.identity,
    });

    if (decision.outcome === 'BOOTSTRAP_TOKENLESS') {
      // Not an authenticated request: there is no session to key a budget on.
      // The tokenless bootstrap is bounded pre-session by Layer B, and this
      // authority deliberately does not invent a second pre-session budget.
      return { outcome: 'BOOTSTRAP_TOKENLESS', identity: decision.identity };
    }

    if (decision.outcome !== 'AUTHENTICATED') {
      // Stop on any admission failure, before any rate accounting, schema,
      // policy, or approval. Layer C is unreachable without authentication.
      return { outcome: decision.outcome };
    }

    const session = decision.session;

    // 2. Layer C: the authenticated session/device rate budget, keyed on the
    //    server-derived device and session identifiers only (§21.1 Layer C).
    const budget = this.authenticatedLimiter.consume(sessionRateLimitKey(session));
    if (!budget.consumed) {
      // Rate refusals and saturation share ONE client-facing error, so the
      // refusal is not a probe for whether a key exists or how full a bucket is.
      return { outcome: 'RATE_LIMITED' };
    }

    // 3. Per-session concurrency (§26 C-3). A request beyond the bound is
    //    refused immediately and is NEVER queued, so no unbounded backlog can
    //    accumulate behind a session.
    const slot = this.authenticatedLimiter.tryHold(budget.bucket);
    if (!slot.held) {
      return { outcome: 'RATE_LIMITED' };
    }

    return {
      outcome: 'ADMITTED',
      admission: createAdmittedRemoteRequest({
        session,
        spkiPin: input.trustedSpkiPin,
        release: slot.release,
      }),
    };
  }
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
  /**
   * The ONE admission authority this bridge executes against.
   *
   * Production composition supplies the SAME instance the transport was given,
   * so there is exactly one admission authority over exactly one Layer C
   * limiter. When omitted, a bridge builds one over `sessionManager` and
   * `authenticatedLimiter` — the same objects, so the accounting is identical.
   */
  admission?: RemoteRequestAdmission;
}

/** One remote tool call, as the future transport will supply it. */
export interface RemoteToolCallInput {
  /**
   * Canonical SPKI pin derived from the verified mTLS peer certificate by
   * Task-3 admission. INTERNAL trusted transport input: it is never read from
   * JSON-RPC parameters, headers, or a body.
   */
  trustedSpkiPin: string;
  /**
   * The admission the transport already granted for THIS request, when there is
   * one.
   *
   * Supplying it is what makes a `tools/call` cost exactly ONE Layer C rate
   * token and ONE outstanding slot: the transport already spent both admitting
   * the HTTP request, and the bridge executes against that same admission
   * instead of authenticating and charging a second time. Omitting it (the
   * direct application-API path) makes the bridge perform its own admission.
   *
   * A lease is only accepted when this module minted it AND it was granted on
   * the same SPKI pin as `trustedSpkiPin`, so a lease cannot be replayed onto
   * another request or another peer.
   */
  admission?: AdmittedRemoteRequest;
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
 * The HTTP body for the frozen `RATE_LIMIT_EXCEEDED` refusal (§21.1 Layer C).
 *
 * Derived from {@link remoteRateLimitFailure} so the wire representation and the
 * shared pipeline's error can never disagree. No retry-after hint, remaining
 * budget, limiter key, or session identifier is included: §25.1 requires a
 * sanitized refusal, and a computed retry delay would disclose exactly how full
 * the bucket is.
 */
export function remoteRateLimitResponseBody(): string {
  const failure = remoteRateLimitFailure();
  return JSON.stringify({ code: failure.code, message: failure.message });
}

/**
 * The composition-ready remote execution entry point.
 *
 * TWO entry shapes, deliberately:
 * - `executeRemoteToolCall(input)` is the application API. Called with no
 *   `admission` (as the Task-6 tests and any non-HTTP caller do) it performs
 *   admission itself and releases it in a `finally`.
 * - Called WITH the `admission` the transport already granted for the very same
 *   request, it re-authenticates nothing, spends no second rate token, and takes
 *   no second concurrency slot: it executes against the trusted lease. The lease
 *   belongs to the caller, which releases it when the HTTP exchange settles.
 *
 * Nothing here performs network I/O.
 */
export class RemoteExecutionBridge {
  private readonly authenticatedLimiter: BoundedRequestLimiter;
  private readonly admission: RemoteRequestAdmission;

  constructor(private readonly deps: RemoteExecutionDeps) {
    this.authenticatedLimiter = deps.authenticatedLimiter ?? createAuthenticatedRequestLimiter();
    // The SAME session authority and the SAME limiter instance, whether or not
    // the composition supplied the admission authority explicitly: there is
    // exactly one admission authority and exactly one Layer C table per process.
    this.admission =
      deps.admission ??
      new RemoteRequestAdmission({
        sessionManager: deps.sessionManager,
        authenticatedLimiter: this.authenticatedLimiter,
      });
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
    const sessionIdPresented = input.presentedSessionId ?? null;
    const credentialPresented = input.authorizationHeader ?? null;

    // The transport already admitted THIS request. Reuse that admission: the
    // request must not be authenticated or charged a second time.
    if (input.admission !== undefined) {
      const admission = input.admission;
      if (!isAdmittedRemoteRequest(admission) || admission.spkiPin !== input.trustedSpkiPin) {
        // Not a lease this process minted, or one granted to a different peer:
        // refused exactly like an absent credential. The lease is NOT released
        // here — it belongs to the request that was admitted, not to this call.
        throw remoteAuthenticationFailure();
      }
      return await this.executeAdmitted(admission.session, input);
    }

    // The application API path: no HTTP request admitted this call, so it is
    // admitted here and released when the call settles.
    const identity = this.deps.resolveActiveDeviceIdentity(input.trustedSpkiPin);
    const result = this.admission.admit({
      trustedSpkiPin: input.trustedSpkiPin,
      identity,
      presentedSessionId: sessionIdPresented,
      authorizationHeader: credentialPresented,
      hasExistingSessionContext:
        input.hasExistingSessionContext === true ||
        sessionIdPresented !== null ||
        credentialPresented !== null,
      kind: 'ordinary',
    });

    if (result.outcome === 'RATE_LIMITED') {
      throw remoteRateLimitFailure();
    }
    if (result.outcome !== 'ADMITTED') {
      throw this.failureFor(result.outcome, sessionIdPresented, credentialPresented);
    }

    try {
      return await this.executeAdmitted(result.admission.session, input);
    } finally {
      // Released on EVERY exit path — success, actor-field refusal, policy
      // denial, approval requirement, approval rejection, subsystem error, and
      // any thrown internal error — so a failed call can never leak a slot.
      result.admission.release();
    }
  }

  /**
   * Runs one ALREADY-ADMITTED request through the shared RC-04 pipeline.
   *
   * The actor comes from the trusted admission alone, and the actor-field guard
   * runs before any policy evaluation, approval lookup, or subsystem call, so no
   * later stage can observe a spoofing attempt.
   */
  private async executeAdmitted(
    session: TrustedSessionResult,
    input: RemoteToolCallInput,
  ): Promise<RemoteToolCallResult> {
    const actor = deriveRemoteActor(session);

    const injection = findActorFieldInjection(input.parameters);
    if (injection !== null) {
      throw ArcError.invalidRequestSchema(
        `Invalid parameters for tool '${input.toolName}': reserved actor or transport identity field is not permitted in remote request parameters.`,
      );
    }

    return await this.deps.sink.executeAuthenticatedToolCall(
      actor,
      input.toolName,
      input.parameters,
    );
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
