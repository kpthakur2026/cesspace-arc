/**
 * CesSpace ARC — RC-05 Task 8 Streamable HTTP MCP Surface
 *
 * The ONE remote MCP transport. It composes the SDK's
 * `StreamableHTTPServerTransport` in STATEFUL mode over the already-authenticated
 * request stream the gateway hands it, and it owns nothing else: it makes no
 * policy decision, redeems no approval, and calls no subsystem.
 *
 * Authoritative contract: §4, §5.3, §5.4, §6, §7, §10, §11, §12, §13, §21, §25.1,
 * and the Task-8 row of §38. Controls: RC05-NEG-02, RC05-NEG-03, RC05-NEG-04,
 * RC05-NEG-06.
 *
 * Position in the request path: this module runs AFTER every Task-3/4/7 ingress
 * control the gateway already enforces (mTLS admission, Layer B, the 16 KiB
 * header bound, the 10 s header-read deadline, the 2 KiB request-target bound,
 * compressed-request refusal, the request-body ceiling, the 10 s body-read
 * deadline, and the 60 s total request deadline). It can only ever REFUSE
 * further; it re-implements none of them.
 *
 * Design rules:
 * - ONE admission per authenticated request. Identity and session credentials are
 *   authenticated, the Layer C rate token is spent, and a §26 C-3 concurrency
 *   slot is taken by `RemoteRequestAdmission` for EVERY authenticated MCP
 *   request — `initialize` aside, that is POST, GET SSE, DELETE, `tools/list`,
 *   `ping`, and `tools/call` alike. No request kind can bypass Layer C.
 * - The granted admission is held until the HTTP exchange SETTLES, so a
 *   long-lived GET SSE stream keeps its slot for the life of the stream and
 *   releases it exactly once on completion, error, socket close, or shutdown.
 * - ONE session authority. The session ID generator is Task-5's
 *   `SessionManager.createSessionIdGenerator()`, so every `Mcp-Session-Id` is a
 *   reserved server-issued identifier and there is no second authority.
 * - ONE registry, bounded by the frozen global session capacity, keyed by the
 *   server-issued `Mcp-Session-Id`. There is no shadow session ID, and the
 *   registry is reconciled against the session authority before its occupancy is
 *   ever used as a capacity decision, so a dead entry cannot pin capacity.
 * - Identity is the gateway-derived SPKI pin and the ACTIVE enrolled device
 *   behind it. No JSON field, tool parameter, `Host`, `Origin`, `X-Forwarded-*`,
 *   or client-supplied session identifier is ever an identity input.
 * - Every APPLICATION-LEVEL refusal is the SAME bounded MCP JSON-RPC error
 *   envelope (§25): device/session admission failures, the Layer C
 *   rate/concurrency refusal, and a refused JSON-RPC batch are all framed
 *   identically, so the shape of a refusal discloses nothing and never names
 *   whether a session, device, or revocation exists. Transport-level refusals —
 *   Host/Origin, Layer B, method, size, and read bounds — stay transport-level
 *   and keep failing BEFORE any MCP framing, exactly as §25 orders them.
 * - Layer C is the MCP application channel, not the transport channel. Its
 *   refusal is NOT a bare HTTP 429: §25 reserves status-only refusals for the
 *   TRANSPORT layers (Layer A drops the connection, Layer B answers 429 with no
 *   MCP body, and 404/405/413 stay transport-level). Layer C runs only AFTER a
 *   session has been authenticated, so its refusal is a JSON-RPC error reply.
 * - JSON-RPC batching is REFUSED. MCP `2025-06-18` removed batching from the
 *   protocol and the frozen scope requires no batch support, so a batch array is
 *   refused as ONE malformed Request before the SDK sees it. The SDK would
 *   otherwise invoke its handler once per member while ARC had spent a single
 *   Layer C token and a single §26 C-3 slot for the whole batch — a way to
 *   amortize one admission across arbitrarily many MCP requests. Refusing is
 *   fail-closed and needs no per-member accounting.
 * - The SDK's deprecated `allowedHosts`, `allowedOrigins`, and
 *   `enableDnsRebindingProtection` options are NOT used: §10/§11 require ARC's
 *   own gateway-side validation, which runs before the SDK sees the request.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { ArcError } from '@cesspace-arc/protocol';
import {
  ARC_SESSION_TOKEN_HEADER,
  MAX_ACTIVE_SESSIONS_GLOBAL,
  type SessionManager,
  type TrustedSessionIdentity,
} from '@cesspace-arc/auth';
import {
  MCP_POST_REPLY_STATUS,
  MCP_STREAM_REPLY_STATUS,
  isAdmittedRemoteRequest,
  jsonRpcRequestId,
  mcpAdmissionErrorBody,
  mcpBatchRefusalBody,
  remoteAuthenticationFailure,
  remoteRateLimitFailure,
  remoteSessionFailure,
  type AdmittedRemoteRequest,
  type JsonRpcRequestId,
  type RemoteRequestAdmission,
} from './remote-execution.js';
import { checkRequestAuthority, writeAuthorityRefusal } from './remote-request-authority.js';
import {
  MAX_REMOTE_BODY_BYTES,
  RequestBodyError,
  readBoundedRequestBody,
} from './remote-request-bounds.js';

// The Host (§10) and Origin (§11) refusals and their normalization are owned by
// the ONE shared authority module, so `/mcp` and `/enroll/complete` cannot
// drift. Re-exported here because this module is the documented `/mcp` contract.
export {
  HOST_REFUSED_BODY,
  ORIGIN_REFUSED_BODY,
  normalizeHostHeader,
} from './remote-request-authority.js';

/**
 * The Task-4/§7 `UNAUTHENTICATED` body for a request that never became an MCP
 * message: an unreadable body (this module) and the deny-only `/mcp` placeholder
 * `enrollment-bootstrap.ts` answers with when no surface is composed.
 *
 * An ADMISSION failure does NOT use this shape any more — §25 frames those as
 * MCP JSON-RPC errors (see `sendMcpRefusal`). The post-session counterpart is
 * the same envelope carrying `INVALID_SESSION_TOKEN`, so there is no separate
 * bare post-session body constant to keep in step.
 */
export const UNAUTHENTICATED_BODY = JSON.stringify({
  code: 'UNAUTHENTICATED',
  message: 'Authentication failed',
});

/** §4: `/mcp` supports exactly these three methods. */
export const MCP_ALLOWED_METHODS = 'GET, POST, DELETE';

/** §4: any other method on `/mcp`. Refused before the body is read. */
export const METHOD_NOT_ALLOWED_BODY = JSON.stringify({ error: 'Method not allowed' });

/**
 * The `authInfo.token` value attached to every authenticated MCP request.
 *
 * Deliberately NOT a credential, and deliberately not the session token: ARC
 * never copies the raw session token into a second channel. The SDK's `AuthInfo`
 * requires the field, so it carries this fixed marker instead, and the
 * request-scoped values the tool handler actually needs travel in `extra`.
 */
const AUTH_INFO_TOKEN_MARKER = 'arc-gateway-session';

/**
 * The request-scoped facts one authenticated MCP call needs.
 *
 * Rebuilt from the CURRENT request on every call. It is never cached across
 * requests and never stored on the session: a value that outlived its request
 * could be replayed against a later one.
 */
export interface RemoteRequestContext {
  /** Gateway-derived mTLS SPKI pin. The only identity input. */
  spkiPin: string;
  /** The `Mcp-Session-Id` this request presented, verbatim, or null. */
  presentedSessionId: string | null;
  /** The `Authorization` header this request presented, verbatim, or null. */
  authorizationHeader: string | null;
  /**
   * The admission THIS request was granted.
   *
   * Carried so the tool handler executes against the very admission the request
   * already paid for — ONE Layer C rate token and ONE outstanding slot — instead
   * of authenticating and charging a second time. It is the server-minted lease
   * for this request, never a value derived from it, and the handler refuses to
   * proceed without one.
   */
  admission: AdmittedRemoteRequest;
}

/**
 * Per-session facts the MCP `Server` factory needs to build a remote server.
 *
 * Only the SPKI pin: the SDK has not issued the session ID at the moment the
 * server is built, and it does not need to be passed, because the tool handler
 * receives it as `extra.sessionId` and the execution bridge derives the actor
 * session ID from the authenticated session itself.
 */
export interface RemoteSessionServerContext {
  spkiPin: string;
}

/**
 * Builds the MCP `Server` for one remote session.
 *
 * Supplied by `ArcMcpServer` so the remote surface reuses the EXACT SAME tool
 * catalog and execution entry point as stdio. The surface itself never knows how
 * a tool is dispatched, which is what keeps a second dispatcher impossible.
 */
export type RemoteSessionServerFactory = (context: RemoteSessionServerContext) => Server;

export interface RemoteMcpSurfaceDeps {
  sessionManager: SessionManager;
  /**
   * THE ONE authenticated remote-request admission authority.
   *
   * Every authenticated MCP request — POST, GET SSE, DELETE, `tools/list`,
   * `ping`, and `tools/call` alike — passes through it, so Layer C (§21.1) and
   * the §26 C-3 concurrency bound are per-REQUEST controls that no request kind
   * can bypass. It is the SAME instance the execution bridge executes against,
   * so a `tools/call` is never authenticated or charged twice.
   */
  admission: RemoteRequestAdmission;
  createSessionServer: RemoteSessionServerFactory;
  /** The configured public hostname. The single accepted `Host` value (§10). */
  publicHostname: string;
}

/** One live remote MCP session: its SDK transport and its MCP server. */
interface RemoteSessionEntry {
  sessionId: string;
  transport: StreamableHTTPServerTransport;
  server: Server;
}

/**
 * True when the request is a single JSON-RPC `initialize` request.
 *
 * Mirrors the SDK's own classification for one message. There is no batch arm
 * because a batch never reaches this function: `handlePost` refuses a JSON-RPC
 * array immediately after parsing, before classification and before admission,
 * so "initialize plus something else" cannot be classified as a bootstrap at all.
 *
 * This decides only which admission question to ask Task 5; it establishes
 * nothing by itself, and a request merely CLAIMING to be `initialize` still has
 * to satisfy `admitRequest` to reach the transport.
 */
function isInitializeRequest(body: unknown): boolean {
  return (
    typeof body === 'object' &&
    body !== null &&
    !Array.isArray(body) &&
    (body as { method?: unknown }).method === 'initialize'
  );
}

/**
 * Maps an admission refusal to its canonical anti-oracle `ArcError`.
 *
 * `ADMITTED` is not a refusal and is not accepted here, so a caller cannot
 * accidentally frame a success as an error. `BOOTSTRAP_TOKENLESS` IS accepted
 * and maps to the pre-session failure: it means the request presented no
 * credential at all, which for the session-bound GET/DELETE that can reach this
 * mapping is exactly `UNAUTHENTICATED`. `POST` handles its bootstrap before
 * reaching here. This is the ONLY mapping from an admission outcome to a
 * client-facing failure, so the surface cannot invent a second, differently
 * shaped refusal.
 */
function admissionFailure(
  outcome: 'UNAUTHENTICATED' | 'INVALID_SESSION_TOKEN' | 'BOOTSTRAP_TOKENLESS',
): ArcError {
  return outcome === 'INVALID_SESSION_TOKEN'
    ? remoteSessionFailure()
    : remoteAuthenticationFailure();
}

/** Reads one header as a verbatim string, or null when absent or repeated. */
function readSingleHeader(req: IncomingMessage, name: string): string | null {
  const value = req.headers[name];
  return typeof value === 'string' ? value : null;
}

/**
 * Reads the request context back out of the SDK's `authInfo` channel.
 *
 * The SDK copies `req.auth` to `options.authInfo` and hands it to the request
 * handler as `extra.authInfo`, so the context is request-scoped by construction
 * and cannot be confused between two concurrent calls on one session.
 *
 * Returns null — and the caller MUST fail closed — for a missing or malformed
 * context, and equally for an `admission` this process did not mint: executing a
 * tool call without a server-issued admission would mean executing a call that
 * was never authenticated or charged, so the absence of one is a refusal rather
 * than a reason to admit the call a second time.
 */
export function readRemoteRequestContext(
  authInfo: AuthInfo | undefined,
): RemoteRequestContext | null {
  const extra = authInfo?.extra;
  if (extra === undefined || extra === null) {
    return null;
  }
  const { spkiPin, presentedSessionId, authorizationHeader, admission } = extra as Record<
    string,
    unknown
  >;
  if (typeof spkiPin !== 'string' || spkiPin.length === 0) {
    return null;
  }
  if (!isAdmittedRemoteRequest(admission)) {
    return null;
  }
  const sessionId = typeof presentedSessionId === 'string' ? presentedSessionId : null;
  const authorization = typeof authorizationHeader === 'string' ? authorizationHeader : null;
  return {
    spkiPin,
    presentedSessionId: sessionId,
    authorizationHeader: authorization,
    admission,
  };
}

export class RemoteMcpSurface {
  private readonly deps: RemoteMcpSurfaceDeps;
  private readonly sessionIdGenerator: () => string;
  /**
   * THE authoritative association between a server-issued `Mcp-Session-Id`, its
   * SDK transport, and its MCP server.
   *
   * Bounded by the frozen global session capacity, and it is the ONLY collection
   * holding transports: there is no event history, retry queue, or reconnection
   * store, and no entry is created before the session it names exists. An entry
   * is removed by every terminal path — DELETE, failed initialize, revocation
   * observed on a later request, shutdown, and transport close.
   */
  private readonly sessions = new Map<string, RemoteSessionEntry>();
  /**
   * Admissions whose HTTP request is still outstanding.
   *
   * A request holds its Layer C slot from admission until its response settles —
   * for a long-lived GET SSE stream, that is the whole life of the stream. This
   * set exists so shutdown can release those slots deterministically instead of
   * waiting for a socket close that a hard stop may never deliver. It is bounded
   * by the §26 C-3 concurrency bound times the session capacity, and an entry is
   * removed by the same idempotent release the response listeners call.
   */
  private readonly liveAdmissions = new Set<AdmittedRemoteRequest>();
  private closed = false;

  constructor(deps: RemoteMcpSurfaceDeps) {
    this.deps = deps;
    // §5/RC05-NEG-06: the stateful generator is MANDATORY and comes from the one
    // Task-5 session authority. A missing or non-functional authority throws
    // HERE, inside construction, so remote startup fails closed and no listener
    // is ever bound — rather than silently degrading to a stateless transport.
    const generator = deps.sessionManager.createSessionIdGenerator();
    if (typeof generator !== 'function') {
      throw new Error('Remote MCP transport requires the Task-5 session ID generator.');
    }
    this.sessionIdGenerator = generator;
  }

  /** Live remote MCP sessions. Bounded by the frozen global capacity. */
  public getActiveSessionCount(): number {
    return this.sessions.size;
  }

  /**
   * Handles one `/mcp` request that has already passed every earlier ingress
   * control. `spkiPin` is the Task-3 mTLS identity; `identity` is the CURRENT
   * enrolled device behind it, or undefined when there is none.
   */
  public async handle(
    req: IncomingMessage,
    res: ServerResponse,
    spkiPin: string,
    identity: TrustedSessionIdentity | undefined,
  ): Promise<void> {
    if (this.closed) {
      this.send(res, 404, METHOD_NOT_ALLOWED_BODY);
      return;
    }

    // §10 Host and §11 Origin — the SAME shared authority check the gateway
    // applies to every configured remote endpoint, applied here as well so a
    // surface reached by any other composition cannot become a bypass and the
    // two endpoints cannot drift. It reads only the `Host` header Node's parser
    // produced; `X-Forwarded-Host` and every other forwarding header is never
    // consulted, because ARC has no reverse-proxy trust model.
    const refusal = checkRequestAuthority(req.headers, this.deps.publicHostname);
    if (refusal !== null) {
      writeAuthorityRefusal(res, refusal);
      return;
    }

    const method = req.method ?? '';
    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      // §4/RC05-NEG-04: an unsupported method is refused before the body is
      // read, so it cannot reach policy, a session, a subsystem, or the SDK.
      this.send(res, 405, METHOD_NOT_ALLOWED_BODY, { Allow: MCP_ALLOWED_METHODS });
      return;
    }

    if (method === 'POST') {
      await this.handlePost(req, res, spkiPin, identity);
      return;
    }

    await this.handleSessionBound(req, res, spkiPin, identity, method);
  }

  /**
   * POST: either a tokenless `initialize` that may establish a session, or an
   * ordinary request that must be fully authenticated.
   */
  private async handlePost(
    req: IncomingMessage,
    res: ServerResponse,
    spkiPin: string,
    identity: TrustedSessionIdentity | undefined,
  ): Promise<void> {
    let rawBody: string;
    try {
      rawBody = await readBoundedRequestBody(req, { maxBytes: MAX_REMOTE_BODY_BYTES });
    } catch (err: unknown) {
      if (err instanceof RequestBodyError) {
        if (err.kind === 'PAYLOAD_TOO_LARGE') {
          this.send(res, 413, JSON.stringify({ error: 'Payload too large' }));
          return;
        }
        if (err.kind === 'READ_TIMEOUT') {
          // The reader already destroyed the socket: there is no complete
          // request to answer and the connection must not be held open.
          return;
        }
      }
      // Ingress failure, not an admission decision: the body could not be read
      // at all, so there is no request to frame a JSON-RPC reply to. §25 keeps
      // request-size and read bounds transport-level, and this stays with them.
      this.send(res, 400, UNAUTHENTICATED_BODY);
      return;
    }

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(rawBody) as unknown;
    } catch {
      // An unparseable body cannot be an `initialize`, so it is classified as an
      // ordinary request: tokenless it is `UNAUTHENTICATED`, and with a session
      // context it is `INVALID_SESSION_TOKEN`. An AUTHENTICATED caller with a
      // malformed body still reaches the transport, which returns the JSON-RPC
      // parse error itself.
      parsedBody = undefined;
    }

    // §21.1 Layer C / §26 C-3 / MCP `2025-06-18`: a JSON-RPC BATCH is refused.
    //
    // This is the ONLY point at which a batch can be stopped before it costs
    // anything. The installed SDK accepts an array, maps it to messages, and
    // calls its handler ONCE PER MEMBER — while ARC spends exactly one Layer C
    // rate token and takes exactly one §26 C-3 concurrency slot for the whole
    // HTTP request. One POST could therefore carry unbounded MCP requests on a
    // single admission, which is precisely the accounting the frozen bounds
    // forbid (max 300 MCP REQUESTS/min, max 4 outstanding MCP REQUESTS per
    // session).
    //
    // Refusing is the fail-closed reading of the frozen scope: MCP `2025-06-18`
    // removed batching, and the scope requires no batch support, so there is no
    // baseline control to preserve. The check runs on the ALREADY-BOUNDED,
    // ALREADY-PARSED body, before `admit`, so no member of the batch reaches the
    // SDK, the tool catalog, the shared RC-04 pipeline, policy, approval, or any
    // subsystem; no Layer C token or concurrency slot is ever created for it; no
    // session is minted; and the request's active session, if it named one, is
    // left untouched. The refusal is one bounded MCP JSON-RPC error with a
    // `null` id — there is no single request to echo an id for.
    if (Array.isArray(parsedBody)) {
      this.send(res, MCP_POST_REPLY_STATUS, mcpBatchRefusalBody());
      return;
    }

    const presentedSessionId = readSingleHeader(req, 'mcp-session-id');
    const authorizationHeader = readSingleHeader(req, 'authorization');
    const existing =
      presentedSessionId !== null ? this.sessions.get(presentedSessionId) : undefined;
    const kind = isInitializeRequest(parsedBody) ? 'initialize' : 'ordinary';
    // The id every MCP-framed refusal below replies to. Computed once from the
    // bounded body that was already parsed for classification — nothing is read
    // a second time to obtain it, and a body that yielded no id yields `null`.
    const requestId: JsonRpcRequestId = jsonRpcRequestId(parsedBody);

    // ONE admission per request: identity/session authentication, the Layer C
    // rate token, and the §26 C-3 concurrency slot, for EVERY authenticated MCP
    // request — `tools/list`, `ping`, and `tools/call` alike. A client cannot
    // reach the transport without passing all three.
    const decision = this.deps.admission.admit({
      trustedSpkiPin: spkiPin,
      identity,
      presentedSessionId,
      authorizationHeader,
      hasExistingSessionContext: existing !== undefined,
      kind,
    });

    if (decision.outcome === 'BOOTSTRAP_TOKENLESS') {
      await this.bootstrapSession(req, res, spkiPin, decision.identity, parsedBody, requestId);
      return;
    }

    if (decision.outcome === 'RATE_LIMITED') {
      // §21.1 Layer C / §26 C-3: one sanitized refusal for both the rate and the
      // concurrency bound, with the frozen `RATE_LIMIT_EXCEEDED` code. An
      // authenticated session exists at this point, so the refusal is an MCP
      // JSON-RPC error on the MCP channel — NOT a bare HTTP 429, which §25
      // reserves for Layer B, the pre-session transport limit.
      this.sendMcpRefusal(res, 'POST', remoteRateLimitFailure(), requestId);
      return;
    }

    if (decision.outcome !== 'ADMITTED') {
      // §25: a pre-session device failure is `UNAUTHENTICATED` and a post-session
      // failure is `INVALID_SESSION_TOKEN`, both MCP JSON-RPC framed. The two
      // remain indistinguishable from each other in shape, and neither discloses
      // whether the device exists, is revoked, whether the SPKI is recognized, or
      // whether a session ever existed.
      await this.reapPresentedSession(presentedSessionId);
      this.sendMcpRefusal(res, 'POST', admissionFailure(decision.outcome), requestId);
      return;
    }

    const sessionId = decision.admission.session.sessionId;

    // Authenticated. The registry must agree with the session authority; if it
    // somehow does not, this fails closed as a generic session failure rather
    // than serving a request whose transport binding cannot be proven.
    const entry = this.sessions.get(sessionId);
    if (entry === undefined) {
      // Nothing can serve this request, so the admission it holds is released
      // immediately rather than held for a response that will never use it.
      decision.admission.release();
      this.sendMcpRefusal(res, 'POST', remoteSessionFailure(), requestId);
      return;
    }

    await this.dispatch(
      res,
      entry,
      req,
      decision.admission,
      {
        spkiPin,
        presentedSessionId: sessionId,
        authorizationHeader,
      },
      parsedBody,
    );
  }

  /**
   * GET and DELETE: both are session-bound. Neither may act without a matching
   * `Mcp-Session-Id`, bearer credential, and mTLS identity binding, and neither
   * reads a body.
   */
  private async handleSessionBound(
    req: IncomingMessage,
    res: ServerResponse,
    spkiPin: string,
    identity: TrustedSessionIdentity | undefined,
    method: 'GET' | 'DELETE',
  ): Promise<void> {
    const presentedSessionId = readSingleHeader(req, 'mcp-session-id');
    const authorizationHeader = readSingleHeader(req, 'authorization');

    // The same ONE admission as POST. A GET SSE stream therefore consumes the
    // same Layer C budget and holds one of the same four §26 C-3 slots for as
    // long as the stream is open; a DELETE settles like any other request.
    const decision = this.deps.admission.admit({
      trustedSpkiPin: spkiPin,
      identity,
      presentedSessionId,
      authorizationHeader,
      hasExistingSessionContext:
        presentedSessionId !== null && this.sessions.has(presentedSessionId),
      kind: 'ordinary',
    });

    if (decision.outcome === 'RATE_LIMITED') {
      // MCP-framed like the POST refusal, but on the status the installed SDK
      // itself uses for a GET/DELETE it cannot serve. A GET/DELETE carries no
      // JSON-RPC request, so there is no id to echo and the envelope's id is
      // `null`. The ARC semantic code still travels in `error.data.code`.
      this.sendMcpRefusal(res, method, remoteRateLimitFailure(), null);
      return;
    }

    if (decision.outcome !== 'ADMITTED') {
      // §12: no unauthenticated stream may be opened, and §13: no session may be
      // terminated on unproven credentials. Distinguishing pre-session from
      // post-session here would disclose whether a session ID exists, so the
      // pre-session case stays uniformly `UNAUTHENTICATED` and only a request
      // that actually presented a session context gets the session failure.
      await this.reapPresentedSession(presentedSessionId);
      this.sendMcpRefusal(res, method, admissionFailure(decision.outcome), null);
      return;
    }

    const entry = this.sessions.get(decision.admission.session.sessionId);
    if (entry === undefined) {
      decision.admission.release();
      this.sendMcpRefusal(res, method, remoteSessionFailure(), null);
      return;
    }

    await this.dispatch(
      res,
      entry,
      req,
      decision.admission,
      {
        spkiPin,
        presentedSessionId: decision.admission.session.sessionId,
        authorizationHeader,
      },
      undefined,
      method,
    );
  }

  /**
   * Runs one authenticated request through the session's SDK transport.
   *
   * The transport is the ONLY thing that speaks MCP here. It parses the request,
   * validates the session, and calls back into the per-session `Server`, whose
   * tool handler routes into the existing `RemoteExecutionBridge` with the
   * admission handed to it here.
   *
   * The admission is held until the HTTP exchange SETTLES, not until
   * `handleRequest` returns: a GET SSE stream keeps its slot for the whole life
   * of the stream, and a POST keeps its slot until its response is complete.
   * `finish` and `close` are BOTH armed and the release is idempotent, so exactly
   * one slot is freed whichever fires and every path — normal completion,
   * protocol error, stream close, DELETE completion, response error, socket
   * close, and `closeAll()` on shutdown — releases it.
   */
  private async dispatch(
    res: ServerResponse,
    entry: RemoteSessionEntry,
    req: IncomingMessage,
    admission: AdmittedRemoteRequest,
    context: Omit<RemoteRequestContext, 'admission'>,
    parsedBody: unknown,
    method: 'POST' | 'GET' | 'DELETE' = 'POST',
  ): Promise<void> {
    const sessionId = entry.transport.sessionId;
    if (sessionId !== undefined && !this.deps.sessionManager.hasSession(sessionId)) {
      // The authoritative session authority no longer holds this session, so the
      // binding is dropped immediately rather than outliving the session it
      // names. The admission was granted on that same authoritative answer, so
      // it is released here rather than held for a response that will not run.
      admission.release();
      await this.discard(sessionId);
      this.sendMcpRefusal(res, method, remoteSessionFailure(), jsonRpcRequestId(parsedBody));
      return;
    }

    this.holdAdmission(res, admission);

    // The SDK copies this to `options.authInfo` and the request handler receives
    // it as `extra.authInfo`, so the context is scoped to THIS request.
    (req as IncomingMessage & { auth?: AuthInfo }).auth = {
      token: AUTH_INFO_TOKEN_MARKER,
      clientId: sessionId ?? AUTH_INFO_TOKEN_MARKER,
      scopes: [],
      extra: {
        spkiPin: context.spkiPin,
        presentedSessionId: context.presentedSessionId,
        authorizationHeader: context.authorizationHeader,
        admission,
      },
    };

    try {
      await entry.transport.handleRequest(
        req as IncomingMessage & { auth?: AuthInfo },
        res,
        method === 'POST' ? parsedBody : undefined,
      );
    } catch {
      // The transport reports its own protocol errors through the response. A
      // throw here means the exchange could not be completed at all, so the
      // binding is torn down rather than left half-alive. The admission itself is
      // released by the listeners armed above, which `res.destroy()` also fires.
      if (method === 'DELETE' && sessionId !== undefined) {
        await this.discard(sessionId);
      }
      if (!res.headersSent && !res.writableEnded) {
        res.destroy();
      }
    }
  }

  /**
   * Holds one admission until its HTTP response settles.
   *
   * A `finish` (the response completed) and a `close` (the exchange ended,
   * including an aborted or destroyed socket) are both armed because either can
   * be the only signal on a given path; the release is idempotent, so exactly one
   * slot is freed. `closeAll()` drains the same set on shutdown.
   */
  private holdAdmission(res: ServerResponse, admission: AdmittedRemoteRequest): void {
    this.liveAdmissions.add(admission);
    const release = () => {
      this.liveAdmissions.delete(admission);
      admission.release();
    };
    res.once('finish', release);
    res.once('close', release);
  }

  /**
   * The tokenless `initialize` flow (§6).
   *
   * Order matters and is fixed: the SDK has ALREADY validated the initialize
   * shape before it calls the generator, so the generator runs only when a
   * session is genuinely being established; the session ID is reserved by the
   * Task-5 authority and never taken from the request; activation happens in
   * `onsessioninitialized`, after the SDK has accepted the initialize; and the
   * raw token is written once as a response header before the response is sent.
   */
  private async bootstrapSession(
    req: IncomingMessage,
    res: ServerResponse,
    spkiPin: string,
    identity: TrustedSessionIdentity,
    parsedBody: unknown,
    requestId: JsonRpcRequestId,
  ): Promise<void> {
    // BEFORE registry occupancy is used as a capacity decision, the registry is
    // reconciled against the authoritative session manager. An entry whose
    // session has expired or been revoked is not normally presented again — the
    // authority removes an expired session before this surface sees the request —
    // so without this sweep a dead entry would consume the global session
    // capacity for the life of the process and could eventually stop every new
    // session from being created.
    await this.reapOrphanedSessions();

    if (this.sessions.size >= MAX_ACTIVE_SESSIONS_GLOBAL) {
      // Capacity, not a credential: refused with the same `UNAUTHENTICATED`
      // envelope as any other pre-session failure so it cannot be used to probe
      // how many sessions exist.
      this.sendMcpRefusal(res, 'POST', remoteAuthenticationFailure(), requestId);
      return;
    }

    // The ID the generator reserved for THIS bootstrap, captured so a failure
    // can release exactly that reservation and nothing else.
    let reservedSessionId: string | undefined;

    const transport = new StreamableHTTPServerTransport({
      // §5: STATEFUL, always. Supplying a real generator is what makes the SDK
      // maintain one transport per session; omitting it would silently select
      // stateless mode, which §3 forbids and RC05-NEG-06 fails closed on.
      sessionIdGenerator: () => {
        const generated = this.sessionIdGenerator();
        reservedSessionId = generated;
        return generated;
      },
      onsessioninitialized: (sessionId: string) => {
        // The SDK has accepted `initialize` and adopted `sessionId`; nothing has
        // been written to the response yet, so the one-time token can still be
        // delivered as a header. A client-supplied `Mcp-Session-Id` is never
        // consulted: `sessionId` comes only from the generator above.
        //
        // `issueSession` consumes the reservation the generator made, mints the
        // raw token, retains only its digest, and returns the token exactly once.
        // It throws on a quota refusal, which propagates out of `handleRequest`
        // and down into the rollback below.
        const issuance = this.deps.sessionManager.issueSession({ sessionId, identity });
        res.setHeader(ARC_SESSION_TOKEN_HEADER, issuance.token);
        this.sessions.set(sessionId, { sessionId, transport, server: entryServer });
      },
      onsessionclosed: (sessionId: string) => {
        this.teardownSession(sessionId);
      },
    });

    const entryServer = this.deps.createSessionServer({ spkiPin });
    await entryServer.connect(transport);

    try {
      await transport.handleRequest(req as IncomingMessage & { auth?: AuthInfo }, res, parsedBody);
    } catch {
      // §6: an initialize that failed before activation must not retain a
      // reservation, a session, or a transport. The reservation is released by
      // ID (a no-op if issuance already consumed it), the session is closed, the
      // registry entry is dropped, and the SDK objects are closed.
      await this.rollbackBootstrap(reservedSessionId, entryServer, transport);
      if (!res.headersSent && !res.writableEnded) {
        res.destroy();
      }
      return;
    }

    // A session that was reserved but never activated — the SDK generated an ID
    // and then refused the initialize — is released here, so a failed bootstrap
    // cannot pin capacity until the reservation window expires.
    if (reservedSessionId !== undefined && !this.sessions.has(reservedSessionId)) {
      await this.rollbackBootstrap(reservedSessionId, entryServer, transport);
    }
  }

  /** Releases everything one bootstrap attempt may have retained. */
  private async rollbackBootstrap(
    reservedSessionId: string | undefined,
    server: Server,
    transport: StreamableHTTPServerTransport,
  ): Promise<void> {
    if (reservedSessionId !== undefined) {
      this.deps.sessionManager.releaseSessionIdReservation(reservedSessionId);
      this.deps.sessionManager.closeSession(reservedSessionId);
      this.sessions.delete(reservedSessionId);
    }
    await server.close().catch(() => undefined);
    await transport.close().catch(() => undefined);
  }

  /** Removes a session's binding and closes its SDK objects. Idempotent. */
  private async discard(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (entry === undefined) {
      return;
    }
    this.sessions.delete(sessionId);
    await entry.server.close().catch(() => undefined);
    await entry.transport.close().catch(() => undefined);
  }

  /**
   * Reclaims ONE presented registry entry the authoritative session manager no
   * longer has.
   *
   * The question is asked OF the session manager — `hasSession` is its own
   * answer about whether the session still exists and is live — and never
   * inferred from the fact that authentication failed. A wrong token presented
   * for a STILL-ACTIVE session is also an authentication failure, and reaping on
   * that basis would let any caller destroy a legitimate session by presenting a
   * bad credential. Only "the authority says this session is gone" reclaims an
   * entry, and the entry's SDK server and transport are closed with it.
   */
  private async reapPresentedSession(presentedSessionId: string | null): Promise<void> {
    if (presentedSessionId === null || !this.sessions.has(presentedSessionId)) {
      return;
    }
    if (this.deps.sessionManager.hasSession(presentedSessionId)) {
      return;
    }
    await this.discard(presentedSessionId);
  }

  /**
   * Reconciles the WHOLE registry against the authoritative session manager.
   *
   * The registry is capped at the same frozen global session capacity, so this
   * sweep is bounded by 1024 `hasSession` calls. It arms no timer, retains no
   * history, and keeps no tombstones: it is a reconciliation, not a bookkeeping
   * structure, and it is the only thing that lets capacity pinned by an expired
   * session become reusable again without a process restart.
   */
  private async reapOrphanedSessions(): Promise<void> {
    for (const sessionId of [...this.sessions.keys()]) {
      if (!this.deps.sessionManager.hasSession(sessionId)) {
        await this.discard(sessionId);
      }
    }
  }

  /**
   * §13: the DELETE path. Revokes the gateway session bound to exactly this
   * `Mcp-Session-Id` through the existing Task-5 primitive, then releases the
   * server. No other session is touched, and the transport is left to the SDK,
   * which closes it immediately after this callback returns.
   */
  private teardownSession(sessionId: string): void {
    this.deps.sessionManager.closeSession(sessionId);
    const entry = this.sessions.get(sessionId);
    if (entry === undefined) {
      return;
    }
    this.sessions.delete(sessionId);
    void entry.server.close().catch(() => undefined);
  }

  /**
   * Releases every remote session. Used by gateway shutdown and server stop, so
   * a stopped process holds no live transport.
   *
   * Every admission still held by an outstanding HTTP exchange is released here
   * as well: a hard stop may end a long-lived GET SSE stream without ever
   * delivering its response listeners, and a slot that outlived its session
   * would be a permanent leak in the ONE process-wide Layer C table.
   */
  public async closeAll(): Promise<void> {
    this.closed = true;
    for (const admission of [...this.liveAdmissions]) {
      this.liveAdmissions.delete(admission);
      admission.release();
    }
    const entries = [...this.sessions.values()];
    this.sessions.clear();
    for (const entry of entries) {
      this.deps.sessionManager.closeSession(entry.sessionId);
      await entry.server.close().catch(() => undefined);
      await entry.transport.close().catch(() => undefined);
    }
  }

  /**
   * Answers ONE application-level refusal with the shared MCP JSON-RPC envelope
   * (§25).
   *
   * `POST` replies on {@link MCP_POST_REPLY_STATUS} — the MCP application
   * channel, where the envelope carries the outcome and the status does not.
   * `GET`/`DELETE` carry no JSON-RPC request, so they reply on
   * {@link MCP_STREAM_REPLY_STATUS}, the status the installed SDK itself uses
   * for a stream request it cannot serve. Neither is the Layer B transport
   * model: there is no bare 429 here and no `{code, message}` body.
   *
   * The envelope is built from the canonical `ArcError`, so the observable
   * semantic code is the frozen ARC code and the message is the frozen message,
   * with nothing else added — no limiter key, token count, retry-after, session
   * identifier, or peer identity.
   */
  private sendMcpRefusal(
    res: ServerResponse,
    method: 'POST' | 'GET' | 'DELETE',
    failure: ArcError,
    id: JsonRpcRequestId,
  ): void {
    const status = method === 'POST' ? MCP_POST_REPLY_STATUS : MCP_STREAM_REPLY_STATUS;
    this.send(res, status, mcpAdmissionErrorBody(failure, id));
  }

  /** Bounded, non-secret refusal. Never carries peer-supplied text. */
  private send(
    res: ServerResponse,
    statusCode: number,
    body: string,
    extraHeaders: Record<string, string> = {},
  ): void {
    if (res.headersSent || res.writableEnded) {
      res.destroy();
      return;
    }
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      Connection: 'close',
      ...extraHeaders,
    });
    res.end(body);
  }
}
