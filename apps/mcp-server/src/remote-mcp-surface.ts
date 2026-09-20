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
 * - ONE session authority. The session ID generator is Task-5's
 *   `SessionManager.createSessionIdGenerator()`, so every `Mcp-Session-Id` is a
 *   reserved server-issued identifier and there is no second authority.
 * - ONE registry, bounded by the frozen global session capacity, keyed by the
 *   server-issued `Mcp-Session-Id`. There is no shadow session ID.
 * - Identity is the gateway-derived SPKI pin and the ACTIVE enrolled device
 *   behind it. No JSON field, tool parameter, `Host`, `Origin`, `X-Forwarded-*`,
 *   or client-supplied session identifier is ever an identity input.
 * - Every refusal is the same bounded, non-secret body; nothing here discloses
 *   whether a session, device, or revocation exists.
 * - The SDK's deprecated `allowedHosts`, `allowedOrigins`, and
 *   `enableDnsRebindingProtection` options are NOT used: §10/§11 require ARC's
 *   own gateway-side validation, which runs before the SDK sees the request.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  ARC_SESSION_TOKEN_HEADER,
  MAX_ACTIVE_SESSIONS_GLOBAL,
  type SessionManager,
  type TrustedSessionIdentity,
} from '@cesspace-arc/auth';
import type { RemoteExecutionBridge } from './remote-execution.js';
import {
  MAX_REMOTE_BODY_BYTES,
  RequestBodyError,
  readBoundedRequestBody,
} from './remote-request-bounds.js';

/** §10: the request did not present the configured public hostname. */
export const HOST_REFUSED_BODY = JSON.stringify({ error: 'Forbidden' });

/**
 * §11: every request carrying an `Origin` header is refused by default.
 *
 * Baseline has no browser origin trust model at all, so the `Origin` value is
 * never parsed, never compared against a list, and never reflected. The body is
 * byte-identical to the Host refusal, so a caller cannot use the response to
 * tell "browser origin" from "wrong host".
 */
export const ORIGIN_REFUSED_BODY = HOST_REFUSED_BODY;

/** §7 pre-session refusal. Byte-identical to the Task-4 deny-only placeholder. */
export const UNAUTHENTICATED_BODY = JSON.stringify({
  code: 'UNAUTHENTICATED',
  message: 'Authentication failed',
});

/** §7 post-session refusal. Generic; never names the cause. */
export const INVALID_SESSION_TOKEN_BODY = JSON.stringify({
  code: 'INVALID_SESSION_TOKEN',
  message: 'Invalid or expired session token',
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
  bridge: RemoteExecutionBridge;
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
 * True when a value holds any C0 control character or DEL.
 *
 * Written as an explicit code-point scan rather than a control-character
 * regular expression, so the check is plainly readable and needs no lint
 * suppression.
 */
function hasControlCharacters(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/**
 * Normalizes a `Host` header to a bare lowercase hostname, or null when the
 * value cannot be a single well-formed host.
 *
 * A port is allowed and ignored: the listener's port is not a security boundary,
 * and testing and production bind different ones. An IPv6 literal keeps its
 * brackets stripped. Whitespace, control characters, and comma-separated
 * multiple values are refused outright rather than parsed, so a malformed or
 * smuggled `Host` fails closed instead of being reinterpreted.
 */
export function normalizeHostHeader(raw: unknown): string | null {
  if (typeof raw !== 'string') {
    return null;
  }
  const value = raw.trim();
  if (
    value.length === 0 ||
    /\s/.test(value) ||
    hasControlCharacters(value) ||
    value.includes(',')
  ) {
    return null;
  }
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    if (end === -1) {
      return null;
    }
    const rest = value.slice(end + 1);
    if (rest.length > 0 && !/^:\d+$/.test(rest)) {
      return null;
    }
    return value.slice(1, end).toLowerCase();
  }
  const colon = value.indexOf(':');
  if (colon === -1) {
    return value.toLowerCase();
  }
  if (!/^\d+$/.test(value.slice(colon + 1))) {
    return null;
  }
  return value.slice(0, colon).toLowerCase();
}

/**
 * True when the request is a JSON-RPC `initialize` request.
 *
 * Mirrors the SDK's own classification: a batch counts when ANY member is an
 * `initialize`, because that is exactly the case the SDK treats as session
 * establishment. This decides only which admission question to ask Task 5; it
 * establishes nothing by itself, and a request merely CLAIMING to be
 * `initialize` still has to satisfy `admitRequest` to reach the transport.
 */
function isInitializeRequest(body: unknown): boolean {
  const isOne = (message: unknown): boolean =>
    typeof message === 'object' &&
    message !== null &&
    (message as { method?: unknown }).method === 'initialize';
  if (Array.isArray(body)) {
    return body.some(isOne);
  }
  return isOne(body);
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
 * and cannot be confused between two concurrent calls on one session. A missing
 * or malformed context returns null and the caller must fail closed.
 */
export function readRemoteRequestContext(
  authInfo: AuthInfo | undefined,
): RemoteRequestContext | null {
  const extra = authInfo?.extra;
  if (extra === undefined || extra === null) {
    return null;
  }
  const { spkiPin, presentedSessionId, authorizationHeader } = extra as Record<string, unknown>;
  if (typeof spkiPin !== 'string' || spkiPin.length === 0) {
    return null;
  }
  const sessionId = typeof presentedSessionId === 'string' ? presentedSessionId : null;
  const authorization = typeof authorizationHeader === 'string' ? authorizationHeader : null;
  return { spkiPin, presentedSessionId: sessionId, authorizationHeader: authorization };
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

    // §10 Host validation — BEFORE any MCP parsing or session work. The check
    // reads only the `Host` header Node's parser produced; `X-Forwarded-Host`
    // and every other forwarding header is never consulted, because ARC has no
    // reverse-proxy trust model and a forwarded address must not be able to
    // substitute for the real one.
    if (normalizeHostHeader(req.headers.host) !== this.deps.publicHostname.toLowerCase()) {
      this.send(res, 403, HOST_REFUSED_BODY);
      return;
    }

    // §11 Origin default-deny — also before MCP parsing and session work. The
    // value is not parsed, not compared, and never echoed: ARC emits no
    // `Access-Control-Allow-Origin` on any response, so no browser origin is
    // ever granted access and no preflight can be satisfied.
    if (req.headers.origin !== undefined) {
      this.send(res, 403, ORIGIN_REFUSED_BODY);
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

    const presentedSessionId = readSingleHeader(req, 'mcp-session-id');
    const authorizationHeader = readSingleHeader(req, 'authorization');
    const existing =
      presentedSessionId !== null ? this.sessions.get(presentedSessionId) : undefined;
    const kind =
      parsedBody !== undefined && isInitializeRequest(parsedBody) ? 'initialize' : 'ordinary';

    const decision = this.deps.sessionManager.admitRequest({
      kind,
      hasExistingSessionContext: existing !== undefined,
      presentedSessionId,
      authorizationHeader,
      identity,
    });

    if (decision.outcome === 'BOOTSTRAP_TOKENLESS') {
      await this.bootstrapSession(req, res, spkiPin, decision.identity, parsedBody);
      return;
    }

    if (decision.outcome !== 'AUTHENTICATED') {
      this.send(
        res,
        401,
        decision.outcome === 'INVALID_SESSION_TOKEN'
          ? INVALID_SESSION_TOKEN_BODY
          : UNAUTHENTICATED_BODY,
      );
      return;
    }

    // Authenticated. The registry must agree with the session authority; if it
    // somehow does not, this fails closed as a generic session failure rather
    // than serving a request whose transport binding cannot be proven.
    const entry = this.sessions.get(decision.session.sessionId);
    if (entry === undefined) {
      this.send(res, 401, INVALID_SESSION_TOKEN_BODY);
      return;
    }

    await this.dispatch(
      res,
      entry,
      req,
      {
        spkiPin,
        presentedSessionId: decision.session.sessionId,
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

    const decision = this.deps.sessionManager.admitRequest({
      kind: 'ordinary',
      hasExistingSessionContext:
        presentedSessionId !== null && this.sessions.has(presentedSessionId),
      presentedSessionId,
      authorizationHeader,
      identity,
    });

    if (decision.outcome !== 'AUTHENTICATED') {
      // §12: no unauthenticated stream may be opened, and §13: no session may be
      // terminated on unproven credentials. Distinguishing pre-session from
      // post-session here would disclose whether a session ID exists, so the
      // pre-session case stays uniformly `UNAUTHENTICATED` and only a request
      // that actually presented a session context gets the session failure.
      const preSession = decision.outcome !== 'INVALID_SESSION_TOKEN';
      this.send(res, 401, preSession ? UNAUTHENTICATED_BODY : INVALID_SESSION_TOKEN_BODY);
      return;
    }

    const entry = this.sessions.get(decision.session.sessionId);
    if (entry === undefined) {
      this.send(res, 401, INVALID_SESSION_TOKEN_BODY);
      return;
    }

    await this.dispatch(
      res,
      entry,
      req,
      {
        spkiPin,
        presentedSessionId: decision.session.sessionId,
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
   * tool handler routes into the existing `RemoteExecutionBridge`.
   */
  private async dispatch(
    res: ServerResponse,
    entry: RemoteSessionEntry,
    req: IncomingMessage,
    context: RemoteRequestContext,
    parsedBody: unknown,
    method: 'POST' | 'GET' | 'DELETE' = 'POST',
  ): Promise<void> {
    const sessionId = entry.transport.sessionId;
    if (sessionId !== undefined && !this.deps.sessionManager.hasSession(sessionId)) {
      // Expiry or revocation observed on a live transport: drop the binding
      // immediately so the registry cannot outlive the session it names.
      await this.discard(sessionId);
      this.send(res, 401, INVALID_SESSION_TOKEN_BODY);
      return;
    }

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
      // binding is torn down rather than left half-alive.
      if (method === 'DELETE' && sessionId !== undefined) {
        await this.discard(sessionId);
      }
      if (!res.headersSent && !res.writableEnded) {
        res.destroy();
      }
    }
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
  ): Promise<void> {
    if (this.sessions.size >= MAX_ACTIVE_SESSIONS_GLOBAL) {
      this.send(res, 401, UNAUTHENTICATED_BODY);
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
   */
  public async closeAll(): Promise<void> {
    this.closed = true;
    const entries = [...this.sessions.values()];
    this.sessions.clear();
    for (const entry of entries) {
      this.deps.sessionManager.closeSession(entry.sessionId);
      await entry.server.close().catch(() => undefined);
      await entry.transport.close().catch(() => undefined);
    }
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
