/**
 * CesSpace ARC — RC-05 Task 3 TLS 1.3 / mTLS Admission Gateway
 *
 * Terminates TLS 1.3 in-process, requires a client certificate chained to a
 * configured trust root, derives the canonical peer SPKI pin, and admits the
 * connection. It does NOT speak MCP, does NOT issue sessions, and does NOT
 * decide device authorization: those belong to Tasks 5 and beyond.
 *
 * Authoritative contract: §5, §6 (T-1..T-11), §7 P-1..P-3, §18, §19, §20, §21.1.
 *
 * Since Task 4 the listener is a Node HTTPS server rather than a raw TLS
 * server, because `POST /enroll/complete` is the first HTTP surface. That
 * change is deliberately invisible to the Task-3 properties it must preserve:
 *
 * - `https.createServer` IS a `tls.Server`; the same TLS options, the same
 *   `connection` / `secureConnection` / `tlsClientError` lifecycle, and the
 *   same raw-socket-before-TLS ordering are used here unchanged.
 * - `rejectUnauthorized: true` means a connection without a CA-valid client
 *   certificate fails the handshake itself, so the HTTP parser is never handed
 *   the socket and no request listener can run (§20/T-8, RC05-NEG-30).
 * - The request listener therefore runs only AFTER an authenticated mTLS
 *   handshake, and it resolves the peer identity from the admission registry
 *   rather than re-deriving it.
 */

import * as https from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Server, TLSSocket } from 'node:tls';
import { deriveSpkiPin, EnrollmentManager } from '@cesspace-arc/auth';
import { DeviceTrustStore } from '@cesspace-arc/auth';
import type { TrustedSessionIdentity } from '@cesspace-arc/auth';
import {
  isWildcardBindHost,
  resolveRemoteConfig,
  TLS_HANDSHAKE_TIMEOUT_MS,
  type RemoteConfig,
  type ResolvedRemoteConfig,
} from './remote-config.js';
import {
  assertKeyMatchesCertificate,
  loadClientCaRoots,
  loadServerCertificate,
  loadServerPrivateKey,
  type ServerCertificateFacts,
} from './tls-material.js';
import { RemoteConfigError } from './remote-errors.js';
import {
  ENROLL_COMPLETE_PATH,
  EnrollmentBootstrap,
  MCP_PATH,
  type EnrollmentBootstrapOptions,
} from './enrollment-bootstrap.js';
import { checkRequestAuthority, writeAuthorityRefusal } from './remote-request-authority.js';
import type { RemoteMcpSurface } from './remote-mcp-surface.js';
import type { DeviceTrustAuthority } from './device-administration.js';
import { getGatewayAuditSink, type GatewayAuditSink } from './gateway-audit.js';
import type { AuditLogger } from '@cesspace-arc/audit';
import {
  AdmissionLimiter,
  type AdmissionLimiterOptions,
  type AdmissionRefusalReason,
} from './admission-limiter.js';
import {
  BoundedRequestLimiter,
  LAYER_B_BURST,
  LAYER_B_REQUESTS_PER_MINUTE,
  MAX_LAYER_B_KEYS,
  normalizePeerNetwork,
} from './remote-resource-limits.js';
import {
  MAX_REQUEST_HEADER_BYTES,
  MAX_REQUEST_TARGET_BYTES,
  TOTAL_REQUEST_TIMEOUT_MS,
  hasContentEncoding,
  requestTargetBytes,
  resolveHeaderReadCheckIntervalMs,
  resolveHeaderReadTimeoutMs,
} from './remote-request-bounds.js';

/**
 * Bounded, non-secret remote gateway state.
 *
 * Contains no certificate bytes, no key material, no file paths, no SPKI pins,
 * no peer addresses, and no trust-store path.
 */
export interface RemoteGatewayStatus {
  transportMode: 'stdio' | 'remote';
  /** True while the TCP/TLS listener is physically bound. */
  listenerActive: boolean;
  /** True only when the bound listener can actually serve a new session. */
  activeAndServing: boolean;
  /** True when the gateway is running but cannot admit new sessions. */
  degraded: boolean;
  /** Bounded reason for degradation. Absent when healthy. */
  degradedReason?: 'certificate_expired';
  /** Live admitted connections. */
  liveConnections: number;
  /** TLS handshakes currently in progress. */
  inFlightHandshakes: number;
}

/**
 * Authenticated TLS identity handed to later gateway layers.
 *
 * Task 3 stops here: it proves a valid chain and yields the canonical SPKI pin.
 * Whether that pin is enrolled, pending, revoked, or permitted to open a session
 * is decided by later tasks, which is why this context carries no authorization
 * decision and no error is returned for an unknown pin.
 */
export interface PeerAdmissionContext {
  /** Canonical SPKI pin of the presented client certificate (§7 P-4/P-5). */
  spkiPin: string;
  /** Peer TLS socket. Later tasks own everything that happens on it. */
  socket: TLSSocket;
}

/**
 * Internal seams.
 *
 * These exist for deterministic tests and are deliberately NOT reachable from
 * the production ArcServerConfig/RemoteConfig surface: no configuration can
 * weaken the frozen security values.
 */
export interface RemoteGatewayOptions {
  /** Wall clock used for certificate-validity decisions. */
  getWallTime?: () => number;
  /**
   * Test-only handshake timeout. Production always uses the frozen
   * {@link TLS_HANDSHAKE_TIMEOUT_MS}; this seam may only SHORTEN it, and is
   * ignored when it would lengthen the frozen value.
   */
  handshakeTimeoutMsForTests?: number;
  /** Layer A limiter overrides. */
  admission?: AdmissionLimiterOptions;
  /**
   * @internal Test-only Layer A limiter injection.
   *
   * Replaces the internally constructed limiter so a test can observe the exact
   * peer keys admission bucketed on. Never populated from ArcServerConfig,
   * RemoteConfig, the environment, or a request.
   */
  admissionLimiterForTests?: AdmissionLimiter;
  /**
   * @internal Test-only Layer B limiter injection, for a deterministic clock and
   * for direct observation of pre-session refusals. Never populated from
   * configuration, the environment, or a request.
   */
  layerBLimiterForTests?: BoundedRequestLimiter;
  /**
   * @internal Test-only body-read deadline. May only SHORTEN the frozen 10 s.
   * Never populated from configuration, the environment, or a request.
   */
  bodyReadTimeoutMsForTests?: number;
  /**
   * @internal Test-only total-request deadline. May only SHORTEN the frozen 60 s.
   * Never populated from configuration, the environment, or a request.
   */
  totalRequestTimeoutMsForTests?: number;
  /**
   * @internal Test-only header-read deadline. May only SHORTEN the frozen 10 s.
   * Never populated from configuration, the environment, or a request.
   */
  headerReadTimeoutMsForTests?: number;
  /**
   * The pending-enrollment authority used by `POST /enroll/complete`.
   *
   * Production composition (`createArcMcpServer`) supplies the EXACT SAME
   * instance that the authenticated local admin IPC channel writes to, so a
   * challenge an operator creates locally is immediately visible to a remote
   * completion. Pending challenges stay volatile and are never persisted, and
   * this option is not reachable from RemoteConfig, the environment, or the
   * network.
   *
   * `ArcMcpServer` ALWAYS supplies the process-wide instance it owns, and its
   * constructor refuses to compose an admin IPC channel over a different one,
   * so a running server can never complete against a second pending table.
   *
   * When omitted — only reachable by constructing a `RemoteGateway` directly —
   * the gateway creates its own instance. That is correct for admission-only
   * tests and for a standalone gateway with no composed admin channel; it is
   * never how a composed `ArcMcpServer` behaves.
   */
  enrollmentManager?: EnrollmentManager;
  /**
   * @internal Test-only bootstrap seams (durable-write injection). Never
   * populated from ArcServerConfig, RemoteConfig, the environment, or a request.
   */
  bootstrap?: EnrollmentBootstrapOptions;
  /** Invoked once per admitted, chain-validated connection. */
  onAdmitted?: (context: PeerAdmissionContext) => void;
  /** Invoked when Layer A refuses a connection. */
  onRefused?: (reason: AdmissionRefusalReason) => void;
  /**
   * The ONE audit chain every gateway lifecycle event is committed to (rc05 §24).
   *
   * Production composition (`ArcMcpServer.start`) ALWAYS supplies the process-wide
   * `AuditLogger`, so `GATEWAY_STARTED`, `GATEWAY_STOPPED`, `AUTH_FAILED`,
   * `RATE_LIMITED`, and `REMOTE_DISCONNECTED` are emitted at the real lifecycle
   * transitions and share the chain that already carries ordinary MCP and RC-04
   * approval records.
   *
   * When omitted — only reachable by constructing a `RemoteGateway` directly —
   * the gateway emits nothing. That is correct for an admission-only unit test
   * with no audit chain to write to; it is never how a composed `ArcMcpServer`
   * behaves, and this option is not reachable from RemoteConfig, the
   * environment, or a request.
   */
  auditLogger?: AuditLogger;
}

interface ConnectionState {
  /** The exact admission slot held by this connection. */
  release: () => void;
  /** The raw socket accepted before any TLS work. Always present. */
  rawSocket: TLSSocket;
  /** The TLS socket, once the handshake has produced one. */
  tlsSocket?: TLSSocket;
  /**
   * Canonical SPKI pin, set exactly once at post-handshake admission.
   *
   * Routing reads the identity from HERE rather than re-deriving it per
   * request: the pin the endpoint verifies is the pin the TLS handshake
   * proved, and there is no second derivation that could disagree.
   */
  spkiPin?: string;
  handshakeSettled: boolean;
  connectionSettled: boolean;
}

/**
 * Stable identity for one open TCP connection, built only from documented
 * socket properties. Two simultaneously open connections cannot share a tuple.
 */
function connectionTuple(socket: {
  localAddress?: string;
  localPort?: number;
  remoteAddress?: string;
  remotePort?: number;
}): string {
  return `${socket.localAddress ?? ''}:${socket.localPort ?? 0}|${socket.remoteAddress ?? ''}:${socket.remotePort ?? 0}`;
}

/** Maximum time to wait for `close()` to settle during shutdown. */
const SHUTDOWN_GRACE_MS = 2000;

/** Sanitized plaintext Layer B refusal (§21.1 Layer B). No MCP body, no detail. */
const RATE_LIMITED_BODY = 'Too Many Requests\n';

/** Sanitized refusal for a request target beyond the frozen 2 KiB bound (§20). */
const REQUEST_TARGET_TOO_LONG_BODY = 'URI Too Long\n';

/** Sanitized refusal for a compressed request, which baseline does not support (§20). */
const UNSUPPORTED_ENCODING_BODY = 'Payload Too Large\n';

export class RemoteGateway {
  private readonly config: ResolvedRemoteConfig;
  private readonly getWallTime: () => number;
  /**
   * Resolved TLS handshake timeout in milliseconds.
   *
   * Always the frozen {@link TLS_HANDSHAKE_TIMEOUT_MS} in production; only the
   * internal test seam may resolve it lower.
   */
  public readonly handshakeTimeoutMs: number;
  /**
   * Resolved total request deadline in milliseconds.
   *
   * Always the frozen {@link TOTAL_REQUEST_TIMEOUT_MS} in production; only the
   * internal test seam may resolve it lower. Distinct from the 5 s TLS handshake
   * deadline and the 10 s body-read deadline.
   */
  public readonly totalRequestTimeoutMs: number;
  /**
   * Resolved header-read deadline in milliseconds.
   *
   * Always the frozen 10 s header-read bound in production; only the internal
   * test seam may resolve it lower. This is the slowloris bound for the HEADER
   * phase and is enforced by the HTTP parser before any handler runs, so an
   * incomplete header block is aborted at 10 s rather than being carried toward
   * the 60 s total request deadline.
   */
  public readonly headerReadTimeoutMs: number;
  /**
   * Sweep granularity Node uses to enforce {@link headerReadTimeoutMs}.
   *
   * Always at most the frozen 1 s, and never longer than the resolved deadline.
   * `headersTimeout` is evaluated by a periodic connections checker rather than a
   * per-socket timer, so without this the frozen 10 s would be enforced at Node's
   * default 30 s sweep instead. It bounds the OVERSHOOT, never the deadline.
   */
  public readonly headerReadCheckIntervalMs: number;
  private readonly limiter: AdmissionLimiter;
  /**
   * Layer B: the secure HTTP pre-session limiter (§21.1 Layer B).
   *
   * Keyed on the NORMALIZED peer network — the same canonical key Layer A uses —
   * so a peer cannot buy a second pre-session budget by presenting an
   * IPv4-mapped or re-spelled address.
   */
  private readonly layerB: BoundedRequestLimiter;
  private readonly options: RemoteGatewayOptions;
  /**
   * The gateway's enrollment bootstrap surface.
   *
   * Created once, in the constructor, over the trust store loaded from the
   * REQUIRED `trustStorePath`. It owns the authoritative in-memory trust store
   * for the process lifetime, so a completed enrollment is visible to every
   * later request without re-reading the file.
   */
  private readonly bootstrap: EnrollmentBootstrap;
  /**
   * The composed Streamable HTTP MCP surface, once Task 8 attaches one.
   *
   * Held so shutdown can release every remote session. `undefined` means no
   * transport is composed and `/mcp` remains deny-only.
   */
  private mcpSurface?: RemoteMcpSurface;
  /**
   * The gateway lifecycle audit sink, when an audit chain was composed in.
   *
   * Memoized per `AuditLogger`, so the gateway, the MCP surface, the enrollment
   * bootstrap, and the local admin channel all write through ONE sink into ONE
   * chain and no lifecycle transition can be recorded twice.
   */
  private readonly audit?: GatewayAuditSink;

  /** Server key material, held only until the listener consumes it. */
  private privateKeyMaterial?: ReturnType<typeof loadServerPrivateKey>;
  private server?: Server;
  private facts?: ServerCertificateFacts;
  private started = false;
  private degradedReason?: 'certificate_expired';
  /** Terminal latch: once the certificate is seen expired it stays expired. */
  private expiryLatched = false;
  /**
   * THE authoritative registry of active admitted connections, keyed by the TCP
   * connection tuple.
   *
   * The raw socket seen in `connection` and the TLSSocket seen in
   * `secureConnection` are DIFFERENT objects, so state cannot be keyed by either
   * one. The tuple (localAddress:localPort|remoteAddress:remotePort) is made of
   * public properties, is identical for both objects, and uniquely identifies a
   * connection while it is open.
   *
   * This is the ONLY collection that holds admitted sockets. An entry is created
   * on raw admission and deleted on settlement, so the map is bounded by the
   * global live-connection cap: there is no second collection that could retain
   * a closed socket after its counters were released.
   */
  private readonly connectionStates = new Map<string, ConnectionState>();

  constructor(config: RemoteConfig, options: RemoteGatewayOptions = {}) {
    this.options = options;
    this.getWallTime = options.getWallTime ?? (() => Date.now());
    const requestedTimeout = options.handshakeTimeoutMsForTests;
    this.handshakeTimeoutMs =
      typeof requestedTimeout === 'number' &&
      Number.isInteger(requestedTimeout) &&
      requestedTimeout > 0 &&
      requestedTimeout < TLS_HANDSHAKE_TIMEOUT_MS
        ? requestedTimeout
        : TLS_HANDSHAKE_TIMEOUT_MS;
    const requestedTotalTimeout = options.totalRequestTimeoutMsForTests;
    this.totalRequestTimeoutMs =
      typeof requestedTotalTimeout === 'number' &&
      Number.isInteger(requestedTotalTimeout) &&
      requestedTotalTimeout > 0 &&
      requestedTotalTimeout < TOTAL_REQUEST_TIMEOUT_MS
        ? requestedTotalTimeout
        : TOTAL_REQUEST_TIMEOUT_MS;
    // §20/RC05-NEG-61: the HEADER phase has its own frozen 10 s slowloris bound,
    // resolved through the shared shorten-only rule so it can never be widened.
    this.headerReadTimeoutMs = resolveHeaderReadTimeoutMs(options.headerReadTimeoutMsForTests);
    // The sweep is derived from the RESOLVED deadline, so a shortened test seam
    // is enforced promptly instead of waiting out the production sweep.
    this.headerReadCheckIntervalMs = resolveHeaderReadCheckIntervalMs(this.headerReadTimeoutMs);
    this.limiter =
      options.admissionLimiterForTests ?? new AdmissionLimiter(options.admission ?? {});
    this.layerB =
      options.layerBLimiterForTests ??
      new BoundedRequestLimiter({
        requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
        burst: LAYER_B_BURST,
        maxKeys: MAX_LAYER_B_KEYS,
      });

    // Everything below runs BEFORE a listener exists. Any rejection propagates
    // out of the constructor, so a failed startup cannot leave a bound socket.
    this.config = resolveRemoteConfig(config);

    // The device trust store is a REQUIRED remote authentication root, resolved
    // by `resolveRemoteConfig` already. Reuse the Task-1 loader verbatim: no
    // second trust-store parser exists. A corrupt, missing, symlinked, or
    // insecurely-permissioned store fails startup, while a store that is valid
    // but holds zero devices is explicitly allowed — that is the first
    // enrollment case (§5.2, §16.1, §18).
    let trustStore: DeviceTrustStore;
    try {
      trustStore = DeviceTrustStore.loadFromFile(this.config.trustStorePath);
    } catch (err: unknown) {
      throw new RemoteConfigError(
        'Configured device trust store failed validation.',
        'TRUST_STORE_INVALID',
        // Preserve the underlying reason for the operator without exposing it.
        { cause: err },
      );
    }

    this.bootstrap = new EnrollmentBootstrap(
      options.enrollmentManager ?? new EnrollmentManager(),
      trustStore,
      this.config.trustStorePath,
      {
        ...(options.bootstrap ?? {}),
        // The gateway-level seam, when supplied, is the one the transport uses;
        // both are internal and neither is reachable from configuration.
        ...(options.bodyReadTimeoutMsForTests === undefined
          ? {}
          : { bodyReadTimeoutMsForTests: options.bodyReadTimeoutMsForTests }),
      },
    );
    // The bootstrap owns the remote enrollment completion path, so it is the
    // only object that can witness `DEVICE_ENROLLED` and a rejected completion.
    // It writes through the SAME sink the gateway holds, into the same chain.
    this.audit =
      options.auditLogger === undefined ? undefined : getGatewayAuditSink(options.auditLogger);
    if (this.audit !== undefined) {
      this.bootstrap.attachGatewayAudit(this.audit);
    }

    const keyMaterial = loadServerPrivateKey(this.config.privateKey);
    try {
      const facts = loadServerCertificate(
        this.config.serverCertificatePath,
        this.config.publicHostname,
        this.getWallTime,
      );
      assertKeyMatchesCertificate(keyMaterial.key, facts.certificate);
      this.facts = facts;
    } catch (err: unknown) {
      keyMaterial.pem.fill(0);
      throw err;
    }
    this.privateKeyMaterial = keyMaterial;
  }

  /**
   * Attaches the Task-8 Streamable HTTP MCP surface to the `/mcp` route.
   *
   * MUST be called before `start()`. The gateway delegates `/mcp` to the surface
   * only once it is attached, so the composition is complete before the listener
   * can accept a request and there is no window in which `/mcp` is reachable
   * without its transport. Attaching after the listener is bound is refused
   * rather than accepted, so a late attach cannot change reachability at runtime.
   */
  public attachMcpSurface(surface: RemoteMcpSurface): void {
    if (this.started) {
      throw new Error('The MCP surface must be attached before the gateway starts.');
    }
    this.mcpSurface = surface;
    this.bootstrap.attachMcpSurface(surface);
  }

  /**
   * The device trust authority for RC-05 Task 9 local operator administration.
   *
   * Returns a NARROWED capability over the gateway's own `EnrollmentBootstrap`:
   * the durable-transaction primitive and the frozen device-record snapshot.
   * The raw mutable `DeviceTrustStore` is NOT exposed and neither is anything
   * that could re-attach a transport, so the composed administration facade can
   * only ever act on the SAME authoritative trust state every remote admission
   * decision reads. Storage-latch state is reported through the mutation
   * outcome rather than as a separate accessor.
   */
  public getDeviceTrustAuthority(): DeviceTrustAuthority {
    return this.bootstrap;
  }

  /** Starts the TLS listener. Resolves once it is bound and accepting. */
  public async start(): Promise<void> {
    if (this.started) {
      throw new RemoteConfigError('Remote gateway is already started.', 'GATEWAY_ALREADY_STARTED');
    }

    const caRoots = loadClientCaRoots(this.config.clientCaPaths);
    // The EXACT bytes validated in the constructor, never a re-read of the
    // configured path: a file replaced after validation must not be served.
    const certificatePem = this.facts?.pem;
    if (certificatePem === undefined) {
      throw new RemoteConfigError(
        'Server certificate material is unavailable.',
        'SERVER_CERTIFICATE_UNREADABLE',
      );
    }

    const keyMaterial = this.privateKeyMaterial;
    if (keyMaterial === undefined) {
      throw new RemoteConfigError('Server private key is unavailable.', 'PRIVATE_KEY_UNREADABLE');
    }

    let server: Server;
    try {
      server = https.createServer(
        {
          // §6 T-1: exactly TLS 1.3. No compatibility version, no fallback.
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          // §7 P-1: mTLS is mandatory.
          requestCert: true,
          rejectUnauthorized: true,
          ca: caRoots,
          cert: certificatePem,
          key: keyMaterial.pem,
          // §20: a stalled handshake must not hold a slot indefinitely. The
          // test seam may only SHORTEN the frozen value.
          handshakeTimeout: this.handshakeTimeoutMs,
          // §20: the header block and the request-receipt window are bounded at
          // the PARSER, so an oversized header block never reaches a handler and
          // no second copy of the headers is made in order to measure them.
          // Node answers an over-long header block itself and destroys the
          // socket, which is exactly the required refusal.
          maxHeaderSize: MAX_REQUEST_HEADER_BYTES,
          // §20: the WHOLE request — parser, routing, and handler — is bounded
          // by the frozen 60 s total request deadline.
          requestTimeout: TOTAL_REQUEST_TIMEOUT_MS,
          // §20/RC05-NEG-61: the HEADER phase is bounded separately and far more
          // tightly. `headersTimeout` is evaluated by the HTTP parser while the
          // header block is still incomplete, so a trickled request line or a
          // never-terminated header block is refused and its socket destroyed
          // without ever reaching a handler. It can never be carried toward the
          // 60 s total deadline. Node requires `headersTimeout <= requestTimeout`.
          headersTimeout: this.headerReadTimeoutMs,
          // §20/RC05-NEG-61: `headersTimeout` alone does NOT abort at its own
          // value — Node evaluates it from a periodic sweep, whose default 30 s
          // interval would let a stalled header block outlive the frozen 10 s
          // bound several times over. Supplying the sweep interval is what makes
          // the 10 s real; the abort lands at the deadline plus at most one
          // sweep. This is a check granularity, never a deadline: it cannot
          // extend the bound, and it also tightens the 60 s requestTimeout
          // backstop above.
          connectionsCheckingInterval: this.headerReadCheckIntervalMs,
        },
        (req: IncomingMessage, res: ServerResponse) => {
          // Reached ONLY after a completed, CA-validated mTLS handshake: with
          // `rejectUnauthorized: true` an unauthenticated peer never produces a
          // TLSSocket for the HTTP parser to attach to. Routing is therefore
          // structurally unreachable without mTLS.
          this.handleRequest(req, res);
        },
      );
    } finally {
      // `createServer` builds the secure context synchronously, so ARC's own
      // copy of the key bytes is no longer needed. Best-effort overwrite only;
      // this is not a claim of cryptographic zeroization.
      keyMaterial.pem.fill(0);
      this.privateKeyMaterial = undefined;
    }

    server.on('connection', (socket) => this.handleConnection(socket));
    server.on('tlsClientError', (_err, socket) => this.handleHandshakeFailure(socket as TLSSocket));
    server.on('secureConnection', (socket) => this.handleSecureConnection(socket));
    server.on('error', () => {
      // Listener-level errors are surfaced through close/start failure paths; a
      // per-connection error must not take the gateway down silently.
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error) => {
          server.removeListener('listening', onListening);
          reject(err);
        };
        const onListening = () => {
          server.removeListener('error', onError);
          resolve();
        };
        server.once('error', onError);
        server.once('listening', onListening);
        // Literal bind semantics: an explicitly opted-in IPv6 wildcard must not
        // silently broaden into an unintended dual-stack IPv4 listener.
        server.listen({
          host: this.config.bindHost,
          port: this.config.port,
          ...(isWildcardBindHost(this.config.bindHost) && this.config.bindHost.includes(':')
            ? { ipv6Only: true }
            : {}),
        });
      });
    } catch (err: unknown) {
      // Leave nothing half-open.
      try {
        server.close();
      } catch {
        // ignore
      }
      throw new RemoteConfigError('Remote TLS listener could not bind.', 'LISTENER_BIND_FAILED', {
        cause: err,
      });
    }

    this.server = server;
    this.started = true;

    // §24 GATEWAY_STARTED: emitted only HERE, once the listener has actually
    // bound and is serving. Every failure path above — invalid configuration, an
    // unreadable certificate or key, a rejected trust store, a TLS startup
    // failure, and a bind failure — throws before this line, so none of them can
    // emit a start event, and no listener is left bound.
    //
    // The record carries the transport mode and nothing about the socket, the
    // bind address, the certificate, the key, the client CA, or the trust-store
    // path.
    this.audit?.emit({ eventType: 'GATEWAY_STARTED', transportMode: 'remote' });
  }

  /** True once the listener is bound and serving. */
  public isStarted(): boolean {
    return this.started;
  }

  /** The port actually bound, useful when tests request port 0 semantics. */
  public getBoundPort(): number | undefined {
    const address = this.server?.address();
    if (address === null || address === undefined || typeof address === 'string') {
      return undefined;
    }
    return address.port;
  }

  /**
   * Bounded, non-secret gateway status (§19, §6 T-7).
   *
   * Never contains certificate bytes, key bytes, file paths, SPKI pins, peer
   * addresses, or the trust-store path.
   */
  public getStatus(): RemoteGatewayStatus {
    // The degraded state is COMPUTED from the injected clock on every call, so
    // it becomes truthful the moment the certificate reaches notAfter even if
    // no further connection is ever attempted.
    const degraded = this.isServerCertificateExpiredOrLatched();
    return {
      transportMode: 'remote',
      listenerActive: this.started,
      degraded,
      // A physically bound listener whose certificate has expired is NOT
      // serving new sessions, so it is reported inactive for health purposes.
      activeAndServing: this.started && !degraded,
      ...(degraded ? { degradedReason: 'certificate_expired' as const } : {}),
      liveConnections: this.limiter.getLiveConnectionCount(),
      inFlightHandshakes: this.limiter.getInFlightHandshakeCount(),
    };
  }

  /** Stops the listener and drops every live connection. */
  public async stop(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    this.started = false;

    // 0. Release every composed remote MCP session first: each one holds an SDK
    //    transport, an MCP server, and a gateway session, and none of them may
    //    outlive the listener. The sessions are volatile by construction, so
    //    this is the same teardown a process restart performs implicitly.
    await this.mcpSurface?.closeAll();

    // 1. Stop accepting new connections first, so nothing new can be admitted
    //    while the existing state is being torn down.
    if (server !== undefined) {
      try {
        server.close();
      } catch {
        // Already closed; teardown continues.
      }
    }

    // 2. Capture both sockets of every outstanding connection BEFORE settling.
    //    The registry holds every admitted socket, handshaken or not, so a
    //    socket still mid-handshake cannot survive until its TLS timeout.
    const outstanding = [...this.connectionStates.entries()].map(([tuple, state]) => ({
      tuple,
      sockets: [state.rawSocket, state.tlsSocket].filter(
        (candidate): candidate is TLSSocket => candidate !== undefined,
      ),
    }));

    // 3. Synchronously settle every connection exactly once. This neutralizes
    //    each captured `release` closure BEFORE any counter is reset, so a late
    //    close/error/timeout callback cannot decrement a reset counter below
    //    zero: the state entry is gone and settleConnection() becomes a no-op.
    for (const { tuple } of outstanding) {
      this.settleConnection(tuple);
    }
    this.connectionStates.clear();

    // 4. Destroy every admitted socket, handshaken or not. Destroy is
    //    idempotent, so overlapping raw/TLS destruction is harmless.
    for (const { sockets } of outstanding) {
      for (const socket of sockets) {
        socket.destroy();
      }
    }
    // 5. Only now may limiter state be reset: every release closure has already
    //    run, and any that could still fire has nothing to act on.
    this.limiter.reset();
    // Layer B state is equally volatile: a restart gets a clean pre-session
    // budget, and nothing about it is ever persisted.
    this.layerB.reset();

    if (server === undefined) {
      // A second stop finds nothing tracked, nothing to destroy, and counters
      // that are already zero, so it is a structural no-op. §24 GATEWAY_STOPPED
      // is emitted past this point only, so a repeated or idempotent stop — and
      // the all-or-nothing `stop()` a failed startup performs before any
      // listener existed — can never produce a second or spurious stop event.
      return;
    }

    this.audit?.emit({ eventType: 'GATEWAY_STOPPED', transportMode: 'remote' });

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        resolve();
      }, SHUTDOWN_GRACE_MS);
      timer.unref();
      server.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });

    // Commits every buffered lifecycle event before the gateway reports itself
    // stopped, and fails closed when required evidence could not be written.
    // The queue is bounded and the drain is continuous, so this is a final
    // barrier rather than the only write opportunity; it is what makes
    // "the gateway stopped" and "the stop is recorded" inseparable.
    await this.audit?.flush();
  }

  // -------------------------------------------------------------------------
  // Layer A admission and TLS lifecycle
  // -------------------------------------------------------------------------

  /**
   * Layer A admission, running on the raw TCP connection before any TLS work.
   *
   * A refused peer is destroyed immediately: no handshake, no HTTP, no MCP.
   */
  private handleConnection(socket: TLSSocket): void {
    const tuple = connectionTuple(socket);

    // T-7: the runtime expiry gate runs BEFORE any TLS work on a NEW connection.
    // Once the server certificate has reached notAfter, no new session may be
    // established, so the raw socket is destroyed before a handshake can begin.
    // Connections admitted earlier are untouched and drain normally.
    if (this.isServerCertificateExpiredOrLatched()) {
      socket.destroy();
      return;
    }

    const peerKey = peerNetworkKeyFor(socket);
    if (peerKey === null) {
      // A peer address that is not an address at all cannot become a limiter
      // key: an attacker-supplied string must never mint a bucket.
      this.options.onRefused?.('PEER_KEY_INVALID');
      socket.destroy();
      return;
    }

    const decision = this.limiter.admit(peerKey);
    if (!decision.admitted) {
      this.options.onRefused?.(decision.reason);
      // §24 RATE_LIMITED / §21.1 Layer A. The record names the layer and nothing
      // else: no peer address, no limiter key, no bucket contents, no remaining
      // token count, no refusal reason, and no retry hint.
      this.audit?.emit({ eventType: 'RATE_LIMITED', admissionLayer: 'A' });
      socket.destroy();
      return;
    }

    // Two independent slots are held by an admitted connection:
    //  - the in-flight handshake slot, released when the handshake settles;
    //  - the live connection slot, released when the socket closes.
    const state: ConnectionState = {
      release: decision.release,
      rawSocket: socket,
      handshakeSettled: false,
      connectionSettled: false,
    };
    this.connectionStates.set(tuple, state);

    socket.once('close', () => this.settleConnection(tuple));
    socket.once('error', () => {
      socket.destroy();
    });
    socket.once('timeout', () => {
      socket.destroy();
    });
  }

  /**
   * Releases the in-flight handshake slot for a connection, exactly once.
   *
   * Called from the TLS layer when the handshake settles, looked up by the
   * connection tuple because the raw and TLS sockets are distinct objects.
   */
  private settleHandshakeFor(tuple: string): void {
    const state = this.connectionStates.get(tuple);
    if (state === undefined || state.handshakeSettled) {
      return;
    }
    state.handshakeSettled = true;
    this.limiter.releaseHandshake();
  }

  /** Releases every slot held by a connection, exactly once. */
  private settleConnection(tuple: string): void {
    const state = this.connectionStates.get(tuple);
    if (state === undefined || state.connectionSettled) {
      return;
    }
    state.connectionSettled = true;
    // A connection that closes without ever completing a handshake (timeout,
    // socket error, destroy) must still release its handshake slot.
    this.settleHandshakeFor(tuple);
    state.release();
    this.connectionStates.delete(tuple);

    // §24 REMOTE_DISCONNECTED: a "remote connection" is an AUTHENTICATED one, so
    // only a connection that reached post-handshake admission and resolved an
    // identity produces this event. It is emitted AFTER the registry entry is
    // deleted and the slot released, and appears at most once per connection
    // because `connectionSettled` was set above.
    //
    // The only identifier carried is the connection's SPKI pin — the approved
    // public-key digest of §7/§8. No socket is retained for auditing and no peer
    // address or network topology is recorded.
    if (state.spkiPin !== undefined) {
      this.audit?.emit({ eventType: 'REMOTE_DISCONNECTED', spkiPin: state.spkiPin });
    }
  }

  /**
   * Post-handshake admission.
   *
   * Reached only when the TLS handshake completed with a client certificate
   * that chained to a configured trust root, because `rejectUnauthorized` is
   * true. The identity is derived here and nowhere else.
   */
  private handleSecureConnection(socket: TLSSocket): void {
    const tuple = connectionTuple(socket);

    // A handshake that began before expiry but completed after it must still be
    // refused: the runtime check is repeated at the post-handshake boundary.
    if (this.isServerCertificateExpiredOrLatched()) {
      this.recordPostHandshakeAuthFailure(tuple);
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    const peerCertificate = socket.getPeerCertificate(true);
    if (peerCertificate === undefined || !socket.authorized || peerCertificate.raw === undefined) {
      this.recordPostHandshakeAuthFailure(tuple);
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    let spkiPin: string;
    try {
      spkiPin = deriveSpkiPin(peerCertificate.raw);
    } catch {
      this.recordPostHandshakeAuthFailure(tuple);
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    // The handshake has settled, so its slot is released now; the connection
    // remains counted as live until it closes.
    this.settleHandshakeFor(tuple);
    // Attach the TLS socket and the derived identity to the SAME registry entry
    // that already owns the admission slot. There is no separate collection to
    // keep in step, so a closed socket cannot be retained after its entry is
    // deleted, and the router has exactly one source for the peer identity.
    const state = this.connectionStates.get(tuple);
    if (state !== undefined) {
      state.tlsSocket = socket;
      state.spkiPin = spkiPin;
    }

    // Task 3 boundary: a valid chain and a canonical SPKI pin. No enrollment,
    // revocation, or session decision is made here, so an unknown pin is NOT
    // an error at this layer (Task 4 admits pending, not-yet-enrolled pins).
    this.options.onAdmitted?.({ spkiPin, socket });
  }

  /**
   * Records one post-handshake authentication refusal.
   *
   * §24 AUTH_FAILED for the TLS layer's own refusals — a certificate that
   * reached notAfter mid-handshake, a peer certificate the TLS stack would not
   * authorize, and a certificate whose SPKI cannot be derived. Bounded and
   * generic, exactly like {@link handleHandshakeFailure}, and guarded by the
   * same exactly-once flag so one connection records one refusal.
   */
  private recordPostHandshakeAuthFailure(tuple: string): void {
    const state = this.connectionStates.get(tuple);
    if (state !== undefined && !state.connectionSettled) {
      this.audit?.emit({ eventType: 'AUTH_FAILED' });
    }
  }

  /**
   * Handshake failure: record the refusal, settle the slot, drop the socket.
   *
   * §24 AUTH_FAILED, emitted ONLY for a connection this gateway admitted to the
   * TLS layer. A socket refused at Layer A never began a handshake, and its
   * refusal is already recorded as `RATE_LIMITED`.
   *
   * The record is deliberately generic: it carries no reason, no certificate,
   * no pin, no peer address, and no token, so the chain cannot be read as an
   * oracle for whether a presented certificate was unknown, unenrolled, expired,
   * revoked, or bound to a different client.
   */
  private handleHandshakeFailure(socket: TLSSocket): void {
    const tuple = connectionTuple(socket);
    const state = this.connectionStates.get(tuple);
    // `connectionSettled` is the same exactly-once guard `settleConnection`
    // applies, so a repeated TLS error for one connection cannot record two
    // AUTH_FAILED events for one failed handshake.
    if (state !== undefined && !state.connectionSettled) {
      this.audit?.emit({ eventType: 'AUTH_FAILED' });
    }
    this.settleConnection(tuple);
    socket.destroy();
  }

  // -------------------------------------------------------------------------
  // Minimal HTTP router (Task 4)
  // -------------------------------------------------------------------------

  /**
   * Routes one HTTP request on an already-authenticated mTLS connection.
   *
   * The peer identity is read from the admission registry, keyed by the SAME
   * connection tuple the raw and TLS sockets share. It is never recomputed from
   * the request and never accepted from the request (§5 of Task 4).
   *
   * Order of bounds, all of which run BEFORE the endpoint router:
   * 1. the total request deadline (§20, 60 s) is armed at request admission;
   * 2. Layer B pre-session admission (§21.1), keyed on the normalized peer —
   *    after successful mTLS and before endpoint routing, enrollment
   *    verification, session lookup, MCP parsing, policy, or any subsystem;
   * 3. the request-target bound (§20, 2 KiB);
   * 4. the compressed-request refusal (§20);
   * 5. the Host (§10) and Origin (§11) authority check, for every configured
   *    remote endpoint.
   *
   * Every refusal on these paths is a sanitized response with `Connection:
   * close`: no MCP JSON-RPC body, no limiter key, no peer address, no
   * remaining-token count, and no internal bucket state.
   */
  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const state = this.connectionStates.get(connectionTuple(req.socket as TLSSocket));
    const spkiPin = state?.spkiPin;

    if (spkiPin === undefined) {
      // Structurally unreachable for an admitted connection: a request cannot
      // be parsed before the post-handshake handler recorded the identity. If
      // it ever happens the request is dropped without a body, because there is
      // no authenticated identity to act on.
      req.socket.destroy();
      return;
    }

    // §20: the total request deadline, armed at HTTP request admission and
    // released when the response settles. A request still being processed at the
    // deadline is aborted, so no unbounded work is retained.
    const deadline = setTimeout(() => {
      req.socket.destroy();
    }, this.totalRequestTimeoutMs);
    const clearDeadline = () => {
      clearTimeout(deadline);
    };
    res.once('finish', clearDeadline);
    res.once('close', clearDeadline);

    const peerKey = peerNetworkKeyFor(req.socket);
    if (peerKey === null) {
      // Fail closed: a peer address that is not an address cannot be bucketed,
      // so the connection is dropped without a response rather than admitted
      // against an invented key.
      req.socket.destroy();
      return;
    }

    // §21.1 Layer B: secure HTTP pre-session admission.
    const admitted = this.layerB.consume(peerKey);
    if (!admitted.consumed) {
      // §24 RATE_LIMITED / §21.1 Layer B. Same bounded shape as the Layer A
      // record: the layer is the whole of the evidence.
      this.audit?.emit({ eventType: 'RATE_LIMITED', admissionLayer: 'B' });
      this.sendSanitized(res, 429, RATE_LIMITED_BODY);
      return;
    }

    // §20: the request target is measured on the received representation before
    // any routing or query parsing happens.
    if (requestTargetBytes(req.url) > MAX_REQUEST_TARGET_BYTES) {
      this.sendSanitized(res, 414, REQUEST_TARGET_TOO_LONG_BODY);
      return;
    }

    // §20: baseline supports no compressed request. Nothing in ARC decodes
    // gzip, br, or deflate, so refusing every Content-Encoding removes any
    // decompression-bomb path before a body is read.
    if (hasContentEncoding(req)) {
      this.sendSanitized(res, 413, UNSUPPORTED_ENCODING_BODY);
      return;
    }

    // §10/§11: the Host and Origin authority check runs HERE, at the gateway
    // boundary, for every CONFIGURED remote endpoint and before any
    // endpoint-specific processing. Neither endpoint owns a private variant, so
    // `/mcp` and `/enroll/complete` cannot drift: a request carrying `Origin` is
    // refused by default, a wrong or malformed `Host` fails closed, and
    // `X-Forwarded-Host` and every other forwarding header grants nothing.
    //
    // For `/enroll/complete` this lands BEFORE the body is read, before any
    // enrollment proof is verified, and before any challenge, failed-attempt
    // counter, or trust-store state can be touched — so neither endpoint is an
    // oracle for host or origin.
    //
    // Only the two configured paths are checked. An unknown path still falls
    // through to the router's uniform 404, so moving this validation earlier does
    // not turn every unknown-path probe into a Host/Origin oracle.
    const pathOnly = (req.url ?? '').split('?')[0];
    if (pathOnly === MCP_PATH || pathOnly === ENROLL_COMPLETE_PATH) {
      const refusal = checkRequestAuthority(req.headers, this.config.publicHostname);
      if (refusal !== null) {
        writeAuthorityRefusal(res, refusal);
        return;
      }
    }

    this.bootstrap.handle(req, res, spkiPin).catch(() => {
      // The controller answers every path it accepts. A rejected promise here
      // means the response could not be written, so the connection is dropped
      // rather than left half-answered.
      if (!res.headersSent && !res.writableEnded) {
        res.destroy();
      }
    });
  }

  /**
   * Writes one sanitized plaintext refusal and terminates the connection.
   *
   * Carries a fixed content type, a fixed length, and a fixed body. Nothing
   * derived from the peer, the limiter, or the request is echoed.
   */
  private sendSanitized(res: ServerResponse, statusCode: number, body: string): void {
    if (res.headersSent || res.writableEnded) {
      res.destroy();
      return;
    }
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Length', Buffer.byteLength(body, 'utf8'));
    res.setHeader('Connection', 'close');
    res.end(body);
  }

  /** Enrolled device count held by this gateway's trust store. */
  public getEnrolledDeviceCount(): number {
    return this.bootstrap.getEnrolledDeviceCount();
  }

  /**
   * True once the bootstrap could not prove durable trust storage restored.
   *
   * @internal Deliberately NOT part of {@link RemoteGatewayStatus}: the storage
   * reason is never disclosed remotely, and completions simply keep failing.
   */
  public isEnrollmentStorageFailed(): boolean {
    return this.bootstrap.isStorageFailureLatched();
  }

  /**
   * Resolves the CURRENT active enrolled device for a trusted SPKI pin.
   *
   * The gateway's authoritative trust store is the one Task 4 loaded and keeps
   * authoritative, so this is the read path every remote request must use. It
   * resolves afresh on every call and never caches the result: a resolver-minted
   * identity remains a valid Task-5 capability object after revocation, so
   * retaining one would let a revoked device keep authenticating.
   */
  public resolveActiveDeviceIdentity(spkiPin: string): TrustedSessionIdentity | undefined {
    return this.bootstrap.resolveActiveDeviceIdentity(spkiPin);
  }

  /**
   * True when the server certificate has reached notAfter, or has ever been
   * observed to have reached it.
   *
   * The boundary is inclusive: at exactly notAfter the certificate is expired.
   * The result is LATCHED, because frozen T-7 says "once expired, new TLS
   * handshakes are refused" — a clock that moves backwards must not restore
   * admission. A wall clock is not monotonic, so an unlatched comparison could
   * be reversed by a backwards correction and silently reopen the gateway.
   */
  private isServerCertificateExpiredOrLatched(): boolean {
    if (this.expiryLatched) {
      return true;
    }
    const facts = this.facts;
    if (facts === undefined) {
      // Without validated facts the gateway cannot prove it may serve.
      this.expiryLatched = true;
      this.degradedReason = 'certificate_expired';
      return true;
    }
    if (this.getWallTime() >= facts.validToMs) {
      this.expiryLatched = true;
      this.degradedReason = 'certificate_expired';
      return true;
    }
    return false;
  }
}

/**
 * THE canonical peer-network key for one socket (§21.3), shared by Layer A and
 * Layer B.
 *
 * Only the socket peer address is authoritative. `X-Forwarded-For`,
 * `Forwarded`, `X-Real-IP`, `Host`, and every request parameter are ignored by
 * construction — this helper is given a socket, reads exactly one documented
 * property from it, and can consult nothing else.
 *
 * Returns the normalized key, or null when the address is not an address at
 * all, which every caller treats as fail-closed refusal. A missing address is
 * not null: it collapses into the ONE shared bounded bucket.
 */
function peerNetworkKeyFor(socket: { remoteAddress?: string }): string | null {
  return normalizePeerNetwork(socket.remoteAddress);
}
