/**
 * CesSpace ARC — RC-05 Task 3 TLS 1.3 / mTLS Admission Gateway
 *
 * A pure TLS admission listener. It terminates TLS 1.3 in-process, requires a
 * client certificate chained to a configured trust root, derives the canonical
 * peer SPKI pin, and admits the connection. It does NOT parse HTTP, does NOT
 * speak MCP, does NOT issue sessions, and does NOT decide device authorization.
 * Those belong to Tasks 4 and beyond.
 *
 * Authoritative contract: §5, §6 (T-1..T-11), §7 P-1..P-3, §18, §19, §20, §21.1.
 *
 * Why `tls.createServer` and not an HTTP server: §20/T-8 require a malformed or
 * unauthenticated connection to be rejected before any HTTP or MCP byte is
 * parsed. A raw TLS server has no HTTP parser in the path at all, so that
 * property is structural rather than a matter of careful routing.
 */

import * as tls from 'node:tls';
import type { Server, TLSSocket } from 'node:tls';
import { deriveSpkiPin } from '@cesspace-arc/auth';
import { DeviceTrustStore } from '@cesspace-arc/auth';
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
  AdmissionLimiter,
  type AdmissionLimiterOptions,
  type AdmissionRefusalReason,
} from './admission-limiter.js';

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
  /** Invoked once per admitted, chain-validated connection. */
  onAdmitted?: (context: PeerAdmissionContext) => void;
  /** Invoked when Layer A refuses a connection. */
  onRefused?: (reason: AdmissionRefusalReason) => void;
}

interface ConnectionState {
  /** The exact admission slot held by this connection. */
  release: () => void;
  /** The raw socket accepted before any TLS work. Always present. */
  rawSocket: TLSSocket;
  /** The TLS socket, once the handshake has produced one. */
  tlsSocket?: TLSSocket;
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
  private readonly limiter: AdmissionLimiter;
  private readonly options: RemoteGatewayOptions;

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
    this.limiter = new AdmissionLimiter(options.admission ?? {});

    // Everything below runs BEFORE a listener exists. Any rejection propagates
    // out of the constructor, so a failed startup cannot leave a bound socket.
    this.config = resolveRemoteConfig(config);

    if (this.config.trustStorePath !== undefined) {
      // Reuse the Task-1 loader verbatim. No second trust-store parser exists,
      // and zero enrolled devices is explicitly valid here (§18, §16).
      try {
        DeviceTrustStore.loadFromFile(this.config.trustStorePath);
      } catch (err: unknown) {
        throw new RemoteConfigError(
          'Configured device trust store failed validation.',
          'TRUST_STORE_INVALID',
          // Preserve the underlying reason for the operator without exposing it.
          { cause: err },
        );
      }
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
      server = tls.createServer(
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
        },
        () => {
          // Intentionally empty. Task 3 has no application protocol: an admitted
          // connection is held open and counted, and nothing is parsed from it.
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

    if (server === undefined) {
      // A second stop finds nothing tracked, nothing to destroy, and counters
      // that are already zero, so it is a structural no-op.
      return;
    }
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

    const peerKey = this.peerKeyFor(socket);
    const decision = this.limiter.admit(peerKey);
    if (!decision.admitted) {
      this.options.onRefused?.(decision.reason);
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
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    const peerCertificate = socket.getPeerCertificate(true);
    if (peerCertificate === undefined || !socket.authorized || peerCertificate.raw === undefined) {
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    let spkiPin: string;
    try {
      spkiPin = deriveSpkiPin(peerCertificate.raw);
    } catch {
      this.settleConnection(tuple);
      socket.destroy();
      return;
    }

    // The handshake has settled, so its slot is released now; the connection
    // remains counted as live until it closes.
    this.settleHandshakeFor(tuple);
    // Attach the TLS socket to the SAME registry entry that already owns the
    // admission slot. There is no separate collection to keep in step, so a
    // closed socket cannot be retained after its entry is deleted.
    const state = this.connectionStates.get(tuple);
    if (state !== undefined) {
      state.tlsSocket = socket;
    }

    // Task 3 boundary: a valid chain and a canonical SPKI pin. No enrollment,
    // revocation, or session decision is made here, so an unknown pin is NOT
    // an error at this layer (Task 4 admits pending, not-yet-enrolled pins).
    this.options.onAdmitted?.({ spkiPin, socket });
  }

  /** Handshake failure: settle the slot and drop the socket. */
  private handleHandshakeFailure(socket: TLSSocket): void {
    this.settleConnection(connectionTuple(socket));
    socket.destroy();
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

  /** Peer key for Layer A accounting: the remote address, else a fixed bucket. */
  private peerKeyFor(socket: TLSSocket): string {
    const address = socket.remoteAddress;
    return typeof address === 'string' && address.length > 0 ? address : 'unknown-peer';
  }
}
