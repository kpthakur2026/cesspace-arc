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

import fs from 'node:fs';
import * as tls from 'node:tls';
import type { Server, TLSSocket } from 'node:tls';
import { deriveSpkiPin } from '@cesspace-arc/auth';
import { DeviceTrustStore } from '@cesspace-arc/auth';
import {
  resolveRemoteConfig,
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
  listenerActive: boolean;
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

/** Injectable seams for deterministic tests. */
export interface RemoteGatewayOptions {
  /** Wall clock used for certificate-validity decisions. */
  getWallTime?: () => number;
  /** Layer A limiter overrides. */
  admission?: AdmissionLimiterOptions;
  /** Invoked once per admitted, chain-validated connection. */
  onAdmitted?: (context: PeerAdmissionContext) => void;
  /** Invoked when Layer A refuses a connection. */
  onRefused?: (reason: AdmissionRefusalReason) => void;
}

interface ConnectionState {
  handshakeSettled: boolean;
  connectionSettled: boolean;
  settleHandshake?: () => void;
}

/** Maximum time to wait for `close()` to settle during shutdown. */
const SHUTDOWN_GRACE_MS = 2000;

export class RemoteGateway {
  private readonly config: ResolvedRemoteConfig;
  private readonly getWallTime: () => number;
  private readonly limiter: AdmissionLimiter;
  private readonly options: RemoteGatewayOptions;

  /** Server key material, held only until the listener consumes it. */
  private privateKeyMaterial?: ReturnType<typeof loadServerPrivateKey>;
  private server?: Server;
  private facts?: ServerCertificateFacts;
  private started = false;
  private degradedReason?: 'certificate_expired';
  private readonly liveSockets = new Set<TLSSocket>();
  /** Per-socket settle flags, so each counter is released exactly once. */
  private readonly connectionStates = new WeakMap<TLSSocket, ConnectionState>();

  constructor(config: RemoteConfig, options: RemoteGatewayOptions = {}) {
    this.options = options;
    this.getWallTime = options.getWallTime ?? (() => Date.now());
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
    const certificatePem = fs.readFileSync(this.config.serverCertificatePath, 'utf8');

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
          // §20: a stalled handshake must not hold a slot indefinitely.
          handshakeTimeout: this.config.handshakeTimeoutMs,
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
        server.listen({ host: this.config.bindHost, port: this.config.port });
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
    return {
      transportMode: 'remote',
      listenerActive: this.started,
      degraded: this.degradedReason !== undefined,
      ...(this.degradedReason === undefined ? {} : { degradedReason: this.degradedReason }),
      liveConnections: this.limiter.getLiveConnectionCount(),
      inFlightHandshakes: this.limiter.getInFlightHandshakeCount(),
    };
  }

  /** Stops the listener and drops every live connection. */
  public async stop(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    this.started = false;

    for (const socket of this.liveSockets) {
      socket.destroy();
    }
    this.liveSockets.clear();
    this.limiter.reset();

    if (server === undefined) {
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
    // Each settles exactly once regardless of the path taken.
    const state: ConnectionState = { handshakeSettled: false, connectionSettled: false };
    this.connectionStates.set(socket, state);

    const settleHandshake = () => {
      if (state.handshakeSettled) {
        return;
      }
      state.handshakeSettled = true;
      this.limiter.releaseHandshake();
    };
    const settleConnection = () => {
      if (state.connectionSettled) {
        return;
      }
      state.connectionSettled = true;
      // A connection that closes without ever completing a handshake (timeout,
      // socket error, destroy) must still release its handshake slot.
      settleHandshake();
      decision.release();
      this.liveSockets.delete(socket);
      this.connectionStates.delete(socket);
    };
    state.settleHandshake = settleHandshake;

    socket.once('close', settleConnection);
    socket.once('error', () => {
      socket.destroy();
    });
    socket.once('timeout', () => {
      socket.destroy();
    });
  }

  /**
   * Post-handshake admission.
   *
   * Reached only when the TLS handshake completed with a client certificate
   * that chained to a configured trust root, because `rejectUnauthorized` is
   * true. The identity is derived here and nowhere else.
   */
  private handleSecureConnection(socket: TLSSocket): void {
    // The handshake has settled, whatever happens next.
    this.connectionStates.get(socket)?.settleHandshake?.();

    if (this.isServerCertificateExpired()) {
      // §6 T-7: once the server certificate has expired, no NEW session may be
      // established. Existing admitted connections are left to drain.
      this.degradedReason = 'certificate_expired';
      socket.destroy();
      return;
    }

    const peerCertificate = socket.getPeerCertificate(true);
    if (peerCertificate === undefined || !socket.authorized) {
      socket.destroy();
      return;
    }

    let spkiPin: string;
    try {
      spkiPin = deriveSpkiPin(peerCertificate.raw);
    } catch {
      socket.destroy();
      return;
    }

    // The connection remains counted as live until it closes; the handshake
    // slot was released above.
    this.liveSockets.add(socket);

    // Task 3 boundary: a valid chain and a canonical SPKI pin. No enrollment,
    // revocation, or session decision is made here, so an unknown pin is NOT
    // an error at this layer (Task 4 admits pending, not-yet-enrolled pins).
    this.options.onAdmitted?.({ spkiPin, socket });
  }

  /** Handshake failure: settle the slot and drop the socket. */
  private handleHandshakeFailure(socket: TLSSocket): void {
    this.connectionStates.get(socket)?.settleHandshake?.();
    socket.destroy();
  }

  private isServerCertificateExpired(): boolean {
    const facts = this.facts;
    if (facts === undefined) {
      return true;
    }
    return this.getWallTime() >= facts.validToMs;
  }

  /** Peer key for Layer A accounting: the remote address, else a fixed bucket. */
  private peerKeyFor(socket: TLSSocket): string {
    const address = socket.remoteAddress;
    return typeof address === 'string' && address.length > 0 ? address : 'unknown-peer';
  }
}
