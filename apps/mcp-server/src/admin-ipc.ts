/**
 * CesSpace ARC — RC-04 Authenticated Local Admin IPC Server
 *
 * Implements §24 Local Admin Channel Trust Boundary: a local-only IPC channel
 * over which a human operator administers approvals.
 *
 * Design invariants:
 * - Local IPC only. No HTTP, no SSE, no WebSocket, no TCP host/port listener.
 * - Socket access is NOT authentication. A same-UID local agent process can also
 *   connect to a Unix socket, so every admin request is authenticated by an
 *   Ed25519 challenge-response signature against the trusted operator public key.
 * - One connection carries exactly one challenge, one authentication attempt,
 *   and one operation. No challenge replay.
 * - The server holds only the operator PUBLIC key. It never sees, stores, or
 *   logs private key material.
 * - Admin actions may only transition approval state. They never execute
 *   mutations, never redeem tokens, and never touch the filesystem subsystem.
 */

import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, type KeyObject } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import {
  ADMIN_CHALLENGE_ID_REGEX,
  ADMIN_CHALLENGE_TTL_MS,
  ADMIN_DEVICE_ID_REGEX,
  ADMIN_MAX_CHALLENGE_FRAME_BYTES,
  ADMIN_MAX_DISPLAY_LABEL_BYTES,
  ADMIN_MAX_REASON_BYTES,
  ADMIN_MAX_REQUEST_FRAME_BYTES,
  ADMIN_MAX_RESPONSE_FRAME_BYTES,
  ADMIN_METHODS,
  ADMIN_PROTOCOL_VERSION,
  ADMIN_REQUEST_ID_REGEX,
  ADMIN_SESSION_ID_REGEX,
  ADMIN_SPKI_PIN_REGEX,
  ArcError,
  decodeBase64Strict,
  encodeAdminPayload,
  importOperatorPublicKey,
  verifyAdminPayload,
  type AdminApprovalSummary,
  type AdminChallenge,
  type AdminErrorCode,
  type AdminMethod,
  type AdminRequestParams,
  type AdminRequestPayload,
  type AdminResponse,
  type AdminResult,
} from '@cesspace-arc/protocol';
import type { ApprovalStateManager } from '@cesspace-arc/policy';
import { EnrollmentManager, deriveOperatorId, ENROLLMENT_ID_REGEX } from '@cesspace-arc/auth';
import { toAdminSummary } from './approval-gate.js';
import { ApprovalAuditSink, getApprovalAuditSink } from './approval-audit.js';
import { getGatewayAuditSink, type GatewayAuditSink } from './gateway-audit.js';
import type { AuditLogger } from '@cesspace-arc/audit';
import type {
  AdministrationOutcome,
  DeviceAdministrationAuthority,
} from './device-administration.js';

/**
 * Conservative bound on a Unix socket path.
 *
 * `sockaddr_un.sun_path` is 108 bytes on Linux including the terminator; this
 * leaves margin for platform variation and for the terminator itself.
 */
const MAX_UNIX_SOCKET_PATH_BYTES = 100;

/** Extra wall time beyond the auth deadline before a stalled socket is dropped. */
const SOCKET_STALL_GRACE_MS = 2000;

export interface AdminIpcServerOptions {
  /** Absolute path of the Unix domain socket endpoint. */
  endpoint: string;
  /** Base64 DER SPKI Ed25519 public key of the trusted operator. */
  operatorPublicKeyB64: string;
  /** Approval state manager to administer. */
  approvalStateManager: ApprovalStateManager;
  /** Injectable monotonic clock in milliseconds. Defaults to performance.now(). */
  getMonotonicTimeMs?: () => number;
  /**
   * Audit logger used to commit approval lifecycle evidence. REQUIRED.
   *
   * There is deliberately no "no audit" mode. An admin channel can drive real
   * state transitions (PENDING -> APPROVED and back out a raw token) and every
   * one of them must be durable in an audit chain BEFORE the operator observes
   * the result. A channel that could be constructed without audit capability
   * would be an unaudited approval authority, so construction fails closed
   * instead. No raw token ever enters the sink.
   */
  auditLogger: AuditLogger;
  /**
   * RC-05 Task 2 pending-enrollment manager. Optional composition seam: a fresh
   * volatile manager is created when absent, exactly as the approval state
   * manager behaves. It is never persisted and never written to the trust store.
   */
  enrollmentManager?: EnrollmentManager;
  /**
   * RC-05 Task 9 device/session administration authority.
   *
   * Optional composition seam and DELIBERATELY never defaulted. When absent —
   * which is every deployment without an authoritative remote trust-store
   * composition — the eight administration methods refuse with
   * `ADMINISTRATION_UNAVAILABLE`. The channel never loads, creates, or falls
   * back to a second trust store of its own.
   */
  deviceAdministration?: DeviceAdministrationAuthority;
}

/** Machine-readable startup/socket failures. */
export class AdminIpcError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
  ) {
    super(message);
    this.name = 'AdminIpcError';
  }
}

interface SocketIdentity {
  dev: number;
  ino: number;
}

/**
 * Decorates an error with a filesystem error code for narrow checks.
 */
function errorCode(err: unknown): string | undefined {
  return (err as { code?: string }).code;
}

/**
 * Validates the Unix socket endpoint and its parent directory before binding.
 *
 * Directory permissions are DEFENSE IN DEPTH ONLY and are never treated as
 * operator authentication; the Ed25519 challenge-response remains mandatory.
 */
function assertSafeEndpoint(endpoint: unknown, currentUid: number | undefined): string {
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw new AdminIpcError('Admin IPC endpoint must be a non-empty string.', 'ENDPOINT_INVALID');
  }
  if (endpoint.includes('\u0000')) {
    throw new AdminIpcError('Admin IPC endpoint must not contain NUL.', 'ENDPOINT_INVALID');
  }
  if (!path.isAbsolute(endpoint)) {
    throw new AdminIpcError(
      'Admin IPC endpoint must be an absolute path.',
      'ENDPOINT_NOT_ABSOLUTE',
    );
  }
  if (Buffer.byteLength(endpoint, 'utf8') > MAX_UNIX_SOCKET_PATH_BYTES) {
    throw new AdminIpcError(
      'Admin IPC endpoint path is too long for a Unix domain socket.',
      'ENDPOINT_TOO_LONG',
    );
  }

  const parent = path.dirname(endpoint);
  let parentStat: fs.Stats;
  try {
    // lstat, deliberately: a symlinked parent directory must not be followed.
    parentStat = fs.lstatSync(parent);
  } catch {
    throw new AdminIpcError('Admin IPC parent directory does not exist.', 'PARENT_MISSING');
  }
  if (!parentStat.isDirectory()) {
    throw new AdminIpcError(
      'Admin IPC parent must be a real directory (symlinks are rejected).',
      'PARENT_NOT_DIRECTORY',
    );
  }
  if (typeof currentUid === 'number' && parentStat.uid !== currentUid) {
    throw new AdminIpcError(
      'Admin IPC parent directory is not owned by this user.',
      'PARENT_NOT_OWNED',
    );
  }
  if ((parentStat.mode & 0o077) !== 0) {
    throw new AdminIpcError(
      'Admin IPC parent directory must not grant group or other access.',
      'PARENT_PERMISSIVE',
    );
  }

  return endpoint;
}

/**
 * Authenticated local admin IPC server.
 *
 * Constructed only by trusted server launch configuration. There is no global
 * singleton, no implicit listener, and no default endpoint.
 */
export class AdminIpcServer {
  private readonly endpoint: string;
  private readonly operatorPublicKey: KeyObject;
  private readonly approvalStateManager: ApprovalStateManager;
  private readonly getMonotonicTimeMs: () => number;

  private readonly approvalAuditSink: ApprovalAuditSink;
  /**
   * RC-05 Task 10 gateway lifecycle sink (rc05 §24).
   *
   * The SAME sink instance the remote gateway, the enrollment bootstrap, and the
   * MCP surface emit through, obtained from the per-chain memo, so an enrollment
   * request created or cancelled here is recorded in the one existing
   * `AuditLogger` chain rather than a gateway-only one.
   */
  private readonly gatewayAuditSink: GatewayAuditSink;
  /** RC-05 Task 2 volatile pending-enrollment manager. */
  private readonly enrollmentManager: EnrollmentManager;
  /** Server-derived per-operator quota key (SHA-256 of the operator SPKI key). */
  private readonly operatorId: string;
  private server?: net.Server;
  private socketIdentity?: SocketIdentity;
  private started = false;
  /**
   * RC-05 Task 9 device/session administration authority.
   *
   * Attached once by the server composition, after the remote gateway exists.
   * Left undefined in a composition with no authoritative remote trust state,
   * in which case administration requests fail closed.
   */
  private deviceAdministration?: DeviceAdministrationAuthority;

  constructor(options: AdminIpcServerOptions) {
    if (process.platform === 'win32') {
      // Windows named pipes are not implemented in RC-04 Task 3.
      throw new AdminIpcError(
        'Admin IPC over Windows named pipes is not implemented.',
        'PLATFORM_UNSUPPORTED',
      );
    }

    if (
      options === null ||
      typeof options !== 'object' ||
      typeof options.operatorPublicKeyB64 !== 'string'
    ) {
      throw new AdminIpcError('Admin IPC requires an operator public key.', 'PUBLIC_KEY_INVALID');
    }

    const publicKey = importOperatorPublicKey(options.operatorPublicKeyB64);
    if (publicKey === null) {
      // Fails closed: no admin channel without a valid Ed25519 operator key.
      throw new AdminIpcError(
        'Operator public key must be a base64 DER SPKI Ed25519 key.',
        'PUBLIC_KEY_INVALID',
      );
    }
    this.operatorPublicKey = publicKey;

    if (options.approvalStateManager === null || typeof options.approvalStateManager !== 'object') {
      throw new AdminIpcError('Admin IPC requires an approval state manager.', 'MANAGER_MISSING');
    }
    this.approvalStateManager = options.approvalStateManager;

    // Fail closed: an admin channel that cannot commit lifecycle evidence would
    // be an unaudited approval authority. There is no fallback and no "no sink"
    // success path.
    const auditLogger = options.auditLogger;
    if (auditLogger === null || typeof auditLogger !== 'object') {
      throw new AdminIpcError(
        'Admin IPC requires an audit logger for approval lifecycle evidence.',
        'AUDIT_LOGGER_MISSING',
      );
    }
    if (typeof auditLogger.log !== 'function') {
      throw new AdminIpcError(
        'Admin IPC requires an audit logger for approval lifecycle evidence.',
        'AUDIT_LOGGER_INVALID',
      );
    }

    const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    this.endpoint = assertSafeEndpoint(options.endpoint, currentUid);

    this.getMonotonicTimeMs = options.getMonotonicTimeMs ?? (() => performance.now());

    // The admin channel is a local operator channel: every state transition it
    // causes must be committed to the same audit chain before the operator sees
    // the result. No raw token ever enters the sink.
    //
    // The sink is memoized per audit chain. Constructing a second sink over the
    // same logger would register a second lifecycle observer on the same
    // manager, and the manager emits one event per observer, so every
    // transition would be written to the chain twice.
    this.approvalAuditSink = getApprovalAuditSink(auditLogger);
    this.approvalStateManager.registerLifecycleSink(this.approvalAuditSink);

    // RC-05 Task 10: the SAME memoized-per-chain gateway lifecycle sink the
    // gateway, the bootstrap, and the MCP surface write through, so an
    // enrollment transition started here lands in the ONE existing chain. It is
    // never a second logger and never a second queue over the same chain.
    this.gatewayAuditSink = getGatewayAuditSink(auditLogger);

    // RC-05 Task 2: volatile pending-enrollment lifecycle. Pure domain state,
    // never persisted, never written to the trust store.
    this.enrollmentManager = options.enrollmentManager ?? new EnrollmentManager();

    // The per-operator quota key is derived from the VERIFIED operator public
    // key, never from request parameters. Only the digest is retained, so the
    // raw operator key never appears in enrollment state, responses, or errors.
    this.operatorId = deriveOperatorId(publicKey);

    // RC-05 Task 9: composition-supplied, never constructed here. A channel with
    // no authority refuses administration rather than inventing one.
    this.deviceAdministration = options.deviceAdministration;
  }

  /**
   * The pending-enrollment authority this channel writes to (RC-05 Task 4).
   *
   * Returns the exact instance, never a copy. A composing owner uses this to
   * prove that the local operator channel and the remote bootstrap endpoint
   * share ONE challenge table: two instances would mean a challenge created
   * locally could never be observed by a remote completion.
   */
  public getEnrollmentManager(): EnrollmentManager {
    return this.enrollmentManager;
  }

  /**
   * Attaches the ONE device/session administration authority (RC-05 Task 9).
   *
   * A setter rather than a constructor argument because the authority is backed
   * by the remote gateway's authoritative trust store, and the gateway is built
   * after the admin channel. Idempotent for the SAME instance and refuses to
   * replace a DIFFERENT one: two authorities over two trust stores is exactly
   * the split-brain the one-store invariant forbids. Re-attaching the same
   * instance is a no-op so a re-entrant composition cannot fail spuriously.
   */
  public attachDeviceAdministration(authority: DeviceAdministrationAuthority): void {
    if (authority === null || typeof authority !== 'object') {
      throw new AdminIpcError(
        'Device administration authority must be an object.',
        'ADMINISTRATION_AUTHORITY_INVALID',
      );
    }
    if (this.deviceAdministration !== undefined && this.deviceAdministration !== authority) {
      throw new AdminIpcError(
        'Device administration authority is already attached to this admin channel.',
        'ADMINISTRATION_AUTHORITY_CONFLICT',
      );
    }
    this.deviceAdministration = authority;
  }

  /**
   * The attached authority, or undefined when this composition has none.
   *
   * Exposed for composition-time proof that the local admin channel and the
   * remote gateway share ONE administration authority; it is not reachable from
   * any request, and the mutable trust store is not reachable through it.
   */
  public getDeviceAdministration(): DeviceAdministrationAuthority | undefined {
    return this.deviceAdministration;
  }

  /** Starts listening. Rejects if the endpoint already exists for any reason. */
  public async start(): Promise<void> {
    if (this.started) {
      return;
    }

    // Never blindly unlink a pre-existing path: it may be a regular file, a
    // symlink, or another socket. Fail closed instead.
    let existing: fs.Stats | undefined;
    try {
      existing = fs.lstatSync(this.endpoint);
    } catch (err: unknown) {
      if (errorCode(err) !== 'ENOENT') {
        throw new AdminIpcError(
          'Admin IPC endpoint could not be inspected.',
          'ENDPOINT_UNREADABLE',
        );
      }
    }
    if (existing !== undefined) {
      throw new AdminIpcError(
        'Admin IPC endpoint already exists; refusing to replace it.',
        'ENDPOINT_EXISTS',
      );
    }

    const server = net.createServer({ allowHalfOpen: false }, (socket) => {
      void this.handleConnection(socket);
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error): void => {
        server.removeListener('listening', onListening);
        reject(new AdminIpcError('Admin IPC endpoint could not be bound.', 'BIND_FAILED'));
        void err;
      };
      const onListening = (): void => {
        server.removeListener('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.endpoint);
    });

    this.server = server;

    try {
      fs.chmodSync(this.endpoint, 0o600);
      const stat = fs.lstatSync(this.endpoint);
      this.socketIdentity = { dev: stat.dev, ino: stat.ino };
    } catch {
      await this.stop();
      throw new AdminIpcError('Admin IPC socket could not be secured.', 'SOCKET_SECURE_FAILED');
    }

    this.started = true;
  }

  /**
   * Stops listening and removes only the socket this server created.
   *
   * Ownership MUST be decided before close(). Closing a Unix domain socket
   * listener unlinks the bound pathname unconditionally at the runtime level, so
   * a replacement object occupying the endpoint would otherwise be destroyed
   * before any identity check could run.
   */
  public async stop(): Promise<void> {
    // Best effort: commit any lifecycle evidence still buffered before the
    // channel goes away. A standalone admin channel has no later flush point,
    // and the operator may have already observed outcomes whose transitions
    // were only queued. Failure here is not fatal to teardown — the queue keeps
    // the evidence and every later flush still fails closed.
    await this.flushLifecycleAudit();

    const server = this.server;
    this.server = undefined;
    this.started = false;

    const identity = this.socketIdentity;
    this.socketIdentity = undefined;

    // A foreign object found at the endpoint, moved aside for the duration of
    // the close so the runtime cannot unlink it.
    let shieldedOriginalPath: string | undefined;
    let shieldedMovedPath: string | undefined;

    if (identity !== undefined) {
      try {
        const stat = fs.lstatSync(this.endpoint);
        if (stat.isSocket() && stat.dev === identity.dev && stat.ino === identity.ino) {
          // Still exactly the socket we created: remove it now, so the
          // close-time unlink has nothing left to act on.
          fs.unlinkSync(this.endpoint);
        } else {
          // The dev/inode comparison alone is not sufficient on its own: a
          // freed inode can be handed straight back to a new object. The
          // file-type check covers that, and anything that is not our socket is
          // shielded here rather than unlinked.
          shieldedOriginalPath = this.endpoint;
          shieldedMovedPath = `${this.endpoint}.shielded-${randomBytes(8).toString('hex')}`;
          fs.renameSync(this.endpoint, shieldedMovedPath);
        }
      } catch {
        // Already gone, or unreadable: never unlink what cannot be identified.
        shieldedOriginalPath = undefined;
        shieldedMovedPath = undefined;
      }
    }

    try {
      if (server !== undefined) {
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
      }
    } finally {
      if (shieldedOriginalPath !== undefined && shieldedMovedPath !== undefined) {
        try {
          // Restore only if nothing else has taken the path in the meantime:
          // overwriting a newly appeared object would itself be destructive.
          if (!fs.existsSync(shieldedOriginalPath)) {
            fs.renameSync(shieldedMovedPath, shieldedOriginalPath);
          }
        } catch {
          // Restore failed; the object remains preserved under the shielded name.
        }
      }
    }
  }

  /** True when the listener is active. */
  public isStarted(): boolean {
    return this.started;
  }

  // -------------------------------------------------------------------------
  // Connection handling
  // -------------------------------------------------------------------------

  private async handleConnection(socket: net.Socket): Promise<void> {
    let closed = false;
    const closeNow = (): void => {
      if (!closed) {
        closed = true;
        socket.destroy();
      }
    };

    // Bound a stalled peer. The explicit monotonic deadline below remains the
    // authority for the authentication window.
    socket.setTimeout(ADMIN_CHALLENGE_TTL_MS + SOCKET_STALL_GRACE_MS);
    socket.on('timeout', closeNow);
    socket.on('error', closeNow);

    try {
      const challengeId = randomBytes(16).toString('hex');
      const nonce = randomBytes(32).toString('hex');
      const issuedAtMs = this.getMonotonicTimeMs();

      const challenge: AdminChallenge = {
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId,
        nonce,
        expiresInMs: ADMIN_CHALLENGE_TTL_MS,
      };
      const challengeFrame = `${JSON.stringify(challenge)}\n`;
      if (Buffer.byteLength(challengeFrame, 'utf8') > ADMIN_MAX_CHALLENGE_FRAME_BYTES) {
        closeNow();
        return;
      }
      socket.write(challengeFrame);

      const frame = await this.readFrame(socket, ADMIN_MAX_REQUEST_FRAME_BYTES);
      if (frame === null) {
        closeNow();
        return;
      }

      const response = await this.processAuthenticatedFrame(frame, challengeId, nonce, issuedAtMs);
      this.writeResponse(socket, response);
    } catch {
      // Any unexpected failure closes without disclosing detail.
    } finally {
      closeNow();
    }
  }

  /**
   * Reads exactly one newline-delimited frame with a hard byte bound.
   * Returns null when the peer exceeds the bound or disconnects first.
   */
  private readFrame(socket: net.Socket, maxBytes: number): Promise<Buffer | null> {
    return new Promise((resolve) => {
      let total = 0;
      const chunks: Buffer[] = [];
      let settled = false;

      const finish = (value: Buffer | null): void => {
        if (settled) return;
        settled = true;
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onClose);
        socket.removeListener('error', onError);
        resolve(value);
      };

      const onData = (chunk: Buffer): void => {
        total += chunk.length;
        if (total > maxBytes) {
          // Rejected before unbounded accumulation.
          finish(null);
          return;
        }
        chunks.push(chunk);
        const buffer = Buffer.concat(chunks);
        const newlineAt = buffer.indexOf(0x0a);
        if (newlineAt !== -1) {
          finish(buffer.subarray(0, newlineAt));
        } else {
          chunks.length = 0;
          chunks.push(buffer);
        }
      };
      const onEnd = (): void => finish(null);
      const onClose = (): void => finish(null);
      const onError = (): void => finish(null);

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onClose);
      socket.on('error', onError);
    });
  }

  /** Writes one bounded response frame, substituting a safe error if oversized. */
  private writeResponse(socket: net.Socket, response: AdminResponse): void {
    let frame: string;
    try {
      frame = `${JSON.stringify(response)}\n`;
    } catch {
      return;
    }
    if (Buffer.byteLength(frame, 'utf8') > ADMIN_MAX_RESPONSE_FRAME_BYTES) {
      frame = `${JSON.stringify(errorResponse('INTERNAL_ERROR'))}\n`;
    }
    try {
      socket.write(frame);
    } catch {
      // Peer already gone.
    }
  }

  // -------------------------------------------------------------------------
  // Authentication then dispatch
  // -------------------------------------------------------------------------

  /**
   * Verifies the signature over the raw received payload bytes against THIS
   * connection's challenge, and only then parses and validates the request.
   */
  private async processAuthenticatedFrame(
    frame: Buffer,
    challengeId: string,
    nonce: string,
    issuedAtMs: number,
  ): Promise<AdminResponse> {
    // Enforce the authentication deadline on a monotonic clock.
    if (this.getMonotonicTimeMs() - issuedAtMs >= ADMIN_CHALLENGE_TTL_MS) {
      return errorResponse('AUTHENTICATION_FAILED');
    }

    let envelope: unknown;
    try {
      envelope = JSON.parse(frame.toString('utf8'));
    } catch {
      return errorResponse('INVALID_ADMIN_REQUEST');
    }

    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return errorResponse('INVALID_ADMIN_REQUEST');
    }
    const keys = Object.keys(envelope as Record<string, unknown>);
    if (keys.length !== 2 || !keys.includes('payload') || !keys.includes('signature')) {
      // Extra or missing envelope properties are rejected.
      return errorResponse('INVALID_ADMIN_REQUEST');
    }

    const rawEnvelope = envelope as Record<string, unknown>;
    const payloadBytes = decodeBase64Strict(rawEnvelope.payload);
    const signatureBytes = decodeBase64Strict(rawEnvelope.signature);
    if (payloadBytes === null || signatureBytes === null) {
      return errorResponse('INVALID_ADMIN_REQUEST');
    }
    if (payloadBytes.length === 0 || payloadBytes.length > ADMIN_MAX_REQUEST_FRAME_BYTES) {
      return errorResponse('INVALID_ADMIN_REQUEST');
    }
    if (signatureBytes.length !== 64) {
      return errorResponse('AUTHENTICATION_FAILED');
    }

    // Signature verification happens BEFORE any payload parsing or state access.
    if (
      !verifyAdminPayload(this.operatorPublicKey, challengeId, nonce, payloadBytes, signatureBytes)
    ) {
      return errorResponse('AUTHENTICATION_FAILED');
    }

    const payload = this.parsePayload(payloadBytes, challengeId);
    if (payload === null) {
      return errorResponse('INVALID_ADMIN_REQUEST');
    }

    return this.dispatch(payload);
  }

  /** Parses and strictly validates an already-signature-verified payload. */
  private parsePayload(
    payloadBytes: Buffer,
    expectedChallengeId: string,
  ): AdminRequestPayload | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(payloadBytes.toString('utf8'));
    } catch {
      return null;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const record = parsed as Record<string, unknown>;

    const payloadKeys = Object.keys(record);
    if (
      payloadKeys.length !== 4 ||
      !payloadKeys.includes('protocol') ||
      !payloadKeys.includes('challengeId') ||
      !payloadKeys.includes('method') ||
      !payloadKeys.includes('params')
    ) {
      return null;
    }

    if (record.protocol !== ADMIN_PROTOCOL_VERSION) {
      return null;
    }
    if (
      typeof record.challengeId !== 'string' ||
      !ADMIN_CHALLENGE_ID_REGEX.test(record.challengeId)
    ) {
      return null;
    }
    // The signed payload must bind exactly this connection's challenge.
    if (record.challengeId !== expectedChallengeId) {
      return null;
    }
    if (
      typeof record.method !== 'string' ||
      !(ADMIN_METHODS as readonly string[]).includes(record.method)
    ) {
      return null;
    }

    const rawParams = record.params;
    if (rawParams === null || typeof rawParams !== 'object' || Array.isArray(rawParams)) {
      return null;
    }
    // The parameter shape is closed: any key outside this set is rejected, so a
    // caller cannot smuggle an operator identity, TTL, attempt counter, or
    // one-time secret into a signed request. This set is the union across ALL
    // methods; `dispatch` additionally enforces which keys each method accepts,
    // so a valid key for one method is still rejected on another.
    const params: AdminRequestParams = {};
    for (const key of Object.keys(rawParams as Record<string, unknown>)) {
      const value = (rawParams as Record<string, unknown>)[key];
      if (
        key !== 'requestId' &&
        key !== 'reason' &&
        key !== 'clientId' &&
        key !== 'clientType' &&
        key !== 'spkiPin' &&
        key !== 'displayLabel' &&
        key !== 'enrollmentId' &&
        key !== 'deviceId' &&
        key !== 'sessionId'
      ) {
        // Unexpected params are rejected.
        return null;
      }
      if (typeof value !== 'string') return null;
      params[key] = value;
    }

    const payload: AdminRequestPayload = {
      protocol: ADMIN_PROTOCOL_VERSION,
      challengeId: record.challengeId,
      method: record.method as AdminMethod,
      params,
    };

    // Enforce canonical form: a signature must cover exactly the canonical
    // byte encoding, so alternate encodings of the same object are rejected.
    if (encodeAdminPayload(payload) !== payloadBytes.toString('utf8')) {
      return null;
    }

    return payload;
  }

  // -------------------------------------------------------------------------
  // Method dispatch
  // -------------------------------------------------------------------------

  private async dispatch(payload: AdminRequestPayload): Promise<AdminResponse> {
    const { method, params } = payload;

    if (method === 'approvals.list') {
      if (
        params.requestId !== undefined ||
        params.reason !== undefined ||
        params.clientId !== undefined ||
        params.clientType !== undefined ||
        params.spkiPin !== undefined ||
        params.displayLabel !== undefined ||
        params.enrollmentId !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleList();
    }

    if (method === 'enrollment.create') {
      if (
        params.requestId !== undefined ||
        params.reason !== undefined ||
        params.enrollmentId !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (
        params.clientId === undefined ||
        params.clientType === undefined ||
        params.spkiPin === undefined
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleEnrollmentCreate({
        clientId: params.clientId,
        clientType: params.clientType,
        spkiPin: params.spkiPin,
        ...(params.displayLabel === undefined ? {} : { displayLabel: params.displayLabel }),
      });
    }

    if (method === 'enrollment.cancel') {
      if (
        params.requestId !== undefined ||
        params.reason !== undefined ||
        params.clientId !== undefined ||
        params.clientType !== undefined ||
        params.spkiPin !== undefined ||
        params.displayLabel !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.enrollmentId === undefined) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ENROLLMENT_ID_REGEX.test(params.enrollmentId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleEnrollmentCancel(params.enrollmentId);
    }

    if (method === 'approvals.inspect') {
      if (
        params.requestId === undefined ||
        params.reason !== undefined ||
        params.clientId !== undefined ||
        params.clientType !== undefined ||
        params.spkiPin !== undefined ||
        params.displayLabel !== undefined ||
        params.enrollmentId !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined ||
        false
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ADMIN_REQUEST_ID_REGEX.test(params.requestId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleInspect(params.requestId);
    }

    if (method === 'approval.approve') {
      if (
        params.requestId === undefined ||
        params.reason !== undefined ||
        params.clientId !== undefined ||
        params.clientType !== undefined ||
        params.spkiPin !== undefined ||
        params.displayLabel !== undefined ||
        params.enrollmentId !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined ||
        false
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ADMIN_REQUEST_ID_REGEX.test(params.requestId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleApprove(params.requestId);
    }

    if (method === 'approval.reject') {
      if (
        params.requestId === undefined ||
        params.clientId !== undefined ||
        params.clientType !== undefined ||
        params.spkiPin !== undefined ||
        params.displayLabel !== undefined ||
        params.enrollmentId !== undefined ||
        params.deviceId !== undefined ||
        params.sessionId !== undefined ||
        false
      ) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ADMIN_REQUEST_ID_REGEX.test(params.requestId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.reason !== undefined) {
        if (
          params.reason.includes('\u0000') ||
          Buffer.byteLength(params.reason, 'utf8') > ADMIN_MAX_REASON_BYTES
        ) {
          return errorResponse('INVALID_ADMIN_REQUEST');
        }
      }
      return await this.handleReject(params.requestId, params.reason);
    }

    // -------------------------------------------------------------------------
    // RC-05 Task 9: local device and session administration.
    //
    // These eight methods exist ONLY on this authenticated local channel. They
    // are not MCP tools, not HTTP endpoints, and not WebSocket channels, and no
    // remote actor can reach them by any route. Each requires the same Ed25519
    // challenge-response proof as every other admin method, each is strictly
    // validated here (the CLI's validation is a convenience, never the
    // authority), and each fails closed with ADMINISTRATION_UNAVAILABLE when no
    // authoritative trust-store composition is attached.
    // -------------------------------------------------------------------------

    if (method === 'devices.list') {
      if (!paramsAreExactly(params, [])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleDevicesList();
    }

    if (method === 'devices.inspect') {
      if (!paramsAreExactly(params, ['deviceId'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.deviceId === undefined || !ADMIN_DEVICE_ID_REGEX.test(params.deviceId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleDeviceInspect(params.deviceId);
    }

    if (method === 'device.revoke') {
      if (!paramsAreExactly(params, ['deviceId'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.deviceId === undefined || !ADMIN_DEVICE_ID_REGEX.test(params.deviceId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleDeviceRevoke(params.deviceId);
    }

    if (method === 'device.rename') {
      if (!paramsAreExactly(params, ['deviceId', 'displayLabel'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.deviceId === undefined || !ADMIN_DEVICE_ID_REGEX.test(params.deviceId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!isAcceptableDisplayLabel(params.displayLabel)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleDeviceRename(params.deviceId, params.displayLabel);
    }

    if (method === 'device.pin.add') {
      if (!paramsAreExactly(params, ['deviceId', 'spkiPin'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.deviceId === undefined || !ADMIN_DEVICE_ID_REGEX.test(params.deviceId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.spkiPin === undefined || !ADMIN_SPKI_PIN_REGEX.test(params.spkiPin)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleDevicePinAdd(params.deviceId, params.spkiPin);
    }

    if (method === 'device.pin.remove') {
      if (!paramsAreExactly(params, ['deviceId', 'spkiPin'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.deviceId === undefined || !ADMIN_DEVICE_ID_REGEX.test(params.deviceId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.spkiPin === undefined || !ADMIN_SPKI_PIN_REGEX.test(params.spkiPin)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleDevicePinRemove(params.deviceId, params.spkiPin);
    }

    if (method === 'sessions.list') {
      if (!paramsAreExactly(params, [])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleSessionsList();
    }

    if (method === 'session.revoke') {
      if (!paramsAreExactly(params, ['sessionId'])) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (params.sessionId === undefined || !ADMIN_SESSION_ID_REGEX.test(params.sessionId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return await this.handleSessionRevoke(params.sessionId);
    }

    return errorResponse('INVALID_ADMIN_REQUEST');
  }

  /**
   * Commits buffered approval lifecycle evidence before the operator observes a
   * result. Returns false when required evidence could not be written, in which
   * case the caller fails the admin request closed rather than disclosing a
   * token or confirming a transition the audit chain does not record.
   */
  private async flushLifecycleAudit(): Promise<boolean> {
    // No "no sink" shortcut exists: the sink is mandatory, so a true result
    // always means the evidence was actually committed.
    try {
      await this.approvalAuditSink.flush();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Commits buffered gateway lifecycle evidence before the operator observes a
   * result. The gateway and the approval sink share one chain but hold separate
   * bounded queues, so each is drained by its own owner.
   */
  private async flushGatewayAudit(): Promise<boolean> {
    try {
      await this.gatewayAuditSink.flush();
      return true;
    } catch {
      return false;
    }
  }

  private async handleList(): Promise<AdminResponse> {
    // Purge expired state before listing so the operator never sees a stale
    // PENDING entry.
    this.approvalStateManager.purgeExpired();

    // Lazy expiry discovered here is a real state transition and must be
    // committed to audit before the operator sees the list.
    if (!(await this.flushLifecycleAudit())) {
      return errorResponse('INTERNAL_ERROR');
    }

    const approvals: AdminApprovalSummary[] = [];
    for (const snapshot of this.approvalStateManager.listActive()) {
      if (snapshot.state !== 'PENDING') {
        continue;
      }
      // One authoritative projection (approval-gate.toAdminSummary). It carries
      // the safe review summary -- including target paths -- but never raw
      // review material, a token, a token digest, or a monotonic deadline.
      approvals.push(toAdminSummary(snapshot));
    }
    return { ok: true, result: { approvals } };
  }

  private async handleInspect(requestId: string): Promise<AdminResponse> {
    const snapshot = this.approvalStateManager.getRequest(requestId);
    // getRequest() performs lazy expiry, which is a REAL state transition and
    // queues APPROVAL_EXPIRED. It must be committed before ANY response is
    // returned, including the not-pending response below.
    if (!(await this.flushLifecycleAudit())) {
      return errorResponse('INTERNAL_ERROR');
    }
    // Terminal states are reported identically to unknown IDs so this method
    // does not become an existence oracle for non-pending records.
    if (snapshot === undefined || snapshot.state !== 'PENDING') {
      return errorResponse('NOT_FOUND_OR_NOT_PENDING');
    }
    const reviewMaterial = this.approvalStateManager.inspectPending(requestId) ?? '';
    if (!(await this.flushLifecycleAudit())) {
      return errorResponse('INTERNAL_ERROR');
    }
    return {
      ok: true,
      result: {
        requestId: snapshot.requestId,
        toolName: snapshot.toolName,
        state: snapshot.state,
        workspaceId: snapshot.binding.workspace.workspaceId,
        clientId: snapshot.binding.actor.clientId,
        clientType: snapshot.binding.actor.clientType,
        sessionId: snapshot.binding.actor.sessionId,
        deviceId: snapshot.binding.actor.deviceId,
        createdAt: snapshot.createdAt,
        expiresAt: snapshot.expiresAt,
        remainingSeconds: snapshot.remainingSeconds,
        reviewSummary: snapshot.reviewSummary,
        reviewMaterial,
      },
    };
  }

  private async handleApprove(requestId: string): Promise<AdminResponse> {
    try {
      const grant = this.approvalStateManager.approve(requestId);

      // APPROVAL_GRANTED must be durable BEFORE the raw token is disclosed. If
      // the evidence cannot be written, no token is returned; the record may
      // already be APPROVED and is left to expire naturally (rc04 §39).
      if (!(await this.flushLifecycleAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }

      // The raw token is returned exactly once, on this authenticated channel.
      // It is never logged, persisted, audited, or retained here.
      return {
        ok: true,
        result: {
          requestId: grant.snapshot.requestId,
          state: grant.snapshot.state,
          token: grant.token,
          expiresAt: grant.snapshot.expiresAt,
          remainingSeconds: grant.snapshot.remainingSeconds,
        },
      };
    } catch (err: unknown) {
      // A failure is not a reason to skip evidence: approve() runs lazy expiry
      // first, so this path can have queued a real APPROVAL_EXPIRED.
      //
      // When that evidence cannot be committed, the semantic error (for example
      // APPROVAL_EXPIRED) is NOT returned: the operator must not be told a
      // definitive outcome the audit chain does not record. The state machine's
      // truth is already committed and is NOT rolled back; the queued evidence
      // is retained for a later retry.
      if (!(await this.flushLifecycleAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }
      return errorResponse(this.mapApprovalError(err));
    }
  }

  private async handleReject(requestId: string, reason?: string): Promise<AdminResponse> {
    try {
      // The operator-supplied reason is validated by the caller but is NEVER
      // persisted, audited, or logged: it can contain secrets or host paths.
      // Only its PRESENCE is recorded, as a bounded boolean.
      const snapshot = this.approvalStateManager.reject(requestId, reason);
      if (!(await this.flushLifecycleAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }
      return { ok: true, result: { requestId: snapshot.requestId, state: snapshot.state } };
    } catch (err: unknown) {
      // See handleApprove: evidence that cannot be committed must not be
      // papered over with a semantic outcome. State is preserved, not rolled back.
      if (!(await this.flushLifecycleAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }
      return errorResponse(this.mapApprovalError(err));
    }
  }

  /**
   * Creates a pending enrollment challenge.
   *
   * The one-time secret is generated server-side and returned exactly once in
   * this successful authenticated response. It is never audited, logged,
   * persisted, or echoed on any failure path.
   */
  private async handleEnrollmentCreate(input: {
    clientId: string;
    clientType: string;
    spkiPin: string;
    displayLabel?: string;
  }): Promise<AdminResponse> {
    try {
      const created = this.enrollmentManager.create({
        clientId: input.clientId,
        clientType: input.clientType,
        spkiPin: input.spkiPin,
        ...(input.displayLabel === undefined ? {} : { displayLabel: input.displayLabel }),
        // Server-derived from the VERIFIED operator public key. A caller cannot
        // supply or influence the per-operator quota key.
        operatorId: this.operatorId,
      });

      // Constructed field by field against the declared closed protocol shape.
      // A structural spread would also carry PendingEnrollmentView's internal
      // fields (notably the failed-attempt counter) into the response.
      const view = created.enrollment;

      // §24 DEVICE_ENROLLMENT_REQUESTED, emitted only once the pending
      // enrollment actually committed. The ONE-TIME SECRET is deliberately
      // absent: it is returned exactly once to the operator in the response
      // below and is never written to the audit chain, not even as a digest —
      // the record carries the server-issued enrollment identifier, the
      // operator-supplied client identity, the device's already-public SPKI pin,
      // and nothing else.
      this.gatewayAuditSink.emit({
        eventType: 'DEVICE_ENROLLMENT_REQUESTED',
        enrollmentId: view.enrollmentId,
        clientId: view.clientId,
        clientType: view.clientType,
        spkiPin: view.spkiPin,
      });

      // The one-time secret leaves the process in the response below, so the
      // record of the request that created it is committed FIRST. An operator is
      // never handed a credential for a transition the audit chain does not
      // record.
      if (!(await this.flushGatewayAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }

      return {
        ok: true,
        result: {
          enrollment: {
            enrollmentId: view.enrollmentId,
            clientId: view.clientId,
            clientType: view.clientType,
            spkiPin: view.spkiPin,
            displayLabel: view.displayLabel,
            createdAt: view.createdAt,
            expiresAt: view.expiresAt,
            remainingSeconds: view.remainingSeconds,
          },
          secret: created.secret,
        },
      };
    } catch (err: unknown) {
      return errorResponse(this.mapEnrollmentError(err));
    }
  }

  /**
   * Cancels a pending enrollment.
   *
   * An unknown, expired, already-consumed, or already-cancelled identifier
   * produces the same bounded NOT_FOUND_OR_NOT_PENDING result as an approval
   * that is not pending, so cancellation is not an existence oracle.
   */
  private async handleEnrollmentCancel(enrollmentId: string): Promise<AdminResponse> {
    try {
      const cancelled = this.enrollmentManager.cancel(enrollmentId);
      if (!cancelled) {
        return errorResponse('NOT_FOUND_OR_NOT_PENDING');
      }
      // §24 DEVICE_ENROLLMENT_REJECTED. An operator cancellation ends a pending
      // enrollment without enrolling a device, so it is the CANCELLED member of
      // the frozen bounded reason vocabulary and never a free-text explanation.
      // Emitted only when the cancellation actually took effect, so a repeated
      // cancel of an identifier that is already gone records nothing.
      this.gatewayAuditSink.emit({
        eventType: 'DEVICE_ENROLLMENT_REJECTED',
        reason: 'CANCELLED',
        enrollmentId,
      });
      if (!(await this.flushGatewayAudit())) {
        return errorResponse('INTERNAL_ERROR');
      }
      return { ok: true, result: { enrollmentId, state: 'CANCELLED' } };
    } catch {
      return errorResponse('INTERNAL_ERROR');
    }
  }

  // -------------------------------------------------------------------------
  // RC-05 Task 9 handlers
  //
  // Every one of them resolves the attached authority first and refuses with
  // ADMINISTRATION_UNAVAILABLE when there is none. None of them reads, creates,
  // or falls back to a trust store of its own, and none of them touches the
  // trust-store file: the authority owns the ONE authoritative store and the
  // ONE durable transaction.
  // -------------------------------------------------------------------------

  /** Lists bounded metadata for every enrolled device. Never discloses pins. */
  private handleDevicesList(): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.listDevices());
  }

  /** Reports one device, including the active public SPKI pins it is bound to. */
  private handleDeviceInspect(deviceId: string): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.inspectDevice(deviceId));
  }

  /**
   * Revokes a device and, on a durable commit, every one of its live sessions.
   *
   * Nothing is reported as revoked until the trust-store revocation is durable,
   * and no success is returned until the device's Task-5 sessions and Task-8
   * transports are already gone.
   */
  private async handleDeviceRevoke(deviceId: string): Promise<AdminResponse> {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(await authority.revokeDevice(deviceId));
  }

  /** Replaces non-security display metadata. Changes no identity or binding. */
  private handleDeviceRename(deviceId: string, displayLabel: string): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.renameDevice(deviceId, displayLabel));
  }

  /** Adds one rotation-overlap pin, subject to the two-active-pin ceiling. */
  private handleDevicePinAdd(deviceId: string, spkiPin: string): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.addPin(deviceId, spkiPin));
  }

  /** Removes one pin. The final remaining pin can never be removed. */
  private handleDevicePinRemove(deviceId: string, spkiPin: string): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.removePin(deviceId, spkiPin));
  }

  /** Lists CURRENT LIVE sessions only. Never discloses tokens or digests. */
  private handleSessionsList(): AdminResponse {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(authority.listSessions());
  }

  /**
   * Revokes exactly one live session and tears down its Task-8 transport.
   *
   * An unknown, expired, or already-revoked identifier is a bounded refusal
   * that mutates nothing and can never disturb another session.
   */
  private async handleSessionRevoke(sessionId: string): Promise<AdminResponse> {
    const authority = this.deviceAdministration;
    if (authority === undefined) {
      return errorResponse('ADMINISTRATION_UNAVAILABLE');
    }
    return toAdminResponse(await authority.revokeSession(sessionId));
  }

  /** Maps an enrollment failure to a bounded admin code. Never leaks detail. */
  private mapEnrollmentError(err: unknown): AdminErrorCode {
    if (err instanceof ArcError) {
      if (err.code === 'RESOURCE_EXHAUSTED') return 'RESOURCE_EXHAUSTED';
      if (err.code === 'INVALID_REQUEST_SCHEMA') return 'INVALID_ADMIN_REQUEST';
    }
    return 'INTERNAL_ERROR';
  }

  /** Maps an approval failure to a bounded admin code. Never leaks detail. */
  private mapApprovalError(err: unknown): AdminErrorCode {
    if (err instanceof ArcError) {
      if (err.code === 'APPROVAL_EXPIRED') return 'APPROVAL_EXPIRED';
      if (err.code === 'APPROVAL_REJECTED') return 'APPROVAL_REJECTED';
      if (err.code === 'RESOURCE_EXHAUSTED') return 'RESOURCE_EXHAUSTED';
    }
    return 'INTERNAL_ERROR';
  }
}

function errorResponse(code: AdminErrorCode): AdminResponse {
  return { ok: false, error: { code } };
}

/**
 * True when `params` carries ONLY the named keys (RC-05 Task 9).
 *
 * The administration methods take a fixed, tiny parameter set, so it is
 * enumerated POSITIVELY here. Enumerating what is forbidden instead would mean
 * a parameter added to `AdminRequestParams` later could silently become
 * acceptable on a method that never intended to accept it.
 */
function paramsAreExactly(
  params: AdminRequestParams,
  allowed: readonly (keyof AdminRequestParams)[],
): boolean {
  return Object.keys(params).every((key) => (allowed as readonly string[]).includes(key));
}

/**
 * Validates an operator-supplied display label (RC-05 Task 9 `device.rename`).
 *
 * The 64 UTF-8 byte ceiling is the frozen Task-1 trust-store bound. NUL is
 * rejected here as well so an operator can never introduce a label the trust
 * store's read path would have to tolerate.
 */
function isAcceptableDisplayLabel(label: unknown): label is string {
  return (
    typeof label === 'string' &&
    !label.includes('\u0000') &&
    Buffer.byteLength(label, 'utf8') <= ADMIN_MAX_DISPLAY_LABEL_BYTES
  );
}

/**
 * Projects one bounded administration outcome onto the admin wire response.
 *
 * The authority already returns a bounded `AdminErrorCode`, so nothing an
 * internal failure carries can reach the operator through this mapping.
 */
function toAdminResponse<T extends AdminResult>(outcome: AdministrationOutcome<T>): AdminResponse {
  return outcome.ok ? { ok: true, result: outcome.result } : errorResponse(outcome.code);
}
