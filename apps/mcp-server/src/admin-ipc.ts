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
  ADMIN_MAX_CHALLENGE_FRAME_BYTES,
  ADMIN_MAX_REASON_BYTES,
  ADMIN_MAX_REQUEST_FRAME_BYTES,
  ADMIN_MAX_RESPONSE_FRAME_BYTES,
  ADMIN_METHODS,
  ADMIN_PROTOCOL_VERSION,
  ADMIN_REQUEST_ID_REGEX,
  ArcError,
  decodeBase64Strict,
  encodeAdminPayload,
  importOperatorPublicKey,
  verifyAdminPayload,
  type AdminApprovalSummary,
  type AdminChallenge,
  type AdminErrorCode,
  type AdminMethod,
  type AdminRequestPayload,
  type AdminResponse,
} from '@cesspace-arc/protocol';
import type { ApprovalStateManager } from '@cesspace-arc/policy';
import { toAdminSummary } from './approval-gate.js';

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

  private server?: net.Server;
  private socketIdentity?: SocketIdentity;
  private started = false;

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

    const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    this.endpoint = assertSafeEndpoint(options.endpoint, currentUid);

    this.getMonotonicTimeMs = options.getMonotonicTimeMs ?? (() => performance.now());
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

      const response = this.processAuthenticatedFrame(frame, challengeId, nonce, issuedAtMs);
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
  private processAuthenticatedFrame(
    frame: Buffer,
    challengeId: string,
    nonce: string,
    issuedAtMs: number,
  ): AdminResponse {
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
    const params: { requestId?: string; reason?: string } = {};
    for (const key of Object.keys(rawParams as Record<string, unknown>)) {
      const value = (rawParams as Record<string, unknown>)[key];
      if (key === 'requestId') {
        if (typeof value !== 'string') return null;
        params.requestId = value;
      } else if (key === 'reason') {
        if (typeof value !== 'string') return null;
        params.reason = value;
      } else {
        // Unexpected params are rejected.
        return null;
      }
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

  private dispatch(payload: AdminRequestPayload): AdminResponse {
    const { method, params } = payload;

    if (method === 'approvals.list') {
      if (params.requestId !== undefined || params.reason !== undefined) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleList();
    }

    if (method === 'approvals.inspect') {
      if (params.requestId === undefined || params.reason !== undefined) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ADMIN_REQUEST_ID_REGEX.test(params.requestId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleInspect(params.requestId);
    }

    if (method === 'approval.approve') {
      if (params.requestId === undefined || params.reason !== undefined) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      if (!ADMIN_REQUEST_ID_REGEX.test(params.requestId)) {
        return errorResponse('INVALID_ADMIN_REQUEST');
      }
      return this.handleApprove(params.requestId);
    }

    if (method === 'approval.reject') {
      if (params.requestId === undefined) {
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
      return this.handleReject(params.requestId);
    }

    return errorResponse('INVALID_ADMIN_REQUEST');
  }

  private handleList(): AdminResponse {
    // Purge expired state before listing so the operator never sees a stale
    // PENDING entry.
    this.approvalStateManager.purgeExpired();

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

  private handleInspect(requestId: string): AdminResponse {
    const snapshot = this.approvalStateManager.getRequest(requestId);
    // Terminal states are reported identically to unknown IDs so this method
    // does not become an existence oracle for non-pending records.
    if (snapshot === undefined || snapshot.state !== 'PENDING') {
      return errorResponse('NOT_FOUND_OR_NOT_PENDING');
    }
    const reviewMaterial = this.approvalStateManager.inspectPending(requestId) ?? '';
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

  private handleApprove(requestId: string): AdminResponse {
    try {
      const grant = this.approvalStateManager.approve(requestId);
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
      return errorResponse(this.mapApprovalError(err));
    }
  }

  private handleReject(requestId: string): AdminResponse {
    try {
      // The operator-supplied reason is validated by the caller but is NOT
      // persisted: approval audit lifecycle integration belongs to Task 5.
      const snapshot = this.approvalStateManager.reject(requestId);
      return { ok: true, result: { requestId: snapshot.requestId, state: snapshot.state } };
    } catch (err: unknown) {
      return errorResponse(this.mapApprovalError(err));
    }
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
