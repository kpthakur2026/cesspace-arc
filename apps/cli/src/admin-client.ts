/**
 * CesSpace ARC — RC-04 Admin IPC Client
 *
 * Operator-side half of the authenticated local admin channel.
 *
 * Private key handling (frozen for RC-04):
 * - The private key is accepted ONLY from an already-open inherited file
 *   descriptor. It is never accepted through argv, environment bytes, a config
 *   file, a policy file, or any MCP parameter.
 * - Only the integer FD NUMBER may appear in argv or the environment.
 * - The key source is read once, imported, and the descriptor is closed.
 *
 * This module never logs, formats, or embeds key material in errors.
 */

import net from 'node:net';
import fs from 'node:fs';

import {
  ADMIN_CHALLENGE_ID_REGEX,
  ADMIN_CHALLENGE_TTL_MS,
  ADMIN_MAX_CHALLENGE_FRAME_BYTES,
  ADMIN_MAX_PRIVATE_KEY_SOURCE_BYTES,
  ADMIN_MAX_RESPONSE_FRAME_BYTES,
  ADMIN_NONCE_REGEX,
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  importOperatorPrivateKey,
  signAdminPayload,
  type AdminChallenge,
  type AdminMethod,
  type AdminRequestParams,
  type AdminResponse,
} from '@cesspace-arc/protocol';
import type { KeyObject } from 'node:crypto';

/** Failure raised for operator-facing admin client problems. */
export class AdminClientError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
  ) {
    super(message);
    this.name = 'AdminClientError';
  }
}

/**
 * Reads an operator private key from an inherited file descriptor.
 *
 * The source is base64-encoded DER PKCS#8 Ed25519, bounded to 16 KiB exactly
 * (an exactly-16 KiB source is accepted; anything larger is rejected). The
 * descriptor is closed and the single mutable source buffer is overwritten
 * before returning, whether or not the import succeeded.
 *
 * Bounded memory claim: ARC best-effort overwrites mutable temporary Buffers
 * that ARC controls. It does NOT claim that JavaScript strings, V8 internal
 * copies, or OpenSSL internal memory are zeroized.
 */
export function readPrivateKeyFromFd(
  fd: unknown,
  readSync: typeof fs.readSync = fs.readSync,
  closeSync: typeof fs.closeSync = fs.closeSync,
): KeyObject {
  if (typeof fd !== 'number' || !Number.isInteger(fd) || fd < 0) {
    throw new AdminClientError('Admin key file descriptor is not a valid number.', 'FD_INVALID');
  }

  let closed = false;
  const closeOnce = (): void => {
    if (!closed) {
      closed = true;
      try {
        closeSync(fd);
      } catch {
        // Descriptor already closed; nothing further to release.
      }
    }
  };

  // One preallocated mutable buffer holds the entire key source. Capacity is
  // one byte beyond the permitted maximum, which is enough to distinguish an
  // exactly-at-limit source from an oversized one without any scratch buffer,
  // chunk copies, or concatenation step.
  const capacity = ADMIN_MAX_PRIVATE_KEY_SOURCE_BYTES + 1;
  const source = Buffer.alloc(capacity);
  let total = 0;
  let text: string;

  try {
    for (;;) {
      let bytesRead = 0;
      try {
        bytesRead = readSync(fd, source, total, capacity - total, null);
      } catch {
        throw new AdminClientError('Admin key source could not be read.', 'FD_READ_FAILED');
      }
      if (bytesRead === 0) {
        break;
      }
      total += bytesRead;
      if (total > ADMIN_MAX_PRIVATE_KEY_SOURCE_BYTES) {
        throw new AdminClientError('Admin key source exceeds the permitted size.', 'KEY_TOO_LARGE');
      }
    }

    if (total === 0) {
      throw new AdminClientError('Admin key source was empty.', 'KEY_EMPTY');
    }

    // subarray is a view, not a copy: no additional key-bearing buffer exists.
    text = source.subarray(0, total).toString('utf8');
  } finally {
    closeOnce();
    // Best-effort overwrite of the single mutable key-source buffer, on every
    // path: success, empty source, oversized source, read failure, or malformed
    // key. JavaScript strings and OpenSSL internal copies are NOT claimed to be
    // cryptographically zeroized, and the imported KeyObject is not destroyed.
    source.fill(0);
  }

  const privateKey = importOperatorPrivateKey(text.trim());
  if (privateKey === null) {
    throw new AdminClientError(
      'Admin key must be a base64 DER PKCS#8 Ed25519 private key.',
      'KEY_INVALID',
    );
  }
  return privateKey;
}

export interface AdminIpcClientOptions {
  /** Absolute path of the local admin Unix socket. */
  endpoint: string;
  /** Trusted operator private key, imported from the inherited FD. */
  privateKey: KeyObject;
  /** Injectable monotonic clock for deadline assertions. */
  getMonotonicTimeMs?: () => number;
}

/**
 * One-shot admin IPC client.
 *
 * Connect, receive the challenge, sign the challenge-bound request, send exactly
 * one envelope, read one bounded response, close. There is no HTTP or TCP
 * fallback of any kind.
 */
export class AdminIpcClient {
  private readonly endpoint: string;
  private readonly privateKey: KeyObject;

  constructor(options: AdminIpcClientOptions) {
    if (typeof options?.endpoint !== 'string' || options.endpoint.length === 0) {
      throw new AdminClientError('Admin endpoint is required.', 'ENDPOINT_MISSING');
    }
    if (options.privateKey === null || typeof options.privateKey !== 'object') {
      throw new AdminClientError('Admin private key is required.', 'KEY_MISSING');
    }
    this.endpoint = options.endpoint;
    this.privateKey = options.privateKey;
  }

  /** Performs one authenticated admin operation over a fresh connection. */
  public async request(
    method: AdminMethod,
    params: AdminRequestParams = {},
  ): Promise<AdminResponse> {
    const socket = await this.connect();
    try {
      const challenge = await this.receiveChallenge(socket);
      const payloadBytes = this.buildSignedPayload(challenge, method, params);
      socket.write(`${JSON.stringify(payloadBytes)}\n`);
      const response = await this.readResponse(socket);
      return response;
    } finally {
      socket.destroy();
    }
  }

  private connect(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.endpoint);
      const onError = (): void => {
        socket.removeListener('connect', onConnect);
        reject(
          new AdminClientError('Could not connect to the local admin channel.', 'CONNECT_FAILED'),
        );
      };
      const onConnect = (): void => {
        socket.removeListener('error', onError);
        resolve(socket);
      };
      socket.once('error', onError);
      socket.once('connect', onConnect);
      socket.setTimeout(ADMIN_CHALLENGE_TTL_MS * 4);
    });
  }

  /** Validates the received challenge before any signature is produced. */
  private async receiveChallenge(socket: net.Socket): Promise<AdminChallenge> {
    const frame = await this.readFrame(socket, ADMIN_MAX_CHALLENGE_FRAME_BYTES);
    if (frame === null) {
      throw new AdminClientError('Admin challenge was not received.', 'CHALLENGE_MISSING');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(frame.toString('utf8'));
    } catch {
      throw new AdminClientError('Admin challenge was malformed.', 'CHALLENGE_MALFORMED');
    }
    if (parsed === null || typeof parsed !== 'object') {
      throw new AdminClientError('Admin challenge was malformed.', 'CHALLENGE_MALFORMED');
    }
    const challenge = parsed as Partial<AdminChallenge>;
    if (
      challenge.protocol !== ADMIN_PROTOCOL_VERSION ||
      typeof challenge.challengeId !== 'string' ||
      !ADMIN_CHALLENGE_ID_REGEX.test(challenge.challengeId) ||
      typeof challenge.nonce !== 'string' ||
      !ADMIN_NONCE_REGEX.test(challenge.nonce)
    ) {
      throw new AdminClientError('Admin challenge was malformed.', 'CHALLENGE_MALFORMED');
    }
    return {
      protocol: challenge.protocol,
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      expiresInMs:
        typeof challenge.expiresInMs === 'number' ? challenge.expiresInMs : ADMIN_CHALLENGE_TTL_MS,
    };
  }

  /** Builds the canonical, challenge-bound signed envelope. */
  private buildSignedPayload(
    challenge: AdminChallenge,
    method: AdminMethod,
    params: AdminRequestParams,
  ): { payload: string; signature: string } {
    const canonical = encodeAdminPayload({
      protocol: ADMIN_PROTOCOL_VERSION,
      challengeId: challenge.challengeId,
      method,
      params,
    });
    const payloadBytes = Buffer.from(canonical, 'utf8');
    const signature = signAdminPayload(
      this.privateKey,
      challenge.challengeId,
      challenge.nonce,
      payloadBytes,
    );
    return {
      payload: payloadBytes.toString('base64'),
      signature: signature.toString('base64'),
    };
  }

  private readResponse(socket: net.Socket): Promise<AdminResponse> {
    return this.readFrame(socket, ADMIN_MAX_RESPONSE_FRAME_BYTES).then((frame) => {
      if (frame === null) {
        throw new AdminClientError('Admin response was not received.', 'RESPONSE_MISSING');
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(frame.toString('utf8'));
      } catch {
        throw new AdminClientError('Admin response was malformed.', 'RESPONSE_MALFORMED');
      }
      if (
        parsed === null ||
        typeof parsed !== 'object' ||
        typeof (parsed as AdminResponse).ok !== 'boolean'
      ) {
        throw new AdminClientError('Admin response was malformed.', 'RESPONSE_MALFORMED');
      }
      return parsed as AdminResponse;
    });
  }

  /** Reads exactly one newline-delimited frame with a hard byte bound. */
  private readFrame(socket: net.Socket, maxBytes: number): Promise<Buffer | null> {
    return new Promise((resolve) => {
      let buffer = Buffer.alloc(0);
      let settled = false;
      const finish = (value: Buffer | null): void => {
        if (settled) return;
        settled = true;
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onClose);
        socket.removeListener('error', onError);
        socket.removeListener('timeout', onTimeout);
        resolve(value);
      };
      const onData = (chunk: Buffer): void => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > maxBytes) {
          finish(null);
          return;
        }
        const newlineAt = buffer.indexOf(0x0a);
        if (newlineAt !== -1) {
          finish(buffer.subarray(0, newlineAt));
        }
      };
      const onEnd = (): void => finish(null);
      const onClose = (): void => finish(null);
      const onError = (): void => finish(null);
      const onTimeout = (): void => finish(null);

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onClose);
      socket.on('error', onError);
      socket.on('timeout', onTimeout);
    });
  }
}
