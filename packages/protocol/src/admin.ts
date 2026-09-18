/**
 * CesSpace ARC — RC-04 Local Operator Administrative Channel Protocol
 *
 * Shared contract for the authenticated local IPC channel between
 * apps/cli (operator) and apps/mcp-server (ARC control plane).
 *
 * Trust boundary (rc04-scope-acceptance.md §24.1):
 * - Approval administration is NEVER an MCP tool or capability.
 * - The channel is local IPC only: no HTTP, SSE, WebSocket, or TCP listener.
 * - Local socket access is NOT operator identity. Every admin request is
 *   authenticated by an Ed25519 challenge-response proof of possession of the
 *   operator private key, because a same-UID local agent process can also
 *   connect to a Unix socket.
 *
 * This module intentionally contains NO private-key material, and NO MCP-facing
 * schema. The operator private key exists only on the operator side, inside the
 * CLI process, imported from an inherited file descriptor.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/** Wire protocol identifier. Binds every signature to this protocol version. */
export const ADMIN_PROTOCOL_VERSION = 'cesspace-arc-admin-v1';

/** Maximum admin methods are closed; arbitrary method strings are rejected. */
export type AdminMethod =
  'approvals.list' | 'approvals.inspect' | 'approval.approve' | 'approval.reject';

export const ADMIN_METHODS: readonly AdminMethod[] = [
  'approvals.list',
  'approvals.inspect',
  'approval.approve',
  'approval.reject',
] as const;

/** Challenge lifetime in milliseconds, enforced on a monotonic clock. */
export const ADMIN_CHALLENGE_TTL_MS = 5000;

/** Maximum request envelope frame (newline-delimited JSON), in UTF-8 bytes. */
export const ADMIN_MAX_REQUEST_FRAME_BYTES = 32 * 1024;

/** Maximum challenge frame, in UTF-8 bytes. */
export const ADMIN_MAX_CHALLENGE_FRAME_BYTES = 4 * 1024;

/**
 * Maximum response frame, in UTF-8 bytes.
 *
 * Sized to carry one full 1 MiB per-record review-material bound plus JSON
 * escaping, with generous headroom.
 */
export const ADMIN_MAX_RESPONSE_FRAME_BYTES = 8 * 1024 * 1024;

/** Maximum operator-supplied rejection reason, in UTF-8 bytes. */
export const ADMIN_MAX_REASON_BYTES = 256;

/** Maximum operator private key source accepted from the inherited FD. */
export const ADMIN_MAX_PRIVATE_KEY_SOURCE_BYTES = 16 * 1024;

/** Canonical lowercase approval request identifier shape. */
export const ADMIN_REQUEST_ID_REGEX = /^[0-9a-f]{32}$/;
/** Server-generated challenge identifier shape. */
export const ADMIN_CHALLENGE_ID_REGEX = /^[0-9a-f]{32}$/;
/** Server-generated nonce shape. */
export const ADMIN_NONCE_REGEX = /^[0-9a-f]{64}$/;

/**
 * Server-issued one-shot challenge.
 * Sent in clear on the local channel; it is not a secret credential.
 */
export interface AdminChallenge {
  protocol: string;
  challengeId: string;
  nonce: string;
  expiresInMs: number;
}

/**
 * Parameters for an admin request. The shape is closed per method and is
 * validated again after signature verification.
 */
export interface AdminRequestParams {
  requestId?: string;
  reason?: string;
}

/** Canonical signed admin payload. */
export interface AdminRequestPayload {
  protocol: string;
  challengeId: string;
  method: AdminMethod;
  params: AdminRequestParams;
}

/** Signed wire envelope. Contains no private key and no reusable credential. */
export interface AdminSignedEnvelope {
  payload: string; // base64 of the canonical payload bytes
  signature: string; // base64 of the Ed25519 signature
}

/**
 * Bounded admin error codes.
 *
 * These are safe, coarse categories. They never carry stack traces, parser
 * text, filesystem paths, key material, signature bytes, or review material.
 */
export type AdminErrorCode =
  | 'AUTHENTICATION_FAILED'
  | 'INVALID_ADMIN_REQUEST'
  | 'NOT_FOUND_OR_NOT_PENDING'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_REJECTED'
  | 'RESOURCE_EXHAUSTED'
  | 'INTERNAL_ERROR';

/** Bounded pending-approval summary. Never contains review material or tokens. */
export interface AdminApprovalSummary {
  requestId: string;
  toolName: string;
  state: string;
  workspaceId: string;
  clientId: string;
  clientType: string;
  sessionId?: string;
  deviceId?: string;
  createdAt: string;
  expiresAt: string;
  remainingSeconds: number;
  reviewMaterialBytes: number;
}

export interface AdminApprovalsListResult {
  approvals: AdminApprovalSummary[];
}

/** Detailed operator review view. Contains review material, never a token. */
export interface AdminApprovalsInspectResult {
  requestId: string;
  toolName: string;
  state: string;
  workspaceId: string;
  clientId: string;
  clientType: string;
  sessionId?: string;
  deviceId?: string;
  createdAt: string;
  expiresAt: string;
  remainingSeconds: number;
  reviewMaterial: string;
}

/**
 * Successful approval result.
 *
 * The raw token appears ONLY here, and only on the authenticated admin channel.
 * It is never logged, persisted, audited, or retained by the IPC server.
 */
export interface AdminApprovalApproveResult {
  requestId: string;
  state: string;
  token: string;
  expiresAt: string;
  remainingSeconds: number;
}

export interface AdminApprovalRejectResult {
  requestId: string;
  state: string;
}

export type AdminResult =
  | AdminApprovalsListResult
  | AdminApprovalsInspectResult
  | AdminApprovalApproveResult
  | AdminApprovalRejectResult;

/** Bounded admin response frame. */
export interface AdminResponse {
  ok: boolean;
  result?: AdminResult;
  error?: {
    code: AdminErrorCode;
  };
}

// ---------------------------------------------------------------------------
// Canonical encoding
//
// The admin payload shape is closed and small, so it is encoded by an explicit
// deterministic construction rather than a generic canonicalizer. Object keys
// are emitted in ascending code-unit order, matching the canonical-JSON
// convention used for policy hashing in @cesspace-arc/policy.
//
// This is deliberately NOT imported from @cesspace-arc/policy: packages/policy
// depends on packages/protocol, so the reverse import would be circular.
// tests/rc04-admin-ipc.test.js asserts byte equality with the policy
// canonicalJson() for the same value, which keeps the two conventions aligned.
// ---------------------------------------------------------------------------

/** Canonically encodes an admin payload to its exact signed byte form. */
export function encodeAdminPayload(payload: AdminRequestPayload): string {
  const paramKeys: string[] = [];
  // Ascending code-unit order: "reason" < "requestId".
  if (payload.params.reason !== undefined) paramKeys.push('reason');
  if (payload.params.requestId !== undefined) paramKeys.push('requestId');

  const paramsJson = `{${paramKeys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${JSON.stringify(payload.params[key as keyof AdminRequestParams])}`,
    )
    .join(',')}}`;

  // Ascending code-unit order: challengeId < method < params < protocol.
  return `{${[
    `"challengeId":${JSON.stringify(payload.challengeId)}`,
    `"method":${JSON.stringify(payload.method)}`,
    `"params":${paramsJson}`,
    `"protocol":${JSON.stringify(payload.protocol)}`,
  ].join(',')}}`;
}

/**
 * Builds the exact bytes signed by the operator and verified by the server.
 *
 * Domain-separated construction:
 *   "cesspace-arc-admin-v1" NUL challengeId NUL nonce NUL SHA-256(payloadBytes)
 *
 * The SHA-256 term is appended as 64 lowercase hexadecimal characters, so the
 * layout stays self-delimiting. Both sides MUST use this single implementation.
 */
export function buildAdminSignatureMessage(
  challengeId: string,
  nonce: string,
  payloadBytes: Buffer,
): Buffer {
  const payloadDigest = createHash('sha256').update(payloadBytes).digest('hex');
  return Buffer.from(
    `${ADMIN_PROTOCOL_VERSION}\0${challengeId}\0${nonce}\0${payloadDigest}`,
    'utf8',
  );
}

/**
 * Signs an admin payload. Ed25519 only; the algorithm is implied by the key.
 *
 * The private key never leaves the operator side.
 */
export function signAdminPayload(
  privateKey: KeyObject,
  challengeId: string,
  nonce: string,
  payloadBytes: Buffer,
): Buffer {
  const message = buildAdminSignatureMessage(challengeId, nonce, payloadBytes);
  return sign(null, message, privateKey);
}

/**
 * Verifies an admin payload signature. Ed25519 only.
 *
 * Returns false for any malformed input rather than throwing, so callers fail
 * closed without leaking cryptographic detail.
 */
export function verifyAdminPayload(
  publicKey: KeyObject,
  challengeId: string,
  nonce: string,
  payloadBytes: Buffer,
  signature: Buffer,
): boolean {
  try {
    const message = buildAdminSignatureMessage(challengeId, nonce, payloadBytes);
    return verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Key import
// ---------------------------------------------------------------------------

/**
 * Strict base64 decoding.
 *
 * Buffer.from(value, 'base64') silently ignores invalid characters, so the
 * input is validated against the base64 alphabet and canonical form first.
 *
 * Every rejection that occurs AFTER the decoded Buffer is allocated overwrites
 * that buffer before returning. This matters for private-key input: a
 * non-canonical encoding with unused padding bits (for example `AB==` instead
 * of `AA==`) decodes to the same secret bytes while failing the canonical
 * round-trip, so the caller never receives the buffer and cannot wipe it.
 */
export function decodeBase64Strict(value: unknown): Buffer | null {
  // Rejections below occur before allocation, so there is nothing to wipe.
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  if (value.length % 4 !== 0) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    return null;
  }

  const decoded = Buffer.from(value, 'base64');
  // Re-encoding must round-trip exactly: rejects non-canonical padding.
  if (decoded.toString('base64') !== value) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}

/**
 * Imports an operator Ed25519 private key from base64-encoded DER PKCS#8.
 * Returns null for any other key type or malformed input.
 *
 * The decoded DER Buffer holds private key material, so it is best-effort
 * overwritten once createPrivateKey() has consumed it. The resulting KeyObject
 * is not destroyed and remains fully usable.
 */
export function importOperatorPrivateKey(base64Der: string): KeyObject | null {
  const der = decodeBase64Strict(base64Der);
  if (der === null || der.length === 0) {
    return null;
  }
  try {
    let key: KeyObject;
    try {
      key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    } catch {
      return null;
    }
    if (key.asymmetricKeyType !== 'ed25519') {
      return null;
    }
    return key;
  } finally {
    // Best-effort overwrite of the mutable decoded private DER buffer, on every
    // path: successful import, wrong key type, and createPrivateKey failure.
    der.fill(0);
  }
}

/**
 * Imports an operator Ed25519 public key from base64-encoded DER SPKI.
 * Returns null for any other key type or malformed input.
 */
export function importOperatorPublicKey(base64Der: string): KeyObject | null {
  const der = decodeBase64Strict(base64Der);
  if (der === null || der.length === 0) {
    return null;
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    return null;
  }
  return key;
}

/** Exports a public key as base64-encoded DER SPKI (for test/config plumbing). */
export function exportPublicKeyB64(publicKey: KeyObject): string {
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

/** Exports a private key as base64-encoded DER PKCS#8 (test key generation only). */
export function exportPrivateKeyB64(privateKey: KeyObject): string {
  return privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
}
