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
import type { ApprovalReviewSummary } from './approval.js';
import type { KeyObject } from 'node:crypto';

/** Wire protocol identifier. Binds every signature to this protocol version. */
export const ADMIN_PROTOCOL_VERSION = 'cesspace-arc-admin-v1';

/**
 * Maximum admin methods are closed; arbitrary method strings are rejected.
 *
 * RC-05 Task 9 adds operator device and session administration. Those methods
 * are reachable ONLY here: there is no MCP administrative tool, no remote
 * operator control plane, and no HTTP or WebSocket admin API, so the Ed25519
 * challenge-response local channel remains the single administrative authority.
 */
export type AdminMethod =
  | 'approvals.list'
  | 'approvals.inspect'
  | 'approval.approve'
  | 'approval.reject'
  | 'enrollment.create'
  | 'enrollment.cancel'
  | 'devices.list'
  | 'devices.inspect'
  | 'device.revoke'
  | 'device.rename'
  | 'device.pin.add'
  | 'device.pin.remove'
  | 'sessions.list'
  | 'session.revoke';

export const ADMIN_METHODS: readonly AdminMethod[] = [
  'approvals.list',
  'approvals.inspect',
  'approval.approve',
  'approval.reject',
  'enrollment.create',
  'enrollment.cancel',
  'devices.list',
  'devices.inspect',
  'device.revoke',
  'device.rename',
  'device.pin.add',
  'device.pin.remove',
  'sessions.list',
  'session.revoke',
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

/**
 * Maximum operator-supplied device display label, in UTF-8 bytes.
 *
 * Mirrors the frozen Task-1 trust-store bound (rc05 §8). The server re-validates
 * against the authoritative domain rule; this constant exists so the CLI can
 * fail before opening a connection.
 */
export const ADMIN_MAX_DISPLAY_LABEL_BYTES = 64;

/** Maximum operator private key source accepted from the inherited FD. */
export const ADMIN_MAX_PRIVATE_KEY_SOURCE_BYTES = 16 * 1024;

/** Canonical lowercase approval request identifier shape. */
export const ADMIN_REQUEST_ID_REGEX = /^[0-9a-f]{32}$/;
/** Canonical ARC device identifier shape (rc05 §8). */
export const ADMIN_DEVICE_ID_REGEX = /^[0-9a-f]{32}$/;
/** Server-issued session identifier shape (rc05 §11). */
export const ADMIN_SESSION_ID_REGEX = /^[0-9a-f]{64}$/;
/** Canonical SPKI pin: SHA-256 of DER SPKI, 64 lowercase hexadecimal characters. */
export const ADMIN_SPKI_PIN_REGEX = /^[0-9a-f]{64}$/;
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
 *
 * RC-05 Task 2 adds the enrollment administration inputs. Everything that
 * identifies ARC-side state or authority — enrollmentId on creation, deviceId,
 * operator identity, TTL/deadline, attempt counters, and the one-time secret —
 * is deliberately absent: those are server-derived and a request carrying them
 * is rejected as an unknown parameter.
 */
export interface AdminRequestParams {
  requestId?: string;
  reason?: string;
  /** `enrollment.create`: operator-supplied logical client identity. */
  clientId?: string;
  /** `enrollment.create`: operator-supplied client type. */
  clientType?: string;
  /** `enrollment.create`: canonical 64-lowercase-hex SPKI pin to enroll. */
  spkiPin?: string;
  /** `enrollment.create`: optional non-security display label. */
  displayLabel?: string;
  /** `enrollment.cancel`: server-generated enrollment identifier. */
  enrollmentId?: string;
  /** `devices.*` / `device.*`: ARC-assigned enrolled device identifier. */
  deviceId?: string;
  /** `session.revoke`: server-issued session identifier. */
  sessionId?: string;
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
  /**
   * RC-05 Task 9: no authoritative device/session administration composition is
   * in effect, or the durable trust store's installed state can no longer be
   * vouched for.
   *
   * Both causes mean the same thing to an operator — the authority this request
   * would have acted on is not usable right now — and neither discloses which
   * it was, whether a trust store exists, or where it lives. Device and session
   * administration NEVER falls back to a second, locally loaded trust store:
   * an uncomposed authority is a refusal, not an empty view.
   */
  | 'ADMINISTRATION_UNAVAILABLE'
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
  /**
   * Safe bounded review metadata (target paths, content/patch/hash summaries).
   * Never raw material, never a token, never an absolute host path.
   */
  reviewSummary?: ApprovalReviewSummary;
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
  /** Safe bounded review metadata. Never a token, never an absolute host path. */
  reviewSummary?: ApprovalReviewSummary;
  /** Operator-only raw material, returned only while PENDING. */
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

/**
 * Bounded operator-safe view of a pending enrollment.
 *
 * Never contains the one-time secret, its digest, the operator public key, or
 * the internal monotonic deadline.
 */
export interface AdminEnrollmentSummary {
  enrollmentId: string;
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel: string;
  createdAt: string;
  expiresAt: string;
  remainingSeconds: number;
}

/**
 * Successful pending-enrollment creation.
 *
 * The one-time enrollment secret appears here and ONLY here: on the
 * authenticated local admin channel, exactly once, to the authenticated
 * operator. It is never audited, logged, persisted, echoed in an error, or
 * retained by the IPC server.
 */
export interface AdminEnrollmentCreateResult {
  enrollment: AdminEnrollmentSummary;
  /** 64 lowercase hexadecimal characters. Disclosed exactly once. */
  secret: string;
}

export interface AdminEnrollmentCancelResult {
  enrollmentId: string;
  state: string;
}

// ---------------------------------------------------------------------------
// RC-05 Task 9: device and session administration
//
// Every view here is a SNAPSHOT built field by field from the authoritative
// record. None carries a raw token, a token digest, a private key, certificate
// bytes, a bound SPKI pin outside the pin-administration views, a rate-limiter
// key, an authorization header, or a monotonic internal timestamp.
// ---------------------------------------------------------------------------

/**
 * Bounded device view for `devices.list`.
 *
 * Deliberately carries the ACTIVE PIN COUNT rather than the pin set, so the
 * routine listing step does not put every trust anchor on the operator's
 * terminal. `devices.inspect` is where the exact pins are disclosed, because
 * that is the step that administers the rotation overlap window.
 */
export interface AdminDeviceSummary {
  deviceId: string;
  clientId: string;
  clientType: string;
  displayLabel: string;
  enrolledAt: string;
  revoked: boolean;
  activePinCount: number;
}

export interface AdminDevicesListResult {
  devices: AdminDeviceSummary[];
}

/**
 * `devices.inspect` view: the list projection plus the exact active SPKI pins.
 *
 * The pins are public values — the SHA-256 of a DER SubjectPublicKeyInfo — and
 * the authenticated operator needs them verbatim to add or remove the
 * rotation-overlap pin. Nothing private is added.
 */
export interface AdminDeviceInspectResult extends AdminDeviceSummary {
  /** At most 2 public SPKI pins (the frozen §7 P-7 active-pin ceiling). */
  pins: string[];
}

/**
 * Successful device revocation.
 *
 * `sessionsRevoked` is the count of live gateway sessions the revocation closed,
 * and `transportsClosed` the count of Task-8 transport registry entries torn
 * down with them. Both are counts, never identities, and both are already
 * complete when this result is returned.
 */
export interface AdminDeviceRevokeResult {
  deviceId: string;
  revoked: true;
  sessionsRevoked: number;
  transportsClosed: number;
}

export interface AdminDeviceRenameResult {
  deviceId: string;
  displayLabel: string;
}

/** Successful pin addition or removal. Reports the resulting active pin count. */
export interface AdminDevicePinMutationResult {
  deviceId: string;
  activePinCount: number;
}

/**
 * Bounded live-session view for `sessions.list`.
 *
 * Structurally the Task-5 `SessionView`: only live sessions exist, so there is
 * no revoked or expired state to report and no tombstone to leak.
 */
export interface AdminSessionSummary {
  sessionId: string;
  deviceId: string;
  clientId: string;
  clientType: string;
  issuedAt: string;
  state: 'ACTIVE';
}

export interface AdminSessionsListResult {
  sessions: AdminSessionSummary[];
}

export interface AdminSessionRevokeResult {
  sessionId: string;
  state: 'REVOKED';
  transportClosed: boolean;
}

export type AdminResult =
  | AdminApprovalsListResult
  | AdminApprovalsInspectResult
  | AdminApprovalApproveResult
  | AdminApprovalRejectResult
  | AdminEnrollmentCreateResult
  | AdminEnrollmentCancelResult
  | AdminDevicesListResult
  | AdminDeviceInspectResult
  | AdminDeviceRevokeResult
  | AdminDeviceRenameResult
  | AdminDevicePinMutationResult
  | AdminSessionsListResult
  | AdminSessionRevokeResult;

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

/**
 * Closed parameter key set, in ascending code-unit order.
 *
 * The order is what makes the canonical encoding deterministic; adding a key
 * here in the wrong position would produce a non-canonical byte form for every
 * request that uses it.
 */
const ADMIN_PARAM_KEYS: readonly (keyof AdminRequestParams)[] = [
  'clientId',
  'clientType',
  'deviceId',
  'displayLabel',
  'enrollmentId',
  'reason',
  'requestId',
  'sessionId',
  'spkiPin',
];

/** Canonically encodes an admin payload to its exact signed byte form. */
export function encodeAdminPayload(payload: AdminRequestPayload): string {
  const paramsJson = `{${ADMIN_PARAM_KEYS.filter((key) => payload.params[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${JSON.stringify(payload.params[key])}`)
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
