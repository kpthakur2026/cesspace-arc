/**
 * Legacy placeholder interface.
 *
 * NOT the RC-05 session model. RC-05 session tokens are opaque and carry zero
 * structured claims — no clientId, clientType, deviceId, sessionId, or expiry
 * inside the token — so a claim-bearing token shape cannot express them. The
 * authoritative RC-05 implementation is the session domain in `session.ts`,
 * exported below; nothing in RC-05 implements or consumes these declarations.
 */
export interface AuthTokenClaims {
  clientId: string;
  clientType: string;
  deviceId: string;
  issuedAt: number;
  expiresAt: number;
}

export interface IAuthEngine {
  verifyToken(token: string): Promise<AuthTokenClaims>;
  generateSessionToken(claims: Omit<AuthTokenClaims, 'issuedAt' | 'expiresAt'>): Promise<string>;
}

export * from './device-identity.js';

export {
  type DeviceTrustStoreData,
  validateTrustStoreData,
  assertValidTrustStorePath,
  type MinimalTrustStoreFileStat,
  type MinimalTrustStoreDirStat,
  validateTrustStoreFileStat,
  validateTrustStoreParentDirectoryStat,
  verifyTrustStoreFileIntegrity,
  atomicPersistTrustStore,
  DeviceTrustStore,
} from './trust-store.js';

/**
 * RC-05 Task 2: operator-mediated pending enrollment lifecycle.
 *
 * Pure domain logic. No transport, no session, no trust-store mutation. The
 * consume primitive is exported for Task 4 to call after mTLS/SPKI proof; it is
 * not reachable from any Task-2 admin method.
 */
export {
  EnrollmentManager,
  deriveOperatorId,
  type EnrollmentManagerOptions,
  type PendingEnrollmentView,
  type CreatedEnrollment,
  type CreateEnrollmentInput,
  type ConsumeOutcome,
  ENROLLMENT_TTL_SECONDS,
  ENROLLMENT_ID_HEX_LENGTH,
  ENROLLMENT_ID_REGEX,
  ENROLLMENT_SECRET_HEX_LENGTH,
  ENROLLMENT_SECRET_REGEX,
  OPERATOR_ID_REGEX,
  MAX_PENDING_ENROLLMENTS_GLOBAL,
  MAX_PENDING_ENROLLMENTS_PER_OPERATOR,
  MAX_FAILED_SECRET_ATTEMPTS,
  MAX_ENROLLMENT_METADATA_BYTES,
} from './enrollment.js';

/**
 * RC-05 Task 5: secure session lifecycle.
 *
 * Pure domain logic: no network I/O, no filesystem I/O, no HTTP server, no MCP
 * SDK transport, no policy evaluation, no approval redemption, and no subsystem
 * or tool dispatch. The manager owns server session IDs, digest-only session
 * tokens, binding, monotonic expiry, revocation, active-session quotas, and the
 * pure wire-admission decisions Task 8 will connect to the remote transport.
 */
export {
  SessionManager,
  resolveActiveDeviceIdentity,
  parseBearerCredential,
  isWellFormedSessionId,
  type SessionManagerOptions,
  type TrustedSessionIdentity,
  type TrustedSessionResult,
  type SessionIssuance,
  type SessionView,
  type SessionRequestKind,
  type SessionRequestContext,
  type SessionAdmissionDecision,
  SESSION_HEX_LENGTH,
  SESSION_ID_REGEX,
  SESSION_TOKEN_REGEX,
  MAX_SESSION_TOKEN_INPUT_BYTES,
  MAX_SESSION_AUTHORIZATION_HEADER_BYTES,
  SESSION_ID_RESERVATION_TTL_SECONDS,
  SESSION_ABSOLUTE_TTL_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  MAX_ACTIVE_SESSIONS_PER_DEVICE,
  MAX_ACTIVE_SESSIONS_PER_CLIENT,
  MAX_ACTIVE_SESSIONS_GLOBAL,
  MAX_SESSION_ID_GENERATION_ATTEMPTS,
  ARC_SESSION_TOKEN_HEADER,
  MCP_SESSION_ID_HEADER,
  SESSION_AUTH_SCHEME,
} from './session.js';
