/**
 * Interface definition for Authentication Engine.
 * Implementation target: RC-05.
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
  MAX_CLIENT_IDENTIFIER_BYTES,
  MAX_ENROLLMENT_METADATA_BYTES,
} from './enrollment.js';
