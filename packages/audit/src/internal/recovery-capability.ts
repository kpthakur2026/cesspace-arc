import type { AuditLockAcquisition } from '../lock.js';
import type { AuditStoreMetadataV1 } from '@cesspace-arc/protocol';

/**
 * Unforgeable package-private symbol used exclusively to authorize
 * persistent audit storage initialization from the verified recovery path.
 *
 * This symbol is strictly confined to package-internal modules and MUST NOT
 * be exported from the package root or any public export subpath.
 */
export const RECOVERY_HANDOFF_TOKEN = Symbol('RECOVERY_HANDOFF_TOKEN');

export interface VerifiedRecoveryHandoff {
  lock: AuditLockAcquisition;
  metadata: AuditStoreMetadataV1;
  activeFd: number;
  terminalSequence: number;
  terminalRecordHash: string;
  verifiedActiveIdentity: { dev: number; ino: number };
}
