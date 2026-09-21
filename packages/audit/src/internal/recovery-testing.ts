import type { StorageTestFaults } from './storage-capability.js';
import type { PersistentAuditStorageConfig } from '../storage.js';
import type { TrustedPrimaryChainBoundary, AuditRecoveryResult } from '../recovery.js';
import { executeAuditRecoveryInternal } from '../recovery.js';

/**
 * Test-only fault hooks and callbacks for validating crash recovery,
 * torn tail handling, and dangling operation reconciliation failure modes.
 *
 * Strictly package-internal; not exposed through public package exports.
 */
export interface RecoveryTestHooks {
  sidecarTimestamp?: string;
  failSidecarCreation?: boolean;
  failSidecarWrite?: boolean;
  failSidecarSync?: boolean;
  failTruncation?: boolean;
  beforeTruncate?: () => void;
  beforeFinalAppendOpen?: () => void;
  storageTestFaults?: StorageTestFaults;
  failRecoveryAppendAtIndex?: number;
}

export interface TestAuditRecoveryOptions {
  trustedBoundary?: TrustedPrimaryChainBoundary;
  testHooks?: RecoveryTestHooks;
}

/**
 * Internal test runner for audit recovery with injected test hooks and faults.
 */
export async function recoverPersistentAuditStorageForTest(
  config: PersistentAuditStorageConfig,
  options?: TestAuditRecoveryOptions,
): Promise<AuditRecoveryResult> {
  return executeAuditRecoveryInternal(config, options?.trustedBoundary, options?.testHooks);
}
