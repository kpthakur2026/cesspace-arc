import type { PersistentAuditStorageConfig } from '../storage.js';
import { PersistentAuditStorage } from '../storage.js';
import {
  STORAGE_TEST_TOKEN,
  type StorageTestFaults,
  type StorageTestHooks,
} from './storage-capability.js';

export type { StorageTestFaults, StorageTestHooks };

/**
 * Package-internal test factory for PersistentAuditStorage with injected test faults and hooks.
 *
 * Exposes test capabilities strictly to internal tests via repository-relative built modules.
 * Not exposed through public package exports.
 * @internal
 */
export function createTestPersistentAuditStorage(
  config: PersistentAuditStorageConfig,
  testHooks?: StorageTestHooks | StorageTestFaults,
): PersistentAuditStorage {
  const normalizedHooks: StorageTestHooks =
    testHooks && ('writeFault' in testHooks || 'fdatasyncFault' in testHooks)
      ? { testFaults: testHooks as StorageTestFaults }
      : ((testHooks as StorageTestHooks) ?? {});

  return new (
    PersistentAuditStorage as unknown as {
      new (
        config: PersistentAuditStorageConfig,
        token: symbol,
        hooks?: StorageTestHooks,
      ): PersistentAuditStorage;
    }
  )(config, STORAGE_TEST_TOKEN, normalizedHooks);
}
