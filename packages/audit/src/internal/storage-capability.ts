/**
 * Package-internal storage testing capability token and definitions.
 *
 * This token and types are NEVER exported from the root package index or public package exports.
 * The unforgeable symbol is required to authorize constructor-level test hooks or fault injection.
 * @internal
 */
export const STORAGE_TEST_TOKEN = Symbol('STORAGE_TEST_TOKEN');

export interface StorageTestFaults {
  /**
   * `error` and `partial` simulate a failed and a short write respectively.
   *
   * `enospc` simulates a device that has run out of space: the record is never
   * written, the cursor is never advanced, and the storage is left FAILED. It
   * exists so the fail-closed ENOSPC path can be exercised without filling a
   * real filesystem.
   */
  writeFault?: 'error' | 'partial' | 'enospc';
  fdatasyncFault?: boolean;
}

export interface StorageTestHooks {
  beforeFinalOpen?: () => void;
  testFaults?: StorageTestFaults;
}
