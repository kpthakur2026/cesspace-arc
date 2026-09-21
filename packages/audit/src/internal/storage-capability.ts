/**
 * Package-internal storage testing capability token and definitions.
 *
 * This token and types are NEVER exported from the root package index or public package exports.
 * The unforgeable symbol is required to authorize constructor-level test hooks or fault injection.
 * @internal
 */
export const STORAGE_TEST_TOKEN = Symbol('STORAGE_TEST_TOKEN');

export interface StorageTestFaults {
  writeFault?: 'error' | 'partial';
  fdatasyncFault?: boolean;
}

export interface StorageTestHooks {
  beforeFinalOpen?: () => void;
  testFaults?: StorageTestFaults;
}
