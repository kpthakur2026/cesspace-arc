/**
 * @internal Test-only adapter hooks and interfaces.
 * These symbols are strictly excluded from the @cesspace-arc/auth public contract.
 */
export {
  type TrustStoreFsAdapter,
  defaultFsAdapter,
  verifyTrustStoreFileIntegrityWithAdapter,
  atomicPersistTrustStoreWithAdapter,
  loadTrustStoreWithAdapter,
  saveTrustStoreWithAdapter,
} from './trust-store.js';
