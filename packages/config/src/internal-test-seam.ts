import { AsyncLocalStorage } from 'node:async_hooks';

const preCommitFault = new AsyncLocalStorage<boolean>();

export function isPreCommitFaultEnabled(): boolean {
  return preCommitFault.getStore() === true;
}

export function withPreCommitFault<T>(operation: () => Promise<T>): Promise<T> {
  return preCommitFault.run(true, operation);
}
