/**
 * Process-wide in-process mutation locking manager.
 * Coordinates mutations across all FilesystemSubsystem instances in the process.
 */

export interface ILockManager {
  withLocks<T>(canonicalPaths: string[], action: () => Promise<T>): Promise<T>;
}

interface KeyLockState {
  tail: Promise<void>;
  waiters: number;
}

export class ProcessWideLockManager implements ILockManager {
  private locks = new Map<string, KeyLockState>();

  /**
   * Acquires exclusive locks for all specified canonical paths in deterministic lexicographical order.
   * Executes the given action and releases all locks in finally, ensuring zero memory leaks and deadlock freedom.
   */
  public async withLocks<T>(canonicalPaths: string[], action: () => Promise<T>): Promise<T> {
    if (canonicalPaths.length === 0) {
      return action();
    }

    // Deduplicate and sort lexicographically to prevent deadlocks
    const sortedKeys = Array.from(new Set(canonicalPaths)).sort();
    const releasers: Array<() => void> = [];

    try {
      for (const key of sortedKeys) {
        let state = this.locks.get(key);
        if (!state) {
          state = { tail: Promise.resolve(), waiters: 0 };
          this.locks.set(key, state);
        }

        state.waiters++;
        const currentWait = state.tail;
        let unlockCurrent!: () => void;
        const nextWait = new Promise<void>((resolve) => {
          unlockCurrent = resolve;
        });
        state.tail = currentWait.then(() => nextWait);

        // Wait for prior holder of this key to release
        await currentWait;

        const capturedState = state;
        releasers.push(() => {
          unlockCurrent();
          capturedState.waiters--;
          if (capturedState.waiters === 0 && this.locks.get(key) === capturedState) {
            this.locks.delete(key);
          }
        });
      }

      return await action();
    } finally {
      // Release in reverse order of acquisition
      while (releasers.length > 0) {
        const release = releasers.pop();
        if (release) {
          try {
            release();
          } catch {
            // ignore
          }
        }
      }
    }
  }

  /**
   * Visible for test diagnostics: returns current active lock count.
   */
  public get activeLockCount(): number {
    return this.locks.size;
  }
}

/**
 * Default process-wide lock manager singleton shared by all FilesystemSubsystem instances.
 */
export const defaultLockManager = new ProcessWideLockManager();
