/**
 * Package-internal checkpoint capability token and fault seams (RC-06 Task 4).
 *
 * The token and these types are NEVER exported from the root package index, are
 * NOT listed in the package's `exports` map, and are not reachable from
 * ArcServerConfig, the environment, the CLI or any MCP request. The unforgeable
 * symbol is what authorizes the deterministic seams below — exactly as
 * `STORAGE_TEST_TOKEN` authorizes Task-1 constructor hooks and
 * `ROTATION_CAPABILITY_TOKEN` authorizes Task-3 rotation hooks.
 *
 * Every seam here exists so a security property can be *proved* deterministically
 * rather than argued: a write that fails after the checkpoint was signed, an
 * `fdatasync` that fails, a clock that does not move, a UUID that is predictable,
 * and an expected-UID that does not match the process so the ownership rule can
 * be exercised without a privileged `chown`.
 *
 * None of these can change what a checkpoint *means*. They cannot alter
 * sequence coverage, the primary record hashes, the checkpoint hash chain, the
 * signature preimage or the store binding — the properties §56 freezes against
 * clock manipulation. They change only when a value is read or whether a write
 * completes.
 *
 * @internal
 */
export const CHECKPOINT_TEST_TOKEN = Symbol('CHECKPOINT_TEST_TOKEN');

/** Deterministic seams for Task-4 security tests. @internal */
export interface CheckpointTestHooks {
  /**
   * Wall clock in milliseconds since the epoch.
   *
   * Drives `createdAt` only. It has no effect on coverage, hashes, the hash
   * chain, signature verification or store binding.
   */
  clockMs?: () => number;

  /** Source of checkpoint identifiers. Production always uses `randomUUID()`. */
  randomUUID?: () => string;

  /**
   * The real UID every durable artifact is expected to be owned by.
   *
   * Lets the ownership rule be exercised without a privileged `chown`. The
   * production factory never reads this and always uses the process real UID.
   */
  expectedUid?: number;

  /**
   * Forces the checkpoint append to fail.
   *
   * `zero` reports a write of zero bytes, `partial` writes a strict prefix and
   * then reports zero, and `error` throws from the write itself. All three model
   * an uncertain persistence outcome, which must fail closed without advancing
   * the in-memory checkpoint cursor.
   */
  writeFault?: 'error' | 'partial' | 'zero';

  /** Forces the checkpoint `fdatasync` to fail after a complete write. */
  fdatasyncFault?: boolean;

  /** Observes the open flags used for the checkpoint artifact. */
  openFlagsProbe?: (flags: number) => void;

  /**
   * Runs after initialization has verified the artifact ABSENT and immediately
   * before the exclusive creation is attempted.
   *
   * Lets a test place a racing artifact on the canonical path in the one window
   * where the engine has already committed to owning creation, which is the only
   * way to exercise the `EEXIST` outcome deterministically.
   */
  beforeCheckpointExclusiveCreate?: (filePath: string) => void;

  /**
   * Runs immediately before the checkpoint artifact is revalidated for an
   * append, and therefore before the write.
   *
   * Lets a test substitute the pathname, grow the inode, or detach the canonical
   * path in the window between the descriptor being established and the next
   * checkpoint being committed. It cannot make an invalid append succeed: the
   * revalidation runs after it and fails closed.
   */
  beforeCheckpointAppend?: (filePath: string) => void;

  /**
   * Runs after the checkpoint stream has been read to EOF and verified, and
   * immediately before the artifact identity is re-established.
   *
   * Lets a test grow, shrink, replace or detach the verified artifact in the
   * window between "the bytes were consumed" and "the bytes are still what the
   * artifact contains". The identity check runs after it and fails closed, so it
   * cannot make unverified bytes look verified.
   */
  beforeCheckpointVerificationIdentityCheck?: (filePath: string) => void;

  /**
   * Runs after the signing key's parent chain has been pinned by descriptor and
   * immediately before the final key component is opened.
   *
   * Lets a test substitute a parent pathname in exactly the window a pathname-
   * based check would be vulnerable in. The walk no longer consults a pathname,
   * so the substitution cannot redirect it — and the workspace decision still
   * runs after it, on the descriptor that was really opened.
   */
  beforeFinalKeyOpen?: () => void;
}
