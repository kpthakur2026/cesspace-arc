/**
 * Package-internal rotation capability token and definitions (RC-06 Task 3).
 *
 * This token and these types are NEVER exported from the root package index or
 * any public package subpath. The unforgeable symbol is what authorizes the
 * narrow descriptor-level capability below, exactly as `STORAGE_TEST_TOKEN`
 * authorizes constructor test hooks and `RECOVERY_HANDOFF_TOKEN` authorizes the
 * verified recovery handoff.
 *
 * The capability is deliberately NOT a cursor setter. Rotation preserves the
 * sequence and hash cursors by construction (rc06 §73): a rotated segment ends
 * at `sequenceEnd`/`terminalRecordHash` and the very next append must continue
 * at `sequenceEnd + 1` from `terminalRecordHash`. Exposing
 * `setCurrentSequence`/`setLastRecordHash` would make it possible for a caller
 * to detach the in-memory chain from the durable one, so no such method exists
 * anywhere in the package.
 *
 * @internal
 */
export const ROTATION_CAPABILITY_TOKEN = Symbol('ROTATION_CAPABILITY_TOKEN');

/** The descriptor-level authority the rotation coordinator needs. @internal */
export interface RotationStorageCapability {
  /** Absolute audit store directory. */
  readonly auditDir: string;
  /** Absolute path of the active primary segment. */
  readonly activePath: string;
  /** The expected real UID every durable artifact must be owned by. */
  readonly expectedUid: number;

  /** True while the storage is in its `ACTIVE` state. */
  isActive(): boolean;
  /** True once the storage has been closed. */
  isClosed(): boolean;
  /** True once a security-sensitive outcome became uncertain. */
  isFailed(): boolean;

  /** The authoritative active descriptor, or `null` when none is installed. */
  getActiveFd(): number | null;
  /** Current authoritative active segment size, or `null` when unavailable. */
  getActiveByteSize(): number | null;

  /**
   * The exact serialized byte length the NEXT append of `candidate` would write.
   *
   * Used for the fail-closed capacity preflight (§52) so a record that is known
   * to exceed the remaining budget is refused before any bytes are written.
   */
  projectSerializedBytes(candidate: unknown): number;

  /**
   * Moves the storage into its terminal fail-closed state without touching any
   * historical evidence.
   */
  markRotationFailed(): void;

  /**
   * The ONE synchronous physical rotation critical section (§14 steps 5-9).
   *
   * Finalizes the current active descriptor, installs it as the rotated
   * `archiveName` WITHOUT overwriting anything, fsyncs the parent directory,
   * creates the fresh active segment securely, fsyncs the parent directory
   * again, and returns. The sequence and hash cursors are left exactly as they
   * were, which is what makes the next append continue the chain.
   *
   * It is called only AFTER the sealing authority has succeeded, so a segment
   * can never become a finalized rotated segment before it is sealed.
   */
  rotateActiveSegmentPhysical(archiveName: string): {
    archivedPath: string;
    newActiveFd: number;
  };
}

/** Deterministic rotation fault seams. Package-internal; never a production field. @internal */
export interface RotationTestHooks {
  /** Invoked immediately before the physical rotation critical section. */
  beforePhysicalRotation?: () => void;
  /** Forces the physical rotation critical section to fail. */
  failPhysicalRotation?: boolean;
  /** Simulates a directory `fsync` failure during rotation. */
  failDirectorySync?: boolean;
  /** Simulates a gzip output creation failure. */
  failCompressionCreate?: boolean;
  /** Simulates a gzip output sync failure. */
  failCompressionSync?: boolean;
  /** Simulates a `stat` disagreement between the two representations. */
  failPostCompressionVerification?: boolean;
  /** Simulates a source-removal (`unlink`) failure. */
  failSourceRemoval?: boolean;
  /**
   * Monotonic-free wall clock seam, in milliseconds since the epoch.
   *
   * Used only by package-internal tests to drive the 24-hour operational
   * rotation trigger deterministically (§12). It is never reachable from
   * ArcServerConfig, the environment, the CLI, or any MCP request.
   */
  clockMs?: () => number;
}
