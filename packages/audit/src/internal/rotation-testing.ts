/**
 * Package-internal rotation test support (RC-06 Task 3).
 *
 * This module is NOT exported from the root package index, is NOT listed in the
 * package's `exports` map, is NOT reachable from ArcServerConfig, the
 * environment, the CLI or any MCP request, and is compiled only so that the
 * repository test suite can import it by repository-relative built path — the
 * same mechanism already used for `storage-testing.js` and
 * `recovery-testing.js`.
 *
 * The synthetic sealer here exists for one reason: Task 3 must be able to test
 * the rotation pipeline end to end without implementing Task 4's checkpoint
 * machinery. It therefore records the boundaries it was given and does nothing
 * else.
 *
 * It is NOT a checkpoint. It performs no cryptography, computes no checkpoint
 * hash and no previous-checkpoint hash, loads no key material, signs nothing,
 * verifies nothing, and never creates, opens or writes
 * `audit-checkpoints.jsonl`. A store rotated under the synthetic sealer has no
 * Tier-2 evidence whatsoever, and nothing in the package presents it as though
 * it did.
 *
 * @internal
 */

import { createCodedError, type PersistentAuditStorage } from '../storage.js';
import { ROTATION_CAPABILITY_TOKEN, type RotationTestHooks } from './rotation-capability.js';
import {
  RotatingAuditStore,
  type RotationCheckpointSealer,
  type RotationSealBoundary,
  type RotatingAuditStoreOptions,
} from '../rotation.js';

/**
 * A recording, non-cryptographic sealer for rotation-pipeline tests.
 *
 * @internal
 */
export class SyntheticRotationCheckpointSealer implements RotationCheckpointSealer {
  public readonly boundaries: RotationSealBoundary[] = [];
  public sealCount = 0;

  private readonly failuresBeforeSuccess: number;
  private failureCount = 0;

  constructor(options: { failuresBeforeSuccess?: number } = {}) {
    this.failuresBeforeSuccess = options.failuresBeforeSuccess ?? 0;
  }

  public async sealRotation(boundary: RotationSealBoundary): Promise<void> {
    if (this.failureCount < this.failuresBeforeSuccess) {
      this.failureCount++;
      throw createCodedError('SIMULATED_SEAL_FAILURE', 'simulated rotation seal failure');
    }

    this.sealCount++;
    this.boundaries.push({
      sequenceStart: boundary.sequenceStart,
      sequenceEnd: boundary.sequenceEnd,
      terminalRecordHash: boundary.terminalRecordHash,
    });
  }

  /** The most recent boundary this sealer accepted, if any. */
  public get lastBoundary(): RotationSealBoundary | null {
    return this.boundaries.length === 0 ? null : this.boundaries[this.boundaries.length - 1];
  }
}

/** Additional test seams for the rotation coordinator. @internal */
export interface RotationStoreTestHooks extends RotationTestHooks {
  /** Replaces the wall clock used by the 24-hour interval trigger. */
  clockMs?: () => number;
}

/** Test-only seam that replaces the wall clock driving the interval trigger. @internal */
export class TestClock {
  private current: number;

  constructor(startMs: number) {
    this.current = startMs;
  }

  public now(): number {
    return this.current;
  }

  public advanceMs(deltaMs: number): void {
    this.current += deltaMs;
  }
}

/**
 * Constructs a {@link RotatingAuditStore} with package-internal test seams.
 *
 * @internal
 */
export function createTestRotatingAuditStore(
  storage: PersistentAuditStorage,
  options: RotatingAuditStoreOptions,
  hooks: RotationStoreTestHooks = {},
): RotatingAuditStore {
  const constructed = new (
    RotatingAuditStore as unknown as {
      new (
        storage: PersistentAuditStorage,
        options: RotatingAuditStoreOptions,
        token: symbol,
        hooks?: RotationStoreTestHooks,
      ): RotatingAuditStore;
    }
  )(storage, options, ROTATION_CAPABILITY_TOKEN, hooks);

  return constructed;
}

/**
 * Asserts that no production sealer is available.
 *
 * Task 3 implements no production sealer, and this module deliberately exposes
 * no factory that could stand in for one. Rather than returning a permissive
 * placeholder, this throws, so a no-op sealer can never be reached through this
 * surface — not even accidentally by a caller looking for a default.
 *
 * @internal
 */
export function assertNoProductionSealerAvailable(): never {
  throw createCodedError(
    'AUDIT_ROTATION_SEALER_UNAVAILABLE',
    'no production rotation checkpoint sealer is implemented in Task 3; Task 4 supplies it',
  );
}
