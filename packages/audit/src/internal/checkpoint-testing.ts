/**
 * Package-internal test construction for the Tier-2 checkpoint engine
 * (RC-06 Task 4).
 *
 * Mirrors `rotation-testing.ts`: the deterministic seams are reachable only
 * through the unforgeable {@link CHECKPOINT_TEST_TOKEN}, so no production caller
 * — and nothing reachable from `ArcServerConfig`, the environment, the CLI or an
 * MCP request — can supply a clock, a UUID source, an expected UID or a fault.
 *
 * The seams let a security property be *demonstrated* rather than asserted: that
 * a clock cannot change coverage, that a checkpoint identifier collides with
 * nothing that matters, that a foreign-owned artifact is refused without a
 * privileged `chown`, and that a write or `fdatasync` that fails after signing
 * leaves the checkpoint cursor exactly where it was.
 *
 * @internal
 */

import { Tier2CheckpointEngine, type Tier2CheckpointEngineConfig } from '../checkpoint.js';
import { CHECKPOINT_TEST_TOKEN, type CheckpointTestHooks } from './checkpoint-capability.js';

export { CHECKPOINT_TEST_TOKEN, type CheckpointTestHooks } from './checkpoint-capability.js';

export { enablePrivateKeyLoadProbe, getPrivateKeyLoadCount } from './key-authority.js';

/**
 * Constructs and initializes a checkpoint engine with deterministic seams.
 *
 * @internal
 */
export async function createTestTier2CheckpointEngine(
  config: Tier2CheckpointEngineConfig,
  hooks: CheckpointTestHooks = {},
): Promise<Tier2CheckpointEngine> {
  const engine = new Tier2CheckpointEngine(config, CHECKPOINT_TEST_TOKEN, hooks);
  await engine._initialize();
  return engine;
}
