/**
 * Package-internal test construction for the Tier-3 anchor engine
 * (RC-06 Task 5).
 *
 * Mirrors `checkpoint-testing.ts` and `rotation-testing.ts`: the deterministic
 * seams are reachable only through the unforgeable {@link ANCHOR_TEST_TOKEN}, so
 * no production caller — and nothing reachable from `ArcServerConfig`, the
 * environment, the CLI or an MCP request — can supply a transport, a CA bundle,
 * an attempt timer, a clock, an expected UID or a fault.
 *
 * The seams let a security property be *demonstrated* rather than asserted: that
 * a receipt signed by the wrong key is refused even though it is a perfectly
 * valid Ed25519 signature, that the 5,000 ms budget covers the whole attempt
 * rather than one phase, that the retry vector is exactly `1s, 2s, 4s, 8s,
 * 16s`, that a spool write which fails leaves nothing transmitted, and that a
 * crash between the durable receipt and the spool unlink is reconciled without a
 * second acknowledgement.
 *
 * None of them can change what a receipt *means*. They cannot alter the signature
 * preimage, the receipt schema, the store or checkpoint binding, the endpoint
 * rules or the frozen schedule — only when a value is read, whether a write
 * completes, and what the network answers.
 *
 * @internal
 */

import crypto from 'node:crypto';

import {
  Tier3AnchorEngine,
  computeAnchorReceiptSignaturePreimage,
  type AnchorReceiptV1,
  type Tier3AnchorEngineConfig,
  type UnsignedAnchorReceiptV1,
} from '../anchor.js';
import { ANCHOR_TEST_TOKEN, type AnchorTestHooks } from './anchor-capability.js';
import { createCodedError } from './errors.js';

export { ANCHOR_TEST_TOKEN, type AnchorTestHooks } from './anchor-capability.js';

/**
 * Constructs and initializes an anchor engine with deterministic seams.
 *
 * @internal
 */
export async function createTestTier3AnchorEngine(
  config: Tier3AnchorEngineConfig,
  hooks: AnchorTestHooks = {},
): Promise<Tier3AnchorEngine> {
  const engine = new Tier3AnchorEngine(config, ANCHOR_TEST_TOKEN, hooks);
  await engine.initializeEngine();
  return engine;
}

/**
 * Constructs an anchor engine for the frozen startup sequence, with seams.
 *
 * The counterpart of {@link createTestTier3AnchorEngine} for the runtime
 * composition: configuration and trust roots validated, receipt ledger verified,
 * spool decisions staged and unapplied. The runtime's stage 7 applies them
 * through the same public path production uses, so a regression observes the
 * staging boundary rather than a testing shortcut around it.
 *
 * @internal
 */
export async function createTestTier3AnchorEngineForStartup(
  config: Tier3AnchorEngineConfig,
  hooks: AnchorTestHooks = {},
): Promise<Tier3AnchorEngine> {
  const engine = new Tier3AnchorEngine(config, ANCHOR_TEST_TOKEN, hooks);
  await engine.initializeEngineForStartup();
  return engine;
}

/**
 * Mints a receipt with an ephemeral anchor key, exactly as a real anchor would.
 *
 * The signature is produced over the frozen preimage, so a test can construct a
 * receipt that is cryptographically valid under *any* key it holds — including
 * one that is not the pinned anchor key. That is the point: NEG-90 proves the
 * refusal comes from the pinning rather than from a malformed signature.
 *
 * @internal
 */
export function signTestAnchorReceipt(
  unsigned: UnsignedAnchorReceiptV1,
  privateKey: crypto.KeyObject,
): AnchorReceiptV1 {
  const raw = crypto.sign(null, computeAnchorReceiptSignaturePreimage(unsigned), privateKey);
  return { ...unsigned, signature: raw.toString('base64url') };
}

/** Asserts the capability token, for tests that need to prove it is unforgeable. @internal */
export function assertAnchorTestToken(token: symbol): void {
  if (token !== ANCHOR_TEST_TOKEN) {
    throw createCodedError(
      'ANCHOR_CAPABILITY_REQUIRED',
      'anchor test seams require the package-internal capability token',
    );
  }
}
