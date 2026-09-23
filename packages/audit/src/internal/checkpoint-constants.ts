/**
 * The frozen Tier-2 checkpoint constants (RC-06 §12, §13, §24.1).
 *
 * They live in a leaf module with no imports for one structural reason:
 * `rotation.ts` must recognize `audit-checkpoints.jsonl` as a durable auxiliary
 * artifact (§51), and `checkpoint.ts` must reuse Task-3's streaming verifier. If
 * the filename constant lived in `checkpoint.ts`, those two modules would import
 * each other. Keeping the constants dependency-free lets both depend on them
 * without a cycle.
 *
 * `checkpoint.ts` re-exports every name here, so the package's public surface is
 * exactly what §4 and §95 require and nothing about this file's location is
 * observable to a consumer.
 *
 * These values are fixed. There is no configuration, environment, CLI or MCP
 * override for any of them.
 *
 * @internal
 */

/** Primary audit records between interval checkpoints (rc06 §12.2). */
export const CHECKPOINT_INTERVAL = 1_000;

/** Hard upper bound on a signing-key or trust-root file (rc06 §13.1, §13.2). */
export const MAX_SIGNING_KEY_BYTES = 4_096;

/** The one checkpoint artifact stream, inside the validated audit directory. */
export const CHECKPOINT_FILENAME = 'audit-checkpoints.jsonl';

/**
 * The exact Ed25519 signing domain, including its terminating NUL.
 *
 * The signature preimage is `domain || UTF8(canonicalJson(unsigned))` with no
 * separator, no length prefix and no additional byte, so the NUL is
 * load-bearing: it is what prevents a canonical JSON body from being able to
 * masquerade as part of the domain.
 */
export const CHECKPOINT_SIGNATURE_DOMAIN = 'CESSPACE-ARC-CHECKPOINT-V1\0';
