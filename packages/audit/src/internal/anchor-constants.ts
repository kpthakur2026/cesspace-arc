/**
 * The frozen Tier-3 anchor constants (RC-06 §14.2, §14.3, §14.4, §14.5, §14.7).
 *
 * They live in a leaf module with no imports for the same structural reason the
 * Tier-2 checkpoint constants do: `rotation.ts` must recognize
 * `audit-anchors.jsonl` and `anchor-spool/` as durable auxiliary artifacts
 * (§21), and `anchor.ts` must reuse Task-3's storage-budget scanner. If these
 * names lived in `anchor.ts`, those two modules would import each other; a
 * dependency-free leaf lets both depend on them without a cycle.
 *
 * `anchor.ts` re-exports every name here, so the package's public surface is
 * exactly what §3 and §90 require and nothing about this file's location is
 * observable to a consumer.
 *
 * These values are fixed. There is no configuration, environment, CLI or MCP
 * override for any of them, and there is no `algorithm` field to negotiate.
 *
 * @internal
 */

/** The one anchor receipt stream, inside the validated audit directory. */
export const ANCHOR_RECEIPT_FILENAME = 'audit-anchors.jsonl';

/** The crash-recoverable pending-checkpoint spool directory. */
export const ANCHOR_SPOOL_DIRNAME = 'anchor-spool';

/**
 * The spool file mode. One file per pending checkpoint.
 *
 * The filename is the lowercase 64-hex `checkpointHash`, so the artifact a
 * pending entry describes is recoverable from the directory listing alone,
 * without reading any file's contents.
 */
export const ANCHOR_SPOOL_FILE_MODE = 0o600;

/** The spool directory mode. */
export const ANCHOR_SPOOL_DIRECTORY_MODE = 0o700;

/** A canonical spool entry name: lowercase 64-hex checkpoint hash plus `.json`. */
export const ANCHOR_SPOOL_FILENAME_REGEX = /^[0-9a-f]{64}\.json$/;

/**
 * The exact Ed25519 anchor receipt domain, including its terminating NUL.
 *
 * The signature preimage is `domain || UTF8(canonicalJson(unsignedReceipt))`
 * with no separator, no length prefix and no additional byte, so the NUL is
 * load-bearing: it is what prevents a canonical JSON body from being able to
 * masquerade as part of the domain. The anchor domain is distinct from the
 * checkpoint domain, so neither signature can be replayed as the other.
 */
export const ANCHOR_RECEIPT_SIGNATURE_DOMAIN = 'CESSPACE-ARC-ANCHOR-RECEIPT-V1\0';

/** Hard upper bound on an anchor response body (rc06 §14.2). */
export const MAX_ANCHOR_RECEIPT_BYTES = 2_048;

/**
 * Hard upper bound on one spool entry.
 *
 * A spool entry is the canonical JSON of an `AuditCheckpointV1`, whose largest
 * field is a 64-character signature: the encoding is a few hundred bytes. The
 * bound matches the checkpoint line bound so that no artifact which could be a
 * canonical checkpoint is ever truncated on read, and an entry larger than it
 * is a refusal rather than a first chunk.
 */
export const MAX_ANCHOR_SPOOL_ENTRY_BYTES = 65_536;

/** Hard upper bound on the serialized anchor endpoint (rc06 §14.2). */
export const MAX_ANCHOR_ENDPOINT_BYTES = 2_048;

/**
 * Total per-attempt network timeout (rc06 §14.3).
 *
 * It covers DNS resolution, the TLS handshake, request transmission and receipt
 * body acquisition as one budget — not one timeout per phase — so a peer cannot
 * extend an attempt by making progress slowly in each phase in turn.
 */
export const ANCHOR_REQUEST_TIMEOUT_MS = 5_000;

/** Exactly five attempts per retry cycle (rc06 §14.7). */
export const MAX_ANCHOR_ATTEMPTS = 5;

/**
 * The fixed backoff vector between attempts, in milliseconds (rc06 §14.7).
 *
 * `ANCHOR_RETRY_BACKOFF_MS[i]` is the delay observed after attempt `i + 1`
 * fails. The vector has one entry per attempt — including the fifth — because
 * the fifth delay is the terminal backoff of a cycle whose spool entry is
 * retained for the next recovery cycle. It is a fixed vector, never an
 * exponent computed at runtime, so the schedule cannot drift.
 */
export const ANCHOR_RETRY_BACKOFF_MS: readonly number[] = [1_000, 2_000, 4_000, 8_000, 16_000];

/** Backpressure ceiling on pending spool entries (rc06 §14.7). */
export const MAX_PENDING_ANCHOR_CHECKPOINTS = 100;

/** Backpressure ceiling on the total spool payload (rc06 §14.7). */
export const MAX_ANCHOR_SPOOL_BYTES = 1_048_576;

/** The `Idempotency-Key` header the anchor contract is built on (rc06 §14.3). */
export const ANCHOR_IDEMPOTENCY_HEADER = 'Idempotency-Key';

/** The HTTP methods the anchor contract acknowledges (rc06 §14.5). */
export const ANCHOR_ACKNOWLEDGING_STATUS_CODES: readonly number[] = [200, 201];
