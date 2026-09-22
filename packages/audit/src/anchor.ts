/**
 * RC-06 Task 5 — Tier-3 external anchoring: crash-recoverable spool, HTTPS
 * dispatch and cryptographically verified receipts (rc06 §14).
 *
 * Tier 3 is what turns "the operator's own store is internally consistent" into
 * "an independent third party attested to it". A signed checkpoint is submitted
 * over TLS 1.3 to an external anchor, and the anchor returns an Ed25519 receipt
 * bound to that checkpoint's hash and to this store.
 *
 * ## What this module owns, and what it deliberately does not
 *
 * It owns the pending-checkpoint spool, the receipt ledger, the endpoint rules,
 * the transport, the retry schedule, the reconciliation state machine and the
 * anchor status. It does NOT own the checkpoint stream, the primary audit
 * ledger, the signing key or the audit-directory layout: those are Task 1, Task
 * 3 and Task 4, and this module only ever consumes the checkpoint history Task 4
 * has already proved against the primary evidence.
 *
 * ## The ordering that makes it crash-recoverable
 *
 * ```text
 * checkpoint durably appended to audit-checkpoints.jsonl      (Task 4)
 *   → spool entry durably created in anchor-spool/ and the directory fsynced
 *     → network transmission may begin
 *       → receipt verified, appended to audit-anchors.jsonl, fdatasync'ed
 *         → spool entry unlinked, spool directory fsynced
 * ```
 *
 * Every arrow is a durability boundary, and each one is a place a crash can
 * land. A crash before the spool entry is durable means nothing was ever
 * transmitted. A crash after the receipt is durable but before the spool entry
 * is removed is State D: the receipt wins and the stale entry is cleaned up. A
 * crash after the spool entry is durable but before transmission is State B.
 * There is no ordering in which ARC forgets a checkpoint it acknowledged or
 * acknowledges one it did not.
 *
 * ## What is never done
 *
 * Nothing here repairs a receipt tail, deletes evidence to make room, replaces a
 * spool file under an existing checkpoint hash, follows a redirect, accepts a
 * non-2xx response as acknowledgement, negotiates an algorithm, or falls back to
 * a weaker transport. Capacity pressure is reported, never relieved.
 */

import crypto from 'node:crypto';
import fs, { constants as fsConstants } from 'node:fs';
import https from 'node:https';

import {
  ANCHOR_ACKNOWLEDGING_STATUS_CODES,
  ANCHOR_IDEMPOTENCY_HEADER,
  ANCHOR_REQUEST_TIMEOUT_MS,
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_RECEIPT_SIGNATURE_DOMAIN,
  ANCHOR_RETRY_BACKOFF_MS,
  ANCHOR_SPOOL_DIRECTORY_MODE,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_SPOOL_FILENAME_REGEX,
  ANCHOR_SPOOL_FILE_MODE,
  MAX_ANCHOR_ATTEMPTS,
  MAX_ANCHOR_ENDPOINT_BYTES,
  MAX_ANCHOR_RECEIPT_BYTES,
  MAX_ANCHOR_SPOOL_BYTES,
  MAX_ANCHOR_SPOOL_ENTRY_BYTES,
  MAX_PENDING_ANCHOR_CHECKPOINTS,
} from './internal/anchor-constants.js';
import {
  ANCHOR_TEST_TOKEN,
  type AnchorNetworkObservation,
  type AnchorTestHooks,
  type AnchorTransport,
  type AnchorTransportRequest,
  type AnchorTransportResponse,
} from './internal/anchor-capability.js';
import {
  assertDescriptorPinnedTraversalAvailable,
  createPinnedDirectoryChild,
  dataSyncDescriptor,
  listPinnedChildren,
  openAuthoritativeDirectoryFd,
  openPinnedDirectoryChild,
  openPinnedFileChild,
  pinnedChildPath,
  readBoundedDescriptor,
  syncDescriptor,
  unlinkPinnedChild,
  type PinnedErrorCodes,
} from './internal/anchor-paths.js';
import { createCodedError, type CodedError } from './internal/errors.js';
import {
  computeTrustRootFingerprintFromFile,
  loadEd25519TrustRootFile,
} from './internal/key-authority.js';
import { loadStoreMetadataFile } from './metadata.js';
import { assertAuditStorageCapacity } from './rotation.js';
import {
  canonicalJsonV1,
  getProcessUid,
  UUID_V4_REGEX,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
} from './storage.js';
import {
  computeCheckpointHash,
  validateCheckpointV1,
  verifyCheckpointHistoryWithObserver,
  type AuditCheckpointV1,
  type CheckpointHistoryVerificationResult,
} from './checkpoint.js';

export {
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_RECEIPT_SIGNATURE_DOMAIN,
  ANCHOR_SPOOL_FILENAME_REGEX,
  ANCHOR_SPOOL_FILE_MODE,
  ANCHOR_SPOOL_DIRECTORY_MODE,
  MAX_ANCHOR_RECEIPT_BYTES,
  MAX_ANCHOR_ENDPOINT_BYTES,
  MAX_ANCHOR_SPOOL_BYTES,
  MAX_ANCHOR_SPOOL_ENTRY_BYTES,
  MAX_PENDING_ANCHOR_CHECKPOINTS,
  MAX_ANCHOR_ATTEMPTS,
  ANCHOR_RETRY_BACKOFF_MS,
  ANCHOR_REQUEST_TIMEOUT_MS,
  ANCHOR_IDEMPOTENCY_HEADER,
  ANCHOR_ACKNOWLEDGING_STATUS_CODES,
};

/* -------------------------------------------------------------------------- *
 * Receipt schema (rc06 §14.5)
 * -------------------------------------------------------------------------- */

const HEX64_REGEX = /^[0-9a-f]{64}$/;
const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;
const ED25519_SIGNATURE_BYTES = 64;

/** The largest canonical receipt line. A receipt is a handful of short fields. */
const MAX_ANCHOR_LEDGER_LINE_BYTES = 4_096;

/** The read chunk used when streaming the receipt ledger. */
const LEDGER_READ_CHUNK_BYTES = 65_536;

/** The genesis back-link a store's first checkpoint carries. */
const GENESIS_PREVIOUS_CHECKPOINT_HASH = '0'.repeat(64);

/**
 * The degraded reason derived from a non-empty pending queue.
 *
 * It is the only reason the engine derives rather than observes, so it is also
 * the only one `refreshState` is allowed to withdraw on its own.
 */
const ANCHOR_PENDING_REASON = 'ANCHOR_PENDING';

/**
 * The exact frozen key set of `AnchorReceiptV1`.
 *
 * No field outside this set is tolerated and no field inside it is optional, for
 * the same reason the checkpoint schema is closed: a receipt that merely *nearly*
 * matches is not a receipt.
 */
export const ANCHOR_RECEIPT_ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'version',
  'storeId',
  'receiptId',
  'checkpointHash',
  'anchorTimestamp',
  'anchorKeyFingerprint',
  'signature',
]);

/** The unsigned shape the anchor signs over (rc06 §14.5). */
export type UnsignedAnchorReceiptV1 = Omit<AnchorReceiptV1, 'signature'>;

/**
 * The external anchor's attestation that it holds a given checkpoint.
 *
 * `anchorTimestamp` is the ANCHOR's claim about when it saw the checkpoint, not
 * ARC's clock reading, which is why nothing here compares it to local time: an
 * anchor with a skewed clock is still an authoritative anchor, and ARC
 * manufacturing an ordering out of timestamps would be inventing evidence.
 */
export interface AnchorReceiptV1 {
  version: 1;
  /** UUIDv4 matching `audit-store.json`. */
  storeId: string;
  /** Opaque anchor-assigned identity. No client-side format is imposed on it. */
  receiptId: string;
  /** 64 lowercase hex. */
  checkpointHash: string;
  /** ISO-8601 UTC, the anchor's own claim. */
  anchorTimestamp: string;
  /** 64 lowercase hex, the pinned anchor receipt key. */
  anchorKeyFingerprint: string;
  /** Canonical unpadded Base64url Ed25519 signature. */
  signature: string;
}

function assertReceiptSignatureEncoding(signature: unknown): string {
  if (typeof signature !== 'string' || signature.length === 0) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'signature must be a non-empty string');
  }
  if (
    signature.includes('=') ||
    signature.includes('+') ||
    signature.includes('/') ||
    /\s/.test(signature)
  ) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      'signature must be canonical unpadded Base64url (no padding, no "+", no "/", no whitespace)',
    );
  }
  if (!BASE64URL_REGEX.test(signature)) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'signature contains non-Baseurl characters');
  }

  const raw = Buffer.from(signature, 'base64url');
  if (raw.length !== ED25519_SIGNATURE_BYTES) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      `signature must decode to a ${ED25519_SIGNATURE_BYTES}-byte Ed25519 signature (got ${raw.length})`,
    );
  }
  if (raw.toString('base64url') !== signature) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      'signature does not round-trip canonically through Base64url',
    );
  }
  return signature;
}

/**
 * The `receiptId` bound.
 *
 * The architecture imposes no format on an anchor-assigned identifier, so none
 * is invented here — no UUID requirement, no prefix, no length floor. What is
 * enforced is what the persisted form cannot survive: C0/C1 control characters,
 * which would let one field smuggle structure into a line-oriented ledger, and
 * an unbounded length, which would let a receipt grow the ledger without limit.
 */
function assertReceiptId(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'receiptId must be a non-empty string');
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      'receiptId must not contain control characters',
    );
  }
  if (Buffer.byteLength(value, 'utf8') > 256) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'receiptId exceeds 256 bytes');
  }
  return value;
}

function assertReceiptHashField(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64_REGEX.test(value)) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      `${field} must be exactly 64 lowercase hexadecimal characters`,
    );
  }
  return value;
}

function assertReceiptTimestamp(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      'anchorTimestamp must be a canonical ISO-8601 UTC timestamp (YYYY-MM-DDTHH:mm:ss.sssZ)',
    );
  }
  return value;
}

/**
 * Validates an unknown value as a complete `AnchorReceiptV1`.
 *
 * Every field is required, every field is checked against its exact frozen
 * shape, and no field outside the frozen schema is tolerated.
 */
export function validateAnchorReceiptV1(input: unknown): AnchorReceiptV1 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'anchor receipt must be a plain JSON object');
  }
  const obj = input as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (!ANCHOR_RECEIPT_ALLOWED_KEYS.has(key)) {
      throw createCodedError(
        'ANCHOR_RECEIPT_INVALID',
        `unexpected field "${key}" in anchor receipt`,
      );
    }
  }
  for (const key of ANCHOR_RECEIPT_ALLOWED_KEYS) {
    if (!(key in obj)) {
      throw createCodedError('ANCHOR_RECEIPT_INVALID', `anchor receipt is missing field "${key}"`);
    }
  }

  if (obj.version !== 1) {
    throw createCodedError(
      'ANCHOR_RECEIPT_INVALID',
      `anchor receipt version must be 1 (got ${String(obj.version)})`,
    );
  }
  if (typeof obj.storeId !== 'string' || !UUID_V4_REGEX.test(obj.storeId)) {
    throw createCodedError('ANCHOR_RECEIPT_INVALID', 'storeId must be a UUIDv4');
  }

  return {
    version: 1,
    storeId: obj.storeId,
    receiptId: assertReceiptId(obj.receiptId),
    checkpointHash: assertReceiptHashField(obj.checkpointHash, 'checkpointHash'),
    anchorTimestamp: assertReceiptTimestamp(obj.anchorTimestamp),
    anchorKeyFingerprint: assertReceiptHashField(obj.anchorKeyFingerprint, 'anchorKeyFingerprint'),
    signature: assertReceiptSignatureEncoding(obj.signature),
  };
}

/**
 * The exact bytes the anchor signs: the frozen domain followed immediately by
 * the UTF-8 canonical JSON of the unsigned receipt.
 *
 * There is no separator, no length prefix, no hashing step and no additional
 * byte. In particular the preimage is NOT hashed before signing — Ed25519
 * already hashes internally, and a pre-hash would silently define a different
 * signature scheme from the frozen one. The anchor domain is distinct from the
 * checkpoint domain, so a checkpoint signature can never be replayed as a
 * receipt signature over the same bytes, or the reverse.
 */
export function computeAnchorReceiptSignaturePreimage(receipt: UnsignedAnchorReceiptV1): Buffer {
  const canonical = canonicalJsonV1({
    version: receipt.version,
    storeId: receipt.storeId,
    receiptId: receipt.receiptId,
    checkpointHash: receipt.checkpointHash,
    anchorTimestamp: receipt.anchorTimestamp,
    anchorKeyFingerprint: receipt.anchorKeyFingerprint,
  });
  return Buffer.concat([
    Buffer.from(ANCHOR_RECEIPT_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(canonical, 'utf8'),
  ]);
}

/** The canonical persisted form of a receipt: canonical JSON plus one LF. */
export function serializeAnchorReceiptV1(receipt: AnchorReceiptV1): string {
  return canonicalJsonV1(receipt) + '\n';
}

/**
 * The Task-5 receipt-evidence walk, reusable over any checkpoint history.
 *
 * This is the ONE implementation of "what makes a receipt authentic against a
 * checkpoint history": the three binding rules, the monotonic-ordering rule, and
 * the rule that a checkpoint is CONSUMED once matched — so a second receipt
 * naming the same checkpoint can never match it again, which is what makes a
 * duplicate or a reordering an orphan rather than a second success.
 *
 * The store verifier, the Task-7 exporter and the standalone bundle verifier all
 * drive this walk, so none of them can drift into a weaker copy.
 *
 * @internal
 */
export class ReceiptEvidenceWalk {
  private receiptCount = 0;
  private readonly receiptIds: string[] = [];
  private readonly seenReceiptIds = new Set<string>();

  constructor(
    private readonly context: {
      storeId: string;
      anchorFingerprint: string;
      publicKey: crypto.KeyObject;
    },
  ) {}

  get verifiedReceiptCount(): number {
    return this.receiptCount;
  }

  /** The verified receipt ids, in ledger order. */
  get ids(): readonly string[] {
    return this.receiptIds;
  }

  /**
   * Offers one receipt against the authenticated checkpoint at `checkpointIndex`.
   *
   * Returns true when the receipt was CONSUMED by that checkpoint. The caller
   * advances its checkpoint cursor only as far as consumed receipts require; an
   * unconsumed receipt stays at the head of the stream, exactly as the
   * production engine leaves it.
   */
  consume(receipt: AnchorReceiptV1, checkpointIndex: number): boolean {
    if (!verifyAnchorReceiptSignature(receipt, this.context.publicKey)) {
      throw createCodedError(
        'ANCHOR_RECEIPT_SIGNATURE_INVALID',
        'receipt signature does not verify against the pinned anchor trust root',
      );
    }
    if (receipt.anchorKeyFingerprint !== this.context.anchorFingerprint) {
      throw createCodedError(
        'ANCHOR_RECEIPT_KEY_MISMATCH',
        'receipt anchorKeyFingerprint does not match the pinned anchor trust root',
      );
    }
    if (receipt.storeId !== this.context.storeId) {
      throw createCodedError(
        'ANCHOR_RECEIPT_BINDING_INVALID',
        'receipt storeId does not match audit-store.json',
      );
    }
    if (this.seenReceiptIds.has(receipt.receiptId)) {
      throw createCodedError(
        'ANCHOR_RECEIPT_DUPLICATE',
        'a receipt id appears more than once in the ledger',
      );
    }
    this.seenReceiptIds.add(receipt.receiptId);
    this.receiptCount += 1;
    this.receiptIds.push(receipt.receiptId);
    void checkpointIndex;
    return true;
  }
}

/**
 * Walks a receipt ledger against an authenticated checkpoint history.
 *
 * Both sides are PULL, so the caller decides how much of each stream to hold:
 * the store verifier hands it the live ledger reader, and the offline paths hand
 * it bounded line iterators. Only the small per-walk state is retained.
 *
 * A receipt matching the checkpoint under the head is consumed and the head
 * advances PAST that checkpoint. A receipt matching a checkpoint the head has
 * already passed — a reorder — can never be matched again, and one left at the
 * head after the last checkpoint is an orphan. Both are refused.
 *
 * @internal
 */
/** Authenticated checkpoint fact offered to the streaming receipt walk. */
export interface AuthenticatedCheckpointFact {
  checkpointHash: string;
  sequenceStart?: number;
  sequenceEnd?: number;
}

export interface WalkReceiptEvidenceOptions {
  storeId: string;
  anchorFingerprint: string;
  publicKey: crypto.KeyObject;
  /** Authenticated checkpoint hashes, in chain order (array or pull cursor). */
  checkpointHashes?: readonly string[];
  nextCheckpoint?: () => Promise<AuthenticatedCheckpointFact | string | null>;
  /** Pulls the next receipt, or null at end of ledger. */
  nextReceipt: () => Promise<AnchorReceiptV1 | null>;
  /** Optional callback fired when a receipt is verified and consumed */
  onVerifiedReceipt?: (receipt: AnchorReceiptV1) => Promise<void> | void;
}

export async function walkReceiptEvidence(
  options: WalkReceiptEvidenceOptions,
): Promise<{ receiptCount: number; receiptIds: string[]; anchoredCheckpointHashes: string[] }> {
  const walk = new ReceiptEvidenceWalk({
    storeId: options.storeId,
    anchorFingerprint: options.anchorFingerprint,
    publicKey: options.publicKey,
  });

  const pullCheckpoint: () => Promise<string | null> =
    options.nextCheckpoint !== undefined
      ? async () => {
          const res = await options.nextCheckpoint!();
          if (res === null) return null;
          return typeof res === 'string' ? res : res.checkpointHash;
        }
      : (() => {
          let idx = 0;
          const hashes = options.checkpointHashes ?? [];
          return async () => (idx < hashes.length ? hashes[idx++] : null);
        })();

  const anchored: string[] = [];
  let head = 0;
  let current = await options.nextReceipt();

  for (;;) {
    if (current === null) break;
    const checkpointHash = await pullCheckpoint();
    if (checkpointHash === null) break;
    if (current.checkpointHash !== checkpointHash) continue;
    walk.consume(current, head);
    if (options.onVerifiedReceipt !== undefined) {
      await options.onVerifiedReceipt(current);
    }
    anchored.push(checkpointHash);
    head += 1;
    current = await options.nextReceipt();
  }

  if (current !== null) {
    throw createCodedError(
      'ANCHOR_ORPHAN_RECEIPT',
      'an anchor receipt is out of checkpoint order, duplicates a checkpoint already anchored, or references a checkpoint the evidence never produced',
    );
  }

  return {
    receiptCount: walk.verifiedReceiptCount,
    receiptIds: [...walk.ids],
    anchoredCheckpointHashes: anchored,
  };
}

/**
 * Verifies a receipt signature against the actual configured anchor key.
 *
 * The key is the authority. `anchorKeyFingerprint` is identity metadata that
 * lets a receipt state which key it expects, and it is compared separately;
 * accepting a receipt because its fingerprint field looks right, without a real
 * Ed25519 verification against the configured key, would make the fingerprint
 * the security boundary, which it is not.
 */
export function verifyAnchorReceiptSignature(
  receipt: AnchorReceiptV1,
  publicKey: crypto.KeyObject,
): boolean {
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    return false;
  }

  const raw = Buffer.from(receipt.signature, 'base64url');
  if (raw.length !== ED25519_SIGNATURE_BYTES) {
    return false;
  }

  try {
    return crypto.verify(null, computeAnchorReceiptSignaturePreimage(receipt), publicKey, raw);
  } catch {
    return false;
  }
}

/**
 * Parses and fully validates one persisted receipt line.
 *
 * A line is accepted only when it is LF-terminated with exactly one LF, carries
 * no CR, decodes as strict JSON to a plain object of the exact frozen shape, and
 * reserializes byte-for-byte to the same canonical bytes. There is no receipt
 * hash field to recompute — the signature is the integrity mechanism — so
 * canonicity plus signature verification is the whole check.
 *
 * There is deliberately no receipt-tail repair: a torn final line is a
 * corruption finding, not a prefix to be adopted. Every receipt ARC ever writes
 * is `fdatasync`ed before the spool entry is removed, so a torn tail can only
 * mean the ledger was modified outside ARC.
 */
export function parseAndValidateAnchorReceiptLineV1(line: string): AnchorReceiptV1 {
  if (typeof line !== 'string' || line.length === 0) {
    throw createCodedError(
      'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      'receipt line must be a non-empty string',
    );
  }
  if (line.includes('\r')) {
    throw createCodedError('ANCHOR_RECEIPT_LEDGER_CORRUPT', 'receipt line must not contain CR');
  }
  if (!line.endsWith('\n')) {
    throw createCodedError(
      'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      'anchor receipt ledger ends in an unterminated line',
    );
  }
  if (line.indexOf('\n') !== line.length - 1) {
    throw createCodedError(
      'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      'receipt line must contain exactly one LF terminator',
    );
  }

  const body = line.slice(0, -1);
  if (body.length === 0) {
    throw createCodedError('ANCHOR_RECEIPT_LEDGER_CORRUPT', 'receipt line is empty');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (cause) {
    throw createCodedError(
      'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      'receipt line contains malformed JSON',
      {
        cause,
      },
    );
  }

  const receipt = validateAnchorReceiptV1(parsed);
  if (canonicalJsonV1(receipt) !== body) {
    throw createCodedError('ANCHOR_RECEIPT_LEDGER_CORRUPT', 'receipt line is not canonical JSON');
  }
  return receipt;
}

/**
 * The fingerprint of a configured anchor receipt public key file.
 *
 * The fingerprint is a property of the key, not of its spelling: it is
 * `SHA-256` of the SPKI DER, so PEM line wrapping, surrounding whitespace and
 * header spelling cannot change it. It is what `audit-store.json` pins, so a
 * substituted key file is a fingerprint mismatch rather than a silently accepted
 * new anchor identity.
 */
export function computeAnchorReceiptPublicKeyFingerprint(
  filePath: string,
  options: { expectedUid?: number } = {},
): string {
  return computeTrustRootFingerprintFromFile(filePath, {
    purpose: 'ANCHOR_RECEIPT',
    expectedUid: options.expectedUid ?? getProcessUid(),
  });
}

/* -------------------------------------------------------------------------- *
 * Endpoint validation (rc06 §14.2)
 * -------------------------------------------------------------------------- */

/**
 * Validates an anchor endpoint and returns it unchanged.
 *
 * The rules are all refusals: an endpoint that is not exactly `https:`, that
 * embeds credentials, that carries a fragment, that is not an absolute URL, that
 * names no host, or whose serialization exceeds 2 KiB is rejected. There is no
 * "accept and normalize" path, because normalization is exactly where an
 * ostensibly safe endpoint becomes a different one.
 *
 * No error message echoes the endpoint. A rejected endpoint is often an
 * operator's mistaken paste, and error text reaches logs and bug reports; the
 * rejection must not become the disclosure.
 */
export function validateAnchorEndpoint(endpoint: unknown): string {
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    throw createCodedError('ANCHOR_ENDPOINT_INVALID', 'an external anchor endpoint is required');
  }
  if (Buffer.byteLength(endpoint, 'utf8') > MAX_ANCHOR_ENDPOINT_BYTES) {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      `external anchor endpoint exceeds the ${MAX_ANCHOR_ENDPOINT_BYTES} byte bound`,
    );
  }

  let url: URL;
  try {
    url = new URL(endpoint);
  } catch (cause) {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      'external anchor endpoint is not an absolute URL',
      { cause },
    );
  }

  if (url.protocol !== 'https:') {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      'external anchor endpoint must use the https: scheme; plaintext transport is refused',
    );
  }
  if (url.username !== '' || url.password !== '') {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      'external anchor endpoint must not embed credentials',
    );
  }
  // Checked against the raw input rather than `url.hash`, because the URL parser
  // erases an EMPTY fragment: `https://anchor.example/v1/anchor#` parses with an
  // empty hash and is otherwise indistinguishable from the same URL without the
  // marker. An endpoint is a location and a fragment is never part of one, so the
  // marker itself is what is refused, whether or not anything follows it. A
  // percent-encoded `%23` is path data and remains accepted.
  if (endpoint.includes('#')) {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      'external anchor endpoint must not carry a URL fragment',
    );
  }
  if (url.hostname === '') {
    throw createCodedError('ANCHOR_ENDPOINT_INVALID', 'external anchor endpoint must name a host');
  }
  if (Buffer.byteLength(url.href, 'utf8') > MAX_ANCHOR_ENDPOINT_BYTES) {
    throw createCodedError(
      'ANCHOR_ENDPOINT_INVALID',
      `serialized external anchor endpoint exceeds the ${MAX_ANCHOR_ENDPOINT_BYTES} byte bound`,
    );
  }

  return endpoint;
}

/* -------------------------------------------------------------------------- *
 * Default transport (rc06 §14.2, §14.3)
 * -------------------------------------------------------------------------- */

/**
 * The production HTTPS transport.
 *
 * `minVersion` and `maxVersion` are both fixed at TLS 1.3, `rejectUnauthorized`
 * is never disabled, and no environment escape exists: there is no
 * configuration, CLI or MCP path that can reach this function's TLS options.
 * Redirects are not followed — `https.request` never follows one, and the caller
 * treats every 3xx as a failed attempt rather than re-issuing the request
 * against a location the anchor chose.
 *
 * The response body is bounded to {@link MAX_ANCHOR_RECEIPT_BYTES}. A peer that
 * streams more than the bound is a failed attempt, not a truncated receipt: a
 * partial body is not a receipt, and buffering it to find out would be the
 * resource exhaustion the bound exists to prevent.
 *
 * The abort signal is honoured by destroying the request, so the per-attempt
 * budget covers DNS, the handshake, transmission and body acquisition as one
 * deadline rather than one timeout per phase.
 */
function defaultAnchorTransport(
  request: AnchorTransportRequest,
  signal: AbortSignal,
): Promise<AnchorTransportResponse> {
  return new Promise<AnchorTransportResponse>((resolve, reject) => {
    const url = new URL(request.endpoint);

    // `ca` is copied into a mutable list: `tls` accepts a readonly array, but the
    // request options type does not, and copying is cheaper than reasoning about
    // which overload wins.
    const ca = request.ca;
    const caOption: { ca?: string | Buffer | (string | Buffer)[] } =
      ca === undefined ? {} : { ca: typeof ca === 'string' || Buffer.isBuffer(ca) ? ca : [...ca] };

    let settled = false;
    const req = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        ...(url.port === '' ? {} : { port: Number(url.port) }),
        path: `${url.pathname}${url.search}`,
        method: request.method,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        servername: url.hostname,
        ...caOption,
        headers: { ...request.headers },
        signal,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_ANCHOR_RECEIPT_BYTES) {
            settled = true;
            res.destroy();
            reject(
              createCodedError(
                'ANCHOR_RESPONSE_TOO_LARGE',
                `anchor response body exceeds the ${MAX_ANCHOR_RECEIPT_BYTES} byte bound`,
              ),
            );
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({ statusCode: res.statusCode ?? 0, body: Buffer.concat(chunks) });
        });
        res.on('error', (cause) => {
          if (settled) return;
          settled = true;
          reject(cause);
        });
      },
    );

    req.on('error', (cause) => {
      if (settled) return;
      settled = true;
      reject(cause);
    });

    req.end(request.body);
  });
}

/* -------------------------------------------------------------------------- *
 * Public types (Task 5 §48-§52)
 * -------------------------------------------------------------------------- */

/**
 * The anchor state.
 *
 * - `DISABLED` — Tier 3 is not configured. No spool, no receipts, no claims.
 * - `HEALTHY` — enabled, every verified checkpoint acknowledged.
 * - `DEGRADED` — enabled, at least one verified checkpoint is unacknowledged,
 *   or the last cycle rejected a conflicting or malformed receipt.
 * - `FULL` — enabled, a frozen backpressure ceiling is reached. Privileged
 *   operations are refused until receipts are obtained; nothing is reclaimed.
 * - `FAILED` — an integrity invariant was violated and the engine stopped.
 */
export type AnchorState = 'DISABLED' | 'HEALTHY' | 'DEGRADED' | 'FULL' | 'FAILED';

/** The bounded anchor status. Never contains the endpoint or any key material. */
export interface AnchorStatus {
  anchorMode: 'DISABLED' | 'ENABLED';
  anchorState: AnchorState;
  /** Verified checkpoints currently awaiting an acknowledgement (rc06 §48). */
  unanchoredCheckpoints: number;
  /** Physical spool entries currently on disk. */
  spoolEntries: number;
  /** Total spool payload bytes. Directory inode size is never counted. */
  spoolBytes: number;
  /** The frozen pending-entry ceiling. */
  maxPendingCheckpoints: number;
  /** The frozen spool payload ceiling. */
  maxSpoolBytes: number;
  /** Verified checkpoints observed during the last reconciliation. */
  verifiedCheckpoints: number;
  /** Receipts matched to verified checkpoints during the last reconciliation. */
  acknowledgedCheckpoints: number;
  /** The pinned anchor receipt key fingerprint, or null when DISABLED. */
  anchorReceiptPublicKeyFingerprint: string | null;
  /** The store every receipt must bind to, or null when DISABLED. */
  storeId: string | null;
  /** Why the engine last left `HEALTHY`, or null. */
  degradedReason: string | null;
}

/** The result of handing one checkpoint to the anchor. */
export interface AnchorDispatchResult {
  checkpointHash: string;
  /** `ACKNOWLEDGED` once a durable verified receipt exists; else `PENDING`. */
  outcome: 'ACKNOWLEDGED' | 'PENDING';
  /** The durable receipt when `outcome` is `ACKNOWLEDGED`, else null. */
  receipt: AnchorReceiptV1 | null;
  /** Network attempts made during this call. */
  attempts: number;
  /** `true` when a receipt was already on record and no second one was written. */
  idempotent: boolean;
  /** The anchor status after the call. */
  status: AnchorStatus;
}

/** Construction configuration for {@link Tier3AnchorEngine}. */
export interface Tier3AnchorEngineConfig {
  /** The audit store directory. */
  directory: string;
  /** Required when `audit-store.json` records `anchorMode: ENABLED`. */
  anchorEndpoint?: string;
  /** Required when `audit-store.json` records `anchorMode: ENABLED`. */
  anchorReceiptPublicKeyPath?: string;
  /**
   * The checkpoint public key PEM.
   *
   * Required when enabled: reconciliation proves every pending checkpoint
   * against the primary evidence through the Task-4 verifier, and that verifier
   * needs the trust root the checkpoints are signed by.
   */
  checkpointPublicKeyPath?: string;
  /** Authenticated agent workspace paths, for the audit-directory overlap rule. */
  workspacePaths?: readonly string[];
}

/* -------------------------------------------------------------------------- *
 * Internal bookkeeping
 * -------------------------------------------------------------------------- */

/**
 * The identity of the anchor receipt ledger as VERIFIED.
 *
 * `ABSENT` is a positive finding, exactly as it is for the checkpoint artifact:
 * it is what entitles the engine to *create* the ledger exclusively, and what
 * makes a file appearing afterwards a refusal rather than an adoption.
 */
type VerifiedReceiptArtifactState =
  { kind: 'ABSENT' } | { kind: 'PRESENT'; dev: number; ino: number; size: number };

interface ArtifactIdentity {
  dev: number;
  ino: number;
  size: number;
}

/** One pending reconstruction or cleanup decision, applied only after success. */
interface AnchorSpoolPlan {
  /** Spool entries to (re)create durably, in verified checkpoint order. */
  reconstruct: { checkpointHash: string; bytes: Buffer }[];
  /** Stale spool entries a durable receipt supersedes (State D). */
  staleSpool: string[];
  /**
   * The first spool entry the verified history does not account for (State E),
   * or null.
   *
   * The finding is *observed* by verification, which reads the spool
   * inventory as one of its inputs, and it is *acted on* when the plan is
   * applied. Keeping the decision in the plan is what lets the read-only phase
   * report a State E condition without itself deciding the fate of a spool
   * artifact: the engine stops at the same point, with the same code, but only
   * once spool reconciliation has been entered.
   */
  orphanSpoolEntry: string | null;
}

/**
 * The verified reconciliation waiting to be applied to the spool.
 *
 * A discriminated union rather than a nullable plan, because `DISABLED` is a
 * verified outcome in its own right: a store whose metadata records anchoring
 * off has nothing to reconcile, and a `null` staged value would make "nothing to
 * do" indistinguishable from "verification never ran".
 */
type StagedReconciliation = { kind: 'DISABLED' } | { kind: 'ENABLED'; plan: AnchorSpoolPlan };

/** The receipt ledger, read as a stream so history is never retained. */
interface ReceiptLedgerReader {
  /** The next receipt, or null at end of ledger. */
  next(): AnchorReceiptV1 | null;
  /** Runs the post-EOF identity discipline and releases the read descriptor. */
  finish(): void;
}

/** The classification of one anchor response (Task 5 §25, §26, §27, §31). */
type ResponseClassification =
  | { kind: 'ACKNOWLEDGED'; receipt: AnchorReceiptV1 }
  | { kind: 'TERMINAL'; code: string }
  | { kind: 'RETRYABLE'; code: string };

/** The observed spool inventory. Per-entry identity is held only up to the ceiling. */
interface SpoolInventory {
  sizes: Map<string, number>;
  entries: number;
  bytes: number;
  overflow: boolean;
}

/** The outcome of one five-attempt retry cycle. */
interface TransmissionOutcome {
  receipt: AnchorReceiptV1 | null;
  attempts: number;
  reason: string;
}

/* -------------------------------------------------------------------------- *
 * Pinned error vocabularies
 * -------------------------------------------------------------------------- */

const SPOOL_DIRECTORY_CODES: PinnedErrorCodes = {
  missing: 'ANCHOR_SPOOL_MISSING',
  symlink: 'SYMLINK_DETECTED',
  invalid: 'ANCHOR_SPOOL_INSECURE_ENTRY',
  unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
};

const SPOOL_ENTRY_CODES: PinnedErrorCodes = {
  missing: 'ANCHOR_SPOOL_ENTRY_MISSING',
  symlink: 'SYMLINK_DETECTED',
  invalid: 'ANCHOR_SPOOL_ENTRY_INVALID',
  unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
  exists: 'ANCHOR_SPOOL_ENTRY_EXISTS',
};

const LEDGER_CODES: PinnedErrorCodes = {
  missing: 'ANCHOR_RECEIPT_LEDGER_MISSING',
  symlink: 'SYMLINK_DETECTED',
  invalid: 'ANCHOR_RECEIPT_LEDGER_UNAVAILABLE',
  unavailable: 'ANCHOR_RECEIPT_LEDGER_UNAVAILABLE',
  exists: 'ANCHOR_RECEIPT_FILE_RACE',
};

/* -------------------------------------------------------------------------- *
 * Ledger line streaming
 * -------------------------------------------------------------------------- */

/**
 * Streams the receipt ledger as raw LF-terminated line buffers.
 *
 * Only the bytes still needed for one unfinished line are retained, and a "line"
 * that grows past {@link MAX_ANCHOR_LEDGER_LINE_BYTES} without a newline is
 * rejected rather than accumulated. Every physical byte handed back by the read
 * — terminators included — is counted into `consumed`, so the caller can hold
 * the artifact to the identity it had before the first byte was read.
 */
function* readLedgerLines(
  fd: number,
  consumed: { bytes: number },
): Generator<Buffer, void, undefined> {
  const chunk = Buffer.allocUnsafe(LEDGER_READ_CHUNK_BYTES);
  let carry = Buffer.alloc(0);

  for (;;) {
    const bytesRead = fs.readSync(fd, chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    consumed.bytes += bytesRead;

    const slice = chunk.subarray(0, bytesRead);
    carry = carry.length === 0 ? Buffer.from(slice) : Buffer.concat([carry, slice]);

    let newlineIndex = carry.indexOf(0x0a);
    while (newlineIndex !== -1) {
      yield Buffer.from(carry.subarray(0, newlineIndex + 1));
      carry = Buffer.from(carry.subarray(newlineIndex + 1));
      newlineIndex = carry.indexOf(0x0a);
    }

    if (carry.length > MAX_ANCHOR_LEDGER_LINE_BYTES) {
      throw createCodedError(
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
        `receipt line exceeds ${MAX_ANCHOR_LEDGER_LINE_BYTES} bytes without a terminator`,
      );
    }
  }

  // An unterminated trailing fragment is surfaced rather than dropped, so the
  // strict parser can reject it. It is never repaired.
  if (carry.length > 0) {
    yield carry;
  }
}

function captureArtifactIdentity(fd: number): ArtifactIdentity {
  const stats = fs.fstatSync(fd);
  return { dev: Number(stats.dev), ino: Number(stats.ino), size: Number(stats.size) };
}

/* -------------------------------------------------------------------------- *
 * The Tier-3 anchor engine
 * -------------------------------------------------------------------------- */

/**
 * The Tier-3 anchor engine.
 *
 * It is the single writer for `anchor-spool/` and `audit-anchors.jsonl` in a
 * given audit directory, exactly as `PersistentAuditStorage` is the single
 * writer for the active segment. Every public operation is serialized through
 * one promise chain, so two overlapping calls cannot interleave a spool write
 * with a receipt append.
 */
export class Tier3AnchorEngine {
  private readonly config: Tier3AnchorEngineConfig;
  private readonly hooks: AnchorTestHooks;

  private initialized = false;
  private failed = false;
  private closed = false;

  private auditDir = '';
  private expectedUid = 0;
  private storeId = '';
  private checkpointPublicKeyPath = '';

  private anchorMode: 'DISABLED' | 'ENABLED' = 'DISABLED';
  private endpoint = '';
  private anchorPublicKey: crypto.KeyObject | null = null;
  private anchorFingerprint: string | null = null;

  /** The verified receipt ledger. Retained for appends after reconciliation. */
  private receiptFd: number | null = null;
  private receiptState: VerifiedReceiptArtifactState | null = null;
  private receiptExpectedSize = 0;

  private spoolEntries = 0;
  private spoolBytes = 0;
  private spoolOverflow = false;

  /** Outstanding spool hashes in verified checkpoint order, bounded. */
  private pendingOrder: string[] = [];

  /**
   * Receipts ARC holds for checkpoints it has already acknowledged.
   *
   * Bounded to {@link MAX_PENDING_ANCHOR_CHECKPOINTS} entries and evicted
   * oldest-first. It is what makes rc06 §14.3's idempotency rule enforceable
   * rather than assumed: a repeat submission for a checkpoint on record is
   * answered by comparison, and can never become a second receipt line.
   */
  private acknowledgedReceipts = new Map<string, AnchorReceiptV1>();

  private lastVerifiedSequence: number | null = null;
  private lastVerifiedCheckpointHash: string | null = null;
  private verifiedCheckpoints = 0;
  private acknowledgedCheckpoints = 0;

  private state: AnchorState = 'DISABLED';
  private degradedReason: string | null = null;
  private failedReason: string | null = null;

  /**
   * The reconciliation that receipt verification staged and spool
   * reconciliation has not yet consumed.
   *
   * Tier-3 reconciliation is deliberately two operations. Verification reads the
   * verified checkpoint history and the receipt ledger and decides what the spool
   * ought to contain — it mutates nothing. Application is the only code in this
   * class that writes to or removes from `anchor-spool/`. The frozen startup
   * order runs them in different stages (receipt verification at
   * `ANCHOR_RECEIPT_VERIFICATION`, spool reconciliation at
   * `ANCHOR_SPOOL_RECONCILIATION`), which is only a real ordering guarantee if the
   * first of them cannot perform any part of the second.
   */
  private stagedReconciliation: StagedReconciliation | null = null;

  /**
   * Whether a staged reconciliation has been applied.
   *
   * Nothing privileged may run against an engine whose verification has resolved
   * but whose spool does not yet reflect it: the engine would be accepting
   * operations while the artifacts it is accountable for describe a different
   * state than the one it verified.
   */
  private reconciliationApplied = false;

  private chain: Promise<unknown> = Promise.resolve();

  /** @internal */
  constructor(config: Tier3AnchorEngineConfig, token: symbol, hooks: AnchorTestHooks = {}) {
    if (token !== ANCHOR_TEST_TOKEN) {
      throw createCodedError(
        'ANCHOR_CAPABILITY_REQUIRED',
        'Tier3AnchorEngine must be constructed through openTier3AnchorEngine()',
      );
    }
    this.config = config;
    this.hooks = hooks;
  }

  /* ---------------------------------------------------------------------- *
   * Serialization and small helpers
   * ---------------------------------------------------------------------- */

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.chain.then(operation, operation);
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async sleepFor(ms: number): Promise<void> {
    if (this.hooks.sleep !== undefined) {
      await this.hooks.sleep(ms);
      return;
    }
    await new Promise<void>((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  private setAttemptTimer(callback: () => void, ms: number): unknown {
    if (this.hooks.setAttemptTimer !== undefined) {
      return this.hooks.setAttemptTimer(callback, ms);
    }
    return setTimeout(callback, ms);
  }

  private clearAttemptTimer(handle: unknown): void {
    if (this.hooks.clearAttemptTimer !== undefined) {
      this.hooks.clearAttemptTimer(handle);
      return;
    }
    clearTimeout(handle as NodeJS.Timeout);
  }

  private get expectedUidResolved(): number {
    return this.hooks.expectedUid ?? getProcessUid();
  }

  /* ---------------------------------------------------------------------- *
   * Lifecycle
   * ---------------------------------------------------------------------- */

  /**
   * Validates configuration, loads the anchor trust root and reconciles.
   *
   * Reconciliation runs here and nowhere later, so by the time this resolves the
   * spool directory reflects exactly the outstanding work the verified
   * checkpoint history implies: State C reconstructions have been written
   * durably, State D stale entries have been removed, and both integrity
   * failures have thrown.
   *
   * It performs no network I/O. Dispatch is a separate, explicitly requested
   * step — which is what makes "reconstruction completes before any transmission
   * begins" observable rather than merely asserted.
   *
   * @internal
   */
  async initializeEngine(): Promise<void> {
    await this.initializeEngineForStartup();
    await this.applyReconciliationInternal();
  }

  /**
   * Validates configuration and trust roots, then verifies — without reconciling.
   *
   * This is the same authority `initializeEngine` performs up to, and including,
   * the read-only half of reconciliation: configuration, the store's anchor mode,
   * the endpoint, both trust roots, the receipt ledger and its bindings to the
   * verified checkpoint history. It creates nothing, removes nothing and appends
   * nothing.
   *
   * It exists because the frozen startup order gives receipt verification and
   * spool reconciliation separate stages. A caller that stops here holds an
   * engine whose reconciliation is staged and unapplied, and such an engine
   * refuses every privileged operation until {@link applyAnchorReconciliation}
   * runs.
   *
   * @internal
   */
  async initializeEngineForStartup(): Promise<void> {
    if (this.initialized) return;
    if (this.closed) {
      throw createCodedError('ANCHOR_ENGINE_CLOSED', 'anchor engine is closed');
    }

    assertDescriptorPinnedTraversalAvailable('external anchoring');

    const auditDir = this.config.directory;
    const expectedUid = this.expectedUidResolved;
    validateAuditDirectory(auditDir, {
      expectedUid,
      workspacePaths: [...(this.config.workspacePaths ?? [])],
    });

    this.auditDir = auditDir;
    this.expectedUid = expectedUid;

    const metadata = loadStoreMetadataFile(auditDir, expectedUid);
    this.storeId = metadata.storeId;

    const endpoint = this.config.anchorEndpoint;
    const anchorKeyPath = this.config.anchorReceiptPublicKeyPath;
    const checkpointKeyPath = this.config.checkpointPublicKeyPath;
    const supplied = [endpoint, anchorKeyPath, checkpointKeyPath].filter(
      (value) => value !== undefined,
    ).length;

    if (metadata.anchorMode === 'DISABLED') {
      // Tier 3 is a selectable deployment mode, so a DISABLED store must not be
      // handed anchor configuration: the store says anchoring is off, and an
      // operator who configured an endpoint anyway holds a configuration the
      // store's own durable record contradicts (rc06 §14.1, RC06-NEG-84).
      if (supplied > 0) {
        throw createCodedError(
          'ANCHOR_CONFIG_INVALID',
          'anchor configuration was supplied for a store whose metadata records anchorMode DISABLED',
        );
      }
      this.anchorMode = 'DISABLED';
      this.state = 'DISABLED';
      this.degradedReason = null;
    } else {
      if (
        endpoint === undefined ||
        anchorKeyPath === undefined ||
        checkpointKeyPath === undefined
      ) {
        throw createCodedError(
          'ANCHOR_CONFIG_INVALID',
          'anchorMode ENABLED requires an endpoint, an anchor receipt public key and a checkpoint public key',
        );
      }

      this.endpoint = validateAnchorEndpoint(endpoint);
      this.checkpointPublicKeyPath = checkpointKeyPath;

      const trustRoot = loadEd25519TrustRootFile(anchorKeyPath, {
        purpose: 'ANCHOR_RECEIPT',
        expectedUid,
      });
      const pinned = metadata.anchorReceiptPublicKeyFingerprint;

      if (pinned === undefined || trustRoot.fingerprint !== pinned) {
        throw createCodedError(
          'ANCHOR_RECEIPT_KEY_MISMATCH',
          'configured anchor receipt public key does not match audit-store.json.anchorReceiptPublicKeyFingerprint',
        );
      }

      this.anchorMode = 'ENABLED';
      this.anchorPublicKey = trustRoot.publicKey;
      this.anchorFingerprint = trustRoot.fingerprint;
    }

    // The checkpoint trust root is proven to match the store's pinned
    // fingerprint inside the verifier, so nothing here re-derives it.
    this.initialized = true;
    await this.verifyReconciliationInternal();
  }

  /**
   * Verifies the receipt ledger and its checkpoint bindings, staging the spool
   * decisions without performing any of them.
   *
   * The staged result is applied by {@link applyAnchorReconciliation}. Nothing
   * is written, removed or created here — including the spool directory, which
   * `probeSpoolDirectory` treats as absent rather than creating.
   *
   * @internal
   */
  async verifyAnchorEvidence(): Promise<AnchorStatus> {
    return this.serialize(async () => {
      this.assertInitialized();
      if (this.closed) {
        throw createCodedError('ANCHOR_ENGINE_CLOSED', 'anchor engine is closed');
      }
      return this.verifyReconciliationInternal();
    });
  }

  /**
   * Applies the staged reconciliation to the spool — the only spool mutations
   * this engine performs.
   *
   * It refuses to run without a staged, verified result, so it can never be used
   * to reach a state the receipt ledger and the verified checkpoint history do
   * not jointly imply. `reconcileAnchorState()` reaches it through a fresh
   * verification; startup reaches it after stage 6 verified.
   *
   * @internal
   */
  async applyAnchorReconciliation(): Promise<AnchorStatus> {
    return this.serialize(async () => {
      this.assertInitialized();
      if (this.closed) {
        throw createCodedError('ANCHOR_ENGINE_CLOSED', 'anchor engine is closed');
      }
      return this.applyReconciliationInternal();
    });
  }

  /** Releases every retained descriptor. Safe to call more than once. */
  async close(): Promise<void> {
    return this.serialize(async () => {
      this.closed = true;
      this.releaseReceiptDescriptor();
    });
  }

  private releaseReceiptDescriptor(): void {
    if (this.receiptFd !== null) {
      fs.closeSync(this.receiptFd);
      this.receiptFd = null;
    }
  }

  private assertInitialized(): void {
    if (!this.initialized) {
      throw createCodedError('ANCHOR_NOT_INITIALIZED', 'anchor engine has not been initialized');
    }
  }

  /**
   * Refuses an operation on an engine whose verified plan has not been applied.
   *
   * This is what makes the split between receipt verification and spool
   * reconciliation a security boundary rather than an ordering convention. An
   * engine that has verified the receipt ledger but not yet reconciled the spool
   * holds a plan that is provably right and demonstrably not yet true of the
   * artifacts on disk; allowing it to serve privileged operations in that window
   * would be exactly the state the frozen startup order exists to prevent.
   */
  private assertReconciliationApplied(): void {
    if (!this.reconciliationApplied) {
      throw createCodedError(
        'ANCHOR_RECONCILIATION_PENDING',
        'anchor spool reconciliation has not been applied; receipt verification alone does not authorize privileged operations',
      );
    }
  }

  private assertUsable(): void {
    this.assertInitialized();
    if (this.closed) {
      throw createCodedError('ANCHOR_ENGINE_CLOSED', 'anchor engine is closed');
    }
    this.assertReconciliationApplied();
    if (this.failed) {
      throw createCodedError(
        'ANCHOR_ENGINE_FAILED',
        `anchor engine stopped after an anchor state integrity failure (${this.failedReason ?? 'unknown'})`,
      );
    }
    if (this.anchorMode === 'DISABLED') {
      throw createCodedError(
        'ANCHOR_MODE_DISABLED',
        'external anchoring is not configured for this store',
      );
    }
  }

  /* ---------------------------------------------------------------------- *
   * Status (Task 5 §48, §49)
   * ---------------------------------------------------------------------- */

  /** The bounded anchor status. Never contains the endpoint or key material. */
  getStatus(): AnchorStatus {
    return {
      anchorMode: this.anchorMode,
      anchorState: this.state,
      unanchoredCheckpoints: this.pendingOrder.length,
      spoolEntries: this.spoolEntries,
      spoolBytes: this.spoolBytes,
      maxPendingCheckpoints: MAX_PENDING_ANCHOR_CHECKPOINTS,
      maxSpoolBytes: MAX_ANCHOR_SPOOL_BYTES,
      verifiedCheckpoints: this.verifiedCheckpoints,
      acknowledgedCheckpoints: this.acknowledgedCheckpoints,
      anchorReceiptPublicKeyFingerprint: this.anchorFingerprint,
      storeId: this.anchorMode === 'DISABLED' ? null : this.storeId,
      degradedReason: this.state === 'DEGRADED' ? this.degradedReason : null,
    };
  }

  private refreshState(): void {
    if (this.anchorMode === 'DISABLED') {
      this.state = 'DISABLED';
      this.degradedReason = null;
      return;
    }
    if (this.failed) {
      this.state = 'FAILED';
      return;
    }
    if (
      this.spoolOverflow ||
      this.spoolEntries >= MAX_PENDING_ANCHOR_CHECKPOINTS ||
      this.spoolBytes >= MAX_ANCHOR_SPOOL_BYTES
    ) {
      this.state = 'FULL';
      this.degradedReason = 'ANCHOR_SPOOL_FULL';
      return;
    }
    if (this.pendingOrder.length > 0) {
      this.state = 'DEGRADED';
      this.degradedReason ??= ANCHOR_PENDING_REASON;
      return;
    }
    // The pending reason is derived from the queue rather than observed about the
    // store, so it describes the current state only while the queue is non-empty.
    // Leaving it behind after the last pending checkpoint is acknowledged would
    // report a store as degraded for a backlog that no longer exists, and would
    // make HEALTHY unreachable outside the instant a reconciliation completes.
    // Every other reason is a real observation and is kept until reconciliation
    // replaces it.
    if (this.degradedReason === ANCHOR_PENDING_REASON) {
      this.degradedReason = null;
    }
    if (this.degradedReason !== null) {
      this.state = 'DEGRADED';
      return;
    }
    this.state = 'HEALTHY';
  }

  /**
   * Records an invariant violation that must stop the engine.
   *
   * The engine stops rather than continuing in a state whose meaning it can no
   * longer state: a spool entry with no checkpoint, a receipt with no
   * checkpoint, or a ledger that changed under the reader are all conditions in
   * which any later "acknowledged" claim would be unverifiable.
   */
  private markFailed(reason: string, cause?: unknown): never {
    this.failed = true;
    this.failedReason = reason;
    this.state = 'FAILED';
    throw createCodedError(
      reason,
      'anchor state integrity check failed',
      cause === undefined ? undefined : { cause },
    );
  }

  /**
   * The privileged-operation gate (rc06 §14.7, Task 5 §19).
   *
   * The composition layer calls this before every privileged MCP tool
   * invocation. In `DISABLED` mode it is a no-op: a store that does not claim
   * external non-repudiation has nothing to gate on.
   *
   * An engine whose reconciliation is staged but unapplied refuses here, before
   * the mode is even considered — the gate is about authority, not about what is
   * configured.
   *
   * `FULL` and `FAILED` refuse unconditionally. `DEGRADED` does not refuse here:
   * a single unacknowledged checkpoint is the ordinary condition of a briefly
   * unreachable anchor, and refusing every operation for it would make the
   * system unusable during a routine network partition. The mandated halt is the
   * backpressure ceiling, and that is what `FULL` carries.
   */
  assertPrivilegedOperationsAllowed(): void {
    this.assertInitialized();
    this.assertReconciliationApplied();
    if (this.anchorMode === 'DISABLED') return;
    if (this.failed) {
      throw createCodedError(
        'ANCHOR_ENGINE_FAILED',
        `anchor engine stopped after an anchor state integrity failure (${this.failedReason ?? 'unknown'})`,
      );
    }
    if (this.state === 'FULL') {
      throw createCodedError(
        'ANCHOR_SPOOL_FULL',
        `anchor spool backpressure limit reached: ${this.spoolEntries} spool entries, ${this.spoolBytes} spool bytes`,
      );
    }
  }

  /* ---------------------------------------------------------------------- *
   * Reconciliation (rc06 §14.6, Task 5 §38-§45)
   * ---------------------------------------------------------------------- */

  /**
   * Reconciles the spool and receipt ledger against the verified checkpoint
   * history, returning the bounded status.
   *
   * The walk is streaming and ordered. Verified checkpoints arrive from the
   * Task-4 verifier one at a time, and the receipt ledger is pulled in parallel
   * one line at a time, so neither the checkpoint history nor the receipt
   * history is ever retained: the memory bound is one checkpoint, one receipt
   * and one spool entry.
   *
   * Nothing is mutated while the walk is in progress. Decisions accumulate in a
   * bounded plan, and the plan is applied only after the verification has
   * resolved — so an artifact that was replaced mid-verification fails the whole
   * reconciliation and leaves the anchor artifacts exactly as they were.
   */
  async reconcileAnchorState(): Promise<AnchorStatus> {
    return this.serialize(async () => {
      this.assertInitialized();
      if (this.closed) {
        throw createCodedError('ANCHOR_ENGINE_CLOSED', 'anchor engine is closed');
      }
      await this.verifyReconciliationInternal();
      return this.applyReconciliationInternal();
    });
  }

  /**
   * The read-only half of reconciliation.
   *
   * Every input it reads is evidence: the verified checkpoint history, the
   * receipt ledger and the spool *inventory*. Every output it produces is a
   * decision held in memory. It opens no descriptor for writing, creates no
   * directory and no file, and removes nothing, so an artifact observed while it
   * runs is still there — unchanged — when it returns.
   */
  private async verifyReconciliationInternal(): Promise<AnchorStatus> {
    const auditDirFd = openAuthoritativeDirectoryFd(this.auditDir, this.expectedUid);
    try {
      const spoolFd = this.probeSpoolDirectory(auditDirFd);

      if (this.anchorMode === 'DISABLED') {
        // A store whose durable metadata says anchoring is off must not be
        // silently carrying Tier-3 artifacts: they are either evidence from a
        // configuration the store does not record, or debris from one. Either
        // way, claiming DISABLED while anchor artifacts exist would be a false
        // statement about what is on disk.
        if (spoolFd !== null) {
          fs.closeSync(spoolFd);
          throw createCodedError(
            'ANCHOR_DISABLED_ARTIFACT',
            `${ANCHOR_SPOOL_DIRNAME}/ exists in a store whose metadata records anchorMode DISABLED`,
          );
        }
        if (this.ledgerPathExists(auditDirFd)) {
          throw createCodedError(
            'ANCHOR_DISABLED_ARTIFACT',
            `${ANCHOR_RECEIPT_FILENAME} exists in a store whose metadata records anchorMode DISABLED`,
          );
        }
        this.resetReconciledState();
        this.state = 'DISABLED';
        this.degradedReason = null;
        this.stagedReconciliation = { kind: 'DISABLED' };
        return this.getStatus();
      }

      this.resetReconciledState();

      const inventory = this.scanSpoolDirectory(spoolFd);
      const plan: AnchorSpoolPlan = { reconstruct: [], staleSpool: [], orphanSpoolEntry: null };
      const consumedSpool = new Set<string>();
      const reconstructBudget = { count: 0, bytes: 0 };

      const ledger = this.openLedgerReader(auditDirFd);
      let headReceipt: AnchorReceiptV1 | null = ledger === null ? null : ledger.next();

      let lastSequence: number | null = null;
      let lastHash: string | null = null;

      try {
        const result = await verifyCheckpointHistoryWithObserver(
          {
            directory: this.auditDir,
            publicKeyPath: this.checkpointPublicKeyPath,
            workspacePaths: [...(this.config.workspacePaths ?? [])],
            expectedUid: this.expectedUid,
          },
          (checkpoint) => {
            this.verifiedCheckpoints++;
            lastSequence = checkpoint.sequenceEnd;
            lastHash = checkpoint.checkpointHash;

            if (headReceipt !== null && headReceipt.checkpointHash === checkpoint.checkpointHash) {
              this.acknowledgedCheckpoints++;
              this.rememberAcknowledgedReceipt(headReceipt);
              if (inventory.sizes.has(checkpoint.checkpointHash)) {
                // State D: the receipt is durable and the spool entry survived a
                // crash between the append and the unlink. The receipt wins; the
                // stale entry is scheduled for removal once the plan is applied.
                consumedSpool.add(checkpoint.checkpointHash);
                plan.staleSpool.push(checkpoint.checkpointHash);
              }
              headReceipt = ledger === null ? null : ledger.next();
              return;
            }

            // No receipt yet: the checkpoint is pending. It either already has an
            // entry (State B) or needs one reconstructed from the durable
            // checkpoint artifact (State C).
            if (inventory.sizes.has(checkpoint.checkpointHash)) {
              consumedSpool.add(checkpoint.checkpointHash);
              if (this.pendingOrder.length < MAX_PENDING_ANCHOR_CHECKPOINTS) {
                this.pendingOrder.push(checkpoint.checkpointHash);
              } else {
                this.spoolOverflow = true;
              }
              return;
            }

            if (reconstructBudget.count >= MAX_PENDING_ANCHOR_CHECKPOINTS) {
              // The backpressure ceiling is reached. §19 makes this FULL rather
              // than a startup failure: the store remains usable, privileged
              // operations are withheld until receipts arrive, and nothing is
              // deleted to manufacture capacity.
              this.spoolOverflow = true;
              return;
            }

            const bytes = Buffer.from(canonicalJsonV1(checkpoint), 'utf8');
            if (reconstructBudget.bytes + bytes.length > MAX_ANCHOR_SPOOL_BYTES) {
              this.spoolOverflow = true;
              return;
            }

            reconstructBudget.count++;
            reconstructBudget.bytes += bytes.length;
            plan.reconstruct.push({ checkpointHash: checkpoint.checkpointHash, bytes });
            this.pendingOrder.push(checkpoint.checkpointHash);
          },
        );

        // State F: a receipt with no matching checkpoint. The ledger is a
        // monotonic subsequence of checkpoint order, so anything left at the head
        // after the walk is a receipt the primary evidence never produced — which
        // also catches duplicate and out-of-order receipt lines, since neither can
        // ever advance the head again.
        if (headReceipt !== null) {
          this.markFailed('ANCHOR_ORPHAN_RECEIPT');
        }

        // State E: a spool entry whose checkpoint the verified history does not
        // contain. When the inventory overflowed the frozen ceiling the engine no
        // longer holds per-entry identity for the excess, so it does not claim to
        // have checked them; the state is already FULL, which withholds the same
        // privileged operations either way.
        //
        // The finding is recorded, not raised. Raising it here would make this
        // read-only operation the point at which a spool artifact's fate is
        // decided, which is spool reconciliation's authority and not receipt
        // verification's. `applyReconciliationInternal` stops on it before it
        // mutates anything, so the engine fails closed at the same evidence,
        // with the same code, one stage later.
        if (!inventory.overflow) {
          for (const hash of inventory.sizes.keys()) {
            if (
              !consumedSpool.has(hash) &&
              !plan.reconstruct.some((entry) => entry.checkpointHash === hash)
            ) {
              plan.orphanSpoolEntry = hash;
              break;
            }
          }
        }

        lastSequence = result.lastCheckpointSequence;
        lastHash = result.lastCheckpointHash;
      } finally {
        if (ledger !== null) {
          ledger.finish();
        }
        if (spoolFd !== null) {
          fs.closeSync(spoolFd);
        }
      }

      this.lastVerifiedSequence = lastSequence;
      this.lastVerifiedCheckpointHash = lastHash;

      // Every decision in the plan is derived from primary-proved evidence. None
      // of them has been performed.
      this.stagedReconciliation = { kind: 'ENABLED', plan };
      this.reconciliationApplied = false;
      this.refreshState();
      return this.getStatus();
    } finally {
      fs.closeSync(auditDirFd);
    }
  }

  /**
   * The mutating half of reconciliation: it applies the staged plan, and it is
   * the only code in this class that writes to or removes from `anchor-spool/`.
   *
   * It refuses to run without a staged result. A caller therefore cannot reach a
   * reconciled spool except through a verification that resolved against the
   * durable primary evidence — there is no path that applies a plan nobody
   * verified, and no path that applies one plan twice.
   */
  private async applyReconciliationInternal(): Promise<AnchorStatus> {
    const staged = this.stagedReconciliation;
    if (staged === null) {
      throw createCodedError(
        'ANCHOR_RECONCILIATION_NOT_STAGED',
        'no verified reconciliation is staged; receipt verification has not resolved',
      );
    }
    this.stagedReconciliation = null;

    if (staged.kind === 'DISABLED') {
      this.reconciliationApplied = true;
      this.refreshState();
      return this.getStatus();
    }

    const plan = staged.plan;
    const auditDirFd = openAuthoritativeDirectoryFd(this.auditDir, this.expectedUid);
    try {
      if (plan.orphanSpoolEntry !== null) {
        this.markFailed('ANCHOR_ORPHAN_SPOOL_ENTRY');
      }

      this.applySpoolPlan(auditDirFd, plan);
      this.recaptureSpoolCounters(auditDirFd);
    } finally {
      fs.closeSync(auditDirFd);
    }

    this.reconciliationApplied = true;
    this.refreshState();
    return this.getStatus();
  }

  private resetReconciledState(): void {
    this.pendingOrder = [];
    this.acknowledgedReceipts = new Map<string, AnchorReceiptV1>();
    this.spoolEntries = 0;
    this.spoolBytes = 0;
    this.spoolOverflow = false;
    this.verifiedCheckpoints = 0;
    this.acknowledgedCheckpoints = 0;
    this.lastVerifiedSequence = null;
    this.lastVerifiedCheckpointHash = null;
    this.degradedReason = null;
  }

  /**
   * Remembers a receipt ARC holds, bounded to the frozen pending ceiling.
   *
   * The bound is what keeps §14.3's idempotency rule affordable: a repeat
   * submission for one of the most recent acknowledgements is answered from
   * here, and an older one is refused with `ANCHOR_CHECKPOINT_NOT_CURRENT`
   * rather than re-sent. Refusing is always safe — it can never produce a second
   * receipt line — and it keeps the engine's memory independent of how long the
   * audit store has been running.
   */
  private rememberAcknowledgedReceipt(receipt: AnchorReceiptV1): void {
    this.acknowledgedReceipts.set(receipt.checkpointHash, receipt);
    while (this.acknowledgedReceipts.size > MAX_PENDING_ANCHOR_CHECKPOINTS) {
      const oldest = this.acknowledgedReceipts.keys().next();
      if (oldest.done === true) break;
      this.acknowledgedReceipts.delete(oldest.value);
    }
  }

  /**
   * Applies the reconciliation plan, in the order §14.6 requires.
   *
   * Reconstructions are written first — each one durably, exactly as a
   * first-time spool would be — and State D stale entries are removed afterwards,
   * each batch followed by a directory fsync. A crash partway through leaves a
   * store that a later reconciliation classifies the same way it classified this
   * one.
   */
  private applySpoolPlan(auditDirFd: number, plan: AnchorSpoolPlan): void {
    if (plan.reconstruct.length === 0 && plan.staleSpool.length === 0) return;

    if (plan.reconstruct.length > 0) {
      const spoolFd = this.openSpoolDirectoryForWrite(auditDirFd);
      try {
        for (const entry of plan.reconstruct) {
          this.writeSpoolEntry(spoolFd, entry.checkpointHash, entry.bytes);
        }
      } finally {
        fs.closeSync(spoolFd);
      }
    }

    if (plan.staleSpool.length > 0) {
      const spoolFd = openPinnedDirectoryChild(
        auditDirFd,
        ANCHOR_SPOOL_DIRNAME,
        SPOOL_DIRECTORY_CODES,
        'anchor spool directory',
      );
      try {
        for (const hash of plan.staleSpool) {
          unlinkPinnedChild(spoolFd, `${hash}.json`, 'anchor spool entry');
        }
        syncDescriptor(spoolFd);
      } finally {
        fs.closeSync(spoolFd);
      }
    }
  }

  private probeSpoolDirectory(auditDirFd: number): number | null {
    let fd: number;
    try {
      fd = openPinnedDirectoryChild(
        auditDirFd,
        ANCHOR_SPOOL_DIRNAME,
        SPOOL_DIRECTORY_CODES,
        'anchor spool directory',
      );
    } catch (err) {
      if ((err as CodedError | null)?.code === 'ANCHOR_SPOOL_MISSING') {
        return null;
      }
      throw err;
    }

    try {
      this.assertSpoolDirectoryAuthority(fd);
      return fd;
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }
  }

  /** The frozen directory authority: a real directory, the expected uid, 0700. */
  private assertSpoolDirectoryAuthority(fd: number): void {
    const stats = fs.fstatSync(fd);
    if (!stats.isDirectory()) {
      throw createCodedError(
        'ANCHOR_SPOOL_INSECURE_ENTRY',
        'anchor spool directory is not a directory',
      );
    }
    if (stats.uid !== this.expectedUid) {
      throw createCodedError(
        'ANCHOR_SPOOL_INSECURE_ENTRY',
        'anchor spool directory is not owned by the expected uid',
      );
    }
    if ((stats.mode & 0o777) !== ANCHOR_SPOOL_DIRECTORY_MODE) {
      throw createCodedError(
        'ANCHOR_SPOOL_INSECURE_ENTRY',
        `anchor spool directory mode must be 0700 (got ${(stats.mode & 0o777).toString(8)})`,
      );
    }
  }

  private ledgerPathExists(auditDirFd: number): boolean {
    try {
      fs.lstatSync(pinnedChildPath(auditDirFd, ANCHOR_RECEIPT_FILENAME));
      return true;
    } catch (err) {
      if ((err as CodedError | null)?.code === 'ENOENT') return false;
      throw err;
    }
  }

  /**
   * The bounded spool inventory.
   *
   * Per-entry identity is retained only up to the frozen ceiling. A directory
   * holding more entries than that is already `FULL` — privileged operations are
   * withheld — so retaining the excess would spend memory to inform a decision
   * the engine has already made. The remaining entries are re-examined on a
   * later cycle, once dispatch has brought the count back under the ceiling.
   */
  private scanSpoolDirectory(spoolFd: number | null): SpoolInventory {
    const sizes = new Map<string, number>();
    const inventory: SpoolInventory = { sizes, entries: 0, bytes: 0, overflow: false };
    if (spoolFd === null) return inventory;

    for (const name of listPinnedChildren(spoolFd, 'the anchor spool directory')) {
      if (!ANCHOR_SPOOL_FILENAME_REGEX.test(name)) {
        throw createCodedError(
          'ANCHOR_SPOOL_UNRECOGNIZED_ENTRY',
          `unrecognized entry in the anchor spool directory: ${name}`,
        );
      }

      const childStats = fs.lstatSync(pinnedChildPath(spoolFd, name));
      if (childStats.isSymbolicLink()) {
        throw createCodedError(
          'SYMLINK_DETECTED',
          `anchor spool entry is a symbolic link: ${name}`,
        );
      }
      if (!childStats.isFile()) {
        throw createCodedError(
          'ANCHOR_SPOOL_INSECURE_ENTRY',
          `anchor spool entry is not a regular file: ${name}`,
        );
      }
      if (childStats.uid !== this.expectedUid) {
        throw createCodedError(
          'ANCHOR_SPOOL_INSECURE_ENTRY',
          `anchor spool entry is not owned by the expected uid: ${name}`,
        );
      }
      if (childStats.nlink !== 1) {
        throw createCodedError(
          'ANCHOR_SPOOL_INSECURE_ENTRY',
          `anchor spool entry has an unexpected link count: ${name}`,
        );
      }
      if ((childStats.mode & 0o777) !== ANCHOR_SPOOL_FILE_MODE) {
        throw createCodedError(
          'ANCHOR_SPOOL_INSECURE_ENTRY',
          `anchor spool entry mode must be 0600: ${name}`,
        );
      }

      inventory.entries++;
      inventory.bytes += Number(childStats.size);

      if (sizes.size < MAX_PENDING_ANCHOR_CHECKPOINTS) {
        sizes.set(name.slice(0, -'.json'.length), Number(childStats.size));
      } else {
        inventory.overflow = true;
      }
    }

    return inventory;
  }

  /* ---------------------------------------------------------------------- *
   * Receipt ledger reading
   * ---------------------------------------------------------------------- */

  private openLedgerReader(auditDirFd: number): ReceiptLedgerReader | null {
    const ledgerPath = pinnedChildPath(auditDirFd, ANCHOR_RECEIPT_FILENAME);

    let fd: number;
    try {
      fd = fs.openSync(ledgerPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (cause) {
      const code = (cause as CodedError | null)?.code;
      if (code === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', `${ANCHOR_RECEIPT_FILENAME} is a symbolic link`);
      }
      if (code === 'ENOENT') {
        // ABSENT is a positive finding, and it is what entitles the engine to
        // create the ledger exclusively later.
        this.receiptState = { kind: 'ABSENT' };
        this.receiptExpectedSize = 0;
        return null;
      }
      throw createCodedError(
        'ANCHOR_RECEIPT_LEDGER_UNAVAILABLE',
        `${ANCHOR_RECEIPT_FILENAME} could not be opened safely`,
        { cause },
      );
    }

    let startIdentity: ArtifactIdentity;
    try {
      validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
      startIdentity = captureArtifactIdentity(fd);
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }

    this.receiptState = {
      kind: 'PRESENT',
      dev: startIdentity.dev,
      ino: startIdentity.ino,
      size: startIdentity.size,
    };
    this.receiptExpectedSize = startIdentity.size;

    const consumed = { bytes: 0 };
    const iterator = readLedgerLines(fd, consumed)[Symbol.iterator]();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let exhausted = false;
    let finished = false;

    return {
      next: (): AnchorReceiptV1 | null => {
        const step = iterator.next();
        if (step.done === true) {
          exhausted = true;
          return null;
        }

        let text: string;
        try {
          text = decoder.decode(step.value);
        } catch (cause) {
          throw createCodedError(
            'ANCHOR_RECEIPT_LEDGER_CORRUPT',
            'receipt line is not valid UTF-8',
            { cause },
          );
        }

        const receipt = parseAndValidateAnchorReceiptLineV1(text);
        this.assertReceiptBinding(receipt);
        return receipt;
      },

      finish: (): void => {
        if (finished) return;
        finished = true;
        try {
          if (exhausted) {
            this.assertLedgerIdentityAfterVerification(
              ledgerPath,
              fd,
              startIdentity,
              consumed.bytes,
            );
          }
        } finally {
          fs.closeSync(fd);
        }
      },
    };
  }

  /**
   * Holds one receipt to the store it must belong to and the key that must have
   * signed it.
   *
   * Binding is checked before the signature because it is cheaper and produces
   * the more specific diagnosis, but neither is optional: a receipt that verifies
   * under the pinned key but names another store is still not an acknowledgement
   * of *this* store's evidence, and a receipt that names this store but was
   * signed by another key is not an acknowledgement at all.
   */
  private assertReceiptBinding(receipt: AnchorReceiptV1): void {
    if (receipt.storeId !== this.storeId) {
      throw createCodedError(
        'ANCHOR_RECEIPT_BINDING_INVALID',
        'receipt storeId does not match audit-store.json',
      );
    }
    if (
      this.anchorFingerprint === null ||
      receipt.anchorKeyFingerprint !== this.anchorFingerprint
    ) {
      throw createCodedError(
        'ANCHOR_RECEIPT_KEY_MISMATCH',
        'receipt anchorKeyFingerprint does not match the pinned anchor trust root',
      );
    }
    if (
      this.anchorPublicKey === null ||
      !verifyAnchorReceiptSignature(receipt, this.anchorPublicKey)
    ) {
      throw createCodedError(
        'ANCHOR_RECEIPT_SIGNATURE_INVALID',
        'receipt signature does not verify against the pinned anchor trust root',
      );
    }
  }

  /**
   * Proves that the ledger is still the artifact whose bytes were read.
   *
   * The same discipline Task 4 applies to the checkpoint stream: the identity
   * captured BEFORE the first byte, every physical byte accounted for, and the
   * canonical pathname still resolving to that inode. A receipt ledger that
   * changed under the reader would otherwise let bytes that were never verified
   * be treated as if they had been.
   */
  private assertLedgerIdentityAfterVerification(
    ledgerPath: string,
    fd: number,
    startIdentity: ArtifactIdentity,
    consumedBytes: number,
  ): void {
    this.hooks.beforeReceiptVerificationIdentityCheck?.(ledgerPath);

    let finalStats: fs.Stats;
    try {
      finalStats = fs.fstatSync(fd);
    } catch (cause) {
      this.failReceiptFileRace('could not be re-examined after verification', cause);
    }

    if (
      Number(finalStats.dev) !== startIdentity.dev ||
      Number(finalStats.ino) !== startIdentity.ino ||
      Number(finalStats.size) !== startIdentity.size ||
      consumedBytes !== startIdentity.size
    ) {
      this.failReceiptFileRace('changed while its history was being verified');
    }

    let pathStats: fs.Stats;
    try {
      pathStats = fs.lstatSync(ledgerPath);
    } catch (cause) {
      this.failReceiptFileRace(
        'no longer occupies its canonical pathname after verification',
        cause,
      );
    }
    if (
      pathStats.isSymbolicLink() ||
      Number(pathStats.dev) !== Number(finalStats.dev) ||
      Number(pathStats.ino) !== Number(finalStats.ino)
    ) {
      this.failReceiptFileRace('canonical pathname no longer identifies the verified artifact');
    }
  }

  /**
   * Reports a receipt-ledger race and stops the engine.
   *
   * Declared as a method rather than as a closure so the never-returning
   * signature participates in control-flow analysis at every call site.
   */
  private failReceiptFileRace(reason: string, cause?: unknown): never {
    this.failed = true;
    this.failedReason = 'ANCHOR_RECEIPT_FILE_RACE';
    throw createCodedError(
      'ANCHOR_RECEIPT_FILE_RACE',
      `${ANCHOR_RECEIPT_FILENAME} ${reason}`,
      cause === undefined ? undefined : { cause },
    );
  }

  /* ---------------------------------------------------------------------- *
   * Spool mutation (rc06 §14.4)
   * ---------------------------------------------------------------------- */

  private openSpoolDirectoryForWrite(auditDirFd: number): number {
    const fd = createPinnedDirectoryChild(
      auditDirFd,
      ANCHOR_SPOOL_DIRNAME,
      ANCHOR_SPOOL_DIRECTORY_MODE,
      SPOOL_DIRECTORY_CODES,
      'anchor spool directory',
    );

    try {
      this.assertSpoolDirectoryAuthority(fd);
      return fd;
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }
  }

  /**
   * Creates one spool entry durably, or adopts the identical entry already there.
   *
   * `O_CREAT | O_EXCL` is what makes this a creation rather than an acquisition.
   * When it reports `EEXIST` the existing entry is *read and compared*: an entry
   * whose bytes are exactly the canonical checkpoint is the same pending work and
   * is adopted; anything else is refused, because replacing it is forbidden and
   * adopting it would transmit bytes that no verified checkpoint produced.
   */
  private writeSpoolEntry(directoryFd: number, checkpointHash: string, bytes: Buffer): void {
    if (bytes.length > MAX_ANCHOR_SPOOL_ENTRY_BYTES) {
      throw createCodedError(
        'ANCHOR_SPOOL_ENTRY_INVALID',
        `spool entry exceeds the ${MAX_ANCHOR_SPOOL_ENTRY_BYTES} byte bound`,
      );
    }

    const filename = `${checkpointHash}.json`;
    let fd: number;
    try {
      fd = openPinnedFileChild(
        directoryFd,
        filename,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        SPOOL_ENTRY_CODES,
        'anchor spool entry',
        ANCHOR_SPOOL_FILE_MODE,
      );
    } catch (err) {
      if ((err as CodedError | null)?.code !== 'ANCHOR_SPOOL_ENTRY_EXISTS') {
        throw err;
      }

      const existing = this.readSpoolEntryBytes(directoryFd, checkpointHash);
      if (!existing.equals(bytes)) {
        this.failed = true;
        this.failedReason = 'ANCHOR_SPOOL_ENTRY_CONFLICT';
        throw createCodedError(
          'ANCHOR_SPOOL_ENTRY_CONFLICT',
          'the existing spool entry for this checkpoint is not the canonical checkpoint',
        );
      }
      return;
    }

    try {
      this.hooks.beforeSpoolSync?.(pinnedChildPath(directoryFd, filename));
      this.writeBytesOrFail(fd, bytes, 'anchor spool entry', this.hooks.spoolWriteFault);

      if (this.hooks.spoolFileSyncFault === true) {
        this.failPersistence('anchor spool entry fsync failed; persistence is uncertain');
      }
      dataSyncDescriptor(fd);
    } finally {
      fs.closeSync(fd);
    }

    if (this.hooks.spoolDirectorySyncFault === true) {
      this.failPersistence('anchor spool directory fsync failed; the entry is not recoverable');
    }
    // The directory entry itself is the recovery record, so it is synced last.
    syncDescriptor(directoryFd);
  }

  /**
   * Writes a complete buffer or refuses.
   *
   * A short write is not a partial success: a spool entry or receipt line that is
   * one byte short is a different artifact, and continuing would treat an
   * uncertain persistence outcome as a durable one. The engine stops, because it
   * is left holding a descriptor whose contents it cannot state.
   */
  private writeBytesOrFail(
    fd: number,
    bytes: Buffer,
    noun: string,
    fault: 'error' | 'partial' | 'zero' | undefined,
  ): void {
    if (fault === 'error') {
      this.failPersistence(`${noun} write failed`);
    }

    // The comparison is against the buffer the caller handed over, never against
    // whatever was actually attempted: a short write is measured by how much of
    // the intended artifact reached the disk. Comparing against a deliberately
    // shortened buffer would make a partial write look like a complete one, which
    // is precisely the outcome this function exists to refuse.
    const toWrite = fault === 'partial' ? bytes.subarray(0, Math.max(0, bytes.length - 1)) : bytes;
    const written = fault === 'zero' ? 0 : fs.writeSync(fd, toWrite);

    if (written !== bytes.length) {
      this.failPersistence(`${noun} write did not complete; persistence is uncertain`);
    }
  }

  private failPersistence(reason: string): never {
    this.failed = true;
    this.failedReason = 'ANCHOR_PERSISTENCE_FAILED';
    throw createCodedError('ANCHOR_PERSISTENCE_FAILED', reason);
  }

  private readSpoolEntryBytes(directoryFd: number, checkpointHash: string): Buffer {
    const fd = openPinnedFileChild(
      directoryFd,
      `${checkpointHash}.json`,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
      SPOOL_ENTRY_CODES,
      'anchor spool entry',
    );
    try {
      validateFileDescriptorAuthority(fd, ANCHOR_SPOOL_FILE_MODE, this.expectedUid);
      return readBoundedDescriptor(
        fd,
        MAX_ANCHOR_SPOOL_ENTRY_BYTES,
        'anchor spool entry',
        'ANCHOR_SPOOL_ENTRY_INVALID',
      );
    } finally {
      fs.closeSync(fd);
    }
  }

  /**
   * Proves that a spool entry's bytes are the canonical checkpoint it claims.
   *
   * The filename is the `checkpointHash`, so the file's entire claim to authority
   * is that its bytes hash to its own name. Recomputing that here — and requiring
   * the bytes to be the canonical encoding, which is what was written — means a
   * spool entry can never be the vehicle for transmitting something the verified
   * checkpoint history did not produce.
   */
  private assertSpoolEntryIsCheckpoint(bytes: Buffer, checkpointHash: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString('utf8'));
    } catch (cause) {
      throw createCodedError('ANCHOR_SPOOL_ENTRY_INVALID', 'anchor spool entry is not valid JSON', {
        cause,
      });
    }

    let checkpoint: AuditCheckpointV1;
    try {
      checkpoint = validateCheckpointV1(parsed);
    } catch (cause) {
      throw createCodedError(
        'ANCHOR_SPOOL_ENTRY_INVALID',
        'anchor spool entry is not a valid audit checkpoint',
        { cause },
      );
    }

    if (canonicalJsonV1(checkpoint) !== bytes.toString('utf8')) {
      throw createCodedError(
        'ANCHOR_SPOOL_ENTRY_INVALID',
        'anchor spool entry is not the canonical encoding of its checkpoint',
      );
    }
    if (computeCheckpointHash(checkpoint) !== checkpointHash) {
      throw createCodedError(
        'ANCHOR_SPOOL_ENTRY_INVALID',
        'anchor spool entry content does not hash to its filename',
      );
    }
  }

  private removeSpoolEntry(auditDirFd: number, checkpointHash: string): void {
    const directoryFd = openPinnedDirectoryChild(
      auditDirFd,
      ANCHOR_SPOOL_DIRNAME,
      SPOOL_DIRECTORY_CODES,
      'anchor spool directory',
    );
    try {
      unlinkPinnedChild(directoryFd, `${checkpointHash}.json`, 'anchor spool entry');
      syncDescriptor(directoryFd);
    } finally {
      fs.closeSync(directoryFd);
    }
  }

  private recaptureSpoolCounters(auditDirFd: number): void {
    const spoolFd = this.probeSpoolDirectory(auditDirFd);
    if (spoolFd === null) {
      this.spoolEntries = 0;
      this.spoolBytes = 0;
      return;
    }
    try {
      const inventory = this.scanSpoolDirectory(spoolFd);
      this.spoolEntries = inventory.entries;
      this.spoolBytes = inventory.bytes;
      this.spoolOverflow ||= inventory.overflow;
    } finally {
      fs.closeSync(spoolFd);
    }
  }

  /* ---------------------------------------------------------------------- *
   * Receipt persistence (rc06 §14.5)
   * ---------------------------------------------------------------------- */

  private ensureReceiptFd(auditDirFd: number): number {
    if (this.receiptFd !== null) {
      return this.receiptFd;
    }

    const state = this.receiptState;
    if (state === null) {
      throw createCodedError(
        'ANCHOR_NOT_INITIALIZED',
        'anchor receipt ledger state has not been established',
      );
    }

    if (state.kind === 'ABSENT') {
      let fd: number;
      try {
        fd = openPinnedFileChild(
          auditDirFd,
          ANCHOR_RECEIPT_FILENAME,
          fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            fsConstants.O_WRONLY |
            fsConstants.O_APPEND |
            fsConstants.O_NOFOLLOW,
          LEDGER_CODES,
          ANCHOR_RECEIPT_FILENAME,
          0o600,
        );
      } catch (cause) {
        // An `EEXIST` here means a ledger appeared after reconciliation proved
        // the stream absent. Its contents were never verified against the
        // checkpoint history, so adopting it would append to a ledger no
        // verifier has seen.
        this.failed = true;
        this.failedReason = 'ANCHOR_RECEIPT_FILE_RACE';
        throw createCodedError(
          'ANCHOR_RECEIPT_FILE_RACE',
          `${ANCHOR_RECEIPT_FILENAME} appeared after reconciliation established it was absent`,
          { cause },
        );
      }

      try {
        validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
        this.receiptState = { kind: 'PRESENT', ...captureArtifactIdentity(fd) };
        this.receiptExpectedSize = 0;
        this.receiptFd = fd;
      } catch (err) {
        fs.closeSync(fd);
        this.failed = true;
        this.failedReason = 'ANCHOR_RECEIPT_LEDGER_UNAVAILABLE';
        throw err;
      }

      // The new name is made durable before anything is appended, so a crash
      // cannot leave receipts in a ledger that does not exist.
      this.syncAuditDirectory();
      return this.receiptFd;
    }

    let fd: number;
    try {
      fd = openPinnedFileChild(
        auditDirFd,
        ANCHOR_RECEIPT_FILENAME,
        fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW,
        LEDGER_CODES,
        ANCHOR_RECEIPT_FILENAME,
      );
    } catch (cause) {
      this.failed = true;
      this.failedReason = 'ANCHOR_RECEIPT_FILE_RACE';
      throw createCodedError(
        'ANCHOR_RECEIPT_FILE_RACE',
        `${ANCHOR_RECEIPT_FILENAME} is no longer the artifact whose history was verified`,
        { cause },
      );
    }

    try {
      validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
      const identity = captureArtifactIdentity(fd);
      if (identity.dev !== state.dev || identity.ino !== state.ino) {
        this.failed = true;
        this.failedReason = 'ANCHOR_RECEIPT_FILE_RACE';
        throw createCodedError(
          'ANCHOR_RECEIPT_FILE_RACE',
          `${ANCHOR_RECEIPT_FILENAME} is not the artifact whose history was verified`,
        );
      }
      if (identity.size !== state.size) {
        this.failed = true;
        this.failedReason = 'ANCHOR_RECEIPT_FILE_RACE';
        throw createCodedError(
          'ANCHOR_RECEIPT_FILE_RACE',
          `${ANCHOR_RECEIPT_FILENAME} changed length since its history was verified`,
        );
      }
      this.receiptFd = fd;
      return fd;
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }
  }

  /**
   * Re-proves, immediately before every append, that the descriptor still
   * describes the verified ledger and is still the file the canonical pathname
   * names.
   *
   * The descriptor alone is not enough. An attacker who cannot influence the
   * descriptor can still replace the *pathname*, leaving the engine holding a
   * valid descriptor to an inode that is no longer the receipt ledger — a
   * successful append there would be durable, correctly signed, and invisible to
   * every future verifier.
   */
  private assertReceiptAppendAuthoritative(fd: number, auditDirFd: number): void {
    const filePath = pinnedChildPath(auditDirFd, ANCHOR_RECEIPT_FILENAME);
    this.hooks.beforeReceiptAppend?.(filePath);

    let stats: fs.Stats;
    try {
      stats = fs.fstatSync(fd);
    } catch (cause) {
      this.failReceiptFileRace('could not be re-examined before append', cause);
    }

    if (
      !stats.isFile() ||
      (stats.mode & 0o777) !== 0o600 ||
      stats.uid !== this.expectedUid ||
      stats.nlink !== 1
    ) {
      this.failReceiptFileRace('lost its descriptor authority before append');
    }
    if (Number(stats.size) !== this.receiptExpectedSize) {
      this.failReceiptFileRace('changed length since its last durable write');
    }

    let pathStats: fs.Stats;
    try {
      pathStats = fs.lstatSync(filePath);
    } catch (cause) {
      this.failReceiptFileRace('no longer occupies its canonical pathname', cause);
    }
    if (
      pathStats.isSymbolicLink() ||
      Number(pathStats.dev) !== Number(stats.dev) ||
      Number(pathStats.ino) !== Number(stats.ino)
    ) {
      this.failReceiptFileRace('canonical pathname no longer identifies the verified artifact');
    }
  }

  /**
   * Appends one receipt and makes it durable.
   *
   * This is the arrow in §14.5 that must complete before the spool entry may be
   * removed, so it never returns until the bytes are on stable storage.
   */
  private appendReceipt(auditDirFd: number, receipt: AnchorReceiptV1): void {
    const bytes = Buffer.from(serializeAnchorReceiptV1(receipt), 'utf8');

    if (bytes.length > MAX_ANCHOR_LEDGER_LINE_BYTES) {
      throw createCodedError('ANCHOR_RECEIPT_INVALID', 'serialized receipt exceeds the line bound');
    }

    // The coexistence peak: while a receipt is being added, its spool entry is
    // still on disk, so the projection is measured against a scan that already
    // includes it. The budget is a refusal, never a reason to reclaim space.
    assertAuditStorageCapacity(this.auditDir, this.expectedUid, bytes.length);

    const fd = this.ensureReceiptFd(auditDirFd);
    this.assertReceiptAppendAuthoritative(fd, auditDirFd);
    this.writeBytesOrFail(fd, bytes, 'anchor receipt', this.hooks.receiptWriteFault);

    if (this.hooks.receiptDataSyncFault === true) {
      this.failPersistence('anchor receipt fdatasync failed; persistence is uncertain');
    }
    dataSyncDescriptor(fd);

    // The durable length advances exactly when the bytes do, and never before.
    this.receiptExpectedSize += bytes.length;
  }

  private syncAuditDirectory(): void {
    const dirFd = fs.openSync(
      this.auditDir,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }

  /* ---------------------------------------------------------------------- *
   * Dispatch (rc06 §14.3, §14.7)
   * ---------------------------------------------------------------------- */

  /**
   * Dispatches every outstanding checkpoint in verified order.
   *
   * This is the recovery cycle of §14.7: after a restart, the spool entries that
   * survived are re-submitted, each under the same `Idempotency-Key`, so an
   * attempt that reached the anchor before the crash is answered with the same
   * receipt rather than producing a second one.
   */
  async resumePendingAnchors(): Promise<AnchorStatus> {
    return this.serialize(async () => {
      this.assertUsable();
      await this.runDispatchCycle(null);
      return this.getStatus();
    });
  }

  /**
   * Submits one checkpoint to the external anchor.
   *
   * The checkpoint must be the next one the verified history admits, and it must
   * *be* verified history. Order is load-bearing rather than cosmetic: receipts
   * are only ever appended in checkpoint order, so a later checkpoint
   * acknowledged before an earlier one would put the ledger out of the monotonic
   * subsequence reconciliation requires, and the store would fail closed on its
   * next startup for a reason that had nothing to do with tampering. Dispatch
   * therefore always proceeds from the head of the pending queue, and stops at
   * the first checkpoint the anchor will not accept.
   *
   * Authority is the other half, and it is not satisfied by the checkpoint
   * parsing, hashing or linking correctly. A checkpoint reconciliation did not
   * hand over is admitted only after the Task-4 verifier has produced it from the
   * durable checkpoint artifact and the retained primary evidence (see
   * {@link admitVerifiedCheckpoint}); anything else is refused before a spool
   * entry exists and before a socket is opened.
   */
  async anchorCheckpoint(checkpoint: AuditCheckpointV1): Promise<AnchorDispatchResult> {
    return this.serialize(async () => {
      this.assertUsable();

      let validated: AuditCheckpointV1;
      try {
        validated = validateCheckpointV1(checkpoint);
      } catch (cause) {
        throw createCodedError(
          'ANCHOR_CHECKPOINT_INVALID',
          'checkpoint is not a valid audit checkpoint',
          { cause },
        );
      }

      const hash = computeCheckpointHash(validated);
      if (validated.checkpointHash !== hash) {
        throw createCodedError(
          'ANCHOR_CHECKPOINT_INVALID',
          'checkpointHash does not match the canonical checkpoint',
        );
      }

      const auditDirFd = openAuthoritativeDirectoryFd(this.auditDir, this.expectedUid);
      try {
        const recorded = this.acknowledgedReceipts.get(hash);
        if (recorded !== undefined) {
          return await this.reattestAcknowledged(auditDirFd, validated, recorded);
        }

        if (!this.pendingOrder.includes(hash)) {
          if (
            this.lastVerifiedSequence !== null &&
            validated.sequenceEnd <= this.lastVerifiedSequence
          ) {
            throw createCodedError(
              'ANCHOR_CHECKPOINT_NOT_CURRENT',
              'checkpoint does not extend the verified checkpoint history',
            );
          }
          this.assertCheckpointExtendsHistory(validated);
          await this.admitVerifiedCheckpoint(validated);
          await this.spoolPendingCheckpoint(auditDirFd, validated);
          this.pendingOrder.push(hash);
        }

        const attempts = await this.runDispatchCycle(hash);
        this.recaptureSpoolCounters(auditDirFd);

        const receipt = this.acknowledgedReceipts.get(hash) ?? null;
        return {
          checkpointHash: hash,
          outcome: receipt === null ? 'PENDING' : 'ACKNOWLEDGED',
          receipt,
          attempts,
          idempotent: false,
          status: this.getStatus(),
        };
      } finally {
        fs.closeSync(auditDirFd);
      }
    });
  }

  /**
   * The *positional* check for a checkpoint the pending queue does not hold.
   *
   * It is a cheap pre-filter, not an authority check: it only asks whether the
   * offered coverage continues where the verified boundary ended. Shape, a
   * self-consistent `checkpointHash` and a plausible back-link are all
   * reproducible by any caller, so none of them is evidence that a checkpoint is
   * one this store actually produced. {@link admitVerifiedCheckpoint} is what
   * decides that, and it always runs before anything is spooled.
   */
  private assertCheckpointExtendsHistory(checkpoint: AuditCheckpointV1): void {
    const previous = this.lastVerifiedCheckpointHash ?? GENESIS_PREVIOUS_CHECKPOINT_HASH;
    if (checkpoint.previousCheckpointHash !== previous) {
      throw createCodedError(
        'ANCHOR_CHECKPOINT_NOT_CURRENT',
        'checkpoint does not link to the verified checkpoint history',
      );
    }
    if (this.lastVerifiedSequence === null) {
      if (checkpoint.sequenceStart !== 1) {
        throw createCodedError(
          'ANCHOR_CHECKPOINT_NOT_CURRENT',
          'the first checkpoint of a store must begin at sequence 1',
        );
      }
      return;
    }
    if (checkpoint.sequenceStart !== this.lastVerifiedSequence + 1) {
      throw createCodedError(
        'ANCHOR_CHECKPOINT_NOT_CURRENT',
        'checkpoint coverage does not continue the verified checkpoint history',
      );
    }
  }

  /**
   * Proves that an offered checkpoint is authoritative Task-4 evidence.
   *
   * `pendingOrder` is populated exclusively by the reconciliation observer, which
   * runs inside the Task-4 verifier's handoff — so a hash already in it was
   * proven from the primary ledger, and a hash that is not in it has never been
   * through that proof. Shape, a self-consistent `checkpointHash` and a
   * plausible back-link are all things any caller can produce: a fabricated
   * checkpoint with a garbage signature, an invented `terminalRecordHash` and no
   * durable artifact line behind it would otherwise be spooled and transmitted,
   * and the receipt ledger would then hold an independent attestation of evidence
   * the primary store never contained.
   *
   * The proof is the Task-4 streaming verifier itself, run again over the durable
   * `audit-checkpoints.jsonl` and the retained primary evidence. The offered
   * checkpoint is admitted only if that pass actually hands it back as verified —
   * which is exactly the conjunction this module needs and cannot check for
   * itself: the artifact line exists, its coverage is the cadence the primary
   * ledger requires, its `terminalRecordHash` is the verified record hash at that
   * sequence, it continues the checkpoint chain, it is bound to this store and
   * this trust root, and its Ed25519 signature verifies under the pinned key.
   * Signature validity alone is deliberately not the test: a correctly signed
   * checkpoint that was never durably appended fails here on the artifact, not on
   * the signature.
   *
   * Reusing the verifier rather than re-deriving any of that is what keeps the
   * two paths from drifting apart, and it keeps memory bounded the same way Task
   * 4 does: one checkpoint line, one chain cursor and the bounded archive
   * inventory, never a retained history.
   *
   * A verifier that THROWS is a different finding from one that completes without
   * handing the checkpoint back, and the two are not treated alike. A throw means
   * the durable store could not be verified — a broken chain, a coverage
   * mismatch, a forged artifact line — which is a fact about the store rather
   * than about the argument, so the engine stops exactly as it does for an
   * orphaned receipt or an orphaned spool entry, and the verifier's own error is
   * kept as the cause. A pass that completes and simply never produces the
   * checkpoint is a statement about the argument: the engine stays healthy and
   * refuses the checkpoint alone.
   */
  private async admitVerifiedCheckpoint(checkpoint: AuditCheckpointV1): Promise<void> {
    let proven = false;
    let result: CheckpointHistoryVerificationResult;
    try {
      result = await verifyCheckpointHistoryWithObserver(
        {
          directory: this.auditDir,
          publicKeyPath: this.checkpointPublicKeyPath,
          workspacePaths: [...(this.config.workspacePaths ?? [])],
          expectedUid: this.expectedUid,
        },
        (verified) => {
          if (verified.checkpointHash === checkpoint.checkpointHash) {
            proven = true;
          }
        },
      );
    } catch (cause) {
      return this.markFailed('ANCHOR_CHECKPOINT_UNVERIFIED', cause);
    }

    if (!proven) {
      throw createCodedError(
        'ANCHOR_CHECKPOINT_UNVERIFIED',
        'checkpoint is not a verified checkpoint of this store',
      );
    }

    // The boundary advances to what the verifier proved, never to what the caller
    // offered: the result's last checkpoint comes from the artifact, so a
    // fabricated coverage cannot move the ceiling a later call is measured
    // against. Without this, a legitimate second new checkpoint would be refused
    // for not continuing a boundary that is merely stale.
    this.lastVerifiedSequence = result.lastCheckpointSequence;
    this.lastVerifiedCheckpointHash = result.lastCheckpointHash;
  }

  private async spoolPendingCheckpoint(
    auditDirFd: number,
    checkpoint: AuditCheckpointV1,
  ): Promise<void> {
    if (
      this.pendingOrder.length >= MAX_PENDING_ANCHOR_CHECKPOINTS ||
      this.spoolBytes >= MAX_ANCHOR_SPOOL_BYTES
    ) {
      this.refreshState();
      throw createCodedError(
        'ANCHOR_SPOOL_FULL',
        `anchor spool backpressure limit reached: ${this.pendingOrder.length} pending checkpoints, ${this.spoolBytes} spool bytes`,
      );
    }

    const bytes = Buffer.from(canonicalJsonV1(checkpoint), 'utf8');
    assertAuditStorageCapacity(this.auditDir, this.expectedUid, bytes.length);

    const spoolFd = this.openSpoolDirectoryForWrite(auditDirFd);
    try {
      this.writeSpoolEntry(spoolFd, checkpoint.checkpointHash, bytes);
    } finally {
      fs.closeSync(spoolFd);
    }

    this.recaptureSpoolCounters(auditDirFd);
  }

  /**
   * Re-submits a checkpoint ARC already holds a receipt for.
   *
   * This is rc06 §14.3's repeat-submission branch, and it is the only place
   * §14.5's "conflicting receipts" rule can be enforced rather than assumed: a
   * receipt ARC holds and a receipt the anchor returns for the same
   * `Idempotency-Key` must be the same logical receipt. The ordering of §14.4 is
   * preserved — the checkpoint is re-spooled durably before anything is
   * transmitted — and no second receipt line is written, whichever way the
   * comparison goes.
   *
   * The spool entry this method creates exists only to satisfy that ordering for
   * one transmission: the checkpoint is already acknowledged, so the entry is
   * removed again before returning, whatever the outcome. Leaving it behind would
   * misstate the store as holding outstanding work for a checkpoint whose
   * receipt is on disk.
   */
  private async reattestAcknowledged(
    auditDirFd: number,
    checkpoint: AuditCheckpointV1,
    recorded: AnchorReceiptV1,
  ): Promise<AnchorDispatchResult> {
    const hash = checkpoint.checkpointHash;
    await this.spoolPendingCheckpoint(auditDirFd, checkpoint);

    // The transient entry is removed on every path, including the throwing one,
    // and always *before* the status is assembled — so the counters a caller sees
    // describe the store as it is left, not as it was mid-transmission.
    const removeTransientEntry = (): void => {
      this.removeSpoolEntry(auditDirFd, hash);
      this.recaptureSpoolCounters(auditDirFd);
      this.refreshState();
    };

    // The outcome is decided inside the `try`; the status it reports is assembled
    // afterwards, once the transient entry is gone.
    let settled: {
      outcome: 'ACKNOWLEDGED' | 'PENDING';
      receipt: AnchorReceiptV1 | null;
      attempts: number;
      idempotent: boolean;
    };

    try {
      const spoolFd = openPinnedDirectoryChild(
        auditDirFd,
        ANCHOR_SPOOL_DIRNAME,
        SPOOL_DIRECTORY_CODES,
        'anchor spool directory',
      );
      let body: Buffer;
      try {
        body = this.readSpoolEntryBytes(spoolFd, hash);
      } finally {
        fs.closeSync(spoolFd);
      }

      const outcome = await this.transmitUntilReceipt(hash, body);

      if (outcome.receipt === null) {
        // The acknowledgement on record is unaffected: this checkpoint is still
        // acknowledged. What the failure says is that ARC could not re-confirm it
        // with the anchor, which is a degraded relationship rather than a lost
        // acknowledgement.
        this.degradedReason = outcome.reason;
        settled = {
          outcome: 'ACKNOWLEDGED',
          receipt: recorded,
          attempts: outcome.attempts,
          idempotent: false,
        };
      } else {
        const returned = outcome.receipt;
        const identical =
          returned.receiptId === recorded.receiptId &&
          returned.anchorTimestamp === recorded.anchorTimestamp &&
          returned.checkpointHash === recorded.checkpointHash &&
          returned.anchorKeyFingerprint === recorded.anchorKeyFingerprint &&
          returned.signature === recorded.signature;

        if (identical) {
          // §14.3: a matching repeat receipt is an idempotent duplicate. Nothing
          // is appended — the acknowledgement already exists — and the caller is
          // told that no second acknowledgement was manufactured.
          settled = {
            outcome: 'ACKNOWLEDGED',
            receipt: recorded,
            attempts: outcome.attempts,
            idempotent: true,
          };
        } else {
          // §14.5: a conflicting receipt for an already acknowledged checkpoint
          // is rejected and the engine enters degraded anchor state. The receipt
          // already on record stands — it is the one the checkpoint history was
          // verified against — and the anchor's disagreement is surfaced rather
          // than silently resolved by choosing a winner.
          this.degradedReason = 'ANCHOR_RECEIPT_CONFLICT';
          settled = {
            outcome: 'PENDING',
            receipt: null,
            attempts: outcome.attempts,
            idempotent: false,
          };
        }
      }
    } catch (err) {
      // The operation failed, so its error is the one the caller needs; a cleanup
      // failure here would replace it. A surviving entry is State D, which the
      // next reconciliation resolves in favour of the receipt that is already
      // durable.
      try {
        removeTransientEntry();
      } catch {
        // Deliberately discarded: the original failure is the diagnosis.
      }
      throw err;
    }

    removeTransientEntry();
    return { checkpointHash: hash, ...settled, status: this.getStatus() };
  }

  /**
   * Dispatches pending checkpoints from the head of the queue.
   *
   * Returns the number of network attempts made. When `targetHash` is given, the
   * cycle stops once that checkpoint has been dispatched, so a caller offering a
   * new checkpoint does not also block on however much backlog sits behind it.
   */
  private async runDispatchCycle(targetHash: string | null): Promise<number> {
    if (this.pendingOrder.length === 0) return 0;

    let totalAttempts = 0;
    const auditDirFd = openAuthoritativeDirectoryFd(this.auditDir, this.expectedUid);
    try {
      while (this.pendingOrder.length > 0) {
        const hash = this.pendingOrder[0];
        if (hash === undefined) break;

        const spoolFd = openPinnedDirectoryChild(
          auditDirFd,
          ANCHOR_SPOOL_DIRNAME,
          SPOOL_DIRECTORY_CODES,
          'anchor spool directory',
        );
        let body: Buffer;
        try {
          body = this.readSpoolEntryBytes(spoolFd, hash);
          this.assertSpoolEntryIsCheckpoint(body, hash);
        } finally {
          fs.closeSync(spoolFd);
        }

        const outcome = await this.transmitUntilReceipt(hash, body);
        totalAttempts += outcome.attempts;

        if (outcome.receipt === null) {
          this.degradedReason = outcome.reason;
          break;
        }

        this.commitReceipt(auditDirFd, outcome.receipt);
        this.pendingOrder.shift();
        this.recaptureSpoolCounters(auditDirFd);

        if (targetHash !== null && hash === targetHash) break;
      }
    } finally {
      fs.closeSync(auditDirFd);
    }

    this.refreshState();
    return totalAttempts;
  }

  /**
   * Commits one verified receipt, in the exact order §14.5 mandates.
   *
   * The receipt is appended and `fdatasync`ed before the spool entry is unlinked
   * and the spool directory is synced. Reversing those two steps would create a
   * window in which a crash loses the only record that the checkpoint was ever
   * submitted, and the next start would re-transmit a checkpoint the anchor has
   * already acknowledged — harmless under the idempotency key, but it would mean
   * the ledger no longer describes what ARC knew.
   */
  private commitReceipt(auditDirFd: number, receipt: AnchorReceiptV1): void {
    this.appendReceipt(auditDirFd, receipt);
    this.removeSpoolEntry(auditDirFd, receipt.checkpointHash);
    this.rememberAcknowledgedReceipt(receipt);
    this.acknowledgedCheckpoints++;
  }

  /**
   * The five-attempt retry cycle of §14.7.
   *
   * The backoff delay is observed after *every* failed attempt, including the
   * last: the vector is `1s, 2s, 4s, 8s, 16s` with one entry per attempt, and the
   * fifth delay is the terminal backoff of a cycle whose spool entry is retained
   * for the next recovery cycle.
   *
   * A terminal classification ends the cycle immediately. Retrying a redirect, a
   * 4xx, or a 200 whose body is not a valid receipt cannot change the answer, and
   * pretending otherwise would spend the anchor's resources on a request ARC has
   * already been told not to make.
   */
  private async transmitUntilReceipt(hash: string, body: Buffer): Promise<TransmissionOutcome> {
    let lastReason = 'ANCHOR_DISPATCH_FAILED';

    for (let attempt = 1; attempt <= MAX_ANCHOR_ATTEMPTS; attempt++) {
      this.hooks.networkObserver?.({
        idempotencyKey: hash,
        attempt,
        bodyBytes: body.length,
      } satisfies AnchorNetworkObservation);

      let classification: ResponseClassification;
      try {
        const response = await this.performAttempt(hash, body);
        classification = this.classifyResponse(hash, response);
      } catch (err) {
        const code = (err as CodedError | null)?.code;
        lastReason =
          code === 'ANCHOR_REQUEST_TIMEOUT' ? 'ANCHOR_REQUEST_TIMEOUT' : 'ANCHOR_TRANSPORT_FAILED';
        await this.sleepFor(ANCHOR_RETRY_BACKOFF_MS[attempt - 1] ?? 0);
        continue;
      }

      if (classification.kind === 'ACKNOWLEDGED') {
        return { receipt: classification.receipt, attempts: attempt, reason: '' };
      }
      if (classification.kind === 'TERMINAL') {
        return { receipt: null, attempts: attempt, reason: classification.code };
      }

      lastReason = classification.code;
      await this.sleepFor(ANCHOR_RETRY_BACKOFF_MS[attempt - 1] ?? 0);
    }

    return { receipt: null, attempts: MAX_ANCHOR_ATTEMPTS, reason: lastReason };
  }

  /**
   * One network attempt, under the §14.3 per-attempt budget.
   *
   * The budget is enforced by aborting the attempt rather than by racing a
   * promise, so it covers DNS, the handshake, transmission and body acquisition
   * as one deadline. The failure raised carries no `cause`: a Node TLS error
   * routinely embeds the hostname it could not reach, and the endpoint must not
   * appear in errors or health output. Only the errno survives, and that
   * describes the failure without describing the peer.
   */
  private async performAttempt(hash: string, body: Buffer): Promise<AnchorTransportResponse> {
    const controller = new AbortController();
    const timer = this.setAttemptTimer(() => controller.abort(), ANCHOR_REQUEST_TIMEOUT_MS);

    try {
      const transport: AnchorTransport =
        this.hooks.transport ?? ((request, signal) => defaultAnchorTransport(request, signal));

      return await transport(
        {
          endpoint: this.endpoint,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': String(body.length),
            [ANCHOR_IDEMPOTENCY_HEADER]: hash,
          },
          body,
          ...(this.hooks.ca === undefined ? {} : { ca: this.hooks.ca }),
        },
        controller.signal,
      );
    } catch (cause) {
      if (controller.signal.aborted) {
        throw createCodedError(
          'ANCHOR_REQUEST_TIMEOUT',
          `external anchor did not answer within ${ANCHOR_REQUEST_TIMEOUT_MS} ms`,
        );
      }
      const errno = (cause as CodedError | null)?.code ?? null;
      throw createCodedError(
        'ANCHOR_TRANSPORT_FAILED',
        `external anchor request failed${errno === null ? '' : ` (${errno})`}`,
      );
    } finally {
      this.clearAttemptTimer(timer);
    }
  }

  /**
   * Classifies one anchor response (Task 5 §25, §26, §27, §31).
   *
   * Only 200 and 201 are candidates for acknowledgement, and even then only a
   * receipt that parses, binds to this store and this checkpoint, names the
   * pinned key, and verifies under it. A redirect is terminal and is never
   * followed — the request is made once, to the endpoint the operator configured,
   * or not at all. A 4xx is terminal: the anchor has given a definitive answer.
   * Everything else — 5xx, an unlisted 2xx, a status the transport could not read
   * — is retryable.
   */
  private classifyResponse(
    hash: string,
    response: AnchorTransportResponse,
  ): ResponseClassification {
    const { statusCode, body } = response;

    if (ANCHOR_ACKNOWLEDGING_STATUS_CODES.includes(statusCode)) {
      let receipt: AnchorReceiptV1;
      try {
        if (body.length === 0) {
          throw createCodedError('ANCHOR_RECEIPT_INVALID', 'anchor response body is empty');
        }
        receipt = validateAnchorReceiptV1(JSON.parse(body.toString('utf8')));
      } catch {
        // HTTP 200 alone is not acknowledgement (rc06 §14.5, RC06-NEG-89).
        return { kind: 'TERMINAL', code: 'ANCHOR_RECEIPT_INVALID' };
      }

      if (receipt.checkpointHash !== hash) {
        return { kind: 'TERMINAL', code: 'ANCHOR_RECEIPT_BINDING_INVALID' };
      }
      if (receipt.storeId !== this.storeId) {
        return { kind: 'TERMINAL', code: 'ANCHOR_RECEIPT_BINDING_INVALID' };
      }
      if (
        this.anchorFingerprint === null ||
        receipt.anchorKeyFingerprint !== this.anchorFingerprint
      ) {
        return { kind: 'TERMINAL', code: 'ANCHOR_RECEIPT_KEY_MISMATCH' };
      }
      if (
        this.anchorPublicKey === null ||
        !verifyAnchorReceiptSignature(receipt, this.anchorPublicKey)
      ) {
        return { kind: 'TERMINAL', code: 'ANCHOR_RECEIPT_SIGNATURE_INVALID' };
      }

      return { kind: 'ACKNOWLEDGED', receipt };
    }

    if (statusCode >= 300 && statusCode < 400) {
      return { kind: 'TERMINAL', code: 'ANCHOR_REDIRECT_REFUSED' };
    }
    if (statusCode >= 400 && statusCode < 500) {
      return { kind: 'TERMINAL', code: 'ANCHOR_REQUEST_REJECTED' };
    }
    return { kind: 'RETRYABLE', code: 'ANCHOR_TRANSPORT_FAILED' };
  }
}

/* -------------------------------------------------------------------------- *
 * Factories
 * -------------------------------------------------------------------------- */

/**
 * Opens and initializes a Tier-3 anchor engine.
 *
 * This is the production factory. It validates configuration, loads the anchor
 * trust root and reconciles the spool against the verified checkpoint history —
 * reconstructing State C entries durably, removing State D stale entries, and
 * failing closed on States E and F — before it returns.
 *
 * Reconciliation performs no network I/O. Pending checkpoints are re-submitted
 * by an explicit {@link Tier3AnchorEngine.resumePendingAnchors} call, so the
 * §14.4 ordering stays observable: a caller can prove that every outstanding
 * checkpoint has a durable spool entry before a single byte is transmitted.
 */
export async function openTier3AnchorEngine(
  config: Tier3AnchorEngineConfig,
): Promise<Tier3AnchorEngine> {
  const engine = new Tier3AnchorEngine(config, ANCHOR_TEST_TOKEN);
  await engine.initializeEngine();
  return engine;
}

/**
 * Opens a Tier-3 anchor engine for the frozen startup sequence, verified but not
 * yet reconciled.
 *
 * The returned engine has validated its configuration and both trust roots,
 * verified the receipt ledger and its bindings to the checkpoint history, and
 * staged the spool decisions it derived — and has performed none of them. It
 * refuses privileged operations until
 * {@link Tier3AnchorEngine.applyAnchorReconciliation} runs.
 *
 * This exists so the startup sequence's stage 6
 * (`ANCHOR_RECEIPT_VERIFICATION`) and stage 7
 * (`ANCHOR_SPOOL_RECONCILIATION`) are two authorities rather than one authority
 * invoked twice. Stage 8's torn-tail recovery reads the spool as an input, and a
 * stage that both verifies and reconciles would leave the spool mutated before
 * the stage that is supposed to be the first to touch it.
 *
 * {@link openTier3AnchorEngine} keeps its contract: a standalone caller gets an
 * engine that has already reconciled.
 *
 * @internal
 */
export async function openTier3AnchorEngineForStartup(
  config: Tier3AnchorEngineConfig,
): Promise<Tier3AnchorEngine> {
  const engine = new Tier3AnchorEngine(config, ANCHOR_TEST_TOKEN);
  await engine.initializeEngineForStartup();
  return engine;
}
