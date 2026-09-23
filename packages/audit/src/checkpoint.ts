/**
 * CesSpace ARC — RC-06 Task 4: Tier 2 Signed Checkpoint Artifacts & Key Authority
 *
 * A checkpoint is a cryptographic integrity artifact that authenticates the
 * primary audit chain. It is NOT an audit event (rc06 §12): it never consumes a
 * `sequenceNumber`, never advances the primary sequence, and never enters the
 * primary hash chain. It lives in its own append-only artifact stream —
 * `audit-checkpoints.jsonl` — sealed with Ed25519 over an exact, frozen signing
 * domain and chained to its predecessor by its own hash.
 *
 * This module owns:
 *
 *  - the `AuditCheckpointV1` schema and its strict canonical parser,
 *  - the exact signature and checkpoint-hash preimages,
 *  - the Ed25519 signer and public-key verifier,
 *  - the real `RotationCheckpointSealer` Task 3 depends on,
 *  - the post-durable-primary interval cadence primitive Task 6 will drive,
 *  - bounded streaming verification of the whole checkpoint history, bound to
 *    the actual verified primary evidence rather than to the checkpoint's own
 *    claims, and
 *  - the authenticated primary boundary Task 6 can later hand to Task-2 recovery.
 *
 * Two properties shape almost every decision below.
 *
 * **A valid signature is not sufficient.** Every checkpoint claim is checked
 * against the primary chain it claims to cover: the terminal record must exist
 * at the claimed sequence and carry the claimed hash, the coverage range must
 * continue exactly where the previous checkpoint ended, and the checkpoint must
 * sit at a sequence the frozen cadence actually requires. A perfectly signed
 * checkpoint that lies about the ledger is invalid.
 *
 * **Nothing is buffered.** The checkpoint stream and the primary stream are
 * walked in lockstep, one checkpoint line and one chain cursor at a time, so the
 * verifier never holds the checkpoint history, the record hashes, or the record
 * bodies in memory however large the store grows.
 */

import crypto from 'node:crypto';
import fs, { constants as fsConstants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import {
  CHECKPOINT_FILENAME,
  CHECKPOINT_INTERVAL,
  CHECKPOINT_SIGNATURE_DOMAIN,
} from './internal/checkpoint-constants.js';
import {
  CHECKPOINT_TEST_TOKEN,
  type CheckpointTestHooks,
} from './internal/checkpoint-capability.js';
import {
  assertSigningKeyOutsideWorkspaces,
  computeTrustRootFingerprintFromFile,
  loadEd25519SigningKeyFile,
  loadEd25519TrustRootFile,
} from './internal/key-authority.js';
import { loadStoreMetadataFile } from './metadata.js';
import {
  assertAuditStorageCapacity,
  listLogicalArchiveInventory,
  validateRotationSealBoundary,
  verifyRetainedPrimaryHistory,
  type RotationCheckpointSealer,
  type RotationSealBoundary,
  type VerifiedPrimaryCheckpointFact,
} from './rotation.js';
import {
  UUID_V4_REGEX,
  canonicalJsonV1,
  createCodedError,
  getProcessUid,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
} from './storage.js';

export {
  CHECKPOINT_FILENAME,
  CHECKPOINT_INTERVAL,
  CHECKPOINT_SIGNATURE_DOMAIN,
  MAX_SIGNING_KEY_BYTES,
} from './internal/checkpoint-constants.js';

export {
  assertNoRawSigningKeyMaterial,
  computePublicKeyFingerprint,
  computeTrustRootFingerprintFromFile,
  type SigningKeySource,
  type TrustRootPurpose,
} from './internal/key-authority.js';

/** The virtual predecessor of the first checkpoint in the chain. */
const ZERO_HASH = '0'.repeat(64);

const HEX64_REGEX = /^[0-9a-f]{64}$/;
const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

/** A raw Ed25519 signature is exactly 64 bytes. */
const ED25519_SIGNATURE_BYTES = 64;

/**
 * Largest single checkpoint line that may be buffered while streaming.
 *
 * One line is permitted in memory; the stream is not. A canonical checkpoint is
 * a few hundred bytes, so this bound is generous by two orders of magnitude
 * while still refusing to accumulate an unbounded "line" from a stream that
 * never produces a newline.
 */
const MAX_CHECKPOINT_LINE_BYTES = 65_536;

/** Streaming read chunk size for the checkpoint artifact. */
const CHECKPOINT_READ_CHUNK_BYTES = 65_536;

/**
 * Every top-level field a checkpoint may carry.
 *
 * Closed by construction: a field not in this set is rejected, not ignored, so a
 * checkpoint can never become a carrier for anything the frozen schema does not
 * name.
 */
export const CHECKPOINT_ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'version',
  'storeId',
  'checkpointId',
  'sequenceStart',
  'sequenceEnd',
  'terminalRecordHash',
  'previousCheckpointHash',
  'createdAt',
  'publicKeyFingerprint',
  'signature',
  'checkpointHash',
]);

/**
 * Fields that belong to a primary audit record and are forbidden on a
 * checkpoint.
 *
 * Rejecting these by name — rather than letting them fall into the generic
 * unknown-field case — is deliberate: "a checkpoint is not an audit event" is a
 * structural property of Tier 2, and an artifact that tries to carry an audit
 * event's identity should fail with that reason rather than a generic one.
 */
export const CHECKPOINT_FORBIDDEN_EVENT_KEYS: ReadonlySet<string> = new Set([
  'sequenceNumber',
  'actor',
  'target',
  'invocation',
  'policy',
  'execution',
  'lifecycle',
  'gateway',
  'approval',
]);

/** A checkpoint artifact (rc06 §12.1). */
export interface AuditCheckpointV1 {
  version: 1;
  /** UUIDv4 matching `audit-store.json`. */
  storeId: string;
  /** UUIDv4, freshly minted for every checkpoint. */
  checkpointId: string;
  /** First primary audit sequence covered. */
  sequenceStart: number;
  /** Terminal primary audit sequence covered. */
  sequenceEnd: number;
  /** `recordHash` of the primary record at `sequenceEnd`. */
  terminalRecordHash: string;
  /** `checkpointHash` of the preceding checkpoint, or 64 zeros for genesis. */
  previousCheckpointHash: string;
  /** Canonical UTC ISO-8601 with milliseconds. */
  createdAt: string;
  /** `SHA-256` of the Ed25519 SPKI DER, 64 lowercase hex. */
  publicKeyFingerprint: string;
  /** Canonical unpadded Base64url Ed25519 signature. */
  signature: string;
  /** `SHA-256` of the canonical checkpoint-with-signature projection. */
  checkpointHash: string;
}

/** A checkpoint before it has been signed and hashed. */
export type UnsignedAuditCheckpointV1 = Omit<AuditCheckpointV1, 'signature' | 'checkpointHash'>;

/* -------------------------------------------------------------------------- *
 * Schema validation (rc06 §12.1, Task 4 §6/§7/§10)
 * -------------------------------------------------------------------------- */

function assertSignatureEncoding(signature: unknown): void {
  if (typeof signature !== 'string' || signature.length === 0) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'signature must be a non-empty string');
  }
  if (
    signature.includes('=') ||
    signature.includes('+') ||
    signature.includes('/') ||
    /\s/.test(signature)
  ) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_INVALID',
      'signature must be canonical unpadded Base64url (no padding, no "+", no "/", no whitespace)',
    );
  }
  if (!BASE64URL_REGEX.test(signature)) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'signature contains non-Baseurl characters');
  }

  const raw = Buffer.from(signature, 'base64url');
  if (raw.length !== ED25519_SIGNATURE_BYTES) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_INVALID',
      `signature must decode to a ${ED25519_SIGNATURE_BYTES}-byte Ed25519 signature (got ${raw.length})`,
    );
  }
  if (raw.toString('base64url') !== signature) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_INVALID',
      'signature does not round-trip canonically through Base64url',
    );
  }
}

function assertSequenceField(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', `${field} must be a positive safe integer`);
  }
  return value as number;
}

function assertHashField(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64_REGEX.test(value)) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_INVALID',
      `${field} must be exactly 64 lowercase hexadecimal characters`,
    );
  }
  return value;
}

function assertCanonicalTimestamp(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_INVALID',
      'createdAt must be a canonical ISO-8601 UTC timestamp (YYYY-MM-DDTHH:mm:ss.sssZ)',
    );
  }
  return value;
}

/**
 * Validates an unknown value as a complete `AuditCheckpointV1`.
 *
 * Every field is required, every field is checked against its exact frozen
 * shape, and no field outside the frozen schema is tolerated. A checkpoint that
 * merely *nearly* matches is not a checkpoint.
 */
export function validateCheckpointV1(input: unknown): AuditCheckpointV1 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'checkpoint must be a plain JSON object');
  }
  const obj = input as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (CHECKPOINT_FORBIDDEN_EVENT_KEYS.has(key)) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_FORBIDDEN_FIELD',
        `checkpoints are not audit events: field "${key}" is forbidden on a checkpoint artifact`,
      );
    }
    if (!CHECKPOINT_ALLOWED_KEYS.has(key)) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID',
        `unknown top-level field "${key}" in checkpoint artifact`,
      );
    }
  }

  for (const key of CHECKPOINT_ALLOWED_KEYS) {
    if (!(key in obj)) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID',
        `checkpoint missing required field "${key}"`,
      );
    }
  }

  if (obj.version !== 1) {
    throw createCodedError(
      'AUDIT_CHECKPOINT_UNSUPPORTED_VERSION',
      `checkpoint version must be 1 (got ${String(obj.version)})`,
    );
  }

  if (typeof obj.storeId !== 'string' || !UUID_V4_REGEX.test(obj.storeId)) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'storeId must be a valid UUIDv4');
  }
  if (typeof obj.checkpointId !== 'string' || !UUID_V4_REGEX.test(obj.checkpointId)) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'checkpointId must be a valid UUIDv4');
  }

  const sequenceStart = assertSequenceField(obj.sequenceStart, 'sequenceStart');
  const sequenceEnd = assertSequenceField(obj.sequenceEnd, 'sequenceEnd');
  if (sequenceStart > sequenceEnd) {
    throw createCodedError('AUDIT_CHECKPOINT_INVALID', 'sequenceStart must not exceed sequenceEnd');
  }

  const createdAt = assertCanonicalTimestamp(obj.createdAt);
  const terminalRecordHash = assertHashField(obj.terminalRecordHash, 'terminalRecordHash');
  const previousCheckpointHash = assertHashField(
    obj.previousCheckpointHash,
    'previousCheckpointHash',
  );
  const publicKeyFingerprint = assertHashField(obj.publicKeyFingerprint, 'publicKeyFingerprint');
  const checkpointHash = assertHashField(obj.checkpointHash, 'checkpointHash');
  assertSignatureEncoding(obj.signature);

  return {
    version: 1,
    storeId: obj.storeId,
    checkpointId: obj.checkpointId,
    sequenceStart,
    sequenceEnd,
    terminalRecordHash,
    previousCheckpointHash,
    createdAt,
    publicKeyFingerprint,
    signature: obj.signature as string,
    checkpointHash,
  };
}

/* -------------------------------------------------------------------------- *
 * Canonical encoding and exact preimages (rc06 §12.3)
 * -------------------------------------------------------------------------- */

/**
 * The unsigned projection: every field except `signature` and `checkpointHash`.
 *
 * The key order written here is irrelevant — `canonicalJsonV1` sorts keys
 * recursively — but the *set* is the frozen set, which is why it is spelled out
 * once and reused by both preimages.
 */
function unsignedProjection(checkpoint: UnsignedAuditCheckpointV1): Record<string, unknown> {
  return {
    version: checkpoint.version,
    storeId: checkpoint.storeId,
    checkpointId: checkpoint.checkpointId,
    sequenceStart: checkpoint.sequenceStart,
    sequenceEnd: checkpoint.sequenceEnd,
    terminalRecordHash: checkpoint.terminalRecordHash,
    previousCheckpointHash: checkpoint.previousCheckpointHash,
    createdAt: checkpoint.createdAt,
    publicKeyFingerprint: checkpoint.publicKeyFingerprint,
  };
}

/**
 * The exact bytes Ed25519 signs: the frozen domain followed immediately by the
 * UTF-8 canonical JSON of the unsigned checkpoint.
 *
 * There is no separator, no length prefix, no hashing step and no additional
 * byte. In particular the preimage is NOT hashed before signing — Ed25519
 * already hashes internally, and a pre-hash would silently define a different
 * signature scheme from the frozen one.
 */
export function computeCheckpointSignaturePreimage(checkpoint: UnsignedAuditCheckpointV1): Buffer {
  const canonical = canonicalJsonV1(unsignedProjection(checkpoint));
  return Buffer.concat([
    Buffer.from(CHECKPOINT_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(canonical, 'utf8'),
  ]);
}

/** The exact canonical JSON the checkpoint hash is taken over (rc06 §12.3). */
export function computeCheckpointHashPreimage(
  checkpoint: UnsignedAuditCheckpointV1 & { signature: string },
): string {
  return canonicalJsonV1({
    ...unsignedProjection(checkpoint),
    signature: checkpoint.signature,
  });
}

/**
 * `SHA-256` of the checkpoint-with-signature projection, as 64 lowercase hex.
 *
 * `checkpointHash` is omitted from its own preimage, which is what makes the
 * digest well defined. The trailing LF of the persisted line is likewise not
 * part of it: framing is a transport detail, not checkpoint content.
 */
export function computeCheckpointHash(
  checkpoint: UnsignedAuditCheckpointV1 & { signature: string },
): string {
  return crypto
    .createHash('sha256')
    .update(computeCheckpointHashPreimage(checkpoint), 'utf8')
    .digest('hex');
}

/** The canonical persisted form of a checkpoint: canonical JSON plus one LF. */
export function serializeCheckpointV1(checkpoint: AuditCheckpointV1): string {
  return canonicalJsonV1(checkpoint) + '\n';
}

/* -------------------------------------------------------------------------- *
 * Signature verification
 * -------------------------------------------------------------------------- */

/**
 * Verifies a checkpoint signature against the actual configured public key.
 *
 * The key is the authority; `publicKeyFingerprint` is identity metadata that
 * lets a checkpoint state which key it expects, and it is compared separately
 * by the verifier. Accepting a checkpoint because its fingerprint field looks
 * right — without a real Ed25519 verification against the configured key — would
 * make the fingerprint the security boundary, which it is not.
 */
export function verifyCheckpointSignature(
  checkpoint: AuditCheckpointV1,
  publicKey: crypto.KeyObject,
): boolean {
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    return false;
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(checkpoint.signature, 'base64url');
  } catch {
    return false;
  }
  if (raw.length !== ED25519_SIGNATURE_BYTES) {
    return false;
  }

  try {
    return crypto.verify(null, computeCheckpointSignaturePreimage(checkpoint), publicKey, raw);
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- *
 * Strict canonical parser (Task 4 §57/§58)
 * -------------------------------------------------------------------------- */

/**
 * Parses and fully validates one persisted checkpoint line.
 *
 * A line is accepted only when it is LF-terminated with exactly one LF, carries
 * no CR, decodes as strict JSON to a plain object of the exact frozen shape,
 * reserializes byte-for-byte to the same canonical bytes, and carries a
 * `checkpointHash` that matches its own recomputation. Whitespace, key ordering
 * and numeric spelling variations are therefore not "equivalent forms" — they
 * are rejected.
 *
 * There is deliberately no checkpoint-tail repair (rc06 §"no checkpoint-tail
 * repair", Task 4 §24): torn-tail recovery is defined only for the primary
 * active audit segment.
 */
export function parseAndValidateCheckpointLineV1(line: string): {
  checkpoint: AuditCheckpointV1;
} {
  if (typeof line !== 'string' || line.length === 0) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      'checkpoint line must be a non-empty string',
    );
  }
  if (line.includes('\r')) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'checkpoint line must not contain CR');
  }
  if (!line.endsWith('\n')) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      'checkpoint artifact ends in an unterminated line',
    );
  }
  if (line.indexOf('\n') !== line.length - 1) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      'checkpoint line must contain exactly one LF terminator',
    );
  }

  const body = line.slice(0, -1);
  if (body.length === 0) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'checkpoint line is empty');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (cause) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'checkpoint line contains malformed JSON', {
      cause,
    });
  }

  const checkpoint = validateCheckpointV1(parsed);

  if (canonicalJsonV1(checkpoint) !== body) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'checkpoint line is not canonical JSON');
  }

  if (computeCheckpointHash(checkpoint) !== checkpoint.checkpointHash) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      'checkpointHash does not match the checkpoint preimage',
    );
  }

  return { checkpoint };
}

/* -------------------------------------------------------------------------- *
 * Checkpoint artifact file authority (rc06 §8.4, Task 4 §20-§23)
 * -------------------------------------------------------------------------- */

/**
 * The identity of the checkpoint artifact as VERIFIED, captured from the exact
 * descriptor verification read.
 *
 * This is security state, not a cache. The engine initializes its cursor from
 * verified history, so the artifact it later appends to must be the same object
 * that history was verified from. Recording `ABSENT` as a positive finding is
 * just as important as recording a present artifact: it is what entitles the
 * engine to *create* the stream, and what makes a file appearing afterwards a
 * refusal rather than an adoption.
 *
 * @internal
 */
export type VerifiedCheckpointArtifactState =
  | { kind: 'ABSENT' }
  | {
      kind: 'PRESENT';
      dev: number;
      ino: number;
      size: number;
      bytes: number;
      sha256: string;
    };

/** Opens an existing checkpoint artifact with `O_NOFOLLOW` and validates it. */
async function openExistingCheckpointFile(
  filePath: string,
  expectedUid: number,
): Promise<FileHandle> {
  let handle: FileHandle;
  try {
    handle = await fs.promises.open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (err: unknown) {
    const code = (err as { code?: string } | null)?.code;
    if (code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', `${CHECKPOINT_FILENAME} is a symbolic link`);
    }
    if (code === 'ENOENT') {
      throw createCodedError('AUDIT_CHECKPOINT_FILE_MISSING', `${CHECKPOINT_FILENAME} is absent`);
    }
    throw createCodedError(
      'AUDIT_CHECKPOINT_FILE_UNAVAILABLE',
      `${CHECKPOINT_FILENAME} could not be opened safely`,
      { cause: err },
    );
  }

  try {
    validateFileDescriptorAuthority(handle.fd, 0o600, expectedUid);
    return handle;
  } catch (err) {
    await handle.close();
    throw err;
  }
}

/** `fsync`s the audit directory, so a directory entry change is durable. */
function syncAuditDirectory(auditDir: string): void {
  const dirFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    fs.fsyncSync(dirFd);
  } finally {
    fs.closeSync(dirFd);
  }
}

/**
 * Streams the checkpoint artifact as raw LF-terminated line buffers.
 *
 * Only the bytes still needed for one unfinished line are retained, and a
 * "line" that grows past {@link MAX_CHECKPOINT_LINE_BYTES} without a newline is
 * rejected rather than accumulated. The whole checkpoint file is never read into
 * memory, however long the store lives.
 *
 * Every physical byte handed back by the read — terminators included — is also
 * counted into `consumed`, so the caller can hold the artifact to the identity
 * it had before the first byte was read.
 */
async function* readCheckpointLines(
  handle: FileHandle,
  consumed: { bytes: number; hasher?: crypto.Hash },
): AsyncGenerator<Buffer> {
  const chunk = Buffer.allocUnsafe(CHECKPOINT_READ_CHUNK_BYTES);
  let carry = Buffer.alloc(0);

  for (;;) {
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    consumed.bytes += bytesRead;

    const slice = chunk.subarray(0, bytesRead);
    consumed.hasher?.update(slice);
    carry = carry.length === 0 ? Buffer.from(slice) : Buffer.concat([carry, slice]);

    let newlineIndex = carry.indexOf(0x0a);
    while (newlineIndex !== -1) {
      yield Buffer.from(carry.subarray(0, newlineIndex + 1));
      carry = Buffer.from(carry.subarray(newlineIndex + 1));
      newlineIndex = carry.indexOf(0x0a);
    }

    if (carry.length > MAX_CHECKPOINT_LINE_BYTES) {
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `checkpoint line exceeds ${MAX_CHECKPOINT_LINE_BYTES} bytes without a terminator`,
      );
    }
  }

  // An unterminated trailing fragment is surfaced rather than dropped, so the
  // strict parser can reject it. It is never repaired.
  if (carry.length > 0) {
    yield carry;
  }
}

/* -------------------------------------------------------------------------- *
 * Checkpoint history verification (Task 4 §25-§36)
 * -------------------------------------------------------------------------- */

/** The bounded result of verifying the whole checkpoint history. */
export interface CheckpointHistoryVerificationResult {
  /** Number of verified checkpoints. */
  checkpointCount: number;
  /** `sequenceEnd` of the last verified checkpoint, or null when there is none. */
  lastCheckpointSequence: number | null;
  /** `checkpointHash` of the last verified checkpoint, or null. */
  lastCheckpointHash: string | null;
  /** `terminalRecordHash` of the last verified checkpoint, or null. */
  lastCheckpointTerminalRecordHash: string | null;
  /** The fingerprint every verified checkpoint is bound to. */
  publicKeyFingerprint: string;
  /**
   * The authenticated primary chain boundary implied by the last checkpoint.
   *
   * Absent when there is no checkpoint. This is the value Task 6 can hand to
   * Task-2 recovery as an already-authenticated boundary; Task 4 itself never
   * mutates the primary store.
   */
  trustedPrimaryBoundary?: { sequenceNumber: number; recordHash: string };
}

/** Options for {@link verifyCheckpointHistory}. */
export interface CheckpointHistoryVerificationOptions {
  /** The audit store directory. */
  directory: string;
  /** Path to the Ed25519 public key PEM the checkpoints must be signed by. */
  publicKeyPath: string;
  /** Authenticated agent workspace paths, for the audit-directory overlap rule. */
  workspacePaths?: readonly string[];
}

/** Internal parameters for the store-level verification core. @internal */
interface CheckpointVerificationCore {
  auditDir: string;
  expectedUid: number;
  publicKey: crypto.KeyObject;
  storeId: string;
  fingerprint: string;
  /** Deterministic seams. Absent on the offline public verification path. */
  hooks?: CheckpointTestHooks;
  /**
   * The verified-checkpoint handoff (Task 5 §37).
   *
   * Called once per checkpoint, in checkpoint order, after every Task-4 check
   * on that checkpoint has passed — coverage, chain continuity, terminal record
   * hash against the verified primary evidence, store binding, trust-root
   * binding and the Ed25519 signature. A checkpoint handed here is a checkpoint
   * that was proven from the primary ledger, not merely one that parsed.
   *
   * The observer is offered the checkpoint before the artifact identity is
   * re-established, so an observer that persists anything must treat its own
   * writes as provisional until the verification promise resolves: a raced
   * artifact fails the whole verification, and a plan built here is discarded
   * with it.
   */
  onVerifiedCheckpoint?: (checkpoint: AuditCheckpointV1) => void | Promise<void>;
}

/**
 * The identity of the checkpoint artifact as it was BEFORE verification read it.
 *
 * A size observed after the read is not evidence about the bytes that were read:
 * the same inode can be appended to between the verifier's EOF and its final
 * `fstat`. Recording the identity first and then accounting for every byte
 * consumed is what makes the recorded size describe the verified stream rather
 * than whatever the file happened to be when the verifier looked back.
 *
 * @internal
 */
interface CheckpointArtifactIdentity {
  dev: number;
  ino: number;
  size: number;
}

/** Reads the identity a descriptor currently names. @internal */
function captureCheckpointArtifactIdentity(fd: number): CheckpointArtifactIdentity {
  const stats = fs.fstatSync(fd);
  return { dev: Number(stats.dev), ino: Number(stats.ino), size: Number(stats.size) };
}

/**
 * The bounded error for "the checkpoint artifact is not the artifact that was
 * verified". One code covers growth, shrink, replacement and detachment, because
 * they are one condition: the stream stopped being the stream.
 */
function checkpointRaceError(
  message: string,
  cause?: unknown,
): ReturnType<typeof createCodedError> {
  return createCodedError(
    'AUDIT_CHECKPOINT_FILE_RACE',
    `${CHECKPOINT_FILENAME} ${message}`,
    cause === undefined ? undefined : { cause },
  );
}

/**
 * The public verification result plus the verified artifact identity.
 *
 * The identity stays on this internal shape rather than on
 * {@link CheckpointHistoryVerificationResult}: an offline verifier has no writer
 * to bind, so it has no use for the inode of the file it just read, and a public
 * surface that exposed it would invite a caller to treat it as authority.
 *
 * @internal
 */
export interface CheckpointVerificationOutcome extends CheckpointHistoryVerificationResult {
  /** Identity of the artifact the history was verified from. */
  artifactState: VerifiedCheckpointArtifactState;
}

/**
 * The Task-4 checkpoint cadence walk, reusable over any primary fact stream.
 *
 * This is the ONE implementation of "what makes a checkpoint authentic". The
 * store verifier drives it from a real store scan; the Task-7 exporter and
 * bundle verifier drive it from the evidence they are working with. Because the
 * cadence, coverage, chain, binding and signature rules all live here, none of
 * those callers can drift into a weaker second rule set.
 *
 * The fact source is PUSH (a streaming scan reports each verified record) while
 * the checkpoint source is PULL (a bounded line iterator), which is exactly the
 * shape a streamed verification needs: neither side is buffered.
 *
 * @internal
 */
export class CheckpointEvidenceWalk {
  private checkpointCount = 0;
  private checkpointedThroughValue = 0;
  private previousCheckpointHash = ZERO_HASH;
  private lastCheckpointHash: string | null = null;
  private lastCheckpointTerminalRecordHash: string | null = null;

  constructor(
    private readonly options: {
      storeId: string;
      fingerprint: string;
      publicKey: crypto.KeyObject;
      /** Sequences at which a rotation checkpoint is mandatory. */
      rotationTerminals: ReadonlySet<number>;
      /** Pulls the next checkpoint LINE, or null at end of stream. */
      nextCheckpointLine: () => Promise<string | null>;
      onVerifiedCheckpoint?: (checkpoint: AuditCheckpointV1) => void | Promise<void>;
    },
  ) {}

  /** The sequence the next checkpoint must begin at. */
  get checkpointedThrough(): number {
    return this.checkpointedThroughValue;
  }

  get verifiedCheckpointCount(): number {
    return this.checkpointCount;
  }

  get terminalCheckpointHash(): string | null {
    return this.lastCheckpointHash;
  }

  get terminalCheckpointRecordHash(): string | null {
    return this.lastCheckpointTerminalRecordHash;
  }

  /** Reports one verified primary record, driving the frozen cadence. */
  async observeRecord(fact: VerifiedPrimaryCheckpointFact): Promise<void> {
    const intervalDue = fact.sequenceNumber - this.checkpointedThroughValue === CHECKPOINT_INTERVAL;
    const rotationDue = this.options.rotationTerminals.has(fact.sequenceNumber);
    if (!intervalDue && !rotationDue) return;
    // One checkpoint covers a coincident interval and rotation boundary, because
    // the two causes resolve to the same single artifact.
    await this.consumeRequiredCheckpoint(fact);
  }

  /**
   * Proves no checkpoint exists at a sequence the frozen cadence does not
   * require. Call once, after the last fact.
   */
  async finish(): Promise<void> {
    const extra = await this.options.nextCheckpointLine();
    if (extra !== null) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_UNEXPECTED',
        'checkpoint artifact stream contains a checkpoint at a sequence the frozen cadence does not require',
      );
    }
  }

  private async consumeRequiredCheckpoint(fact: VerifiedPrimaryCheckpointFact): Promise<void> {
    const raw = await this.options.nextCheckpointLine();
    if (raw === null) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_MISSING',
        `primary history requires a checkpoint ending at sequence ${fact.sequenceNumber}, but the checkpoint artifact stream ends first`,
      );
    }

    const { checkpoint } = parseAndValidateCheckpointLineV1(raw);

    if (checkpoint.storeId !== this.options.storeId) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_LEDGER_MISMATCH',
        'checkpoint storeId does not match audit-store.json',
      );
    }
    if (checkpoint.publicKeyFingerprint !== this.options.fingerprint) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_TRUST_ROOT_MISMATCH',
        'checkpoint publicKeyFingerprint does not match the configured checkpoint trust root',
      );
    }
    if (checkpoint.previousCheckpointHash !== this.previousCheckpointHash) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_CHAIN_BROKEN',
        `checkpoint previousCheckpointHash does not continue the chain at sequence ${checkpoint.sequenceEnd}`,
      );
    }
    if (checkpoint.sequenceStart !== this.checkpointedThroughValue + 1) {
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `checkpoint coverage does not continue the previous range: expected sequenceStart ${this.checkpointedThroughValue + 1}, got ${checkpoint.sequenceStart}`,
      );
    }
    if (checkpoint.sequenceEnd !== fact.sequenceNumber) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_COVERAGE_MISMATCH',
        `checkpoint coverage ends at sequence ${checkpoint.sequenceEnd}, but the cadence requires a checkpoint ending at ${fact.sequenceNumber}`,
      );
    }
    if (checkpoint.terminalRecordHash !== fact.recordHash) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_TERMINAL_MISMATCH',
        `checkpoint terminalRecordHash does not match the primary record at sequence ${fact.sequenceNumber}`,
      );
    }
    if (!verifyCheckpointSignature(checkpoint, this.options.publicKey)) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_SIGNATURE_INVALID',
        `checkpoint signature does not verify at sequence ${checkpoint.sequenceEnd}`,
      );
    }

    this.checkpointCount++;
    this.checkpointedThroughValue = checkpoint.sequenceEnd;
    this.previousCheckpointHash = checkpoint.checkpointHash;
    this.lastCheckpointHash = checkpoint.checkpointHash;
    this.lastCheckpointTerminalRecordHash = checkpoint.terminalRecordHash;

    // Every claim above holds, so this checkpoint is verified primary-derived
    // evidence. The handoff runs last, so an observer never sees a checkpoint
    // that a later check on the same checkpoint would have rejected.
    if (this.options.onVerifiedCheckpoint !== undefined) {
      await this.options.onVerifiedCheckpoint(checkpoint);
    }
  }
}

/**
 * Verifies the checkpoint history against the actual retained primary evidence.
 *
 * The two streams are walked together. The primary walk supplies the only
 * trustworthy facts — the sequence and hash of each verified record — and the
 * checkpoint stream must agree with them exactly:
 *
 *  - a checkpoint is required at every rotated-segment terminal and at every
 *    `CHECKPOINT_INTERVAL`-th record since the preceding checkpoint;
 *  - exactly one checkpoint must exist there, whether one cause or both apply;
 *  - its coverage must continue exactly where the previous checkpoint ended;
 *  - its `terminalRecordHash` must equal the verified record hash at that
 *    sequence;
 *  - its `previousCheckpointHash` must equal the previous checkpoint's hash;
 *  - it must be signed by the configured key and bound to this store; and
 *  - no checkpoint may exist at a sequence the cadence does not require.
 *
 * Memory stays bounded: one checkpoint line, one chain cursor, the bounded
 * archive inventory, and one `KeyObject`.
 */
/**
 * Core checkpoint verification shared by internal and public callers.
 * @internal
 */
export async function verifyCheckpointHistoryCore(
  core: CheckpointVerificationCore,
): Promise<CheckpointVerificationOutcome> {
  const { auditDir, expectedUid, publicKey, storeId, fingerprint } = core;

  // Rotated-segment terminals are mandatory rotation-checkpoint boundaries
  // (rc06 §12.2 as staged by §34.2). The inventory is bounded by
  // MAX_ARCHIVE_SEGMENTS, and rotation is never inferred from a timestamp.
  const rotationTerminals = new Set(
    listLogicalArchiveInventory(auditDir, expectedUid).map((entry) => entry.sequenceEnd),
  );

  const checkpointPath = path.join(auditDir, CHECKPOINT_FILENAME);

  // Absence is established by the open itself rather than by a separate
  // existence probe, so there is no window between "the path looked empty" and
  // "the open was attempted" in which the answer could change. Either way the
  // finding is recorded as verified state below, and never re-inferred later.
  let checkpointHandle: FileHandle | null;
  try {
    checkpointHandle = await openExistingCheckpointFile(checkpointPath, expectedUid);
  } catch (err: unknown) {
    if ((err as { code?: string } | null)?.code === 'AUDIT_CHECKPOINT_FILE_MISSING') {
      checkpointHandle = null;
    } else {
      throw err;
    }
  }

  // The identity of the stream BEFORE a single byte of it has been read. Every
  // conclusion this function reaches about the artifact is bound to it, so a size
  // observed after the read can never be mistaken for a statement about the bytes
  // that were read.
  const verificationStartIdentity =
    checkpointHandle === null ? null : captureCheckpointArtifactIdentity(checkpointHandle.fd);

  const hasher = crypto.createHash('sha256');
  const consumed = { bytes: 0, hasher };
  const iterator =
    checkpointHandle === null
      ? null
      : readCheckpointLines(checkpointHandle, consumed)[Symbol.asyncIterator]();

  // The ONE implementation of the checkpoint rule set. The store verifier,
  // the Task-7 exporter and the bundle verifier all drive this same walk, so no
  // caller can hold a weaker copy of the cadence, coverage, chain, binding or
  // signature rules.
  const walk = new CheckpointEvidenceWalk({
    storeId,
    fingerprint,
    publicKey,
    rotationTerminals,
    nextCheckpointLine: async () => {
      if (iterator === null) {
        throw createCodedError(
          'AUDIT_CHECKPOINT_MISSING',
          'primary history requires a checkpoint, but no checkpoint artifact exists',
        );
      }
      const step = await iterator.next();
      if (step.done) return null;
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(step.value);
      } catch (cause) {
        throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'checkpoint line is not valid UTF-8', {
          cause,
        });
      }
    },
    ...(core.onVerifiedCheckpoint === undefined
      ? {}
      : { onVerifiedCheckpoint: core.onVerifiedCheckpoint }),
  });

  // Identity of the artifact this history was verified from. Only a PRESENT
  // finding carries an identity, and it is established by accounting for the
  // bytes actually consumed — before the descriptor is closed, so the recorded
  // identity cannot describe a file that was swapped in afterwards.
  let artifactState: VerifiedCheckpointArtifactState = { kind: 'ABSENT' };

  try {
    await verifyRetainedPrimaryHistory(auditDir, expectedUid, {
      onVerifiedRecord: (fact) => walk.observeRecord(fact),
    });

    if (iterator !== null) {
      await walk.finish();
    }

    if (checkpointHandle !== null && verificationStartIdentity !== null) {
      // The stream has been read to EOF and every required checkpoint in it has
      // been proven against the primary evidence. What remains is to prove that
      // the artifact still *is* the stream those bytes came from: a same-inode
      // append between the verifier's EOF and this moment would otherwise let an
      // unverified suffix be recorded as a verified length.
      core.hooks?.beforeCheckpointVerificationIdentityCheck?.(checkpointPath);

      let finalStats: fs.Stats;
      try {
        finalStats = fs.fstatSync(checkpointHandle.fd);
      } catch (cause) {
        throw checkpointRaceError('could not be re-examined after verification', cause);
      }

      // Same object, same length, and that length is exactly what was read:
      // neither growth nor shrink nor replacement is a verified stable artifact.
      if (
        Number(finalStats.dev) !== verificationStartIdentity.dev ||
        Number(finalStats.ino) !== verificationStartIdentity.ino ||
        Number(finalStats.size) !== verificationStartIdentity.size ||
        consumed.bytes !== verificationStartIdentity.size
      ) {
        throw checkpointRaceError('changed while its history was being verified');
      }

      // And the canonical pathname must still name that same descriptor, so a
      // verified history can never be reported as a PRESENT state for an inode
      // the canonical path no longer identifies.
      let pathStats: fs.Stats;
      try {
        pathStats = fs.lstatSync(checkpointPath);
      } catch (cause) {
        throw checkpointRaceError(
          'no longer occupies its canonical pathname after verification',
          cause,
        );
      }
      if (
        pathStats.isSymbolicLink() ||
        Number(pathStats.dev) !== Number(finalStats.dev) ||
        Number(pathStats.ino) !== Number(finalStats.ino)
      ) {
        throw checkpointRaceError('canonical pathname no longer identifies the verified artifact');
      }

      // The verified stable size, not a newly observed one.
      artifactState = {
        kind: 'PRESENT',
        dev: verificationStartIdentity.dev,
        ino: verificationStartIdentity.ino,
        size: verificationStartIdentity.size,
        bytes: consumed.bytes,
        sha256: hasher.digest('hex'),
      };
    }
  } finally {
    if (checkpointHandle !== null) {
      await checkpointHandle.close();
    }
  }

  return {
    artifactState,
    checkpointCount: walk.verifiedCheckpointCount,
    lastCheckpointSequence: walk.verifiedCheckpointCount === 0 ? null : walk.checkpointedThrough,
    lastCheckpointHash: walk.terminalCheckpointHash,
    lastCheckpointTerminalRecordHash: walk.terminalCheckpointRecordHash,
    publicKeyFingerprint: fingerprint,
    ...(walk.verifiedCheckpointCount === 0 || walk.terminalCheckpointRecordHash === null
      ? {}
      : {
          trustedPrimaryBoundary: {
            sequenceNumber: walk.checkpointedThrough,
            recordHash: walk.terminalCheckpointRecordHash,
          },
        }),
  };
}

/**
 * Verifies the checkpoint history using the public trust root only.
 *
 * This is the offline/public-key-only path (Task 4 §36): it needs the audit
 * directory, the checkpoint public key and the store metadata, and it never
 * opens, reads or parses the private signing key. It is the path Flow 14 and the
 * future Task-7 offline verification use.
 */
export async function verifyCheckpointHistory(
  options: CheckpointHistoryVerificationOptions,
): Promise<CheckpointHistoryVerificationResult> {
  const expectedUid = getProcessUid();
  validateAuditDirectory(options.directory, {
    expectedUid,
    workspacePaths: [...(options.workspacePaths ?? [])],
  });

  const metadata = loadStoreMetadataFile(options.directory, expectedUid);
  const trustRoot = loadEd25519TrustRootFile(options.publicKeyPath, {
    purpose: 'CHECKPOINT',
    expectedUid,
  });

  if (trustRoot.fingerprint !== metadata.checkpointPublicKeyFingerprint) {
    throw createCodedError(
      'FINGERPRINT_MISMATCH',
      'configured checkpoint public key does not match audit-store.json.checkpointPublicKeyFingerprint',
    );
  }

  return verifyCheckpointHistoryCore({
    auditDir: options.directory,
    expectedUid,
    publicKey: trustRoot.publicKey,
    storeId: metadata.storeId,
    fingerprint: trustRoot.fingerprint,
  });
}

/**
 * Verifies the checkpoint history and hands every verified checkpoint to an
 * observer as it is proven (RC-06 Task 5 §37).
 *
 * This is the same pass, with the same authority rules and the same fail-closed
 * outcomes as {@link verifyCheckpointHistory}; the only difference is the
 * handoff. It exists because Tier-3 reconciliation has to walk the verified
 * checkpoint history in order without ever retaining it: the anchor spool plan
 * is built from the checkpoints the primary ledger actually proves, one at a
 * time, and is thrown away entirely if the verification does not complete.
 *
 * Reusing the Task-4 verifier rather than re-deriving server-anchor state from
 * `audit-checkpoints.jsonl` directly is the point: a checkpoint is only ever
 * spooled or acknowledged because the primary evidence proved it.
 *
 * @internal
 */
export async function verifyCheckpointHistoryWithObserver(
  options: CheckpointHistoryVerificationOptions & { expectedUid?: number },
  onVerifiedCheckpoint: (checkpoint: AuditCheckpointV1) => void | Promise<void>,
): Promise<CheckpointHistoryVerificationResult> {
  const expectedUid = options.expectedUid ?? getProcessUid();
  validateAuditDirectory(options.directory, {
    expectedUid,
    workspacePaths: [...(options.workspacePaths ?? [])],
  });

  const metadata = loadStoreMetadataFile(options.directory, expectedUid);
  const trustRoot = loadEd25519TrustRootFile(options.publicKeyPath, {
    purpose: 'CHECKPOINT',
    expectedUid,
  });

  if (trustRoot.fingerprint !== metadata.checkpointPublicKeyFingerprint) {
    throw createCodedError(
      'FINGERPRINT_MISMATCH',
      'configured checkpoint public key does not match audit-store.json.checkpointPublicKeyFingerprint',
    );
  }

  return verifyCheckpointHistoryCore({
    auditDir: options.directory,
    expectedUid,
    publicKey: trustRoot.publicKey,
    storeId: metadata.storeId,
    fingerprint: trustRoot.fingerprint,
    onVerifiedCheckpoint,
  });
}

/* -------------------------------------------------------------------------- *
 * The real Tier 2 checkpoint engine (Task 4 §15, §16, §53-§56)
 * -------------------------------------------------------------------------- */

/** Construction configuration for {@link Tier2CheckpointEngine}. */
export interface Tier2CheckpointEngineConfig {
  /** The audit store directory. */
  directory: string;
  /**
   * Absolute path to the PKCS#8 Ed25519 private signing key.
   *
   * Production configuration carries this PATH and nothing else. Raw key
   * material is never an accepted input on any channel.
   */
  signingKeyPath: string;
  /** Absolute path to the Ed25519 public key the checkpoints are verified with. */
  publicKeyPath: string;
  /** Authenticated agent workspace paths the signing key must lie outside of. */
  workspacePaths?: readonly string[];
  /**
   * The production durable-completion handoff (Task 6 §22.1, §25).
   *
   * Invoked with each checkpoint at the moment it is durable — after the append
   * and its `fdatasync` have both succeeded and after every cursor has advanced
   * — and `await`ed before this engine returns. Two consequences follow, and
   * both are load-bearing:
   *
   *  - an observer can only ever be offered a checkpoint that is already on
   *    disk, so a composition that anchors from here gets the ordering
   *    "checkpoint durable, then spool, then network" without having to
   *    reconstruct it; and
   *  - because the call happens INSIDE the engine's serialized section, no
   *    second checkpoint can be emitted until the handoff has resolved. A
   *    composition therefore cannot accumulate two durable checkpoints it has
   *    not yet seen and then anchor them one at a time from a stale boundary.
   *
   * The hook both interval cadence and rotation sealing flow through, so a
   * rotation-triggered checkpoint and an interval checkpoint are handed over by
   * the same code path at the same point in their durability.
   *
   * A throw from this callback propagates to the caller of the append that
   * triggered it. That is deliberate: a checkpoint that could not be handed
   * onward is an audit integrity failure, and the caller must stop rather than
   * proceed. The checkpoint itself is durable either way.
   */
  onDurableCheckpoint?: (checkpoint: AuditCheckpointV1) => void | Promise<void>;
}

/** Bounded, read-only view of the engine's checkpoint cursor. */
export interface CheckpointEngineState {
  /** Sequence the next emitted checkpoint will begin covering. */
  nextCoverageStart: number;
  /** `previousCheckpointHash` the next emitted checkpoint will carry. */
  previousCheckpointHash: string;
  /** `sequenceEnd` of the last durable checkpoint, or null when there is none. */
  lastCheckpointSequence: number | null;
  /** `checkpointHash` of the last durable checkpoint, or null. */
  lastCheckpointHash: string | null;
  /** True once a persistence outcome became uncertain; the engine then refuses. */
  failed: boolean;
}

/**
 * The production Tier 2 checkpoint engine.
 *
 * It is simultaneously:
 *
 *  - the real `RotationCheckpointSealer` Task 3 requires before a non-empty
 *    segment rotation may be finalized, and
 *  - the interval cadence primitive Task 6 drives after durable primary
 *    progression.
 *
 * Both paths share ONE checkpoint cursor and ONE artifact writer. There is no
 * parallel cursor and no second file writer, which is what makes a rotation
 * checkpoint and an interval checkpoint the same kind of object with the same
 * chain link.
 *
 * Construct through {@link openTier2CheckpointEngine}, which is the supported
 * entry point: the constructor alone performs no initialization and yields an
 * engine that is not yet usable.
 */
export class Tier2CheckpointEngine implements RotationCheckpointSealer {
  private readonly config: Tier2CheckpointEngineConfig;
  private readonly hooks: CheckpointTestHooks;

  private initialized = false;
  private failed = false;

  private auditDir = '';
  private expectedUid = 0;
  private storeId = '';
  private fingerprint = '';
  private publicKey: crypto.KeyObject | null = null;
  private privateKey: crypto.KeyObject | null = null;

  private checkpointFd: number | null = null;

  /** The artifact identity verified during initialization; never re-inferred. */
  private artifactState: VerifiedCheckpointArtifactState | null = null;

  /** Durable length of the checkpoint artifact, advanced only after fdatasync. */
  private expectedSize = 0;

  private nextCoverageStart = 1;
  private previousCheckpointHash = ZERO_HASH;
  private lastCheckpointSequence: number | null = null;
  private lastCheckpointHash: string | null = null;
  private lastCheckpointTerminalRecordHash: string | null = null;

  public constructor(config: Tier2CheckpointEngineConfig, ...rest: unknown[]) {
    if (rest.length > 0) {
      if (rest[0] !== CHECKPOINT_TEST_TOKEN) {
        throw createCodedError(
          'AUDIT_CHECKPOINT_INVALID_CONFIG',
          'Unexpected constructor arguments; checkpoint test hooks require internal capability',
        );
      }
      this.hooks = (rest[1] as CheckpointTestHooks | undefined) ?? {};
    } else {
      this.hooks = {};
    }
    this.config = config;
  }

  /**
   * Loads and cross-checks all key authority, then initializes the cursor from
   * the *verified* checkpoint history.
   *
   * @internal
   */
  public async _initialize(): Promise<void> {
    const config = this.config;
    const expectedUid = this.hooks.expectedUid ?? getProcessUid();
    const workspacePaths = [...(config.workspacePaths ?? [])];

    validateAuditDirectory(config.directory, { expectedUid, workspacePaths });

    const metadata = loadStoreMetadataFile(config.directory, expectedUid);

    // Path isolation is established BEFORE any key bytes are read (Task 4 §47).
    // This is defense in depth: it narrows nothing that the loader does not
    // already enforce on the descriptor it actually opened, which is where the
    // decision that matters is made.
    assertSigningKeyOutsideWorkspaces(config.signingKeyPath, workspacePaths);

    const trustRoot = loadEd25519TrustRootFile(config.publicKeyPath, {
      purpose: 'CHECKPOINT',
      expectedUid,
    });

    if (trustRoot.fingerprint !== metadata.checkpointPublicKeyFingerprint) {
      throw createCodedError(
        'FINGERPRINT_MISMATCH',
        'configured checkpoint public key does not match audit-store.json.checkpointPublicKeyFingerprint',
      );
    }

    // The loader owns the ordering: it pins every parent component by
    // descriptor, decides workspace isolation against the location of the
    // descriptor it is about to read, and only then hands back key material.
    // No caller can read a key before that rule has been applied to the file it
    // really came from.
    const signing = loadEd25519SigningKeyFile(config.signingKeyPath, {
      expectedUid,
      workspacePaths,
      ...(this.hooks.beforeFinalKeyOpen === undefined
        ? {}
        : { beforeFinalKeyOpen: this.hooks.beforeFinalKeyOpen }),
    });
    if (signing.derivedFingerprint !== trustRoot.fingerprint) {
      throw createCodedError(
        'AUDIT_SIGNING_KEY_MISMATCH',
        'the signing key does not correspond to the configured checkpoint public trust root',
      );
    }

    const verified = await verifyCheckpointHistoryCore({
      auditDir: config.directory,
      expectedUid,
      publicKey: trustRoot.publicKey,
      storeId: metadata.storeId,
      fingerprint: trustRoot.fingerprint,
      hooks: this.hooks,
    });

    this.auditDir = config.directory;
    this.expectedUid = expectedUid;
    this.storeId = metadata.storeId;
    this.fingerprint = trustRoot.fingerprint;
    this.publicKey = trustRoot.publicKey;
    this.privateKey = signing.privateKey;

    // The cursor is initialized only from a VERIFIED result (Task 4 §53). An
    // unverified last line never becomes a starting point.
    this.lastCheckpointSequence = verified.lastCheckpointSequence;
    this.lastCheckpointHash = verified.lastCheckpointHash;
    this.lastCheckpointTerminalRecordHash = verified.lastCheckpointTerminalRecordHash;
    this.nextCoverageStart =
      verified.lastCheckpointSequence === null ? 1 : verified.lastCheckpointSequence + 1;
    this.previousCheckpointHash = verified.lastCheckpointHash ?? ZERO_HASH;

    // The stream this engine may append to is the exact stream it just verified.
    // An ABSENT finding is recorded just as positively: it is what authorizes
    // creation, and what makes a later arrival at that path a refusal.
    this.artifactState = verified.artifactState;
    this.expectedSize = verified.artifactState.kind === 'PRESENT' ? verified.artifactState.size : 0;

    this.initialized = true;
  }

  /** The bounded checkpoint cursor and failure latch. */
  public getCheckpointState(): CheckpointEngineState {
    return {
      nextCoverageStart: this.nextCoverageStart,
      previousCheckpointHash: this.previousCheckpointHash,
      lastCheckpointSequence: this.lastCheckpointSequence,
      lastCheckpointHash: this.lastCheckpointHash,
      failed: this.failed,
    };
  }

  /** Closes the checkpoint artifact descriptor. */
  public close(): void {
    if (this.checkpointFd !== null) {
      const fd = this.checkpointFd;
      this.checkpointFd = null;
      fs.closeSync(fd);
    }
    this.artifactState = null;
    this.initialized = false;
  }

  /**
   * Seals a rotation boundary with a real checkpoint.
   *
   * The boundary's `sequenceEnd` is the rotation's terminal sequence and its
   * `sequenceStart` is the first record of the PHYSICAL segment. Those are not
   * the same quantity: checkpoint coverage begins at the first record not yet
   * checkpointed, so a segment that already contributed an interval checkpoint
   * is covered from `lastCheckpointSequence + 1` rather than from the physical
   * segment start. Re-covering already-checkpointed sequences is refused.
   *
   * If the boundary's terminal sequence is already checkpointed — the interval
   * and the rotation coincided — the existing artifact is validated and the call
   * succeeds without writing a second checkpoint.
   */
  public async sealRotation(boundary: RotationSealBoundary): Promise<void> {
    this.assertReady();
    validateRotationSealBoundary(boundary);

    const terminal = boundary.sequenceEnd;

    if (this.lastCheckpointSequence !== null && terminal <= this.lastCheckpointSequence) {
      if (
        terminal === this.lastCheckpointSequence &&
        this.lastCheckpointTerminalRecordHash === boundary.terminalRecordHash
      ) {
        return;
      }
      throw createCodedError(
        'AUDIT_CHECKPOINT_COVERAGE_CONFLICT',
        `rotation terminal sequence ${terminal} is already covered by a different checkpoint`,
      );
    }

    await this.emitCheckpoint(terminal, boundary.terminalRecordHash);
  }

  /**
   * Emits the interval checkpoint implied by a durable primary boundary.
   *
   * Called only after the referenced primary record is durable. It never signs a
   * different, later boundary to "catch up": a coverage gap larger than the
   * frozen interval is a cadence violation and fails closed.
   */
  public async checkpointAfterDurablePrimary(boundary: {
    sequenceNumber: number;
    recordHash: string;
  }): Promise<AuditCheckpointV1 | null> {
    this.assertReady();

    if (boundary === null || typeof boundary !== 'object') {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID',
        'durable primary boundary must be an object',
      );
    }
    if (!Number.isSafeInteger(boundary.sequenceNumber) || boundary.sequenceNumber < 1) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID',
        'durable primary boundary sequenceNumber must be a positive safe integer',
      );
    }
    if (typeof boundary.recordHash !== 'string' || !HEX64_REGEX.test(boundary.recordHash)) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID',
        'durable primary boundary recordHash must be exactly 64 lowercase hexadecimal characters',
      );
    }

    const checkpointedThrough = this.lastCheckpointSequence ?? 0;
    const covered = boundary.sequenceNumber - checkpointedThrough;

    if (covered < CHECKPOINT_INTERVAL) {
      return null;
    }
    if (covered > CHECKPOINT_INTERVAL) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_CADENCE_VIOLATION',
        `covered primary record count ${covered} exceeds the frozen checkpoint interval ${CHECKPOINT_INTERVAL}`,
      );
    }

    return this.emitCheckpoint(boundary.sequenceNumber, boundary.recordHash);
  }

  /* ---------------------------------------------------------------------- *
   * Internals
   * ---------------------------------------------------------------------- */

  private assertReady(): void {
    if (!this.initialized) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID_STATE',
        'checkpoint engine is not initialized',
      );
    }
    if (this.failed) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID_STATE',
        'checkpoint engine is failed closed after an uncertain persistence outcome',
      );
    }
  }

  private now(): number {
    return this.hooks.clockMs?.() ?? Date.now();
  }

  private newCheckpointId(): string {
    return this.hooks.randomUUID?.() ?? crypto.randomUUID();
  }

  /**
   * Opens the checkpoint artifact for appending, bound to the verified identity.
   *
   * Which of the two paths is taken is decided by the state initialization
   * *verified*, never by what the filesystem looks like now. A stream that was
   * verified ABSENT may only be created — by this engine, exclusively — and a
   * stream that was verified PRESENT may only be reopened if it is provably the
   * same object. There is no third path, and in particular there is no
   * "the path exists now, so adopt it" path: a file that appears where the
   * verified state was absent is the race this exists to refuse.
   */
  private ensureCheckpointFd(): number {
    if (this.checkpointFd !== null) {
      return this.checkpointFd;
    }

    const state = this.artifactState;
    if (state === null) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID_STATE',
        'checkpoint artifact identity has not been verified',
      );
    }

    const filePath = path.join(this.auditDir, CHECKPOINT_FILENAME);

    // A stream verified PRESENT must still be reopenable as that same object.
    // If any part of the reopen fails — deleted, replaced, redirected, or no
    // longer carrying the authority it was verified with — the engine cannot
    // distinguish an uncertain outcome from a durable one, so it stops for good
    // rather than recreating the artifact, adopting what is there now, or
    // retrying on a later call. The failure is reported as the race it is, with
    // the underlying refusal preserved as the cause.
    if (state.kind === 'PRESENT') {
      let fd: number;
      try {
        fd = this.openVerifiedCheckpointFile(filePath, state);
      } catch (err) {
        this.failed = true;
        if ((err as { code?: string } | null)?.code === 'AUDIT_CHECKPOINT_FILE_RACE') {
          throw err;
        }
        throw createCodedError(
          'AUDIT_CHECKPOINT_FILE_RACE',
          `${CHECKPOINT_FILENAME} is no longer the artifact whose history was verified`,
          { cause: err },
        );
      }
      this.checkpointFd = fd;
      this.expectedSize = state.size;
      return fd;
    }

    const fd = this.createCheckpointFile(filePath);
    this.checkpointFd = fd;
    this.expectedSize = 0;
    return fd;
  }

  /** Reopens the verified artifact and proves it is still the same object. */
  private openVerifiedCheckpointFile(
    filePath: string,
    state: { kind: 'PRESENT'; dev: number; ino: number; size: number },
  ): number {
    const openFlags = fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW;
    this.hooks.openFlagsProbe?.(openFlags);

    const fd = openExistingCheckpointFileForAppend(filePath, this.expectedUid);

    let stats: fs.Stats;
    try {
      stats = fs.fstatSync(fd);
    } catch (cause) {
      fs.closeSync(fd);
      this.failed = true;
      throw createCodedError(
        'AUDIT_CHECKPOINT_FILE_RACE',
        `${CHECKPOINT_FILENAME} could not be re-examined after opening`,
        { cause },
      );
    }

    if (
      Number(stats.dev) !== state.dev ||
      Number(stats.ino) !== state.ino ||
      Number(stats.size) !== state.size
    ) {
      fs.closeSync(fd);
      this.failed = true;
      throw createCodedError(
        'AUDIT_CHECKPOINT_FILE_RACE',
        `${CHECKPOINT_FILENAME} is not the artifact whose history was verified`,
      );
    }

    return fd;
  }

  /**
   * Creates the checkpoint artifact exclusively, then syncs the directory.
   *
   * `O_EXCL` is what makes this a creation rather than an acquisition. If it
   * reports `EEXIST`, something placed an artifact on the canonical path after
   * initialization verified the stream absent — and that artifact's contents
   * were never verified against the primary chain, so adopting it would append
   * to a stream the cursor does not describe. Nothing is opened, nothing is
   * truncated and nothing is deleted: the engine simply stops.
   */
  private createCheckpointFile(filePath: string): number {
    const flags =
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_WRONLY |
      fsConstants.O_APPEND |
      fsConstants.O_NOFOLLOW;
    this.hooks.openFlagsProbe?.(flags);
    this.hooks.beforeCheckpointExclusiveCreate?.(filePath);

    let fd: number;
    try {
      fd = fs.openSync(filePath, flags, 0o600);
    } catch (err: unknown) {
      const code = (err as { code?: string } | null)?.code;
      if (code === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', `${CHECKPOINT_FILENAME} is a symbolic link`);
      }
      if (code === 'EEXIST') {
        this.failed = true;
        throw createCodedError(
          'AUDIT_CHECKPOINT_FILE_RACE',
          `${CHECKPOINT_FILENAME} appeared after verification established it was absent`,
        );
      }
      throw createCodedError(
        'AUDIT_CHECKPOINT_FILE_UNAVAILABLE',
        `${CHECKPOINT_FILENAME} could not be created`,
        { cause: err },
      );
    }

    try {
      validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
    } catch (err) {
      fs.closeSync(fd);
      this.failed = true;
      throw err;
    }

    syncAuditDirectory(this.auditDir);
    return fd;
  }

  /**
   * Re-proves, immediately before every append, that the descriptor still
   * describes the verified stream and is still the file the canonical path
   * names.
   *
   * The descriptor alone is not enough. An attacker who cannot influence the
   * descriptor can still replace the *pathname*, leaving the engine holding a
   * perfectly valid descriptor to an inode that is no longer the checkpoint
   * stream — a successful append there would be durable, correctly signed, and
   * invisible to every future verifier. So both are checked: the descriptor's
   * own authority and size, and the pathname's resolution back to the same
   * `dev`/`ino`. Any disagreement fails closed rather than writing to an
   * ambiguous stream.
   */
  private assertAppendAuthoritative(fd: number): void {
    const filePath = path.join(this.auditDir, CHECKPOINT_FILENAME);
    const state = this.artifactState;

    this.hooks.beforeCheckpointAppend?.(filePath);

    const reject: (reason: string) => never = (reason) => {
      this.failed = true;
      throw createCodedError('AUDIT_CHECKPOINT_FILE_RACE', `${CHECKPOINT_FILENAME} ${reason}`);
    };

    let stats: fs.Stats;
    try {
      stats = fs.fstatSync(fd);
    } catch (cause) {
      this.failed = true;
      throw createCodedError(
        'AUDIT_CHECKPOINT_FILE_RACE',
        `${CHECKPOINT_FILENAME} could not be re-examined before append`,
        { cause },
      );
    }

    if (
      !stats.isFile() ||
      (stats.mode & 0o777) !== 0o600 ||
      stats.uid !== this.expectedUid ||
      stats.nlink !== 1
    ) {
      reject('lost its descriptor authority before append');
    }

    // Externally added or removed bytes mean the stream is no longer the one the
    // verified history and the cursor describe. They are never adopted.
    if (Number(stats.size) !== this.expectedSize) {
      reject('changed length since its last durable write');
    }

    if (
      state !== null &&
      state.kind === 'PRESENT' &&
      (Number(stats.dev) !== state.dev || Number(stats.ino) !== state.ino)
    ) {
      reject('is not the artifact whose history was verified');
    }

    let pathStats: fs.Stats;
    try {
      pathStats = fs.lstatSync(filePath);
    } catch {
      reject('no longer occupies its canonical pathname');
    }
    if (pathStats.isSymbolicLink()) {
      reject('canonical pathname was replaced by a symbolic link');
    }
    if (
      Number(pathStats.dev) !== Number(stats.dev) ||
      Number(pathStats.ino) !== Number(stats.ino)
    ) {
      reject('canonical pathname no longer identifies the open artifact');
    }
  }

  /** Writes every byte or throws; a zero or short write is never a success. */
  private writeCheckpointBytes(fd: number, bytes: Buffer): void {
    const fault = this.hooks.writeFault;

    if (fault === 'error') {
      this.failed = true;
      throw createCodedError(
        'AUDIT_PERSISTENCE_FAILED',
        'checkpoint append failed; persistence is uncertain',
      );
    }

    const target = fault === 'partial' ? Math.max(1, Math.floor(bytes.length / 2)) : bytes.length;
    let offset = 0;

    while (offset < target) {
      const written = fault === 'zero' ? 0 : fs.writeSync(fd, bytes, offset, target - offset, null);
      if (written <= 0) {
        this.failed = true;
        throw createCodedError(
          'AUDIT_PERSISTENCE_FAILED',
          'checkpoint append wrote zero bytes; persistence is uncertain',
        );
      }
      offset += written;
    }

    if (offset < bytes.length) {
      this.failed = true;
      throw createCodedError(
        'AUDIT_PERSISTENCE_FAILED',
        'checkpoint append was short; persistence is uncertain',
      );
    }
  }

  /** Signs, hashes, preflights the budget, appends durably, then advances. */
  private async emitCheckpoint(
    sequenceEnd: number,
    terminalRecordHash: string,
  ): Promise<AuditCheckpointV1> {
    const privateKey = this.privateKey;
    const publicKey = this.publicKey;
    if (privateKey === null || publicKey === null) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_INVALID_STATE',
        'checkpoint engine has no signing authority',
      );
    }

    const unsigned: UnsignedAuditCheckpointV1 = {
      version: 1,
      storeId: this.storeId,
      checkpointId: this.newCheckpointId(),
      sequenceStart: this.nextCoverageStart,
      sequenceEnd,
      terminalRecordHash,
      previousCheckpointHash: this.previousCheckpointHash,
      createdAt: new Date(this.now()).toISOString(),
      publicKeyFingerprint: this.fingerprint,
    };

    if (unsigned.sequenceStart > unsigned.sequenceEnd) {
      throw createCodedError(
        'AUDIT_CHECKPOINT_COVERAGE_CONFLICT',
        `checkpoint coverage ${unsigned.sequenceStart}..${unsigned.sequenceEnd} is empty or inverted`,
      );
    }

    // Sign the exact frozen preimage: domain followed immediately by UTF-8
    // canonical JSON, passed to Ed25519 unhashed.
    const rawSignature = crypto.sign(
      null,
      computeCheckpointSignaturePreimage(unsigned),
      privateKey,
    );

    const withSignature = {
      ...unsigned,
      signature: rawSignature.toString('base64url'),
    };
    const checkpointHash = computeCheckpointHash(withSignature);
    const checkpoint: AuditCheckpointV1 = { ...withSignature, checkpointHash };
    const line = serializeCheckpointV1(checkpoint);

    // Physical-budget preflight against the SAME frozen 1 GiB audit-store budget
    // (Task 4 §52). An exhausted store consumes no checkpoint and no evidence is
    // ever reclaimed to make room.
    assertAuditStorageCapacity(this.auditDir, this.expectedUid, Buffer.byteLength(line, 'utf8'));

    const fd = this.ensureCheckpointFd();
    this.assertAppendAuthoritative(fd);

    const bytes = Buffer.from(line, 'utf8');
    this.writeCheckpointBytes(fd, bytes);

    if (this.hooks.fdatasyncFault === true) {
      this.failed = true;
      throw createCodedError(
        'AUDIT_PERSISTENCE_FAILED',
        'checkpoint fdatasync failed; persistence is uncertain',
      );
    }
    fs.fdatasyncSync(fd);

    // The durable length advances exactly when the bytes do, and never before.
    // A short or failed write never reaches this line, so the expected size can
    // never describe bytes that are not on disk.
    this.expectedSize += bytes.length;

    // Durable completion is the ONLY thing that advances the cursor (§23/§53).
    this.nextCoverageStart = sequenceEnd + 1;
    this.previousCheckpointHash = checkpointHash;
    this.lastCheckpointSequence = sequenceEnd;
    this.lastCheckpointHash = checkpointHash;
    this.lastCheckpointTerminalRecordHash = terminalRecordHash;

    // The durable-completion handoff (Task 5 §37, Task 6 §25). It runs after the
    // append and its `fdatasync` have both succeeded and after every cursor has
    // advanced, so an observer can only ever be offered a checkpoint that is
    // already on disk. A composition that anchors from here therefore gets the
    // ordering §14.4 mandates for free: checkpoint durable, then spool, then
    // network. Because this is inside the engine's serialized section, the
    // await also guarantees no SECOND checkpoint becomes durable until the
    // handoff of this one has finished.
    if (this.config.onDurableCheckpoint !== undefined) {
      await this.config.onDurableCheckpoint(checkpoint);
    }
    if (this.hooks.onCheckpointEmitted !== undefined) {
      await this.hooks.onCheckpointEmitted(checkpoint);
    }

    return checkpoint;
  }
}

/** Opens an existing checkpoint artifact for append with full authority checks. */
function openExistingCheckpointFileForAppend(filePath: string, expectedUid: number): number {
  let fd: number;
  try {
    fd = fs.openSync(
      filePath,
      fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW,
    );
  } catch (err: unknown) {
    const code = (err as { code?: string } | null)?.code;
    if (code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', `${CHECKPOINT_FILENAME} is a symbolic link`);
    }
    throw createCodedError(
      'AUDIT_CHECKPOINT_FILE_UNAVAILABLE',
      `${CHECKPOINT_FILENAME} could not be opened safely`,
      { cause: err },
    );
  }

  try {
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);
    return fd;
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
}

/**
 * Opens the production Tier 2 checkpoint engine.
 *
 * @param config Audit directory and key paths.
 */
export async function openTier2CheckpointEngine(
  config: Tier2CheckpointEngineConfig,
): Promise<Tier2CheckpointEngine> {
  const engine = new Tier2CheckpointEngine(config);
  await engine._initialize();
  return engine;
}

/**
 * The §46 fresh-store helper: the checkpoint public-key fingerprint, computed
 * from the configured trust-root file without any private-key involvement.
 *
 * Task 1 must persist this value into `audit-store.json` before the store
 * accepts its first record; Task 4 can therefore be composed with a fresh store
 * that has no checkpoints and no signing key loaded yet.
 */
export function computeCheckpointPublicKeyFingerprint(
  publicKeyPath: string,
  options: { expectedUid?: number } = {},
): string {
  return computeTrustRootFingerprintFromFile(publicKeyPath, {
    purpose: 'CHECKPOINT',
    expectedUid: options.expectedUid ?? getProcessUid(),
  });
}
