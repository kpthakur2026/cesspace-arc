/**
 * CesSpace ARC — RC-06 Task 7: standalone offline verification.
 *
 * `arc audit verify` answers one question from filesystem evidence alone: is
 * this retained audit history internally consistent, contiguous and authentic
 * under the operator's PUBLIC verification keys?
 *
 * ## Read-only, public-key-only
 *
 * Verification observes evidence. It never produces or changes any:
 *
 * - it does not open the store for writing and never takes the writer lock;
 * - it does not repair a torn tail, append recovery evidence, or move a cursor;
 * - it does not create store metadata, checkpoint artifacts or spool state;
 * - it does not reconcile spool state and never dispatches a Tier-3 request;
 * - it never reads a private signing key, and no entry point accepts one.
 *
 * That property is structural, not incidental: this module deliberately does not
 * import `openAuditRuntime`, `PersistentAuditStorage`,
 * `recoverPersistentAuditStorage` or `openTier3AnchorEngine`. Verification is
 * composed entirely from the already-reviewed Task 1-5 primitives, so that no
 * cryptographic rule is restated in a weaker second implementation:
 *
 *   Task 1  `validateAuditDirectory`, `loadStoreMetadataEvidence` store identity
 *   Task 3  `verifyRetainedPrimaryHistory`                       primary chain
 *   Task 4  `verifyCheckpointHistoryWithObserver`                checkpoint chain
 *   Task 4  `loadEd25519TrustRootFile`                           public keys only
 *   Task 5  `parseAndValidateAnchorReceiptLineV1`,
 *           `verifyAnchorReceiptSignature`                       receipt ledger
 *   Task 5  `openAuthoritativeDirectoryFd`, `pinnedChildPath`    pinned traversal
 *
 * ## Bounded memory
 *
 * Every full-history operation here streams. Segment sources are enumerated
 * first, then read one line at a time — `.jsonl.gz` through a streaming
 * `gunzip`, never by decompressing a whole 10 MiB segment into memory. At no
 * point is the retained history held in memory, and the 256-record runtime
 * cache is never used as the authority for a full-history answer.
 *
 * @packageDocumentation
 */

import fs from 'node:fs';
import fsConstants from 'node:constants';
import path from 'node:path';
import readline from 'node:readline';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';

import type { AuditStoreMetadataV1, PersistentAuditRecordV1 } from '@cesspace-arc/protocol';
import { MAX_RECORD_BYTES } from '@cesspace-arc/protocol';

import {
  ACTIVE_SEGMENT_FILENAME,
  getProcessUid,
  createCodedError,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  parseAndValidateRecordLineV1,
} from './storage.js';
import { loadStoreMetadataEvidence, METADATA_FILENAME } from './metadata.js';
import {
  listLogicalArchiveInventory,
  verifyRetainedPrimaryHistory,
  type LogicalArchiveEntry,
  type RetainedPrimaryHistoryVerificationResult,
} from './rotation.js';
import {
  CHECKPOINT_FILENAME,
  parseAndValidateCheckpointLineV1,
  verifyCheckpointHistory,
  type AuditCheckpointV1,
  type CheckpointHistoryVerificationResult,
} from './checkpoint.js';
import { ANCHOR_RECEIPT_FILENAME, ANCHOR_SPOOL_DIRNAME } from './internal/anchor-constants.js';
import { loadEd25519TrustRootFile } from './internal/key-authority.js';
import {
  MAX_MANIFEST_CHECKPOINT_REFS,
  assertManifestReferenceWithinBound,
} from './internal/manifest-bounds.js';
import {
  assertDescriptorPinnedTraversalAvailable,
  pinnedChildPath,
} from './internal/anchor-paths.js';
import {
  parseAndValidateAnchorReceiptLineV1,
  walkReceiptEvidence,
  type AuthenticatedCheckpointFact,
} from './anchor.js';

/* -------------------------------------------------------------------------- *
 * Frozen bounds (rc06 §24.1)
 * -------------------------------------------------------------------------- */

/** Maximum records `arc audit inspect` may emit in one invocation. */
export const MAX_INSPECT_RECORDS = 100;

/** Identifier of the lifecycle phase a reconciliation record carries. */
const RECOVERY_INDETERMINATE_PHASE = 'RECOVERY_INDETERMINATE';

/* -------------------------------------------------------------------------- *
 * Streaming segment sources
 * -------------------------------------------------------------------------- */

/**
 * One physical artifact that carries retained primary records.
 *
 * A logical rotated range may be present as `.jsonl` and `.jsonl.gz` at the same
 * time (the crash window between installing the compressed artifact and removing
 * its source). Exactly one representation is selected per logical range — the
 * compressed canonical form when it exists — so a range is never yielded twice.
 */
export interface RetainedSegmentSource {
  kind: 'ARCHIVE' | 'ACTIVE';
  /** Filename as it appears on disk. */
  label: string;
  /** Absolute path. */
  filePath: string;
  compressed: boolean;
  /** First global sequence in the range, inclusive. */
  sequenceStart: number;
  /** Last global sequence in the range, inclusive. */
  sequenceEnd: number;
}

function sourceForLogicalArchive(entry: LogicalArchiveEntry): RetainedSegmentSource {
  const chosen = entry.gzip ?? entry.plain;
  if (chosen === undefined) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `rotated range ${entry.sequenceStart}..${entry.sequenceEnd} has no physical representation`,
    );
  }
  return {
    kind: 'ARCHIVE',
    label: chosen.filename,
    filePath: chosen.filePath,
    compressed: chosen.compressed,
    sequenceStart: entry.sequenceStart,
    sequenceEnd: entry.sequenceEnd,
  };
}

/**
 * Every retained primary artifact, in ascending sequence order.
 *
 * The inventory is read from the store's own filename vocabulary, so a
 * mislabeled or overlapping range fails here — before any content is read —
 * rather than producing a plausible-looking ordering.
 */
export function listRetainedSegmentSources(
  directory: string,
  expectedUid: number = getProcessUid(),
): RetainedSegmentSource[] {
  const sources = listLogicalArchiveInventory(directory, expectedUid)
    .map(sourceForLogicalArchive)
    .sort((a, b) => a.sequenceStart - b.sequenceStart);

  const activePath = path.join(directory, ACTIVE_SEGMENT_FILENAME);
  let activeSize: number | null = null;
  try {
    activeSize = fs.lstatSync(activePath).size;
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw cause;
  }
  if (activeSize !== null && activeSize > 0) {
    const last = sources[sources.length - 1];
    sources.push({
      kind: 'ACTIVE',
      label: ACTIVE_SEGMENT_FILENAME,
      filePath: activePath,
      compressed: false,
      sequenceStart: last === undefined ? 1 : last.sequenceEnd + 1,
      sequenceEnd: Number.MAX_SAFE_INTEGER,
    });
  }
  return sources;
}

/**
 * Opens one artifact for reading with the hardened descriptor discipline used
 * everywhere else in the package: `O_NOFOLLOW`, then descriptor authority
 * validation, so a symlink or a foreign-owned or over-linked artifact fails the
 * read rather than being followed.
 */
export function openArtifactFd(filePath: string, label: string, expectedUid: number): number {
  let fd: number;
  try {
    fd = fs.openSync(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', `${label} is a symbolic link`);
    }
    throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', `${label} could not be opened`, {
      cause,
    });
  }
  try {
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
  return fd;
}

/** Identity of an artifact whose bytes are being read. */
export interface ArtifactIdentity {
  dev: number;
  ino: number;
  size: number;
}

export function captureIdentity(fd: number): ArtifactIdentity {
  const stats = fs.fstatSync(fd);
  return { dev: Number(stats.dev), ino: Number(stats.ino), size: Number(stats.size) };
}

/**
 * Streams the parsed records of one retained artifact, in file order.
 *
 * The file is read line at a time through a bounded stream: a `.jsonl.gz`
 * source is decompressed by a streaming gunzip, so no whole segment is ever
 * materialized. Only LF-terminated lines are yielded — an unterminated trailing
 * line is a torn tail, which verification reports rather than repairs.
 */
export async function* streamSegmentRecordsFromFd(
  fd: number,
  label: string,
  compressed: boolean,
  strictFraming: boolean = true,
  autoClose: boolean = true,
): AsyncGenerator<PersistentAuditRecordV1> {
  let stream: NodeJS.ReadableStream = fs.createReadStream(null as unknown as fs.PathLike, {
    fd,
    autoClose,
  });
  if (compressed) {
    stream = stream.pipe(zlib.createGunzip());
  }

  if (strictFraming) {
    let carry: Buffer = Buffer.alloc(0);
    for await (const chunk of consumeDecompressible(stream, label) as AsyncIterable<Buffer>) {
      carry = carry.length === 0 ? Buffer.from(chunk) : Buffer.concat([carry, chunk]);
      for (;;) {
        const index = carry.indexOf(0x0a);
        if (index === -1) break;
        const line = carry.subarray(0, index).toString('utf8');
        carry = Buffer.from(carry.subarray(index + 1));
        if (line.length === 0) continue;
        yield parseAndValidateRecordLineV1(`${line}\n`).record;
      }
      if (carry.length > MAX_RECORD_BYTES) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          `${label} contains a record longer than ${MAX_RECORD_BYTES} bytes`,
        );
      }
    }
    if (carry.length > 0) {
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `${label} ends in an unterminated record line`,
      );
    }
    return;
  }

  const lines = readline.createInterface({
    input: Readable.from(consumeDecompressible(stream, label)),
    crlfDelay: Infinity,
  });
  try {
    for await (const line of lines) {
      if (line.length === 0) continue;
      yield parseAndValidateRecordLineV1(`${line}\n`).record;
    }
  } finally {
    lines.close();
  }
}

async function* streamSegmentRecords(
  source: RetainedSegmentSource,
  expectedUid: number,
  strictFraming: boolean,
): AsyncGenerator<PersistentAuditRecordV1> {
  const fd = openArtifactFd(source.filePath, source.label, expectedUid);
  yield* streamSegmentRecordsFromFd(fd, source.label, source.compressed, strictFraming, true);
}

/**
 * Re-labels a decompression failure as bounded corruption.
 *
 * A truncated or corrupted `.jsonl.gz` makes `zlib` throw its own `Z_*` error.
 * That is not a vocabulary this package publishes, and letting it escape would
 * hand a caller an unbounded implementation detail instead of a coded refusal.
 */
async function* consumeDecompressible(
  stream: NodeJS.ReadableStream,
  label: string,
): AsyncGenerator<Buffer> {
  try {
    for await (const chunk of stream as AsyncIterable<Buffer>) {
      yield chunk;
    }
  } catch (cause) {
    if ((cause as { code?: string })?.code === 'AUDIT_CORRUPTION_DETECTED') throw cause;
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', `${label} is not readable evidence`, {
      cause,
    });
  }
}

/**
 * Streams retained primary records in ascending sequence order across every
 * rotated archive and the active segment.
 *
 * Stops as soon as the caller's `to` bound is passed, so a bounded range read
 * never scans the whole store. `from` and `to` are both inclusive.
 */
export async function* streamRetainedRecords(
  sources: readonly RetainedSegmentSource[],
  options: {
    from?: number;
    to?: number;
    expectedUid?: number;
    /**
     * Require every artifact to be LF-terminated.
     *
     * Off for inspection, where a torn active tail is a legitimate state to stop
     * at; ON wherever a missing terminator would silently turn a truncated
     * artifact into apparently-valid evidence.
     */
    strictFraming?: boolean;
  } = {},
): AsyncGenerator<PersistentAuditRecordV1> {
  const {
    from = 1,
    to = Number.MAX_SAFE_INTEGER,
    expectedUid = getProcessUid(),
    strictFraming = false,
  } = options;
  for (const source of sources) {
    if (source.sequenceEnd < from) continue;
    if (source.sequenceStart > to) return;
    for await (const record of streamSegmentRecords(source, expectedUid, strictFraming)) {
      const sequence = record.sequenceNumber;
      if (sequence < from) continue;
      if (sequence > to) return;
      yield record;
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Evidence inventory — source stability
 * -------------------------------------------------------------------------- */

/** Descriptor-level identity of one evidence artifact. */
export interface EvidenceIdentity {
  dev: number;
  ino: number;
  size: number;
  mtimeMs: number;
}

/**
 * An authoritative inventory of every artifact that carries evidence.
 *
 * Device and inode are what make this a *stability* check rather than a size
 * check: a same-size replacement of a file keeps its length but not its inode,
 * so a swap cannot hide behind an unchanged byte count.
 */
export type EvidenceInventory = Map<string, EvidenceIdentity>;

function identityOf(filePath: string): EvidenceIdentity | null {
  try {
    const stats = fs.lstatSync(filePath);
    if (stats.isSymbolicLink()) return null;
    return {
      dev: Number(stats.dev),
      ino: Number(stats.ino),
      size: Number(stats.size),
      mtimeMs: stats.mtimeMs,
    };
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw cause;
  }
}

/**
 * Snapshots the identity of every retained primary artifact, the store
 * metadata, and the checkpoint and receipt ledgers.
 *
 * Read only: it `lstat`s names and never opens a file for writing.
 */
export function snapshotEvidenceInventory(
  directory: string,
  expectedUid: number = getProcessUid(),
): EvidenceInventory {
  const inventory: EvidenceInventory = new Map();

  for (const name of fs.readdirSync(directory).sort()) {
    const full = path.join(directory, name);
    const identity = identityOf(full);
    if (identity !== null) inventory.set(name, identity);
  }

  void expectedUid;
  return inventory;
}

/**
 * Proves the evidence did not change between two snapshots.
 *
 * A source that is appended to, replaced — even by a file of exactly the same
 * size — added, or removed between the two observations fails here, so a
 * result can never describe a mixture of two generations of evidence.
 */
export function assertInventoryUnchanged(
  before: EvidenceInventory,
  after: EvidenceInventory,
  operation: string,
): void {
  const beforeNames = [...before.keys()].sort();
  const afterNames = [...after.keys()].sort();
  if (beforeNames.length !== afterNames.length) {
    throw createCodedError(
      'AUDIT_SOURCE_UNSTABLE',
      `${operation}: the evidence set changed while it was being read`,
    );
  }
  for (let index = 0; index < beforeNames.length; index += 1) {
    const name = beforeNames[index];
    if (name !== afterNames[index]) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `${operation}: the evidence set changed while it was being read`,
      );
    }
    const was = before.get(name) as EvidenceIdentity;
    const now = after.get(name) as EvidenceIdentity;
    if (was.dev !== now.dev || was.ino !== now.ino || was.size !== now.size) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `${operation}: ${name} changed while it was being read`,
      );
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Bounded ledger streaming
 * -------------------------------------------------------------------------- */

/**
 * Streams a line-oriented signed ledger without materializing it.
 *
 * The whole ledger is never read into memory: it is opened with the hardened
 * descriptor discipline, framed strictly on LF, and yielded one line at a time
 * (terminator removed — the canonical parsers re-add it). A final fragment with
 * no terminator is corruption, never a line, and an over-long fragment fails on
 * the frozen per-record ceiling rather than growing the buffer.
 */
export async function* streamLedgerLinesFromFd(
  fd: number,
  label: string,
  autoClose: boolean = false,
): AsyncGenerator<string> {
  const stream = fs.createReadStream(null as unknown as fs.PathLike, { fd, autoClose });

  let carry: Buffer = Buffer.alloc(0);
  try {
    for await (const chunk of consumeDecompressible(stream, label) as AsyncIterable<Buffer>) {
      carry = carry.length === 0 ? Buffer.from(chunk) : Buffer.concat([carry, chunk]);
      for (;;) {
        const index = carry.indexOf(0x0a);
        if (index === -1) break;
        const line = carry.subarray(0, index).toString('utf8');
        carry = Buffer.from(carry.subarray(index + 1));
        if (line.includes('\r')) {
          throw createCodedError('AUDIT_CORRUPTION_DETECTED', `${label} contains a CR`);
        }
        if (line.length === 0) continue;
        yield line;
      }
      if (carry.length > MAX_RECORD_BYTES) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          `${label} contains a line longer than ${MAX_RECORD_BYTES} bytes`,
        );
      }
    }
  } finally {
    // The stream autoClose handles closing if requested.
  }

  if (carry.length > 0) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', `${label} ends in an unterminated line`);
  }
}

export async function* streamLedgerLines(
  filePath: string,
  label: string,
  expectedUid: number = getProcessUid(),
): AsyncGenerator<string> {
  const fd = openArtifactFd(filePath, label, expectedUid);
  yield* streamLedgerLinesFromFd(fd, label, true);
}

/* -------------------------------------------------------------------------- *
 * Anchor receipt ledger — offline verification
 * -------------------------------------------------------------------------- */

export type VerifiedReceiptArtifactState =
  | { kind: 'ABSENT' }
  | { kind: 'PRESENT'; dev: number; ino: number; size: number; bytes: number; sha256: string };

/** The outcome of checking the Tier-3 receipt ledger. */
export type OfflineAnchorOutcome =
  | { configured: false; artifactState?: VerifiedReceiptArtifactState }
  | {
      configured: true;
      receiptCount: number;
      publicKeyFingerprint: string;
      /** Checkpoint hashes that carry at least one verified receipt. */
      anchoredCheckpointHashes: string[];
      artifactState: VerifiedReceiptArtifactState;
    };

function lstatOrNull(target: string): fs.Stats | null {
  try {
    return fs.lstatSync(target);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw cause;
  }
}

export interface VerifyAnchorLedgerOfflineOptions {
  directory: string;
  metadata: AuditStoreMetadataV1;
  anchorReceiptPublicKeyPath: string | undefined;
  checkpointsInOrder?: readonly AuditCheckpointV1[];
  nextCheckpoint?: () => Promise<AuthenticatedCheckpointFact | string | null>;
  expectedUid?: number;
}

/**
 * Verifies the anchor receipt ledger against the already-authenticated
 * checkpoints.
 *
 * Only the receipt PUBLIC key is read, and it must match the fingerprint pinned
 * in `audit-store.json`. Each line is parsed by the Task-5 parser and its
 * Ed25519 signature checked by the Task-5 verifier.
 *
 * The ordering rule mirrors the production engine exactly. The ledger is a
 * monotonic subsequence of checkpoint order: walking the authenticated
 * checkpoints in order, a receipt is consumed only when its `checkpointHash`
 * names the checkpoint currently under the head. A receipt that names a
 * checkpoint the primary evidence never produced — including a duplicate or an
 * out-of-order line, neither of which can advance the head again — is left
 * unmatched at the end of the walk and fails as an orphan.
 */
export async function verifyAnchorLedgerOffline(
  options: VerifyAnchorLedgerOfflineOptions,
): Promise<OfflineAnchorOutcome> {
  const { directory, metadata, checkpointsInOrder } = options;
  const expectedUid = options.expectedUid ?? getProcessUid();

  let nextCheckpoint = options.nextCheckpoint;
  if (nextCheckpoint === undefined && checkpointsInOrder === undefined) {
    const cpPath = path.join(directory, CHECKPOINT_FILENAME);
    if (fs.existsSync(cpPath)) {
      const cpLines = streamLedgerLines(cpPath, CHECKPOINT_FILENAME, expectedUid);
      const cpIter = cpLines[Symbol.asyncIterator]();
      nextCheckpoint = async () => {
        const step = await cpIter.next();
        if (step.done === true) return null;
        const { checkpoint } = parseAndValidateCheckpointLineV1(`${step.value}\n`);
        return checkpoint.checkpointHash;
      };
    }
  }

  if (metadata.anchorMode === 'DISABLED') {
    // A store whose durable metadata says anchoring is off must not be silently
    // carrying Tier-3 artifacts: they are either evidence from a configuration
    // the store does not record, or debris from one. Either way, reporting a
    // clean verification while anchor artifacts sit on disk would be a false
    // statement about what is there.
    if (lstatOrNull(path.join(directory, ANCHOR_SPOOL_DIRNAME)) !== null) {
      throw createCodedError(
        'ANCHOR_DISABLED_ARTIFACT',
        `${ANCHOR_SPOOL_DIRNAME}/ exists in a store whose metadata records anchorMode DISABLED`,
      );
    }
    if (lstatOrNull(path.join(directory, ANCHOR_RECEIPT_FILENAME)) !== null) {
      throw createCodedError(
        'ANCHOR_DISABLED_ARTIFACT',
        `${ANCHOR_RECEIPT_FILENAME} exists in a store whose metadata records anchorMode DISABLED`,
      );
    }
    return { configured: false, artifactState: { kind: 'ABSENT' } };
  }

  const keyPath = options.anchorReceiptPublicKeyPath;
  if (keyPath === undefined || keyPath.length === 0) {
    throw createCodedError(
      'ANCHOR_PUBLIC_KEY_REQUIRED',
      'anchor mode is ENABLED: an anchor receipt public key is required for offline verification',
    );
  }

  const trustRoot = loadEd25519TrustRootFile(keyPath, {
    purpose: 'ANCHOR_RECEIPT',
    expectedUid,
  });
  const pinned = metadata.anchorReceiptPublicKeyFingerprint;
  if (pinned === undefined || trustRoot.fingerprint !== pinned) {
    throw createCodedError(
      'ANCHOR_RECEIPT_KEY_MISMATCH',
      'anchor receipt public key does not match audit-store.json.anchorReceiptPublicKeyFingerprint',
    );
  }

  // The ledger is reached through a validated directory descriptor rather than
  // through an attacker-influenceable pathname. That descriptor stays open for
  // the whole read: `/proc/self/fd/<dirFd>/<name>` names a live descriptor, and
  // closing the parent would silently detach the child path from it.
  assertDescriptorPinnedTraversalAvailable('offline anchor ledger verification');
  const dirFd = fs.openSync(
    directory,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
  );
  try {
    const ledgerPath = pinnedChildPath(dirFd, ANCHOR_RECEIPT_FILENAME);
    if (lstatOrNull(ledgerPath) === null) {
      return {
        configured: true,
        receiptCount: 0,
        publicKeyFingerprint: trustRoot.fingerprint,
        anchoredCheckpointHashes: [],
        artifactState: { kind: 'ABSENT' },
      };
    }
    return await readAndVerifyLedger({
      ledgerPath,
      metadata,
      trustRoot,
      ...(checkpointsInOrder !== undefined ? { checkpointsInOrder } : {}),
      ...(nextCheckpoint !== undefined ? { nextCheckpoint } : {}),
      expectedUid,
    });
  } finally {
    fs.closeSync(dirFd);
  }
}

/**
 * Reads the whole receipt ledger and applies every binding rule to it.
 *
 * Split out so the directory descriptor that authorizes `ledgerPath` is still
 * open for the entire read.
 */
async function readAndVerifyLedger(options: {
  ledgerPath: string;
  metadata: AuditStoreMetadataV1;
  trustRoot: { publicKey: crypto.KeyObject; fingerprint: string };
  checkpointsInOrder?: readonly AuditCheckpointV1[];
  nextCheckpoint?: () => Promise<AuthenticatedCheckpointFact | string | null>;
  expectedUid: number;
}): Promise<OfflineAnchorOutcome> {
  const { ledgerPath, metadata, trustRoot, expectedUid } = options;
  const fd = openArtifactFd(ledgerPath, ANCHOR_RECEIPT_FILENAME, expectedUid);
  const startIdentity = captureIdentity(fd);

  const hasher = crypto.createHash('sha256');
  const stream = fs.createReadStream(null as unknown as fs.PathLike, { fd, autoClose: false });
  stream.on('data', (chunk: string | Buffer) => {
    hasher.update(chunk);
  });
  const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
  const iterator = lines[Symbol.asyncIterator]();

  try {
    // The Task-5 receipt authority, not a second copy of it. This path holds the
    // descriptor open for the whole walk and streams the ledger one receipt at a
    // time, exactly as the exporter and the bundle verifier do.
    const anchoredCheckpointHashes: string[] = [];
    const outcome = await walkReceiptEvidence({
      storeId: metadata.storeId,
      anchorFingerprint: trustRoot.fingerprint,
      publicKey: trustRoot.publicKey,
      ...(options.nextCheckpoint !== undefined
        ? { nextCheckpoint: options.nextCheckpoint }
        : options.checkpointsInOrder !== undefined
          ? {
              nextCheckpoint: (() => {
                let idx = 0;
                const cps = options.checkpointsInOrder;
                return async () => (idx < cps.length ? cps[idx++].checkpointHash : null);
              })(),
            }
          : {}),
      onAnchoredCheckpoint: (hash) => {
        assertManifestReferenceWithinBound(
          anchoredCheckpointHashes.length + 1,
          MAX_MANIFEST_CHECKPOINT_REFS,
          'anchored checkpoints',
        );
        anchoredCheckpointHashes.push(hash);
      },
      nextReceipt: async () => {
        for (;;) {
          const step = await iterator.next();
          if (step.done === true) return null;
          if (step.value.length === 0) continue;
          return parseAndValidateAnchorReceiptLineV1(`${step.value}\n`);
        }
      },
    });

    // The ledger must still be the artifact whose bytes were read.
    const finalStats = fs.fstatSync(fd);
    const consumingStream = stream as unknown as { bytesRead: number };
    if (
      Number(finalStats.dev) !== startIdentity.dev ||
      Number(finalStats.ino) !== startIdentity.ino ||
      Number(finalStats.size) !== startIdentity.size ||
      consumingStream.bytesRead !== startIdentity.size
    ) {
      throw createCodedError(
        'ANCHOR_RECEIPT_FILE_RACE',
        `${ANCHOR_RECEIPT_FILENAME} changed while its history was being verified`,
      );
    }

    return {
      configured: true,
      receiptCount: outcome.receiptCount,
      publicKeyFingerprint: trustRoot.fingerprint,
      anchoredCheckpointHashes,
      artifactState: {
        kind: 'PRESENT',
        dev: startIdentity.dev,
        ino: startIdentity.ino,
        size: startIdentity.size,
        bytes: consumingStream.bytesRead,
        sha256: hasher.digest('hex'),
      },
    };
  } finally {
    lines.close();
    fs.closeSync(fd);
  }
}

/* -------------------------------------------------------------------------- *
 * Offline verification
 * -------------------------------------------------------------------------- */

export interface OfflineVerificationOptions {
  /** The audit store directory. Never created if absent. */
  directory: string;
  /** Path to the Ed25519 PUBLIC key the checkpoints must be signed by. */
  checkpointPublicKeyPath: string;
  /** Path to the Ed25519 PUBLIC receipt key. Required only when anchor mode is ENABLED. */
  anchorReceiptPublicKeyPath?: string;
  /** Authenticated agent workspace paths, for the audit-directory overlap rule. */
  workspacePaths?: readonly string[];
  /** Expected owner of the audit artifacts. Defaults to this process's uid. */
  expectedUid?: number;
  /**
   * Internal test seams (RC-06 Task 7).
   * @internal
   */
  hooks?: {
    afterMetadataLoad?: () => void | Promise<void>;
    afterPrimaryVerification?: () => void | Promise<void>;
    afterCheckpointVerification?: () => void | Promise<void>;
    afterReceiptVerification?: () => void | Promise<void>;
    beforeFinalStabilityCheck?: () => void | Promise<void>;
  };
}

export interface OfflineVerificationResult {
  status: 'VERIFIED';
  storeId: string;
  anchorMode: 'DISABLED' | 'ENABLED';
  primary: {
    recordCount: number;
    terminalSequence: number;
    terminalRecordHash: string;
    nextSequence: number;
    logicalArchiveCount: number;
    physicalPrimaryBytes: number;
    activeSegmentPresent: boolean;
  };
  checkpoints: {
    checkpointCount: number;
    lastCheckpointSequence: number | null;
    lastCheckpointHash: string | null;
    checkpointPublicKeyFingerprint: string;
  };
  anchor: OfflineAnchorOutcome;
  /**
   * Which trust tiers an operator may truthfully rely on for this evidence.
   *
   * Tier 3 is only claimed when receipts were actually verified against the
   * pinned anchor public key. With anchoring configured but no receipts written
   * yet, the honest answer is Tier 1 + Tier 2 only.
   */
  tiers: {
    primary: 'VERIFIED';
    checkpoint: 'VERIFIED';
    anchor: 'VERIFIED' | 'NO_RECEIPTS' | 'NOT_CONFIGURED';
  };
}

/**
 * Streams an artifact and calculates the SHA-256 of its logical representation.
 *
 * For uncompressed artifacts (e.g. metadata, active segment, checkpoints, receipts,
 * uncompressed segments), this is the SHA-256 of the raw byte stream.
 * For compressed segments (.jsonl.gz), this is the SHA-256 of the decompressed byte stream,
 * exactly matching the logical digest produced by `verifyRetainedPrimaryHistory`.
 */
export async function streamDigestLogicalSegment(
  filePath: string,
  label: string,
  compressed: boolean,
  expectedUid: number,
): Promise<{ sha256: string; identity: ArtifactIdentity }> {
  let fd: number | null = null;
  try {
    try {
      fd = openArtifactFd(filePath, label, expectedUid);
    } catch (cause) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `offline verification: ${label} could not be opened (${(cause as Error)?.message})`,
        { cause },
      );
    }

    const identity = captureIdentity(fd);
    const hasher = crypto.createHash('sha256');
    const readStream = fs.createReadStream(filePath, {
      fd,
      autoClose: true,
      highWaterMark: 64 * 1024,
    });
    // Ownership of fd transfers to readStream, which closes it exactly once.
    fd = null;
    readStream.on('error', () => {});

    let source: AsyncIterable<Buffer>;
    let gunzip: zlib.Gunzip | null = null;
    if (compressed) {
      gunzip = zlib.createGunzip();
      readStream.on('error', (err) => gunzip?.destroy(err));
      readStream.pipe(gunzip);
      source = gunzip;
    } else {
      source = readStream;
    }

    try {
      for await (const chunk of source) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        hasher.update(buf);
      }
    } catch (cause) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `offline verification: ${label} stream failed while it was being read`,
        { cause },
      );
    } finally {
      if (gunzip !== null) {
        gunzip.destroy();
      }
    }

    return { sha256: hasher.digest('hex'), identity };
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

export type OfflineVerifiedCheckpoints = CheckpointHistoryVerificationResult & {
  artifactState:
    | { kind: 'ABSENT' }
    | { kind: 'PRESENT'; dev: number; ino: number; size: number; bytes: number; sha256: string };
};

export interface ContentGenerationBaseline {
  directory: string;
  expectedUid: number;
  inventoryBefore: EvidenceInventory;
  metadataDigest: { sha256: string; identity: ArtifactIdentity };
  primary: RetainedPrimaryHistoryVerificationResult;
  checkpoints: OfflineVerifiedCheckpoints;
  anchor: OfflineAnchorOutcome;
}

/**
 * Proves that the filesystem evidence observed at the final stability boundary
 * is byte-for-byte and logical-for-logical the exact same generation authenticated
 * across all independent verification passes.
 */
export async function assertOfflineEvidenceContentGenerationUnchanged(
  baseline: ContentGenerationBaseline,
): Promise<void> {
  const { directory, expectedUid, inventoryBefore, metadataDigest, primary, checkpoints, anchor } =
    baseline;

  // 1. Content-bind audit-store.json
  const currentMetadata = await streamDigestLogicalSegment(
    path.join(directory, METADATA_FILENAME),
    METADATA_FILENAME,
    false,
    expectedUid,
  );
  if (
    currentMetadata.identity.dev !== metadataDigest.identity.dev ||
    currentMetadata.identity.ino !== metadataDigest.identity.ino ||
    currentMetadata.identity.size !== metadataDigest.identity.size ||
    currentMetadata.sha256 !== metadataDigest.sha256
  ) {
    throw createCodedError(
      'AUDIT_SOURCE_UNSTABLE',
      'offline verification: audit-store.json changed while it was being read',
    );
  }

  // 2. Content-bind every retained primary archive
  for (const segment of primary.segments) {
    for (const fn of segment.filenames) {
      const fullPath = path.join(directory, fn);
      const compressed = fn.endsWith('.gz');
      const current = await streamDigestLogicalSegment(fullPath, fn, compressed, expectedUid);
      const beforeId = inventoryBefore.get(fn);
      if (
        beforeId === undefined ||
        current.identity.dev !== beforeId.dev ||
        current.identity.ino !== beforeId.ino ||
        current.identity.size !== beforeId.size ||
        current.sha256 !== segment.digest.sha256
      ) {
        throw createCodedError(
          'AUDIT_SOURCE_UNSTABLE',
          `offline verification: ${fn} changed while it was being read`,
        );
      }
    }
  }

  // 3. Content-bind active segment when present
  if (primary.active !== null) {
    const activePath = path.join(directory, ACTIVE_SEGMENT_FILENAME);
    const current = await streamDigestLogicalSegment(
      activePath,
      ACTIVE_SEGMENT_FILENAME,
      false,
      expectedUid,
    );
    const beforeId = inventoryBefore.get(ACTIVE_SEGMENT_FILENAME);
    if (
      beforeId === undefined ||
      current.identity.dev !== beforeId.dev ||
      current.identity.ino !== beforeId.ino ||
      current.identity.size !== beforeId.size ||
      current.sha256 !== primary.active.sha256
    ) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `offline verification: ${ACTIVE_SEGMENT_FILENAME} changed while it was being read`,
      );
    }
  }

  // 4. Content-bind checkpoint ledger when present
  if (checkpoints.artifactState.kind === 'PRESENT') {
    const cpPath = path.join(directory, CHECKPOINT_FILENAME);
    const current = await streamDigestLogicalSegment(
      cpPath,
      CHECKPOINT_FILENAME,
      false,
      expectedUid,
    );
    if (
      current.identity.dev !== checkpoints.artifactState.dev ||
      current.identity.ino !== checkpoints.artifactState.ino ||
      current.identity.size !== checkpoints.artifactState.size ||
      current.sha256 !== checkpoints.artifactState.sha256
    ) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `offline verification: ${CHECKPOINT_FILENAME} changed while it was being read`,
      );
    }
  }

  // 5. Content-bind receipt ledger when present
  if (anchor.artifactState?.kind === 'PRESENT') {
    const receiptPath = path.join(directory, ANCHOR_RECEIPT_FILENAME);
    const current = await streamDigestLogicalSegment(
      receiptPath,
      ANCHOR_RECEIPT_FILENAME,
      false,
      expectedUid,
    );
    if (
      current.identity.dev !== anchor.artifactState.dev ||
      current.identity.ino !== anchor.artifactState.ino ||
      current.identity.size !== anchor.artifactState.size ||
      current.sha256 !== anchor.artifactState.sha256
    ) {
      throw createCodedError(
        'AUDIT_SOURCE_UNSTABLE',
        `offline verification: ${ANCHOR_RECEIPT_FILENAME} changed while it was being read`,
      );
    }
  }
}

/**
 * Verifies a retained audit store offline, from filesystem evidence alone.
 *
 * Throws a coded error with a bounded message on the first failure. Nothing is
 * written on either path.
 */
export async function verifyOfflineStore(
  options: OfflineVerificationOptions,
): Promise<OfflineVerificationResult> {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const workspacePaths = [...(options.workspacePaths ?? [])];

  // `createIfMissing` is deliberately left at its false default: an absent store
  // is an error, never something verification brings into existence.
  validateAuditDirectory(options.directory, { expectedUid, workspacePaths });

  // The inventory is taken before and after, and any change — an appended active
  // segment, a replaced rotated archive, a same-size pathname swap, a new
  // checkpoint or receipt ledger — fails the whole verification.
  const inventoryBefore = snapshotEvidenceInventory(options.directory, expectedUid);

  const metadataEvidence = loadStoreMetadataEvidence(options.directory, expectedUid);
  const { metadata } = metadataEvidence;
  await options.hooks?.afterMetadataLoad?.();

  const primary = await verifyRetainedPrimaryHistory(options.directory, expectedUid);
  if (primary.status !== 'VERIFIED') {
    throw createCodedError(
      'AUDIT_VERIFICATION_FAILED',
      `primary history is not verified (${primary.status})`,
    );
  }
  await options.hooks?.afterPrimaryVerification?.();

  const checkpoints = (await verifyCheckpointHistory({
    directory: options.directory,
    publicKeyPath: options.checkpointPublicKeyPath,
    workspacePaths,
  })) as OfflineVerifiedCheckpoints;
  await options.hooks?.afterCheckpointVerification?.();

  const cpPath = path.join(options.directory, CHECKPOINT_FILENAME);
  const cpLines = fs.existsSync(cpPath)
    ? streamLedgerLines(cpPath, CHECKPOINT_FILENAME, expectedUid)
    : null;
  const cpIter = cpLines !== null ? cpLines[Symbol.asyncIterator]() : null;
  const nextCheckpoint =
    cpIter !== null
      ? async () => {
          const step = await cpIter.next();
          if (step.done === true) return null;
          const { checkpoint } = parseAndValidateCheckpointLineV1(`${step.value}\n`);
          return checkpoint.checkpointHash;
        }
      : undefined;

  const anchor = await verifyAnchorLedgerOffline({
    directory: options.directory,
    metadata,
    anchorReceiptPublicKeyPath: options.anchorReceiptPublicKeyPath,
    ...(nextCheckpoint !== undefined ? { nextCheckpoint } : {}),
    expectedUid,
  });
  await options.hooks?.afterReceiptVerification?.();

  await options.hooks?.beforeFinalStabilityCheck?.();

  assertInventoryUnchanged(
    inventoryBefore,
    snapshotEvidenceInventory(options.directory, expectedUid),
    'offline verification',
  );

  await assertOfflineEvidenceContentGenerationUnchanged({
    directory: options.directory,
    expectedUid,
    inventoryBefore,
    metadataDigest: {
      sha256: metadataEvidence.artifactState.sha256,
      identity: metadataEvidence.artifactState,
    },
    primary,
    checkpoints,
    anchor,
  });

  const tiers: OfflineVerificationResult['tiers'] = {
    primary: 'VERIFIED',
    checkpoint: 'VERIFIED',
    anchor: !anchor.configured
      ? 'NOT_CONFIGURED'
      : anchor.receiptCount === 0
        ? 'NO_RECEIPTS'
        : 'VERIFIED',
  };

  return {
    status: 'VERIFIED',
    storeId: metadata.storeId,
    anchorMode: metadata.anchorMode,
    primary: {
      recordCount: primary.recordCount,
      terminalSequence: primary.terminalSequence,
      terminalRecordHash: primary.terminalRecordHash,
      nextSequence: primary.nextSequence,
      logicalArchiveCount: primary.logicalArchiveCount,
      physicalPrimaryBytes: primary.physicalPrimaryBytes,
      activeSegmentPresent: primary.active !== null,
    },
    checkpoints: {
      checkpointCount: checkpoints.checkpointCount,
      lastCheckpointSequence: checkpoints.lastCheckpointSequence,
      lastCheckpointHash: checkpoints.lastCheckpointHash,
      checkpointPublicKeyFingerprint: checkpoints.publicKeyFingerprint,
    },
    anchor,
    tiers,
  };
}

/* -------------------------------------------------------------------------- *
 * Local operator status
 * -------------------------------------------------------------------------- */

export interface OfflineAuditStatus {
  storagePath: string;
  storeId: string;
  anchorMode: 'DISABLED' | 'ENABLED';
  activeSegment: { present: boolean; filename: string };
  totalRetainedSegments: number;
  currentSequence: number;
  lastCheckpointSequence: number | null;
  unanchoredCheckpointCount: number;
  indeterminateRecoveries: number;
  integrity: 'VERIFIED' | 'FAILED';
  tiers: OfflineVerificationResult['tiers'];
}

/**
 * Produces the local operator status summary.
 *
 * Every field is derived from verified evidence. When the store cannot be
 * verified this throws rather than reporting an optimistic `HEALTHY` summary — a
 * status command that cannot vouch for its own numbers is not a status.
 */
export async function readOfflineAuditStatus(
  options: OfflineVerificationOptions,
): Promise<OfflineAuditStatus> {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const verification = await verifyOfflineStore(options);

  const sources = listRetainedSegmentSources(options.directory, expectedUid);
  let indeterminateRecoveries = 0;
  for await (const record of streamRetainedRecords(sources, { expectedUid })) {
    if (record.lifecycle?.phase === RECOVERY_INDETERMINATE_PHASE) indeterminateRecoveries += 1;
  }

  const anchored = verification.anchor.configured
    ? verification.anchor.anchoredCheckpointHashes.length
    : 0;
  const unanchoredCheckpointCount = verification.anchor.configured
    ? Math.max(0, verification.checkpoints.checkpointCount - anchored)
    : 0;

  const active = lstatOrNull(path.join(options.directory, ACTIVE_SEGMENT_FILENAME));

  return {
    storagePath: path.resolve(options.directory),
    storeId: verification.storeId,
    anchorMode: verification.anchorMode,
    activeSegment: {
      present: active !== null && active.size > 0,
      filename: ACTIVE_SEGMENT_FILENAME,
    },
    totalRetainedSegments: verification.primary.logicalArchiveCount,
    currentSequence: verification.primary.terminalSequence,
    lastCheckpointSequence: verification.checkpoints.lastCheckpointSequence,
    unanchoredCheckpointCount,
    indeterminateRecoveries,
    integrity: 'VERIFIED',
    tiers: verification.tiers,
  };
}

/* -------------------------------------------------------------------------- *
 * Bounded inspection
 * -------------------------------------------------------------------------- */

/**
 * Options for {@link inspectRetainedRecords}.
 *
 * Inspection displays stored records; it does not authenticate them, so it
 * needs no verification key at all. Requiring one would suggest this path
 * proves something about the evidence, which it does not — `verify` does that.
 */
export interface InspectOptions {
  /** The audit store directory. Never created if absent. */
  directory: string;
  /** Authenticated agent workspace paths, for the audit-directory overlap rule. */
  workspacePaths?: readonly string[];
  /** Expected owner of the audit artifacts. Defaults to this process's uid. */
  expectedUid?: number;
  from?: number;
  to?: number;
  limit?: number;
}

/**
 * Streams at most {@link MAX_INSPECT_RECORDS} stored records for the requested
 * inclusive sequence range.
 *
 * The records returned are the persisted evidence exactly as the central
 * redaction authority wrote it. There is no second redaction pass here: a
 * display-time filter would be a weaker copy of that authority and would change
 * what the operator is actually looking at.
 */
export async function inspectRetainedRecords(
  options: InspectOptions,
): Promise<PersistentAuditRecordV1[]> {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const { from, to, limit } = validateInspectRange(options);

  validateAuditDirectory(options.directory, {
    expectedUid,
    workspacePaths: [...(options.workspacePaths ?? [])],
  });

  const sources = listRetainedSegmentSources(options.directory, expectedUid);
  const records: PersistentAuditRecordV1[] = [];
  for await (const record of streamRetainedRecords(sources, { from, to, expectedUid })) {
    if (records.length === limit) break;
    records.push(record);
  }
  return records;
}

/**
 * Validates `--from`, `--to` and `--limit`.
 *
 * The limit is never widened silently: `limit > MAX_INSPECT_RECORDS` is an
 * error, not a clamp, so an operator never believes they read more history than
 * they did.
 */
export function validateSequenceRange(input: { from?: number; to?: number }): {
  from: number;
  to: number;
} {
  for (const [name, value] of [
    ['--from', input.from],
    ['--to', input.to],
  ] as const) {
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw createCodedError('INVALID_SEQUENCE_RANGE', `${name} must be a positive integer`);
    }
  }
  const from = input.from ?? 1;
  const to = input.to ?? Number.MAX_SAFE_INTEGER;
  if (from > to) {
    throw createCodedError('INVALID_SEQUENCE_RANGE', '--from must not be greater than --to');
  }
  return { from, to };
}

export function validateInspectRange(input: { from?: number; to?: number; limit?: number }): {
  from: number;
  to: number;
  limit: number;
} {
  const { from, to } = validateSequenceRange(input);
  const limit = input.limit ?? MAX_INSPECT_RECORDS;

  if (input.limit !== undefined && (!Number.isSafeInteger(input.limit) || input.limit <= 0)) {
    throw createCodedError('INVALID_SEQUENCE_RANGE', '--limit must be a positive integer');
  }
  if (limit > MAX_INSPECT_RECORDS) {
    throw createCodedError(
      'INSPECT_LIMIT_EXCEEDED',
      `--limit must not exceed ${MAX_INSPECT_RECORDS} records`,
    );
  }
  return { from, to, limit };
}

/** Filename of the checkpoint artifact, re-exported for offline consumers. */
export { CHECKPOINT_FILENAME };
