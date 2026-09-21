/**
 * RC-06 Task 3 — segment rotation, streaming compression and storage budget.
 *
 * This module is the rotation coordinator. It does NOT own the append path, the
 * active descriptor, the writer lock, or the chain cursors: `PersistentAuditStorage`
 * remains the single writer for a given audit directory, and rotation reuses that
 * one descriptor and that one lock. No second `PersistentAuditStorage` is created,
 * `audit.lock` is never released and reacquired, and no parallel writer is
 * introduced (rc06 §8).
 *
 * Rotation is staged, not complete. Task 3 freezes the sealing *boundary* and the
 * sealing *interface* and calls a mandatory `RotationCheckpointSealer`, but it
 * does not implement checkpoint construction, hashing, signing or persistence.
 * Task 4 owns all of that, and Task 6 composes the real sealer into production.
 * Until then the only sealer available is package-internal and test-only.
 *
 * Nothing here performs automatic deletion of anything. The single `unlink` in
 * this file removes the *source* `.jsonl` after its compressed replacement has
 * been verified, which the architecture mandates (§10.4); there is no retention
 * policy, no purge, no prune, no vacuum and no delete-oldest operation.
 */

import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { createGzip, createGunzip } from 'node:zlib';
import { MAX_RECORD_BYTES, type PersistentAuditRecordV1 } from '@cesspace-arc/protocol';
import {
  ACTIVE_SEGMENT_FILENAME,
  createCodedError,
  parseAndValidateRecordLineV1,
  validateFileDescriptorAuthority,
  type PersistentAuditStorage,
  type StorageState,
} from './storage.js';
import { LOCK_FILENAME } from './lock.js';
import { METADATA_FILENAME } from './metadata.js';
import {
  MAX_TORN_TAIL_BYTES,
  extractDanglingOperations,
  updateLifecycle,
  type DanglingOperation,
  type LifecycleTrackingEntry,
} from './recovery.js';
import {
  ROTATION_CAPABILITY_TOKEN,
  type RotationStorageCapability,
  type RotationTestHooks,
} from './internal/rotation-capability.js';
import {
  formatRotatedSegmentFilename,
  formatRotationTimestamp,
  parseRotatedSegmentFilename,
  type ParsedRotatedSegmentFilename,
} from './rotation-filename.js';

/* -------------------------------------------------------------------------- *
 * Frozen constants (rc06 §24.1)
 * -------------------------------------------------------------------------- */

/** Hard size trigger: rotate once the active segment reaches 10 MiB. */
export const SEGMENT_SIZE_THRESHOLD = 10_485_760;

/** Operational time trigger, in seconds: rotate after 24 hours. */
export const ROTATION_INTERVAL = 86_400;

/** Maximum number of retained rotated segments. */
export const MAX_ARCHIVE_SEGMENTS = 100;

/** Total physical budget for the audit store, in bytes (1 GiB). */
export const TOTAL_AUDIT_BUDGET_BYTES = 1_073_741_824;

/** Number of most recent records rebuildable from retained primary history. */
export const RECENT_RECORDS_CACHE_LIMIT = 256;

/** Millisecond equivalent of {@link ROTATION_INTERVAL}. */
export const ROTATION_INTERVAL_MS = ROTATION_INTERVAL * 1000;

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const HASH_REGEX = /^[0-9a-f]{64}$/;
const NEWLINE = 0x0a;

/** Transient gzip scratch name. Never a canonical artifact. */
const ROTATION_SCRATCH_REGEX =
  /^rotation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;

/** The torn-tail sidecar naming produced by Task-2 recovery. */
const TORN_SIDECAR_REGEX = /^audit-active\.jsonl\.torn\..+$/;

/* -------------------------------------------------------------------------- *
 * Sealing boundary (rc06 §34.2) — frozen contract, staged by Task 3
 * -------------------------------------------------------------------------- */

/** The exact chain range a rotation finalizes, presented to the sealing authority. */
export interface RotationSealBoundary {
  /** First global sequence number contained in the segment being finalized. */
  sequenceStart: number;
  /** Last global sequence number contained in the segment being finalized. */
  sequenceEnd: number;
  /** `recordHash` of sequence `sequenceEnd`; the rotation's chain anchor. */
  terminalRecordHash: string;
}

/**
 * The mandatory rotation-sealing authority.
 *
 * Task 3 requires this dependency and never substitutes a no-op for it in
 * production. Task 4 supplies the real implementation; Task 6 wires it.
 */
export interface RotationCheckpointSealer {
  sealRotation(boundary: RotationSealBoundary): Promise<void>;
}

/**
 * Validates a sealing boundary before it is handed to the sealing authority.
 *
 * Called BEFORE the sealer and before any physical rotation step, so a malformed
 * boundary can never be sealed and can never leave a half-rotated store.
 */
export function validateRotationSealBoundary(boundary: RotationSealBoundary): void {
  const invalid = (detail: string): never => {
    throw createCodedError(
      'AUDIT_ROTATION_INVALID_BOUNDARY',
      `Invalid rotation seal boundary: ${detail}`,
    );
  };

  if (boundary === null || typeof boundary !== 'object') {
    invalid('boundary must be an object');
  }
  const { sequenceStart, sequenceEnd, terminalRecordHash } = boundary;

  if (!Number.isSafeInteger(sequenceStart) || sequenceStart < 1) {
    invalid('sequenceStart must be a positive safe integer');
  }
  if (!Number.isSafeInteger(sequenceEnd) || sequenceEnd < 1) {
    invalid('sequenceEnd must be a positive safe integer');
  }
  if (sequenceStart > sequenceEnd) {
    invalid('sequenceStart must not exceed sequenceEnd');
  }
  if (typeof terminalRecordHash !== 'string' || !HASH_REGEX.test(terminalRecordHash)) {
    invalid('terminalRecordHash must be exactly 64 lowercase hexadecimal characters');
  }
}

/* -------------------------------------------------------------------------- *
 * Archive inventory
 * -------------------------------------------------------------------------- */

/** One retained rotated segment, as discovered from validated directory entries. */
export interface ArchiveInventoryEntry {
  /** Filename exactly as it appears on disk. */
  filename: string;
  /** Absolute path. */
  filePath: string;
  /** Parsed, canonical sequence range and operational timestamp. */
  parsed: ParsedRotatedSegmentFilename;
  /** Physical on-disk size in bytes. */
  physicalByteLength: number;
}

/** Why a rotation was performed. */
export type SegmentRotationReason = 'SIZE_THRESHOLD' | 'ROTATION_INTERVAL' | 'INTERNAL_MANUAL';

/** The outcome of one completed rotation. */
export interface RotationResult {
  reason: SegmentRotationReason;
  boundary: RotationSealBoundary;
  /** Filename of the installed compressed rotated segment. */
  archiveFilename: string;
  /** Absolute path of the compressed rotated segment. */
  archivePath: string;
  /** Physical size of the compressed rotated segment. */
  archiveByteLength: number;
  /** Physical size of the source segment before compression. */
  sourceByteLength: number;
  /** True when the source `.jsonl` was removed after verification. */
  sourceRemoved: boolean;
  /** Retained archive count after this rotation. */
  archiveCount: number;
}

/* -------------------------------------------------------------------------- *
 * Directory enumeration, authority and classification (rc06 §50, §72)
 * -------------------------------------------------------------------------- */

type StoreEntryKind = 'ACTIVE' | 'AUXILIARY' | 'ROTATED' | 'SCRATCH' | 'UNKNOWN';

interface StoreEntry {
  filename: string;
  filePath: string;
  kind: StoreEntryKind;
  parsed: ParsedRotatedSegmentFilename | null;
  physicalByteLength: number;
}

function classifyStoreEntry(filename: string): StoreEntryKind {
  if (filename === ACTIVE_SEGMENT_FILENAME) return 'ACTIVE';
  if (filename === LOCK_FILENAME || filename === METADATA_FILENAME) return 'AUXILIARY';
  if (TORN_SIDECAR_REGEX.test(filename)) return 'AUXILIARY';
  if (ROTATION_SCRATCH_REGEX.test(filename)) return 'SCRATCH';
  if (parseRotatedSegmentFilename(filename) !== null) return 'ROTATED';
  return 'UNKNOWN';
}

/**
 * Enumerates the audit store directory, failing closed on any entry that is not
 * a recognized canonical artifact.
 *
 * The filename is never trusted for authority: every entry is `lstat`-ed and
 * symlinks, non-regular files, foreign-owned files and multiply-linked files are
 * rejected outright. A rotated segment whose name is nearly-but-not-exactly
 * canonical is UNKNOWN and therefore fatal — silently ignoring it could hide
 * bytes from the budget check or hide a segment from chain verification.
 */
function enumerateAuditStoreEntries(auditDir: string, expectedUid: number): StoreEntry[] {
  let dirents: fs.Dirent[];
  try {
    dirents = fs.readdirSync(auditDir, { withFileTypes: true });
  } catch (err) {
    throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', 'unable to enumerate the audit directory', {
      cause: err,
    });
  }

  const entries: StoreEntry[] = [];

  for (const dirent of dirents) {
    const filename = dirent.name;
    const filePath = path.join(auditDir, filename);
    const kind = classifyStoreEntry(filename);

    if (kind === 'UNKNOWN') {
      throw createCodedError(
        'AUDIT_STORE_UNRECOGNIZED_ENTRY',
        `Unrecognized entry in audit store directory: ${filename}`,
      );
    }

    let lstat: fs.Stats;
    try {
      lstat = fs.lstatSync(filePath);
    } catch (err) {
      throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', `unable to stat ${filename}`, {
        cause: err,
      });
    }

    if (lstat.isSymbolicLink()) {
      throw createCodedError(
        'SYMLINK_DETECTED',
        `audit store entry is a symbolic link: ${filename}`,
      );
    }
    if (!lstat.isFile()) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `audit store entry is not a regular file: ${filename}`,
      );
    }
    if (lstat.uid !== expectedUid) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `audit store entry is not owned by the expected uid: ${filename}`,
      );
    }
    if (lstat.nlink !== 1) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `audit store entry has an unexpected link count: ${filename}`,
      );
    }

    entries.push({
      filename,
      filePath,
      kind,
      parsed: kind === 'ROTATED' ? parseRotatedSegmentFilename(filename) : null,
      physicalByteLength: lstat.size,
    });
  }

  return entries;
}

/** Lists the retained rotated segments in canonical sequence order. */
export function listArchiveInventory(
  auditDir: string,
  expectedUid: number,
): ArchiveInventoryEntry[] {
  const entries = enumerateAuditStoreEntries(auditDir, expectedUid).filter(
    (entry): entry is StoreEntry & { parsed: ParsedRotatedSegmentFilename } =>
      entry.kind === 'ROTATED' && entry.parsed !== null,
  );

  // Ordering is by the authoritative sequence range, never by the timestamp.
  entries.sort((a, b) => {
    if (a.parsed.sequenceStart !== b.parsed.sequenceStart) {
      return a.parsed.sequenceStart - b.parsed.sequenceStart;
    }
    return a.parsed.sequenceEnd - b.parsed.sequenceEnd;
  });

  return entries.map((entry) => ({
    filename: entry.filename,
    filePath: entry.filePath,
    parsed: entry.parsed,
    physicalByteLength: entry.physicalByteLength,
  }));
}

/* -------------------------------------------------------------------------- *
 * Storage budget (rc06 §11, §50, §51)
 * -------------------------------------------------------------------------- */

/**
 * Sums the physical size of every durable byte in the audit store directory.
 *
 * Physical bytes, not logical record bytes: compressed rotated segments count at
 * their compressed size, which is the quantity the on-disk budget is about.
 * Scratch files count too — they are real bytes on the device — so a rotation in
 * flight cannot be used to slip past the budget.
 */
export function scanAuditStorePhysicalBytes(auditDir: string, expectedUid: number): number {
  return enumerateAuditStoreEntries(auditDir, expectedUid).reduce(
    (total, entry) => total + entry.physicalByteLength,
    0,
  );
}

/**
 * Fail-closed capacity preflight.
 *
 * Throws `AUDIT_STORAGE_EXHAUSTED` when the store's physical bytes plus the
 * bytes about to be written would exceed the total budget. It never deletes,
 * truncates, compresses-away or otherwise reclaims anything: the operator
 * remediates out of band (rc06 §11).
 */
export function assertAuditStorageCapacity(
  auditDir: string,
  expectedUid: number,
  additionalBytes: number,
): number {
  const projected = Math.max(0, Math.trunc(additionalBytes));
  const used = scanAuditStorePhysicalBytes(auditDir, expectedUid);

  if (used + projected > TOTAL_AUDIT_BUDGET_BYTES) {
    throw createCodedError(
      'AUDIT_STORAGE_EXHAUSTED',
      `audit storage budget exhausted: ${used} bytes retained, ${projected} bytes requested, ${TOTAL_AUDIT_BUDGET_BYTES} byte budget`,
    );
  }

  return used + projected;
}

/* -------------------------------------------------------------------------- *
 * Streaming segment verification (rc06 §22, §29, §82)
 * -------------------------------------------------------------------------- */

/** Streamed facts about one primary segment's content. */
export interface SegmentDigest {
  /** sha256 of the decompressed byte stream. */
  sha256: string;
  /** Decompressed (logical) byte length. */
  logicalByteLength: number;
  /** On-disk size. */
  physicalByteLength: number;
  /** Number of records in the segment. */
  recordCount: number;
  /** Sequence of the first record, or null when the segment is empty. */
  firstSequence: number | null;
  /** Sequence of the last record. */
  terminalSequence: number;
  /** recordHash of the last record. */
  terminalRecordHash: string;
  /** Sequence the next record must carry. */
  nextSequence: number;
  /** recordHash the next record must reference. */
  previousRecordHash: string;
  /** Decompressed torn-tail bytes, for the active segment only. */
  tornBytes: Buffer | null;
  /** Identity of the verified descriptor. */
  identity: { dev: number; ino: number };
}

interface ScanOptions {
  /** Expected sequence of the first record in this segment. */
  expectedFirstSequence: number;
  /**
   * Expected `previousRecordHash` of the first record in this segment.
   *
   * `null` means the predecessor lies outside this segment and is therefore
   * unknown here; the first record's declared hash is accepted and the link is
   * proven by the whole-history walk instead. Every subsequent record in the
   * segment is still checked against its predecessor.
   */
  expectedPreviousRecordHash: string | null;
  /** Only the live active segment may present a torn tail. */
  allowTornTail: boolean;
  /** Cross-check the content against the filename-declared range. */
  declaredRange?: { sequenceStart: number; sequenceEnd: number };
  /** Exact terminal chain position this segment must reach. */
  expectedTerminalRecordHash?: string;
  /** Lifecycle state carried across segments. */
  lifecycleMap: Map<string, LifecycleTrackingEntry>;
  /** Rolling most-recent-records cache, shared across segments. */
  recentRecords: PersistentAuditRecordV1[];
  /** Label used in error messages. */
  label: string;
}

interface ScanCore {
  recordCount: number;
  firstSequence: number | null;
  terminalSequence: number;
  terminalRecordHash: string;
  nextSequence: number;
  previousRecordHash: string;
  logicalByteLength: number;
  tornBytes: Buffer | null;
}

async function* bufferChunks(source: AsyncIterable<Buffer | string>): AsyncIterable<Buffer> {
  for await (const chunk of source) {
    yield typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
  }
}

/**
 * Streams one segment's records, enforcing the whole V1 chain contract.
 *
 * Validation is the same contract Task-2's `verifyActiveStream` enforces,
 * generalized in three ways: the starting boundary is supplied by the caller
 * (so a rotated segment can begin at an arbitrary sequence rather than at
 * virtual genesis), the byte source may be a gunzip transform rather than a file
 * descriptor, and the source may be a finalized artifact in which no torn tail
 * is permissible.
 *
 * Malformed-line handling mirrors Task 2 exactly: a malformed line is only a
 * recoverable torn tail when nothing at all follows it in the stream. Anything
 * after it makes it corruption.
 *
 * Decompressed bytes are bounded by the total storage budget, so a crafted gzip
 * bomb is rejected rather than expanded into memory.
 */
async function scanSegmentStream(
  source: AsyncIterable<Buffer | string>,
  options: ScanOptions,
  onDecompressedChunk: (chunk: Buffer) => void,
): Promise<ScanCore> {
  const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

  let recordCount = 0;
  let firstSequence: number | null = null;
  let terminalSequence = 0;
  let terminalRecordHash = GENESIS_HASH;
  let nextSequence = options.expectedFirstSequence;
  let previousRecordHash = options.expectedPreviousRecordHash ?? GENESIS_HASH;
  let logicalByteLength = 0;
  let tornBytes: Buffer | null = null;

  let accumulated = Buffer.alloc(0);
  /** A newline-terminated line that failed to parse, still a torn-tail candidate. */
  let malformedCandidate: Buffer | null = null;

  const corrupt = (detail: string): never => {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', `[${options.label}] ${detail}`);
  };

  /** Returns false when the line is not parseable (a torn-tail candidate). */
  const tryAcceptLine = (lineBytes: Buffer): boolean => {
    if (lineBytes.length > MAX_RECORD_BYTES) {
      corrupt(`record line exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES})`);
    }

    let record: PersistentAuditRecordV1;
    try {
      const decodedLine = utf8Decoder.decode(lineBytes);
      record = parseAndValidateRecordLineV1(decodedLine).record;
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code;
      if (code === 'MALFORMED_JSON' || code === 'INVALID_LINE') {
        return false;
      }
      const message = (err as Error)?.message ?? 'Record validation failed';
      if (code === 'INVALID_RECORD' && message.includes('lifecycle')) {
        throw createCodedError('AUDIT_LIFECYCLE_CORRUPTION', message, { cause: err });
      }
      throw createCodedError('AUDIT_CORRUPTION_DETECTED', `[${options.label}] ${message}`, {
        cause: err,
      });
    }

    if (record.sequenceNumber !== nextSequence) {
      corrupt(`sequence discontinuity: expected ${nextSequence}, got ${record.sequenceNumber}`);
    }
    // When the predecessor is unknown (`expectedPreviousRecordHash === null`),
    // only the segment's first record is exempt; every later record is still
    // linked to the one before it, and the cross-segment link is proven by the
    // whole-history walk.
    if (recordCount > 0 || options.expectedPreviousRecordHash !== null) {
      if (record.integrity.previousRecordHash !== previousRecordHash) {
        corrupt(`previousRecordHash mismatch at sequence ${record.sequenceNumber}`);
      }
    }

    if (record.lifecycle !== undefined) {
      updateLifecycle(options.lifecycleMap, record);
    }

    if (firstSequence === null) {
      firstSequence = record.sequenceNumber;
    }

    recordCount++;
    terminalSequence = record.sequenceNumber;
    terminalRecordHash = record.integrity.recordHash;
    nextSequence = record.sequenceNumber + 1;
    previousRecordHash = record.integrity.recordHash;

    options.recentRecords.push(JSON.parse(JSON.stringify(record)) as PersistentAuditRecordV1);
    if (options.recentRecords.length > RECENT_RECORDS_CACHE_LIMIT) {
      options.recentRecords.splice(0, options.recentRecords.length - RECENT_RECORDS_CACHE_LIMIT);
    }

    return true;
  };

  const acceptTornTail = (bytes: Buffer): void => {
    if (!options.allowTornTail) {
      corrupt('segment is a finalized rotated segment but ends in a truncated record');
    }
    if (bytes.length > MAX_TORN_TAIL_BYTES) {
      corrupt(`torn tail exceeds MAX_TORN_TAIL_BYTES (${MAX_TORN_TAIL_BYTES})`);
    }
    tornBytes = Buffer.from(bytes);
  };

  for await (const chunk of bufferChunks(source)) {
    if (malformedCandidate !== null) {
      // More bytes arrived after a malformed line: it was corruption, not a tail.
      corrupt('malformed JSON line before end of segment');
    }

    logicalByteLength += chunk.length;
    onDecompressedChunk(chunk);

    if (logicalByteLength > TOTAL_AUDIT_BUDGET_BYTES) {
      corrupt('decompressed segment exceeds the total audit storage budget');
    }

    accumulated =
      accumulated.length === 0 ? Buffer.from(chunk) : Buffer.concat([accumulated, chunk]);

    let newlineIdx = accumulated.indexOf(NEWLINE);
    while (newlineIdx !== -1) {
      const lineBytes = accumulated.subarray(0, newlineIdx + 1);
      const remaining = accumulated.subarray(newlineIdx + 1);

      if (!tryAcceptLine(lineBytes)) {
        malformedCandidate = Buffer.from(lineBytes);
        accumulated = Buffer.from(remaining);
        break;
      }

      accumulated = Buffer.from(remaining);
      newlineIdx = accumulated.indexOf(NEWLINE);
    }

    if (malformedCandidate === null && accumulated.length > MAX_RECORD_BYTES) {
      corrupt(`record line exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES}) without newline`);
    }
  }

  if (malformedCandidate !== null) {
    if (accumulated.length > 0) {
      corrupt('malformed JSON line before end of segment');
    }
    acceptTornTail(malformedCandidate);
  } else if (accumulated.length > 0) {
    // An unterminated final fragment. It is a torn tail only when it is not a
    // complete, canonical record that merely lost its newline.
    if (accumulated.length > MAX_RECORD_BYTES) {
      corrupt(`record line exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES})`);
    }
    let decodes = true;
    try {
      utf8Decoder.decode(accumulated);
    } catch {
      decodes = false;
    }
    if (decodes) {
      corrupt('segment does not end with a newline');
    }
    acceptTornTail(accumulated);
  }

  if (tornBytes === null && recordCount === 0) {
    corrupt('segment contains no records');
  }

  if (tornBytes === null) {
    if (options.declaredRange !== undefined) {
      if (firstSequence !== options.declaredRange.sequenceStart) {
        corrupt(
          `filename declares sequenceStart ${options.declaredRange.sequenceStart} but content starts at ${String(firstSequence)}`,
        );
      }
      if (terminalSequence !== options.declaredRange.sequenceEnd) {
        corrupt(
          `filename declares sequenceEnd ${options.declaredRange.sequenceEnd} but content ends at ${terminalSequence}`,
        );
      }
    }
    if (
      options.expectedTerminalRecordHash !== undefined &&
      terminalRecordHash !== options.expectedTerminalRecordHash
    ) {
      corrupt(
        `segment terminates at ${terminalRecordHash}, expected ${options.expectedTerminalRecordHash}`,
      );
    }
  }

  return {
    recordCount,
    firstSequence,
    terminalSequence,
    terminalRecordHash,
    nextSequence,
    previousRecordHash,
    logicalByteLength,
    tornBytes,
  };
}

/**
 * Opens, validates and streams a primary segment.
 *
 * Authority is established on the descriptor, not the path: `O_NOFOLLOW`, exact
 * `0o600`, real UID ownership, a regular file and `nlink === 1`.
 */
async function digestSegment(
  filePath: string,
  expectedUid: number,
  compressed: boolean,
  options: ScanOptions,
): Promise<SegmentDigest> {
  let fd: number | null = null;
  let readStream: fs.ReadStream | null = null;
  let gunzip: ReturnType<typeof createGunzip> | null = null;

  try {
    try {
      fd = fs.openSync(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (err: unknown) {
      if ((err as { code?: string })?.code === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', `segment is a symbolic link: ${filePath}`);
      }
      throw err;
    }

    const stats = validateFileDescriptorAuthority(fd, 0o600, expectedUid);

    const hash = createHash('sha256');
    readStream = fs.createReadStream(filePath, {
      fd,
      autoClose: true,
      highWaterMark: 64 * 1024,
    });
    // Ownership of the descriptor transfers to the stream, which closes it
    // exactly once when it ends or is destroyed. Closing it here as well would
    // be a double close.
    fd = null;

    let source: AsyncIterable<Buffer | string> = readStream;

    if (compressed) {
      gunzip = createGunzip();
      // A read error must destroy the transform, otherwise the gunzip stream
      // would simply end and the segment would look truncated rather than broken.
      readStream.on('error', (err) => gunzip?.destroy(err));
      readStream.pipe(gunzip);
      source = gunzip;
    }

    let scan: ScanCore;
    try {
      scan = await scanSegmentStream(source, options, (chunk) => hash.update(chunk));
    } catch (err: unknown) {
      const code = (err as { code?: string })?.code;
      if (typeof code === 'string' && code.startsWith('AUDIT_')) {
        throw err;
      }
      // A zlib failure, a short read or any other stream error is corruption of
      // the artifact, and must fail closed rather than surface as a bare I/O
      // error a caller might mistake for a transient condition.
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `[${options.label}] ${(err as Error)?.message ?? 'segment read failed'}`,
        { cause: err },
      );
    }

    return {
      ...scan,
      sha256: hash.digest('hex'),
      physicalByteLength: stats.size,
      identity: { dev: stats.dev, ino: stats.ino },
    };
  } finally {
    if (gunzip !== null) {
      gunzip.destroy();
    }
    readStream?.destroy();
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Full retained primary-history verification (rc06 §29, §60)
 * -------------------------------------------------------------------------- */

/** Options for {@link verifyRetainedPrimaryHistory}. */
export interface RetainedPrimaryHistoryVerificationOptions {
  /**
   * Trusted primary chain boundary. When supplied, the retained history must
   * reach it and the record at that sequence must carry the expected hash.
   */
  trustedBoundary?: { sequenceNumber: number; recordHash: string };
  /** Overrides the recent-record cache size. Never larger than the frozen limit. */
  recentRecordsLimit?: number;
}

/** The verified state of the whole retained primary history. */
export interface RetainedPrimaryHistoryVerificationResult {
  status: 'VERIFIED' | 'RECOVERABLE_TORN_ACTIVE_TAIL';
  /** Number of logical (canonical) rotated segments. */
  logicalArchiveCount: number;
  /** Sum of the physical bytes of every retained primary artifact. */
  physicalPrimaryBytes: number;
  /** Number of records across the whole retained history. */
  recordCount: number;
  /** Sequence of the last verified record. */
  terminalSequence: number;
  /** recordHash of the last verified record. */
  terminalRecordHash: string;
  /** Sequence the next append must carry. */
  nextSequence: number;
  /** recordHash the next append must reference. */
  previousRecordHash: string;
  /** Up to {@link RECENT_RECORDS_CACHE_LIMIT} most recent records, oldest first. */
  recentRecords: PersistentAuditRecordV1[];
  /** Operations left dangling across the whole retained history. */
  danglingOperations: DanglingOperation[];
  /** Per-segment digests in canonical order. */
  segments: Array<{ filename: string; digest: SegmentDigest }>;
  /** The active segment digest, or null when the active segment is absent or empty. */
  active: SegmentDigest | null;
}

/**
 * Verifies the entire retained primary history: every rotated segment in
 * canonical sequence order, then the active segment, as one unbroken chain.
 *
 * The chain starts at virtual genesis — sequence 1 with a 64-zero predecessor —
 * and must be continuous across every segment boundary. A gap, a duplicate
 * range, an overlapping range, an unrecognized entry, a content/filename
 * disagreement, or a broken hash link is fatal.
 */
export async function verifyRetainedPrimaryHistory(
  auditDir: string,
  expectedUid: number,
  options: RetainedPrimaryHistoryVerificationOptions = {},
): Promise<RetainedPrimaryHistoryVerificationResult> {
  const entries = enumerateAuditStoreEntries(auditDir, expectedUid);

  const archiveEntries = entries
    .filter(
      (entry): entry is StoreEntry & { parsed: ParsedRotatedSegmentFilename } =>
        entry.kind === 'ROTATED' && entry.parsed !== null,
    )
    .sort((a, b) => a.parsed.sequenceStart - b.parsed.sequenceStart);

  const activeEntry = entries.find((entry) => entry.kind === 'ACTIVE') ?? null;

  // Duplicate / overlap detection runs on the authoritative ranges before any
  // content is read, so a conflicting store is rejected as a whole.
  for (let i = 1; i < archiveEntries.length; i++) {
    const previous = archiveEntries[i - 1].parsed;
    const current = archiveEntries[i].parsed;
    if (current.sequenceStart <= previous.sequenceEnd) {
      throw createCodedError(
        'AUDIT_SEGMENT_RANGE_CONFLICT',
        `rotated segments overlap or duplicate: ${previous.filename} and ${current.filename}`,
      );
    }
  }

  const firstArchive = archiveEntries[0]?.parsed;
  if (firstArchive !== undefined && firstArchive.sequenceStart !== 1) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `retained history does not begin at sequence 1 (starts at ${firstArchive.sequenceStart})`,
    );
  }

  const limit = Math.min(
    options.recentRecordsLimit ?? RECENT_RECORDS_CACHE_LIMIT,
    RECENT_RECORDS_CACHE_LIMIT,
  );

  const lifecycleMap = new Map<string, LifecycleTrackingEntry>();
  const recentRecords: PersistentAuditRecordV1[] = [];

  let expectedFirstSequence = 1;
  let expectedPreviousRecordHash: string | null = GENESIS_HASH;

  let recordCount = 0;
  let terminalSequence = 0;
  let terminalRecordHash = GENESIS_HASH;
  let nextSequence: number;
  let previousRecordHash: string;
  let physicalPrimaryBytes = 0;
  let trustedBoundaryMatched = options.trustedBoundary === undefined;
  const segments: Array<{ filename: string; digest: SegmentDigest }> = [];

  const noteBoundary = (sequence: number, hash: string): void => {
    if (
      options.trustedBoundary !== undefined &&
      sequence === options.trustedBoundary.sequenceNumber
    ) {
      if (hash !== options.trustedBoundary.recordHash) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          `trusted boundary hash mismatch at sequence ${sequence}: expected ${options.trustedBoundary.recordHash}, got ${hash}`,
        );
      }
      trustedBoundaryMatched = true;
    }
  };

  for (const entry of archiveEntries) {
    if (entry.parsed.sequenceStart !== expectedFirstSequence) {
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `missing retained segment before ${entry.filename}: expected sequence ${expectedFirstSequence}, segment starts at ${entry.parsed.sequenceStart}`,
      );
    }

    const digest = await digestSegment(entry.filePath, expectedUid, entry.parsed.compressed, {
      expectedFirstSequence,
      expectedPreviousRecordHash,
      allowTornTail: false,
      declaredRange: {
        sequenceStart: entry.parsed.sequenceStart,
        sequenceEnd: entry.parsed.sequenceEnd,
      },
      lifecycleMap,
      recentRecords,
      label: entry.filename,
    });

    recordCount += digest.recordCount;
    terminalSequence = digest.terminalSequence;
    terminalRecordHash = digest.terminalRecordHash;
    expectedFirstSequence = digest.nextSequence;
    expectedPreviousRecordHash = digest.previousRecordHash;
    physicalPrimaryBytes += digest.physicalByteLength;
    segments.push({ filename: entry.filename, digest });
    noteBoundary(digest.terminalSequence, digest.terminalRecordHash);
  }

  let active: SegmentDigest | null = null;
  let status: 'VERIFIED' | 'RECOVERABLE_TORN_ACTIVE_TAIL' = 'VERIFIED';

  if (activeEntry !== null && activeEntry.physicalByteLength > 0) {
    active = await digestSegment(activeEntry.filePath, expectedUid, false, {
      expectedFirstSequence,
      expectedPreviousRecordHash,
      allowTornTail: true,
      lifecycleMap,
      recentRecords,
      label: activeEntry.filename,
    });

    recordCount += active.recordCount;
    terminalSequence = active.terminalSequence;
    terminalRecordHash = active.terminalRecordHash;
    nextSequence = active.nextSequence;
    previousRecordHash = active.previousRecordHash;
    physicalPrimaryBytes += active.physicalByteLength;

    if (active.tornBytes !== null) {
      status = 'RECOVERABLE_TORN_ACTIVE_TAIL';
    }
  } else {
    nextSequence = expectedFirstSequence;
    previousRecordHash = expectedPreviousRecordHash ?? GENESIS_HASH;
  }

  if (options.trustedBoundary !== undefined && !trustedBoundaryMatched) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `trusted boundary sequence ${options.trustedBoundary.sequenceNumber} not found in retained history`,
    );
  }

  while (recentRecords.length > limit) {
    recentRecords.shift();
  }

  return {
    status,
    logicalArchiveCount: archiveEntries.length,
    physicalPrimaryBytes,
    recordCount,
    terminalSequence,
    terminalRecordHash,
    nextSequence,
    previousRecordHash,
    recentRecords,
    danglingOperations: extractDanglingOperations(lifecycleMap),
    segments,
    active,
  };
}

/* -------------------------------------------------------------------------- *
 * Rotation coordinator (rc06 §10, §12, §13, §14)
 * -------------------------------------------------------------------------- */

/** Construction options for {@link RotatingAuditStore}. */
export interface RotatingAuditStoreOptions {
  /**
   * The mandatory rotation-sealing authority.
   *
   * There is no default. A store without a sealer cannot be constructed, so no
   * production composition can rotate a segment without sealing it first.
   */
  sealer: RotationCheckpointSealer;
}

/**
 * The rotation-aware writer for a single audit directory.
 *
 * It wraps exactly one `PersistentAuditStorage` and reuses that storage's writer
 * lock, active descriptor and chain cursors. It never opens a second storage for
 * the same directory, never releases and reacquires `audit.lock` during a
 * rotation, and never rewrites a cursor (rc06 §8, §73).
 */
export class RotatingAuditStore {
  private readonly storage: PersistentAuditStorage;
  private readonly capability: RotationStorageCapability;
  private readonly sealer: RotationCheckpointSealer;
  private readonly hooks: RotationTestHooks | undefined;

  private segmentStartSequence: number;
  private segmentOpenedAtMs: number;
  private recentRecords: PersistentAuditRecordV1[] = [];
  private queue: Promise<unknown> = Promise.resolve();
  private lastRotation: RotationResult | null = null;

  constructor(storage: PersistentAuditStorage, options: RotatingAuditStoreOptions);
  constructor(
    storage: PersistentAuditStorage,
    options: RotatingAuditStoreOptions,
    ...rest: unknown[]
  ) {
    if (rest.length > 0) {
      const [token, hooks] = rest;
      if (token !== ROTATION_CAPABILITY_TOKEN) {
        throw createCodedError(
          'AUDIT_ROTATION_INVALID_CONFIG',
          'Unexpected constructor arguments; rotation test hooks require internal capability',
        );
      }
      this.hooks = hooks as RotationTestHooks | undefined;
    }

    if (options === null || typeof options !== 'object' || options.sealer === undefined) {
      throw createCodedError(
        'AUDIT_ROTATION_INVALID_CONFIG',
        'a RotationCheckpointSealer is mandatory for segment rotation',
      );
    }
    if (typeof options.sealer.sealRotation !== 'function') {
      throw createCodedError(
        'AUDIT_ROTATION_INVALID_CONFIG',
        'sealer.sealRotation must be a function',
      );
    }

    this.storage = storage;
    this.sealer = options.sealer;
    this.capability = storage._rotationCapability(ROTATION_CAPABILITY_TOKEN);
    this.segmentStartSequence = storage.getCurrentSequence();
    this.segmentOpenedAtMs = this.now();
  }

  private now(): number {
    return this.hooks?.clockMs !== undefined ? this.hooks.clockMs() : Date.now();
  }

  /** Serializes every mutating operation: rotation is never re-entrant. */
  private runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation, operation);
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  /** The wrapped single-writer storage. */
  public getStorage(): PersistentAuditStorage {
    return this.storage;
  }

  /** The current storage state. */
  public getState(): StorageState {
    return this.storage.getState();
  }

  /** Retained rotated segments, determined from the directory itself. */
  public listArchives(): ArchiveInventoryEntry[] {
    return listArchiveInventory(this.capability.auditDir, this.capability.expectedUid);
  }

  /** The most recent rotation performed by this coordinator, if any. */
  public getLastRotation(): RotationResult | null {
    return this.lastRotation;
  }

  /** Most recent records observed through this coordinator, oldest first. */
  public getRecentRecords(): PersistentAuditRecordV1[] {
    return this.recentRecords.map(
      (record) => JSON.parse(JSON.stringify(record)) as PersistentAuditRecordV1,
    );
  }

  /** Appends a record, rotating before or after as the frozen triggers require. */
  public append(
    recordCandidate: Parameters<PersistentAuditStorage['append']>[0],
  ): Promise<PersistentAuditRecordV1> {
    return this.runExclusive(async () => {
      if (!this.capability.isActive()) {
        throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'rotating store is not active');
      }

      // Fail-closed capacity preflight: a record known to exceed the remaining
      // budget is refused before any byte is written.
      assertAuditStorageCapacity(
        this.capability.auditDir,
        this.capability.expectedUid,
        this.capability.projectSerializedBytes(recordCandidate),
      );

      if (this.isIntervalRotationDue()) {
        if (this.activeSegmentHasRecords()) {
          await this.performRotation('ROTATION_INTERVAL');
        } else {
          // An empty segment is never sealed and never archived: the interval
          // clock simply restarts, and no checkpoint is consumed.
          this.segmentOpenedAtMs = this.now();
        }
      }

      const record = await this.storage.append(recordCandidate);
      this.rememberRecent(record);

      if (this.isSizeRotationDue()) {
        await this.performRotation('SIZE_THRESHOLD');
      }

      return record;
    });
  }

  private activeSegmentHasRecords(): boolean {
    const size = this.capability.getActiveByteSize();
    return size !== null && size > 0;
  }

  private isSizeRotationDue(): boolean {
    const size = this.capability.getActiveByteSize();
    return size !== null && size >= SEGMENT_SIZE_THRESHOLD;
  }

  private isIntervalRotationDue(): boolean {
    return this.now() - this.segmentOpenedAtMs >= ROTATION_INTERVAL_MS;
  }

  private rememberRecent(record: PersistentAuditRecordV1): void {
    this.recentRecords.push(JSON.parse(JSON.stringify(record)) as PersistentAuditRecordV1);
    if (this.recentRecords.length > RECENT_RECORDS_CACHE_LIMIT) {
      this.recentRecords.splice(0, this.recentRecords.length - RECENT_RECORDS_CACHE_LIMIT);
    }
  }

  /**
   * Rotates the active segment.
   *
   * The frozen ordering is load-bearing and lives here in one place: archive
   * capacity, boundary validation, sealing, the single physical critical
   * section, streaming compression, post-compression verification, raw-byte
   * equivalence, and only then removal of the source.
   *
   * A failure before the physical critical section leaves the store exactly as
   * it was. A failure at or after it leaves the store fail-closed with every
   * byte still retained.
   */
  public rotateNow(reason: SegmentRotationReason): Promise<RotationResult> {
    return this.runExclusive(() => this.performRotation(reason));
  }

  private async performRotation(reason: SegmentRotationReason): Promise<RotationResult> {
    const capability = this.capability;

    if (!capability.isActive()) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'rotating store is not active');
    }

    // The storage budget is a hard ceiling on privileged-storage progression:
    // an exhausted store must not rotate, compress or archive anything, and it
    // must never reclaim space by deleting evidence. It is checked before every
    // other rotation precondition so exhaustion is always the reported cause.
    assertAuditStorageCapacity(capability.auditDir, capability.expectedUid, 0);

    const sequenceEnd = this.storage.getCurrentSequence() - 1;
    if (sequenceEnd < this.segmentStartSequence) {
      throw createCodedError(
        'AUDIT_ROTATION_EMPTY_SEGMENT',
        'refusing to rotate a segment that contains no records',
      );
    }

    const inventory = listArchiveInventory(capability.auditDir, capability.expectedUid);

    // The archive-count ceiling is checked before sealing, so an exhausted store
    // never consumes a checkpoint and never removes an older segment.
    if (inventory.length + 1 > MAX_ARCHIVE_SEGMENTS) {
      throw createCodedError(
        'AUDIT_STORAGE_EXHAUSTED',
        `archive segment limit reached: ${inventory.length} retained, limit ${MAX_ARCHIVE_SEGMENTS}`,
      );
    }

    const boundary: RotationSealBoundary = {
      sequenceStart: this.segmentStartSequence,
      sequenceEnd,
      terminalRecordHash: this.storage.getLastRecordHash(),
    };

    validateRotationSealBoundary(boundary);

    // ---- Seal. Nothing has moved yet, so a failure here is fully recoverable
    // and the segment remains the live active segment.
    await this.sealer.sealRotation(boundary);

    const rotationTimestamp = formatRotationTimestamp(new Date(this.now()));
    const plainFilename = formatRotatedSegmentFilename({
      rotationTimestamp,
      sequenceStart: boundary.sequenceStart,
      sequenceEnd: boundary.sequenceEnd,
      compressed: false,
    });
    const compressedFilename = formatRotatedSegmentFilename({
      rotationTimestamp,
      sequenceStart: boundary.sequenceStart,
      sequenceEnd: boundary.sequenceEnd,
      compressed: true,
    });

    this.hooks?.beforePhysicalRotation?.();

    if (this.hooks?.failPhysicalRotation === true) {
      capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_FAILED', 'simulated physical rotation failure');
    }

    // ---- The one synchronous physical critical section.
    let sourcePath: string;
    try {
      sourcePath = capability.rotateActiveSegmentPhysical(plainFilename).archivedPath;
    } catch (err) {
      capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_FAILED', 'physical rotation failed', { cause: err });
    }

    let sourceByteLength: number;
    try {
      sourceByteLength = fs.lstatSync(sourcePath).size;
    } catch (err) {
      capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_FAILED', 'unable to stat the rotated segment', {
        cause: err,
      });
    }

    this.segmentStartSequence = this.storage.getCurrentSequence();
    this.segmentOpenedAtMs = this.now();

    const archivePath = await this.compressAndVerify({
      sourcePath,
      plainFilename,
      compressedFilename,
      expectedUid: capability.expectedUid,
      auditDir: capability.auditDir,
      boundary,
    });

    const result: RotationResult = {
      reason,
      boundary,
      archiveFilename: compressedFilename,
      archivePath,
      archiveByteLength: fs.lstatSync(archivePath).size,
      sourceByteLength,
      sourceRemoved: true,
      archiveCount: listArchiveInventory(capability.auditDir, capability.expectedUid).length,
    };

    this.lastRotation = result;
    return result;
  }

  /**
   * Streams the rotated segment into a gzip artifact, verifies it, and only then
   * removes the source.
   *
   * In order:
   *   1. gzip the source into an exclusively-created scratch file, streamed;
   *   2. fsync and validate the scratch descriptor;
   *   3. install the `.gz` name without overwriting anything;
   *   4. verify the compressed artifact by streaming gunzip, hashing the
   *      decompressed bytes and replaying the whole chain contract;
   *   5. verify the source `.jsonl` the same way;
   *   6. require raw-byte and record-for-record equivalence;
   *   7. unlink the source and fsync the directory.
   *
   * A failure anywhere before step 7 leaves the source `.jsonl` in place, so the
   * store never loses a segment to a compression fault.
   */
  private async compressAndVerify(params: {
    sourcePath: string;
    plainFilename: string;
    compressedFilename: string;
    expectedUid: number;
    auditDir: string;
    boundary: RotationSealBoundary;
  }): Promise<string> {
    const { sourcePath, compressedFilename, expectedUid, auditDir } = params;
    const archivePath = path.join(auditDir, compressedFilename);
    const scratchPath = path.join(auditDir, `rotation-${randomUUID()}.tmp`);

    if (this.hooks?.failCompressionCreate === true) {
      this.capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_COMPRESSION_FAILED', 'simulated gzip create failure');
    }

    let scratchFd: number | null = null;
    try {
      scratchFd = fs.openSync(
        scratchPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );

      await pipeline(
        fs.createReadStream(sourcePath),
        createGzip({ level: 6 }),
        fs.createWriteStream(scratchPath, { fd: scratchFd, autoClose: false }),
      );

      if (this.hooks?.failCompressionSync === true) {
        throw createCodedError('AUDIT_ROTATION_COMPRESSION_FAILED', 'simulated gzip sync failure');
      }

      fs.fsyncSync(scratchFd);

      const scratchStats = validateFileDescriptorAuthority(scratchFd, 0o600, expectedUid);
      if (!scratchStats.isFile() || scratchStats.nlink !== 1) {
        throw createCodedError(
          'AUDIT_ROTATION_COMPRESSION_FAILED',
          'insecure compression scratch descriptor',
        );
      }

      fs.closeSync(scratchFd);
      scratchFd = null;

      // No-overwrite installation, mirroring the physical rotation step.
      fs.linkSync(scratchPath, archivePath);
      fs.unlinkSync(scratchPath);
      this.syncDirectory(auditDir);

      await this.verifyCompressedArtifact({
        archivePath,
        compressedFilename,
        sourcePath,
        plainFilename: params.plainFilename,
        expectedUid,
        boundary: params.boundary,
      });

      if (this.hooks?.failSourceRemoval === true) {
        throw createCodedError(
          'AUDIT_ROTATION_SOURCE_REMOVAL_FAILED',
          'simulated source removal failure',
        );
      }

      // Only now, with both representations verified and byte-equivalent, is the
      // uncompressed source removed. This is the only unlink of durable primary
      // evidence anywhere in Task 3, and it is never automatic.
      fs.unlinkSync(sourcePath);
      this.syncDirectory(auditDir);

      return archivePath;
    } catch (err) {
      if (scratchFd !== null) {
        try {
          fs.closeSync(scratchFd);
        } catch {
          // ignore
        }
      }
      try {
        if (fs.existsSync(scratchPath)) fs.unlinkSync(scratchPath);
      } catch {
        // ignore
      }
      this.capability.markRotationFailed();
      throw err;
    }
  }

  private async verifyCompressedArtifact(params: {
    archivePath: string;
    compressedFilename: string;
    sourcePath: string;
    plainFilename: string;
    expectedUid: number;
    boundary: RotationSealBoundary;
  }): Promise<void> {
    const { archivePath, compressedFilename, sourcePath, plainFilename, expectedUid, boundary } =
      params;

    const parsed = parseRotatedSegmentFilename(compressedFilename);
    if (parsed === null) {
      throw createCodedError(
        'AUDIT_ROTATION_INVALID_TARGET',
        `refusing to verify a non-canonical rotated segment name: ${compressedFilename}`,
      );
    }

    const shared = {
      expectedFirstSequence: parsed.sequenceStart,
      // The predecessor of the segment's first record lives in the previous
      // segment, which is not read here; the whole-history walk proves that link.
      expectedPreviousRecordHash: null,
      allowTornTail: false as const,
      declaredRange: {
        sequenceStart: parsed.sequenceStart,
        sequenceEnd: parsed.sequenceEnd,
      },
      expectedTerminalRecordHash: boundary.terminalRecordHash,
      recentRecords: [] as PersistentAuditRecordV1[],
    };

    const compressedDigest = await digestSegment(archivePath, expectedUid, true, {
      ...shared,
      lifecycleMap: new Map(),
      label: compressedFilename,
    });

    const plainDigest = await digestSegment(sourcePath, expectedUid, false, {
      ...shared,
      lifecycleMap: new Map(),
      label: plainFilename,
    });

    if (this.hooks?.failPostCompressionVerification === true) {
      throw createCodedError(
        'AUDIT_ROTATION_VERIFICATION_FAILED',
        'simulated post-compression verification failure',
      );
    }

    // Raw byte equivalence: the decompressed stream must be bit-identical.
    if (compressedDigest.sha256 !== plainDigest.sha256) {
      throw createCodedError(
        'AUDIT_ROTATION_VERIFICATION_FAILED',
        `decompressed bytes differ from the source segment (${compressedDigest.sha256} != ${plainDigest.sha256})`,
      );
    }
    if (compressedDigest.logicalByteLength !== plainDigest.logicalByteLength) {
      throw createCodedError(
        'AUDIT_ROTATION_VERIFICATION_FAILED',
        `decompressed length ${compressedDigest.logicalByteLength} differs from source length ${plainDigest.logicalByteLength}`,
      );
    }
    if (compressedDigest.recordCount !== plainDigest.recordCount) {
      throw createCodedError(
        'AUDIT_ROTATION_VERIFICATION_FAILED',
        `record count ${compressedDigest.recordCount} differs from source count ${plainDigest.recordCount}`,
      );
    }
    if (
      compressedDigest.terminalSequence !== plainDigest.terminalSequence ||
      compressedDigest.terminalRecordHash !== plainDigest.terminalRecordHash
    ) {
      throw createCodedError(
        'AUDIT_ROTATION_VERIFICATION_FAILED',
        'compressed artifact does not terminate at the same chain position as the source segment',
      );
    }
  }

  private syncDirectory(auditDir: string): void {
    if (this.hooks?.failDirectorySync === true) {
      throw createCodedError('AUDIT_ROTATION_FAILED', 'simulated directory sync failure');
    }
    const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try {
      fs.fsyncSync(parentFd);
    } finally {
      fs.closeSync(parentFd);
    }
  }

  /**
   * Verifies the whole retained primary history and rebuilds the recent-record
   * cache from durable bytes.
   *
   * The in-memory cache is an optimization only: this method proves the cache
   * can always be reconstructed from the retained history, and it consumes the
   * verifier's result rather than trusting anything held in memory.
   */
  public async verifyAndRebuildRecentRecords(): Promise<RetainedPrimaryHistoryVerificationResult> {
    const result = await verifyRetainedPrimaryHistory(
      this.capability.auditDir,
      this.capability.expectedUid,
    );
    this.recentRecords = result.recentRecords.map(
      (record) => JSON.parse(JSON.stringify(record)) as PersistentAuditRecordV1,
    );
    return result;
  }
}
