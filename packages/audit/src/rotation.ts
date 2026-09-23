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
import { Transform } from 'node:stream';
import { createHash, randomUUID } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { createGzip, createGunzip } from 'node:zlib';
import { MAX_RECORD_BYTES, type PersistentAuditRecordV1 } from '@cesspace-arc/protocol';
import {
  ACTIVE_SEGMENT_FILENAME,
  createCodedError,
  parseAndValidateRecordLineV1,
  validateFileDescriptorAuthority,
  type CodedError,
  type PersistentAuditStorage,
  type StorageState,
} from './storage.js';
import { LOCK_FILENAME } from './lock.js';
import { METADATA_FILENAME } from './metadata.js';
import {
  extractDanglingOperations,
  updateLifecycle,
  type DanglingOperation,
  type LifecycleTrackingEntry,
} from './recovery.js';
import { MAX_TORN_TAIL_BYTES, classifyTrailingBytes } from './internal/torn-tail.js';
import { assertPathIdentity } from './internal/file-identity.js';
import { CHECKPOINT_FILENAME } from './internal/checkpoint-constants.js';
import {
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRECTORY_MODE,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_SPOOL_FILENAME_REGEX,
  ANCHOR_SPOOL_FILE_MODE,
} from './internal/anchor-constants.js';
import {
  ROTATION_CAPABILITY_TOKEN,
  type FileIdentity,
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

/**
 * One physical representation of a logical rotated segment.
 *
 * A logical segment may be represented on disk by an uncompressed `.jsonl`, a
 * compressed `.jsonl.gz`, or — during the crash window between installing the
 * compressed artifact and removing its source — by both at once.
 */
export interface PhysicalArchiveRepresentation {
  /** Filename exactly as it appears on disk. */
  filename: string;
  /** Absolute path. */
  filePath: string;
  /** True for `.jsonl.gz`. */
  compressed: boolean;
  /** Operational timestamp component; never an ordering or identity key. */
  rotationTimestamp: string;
  /** Physical on-disk size in bytes. */
  physicalByteLength: number;
}

/**
 * One retained rotated segment, grouped by its authoritative sequence range.
 *
 * This is the unit that the archive ceiling counts and that history
 * verification walks. Grouping by `(sequenceStart, sequenceEnd)` is what keeps a
 * legitimate compression crash — where both the plain and the compressed
 * representation of one range are on disk — from being mistaken for two
 * archives, or for a range conflict.
 */
export interface LogicalArchiveEntry {
  /** First global sequence number in the range (inclusive). */
  sequenceStart: number;
  /** Last global sequence number in the range (inclusive). */
  sequenceEnd: number;
  /** The uncompressed representation, when present. */
  plain?: PhysicalArchiveRepresentation;
  /** The compressed representation, when present. */
  gzip?: PhysicalArchiveRepresentation;
  /** Sum of the physical sizes of every present representation. */
  physicalByteLength: number;
  /** Diagnostic label: the plain name when present, otherwise the gzip name. */
  label: string;
}

function toPhysicalRepresentation(
  entry: StoreEntry & { parsed: ParsedRotatedSegmentFilename },
): PhysicalArchiveRepresentation {
  return {
    filename: entry.filename,
    filePath: entry.filePath,
    compressed: entry.parsed.compressed,
    rotationTimestamp: entry.parsed.rotationTimestamp,
    physicalByteLength: entry.physicalByteLength,
  };
}

/**
 * Groups the physical rotated entries currently on disk by sequence range.
 *
 * Fail-closed rules, applied before any content is read:
 *
 *  - At most one plain and at most one compressed representation per range.
 *    Two `.jsonl` files, or two `.jsonl.gz` files, for the same range are
 *    ambiguous and rejected.
 *  - When both representations exist they must share the rotation timestamp.
 *    Rotation names both halves of a compression transition from one instant,
 *    so a range whose two representations carry different timestamps is not a
 *    canonical compression pair. Timestamp freshness is never used to pick a
 *    winner; a mismatch is a conflict.
 *  - Ranges must be strictly increasing and must not overlap or nest.
 *
 * Returns ranges in ascending order.
 */
function groupArchiveEntriesByRange(auditDir: string, expectedUid: number): LogicalArchiveEntry[] {
  const rotated = enumerateAuditStoreEntries(auditDir, expectedUid).filter(
    (entry): entry is StoreEntry & { parsed: ParsedRotatedSegmentFilename } =>
      entry.kind === 'ROTATED' && entry.parsed !== null,
  );

  interface RangeGroup {
    sequenceStart: number;
    sequenceEnd: number;
    plain?: PhysicalArchiveRepresentation;
    gzip?: PhysicalArchiveRepresentation;
  }

  const groups = new Map<string, RangeGroup>();

  for (const entry of rotated) {
    const { sequenceStart, sequenceEnd, compressed } = entry.parsed;
    const key = `${sequenceStart}-${sequenceEnd}`;

    let group = groups.get(key);
    if (group === undefined) {
      group = { sequenceStart, sequenceEnd };
      groups.set(key, group);
    }

    if (compressed) {
      if (group.gzip !== undefined) {
        throw createCodedError(
          'AUDIT_SEGMENT_RANGE_CONFLICT',
          `two compressed representations for sequence range ${key}: ${group.gzip.filename} and ${entry.filename}`,
        );
      }
      group.gzip = toPhysicalRepresentation(entry);
    } else {
      if (group.plain !== undefined) {
        throw createCodedError(
          'AUDIT_SEGMENT_RANGE_CONFLICT',
          `two uncompressed representations for sequence range ${key}: ${group.plain.filename} and ${entry.filename}`,
        );
      }
      group.plain = toPhysicalRepresentation(entry);
    }
  }

  const logical: LogicalArchiveEntry[] = [];

  for (const group of groups.values()) {
    const { plain, gzip } = group;

    if (plain !== undefined && gzip !== undefined) {
      if (plain.rotationTimestamp !== gzip.rotationTimestamp) {
        throw createCodedError(
          'AUDIT_SEGMENT_RANGE_CONFLICT',
          `sequence range ${group.sequenceStart}-${group.sequenceEnd} has competing timestamps ` +
            `(${plain.filename} and ${gzip.filename}); only a canonical compression pair may coexist`,
        );
      }
    }

    const representations = [plain, gzip].filter(
      (rep): rep is PhysicalArchiveRepresentation => rep !== undefined,
    );

    logical.push({
      sequenceStart: group.sequenceStart,
      sequenceEnd: group.sequenceEnd,
      ...(plain !== undefined ? { plain } : {}),
      ...(gzip !== undefined ? { gzip } : {}),
      physicalByteLength: representations.reduce((total, rep) => total + rep.physicalByteLength, 0),
      label: (plain ?? gzip)?.filename as string,
    });
  }

  // Ordering is by the authoritative sequence range, never by the timestamp.
  logical.sort((a, b) => {
    if (a.sequenceStart !== b.sequenceStart) return a.sequenceStart - b.sequenceStart;
    return a.sequenceEnd - b.sequenceEnd;
  });

  for (let i = 1; i < logical.length; i++) {
    const previous = logical[i - 1];
    const current = logical[i];
    if (current.sequenceStart <= previous.sequenceEnd) {
      throw createCodedError(
        'AUDIT_SEGMENT_RANGE_CONFLICT',
        `rotated segments overlap or duplicate: ${previous.label} and ${current.label}`,
      );
    }
  }

  return logical;
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

type StoreEntryKind =
  'ACTIVE' | 'AUXILIARY' | 'AUXILIARY_DIRECTORY' | 'ROTATED' | 'SCRATCH' | 'UNKNOWN';

interface StoreEntry {
  filename: string;
  filePath: string;
  kind: StoreEntryKind;
  parsed: ParsedRotatedSegmentFilename | null;
  physicalByteLength: number;
}

/**
 * Validates the Tier-3 spool directory and returns its total physical bytes.
 *
 * The directory is the one recognized store entry that is not a file, so its
 * authority is checked against the directory rules — 0700, expected uid, not a
 * symbolic link, not multiply reachable — and then every child is checked
 * against the spool entry rules: a canonical lowercase 64-hex `<checkpointHash>
 * .json` name, a regular file, 0600, the expected uid, a single link and not a
 * symlink.
 *
 * This is rc06 §21 and RC06-NEG-99: a spool directory that is wider than 0700,
 * or an entry that is wider than 0600 or is a symbolic link, is a loading
 * failure rather than something to be repaired. The bytes returned include the
 * directory's own inode size, because the budget is about physical storage and a
 * directory occupies some.
 */
function scanAnchorSpoolDirectory(
  directoryPath: string,
  directoryStats: fs.Stats,
  expectedUid: number,
): number {
  if (!directoryStats.isDirectory()) {
    throw createCodedError(
      'AUDIT_STORE_INSECURE_ENTRY',
      `audit store entry is not a directory: ${ANCHOR_SPOOL_DIRNAME}`,
    );
  }
  if (directoryStats.uid !== expectedUid) {
    throw createCodedError(
      'AUDIT_STORE_INSECURE_ENTRY',
      `audit store entry is not owned by the expected uid: ${ANCHOR_SPOOL_DIRNAME}`,
    );
  }
  if ((directoryStats.mode & 0o777) !== ANCHOR_SPOOL_DIRECTORY_MODE) {
    throw createCodedError(
      'AUDIT_STORE_INSECURE_ENTRY',
      `audit store entry mode must be 0700: ${ANCHOR_SPOOL_DIRNAME}`,
    );
  }

  let children: string[];
  try {
    children = fs.readdirSync(directoryPath);
  } catch (err) {
    throw createCodedError(
      'AUDIT_STORAGE_UNAVAILABLE',
      `unable to enumerate ${ANCHOR_SPOOL_DIRNAME}`,
      { cause: err },
    );
  }

  let bytes = directoryStats.size;

  for (const child of children) {
    const childPath = path.join(directoryPath, child);

    if (!ANCHOR_SPOOL_FILENAME_REGEX.test(child)) {
      throw createCodedError(
        'AUDIT_STORE_UNRECOGNIZED_ENTRY',
        `Unrecognized entry in ${ANCHOR_SPOOL_DIRNAME}: ${child}`,
      );
    }

    let childStats: fs.Stats;
    try {
      childStats = fs.lstatSync(childPath);
    } catch (err) {
      throw createCodedError(
        'AUDIT_STORAGE_UNAVAILABLE',
        `unable to stat ${ANCHOR_SPOOL_DIRNAME}/${child}`,
        { cause: err },
      );
    }

    if (childStats.isSymbolicLink()) {
      throw createCodedError(
        'SYMLINK_DETECTED',
        `${ANCHOR_SPOOL_DIRNAME} entry is a symbolic link: ${child}`,
      );
    }
    if (!childStats.isFile()) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `${ANCHOR_SPOOL_DIRNAME} entry is not a regular file: ${child}`,
      );
    }
    if (childStats.uid !== expectedUid) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `${ANCHOR_SPOOL_DIRNAME} entry is not owned by the expected uid: ${child}`,
      );
    }
    if (childStats.nlink !== 1) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `${ANCHOR_SPOOL_DIRNAME} entry has an unexpected link count: ${child}`,
      );
    }
    if ((childStats.mode & 0o777) !== ANCHOR_SPOOL_FILE_MODE) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `${ANCHOR_SPOOL_DIRNAME} entry mode must be 0600: ${child}`,
      );
    }

    bytes += childStats.size;
  }

  return bytes;
}

function classifyStoreEntry(filename: string): StoreEntryKind {
  if (filename === ACTIVE_SEGMENT_FILENAME) return 'ACTIVE';
  if (filename === LOCK_FILENAME || filename === METADATA_FILENAME) return 'AUXILIARY';
  // The Tier-2 checkpoint artifact is a durable auxiliary artifact (rc06 §51): it
  // is enumerated and authority-checked like every other entry, and it counts
  // toward the physical storage budget, but it is not a rotated primary segment,
  // it is not part of the primary hash chain, and it never appears in the
  // bounded archive inventory. Recognizing it by exact name — rather than
  // teaching the rotated-filename parser about it — keeps a checkpoint from ever
  // being mistaken for primary evidence.
  if (filename === CHECKPOINT_FILENAME) return 'AUXILIARY';
  // The Tier-3 anchor receipt ledger is a durable auxiliary artifact for the same
  // reasons, and it is recognized by exact name for the same reason (rc06 §21).
  if (filename === ANCHOR_RECEIPT_FILENAME) return 'AUXILIARY';
  // The Tier-3 pending-checkpoint spool is the one recognized entry that is a
  // *directory*. It is enumerated and authority-checked like every other entry,
  // and every byte it holds counts toward the physical budget — but it is
  // validated as a directory, and its children recursively, rather than being
  // rejected for failing the regular-file rules that do not apply to it.
  if (filename === ANCHOR_SPOOL_DIRNAME) return 'AUXILIARY_DIRECTORY';
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

    if (kind === 'AUXILIARY_DIRECTORY') {
      entries.push({
        filename,
        filePath,
        kind,
        parsed: null,
        physicalByteLength: scanAnchorSpoolDirectory(filePath, lstat, expectedUid),
      });
      continue;
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

/**
 * Lists retained rotated segments grouped by logical sequence range.
 *
 * This is the inventory every capacity decision is made from. It is bounded by
 * {@link MAX_ARCHIVE_SEGMENTS} logical ranges, each holding at most two physical
 * representations, and it never retains record content.
 */
export function listLogicalArchiveInventory(
  auditDir: string,
  expectedUid: number,
): LogicalArchiveEntry[] {
  return groupArchiveEntriesByRange(auditDir, expectedUid);
}

/** The number of retained logical archive ranges. */
export function countLogicalArchives(auditDir: string, expectedUid: number): number {
  return groupArchiveEntriesByRange(auditDir, expectedUid).length;
}

/**
 * Fail-closed archive-ceiling preflight.
 *
 * {@link MAX_ARCHIVE_SEGMENTS} bounds the number of retained *logical* archive
 * ranges. A crash pair — one range present as both `.jsonl` and `.jsonl.gz` — is
 * one archive, so the ceiling is reached by ranges, never by pathnames.
 *
 * Reaching the ceiling makes the store exhausted for every privileged-storage
 * progression: neither another record nor another rotation may proceed, and
 * nothing is ever reclaimed to make room. The check runs before a record is
 * written and before a boundary is sealed, so an exhausted store consumes no
 * checkpoint.
 */
export function assertArchiveCapacityAvailable(auditDir: string, expectedUid: number): number {
  const retained = countLogicalArchives(auditDir, expectedUid);

  if (retained >= MAX_ARCHIVE_SEGMENTS) {
    throw createCodedError(
      'AUDIT_STORAGE_EXHAUSTED',
      `archive segment limit reached: ${retained} retained logical archives, limit ${MAX_ARCHIVE_SEGMENTS}`,
    );
  }

  return retained;
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
 * bytes about to be written would reach the total budget. Reaching the ceiling
 * is exhausted, not merely exceeding it: the frozen budget is a hard ceiling on
 * durable disk evidence, so a successful operation may never leave the store
 * sitting exactly at it (rc06 §11, §51). The comparison is therefore `>=`, and
 * it is the same comparison on every path — append, rotation, compression and
 * scratch creation all route through here or through the streaming guard built
 * on the same rule.
 *
 * It never deletes, truncates, compresses-away or otherwise reclaims anything:
 * the operator remediates out of band.
 */
export function assertAuditStorageCapacity(
  auditDir: string,
  expectedUid: number,
  additionalBytes: number,
): number {
  const projected = Math.max(0, Math.trunc(additionalBytes));
  const used = scanAuditStorePhysicalBytes(auditDir, expectedUid);

  if (used + projected >= TOTAL_AUDIT_BUDGET_BYTES) {
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
  /** Timestamp of the first verified record, in ms, or null when empty. */
  openedAtMs: number | null;
  /** True when this segment carried the requested trusted boundary record. */
  trustedBoundaryMatched: boolean;
  /** Identity of the verified descriptor. */
  identity: { dev: number; ino: number };
}

/**
 * One primary record that a scan accepted as verified chain evidence.
 *
 * A fact is emitted only after the whole V1 contract has been enforced on the
 * record: it parsed, its sequence is contiguous with its predecessor, its
 * `previousRecordHash` links to the record before it, and its own `recordHash`
 * is the one the chain now stands on. A fact therefore never describes a
 * partially-validated record, and never describes a torn tail.
 *
 * @internal
 */
export interface VerifiedPrimaryCheckpointFact {
  /** Sequence of the verified record. */
  sequenceNumber: number;
  /** Its `recordHash`, as verified. */
  recordHash: string;
}

interface ScanOptions {
  /**
   * Internal observer invoked once per verified record, in chain order.
   *
   * This is the seam that lets the checkpoint verifier compare a checkpoint
   * stream against real primary evidence without buffering either. It is
   * `@internal`, it is not exported from the package root, and it is only ever
   * populated by the checkpoint module — no caller can use it to change what a
   * scan verifies, only to observe what a scan has already verified.
   *
   * It is deliberately NOT propagated to the throwaway secondary pass of a
   * dual-representation archive: that pass exists to prove the two physical
   * representations agree, and letting it report facts too would double-count
   * every record in the range.
   */
  onVerifiedRecord?: (fact: VerifiedPrimaryCheckpointFact) => void | Promise<void>;
  /**
   * Expected sequence of the first record in this segment.
   *
   * `null` means the caller does not know where the segment starts. Only the
   * bounded active-segment bootstrap scan passes `null`, because it reads a
   * segment whose origin is not known a priori; the sequence it then reports is
   * cross-checked against the storage cursors before it is trusted. Every other
   * caller knows the boundary and passes a number, which keeps the discontinuity
   * check armed for all of them.
   */
  expectedFirstSequence: number | null;
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
  /**
   * Trusted primary chain boundary to confirm while scanning, if any.
   *
   * Checked against EVERY record rather than only at segment terminals, so a
   * boundary recorded mid-segment — or in the live active segment, which is
   * where the newest records live — is satisfied exactly as Task-2 recovery
   * satisfies it.
   */
  trustedBoundary?: { sequenceNumber: number; recordHash: string };
  /** Label used in error messages. */
  label: string;
}

interface ScanCore {
  recordCount: number;
  firstSequence: number | null;
  terminalSequence: number;
  terminalRecordHash: string;
  /**
   * Sequence the next record must carry.
   *
   * `0` is reported only when the caller passed `expectedFirstSequence: null`
   * and the segment yielded no complete record; no caller consumes the value in
   * that case.
   */
  nextSequence: number;
  previousRecordHash: string;
  logicalByteLength: number;
  tornBytes: Buffer | null;
  /** Operational open time: the first verified record's timestamp, in ms. */
  openedAtMs: number | null;
  /**
   * True when this segment carried the trusted boundary record.
   *
   * `true` vacuously when no boundary was requested, mirroring the "nothing to
   * prove" reading that the caller's final check depends on.
   */
  trustedBoundaryMatched: boolean;
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

  let trustedBoundaryMatched = options.trustedBoundary === undefined;
  let recordCount = 0;
  let firstSequence: number | null = null;
  let terminalSequence = 0;
  let terminalRecordHash = GENESIS_HASH;
  let nextSequence = options.expectedFirstSequence ?? 0;
  let previousRecordHash = options.expectedPreviousRecordHash ?? GENESIS_HASH;
  let logicalByteLength = 0;
  let tornBytes: Buffer | null = null;
  let openedAtMs: number | null = null;

  let accumulated = Buffer.alloc(0);
  /** A newline-terminated line that failed to parse, still a torn-tail candidate. */
  let malformedCandidate: Buffer | null = null;

  const corrupt = (detail: string): never => {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', `[${options.label}] ${detail}`);
  };

  /**
   * Returns false when the line is not parseable (a torn-tail candidate).
   *
   * Asynchronous because the optional verified-record observer may be
   * asynchronous. The observer runs only after the record has been fully
   * validated and the scan state has advanced past it, and nothing it returns can
   * alter acceptance: it observes the chain, it does not participate in it.
   */
  const tryAcceptLine = async (lineBytes: Buffer): Promise<boolean> => {
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

    // When the caller does not know where the segment starts
    // (`expectedFirstSequence === null`), only the first record is exempt from
    // the discontinuity check; every later record must still be consecutive.
    if (recordCount > 0 || options.expectedFirstSequence !== null) {
      if (record.sequenceNumber !== nextSequence) {
        corrupt(`sequence discontinuity: expected ${nextSequence}, got ${record.sequenceNumber}`);
      }
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
      // The operational open time of a segment is the timestamp of its first
      // record, not the moment the process happened to look at it. The record's
      // timestamp is a canonical ISO-8601 UTC string already enforced by
      // `validatePersistentRecordV1`, so parsing cannot fail here.
      const parsedTimestamp = Date.parse(record.timestamp);
      openedAtMs = Number.isNaN(parsedTimestamp) ? null : parsedTimestamp;
    }

    // The trusted boundary is confirmed on the record that carries it, wherever
    // in the retained history that turns out to be. A boundary sequence that
    // only ever appeared inside a torn tail is never parsed, so it can never
    // reach this line — which is exactly what makes a torn tail incapable of
    // satisfying the boundary.
    if (
      options.trustedBoundary !== undefined &&
      record.sequenceNumber === options.trustedBoundary.sequenceNumber
    ) {
      if (record.integrity.recordHash !== options.trustedBoundary.recordHash) {
        corrupt(
          `trusted boundary hash mismatch at sequence ${record.sequenceNumber}: expected ${options.trustedBoundary.recordHash}, got ${record.integrity.recordHash}`,
        );
      }
      trustedBoundaryMatched = true;
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

    if (options.onVerifiedRecord !== undefined) {
      await options.onVerifiedRecord({
        sequenceNumber: record.sequenceNumber,
        recordHash: record.integrity.recordHash,
      });
    }

    return true;
  };

  /**
   * Applies the shared torn-tail rule (see `internal/torn-tail.ts`).
   *
   * Decodability is deliberately not consulted: an incomplete JSON prefix that
   * happens to decode as UTF-8 is just as much a crash artifact as one that does
   * not, and treating the two differently would make Task-3 startup reject
   * stores that Task-2 restart recovery accepts.
   */
  const acceptTornTail = (bytes: Buffer): void => {
    const classification = classifyTrailingBytes(bytes, { allowTornTail: options.allowTornTail });
    if (classification.recoverable) {
      tornBytes = classification.tornBytes;
      return;
    }
    corrupt(
      classification.rejection === 'TORN_TAIL_TOO_LARGE'
        ? `torn tail exceeds MAX_TORN_TAIL_BYTES (${MAX_TORN_TAIL_BYTES})`
        : 'segment is a finalized rotated segment but ends in a truncated record',
    );
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

      const accepted = await tryAcceptLine(lineBytes);
      if (!accepted) {
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
    // An unterminated final fragment. Whether it decodes, and whether it happens
    // to be a complete record missing only its newline, is irrelevant: the
    // shared rule decides, exactly as it does for Task-2 recovery.
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
    openedAtMs,
    trustedBoundaryMatched,
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
  expectedIdentity?: FileIdentity,
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

    // When the caller already knows which artifact it means, the descriptor must
    // be that artifact. This is what stops a pathname swapped between the
    // physical rotation and the compression step from being read instead.
    if (expectedIdentity !== undefined) {
      if (
        stats.dev !== expectedIdentity.dev ||
        stats.ino !== expectedIdentity.ino ||
        stats.size !== expectedIdentity.size
      ) {
        throw createCodedError(
          'AUDIT_ROTATION_FAILED',
          `segment no longer matches the identity it was validated with: ${options.label}`,
        );
      }
    }

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
  /**
   * Internal observer invoked once per verified record, in chain order.
   *
   * See {@link ScanOptions.onVerifiedRecord}. This is the checkpoint verifier's
   * streaming seam: it allows a caller to compare an artifact stream against the
   * real retained primary evidence, record by record, without either side ever
   * being buffered.
   *
   * @internal
   */
  onVerifiedRecord?: (fact: VerifiedPrimaryCheckpointFact) => void | Promise<void>;
}

/**
 * Requires two physical representations of one logical range to describe
 * exactly the same record sequence.
 *
 * Every fact that identifies the logical content is compared: the decompressed
 * bytes themselves, their length, the record count, the first and terminal
 * sequences and the terminal hash. A mismatch is corruption — the two files
 * disagree about what was written, and there is no basis for preferring one.
 */
function assertRepresentationsEquivalent(
  primary: PhysicalArchiveRepresentation,
  primaryDigest: SegmentDigest,
  secondary: PhysicalArchiveRepresentation,
  secondaryDigest: SegmentDigest,
): void {
  const mismatch = (detail: string): never => {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `dual representations of one sequence range disagree: ${primary.filename} and ${secondary.filename} ${detail}`,
    );
  };

  if (primaryDigest.sha256 !== secondaryDigest.sha256) {
    mismatch('decompress to different bytes');
  }
  if (primaryDigest.logicalByteLength !== secondaryDigest.logicalByteLength) {
    mismatch(
      `decompress to different lengths (${primaryDigest.logicalByteLength} vs ${secondaryDigest.logicalByteLength})`,
    );
  }
  if (primaryDigest.recordCount !== secondaryDigest.recordCount) {
    mismatch(
      `contain different record counts (${primaryDigest.recordCount} vs ${secondaryDigest.recordCount})`,
    );
  }
  if (primaryDigest.firstSequence !== secondaryDigest.firstSequence) {
    mismatch('begin at different sequences');
  }
  if (
    primaryDigest.terminalSequence !== secondaryDigest.terminalSequence ||
    primaryDigest.terminalRecordHash !== secondaryDigest.terminalRecordHash
  ) {
    mismatch('terminate at different chain positions');
  }
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
  /**
   * Per-logical-segment digests in canonical order.
   *
   * `filename` is the primary representation's name; `filenames` lists every
   * physical representation that was verified for that one logical range.
   */
  segments: Array<{ filename: string; filenames: string[]; digest: SegmentDigest }>;
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

  // Grouping, duplicate/overlap detection and the canonical-pair rule all run on
  // the authoritative ranges before any content is read, so a conflicting store
  // is rejected as a whole.
  const archiveEntries = groupArchiveEntriesByRange(auditDir, expectedUid);

  const activeEntry = entries.find((entry) => entry.kind === 'ACTIVE') ?? null;

  const firstArchive = archiveEntries[0];
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
  // Each segment reports whether it carried the boundary; the walk ORs them.
  let trustedBoundaryMatched = options.trustedBoundary === undefined;
  const segments: Array<{ filename: string; filenames: string[]; digest: SegmentDigest }> = [];

  for (const entry of archiveEntries) {
    if (entry.sequenceStart !== expectedFirstSequence) {
      throw createCodedError(
        'AUDIT_CORRUPTION_DETECTED',
        `missing retained segment before ${entry.label}: expected sequence ${expectedFirstSequence}, segment starts at ${entry.sequenceStart}`,
      );
    }

    const representations = [entry.plain, entry.gzip].filter(
      (rep): rep is PhysicalArchiveRepresentation => rep !== undefined,
    );
    // The uncompressed representation is primary when it exists, purely so the
    // choice is deterministic; both are verified either way.
    const primary = representations[0];

    const shared = {
      expectedFirstSequence,
      expectedPreviousRecordHash,
      allowTornTail: false as const,
      declaredRange: {
        sequenceStart: entry.sequenceStart,
        sequenceEnd: entry.sequenceEnd,
      },
      trustedBoundary: options.trustedBoundary,
      onVerifiedRecord: options.onVerifiedRecord,
    };

    const secondary = representations[1] ?? null;

    // A dual representation is verified twice and consumed once. The secondary
    // is verified first, into throwaway state, so the shared lifecycle map and
    // recent-record cache advance exactly once per logical archive and never
    // twice for a crash pair. Its digest is then compared with the primary's:
    // a disagreement is corruption, and there is no "the valid copy wins" path.
    let secondaryDigest: SegmentDigest | null = null;
    if (secondary !== null) {
      secondaryDigest = await digestSegment(secondary.filePath, expectedUid, secondary.compressed, {
        ...shared,
        lifecycleMap: new Map(),
        recentRecords: [],
        // The throwaway pass proves the two representations agree; it reports no
        // facts, so a crash pair is never counted twice.
        onVerifiedRecord: undefined,
        label: secondary.filename,
      });
    }

    const digest = await digestSegment(primary.filePath, expectedUid, primary.compressed, {
      ...shared,
      lifecycleMap,
      recentRecords,
      label: primary.filename,
    });

    if (secondary !== null && secondaryDigest !== null) {
      assertRepresentationsEquivalent(primary, digest, secondary, secondaryDigest);
    }

    recordCount += digest.recordCount;
    terminalSequence = digest.terminalSequence;
    terminalRecordHash = digest.terminalRecordHash;
    expectedFirstSequence = digest.nextSequence;
    expectedPreviousRecordHash = digest.previousRecordHash;
    trustedBoundaryMatched ||= digest.trustedBoundaryMatched;
    // Both physical representations occupy disk, so both are budgeted.
    physicalPrimaryBytes += entry.physicalByteLength;
    segments.push({
      filename: primary.filename,
      filenames: representations.map((rep) => rep.filename),
      digest,
    });
  }

  let active: SegmentDigest | null = null;
  let status: 'VERIFIED' | 'RECOVERABLE_TORN_ACTIVE_TAIL' = 'VERIFIED';

  if (activeEntry !== null && activeEntry.physicalByteLength > 0) {
    active = await digestSegment(activeEntry.filePath, expectedUid, false, {
      expectedFirstSequence,
      expectedPreviousRecordHash,
      allowTornTail: true,
      trustedBoundary: options.trustedBoundary,
      onVerifiedRecord: options.onVerifiedRecord,
      lifecycleMap,
      recentRecords,
      label: activeEntry.filename,
    });

    recordCount += active.recordCount;
    terminalSequence = active.terminalSequence;
    terminalRecordHash = active.terminalRecordHash;
    nextSequence = active.nextSequence;
    previousRecordHash = active.previousRecordHash;
    trustedBoundaryMatched ||= active.trustedBoundaryMatched;
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
  /**
   * False until {@link ensureBootstrapped} has established the active segment's
   * operational state from durable bytes. No append and no rotation may run
   * before then, so a store recovered with a non-empty active segment can never
   * operate on a guessed boundary.
   */
  private bootstrapped = false;
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
    // Provisional only, and never used before `ensureBootstrapped` replaces it.
    // Deriving the active segment's origin from the chain cursor is correct
    // solely for a fresh, empty active segment; after Task-2 recovery the active
    // segment may already hold records 8..12 while the cursor reads 13, and a
    // rotation boundary of 13..12 would be nonsense.
    this.segmentStartSequence = storage.getCurrentSequence();
    this.segmentOpenedAtMs = this.now();
  }

  /**
   * Establishes the active segment's operational state from verified durable
   * bytes, once, before the first mutating operation.
   *
   * The constructor cannot do this: it would require streaming the active
   * segment, and a constructor that returns before the bytes have been read
   * would have to guess. Guessing is exactly the defect this replaces, so the
   * work is deferred to the first append or rotation and no operation may run
   * ahead of it.
   *
   * Bounded by construction: only the active segment is streamed, never the
   * retained archives, and never more than one record line is buffered.
   */
  private async ensureBootstrapped(): Promise<void> {
    if (this.bootstrapped) return;

    const capability = this.capability;
    const activeByteLength = capability.getActiveByteSize();

    if (activeByteLength === null || activeByteLength === 0) {
      // A fresh, empty active segment: the next record it receives is the one
      // the chain cursor names, and the interval clock starts now.
      this.segmentStartSequence = this.storage.getCurrentSequence();
      this.segmentOpenedAtMs = this.now();
      this.bootstrapped = true;
      return;
    }

    const scan = await this.readActiveSegmentState();

    // The durable bytes and the in-memory cursors must agree. If they do not,
    // one of them is wrong and there is no safe way to choose.
    const storageNextSequence = this.storage.getCurrentSequence();
    if (scan.terminalRecordHash !== this.storage.getLastRecordHash()) {
      throw createCodedError(
        'AUDIT_STORAGE_INVALID_STATE',
        'active segment terminal hash disagrees with the storage cursor',
      );
    }
    if (scan.recordCount > 0 && scan.terminalSequence + 1 !== storageNextSequence) {
      throw createCodedError(
        'AUDIT_STORAGE_INVALID_STATE',
        'active segment terminal sequence disagrees with the storage cursor',
      );
    }

    this.segmentStartSequence = scan.firstSequence ?? storageNextSequence;
    // The segment's age is measured from the timestamp of its first record, not
    // from the moment this process happened to start. Restarting a process does
    // not make an old segment young.
    this.segmentOpenedAtMs = scan.openedAtMs ?? this.now();
    this.bootstrapped = true;
  }

  /**
   * Streams the live active segment to recover its operational state.
   *
   * The read is bound to the authoritative active descriptor: the pathname is
   * opened with `O_NOFOLLOW`, put through descriptor authority validation, and
   * required to resolve to the same inode the writer is appending to. A
   * pathname swapped out from under the store therefore fails bootstrap rather
   * than producing a boundary taken from someone else's bytes.
   */
  private async readActiveSegmentState(): Promise<ScanCore> {
    const capability = this.capability;
    const activeFd = capability.getActiveFd();
    if (activeFd === null) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'no authoritative active descriptor');
    }
    const authoritative = fs.fstatSync(activeFd);

    let readFd: number | null = null;
    try {
      readFd = fs.openSync(capability.activePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      const opened = validateFileDescriptorAuthority(readFd, 0o600, capability.expectedUid);
      if (opened.dev !== authoritative.dev || opened.ino !== authoritative.ino) {
        throw createCodedError(
          'AUDIT_STORAGE_INVALID_STATE',
          'active segment pathname does not refer to the authoritative active descriptor',
        );
      }

      const readStream = fs.createReadStream(capability.activePath, {
        fd: readFd,
        autoClose: true,
        highWaterMark: 64 * 1024,
      });
      // Ownership of the descriptor transfers to the stream, which closes it
      // exactly once. Closing it here as well would be a double close.
      readFd = null;

      return await scanSegmentStream(
        readStream,
        {
          expectedFirstSequence: null,
          expectedPreviousRecordHash: null,
          allowTornTail: true,
          lifecycleMap: new Map(),
          recentRecords: [],
          label: ACTIVE_SEGMENT_FILENAME,
        },
        () => undefined,
      );
    } finally {
      if (readFd !== null) {
        try {
          fs.closeSync(readFd);
        } catch {
          // ignore
        }
      }
    }
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

      await this.ensureBootstrapped();

      // Fail-closed capacity preflight: a record known to exceed the remaining
      // budget is refused before any byte is written.
      assertAuditStorageCapacity(
        this.capability.auditDir,
        this.capability.expectedUid,
        this.capability.projectSerializedBytes(recordCandidate),
      );

      // Archive-count preflight. A store that already holds the ceiling number of
      // logical archives has no room to archive the segment this record would
      // join, so the append is refused now rather than accepted and then found
      // unrotatable. Nothing is written, no cursor moves, and no checkpoint is
      // consumed.
      assertArchiveCapacityAvailable(this.capability.auditDir, this.capability.expectedUid);

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
    return this.runExclusive(async () => {
      await this.ensureBootstrapped();
      return this.performRotation(reason);
    });
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

    // The archive ceiling is checked just as early, and from the same basis: a
    // store that already holds the maximum number of logical archives cannot
    // archive this segment at all, so it must not be sealed first and refused
    // afterwards. Checking before the seal is what keeps the sealer unconsumed.
    assertArchiveCapacityAvailable(capability.auditDir, capability.expectedUid);

    const sequenceEnd = this.storage.getCurrentSequence() - 1;
    if (sequenceEnd < this.segmentStartSequence) {
      throw createCodedError(
        'AUDIT_ROTATION_EMPTY_SEGMENT',
        'refusing to rotate a segment that contains no records',
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

    // The identity of the artifact about to be sealed is read from the
    // authoritative descriptor BEFORE the fault seam runs. Capturing it after
    // the seam would let the seam redefine what "the segment" means — a
    // replacement pathname, an in-place growth, or an in-place shrink would all
    // be adopted as the new truth and then faithfully archived. Captured here,
    // every one of them is a mismatch.
    const activeFd = capability.getActiveFd();
    if (activeFd === null) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'no authoritative active descriptor');
    }
    const activeStats = validateFileDescriptorAuthority(activeFd, 0o600, capability.expectedUid);
    const sourceIdentity: FileIdentity = {
      dev: activeStats.dev,
      ino: activeStats.ino,
      size: activeStats.size,
    };

    this.hooks?.beforePhysicalRotation?.();

    if (this.hooks?.failPhysicalRotation === true) {
      capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_FAILED', 'simulated physical rotation failure');
    }

    // ---- The one synchronous physical critical section.
    let sourcePath: string;
    try {
      const physical = capability.rotateActiveSegmentPhysical(plainFilename, sourceIdentity);
      sourcePath = physical.archivedPath;
    } catch (err) {
      capability.markRotationFailed();
      // The specific failure is preserved: an operator needs to know whether a
      // pathname was replaced, a symlink appeared, or the descriptor changed.
      const detail = err instanceof Error ? err.message : String(err);
      const code = (err as CodedError | undefined)?.code ?? 'AUDIT_ROTATION_FAILED';
      throw createCodedError(code, `physical rotation failed: ${detail}`, { cause: err });
    }

    // The archived artifact is the source segment, byte for byte: the physical
    // critical section proved both the descriptor and the installed name still
    // refer to the identity captured above, and that identity is carried forward
    // so compression and deletion can each re-prove it.
    const sourceByteLength = sourceIdentity.size;

    this.segmentStartSequence = this.storage.getCurrentSequence();
    this.segmentOpenedAtMs = this.now();

    const archivePath = await this.compressAndVerify({
      sourcePath,
      sourceIdentity,
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
      archiveCount: countLogicalArchives(capability.auditDir, capability.expectedUid),
    };

    this.lastRotation = result;
    return result;
  }

  /**
   * Streams the rotated segment into a gzip artifact, verifies it, and only then
   * removes the source.
   *
   * In order:
   *   1. establish the remaining physical budget and refuse to start without it;
   *   2. open the source by its authoritative descriptor and prove it is still
   *      the artifact the physical rotation produced;
   *   3. gzip the source into an exclusively-created scratch file, streamed,
   *      aborting the moment the compressed bytes would reach the budget;
   *   4. fsync and validate the scratch descriptor;
   *   5. install the `.gz` name without overwriting anything;
   *   6. verify the compressed artifact by streaming gunzip, hashing the
   *      decompressed bytes and replaying the whole chain contract;
   *   7. verify the source `.jsonl` the same way;
   *   8. require raw-byte and record-for-record equivalence;
   *   9. re-prove the source pathname, then unlink it, then fsync the directory.
   *
   * A failure anywhere before step 9 leaves the source `.jsonl` in place, so the
   * store never loses a segment to a compression fault. The scratch file is the
   * only thing a failure removes, and only because it was never installed as
   * evidence. Nothing else is ever deleted to reclaim capacity.
   */
  private async compressAndVerify(params: {
    sourcePath: string;
    sourceIdentity: FileIdentity;
    plainFilename: string;
    compressedFilename: string;
    expectedUid: number;
    auditDir: string;
    boundary: RotationSealBoundary;
  }): Promise<string> {
    const { sourcePath, sourceIdentity, compressedFilename, expectedUid, auditDir } = params;
    const archivePath = path.join(auditDir, compressedFilename);
    const scratchPath = path.join(auditDir, `rotation-${randomUUID()}.tmp`);

    // The transition holds both representations at once, so its peak is the
    // current usage plus every compressed byte written. The budget is measured
    // against that peak, not against the finished size.
    const usedAtStart = scanAuditStorePhysicalBytes(auditDir, expectedUid);
    if (usedAtStart >= TOTAL_AUDIT_BUDGET_BYTES) {
      this.capability.markRotationFailed();
      throw createCodedError(
        'AUDIT_STORAGE_EXHAUSTED',
        `audit storage budget exhausted before compression: ${usedAtStart} bytes retained of ${TOTAL_AUDIT_BUDGET_BYTES}`,
      );
    }

    let compressedBytesWritten = 0;
    const budgetGuard = new Transform({
      transform: (chunk: Buffer, _encoding, callback) => {
        compressedBytesWritten += chunk.length;
        if (usedAtStart + compressedBytesWritten >= TOTAL_AUDIT_BUDGET_BYTES) {
          callback(
            createCodedError(
              'AUDIT_STORAGE_EXHAUSTED',
              `compression would reach the audit storage budget: ${usedAtStart} bytes retained plus ${compressedBytesWritten} compressed bytes of ${TOTAL_AUDIT_BUDGET_BYTES}`,
            ),
          );
          return;
        }
        callback(null, chunk);
      },
    });

    if (this.hooks?.failCompressionCreate === true) {
      this.capability.markRotationFailed();
      throw createCodedError('AUDIT_ROTATION_COMPRESSION_FAILED', 'simulated gzip create failure');
    }

    let scratchFd: number | null = null;
    let sourceFd: number | null = null;
    try {
      scratchFd = fs.openSync(
        scratchPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );

      // Descriptor authority, not pathname trust: the source is opened with
      // `O_NOFOLLOW`, validated, and required to be the exact inode and size the
      // physical rotation finalized.
      try {
        sourceFd = fs.openSync(sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      } catch (err: unknown) {
        if ((err as { code?: string })?.code === 'ELOOP') {
          throw createCodedError('SYMLINK_DETECTED', 'rotated segment is a symbolic link');
        }
        throw err;
      }
      const sourceStats = validateFileDescriptorAuthority(sourceFd, 0o600, expectedUid);
      if (
        sourceStats.dev !== sourceIdentity.dev ||
        sourceStats.ino !== sourceIdentity.ino ||
        sourceStats.size !== sourceIdentity.size
      ) {
        throw createCodedError(
          'AUDIT_ROTATION_FAILED',
          'rotated source no longer matches the finalized active segment',
        );
      }

      const sourceStream = fs.createReadStream(sourcePath, {
        fd: sourceFd,
        autoClose: true,
        highWaterMark: 64 * 1024,
      });
      // Ownership of the descriptor transfers to the stream.
      sourceFd = null;

      await pipeline(
        sourceStream,
        createGzip({ level: 6 }),
        budgetGuard,
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
        sourceIdentity,
        plainFilename: params.plainFilename,
        expectedUid,
        boundary: params.boundary,
      });

      this.hooks?.beforeSourceRemoval?.();

      // Removal is identity-checked, never name-checked. The pathname must still
      // resolve to the very artifact that was compressed; a replacement left in
      // its place is neither deleted nor mistaken for the source.
      assertPathIdentity(sourcePath, sourceIdentity, 'plain rotated source');

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
      if (sourceFd !== null) {
        try {
          fs.closeSync(sourceFd);
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
    sourceIdentity: FileIdentity;
    plainFilename: string;
    expectedUid: number;
    boundary: RotationSealBoundary;
  }): Promise<void> {
    const {
      archivePath,
      compressedFilename,
      sourcePath,
      sourceIdentity,
      plainFilename,
      expectedUid,
      boundary,
    } = params;

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

    // The plain source is verified against the identity the physical rotation
    // finalized, so a pathname swapped between rotation and verification is
    // rejected instead of being certified as the compressed artifact's twin.
    const plainDigest = await digestSegment(
      sourcePath,
      expectedUid,
      false,
      {
        ...shared,
        lifecycleMap: new Map(),
        label: plainFilename,
      },
      sourceIdentity,
    );

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
