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
 *   Task 1  `validateAuditDirectory`, `loadStoreMetadataFile`    store identity
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

import type { AuditStoreMetadataV1, PersistentAuditRecordV1 } from '@cesspace-arc/protocol';

import {
  ACTIVE_SEGMENT_FILENAME,
  getProcessUid,
  createCodedError,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  parseAndValidateRecordLineV1,
} from './storage.js';
import { loadStoreMetadataFile } from './metadata.js';
import {
  listLogicalArchiveInventory,
  verifyRetainedPrimaryHistory,
  type LogicalArchiveEntry,
} from './rotation.js';
import {
  CHECKPOINT_FILENAME,
  verifyCheckpointHistoryWithObserver,
  type AuditCheckpointV1,
} from './checkpoint.js';
import { ANCHOR_RECEIPT_FILENAME, ANCHOR_SPOOL_DIRNAME } from './internal/anchor-constants.js';
import { loadEd25519TrustRootFile } from './internal/key-authority.js';
import {
  assertDescriptorPinnedTraversalAvailable,
  pinnedChildPath,
} from './internal/anchor-paths.js';
import {
  parseAndValidateAnchorReceiptLineV1,
  verifyAnchorReceiptSignature,
  type AnchorReceiptV1,
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
function openArtifactFd(filePath: string, label: string, expectedUid: number): number {
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
interface ArtifactIdentity {
  dev: number;
  ino: number;
  size: number;
}

function captureIdentity(fd: number): ArtifactIdentity {
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
async function* streamSegmentRecords(
  source: RetainedSegmentSource,
  expectedUid: number,
): AsyncGenerator<PersistentAuditRecordV1> {
  const fd = openArtifactFd(source.filePath, source.label, expectedUid);
  let stream: NodeJS.ReadableStream = fs.createReadStream(null as unknown as fs.PathLike, {
    fd,
    autoClose: true,
  });
  if (source.compressed) {
    stream = stream.pipe(zlib.createGunzip());
  }

  const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (line.length === 0) continue;
      yield parseAndValidateRecordLineV1(`${line}\n`).record;
    }
  } finally {
    lines.close();
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
  options: { from?: number; to?: number; expectedUid?: number } = {},
): AsyncGenerator<PersistentAuditRecordV1> {
  const { from = 1, to = Number.MAX_SAFE_INTEGER, expectedUid = getProcessUid() } = options;
  for (const source of sources) {
    if (source.sequenceEnd < from) continue;
    if (source.sequenceStart > to) return;
    for await (const record of streamSegmentRecords(source, expectedUid)) {
      const sequence = record.sequenceNumber;
      if (sequence < from) continue;
      if (sequence > to) return;
      yield record;
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Anchor receipt ledger — offline verification
 * -------------------------------------------------------------------------- */

/** The outcome of checking the Tier-3 receipt ledger. */
export type OfflineAnchorOutcome =
  | { configured: false }
  | {
      configured: true;
      receiptCount: number;
      publicKeyFingerprint: string;
      /** Checkpoint hashes that carry at least one verified receipt. */
      anchoredCheckpointHashes: string[];
    };

function lstatOrNull(target: string): fs.Stats | null {
  try {
    return fs.lstatSync(target);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw cause;
  }
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
async function verifyAnchorLedgerOffline(options: {
  directory: string;
  metadata: AuditStoreMetadataV1;
  anchorReceiptPublicKeyPath: string | undefined;
  checkpointsInOrder: readonly AuditCheckpointV1[];
  expectedUid: number;
}): Promise<OfflineAnchorOutcome> {
  const { directory, metadata, checkpointsInOrder, expectedUid } = options;

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
    return { configured: false };
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
      };
    }
    return await readAndVerifyLedger({
      ledgerPath,
      metadata,
      trustRoot,
      checkpointsInOrder,
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
  checkpointsInOrder: readonly AuditCheckpointV1[];
  expectedUid: number;
}): Promise<OfflineAnchorOutcome> {
  const { ledgerPath, metadata, trustRoot, checkpointsInOrder, expectedUid } = options;
  const fd = openArtifactFd(ledgerPath, ANCHOR_RECEIPT_FILENAME, expectedUid);
  const startIdentity = captureIdentity(fd);
  const anchored = new Set<string>();
  let receiptCount = 0;

  const stream = fs.createReadStream(null as unknown as fs.PathLike, { fd, autoClose: false });
  const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });

  /** Reads the next receipt, or null at end of ledger. */
  const iterator = lines[Symbol.asyncIterator]();
  const readNext = async (): Promise<AnchorReceiptV1 | null> => {
    for (;;) {
      const step = await iterator.next();
      if (step.done === true) return null;
      const line = step.value;
      if (line.length === 0) continue;
      const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
      assertReceiptBindings(receipt, {
        metadata,
        publicKey: trustRoot.publicKey,
        anchorKeyFingerprint: trustRoot.fingerprint,
      });
      receiptCount += 1;
      return receipt;
    }
  };

  let head: AnchorReceiptV1 | null;
  try {
    head = await readNext();
    for (const checkpoint of checkpointsInOrder) {
      if (head !== null && head.checkpointHash === checkpoint.checkpointHash) {
        anchored.add(checkpoint.checkpointHash);
        head = await readNext();
      }
    }
  } finally {
    lines.close();
  }

  // Anything left at the head after the walk is a receipt the authenticated
  // primary evidence never produced.
  if (head !== null) {
    throw createCodedError(
      'ANCHOR_ORPHAN_RECEIPT',
      'anchor receipt references a checkpoint that the verified checkpoint history never produced',
    );
  }

  // The ledger must still be the artifact whose bytes were read.
  const finalStats = fs.fstatSync(fd);
  const consumingStream = stream as unknown as { bytesRead: number };
  if (
    Number(finalStats.dev) !== startIdentity.dev ||
    Number(finalStats.ino) !== startIdentity.ino ||
    Number(finalStats.size) !== startIdentity.size ||
    consumingStream.bytesRead !== startIdentity.size
  ) {
    fs.closeSync(fd);
    throw createCodedError(
      'ANCHOR_RECEIPT_FILE_RACE',
      `${ANCHOR_RECEIPT_FILENAME} changed while its history was being verified`,
    );
  }
  fs.closeSync(fd);

  return {
    configured: true,
    receiptCount,
    publicKeyFingerprint: trustRoot.fingerprint,
    anchoredCheckpointHashes: [...anchored].sort(),
  };
}

/**
 * The three bindings every receipt must satisfy, matching the production
 * engine's `assertReceiptBinding` rule-for-rule and in the same order.
 */
function assertReceiptBindings(
  receipt: AnchorReceiptV1,
  context: {
    metadata: AuditStoreMetadataV1;
    publicKey: crypto.KeyObject;
    anchorKeyFingerprint: string;
  },
): void {
  if (receipt.storeId !== context.metadata.storeId) {
    throw createCodedError(
      'ANCHOR_RECEIPT_BINDING_INVALID',
      'receipt storeId does not match audit-store.json',
    );
  }
  if (receipt.anchorKeyFingerprint !== context.anchorKeyFingerprint) {
    throw createCodedError(
      'ANCHOR_RECEIPT_KEY_MISMATCH',
      'receipt anchorKeyFingerprint does not match the pinned anchor trust root',
    );
  }
  if (!verifyAnchorReceiptSignature(receipt, context.publicKey)) {
    throw createCodedError(
      'ANCHOR_RECEIPT_SIGNATURE_INVALID',
      'receipt signature does not verify against the pinned anchor trust root',
    );
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
  const metadata = loadStoreMetadataFile(options.directory, expectedUid);

  const primary = await verifyRetainedPrimaryHistory(options.directory, expectedUid);
  if (primary.status !== 'VERIFIED') {
    throw createCodedError(
      'AUDIT_VERIFICATION_FAILED',
      `primary history is not verified (${primary.status})`,
    );
  }

  // The authenticated checkpoint walk. The observer fires once per checkpoint,
  // in order, only after every Task-4 check on that checkpoint has passed, so
  // the collected list is authenticated evidence rather than mere file order.
  const checkpointsInOrder: AuditCheckpointV1[] = [];
  const checkpoints = await verifyCheckpointHistoryWithObserver(
    {
      directory: options.directory,
      publicKeyPath: options.checkpointPublicKeyPath,
      workspacePaths,
    },
    (checkpoint) => {
      checkpointsInOrder.push(checkpoint);
    },
  );

  const anchor = await verifyAnchorLedgerOffline({
    directory: options.directory,
    metadata,
    anchorReceiptPublicKeyPath: options.anchorReceiptPublicKeyPath,
    checkpointsInOrder,
    expectedUid,
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
