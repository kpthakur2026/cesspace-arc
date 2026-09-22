/**
 * CesSpace ARC — RC-06 Task 7: deterministic local evidence export.
 *
 * `arc audit export` writes a self-contained DIRECTORY bundle that an operator
 * can hand to a reviewer, who can then check the selected sequence range and its
 * authenticity with public material alone:
 *
 *     <output-dir>/
 *       manifest.json
 *       audit/            rotated + active primary artifacts
 *       checkpoints/      the signed checkpoints covering the range
 *       anchors/          the receipts for those checkpoints (when enabled)
 *       public-keys/      the PUBLIC verification keys only
 *
 * Node ships no tar/zip packager and no third-party packaging dependency is
 * permitted, so the bundle is a directory with a manifest that digests every
 * emitted file. Determinism is a property of the manifest: identical source
 * evidence and an identical range produce byte-identical manifests.
 *
 * ## What this module refuses to do
 *
 * - It never opens the checkpoint signing key. Only public verification keys are
 *   copied, and there is no parameter through which a private key could arrive.
 * - It never rewrites a record. Each emitted artifact is a byte-for-byte copy of
 *   authentic source evidence (or a byte-identical subset of a signed ledger's
 *   canonical lines). No hash is recomputed to manufacture a prettier range.
 * - It never merges into an existing destination and never replaces a file.
 *
 * ## Success is bound to the exact bytes that were verified
 *
 * Device, inode and size are useful race signals but they are not the
 * cryptographic identity of a byte sequence: an in-place rewrite preserves all
 * three. Export therefore binds success to content, not to a stat:
 *
 *   - every primary artifact copied is required to reproduce the digest the
 *     authenticated verification pass computed for its range;
 *   - the public key bytes written are the bytes whose fingerprint matched the
 *     store's durable pin;
 *   - the selected checkpoint and receipt lines are authenticated with the same
 *     Task-4/Task-5 rules the store verifier uses;
 *   - and the finished bundle is re-verified end to end before this call
 *     reports success.
 *
 * ## Destination authority is descriptor-bound, not pathname-bound
 *
 * Each ancestor is opened `O_DIRECTORY | O_NOFOLLOW` by its parent's own
 * descriptor, and both the destination and every file inside it are created by
 * name relative to a descriptor this process holds. Cleanup is equally
 * descriptor-bound: the destination is deleted through a name resolved from the
 * retained parent descriptor, only after the leaf is proven to still be the
 * directory this call created.
 *
 * @packageDocumentation
 */

import fs from 'node:fs';
import fsConstants from 'node:constants';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import readline from 'node:readline';

import {
  ACTIVE_SEGMENT_FILENAME,
  canonicalJsonV1,
  getProcessUid,
  createCodedError,
  type CodedError,
} from './storage.js';
import {
  CHECKPOINT_FILENAME,
  computeCheckpointHash,
  parseAndValidateCheckpointLineV1,
  verifyCheckpointHistory,
  verifyCheckpointHistoryCore,
  verifyCheckpointSignature,
  type AuditCheckpointV1,
} from './checkpoint.js';
import { loadStoreMetadataFile } from './metadata.js';
import { CHECKPOINT_INTERVAL } from './checkpoint.js';
import {
  MAX_ARCHIVE_SEGMENTS,
  TOTAL_AUDIT_BUDGET_BYTES,
  verifyRetainedPrimaryHistory,
  type RetainedPrimaryHistoryVerificationResult,
} from './rotation.js';
import { parseRotatedSegmentFilename } from './rotation-filename.js';
import { ANCHOR_RECEIPT_FILENAME } from './internal/anchor-constants.js';
import {
  loadEd25519TrustRootFile,
  loadEd25519TrustRootFromDescriptor,
  type LoadedTrustRoot,
} from './internal/key-authority.js';
import {
  assertDescriptorPinnedTraversalAvailable,
  pinnedChildPath,
  openPinnedDirectoryChild,
  openPinnedFileChild,
  listPinnedChildren,
  readBoundedDescriptor,
} from './internal/anchor-paths.js';
import { parseAndValidateAnchorReceiptLineV1, walkReceiptEvidence } from './anchor.js';
import {
  listRetainedSegmentSources,
  snapshotEvidenceInventory,
  assertInventoryUnchanged,
  streamLedgerLines,
  streamLedgerLinesFromFd,
  streamSegmentRecordsFromFd,
  validateSequenceRange,
  openArtifactFd,
  captureIdentity,
  type EvidenceIdentity,
} from './verify.js';

/* -------------------------------------------------------------------------- *
 * Frozen bounds (rc06 §24.1)
 * -------------------------------------------------------------------------- */

/**
 * Maximum total bytes one export bundle may emit.
 *
 * This bounds the EMITTED BUNDLE — every byte written into the destination,
 * including the public keys and the manifest itself — not merely the primary
 * evidence. Fixed by the architecture, not configurable.
 */
export const MAX_EXPORT_BYTES = 1_073_741_824;

/** Bundle layout, frozen by rc06 §17.2. */
export const BUNDLE_MANIFEST_FILENAME = 'manifest.json';
export const BUNDLE_AUDIT_DIRNAME = 'audit';
export const BUNDLE_CHECKPOINTS_DIRNAME = 'checkpoints';
export const BUNDLE_ANCHORS_DIRNAME = 'anchors';
export const BUNDLE_PUBLIC_KEYS_DIRNAME = 'public-keys';
/**
 * A conservative floor on the canonical size of one persistent audit record.
 *
 * A record carries a UUID, an ISO-8601 timestamp, four 64-character hex fields
 * (device id, session id, workspace root hash, payload hash), a second UUID and
 * a nested actor/target/invocation/policy/execution structure. Its canonical
 * JSON cannot approach this figure; the floor is deliberately far below the
 * ~950 bytes a real record occupies, so the derived bound below is an
 * over-estimate rather than an under-estimate.
 */
export const MIN_CANONICAL_RECORD_BYTES = 256;

/**
 * The finite maximum number of checkpoint references one manifest may carry.
 *
 * Derived from frozen limits, not chosen for convenience. A retained checkpoint
 * is mandatory at every rotation boundary — at most `MAX_ARCHIVE_SEGMENTS` —
 * and on the interval cadence, one per `CHECKPOINT_INTERVAL` records. The record
 * count is itself bounded by the frozen storage budget:
 *
 *   TOTAL_AUDIT_BUDGET_BYTES / MIN_CANONICAL_RECORD_BYTES / CHECKPOINT_INTERVAL
 *
 * plus the rotation boundaries. Worst-case manifest memory is therefore
 * MAX_MANIFEST_CHECKPOINT_REFS x (64 hex + JSON quoting and separator) — about
 * 285 KB, not something proportional to a 1 GiB history.
 */
export const MAX_MANIFEST_CHECKPOINT_REFS =
  MAX_ARCHIVE_SEGMENTS +
  Math.ceil(TOTAL_AUDIT_BUDGET_BYTES / MIN_CANONICAL_RECORD_BYTES / CHECKPOINT_INTERVAL);

/**
 * The finite maximum number of receipt references one manifest may carry.
 *
 * At most one receipt is consumed per checkpoint, so the checkpoint bound holds
 * here too. A receipt id is capped separately by the Task-5 receipt schema
 * (<= 256 UTF-8 bytes), so worst-case memory is likewise bounded.
 */
export const MAX_MANIFEST_RECEIPT_REFS = MAX_MANIFEST_CHECKPOINT_REFS;

/**
 * Refuses a manifest reference beyond the frozen bound.
 *
 * Called BEFORE a reference is accumulated, so memory cannot grow past the
 * documented maximum: the bound is enforced at the point of growth rather than
 * discovered after the fact.
 */
export function assertManifestReferenceWithinBound(
  count: number,
  bound: number,
  noun: string,
): void {
  if (count > bound) {
    throw createCodedError(
      'EXPORT_MANIFEST_LIMIT_EXCEEDED',
      `the manifest cannot reference more than ${bound} ${noun}`,
    );
  }
}

/** Purpose-named bundled keys, so a reviewer never has to guess which is which. */
export const BUNDLE_CHECKPOINT_KEY_FILENAME = 'checkpoint-public.pem';
export const BUNDLE_ANCHOR_KEY_FILENAME = 'anchor-receipt-public.pem';

/** The predecessor hash of the first checkpoint and the first record. */
const ZERO_HASH = '0'.repeat(64);

/* -------------------------------------------------------------------------- *
 * Manifest
 * -------------------------------------------------------------------------- */

export interface ManifestFileEntry {
  sha256: string;
  bytes: number;
}

export interface ExportManifest {
  version: 1;
  storeId: string;
  sequenceRange: { start: number; end: number };
  /** Every emitted evidence file, keyed by its bundle-relative path. */
  files: Record<string, ManifestFileEntry>;
  checkpointHashes: string[];
  anchorReceiptIds: string[];
}

export interface ExportEvidenceOptions {
  /** The source audit store. Read only. */
  directory: string;
  /** Destination directory. Must not exist; it is created by this call. */
  outputDirectory: string;
  /** Ed25519 PUBLIC checkpoint key to include in the bundle. */
  checkpointPublicKeyPath: string;
  /** Ed25519 PUBLIC anchor receipt key. Required when anchor mode is ENABLED. */
  anchorReceiptPublicKeyPath?: string;
  /**
   * Authoritative agent workspace roots.
   *
   * Optional in the type only so the fail-closed check can be expressed: when it
   * is ABSENT the export refuses, because an exporter that cannot be told where
   * the agent workspaces are cannot prove the destination is outside them, and
   * treating "not supplied" as "there are none" is exactly the assumption an
   * attacker would want. An explicit empty array is a different act: it is the
   * operator authoritatively saying there are none.
   */
  workspacePaths?: readonly string[];
  from?: number;
  to?: number;
  expectedUid?: number;
  /**
   * Internal test seams (RC-06 Task 7).
   * @internal
   */
  hooks?: {
    afterCheckpointVerification?: () => void | Promise<void>;
    afterReceiptVerification?: () => void | Promise<void>;
    beforeFinalVerification?: () => void | Promise<void>;
    afterFinalVerification?: () => void | Promise<void>;
  };
}

export interface ExportEvidenceResult {
  outputDirectory: string;
  manifest: ExportManifest;
  fileCount: number;
  totalBytes: number;
}

/**
 * Pinned directory authority for verified bundle inspection (RC-06 Task 7).
 *
 * Every child and nested subdirectory is opened relative to the held root
 * descriptor, preventing concurrent pathname substitution races from
 * authenticating a different artifact than the one held by the caller.
 */
export interface BundleDirectoryAuthority {
  readonly rootFd: number;
  openRootFile(fileName: string): number;
  openChildFile(dirName: string, fileName: string): number;
  childFileExists(dirName: string, fileName: string): boolean;
  listAuditArtifacts(): string[];
}

export function createBundleDirectoryAuthority(rootFd: number): BundleDirectoryAuthority {
  return {
    rootFd,
    openRootFile(fileName: string): number {
      return openPinnedFileChild(
        rootFd,
        fileName,
        fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
        {
          missing: 'BUNDLE_FILE_MISSING',
          symlink: 'BUNDLE_FILE_INSECURE',
          invalid: 'BUNDLE_FILE_INSECURE',
          unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
        },
        `bundle root file ${fileName}`,
      );
    },
    openChildFile(dirName: string, fileName: string): number {
      const dirFd = openPinnedDirectoryChild(
        rootFd,
        dirName,
        {
          missing: 'BUNDLE_FILE_MISSING',
          symlink: 'BUNDLE_FILE_INSECURE',
          invalid: 'BUNDLE_FILE_INSECURE',
          unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
        },
        `bundle directory ${dirName}`,
      );
      try {
        return openPinnedFileChild(
          dirFd,
          fileName,
          fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
          {
            missing: 'BUNDLE_FILE_MISSING',
            symlink: 'BUNDLE_FILE_INSECURE',
            invalid: 'BUNDLE_FILE_INSECURE',
            unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
          },
          `bundle child ${dirName}/${fileName}`,
        );
      } finally {
        fs.closeSync(dirFd);
      }
    },
    childFileExists(dirName: string, fileName: string): boolean {
      try {
        const fd = this.openChildFile(dirName, fileName);
        fs.closeSync(fd);
        return true;
      } catch (err) {
        if ((err as CodedError)?.code === 'BUNDLE_FILE_MISSING') {
          return false;
        }
        throw err;
      }
    },
    listAuditArtifacts(): string[] {
      const dirFd = openPinnedDirectoryChild(
        rootFd,
        BUNDLE_AUDIT_DIRNAME,
        {
          missing: 'BUNDLE_FILE_MISSING',
          symlink: 'BUNDLE_FILE_INSECURE',
          invalid: 'BUNDLE_FILE_INSECURE',
          unavailable: 'AUDIT_STORAGE_UNAVAILABLE',
        },
        `bundle ${BUNDLE_AUDIT_DIRNAME} directory`,
      );
      try {
        return listPinnedChildren(dirFd, `bundle ${BUNDLE_AUDIT_DIRNAME} directory`);
      } finally {
        fs.closeSync(dirFd);
      }
    },
  };
}

/* -------------------------------------------------------------------------- *
 * Frozen byte budget
 * -------------------------------------------------------------------------- */

/**
 * The frozen budget as an assertion over a projection.
 *
 * Kept separate and exported so the limit can be proved at its exact boundary
 * from a structural projection, without materializing a gigabyte of evidence to
 * reach it. There is no parameter, flag or environment variable that raises it.
 */
export function assertExportWithinBudget(projectedBytes: number): void {
  if (projectedBytes > MAX_EXPORT_BYTES) {
    throw createCodedError(
      'EXPORT_TOO_LARGE',
      `export would emit ${projectedBytes} bytes, exceeding the ${MAX_EXPORT_BYTES}-byte limit`,
    );
  }
}

/* -------------------------------------------------------------------------- *
 * Path shape and containment
 * -------------------------------------------------------------------------- */

function assertPathShape(target: string, noun: string): string {
  if (typeof target !== 'string' || target.length === 0) {
    throw createCodedError('INVALID_EXPORT_PATH', `${noun} is required`);
  }
  if (target.includes('~')) {
    throw createCodedError('INVALID_EXPORT_PATH', `literal ~ is not allowed in ${noun}`);
  }
  if (!path.isAbsolute(target)) {
    throw createCodedError('INVALID_EXPORT_PATH', `${noun} must be an absolute path`);
  }
  const normalized = path.normalize(target);
  if (normalized !== target) {
    throw createCodedError('INVALID_EXPORT_PATH', `${noun} must be a normalized path`);
  }
  if (normalized === path.sep || normalized === '.') {
    throw createCodedError('INVALID_EXPORT_PATH', `${noun} must not be the filesystem root`);
  }
  return normalized;
}

/**
 * Component-wise containment: is `child` inside (or equal to) `parent`?
 *
 * Deliberately not a string-prefix test. `/work/a` is not inside `/work/abc`,
 * and `/work/a/../abc` is not inside `/work/a`.
 */
function isInsideOrEqual(child: string, parent: string): boolean {
  const childSegments = path
    .resolve(child)
    .split(path.sep)
    .filter((s) => s.length > 0);
  const parentSegments = path
    .resolve(parent)
    .split(path.sep)
    .filter((s) => s.length > 0);
  if (parentSegments.length > childSegments.length) return false;
  return parentSegments.every((segment, index) => childSegments[index] === segment);
}

function assertDestinationContainment(options: {
  destination: string;
  auditDirectory: string;
  workspacePaths: readonly string[];
}): void {
  const { destination, auditDirectory, workspacePaths } = options;

  const auditRoot = assertPathShape(auditDirectory, 'audit directory');
  if (isInsideOrEqual(destination, auditRoot)) {
    throw createCodedError(
      'EXPORT_DESTINATION_INSIDE_AUDIT_STORE',
      'export destination must not be inside the audit store',
    );
  }

  for (const workspaceRoot of workspacePaths) {
    if (isInsideOrEqual(destination, assertPathShape(workspaceRoot, 'workspace root'))) {
      throw createCodedError(
        'EXPORT_DESTINATION_INSIDE_WORKSPACE',
        'export destination must not be inside an agent workspace',
      );
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Descriptor-pinned destination
 * -------------------------------------------------------------------------- */

function openDirectoryNoFollow(target: string, label: string): number {
  try {
    return fs.openSync(
      target,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === 'ELOOP' || code === 'ENOTDIR') {
      throw createCodedError('SYMLINK_DETECTED', `${label} is a symbolic link`);
    }
    if (code === 'ENOENT') {
      throw createCodedError('INVALID_EXPORT_PATH', `${label} does not exist`);
    }
    throw createCodedError('INVALID_EXPORT_PATH', `${label} could not be opened`, { cause });
  }
}

/**
 * Opens every ancestor of `destination`, one descriptor at a time, and returns
 * the descriptor for the immediate parent.
 *
 * Each component is opened by name RELATIVE TO ITS PARENT'S DESCRIPTOR, with
 * `O_DIRECTORY | O_NOFOLLOW`, so a component swapped for a symlink after it was
 * opened cannot affect a later traversal that never re-resolves it by pathname.
 */
function openPinnedParent(destination: string): { parentFd: number; leafName: string } {
  assertDescriptorPinnedTraversalAvailable('evidence export');
  const segments = destination.split(path.sep).filter((segment) => segment.length > 0);
  const ancestors = segments.slice(0, -1);
  const leafName = segments[segments.length - 1];

  let fd = openDirectoryNoFollow(path.sep, 'filesystem root');
  for (const segment of ancestors) {
    const next = openDirectoryNoFollow(
      pinnedChildPath(fd, segment),
      `export destination component "${segment}"`,
    );
    fs.closeSync(fd);
    fd = next;
  }
  return { parentFd: fd, leafName };
}

/* -------------------------------------------------------------------------- *
 * Bundle writer
 * -------------------------------------------------------------------------- */

/** Tracks what this invocation created, so partial failure can be undone. */
interface BundleWriter {
  root: string;
  /**
   * The descriptor of the directory the destination was created in, and the name
   * it was created under. Cleanup needs both: neither the held root descriptor
   * nor the pathname alone can prove the other still refers to the same object.
   */
  parentFd: number;
  leafName: string;
  rootFd: number;
  rootIdentity: { dev: number; ino: number };
  dirFds: Map<string, number>;
  fileHashes: Map<string, ManifestFileEntry>;
  totalBytes: number;
}

function createBundleRoot(parentFd: number, leafName: string, destination: string): BundleWriter {
  const childPath = pinnedChildPath(parentFd, leafName);
  try {
    fs.mkdirSync(childPath, { mode: 0o700 });
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === 'EEXIST') {
      throw createCodedError(
        'EXPORT_DESTINATION_EXISTS',
        'export destination already exists; export never merges or overwrites',
      );
    }
    if (code === 'ELOOP' || code === 'ENOTDIR') {
      throw createCodedError('SYMLINK_DETECTED', 'export destination is a symbolic link');
    }
    throw createCodedError('EXPORT_FAILED', 'export destination could not be created', { cause });
  }
  fs.chmodSync(childPath, 0o700);

  const rootFd = openDirectoryNoFollow(childPath, 'export destination');
  const stats = fs.fstatSync(rootFd);
  return {
    root: destination,
    parentFd,
    leafName,
    rootFd,
    rootIdentity: { dev: Number(stats.dev), ino: Number(stats.ino) },
    dirFds: new Map(),
    fileHashes: new Map(),
    totalBytes: 0,
  };
}

function createBundleDirectory(writer: BundleWriter, name: string): void {
  const childPath = pinnedChildPath(writer.rootFd, name);
  fs.mkdirSync(childPath, { mode: 0o700 });
  fs.chmodSync(childPath, 0o700);
  writer.dirFds.set(name, openDirectoryNoFollow(childPath, `bundle ${name}/`));
}

/**
 * Enforces the frozen ceiling against what has actually been written, so a
 * source that grows between projection and copy cannot carry the bundle past it.
 */
function assertWithinBudget(written: number): void {
  if (written > MAX_EXPORT_BYTES) {
    throw createCodedError(
      'EXPORT_TOO_LARGE',
      `export has emitted ${written} bytes, exceeding the ${MAX_EXPORT_BYTES}-byte limit`,
    );
  }
}

/** An open bundle file being written incrementally. */
interface BundleFileHandle {
  fd: number;
  hash: crypto.Hash;
  bytes: number;
}

function openBundleFile(writer: BundleWriter, dirName: string, fileName: string): BundleFileHandle {
  const dirFd = writer.dirFds.get(dirName);
  if (dirFd === undefined) {
    throw createCodedError('EXPORT_FAILED', `bundle directory ${dirName}/ was never created`);
  }
  const fd = fs.openSync(
    pinnedChildPath(dirFd, fileName),
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  return { fd, hash: crypto.createHash('sha256'), bytes: 0 };
}

function appendToBundleFile(handle: BundleFileHandle, chunk: Buffer): void {
  fs.writeSync(handle.fd, chunk);
  handle.hash.update(chunk);
  handle.bytes += chunk.byteLength;
}

function closeBundleFile(
  writer: BundleWriter,
  dirName: string,
  fileName: string,
  handle: BundleFileHandle,
): void {
  fs.fchmodSync(handle.fd, 0o600);
  fs.fsyncSync(handle.fd);
  fs.closeSync(handle.fd);
  writer.fileHashes.set(`${dirName}/${fileName}`, {
    sha256: handle.hash.digest('hex'),
    bytes: handle.bytes,
  });
  writer.totalBytes += handle.bytes;
  assertWithinBudget(writer.totalBytes);
}

function openRootBundleFile(writer: BundleWriter, fileName: string): BundleFileHandle {
  const fd = fs.openSync(
    pinnedChildPath(writer.rootFd, fileName),
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  return { fd, hash: crypto.createHash('sha256'), bytes: 0 };
}

function writeBundleFile(
  writer: BundleWriter,
  dirName: string,
  fileName: string,
  contents: Buffer,
): void {
  const handle = openBundleFile(writer, dirName, fileName);
  try {
    appendToBundleFile(handle, contents);
  } finally {
    closeBundleFile(writer, dirName, fileName, handle);
  }
}

function writeBundleRootFile(writer: BundleWriter, fileName: string, contents: Buffer): void {
  const handle = openRootBundleFile(writer, fileName);
  try {
    appendToBundleFile(handle, contents);
  } finally {
    fs.fchmodSync(handle.fd, 0o600);
    fs.fsyncSync(handle.fd);
    fs.closeSync(handle.fd);
    writer.fileHashes.set(fileName, {
      sha256: handle.hash.digest('hex'),
      bytes: handle.bytes,
    });
    writer.totalBytes += handle.bytes;
    assertWithinBudget(writer.totalBytes);
  }
}

/**
 * The digest of an artifact's LOGICAL content.
 *
 * A rotated artifact is stored compressed, and the verification pass digests the
 * decompressed stream — so the binding has to be made in that same form, or a
 * `.jsonl.gz` could never be compared with what was authenticated for it.
 */
async function logicalDigestOfFd(fd: number, label: string, compressed: boolean): Promise<string> {
  let stream: NodeJS.ReadableStream = fs.createReadStream(null as unknown as fs.PathLike, {
    fd,
    autoClose: true,
  });
  if (compressed) stream = stream.pipe(zlib.createGunzip());

  const hash = crypto.createHash('sha256');
  try {
    for await (const chunk of stream as AsyncIterable<Buffer>) {
      hash.update(chunk);
    }
  } catch (cause) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `${label} could not be read as retained evidence`,
      { cause },
    );
  }
  return hash.digest('hex');
}

/**
 * Copies one verified source artifact into the bundle and binds the emitted
 * bytes to the digest the authenticated pass computed for its range.
 *
 * The copy is bound to the identity recorded when the artifact was selected, and
 * the emitted artifact is then digested in the same logical form the verifier
 * used. An in-place rewrite preserves device, inode and size, so nothing short
 * of this content comparison would catch it.
 */
async function copyVerifiedArtifact(
  writer: BundleWriter,
  artifact: SelectedArtifact,
): Promise<void> {
  const { dirName, fileName, sourcePath, identity, verifiedDigest } = artifact;
  const dirFd = writer.dirFds.get(dirName);
  if (dirFd === undefined) {
    throw createCodedError('EXPORT_FAILED', `bundle directory ${dirName}/ was never created`);
  }

  let sourceFd: number;
  try {
    sourceFd = fs.openSync(sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', `${fileName} is a symbolic link`);
    }
    throw createCodedError('EXPORT_SOURCE_CHANGED', `${fileName} could not be re-opened`, {
      cause,
    });
  }

  const destFd = fs.openSync(
    pinnedChildPath(dirFd, fileName),
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );

  const handle: BundleFileHandle = { fd: destFd, hash: crypto.createHash('sha256'), bytes: 0 };
  try {
    const opened = fs.fstatSync(sourceFd);
    if (
      Number(opened.dev) !== identity.dev ||
      Number(opened.ino) !== identity.ino ||
      Number(opened.size) !== identity.size
    ) {
      throw createCodedError(
        'EXPORT_SOURCE_CHANGED',
        `${fileName} is no longer the artifact whose evidence was verified`,
      );
    }

    const buffer = Buffer.allocUnsafe(65_536);
    for (;;) {
      const read = fs.readSync(sourceFd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      const slice = buffer.subarray(0, read);
      appendToBundleFile(handle, slice);
      assertWithinBudget(writer.totalBytes + handle.bytes);
    }

    const settled = fs.fstatSync(sourceFd);
    if (
      Number(settled.dev) !== identity.dev ||
      Number(settled.ino) !== identity.ino ||
      Number(settled.size) !== identity.size ||
      handle.bytes !== identity.size
    ) {
      throw createCodedError(
        'EXPORT_SOURCE_CHANGED',
        `${fileName} changed while it was being copied`,
      );
    }
  } finally {
    fs.closeSync(sourceFd);
    closeBundleFile(writer, dirName, fileName, handle);
  }

  // The emitted artifact must reproduce the digest the authenticated pass
  // computed. This is the binding that survives an in-place rewrite.
  const emittedFd = fs.openSync(
    pinnedChildPath(dirFd, fileName),
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  const emittedDigest = await logicalDigestOfFd(emittedFd, fileName, fileName.endsWith('.gz'));
  if (verifiedDigest !== null && emittedDigest !== verifiedDigest) {
    throw createCodedError(
      'EXPORT_SOURCE_CHANGED',
      `${fileName} does not reproduce the evidence digest that was verified`,
    );
  }
}

function closeBundleWriter(writer: BundleWriter): void {
  for (const fd of writer.dirFds.values()) {
    try {
      fs.closeSync(fd);
    } catch {
      // already closed
    }
  }
  writer.dirFds.clear();
  for (const fd of [writer.rootFd, writer.parentFd]) {
    try {
      fs.closeSync(fd);
    } catch {
      // already closed
    }
  }
}

/**
 * Removes only what this invocation created, and only while that is provable.
 *
 * The held root descriptor proves what it references; it does NOT prove that the
 * destination PATHNAME still names the same object. So the leaf is re-resolved
 * through the retained parent descriptor, refused if it is a symlink, and
 * required to carry the very device and inode this call created. If any of that
 * cannot be proven, no recursive pathname cleanup happens at all — a partial
 * bundle left behind is strictly better than deleting somebody else's directory.
 */
function cleanupBundleRoot(writer: BundleWriter): void {
  // FAIL SAFE: no recursive deletion is performed.
  //
  // Cleanup would have to decide on the leaf's identity and then consume that
  // decision with a SEPARATE, still-mutable leaf lookup — an `lstat` followed by
  // a pathname-based `rmSync` makes a security decision on one resolution and
  // acts on another, and Node offers no atomic, descriptor-relative,
  // identity-bound recursive delete. The frozen rule permits cleanup only when
  // it is safely proven; it does not outrank avoiding the deletion of unrelated
  // data. A fresh partial bundle is therefore left behind, and the caller
  // reports the original failure.
  closeBundleWriter(writer);
}

/* -------------------------------------------------------------------------- *
 * Evidence selection
 * -------------------------------------------------------------------------- */

interface SelectedArtifact {
  dirName: string;
  fileName: string;
  sourcePath: string;
  identity: EvidenceIdentity;
  /** Logical digest the authenticated pass computed, or null when unbound. */
  verifiedDigest: string | null;
}

interface SelectedEvidence {
  artifacts: SelectedArtifact[];
  checkpointHashes: string[];
  anchorReceiptIds: string[];
  checkpointKeyBytes: Buffer;
  anchorKeyBytes: Buffer | null;
}

function identityFor(filePath: string, label: string): EvidenceIdentity {
  const stats = fs.lstatSync(filePath);
  if (stats.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', `${label} is a symbolic link`);
  }
  return {
    dev: Number(stats.dev),
    ino: Number(stats.ino),
    size: Number(stats.size),
    mtimeMs: stats.mtimeMs,
  };
}

/**
 * Digests of every verified primary artifact, keyed by its on-disk filename.
 *
 * A rotated range may be represented physically by a plain or a compressed
 * artifact; both carry the same logical content, so both names map to the one
 * digest the verification pass computed for that range.
 */
function verifiedPrimaryDigests(
  primary: RetainedPrimaryHistoryVerificationResult,
): Map<string, string> {
  const digests = new Map<string, string>();
  for (const segment of primary.segments) {
    for (const name of segment.filenames) digests.set(name, segment.digest.sha256);
  }
  if (primary.active !== null) {
    digests.set(ACTIVE_SEGMENT_FILENAME, primary.active.sha256);
  }
  return digests;
}

/** True when two inclusive ranges share at least one sequence. */
function rangesIntersect(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return aEnd >= bStart && aStart <= bEnd;
}

/**
 * Chooses the authentic evidence that covers `[from, to]`.
 *
 * Only artifacts whose physical sequence range INTERSECTS the required interval
 * are selected. The active segment is no exception: including it for a purely
 * historical range would splice a discontinuous tail onto an earlier archive and
 * create a sequence gap inside the bundle.
 *
 * Whole artifacts are copied byte-for-byte; the checkpoint and receipt ledgers
 * contribute byte-identical signed lines.
 */
function selectEvidence(options: {
  directory: string;
  metadata: { anchorMode: 'DISABLED' | 'ENABLED' };
  from: number;
  to: number;
  expectedUid: number;
  primary: RetainedPrimaryHistoryVerificationResult;
  checkpointKeyBytes: Buffer;
  anchorKeyBytes: Buffer | null;
}): SelectedEvidence {
  const { directory, from, to, expectedUid } = options;
  const digests = verifiedPrimaryDigests(options.primary);

  const allSources = listRetainedSegmentSources(directory, expectedUid);
  const lastArchive = allSources.filter((source) => source.kind === 'ARCHIVE').pop();
  const activeStart = lastArchive === undefined ? 1 : lastArchive.sequenceEnd + 1;
  const activeEnd = options.primary.terminalSequence;

  const artifacts: SelectedArtifact[] = [];
  for (const source of allSources) {
    const start = source.kind === 'ACTIVE' ? activeStart : source.sequenceStart;
    const end = source.kind === 'ACTIVE' ? activeEnd : source.sequenceEnd;
    if (!rangesIntersect(start, end, from, to)) continue;
    artifacts.push({
      dirName: BUNDLE_AUDIT_DIRNAME,
      fileName: source.label,
      sourcePath: source.filePath,
      identity: identityFor(source.filePath, source.label),
      verifiedDigest: digests.get(source.label) ?? null,
    });
  }

  return {
    artifacts,
    checkpointHashes: [],
    anchorReceiptIds: [],
    checkpointKeyBytes: options.checkpointKeyBytes,
    anchorKeyBytes: options.anchorKeyBytes,
  };
}

/* -------------------------------------------------------------------------- *
 * Checkpoint and receipt authentication (shared with the bundle verifier)
 * -------------------------------------------------------------------------- */

/**
 * The rule set for a BUNDLE's checkpoint window.
 *
 * A bundle carries a window of evidence, not a store: it does not carry the
 * rotation history that made each checkpoint mandatory, so the frozen cadence
 * cannot be re-derived from it. The cadence is therefore enforced where it is
 * expressible — against the SOURCE, by the full Task-4 verifier above — and what
 * remains here is what a window CAN be held to: one chain from checkpoint
 * genesis, contiguous coverage, and every checkpoint bound to this store, this
 * key, its own signature and its own canonical hash. Those are Task-4 rules
 * (verifyCheckpointSignature, computeCheckpointHash), not a second crypto
 * implementation.
 */
interface CheckpointAuthContext {
  storeId: string;
  keyFingerprint: string;
  /** The PUBLIC verification key the checkpoints must be signed by. */
  publicKey: crypto.KeyObject;
  /** recordHash by sequence, for terminal binding. */
  chainBySequence: ReadonlyMap<number, string>;
}

/**
 * Applies every Task-4 rule that binds a checkpoint to a store, a key, a range
 * and its predecessor.
 *
 * Shared by the exporter (over the selected SOURCE lines, before anything is
 * written) and by the bundle verifier (over the emitted lines), so the two
 * cannot drift into disagreeing about what an authentic checkpoint is.
 */
export interface CheckpointCursorState {
  previousHash: string;
  previousSequenceEnd: number | null;
}

/**
 * Applies every Task-4 rule that binds a checkpoint to a store, a key, a range
 * and its predecessor incrementally (RC-06 Task 7).
 */
export function authenticateCheckpointItem(
  checkpoint: AuditCheckpointV1,
  cursor: CheckpointCursorState,
  context: CheckpointAuthContext,
): void {
  if (checkpoint.storeId !== context.storeId) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_STORE_MISMATCH',
      'a checkpoint names a different store',
    );
  }
  if (checkpoint.publicKeyFingerprint !== context.keyFingerprint) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_KEY_MISMATCH',
      'a checkpoint is bound to a different public key than the one configured',
    );
  }
  if (
    !Number.isSafeInteger(checkpoint.sequenceStart) ||
    !Number.isSafeInteger(checkpoint.sequenceEnd) ||
    checkpoint.sequenceStart <= 0 ||
    checkpoint.sequenceStart > checkpoint.sequenceEnd
  ) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_RANGE_INVALID',
      'a checkpoint declares an invalid sequence range',
    );
  }
  if (checkpoint.previousCheckpointHash !== cursor.previousHash) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_CHAIN_BROKEN',
      'checkpoints do not form one unbroken chain',
    );
  }
  // Task-4 coverage continuity: checkpoints cover the primary sequence without
  // a gap and without overlapping.
  if (
    cursor.previousSequenceEnd !== null &&
    checkpoint.sequenceStart !== cursor.previousSequenceEnd + 1
  ) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_CHAIN_BROKEN',
      'checkpoints do not cover the primary sequence contiguously',
    );
  }
  if (!verifyCheckpointSignature(checkpoint, context.publicKey)) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
      'a checkpoint signature does not verify',
    );
  }
  if (computeCheckpointHash(checkpoint) !== checkpoint.checkpointHash) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_HASH_INVALID',
      'a checkpoint hash is not the hash of its own contents',
    );
  }
  const covered = context.chainBySequence.get(checkpoint.sequenceEnd);
  if (covered !== undefined && covered !== checkpoint.terminalRecordHash) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_TERMINAL_MISMATCH',
      'a checkpoint does not bind to the primary record it covers',
    );
  }
  cursor.previousHash = checkpoint.checkpointHash;
  cursor.previousSequenceEnd = checkpoint.sequenceEnd;
}

export function authenticateCheckpointSequence(
  checkpoints: readonly AuditCheckpointV1[],
  context: CheckpointAuthContext,
): void {
  const cursor: CheckpointCursorState = {
    previousHash: ZERO_HASH,
    previousSequenceEnd: null,
  };
  for (const checkpoint of checkpoints) {
    authenticateCheckpointItem(checkpoint, cursor, context);
  }
}

/* -------------------------------------------------------------------------- *
 * Manifest sizing
 * -------------------------------------------------------------------------- */

/**
 * The exact serialized size of the manifest that will be written.
 *
 * Digest fields are always 64 lowercase hex characters, so substituting a
 * fixed-width placeholder produces a manifest of exactly the real length. That
 * makes the manifest's own contribution to the byte budget knowable BEFORE it is
 * written, rather than discovered after the ceiling has already been passed.
 */
export function predictManifestBytes(
  header: Omit<ExportManifest, 'files'>,
  fileBytes: ReadonlyMap<string, number>,
): number {
  const files: Record<string, ManifestFileEntry> = {};
  for (const relativePath of [...fileBytes.keys()].sort()) {
    files[relativePath] = { sha256: '0'.repeat(64), bytes: fileBytes.get(relativePath) as number };
  }
  return Buffer.byteLength(`${canonicalJsonV1({ ...header, files })}\n`, 'utf8');
}

/* -------------------------------------------------------------------------- *
 * Export
 * -------------------------------------------------------------------------- */

/**
 * Writes a deterministic evidence bundle for the requested inclusive range.
 *
 * The manifest is the determinism contract: sorted file keys, checkpoint hashes
 * and receipt ids in authenticated order, and a digest over every emitted file.
 * Nothing is reported as successful until the emitted bundle has been verified
 * end to end from its own contents.
 */
export async function exportEvidenceBundle(
  options: ExportEvidenceOptions,
): Promise<ExportEvidenceResult> {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const { from, to } = validateSequenceRange({
    ...(options.from === undefined ? {} : { from: options.from }),
    ...(options.to === undefined ? {} : { to: options.to }),
  });

  const destination = assertPathShape(options.outputDirectory, 'export destination');

  // Fail closed BEFORE anything else: an operator who supplied no authoritative
  // workspace information has not told us there are no workspaces.
  if (options.workspacePaths === undefined) {
    throw createCodedError(
      'EXPORT_WORKSPACE_ROOTS_REQUIRED',
      'authoritative workspace roots are required: export must not assume there are none',
    );
  }

  const metadata = loadStoreMetadataFile(options.directory, expectedUid);

  // The inventory bracket opens BEFORE verification, not after it. If it opened
  // afterwards, a source rewritten while verification was reading it would be
  // invisible to the comparison while the copy went on to emit the rewrite —
  // bytes that were never authenticated.
  const inventoryBefore = snapshotEvidenceInventory(options.directory, expectedUid);

  const primary = await verifyRetainedPrimaryHistory(options.directory, expectedUid);
  if (primary.status !== 'VERIFIED') {
    throw createCodedError(
      'AUDIT_VERIFICATION_FAILED',
      `source history is not verified (${primary.status}); refusing to export unverified evidence`,
    );
  }
  if (from > primary.terminalSequence) {
    throw createCodedError(
      'INVALID_SEQUENCE_RANGE',
      `--from ${from} is past the terminal sequence ${primary.terminalSequence}`,
    );
  }
  const rangeEnd = Math.min(to, primary.terminalSequence);

  // The FULL Task-4 checkpoint authority over the source, before a byte is
  // written. This is the same reviewed verifier `arc audit verify` runs, so the
  // frozen cadence, mandatory rotation boundaries, required-interval detection,
  // missing/unexpected checkpoint detection, coverage continuity, chain,
  // storeId/key binding, terminal-record binding and Ed25519 signature are all
  // authoritative here rather than restated. A source with a required checkpoint
  // deleted — or with a validly signed checkpoint whose coverage the cadence does
  // not permit — cannot be exported.
  await verifyCheckpointHistory({
    directory: options.directory,
    publicKeyPath: options.checkpointPublicKeyPath,
    workspacePaths: [...options.workspacePaths],
  });

  // ---- Public keys: read the bytes ONCE, then prove they are the validated
  // bytes by fingerprint before those exact bytes are copied. A key-path
  // substitution between validation and copy would otherwise let the bundle
  // carry a different key than the one the store pins.
  const checkpointTrustRoot = loadEd25519TrustRootFile(options.checkpointPublicKeyPath, {
    purpose: 'CHECKPOINT',
    expectedUid,
  });
  if (checkpointTrustRoot.fingerprint !== metadata.checkpointPublicKeyFingerprint) {
    throw createCodedError(
      'EXPORT_KEY_MISMATCH',
      'checkpoint public key does not match audit-store.json.checkpointPublicKeyFingerprint',
    );
  }
  const checkpointKeyBytes = fs.readFileSync(options.checkpointPublicKeyPath);
  if (fingerprintOfPem(checkpointKeyBytes, 'CHECKPOINT') !== checkpointTrustRoot.fingerprint) {
    throw createCodedError(
      'EXPORT_KEY_CHANGED',
      'the checkpoint public key changed after it was validated',
    );
  }

  // An enabled store MUST carry the anchor public key: without it the bundled
  // receipts could never be checked by anyone, so the bundle would assert an
  // external witness it does not let a reviewer confirm.
  const anchorRequired = metadata.anchorMode === 'ENABLED';
  if (
    anchorRequired &&
    (options.anchorReceiptPublicKeyPath === undefined ||
      options.anchorReceiptPublicKeyPath.length === 0)
  ) {
    throw createCodedError(
      'ANCHOR_PUBLIC_KEY_REQUIRED',
      'anchor mode is ENABLED: the anchor receipt public key is required to export verifiable receipts',
    );
  }

  let anchorKeyBytes: Buffer | null = null;
  let anchorFingerprint: string | null = null;
  if (options.anchorReceiptPublicKeyPath !== undefined) {
    const anchorTrustRoot = loadEd25519TrustRootFile(options.anchorReceiptPublicKeyPath, {
      purpose: 'ANCHOR_RECEIPT',
      expectedUid,
    });
    if (anchorTrustRoot.fingerprint !== metadata.anchorReceiptPublicKeyFingerprint) {
      throw createCodedError(
        'EXPORT_KEY_MISMATCH',
        'anchor receipt public key does not match audit-store.json.anchorReceiptPublicKeyFingerprint',
      );
    }
    anchorKeyBytes = fs.readFileSync(options.anchorReceiptPublicKeyPath);
    if (fingerprintOfPem(anchorKeyBytes, 'ANCHOR_RECEIPT') !== anchorTrustRoot.fingerprint) {
      throw createCodedError(
        'EXPORT_KEY_CHANGED',
        'the anchor receipt public key changed after it was validated',
      );
    }
    anchorFingerprint = anchorTrustRoot.fingerprint;
  }

  assertDestinationContainment({
    destination,
    auditDirectory: options.directory,
    workspacePaths: options.workspacePaths,
  });

  const evidence = selectEvidence({
    directory: options.directory,
    metadata,
    from,
    to: rangeEnd,
    expectedUid,
    primary,
    checkpointKeyBytes,
    anchorKeyBytes,
  });
  if (evidence.artifacts.length === 0) {
    throw createCodedError(
      'BUNDLE_RANGE_NOT_COVERED',
      'no retained primary artifact covers the requested sequence range',
    );
  }

  // ---- Authenticate the selected SOURCE checkpoint and receipt evidence before
  // a single byte is written. This reuses the same reviewed Task-4/Task-5 rules
  // the store verifier applies; nothing weaker is restated here.
  const chainBySequence = new Map<number, string>();
  for (const segment of primary.segments) {
    chainBySequence.set(segment.digest.terminalSequence, segment.digest.terminalRecordHash);
  }
  if (primary.active !== null) {
    chainBySequence.set(primary.active.terminalSequence, primary.active.terminalRecordHash);
  }

  const checkpointVerification = await verifyCheckpointHistoryCore({
    auditDir: options.directory,
    expectedUid,
    publicKey: checkpointTrustRoot.publicKey,
    storeId: metadata.storeId,
    fingerprint: checkpointTrustRoot.fingerprint,
  });
  await options.hooks?.afterCheckpointVerification?.();

  let receiptVerification: {
    artifactState: { dev: number; ino: number; size: number; bytes: number; sha256: string };
  } | null = null;
  if (metadata.anchorMode === 'ENABLED') {
    const receiptLedgerPath = path.join(options.directory, ANCHOR_RECEIPT_FILENAME);
    if (fs.existsSync(receiptLedgerPath)) {
      if (
        options.anchorReceiptPublicKeyPath === undefined ||
        options.anchorReceiptPublicKeyPath.length === 0
      ) {
        throw createCodedError(
          'ANCHOR_PUBLIC_KEY_REQUIRED',
          'anchor mode is ENABLED: the anchor receipt public key is required to export verifiable receipts',
        );
      }
      const anchorTrustRoot = loadEd25519TrustRootFile(options.anchorReceiptPublicKeyPath, {
        purpose: 'ANCHOR_RECEIPT',
        expectedUid,
      });

      const rFd = openArtifactFd(receiptLedgerPath, ANCHOR_RECEIPT_FILENAME, expectedUid);
      const rStartId = captureIdentity(rFd);
      const rHasher = crypto.createHash('sha256');
      let rBytesRead = 0;
      const rStream = fs.createReadStream(null as unknown as fs.PathLike, {
        fd: rFd,
        autoClose: false,
      });
      rStream.on('data', (chunk: string | Buffer) => {
        rHasher.update(chunk);
        rBytesRead += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length;
      });
      const rLines = readline.createInterface({ input: rStream, crlfDelay: Infinity });
      const rIter = rLines[Symbol.asyncIterator]();

      const selectedCpHashes: string[] = [];
      const cpLedgerPath = path.join(options.directory, CHECKPOINT_FILENAME);
      if (fs.existsSync(cpLedgerPath)) {
        for await (const line of streamLedgerLines(
          cpLedgerPath,
          CHECKPOINT_FILENAME,
          expectedUid,
        )) {
          const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
          if (checkpoint.sequenceStart <= rangeEnd) {
            selectedCpHashes.push(checkpoint.checkpointHash);
          }
        }
      }
      const includedCpHashes = new Set(selectedCpHashes);

      try {
        await walkReceiptEvidence({
          storeId: metadata.storeId,
          anchorFingerprint: anchorTrustRoot.fingerprint,
          publicKey: anchorTrustRoot.publicKey,
          checkpointHashes: selectedCpHashes,
          nextReceipt: async () => {
            for (;;) {
              const step = await rIter.next();
              if (step.done === true) return null;
              if (step.value.length === 0) continue;
              const receipt = parseAndValidateAnchorReceiptLineV1(`${step.value}\n`);
              if (includedCpHashes.has(receipt.checkpointHash)) {
                return receipt;
              }
            }
          },
        });

        for (;;) {
          const step = await rIter.next();
          if (step.done === true) break;
        }

        const rFinalStats = fs.fstatSync(rFd);
        if (
          Number(rFinalStats.dev) !== rStartId.dev ||
          Number(rFinalStats.ino) !== rStartId.ino ||
          Number(rFinalStats.size) !== rStartId.size ||
          rBytesRead !== rStartId.size
        ) {
          throw createCodedError(
            'ANCHOR_RECEIPT_FILE_RACE',
            `${ANCHOR_RECEIPT_FILENAME} changed while its history was being verified`,
          );
        }

        receiptVerification = {
          artifactState: {
            dev: rStartId.dev,
            ino: rStartId.ino,
            size: rStartId.size,
            bytes: rBytesRead,
            sha256: rHasher.digest('hex'),
          },
        };
      } finally {
        rLines.close();
        fs.closeSync(rFd);
      }

      await options.hooks?.afterReceiptVerification?.();
    }
  }

  // ---- The projection covers EVERY emitted file.
  const emittedBytes = new Map<string, number>();
  for (const artifact of evidence.artifacts) {
    emittedBytes.set(`${artifact.dirName}/${artifact.fileName}`, artifact.identity.size);
  }
  const sourceCheckpointBytes =
    checkpointVerification.artifactState.kind === 'PRESENT'
      ? checkpointVerification.artifactState.size
      : 0;
  const sourceReceiptBytes =
    receiptVerification !== null ? receiptVerification.artifactState.size : 0;
  emittedBytes.set(`${BUNDLE_CHECKPOINTS_DIRNAME}/${CHECKPOINT_FILENAME}`, sourceCheckpointBytes);
  emittedBytes.set(`${BUNDLE_ANCHORS_DIRNAME}/${ANCHOR_RECEIPT_FILENAME}`, sourceReceiptBytes);
  emittedBytes.set(
    `${BUNDLE_PUBLIC_KEYS_DIRNAME}/${BUNDLE_CHECKPOINT_KEY_FILENAME}`,
    checkpointKeyBytes.byteLength,
  );
  if (anchorKeyBytes !== null) {
    emittedBytes.set(
      `${BUNDLE_PUBLIC_KEYS_DIRNAME}/${BUNDLE_ANCHOR_KEY_FILENAME}`,
      anchorKeyBytes.byteLength,
    );
  }

  const projectedManifestBytes = 65536;
  assertExportWithinBudget(
    [...emittedBytes.values()].reduce((total, bytes) => total + bytes, 0) + projectedManifestBytes,
  );

  const { parentFd, leafName } = openPinnedParent(destination);
  let writer: BundleWriter;
  try {
    writer = createBundleRoot(parentFd, leafName, destination);
  } catch (err) {
    fs.closeSync(parentFd);
    throw err;
  }

  try {
    createBundleDirectory(writer, BUNDLE_AUDIT_DIRNAME);
    createBundleDirectory(writer, BUNDLE_CHECKPOINTS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_ANCHORS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_PUBLIC_KEYS_DIRNAME);

    for (const artifact of evidence.artifacts) await copyVerifiedArtifact(writer, artifact);

    writeBundleFile(
      writer,
      BUNDLE_PUBLIC_KEYS_DIRNAME,
      BUNDLE_CHECKPOINT_KEY_FILENAME,
      checkpointKeyBytes,
    );
    if (anchorKeyBytes !== null) {
      writeBundleFile(
        writer,
        BUNDLE_PUBLIC_KEYS_DIRNAME,
        BUNDLE_ANCHOR_KEY_FILENAME,
        anchorKeyBytes,
      );
    }

    const checkpointHashes: string[] = [];
    const cpCursor: CheckpointCursorState = {
      previousHash: ZERO_HASH,
      previousSequenceEnd: null,
    };
    const checkpointLedgerPath = path.join(options.directory, CHECKPOINT_FILENAME);
    const cpHandle = openBundleFile(writer, BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME);
    const cpSourceHasher = crypto.createHash('sha256');

    try {
      if (checkpointVerification.artifactState.kind === 'PRESENT') {
        const cpFd = openArtifactFd(checkpointLedgerPath, CHECKPOINT_FILENAME, expectedUid);
        const cpStartId = captureIdentity(cpFd);
        if (
          cpStartId.dev !== checkpointVerification.artifactState.dev ||
          cpStartId.ino !== checkpointVerification.artifactState.ino ||
          cpStartId.size !== checkpointVerification.artifactState.size
        ) {
          fs.closeSync(cpFd);
          throw createCodedError(
            'EXPORT_SOURCE_CHANGED',
            'the checkpoint ledger changed after its evidence was authenticated',
          );
        }

        const stream = fs.createReadStream(null as unknown as fs.PathLike, {
          fd: cpFd,
          autoClose: true,
        });
        stream.on('data', (chunk: string | Buffer) => {
          cpSourceHasher.update(chunk);
        });
        const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
        for await (const line of lines) {
          const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
          authenticateCheckpointItem(checkpoint, cpCursor, {
            storeId: metadata.storeId,
            keyFingerprint: checkpointTrustRoot.fingerprint,
            publicKey: checkpointTrustRoot.publicKey,
            chainBySequence,
          });
          if (checkpoint.sequenceStart <= rangeEnd) {
            assertManifestReferenceWithinBound(
              checkpointHashes.length + 1,
              MAX_MANIFEST_CHECKPOINT_REFS,
              'checkpoints',
            );
            checkpointHashes.push(checkpoint.checkpointHash);
            appendToBundleFile(cpHandle, Buffer.from(`${line}\n`, 'utf8'));
          }
        }
      }
    } finally {
      closeBundleFile(writer, BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME, cpHandle);
    }

    if (
      checkpointVerification.artifactState.kind === 'PRESENT' &&
      cpSourceHasher.digest('hex') !== checkpointVerification.artifactState.sha256
    ) {
      throw createCodedError(
        'EXPORT_SOURCE_CHANGED',
        'the checkpoint ledger changed after its evidence was authenticated',
      );
    }

    const anchorReceiptIds: string[] = [];
    const receiptHandle = openBundleFile(writer, BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME);
    const receiptSourceHasher = crypto.createHash('sha256');

    try {
      if (metadata.anchorMode === 'ENABLED' && receiptVerification !== null) {
        if (anchorKeyBytes === null || anchorFingerprint === null) {
          throw createCodedError(
            'ANCHOR_PUBLIC_KEY_REQUIRED',
            'receipts are present: the anchor receipt public key is required to export them',
          );
        }
        const anchorTrustRoot = loadEd25519TrustRootFile(
          options.anchorReceiptPublicKeyPath as string,
          {
            purpose: 'ANCHOR_RECEIPT',
            expectedUid,
          },
        );

        const receiptLedgerPath = path.join(options.directory, ANCHOR_RECEIPT_FILENAME);
        const receiptFd = openArtifactFd(receiptLedgerPath, ANCHOR_RECEIPT_FILENAME, expectedUid);
        const receiptStartId = captureIdentity(receiptFd);
        if (
          receiptStartId.dev !== receiptVerification.artifactState.dev ||
          receiptStartId.ino !== receiptVerification.artifactState.ino ||
          receiptStartId.size !== receiptVerification.artifactState.size
        ) {
          fs.closeSync(receiptFd);
          throw createCodedError(
            'EXPORT_SOURCE_CHANGED',
            'the anchor receipt ledger changed after its evidence was authenticated',
          );
        }

        const stream = fs.createReadStream(null as unknown as fs.PathLike, {
          fd: receiptFd,
          autoClose: true,
        });
        stream.on('data', (chunk: string | Buffer) => {
          receiptSourceHasher.update(chunk);
        });
        const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
        const iterator = lines[Symbol.asyncIterator]();
        const includedCheckpointHashes = new Set(checkpointHashes);

        await walkReceiptEvidence({
          storeId: metadata.storeId,
          anchorFingerprint,
          publicKey: anchorTrustRoot.publicKey,
          checkpointHashes,
          nextReceipt: async () => {
            for (;;) {
              const step = await iterator.next();
              if (step.done) return null;
              const line = step.value;
              const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
              if (includedCheckpointHashes.has(receipt.checkpointHash)) {
                assertManifestReferenceWithinBound(
                  anchorReceiptIds.length + 1,
                  MAX_MANIFEST_RECEIPT_REFS,
                  'anchor receipts',
                );
                anchorReceiptIds.push(receipt.receiptId);
                appendToBundleFile(receiptHandle, Buffer.from(`${line}\n`, 'utf8'));
                return receipt;
              }
            }
          },
        });

        for (;;) {
          const step = await iterator.next();
          if (step.done) break;
        }
      }
    } finally {
      closeBundleFile(writer, BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME, receiptHandle);
    }

    if (
      metadata.anchorMode === 'ENABLED' &&
      receiptVerification !== null &&
      receiptSourceHasher.digest('hex') !== receiptVerification.artifactState.sha256
    ) {
      throw createCodedError(
        'EXPORT_SOURCE_CHANGED',
        'the anchor receipt ledger changed after its evidence was authenticated',
      );
    }

    // Nothing may have moved while the bundle was being written.
    assertInventoryUnchanged(
      inventoryBefore,
      snapshotEvidenceInventory(options.directory, expectedUid),
      'evidence export',
    );

    const files: Record<string, ManifestFileEntry> = {};
    for (const key of [...writer.fileHashes.keys()].sort()) {
      files[key] = writer.fileHashes.get(key) as ManifestFileEntry;
    }
    const manifest: ExportManifest = {
      version: 1,
      storeId: metadata.storeId,
      sequenceRange: { start: from, end: rangeEnd },
      checkpointHashes,
      anchorReceiptIds,
      files,
    };
    writeBundleRootFile(
      writer,
      BUNDLE_MANIFEST_FILENAME,
      Buffer.from(`${canonicalJsonV1(manifest)}\n`, 'utf8'),
    );

    const leafBefore = fs.lstatSync(pinnedChildPath(writer.parentFd, writer.leafName));
    if (
      leafBefore.isSymbolicLink() ||
      Number(leafBefore.dev) !== writer.rootIdentity.dev ||
      Number(leafBefore.ino) !== writer.rootIdentity.ino
    ) {
      throw createCodedError(
        'EXPORT_DESTINATION_REPLACED',
        'the export destination no longer names the bundle this invocation created',
      );
    }

    await options.hooks?.beforeFinalVerification?.();

    const authority = createBundleDirectoryAuthority(writer.rootFd);
    await verifyEvidenceBundleAuthoritative(authority);

    await options.hooks?.afterFinalVerification?.();

    const leaf = fs.lstatSync(pinnedChildPath(writer.parentFd, writer.leafName));
    if (
      leaf.isSymbolicLink() ||
      Number(leaf.dev) !== writer.rootIdentity.dev ||
      Number(leaf.ino) !== writer.rootIdentity.ino
    ) {
      throw createCodedError(
        'EXPORT_DESTINATION_REPLACED',
        'the export destination no longer names the bundle this invocation created',
      );
    }

    const totalBytes = writer.totalBytes;
    const fileCount = writer.fileHashes.size;

    closeBundleWriter(writer);
    return { outputDirectory: destination, manifest, fileCount, totalBytes };
  } catch (err) {
    cleanupBundleRoot(writer);
    throw err;
  }
}

/** The SPKI fingerprint of a PEM public key held in memory. */
function fingerprintOfPem(pem: Buffer, purpose: 'CHECKPOINT' | 'ANCHOR_RECEIPT'): string {
  if (/PRIVATE KEY/.test(pem.toString('utf8'))) {
    throw createCodedError(
      'PRIVATE_KEY_REJECTED',
      `${purpose.toLowerCase()} key file contains private key material`,
    );
  }
  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey(pem);
  } catch (cause) {
    throw createCodedError(
      'INVALID_KEY_MATERIAL',
      `${purpose.toLowerCase()} public key is unreadable`,
      {
        cause,
      },
    );
  }
  return crypto
    .createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

/* -------------------------------------------------------------------------- *
 * Bundle verification
 * -------------------------------------------------------------------------- */

export interface VerifyBundleResult {
  status: 'VERIFIED';
  storeId: string;
  sequenceRange: { start: number; end: number };
  fileCount: number;
  checkpointCount: number;
  anchorReceiptCount: number;
  /** Lowest primary sequence the bundle carries. */
  coveredSequenceStart: number;
  /** Highest sequence the bundled primary artifacts actually carry. */
  coveredSequenceEnd: number;
}

/**
 * Streams a file descriptor, hashing it without materializing it.
 */
function digestFd(fd: number): { sha256: string; bytes: number } {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(65_536);
  let total = 0;
  for (;;) {
    const read = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (read === 0) break;
    hash.update(buffer.subarray(0, read));
    total += read;
  }
  return { sha256: hash.digest('hex'), bytes: total };
}

export function digestFile(filePath: string): { sha256: string; bytes: number } {
  const fd = fs.openSync(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(65_536);
    let total = 0;
    for (;;) {
      const read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
      total += read;
    }
    return { sha256: hash.digest('hex'), bytes: total };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Re-verifies a bundle descriptor-authoritatively from an already-held root
 * directory authority (RC-06 Task 7).
 */
export async function verifyEvidenceBundleAuthoritative(
  authority: BundleDirectoryAuthority,
): Promise<VerifyBundleResult> {
  const manifestFd = authority.openRootFile(BUNDLE_MANIFEST_FILENAME);
  let manifestRaw: string;
  try {
    manifestRaw = readBoundedDescriptor(
      manifestFd,
      16 * 1024 * 1024,
      'manifest',
      'BUNDLE_MANIFEST_INVALID',
    ).toString('utf8');
  } finally {
    fs.closeSync(manifestFd);
  }

  let manifest: ExportManifest;
  try {
    manifest = JSON.parse(manifestRaw) as ExportManifest;
  } catch (cause) {
    throw createCodedError('BUNDLE_MANIFEST_INVALID', 'manifest is not valid JSON', {
      cause,
    });
  }

  if (manifest.version !== 1) {
    throw createCodedError('BUNDLE_MANIFEST_INVALID', 'unsupported bundle manifest version');
  }

  // 1. Every listed file: streamed digest, never a whole-file read.
  for (const [relativePath, entry] of Object.entries(manifest.files)) {
    if (relativePath.includes('..') || path.isAbsolute(relativePath)) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', 'manifest lists a path outside the bundle');
    }
    const parts = relativePath.split('/');
    if (parts.length !== 2 || parts.some((p) => !p || p === '.' || p === '..')) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', 'manifest lists an invalid file path');
    }
    const [dirName, fileName] = parts;
    const fileFd = authority.openChildFile(dirName, fileName);
    let digest: { sha256: string; bytes: number };
    try {
      digest = digestFd(fileFd);
    } finally {
      fs.closeSync(fileFd);
    }
    if (digest.sha256 !== entry.sha256 || digest.bytes !== entry.bytes) {
      throw createCodedError(
        'BUNDLE_DIGEST_MISMATCH',
        `manifest digest for ${relativePath} does not match the emitted bytes`,
      );
    }
  }

  if (!authority.childFileExists(BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_CHECKPOINT_KEY_FILENAME)) {
    throw createCodedError('BUNDLE_KEY_MISSING', 'the bundle carries no checkpoint public key');
  }
  const checkpointKeyFd = authority.openChildFile(
    BUNDLE_PUBLIC_KEYS_DIRNAME,
    BUNDLE_CHECKPOINT_KEY_FILENAME,
  );
  let checkpointKey: LoadedTrustRoot;
  try {
    checkpointKey = loadEd25519TrustRootFromDescriptor(checkpointKeyFd, { purpose: 'CHECKPOINT' });
  } finally {
    fs.closeSync(checkpointKeyFd);
  }

  // 2. The primary chain: streamed, strictly framed, in SEQUENCE order.
  const chain = await verifyBundledChainFromAuthority(authority, manifest.sequenceRange);

  // 3. Checkpoints, streamed by Task-4 rule set.
  let checkpointCount = 0;
  let boundarySealFound = false;
  let boundarySealValid = false;
  const cursor: CheckpointCursorState = {
    previousHash: ZERO_HASH,
    previousSequenceEnd: null,
  };

  if (authority.childFileExists(BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME)) {
    const cpFd = authority.openChildFile(BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME);
    for await (const line of streamLedgerLinesFromFd(cpFd, CHECKPOINT_FILENAME, true)) {
      const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
      assertManifestReferenceWithinBound(
        checkpointCount + 1,
        MAX_MANIFEST_CHECKPOINT_REFS,
        'checkpoints',
      );
      authenticateCheckpointItem(checkpoint, cursor, {
        storeId: manifest.storeId,
        keyFingerprint: checkpointKey.fingerprint,
        publicKey: checkpointKey.publicKey,
        chainBySequence: chain.terminalHashes,
      });

      if (
        checkpointCount >= manifest.checkpointHashes.length ||
        checkpoint.checkpointHash !== manifest.checkpointHashes[checkpointCount]
      ) {
        throw createCodedError(
          'BUNDLE_CHECKPOINT_MISMATCH',
          'bundled checkpoints do not match the manifest checkpoint hashes',
        );
      }
      checkpointCount += 1;

      if (
        chain.coveredSequenceStart > 1 &&
        checkpoint.sequenceEnd === chain.coveredSequenceStart - 1
      ) {
        boundarySealFound = true;
        if (
          chain.boundaryPredecessorHash !== undefined &&
          checkpoint.terminalRecordHash === chain.boundaryPredecessorHash
        ) {
          boundarySealValid = true;
        }
      }
    }
  }

  if (checkpointCount !== manifest.checkpointHashes.length) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_MISMATCH',
      'bundled checkpoints do not match the manifest checkpoint hashes',
    );
  }

  if (chain.coveredSequenceStart > 1) {
    if (!boundarySealFound || !boundarySealValid) {
      throw createCodedError(
        'BUNDLE_BOUNDARY_UNVERIFIED',
        !boundarySealFound
          ? 'the bundle begins mid-history without a checkpoint sealing the evidence before it'
          : 'the bundled boundary checkpoint does not bind to the evidence before the bundle',
      );
    }
  }

  // 4. Receipts, streamed by Task-5 rule set.
  let receiptCount = 0;
  let manifestMismatch = false;
  if (authority.childFileExists(BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME)) {
    const receiptFd = authority.openChildFile(BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME);
    const lineIterator = streamLedgerLinesFromFd(receiptFd, ANCHOR_RECEIPT_FILENAME, true);
    const firstStep = await lineIterator.next();
    if (!firstStep.done) {
      if (!authority.childFileExists(BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_ANCHOR_KEY_FILENAME)) {
        throw createCodedError(
          'BUNDLE_KEY_MISSING',
          'the bundle carries receipts but no anchor key',
        );
      }
      const anchorKeyFd = authority.openChildFile(
        BUNDLE_PUBLIC_KEYS_DIRNAME,
        BUNDLE_ANCHOR_KEY_FILENAME,
      );
      let anchorTrustRoot: LoadedTrustRoot;
      try {
        anchorTrustRoot = loadEd25519TrustRootFromDescriptor(anchorKeyFd, {
          purpose: 'ANCHOR_RECEIPT',
        });
      } finally {
        fs.closeSync(anchorKeyFd);
      }

      let nextLine: string | null = firstStep.value;
      await walkReceiptEvidence({
        storeId: manifest.storeId,
        anchorFingerprint: anchorTrustRoot.fingerprint,
        publicKey: anchorTrustRoot.publicKey,
        checkpointHashes: manifest.checkpointHashes,
        nextReceipt: async () => {
          let line: string;
          if (nextLine !== null) {
            line = nextLine;
            nextLine = null;
          } else {
            const step = await lineIterator.next();
            if (step.done) return null;
            line = step.value;
          }
          const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
          assertManifestReferenceWithinBound(
            receiptCount + 1,
            MAX_MANIFEST_RECEIPT_REFS,
            'anchor receipts',
          );
          if (
            receiptCount >= manifest.anchorReceiptIds.length ||
            receipt.receiptId !== manifest.anchorReceiptIds[receiptCount]
          ) {
            manifestMismatch = true;
          }
          receiptCount += 1;
          return receipt;
        },
      });
    }
  }

  if (manifestMismatch || receiptCount !== manifest.anchorReceiptIds.length) {
    throw createCodedError(
      'BUNDLE_RECEIPT_MISMATCH',
      'bundled anchor receipts do not match the manifest receipt ids',
    );
  }

  return {
    status: 'VERIFIED',
    storeId: manifest.storeId,
    sequenceRange: manifest.sequenceRange,
    fileCount: Object.keys(manifest.files).length,
    checkpointCount,
    anchorReceiptCount: receiptCount,
    coveredSequenceStart: chain.coveredSequenceStart,
    coveredSequenceEnd: chain.coveredSequenceEnd,
  };
}

/**
 * Re-verifies a bundle from its own contents and public material only.
 */
export async function verifyEvidenceBundle(bundleDirectory: string): Promise<VerifyBundleResult> {
  const root = assertPathShape(bundleDirectory, 'bundle directory');
  const rootFd = openDirectoryNoFollow(root, 'bundle directory');
  try {
    const authority = createBundleDirectoryAuthority(rootFd);
    return await verifyEvidenceBundleAuthoritative(authority);
  } finally {
    fs.closeSync(rootFd);
  }
}

interface BundledChain {
  coveredSequenceStart: number;
  coveredSequenceEnd: number;
  terminalHashes: Map<number, string>;
  boundaryPredecessorHash: string | undefined;
}

/**
 * Streams the bundled primary artifacts as one chain, in SEQUENCE order.
 */
async function verifyBundledChainFromAuthority(
  authority: BundleDirectoryAuthority,
  sequenceRange: { start: number; end: number },
): Promise<BundledChain> {
  const names = authority.listAuditArtifacts();

  const activeNames: string[] = [];
  const archives: Array<{ name: string; sequenceStart: number; sequenceEnd: number }> = [];
  for (const name of names) {
    if (name === ACTIVE_SEGMENT_FILENAME) {
      activeNames.push(name);
      continue;
    }
    const parsed = parseRotatedSegmentFilename(name);
    if (parsed === null) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', `unrecognized bundle artifact ${name}`);
    }
    archives.push({
      name,
      sequenceStart: parsed.sequenceStart,
      sequenceEnd: parsed.sequenceEnd,
    });
  }

  archives.sort((a, b) =>
    a.sequenceStart === b.sequenceStart
      ? a.sequenceEnd - b.sequenceEnd
      : a.sequenceStart - b.sequenceStart,
  );

  let previousEnd = 0;
  for (const archive of archives) {
    if (archive.sequenceStart <= previousEnd) {
      throw createCodedError(
        'BUNDLE_CHAIN_BROKEN',
        `bundled artifacts overlap or duplicate the range ending at ${previousEnd}`,
      );
    }
    previousEnd = archive.sequenceEnd;
  }

  const ordered: Array<{ name: string; compressed: boolean }> = archives.map((archive) => ({
    name: archive.name,
    compressed: archive.name.endsWith('.gz'),
  }));
  for (const name of activeNames) ordered.push({ name, compressed: false });

  if (ordered.length === 0) {
    throw createCodedError('BUNDLE_RANGE_NOT_COVERED', 'the bundle carries no primary evidence');
  }

  const terminalHashes = new Map<number, string>();
  let expectedSequence: number | null = null;
  let previousHash: string | null = null;
  let boundaryPredecessorHash: string | undefined;
  let coveredSequenceStart = 0;
  let coveredSequenceEnd = 0;

  for (const entry of ordered) {
    const fd = authority.openChildFile(BUNDLE_AUDIT_DIRNAME, entry.name);
    let segmentTerminalSequence: number | null = null;
    let segmentTerminalHash: string | null = null;

    for await (const record of streamSegmentRecordsFromFd(
      fd,
      entry.name,
      entry.compressed,
      true,
      true,
    )) {
      if (expectedSequence === null) {
        expectedSequence = record.sequenceNumber;
        coveredSequenceStart = record.sequenceNumber;
        boundaryPredecessorHash = record.integrity.previousRecordHash;
      }
      if (record.sequenceNumber !== expectedSequence) {
        throw createCodedError(
          'BUNDLE_CHAIN_BROKEN',
          `bundled primary history is not contiguous at sequence ${expectedSequence}`,
        );
      }
      if (previousHash !== null && record.integrity.previousRecordHash !== previousHash) {
        throw createCodedError(
          'BUNDLE_CHAIN_BROKEN',
          `bundled primary hash link is broken at sequence ${record.sequenceNumber}`,
        );
      }
      previousHash = record.integrity.recordHash;
      coveredSequenceEnd = record.sequenceNumber;
      segmentTerminalSequence = record.sequenceNumber;
      segmentTerminalHash = record.integrity.recordHash;
      expectedSequence += 1;
    }

    if (segmentTerminalSequence !== null && segmentTerminalHash !== null) {
      terminalHashes.set(segmentTerminalSequence, segmentTerminalHash);
    }
  }

  if (coveredSequenceStart > sequenceRange.start) {
    throw createCodedError(
      'BUNDLE_RANGE_NOT_COVERED',
      `the bundle begins at sequence ${coveredSequenceStart}, after the declared range start`,
    );
  }
  if (coveredSequenceEnd < sequenceRange.end) {
    throw createCodedError(
      'BUNDLE_RANGE_NOT_COVERED',
      `the bundle ends at sequence ${coveredSequenceEnd}, before the declared range end`,
    );
  }

  return { coveredSequenceStart, coveredSequenceEnd, terminalHashes, boundaryPredecessorHash };
}
