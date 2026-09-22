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
 * - It never opens the checkpoint signing key. Only public verification keys
 *   are copied, and there is no parameter through which a private key could
 *   arrive.
 * - It never rewrites a record. Each emitted artifact is a byte-for-byte copy of
 *   authentic source evidence (or, for the line-oriented checkpoint and receipt
 *   ledgers, a byte-identical subset of their canonical lines). No hash is
 *   recomputed to manufacture a prettier partial range.
 * - It never merges into an existing destination and never replaces a file.
 *
 * ## Destination authority is descriptor-bound, not pathname-bound
 *
 * `lstat`-ing the parent components and later calling `mkdir` on a pathname
 * proves nothing: the hierarchy that was checked is not the hierarchy that
 * receives the bundle, so a component can be swapped for a symlink in between.
 * The destination is therefore resolved and created entirely through
 * descriptors — each ancestor is opened `O_DIRECTORY | O_NOFOLLOW` by its
 * parent's own descriptor, and both the destination and every file inside it are
 * created by name relative to a descriptor this process already holds. A
 * substitution anywhere in the chain cannot redirect the write.
 *
 * ## Emitted bytes are the verified bytes
 *
 * The artifacts copied into a bundle are the ones whose authenticity the
 * preceding verification authenticated. Each copy re-opens its source, proves
 * the descriptor still carries the device, inode and size recorded at selection
 * time, and copies from that descriptor — so a same-size pathname replacement
 * cannot smuggle different bytes into a bundle that reports success.
 *
 * @packageDocumentation
 */

import fs from 'node:fs';
import fsConstants from 'node:constants';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  ACTIVE_SEGMENT_FILENAME,
  canonicalJsonV1,
  getProcessUid,
  createCodedError,
} from './storage.js';
import {
  CHECKPOINT_FILENAME,
  computeCheckpointHash,
  parseAndValidateCheckpointLineV1,
  verifyCheckpointSignature,
} from './checkpoint.js';
import { loadStoreMetadataFile } from './metadata.js';
import {
  listLogicalArchiveInventory,
  verifyRetainedPrimaryHistory,
  type LogicalArchiveEntry,
  type PhysicalArchiveRepresentation,
} from './rotation.js';
import { parseRotatedSegmentFilename } from './rotation-filename.js';
import { ANCHOR_RECEIPT_FILENAME } from './internal/anchor-constants.js';
import { loadEd25519TrustRootFile } from './internal/key-authority.js';
import {
  assertDescriptorPinnedTraversalAvailable,
  pinnedChildPath,
} from './internal/anchor-paths.js';
import { parseAndValidateAnchorReceiptLineV1, verifyAnchorReceiptSignature } from './anchor.js';
import {
  listRetainedSegmentSources,
  snapshotEvidenceInventory,
  assertInventoryUnchanged,
  streamRetainedRecords,
  validateSequenceRange,
  type EvidenceIdentity,
  type RetainedSegmentSource,
} from './verify.js';

/* -------------------------------------------------------------------------- *
 * Frozen bounds (rc06 §24.1)
 * -------------------------------------------------------------------------- */

/**
 * Maximum total bytes one export bundle may emit.
 *
 * This bounds the EMITTED BUNDLE — every byte written into the destination,
 * including the public keys and the manifest itself — not merely the primary
 * evidence. Fixed by the architecture, not configurable: no flag, environment
 * variable or configuration file may raise it.
 */
export const MAX_EXPORT_BYTES = 1_073_741_824;

/** Bundle layout, frozen by rc06 §17.2. */
export const BUNDLE_MANIFEST_FILENAME = 'manifest.json';
export const BUNDLE_AUDIT_DIRNAME = 'audit';
export const BUNDLE_CHECKPOINTS_DIRNAME = 'checkpoints';
export const BUNDLE_ANCHORS_DIRNAME = 'anchors';
export const BUNDLE_PUBLIC_KEYS_DIRNAME = 'public-keys';
/** Purpose-named bundled keys, so a reviewer never has to guess which is which. */
export const BUNDLE_CHECKPOINT_KEY_FILENAME = 'checkpoint-public.pem';
export const BUNDLE_ANCHOR_KEY_FILENAME = 'anchor-receipt-public.pem';

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
  /** Ed25519 PUBLIC anchor receipt key. Required only when anchor mode is ENABLED. */
  anchorReceiptPublicKeyPath?: string;
  /**
   * Authoritative agent workspace roots.
   *
   * Optional in the type only so the fail-closed check can be expressed: when it
   * is ABSENT the export refuses, because an exporter that cannot be told where
   * the agent workspaces are cannot prove the destination is outside them, and
   * treating "not supplied" as "there are none" is exactly the assumption an
   * attacker would want. Passing an explicit empty array is a different act: it
   * is the operator authoritatively saying there are none.
   */
  workspacePaths?: readonly string[];
  from?: number;
  to?: number;
  expectedUid?: number;
}

export interface ExportEvidenceResult {
  outputDirectory: string;
  manifest: ExportManifest;
  fileCount: number;
  totalBytes: number;
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
 * and `/work/a/../abc` is not inside `/work/a`. Both paths are normalized and
 * compared segment by segment, so lexical siblings never collide.
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
 * `O_DIRECTORY | O_NOFOLLOW`. A component that is a symlink therefore fails at
 * the moment it is traversed, and — critically — a component swapped for a
 * symlink after it was opened cannot affect the next traversal, because the next
 * traversal never re-resolves the earlier component by pathname.
 *
 * Ancestors are not created: an operator who names a destination below a
 * directory that does not exist gets an error, not a manufactured tree.
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
  rootFd: number;
  rootIdentity: { dev: number; ino: number };
  dirFds: Map<string, number>;
  fileHashes: Map<string, ManifestFileEntry>;
  totalBytes: number;
}

/**
 * Creates the destination relative to its pinned parent descriptor and returns
 * an open descriptor for it.
 *
 * `mkdir` on a descriptor-relative name is the atomic create: it either creates
 * the directory or fails, so an existing destination — empty, populated, or a
 * symlink to either — is rejected rather than merged into.
 */
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
  // `mode` is masked by the process umask, so the mode is applied again.
  fs.chmodSync(childPath, 0o700);

  const rootFd = openDirectoryNoFollow(childPath, 'export destination');
  const stats = fs.fstatSync(rootFd);
  return {
    root: destination,
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
 * Enforces the frozen ceiling against what has actually been written.
 *
 * The projection is checked before any byte is written; this is the second,
 * cumulative guard, so a source that grows between projection and copy cannot
 * carry the emitted bundle past the limit.
 */
function assertWithinBudget(written: number): void {
  if (written > MAX_EXPORT_BYTES) {
    throw createCodedError(
      'EXPORT_TOO_LARGE',
      `export has emitted ${written} bytes, exceeding the ${MAX_EXPORT_BYTES}-byte limit`,
    );
  }
}

/**
 * Writes a file directly into the bundle root, relative to the root descriptor.
 *
 * `manifest.json` lives beside the four subdirectories, so it cannot go through
 * `writeBundleFile`, which addresses a file inside one of them.
 */
function writeBundleRootFile(writer: BundleWriter, fileName: string, contents: Buffer): void {
  const fd = fs.openSync(
    pinnedChildPath(writer.rootFd, fileName),
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  try {
    fs.writeSync(fd, contents);
    fs.fchmodSync(fd, 0o600);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  writer.fileHashes.set(fileName, {
    sha256: crypto.createHash('sha256').update(contents).digest('hex'),
    bytes: contents.byteLength,
  });
  writer.totalBytes += contents.byteLength;
  assertWithinBudget(writer.totalBytes);
}

function writeBundleFile(writer: BundleWriter, relativePath: string, contents: Buffer): void {
  const slash = relativePath.indexOf('/');
  const dirName = relativePath.slice(0, slash);
  const fileName = relativePath.slice(slash + 1);
  const dirFd = writer.dirFds.get(dirName);
  if (dirFd === undefined) {
    throw createCodedError('EXPORT_FAILED', `bundle directory ${dirName}/ was never created`);
  }

  const fd = fs.openSync(
    pinnedChildPath(dirFd, fileName),
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600,
  );
  try {
    fs.writeSync(fd, contents);
    fs.fchmodSync(fd, 0o600);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  writer.fileHashes.set(relativePath, {
    sha256: crypto.createHash('sha256').update(contents).digest('hex'),
    bytes: contents.byteLength,
  });
  writer.totalBytes += contents.byteLength;
  assertWithinBudget(writer.totalBytes);
}

/**
 * Copies one verified source artifact into the bundle.
 *
 * The copy is bound to the identity recorded when the artifact was selected —
 * which is the identity that participated in verification. The source is
 * re-opened `O_NOFOLLOW`, its descriptor is required to still carry that same
 * device, inode and size, and the bytes are read from THAT descriptor. A
 * pathname swapped for a different file, even one of exactly the same length,
 * fails rather than contributing unverified bytes to a bundle that reports
 * success.
 */
function copyVerifiedArtifact(
  writer: BundleWriter,
  dirName: string,
  fileName: string,
  sourcePath: string,
  verified: EvidenceIdentity,
): void {
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

  let destFd: number;
  try {
    destFd = fs.openSync(
      pinnedChildPath(dirFd, fileName),
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch (err) {
    fs.closeSync(sourceFd);
    throw err;
  }

  const hash = crypto.createHash('sha256');
  let total = 0;
  try {
    const opened = fs.fstatSync(sourceFd);
    if (
      Number(opened.dev) !== verified.dev ||
      Number(opened.ino) !== verified.ino ||
      Number(opened.size) !== verified.size
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
      hash.update(slice);
      fs.writeSync(destFd, slice);
      total += read;
      assertWithinBudget(writer.totalBytes + total);
    }
    fs.fchmodSync(destFd, 0o600);
    fs.fsyncSync(destFd);

    const settled = fs.fstatSync(sourceFd);
    if (
      Number(settled.dev) !== verified.dev ||
      Number(settled.ino) !== verified.ino ||
      Number(settled.size) !== verified.size ||
      total !== verified.size
    ) {
      throw createCodedError(
        'EXPORT_SOURCE_CHANGED',
        `${fileName} changed while it was being copied`,
      );
    }
  } finally {
    fs.closeSync(destFd);
    fs.closeSync(sourceFd);
  }

  writer.fileHashes.set(`${dirName}/${fileName}`, { sha256: hash.digest('hex'), bytes: total });
  writer.totalBytes += total;
  assertWithinBudget(writer.totalBytes);
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
  try {
    fs.closeSync(writer.rootFd);
  } catch {
    // already closed
  }
}

/**
 * Removes only what this invocation created.
 *
 * The destination is removed only while it is still the very directory this call
 * created — same device and inode, re-checked against a live descriptor — so a
 * destination that was swapped, replaced or turned into a symlink after creation
 * is left strictly alone. Data whose identity cannot be proven is never deleted.
 */
function cleanupBundleRoot(writer: BundleWriter): void {
  try {
    const held = fs.fstatSync(writer.rootFd);
    if (
      Number(held.dev) !== writer.rootIdentity.dev ||
      Number(held.ino) !== writer.rootIdentity.ino
    ) {
      return;
    }
  } catch {
    return;
  }
  closeBundleWriter(writer);
  try {
    // `rmSync` follows the pathname, so it runs only after the descriptor above
    // proved the directory is still ours. The entries inside it are ours by
    // construction: the destination was created by this call and never merged
    // into.
    fs.rmSync(writer.root, { recursive: true, force: false });
  } catch {
    // Cleanup is best-effort by design. A failure to tidy up must never mask the
    // original export failure, and must never escalate into deleting something
    // whose identity was not proven.
  }
}

/* -------------------------------------------------------------------------- *
 * Evidence selection
 * -------------------------------------------------------------------------- */

interface SelectedArtifact {
  dirName: string;
  fileName: string;
  sourcePath: string;
  identity: EvidenceIdentity;
}

interface SelectedEvidence {
  artifacts: SelectedArtifact[];
  checkpointLineBytes: Buffer;
  receiptLineBytes: Buffer;
  checkpointHashes: string[];
  anchorReceiptIds: string[];
  /** Sum of every selected evidence byte, including the public keys. */
  projectedBytes: number;
  checkpointKeyBytes: Buffer;
  anchorKeyBytes: Buffer | null;
}

function readFileLines(filePath: string): string[] {
  const raw = fs.readFileSync(filePath, 'utf8');
  if (raw.length === 0) return [];
  if (!raw.endsWith('\n')) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `${path.basename(filePath)} is not LF-terminated`,
    );
  }
  return raw.slice(0, -1).split('\n');
}

function physicalForArchive(entry: LogicalArchiveEntry): PhysicalArchiveRepresentation {
  const chosen = entry.gzip ?? entry.plain;
  if (chosen === undefined) {
    throw createCodedError(
      'AUDIT_CORRUPTION_DETECTED',
      `rotated range ${entry.sequenceStart}..${entry.sequenceEnd} has no physical representation`,
    );
  }
  return chosen;
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
 * Chooses the authentic evidence that covers `[from, to]`.
 *
 * Whole primary artifacts are selected — never a synthesized partial segment —
 * so every emitted record keeps the exact bytes, and therefore the exact hash,
 * that the store produced. The checkpoint and receipt ledgers are line-oriented
 * signed artifacts, so the selected *lines* are copied byte-for-byte.
 *
 * The bundle must be able to authenticate its own evidence boundary: when the
 * first bundled primary artifact does not start at sequence 1, the checkpoint
 * that seals the range immediately before it is included too, so a reviewer can
 * prove the history *before* the bundle without trusting it.
 */
function selectEvidence(options: {
  directory: string;
  metadata: { anchorMode: 'DISABLED' | 'ENABLED' };
  from: number;
  to: number;
  expectedUid: number;
  checkpointKeyBytes: Buffer;
  anchorKeyBytes: Buffer | null;
}): SelectedEvidence {
  const { directory, metadata, from, to, expectedUid } = options;

  const archiveEntries = listLogicalArchiveInventory(directory, expectedUid);
  const intersecting = archiveEntries.filter(
    (entry) => entry.sequenceEnd >= from && entry.sequenceStart <= to,
  );

  const sources: RetainedSegmentSource[] = listRetainedSegmentSources(
    directory,
    expectedUid,
  ).filter(
    (source) =>
      source.kind === 'ACTIVE' || (source.sequenceEnd >= from && source.sequenceStart <= to),
  );

  const artifacts: SelectedArtifact[] = [];
  let projectedBytes = 0;

  for (const source of sources) {
    const identity = identityFor(source.filePath, source.label);
    artifacts.push({
      dirName: BUNDLE_AUDIT_DIRNAME,
      fileName: source.label,
      sourcePath: source.filePath,
      identity,
    });
    projectedBytes += identity.size;
  }
  for (const entry of intersecting) {
    // The projection uses the PHYSICAL size of the representation that will be
    // copied, which `listRetainedSegmentSources` already selected.
    void physicalForArchive(entry);
  }

  const boundarySequence = sources.reduce(
    (lowest, source) => Math.min(lowest, source.sequenceStart),
    Number.MAX_SAFE_INTEGER,
  );

  const checkpointPath = path.join(directory, CHECKPOINT_FILENAME);
  const checkpointLines: string[] = [];
  const checkpointHashes: string[] = [];
  if (fs.existsSync(checkpointPath)) {
    for (const line of readFileLines(checkpointPath)) {
      if (line.length === 0) continue;
      const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
      // A checkpoint belongs in the bundle when it covers part of the selected
      // range, or when it seals the range immediately before the bundle's own
      // evidence boundary.
      const coversRange = checkpoint.sequenceEnd >= from && checkpoint.sequenceStart <= to;
      const sealsBoundary =
        boundarySequence !== Number.MAX_SAFE_INTEGER &&
        boundarySequence > 1 &&
        checkpoint.sequenceEnd === boundarySequence - 1;
      if (!coversRange && !sealsBoundary) continue;
      checkpointLines.push(line);
      checkpointHashes.push(checkpoint.checkpointHash);
      projectedBytes += Buffer.byteLength(`${line}\n`, 'utf8');
    }
  }

  const receiptLines: string[] = [];
  const anchorReceiptIds: string[] = [];
  if (metadata.anchorMode === 'ENABLED') {
    const receiptPath = path.join(directory, ANCHOR_RECEIPT_FILENAME);
    if (fs.existsSync(receiptPath)) {
      const included = new Set(checkpointHashes);
      for (const line of readFileLines(receiptPath)) {
        if (line.length === 0) continue;
        const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
        if (!included.has(receipt.checkpointHash)) continue;
        receiptLines.push(line);
        anchorReceiptIds.push(receipt.receiptId);
        projectedBytes += Buffer.byteLength(`${line}\n`, 'utf8');
      }
    }
  }

  projectedBytes += options.checkpointKeyBytes.byteLength;
  if (options.anchorKeyBytes !== null) projectedBytes += options.anchorKeyBytes.byteLength;

  return {
    artifacts,
    checkpointLineBytes: Buffer.from(checkpointLines.map((line) => `${line}\n`).join(''), 'utf8'),
    receiptLineBytes: Buffer.from(receiptLines.map((line) => `${line}\n`).join(''), 'utf8'),
    checkpointHashes,
    anchorReceiptIds,
    projectedBytes,
    checkpointKeyBytes: options.checkpointKeyBytes,
    anchorKeyBytes: options.anchorKeyBytes,
  };
}

/**
 * The exact serialized size of the manifest that will be written.
 *
 * Digest fields are always 64 lowercase hex characters, so substituting a
 * fixed-width placeholder produces a manifest of exactly the real length. That
 * makes the manifest's own contribution to the byte budget knowable BEFORE it is
 * written, rather than discovered after the ceiling has already been passed.
 */
function predictManifestBytes(
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
  // afterwards, a source replaced while verification was reading it would be
  // invisible to the comparison while the copy went on to emit the replacement
  // — bytes that were never authenticated. Opening it here means every byte the
  // bundle receives was stable across the whole operation, verification
  // included.
  const inventoryBefore = snapshotEvidenceInventory(options.directory, expectedUid);

  // The declared range must be the range the bundle actually covers, so `--to`
  // is clamped to the verified terminal sequence rather than left at an
  // open-ended sentinel. A range that starts past the end of the store is not a
  // range at all, and is rejected rather than silently exported empty.
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

  // A bundle whose public key does not match the store's durable pin is a bundle
  // nobody can ever verify. Refuse to emit one.
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
  const anchorTrustRoot =
    metadata.anchorMode === 'ENABLED' && options.anchorReceiptPublicKeyPath !== undefined
      ? loadEd25519TrustRootFile(options.anchorReceiptPublicKeyPath, {
          purpose: 'ANCHOR_RECEIPT',
          expectedUid,
        })
      : null;
  if (
    anchorTrustRoot !== null &&
    anchorTrustRoot.fingerprint !== metadata.anchorReceiptPublicKeyFingerprint
  ) {
    throw createCodedError(
      'EXPORT_KEY_MISMATCH',
      'anchor receipt public key does not match audit-store.json.anchorReceiptPublicKeyFingerprint',
    );
  }

  const checkpointKeyBytes = fs.readFileSync(options.checkpointPublicKeyPath);
  const anchorKeyBytes =
    anchorTrustRoot !== null && options.anchorReceiptPublicKeyPath !== undefined
      ? fs.readFileSync(options.anchorReceiptPublicKeyPath)
      : null;

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
    checkpointKeyBytes,
    anchorKeyBytes,
  });

  // The projection covers EVERY emitted file: primary artifacts, both ledgers,
  // the public keys, and the manifest itself.
  const emittedBytes = new Map<string, number>();
  for (const artifact of evidence.artifacts) {
    emittedBytes.set(`${artifact.dirName}/${artifact.fileName}`, artifact.identity.size);
  }
  emittedBytes.set(
    `${BUNDLE_CHECKPOINTS_DIRNAME}/${CHECKPOINT_FILENAME}`,
    evidence.checkpointLineBytes.byteLength,
  );
  emittedBytes.set(
    `${BUNDLE_ANCHORS_DIRNAME}/${ANCHOR_RECEIPT_FILENAME}`,
    evidence.receiptLineBytes.byteLength,
  );
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

  const manifestHeader = {
    version: 1 as const,
    storeId: metadata.storeId,
    sequenceRange: { start: from, end: rangeEnd },
    checkpointHashes: evidence.checkpointHashes,
    anchorReceiptIds: evidence.anchorReceiptIds,
  };
  const manifestBytes = predictManifestBytes(manifestHeader, emittedBytes);
  assertExportWithinBudget(evidence.projectedBytes + manifestBytes);

  const { parentFd, leafName } = openPinnedParent(destination);
  let writer: BundleWriter;
  try {
    writer = createBundleRoot(parentFd, leafName, destination);
  } finally {
    fs.closeSync(parentFd);
  }

  try {
    createBundleDirectory(writer, BUNDLE_AUDIT_DIRNAME);
    createBundleDirectory(writer, BUNDLE_CHECKPOINTS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_ANCHORS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_PUBLIC_KEYS_DIRNAME);

    for (const artifact of evidence.artifacts) {
      copyVerifiedArtifact(
        writer,
        artifact.dirName,
        artifact.fileName,
        artifact.sourcePath,
        artifact.identity,
      );
    }

    writeBundleFile(
      writer,
      `${BUNDLE_CHECKPOINTS_DIRNAME}/${CHECKPOINT_FILENAME}`,
      evidence.checkpointLineBytes,
    );
    writeBundleFile(
      writer,
      `${BUNDLE_ANCHORS_DIRNAME}/${ANCHOR_RECEIPT_FILENAME}`,
      evidence.receiptLineBytes,
    );
    writeBundleFile(
      writer,
      `${BUNDLE_PUBLIC_KEYS_DIRNAME}/${BUNDLE_CHECKPOINT_KEY_FILENAME}`,
      checkpointKeyBytes,
    );
    if (anchorKeyBytes !== null) {
      writeBundleFile(
        writer,
        `${BUNDLE_PUBLIC_KEYS_DIRNAME}/${BUNDLE_ANCHOR_KEY_FILENAME}`,
        anchorKeyBytes,
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

    const manifest: ExportManifest = { ...manifestHeader, files };
    writeBundleRootFile(
      writer,
      BUNDLE_MANIFEST_FILENAME,
      Buffer.from(`${canonicalJsonV1(manifest)}\n`, 'utf8'),
    );

    const totalBytes = writer.totalBytes;
    const fileCount = writer.fileHashes.size;
    closeBundleWriter(writer);
    return { outputDirectory: destination, manifest, fileCount, totalBytes };
  } catch (err) {
    cleanupBundleRoot(writer);
    throw err;
  }
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
 * Streams a manifest-listed file, hashing it without materializing it.
 *
 * A 10 MiB uncompressed segment must never be read wholly into memory merely to
 * be digested, so the digest is computed chunk by chunk.
 */
function digestFile(filePath: string): { sha256: string; bytes: number } {
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
 * Splits a ledger into its canonical lines with STRICT LF framing.
 *
 * A line-oriented reader that strips terminators would silently accept an
 * unterminated final record as a valid one. Here a final fragment with no
 * terminator is a corruption, never a record.
 */
function strictLines(raw: string, label: string): string[] {
  if (raw.length === 0) return [];
  if (!raw.endsWith('\n')) {
    throw createCodedError('BUNDLE_LINE_FRAMING_INVALID', `${label} ends in an unterminated line`);
  }
  const body = raw.slice(0, -1);
  if (body.includes('\r')) {
    throw createCodedError('BUNDLE_LINE_FRAMING_INVALID', `${label} contains a CR`);
  }
  if (body.length === 0) return [];
  return body.split('\n');
}

/**
 * Re-verifies a bundle from its own contents and public material only.
 *
 * Every manifest digest is recomputed against the emitted bytes, checkpoint and
 * receipt signatures are checked against the bundled public keys with the same
 * Task-4 and Task-5 rules the store verifier uses, and the bundled primary
 * artifacts are streamed to prove they form one contiguous chain that covers the
 * declared range and can authenticate its own evidence boundary.
 */
export async function verifyEvidenceBundle(bundleDirectory: string): Promise<VerifyBundleResult> {
  const root = assertPathShape(bundleDirectory, 'bundle directory');
  const manifestRaw = fs.readFileSync(path.join(root, BUNDLE_MANIFEST_FILENAME), 'utf8');
  const manifest = JSON.parse(manifestRaw) as ExportManifest;
  if (manifest.version !== 1) {
    throw createCodedError('BUNDLE_MANIFEST_INVALID', 'unsupported bundle manifest version');
  }

  // 1. Every listed file: streamed digest, never a whole-file read.
  for (const [relativePath, entry] of Object.entries(manifest.files)) {
    if (relativePath.includes('..') || path.isAbsolute(relativePath)) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', 'manifest lists a path outside the bundle');
    }
    const full = path.join(root, relativePath);
    if (!fs.existsSync(full)) {
      throw createCodedError('BUNDLE_FILE_MISSING', `manifest file ${relativePath} is absent`);
    }
    const digest = digestFile(full);
    if (digest.sha256 !== entry.sha256 || digest.bytes !== entry.bytes) {
      throw createCodedError(
        'BUNDLE_DIGEST_MISMATCH',
        `manifest digest for ${relativePath} does not match the emitted bytes`,
      );
    }
  }

  const checkpointKeyPath = path.join(
    root,
    BUNDLE_PUBLIC_KEYS_DIRNAME,
    BUNDLE_CHECKPOINT_KEY_FILENAME,
  );
  if (!fs.existsSync(checkpointKeyPath)) {
    throw createCodedError('BUNDLE_KEY_MISSING', 'the bundle carries no checkpoint public key');
  }
  const checkpointKey = loadEd25519TrustRootFile(checkpointKeyPath, { purpose: 'CHECKPOINT' });
  // The loader's fingerprint is the SHA-256 of the key's SPKI DER — exactly the
  // value a checkpoint carries in `publicKeyFingerprint`.
  const checkpointFingerprint = checkpointKey.fingerprint;

  // 2. The primary chain: streamed, strictly framed, contiguous.
  const chain = await verifyBundledChain(
    path.join(root, BUNDLE_AUDIT_DIRNAME),
    manifest.sequenceRange,
  );

  // 3. Checkpoints: every Task-4 rule that binds one to this store and range.
  const checkpointRaw = fs.readFileSync(
    path.join(root, BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME),
    'utf8',
  );
  const checkpoints = strictLines(checkpointRaw, CHECKPOINT_FILENAME).map(
    (line) => parseAndValidateCheckpointLineV1(`${line}\n`).checkpoint,
  );

  let previousHash = '0'.repeat(64);
  for (const checkpoint of checkpoints) {
    if (checkpoint.storeId !== manifest.storeId) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_STORE_MISMATCH',
        'a bundled checkpoint names a different store than the manifest',
      );
    }
    if (checkpoint.publicKeyFingerprint !== checkpointFingerprint) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_KEY_MISMATCH',
        'a bundled checkpoint is bound to a different public key than the bundle carries',
      );
    }
    if (
      !Number.isSafeInteger(checkpoint.sequenceStart) ||
      !Number.isSafeInteger(checkpoint.sequenceEnd) ||
      checkpoint.sequenceStart > checkpoint.sequenceEnd
    ) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_RANGE_INVALID',
        'a bundled checkpoint declares an invalid sequence range',
      );
    }
    if (checkpoint.previousCheckpointHash !== previousHash) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_CHAIN_BROKEN',
        'bundled checkpoints do not form one unbroken chain',
      );
    }
    if (!verifyCheckpointSignature(checkpoint, checkpointKey.publicKey)) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
        'a bundled checkpoint signature does not verify',
      );
    }
    if (computeCheckpointHash(checkpoint) !== checkpoint.checkpointHash) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_HASH_INVALID',
        'a bundled checkpoint hash is not the hash of its own contents',
      );
    }
    previousHash = checkpoint.checkpointHash;
  }

  // Every checkpoint that covers a sequence present in the bundle must bind to
  // the record the bundled chain actually carries there.
  for (const checkpoint of checkpoints) {
    const covered = chain.bySequence.get(checkpoint.sequenceEnd);
    if (covered === undefined) continue; // outside this bundle's evidence
    if (covered !== checkpoint.terminalRecordHash) {
      throw createCodedError(
        'BUNDLE_CHECKPOINT_TERMINAL_MISMATCH',
        'a bundled checkpoint does not bind to the bundled primary record it covers',
      );
    }
  }

  const manifestHashes = checkpoints.map((checkpoint) => checkpoint.checkpointHash);
  if (
    manifestHashes.length !== manifest.checkpointHashes.length ||
    manifestHashes.some((hash, index) => hash !== manifest.checkpointHashes[index])
  ) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_MISMATCH',
      'bundled checkpoints do not match the manifest checkpoint hashes',
    );
  }

  // 4. The evidence boundary must be authenticated. Sequence 1 is genesis;
  //    a bundle that begins later must be sealed by a bundled checkpoint that
  //    binds to the record immediately before its first record.
  if (chain.coveredSequenceStart > 1) {
    const boundarySeal = checkpoints.find(
      (checkpoint) => checkpoint.sequenceEnd === chain.coveredSequenceStart - 1,
    );
    if (boundarySeal === undefined) {
      throw createCodedError(
        'BUNDLE_BOUNDARY_UNVERIFIED',
        'the bundle begins mid-history without a checkpoint sealing the evidence before it',
      );
    }
    const boundaryPredecessor = chain.boundaryPredecessorHash;
    if (
      boundaryPredecessor === undefined ||
      boundarySeal.terminalRecordHash !== boundaryPredecessor
    ) {
      throw createCodedError(
        'BUNDLE_BOUNDARY_UNVERIFIED',
        'the bundled boundary checkpoint does not bind to the evidence before the bundle',
      );
    }
  }

  // 5. Receipts: signature, key, store and checkpoint binding, no duplicates.
  const anchorRaw = fs.readFileSync(
    path.join(root, BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME),
    'utf8',
  );
  const receiptLines = strictLines(anchorRaw, ANCHOR_RECEIPT_FILENAME);
  const seenReceiptIds: string[] = [];
  if (receiptLines.length > 0) {
    const anchorKeyPath = path.join(root, BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_ANCHOR_KEY_FILENAME);
    if (!fs.existsSync(anchorKeyPath)) {
      throw createCodedError('BUNDLE_KEY_MISSING', 'the bundle carries receipts but no anchor key');
    }
    const anchorKey = loadEd25519TrustRootFile(anchorKeyPath, { purpose: 'ANCHOR_RECEIPT' });
    const checkpointSet = new Set(manifestHashes);
    const seen = new Set<string>();
    for (const line of receiptLines) {
      const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
      if (!verifyAnchorReceiptSignature(receipt, anchorKey.publicKey)) {
        throw createCodedError(
          'BUNDLE_RECEIPT_SIGNATURE_INVALID',
          'a bundled anchor receipt signature does not verify',
        );
      }
      if (receipt.anchorKeyFingerprint !== anchorKey.fingerprint) {
        throw createCodedError(
          'BUNDLE_RECEIPT_KEY_MISMATCH',
          'a bundled receipt is bound to a different key than the bundle carries',
        );
      }
      // A receipt proves something about THIS store. A validly signed receipt
      // from another store must not verify merely because its checkpoint hash
      // looks well-formed.
      if (receipt.storeId !== manifest.storeId) {
        throw createCodedError(
          'BUNDLE_RECEIPT_STORE_MISMATCH',
          'a bundled receipt names a different store than the manifest',
        );
      }
      if (!checkpointSet.has(receipt.checkpointHash)) {
        throw createCodedError(
          'BUNDLE_RECEIPT_ORPHAN',
          'a bundled anchor receipt references a checkpoint the bundle does not carry',
        );
      }
      if (seen.has(receipt.receiptId)) {
        throw createCodedError(
          'BUNDLE_RECEIPT_DUPLICATE',
          'a bundled receipt id appears more than once',
        );
      }
      seen.add(receipt.receiptId);
      seenReceiptIds.push(receipt.receiptId);
    }
  }
  if (
    seenReceiptIds.length !== manifest.anchorReceiptIds.length ||
    seenReceiptIds.some((id, index) => id !== manifest.anchorReceiptIds[index])
  ) {
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
    checkpointCount: checkpoints.length,
    anchorReceiptCount: seenReceiptIds.length,
    coveredSequenceStart: chain.coveredSequenceStart,
    coveredSequenceEnd: chain.coveredSequenceEnd,
  };
}

interface BundledChain {
  coveredSequenceStart: number;
  coveredSequenceEnd: number;
  /** recordHash of every bundled record, by sequence. */
  bySequence: Map<number, string>;
  /**
   * `previousRecordHash` of the bundle's first record.
   *
   * For a bundle that does not start at sequence 1 this is the hash the evidence
   * BEFORE the bundle must terminate at, and it is what a boundary checkpoint
   * has to bind to.
   */
  boundaryPredecessorHash: string | undefined;
}

/**
 * Streams the bundled primary artifacts as one chain.
 *
 * The chain must be contiguous from its first record onward, and it must cover
 * the whole declared inclusive range. A bundle that reaches `start` but stops
 * before `end` is under-covering evidence and fails.
 *
 * A bundle whose range begins mid-history legitimately does not start at
 * sequence 1; its boundary is authenticated separately, against a bundled
 * checkpoint, rather than by disabling continuity checking.
 */
async function verifyBundledChain(
  auditDir: string,
  sequenceRange: { start: number; end: number },
): Promise<BundledChain> {
  const names = fs.readdirSync(auditDir).sort();
  if (names.length === 0) {
    throw createCodedError('BUNDLE_RANGE_NOT_COVERED', 'the bundle carries no primary evidence');
  }

  const bySequence = new Map<number, string>();
  let expectedSequence = null;
  let previousHash = null;
  let boundaryPredecessorHash;

  for (const name of names) {
    const parsed = name === ACTIVE_SEGMENT_FILENAME ? null : parseRotatedSegmentFilename(name);
    if (name !== ACTIVE_SEGMENT_FILENAME && parsed === null) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', `unrecognized bundle artifact ${name}`);
    }
    const source: RetainedSegmentSource = {
      kind: parsed === null ? 'ACTIVE' : 'ARCHIVE',
      label: name,
      filePath: path.join(auditDir, name),
      compressed: name.endsWith('.gz'),
      sequenceStart: parsed === null ? 0 : parsed.sequenceStart,
      sequenceEnd: parsed === null ? Number.MAX_SAFE_INTEGER : parsed.sequenceEnd,
    };

    for await (const record of streamRetainedRecords([source], { strictFraming: true })) {
      if (expectedSequence === null) {
        expectedSequence = record.sequenceNumber;
        boundaryPredecessorHash = record.integrity.previousRecordHash;
        previousHash =
          record.sequenceNumber === 1 ? '0'.repeat(64) : record.integrity.previousRecordHash;
      }
      if (record.sequenceNumber !== expectedSequence) {
        throw createCodedError(
          'BUNDLE_CHAIN_BROKEN',
          `bundled primary history is not contiguous at sequence ${expectedSequence}`,
        );
      }
      if (record.integrity.previousRecordHash !== previousHash) {
        throw createCodedError(
          'BUNDLE_CHAIN_BROKEN',
          `bundled primary hash link is broken at sequence ${record.sequenceNumber}`,
        );
      }
      previousHash = record.integrity.recordHash;
      bySequence.set(record.sequenceNumber, record.integrity.recordHash);
      expectedSequence += 1;
    }
  }

  const coveredSequenceStart = Math.min(...bySequence.keys());
  const coveredSequenceEnd = Math.max(...bySequence.keys());

  // The declared range must be fully covered. Reaching the start is not enough.
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
  for (let sequence = sequenceRange.start; sequence <= sequenceRange.end; sequence += 1) {
    if (!bySequence.has(sequence)) {
      throw createCodedError(
        'BUNDLE_RANGE_NOT_COVERED',
        `the bundle does not carry sequence ${sequence} of its declared range`,
      );
    }
  }

  return { coveredSequenceStart, coveredSequenceEnd, bySequence, boundaryPredecessorHash };
}
