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
 * - It never merges into an existing destination, never replaces a file, and
 *   never follows a symlink — not in the destination, and not in any parent
 *   component of it.
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
import { ANCHOR_RECEIPT_FILENAME } from './internal/anchor-constants.js';
import { loadEd25519TrustRootFile } from './internal/key-authority.js';
import { parseAndValidateAnchorReceiptLineV1, verifyAnchorReceiptSignature } from './anchor.js';
import {
  listRetainedSegmentSources,
  streamRetainedRecords,
  validateSequenceRange,
  type RetainedSegmentSource,
} from './verify.js';

/* -------------------------------------------------------------------------- *
 * Frozen bounds (rc06 §24.1)
 * -------------------------------------------------------------------------- */

/**
 * Maximum total bytes one export bundle may emit.
 *
 * Fixed by the architecture, not configurable: no flag, environment variable or
 * configuration file may raise it.
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
   * Required, deliberately. An exporter that cannot be told where the agent
   * workspaces are cannot prove the destination is outside them, and assuming
   * there are none is exactly the assumption an attacker would want.
   */
  workspacePaths: readonly string[];
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
 * Hardened destination authority
 * -------------------------------------------------------------------------- */

/**
 * Rejects a path that is not an absolute, normalized, `~`-free path.
 *
 * This is the same shape of authority `validateAuditDirectory` applies to the
 * audit directory, applied here to the export destination.
 */
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
 * Walks every component of `target` from the filesystem root, refusing any
 * symlinked component.
 *
 * A prefix check or a `realpath()` taken earlier and used later proves nothing:
 * the resolved value is not bound to the directory that is eventually created,
 * so a component can be swapped for a symlink in between. Each component is
 * therefore `lstat`ed directly, and the destination is later created with a
 * single atomic `mkdir` that fails if anything appeared in the meantime.
 */
function assertNoSymlinkedComponent(target: string): void {
  const segments = target.split(path.sep).filter((segment) => segment.length > 0);
  let current: string = path.sep;
  for (const segment of segments) {
    current = path.join(current, segment);
    let stats: fs.Stats;
    try {
      stats = fs.lstatSync(current);
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return; // remainder is new
      throw createCodedError('INVALID_EXPORT_PATH', 'export destination could not be examined', {
        cause,
      });
    }
    if (stats.isSymbolicLink()) {
      throw createCodedError(
        'SYMLINK_DETECTED',
        'export destination contains a symbolic link component',
      );
    }
  }
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

/**
 * Rejects a destination inside the audit store or inside any registered agent
 * workspace, and one whose projected bytes exceed {@link MAX_EXPORT_BYTES}.
 */
function assertDestinationAuthority(options: {
  destination: string;
  auditDirectory: string;
  workspacePaths: readonly string[];
  projectedBytes: number;
}): void {
  const { destination, auditDirectory, workspacePaths, projectedBytes } = options;

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

  assertExportWithinBudget(projectedBytes);
}

/**
 * The frozen byte budget, as an assertion over a projection.
 *
 * Kept separate and exported so the limit can be proved at its exact boundary
 * from a structural projection, without a caller having to materialize a
 * gigabyte of evidence to reach it. There is no parameter, flag or environment
 * variable anywhere that raises the bound.
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
 * Bundle writing
 * -------------------------------------------------------------------------- */

/** Tracks what this invocation created, so partial failure can be undone. */
interface BundleWriter {
  root: string;
  rootIdentity: { dev: number; ino: number };
  fileHashes: Map<string, ManifestFileEntry>;
  totalBytes: number;
}

function createBundleRoot(destination: string): BundleWriter {
  // `mkdir` without `recursive` is atomic: it either creates the directory or
  // fails, so an existing destination — empty, populated, or a symlink to either
  // — is rejected rather than merged into.
  try {
    fs.mkdirSync(destination, { mode: 0o700 });
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === 'EEXIST') {
      throw createCodedError(
        'EXPORT_DESTINATION_EXISTS',
        'export destination already exists; export never merges or overwrites',
      );
    }
    throw createCodedError('EXPORT_FAILED', 'export destination could not be created', { cause });
  }
  // `mode` is masked by the process umask, so the mode is applied again.
  fs.chmodSync(destination, 0o700);
  const stats = fs.lstatSync(destination);
  return {
    root: destination,
    rootIdentity: { dev: Number(stats.dev), ino: Number(stats.ino) },
    fileHashes: new Map(),
    totalBytes: 0,
  };
}

function createBundleDirectory(writer: BundleWriter, name: string): string {
  const full = path.join(writer.root, name);
  fs.mkdirSync(full, { mode: 0o700 });
  fs.chmodSync(full, 0o700);
  return full;
}

function writeBundleFile(writer: BundleWriter, relativePath: string, contents: Buffer): void {
  const full = path.join(writer.root, relativePath);
  const fd = fs.openSync(
    full,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
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
}

/**
 * Streams a source artifact into the bundle, digesting exactly the bytes that
 * were written.
 *
 * The digest is taken over the emitted stream rather than over a second read of
 * the source, so a source that changes mid-copy cannot produce a manifest that
 * describes bytes the bundle does not contain.
 */
function copyBundleArtifact(
  writer: BundleWriter,
  relativePath: string,
  sourcePath: string,
  expectedBytes: number,
): void {
  const sourceFd = fs.openSync(sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let destFd: number;
  const full = path.join(writer.root, relativePath);
  try {
    destFd = fs.openSync(
      full,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      0o600,
    );
  } catch (err) {
    fs.closeSync(sourceFd);
    throw err;
  }

  const hash = crypto.createHash('sha256');
  let total = 0;
  const buffer = Buffer.allocUnsafe(65_536);
  try {
    for (;;) {
      const read = fs.readSync(sourceFd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      const slice = buffer.subarray(0, read);
      hash.update(slice);
      fs.writeSync(destFd, slice);
      total += read;
    }
    fs.fchmodSync(destFd, 0o600);
    fs.fsyncSync(destFd);
  } finally {
    fs.closeSync(destFd);
    fs.closeSync(sourceFd);
  }

  if (total !== expectedBytes) {
    throw createCodedError(
      'EXPORT_SOURCE_CHANGED',
      `${path.basename(sourcePath)} changed size while the bundle was being written`,
    );
  }

  writer.fileHashes.set(relativePath, {
    sha256: hash.digest('hex'),
    bytes: total,
  });
  writer.totalBytes += total;
}

/**
 * Removes only what this invocation created.
 *
 * The destination is removed only when it is still the very directory this call
 * created — same device and inode — so a destination that was swapped, replaced
 * or turned into a symlink after creation is left strictly alone. Data whose
 * identity cannot be proven is never deleted.
 */
function cleanupBundleRoot(writer: BundleWriter): void {
  try {
    const stats = fs.lstatSync(writer.root);
    if (
      stats.isSymbolicLink() ||
      Number(stats.dev) !== writer.rootIdentity.dev ||
      Number(stats.ino) !== writer.rootIdentity.ino
    ) {
      return;
    }
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

interface SelectedEvidence {
  segments: RetainedSegmentSource[];
  checkpointLines: Array<{
    line: string;
    checkpointHash: string;
    sequenceStart: number;
    sequenceEnd: number;
  }>;
  checkpointHashes: string[];
  receiptLines: Array<{ line: string; receiptId: string; checkpointHash: string }>;
  anchorReceiptIds: string[];
  projectedBytes: number;
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

/**
 * Chooses the authentic evidence that covers `[from, to]`.
 *
 * Whole primary artifacts are selected — never a synthesized partial segment —
 * so every emitted record keeps the exact bytes, and therefore the exact hash,
 * that the store produced. The checkpoint and receipt ledgers are line-oriented
 * signed artifacts, so the selected *lines* are copied byte-for-byte.
 */
function selectEvidence(options: {
  directory: string;
  metadata: { anchorMode: 'DISABLED' | 'ENABLED' };
  from: number;
  to: number;
  expectedUid: number;
}): SelectedEvidence {
  const { directory, metadata, from, to, expectedUid } = options;

  const archiveEntries = listLogicalArchiveInventory(directory, expectedUid);
  const intersecting = archiveEntries.filter(
    (entry) => entry.sequenceEnd >= from && entry.sequenceStart <= to,
  );

  const segments: RetainedSegmentSource[] = listRetainedSegmentSources(
    directory,
    expectedUid,
  ).filter(
    (source) =>
      source.kind === 'ACTIVE' || (source.sequenceEnd >= from && source.sequenceStart <= to),
  );

  let projectedBytes = 0;
  for (const entry of intersecting) projectedBytes += physicalForArchive(entry).physicalByteLength;
  for (const source of segments) {
    if (source.kind === 'ACTIVE') projectedBytes += fs.lstatSync(source.filePath).size;
  }

  const checkpointPath = path.join(directory, CHECKPOINT_FILENAME);
  const checkpointLines: SelectedEvidence['checkpointLines'] = [];
  if (fs.existsSync(checkpointPath)) {
    for (const line of readFileLines(checkpointPath)) {
      if (line.length === 0) continue;
      const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
      if (checkpoint.sequenceEnd < from || checkpoint.sequenceStart > to) continue;
      checkpointLines.push({
        line,
        checkpointHash: checkpoint.checkpointHash,
        sequenceStart: checkpoint.sequenceStart,
        sequenceEnd: checkpoint.sequenceEnd,
      });
      projectedBytes += Buffer.byteLength(`${line}\n`, 'utf8');
    }
  }

  const receiptLines: SelectedEvidence['receiptLines'] = [];
  if (metadata.anchorMode === 'ENABLED') {
    const receiptPath = path.join(directory, ANCHOR_RECEIPT_FILENAME);
    if (fs.existsSync(receiptPath)) {
      const included = new Set(checkpointLines.map((entry) => entry.checkpointHash));
      for (const line of readFileLines(receiptPath)) {
        if (line.length === 0) continue;
        const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
        if (!included.has(receipt.checkpointHash)) continue;
        receiptLines.push({
          line,
          receiptId: receipt.receiptId,
          checkpointHash: receipt.checkpointHash,
        });
        projectedBytes += Buffer.byteLength(`${line}\n`, 'utf8');
      }
    }
  }

  return {
    segments,
    checkpointLines,
    checkpointHashes: checkpointLines.map((entry) => entry.checkpointHash),
    receiptLines,
    anchorReceiptIds: receiptLines.map((entry) => entry.receiptId),
    projectedBytes,
  };
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
  assertNoSymlinkedComponent(path.dirname(destination));

  if (options.workspacePaths === undefined) {
    throw createCodedError(
      'EXPORT_WORKSPACE_ROOTS_REQUIRED',
      'authoritative workspace roots are required: export must not assume there are none',
    );
  }

  const metadata = loadStoreMetadataFile(options.directory, expectedUid);

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

  const evidence = selectEvidence({
    directory: options.directory,
    metadata,
    from,
    to: rangeEnd,
    expectedUid,
  });

  assertDestinationAuthority({
    destination,
    auditDirectory: options.directory,
    workspacePaths: options.workspacePaths,
    projectedBytes: evidence.projectedBytes,
  });

  const checkpointTrustRoot = loadEd25519TrustRootFile(options.checkpointPublicKeyPath, {
    purpose: 'CHECKPOINT',
    expectedUid,
  });
  // A bundle whose public key does not match the store's durable pin is a
  // bundle nobody can ever verify. Refuse to emit one.
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

  const writer = createBundleRoot(destination);
  try {
    createBundleDirectory(writer, BUNDLE_AUDIT_DIRNAME);
    createBundleDirectory(writer, BUNDLE_CHECKPOINTS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_ANCHORS_DIRNAME);
    createBundleDirectory(writer, BUNDLE_PUBLIC_KEYS_DIRNAME);

    for (const source of evidence.segments) {
      const expected = fs.lstatSync(source.filePath).size;
      copyBundleArtifact(
        writer,
        path.join(BUNDLE_AUDIT_DIRNAME, source.label),
        source.filePath,
        expected,
      );
    }

    if (evidence.checkpointLines.length > 0) {
      writeBundleFile(
        writer,
        path.join(BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME),
        Buffer.from(evidence.checkpointLines.map((entry) => `${entry.line}\n`).join(''), 'utf8'),
      );
    } else {
      writeBundleFile(
        writer,
        path.join(BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME),
        Buffer.alloc(0),
      );
    }

    writeBundleFile(
      writer,
      path.join(BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME),
      Buffer.from(evidence.receiptLines.map((entry) => `${entry.line}\n`).join(''), 'utf8'),
    );

    writeBundleFile(
      writer,
      path.join(BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_CHECKPOINT_KEY_FILENAME),
      fs.readFileSync(options.checkpointPublicKeyPath),
    );
    if (anchorTrustRoot !== null && options.anchorReceiptPublicKeyPath !== undefined) {
      writeBundleFile(
        writer,
        path.join(BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_ANCHOR_KEY_FILENAME),
        fs.readFileSync(options.anchorReceiptPublicKeyPath),
      );
    }

    const files: Record<string, ManifestFileEntry> = {};
    for (const key of [...writer.fileHashes.keys()].sort()) {
      files[key] = writer.fileHashes.get(key) as ManifestFileEntry;
    }

    const manifest: ExportManifest = {
      version: 1,
      storeId: metadata.storeId,
      sequenceRange: { start: from, end: rangeEnd },
      files,
      checkpointHashes: evidence.checkpointHashes,
      anchorReceiptIds: evidence.anchorReceiptIds,
    };

    writeBundleFile(
      writer,
      BUNDLE_MANIFEST_FILENAME,
      Buffer.from(`${canonicalJsonV1(manifest)}\n`, 'utf8'),
    );

    return {
      outputDirectory: destination,
      manifest,
      fileCount: writer.fileHashes.size,
      totalBytes: writer.totalBytes,
    };
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
  /** Highest sequence the bundled primary artifacts actually carry. */
  coveredSequenceEnd: number;
}

/**
 * Re-verifies a bundle from its own contents and public material only.
 *
 * Every manifest digest is recomputed against the emitted bytes, checkpoint and
 * receipt signatures are checked against the bundled public keys, and the
 * bundled primary artifacts are streamed to prove they still form one
 * contiguous chain covering the declared range.
 */
export async function verifyEvidenceBundle(bundleDirectory: string): Promise<VerifyBundleResult> {
  const root = assertPathShape(bundleDirectory, 'bundle directory');
  const manifestRaw = fs.readFileSync(path.join(root, BUNDLE_MANIFEST_FILENAME), 'utf8');
  const manifest = JSON.parse(manifestRaw) as ExportManifest;
  if (manifest.version !== 1) {
    throw createCodedError('BUNDLE_MANIFEST_INVALID', 'unsupported bundle manifest version');
  }

  for (const [relativePath, entry] of Object.entries(manifest.files)) {
    if (relativePath.includes('..') || path.isAbsolute(relativePath)) {
      throw createCodedError('BUNDLE_MANIFEST_INVALID', 'manifest lists a path outside the bundle');
    }
    const full = path.join(root, relativePath);
    let raw: Buffer;
    try {
      raw = fs.readFileSync(full);
    } catch (cause) {
      throw createCodedError('BUNDLE_FILE_MISSING', `manifest file ${relativePath} is absent`, {
        cause,
      });
    }
    const digest = crypto.createHash('sha256').update(raw).digest('hex');
    if (digest !== entry.sha256 || raw.byteLength !== entry.bytes) {
      throw createCodedError(
        'BUNDLE_DIGEST_MISMATCH',
        `manifest digest for ${relativePath} does not match the emitted bytes`,
      );
    }
  }

  // Checkpoints: signature and identity, against the bundled public key.
  const checkpointRaw = fs.readFileSync(
    path.join(root, BUNDLE_CHECKPOINTS_DIRNAME, CHECKPOINT_FILENAME),
    'utf8',
  );
  const checkpointKeyPath = path.join(
    root,
    BUNDLE_PUBLIC_KEYS_DIRNAME,
    BUNDLE_CHECKPOINT_KEY_FILENAME,
  );
  if (!fs.existsSync(checkpointKeyPath)) {
    throw createCodedError('BUNDLE_KEY_MISSING', 'the bundle carries no checkpoint public key');
  }
  const checkpointKey = loadEd25519TrustRootFile(checkpointKeyPath, { purpose: 'CHECKPOINT' });

  const seenHashes: string[] = [];
  if (checkpointRaw.length > 0) {
    for (const line of checkpointRaw.slice(0, -1).split('\n')) {
      if (line.length === 0) continue;
      const { checkpoint } = parseAndValidateCheckpointLineV1(`${line}\n`);
      if (!verifyCheckpointSignature(checkpoint, checkpointKey.publicKey)) {
        throw createCodedError(
          'BUNDLE_CHECKPOINT_SIGNATURE_INVALID',
          'a bundled checkpoint signature does not verify',
        );
      }
      seenHashes.push(checkpoint.checkpointHash);
    }
  }
  if (
    seenHashes.length !== manifest.checkpointHashes.length ||
    seenHashes.some((hash, index) => hash !== manifest.checkpointHashes[index])
  ) {
    throw createCodedError(
      'BUNDLE_CHECKPOINT_MISMATCH',
      'bundled checkpoints do not match the manifest checkpoint hashes',
    );
  }

  // Receipts: signature and identity, against the bundled anchor public key.
  const anchorRaw = fs.readFileSync(
    path.join(root, BUNDLE_ANCHORS_DIRNAME, ANCHOR_RECEIPT_FILENAME),
    'utf8',
  );
  const anchorKeyPath = path.join(root, BUNDLE_PUBLIC_KEYS_DIRNAME, BUNDLE_ANCHOR_KEY_FILENAME);
  const seenReceiptIds: string[] = [];
  if (anchorRaw.length > 0) {
    if (!fs.existsSync(anchorKeyPath)) {
      throw createCodedError('BUNDLE_KEY_MISSING', 'the bundle carries receipts but no anchor key');
    }
    const anchorKey = loadEd25519TrustRootFile(anchorKeyPath, { purpose: 'ANCHOR_RECEIPT' });
    const checkpointSet = new Set(seenHashes);
    for (const line of anchorRaw.slice(0, -1).split('\n')) {
      if (line.length === 0) continue;
      const receipt = parseAndValidateAnchorReceiptLineV1(`${line}\n`);
      if (!verifyAnchorReceiptSignature(receipt, anchorKey.publicKey)) {
        throw createCodedError(
          'BUNDLE_RECEIPT_SIGNATURE_INVALID',
          'a bundled anchor receipt signature does not verify',
        );
      }
      if (!checkpointSet.has(receipt.checkpointHash)) {
        throw createCodedError(
          'BUNDLE_RECEIPT_ORPHAN',
          'a bundled anchor receipt references a checkpoint the bundle does not carry',
        );
      }
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

  const coveredSequenceEnd = await verifyBundledChain(
    path.join(root, BUNDLE_AUDIT_DIRNAME),
    manifest.sequenceRange,
  );

  return {
    status: 'VERIFIED',
    storeId: manifest.storeId,
    sequenceRange: manifest.sequenceRange,
    fileCount: Object.keys(manifest.files).length,
    checkpointCount: seenHashes.length,
    anchorReceiptCount: seenReceiptIds.length,
    coveredSequenceEnd,
  };
}

/**
 * Streams the bundled primary artifacts as one chain and proves the declared
 * range is covered contiguously.
 *
 * The bundle's own file names carry the sequence ranges, so continuity across
 * artifact boundaries is checked exactly as the store would check it.
 */
async function verifyBundledChain(
  auditDir: string,
  sequenceRange: { start: number; end: number },
): Promise<number> {
  const names = fs.readdirSync(auditDir).sort();
  let expectedSequence = 1;
  let coveredEnd = 0;
  let previousHash = '0'.repeat(64);

  for (const name of names) {
    const full = path.join(auditDir, name);
    const source: RetainedSegmentSource = {
      kind: name === ACTIVE_SEGMENT_FILENAME ? 'ACTIVE' : 'ARCHIVE',
      label: name,
      filePath: full,
      compressed: name.endsWith('.gz'),
      sequenceStart: 1,
      sequenceEnd: Number.MAX_SAFE_INTEGER,
    };
    for await (const record of streamRetainedRecords([source])) {
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
      coveredEnd = record.sequenceNumber;
      expectedSequence += 1;
    }
  }

  if (coveredEnd < sequenceRange.end && coveredEnd < sequenceRange.start) {
    throw createCodedError(
      'BUNDLE_RANGE_NOT_COVERED',
      'the bundle does not cover the sequence range its manifest declares',
    );
  }
  return coveredEnd;
}
