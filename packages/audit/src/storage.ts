import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import {
  MAX_RECORD_BYTES,
  type AuditRecord,
  type AuditStoreMetadataV1,
  type PersistentAuditRecordV1,
} from '@cesspace-arc/protocol';
import {
  METADATA_FILENAME,
  createStoreMetadataFile,
  loadStoreMetadataFile,
  validateStoreMetadataConsistency,
} from './metadata.js';
import { acquireWriterLock, type AuditLockAcquisition } from './lock.js';

export const DEFAULT_AUDIT_DIR = path.join(os.homedir(), '.cesspace-arc', 'audit');
export const ACTIVE_SEGMENT_FILENAME = 'audit-active.jsonl';

export const PERSISTENT_RECORD_V1_ALLOWED_KEYS = new Set([
  'eventId',
  'timestamp',
  'sequenceNumber',
  'actor',
  'target',
  'invocation',
  'policy',
  'execution',
  'error',
  'approval',
  'gateway',
  'lifecycle',
  'integrity',
  'schemaVersion',
]);

export interface CodedError extends Error {
  code?: string;
}

export function createCodedError(
  code: string,
  message: string,
  options?: { cause?: unknown },
): CodedError {
  const err = new Error(`${code}: ${message}`, options) as CodedError;
  err.code = code;
  return err;
}

export function getProcessUid(): number {
  return typeof process.getuid === 'function' ? process.getuid() : -1;
}

export interface PlatformCapabilities {
  hasGetUid: boolean;
  isPosixPlatform: boolean;
  hasONoFollow: boolean;
  hasOCreatExcl: boolean;
  hasFstat: boolean;
  hasFsync: boolean;
}

export function detectPlatformCapabilities(): PlatformCapabilities {
  return {
    hasGetUid: typeof process.getuid === 'function',
    isPosixPlatform: process.platform !== 'win32',
    hasONoFollow: typeof fsConstants.O_NOFOLLOW === 'number',
    hasOCreatExcl:
      typeof fsConstants.O_CREAT === 'number' && typeof fsConstants.O_EXCL === 'number',
    hasFstat: typeof fs.fstatSync === 'function',
    hasFsync: typeof fs.fsyncSync === 'function',
  };
}

export function validatePlatformCapabilities(probe?: Partial<PlatformCapabilities>): void {
  const current = { ...detectPlatformCapabilities(), ...probe };
  if (
    !current.hasGetUid ||
    !current.isPosixPlatform ||
    !current.hasONoFollow ||
    !current.hasOCreatExcl ||
    !current.hasFstat ||
    !current.hasFsync
  ) {
    throw createCodedError(
      'AUDIT_PLATFORM_UNSUPPORTED',
      'host platform lacks required POSIX audit security primitives',
    );
  }
}

export function validateAuditDirectory(
  auditDir: string,
  options: {
    createIfMissing?: boolean;
    workspacePaths?: string[];
    expectedUid?: number;
  } = {},
): fs.Stats {
  const { createIfMissing = false, workspacePaths = [], expectedUid = getProcessUid() } = options;

  if (typeof auditDir !== 'string' || auditDir.length === 0) {
    throw createCodedError('INVALID_AUDIT_PATH', 'audit directory path is required');
  }

  if (auditDir.includes('~')) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      'literal ~ is not allowed in audit directory path',
    );
  }

  if (!path.isAbsolute(auditDir)) {
    throw createCodedError('INVALID_AUDIT_PATH', `path must be absolute: "${auditDir}"`);
  }

  const normalized = path.normalize(auditDir);
  if (normalized !== auditDir || auditDir.includes('..')) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      `directory traversal is forbidden in path: "${auditDir}"`,
    );
  }

  for (const ws of workspacePaths) {
    const normWs = path.resolve(ws);
    const normDir = path.resolve(auditDir);
    if (
      normDir === normWs ||
      normDir.startsWith(normWs + path.sep) ||
      normWs.startsWith(normDir + path.sep)
    ) {
      throw createCodedError(
        'INVALID_AUDIT_PATH',
        `audit directory overlaps agent workspace: "${auditDir}"`,
      );
    }
  }

  // Check parent path components for symbolic links
  const segments = path.resolve(auditDir).split(path.sep);
  let currentPath = '';
  for (let i = 1; i < segments.length - 1; i++) {
    currentPath += path.sep + segments[i];
    if (fs.existsSync(currentPath)) {
      try {
        const lstat = fs.lstatSync(currentPath);
        if (lstat.isSymbolicLink()) {
          throw createCodedError(
            'SYMLINK_DETECTED',
            `parent component is a symbolic link: "${currentPath}"`,
          );
        }
      } catch (err: unknown) {
        if (
          typeof err === 'object' &&
          err !== null &&
          'code' in err &&
          (err as { code: unknown }).code === 'SYMLINK_DETECTED'
        ) {
          throw err;
        }
      }
    }
  }

  if (!fs.existsSync(auditDir)) {
    if (!createIfMissing) {
      throw createCodedError('INVALID_AUDIT_PATH', `directory does not exist: "${auditDir}"`);
    }
    try {
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      fs.chmodSync(auditDir, 0o700);
    } catch (cause) {
      throw createCodedError(
        'INVALID_AUDIT_PATH',
        `failed to create audit directory: "${auditDir}"`,
        { cause },
      );
    }
  }

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(auditDir);
  } catch (cause) {
    throw createCodedError('INVALID_AUDIT_PATH', `cannot stat audit directory: "${auditDir}"`, {
      cause,
    });
  }

  if (stats.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', `audit directory is a symbolic link: "${auditDir}"`);
  }

  if (!stats.isDirectory()) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      `audit directory path is not a directory: "${auditDir}"`,
    );
  }

  if (stats.uid !== expectedUid) {
    throw createCodedError(
      'OWNERSHIP_MISMATCH',
      `audit directory owner (${stats.uid}) does not match process UID (${expectedUid})`,
    );
  }

  const mode = stats.mode & 0o777;
  if (mode !== 0o700) {
    throw createCodedError(
      'INSECURE_PERMISSIONS',
      `directory permissions 0${mode.toString(8)} wider than 0700`,
    );
  }

  return stats;
}

export function validateFileDescriptorAuthority(
  fd: number,
  expectedMode = 0o600,
  expectedUid = getProcessUid(),
): fs.Stats {
  const stats = fs.fstatSync(fd);

  if (!stats.isFile()) {
    throw createCodedError('NOT_REGULAR_FILE', 'target audit path is not a regular file');
  }

  if (stats.uid !== expectedUid) {
    throw createCodedError(
      'OWNERSHIP_MISMATCH',
      `file owner (${stats.uid}) does not match required UID (${expectedUid})`,
    );
  }

  const mode = stats.mode & 0o777;
  if (mode !== expectedMode) {
    throw createCodedError(
      'INSECURE_PERMISSIONS',
      `file permissions 0${mode.toString(8)} wider than expected 0${expectedMode.toString(8)}`,
    );
  }

  if (stats.nlink !== 1) {
    throw createCodedError('HARD_LINK_DETECTED', `file has hard link count ${stats.nlink} > 1`);
  }

  return stats;
}

export function canonicalJsonV1(val: unknown, seen: Set<object> = new Set()): string {
  if (val === undefined) {
    throw createCodedError(
      'CANONICAL_JSON_UNDEFINED',
      'undefined is not permitted in canonical JSON V1',
    );
  }

  if (typeof val === 'number') {
    if (!Number.isFinite(val)) {
      throw createCodedError(
        'CANONICAL_JSON_INVALID_NUMBER',
        `non-finite number ${val} is not permitted`,
      );
    }
    return JSON.stringify(val);
  }

  if (typeof val === 'string' || typeof val === 'boolean' || val === null) {
    return JSON.stringify(val);
  }

  if (typeof val === 'bigint' || typeof val === 'symbol' || typeof val === 'function') {
    throw createCodedError('CANONICAL_JSON_UNSUPPORTED_TYPE', `unsupported type ${typeof val}`);
  }

  if (typeof val === 'object') {
    if (seen.has(val)) {
      throw createCodedError('CANONICAL_JSON_CIRCULAR', 'circular object structure detected');
    }
    seen.add(val);
    try {
      if (Array.isArray(val)) {
        const elements = val.map((item) => {
          if (item === undefined) {
            throw createCodedError(
              'CANONICAL_JSON_UNDEFINED',
              'undefined is not permitted in arrays',
            );
          }
          return canonicalJsonV1(item, seen);
        });
        return '[' + elements.join(',') + ']';
      }

      const proto = Object.getPrototypeOf(val);
      if (proto !== null && proto !== Object.prototype) {
        throw createCodedError('CANONICAL_JSON_EXOTIC_OBJECT', 'only plain objects are supported');
      }

      const keys = Object.keys(val as Record<string, unknown>).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const propVal = (val as Record<string, unknown>)[key];
        if (propVal === undefined) {
          // Optional properties whose value is undefined are omitted
          continue;
        }
        parts.push(`${JSON.stringify(key)}:${canonicalJsonV1(propVal, seen)}`);
      }
      return '{' + parts.join(',') + '}';
    } finally {
      seen.delete(val);
    }
  }

  throw createCodedError('CANONICAL_JSON_UNSUPPORTED_VALUE', 'unsupported value');
}

export function computeRecordHashPreimageV1(record: PersistentAuditRecordV1): string {
  const integrityWithoutRecordHash = {
    previousRecordHash: record.integrity.previousRecordHash,
  };
  const preimageObj = {
    ...record,
    integrity: integrityWithoutRecordHash,
  };
  return canonicalJsonV1(preimageObj);
}

export function computeRecordHashV1(record: PersistentAuditRecordV1): string {
  const preimage = computeRecordHashPreimageV1(record);
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}

export function serializeRecordV1(record: PersistentAuditRecordV1): string {
  return canonicalJsonV1(record) + '\n';
}

function hasUnescapedControlChars(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) < 0x20) {
      return true;
    }
  }
  return false;
}

export function parseAndValidateRecordLineV1(line: string): {
  record: PersistentAuditRecordV1;
  computedHash: string;
} {
  if (!line.endsWith('\n')) {
    throw createCodedError('INVALID_LINE', 'line missing terminating newline');
  }

  if (line.includes('\r')) {
    throw createCodedError('INVALID_LINE', 'line contains carriage return character');
  }

  const byteLength = Buffer.byteLength(line, 'utf8');
  if (byteLength > MAX_RECORD_BYTES) {
    throw createCodedError(
      'RECORD_TOO_LARGE',
      `line exceeds maximum size of ${MAX_RECORD_BYTES} bytes (actual: ${byteLength})`,
    );
  }

  const text = line.slice(0, -1);
  if (hasUnescapedControlChars(text)) {
    throw createCodedError('INVALID_LINE', 'line contains unescaped control characters');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw createCodedError('MALFORMED_JSON', 'line contains malformed JSON', { cause });
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw createCodedError('INVALID_RECORD', 'record must be a plain JSON object');
  }

  const rawRecord = parsed as Record<string, unknown>;

  if (!('schemaVersion' in rawRecord)) {
    throw createCodedError(
      'MISSING_SCHEMA_VERSION',
      'record is missing mandatory schemaVersion field',
    );
  }

  if (rawRecord.schemaVersion !== 1) {
    throw createCodedError(
      'UNSUPPORTED_SCHEMA_VERSION',
      `schemaVersion must be 1 (got ${String(rawRecord.schemaVersion)})`,
    );
  }

  for (const key of Object.keys(rawRecord)) {
    if (!PERSISTENT_RECORD_V1_ALLOWED_KEYS.has(key)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown top-level field "${key}" outside V1 schema`);
    }
  }

  const requiredFields = [
    'eventId',
    'timestamp',
    'sequenceNumber',
    'actor',
    'target',
    'invocation',
    'policy',
    'execution',
    'integrity',
  ];

  for (const field of requiredFields) {
    if (!(field in rawRecord) || rawRecord[field] === undefined) {
      throw createCodedError('INVALID_RECORD', `missing required field "${field}"`);
    }
  }

  const integrity = rawRecord.integrity as Record<string, unknown> | null;
  if (!integrity || typeof integrity !== 'object' || Array.isArray(integrity)) {
    throw createCodedError('INVALID_RECORD', 'integrity must be an object');
  }

  if (
    typeof integrity.previousRecordHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(integrity.previousRecordHash)
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'integrity.previousRecordHash must be a 64 lowercase hex digest',
    );
  }

  if (typeof integrity.recordHash !== 'string' || !/^[0-9a-f]{64}$/.test(integrity.recordHash)) {
    throw createCodedError(
      'INVALID_RECORD',
      'integrity.recordHash must be a 64 lowercase hex digest',
    );
  }

  const record = rawRecord as unknown as PersistentAuditRecordV1;
  const computedHash = computeRecordHashV1(record);

  if (record.integrity.recordHash !== computedHash) {
    throw createCodedError(
      'HASH_MISMATCH',
      `recordHash ${record.integrity.recordHash} does not match computed hash ${computedHash}`,
    );
  }

  return { record, computedHash };
}

export interface PersistentAuditStorageConfig {
  directory?: string;
  metadata: {
    checkpointPublicKeyFingerprint: string;
    anchorMode?: 'DISABLED' | 'ENABLED';
    anchorReceiptPublicKeyFingerprint?: string;
  };
  createIfMissing?: boolean;
  workspacePaths?: string[];
  expectedUid?: number;
  platformProbe?: Partial<PlatformCapabilities>;
  simulateWriteFailure?: boolean;
  simulateShortWrite?: boolean;
}

export class PersistentAuditStorage {
  private readonly auditDir: string;
  private readonly activePath: string;
  private readonly config: PersistentAuditStorageConfig;
  private readonly expectedUid: number;
  private lock: AuditLockAcquisition | null = null;
  private activeFd: number | null = null;
  private metadata: AuditStoreMetadataV1 | null = null;
  private currentSequence = 1;
  private lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
  private appendInProgress = false;
  private isClosed = false;

  constructor(config: PersistentAuditStorageConfig) {
    this.config = config;
    this.expectedUid = config.expectedUid ?? getProcessUid();
    this.auditDir = config.directory ?? DEFAULT_AUDIT_DIR;
    this.activePath = path.join(this.auditDir, ACTIVE_SEGMENT_FILENAME);
  }

  public initialize(): void {
    validatePlatformCapabilities(this.config.platformProbe);

    validateAuditDirectory(this.auditDir, {
      createIfMissing: this.config.createIfMissing ?? false,
      workspacePaths: this.config.workspacePaths,
      expectedUid: this.expectedUid,
    });

    this.lock = acquireWriterLock({
      auditDir: this.auditDir,
      expectedUid: this.expectedUid,
    });

    const metadataPath = path.join(this.auditDir, METADATA_FILENAME);
    const storeExists = fs.existsSync(this.activePath) && fs.statSync(this.activePath).size > 0;

    if (!fs.existsSync(metadataPath)) {
      if (storeExists) {
        throw createCodedError('METADATA_MISSING', 'audit-store.json missing on non-empty store');
      }

      const freshMetadata: AuditStoreMetadataV1 = {
        version: 1,
        storeId: randomUUID(),
        createdAt: new Date().toISOString(),
        checkpointPublicKeyFingerprint: this.config.metadata.checkpointPublicKeyFingerprint,
        anchorMode: this.config.metadata.anchorMode ?? 'DISABLED',
        ...(this.config.metadata.anchorMode === 'ENABLED' &&
        this.config.metadata.anchorReceiptPublicKeyFingerprint
          ? {
              anchorReceiptPublicKeyFingerprint:
                this.config.metadata.anchorReceiptPublicKeyFingerprint,
            }
          : {}),
      };

      createStoreMetadataFile(this.auditDir, freshMetadata, this.expectedUid);
      this.metadata = freshMetadata;
    } else {
      const loaded = loadStoreMetadataFile(this.auditDir, this.expectedUid);
      validateStoreMetadataConsistency(loaded, this.config.metadata);
      this.metadata = loaded;
    }

    if (fs.existsSync(this.activePath)) {
      const lstat = fs.lstatSync(this.activePath);
      if (lstat.isSymbolicLink()) {
        throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
      }
    }

    let fd: number;
    try {
      fd = fs.openSync(
        this.activePath,
        fsConstants.O_CREAT | fsConstants.O_APPEND | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
    } catch (err: unknown) {
      const errCode =
        typeof err === 'object' && err !== null && 'code' in err
          ? (err as { code: unknown }).code
          : undefined;

      if (errCode === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
      }
      throw err;
    }

    try {
      validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
      this.activeFd = fd;
    } catch (err) {
      fs.closeSync(fd);
      throw err;
    }

    this.currentSequence = 1;
    this.lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
  }

  public async append(
    recordCandidate: Omit<
      PersistentAuditRecordV1,
      'sequenceNumber' | 'integrity' | 'schemaVersion'
    >,
  ): Promise<PersistentAuditRecordV1> {
    if (this.isClosed || this.activeFd === null) {
      throw createCodedError('AUDIT_STORAGE_CLOSED', 'storage is closed');
    }

    if (this.appendInProgress) {
      throw createCodedError('APPEND_REENTRANT', 'concurrent or re-entrant append rejected');
    }

    this.appendInProgress = true;
    try {
      const candidate: PersistentAuditRecordV1 = {
        ...(recordCandidate as AuditRecord),
        schemaVersion: 1,
        sequenceNumber: this.currentSequence,
        integrity: {
          previousRecordHash: this.lastRecordHash,
          recordHash: '',
        },
      };

      const recordHash = computeRecordHashV1(candidate);
      candidate.integrity.recordHash = recordHash;

      const line = serializeRecordV1(candidate);
      const byteLen = Buffer.byteLength(line, 'utf8');
      if (byteLen > MAX_RECORD_BYTES) {
        throw createCodedError(
          'RECORD_TOO_LARGE',
          `record line (${byteLen} bytes) exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES})`,
        );
      }

      if (this.config.simulateWriteFailure) {
        throw createCodedError('SIMULATED_WRITE_FAILURE', 'disk write failed');
      }

      const buf = Buffer.from(line, 'utf8');
      let bytesWritten: number;
      if (this.config.simulateShortWrite) {
        bytesWritten = fs.writeSync(this.activeFd, buf, 0, Math.floor(buf.length / 2), null);
      } else {
        bytesWritten = fs.writeSync(this.activeFd, buf, 0, buf.length, null);
      }

      if (bytesWritten !== buf.length) {
        throw createCodedError('SHORT_WRITE', 'failed to write complete line to active segment');
      }

      fs.fdatasyncSync(this.activeFd);

      this.currentSequence++;
      this.lastRecordHash = recordHash;

      return JSON.parse(JSON.stringify(candidate)) as PersistentAuditRecordV1;
    } finally {
      this.appendInProgress = false;
    }
  }

  public getMetadata(): AuditStoreMetadataV1 | null {
    return this.metadata;
  }

  public getCurrentSequence(): number {
    return this.currentSequence;
  }

  public getLastRecordHash(): string {
    return this.lastRecordHash;
  }

  public getActivePath(): string {
    return this.activePath;
  }

  public close(): void {
    if (this.isClosed) return;
    this.isClosed = true;

    if (this.activeFd !== null) {
      try {
        fs.closeSync(this.activeFd);
      } catch {
        // ignore
      }
      this.activeFd = null;
    }

    if (this.lock !== null) {
      try {
        this.lock.release();
      } catch {
        // ignore
      }
      this.lock = null;
    }
  }
}
