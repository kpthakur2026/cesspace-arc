import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import type { AuditStoreMetadataV1 } from '@cesspace-arc/protocol';
import {
  canonicalJsonV1,
  createCodedError,
  getProcessUid,
  validateFileDescriptorAuthority,
} from './storage.js';

export const METADATA_FILENAME = 'audit-store.json';

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-f]{64}$/;
const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export const METADATA_ALLOWED_KEYS = new Set([
  'version',
  'storeId',
  'createdAt',
  'checkpointPublicKeyFingerprint',
  'anchorMode',
  'anchorReceiptPublicKeyFingerprint',
]);

export interface NormalizedStoreMetadataConfig {
  checkpointPublicKeyFingerprint: string;
  anchorMode: 'DISABLED' | 'ENABLED';
  anchorReceiptPublicKeyFingerprint?: string;
}

export function normalizeStoreMetadataConfig(input: {
  checkpointPublicKeyFingerprint: string;
  anchorMode?: 'DISABLED' | 'ENABLED';
  anchorReceiptPublicKeyFingerprint?: string;
}): NormalizedStoreMetadataConfig {
  if (
    typeof input !== 'object' ||
    input === null ||
    typeof input.checkpointPublicKeyFingerprint !== 'string' ||
    !HEX64_REGEX.test(input.checkpointPublicKeyFingerprint)
  ) {
    throw createCodedError(
      'INVALID_METADATA_CONFIG',
      'checkpointPublicKeyFingerprint must be 64 lowercase hex characters',
    );
  }

  const { anchorMode, anchorReceiptPublicKeyFingerprint } = input;

  if (anchorMode === undefined || anchorMode === 'DISABLED') {
    if (anchorReceiptPublicKeyFingerprint !== undefined) {
      throw createCodedError(
        'INVALID_METADATA_CONFIG',
        'anchorReceiptPublicKeyFingerprint is forbidden when anchorMode is omitted or DISABLED',
      );
    }
    return {
      checkpointPublicKeyFingerprint: input.checkpointPublicKeyFingerprint,
      anchorMode: 'DISABLED',
    };
  }

  if (anchorMode === 'ENABLED') {
    if (
      typeof anchorReceiptPublicKeyFingerprint !== 'string' ||
      !HEX64_REGEX.test(anchorReceiptPublicKeyFingerprint)
    ) {
      throw createCodedError(
        'INVALID_METADATA_CONFIG',
        'anchorReceiptPublicKeyFingerprint is required and must be 64 lowercase hex when anchorMode is ENABLED',
      );
    }
    return {
      checkpointPublicKeyFingerprint: input.checkpointPublicKeyFingerprint,
      anchorMode: 'ENABLED',
      anchorReceiptPublicKeyFingerprint,
    };
  }

  throw createCodedError(
    'INVALID_METADATA_CONFIG',
    `unrecognized anchorMode "${String(anchorMode)}"`,
  );
}

export function validateStoreMetadata(input: unknown): AuditStoreMetadataV1 {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw createCodedError('INVALID_METADATA', 'metadata must be a plain JSON object');
  }
  const obj = input as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (!METADATA_ALLOWED_KEYS.has(key)) {
      throw createCodedError(
        'INVALID_METADATA',
        `unknown top-level field "${key}" in audit-store metadata`,
      );
    }
  }

  if (!('version' in obj)) {
    throw createCodedError('INVALID_METADATA', 'metadata missing version field');
  }
  if (obj.version !== 1) {
    throw createCodedError(
      'UNSUPPORTED_METADATA_VERSION',
      `metadata version must be 1 (got ${String(obj.version)})`,
    );
  }

  if (typeof obj.storeId !== 'string' || !UUID_V4_REGEX.test(obj.storeId)) {
    throw createCodedError('INVALID_METADATA', 'storeId must be a valid UUIDv4');
  }

  if (
    typeof obj.createdAt !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(obj.createdAt) ||
    isNaN(Date.parse(obj.createdAt)) ||
    new Date(obj.createdAt).toISOString() !== obj.createdAt
  ) {
    throw createCodedError(
      'INVALID_METADATA',
      'createdAt must be a valid canonical ISO-8601 UTC timestamp (YYYY-MM-DDTHH:mm:ss.sssZ)',
    );
  }

  if (
    typeof obj.checkpointPublicKeyFingerprint !== 'string' ||
    !HEX64_REGEX.test(obj.checkpointPublicKeyFingerprint)
  ) {
    throw createCodedError(
      'INVALID_METADATA',
      'checkpointPublicKeyFingerprint must be 64 lowercase hex characters',
    );
  }

  if (obj.anchorMode !== 'DISABLED' && obj.anchorMode !== 'ENABLED') {
    throw createCodedError('INVALID_METADATA', 'anchorMode must be DISABLED or ENABLED');
  }

  if (obj.anchorMode === 'DISABLED') {
    if (obj.anchorReceiptPublicKeyFingerprint !== undefined) {
      throw createCodedError(
        'INVALID_METADATA',
        'anchorReceiptPublicKeyFingerprint must be absent when anchorMode is DISABLED',
      );
    }
  } else {
    if (
      typeof obj.anchorReceiptPublicKeyFingerprint !== 'string' ||
      !HEX64_REGEX.test(obj.anchorReceiptPublicKeyFingerprint)
    ) {
      throw createCodedError(
        'INVALID_METADATA',
        'anchorReceiptPublicKeyFingerprint is required and must be 64 lowercase hex when anchorMode is ENABLED',
      );
    }
  }

  return {
    version: 1,
    storeId: obj.storeId,
    createdAt: obj.createdAt,
    checkpointPublicKeyFingerprint: obj.checkpointPublicKeyFingerprint,
    anchorMode: obj.anchorMode,
    ...(obj.anchorReceiptPublicKeyFingerprint !== undefined
      ? { anchorReceiptPublicKeyFingerprint: obj.anchorReceiptPublicKeyFingerprint as string }
      : {}),
  };
}

export function createStoreMetadataFile(
  auditDir: string,
  metadata: AuditStoreMetadataV1,
  expectedUid = getProcessUid(),
): void {
  const validated = validateStoreMetadata(metadata);
  const metadataPath = path.join(auditDir, METADATA_FILENAME);

  let fd: number;
  try {
    fd = fs.openSync(
      metadataPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch (err: unknown) {
    const errCode =
      typeof err === 'object' && err !== null && 'code' in err
        ? (err as { code: unknown }).code
        : undefined;

    if (errCode === 'EEXIST') {
      throw createCodedError('METADATA_ALREADY_EXISTS', 'audit-store.json already exists');
    }
    if (errCode === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', 'audit-store.json is a symbolic link');
    }
    throw err;
  }

  try {
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);
    const content = canonicalJsonV1(validated) + '\n';
    const buf = Buffer.from(content, 'utf8');
    let offset = 0;
    while (offset < buf.length) {
      const written = fs.writeSync(fd, buf, offset, buf.length - offset, null);
      if (written <= 0) {
        throw createCodedError('SHORT_WRITE', 'zero bytes written to audit-store.json');
      }
      offset += written;
    }
    fs.fsyncSync(fd);
  } catch (err) {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    try {
      if (fs.existsSync(metadataPath)) {
        fs.unlinkSync(metadataPath);
      }
    } catch {
      // ignore
    }
    throw err;
  }
  fs.closeSync(fd);

  // Mandatory parent directory fsync
  const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    fs.fsyncSync(parentFd);
  } finally {
    fs.closeSync(parentFd);
  }
}

export function loadStoreMetadataFile(
  auditDir: string,
  expectedUid = getProcessUid(),
): AuditStoreMetadataV1 {
  const metadataPath = path.join(auditDir, METADATA_FILENAME);
  if (!fs.existsSync(metadataPath)) {
    throw createCodedError('METADATA_MISSING', 'audit-store.json missing on non-empty store');
  }

  const lstats = fs.lstatSync(metadataPath);
  if (lstats.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', 'audit-store.json is a symbolic link');
  }

  let fd: number;
  try {
    fd = fs.openSync(metadataPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (err: unknown) {
    const errCode =
      typeof err === 'object' && err !== null && 'code' in err
        ? (err as { code: unknown }).code
        : undefined;

    if (errCode === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', 'audit-store.json is a symbolic link');
    }
    throw err;
  }

  let rawContent: string;
  try {
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);
    rawContent = fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawContent);
  } catch (cause) {
    throw createCodedError('INVALID_METADATA', 'audit-store.json contains malformed JSON', {
      cause,
    });
  }

  return validateStoreMetadata(parsed);
}

export function validateStoreMetadataConsistency(
  existing: AuditStoreMetadataV1,
  expectedInput: {
    checkpointPublicKeyFingerprint: string;
    anchorMode?: 'DISABLED' | 'ENABLED';
    anchorReceiptPublicKeyFingerprint?: string;
  },
): void {
  if (expectedInput.anchorMode !== undefined && expectedInput.anchorMode !== existing.anchorMode) {
    throw createCodedError(
      'STORE_RECONFIGURATION_FORBIDDEN',
      `changing anchorMode from ${existing.anchorMode} to ${expectedInput.anchorMode} on an existing store is forbidden`,
    );
  }

  const normalizedExpected = normalizeStoreMetadataConfig(expectedInput);

  if (
    existing.checkpointPublicKeyFingerprint !== normalizedExpected.checkpointPublicKeyFingerprint
  ) {
    throw createCodedError(
      'FINGERPRINT_MISMATCH',
      `configured checkpoint key fingerprint (${normalizedExpected.checkpointPublicKeyFingerprint}) does not match store metadata (${existing.checkpointPublicKeyFingerprint})`,
    );
  }

  if (existing.anchorMode !== normalizedExpected.anchorMode) {
    throw createCodedError(
      'STORE_RECONFIGURATION_FORBIDDEN',
      `changing anchorMode from ${existing.anchorMode} to ${normalizedExpected.anchorMode} on an existing store is forbidden`,
    );
  }

  if (existing.anchorMode === 'ENABLED') {
    if (
      existing.anchorReceiptPublicKeyFingerprint !==
      normalizedExpected.anchorReceiptPublicKeyFingerprint
    ) {
      throw createCodedError(
        'FINGERPRINT_MISMATCH',
        `configured anchor receipt key fingerprint (${normalizedExpected.anchorReceiptPublicKeyFingerprint}) does not match store metadata (${existing.anchorReceiptPublicKeyFingerprint})`,
      );
    }
  }
}
