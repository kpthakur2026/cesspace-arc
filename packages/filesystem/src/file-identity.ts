import { createHash } from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';
import type { IFilesystemOps } from './fs-ops.js';

export interface FileIdentity {
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  size: number;
  hash: string;
}

/**
 * Computes SHA-256 hex digest of buffer or UTF-8 string.
 */
export function computeSha256(data: Buffer | string): string {
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Validates that an expectedHash or expectedSourceHash is a valid 64-character hex string.
 */
export function validateExpectedHash(expectedHash: unknown, paramName = 'expectedHash'): string {
  if (typeof expectedHash !== 'string' || !/^[0-9a-f]{64}$/i.test(expectedHash)) {
    throw ArcError.invalidRequestSchema(
      `${paramName} is required and must be a 64-character SHA-256 hex string.`,
    );
  }
  return expectedHash.toLowerCase();
}

/**
 * Captures regular file metadata, link count, and SHA-256 hash.
 * Fails closed if target is a directory, symlink, special file, or has multiple hardlinks.
 */
export function captureFileIdentity(fsOps: IFilesystemOps, canonicalPath: string): FileIdentity {
  let st;
  try {
    st = fsOps.lstat(canonicalPath);
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ENOENT') {
      throw ArcError.fileNotFound('Target file does not exist.');
    }
    throw err;
  }

  if (st.isDirectory()) {
    throw ArcError.isADirectory('Target path is a directory, not a file.');
  }

  if (st.isSymbolicLink()) {
    throw ArcError.unsafeSymlink('Target path is a symbolic link.');
  }

  if (!st.isFile()) {
    throw ArcError.notAFile('Target path is not a regular file.');
  }

  if (st.nlink > 1) {
    throw ArcError.hardlinkDetected(
      'Security violation: Target file has hardlink count greater than 1.',
    );
  }

  const content = fsOps.readFile(canonicalPath);
  const hash = computeSha256(content);

  return {
    dev: st.dev,
    ino: st.ino,
    mode: st.mode & 0o777,
    nlink: st.nlink,
    size: st.size,
    hash,
  };
}

/**
 * Revalidates file identity and content hash immediately prior to commit/destructive operation.
 */
export function verifyPrecommitIdentity(
  fsOps: IFilesystemOps,
  canonicalPath: string,
  expected: { dev: number; ino: number; hash: string },
): void {
  let st;
  try {
    st = fsOps.lstat(canonicalPath);
  } catch (err: unknown) {
    const code = (err as { code?: string }).code;
    if (code === 'ENOENT') {
      throw ArcError.conflictPreconditionFailed('Target file was removed before commit.');
    }
    throw err;
  }

  if (st.isDirectory()) {
    throw ArcError.isADirectory('Target path became a directory before commit.');
  }

  if (st.isSymbolicLink()) {
    throw ArcError.unsafeSymlink('Target path became a symbolic link before commit.');
  }

  if (!st.isFile()) {
    throw ArcError.notAFile('Target path is not a regular file.');
  }

  if (st.nlink > 1) {
    throw ArcError.hardlinkDetected('Target file acquired multiple hardlinks before commit.');
  }

  if (st.dev !== expected.dev || st.ino !== expected.ino) {
    throw ArcError.conflictPreconditionFailed('Target file identity changed before commit.');
  }

  const content = fsOps.readFile(canonicalPath);
  const currentHash = computeSha256(content);
  if (currentHash !== expected.hash) {
    throw ArcError.conflictPreconditionFailed('Target file content changed before commit.');
  }
}
