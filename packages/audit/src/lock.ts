import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { canonicalJsonV1, getProcessUid, validateFileDescriptorAuthority } from './storage.js';

export const LOCK_FILENAME = 'audit.lock';

export interface AuditLockAcquisition {
  lockPath: string;
  fd: number;
  release: () => void;
}

export interface AuditLockOptions {
  auditDir: string;
  expectedUid?: number;
}

interface CodedError extends Error {
  code?: string;
}

function createCodedError(
  code: string,
  message: string,
  options?: { cause?: unknown },
): CodedError {
  const err = new Error(`${code}: ${message}`, options) as CodedError;
  err.code = code;
  return err;
}

export function acquireWriterLock(options: AuditLockOptions): AuditLockAcquisition {
  const { auditDir, expectedUid = getProcessUid() } = options;
  const lockPath = path.join(auditDir, LOCK_FILENAME);

  if (fs.existsSync(lockPath)) {
    let lstats: fs.Stats | undefined;
    try {
      lstats = fs.lstatSync(lockPath);
    } catch {
      // ignore
    }
    if (lstats) {
      if (lstats.isSymbolicLink() || lstats.nlink !== 1) {
        throw createCodedError(
          'AUDIT_LOCK_INSECURE',
          'lock file is a symbolic link or has hard link count > 1',
        );
      }
      throw createCodedError(
        'AUDIT_STORE_LOCKED',
        'audit store is already locked by another process',
      );
    }
  }

  let fd: number;
  try {
    fd = fs.openSync(
      lockPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600,
    );
  } catch (err: unknown) {
    const errCode =
      typeof err === 'object' && err !== null && 'code' in err
        ? (err as { code: unknown }).code
        : undefined;

    if (errCode === 'EEXIST') {
      throw createCodedError(
        'AUDIT_STORE_LOCKED',
        'audit store is already locked by another process',
      );
    }
    if (errCode === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', 'audit.lock is a symbolic link');
    }
    throw err;
  }

  try {
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);

    const payload =
      canonicalJsonV1({
        pid: process.pid,
        startedAt: new Date().toISOString(),
      }) + '\n';

    const buf = Buffer.from(payload, 'utf8');
    let offset = 0;
    while (offset < buf.length) {
      const written = fs.writeSync(fd, buf, offset, buf.length - offset, null);
      if (written <= 0) {
        throw createCodedError('SHORT_WRITE', 'zero bytes written to audit.lock');
      }
      offset += written;
    }
    fs.fsyncSync(fd);

    const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try {
      fs.fsyncSync(parentFd);
    } finally {
      fs.closeSync(parentFd);
    }
  } catch (err) {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    try {
      if (fs.existsSync(lockPath)) {
        fs.unlinkSync(lockPath);
      }
    } catch {
      // ignore
    }
    throw err;
  }

  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
    let releaseError: unknown = null;
    try {
      fs.closeSync(fd);
    } catch (err) {
      releaseError = releaseError ?? err;
    }
    try {
      if (fs.existsSync(lockPath)) {
        fs.unlinkSync(lockPath);
      }
    } catch (err) {
      releaseError = releaseError ?? err;
    }
    try {
      const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
      try {
        fs.fsyncSync(parentFd);
      } finally {
        fs.closeSync(parentFd);
      }
    } catch (err) {
      releaseError = releaseError ?? err;
    }
    if (releaseError) {
      throw createCodedError('LOCK_RELEASE_FAILED', 'failed to cleanly release writer lock', {
        cause: releaseError,
      });
    }
  };

  return { lockPath, fd, release };
}
