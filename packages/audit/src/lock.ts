import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { getProcessUid, validateFileDescriptorAuthority } from './storage.js';

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
      JSON.stringify({
        pid: process.pid,
        startedAt: new Date().toISOString(),
      }) + '\n';

    fs.writeSync(fd, Buffer.from(payload, 'utf8'));
    fs.fsyncSync(fd);

    try {
      const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
      try {
        fs.fsyncSync(parentFd);
      } finally {
        fs.closeSync(parentFd);
      }
    } catch {
      // directory fsync
    }
  } catch (err) {
    try {
      fs.closeSync(fd);
    } catch {
      // ignore
    }
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // ignore
    }
    throw err;
  }

  let released = false;
  const release = (): void => {
    if (released) return;
    released = true;
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
    try {
      const parentFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
      try {
        fs.fsyncSync(parentFd);
      } finally {
        fs.closeSync(parentFd);
      }
    } catch {
      // ignore
    }
  };

  return { lockPath, fd, release };
}
