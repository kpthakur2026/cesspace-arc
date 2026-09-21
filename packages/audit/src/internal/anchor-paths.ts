/**
 * Descriptor-pinned filesystem authority for the Tier-3 anchor artifacts
 * (RC-06 Task 5, §12, §13, §16, §35).
 *
 * The spool directory and both durable anchor streams live inside the audit
 * directory, and every operation on them — create, open, enumerate, unlink —
 * runs relative to a descriptor that was already proven, never relative to a
 * pathname that could be replaced between the check and the use.
 *
 * Linux exposes no `openat(2)` to Node, but it exposes every open descriptor
 * under `/proc/self/fd`, and opening `<bridge>/<parentFd>/<component>` *is*
 * `openat(parentFd, component)`: resolution happens relative to the descriptor.
 * `mkdir`, `readdir` and `unlink` resolve the same bridge the same way, so the
 * whole surface is pinned, not just the opens.
 *
 * ## Why this is a separate module from `key-authority.ts`
 *
 * `key-authority.ts` solves a different problem: it walks an operator-supplied
 * absolute path from the filesystem root, one component at a time, and its
 * `(deleted)` discipline exists because a key descriptor outlives many
 * operations. This module starts from a directory descriptor the audit store
 * already validated and never walks upward. The overlap is the traversal
 * primitive itself.
 *
 * It is deliberately NOT extracted out of `key-authority.ts`. That module was
 * hardened and independently approved as part of Task 4, and the security value
 * of leaving approved authority code byte-identical outweighs the cost of one
 * shared primitive existing in two places. Nothing here weakens the key-path
 * rules: it is additive, and it is used only for the anchor artifacts.
 *
 * @internal
 */

import fs, { constants as fsConstants } from 'node:fs';

import { createCodedError, type CodedError } from './errors.js';

/** The descriptor bridge Linux provides in place of `openat(2)`. */
export const PROC_SELF_FD = '/proc/self/fd';

/** Kernel suffix reported for a descriptor whose file is no longer linked. */
const DELETED_SUFFIX = ' (deleted)';

/**
 * Proves the host can traverse by descriptor rather than by pathname.
 *
 * Checking a pathname and then opening it is not a security boundary: a parent
 * directory can be replaced by a symbolic link in between, and the kernel
 * follows a symlinked *parent* exactly like a real directory, so `O_NOFOLLOW`
 * on the final component proves nothing about where the artifact came from.
 *
 * When the bridge is absent the engine refuses rather than silently falling back
 * to the pathname-only validation this module exists to replace.
 */
export function assertDescriptorPinnedTraversalAvailable(operation: string): void {
  const unsupported = (cause?: unknown): CodedError =>
    createCodedError(
      'AUDIT_PLATFORM_UNSUPPORTED',
      `host platform lacks the descriptor-pinned path traversal required for ${operation}`,
      cause === undefined ? undefined : { cause },
    );

  if (process.platform !== 'linux') {
    throw unsupported();
  }

  let probe: number | null = null;
  try {
    probe = fs.openSync(PROC_SELF_FD, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  } catch (cause) {
    throw unsupported(cause);
  } finally {
    if (probe !== null) {
      fs.closeSync(probe);
    }
  }
}

/** The bridge path that names `component` relative to an open directory. */
export function pinnedChildPath(parentFd: number, component: string): string {
  if (
    component.includes('/') ||
    component.includes('\0') ||
    component === '.' ||
    component === '..'
  ) {
    throw createCodedError(
      'ANCHOR_SPOOL_ENTRY_INVALID',
      'spool entry name is not a single component',
    );
  }
  return `${PROC_SELF_FD}/${parentFd}/${component}`;
}

/**
 * Classifies one child of a pinned parent without following it.
 *
 * Used only to choose an error code. `lstat` through the bridge never
 * dereferences the component, so a symlink is observed as a symlink.
 */
function pinnedChildIsSymlink(parentFd: number, component: string): boolean {
  try {
    return fs.lstatSync(pinnedChildPath(parentFd, component)).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Turns a failed pinned operation into the bounded error that describes it.
 *
 * A symbolic link is reported as `ENOTDIR` once `O_DIRECTORY` is in play, so the
 * component is classified with a non-following `lstat` through the *same* pinned
 * parent. That classification chooses the error text only — it is never the
 * authority, which is the descriptor this function failed to produce.
 */
function pinnedError(
  parentFd: number,
  component: string,
  cause: unknown,
  codes: PinnedErrorCodes,
  noun: string,
): CodedError {
  const code = (cause as { code?: string } | null)?.code;

  // `EEXIST` is only reachable from an exclusive create, and is reported with
  // its own code so a caller can distinguish "something is already there" from
  // "the entry is malformed". Every other caller leaves it unset.
  if (code === 'EEXIST' && codes.exists !== undefined) {
    return createCodedError(codes.exists, `${noun} already exists: ${component}`);
  }

  if (code === 'ELOOP' || code === 'ENOENT' || code === 'ENOTDIR') {
    if (pinnedChildIsSymlink(parentFd, component)) {
      return createCodedError(codes.symlink, `${noun} is a symbolic link: ${component}`);
    }
    if (code === 'ENOENT') {
      return createCodedError(codes.missing, `${noun} does not exist: ${component}`);
    }
    return createCodedError(
      codes.invalid,
      `${noun} is not the expected kind of entry: ${component}`,
    );
  }

  return createCodedError(codes.unavailable, `${noun} could not be opened safely`, { cause });
}

/** The bounded error vocabulary one pinned operation reports through. @internal */
export interface PinnedErrorCodes {
  missing: string;
  symlink: string;
  invalid: string;
  unavailable: string;
  /** Reported for an exclusive create that found something already there. */
  exists?: string;
}

/** Opens an existing child directory relative to a pinned parent. */
export function openPinnedDirectoryChild(
  parentFd: number,
  component: string,
  codes: PinnedErrorCodes,
  noun: string,
): number {
  const flags = fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW;
  try {
    return fs.openSync(pinnedChildPath(parentFd, component), flags);
  } catch (cause) {
    throw pinnedError(parentFd, component, cause, codes, noun);
  }
}

/**
 * Creates `component` as a directory relative to a pinned parent, then opens it.
 *
 * `EEXIST` is not an error: the spool directory is created by whichever engine
 * instance gets there first, and every other instance must adopt the *same*
 * directory. Adoption is not trust — the descriptor is authority-validated
 * after the open, so a pre-existing directory that is a symlink, carries wider
 * permissions, or is owned by another uid is refused rather than used.
 */
export function createPinnedDirectoryChild(
  parentFd: number,
  component: string,
  mode: number,
  codes: PinnedErrorCodes,
  noun: string,
): number {
  const target = pinnedChildPath(parentFd, component);
  let created = false;
  try {
    fs.mkdirSync(target, { mode });
    created = true;
  } catch (cause) {
    if ((cause as { code?: string } | null)?.code !== 'EEXIST') {
      throw pinnedError(parentFd, component, cause, codes, noun);
    }
  }

  if (created) {
    // `mkdir`'s mode is masked by the process umask, so the requested mode is
    // restated on the entry that was actually created. An entry that already
    // existed is never repaired: it is authority-validated below and refused if
    // it is wider than the frozen mode.
    fs.chmodSync(target, mode);
  }

  return openPinnedDirectoryChild(parentFd, component, codes, noun);
}

/** Opens a child file relative to a pinned parent, with explicit flags. */
export function openPinnedFileChild(
  parentFd: number,
  component: string,
  flags: number,
  codes: PinnedErrorCodes,
  noun: string,
  mode?: number,
): number {
  try {
    return mode === undefined
      ? fs.openSync(pinnedChildPath(parentFd, component), flags)
      : fs.openSync(pinnedChildPath(parentFd, component), flags, mode);
  } catch (cause) {
    throw pinnedError(parentFd, component, cause, codes, noun);
  }
}

/** Enumerates the children of a pinned directory descriptor, unsorted. */
export function listPinnedChildren(parentFd: number, noun: string): string[] {
  try {
    return fs.readdirSync(`${PROC_SELF_FD}/${parentFd}`);
  } catch (cause) {
    throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', `unable to enumerate ${noun}`, { cause });
  }
}

/**
 * Removes one child relative to a pinned parent.
 *
 * `ENOENT` is not an error: two engines that reconcile concurrently may both
 * decide a stale spool entry must go, and the second one removing an entry that
 * is already gone has observed the intended end state. Every other failure is
 * surfaced — never repaired, never worked around.
 */
export function unlinkPinnedChild(parentFd: number, component: string, noun: string): boolean {
  try {
    fs.unlinkSync(pinnedChildPath(parentFd, component));
    return true;
  } catch (cause) {
    if ((cause as { code?: string } | null)?.code === 'ENOENT') {
      return false;
    }
    throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', `unable to remove ${noun}`, { cause });
  }
}

/** `fsync`s a descriptor, so a directory entry change or file write is durable. */
export function syncDescriptor(fd: number): void {
  fs.fsyncSync(fd);
}

/** `fdatasync`s a descriptor, so a file's data is durable without its metadata. */
export function dataSyncDescriptor(fd: number): void {
  fs.fdatasyncSync(fd);
}

/**
 * The absolute location a descriptor currently names, as the kernel reports it.
 *
 * A descriptor whose file has been unlinked reports a ` (deleted)` suffix. That
 * is a real observation about the artifact — it is no longer reachable through
 * any name — and is never treated as a usable location.
 */
export function descriptorLocation(fd: number, noun: string): string {
  let target: string;
  try {
    target = fs.readlinkSync(`${PROC_SELF_FD}/${fd}`);
  } catch (cause) {
    throw createCodedError(
      'AUDIT_FILE_IDENTITY_UNAVAILABLE',
      `${noun} descriptor no longer names a reachable file`,
      { cause },
    );
  }

  if (target.endsWith(DELETED_SUFFIX)) {
    throw createCodedError('AUDIT_FILE_IDENTITY_UNAVAILABLE', `${noun} is no longer linked`);
  }

  return target;
}

/**
 * Opens the audit directory itself as an authoritative descriptor.
 *
 * This is the root the anchor artifacts hang from, so its mode, owner and
 * non-symlink status are settled on the descriptor rather than on the pathname
 * `validateAuditDirectory` already checked. A symlinked parent is refused by
 * `O_NOFOLLOW`, and everything below is then reached relative to this
 * descriptor.
 */
export function openAuthoritativeDirectoryFd(directory: string, expectedUid: number): number {
  let fd: number;
  try {
    fd = fs.openSync(
      directory,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
  } catch (cause) {
    const code = (cause as { code?: string } | null)?.code;
    if (code === 'ELOOP' || code === 'ENOTDIR') {
      throw createCodedError('SYMLINK_DETECTED', 'audit directory is a symbolic link');
    }
    throw createCodedError('AUDIT_STORAGE_UNAVAILABLE', 'unable to open the audit directory', {
      cause,
    });
  }

  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isDirectory()) {
      throw createCodedError('AUDIT_STORE_INSECURE_ENTRY', 'audit directory is not a directory');
    }
    if (stats.uid !== expectedUid) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        'audit directory is not owned by the expected uid',
      );
    }
    if ((stats.mode & 0o777) !== 0o700) {
      throw createCodedError(
        'AUDIT_STORE_INSECURE_ENTRY',
        `audit directory mode must be 0700 (got ${(stats.mode & 0o777).toString(8)})`,
      );
    }
    return fd;
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
}

/**
 * Reads at most `maxBytes` from a descriptor, never growing past the bound.
 *
 * The artifact is read into a buffer of exactly the permitted size and one byte
 * more; a read that fills the extra byte proves the artifact is over the bound,
 * which is a refusal rather than a first chunk of a larger read.
 */
export function readBoundedDescriptor(
  fd: number,
  maxBytes: number,
  noun: string,
  code: string,
): Buffer {
  const buffer = Buffer.alloc(maxBytes + 1);
  let filled = 0;

  for (;;) {
    const bytesRead = fs.readSync(fd, buffer, filled, buffer.length - filled, filled);
    if (bytesRead === 0) break;
    filled += bytesRead;
    if (filled > maxBytes) {
      throw createCodedError(code, `${noun} exceeds the ${maxBytes} byte bound`);
    }
  }

  return buffer.subarray(0, filled);
}
