import { resolve, normalize, sep, relative, join } from 'node:path';
import { ArcError } from '@cesspace-arc/protocol';
import type { IFilesystemOps } from './fs-ops.js';

/**
 * Maximum input path length: 1024 characters.
 */
export const MAX_MUTATION_PATH_LENGTH = 1024;

/**
 * Maximum mutation payload byte size: 1 MiB (1,048,576 bytes).
 */
export const MAX_MUTATION_BYTES = 1024 * 1024;

/**
 * Sensitive path patterns permanently blacklisted from all mutation operations.
 * Permanently denies .git/** metadata, cloud/ssh credentials, private keys, and host virtual filesystems.
 */
export const MUTATION_BLACKLIST_PATTERNS: RegExp[] = [
  /(^|[/\\])\.git([/\\]|$)/i,
  /(^|[/\\])\.env($|\..*)/i,
  /(^|[/\\])\.ssh([/\\]|$)/i,
  /(^|[/\\])\.aws([/\\]|$)/i,
  /(^|[/\\])\.gnupg([/\\]|$)/i,
  /(^|[/\\])\.kube([/\\]|$)/i,
  /(^|[/\\])id_rsa/i,
  /(^|[/\\])id_ed25519/i,
  /\.(pem|key|p12|pfx)$/i,
  /^[/\\]?(etc|proc|sys|root|dev)([/\\]|$)/i,
];

/**
 * Checks whether a path touches any mutation blacklisted pattern.
 */
export function isMutationBlacklistedPath(targetPath: string, relativePath?: string): boolean {
  for (const pattern of MUTATION_BLACKLIST_PATTERNS) {
    if (pattern.test(targetPath)) {
      return true;
    }
    if (relativePath && pattern.test(relativePath)) {
      return true;
    }
  }
  return false;
}

export interface ValidatedMutationPath {
  canonicalRoot: string;
  absolutePath: string;
  relativePath: string;
  parentDir: string;
}

/**
 * Validates a mutation path against all RC-03 security constraints:
 * - non-empty workspace-relative string
 * - length <= 1024 characters
 * - no null bytes or URL encoded traversals
 * - no absolute paths
 * - no traversal outside canonical workspace root
 * - no .git/** or sensitive path blacklist matches
 * - no intermediate symbolic links (checked via lstat)
 */
export function validateMutationPath(
  workspaceRoot: string,
  requestedPath: unknown,
  fsOps: IFilesystemOps,
): ValidatedMutationPath {
  if (!workspaceRoot || typeof workspaceRoot !== 'string') {
    throw ArcError.noWorkspaceConfigured();
  }

  if (typeof requestedPath !== 'string' || requestedPath.trim().length === 0) {
    throw ArcError.invalidRequestSchema(
      'Path parameter is required and must be a non-empty string.',
    );
  }

  if (requestedPath.length > MAX_MUTATION_PATH_LENGTH) {
    throw ArcError.invalidRequestSchema(
      `Path parameter exceeds maximum allowed limit of ${MAX_MUTATION_PATH_LENGTH} characters.`,
    );
  }

  // Null byte check
  if (requestedPath.includes('\0')) {
    throw ArcError.invalidPathChars('Path contains invalid null byte.');
  }

  // URL-encoded traversal check
  if (/%2e%2e|%2f|%5c/i.test(requestedPath)) {
    throw ArcError.invalidPathChars('Path contains forbidden URL-encoded traversal characters.');
  }

  const trimmed = requestedPath.trim();

  // Reject absolute paths
  if (trimmed.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(trimmed) || trimmed.startsWith('\\')) {
    throw ArcError.pathEscapesRoot(
      'Security violation: Absolute path is forbidden for file mutation.',
    );
  }

  // Syntactic normalization & relative traversal guard
  const normalized = normalize(trimmed);
  if (
    normalized === '..' ||
    normalized.startsWith(`..${sep}`) ||
    normalized.startsWith('../') ||
    normalized.startsWith('..\\')
  ) {
    throw ArcError.pathEscapesRoot(
      'Security violation: Path traverses outside authorized workspace root.',
    );
  }

  // Blacklist checks on raw and normalized input
  if (isMutationBlacklistedPath(trimmed) || isMutationBlacklistedPath(normalized)) {
    throw ArcError.accessDenied(
      'Access denied: Target path matches sensitive credential, system, or Git metadata pattern.',
    );
  }

  // Canonicalize workspace root
  let canonicalRoot: string;
  try {
    canonicalRoot = fsOps.realpath(resolve(workspaceRoot));
  } catch {
    throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
  }

  // Absolute candidate path
  const candidatePath = resolve(canonicalRoot, normalized);

  // Prefix enclosure check
  const insideBoundary =
    candidatePath === canonicalRoot || candidatePath.startsWith(canonicalRoot + sep);
  if (!insideBoundary) {
    throw ArcError.pathEscapesRoot(
      'Security violation: Path resolves outside the authorized workspace boundary.',
    );
  }

  const relFromRoot = relative(canonicalRoot, candidatePath).replace(/\\/g, '/');
  if (relFromRoot.startsWith('..') || isMutationBlacklistedPath(candidatePath, relFromRoot)) {
    throw ArcError.accessDenied(
      'Access denied: Target path matches sensitive credential, system, or Git metadata pattern.',
    );
  }

  // Check intermediate path components for symlinks using lstat
  const segments = relFromRoot.split('/').filter(Boolean);
  // All segments except the final target are parent/ancestor components
  for (let i = 0; i < segments.length - 1; i++) {
    const intermediatePath = join(canonicalRoot, ...segments.slice(0, i + 1));
    try {
      const st = fsOps.lstat(intermediatePath);
      if (st.isSymbolicLink()) {
        throw ArcError.unsafeSymlink(
          'Security violation: Intermediate path component is a symbolic link.',
        );
      }
    } catch (err: unknown) {
      if ((err as { code?: string }).code === 'ENOENT') {
        // Component does not exist yet; stopped traversal
        break;
      }
      throw err;
    }
  }

  const parentDir = resolve(candidatePath, '..');

  return {
    canonicalRoot,
    absolutePath: candidatePath,
    relativePath: relFromRoot,
    parentDir,
  };
}
