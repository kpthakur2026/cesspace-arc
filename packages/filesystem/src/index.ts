import {
  realpathSync,
  statSync,
  readdirSync,
  openSync,
  readSync,
  closeSync,
  existsSync,
  type Stats,
} from 'node:fs';
import { resolve, normalize, sep, relative, join, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  ArcError,
  type ListDirectoryRequest,
  type ListDirectoryResponse,
  type DirectoryEntry,
  type ReadFileRequest,
  type ReadFileResponse,
  type SearchFilesRequest,
  type SearchFilesResponse,
  type SearchTextRequest,
  type SearchTextResponse,
  type TextMatchItem,
  type CreateFileRequest,
  type CreateFileResponse,
  type WriteFileRequest,
  type WriteFileResponse,
  type DeleteFileRequest,
  type DeleteFileResponse,
  type MoveFileRequest,
  type MoveFileResponse,
  type ApplyPatchRequest,
  type ApplyPatchResponse,
} from '@cesspace-arc/protocol';

export * from './fs-ops.js';
export * from './locks.js';
export * from './mutation-security.js';
export * from './file-identity.js';
export * from './patch-engine.js';

import { type IFilesystemOps, NodeFilesystemOps } from './fs-ops.js';
import { type ILockManager, defaultLockManager } from './locks.js';
import { applyPatch } from './patch-engine.js';
import {
  MAX_MUTATION_BYTES,
  validateMutationPath,
  writeAll,
  sanitizeFsError,
} from './mutation-security.js';
import {
  captureFileIdentity,
  verifyPrecommitIdentity,
  computeSha256,
  validateExpectedHash,
} from './file-identity.js';

/**
 * Interface definition for Jailed Filesystem Subsystem.
 */
export interface IFilesystemSubsystem {
  resolveSecurePath(workspaceRoot: string, requestedPath: string): Promise<string>;
  listDirectory(
    workspaceRoot: string,
    request: ListDirectoryRequest,
  ): Promise<ListDirectoryResponse>;
  readFile(workspaceRoot: string, request: ReadFileRequest): Promise<ReadFileResponse>;
  searchFiles(workspaceRoot: string, request: SearchFilesRequest): Promise<SearchFilesResponse>;
  searchText(workspaceRoot: string, request: SearchTextRequest): Promise<SearchTextResponse>;
  createFile(workspaceRoot: string, request: CreateFileRequest): Promise<CreateFileResponse>;
  writeFile(workspaceRoot: string, request: WriteFileRequest): Promise<WriteFileResponse>;
  deleteFile(workspaceRoot: string, request: DeleteFileRequest): Promise<DeleteFileResponse>;
  moveFile(workspaceRoot: string, request: MoveFileRequest): Promise<MoveFileResponse>;
  applyPatch(workspaceRoot: string, request: ApplyPatchRequest): Promise<ApplyPatchResponse>;
  validateWorkspaceContainment(workspaceRoot: string, targetPath: string): Promise<string>;
  validateReviewDiffPath(workspaceRoot: string, targetPath: string): Promise<string>;
  validateTestPath(workspaceRoot: string, targetPath: string): Promise<string>;
  validateWorkflowPath(workspaceRoot: string, targetPath: string): Promise<string>;
  listWorkflowFiles(workspaceRoot: string): Promise<string[]>;
}

/**
 * Pluggable Search Backend interface (P2 architecture).
 */
export interface ISearchBackend {
  searchFiles(
    searchRoot: string,
    canonicalRoot: string,
    request: SearchFilesRequest,
  ): Promise<SearchFilesResponse>;
  searchText(canonicalRoot: string, request: SearchTextRequest): Promise<SearchTextResponse>;
}

/**
 * Sensitive path patterns permanently blacklisted.
 */
export const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /(^|[/\\])\.env($|\..*)/i,
  /(^|[/\\])\.ssh([/\\]|$)/i,
  /(^|[/\\])\.aws([/\\]|$)/i,
  /(^|[/\\])\.gnupg([/\\]|$)/i,
  /(^|[/\\])\.kube([/\\]|$)/i,
  /(^|[/\\])\.git[/\\]config$/i,
  /(^|[/\\])\.git[/\\]hooks([/\\]|$)/i,
  /(^|[/\\])id_rsa/i,
  /(^|[/\\])id_ed25519/i,
  /\.(pem|key|p12|pfx)$/i,
  /^[/\\]?(etc|proc|sys|root|dev)([/\\]|$)/i,
];

/**
 * Maximum read buffer size: 1 MiB (1,048,576 bytes).
 */
export const MAX_READ_BYTES = 1024 * 1024;

/**
 * Maximum search results/matches: 200.
 */
export const MAX_SEARCH_RESULTS = 200;

/**
 * Maximum directory depth: 5.
 */
export const MAX_DIRECTORY_DEPTH = 5;

/**
 * Checks whether a path matches any blacklisted sensitive patterns.
 */
export function isBlacklistedPath(targetPath: string, relativePath?: string): boolean {
  for (const pattern of SENSITIVE_PATH_PATTERNS) {
    if (pattern.test(targetPath)) {
      return true;
    }
    if (relativePath && pattern.test(relativePath)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether a file appears to be binary by scanning first 8 KB for null bytes.
 */
export function isBinaryFile(filePath: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(filePath, 'r');
    const buffer = Buffer.alloc(8192);
    const bytesRead = readSync(fd, buffer, 0, 8192, 0);
    for (let i = 0; i < bytesRead; i++) {
      if (buffer[i] === 0x00) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/**
 * Canonical Filesystem Subsystem implementation.
 * Enforces Tier 1 Userspace Canonicalization baseline as specified in the architecture.
 */
export class FilesystemSubsystem implements IFilesystemSubsystem {
  private searchBackend: ISearchBackend;
  private fsOps: IFilesystemOps;
  private lockManager: ILockManager;

  constructor(searchBackend?: ISearchBackend, fsOps?: IFilesystemOps, lockManager?: ILockManager) {
    this.searchBackend = searchBackend || new NodeSearchBackend();
    this.fsOps = fsOps || new NodeFilesystemOps();
    this.lockManager = lockManager || defaultLockManager;
  }

  /**
   * Resolves and verifies that requestedPath resides strictly within workspaceRoot.
   * Rejects path escapes (relative traversal, symlink escapes) and blacklisted secrets.
   */
  public async resolveSecurePath(workspaceRoot: string, requestedPath: string): Promise<string> {
    if (!workspaceRoot || typeof workspaceRoot !== 'string') {
      throw ArcError.noWorkspaceConfigured();
    }
    if (requestedPath === undefined || requestedPath === null) {
      throw ArcError.invalidRequestSchema('Path parameter is required.');
    }
    if (typeof requestedPath !== 'string') {
      throw ArcError.invalidRequestSchema('Path parameter must be a string.');
    }

    // 1. Syntactic Normalization & Null Byte Check
    if (requestedPath.includes('\0')) {
      throw ArcError.invalidPathChars('Path contains invalid null byte.');
    }

    // Check for raw URL encoded directory traversal
    if (/%2e%2e|%2f|%5c/i.test(requestedPath)) {
      throw ArcError.invalidPathChars('Path contains forbidden URL-encoded traversal characters.');
    }

    // 2. Canonicalize Workspace Root
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }

    // 3. Workspace Root Join & Pre-Check
    const trimmedPath = requestedPath.trim();
    let candidatePath: string;

    if (trimmedPath.startsWith('/') || /^[a-zA-Z]:\\/.test(trimmedPath)) {
      // Absolute path requested: must start with canonical root syntactically
      const normRequested = normalize(resolve(trimmedPath));
      if (normRequested !== canonicalRoot && !normRequested.startsWith(canonicalRoot + sep)) {
        throw ArcError.pathEscapesRoot(
          'Security violation: Absolute path resides outside the authorized workspace boundary.',
        );
      }
      candidatePath = normRequested;
    } else {
      // Relative path: resolve against canonicalRoot
      candidatePath = resolve(canonicalRoot, trimmedPath);
    }

    // 4. Canonical Realpath Resolution
    let canonicalPath: string;
    try {
      canonicalPath = realpathSync(candidatePath);
    } catch (err: unknown) {
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code === 'ENOENT') {
        // Path does not exist. Check if its normalized form escapes root.
        const norm = normalize(candidatePath);
        if (norm !== canonicalRoot && !norm.startsWith(canonicalRoot + sep)) {
          throw ArcError.pathEscapesRoot();
        }
        throw ArcError.fileNotFound('Target path does not exist in workspace.');
      }
      throw ArcError.internalError('Filesystem path resolution failed.');
    }

    // 5. Prefix Enclosure Check (Symlink escape & traversal guard)
    const insideBoundary =
      canonicalPath === canonicalRoot || canonicalPath.startsWith(canonicalRoot + sep);

    if (!insideBoundary) {
      throw ArcError.pathEscapesRoot(
        'Security violation: Path resolves outside the authorized workspace boundary.',
      );
    }

    // 6. Blacklist & Secret Filtering
    const relFromRoot = relative(canonicalRoot, canonicalPath);
    if (isBlacklistedPath(canonicalPath, relFromRoot) || isBlacklistedPath(trimmedPath)) {
      throw ArcError.accessDenied(
        'Access denied: Target path matches sensitive credential or system blacklist pattern.',
      );
    }

    return canonicalPath;
  }

  /**
   * Validates that targetPath resides strictly within workspaceRoot.
   * Enforces RC07-NEG-016 (rejecting traversal tokens like .. before resolution)
   * and RC07-NEG-014 (failing closed with PATH_OUTSIDE_WORKSPACE if resolving outside).
   */
  public async validateWorkspaceContainment(
    workspaceRoot: string,
    targetPath: string,
  ): Promise<string> {
    if (!targetPath || typeof targetPath !== 'string') {
      throw ArcError.invalidRequestSchema('Path parameter is required and must be a string.');
    }
    // RC07-NEG-016: directory traversal (..) rejected before unsafe resolution
    if (/(^|[/\\])\.\.([/\\]|$)/.test(targetPath)) {
      throw ArcError.pathOutsideWorkspace(
        'Directory traversal (..) is forbidden in workspace path.',
      );
    }
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }
    let canonicalTarget: string;
    try {
      canonicalTarget = realpathSync(resolve(targetPath));
    } catch {
      throw ArcError.pathOutsideWorkspace('Target path cannot be resolved.');
    }
    if (canonicalTarget !== canonicalRoot && !canonicalTarget.startsWith(canonicalRoot + sep)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Target path resides outside authorized workspace boundary.',
      );
    }
    return canonicalTarget;
  }

  /**
   * Validates a workspace-relative review diff path filter.
   * Enforces RC07-NEG-021 (PATH_OUTSIDE_WORKSPACE on traversal escape like ../../etc/passwd),
   * RC07-NEG-026 (blocking sensitive paths like .env and id_rsa with ACCESS_DENIED),
   * and symlink escape detection.
   * Correctly validates tracked files that may be deleted or missing from the working tree.
   * Returns normalized workspace-relative filter path.
   */
  public async validateReviewDiffPath(
    workspaceRoot: string,
    requestedPath: string,
  ): Promise<string> {
    if (!requestedPath || typeof requestedPath !== 'string') {
      throw ArcError.invalidRequestSchema('Path parameter is required and must be a string.');
    }

    const trimmed = requestedPath.trim();
    if (trimmed.length === 0) {
      throw ArcError.invalidRequestSchema('Path parameter must not be empty.');
    }

    // 1. Syntactic Null Byte & Traversal Pre-checks
    if (trimmed.includes('\0')) {
      throw ArcError.invalidPathChars('Path contains invalid null byte.');
    }
    if (/%2e%2e|%2f|%5c/i.test(trimmed)) {
      throw ArcError.invalidPathChars('Path contains forbidden URL-encoded traversal characters.');
    }
    // RC07-NEG-021: directory traversal (..) rejected with PATH_OUTSIDE_WORKSPACE
    if (/(^|[/\\])\.\.([/\\]|$)/.test(trimmed)) {
      throw ArcError.pathOutsideWorkspace(
        'Directory traversal (..) is forbidden in review diff path.',
      );
    }

    // 2. Canonicalize Workspace Root
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }

    // 3. Workspace Root Join & Boundary Check
    let candidatePath: string;
    if (trimmed.startsWith('/') || /^[a-zA-Z]:\\/.test(trimmed)) {
      const normRequested = normalize(resolve(trimmed));
      if (normRequested !== canonicalRoot && !normRequested.startsWith(canonicalRoot + sep)) {
        throw ArcError.pathOutsideWorkspace(
          'Security violation: Path resides outside authorized workspace boundary.',
        );
      }
      candidatePath = normRequested;
    } else {
      candidatePath = resolve(canonicalRoot, trimmed);
    }

    const norm = normalize(candidatePath);
    if (norm !== canonicalRoot && !norm.startsWith(canonicalRoot + sep)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Path resides outside authorized workspace boundary.',
      );
    }

    // 4. Symlink containment check for existing path components
    let currentCheck = candidatePath;
    while (currentCheck !== canonicalRoot && currentCheck.length >= canonicalRoot.length) {
      try {
        const resolvedCurrent = realpathSync(currentCheck);
        if (resolvedCurrent !== canonicalRoot && !resolvedCurrent.startsWith(canonicalRoot + sep)) {
          throw ArcError.symlinkEscapeDetected(
            'Symlink resolves outside authorized workspace boundary.',
          );
        }
        break; // Successfully verified nearest existing ancestor
      } catch (err: unknown) {
        const nodeErr = err as NodeJS.ErrnoException;
        if (nodeErr.code === 'ENOENT') {
          const parent = dirname(currentCheck);
          if (parent === currentCheck) {
            break;
          }
          currentCheck = parent;
        } else {
          throw ArcError.internalError('Filesystem path resolution failed.');
        }
      }
    }

    // 5. RC07-NEG-026: Blacklist & Sensitive Path Enforcement
    const relFromRoot = relative(canonicalRoot, candidatePath);
    if (isBlacklistedPath(candidatePath, relFromRoot) || isBlacklistedPath(trimmed)) {
      throw ArcError.accessDenied(
        'Access denied: Target path matches sensitive credential or system blacklist pattern.',
      );
    }

    return relFromRoot.length > 0 ? relFromRoot : '.';
  }

  /**
   * Dedicated read-only test path validator for arc_test (RC-07 Task 5).
   * Validates workspace containment, symlink safety, sensitive path blacklist,
   * and verifies that the target exists on disk.
   * Returns normalized workspace-relative test path.
   */
  public async validateTestPath(workspaceRoot: string, requestedPath: string): Promise<string> {
    if (!requestedPath || typeof requestedPath !== 'string') {
      throw ArcError.invalidRequestSchema('Path parameter is required and must be a string.');
    }

    const trimmed = requestedPath.trim();
    if (trimmed.length === 0) {
      throw ArcError.invalidRequestSchema('Path parameter must not be empty.');
    }

    // 1. Syntactic Null Byte & Traversal Pre-checks
    if (trimmed.includes('\0')) {
      throw ArcError.invalidPathChars('Path contains invalid null byte.');
    }
    if (/%2e%2e|%2f|%5c/i.test(trimmed)) {
      throw ArcError.invalidPathChars('Path contains forbidden URL-encoded traversal characters.');
    }
    // RC07-NEG-038: directory traversal (..) rejected with PATH_OUTSIDE_WORKSPACE
    if (/(^|[/\\])\.\.([/\\]|$)/.test(trimmed)) {
      throw ArcError.pathOutsideWorkspace('Directory traversal (..) is forbidden in test path.');
    }

    // 2. Canonicalize Workspace Root
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }

    // 3. Workspace Root Join & Absolute Escape Check
    if (trimmed.startsWith('/') || /^[a-zA-Z]:\\/.test(trimmed)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Absolute path is forbidden in test path.',
      );
    }

    const candidatePath = resolve(canonicalRoot, trimmed);
    const norm = normalize(candidatePath);
    if (norm !== canonicalRoot && !norm.startsWith(canonicalRoot + sep)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Path resides outside authorized workspace boundary.',
      );
    }

    // 4. Verify existence
    if (!existsSync(candidatePath)) {
      throw ArcError.fileNotFound(`Target test path does not exist: '${trimmed}'.`);
    }

    // 5. Canonicalize target and verify symlink containment
    let canonicalTarget: string;
    try {
      canonicalTarget = realpathSync(candidatePath);
    } catch {
      throw ArcError.fileNotFound(`Target test path does not exist: '${trimmed}'.`);
    }

    if (canonicalTarget !== canonicalRoot && !canonicalTarget.startsWith(canonicalRoot + sep)) {
      throw ArcError.symlinkEscapeDetected(
        'Symlink resolves outside authorized workspace boundary.',
      );
    }

    // 6. Blacklist & Sensitive Path Enforcement
    const relFromRoot = relative(canonicalRoot, canonicalTarget);
    if (isBlacklistedPath(canonicalTarget, relFromRoot) || isBlacklistedPath(trimmed)) {
      throw ArcError.accessDenied(
        'Access denied: Target test path matches sensitive credential or system blacklist pattern.',
      );
    }

    const normalizedRel = normalize(relFromRoot);
    return normalizedRel.length > 0 ? normalizedRel : '.';
  }

  /**
   * Dedicated read-only workflow path validator for arc_ci_status (RC-07 Task 6).
   * Confines inspection strictly to .github/workflows/ within authorized workspace.
   * Validates workspace containment, symlink safety, sensitive path blacklist,
   * and verifies that the target exists and is a .yml/.yaml file.
   * Returns normalized workspace-relative workflow path (e.g. .github/workflows/ci.yml).
   */
  public async validateWorkflowPath(workspaceRoot: string, requestedPath: string): Promise<string> {
    if (!requestedPath || typeof requestedPath !== 'string') {
      throw ArcError.invalidRequestSchema(
        'Workflow path parameter is required and must be a string.',
      );
    }

    const trimmed = requestedPath.trim();
    if (trimmed.length === 0) {
      throw ArcError.invalidRequestSchema('Workflow path parameter must not be empty.');
    }

    // 1. Syntactic Null Byte & Traversal Pre-checks
    if (trimmed.includes('\0')) {
      throw ArcError.invalidPathChars('Path contains invalid null byte.');
    }
    if (/%2e%2e|%2f|%5c/i.test(trimmed)) {
      throw ArcError.invalidPathChars('Path contains forbidden URL-encoded traversal characters.');
    }
    // RC07-NEG-049: directory traversal (..) rejected with PATH_OUTSIDE_WORKSPACE
    if (/(^|[/\\])\.\.([/\\]|$)/.test(trimmed)) {
      throw ArcError.pathOutsideWorkspace(
        'Directory traversal (..) is forbidden in workflow path.',
      );
    }

    // 2. Canonicalize Workspace Root
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }

    // 3. Absolute path rejection
    if (trimmed.startsWith('/') || /^[a-zA-Z]:\\/.test(trimmed)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Absolute path is forbidden in workflow path.',
      );
    }

    const candidatePath = resolve(canonicalRoot, trimmed);
    const norm = normalize(candidatePath);

    // 4. Must be inside workspaceRoot
    if (norm !== canonicalRoot && !norm.startsWith(canonicalRoot + sep)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Workflow path resides outside authorized workspace boundary.',
      );
    }

    // 5. Must be strictly inside .github/workflows/
    const expectedPrefix = resolve(canonicalRoot, '.github', 'workflows');
    if (norm !== expectedPrefix && !norm.startsWith(expectedPrefix + sep)) {
      throw ArcError.pathOutsideWorkspace(
        'Security violation: Workflow path must reside strictly within .github/workflows/.',
      );
    }

    // 6. Symlink containment check
    let canonicalTarget: string;
    try {
      canonicalTarget = realpathSync(candidatePath);
    } catch (err: unknown) {
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code === 'ENOENT') {
        throw ArcError.fileNotFound(`Workflow file not found: ${trimmed}`);
      }
      throw ArcError.internalError('Filesystem path resolution failed.');
    }

    if (canonicalTarget !== canonicalRoot && !canonicalTarget.startsWith(canonicalRoot + sep)) {
      throw ArcError.symlinkEscapeDetected(
        'Symlink resolves outside authorized workspace boundary.',
      );
    }

    // 7. Verify extension is .yml or .yaml
    if (!/\.ya?ml$/i.test(trimmed)) {
      throw ArcError.invalidRequestSchema('Workflow file must have a .yml or .yaml extension.');
    }

    // 8. Blacklist & Sensitive Path Enforcement
    const relFromRoot = relative(canonicalRoot, canonicalTarget);
    if (isBlacklistedPath(canonicalTarget, relFromRoot) || isBlacklistedPath(trimmed)) {
      throw ArcError.accessDenied(
        'Access denied: Target workflow path matches sensitive credential or system blacklist pattern.',
      );
    }

    const normalizedRel = normalize(relative(canonicalRoot, candidatePath)).replace(/\\/g, '/');
    return normalizedRel;
  }

  /**
   * Dedicated workflow directory scanner for arc_ci_status (RC-07 Task 6).
   * Confines scanning strictly to .github/workflows/ within authorized workspace.
   * If .github/workflows does not exist, returns empty array.
   * If a symlink in the workflow hierarchy escapes the workspace boundary,
   * rejects with PATH_OUTSIDE_WORKSPACE.
   * Returns sorted array of relative paths (e.g. ['.github/workflows/ci.yml']).
   */
  public async listWorkflowFiles(workspaceRoot: string): Promise<string[]> {
    let canonicalRoot: string;
    try {
      canonicalRoot = realpathSync(resolve(workspaceRoot));
    } catch {
      throw ArcError.noWorkspaceConfigured('Workspace root directory does not exist.');
    }

    const githubDir = join(canonicalRoot, '.github');
    if (!existsSync(githubDir)) {
      return [];
    }

    // Verify .github does not escape workspace via symlink
    try {
      const realGithub = realpathSync(githubDir);
      if (realGithub !== canonicalRoot && !realGithub.startsWith(canonicalRoot + sep)) {
        throw ArcError.pathOutsideWorkspace(
          'Security violation: .github directory escapes authorized workspace boundary.',
        );
      }
    } catch (err: unknown) {
      if (err instanceof ArcError) throw err;
      return [];
    }

    const workflowsDir = join(githubDir, 'workflows');
    if (!existsSync(workflowsDir)) {
      return [];
    }

    // Verify .github/workflows does not escape workspace via symlink
    try {
      const realWorkflows = realpathSync(workflowsDir);
      if (realWorkflows !== canonicalRoot && !realWorkflows.startsWith(canonicalRoot + sep)) {
        throw ArcError.pathOutsideWorkspace(
          'Security violation: .github/workflows directory escapes authorized workspace boundary.',
        );
      }
    } catch (err: unknown) {
      if (err instanceof ArcError) throw err;
      return [];
    }

    let st: Stats;
    try {
      st = statSync(workflowsDir);
    } catch {
      return [];
    }
    if (!st.isDirectory()) {
      return [];
    }

    let dirents;
    try {
      dirents = readdirSync(workflowsDir, { withFileTypes: true });
    } catch {
      return [];
    }

    const workflowPaths: string[] = [];

    for (const dirent of dirents) {
      const name = dirent.name;
      // Only process .yml and .yaml files
      if (!/\.ya?ml$/i.test(name)) {
        continue;
      }

      const fullEntryPath = join(workflowsDir, name);

      if (dirent.isSymbolicLink()) {
        try {
          const realTarget = realpathSync(fullEntryPath);
          if (realTarget !== canonicalRoot && !realTarget.startsWith(canonicalRoot + sep)) {
            throw ArcError.pathOutsideWorkspace(
              'Security violation: Workflow symlink resolves outside authorized workspace boundary.',
            );
          }
          const targetStat = statSync(realTarget);
          if (!targetStat.isFile()) {
            continue;
          }
        } catch (err: unknown) {
          if (err instanceof ArcError) throw err;
          // Broken symlink or inaccessible: skip
          continue;
        }
      } else if (!dirent.isFile()) {
        continue;
      }

      const relPath = relative(canonicalRoot, fullEntryPath).replace(/\\/g, '/');
      if (isBlacklistedPath(fullEntryPath, relPath)) {
        continue;
      }

      workflowPaths.push(relPath);
    }

    // Deterministic sorting (code unit comparison)
    workflowPaths.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return workflowPaths;
  }

  public async listDirectory(
    workspaceRoot: string,
    request: ListDirectoryRequest,
  ): Promise<ListDirectoryResponse> {
    const rawPath = request.path || '.';
    const canonicalPath = await this.resolveSecurePath(workspaceRoot, rawPath);

    const st = statSync(canonicalPath);
    if (!st.isDirectory()) {
      throw ArcError.notADirectory('Requested path is not a directory.');
    }

    const recursive = Boolean(request.recursive);
    const maxDepth = request.maxDepth !== undefined ? request.maxDepth : 1;

    if (
      typeof maxDepth !== 'number' ||
      !Number.isInteger(maxDepth) ||
      maxDepth < 1 ||
      maxDepth > MAX_DIRECTORY_DEPTH
    ) {
      throw ArcError.invalidRequestSchema(
        `maxDepth must be an integer between 1 and ${MAX_DIRECTORY_DEPTH}.`,
      );
    }

    const includeHidden = Boolean(request.includeHidden);
    const entries: DirectoryEntry[] = [];

    const canonicalRoot = realpathSync(resolve(workspaceRoot));

    const walk = (currentDir: string, currentDepth: number): void => {
      if (currentDepth > maxDepth || entries.length >= 500) {
        return;
      }

      let dirents;
      try {
        dirents = readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const dirent of dirents) {
        if (entries.length >= 500) {
          break;
        }

        const name = dirent.name;
        if (!includeHidden && name.startsWith('.')) {
          continue;
        }

        const fullPath = join(currentDir, name);
        const relFromRoot = relative(canonicalRoot, fullPath);

        // Blacklist filter
        if (isBlacklistedPath(fullPath, relFromRoot)) {
          continue;
        }

        let entryType: 'file' | 'directory' | 'symlink' | 'other' = 'other';
        let sizeBytes: number | undefined;
        let modifiedTime: string | undefined;

        try {
          if (dirent.isSymbolicLink()) {
            entryType = 'symlink';
            // Verify symlink target does not escape
            try {
              const realTarget = realpathSync(fullPath);
              if (realTarget !== canonicalRoot && !realTarget.startsWith(canonicalRoot + sep)) {
                // Skip escaping symlinks in directory listings
                continue;
              }
            } catch {
              // Broken symlink
            }
          } else if (dirent.isDirectory()) {
            entryType = 'directory';
          } else if (dirent.isFile()) {
            entryType = 'file';
            const fst = statSync(fullPath);
            sizeBytes = fst.size;
            modifiedTime = fst.mtime.toISOString();
          }
        } catch {
          // Skip unreadable entries
          continue;
        }

        entries.push({
          name,
          relativePath: relFromRoot.replace(/\\/g, '/'),
          type: entryType,
          sizeBytes,
          modifiedTime,
        });

        if (recursive && dirent.isDirectory() && currentDepth < maxDepth) {
          walk(fullPath, currentDepth + 1);
        }
      }
    };

    walk(canonicalPath, 1);

    return {
      entries,
      totalCount: entries.length,
    };
  }

  public async readFile(
    workspaceRoot: string,
    request: ReadFileRequest,
  ): Promise<ReadFileResponse> {
    const canonicalPath = await this.resolveSecurePath(workspaceRoot, request.path);

    const st = statSync(canonicalPath);
    if (st.isDirectory()) {
      throw ArcError.isADirectory('Requested path is a directory, not a file.');
    }

    const totalSize = st.size;
    const offset = request.offset ?? 0;
    const requestedLength = request.length ?? 65536;

    if (typeof offset !== 'number' || offset < 0 || !Number.isInteger(offset)) {
      throw ArcError.invalidRequestSchema('offset must be a non-negative integer.');
    }
    if (
      typeof requestedLength !== 'number' ||
      requestedLength < 0 ||
      !Number.isInteger(requestedLength)
    ) {
      throw ArcError.invalidRequestSchema('length must be a non-negative integer.');
    }

    if (requestedLength > MAX_READ_BYTES) {
      throw ArcError.payloadTooLarge(
        'Requested read length exceeds maximum allowed limit of 1 MiB.',
      );
    }

    // Binary file check
    if (isBinaryFile(canonicalPath)) {
      return {
        content: `[BINARY FILE: ${totalSize} bytes; raw content suppressed for safety]`,
        bytesRead: 0,
        totalSize,
        truncated: false,
      };
    }

    if (offset >= totalSize) {
      return {
        content: '',
        bytesRead: 0,
        totalSize,
        truncated: false,
      };
    }

    const bytesToRead = Math.min(requestedLength, totalSize - offset);
    const buffer = Buffer.alloc(bytesToRead);

    const fd = openSync(canonicalPath, 'r');
    let bytesRead: number;
    try {
      bytesRead = readSync(fd, buffer, 0, bytesToRead, offset);
    } finally {
      closeSync(fd);
    }

    const content = buffer.toString('utf8', 0, bytesRead);
    const truncated = offset + bytesRead < totalSize;

    return {
      content,
      bytesRead,
      totalSize,
      truncated,
    };
  }

  public async searchFiles(
    workspaceRoot: string,
    request: SearchFilesRequest,
  ): Promise<SearchFilesResponse> {
    const subPath = request.subPath || '.';
    const searchRoot = await this.resolveSecurePath(workspaceRoot, subPath);
    const canonicalRoot = realpathSync(resolve(workspaceRoot));
    return this.searchBackend.searchFiles(searchRoot, canonicalRoot, request);
  }

  public async searchText(
    workspaceRoot: string,
    request: SearchTextRequest,
  ): Promise<SearchTextResponse> {
    const canonicalRoot = realpathSync(resolve(workspaceRoot));
    return this.searchBackend.searchText(canonicalRoot, request);
  }

  public async createFile(
    workspaceRoot: string,
    request: CreateFileRequest,
  ): Promise<CreateFileResponse> {
    if (!request || typeof request !== 'object') {
      throw ArcError.invalidRequestSchema('Invalid request payload.');
    }
    if (typeof request.content !== 'string') {
      throw ArcError.invalidRequestSchema('content must be a string.');
    }

    const contentBuffer = Buffer.from(request.content, 'utf8');
    if (contentBuffer.length > MAX_MUTATION_BYTES) {
      throw ArcError.payloadTooLarge('create_file content exceeds maximum allowed limit of 1 MiB.');
    }

    const { absolutePath, relativePath, parentDir } = validateMutationPath(
      workspaceRoot,
      request.path,
      this.fsOps,
    );

    // Immediate parent directory must already exist
    let parentSt: Stats;
    try {
      parentSt = this.fsOps.lstat(parentDir);
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        throw err;
      }
      const code = (err as { code?: string }).code;
      if (code === 'ENOENT') {
        throw ArcError.parentNotFound('Immediate parent directory does not exist.');
      }
      sanitizeFsError(err);
    }

    if (!parentSt.isDirectory()) {
      throw ArcError.notADirectory('Immediate parent path is not a directory.');
    }
    if (parentSt.isSymbolicLink()) {
      throw ArcError.unsafeSymlink('Immediate parent path is a symbolic link.');
    }

    return this.lockManager.withLocks([absolutePath], async () => {
      try {
        const existing = this.fsOps.lstat(absolutePath);
        if (existing) {
          if (existing.isSymbolicLink()) {
            throw ArcError.unsafeSymlink('Target path is an existing symbolic link.');
          }
          throw ArcError.alreadyExists('Target file already exists.');
        }
      } catch (err: unknown) {
        if (err instanceof ArcError) {
          throw err;
        }
        const code = (err as { code?: string }).code;
        if (code !== 'ENOENT') {
          sanitizeFsError(err);
        }
      }

      const tmpPath = join(parentDir, `.arc-tmp-${randomUUID()}`);
      let tmpCreated = false;
      let fd: number | undefined;
      let tmpDev = 0;
      let tmpIno = 0;

      try {
        try {
          fd = this.fsOps.open(tmpPath, 'wx', 0o644);
          tmpCreated = true;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        writeAll(this.fsOps, fd, contentBuffer);

        try {
          this.fsOps.fsync(fd);
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        try {
          const tmpSt = this.fsOps.lstat(tmpPath);
          tmpDev = tmpSt.dev;
          tmpIno = tmpSt.ino;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        try {
          this.fsOps.close(fd);
          fd = undefined;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        try {
          this.fsOps.link(tmpPath, absolutePath);
        } catch (linkErr: unknown) {
          if (linkErr instanceof ArcError) {
            throw linkErr;
          }
          const code = (linkErr as { code?: string }).code;
          if (code === 'EEXIST') {
            try {
              const raceSt = this.fsOps.lstat(absolutePath);
              if (raceSt.isSymbolicLink()) {
                throw ArcError.unsafeSymlink('Target path is an existing symbolic link.');
              }
            } catch (stErr: unknown) {
              if (stErr instanceof ArcError) {
                throw stErr;
              }
            }
            throw ArcError.alreadyExists('Target file already exists.');
          }
          sanitizeFsError(linkErr);
        }

        try {
          this.fsOps.unlink(tmpPath);
          tmpCreated = false;
        } catch {
          // Temp cleanup failed after destination link succeeded.
          // Truthful recovery: attempt safe rollback ONLY if destination still refers to staged inode.
          let destSt: Stats | undefined;
          try {
            destSt = this.fsOps.lstat(absolutePath);
          } catch {
            destSt = undefined;
          }

          let rollbackSucceeded = false;
          if (destSt && destSt.dev === tmpDev && destSt.ino === tmpIno) {
            try {
              this.fsOps.unlink(absolutePath);
              rollbackSucceeded = true;
            } catch {
              rollbackSucceeded = false;
            }
          }

          if (rollbackSucceeded) {
            throw ArcError.internalError(
              'Failed to clean up temporary file; file creation was rolled back.',
            );
          } else {
            throw ArcError.rollbackFailed(
              'File creation committed but temporary cleanup failed and destination rollback could not be completed.',
              {
                path: relativePath,
                committed: true,
              },
            );
          }
        }
      } finally {
        if (fd !== undefined) {
          try {
            this.fsOps.close(fd);
          } catch {
            // ignore
          }
        }
        if (tmpCreated) {
          try {
            this.fsOps.unlink(tmpPath);
          } catch {
            // ignore
          }
        }
      }

      return {
        path: relativePath,
        bytesWritten: contentBuffer.length,
        contentHash: computeSha256(contentBuffer),
        created: true,
      };
    });
  }

  public async writeFile(
    workspaceRoot: string,
    request: WriteFileRequest,
  ): Promise<WriteFileResponse> {
    if (!request || typeof request !== 'object') {
      throw ArcError.invalidRequestSchema('Invalid request payload.');
    }
    if (typeof request.content !== 'string') {
      throw ArcError.invalidRequestSchema('content must be a string.');
    }
    if (request.overwrite !== true) {
      throw ArcError.invalidRequestSchema('overwrite must be explicitly true.');
    }

    const expectedHash = validateExpectedHash(request.expectedHash);
    const contentBuffer = Buffer.from(request.content, 'utf8');
    if (contentBuffer.length > MAX_MUTATION_BYTES) {
      throw ArcError.payloadTooLarge('write_file content exceeds maximum allowed limit of 1 MiB.');
    }

    const { absolutePath, relativePath, parentDir } = validateMutationPath(
      workspaceRoot,
      request.path,
      this.fsOps,
    );

    return this.lockManager.withLocks([absolutePath], async () => {
      const initial = captureFileIdentity(this.fsOps, absolutePath);
      if (initial.hash !== expectedHash) {
        throw ArcError.conflictPreconditionFailed('Current file hash does not match expectedHash.');
      }

      const targetMode = initial.mode & 0o777;
      const tmpPath = join(parentDir, `.arc-tmp-${randomUUID()}`);
      let tmpCreated = false;
      let fd: number | undefined;

      try {
        try {
          fd = this.fsOps.open(tmpPath, 'wx', targetMode);
          tmpCreated = true;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        writeAll(this.fsOps, fd, contentBuffer);

        try {
          this.fsOps.fchmod(fd, targetMode);
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        try {
          this.fsOps.fsync(fd);
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        try {
          this.fsOps.close(fd);
          fd = undefined;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }

        verifyPrecommitIdentity(this.fsOps, absolutePath, {
          dev: initial.dev,
          ino: initial.ino,
          hash: expectedHash,
        });

        try {
          this.fsOps.rename(tmpPath, absolutePath);
          tmpCreated = false;
        } catch (err: unknown) {
          sanitizeFsError(err);
        }
      } finally {
        if (fd !== undefined) {
          try {
            this.fsOps.close(fd);
          } catch {
            // ignore
          }
        }
        if (tmpCreated) {
          try {
            this.fsOps.unlink(tmpPath);
          } catch {
            // ignore
          }
        }
      }

      return {
        path: relativePath,
        bytesWritten: contentBuffer.length,
        contentHash: computeSha256(contentBuffer),
        previousHash: initial.hash,
      };
    });
  }

  public async deleteFile(
    workspaceRoot: string,
    request: DeleteFileRequest,
  ): Promise<DeleteFileResponse> {
    if (!request || typeof request !== 'object') {
      throw ArcError.invalidRequestSchema('Invalid request payload.');
    }
    const expectedHash = validateExpectedHash(request.expectedHash);

    const { absolutePath, relativePath } = validateMutationPath(
      workspaceRoot,
      request.path,
      this.fsOps,
    );

    return this.lockManager.withLocks([absolutePath], async () => {
      const initial = captureFileIdentity(this.fsOps, absolutePath);
      if (initial.hash !== expectedHash) {
        throw ArcError.conflictPreconditionFailed('Current file hash does not match expectedHash.');
      }

      verifyPrecommitIdentity(this.fsOps, absolutePath, {
        dev: initial.dev,
        ino: initial.ino,
        hash: expectedHash,
      });

      try {
        this.fsOps.unlink(absolutePath);
      } catch (err: unknown) {
        sanitizeFsError(err);
      }

      return {
        path: relativePath,
        deleted: true,
        contentHash: initial.hash,
      };
    });
  }

  public async moveFile(
    workspaceRoot: string,
    request: MoveFileRequest,
  ): Promise<MoveFileResponse> {
    if (!request || typeof request !== 'object') {
      throw ArcError.invalidRequestSchema('Invalid request payload.');
    }
    const expectedSourceHash = validateExpectedHash(
      request.expectedSourceHash,
      'expectedSourceHash',
    );

    const src = validateMutationPath(workspaceRoot, request.sourcePath, this.fsOps);
    const dest = validateMutationPath(workspaceRoot, request.destinationPath, this.fsOps);

    if (src.absolutePath === dest.absolutePath) {
      throw ArcError.alreadyExists('Destination path is identical to source path.');
    }

    // Destination parent directory must exist
    let destParentSt: Stats;
    try {
      destParentSt = this.fsOps.lstat(dest.parentDir);
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        throw err;
      }
      const code = (err as { code?: string }).code;
      if (code === 'ENOENT') {
        throw ArcError.parentNotFound('Destination parent directory does not exist.');
      }
      sanitizeFsError(err);
    }

    if (!destParentSt.isDirectory()) {
      throw ArcError.notADirectory('Destination parent path is not a directory.');
    }
    if (destParentSt.isSymbolicLink()) {
      throw ArcError.unsafeSymlink('Destination parent path is a symbolic link.');
    }

    return this.lockManager.withLocks([src.absolutePath, dest.absolutePath], async () => {
      const srcInitial = captureFileIdentity(this.fsOps, src.absolutePath);
      if (srcInitial.hash !== expectedSourceHash) {
        throw ArcError.conflictPreconditionFailed(
          'Current source file hash does not match expectedSourceHash.',
        );
      }

      try {
        const destSt = this.fsOps.lstat(dest.absolutePath);
        if (destSt) {
          if (destSt.isSymbolicLink()) {
            throw ArcError.unsafeSymlink('Destination path is an existing symbolic link.');
          }
          throw ArcError.alreadyExists('Destination file already exists.');
        }
      } catch (err: unknown) {
        if (err instanceof ArcError) {
          throw err;
        }
        const code = (err as { code?: string }).code;
        if (code !== 'ENOENT') {
          sanitizeFsError(err);
        }
      }

      verifyPrecommitIdentity(this.fsOps, src.absolutePath, {
        dev: srcInitial.dev,
        ino: srcInitial.ino,
        hash: expectedSourceHash,
      });

      try {
        this.fsOps.link(src.absolutePath, dest.absolutePath);
      } catch (err: unknown) {
        if (err instanceof ArcError) {
          throw err;
        }
        const code = (err as { code?: string }).code;
        if (code === 'EEXIST') {
          throw ArcError.alreadyExists('Destination file already exists.');
        }
        if (code === 'EXDEV') {
          throw ArcError.crossDeviceMoveUnsupported('Cross-device move is not supported.');
        }
        sanitizeFsError(err);
      }

      let destSt: Stats;
      try {
        destSt = this.fsOps.lstat(dest.absolutePath);
      } catch (err: unknown) {
        sanitizeFsError(err);
      }

      if (destSt.dev !== srcInitial.dev || destSt.ino !== srcInitial.ino) {
        // Destination identity does not match source. Do NOT blindly unlink unrelated replacement!
        throw ArcError.conflictPreconditionFailed(
          'Destination link identity does not match source file.',
        );
      }

      try {
        this.fsOps.unlink(src.absolutePath);
      } catch (unlinkErr: unknown) {
        // Source unlink failed. Before rollback unlink:
        // lstat destination and prove destination dev/inode still equals captured source identity!
        let rollDestSt: Stats | undefined;
        try {
          rollDestSt = this.fsOps.lstat(dest.absolutePath);
        } catch {
          rollDestSt = undefined;
        }

        let rollbackSucceeded = false;
        if (rollDestSt && rollDestSt.dev === srcInitial.dev && rollDestSt.ino === srcInitial.ino) {
          try {
            this.fsOps.unlink(dest.absolutePath);
            rollbackSucceeded = true;
          } catch {
            rollbackSucceeded = false;
          }
        }

        if (!rollbackSucceeded) {
          throw ArcError.rollbackFailed(
            'Move failed: source file could not be removed and destination rollback could not be verified or completed.',
            {
              sourcePath: src.relativePath,
              destinationPath: dest.relativePath,
              sourceExists: true,
            },
          );
        }

        sanitizeFsError(unlinkErr);
      }

      return {
        sourcePath: src.relativePath,
        destinationPath: dest.relativePath,
        moved: true,
      };
    });
  }

  public async applyPatch(
    workspaceRoot: string,
    request: ApplyPatchRequest,
  ): Promise<ApplyPatchResponse> {
    return applyPatch(workspaceRoot, request, this.fsOps, this.lockManager);
  }
}

/**
 * Default Node.js filesystem search backend.
 */
export class NodeSearchBackend implements ISearchBackend {
  public async searchFiles(
    searchRoot: string,
    canonicalRoot: string,
    request: SearchFilesRequest,
  ): Promise<SearchFilesResponse> {
    if (
      !request.pattern ||
      typeof request.pattern !== 'string' ||
      request.pattern.trim().length === 0
    ) {
      throw ArcError.invalidRequestSchema('pattern must be a non-empty string.');
    }

    const maxResults = Math.min(
      request.maxResults && request.maxResults > 0 ? request.maxResults : 50,
      MAX_SEARCH_RESULTS,
    );

    const pattern = request.pattern.trim();
    // Convert glob-like wildcard (*, ?) to regex
    const regexPattern = new RegExp(
      '^' +
        pattern
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*/g, '.*')
          .replace(/\?/g, '.') +
        '$',
      'i',
    );

    const matches: string[] = [];

    const walk = (currentDir: string): void => {
      if (matches.length >= maxResults) {
        return;
      }

      let dirents;
      try {
        dirents = readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const dirent of dirents) {
        if (matches.length >= maxResults) {
          break;
        }

        const name = dirent.name;
        const fullPath = join(currentDir, name);
        const relFromRoot = relative(canonicalRoot, fullPath);

        // Blacklist filtering
        if (isBlacklistedPath(fullPath, relFromRoot)) {
          continue;
        }

        if (dirent.isDirectory()) {
          // Skip .git directory traversal
          if (name === '.git') {
            continue;
          }
          walk(fullPath);
        } else if (dirent.isFile()) {
          if (regexPattern.test(name) || regexPattern.test(relFromRoot)) {
            matches.push(relFromRoot.replace(/\\/g, '/'));
          }
        }
      }
    };

    walk(searchRoot);

    return {
      matches,
      totalMatches: matches.length,
    };
  }

  public async searchText(
    canonicalRoot: string,
    request: SearchTextRequest,
  ): Promise<SearchTextResponse> {
    if (!request.query || typeof request.query !== 'string') {
      throw ArcError.invalidRequestSchema('query must be a non-empty string.');
    }

    const maxMatches = Math.min(
      request.maxMatches && request.maxMatches > 0 ? request.maxMatches : 50,
      MAX_SEARCH_RESULTS,
    );

    const isRegex = Boolean(request.isRegex);

    let matcher: (line: string) => boolean;

    if (isRegex) {
      if (request.query.length > 100) {
        throw ArcError.invalidRequestSchema(
          'Regex query exceeds 100 characters limit (ReDoS defense).',
        );
      }
      // Check for pathological nested quantifiers: (a+)+, (a*)*, etc.
      if (
        /(\+[*+]|\*[*+]|\{[0-9,]+\}[*+])/.test(request.query) ||
        /\([^)]+[*+]\)[*+]/.test(request.query) ||
        /([a-zA-Z0-9_]+)+\$/.test(request.query)
      ) {
        throw ArcError.invalidRequestSchema(
          'Regex contains potentially dangerous nested quantifiers (ReDoS protection).',
        );
      }
      try {
        const rx = new RegExp(request.query);
        matcher = (line: string) => rx.test(line);
      } catch (err: unknown) {
        throw ArcError.invalidRequestSchema(
          `Invalid regular expression: ${(err as Error).message}`,
        );
      }
    } else {
      const q = request.query;
      matcher = (line: string) => line.includes(q);
    }

    // Optional filePattern filter (glob style)
    let filePatternRegex: RegExp | undefined;
    if (request.filePattern && typeof request.filePattern === 'string') {
      const pat = request.filePattern.trim();
      if (pat.length > 0) {
        filePatternRegex = new RegExp(
          '^' +
            pat
              .replace(/[.+^${}()|[\]\\]/g, '\\$&')
              .replace(/\*/g, '.*')
              .replace(/\?/g, '.') +
            '$',
          'i',
        );
      }
    }

    const matches: TextMatchItem[] = [];
    const searchStartMs = Date.now();
    const MAX_SEARCH_DURATION_MS = 5000;

    const walk = (currentDir: string): void => {
      if (matches.length >= maxMatches || Date.now() - searchStartMs > MAX_SEARCH_DURATION_MS) {
        return;
      }

      let dirents;
      try {
        dirents = readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const dirent of dirents) {
        if (matches.length >= maxMatches || Date.now() - searchStartMs > MAX_SEARCH_DURATION_MS) {
          break;
        }

        const name = dirent.name;
        const fullPath = join(currentDir, name);
        const relFromRoot = relative(canonicalRoot, fullPath);

        if (isBlacklistedPath(fullPath, relFromRoot)) {
          continue;
        }

        if (dirent.isDirectory()) {
          if (name === '.git' || name === 'node_modules') {
            continue;
          }
          walk(fullPath);
        } else if (dirent.isFile()) {
          // If filePattern is specified, filter files
          if (
            filePatternRegex &&
            !filePatternRegex.test(name) &&
            !filePatternRegex.test(relFromRoot.replace(/\\/g, '/'))
          ) {
            continue;
          }

          // Skip binary files
          if (isBinaryFile(fullPath)) {
            continue;
          }

          try {
            const st = statSync(fullPath);
            if (st.size > MAX_READ_BYTES) {
              // Skip files larger than 1 MiB for text search to prevent memory exhaustion
              continue;
            }

            const content = Buffer.alloc(st.size);
            const fd = openSync(fullPath, 'r');
            try {
              readSync(fd, content, 0, st.size, 0);
            } finally {
              closeSync(fd);
            }

            const lines = content.toString('utf8').split(/\r?\n/);
            for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
              if (
                matches.length >= maxMatches ||
                Date.now() - searchStartMs > MAX_SEARCH_DURATION_MS
              ) {
                break;
              }
              const line = lines[lineIdx];
              if (matcher(line)) {
                matches.push({
                  path: relFromRoot.replace(/\\/g, '/'),
                  lineNumber: lineIdx + 1,
                  lineContent: line.slice(0, 500), // Cap line snippet length
                });
              }
            }
          } catch {
            // Skip unreadable files
          }
        }
      }
    };

    walk(canonicalRoot);

    return {
      matches,
      totalMatches: matches.length,
    };
  }
}
