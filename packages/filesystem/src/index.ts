import { realpathSync, statSync, readdirSync, openSync, readSync, closeSync } from 'node:fs';
import { resolve, normalize, sep, relative, join } from 'node:path';
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
} from '@cesspace-arc/protocol';

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
      throw ArcError.noWorkspaceConfigured(`Workspace root '${workspaceRoot}' does not exist.`);
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
        throw ArcError.fileNotFound(`Target path '${requestedPath}' does not exist in workspace.`);
      }
      throw ArcError.internalError(`Filesystem resolution error: ${nodeErr.message}`);
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

  public async listDirectory(
    workspaceRoot: string,
    request: ListDirectoryRequest,
  ): Promise<ListDirectoryResponse> {
    const rawPath = request.path || '.';
    const canonicalPath = await this.resolveSecurePath(workspaceRoot, rawPath);

    const st = statSync(canonicalPath);
    if (!st.isDirectory()) {
      throw ArcError.notADirectory(`Path '${rawPath}' is not a directory.`);
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
      throw ArcError.isADirectory(`Target path '${request.path}' is a directory, not a file.`);
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
        `Requested read length (${requestedLength} bytes) exceeds maximum limit of 1 MiB (${MAX_READ_BYTES} bytes).`,
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

    const subPath = request.subPath || '.';
    const searchRoot = await this.resolveSecurePath(workspaceRoot, subPath);
    const canonicalRoot = realpathSync(resolve(workspaceRoot));

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
    workspaceRoot: string,
    request: SearchTextRequest,
  ): Promise<SearchTextResponse> {
    if (!request.query || typeof request.query !== 'string') {
      throw ArcError.invalidRequestSchema('query must be a non-empty string.');
    }

    const maxMatches = Math.min(
      request.maxMatches && request.maxMatches > 0 ? request.maxMatches : 50,
      MAX_SEARCH_RESULTS,
    );

    const canonicalRoot = realpathSync(resolve(workspaceRoot));
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
        /\([^)]+[*+]\)[*+]/.test(request.query)
      ) {
        throw ArcError.invalidRequestSchema(
          'Regex contains potentially dangerous nested quantifiers.',
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

    const matches: TextMatchItem[] = [];

    const walk = (currentDir: string): void => {
      if (matches.length >= maxMatches) {
        return;
      }

      let dirents;
      try {
        dirents = readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const dirent of dirents) {
        if (matches.length >= maxMatches) {
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
              if (matches.length >= maxMatches) {
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
