import { normalize, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Stats } from 'node:fs';
import { ArcError, type ApplyPatchRequest, type ApplyPatchResponse } from '@cesspace-arc/protocol';
import type { IFilesystemOps } from './fs-ops.js';
import type { ILockManager } from './locks.js';
import { validateMutationPath, writeAll, sanitizeFsError } from './mutation-security.js';
import { computeSha256, verifyPrecommitIdentity } from './file-identity.js';

/**
 * Maximum patch payload byte size: 512 KiB (524,288 UTF-8 bytes).
 */
export const MAX_PATCH_BYTES = 512 * 1024;

/**
 * Maximum distinct target files in a single patch.
 */
export const MAX_PATCH_FILES = 10;

export interface HunkLine {
  type: 'context' | 'insert' | 'delete';
  content: string;
  noNewline?: boolean;
}

export interface ParsedHunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: HunkLine[];
}

export interface ParsedFilePatch {
  oldHeaderPath: string;
  newHeaderPath: string;
  targetPath: string;
  hunks: ParsedHunk[];
}

export interface ParsedPatch {
  files: ParsedFilePatch[];
}

export interface PatchPreflightFile {
  targetPath: string;
  canonicalPath: string;
  relativePath: string;
  parentDir: string;
  originalBytes: Buffer;
  originalText: string;
  preflightHash: string;
  dev: number;
  ino: number;
  originalMode: number;
  eol: '\r\n' | '\n';
  hasFinalNewline: boolean;
  patchedBytes: Buffer;
  patchedHash: string;
  insertions: number;
  deletions: number;
}

const FORBIDDEN_DIRECTIVES: RegExp[] = [
  /^old mode /i,
  /^new mode /i,
  /^new file mode /i,
  /^deleted file mode /i,
  /^rename from /i,
  /^rename to /i,
  /^copy from /i,
  /^copy to /i,
  /^similarity index /i,
  /^GIT binary patch/i,
  /^Binary files? .* differ/i,
];

/**
 * Extracts and normalizes the logical relative path from a patch header line.
 */
function extractLogicalPath(headerPath: string): string {
  // Strip tab and trailing timestamp metadata
  const withoutTimestamp = headerPath.split('\t')[0].trim();
  let clean = withoutTimestamp;
  if (clean.startsWith('"') && clean.endsWith('"')) {
    clean = clean.slice(1, -1);
  }
  // Strip conventional a/ or b/ prefixes
  if (clean.startsWith('a/') || clean.startsWith('b/')) {
    clean = clean.slice(2);
  } else if (clean.startsWith('a\\') || clean.startsWith('b\\')) {
    clean = clean.slice(2);
  }
  return normalize(clean).replace(/\\/g, '/');
}

/**
 * Parses a unified diff string conforming to the frozen RC-03 specification.
 * Rejects forbidden directives, malformed headers, invalid line counts, overlapping hunks,
 * and duplicate file sections.
 */
export function parseUnifiedPatch(patch: string): ParsedPatch {
  const byteLength = Buffer.byteLength(patch, 'utf8');
  if (byteLength > MAX_PATCH_BYTES) {
    throw ArcError.payloadTooLarge(
      `Patch payload size of ${byteLength} bytes exceeds the maximum limit of ${MAX_PATCH_BYTES} bytes.`,
    );
  }

  if (byteLength === 0 || patch.trim().length === 0) {
    throw ArcError.invalidRequestSchema('Patch parameter is required and cannot be empty.');
  }

  const rawLines = patch.split(/\r?\n/);
  const files: ParsedFilePatch[] = [];

  let currentOldPath: string | null = null;
  let currentNewPath: string | null = null;
  let currentFileHunks: ParsedHunk[] = [];

  let currentHunk: ParsedHunk | null = null;
  let inHunk = false;
  let expectedContextAndDeletions = 0;
  let expectedContextAndInsertions = 0;
  let seenContextAndDeletions = 0;
  let seenContextAndInsertions = 0;
  let cumulativeDelta = 0;

  function finalizeCurrentFile(): void {
    const oldTarget = extractLogicalPath(currentOldPath!);
    const newTarget = extractLogicalPath(currentNewPath!);

    if (oldTarget !== newTarget) {
      throw ArcError.patchUnsupportedOperation(
        'Old path and new path do not match: renaming or moving is not supported.',
      );
    }

    if (files.some((f) => f.targetPath === oldTarget)) {
      throw ArcError.patchParseError('Duplicate file section in patch is not allowed.');
    }

    if (currentFileHunks.length === 0) {
      throw ArcError.patchParseError('File section contains no hunks.');
    }

    // Verify hunks are ordered and non-overlapping
    for (let h = 0; h < currentFileHunks.length - 1; h++) {
      const h1 = currentFileHunks[h];
      const h2 = currentFileHunks[h + 1];
      const h1End = h1.oldCount === 0 ? h1.oldStart : h1.oldStart + h1.oldCount - 1;
      if (h2.oldStart <= h1End) {
        throw ArcError.patchParseError('Hunks in file patch overlap or are out of order.');
      }
    }

    files.push({
      oldHeaderPath: currentOldPath!,
      newHeaderPath: currentNewPath!,
      targetPath: oldTarget,
      hunks: currentFileHunks,
    });

    currentOldPath = null;
    currentNewPath = null;
    currentFileHunks = [];
    cumulativeDelta = 0;
  }

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i];

    if (inHunk && currentHunk) {
      if (line.startsWith('\\ No newline at end of file')) {
        if (currentHunk.lines.length > 0) {
          currentHunk.lines[currentHunk.lines.length - 1].noNewline = true;
        }
        continue;
      }

      if (line.startsWith(' ') || line.startsWith('+') || line.startsWith('-')) {
        const type = line[0] === ' ' ? 'context' : line[0] === '+' ? 'insert' : 'delete';
        const content = line.slice(1);
        currentHunk.lines.push({ type, content });

        if (type === 'context') {
          seenContextAndDeletions++;
          seenContextAndInsertions++;
        } else if (type === 'delete') {
          seenContextAndDeletions++;
        } else if (type === 'insert') {
          seenContextAndInsertions++;
        }

        if (
          seenContextAndDeletions === expectedContextAndDeletions &&
          seenContextAndInsertions === expectedContextAndInsertions
        ) {
          cumulativeDelta += currentHunk.newCount - currentHunk.oldCount;
          currentFileHunks.push(currentHunk);
          currentHunk = null;
          inHunk = false;
        }
        continue;
      }

      // If in hunk and line doesn't match hunk line markers, line counts did not match
      throw ArcError.patchParseError('Hunk line counts do not match hunk header.');
    }

    // HEADER / BETWEEN HUNKS
    if (line.startsWith('\\ No newline at end of file')) {
      if (currentFileHunks.length > 0) {
        const lastHunk = currentFileHunks[currentFileHunks.length - 1];
        if (lastHunk.lines.length > 0) {
          lastHunk.lines[lastHunk.lines.length - 1].noNewline = true;
        }
      }
      continue;
    }

    // Check forbidden directives (only outside of hunk contents)
    for (const pattern of FORBIDDEN_DIRECTIVES) {
      if (pattern.test(line)) {
        throw ArcError.patchUnsupportedOperation(
          'Unsupported patch operation: file creation, deletion, renaming, mode changes, and binary patches are forbidden.',
        );
      }
    }

    if (line.startsWith('--- ')) {
      if (currentOldPath && currentNewPath) {
        finalizeCurrentFile();
      } else if (currentOldPath && !currentNewPath) {
        throw ArcError.patchParseError('Malformed patch header: missing +++ after ---.');
      }

      const rawOld = line.slice(4).trim();
      if (rawOld === '/dev/null' || rawOld.startsWith('/dev/null')) {
        throw ArcError.patchUnsupportedOperation('File creation is not supported by apply_patch.');
      }
      currentOldPath = rawOld;
      continue;
    }

    if (line.startsWith('+++ ')) {
      if (!currentOldPath) {
        throw ArcError.patchParseError('Malformed patch header: +++ without preceding ---.');
      }
      const rawNew = line.slice(4).trim();
      if (rawNew === '/dev/null' || rawNew.startsWith('/dev/null')) {
        throw ArcError.patchUnsupportedOperation('File deletion is not supported by apply_patch.');
      }
      currentNewPath = rawNew;
      continue;
    }

    const hunkMatch = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (hunkMatch) {
      if (!currentOldPath || !currentNewPath) {
        throw ArcError.patchParseError('Hunk found without preceding file headers (--- and +++).');
      }

      const oldStart = parseInt(hunkMatch[1], 10);
      const oldCount = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
      const newStart = parseInt(hunkMatch[3], 10);
      const newCount = hunkMatch[4] !== undefined ? parseInt(hunkMatch[4], 10) : 1;

      if (
        !Number.isSafeInteger(oldStart) ||
        !Number.isSafeInteger(oldCount) ||
        !Number.isSafeInteger(newStart) ||
        !Number.isSafeInteger(newCount) ||
        oldStart < 0 ||
        oldCount < 0 ||
        newStart < 0 ||
        newCount < 0
      ) {
        throw ArcError.patchParseError('Hunk header contains invalid numeric coordinates.');
      }

      let expectedNewStart: number;
      if (oldCount > 0 && newCount > 0) {
        expectedNewStart = oldStart + cumulativeDelta;
      } else if (oldCount === 0) {
        if (oldStart === 0) {
          expectedNewStart = newCount === 0 ? 0 : 1 + cumulativeDelta;
        } else {
          expectedNewStart = oldStart + cumulativeDelta + 1;
        }
      } else {
        expectedNewStart = oldStart + cumulativeDelta > 0 ? oldStart + cumulativeDelta - 1 : 0;
      }

      if (newStart !== expectedNewStart) {
        throw ArcError.patchParseError(
          `Hunk new-range coordinates (${newStart}) are inconsistent with old-range coordinates (${oldStart}) and delta (${cumulativeDelta}).`,
        );
      }

      currentHunk = {
        oldStart,
        oldCount,
        newStart,
        newCount,
        lines: [],
      };
      inHunk = true;
      expectedContextAndDeletions = oldCount;
      expectedContextAndInsertions = newCount;
      seenContextAndDeletions = 0;
      seenContextAndInsertions = 0;

      if (oldCount === 0 && newCount === 0) {
        cumulativeDelta += newCount - oldCount;
        currentFileHunks.push(currentHunk);
        currentHunk = null;
        inHunk = false;
      }
      continue;
    }

    if (line.startsWith('diff --git ')) {
      if (currentOldPath && currentNewPath) {
        finalizeCurrentFile();
      }
      continue;
    }

    if (line.startsWith('index ')) {
      continue;
    }

    if (line.trim() === '') {
      continue;
    }

    // Unrecognized directive outside hunk
    throw ArcError.patchParseError('Malformed patch line outside of hunk.');
  }

  if (inHunk) {
    throw ArcError.patchParseError(
      'Patch ended unexpectedly before hunk line counts were satisfied.',
    );
  }

  if (currentOldPath && currentNewPath) {
    finalizeCurrentFile();
  } else if (currentOldPath && !currentNewPath) {
    throw ArcError.patchParseError('Malformed patch header: missing +++ after ---.');
  }

  if (files.length === 0) {
    throw ArcError.patchParseError('Patch contains no valid file modifications.');
  }

  if (files.length > MAX_PATCH_FILES) {
    throw ArcError.payloadTooLarge(
      `Patch contains ${files.length} target files, exceeding maximum allowed limit of ${MAX_PATCH_FILES}.`,
    );
  }

  return { files };
}

/**
 * Validates text file characteristics and detects line-ending conventions.
 * Rejects binary files (NUL bytes), invalid UTF-8, and mixed line endings.
 */
export function detectTextFileAndNewlines(bytes: Buffer): {
  text: string;
  eol: '\r\n' | '\n';
  hasFinalNewline: boolean;
} {
  if (bytes.includes(0)) {
    throw ArcError.patchPreflightFailed('Target file contains binary content (NUL byte detected).');
  }

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw ArcError.patchPreflightFailed('Target file is not valid UTF-8 text.');
  }

  const hasCRLF = text.includes('\r\n');
  const hasStandaloneLF = /(?<!\r)\n/.test(text);
  const hasStandaloneCR = /\r(?!\n)/.test(text);

  if ((hasCRLF && hasStandaloneLF) || hasStandaloneCR) {
    throw ArcError.patchPreflightFailed(
      'Target file contains mixed or unsupported line endings (preservation not possible).',
    );
  }

  const eol: '\r\n' | '\n' = hasCRLF ? '\r\n' : '\n';
  const hasFinalNewline = text.endsWith(eol);

  return { text, eol, hasFinalNewline };
}

/**
 * Applies hunks with exact zero-fuzz matching in memory.
 * Preserves existing line ending conventions and final newline status.
 */
export function applyHunksExact(
  originalText: string,
  hunks: ParsedHunk[],
  eol: '\r\n' | '\n',
  hasFinalNewline: boolean,
): {
  patchedBytes: Buffer;
  insertions: number;
  deletions: number;
} {
  let lines: string[];
  if (originalText.length === 0) {
    lines = [];
  } else if (hasFinalNewline) {
    lines = originalText.slice(0, -eol.length).split(eol);
  } else {
    lines = originalText.split(eol);
  }

  let insertions = 0;
  let deletions = 0;

  // Verify all hunks match first
  for (const hunk of hunks) {
    const origStart = hunk.oldCount === 0 ? hunk.oldStart : hunk.oldStart - 1;
    if (hunk.oldCount > 0) {
      if (hunk.oldStart < 1 || origStart + hunk.oldCount > lines.length) {
        throw ArcError.patchPreflightFailed('Patch hunk line range is out of bounds.');
      }
    } else {
      if (hunk.oldStart < 0 || hunk.oldStart > lines.length) {
        throw ArcError.patchPreflightFailed('Patch hunk line range is out of bounds.');
      }
    }

    let lineIdx = origStart;
    for (const hLine of hunk.lines) {
      if (hLine.type === 'context') {
        if (lineIdx >= lines.length || lines[lineIdx] !== hLine.content) {
          throw ArcError.patchPreflightFailed('Patch hunk context did not match target file.');
        }
        lineIdx++;
      } else if (hLine.type === 'delete') {
        if (lineIdx >= lines.length || lines[lineIdx] !== hLine.content) {
          throw ArcError.patchPreflightFailed(
            'Patch hunk deletion line did not match target file.',
          );
        }
        lineIdx++;
        deletions++;
      } else if (hLine.type === 'insert') {
        insertions++;
      }
    }
  }

  // Generate patched lines
  const newLines: string[] = [];
  let cursor = 0;
  let lastLineNoNewline = false;

  for (const hunk of hunks) {
    const hunkStart = hunk.oldCount === 0 ? hunk.oldStart : hunk.oldStart - 1;
    const hunkEnd = hunkStart + hunk.oldCount;

    while (cursor < hunkStart) {
      newLines.push(lines[cursor]);
      cursor++;
    }

    for (const hLine of hunk.lines) {
      if (hLine.type === 'context' || hLine.type === 'insert') {
        newLines.push(hLine.content);
        if (hLine.noNewline) {
          lastLineNoNewline = true;
        } else {
          lastLineNoNewline = false;
        }
      }
    }

    cursor = hunkEnd;
  }

  const hadUntouchedTrailingLines = cursor < lines.length;

  while (cursor < lines.length) {
    newLines.push(lines[cursor]);
    cursor++;
    lastLineNoNewline = false;
  }

  let finalNewline: boolean;
  if (newLines.length === 0) {
    finalNewline = false;
  } else if (hadUntouchedTrailingLines) {
    finalNewline = hasFinalNewline;
  } else {
    finalNewline = !lastLineNoNewline;
  }

  const patchedText = newLines.join(eol) + (finalNewline ? eol : '');
  const patchedBytes = Buffer.from(patchedText, 'utf8');

  return {
    patchedBytes,
    insertions,
    deletions,
  };
}

/**
 * Authoritative apply_patch engine implementing:
 * PARSE -> RESOLVE TARGETS -> ACQUIRE LOCKS -> PREFLIGHT ALL -> DRY-RUN OR STAGE ALL -> REVALIDATE -> COMMIT -> ROLLBACK
 */
export async function applyPatch(
  workspaceRoot: string,
  request: ApplyPatchRequest,
  fsOps: IFilesystemOps,
  lockManager: ILockManager,
): Promise<ApplyPatchResponse> {
  if (!request || typeof request !== 'object') {
    throw ArcError.invalidRequestSchema('Invalid request payload.');
  }
  if (typeof request.patch !== 'string') {
    throw ArcError.invalidRequestSchema('patch must be a string.');
  }
  if (request.fuzz !== undefined) {
    if (typeof request.fuzz !== 'number' || !Number.isInteger(request.fuzz) || request.fuzz !== 0) {
      throw ArcError.invalidRequestSchema('fuzz parameter must be an integer equal to 0.');
    }
  }
  if (request.dryRun !== undefined && typeof request.dryRun !== 'boolean') {
    throw ArcError.invalidRequestSchema('dryRun parameter must be a boolean.');
  }

  const dryRun = Boolean(request.dryRun);

  // 1. Parse patch
  const parsedPatch = parseUnifiedPatch(request.patch);

  // 2. Validate mutation paths for all targets
  const targetItems = parsedPatch.files.map((file) => {
    const validated = validateMutationPath(workspaceRoot, file.targetPath, fsOps);
    return { file, validated };
  });

  // Sort deterministically by canonical absolute path
  targetItems.sort((a, b) => a.validated.absolutePath.localeCompare(b.validated.absolutePath));
  const allAbsPaths = targetItems.map((t) => t.validated.absolutePath);

  // 3. Acquire locks for ALL target files before preflight
  return lockManager.withLocks(allAbsPaths, async () => {
    // 4. Preflight all targets in memory
    const preflightFiles: PatchPreflightFile[] = [];
    let totalInsertions = 0;
    let totalDeletions = 0;

    for (const target of targetItems) {
      let st: Stats;
      try {
        st = fsOps.lstat(target.validated.absolutePath);
      } catch (err: unknown) {
        if (err instanceof ArcError) {
          throw err;
        }
        const code = (err as { code?: string }).code;
        if (code === 'ENOENT') {
          throw ArcError.patchPreflightFailed('Target file does not exist.');
        }
        sanitizeFsError(err);
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

      let originalBytes: Buffer;
      try {
        originalBytes = fsOps.readFile(target.validated.absolutePath);
      } catch (err: unknown) {
        sanitizeFsError(err);
      }

      const { text, eol, hasFinalNewline } = detectTextFileAndNewlines(originalBytes);
      const preflightHash = computeSha256(originalBytes);

      const { patchedBytes, insertions, deletions } = applyHunksExact(
        text,
        target.file.hunks,
        eol,
        hasFinalNewline,
      );

      const patchedHash = computeSha256(patchedBytes);
      totalInsertions += insertions;
      totalDeletions += deletions;

      preflightFiles.push({
        targetPath: target.file.targetPath,
        canonicalPath: target.validated.absolutePath,
        relativePath: target.validated.relativePath,
        parentDir: target.validated.parentDir,
        originalBytes,
        originalText: text,
        preflightHash,
        dev: st.dev,
        ino: st.ino,
        originalMode: st.mode & 0o777,
        eol,
        hasFinalNewline,
        patchedBytes,
        patchedHash,
        insertions,
        deletions,
      });
    }

    // 5. If dryRun, return simulation results with ZERO disk mutation
    if (dryRun) {
      return {
        success: true,
        modifiedFiles: preflightFiles.map((p) => p.relativePath),
        stats: {
          filesChanged: preflightFiles.length,
          insertions: totalInsertions,
          deletions: totalDeletions,
        },
        dryRun: true,
      };
    }

    // 6. Phase 2: Stage all replacements in temporary sibling files
    interface StagedItem {
      preflight: PatchPreflightFile;
      tmpPath: string;
      stagedDev: number;
      stagedIno: number;
    }
    const stagedItems: StagedItem[] = [];
    let stagingCleanupFailed = false;

    for (const p of preflightFiles) {
      const tmpPath = join(p.parentDir, `.arc-tmp-${randomUUID()}`);
      let fd: number | undefined;
      try {
        fd = fsOps.open(tmpPath, 'wx', p.originalMode);
        writeAll(fsOps, fd, p.patchedBytes);
        fsOps.fchmod(fd, p.originalMode);
        fsOps.fsync(fd);
        fsOps.close(fd);
        fd = undefined;

        const stagedSt = fsOps.lstat(tmpPath);
        stagedItems.push({
          preflight: p,
          tmpPath,
          stagedDev: stagedSt.dev,
          stagedIno: stagedSt.ino,
        });
      } catch (err: unknown) {
        if (fd !== undefined) {
          try {
            fsOps.close(fd);
          } catch {
            // ignore
          }
        }
        try {
          fsOps.unlink(tmpPath);
        } catch {
          stagingCleanupFailed = true;
        }
        for (const s of stagedItems) {
          try {
            fsOps.unlink(s.tmpPath);
          } catch {
            stagingCleanupFailed = true;
          }
        }
        if (stagingCleanupFailed) {
          throw ArcError.rollbackFailed(
            'Patch staging failed and temporary replacement files could not be safely removed.',
            { recoveryRequired: true },
          );
        }
        if (err instanceof ArcError) {
          throw err;
        }
        sanitizeFsError(err);
      }
    }

    // 7. Phase 3: Precommit Revalidation & Individual Commit with Rollback
    interface CommittedPatchFile {
      preflight: PatchPreflightFile;
      stagedDev: number;
      stagedIno: number;
      committedDev: number;
      committedIno: number;
      patchedHash: string;
      verified: boolean;
    }
    const committedFiles: CommittedPatchFile[] = [];
    let commitFailed = false;
    let failureError: unknown = null;
    let stagedCleanupFailed = false;

    try {
      for (const s of stagedItems) {
        const p = s.preflight;

        // Revalidate precommit identity
        try {
          verifyPrecommitIdentity(fsOps, p.canonicalPath, {
            dev: p.dev,
            ino: p.ino,
            hash: p.preflightHash,
          });
        } catch (err: unknown) {
          commitFailed = true;
          failureError = err;
          break;
        }

        // Commit via atomic rename
        try {
          fsOps.rename(s.tmpPath, p.canonicalPath);
        } catch (renameErr: unknown) {
          commitFailed = true;
          failureError = renameErr;
          break;
        }

        // RENAME OCCURRED: target has changed on disk!
        // Register immediately into committedFiles so it is never lost or forgotten
        const committedRecord: CommittedPatchFile = {
          preflight: p,
          stagedDev: s.stagedDev,
          stagedIno: s.stagedIno,
          committedDev: s.stagedDev,
          committedIno: s.stagedIno,
          patchedHash: p.patchedHash,
          verified: false,
        };
        committedFiles.push(committedRecord);

        // Post-commit identity and content verification
        try {
          const targetSt = fsOps.lstat(p.canonicalPath);
          if (
            !targetSt.isFile() ||
            targetSt.isSymbolicLink() ||
            targetSt.nlink !== 1 ||
            targetSt.dev !== s.stagedDev ||
            targetSt.ino !== s.stagedIno
          ) {
            throw ArcError.conflictPreconditionFailed(
              'Committed file inode identity did not match staged file identity.',
            );
          }
          committedRecord.committedDev = targetSt.dev;
          committedRecord.committedIno = targetSt.ino;

          const postBytes = fsOps.readFile(p.canonicalPath);
          const postHash = computeSha256(postBytes);
          if (postHash !== p.patchedHash) {
            throw ArcError.conflictPreconditionFailed('Post-commit content hash mismatch.');
          }
          committedRecord.verified = true;
        } catch (postVerifyErr: unknown) {
          commitFailed = true;
          failureError = postVerifyErr;
          break;
        }
      }
    } finally {
      // Clean up any unconsumed staged files
      for (const s of stagedItems) {
        if (!committedFiles.some((c) => c.preflight === s.preflight)) {
          try {
            fsOps.unlink(s.tmpPath);
          } catch {
            stagedCleanupFailed = true;
          }
        }
      }
    }

    // 8. Rollback if commit failed after one or more commits
    if (commitFailed) {
      if (committedFiles.length > 0) {
        const unrestoredFiles: string[] = [];
        let rollbackErrorOccurred = false;

        for (let i = committedFiles.length - 1; i >= 0; i--) {
          const c = committedFiles[i];
          const p = c.preflight;
          let curSt: Stats | undefined;
          let curHash: string | undefined;

          try {
            curSt = fsOps.lstat(p.canonicalPath);
            if (curSt.isFile() && !curSt.isSymbolicLink() && curSt.nlink === 1) {
              const curBytes = fsOps.readFile(p.canonicalPath);
              curHash = computeSha256(curBytes);
            }
          } catch {
            curSt = undefined;
          }

          // Inode identity MUST match ARC committed identity!
          // If inode changed: DO NOT OVERWRITE even if content hash is identical!
          if (
            curSt &&
            curSt.dev === c.committedDev &&
            curSt.ino === c.committedIno &&
            curHash === p.patchedHash
          ) {
            // File matches ARC committed state and inode: safe to rollback
            const rollTmp = join(p.parentDir, `.arc-tmp-${randomUUID()}`);
            let fd: number | undefined;
            try {
              fd = fsOps.open(rollTmp, 'wx', p.originalMode);
              writeAll(fsOps, fd, p.originalBytes);
              fsOps.fchmod(fd, p.originalMode);
              fsOps.fsync(fd);
              fsOps.close(fd);
              fd = undefined;

              const preRollSt = fsOps.lstat(p.canonicalPath);
              if (
                preRollSt.dev === c.committedDev &&
                preRollSt.ino === c.committedIno &&
                computeSha256(fsOps.readFile(p.canonicalPath)) === p.patchedHash
              ) {
                fsOps.rename(rollTmp, p.canonicalPath);

                // Immediately verify rollback restoration
                const restoredSt = fsOps.lstat(p.canonicalPath);
                const restoredBytes = fsOps.readFile(p.canonicalPath);
                const restoredHash = computeSha256(restoredBytes);

                if (
                  !restoredSt.isFile() ||
                  restoredSt.isSymbolicLink() ||
                  restoredSt.nlink !== 1 ||
                  (restoredSt.mode & 0o777) !== p.originalMode ||
                  restoredHash !== p.preflightHash
                ) {
                  unrestoredFiles.push(p.relativePath);
                  rollbackErrorOccurred = true;
                }
              } else {
                unrestoredFiles.push(p.relativePath);
                rollbackErrorOccurred = true;
              }
            } catch {
              if (fd !== undefined) {
                try {
                  fsOps.close(fd);
                } catch {
                  // ignore
                }
              }
              unrestoredFiles.push(p.relativePath);
              rollbackErrorOccurred = true;
            } finally {
              try {
                fsOps.unlink(rollTmp);
              } catch {
                // ignore
              }
            }
          } else {
            // File modified externally or changed identity: DO NOT overwrite
            unrestoredFiles.push(p.relativePath);
            rollbackErrorOccurred = true;
          }
        }

        if (rollbackErrorOccurred || unrestoredFiles.length > 0 || stagedCleanupFailed) {
          throw ArcError.rollbackFailed(
            'Patch application failed and one or more committed files could not be safely rolled back.',
            {
              recoveryRequired: true,
              recoveryFileCount: unrestoredFiles.length,
            },
          );
        }
      }

      if (failureError instanceof ArcError) {
        throw failureError;
      }
      sanitizeFsError(failureError);
    }

    return {
      success: true,
      modifiedFiles: preflightFiles.map((p) => p.relativePath),
      stats: {
        filesChanged: preflightFiles.length,
        insertions: totalInsertions,
        deletions: totalDeletions,
      },
      dryRun: false,
    };
  });
}
