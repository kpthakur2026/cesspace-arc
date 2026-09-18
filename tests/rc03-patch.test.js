import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import {
  FilesystemSubsystem,
  NodeFilesystemOps,
  ProcessWideLockManager,
  applyPatch,
  safeUnlinkTemp,
  MAX_PATCH_BYTES,
} from '../packages/filesystem/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

describe('CesSpace ARC — RC-03 Bounded apply_patch Engine', () => {
  let tempDir;
  let workspaceDir;
  let fsSubsystem;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc03-patch-test-'));
    workspaceDir = path.join(tempDir, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Mock .git directory for security boundary tests
    fs.mkdirSync(path.join(workspaceDir, '.git', 'refs', 'heads'), { recursive: true });
    fs.mkdirSync(path.join(workspaceDir, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    fs.writeFileSync(
      path.join(workspaceDir, '.git', 'config'),
      '[core]\n\trepositoryformatversion = 0\n',
    );

    fsSubsystem = new FilesystemSubsystem();
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // ==========================================================================
  // 1. Positive Tests
  // ==========================================================================

  test('RC03-PATCH-P-01: Single-file single-hunk patch applies cleanly with exact stats', async () => {
    const fileRel = 'hello.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\nline2\nline3\n', 'utf8');

    const patch = `--- a/hello.txt
+++ b/hello.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2-modified
 line3
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });

    assert.equal(res.success, true);
    assert.deepEqual(res.modifiedFiles, [fileRel]);
    assert.equal(res.stats.filesChanged, 1);
    assert.equal(res.stats.insertions, 1);
    assert.equal(res.stats.deletions, 1);
    assert.equal(res.dryRun, false);

    const afterContent = fs.readFileSync(filePath, 'utf8');
    assert.equal(afterContent, 'line1\nline2-modified\nline3\n');
  });

  test('RC03-PATCH-P-02: Single-file multiple hunks apply in correct order', async () => {
    const fileRel = 'multihunk.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n', 'utf8');

    const patch = `--- a/multihunk.txt
+++ b/multihunk.txt
@@ -1,3 +1,4 @@
 line1
-line2
+line2-edit
+line2-extra
 line3
@@ -6,3 +7,2 @@
 line6
-line7
 line8
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });

    assert.equal(res.success, true);
    assert.equal(res.stats.filesChanged, 1);
    assert.equal(res.stats.insertions, 2);
    assert.equal(res.stats.deletions, 2);

    const afterContent = fs.readFileSync(filePath, 'utf8');
    assert.equal(
      afterContent,
      'line1\nline2-edit\nline2-extra\nline3\nline4\nline5\nline6\nline8\n',
    );
  });

  test('RC03-PATCH-P-03: Multi-file patch applies across multiple targets with combined stats', async () => {
    const file1Rel = 'pkg/fileA.ts';
    const file2Rel = 'pkg/fileB.ts';
    fs.mkdirSync(path.join(workspaceDir, 'pkg'), { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, file1Rel), 'const a = 1;\n', 'utf8');
    fs.writeFileSync(path.join(workspaceDir, file2Rel), 'const b = 2;\n', 'utf8');

    const patch = `--- a/pkg/fileA.ts
+++ b/pkg/fileA.ts
@@ -1,1 +1,2 @@
-const a = 1;
+const a = 10;
+const a2 = 20;
--- a/pkg/fileB.ts
+++ b/pkg/fileB.ts
@@ -1,1 +1,1 @@
-const b = 2;
+const b = 20;
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });

    assert.equal(res.success, true);
    assert.equal(res.stats.filesChanged, 2);
    assert.equal(res.stats.insertions, 3);
    assert.equal(res.stats.deletions, 2);
    assert.ok(res.modifiedFiles.includes(file1Rel));
    assert.ok(res.modifiedFiles.includes(file2Rel));

    assert.equal(
      fs.readFileSync(path.join(workspaceDir, file1Rel), 'utf8'),
      'const a = 10;\nconst a2 = 20;\n',
    );
    assert.equal(fs.readFileSync(path.join(workspaceDir, file2Rel), 'utf8'), 'const b = 20;\n');
  });

  test('RC03-PATCH-P-04: dryRun mode reports accurate simulation stats with zero disk mutation', async () => {
    const fileRel = 'dryrun-target.txt';
    const filePath = path.join(workspaceDir, fileRel);
    const originalContent = 'alpha\nbeta\ngamma\n';
    fs.writeFileSync(filePath, originalContent, 'utf8');

    const statBefore = fs.statSync(filePath);
    const hashBefore = crypto.createHash('sha256').update(originalContent).digest('hex');

    const patch = `--- a/dryrun-target.txt
+++ b/dryrun-target.txt
@@ -1,3 +1,3 @@
 alpha
-beta
+beta-updated
 gamma
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch, dryRun: true });

    assert.equal(res.success, true);
    assert.equal(res.dryRun, true);
    assert.equal(res.stats.filesChanged, 1);
    assert.equal(res.stats.insertions, 1);
    assert.equal(res.stats.deletions, 1);

    // Verify ZERO disk mutation
    const contentAfter = fs.readFileSync(filePath, 'utf8');
    const statAfter = fs.statSync(filePath);
    const hashAfter = crypto.createHash('sha256').update(contentAfter).digest('hex');

    assert.equal(contentAfter, originalContent);
    assert.equal(hashAfter, hashBefore);
    assert.equal(statAfter.mtimeMs, statBefore.mtimeMs);
  });

  test('RC03-PATCH-P-05: Mode permissions are preserved on disk via fchmod', async () => {
    const fileRel = 'script.sh';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, '#!/bin/sh\necho "v1"\n', { mode: 0o755 });

    const patch = `--- a/script.sh
+++ b/script.sh
@@ -1,2 +1,2 @@
 #!/bin/sh
-echo "v1"
+echo "v2"
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });
    assert.equal(res.success, true);

    const st = fs.statSync(filePath);
    assert.equal(st.mode & 0o777, 0o755);
  });

  test('RC03-PATCH-P-06: LF line endings are preserved', async () => {
    const fileRel = 'lf.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'foo\nbar\nbaz\n', 'utf8');

    const patch = `--- a/lf.txt
+++ b/lf.txt
@@ -1,3 +1,3 @@
 foo
-bar
+bar2
 baz
`;

    await fsSubsystem.applyPatch(workspaceDir, { patch });
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'foo\nbar2\nbaz\n');
    assert.ok(!content.includes('\r'));
  });

  test('RC03-PATCH-P-07: CRLF line endings are preserved without LF conversion', async () => {
    const fileRel = 'crlf.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'foo\r\nbar\r\nbaz\r\n', 'utf8');

    const patch = `--- a/crlf.txt
+++ b/crlf.txt
@@ -1,3 +1,3 @@
 foo
-bar
+bar2
 baz
`;

    await fsSubsystem.applyPatch(workspaceDir, { patch });
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'foo\r\nbar2\r\nbaz\r\n');
  });

  test('RC03-PATCH-P-08: Final newline status is preserved when present', async () => {
    const fileRel = 'with-newline.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\nline2\n', 'utf8');

    const patch = `--- a/with-newline.txt
+++ b/with-newline.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2-edit
`;

    await fsSubsystem.applyPatch(workspaceDir, { patch });
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'line1\nline2-edit\n');
    assert.ok(content.endsWith('\n'));
  });

  test('RC03-PATCH-P-09: No-final-newline status is preserved', async () => {
    const fileRel = 'no-newline.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\nline2', 'utf8');

    const patch = `--- a/no-newline.txt
+++ b/no-newline.txt
@@ -1,2 +1,2 @@
 line1
-line2
\\ No newline at end of file
+line2-edit
\\ No newline at end of file
`;

    await fsSubsystem.applyPatch(workspaceDir, { patch });
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'line1\nline2-edit');
    assert.ok(!content.endsWith('\n'));
  });

  test('RC03-PATCH-P-10: Up to maximum 10 target files in single patch succeeds', async () => {
    const files = [];
    let patchText = '';

    for (let i = 1; i <= 10; i++) {
      const rel = `file_${i}.txt`;
      files.push(rel);
      fs.writeFileSync(path.join(workspaceDir, rel), `content ${i}\n`, 'utf8');

      patchText += `--- a/${rel}
+++ b/${rel}
@@ -1,1 +1,1 @@
-content ${i}
+updated ${i}
`;
    }

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch: patchText });
    assert.equal(res.success, true);
    assert.equal(res.stats.filesChanged, 10);

    for (let i = 1; i <= 10; i++) {
      const content = fs.readFileSync(path.join(workspaceDir, `file_${i}.txt`), 'utf8');
      assert.equal(content, `updated ${i}\n`);
    }
  });

  test('RC03-PATCH-P-11: Zero temporary sibling files (.arc-tmp-*) remain after success', async () => {
    const fileRel = 'clean-temp.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'original\n', 'utf8');

    const patch = `--- a/clean-temp.txt
+++ b/clean-temp.txt
@@ -1,1 +1,1 @@
-original
+modified
`;

    await fsSubsystem.applyPatch(workspaceDir, { patch });

    const dirFiles = fs.readdirSync(workspaceDir);
    const tmpFiles = dirFiles.filter((f) => f.startsWith('.arc-tmp-'));
    assert.equal(tmpFiles.length, 0);
  });

  test('RC03-PATCH-P-12: no-final-newline to final-newline transition adds newline', async () => {
    const fileRel = 'no-to-final.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'alpha', 'utf8'); // no newline

    const patch = `--- a/no-to-final.txt
+++ b/no-to-final.txt
@@ -1 +1 @@
-alpha
\\ No newline at end of file
+alpha-mod
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });
    assert.equal(res.success, true);
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'alpha-mod\n');
  });

  test('RC03-PATCH-P-13: final-newline to no-final-newline transition removes newline', async () => {
    const fileRel = 'final-to-no.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'alpha\n', 'utf8'); // has newline

    const patch = `--- a/final-to-no.txt
+++ b/final-to-no.txt
@@ -1 +1 @@
-alpha
+alpha-mod
\\ No newline at end of file
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });
    assert.equal(res.success, true);
    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'alpha-mod');
  });

  // ==========================================================================
  // 2. Negative Parser & Input Validation Tests
  // ==========================================================================

  test('RC03-PATCH-N-01: Non-object or null request payload rejected', async () => {
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, null),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, undefined),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-02: Missing or non-string patch rejected', async () => {
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, {}),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: 123 }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-03: Empty patch string or whitespace-only rejected', async () => {
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: '' }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: '   \n  \t  ' }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-04: Patch payload exceeding 512 KiB rejected with PAYLOAD_TOO_LARGE', async () => {
    const bigString = 'a'.repeat(MAX_PATCH_BYTES + 1);
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: bigString }),
      (err) => err instanceof ArcError && err.code === 'PAYLOAD_TOO_LARGE',
    );
  });

  test('RC03-PATCH-N-05: Patch exceeding 10 files (11 files) rejected with PAYLOAD_TOO_LARGE', async () => {
    let patchText = '';
    for (let i = 1; i <= 11; i++) {
      patchText += `--- a/file_${i}.txt
+++ b/file_${i}.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    }

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patchText }),
      (err) => err instanceof ArcError && err.code === 'PAYLOAD_TOO_LARGE',
    );
  });

  test('RC03-PATCH-N-06: Non-zero fuzz rejected with INVALID_REQUEST_SCHEMA', async () => {
    const patch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch, fuzz: 1 }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch, fuzz: 0.5 }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-07: Non-boolean dryRun rejected with INVALID_REQUEST_SCHEMA', async () => {
    const patch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch, dryRun: 'true' }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-08: Malformed patch header rejected with PATCH_PARSE_ERROR', async () => {
    const malformed1 = `+++ b/missing-minus.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: malformed1 }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );

    const malformed2 = `--- a/missing-plus.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: malformed2 }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-09: Malformed hunk header rejected with PATCH_PARSE_ERROR', async () => {
    const malformed = `--- a/foo.txt
+++ b/foo.txt
@@ not-a-valid-hunk @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: malformed }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-10: Hunk line count mismatch rejected with PATCH_PARSE_ERROR', async () => {
    const mismatch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2-mod
`;
    // Only 2 lines provided when oldCount declared 3
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: mismatch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-11: Duplicate file sections rejected with PATCH_PARSE_ERROR', async () => {
    const duplicate = `--- a/foo.txt
+++ b/foo.txt
@@ -1,1 +1,1 @@
-a
+b
--- a/foo.txt
+++ b/foo.txt
@@ -1,1 +1,1 @@
-b
+c
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: duplicate }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-12: Overlapping hunks rejected with PATCH_PARSE_ERROR', async () => {
    const overlapping = `--- a/foo.txt
+++ b/foo.txt
@@ -1,3 +1,3 @@
 a
-b
+b2
 c
@@ -2,3 +2,3 @@
 b
-c
+c2
 d
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: overlapping }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-13: Out-of-order hunks rejected with PATCH_PARSE_ERROR', async () => {
    const outOfOrder = `--- a/foo.txt
+++ b/foo.txt
@@ -5,2 +5,2 @@
 e
-f
+f2
@@ -1,2 +1,2 @@
 a
-b
+b2
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: outOfOrder }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-14: Context mismatch fails with PATCH_PREFLIGHT_FAILED and leaves disk unchanged', async () => {
    const fileRel = 'context-mismatch.txt';
    const filePath = path.join(workspaceDir, fileRel);
    const original = 'first\nsecond\nthird\n';
    fs.writeFileSync(filePath, original, 'utf8');

    const patch = `--- a/context-mismatch.txt
+++ b/context-mismatch.txt
@@ -1,3 +1,3 @@
 first
-WRONG_CONTEXT
+new_second
 third
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );

    assert.equal(fs.readFileSync(filePath, 'utf8'), original);
  });

  test('RC03-PATCH-N-15: Deletion mismatch fails with PATCH_PREFLIGHT_FAILED and leaves disk unchanged', async () => {
    const fileRel = 'deletion-mismatch.txt';
    const filePath = path.join(workspaceDir, fileRel);
    const original = 'alpha\nbeta\ngamma\n';
    fs.writeFileSync(filePath, original, 'utf8');

    const patch = `--- a/deletion-mismatch.txt
+++ b/deletion-mismatch.txt
@@ -1,3 +1,3 @@
 alpha
-WRONG_DELETION
+delta
 gamma
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );

    assert.equal(fs.readFileSync(filePath, 'utf8'), original);
  });

  test('RC03-PATCH-N-16: Missing target file fails with PATCH_PREFLIGHT_FAILED', async () => {
    const patch = `--- a/nonexistent.txt
+++ b/nonexistent.txt
@@ -1,1 +1,1 @@
-a
+b
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );
  });

  test('RC03-PATCH-N-17: Target file with binary content (NUL byte) fails with PATCH_PREFLIGHT_FAILED', async () => {
    const fileRel = 'binary.bin';
    const filePath = path.join(workspaceDir, fileRel);
    const binBuf = Buffer.from([0x61, 0x00, 0x62, 0x0a]); // 'a\0b\n'
    fs.writeFileSync(filePath, binBuf);

    const patch = `--- a/binary.bin
+++ b/binary.bin
@@ -1,1 +1,1 @@
-a
+c
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );
  });

  test('RC03-PATCH-N-18: Target file with invalid UTF-8 fails with PATCH_PREFLIGHT_FAILED', async () => {
    const fileRel = 'invalid-utf8.txt';
    const filePath = path.join(workspaceDir, fileRel);
    const badUtf8 = Buffer.from([0xff, 0xfe, 0x61, 0x0a]);
    fs.writeFileSync(filePath, badUtf8);

    const patch = `--- a/invalid-utf8.txt
+++ b/invalid-utf8.txt
@@ -1,1 +1,1 @@
-a
+b
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );
  });

  test('RC03-PATCH-N-19: Target file with mixed line endings fails with PATCH_PREFLIGHT_FAILED', async () => {
    const fileRel = 'mixed-newlines.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\r\nline2\nline3\r\n', 'utf8');

    const patch = `--- a/mixed-newlines.txt
+++ b/mixed-newlines.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2-mod
 line3
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );
  });

  test('RC03-PATCH-N-20: Target path is a directory fails with IS_A_DIRECTORY', async () => {
    const dirRel = 'somedir';
    fs.mkdirSync(path.join(workspaceDir, dirRel), { recursive: true });

    const patch = `--- a/somedir
+++ b/somedir
@@ -1,1 +1,1 @@
-a
+b
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'IS_A_DIRECTORY',
    );
  });

  test('RC03-PATCH-N-21: Target path is a symbolic link fails with UNSAFE_SYMLINK', async () => {
    const realFile = path.join(workspaceDir, 'real.txt');
    const linkFile = path.join(workspaceDir, 'link.txt');
    fs.writeFileSync(realFile, 'real content\n', 'utf8');
    fs.symlinkSync(realFile, linkFile);

    const patch = `--- a/link.txt
+++ b/link.txt
@@ -1,1 +1,1 @@
-real content
+modified
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'UNSAFE_SYMLINK',
    );
  });

  test('RC03-PATCH-N-22: Target file with hardlink count > 1 fails with HARDLINK_DETECTED', async () => {
    const origFile = path.join(workspaceDir, 'orig-hard.txt');
    const hardlinkFile = path.join(workspaceDir, 'link-hard.txt');
    fs.writeFileSync(origFile, 'hard content\n', 'utf8');
    fs.linkSync(origFile, hardlinkFile);

    const patch = `--- a/orig-hard.txt
+++ b/orig-hard.txt
@@ -1,1 +1,1 @@
-hard content
+modified
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'HARDLINK_DETECTED',
    );
  });

  test('RC03-PATCH-N-23: Path traversal in patch headers fails with PATH_ESCAPES_ROOT', async () => {
    const patch = `--- a/../../outside.txt
+++ b/../../outside.txt
@@ -1,1 +1,1 @@
-a
+b
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATH_ESCAPES_ROOT',
    );
  });

  test('RC03-PATCH-N-24: Absolute path outside workspace fails with PATH_ESCAPES_ROOT', async () => {
    const patch = `--- /etc/passwd
+++ /etc/passwd
@@ -1,1 +1,1 @@
-a
+b
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATH_ESCAPES_ROOT',
    );
  });

  test('RC03-PATCH-N-25: Git internal mutation targeting .git fails with ACCESS_DENIED', async () => {
    const patch = `--- a/.git/config
+++ b/.git/config
@@ -1,1 +1,1 @@
-[core]
+[core-bad]
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
    );
  });

  test('RC03-PATCH-N-26: Blacklisted sensitive files (.env*) fail with ACCESS_DENIED', async () => {
    const patch1 = `--- a/.env
+++ b/.env
@@ -1,1 +1,1 @@
-SECRET=1
+SECRET=2
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patch1 }),
      (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
    );

    const patch2 = `--- a/.envlocal
+++ b/.envlocal
@@ -1,1 +1,1 @@
-SECRET=1
+SECRET=2
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patch2 }),
      (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
    );

    const patch3 = `--- a/id_rsa
+++ b/id_rsa
@@ -1,1 +1,1 @@
-KEY=1
+KEY=2
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patch3 }),
      (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
    );
  });

  test('RC03-PATCH-N-27: Intermediate symlink directory fails with UNSAFE_SYMLINK and leaves real target untouched', async () => {
    const realDir = path.join(workspaceDir, 'real-dir');
    fs.mkdirSync(realDir, { recursive: true });
    const realTarget = path.join(realDir, 'target.txt');
    const origContent = 'original-unmodified-content\n';
    fs.writeFileSync(realTarget, origContent, 'utf8');

    const linkedDir = path.join(workspaceDir, 'linked-dir');
    fs.symlinkSync(realDir, linkedDir);

    const patch = `--- a/linked-dir/target.txt
+++ b/linked-dir/target.txt
@@ -1,1 +1,1 @@
-original-unmodified-content
+tampered-content
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'UNSAFE_SYMLINK',
    );

    // Real target was NOT modified
    assert.equal(fs.readFileSync(realTarget, 'utf8'), origContent);
  });

  test('RC03-PATCH-N-28: Special non-regular node target rejected with NOT_A_FILE', async () => {
    const fileRel = 'special-fifo.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'special content\n', 'utf8');

    class SpecialMockOps extends NodeFilesystemOps {
      lstat(targetPath) {
        const st = super.lstat(targetPath);
        if (targetPath === filePath) {
          return {
            ...st,
            isFile: () => false,
            isDirectory: () => false,
            isSymbolicLink: () => false,
            isFIFO: () => true,
            nlink: 1,
          };
        }
        return st;
      }
    }
    const mockOps = new SpecialMockOps();
    const lockManager = new ProcessWideLockManager();

    const patch = `--- a/special-fifo.txt
+++ b/special-fifo.txt
@@ -1,1 +1,1 @@
-special content
+modified
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => err instanceof ArcError && err.code === 'NOT_A_FILE',
    );

    assert.equal(fs.readFileSync(filePath, 'utf8'), 'special content\n');
  });

  test('RC03-PATCH-N-29: Negative fuzz (fuzz: -1) rejected with INVALID_REQUEST_SCHEMA', async () => {
    const patch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch, fuzz: -1 }),
      (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('RC03-PATCH-N-30: Fraudulent newStart coordinate rejected with PATCH_PARSE_ERROR', async () => {
    const fraudulentPatch = `--- a/foo.txt
+++ b/foo.txt
@@ -1,3 +999,3 @@
 line1
 line2
 line3
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: fraudulentPatch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  test('RC03-PATCH-N-31: Multi-hunk delta coordinate inconsistency rejected with PATCH_PARSE_ERROR', async () => {
    const inconsistentMultiHunk = `--- a/foo.txt
+++ b/foo.txt
@@ -1,2 +1,3 @@
 line1
-line2
+line2-a
+line2-b
@@ -5,2 +5,2 @@
 line5
 line6
`;
    // Hunk 1 delta was +1, so hunk 2 newStart must be 6, not 5
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: inconsistentMultiHunk }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PARSE_ERROR',
    );
  });

  // ==========================================================================
  // 3. Unsupported Operation Directive Tests
  // ==========================================================================

  test('RC03-PATCH-U-01: File creation directive (--- /dev/null) rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `--- /dev/null
+++ b/created.txt
@@ -0,0 +1,1 @@
+new file content
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-02: File deletion directive (+++ /dev/null) rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const fileRel = 'delete-me.txt';
    fs.writeFileSync(path.join(workspaceDir, fileRel), 'content\n', 'utf8');

    const patch = `--- a/delete-me.txt
+++ /dev/null
@@ -1,1 +0,0 @@
-content
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-03: Mode change directives rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patchOldMode = `diff --git a/file.txt b/file.txt
old mode 100644
new mode 100755
--- a/file.txt
+++ b/file.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patchOldMode }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-04: new file mode directive rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `diff --git a/file.txt b/file.txt
new file mode 100644
--- a/file.txt
+++ b/file.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-05: deleted file mode directive rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `diff --git a/file.txt b/file.txt
deleted file mode 100644
--- a/file.txt
+++ b/file.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-06: Rename directives (rename from / to) rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `diff --git a/old.txt b/new.txt
similarity index 100%
rename from old.txt
rename to new.txt
--- a/old.txt
+++ b/new.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-07: Copy directives (copy from / to) rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `diff --git a/old.txt b/copy.txt
copy from old.txt
copy to copy.txt
--- a/old.txt
+++ b/copy.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-08: Binary patch directives rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patchBinary1 = `diff --git a/bin.dat b/bin.dat
GIT binary patch
literal 10
zc$}q-U|?o-
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patchBinary1 }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );

    const patchBinary2 = `Binary files a/bin.dat and b/bin.dat differ\n`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch: patchBinary2 }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  test('RC03-PATCH-U-09: Old path != new path header mismatch rejected with PATCH_UNSUPPORTED_OPERATION', async () => {
    const patch = `--- a/fileA.txt
+++ b/fileB.txt
@@ -1,1 +1,1 @@
-a
+b
`;
    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_UNSUPPORTED_OPERATION',
    );
  });

  // ==========================================================================
  // 4. Preflight-All, Staging, Race, Rollback & Privacy Tests
  // ==========================================================================

  test('RC03-PATCH-A-01: Preflight-all atomicity: Target A valid, Target B context mismatch leaves both files unchanged', async () => {
    const fileA = path.join(workspaceDir, 'atom-a.txt');
    const fileB = path.join(workspaceDir, 'atom-b.txt');
    const contentA = 'alpha\n';
    const contentB = 'beta\n';
    fs.writeFileSync(fileA, contentA, 'utf8');
    fs.writeFileSync(fileB, contentB, 'utf8');

    const patch = `--- a/atom-a.txt
+++ b/atom-a.txt
@@ -1,1 +1,1 @@
-alpha
+alpha-modified
--- a/atom-b.txt
+++ b/atom-b.txt
@@ -1,1 +1,1 @@
-WRONG_B
+beta-modified
`;

    await assert.rejects(
      async () => fsSubsystem.applyPatch(workspaceDir, { patch }),
      (err) => err instanceof ArcError && err.code === 'PATCH_PREFLIGHT_FAILED',
    );

    // Verify NEITHER file was touched
    assert.equal(fs.readFileSync(fileA, 'utf8'), contentA);
    assert.equal(fs.readFileSync(fileB, 'utf8'), contentB);
  });

  test('RC03-PATCH-A-02: Staging failure cleanup: Temp files unlinked, zero files committed', async () => {
    const fileA = path.join(workspaceDir, 'stage-a.txt');
    const fileB = path.join(workspaceDir, 'stage-b.txt');
    fs.writeFileSync(fileA, 'lineA\n', 'utf8');
    fs.writeFileSync(fileB, 'lineB\n', 'utf8');

    let openCount = 0;
    class StageMockOps extends NodeFilesystemOps {
      open(filePath, flags, mode) {
        if (filePath.includes('.arc-tmp-')) {
          openCount++;
          if (openCount === 2) {
            throw new Error('ENOSPC: Injected disk full simulation during staging');
          }
        }
        return super.open(filePath, flags, mode);
      }
    }
    const mockOps = new StageMockOps();

    const lockManager = new ProcessWideLockManager();
    const patch = `--- a/stage-a.txt
+++ b/stage-a.txt
@@ -1,1 +1,1 @@
-lineA
+lineA-mod
--- a/stage-b.txt
+++ b/stage-b.txt
@@ -1,1 +1,1 @@
-lineB
+lineB-mod
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => err instanceof ArcError,
    );

    // Neither file modified
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'lineA\n');
    assert.equal(fs.readFileSync(fileB, 'utf8'), 'lineB\n');

    // All temp files cleaned up
    const dirFiles = fs.readdirSync(workspaceDir);
    assert.equal(dirFiles.filter((f) => f.startsWith('.arc-tmp-')).length, 0);
  });

  test('RC03-PATCH-A-03: Precommit race detection: External file modification halts commit and rolls back committed files', async () => {
    const fileA = path.join(workspaceDir, 'race-a.txt');
    const fileB = path.join(workspaceDir, 'race-b.txt');
    fs.writeFileSync(fileA, 'initialA\n', 'utf8');
    fs.writeFileSync(fileB, 'initialB\n', 'utf8');

    class RaceMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        super.rename(src, dst);
        if (dst === fileA) {
          // Simulate race: external process modifies fileB right after fileA commits!
          fs.writeFileSync(fileB, 'concurrent-external-edit\n', 'utf8');
        }
      }
    }
    const mockOps = new RaceMockOps();

    const lockManager = new ProcessWideLockManager();
    const patch = `--- a/race-a.txt
+++ b/race-a.txt
@@ -1,1 +1,1 @@
-initialA
+initialA-committed
--- a/race-b.txt
+++ b/race-b.txt
@@ -1,1 +1,1 @@
-initialB
+initialB-committed
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => err instanceof ArcError && err.code === 'CONFLICT_PRECONDITION_FAILED',
    );

    // fileA MUST be rolled back to initialA
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'initialA\n');
    // fileB has the external edit preserved
    assert.equal(fs.readFileSync(fileB, 'utf8'), 'concurrent-external-edit\n');
  });

  test('RC03-PATCH-A-04: Commit failure safe rollback: Injected rename failure on Target B restores Target A', async () => {
    const fileA = path.join(workspaceDir, 'fail-a.txt');
    const fileB = path.join(workspaceDir, 'fail-b.txt');
    fs.writeFileSync(fileA, 'fileA-orig\n', 'utf8');
    fs.writeFileSync(fileB, 'fileB-orig\n', 'utf8');

    class FailMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === fileB) {
          throw new Error('EIO: Injected I/O error during Target B rename');
        }
        return super.rename(src, dst);
      }
    }
    const mockOps = new FailMockOps();

    const lockManager = new ProcessWideLockManager();
    const patch = `--- a/fail-a.txt
+++ b/fail-a.txt
@@ -1,1 +1,1 @@
-fileA-orig
+fileA-committed
--- a/fail-b.txt
+++ b/fail-b.txt
@@ -1,1 +1,1 @@
-fileB-orig
+fileB-committed
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => err instanceof ArcError,
    );

    // fileA should be safely rolled back to fileA-orig
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'fileA-orig\n');
    // fileB was never committed
    assert.equal(fs.readFileSync(fileB, 'utf8'), 'fileB-orig\n');
  });

  test('RC03-PATCH-A-05: Rollback conflict safety: Refuses to overwrite externally modified file during rollback and raises ROLLBACK_FAILED', async () => {
    const fileA = path.join(workspaceDir, 'conflict-a.txt');
    const fileB = path.join(workspaceDir, 'conflict-b.txt');
    fs.writeFileSync(fileA, 'targetA-orig\n', 'utf8');
    fs.writeFileSync(fileB, 'targetB-orig\n', 'utf8');

    class ConflictMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === fileB) {
          // Right before Target B rename failure, external writer modifies Target A
          fs.writeFileSync(fileA, 'external-overwrite-after-A-commit\n', 'utf8');
          throw new Error('EIO: Target B commit failed');
        }
        return super.rename(src, dst);
      }
    }
    const mockOps = new ConflictMockOps();

    const lockManager = new ProcessWideLockManager();
    const patch = `--- a/conflict-a.txt
+++ b/conflict-a.txt
@@ -1,1 +1,1 @@
-targetA-orig
+targetA-committed
--- a/conflict-b.txt
+++ b/conflict-b.txt
@@ -1,1 +1,1 @@
-targetB-orig
+targetB-committed
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details.recoveryRequired, true);
        assert.equal(err.details.recoveryFileCount, 1);
        return true;
      },
    );

    // Target A was NOT overwritten by rollback: external edit preserved
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'external-overwrite-after-A-commit\n');
  });

  test('RC03-PATCH-A-06: Directive phrases inside hunk lines are accepted as normal code', async () => {
    const fileRel = 'code-with-directives.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'line1\nline2\n', 'utf8');

    // These lines contain text that looks like patch directives, but they are in hunk content!
    const patch = `--- a/code-with-directives.txt
+++ b/code-with-directives.txt
@@ -1,2 +1,4 @@
 line1
+rename from old.txt
+similarity index 100%
 line2
`;

    const res = await fsSubsystem.applyPatch(workspaceDir, { patch });
    assert.equal(res.success, true);
    assert.equal(res.stats.insertions, 2);

    const content = fs.readFileSync(filePath, 'utf8');
    assert.equal(content, 'line1\nrename from old.txt\nsimilarity index 100%\nline2\n');
  });

  test('RC03-PATCH-A-07: Privacy & Zero-leakage: Injected secrets do not leak into ArcError message or details', async () => {
    const fileRel = 'secret-test.txt';
    const filePath = path.join(workspaceDir, fileRel);
    fs.writeFileSync(filePath, 'header\nactual-data\nfooter\n', 'utf8');

    const superSecret = 'SUPER_SECRET_BEARER_TOKEN_99999999999999999999';
    const patch = `--- a/secret-test.txt
+++ b/secret-test.txt
@@ -1,3 +1,3 @@
 header
-${superSecret}
+replacement
 footer
`;

    try {
      await fsSubsystem.applyPatch(workspaceDir, { patch });
      assert.fail('Expected error');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      const jsonStr = JSON.stringify(err);
      assert.ok(
        !jsonStr.includes(superSecret),
        'Secret token must not appear anywhere in ArcError serialized payload',
      );
    }
  });

  test('RC03-PATCH-A-08: Rename succeeds then post-commit readFile fails: target is not forgotten and ROLLBACK_FAILED is returned if unrestorable', async () => {
    const fileA = path.join(workspaceDir, 'post-read-fail-a.txt');
    fs.writeFileSync(fileA, 'initial-content\n', 'utf8');

    let renameDone = false;
    class PostReadFailMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        super.rename(src, dst);
        if (dst === fileA) {
          renameDone = true;
        }
      }
      readFile(targetPath) {
        if (renameDone && targetPath === fileA) {
          throw new Error('EIO: Injected disk read error post-commit');
        }
        return super.readFile(targetPath);
      }
    }
    const mockOps = new PostReadFailMockOps();
    const lockManager = new ProcessWideLockManager();

    const patch = `--- a/post-read-fail-a.txt
+++ b/post-read-fail-a.txt
@@ -1,1 +1,1 @@
-initial-content
+patched-content
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details.recoveryRequired, true);
        assert.equal(err.details.recoveryFileCount, 1);
        return true;
      },
    );
  });

  test('RC03-PATCH-A-09: Rename succeeds then post-commit inode mismatch halts and triggers safe rollback', async () => {
    const fileA = path.join(workspaceDir, 'post-lstat-fail-a.txt');
    fs.writeFileSync(fileA, 'initial-a\n', 'utf8');

    let renameDone = false;
    let rollbackRenamed = false;
    class PostLstatFailMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        super.rename(src, dst);
        if (dst === fileA) {
          if (!renameDone) {
            renameDone = true;
          } else {
            rollbackRenamed = true;
          }
        }
      }
      lstat(targetPath) {
        const st = super.lstat(targetPath);
        if (renameDone && !rollbackRenamed && targetPath === fileA) {
          // Return simulated mismatched dev/ino
          return {
            ...st,
            dev: st.dev + 1,
            ino: st.ino + 9999,
          };
        }
        return st;
      }
    }
    const mockOps = new PostLstatFailMockOps();
    const lockManager = new ProcessWideLockManager();

    const patch = `--- a/post-lstat-fail-a.txt
+++ b/post-lstat-fail-a.txt
@@ -1,1 +1,1 @@
-initial-a
+patched-a
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details.recoveryRequired, true);
        return true;
      },
    );
  });

  test('RC03-PATCH-A-10: Rollback does not overwrite external replacement with identical content bytes and new inode', async () => {
    const fileA = path.join(workspaceDir, 'same-content-a.txt');
    const fileB = path.join(workspaceDir, 'same-content-b.txt');
    fs.writeFileSync(fileA, 'targetA-orig\n', 'utf8');
    fs.writeFileSync(fileB, 'targetB-orig\n', 'utf8');

    class SameContentReplaceMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === fileB) {
          // File A was committed with patched-a content.
          // External actor replaces File A with a brand new file (new inode) having the SAME patched bytes!
          fs.unlinkSync(fileA);
          fs.writeFileSync(fileA, 'targetA-patched\n', 'utf8');
          // Now fail File B commit
          throw new Error('EIO: Target B rename failure');
        }
        return super.rename(src, dst);
      }
    }
    const mockOps = new SameContentReplaceMockOps();
    const lockManager = new ProcessWideLockManager();

    const patch = `--- a/same-content-a.txt
+++ b/same-content-a.txt
@@ -1,1 +1,1 @@
-targetA-orig
+targetA-patched
--- a/same-content-b.txt
+++ b/same-content-b.txt
@@ -1,1 +1,1 @@
-targetB-orig
+targetB-patched
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details.recoveryRequired, true);
        assert.equal(err.details.recoveryFileCount, 1);
        return true;
      },
    );

    // External replacement file was NOT overwritten by rollback
    assert.equal(fs.readFileSync(fileA, 'utf8'), 'targetA-patched\n');
  });

  test('RC03-PATCH-A-11: Rollback restoration failure raises ROLLBACK_FAILED with truthful recovery metadata', async () => {
    const fileA = path.join(workspaceDir, 'restore-fail-a.txt');
    const fileB = path.join(workspaceDir, 'restore-fail-b.txt');
    fs.writeFileSync(fileA, 'fileA-orig\n', 'utf8');
    fs.writeFileSync(fileB, 'fileB-orig\n', 'utf8');

    let fileACommitted = false;
    class RestoreFailMockOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === fileA && !fileACommitted) {
          fileACommitted = true;
          return super.rename(src, dst);
        }
        if (dst === fileB) {
          throw new Error('EIO: Injected Target B commit failure');
        }
        if (dst === fileA && fileACommitted) {
          // Fail the rollback rename of Target A
          throw new Error('EIO: Injected rollback rename failure on Target A');
        }
        return super.rename(src, dst);
      }
    }
    const mockOps = new RestoreFailMockOps();
    const lockManager = new ProcessWideLockManager();

    const patch = `--- a/restore-fail-a.txt
+++ b/restore-fail-a.txt
@@ -1,1 +1,1 @@
-fileA-orig
+fileA-patched
--- a/restore-fail-b.txt
+++ b/restore-fail-b.txt
@@ -1,1 +1,1 @@
-fileB-orig
+fileB-patched
`;

    await assert.rejects(
      async () => applyPatch(workspaceDir, { patch }, mockOps, lockManager),
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details.recoveryRequired, true);
        assert.equal(err.details.recoveryFileCount, 1);
        const jsonStr = JSON.stringify(err);
        assert.ok(!jsonStr.includes(workspaceDir));
        assert.ok(!jsonStr.includes('.arc-tmp-'));
        assert.ok(!jsonStr.includes('fileA-orig'));
        return true;
      },
    );
  });

  test('RC03-PATCH-A-12: Exclusive in-process locks are acquired for ALL targets before preflight begins', async () => {
    const fileA = path.join(workspaceDir, 'lock-barrier-a.txt');
    const fileB = path.join(workspaceDir, 'lock-barrier-b.txt');
    fs.writeFileSync(fileA, 'content-a\n', 'utf8');
    fs.writeFileSync(fileB, 'content-b\n', 'utf8');

    const canonicalB = fs.realpathSync(fileB);
    const lockManager = new ProcessWideLockManager();

    let releaseBarrier;
    const barrier = new Promise((r) => {
      releaseBarrier = r;
    });
    let barrierReached;
    const reached = new Promise((r) => {
      barrierReached = r;
    });

    const origWithLocks = lockManager.withLocks.bind(lockManager);
    let patchLockCall = true;
    lockManager.withLocks = async (paths, fn) => {
      if (patchLockCall) {
        patchLockCall = false;
        return origWithLocks(paths, async () => {
          barrierReached();
          await barrier;
          return fn();
        });
      }
      return origWithLocks(paths, fn);
    };

    const patch = `--- a/lock-barrier-a.txt
+++ b/lock-barrier-a.txt
@@ -1,1 +1,1 @@
-content-a
+modified-a
--- a/lock-barrier-b.txt
+++ b/lock-barrier-b.txt
@@ -1,1 +1,1 @@
-content-b
+modified-b
`;

    const patchPromise = applyPatch(workspaceDir, { patch }, new NodeFilesystemOps(), lockManager);

    // Wait until applyPatch has acquired all locks
    await reached;

    let concurrentEntered = false;
    const concurrentLockPromise = lockManager.withLocks([canonicalB], async () => {
      concurrentEntered = true;
    });

    // Short yield: concurrentLockPromise should NOT be able to enter because canonicalB is locked
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(
      concurrentEntered,
      false,
      'Concurrent action must not enter while applyPatch holds lock',
    );

    // Release the barrier so applyPatch can proceed
    releaseBarrier();

    const patchRes = await patchPromise;
    assert.equal(patchRes.success, true);

    await concurrentLockPromise;
    assert.equal(
      concurrentEntered,
      true,
      'Concurrent action must enter once applyPatch releases lock',
    );
    assert.equal(lockManager.activeLockCount, 0, 'Active lock count must return to 0');
  });

  test('RC03-PATCH-A-13: Serialized ArcError never leaks injected paths, temp names, tokens, or content', async () => {
    const secretToken = 'SECRET_TOKEN_123_SUPER_CLASSIFIED';
    const secretPath = '/home/secretuser/workspace/file.ts';
    const secretTemp = '/home/secretuser/workspace/.arc-tmp-secret';
    const secretContext = 'sensitive hunk context string';

    // 1. Staging failure with raw injected error
    {
      const fileStaging = path.join(workspaceDir, 'leak-staging.txt');
      fs.writeFileSync(fileStaging, 'initial staging\n', 'utf8');

      const patchStaging = `--- a/leak-staging.txt
+++ b/leak-staging.txt
@@ -1,1 +1,1 @@
-initial staging
+modified staging
`;

      class LeakStagingMockOps extends NodeFilesystemOps {
        open(p, flags, mode) {
          if (p.includes('.arc-tmp-')) {
            const err = new Error(
              `EACCES: permission denied, open '${secretTemp}' with token ${secretToken}`,
            );
            err.code = 'EACCES';
            throw err;
          }
          return super.open(p, flags, mode);
        }
      }
      const stagingOps = new LeakStagingMockOps();
      const lockManager = new ProcessWideLockManager();

      try {
        await applyPatch(workspaceDir, { patch: patchStaging }, stagingOps, lockManager);
        assert.fail('Should have failed');
      } catch (err) {
        assert.ok(err instanceof ArcError);
        const json = JSON.stringify(err);
        assert.ok(!json.includes(secretToken));
        assert.ok(!json.includes(secretPath));
        assert.ok(!json.includes(secretTemp));
        assert.ok(!json.includes(secretContext));
      }
    }

    // 2. Post-rename verify failure with raw injected error
    {
      const fileVerify = path.join(workspaceDir, 'leak-verify.txt');
      fs.writeFileSync(fileVerify, 'initial verify\n', 'utf8');

      const patchVerify = `--- a/leak-verify.txt
+++ b/leak-verify.txt
@@ -1,1 +1,1 @@
-initial verify
+modified verify
`;

      let renamed = false;
      class LeakVerifyMockOps extends NodeFilesystemOps {
        rename(src, dst) {
          super.rename(src, dst);
          renamed = true;
        }
        readFile(p) {
          if (renamed && p === fileVerify) {
            const err = new Error(`EIO: I/O error reading '${secretPath}' token ${secretToken}`);
            err.code = 'EIO';
            throw err;
          }
          return super.readFile(p);
        }
      }
      const verifyOps = new LeakVerifyMockOps();
      const lockManager = new ProcessWideLockManager();

      try {
        await applyPatch(workspaceDir, { patch: patchVerify }, verifyOps, lockManager);
        assert.fail('Should have failed');
      } catch (err) {
        assert.ok(err instanceof ArcError);
        const json = JSON.stringify(err);
        assert.ok(!json.includes(secretToken));
        assert.ok(!json.includes(secretPath));
        assert.ok(!json.includes(secretTemp));
        assert.ok(!json.includes(secretContext));
      }
    }

    // 3. Rollback failure with raw injected error (exercises actual rollback restoration failure)
    {
      const fileRollA = path.join(workspaceDir, 'leak-roll-a.txt');
      const fileRollB = path.join(workspaceDir, 'leak-roll-b.txt');
      fs.writeFileSync(fileRollA, 'initial roll a\n', 'utf8');
      fs.writeFileSync(fileRollB, 'initial roll b\n', 'utf8');

      const patchRollback = `--- a/leak-roll-a.txt
+++ b/leak-roll-a.txt
@@ -1,1 +1,1 @@
-initial roll a
+modified roll a
--- a/leak-roll-b.txt
+++ b/leak-roll-b.txt
@@ -1,1 +1,1 @@
-initial roll b
+modified roll b
`;

      let targetACommitted = false;
      let rollbackStarted = false;

      class LeakRollbackMockOps extends NodeFilesystemOps {
        rename(src, dst) {
          if (dst === fileRollA && !rollbackStarted) {
            targetACommitted = true;
            return super.rename(src, dst);
          }
          if (dst === fileRollB && !rollbackStarted) {
            const err = new Error('EIO: second target commit rename failure');
            err.code = 'EIO';
            throw err;
          }
          if (rollbackStarted && dst === fileRollA) {
            const err = new Error(
              `EIO: rollback rename failed for '${secretPath}' temp '${secretTemp}' token ${secretToken}`,
            );
            err.code = 'EIO';
            throw err;
          }
          return super.rename(src, dst);
        }

        open(p, flags, mode) {
          if (targetACommitted && p.includes('.arc-tmp-')) {
            rollbackStarted = true;
          }
          return super.open(p, flags, mode);
        }
      }

      const rollbackOps = new LeakRollbackMockOps();
      const lockManager = new ProcessWideLockManager();

      try {
        await applyPatch(workspaceDir, { patch: patchRollback }, rollbackOps, lockManager);
        assert.fail('Should have failed');
      } catch (err) {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.equal(err.details?.recoveryRequired, true);
        const json = JSON.stringify(err);
        assert.ok(!json.includes(secretToken), 'Must not leak secret token');
        assert.ok(!json.includes(secretPath), 'Must not leak secret path');
        assert.ok(!json.includes(secretTemp), 'Must not leak secret temp');
        assert.ok(!json.includes(secretContext), 'Must not leak secret context');
      }
    }
  });

  test('5.A: Temp open fails before temp creation -> cleanup gets ENOENT -> treated clean -> original sanitized error returned', async () => {
    const file5a = path.join(workspaceDir, 'test-5a.txt');
    fs.writeFileSync(file5a, 'original 5a\n', 'utf8');

    const patch5a = `--- a/test-5a.txt
+++ b/test-5a.txt
@@ -1,1 +1,1 @@
-original 5a
+modified 5a
`;

    class OpenFailOps extends NodeFilesystemOps {
      open(p, flags, mode) {
        if (p.includes('.arc-tmp-')) {
          const err = new Error('EACCES: permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return super.open(p, flags, mode);
      }
    }

    const ops = new OpenFailOps();
    const lockManager = new ProcessWideLockManager();

    try {
      await applyPatch(workspaceDir, { patch: patch5a }, ops, lockManager);
      assert.fail('Should have failed');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      assert.notEqual(
        err.code,
        'ROLLBACK_FAILED',
        'Must not return ROLLBACK_FAILED when temp was never created',
      );
      assert.equal(err.code, 'ACCESS_DENIED');
      assert.equal(fs.readFileSync(file5a, 'utf8'), 'original 5a\n');
    }
  });

  test('5.B: Precommit conflict before first commit + injected staged temp unlink failure -> ROLLBACK_FAILED with recoveryRequired true', async () => {
    const file5b = path.join(workspaceDir, 'test-5b.txt');
    fs.writeFileSync(file5b, 'original 5b\n', 'utf8');

    const patch5b = `--- a/test-5b.txt
+++ b/test-5b.txt
@@ -1,1 +1,1 @@
-original 5b
+modified 5b
`;

    let stagingComplete = false;

    class PrecommitConflictUnlinkFailOps extends NodeFilesystemOps {
      open(p, flags, mode) {
        const fd = super.open(p, flags, mode);
        if (p.includes('.arc-tmp-')) {
          stagingComplete = true;
        }
        return fd;
      }
      readFile(p) {
        if (stagingComplete && p === file5b) {
          return Buffer.from('external modification\n', 'utf8');
        }
        return super.readFile(p);
      }
      unlink(p) {
        if (p.includes('.arc-tmp-')) {
          const err = new Error('EPERM: operation not permitted');
          err.code = 'EPERM';
          throw err;
        }
        return super.unlink(p);
      }
    }

    const ops = new PrecommitConflictUnlinkFailOps();
    const lockManager = new ProcessWideLockManager();

    try {
      await applyPatch(workspaceDir, { patch: patch5b }, ops, lockManager);
      assert.fail('Should have failed');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      assert.equal(err.code, 'ROLLBACK_FAILED');
      assert.equal(err.details?.recoveryRequired, true);
      assert.equal(fs.readFileSync(file5b, 'utf8'), 'original 5b\n');
    }
  });

  test('5.C: First target rename failure + staged temp unlink failure -> ROLLBACK_FAILED with 0 target contents committed', async () => {
    const file5c = path.join(workspaceDir, 'test-5c.txt');
    fs.writeFileSync(file5c, 'original 5c\n', 'utf8');

    const patch5c = `--- a/test-5c.txt
+++ b/test-5c.txt
@@ -1,1 +1,1 @@
-original 5c
+modified 5c
`;

    class RenameFailUnlinkFailOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === file5c) {
          const err = new Error('EIO: rename failed');
          err.code = 'EIO';
          throw err;
        }
        return super.rename(src, dst);
      }
      unlink(p) {
        if (p.includes('.arc-tmp-')) {
          const err = new Error('EPERM: staged cleanup failed');
          err.code = 'EPERM';
          throw err;
        }
        return super.unlink(p);
      }
    }

    const ops = new RenameFailUnlinkFailOps();
    const lockManager = new ProcessWideLockManager();

    try {
      await applyPatch(workspaceDir, { patch: patch5c }, ops, lockManager);
      assert.fail('Should have failed');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      assert.equal(err.code, 'ROLLBACK_FAILED');
      assert.equal(err.details?.recoveryRequired, true);
      assert.equal(fs.readFileSync(file5c, 'utf8'), 'original 5c\n');
    }
  });

  test('5.D: Cleanup ENOENT caused by temp already absent -> not considered recovery failure', async () => {
    const file5d = path.join(workspaceDir, 'test-5d.txt');
    fs.writeFileSync(file5d, 'original 5d\n', 'utf8');

    const patch5d = `--- a/test-5d.txt
+++ b/test-5d.txt
@@ -1,1 +1,1 @@
-original 5d
+modified 5d
`;

    class StagedEnoentOps extends NodeFilesystemOps {
      rename(src, dst) {
        if (dst === file5d) {
          const err = new Error('EACCES: rename permission denied');
          err.code = 'EACCES';
          throw err;
        }
        return super.rename(src, dst);
      }
      unlink(p) {
        if (p.includes('.arc-tmp-')) {
          const err = new Error('ENOENT: no such file or directory');
          err.code = 'ENOENT';
          throw err;
        }
        return super.unlink(p);
      }
    }

    const ops = new StagedEnoentOps();
    const lockManager = new ProcessWideLockManager();

    try {
      await applyPatch(workspaceDir, { patch: patch5d }, ops, lockManager);
      assert.fail('Should have failed');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      assert.notEqual(
        err.code,
        'ROLLBACK_FAILED',
        'ENOENT on temp cleanup must not trigger ROLLBACK_FAILED',
      );
      assert.equal(err.code, 'ACCESS_DENIED');
      assert.equal(fs.readFileSync(file5d, 'utf8'), 'original 5d\n');
    }
  });

  test('safeUnlinkTemp helper unit behavior', () => {
    const successOps = {
      unlink(_p) {
        return;
      },
    };
    assert.equal(safeUnlinkTemp(successOps, '/some/tmp'), true);

    const enoentOps = {
      unlink(_p) {
        const err = new Error('ENOENT: file not found');
        err.code = 'ENOENT';
        throw err;
      },
    };
    assert.equal(safeUnlinkTemp(enoentOps, '/some/tmp'), true);

    const epermOps = {
      unlink(_p) {
        const err = new Error('EPERM: permission denied');
        err.code = 'EPERM';
        throw err;
      },
    };
    assert.equal(safeUnlinkTemp(epermOps, '/some/tmp'), false);

    const otherOps = {
      unlink(_p) {
        throw new Error('disk failure');
      },
    };
    assert.equal(safeUnlinkTemp(otherOps, '/some/tmp'), false);
  });
});
