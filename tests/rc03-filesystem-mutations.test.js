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
} from '../packages/filesystem/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

describe('CesSpace ARC — RC-03 Safe File Mutation Primitives', () => {
  let tempDir;
  let workspaceDir;
  let fsSubsystem;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc03-test-'));
    workspaceDir = path.join(tempDir, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Initialize mock .git directory to test Git metadata denial
    fs.mkdirSync(path.join(workspaceDir, '.git', 'refs', 'heads'), { recursive: true });
    fs.mkdirSync(path.join(workspaceDir, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(workspaceDir, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    fs.writeFileSync(
      path.join(workspaceDir, '.git', 'config'),
      '[core]\n\trepositoryformatversion = 0\n',
    );
    fs.writeFileSync(
      path.join(workspaceDir, '.git', 'refs', 'heads', 'main'),
      '0123456789abcdef0123456789abcdef01234567\n',
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
  // 1. create_file Controls
  // ==========================================================================

  test('RC03-P-01: create_file creates new file with exact content, SHA-256, and cleans temp file', async () => {
    const content = 'Hello, RC-03 create_file!';
    const expectedHash = crypto.createHash('sha256').update(content).digest('hex');

    const result = await fsSubsystem.createFile(workspaceDir, {
      path: 'new-file.txt',
      content,
    });

    assert.equal(result.path, 'new-file.txt');
    assert.equal(result.created, true);
    assert.equal(result.bytesWritten, Buffer.byteLength(content, 'utf8'));
    assert.equal(result.contentHash, expectedHash);

    const onDisk = fs.readFileSync(path.join(workspaceDir, 'new-file.txt'), 'utf8');
    assert.equal(onDisk, content);

    // Verify no temporary files left in directory
    const files = fs.readdirSync(workspaceDir);
    const tempFiles = files.filter((f) => f.startsWith('.arc-tmp-'));
    assert.equal(tempFiles.length, 0);
  });

  test('RC03-N-01: create_file on existing file fails with ALREADY_EXISTS', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: 'new-file.txt',
          content: 'overwrite attempt',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ALREADY_EXISTS');
        return true;
      },
    );
  });

  test('RC03-N-02: create_file when immediate parent does not exist fails with PARENT_NOT_FOUND', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: 'non/existent/dir/file.txt',
          content: 'should fail',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PARENT_NOT_FOUND');
        return true;
      },
    );
  });

  test('RC03-N-03: create_file with path traversal escaping workspace fails with PATH_ESCAPES_ROOT', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: '../outside-workspace.txt',
          content: 'escape',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PATH_ESCAPES_ROOT');
        return true;
      },
    );
  });

  test('RC03-N-04: create_file with absolute path fails with PATH_ESCAPES_ROOT', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: '/tmp/absolute-path.txt',
          content: 'absolute',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PATH_ESCAPES_ROOT');
        return true;
      },
    );
  });

  test('RC03-N-05: create_file under .git/** fails with ACCESS_DENIED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: '.git/refs/heads/feature',
          content: 'bad',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  test('RC03-N-06: create_file targeting sensitive .env pattern fails with ACCESS_DENIED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: '.env',
          content: 'SECRET=123',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  test('RC03-N-07: create_file under symlinked parent directory fails with UNSAFE_SYMLINK', async () => {
    const realDir = path.join(workspaceDir, 'real-dir');
    fs.mkdirSync(realDir, { recursive: true });
    const symlinkDir = path.join(workspaceDir, 'symlink-dir');
    fs.symlinkSync(realDir, symlinkDir);

    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: 'symlink-dir/subfile.txt',
          content: 'symlink test',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'UNSAFE_SYMLINK');
        return true;
      },
    );
  });

  test('RC03-N-08: create_file where target is existing symlink fails with UNSAFE_SYMLINK', async () => {
    const targetReal = path.join(workspaceDir, 'real-target.txt');
    fs.writeFileSync(targetReal, 'real');
    const targetSymlink = path.join(workspaceDir, 'symlink-target.txt');
    fs.symlinkSync(targetReal, targetSymlink);

    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: 'symlink-target.txt',
          content: 'symlink target replace attempt',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'UNSAFE_SYMLINK');
        return true;
      },
    );
  });

  test('RC03-N-09: create_file with oversized payload (> 1 MiB) fails with PAYLOAD_TOO_LARGE', async () => {
    const oversized = 'a'.repeat(1024 * 1024 + 1);
    await assert.rejects(
      async () => {
        await fsSubsystem.createFile(workspaceDir, {
          path: 'oversized.txt',
          content: oversized,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PAYLOAD_TOO_LARGE');
        return true;
      },
    );
  });

  test('RC03-N-10: concurrent create_file calls on same target result in one success and one ALREADY_EXISTS', async () => {
    const p1 = fsSubsystem.createFile(workspaceDir, {
      path: 'concurrent-create.txt',
      content: 'first write',
    });
    const p2 = fsSubsystem.createFile(workspaceDir, {
      path: 'concurrent-create.txt',
      content: 'second write',
    });

    const results = await Promise.allSettled([p1, p2]);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason.code, 'ALREADY_EXISTS');
  });

  test('RC03-N-11: create_file final commit link EEXIST race fails with ALREADY_EXISTS and cleans temp file', async () => {
    class RaceFsOps extends NodeFilesystemOps {
      link(_tmp, _target) {
        const err = new Error('Destination appeared concurrently');
        err.code = 'EEXIST';
        throw err;
      }
    }

    const raceSubsystem = new FilesystemSubsystem(undefined, new RaceFsOps());
    await assert.rejects(
      async () => {
        await raceSubsystem.createFile(workspaceDir, {
          path: 'race-link-file.txt',
          content: 'test race',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ALREADY_EXISTS');
        return true;
      },
    );

    // Verify temp file was cleaned up
    const files = fs.readdirSync(workspaceDir);
    assert.equal(files.filter((f) => f.startsWith('.arc-tmp-')).length, 0);
  });

  // ==========================================================================
  // 2. write_file Controls
  // ==========================================================================

  test('RC03-P-02: write_file replaces existing file, preserves original mode, returns old/new hashes, and cleans temp', async () => {
    const filePath = path.join(workspaceDir, 'writable.txt');
    const initialContent = 'Version 1 content';
    fs.writeFileSync(filePath, initialContent, { mode: 0o600 });
    const initialHash = crypto.createHash('sha256').update(initialContent).digest('hex');

    const newContent = 'Version 2 updated content';
    const newHash = crypto.createHash('sha256').update(newContent).digest('hex');

    const result = await fsSubsystem.writeFile(workspaceDir, {
      path: 'writable.txt',
      content: newContent,
      expectedHash: initialHash,
      overwrite: true,
    });

    assert.equal(result.path, 'writable.txt');
    assert.equal(result.previousHash, initialHash);
    assert.equal(result.contentHash, newHash);
    assert.equal(result.bytesWritten, Buffer.byteLength(newContent, 'utf8'));

    const onDisk = fs.readFileSync(filePath, 'utf8');
    assert.equal(onDisk, newContent);

    // Check mode preservation
    const st = fs.statSync(filePath);
    assert.equal(st.mode & 0o777, 0o600);

    // Temp file clean check
    const files = fs.readdirSync(workspaceDir);
    assert.equal(files.filter((f) => f.startsWith('.arc-tmp-')).length, 0);
  });

  test('RC03-N-13: write_file with missing or invalid expectedHash fails with INVALID_REQUEST_SCHEMA', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'writable.txt',
          content: 'new',
          expectedHash: 'invalid-hash-not-64-hex',
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
        return true;
      },
    );
  });

  test('RC03-N-14: write_file with overwrite: false or omitted fails with INVALID_REQUEST_SCHEMA', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'writable.txt',
          content: 'new',
          expectedHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          overwrite: false,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
        return true;
      },
    );
  });

  test('RC03-N-15: write_file with mismatched expectedHash fails with CONFLICT_PRECONDITION_FAILED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'writable.txt',
          content: 'new content',
          expectedHash: '0000000000000000000000000000000000000000000000000000000000000000',
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CONFLICT_PRECONDITION_FAILED');
        return true;
      },
    );
  });

  test('RC03-N-16: write_file on non-existent file fails with FILE_NOT_FOUND', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'does-not-exist.txt',
          content: 'new',
          expectedHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'FILE_NOT_FOUND');
        return true;
      },
    );
  });

  test('RC03-N-17: write_file on directory fails with IS_A_DIRECTORY', async () => {
    const subDir = path.join(workspaceDir, 'subdir');
    fs.mkdirSync(subDir, { recursive: true });

    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'subdir',
          content: 'content',
          expectedHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'IS_A_DIRECTORY');
        return true;
      },
    );
  });

  test('RC03-N-18: write_file on symlink target fails with UNSAFE_SYMLINK', async () => {
    const realFile = path.join(workspaceDir, 'symlink-source-for-write.txt');
    fs.writeFileSync(realFile, 'data');
    const symlinkPath = path.join(workspaceDir, 'symlink-for-write.txt');
    fs.symlinkSync(realFile, symlinkPath);

    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'symlink-for-write.txt',
          content: 'overwrite attempt',
          expectedHash: crypto.createHash('sha256').update('data').digest('hex'),
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'UNSAFE_SYMLINK');
        return true;
      },
    );
  });

  test('RC03-N-19: write_file on file with multiple hardlinks fails with HARDLINK_DETECTED', async () => {
    const origFile = path.join(workspaceDir, 'hardlinked-orig.txt');
    fs.writeFileSync(origFile, 'hardlinked content');
    const linkFile = path.join(workspaceDir, 'hardlinked-link.txt');
    fs.linkSync(origFile, linkFile);

    const contentHash = crypto.createHash('sha256').update('hardlinked content').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'hardlinked-orig.txt',
          content: 'mutation attempt',
          expectedHash: contentHash,
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'HARDLINK_DETECTED');
        return true;
      },
    );
  });

  test('RC03-N-20: write_file targeting .git/** files fails with ACCESS_DENIED', async () => {
    const headContent = fs.readFileSync(path.join(workspaceDir, '.git', 'HEAD'), 'utf8');
    const headHash = crypto.createHash('sha256').update(headContent).digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: '.git/HEAD',
          content: 'ref: refs/heads/pwned\n',
          expectedHash: headHash,
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  test('RC03-N-21: write_file with oversized payload (> 1 MiB) fails with PAYLOAD_TOO_LARGE', async () => {
    const validFile = path.join(workspaceDir, 'small.txt');
    fs.writeFileSync(validFile, 'small');
    const smallHash = crypto.createHash('sha256').update('small').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.writeFile(workspaceDir, {
          path: 'small.txt',
          content: 'b'.repeat(1024 * 1024 + 1),
          expectedHash: smallHash,
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PAYLOAD_TOO_LARGE');
        return true;
      },
    );
  });

  test('RC03-N-22: write_file revalidation fails when file content changes before commit', async () => {
    const file = path.join(workspaceDir, 'race-write.txt');
    fs.writeFileSync(file, 'initial');
    const initialHash = crypto.createHash('sha256').update('initial').digest('hex');

    class ConcurrentModOps extends NodeFilesystemOps {
      open(pathStr, flags, mode) {
        // Concurrently modify the file while staging temp file
        fs.writeFileSync(file, 'concurrent-external-edit');
        return super.open(pathStr, flags, mode);
      }
    }

    const testSubsystem = new FilesystemSubsystem(undefined, new ConcurrentModOps());

    await assert.rejects(
      async () => {
        await testSubsystem.writeFile(workspaceDir, {
          path: 'race-write.txt',
          content: 'arc replacement',
          expectedHash: initialHash,
          overwrite: true,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CONFLICT_PRECONDITION_FAILED');
        return true;
      },
    );

    // Verify temp file cleaned up
    const files = fs.readdirSync(workspaceDir);
    assert.equal(files.filter((f) => f.startsWith('.arc-tmp-')).length, 0);
  });

  // ==========================================================================
  // 3. delete_file Controls
  // ==========================================================================

  test('RC03-P-03: delete_file unlinks file and returns deleted content hash', async () => {
    const filePath = path.join(workspaceDir, 'to-delete.txt');
    const content = 'Delete me please';
    fs.writeFileSync(filePath, content);
    const hash = crypto.createHash('sha256').update(content).digest('hex');

    const result = await fsSubsystem.deleteFile(workspaceDir, {
      path: 'to-delete.txt',
      expectedHash: hash,
    });

    assert.equal(result.path, 'to-delete.txt');
    assert.equal(result.deleted, true);
    assert.equal(result.contentHash, hash);
    assert.equal(fs.existsSync(filePath), false);
  });

  test('RC03-N-24: delete_file without expectedHash fails with INVALID_REQUEST_SCHEMA', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: 'some-file.txt',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
        return true;
      },
    );
  });

  test('RC03-N-25: delete_file with mismatched expectedHash fails with CONFLICT_PRECONDITION_FAILED', async () => {
    const file = path.join(workspaceDir, 'delete-mismatch.txt');
    fs.writeFileSync(file, 'live data');

    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: 'delete-mismatch.txt',
          expectedHash: '0000000000000000000000000000000000000000000000000000000000000000',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CONFLICT_PRECONDITION_FAILED');
        return true;
      },
    );

    assert.equal(fs.existsSync(file), true);
  });

  test('RC03-N-26: delete_file on directory fails with IS_A_DIRECTORY', async () => {
    const dir = path.join(workspaceDir, 'cannot-delete-dir');
    fs.mkdirSync(dir, { recursive: true });

    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: 'cannot-delete-dir',
          expectedHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'IS_A_DIRECTORY');
        return true;
      },
    );
  });

  test('RC03-N-27: delete_file on symlink fails with UNSAFE_SYMLINK', async () => {
    const real = path.join(workspaceDir, 'real-for-del-symlink.txt');
    fs.writeFileSync(real, 'content');
    const symlinkPath = path.join(workspaceDir, 'symlink-for-delete.txt');
    fs.symlinkSync(real, symlinkPath);

    const hash = crypto.createHash('sha256').update('content').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: 'symlink-for-delete.txt',
          expectedHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'UNSAFE_SYMLINK');
        return true;
      },
    );
  });

  test('RC03-N-28: delete_file on hardlink target fails with HARDLINK_DETECTED', async () => {
    const f1 = path.join(workspaceDir, 'hardlink-del-1.txt');
    const f2 = path.join(workspaceDir, 'hardlink-del-2.txt');
    fs.writeFileSync(f1, 'link content');
    fs.linkSync(f1, f2);

    const hash = crypto.createHash('sha256').update('link content').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: 'hardlink-del-1.txt',
          expectedHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'HARDLINK_DETECTED');
        return true;
      },
    );
  });

  test('RC03-N-29: delete_file under .git/** fails with ACCESS_DENIED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.deleteFile(workspaceDir, {
          path: '.git/refs/heads/main',
          expectedHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  // ==========================================================================
  // 4. move_file Controls
  // ==========================================================================

  test('RC03-P-04: move_file executes no-replace move with rollback, moves to destination, unlinks source', async () => {
    const srcPath = path.join(workspaceDir, 'move-source.txt');
    const content = 'Content to be moved';
    fs.writeFileSync(srcPath, content);
    const hash = crypto.createHash('sha256').update(content).digest('hex');

    const result = await fsSubsystem.moveFile(workspaceDir, {
      sourcePath: 'move-source.txt',
      destinationPath: 'move-dest.txt',
      expectedSourceHash: hash,
    });

    assert.equal(result.sourcePath, 'move-source.txt');
    assert.equal(result.destinationPath, 'move-dest.txt');
    assert.equal(result.moved, true);

    assert.equal(fs.existsSync(srcPath), false);
    assert.equal(fs.readFileSync(path.join(workspaceDir, 'move-dest.txt'), 'utf8'), content);
  });

  test('RC03-N-32: move_file without expectedSourceHash fails with INVALID_REQUEST_SCHEMA', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'move-dest.txt',
          destinationPath: 'move-again.txt',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
        return true;
      },
    );
  });

  test('RC03-N-33: move_file with mismatched expectedSourceHash fails with CONFLICT_PRECONDITION_FAILED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'move-dest.txt',
          destinationPath: 'move-again.txt',
          expectedSourceHash: '0000000000000000000000000000000000000000000000000000000000000000',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CONFLICT_PRECONDITION_FAILED');
        return true;
      },
    );
  });

  test('RC03-N-34: move_file onto existing destination fails with ALREADY_EXISTS', async () => {
    const existing = path.join(workspaceDir, 'existing-dest.txt');
    fs.writeFileSync(existing, 'existing');

    const src = path.join(workspaceDir, 'src-for-existing.txt');
    fs.writeFileSync(src, 'src data');
    const srcHash = crypto.createHash('sha256').update('src data').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'src-for-existing.txt',
          destinationPath: 'existing-dest.txt',
          expectedSourceHash: srcHash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ALREADY_EXISTS');
        return true;
      },
    );
  });

  test('RC03-N-35: move_file with missing source file fails with FILE_NOT_FOUND', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'non-existent-source.txt',
          destinationPath: 'some-dest.txt',
          expectedSourceHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'FILE_NOT_FOUND');
        return true;
      },
    );
  });

  test('RC03-N-36: move_file with .git source fails with ACCESS_DENIED', async () => {
    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: '.git/HEAD',
          destinationPath: 'stolen-head.txt',
          expectedSourceHash: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  test('RC03-N-37: move_file with .git destination fails with ACCESS_DENIED', async () => {
    const f = path.join(workspaceDir, 'file-to-hide.txt');
    fs.writeFileSync(f, 'payload');
    const hash = crypto.createHash('sha256').update('payload').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'file-to-hide.txt',
          destinationPath: '.git/objects/injected',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );
  });

  test('RC03-N-38: move_file with symlink source fails with UNSAFE_SYMLINK', async () => {
    const real = path.join(workspaceDir, 'real-src.txt');
    fs.writeFileSync(real, 'real content');
    const symlinkSrc = path.join(workspaceDir, 'symlink-src.txt');
    fs.symlinkSync(real, symlinkSrc);

    const hash = crypto.createHash('sha256').update('real content').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'symlink-src.txt',
          destinationPath: 'dest-from-symlink.txt',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'UNSAFE_SYMLINK');
        return true;
      },
    );
  });

  test('RC03-N-39: move_file with missing destination parent directory fails with PARENT_NOT_FOUND', async () => {
    const f = path.join(workspaceDir, 'valid-src.txt');
    fs.writeFileSync(f, 'data');
    const hash = crypto.createHash('sha256').update('data').digest('hex');

    await assert.rejects(
      async () => {
        await fsSubsystem.moveFile(workspaceDir, {
          sourcePath: 'valid-src.txt',
          destinationPath: 'missing-parent/moved.txt',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'PARENT_NOT_FOUND');
        return true;
      },
    );
  });

  test('RC03-N-40: move_file across devices (EXDEV) fails with CROSS_DEVICE_MOVE_UNSUPPORTED', async () => {
    const f = path.join(workspaceDir, 'exdev-src.txt');
    fs.writeFileSync(f, 'cross device');
    const hash = crypto.createHash('sha256').update('cross device').digest('hex');

    class ExdevOps extends NodeFilesystemOps {
      link() {
        const err = new Error('Cross-device link');
        err.code = 'EXDEV';
        throw err;
      }
    }

    const exdevSubsystem = new FilesystemSubsystem(undefined, new ExdevOps());
    await assert.rejects(
      async () => {
        await exdevSubsystem.moveFile(workspaceDir, {
          sourcePath: 'exdev-src.txt',
          destinationPath: 'exdev-dest.txt',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CROSS_DEVICE_MOVE_UNSUPPORTED');
        return true;
      },
    );
  });

  test('RC03-N-41: move_file source unlink failure triggers rollback (unlinks destination)', async () => {
    const f = path.join(workspaceDir, 'rollback-src.txt');
    fs.writeFileSync(f, 'rollback test');
    const hash = crypto.createHash('sha256').update('rollback test').digest('hex');

    let unlinkCount = 0;
    class UnlinkFailOps extends NodeFilesystemOps {
      unlink(target) {
        unlinkCount++;
        if (unlinkCount === 1) {
          // Fail the source unlink
          const err = new Error('EPERM: cannot unlink source');
          err.code = 'EPERM';
          throw err;
        }
        // Rollback unlink succeeds
        super.unlink(target);
      }
    }

    const rollbackSubsystem = new FilesystemSubsystem(undefined, new UnlinkFailOps());
    await assert.rejects(
      async () => {
        await rollbackSubsystem.moveFile(workspaceDir, {
          sourcePath: 'rollback-src.txt',
          destinationPath: 'rollback-dest.txt',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );

    // Verify destination was removed by rollback
    assert.equal(fs.existsSync(path.join(workspaceDir, 'rollback-dest.txt')), false);
    // Source still exists
    assert.equal(fs.existsSync(f), true);
  });

  test('RC03-N-42: move_file rollback failure maps to ROLLBACK_FAILED with recovery metadata', async () => {
    const f = path.join(workspaceDir, 'severe-rollback-src.txt');
    fs.writeFileSync(f, 'severe rollback');
    const hash = crypto.createHash('sha256').update('severe rollback').digest('hex');

    class CatastrophicOps extends NodeFilesystemOps {
      unlink() {
        const err = new Error('Fatal I/O error during unlink');
        err.code = 'EIO';
        throw err;
      }
    }

    const failSubsystem = new FilesystemSubsystem(undefined, new CatastrophicOps());
    await assert.rejects(
      async () => {
        await failSubsystem.moveFile(workspaceDir, {
          sourcePath: 'severe-rollback-src.txt',
          destinationPath: 'severe-rollback-dest.txt',
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.ok(err.details);
        assert.equal(err.details.sourcePath, 'severe-rollback-src.txt');
        assert.equal(err.details.destinationPath, 'severe-rollback-dest.txt');
        return true;
      },
    );
  });

  // ==========================================================================
  // 5. Locking & Concurrency Invariants
  // ==========================================================================

  test('RC03-L-01: ProcessWideLockManager coordinates concurrent callers with barrier contention and cleans up state', async () => {
    const lm = new ProcessWideLockManager();
    let action1Entered = false;
    let action2Entered = false;

    let releaseAction1;
    const barrier = new Promise((resolve) => {
      releaseAction1 = resolve;
    });

    const p1 = lm.withLocks(['test-key'], async () => {
      action1Entered = true;
      await barrier;
    });

    while (!action1Entered) {
      await new Promise((r) => setTimeout(r, 5));
    }

    const p2 = lm.withLocks(['test-key'], async () => {
      action2Entered = true;
    });

    await new Promise((r) => setTimeout(r, 20));
    assert.equal(
      action2Entered,
      false,
      'Action 2 must not enter critical section while Action 1 holds lock',
    );

    releaseAction1();
    await Promise.all([p1, p2]);

    assert.equal(action2Entered, true, 'Action 2 entered critical section after Action 1 released');
    assert.equal(lm.activeLockCount, 0, 'Locks map cleaned up completely');
  });

  test('RC03-L-02: two FilesystemSubsystem instances without explicit lockManager coordinate via defaultLockManager', async () => {
    const fs1 = new FilesystemSubsystem();
    const fs2 = new FilesystemSubsystem();

    const targetRel = 'default-lock-test.txt';
    const targetAbs = path.join(workspaceDir, targetRel);
    fs.writeFileSync(targetAbs, 'init');
    const hash = crypto.createHash('sha256').update('init').digest('hex');

    const p1 = fs1.writeFile(workspaceDir, {
      path: targetRel,
      content: 'fs1 write',
      expectedHash: hash,
      overwrite: true,
    });
    const p2 = fs2.writeFile(workspaceDir, {
      path: targetRel,
      content: 'fs2 write',
      expectedHash: hash,
      overwrite: true,
    });

    const results = await Promise.allSettled([p1, p2]);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');

    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason.code, 'CONFLICT_PRECONDITION_FAILED');
  });

  test('RC03-L-03: multi-path locking in move_file is deterministic and deadlock-free across reversed pairs', async () => {
    const fA = path.join(workspaceDir, 'pair-a.txt');
    const fB = path.join(workspaceDir, 'pair-b.txt');
    fs.writeFileSync(fA, 'data A');
    fs.writeFileSync(fB, 'data B');

    const hashA = crypto.createHash('sha256').update('data A').digest('hex');
    const hashB = crypto.createHash('sha256').update('data B').digest('hex');

    // Both attempt moves touching pair-a and pair-b in reverse directions concurrently
    const p1 = fsSubsystem
      .moveFile(workspaceDir, {
        sourcePath: 'pair-a.txt',
        destinationPath: 'pair-b.txt', // will fail ALREADY_EXISTS because pair-b exists
        expectedSourceHash: hashA,
      })
      .catch((e) => e);

    const p2 = fsSubsystem
      .moveFile(workspaceDir, {
        sourcePath: 'pair-b.txt',
        destinationPath: 'pair-a.txt', // will fail ALREADY_EXISTS because pair-a exists
        expectedSourceHash: hashB,
      })
      .catch((e) => e);

    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1.code, 'ALREADY_EXISTS');
    assert.equal(r2.code, 'ALREADY_EXISTS');
  });

  test('RC03-L-04: multi-key locking with reverse key requests executes without deadlock', async () => {
    const lm = new ProcessWideLockManager();
    const keyA = '/canonical/dir/a.txt';
    const keyB = '/canonical/dir/b.txt';

    const order = [];

    const op1 = lm.withLocks([keyA, keyB], async () => {
      order.push('op1-start');
      await new Promise((r) => setTimeout(r, 10));
      order.push('op1-end');
    });

    const op2 = lm.withLocks([keyB, keyA], async () => {
      order.push('op2-start');
      await new Promise((r) => setTimeout(r, 10));
      order.push('op2-end');
    });

    await Promise.all([op1, op2]);

    assert.equal(lm.activeLockCount, 0);
    const op1First = order[0] === 'op1-start';
    if (op1First) {
      assert.deepEqual(order, ['op1-start', 'op1-end', 'op2-start', 'op2-end']);
    } else {
      assert.deepEqual(order, ['op2-start', 'op2-end', 'op1-start', 'op1-end']);
    }
  });

  test('RC03-N-46: error messages never leak host absolute paths, usernames, or temp file names', async () => {
    try {
      await fsSubsystem.createFile(workspaceDir, {
        path: '../escaped-dir/evil.txt',
        content: 'bad',
      });
      assert.fail('Should have thrown');
    } catch (err) {
      assert.ok(err instanceof ArcError);
      assert.ok(!err.message.includes(workspaceDir));
      assert.ok(!err.message.includes(os.homedir()));
      assert.ok(!err.message.includes('.arc-tmp-'));
    }
  });

  test('RC03-G-01: existing read operations continue to work without regression', async () => {
    const readResult = await fsSubsystem.readFile(workspaceDir, {
      path: 'new-file.txt',
    });
    assert.equal(readResult.content, 'Hello, RC-03 create_file!');
    assert.equal(readResult.truncated, false);

    const listResult = await fsSubsystem.listDirectory(workspaceDir, {
      path: '.',
    });
    assert.ok(listResult.entries.length > 0);
  });

  // ==========================================================================
  // 6. Security Remediations & Failure Boundary Hardening
  // ==========================================================================

  test('RC03-REM-01: partial write correctness persists complete buffer across multiple writes and fails closed on zero progress', async () => {
    class FragmentedWriteFsOps extends NodeFilesystemOps {
      write(fd, buffer, offset = 0, length = buffer.length - offset, position = null) {
        const chunk = Math.min(length, 7);
        return super.write(fd, buffer, offset, chunk, position);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new FragmentedWriteFsOps());
    const content =
      'This is a long test payload that must be safely written in small 7-byte chunks!';
    const res = await customFs.createFile(workspaceDir, {
      path: 'fragmented-write.txt',
      content,
    });

    assert.equal(res.created, true);
    assert.equal(res.bytesWritten, Buffer.byteLength(content, 'utf8'));

    const readBack = fs.readFileSync(path.join(workspaceDir, 'fragmented-write.txt'), 'utf8');
    assert.equal(readBack, content);

    class ZeroProgressFsOps extends NodeFilesystemOps {
      write(_fd, _buffer, _offset, _length, _position) {
        return 0;
      }
    }
    const zeroFs = new FilesystemSubsystem(undefined, new ZeroProgressFsOps());
    await assert.rejects(
      async () => {
        await zeroFs.createFile(workspaceDir, {
          path: 'zero-progress.txt',
          content: 'fail me',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INTERNAL_ERROR');
        return true;
      },
    );
  });

  test('RC03-REM-02: write_file preserves exact original mode bits via fchmod (bypassing umask)', async () => {
    const targetFile = path.join(workspaceDir, 'mode-preserve.txt');
    fs.writeFileSync(targetFile, 'original content');
    fs.chmodSync(targetFile, 0o666);
    const origSt = fs.statSync(targetFile);
    const origMode = origSt.mode & 0o777;

    const origHash = crypto.createHash('sha256').update('original content').digest('hex');

    const res = await fsSubsystem.writeFile(workspaceDir, {
      path: 'mode-preserve.txt',
      content: 'replacement content',
      expectedHash: origHash,
      overwrite: true,
    });

    assert.ok(res.contentHash);
    const newSt = fs.statSync(targetFile);
    const newMode = newSt.mode & 0o777;
    assert.equal(
      newMode,
      origMode,
      `Preserved mode ${newMode.toString(8)} must equal original mode ${origMode.toString(8)}`,
    );
  });

  test('RC03-REM-03: create_file temp unlink failure after link triggers destination rollback and throws sanitized internalError', async () => {
    let linkCalled = false;
    class TempUnlinkFailFsOps extends NodeFilesystemOps {
      link(tmp, target) {
        super.link(tmp, target);
        linkCalled = true;
      }
      unlink(targetPath) {
        if (linkCalled && targetPath.includes('.arc-tmp-')) {
          const err = new Error('Injected temp unlink failure');
          err.code = 'EIO';
          throw err;
        }
        super.unlink(targetPath);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new TempUnlinkFailFsOps());
    const targetRel = 'rollback-create-success.txt';
    const targetAbs = path.join(workspaceDir, targetRel);

    await assert.rejects(
      async () => {
        await customFs.createFile(workspaceDir, {
          path: targetRel,
          content: 'rollback test content',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'INTERNAL_ERROR');
        assert.ok(!err.message.includes('.arc-tmp-'));
        return true;
      },
    );

    assert.equal(fs.existsSync(targetAbs), false);
  });

  test('RC03-REM-04: create_file temp unlink failure with destination rollback failure throws ROLLBACK_FAILED with safe metadata', async () => {
    let linkCalled = false;
    class DoubleUnlinkFailFsOps extends NodeFilesystemOps {
      link(tmp, target) {
        super.link(tmp, target);
        linkCalled = true;
      }
      unlink(targetPath) {
        if (linkCalled) {
          const err = new Error('Injected unlink failure');
          err.code = 'EIO';
          throw err;
        }
        super.unlink(targetPath);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new DoubleUnlinkFailFsOps());
    const targetRel = 'rollback-create-fail.txt';

    await assert.rejects(
      async () => {
        await customFs.createFile(workspaceDir, {
          path: targetRel,
          content: 'unrollable content',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        assert.deepEqual(err.details, {
          path: targetRel,
          committed: true,
        });
        assert.ok(!JSON.stringify(err.details).includes('.arc-tmp-'));
        return true;
      },
    );
  });

  test('RC03-REM-05: create_file temp unlink failure does not unlink changed destination inode', async () => {
    let linkCalled = false;
    const targetRel = 'rollback-inode-mismatch.txt';
    const targetAbs = path.join(workspaceDir, targetRel);

    class InodeChangeFsOps extends NodeFilesystemOps {
      link(tmp, target) {
        super.link(tmp, target);
        linkCalled = true;
      }
      unlink(targetPath) {
        if (linkCalled && targetPath.includes('.arc-tmp-')) {
          fs.unlinkSync(targetAbs);
          fs.writeFileSync(targetAbs, 'replaced content');
          const err = new Error('Injected temp unlink failure');
          err.code = 'EIO';
          throw err;
        }
        super.unlink(targetPath);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new InodeChangeFsOps());
    await assert.rejects(
      async () => {
        await customFs.createFile(workspaceDir, {
          path: targetRel,
          content: 'original staged content',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        return true;
      },
    );

    assert.equal(fs.existsSync(targetAbs), true);
    assert.equal(fs.readFileSync(targetAbs, 'utf8'), 'replaced content');
  });

  test('RC03-REM-06: move_file source unlink failure rolls back destination when dev/ino matches', async () => {
    const srcRel = 'move-rollback-src.txt';
    const destRel = 'move-rollback-dest.txt';
    const srcAbs = path.join(workspaceDir, srcRel);
    const destAbs = path.join(workspaceDir, destRel);
    fs.writeFileSync(srcAbs, 'move rollback content');
    const hash = crypto.createHash('sha256').update('move rollback content').digest('hex');

    class UnlinkSrcFailFsOps extends NodeFilesystemOps {
      unlink(targetPath) {
        if (targetPath === srcAbs) {
          const err = new Error('Injected source unlink error');
          err.code = 'EACCES';
          throw err;
        }
        super.unlink(targetPath);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new UnlinkSrcFailFsOps());
    await assert.rejects(
      async () => {
        await customFs.moveFile(workspaceDir, {
          sourcePath: srcRel,
          destinationPath: destRel,
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ACCESS_DENIED');
        return true;
      },
    );

    assert.equal(fs.existsSync(destAbs), false);
    assert.equal(fs.existsSync(srcAbs), true);
  });

  test('RC03-REM-07: move_file source unlink failure does not unlink changed destination inode', async () => {
    const srcRel = 'move-changed-dest-src.txt';
    const destRel = 'move-changed-dest-dest.txt';
    const srcAbs = path.join(workspaceDir, srcRel);
    const destAbs = path.join(workspaceDir, destRel);
    fs.writeFileSync(srcAbs, 'content for move');
    const hash = crypto.createHash('sha256').update('content for move').digest('hex');

    class DestChangedFsOps extends NodeFilesystemOps {
      unlink(targetPath) {
        if (targetPath === srcAbs) {
          fs.unlinkSync(destAbs);
          fs.writeFileSync(destAbs, 'unrelated replaced content');
          const err = new Error('Injected source unlink failure');
          err.code = 'EIO';
          throw err;
        }
        super.unlink(targetPath);
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new DestChangedFsOps());
    await assert.rejects(
      async () => {
        await customFs.moveFile(workspaceDir, {
          sourcePath: srcRel,
          destinationPath: destRel,
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'ROLLBACK_FAILED');
        return true;
      },
    );

    assert.equal(fs.existsSync(destAbs), true);
    assert.equal(fs.readFileSync(destAbs, 'utf8'), 'unrelated replaced content');
  });

  test('RC03-REM-08: move_file post-link identity mismatch does not unlink destination and throws CONFLICT_PRECONDITION_FAILED', async () => {
    const srcRel = 'move-mismatch-src.txt';
    const destRel = 'move-mismatch-dest.txt';
    const srcAbs = path.join(workspaceDir, srcRel);
    const destAbs = path.join(workspaceDir, destRel);
    fs.writeFileSync(srcAbs, 'mismatch content');
    const hash = crypto.createHash('sha256').update('mismatch content').digest('hex');

    class PostLinkMismatchFsOps extends NodeFilesystemOps {
      link(_src, dest) {
        fs.writeFileSync(dest, 'different inode file');
      }
    }

    const customFs = new FilesystemSubsystem(undefined, new PostLinkMismatchFsOps());
    await assert.rejects(
      async () => {
        await customFs.moveFile(workspaceDir, {
          sourcePath: srcRel,
          destinationPath: destRel,
          expectedSourceHash: hash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        assert.equal(err.code, 'CONFLICT_PRECONDITION_FAILED');
        return true;
      },
    );

    assert.equal(fs.existsSync(destAbs), true);
    assert.equal(fs.readFileSync(destAbs, 'utf8'), 'different inode file');
  });

  test('RC03-REM-09: stale ARC write: two callers with same expectedHash - only first commits, second fails with CONFLICT_PRECONDITION_FAILED', async () => {
    const targetRel = 'stale-arc-write.txt';
    const targetAbs = path.join(workspaceDir, targetRel);
    const initialContent = 'initial state content';
    fs.writeFileSync(targetAbs, initialContent);
    const initialHash = crypto.createHash('sha256').update(initialContent).digest('hex');

    const call1 = fsSubsystem.writeFile(workspaceDir, {
      path: targetRel,
      content: 'first mutation won',
      expectedHash: initialHash,
      overwrite: true,
    });

    const call2 = fsSubsystem.writeFile(workspaceDir, {
      path: targetRel,
      content: 'second mutation stale',
      expectedHash: initialHash,
      overwrite: true,
    });

    const [res1, res2] = await Promise.allSettled([call1, call2]);

    const winner = res1.status === 'fulfilled' ? res1 : res2;
    const loser = res1.status === 'rejected' ? res1 : res2;

    assert.equal(winner.status, 'fulfilled');
    assert.equal(loser.status, 'rejected');
    assert.equal(loser.reason.code, 'CONFLICT_PRECONDITION_FAILED');

    const diskContent = fs.readFileSync(targetAbs, 'utf8');
    assert.ok(diskContent === 'first mutation won' || diskContent === 'second mutation stale');
  });

  test('RC03-REM-10: injected errors containing sensitive absolute and temp paths never leak to caller across operation classes', async () => {
    const sensitiveMsg =
      'CRITICAL_LEAK: /home/secretuser/project/.arc-tmp-99999 failed at /sys/kernel';

    class LeakingFsOps extends NodeFilesystemOps {
      open() {
        const err = new Error(sensitiveMsg);
        err.code = 'EIO';
        throw err;
      }
      unlink() {
        const err = new Error(sensitiveMsg);
        err.code = 'EIO';
        throw err;
      }
      link() {
        const err = new Error(sensitiveMsg);
        err.code = 'EIO';
        throw err;
      }
    }

    const leakFs = new FilesystemSubsystem(undefined, new LeakingFsOps());

    // 1. createFile
    await assert.rejects(
      async () => {
        await leakFs.createFile(workspaceDir, {
          path: 'leak-create.txt',
          content: 'data',
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        const errStr = `${err.message} ${JSON.stringify(err.details ?? {})}`;
        assert.ok(!errStr.includes('/home/secretuser'));
        assert.ok(!errStr.includes('.arc-tmp-'));
        assert.ok(!errStr.includes('secretuser'));
        assert.ok(!errStr.includes('CRITICAL_LEAK'));
        return true;
      },
    );

    // 2. deleteFile
    const existingFile = path.join(workspaceDir, 'leak-del.txt');
    fs.writeFileSync(existingFile, 'del');
    const delHash = crypto.createHash('sha256').update('del').digest('hex');

    await assert.rejects(
      async () => {
        await leakFs.deleteFile(workspaceDir, {
          path: 'leak-del.txt',
          expectedHash: delHash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        const errStr = `${err.message} ${JSON.stringify(err.details ?? {})}`;
        assert.ok(!errStr.includes('/home/secretuser'));
        assert.ok(!errStr.includes('.arc-tmp-'));
        assert.ok(!errStr.includes('secretuser'));
        assert.ok(!errStr.includes('CRITICAL_LEAK'));
        return true;
      },
    );

    // 3. moveFile
    const moveSrc = path.join(workspaceDir, 'leak-move.txt');
    fs.writeFileSync(moveSrc, 'move');
    const moveHash = crypto.createHash('sha256').update('move').digest('hex');

    await assert.rejects(
      async () => {
        await leakFs.moveFile(workspaceDir, {
          sourcePath: 'leak-move.txt',
          destinationPath: 'leak-move-dest.txt',
          expectedSourceHash: moveHash,
        });
      },
      (err) => {
        assert.ok(err instanceof ArcError);
        const errStr = `${err.message} ${JSON.stringify(err.details ?? {})}`;
        assert.ok(!errStr.includes('/home/secretuser'));
        assert.ok(!errStr.includes('.arc-tmp-'));
        assert.ok(!errStr.includes('secretuser'));
        assert.ok(!errStr.includes('CRITICAL_LEAK'));
        return true;
      },
    );
  });
});
