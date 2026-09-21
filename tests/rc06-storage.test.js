/**
 * CesSpace ARC — RC-06 Task 1: Persistent Append Storage, Protocol, Metadata & Lock
 *
 * Test suite verifying:
 * - Fresh store initialization and directory security
 * - AuditStoreMetadataV1 validation and persistence
 * - Single-writer process lock (audit.lock)
 * - Canonical V1 JSON representation and non-circular hash preimage
 * - PersistentAuditStorage append engine
 * - All frozen Task-1 negative security controls RC06-NEG-01..29
 * - Hardened strict V1 schema and parser canonicality
 * - Storage state machine and failure bounds
 * - Initialization rollback and lock cleanup
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

import { MAX_RECORD_BYTES } from '../packages/protocol/dist/index.js';

import {
  PersistentAuditStorage,
  canonicalJsonV1,
  computeRecordHashPreimageV1,
  computeRecordHashV1,
  serializeRecordV1,
  parseAndValidateRecordLineV1,
  validatePersistentRecordV1,
  validateIntegrityObjectV1,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  validatePlatformCapabilities,
  acquireWriterLock,
  createStoreMetadataFile,
  loadStoreMetadataFile,
  normalizeStoreMetadataConfig,
  validateStoreMetadataConsistency,
  ACTIVE_SEGMENT_FILENAME,
  METADATA_FILENAME,
  UUID_V4_REGEX,
} from '../packages/audit/dist/index.js';

import { createTestPersistentAuditStorage } from '../packages/audit/dist/internal/storage-testing.js';

function createSampleRecordCandidate() {
  return {
    eventId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    timestamp: '2026-09-20T18:00:00.000Z',
    actor: {
      clientId: 'test-client',
      clientType: 'admin',
      deviceId: 'a'.repeat(32),
      sessionId: 'b'.repeat(64),
    },
    target: {
      workspaceId: 'ws-test',
      workspacePath: '',
      workspaceRootHash: 'c'.repeat(64),
    },
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { path: 'test.txt' },
      payloadHash: 'd'.repeat(64),
    },
    policy: {
      decision: 'ALLOW',
      ruleId: 'rule-test-01',
      evaluationDurationMs: 1.5,
    },
    execution: {
      status: 'SUCCESS',
      startTime: '2026-09-20T18:00:00.000Z',
      endTime: '2026-09-20T18:00:00.010Z',
      durationMs: 10,
    },
  };
}

describe('CesSpace ARC — RC-06 Task 1: Persistent Append Storage Foundation', () => {
  let tempBaseDir;

  before(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task1-'));
  });

  after(() => {
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe('Positive Flows: Store Initialization, Locking & V1 Append', () => {
    test('Fresh store initialization creates directory, lock, metadata, and active segment', async () => {
      const auditDir = path.join(tempBaseDir, 'store-init');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: '1'.repeat(64),
          anchorMode: 'DISABLED',
        },
      });

      storage.initialize();

      const dirStats = fs.statSync(auditDir);
      assert.equal(dirStats.mode & 0o777, 0o700, 'audit directory must be 0700');

      const metaPath = path.join(auditDir, METADATA_FILENAME);
      assert.ok(fs.existsSync(metaPath), 'audit-store.json must exist');
      const metaStats = fs.statSync(metaPath);
      assert.equal(metaStats.mode & 0o777, 0o600, 'audit-store.json must be 0600');

      const metadata = storage.getMetadata();
      assert.ok(metadata !== null, 'metadata must be loaded');
      assert.equal(metadata.version, 1);
      assert.equal(metadata.anchorMode, 'DISABLED');
      assert.equal(metadata.checkpointPublicKeyFingerprint, '1'.repeat(64));
      assert.match(
        metadata.storeId,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );

      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      assert.ok(fs.existsSync(activePath), 'active segment must exist');
      const activeStats = fs.statSync(activePath);
      assert.equal(activeStats.mode & 0o777, 0o600, 'active segment must be 0600');

      assert.equal(storage.getCurrentSequence(), 1);
      assert.equal(storage.getLastRecordHash(), '0'.repeat(64));
      assert.equal(storage.getState(), 'ACTIVE');

      storage.close();
    });

    test('Canonical V1 appends advance sequence and previousRecordHash strictly', async () => {
      const auditDir = path.join(tempBaseDir, 'store-appends');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: '2'.repeat(64),
          anchorMode: 'ENABLED',
          anchorReceiptPublicKeyFingerprint: '3'.repeat(64),
        },
      });

      storage.initialize();

      const r1 = await storage.append(createSampleRecordCandidate());
      assert.equal(r1.schemaVersion, 1);
      assert.equal(r1.sequenceNumber, 1);
      assert.equal(r1.integrity.previousRecordHash, '0'.repeat(64));
      assert.match(r1.integrity.recordHash, /^[0-9a-f]{64}$/);

      const r2 = await storage.append(createSampleRecordCandidate());
      assert.equal(r2.schemaVersion, 1);
      assert.equal(r2.sequenceNumber, 2);
      assert.equal(r2.integrity.previousRecordHash, r1.integrity.recordHash);
      assert.match(r2.integrity.recordHash, /^[0-9a-f]{64}$/);

      assert.equal(storage.getCurrentSequence(), 3);
      assert.equal(storage.getLastRecordHash(), r2.integrity.recordHash);

      const lines = fs
        .readFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME), 'utf8')
        .split('\n');
      assert.equal(lines.length, 3); // 2 lines + trailing newline
      assert.equal(lines[2], '');

      const parsed1 = parseAndValidateRecordLineV1(lines[0] + '\n');
      assert.equal(parsed1.record.sequenceNumber, 1);
      assert.equal(parsed1.record.integrity.recordHash, r1.integrity.recordHash);

      const parsed2 = parseAndValidateRecordLineV1(lines[1] + '\n');
      assert.equal(parsed2.record.sequenceNumber, 2);
      assert.equal(parsed2.record.integrity.recordHash, r2.integrity.recordHash);

      storage.close();
    });

    test('Non-circular record hash preimage reconstructs and verifies', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: {
          previousRecordHash: '0'.repeat(64),
          recordHash: '',
        },
      };

      const hash = computeRecordHashV1(candidate);
      candidate.integrity.recordHash = hash;

      const line = serializeRecordV1(candidate);
      const parsed = parseAndValidateRecordLineV1(line);
      assert.equal(parsed.computedHash, hash);

      const preimage = computeRecordHashPreimageV1(candidate);
      assert.ok(typeof preimage === 'string' && preimage.length > 0);

      const lineWithoutNewline = line.slice(0, -1);
      const directLineHash = createHash('sha256').update(lineWithoutNewline, 'utf8').digest('hex');
      assert.notEqual(
        directLineHash,
        hash,
        'direct hash of stored line must differ from recordHash',
      );
    });

    test('Durability and cursor safety on simulated write failure and short write', async () => {
      const auditDir = path.join(tempBaseDir, 'store-failure');

      const storageFail = createTestPersistentAuditStorage(
        {
          directory: auditDir,
          createIfMissing: true,
          metadata: {
            checkpointPublicKeyFingerprint: '4'.repeat(64),
          },
        },
        { writeFault: 'error' },
      );
      storageFail.initialize();

      await assert.rejects(async () => {
        await storageFail.append(createSampleRecordCandidate());
      }, /SIMULATED_WRITE_FAILURE/);

      assert.equal(storageFail.getCurrentSequence(), 1, 'cursor must not advance on failure');
      assert.equal(storageFail.getLastRecordHash(), '0'.repeat(64));
      assert.equal(storageFail.getState(), 'FAILED');

      // Subsequent append must fail with AUDIT_STORAGE_FAILED
      await assert.rejects(
        async () => {
          await storageFail.append(createSampleRecordCandidate());
        },
        (err) => err.code === 'AUDIT_STORAGE_FAILED',
      );

      storageFail.close();

      const auditDirShort = path.join(tempBaseDir, 'store-short-write');
      const storageShort = createTestPersistentAuditStorage(
        {
          directory: auditDirShort,
          createIfMissing: true,
          metadata: {
            checkpointPublicKeyFingerprint: '4'.repeat(64),
          },
        },
        { writeFault: 'partial' },
      );
      storageShort.initialize();

      await assert.rejects(async () => {
        await storageShort.append(createSampleRecordCandidate());
      }, /SHORT_WRITE/);

      assert.equal(storageShort.getCurrentSequence(), 1, 'cursor must not advance on short write');
      assert.equal(storageShort.getState(), 'FAILED');

      // Subsequent append must fail with AUDIT_STORAGE_FAILED
      await assert.rejects(
        async () => {
          await storageShort.append(createSampleRecordCandidate());
        },
        (err) => err.code === 'AUDIT_STORAGE_FAILED',
      );

      storageShort.close();
    });

    test('Exclusive writer lock lifecycle and reacquisition', () => {
      const auditDir = path.join(tempBaseDir, 'store-lock-lifecycle');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      const lock1 = acquireWriterLock({ auditDir });
      assert.ok(fs.existsSync(lock1.lockPath));

      assert.throws(
        () => acquireWriterLock({ auditDir }),
        (err) => err.code === 'AUDIT_STORE_LOCKED',
      );

      lock1.release();
      assert.ok(!fs.existsSync(lock1.lockPath));

      const lock2 = acquireWriterLock({ auditDir });
      assert.ok(fs.existsSync(lock2.lockPath));
      lock2.release();
    });
  });

  describe('Negative Controls: RC06-NEG-01..29', () => {
    test('RC06-NEG-01: Audit directory is a symlink. Startup rejected.', () => {
      const targetDir = path.join(tempBaseDir, 'neg-01-target');
      fs.mkdirSync(targetDir, { mode: 0o700, recursive: true });
      const symlinkDir = path.join(tempBaseDir, 'neg-01-symlink');
      fs.symlinkSync(targetDir, symlinkDir, 'dir');

      assert.throws(
        () => validateAuditDirectory(symlinkDir),
        (err) => err.code === 'SYMLINK_DETECTED' || err.code === 'INVALID_AUDIT_PATH',
      );
    });

    test('RC06-NEG-02: Active audit segment file is a symlink. Write rejected.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-02-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const targetFile = path.join(tempBaseDir, 'neg-02-target.jsonl');
      fs.writeFileSync(targetFile, '', { mode: 0o600 });
      const symlinkSegment = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      fs.symlinkSync(targetFile, symlinkSegment);

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'SYMLINK_DETECTED',
      );
    });

    test('RC06-NEG-03: Audit directory permissions wider than 0700 (e.g. 0755). Startup rejected.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-03-store');
      fs.mkdirSync(auditDir, { mode: 0o755, recursive: true });
      fs.chmodSync(auditDir, 0o755);

      assert.throws(
        () => validateAuditDirectory(auditDir),
        (err) => err.code === 'INSECURE_PERMISSIONS',
      );
    });

    test('RC06-NEG-04: Audit segment file permissions wider than 0600 (e.g. 0644). Startup rejected.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-04-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const segmentFile = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      fs.writeFileSync(segmentFile, '', { mode: 0o644 });
      fs.chmodSync(segmentFile, 0o644);

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'INSECURE_PERMISSIONS',
      );
    });

    test('RC06-NEG-05: Audit directory owned by different UID. Startup rejected with OWNERSHIP_MISMATCH.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-05-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      assert.throws(
        () => validateAuditDirectory(auditDir, { expectedUid: process.getuid() + 9999 }),
        (err) => err.code === 'OWNERSHIP_MISMATCH',
      );
    });

    test('RC06-NEG-06: Audit segment owned by different UID. Write rejected with OWNERSHIP_MISMATCH.', () => {
      const filePath = path.join(tempBaseDir, 'neg-06-file.jsonl');
      fs.writeFileSync(filePath, '', { mode: 0o600 });
      const fd = fs.openSync(filePath, fs.constants.O_RDWR);

      try {
        assert.throws(
          () => validateFileDescriptorAuthority(fd, 0o600, process.getuid() + 9999),
          (err) => err.code === 'OWNERSHIP_MISMATCH',
        );
      } finally {
        fs.closeSync(fd);
      }
    });

    test('RC06-NEG-07: Target audit path is a non-regular file (FIFO, device). Write rejected.', () => {
      const fifoPath = path.join(tempBaseDir, 'neg-07-fifo');
      try {
        execFileSync('mkfifo', [fifoPath]);
      } catch {
        // ignore
      }

      if (fs.existsSync(fifoPath)) {
        const fd = fs.openSync(fifoPath, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
        try {
          assert.throws(
            () => validateFileDescriptorAuthority(fd, 0o600),
            (err) => err.code === 'NOT_REGULAR_FILE',
          );
        } finally {
          fs.closeSync(fd);
        }
      } else {
        const devFd = fs.openSync('/dev/null', fs.constants.O_RDONLY);
        try {
          assert.throws(
            () => validateFileDescriptorAuthority(devFd, 0o600),
            (err) => err.code === 'NOT_REGULAR_FILE',
          );
        } finally {
          fs.closeSync(devFd);
        }
      }
    });

    test('RC06-NEG-08: Target audit path attempts directory traversal (../). Path rejected.', () => {
      const traversalPath = path.join(tempBaseDir, 'sub', '..', 'neg-08-traversal');
      assert.throws(
        () => validateAuditDirectory(traversalPath),
        (err) => err.code === 'INVALID_AUDIT_PATH',
      );
    });

    test('RC06-NEG-09: Active audit segment file has hard-link count > 1 (nlink != 1). Write rejected.', () => {
      const filePath = path.join(tempBaseDir, 'neg-09-file.jsonl');
      const linkPath = path.join(tempBaseDir, 'neg-09-link.jsonl');
      fs.writeFileSync(filePath, '', { mode: 0o600 });
      fs.linkSync(filePath, linkPath);

      const fd = fs.openSync(filePath, fs.constants.O_RDWR);
      try {
        assert.throws(
          () => validateFileDescriptorAuthority(fd, 0o600),
          (err) => err.code === 'HARD_LINK_DETECTED',
        );
      } finally {
        fs.closeSync(fd);
      }
    });

    test('RC06-NEG-10: O_NOFOLLOW / fstat descriptor check detects symlink substitution during open. Rejected.', () => {
      const targetFile = path.join(tempBaseDir, 'neg-10-target');
      fs.writeFileSync(targetFile, 'data', { mode: 0o600 });
      const symlinkFile = path.join(tempBaseDir, 'neg-10-symlink');
      fs.symlinkSync(targetFile, symlinkFile);

      assert.throws(
        () => fs.openSync(symlinkFile, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW),
        /ELOOP/,
      );
    });

    test('RC06-NEG-11: Unsupported platform lacking O_NOFOLLOW or required POSIX primitives fails production startup.', () => {
      assert.throws(
        () => validatePlatformCapabilities({ hasONoFollow: false }),
        (err) => err.code === 'AUDIT_PLATFORM_UNSUPPORTED',
      );
      assert.throws(
        () => validatePlatformCapabilities({ isPosixPlatform: false }),
        (err) => err.code === 'AUDIT_PLATFORM_UNSUPPORTED',
      );
      assert.throws(
        () => validatePlatformCapabilities({ hasGetUid: false }),
        (err) => err.code === 'AUDIT_PLATFORM_UNSUPPORTED',
      );
    });

    test('RC06-NEG-12: Second ARC process attempts lock on existing audit.lock (fails with AUDIT_STORE_LOCKED).', () => {
      const auditDir = path.join(tempBaseDir, 'neg-12-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      const lock1 = acquireWriterLock({ auditDir });
      try {
        assert.throws(
          () => acquireWriterLock({ auditDir }),
          (err) => err.code === 'AUDIT_STORE_LOCKED',
        );
      } finally {
        lock1.release();
      }
    });

    test('RC06-NEG-13: Stale lock takeover attempted without operator intervention. Automatic takeover rejected.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-13-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const staleLockPath = path.join(auditDir, 'audit.lock');
      fs.writeFileSync(
        staleLockPath,
        JSON.stringify({ pid: 999999, startedAt: '2020-01-01T00:00:00.000Z' }) + '\n',
        { mode: 0o600 },
      );

      assert.throws(
        () => acquireWriterLock({ auditDir }),
        (err) => err.code === 'AUDIT_STORE_LOCKED',
      );
      assert.ok(fs.existsSync(staleLockPath), 'stale lock file must not be deleted');
    });

    test('RC06-NEG-14: Audit lock file is a symlink or hard link. Startup fails immediately.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-14-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const dummyFile = path.join(tempBaseDir, 'neg-14-dummy');
      fs.writeFileSync(dummyFile, 'dummy', { mode: 0o600 });
      const lockSymlink = path.join(auditDir, 'audit.lock');
      fs.symlinkSync(dummyFile, lockSymlink);

      assert.throws(
        () => acquireWriterLock({ auditDir }),
        (err) => err.code === 'AUDIT_LOCK_INSECURE' || err.code === 'SYMLINK_DETECTED',
      );
    });

    test('RC06-NEG-15: Configured audit directory path contains unexpanded literal ~. Startup fails; shell expansion prohibited.', () => {
      assert.throws(
        () => validateAuditDirectory('~/.cesspace-arc/audit'),
        (err) => err.code === 'INVALID_AUDIT_PATH',
      );
    });

    test('RC06-NEG-16: audit-store.json missing on non-empty audit store. Startup fails closed.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-16-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const activeFile = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      fs.writeFileSync(activeFile, 'some-prior-record\n', { mode: 0o600 });

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'METADATA_MISSING',
      );
    });

    test('RC06-NEG-17: Tampered or malformed audit-store.json metadata. Startup fails closed.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-17-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      const metaFile = path.join(auditDir, METADATA_FILENAME);

      fs.writeFileSync(metaFile, '{ not valid json\n', { mode: 0o600 });
      assert.throws(
        () => loadStoreMetadataFile(auditDir),
        (err) => err.code === 'INVALID_METADATA',
      );

      fs.writeFileSync(metaFile, JSON.stringify({ version: 2 }) + '\n', { mode: 0o600 });
      assert.throws(
        () => loadStoreMetadataFile(auditDir),
        (err) => err.code === 'UNSUPPORTED_METADATA_VERSION',
      );

      // Unknown field in metadata
      fs.writeFileSync(
        metaFile,
        JSON.stringify({
          version: 1,
          storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          createdAt: '2026-09-20T18:00:00.000Z',
          checkpointPublicKeyFingerprint: 'a'.repeat(64),
          anchorMode: 'DISABLED',
          unknownField: 'forbidden',
        }) + '\n',
        { mode: 0o600 },
      );
      assert.throws(
        () => loadStoreMetadataFile(auditDir),
        (err) => err.code === 'INVALID_METADATA',
      );

      // Non-canonical createdAt format (missing milliseconds)
      fs.writeFileSync(
        metaFile,
        JSON.stringify({
          version: 1,
          storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          createdAt: '2026-09-20T18:00:00Z',
          checkpointPublicKeyFingerprint: 'a'.repeat(64),
          anchorMode: 'DISABLED',
        }) + '\n',
        { mode: 0o600 },
      );
      assert.throws(
        () => loadStoreMetadataFile(auditDir),
        (err) => err.code === 'INVALID_METADATA',
      );
    });

    test('RC06-NEG-18: Configured checkpoint public key fingerprint does not match audit-store.json. Startup fails closed.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-18-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'DISABLED',
      });

      const loaded = loadStoreMetadataFile(auditDir);
      assert.throws(
        () =>
          validateStoreMetadataConsistency(loaded, {
            checkpointPublicKeyFingerprint: 'b'.repeat(64),
          }),
        (err) => err.code === 'FINGERPRINT_MISMATCH',
      );
    });

    test('RC06-NEG-19: Configured anchor receipt public key fingerprint does not match audit-store.json when anchor mode is enabled. Startup fails closed.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-19-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'ENABLED',
        anchorReceiptPublicKeyFingerprint: 'b'.repeat(64),
      });

      const loaded = loadStoreMetadataFile(auditDir);
      assert.throws(
        () =>
          validateStoreMetadataConsistency(loaded, {
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
            anchorMode: 'ENABLED',
            anchorReceiptPublicKeyFingerprint: 'c'.repeat(64),
          }),
        (err) => err.code === 'FINGERPRINT_MISMATCH',
      );
    });

    test('RC06-NEG-20: Attempting to change checkpoint signer or anchor trust settings on existing non-empty store. Rejected.', () => {
      const auditDir = path.join(tempBaseDir, 'neg-20-store');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'DISABLED',
      });

      const loaded = loadStoreMetadataFile(auditDir);
      assert.throws(
        () =>
          validateStoreMetadataConsistency(loaded, {
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
            anchorMode: 'ENABLED',
          }),
        (err) => err.code === 'STORE_RECONFIGURATION_FORBIDDEN',
      );
    });

    test('RC06-NEG-21: Record line missing terminating newline character (\\n). Line rejected as malformed.', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: '' },
      };
      candidate.integrity.recordHash = computeRecordHashV1(candidate);
      const lineWithoutNl = serializeRecordV1(candidate).slice(0, -1);

      assert.throws(
        () => parseAndValidateRecordLineV1(lineWithoutNl),
        (err) => err.code === 'INVALID_LINE',
      );
    });

    test('RC06-NEG-22: Record line containing carriage return character (\\r). Line rejected as malformed.', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: '' },
      };
      candidate.integrity.recordHash = computeRecordHashV1(candidate);
      const lineWithCr = serializeRecordV1(candidate).slice(0, -1) + '\r\n';

      assert.throws(
        () => parseAndValidateRecordLineV1(lineWithCr),
        (err) => err.code === 'INVALID_LINE',
      );
    });

    test('RC06-NEG-23: Record containing raw undefined or NaN/Infinity values. Canonicalization fails.', () => {
      assert.throws(
        () => canonicalJsonV1(undefined),
        (err) => err.code === 'CANONICAL_JSON_UNDEFINED',
      );
      assert.throws(
        () => canonicalJsonV1([undefined]),
        (err) => err.code === 'CANONICAL_JSON_UNDEFINED',
      );
      assert.throws(
        () => canonicalJsonV1({ num: NaN }),
        (err) => err.code === 'CANONICAL_JSON_INVALID_NUMBER',
      );
      assert.throws(
        () => canonicalJsonV1({ num: Infinity }),
        (err) => err.code === 'CANONICAL_JSON_INVALID_NUMBER',
      );
      assert.throws(
        () => canonicalJsonV1({ num: -Infinity }),
        (err) => err.code === 'CANONICAL_JSON_INVALID_NUMBER',
      );
    });

    test('RC06-NEG-24: Record containing unescaped control characters (< 0x20 or NUL). Line rejected.', () => {
      const badLine = '{"eventId":"\x01"}\n';
      assert.throws(
        () => parseAndValidateRecordLineV1(badLine),
        (err) => err.code === 'INVALID_LINE',
      );
    });

    test('RC06-NEG-25: Record with unsupported schemaVersion (e.g. 2 or 0). Verifier rejects with UNSUPPORTED_SCHEMA_VERSION.', () => {
      const badRecord = {
        ...createSampleRecordCandidate(),
        schemaVersion: 2,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      const line = JSON.stringify(badRecord) + '\n';
      assert.throws(
        () => parseAndValidateRecordLineV1(line),
        (err) => err.code === 'UNSUPPORTED_SCHEMA_VERSION',
      );
    });

    test('RC06-NEG-26: Record missing mandatory top-level schemaVersion: 1 field. Verification fails.', () => {
      const badRecord = {
        ...createSampleRecordCandidate(),
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      const line = JSON.stringify(badRecord) + '\n';
      assert.throws(
        () => parseAndValidateRecordLineV1(line),
        (err) => err.code === 'MISSING_SCHEMA_VERSION',
      );
    });

    test('RC06-NEG-27: Record containing unknown top-level field outside V1 schema. Verification fails.', () => {
      const badRecord = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        unknownField: 'bad-metadata',
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      const line = JSON.stringify(badRecord) + '\n';
      assert.throws(
        () => parseAndValidateRecordLineV1(line),
        (err) => err.code === 'UNKNOWN_FIELD',
      );
    });

    test('RC06-NEG-28: Single record exceeding MAX_RECORD_BYTES (64 KiB). Append rejected with RECORD_TOO_LARGE.', async () => {
      const auditDir = path.join(tempBaseDir, 'neg-28-store');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      const oversizedCandidate = {
        ...createSampleRecordCandidate(),
        invocation: {
          toolName: 'read_file',
          parametersRedacted: {
            hugeData: 'x'.repeat(MAX_RECORD_BYTES + 100),
          },
          payloadHash: 'd'.repeat(64),
        },
      };

      await assert.rejects(
        async () => {
          await storage.append(oversizedCandidate);
        },
        (err) => err.code === 'RECORD_TOO_LARGE',
      );

      assert.equal(storage.getCurrentSequence(), 1, 'cursor must not advance on oversized record');
      assert.equal(
        storage.getState(),
        'ACTIVE',
        'storage must remain active after oversized record rejected',
      );

      // Ensure storage remains healthy and can append next valid record
      const valid = await storage.append(createSampleRecordCandidate());
      assert.equal(valid.sequenceNumber, 1);

      storage.close();
    });

    test('RC06-NEG-29: Direct hash of stored line bytes asserted as recordHash. Rejected; verifier enforces hash preimage omission of integrity.recordHash.', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: '' },
      };

      const selfReferentialCandidate = {
        ...candidate,
        integrity: {
          previousRecordHash: '0'.repeat(64),
          recordHash: '0'.repeat(64),
        },
      };
      const directLine = serializeRecordV1(selfReferentialCandidate);
      const textWithoutNl = directLine.slice(0, -1);
      const directHash = createHash('sha256').update(textWithoutNl, 'utf8').digest('hex');

      const falseRecord = {
        ...candidate,
        integrity: {
          previousRecordHash: '0'.repeat(64),
          recordHash: directHash,
        },
      };

      const falseLine = serializeRecordV1(falseRecord);
      assert.throws(
        () => parseAndValidateRecordLineV1(falseLine),
        (err) => err.code === 'HASH_MISMATCH',
      );
    });
  });

  describe('Strict V1 Schema, Preimage and Canonical Parser Invariants', () => {
    test('Valid semantic record with reordered keys rejected as NON_CANONICAL_RECORD', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: '' },
      };
      candidate.integrity.recordHash = computeRecordHashV1(candidate);

      // Construct non-canonical JSON with inverted key ordering
      const nonCanonicalJson =
        '{"schemaVersion":1,"timestamp":"2026-09-20T18:00:00.000Z","eventId":"f47ac10b-58cc-4372-a567-0e02b2c3d479",' +
        `"actor":${canonicalJsonV1(candidate.actor)},"target":${canonicalJsonV1(candidate.target)},"invocation":${canonicalJsonV1(candidate.invocation)},` +
        `"policy":${canonicalJsonV1(candidate.policy)},"execution":${canonicalJsonV1(candidate.execution)},"integrity":${canonicalJsonV1(candidate.integrity)},"sequenceNumber":1}\n`;

      assert.throws(
        () => parseAndValidateRecordLineV1(nonCanonicalJson),
        (err) => err.code === 'NON_CANONICAL_RECORD',
      );
    });

    test('Valid record with extra insignificant spaces rejected as NON_CANONICAL_RECORD', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: '' },
      };
      candidate.integrity.recordHash = computeRecordHashV1(candidate);
      const canonicalLine = serializeRecordV1(candidate);
      const nonCanonicalWithSpaces = canonicalLine.replace('{"actor"', '{ "actor"');

      assert.throws(
        () => parseAndValidateRecordLineV1(nonCanonicalWithSpaces),
        (err) => err.code === 'NON_CANONICAL_RECORD',
      );
    });

    test('Unknown field in integrity object rejected with UNKNOWN_FIELD', () => {
      assert.throws(
        () =>
          validateIntegrityObjectV1({
            previousRecordHash: '0'.repeat(64),
            recordHash: '1'.repeat(64),
            unhashedExtra: 'attacker-controlled',
          }),
        (err) => err.code === 'UNKNOWN_FIELD',
      );
    });

    test('Regression: Unknown field in integrity cannot survive with old hash', () => {
      const candidate = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: {
          previousRecordHash: '0'.repeat(64),
          recordHash: '',
        },
      };
      const initialHash = computeRecordHashV1(candidate);
      candidate.integrity.recordHash = initialHash;

      // Tamper integrity with unhashedExtra
      const tamperedRecord = {
        ...candidate,
        integrity: {
          previousRecordHash: '0'.repeat(64),
          recordHash: initialHash,
          unhashedExtra: 'attacker-controlled',
        },
      };

      const tamperedLine = canonicalJsonV1(tamperedRecord) + '\n';
      assert.throws(
        () => parseAndValidateRecordLineV1(tamperedLine),
        (err) => err.code === 'UNKNOWN_FIELD',
      );
    });

    test('Wrong actor type or missing required actor fields rejected with INVALID_RECORD', () => {
      const badActorRecord = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        actor: 'not-an-object',
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badActorRecord),
        (err) => err.code === 'INVALID_RECORD',
      );

      const missingFieldActor = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        actor: { clientId: 'c1', clientType: 'admin', deviceId: 'd1' }, // missing sessionId
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(missingFieldActor),
        (err) => err.code === 'INVALID_RECORD',
      );
    });

    test('Unknown field in closed actor structure rejected with UNKNOWN_FIELD', () => {
      const extraActorField = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        actor: {
          clientId: 'c1',
          clientType: 'admin',
          deviceId: 'd1',
          sessionId: 's1',
          extraActorKey: 'invalid',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(extraActorField),
        (err) => err.code === 'UNKNOWN_FIELD',
      );
    });

    test('sequenceNumber not a safe positive integer or 0 rejected with INVALID_RECORD', () => {
      const seqZero = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 0,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(seqZero),
        (err) => err.code === 'INVALID_RECORD',
      );

      const seqString = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: '1',
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(seqString),
        (err) => err.code === 'INVALID_RECORD',
      );
    });

    test('Bad lifecycle operationId or phase rejected with INVALID_RECORD', () => {
      const badOpId = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        lifecycle: {
          operationId: 'not-a-uuid',
          phase: 'STARTED',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badOpId),
        (err) => err.code === 'INVALID_RECORD',
      );

      const badPhase = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        lifecycle: {
          operationId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          phase: 'UNKNOWN_PHASE',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badPhase),
        (err) => err.code === 'INVALID_RECORD',
      );

      const unknownKey = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        lifecycle: {
          operationId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          phase: 'STARTED',
          unknownField: 'bad',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(unknownKey),
        (err) => err.code === 'UNKNOWN_FIELD',
      );
    });

    test('Lifecycle operationId requires valid UUIDv4; valid UUIDv4 accepted', () => {
      const validOpId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
      assert.ok(UUID_V4_REGEX.test(validOpId));

      const validLifecycleRecord = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        lifecycle: {
          operationId: validOpId,
          phase: 'STARTED',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.doesNotThrow(() => validatePersistentRecordV1(validLifecycleRecord));
    });

    test('Syntactically valid non-v4 UUIDs (v1, v3, v5) rejected in lifecycle.operationId with INVALID_RECORD', () => {
      const nonV4Uuids = [
        { version: 'v1', id: 'f47ac10b-58cc-1372-a567-0e02b2c3d479' },
        { version: 'v3', id: 'f47ac10b-58cc-3372-a567-0e02b2c3d479' },
        { version: 'v5', id: 'f47ac10b-58cc-5372-a567-0e02b2c3d479' },
      ];

      for (const { version, id } of nonV4Uuids) {
        assert.ok(!UUID_V4_REGEX.test(id), `UUID${version} must not match UUID_V4_REGEX`);
        const candidate = {
          ...createSampleRecordCandidate(),
          schemaVersion: 1,
          sequenceNumber: 1,
          lifecycle: {
            operationId: id,
            phase: 'STARTED',
          },
          integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
        };
        assert.throws(
          () => validatePersistentRecordV1(candidate),
          (err) => err.code === 'INVALID_RECORD',
          `UUID${version} must be rejected with INVALID_RECORD`,
        );
      }
    });

    test('Generic eventId preserves v1..v5 UUID support while lifecycle.operationId requires v4', () => {
      const v1EventRecord = {
        ...createSampleRecordCandidate(),
        eventId: 'f47ac10b-58cc-1372-a567-0e02b2c3d479', // UUIDv1
        schemaVersion: 1,
        sequenceNumber: 1,
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.doesNotThrow(() => validatePersistentRecordV1(v1EventRecord));
    });

    test('Invalid execution status, duration, or non-string changedFiles rejected with INVALID_RECORD', () => {
      const badStatus = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        execution: {
          ...createSampleRecordCandidate().execution,
          status: 'INVALID_STATUS',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badStatus),
        (err) => err.code === 'INVALID_RECORD',
      );

      const badChangedFiles = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        execution: {
          ...createSampleRecordCandidate().execution,
          changedFiles: [123, 'valid.txt'],
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badChangedFiles),
        (err) => err.code === 'INVALID_RECORD',
      );
    });

    test('Invalid payloadHash rejected with INVALID_RECORD', () => {
      const badPayloadHash = {
        ...createSampleRecordCandidate(),
        schemaVersion: 1,
        sequenceNumber: 1,
        invocation: {
          ...createSampleRecordCandidate().invocation,
          payloadHash: 'short-hash',
        },
        integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
      };
      assert.throws(
        () => validatePersistentRecordV1(badPayloadHash),
        (err) => err.code === 'INVALID_RECORD',
      );
    });
  });

  describe('Storage Append Boundary, Pre-Write Validation & Failure Invariants', () => {
    test('Storage append rejects candidate with unknown top-level field before disk write', async () => {
      const auditDir = path.join(tempBaseDir, 'store-unknown-field');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      const candidateWithUnknown = {
        ...createSampleRecordCandidate(),
        unknownExtraField: 'malicious',
      };

      await assert.rejects(
        async () => {
          await storage.append(candidateWithUnknown);
        },
        (err) => err.code === 'UNKNOWN_FIELD',
      );

      assert.equal(
        storage.getCurrentSequence(),
        1,
        'cursor must not advance on rejected candidate',
      );
      assert.equal(
        storage.getState(),
        'ACTIVE',
        'storage remains ACTIVE after pre-write rejection',
      );

      // Segment file must remain completely empty (0 bytes)
      const segmentBytes = fs.readFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME));
      assert.equal(segmentBytes.length, 0, 'no bytes written to disk');

      // Subsequent valid append succeeds
      const validRec = await storage.append(createSampleRecordCandidate());
      assert.equal(validRec.sequenceNumber, 1);
      assert.equal(storage.getCurrentSequence(), 2);

      storage.close();
    });

    test('Storage append rejects candidate with unknown closed nested field before disk write', async () => {
      const auditDir = path.join(tempBaseDir, 'store-unknown-nested');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      const candidateWithBadActor = {
        ...createSampleRecordCandidate(),
        actor: {
          ...createSampleRecordCandidate().actor,
          nestedUnknownKey: 'invalid',
        },
      };

      await assert.rejects(
        async () => {
          await storage.append(candidateWithBadActor);
        },
        (err) => err.code === 'UNKNOWN_FIELD',
      );

      assert.equal(storage.getCurrentSequence(), 1);
      assert.equal(storage.getState(), 'ACTIVE');

      storage.close();
    });

    test('Invariant: Every successfully appended record produces an independently parseable canonical line', async () => {
      const auditDir = path.join(tempBaseDir, 'store-independent-parse');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      for (let i = 1; i <= 5; i++) {
        const appended = await storage.append({
          ...createSampleRecordCandidate(),
          invocation: {
            toolName: `tool_${i}`,
            parametersRedacted: { index: i },
            payloadHash: createHash('sha256').update(String(i)).digest('hex'),
          },
        });

        assert.equal(appended.sequenceNumber, i);
      }

      storage.close();

      const lines = fs
        .readFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME), 'utf8')
        .split('\n');
      assert.equal(lines.length, 6); // 5 records + empty trailing
      assert.equal(lines[5], '');

      for (let i = 0; i < 5; i++) {
        const lineWithNl = lines[i] + '\n';
        const parsed = parseAndValidateRecordLineV1(lineWithNl);
        assert.equal(parsed.record.sequenceNumber, i + 1);
        assert.equal(parsed.computedHash, parsed.record.integrity.recordHash);
      }
    });

    test('Deterministic injected fdatasync failure poisons writer to FAILED state and rejects subsequent appends', async () => {
      const auditDir = path.join(tempBaseDir, 'store-sync-failure');
      const storage = createTestPersistentAuditStorage(
        {
          directory: auditDir,
          createIfMissing: true,
          metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
        },
        { fdatasyncFault: true },
      );
      storage.initialize();

      await assert.rejects(async () => {
        await storage.append(createSampleRecordCandidate());
      }, /SIMULATED_SYNC_FAILURE/);

      assert.equal(
        storage.getCurrentSequence(),
        1,
        'cursor must remain unadvanced on sync failure',
      );
      assert.equal(storage.getState(), 'FAILED', 'storage state must transition to FAILED');

      // Subsequent appends must throw AUDIT_STORAGE_FAILED
      await assert.rejects(
        async () => {
          await storage.append(createSampleRecordCandidate());
        },
        (err) => err.code === 'AUDIT_STORAGE_FAILED',
      );

      storage.close();
    });
  });

  describe('Initialization Cleanup, Rollback & Recovery Invariants', () => {
    test('Initialization cleanup on malformed metadata: lock acquired then released, audit.lock absent afterward', () => {
      const auditDir = path.join(tempBaseDir, 'cleanup-malformed-meta');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      fs.writeFileSync(path.join(auditDir, METADATA_FILENAME), 'not valid json', { mode: 0o600 });

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'INVALID_METADATA',
      );

      assert.ok(
        !fs.existsSync(path.join(auditDir, 'audit.lock')),
        'audit.lock must be cleaned up after initialization failure',
      );
    });

    test('Initialization cleanup on active segment permission failure: lock acquired then released, audit.lock absent afterward', () => {
      const auditDir = path.join(tempBaseDir, 'cleanup-insecure-perms');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'DISABLED',
      });

      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      fs.writeFileSync(activePath, '', { mode: 0o644 });
      fs.chmodSync(activePath, 0o644);

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'INSECURE_PERMISSIONS',
      );

      assert.ok(
        !fs.existsSync(path.join(auditDir, 'audit.lock')),
        'audit.lock must be cleaned up after permission failure',
      );
    });

    test('Existing non-empty active segment throws AUDIT_RECOVERY_REQUIRED: file bytes unchanged, audit.lock removed', () => {
      const auditDir = path.join(tempBaseDir, 'cleanup-recovery-required');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'DISABLED',
      });

      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const priorContent = 'prior-audit-line-bytes\n';
      fs.writeFileSync(activePath, priorContent, { mode: 0o600 });

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'AUDIT_RECOVERY_REQUIRED',
      );

      const activeBytes = fs.readFileSync(activePath, 'utf8');
      assert.equal(activeBytes, priorContent, 'active segment must remain byte-for-byte unchanged');

      assert.ok(
        !fs.existsSync(path.join(auditDir, 'audit.lock')),
        'audit.lock must be cleaned up after AUDIT_RECOVERY_REQUIRED',
      );
    });

    test('Replacement race between initial probe and final open fails with AUDIT_RECOVERY_REQUIRED', () => {
      const auditDir = path.join(tempBaseDir, 'cleanup-replacement-race');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'DISABLED',
      });

      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const injectedBytes = 'injected-during-race\n';

      const storage = createTestPersistentAuditStorage(
        {
          directory: auditDir,
          metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
        },
        {
          beforeFinalOpen: () => {
            fs.writeFileSync(activePath, injectedBytes, { mode: 0o600 });
          },
        },
      );

      assert.throws(
        () => storage.initialize(),
        (err) => err.code === 'AUDIT_RECOVERY_REQUIRED',
      );

      const remainingBytes = fs.readFileSync(activePath, 'utf8');
      assert.equal(remainingBytes, injectedBytes, 'replacement bytes must remain unchanged');

      assert.ok(
        !fs.existsSync(path.join(auditDir, 'audit.lock')),
        'audit.lock must be cleaned up after replacement-race failure',
      );
    });
  });

  describe('Real RC-04 Approval Audit Compatibility & Invariants', () => {
    test('Representative RC-04 approval lifecycle records append and independently parse', async () => {
      const auditDir = path.join(tempBaseDir, 'store-approval-compat');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      const approvalCases = [
        {
          approval: {
            eventType: 'APPROVAL_REQUESTED',
            requestId: 'req-01',
            state: 'PENDING',
            source: 'MCP',
          },
        },
        {
          approval: {
            eventType: 'APPROVAL_GRANTED',
            requestId: 'req-01',
            state: 'APPROVED',
            source: 'LOCAL_OPERATOR',
            operatorReasonProvided: true,
          },
        },
        {
          approval: {
            eventType: 'APPROVAL_REJECTED',
            requestId: 'req-02',
            state: 'REJECTED',
            source: 'LOCAL_OPERATOR',
            reasonCode: 'PAYLOAD_BINDING_MISMATCH',
            operatorReasonProvided: true,
          },
        },
        {
          approval: {
            eventType: 'APPROVAL_EXPIRED',
            requestId: 'req-03',
            state: 'EXPIRED',
            source: 'SYSTEM',
          },
        },
        {
          approval: {
            eventType: 'APPROVAL_CONSUMED',
            requestId: 'req-01',
            state: 'CONSUMED',
            source: 'MCP',
          },
        },
        {
          approval: {
            eventType: 'APPROVAL_INVALIDATED',
            requestId: 'req-04',
            state: 'INVALIDATED',
            source: 'MCP',
            reasonCode: 'TOKEN_MISMATCH',
          },
        },
        {
          approval: {
            eventType: 'APPROVED_EXECUTION_SUCCEEDED',
            requestId: 'req-01',
          },
        },
        {
          approval: {
            eventType: 'APPROVED_EXECUTION_FAILED',
            requestId: 'req-05',
            reasonCode: 'ALREADY_CONSUMED',
          },
        },
      ];

      for (let i = 0; i < approvalCases.length; i++) {
        const candidate = {
          ...createSampleRecordCandidate(),
          approval: approvalCases[i].approval,
        };

        const appended = await storage.append(candidate);
        assert.equal(appended.sequenceNumber, i + 1);
      }

      storage.close();

      const lines = fs
        .readFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME), 'utf8')
        .split('\n');
      assert.equal(lines.length, approvalCases.length + 1);

      for (let i = 0; i < approvalCases.length; i++) {
        const lineWithNl = lines[i] + '\n';
        const parsed = parseAndValidateRecordLineV1(lineWithNl);
        assert.equal(parsed.record.sequenceNumber, i + 1);
        assert.deepEqual(parsed.record.approval, approvalCases[i].approval);
        assert.equal(parsed.computedHash, parsed.record.integrity.recordHash);
      }
    });

    test('Rejection of invalid approval-vocabulary aliases and arbitrary reason codes', () => {
      const badAliases = [
        { approval: { eventType: 'REQUESTED' } },
        { approval: { eventType: 'GRANTED' } },
        { approval: { state: 'DENIED' } },
        { approval: { state: 'TIMED_OUT' } },
        { approval: { state: 'CANCELLED' } },
        { approval: { reasonCode: 'ATTACKER_TEXT' } },
        { approval: { unknownApprovalKey: 'forbidden' } },
      ];

      for (const bad of badAliases) {
        const candidate = {
          ...createSampleRecordCandidate(),
          schemaVersion: 1,
          sequenceNumber: 1,
          ...bad,
          integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
        };
        assert.throws(
          () => validatePersistentRecordV1(candidate),
          (err) => err.code === 'INVALID_RECORD' || err.code === 'UNKNOWN_FIELD',
        );
      }
    });
  });

  describe('RC-05 Gateway Audit Identifier Compatibility & Shape Enforcement', () => {
    test('Representative RC-05 gateway lifecycle records append and independently parse', async () => {
      const auditDir = path.join(tempBaseDir, 'store-gateway-compat');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: 'a'.repeat(64) },
      });
      storage.initialize();

      const validGatewayRecord = {
        ...createSampleRecordCandidate(),
        gateway: {
          eventType: 'AUTH_SUCCEEDED',
          reason: 'SHUTDOWN',
          admissionLayer: 'B',
          mcpSessionId: 'a'.repeat(64),
          deviceId: 'b'.repeat(32),
          spkiPin: 'c'.repeat(64),
          enrollmentId: 'd'.repeat(32),
          clientId: 'valid-client-id',
          clientType: 'admin-dashboard',
          transportMode: 'remote',
        },
      };

      const appended = await storage.append(validGatewayRecord);
      assert.equal(appended.sequenceNumber, 1);
      assert.deepEqual(appended.gateway, validGatewayRecord.gateway);

      storage.close();

      const lines = fs
        .readFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME), 'utf8')
        .split('\n');
      const parsed = parseAndValidateRecordLineV1(lines[0] + '\n');
      assert.equal(parsed.record.sequenceNumber, 1);
      assert.deepEqual(parsed.record.gateway, validGatewayRecord.gateway);
      assert.equal(parsed.computedHash, parsed.record.integrity.recordHash);
    });

    test('Malformed gateway shapes and unknown fields rejected with INVALID_RECORD or UNKNOWN_FIELD', () => {
      const badGatewayCases = [
        { gateway: { eventType: 'AUTH_SUCCEEDED', mcpSessionId: 'a'.repeat(63) } }, // 63 hex
        { gateway: { eventType: 'AUTH_SUCCEEDED', mcpSessionId: 'g'.repeat(64) } }, // non-hex
        { gateway: { eventType: 'AUTH_SUCCEEDED', deviceId: 'b'.repeat(31) } }, // 31 hex
        { gateway: { eventType: 'AUTH_SUCCEEDED', spkiPin: 'c'.repeat(63) } }, // 63 hex
        { gateway: { eventType: 'AUTH_SUCCEEDED', enrollmentId: 'd'.repeat(31) } }, // 31 hex
        { gateway: { eventType: 'AUTH_SUCCEEDED', clientId: 'bad\x01client' } }, // control char
        { gateway: { eventType: 'AUTH_SUCCEEDED', clientId: 'x'.repeat(129) } }, // length 129
        { gateway: { eventType: 'AUTH_SUCCEEDED', clientType: 'bad\x00client' } }, // NUL char
        { gateway: { eventType: 'AUTH_SUCCEEDED', clientType: 'x'.repeat(129) } }, // length 129
        { gateway: { eventType: 'UNKNOWN_EVENT' } }, // unknown event
        { gateway: { eventType: 'AUTH_SUCCEEDED', reason: 'UNKNOWN_REASON' } }, // unknown reason
        { gateway: { eventType: 'AUTH_SUCCEEDED', unknownGatewayField: 'forbidden' } }, // unknown key
      ];

      for (const bad of badGatewayCases) {
        const candidate = {
          ...createSampleRecordCandidate(),
          schemaVersion: 1,
          sequenceNumber: 1,
          ...bad,
          integrity: { previousRecordHash: '0'.repeat(64), recordHash: 'a'.repeat(64) },
        };
        assert.throws(
          () => validatePersistentRecordV1(candidate),
          (err) => err.code === 'INVALID_RECORD' || err.code === 'UNKNOWN_FIELD',
        );
      }
    });
  });

  describe('Tier-3 Metadata Configuration Normalization & Consistency', () => {
    test('Caller omitting anchorMode against existing ENABLED store throws STORE_RECONFIGURATION_FORBIDDEN', () => {
      const auditDir = path.join(tempBaseDir, 'meta-omission-check');
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });

      createStoreMetadataFile(auditDir, {
        version: 1,
        storeId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        createdAt: '2026-09-20T18:00:00.000Z',
        checkpointPublicKeyFingerprint: 'a'.repeat(64),
        anchorMode: 'ENABLED',
        anchorReceiptPublicKeyFingerprint: 'b'.repeat(64),
      });

      const loaded = loadStoreMetadataFile(auditDir);
      // Caller passes only checkpoint fingerprint (omitting anchorMode)
      assert.throws(
        () =>
          validateStoreMetadataConsistency(loaded, {
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
          }),
        (err) => err.code === 'STORE_RECONFIGURATION_FORBIDDEN',
      );
    });

    test('Partial metadata configurations rejected by normalizeStoreMetadataConfig with INVALID_METADATA_CONFIG', () => {
      // anchorMode omitted + anchorReceiptPublicKeyFingerprint present
      assert.throws(
        () =>
          normalizeStoreMetadataConfig({
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
            anchorReceiptPublicKeyFingerprint: 'b'.repeat(64),
          }),
        (err) => err.code === 'INVALID_METADATA_CONFIG',
      );

      // anchorMode DISABLED + anchorReceiptPublicKeyFingerprint present
      assert.throws(
        () =>
          normalizeStoreMetadataConfig({
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
            anchorMode: 'DISABLED',
            anchorReceiptPublicKeyFingerprint: 'b'.repeat(64),
          }),
        (err) => err.code === 'INVALID_METADATA_CONFIG',
      );

      // anchorMode ENABLED + anchorReceiptPublicKeyFingerprint absent
      assert.throws(
        () =>
          normalizeStoreMetadataConfig({
            checkpointPublicKeyFingerprint: 'a'.repeat(64),
            anchorMode: 'ENABLED',
          }),
        (err) => err.code === 'INVALID_METADATA_CONFIG',
      );
    });
  });

  describe('Public API Surface & Storage Capability Boundary Invariants', () => {
    test('Root public API does not expose storage test facilities or internal tokens', async () => {
      const auditPublic = await import('../packages/audit/dist/index.js');
      assert.strictEqual(auditPublic.StorageTestFaults, undefined);
      assert.strictEqual(auditPublic.StorageTestHooks, undefined);
      assert.strictEqual(auditPublic.createTestPersistentAuditStorage, undefined);
      assert.strictEqual(auditPublic.STORAGE_TEST_TOKEN, undefined);
      assert.strictEqual(auditPublic.RECOVERY_HANDOFF_TOKEN, undefined);
      assert.strictEqual(auditPublic.recoverPersistentAuditStorageForTest, undefined);
      assert.strictEqual(auditPublic.executeAuditRecoveryInternal, undefined);
    });

    test('Root index.d.ts declaration does not expose internal test interfaces or tokens', () => {
      const dtsPath = path.resolve('packages/audit/dist/index.d.ts');
      const dtsContent = fs.readFileSync(dtsPath, 'utf8');
      assert.strictEqual(dtsContent.includes('StorageTestFaults'), false);
      assert.strictEqual(dtsContent.includes('StorageTestHooks'), false);
      assert.strictEqual(dtsContent.includes('createTestPersistentAuditStorage'), false);
      assert.strictEqual(dtsContent.includes('STORAGE_TEST_TOKEN'), false);
      assert.strictEqual(dtsContent.includes('RECOVERY_HANDOFF_TOKEN'), false);
    });

    test('PersistentAuditStorage constructor rejects unexpected test hook arguments without internal capability', () => {
      const config = {
        directory: path.join(tempBaseDir, 'pub-constructor-test'),
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: '1'.repeat(64),
          anchorMode: 'DISABLED',
        },
      };

      // Passing unexpected extra arguments without the unforgeable internal capability token is rejected
      assert.throws(
        () => {
          new PersistentAuditStorage(config, {
            writeFault: 'error',
            beforeFinalOpen: () => {},
          });
        },
        (err) =>
          err.code === 'AUDIT_STORAGE_INVALID_CONFIG' &&
          err.message.includes('Unexpected constructor arguments'),
      );

      // Passing a foreign forged symbol is also rejected
      assert.throws(
        () => {
          new PersistentAuditStorage(config, Symbol('STORAGE_TEST_TOKEN'), {
            testFaults: { writeFault: 'error' },
          });
        },
        (err) =>
          err.code === 'AUDIT_STORAGE_INVALID_CONFIG' &&
          err.message.includes('Unexpected constructor arguments'),
      );

      // Normal single-argument production constructor succeeds cleanly
      const storage = new PersistentAuditStorage(config);
      assert.strictEqual(storage.getState(), 'UNINITIALIZED');
    });

    test('Package deep-import subpath protection for internal modules', () => {
      const pkgUrl = new URL('../packages/audit/package.json', import.meta.url);
      const subpaths = [
        '@cesspace-arc/audit/internal/storage-testing',
        '@cesspace-arc/audit/internal/recovery-testing',
        '@cesspace-arc/audit/internal/storage-capability',
        '@cesspace-arc/audit/internal/recovery-capability',
        '@cesspace-arc/audit/storage',
        '@cesspace-arc/audit/recovery',
      ];

      for (const subpath of subpaths) {
        assert.throws(
          () => {
            import.meta.resolve(subpath, pkgUrl);
          },
          (err) => err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
        );
      }
    });
  });
});
