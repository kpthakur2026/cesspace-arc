/**
 * CesSpace ARC — RC-06 Task 3: Segment Rotation, Streaming Compression & Storage Budget
 *
 * Test suite verifying:
 * - Frozen rotation constants and the canonical rotated-segment filename schema
 * - The staged rotation-sealing contract (RotationSealBoundary / RotationCheckpointSealer)
 * - Automatic rotation on the 10 MiB size trigger and the 24 hour interval trigger
 * - Empty-segment rotation rules and the coincidence rule
 * - Streaming gzip with post-compression verification and raw-byte equivalence
 * - Source-removal ordering and compression-failure safety
 * - Full retained primary-history verification across segment boundaries
 * - The 256-record recent-record cache and its reconstruction from durable bytes
 * - Storage budget accounting, archive-count bounds and non-deletion retention
 * - Single-writer preservation across rotation (one lock, one descriptor)
 * - All frozen Task-3 negative security controls RC06-NEG-48..63
 *
 * Control namespace: Task 3 owns exactly the RC06-NEG range 48..63 and no
 * more. The additive correction regressions below carry the RC06-T3-REG-nn
 * namespace precisely because it is NOT part of the frozen 108-control
 * architecture numbering — they assert behavior, they are not frozen security
 * controls, and they must never be counted as controls.
 *
 * The next block of the RC06-NEG namespace, 64..83, is reserved to Task 4
 * (Tier 2 Ed25519 checkpoint artifacts and key authority). No Task-3 test may
 * claim an ID from it; this file deliberately contains none.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { gzipSync, gunzipSync } from 'node:zlib';
import { createRequire } from 'node:module';

import * as auditPackage from '../packages/audit/dist/index.js';

import {
  PersistentAuditStorage,
  ACTIVE_SEGMENT_FILENAME,
  LOCK_FILENAME,
  METADATA_FILENAME,
  computeRecordHashV1,
  serializeRecordV1,
  verifyRetainedPrimaryHistory,
  listArchiveInventory,
  listLogicalArchiveInventory,
  countLogicalArchives,
  scanAuditStorePhysicalBytes,
  assertAuditStorageCapacity,
  assertArchiveCapacityAvailable,
  recoverPersistentAuditStorage,
  validateRotationSealBoundary,
  parseRotatedSegmentFilename,
  formatRotatedSegmentFilename,
  formatRotationTimestamp,
  isValidRotatedSegmentFilename,
  RotatingAuditStore,
  SEGMENT_SIZE_THRESHOLD,
  ROTATION_INTERVAL,
  ROTATION_INTERVAL_MS,
  MAX_ARCHIVE_SEGMENTS,
  TOTAL_AUDIT_BUDGET_BYTES,
  RECENT_RECORDS_CACHE_LIMIT,
  MAX_TORN_TAIL_BYTES,
} from '../packages/audit/dist/index.js';

import { createTestPersistentAuditStorage } from '../packages/audit/dist/internal/storage-testing.js';
import {
  SyntheticRotationCheckpointSealer,
  createTestRotatingAuditStore,
  TestClock,
  assertNoProductionSealerAvailable,
} from '../packages/audit/dist/internal/rotation-testing.js';

const GENESIS = '0'.repeat(64);
const FIXED_CLOCK_START = Date.parse('2026-09-21T00:00:00.000Z');

function createSampleRecordCandidate(overrides = {}) {
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
    ...overrides,
  };
}

/** A deliberately large but individually valid record, for size-trigger tests. */
function largeRecordCandidate() {
  return createSampleRecordCandidate({
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { blob: 'x'.repeat(60_000) },
      payloadHash: 'd'.repeat(64),
    },
  });
}

/** Builds a canonical, chain-valid record line with a caller-chosen predecessor. */
function buildRecordLine({ sequenceNumber, previousRecordHash, recordOverrides = {} }) {
  const record = {
    ...createSampleRecordCandidate(recordOverrides),
    schemaVersion: 1,
    sequenceNumber,
    integrity: { previousRecordHash, recordHash: GENESIS },
  };
  const recordHash = computeRecordHashV1(record);
  record.integrity.recordHash = recordHash;
  return { line: serializeRecordV1(record), record, recordHash };
}

function writeSparseFile(filePath, size) {
  const fd = fs.openSync(filePath, 'w', 0o600);
  try {
    fs.ftruncateSync(fd, size);
  } finally {
    fs.closeSync(fd);
  }
}

function assertThrowsWithCode(fn, codes) {
  const expected = Array.isArray(codes) ? codes : [codes];
  assert.throws(fn, (err) => {
    assert.ok(
      expected.includes(err.code),
      `expected error code one of [${expected.join(', ')}], got ${err.code}: ${err.message}`,
    );
    return true;
  });
}

async function assertRejectsWithCode(promise, codes) {
  const expected = Array.isArray(codes) ? codes : [codes];
  await assert.rejects(promise, (err) => {
    assert.ok(
      expected.includes(err.code),
      `expected error code one of [${expected.join(', ')}], got ${err.code}: ${err.message}`,
    );
    return true;
  });
}

describe('CesSpace ARC — RC-06 Task 3: Segment Rotation, Streaming Compression & Storage Budget', () => {
  let tempBaseDir;

  before(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task3-'));
  });

  after(() => {
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  /** Creates an initialized single-writer storage plus a rotation coordinator. */
  function createRotatingStore(name, { sealer, clock, hooks } = {}) {
    const auditDir = path.join(tempBaseDir, name);
    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: '1'.repeat(64),
        anchorMode: 'DISABLED',
      },
    });
    storage.initialize();

    const activeSealer = sealer ?? new SyntheticRotationCheckpointSealer();
    const activeClock = clock ?? new TestClock(FIXED_CLOCK_START);
    const store = createTestRotatingAuditStore(
      storage,
      { sealer: activeSealer },
      { clockMs: () => activeClock.now(), ...hooks },
    );

    return { auditDir, storage, store, sealer: activeSealer, clock: activeClock };
  }

  /* ==================================================================== *
   * Frozen constants and filename schema
   * ==================================================================== */

  describe('Frozen Constants and Canonical Filename Schema', () => {
    test('Frozen RC-06 rotation constants match the architecture exactly', () => {
      assert.equal(SEGMENT_SIZE_THRESHOLD, 10_485_760, '10 MiB hard size trigger');
      assert.equal(ROTATION_INTERVAL, 86_400, '24h operational interval');
      assert.equal(ROTATION_INTERVAL_MS, 86_400_000);
      assert.equal(MAX_ARCHIVE_SEGMENTS, 100, 'archive segment ceiling');
      assert.equal(TOTAL_AUDIT_BUDGET_BYTES, 1_073_741_824, '1 GiB total budget');
      assert.equal(RECENT_RECORDS_CACHE_LIMIT, 256, 'recent-record cache limit');
    });

    test('Rotation timestamp formatting is canonical UTC with no sub-second field', () => {
      const stamp = formatRotationTimestamp(new Date(Date.parse('2026-03-04T05:06:07.891Z')));
      assert.equal(stamp, '20260304T050607Z');
      assert.ok(!stamp.includes(':'), 'timestamp must never contain a colon');
      assert.ok(!stamp.includes('.'), 'timestamp must never contain a sub-second field');

      // Local-time rendering would differ; the canonical form is always UTC.
      const late = formatRotationTimestamp(new Date(Date.parse('2026-12-31T23:59:59.999Z')));
      assert.equal(late, '20261231T235959Z');
    });

    test('Round-trips canonical rotated-segment filenames for both suffixes', () => {
      for (const compressed of [false, true]) {
        const filename = formatRotatedSegmentFilename({
          rotationTimestamp: '20260921T000000Z',
          sequenceStart: 1,
          sequenceEnd: 500,
          compressed,
        });
        assert.equal(
          filename,
          compressed
            ? 'audit-20260921T000000Z-seq1-seq500.jsonl.gz'
            : 'audit-20260921T000000Z-seq1-seq500.jsonl',
        );

        const parsed = parseRotatedSegmentFilename(filename);
        assert.ok(parsed !== null, 'canonical filename must parse');
        assert.equal(parsed.rotationTimestamp, '20260921T000000Z');
        assert.equal(parsed.sequenceStart, 1);
        assert.equal(parsed.sequenceEnd, 500);
        assert.equal(parsed.compressed, compressed);
        assert.equal(isValidRotatedSegmentFilename(filename), true);
      }
    });

    test('Rejects every non-canonical filename spelling', () => {
      const rejected = [
        'audit-20260921T000000Z-seq1-seq500.jsonl.bak',
        'audit-20260921T000000Z-seq1-seq500.gz',
        'audit-20260921T000000Z-seq1-seq500',
        'audit-20260921T000000-seq1-seq500.jsonl',
        'audit-20260921T000000Z-seq1-seq500.jsonl.gz.gz',
        'audit_20260921T000000Z-seq1-seq500.jsonl',
        'audit-20260921T000000Z-seq1.jsonl',
        'audit-20260921T000000Z-seq0-seq5.jsonl',
        'audit-20260921T000000Z-seq5-seq1.jsonl',
        'audit-20260921T000000Z-seq007-seq9.jsonl',
        'audit-20260921T000000Z-seq01-seq9.jsonl',
        'audit-20261321T000000Z-seq1-seq5.jsonl',
        'audit-20260230T000000Z-seq1-seq5.jsonl',
        'audit-20260921T240000Z-seq1-seq5.jsonl',
        'audit-20260921T006000Z-seq1-seq5.jsonl',
        'audit-20260921T000060Z-seq1-seq5.jsonl',
        'audit-active.jsonl',
        'audit-store.json',
        'audit.lock',
        'rotated-audit-20260921T000000Z-seq1-seq5.jsonl',
        '',
      ];

      for (const filename of rejected) {
        assert.equal(
          parseRotatedSegmentFilename(filename),
          null,
          `must reject non-canonical name: ${filename}`,
        );
        assert.equal(isValidRotatedSegmentFilename(filename), false);
      }
    });

    test('Accepts a leap day and rejects a non-leap-year February 29', () => {
      assert.ok(parseRotatedSegmentFilename('audit-20240229T000000Z-seq1-seq5.jsonl') !== null);
      assert.equal(parseRotatedSegmentFilename('audit-20260229T000000Z-seq1-seq5.jsonl'), null);
    });

    test('Sequence range, not the timestamp, defines ordering and identity', () => {
      const earlier = parseRotatedSegmentFilename('audit-20270101T000000Z-seq1-seq10.jsonl');
      const later = parseRotatedSegmentFilename('audit-20200101T000000Z-seq11-seq20.jsonl');
      assert.ok(earlier !== null && later !== null);
      assert.ok(earlier.sequenceEnd < later.sequenceStart, 'ordering follows the sequence range');
    });
  });

  /* ==================================================================== *
   * Sealing boundary contract
   * ==================================================================== */

  describe('Staged Rotation-Sealing Contract', () => {
    test('Validates well-formed sealing boundaries', () => {
      assert.doesNotThrow(() =>
        validateRotationSealBoundary({
          sequenceStart: 1,
          sequenceEnd: 1,
          terminalRecordHash: 'a'.repeat(64),
        }),
      );
      assert.doesNotThrow(() =>
        validateRotationSealBoundary({
          sequenceStart: 1,
          sequenceEnd: 500,
          terminalRecordHash: '0123456789abcdef'.repeat(4),
        }),
      );
    });

    test('Rejects malformed sealing boundaries before any seal is attempted', () => {
      const bad = [
        { sequenceStart: 0, sequenceEnd: 1, terminalRecordHash: 'a'.repeat(64) },
        { sequenceStart: -1, sequenceEnd: 1, terminalRecordHash: 'a'.repeat(64) },
        { sequenceStart: 1.5, sequenceEnd: 2, terminalRecordHash: 'a'.repeat(64) },
        { sequenceStart: 5, sequenceEnd: 1, terminalRecordHash: 'a'.repeat(64) },
        { sequenceStart: 1, sequenceEnd: 0, terminalRecordHash: 'a'.repeat(64) },
        { sequenceStart: 1, sequenceEnd: 1, terminalRecordHash: 'A'.repeat(64) },
        { sequenceStart: 1, sequenceEnd: 1, terminalRecordHash: 'a'.repeat(63) },
        { sequenceStart: 1, sequenceEnd: 1, terminalRecordHash: 'a'.repeat(65) },
        { sequenceStart: 1, sequenceEnd: 1, terminalRecordHash: '' },
        {
          sequenceStart: Number.MAX_SAFE_INTEGER + 2,
          sequenceEnd: 1,
          terminalRecordHash: 'a'.repeat(64),
        },
        null,
      ];

      for (const boundary of bad) {
        assertThrowsWithCode(
          () => validateRotationSealBoundary(boundary),
          'AUDIT_ROTATION_INVALID_BOUNDARY',
        );
      }
    });

    test('A store cannot be constructed without a sealing authority', () => {
      const { storage } = createRotatingStore('sealer-required');
      assertThrowsWithCode(
        () => new RotatingAuditStore(storage, {}),
        'AUDIT_ROTATION_INVALID_CONFIG',
      );
      assertThrowsWithCode(
        () => new RotatingAuditStore(storage, null),
        'AUDIT_ROTATION_INVALID_CONFIG',
      );
      assertThrowsWithCode(
        () => new RotatingAuditStore(storage, { sealer: {} }),
        'AUDIT_ROTATION_INVALID_CONFIG',
      );
      assertThrowsWithCode(
        () => new RotatingAuditStore(storage, { sealer: { sealRotation: 'not-a-function' } }),
        'AUDIT_ROTATION_INVALID_CONFIG',
      );
    });

    test('No production sealer exists in Task 3', () => {
      assertThrowsWithCode(
        () => assertNoProductionSealerAvailable(),
        'AUDIT_ROTATION_SEALER_UNAVAILABLE',
      );

      const exports = Object.keys(auditPackage);
      for (const forbidden of [
        'SyntheticRotationCheckpointSealer',
        'createTestRotatingAuditStore',
        'TestClock',
        'assertNoProductionSealerAvailable',
        'ROTATION_CAPABILITY_TOKEN',
      ]) {
        assert.ok(!exports.includes(forbidden), `${forbidden} must not be a package export`);
      }
    });

    test('Internal rotation modules are not resolvable through the package specifier', () => {
      const auditRequire = createRequire(path.resolve('packages/audit/package.json'));
      assert.strictEqual(
        auditRequire.resolve('@cesspace-arc/audit'),
        path.resolve('packages/audit/dist/index.js'),
      );

      for (const subpath of [
        '@cesspace-arc/audit/internal/rotation-testing',
        '@cesspace-arc/audit/internal/rotation-capability',
        '@cesspace-arc/audit/rotation',
        '@cesspace-arc/audit/rotation-filename',
      ]) {
        assert.throws(
          () => auditRequire.resolve(subpath),
          (err) => err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
        );
      }
    });

    test('Do not expose cursor setters or lock/descriptor replacement APIs', () => {
      const { store, storage } = createRotatingStore('no-cursor-setters');

      for (const forbidden of [
        'setCurrentSequence',
        'setLastRecordHash',
        'setActiveFd',
        'replaceLock',
        'forceRotateWithoutSeal',
        'clear',
        'purge',
        'reset',
        'prune',
        'vacuum',
        'wrap',
        'deleteOldest',
      ]) {
        assert.equal(
          typeof store[forbidden],
          'undefined',
          `RotatingAuditStore.${forbidden} must not exist`,
        );
        assert.equal(
          typeof storage[forbidden],
          'undefined',
          `PersistentAuditStorage.${forbidden} must not exist`,
        );
      }
    });
  });

  /* ==================================================================== *
   * Positive flows
   * ==================================================================== */

  describe('Positive Flows: Rotation, Compression & Full-History Verification', () => {
    test('Manual rotation seals the boundary, compresses, verifies and removes the source', async () => {
      const { auditDir, store, sealer } = createRotatingStore('manual-rotation', {
        clock: new TestClock(Date.parse('2026-09-21T00:00:00.000Z')),
      });

      for (let i = 0; i < 5; i++) {
        await store.append(createSampleRecordCandidate());
      }

      const terminalHash = store.getStorage().getLastRecordHash();
      const result = await store.rotateNow('INTERNAL_MANUAL');

      assert.deepEqual(result.boundary, {
        sequenceStart: 1,
        sequenceEnd: 5,
        terminalRecordHash: terminalHash,
      });
      assert.equal(result.reason, 'INTERNAL_MANUAL');
      assert.equal(result.archiveFilename, 'audit-20260921T000000Z-seq1-seq5.jsonl.gz');
      assert.equal(result.sourceRemoved, true);
      assert.equal(result.archiveCount, 1);

      // Exactly one seal was consumed, and it carried the sealed boundary.
      assert.equal(sealer.sealCount, 1);
      assert.deepEqual(sealer.lastBoundary, result.boundary);

      // The source is gone and only the compressed representation remains.
      assert.ok(fs.existsSync(result.archivePath), 'compressed archive must exist');
      assert.ok(
        !fs.existsSync(path.join(auditDir, 'audit-20260921T000000Z-seq1-seq5.jsonl')),
        'uncompressed source must be removed after verification',
      );

      const entries = fs.readdirSync(auditDir).sort();
      assert.deepEqual(
        entries,
        [
          'audit-20260921T000000Z-seq1-seq5.jsonl.gz',
          ACTIVE_SEGMENT_FILENAME,
          METADATA_FILENAME,
          LOCK_FILENAME,
        ].sort(),
      );

      const archiveStats = fs.statSync(result.archivePath);
      assert.equal(archiveStats.mode & 0o777, 0o600, 'compressed archive must be 0600');
      assert.equal(archiveStats.nlink, 1, 'compressed archive must have exactly one link');
    });

    test('The chain continues unbroken across the rotation boundary', async () => {
      const { auditDir, storage, store } = createRotatingStore('chain-continuity');

      const before = [];
      for (let i = 0; i < 3; i++) before.push(await store.append(createSampleRecordCandidate()));

      const cursorSequence = storage.getCurrentSequence();
      const cursorHash = storage.getLastRecordHash();

      await store.rotateNow('INTERNAL_MANUAL');

      // Cursors are untouched by rotation: no reset, no re-derivation.
      assert.equal(storage.getCurrentSequence(), cursorSequence, 'sequence cursor preserved');
      assert.equal(storage.getLastRecordHash(), cursorHash, 'hash cursor preserved');

      const after = [];
      for (let i = 0; i < 3; i++) after.push(await store.append(createSampleRecordCandidate()));

      assert.equal(after[0].sequenceNumber, 4);
      assert.equal(after[0].integrity.previousRecordHash, before[2].integrity.recordHash);

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.recordCount, 6);
      assert.equal(history.terminalSequence, 6);
      assert.equal(history.nextSequence, 7);
      assert.equal(history.logicalArchiveCount, 1);
    });

    test('Automatic rotation triggers on the 10 MiB hard size limit', async () => {
      const { auditDir, store, sealer } = createRotatingStore('size-trigger');

      let appended = 0;
      while (store.getLastRotation() === null && appended < 400) {
        await store.append(largeRecordCandidate());
        appended++;
      }

      const rotation = store.getLastRotation();
      assert.ok(rotation !== null, 'the size trigger must fire');
      assert.equal(rotation.reason, 'SIZE_THRESHOLD');
      assert.equal(rotation.boundary.sequenceStart, 1);
      assert.equal(rotation.boundary.sequenceEnd, appended);
      assert.ok(rotation.sourceByteLength >= SEGMENT_SIZE_THRESHOLD);
      assert.equal(sealer.sealCount, 1, 'exactly one checkpoint per rotation');

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.recordCount, appended);
      assert.equal(history.terminalSequence, appended);
    });

    test('Automatic rotation triggers on the 24 hour operational interval', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { auditDir, store, sealer } = createRotatingStore('interval-trigger', { clock });

      for (let i = 0; i < 3; i++) await store.append(createSampleRecordCandidate());
      assert.equal(store.listArchives().length, 0);

      clock.advanceMs(ROTATION_INTERVAL_MS);

      const fourth = await store.append(createSampleRecordCandidate());
      assert.equal(fourth.sequenceNumber, 4, 'the triggering record is still appended');

      const rotation = store.getLastRotation();
      assert.ok(rotation !== null, 'the interval trigger must fire');
      assert.equal(rotation.reason, 'ROTATION_INTERVAL');
      assert.deepEqual(rotation.boundary.sequenceStart, 1);
      assert.deepEqual(rotation.boundary.sequenceEnd, 3);
      assert.equal(sealer.sealCount, 1);

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.recordCount, 4);
      assert.equal(history.logicalArchiveCount, 1);
    });

    test('Interval rotation fires at 24h and not at 24h minus one millisecond', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { store, sealer } = createRotatingStore('interval-boundary', { clock });

      await store.append(createSampleRecordCandidate());
      clock.advanceMs(ROTATION_INTERVAL_MS - 1);
      await store.append(createSampleRecordCandidate());
      assert.equal(sealer.sealCount, 0, 'must not rotate before the interval elapses');

      clock.advanceMs(1);
      await store.append(createSampleRecordCandidate());
      assert.equal(sealer.sealCount, 1, 'must rotate once the interval has fully elapsed');
    });

    test('An empty segment is never sealed or archived; the interval clock restarts', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { store, sealer } = createRotatingStore('empty-segment', { clock });

      // Well past the interval, but there is nothing to seal.
      clock.advanceMs(ROTATION_INTERVAL_MS * 5);
      const record = await store.append(createSampleRecordCandidate());

      assert.equal(record.sequenceNumber, 1);
      assert.equal(sealer.sealCount, 0, 'an empty segment must never consume a checkpoint');
      assert.equal(store.listArchives().length, 0, 'an empty segment must never be archived');
      assert.equal(store.getLastRotation(), null);

      // The clock restarted, so a further append shortly afterwards does not rotate.
      clock.advanceMs(1000);
      await store.append(createSampleRecordCandidate());
      assert.equal(sealer.sealCount, 0);

      // ...and a full interval after the restart does.
      clock.advanceMs(ROTATION_INTERVAL_MS);
      await store.append(createSampleRecordCandidate());
      assert.equal(sealer.sealCount, 1, 'exactly one checkpoint for the restarted segment');
    });

    test('An append that arms both triggers at once yields exactly one rotation and one seal', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { store, sealer } = createRotatingStore('coincidence', { clock });

      // Arm the size trigger: grow the segment until the hard limit rotates it.
      let appended = 0;
      while (store.getLastRotation() === null && appended < 400) {
        await store.append(largeRecordCandidate());
        appended++;
      }
      assert.equal(sealer.sealCount, 1, 'the size rotation consumed exactly one checkpoint');

      // Put a record in the fresh segment, then arm the interval trigger too.
      await store.append(largeRecordCandidate());
      clock.advanceMs(ROTATION_INTERVAL_MS);

      const sealsBefore = sealer.sealCount;
      const archivesBefore = store.listArchives().length;

      // This append is evaluated against both triggers: the pre-append interval
      // check and the post-append size check. Exactly one rotation may result.
      await store.append(largeRecordCandidate());

      assert.equal(
        sealer.sealCount,
        sealsBefore + 1,
        'a coincidence must consume exactly one checkpoint',
      );
      assert.equal(
        store.listArchives().length,
        archivesBefore + 1,
        'a coincidence must produce exactly one rotated segment',
      );
      assert.equal(store.getLastRotation().reason, 'ROTATION_INTERVAL');
    });

    test('Repeated rotations produce a contiguous, non-overlapping archive sequence', async () => {
      const { auditDir, store } = createRotatingStore('repeated-rotation');

      for (let cycle = 0; cycle < 4; cycle++) {
        for (let i = 0; i < 3; i++) await store.append(createSampleRecordCandidate());
        await store.rotateNow('INTERNAL_MANUAL');
      }

      const archives = listArchiveInventory(auditDir, process.getuid());
      assert.equal(archives.length, 4);

      let expectedStart = 1;
      for (const archive of archives) {
        assert.equal(archive.parsed.sequenceStart, expectedStart, 'ranges must be contiguous');
        assert.equal(archive.parsed.compressed, true, 'archives are stored compressed');
        assert.equal(archive.physicalByteLength, fs.statSync(archive.filePath).size);
        expectedStart = archive.parsed.sequenceEnd + 1;
      }
      assert.equal(expectedStart, 13);

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.recordCount, 12);
      assert.equal(history.logicalArchiveCount, 4);
    });

    test('Recent-record cache holds at most 256 records and is rebuildable from disk', async () => {
      const { store } = createRotatingStore('recent-cache');

      const total = RECENT_RECORDS_CACHE_LIMIT + 44;
      for (let i = 0; i < total; i++) await store.append(createSampleRecordCandidate());

      const cached = store.getRecentRecords();
      assert.equal(cached.length, RECENT_RECORDS_CACHE_LIMIT);
      assert.equal(cached[0].sequenceNumber, total - RECENT_RECORDS_CACHE_LIMIT + 1);
      assert.equal(cached[cached.length - 1].sequenceNumber, total);

      const rebuilt = await store.verifyAndRebuildRecentRecords();
      assert.equal(rebuilt.recordCount, total);
      assert.equal(rebuilt.recentRecords.length, RECENT_RECORDS_CACHE_LIMIT);

      const afterRebuild = store.getRecentRecords();
      assert.deepEqual(
        afterRebuild.map((r) => r.sequenceNumber),
        rebuilt.recentRecords.map((r) => r.sequenceNumber),
      );
    });

    test('Returned recent records are defensive copies, not live state', async () => {
      const { store } = createRotatingStore('recent-cache-copies');
      await store.append(createSampleRecordCandidate());

      const first = store.getRecentRecords();
      first[0].sequenceNumber = 999_999;
      first.push({ tampered: true });

      const second = store.getRecentRecords();
      assert.equal(second.length, 1);
      assert.equal(second[0].sequenceNumber, 1, 'cache must be immune to caller mutation');
    });

    test('Storage budget accounting uses physical bytes of every retained artifact', async () => {
      const { auditDir, store } = createRotatingStore('budget-accounting');
      for (let i = 0; i < 3; i++) await store.append(createSampleRecordCandidate());
      await store.rotateNow('INTERNAL_MANUAL');

      const expected = fs
        .readdirSync(auditDir)
        .map((name) => fs.statSync(path.join(auditDir, name)).size)
        .reduce((a, b) => a + b, 0);

      assert.equal(scanAuditStorePhysicalBytes(auditDir, process.getuid()), expected);
      assert.equal(assertAuditStorageCapacity(auditDir, process.getuid(), 0), expected);
    });

    test('Full-history verification reports dangling operations spanning segments', async () => {
      const { auditDir, store } = createRotatingStore('dangling-operations');

      const opId = '11111111-2222-4333-8444-555555555555';
      await store.append(
        createSampleRecordCandidate({ lifecycle: { operationId: opId, phase: 'STARTED' } }),
      );
      await store.append(createSampleRecordCandidate());
      await store.rotateNow('INTERNAL_MANUAL');
      await store.append(createSampleRecordCandidate());

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.danglingOperations.length, 1);
      assert.equal(history.danglingOperations[0].operationId, opId);
      assert.equal(history.danglingOperations[0].startedSequenceNumber, 1);

      // Closing the operation in the active segment clears the dangling evidence.
      await store.append(
        createSampleRecordCandidate({ lifecycle: { operationId: opId, phase: 'COMPLETED' } }),
      );
      const settled = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(settled.danglingOperations.length, 0);
    });

    test('Rejects a lifecycle violation that spans a segment boundary', async () => {
      const { auditDir, store } = createRotatingStore('lifecycle-across-segments');
      const opId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

      await store.append(
        createSampleRecordCandidate({ lifecycle: { operationId: opId, phase: 'STARTED' } }),
      );
      await store.rotateNow('INTERNAL_MANUAL');
      await store.append(
        createSampleRecordCandidate({ lifecycle: { operationId: opId, phase: 'COMPLETED' } }),
      );
      await store.append(
        createSampleRecordCandidate({ lifecycle: { operationId: opId, phase: 'COMPLETED' } }),
      );

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_LIFECYCLE_CORRUPTION',
      );
    });

    test('Rotation preserves the single writer: one lock and one active descriptor', async () => {
      const { auditDir, storage, store } = createRotatingStore('single-writer');

      for (let i = 0; i < 3; i++) await store.append(createSampleRecordCandidate());
      assert.ok(fs.existsSync(path.join(auditDir, LOCK_FILENAME)));

      await store.rotateNow('INTERNAL_MANUAL');

      // The lock was neither released nor reacquired.
      assert.ok(fs.existsSync(path.join(auditDir, LOCK_FILENAME)), 'lock retained across rotation');
      assert.equal(storage.getState(), 'ACTIVE', 'the same storage remains the active writer');

      // A second writer still cannot acquire the directory.
      const intruder = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: false,
        metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
      });
      assert.throws(() => intruder.initialize());

      // ...and the original writer keeps appending after rotation.
      const record = await store.append(createSampleRecordCandidate());
      assert.equal(record.sequenceNumber, 4);
    });

    test('Rotation is never re-entrant; concurrent appends are serialized', async () => {
      const { auditDir, store } = createRotatingStore('reentrancy');

      const results = await Promise.all(
        Array.from({ length: 8 }, () => store.append(createSampleRecordCandidate())),
      );

      const sequences = results.map((r) => r.sequenceNumber).sort((a, b) => a - b);
      assert.deepEqual(sequences, [1, 2, 3, 4, 5, 6, 7, 8]);

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.recordCount, 8);
      assert.equal(history.terminalSequence, 8);
    });
  });

  /* ==================================================================== *
   * RC06-NEG-48..59 — rotation, compression and full-history startup
   * ==================================================================== */

  describe('Negative Controls: Rotation, Compression & Full-History Startup (RC06-NEG-48..59)', () => {
    test('RC06-NEG-48: sequence gap between rotated segments is flagged', async () => {
      const auditDir = path.join(tempBaseDir, 'neg48');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const second = buildRecordLine({ sequenceNumber: 2, previousRecordHash: first.recordHash });
      fs.writeFileSync(
        path.join(auditDir, 'audit-20260101T000000Z-seq1-seq2.jsonl'),
        first.line + second.line,
        { mode: 0o600 },
      );

      // Segment 2 begins at sequence 4, leaving sequence 3 unaccounted for.
      const fourth = buildRecordLine({ sequenceNumber: 4, previousRecordHash: second.recordHash });
      fs.writeFileSync(path.join(auditDir, 'audit-20260102T000000Z-seq4-seq4.jsonl'), fourth.line, {
        mode: 0o600,
      });

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-NEG-49: previousRecordHash mismatch at a segment boundary is flagged', async () => {
      const auditDir = path.join(tempBaseDir, 'neg49');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const second = buildRecordLine({ sequenceNumber: 2, previousRecordHash: first.recordHash });
      fs.writeFileSync(
        path.join(auditDir, 'audit-20260101T000000Z-seq1-seq2.jsonl'),
        first.line + second.line,
        { mode: 0o600 },
      );

      // Internally consistent record whose predecessor hash is wrong across the
      // boundary: recordHash is recomputed, so only the chain link is broken.
      const broken = buildRecordLine({ sequenceNumber: 3, previousRecordHash: 'f'.repeat(64) });
      fs.writeFileSync(path.join(auditDir, 'audit-20260102T000000Z-seq3-seq3.jsonl'), broken.line, {
        mode: 0o600,
      });

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-NEG-50: a corrupted gzip archive fails verification closed', async () => {
      const { auditDir, store } = createRotatingStore('neg50');
      for (let i = 0; i < 4; i++) await store.append(createSampleRecordCandidate());
      const rotation = await store.rotateNow('INTERNAL_MANUAL');

      // Flip bytes inside the deflate stream, leaving the file a valid regular
      // file with correct permissions and link count.
      const corrupted = fs.readFileSync(rotation.archivePath);
      for (let i = 12; i < Math.min(corrupted.length, 40); i++) corrupted[i] ^= 0xff;
      fs.writeFileSync(rotation.archivePath, corrupted, { mode: 0o600 });

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-NEG-51: a missing intermediate rotated segment fails verification closed', async () => {
      const { auditDir, store } = createRotatingStore('neg51');

      for (let cycle = 0; cycle < 3; cycle++) {
        await store.append(createSampleRecordCandidate());
        await store.rotateNow('INTERNAL_MANUAL');
      }

      const archives = listArchiveInventory(auditDir, process.getuid());
      assert.equal(archives.length, 3);
      fs.unlinkSync(archives[1].filePath);

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-NEG-52: the uncompressed source is never deleted before verification succeeds', async () => {
      const { auditDir, store } = createRotatingStore('neg52', {
        hooks: { failPostCompressionVerification: true },
      });

      for (let i = 0; i < 4; i++) await store.append(createSampleRecordCandidate());

      const sourceStatsBefore = fs.statSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME));

      await assertRejectsWithCode(
        store.rotateNow('INTERNAL_MANUAL'),
        'AUDIT_ROTATION_VERIFICATION_FAILED',
      );

      // The rotated bytes are still present under their uncompressed name.
      const plainName = 'audit-20260921T000000Z-seq1-seq4.jsonl';
      assert.ok(
        fs.existsSync(path.join(auditDir, plainName)),
        'the uncompressed rotated segment must survive a failed post-compression verification',
      );
      assert.equal(
        fs.statSync(path.join(auditDir, plainName)).size,
        sourceStatsBefore.size,
        'no bytes may be lost to a failed verification',
      );
      assert.ok(
        fs.existsSync(path.join(auditDir, `${plainName}.gz`)),
        'the unverified compressed artifact is retained rather than deleted',
      );
    });

    test('RC06-NEG-53: a filename collision never overwrites an existing archive', async () => {
      const auditDir = path.join(tempBaseDir, 'neg53');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
      });
      storage.initialize();

      const clock = new TestClock(FIXED_CLOCK_START);
      const sealer = new SyntheticRotationCheckpointSealer();
      const store = createTestRotatingAuditStore(
        storage,
        { sealer },
        { clockMs: () => clock.now() },
      );

      await store.append(createSampleRecordCandidate());

      // Pre-existing evidence occupying the exact target name of the next
      // rotation. Rotation must fail rather than clobber it.
      const sentinel = Buffer.from('SENTINEL: pre-existing archival evidence\n', 'utf8');
      const colliding = path.join(auditDir, 'audit-20260921T000000Z-seq1-seq1.jsonl.gz');
      fs.writeFileSync(colliding, sentinel, { mode: 0o600 });

      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), [
        'AUDIT_ROTATION_FAILED',
        'AUDIT_ROTATION_COMPRESSION_FAILED',
        'EEXIST',
      ]);

      assert.deepEqual(
        fs.readFileSync(colliding),
        sentinel,
        'the pre-existing archive must be byte-identical after the failed rotation',
      );
      assert.ok(
        fs.existsSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME)),
        'the active segment must not be consumed by a failed rotation',
      );
    });

    test('RC06-NEG-53b: rapid rotations in the same second stay distinct via the sequence range', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { auditDir, store } = createRotatingStore('neg53-rapid', { clock });

      const names = [];
      for (let cycle = 0; cycle < 5; cycle++) {
        await store.append(createSampleRecordCandidate());
        names.push((await store.rotateNow('INTERNAL_MANUAL')).archiveFilename);
      }

      assert.equal(new Set(names).size, 5, 'every rotation must produce a distinct archive name');
      for (const name of names) {
        assert.match(name, /-seq\d+-seq\d+\.jsonl\.gz$/, 'distinguished by the sequence range');
      }
      assert.equal(listArchiveInventory(auditDir, process.getuid()).length, 5);
    });

    test('RC06-NEG-54: an uncompressed segment with wider permissions is rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'neg54');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const plain = path.join(auditDir, 'audit-20260101T000000Z-seq1-seq1.jsonl');
      fs.writeFileSync(plain, first.line, { mode: 0o600 });
      fs.chmodSync(plain, 0o644);

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'INSECURE_PERMISSIONS',
      );
    });

    test('RC06-NEG-55: a compressed archive with wider permissions is rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'neg55');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const archive = path.join(auditDir, 'audit-20260101T000000Z-seq1-seq1.jsonl.gz');
      fs.writeFileSync(archive, gzipSync(Buffer.from(first.line, 'utf8')), { mode: 0o600 });
      fs.chmodSync(archive, 0o640);

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'INSECURE_PERMISSIONS',
      );
    });

    test('RC06-NEG-56: a compressed archive with more than one hard link is rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'neg56');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const archive = path.join(auditDir, 'audit-20260101T000000Z-seq1-seq1.jsonl.gz');
      fs.writeFileSync(archive, gzipSync(Buffer.from(first.line, 'utf8')), { mode: 0o600 });
      fs.linkSync(archive, path.join(tempBaseDir, 'neg56-alias'));
      assert.equal(fs.statSync(archive).nlink, 2);

      await assertRejectsWithCode(verifyRetainedPrimaryHistory(auditDir, process.getuid()), [
        'AUDIT_STORE_INSECURE_ENTRY',
        'HARD_LINK_DETECTED',
      ]);
    });

    test('RC06-NEG-56b: a symlinked archive entry is rejected outright', async () => {
      const auditDir = path.join(tempBaseDir, 'neg56b');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const target = path.join(tempBaseDir, 'neg56b-target');
      fs.writeFileSync(target, 'not-a-segment\n', { mode: 0o600 });
      fs.symlinkSync(target, path.join(auditDir, 'audit-20260101T000000Z-seq1-seq1.jsonl.gz'));

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'SYMLINK_DETECTED',
      );
    });

    test('RC06-NEG-57: a wall-clock rollback cannot delay rotation past the 10 MiB limit', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { auditDir, store } = createRotatingStore('neg57', { clock });

      let appended = 0;
      while (store.getLastRotation() === null && appended < 400) {
        // Every append steps the clock BACKWARDS, so the interval trigger can
        // never fire and only the hard size limit can force rotation.
        clock.advanceMs(-60_000);
        await store.append(largeRecordCandidate());
        appended++;
      }

      const rotation = store.getLastRotation();
      assert.ok(rotation !== null, 'the hard size limit must defeat a clock rollback');
      assert.equal(rotation.reason, 'SIZE_THRESHOLD');

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.recordCount, appended);
      assert.equal(history.status, 'VERIFIED');
    });

    test('RC06-NEG-58: a wall-clock forward jump triggers rotation but deletes nothing', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { auditDir, store, sealer } = createRotatingStore('neg58', { clock });

      for (let cycle = 0; cycle < 3; cycle++) {
        await store.append(createSampleRecordCandidate());
        await store.append(createSampleRecordCandidate());
        clock.advanceMs(ROTATION_INTERVAL_MS * 365);
      }

      assert.equal(sealer.sealCount, 2, 'each elapsed interval rotates at most once per append');
      const archives = listArchiveInventory(auditDir, process.getuid());
      assert.equal(archives.length, 2, 'no segment may be auto-deleted');

      for (const archive of archives) {
        assert.ok(fs.existsSync(archive.filePath), 'every retained archive must still exist');
      }

      const history = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(history.status, 'VERIFIED');
      assert.equal(history.recordCount, 6);
    });

    test('RC06-NEG-59: a non-empty store with a corrupted intermediate segment fails closed', async () => {
      const { auditDir, store } = createRotatingStore('neg59');

      for (let cycle = 0; cycle < 3; cycle++) {
        await store.append(createSampleRecordCandidate());
        await store.rotateNow('INTERNAL_MANUAL');
      }
      await store.append(createSampleRecordCandidate());

      // Tamper with the middle archive: inflate it, rewrite one record with an
      // inconsistent hash, and store it back under the same canonical name.
      const archives = listArchiveInventory(auditDir, process.getuid());
      const middle = archives[1];
      const raw = fs.readFileSync(middle.filePath);
      const text = gunzipSync(raw).toString('utf8');
      const lines = text.split('\n').filter((l) => l.length > 0);
      const tampered = JSON.parse(lines[0]);
      tampered.integrity.recordHash = 'e'.repeat(64);
      // Re-serialize canonically so the failure is precisely a hash-chain break
      // rather than a formatting complaint.
      lines[0] = serializeRecordV1(tampered).slice(0, -1);
      fs.writeFileSync(middle.filePath, gzipSync(Buffer.from(lines.join('\n') + '\n', 'utf8')), {
        mode: 0o600,
      });

      await assertRejectsWithCode(verifyRetainedPrimaryHistory(auditDir, process.getuid()), [
        'AUDIT_CORRUPTION_DETECTED',
        'AUDIT_LIFECYCLE_CORRUPTION',
      ]);
    });

    test('RC06-NEG-59b: a content range that disagrees with the filename is rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'neg59b');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      // The name claims seq1-seq2; the content holds a single record.
      fs.writeFileSync(path.join(auditDir, 'audit-20260101T000000Z-seq1-seq2.jsonl'), first.line, {
        mode: 0o600,
      });

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('An unrecognized entry in the store directory fails closed', async () => {
      const { auditDir, store } = createRotatingStore('neg-unknown-entry');
      await store.append(createSampleRecordCandidate());

      fs.writeFileSync(path.join(auditDir, 'audit-20260101T000000Z-seq1-seq1.jsonl.bak'), 'x', {
        mode: 0o600,
      });

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_STORE_UNRECOGNIZED_ENTRY',
      );
    });

    test('RC06-NEG-48b: duplicate and overlapping archive ranges are rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'neg48b');
      fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

      const first = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      const second = buildRecordLine({ sequenceNumber: 2, previousRecordHash: first.recordHash });

      fs.writeFileSync(
        path.join(auditDir, 'audit-20260101T000000Z-seq1-seq2.jsonl'),
        first.line + second.line,
        { mode: 0o600 },
      );
      // Same authoritative range, different timestamp: a duplicate, not a new segment.
      fs.writeFileSync(
        path.join(auditDir, 'audit-20260102T000000Z-seq1-seq2.jsonl'),
        first.line + second.line,
        { mode: 0o600 },
      );

      await assertRejectsWithCode(
        verifyRetainedPrimaryHistory(auditDir, process.getuid()),
        'AUDIT_SEGMENT_RANGE_CONFLICT',
      );
    });
  });

  /* ==================================================================== *
   * RC06-NEG-60..63 — storage bounds and non-deletion retention
   * ==================================================================== */

  describe('Negative Controls: Storage Bounds & Non-Deletion Retention (RC06-NEG-60..63)', () => {
    test('RC06-NEG-60: ENOSPC during append throws and leaves state consistent', async () => {
      const auditDir = path.join(tempBaseDir, 'neg60');
      const storage = createTestPersistentAuditStorage(
        {
          directory: auditDir,
          createIfMissing: true,
          metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
        },
        { testFaults: { writeFault: 'enospc' } },
      );
      storage.initialize();

      const sizeBefore = fs.statSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME)).size;

      await assertRejectsWithCode(storage.append(createSampleRecordCandidate()), 'ENOSPC');

      // No bytes were written and the cursor never advanced.
      assert.equal(fs.statSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME)).size, sizeBefore);
      assert.equal(
        storage.getCurrentSequence(),
        1,
        'the chain cursor must not claim an unwritten record',
      );
      assert.equal(storage.getLastRecordHash(), GENESIS);
      assert.equal(storage.getState(), 'FAILED', 'the store must fail closed');

      // Further appends are refused rather than silently succeeding.
      await assertRejectsWithCode(
        storage.append(createSampleRecordCandidate()),
        'AUDIT_STORAGE_FAILED',
      );

      // Historical evidence is untouched.
      assert.ok(fs.existsSync(path.join(auditDir, METADATA_FILENAME)));
      storage.close();
    });

    test('RC06-NEG-61: a short write during append is detected and fails closed', async () => {
      const auditDir = path.join(tempBaseDir, 'neg61');
      const storage = createTestPersistentAuditStorage(
        {
          directory: auditDir,
          createIfMissing: true,
          metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
        },
        { testFaults: { writeFault: 'partial' } },
      );
      storage.initialize();

      await assertRejectsWithCode(storage.append(createSampleRecordCandidate()), 'SHORT_WRITE');

      assert.equal(
        storage.getCurrentSequence(),
        1,
        'a partial write must never advance the cursor',
      );
      assert.equal(storage.getState(), 'FAILED', 'a partial write must fail closed');
      storage.close();
    });

    test('RC06-NEG-62: reaching MAX_ARCHIVE_SEGMENTS halts privileged operations with zero deletion', async () => {
      const clock = new TestClock(FIXED_CLOCK_START);
      const { auditDir, store, sealer } = createRotatingStore('neg62', { clock });

      for (let cycle = 0; cycle < MAX_ARCHIVE_SEGMENTS; cycle++) {
        await store.append(createSampleRecordCandidate());
        await store.rotateNow('INTERNAL_MANUAL');
      }

      const archives = listArchiveInventory(auditDir, process.getuid());
      assert.equal(archives.length, MAX_ARCHIVE_SEGMENTS);
      assert.equal(
        countLogicalArchives(auditDir, process.getuid()),
        MAX_ARCHIVE_SEGMENTS,
        'each compressed archive occupies exactly one logical archive slot',
      );
      const before = archives.map((a) => a.filename);

      // The ceiling is checked BEFORE the next record is written, not once the
      // segment is already full and rotation has become impossible: a store that
      // accepted this record would be admitting evidence it can never archive.
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const activeBytesBefore = fs.statSync(activePath).size;
      const sealsBefore = sealer.sealCount;

      await assertRejectsWithCode(
        store.append(createSampleRecordCandidate()),
        'AUDIT_STORAGE_EXHAUSTED',
      );
      assert.equal(
        fs.statSync(activePath).size,
        activeBytesBefore,
        'the refused record must not have been written to the active segment',
      );
      assert.equal(
        sealer.sealCount,
        sealsBefore,
        'an exhausted store must not consume a checkpoint',
      );

      // Rotation is refused too, and refuses before sealing.
      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_STORAGE_EXHAUSTED');
      assert.equal(
        sealer.sealCount,
        sealsBefore,
        'a refused rotation must not consume a checkpoint',
      );

      const after = listArchiveInventory(auditDir, process.getuid()).map((a) => a.filename);
      assert.deepEqual(after, before, 'zero auto-deletion: every archived segment is retained');
      for (const archive of listArchiveInventory(auditDir, process.getuid())) {
        assert.ok(fs.existsSync(archive.filePath));
      }

      // The capacity probe is what both call sites consult, and it agrees.
      assertThrowsWithCode(
        () => assertArchiveCapacityAvailable(auditDir, process.getuid()),
        'AUDIT_STORAGE_EXHAUSTED',
      );

      // Nothing was deleted, so the store is still fully verifiable.
      const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(verification.logicalArchiveCount, MAX_ARCHIVE_SEGMENTS);
      assert.equal(
        verification.status,
        'VERIFIED',
        'the refused record left the fresh active segment empty, so there is no tail to recover',
      );
    });

    test('RC06-NEG-63: reaching TOTAL_AUDIT_BUDGET_BYTES halts appends with zero deletion', async () => {
      const { auditDir, store } = createRotatingStore('neg63');
      for (let i = 0; i < 2; i++) await store.append(createSampleRecordCandidate());
      await store.rotateNow('INTERNAL_MANUAL');

      const retainedBefore = fs.readdirSync(auditDir).sort();
      for (const name of retainedBefore) {
        assert.ok(fs.existsSync(path.join(auditDir, name)));
      }

      // A sparse file of exactly the total budget, so no 1 GiB is allocated.
      const ballast = path.join(auditDir, 'audit-20990101T000000Z-seq1-seq1.jsonl');
      writeSparseFile(ballast, TOTAL_AUDIT_BUDGET_BYTES);
      assert.equal(fs.statSync(ballast).size, TOTAL_AUDIT_BUDGET_BYTES);

      assertThrowsWithCode(
        () => assertAuditStorageCapacity(auditDir, process.getuid(), 0),
        'AUDIT_STORAGE_EXHAUSTED',
      );

      await assertRejectsWithCode(
        store.append(createSampleRecordCandidate()),
        'AUDIT_STORAGE_EXHAUSTED',
      );

      // A rotation must also refuse rather than reclaiming space.
      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_STORAGE_EXHAUSTED');

      // Zero auto-deletion: every retained artifact, including the ballast, remains.
      assert.equal(fs.statSync(ballast).size, TOTAL_AUDIT_BUDGET_BYTES);
      for (const name of retainedBefore) {
        assert.ok(fs.existsSync(path.join(auditDir, name)), `${name} must be retained`);
      }
    });

    test('RC06-NEG-63b: a record that would exceed the remaining budget is refused before writing', async () => {
      const { auditDir, store } = createRotatingStore('neg63b');
      await store.append(createSampleRecordCandidate());

      const used = scanAuditStorePhysicalBytes(auditDir, process.getuid());
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const sizeBefore = fs.statSync(activePath).size;

      // Fill the budget to within a byte of the ceiling.
      const ballast = path.join(auditDir, 'audit-20990101T000000Z-seq1-seq1.jsonl');
      writeSparseFile(ballast, TOTAL_AUDIT_BUDGET_BYTES - used + 1);

      await assertRejectsWithCode(
        store.append(createSampleRecordCandidate()),
        'AUDIT_STORAGE_EXHAUSTED',
      );
      assert.equal(
        fs.statSync(activePath).size,
        sizeBefore,
        'the refused record must not have been written',
      );
    });
  });

  /* ==================================================================== *
   * Correction regression matrix
   *
   * One case per defect and per identity window hardened by the Task-3
   * correction. The RC06-NEG-48..63 controls above keep their numbering; these
   * are additive.
   * ==================================================================== */

  describe('Correction Regression Matrix: Crash States, Identity Windows and Recovery', () => {
    const ALTERNATE_EVENT_ID = '11111111-2222-4333-8444-555555555555';
    const DECOY_EVENT_ID = '99999999-8888-4777-8666-555555555555';

    /** The canonical store config for a directory, matching createRotatingStore. */
    function storeConfig(directory) {
      return {
        directory,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
      };
    }

    /** Produces the genuine dual plain+gzip crash state documented in §53.1. */
    async function createCrashPairState(name) {
      const auditDir = path.join(tempBaseDir, name);
      const { store, sealer } = createRotatingStore(name, {
        hooks: { failSourceRemoval: true },
      });
      await store.append(createSampleRecordCandidate());
      await store.append(createSampleRecordCandidate());

      // Compression, installation and verification all succeed. Only the final
      // unlink of the plain source is lost, which is exactly the crash window
      // between "compressed artifact installed" and "source removed".
      await assertRejectsWithCode(
        store.rotateNow('INTERNAL_MANUAL'),
        'AUDIT_ROTATION_SOURCE_REMOVAL_FAILED',
      );

      const names = fs.readdirSync(auditDir);
      const plainName = names.find((n) => n.endsWith('.jsonl') && n !== ACTIVE_SEGMENT_FILENAME);
      const gzipName = names.find((n) => n.endsWith('.jsonl.gz'));
      assert.ok(plainName !== undefined, 'the plain representation must survive the crash');
      assert.ok(gzipName !== undefined, 'the compressed representation must be installed');
      assert.equal(`${plainName}.gz`, gzipName, 'both names must describe one range and timestamp');

      return { auditDir, store, sealer, plainName, gzipName };
    }

    test('RC06-T3-REG-01: a legitimate dual plain+gzip crash state verifies as one logical archive', async () => {
      const { auditDir, plainName, gzipName } = await createCrashPairState('neg64');

      const plainBytes = fs.statSync(path.join(auditDir, plainName)).size;
      const gzipBytes = fs.statSync(path.join(auditDir, gzipName)).size;

      // The inventory agrees with the verifier: one logical archive, two files,
      // and the pair is budgeted for the bytes both of them occupy.
      const logical = listLogicalArchiveInventory(auditDir, process.getuid());
      assert.equal(logical.length, 1, 'the crash pair occupies ONE logical archive slot');
      assert.equal(logical[0].physicalByteLength, plainBytes + gzipBytes);
      assert.equal(countLogicalArchives(auditDir, process.getuid()), 1);

      const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());

      assert.equal(verification.status, 'VERIFIED');
      assert.equal(
        verification.logicalArchiveCount,
        1,
        'a crash pair is ONE logical archive, not two',
      );
      assert.equal(verification.recordCount, 2);
      assert.equal(verification.terminalSequence, 2);
      assert.equal(verification.nextSequence, 3);
      assert.equal(
        verification.physicalPrimaryBytes,
        plainBytes + gzipBytes,
        'both representations occupy disk and both must be budgeted',
      );
      assert.deepEqual(
        verification.segments[0].filenames.sort(),
        [plainName, gzipName].sort(),
        'both physical names must be reported for the one logical archive',
      );
    });

    test('RC06-T3-REG-02: a dual crash state whose representations disagree is corruption', async () => {
      const { auditDir, gzipName } = await createCrashPairState('neg65');

      // Replace the compressed half with a different, internally self-consistent
      // chain for the SAME sequence range. Every digest field still describes a
      // valid segment, so only a representation-to-representation comparison can
      // catch it — and a "the valid copy wins" rule would silently accept it.
      const alt1 = buildRecordLine({
        sequenceNumber: 1,
        previousRecordHash: GENESIS,
        recordOverrides: { eventId: ALTERNATE_EVENT_ID },
      });
      const alt2 = buildRecordLine({
        sequenceNumber: 2,
        previousRecordHash: alt1.recordHash,
        recordOverrides: { eventId: ALTERNATE_EVENT_ID },
      });
      fs.writeFileSync(
        path.join(auditDir, gzipName),
        gzipSync(Buffer.from(alt1.line + alt2.line)),
        {
          mode: 0o600,
        },
      );

      await assert.rejects(verifyRetainedPrimaryHistory(auditDir, process.getuid()), (err) => {
        assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED');
        assert.match(err.message, /dual representations of one sequence range disagree/);
        return true;
      });
    });

    test('RC06-T3-REG-03: a replacement left at the plain source pathname is never unlinked', async () => {
      const auditDir = path.join(tempBaseDir, 'neg66');
      const displacedPath = path.join(tempBaseDir, 'neg66-displaced.jsonl');
      let plainPath = null;
      let decoyBytes = null;

      const { store } = createRotatingStore('neg66', {
        hooks: {
          beforeSourceRemoval: () => {
            plainPath = path.join(
              auditDir,
              fs.readdirSync(auditDir).find((n) => n.endsWith('.jsonl') && !n.endsWith('.gz')),
            );

            // Displace the genuine source, then leave a valid-looking segment
            // behind in its place: valid JSONL, valid chain, wrong inode.
            fs.renameSync(plainPath, displacedPath);
            const decoy = buildRecordLine({
              sequenceNumber: 1,
              previousRecordHash: GENESIS,
              recordOverrides: { eventId: DECOY_EVENT_ID },
            });
            decoyBytes = Buffer.from(decoy.line);
            fs.writeFileSync(plainPath, decoyBytes, { mode: 0o600 });
          },
        },
      });

      await store.append(createSampleRecordCandidate());
      await store.append(createSampleRecordCandidate());

      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_ROTATION_FAILED');

      assert.ok(plainPath !== null, 'the seam must have run');
      assert.deepEqual(
        fs.readFileSync(plainPath),
        decoyBytes,
        'the replacement must never be unlinked as if it were the source',
      );
      assert.ok(
        fs.existsSync(displacedPath),
        'the displaced genuine source must not be unlinked either',
      );

      const gzipNames = fs.readdirSync(auditDir).filter((n) => n.endsWith('.jsonl.gz'));
      assert.equal(gzipNames.length, 1, 'the already-installed compressed artifact is retained');
      assert.equal(
        store.getState(),
        'FAILED',
        'an unprovable source identity must fail the store closed',
      );
    });

    test('RC06-T3-REG-04: an active segment pathname replaced before rotation is never archived', async () => {
      const auditDir = path.join(tempBaseDir, 'neg67');
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const displacedPath = path.join(tempBaseDir, 'neg67-displaced-active.jsonl');
      let replacementBytes = null;

      const { store } = createRotatingStore('neg67', {
        hooks: {
          beforePhysicalRotation: () => {
            replacementBytes = fs.readFileSync(activePath);
            fs.renameSync(activePath, displacedPath);
            // Byte-identical, same size: only the inode differs, so a name- or
            // size-based check would accept it.
            fs.writeFileSync(activePath, replacementBytes, { mode: 0o600 });
          },
        },
      });

      await store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_ROTATION_FAILED');

      assert.equal(listArchiveInventory(auditDir, process.getuid()).length, 0, 'nothing archived');
      assert.deepEqual(fs.readFileSync(activePath), replacementBytes, 'replacement untouched');
      assert.ok(fs.existsSync(displacedPath), 'the displaced original is untouched');
      assert.equal(store.getState(), 'FAILED');
    });

    test('RC06-T3-REG-05: an active segment grown in place before rotation is never archived', async () => {
      const auditDir = path.join(tempBaseDir, 'neg68');
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const firstRecord = buildRecordLine({ sequenceNumber: 1, previousRecordHash: GENESIS });
      let grownBytes = null;

      const { store } = createRotatingStore('neg68', {
        hooks: {
          beforePhysicalRotation: () => {
            // A same-inode growth whose appended content is itself a valid,
            // chain-correct record: the only thing wrong with it is that the
            // segment is no longer the one that was validated.
            const second = buildRecordLine({
              sequenceNumber: 2,
              previousRecordHash: firstRecord.recordHash,
            });
            grownBytes = Buffer.from(second.line);
            fs.appendFileSync(activePath, grownBytes);
          },
        },
      });

      await store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_ROTATION_FAILED');

      assert.equal(listArchiveInventory(auditDir, process.getuid()).length, 0, 'nothing archived');
      assert.equal(
        fs.readFileSync(activePath).subarray(-grownBytes.length).toString(),
        grownBytes.toString(),
        'the appended bytes must not be silently adopted or truncated',
      );
      assert.equal(store.getState(), 'FAILED');
    });

    test('RC06-T3-REG-06: an active segment shrunk in place before rotation is never archived', async () => {
      const auditDir = path.join(tempBaseDir, 'neg69');
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      let shrunkSize = null;

      const { store } = createRotatingStore('neg69', {
        hooks: {
          beforePhysicalRotation: () => {
            shrunkSize = fs.statSync(activePath).size - 1;
            fs.truncateSync(activePath, shrunkSize);
          },
        },
      });

      await store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_ROTATION_FAILED');

      assert.equal(listArchiveInventory(auditDir, process.getuid()).length, 0, 'nothing archived');
      assert.equal(
        fs.statSync(activePath).size,
        shrunkSize,
        'the truncation is not undone or hidden',
      );
      assert.equal(store.getState(), 'FAILED');
    });

    test('RC06-T3-REG-07: the physical budget is enforced per compressed chunk, not after the fact', async () => {
      const auditDir = path.join(tempBaseDir, 'neg70');
      const { store } = createRotatingStore('neg70');

      await store.append(createSampleRecordCandidate());

      const used = scanAuditStorePhysicalBytes(auditDir, process.getuid());
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const retainedBefore = fs.readdirSync(auditDir).sort();

      // Leave exactly one byte of headroom. The segment's own bytes simply move
      // from the active name to the archive name during rotation, so the peak
      // the compressed stream may consume is that one remaining byte.
      const ballast = path.join(auditDir, 'audit-20990101T000000Z-seq1-seq1.jsonl');
      writeSparseFile(ballast, TOTAL_AUDIT_BUDGET_BYTES - used - 1);

      await assertRejectsWithCode(store.rotateNow('INTERNAL_MANUAL'), 'AUDIT_STORAGE_EXHAUSTED');

      // The refusal happens while streaming, so no `.gz` is ever installed.
      assert.equal(
        fs.readdirSync(auditDir).filter((n) => n.endsWith('.jsonl.gz')).length,
        0,
        'an over-budget compression must not produce an archive',
      );
      assert.equal(fs.statSync(ballast).size, TOTAL_AUDIT_BUDGET_BYTES - used - 1);
      for (const name of retainedBefore) {
        assert.ok(fs.existsSync(path.join(auditDir, name)), `${name} must be retained`);
      }
      // No scratch file is left behind by the aborted stream.
      assert.equal(
        fs.readdirSync(auditDir).filter((n) => n.endsWith('.tmp')).length,
        0,
        'the aborted compression scratch must be cleaned up',
      );
      assert.ok(fs.existsSync(activePath), 'the active segment is untouched');
    });

    test('RC06-T3-REG-08: a UTF-8-valid incomplete active JSON fragment is a recoverable torn tail', async () => {
      const auditDir = path.join(tempBaseDir, 'neg71');
      const { store, storage } = createRotatingStore('neg71');
      await store.append(createSampleRecordCandidate());
      storage.close();

      // An incomplete JSON prefix. It decodes cleanly as UTF-8 and is longer than
      // a partial multibyte sequence, so a decodability-based rule would call it
      // corruption — but the write simply did not finish.
      const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
      const fragment = '{"schemaVersion":1,"sequenceNumber":2,"eventId":"f47ac10b-58cc-4372';
      fs.appendFileSync(activePath, fragment);

      const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(verification.status, 'RECOVERABLE_TORN_ACTIVE_TAIL');
      assert.equal(verification.terminalSequence, 1);
      assert.equal(verification.nextSequence, 2);
      assert.equal(verification.active.tornBytes.toString(), fragment);

      // Task-2 restart recovery must agree, on the same bytes.
      const recovered = await recoverPersistentAuditStorage(storeConfig(auditDir));
      assert.equal(recovered.recoveredTornTail, true);
      assert.equal(recovered.terminalSequence, 1);
      assert.equal(recovered.nextSequence, 2);
      recovered.storage.close();
    });

    test('RC06-T3-REG-09: the same torn tail inside a finalized rotated segment is corruption', async () => {
      const auditDir = path.join(tempBaseDir, 'neg72');
      const { store, storage } = createRotatingStore('neg72');
      await store.append(createSampleRecordCandidate());
      await store.rotateNow('INTERNAL_MANUAL');
      await store.append(createSampleRecordCandidate());
      storage.close();

      // Append an equivalent fragment to a segment that was sealed at a complete
      // record boundary. A finalized rotated segment never carries a torn tail,
      // so the identical bytes are corruption here.
      const archiveName = fs.readdirSync(auditDir).find((n) => n.endsWith('.jsonl.gz'));
      const archivePath = path.join(auditDir, archiveName);
      const decoded = gunzipSync(fs.readFileSync(archivePath));
      const fragment = '{"schemaVersion":1,"sequenceNumber":2,"eventId":"f47ac10b-58cc-4372';
      fs.writeFileSync(archivePath, gzipSync(Buffer.concat([decoded, Buffer.from(fragment)])), {
        mode: 0o600,
      });

      await assert.rejects(verifyRetainedPrimaryHistory(auditDir, process.getuid()), (err) => {
        assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED');
        return true;
      });
    });

    test('RC06-T3-REG-10: a rotation source replaced before compression is never compressed or deleted', async () => {
      const auditDir = path.join(tempBaseDir, 'neg73');
      const { store } = createRotatingStore('neg73', { hooks: { failCompressionCreate: true } });

      await store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(
        store.rotateNow('INTERNAL_MANUAL'),
        'AUDIT_ROTATION_COMPRESSION_FAILED',
      );

      // The physical rotation stands: the plain archive exists and no compressed
      // artifact was produced. Recovering must therefore still see the plain
      // representation as the retained primary history.
      const names = fs.readdirSync(auditDir);
      assert.equal(names.filter((n) => n.endsWith('.jsonl.gz')).length, 0);
      assert.equal(names.filter((n) => n.endsWith('.jsonl')).length, 2, 'archive + fresh active');

      const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(verification.logicalArchiveCount, 1);
      assert.equal(verification.status, 'VERIFIED');
    });

    test('RC06-T3-REG-11: a recovered non-empty active segment rotates exactly the range it holds', async () => {
      const auditDir = path.join(tempBaseDir, 'neg74');
      const { store, storage } = createRotatingStore('neg74');
      await store.append(createSampleRecordCandidate());
      await store.append(createSampleRecordCandidate());
      await store.append(createSampleRecordCandidate());
      storage.close();

      // Restart: the active segment already holds records 1..3, so the rotating
      // store must adopt that range rather than assuming it opened at the cursor.
      const recovered = await recoverPersistentAuditStorage(storeConfig(auditDir));
      assert.equal(recovered.nextSequence, 4);

      const clock = new TestClock(FIXED_CLOCK_START);
      const sealer = new SyntheticRotationCheckpointSealer();
      const restarted = createTestRotatingAuditStore(
        recovered.storage,
        { sealer },
        { clockMs: () => clock.now() },
      );

      const result = await restarted.rotateNow('INTERNAL_MANUAL');
      assert.equal(
        result.boundary.sequenceStart,
        1,
        'the recovered range starts at the first record',
      );
      assert.equal(result.boundary.sequenceEnd, 3, 'the recovered range ends at the last record');

      const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
      assert.equal(verification.logicalArchiveCount, 1);
      assert.equal(verification.terminalSequence, 3);
      assert.equal(verification.nextSequence, 4);

      // The chain continues from the recovered cursor, not from a reset one.
      await restarted.append(createSampleRecordCandidate());
      assert.equal(restarted.getStorage().getCurrentSequence(), 5);
    });

    test('RC06-T3-REG-12: a recovered older active segment keeps its true age for the interval trigger', async () => {
      const auditDir = path.join(tempBaseDir, 'neg75');
      const { store, storage } = createRotatingStore('neg75');
      await store.append(createSampleRecordCandidate());
      storage.close();

      // The segment's own first record is two days old. A restart that stamped
      // "opened now" would postpone the interval rotation by a full day.
      const clock = new TestClock(FIXED_CLOCK_START + 2 * ROTATION_INTERVAL_MS);
      const recovered = await recoverPersistentAuditStorage(storeConfig(auditDir));
      const sealer = new SyntheticRotationCheckpointSealer();
      const restarted = createTestRotatingAuditStore(
        recovered.storage,
        { sealer },
        { clockMs: () => clock.now() },
      );

      await restarted.append(createSampleRecordCandidate());
      const rotation = restarted.getLastRotation();
      assert.ok(rotation !== null, 'the age trigger must have fired on the first append');
      assert.equal(
        rotation.reason,
        'ROTATION_INTERVAL',
        'the recovered segment must rotate on age, not on a fabricated open time',
      );
      assert.equal(rotation.boundary.sequenceStart, 1);
      assert.equal(rotation.boundary.sequenceEnd, 1);
    });

    test('RC06-T3-REG-13: an active segment whose age cannot be established still rotates on size', async () => {
      const auditDir = path.join(tempBaseDir, 'neg76');
      const { store, storage } = createRotatingStore('neg76');
      await store.append(createSampleRecordCandidate());
      storage.close();

      // The size trigger is independent of the recovered open time, so it must
      // keep working whichever way the age was resolved.
      const recovered = await recoverPersistentAuditStorage(storeConfig(auditDir));
      const clock = new TestClock(FIXED_CLOCK_START);
      const restarted = createTestRotatingAuditStore(
        recovered.storage,
        { sealer: new SyntheticRotationCheckpointSealer() },
        { clockMs: () => clock.now() },
      );

      const oversized = largeRecordCandidate();
      let guard = 0;
      while (restarted.getLastRotation() === null && guard < 400) {
        await restarted.append(oversized);
        guard++;
      }

      const rotation = restarted.getLastRotation();
      assert.ok(rotation !== null, 'the 10 MiB size trigger must still fire');
      assert.equal(rotation.reason, 'SIZE_THRESHOLD');
      assert.ok(
        fs.statSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME)).size < SEGMENT_SIZE_THRESHOLD,
        'the fresh active segment must start below the threshold',
      );
    });
  });

  /* ==================================================================== *
   * Torn-tail parity between Task-2 recovery and Task-3 startup verification
   *
   * The two surfaces must reach the SAME verdict on the same bytes. Task 2 runs
   * first historically and truncates the tail, so every case here is verified by
   * Task 3 first — Task 3 reads only — and then handed to Task 2 unmodified.
   * ==================================================================== */

  describe('Torn-Tail Parity: Task-2 Recovery vs Task-3 Startup Verification', () => {
    /** Builds a store holding one committed record plus `trailing` raw bytes. */
    async function buildActiveTailFixture(name, trailing) {
      const auditDir = path.join(tempBaseDir, name);
      const config = {
        directory: auditDir,
        createIfMissing: true,
        metadata: { checkpointPublicKeyFingerprint: '1'.repeat(64), anchorMode: 'DISABLED' },
      };
      const { store, storage } = createRotatingStore(name);
      const record = await store.append(createSampleRecordCandidate());
      storage.close();

      fs.appendFileSync(path.join(auditDir, ACTIVE_SEGMENT_FILENAME), trailing);
      return { auditDir, config, record };
    }

    /**
     * Runs both surfaces over one fixture and asserts they agree.
     *
     * `expected` is 'RECOVERABLE' when both must accept the trailing bytes and
     * 'CORRUPTION' when both must refuse them.
     */
    async function assertParity(fixture, expected, label) {
      const { auditDir, config } = fixture;

      // Task 3 first: it is read-only, so Task 2 sees the bytes untouched.
      let taskThree;
      try {
        const verification = await verifyRetainedPrimaryHistory(auditDir, process.getuid());
        taskThree =
          verification.status === 'RECOVERABLE_TORN_ACTIVE_TAIL' ? 'RECOVERABLE' : 'ACCEPTED';
      } catch (err) {
        assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED', `${label}: unexpected Task-3 code`);
        taskThree = 'CORRUPTION';
      }

      let taskTwo;
      let recovery = null;
      try {
        recovery = await recoverPersistentAuditStorage(config);
        taskTwo = recovery.recoveredTornTail ? 'RECOVERABLE' : 'ACCEPTED';
      } catch (err) {
        assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED', `${label}: unexpected Task-2 code`);
        taskTwo = 'CORRUPTION';
      } finally {
        if (recovery !== null) recovery.storage.close();
      }

      assert.equal(taskTwo, taskThree, `${label}: the two surfaces must reach one verdict`);
      assert.equal(taskThree, expected, `${label}: verdict`);
      return { taskThree, taskTwo };
    }

    test('RC06-T3-REG-14: parity — an incomplete JSON prefix is a recoverable tail for both surfaces', async () => {
      await assertParity(
        await buildActiveTailFixture(
          'parity-json-prefix',
          '{"schemaVersion":1,"sequenceNumber":2,',
        ),
        'RECOVERABLE',
        'incomplete JSON prefix',
      );
    });

    test('RC06-T3-REG-15: parity — a complete record that lost only its newline is a recoverable tail', async () => {
      // Syntactically a whole, valid record; the only thing missing is the
      // terminator that would have made the write complete.
      const complete = buildRecordLine({ sequenceNumber: 2, previousRecordHash: GENESIS });
      await assertParity(
        await buildActiveTailFixture('parity-no-newline', complete.line.trimEnd()),
        'RECOVERABLE',
        'newline-less complete record',
      );
    });

    test('RC06-T3-REG-16: parity — trailing bytes that are not valid UTF-8 are a recoverable tail', async () => {
      // A partial multibyte sequence: undecodable, but no less a crash artifact.
      const undecodable = Buffer.from([
        0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xe2, 0x82, 0xac, 0xff, 0xfe, 0x80,
      ]);
      assert.ok(
        undecodable.toString('utf8').includes('�'),
        'the fixture must genuinely fail strict UTF-8 decoding',
      );
      await assertParity(
        await buildActiveTailFixture('parity-undecodable', undecodable),
        'RECOVERABLE',
        'undecodable trailing bytes',
      );
    });

    test('RC06-T3-REG-17: parity — a tail beyond MAX_TORN_TAIL_BYTES is corruption for both surfaces', async () => {
      await assertParity(
        await buildActiveTailFixture(
          'parity-too-large',
          Buffer.alloc(MAX_TORN_TAIL_BYTES + 1, 0x61),
        ),
        'CORRUPTION',
        'oversized tail',
      );
    });

    test('RC06-T3-REG-18: parity — a tail at exactly MAX_TORN_TAIL_BYTES is recoverable for both', async () => {
      await assertParity(
        await buildActiveTailFixture('parity-exact-limit', Buffer.alloc(MAX_TORN_TAIL_BYTES, 0x61)),
        'RECOVERABLE',
        'tail at the limit',
      );
    });

    test('RC06-T3-REG-19: a trusted boundary inside the verified prefix is satisfied by both surfaces', async () => {
      const fixture = await buildActiveTailFixture(
        'parity-boundary-prefix',
        '{"schemaVersion":1,"sequenceNumber":2,',
      );
      const boundary = {
        sequenceNumber: fixture.record.sequenceNumber,
        recordHash: fixture.record.integrity.recordHash,
      };

      const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, process.getuid(), {
        trustedBoundary: boundary,
      });
      assert.equal(verification.status, 'RECOVERABLE_TORN_ACTIVE_TAIL');

      const recovery = await recoverPersistentAuditStorage(fixture.config, {
        trustedBoundary: boundary,
      });
      assert.equal(recovery.recoveredTornTail, true);
      assert.equal(recovery.terminalSequence, fixture.record.sequenceNumber);
      recovery.storage.close();
    });

    test('RC06-T3-REG-20: a trusted boundary inside the torn tail is never satisfied by either surface', async () => {
      const fixture = await buildActiveTailFixture(
        'parity-boundary-tail',
        '{"schemaVersion":1,"sequenceNumber":2,',
      );
      // Sequence 2 exists only as a fragment: it was never durably written, so no
      // surface may certify it.
      const boundary = { sequenceNumber: 2, recordHash: 'a'.repeat(64) };

      await assert.rejects(
        verifyRetainedPrimaryHistory(fixture.auditDir, process.getuid(), {
          trustedBoundary: boundary,
        }),
        (err) => {
          assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED');
          assert.match(err.message, /trusted boundary sequence 2/);
          return true;
        },
      );

      await assert.rejects(
        recoverPersistentAuditStorage(fixture.config, { trustedBoundary: boundary }),
        (err) => {
          assert.equal(err.code, 'AUDIT_CORRUPTION_DETECTED');
          return true;
        },
      );

      // Fail-closed means no truncation: the tail is still on disk afterwards.
      assert.match(
        fs.readFileSync(path.join(fixture.auditDir, ACTIVE_SEGMENT_FILENAME), 'utf8'),
        /\{"schemaVersion":1,"sequenceNumber":2,$/,
      );
    });
  });
});
