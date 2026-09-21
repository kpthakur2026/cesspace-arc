/**
 * CesSpace ARC — RC-06 Task 2: Restart Recovery, Torn Tails & Dangling Operations
 *
 * Test suite verifying:
 * - Streaming active-stream verification and virtual genesis
 * - Chain continuity and tamper detection (RC06-NEG-30..35)
 * - Trusted primary-chain boundary staging verification (RC06-NEG-36)
 * - Recoverable torn active tails vs non-recoverable corruption (RC06-NEG-37, NEG-38)
 * - Restart sequence continuity and anti-reset (RC06-NEG-39)
 * - Dangling STARTED reconciliation & idempotency (RC06-NEG-46)
 * - Recovery append failure safety & partial progress idempotency (RC06-NEG-47)
 * - Strict lifecycle state machine validation matrix
 * - Positive lifecycle flows (standalone DENIED, completed, already recovered)
 * - Sidecar security, collision resistance, and durability failure safety
 * - Active file replacement race protection
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';

import { MAX_RECORD_BYTES } from '../packages/protocol/dist/index.js';

import {
  PersistentAuditStorage,
  MAX_TORN_TAIL_BYTES,
  verifyActiveStream,
  recoverPersistentAuditStorage,
  computeRecordHashV1,
  serializeRecordV1,
  ACTIVE_SEGMENT_FILENAME,
} from '../packages/audit/dist/index.js';

import { recoverPersistentAuditStorageForTest } from '../packages/audit/dist/internal/recovery-testing.js';

function createSampleRecord(seq, prevHash, overrides = {}) {
  const base = {
    schemaVersion: 1,
    eventId: randomUUID(),
    timestamp: '2026-09-21T08:00:00.000Z',
    sequenceNumber: seq,
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
      startTime: '2026-09-21T08:00:00.000Z',
      endTime: '2026-09-21T08:00:00.010Z',
      durationMs: 10,
    },
    integrity: {
      previousRecordHash: prevHash,
      recordHash: '0000000000000000000000000000000000000000000000000000000000000000',
    },
    ...overrides,
  };

  const hash = computeRecordHashV1(base);
  base.integrity.recordHash = hash;
  return base;
}

function writeRecordsToFile(filePath, records) {
  const lines = records.map((r) => (typeof r === 'string' ? r : serializeRecordV1(r))).join('');
  fs.writeFileSync(filePath, lines, { mode: 0o600 });
}

describe('CesSpace ARC — RC-06 Task 2: Restart Recovery, Torn Tails & Dangling Operations', () => {
  let tempBaseDir;
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const sampleFingerprint = 'e'.repeat(64);

  before(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task2-'));
  });

  after(() => {
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  function createTestStoreConfig(subDir, overrides = {}) {
    const auditDir = path.join(tempBaseDir, subDir);
    return {
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: sampleFingerprint,
        anchorMode: 'DISABLED',
      },
      expectedUid: currentUid,
      ...overrides,
    };
  }

  describe('1. Virtual Genesis & Streaming Active Stream Verification', () => {
    test('Fixed architectural constants: MAX_TORN_TAIL_BYTES and MAX_RECORD_BYTES are exactly 65536', () => {
      assert.strictEqual(MAX_TORN_TAIL_BYTES, 65536);
      assert.strictEqual(MAX_RECORD_BYTES, 65536);
    });

    test('Empty active stream returns virtual genesis cursor (nextSequence: 1, zero hash)', () => {
      const activePath = path.join(tempBaseDir, 'genesis-empty.jsonl');
      fs.writeFileSync(activePath, '', { mode: 0o600 });

      const res = verifyActiveStream(activePath, currentUid);
      assert.strictEqual(res.status, 'VERIFIED');
      assert.strictEqual(res.recordCount, 0);
      assert.strictEqual(res.terminalSequence, 0);
      assert.strictEqual(res.nextSequence, 1);
      assert.strictEqual(
        res.terminalRecordHash,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      assert.strictEqual(
        res.previousRecordHash,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      assert.strictEqual(res.verifiedByteLength, 0);
    });

    test('Non-empty stream first record starting at sequence 2 fails with AUDIT_CORRUPTION_DETECTED', () => {
      const activePath = path.join(tempBaseDir, 'genesis-bad-seq.jsonl');
      const r1 = createSampleRecord(
        2,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      writeRecordsToFile(activePath, [r1]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('sequenceNumber'),
      );
    });

    test('First record with non-zero previousRecordHash fails with AUDIT_CORRUPTION_DETECTED', () => {
      const activePath = path.join(tempBaseDir, 'genesis-bad-hash.jsonl');
      const r1 = createSampleRecord(1, '1'.repeat(64));
      writeRecordsToFile(activePath, [r1]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) =>
          err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('previousRecordHash'),
      );
    });

    test('Streaming verification across multiple chunk buffers works deterministically', () => {
      const activePath = path.join(tempBaseDir, 'streaming-chunks.jsonl');
      const records = [];
      let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
      for (let i = 1; i <= 50; i++) {
        const rec = createSampleRecord(i, prevHash);
        records.push(rec);
        prevHash = rec.integrity.recordHash;
      }
      writeRecordsToFile(activePath, records);

      const res = verifyActiveStream(activePath, currentUid);
      assert.strictEqual(res.status, 'VERIFIED');
      assert.strictEqual(res.recordCount, 50);
      assert.strictEqual(res.terminalSequence, 50);
      assert.strictEqual(res.nextSequence, 51);
      assert.strictEqual(res.terminalRecordHash, prevHash);
    });

    test('Strict UTF-8: invalid UTF-8 byte in complete line fails with AUDIT_CORRUPTION_DETECTED', () => {
      const activePath = path.join(tempBaseDir, 'invalid-utf8.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, r1.integrity.recordHash);
      const line1 = serializeRecordV1(r1);
      const line2 = serializeRecordV1(r2);

      // Corrupt line1 with an invalid UTF-8 sequence (0xFF, 0xFE) followed by valid line 2
      const buf1 = Buffer.from(line1, 'utf8');
      buf1[20] = 0xff;
      buf1[21] = 0xfe;

      const fd = fs.openSync(activePath, fs.constants.O_CREAT | fs.constants.O_WRONLY, 0o600);
      fs.writeSync(fd, buf1);
      fs.writeSync(fd, Buffer.from(line2, 'utf8'));
      fs.closeSync(fd);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED',
      );
    });
  });

  describe('2. Negative Controls: RC06-NEG-30..35 (Chain Continuity & Tampering)', () => {
    test('RC06-NEG-30: Sequence number gap (seq 1, then seq 3) fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-30.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r3 = createSampleRecord(3, r1.integrity.recordHash);
      writeRecordsToFile(activePath, [r1, r3]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('discontinuity'),
      );
    });

    test('RC06-NEG-31: Duplicate sequence number (seq 1, then seq 1) fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-31.jsonl');
      const r1a = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r1b = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      writeRecordsToFile(activePath, [r1a, r1b]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('discontinuity'),
      );
    });

    test('RC06-NEG-32: Broken previousRecordHash link fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-32.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, '2'.repeat(64));
      writeRecordsToFile(activePath, [r1, r2]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) =>
          err.code === 'AUDIT_CORRUPTION_DETECTED' &&
          err.message.includes('previousRecordHash mismatch'),
      );
    });

    test('RC06-NEG-33: Tampered record payload with original recordHash fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-33.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const originalHash = r1.integrity.recordHash;
      // Alter execution durationMs without updating recordHash
      r1.execution.durationMs = 999;
      r1.integrity.recordHash = originalHash;
      writeRecordsToFile(activePath, [r1]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('recordHash'),
      );
    });

    test('RC06-NEG-34: Tampered recordHash with original payload fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-34.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      r1.integrity.recordHash = 'f'.repeat(64);
      writeRecordsToFile(activePath, [r1]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('recordHash'),
      );
    });

    test('RC06-NEG-35: Middle record deletion detects sequence/hash break', () => {
      const activePath = path.join(tempBaseDir, 'neg-35.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, r1.integrity.recordHash);
      const r3 = createSampleRecord(3, r2.integrity.recordHash);
      // Omit r2
      writeRecordsToFile(activePath, [r1, r3]);

      assert.throws(
        () => verifyActiveStream(activePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('discontinuity'),
      );
    });
  });

  describe('3. Negative Control: RC06-NEG-36 (Trusted Primary-Chain Boundary)', () => {
    test('Boundary sequence beyond retained history fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-36-missing.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, r1.integrity.recordHash);
      writeRecordsToFile(activePath, [r1, r2]);

      const trustedBoundary = {
        sequenceNumber: 5,
        recordHash: '3'.repeat(64),
      };

      assert.throws(
        () => verifyActiveStream(activePath, currentUid, { trustedBoundary }),
        (err) =>
          err.code === 'AUDIT_CORRUPTION_DETECTED' &&
          err.message.includes('Trusted boundary sequence 5 was not found'),
      );
    });

    test('Boundary sequence exists but recordHash differs fails closed', () => {
      const activePath = path.join(tempBaseDir, 'neg-36-hash-mismatch.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      writeRecordsToFile(activePath, [r1]);

      const trustedBoundary = {
        sequenceNumber: 1,
        recordHash: '4'.repeat(64), // Mismatch with r1's actual recordHash
      };

      assert.throws(
        () => verifyActiveStream(activePath, currentUid, { trustedBoundary }),
        (err) =>
          err.code === 'AUDIT_CORRUPTION_DETECTED' &&
          err.message.includes('Trusted boundary hash mismatch'),
      );
    });

    test('Boundary sequence inside candidate torn tail fails closed (tail not truncated)', () => {
      const activePath = path.join(tempBaseDir, 'neg-36-tail-boundary.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const line1 = serializeRecordV1(r1);
      // Unterminated torn tail for sequence 2
      const tornTail = '{"schemaVersion":1,"sequenceNumber":2,"eventId":"';
      fs.writeFileSync(activePath, line1 + tornTail, { mode: 0o600 });

      const trustedBoundary = {
        sequenceNumber: 2,
        recordHash: '5'.repeat(64),
      };

      assert.throws(
        () => verifyActiveStream(activePath, currentUid, { trustedBoundary }),
        (err) =>
          err.code === 'AUDIT_CORRUPTION_DETECTED' &&
          err.message.includes('Trusted boundary sequence 2 lies in candidate torn tail'),
      );
    });

    test('Valid history satisfying trusted boundary succeeds', () => {
      const activePath = path.join(tempBaseDir, 'neg-36-valid.jsonl');
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, r1.integrity.recordHash);
      writeRecordsToFile(activePath, [r1, r2]);

      const trustedBoundary = {
        sequenceNumber: 2,
        recordHash: r2.integrity.recordHash,
      };

      const res = verifyActiveStream(activePath, currentUid, { trustedBoundary });
      assert.strictEqual(res.status, 'VERIFIED');
      assert.strictEqual(res.recordCount, 2);
    });
  });

  describe('4. Negative Controls: RC06-NEG-37..39 (Torn Tails, Corruption & Anti-Reset)', () => {
    test('RC06-NEG-37 (Case A): Torn final line missing LF recovers to sidecar, truncates active, continues chain', async () => {
      const config = createTestStoreConfig('neg-37-case-a');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't2', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:01.001Z',
          durationMs: 1,
        },
      });

      storage1.close();

      // Append unterminated torn tail
      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const initialBytes = fs.readFileSync(activePath);
      const tornBytes = Buffer.from('{"schemaVersion":1,"sequenceNumber":3,"incomplete":true');
      fs.appendFileSync(activePath, tornBytes);

      // Perform recovery
      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.recoveredTornTail, true);
      assert.ok(recResult.tornSidecarPath);
      assert.strictEqual(recResult.terminalSequence, 2);
      assert.strictEqual(recResult.nextSequence, 3);

      // Check sidecar properties: 0600 mode, regular file, nlink 1, exact torn bytes
      const sidecarStat = fs.statSync(recResult.tornSidecarPath);
      assert.strictEqual(sidecarStat.isFile(), true);
      assert.strictEqual(sidecarStat.mode & 0o777, 0o600);
      assert.strictEqual(sidecarStat.nlink, 1);
      assert.strictEqual(sidecarStat.uid, currentUid);
      const sidecarBytes = fs.readFileSync(recResult.tornSidecarPath);
      assert.deepStrictEqual(sidecarBytes, tornBytes);

      // Verify active file bytes are truncated to exact initial bytes
      const currentActiveBytes = fs.readFileSync(activePath);
      assert.deepStrictEqual(currentActiveBytes, initialBytes);

      // Verify storage is active and can append cleanly as sequence 3
      const rec3 = await recResult.storage.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:02.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't3', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:02.000Z',
          endTime: '2026-09-21T08:00:02.001Z',
          durationMs: 1,
        },
      });

      assert.strictEqual(rec3.sequenceNumber, 3);
      recResult.storage.close();
    });

    test('RC06-NEG-37 (Case B): Malformed JSON line at EOF recovers to sidecar', async () => {
      const config = createTestStoreConfig('neg-37-case-b');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const malformedLine = '{"schemaVersion":1,"invalidJson":broken\n';
      fs.appendFileSync(activePath, malformedLine);

      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.recoveredTornTail, true);
      assert.ok(recResult.tornSidecarPath);
      assert.strictEqual(recResult.terminalSequence, 1);

      const sidecarBytes = fs.readFileSync(recResult.tornSidecarPath, 'utf8');
      assert.strictEqual(sidecarBytes, malformedLine);
      recResult.storage.close();
    });

    test('RC06-NEG-38: Torn tail accompanied by historical corruption fails closed (no truncation, no sidecar)', async () => {
      const config = createTestStoreConfig('neg-38');
      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);

      // Create store metadata
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();
      storage1.close();

      // Write seq 1, then corrupted seq 2 (gap or bad hash), then torn tail
      const r1 = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const r2 = createSampleRecord(2, 'f'.repeat(64)); // Corrupted hash link
      const line1 = serializeRecordV1(r1);
      const line2 = serializeRecordV1(r2);
      const tornTail = '{"schemaVersion":1,"unterminated":true';
      const fileBytes = Buffer.from(line1 + line2 + tornTail, 'utf8');
      fs.writeFileSync(activePath, fileBytes, { mode: 0o600 });

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorage(config);
        },
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED',
      );

      // Assert active bytes unchanged
      const bytesAfter = fs.readFileSync(activePath);
      assert.deepStrictEqual(bytesAfter, fileBytes);

      // Assert zero sidecar files created
      const files = fs.readdirSync(config.directory);
      const sidecars = files.filter((f) => f.includes('.torn.'));
      assert.strictEqual(sidecars.length, 0);
    });

    test('RC06-NEG-39: Attempted sequence number reset to 1 rejected; recovered storage resumes at terminal + 1', async () => {
      const config = createTestStoreConfig('neg-39');

      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();
      const r1 = await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      // 1. If someone manually appends a record with seq 1 to non-empty store:
      const resetRecord = createSampleRecord(
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
      );
      const resetActivePath = path.join(tempBaseDir, 'neg-39-tampered.jsonl');
      fs.writeFileSync(resetActivePath, serializeRecordV1(r1) + serializeRecordV1(resetRecord), {
        mode: 0o600,
      });

      assert.throws(
        () => verifyActiveStream(resetActivePath, currentUid),
        (err) => err.code === 'AUDIT_CORRUPTION_DETECTED' && err.message.includes('discontinuity'),
      );

      // 2. Legitimate recovery opens store and proves sequence continues at terminal + 1 (2):
      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.terminalSequence, 1);
      assert.strictEqual(recResult.nextSequence, 2);

      const r2 = await recResult.storage.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't2', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:01.001Z',
          durationMs: 1,
        },
      });

      assert.strictEqual(r2.sequenceNumber, 2);
      assert.strictEqual(r2.integrity.previousRecordHash, r1.integrity.recordHash);
      recResult.storage.close();
    });
  });

  describe('5. Negative Controls: RC06-NEG-46..47 (Lifecycle Crash Recovery & Reconciliation)', () => {
    test('RC06-NEG-46: Dangling STARTED emits RECOVERY_INDETERMINATE, subsequent restart is idempotent', async () => {
      const config = createTestStoreConfig('neg-46');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const opId = randomUUID();
      const started = await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'agent-1', clientType: 'user', deviceId: 'dev-1', sessionId: 'sess-1' },
        target: { workspaceId: 'ws-1', workspacePath: '', workspaceRootHash: '1'.repeat(64) },
        invocation: {
          toolName: 'modify_file',
          parametersRedacted: { p: 1 },
          payloadHash: '2'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'rule-mut', evaluationDurationMs: 2 },
        approval: {
          eventType: 'APPROVAL_REQUESTED',
          requestId: 'req-1',
          state: 'APPROVED',
          source: 'LOCAL_OPERATOR',
        },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.002Z',
          durationMs: 2,
        },
        lifecycle: {
          operationId: opId,
          phase: 'STARTED',
        },
      });

      // Simulate crash: storage closed before COMPLETED is appended
      storage1.close();

      // First restart recovery
      const recResult1 = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult1.indeterminateRecoveries, 1);
      assert.strictEqual(recResult1.terminalSequence, 2);
      assert.strictEqual(recResult1.nextSequence, 3);

      // Verify the generated recovery record on disk
      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 2);

      const recoveryRec = JSON.parse(lines[1]);
      assert.strictEqual(recoveryRec.sequenceNumber, 2);
      assert.strictEqual(recoveryRec.integrity.previousRecordHash, started.integrity.recordHash);
      assert.strictEqual(recoveryRec.lifecycle.operationId, opId);
      assert.strictEqual(recoveryRec.lifecycle.phase, 'RECOVERY_INDETERMINATE');
      assert.deepStrictEqual(recoveryRec.actor, {
        clientId: 'system',
        clientType: 'SYSTEM',
        deviceId: '',
        sessionId: '',
      });
      assert.strictEqual(recoveryRec.execution.status, 'ERROR');
      assert.strictEqual(recoveryRec.execution.durationMs, 0);
      assert.strictEqual(recoveryRec.execution.startTime, recoveryRec.execution.endTime);
      assert.deepStrictEqual(recoveryRec.error, {
        code: 'AUDIT_OUTCOME_INDETERMINATE',
        message: 'Prior operation outcome is indeterminate after crash recovery.',
      });
      assert.deepStrictEqual(recoveryRec.target, started.target);
      assert.deepStrictEqual(recoveryRec.invocation, started.invocation);
      assert.deepStrictEqual(recoveryRec.policy, started.policy);
      assert.deepStrictEqual(recoveryRec.approval, started.approval);
      assert.strictEqual(recoveryRec.gateway, undefined);

      recResult1.storage.close();

      // Second restart recovery: MUST be idempotent (zero new recovery records)
      const recResult2 = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult2.indeterminateRecoveries, 0);
      assert.strictEqual(recResult2.terminalSequence, 2);
      assert.strictEqual(recResult2.nextSequence, 3);
      recResult2.storage.close();
    });

    test('RC06-NEG-47: Recovery append failure fails closed; partial progress is preserved and completed on next restart', async () => {
      const config = createTestStoreConfig('neg-47');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const opId1 = randomUUID();
      const opId2 = randomUUID();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'agent', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w', workspacePath: '', workspaceRootHash: '1'.repeat(64) },
        invocation: { toolName: 't', parametersRedacted: {}, payloadHash: '2'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opId1, phase: 'STARTED' },
      });

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'agent', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w', workspacePath: '', workspaceRootHash: '1'.repeat(64) },
        invocation: { toolName: 't', parametersRedacted: {}, payloadHash: '2'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:01.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opId2, phase: 'STARTED' },
      });

      storage1.close();

      // Simulate failure on second recovery append (index 1) after first append succeeds
      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: {
              failRecoveryAppendAtIndex: 1,
            },
          });
        },
        (err) => err.code === 'AUDIT_RECOVERY_FAILED',
      );

      // Verify that store lock was cleaned up
      const lockPath = path.join(config.directory, 'audit.lock');
      assert.strictEqual(fs.existsSync(lockPath), false);

      // Verify durable partial progress: Op 1 recovery record was persisted at sequence 3
      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const linesAfterPartial = fs.readFileSync(activePath, 'utf8').trim().split('\n');
      assert.strictEqual(linesAfterPartial.length, 3);
      const rec1 = JSON.parse(linesAfterPartial[2]);
      assert.strictEqual(rec1.sequenceNumber, 3);
      assert.strictEqual(rec1.lifecycle.operationId, opId1);
      assert.strictEqual(rec1.lifecycle.phase, 'RECOVERY_INDETERMINATE');

      // Second restart: Op 1 is already terminal; only Op 2 is reconciled (indeterminateRecoveries === 1)
      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.indeterminateRecoveries, 1);
      assert.strictEqual(recResult.terminalSequence, 4);
      assert.strictEqual(recResult.nextSequence, 5);

      const linesAfterFinal = fs.readFileSync(activePath, 'utf8').trim().split('\n');
      assert.strictEqual(linesAfterFinal.length, 4);
      const rec2 = JSON.parse(linesAfterFinal[3]);
      assert.strictEqual(rec2.sequenceNumber, 4);
      assert.strictEqual(rec2.lifecycle.operationId, opId2);
      assert.strictEqual(rec2.lifecycle.phase, 'RECOVERY_INDETERMINATE');
      assert.strictEqual(rec2.integrity.previousRecordHash, rec1.integrity.recordHash);

      recResult.storage.close();
    });
  });

  describe('6. Lifecycle Structural Invariants & Failure Matrix (AUDIT_LIFECYCLE_CORRUPTION)', () => {
    const invalidLifecycleCases = [
      {
        name: 'COMPLETED without prior STARTED',
        records: (opId) => [
          createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'COMPLETED' },
          }),
        ],
      },
      {
        name: 'RECOVERY_INDETERMINATE without prior STARTED',
        records: (opId) => [
          createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'RECOVERY_INDETERMINATE' },
          }),
        ],
      },
      {
        name: 'DENIED followed by STARTED',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'DENIED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          return [r1, r2];
        },
      },
      {
        name: 'STARTED followed by DENIED',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'DENIED' },
          });
          return [r1, r2];
        },
      },
      {
        name: 'STARTED -> COMPLETED -> another record with same opId',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'COMPLETED' },
          });
          const r3 = createSampleRecord(3, r2.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'COMPLETED' },
          });
          return [r1, r2, r3];
        },
      },
      {
        name: 'STARTED -> RECOVERY_INDETERMINATE -> another record with same opId',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'RECOVERY_INDETERMINATE' },
          });
          const r3 = createSampleRecord(3, r2.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'COMPLETED' },
          });
          return [r1, r2, r3];
        },
      },
      {
        name: 'Duplicate STARTED records',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          return [r1, r2];
        },
      },
      {
        name: 'Duplicate DENIED records',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'DENIED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'DENIED' },
          });
          return [r1, r2];
        },
      },
      {
        name: 'COMPLETED followed by RECOVERY_INDETERMINATE',
        records: (opId) => {
          const r1 = createSampleRecord(1, '0'.repeat(64), {
            lifecycle: { operationId: opId, phase: 'STARTED' },
          });
          const r2 = createSampleRecord(2, r1.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'COMPLETED' },
          });
          const r3 = createSampleRecord(3, r2.integrity.recordHash, {
            lifecycle: { operationId: opId, phase: 'RECOVERY_INDETERMINATE' },
          });
          return [r1, r2, r3];
        },
      },
    ];

    for (const c of invalidLifecycleCases) {
      test(`Lifecycle corruption rejected: ${c.name}`, () => {
        const opId = randomUUID();
        const activePath = path.join(tempBaseDir, `lc-corrupt-${randomUUID()}.jsonl`);
        const recs = c.records(opId);
        writeRecordsToFile(activePath, recs);

        assert.throws(
          () => verifyActiveStream(activePath, currentUid),
          (err) => err.code === 'AUDIT_LIFECYCLE_CORRUPTION',
        );
      });
    }
  });

  describe('7. Positive Lifecycle Flows & Multiple Dangling Operations Ordering', () => {
    test('Standalone DENIED record is valid, terminal, and not dangling', async () => {
      const config = createTestStoreConfig('pos-denied');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const opId = randomUUID();
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'DENY', ruleId: 'deny-rule', evaluationDurationMs: 1 },
        execution: {
          status: 'DENIED',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opId, phase: 'DENIED' },
      });
      storage1.close();

      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.indeterminateRecoveries, 0);
      assert.strictEqual(recResult.terminalSequence, 1);
      recResult.storage.close();
    });

    test('STARTED -> COMPLETED pair is valid, terminal, and not dangling', async () => {
      const config = createTestStoreConfig('pos-completed');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const opId = randomUUID();
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opId, phase: 'STARTED' },
      });

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:01.000Z',
          durationMs: 1000,
        },
        lifecycle: { operationId: opId, phase: 'COMPLETED' },
      });
      storage1.close();

      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.indeterminateRecoveries, 0);
      assert.strictEqual(recResult.terminalSequence, 2);
      recResult.storage.close();
    });

    test('Multiple interleaved dangling operations are reconciled in ascending sequence order of originating STARTED', async () => {
      const config = createTestStoreConfig('pos-multi-dangling');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const opIdA = randomUUID();
      const opIdB = randomUUID();
      const opIdC = randomUUID();

      // Op A started at seq 1
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: {
          toolName: 'tA',
          parametersRedacted: { id: 'A' },
          payloadHash: 'b'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opIdA, phase: 'STARTED' },
      });

      // Op B started at seq 2
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: {
          toolName: 'tB',
          parametersRedacted: { id: 'B' },
          payloadHash: 'b'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:01.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opIdB, phase: 'STARTED' },
      });

      // Op C started at seq 3
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:02.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: {
          toolName: 'tC',
          parametersRedacted: { id: 'C' },
          payloadHash: 'b'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:02.000Z',
          endTime: '2026-09-21T08:00:02.001Z',
          durationMs: 1,
        },
        lifecycle: { operationId: opIdC, phase: 'STARTED' },
      });

      // Op B completed at seq 4 (so only A and C are dangling)
      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:03.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: {
          toolName: 'tB',
          parametersRedacted: { id: 'B' },
          payloadHash: 'b'.repeat(64),
        },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:03.000Z',
          durationMs: 2000,
        },
        lifecycle: { operationId: opIdB, phase: 'COMPLETED' },
      });

      storage1.close();

      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.indeterminateRecoveries, 2);
      assert.strictEqual(recResult.terminalSequence, 6);

      // Check the appended recovery records in order:
      // Seq 5 must be Op A (originating seq 1)
      // Seq 6 must be Op C (originating seq 3)
      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const lines = fs.readFileSync(activePath, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 6);

      const r5 = JSON.parse(lines[4]);
      const r6 = JSON.parse(lines[5]);

      assert.strictEqual(r5.sequenceNumber, 5);
      assert.strictEqual(r5.lifecycle.operationId, opIdA);
      assert.strictEqual(r5.invocation.parametersRedacted.id, 'A');

      assert.strictEqual(r6.sequenceNumber, 6);
      assert.strictEqual(r6.lifecycle.operationId, opIdC);
      assert.strictEqual(r6.invocation.parametersRedacted.id, 'C');

      recResult.storage.close();
    });
  });

  describe('8. Sidecar Security, Collision & Durability Failure Safety', () => {
    test('Sidecar creation failure preserves active file unchanged and fails closed', async () => {
      const config = createTestStoreConfig('sidecar-fail-create');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const tornBytes = Buffer.from('{"torn":1');
      fs.appendFileSync(activePath, tornBytes);
      const fileBytesBefore = fs.readFileSync(activePath);

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: { failSidecarCreation: true },
          });
        },
        (err) => err.code === 'AUDIT_RECOVERY_FAILED',
      );

      const fileBytesAfter = fs.readFileSync(activePath);
      assert.deepStrictEqual(fileBytesAfter, fileBytesBefore);
    });

    test('Sidecar write failure preserves active file unchanged and fails closed', async () => {
      const config = createTestStoreConfig('sidecar-fail-write');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const tornBytes = Buffer.from('{"torn":2');
      fs.appendFileSync(activePath, tornBytes);
      const fileBytesBefore = fs.readFileSync(activePath);

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: { failSidecarWrite: true },
          });
        },
        (err) => err.code === 'AUDIT_RECOVERY_FAILED',
      );

      const fileBytesAfter = fs.readFileSync(activePath);
      assert.deepStrictEqual(fileBytesAfter, fileBytesBefore);
    });

    test('Sidecar fsync failure preserves active file unchanged, retains sidecar, and fails closed', async () => {
      const config = createTestStoreConfig('sidecar-fail-sync');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const tornBytes = Buffer.from('{"torn":2.5');
      fs.appendFileSync(activePath, tornBytes);
      const fileBytesBefore = fs.readFileSync(activePath);

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: { failSidecarSync: true },
          });
        },
        (err) => err.code === 'AUDIT_RECOVERY_FAILED',
      );

      // Active file MUST remain byte-for-byte unchanged
      const fileBytesAfter = fs.readFileSync(activePath);
      assert.deepStrictEqual(fileBytesAfter, fileBytesBefore);

      // Sidecar file remains as retained forensic evidence
      const files = fs.readdirSync(config.directory);
      const sidecars = files.filter((f) => f.includes('.torn.'));
      assert.strictEqual(sidecars.length, 1);
      const sidecarContent = fs.readFileSync(path.join(config.directory, sidecars[0]));
      assert.deepStrictEqual(sidecarContent, tornBytes);
    });

    test('Truncation failure retains sidecar as forensic evidence and fails closed', async () => {
      const config = createTestStoreConfig('sidecar-fail-trunc');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      const tornBytes = Buffer.from('{"torn":3');
      fs.appendFileSync(activePath, tornBytes);

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: { failTruncation: true },
          });
        },
        (err) => err.code === 'AUDIT_RECOVERY_FAILED',
      );

      // Sidecar MUST remain as retained forensic evidence
      const files = fs.readdirSync(config.directory);
      const sidecars = files.filter((f) => f.includes('.torn.'));
      assert.strictEqual(sidecars.length, 1);
      const sidecarContent = fs.readFileSync(path.join(config.directory, sidecars[0]));
      assert.deepStrictEqual(sidecarContent, tornBytes);
    });

    test('Sidecar collision safety: pre-existing sidecar path causes collision-free naming', async () => {
      const config = createTestStoreConfig('sidecar-collision');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      fs.appendFileSync(activePath, '{"torn":4');

      // Pre-create the candidate sidecar path with distinct content
      const fixedTimestamp = '2026-09-21T08-30-00.000Z';
      const collidingSidecar = path.join(
        config.directory,
        `${ACTIVE_SEGMENT_FILENAME}.torn.${fixedTimestamp}`,
      );
      const preExistingContent = Buffer.from('PRE_EXISTING_DO_NOT_OVERWRITE');
      fs.writeFileSync(collidingSidecar, preExistingContent, { mode: 0o600 });

      // Run recovery with fixedTimestamp
      const recResult = await recoverPersistentAuditStorageForTest(config, {
        testHooks: { sidecarTimestamp: fixedTimestamp },
      });

      assert.strictEqual(recResult.recoveredTornTail, true);
      assert.notStrictEqual(recResult.tornSidecarPath, collidingSidecar);
      assert.ok(recResult.tornSidecarPath.startsWith(collidingSidecar));

      // Assert pre-existing sidecar was NOT overwritten
      const preExistingAfter = fs.readFileSync(collidingSidecar);
      assert.deepStrictEqual(preExistingAfter, preExistingContent);

      recResult.storage.close();
    });

    test('Active file same-inode growth before truncation fails closed (no truncation, new bytes preserved)', async () => {
      const config = createTestStoreConfig('same-inode-growth');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      fs.appendFileSync(activePath, '{"torn":6');

      const statBefore = fs.statSync(activePath);
      let statAfterAppend = null;

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: {
              beforeTruncate: () => {
                // Append extra bytes to the SAME file/inode without unlinking or replacing
                const extraFd = fs.openSync(
                  activePath,
                  fs.constants.O_WRONLY | fs.constants.O_APPEND,
                );
                fs.writeSync(extraFd, Buffer.from('EXTRA_CONCURRENT_GROWTH'));
                fs.closeSync(extraFd);

                statAfterAppend = fs.statSync(activePath);
                // Inode remains identical, size increases
                assert.strictEqual(statAfterAppend.ino, statBefore.ino);
                assert.strictEqual(statAfterAppend.dev, statBefore.dev);
                assert.ok(statAfterAppend.size > statBefore.size);
              },
            },
          });
        },
        (err) =>
          err.code === 'AUDIT_RECOVERY_FAILED' &&
          err.message.includes('size changed unexpectedly before truncation'),
      );

      // Verify that ftruncate never occurred: active file bytes match exact bytes after injected growth
      const currentBytes = fs.readFileSync(activePath);
      assert.strictEqual(currentBytes.length, statAfterAppend.size);
      assert.ok(currentBytes.toString('utf8').includes('EXTRA_CONCURRENT_GROWTH'));
    });

    test('Active file same-inode shrink before truncation fails closed (no truncation)', async () => {
      const config = createTestStoreConfig('same-inode-shrink');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      fs.appendFileSync(activePath, '{"torn":7');

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: {
              beforeTruncate: () => {
                // Shrink file to smaller size
                fs.truncateSync(activePath, 10);
              },
            },
          });
        },
        (err) =>
          err.code === 'AUDIT_RECOVERY_FAILED' &&
          err.message.includes('size changed unexpectedly before truncation'),
      );
    });

    test('Active file replacement race safety: pathname replacement between verification and truncation fails closed', async () => {
      const config = createTestStoreConfig('replace-race');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      fs.appendFileSync(activePath, '{"torn":5');

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: {
              beforeTruncate: () => {
                // Replace active file with a new file before truncation using different inode
                const replPath = path.join(tempBaseDir, `repl-${randomUUID()}`);
                fs.writeFileSync(replPath, 'SUBSTITUTED_FILE', { mode: 0o600 });
                fs.renameSync(replPath, activePath);
              },
            },
          });
        },
        (err) =>
          err.code === 'AUDIT_RECOVERY_FAILED' &&
          (err.message.includes('identity changed') || err.message.includes('size changed')),
      );
    });

    test('Active file replacement race safety: replacement before final append activation fails closed', async () => {
      const config = createTestStoreConfig('replace-race-append');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);

      await assert.rejects(
        async () => {
          await recoverPersistentAuditStorageForTest(config, {
            testHooks: {
              beforeFinalAppendOpen: () => {
                // Replace active file right before final append open using different inode
                const orig = fs.readFileSync(activePath);
                const replPath = path.join(tempBaseDir, `repl-append-${randomUUID()}`);
                fs.writeFileSync(replPath, orig, { mode: 0o600 });
                fs.renameSync(replPath, activePath);
              },
            },
          });
        },
        (err) =>
          err.code === 'AUDIT_RECOVERY_FAILED' &&
          err.message.includes('Active file replacement detected'),
      );
    });
  });

  describe('9. Positive Restart Continuation Integration', () => {
    test('Clean restart continuation: multiple records written, cleanly closed, recovered without torn/dangling', async () => {
      const config = createTestStoreConfig('pos-restart-clean');

      // First run: fresh store
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      const r1 = await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 'read_dir', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      assert.strictEqual(r1.sequenceNumber, 1);

      const r2 = await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:01.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:01.000Z',
          endTime: '2026-09-21T08:00:01.001Z',
          durationMs: 1,
        },
      });

      storage1.close();

      // Second run: restart through Task-2 recovery
      const recResult = await recoverPersistentAuditStorage(config);
      assert.strictEqual(recResult.recoveredTornTail, false);
      assert.strictEqual(recResult.indeterminateRecoveries, 0);
      assert.strictEqual(recResult.terminalSequence, 2);
      assert.strictEqual(recResult.terminalRecordHash, r2.integrity.recordHash);
      assert.strictEqual(recResult.nextSequence, 3);

      // Third record appended seamlessly
      const r3 = await recResult.storage.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:02.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 'write_file', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:02.000Z',
          endTime: '2026-09-21T08:00:02.001Z',
          durationMs: 1,
        },
      });

      assert.strictEqual(r3.sequenceNumber, 3);
      assert.strictEqual(r3.integrity.previousRecordHash, r2.integrity.recordHash);
      recResult.storage.close();

      // Re-verify entire file on disk
      const finalVerification = verifyActiveStream(
        path.join(config.directory, ACTIVE_SEGMENT_FILENAME),
        currentUid,
      );
      assert.strictEqual(finalVerification.status, 'VERIFIED');
      assert.strictEqual(finalVerification.recordCount, 3);
      assert.strictEqual(finalVerification.terminalSequence, 3);
      assert.strictEqual(finalVerification.terminalRecordHash, r3.integrity.recordHash);
    });
  });

  describe('10. Public API Surface & Capability Boundary Verification', () => {
    test('Public API root does not expose RECOVERY_HANDOFF_TOKEN or internal testing helpers', async () => {
      const auditPublic = await import('../packages/audit/dist/index.js');
      assert.strictEqual(auditPublic.RECOVERY_HANDOFF_TOKEN, undefined);
      assert.strictEqual(auditPublic.VerifiedRecoveryHandoff, undefined);
      assert.strictEqual(auditPublic.RecoveryTestHooks, undefined);
      assert.strictEqual(auditPublic.TestAuditRecoveryOptions, undefined);
      assert.strictEqual(auditPublic.recoverPersistentAuditStorageForTest, undefined);
      assert.strictEqual(auditPublic.executeAuditRecoveryInternal, undefined);
      assert.strictEqual(auditPublic.StorageTestFaults, undefined);
      assert.strictEqual(auditPublic.StorageTestHooks, undefined);
      assert.strictEqual(auditPublic.createTestPersistentAuditStorage, undefined);
      assert.strictEqual(auditPublic.STORAGE_TEST_TOKEN, undefined);
    });

    test('PersistentAuditStorage._fromVerifiedRecovery rejects unauthorized invocation without internal symbol', async () => {
      const auditPublic = await import('../packages/audit/dist/index.js');
      const fakeToken = Symbol('RECOVERY_HANDOFF_TOKEN');
      assert.throws(
        () => {
          auditPublic.PersistentAuditStorage._fromVerifiedRecovery(
            fakeToken,
            { directory: '/tmp/test' },
            {},
          );
        },
        (err) =>
          err.code === 'AUDIT_STORAGE_INVALID_STATE' &&
          err.message.includes('unauthorized recovery handoff'),
      );
    });

    test('Production recoverPersistentAuditStorage rejects test hooks and accepts only production options', async () => {
      const config = createTestStoreConfig('pub-api-no-hooks');
      const storage1 = new PersistentAuditStorage(config);
      storage1.initialize();

      await storage1.append({
        eventId: randomUUID(),
        timestamp: '2026-09-21T08:00:00.000Z',
        actor: { clientId: 'c1', clientType: 'admin', deviceId: '', sessionId: '' },
        target: { workspaceId: 'w1', workspacePath: '', workspaceRootHash: 'a'.repeat(64) },
        invocation: { toolName: 't1', parametersRedacted: {}, payloadHash: 'b'.repeat(64) },
        policy: { decision: 'ALLOW', ruleId: 'r1', evaluationDurationMs: 1 },
        execution: {
          status: 'SUCCESS',
          startTime: '2026-09-21T08:00:00.000Z',
          endTime: '2026-09-21T08:00:00.001Z',
          durationMs: 1,
        },
      });
      storage1.close();

      const activePath = path.join(config.directory, ACTIVE_SEGMENT_FILENAME);
      fs.appendFileSync(activePath, '{"torn":8');

      // Calling public recoverPersistentAuditStorage with testHooks ignored
      // (it will NOT trigger failTruncation because public API does not accept testHooks)
      const res = await recoverPersistentAuditStorage(config, {
        testHooks: { failTruncation: true },
      });
      assert.strictEqual(res.recoveredTornTail, true);
      res.storage.close();
    });
  });
});
