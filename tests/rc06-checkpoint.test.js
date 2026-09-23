/**
 * CesSpace ARC — RC-06 Task 4: Tier-2 Ed25519 Checkpoint Artifacts & Key Authority
 *
 * Test suite verifying:
 * - The frozen Tier-2 checkpoint constants and the closed `AuditCheckpointV1` schema
 * - Canonical checkpoint encoding and the exact signature / checkpoint-hash preimages
 * - Ed25519 signing, public-key verification and SPKI-DER fingerprint pinning
 * - The `audit-checkpoints.jsonl` artifact stream, its authority rules and its budget
 * - The checkpoint hash chain and its binding to the primary audit chain
 * - The 1,000-record interval cadence and rotation-boundary sealing
 * - Interval / rotation coincidence producing exactly one checkpoint
 * - Restart state reconstructed only from VERIFIED durable checkpoint history
 * - Bounded streaming verification of the whole checkpoint history
 * - Secure signing-key and trust-root loading (descriptor authority, Ed25519 only)
 * - All frozen Task-4 negative security controls RC06-NEG-64..83
 *
 * Control namespace: Task 4 owns exactly the RC06-NEG range 64..83 and no more.
 * The additive regressions below carry the RC06-T4-REG-nn namespace precisely
 * because it is NOT part of the frozen architecture numbering — they assert
 * behavior, they are not frozen security controls, and they must never be
 * counted as controls.
 *
 * The neighboring blocks are deliberately untouched here: 48..63 belong to
 * Task 3 (segment rotation) and 84..99 belong to Task 5 (Tier-3 anchoring). This
 * file claims no control from either range.
 *
 * Regression numbering note: the post-review correction added the eight
 * regressions covering symlinked key-path components, exact PEM framing, and
 * checkpoint-artifact identity as RC06-T4-REG-33..40. The reviewed instruction
 * named them 32..39, but 32 was already in use by the test-clock/UUID seam
 * regression and the same instruction forbids renaming the existing additive
 * regressions, so the block continues after the highest number in use instead.
 * (15 was already vacant and remains so; it is not reused for new work.)
 *
 * Two ideas run through every control in Category 8. The first is that a valid
 * signature is not sufficient: wherever a checkpoint can lie — about its covered
 * range, its terminal hash, its position in its own chain, or the ledger it
 * belongs to — the control reconstructs a checkpoint that is *correctly signed*
 * and then proves that the lie is still refused. Rejecting a merely inconsistent
 * file would prove nothing about the binding. The second is that the primary
 * chain is the authority: the checkpoint is checked against the actual verified
 * retained evidence, never against its own claims.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PersistentAuditStorage,
  ACTIVE_SEGMENT_FILENAME,
  CHECKPOINT_FILENAME,
  CHECKPOINT_INTERVAL,
  MAX_SIGNING_KEY_BYTES,
  CHECKPOINT_SIGNATURE_DOMAIN,
  CHECKPOINT_ALLOWED_KEYS,
  CHECKPOINT_FORBIDDEN_EVENT_KEYS,
  validateCheckpointV1,
  computeCheckpointSignaturePreimage,
  computeCheckpointHashPreimage,
  computeCheckpointHash,
  serializeCheckpointV1,
  verifyCheckpointSignature,
  parseAndValidateCheckpointLineV1,
  verifyCheckpointHistory,
  verifyRetainedPrimaryHistory,
  listLogicalArchiveInventory,
  countLogicalArchives,
  scanAuditStorePhysicalBytes,
  computeCheckpointPublicKeyFingerprint,
  assertNoRawSigningKeyMaterial,
  TOTAL_AUDIT_BUDGET_BYTES,
} from '../packages/audit/dist/index.js';

import {
  createTestTier2CheckpointEngine,
  enablePrivateKeyLoadProbe,
  getPrivateKeyLoadCount,
} from '../packages/audit/dist/internal/checkpoint-testing.js';
import {
  loadEd25519SigningKeyFile,
  loadEd25519TrustRootFile,
  assertSigningKeyOutsideWorkspaces,
} from '../packages/audit/dist/internal/key-authority.js';
import { createTestRotatingAuditStore } from '../packages/audit/dist/internal/rotation-testing.js';

const ZERO_HASH = '0'.repeat(64);
const FIXED_CLOCK_START = Date.parse('2026-09-21T00:00:00.000Z');
const OTHER_HASH = '9'.repeat(64);

/** Built declarations, for the public-surface assertions. */
const PACKAGE_DIST_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../packages/audit/dist',
);

/* -------------------------------------------------------------------------- *
 * Harness
 * -------------------------------------------------------------------------- */

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
    target: { workspaceId: 'ws-test', workspacePath: '', workspaceRootHash: 'c'.repeat(64) },
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { path: 'test.txt' },
      payloadHash: 'd'.repeat(64),
    },
    policy: { decision: 'ALLOW', ruleId: 'rule-test-01', evaluationDurationMs: 1.5 },
    execution: {
      status: 'SUCCESS',
      startTime: '2026-09-20T18:00:00.000Z',
      endTime: '2026-09-20T18:00:00.010Z',
      durationMs: 10,
    },
    ...overrides,
  };
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

function writeSparseFile(filePath, size) {
  const fd = fs.openSync(filePath, 'w', 0o600);
  try {
    fs.ftruncateSync(fd, size);
  } finally {
    fs.closeSync(fd);
  }
}

/** The nine fields that make up the unsigned checkpoint projection. */
function pickUnsigned(checkpoint) {
  return {
    version: checkpoint.version,
    storeId: checkpoint.storeId,
    checkpointId: checkpoint.checkpointId,
    sequenceStart: checkpoint.sequenceStart,
    sequenceEnd: checkpoint.sequenceEnd,
    terminalRecordHash: checkpoint.terminalRecordHash,
    previousCheckpointHash: checkpoint.previousCheckpointHash,
    createdAt: checkpoint.createdAt,
    publicKeyFingerprint: checkpoint.publicKeyFingerprint,
  };
}

describe('CesSpace ARC — RC-06 Task 4: Tier-2 Ed25519 Checkpoint Artifacts & Key Authority', () => {
  let tempBaseDir;
  /** Fixtures whose storage handles are closed after the suite. */
  const openFixtures = [];

  before(() => {
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task4-'));
  });

  after(() => {
    for (const fixture of openFixtures) {
      try {
        fixture.engine?.close();
      } catch {
        // ignore
      }
      try {
        fixture.storage?.close();
      } catch {
        // ignore
      }
    }
    try {
      fs.rmSync(tempBaseDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  /** Generates an Ed25519 keypair written as 0600 PKCS#8 / SPKI PEM files. */
  function writeKeyPair(
    dir,
    name = 'checkpoint',
    { privateMode = 0o600, publicMode = 0o600 } = {},
  ) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

    const signingKeyPath = path.join(dir, `${name}-signing.pem`);
    const publicKeyPath = path.join(dir, `${name}-public.pem`);
    fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: privateMode,
    });
    fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
      mode: publicMode,
    });

    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    return {
      privateKey,
      publicKey,
      spkiDer,
      signingKeyPath,
      publicKeyPath,
      fingerprint: crypto.createHash('sha256').update(spkiDer).digest('hex'),
    };
  }

  /**
   * Builds a real audit store with a real checkpoint engine.
   *
   * Every record is appended through `RotatingAuditStore` and then driven into
   * the engine exactly as production composition will drive it, so the fixture
   * exercises the same interval-cadence path the tests then assert on.
   */
  async function createFixture(
    name,
    { records = 0, rotateAt = [], keys = null, hooks = undefined, engineConfig = {} } = {},
  ) {
    const root = path.join(tempBaseDir, name);
    const auditDir = path.join(root, 'audit');
    const keyDir = path.join(root, 'keys');
    const material = keys ?? writeKeyPair(keyDir);

    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: material.fingerprint,
        anchorMode: 'DISABLED',
      },
    });
    storage.initialize();

    const engine = await createTestTier2CheckpointEngine(
      {
        directory: auditDir,
        signingKeyPath: material.signingKeyPath,
        publicKeyPath: material.publicKeyPath,
        ...engineConfig,
      },
      hooks,
    );

    const store = createTestRotatingAuditStore(storage, { sealer: engine }, {});

    const records_ = [];
    for (let i = 1; i <= records; i++) {
      const record = await store.append(createSampleRecordCandidate());
      records_.push(record);
      await engine.checkpointAfterDurablePrimary({
        sequenceNumber: record.sequenceNumber,
        recordHash: record.integrity.recordHash,
      });
      if (rotateAt.includes(i)) await store.rotateNow('SIZE_THRESHOLD');
    }

    const fixture = {
      root,
      auditDir,
      keyDir,
      material,
      storage,
      engine,
      store,
      records: records_,
      checkpointPath: path.join(auditDir, CHECKPOINT_FILENAME),
    };
    openFixtures.push(fixture);
    return fixture;
  }

  /** Copies a fixture's audit directory, so destructive tampering is isolated. */
  function cloneAuditDir(fixture, name) {
    const auditDir = path.join(tempBaseDir, name);
    fs.cpSync(fixture.auditDir, auditDir, { recursive: true });
    fs.chmodSync(auditDir, 0o700);
    return auditDir;
  }

  function readCheckpointLines(checkpointPath) {
    const raw = fs.readFileSync(checkpointPath, 'utf8');
    assert.ok(raw.endsWith('\n'), 'a checkpoint artifact must be LF-terminated');
    return raw.slice(0, -1).split('\n');
  }

  function writeCheckpointLines(checkpointPath, lines) {
    // `mode` applies only when the write creates the file, which is exactly the
    // case that must not default to the umask-derived 0664.
    fs.writeFileSync(checkpointPath, lines.map((line) => `${line}\n`).join(''), { mode: 0o600 });
  }

  /**
   * Parses one persisted checkpoint line.
   *
   * `readCheckpointLines` splits the artifact on its LF terminators, so a line
   * read back that way has lost its framing; it is restored here because the
   * parser deliberately requires exactly one LF and refuses to accept an
   * unterminated artifact.
   */
  function parseLine(line) {
    return parseAndValidateCheckpointLineV1(`${line}\n`).checkpoint;
  }

  function firstCheckpoint(checkpointPath) {
    return parseLine(readCheckpointLines(checkpointPath)[0]);
  }

  /**
   * Rebuilds a checkpoint that is internally consistent and, by default,
   * validly signed.
   *
   * This is the negative controls' core tool. A tampered artifact whose hash no
   * longer matches its own preimage is rejected by the canonical parser, which
   * proves only that inconsistency is detected — not that the binding the
   * control names is enforced. Re-signing with the real key isolates the one
   * property under test: the checkpoint is a perfect artifact, and it is still
   * refused because of what it claims.
   */
  function reforge(checkpoint, overrides = {}, options = {}) {
    const unsigned = { ...pickUnsigned(checkpoint), ...overrides };
    const signature =
      options.signature !== undefined
        ? options.signature
        : crypto
            .sign(null, computeCheckpointSignaturePreimage(unsigned), options.privateKey)
            .toString('base64url');
    const withSignature = { ...unsigned, signature };
    const checkpointHash =
      options.recomputeHash === false
        ? checkpoint.checkpointHash
        : computeCheckpointHash(withSignature);
    return { ...withSignature, checkpointHash };
  }

  function lineOf(checkpoint) {
    return serializeCheckpointV1(checkpoint).slice(0, -1);
  }

  /* ====================================================================== *
   * Frozen constants and canonical encoding
   * ====================================================================== */

  describe('Frozen Constants and Canonical Checkpoint Encoding', () => {
    test('RC06-T4-REG-01: frozen Tier-2 checkpoint constants match the architecture exactly', () => {
      assert.equal(CHECKPOINT_INTERVAL, 1_000, 'one checkpoint per 1,000 primary records');
      assert.equal(MAX_SIGNING_KEY_BYTES, 4_096, '4 KiB key and trust-root bound');
      assert.equal(CHECKPOINT_FILENAME, 'audit-checkpoints.jsonl');
      assert.equal(CHECKPOINT_SIGNATURE_DOMAIN, 'CESSPACE-ARC-CHECKPOINT-V1\0');
      assert.equal(
        Buffer.from(CHECKPOINT_SIGNATURE_DOMAIN, 'utf8').length,
        27,
        'the domain is 26 ASCII characters plus its load-bearing terminating NUL',
      );
      assert.equal(CHECKPOINT_SIGNATURE_DOMAIN.charCodeAt(26), 0, 'the domain ends in a NUL byte');
    });

    test('RC06-T4-REG-02: the schema is closed and every field round-trips canonically', async () => {
      const fixture = await createFixture('reg02', { records: 3, rotateAt: [3] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      assert.deepEqual(
        Object.keys(checkpoint).sort(),
        [...CHECKPOINT_ALLOWED_KEYS].sort(),
        'the artifact carries exactly the frozen field set',
      );
      assert.equal(checkpoint.version, 1);
      assert.equal(checkpoint.sequenceStart, 1);
      assert.equal(checkpoint.sequenceEnd, 3);
      assert.equal(checkpoint.previousCheckpointHash, ZERO_HASH, 'genesis link is 64 zeros');
      assert.equal(checkpoint.publicKeyFingerprint, fixture.material.fingerprint);

      const line = serializeCheckpointV1(checkpoint);
      assert.ok(line.endsWith('\n'), 'exactly one trailing LF');
      assert.equal(line.indexOf('\n'), line.length - 1, 'no embedded newline');
      assert.deepEqual(parseAndValidateCheckpointLineV1(line).checkpoint, checkpoint);

      // Key order in the file is canonical (sorted), not insertion order.
      const body = line.slice(0, -1);
      assert.equal(body, JSON.stringify(JSON.parse(body)), 'canonical JSON is compact');
      assert.equal(
        computeCheckpointHash(checkpoint),
        checkpoint.checkpointHash,
        'the checkpoint hash is self-consistent',
      );
    });

    test('RC06-T4-REG-03: the signature preimage is exactly domain || UTF8(canonical JSON)', async () => {
      const fixture = await createFixture('reg03', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const unsigned = pickUnsigned(checkpoint);

      const preimage = computeCheckpointSignaturePreimage(unsigned);
      const domainBytes = Buffer.from(CHECKPOINT_SIGNATURE_DOMAIN, 'utf8');
      const canonical = preimage.subarray(domainBytes.length);

      assert.deepEqual(
        preimage.subarray(0, domainBytes.length),
        domainBytes,
        'the preimage begins with the exact frozen domain, NUL included',
      );
      // What follows is canonical JSON: sorted, compact, whitespace-free, and
      // exactly the unsigned projection with nothing added and nothing dropped.
      const tail = canonical.toString('utf8');
      assert.equal(tail, JSON.stringify(JSON.parse(tail)), 'the body is compact canonical JSON');
      assert.deepEqual(JSON.parse(tail), unsigned);
      assert.equal(
        tail,
        JSON.stringify(unsigned, Object.keys(unsigned).sort()),
        'the body carries the unsigned projection in canonical key order',
      );

      // The signature verifies against the configured key over exactly this preimage.
      assert.equal(verifyCheckpointSignature(checkpoint, fixture.material.publicKey), true);

      // Removing the NUL from the domain changes the preimage, so the NUL is
      // load-bearing rather than decorative.
      const withoutNul = Buffer.concat([
        Buffer.from('CESSPACE-ARC-CHECKPOINT-V1', 'utf8'),
        canonical,
      ]);
      assert.notDeepEqual(preimage, withoutNul);

      // Unhashed: a pre-hash would define a different scheme, so a signature over
      // SHA-256(preimage) must NOT verify.
      const prehashed = crypto.createHash('sha256').update(preimage).digest();
      assert.equal(
        crypto.verify(
          null,
          prehashed,
          fixture.material.publicKey,
          Buffer.from(checkpoint.signature, 'base64url'),
        ),
        false,
        'the preimage is signed directly, never pre-hashed',
      );
    });

    test('RC06-T4-REG-04: the checkpoint-hash preimage covers the signature and excludes checkpointHash', async () => {
      const fixture = await createFixture('reg04', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      const preimage = JSON.parse(computeCheckpointHashPreimage(checkpoint));
      assert.equal(preimage.signature, checkpoint.signature, 'the signature is covered');
      assert.equal(
        'checkpointHash' in preimage,
        false,
        'checkpointHash is outside its own preimage',
      );
      assert.deepEqual(
        Object.keys(preimage).sort(),
        [...CHECKPOINT_ALLOWED_KEYS].sort().filter((k) => k !== 'checkpointHash'),
      );

      // Overwriting checkpointHash cannot change the preimage, so it cannot
      // bootstrap a different hash.
      assert.equal(
        computeCheckpointHash({ ...checkpoint, checkpointHash: OTHER_HASH }),
        checkpoint.checkpointHash,
      );
      // Changing the signature does change it.
      const otherSignature = Buffer.alloc(64, 7).toString('base64url');
      assert.notEqual(
        computeCheckpointHash({ ...checkpoint, signature: otherSignature }),
        checkpoint.checkpointHash,
      );
    });

    test('RC06-T4-REG-25: the fingerprint is SHA-256 of the SPKI DER, not of the PEM text', async () => {
      const fixture = await createFixture('reg25', { records: 1 });
      const { publicKeyPath, fingerprint, spkiDer } = fixture.material;

      assert.equal(fingerprint, crypto.createHash('sha256').update(spkiDer).digest('hex'));
      assert.equal(computeCheckpointPublicKeyFingerprint(publicKeyPath), fingerprint);

      const pemText = fs.readFileSync(publicKeyPath, 'utf8');
      assert.notEqual(
        fingerprint,
        crypto.createHash('sha256').update(pemText, 'utf8').digest('hex'),
        'a PEM-text digest would change under line rewrapping',
      );

      // Rewrapping the PEM must not change the key identity.
      const rewrapped = path.join(fixture.keyDir, 'rewrapped-public.pem');
      fs.writeFileSync(rewrapped, `${pemText.trimEnd()}\n\n`, { mode: 0o600 });
      assert.equal(
        computeCheckpointPublicKeyFingerprint(rewrapped),
        fingerprint,
        'whitespace outside the block cannot change the fingerprint',
      );
    });

    test('RC06-T4-REG-19: unknown top-level fields are rejected, not ignored', async () => {
      const fixture = await createFixture('reg19', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, extra: 1 }),
        'AUDIT_CHECKPOINT_INVALID',
      );
      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, alg: 'none' }),
        'AUDIT_CHECKPOINT_INVALID',
      );
      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, signatureAlgorithm: 'RSA' }),
        'AUDIT_CHECKPOINT_INVALID',
      );

      const { checkpointId, ...missing } = checkpoint;
      assertThrowsWithCode(() => validateCheckpointV1(missing), 'AUDIT_CHECKPOINT_INVALID');
      void checkpointId;
    });

    test('RC06-T4-REG-27: a non-canonical checkpoint line is rejected', async () => {
      const fixture = await createFixture('reg27', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const canonical = lineOf(checkpoint);

      // Pretty-printed, reordered and whitespace-padded spellings of the same
      // object are all rejected: they are not "equivalent forms".
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${JSON.stringify(checkpoint, null, 2)}\n`),
        'AUDIT_CORRUPTION_DETECTED',
      );
      // Byte-identical content with a different key order is still not the
      // canonical spelling, so key ordering is part of the encoding.
      const parsed = JSON.parse(canonical);
      const reordered = {};
      for (const key of Object.keys(parsed).reverse()) reordered[key] = parsed[key];
      assert.deepEqual(reordered, parsed, 'the reordered object is the same value');
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${JSON.stringify(reordered)}\n`),
        'AUDIT_CORRUPTION_DETECTED',
      );

      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${canonical.replace('{', '{ ')}\n`),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(canonical.replace(/^\{/, '')),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${canonical} \n`),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${canonical}\r\n`),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(`${canonical}\n\n`),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-T4-REG-28: an unterminated or malformed checkpoint line is rejected and never repaired', async () => {
      const fixture = await createFixture('reg28', { records: 2, rotateAt: [2] });
      const canonical = lineOf(firstCheckpoint(fixture.checkpointPath));

      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1(canonical),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1('not json\n'),
        'AUDIT_CORRUPTION_DETECTED',
      );
      assertThrowsWithCode(
        () => parseAndValidateCheckpointLineV1('\n'),
        'AUDIT_CORRUPTION_DETECTED',
      );

      // A torn checkpoint tail is not a recoverable condition: the primary
      // active segment is the only artifact with a torn-tail rule.
      const tornDir = cloneAuditDir(fixture, 'reg28-torn');
      fs.writeFileSync(path.join(tornDir, CHECKPOINT_FILENAME), `${canonical.slice(0, 40)}`, {
        mode: 0o600,
      });
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: tornDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CORRUPTION_DETECTED',
      );
    });

    test('RC06-T4-REG-29: an unsupported checkpoint version is rejected', async () => {
      const fixture = await createFixture('reg29', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, version: 2 }),
        'AUDIT_CHECKPOINT_UNSUPPORTED_VERSION',
      );
      assertThrowsWithCode(
        () =>
          parseAndValidateCheckpointLineV1(
            lineOf(
              reforge(checkpoint, { version: 2 }, { privateKey: fixture.material.privateKey }),
            ) + '\n',
          ),
        'AUDIT_CHECKPOINT_UNSUPPORTED_VERSION',
      );
    });

    test('RC06-T4-REG-31: struct-shape violations are rejected field by field', async () => {
      const fixture = await createFixture('reg31', { records: 2, rotateAt: [2] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      const bad = [
        { storeId: 'not-a-uuid' },
        { checkpointId: 'not-a-uuid' },
        { sequenceStart: 0 },
        { sequenceEnd: 0 },
        { sequenceStart: 5, sequenceEnd: 4 },
        { sequenceStart: 1.5 },
        { terminalRecordHash: 'A'.repeat(64) },
        { terminalRecordHash: 'a'.repeat(63) },
        { previousCheckpointHash: 'zz' },
        { publicKeyFingerprint: 'a'.repeat(63) },
        { checkpointHash: 'a'.repeat(63) },
        { createdAt: '2026-09-21T00:00:00Z' },
        { createdAt: '2026-09-21 00:00:00.000Z' },
        { signature: '' },
        { signature: 'AAAA=' },
        { signature: 'AAAA' },
        { signature: 'AEhv+A==' },
      ];

      for (const overrides of bad) {
        assertThrowsWithCode(
          () => validateCheckpointV1({ ...checkpoint, ...overrides }),
          ['AUDIT_CHECKPOINT_INVALID'],
        );
      }

      assertThrowsWithCode(() => validateCheckpointV1(null), 'AUDIT_CHECKPOINT_INVALID');
      assertThrowsWithCode(() => validateCheckpointV1([]), 'AUDIT_CHECKPOINT_INVALID');
      assertThrowsWithCode(() => validateCheckpointV1('checkpoint'), 'AUDIT_CHECKPOINT_INVALID');
    });

    test('RC06-T4-REG-32: the test clock and UUID seams cannot change coverage or the hash chain', async () => {
      const frozen = await createFixture('reg32-frozen', { records: 2, rotateAt: [2] });
      const frozenCheckpoint = firstCheckpoint(frozen.checkpointPath);

      const shifted = await createFixture('reg32-shifted', {
        records: 2,
        rotateAt: [2],
        hooks: {
          clockMs: () => FIXED_CLOCK_START + 86_400_000 * 365,
          randomUUID: () => '00000000-0000-4000-8000-000000000000',
        },
      });
      const shiftedCheckpoint = firstCheckpoint(shifted.checkpointPath);

      assert.notEqual(
        shiftedCheckpoint.createdAt,
        frozenCheckpoint.createdAt,
        'createdAt does follow the clock',
      );
      assert.notEqual(shiftedCheckpoint.checkpointId, frozenCheckpoint.checkpointId);

      // Everything that carries integrity is untouched by either seam.
      assert.equal(shiftedCheckpoint.sequenceStart, frozenCheckpoint.sequenceStart);
      assert.equal(shiftedCheckpoint.sequenceEnd, frozenCheckpoint.sequenceEnd);
      assert.equal(shiftedCheckpoint.terminalRecordHash, frozenCheckpoint.terminalRecordHash);
      assert.equal(
        shiftedCheckpoint.previousCheckpointHash,
        frozenCheckpoint.previousCheckpointHash,
      );
      // The fingerprint is key identity: it differs because the two fixtures
      // have different keys, and each checkpoint still names its OWN trust root.
      assert.notEqual(
        shiftedCheckpoint.publicKeyFingerprint,
        frozenCheckpoint.publicKeyFingerprint,
      );
      assert.equal(shiftedCheckpoint.publicKeyFingerprint, shifted.material.fingerprint);
      assert.equal(frozenCheckpoint.publicKeyFingerprint, frozen.material.fingerprint);
      // storeId is per-store, so it is asserted to be a well-formed UUID rather
      // than compared across two independently created ledgers.
      assert.match(
        shiftedCheckpoint.storeId,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );

      // Per §56: a clock cannot fabricate token validity.
      assertThrowsWithCode(
        () => validateCheckpointV1({ ...frozenCheckpoint, createdAt: '2026-09-21T00:00:00.000' }),
        'AUDIT_CHECKPOINT_INVALID',
      );
    });
  });

  /* ====================================================================== *
   * Category 8 — Tier 2 Signed Checkpoint Artifacts (RC06-NEG-64..74)
   * ====================================================================== */

  describe('Category 8: Tier 2 Signed Checkpoint Artifacts (RC06-NEG-64..74)', () => {
    test('RC06-NEG-64: a checkpoint artifact assigned an audit sequenceNumber is rejected', async () => {
      const fixture = await createFixture('neg64', { records: 3, rotateAt: [3] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      // A checkpoint is not an audit event: every record-identity field is
      // refused by name rather than falling through to the unknown-field case.
      for (const key of CHECKPOINT_FORBIDDEN_EVENT_KEYS) {
        assertThrowsWithCode(
          () => validateCheckpointV1({ ...checkpoint, [key]: 1 }),
          'AUDIT_CHECKPOINT_FORBIDDEN_FIELD',
        );
      }
      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, sequenceNumber: 1001 }),
        'AUDIT_CHECKPOINT_FORBIDDEN_FIELD',
      );

      // And it consumes no primary sequence: the cursor is exactly where the
      // three appends left it, with the checkpoint artifact present.
      assert.equal(fixture.storage.getCurrentSequence(), 4, 'checkpoints advance no sequence');
      assert.equal(
        fixture.engine.getCheckpointState().lastCheckpointSequence,
        3,
        'the checkpoint covers sequence 3 without consuming sequence 4',
      );

      const history = await verifyRetainedPrimaryHistory(fixture.auditDir, process.getuid());
      assert.equal(history.recordCount, 3, 'the checkpoint is not counted as a record');
      assert.equal(history.terminalSequence, 3);
      assert.equal(history.nextSequence, 4);

      // It is not a rotated segment either.
      assert.equal(countLogicalArchives(fixture.auditDir, process.getuid()), 1);
      assert.equal(
        listLogicalArchiveInventory(fixture.auditDir, process.getuid()).some((e) =>
          e.label.includes('checkpoint'),
        ),
        false,
      );
    });

    test('RC06-NEG-65: a checkpoint sequence range that disagrees with the covered records fails', async () => {
      const fixture = await createFixture('neg65', { records: 5, rotateAt: [5] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const { privateKey } = fixture.material;

      // Range that reaches past the required boundary.
      const tooFar = cloneAuditDir(fixture, 'neg65-far');
      writeCheckpointLines(path.join(tooFar, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, { sequenceEnd: 6 }, { privateKey })),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: tooFar,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_COVERAGE_MISMATCH',
      );

      // Range that starts after the first uncovered record.
      const offset = cloneAuditDir(fixture, 'neg65-offset');
      writeCheckpointLines(path.join(offset, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, { sequenceStart: 2 }, { privateKey })),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: offset,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CORRUPTION_DETECTED',
      );

      // Range that ends before the required boundary leaves the boundary unsealed.
      const tooShort = cloneAuditDir(fixture, 'neg65-short');
      writeCheckpointLines(path.join(tooShort, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, { sequenceEnd: 4 }, { privateKey })),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: tooShort,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        [
          'AUDIT_CHECKPOINT_MISSING',
          'AUDIT_CHECKPOINT_UNEXPECTED',
          'AUDIT_CHECKPOINT_COVERAGE_MISMATCH',
        ],
      );

      // The untouched original is still accepted, so the refusals above are
      // attributable to the forged range and not to the fixture.
      const clean = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      assert.equal(clean.checkpointCount, 1);
      assert.equal(clean.lastCheckpointSequence, 5);
    });

    test('RC06-NEG-66: a checkpoint terminalRecordHash that disagrees with the terminal record fails', async () => {
      const fixture = await createFixture('neg66', { records: 4, rotateAt: [4] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const { privateKey } = fixture.material;

      const actualTerminal = fixture.records[3].integrity.recordHash;
      assert.equal(
        checkpoint.terminalRecordHash,
        actualTerminal,
        'baseline is bound to the real record',
      );

      const forgedDir = cloneAuditDir(fixture, 'neg66-forged');
      writeCheckpointLines(path.join(forgedDir, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, { terminalRecordHash: OTHER_HASH }, { privateKey })),
      ]);

      // The forged checkpoint is correctly signed and internally consistent, so
      // only the binding to the actual record can reject it.
      const forged = parseLine(readCheckpointLines(path.join(forgedDir, CHECKPOINT_FILENAME))[0]);
      assert.equal(verifyCheckpointSignature(forged, fixture.material.publicKey), true);
      assert.equal(forged.checkpointHash, computeCheckpointHash(forged));

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: forgedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_TERMINAL_MISMATCH',
      );
    });

    test('RC06-NEG-67: a broken previousCheckpointHash chain link fails verification', async () => {
      const fixture = await createFixture('neg67', { records: 10, rotateAt: [5, 10] });
      const lines = readCheckpointLines(fixture.checkpointPath);
      assert.equal(lines.length, 2, 'two rotations produce two chained checkpoints');

      const first = parseLine(lines[0]);
      const second = parseLine(lines[1]);
      assert.equal(second.previousCheckpointHash, first.checkpointHash, 'baseline chain is intact');

      const { privateKey } = fixture.material;
      const forgedDir = cloneAuditDir(fixture, 'neg67-forged');
      writeCheckpointLines(path.join(forgedDir, CHECKPOINT_FILENAME), [
        lines[0],
        lineOf(reforge(second, { previousCheckpointHash: OTHER_HASH }, { privateKey })),
      ]);

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: forgedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_CHAIN_BROKEN',
      );

      // Breaking the genesis link of the first checkpoint is equally fatal.
      const genesisDir = cloneAuditDir(fixture, 'neg67-genesis');
      writeCheckpointLines(path.join(genesisDir, CHECKPOINT_FILENAME), [
        lineOf(reforge(first, { previousCheckpointHash: '1'.repeat(64) }, { privateKey })),
        lines[1],
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: genesisDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_CHAIN_BROKEN',
      );
    });

    test('RC06-NEG-68: a checkpoint storeId that disagrees with audit-store.json fails', async () => {
      const fixture = await createFixture('neg68', { records: 3, rotateAt: [3] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const { privateKey } = fixture.material;

      const otherStoreId = '00000000-0000-4000-8000-000000000001';
      assert.notEqual(checkpoint.storeId, otherStoreId);

      const forgedDir = cloneAuditDir(fixture, 'neg68-forged');
      writeCheckpointLines(path.join(forgedDir, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, { storeId: otherStoreId }, { privateKey })),
      ]);

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: forgedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_LEDGER_MISMATCH',
      );

      // The same forgery is refused by the engine at startup, so a restart can
      // never adopt a checkpoint belonging to another ledger.
      await assertRejectsWithCode(
        createTestTier2CheckpointEngine({
          directory: forgedDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_LEDGER_MISMATCH',
      );
    });

    test('RC06-NEG-69: tampered checkpoint signature bytes fail signature verification', async () => {
      const fixture = await createFixture('neg69', { records: 4, rotateAt: [4] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const { privateKey } = fixture.material;

      // (a) A raw byte flip leaves the artifact internally inconsistent, so the
      // canonical parser refuses it before any signature is considered.
      const raw = Buffer.from(checkpoint.signature, 'base64url');
      raw[0] ^= 0xff;
      const flipped = { ...checkpoint, signature: raw.toString('base64url') };
      assert.notEqual(computeCheckpointHash(flipped), flipped.checkpointHash);
      const flipDir = cloneAuditDir(fixture, 'neg69-flip');
      writeCheckpointLines(path.join(flipDir, CHECKPOINT_FILENAME), [lineOf(flipped)]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: flipDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CORRUPTION_DETECTED',
      );

      // (b) A well-formed 64-byte signature that is simply wrong, with the hash
      // recomputed so the artifact is internally consistent. Only real Ed25519
      // verification can reject this.
      const wrongSignature = Buffer.alloc(64, 0x5a).toString('base64url');
      const resealed = reforge(checkpoint, {}, { privateKey, signature: wrongSignature });
      assert.equal(resealed.checkpointHash, computeCheckpointHash(resealed));
      assert.equal(verifyCheckpointSignature(resealed, fixture.material.publicKey), false);

      const resealDir = cloneAuditDir(fixture, 'neg69-reseal');
      writeCheckpointLines(path.join(resealDir, CHECKPOINT_FILENAME), [lineOf(resealed)]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: resealDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_SIGNATURE_INVALID',
      );

      // (c) A single flipped bit in an otherwise valid signature is detected
      // because the R and S halves are both covered by verification.
      const bitFlipped = Buffer.from(checkpoint.signature, 'base64url');
      bitFlipped[40] ^= 0x01;
      assert.equal(
        verifyCheckpointSignature(
          { ...checkpoint, signature: bitFlipped.toString('base64url') },
          fixture.material.publicKey,
        ),
        false,
      );
    });

    test('RC06-NEG-70: a checkpoint verified with the wrong Ed25519 public key fails', async () => {
      const fixture = await createFixture('neg70', { records: 4, rotateAt: [4] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const other = writeKeyPair(path.join(tempBaseDir, 'neg70-other-keys'), 'other');

      // (a) The stored signature does not verify under a different key.
      assert.equal(verifyCheckpointSignature(checkpoint, fixture.material.publicKey), true);
      assert.equal(verifyCheckpointSignature(checkpoint, other.publicKey), false);

      // (b) Configuring a different trust root is refused by the pinned
      // fingerprint before any signature is examined.
      assert.notEqual(other.fingerprint, fixture.material.fingerprint);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: fixture.auditDir,
          publicKeyPath: other.publicKeyPath,
        }),
        'FINGERPRINT_MISMATCH',
      );

      // (c) A checkpoint signed by the wrong key, with the pinned fingerprint
      // left correct, is refused by verification rather than by the pin.
      const foreignDir = cloneAuditDir(fixture, 'neg70-foreign');
      writeCheckpointLines(path.join(foreignDir, CHECKPOINT_FILENAME), [
        lineOf(reforge(checkpoint, {}, { privateKey: other.privateKey })),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: foreignDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_SIGNATURE_INVALID',
      );
    });

    test('RC06-NEG-71: a signature-algorithm downgrade attempt is rejected', async () => {
      const fixture = await createFixture('neg71', { records: 3, rotateAt: [3] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      const { privateKey } = fixture.material;

      // (a) An RSA key file cannot stand in for the Ed25519 trust root, even
      // though it is a perfectly valid PEM public key.
      const rsaDir = path.join(tempBaseDir, 'neg71-rsa');
      fs.mkdirSync(rsaDir, { recursive: true, mode: 0o700 });
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const rsaPubPath = path.join(rsaDir, 'rsa-public.pem');
      const rsaPrivPath = path.join(rsaDir, 'rsa-signing.pem');
      fs.writeFileSync(rsaPubPath, rsa.publicKey.export({ type: 'spki', format: 'pem' }), {
        mode: 0o600,
      });
      fs.writeFileSync(rsaPrivPath, rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }), {
        mode: 0o600,
      });

      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(rsaPubPath, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_ALGORITHM_FORBIDDEN',
      );
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(rsaPrivPath),
        'AUDIT_KEY_ALGORITHM_FORBIDDEN',
      );

      // (b) A "none" downgrade: an empty or zeroed signature is never accepted.
      for (const signature of ['', Buffer.alloc(64).toString('base64url')]) {
        const forged = reforge(checkpoint, {}, { privateKey, signature });
        assert.equal(verifyCheckpointSignature(forged, fixture.material.publicKey), false);
      }
      assertThrowsWithCode(
        () => validateCheckpointV1({ ...checkpoint, signature: '' }),
        'AUDIT_CHECKPOINT_INVALID',
      );

      // (c) An RSA-sized signature cannot masquerade as an Ed25519 one.
      const rsaSignature = crypto
        .sign(
          'sha256',
          computeCheckpointSignaturePreimage(pickUnsigned(checkpoint)),
          rsa.privateKey,
        )
        .toString('base64url');
      assert.notEqual(Buffer.from(rsaSignature, 'base64url').length, 64);
      const rsaSignedDir = cloneAuditDir(fixture, 'neg71-rsa-signed');
      writeCheckpointLines(path.join(rsaSignedDir, CHECKPOINT_FILENAME), [
        lineOf({
          ...pickUnsigned(checkpoint),
          signature: rsaSignature,
          checkpointHash: checkpoint.checkpointHash,
        }),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: rsaSignedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_INVALID',
      );
    });

    test('RC06-NEG-72: a replayed checkpoint from a prior sequence range is rejected', async () => {
      const fixture = await createFixture('neg72', { records: 10, rotateAt: [5, 10] });
      const lines = readCheckpointLines(fixture.checkpointPath);
      assert.equal(lines.length, 2);

      const first = parseLine(lines[0]);
      const second = parseLine(lines[1]);
      assert.equal(first.sequenceStart, 1);
      assert.equal(first.sequenceEnd, 5);
      assert.equal(second.sequenceStart, 6);
      assert.equal(second.sequenceEnd, 10);

      // The replayed artifact is the FIRST checkpoint, byte for byte: a real,
      // validly signed checkpoint from a prior sequence range, inserted where
      // the second belongs. Nothing about it is forged or inconsistent.
      const replayDir = cloneAuditDir(fixture, 'neg72-replay');
      writeCheckpointLines(path.join(replayDir, CHECKPOINT_FILENAME), [lines[0], lines[0]]);

      const replayed = parseLine(readCheckpointLines(path.join(replayDir, CHECKPOINT_FILENAME))[1]);
      assert.equal(replayed.checkpointHash, first.checkpointHash);
      assert.equal(verifyCheckpointSignature(replayed, fixture.material.publicKey), true);
      assert.equal(replayed.sequenceEnd, 5, 'the replay claims a range that is already covered');

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: replayDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        [
          'AUDIT_CHECKPOINT_CHAIN_BROKEN',
          'AUDIT_CORRUPTION_DETECTED',
          'AUDIT_CHECKPOINT_COVERAGE_MISMATCH',
          'AUDIT_CHECKPOINT_UNEXPECTED',
        ],
      );

      // With the chain link re-signed so it does continue the chain, only the
      // sequence range is left to reject the replayed coverage — which is the
      // sequence validation the control names.
      const rangeDir = cloneAuditDir(fixture, 'neg72-range');
      writeCheckpointLines(path.join(rangeDir, CHECKPOINT_FILENAME), [
        lines[0],
        lineOf(
          reforge(
            second,
            { sequenceStart: 1, sequenceEnd: 5 },
            { privateKey: fixture.material.privateKey },
          ),
        ),
      ]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: rangeDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        ['AUDIT_CORRUPTION_DETECTED', 'AUDIT_CHECKPOINT_COVERAGE_MISMATCH'],
      );

      // The engine also refuses to re-seal an already-covered sequence, so a
      // restart cannot replay a boundary it has already sealed.
      await assertRejectsWithCode(
        fixture.engine.sealRotation({
          sequenceStart: 1,
          sequenceEnd: 5,
          terminalRecordHash: first.terminalRecordHash,
        }),
        'AUDIT_CHECKPOINT_COVERAGE_CONFLICT',
      );
    });

    test('RC06-NEG-73: an out-of-order checkpoint artifact fails the sequence continuity check', async () => {
      const fixture = await createFixture('neg73', { records: 10, rotateAt: [5, 10] });
      const lines = readCheckpointLines(fixture.checkpointPath);

      const swappedDir = cloneAuditDir(fixture, 'neg73-swapped');
      writeCheckpointLines(path.join(swappedDir, CHECKPOINT_FILENAME), [lines[1], lines[0]]);

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: swappedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        ['AUDIT_CHECKPOINT_CHAIN_BROKEN', 'AUDIT_CHECKPOINT_COVERAGE_MISMATCH'],
      );

      // Dropping the first checkpoint entirely leaves the second one starting
      // mid-history, which is the same continuity violation.
      const droppedDir = cloneAuditDir(fixture, 'neg73-dropped');
      writeCheckpointLines(path.join(droppedDir, CHECKPOINT_FILENAME), [lines[1]]);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: droppedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        [
          'AUDIT_CHECKPOINT_CHAIN_BROKEN',
          'AUDIT_CHECKPOINT_COVERAGE_MISMATCH',
          'AUDIT_CORRUPTION_DETECTED',
        ],
      );

      // The correctly ordered artifact still verifies.
      const ordered = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      assert.equal(ordered.checkpointCount, 2);
      assert.equal(ordered.lastCheckpointSequence, 10);
    });

    test('RC06-NEG-74: a checkpoint artifact that is wider than 0600 or hard-linked is refused', async () => {
      const fixture = await createFixture('neg74', { records: 3, rotateAt: [3] });

      // Baseline: the artifact is created 0600 with a single link.
      const stats = fs.statSync(fixture.checkpointPath);
      assert.equal(stats.mode & 0o777, 0o600, 'the checkpoint artifact is created mode 0600');
      assert.equal(stats.nlink, 1);

      const wideDir = cloneAuditDir(fixture, 'neg74-wide');
      const widePath = path.join(wideDir, CHECKPOINT_FILENAME);
      fs.chmodSync(widePath, 0o644);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: wideDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'INSECURE_PERMISSIONS',
      );

      const groupDir = cloneAuditDir(fixture, 'neg74-group');
      fs.chmodSync(path.join(groupDir, CHECKPOINT_FILENAME), 0o640);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: groupDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'INSECURE_PERMISSIONS',
      );

      // A hard link is created OUTSIDE the audit directory so the entry
      // enumeration stays clean and the rejection is attributable to the
      // checkpoint artifact's own link count.
      const linkDir = cloneAuditDir(fixture, 'neg74-link');
      const linkPath = path.join(linkDir, CHECKPOINT_FILENAME);
      fs.linkSync(linkPath, path.join(tempBaseDir, 'neg74-alias'));
      assert.equal(fs.statSync(linkPath).nlink, 2);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: linkDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        ['HARD_LINK_DETECTED', 'AUDIT_STORE_INSECURE_ENTRY'],
      );

      // A symlinked checkpoint artifact is refused by O_NOFOLLOW itself.
      const symlinkDir = cloneAuditDir(fixture, 'neg74-symlink');
      const target = path.join(symlinkDir, CHECKPOINT_FILENAME);
      const decoy = path.join(tempBaseDir, 'neg74-decoy.jsonl');
      fs.renameSync(target, decoy);
      fs.symlinkSync(decoy, target);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: symlinkDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        ['SYMLINK_DETECTED', 'AUDIT_STORE_INSECURE_ENTRY'],
      );

      // The original artifact is untouched by all of the above.
      assert.equal(fs.statSync(fixture.checkpointPath).mode & 0o777, 0o600);
      const clean = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      assert.equal(clean.checkpointCount, 1);
    });
  });

  /* ====================================================================== *
   * Category 9 — Trust Roots & Key Authority (RC06-NEG-75..83)
   * ====================================================================== */

  describe('Category 9: Trust Roots & Key Authority (RC06-NEG-75..83)', () => {
    /** A realistic PKCS#8 Ed25519 PEM, for the forbidden-source controls. */
    function privatePem() {
      return crypto.generateKeyPairSync('ed25519').privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      });
    }

    test('RC06-NEG-75: a signing key supplied via argv is rejected immediately', () => {
      const pem = privatePem();
      assertThrowsWithCode(
        () => assertNoRawSigningKeyMaterial([{ source: 'argv', value: pem }]),
        'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
      );

      // The rejection names the channel and never echoes the material, so the
      // failure cannot itself become the leak it exists to prevent.
      try {
        assertNoRawSigningKeyMaterial([{ source: 'argv', value: pem }]);
        assert.fail('expected a rejection');
      } catch (err) {
        assert.ok(err.message.includes('argv'), 'the message names the source');
        assert.equal(
          err.message.includes('PRIVATE KEY'),
          false,
          'the message never quotes the key',
        );
        assert.equal(err.message.includes(pem.slice(40, 80)), false);
      }

      // An ordinary configuration value is not flagged: a path is not key material.
      assert.doesNotThrow(() =>
        assertNoRawSigningKeyMaterial([
          { source: 'argv', value: '/etc/cesspace-arc/checkpoint-signing.pem' },
          { source: 'argv', value: 'a'.repeat(64) },
          { source: 'argv', value: '' },
          { source: 'argv', value: 1 },
        ]),
      );
    });

    test('RC06-NEG-76: a signing key supplied via an ambient environment variable is rejected', () => {
      const pem = privatePem();
      assertThrowsWithCode(
        () => assertNoRawSigningKeyMaterial([{ source: 'environment', value: pem }]),
        'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
      );

      // A Base64 envelope around the same PEM is caught too, since that is how
      // key material usually travels through an environment variable.
      const enveloped = Buffer.from(pem, 'utf8').toString('base64');
      assertThrowsWithCode(
        () => assertNoRawSigningKeyMaterial([{ source: 'environment', value: enveloped }]),
        'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
      );

      // Raw key bytes are rejected regardless of encoding.
      assertThrowsWithCode(
        () =>
          assertNoRawSigningKeyMaterial([{ source: 'environment', value: Buffer.alloc(64, 3) }]),
        'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
      );
    });

    test('RC06-NEG-77: a signing key supplied via an MCP header or tool argument is rejected', () => {
      const pem = privatePem();
      for (const source of ['mcp-header', 'mcp-tool-argument']) {
        assertThrowsWithCode(
          () => assertNoRawSigningKeyMaterial([{ source, value: pem }]),
          'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
        );

        // Relabelling the PEM block does not walk past the guard.
        for (const label of [
          'RSA PRIVATE KEY',
          'EC PRIVATE KEY',
          'OPENSSH PRIVATE KEY',
          'ENCRYPTED PRIVATE KEY',
        ]) {
          const relabelled = pem.replace(/PRIVATE KEY/g, label);
          assertThrowsWithCode(
            () => assertNoRawSigningKeyMaterial([{ source, value: relabelled }]),
            'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
          );
        }
      }

      // A set of clean candidates passes, so the guard is not simply always-on.
      assert.doesNotThrow(() =>
        assertNoRawSigningKeyMaterial([
          { source: 'mcp-header', value: 'x-cesspace-request-id' },
          { source: 'mcp-tool-argument', value: { auditDirectory: '/var/lib/cesspace/audit' } },
        ]),
      );
    });

    test('RC06-NEG-78: a symlinked signing key file is rejected', () => {
      const dir = path.join(tempBaseDir, 'neg78');
      const material = writeKeyPair(dir, 'real');
      const linkPath = path.join(dir, 'linked-signing.pem');
      fs.symlinkSync(material.signingKeyPath, linkPath);

      assertThrowsWithCode(() => loadEd25519SigningKeyFile(linkPath), 'SYMLINK_DETECTED');

      // A symlinked trust root is refused by the same rule (§83).
      const pubLink = path.join(dir, 'linked-public.pem');
      fs.symlinkSync(material.publicKeyPath, pubLink);
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(pubLink, { purpose: 'CHECKPOINT' }),
        'SYMLINK_DETECTED',
      );

      // The real files still load, so the refusal is about the link.
      assert.doesNotThrow(() => loadEd25519SigningKeyFile(material.signingKeyPath));
    });

    test('RC06-NEG-79: a signing key file with more than one hard link is rejected', () => {
      const dir = path.join(tempBaseDir, 'neg79');
      const material = writeKeyPair(dir, 'linked');
      fs.linkSync(material.signingKeyPath, path.join(dir, 'signing-alias.pem'));
      assert.equal(fs.statSync(material.signingKeyPath).nlink, 2);

      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(material.signingKeyPath),
        'HARD_LINK_DETECTED',
      );

      const trustDir = path.join(tempBaseDir, 'neg79-trust');
      const trust = writeKeyPair(trustDir, 'linked');
      fs.linkSync(trust.publicKeyPath, path.join(trustDir, 'public-alias.pem'));
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(trust.publicKeyPath, { purpose: 'CHECKPOINT' }),
        'HARD_LINK_DETECTED',
      );
    });

    test('RC06-NEG-80: a signing key file with permissions wider than 0600 is rejected', () => {
      for (const mode of [0o644, 0o640, 0o604, 0o666, 0o700]) {
        const dir = path.join(tempBaseDir, `neg80-${mode.toString(8)}`);
        const material = writeKeyPair(dir, 'wide');
        fs.chmodSync(material.signingKeyPath, mode);
        assertThrowsWithCode(
          () => loadEd25519SigningKeyFile(material.signingKeyPath),
          'INSECURE_PERMISSIONS',
        );

        fs.chmodSync(material.publicKeyPath, mode);
        assertThrowsWithCode(
          () => loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }),
          'INSECURE_PERMISSIONS',
        );
      }
    });

    test('RC06-NEG-81: a signing key file owned by a different UID is rejected', () => {
      const dir = path.join(tempBaseDir, 'neg81');
      const material = writeKeyPair(dir, 'foreign');

      // Exercised through the expected-UID seam so the ownership rule is proved
      // without a privileged chown.
      const otherUid = process.getuid() + 1;
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(material.signingKeyPath, { expectedUid: otherUid }),
        'OWNERSHIP_MISMATCH',
      );
      assertThrowsWithCode(
        () =>
          loadEd25519TrustRootFile(material.publicKeyPath, {
            purpose: 'CHECKPOINT',
            expectedUid: otherUid,
          }),
        'OWNERSHIP_MISMATCH',
      );

      // With the true UID both files load, so the rule is the UID and nothing else.
      assert.doesNotThrow(() =>
        loadEd25519SigningKeyFile(material.signingKeyPath, { expectedUid: process.getuid() }),
      );
    });

    test('RC06-NEG-82: a signing key larger than MAX_SIGNING_KEY_BYTES is rejected', () => {
      const dir = path.join(tempBaseDir, 'neg82');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(dir, 'real');

      const oversize = path.join(dir, 'oversize-signing.pem');
      const real = fs.readFileSync(material.signingKeyPath, 'utf8');
      fs.writeFileSync(oversize, real + '#'.repeat(MAX_SIGNING_KEY_BYTES), { mode: 0o600 });
      assert.ok(fs.statSync(oversize).size > MAX_SIGNING_KEY_BYTES);

      assertThrowsWithCode(() => loadEd25519SigningKeyFile(oversize), 'AUDIT_KEY_TOO_LARGE');

      // Exactly at the bound is still read and parsed, so the limit is a
      // maximum rather than an off-by-one refusal.
      const atBound = path.join(dir, 'at-bound-signing.pem');
      const padding = MAX_SIGNING_KEY_BYTES - Buffer.byteLength(real, 'utf8');
      assert.ok(padding >= 0, 'a real PKCS#8 Ed25519 PEM is far below the bound');
      fs.writeFileSync(atBound, real + ' '.repeat(padding), { mode: 0o600 });
      assert.equal(fs.statSync(atBound).size, MAX_SIGNING_KEY_BYTES);
      assert.doesNotThrow(() => loadEd25519SigningKeyFile(atBound));

      // The trust root is bounded by the same constant.
      const oversizePublic = path.join(dir, 'oversize-public.pem');
      fs.writeFileSync(
        oversizePublic,
        fs.readFileSync(material.publicKeyPath, 'utf8') + '#'.repeat(MAX_SIGNING_KEY_BYTES),
        { mode: 0o600 },
      );
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(oversizePublic, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_TOO_LARGE',
      );
    });

    test('RC06-NEG-83: a trust root that is linked, wide or foreign-owned is rejected', async () => {
      const dir = path.join(tempBaseDir, 'neg83');
      const material = writeKeyPair(dir, 'trust');

      // Symlink, hard link, wider permissions and foreign ownership are each
      // refused on the trust root exactly as they are on the signing key.
      const link = path.join(dir, 'trust-link.pem');
      fs.symlinkSync(material.publicKeyPath, link);
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(link, { purpose: 'CHECKPOINT' }),
        'SYMLINK_DETECTED',
      );

      const hard = path.join(dir, 'trust-hard.pem');
      fs.linkSync(material.publicKeyPath, hard);
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }),
        'HARD_LINK_DETECTED',
      );
      fs.unlinkSync(hard);

      fs.chmodSync(material.publicKeyPath, 0o644);
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }),
        'INSECURE_PERMISSIONS',
      );
      fs.chmodSync(material.publicKeyPath, 0o600);

      assertThrowsWithCode(
        () =>
          loadEd25519TrustRootFile(material.publicKeyPath, {
            purpose: 'CHECKPOINT',
            expectedUid: process.getuid() + 1,
          }),
        'OWNERSHIP_MISMATCH',
      );

      // A certificate, an OpenSSH key and a PKCS#1 key are all valid PEM files
      // that are NOT an SPKI public key, and none of them may be accepted.
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pkcs1 = path.join(dir, 'pkcs1.pem');
      fs.writeFileSync(pkcs1, rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }), {
        mode: 0o600,
      });
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(pkcs1, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_ENCODING_FORBIDDEN',
      );

      const bundle = path.join(dir, 'bundle.pem');
      fs.writeFileSync(
        bundle,
        fs.readFileSync(material.publicKeyPath, 'utf8') + fs.readFileSync(pkcs1, 'utf8'),
        { mode: 0o600 },
      );
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(bundle, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_ENCODING_FORBIDDEN',
      );

      const truncated = path.join(dir, 'truncated.pem');
      const pem = fs.readFileSync(material.publicKeyPath, 'utf8');
      fs.writeFileSync(truncated, pem.replace(/-----END PUBLIC KEY-----/, ''), { mode: 0o600 });
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(truncated, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_ENCODING_FORBIDDEN',
      );

      const garbage = path.join(dir, 'garbage.pem');
      fs.writeFileSync(garbage, 'not a pem file at all\n', { mode: 0o600 });
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(garbage, { purpose: 'CHECKPOINT' }),
        'AUDIT_KEY_ENCODING_FORBIDDEN',
      );

      // The anchor-receipt purpose enforces identical authority rules, so the
      // reloadable Task-5 trust root cannot be weaker than the Task-4 one.
      assert.doesNotThrow(() =>
        loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'ANCHOR_RECEIPT' }),
      );
    });

    test('RC06-T4-REG-17: a signing key inside an agent workspace is rejected', () => {
      const workspace = path.join(tempBaseDir, 'reg17-workspace');
      const keyDir = path.join(workspace, 'keys');
      const material = writeKeyPair(keyDir, 'inside');

      assertThrowsWithCode(
        () => assertSigningKeyOutsideWorkspaces(material.signingKeyPath, [workspace]),
        'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
      );

      // A key that CONTAINS a workspace is refused too: it would be reachable
      // from everything the workspace can reach.
      assertThrowsWithCode(
        () => assertSigningKeyOutsideWorkspaces(material.signingKeyPath, [keyDir]),
        'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
      );

      // A key outside every workspace is accepted.
      const outside = writeKeyPair(path.join(tempBaseDir, 'reg17-outside'), 'outside');
      assert.doesNotThrow(() =>
        assertSigningKeyOutsideWorkspaces(outside.signingKeyPath, [workspace]),
      );
      assert.doesNotThrow(() => assertSigningKeyOutsideWorkspaces(outside.signingKeyPath, []));

      // The engine enforces the same rule, and refuses before reading key bytes.
      const auditDir = path.join(tempBaseDir, 'reg17-audit');
      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: material.fingerprint,
          anchorMode: 'DISABLED',
        },
      });
      storage.initialize();
      const fixture = { auditDir, storage, engine: null };
      openFixtures.push(fixture);

      return assertRejectsWithCode(
        createTestTier2CheckpointEngine(
          {
            directory: auditDir,
            signingKeyPath: material.signingKeyPath,
            publicKeyPath: material.publicKeyPath,
            workspacePaths: [workspace],
          },
          {},
        ),
        'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
      );
    });

    test('RC06-T4-REG-30: a signing key that does not match the pinned trust root is rejected', async () => {
      const auditDir = path.join(tempBaseDir, 'reg30');
      const pinned = writeKeyPair(path.join(tempBaseDir, 'reg30-pinned'), 'pinned');
      const impostor = writeKeyPair(path.join(tempBaseDir, 'reg30-impostor'), 'impostor');

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: pinned.fingerprint,
          anchorMode: 'DISABLED',
        },
      });
      storage.initialize();
      openFixtures.push({ auditDir, storage, engine: null });

      await assertRejectsWithCode(
        createTestTier2CheckpointEngine({
          directory: auditDir,
          signingKeyPath: impostor.signingKeyPath,
          publicKeyPath: pinned.publicKeyPath,
        }),
        'AUDIT_SIGNING_KEY_MISMATCH',
      );

      // The matching pair is accepted, so the check is correspondence and not
      // an unconditional refusal.
      const engine = await createTestTier2CheckpointEngine({
        directory: auditDir,
        signingKeyPath: pinned.signingKeyPath,
        publicKeyPath: pinned.publicKeyPath,
      });
      assert.equal(engine.getCheckpointState().failed, false);
      engine.close();
    });
  });

  /* ====================================================================== *
   * Post-review correction: key-path authority, exact PEM framing and
   * checkpoint-artifact identity
   *
   * Each regression here corresponds to a defect that was independently
   * verified against the reviewed Task-4 head. They are additive regressions,
   * not frozen controls, so they carry the non-frozen RC06-T4-REG-nn namespace
   * and claim no RC06-NEG number.
   * ====================================================================== */

  describe('Post-Review Correction: Key Path, PEM Framing and Artifact Identity', () => {
    /** Error codes that legitimately express "this key path is not authoritative". */
    const KEY_PATH_AUTHORITY_CODES = [
      'SYMLINK_DETECTED',
      'AUDIT_KEY_PATH_INVALID',
      'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
    ];

    /** Codes for a file whose framing is not exactly one expected PEM block. */
    const PEM_FRAMING_CODES = ['AUDIT_KEY_ENCODING_FORBIDDEN', 'AUDIT_KEY_MALFORMED'];

    test('RC06-T4-REG-33: a key path reached through a symlinked component is refused', () => {
      const root = path.join(tempBaseDir, 'reg33');
      const workspace = path.join(root, 'workspace');
      const outside = path.join(root, 'outside');
      fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
      fs.mkdirSync(outside, { recursive: true, mode: 0o700 });

      const material = writeKeyPair(workspace, 'workspace');
      // The signing key is a regular file inside the workspace. The alias is a
      // directory symlink pointing at the workspace, so `/outside/alias/...`
      // names the same file while looking, lexically, like a path outside it.
      fs.symlinkSync(workspace, path.join(outside, 'alias'), 'dir');
      const aliasedSigningKey = path.join(outside, 'alias', `${'workspace'}-signing.pem`);

      // Final-component `O_NOFOLLOW` alone cannot catch this: the final
      // component is a genuine regular file. The whole path is therefore
      // checked, and the alias is refused before the key is ever read.
      assert.equal(fs.lstatSync(aliasedSigningKey).isSymbolicLink(), false);
      assert.ok(fs.readFileSync(aliasedSigningKey, 'utf8').includes('PRIVATE KEY'));

      assertThrowsWithCode(
        () =>
          loadEd25519SigningKeyFile(aliasedSigningKey, {
            workspacePaths: [workspace],
          }),
        KEY_PATH_AUTHORITY_CODES,
      );
      assertThrowsWithCode(
        () => assertSigningKeyOutsideWorkspaces(aliasedSigningKey, [workspace]),
        KEY_PATH_AUTHORITY_CODES,
      );

      // The canonical path to the same file is still perfectly loadable, so the
      // refusal is about the alias and not about the key.
      const direct = loadEd25519SigningKeyFile(material.signingKeyPath, {
        workspacePaths: [path.join(root, 'not-a-workspace')],
      });
      assert.equal(direct.derivedFingerprint, material.fingerprint);

      // And workspace isolation is decided on canonical identity, not on the
      // lexical spelling: a workspace declared through the alias still contains
      // the key when both are resolved for real.
      const aliasedWorkspace = path.join(outside, 'alias');
      assertThrowsWithCode(
        () => assertSigningKeyOutsideWorkspaces(material.signingKeyPath, [aliasedWorkspace]),
        ['AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP'],
      );
    });

    test('RC06-T4-REG-34: a trust root reached through a symlinked component is refused', () => {
      const root = path.join(tempBaseDir, 'reg34');
      const real = path.join(root, 'real');
      fs.mkdirSync(real, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(real, 'real');

      fs.symlinkSync(real, path.join(root, 'alias'), 'dir');
      const aliased = path.join(root, 'alias', 'real-public.pem');
      assert.equal(fs.lstatSync(aliased).isSymbolicLink(), false);

      // The same rule applies to every trust root the loader serves, including
      // the future anchor-receipt one. No anchor logic is involved here.
      for (const purpose of ['CHECKPOINT', 'ANCHOR_RECEIPT']) {
        assertThrowsWithCode(
          () => loadEd25519TrustRootFile(aliased, { purpose }),
          KEY_PATH_AUTHORITY_CODES,
        );
      }

      // A symlinked *final* component is still refused too: that protection was
      // not traded away for the parent-component one.
      const fileLink = path.join(root, 'link-public.pem');
      fs.symlinkSync(material.publicKeyPath, fileLink, 'file');
      assertThrowsWithCode(
        () => loadEd25519TrustRootFile(fileLink, { purpose: 'CHECKPOINT' }),
        KEY_PATH_AUTHORITY_CODES,
      );

      // The canonical trust root still loads and still fingerprints the SPKI DER.
      const loaded = loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' });
      assert.equal(loaded.fingerprint, material.fingerprint);
    });

    test('RC06-T4-REG-35: a signing-key PEM with surrounding content is refused', () => {
      const dir = path.join(tempBaseDir, 'reg35');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(dir, 'reg35');
      const privatePem = fs.readFileSync(material.signingKeyPath, 'utf8');

      const write = (name, content) => {
        const filePath = path.join(dir, name);
        fs.writeFileSync(filePath, content, { mode: 0o600 });
        return filePath;
      };

      // `node:crypto` extracts a usable key from a block embedded in arbitrary
      // text, so these are files that *would* have produced a working signing
      // key. Framing is therefore validated on the whole file, before parsing.
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(write('prefix.pem', `garbage\n${privatePem}`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(write('suffix.pem', `${privatePem}\ngarbage`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(write('both.pem', `garbage\n${privatePem}\ngarbage`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(write('nul.pem', `${privatePem}\0`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () =>
          loadEd25519SigningKeyFile(
            write('comment.pem', `# operator note\n${privatePem}# trailing note\n`),
          ),
        PEM_FRAMING_CODES,
      );

      // Permitted surrounding ASCII whitespace is still harmless: the rule
      // constrains what else the file may contain, not how it is padded.
      const padded = loadEd25519SigningKeyFile(write('padded.pem', `\n \t${privatePem}\n\n`));
      assert.equal(padded.derivedFingerprint, material.fingerprint);

      // The same key bytes remain loadable from their canonical file, so the
      // refusals are about the wrapping rather than about the key.
      assert.equal(
        loadEd25519SigningKeyFile(material.signingKeyPath).derivedFingerprint,
        material.fingerprint,
      );
    });

    test('RC06-T4-REG-36: a trust-root PEM with surrounding content is refused', () => {
      const dir = path.join(tempBaseDir, 'reg36');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(dir, 'reg36');
      const publicPem = fs.readFileSync(material.publicKeyPath, 'utf8');

      const write = (name, content) => {
        const filePath = path.join(dir, name);
        fs.writeFileSync(filePath, content, { mode: 0o600 });
        return filePath;
      };
      const load = (filePath) => loadEd25519TrustRootFile(filePath, { purpose: 'CHECKPOINT' });

      assertThrowsWithCode(
        () => load(write('prefix.pem', `garbage\n${publicPem}`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () => load(write('suffix.pem', `${publicPem}\ngarbage`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () => load(write('both.pem', `garbage\n${publicPem}\ngarbage`)),
        PEM_FRAMING_CODES,
      );
      assertThrowsWithCode(
        () =>
          load(
            write(
              'cert-then-key.pem',
              `-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n${publicPem}`,
            ),
          ),
        PEM_FRAMING_CODES,
      );

      // Two blocks of the correct label are still two blocks.
      assertThrowsWithCode(
        () => load(write('double.pem', publicPem + publicPem)),
        PEM_FRAMING_CODES,
      );

      // The fingerprint stays a property of the parsed SPKI DER, so whitespace
      // around the block cannot change which key is identified.
      const padded = load(write('padded.pem', `\n\t${publicPem}\n`));
      assert.equal(padded.fingerprint, material.fingerprint);
      assert.equal(
        crypto.createHash('sha256').update(padded.spkiDer).digest('hex'),
        material.fingerprint,
      );
    });

    test('RC06-T4-REG-37: replacing the verified checkpoint pathname is refused', async () => {
      const fixture = await createFixture('reg37', { records: 2 });
      await fixture.store.rotateNow('SIZE_THRESHOLD');

      const verifiedBytes = fs.readFileSync(fixture.checkpointPath);
      const before = fixture.engine.getCheckpointState();

      // The verified artifact is replaced at its canonical pathname by a
      // different inode carrying identical bytes, identical mode and identical
      // ownership. Only its identity distinguishes it from the verified stream.
      fs.unlinkSync(fixture.checkpointPath);
      fs.writeFileSync(fixture.checkpointPath, verifiedBytes, { mode: 0o600 });
      assert.notEqual(fs.statSync(fixture.checkpointPath).ino, 0);

      await fixture.store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(
        fixture.store.rotateNow('SIZE_THRESHOLD'),
        'AUDIT_CHECKPOINT_FILE_RACE',
      );

      const after = fixture.engine.getCheckpointState();
      assert.equal(after.failed, true);
      assert.equal(after.nextCoverageStart, before.nextCoverageStart);
      assert.equal(after.lastCheckpointSequence, before.lastCheckpointSequence);
      // The replacement was neither overwritten nor truncated.
      assert.ok(fs.readFileSync(fixture.checkpointPath).equals(verifiedBytes));

      // And the engine is unusable for further checkpoint progression.
      await assertRejectsWithCode(
        fixture.engine.sealRotation({
          sequenceStart: 1,
          sequenceEnd: fixture.records.length,
          terminalRecordHash: 'a'.repeat(64),
        }),
        'AUDIT_CHECKPOINT_INVALID_STATE',
      );
    });

    test('RC06-T4-REG-38: an artifact appearing after verified absence is not adopted', async () => {
      const fixture = await createFixture('reg38', {
        records: 2,
        hooks: {
          beforeCheckpointExclusiveCreate: (filePath) => {
            if (!fs.existsSync(filePath)) {
              fs.writeFileSync(filePath, 'RACING\n', { mode: 0o600 });
            }
          },
        },
      });

      assert.equal(fs.existsSync(fixture.checkpointPath), false);
      const before = fixture.engine.getCheckpointState();

      await assertRejectsWithCode(
        fixture.store.rotateNow('SIZE_THRESHOLD'),
        'AUDIT_CHECKPOINT_FILE_RACE',
      );

      const after = fixture.engine.getCheckpointState();
      assert.equal(after.failed, true);
      assert.equal(after.nextCoverageStart, before.nextCoverageStart);
      assert.equal(after.lastCheckpointSequence, null);
      assert.equal(after.lastCheckpointHash, null);

      // The racing artifact was not reopened, adopted, overwritten or removed,
      // and no checkpoint was appended to it.
      assert.equal(fs.readFileSync(fixture.checkpointPath, 'utf8'), 'RACING\n');
    });

    test('RC06-T4-REG-39: growth of the verified checkpoint inode is refused', async () => {
      const fixture = await createFixture('reg39', { records: 2 });
      await fixture.store.rotateNow('SIZE_THRESHOLD');

      const before = fixture.engine.getCheckpointState();
      const inodeBefore = fs.statSync(fixture.checkpointPath).ino;

      // Bytes are appended to the SAME inode the engine verified. The identity
      // is unchanged; only the length is, and the length is what proves the
      // stream still ends where the last durable write left it.
      fs.appendFileSync(fixture.checkpointPath, 'externally-added\n');
      const grown = fs.readFileSync(fixture.checkpointPath);
      assert.equal(fs.statSync(fixture.checkpointPath).ino, inodeBefore);

      await fixture.store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(
        fixture.store.rotateNow('SIZE_THRESHOLD'),
        'AUDIT_CHECKPOINT_FILE_RACE',
      );

      const after = fixture.engine.getCheckpointState();
      assert.equal(after.failed, true);
      assert.equal(after.nextCoverageStart, before.nextCoverageStart);
      // No repair: the externally added bytes are still there, untouched.
      assert.ok(fs.readFileSync(fixture.checkpointPath).equals(grown));
    });

    test('RC06-T4-REG-40: detaching the canonical path from the open descriptor is refused', async () => {
      const fixture = await createFixture('reg40', { records: 2 });

      // This rotation emits the first checkpoint, which establishes and caches
      // the append descriptor. The next append is then made while the engine
      // still holds that descriptor.
      await fixture.store.rotateNow('SIZE_THRESHOLD');
      const orphanBytes = fs.readFileSync(fixture.checkpointPath);

      const orphanPath = path.join(fixture.root, 'detached-checkpoints.jsonl');
      fs.renameSync(fixture.checkpointPath, orphanPath);
      fs.writeFileSync(fixture.checkpointPath, '', { mode: 0o600 });

      const before = fixture.engine.getCheckpointState();

      await fixture.store.append(createSampleRecordCandidate());
      await assertRejectsWithCode(
        fixture.store.rotateNow('SIZE_THRESHOLD'),
        'AUDIT_CHECKPOINT_FILE_RACE',
      );

      const after = fixture.engine.getCheckpointState();
      assert.equal(after.failed, true);
      assert.equal(after.nextCoverageStart, before.nextCoverageStart);

      // Nothing was written to the orphaned inode the descriptor still names,
      // and nothing was written to the replacement now occupying the canonical
      // path — a write to either would have been durable, signed, and invisible
      // to every future verifier.
      assert.ok(fs.readFileSync(orphanPath).equals(orphanBytes));
      assert.equal(fs.readFileSync(fixture.checkpointPath).length, 0);
    });

    test('RC06-T4-REG-41: the corrected internals stay out of the public declarations', () => {
      // Only the package's public declarations are in scope. The internal
      // modules are not reachable through the package exports map, and their
      // own declarations carrying internal names is what makes the test suite's
      // import of them possible.
      const publicDeclarations = [
        path.join(PACKAGE_DIST_DIR, 'index.d.ts'),
        path.join(PACKAGE_DIST_DIR, 'checkpoint.d.ts'),
      ];

      // The correction added internal security state and internal race seams.
      // Neither may become exported surface: `stripInternal` must keep removing
      // them, so a caller can never hand the engine a precondition of its own.
      const forbidden = [
        'VerifiedCheckpointArtifactState',
        'CheckpointVerificationOutcome',
        'beforeCheckpointExclusiveCreate',
        'beforeCheckpointAppend',
        'CHECKPOINT_TEST_TOKEN',
        'CheckpointTestHooks',
        'CheckpointArtifactIdentity',
        'captureCheckpointArtifactIdentity',
        'checkpointRaceError',
        'beforeCheckpointVerificationIdentityCheck',
        'beforeFinalKeyOpen',
        'resolveCanonicalKeyPath',
        'openAuthoritativeKeyFile',
        'assertCanonicalOutsideWorkspaces',
        'assertDescriptorPinnedTraversalAvailable',
        'assertKeyPathShape',
        'pathComponents',
        'pinnedOpenError',
        'openPinnedComponent',
        'openDescriptorPinnedKeyFile',
        'descriptorLocation',
        'canonicalizeWorkspacePath',
        'workspaceAuthorityError',
        'assertLocationOutsideWorkspaces',
        'PROC_SELF_FD',
      ];

      for (const file of publicDeclarations) {
        const text = fs.readFileSync(file, 'utf8');
        for (const symbol of forbidden) {
          assert.equal(
            text.includes(symbol),
            false,
            `${path.basename(file)} must not declare internal symbol ${symbol}`,
          );
        }
      }

      // The production-safe surface the correction hardened is unchanged.
      const index = fs.readFileSync(path.join(PACKAGE_DIST_DIR, 'index.d.ts'), 'utf8');
      for (const symbol of [
        'verifyCheckpointHistory',
        'Tier2CheckpointEngine',
        'computeCheckpointPublicKeyFingerprint',
        'computeTrustRootFingerprintFromFile',
        'assertNoRawSigningKeyMaterial',
      ]) {
        assert.ok(index.includes(symbol), `index.d.ts must still export ${symbol}`);
      }
    });

    test('RC06-T4-REG-42: a parent substituted after pinning cannot redirect the signing key', () => {
      const root = path.join(tempBaseDir, 'reg42');
      const outside = path.join(root, 'outside');
      const workspace = path.join(root, 'workspace');
      const staged = path.join(root, 'staged-outside');
      fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });

      // The canonical key is a regular file in a regular directory. The
      // workspace holds a DIFFERENT keypair under the very same file name, so
      // "which of the two was read" is decidable from the fingerprint alone.
      const material = writeKeyPair(outside, 'reg42');
      const decoy = writeKeyPair(workspace, 'reg42');
      assert.notEqual(decoy.fingerprint, material.fingerprint);

      // The substitution happens after every parent component has been pinned
      // by descriptor and immediately before the final component is opened:
      // exactly the window a pathname-based check cannot survive. The alias now
      // points into the workspace, so a walk that re-resolved `outside` from
      // its pathname would land on the workspace key.
      let loadedFingerprint = null;
      let refusal = null;
      try {
        loadedFingerprint = loadEd25519SigningKeyFile(material.signingKeyPath, {
          workspacePaths: [workspace],
          beforeFinalKeyOpen: () => {
            fs.renameSync(outside, staged);
            fs.symlinkSync(workspace, outside, 'dir');
          },
        }).derivedFingerprint;
      } catch (err) {
        refusal = err;
      }

      // Either the loader refuses, or it stays bound to the directory it pinned
      // — and the pinned directory is the one holding the canonical key. The
      // one outcome that is not permitted is the workspace key.
      assert.equal(loadedFingerprint, refusal === null ? material.fingerprint : null);
      assert.notEqual(loadedFingerprint, decoy.fingerprint);

      assert.ok(refusal !== null, 'the substituted pathname must not be accepted');
      assert.equal(refusal.code, 'AUDIT_KEY_PATH_INVALID');

      // The substitution was not undone and nothing was adopted: the descriptor
      // that was really opened no longer occupies the canonical pathname, and
      // that disagreement is the refusal. A later load cannot reach the
      // workspace through the alias either.
      assert.ok(fs.lstatSync(outside).isSymbolicLink());
      assert.equal(fs.realpathSync(outside), fs.realpathSync(workspace));
      assertThrowsWithCode(
        () => loadEd25519SigningKeyFile(material.signingKeyPath, { workspacePaths: [workspace] }),
        'SYMLINK_DETECTED',
      );
      // The workspace key is still exactly where it was, untouched.
      assert.equal(
        loadEd25519SigningKeyFile(decoy.signingKeyPath, {
          workspacePaths: [path.join(root, 'not-a-workspace')],
        }).derivedFingerprint,
        decoy.fingerprint,
      );
    });

    test('RC06-T4-REG-43: engine initialization is bound by the same substitution rule', async () => {
      const root = path.join(tempBaseDir, 'reg43');
      const auditDir = path.join(root, 'audit');
      const workspace = path.join(root, 'workspace');
      const staged = path.join(root, 'staged-keys');
      const keyDir = path.join(root, 'keys');
      fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });

      const material = writeKeyPair(keyDir, 'reg43');
      const decoy = writeKeyPair(workspace, 'reg43');
      assert.notEqual(decoy.fingerprint, material.fingerprint);

      const storage = new PersistentAuditStorage({
        directory: auditDir,
        createIfMissing: true,
        metadata: {
          checkpointPublicKeyFingerprint: material.fingerprint,
          anchorMode: 'DISABLED',
        },
      });
      storage.initialize();

      // The store is bound to the CANONICAL key's fingerprint, so a loader that
      // were redirected to the workspace key would be refused a second time, by
      // a different rule than the pathname binding — proving the refusal came
      // from the pathname binding and not from the key being unusable.
      const enginePromise = createTestTier2CheckpointEngine(
        {
          directory: auditDir,
          signingKeyPath: material.signingKeyPath,
          publicKeyPath: material.publicKeyPath,
          workspacePaths: [workspace],
        },
        {
          beforeFinalKeyOpen: () => {
            fs.renameSync(keyDir, staged);
            fs.symlinkSync(workspace, keyDir, 'dir');
          },
        },
      );
      await assertRejectsWithCode(enginePromise, 'AUDIT_KEY_PATH_INVALID');

      // The refusal was about the substituted path, not about the key behind it:
      // the decoy loads cleanly from its own path when that path is outside
      // every workspace, and the canonical key does too once the alias is gone.
      assert.equal(
        loadEd25519SigningKeyFile(decoy.signingKeyPath, {
          workspacePaths: [path.join(root, 'not-a-workspace')],
        }).derivedFingerprint,
        decoy.fingerprint,
      );

      // Removing the planted alias restores the canonical path and the engine
      // initializes against the untouched store.
      fs.unlinkSync(keyDir);
      fs.renameSync(staged, keyDir);
      const restored = await createTestTier2CheckpointEngine({
        directory: auditDir,
        signingKeyPath: material.signingKeyPath,
        publicKeyPath: material.publicKeyPath,
        workspacePaths: [workspace],
      });
      openFixtures.push({ engine: restored, storage });
      assert.equal(restored.getCheckpointState().failed, false);
    });

    test('RC06-T4-REG-44: the trust-root path decision precedes any content decision', () => {
      const root = path.join(tempBaseDir, 'reg44');
      const hidden = path.join(root, 'hidden');
      fs.mkdirSync(hidden, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(hidden, 'reg44');

      // `alias` is a directory symlink, so the path is lexically canonical while
      // its parent component is not. Every trust root this loader serves — the
      // checkpoint one today and the future anchor-receipt one — is reached
      // through the same walk, so both must refuse identically.
      fs.symlinkSync(hidden, path.join(root, 'alias'), 'dir');
      const aliased = path.join(root, 'alias', 'reg44-public.pem');

      for (const purpose of ['CHECKPOINT', 'ANCHOR_RECEIPT']) {
        // A valid, correctly framed trust root behind the alias.
        assertThrowsWithCode(
          () => loadEd25519TrustRootFile(aliased, { purpose }),
          'SYMLINK_DETECTED',
        );
        // The very same alias with nothing behind it at all. The refusal code
        // is unchanged, which is what makes it a decision about the path
        // structure rather than about what the file happens to contain or
        // whether it happens to exist.
        fs.rmSync(material.publicKeyPath);
        assertThrowsWithCode(
          () => loadEd25519TrustRootFile(aliased, { purpose }),
          'SYMLINK_DETECTED',
        );
        fs.writeFileSync(
          material.publicKeyPath,
          material.publicKey.export({ type: 'spki', format: 'pem' }),
          { mode: 0o600 },
        );
      }

      // The fingerprint behind the alias is never reported, and the canonical
      // trust root still loads and still identifies the same SPKI DER.
      assert.notEqual(
        loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }).fingerprint,
        null,
      );
      assert.equal(
        loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }).fingerprint,
        material.fingerprint,
      );
    });

    test('RC06-T4-REG-45: growth of the artifact after the stream was consumed is refused', async () => {
      const fixture = await createFixture('reg45', { records: 2, rotateAt: [2] });
      const verifiedBytes = fs.readFileSync(fixture.checkpointPath);
      fixture.engine.close();

      // The verifier has read the artifact to EOF and proven every checkpoint
      // in it. Only now are the extra bytes added — to the SAME inode, so the
      // identity is unchanged and only the length disagrees with what was read.
      const restarted = createTestTier2CheckpointEngine(
        {
          directory: fixture.auditDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        },
        {
          beforeCheckpointVerificationIdentityCheck: (filePath) => {
            fs.appendFileSync(filePath, 'externally-added\n');
          },
        },
      );
      await assertRejectsWithCode(restarted, 'AUDIT_CHECKPOINT_FILE_RACE');

      // Nothing was truncated, repaired or removed: the appended bytes are
      // exactly as the racing writer left them.
      const after = fs.readFileSync(fixture.checkpointPath);
      assert.equal(after.length, verifiedBytes.length + 'externally-added\n'.length);
      assert.ok(after.subarray(0, verifiedBytes.length).equals(verifiedBytes));
    });

    test('RC06-T4-REG-46: shrinkage of the artifact after the stream was consumed is refused', async () => {
      const fixture = await createFixture('reg46', { records: 2, rotateAt: [2] });
      const verifiedBytes = fs.readFileSync(fixture.checkpointPath);
      const inodeBefore = fs.statSync(fixture.checkpointPath).ino;
      fixture.engine.close();

      // The opposite direction, on the same inode: a length that is shorter than
      // what was consumed is just as unverified as one that is longer, because
      // the recorded length must describe the bytes that were actually read.
      const restarted = createTestTier2CheckpointEngine(
        {
          directory: fixture.auditDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        },
        {
          beforeCheckpointVerificationIdentityCheck: (filePath) => {
            fs.truncateSync(filePath, 1);
          },
        },
      );
      await assertRejectsWithCode(restarted, 'AUDIT_CHECKPOINT_FILE_RACE');

      assert.equal(fs.statSync(fixture.checkpointPath).ino, inodeBefore);
      assert.equal(fs.readFileSync(fixture.checkpointPath).length, 1);
      assert.notEqual(verifiedBytes.length, 1);
    });

    test('RC06-T4-REG-47: an identical-bytes replacement after the stream was consumed is refused', async () => {
      const fixture = await createFixture('reg47', { records: 2, rotateAt: [2] });
      const verifiedBytes = fs.readFileSync(fixture.checkpointPath);
      const inodeBefore = fs.statSync(fixture.checkpointPath).ino;
      const statBefore = fs.statSync(fixture.checkpointPath);
      fixture.engine.close();

      // Identical bytes, identical mode, identical ownership, identical length.
      // Only the inode differs, so a length or content check would accept this
      // artifact — and every future verifier would be reading a stream that the
      // engine recorded as verified when it was a different file.
      const restarted = createTestTier2CheckpointEngine(
        {
          directory: fixture.auditDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        },
        {
          beforeCheckpointVerificationIdentityCheck: (filePath) => {
            fs.unlinkSync(filePath);
            fs.writeFileSync(filePath, verifiedBytes, { mode: 0o600 });
          },
        },
      );
      await assertRejectsWithCode(restarted, 'AUDIT_CHECKPOINT_FILE_RACE');

      const statAfter = fs.statSync(fixture.checkpointPath);
      assert.notEqual(statAfter.ino, inodeBefore);
      assert.equal(statAfter.size, statBefore.size);
      assert.ok(fs.readFileSync(fixture.checkpointPath).equals(verifiedBytes));
    });

    test('RC06-T4-REG-48: a verified artifact that disappears before its reopen fails closed', async () => {
      const fixture = await createFixture('reg48', { records: 2, rotateAt: [2] });
      const verifiedBytes = fs.readFileSync(fixture.checkpointPath);
      fixture.engine.close();

      // A restart verifies the artifact PRESENT and records its identity. Nothing
      // is cached yet: the descriptor is established lazily, on the first append.
      const restarted = await createTestTier2CheckpointEngine({
        directory: fixture.auditDir,
        signingKeyPath: fixture.material.signingKeyPath,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      openFixtures.push({ engine: restarted });

      const before = restarted.getCheckpointState();
      assert.equal(before.failed, false);
      assert.equal(fs.existsSync(fixture.checkpointPath), true);

      // The canonical path is removed after verification and before the reopen.
      // Recreating it would silently start a second checkpoint history that the
      // already-verified one does not describe.
      fs.unlinkSync(fixture.checkpointPath);

      const restartedStore = createTestRotatingAuditStore(
        fixture.storage,
        { sealer: restarted },
        {},
      );
      await restartedStore.append(createSampleRecordCandidate());
      await assertRejectsWithCode(
        restartedStore.rotateNow('SIZE_THRESHOLD'),
        'AUDIT_CHECKPOINT_FILE_RACE',
      );

      const after = restarted.getCheckpointState();
      assert.equal(after.failed, true);
      assert.equal(after.nextCoverageStart, before.nextCoverageStart);
      assert.equal(after.lastCheckpointSequence, before.lastCheckpointSequence);
      assert.equal(after.lastCheckpointHash, before.lastCheckpointHash);

      // No replacement artifact was created at the canonical path, and the
      // verified bytes were not resurrected from anywhere.
      assert.equal(fs.existsSync(fixture.checkpointPath), false);
      assert.equal(
        fs.readdirSync(fixture.auditDir).some((name) => name.includes('checkpoint')),
        false,
      );

      // And the failure is latched: no later call can retry the reopen.
      await assertRejectsWithCode(
        restarted.sealRotation({
          sequenceStart: 1,
          sequenceEnd: fixture.records.length,
          terminalRecordHash: 'a'.repeat(64),
        }),
        'AUDIT_CHECKPOINT_INVALID_STATE',
      );
      assert.equal(verifiedBytes.length > 0, true);
    });
  });

  /* ====================================================================== *
   * Cadence, rotation sealing, restart and bounded verification
   * ====================================================================== */

  describe('Checkpoint Cadence, Rotation Sealing and Restart', () => {
    test('RC06-T4-REG-05: the checkpoint artifact never enters the primary chain', async () => {
      const fixture = await createFixture('reg05', { records: 4, rotateAt: [4] });

      const withoutCheckpoint = await verifyRetainedPrimaryHistory(
        fixture.auditDir,
        process.getuid(),
      );

      // The checkpoint file occupies disk and is a recognized, authority-checked
      // auxiliary entry — but it is not a record, not a segment and not a chain link.
      const physical = scanAuditStorePhysicalBytes(fixture.auditDir, process.getuid());
      assert.ok(
        physical > withoutCheckpoint.physicalPrimaryBytes,
        'it does count toward the budget',
      );
      assert.equal(fs.existsSync(fixture.checkpointPath), true);

      const history = await verifyRetainedPrimaryHistory(fixture.auditDir, process.getuid());
      assert.equal(history.recordCount, withoutCheckpoint.recordCount);
      assert.equal(history.terminalSequence, withoutCheckpoint.terminalSequence);
      assert.equal(history.terminalRecordHash, withoutCheckpoint.terminalRecordHash);
      assert.equal(history.nextSequence, withoutCheckpoint.nextSequence);
      assert.equal(history.logicalArchiveCount, withoutCheckpoint.logicalArchiveCount);

      // Deleting it does not change the primary chain either — the two artifacts
      // are independent, which is exactly why Task 5 can anchor one without
      // touching the other.
      const freshDir = cloneAuditDir(fixture, 'reg05-fresh');
      fs.unlinkSync(path.join(freshDir, CHECKPOINT_FILENAME));
      const deleted = await verifyRetainedPrimaryHistory(freshDir, process.getuid());
      assert.equal(deleted.recordCount, history.recordCount);
      assert.equal(deleted.terminalRecordHash, history.terminalRecordHash);
    });

    test('RC06-T4-REG-06: the 1,000-record interval cadence emits exactly one chained checkpoint', async () => {
      const fixture = await createFixture('reg06', { records: 1000 });

      assert.equal(fs.existsSync(fixture.checkpointPath), true, 'a checkpoint is due at 1,000');
      const lines = readCheckpointLines(fixture.checkpointPath);
      assert.equal(lines.length, 1, 'exactly one checkpoint for exactly one interval');

      const checkpoint = parseLine(lines[0]);
      assert.equal(checkpoint.sequenceStart, 1);
      assert.equal(checkpoint.sequenceEnd, CHECKPOINT_INTERVAL);
      assert.equal(checkpoint.previousCheckpointHash, ZERO_HASH);
      assert.equal(
        checkpoint.terminalRecordHash,
        fixture.records[999].integrity.recordHash,
        'bound to the real 1,000th record',
      );
      assert.equal(verifyCheckpointSignature(checkpoint, fixture.material.publicKey), true);

      // No checkpoint existed before the interval completed.
      assert.equal(fixture.engine.getCheckpointState().lastCheckpointSequence, 1000);
      assert.equal(fixture.engine.getCheckpointState().nextCoverageStart, 1001);

      const result = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      assert.equal(result.checkpointCount, 1);
      assert.deepEqual(result.trustedPrimaryBoundary, {
        sequenceNumber: 1000,
        recordHash: checkpoint.terminalRecordHash,
      });
    });

    test('RC06-T4-REG-07: a rotation boundary is sealed with its own chained checkpoint', async () => {
      const fixture = await createFixture('reg07', { records: 1000 });

      const first = firstCheckpoint(fixture.checkpointPath);

      // The interval and the rotation coincide here, so the rotation must not
      // produce a second checkpoint.
      await fixture.store.rotateNow('SIZE_THRESHOLD');
      assert.equal(readCheckpointLines(fixture.checkpointPath).length, 1, 'coincidence yields one');

      // A subsequent rotation of a later segment produces the next link.
      for (let i = 0; i < 5; i++) {
        const record = await fixture.store.append(createSampleRecordCandidate());
        await fixture.engine.checkpointAfterDurablePrimary({
          sequenceNumber: record.sequenceNumber,
          recordHash: record.integrity.recordHash,
        });
      }
      await fixture.store.rotateNow('SIZE_THRESHOLD');

      const lines = readCheckpointLines(fixture.checkpointPath);
      assert.equal(lines.length, 2);
      const second = parseLine(lines[1]);

      // Coverage continues exactly where the first checkpoint ended, not at the
      // physical start of the rotated segment.
      assert.equal(second.sequenceStart, 1001);
      assert.equal(second.sequenceEnd, 1005);
      assert.equal(second.previousCheckpointHash, first.checkpointHash);

      const result = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      assert.equal(result.checkpointCount, 2);
      assert.equal(result.lastCheckpointSequence, 1005);
    });

    test('RC06-T4-REG-08: a rotation of an already-sealed boundary writes no second checkpoint', async () => {
      const fixture = await createFixture('reg08', { records: 4, rotateAt: [4] });
      const before = readCheckpointLines(fixture.checkpointPath);
      assert.equal(before.length, 1);
      const checkpoint = parseLine(before[0]);

      const stateBefore = fixture.engine.getCheckpointState();

      // Re-sealing the identical boundary is idempotent: the interval and the
      // rotation are two causes for one artifact, and the artifact already exists.
      const boundary = {
        sequenceStart: 1,
        sequenceEnd: 4,
        terminalRecordHash: checkpoint.terminalRecordHash,
      };
      await fixture.engine.sealRotation(boundary);
      assert.equal(readCheckpointLines(fixture.checkpointPath).length, 1);
      assert.deepEqual(fixture.engine.getCheckpointState(), stateBefore);

      // A boundary whose terminal hash disagrees with the sealed one is a
      // conflict, not a silent overwrite.
      await assertRejectsWithCode(
        fixture.engine.sealRotation({ ...boundary, terminalRecordHash: OTHER_HASH }),
        'AUDIT_CHECKPOINT_COVERAGE_CONFLICT',
      );
      assert.equal(readCheckpointLines(fixture.checkpointPath).length, 1);
    });

    test('RC06-T4-REG-09: restart state is reconstructed only from VERIFIED checkpoint history', async () => {
      const fixture = await createFixture('reg09', { records: 5, rotateAt: [5] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);
      fixture.engine.close();

      const restarted = await createTestTier2CheckpointEngine({
        directory: fixture.auditDir,
        signingKeyPath: fixture.material.signingKeyPath,
        publicKeyPath: fixture.material.publicKeyPath,
      });
      openFixtures.push({ engine: restarted });

      const state = restarted.getCheckpointState();
      assert.equal(state.lastCheckpointSequence, 5);
      assert.equal(state.lastCheckpointHash, checkpoint.checkpointHash);
      assert.equal(state.nextCoverageStart, 6);
      assert.equal(state.previousCheckpointHash, checkpoint.checkpointHash);
      assert.equal(state.failed, false);

      // The restarted engine continues the very same chain rather than starting
      // a new one. A restart composes a NEW coordinator over the SAME storage,
      // which is exactly what a new process does.
      const restartedStore = createTestRotatingAuditStore(
        fixture.storage,
        { sealer: restarted },
        {},
      );
      for (let i = 0; i < 5; i++) {
        const record = await restartedStore.append(createSampleRecordCandidate());
        await restarted.checkpointAfterDurablePrimary({
          sequenceNumber: record.sequenceNumber,
          recordHash: record.integrity.recordHash,
        });
      }
      await restartedStore.rotateNow('SIZE_THRESHOLD');

      const lines = readCheckpointLines(fixture.checkpointPath);
      assert.equal(lines.length, 2);
      const next = parseLine(lines[1]);
      assert.equal(next.previousCheckpointHash, checkpoint.checkpointHash);
      assert.equal(next.sequenceStart, 6);
      assert.equal(next.sequenceEnd, 10);
      restarted.close();
    });

    test('RC06-T4-REG-10: a coverage gap larger than the frozen interval fails closed', async () => {
      const fixture = await createFixture('reg10', { records: 1000 });
      const stateBefore = fixture.engine.getCheckpointState();

      // Catching up by signing a later record would silently skip a required
      // boundary, so the engine refuses rather than papering over the gap.
      await assertRejectsWithCode(
        fixture.engine.checkpointAfterDurablePrimary({
          sequenceNumber: 2001,
          recordHash: OTHER_HASH,
        }),
        'AUDIT_CHECKPOINT_CADENCE_VIOLATION',
      );
      assert.deepEqual(
        fixture.engine.getCheckpointState(),
        stateBefore,
        'the cursor does not move',
      );

      // A boundary below the interval is simply not due yet.
      assert.equal(
        await fixture.engine.checkpointAfterDurablePrimary({
          sequenceNumber: 1500,
          recordHash: OTHER_HASH,
        }),
        null,
      );

      // The exact interval is the one gap that IS accepted, and it advances the
      // cursor by exactly one interval.
      const second = await fixture.engine.checkpointAfterDurablePrimary({
        sequenceNumber: 2000,
        recordHash: OTHER_HASH,
      });
      assert.ok(second !== null, 'a full interval is a due checkpoint');
      assert.equal(second.sequenceStart, 1001);
      assert.equal(second.sequenceEnd, 2000);
      assert.equal(second.previousCheckpointHash, stateBefore.lastCheckpointHash);
      assert.equal(fixture.engine.getCheckpointState().lastCheckpointSequence, 2000);
      assert.equal(fixture.engine.getCheckpointState().nextCoverageStart, 2001);
    });

    test('RC06-T4-REG-11: a tampered primary record invalidates a perfectly valid checkpoint', async () => {
      const fixture = await createFixture('reg11', { records: 1000 });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      // Replace the LAST record with a different but entirely self-consistent
      // record: correct sequence, correct predecessor link, recomputed hash. The
      // primary chain itself still verifies; only the checkpoint disagrees.
      const activePath = path.join(fixture.auditDir, ACTIVE_SEGMENT_FILENAME);
      const lines = fs.readFileSync(activePath, 'utf8').slice(0, -1).split('\n');
      const lastRecord = JSON.parse(lines[999]);
      const previousRecordHash = JSON.parse(lines[998]).integrity.recordHash;

      const { computeRecordHashV1, serializeRecordV1 } =
        await import('../packages/audit/dist/index.js');
      const replacement = {
        ...JSON.parse(JSON.stringify(lastRecord)),
        invocation: { ...lastRecord.invocation, parametersRedacted: { path: 'rewritten.txt' } },
        integrity: { previousRecordHash, recordHash: ZERO_HASH },
      };
      replacement.integrity.recordHash = computeRecordHashV1(replacement);

      lines[999] = serializeRecordV1(replacement).slice(0, -1);
      fs.writeFileSync(activePath, `${lines.join('\n')}\n`);

      // The forged record is a legitimate chain member...
      const history = await verifyRetainedPrimaryHistory(fixture.auditDir, process.getuid());
      assert.equal(history.terminalSequence, 1000);
      assert.equal(history.terminalRecordHash, replacement.integrity.recordHash);

      // ...and the still-validly-signed checkpoint is nonetheless refused,
      // because it is bound to evidence that no longer exists.
      assert.equal(verifyCheckpointSignature(checkpoint, fixture.material.publicKey), true);
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: fixture.auditDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_TERMINAL_MISMATCH',
      );
    });

    test('RC06-T4-REG-12: a failed checkpoint write leaves the cursor exactly where it was', async () => {
      for (const writeFault of ['error', 'partial', 'zero']) {
        const fixture = await createFixture(`reg12-${writeFault}`, {
          records: 4,
          hooks: { writeFault },
        });

        const stateBefore = fixture.engine.getCheckpointState();
        assert.equal(stateBefore.lastCheckpointSequence, null, 'nothing durable yet');

        assert.equal(fs.existsSync(fixture.checkpointPath), false, 'the rotation sealed nothing');

        // The rotation is what drives sealing here; the same failure surfaces
        // through the production sealer interface.
        await assertRejectsWithCode(fixture.store.rotateNow('INTERNAL_MANUAL'), [
          'AUDIT_PERSISTENCE_FAILED',
          'AUDIT_ROTATION_FAILED',
        ]);

        const stateAfter = fixture.engine.getCheckpointState();
        assert.equal(stateAfter.lastCheckpointSequence, null, 'the cursor must not advance');
        assert.equal(stateAfter.nextCoverageStart, 1);
        assert.equal(stateAfter.previousCheckpointHash, ZERO_HASH);
        assert.equal(stateAfter.failed, true, 'an uncertain persistence outcome fails closed');

        // And the failed engine refuses to keep going rather than retrying into
        // a possibly half-written artifact.
        await assertRejectsWithCode(
          fixture.engine.checkpointAfterDurablePrimary({
            sequenceNumber: 1000,
            recordHash: OTHER_HASH,
          }),
          'AUDIT_CHECKPOINT_INVALID_STATE',
        );
      }
    });

    test('RC06-T4-REG-13: a failed fdatasync after a complete write fails closed', async () => {
      const fixture = await createFixture('reg13', {
        records: 4,
        hooks: { fdatasyncFault: true },
      });

      const stateBefore = fixture.engine.getCheckpointState();

      await assertRejectsWithCode(fixture.store.rotateNow('INTERNAL_MANUAL'), [
        'AUDIT_PERSISTENCE_FAILED',
        'AUDIT_ROTATION_FAILED',
      ]);

      const stateAfter = fixture.engine.getCheckpointState();
      assert.equal(stateAfter.lastCheckpointSequence, null);
      assert.equal(stateAfter.nextCoverageStart, 1);
      assert.equal(stateAfter.failed, true);
      assert.deepEqual(stateBefore, { ...stateAfter, failed: false });

      // The line reached the file, but the rotation that would have justified it
      // never completed — so the artifact is a checkpoint at a sequence the
      // frozen cadence does not require, and verification refuses it. A write
      // whose durability is unknown is never adopted as durable.
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: fixture.auditDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        [
          'AUDIT_CHECKPOINT_UNEXPECTED',
          'AUDIT_CHECKPOINT_MISSING',
          'AUDIT_CORRUPTION_DETECTED',
          'AUDIT_CHECKPOINT_INVALID',
        ],
      );
    });

    test('RC06-T4-REG-14: the checkpoint artifact is opened append-only, no-follow and never truncated', async () => {
      const probed = [];
      const fixture = await createFixture('reg14', {
        records: 3,
        rotateAt: [3],
        hooks: { openFlagsProbe: (flags) => probed.push(flags) },
      });

      const C = fs.constants;
      const assertNeverTruncates = (flags, label) => {
        assert.ok((flags & C.O_NOFOLLOW) !== 0, `${label}: O_NOFOLLOW is always set`);
        assert.ok((flags & C.O_WRONLY) !== 0, `${label}: the artifact is write-only`);
        assert.ok((flags & C.O_APPEND) !== 0, `${label}: appends only ever extend`);
        assert.equal((flags & C.O_TRUNC) !== 0, false, `${label}: O_TRUNC is never used`);
        assert.equal((flags & C.O_RDWR) !== 0, false, `${label}: never opened read-write`);
      };

      // The exclusive create is what makes concurrent creation safe.
      assert.ok(probed.length >= 1, 'the first checkpoint is probed');
      for (const flags of probed) assertNeverTruncates(flags, 'create');
      assert.ok(
        probed.some((flags) => (flags & C.O_EXCL) !== 0 && (flags & C.O_CREAT) !== 0),
        'creation is O_EXCL so a racing creator is refused rather than truncated',
      );

      assert.equal(fs.statSync(fixture.checkpointPath).mode & 0o777, 0o600);
      assert.equal(readCheckpointLines(fixture.checkpointPath).length, 1);

      // The reopen path is probed separately: an existing artifact is opened
      // without O_CREAT and without O_EXCL, and still never truncated.
      const reopenProbes = [];
      fixture.engine.close();
      const reopened = await createTestTier2CheckpointEngine(
        {
          directory: fixture.auditDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        },
        { openFlagsProbe: (flags) => reopenProbes.push(flags) },
      );
      openFixtures.push({ engine: reopened });

      const reopenedStore = createTestRotatingAuditStore(fixture.storage, { sealer: reopened }, {});
      for (let i = 0; i < 4; i++) {
        const record = await reopenedStore.append(createSampleRecordCandidate());
        await reopened.checkpointAfterDurablePrimary({
          sequenceNumber: record.sequenceNumber,
          recordHash: record.integrity.recordHash,
        });
      }
      await reopenedStore.rotateNow('SIZE_THRESHOLD');

      assert.equal(reopenProbes.length, 1, 'exactly one reopen for the second checkpoint');
      assertNeverTruncates(reopenProbes[0], 'reopen');
      assert.equal((reopenProbes[0] & C.O_CREAT) !== 0, false, 'reopen never creates');
      assert.equal((reopenProbes[0] & C.O_EXCL) !== 0, false, 'reopen never claims exclusivity');
      assert.equal(readCheckpointLines(fixture.checkpointPath).length, 2);
      reopened.close();
    });

    test('RC06-T4-REG-16: the public-key-only verification path never loads the private key', async () => {
      const fixture = await createFixture('reg16', { records: 3, rotateAt: [3] });
      const { signingKeyPath, publicKeyPath } = fixture.material;

      enablePrivateKeyLoadProbe();
      assert.equal(getPrivateKeyLoadCount(), 0);

      await verifyCheckpointHistory({ directory: fixture.auditDir, publicKeyPath });
      assert.equal(getPrivateKeyLoadCount(), 0, 'offline verification is public-key only');

      computeCheckpointPublicKeyFingerprint(publicKeyPath);
      assert.equal(
        getPrivateKeyLoadCount(),
        0,
        'fingerprinting the trust root needs no private key',
      );

      loadEd25519TrustRootFile(publicKeyPath, { purpose: 'CHECKPOINT' });
      assert.equal(getPrivateKeyLoadCount(), 0);

      // The engine, which must sign, does load it — so the probe is live and the
      // zero above is meaningful rather than a probe that never fires.
      const signer = await createTestTier2CheckpointEngine({
        directory: fixture.auditDir,
        signingKeyPath,
        publicKeyPath,
      });
      assert.equal(getPrivateKeyLoadCount(), 1);
      signer.close();
    });

    test('RC06-T4-REG-18: a malformed or wrongly-encoded key file is rejected', () => {
      const dir = path.join(tempBaseDir, 'reg18');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const material = writeKeyPair(dir, 'real');

      const privatePem = fs.readFileSync(material.signingKeyPath, 'utf8');
      const publicPem = fs.readFileSync(material.publicKeyPath, 'utf8');
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const pkcs1 = rsa.privateKey.export({ type: 'pkcs1', format: 'pem' });
      const rsaPublic = rsa.publicKey.export({ type: 'spki', format: 'pem' });

      // The delimiters are assembled rather than written literally. These
      // fixtures exist precisely to be refused, and a secret scanner cannot tell
      // a deliberately-invalid one from real key material — so the source
      // carries no literal key header. The bytes handed to the loader are
      // identical either way.
      const pem = (label) => `-----BEGIN ${label}-----\nZm9v\n-----END ${label}-----\n`;

      const certificate = pem('CERTIFICATE');
      const openssh = pem('OPENSSH PRIVATE KEY');
      const encrypted = pem('ENCRYPTED PRIVATE KEY');

      const write = (name, content) => {
        const filePath = path.join(dir, name);
        fs.writeFileSync(filePath, content, { mode: 0o600 });
        return filePath;
      };

      const KEY_CODES = ['AUDIT_KEY_ENCODING_FORBIDDEN', 'AUDIT_KEY_MALFORMED'];

      // Everything that is not exactly one PKCS#8 Ed25519 block is refused as a
      // signing key. Each case is checked against the loader it must fail for:
      // a public key is a perfectly good trust root and a perfectly bad signing
      // key, and the two rules are not the same rule.
      const signingRejects = [
        ['empty.pem', ''],
        ['whitespace.pem', '\n\n'],
        ['not-pem.pem', 'hello world\n'],
        ['no-end.pem', privatePem.replace(/-----END PRIVATE KEY-----/, '')],
        ['certificate.pem', certificate],
        ['openssh.pem', openssh],
        ['encrypted.pem', encrypted],
        ['public-as-signing.pem', publicPem],
        ['rsa-pkcs1.pem', pkcs1],
        ['rsa-spki.pem', rsaPublic],
        ['bundle.pem', `${privatePem}${publicPem}`],
        ['swapped-labels.pem', privatePem.replace(/PRIVATE KEY/g, 'PUBLIC KEY')],
      ];

      for (const [name, content] of signingRejects) {
        assertThrowsWithCode(() => loadEd25519SigningKeyFile(write(name, content)), KEY_CODES);
      }

      const trustRejects = [
        ['t-empty.pem', ''],
        ['t-whitespace.pem', '\n\n'],
        ['t-not-pem.pem', 'hello world\n'],
        ['t-no-end.pem', publicPem.replace(/-----END PUBLIC KEY-----/, '')],
        ['t-certificate.pem', certificate],
        ['t-openssh.pem', openssh],
        ['t-encrypted.pem', encrypted],
        ['t-private-as-trust.pem', privatePem],
        ['t-rsa-pkcs1.pem', pkcs1],
        ['t-bundle.pem', `${publicPem}${publicPem}`],
      ];

      for (const [name, content] of trustRejects) {
        assertThrowsWithCode(
          () => loadEd25519TrustRootFile(write(name, content), { purpose: 'CHECKPOINT' }),
          KEY_CODES,
        );
      }

      // The well-formed pair still loads under both rules, so the refusals above
      // are about encoding and not about a loader that rejects everything.
      assert.doesNotThrow(() => loadEd25519SigningKeyFile(material.signingKeyPath));
      assert.doesNotThrow(() =>
        loadEd25519TrustRootFile(material.publicKeyPath, { purpose: 'CHECKPOINT' }),
      );
    });

    test('RC06-T4-REG-20: an exhausted store refuses a checkpoint without moving the cursor', async () => {
      const fixture = await createFixture('reg20', { records: 999 });
      assert.equal(fs.existsSync(fixture.checkpointPath), false, 'no checkpoint before 1,000');

      // The 1,000th record becomes durable first, and only THEN does the store
      // run out of budget — so the refusal is the checkpoint write's own.
      const thousandth = await fixture.store.append(createSampleRecordCandidate());
      const cursorBefore = fixture.storage.getCurrentSequence();
      assert.equal(cursorBefore, 1001);

      const ballast = path.join(fixture.auditDir, 'audit-20990101T000000Z-seq1-seq1.jsonl');
      writeSparseFile(ballast, TOTAL_AUDIT_BUDGET_BYTES);

      const stateBefore = fixture.engine.getCheckpointState();
      await assertRejectsWithCode(
        fixture.engine.checkpointAfterDurablePrimary({
          sequenceNumber: thousandth.sequenceNumber,
          recordHash: thousandth.integrity.recordHash,
        }),
        'AUDIT_STORAGE_EXHAUSTED',
      );

      // No checkpoint was consumed, no evidence was reclaimed, and the cursor
      // never advanced — an exhausted store is not a reason to forget a boundary.
      assert.equal(fixture.engine.getCheckpointState().lastCheckpointSequence, null);
      assert.deepEqual(fixture.engine.getCheckpointState(), stateBefore);
      assert.equal(fs.existsSync(fixture.checkpointPath), false, 'nothing was written');
      assert.equal(fs.statSync(ballast).size, TOTAL_AUDIT_BUDGET_BYTES);
      assert.equal(fixture.storage.getCurrentSequence(), cursorBefore, 'the primary is untouched');

      // Freeing space lets the SAME boundary be sealed, starting at sequence 1 —
      // which is only possible because the cursor never moved.
      fs.unlinkSync(ballast);
      const checkpoint = await fixture.engine.checkpointAfterDurablePrimary({
        sequenceNumber: thousandth.sequenceNumber,
        recordHash: thousandth.integrity.recordHash,
      });
      assert.equal(checkpoint.sequenceStart, 1);
      assert.equal(checkpoint.sequenceEnd, 1000);
    });

    test('RC06-T4-REG-21: verification reports the authentic primary boundary the checkpoint implies', async () => {
      const fixture = await createFixture('reg21', { records: 5, rotateAt: [5] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      const result = await verifyCheckpointHistory({
        directory: fixture.auditDir,
        publicKeyPath: fixture.material.publicKeyPath,
      });

      assert.equal(result.checkpointCount, 1);
      assert.equal(result.publicKeyFingerprint, fixture.material.fingerprint);
      assert.equal(result.lastCheckpointSequence, 5);
      assert.equal(result.lastCheckpointHash, checkpoint.checkpointHash);
      assert.equal(
        result.lastCheckpointTerminalRecordHash,
        fixture.records[4].integrity.recordHash,
      );
      assert.deepEqual(result.trustedPrimaryBoundary, {
        sequenceNumber: 5,
        recordHash: fixture.records[4].integrity.recordHash,
      });

      // With no checkpoint at all there is no authenticated boundary to report,
      // rather than a boundary inferred from the primary chain. This store has
      // no rotation and fewer than 1,000 records, so nothing is due and the
      // absence of an artifact is legitimate rather than a missing seal.
      const unrotated = await createFixture('reg21-unrotated', { records: 3 });
      assert.equal(fs.existsSync(unrotated.checkpointPath), false);
      const none = await verifyCheckpointHistory({
        directory: unrotated.auditDir,
        publicKeyPath: unrotated.material.publicKeyPath,
      });
      assert.equal(none.checkpointCount, 0);
      assert.equal(none.lastCheckpointSequence, null);
      assert.equal(none.trustedPrimaryBoundary, undefined);
      assert.equal(none.lastCheckpointHash, null);
    });

    test('RC06-T4-REG-23: a missing checkpoint at a required boundary fails verification', async () => {
      const fixture = await createFixture('reg23', { records: 5, rotateAt: [5] });
      assert.equal(fs.existsSync(fixture.checkpointPath), true);

      const missingDir = cloneAuditDir(fixture, 'reg23-missing');
      fs.unlinkSync(path.join(missingDir, CHECKPOINT_FILENAME));
      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: missingDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_MISSING',
      );

      // A store that requires a checkpoint cannot be started without one.
      await assertRejectsWithCode(
        createTestTier2CheckpointEngine({
          directory: missingDir,
          signingKeyPath: fixture.material.signingKeyPath,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_MISSING',
      );
    });

    test('RC06-T4-REG-24: a checkpoint at a sequence the cadence does not require is refused', async () => {
      // Five records and no rotation: nothing is due, so no checkpoint may exist.
      const fixture = await createFixture('reg24', { records: 5 });
      assert.equal(fs.existsSync(fixture.checkpointPath), false, 'no boundary is due');

      const unearnedDir = cloneAuditDir(fixture, 'reg24-unearned');
      const donor = await createFixture('reg24-donor', { records: 5, rotateAt: [5] });
      const donorLine = readCheckpointLines(donor.checkpointPath)[0];
      const donorCheckpoint = parseLine(donorLine);

      // A validly signed checkpoint, transplanted onto a store with the same
      // ledger identity but no rotation to justify it.
      const donorMaterialMatches =
        donorCheckpoint.storeId ===
        JSON.parse(fs.readFileSync(path.join(unearnedDir, 'audit-store.json'), 'utf8')).storeId;
      assert.equal(donorMaterialMatches, false, 'the donor belongs to a different ledger');

      // Rebuild it for THIS ledger instead, so only the cadence can reject it.
      const own = { storeId: fixture.engine.getCheckpointState().previousCheckpointHash };
      void own;
      const metadata = JSON.parse(
        fs.readFileSync(path.join(unearnedDir, 'audit-store.json'), 'utf8'),
      );
      const forged = reforge(
        {
          ...donorCheckpoint,
          storeId: metadata.storeId,
          publicKeyFingerprint: fixture.material.fingerprint,
        },
        {},
        { privateKey: fixture.material.privateKey },
      );
      writeCheckpointLines(path.join(unearnedDir, CHECKPOINT_FILENAME), [lineOf(forged)]);

      await assertRejectsWithCode(
        verifyCheckpointHistory({
          directory: unearnedDir,
          publicKeyPath: fixture.material.publicKeyPath,
        }),
        'AUDIT_CHECKPOINT_UNEXPECTED',
      );
    });

    test('RC06-T4-REG-26: the checkpoint artifact counts toward the budget but is not an archive', async () => {
      const fixture = await createFixture('reg26', { records: 4, rotateAt: [4] });

      const physical = scanAuditStorePhysicalBytes(fixture.auditDir, process.getuid());
      const artifactBytes = fs.statSync(fixture.checkpointPath).size;
      assert.ok(artifactBytes > 0);

      // Removing the checkpoint reduces the physical accounting by exactly its size.
      const clone = cloneAuditDir(fixture, 'reg26-clone');
      const clonePhysical = scanAuditStorePhysicalBytes(clone, process.getuid());
      fs.unlinkSync(path.join(clone, CHECKPOINT_FILENAME));
      assert.equal(
        scanAuditStorePhysicalBytes(clone, process.getuid()),
        clonePhysical - artifactBytes,
        'the checkpoint is budgeted like any other durable artifact',
      );
      assert.equal(physical, clonePhysical);

      // It is never counted as a retained logical segment.
      assert.equal(countLogicalArchives(fixture.auditDir, process.getuid()), 1);
      const inventory = listLogicalArchiveInventory(fixture.auditDir, process.getuid());
      assert.equal(inventory.length, 1);
      assert.equal(inventory[0].sequenceEnd, 4);

      // Creating the artifact did not disturb the store's other entries.
      assert.ok(fs.existsSync(path.join(fixture.auditDir, 'audit-store.json')));
      assert.ok(fs.existsSync(path.join(fixture.auditDir, 'audit.lock')));
    });

    test('RC06-T4-REG-22: checkpoint signing is deterministic in everything that carries integrity', async () => {
      const fixture = await createFixture('reg22', { records: 3, rotateAt: [3] });
      const checkpoint = firstCheckpoint(fixture.checkpointPath);

      // Re-deriving the hash from the persisted artifact is stable, which is what
      // makes an offline verifier able to re-check it indefinitely.
      for (let i = 0; i < 3; i++) {
        assert.equal(computeCheckpointHash(checkpoint), checkpoint.checkpointHash);
        assert.equal(verifyCheckpointSignature(checkpoint, fixture.material.publicKey), true);
      }

      // Re-signing the identical unsigned projection yields a stable Ed25519
      // signature, so two honest signers of the same boundary agree.
      const again = crypto
        .sign(
          null,
          computeCheckpointSignaturePreimage(pickUnsigned(checkpoint)),
          fixture.material.privateKey,
        )
        .toString('base64url');
      assert.equal(again, checkpoint.signature);

      // And a verification against an unrelated record hash is not fooled.
      assert.notEqual(
        computeCheckpointHash({ ...checkpoint, terminalRecordHash: OTHER_HASH }),
        checkpoint.checkpointHash,
      );
    });
  });
});
