/**
 * CesSpace ARC — RC-06 Task 5: Tier-3 External Anchoring Client, Crash-Recoverable
 * Spool & Cryptographic Receipts
 *
 * Test suite verifying:
 * - The frozen Tier-3 anchor constants and the closed `AnchorReceiptV1` schema
 * - The exact Ed25519 receipt signature preimage (frozen domain, UTF-8 canonical
 *   JSON, no separator, no length prefix, no pre-hash)
 * - Endpoint rules: https only, no credentials, no fragment, 2 KiB bound
 * - TLS 1.3 minimum, hostname and CA verification, no redirect following
 * - The crash-recoverable spool and the durability ordering that makes it work
 * - Cryptographically verified receipts as the only acknowledgement
 * - Reconciliation states A–F, including both integrity failures
 * - The five-attempt retry cycle and the fixed `1s, 2s, 4s, 8s, 16s` vector
 * - Backpressure: `ANCHOR_SPOOL_FULL` halting privileged operations
 * - All frozen Task-5 negative security controls RC06-NEG-84..99
 *
 * Control namespace: Task 5 owns exactly the RC06-NEG range 84..99 and no more.
 * The additive regressions below carry the RC06-T5-REG-nn namespace precisely
 * because it is NOT part of the frozen architecture numbering — they assert
 * behavior, they are not frozen security controls, and they must never be
 * counted as controls. The neighbouring ranges are deliberately untouched here:
 * 64..83 belong to Task 4 (Tier-2 checkpoints) and 48..63 to Task 3 (rotation).
 * This file claims no control from either range.
 *
 * Two ideas run through every control in Category 10. The first is that HTTP
 * success is not acknowledgement: a 200 with no receipt, a receipt signed by the
 * wrong key, a receipt bound to another checkpoint or another store, and a
 * receipt that merely *looks* well-formed are all refused, because only a
 * signature that verifies under the pinned trust root acknowledges anything. The
 * second is that the durability order is the security property: a checkpoint is
 * never transmitted before its spool entry is on stable storage, and a receipt is
 * never durable before it has been verified — so no crash can produce an
 * unacknowledged transmission or a forgotten acknowledgement.
 *
 * TLS material is generated at test time by `tests/helpers/rc05-test-pki.mjs`.
 * The repository commits no certificate or private key, so a missing `openssl`
 * binary is a hard environment failure rather than a silent skip.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import {
  PersistentAuditStorage,
  ACTIVE_SEGMENT_FILENAME,
  CHECKPOINT_FILENAME,
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_RECEIPT_SIGNATURE_DOMAIN,
  ANCHOR_RECEIPT_ALLOWED_KEYS,
  ANCHOR_SPOOL_FILENAME_REGEX,
  ANCHOR_SPOOL_FILE_MODE,
  ANCHOR_SPOOL_DIRECTORY_MODE,
  ANCHOR_IDEMPOTENCY_HEADER,
  ANCHOR_ACKNOWLEDGING_STATUS_CODES,
  ANCHOR_RETRY_BACKOFF_MS,
  ANCHOR_REQUEST_TIMEOUT_MS,
  MAX_ANCHOR_ATTEMPTS,
  MAX_ANCHOR_ENDPOINT_BYTES,
  MAX_ANCHOR_RECEIPT_BYTES,
  MAX_ANCHOR_SPOOL_BYTES,
  MAX_ANCHOR_SPOOL_ENTRY_BYTES,
  MAX_PENDING_ANCHOR_CHECKPOINTS,
  CHECKPOINT_INTERVAL,
  validateAnchorReceiptV1,
  computeAnchorReceiptSignaturePreimage,
  computeAnchorReceiptPublicKeyFingerprint,
  verifyAnchorReceiptSignature,
  serializeAnchorReceiptV1,
  parseAndValidateAnchorReceiptLineV1,
  validateAnchorEndpoint,
  Tier3AnchorEngine,
  openTier3AnchorEngine,
  scanAuditStorePhysicalBytes,
  parseAndValidateCheckpointLineV1,
  computeCheckpointHash,
  computeCheckpointSignaturePreimage,
  verifyCheckpointSignature,
  serializeCheckpointV1,
  getProcessUid,
} from '../packages/audit/dist/index.js';

import {
  createTestTier3AnchorEngine,
  signTestAnchorReceipt,
  ANCHOR_TEST_TOKEN,
} from '../packages/audit/dist/internal/anchor-testing.js';
import { createTestTier2CheckpointEngine } from '../packages/audit/dist/internal/checkpoint-testing.js';
import { createTestRotatingAuditStore } from '../packages/audit/dist/internal/rotation-testing.js';
import { hasOpenssl, createTestPki, symlinkTo } from './helpers/rc05-test-pki.mjs';

const STORE_EXAMPLE_ID = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
const ENDPOINT = 'https://anchor.example.invalid/v1/anchor';

/**
 * The store shape that really holds one more checkpoint than the pending ceiling.
 *
 * A store retains at most `MAX_ARCHIVE_SEGMENTS` logical archives, so at most a
 * hundred checkpoints can come from rotated-segment terminals. The
 * hundred-and-first therefore has to come from the interval cadence, which fires
 * on exactly the `CHECKPOINT_INTERVAL`-th record since the previous checkpoint —
 * and it has to come first, because the append path refuses a new record once the
 * archive ceiling has been reached. That is why the fixture is an uninterrupted
 * run of interval-length records followed by one rotation per remaining record,
 * and why nothing here is a synthesized checkpoint: each of the hundred-and-one
 * is signed, bound and durable exactly as a production store would make it.
 */
const OVERFLOW_CHECKPOINTS = MAX_PENDING_ANCHOR_CHECKPOINTS + 1;
const OVERFLOW_RECORDS = CHECKPOINT_INTERVAL + MAX_PENDING_ANCHOR_CHECKPOINTS;
const OVERFLOW_ROTATE_AT = Array.from(
  { length: MAX_PENDING_ANCHOR_CHECKPOINTS },
  (_, index) => CHECKPOINT_INTERVAL + index + 1,
);
/** The store metadata artifact, read directly because `storeId` is durable state. */
const STORE_METADATA_FILENAME = 'audit-store.json';

/** Built declarations, for the public-surface assertions. */
const PACKAGE_DIST_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../packages/audit/dist',
);

/* -------------------------------------------------------------------------- *
 * Harness
 * -------------------------------------------------------------------------- */

function createSampleRecordCandidate() {
  return {
    eventId: crypto.randomUUID(),
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

/** Asserts `text` never names the anchor peer or carries key material. */
function assertNoDisclosure(text, endpoint) {
  assert.equal(text.includes('anchor.example.invalid'), false, 'must not name the anchor host');
  assert.equal(text.includes(endpoint), false, 'must not echo the configured endpoint');
  assert.equal(text.includes('BEGIN'), false, 'must not contain PEM material');
  assert.equal(text.includes('PRIVATE'), false, 'must not contain key material');
}

describe('CesSpace ARC — RC-06 Task 5: Tier-3 External Anchoring', () => {
  let tempBaseDir;
  let pki;
  let caPem;

  /** Fixtures whose handles are closed after the suite. */
  const openFixtures = [];
  /** Anchor servers started by individual tests. */
  const openServers = [];

  before(() => {
    assert.equal(
      hasOpenssl(),
      true,
      'the RC-06 Task-5 suite generates its own TLS material and requires the platform openssl binary',
    );
    tempBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task5-'));
    pki = createTestPki(path.join(tempBaseDir, 'pki'));
    caPem = fs.readFileSync(pki.trustedCaCertPath);
  });

  after(async () => {
    for (const server of openServers) {
      await new Promise((resolve) => server.close(resolve));
    }
    for (const fixture of openFixtures) {
      try {
        await fixture.engine?.close();
      } catch {
        // ignore
      }
      try {
        fixture.checkpointEngine?.close();
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

  /* ---------------------------------------------------------------------- *
   * Keys, fixtures and servers
   * ---------------------------------------------------------------------- */

  /** Generates an Ed25519 keypair written as 0600 PKCS#8 / SPKI PEM files. */
  function writeKeyPair(dir, name) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

    const signingKeyPath = path.join(dir, `${name}-signing.pem`);
    const publicKeyPath = path.join(dir, `${name}-public.pem`);
    fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
    });
    fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
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
   * Builds a real audit store with a real Tier-2 checkpoint engine.
   *
   * The checkpoint cadence is the frozen one, not a test convenience: a
   * checkpoint is required at every rotated-segment terminal and at every
   * thousandth record since the last checkpoint, and the verifier refuses a
   * checkpoint at any sequence the cadence does not require. So a fixture
   * produces checkpoints the only way a real store can — by really rotating —
   * and `checkpointCount` is sugar for `rotateAt: [1..checkpointCount]`, which
   * yields that many checkpoints whose covers are `[1..1]`, `[2..2]`, and so on.
   *
   * Without either option the fixture rotates once, at the final record, so the
   * default shape is a single checkpoint covering the whole ledger. That is how
   * the backpressure controls reach the hundred-entry and one-mebibyte ceilings
   * without inventing store state: every one of those checkpoints is really
   * signed and really bound to the primary ledger.
   */
  async function createFixture(name, options = {}) {
    const {
      records = 5,
      checkpointCount = null,
      rotateAt: explicitRotateAt = null,
      anchorMode = 'ENABLED',
      anchorMaterial: providedAnchorMaterial = null,
      checkpointMaterial: providedCheckpointMaterial = null,
    } = options;

    const root = path.join(tempBaseDir, name);
    const auditDir = path.join(root, 'audit');
    const keyDir = path.join(root, 'keys');

    const checkpointMaterial = providedCheckpointMaterial ?? writeKeyPair(keyDir, 'checkpoint');
    const anchorMaterial = providedAnchorMaterial ?? writeKeyPair(keyDir, 'anchor');

    const storage = new PersistentAuditStorage({
      directory: auditDir,
      createIfMissing: true,
      metadata: {
        checkpointPublicKeyFingerprint: checkpointMaterial.fingerprint,
        anchorMode,
        ...(anchorMode === 'ENABLED'
          ? { anchorReceiptPublicKeyFingerprint: anchorMaterial.fingerprint }
          : {}),
      },
    });
    storage.initialize();

    const checkpointEngine = await createTestTier2CheckpointEngine({
      directory: auditDir,
      signingKeyPath: checkpointMaterial.signingKeyPath,
      publicKeyPath: checkpointMaterial.publicKeyPath,
    });

    const store = createTestRotatingAuditStore(storage, { sealer: checkpointEngine }, {});

    const rotateAt =
      explicitRotateAt ??
      (checkpointCount === null
        ? records > 0
          ? [records]
          : []
        : Array.from({ length: checkpointCount }, (_, index) => index + 1));

    const appended = [];
    for (let i = 1; i <= records; i++) {
      const record = await store.append(createSampleRecordCandidate());
      appended.push(record);

      // The interval cadence is offered at every durable boundary exactly as a
      // production composition offers it. It answers `null` while the frozen
      // interval has not elapsed, which is always the case here; the rotation
      // terminals below are what actually require a checkpoint.
      await checkpointEngine.checkpointAfterDurablePrimary({
        sequenceNumber: record.sequenceNumber,
        recordHash: record.integrity.recordHash,
      });

      // Rotating is what seals. `rotateNow` hands the segment boundary to the
      // sealer before anything moves, so the checkpoint is signed and durable
      // before the segment is archived — the real ordering, not a simulation.
      if (rotateAt.includes(i)) {
        await store.rotateNow('SIZE_THRESHOLD');
      }
    }

    const metadataPath = path.join(auditDir, STORE_METADATA_FILENAME);
    const storeId = JSON.parse(fs.readFileSync(metadataPath, 'utf8')).storeId;

    const fixture = {
      root,
      auditDir,
      keyDir,
      storeId,
      checkpointMaterial,
      anchorMaterial,
      storage,
      checkpointEngine,
      store,
      records: appended,
      checkpointPath: path.join(auditDir, CHECKPOINT_FILENAME),
      receiptPath: path.join(auditDir, ANCHOR_RECEIPT_FILENAME),
      spoolDir: path.join(auditDir, ANCHOR_SPOOL_DIRNAME),
    };
    openFixtures.push(fixture);
    return fixture;
  }

  /** The engine configuration for a fixture, defaulting to a real https endpoint. */
  function anchorConfig(fixture, overrides = {}) {
    return {
      directory: fixture.auditDir,
      checkpointPublicKeyPath: fixture.checkpointMaterial.publicKeyPath,
      anchorEndpoint: ENDPOINT,
      anchorReceiptPublicKeyPath: fixture.anchorMaterial.publicKeyPath,
      workspacePaths: [],
      ...overrides,
    };
  }

  /**
   * Reads back the checkpoint artifact exactly as it is on disk: one canonical
   * line per checkpoint, in order, each still LF-terminated.
   */
  function readCheckpointLines(fixture) {
    const raw = fs.readFileSync(fixture.checkpointPath, 'utf8');
    assert.ok(raw.endsWith('\n'), 'a checkpoint artifact must be LF-terminated');
    return raw
      .slice(0, -1)
      .split('\n')
      .map((line) => `${line}\n`);
  }

  /** Reads back every checkpoint the fixture's engine has sealed, in order. */
  function readCheckpoints(fixture) {
    return readCheckpointLines(fixture).map(
      (line) => parseAndValidateCheckpointLineV1(line).checkpoint,
    );
  }

  function spoolEntryPath(fixture, checkpointHash) {
    return path.join(fixture.spoolDir, `${checkpointHash}.json`);
  }

  /** Every entry currently in the fixture's spool directory, in directory order. */
  function spoolEntries(fixture) {
    if (!fs.existsSync(fixture.spoolDir)) return [];
    return fs.readdirSync(fixture.spoolDir).sort();
  }

  /**
   * Mints a checkpoint that has every property a caller is able to control.
   *
   * The signature is produced over the frozen preimage exactly as the real Tier-2
   * engine produces it, the hash is the canonical digest of the checkpoint the
   * caller actually holds, and the back-link and coverage are taken from the
   * fixture's real durable artifact so they genuinely continue its history.
   * Anything a caller can get right, this helper gets right; the caller then
   * says which single property should be wrong.
   *
   * That is the point. `RC06-T5-REG-34`..`RC06-T5-REG-39` use it to show that
   * shape, a self-consistent hash, a correct back-link and even a valid Ed25519
   * signature are each insufficient on their own — a checkpoint is admissible
   * only when the Task-4 verifier produces it from the durable artifact and the
   * retained primary evidence.
   */
  function forgeCheckpoint(fixture, overrides = {}) {
    const sealed = fs.existsSync(fixture.checkpointPath) ? readCheckpoints(fixture) : [];
    const head = sealed.length === 0 ? null : sealed[sealed.length - 1];
    const next = head === null ? 1 : head.sequenceEnd + 1;

    const unsigned = {
      version: 1,
      storeId: fixture.storeId,
      checkpointId: crypto.randomUUID(),
      sequenceStart: next,
      sequenceEnd: next,
      terminalRecordHash: 'f'.repeat(64),
      previousCheckpointHash: head === null ? '0'.repeat(64) : head.checkpointHash,
      createdAt: '2026-09-20T18:00:00.000Z',
      publicKeyFingerprint: fixture.checkpointMaterial.fingerprint,
      ...overrides,
    };
    const signature =
      overrides.signature ??
      crypto
        .sign(
          null,
          computeCheckpointSignaturePreimage(unsigned),
          fixture.checkpointMaterial.privateKey,
        )
        .toString('base64url');

    const signed = { ...unsigned, signature };
    return { ...signed, checkpointHash: computeCheckpointHash(signed) };
  }

  function receiptLines(fixture) {
    if (!fs.existsSync(fixture.receiptPath)) return [];
    const raw = fs.readFileSync(fixture.receiptPath, 'utf8');
    if (raw.length === 0) return [];
    assert.ok(raw.endsWith('\n'), 'a receipt ledger must be LF-terminated');
    return raw
      .slice(0, -1)
      .split('\n')
      .map((line) => parseAndValidateAnchorReceiptLineV1(`${line}\n`));
  }

  /** A transport seam that answers every attempt identically. */
  function staticTransport(statusCode, body) {
    return async () => ({ statusCode, body: Buffer.from(body, 'utf8') });
  }

  /** A transport that records every request and never succeeds. */
  function failingTransport(observation) {
    return async (request) => {
      observation.push(request.headers[ANCHOR_IDEMPOTENCY_HEADER]);
      throw new Error('network unreachable');
    };
  }

  /**
   * The deterministic retry seam.
   *
   * Without it a five-attempt failure spends the real 31-second backoff, so
   * every test that can exhaust the cycle supplies it. The delays it records are
   * the observation: the frozen vector is read rather than timed.
   */
  function instantRetryHooks(extra = {}) {
    const delays = [];
    return {
      hooks: {
        sleep: async (ms) => {
          delays.push(ms);
        },
        ...extra,
      },
      delays,
    };
  }

  /** Mints a receipt for a checkpoint, signed by the given key. */
  function mintReceipt(fixture, checkpoint, privateKey, overrides = {}) {
    return signTestAnchorReceipt(
      {
        version: 1,
        storeId: fixture.storeId,
        receiptId: crypto.randomUUID(),
        checkpointHash: checkpoint.checkpointHash,
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
        anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
        ...overrides,
      },
      privateKey,
    );
  }

  /** A transport that mints a genuine receipt for whichever checkpoint is asked. */
  function acknowledgingTransport(fixture, checkpoints, observation = []) {
    return async (request) => {
      const hash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
      observation.push(hash);
      const checkpoint = checkpoints.find((candidate) => candidate.checkpointHash === hash);
      if (checkpoint === undefined) {
        return { statusCode: 400, body: Buffer.from('unknown checkpoint', 'utf8') };
      }
      return {
        statusCode: 200,
        body: Buffer.from(
          JSON.stringify(mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey)),
          'utf8',
        ),
      };
    };
  }

  /** Starts an HTTPS anchor over the ephemeral PKI, on an ephemeral port. */
  async function startAnchorServer(handler, serverOptions = {}) {
    const server = https.createServer(
      {
        key: fs.readFileSync(pki.serverKeyPath),
        cert: fs.readFileSync(pki.serverCertPath),
        minVersion: 'TLSv1.3',
        ...serverOptions,
      },
      handler,
    );
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    openServers.push(server);
    const { port } = server.address();
    return { server, port, endpoint: `https://localhost:${port}/v1/anchor` };
  }

  /** Reads a complete request body, then answers with `respond`. */
  function collectBodyResponder(respond) {
    return (req, res) => {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        respond(req, res, Buffer.concat(chunks));
      });
    };
  }

  /* ====================================================================== *
   * Frozen constants and the closed receipt schema
   * ====================================================================== */

  describe('frozen Tier-3 constants and the anchor receipt schema', () => {
    test('RC06-T5-REG-01: the frozen constants match the architecture exactly', () => {
      assert.equal(ANCHOR_RECEIPT_FILENAME, 'audit-anchors.jsonl');
      assert.equal(ANCHOR_SPOOL_DIRNAME, 'anchor-spool');
      assert.equal(ANCHOR_SPOOL_FILE_MODE, 0o600);
      assert.equal(ANCHOR_SPOOL_DIRECTORY_MODE, 0o700);
      assert.equal(ANCHOR_SPOOL_FILENAME_REGEX.source, '^[0-9a-f]{64}\\.json$');
      assert.equal(ANCHOR_RECEIPT_SIGNATURE_DOMAIN, 'CESSPACE-ARC-ANCHOR-RECEIPT-V1\0');
      assert.equal(MAX_ANCHOR_RECEIPT_BYTES, 2_048);
      assert.equal(MAX_ANCHOR_ENDPOINT_BYTES, 2_048);
      assert.equal(MAX_ANCHOR_SPOOL_ENTRY_BYTES, 65_536);
      assert.equal(ANCHOR_REQUEST_TIMEOUT_MS, 5_000);
      assert.equal(MAX_ANCHOR_ATTEMPTS, 5);
      assert.deepEqual([...ANCHOR_RETRY_BACKOFF_MS], [1_000, 2_000, 4_000, 8_000, 16_000]);
      assert.equal(MAX_PENDING_ANCHOR_CHECKPOINTS, 100);
      assert.equal(MAX_ANCHOR_SPOOL_BYTES, 1_048_576);
      assert.equal(ANCHOR_IDEMPOTENCY_HEADER, 'Idempotency-Key');
      assert.deepEqual([...ANCHOR_ACKNOWLEDGING_STATUS_CODES], [200, 201]);
    });

    test('RC06-T5-REG-02: the receipt schema is closed — an extra field is rejected', () => {
      assertThrowsWithCode(
        () =>
          validateAnchorReceiptV1({
            version: 1,
            storeId: STORE_EXAMPLE_ID,
            receiptId: 'anchor-receipt-1',
            checkpointHash: 'a'.repeat(64),
            anchorTimestamp: '2026-09-21T00:00:00.000Z',
            anchorKeyFingerprint: 'b'.repeat(64),
            signature: Buffer.alloc(64, 7).toString('base64url'),
            // An `algorithm` field is precisely what a schema that trusts the
            // receipt's own word about how it was signed would accept.
            algorithm: 'Ed25519',
          }),
        'ANCHOR_RECEIPT_INVALID',
      );
    });

    test('RC06-T5-REG-03: the receipt schema is closed — a missing field is rejected', () => {
      assert.equal(ANCHOR_RECEIPT_ALLOWED_KEYS.size, 7);
      for (const key of ANCHOR_RECEIPT_ALLOWED_KEYS) {
        const receipt = {
          version: 1,
          storeId: STORE_EXAMPLE_ID,
          receiptId: 'anchor-receipt-1',
          checkpointHash: 'a'.repeat(64),
          anchorTimestamp: '2026-09-21T00:00:00.000Z',
          anchorKeyFingerprint: 'b'.repeat(64),
          signature: Buffer.alloc(64, 7).toString('base64url'),
        };
        delete receipt[key];
        assertThrowsWithCode(() => validateAnchorReceiptV1(receipt), 'ANCHOR_RECEIPT_INVALID');
      }
    });

    test('RC06-T5-REG-04: field-level rules are exact', () => {
      const base = {
        version: 1,
        storeId: STORE_EXAMPLE_ID,
        receiptId: 'anchor-receipt-1',
        checkpointHash: 'a'.repeat(64),
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
        anchorKeyFingerprint: 'b'.repeat(64),
        signature: Buffer.alloc(64, 7).toString('base64url'),
      };

      assert.equal(validateAnchorReceiptV1(base).receiptId, 'anchor-receipt-1');

      for (const invalid of [
        { ...base, version: 2 },
        { ...base, storeId: 'not-a-uuid' },
        { ...base, checkpointHash: 'A'.repeat(64) },
        { ...base, checkpointHash: 'a'.repeat(63) },
        { ...base, checkpointHash: `${'a'.repeat(63)}z` },
        { ...base, anchorTimestamp: '2026-09-21T00:00:00Z' },
        { ...base, anchorTimestamp: '2026-09-21T00:00:00.000+00:00' },
        { ...base, receiptId: '' },
        { ...base, receiptId: 'bad\nid' },
        { ...base, receiptId: 'x'.repeat(257) },
        { ...base, anchorKeyFingerprint: 'b'.repeat(63) },
        // Padding is not part of the base64url alphabet, so a signature that
        // carries it is not the encoding this schema names.
        { ...base, signature: `${base.signature}==` },
        { ...base, signature: Buffer.alloc(63, 7).toString('base64url') },
        { ...base, signature: Buffer.alloc(65, 7).toString('base64url') },
      ]) {
        assertThrowsWithCode(() => validateAnchorReceiptV1(invalid), 'ANCHOR_RECEIPT_INVALID');
      }

      for (const invalid of [null, [], 'receipt', 7]) {
        assertThrowsWithCode(() => validateAnchorReceiptV1(invalid), 'ANCHOR_RECEIPT_INVALID');
      }
    });

    test('RC06-T5-REG-05: the signature preimage is the domain followed by canonical JSON', () => {
      const preimage = computeAnchorReceiptSignaturePreimage({
        version: 1,
        storeId: STORE_EXAMPLE_ID,
        receiptId: 'anchor-receipt-1',
        checkpointHash: 'a'.repeat(64),
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
        anchorKeyFingerprint: 'b'.repeat(64),
      });

      // The body is canonical JSON: keys sorted, no whitespace. Supplying the
      // fields in a different order must not change a single byte.
      const expectedBody =
        '{"anchorKeyFingerprint":"' +
        'b'.repeat(64) +
        '","anchorTimestamp":"2026-09-21T00:00:00.000Z","checkpointHash":"' +
        'a'.repeat(64) +
        '","receiptId":"anchor-receipt-1","storeId":"' +
        STORE_EXAMPLE_ID +
        '","version":1}';

      assert.equal(preimage.toString('utf8'), `${ANCHOR_RECEIPT_SIGNATURE_DOMAIN}${expectedBody}`);

      // Ed25519 hashes internally. A pre-hash would define a different scheme, so
      // the preimage is the raw concatenation and nothing else.
      const shuffled = computeAnchorReceiptSignaturePreimage({
        anchorKeyFingerprint: 'b'.repeat(64),
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
        checkpointHash: 'a'.repeat(64),
        receiptId: 'anchor-receipt-1',
        storeId: STORE_EXAMPLE_ID,
        version: 1,
      });
      assert.deepEqual(shuffled, preimage);

      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      assert.equal(
        crypto.verify(null, preimage, publicKey, crypto.sign(null, preimage, privateKey)),
        true,
      );
    });

    test('RC06-T5-REG-06: verification requires the key, not the fingerprint field', () => {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      const { publicKey: otherPublic } = crypto.generateKeyPairSync('ed25519');

      const receipt = signTestAnchorReceipt(
        {
          version: 1,
          storeId: STORE_EXAMPLE_ID,
          receiptId: 'anchor-receipt-1',
          checkpointHash: 'a'.repeat(64),
          anchorTimestamp: '2026-09-21T00:00:00.000Z',
          anchorKeyFingerprint: 'b'.repeat(64),
        },
        privateKey,
      );

      assert.equal(verifyAnchorReceiptSignature(receipt, publicKey), true);
      assert.equal(verifyAnchorReceiptSignature(receipt, otherPublic), false);

      // A tampered field invalidates the signature even though every field still
      // validates and the fingerprint field is untouched.
      const tampered = { ...receipt, checkpointHash: 'c'.repeat(64) };
      assert.equal(validateAnchorReceiptV1(tampered).checkpointHash, 'c'.repeat(64));
      assert.equal(verifyAnchorReceiptSignature(tampered, publicKey), false);
    });

    test('RC06-T5-REG-07: the persisted line is canonical, LF-terminated and strictly parsed', () => {
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      const receipt = signTestAnchorReceipt(
        {
          version: 1,
          storeId: STORE_EXAMPLE_ID,
          receiptId: 'anchor-receipt-1',
          checkpointHash: 'a'.repeat(64),
          anchorTimestamp: '2026-09-21T00:00:00.000Z',
          anchorKeyFingerprint: 'b'.repeat(64),
        },
        privateKey,
      );

      const line = serializeAnchorReceiptV1(receipt);
      assert.equal(line.endsWith('\n'), true);
      assert.equal(line.indexOf('\n'), line.length - 1);
      assert.ok(Buffer.byteLength(line, 'utf8') <= MAX_ANCHOR_RECEIPT_BYTES);
      assert.deepEqual(parseAndValidateAnchorReceiptLineV1(line), receipt);

      // A pretty-printed re-encoding of the same object is refused: the persisted
      // form is not "any JSON that parses", it is one exact byte string.
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1(`${JSON.stringify(receipt, null, 2)}\n`),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
      // There is no receipt-tail repair: a torn line is a finding, not a prefix.
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1(line.slice(0, -1)),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1(line.replace('\n', '\r\n')),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1(`${line}${line}`),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1('\n'),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
      assertThrowsWithCode(
        () => parseAndValidateAnchorReceiptLineV1('not json\n'),
        'ANCHOR_RECEIPT_LEDGER_CORRUPT',
      );
    });

    test('RC06-T5-REG-08: the fingerprint is of the SPKI DER, exactly as the metadata records it', () => {
      const material = writeKeyPair(path.join(tempBaseDir, 'fingerprint'), 'anchor');

      assert.equal(
        computeAnchorReceiptPublicKeyFingerprint(material.publicKeyPath),
        material.fingerprint,
      );
      assert.equal(
        computeAnchorReceiptPublicKeyFingerprint(material.publicKeyPath),
        crypto.createHash('sha256').update(material.spkiDer).digest('hex'),
      );

      // The fingerprint is a property of the file's SPKI bytes, so it is stable
      // across processes and is what the store's durable metadata records. A
      // private key is a different file with different bytes, and hashing it
      // yields a different string — which is why the engine cannot be talked
      // into treating one as the other.
      assert.equal(
        computeAnchorReceiptPublicKeyFingerprint(material.publicKeyPath),
        computeAnchorReceiptPublicKeyFingerprint(material.publicKeyPath),
      );
      assert.equal(
        material.spkiDer.equals(material.privateKey.export({ type: 'pkcs8', format: 'der' })),
        false,
      );
    });
  });

  /* ====================================================================== *
   * Endpoint rules (rc06 §14.2)
   * ====================================================================== */

  describe('external anchor endpoint rules', () => {
    test('RC06-NEG-85: a plaintext http endpoint is rejected', async () => {
      const refused = [
        'http://anchor.example.invalid/v1/anchor',
        'http://localhost:8080/anchor',
        'ftp://a.invalid/x',
        'file:///etc/passwd',
        'ws://a.invalid/x',
      ];
      for (const endpoint of refused) {
        assertThrowsWithCode(() => validateAnchorEndpoint(endpoint), 'ANCHOR_ENDPOINT_INVALID');
      }

      // Refused by the validator AND refused at startup: an engine is never
      // constructed holding an endpoint that could be dialled in the clear, so
      // there is no window in which an unreachable validator is the only guard.
      const fixture = await createFixture('neg85', { records: 2 });
      for (const endpoint of refused) {
        await assertRejectsWithCode(
          createTestTier3AnchorEngine(anchorConfig(fixture, { anchorEndpoint: endpoint }), {}),
          'ANCHOR_ENDPOINT_INVALID',
        );
      }
    });

    test('RC06-NEG-86: embedded credentials and fragments are rejected', async () => {
      const refused = [
        'https://user:secret@anchor.example.invalid/v1/anchor',
        'https://user@anchor.example.invalid/v1/anchor',
        'https://anchor.example.invalid/v1/anchor#fragment',
        'https://anchor.example.invalid/v1/anchor#',
      ];
      for (const endpoint of refused) {
        assertThrowsWithCode(() => validateAnchorEndpoint(endpoint), 'ANCHOR_ENDPOINT_INVALID');
      }

      // A percent-encoded `#` is path data, not a fragment, and stays accepted —
      // the rule refuses the marker, not the character's encoding.
      assert.equal(
        validateAnchorEndpoint('https://anchor.example.invalid/v1/an%23chor'),
        'https://anchor.example.invalid/v1/an%23chor',
      );

      const fixture = await createFixture('neg86', { records: 2 });
      for (const endpoint of refused) {
        await assertRejectsWithCode(
          createTestTier3AnchorEngine(anchorConfig(fixture, { anchorEndpoint: endpoint }), {}),
          'ANCHOR_ENDPOINT_INVALID',
        );
      }
    });

    test('RC06-T5-REG-09: endpoint validation is bounded and never echoes the endpoint', () => {
      const accepted = 'https://anchor.example.invalid/v1/anchor';
      assert.equal(validateAnchorEndpoint(accepted), accepted);

      const oversized = `https://anchor.example.invalid/${'x'.repeat(MAX_ANCHOR_ENDPOINT_BYTES)}`;
      assertThrowsWithCode(() => validateAnchorEndpoint(oversized), 'ANCHOR_ENDPOINT_INVALID');
      assertThrowsWithCode(() => validateAnchorEndpoint(''), 'ANCHOR_ENDPOINT_INVALID');
      assertThrowsWithCode(() => validateAnchorEndpoint('https://'), 'ANCHOR_ENDPOINT_INVALID');

      // A rejected endpoint is frequently an operator's mistaken paste, and error
      // text reaches logs: the refusal must not become the disclosure.
      for (const candidate of [
        'https://user:hunter2@anchor.example.invalid/v1/anchor#tok',
        oversized,
        'http://plaintext.example.invalid/anchor',
      ]) {
        try {
          validateAnchorEndpoint(candidate);
          assert.fail('expected the endpoint to be rejected');
        } catch (err) {
          assert.equal(err.message.includes('example.invalid'), false);
          assert.equal(err.message.includes('hunter2'), false);
          assert.equal(err.message.includes(candidate), false);
        }
      }
    });
  });

  /* ====================================================================== *
   * Flow 15 — the end-to-end anchoring flow
   * ====================================================================== */

  describe('Flow 15 — checkpoint to verified receipt over real TLS 1.3', () => {
    test('RC06-T5-REG-10: a real anchor acknowledges a checkpoint end to end', async () => {
      const fixture = await createFixture('flow15', { records: 3 });
      const [checkpoint] = readCheckpoints(fixture);

      const requests = [];
      const anchor = await startAnchorServer(
        collectBodyResponder((req, res, body) => {
          requests.push({ headers: req.headers, body });
          const receipt = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
            receiptId: 'anchor-receipt-flow15',
          });
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(receipt));
        }),
      );

      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture, { anchorEndpoint: anchor.endpoint }),
        { ca: caPem },
      );

      // Reconciliation performs no network I/O: the spool entry is durable before
      // anything is transmitted, which is the ordering §14.4 mandates.
      assert.equal(requests.length, 0, 'reconciliation must not transmit');
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);
      assert.equal(engine.getStatus().anchorState, 'DEGRADED');
      assert.equal(engine.getStatus().unanchoredCheckpoints, 1);
      assert.equal(receiptLines(fixture).length, 0);

      const result = await engine.anchorCheckpoint(checkpoint);
      assert.equal(result.outcome, 'ACKNOWLEDGED');
      assert.equal(result.attempts, 1);
      assert.equal(result.idempotent, false);
      assert.equal(result.receipt.checkpointHash, checkpoint.checkpointHash);
      assert.equal(result.receipt.anchorKeyFingerprint, fixture.anchorMaterial.fingerprint);
      assert.deepEqual(result.status, engine.getStatus());
      assert.equal(result.status.anchorState, 'HEALTHY');
      assert.equal(result.status.unanchoredCheckpoints, 0);
      assert.equal(result.status.acknowledgedCheckpoints, 1);

      // The wire request is the frozen envelope: POST, JSON, the checkpoint hash
      // as the idempotency key, and the canonical checkpoint as the body.
      assert.equal(requests.length, 1);
      const sent = requests[0];
      assert.equal(
        sent.headers[ANCHOR_IDEMPOTENCY_HEADER.toLowerCase()],
        checkpoint.checkpointHash,
      );
      assert.equal(sent.headers['content-type'], 'application/json');
      assert.equal(Number(sent.headers['content-length']), sent.body.length);
      assert.equal(
        sent.body.toString('utf8'),
        // The artifact line minus its record separator: the durable form of a
        // checkpoint is its canonical JSON, and the LF belongs to the stream.
        readCheckpointLines(fixture)[0].slice(0, -1),
        'the body must be the checkpoint exactly as it was durably written',
      );

      // The spool entry is gone and the receipt is durable.
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), false);
      const lines = receiptLines(fixture);
      assert.equal(lines.length, 1);
      assert.equal(lines[0].receiptId, 'anchor-receipt-flow15');
      assert.equal(lines[0].storeId, fixture.storeId);
      assert.equal(verifyAnchorReceiptSignature(lines[0], fixture.anchorMaterial.publicKey), true);

      // The acknowledgement survives a restart, and the restarted engine reaches
      // the same conclusion from the durable artifacts alone.
      await engine.close();
      const restarted = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      const restartedStatus = restarted.getStatus();
      assert.equal(restartedStatus.anchorState, 'HEALTHY');
      assert.equal(restartedStatus.unanchoredCheckpoints, 0);
      assert.equal(restartedStatus.acknowledgedCheckpoints, 1);
      await restarted.close();
    });

    test('RC06-T5-REG-11: TLS 1.3 is the floor, and certificate and hostname are verified', async () => {
      const respondAck = collectBodyResponder((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      });

      // A server that cannot negotiate 1.3 must fail the attempt rather than be
      // silently downgraded.
      const legacy = await startAnchorServer(respondAck, {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.2',
      });

      const downgradeFixture = await createFixture('flow15-downgrade', { records: 2 });
      const [downgradeCheckpoint] = readCheckpoints(downgradeFixture);
      const downgrade = instantRetryHooks({ ca: caPem });
      const downgradeEngine = await createTestTier3AnchorEngine(
        anchorConfig(downgradeFixture, { anchorEndpoint: legacy.endpoint }),
        downgrade.hooks,
      );
      const downgradeResult = await downgradeEngine.anchorCheckpoint(downgradeCheckpoint);
      assert.equal(downgradeResult.outcome, 'PENDING');
      assert.equal(downgradeResult.status.anchorState, 'DEGRADED');
      assert.equal(downgradeResult.status.unanchoredCheckpoints, 1);
      assert.equal(downgradeResult.status.degradedReason, 'ANCHOR_TRANSPORT_FAILED');
      assert.deepEqual(downgrade.delays, [1_000, 2_000, 4_000, 8_000, 16_000]);
      await downgradeEngine.close();

      // A leaf issued by a CA the operator did not pin must fail: the trust root
      // is the operator's, not the peer's.
      const untrusted = await startAnchorServer(respondAck, {
        key: fs.readFileSync(pki.unknownCaClientKeyPath),
        cert: fs.readFileSync(pki.unknownCaClientCertPath),
      });

      const untrustedFixture = await createFixture('flow15-untrusted', { records: 2 });
      const [untrustedCheckpoint] = readCheckpoints(untrustedFixture);
      const untrustedEngine = await createTestTier3AnchorEngine(
        anchorConfig(untrustedFixture, { anchorEndpoint: untrusted.endpoint }),
        instantRetryHooks({ ca: caPem }).hooks,
      );
      const untrustedResult = await untrustedEngine.anchorCheckpoint(untrustedCheckpoint);
      assert.equal(untrustedResult.outcome, 'PENDING');
      assert.equal(untrustedResult.status.anchorState, 'DEGRADED');
      assert.equal(receiptLines(untrustedFixture).length, 0);
      await untrustedEngine.close();

      // A leaf that chains to the pinned CA but does not name the host being
      // contacted must fail too: hostname verification is not optional.
      const sanMismatch = await startAnchorServer(respondAck, {
        key: fs.readFileSync(pki.sanMismatchKeyPath),
        cert: fs.readFileSync(pki.sanMismatchCertPath),
      });

      const sanFixture = await createFixture('flow15-san', { records: 2 });
      const [sanCheckpoint] = readCheckpoints(sanFixture);
      const sanEngine = await createTestTier3AnchorEngine(
        anchorConfig(sanFixture, { anchorEndpoint: sanMismatch.endpoint }),
        instantRetryHooks({ ca: caPem }).hooks,
      );
      const sanResult = await sanEngine.anchorCheckpoint(sanCheckpoint);
      assert.equal(sanResult.outcome, 'PENDING');
      assert.equal(sanResult.status.anchorState, 'DEGRADED');
      assert.equal(receiptLines(sanFixture).length, 0);

      // The transport failure names no peer: a Node TLS error routinely embeds
      // the hostname, so it is not carried through as a cause.
      assertNoDisclosure(JSON.stringify(sanEngine.getStatus()), sanMismatch.endpoint);
      await sanEngine.close();
    });
  });

  /* ====================================================================== *
   * Flow 16 — crash recovery
   * ====================================================================== */

  describe('Flow 16 — crash recovery', () => {
    test('RC06-T5-REG-12: a crash between the durable receipt and the spool unlink reconciles cleanly', async () => {
      const fixture = await createFixture('flow16', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      // Phase 1: the checkpoint is spooled but the anchor is unreachable, so the
      // store is left with outstanding work and a retained spool entry.
      const submitted = [];
      const stalled = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({ transport: failingTransport(submitted) }).hooks,
      );
      const stalledResult = await stalled.anchorCheckpoint(checkpoint);
      assert.equal(stalledResult.outcome, 'PENDING');
      assert.deepEqual(submitted, Array(MAX_ANCHOR_ATTEMPTS).fill(checkpoint.checkpointHash));
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);
      await stalled.close();

      // Phase 2: the anchor acknowledged the checkpoint and ARC crashed between
      // making the receipt durable and removing the spool entry — State D. The
      // receipt is written directly, exactly as the crashed process would have.
      const receipt = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
        receiptId: 'anchor-receipt-flow16',
      });
      fs.writeFileSync(fixture.receiptPath, serializeAnchorReceiptV1(receipt), { mode: 0o600 });
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);

      // Phase 3: a restarted engine reconciles in favour of the receipt and
      // removes the stale entry, without manufacturing a second acknowledgement.
      const restarted = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      const status = restarted.getStatus();
      assert.equal(status.anchorState, 'HEALTHY');
      assert.equal(status.unanchoredCheckpoints, 0);
      assert.equal(status.acknowledgedCheckpoints, 1);
      assert.equal(status.spoolEntries, 0);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), false);

      const lines = receiptLines(fixture);
      assert.equal(lines.length, 1, 'reconciliation must not append a second receipt');
      assert.equal(lines[0].receiptId, 'anchor-receipt-flow16');

      // The cleanup is durable rather than merely in-memory: a further restart
      // sees the same store.
      await restarted.close();
      const third = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      assert.equal(third.getStatus().anchorState, 'HEALTHY');
      assert.equal(receiptLines(fixture).length, 1);
      await third.close();
    });
  });

  /* ====================================================================== *
   * rc06 §14.7 — the retry cycle, the timeout and backpressure
   * ====================================================================== */

  describe('retry cycle, per-attempt budget and backpressure', () => {
    test('RC06-NEG-87: an attempt that exceeds the 5,000 ms budget is aborted and the checkpoint retained', async () => {
      const fixture = await createFixture('neg87', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      // The seam observes the exact requested budget and fires it deterministically,
      // so the control proves the deadline instead of spending five seconds per
      // attempt waiting for it.
      const observedBudgets = [];
      let fireDeadline = null;
      const { hooks, delays } = instantRetryHooks({
        setAttemptTimer: (callback, ms) => {
          observedBudgets.push(ms);
          fireDeadline = callback;
          return callback;
        },
        clearAttemptTimer: () => {},
        transport: async (request, signal) =>
          new Promise((resolve, reject) => {
            signal.addEventListener('abort', () => {
              reject(new Error('aborted'));
            });
            // The transport never answers; the budget is what ends the attempt.
            setImmediate(() => {
              fireDeadline?.();
            });
          }),
      });

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), hooks);
      const result = await engine.anchorCheckpoint(checkpoint);

      assert.deepEqual(
        observedBudgets,
        [5_000, 5_000, 5_000, 5_000, 5_000],
        'the 5,000 ms budget covers the whole attempt, on every attempt',
      );
      assert.deepEqual(delays, [1_000, 2_000, 4_000, 8_000, 16_000]);
      assert.equal(result.attempts, MAX_ANCHOR_ATTEMPTS);
      assert.equal(result.outcome, 'PENDING');
      assert.equal(result.receipt, null);
      assert.equal(result.status.anchorState, 'DEGRADED');
      assert.equal(result.status.degradedReason, 'ANCHOR_REQUEST_TIMEOUT');
      assert.equal(result.status.unanchoredCheckpoints, 1);

      // The checkpoint is retained in the crash-recoverable spool, so the next
      // cycle re-submits it under the same idempotency key.
      const spoolPath = spoolEntryPath(fixture, checkpoint.checkpointHash);
      assert.equal(fs.existsSync(spoolPath), true);
      assert.equal(fs.statSync(fixture.spoolDir).mode & 0o777, ANCHOR_SPOOL_DIRECTORY_MODE);
      assert.equal(fs.statSync(spoolPath).mode & 0o777, ANCHOR_SPOOL_FILE_MODE);
      assert.equal(
        JSON.parse(fs.readFileSync(spoolPath, 'utf8')).checkpointHash,
        checkpoint.checkpointHash,
      );
      assert.equal(receiptLines(fixture).length, 0);

      await engine.close();
    });

    test('RC06-NEG-88: a 5xx response is retried on the frozen vector and the checkpoint is retained', async () => {
      const fixture = await createFixture('neg88', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      const attempts = [];
      const { hooks, delays } = instantRetryHooks({
        transport: async (request) => {
          attempts.push(request.headers[ANCHOR_IDEMPOTENCY_HEADER]);
          return { statusCode: 503, body: Buffer.from('service unavailable', 'utf8') };
        },
      });

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), hooks);
      const result = await engine.anchorCheckpoint(checkpoint);

      assert.equal(attempts.length, MAX_ANCHOR_ATTEMPTS);
      assert.deepEqual(delays, [1_000, 2_000, 4_000, 8_000, 16_000]);
      assert.equal(result.outcome, 'PENDING');
      assert.equal(result.status.anchorState, 'DEGRADED');
      assert.equal(result.status.unanchoredCheckpoints, 1);
      assert.equal(fs.existsSync(fixture.receiptPath), false, 'no receipt may be written');
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);

      // Every attempt reuses the same idempotency key, so a repeat submission the
      // anchor did receive is answered with the identical logical receipt.
      assert.equal(new Set(attempts).size, 1);

      await engine.close();
    });

    test('RC06-T5-REG-13: a 4xx is terminal and a redirect is refused rather than followed', async () => {
      const rejectedFixture = await createFixture('terminal-4xx', { records: 2 });
      const [rejectedCheckpoint] = readCheckpoints(rejectedFixture);
      const rejected = instantRetryHooks({ transport: staticTransport(400, 'bad request') });
      const rejectedEngine = await createTestTier3AnchorEngine(
        anchorConfig(rejectedFixture),
        rejected.hooks,
      );
      const rejectedResult = await rejectedEngine.anchorCheckpoint(rejectedCheckpoint);
      assert.equal(rejectedResult.attempts, 1, 'a definitive answer is not retried');
      assert.equal(rejectedResult.status.degradedReason, 'ANCHOR_REQUEST_REJECTED');
      assert.deepEqual(rejected.delays, [], 'a terminal classification ends the cycle immediately');
      assert.equal(fs.existsSync(rejectedFixture.receiptPath), false);
      await rejectedEngine.close();

      const redirectFixture = await createFixture('terminal-3xx', { records: 2 });
      const [redirectCheckpoint] = readCheckpoints(redirectFixture);
      const redirect = instantRetryHooks({ transport: staticTransport(302, '') });
      const redirectEngine = await createTestTier3AnchorEngine(
        anchorConfig(redirectFixture),
        redirect.hooks,
      );
      const redirectResult = await redirectEngine.anchorCheckpoint(redirectCheckpoint);
      assert.equal(redirectResult.attempts, 1, 'a redirect is never followed');
      assert.equal(redirectResult.status.degradedReason, 'ANCHOR_REDIRECT_REFUSED');
      assert.equal(redirectResult.status.anchorState, 'DEGRADED');
      assert.deepEqual(redirect.delays, []);
      await redirectEngine.close();

      // An unlisted 2xx is not an acknowledgement and not a definitive answer, so
      // it is retried and the checkpoint stays spooled.
      const unexpectedFixture = await createFixture('terminal-2xx', { records: 2 });
      const [unexpectedCheckpoint] = readCheckpoints(unexpectedFixture);
      const unexpected = instantRetryHooks({ transport: staticTransport(204, '') });
      const unexpectedEngine = await createTestTier3AnchorEngine(
        anchorConfig(unexpectedFixture),
        unexpected.hooks,
      );
      const unexpectedResult = await unexpectedEngine.anchorCheckpoint(unexpectedCheckpoint);
      assert.equal(unexpectedResult.attempts, MAX_ANCHOR_ATTEMPTS);
      assert.equal(unexpectedResult.outcome, 'PENDING');
      assert.deepEqual(unexpected.delays, [1_000, 2_000, 4_000, 8_000, 16_000]);
      await unexpectedEngine.close();
    });

    test('RC06-NEG-97: more than 100 pending checkpoints withholds privileged operations', async () => {
      const fixture = await createFixture('neg97', {
        records: OVERFLOW_RECORDS,
        rotateAt: OVERFLOW_ROTATE_AT,
      });
      assert.equal(readCheckpoints(fixture).length, OVERFLOW_CHECKPOINTS);

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });

      const status = engine.getStatus();
      assert.equal(status.anchorState, 'FULL');
      assert.equal(status.anchorMode, 'ENABLED');
      assert.equal(status.maxPendingCheckpoints, MAX_PENDING_ANCHOR_CHECKPOINTS);
      assert.equal(status.unanchoredCheckpoints, MAX_PENDING_ANCHOR_CHECKPOINTS);

      // Privileged operations are withheld until receipts arrive.
      assertThrowsWithCode(() => engine.assertPrivilegedOperationsAllowed(), 'ANCHOR_SPOOL_FULL');

      // Nothing was deleted to manufacture capacity: the ceiling is exactly the
      // number of entries on disk, and every one is a canonical entry name.
      const spoolEntries = fs.readdirSync(fixture.spoolDir);
      assert.equal(spoolEntries.length, MAX_PENDING_ANCHOR_CHECKPOINTS);
      for (const entry of spoolEntries) {
        assert.equal(ANCHOR_SPOOL_FILENAME_REGEX.test(entry), true, `${entry} is not canonical`);
      }
      await engine.close();
    });

    test('RC06-NEG-98: a spool payload over 1 MiB withholds privileged operations', async () => {
      const count = 50;
      const fixture = await createFixture('neg98', { records: count, checkpointCount: count });

      // Phase 1: the engine durably spools every pending checkpoint itself, so the
      // directory starts out entirely legitimate and under both ceilings.
      const first = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      assert.equal(first.getStatus().unanchoredCheckpoints, count);
      assert.equal(first.getStatus().spoolEntries, count);
      assert.ok(first.getStatus().spoolBytes < MAX_ANCHOR_SPOOL_BYTES);
      await first.close();

      // Phase 2: the ceiling is a property of the DIRECTORY, measured from disk,
      // not of ARC's own bookkeeping about what it wrote. Growing the entries in
      // place — which the engine cannot prevent, and must not paper over — puts
      // the store over the byte ceiling while leaving the entry count under its
      // own, so only the byte ceiling can be what trips.
      const perEntry = Math.ceil(MAX_ANCHOR_SPOOL_BYTES / count) + 1_024;
      for (const entry of fs.readdirSync(fixture.spoolDir)) {
        const entryPath = path.join(fixture.spoolDir, entry);
        fs.truncateSync(entryPath, perEntry);
        fs.chmodSync(entryPath, ANCHOR_SPOOL_FILE_MODE);
      }

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      const status = engine.getStatus();

      assert.equal(status.spoolEntries, count);
      assert.ok(
        status.spoolEntries < MAX_PENDING_ANCHOR_CHECKPOINTS,
        'the entry-count ceiling must not be what tripped',
      );
      assert.ok(status.spoolBytes >= MAX_ANCHOR_SPOOL_BYTES);
      assert.equal(status.maxSpoolBytes, MAX_ANCHOR_SPOOL_BYTES);
      assert.equal(status.anchorState, 'FULL');
      assertThrowsWithCode(() => engine.assertPrivilegedOperationsAllowed(), 'ANCHOR_SPOOL_FULL');

      // The enlarged entries are never served: dispatch proves each entry's bytes
      // are the canonical checkpoint before transmitting anything.
      await assertRejectsWithCode(engine.resumePendingAnchors(), 'ANCHOR_SPOOL_ENTRY_INVALID');
      assert.equal(fs.existsSync(fixture.receiptPath), false);
      await engine.close();
    });
  });

  /* ====================================================================== *
   * rc06 §14.5 — acknowledgement is a verified receipt
   * ====================================================================== */

  describe('acknowledgement requires a verified receipt', () => {
    test('RC06-NEG-89: HTTP 200 without a cryptographic receipt is not acknowledgement', async () => {
      const cases = [
        { name: 'empty body', body: '' },
        { name: 'not json', body: 'acknowledged' },
        { name: 'empty object', body: '{}' },
        { name: 'json null', body: 'null' },
        { name: 'wrong version', body: JSON.stringify({ version: 2 }) },
      ];

      for (const [index, scenario] of cases.entries()) {
        const fixture = await createFixture(`neg89-${index}`, { records: 2 });
        const [checkpoint] = readCheckpoints(fixture);

        const engine = await createTestTier3AnchorEngine(
          anchorConfig(fixture),
          instantRetryHooks({ transport: staticTransport(200, scenario.body) }).hooks,
        );
        const result = await engine.anchorCheckpoint(checkpoint);

        assert.equal(result.outcome, 'PENDING', `${scenario.name} must not acknowledge`);
        assert.equal(result.receipt, null);
        assert.equal(result.attempts, 1);
        assert.equal(result.status.degradedReason, 'ANCHOR_RECEIPT_INVALID');
        assert.equal(result.status.anchorState, 'DEGRADED');
        assert.equal(fs.existsSync(fixture.receiptPath), false, `${scenario.name} wrote a receipt`);
        assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);

        await engine.close();
      }
    });

    test('RC06-NEG-90: a receipt signed by an untrusted key is rejected', async () => {
      const fixture = await createFixture('neg90', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      // The signature is a perfectly valid Ed25519 signature — under a key that is
      // not the pinned anchor key, and with the fingerprint field forged to look
      // like the pinned one. The refusal must come from the pinning rather than
      // from the signature being malformed.
      const impostor = crypto.generateKeyPairSync('ed25519');
      const forged = signTestAnchorReceipt(
        {
          version: 1,
          storeId: fixture.storeId,
          receiptId: 'impostor-receipt',
          checkpointHash: checkpoint.checkpointHash,
          anchorTimestamp: '2026-09-21T00:00:00.000Z',
          anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
        },
        impostor.privateKey,
      );
      assert.equal(verifyAnchorReceiptSignature(forged, impostor.publicKey), true);
      assert.equal(verifyAnchorReceiptSignature(forged, fixture.anchorMaterial.publicKey), false);

      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({ transport: staticTransport(200, JSON.stringify(forged)) }).hooks,
      );
      const result = await engine.anchorCheckpoint(checkpoint);

      assert.equal(result.outcome, 'PENDING');
      assert.equal(result.receipt, null);
      assert.equal(result.status.degradedReason, 'ANCHOR_RECEIPT_SIGNATURE_INVALID');
      assert.equal(
        fs.existsSync(fixture.receiptPath),
        false,
        'the impostor receipt is not persisted',
      );
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);
      await engine.close();
    });

    test('RC06-NEG-91: a receipt bound to another checkpoint, store or key is rejected', async () => {
      const scenarios = [
        {
          name: 'another checkpoint',
          code: 'ANCHOR_RECEIPT_BINDING_INVALID',
          overrides: () => ({ checkpointHash: 'f'.repeat(64) }),
        },
        {
          name: 'another store',
          code: 'ANCHOR_RECEIPT_BINDING_INVALID',
          overrides: () => ({ storeId: crypto.randomUUID() }),
        },
        {
          name: 'another key fingerprint',
          code: 'ANCHOR_RECEIPT_KEY_MISMATCH',
          overrides: () => ({ anchorKeyFingerprint: 'e'.repeat(64) }),
        },
      ];

      for (const [index, scenario] of scenarios.entries()) {
        const fixture = await createFixture(`neg91-${index}`, { records: 2 });
        const [checkpoint] = readCheckpoints(fixture);
        const receipt = mintReceipt(
          fixture,
          checkpoint,
          fixture.anchorMaterial.privateKey,
          scenario.overrides(),
        );

        const engine = await createTestTier3AnchorEngine(
          anchorConfig(fixture),
          instantRetryHooks({ transport: staticTransport(200, JSON.stringify(receipt)) }).hooks,
        );
        const result = await engine.anchorCheckpoint(checkpoint);

        assert.equal(result.outcome, 'PENDING', `${scenario.name} must not acknowledge`);
        assert.equal(result.status.degradedReason, scenario.code, scenario.name);
        assert.equal(fs.existsSync(fixture.receiptPath), false);
        await engine.close();
      }
    });

    test('RC06-NEG-92: a conflicting receipt for an acknowledged checkpoint is rejected', async () => {
      const fixture = await createFixture('neg92', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      let served = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
        receiptId: 'receipt-original',
        anchorTimestamp: '2026-09-21T00:00:00.000Z',
      });
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: async () => ({ statusCode: 200, body: Buffer.from(JSON.stringify(served)) }),
        }).hooks,
      );

      const acknowledged = await engine.anchorCheckpoint(checkpoint);
      assert.equal(acknowledged.outcome, 'ACKNOWLEDGED');
      assert.equal(acknowledged.status.anchorState, 'HEALTHY');
      assert.equal(receiptLines(fixture).length, 1);

      // The anchor now answers the SAME idempotency key with a different logical
      // receipt — a conflicting identity for an already acknowledged checkpoint.
      served = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
        receiptId: 'receipt-conflicting',
        anchorTimestamp: '2026-09-21T00:00:01.000Z',
      });

      const conflicted = await engine.anchorCheckpoint(checkpoint);
      assert.equal(conflicted.outcome, 'PENDING');
      assert.equal(conflicted.receipt, null);
      assert.equal(conflicted.status.anchorState, 'DEGRADED');
      assert.equal(conflicted.status.degradedReason, 'ANCHOR_RECEIPT_CONFLICT');

      // Neither receipt is deleted and no second line is appended: the ledger is
      // append-only, and "latest receipt wins" is exactly the resolution §14.5
      // forbids. The receipt already on record is still the only one.
      const lines = receiptLines(fixture);
      assert.equal(lines.length, 1, 'a conflicting receipt is never persisted');
      assert.equal(lines[0].receiptId, 'receipt-original');

      // The transient spool entry the re-attestation created is gone: the receipt
      // on record governs, so the checkpoint is not left looking pending.
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), false);
      assert.equal(conflicted.status.unanchoredCheckpoints, 0);
      await engine.close();
    });

    test('RC06-NEG-93: a repeat submission with the same receipt is an idempotent duplicate', async () => {
      const fixture = await createFixture('neg93', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      const receipt = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
        receiptId: 'receipt-idempotent',
      });
      let submissions = 0;
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: async (request) => {
            submissions += 1;
            assert.equal(request.headers[ANCHOR_IDEMPOTENCY_HEADER], checkpoint.checkpointHash);
            return { statusCode: 200, body: Buffer.from(JSON.stringify(receipt)) };
          },
        }).hooks,
      );

      const first = await engine.anchorCheckpoint(checkpoint);
      assert.equal(first.outcome, 'ACKNOWLEDGED');
      assert.equal(first.idempotent, false);
      const afterFirst = fs.readFileSync(fixture.receiptPath, 'utf8');

      const repeat = await engine.anchorCheckpoint(checkpoint);
      assert.equal(submissions, 2, 'the repeat really is re-submitted under the same key');
      assert.equal(repeat.outcome, 'ACKNOWLEDGED');
      assert.equal(repeat.idempotent, true);
      assert.equal(repeat.receipt.receiptId, 'receipt-idempotent');
      assert.equal(repeat.status.anchorState, 'HEALTHY');
      assert.equal(repeat.status.acknowledgedCheckpoints, 1);

      assert.equal(
        fs.readFileSync(fixture.receiptPath, 'utf8'),
        afterFirst,
        'an idempotent duplicate must not append a second acknowledgement',
      );
      assert.equal(receiptLines(fixture).length, 1);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), false);
      await engine.close();
    });
  });

  /* ====================================================================== *
   * rc06 §14.6 — reconciliation states, including both integrity failures
   * ====================================================================== */

  describe('reconciliation states', () => {
    test('RC06-NEG-95: a checkpoint with no receipt and no spool entry is reconstructed before serving', async () => {
      const fixture = await createFixture('neg95', { records: 4 });
      const [checkpoint] = readCheckpoints(fixture);
      assert.equal(
        fs.existsSync(fixture.spoolDir),
        false,
        'the fixture starts with no spool at all',
      );

      let transmissions = 0;
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), {
        ca: caPem,
        transport: async () => {
          transmissions += 1;
          throw new Error('must not be reached during reconciliation');
        },
      });

      // State C is resolved during initialization, before any privileged
      // operation can be served and before any byte is transmitted.
      assert.equal(transmissions, 0);
      assert.equal(fs.existsSync(fixture.spoolDir), true);
      assert.equal(fs.statSync(fixture.spoolDir).mode & 0o777, ANCHOR_SPOOL_DIRECTORY_MODE);
      assert.equal(fs.statSync(fixture.spoolDir).uid, getProcessUid());

      const spoolPath = spoolEntryPath(fixture, checkpoint.checkpointHash);
      assert.equal(fs.existsSync(spoolPath), true);
      assert.equal(fs.statSync(spoolPath).mode & 0o777, ANCHOR_SPOOL_FILE_MODE);
      assert.equal(fs.statSync(spoolPath).nlink, 1);

      // The reconstruction is the canonical checkpoint, so the entry is
      // re-transmittable as the same bytes the verified history produced.
      const reconstructed = JSON.parse(fs.readFileSync(spoolPath, 'utf8'));
      assert.deepEqual(reconstructed, JSON.parse(JSON.stringify(checkpoint)));
      assert.equal(computeCheckpointHash(reconstructed), checkpoint.checkpointHash);

      const status = engine.getStatus();
      assert.equal(status.anchorState, 'DEGRADED');
      assert.equal(status.unanchoredCheckpoints, 1);
      assert.equal(status.spoolEntries, 1);
      assert.equal(status.verifiedCheckpoints, 1);
      assert.equal(receiptLines(fixture).length, 0);
      await engine.close();
    });

    test('RC06-NEG-96: a durable receipt with a surviving stale spool entry reconciles without a duplicate acknowledgement', async () => {
      // Two checkpoints, so reconciliation has to tell two adjacent crash states
      // apart in a single pass: the head checkpoint crashed after its receipt was
      // durable (State D — receipt plus a spool entry that should not be there),
      // and the next one never got a receipt at all (State B — a spool entry that
      // should be there). Treating them alike either way is wrong: cleaning up the
      // first as if it were pending would re-transmit an acknowledged checkpoint,
      // and keeping the second as if it were acknowledged would lose it.
      const fixture = await createFixture('neg96', { records: 4, rotateAt: [2, 4] });
      const checkpoints = readCheckpoints(fixture);
      assert.equal(checkpoints.length, 2);

      // Phase 1: the anchor is unreachable, so the dispatch cycle stops at the head
      // and both entries survive.
      const stalled = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({ transport: failingTransport([]) }).hooks,
      );
      await stalled.anchorCheckpoint(checkpoints[1]);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoints[0].checkpointHash)), true);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoints[1].checkpointHash)), true);
      assert.equal(receiptLines(fixture).length, 0);
      await stalled.close();

      // Phase 2: the anchor acknowledged the HEAD checkpoint and the process died
      // before the unlink. The receipt is written directly, exactly as the crashed
      // process would have left it.
      const receipt = mintReceipt(fixture, checkpoints[0], fixture.anchorMaterial.privateKey, {
        receiptId: 'anchor-receipt-neg96',
      });
      fs.writeFileSync(fixture.receiptPath, serializeAnchorReceiptV1(receipt), { mode: 0o600 });

      // Phase 3: startup classes each checkpoint from durable state alone, and
      // performs no network I/O while doing it.
      const restarted = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: async () => {
            throw new Error('reconciliation must not transmit');
          },
        }).hooks,
      );

      const status = restarted.getStatus();
      assert.equal(status.verifiedCheckpoints, 2);
      assert.equal(status.acknowledgedCheckpoints, 1);
      assert.equal(status.unanchoredCheckpoints, 1);
      assert.equal(status.spoolEntries, 1);
      assert.equal(status.anchorState, 'DEGRADED');

      // The acknowledged checkpoint's entry is gone and the pending one's is kept,
      // and the ledger still holds exactly the one receipt that was durable.
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoints[0].checkpointHash)), false);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoints[1].checkpointHash)), true);
      const lines = receiptLines(fixture);
      assert.equal(lines.length, 1, 'reconciliation must not append a second receipt');
      assert.equal(lines[0].receiptId, 'anchor-receipt-neg96');
      await restarted.close();

      // The classification is a property of the artifacts, not of one process run.
      const third = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      assert.equal(third.getStatus().acknowledgedCheckpoints, 1);
      assert.equal(third.getStatus().unanchoredCheckpoints, 1);
      assert.equal(third.getStatus().spoolEntries, 1);
      assert.equal(receiptLines(fixture).length, 1);
      await third.close();
    });

    test('RC06-NEG-94: a spool entry with no matching checkpoint fails startup closed', async () => {
      const fixture = await createFixture('neg94', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      // A well-formed entry in every respect but one: it names a checkpoint the
      // verified history does not contain.
      fs.mkdirSync(fixture.spoolDir, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      fs.chmodSync(fixture.spoolDir, ANCHOR_SPOOL_DIRECTORY_MODE);
      const orphanHash = 'a'.repeat(64);
      assert.notEqual(orphanHash, checkpoint.checkpointHash);
      const orphanPath = path.join(fixture.spoolDir, `${orphanHash}.json`);
      fs.writeFileSync(orphanPath, JSON.stringify({ checkpointHash: orphanHash }), {
        mode: ANCHOR_SPOOL_FILE_MODE,
      });

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem }),
        'ANCHOR_ORPHAN_SPOOL_ENTRY',
      );

      // Fail closed means fail closed: the orphan is not deleted, not ignored and
      // not reinterpreted, and no receipt is written.
      assert.equal(fs.existsSync(orphanPath), true);
      assert.equal(fs.existsSync(fixture.receiptPath), false);
    });

    test('RC06-T5-REG-14: a receipt with no matching checkpoint fails startup closed', async () => {
      const fixture = await createFixture('stateF', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      // A receipt that verifies perfectly and binds to this store, for a
      // checkpoint the primary evidence never produced.
      const orphan = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey, {
        checkpointHash: 'b'.repeat(64),
      });
      fs.writeFileSync(fixture.receiptPath, serializeAnchorReceiptV1(orphan), {
        mode: 0o600,
      });

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem }),
        'ANCHOR_ORPHAN_RECEIPT',
      );
      // Not deleted, not truncated, not repaired.
      assert.equal(receiptLines(fixture).length, 1);
      assert.equal(receiptLines(fixture)[0].checkpointHash, 'b'.repeat(64));
    });

    test('RC06-T5-REG-15: a duplicate receipt line fails startup closed rather than being ignored', async () => {
      const fixture = await createFixture('stateF-dup', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      const receipt = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey);
      fs.writeFileSync(
        fixture.receiptPath,
        serializeAnchorReceiptV1(receipt) + serializeAnchorReceiptV1(receipt),
        { mode: 0o600 },
      );

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem }),
        'ANCHOR_ORPHAN_RECEIPT',
      );
      assert.equal(receiptLines(fixture).length, 2);
    });

    test('RC06-T5-REG-16: an out-of-order receipt line fails startup closed', async () => {
      const fixture = await createFixture('stateF-order', { records: 2, checkpointCount: 2 });
      const checkpoints = readCheckpoints(fixture);
      assert.equal(checkpoints.length, 2);

      // The ledger is written with the LATER checkpoint first. Receipts are only
      // ever appended in checkpoint order, so this is not a ledger ARC could have
      // produced — and accepting it would break the monotonic subsequence the
      // next startup depends on.
      const later = mintReceipt(fixture, checkpoints[1], fixture.anchorMaterial.privateKey);
      const earlier = mintReceipt(fixture, checkpoints[0], fixture.anchorMaterial.privateKey);
      fs.writeFileSync(
        fixture.receiptPath,
        serializeAnchorReceiptV1(later) + serializeAnchorReceiptV1(earlier),
        { mode: 0o600 },
      );

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem }),
        'ANCHOR_ORPHAN_RECEIPT',
      );
    });

    test('RC06-T5-REG-17: DISABLED mode claims nothing and refuses anchor artifacts', async () => {
      const fixture = await createFixture('disabled', {
        records: 2,
        anchorMode: 'DISABLED',
      });

      // A DISABLED store must not be handed anchor configuration: the store says
      // anchoring is off, and a configuration that contradicts its own durable
      // record is refused rather than silently honoured.
      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), {}),
        'ANCHOR_CONFIG_INVALID',
      );

      const engine = await openTier3AnchorEngine({ directory: fixture.auditDir });
      const status = engine.getStatus();
      assert.equal(status.anchorMode, 'DISABLED');
      assert.equal(status.anchorState, 'DISABLED');
      assert.equal(status.anchorReceiptPublicKeyFingerprint, null);
      assert.equal(status.storeId, null);
      assert.equal(status.unanchoredCheckpoints, 0);
      assert.equal(status.spoolEntries, 0);
      assert.equal(status.acknowledgedCheckpoints, 0);
      assert.equal(status.degradedReason, null);
      assert.equal(fs.existsSync(fixture.spoolDir), false, 'DISABLED mode creates no spool');

      // The gate is a no-op in DISABLED mode, and the engine refuses to be driven.
      engine.assertPrivilegedOperationsAllowed();
      await assertRejectsWithCode(
        engine.anchorCheckpoint(readCheckpoints(fixture)[0]),
        'ANCHOR_MODE_DISABLED',
      );
      await assertRejectsWithCode(engine.resumePendingAnchors(), 'ANCHOR_MODE_DISABLED');
      await engine.close();

      // A Tier-3 artifact in a store whose metadata says DISABLED is a false
      // statement about what is on disk, and it fails closed.
      const stray = await createFixture('disabled-stray', {
        records: 2,
        anchorMode: 'DISABLED',
      });
      fs.mkdirSync(stray.spoolDir, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      fs.chmodSync(stray.spoolDir, ANCHOR_SPOOL_DIRECTORY_MODE);
      await assertRejectsWithCode(
        openTier3AnchorEngine({ directory: stray.auditDir }),
        'ANCHOR_DISABLED_ARTIFACT',
      );
      assert.equal(fs.existsSync(stray.spoolDir), true, 'the stray artifact is not deleted');
    });
  });

  /* ====================================================================== *
   * Configuration and trust-root pinning
   * ====================================================================== */

  describe('configuration and trust-root pinning', () => {
    test('RC06-NEG-84: partial anchor configuration fails closed', async () => {
      const fixture = await createFixture('neg84', { records: 2 });
      const base = {
        directory: fixture.auditDir,
        checkpointPublicKeyPath: fixture.checkpointMaterial.publicKeyPath,
        anchorEndpoint: ENDPOINT,
        anchorReceiptPublicKeyPath: fixture.anchorMaterial.publicKeyPath,
        workspacePaths: [],
      };

      // Endpoint without the anchor key; key without the endpoint; and neither
      // required key present. Reconciliation could not prove a single pending
      // checkpoint without the checkpoint trust root, so anchoring would mean
      // acknowledging evidence nothing verified.
      for (const key of [
        'anchorReceiptPublicKeyPath',
        'anchorEndpoint',
        'checkpointPublicKeyPath',
      ]) {
        const partial = { ...base };
        delete partial[key];
        await assertRejectsWithCode(
          createTestTier3AnchorEngine(partial, {}),
          'ANCHOR_CONFIG_INVALID',
        );
      }

      await assertRejectsWithCode(
        createTestTier3AnchorEngine({ directory: fixture.auditDir, workspacePaths: [] }, {}),
        'ANCHOR_CONFIG_INVALID',
      );

      // A supplied endpoint that is not https is a configuration failure, not a
      // runtime downgrade.
      await assertRejectsWithCode(
        createTestTier3AnchorEngine(
          { ...base, anchorEndpoint: 'http://anchor.example.invalid/a' },
          {},
        ),
        'ANCHOR_ENDPOINT_INVALID',
      );

      // No refused configuration left a spool behind.
      assert.equal(fs.existsSync(fixture.spoolDir), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false);
    });

    test('RC06-T5-REG-18: a substituted anchor key is refused by the pinned fingerprint', async () => {
      const fixture = await createFixture('keypin', { records: 2 });
      const impostor = writeKeyPair(path.join(fixture.root, 'impostor'), 'anchor');

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(
          anchorConfig(fixture, { anchorReceiptPublicKeyPath: impostor.publicKeyPath }),
          {},
        ),
        'ANCHOR_RECEIPT_KEY_MISMATCH',
      );

      // A private key is not a trust root: the trust root loader accepts exactly
      // one PUBLIC KEY PEM block and nothing else.
      await assertRejectsWithCode(
        createTestTier3AnchorEngine(
          anchorConfig(fixture, {
            anchorReceiptPublicKeyPath: fixture.anchorMaterial.signingKeyPath,
          }),
          {},
        ),
        ['AUDIT_KEY_ENCODING_FORBIDDEN', 'AUDIT_KEY_MALFORMED', 'AUDIT_KEY_ALGORITHM_FORBIDDEN'],
      );

      // The checkpoint trust root is pinned too. Anchoring is only meaningful over
      // a checkpoint history Task 4 verified, so a substituted checkpoint key is
      // refused by that verifier rather than used to establish one.
      await assertRejectsWithCode(
        createTestTier3AnchorEngine(
          anchorConfig(fixture, {
            checkpointPublicKeyPath: impostor.publicKeyPath,
          }),
          {},
        ),
        ['FINGERPRINT_MISMATCH', 'AUDIT_KEY_ENCODING_FORBIDDEN', 'AUDIT_KEY_MALFORMED'],
      );

      // Nothing was anchored, spooled or acknowledged on the strength of any of
      // the refused configurations.
      assert.equal(fs.existsSync(fixture.receiptPath), false);
    });
  });

  /* ====================================================================== *
   * Artifact authority (rc06 §16, §35)
   * ====================================================================== */

  describe('anchor artifact authority', () => {
    test('RC06-NEG-99: a wider spool directory or entry, or a symlinked one, is refused', async () => {
      // Directory wider than 0700.
      const wideDir = await createFixture('neg99-dir', { records: 2 });
      fs.mkdirSync(wideDir.spoolDir, { mode: 0o755 });
      fs.chmodSync(wideDir.spoolDir, 0o755);
      await assertRejectsWithCode(createTestTier3AnchorEngine(anchorConfig(wideDir), {}), [
        'ANCHOR_SPOOL_INSECURE_ENTRY',
        'AUDIT_STORE_INSECURE_ENTRY',
      ]);

      // Entry wider than 0600.
      const wideEntry = await createFixture('neg99-entry', { records: 2 });
      const [wideCheckpoint] = readCheckpoints(wideEntry);
      fs.mkdirSync(wideEntry.spoolDir, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      fs.chmodSync(wideEntry.spoolDir, ANCHOR_SPOOL_DIRECTORY_MODE);
      const widePath = spoolEntryPath(wideEntry, wideCheckpoint.checkpointHash);
      fs.writeFileSync(widePath, JSON.stringify(wideCheckpoint), { mode: 0o644 });
      fs.chmodSync(widePath, 0o644);
      await assertRejectsWithCode(createTestTier3AnchorEngine(anchorConfig(wideEntry), {}), [
        'ANCHOR_SPOOL_INSECURE_ENTRY',
        'AUDIT_STORE_INSECURE_ENTRY',
      ]);

      // Symlinked spool directory.
      const linkedDir = await createFixture('neg99-linkdir', { records: 2 });
      const linkedTarget = path.join(linkedDir.root, 'elsewhere');
      fs.mkdirSync(linkedTarget, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      symlinkTo(linkedTarget, linkedDir.spoolDir);
      await assertRejectsWithCode(createTestTier3AnchorEngine(anchorConfig(linkedDir), {}), [
        'SYMLINK_DETECTED',
        'ANCHOR_SPOOL_INSECURE_ENTRY',
      ]);

      // Symlinked spool entry.
      const linkedEntry = await createFixture('neg99-linkentry', { records: 2 });
      const [linkedCheckpoint] = readCheckpoints(linkedEntry);
      fs.mkdirSync(linkedEntry.spoolDir, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      fs.chmodSync(linkedEntry.spoolDir, ANCHOR_SPOOL_DIRECTORY_MODE);
      const decoy = path.join(linkedEntry.root, 'decoy.json');
      fs.writeFileSync(decoy, JSON.stringify(linkedCheckpoint), { mode: ANCHOR_SPOOL_FILE_MODE });
      symlinkTo(decoy, spoolEntryPath(linkedEntry, linkedCheckpoint.checkpointHash));
      await assertRejectsWithCode(createTestTier3AnchorEngine(anchorConfig(linkedEntry), {}), [
        'SYMLINK_DETECTED',
        'ANCHOR_SPOOL_INSECURE_ENTRY',
      ]);

      // An entry name outside the frozen canonical form is not silently ignored:
      // a name the budget cannot account for could hide bytes from the ceiling.
      const strayEntry = await createFixture('neg99-stray', { records: 2 });
      fs.mkdirSync(strayEntry.spoolDir, { mode: ANCHOR_SPOOL_DIRECTORY_MODE });
      fs.chmodSync(strayEntry.spoolDir, ANCHOR_SPOOL_DIRECTORY_MODE);
      fs.writeFileSync(path.join(strayEntry.spoolDir, 'notes.txt'), 'hello', {
        mode: ANCHOR_SPOOL_FILE_MODE,
      });
      await assertRejectsWithCode(createTestTier3AnchorEngine(anchorConfig(strayEntry), {}), [
        'ANCHOR_SPOOL_UNRECOGNIZED_ENTRY',
        'AUDIT_STORE_UNRECOGNIZED_ENTRY',
      ]);
    });

    test('RC06-T5-REG-19: the anchor artifacts count toward the audit store budget', async () => {
      const fixture = await createFixture('budget', { records: 2 });
      const before = scanAuditStorePhysicalBytes(fixture.auditDir, getProcessUid());

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      const [checkpoint] = readCheckpoints(fixture);

      const afterSpool = scanAuditStorePhysicalBytes(fixture.auditDir, getProcessUid());
      assert.ok(afterSpool > before, 'the spool directory is part of the store');
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);

      // Acknowledging moves bytes from the spool into the receipt ledger; the
      // ledger is part of the store too, and the Task-3 scanner recognizes both
      // without treating either as an unrecognized entry.
      const engine2 = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: staticTransport(
            200,
            JSON.stringify(mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey)),
          ),
        }).hooks,
      );
      await engine2.anchorCheckpoint(checkpoint);
      assert.equal(fs.existsSync(fixture.receiptPath), true);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), false);

      const afterReceipt = scanAuditStorePhysicalBytes(fixture.auditDir, getProcessUid());
      assert.ok(afterReceipt > 0);
      assert.equal(
        scanAuditStorePhysicalBytes(fixture.auditDir, getProcessUid()),
        afterReceipt,
        'the scanner must not report the anchor artifacts as unknown entries',
      );

      await engine2.close();
      await engine.close();
    });
  });

  /* ====================================================================== *
   * Crash safety and race authority
   * ====================================================================== */

  describe('crash safety and race authority', () => {
    test('RC06-T5-REG-20: a spool write that does not complete transmits nothing', async () => {
      for (const fault of ['error', 'partial', 'zero']) {
        const fixture = await createFixture(`spoolfault-${fault}`, { records: 2 });
        const [checkpoint] = readCheckpoints(fixture);

        let transmissions = 0;
        await assertRejectsWithCode(
          createTestTier3AnchorEngine(
            anchorConfig(fixture),
            instantRetryHooks({
              spoolWriteFault: fault,
              transport: async () => {
                transmissions += 1;
                return { statusCode: 200, body: Buffer.from('{}') };
              },
            }).hooks,
          ),
          'ANCHOR_PERSISTENCE_FAILED',
        );

        // §14.4: a checkpoint is never transmitted before its spool entry is
        // durably synced, so an uncertain spool write cannot reach the anchor.
        assert.equal(transmissions, 0, `fault ${fault} must not transmit`);
        assert.equal(fs.existsSync(fixture.receiptPath), false);

        // What the interrupted write left is one entry under the right name and
        // holding something other than the checkpoint: the name is already taken,
        // which is why the residue is refused rather than overwritten.
        assert.deepEqual(fs.readdirSync(fixture.spoolDir), [`${checkpoint.checkpointHash}.json`]);
        assert.notEqual(
          fs.readFileSync(spoolEntryPath(fixture, checkpoint.checkpointHash), 'utf8'),
          readCheckpointLines(fixture)[0].slice(0, -1),
          `fault ${fault} must leave bytes that are not the checkpoint`,
        );

        // Whatever the failed write left behind is never served. A fresh engine
        // adopts the entry as pending work — its name is canonical and its mode
        // and owner are right — and then refuses to transmit it, because dispatch
        // re-proves that an entry's bytes are the checkpoint its own name claims.
        // That re-proof is what makes a short write harmless rather than a way to
        // get bytes to the anchor that no verified checkpoint produced.
        const recovering = await createTestTier3AnchorEngine(
          anchorConfig(fixture, {
            anchorEndpoint: ENDPOINT,
          }),
          instantRetryHooks({
            transport: async () => {
              throw new Error('the incomplete entry must never be served');
            },
          }).hooks,
        );
        await assertRejectsWithCode(
          recovering.resumePendingAnchors(),
          'ANCHOR_SPOOL_ENTRY_INVALID',
        );
        assert.equal(fs.existsSync(fixture.receiptPath), false);
        await recovering.close();
      }
    });

    test('RC06-T5-REG-21: a spool sync failure fails closed without transmitting', async () => {
      for (const hookName of ['spoolFileSyncFault', 'spoolDirectorySyncFault']) {
        const fixture = await createFixture(`syncfault-${hookName}`, { records: 2 });
        const [checkpoint] = readCheckpoints(fixture);

        let transmissions = 0;
        await assertRejectsWithCode(
          createTestTier3AnchorEngine(
            anchorConfig(fixture),
            instantRetryHooks({
              [hookName]: true,
              transport: async () => {
                transmissions += 1;
                return { statusCode: 200, body: Buffer.from('{}') };
              },
            }).hooks,
          ),
          'ANCHOR_PERSISTENCE_FAILED',
        );

        // The bytes may well be on disk, and that is the point: what the failure
        // guarantees is that the engine never *claims* a durability it could not
        // confirm, so it fails closed and transmits nothing.
        assert.equal(transmissions, 0, `${hookName} must not transmit`);
        assert.equal(fs.existsSync(fixture.receiptPath), false);
        assert.equal(fs.existsSync(spoolEntryPath(fixture, checkpoint.checkpointHash)), true);
      }
    });

    test('RC06-T5-REG-22: a receipt ledger replaced mid-verification fails closed', async () => {
      const fixture = await createFixture('ledger-race', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);
      const receipt = mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey);
      fs.writeFileSync(fixture.receiptPath, serializeAnchorReceiptV1(receipt), { mode: 0o600 });

      // The substitution happens after the ledger has been read to EOF and before
      // the artifact identity is re-established — precisely the window a
      // pathname-based check is vulnerable in.
      const decoy = path.join(fixture.root, 'decoy-ledger.jsonl');
      fs.writeFileSync(decoy, serializeAnchorReceiptV1(receipt), { mode: 0o600 });

      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), {
          ca: caPem,
          beforeReceiptVerificationIdentityCheck: (ledgerPath) => {
            fs.renameSync(decoy, ledgerPath);
          },
        }),
        'ANCHOR_RECEIPT_FILE_RACE',
      );

      // Nothing was reconciled or repaired on the strength of the substituted
      // artifact, and the spool was left untouched.
      assert.equal(fs.existsSync(fixture.spoolDir), false);
    });

    test('RC06-T5-REG-23: a receipt ledger detached before an append is refused', async () => {
      const fixture = await createFixture('append-race', { records: 2 });
      const [checkpoint] = readCheckpoints(fixture);

      let transportCalls = 0;
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: async () => {
            transportCalls += 1;
            return {
              statusCode: 200,
              body: Buffer.from(
                JSON.stringify(mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey)),
                'utf8',
              ),
            };
          },
          beforeReceiptAppend: (ledgerPath) => {
            // Detach the verified artifact and put a different file in its place.
            // A write to either would be durable, correctly signed, and invisible
            // to every future verifier.
            fs.renameSync(ledgerPath, `${ledgerPath}.detached`);
            fs.writeFileSync(ledgerPath, '', { mode: 0o600 });
          },
        }).hooks,
      );

      await assertRejectsWithCode(engine.anchorCheckpoint(checkpoint), [
        'ANCHOR_RECEIPT_FILE_RACE',
        'ANCHOR_ENGINE_FAILED',
        'ANCHOR_PERSISTENCE_FAILED',
      ]);

      // The anchor answered and the receipt verified, and it still was not
      // persisted anywhere the store can see.
      assert.equal(transportCalls, 1);
      assert.equal(fs.readFileSync(fixture.receiptPath, 'utf8'), '');
      assert.equal(fs.readFileSync(`${fixture.receiptPath}.detached`, 'utf8'), '');
      await engine.close();
    });
  });

  /* ====================================================================== *
   * Ordering and bounds
   * ====================================================================== */

  describe('ordering discipline and bounded state', () => {
    test('RC06-T5-REG-24: receipts are appended only in checkpoint order', async () => {
      const fixture = await createFixture('ordering', { records: 4, checkpointCount: 3 });
      const checkpoints = readCheckpoints(fixture);
      assert.equal(checkpoints.length, 3);

      // The anchor answers only for the SECOND checkpoint. The cycle must stop at
      // the head of the queue rather than skip ahead, because a receipt appended
      // out of checkpoint order would break the monotonic subsequence the next
      // startup's reconciliation requires — and the store would then fail closed
      // for a reason that had nothing to do with tampering.
      const requested = [];
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: async (request) => {
            const hash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
            requested.push(hash);
            if (hash !== checkpoints[1].checkpointHash) {
              return { statusCode: 400, body: Buffer.from('unknown checkpoint', 'utf8') };
            }
            return {
              statusCode: 200,
              body: Buffer.from(
                JSON.stringify(
                  mintReceipt(fixture, checkpoints[1], fixture.anchorMaterial.privateKey),
                ),
                'utf8',
              ),
            };
          },
        }).hooks,
      );

      const result = await engine.anchorCheckpoint(checkpoints[2]);

      assert.deepEqual(requested, [checkpoints[0].checkpointHash]);
      assert.equal(result.attempts, 1);
      assert.equal(result.outcome, 'PENDING');
      assert.equal(result.status.unanchoredCheckpoints, 3);
      assert.equal(result.status.degradedReason, 'ANCHOR_REQUEST_REJECTED');
      assert.equal(
        fs.existsSync(fixture.receiptPath),
        false,
        'no receipt may be written out of order',
      );
      await engine.close();

      // The store still reconciles cleanly, which it would not if a receipt had
      // been written for a later checkpoint.
      const restarted = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });
      assert.equal(restarted.getStatus().unanchoredCheckpoints, 3);
      assert.equal(restarted.getStatus().spoolEntries, 3);
      await restarted.close();
    });

    test('RC06-T5-REG-25: anchoring requires the checkpoint to continue the verified history', async () => {
      // The store already holds one checkpoint, covering records 1..2, and is
      // reconciled against exactly that boundary. A second rotation then seals
      // records 3..4, so the store really has a two-checkpoint history and a
      // genuine third record-boundary to test against.
      const fixture = await createFixture('extension', { records: 4, rotateAt: [2] });
      assert.equal(readCheckpoints(fixture)[0].sequenceEnd, 2);
      await fixture.store.rotateNow('SIZE_THRESHOLD');
      const afterSeal = readCheckpoints(fixture);
      assert.equal(afterSeal.length, 2);
      assert.equal(afterSeal[1].sequenceStart, 3);
      assert.equal(afterSeal[1].sequenceEnd, 4);

      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });

      // A checkpoint from an unrelated store whose coverage would extend this one:
      // right shape, right sequence range, wrong history. It is signed, it is
      // bound to its own store, and its back-link names a checkpoint this store
      // never produced — so the back-link is the only thing that can fail.
      const foreign = await createFixture('extension-foreign', { records: 4, rotateAt: [2, 4] });
      const foreignCheckpoints = readCheckpoints(foreign);
      assert.equal(foreignCheckpoints.length, 2);
      assert.equal(foreignCheckpoints[1].sequenceStart, 3);
      assert.equal(foreignCheckpoints[1].sequenceEnd, 4);
      assert.notEqual(
        foreignCheckpoints[1].previousCheckpointHash,
        afterSeal[0].checkpointHash,
        'the foreign back-link must genuinely differ, or the refusal proves nothing',
      );
      await assertRejectsWithCode(
        engine.anchorCheckpoint(foreignCheckpoints[1]),
        'ANCHOR_CHECKPOINT_NOT_CURRENT',
      );

      // A checkpoint whose stored hash does not match its own content is refused
      // before any of that: the hash is the filename the spool entry would take.
      const [first] = afterSeal;
      await assertRejectsWithCode(
        engine.anchorCheckpoint({ ...first, terminalRecordHash: 'a'.repeat(64) }),
        'ANCHOR_CHECKPOINT_INVALID',
      );
      await assertRejectsWithCode(
        engine.anchorCheckpoint({ ...first, version: 2 }),
        'ANCHOR_CHECKPOINT_INVALID',
      );

      // The genuine new checkpoint is already in the pending queue, because
      // reconciliation adopted it from the durable artifact. It is admitted — and
      // the whole backlog is dispatched in order, so nothing earlier is skipped.
      const fresh = afterSeal[1];
      const submitted = [];
      const driving = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: acknowledgingTransport(fixture, afterSeal, submitted),
        }).hooks,
      );
      const result = await driving.anchorCheckpoint(fresh);

      assert.deepEqual(
        submitted,
        afterSeal.map((cp) => cp.checkpointHash),
      );
      assert.equal(result.outcome, 'ACKNOWLEDGED');
      assert.equal(result.attempts, 2);
      assert.equal(result.status.unanchoredCheckpoints, 0);
      assert.deepEqual(
        receiptLines(fixture).map((line) => line.checkpointHash),
        afterSeal.map((cp) => cp.checkpointHash),
      );

      await driving.close();
      await engine.close();
    });

    test('RC06-T5-REG-26: acknowledged receipts are remembered within a bounded window', async () => {
      // One more checkpoint than the frozen pending ceiling, so the receipt map
      // is driven to its bound and the oldest acknowledgement is evicted.
      const total = OVERFLOW_CHECKPOINTS;
      const fixture = await createFixture('bounded', {
        records: OVERFLOW_RECORDS,
        rotateAt: OVERFLOW_ROTATE_AT,
      });
      const checkpoints = readCheckpoints(fixture);
      assert.equal(checkpoints.length, total);

      // First run: the ceiling admits the first hundred, and all of them are
      // acknowledged. The hundred-and-first is not dropped silently — the store
      // is FULL and says so.
      const firstRun = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: acknowledgingTransport(fixture, checkpoints),
        }).hooks,
      );
      assert.equal(firstRun.getStatus().anchorState, 'FULL');
      assertThrowsWithCode(() => firstRun.assertPrivilegedOperationsAllowed(), 'ANCHOR_SPOOL_FULL');
      await firstRun.resumePendingAnchors();
      assert.equal(firstRun.getStatus().spoolEntries, 0);
      assert.equal(receiptLines(fixture).length, MAX_PENDING_ANCHOR_CHECKPOINTS);
      await firstRun.close();

      // Second run: reconciliation reconstructs the one outstanding checkpoint
      // from the durable checkpoint artifact, and acknowledging it pushes the
      // receipt map one past its bound.
      const secondRun = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: acknowledgingTransport(fixture, checkpoints),
        }).hooks,
      );
      const outstanding = secondRun.getStatus();
      assert.equal(outstanding.unanchoredCheckpoints, 1);
      assert.equal(outstanding.acknowledgedCheckpoints, MAX_PENDING_ANCHOR_CHECKPOINTS);
      assert.equal(outstanding.anchorState, 'DEGRADED');

      const latest = checkpoints[checkpoints.length - 1];
      const accepted = await secondRun.anchorCheckpoint(latest);
      assert.equal(accepted.outcome, 'ACKNOWLEDGED');
      assert.equal(receiptLines(fixture).length, total);

      // The oldest acknowledgement has aged out of the window. Re-submitting it
      // is refused rather than re-sent: refusing can never produce a second
      // receipt line, which is why the bound is safe.
      const oldest = checkpoints[0];
      await assertRejectsWithCode(
        secondRun.anchorCheckpoint(oldest),
        'ANCHOR_CHECKPOINT_NOT_CURRENT',
      );
      assert.equal(
        receiptLines(fixture).length,
        total,
        'the refusal must not have appended anything',
      );

      await secondRun.close();
    });

    test('RC06-T5-REG-27: status never discloses the endpoint or key material', async () => {
      const fixture = await createFixture('status', { records: 2 });
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), { ca: caPem });

      const status = engine.getStatus();
      assertNoDisclosure(JSON.stringify(status), ENDPOINT);
      assert.equal(
        JSON.stringify(status).includes(
          fixture.anchorMaterial.privateKey.export({ type: 'pkcs8', format: 'pem' }).slice(0, 32),
        ),
        false,
      );

      // The fingerprint and the store binding are identity metadata rather than
      // secrets, and are exactly what an operator needs to confirm what is pinned.
      assert.equal(status.anchorReceiptPublicKeyFingerprint, fixture.anchorMaterial.fingerprint);
      assert.equal(status.storeId, fixture.storeId);
      assert.equal(status.anchorMode, 'ENABLED');

      await engine.close();
    });
  });

  /* ====================================================================== *
   * Public surface and capability isolation
   * ====================================================================== */

  describe('public surface', () => {
    test('RC06-T5-REG-28: the production-safe surface is exported', () => {
      const index = fs.readFileSync(path.join(PACKAGE_DIST_DIR, 'index.d.ts'), 'utf8');
      for (const symbol of [
        'openTier3AnchorEngine',
        'Tier3AnchorEngine',
        'AnchorReceiptV1',
        'UnsignedAnchorReceiptV1',
        'AnchorStatus',
        'AnchorState',
        'AnchorDispatchResult',
        'Tier3AnchorEngineConfig',
        'validateAnchorReceiptV1',
        'verifyAnchorReceiptSignature',
        'computeAnchorReceiptSignaturePreimage',
        'serializeAnchorReceiptV1',
        'parseAndValidateAnchorReceiptLineV1',
        'computeAnchorReceiptPublicKeyFingerprint',
        'validateAnchorEndpoint',
        'ANCHOR_RECEIPT_FILENAME',
        'ANCHOR_SPOOL_DIRNAME',
        'ANCHOR_RECEIPT_SIGNATURE_DOMAIN',
        'ANCHOR_IDEMPOTENCY_HEADER',
        'ANCHOR_RETRY_BACKOFF_MS',
        'MAX_PENDING_ANCHOR_CHECKPOINTS',
        'MAX_ANCHOR_SPOOL_BYTES',
      ]) {
        assert.ok(index.includes(symbol), `index.d.ts must export ${symbol}`);
      }
    });

    test('RC06-T5-REG-29: the internal seams stay out of the public declarations', () => {
      // Only the package's public declarations are in scope: the internal modules
      // are not reachable through the package exports map, which is what makes
      // this suite's import of them possible without exposing them.
      const publicDeclarations = [
        path.join(PACKAGE_DIST_DIR, 'index.d.ts'),
        path.join(PACKAGE_DIST_DIR, 'anchor.d.ts'),
      ];

      const forbidden = [
        'ANCHOR_TEST_TOKEN',
        'AnchorTestHooks',
        'AnchorNetworkObservation',
        'AnchorTransportRequest',
        'AnchorTransportResponse',
        'AnchorTransportFailure',
        'initializeEngine',
        'assertDescriptorPinnedTraversalAvailable',
        'openAuthoritativeDirectoryFd',
        'createPinnedDirectoryChild',
        'openPinnedDirectoryChild',
        'openPinnedFileChild',
        'unlinkPinnedChild',
        'listPinnedChildren',
        'pinnedChildPath',
        'descriptorLocation',
        'readBoundedDescriptor',
        'PROC_SELF_FD',
        'PinnedErrorCodes',
        'verifyCheckpointHistoryWithObserver',
        'onVerifiedCheckpoint',
        'onCheckpointEmitted',
        'CheckpointTestHooks',
        'CHECKPOINT_TEST_TOKEN',
        'spoolWriteFault',
        'spoolFileSyncFault',
        'spoolDirectorySyncFault',
        'receiptWriteFault',
        'receiptDataSyncFault',
        'beforeReceiptAppend',
        'beforeReceiptVerificationIdentityCheck',
        'beforeSpoolSync',
        'clockMs',
        // `expectedUid` is deliberately NOT listed: it is a legitimate public
        // option of `computeAnchorReceiptPublicKeyFingerprint`, which has to be
        // able to assert the owner of a key file. The test-hook field of the same
        // name is already covered by `AnchorTestHooks` above.
        'readLedgerLines',
        'AnchorSpoolPlan',
        'ReceiptLedgerReader',
        'SpoolInventory',
        'TransmissionOutcome',
        'VerifiedReceiptArtifactState',
        'createTestTier3AnchorEngine',
        'signTestAnchorReceipt',
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

      // The anchor declaration refers to the frozen constants module and nothing
      // else internal — the same shape Task 4's checkpoint declaration has.
      const anchorDeclaration = fs.readFileSync(path.join(PACKAGE_DIST_DIR, 'anchor.d.ts'), 'utf8');
      const internalImports = anchorDeclaration.match(/from '\.\/internal\/[^']+'/g) ?? [];
      assert.deepEqual([...new Set(internalImports)], ["from './internal/anchor-constants.js'"]);
    });

    test('RC06-T5-REG-30: an engine cannot be constructed without the capability token', async () => {
      const fixture = await createFixture('capability', { records: 2 });
      const config = anchorConfig(fixture);

      assert.equal(typeof ANCHOR_TEST_TOKEN, 'symbol');
      assert.equal(ANCHOR_TEST_TOKEN.toString(), 'Symbol(ANCHOR_TEST_TOKEN)');

      // The class is public, but every construction path that does not hold the
      // package-internal symbol is refused — so no caller reachable from
      // configuration, the environment, the CLI or an MCP request can supply a
      // transport, a CA, an expected uid, a clock or a fault.
      assertThrowsWithCode(
        () => new Tier3AnchorEngine(config, Symbol('ANCHOR_TEST_TOKEN')),
        ['ANCHOR_CAPABILITY_REQUIRED'],
      );
      assertThrowsWithCode(
        () => new Tier3AnchorEngine(config, 'not-a-token'),
        ['ANCHOR_CAPABILITY_REQUIRED'],
      );

      // A token-holding caller that never initialized gets an inert engine: the
      // status it reports is the DISABLED default, which claims no anchor key, no
      // store binding and no acknowledgement — and every operation that would
      // depend on configuration established during initialization refuses.
      const uninitialized = new Tier3AnchorEngine(config, ANCHOR_TEST_TOKEN);
      const inert = uninitialized.getStatus();
      assert.equal(inert.anchorMode, 'DISABLED');
      assert.equal(inert.anchorState, 'DISABLED');
      assert.equal(inert.anchorReceiptPublicKeyFingerprint, null);
      assert.equal(inert.storeId, null);
      assert.equal(inert.acknowledgedCheckpoints, 0);
      assert.equal(inert.degradedReason, null);

      assertThrowsWithCode(
        () => uninitialized.assertPrivilegedOperationsAllowed(),
        ['ANCHOR_NOT_INITIALIZED'],
      );
      await assertRejectsWithCode(
        uninitialized.anchorCheckpoint(readCheckpoints(fixture)[0]),
        'ANCHOR_NOT_INITIALIZED',
      );
      await assertRejectsWithCode(uninitialized.resumePendingAnchors(), 'ANCHOR_NOT_INITIALIZED');
      await uninitialized.close();
    });

    test('RC06-T5-REG-31: the internal anchor modules are not package export subpaths', () => {
      const manifest = JSON.parse(
        fs.readFileSync(path.resolve(PACKAGE_DIST_DIR, '../package.json'), 'utf8'),
      );
      const exported = Object.keys(manifest.exports ?? {});
      assert.deepEqual(exported, ['.']);
      for (const key of exported) {
        assert.equal(key.includes('internal'), false, `the exports map must not expose ${key}`);
        assert.equal(key.includes('anchor'), false, `the exports map must not expose ${key}`);
      }
    });

    test('RC06-T5-REG-32: the package version is unchanged', () => {
      const auditManifest = JSON.parse(
        fs.readFileSync(path.resolve(PACKAGE_DIST_DIR, '../package.json'), 'utf8'),
      );
      assert.equal(auditManifest.version, '0.0.0-rc00');
    });

    test('RC06-T5-REG-33: the suite exercised real TLS material from the ephemeral PKI', () => {
      // If the platform `openssl` were absent, `before()` would already have
      // failed the suite rather than skipping it. This asserts the material is
      // real and usable, so a silently-empty PKI cannot make the TLS controls
      // vacuous.
      assert.equal(hasOpenssl(), true);
      assert.match(execFileSync('openssl', ['version'], { encoding: 'utf8' }), /^OpenSSL /);
      assert.match(fs.readFileSync(pki.serverCertPath, 'utf8'), /BEGIN CERTIFICATE/);
      assert.equal(fs.existsSync(pki.trustedCaCertPath), true);
      assert.equal(fs.existsSync(pki.sanMismatchCertPath), true);
      assert.equal(fs.existsSync(pki.unknownCaClientCertPath), true);
    });
  });

  /* ------------------------------------------------------------------------ *
   * RC06-T5-REG-34..40 — the anchor authority chain
   *
   * A checkpoint is admissible only when Task 4 has produced it from the durable
   * checkpoint artifact and the retained primary evidence. Shape, a
   * self-consistent `checkpointHash`, a correct back-link and a valid Ed25519
   * signature are each insufficient on their own: every one of them is
   * reproducible by a caller who has read the store's own public artifacts, and a
   * checkpoint admitted on any of them would put an independent attestation of
   * evidence the primary store never contained into the receipt ledger.
   *
   * `RC06-T5-REG-34`..`RC06-T5-REG-39` each forge exactly one checkpoint with
   * every caller-controllable property correct except the one under test, and
   * `RC06-T5-REG-40` is the counterpart that shows the proof is a gate rather
   * than a wall: the ordinary production shape — a genuine checkpoint sealed by
   * the Tier-2 engine after the anchor engine already reconciled — still passes.
   * ------------------------------------------------------------------------ */

  describe('anchor authority: only verified checkpoint evidence may be spooled', () => {
    test('RC06-T5-REG-34: a fabricated genesis checkpoint cannot be spooled or transmitted', async () => {
      // The reviewed reproduction, in its own terms: an ENABLED store whose
      // primary active stream is empty (0 bytes) and which has no
      // `audit-checkpoints.jsonl` at all, offered a fabricated `AuditCheckpointV1`
      // whose shape is valid, whose back-link is genesis, whose hash is the
      // self-consistent digest of its own content, and whose 64-byte signature is
      // well-formed Base64url that is not an Ed25519 signature over anything.
      const fixture = await createFixture('forged-genesis', { records: 0 });
      assert.equal(
        fs.statSync(path.join(fixture.auditDir, ACTIVE_SEGMENT_FILENAME)).size,
        0,
        'the primary active stream must really be empty',
      );
      assert.equal(fs.existsSync(fixture.checkpointPath), false, 'no checkpoint artifact exists');

      const forged = forgeCheckpoint(fixture, {
        signature: Buffer.alloc(64, 0x5a).toString('base64url'),
      });
      assert.equal(forged.sequenceStart, 1);
      assert.equal(forged.sequenceEnd, 1);
      assert.equal(forged.previousCheckpointHash, '0'.repeat(64));
      assert.equal(computeCheckpointHash(forged), forged.checkpointHash);
      assert.equal(
        verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey),
        false,
        'the signature must be shape-valid but worthless, or this proves nothing',
      );

      const observations = [];
      let transportCalls = 0;
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), {
        networkObserver: (observation) => observations.push(observation),
        transport: async () => {
          transportCalls++;
          throw new Error('the anchor must never be contacted for fabricated evidence');
        },
      });

      await assertRejectsWithCode(engine.anchorCheckpoint(forged), 'ANCHOR_CHECKPOINT_UNVERIFIED');

      assert.equal(transportCalls, 0);
      assert.deepEqual(observations, [], 'no attempt may be observed at all');
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.deepEqual(spoolEntries(fixture), []);
      assert.equal(fs.existsSync(fixture.spoolDir), false, 'no spool directory may be created');
      assert.equal(fs.existsSync(fixture.receiptPath), false);

      // The refusal is about the argument rather than the store, so the engine is
      // not stopped and claims nothing.
      assert.equal(engine.getStatus().anchorState, 'HEALTHY');
      assert.equal(engine.getStatus().unanchoredCheckpoints, 0);
      engine.assertPrivilegedOperationsAllowed();
      await engine.close();
    });

    test('RC06-T5-REG-35: a checkpoint with a garbage signature is refused before spool and network', async () => {
      // A real store with one real durable checkpoint, so the forged checkpoint
      // has a genuine predecessor to chain from: coverage, store binding, key
      // fingerprint and back-link are all correct, and only the signature is not.
      const fixture = await createFixture('forged-signature', { records: 2 });
      const [sealed] = readCheckpoints(fixture);
      assert.equal(sealed.sequenceEnd, 2);

      const forged = forgeCheckpoint(fixture, {
        sequenceStart: 3,
        sequenceEnd: 3,
        previousCheckpointHash: sealed.checkpointHash,
        signature: Buffer.alloc(64, 0x5a).toString('base64url'),
      });
      assert.equal(forged.previousCheckpointHash, sealed.checkpointHash);
      assert.equal(forged.storeId, fixture.storeId);
      assert.equal(forged.publicKeyFingerprint, fixture.checkpointMaterial.fingerprint);
      assert.equal(computeCheckpointHash(forged), forged.checkpointHash);
      assert.equal(verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey), false);

      const submitted = [];
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: acknowledgingTransport(fixture, [sealed, forged], submitted),
        }).hooks,
      );

      // Reconciliation legitimately reconstructed the genuine pending
      // checkpoint, so the spool is not empty to begin with — which is what makes
      // "unchanged" the meaningful assertion rather than "empty".
      const spoolBefore = spoolEntries(fixture);
      assert.deepEqual(spoolBefore, [`${sealed.checkpointHash}.json`]);

      await assertRejectsWithCode(engine.anchorCheckpoint(forged), 'ANCHOR_CHECKPOINT_UNVERIFIED');

      assert.deepEqual(submitted, [], 'the forged checkpoint must never reach the transport');
      assert.deepEqual(spoolEntries(fixture), spoolBefore, 'the refusal must not touch the spool');
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false);

      // The refusal is scoped to the argument: the store's own genuine pending
      // checkpoint is still admissible, still dispatched, still acknowledged.
      const genuine = await engine.anchorCheckpoint(sealed);
      assert.deepEqual(submitted, [sealed.checkpointHash]);
      assert.equal(genuine.outcome, 'ACKNOWLEDGED');
      assert.equal(genuine.status.unanchoredCheckpoints, 0);
      assert.deepEqual(
        receiptLines(fixture).map((line) => line.checkpointHash),
        [sealed.checkpointHash],
      );

      await engine.close();
    });

    test('RC06-T5-REG-36: a correctly signed checkpoint that was never durably appended is refused', async () => {
      const fixture = await createFixture('never-appended', { records: 2 });
      const [sealed] = readCheckpoints(fixture);

      const forged = forgeCheckpoint(fixture, {
        sequenceStart: 3,
        sequenceEnd: 3,
        previousCheckpointHash: sealed.checkpointHash,
      });

      // Every property a caller controls is correct here. The signature verifies
      // under the configured checkpoint key; the store binding matches
      // audit-store.json; the key fingerprint matches the pinned trust root; the
      // coverage continues the verified boundary; the back-link names the real
      // preceding checkpoint; the hash is the canonical digest of the checkpoint
      // itself.
      assert.equal(verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey), true);
      assert.equal(forged.storeId, fixture.storeId);
      assert.equal(forged.publicKeyFingerprint, fixture.checkpointMaterial.fingerprint);
      assert.equal(forged.previousCheckpointHash, sealed.checkpointHash);
      assert.equal(computeCheckpointHash(forged), forged.checkpointHash);

      // The one thing that is not true is that this store ever produced it: there
      // is no line for it in the durable checkpoint artifact. Signature validity
      // alone is demonstrably not the test.
      assert.equal(
        readCheckpoints(fixture).some((cp) => cp.checkpointHash === forged.checkpointHash),
        false,
      );

      const observations = [];
      let transportCalls = 0;
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), {
        networkObserver: (observation) => observations.push(observation),
        transport: async () => {
          transportCalls++;
          throw new Error('the anchor must never be contacted for fabricated evidence');
        },
      });

      const spoolBefore = spoolEntries(fixture);
      assert.deepEqual(spoolBefore, [`${sealed.checkpointHash}.json`]);

      await assertRejectsWithCode(engine.anchorCheckpoint(forged), 'ANCHOR_CHECKPOINT_UNVERIFIED');

      assert.equal(transportCalls, 0);
      assert.deepEqual(observations, []);
      assert.deepEqual(spoolEntries(fixture), spoolBefore);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false);
      await engine.close();
    });

    test('RC06-T5-REG-37: a signed checkpoint the primary ledger does not support is refused', async () => {
      // Two genuine checkpoints, covering 1..2 and 3..4, so the store has a real
      // two-checkpoint history and a real verified boundary at sequence 4.
      const fixture = await createFixture('forged-terminal', { records: 4, rotateAt: [2, 4] });
      const [first, second] = readCheckpoints(fixture);
      assert.equal(second.sequenceStart, 3);
      assert.equal(second.sequenceEnd, 4);

      const observations = [];
      let transportCalls = 0;
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), {
        networkObserver: (observation) => observations.push(observation),
        transport: async () => {
          transportCalls++;
          throw new Error('the anchor must never be contacted for fabricated evidence');
        },
      });
      assert.equal(engine.getStatus().unanchoredCheckpoints, 2);

      // A third checkpoint is then really sealed, so the forgery below sits
      // BEYOND the boundary the engine reconciled: it is not refused for being at
      // or below a checkpoint already verified, which is what the positional
      // pre-check would catch.
      const record = await fixture.store.append(createSampleRecordCandidate());
      await fixture.checkpointEngine.checkpointAfterDurablePrimary({
        sequenceNumber: record.sequenceNumber,
        recordHash: record.integrity.recordHash,
      });
      await fixture.store.rotateNow('SIZE_THRESHOLD');
      const sealedThird = readCheckpoints(fixture)[2];
      assert.equal(sealedThird.sequenceStart, 5);
      assert.equal(sealedThird.sequenceEnd, 5);

      // A correctly signed checkpoint with the same coverage, the same chain and
      // the same store and key binding, carrying a `terminalRecordHash` no
      // primary record in this store has. It is then written exactly where the
      // real checkpoint belongs, so it is durably PRESENT: absence from the
      // artifact is not the reason it must fail, and its signature verifies, so
      // the signature is not the reason either. The primary evidence is.
      const forged = forgeCheckpoint(fixture, {
        sequenceStart: 5,
        sequenceEnd: 5,
        previousCheckpointHash: second.checkpointHash,
        terminalRecordHash: 'b'.repeat(64),
      });
      assert.notEqual(forged.terminalRecordHash, sealedThird.terminalRecordHash);
      assert.equal(forged.previousCheckpointHash, second.checkpointHash);
      assert.equal(verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey), true);
      assert.equal(computeCheckpointHash(forged), forged.checkpointHash);
      fs.writeFileSync(
        fixture.checkpointPath,
        readCheckpointLines(fixture).slice(0, 2).join('') + serializeCheckpointV1(forged),
      );
      assert.deepEqual(
        readCheckpointLines(fixture).slice(0, 2),
        [serializeCheckpointV1(first), serializeCheckpointV1(second)],
        'the forgery must replace only the third line',
      );
      assert.equal(
        readCheckpoints(fixture)[2].checkpointHash,
        forged.checkpointHash,
        'the forgery must really be the durable third line',
      );

      await assert.rejects(engine.anchorCheckpoint(forged), (err) => {
        assert.equal(err.code, 'ANCHOR_CHECKPOINT_UNVERIFIED');
        assert.equal(
          err.cause?.code,
          'AUDIT_CHECKPOINT_TERMINAL_MISMATCH',
          'the refusal must be the primary ledger contradicting the terminal record hash',
        );
        return true;
      });

      assert.equal(transportCalls, 0);
      assert.deepEqual(observations, []);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false);

      // A durable checkpoint artifact that cannot be verified against the primary
      // ledger stops the engine, exactly as an orphaned receipt or an orphaned
      // spool entry does: no later "acknowledged" claim would be verifiable.
      assertThrowsWithCode(
        () => engine.assertPrivilegedOperationsAllowed(),
        'ANCHOR_ENGINE_FAILED',
      );
      assert.equal(engine.getStatus().anchorState, 'FAILED');
      await engine.close();
    });

    test('RC06-T5-REG-38: a correctly signed checkpoint at a coverage the cadence does not require is refused', async () => {
      // Records 3 and 4 are retained, but nothing seals at record 4: the only
      // rotation is at record 2, and the thousandth-record interval is nowhere
      // near. The frozen cadence therefore requires exactly one checkpoint — the
      // one covering 1..2 — and a checkpoint covering 3..4 is not a boundary this
      // store ever had.
      const fixture = await createFixture('forged-cadence', { records: 4, rotateAt: [2] });
      const [sealed] = readCheckpoints(fixture);
      assert.equal(sealed.sequenceEnd, 2);

      const forged = forgeCheckpoint(fixture, {
        sequenceStart: 3,
        sequenceEnd: 4,
        previousCheckpointHash: sealed.checkpointHash,
        terminalRecordHash: 'e'.repeat(64),
      });
      assert.equal(verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey), true);

      const observations = [];
      let transportCalls = 0;
      const engine = await createTestTier3AnchorEngine(anchorConfig(fixture), {
        networkObserver: (observation) => observations.push(observation),
        transport: async () => {
          transportCalls++;
          throw new Error('the anchor must never be contacted for fabricated evidence');
        },
      });

      const spoolBefore = spoolEntries(fixture);
      assert.deepEqual(spoolBefore, [`${sealed.checkpointHash}.json`]);

      await assertRejectsWithCode(engine.anchorCheckpoint(forged), 'ANCHOR_CHECKPOINT_UNVERIFIED');
      assert.equal(transportCalls, 0);
      assert.deepEqual(observations, []);
      assert.deepEqual(spoolEntries(fixture), spoolBefore);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false);
      await engine.close();

      // And the cadence is what refuses it, not merely its absence from disk:
      // written into the durable artifact, the store fails closed at
      // initialization rather than adopting it as evidence to anchor.
      fs.appendFileSync(fixture.checkpointPath, serializeCheckpointV1(forged));
      await assertRejectsWithCode(
        createTestTier3AnchorEngine(anchorConfig(fixture), {}),
        'AUDIT_CHECKPOINT_UNEXPECTED',
      );
    });

    test('RC06-T5-REG-39: a cooperating anchor cannot make the ledger attest to a checkpoint the store never produced', async () => {
      const fixture = await createFixture('forged-ledger', { records: 2 });
      const [sealed] = readCheckpoints(fixture);

      const forged = forgeCheckpoint(fixture, {
        sequenceStart: 3,
        sequenceEnd: 3,
        previousCheckpointHash: sealed.checkpointHash,
      });
      assert.equal(verifyCheckpointSignature(forged, fixture.checkpointMaterial.publicKey), true);

      // The transport is the one the defect would have wanted: it acknowledges
      // whatever hash it is handed, minting a receipt signed by the real anchor
      // key. Under the reviewed defect that is exactly how a fabricated
      // checkpoint became a durable acknowledgement of evidence the primary store
      // never contained.
      const submitted = [];
      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({
          transport: acknowledgingTransport(fixture, [sealed, forged], submitted),
        }).hooks,
      );

      const spoolBefore = spoolEntries(fixture);
      assert.deepEqual(spoolBefore, [`${sealed.checkpointHash}.json`]);

      await assertRejectsWithCode(engine.anchorCheckpoint(forged), 'ANCHOR_CHECKPOINT_UNVERIFIED');

      assert.deepEqual(submitted, [], 'the forged hash must never be submitted');
      assert.deepEqual(spoolEntries(fixture), spoolBefore);
      assert.equal(fs.existsSync(spoolEntryPath(fixture, forged.checkpointHash)), false);
      assert.equal(fs.existsSync(fixture.receiptPath), false, 'the ledger must gain no line');
      assert.equal(engine.getStatus().acknowledgedCheckpoints, 0);

      // The genuine checkpoint the store really produced is still anchored, and
      // the ledger then holds exactly one line — for it, and for nothing else.
      const genuine = await engine.anchorCheckpoint(sealed);
      assert.deepEqual(submitted, [sealed.checkpointHash]);
      assert.equal(genuine.outcome, 'ACKNOWLEDGED');
      assert.deepEqual(
        receiptLines(fixture).map((line) => line.checkpointHash),
        [sealed.checkpointHash],
      );

      await engine.close();
    });

    test('RC06-T5-REG-40: a genuine checkpoint sealed after reconciliation is still admitted', async () => {
      // The counterpart to every refusal above: the authority proof is a gate,
      // not a wall. This is the ordinary production shape — the engine reconciles
      // a store holding one checkpoint, the Tier-2 engine really seals a second
      // one afterwards, and that new checkpoint, which the pending queue has
      // never seen, has to be admitted and dispatched in order.
      const fixture = await createFixture('post-reconcile', { records: 2 });
      const [sealed] = readCheckpoints(fixture);

      // The receipt is minted for whichever hash is asked, from the artifact as
      // it stands at request time, because the second checkpoint does not exist
      // yet when the engine is constructed.
      const submitted = [];
      const transport = async (request) => {
        const hash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
        submitted.push(hash);
        const checkpoint = readCheckpoints(fixture).find((cp) => cp.checkpointHash === hash);
        if (checkpoint === undefined) {
          return { statusCode: 400, body: Buffer.from('unknown checkpoint', 'utf8') };
        }
        return {
          statusCode: 200,
          body: Buffer.from(
            JSON.stringify(mintReceipt(fixture, checkpoint, fixture.anchorMaterial.privateKey)),
            'utf8',
          ),
        };
      };

      const engine = await createTestTier3AnchorEngine(
        anchorConfig(fixture),
        instantRetryHooks({ transport }).hooks,
      );
      assert.equal(engine.getStatus().unanchoredCheckpoints, 1);

      // A real record, a real cadence offer and a real rotation, so the new
      // checkpoint is durable before the anchor engine is told about it — the
      // ordering the whole module is built on.
      const record = await fixture.store.append(createSampleRecordCandidate());
      await fixture.checkpointEngine.checkpointAfterDurablePrimary({
        sequenceNumber: record.sequenceNumber,
        recordHash: record.integrity.recordHash,
      });
      await fixture.store.rotateNow('SIZE_THRESHOLD');

      const checkpoints = readCheckpoints(fixture);
      assert.equal(checkpoints.length, 2);
      const fresh = checkpoints[1];
      assert.equal(fresh.sequenceStart, 3);
      assert.equal(fresh.sequenceEnd, 3);
      assert.equal(fresh.previousCheckpointHash, sealed.checkpointHash);

      const result = await engine.anchorCheckpoint(fresh);

      assert.deepEqual(
        submitted,
        checkpoints.map((cp) => cp.checkpointHash),
        'the backlog is dispatched in order, and the new checkpoint is included',
      );
      assert.equal(result.outcome, 'ACKNOWLEDGED');
      assert.equal(result.attempts, 2);
      assert.equal(result.status.unanchoredCheckpoints, 0);
      assert.deepEqual(
        receiptLines(fixture).map((line) => line.checkpointHash),
        checkpoints.map((cp) => cp.checkpointHash),
      );

      await engine.close();
    });
  });
});
