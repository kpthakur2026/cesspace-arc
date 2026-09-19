/**
 * CesSpace ARC — RC-05 Task 1: Device Identity, SPKI Pinning, and Trust-Store Integrity
 *
 * Test catalog verifying:
 * - §7 P-4..P-8: SPKI pinning, canonical representation, rotation overlap window
 * - §8: Device identity model, duplicate enrollment semantics, resource bounds, revocation state
 * - §16 / §16.1: Persistence model, strict closed-schema validation, filesystem integrity, atomic write protocol
 * - Negative controls: RC05-NEG-16 through RC05-NEG-27
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import * as PublicAuth from '../packages/auth/dist/index.js';
import {
  generateDeviceId,
  isValidDeviceId,
  isValidSpkiPin,
  deriveSpkiPin,
  validateDisplayLabel,
  DeviceTrustStore,
  validateTrustStoreData,
  assertValidTrustStorePath,
  validateTrustStoreFileStat,
  validateTrustStoreParentDirectoryStat,
  verifyTrustStoreFileIntegrity,
  MAX_TRUST_STORE_BYTES,
} from '../packages/auth/dist/index.js';
import {
  defaultFsAdapter,
  verifyTrustStoreFileIntegrityWithAdapter,
  atomicPersistTrustStoreWithAdapter,
} from '../packages/auth/dist/internal-testing.js';
import { ArcError } from '../packages/protocol/dist/index.js';

describe('CesSpace ARC — RC-05 Task 1: Device Identity, SPKI Pinning & Trust Store', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-trust-store-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // Helper to generate a valid 64-char lowercase hex pin (using 0xab so it contains letters a and b)
  function samplePin(byte = 0xab) {
    return Buffer.alloc(32, byte).toString('hex');
  }

  // ---------------------------------------------------------------------------
  // 1. Device Identity Primitives (§8)
  // ---------------------------------------------------------------------------
  describe('1. Device Identity Primitives (§8)', () => {
    test('generateDeviceId creates 32 lowercase hex characters with high entropy', () => {
      const id1 = generateDeviceId();
      const id2 = generateDeviceId();

      assert.equal(id1.length, 32);
      assert.equal(id2.length, 32);
      assert.notEqual(id1, id2);
      assert.match(id1, /^[0-9a-f]{32}$/);
      assert.match(id2, /^[0-9a-f]{32}$/);
    });

    test('isValidDeviceId strictly validates 32 lowercase hex format', () => {
      assert.equal(isValidDeviceId(generateDeviceId()), true);
      assert.equal(isValidDeviceId('0123456789abcdef0123456789abcdef'), true);

      // Rejections
      assert.equal(
        isValidDeviceId('0123456789ABCDEF0123456789ABCDEF'),
        false,
        'Uppercase rejected',
      );
      assert.equal(isValidDeviceId('0123456789abcdef0123456789abcde'), false, '31 chars rejected');
      assert.equal(
        isValidDeviceId('0123456789abcdef0123456789abcdef0'),
        false,
        '33 chars rejected',
      );
      assert.equal(isValidDeviceId('0123456789abcdef0123456789abcdeg'), false, 'Non-hex rejected');
      assert.equal(isValidDeviceId(''), false, 'Empty string rejected');
      assert.equal(isValidDeviceId(null), false, 'Null rejected');
      assert.equal(isValidDeviceId(12345), false, 'Number rejected');
    });

    test('validateDisplayLabel enforces maximum 64 UTF-8 bytes ceiling', () => {
      assert.equal(validateDisplayLabel(''), '');
      assert.equal(validateDisplayLabel('Alice Work Laptop'), 'Alice Work Laptop');

      const exact64Ascii = 'a'.repeat(64);
      assert.equal(validateDisplayLabel(exact64Ascii), exact64Ascii);

      // 65 bytes ASCII
      assert.throws(
        () => validateDisplayLabel('a'.repeat(65)),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Multi-byte UTF-8 test: 22 3-byte unicode characters = 66 bytes (exceeds 64)
      const multiByteOver = '€'.repeat(22); // each € is 3 bytes in UTF-8 -> 66 bytes
      assert.equal(Buffer.byteLength(multiByteOver, 'utf8'), 66);
      assert.throws(
        () => validateDisplayLabel(multiByteOver),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // 21 3-byte unicode characters = 63 bytes (valid)
      const multiByteValid = '€'.repeat(21);
      assert.equal(Buffer.byteLength(multiByteValid, 'utf8'), 63);
      assert.equal(validateDisplayLabel(multiByteValid), multiByteValid);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. SPKI Pinning Primitives (§7 P-4..P-8)
  // ---------------------------------------------------------------------------
  describe('2. SPKI Pinning Primitives (§7 P-4..P-8)', () => {
    test('isValidSpkiPin strictly validates 64 lowercase hex characters', () => {
      const validPin = samplePin();
      assert.equal(isValidSpkiPin(validPin), true);

      // Rejections
      assert.equal(isValidSpkiPin(validPin.toUpperCase()), false, 'Uppercase rejected');
      assert.equal(isValidSpkiPin(validPin.slice(0, 63)), false, '63 chars rejected');
      assert.equal(isValidSpkiPin(validPin + '0'), false, '65 chars rejected');
      assert.equal(isValidSpkiPin(validPin.slice(0, 63) + 'z'), false, 'Non-hex rejected');
      assert.equal(isValidSpkiPin(''), false, 'Empty string rejected');
      assert.equal(isValidSpkiPin(null), false, 'Null rejected');
    });

    test('deriveSpkiPin hashes DER SubjectPublicKeyInfo with SHA-256', () => {
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      const derSpki = publicKey.export({ type: 'spki', format: 'der' });
      const expectedPin = crypto.createHash('sha256').update(derSpki).digest('hex');

      const derivedFromKey = deriveSpkiPin(publicKey);
      assert.equal(derivedFromKey, expectedPin);
      assert.match(derivedFromKey, /^[0-9a-f]{64}$/);

      const derivedFromDer = deriveSpkiPin(derSpki);
      assert.equal(derivedFromDer, expectedPin);

      const pemSpki = publicKey.export({ type: 'spki', format: 'pem' });
      const derivedFromPem = deriveSpkiPin(pemSpki);
      assert.equal(derivedFromPem, expectedPin);
    });

    test('deriveSpkiPin rejects arbitrary or malformed Buffers (no silent fallback)', () => {
      // Random bytes must not be silently hashed into a pin
      const randomBuf = crypto.randomBytes(64);
      assert.throws(
        () => deriveSpkiPin(randomBuf),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Malformed non-DER bytes
      const malformedBuf = Buffer.from('malformed-non-der-data');
      assert.throws(
        () => deriveSpkiPin(malformedBuf),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Zero-length buffer
      assert.throws(
        () => deriveSpkiPin(Buffer.alloc(0)),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Unsupported input types
      assert.throws(
        () => deriveSpkiPin(12345),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Negative Controls RC05-NEG-16..22 (Pinning & Resource Bounds)
  // ---------------------------------------------------------------------------
  describe('3. Negative Controls RC05-NEG-16..22 (Pinning & Resource Bounds)', () => {
    test('RC05-NEG-16: Unpinned SPKI cannot resolve to an enrolled device', () => {
      const store = DeviceTrustStore.createEmpty();
      const enrolledPin = samplePin(0x01);
      store.enrollDevice({
        clientId: 'client-1',
        clientType: 'cli',
        pin: enrolledPin,
      });

      const unpinnedPin = samplePin(0x99);
      assert.equal(store.findDeviceByPin(unpinnedPin), undefined);
      assert.notEqual(store.findDeviceByPin(enrolledPin), undefined);
    });

    test('RC05-NEG-17: Rotation overlap allows old+new pins while active, removed old pin no longer resolves', () => {
      const store = DeviceTrustStore.createEmpty();
      const oldPin = samplePin(0x10);
      const newPin = samplePin(0x20);

      const { device } = store.enrollDevice({
        clientId: 'rot-client',
        clientType: 'service',
        pin: oldPin,
      });

      // Initially only oldPin resolves
      assert.equal(store.findDeviceByPin(oldPin)?.deviceId, device.deviceId);
      assert.equal(store.findDeviceByPin(newPin), undefined);

      // Open overlap window by adding new pin
      store.addPinToDevice(device.deviceId, newPin);

      // Both pins resolve during overlap window
      assert.equal(store.findDeviceByPin(oldPin)?.deviceId, device.deviceId);
      assert.equal(store.findDeviceByPin(newPin)?.deviceId, device.deviceId);

      // Close overlap window by removing old pin
      store.removePinFromDevice(device.deviceId, oldPin);

      // Old pin no longer resolves; new pin resolves
      assert.equal(store.findDeviceByPin(oldPin), undefined);
      assert.equal(store.findDeviceByPin(newPin)?.deviceId, device.deviceId);
    });

    test('RC05-NEG-18: Malformed pin configuration is rejected', () => {
      const store = DeviceTrustStore.createEmpty();

      // Non-hex pin
      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'c1',
            clientType: 't1',
            pin: 'g'.repeat(64),
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Uppercase pin
      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'c1',
            clientType: 't1',
            pin: samplePin().toUpperCase(),
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Short pin
      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'c1',
            clientType: 't1',
            pin: samplePin().slice(0, 63),
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
    });

    test('RC05-NEG-19: One pin cannot belong to two devices', () => {
      const store = DeviceTrustStore.createEmpty();
      const sharedPin = samplePin(0x42);

      store.enrollDevice({
        clientId: 'client-1',
        clientType: 'cli',
        pin: sharedPin,
      });

      // Attempting to enroll second device with same pin under another clientId fails
      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'client-2',
            clientType: 'cli',
            pin: sharedPin,
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // In-memory addPinToDevice also rejects duplicate across devices
      const { device: dev2 } = store.enrollDevice({
        clientId: 'client-2',
        clientType: 'cli',
        pin: samplePin(0x99),
      });

      assert.throws(
        () => store.addPinToDevice(dev2.deviceId, sharedPin),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Schema parser rejects duplicate pin across distinct devices
      const conflictData = {
        version: 1,
        devices: [
          {
            deviceId: generateDeviceId(),
            clientId: 'c1',
            clientType: 't1',
            pins: [sharedPin],
            enrolledAt: new Date().toISOString(),
            displayLabel: '',
            revoked: false,
          },
          {
            deviceId: generateDeviceId(),
            clientId: 'c2',
            clientType: 't2',
            pins: [sharedPin],
            enrolledAt: new Date().toISOString(),
            displayLabel: '',
            revoked: false,
          },
        ],
      };
      assert.throws(
        () => validateTrustStoreData(conflictData),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
    });

    test('RC05-NEG-20: Third active pin rejected without altering existing pins', () => {
      const store = DeviceTrustStore.createEmpty();
      const pin1 = samplePin(0x01);
      const pin2 = samplePin(0x02);
      const pin3 = samplePin(0x03);

      const { device } = store.enrollDevice({
        clientId: 'c1',
        clientType: 't1',
        pin: pin1,
      });
      store.addPinToDevice(device.deviceId, pin2);

      const recordBefore = store.findDeviceById(device.deviceId);
      assert.deepEqual(recordBefore?.pins, [pin1, pin2]);

      // Adding 3rd pin throws RESOURCE_EXHAUSTED
      assert.throws(
        () => store.addPinToDevice(device.deviceId, pin3),
        (err) => err instanceof ArcError && err.code === 'RESOURCE_EXHAUSTED',
      );

      // Existing pins remain intact
      const recordAfter = store.findDeviceById(device.deviceId);
      assert.deepEqual(recordAfter?.pins, [pin1, pin2]);
      assert.equal(store.findDeviceByPin(pin3), undefined);
    });

    test('RC05-NEG-21: 257th device rejected without mutating the store', () => {
      const store = DeviceTrustStore.createEmpty();

      // Fill store to capacity of 256 devices
      for (let i = 0; i < 256; i++) {
        const pin =
          Buffer.alloc(32, 0).toString('hex').slice(0, 58) + i.toString(16).padStart(6, '0');
        store.enrollDevice({
          clientId: `client-${i}`,
          clientType: 'cli',
          pin,
        });
      }

      assert.equal(store.getDeviceCount(), 256);

      // Attempting 257th enrollment fails with RESOURCE_EXHAUSTED
      const pin257 = samplePin(0xff);
      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'client-overflow',
            clientType: 'cli',
            pin: pin257,
          }),
        (err) => err instanceof ArcError && err.code === 'RESOURCE_EXHAUSTED',
      );

      // Store size and contents unchanged
      assert.equal(store.getDeviceCount(), 256);
      assert.equal(store.findDeviceByPin(pin257), undefined);
    });

    test('RC05-NEG-22: Display label > 64 UTF-8 bytes rejected', () => {
      const store = DeviceTrustStore.createEmpty();
      const pin = samplePin(0x77);

      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'c1',
            clientType: 'cli',
            pin,
            displayLabel: 'x'.repeat(65),
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      assert.equal(store.getDeviceCount(), 0);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Negative Controls RC05-NEG-23..27 (Filesystem Integrity & Persistence)
  // ---------------------------------------------------------------------------
  describe('4. Negative Controls RC05-NEG-23..27 (Filesystem Integrity & Persistence)', () => {
    test('RC05-NEG-23: Trust-store symlink rejected', () => {
      const realFile = path.join(tempDir, 'real-devices.json');
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });
      store.saveToFile(realFile);

      const symlinkPath = path.join(tempDir, 'devices-symlink.json');
      fs.symlinkSync(realFile, symlinkPath);

      assert.throws(
        () => DeviceTrustStore.loadFromFile(symlinkPath),
        (err) => err instanceof ArcError && err.code === 'UNSAFE_SYMLINK',
      );
    });

    test('RC05-NEG-24: Insecure trust-store permissions rejected', () => {
      if (process.platform === 'win32') return;

      const filePath = path.join(tempDir, 'devices.json');
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });
      store.saveToFile(filePath);

      // Insecure mode 0644 (world readable)
      fs.chmodSync(filePath, 0o644);
      assert.throws(
        () => DeviceTrustStore.loadFromFile(filePath),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // Insecure mode 0666 (world writable)
      fs.chmodSync(filePath, 0o666);
      assert.throws(
        () => DeviceTrustStore.loadFromFile(filePath),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // Mode 0600 is accepted
      fs.chmodSync(filePath, 0o600);
      assert.doesNotThrow(() => DeviceTrustStore.loadFromFile(filePath));
    });

    test('RC05-NEG-25: Real ownership enforcement on trust store file and parent directory', () => {
      if (process.platform === 'win32' || typeof process.getuid !== 'function') return;

      const currentUid = process.getuid();
      const mismatchedUid = currentUid + 9999;
      const filePath = path.join(tempDir, 'devices.json');
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });
      store.saveToFile(filePath);

      // 1. In normal operation, real file matches process UID and passes verification
      const realStat = fs.lstatSync(filePath);
      assert.equal(realStat.uid, currentUid);
      assert.doesNotThrow(() => verifyTrustStoreFileIntegrity(filePath));
      assert.doesNotThrow(() => DeviceTrustStore.loadFromFile(filePath));

      // 2. Production file ownership mismatch causes ACCESS_DENIED (deterministic adapter test)
      const mismatchedFileAdapter = {
        ...defaultFsAdapter,
        lstatSync: (p) => {
          const s = fs.lstatSync(p);
          if (path.resolve(p) === path.resolve(filePath)) {
            return {
              isSymbolicLink: () => false,
              isFile: () => true,
              size: s.size,
              mode: 0o100600,
              uid: mismatchedUid,
            };
          }
          return s;
        },
      };

      assert.throws(
        () => verifyTrustStoreFileIntegrityWithAdapter(filePath, mismatchedFileAdapter),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      assert.throws(
        () => DeviceTrustStore.loadFromFileWithAdapter(filePath, mismatchedFileAdapter),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // 3. Direct pure validation of file stat
      assert.throws(
        () =>
          validateTrustStoreFileStat(
            {
              isSymbolicLink: () => false,
              isFile: () => true,
              size: 100,
              mode: 0o100600,
              uid: mismatchedUid,
            },
            currentUid,
          ),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // 4. Production parent directory ownership mismatch causes ACCESS_DENIED
      const mismatchedParentAdapter = {
        ...defaultFsAdapter,
        lstatSync: (p) => {
          const s = fs.lstatSync(p);
          if (path.resolve(p) === path.resolve(tempDir)) {
            return {
              isSymbolicLink: () => false,
              isDirectory: () => true,
              mode: 0o040700,
              uid: mismatchedUid,
            };
          }
          return s;
        },
      };

      // Both read and write verification fail closed on parent ownership mismatch
      assert.throws(
        () => verifyTrustStoreFileIntegrityWithAdapter(filePath, mismatchedParentAdapter),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      assert.throws(
        () => store.saveToFileWithAdapter(filePath, mismatchedParentAdapter),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // 5. Direct pure validation of parent directory stat (process UID and root pass; others fail)
      assert.doesNotThrow(() =>
        validateTrustStoreParentDirectoryStat(
          {
            isSymbolicLink: () => false,
            isDirectory: () => true,
            mode: 0o040700,
            uid: currentUid,
          },
          currentUid,
        ),
      );

      assert.doesNotThrow(() =>
        validateTrustStoreParentDirectoryStat(
          {
            isSymbolicLink: () => false,
            isDirectory: () => true,
            mode: 0o040700,
            uid: 0, // root is explicitly permitted by §16.1
          },
          currentUid,
        ),
      );

      assert.throws(
        () =>
          validateTrustStoreParentDirectoryStat(
            {
              isSymbolicLink: () => false,
              isDirectory: () => true,
              mode: 0o040700,
              uid: mismatchedUid,
            },
            currentUid,
          ),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );
    });

    test('RC05-NEG-26: Corrupt or > 256 KiB trust store rejected', () => {
      const corruptPath = path.join(tempDir, 'corrupt.json');
      fs.writeFileSync(corruptPath, '{ not valid json', { mode: 0o600 });

      assert.throws(
        () => DeviceTrustStore.loadFromFile(corruptPath),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // > 256 KiB file
      const largePath = path.join(tempDir, 'large.json');
      const largeBuf = Buffer.alloc(MAX_TRUST_STORE_BYTES + 1024, ' ');
      fs.writeFileSync(largePath, largeBuf, { mode: 0o600 });

      assert.throws(
        () => DeviceTrustStore.loadFromFile(largePath),
        (err) => err instanceof ArcError && err.code === 'RESOURCE_EXHAUSTED',
      );
    });

    test('RC05-NEG-27: Atomic persistence pre-commit failure preserves target file and cleans artifacts', () => {
      const filePath = path.join(tempDir, 'devices.json');
      const store = DeviceTrustStore.createEmpty();
      const pin1 = samplePin(0x11);
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: pin1 });
      store.saveToFile(filePath);

      const contentBefore = fs.readFileSync(filePath, 'utf8');

      // Add a 2nd device to store in-memory so saving would change content if it committed
      const pin2 = samplePin(0x22);
      store.enrollDevice({ clientId: 'c2', clientType: 't2', pin: pin2 });

      // Helper to check no temp files remain in tempDir
      const assertNoTempFiles = () => {
        const remaining = fs.readdirSync(tempDir).filter((f) => f.startsWith('.devices.json.tmp.'));
        assert.equal(remaining.length, 0, `Expected 0 temp files, found: ${remaining.join(', ')}`);
      };

      // 1. Pre-commit failure: write failure
      const writeFailAdapter = {
        ...defaultFsAdapter,
        writeSync: () => {
          throw new Error('Simulated write I/O failure');
        },
      };
      assert.throws(() => store.saveToFileWithAdapter(filePath, writeFailAdapter));
      assert.equal(fs.readFileSync(filePath, 'utf8'), contentBefore, 'Prior target bytes intact');
      assertNoTempFiles();

      // 2. Pre-commit failure: incomplete / zero-progress short write
      const shortWriteAdapter = {
        ...defaultFsAdapter,
        writeSync: () => 0, // zero progress
      };
      assert.throws(
        () => store.saveToFileWithAdapter(filePath, shortWriteAdapter),
        (err) => err instanceof ArcError && err.code === 'INTERNAL_ERROR',
      );
      assert.equal(fs.readFileSync(filePath, 'utf8'), contentBefore, 'Prior target bytes intact');
      assertNoTempFiles();

      // 3. Pre-commit failure: file fsync failure
      const fsyncFailAdapter = {
        ...defaultFsAdapter,
        fsyncSync: () => {
          // Fail only on file sync (temp file), not directory
          throw new Error('Simulated file fsync failure');
        },
      };
      assert.throws(() => store.saveToFileWithAdapter(filePath, fsyncFailAdapter));
      assert.equal(fs.readFileSync(filePath, 'utf8'), contentBefore, 'Prior target bytes intact');
      assertNoTempFiles();

      // 4. Pre-commit failure: rename failure
      const renameFailAdapter = {
        ...defaultFsAdapter,
        renameSync: () => {
          throw new Error('Simulated atomic rename failure');
        },
      };
      assert.throws(() => store.saveToFileWithAdapter(filePath, renameFailAdapter));
      assert.equal(fs.readFileSync(filePath, 'utf8'), contentBefore, 'Prior target bytes intact');
      assertNoTempFiles();
    });

    test('Existing target trust-store integrity verified before overwrite (§16.1)', () => {
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });

      // Helper to assert 0 temp files
      const assertNoTempFiles = (dir) => {
        const tempFiles = fs.readdirSync(dir).filter((f) => f.startsWith('.devices.json.tmp.'));
        assert.equal(tempFiles.length, 0, `Expected 0 temp files, found: ${tempFiles.join(', ')}`);
      };

      // 1. Clean initial creation when target is absent
      const freshTarget = path.join(tempDir, 'fresh-devices.json');
      assert.equal(fs.existsSync(freshTarget), false);
      assert.doesNotThrow(() => store.saveToFile(freshTarget));
      assert.equal(fs.existsSync(freshTarget), true);
      assertNoTempFiles(tempDir);

      // 2. Existing symlink target MUST be rejected, not silently overwritten
      const realTarget = path.join(tempDir, 'real-target.json');
      fs.writeFileSync(realTarget, 'original-content', { mode: 0o600 });
      const symlinkTarget = path.join(tempDir, 'symlink-target.json');
      fs.symlinkSync(realTarget, symlinkTarget);

      assert.throws(
        () => store.saveToFile(symlinkTarget),
        (err) => err instanceof ArcError && err.code === 'UNSAFE_SYMLINK',
      );
      // Verify symlink target and original file are untouched
      assert.equal(fs.lstatSync(symlinkTarget).isSymbolicLink(), true);
      assert.equal(fs.readFileSync(realTarget, 'utf8'), 'original-content');
      assertNoTempFiles(tempDir);

      // 3. Existing wrong-owner target MUST be rejected
      if (process.platform !== 'win32' && typeof process.getuid === 'function') {
        const currentUid = process.getuid();
        const wrongOwnerTarget = path.join(tempDir, 'wrong-owner-target.json');
        fs.writeFileSync(wrongOwnerTarget, 'prior-bytes', { mode: 0o600 });

        const mismatchedTargetAdapter = {
          ...defaultFsAdapter,
          lstatSync: (p) => {
            const s = fs.lstatSync(p);
            if (path.resolve(p) === path.resolve(wrongOwnerTarget)) {
              return {
                isSymbolicLink: () => false,
                isFile: () => true,
                size: s.size,
                mode: 0o100600,
                uid: currentUid + 9999,
              };
            }
            return s;
          },
        };

        assert.throws(
          () => store.saveToFileWithAdapter(wrongOwnerTarget, mismatchedTargetAdapter),
          (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
        );
        assert.equal(fs.readFileSync(wrongOwnerTarget, 'utf8'), 'prior-bytes');
        assertNoTempFiles(tempDir);
      }

      // 4. Existing insecure-mode target MUST be rejected (0644 and 0666)
      if (process.platform !== 'win32') {
        const insecureTarget = path.join(tempDir, 'insecure-mode-target.json');
        fs.writeFileSync(insecureTarget, 'prior-mode-bytes', { mode: 0o644 });

        assert.throws(
          () => store.saveToFile(insecureTarget),
          (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
        );
        assert.equal(fs.readFileSync(insecureTarget, 'utf8'), 'prior-mode-bytes');
        assertNoTempFiles(tempDir);

        fs.chmodSync(insecureTarget, 0o666);
        assert.throws(
          () => store.saveToFile(insecureTarget),
          (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
        );
        assert.equal(fs.readFileSync(insecureTarget, 'utf8'), 'prior-mode-bytes');
        assertNoTempFiles(tempDir);
      }

      // 5. Existing non-regular target (directory) MUST be rejected
      const dirAsTarget = path.join(tempDir, 'dir-as-target.json');
      fs.mkdirSync(dirAsTarget, { mode: 0o700 });
      assert.throws(
        () => store.saveToFile(dirAsTarget),
        (err) => err instanceof ArcError && err.code === 'NOT_A_FILE',
      );
      assert.equal(fs.statSync(dirAsTarget).isDirectory(), true);
      assertNoTempFiles(tempDir);
    });

    test('Path traversal sequences (..) and invalid paths fail closed (§16.1)', () => {
      // Direct path assertion checks
      assert.throws(
        () => assertValidTrustStorePath(''),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
      assert.throws(
        () => assertValidTrustStorePath('   '),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
      assert.throws(
        () => assertValidTrustStorePath('/path/to/\0devices.json'),
        (err) => err instanceof ArcError && err.code === 'INVALID_PATH_CHARS',
      );
      assert.throws(
        () => assertValidTrustStorePath('../devices.json'),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );
      assert.throws(
        () => assertValidTrustStorePath('/tmp/foo/../devices.json'),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );
      assert.throws(
        () => assertValidTrustStorePath('foo/../../devices.json'),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // Traversal rejected on load
      assert.throws(
        () => DeviceTrustStore.loadFromFile('../devices.json'),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // Traversal rejected on save
      const store = DeviceTrustStore.createEmpty();
      assert.throws(
        () => store.saveToFile('../devices.json'),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );
    });

    test('Directory fsync error handling: recognized unsupported vs fail-closed operational errors', () => {
      if (process.platform === 'win32') return;

      const filePath = path.join(tempDir, 'devices.json');
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });

      // 1. Recognized unsupported codes (ENOTSUP, EOPNOTSUPP, EINVAL) are tolerated
      for (const unsupportedCode of ['ENOTSUP', 'EOPNOTSUPP', 'EINVAL']) {
        const unsupportedAdapter = {
          ...defaultFsAdapter,
          openSync: (p, flags, mode) => {
            if (path.resolve(p) === path.resolve(tempDir)) {
              const err = new Error(`Directory sync not supported: ${unsupportedCode}`);
              err.code = unsupportedCode;
              throw err;
            }
            return defaultFsAdapter.openSync(p, flags, mode);
          },
        };

        assert.doesNotThrow(
          () => atomicPersistTrustStoreWithAdapter(filePath, store.toData(), unsupportedAdapter),
          `Code ${unsupportedCode} should be tolerated`,
        );
      }

      // 2. EIO must fail closed and report failure
      const eioAdapter = {
        ...defaultFsAdapter,
        openSync: (p, flags, mode) => {
          if (path.resolve(p) === path.resolve(tempDir)) return 999;
          return defaultFsAdapter.openSync(p, flags, mode);
        },
        fsyncSync: (fd) => {
          if (fd === 999) {
            const err = new Error('I/O error during directory fsync');
            err.code = 'EIO';
            throw err;
          }
          return defaultFsAdapter.fsyncSync(fd);
        },
        closeSync: (fd) => {
          if (fd === 999) return;
          return defaultFsAdapter.closeSync(fd);
        },
      };
      assert.throws(
        () => atomicPersistTrustStoreWithAdapter(filePath, store.toData(), eioAdapter),
        (err) => err instanceof ArcError && err.code === 'INTERNAL_ERROR',
      );

      // 3. EBADF must fail closed and report failure
      const ebadfAdapter = {
        ...defaultFsAdapter,
        openSync: (p, flags, mode) => {
          if (path.resolve(p) === path.resolve(tempDir)) {
            const err = new Error('Bad file descriptor');
            err.code = 'EBADF';
            throw err;
          }
          return defaultFsAdapter.openSync(p, flags, mode);
        },
      };
      assert.throws(
        () => atomicPersistTrustStoreWithAdapter(filePath, store.toData(), ebadfAdapter),
        (err) => err instanceof ArcError && err.code === 'INTERNAL_ERROR',
      );

      // 4. EPERM must fail closed and report failure
      const epermAdapter = {
        ...defaultFsAdapter,
        openSync: (p, flags, mode) => {
          if (path.resolve(p) === path.resolve(tempDir)) {
            const err = new Error('Operation not permitted');
            err.code = 'EPERM';
            throw err;
          }
          return defaultFsAdapter.openSync(p, flags, mode);
        },
      };
      assert.throws(
        () => atomicPersistTrustStoreWithAdapter(filePath, store.toData(), epermAdapter),
        (err) => err instanceof ArcError && err.code === 'INTERNAL_ERROR',
      );

      // 5. Unexpected error without code must fail closed
      const unexpectedAdapter = {
        ...defaultFsAdapter,
        openSync: (p, flags, mode) => {
          if (path.resolve(p) === path.resolve(tempDir)) {
            throw new Error('Unexpected catastrophic error');
          }
          return defaultFsAdapter.openSync(p, flags, mode);
        },
      };
      assert.throws(
        () => atomicPersistTrustStoreWithAdapter(filePath, store.toData(), unexpectedAdapter),
        (err) => err instanceof ArcError && err.code === 'INTERNAL_ERROR',
      );
    });

    test('Parent directory write integrity enforcement fails before writing temporary state', () => {
      if (process.platform === 'win32') return;

      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({ clientId: 'c1', clientType: 't1', pin: samplePin(0x11) });

      // 1. Group/world writable parent directory
      const insecureDir = path.join(tempDir, 'insecure-dir');
      fs.mkdirSync(insecureDir, { mode: 0o777 });
      fs.chmodSync(insecureDir, 0o777);
      const insecureTarget = path.join(insecureDir, 'devices.json');

      assert.throws(
        () => store.saveToFile(insecureTarget),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );
      // Ensure no temp file was left behind
      assert.equal(fs.readdirSync(insecureDir).length, 0);

      // 2. Symlink parent directory
      const realDir = path.join(tempDir, 'real-parent');
      fs.mkdirSync(realDir, { mode: 0o700 });
      const symlinkDir = path.join(tempDir, 'symlink-parent');
      fs.symlinkSync(realDir, symlinkDir);
      const symlinkTarget = path.join(symlinkDir, 'devices.json');

      assert.throws(
        () => store.saveToFile(symlinkTarget),
        (err) => err instanceof ArcError && err.code === 'UNSAFE_SYMLINK',
      );
      assert.equal(fs.readdirSync(realDir).length, 0);
    });

    test('Public API does not expose filesystem adapter or bypass seams (§16.1)', () => {
      // 1. Module exports check: @cesspace-arc/auth must not export adapter interfaces/defaults
      assert.equal(PublicAuth.TrustStoreFsAdapter, undefined);
      assert.equal(PublicAuth.defaultFsAdapter, undefined);
      assert.equal(PublicAuth.verifyTrustStoreFileIntegrityWithAdapter, undefined);
      assert.equal(PublicAuth.atomicPersistTrustStoreWithAdapter, undefined);

      // 2. Parameter arity check: production API signatures take only domain arguments
      assert.equal(
        PublicAuth.DeviceTrustStore.loadFromFile.length,
        1,
        'loadFromFile accepts only filePath',
      );
      assert.equal(
        PublicAuth.DeviceTrustStore.prototype.saveToFile.length,
        1,
        'saveToFile accepts only filePath',
      );
      assert.equal(
        PublicAuth.verifyTrustStoreFileIntegrity.length,
        1,
        'verifyTrustStoreFileIntegrity accepts only filePath',
      );
      assert.equal(
        PublicAuth.atomicPersistTrustStore.length,
        2,
        'atomicPersistTrustStore accepts only filePath and data',
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Duplicate Enrollment & Revocation Semantics (§8)
  // ---------------------------------------------------------------------------
  describe('5. Duplicate Enrollment & Revocation Semantics (§8)', () => {
    test('Same pin with same clientId reuses existing deviceId', () => {
      const store = DeviceTrustStore.createEmpty();
      const pin = samplePin(0x42);

      const res1 = store.enrollDevice({
        clientId: 'agent-1',
        clientType: 'cli',
        pin,
        displayLabel: 'Label 1',
      });
      assert.equal(res1.reconnected, false);

      const res2 = store.enrollDevice({
        clientId: 'agent-1',
        clientType: 'cli',
        pin,
        displayLabel: 'Label 2',
      });
      assert.equal(res2.reconnected, true);
      assert.equal(res2.device.deviceId, res1.device.deviceId);
      assert.equal(store.getDeviceCount(), 1);
    });

    test('Same pin with different clientId is rejected', () => {
      const store = DeviceTrustStore.createEmpty();
      const pin = samplePin(0x42);

      store.enrollDevice({
        clientId: 'agent-alice',
        clientType: 'cli',
        pin,
      });

      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'agent-bob',
            clientType: 'cli',
            pin,
          }),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
      assert.equal(store.getDeviceCount(), 1);
    });

    test('Revocation marks device revoked and survives restart/persistence', () => {
      const filePath = path.join(tempDir, 'devices.json');
      const store = DeviceTrustStore.createEmpty();
      const pin = samplePin(0x33);

      const { device } = store.enrollDevice({
        clientId: 'agent-rev',
        clientType: 'cli',
        pin,
      });

      assert.equal(store.isDeviceRevoked(device.deviceId), false);

      // Revoke device
      store.revokeDevice(device.deviceId);
      assert.equal(store.isDeviceRevoked(device.deviceId), true);

      // Persist and reload
      store.saveToFile(filePath);
      const reloaded = DeviceTrustStore.loadFromFile(filePath);

      assert.equal(reloaded.isDeviceRevoked(device.deviceId), true);
      assert.equal(reloaded.findDeviceById(device.deviceId)?.revoked, true);
      assert.equal(reloaded.findDeviceByPin(pin)?.revoked, true);
    });

    test('Strict closed schema rejects unknown fields in root and device objects', () => {
      const invalidRoot = {
        version: 1,
        devices: [],
        extraRootField: 'unauthorized',
      };
      assert.throws(
        () => validateTrustStoreData(invalidRoot),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      const invalidDevice = {
        version: 1,
        devices: [
          {
            deviceId: generateDeviceId(),
            clientId: 'c1',
            clientType: 't1',
            pins: [samplePin(0x11)],
            enrolledAt: new Date().toISOString(),
            displayLabel: '',
            revoked: false,
            injectedField: 'malicious',
          },
        ],
      };
      assert.throws(
        () => validateTrustStoreData(invalidDevice),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Comprehensive Identity & Filesystem Invariants
  // ---------------------------------------------------------------------------
  describe('6. Comprehensive Identity & Filesystem Invariants', () => {
    test('One clientId may have multiple devices with distinct deviceIds and pins', () => {
      const store = DeviceTrustStore.createEmpty();
      const pinA = samplePin(0xa1);
      const pinB = samplePin(0xb2);

      const resA = store.enrollDevice({
        clientId: 'multi-client',
        clientType: 'worker',
        pin: pinA,
      });

      const resB = store.enrollDevice({
        clientId: 'multi-client',
        clientType: 'worker',
        pin: pinB,
      });

      assert.equal(store.getDeviceCount(), 2);
      assert.notEqual(resA.device.deviceId, resB.device.deviceId);
      assert.equal(resA.device.clientId, 'multi-client');
      assert.equal(resB.device.clientId, 'multi-client');
      assert.equal(store.findDeviceByPin(pinA)?.deviceId, resA.device.deviceId);
      assert.equal(store.findDeviceByPin(pinB)?.deviceId, resB.device.deviceId);
    });

    test('Removing sole active pin from a device is rejected (cannot have empty pin set)', () => {
      const store = DeviceTrustStore.createEmpty();
      const pin = samplePin(0x55);

      const { device } = store.enrollDevice({
        clientId: 'c1',
        clientType: 't1',
        pin,
      });

      assert.throws(
        () => store.removePinFromDevice(device.deviceId, pin),
        (err) => err instanceof ArcError && err.code === 'INVALID_REQUEST_SCHEMA',
      );

      // Pin remains intact
      assert.deepEqual(store.findDeviceById(device.deviceId)?.pins, [pin]);
    });

    test('Operations on non-existent device fail with DEVICE_NOT_ENROLLED', () => {
      const store = DeviceTrustStore.createEmpty();
      const fakeId = generateDeviceId();
      const pin = samplePin(0x66);

      assert.throws(
        () => store.addPinToDevice(fakeId, pin),
        (err) => err instanceof ArcError && err.code === 'DEVICE_NOT_ENROLLED',
      );

      assert.throws(
        () => store.removePinFromDevice(fakeId, pin),
        (err) => err instanceof ArcError && err.code === 'DEVICE_NOT_ENROLLED',
      );

      assert.throws(
        () => store.revokeDevice(fakeId),
        (err) => err instanceof ArcError && err.code === 'DEVICE_NOT_ENROLLED',
      );
    });

    test('Parent directory group or world writable is rejected (§16.1)', () => {
      if (process.platform === 'win32') return;

      const subDir = path.join(tempDir, 'insecure-parent');
      fs.mkdirSync(subDir, { mode: 0o777 });
      const storeFile = path.join(subDir, 'devices.json');
      fs.writeFileSync(storeFile, JSON.stringify({ version: 1, devices: [] }), { mode: 0o600 });

      // Insecure parent directory mode (0777 has 0022 bits)
      fs.chmodSync(subDir, 0o777);
      assert.throws(
        () => DeviceTrustStore.loadFromFile(storeFile),
        (err) => err instanceof ArcError && err.code === 'ACCESS_DENIED',
      );

      // Secure parent directory mode (0700 has no 0022 bits)
      fs.chmodSync(subDir, 0o700);
      assert.doesNotThrow(() => DeviceTrustStore.loadFromFile(storeFile));
    });

    test('Loading non-existent trust store file throws FILE_NOT_FOUND', () => {
      const missingPath = path.join(tempDir, 'does-not-exist.json');
      assert.throws(
        () => DeviceTrustStore.loadFromFile(missingPath),
        (err) => err instanceof ArcError && err.code === 'FILE_NOT_FOUND',
      );
    });
  });
});
