/**
 * CesSpace ARC — RC-06 Task 8 Authoritative Negative Controls Acceptance Suite
 *
 * Owns the final secrecy hardening controls:
 * - RC06-NEG-100: Session token secrecy (disk scan, key/free-text redaction, no hash oracle)
 * - RC06-NEG-101: Enrollment / Authorization secrecy (central redaction, Bearer credentials)
 * - RC06-NEG-102: PEM private key and certificate secrecy under innocent and sensitive keys
 * - RC06-NEG-103: Environment variable values secrecy and minimization
 * - RC06-NEG-104: Absolute host workspace paths redaction (POSIX and Windows)
 *
 * Also executes the authoritative meta-acceptance check over all 108 frozen RC-06
 * negative controls (RC06-NEG-01..108) across their reviewed owner suites.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ACTIVE_SEGMENT_FILENAME,
  AuditLogger,
  canonicalJson,
  computeRecordHashV1,
  computeSha256,
  openAuditRuntime,
  verifyOfflineStore,
} from '../packages/audit/dist/index.js';
import { getAuditWriteAuthority } from '../apps/mcp-server/dist/audit-write-authority.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..');

let tempRoot;
const openRuntimes = [];

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task8-neg-'));
});

after(async () => {
  for (const runtime of openRuntimes.reverse()) {
    try {
      await runtime.close();
    } catch {
      // ignore
    }
  }
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function makeTestSetup(label) {
  const fixture = createAuditConfig(tempRoot, label);
  return fixture;
}

describe('CesSpace ARC — RC-06 Task 8 Negative Controls (RC06-NEG-100..104)', () => {
  test('RC06-NEG-100: session token secrecy (disk scan, no raw token, no hash oracle)', async () => {
    const fixture = makeTestSetup('neg100');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const logger = new AuditLogger();
    const authority = getAuditWriteAuthority(logger);
    authority.bindDurableRuntime(runtime);

    // Synthetic session token generated at runtime
    const rawSessionToken = crypto.randomBytes(32).toString('hex');
    const fakeRawTokenOracleHash = computeSha256(rawSessionToken);

    await authority.write({
      timestamp: new Date().toISOString(),
      actor: {
        clientId: 'agent-100',
        clientType: 'cli',
        deviceId: 'dev-100',
        sessionId: 'sess-100',
      },
      target: { workspaceId: 'ws-100', workspacePath: '' },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: {
          path: 'README.md',
          arcSessionToken: rawSessionToken, // under sensitive key
          notes: `Arc-Session-Token: ${rawSessionToken}`, // free text value pattern
          secondaryNote: `session_token=${rawSessionToken}`, // free text value pattern
        },
        payloadHash: fakeRawTokenOracleHash, // caller supplies raw secret oracle hash!
      },
      policy: { decision: 'ALLOW', ruleId: 'rule-100', evaluationDurationMs: 1 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 1,
      },
    });

    // 1. Inspect actual durable JSONL on disk
    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    assert.equal(fs.existsSync(activePath), true, 'active segment must exist on disk');
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // 2. Raw token bytes MUST NOT appear in durable file
    assert.equal(
      diskContent.includes(rawSessionToken),
      false,
      'RC06-NEG-100: raw session token bytes must be absent from persistent JSONL',
    );

    // 3. Raw-secret hash oracle MUST NOT appear in durable file
    assert.equal(
      diskContent.includes(fakeRawTokenOracleHash),
      false,
      'RC06-NEG-100: raw token hash oracle must never survive persistence',
    );

    // 4. Validate parsed persisted record
    const lines = diskContent.trim().split('\n');
    assert.equal(lines.length, 1);
    const persisted = JSON.parse(lines[0]);

    // Token under sensitive key is [REDACTED_BY_NAME]
    assert.equal(persisted.invocation.parametersRedacted.arcSessionToken, '[REDACTED_BY_NAME]');
    // Token embedded in free text is [REDACTED_SECRET]
    assert.equal(persisted.invocation.parametersRedacted.notes, '[REDACTED_SECRET]');
    assert.equal(persisted.invocation.parametersRedacted.secondaryNote, '[REDACTED_SECRET]');

    // 5. Invariant: payloadHash must equal SHA256 of canonical sanitized parameters
    const expectedPayloadHash = computeSha256(
      canonicalJson(persisted.invocation.parametersRedacted),
    );
    assert.equal(persisted.invocation.payloadHash, expectedPayloadHash);
    assert.notEqual(persisted.invocation.payloadHash, fakeRawTokenOracleHash);

    // 6. Invariant: recordHash matches canonical V1 hash
    const expectedRecordHash = computeRecordHashV1(persisted);
    assert.equal(persisted.integrity.recordHash, expectedRecordHash);

    // 7. Store verification succeeds
    const offlineResult = await verifyOfflineStore({
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
    });
    assert.equal(offlineResult.status, 'VERIFIED');
  });

  test('RC06-NEG-101: enrollment and authorization secrecy (central redaction, Bearer credentials)', async () => {
    const fixture = makeTestSetup('neg101');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const logger = new AuditLogger();
    const authority = getAuditWriteAuthority(logger);
    authority.bindDurableRuntime(runtime);

    // Synthetic secrets
    const rawEnrollmentSecret = `enroll-sec-${crypto.randomBytes(16).toString('hex')}`;
    const rawBearerToken = `bearer-cred-${crypto.randomBytes(24).toString('base64url')}`;
    const rawEnrollmentHash = computeSha256(rawEnrollmentSecret);
    const rawBearerHash = computeSha256(rawBearerToken);

    await authority.write({
      timestamp: new Date().toISOString(),
      actor: {
        clientId: 'agent-101',
        clientType: 'cli',
        deviceId: 'dev-101',
        sessionId: 'sess-101',
      },
      target: { workspaceId: 'ws-101', workspacePath: '' },
      invocation: {
        toolName: 'enroll_device',
        parametersRedacted: {
          enrollmentSecret: rawEnrollmentSecret, // sensitive key
          httpHeader: `Authorization: Bearer ${rawBearerToken}`, // free text authorization header
          customHeader: `Bearer ${rawBearerToken}`, // standalone bearer under innocent key
          details: `enrollment-secret: ${rawEnrollmentSecret}`, // free text enrollment pattern
        },
        payloadHash: rawEnrollmentHash, // malicious caller-supplied oracle hash
      },
      policy: { decision: 'ALLOW', ruleId: 'rule-101', evaluationDurationMs: 1 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 1,
      },
    });

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // Raw secrets must be absent from disk bytes
    assert.equal(
      diskContent.includes(rawEnrollmentSecret),
      false,
      'raw enrollment secret must not persist',
    );
    assert.equal(diskContent.includes(rawBearerToken), false, 'raw bearer token must not persist');
    assert.equal(
      diskContent.includes(rawEnrollmentHash),
      false,
      'enrollment secret hash oracle must not persist',
    );
    assert.equal(
      diskContent.includes(rawBearerHash),
      false,
      'bearer token hash oracle must not persist',
    );

    const persisted = JSON.parse(diskContent.trim());
    assert.equal(persisted.invocation.parametersRedacted.enrollmentSecret, '[REDACTED_BY_NAME]');
    assert.equal(persisted.invocation.parametersRedacted.httpHeader, '[REDACTED_SECRET]');
    assert.equal(persisted.invocation.parametersRedacted.customHeader, '[REDACTED_SECRET]');
    assert.equal(persisted.invocation.parametersRedacted.details, '[REDACTED_SECRET]');

    // Authoritative payloadHash equals SHA256 of central sanitized parameters
    const expectedPayloadHash = computeSha256(
      canonicalJson(persisted.invocation.parametersRedacted),
    );
    assert.equal(persisted.invocation.payloadHash, expectedPayloadHash);
    assert.notEqual(persisted.invocation.payloadHash, rawEnrollmentHash);

    // Chain verification succeeds
    const offlineResult = await verifyOfflineStore({
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
    });
    assert.equal(offlineResult.status, 'VERIFIED');
  });

  test('RC06-NEG-102: PEM private key and certificate secrecy under innocent and sensitive keys', async () => {
    const fixture = makeTestSetup('neg102');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const logger = new AuditLogger();
    const authority = getAuditWriteAuthority(logger);
    authority.bindDurableRuntime(runtime);

    // Generate real Ed25519 keypair and self-signed cert for dynamic test fixture
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const rawPrivateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const rawCertificatePem = [
      '-----BEGIN CERTIFICATE-----',
      'MIIBVTCB+wIJALre0X123456MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNVBAMMCHNl',
      'cnZlci0xMB4XDTI2MDkwMTAwMDAwMFoXDTM2MDkwMTAwMDAwMFowEzERMA8GA1UE',
      'AwwIc2VydmVyLTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARX123456789012',
      '3456789012345678901234567890123456789012345678901234567890123456',
      '-----END CERTIFICATE-----',
    ].join('\n');

    const rawKeyHash = computeSha256(rawPrivateKeyPem);
    const rawCertHash = computeSha256(rawCertificatePem);

    await authority.write({
      timestamp: new Date().toISOString(),
      actor: {
        clientId: 'agent-102',
        clientType: 'cli',
        deviceId: 'dev-102',
        sessionId: 'sess-102',
      },
      target: { workspaceId: 'ws-102', workspacePath: '' },
      invocation: {
        toolName: 'crypto_op',
        parametersRedacted: {
          privateKey: rawPrivateKeyPem, // sensitive key name
          innocentFieldNotes: `Key: ${rawPrivateKeyPem}`, // innocent key name
          description: `Cert: ${rawCertificatePem}`, // innocent key name
        },
        payloadHash: rawKeyHash, // raw secret oracle hash supplied
      },
      policy: { decision: 'ALLOW', ruleId: 'rule-102', evaluationDurationMs: 1 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 1,
      },
    });

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // Zero raw PEM bytes in persistent JSONL
    assert.equal(
      diskContent.includes('-----BEGIN PRIVATE KEY-----'),
      false,
      'zero PEM private key bytes',
    );
    assert.equal(
      diskContent.includes('-----END PRIVATE KEY-----'),
      false,
      'zero PEM private key end bytes',
    );
    assert.equal(
      diskContent.includes('-----BEGIN CERTIFICATE-----'),
      false,
      'zero PEM certificate bytes',
    );
    assert.equal(
      diskContent.includes('-----END CERTIFICATE-----'),
      false,
      'zero PEM certificate end bytes',
    );
    assert.equal(diskContent.includes(rawKeyHash), false, 'zero raw key hash oracle');
    assert.equal(diskContent.includes(rawCertHash), false, 'zero raw cert hash oracle');

    const persisted = JSON.parse(diskContent.trim());
    assert.equal(persisted.invocation.parametersRedacted.privateKey, '[REDACTED_BY_NAME]');
    assert.equal(
      persisted.invocation.parametersRedacted.innocentFieldNotes.trim(),
      'Key: [REDACTED_SECRET]',
    );
    assert.equal(
      persisted.invocation.parametersRedacted.description.trim(),
      'Cert: [REDACTED_SECRET]',
    );

    // Authoritative payloadHash check
    const expectedPayloadHash = computeSha256(
      canonicalJson(persisted.invocation.parametersRedacted),
    );
    assert.equal(persisted.invocation.payloadHash, expectedPayloadHash);
    assert.notEqual(persisted.invocation.payloadHash, rawKeyHash);

    // Chain verification succeeds
    const offlineResult = await verifyOfflineStore({
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
    });
    assert.equal(offlineResult.status, 'VERIFIED');
  });

  test('RC06-NEG-103: environment variable values secrecy and minimization', async () => {
    const fixture = makeTestSetup('neg103');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const logger = new AuditLogger();
    const authority = getAuditWriteAuthority(logger);
    authority.bindDurableRuntime(runtime);

    const rawEnvSecret1 = `super_secret_db_pass_${crypto.randomBytes(8).toString('hex')}`;
    const rawEnvSecret2 = `api_token_val_${crypto.randomBytes(8).toString('hex')}`;
    const rawEnvHash = computeSha256(rawEnvSecret1);

    await authority.write({
      timestamp: new Date().toISOString(),
      actor: {
        clientId: 'agent-103',
        clientType: 'cli',
        deviceId: 'dev-103',
        sessionId: 'sess-103',
      },
      target: { workspaceId: 'ws-103', workspacePath: '' },
      invocation: {
        toolName: 'run_command',
        parametersRedacted: {
          executable: 'node',
          env: {
            DB_PASSWORD: rawEnvSecret1,
            API_TOKEN: rawEnvSecret2,
            NODE_ENV: 'production',
          },
          stdout: `output leaked ${rawEnvSecret1}`, // accidental stdout copy
          stderr: `error trace ${rawEnvSecret2}`, // accidental stderr copy
        },
        payloadHash: rawEnvHash,
      },
      policy: { decision: 'ALLOW', ruleId: 'rule-103', evaluationDurationMs: 1 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 1,
      },
    });

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // Values must never appear in persistent JSONL
    assert.equal(diskContent.includes(rawEnvSecret1), false, 'raw env secret 1 must not persist');
    assert.equal(diskContent.includes(rawEnvSecret2), false, 'raw env secret 2 must not persist');
    assert.equal(diskContent.includes(rawEnvHash), false, 'raw env hash oracle must not persist');

    const persisted = JSON.parse(diskContent.trim());
    // env object keys retained, values sanitized to fixed placeholder
    assert.deepEqual(persisted.invocation.parametersRedacted.env, {
      DB_PASSWORD: '[REDACTED_ENV_VALUE]',
      API_TOKEN: '[REDACTED_ENV_VALUE]',
      NODE_ENV: '[REDACTED_ENV_VALUE]',
    });
    // stdout and stderr minimized
    assert.match(persisted.invocation.parametersRedacted.stdout, /^\[OUTPUT_OMITTED: \d+ bytes\]$/);
    assert.match(persisted.invocation.parametersRedacted.stderr, /^\[OUTPUT_OMITTED: \d+ bytes\]$/);

    // payloadHash derived strictly from sanitized parameters
    const expectedPayloadHash = computeSha256(
      canonicalJson(persisted.invocation.parametersRedacted),
    );
    assert.equal(persisted.invocation.payloadHash, expectedPayloadHash);
    assert.notEqual(persisted.invocation.payloadHash, rawEnvHash);

    // Verification succeeds
    const offlineResult = await verifyOfflineStore({
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
    });
    assert.equal(offlineResult.status, 'VERIFIED');
  });

  test('RC06-NEG-104: absolute host workspace paths redaction (POSIX and Windows)', async () => {
    const fixture = makeTestSetup('neg104');
    const runtime = await openAuditRuntime(fixture);
    openRuntimes.push(runtime);

    const logger = new AuditLogger();
    const authority = getAuditWriteAuthority(logger);
    authority.bindDurableRuntime(runtime);

    const rawPosixPath = '/home/cesspace/projects/secret_client_work/src/file.ts';
    const rawWindowsPathBackslash = 'C:\\Users\\cesspace\\secret_project\\config.json';
    const rawWindowsPathSlash = 'C:/Users/cesspace/secret_project/config.json';
    const rawPosixHash = computeSha256(rawPosixPath);

    await authority.write({
      timestamp: new Date().toISOString(),
      actor: {
        clientId: 'agent-104',
        clientType: 'cli',
        deviceId: 'dev-104',
        sessionId: 'sess-104',
      },
      target: {
        workspaceId: 'ws-104',
        workspacePath: rawPosixPath, // raw host path in target
      },
      invocation: {
        toolName: 'read_file',
        parametersRedacted: {
          path: rawPosixPath,
          windowsRef1: rawWindowsPathBackslash,
          windowsRef2: rawWindowsPathSlash,
          note: `Opened file at ${rawPosixPath} and backup at ${rawWindowsPathBackslash}`,
        },
        payloadHash: rawPosixHash,
      },
      policy: { decision: 'ALLOW', ruleId: 'rule-104', evaluationDurationMs: 1 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 1,
      },
    });

    const activePath = path.join(fixture.directory, ACTIVE_SEGMENT_FILENAME);
    const diskContent = fs.readFileSync(activePath, 'utf8');

    // Zero raw host path text survives
    assert.equal(diskContent.includes(rawPosixPath), false, 'raw POSIX path must not persist');
    assert.equal(
      diskContent.includes(rawWindowsPathBackslash),
      false,
      'raw Windows backslash path must not persist',
    );
    assert.equal(
      diskContent.includes(rawWindowsPathSlash),
      false,
      'raw Windows slash path must not persist',
    );

    const persisted = JSON.parse(diskContent.trim());
    // target.workspacePath is empty string, workspaceRootHash is retained
    assert.equal(persisted.target.workspacePath, '');
    assert.equal(persisted.target.workspaceRootHash, rawPosixHash);

    // Free text paths replaced with [REDACTED_PATH]
    assert.equal(persisted.invocation.parametersRedacted.path, '[REDACTED_PATH]');
    assert.equal(persisted.invocation.parametersRedacted.windowsRef1, '[REDACTED_PATH]');
    assert.equal(persisted.invocation.parametersRedacted.windowsRef2, '[REDACTED_PATH]');
    assert.equal(
      persisted.invocation.parametersRedacted.note,
      'Opened file at [REDACTED_PATH] and backup at [REDACTED_PATH]',
    );

    // payloadHash derived strictly from sanitized parameters
    const expectedPayloadHash = computeSha256(
      canonicalJson(persisted.invocation.parametersRedacted),
    );
    assert.equal(persisted.invocation.payloadHash, expectedPayloadHash);

    // Verification succeeds
    const offlineResult = await verifyOfflineStore({
      directory: fixture.directory,
      checkpointPublicKeyPath: fixture.publicKeyPath,
    });
    assert.equal(offlineResult.status, 'VERIFIED');
  });

  test('Authoritative Meta-Acceptance: exactly 108 contiguous unique RC06-NEG controls without gaps or duplicates', () => {
    const AUTHORITATIVE_SUITES = [
      'tests/rc06-storage.test.js',
      'tests/rc06-recovery.test.js',
      'tests/rc06-rotation.test.js',
      'tests/rc06-checkpoint.test.js',
      'tests/rc06-anchor.test.js',
      'tests/rc06-runtime-durability.test.js',
      'tests/rc06-cli-verifier.test.js',
      'tests/rc06-negative-controls.test.js',
    ];

    const testDeclarationPattern =
      /(?:test|it)\s*\(\s*['"`](RC06-NEG-(?:0[1-9]|[1-9][0-9]|10[0-8])):\s/g;
    const forbiddenSkipPattern = new RegExp('\\b(?:test|it|describe)\\.' + '(?:skip|todo)\\b');

    const foundDeclarations = new Map();

    for (const relPath of AUTHORITATIVE_SUITES) {
      const fullPath = path.join(REPO_ROOT, relPath);
      assert.equal(fs.existsSync(fullPath), true, `Authoritative suite ${relPath} must exist`);
      const fileContent = fs.readFileSync(fullPath, 'utf8');

      // Check no skipped or deferred tests
      assert.equal(
        forbiddenSkipPattern.test(fileContent),
        false,
        `Suite ${relPath} must not contain skipped or deferred tests`,
      );

      // Extract test declarations
      let match;
      while ((match = testDeclarationPattern.exec(fileContent)) !== null) {
        const id = match[1];
        if (!foundDeclarations.has(id)) {
          foundDeclarations.set(id, []);
        }
        foundDeclarations.get(id).push(relPath);
      }
    }

    // Assert exact 108 controls RC06-NEG-01..108
    assert.equal(
      foundDeclarations.size,
      108,
      `Must have exactly 108 unique controls; found ${foundDeclarations.size}`,
    );

    const missingIds = [];
    const duplicateIds = [];

    for (let i = 1; i <= 108; i += 1) {
      const expectedId = `RC06-NEG-${String(i).padStart(i < 100 ? 2 : 3, '0')}`;
      const locations = foundDeclarations.get(expectedId);

      if (!locations || locations.length === 0) {
        missingIds.push(expectedId);
      } else if (locations.length > 1) {
        duplicateIds.push({ id: expectedId, locations });
      }
    }

    assert.deepEqual(missingIds, [], `Missing negative controls: ${missingIds.join(', ')}`);
    assert.deepEqual(
      duplicateIds,
      [],
      `Duplicate negative controls: ${JSON.stringify(duplicateIds)}`,
    );
  });
});
