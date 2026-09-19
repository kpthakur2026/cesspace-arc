/**
 * CesSpace ARC — RC-05 Task 2: Enrollment Administration over Local Admin IPC
 *
 * Covers the authenticated local admin channel extensions for pending
 * enrollment (`enrollment.create`, `enrollment.cancel`), the RC05-NEG-33..37
 * controls at the admin-IPC level, and the strict closed request schema.
 *
 * The channel under test is the SAME RC-04 Ed25519 challenge-response Unix
 * socket channel. Task 2 adds no listener, no transport, and no second
 * authentication mechanism.
 */

import { test, describe, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { once } from 'node:events';

import {
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { ApprovalStateManager } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { EnrollmentManager } from '../packages/auth/dist/index.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';

let tempRoot;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-enroll-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function makeSecureDir(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyB64: exportPublicKeyB64(publicKey) };
}

/** Canonical SPKI pin shape. */
function pin(seed) {
  return crypto.createHash('sha256').update(`admin-pin-${seed}`, 'utf8').digest('hex');
}

function readOneFrame(socket, maxBytes) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > maxBytes) {
        cleanup();
        reject(new Error('frame exceeded bound'));
        return;
      }
      const idx = buffer.indexOf(0x0a);
      if (idx !== -1) {
        cleanup();
        resolve(buffer.subarray(0, idx));
      }
    };
    const onEnd = () => {
      cleanup();
      reject(new Error('connection ended before a frame arrived'));
    };
    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('end', onEnd);
      socket.removeListener('error', onEnd);
    };
    socket.on('data', onData);
    socket.on('end', onEnd);
    socket.on('error', onEnd);
  });
}

function buildEnvelope(privateKey, challenge, method, params = {}) {
  const canonical = encodeAdminPayload({
    protocol: ADMIN_PROTOCOL_VERSION,
    challengeId: challenge.challengeId,
    method,
    params,
  });
  const payloadBytes = Buffer.from(canonical, 'utf8');
  const signature = signAdminPayload(
    privateKey,
    challenge.challengeId,
    challenge.nonce,
    payloadBytes,
  );
  return {
    payload: payloadBytes.toString('base64'),
    signature: signature.toString('base64'),
  };
}

/** One-shot authenticated request. */
async function adminRequest(endpoint, privateKey, method, params = {}) {
  const socket = net.createConnection(endpoint);
  await once(socket, 'connect');
  const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));
  socket.write(`${JSON.stringify(buildEnvelope(privateKey, challenge, method, params))}\n`);
  const frame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(frame.toString('utf8'));
}

/** Sends an arbitrary raw envelope, for tampering cases. */
async function adminRawEnvelope(endpoint, envelope) {
  const socket = net.createConnection(endpoint);
  await once(socket, 'connect');
  await readOneFrame(socket, 4096); // challenge
  socket.write(`${JSON.stringify(envelope)}\n`);
  const frame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(frame.toString('utf8'));
}

describe('CesSpace ARC — RC-05 Task 2: Enrollment Admin IPC', () => {
  let dir;
  let endpoint;
  let operator;
  let manager;
  let enrollmentManager;
  let audit;
  let server;

  before(async () => {
    dir = makeSecureDir('enroll');
    endpoint = path.join(dir, 'admin.sock');
    operator = generateOperator();
    manager = new ApprovalStateManager();
    enrollmentManager = new EnrollmentManager();
    audit = new AuditLogger();
    server = new AdminIpcServer({
      endpoint,
      operatorPublicKeyB64: operator.publicKeyB64,
      approvalStateManager: manager,
      auditLogger: audit,
      enrollmentManager,
    });
    await server.start();
  });

  after(async () => {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // The shared fixture uses one volatile enrollment manager across cases, so
  // pending state is released between them. Without this, accumulated
  // challenges would eventually trip the 4-per-operator quota and make unrelated
  // cases depend on execution order.
  afterEach(() => {
    enrollmentManager.clear();
  });

  // =========================================================================
  // enrollment.create
  // =========================================================================

  describe('enrollment.create', () => {
    test('RC05-NEG-33d: creation returns an identifier and a one-time secret exactly once', async () => {
      const response = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        spkiPin: pin('create'),
      });

      assert.equal(response.ok, true);
      assert.match(response.result.enrollment.enrollmentId, /^[0-9a-f]{32}$/);
      assert.match(response.result.secret, /^[0-9a-f]{64}$/);
      assert.equal(response.result.enrollment.clientId, 'agent-alpha');
      assert.equal(response.result.enrollment.clientType, 'claude-code');
      assert.equal(response.result.enrollment.spkiPin, pin('create'));
      assert.equal(response.result.enrollment.remainingSeconds, 300);

      // The secret is not available from any later read.
      const listed = enrollmentManager.list();
      assert.ok(!JSON.stringify(listed).includes(response.result.secret));
      assert.equal(
        enrollmentManager.get(response.result.enrollment.enrollmentId).failedAttempts,
        0,
      );
    });

    test('RC05-NEG-33e: the one-time secret never reaches the audit chain or an error body', async () => {
      const response = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'audit-client',
        clientType: 'claude-code',
        spkiPin: pin('audit'),
      });
      assert.equal(response.ok, true);
      const secret = response.result.secret;

      const serializedAudit = JSON.stringify(audit.getRecords());
      assert.ok(!serializedAudit.includes(secret), 'raw secret must never be audited');
      assert.ok(
        !serializedAudit.includes(crypto.createHash('sha256').update(secret, 'utf8').digest('hex')),
        'the secret digest must never be audited either',
      );

      // A failed request around the same challenge discloses nothing.
      const failure = await adminRequest(endpoint, operator.privateKey, 'enrollment.cancel', {
        enrollmentId: 'f'.repeat(32),
      });
      assert.equal(failure.ok, false);
      assert.ok(!JSON.stringify(failure).includes(secret));
      assert.equal(failure.error.code, 'NOT_FOUND_OR_NOT_PENDING');
    });

    test('RC05-NEG-33s: the create response has exactly the declared closed shape', async () => {
      const response = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'shape-client',
        clientType: 'claude-code',
        spkiPin: pin('shape'),
        displayLabel: 'shape-label',
      });

      assert.equal(response.ok, true);
      // Exact key sets, asserted against the real wire response rather than a
      // TypeScript type. Extra internal fields must not leak by spreading.
      assert.deepEqual(Object.keys(response).sort(), ['ok', 'result']);
      assert.deepEqual(Object.keys(response.result).sort(), ['enrollment', 'secret']);
      assert.deepEqual(Object.keys(response.result.enrollment).sort(), [
        'clientId',
        'clientType',
        'createdAt',
        'displayLabel',
        'enrollmentId',
        'expiresAt',
        'remainingSeconds',
        'spkiPin',
      ]);

      // Internal state must be absent from the serialized response.
      const serialized = JSON.stringify(response);
      for (const leaked of ['failedAttempts', 'operatorId', 'secretDigest', 'monotonicDeadline']) {
        assert.ok(!serialized.includes(leaked), `${leaked} must not appear in the response`);
      }
      // The secret appears exactly once, as its own top-level field.
      assert.match(response.result.secret, /^[0-9a-f]{64}$/);
      assert.equal(JSON.stringify(response).split(response.result.secret).length - 1, 1);
    });

    test('RC05-NEG-33f: a display label is bounded and optional', async () => {
      const withLabel = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'labelled',
        clientType: 'claude-code',
        spkiPin: pin('label'),
        displayLabel: 'workstation-7',
      });
      assert.equal(withLabel.ok, true);
      assert.equal(withLabel.result.enrollment.displayLabel, 'workstation-7');

      const tooLong = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'labelled',
        clientType: 'claude-code',
        spkiPin: pin('label2'),
        displayLabel: 'x'.repeat(65),
      });
      assert.equal(tooLong.ok, false);
      assert.equal(tooLong.error.code, 'INVALID_ADMIN_REQUEST');
    });
  });

  // =========================================================================
  // Strict closed request schema
  // =========================================================================

  describe('Strict request schema', () => {
    test('RC05-NEG-33g: missing required parameters are rejected', async () => {
      const cases = [
        { clientType: 'claude-code', spkiPin: pin('m1') },
        { clientId: 'x', spkiPin: pin('m2') },
        { clientId: 'x', clientType: 'claude-code' },
        {},
      ];
      for (const params of cases) {
        const response = await adminRequest(
          endpoint,
          operator.privateKey,
          'enrollment.create',
          params,
        );
        assert.equal(response.ok, false, JSON.stringify(params));
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }
    });

    test('RC05-NEG-33h: caller-supplied server-derived fields cannot reach the server', async () => {
      const base = { clientId: 'x', clientType: 'claude-code', spkiPin: pin('derived') };
      const notInClosedSet = [
        'deviceId',
        'operatorId',
        'secret',
        'ttl',
        'expiresAt',
        'failedAttempts',
        'monotonicDeadline',
      ];

      // The canonical encoder is driven by the closed parameter key set, so a
      // key outside it is not transmitted at all: it cannot be smuggled through
      // a well-formed client.
      for (const key of notInClosedSet) {
        const encoded = encodeAdminPayload({
          protocol: ADMIN_PROTOCOL_VERSION,
          challengeId: 'a'.repeat(32),
          method: 'enrollment.create',
          params: { ...base, [key]: 'injected' },
        });
        assert.ok(!encoded.includes(key), `${key} must not appear in the canonical payload`);
      }

      // `enrollmentId` IS part of the closed parameter set, because
      // `enrollment.cancel` needs it. On `enrollment.create` it is therefore
      // transmitted and then explicitly refused by the method's own schema.
      const withEnrollmentId = await adminRequest(
        endpoint,
        operator.privateKey,
        'enrollment.create',
        { ...base, enrollmentId: 'a'.repeat(32) },
      );
      assert.equal(withEnrollmentId.ok, false);
      assert.equal(withEnrollmentId.error.code, 'INVALID_ADMIN_REQUEST');

      // A hand-crafted payload that DOES carry one is rejected after the
      // signature verifies: it is not canonical, so it never reaches dispatch.
      const before = enrollmentManager.list().length;
      const socket = net.createConnection(endpoint);
      await once(socket, 'connect');
      const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));
      const handCrafted = `{"challengeId":${JSON.stringify(challenge.challengeId)},"method":"enrollment.create","params":{"clientId":"x","clientType":"c","deviceId":"${'b'.repeat(32)}","spkiPin":${JSON.stringify(pin('derived'))}},"protocol":${JSON.stringify(ADMIN_PROTOCOL_VERSION)}}`;
      const payloadBytes = Buffer.from(handCrafted, 'utf8');
      const signature = signAdminPayload(
        operator.privateKey,
        challenge.challengeId,
        challenge.nonce,
        payloadBytes,
      );
      socket.write(
        `${JSON.stringify({ payload: payloadBytes.toString('base64'), signature: signature.toString('base64') })}\n`,
      );
      const frame = await readOneFrame(socket, 8 * 1024 * 1024);
      socket.destroy();
      const response = JSON.parse(frame.toString('utf8'));

      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      assert.equal(enrollmentManager.list().length, before, 'no state may be created');
    });

    test('RC05-NEG-33i: malformed values are rejected without creating state', async () => {
      const before = enrollmentManager.list().length;
      const cases = [
        { clientId: '', clientType: 'c', spkiPin: pin('m') },
        { clientId: 'x', clientType: '', spkiPin: pin('m') },
        { clientId: 'x', clientType: 'c', spkiPin: 'A'.repeat(64) },
        { clientId: 'x', clientType: 'c', spkiPin: 'a'.repeat(63) },
      ];
      for (const params of cases) {
        const response = await adminRequest(
          endpoint,
          operator.privateKey,
          'enrollment.create',
          params,
        );
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }
      assert.equal(enrollmentManager.list().length, before, 'no pending state may be created');
    });

    test('RC05-NEG-33j: enrollment parameters are rejected on approval methods', async () => {
      const requestId = 'a'.repeat(32);
      const methods = [
        'approvals.list',
        'approvals.inspect',
        'approval.approve',
        'approval.reject',
      ];
      for (const method of methods) {
        const response = await adminRequest(endpoint, operator.privateKey, method, {
          ...(method === 'approvals.list' ? {} : { requestId }),
          spkiPin: pin('cross'),
        });
        assert.equal(response.ok, false, `${method} must reject enrollment parameters`);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }

      // ...and approval parameters are rejected on enrollment methods.
      const crossed = await adminRequest(endpoint, operator.privateKey, 'enrollment.cancel', {
        enrollmentId: 'a'.repeat(32),
        reason: 'nope',
      });
      assert.equal(crossed.ok, false);
      assert.equal(crossed.error.code, 'INVALID_ADMIN_REQUEST');
    });
  });

  // =========================================================================
  // Authentication precedes parsing and state access
  // =========================================================================

  describe('Authentication ordering', () => {
    test('RC05-NEG-33k: an unauthenticated request cannot create an enrollment', async () => {
      const attacker = generateOperator();
      const before = enrollmentManager.list().length;

      const proper = await adminRequest(endpoint, attacker.privateKey, 'enrollment.create', {
        clientId: 'x',
        clientType: 'c',
        spkiPin: pin('attacker'),
      });
      assert.equal(proper.ok, false);
      assert.equal(proper.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(enrollmentManager.list().length, before, 'no state may be created');
    });

    test('RC05-NEG-33l: a tampered payload is rejected before any state access', async () => {
      const before = enrollmentManager.list().length;

      const socket = net.createConnection(endpoint);
      await once(socket, 'connect');
      const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));
      const envelope = buildEnvelope(operator.privateKey, challenge, 'enrollment.create', {
        clientId: 'tampered',
        clientType: 'c',
        spkiPin: pin('tamper'),
      });

      // Re-encode a different payload while keeping the original signature.
      const forged = Buffer.from(
        encodeAdminPayload({
          protocol: ADMIN_PROTOCOL_VERSION,
          challengeId: challenge.challengeId,
          method: 'enrollment.create',
          params: { clientId: 'attacker', clientType: 'c', spkiPin: pin('forged') },
        }),
        'utf8',
      ).toString('base64');

      socket.write(`${JSON.stringify({ payload: forged, signature: envelope.signature })}\n`);
      const frame = await readOneFrame(socket, 8 * 1024 * 1024);
      socket.destroy();
      const response = JSON.parse(frame.toString('utf8'));

      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(enrollmentManager.list().length, before);
    });

    test('RC05-NEG-33m: non-canonical encodings of the same request are rejected', async () => {
      const socket = net.createConnection(endpoint);
      await once(socket, 'connect');
      const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));

      // Same values, different key order: the signature covers canonical bytes.
      const nonCanonical = `{"challengeId":${JSON.stringify(challenge.challengeId)},"method":"enrollment.create","params":{"spkiPin":${JSON.stringify(pin('nc'))},"clientId":"nc","clientType":"c"},"protocol":${JSON.stringify(ADMIN_PROTOCOL_VERSION)}}`;
      const payloadBytes = Buffer.from(nonCanonical, 'utf8');
      const signature = signAdminPayload(
        operator.privateKey,
        challenge.challengeId,
        challenge.nonce,
        payloadBytes,
      );
      socket.write(
        `${JSON.stringify({ payload: payloadBytes.toString('base64'), signature: signature.toString('base64') })}\n`,
      );
      const frame = await readOneFrame(socket, 8 * 1024 * 1024);
      socket.destroy();
      const response = JSON.parse(frame.toString('utf8'));

      // The signature verifies over exactly these bytes, so the request is
      // authenticated but not canonical: it is refused before dispatch.
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
    });

    test('RC05-NEG-33n: an empty or malformed envelope is rejected', async () => {
      // Envelope-shape and encoding faults are malformed requests.
      for (const envelope of [
        {},
        { payload: '' },
        { signature: '' },
        { payload: '!!!', signature: '!!!' },
      ]) {
        const response = await adminRawEnvelope(endpoint, envelope);
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST', JSON.stringify(envelope));
      }

      // A well-formed envelope with a wrong signature is an authentication failure.
      const validPayload = Buffer.from(
        encodeAdminPayload({
          protocol: ADMIN_PROTOCOL_VERSION,
          challengeId: 'a'.repeat(32),
          method: 'enrollment.create',
          params: { clientId: 'x', clientType: 'c', spkiPin: pin('wrongsig') },
        }),
        'utf8',
      ).toString('base64');
      const badSignature = await adminRawEnvelope(endpoint, {
        payload: validPayload,
        signature: Buffer.alloc(64, 0).toString('base64'),
      });
      assert.equal(badSignature.ok, false);
      assert.equal(badSignature.error.code, 'AUTHENTICATION_FAILED');
    });
  });

  // =========================================================================
  // RC05-NEG-37 over the admin channel
  // =========================================================================

  describe('RC05-NEG-37 (admin-IPC coverage)', () => {
    test('RC05-NEG-37d: quota refusal is RESOURCE_EXHAUSTED and preserves existing state', async () => {
      // Dedicated server so the shared fixture's pending state is unaffected.
      const quotaDir = makeSecureDir('quota');
      const quotaEndpoint = path.join(quotaDir, 'admin.sock');
      const quotaEnrollments = new EnrollmentManager();
      const quotaServer = new AdminIpcServer({
        endpoint: quotaEndpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: new ApprovalStateManager(),
        auditLogger: new AuditLogger(),
        enrollmentManager: quotaEnrollments,
      });
      await quotaServer.start();
      try {
        const created = [];
        for (let i = 0; i < 4; i++) {
          const response = await adminRequest(
            quotaEndpoint,
            operator.privateKey,
            'enrollment.create',
            {
              clientId: `quota-${i}`,
              clientType: 'c',
              spkiPin: pin(`quota-${i}`),
            },
          );
          assert.equal(response.ok, true, `creation ${i} must succeed`);
          created.push(response.result.enrollment.enrollmentId);
        }
        const snapshot = JSON.stringify(quotaEnrollments.list());

        const refused = await adminRequest(
          quotaEndpoint,
          operator.privateKey,
          'enrollment.create',
          {
            clientId: 'quota-overflow',
            clientType: 'c',
            spkiPin: pin('quota-overflow'),
          },
        );
        assert.equal(refused.ok, false);
        assert.equal(refused.error.code, 'RESOURCE_EXHAUSTED');
        assert.equal(JSON.stringify(quotaEnrollments.list()), snapshot, 'state must be unchanged');

        // Cancelling one releases quota.
        const cancelled = await adminRequest(
          quotaEndpoint,
          operator.privateKey,
          'enrollment.cancel',
          {
            enrollmentId: created[0],
          },
        );
        assert.equal(cancelled.ok, true);
        assert.equal(cancelled.result.state, 'CANCELLED');

        const admitted = await adminRequest(
          quotaEndpoint,
          operator.privateKey,
          'enrollment.create',
          {
            clientId: 'quota-after-cancel',
            clientType: 'c',
            spkiPin: pin('quota-after-cancel'),
          },
        );
        assert.equal(admitted.ok, true);
      } finally {
        await quotaServer.stop();
        fs.rmSync(quotaDir, { recursive: true, force: true });
      }
    });
  });

  // =========================================================================
  // enrollment.cancel
  // =========================================================================

  describe('enrollment.cancel', () => {
    test('RC05-NEG-33o: cancellation removes the challenge and its secret becomes unusable', async () => {
      const created = await adminRequest(endpoint, operator.privateKey, 'enrollment.create', {
        clientId: 'cancel-me',
        clientType: 'c',
        spkiPin: pin('cancel'),
      });
      assert.equal(created.ok, true);
      const { enrollmentId } = created.result.enrollment;

      const cancelled = await adminRequest(endpoint, operator.privateKey, 'enrollment.cancel', {
        enrollmentId,
      });
      assert.equal(cancelled.ok, true);
      assert.equal(cancelled.result.enrollmentId, enrollmentId);
      assert.equal(cancelled.result.state, 'CANCELLED');

      assert.equal(enrollmentManager.get(enrollmentId), undefined);
      assert.equal(
        enrollmentManager.verifyAndConsumeBySpki(
          created.result.enrollment.spkiPin,
          created.result.secret,
        ).ok,
        false,
      );
    });

    test('RC05-NEG-33p: cancelling an unknown or malformed identifier is not an oracle', async () => {
      for (const enrollmentId of ['0'.repeat(32), 'f'.repeat(32)]) {
        const response = await adminRequest(endpoint, operator.privateKey, 'enrollment.cancel', {
          enrollmentId,
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'NOT_FOUND_OR_NOT_PENDING');
        assert.equal(response.result, undefined);
        assert.equal(response.error.message, undefined, 'no message field may be disclosed');
      }

      // Malformed identifiers are a schema rejection, not a lookup.
      for (const enrollmentId of ['A'.repeat(32), 'a'.repeat(31), 'zz', '']) {
        const response = await adminRequest(endpoint, operator.privateKey, 'enrollment.cancel', {
          enrollmentId,
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }
    });
  });

  // =========================================================================
  // RC-04 regression: the approval surface is unchanged
  // =========================================================================

  describe('RC-04 approval surface regression', () => {
    test('RC05-NEG-33q: existing approval methods still function unchanged', async () => {
      manager.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'agent-alpha', clientType: 'claude-code' },
          workspace: { workspaceId: 'primary', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        },
        reviewMaterial: '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n',
      });

      const listed = await adminRequest(endpoint, operator.privateKey, 'approvals.list', {});
      assert.equal(listed.ok, true);
      assert.equal(listed.result.approvals.length, 1);

      const requestId = listed.result.approvals[0].requestId;
      const approved = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
        requestId,
      });
      assert.equal(approved.ok, true);
      assert.match(approved.result.token, /^[0-9a-f]{64}$/);

      // The approval token never enters enrollment state or the audit chain.
      const serializedAudit = JSON.stringify(audit.getRecords());
      assert.ok(!serializedAudit.includes(approved.result.token));
      assert.ok(!JSON.stringify(enrollmentManager.list()).includes(approved.result.token));
    });

    test('RC05-NEG-33r: the admin method set stays closed', async () => {
      for (const method of ['enrollment.delete', 'enrollment.list', 'device.enroll', 'admin']) {
        const response = await adminRequest(endpoint, operator.privateKey, method, {});
        assert.equal(response.ok, false, `${method} must not be accepted`);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }
    });
  });
});
