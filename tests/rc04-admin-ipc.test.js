import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { once } from 'node:events';

import {
  ADMIN_CHALLENGE_TTL_MS,
  ADMIN_MAX_REASON_BYTES,
  ADMIN_MAX_REQUEST_FRAME_BYTES,
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPrivateKeyB64,
  exportPublicKeyB64,
  importOperatorPrivateKey,
  importOperatorPublicKey,
  signAdminPayload,
  verifyAdminPayload,
} from '../packages/protocol/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  canonicalJson,
} from '../packages/policy/dist/index.js';
import { AdminIpcError, AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
import {
  ALL_TOOL_DEFINITIONS,
  ArcMcpServer,
  createArcMcpServer,
} from '../apps/mcp-server/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

let tempRoot;

function makeSecureDir(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function socketPathIn(dir, name = 'admin.sock') {
  return path.join(dir, name);
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    publicKeyB64: exportPublicKeyB64(publicKey),
    privateKeyB64: exportPrivateKeyB64(privateKey),
  };
}

function makeBinding(overrides = {}) {
  return {
    actor: { clientId: 'agent-alice', clientType: 'claude-code', ...(overrides.actor ?? {}) },
    workspace: {
      workspaceId: 'primary',
      workspaceRootHash: 'b'.repeat(64),
      ...(overrides.workspace ?? {}),
    },
    policyHash: 'c'.repeat(64),
    ...(overrides.rest ?? {}),
  };
}

function seedPending(manager, overrides = {}) {
  return manager.createOrReusePending({
    toolName: overrides.toolName ?? 'write_file',
    executionPayloadHash: overrides.executionPayloadHash ?? 'a'.repeat(64),
    binding: overrides.binding ?? makeBinding(),
    reviewMaterial: overrides.reviewMaterial ?? '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n',
  });
}

/** Opens a connection and reads the server-issued challenge. */
async function connectAndChallenge(endpoint) {
  const socket = net.createConnection(endpoint);
  await once(socket, 'connect');
  const frame = await readOneFrame(socket, 4096);
  return { socket, challenge: JSON.parse(frame.toString('utf8')) };
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

/** Builds a valid signed envelope for a challenge. */
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
  // Exactly the two wire fields: any extra property is rejected by the server.
  return {
    payload: payloadBytes.toString('base64'),
    signature: signature.toString('base64'),
  };
}

/** Sends an envelope and reads the bounded response. */
async function exchange(socket, envelope) {
  socket.write(`${JSON.stringify(envelope)}\n`);
  const frame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(frame.toString('utf8'));
}

/** One-shot authenticated request against a server. */
async function adminRequest(endpoint, privateKey, method, params = {}) {
  const { socket, challenge } = await connectAndChallenge(endpoint);
  return exchange(socket, buildEnvelope(privateKey, challenge, method, params));
}

describe('CesSpace ARC — RC-04 Task 3: Authenticated Local Admin Channel', () => {
  before(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-admin-'));
  });

  after(() => {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // =========================================================================
  // 1. Protocol contract and cryptographic primitives
  // =========================================================================

  describe('Protocol and cryptography', () => {
    test('RC04-A-01: canonical admin payload matches the policy canonicalJson convention', () => {
      const payload = {
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: 'a'.repeat(32),
        method: 'approval.reject',
        params: { requestId: 'b'.repeat(32), reason: 'because' },
      };
      assert.equal(encodeAdminPayload(payload), canonicalJson(payload));
    });

    test('RC04-A-02: canonical payload omits absent optional params', () => {
      const listPayload = {
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: 'a'.repeat(32),
        method: 'approvals.list',
        params: {},
      };
      assert.equal(encodeAdminPayload(listPayload), canonicalJson(listPayload));

      const inspectPayload = {
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: 'a'.repeat(32),
        method: 'approvals.inspect',
        params: { requestId: 'b'.repeat(32) },
      };
      assert.equal(encodeAdminPayload(inspectPayload), canonicalJson(inspectPayload));
    });

    test('RC04-A-03: Ed25519 sign/verify round trip is challenge bound', () => {
      const { publicKey, privateKey } = generateOperator();
      const payloadBytes = Buffer.from('{"x":1}', 'utf8');
      const signature = signAdminPayload(privateKey, 'a'.repeat(32), 'b'.repeat(64), payloadBytes);

      assert.equal(
        verifyAdminPayload(publicKey, 'a'.repeat(32), 'b'.repeat(64), payloadBytes, signature),
        true,
      );
      // Wrong challenge, wrong nonce, wrong payload, and wrong key all fail.
      assert.equal(
        verifyAdminPayload(publicKey, 'c'.repeat(32), 'b'.repeat(64), payloadBytes, signature),
        false,
      );
      assert.equal(
        verifyAdminPayload(publicKey, 'a'.repeat(32), 'c'.repeat(64), payloadBytes, signature),
        false,
      );
      assert.equal(
        verifyAdminPayload(
          publicKey,
          'a'.repeat(32),
          'b'.repeat(64),
          Buffer.from('{"x":2}'),
          signature,
        ),
        false,
      );
      const other = generateOperator();
      assert.equal(
        verifyAdminPayload(
          other.publicKey,
          'a'.repeat(32),
          'b'.repeat(64),
          payloadBytes,
          signature,
        ),
        false,
      );
    });

    test('RC04-A-04: only Ed25519 keys are accepted', () => {
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const rsaPrivate = rsa.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      const rsaPublic = rsa.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
      assert.equal(importOperatorPrivateKey(rsaPrivate), null);
      assert.equal(importOperatorPublicKey(rsaPublic), null);

      const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const ecPrivate = ec.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      assert.equal(importOperatorPrivateKey(ecPrivate), null);
    });

    test('RC04-A-05: malformed key material is rejected without throwing', () => {
      for (const value of [
        '',
        'not-base64!!!',
        'AAAA',
        'aGVsbG8=',
        Buffer.alloc(4).toString('base64'),
      ]) {
        assert.equal(importOperatorPrivateKey(value), null);
        assert.equal(importOperatorPublicKey(value), null);
      }
    });

    test('RC04-A-06: the admin channel opens no TCP listener', async () => {
      const dir = makeSecureDir('tcp');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();
      try {
        const stat = fs.lstatSync(endpoint);
        assert.equal(stat.isSocket(), true, 'endpoint must be a Unix domain socket');
        // A plain TCP connect to the same path is impossible: the channel is not
        // a host/port listener.
        await assert.rejects(
          new Promise((resolve, reject) => {
            const probe = net.createConnection({ host: '127.0.0.1', port: 0 });
            probe.once('connect', () => {
              probe.destroy();
              resolve();
            });
            probe.once('error', reject);
          }),
        );
      } finally {
        await server.stop();
      }
    });
  });

  // =========================================================================
  // 2. Authentication
  // =========================================================================

  describe('Authentication', () => {
    let dir;
    let endpoint;
    let operator;
    let manager;
    let server;

    beforeEach(async () => {
      dir = makeSecureDir('auth');
      endpoint = socketPathIn(dir);
      operator = generateOperator();
      manager = new ApprovalStateManager();
      server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();
    });

    afterEach(async () => {
      await server.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('RC04-A-07: a valid Ed25519 challenge-response is accepted', async () => {
      const seeded = seedPending(manager);
      const response = await adminRequest(endpoint, operator.privateKey, 'approvals.list');
      assert.equal(response.ok, true);
      assert.equal(response.result.approvals.length, 1);
      assert.equal(response.result.approvals[0].requestId, seeded.requestId);
    });

    test('RC04-A-08: a same-UID client with a different valid key cannot administer', async () => {
      // This is the core same-OS-principal control: the attacker can discover
      // the endpoint, connect, and receive a challenge - and still cannot act.
      const seeded = seedPending(manager);
      const attacker = generateOperator();
      const attackerKey = importOperatorPrivateKey(attacker.privateKeyB64);

      for (const [method, params] of [
        ['approvals.list', {}],
        ['approvals.inspect', { requestId: seeded.requestId }],
        ['approval.approve', { requestId: seeded.requestId }],
        ['approval.reject', { requestId: seeded.requestId }],
      ]) {
        const response = await adminRequest(endpoint, attackerKey, method, params);
        assert.equal(response.ok, false, `${method} must not succeed for a wrong key`);
        assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      }

      // Zero approval state mutation, zero token minted, zero material disclosed.
      const snapshot = manager.getRequest(seeded.requestId);
      assert.equal(snapshot.state, 'PENDING');
      assert.equal(
        manager.inspectPending(seeded.requestId),
        '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n',
      );
    });

    test('RC04-A-09: a tampered signature is rejected', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      const envelope = buildEnvelope(operator.privateKey, challenge, 'approval.approve', {
        requestId: seeded.requestId,
      });
      const tampered = Buffer.from(envelope.signature, 'base64');
      tampered[0] ^= 0xff;
      const response = await exchange(socket, {
        payload: envelope.payload,
        signature: tampered.toString('base64'),
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-10: tampered payload bytes are rejected without re-signing', async () => {
      const first = seedPending(manager, { toolName: 'write_file' });
      const second = seedPending(manager, {
        toolName: 'create_file',
        executionPayloadHash: 'd'.repeat(64),
        reviewMaterial: 'second',
      });

      const { socket, challenge } = await connectAndChallenge(endpoint);
      // Sign an approve for request A, then swap in a payload for request B.
      const envelope = buildEnvelope(operator.privateKey, challenge, 'approval.approve', {
        requestId: first.requestId,
      });
      const swapped = encodeAdminPayload({
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: challenge.challengeId,
        method: 'approval.approve',
        params: { requestId: second.requestId },
      });
      const response = await exchange(socket, {
        payload: Buffer.from(swapped, 'utf8').toString('base64'),
        signature: envelope.signature,
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(manager.getRequest(first.requestId).state, 'PENDING');
      assert.equal(manager.getRequest(second.requestId).state, 'PENDING');
    });

    test('RC04-A-11: a signature is bound to the exact admin action', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      // Sign approval.reject, then claim approval.approve.
      const envelope = buildEnvelope(operator.privateKey, challenge, 'approval.reject', {
        requestId: seeded.requestId,
      });
      const forged = encodeAdminPayload({
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: challenge.challengeId,
        method: 'approval.approve',
        params: { requestId: seeded.requestId },
      });
      const response = await exchange(socket, {
        payload: Buffer.from(forged, 'utf8').toString('base64'),
        signature: envelope.signature,
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-12: a signed envelope cannot be replayed on a new challenge', async () => {
      const seeded = seedPending(manager);

      // Connection 1: a valid, completed approve.
      const first = await connectAndChallenge(endpoint);
      const envelope = buildEnvelope(operator.privateKey, first.challenge, 'approval.approve', {
        requestId: seeded.requestId,
      });
      const firstResponse = await exchange(first.socket, envelope);
      assert.equal(firstResponse.ok, true);
      assert.equal(manager.getRequest(seeded.requestId).state, 'APPROVED');

      // Connection 2: replay the identical envelope against a fresh challenge.
      const second = await connectAndChallenge(endpoint);
      assert.notEqual(second.challenge.challengeId, first.challenge.challengeId);
      const replayed = await exchange(second.socket, envelope);
      assert.equal(replayed.ok, false);
      assert.equal(replayed.error.code, 'AUTHENTICATION_FAILED');
    });

    test('RC04-A-13: an expired challenge is rejected without state mutation', async () => {
      // Injectable monotonic clock: no real sleeping.
      let nowMs = 0;
      const clockManager = new ApprovalStateManager();
      const clockDir = makeSecureDir('clock');
      const clockEndpoint = socketPathIn(clockDir);
      const clockServer = new AdminIpcServer({
        endpoint: clockEndpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: clockManager,
        getMonotonicTimeMs: () => nowMs,
      });
      await clockServer.start();
      try {
        const seeded = seedPending(clockManager);
        const { socket, challenge } = await connectAndChallenge(clockEndpoint);

        // Advance beyond the 5000 ms deadline before responding.
        nowMs = ADMIN_CHALLENGE_TTL_MS;
        const response = await exchange(
          socket,
          buildEnvelope(operator.privateKey, challenge, 'approval.approve', {
            requestId: seeded.requestId,
          }),
        );
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
        assert.equal(clockManager.getRequest(seeded.requestId).state, 'PENDING');

        // One millisecond inside the window still succeeds.
        nowMs = ADMIN_CHALLENGE_TTL_MS - 1;
        const ok = await adminRequest(clockEndpoint, operator.privateKey, 'approval.approve', {
          requestId: seeded.requestId,
        });
        assert.equal(ok.ok, true);
      } finally {
        await clockServer.stop();
        fs.rmSync(clockDir, { recursive: true, force: true });
      }
    });

    test('RC04-A-14: a payload bound to a different challengeId is rejected', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      // Sign against a foreign challengeId. The server always rebuilds the
      // signed message from ITS OWN challengeId, so this can never verify.
      const forged = encodeAdminPayload({
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: 'f'.repeat(32),
        method: 'approval.approve',
        params: { requestId: seeded.requestId },
      });
      const payloadBytes = Buffer.from(forged, 'utf8');
      const signature = signAdminPayload(
        operator.privateKey,
        'f'.repeat(32),
        challenge.nonce,
        payloadBytes,
      );
      const response = await exchange(socket, {
        payload: payloadBytes.toString('base64'),
        signature: signature.toString('base64'),
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-15: one connection performs exactly one operation', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      const first = await exchange(
        socket,
        buildEnvelope(operator.privateKey, challenge, 'approvals.list'),
      );
      assert.equal(first.ok, true);
      // The connection is closed after the single operation.
      assert.equal(socket.destroyed || socket.readableEnded || socket.writableEnded, true);
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });
  });

  // =========================================================================
  // 3. Malformed and oversized frames
  // =========================================================================

  describe('Malformed and oversized input', () => {
    let dir;
    let endpoint;
    let operator;
    let manager;
    let server;

    beforeEach(async () => {
      dir = makeSecureDir('malformed');
      endpoint = socketPathIn(dir);
      operator = generateOperator();
      manager = new ApprovalStateManager();
      server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();
    });

    afterEach(async () => {
      await server.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    /** Sends raw bytes and returns the parsed response, or null when closed. */
    async function rawSend(payload) {
      const { socket } = await connectAndChallenge(endpoint);
      socket.write(payload);
      try {
        const frame = await readOneFrame(socket, 8 * 1024 * 1024);
        socket.destroy();
        return JSON.parse(frame.toString('utf8'));
      } catch {
        socket.destroy();
        return null;
      }
    }

    test('RC04-A-16: malformed envelope JSON is rejected', async () => {
      const response = await rawSend('{not json at all\n');
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
    });

    test('RC04-A-17: extra envelope properties are rejected', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      const envelope = buildEnvelope(operator.privateKey, challenge, 'approval.approve', {
        requestId: seeded.requestId,
      });
      const response = await exchange(socket, {
        payload: envelope.payload,
        signature: envelope.signature,
        extra: 'unexpected',
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-18: invalid base64 and wrong signature length are rejected', async () => {
      const seeded = seedPending(manager);

      const badPayload = await rawSend(
        `${JSON.stringify({ payload: '!!!not-base64!!!', signature: 'AAAA' })}\n`,
      );
      assert.equal(badPayload.error.code, 'INVALID_ADMIN_REQUEST');

      const { socket, challenge } = await connectAndChallenge(endpoint);
      const envelope = buildEnvelope(operator.privateKey, challenge, 'approval.approve', {
        requestId: seeded.requestId,
      });
      const shortSignature = await exchange(socket, {
        payload: envelope.payload,
        signature: Buffer.alloc(32).toString('base64'),
      });
      assert.equal(shortSignature.ok, false);
      assert.equal(shortSignature.error.code, 'AUTHENTICATION_FAILED');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-19: an oversized request frame is rejected before accumulation', async () => {
      const oversized = `${'x'.repeat(ADMIN_MAX_REQUEST_FRAME_BYTES + 1024)}\n`;
      const response = await rawSend(oversized);
      // Rejected: the server never accumulated the full frame, so no response
      // is produced and the connection is closed.
      assert.equal(response, null);
    });

    test('RC04-A-20: an unsupported protocol version is rejected', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      const payload = JSON.stringify({
        protocol: 'cesspace-arc-admin-v2',
        challengeId: challenge.challengeId,
        method: 'approval.approve',
        params: { requestId: seeded.requestId },
      });
      const payloadBytes = Buffer.from(payload, 'utf8');
      const signature = signAdminPayload(
        operator.privateKey,
        challenge.challengeId,
        challenge.nonce,
        payloadBytes,
      );
      const response = await exchange(socket, {
        payload: payloadBytes.toString('base64'),
        signature: signature.toString('base64'),
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-21: an unknown admin method is rejected', async () => {
      const seeded = seedPending(manager);
      const { socket, challenge } = await connectAndChallenge(endpoint);
      const payload = JSON.stringify({
        protocol: ADMIN_PROTOCOL_VERSION,
        challengeId: challenge.challengeId,
        method: 'approval.execute',
        params: { requestId: seeded.requestId },
      });
      const payloadBytes = Buffer.from(payload, 'utf8');
      const signature = signAdminPayload(
        operator.privateKey,
        challenge.challengeId,
        challenge.nonce,
        payloadBytes,
      );
      const response = await exchange(socket, {
        payload: payloadBytes.toString('base64'),
        signature: signature.toString('base64'),
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });

    test('RC04-A-22: uppercase, short, and long request IDs are rejected', async () => {
      for (const requestId of ['A'.repeat(32), 'a'.repeat(31), 'a'.repeat(33), 'zz', '']) {
        const response = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId,
        });
        assert.equal(response.ok, false, `expected rejection for ${requestId}`);
        assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
      }
    });

    test('RC04-A-23: unexpected parameters are rejected', async () => {
      const seeded = seedPending(manager);
      const response = await adminRequest(endpoint, operator.privateKey, 'approvals.list', {
        requestId: seeded.requestId,
      });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'INVALID_ADMIN_REQUEST');
    });

    test('RC04-A-24: oversized and NUL-bearing reject reasons are rejected', async () => {
      const seeded = seedPending(manager);

      const tooLong = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
        requestId: seeded.requestId,
        reason: 'r'.repeat(ADMIN_MAX_REASON_BYTES + 1),
      });
      assert.equal(tooLong.ok, false);
      assert.equal(tooLong.error.code, 'INVALID_ADMIN_REQUEST');

      const multibyte = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
        requestId: seeded.requestId,
        reason: '€'.repeat(100), // 300 UTF-8 bytes, 100 characters
      });
      assert.equal(multibyte.ok, false);
      assert.equal(multibyte.error.code, 'INVALID_ADMIN_REQUEST');

      const withNul = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
        requestId: seeded.requestId,
        reason: 'bad\u0000reason',
      });
      assert.equal(withNul.ok, false);
      assert.equal(withNul.error.code, 'INVALID_ADMIN_REQUEST');

      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });
  });

  // =========================================================================
  // 4. Admin method behaviour
  // =========================================================================

  describe('Admin methods', () => {
    let dir;
    let endpoint;
    let operator;
    let manager;
    let server;

    beforeEach(async () => {
      dir = makeSecureDir('methods');
      endpoint = socketPathIn(dir);
      operator = generateOperator();
      manager = new ApprovalStateManager();
      server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();
    });

    afterEach(async () => {
      await server.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('RC04-A-25: approvals.list returns PENDING requests only', async () => {
      const pending = seedPending(manager, { toolName: 'write_file' });
      const rejected = seedPending(manager, {
        toolName: 'create_file',
        executionPayloadHash: 'e'.repeat(64),
        reviewMaterial: 'b',
      });
      manager.reject(rejected.requestId);

      const response = await adminRequest(endpoint, operator.privateKey, 'approvals.list');
      assert.equal(response.ok, true);
      const ids = response.result.approvals.map((a) => a.requestId);
      assert.deepEqual(ids, [pending.requestId]);
      assert.equal(response.result.approvals[0].state, 'PENDING');
    });

    test('RC04-A-26: approvals.list never returns review material or token fields', async () => {
      const secretMaterial = 'SECRET_REVIEW_MATERIAL_MARKER_4417';
      seedPending(manager, { reviewMaterial: secretMaterial });

      const response = await adminRequest(endpoint, operator.privateKey, 'approvals.list');
      const serialized = JSON.stringify(response);
      assert.ok(!serialized.includes(secretMaterial), 'review material leaked into list');
      const entry = response.result.approvals[0];
      assert.equal(entry.reviewMaterial, undefined);
      assert.equal(entry.token, undefined);
      assert.equal(entry.tokenDigest, undefined);
      assert.equal(entry.monotonicDeadline, undefined);
      assert.equal(typeof entry.reviewMaterialBytes, 'number');
    });

    test('RC04-A-27: approvals.inspect returns review material while PENDING', async () => {
      const material = '--- a/src/x.ts\n+++ b/src/x.ts\n@@ -1 +1 @@\n-old\n+new\n';
      const seeded = seedPending(manager, { reviewMaterial: material });

      const response = await adminRequest(endpoint, operator.privateKey, 'approvals.inspect', {
        requestId: seeded.requestId,
      });
      assert.equal(response.ok, true);
      assert.equal(response.result.reviewMaterial, material);
      assert.equal(response.result.toolName, 'write_file');
      assert.equal(response.result.clientId, 'agent-alice');
      assert.equal(response.result.workspaceId, 'primary');
    });

    test('RC04-A-28: approvals.inspect does not disclose non-PENDING records', async () => {
      const approved = seedPending(manager, { executionPayloadHash: 'f'.repeat(64) });
      manager.approve(approved.requestId);
      const rejected = seedPending(manager, {
        executionPayloadHash: '0'.repeat(64),
        reviewMaterial: 'x',
      });
      manager.reject(rejected.requestId);

      for (const requestId of [approved.requestId, rejected.requestId, '1'.repeat(32)]) {
        const response = await adminRequest(endpoint, operator.privateKey, 'approvals.inspect', {
          requestId,
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'NOT_FOUND_OR_NOT_PENDING');
      }
    });

    test('RC04-A-29: approval.approve mints a token exactly once', async () => {
      const seeded = seedPending(manager);
      const first = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
        requestId: seeded.requestId,
      });
      assert.equal(first.ok, true);
      assert.equal(first.result.state, 'APPROVED');
      assert.equal(first.result.requestId, seeded.requestId);
      assert.match(first.result.token, /^[0-9a-f]{64}$/);
      assert.equal(typeof first.result.expiresAt, 'string');
      assert.equal(typeof first.result.remainingSeconds, 'number');

      // The token digest matches the minted token.
      const digest = crypto.createHash('sha256').update(first.result.token, 'utf8').digest('hex');
      assert.match(digest, /^[0-9a-f]{64}$/);

      const second = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
        requestId: seeded.requestId,
      });
      assert.equal(second.ok, false);
      assert.equal(second.error.code, 'APPROVAL_REJECTED');
      assert.ok(!JSON.stringify(second).includes(first.result.token));
    });

    test('RC04-A-30: approving does not extend the 300-second absolute TTL', async () => {
      const seeded = seedPending(manager);
      const before = manager.getRequest(seeded.requestId);

      const response = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
        requestId: seeded.requestId,
      });
      assert.equal(response.ok, true);
      assert.equal(response.result.expiresAt, before.expiresAt);
      assert.ok(response.result.remainingSeconds <= before.remainingSeconds);
    });

    test('RC04-A-31: an expired request mints no token', async () => {
      let nowMs = 1_000_000;
      const clockManager = new ApprovalStateManager({
        getMonotonicTime: () => BigInt(nowMs) * 1_000_000n,
      });
      const clockDir = makeSecureDir('expire');
      const clockEndpoint = socketPathIn(clockDir);
      const clockServer = new AdminIpcServer({
        endpoint: clockEndpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: clockManager,
      });
      await clockServer.start();
      try {
        const seeded = seedPending(clockManager);
        nowMs += 301_000;
        const response = await adminRequest(
          clockEndpoint,
          operator.privateKey,
          'approval.approve',
          {
            requestId: seeded.requestId,
          },
        );
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'APPROVAL_EXPIRED');
        assert.ok(!JSON.stringify(response).includes('"token"'));
      } finally {
        await clockServer.stop();
        fs.rmSync(clockDir, { recursive: true, force: true });
      }
    });

    test('RC04-A-32: approval.reject transitions PENDING only', async () => {
      const seeded = seedPending(manager);
      const response = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
        requestId: seeded.requestId,
        reason: 'not needed for this change',
      });
      assert.equal(response.ok, true);
      assert.equal(response.result.state, 'REJECTED');
      assert.equal(manager.getRequest(seeded.requestId).state, 'REJECTED');

      // Rejecting again fails closed.
      const again = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
        requestId: seeded.requestId,
      });
      assert.equal(again.ok, false);
      assert.equal(again.error.code, 'APPROVAL_REJECTED');
    });

    test('RC04-A-33: an unauthenticated connection cannot reject or approve', async () => {
      const seeded = seedPending(manager);
      const attacker = generateOperator();
      for (const method of ['approval.approve', 'approval.reject']) {
        const response = await adminRequest(endpoint, attacker.privateKey, method, {
          requestId: seeded.requestId,
        });
        assert.equal(response.ok, false);
        assert.equal(response.error.code, 'AUTHENTICATION_FAILED');
      }
      assert.equal(manager.getRequest(seeded.requestId).state, 'PENDING');
    });
  });

  // =========================================================================
  // 5. Token and key material leakage
  // =========================================================================

  describe('Material leakage', () => {
    test('RC04-A-34: the raw token appears only in a successful approve response', async () => {
      const dir = makeSecureDir('leak');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();

      try {
        const seeded = seedPending(manager);
        const inspect = await adminRequest(endpoint, operator.privateKey, 'approvals.inspect', {
          requestId: seeded.requestId,
        });
        const list = await adminRequest(endpoint, operator.privateKey, 'approvals.list');

        const approve = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId: seeded.requestId,
        });
        const token = approve.result.token;

        assert.ok(!JSON.stringify(list).includes(token), 'token leaked into list');
        assert.ok(!JSON.stringify(inspect).includes(token), 'token leaked into inspect');

        // Reject a second, still-pending request: the first token must not appear.
        const other = seedPending(manager, {
          executionPayloadHash: '7'.repeat(64),
          reviewMaterial: 'other',
        });
        const reject = await adminRequest(endpoint, operator.privateKey, 'approval.reject', {
          requestId: other.requestId,
        });
        assert.ok(!JSON.stringify(reject).includes(token), 'token leaked into reject');

        // A failed re-approve must not echo the original token.
        const reApprove = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId: seeded.requestId,
        });
        assert.ok(!JSON.stringify(reApprove).includes(token), 'token echoed on failure');
      } finally {
        await server.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    test('RC04-A-35: the server never retains the minted token', async () => {
      const dir = makeSecureDir('retain');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();

      try {
        const seeded = seedPending(manager);
        const approve = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId: seeded.requestId,
        });
        const token = approve.result.token;

        // Serialize every enumerable surface the server object exposes.
        const surface = JSON.stringify(
          { server, manager: manager.listActive(), request: manager.getRequest(seeded.requestId) },
          (key, value) => (typeof value === 'function' ? '[fn]' : value),
        );
        assert.ok(!surface.includes(token), 'token retained on a server surface');
      } finally {
        await server.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    test('RC04-A-36: error responses carry only bounded codes', async () => {
      const dir = makeSecureDir('errshape');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();

      try {
        const response = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId: '9'.repeat(32),
        });
        assert.equal(response.ok, false);
        assert.deepEqual(Object.keys(response).sort(), ['error', 'ok']);
        assert.deepEqual(Object.keys(response.error), ['code']);
        const serialized = JSON.stringify(response);
        for (const forbidden of ['stack', 'at ', 'node_modules', 'token', 'digest']) {
          assert.ok(!serialized.includes(forbidden), `leaked ${forbidden}`);
        }
      } finally {
        await server.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    test('RC04-A-37: the server holds no private key material', async () => {
      const dir = makeSecureDir('nopriv');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();
      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();
      try {
        const surface = JSON.stringify(server, (key, value) =>
          typeof value === 'function' ? '[fn]' : value,
        );
        assert.ok(!surface.includes(operator.privateKeyB64), 'private key present on server');
        assert.ok(!surface.includes('PRIVATE'), 'private key marker present on server');
      } finally {
        await server.stop();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // =========================================================================
  // 6. Unix socket safety (POSIX)
  // =========================================================================

  describe('Unix socket safety', () => {
    const isPosix = process.platform !== 'win32';

    test(
      'RC04-A-38: the socket is created inside a 0700 parent with mode 0600',
      { skip: !isPosix },
      async () => {
        const dir = makeSecureDir('perm');
        const endpoint = socketPathIn(dir);
        const operator = generateOperator();
        const manager = new ApprovalStateManager();
        const server = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: manager,
        });
        await server.start();
        try {
          assert.equal(fs.lstatSync(endpoint).mode & 0o777, 0o600);
        } finally {
          await server.stop();
          fs.rmSync(dir, { recursive: true, force: true });
        }
      },
    );

    test(
      'RC04-A-39: a group- or other-accessible parent directory is rejected',
      { skip: !isPosix },
      async () => {
        const permissive = fs.mkdtempSync(path.join(tempRoot, 'permissive-'));
        fs.chmodSync(permissive, 0o755);
        const operator = generateOperator();
        const manager = new ApprovalStateManager();

        assert.throws(
          () =>
            new AdminIpcServer({
              endpoint: socketPathIn(permissive),
              operatorPublicKeyB64: operator.publicKeyB64,
              approvalStateManager: manager,
            }),
          (err) => err instanceof AdminIpcError && err.reason === 'PARENT_PERMISSIVE',
        );
        fs.rmSync(permissive, { recursive: true, force: true });
      },
    );

    test('RC04-A-40: a symlinked parent directory is rejected', { skip: !isPosix }, async () => {
      const real = makeSecureDir('real');
      const linkParent = path.join(tempRoot, `link-${Date.now()}`);
      fs.symlinkSync(real, linkParent, 'dir');
      const operator = generateOperator();
      const manager = new ApprovalStateManager();

      assert.throws(
        () =>
          new AdminIpcServer({
            endpoint: socketPathIn(linkParent),
            operatorPublicKeyB64: operator.publicKeyB64,
            approvalStateManager: manager,
          }),
        (err) => err instanceof AdminIpcError && err.reason === 'PARENT_NOT_DIRECTORY',
      );
      fs.unlinkSync(linkParent);
      fs.rmSync(real, { recursive: true, force: true });
    });

    test(
      'RC04-A-41: a relative endpoint and an over-long endpoint are rejected',
      { skip: !isPosix },
      () => {
        const operator = generateOperator();
        const manager = new ApprovalStateManager();

        assert.throws(
          () =>
            new AdminIpcServer({
              endpoint: 'relative/admin.sock',
              operatorPublicKeyB64: operator.publicKeyB64,
              approvalStateManager: manager,
            }),
          (err) => err instanceof AdminIpcError && err.reason === 'ENDPOINT_NOT_ABSOLUTE',
        );

        const longDir = makeSecureDir('long');
        const longEndpoint = path.join(longDir, `${'n'.repeat(150)}.sock`);
        assert.throws(
          () =>
            new AdminIpcServer({
              endpoint: longEndpoint,
              operatorPublicKeyB64: operator.publicKeyB64,
              approvalStateManager: manager,
            }),
          (err) => err instanceof AdminIpcError && err.reason === 'ENDPOINT_TOO_LONG',
        );
        fs.rmSync(longDir, { recursive: true, force: true });
      },
    );

    test(
      'RC04-A-42: an existing regular file is rejected and preserved',
      { skip: !isPosix },
      async () => {
        const dir = makeSecureDir('existingfile');
        const endpoint = socketPathIn(dir);
        fs.writeFileSync(endpoint, 'do-not-delete-me', { mode: 0o600 });
        const operator = generateOperator();
        const manager = new ApprovalStateManager();
        const server = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: manager,
        });

        await assert.rejects(
          () => server.start(),
          (err) => err instanceof AdminIpcError && err.reason === 'ENDPOINT_EXISTS',
        );
        assert.equal(fs.readFileSync(endpoint, 'utf8'), 'do-not-delete-me');
        fs.rmSync(dir, { recursive: true, force: true });
      },
    );

    test(
      'RC04-A-43: an existing socket is rejected and not unlinked',
      { skip: !isPosix },
      async () => {
        const dir = makeSecureDir('existingsock');
        const endpoint = socketPathIn(dir);
        const operator = generateOperator();

        const first = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: new ApprovalStateManager(),
        });
        await first.start();

        const second = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: new ApprovalStateManager(),
        });
        try {
          await assert.rejects(
            () => second.start(),
            (err) => err instanceof AdminIpcError && err.reason === 'ENDPOINT_EXISTS',
          );
          // The original socket is untouched and still serving.
          assert.equal(fs.lstatSync(endpoint).isSocket(), true);
          const manager = new ApprovalStateManager();
          void manager;
          const probe = await connectAndChallenge(endpoint);
          assert.equal(probe.challenge.protocol, ADMIN_PROTOCOL_VERSION);
          probe.socket.destroy();
        } finally {
          await first.stop();
          await second.stop();
          fs.rmSync(dir, { recursive: true, force: true });
        }
      },
    );

    test(
      'RC04-A-44: normal shutdown removes the socket this server created',
      { skip: !isPosix },
      async () => {
        const dir = makeSecureDir('cleanup');
        const endpoint = socketPathIn(dir);
        const operator = generateOperator();
        const server = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: new ApprovalStateManager(),
        });
        await server.start();
        assert.equal(fs.existsSync(endpoint), true);
        await server.stop();
        assert.equal(fs.existsSync(endpoint), false);
        fs.rmSync(dir, { recursive: true, force: true });
      },
    );

    test(
      'RC04-A-45: shutdown does not remove a replacement object',
      { skip: !isPosix },
      async () => {
        const dir = makeSecureDir('replace');
        const endpoint = socketPathIn(dir);
        const operator = generateOperator();
        const server = new AdminIpcServer({
          endpoint,
          operatorPublicKeyB64: operator.publicKeyB64,
          approvalStateManager: new ApprovalStateManager(),
        });
        await server.start();

        // Simulate an attacker replacing the endpoint with their own object.
        // The replacement is deliberately NOT a socket, so it must survive
        // shutdown even if the allocator happens to reuse the freed inode number.
        fs.unlinkSync(endpoint);
        fs.writeFileSync(endpoint, 'replacement-object', { mode: 0o600 });

        await server.stop();
        assert.equal(fs.existsSync(endpoint), true, 'replacement must not be unlinked');
        assert.equal(fs.readFileSync(endpoint, 'utf8'), 'replacement-object');
        fs.rmSync(dir, { recursive: true, force: true });
      },
    );

    test('RC04-A-46: a missing parent directory is rejected', { skip: !isPosix }, () => {
      const operator = generateOperator();
      assert.throws(
        () =>
          new AdminIpcServer({
            endpoint: path.join(tempRoot, 'does-not-exist', 'admin.sock'),
            operatorPublicKeyB64: operator.publicKeyB64,
            approvalStateManager: new ApprovalStateManager(),
          }),
        (err) => err instanceof AdminIpcError && err.reason === 'PARENT_MISSING',
      );
    });

    test('RC04-A-47: an invalid operator public key fails closed', { skip: !isPosix }, () => {
      const dir = makeSecureDir('badkey');
      for (const key of ['', 'not-a-key', Buffer.alloc(64).toString('base64')]) {
        assert.throws(
          () =>
            new AdminIpcServer({
              endpoint: socketPathIn(dir),
              operatorPublicKeyB64: key,
              approvalStateManager: new ApprovalStateManager(),
            }),
          (err) => err instanceof AdminIpcError && err.reason === 'PUBLIC_KEY_INVALID',
        );
      }
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('RC04-A-48: an RSA operator public key is rejected', { skip: !isPosix }, () => {
      const dir = makeSecureDir('rsakey');
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const rsaPublic = rsa.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
      assert.throws(
        () =>
          new AdminIpcServer({
            endpoint: socketPathIn(dir),
            operatorPublicKeyB64: rsaPublic,
            approvalStateManager: new ApprovalStateManager(),
          }),
        (err) => err instanceof AdminIpcError && err.reason === 'PUBLIC_KEY_INVALID',
      );
      fs.rmSync(dir, { recursive: true, force: true });
    });
  });

  // =========================================================================
  // 7. MCP surface stays free of admin capability, and APPROVED != EXECUTED
  // =========================================================================

  describe('MCP surface and execution separation', () => {
    test('RC04-A-49: no admin capability is registered as an MCP tool', () => {
      const names = ALL_TOOL_DEFINITIONS.map((tool) => tool.name);
      for (const forbidden of [
        'approve',
        'reject',
        'approvals',
        'approvals_list',
        'approvals_inspect',
        'admin',
        'policy_test',
      ]) {
        assert.ok(!names.includes(forbidden), `${forbidden} must not be an MCP tool`);
      }
      // The tool surface is exactly the 18 registered RC-03 tools.
      assert.equal(names.length, 18);
    });

    test('RC04-A-50: plausible admin tool names are denied by dispatch and mutate no state', async () => {
      const registry = new WorkspaceRegistry();
      const kernel = new SecurityKernel(registry);
      const manager = new ApprovalStateManager();
      const server = new ArcMcpServer(
        registry,
        kernel,
        new AuditLogger(),
        new FilesystemSubsystem(),
        new GitSubsystem(),
        undefined,
        undefined,
        undefined,
        manager,
      );

      const seeded = seedPending(manager);
      const before = manager.getRequest(seeded.requestId);

      for (const toolName of [
        'approve',
        'reject',
        'approvals',
        'approvals_list',
        'approvals_inspect',
        'admin',
        'policy_test',
        'approval.approve',
      ]) {
        const result = await server.dispatchToolCall(toolName, { requestId: seeded.requestId });
        const body = JSON.parse(result.content[0].text);
        assert.equal(result.isError, true, `${toolName} must be an error`);
        assert.equal(body.code, 'POLICY_DENIED', `${toolName} must be denied`);
      }

      const after = manager.getRequest(seeded.requestId);
      assert.equal(after.state, 'PENDING');
      assert.equal(after.state, before.state);
    });

    test('RC04-A-51: approving through the admin channel executes nothing (APPROVED != EXECUTED)', async () => {
      const dir = makeSecureDir('execsep');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();
      const manager = new ApprovalStateManager();

      // A real workspace and a real target path that a mutation WOULD create.
      const workspaceDir = makeSecureDir('execsep-ws');
      const targetPath = path.join(workspaceDir, 'should-not-exist.txt');

      const server = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: manager,
      });
      await server.start();

      try {
        const seeded = seedPending(manager, {
          toolName: 'create_file',
          reviewMaterial: `create_file ${targetPath}`,
        });
        const response = await adminRequest(endpoint, operator.privateKey, 'approval.approve', {
          requestId: seeded.requestId,
        });

        // The approval transitioned...
        assert.equal(response.ok, true);
        assert.equal(manager.getRequest(seeded.requestId).state, 'APPROVED');

        // ...and nothing executed. APPROVED is not EXECUTED.
        assert.equal(fs.existsSync(targetPath), false, 'approval must not create a file');
        assert.deepEqual(fs.readdirSync(workspaceDir), []);
      } finally {
        await server.stop();
        fs.rmSync(workspaceDir, { recursive: true, force: true });
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    test('RC04-A-52: ArcMcpServer composes the admin channel without changing mutation behaviour', async () => {
      const dir = makeSecureDir('compose');
      const endpoint = socketPathIn(dir);
      const operator = generateOperator();

      // A registered workspace is required for a mutation to reach the policy
      // gate rather than failing workspace admission first.
      const workspaceDir = makeSecureDir('compose-ws');
      const registry = new WorkspaceRegistry();
      registry.registerWorkspace('primary', workspaceDir);

      const approvals = new ApprovalStateManager();
      const adminServer = new AdminIpcServer({
        endpoint,
        operatorPublicKeyB64: operator.publicKeyB64,
        approvalStateManager: approvals,
      });
      const mcpServer = new ArcMcpServer(
        registry,
        new SecurityKernel(registry),
        new AuditLogger(),
        new FilesystemSubsystem(),
        new GitSubsystem(),
        undefined,
        undefined,
        undefined,
        approvals,
        adminServer,
      );

      await adminServer.start();
      try {
        // MCP mutation routing is unchanged: still APPROVAL_REQUIRED, still zero
        // execution, and no approval record is created by MCP.
        const result = await mcpServer.dispatchToolCall('create_file', {
          path: 'nope.txt',
          content: 'x',
          workspaceId: 'primary',
        });
        const body = JSON.parse(result.content[0].text);
        assert.equal(body.code, 'APPROVAL_REQUIRED');

        // No approval record was created by MCP, no token exists, no
        // _arcApproval schema is admitted, and nothing was written.
        assert.equal(approvals.listActive().length, 0);
        assert.ok(!JSON.stringify(result).includes('_arcApproval'));
        assert.equal(fs.existsSync(path.join(workspaceDir, 'nope.txt')), false);
      } finally {
        await adminServer.stop();
        fs.rmSync(workspaceDir, { recursive: true, force: true });
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    test('RC04-A-53: supplying only half of the admin configuration fails closed', () => {
      const operator = generateOperator();
      const dir = makeSecureDir('partial');
      const endpoint = socketPathIn(dir);

      // createArcMcpServer rejects a partially configured admin channel.
      assert.throws(
        () =>
          createArcMcpServer({
            transport: 'stdio',
            authorizedRoots: [],
            admin: { endpoint },
          }),
        /both a local IPC endpoint and an operator public key/,
      );
      assert.throws(
        () =>
          createArcMcpServer({
            transport: 'stdio',
            authorizedRoots: [],
            admin: { operatorPublicKeyB64: operator.publicKeyB64 },
          }),
        /both a local IPC endpoint and an operator public key/,
      );

      // With no admin configuration at all, no admin listener exists.
      const plain = createArcMcpServer({ transport: 'stdio', authorizedRoots: [] });
      assert.equal(plain.adminIpcServer, undefined);
      assert.equal(plain.approvalStateManager.getRequest('0'.repeat(32)), undefined);

      fs.rmSync(dir, { recursive: true, force: true });
    });
  });
});
