/**
 * CesSpace ARC — RC-05 Task 4: Enrollment Completion Bootstrap Endpoint
 *
 * Covers the frozen remote bootstrap contract (rc05-scope-acceptance.md §5.1,
 * §5.2, §9 E-4, §9.1, §12 step 4, §25.1) and the Task-4 negative controls
 * RC05-NEG-29, 30, 31, 32, 38, plus HTTP-level regressions for the Task-2
 * controls RC05-NEG-33..36 across `/enroll/complete`.
 *
 * Every case drives REAL protocol surfaces: the REAL authenticated local admin
 * IPC socket for enrollment creation and the REAL TLS 1.3 mTLS listener for
 * completion. All X.509 material is generated ephemerally into a temporary
 * directory and removed with it; no certificate, key, or trust store is
 * committed and no scanner suppression is used.
 *
 * The ONLY injected seam is the internal durable-write adapter used to prove the
 * atomic-activation rollback. It is a gateway constructor option and is
 * unreachable from ArcServerConfig, RemoteConfig, the environment, and the
 * network.
 */

import { test, describe, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { once } from 'node:events';

import {
  ADMIN_PROTOCOL_VERSION,
  encodeAdminPayload,
  exportPublicKeyB64,
  signAdminPayload,
} from '../packages/protocol/dist/index.js';
import { DeviceTrustStore, deriveSpkiPin, EnrollmentManager } from '../packages/auth/dist/index.js';
import { RemoteGateway } from '../apps/mcp-server/dist/remote-gateway.js';
import { AdminIpcServer } from '../apps/mcp-server/dist/admin-ipc.js';
import { ApprovalStateManager } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { createEmptyTrustStore, createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

let tempRoot;
let pki;
let publicHostname;
/** Canonical SPKI pin of the primary ephemeral client certificate. */
let clientPin;
/** DER-independent trust root bytes, read once. */
let trustedCaPem;

before(() => {
  // The suite generates its own X.509 material rather than shipping fixtures,
  // so a missing platform tool is a hard environment failure, not a skip.
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 Task 4 generates ephemeral certificates and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-bootstrap-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  publicHostname = 'localhost';
  trustedCaPem = fs.readFileSync(pki.trustedCaCertPath);
  clientPin = deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

// ===========================================================================
// Fixtures and protocol helpers
// ===========================================================================

let storeCounter = 0;

/** A fresh, valid, mode-0600, EMPTY trust store on disk. */
function freshStore(tag) {
  storeCounter += 1;
  return createEmptyTrustStore(tempRoot, `devices-${tag}-${storeCounter}.json`);
}

/** A fresh 0700 directory for an admin IPC endpoint. */
function freshAdminDir(tag) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `admin-${tag}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

/** A free TCP port, obtained by binding and releasing port 0. */
async function freePort() {
  return await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function generateOperator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKeyB64: exportPublicKeyB64(publicKey) };
}

/** Base remote configuration naming a valid empty trust store. */
async function remoteConfig(trustStorePath, overrides = {}) {
  return {
    bindHost: '127.0.0.1',
    port: await freePort(),
    publicHostname,
    serverCertificatePath: pki.serverCertPath,
    privateKey: { kind: 'file', path: pki.serverKeyPath },
    clientCaPaths: [pki.trustedCaCertPath],
    trustStorePath,
    ...overrides,
  };
}

// ---- Local admin IPC (real Ed25519 challenge-response over a Unix socket) ----

function readOneFrame(socket, maxBytes) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.removeListener('data', onData);
      socket.removeListener('end', onEnd);
      socket.removeListener('error', onEnd);
    };
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

/** One-shot authenticated admin request over the REAL local IPC channel. */
async function adminRequest(endpoint, privateKey, method, params = {}) {
  const socket = net.createConnection(endpoint);
  await once(socket, 'connect');
  const challenge = JSON.parse((await readOneFrame(socket, 4096)).toString('utf8'));
  socket.write(`${JSON.stringify(buildEnvelope(privateKey, challenge, method, params))}\n`);
  const frame = await readOneFrame(socket, 8 * 1024 * 1024);
  socket.destroy();
  return JSON.parse(frame.toString('utf8'));
}

// ---- Remote bootstrap HTTP over REAL mTLS ----

const clientMaterial = () => ({
  cert: fs.readFileSync(pki.clientCertPath),
  key: fs.readFileSync(pki.clientKeyPath),
});

const otherClientMaterial = (certPath, keyPath) => ({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
});

/**
 * Performs one HTTPS request against the remote gateway.
 *
 * `client` selects the presented certificate material; `client: null` produces a
 * connection with NO client certificate, which is the RC05-NEG-30 control.
 */
function httpsRequest(port, options = {}) {
  const {
    method = 'POST',
    requestPath = '/enroll/complete',
    body,
    client = clientMaterial(),
    headers = {},
    chunked = false,
  } = options;

  return new Promise((resolve) => {
    let settled = false;
    const done = (outcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };

    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [trustedCaPem],
        // The client does not verify the server here: the subject of every case
        // is the SERVER's mTLS requirement, and the server certificate is
        // already covered by the Task-3 suite.
        rejectUnauthorized: false,
        ...(client ?? {}),
        headers,
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () =>
          done({ status: res.statusCode, headers: res.headers, body: data, error: null }),
        );
        res.on('error', (err) => done({ status: null, headers: {}, body: '', error: err }));
      },
    );

    req.on('error', (err) => done({ status: null, headers: {}, body: '', error: err }));

    if (chunked) {
      // No Content-Length: Node frames the request as chunked automatically.
      for (let i = 0; i < 40; i += 1) {
        req.write('y'.repeat(256));
      }
    } else if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

/** Completes a bootstrap proof and returns the raw HTTP outcome. */
function completeEnrollment(port, secret, options = {}) {
  return httpsRequest(port, {
    ...options,
    body: options.rawBody ?? JSON.stringify({ secret }),
    requestPath: options.requestPath ?? '/enroll/complete',
    method: options.method ?? 'POST',
    client: 'client' in options ? options.client : clientMaterial(),
  });
}

/** Asserts the ONE uniform anti-oracle bootstrap failure. */
function assertUniformFailure(outcome) {
  assert.equal(outcome.status, 400, `expected HTTP 400, got ${outcome.status}`);
  assert.deepEqual(JSON.parse(outcome.body), { error: 'Enrollment failed' });
  assert.equal(outcome.headers.connection, 'close');
}

/** Asserts the ONE uniform pre-session `/mcp` failure. */
function assertUnauthenticated(outcome) {
  assert.equal(outcome.status, 401, `expected HTTP 401, got ${outcome.status}`);
  assert.deepEqual(JSON.parse(outcome.body), {
    code: 'UNAUTHENTICATED',
    message: 'Authentication failed',
  });
}

/** The canonical SPKI pin of an issued certificate file. */
function pinOf(certPath) {
  return deriveSpkiPin(fs.readFileSync(certPath, 'utf8'));
}

/**
 * Starts a gateway beside the real local admin IPC channel over ONE shared
 * EnrollmentManager, exactly as `createArcMcpServer` composes them.
 */
async function startPaired(options = {}) {
  const trustStorePath = options.trustStorePath ?? freshStore('paired');
  const enrollmentManager = options.enrollmentManager ?? new EnrollmentManager();
  const config = await remoteConfig(trustStorePath, options.remoteOverrides ?? {});

  const gateway = new RemoteGateway(config, {
    enrollmentManager,
    ...(options.gatewayOptions ?? {}),
  });
  await gateway.start();

  let adminServer;
  let endpoint;
  let operator;
  if (options.withAdmin !== false) {
    endpoint = path.join(freshAdminDir('paired'), 'admin.sock');
    operator = generateOperator();
    adminServer = new AdminIpcServer({
      endpoint,
      operatorPublicKeyB64: operator.publicKeyB64,
      approvalStateManager: new ApprovalStateManager(),
      auditLogger: new AuditLogger(),
      // The SAME instance the gateway completes against. This is the Task-4
      // composition invariant, mirrored from `createArcMcpServer`.
      enrollmentManager,
    });
    await adminServer.start();
  }

  return {
    gateway,
    adminServer,
    endpoint,
    operator,
    config,
    trustStorePath,
    enrollmentManager,
    port: gateway.getBoundPort(),
    async stop() {
      if (adminServer) {
        await adminServer.stop();
      }
      await gateway.stop();
    },
  };
}

/**
 * Creates a pending challenge through the REAL authenticated admin IPC channel.
 *
 * This is the ONLY way a pending enrollment can come into existence: the remote
 * endpoint has no authority to create one.
 */
async function operatorCreateEnrollment(harness, overrides = {}) {
  const response = await adminRequest(
    harness.endpoint,
    harness.operator.privateKey,
    'enrollment.create',
    {
      clientId: 'agent-alpha',
      clientType: 'claude-code',
      spkiPin: clientPin,
      ...overrides,
    },
  );
  assert.equal(response.ok, true, `admin enrollment.create failed: ${response.error?.code}`);
  return response.result;
}

// ===========================================================================

describe('CesSpace ARC — RC-05 Task 4: Enrollment Bootstrap Endpoint', () => {
  /** Every harness started by a case, torn down after it. */
  let harnesses;

  function track(harness) {
    harnesses.push(harness);
    return harness;
  }

  before(() => {
    harnesses = [];
  });

  afterEach(async () => {
    // Pending challenges are volatile per process; release them so a later case
    // never inherits an earlier one's quota or state.
    for (const harness of harnesses.splice(0)) {
      harness.enrollmentManager.clear();
      await harness.stop();
    }
  });

  // =========================================================================
  // Zero-device first enrollment, end to end
  // =========================================================================

  describe('Zero-device bootstrap (real admin IPC -> real mTLS endpoint)', () => {
    test('RC05-ENR-300: the first device enrolls through the REAL admin IPC and the REAL TLS endpoint', async () => {
      const harness = track(await startPaired());

      // 1-2. A valid empty trust store exists and the gateway started with it.
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0, 'zero devices at startup');
      assert.equal(harness.gateway.isStarted(), true);

      // 3-4. The operator creates a pending enrollment through the REAL local
      // authenticated admin channel, sharing the SAME manager instance.
      const created = await operatorCreateEnrollment(harness);
      assert.equal(created.enrollment.spkiPin, clientPin);
      assert.equal(harness.enrollmentManager.getPendingCount(), 1);

      // 5-6. Possession is proven by mTLS; the request body carries ONLY the
      // one-time secret.
      const outcome = await completeEnrollment(harness.port, created.secret);
      assert.equal(outcome.status, 200, `expected HTTP 200, got ${outcome.status}`);
      assert.deepEqual(JSON.parse(outcome.body), { status: 'enrolled' });
      assert.equal(outcome.headers.connection, 'close', 'the exchange is not kept alive');

      // 7. The success body discloses no enrollment internals.
      for (const leaked of [
        created.secret,
        clientPin,
        harness.trustStorePath,
        created.enrollment.enrollmentId,
        'agent-alpha',
      ]) {
        assert.equal(outcome.body.includes(leaked), false, `response leaked ${leaked}`);
      }

      // 8-9. Reload from disk with the Task-1 loader: exactly one device, with
      // the server-derived pin and the operator-declared metadata.
      const reloaded = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(reloaded.getDeviceCount(), 1);
      const device = reloaded.findDeviceByPin(clientPin);
      assert.ok(device, 'the presented SPKI pin must be the enrolled pin');
      assert.equal(device.clientId, 'agent-alpha');
      assert.equal(device.clientType, 'claude-code');
      assert.equal(device.revoked, false);
      assert.equal(reloaded.getDevices().length, 1);

      // 10. The pending challenge is gone.
      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
      assert.equal(
        harness.enrollmentManager.get(created.enrollment.enrollmentId),
        undefined,
        'the challenge was consumed, not merely marked',
      );

      // 11. Replay of the same secret is the uniform failure.
      assertUniformFailure(await completeEnrollment(harness.port, created.secret));

      // 12. A fresh reader over the same file still sees the device, while a
      // fresh manager sees no pending challenge: the enrollment is durable and
      // the challenge is volatile.
      const afterRestart = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(afterRestart.getDeviceCount(), 1);
      assert.equal(afterRestart.findDeviceByPin(clientPin)?.clientId, 'agent-alpha');
      assert.equal(new EnrollmentManager().getPendingCount(), 0);

      // 13. No session, token, or MCP surface was produced.
      assert.equal(harness.gateway.getStatus().transportMode, 'remote');
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 1);
    });

    test('RC05-ENR-301: the composed server shares ONE EnrollmentManager across both halves', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const trustStorePath = freshStore('composed');
      const endpoint = path.join(freshAdminDir('composed'), 'admin.sock');
      const operator = generateOperator();
      const port = await freePort();

      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        admin: { endpoint, operatorPublicKeyB64: operator.publicKeyB64 },
        remote: await remoteConfig(trustStorePath, { port }),
      });
      await server.start();
      try {
        // A challenge created over the local channel is IMMEDIATELY visible to
        // the remote gateway, which is only possible across one instance.
        const created = await operatorCreateEnrollment(
          { endpoint, operator },
          {
            clientId: 'composed-client',
          },
        );
        assert.equal(server.enrollmentManager.getPendingCount(), 1);
        assert.equal(
          server.enrollmentManager.get(created.enrollment.enrollmentId)?.spkiPin,
          clientPin,
        );

        const outcome = await completeEnrollment(port, created.secret);
        assert.equal(outcome.status, 200);
        assert.equal(server.enrollmentManager.getPendingCount(), 0);

        const reloaded = DeviceTrustStore.loadFromFile(trustStorePath);
        assert.equal(reloaded.getDeviceCount(), 1);
        assert.equal(reloaded.findDeviceByPin(clientPin)?.clientId, 'composed-client');

        // The composed server is a REMOTE server: no stdio fallback was started.
        assert.equal(server.getTransportMode(), 'remote');
        assert.equal(server.getRemoteGatewayStatus()?.listenerActive, true);
      } finally {
        await server.stop();
      }
    });
  });

  // =========================================================================
  // RC05-NEG-31 / 32 and the uniform anti-oracle contract
  // =========================================================================

  describe('Uniform bootstrap failure (RC05-NEG-31, 32, 33, 34, 35, 36)', () => {
    test('RC05-NEG-31: no matching pending record is a uniform HTTP 400', async () => {
      const harness = track(await startPaired());

      const outcome = await completeEnrollment(harness.port, 'a'.repeat(64));
      assertUniformFailure(outcome);
      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
    });

    test('RC05-NEG-32: a chain-valid certificate with a different SPKI fails identically', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      // The certificate chains to the configured client CA, so the handshake
      // succeeds; only its identity differs from the pending pin.
      const other = pki.issueTrustedClientCert({ commonName: 'client-mismatch' });
      assert.notEqual(pinOf(other.certPath), clientPin, 'the control needs a different SPKI');

      const outcome = await completeEnrollment(harness.port, created.secret, {
        client: otherClientMaterial(other.certPath, other.keyPath),
      });
      assertUniformFailure(outcome);

      // The matching challenge is untouched: possession failed, but the correct
      // device can still complete with the correct secret.
      const stillPending = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(stillPending, 'the matching challenge must survive a mismatched-SPKI attempt');
      assert.equal(stillPending.failedAttempts, 0, 'another identity never spends an attempt');
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);

      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-NEG-33h: a wrong one-time secret is counted and preserves challenge state', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      assertUniformFailure(await completeEnrollment(harness.port, 'f'.repeat(64)));

      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view, 'the challenge remains pending after the first failure');
      assert.equal(view.failedAttempts, 1);
      assert.equal(view.expiresAt, created.enrollment.expiresAt, 'the deadline never moves');
      assert.equal(view.clientId, 'agent-alpha');
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);

      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-NEG-34h: the third wrong secret purges the challenge and the correct secret dies with it', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);
      const wrong = 'f'.repeat(64);

      assertUniformFailure(await completeEnrollment(harness.port, wrong));
      assert.ok(harness.enrollmentManager.get(created.enrollment.enrollmentId));

      assertUniformFailure(await completeEnrollment(harness.port, wrong));
      assert.ok(harness.enrollmentManager.get(created.enrollment.enrollmentId));

      assertUniformFailure(await completeEnrollment(harness.port, wrong));
      assert.equal(
        harness.enrollmentManager.get(created.enrollment.enrollmentId),
        undefined,
        'the challenge is purged on the third failure, not merely marked',
      );

      // The correct secret is now useless, and the response is unchanged.
      assertUniformFailure(await completeEnrollment(harness.port, created.secret));
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
    });

    test('RC05-NEG-36h: a replayed secret is the uniform failure and mints no second device', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
      const first = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(first.getDeviceCount(), 1);
      const firstDeviceId = first.findDeviceByPin(clientPin)?.deviceId;

      for (let attempt = 0; attempt < 3; attempt += 1) {
        assertUniformFailure(await completeEnrollment(harness.port, created.secret));
      }

      const after = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(after.getDeviceCount(), 1, 'replay must not mint a second device');
      assert.equal(after.findDeviceByPin(clientPin)?.deviceId, firstDeviceId);
    });

    test('RC05-ENR-302: a malformed secret reaches the constant-time verifier and is counted', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      // Well-formed JSON carrying an unusable secret: a genuine proof attempt,
      // spent against the challenge exactly like a wrong secret.
      for (const malformed of ['', 'not-hex', 'a'.repeat(63), 'A'.repeat(64)]) {
        assertUniformFailure(await completeEnrollment(harness.port, malformed));
      }
      assert.equal(
        harness.enrollmentManager.get(created.enrollment.enrollmentId),
        undefined,
        'four malformed proofs are four counted attempts and purge the challenge',
      );
      assertUniformFailure(await completeEnrollment(harness.port, created.secret));
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
    });

    test('RC05-ENR-303: a challenge cancelled locally can no longer be completed remotely', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      const cancelled = await adminRequest(
        harness.endpoint,
        harness.operator.privateKey,
        'enrollment.cancel',
        { enrollmentId: created.enrollment.enrollmentId },
      );
      assert.equal(cancelled.ok, true);

      assertUniformFailure(await completeEnrollment(harness.port, created.secret));
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
    });

    test('RC05-NEG-35h: after the 300-second monotonic deadline the secret is refused', async () => {
      // The monotonic clock lives in the enrollment domain, so it is injected
      // at that boundary; the HTTP mapping of the outcome is covered above.
      let mono = 1_000_000_000_000n;
      const enrollmentManager = new EnrollmentManager({ getMonotonicTime: () => mono });
      const trustStorePath = freshStore('expiry');
      const harness = track(await startPaired({ enrollmentManager, trustStorePath }));

      const created = await operatorCreateEnrollment(harness);
      mono += 300_000_000_000n; // exactly 300 s

      assertUniformFailure(await completeEnrollment(harness.port, created.secret));
      assert.equal(
        harness.enrollmentManager.get(created.enrollment.enrollmentId),
        undefined,
        'the expired challenge is purged, and expiry wins over a correct secret',
      );
      assert.equal(DeviceTrustStore.loadFromFile(trustStorePath).getDeviceCount(), 0);
    });
  });

  // =========================================================================
  // Trusted identity selection
  // =========================================================================

  describe('Trusted SPKI selection (Task 4 §5, §20)', () => {
    test('RC05-ENR-304: extra identity fields cannot influence selection or activation', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      const body = JSON.stringify({
        secret: created.secret,
        spkiPin: clientPin,
        clientId: 'attacker-client',
        clientType: 'attacker-type',
        deviceId: 'f'.repeat(32),
        operatorId: 'e'.repeat(64),
        enrollmentId: 'd'.repeat(32),
      });
      assert.equal(
        (await completeEnrollment(harness.port, undefined, { rawBody: body })).status,
        200,
      );

      // The enrolled record carries the OPERATOR-declared metadata and the
      // mTLS-derived pin — never a field the client submitted.
      const reloaded = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(reloaded.getDeviceCount(), 1);
      const device = reloaded.findDeviceByPin(clientPin);
      assert.ok(device);
      assert.equal(device.clientId, 'agent-alpha');
      assert.equal(device.clientType, 'claude-code');
      assert.notEqual(device.deviceId, 'f'.repeat(32), 'deviceId is ARC-assigned');
      assert.equal(device.pins.length, 1);
    });

    test('RC05-ENR-305: a body-supplied pin cannot substitute for the mTLS identity', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      // A CA-valid client whose SPKI is NOT the pending one names the pending
      // pin in the body. The body is ignored, so selection uses the certificate.
      const other = pki.issueTrustedClientCert({ commonName: 'client-body-pin' });
      const outcome = await completeEnrollment(harness.port, undefined, {
        rawBody: JSON.stringify({ secret: created.secret, spkiPin: clientPin }),
        client: otherClientMaterial(other.certPath, other.keyPath),
      });
      assertUniformFailure(outcome);
      assert.equal(harness.enrollmentManager.getPendingCount(), 1, 'the challenge survives');
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
    });

    test('RC05-ENR-306: a secret in the query string or a header is never accepted', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      // Query string: the path is matched without it, and the body is empty.
      assertUniformFailure(
        await httpsRequest(harness.port, {
          requestPath: `/enroll/complete?secret=${created.secret}`,
          body: JSON.stringify({}),
        }),
      );

      // Header: never read as a proof.
      assertUniformFailure(
        await httpsRequest(harness.port, {
          requestPath: '/enroll/complete',
          body: JSON.stringify({}),
          headers: { 'x-enrollment-secret': created.secret },
        }),
      );

      // Neither attempt mutated the challenge, so the genuine proof still works.
      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.equal(view.failedAttempts, 0);
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });
  });

  // =========================================================================
  // Single-use under concurrency
  // =========================================================================

  describe('Single-use and concurrency (Task 4 §14)', () => {
    test('RC05-ENR-307: two simultaneous valid completions produce exactly one success', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      const [first, second] = await Promise.all([
        completeEnrollment(harness.port, created.secret),
        completeEnrollment(harness.port, created.secret),
      ]);

      const statuses = [first.status, second.status].sort();
      assert.deepEqual(statuses, [200, 400], `exactly one success, got ${statuses}`);
      assertUniformFailure(first.status === 400 ? first : second);

      const reloaded = DeviceTrustStore.loadFromFile(harness.trustStorePath);
      assert.equal(reloaded.getDeviceCount(), 1, 'no duplicate persistence');
      assert.equal(reloaded.getDevices().length, 1);
      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
    });

    test('RC05-ENR-308: a burst of valid completions still yields one device', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      const outcomes = await Promise.all(
        Array.from({ length: 6 }, () => completeEnrollment(harness.port, created.secret)),
      );
      assert.equal(
        outcomes.filter((o) => o.status === 200).length,
        1,
        'the challenge is single-use under a burst',
      );
      for (const outcome of outcomes) {
        if (outcome.status !== 200) {
          assertUniformFailure(outcome);
        }
      }
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 1);
      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
    });
  });

  // =========================================================================
  // Atomic activation
  // =========================================================================

  describe('Atomic activation transaction (Task 4 §11, §19)', () => {
    test('RC05-ENR-309: a persistence failure consumes nothing and leaves the file unchanged', async () => {
      const trustStorePath = freshStore('persist-fail');
      const before = fs.readFileSync(trustStorePath);
      const enrollmentManager = new EnrollmentManager();

      const failingWriter = {
        save() {
          throw new Error('injected durable-write failure');
        },
      };
      const failing = track(
        await startPaired({
          enrollmentManager,
          trustStorePath,
          gatewayOptions: { bootstrap: { trustStoreWriterForTests: failingWriter } },
        }),
      );
      const created = await operatorCreateEnrollment(failing);

      assertUniformFailure(await completeEnrollment(failing.port, created.secret));

      // The challenge survives, untouched: no attempt was spent, and the secret
      // is still usable once the persistence problem is resolved.
      const view = failing.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view, 'a correct-secret persistence failure must not consume the challenge');
      assert.equal(view.failedAttempts, 0, 'a persistence failure is not a failed attempt');
      assert.equal(view.expiresAt, created.enrollment.expiresAt);
      assert.deepEqual(fs.readFileSync(trustStorePath), before, 'the file is byte-identical');
      assert.equal(failing.gateway.getEnrolledDeviceCount(), 0, 'in-memory state is unchanged');

      // A retry against a healthy writer succeeds, and the failure left no trace.
      const healthy = track(await startPaired({ enrollmentManager, trustStorePath }));
      assert.equal((await completeEnrollment(healthy.port, created.secret)).status, 200);
      assert.equal(DeviceTrustStore.loadFromFile(trustStorePath).getDeviceCount(), 1);
      assert.equal(enrollmentManager.getPendingCount(), 0);
    });

    test('RC05-ENR-310: an activation resource failure leaves nothing partially enrolled', async () => {
      // Fill the trust store to its 256-device ceiling so the CANDIDATE
      // enrollment fails after the proof has already verified.
      const trustStorePath = freshStore('capacity');
      const full = DeviceTrustStore.createEmpty();
      for (let i = 0; i < 256; i += 1) {
        full.enrollDevice({
          clientId: `bulk-${i}`,
          clientType: 'bulk-client',
          pin: crypto.createHash('sha256').update(`bulk-pin-${i}`).digest('hex'),
        });
      }
      full.saveToFile(trustStorePath);
      fs.chmodSync(trustStorePath, 0o600);
      const before = fs.readFileSync(trustStorePath);

      const harness = track(await startPaired({ trustStorePath }));
      const created = await operatorCreateEnrollment(harness);

      assertUniformFailure(await completeEnrollment(harness.port, created.secret));

      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view, 'a resource failure must not consume the valid challenge');
      assert.equal(view.failedAttempts, 0);
      assert.deepEqual(fs.readFileSync(trustStorePath), before, 'no partial device was persisted');
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 256);
      assert.equal(
        DeviceTrustStore.loadFromFile(trustStorePath).findDeviceByPin(clientPin),
        undefined,
        'no partial device exists',
      );
    });

    test('RC05-ENR-311: a conflicting client binding fails closed without consuming the challenge', async () => {
      const trustStorePath = freshStore('conflict');
      const existing = DeviceTrustStore.createEmpty();
      const { device } = existing.enrollDevice({
        clientId: 'different-client',
        clientType: 'claude-code',
        pin: clientPin,
      });
      existing.saveToFile(trustStorePath);
      fs.chmodSync(trustStorePath, 0o600);
      const before = fs.readFileSync(trustStorePath);

      const harness = track(await startPaired({ trustStorePath }));
      // The operator authorises the SAME pin under a DIFFERENT clientId; §8
      // rejects that binding, so activation must fail closed here too.
      const created = await operatorCreateEnrollment(harness, { clientId: 'agent-alpha' });

      const outcome = await completeEnrollment(harness.port, created.secret);
      assertUniformFailure(outcome);
      // The collision is never disclosed: the response is byte-identical to an
      // unknown challenge.
      assert.deepEqual(
        outcome.body,
        (await completeEnrollment(harness.port, 'a'.repeat(64))).body,
        'a binding collision must be indistinguishable from an unknown challenge',
      );

      assert.ok(harness.enrollmentManager.get(created.enrollment.enrollmentId));
      const reloaded = DeviceTrustStore.loadFromFile(trustStorePath);
      assert.equal(reloaded.getDeviceCount(), 1);
      assert.equal(reloaded.findDeviceByPin(clientPin)?.deviceId, device.deviceId);
      assert.equal(reloaded.findDeviceByPin(clientPin)?.clientId, 'different-client');
      assert.deepEqual(fs.readFileSync(trustStorePath), before, 'the trust store is unchanged');
    });

    test('RC05-ENR-312: the same pin under the same clientId reuses the deviceId', async () => {
      const trustStorePath = freshStore('reuse');
      const first = track(await startPaired({ trustStorePath }));
      const createdFirst = await operatorCreateEnrollment(first);
      assert.equal((await completeEnrollment(first.port, createdFirst.secret)).status, 200);
      const deviceId =
        DeviceTrustStore.loadFromFile(trustStorePath).findDeviceByPin(clientPin)?.deviceId;

      // A second operator-authorised challenge for the SAME pin and clientId.
      const second = track(await startPaired({ trustStorePath }));
      const createdSecond = await operatorCreateEnrollment(second);
      assert.equal((await completeEnrollment(second.port, createdSecond.secret)).status, 200);

      const reloaded = DeviceTrustStore.loadFromFile(trustStorePath);
      assert.equal(reloaded.getDeviceCount(), 1, 'no duplicate device record');
      assert.equal(reloaded.findDeviceByPin(clientPin)?.deviceId, deviceId);
      assert.equal(reloaded.findDeviceByPin(clientPin)?.pins.length, 1);
    });
  });

  // =========================================================================
  // Request-surface hardening and the deny-only /mcp placeholder
  // =========================================================================

  describe('Request-surface hardening (Task 4 §4, §6, §7, §18, §20)', () => {
    test('RC05-NEG-30: no client certificate never reaches the endpoint', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);
      const before = fs.readFileSync(harness.trustStorePath);

      const outcome = await completeEnrollment(harness.port, created.secret, { client: null });

      // The handshake itself failed: no HTTP status and no HTTP body at all.
      assert.equal(outcome.status, null, 'no HTTP response may be produced');
      assert.ok(outcome.error, 'the TLS handshake must fail');
      assert.equal(outcome.body, '');
      assert.equal(outcome.body.includes('Enrollment'), false);
      assert.equal(outcome.body.includes(created.secret), false);

      // No pending-state mutation, no trust-store mutation.
      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view, 'the challenge is untouched');
      assert.equal(view.failedAttempts, 0, 'the HTTP layer was never reached');
      assert.deepEqual(fs.readFileSync(harness.trustStorePath), before);
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0);

      // The same proof over a correct mTLS connection still succeeds.
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-NEG-30b: a certificate from an untrusted CA never reaches the endpoint', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      const outcome = await completeEnrollment(harness.port, created.secret, {
        client: otherClientMaterial(pki.unknownCaClientCertPath, pki.unknownCaClientKeyPath),
      });
      assert.equal(outcome.status, null);
      assert.ok(outcome.error);
      assert.ok(harness.enrollmentManager.get(created.enrollment.enrollmentId));
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0);
    });

    test('RC05-ENR-313: a wrong method is a 405 that spends no attempt', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      for (const method of ['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']) {
        const outcome = await httpsRequest(harness.port, {
          method,
          requestPath: '/enroll/complete',
          // Even the CORRECT secret in the body must not be verified.
          body: JSON.stringify({ secret: created.secret }),
        });
        assert.equal(outcome.status, 405, `${method} must be refused with 405`);
        assert.equal(outcome.headers.allow, 'POST');
      }

      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view, 'the challenge is untouched by method confusion');
      assert.equal(view.failedAttempts, 0, 'a wrong method must not spend a failed attempt');
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);

      // The genuine POST still works.
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-ENR-314: an unknown path is a 404 that touches no state', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      for (const requestPath of [
        '/',
        '/enroll',
        '/enroll/complete/',
        '/enroll/complete/extra',
        '/ENROLL/COMPLETE',
        '/enroll/complete-ish',
        '/admin',
        '/enroll/complete.json',
      ]) {
        const outcome = await httpsRequest(harness.port, {
          requestPath,
          body: JSON.stringify({ secret: created.secret }),
        });
        assert.equal(outcome.status, 404, `${requestPath} must be 404`);
        assert.deepEqual(JSON.parse(outcome.body), { error: 'Not found' });
      }

      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view);
      assert.equal(view.failedAttempts, 0);
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-ENR-315: an oversized bootstrap body is refused without invoking the manager', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      // 1. Declared Content-Length above the 4 KiB endpoint bound.
      const declared = await httpsRequest(harness.port, {
        requestPath: '/enroll/complete',
        body: JSON.stringify({ secret: created.secret, pad: 'x'.repeat(5000) }),
      });
      assert.equal(declared.status, 413);
      assert.deepEqual(JSON.parse(declared.body), { error: 'Payload too large' });

      // 2. A chunked body that grows past the bound with NO Content-Length.
      const chunked = await httpsRequest(harness.port, {
        requestPath: '/enroll/complete',
        chunked: true,
      });
      assert.equal(chunked.status, 413);
      assert.deepEqual(JSON.parse(chunked.body), { error: 'Payload too large' });

      // 3. A bootstrap body exactly AT the bound is not rejected as oversized;
      // it is simply a malformed proof.
      const atBound = JSON.stringify({ secret: created.secret }).padEnd(4096, ' ');
      assert.equal(atBound.length, 4096);
      const atBoundOutcome = await completeEnrollment(harness.port, undefined, {
        rawBody: atBound,
      });
      // Trailing whitespace is legal JSON padding, so this is the real proof and
      // it consumes the challenge: that is the correct, non-oversized outcome.
      assert.equal(atBoundOutcome.status, 200);

      // No oversized attempt was counted anywhere along the way.
      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 1);
    });

    test('RC05-ENR-316: malformed JSON and wrong-shaped bodies are the uniform failure', async () => {
      const harness = track(await startPaired());
      const created = await operatorCreateEnrollment(harness);

      for (const rawBody of [
        '',
        '{',
        'not json at all',
        'null',
        '[]',
        '"secret"',
        '42',
        '{}',
        '{"secret":null}',
        '{"secret":42}',
        '{"secret":""}',
        '{"secret":["a"]}',
        '{"secret":{"v":"a"}}',
        '{"secret":true}',
      ]) {
        const outcome = await completeEnrollment(harness.port, undefined, { rawBody });
        assertUniformFailure(outcome);
        assert.equal(
          outcome.body.includes('secret'),
          false,
          'the failure body must not echo the submission',
        );
      }

      // A body that fails the closed schema never reaches the verifier, so no
      // attempt is spent; the genuine proof still works.
      const view = harness.enrollmentManager.get(created.enrollment.enrollmentId);
      assert.ok(view);
      assert.equal(view.failedAttempts, 0);
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
    });

    test('RC05-NEG-29: remote self-enrollment through /mcp is refused and enrolls nothing', async () => {
      const harness = track(await startPaired());

      // An unauthenticated attempt to bootstrap an identity through the MCP
      // path, carrying enrollment-looking JSON.
      assertUnauthenticated(
        await httpsRequest(harness.port, {
          requestPath: '/mcp',
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'tools/call',
            params: { name: 'enroll_device', arguments: { spkiPin: clientPin } },
          }),
        }),
      );

      // The same request carrying a real one-time secret is still refused:
      // /mcp has no enrollment authority at all.
      assertUnauthenticated(
        await httpsRequest(harness.port, {
          requestPath: '/mcp',
          body: JSON.stringify({ secret: 'a'.repeat(64), spkiPin: clientPin }),
        }),
      );

      assert.equal(harness.enrollmentManager.getPendingCount(), 0);
      assert.equal(DeviceTrustStore.loadFromFile(harness.trustStorePath).getDeviceCount(), 0);
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0);
    });

    test('RC05-NEG-38: a zero-device ordinary /mcp request is refused while /enroll/complete works', async () => {
      const harness = track(await startPaired());
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0);

      const ordinary = await httpsRequest(harness.port, {
        requestPath: '/mcp',
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        headers: { 'content-type': 'application/json' },
      });
      assertUnauthenticated(ordinary);
      assert.equal(ordinary.headers['mcp-session-id'], undefined, 'no session may be minted');
      assert.equal(ordinary.headers['arc-session-token'], undefined, 'no token may be issued');
      assert.equal(ordinary.body.includes('tools'), false, 'no tool list may be served');

      // The bootstrap endpoint remains fully usable in the same zero-device state.
      const created = await operatorCreateEnrollment(harness);
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 1);
    });

    test('RC05-NEG-38b: /mcp is refused for every method, before and after enrollment', async () => {
      const harness = track(await startPaired());

      for (const method of ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS', 'PATCH']) {
        assertUnauthenticated(await httpsRequest(harness.port, { method, requestPath: '/mcp' }));
      }

      // Even for an ENROLLED device, Task 4 mints no session: the MCP transport
      // belongs to Task 8, and until then /mcp is deny-only.
      const created = await operatorCreateEnrollment(harness);
      assert.equal((await completeEnrollment(harness.port, created.secret)).status, 200);
      assertUnauthenticated(
        await httpsRequest(harness.port, {
          requestPath: '/mcp',
          body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
        }),
      );
    });
  });

  // =========================================================================
  // Trust-store startup requirements
  // =========================================================================

  describe('Remote trust store is a required authentication root (Task 4 §2)', () => {
    test('RC05-ENR-317: a missing trust store fails remote startup with no listener', async () => {
      await assert.rejects(
        () =>
          startPaired({
            trustStorePath: path.join(tempRoot, 'does-not-exist.json'),
            withAdmin: false,
          }),
        (err) => err.reason === 'TRUST_STORE_INVALID',
      );
    });

    test('RC05-ENR-318: an omitted trustStorePath is refused, never defaulted', async () => {
      await assert.rejects(
        () => startPaired({ remoteOverrides: { trustStorePath: undefined }, withAdmin: false }),
        (err) => err.reason === 'TRUST_STORE_PATH_INVALID' || err.reason === 'TRUST_STORE_INVALID',
      );
    });

    test('RC05-ENR-319: an insecurely permissioned trust store fails remote startup', async () => {
      const insecure = freshStore('insecure');
      fs.chmodSync(insecure, 0o644);
      await assert.rejects(
        () => startPaired({ trustStorePath: insecure, withAdmin: false }),
        (err) => err.reason === 'TRUST_STORE_INVALID',
      );
    });

    test('RC05-ENR-320: a corrupt trust store fails remote startup with no listener', async () => {
      storeCounter += 1;
      const corrupt = path.join(tempRoot, `devices-corrupt-${storeCounter}.json`);
      fs.writeFileSync(corrupt, '{"version":1,"devices":"not-an-array"}', { mode: 0o600 });
      fs.chmodSync(corrupt, 0o600);
      await assert.rejects(
        () => startPaired({ trustStorePath: corrupt, withAdmin: false }),
        (err) => err.reason === 'TRUST_STORE_INVALID',
      );
    });

    test('RC05-ENR-321: a VALID empty trust store is a supported startup state', async () => {
      const harness = track(await startPaired({ withAdmin: false }));
      assert.equal(harness.gateway.isStarted(), true);
      assert.equal(harness.gateway.getEnrolledDeviceCount(), 0);
      assert.equal(harness.gateway.getStatus().degraded, false);
      assert.equal(harness.gateway.getStatus().activeAndServing, true);
    });
  });

  // =========================================================================
  // The injected seam is internal only
  // =========================================================================

  describe('The durable-write seam is not reachable from configuration', () => {
    test('RC05-ENR-322: trusted launch configuration cannot express the persistence seam', async () => {
      const trustStorePath = freshStore('seam');
      const config = await remoteConfig(trustStorePath);

      for (const seam of [
        'trustStoreWriterForTests',
        'trustStoreWriter',
        'bootstrap',
        'enrollmentManager',
      ]) {
        assert.equal(
          Object.prototype.hasOwnProperty.call(config, seam),
          false,
          `${seam} must not be expressible through trusted launch configuration`,
        );
      }

      // Smuggling the seam through the configuration object is inert: the
      // gateway reads seams only from its own constructor options, so a smuggled
      // writer is never consulted. The observable consequence is that a genuine
      // enrollment still lands on disk through the REAL Task-1 persistence.
      const enrollmentManager = new EnrollmentManager();
      let writerWasCalled = false;
      const smuggled = new RemoteGateway(
        {
          ...config,
          bootstrap: {
            trustStoreWriterForTests: {
              save: () => {
                writerWasCalled = true;
              },
            },
          },
          trustStoreWriterForTests: {
            save: () => {
              writerWasCalled = true;
            },
          },
        },
        { enrollmentManager },
      );
      await smuggled.start();
      try {
        const created = enrollmentManager.create({
          clientId: 'seam-client',
          clientType: 'claude-code',
          spkiPin: clientPin,
          operatorId: crypto.createHash('sha256').update('seam-operator').digest('hex'),
        });
        const outcome = await completeEnrollment(smuggled.getBoundPort(), created.secret);
        assert.equal(outcome.status, 200);
        assert.equal(
          DeviceTrustStore.loadFromFile(trustStorePath).getDeviceCount(),
          1,
          'the real atomic persistence ran, not the smuggled writer',
        );
        assert.equal(writerWasCalled, false, 'the smuggled writer must never be consulted');
      } finally {
        await smuggled.stop();
      }
    });
  });
});
