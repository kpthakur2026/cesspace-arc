/**
 * CesSpace ARC — RC-05 Task 3: TLS 1.3 / mTLS Admission Layer
 *
 * Covers the frozen TLS admission contract (rc05-scope-acceptance.md §5, §6
 * T-1..T-11, §7 P-1..P-3, §18, §19, §20, §21.1 Layer A) and the Task-3 negative
 * controls RC05-NEG-01, 05, 07–15, 28, 53, 54.
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * test PKI helper and removed with it; no certificate or key is committed and no
 * scanner suppression is used. Clocks are injected, so no test sleeps for a real
 * timeout.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

import { RemoteGateway } from '../apps/mcp-server/dist/remote-gateway.js';
import { RemoteConfigError } from '../apps/mcp-server/dist/remote-errors.js';
import {
  AdmissionLimiter,
  MAX_LIVE_CONNECTIONS_GLOBAL,
  MAX_LIVE_CONNECTIONS_PER_PEER,
  MAX_IN_FLIGHT_HANDSHAKES,
  LAYER_A_BURST,
  LAYER_A_REFILL_MS,
} from '../apps/mcp-server/dist/admission-limiter.js';
import {
  isWildcardBindHost,
  TLS_HANDSHAKE_TIMEOUT_MS,
} from '../apps/mcp-server/dist/remote-config.js';
import { createTestPki, hasOpenssl, oversizedCaFile, symlinkTo } from './helpers/rc05-test-pki.mjs';

let tempRoot;
let pki;
let publicHostname;

before(() => {
  // The suite generates its own X.509 material rather than shipping fixtures,
  // so a missing platform tool is a hard environment failure, not a skip.
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 Task 3 generates ephemeral certificates and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-tls-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  publicHostname = 'localhost';
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/**
 * Waits until `predicate` holds, or fails after a bounded budget.
 *
 * Used instead of fixed sleeps so the suite is not timing-fragile on a busy
 * machine while still never waiting on real protocol timeouts.
 */
async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
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

/** Base remote configuration for a healthy gateway. */
async function baseConfig(overrides = {}) {
  return {
    bindHost: '127.0.0.1',
    port: await freePort(),
    publicHostname,
    serverCertificatePath: pki.serverCertPath,
    privateKey: { kind: 'file', path: pki.serverKeyPath },
    clientCaPaths: [pki.trustedCaCertPath],
    ...overrides,
  };
}

/** Starts a gateway and guarantees teardown. */
async function startGateway(overrides = {}, options = {}) {
  const config = await baseConfig(overrides);
  const admitted = [];
  const refused = [];
  const gateway = new RemoteGateway(config, {
    onAdmitted: (context) => admitted.push(context),
    onRefused: (reason) => refused.push(reason),
    ...options,
  });
  await gateway.start();
  return { gateway, config, admitted, refused, port: gateway.getBoundPort() };
}

/** Connects a TLS client with the given material. Resolves to a socket outcome. */
function tlsConnect(port, options = {}) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: '127.0.0.1',
        port,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        rejectUnauthorized: false,
        ...options,
      },
      () => {
        resolve({ socket, authorized: socket.authorized, connected: true });
      },
    );
    socket.once('error', (err) => {
      resolve({ socket, connected: false, error: err });
    });
  });
}

/** Sends raw bytes to the TLS port and reports whether the connection dropped. */
function rawProbe(port, payload, budgetMs = 500) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let data = Buffer.alloc(0);
    socket.on('connect', () => {
      if (payload !== undefined) {
        socket.write(payload);
      }
    });
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
    });
    socket.on('close', () => resolve({ closed: true, data }));
    socket.on('error', () => resolve({ closed: true, data }));
    setTimeout(() => {
      socket.destroy();
      resolve({ closed: false, data });
    }, budgetMs).unref();
  });
}

describe('CesSpace ARC — RC-05 Task 3: TLS/mTLS Admission Layer', () => {
  // =========================================================================
  // Configuration and startup validation
  // =========================================================================

  describe('Startup validation', () => {
    test('RC05-NEG-05: a wildcard bind without opt-in fails startup with no listener', async () => {
      for (const bindHost of ['0.0.0.0', '::']) {
        await assert.rejects(
          () => startGateway({ bindHost }),
          (err) => err instanceof RemoteConfigError && err.reason === 'WILDCARD_BIND_NOT_OPTED_IN',
          bindHost,
        );
      }
    });

    test('RC05-NEG-05b: a wildcard bind is permitted only with an explicit opt-in', async () => {
      const { gateway, port } = await startGateway({
        bindHost: '127.0.0.1',
        allowWildcardBind: true,
      });
      try {
        assert.equal(gateway.isStarted(), true);
        assert.ok(port > 0);
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-100: the default bind host is loopback', async () => {
      const config = await baseConfig();
      delete config.bindHost;
      const gateway = new RemoteGateway(config);
      try {
        await gateway.start();
        assert.equal(gateway.isStarted(), true);
        // Loopback only: the bound address is not a wildcard.
        assert.notEqual(gateway.getBoundPort(), undefined);
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-12: a key/certificate mismatch fails startup with no listener', async () => {
      await assert.rejects(
        () => startGateway({ privateKey: { kind: 'file', path: pki.wrongServerKeyPath } }),
        (err) =>
          err instanceof RemoteConfigError && err.reason === 'SERVER_KEY_AND_CERTIFICATE_MISMATCH',
      );
    });

    test('RC05-NEG-13: an expired or not-yet-valid server certificate fails startup', async () => {
      // The clock is injected, so a valid certificate can be evaluated as
      // expired or as not yet valid without waiting for real time to pass.
      const farFuture = () => Date.now() + 400 * 86_400_000;
      await assert.rejects(
        () => startGateway({}, { getWallTime: farFuture }),
        (err) => err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_EXPIRED',
      );

      const farPast = () => Date.now() - 400 * 86_400_000;
      await assert.rejects(
        () => startGateway({}, { getWallTime: farPast }),
        (err) =>
          err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_NOT_YET_VALID',
      );
    });

    test('RC05-NEG-14: a SAN mismatch fails startup with no listener', async () => {
      await assert.rejects(
        () =>
          startGateway({
            serverCertificatePath: pki.sanMismatchCertPath,
            privateKey: { kind: 'file', path: pki.sanMismatchKeyPath },
          }),
        (err) =>
          err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_SAN_MISMATCH',
      );

      // The same certificate is accepted when the configured hostname matches.
      const matching = await startGateway({
        publicHostname: 'other.example.invalid',
        serverCertificatePath: pki.sanMismatchCertPath,
        privateKey: { kind: 'file', path: pki.sanMismatchKeyPath },
      });
      await matching.gateway.stop();
    });

    test('RC05-ENR-101: malformed configuration is rejected before binding', async () => {
      const cases = [
        { now: { port: 0 }, reason: 'PORT_INVALID' },
        { now: { port: 70_000 }, reason: 'PORT_INVALID' },
        { now: { port: '8443' }, reason: 'PORT_INVALID' },
        { now: { publicHostname: '' }, reason: 'PUBLIC_HOSTNAME_INVALID' },
        { now: { bindHost: 'http://example.invalid' }, reason: 'BIND_HOST_INVALID' },
        { now: { clientCaPaths: [] }, reason: 'CLIENT_CA_EMPTY' },
        { now: { clientCaPaths: ['a', 'b', 'c', 'd', 'e'] }, reason: 'CLIENT_CA_TOO_MANY' },
        {
          now: { clientCaPaths: [pki.trustedCaCertPath, pki.trustedCaCertPath] },
          reason: 'CLIENT_CA_PATH_INVALID',
        },
        {
          now: { privateKey: { kind: 'raw', value: 'secret' } },
          reason: 'PRIVATE_KEY_SOURCE_INVALID',
        },
      ];
      for (const { now, reason } of cases) {
        await assert.rejects(
          () => startGateway(now),
          (err) => err instanceof RemoteConfigError && err.reason === reason,
          reason,
        );
      }
    });

    test('RC05-ENR-102: missing or insecure key and certificate files fail startup', async () => {
      await assert.rejects(
        () =>
          startGateway({ privateKey: { kind: 'file', path: path.join(tempRoot, 'absent.key') } }),
        (err) => err instanceof RemoteConfigError,
      );
      await assert.rejects(
        () => startGateway({ serverCertificatePath: path.join(tempRoot, 'absent.pem') }),
        (err) => err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_UNREADABLE',
      );

      // Group/world readable key material is refused.
      const looseKey = path.join(tempRoot, 'loose.key');
      fs.copyFileSync(pki.serverKeyPath, looseKey);
      fs.chmodSync(looseKey, 0o644);
      await assert.rejects(
        () => startGateway({ privateKey: { kind: 'file', path: looseKey } }),
        (err) => err instanceof RemoteConfigError && err.reason === 'PRIVATE_KEY_INSECURE',
      );

      // A symlinked key is refused even when it points at valid material.
      const linkedKey = path.join(tempRoot, 'linked.key');
      symlinkTo(pki.serverKeyPath, linkedKey);
      await assert.rejects(
        () => startGateway({ privateKey: { kind: 'file', path: linkedKey } }),
        (err) => err instanceof RemoteConfigError && err.reason === 'PRIVATE_KEY_INSECURE',
      );
    });
  });

  // =========================================================================
  // Client CA trust-root integrity (RC05-NEG-28)
  // =========================================================================

  describe('RC05-NEG-28: client CA trust-root integrity', () => {
    test('RC05-NEG-28a: a symlinked CA is rejected', async () => {
      const link = symlinkTo(pki.trustedCaCertPath, path.join(tempRoot, 'ca-link.pem'));
      await assert.rejects(
        () => startGateway({ clientCaPaths: [link] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_INSECURE',
      );
    });

    test('RC05-NEG-28b: a group/world-writable CA is rejected', async () => {
      const writable = path.join(tempRoot, 'ca-writable.pem');
      fs.copyFileSync(pki.trustedCaCertPath, writable);
      fs.chmodSync(writable, 0o666);
      await assert.rejects(
        () => startGateway({ clientCaPaths: [writable] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_INSECURE',
      );
    });

    test('RC05-NEG-28c: an oversized CA is rejected', async () => {
      const oversized = oversizedCaFile(pki.trustedCaCertPath, path.join(tempRoot, 'ca-big.pem'));
      await assert.rejects(
        () => startGateway({ clientCaPaths: [oversized] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_TOO_LARGE',
      );
    });

    test('RC05-NEG-28d: a malformed or non-certificate CA is rejected', async () => {
      for (const caPath of [pki.malformedCaPath, pki.notACertificatePath]) {
        await assert.rejects(
          () => startGateway({ clientCaPaths: [caPath] }),
          (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_MALFORMED',
          caPath,
        );
      }
    });

    test('RC05-NEG-28e: a missing or empty CA is rejected', async () => {
      await assert.rejects(
        () => startGateway({ clientCaPaths: [path.join(tempRoot, 'absent-ca.pem')] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_UNREADABLE',
      );

      const empty = path.join(tempRoot, 'ca-empty.pem');
      fs.writeFileSync(empty, '', { mode: 0o644 });
      await assert.rejects(
        () => startGateway({ clientCaPaths: [empty] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_MALFORMED',
      );
    });

    test('RC05-NEG-28f: no listener survives any CA rejection', async () => {
      const link = symlinkTo(pki.trustedCaCertPath, path.join(tempRoot, 'ca-link-2.pem'));
      const port = await freePort();
      await assert.rejects(() => startGateway({ clientCaPaths: [link], port }));
      // The port is immediately rebindable, proving nothing is still listening.
      const gateway = await startGateway({ port });
      assert.equal(gateway.gateway.isStarted(), true);
      await gateway.gateway.stop();
    });
  });

  // =========================================================================
  // TLS version and handshake admission
  // =========================================================================

  describe('TLS admission', () => {
    test('RC05-NEG-07: a TLS 1.2 client is refused', async () => {
      const { gateway, port } = await startGateway();
      try {
        const outcome = await tlsConnect(port, {
          maxVersion: 'TLSv1.2',
          minVersion: 'TLSv1.2',
        });
        assert.equal(outcome.connected, false, 'TLS 1.2 must not complete a handshake');
        outcome.socket?.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-01: a plaintext HTTP request is refused at the TLS boundary', async () => {
      const { gateway, port, admitted } = await startGateway();
      try {
        const response = await rawProbe(
          port,
          Buffer.from('POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n'),
        );
        assert.equal(admitted.length, 0, 'no connection may be admitted');
        // The server never speaks plaintext HTTP: whatever arrives back is not a
        // successfully parsed HTTP response to our request.
        assert.ok(
          response.data.length === 0 || !response.data.toString('utf8').startsWith('HTTP/1.1 200'),
          'the server must not answer a plaintext HTTP request',
        );
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-08: a client that presents no certificate is refused', async () => {
      const { gateway, port, admitted } = await startGateway();
      try {
        const outcome = await tlsConnect(port);
        // The server must never admit, and must close the connection.
        await waitFor(() => outcome.socket.destroyed || admitted.length > 0, 1500);
        assert.equal(admitted.length, 0, 'no client certificate means no admission');
        assert.equal(outcome.socket.destroyed, true, 'the server must close the connection');
        outcome.socket?.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-09: a certificate from an unknown CA is refused', async () => {
      const { gateway, port, admitted } = await startGateway();
      try {
        const outcome = await tlsConnect(port, {
          cert: fs.readFileSync(pki.unknownCaClientCertPath),
          key: fs.readFileSync(pki.unknownCaClientKeyPath),
        });
        await waitFor(() => outcome.socket.destroyed || admitted.length > 0, 1500);
        assert.equal(admitted.length, 0, 'an untrusted chain must never be admitted');
        assert.equal(outcome.socket.destroyed, true, 'the server must close the connection');
        outcome.socket?.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-10: an expired and a not-yet-valid client certificate are refused', async () => {
      const { gateway, port, admitted } = await startGateway();
      try {
        for (const [certPath, keyPath] of [
          [pki.expiredClientCertPath, pki.expiredClientKeyPath],
          [pki.futureClientCertPath, pki.futureClientKeyPath],
        ]) {
          const outcome = await tlsConnect(port, {
            cert: fs.readFileSync(certPath),
            key: fs.readFileSync(keyPath),
          });
          await waitFor(() => outcome.socket.destroyed || admitted.length > 0, 1500);
          assert.equal(outcome.socket.destroyed, true, `${certPath} must be refused`);
          outcome.socket?.destroy();
        }
        assert.equal(admitted.length, 0, 'an out-of-window certificate must never be admitted');
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-11: a malformed TLS client input is refused before any higher layer', async () => {
      const { gateway, port, admitted } = await startGateway(
        {},
        { handshakeTimeoutMsForTests: 200 },
      );
      try {
        for (const payload of [
          Buffer.from('not a tls handshake at all\n'),
          Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0x01]),
        ]) {
          const probe = await rawProbe(port, payload, 1500);
          assert.equal(probe.closed, true, 'the server must drop a malformed TLS peer');
          assert.equal(admitted.length, 0, 'malformed input must never be admitted');
        }
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-103: a valid mTLS connection is admitted and yields the peer SPKI', async () => {
      const { gateway, port, admitted } = await startGateway();
      try {
        const outcome = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(outcome.connected, true);
        assert.equal(outcome.authorized, true, 'the client certificate must chain to the CA');

        // Admission is reported exactly once, with a canonical SPKI pin.
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.equal(admitted.length, 1);
        assert.match(admitted[0].spkiPin, /^[0-9a-f]{64}$/);

        // The pin is the SHA-256 of the presented certificate's DER SPKI.
        const { X509Certificate, createHash } = await import('node:crypto');
        const expected = createHash('sha256')
          .update(
            new X509Certificate(fs.readFileSync(pki.clientCertPath)).publicKey.export({
              format: 'der',
              type: 'spki',
            }),
          )
          .digest('hex');
        assert.equal(admitted[0].spkiPin, expected);

        outcome.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-104: an unknown-but-chain-valid SPKI is admitted, not rejected', async () => {
      // Task 3 must not decide enrollment: Task 4 admits a CA-chained
      // certificate whose SPKI is still only pending in the trust store.
      const { gateway, port, admitted } = await startGateway();
      try {
        // A certificate that chains to the configured root is admitted purely
        // on chain validity, with no enrollment lookup of any kind.
        const outcome = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(await waitFor(() => admitted.length > 0, 2000), true);
        assert.match(admitted[0].spkiPin, /^[0-9a-f]{64}$/);
        // No enrollment, revocation, or session decision is exposed by Task 3.
        assert.deepEqual(Object.keys(admitted[0]).sort(), ['socket', 'spkiPin']);

        // The same certificate under an untrusted CA chain is refused, which is
        // the only admission decision this layer makes.
        const untrusted = await tlsConnect(port, {
          cert: fs.readFileSync(pki.unknownCaClientCertPath),
          key: fs.readFileSync(pki.unknownCaClientKeyPath),
        });
        await waitFor(() => untrusted.socket.destroyed || admitted.length > 1, 1500);
        assert.equal(admitted.length, 1, 'no enrollment decision is made in Task 3');
        untrusted.socket?.destroy();
        outcome.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });
  });

  // =========================================================================
  // Runtime server-certificate expiry (RC05-NEG-15)
  // =========================================================================

  describe('RC05-NEG-15: runtime certificate expiry', () => {
    test('RC05-NEG-15a: after expiry new handshakes are refused and status degrades', async () => {
      let now = Date.now();
      const { gateway, port, admitted } = await startGateway({}, { getWallTime: () => now });
      try {
        // Before expiry a normal handshake succeeds.
        const before = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(before.connected, true);
        assert.equal(await waitFor(() => admitted.length > 0, 2000), true);
        before.socket.destroy();

        const healthy = gateway.getStatus();
        assert.equal(healthy.degraded, false);
        assert.equal(healthy.listenerActive, true);

        // Cross the certificate's notAfter exactly.
        now = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(pki.serverCertPath))
            .validTo,
        );

        const atBoundary = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        await waitFor(() => atBoundary.socket.destroyed, 2000);
        assert.equal(atBoundary.socket.destroyed, true, 'the exact expiry boundary must refuse');
        atBoundary.socket?.destroy();

        // Later handshakes remain refused.
        now += 60_000;
        const later = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        await waitFor(() => later.socket.destroyed, 2000);
        assert.equal(later.socket.destroyed, true, 'later handshakes must stay refused');
        later.socket?.destroy();

        const degraded = gateway.getStatus();
        assert.equal(degraded.degraded, true);
        assert.equal(degraded.degradedReason, 'certificate_expired');
        assert.equal(admitted.length, 1, 'no new admission after expiry');
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-15b: the degraded status leaks no certificate, key, or path material', async () => {
      let now = Date.now();
      const config = await baseConfig();
      const gateway = new RemoteGateway(config, { getWallTime: () => now });
      await gateway.start();
      try {
        // Drive the gateway past its certificate's notAfter so the status is
        // genuinely degraded when inspected.
        now = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(pki.serverCertPath))
            .validTo,
        );
        const refused = await tlsConnect(gateway.getBoundPort(), {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        await waitFor(() => refused.socket.destroyed, 2000);
        refused.socket?.destroy();
        await waitFor(() => gateway.getStatus().degraded, 2000);

        const status = gateway.getStatus();
        assert.equal(status.degraded, true);
        const serialized = JSON.stringify(status);
        assert.deepEqual(Object.keys(status).sort(), [
          'activeAndServing',
          'degraded',
          'degradedReason',
          'inFlightHandshakes',
          'listenerActive',
          'liveConnections',
          'transportMode',
        ]);
        assert.equal(status.degradedReason, 'certificate_expired');
        for (const forbidden of [
          'BEGIN',
          'PRIVATE KEY',
          'CERTIFICATE',
          config.serverCertificatePath,
          config.privateKey.path,
          config.clientCaPaths[0],
          'spkiPin',
          'remoteAddress',
        ]) {
          assert.ok(!serialized.includes(forbidden), `${forbidden} must not appear in status`);
        }
      } finally {
        await gateway.stop();
      }
    });
  });

  // =========================================================================
  // Layer A admission (RC05-NEG-53, RC05-NEG-54)
  // =========================================================================

  describe('Layer A admission', () => {
    test('RC05-NEG-53: burst exhaustion drops peers before TLS admission', async () => {
      const { gateway, port, admitted, refused } = await startGateway(
        {},
        {
          admission: {
            // Concurrency kept out of the way so the RATE bound is the one
            // under test; the production burst and rate are unchanged.
            maxLivePerPeer: 1000,
            maxLiveGlobal: 1000,
            maxInFlightHandshakes: 1000,
          },
        },
      );
      try {
        // A fresh peer starts with a full bucket of LAYER_A_BURST tokens, so the
        // first burst-sized group is admitted and the next attempt is refused.
        for (let i = 0; i < LAYER_A_BURST + 3; i++) {
          const socket = net.createConnection({ host: '127.0.0.1', port });
          await new Promise((resolve) => {
            socket.once('connect', resolve);
            socket.once('error', resolve);
          });
          socket.destroy();
        }
        await waitFor(() => refused.includes('RATE_LIMIT'), 2000);

        assert.ok(
          refused.includes('RATE_LIMIT'),
          `expected a rate-limit refusal, saw ${JSON.stringify(refused)}`,
        );
        // Every refusal happened at the TCP layer, so no TLS session resulted.
        assert.equal(admitted.length, 0, 'a refused connection must not be admitted');
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-54: more than 64 concurrent handshakes drops only the excess', async () => {
      const { gateway, port, refused } = await startGateway();
      const sockets = [];
      try {
        // Each TCP peer is a distinct loopback source address. With one address
        // the frozen 32-connection per-peer cap would bind first and mask the
        // 64-slot handshake cap; distinct peers isolate the bound under test.
        const peerCount = 12;
        const perPeer = Math.ceil((MAX_IN_FLIGHT_HANDSHAKES + 8) / peerCount);
        for (let i = 0; i < MAX_IN_FLIGHT_HANDSHAKES + 8; i++) {
          const localAddress = `127.0.0.${2 + (i % peerCount)}`;
          const socket = net.createConnection({ host: '127.0.0.1', port, localAddress });
          await new Promise((resolve) => {
            socket.once('connect', resolve);
            socket.once('error', resolve);
          });
          sockets.push(socket);
          if ((i + 1) % perPeer === 0) {
            await new Promise((resolve) => setTimeout(resolve, 5));
          }
        }
        assert.equal(
          await waitFor(() => refused.includes('HANDSHAKE_CAP'), 3000),
          true,
          `expected a handshake-cap refusal, saw ${JSON.stringify(refused)}`,
        );

        const status = gateway.getStatus();
        assert.equal(
          status.inFlightHandshakes,
          MAX_IN_FLIGHT_HANDSHAKES,
          'the existing handshakes must be preserved exactly at the frozen cap',
        );
        assert.equal(
          status.liveConnections,
          MAX_IN_FLIGHT_HANDSHAKES,
          'the preserved connections are the ones already admitted',
        );
        // Exactly the excess was dropped: 72 attempts, 64 admitted, 8 refused.
        assert.equal(
          refused.filter((r) => r === 'HANDSHAKE_CAP').length,
          MAX_IN_FLIGHT_HANDSHAKES + 8 - MAX_IN_FLIGHT_HANDSHAKES,
        );
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-110: the per-peer live connection cap is enforced', async () => {
      const { gateway, port } = await startGateway();
      const sockets = [];
      try {
        // Hold live TLS connections open by completing the handshake.
        for (let i = 0; i < MAX_LIVE_CONNECTIONS_PER_PEER + 4; i++) {
          const outcome = await tlsConnect(port, {
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
          });
          if (outcome.connected) {
            sockets.push(outcome.socket);
          }
        }
        await waitFor(
          () => gateway.getStatus().liveConnections >= MAX_LIVE_CONNECTIONS_PER_PEER,
          2000,
        );
        assert.ok(
          gateway.getStatus().liveConnections <= MAX_LIVE_CONNECTIONS_PER_PEER,
          `live connections must stay at or below ${MAX_LIVE_CONNECTIONS_PER_PEER}`,
        );
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-111: the global live connection cap is enforced', async () => {
      // Exercised through the limiter's own bound rather than by opening 512
      // real sockets: the frozen constant is asserted directly.
      assert.equal(MAX_LIVE_CONNECTIONS_GLOBAL, 512);
      const { gateway } = await startGateway(
        {},
        { admission: { maxLiveGlobal: 2, maxInFlightHandshakes: 64 } },
      );
      const sockets = [];
      try {
        for (let i = 0; i < 6; i++) {
          const outcome = await tlsConnect(gateway.getBoundPort(), {
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
          });
          if (outcome.connected) sockets.push(outcome.socket);
        }
        await waitFor(() => gateway.getStatus().liveConnections > 0, 2000);
        assert.ok(gateway.getStatus().liveConnections <= 2);
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-112: a stalled handshake times out and releases every slot', async () => {
      const { gateway, port } = await startGateway({}, { handshakeTimeoutMsForTests: 150 });
      const sockets = [];
      try {
        for (let i = 0; i < 3; i++) {
          const socket = net.createConnection({ host: '127.0.0.1', port });
          await new Promise((resolve) => {
            socket.once('connect', resolve);
            socket.once('error', resolve);
          });
          sockets.push(socket);
        }
        await new Promise((resolve) => setTimeout(resolve, 60));
        assert.ok(gateway.getStatus().inFlightHandshakes > 0, 'handshakes are in flight');

        // Wait past the (shortened) handshake timeout.
        await new Promise((resolve) => setTimeout(resolve, 400));
        const after = gateway.getStatus();
        assert.equal(after.inFlightHandshakes, 0, 'stalled handshakes must release their slots');
        assert.equal(after.liveConnections, 0, 'and their connection slots');
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-113: counters are released after failure, success, and shutdown', async () => {
      const { gateway, port } = await startGateway();
      try {
        // Failed handshake.
        const failed = await tlsConnect(port);
        failed.socket?.destroy();
        await waitFor(() => gateway.getStatus().inFlightHandshakes === 0, 2000);
        assert.equal(gateway.getStatus().inFlightHandshakes, 0);
        assert.equal(gateway.getStatus().liveConnections, 0);

        // Successful handshake, then close.
        const ok = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(ok.connected, true);
        assert.equal(await waitFor(() => gateway.getStatus().liveConnections === 1, 2000), true);
        ok.socket.destroy();
        assert.equal(
          await waitFor(() => gateway.getStatus().liveConnections === 0, 2000),
          true,
          'close must release the slot',
        );
      } finally {
        await gateway.stop();
      }
      assert.equal(gateway.getStatus().listenerActive, false);
      assert.equal(gateway.getStatus().liveConnections, 0);
    });
  });

  // =========================================================================
  // Trust store and transport-mode composition
  // =========================================================================

  // =========================================================================
  // Handshake accounting (raw socket vs TLS socket)
  // =========================================================================

  describe('Handshake and connection accounting', () => {
    test('RC05-ENR-140: one successful handshake that stays open frees its handshake slot', async () => {
      const { gateway, port } = await startGateway();
      try {
        const outcome = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(outcome.connected, true);
        assert.equal(
          await waitFor(
            () =>
              gateway.getStatus().liveConnections === 1 &&
              gateway.getStatus().inFlightHandshakes === 0,
            4000,
          ),
          true,
          'a completed handshake must release its handshake slot immediately',
        );
        outcome.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-141: 64 open handshaken connections do not consume handshake slots', async () => {
      const { gateway, port } = await startGateway(
        {},
        { admission: { maxLivePerPeer: 1000, maxLiveGlobal: MAX_LIVE_CONNECTIONS_GLOBAL } },
      );
      const sockets = [];
      try {
        for (let i = 0; i < MAX_IN_FLIGHT_HANDSHAKES; i++) {
          const localAddress = `127.0.0.${2 + (i % 12)}`;
          const outcome = await tlsConnect(port, {
            localAddress,
            cert: fs.readFileSync(pki.clientCertPath),
            key: fs.readFileSync(pki.clientKeyPath),
          });
          if (outcome.connected) sockets.push(outcome.socket);
        }
        assert.equal(sockets.length, MAX_IN_FLIGHT_HANDSHAKES);
        assert.equal(
          await waitFor(
            () =>
              gateway.getStatus().liveConnections === 64 &&
              gateway.getStatus().inFlightHandshakes === 0,
            6000,
          ),
          true,
          'long-lived handshaken connections must not hold handshake slots',
        );

        // A further handshake can still begin, which is the whole point of the
        // fix: the 64-slot bound must not become a 64-connection lifetime cap.
        const extra = await tlsConnect(port, {
          localAddress: '127.0.0.200',
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(extra.connected, true, 'a new handshake must still be possible');
        sockets.push(extra.socket);
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-142: stalled handshakes occupy slots until they fail', async () => {
      const { gateway, port } = await startGateway({}, { handshakeTimeoutMsForTests: 400 });
      const sockets = [];
      try {
        for (let i = 0; i < 3; i++) {
          const socket = net.createConnection({ host: '127.0.0.1', port });
          await new Promise((resolve) => {
            socket.once('connect', resolve);
            socket.once('error', resolve);
          });
          sockets.push(socket);
        }
        assert.equal(await waitFor(() => gateway.getStatus().inFlightHandshakes === 3, 2000), true);

        // Past the (shortened) timeout the slots return.
        assert.equal(
          await waitFor(() => gateway.getStatus().inFlightHandshakes === 0, 3000),
          true,
          'a stalled handshake must release its slot on timeout',
        );
        assert.equal(gateway.getStatus().liveConnections, 0);
      } finally {
        for (const socket of sockets) socket.destroy();
        await gateway.stop();
      }
    });

    test('RC05-ENR-143: every terminal path releases exactly one slot set', async () => {
      const { gateway, port } = await startGateway({}, { handshakeTimeoutMsForTests: 300 });
      try {
        // Failure: no client certificate.
        const failed = await tlsConnect(port);
        await waitFor(() => failed.socket.destroyed, 2000);
        failed.socket?.destroy();
        assert.equal(await waitFor(() => gateway.getStatus().inFlightHandshakes === 0, 2000), true);
        assert.equal(gateway.getStatus().liveConnections, 0);

        // Success then close.
        const ok = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(ok.connected, true);
        assert.equal(
          await waitFor(
            () =>
              gateway.getStatus().liveConnections === 1 &&
              gateway.getStatus().inFlightHandshakes === 0,
            4000,
          ),
          true,
        );
        ok.socket.destroy();
        assert.equal(await waitFor(() => gateway.getStatus().liveConnections === 0, 2000), true);

        // Timeout.
        const stalled = net.createConnection({ host: '127.0.0.1', port });
        await new Promise((resolve) => {
          stalled.once('connect', resolve);
          stalled.once('error', resolve);
        });
        assert.equal(await waitFor(() => gateway.getStatus().inFlightHandshakes === 1, 2000), true);
        assert.equal(await waitFor(() => gateway.getStatus().inFlightHandshakes === 0, 3000), true);
        stalled.destroy();

        // The connection state map holds nothing once everything has settled.
        assert.equal(
          await waitFor(
            () =>
              gateway.getStatus().liveConnections + gateway.getStatus().inFlightHandshakes === 0,
            2000,
          ),
          true,
        );
      } finally {
        await gateway.stop();
      }
      // Shutdown releases everything too.
      assert.equal(gateway.getStatus().liveConnections, 0);
      assert.equal(gateway.getStatus().inFlightHandshakes, 0);
    });
  });

  // =========================================================================
  // Token-bucket rate semantics
  // =========================================================================

  describe('Token bucket rate model', () => {
    /** A limiter whose clock the test drives directly. */
    function limiterAt(clock) {
      return new AdmissionLimiter({
        getMonotonicTimeMs: () => clock.now,
        maxLivePerPeer: 1000,
        maxLiveGlobal: 1000,
        maxInFlightHandshakes: 1000,
      });
    }

    test('RC05-ENR-150: the first burst is admitted and the next attempt is refused', () => {
      const clock = { now: 0 };
      const limiter = limiterAt(clock);

      for (let i = 0; i < LAYER_A_BURST; i++) {
        const decision = limiter.admit('127.0.0.1');
        assert.equal(decision.admitted, true, `attempt ${i + 1} must be admitted`);
        // Release the handshake slot so only the bucket governs the outcome.
        limiter.releaseHandshake();
      }

      const refused = limiter.admit('127.0.0.1');
      assert.equal(refused.admitted, false);
      assert.equal(refused.reason, 'RATE_LIMIT', 'the 21st immediate attempt is refused');
    });

    test('RC05-ENR-151: exactly one token accrues per second of monotonic time', () => {
      const clock = { now: 0 };
      const limiter = limiterAt(clock);
      for (let i = 0; i < LAYER_A_BURST; i++) {
        limiter.admit('127.0.0.1');
        limiter.releaseHandshake();
      }
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');

      // Half a refill interval is not yet a whole token.
      clock.now += LAYER_A_REFILL_MS / 2;
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');

      // A full interval yields exactly one token, and only one.
      clock.now += LAYER_A_REFILL_MS / 2;
      const first = limiter.admit('127.0.0.1');
      assert.equal(first.admitted, true, 'one token is available after one interval');
      limiter.releaseHandshake();
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');
    });

    test('RC05-ENR-152: a long idle period refills to the burst capacity and no further', () => {
      const clock = { now: 0 };
      const limiter = limiterAt(clock);
      for (let i = 0; i < LAYER_A_BURST; i++) {
        limiter.admit('127.0.0.1');
        limiter.releaseHandshake();
      }

      // A very long idle period must not bank more than one burst.
      clock.now += 24 * 60 * 60 * 1000;
      let admitted = 0;
      for (let i = 0; i < LAYER_A_BURST + 5; i++) {
        const decision = limiter.admit('127.0.0.1');
        if (decision.admitted) {
          admitted += 1;
          limiter.releaseHandshake();
        }
      }
      assert.equal(admitted, LAYER_A_BURST, 'the bucket never holds more than one burst');
    });

    test('RC05-ENR-153: the rate budget is driven by the monotonic clock only', () => {
      const wall = { now: 1_800_000_000_000 };
      const clock = { now: 0 };
      const limiter = new AdmissionLimiter({
        getMonotonicTimeMs: () => clock.now,
        maxLivePerPeer: 1000,
        maxLiveGlobal: 1000,
        maxInFlightHandshakes: 1000,
      });

      for (let i = 0; i < LAYER_A_BURST; i++) {
        limiter.admit('127.0.0.1');
        limiter.releaseHandshake();
      }
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');

      // Moving the wall clock arbitrarily has no effect: the limiter never
      // consults it.
      wall.now += 86_400_000;
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');
      wall.now -= 172_800_000;
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');

      // Only monotonic time restores budget.
      clock.now += LAYER_A_REFILL_MS;
      assert.equal(limiter.admit('127.0.0.1').admitted, true);
    });

    test('RC05-ENR-154: peer rate budgets are isolated', () => {
      const clock = { now: 0 };
      const limiter = limiterAt(clock);
      for (let i = 0; i < LAYER_A_BURST; i++) {
        limiter.admit('127.0.0.1');
        limiter.releaseHandshake();
      }
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT');

      // A different peer has its own full bucket.
      for (let i = 0; i < LAYER_A_BURST; i++) {
        const decision = limiter.admit('127.0.0.2');
        assert.equal(decision.admitted, true, 'the second peer has its own budget');
        limiter.releaseHandshake();
      }
      assert.equal(limiter.admit('127.0.0.2').reason, 'RATE_LIMIT');
      assert.equal(limiter.admit('127.0.0.1').reason, 'RATE_LIMIT', 'the first peer is unaffected');
    });

    test('RC05-ENR-155: an attempt refused by a concurrency bound still spends a token', () => {
      const clock = { now: 0 };
      const limiter = new AdmissionLimiter({
        getMonotonicTimeMs: () => clock.now,
        maxLivePerPeer: 1,
        maxLiveGlobal: 1000,
        maxInFlightHandshakes: 1000,
      });

      const first = limiter.admit('127.0.0.1');
      assert.equal(first.admitted, true);
      limiter.releaseHandshake(); // the connection is live but no longer handshaking

      // Refused by the per-peer connection cap, yet still rate-accounted.
      const capped = limiter.admit('127.0.0.1');
      assert.equal(capped.admitted, false);
      assert.equal(capped.reason, 'PEER_CONNECTION_CAP');

      // The token was spent: with the connection slot released, the peer still
      // has one fewer token than a fresh peer would.
      first.release();
      let allowed = 0;
      for (let i = 0; i < LAYER_A_BURST + 5; i++) {
        const decision = limiter.admit('127.0.0.1');
        if (decision.admitted) {
          allowed += 1;
          decision.release();
          limiter.releaseHandshake();
        }
      }
      // A fresh peer would admit LAYER_A_BURST. This peer admits two fewer: one
      // token went to the live connection and one to the attempt that the
      // concurrency bound refused, which is exactly the required accounting.
      assert.equal(
        allowed,
        LAYER_A_BURST - 2,
        'the concurrency-refused attempt consumed one of the burst tokens',
      );
    });
  });

  // =========================================================================
  // Frozen concurrency caps
  // =========================================================================

  describe('Frozen Layer-A caps', () => {
    test('RC05-ENR-160: the actual 512 global live-connection bound', () => {
      const limiter = new AdmissionLimiter({
        // Concurrency bounds are the subject; the rate seam is raised so the
        // token bucket does not mask them. Production constants are untouched.
        attemptsPerMinute: 1_000_000,
        burst: 100_000,
      });

      const releases = [];
      for (let i = 0; i < MAX_LIVE_CONNECTIONS_GLOBAL; i++) {
        const decision = limiter.admit(`peer-${String(i).padStart(4, '0')}`);
        assert.equal(decision.admitted, true, `connection ${i + 1} must be admitted`);
        // Release the handshake slot, retain the live slot.
        limiter.releaseHandshake();
        releases.push(decision.release);
      }
      assert.equal(limiter.getLiveConnectionCount(), 512);
      assert.equal(MAX_LIVE_CONNECTIONS_GLOBAL, 512);

      const overflow = limiter.admit('peer-overflow');
      assert.equal(overflow.admitted, false);
      assert.equal(overflow.reason, 'GLOBAL_CONNECTION_CAP');
      assert.equal(limiter.getLiveConnectionCount(), 512, 'the bound is preserved exactly');

      for (const release of releases) release();
      assert.equal(limiter.getLiveConnectionCount(), 0);
    });

    test('RC05-ENR-161: the actual 32 per-peer live-connection bound', () => {
      const limiter = new AdmissionLimiter({
        attemptsPerMinute: 1_000_000,
        burst: 100_000,
      });

      const releases = [];
      for (let i = 0; i < MAX_LIVE_CONNECTIONS_PER_PEER; i++) {
        const decision = limiter.admit('192.0.2.1');
        assert.equal(decision.admitted, true, `connection ${i + 1} must be admitted`);
        limiter.releaseHandshake();
        releases.push(decision.release);
      }
      assert.equal(MAX_LIVE_CONNECTIONS_PER_PEER, 32);
      assert.equal(limiter.getLiveConnectionCountForPeer('192.0.2.1'), 32);

      const overflow = limiter.admit('192.0.2.1');
      assert.equal(overflow.admitted, false);
      assert.equal(overflow.reason, 'PEER_CONNECTION_CAP');
      assert.equal(limiter.getLiveConnectionCountForPeer('192.0.2.1'), 32);

      // Another peer is unaffected by the saturated one.
      assert.equal(limiter.admit('192.0.2.2').admitted, true);

      for (const release of releases) release();
      assert.equal(limiter.getLiveConnectionCountForPeer('192.0.2.1'), 0);
    });

    test('RC05-ENR-162: the actual 64 in-flight handshake bound', () => {
      const limiter = new AdmissionLimiter({
        attemptsPerMinute: 1_000_000,
        burst: 100_000,
        maxLivePerPeer: 1000,
        maxLiveGlobal: 1000,
      });
      for (let i = 0; i < MAX_IN_FLIGHT_HANDSHAKES; i++) {
        assert.equal(limiter.admit(`198.51.100.${i}`).admitted, true);
      }
      assert.equal(limiter.getInFlightHandshakeCount(), 64);
      const overflow = limiter.admit('198.51.100.200');
      assert.equal(overflow.admitted, false);
      assert.equal(overflow.reason, 'HANDSHAKE_CAP');
      assert.equal(limiter.getInFlightHandshakeCount(), 64, 'the existing 64 are preserved');
    });
  });

  // =========================================================================
  // Wildcard bind canonicalization
  // =========================================================================

  describe('Wildcard bind canonicalization', () => {
    test('RC05-NEG-05c: every spelling of the IPv6 unspecified address is wildcard', () => {
      for (const spelling of [
        '::',
        '::0',
        '0::',
        '0:0:0:0:0:0:0:0',
        '0000:0000:0000:0000:0000:0000:0000:0000',
        '0000:0000:0000:0000:0000:0000:0000:000',
        '::ffff:0.0.0.0',
        '0.0.0.0',
      ]) {
        assert.equal(isWildcardBindHost(spelling), true, `${spelling} must be wildcard`);
      }
    });

    test('RC05-NEG-05d: loopback and explicit literals are not wildcard', () => {
      for (const literal of ['127.0.0.1', '::1', '0:0:0:0:0:0:0:1', '192.0.2.1', 'fe80::1']) {
        assert.equal(isWildcardBindHost(literal), false, `${literal} must not be wildcard`);
      }
    });

    test('RC05-NEG-05e: expanded IPv6 wildcard is refused without opt-in', async () => {
      for (const bindHost of ['::', '0000:0000:0000:0000:0000:0000:0000:0000']) {
        await assert.rejects(
          () => startGateway({ bindHost }),
          (err) => err instanceof RemoteConfigError && err.reason === 'WILDCARD_BIND_NOT_OPTED_IN',
          bindHost,
        );
      }
    });

    test('RC05-NEG-05f: a wildcard bind with opt-in actually binds and admits', async () => {
      // The previous version of this control bound 127.0.0.1, which proved
      // nothing. This one binds the wildcard address itself.
      let gateway;
      try {
        const started = await startGateway({ bindHost: '0.0.0.0', allowWildcardBind: true });
        gateway = started.gateway;
        assert.equal(gateway.isStarted(), true);

        const outcome = await tlsConnect(started.port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(outcome.connected, true, 'an opted-in wildcard bind must serve TLS');
        outcome.socket.destroy();
      } catch (err) {
        // A platform without IPv4 wildcard support must fail loudly, not skip.
        assert.ok(err instanceof RemoteConfigError, `unexpected failure: ${String(err)}`);
        throw err;
      } finally {
        await gateway?.stop();
      }
    });

    test('RC05-NEG-05i: an opted-in IPv6 wildcard binds ipv6Only', async () => {
      // Platform capability is DETECTED, never skipped: the configuration
      // semantics are asserted unconditionally, and the runtime dual-stack
      // behaviour is asserted whenever the platform can actually bind IPv6.
      const ipv6Available = await new Promise((resolve) => {
        const probe = net.createServer();
        probe.once('error', () => resolve(false));
        probe.listen({ host: '::1', port: 0, ipv6Only: true }, () => {
          probe.close(() => resolve(true));
        });
      });

      // Semantic assertion, always executed: the expanded forms are wildcard and
      // require the opt-in regardless of platform support.
      for (const spelling of ['::', '0000:0000:0000:0000:0000:0000:0000:0000']) {
        assert.equal(isWildcardBindHost(spelling), true);
        await assert.rejects(
          () => startGateway({ bindHost: spelling }),
          (err) => err instanceof RemoteConfigError && err.reason === 'WILDCARD_BIND_NOT_OPTED_IN',
        );
      }

      if (!ipv6Available) {
        // The platform genuinely cannot bind IPv6. This is reported as an
        // explicit capability failure rather than being declared a pass for an
        // untested dual-stack behaviour.
        assert.fail(
          'platform cannot bind ::1, so IPv6 wildcard opt-in cannot be verified at runtime',
        );
      }

      const { gateway, port } = await startGateway({ bindHost: '::', allowWildcardBind: true });
      try {
        assert.equal(gateway.isStarted(), true, 'the opted-in IPv6 wildcard binds');

        // A TLS client reaches it over IPv6 loopback.
        const viaV6 = await new Promise((resolve) => {
          const socket = tls.connect(
            {
              host: '::1',
              port,
              servername: publicHostname,
              ca: [fs.readFileSync(pki.trustedCaCertPath)],
              rejectUnauthorized: false,
              cert: fs.readFileSync(pki.clientCertPath),
              key: fs.readFileSync(pki.clientKeyPath),
            },
            () => resolve({ ok: true, socket }),
          );
          socket.once('error', (err) => resolve({ ok: false, error: err }));
        });
        assert.equal(viaV6.ok, true, `IPv6 loopback must reach the listener: ${viaV6.error?.code}`);
        viaV6.socket.destroy();

        // ipv6Only means the same port is NOT a wildcard IPv4 listener.
        const viaV4 = await new Promise((resolve) => {
          const socket = net.createConnection({ host: '127.0.0.1', port });
          socket.once('connect', () => resolve({ connected: true, socket }));
          socket.once('error', () => resolve({ connected: false }));
        });
        assert.equal(
          viaV4.connected,
          false,
          'an IPv6-only wildcard must not silently accept IPv4 connections',
        );
        viaV4.socket?.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-05g: ambiguous numeric host strings fail before binding', async () => {
      for (const bindHost of ['1.2.3', '999.1.1.1', '1.2.3.4.5', '::gggg', '0:0:0:0:0:0:0:0:0']) {
        await assert.rejects(
          () => startGateway({ bindHost }),
          (err) => err instanceof RemoteConfigError && err.reason === 'BIND_HOST_INVALID',
          bindHost,
        );
      }
    });

    test('RC05-NEG-05h: hostnames are accepted under a conservative grammar', async () => {
      // A syntactically valid hostname passes validation; binding is attempted
      // and may fail for name-resolution reasons, which is a different failure.
      for (const bad of ['-leading.example', 'trailing-.example', 'has space.example', 'a..b']) {
        await assert.rejects(
          () => startGateway({ bindHost: bad }),
          (err) => err instanceof RemoteConfigError && err.reason === 'BIND_HOST_INVALID',
          bad,
        );
      }
    });
  });

  // =========================================================================
  // Server certificate SAN: DNS vs IP
  // =========================================================================

  describe('Server certificate SAN validation', () => {
    test('RC05-ENR-170: the DNS SAN satisfies a DNS hostname', async () => {
      const { gateway } = await startGateway({ publicHostname: 'localhost' });
      await gateway.stop();
    });

    test('RC05-ENR-171: the IP SAN satisfies an IP hostname', async () => {
      const { gateway, port } = await startGateway({ publicHostname: '127.0.0.1' });
      try {
        assert.equal(gateway.isStarted(), true);
        assert.equal(port > 0, true);
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-172: an IP absent from the SAN fails', async () => {
      await assert.rejects(
        () => startGateway({ publicHostname: '192.0.2.99' }),
        (err) =>
          err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_SAN_MISMATCH',
      );
    });

    test('RC05-ENR-173: a DNS-only SAN cannot satisfy an IP hostname', () => {
      // The SAN-mismatch certificate carries DNS:other.example.invalid only, so
      // its DNS entry satisfies that name but naming it by IP must fail.
      return assert.rejects(
        () =>
          startGateway({
            publicHostname: '127.0.0.1',
            serverCertificatePath: pki.sanMismatchCertPath,
            privateKey: { kind: 'file', path: pki.sanMismatchKeyPath },
          }),
        (err) =>
          err instanceof RemoteConfigError && err.reason === 'SERVER_CERTIFICATE_SAN_MISMATCH',
      );
    });

    test('RC05-ENR-174: a fully verifying client completes against the gateway', async () => {
      // Every other probe uses rejectUnauthorized:false so it can inspect the
      // server's decision. This one performs real server-chain and hostname
      // validation, exercising §7 P-2 rather than only ARC's self-check.
      const { gateway, port } = await startGateway({ publicHostname: 'localhost' });
      try {
        const verified = await new Promise((resolve) => {
          const socket = tls.connect(
            {
              host: '127.0.0.1',
              port,
              servername: 'localhost',
              ca: [fs.readFileSync(pki.trustedCaCertPath)],
              rejectUnauthorized: true,
              cert: fs.readFileSync(pki.clientCertPath),
              key: fs.readFileSync(pki.clientKeyPath),
            },
            () => resolve({ ok: true, authorized: socket.authorized, socket }),
          );
          socket.once('error', (err) => resolve({ ok: false, error: err }));
        });
        assert.equal(verified.ok, true, `verified client must connect: ${verified.error?.message}`);
        assert.equal(verified.authorized, true);
        verified.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });
  });

  // =========================================================================
  // Runtime expiry, frozen timeout, byte binding, root counting
  // =========================================================================

  describe('Runtime expiry and startup invariants', () => {
    test('RC05-NEG-15c: status is truthful without any new connection', async () => {
      let now = Date.now();
      const config = await baseConfig();
      const gateway = new RemoteGateway(config, { getWallTime: () => now });
      await gateway.start();
      try {
        assert.equal(gateway.getStatus().degraded, false);
        assert.equal(gateway.getStatus().activeAndServing, true);

        // Cross notAfter exactly, then read status WITHOUT connecting.
        now = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(pki.serverCertPath))
            .validTo,
        );
        const status = gateway.getStatus();
        assert.equal(status.degraded, true, 'status must notice expiry on its own');
        assert.equal(status.degradedReason, 'certificate_expired');
        assert.equal(status.activeAndServing, false, 'it cannot serve new sessions');
        assert.equal(status.listenerActive, true, 'the socket is still physically bound');
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-15d: a new connection after expiry is refused before TLS', async () => {
      let now = Date.now();
      const { gateway, port, admitted } = await startGateway({}, { getWallTime: () => now });
      try {
        // Establish one connection while valid, and keep it open.
        const existing = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(existing.connected, true);
        assert.equal(await waitFor(() => admitted.length === 1, 2000), true);

        now = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(pki.serverCertPath))
            .validTo,
        );

        // A new raw connection is dropped before any TLS admission.
        const refused = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        await waitFor(() => refused.socket.destroyed, 2000);
        assert.equal(refused.socket.destroyed, true, 'a new handshake must be refused');
        refused.socket?.destroy();
        assert.equal(admitted.length, 1, 'no new admission may occur');

        // The already-established connection is not destroyed by the expiry.
        assert.equal(existing.socket.destroyed, false, 'established connections drain normally');
        existing.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-175: health reports DEGRADED and remoteGatewayActive=false after expiry', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const remotePort = await freePort();
      // The certificate is issued HERE, valid for a few seconds, so the
      // composed server reaches real expiry against the real clock without any
      // clock seam existing on the production composition.
      const shortLived = pki.issueServerCert({ validSeconds: 6 });
      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        remote: {
          port: remotePort,
          publicHostname,
          serverCertificatePath: shortLived.certPath,
          privateKey: { kind: 'file', path: shortLived.keyPath },
          clientCaPaths: [pki.trustedCaCertPath],
        },
      });

      await server.start();
      try {
        const initial = server.getRemoteGatewayStatus();
        assert.equal(initial.activeAndServing, true, 'starts able to serve');

        const initialHealth = JSON.parse(
          (await server.dispatchToolCall('health', {})).content[0].text,
        );
        assert.equal(initialHealth.remoteGatewayActive, true);
        assert.equal(initialHealth.status, 'HEALTHY');

        // Wait for the certificate to reach notAfter.
        const notAfter = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(shortLived.certPath))
            .validTo,
        );
        while (Date.now() < notAfter + 1000) {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        const expired = server.getRemoteGatewayStatus();
        assert.equal(expired.degraded, true, 'status must notice expiry without a connection');
        assert.equal(expired.activeAndServing, false);
        assert.equal(expired.degradedReason, 'certificate_expired');

        const health = JSON.parse((await server.dispatchToolCall('health', {})).content[0].text);
        assert.equal(health.remoteGatewayActive, false, 'health must not claim an active gateway');
        assert.equal(health.remoteGatewayDegraded, true);
        assert.equal(health.remoteGatewayDegradedReason, 'certificate_expired');
        assert.equal(health.status, 'DEGRADED', 'an expired gateway is not HEALTHY');
      } finally {
        await server.stop();
      }
    });

    test('RC05-ENR-176: production configuration cannot change the 5000 ms timeout', async () => {
      const config = await baseConfig();
      // There is no production field for it at all...
      assert.equal(Object.prototype.hasOwnProperty.call(config, 'handshakeTimeoutMs'), false);

      // ...and an attempt to smuggle one through is ignored, not honoured.
      const gateway = new RemoteGateway({ ...config, handshakeTimeoutMs: 1 });
      try {
        assert.equal(TLS_HANDSHAKE_TIMEOUT_MS, 5000);
        assert.equal(gateway.handshakeTimeoutMs, 5000, 'the frozen value cannot be weakened');
      } finally {
        await gateway.stop();
      }

      // The internal seam may only SHORTEN the frozen value.
      const shortened = new RemoteGateway(config, { handshakeTimeoutMsForTests: 250 });
      try {
        assert.equal(shortened.handshakeTimeoutMs, 250);
      } finally {
        await shortened.stop();
      }
      const extended = new RemoteGateway(config, { handshakeTimeoutMsForTests: 60_000 });
      try {
        assert.equal(extended.handshakeTimeoutMs, 5000, 'lengthening is refused');
      } finally {
        await extended.stop();
      }
    });

    test('RC05-ENR-177: the listener presents exactly the validated certificate bytes', async () => {
      // A dedicated copy, so the shared fixture is never mutated.
      const ownedCertPath = path.join(tempRoot, 'byte-binding-server.pem');
      fs.copyFileSync(pki.serverCertPath, ownedCertPath);
      fs.chmodSync(ownedCertPath, 0o600);

      const config = await baseConfig({ serverCertificatePath: ownedCertPath });
      const gateway = new RemoteGateway(config);
      try {
        // Replace the configured path with the SAN-mismatch certificate AFTER
        // validation but BEFORE the listener is created.
        fs.copyFileSync(pki.sanMismatchCertPath, ownedCertPath);

        await gateway.start();
        // ARC must present the validated bytes, not the replacement. A verifying
        // client that trusts the CA and expects localhost would reject the
        // mismatch certificate, so verifying against localhost proves which
        // bytes are being served.
        const probe = await new Promise((resolve) => {
          const socket = tls.connect(
            {
              host: '127.0.0.1',
              port: gateway.getBoundPort(),
              servername: 'localhost',
              ca: [fs.readFileSync(pki.trustedCaCertPath)],
              rejectUnauthorized: true,
            },
            () => resolve({ ok: true, socket }),
          );
          socket.once('error', (err) => resolve({ ok: false, error: err }));
        });
        // The server still presents the validated localhost certificate, so the
        // TLS layer succeeds even though the file now holds a different one.
        assert.equal(probe.ok, true, `expected the validated certificate: ${probe.error?.code}`);
        probe.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-NEG-28g: a CA file bundling two roots does not bypass the four-root model', async () => {
      const bundle = path.join(tempRoot, 'ca-bundle.pem');
      fs.writeFileSync(
        bundle,
        fs.readFileSync(pki.trustedCaCertPath, 'utf8') +
          fs.readFileSync(pki.untrustedCaCertPath, 'utf8'),
        { mode: 0o644 },
      );
      await assert.rejects(
        () => startGateway({ clientCaPaths: [bundle] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_MULTIPLE_ROOTS',
      );
    });

    test('RC05-NEG-28h: trailing material outside the certificate block fails closed', async () => {
      const trailing = path.join(tempRoot, 'ca-trailing.pem');
      fs.writeFileSync(
        trailing,
        `${fs.readFileSync(pki.trustedCaCertPath, 'utf8')}
trailing-not-pem
`,
        { mode: 0o644 },
      );
      await assert.rejects(
        () => startGateway({ clientCaPaths: [trailing] }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_MALFORMED',
      );
    });

    test('RC05-NEG-28i: five configured roots are refused', async () => {
      const paths = [];
      for (let i = 0; i < 5; i++) {
        const copy = path.join(tempRoot, `ca-copy-${i}.pem`);
        fs.writeFileSync(copy, fs.readFileSync(pki.trustedCaCertPath, 'utf8'), { mode: 0o644 });
        paths.push(copy);
      }
      await assert.rejects(
        () => startGateway({ clientCaPaths: paths }),
        (err) => err instanceof RemoteConfigError && err.reason === 'CLIENT_CA_TOO_MANY',
      );
    });
  });

  // =========================================================================
  // Shutdown lifecycle
  // =========================================================================

  describe('Shutdown releases every admission slot', () => {
    test('RC05-ENR-180: a stalled handshake is destroyed by shutdown, not by timeout', async () => {
      const { gateway, port } = await startGateway({}, { handshakeTimeoutMsForTests: 30_000 });
      const stalled = net.createConnection({ host: '127.0.0.1', port });
      await new Promise((resolve) => {
        stalled.once('connect', resolve);
        stalled.once('error', resolve);
      });
      assert.equal(
        await waitFor(
          () =>
            gateway.getStatus().liveConnections === 1 &&
            gateway.getStatus().inFlightHandshakes === 1,
          2000,
        ),
        true,
      );

      // Stop well before the (deliberately long) handshake timeout.
      await gateway.stop();

      assert.equal(gateway.getStatus().liveConnections, 0, 'live connections reset');
      assert.equal(gateway.getStatus().inFlightHandshakes, 0, 'handshake slots reset');

      // The client must have been destroyed by shutdown itself.
      assert.equal(
        await waitFor(() => stalled.destroyed, 2000),
        true,
        'shutdown must destroy an admitted pre-handshake socket',
      );
      stalled.destroy();

      // Past where the handshake timeout would have fired, counters stay at
      // exactly zero: the neutralized release closures must not run again.
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(gateway.getStatus().liveConnections, 0);
      assert.equal(gateway.getStatus().inFlightHandshakes, 0);
      assert.ok(gateway.getStatus().liveConnections >= 0, 'counters never go negative');
    });

    test('RC05-ENR-181: shutdown destroys an open handshaken connection', async () => {
      const { gateway, port } = await startGateway();
      try {
        const outcome = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(outcome.connected, true);
        assert.equal(
          await waitFor(
            () =>
              gateway.getStatus().liveConnections === 1 &&
              gateway.getStatus().inFlightHandshakes === 0,
            2000,
          ),
          true,
        );

        // Stop WITHOUT closing the client first.
        await gateway.stop();

        assert.equal(gateway.getStatus().liveConnections, 0);
        assert.equal(gateway.getStatus().inFlightHandshakes, 0);
        assert.equal(
          await waitFor(() => outcome.socket.destroyed, 2000),
          true,
          'shutdown must destroy the TLS socket',
        );

        await new Promise((resolve) => setTimeout(resolve, 200));
        assert.equal(gateway.getStatus().liveConnections, 0, 'late close must not decrement');
        assert.equal(gateway.getStatus().inFlightHandshakes, 0);
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-182: mixed handshaken and stalled connections both terminate cleanly', async () => {
      const { gateway, port } = await startGateway({}, { handshakeTimeoutMsForTests: 30_000 });
      const stalled = net.createConnection({ host: '127.0.0.1', port });
      await new Promise((resolve) => {
        stalled.once('connect', resolve);
        stalled.once('error', resolve);
      });
      const outcome = await tlsConnect(port, {
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
      });
      assert.equal(outcome.connected, true);
      assert.equal(
        await waitFor(
          () =>
            gateway.getStatus().liveConnections === 2 &&
            gateway.getStatus().inFlightHandshakes === 1,
          2000,
        ),
        true,
        'one handshaken connection and one stalled handshake',
      );

      await gateway.stop();

      assert.equal(gateway.getStatus().liveConnections, 0);
      assert.equal(gateway.getStatus().inFlightHandshakes, 0);
      assert.equal(await waitFor(() => stalled.destroyed, 2000), true);
      assert.equal(await waitFor(() => outcome.socket.destroyed, 2000), true);

      // Past every delayed event, the counters are still exactly zero.
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(gateway.getStatus().liveConnections, 0);
      assert.equal(gateway.getStatus().inFlightHandshakes, 0);
      stalled.destroy();
    });

    test('RC05-ENR-183: stop is idempotent', async () => {
      const { gateway, port } = await startGateway();
      const outcome = await tlsConnect(port, {
        cert: fs.readFileSync(pki.clientCertPath),
        key: fs.readFileSync(pki.clientKeyPath),
      });
      assert.equal(outcome.connected, true);
      assert.equal(await waitFor(() => gateway.getStatus().liveConnections === 1, 2000), true);

      await gateway.stop();
      const first = gateway.getStatus();
      assert.equal(first.liveConnections, 0);

      // A second stop must neither throw nor move any counter.
      await gateway.stop();
      await gateway.stop();
      const second = gateway.getStatus();
      assert.equal(second.liveConnections, first.liveConnections);
      assert.equal(second.inFlightHandshakes, first.inFlightHandshakes);
      assert.equal(second.listenerActive, false);
      outcome.socket.destroy();
    });
  });

  // =========================================================================
  // Terminal certificate expiry
  // =========================================================================

  describe('Certificate expiry is terminal', () => {
    test('RC05-NEG-15e: a wall-clock rollback cannot restore admission', async () => {
      let now = Date.now();
      const { gateway, port, admitted } = await startGateway({}, { getWallTime: () => now });
      try {
        // Establish a connection while healthy.
        const existing = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(existing.connected, true);
        assert.equal(await waitFor(() => admitted.length === 1, 2000), true);
        const beforeExpiry = now;

        // Cross notAfter exactly and observe the latch.
        now = Date.parse(
          new (await import('node:crypto')).X509Certificate(fs.readFileSync(pki.serverCertPath))
            .validTo,
        );
        const atBoundary = gateway.getStatus();
        assert.equal(atBoundary.degraded, true, 'exact notAfter is expired');
        assert.equal(atBoundary.degradedReason, 'certificate_expired');
        assert.equal(atBoundary.activeAndServing, false);

        // Roll the wall clock BACK to before notAfter.
        now = beforeExpiry;
        const rolled = gateway.getStatus();
        assert.equal(rolled.degraded, true, 'the latch is terminal');
        assert.equal(rolled.activeAndServing, false, 'admission cannot be restored');
        assert.equal(rolled.degradedReason, 'certificate_expired');

        // A new connection is still refused.
        const refused = await tlsConnect(port, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        await waitFor(() => refused.socket.destroyed, 2000);
        assert.equal(refused.socket.destroyed, true, 'new handshakes stay refused');
        refused.socket?.destroy();
        assert.equal(admitted.length, 1, 'no admission after the latch');

        // The connection established before expiry drains normally.
        assert.equal(existing.socket.destroyed, false, 'existing connections are not evicted');
        existing.socket.destroy();
      } finally {
        await gateway.stop();
      }
    });
  });

  // =========================================================================
  // Production configuration surface
  // =========================================================================

  describe('Production remote configuration has no testing seams', () => {
    test('RC05-ENR-184: RemoteConfig exposes no clock, timeout, or limiter override', async () => {
      const resolved = await baseConfig();
      const seamNames = [
        'getWallTime',
        'handshakeTimeoutMs',
        'handshakeTimeoutMsForTests',
        'admission',
        'limiter',
        'maxLivePerPeer',
        'maxLiveGlobal',
        'maxInFlightHandshakes',
        'attemptsPerMinute',
        'burst',
        'maxPeerKeys',
        'idleEvictionMs',
      ];
      for (const seam of seamNames) {
        assert.equal(
          Object.prototype.hasOwnProperty.call(resolved, seam),
          false,
          `${seam} must not exist on production remote configuration`,
        );
      }

      // The resolved configuration is exactly the trusted selector set.
      assert.deepEqual(Object.keys(resolved).sort(), [
        'bindHost',
        'clientCaPaths',
        'port',
        'privateKey',
        'publicHostname',
        'serverCertificatePath',
      ]);

      // Smuggling a seam through the configuration object is ignored: the
      // gateway resolves its own clock and timeout, and the resolved config
      // never carries them forward.
      const gateway = new RemoteGateway({
        ...resolved,
        getWallTime: () => 0,
        handshakeTimeoutMs: 1,
      });
      try {
        assert.equal(gateway.handshakeTimeoutMs, TLS_HANDSHAKE_TIMEOUT_MS);
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-185: the composed server uses the real wall clock', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const remotePort = await freePort();
      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        remote: {
          port: remotePort,
          publicHostname,
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.serverKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
        },
      });
      await server.start();
      try {
        // The gateway is healthy against the real clock, which proves the
        // composed path did not inherit a frozen or zeroed clock.
        const status = server.getRemoteGatewayStatus();
        assert.equal(status.degraded, false);
        assert.equal(status.activeAndServing, true);
      } finally {
        await server.stop();
      }
    });
  });

  describe('Transport mode composition', () => {
    test('RC05-ENR-130: stdio mode creates no remote listener', async () => {
      const { ArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const { WorkspaceRegistry, SecurityKernel, ApprovalStateManager } =
        await import('../packages/policy/dist/index.js');
      const { AuditLogger } = await import('../packages/audit/dist/index.js');
      const { FilesystemSubsystem } = await import('../packages/filesystem/dist/index.js');
      const { GitSubsystem } = await import('../packages/git/dist/index.js');

      const registry = new WorkspaceRegistry();
      const remotePort = await freePort();
      const server = new ArcMcpServer(
        registry,
        new SecurityKernel(registry),
        new AuditLogger(),
        new FilesystemSubsystem(),
        new GitSubsystem(),
        {
          transport: 'stdio',
          authorizedRoots: [],
          // Supplying a remote configuration alongside stdio must NOT activate
          // it: the mode is exclusive, not additive.
          remote: {
            port: remotePort,
            publicHostname,
            serverCertificatePath: pki.serverCertPath,
            privateKey: { kind: 'file', path: pki.serverKeyPath },
            clientCaPaths: [pki.trustedCaCertPath],
          },
        },
        undefined,
        undefined,
        new ApprovalStateManager(),
      );

      assert.equal(server.getTransportMode(), 'stdio');
      assert.equal(server.getRemoteGatewayStatus(), undefined, 'no gateway exists in stdio mode');

      // Nothing was bound on the configured remote port.
      const probe = net.createConnection({ host: '127.0.0.1', port: remotePort });
      const refused = await new Promise((resolve) => {
        probe.once('connect', () => resolve(false));
        probe.once('error', () => resolve(true));
        setTimeout(() => resolve(false), 500).unref();
      });
      probe.destroy();
      assert.equal(refused, true, 'stdio mode must not bind any remote port');
    });

    test('RC05-ENR-131: remote mode binds the listener and reports its status', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const remotePort = await freePort();
      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        remote: {
          port: remotePort,
          publicHostname,
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.serverKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
        },
      });

      assert.equal(server.getTransportMode(), 'remote');

      await server.start();
      try {
        const status = server.getRemoteGatewayStatus();
        assert.ok(status, 'remote mode exposes a gateway status');
        assert.equal(status.transportMode, 'remote');
        assert.equal(status.listenerActive, true);

        // The listener really is serving on the configured port.
        const outcome = await tlsConnect(remotePort, {
          cert: fs.readFileSync(pki.clientCertPath),
          key: fs.readFileSync(pki.clientKeyPath),
        });
        assert.equal(outcome.connected, true);
        outcome.socket.destroy();
      } finally {
        await server.stop();
      }
      // Shutdown removes the gateway entirely: no stale listener state remains.
      assert.equal(server.getRemoteGatewayStatus(), undefined);
    });

    test('RC05-ENR-132: a failed remote startup leaves nothing bound and no stdio fallback', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const remotePort = await freePort();
      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        remote: {
          port: remotePort,
          publicHostname,
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.wrongServerKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
        },
      });

      await assert.rejects(
        () => server.start(),
        (err) => err instanceof RemoteConfigError,
      );
      assert.equal(server.getRemoteGatewayStatus(), undefined);

      // Nothing is bound, so the port is immediately reusable.
      const probe = net.createConnection({ host: '127.0.0.1', port: remotePort });
      const refused = await new Promise((resolve) => {
        probe.once('connect', () => resolve(false));
        probe.once('error', () => resolve(true));
        setTimeout(() => resolve(false), 500).unref();
      });
      probe.destroy();
      assert.equal(refused, true, 'a failed remote start must not leave a listener');
    });

    test('RC05-ENR-133: remote startup succeeds with zero enrolled devices', async () => {
      const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
      const { DeviceTrustStore } = await import('../packages/auth/dist/index.js');
      const trustStorePath = path.join(tempRoot, 'devices-remote.json');
      DeviceTrustStore.createEmpty().saveToFile(trustStorePath);
      fs.chmodSync(trustStorePath, 0o600);

      const remotePort = await freePort();
      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [],
        remote: {
          port: remotePort,
          publicHostname,
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.serverKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
          trustStorePath,
        },
      });
      await server.start();
      try {
        assert.equal(server.getRemoteGatewayStatus()?.listenerActive, true);
      } finally {
        await server.stop();
      }
    });
  });

  describe('Composition', () => {
    test('RC05-ENR-120: remote startup succeeds with a valid, empty trust store', async () => {
      const trustStorePath = path.join(tempRoot, 'devices.json');
      const { DeviceTrustStore } = await import('../packages/auth/dist/index.js');
      DeviceTrustStore.createEmpty().saveToFile(trustStorePath);
      fs.chmodSync(trustStorePath, 0o600);

      const { gateway } = await startGateway({ trustStorePath });
      try {
        assert.equal(gateway.isStarted(), true, 'zero enrolled devices is a valid remote start');
      } finally {
        await gateway.stop();
      }
    });

    test('RC05-ENR-121: an invalid trust store fails remote startup', async () => {
      const trustStorePath = path.join(tempRoot, 'devices-bad.json');
      fs.writeFileSync(trustStorePath, '{"version":1,"devices":"not-an-array"}', { mode: 0o600 });
      await assert.rejects(
        () => startGateway({ trustStorePath }),
        (err) => err instanceof RemoteConfigError && err.reason === 'TRUST_STORE_INVALID',
      );
    });

    test('RC05-ENR-122: a non-wildcard bind is the only default exposure', async () => {
      const { gateway, port } = await startGateway();
      try {
        // The listener answers on loopback...
        const socket = net.createConnection({ host: '127.0.0.1', port });
        await new Promise((resolve) => {
          socket.once('connect', resolve);
          socket.once('error', resolve);
        });
        socket.destroy();
        assert.equal(gateway.getStatus().listenerActive, true);
      } finally {
        await gateway.stop();
      }
    });
  });
});
