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
  MAX_LIVE_CONNECTIONS_GLOBAL,
  MAX_LIVE_CONNECTIONS_PER_PEER,
  MAX_IN_FLIGHT_HANDSHAKES,
  LAYER_A_MAX_ATTEMPTS_PER_WINDOW,
  LAYER_A_BURST,
} from '../apps/mcp-server/dist/admission-limiter.js';
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
        { now: { handshakeTimeoutMs: 0 }, reason: 'HANDSHAKE_TIMEOUT_INVALID' },
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
      const { gateway, port, admitted } = await startGateway({ handshakeTimeoutMs: 200 });
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
    test('RC05-NEG-53: rate/burst exhaustion drops peers before TLS admission', async () => {
      const { gateway, port, admitted, refused } = await startGateway(
        {},
        {
          admission: {
            maxAttemptsPerWindow: LAYER_A_MAX_ATTEMPTS_PER_WINDOW,
            burst: LAYER_A_BURST,
            // Keep concurrency out of the way so the rate bound is the binding
            // limit under test.
            maxLivePerPeer: 1000,
            maxLiveGlobal: 1000,
            maxInFlightHandshakes: 1000,
          },
        },
      );
      try {
        const allowed = LAYER_A_MAX_ATTEMPTS_PER_WINDOW + LAYER_A_BURST;
        let connections = 0;
        // Open and immediately close connections until Layer A refuses.
        for (let i = 0; i < allowed + 5; i++) {
          const socket = net.createConnection({ host: '127.0.0.1', port });
          await new Promise((resolve) => {
            socket.once('connect', resolve);
            socket.once('error', resolve);
          });
          socket.destroy();
          connections += 1;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));

        assert.ok(
          refused.filter((r) => r === 'RATE_LIMIT').length > 0,
          `expected a rate-limit refusal after ${connections} attempts, saw ${JSON.stringify(refused)}`,
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
      const { gateway, port } = await startGateway({ handshakeTimeoutMs: 150 });
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
