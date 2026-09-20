/**
 * CesSpace ARC — RC-05 Task 7: Multi-Layer Rate Limiting and Resource Bounds
 *
 * Covers the frozen resource-bound contract (rc05-scope-acceptance.md §20,
 * §21.1 Layer B, §21.1 Layer C, §21.2, §21.3, §26 C-1, §26 C-3) and the Task-7
 * negative controls RC05-NEG-55, 56, 57, 58, 59, 60, and 61.
 *
 * Every case drives real code over real boundaries:
 * - the canonical peer normalization and the bounded token-bucket tables are the
 *   production modules, driven with an injected MONOTONIC clock, so no test
 *   sleeps for a rate bound and no assertion depends on wall-clock time;
 * - the HTTP cases complete REAL TLS 1.3 mutual-authentication handshakes
 *   against REAL `RemoteGateway` listeners on ephemeral ports;
 * - the body-bound cases stream REAL bytes over REAL sockets, including a real
 *   chunked over-limit body, so "refused during the read" is measured on
 *   received bytes rather than asserted from the source text;
 * - the Layer C cases run the REAL `RemoteExecutionBridge` over the REAL shared
 *   RC-04 pipeline (real `SecurityKernel`, real policy, real subsystems).
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * shared test PKI helper and removed with it; no certificate or key is committed
 * and no scanner suppression is used.
 *
 * Scope note: Task 7 owns BOUNDS ONLY. `/mcp` stays deny-only here — Task 8 owns
 * the Streamable HTTP transport, session issuance over the network, and the
 * final gateway health composition.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

import { RemoteGateway } from '../apps/mcp-server/dist/remote-gateway.js';
import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import {
  AdmissionLimiter,
  LAYER_A_ATTEMPTS_PER_MINUTE,
  LAYER_A_BURST,
  LAYER_A_IDLE_EVICTION_MS,
  LAYER_A_REFILL_MS,
  MAX_IN_FLIGHT_HANDSHAKES,
  MAX_LIVE_CONNECTIONS_GLOBAL,
  MAX_LIVE_CONNECTIONS_PER_PEER,
  MAX_LAYER_A_PEER_KEYS,
} from '../apps/mcp-server/dist/admission-limiter.js';
import {
  BoundedRequestLimiter,
  LAYER_B_BURST,
  LAYER_B_REQUESTS_PER_MINUTE,
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_A_KEYS,
  MAX_LAYER_B_KEYS,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
  RATE_LIMITER_IDLE_EVICTION_MS,
  UNKNOWN_PEER_KEY,
  normalizePeerNetwork,
} from '../apps/mcp-server/dist/remote-resource-limits.js';
import {
  BODY_READ_TIMEOUT_MS,
  HEADER_READ_CHECK_INTERVAL_MS,
  HEADER_READ_TIMEOUT_MS,
  MAX_REMOTE_BODY_BYTES,
  MAX_REQUEST_HEADER_BYTES,
  MAX_REQUEST_TARGET_BYTES,
  TOTAL_REQUEST_TIMEOUT_MS,
  RequestBodyError,
  getActiveBodyReadDeadlineCountForTests,
  hasContentEncoding,
  readBoundedRequestBody,
  requestTargetBytes,
  resolveBodyReadTimeoutMs,
  resolveHeaderReadCheckIntervalMs,
  resolveHeaderReadTimeoutMs,
} from '../apps/mcp-server/dist/remote-request-bounds.js';
import {
  RemoteExecutionBridge,
  createAuthenticatedRequestLimiter,
  remoteRateLimitFailure,
  sessionRateLimitKey,
} from '../apps/mcp-server/dist/remote-execution.js';
import { SecurityKernel, WorkspaceRegistry } from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { DeviceTrustStore, resolveActiveDeviceIdentity } from '../packages/auth/dist/index.js';
import { createEmptyTrustStore, createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

// ---------------------------------------------------------------------------
// Deterministic clock
// ---------------------------------------------------------------------------

/**
 * A controllable MONOTONIC clock.
 *
 * Rate authorization is driven ONLY by monotonic time, so a test can advance it
 * freely without touching the wall clock: no assertion in this suite depends on
 * how long a case took to run, and no case waits out a real production bound.
 */
function makeClock(startMs = 1_000_000) {
  let now = startMs;
  return {
    now: () => now,
    advance: (ms) => {
      now += ms;
      return now;
    },
  };
}

/** Waits until `predicate` holds, or reports failure after a bounded budget. */
async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tempRoot;
let workspaceDir;
let pki;
const publicHostname = 'localhost';
let trustStoreCounter = 0;

before(() => {
  // The suite completes real mTLS handshakes, so a missing platform tool is a
  // hard environment failure rather than a skipped control.
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 Task 7 drives real mTLS connections and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-bounds-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), 'line1\nline2\nline3\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** A fresh, valid, EMPTY device trust store for one remote composition. */
function freshTrustStore(tag) {
  trustStoreCounter += 1;
  return createEmptyTrustStore(tempRoot, `devices-${tag}-${trustStoreCounter}.json`);
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

/** Base remote configuration naming a valid empty trust store. */
async function baseConfig(overrides = {}) {
  return {
    bindHost: '127.0.0.1',
    port: await freePort(),
    publicHostname,
    serverCertificatePath: pki.serverCertPath,
    privateKey: { kind: 'file', path: pki.serverKeyPath },
    clientCaPaths: [pki.trustedCaCertPath],
    trustStorePath: freshTrustStore('bounds'),
    ...overrides,
  };
}

/** Certificate and key bytes of the ephemeral client leaf issued by the test PKI. */
function clientMaterial() {
  return {
    cert: fs.readFileSync(pki.clientCertPath),
    key: fs.readFileSync(pki.clientKeyPath),
  };
}

/** Starts a gateway and hands the caller everything needed to tear it down. */
async function startGateway(overrides = {}, options = {}) {
  const config = await baseConfig(overrides);
  const refused = [];
  const gateway = new RemoteGateway(config, {
    onRefused: (reason) => refused.push(reason),
    ...options,
  });
  await gateway.start();
  return { gateway, config, refused, port: gateway.getBoundPort() };
}

/**
 * A Layer A limiter that cannot interfere with a connection-heavy case.
 *
 * Layer B refills one token per second, so proving "the 31st request is refused
 * with 429" needs 31 connections in the same second — which is exactly what
 * Layer A's frozen burst of 20 exists to refuse. Layer A's real values and
 * behaviour are pinned in their own section; here it is injected wide, so Layer
 * B is unambiguously the layer under test.
 */
function nonInterferingLayerA(clock = makeClock()) {
  return new AdmissionLimiter({
    getMonotonicTimeMs: clock.now,
    attemptsPerMinute: 600_000,
    burst: 4096,
  });
}

/** A pre-session limiter on a FROZEN clock, so no token ever refills mid-case. */
function frozenLayerB(burst) {
  return new BoundedRequestLimiter({
    requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
    burst,
    maxKeys: MAX_LAYER_B_KEYS,
    getMonotonicTimeMs: () => 1_000_000,
  });
}

/** One HTTPS request over REAL mTLS. */
function httpsRequest(port, options = {}) {
  const {
    method = 'POST',
    requestPath = '/enroll/complete',
    body,
    headers = {},
    client = clientMaterial(),
    host = '127.0.0.1',
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
        host,
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        // The client does not verify the server here: the server certificate and
        // its SAN are covered by the Task-3 suite, and every case in this suite
        // is about bounds rather than certificate validation.
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
        res.on('end', () => done({ status: res.statusCode, headers: res.headers, body: data }));
        res.on('error', (err) => done({ status: null, headers: {}, body: '', error: err }));
      },
    );

    req.on('error', (err) => done({ status: null, headers: {}, body: '', error: err }));
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

/** Writes raw request bytes on a completed mTLS connection, reads the status line. */
function rawTlsRequest(port, head, budgetMs = 3000) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port,
      servername: publicHostname,
      ca: [fs.readFileSync(pki.trustedCaCertPath)],
      ...clientMaterial(),
      rejectUnauthorized: false,
    });
    let data = '';
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(outcome);
    };
    socket.on('secureConnect', () => socket.write(head));
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.includes('\r\n')) {
        finish({ statusLine: data.split('\r\n')[0], raw: data });
      }
    });
    socket.on('close', () => finish({ statusLine: data.split('\r\n')[0] ?? '', raw: data }));
    socket.on('error', (err) => finish({ statusLine: '', raw: data, error: err }));
    setTimeout(() => finish({ statusLine: '', raw: data, timedOut: true }), budgetMs).unref();
  });
}

/** A JSON body of exactly `bytes` bytes carrying one `secret` field. */
function bodyOfBytes(bytes) {
  return `{"secret":"${'a'.repeat(bytes - 13)}"}`;
}

/** Captures a rejection instead of failing the case. */
async function failure(promise) {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error('expected the call to fail, but it resolved');
}

// ---------------------------------------------------------------------------
// §21.3 — peer-network normalization
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: §21.3 peer-network normalization', () => {
  test('RC05-NEG-58: canonical IPv4 is its own key', () => {
    assert.equal(normalizePeerNetwork('192.0.2.1'), '192.0.2.1');
    assert.equal(normalizePeerNetwork('198.51.100.7'), '198.51.100.7');
    assert.equal(normalizePeerNetwork('203.0.113.9'), '203.0.113.9');
    assert.notEqual(normalizePeerNetwork('192.0.2.1'), normalizePeerNetwork('192.0.2.2'));
  });

  test('RC05-NEG-58: every IPv4-mapped spelling shares the IPv4 bucket', () => {
    // The dotted-quad form and the equivalent hexadecimal mapped form are the
    // SAME IPv4 address, so all spellings must produce one key equal to the plain
    // IPv4 key: a peer cannot buy a second budget by presenting its address in
    // mapped form.
    for (const spelling of ['::ffff:192.0.2.1', '::FFFF:192.0.2.1', '::ffff:c000:201']) {
      assert.equal(
        normalizePeerNetwork(spelling),
        '192.0.2.1',
        `${spelling} must normalize to the canonical IPv4 address`,
      );
    }
    assert.equal(normalizePeerNetwork('::ffff:198.51.100.7'), normalizePeerNetwork('198.51.100.7'));
    // A mapped address with a NON-zero prefix is genuine IPv6, not IPv4, so it
    // must not be unmapped into an unrelated IPv4 bucket.
    assert.equal(normalizePeerNetwork('2001:db8::ffff:192.0.2.1'), '2001:db8::/64');
  });

  test('RC05-NEG-59: every spelling inside one /64 shares one key', () => {
    const expected = '2001:db8:abcd:12::/64';
    for (const spelling of [
      '2001:db8:abcd:12::1',
      '2001:db8:abcd:12:1:2:3:4',
      '2001:0db8:ABCD:0012:0000:0000:0000:0001',
      '2001:0db8:abcd:0012:ffff:ffff:ffff:ffff',
      '2001:db8:abcd:12::',
    ]) {
      assert.equal(normalizePeerNetwork(spelling), expected, spelling);
    }
  });

  test('RC05-NEG-59: distinct /64 subnets are distinct keys', () => {
    const a = normalizePeerNetwork('2001:db8:abcd:12::1');
    const b = normalizePeerNetwork('2001:db8:abcd:13::1');
    const c = normalizePeerNetwork('2001:0db8:abcd:0012:1:2:3:4');
    assert.notEqual(a, b, 'a neighbouring /64 must not share a bucket');
    assert.equal(a, c, 'the same /64 must share a bucket');
    // The key is a canonical zero-compressed network, not a host address.
    assert.equal(a, '2001:db8:abcd:12::/64');
    assert.equal(normalizePeerNetwork('2001:db8::1'), '2001:db8::/64');
    assert.equal(normalizePeerNetwork('fe80::1%eth0'), 'fe80::/64');
  });

  test('RC05-NEG-57: no malformed or invented input can become a limiter key', () => {
    const malformed = [
      'localhost',
      '192.0.2',
      '192.0.2.1.5',
      '192.0.2.256',
      '192.000.002.001',
      '192.0.2.1 ',
      ' 192.0.2.1',
      '192.0.2.1\n',
      '0x7f.0.0.1',
      '0177.0.0.1',
      '999.1.1.1',
      '-1.0.0.1',
      '[2001:db8::1]',
      '2001:db8::1/64',
      '2001:db8::1::2',
      '2001:db8::gggg',
      '1.2.3.4::',
      '::ffff:999.0.2.1',
      'unknown-peer ',
      'x'.repeat(4096),
      '\u0000',
      '192.0.2.1, 198.51.100.7',
    ];
    for (const input of malformed) {
      assert.equal(
        normalizePeerNetwork(input),
        null,
        `${JSON.stringify(input)} must fail closed rather than mint a key`,
      );
    }
    for (const input of [12345, 0, true, false, {}, [], ['192.0.2.1'], { address: '192.0.2.1' }]) {
      assert.equal(
        normalizePeerNetwork(input),
        null,
        `${String(input)} must fail closed rather than mint a key`,
      );
    }
  });

  test('RC05-NEG-57: a missing peer address shares ONE bounded bucket', () => {
    // Every connection whose socket peer address is unavailable lands in ONE
    // bucket: an absent address cannot become a family of unique keys, and the
    // literal is never address-shaped so it cannot collide with a real peer key.
    for (const input of [undefined, null, '']) {
      assert.equal(normalizePeerNetwork(input), UNKNOWN_PEER_KEY);
    }
    assert.equal(UNKNOWN_PEER_KEY, 'unknown-peer');
    assert.equal(normalizePeerNetwork(UNKNOWN_PEER_KEY), null, 'the sentinel is not an address');
  });

  test('RC05-NEG-58: normalization is deterministic', () => {
    for (const input of [
      '192.0.2.1',
      '::ffff:192.0.2.1',
      '2001:db8:abcd:12::9',
      '2001:0DB8:ABCD:0012::9',
    ]) {
      assert.equal(normalizePeerNetwork(input), normalizePeerNetwork(input), input);
    }
    assert.equal(
      normalizePeerNetwork('2001:db8:abcd:12::1'),
      normalizePeerNetwork('2001:0db8:abcd:0012:0:0:0:1'),
    );
  });
});

// ---------------------------------------------------------------------------
// §21.2 — the bounded table itself
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: §21.2 bounded token-bucket table', () => {
  function table(options) {
    return new BoundedRequestLimiter({
      requestsPerMinute: 60,
      burst: 2,
      maxKeys: 2,
      ...options,
    });
  }

  test('RC05-NEG-57: the entire table state is ONE map, with no auxiliary collection', () => {
    const limiter = table();
    assert.deepEqual(Object.getOwnPropertyNames(limiter).sort(), [
      'burst',
      'entries',
      'getMonotonicTimeMs',
      'idleEvictionMs',
      'maxKeys',
      'maxOutstandingPerKey',
      'refillMs',
    ]);
    assert.equal(limiter.entries instanceof Map, true);
    assert.equal(limiter.getRetainedKeyCount(), limiter.entries.size);
  });

  test('RC05-NEG-57: a full table refuses an untracked key without allocating', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
    assert.equal(limiter.consume('192.0.2.2').consumed, true);
    assert.equal(limiter.getRetainedKeyCount(), 2);

    // Fresh keys cannot mint an entry: the table refuses instead of growing.
    for (let i = 0; i < 64; i += 1) {
      const decision = limiter.consume(`churn-key-${i}`);
      assert.equal(decision.consumed, false);
      assert.equal(decision.reason, 'TABLE_SATURATED');
    }
    assert.equal(limiter.getRetainedKeyCount(), 2, 'the table did not grow by one');
    // A refusal leaves no tombstone or placeholder behind either.
    assert.deepEqual(limiter.getRetainedKeysForTests().sort(), ['192.0.2.1', '192.0.2.2']);
  });

  test('RC05-NEG-57: an idle entry is reclaimed after 60 s of monotonic time', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    limiter.consume('192.0.2.1');
    limiter.consume('192.0.2.2');

    clock.advance(RATE_LIMITER_IDLE_EVICTION_MS - 1);
    assert.equal(limiter.consume('churn-key').consumed, false, 'not yet reclaimable');

    clock.advance(1);
    assert.equal(limiter.consume('churn-key').consumed, true, 'reclaimed once idle');
    assert.equal(limiter.getRetainedKeyCount() <= 2, true);
  });

  test('RC05-NEG-57: a long idle refill reaches the burst and stops there', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    limiter.consume('192.0.2.1');
    limiter.consume('192.0.2.1');
    assert.equal(limiter.getBucket('192.0.2.1').tokens, 0);
    // An hour of idle time buys exactly one burst of 2, never 120 tokens.
    clock.advance(60 * 60_000);
    limiter.consume('192.0.2.1');
    assert.equal(limiter.getBucket('192.0.2.1').tokens, 1);
  });

  test('RC05-NEG-57: an ACTIVE key is never evicted to admit a new one', () => {
    const clock = makeClock();
    const limiter = table({ maxKeys: 1, getMonotonicTimeMs: clock.now });
    const held = limiter.consume('192.0.2.1');
    assert.equal(held.consumed, true);
    const slot = limiter.tryHold(held.bucket);
    assert.equal(slot.held, true);

    // The key is far past the idle timeout, so it would be reclaimable if it were
    // quiet — but a key with live work is never reclaimed, so the table fails
    // closed rather than dropping live state to admit a new key.
    clock.advance(RATE_LIMITER_IDLE_EVICTION_MS * 10);
    const refused = limiter.consume('198.51.100.1');
    assert.equal(refused.consumed, false);
    assert.equal(refused.reason, 'TABLE_SATURATED');
    assert.equal(limiter.getHolderCount('192.0.2.1'), 1);

    // Once the work finishes the entry becomes reclaimable, so one long-lived
    // holder cannot wedge the table permanently.
    slot.release();
    assert.equal(limiter.consume('198.51.100.1').consumed, true);
    assert.equal(limiter.getRetainedKeyCount(), 1);
  });

  test('RC05-NEG-57: a non-expired key is not silently evicted', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    limiter.consume('192.0.2.1');
    limiter.consume('192.0.2.2');
    clock.advance(RATE_LIMITER_IDLE_EVICTION_MS - 1);
    const decision = limiter.consume('churn-key');
    assert.equal(decision.consumed, false);
    assert.equal(decision.reason, 'TABLE_SATURATED');
    assert.notEqual(limiter.getBucket('192.0.2.1'), undefined);
    assert.notEqual(limiter.getBucket('192.0.2.2'), undefined);
  });

  test('RC05-NEG-57: tokens refill lazily at the frozen rate and stop at the burst', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
    assert.equal(limiter.consume('192.0.2.1').consumed, false);
    assert.equal(limiter.consume('192.0.2.1').reason, 'RATE_LIMIT');
    assert.equal(limiter.getBucket('192.0.2.1').tokens, 0);

    clock.advance(1000); // 60/min ⇒ one token per 1000 ms
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
    assert.equal(limiter.consume('192.0.2.1').consumed, false);

    clock.advance(600_000);
    limiter.consume('192.0.2.1');
    assert.equal(limiter.getBucket('192.0.2.1').tokens, 1, 'capped at one burst of 2');
  });

  test('RC05-NEG-57: reset drops every entry and leaks nothing', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    limiter.consume('192.0.2.1');
    limiter.consume('192.0.2.2');
    assert.equal(limiter.getRetainedKeyCount(), 2);

    limiter.reset();
    assert.equal(limiter.getRetainedKeyCount(), 0);
    assert.deepEqual(limiter.getRetainedKeysForTests(), []);
    assert.equal(limiter.getBucket('192.0.2.1'), undefined);
    // A fresh table starts clean, so a restart carries no prior budget.
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
  });

  test('RC05-NEG-57: a released concurrency slot is idempotent and never negative', () => {
    const clock = makeClock();
    const limiter = table({ maxOutstandingPerKey: 1, getMonotonicTimeMs: clock.now });
    const bucket = limiter.consume('192.0.2.1').bucket;
    const slot = limiter.tryHold(bucket);
    assert.equal(slot.held, true);
    const second = limiter.tryHold(bucket);
    assert.equal(second.held, false);
    assert.equal(second.reason, 'CONCURRENCY_LIMIT');

    slot.release();
    slot.release();
    assert.equal(limiter.getHolderCount('192.0.2.1'), 0, 'a double release cannot go negative');
    assert.equal(limiter.tryHold(bucket).held, true);
  });

  test('RC05-NEG-57: without a per-key concurrency bound, holding is always granted', () => {
    const clock = makeClock();
    const limiter = table({ getMonotonicTimeMs: clock.now });
    const bucket = limiter.consume('192.0.2.1').bucket;
    const slots = [];
    for (let i = 0; i < 50; i += 1) {
      const decision = limiter.tryHold(bucket);
      assert.equal(decision.held, true);
      slots.push(decision);
    }
    assert.equal(limiter.getHolderCount('192.0.2.1'), 50);
    for (const slot of slots) slot.release();
    assert.equal(limiter.getHolderCount('192.0.2.1'), 0);
  });
});

// ---------------------------------------------------------------------------
// §21.1 Layer A — the approved Task-3 values, unchanged
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: §21.1 Layer A frozen values are preserved', () => {
  test('RC05-NEG-57: Layer A is 60/min, burst 20, 32/512/64 caps, 4096 keys, 60 s idle', () => {
    assert.equal(LAYER_A_ATTEMPTS_PER_MINUTE, 60);
    assert.equal(LAYER_A_BURST, 20);
    assert.equal(LAYER_A_REFILL_MS, 1000);
    assert.equal(MAX_LIVE_CONNECTIONS_PER_PEER, 32);
    assert.equal(MAX_LIVE_CONNECTIONS_GLOBAL, 512);
    assert.equal(MAX_IN_FLIGHT_HANDSHAKES, 64);
    assert.equal(MAX_LAYER_A_PEER_KEYS, 4096);
    assert.equal(MAX_LAYER_A_KEYS, 4096);
    assert.equal(LAYER_A_IDLE_EVICTION_MS, 60_000);
    assert.equal(RATE_LIMITER_IDLE_EVICTION_MS, 60_000);
  });

  test('RC05-NEG-57: Layer A admits one burst of 20, refuses, and refills at one per second', () => {
    const clock = makeClock();
    const limiter = new AdmissionLimiter({ getMonotonicTimeMs: clock.now });
    const admitted = [];
    let refused = null;
    for (let i = 0; i < 21; i += 1) {
      const decision = limiter.admit('192.0.2.1');
      if (decision.admitted) admitted.push(decision);
      else refused = decision;
    }
    assert.equal(admitted.length, 20, 'the burst is exactly 20');
    assert.deepEqual(refused, { admitted: false, reason: 'RATE_LIMIT' });

    clock.advance(LAYER_A_REFILL_MS);
    const afterRefill = limiter.admit('192.0.2.1');
    assert.equal(afterRefill.admitted, true, 'one token per second');

    // Every admitted connection returns its slot, and the counters return to
    // zero: the frozen Task-3 lifecycle is intact.
    for (const decision of [...admitted, afterRefill]) {
      decision.release();
      limiter.releaseHandshake();
    }
    assert.equal(limiter.getLiveConnectionCount(), 0);
    assert.equal(limiter.getInFlightHandshakeCount(), 0);
  });

  test('RC05-NEG-57: Layer A keeps its exact per-peer, global and handshake refusals', () => {
    const clock = makeClock();
    const perPeer = new AdmissionLimiter({
      getMonotonicTimeMs: clock.now,
      maxLivePerPeer: 1,
      maxLiveGlobal: 8,
      maxInFlightHandshakes: 8,
    });
    assert.equal(perPeer.admit('192.0.2.1').admitted, true);
    assert.deepEqual(perPeer.admit('192.0.2.1'), {
      admitted: false,
      reason: 'PEER_CONNECTION_CAP',
    });

    const global = new AdmissionLimiter({
      getMonotonicTimeMs: clock.now,
      maxLiveGlobal: 1,
      maxLivePerPeer: 8,
      maxInFlightHandshakes: 8,
    });
    assert.equal(global.admit('192.0.2.1').admitted, true);
    assert.deepEqual(global.admit('198.51.100.2'), {
      admitted: false,
      reason: 'GLOBAL_CONNECTION_CAP',
    });

    const handshake = new AdmissionLimiter({
      getMonotonicTimeMs: clock.now,
      maxInFlightHandshakes: 1,
      maxLivePerPeer: 8,
      maxLiveGlobal: 8,
    });
    assert.equal(handshake.admit('192.0.2.1').admitted, true);
    assert.deepEqual(handshake.admit('198.51.100.2'), {
      admitted: false,
      reason: 'HANDSHAKE_CAP',
    });
  });

  test('RC05-NEG-57: Layer A retains at most 4096 peer keys under address churn', () => {
    const clock = makeClock();
    const limiter = new AdmissionLimiter({ getMonotonicTimeMs: clock.now });

    let admitted = 0;
    for (let i = 0; i < MAX_LAYER_A_PEER_KEYS; i += 1) {
      const decision = limiter.admit(`peer-key-${i}`);
      if (decision.admitted) {
        admitted += 1;
        // Released immediately: this case is about the KEY table, not the live cap.
        decision.release();
        limiter.releaseHandshake();
      }
    }
    assert.equal(admitted, MAX_LAYER_A_PEER_KEYS, 'every key inside the ceiling is admitted');
    assert.equal(limiter.getRetainedPeerKeyCount(), MAX_LAYER_A_PEER_KEYS);

    // The 4097th distinct source cannot mint an entry.
    for (let i = 0; i < 32; i += 1) {
      const decision = limiter.admit(`attacker-key-${i}`);
      assert.equal(decision.admitted, false);
      assert.equal(decision.reason, 'PEER_TABLE_SATURATED');
    }
    assert.equal(
      limiter.getRetainedPeerKeyCount(),
      MAX_LAYER_A_PEER_KEYS,
      'the table never exceeded its ceiling',
    );
    assert.equal(limiter.getRetainedPeerKeysForTests().length, MAX_LAYER_A_PEER_KEYS);
  });

  test('RC05-NEG-57: Layer A reclaims idle peers after 60 s and admits the churn again', () => {
    const clock = makeClock();
    const limiter = new AdmissionLimiter({ getMonotonicTimeMs: clock.now });
    for (let i = 0; i < 32; i += 1) {
      const decision = limiter.admit(`peer-key-${i}`);
      decision.release();
      limiter.releaseHandshake();
    }
    assert.equal(limiter.getRetainedPeerKeyCount(), 32);

    clock.advance(LAYER_A_IDLE_EVICTION_MS);
    const decision = limiter.admit('rotated-peer-key');
    assert.equal(decision.admitted, true, 'idle peers were reclaimed deterministically');
    assert.equal(limiter.getRetainedPeerKeyCount(), 1);
    decision.release();
    limiter.releaseHandshake();
  });

  test('RC05-NEG-58: the gateway buckets a real mapped-IPv6 connection on the IPv4 key', async () => {
    // The listener is bound to the mapped form of the loopback address, so a
    // plain IPv4 client arrives with a mapped `remoteAddress` — exactly the
    // bypass shape RC05-NEG-58 describes. Layer A must bucket it on `127.0.0.1`,
    // because the SOCKET peer address is the only authoritative source.
    const observed = new AdmissionLimiter();
    const rawPeerAddresses = [];
    const { gateway, port } = await startGateway(
      { bindHost: '::ffff:127.0.0.1' },
      {
        admissionLimiterForTests: observed,
        onAdmitted: (context) => rawPeerAddresses.push(context.socket.remoteAddress),
      },
    );
    try {
      const res = await httpsRequest(port, { requestPath: '/mcp', body: '{}' });
      assert.equal(res.status, 401, JSON.stringify(res));

      // The premise, asserted rather than assumed: the socket really did report
      // a mapped address, so this case is not vacuously testing plain IPv4.
      assert.deepEqual(rawPeerAddresses, ['::ffff:127.0.0.1']);
      // …and Layer A nonetheless bucketed the connection on the IPv4 key.
      assert.deepEqual(observed.getRetainedPeerKeysForTests(), ['127.0.0.1']);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-59: the gateway buckets a real IPv6 connection on its /64 key', async () => {
    const observed = new AdmissionLimiter();
    const { gateway, port } = await startGateway(
      { bindHost: '::1' },
      { admissionLimiterForTests: observed },
    );
    try {
      const res = await httpsRequest(port, { requestPath: '/mcp', body: '{}', host: '::1' });
      assert.equal(res.status, 401, JSON.stringify(res));
      assert.deepEqual(observed.getRetainedPeerKeysForTests(), ['::/64']);
    } finally {
      await gateway.stop();
    }
  });
});

// ---------------------------------------------------------------------------
// §21.1 Layer B — pre-session HTTP limiter
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: §21.1 Layer B pre-session limiter', () => {
  test('RC05-NEG-55: Layer B is 120 req/min, burst 30, 2048 retained keys', () => {
    assert.equal(LAYER_B_REQUESTS_PER_MINUTE, 120);
    assert.equal(LAYER_B_BURST, 30);
    assert.equal(MAX_LAYER_B_KEYS, 2048);
  });

  test('RC05-NEG-55: Layer B admits one burst of 30, refuses, and refills at 120/min', () => {
    const clock = makeClock();
    const limiter = new BoundedRequestLimiter({
      requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
      burst: LAYER_B_BURST,
      maxKeys: MAX_LAYER_B_KEYS,
      getMonotonicTimeMs: clock.now,
    });
    for (let i = 0; i < LAYER_B_BURST; i += 1) {
      assert.equal(limiter.consume('192.0.2.1').consumed, true, `request ${i}`);
    }
    const refused = limiter.consume('192.0.2.1');
    assert.equal(refused.consumed, false);
    assert.equal(refused.reason, 'RATE_LIMIT');
    assert.equal(limiter.getRetainedKeyCount(), 1, 'a rate refusal allocates no extra state');

    clock.advance(250); // 120/min ⇒ one token per 500 ms
    assert.equal(limiter.consume('192.0.2.1').consumed, false);
    clock.advance(250);
    assert.equal(limiter.consume('192.0.2.1').consumed, true);
    assert.equal(limiter.consume('192.0.2.1').consumed, false);
  });

  test('RC05-NEG-55: Layer B refuses a peer before routing with a sanitized 429', async () => {
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        layerBLimiterForTests: frozenLayerB(2),
      },
    );
    try {
      // The first two requests reach the router and get the ordinary JSON answer.
      for (let i = 0; i < 2; i += 1) {
        const res = await httpsRequest(port, { requestPath: '/enroll/complete', body: '{}' });
        assert.equal(res.status, 400, JSON.stringify(res));
        assert.equal(res.headers['content-type'], 'application/json');
      }

      const refused = await httpsRequest(port, {
        requestPath: '/enroll/complete',
        body: bodyOfBytes(4096),
      });
      assert.equal(refused.status, 429, JSON.stringify(refused));
      assert.equal(refused.body, 'Too Many Requests\n');
      assert.equal(refused.headers['content-type'], 'text/plain; charset=utf-8');
      assert.equal(refused.headers.connection, 'close');
      // No MCP JSON-RPC frame, no device/session oracle, no limiter internals.
      assert.equal(refused.body.includes('{'), false);
      assert.equal(refused.body.includes('jsonrpc'), false);
      assert.equal(refused.body.includes('192.0.2'), false);
      assert.equal(refused.body.includes('127.0.0.1'), false);
      assert.equal(refused.body.includes('unknown-peer'), false);
      assert.equal(refused.headers['retry-after'], undefined);
      assert.equal(refused.headers['x-ratelimit-remaining'], undefined);
      assert.equal(refused.headers['mcp-session-id'], undefined);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-55: a Layer B refusal never reaches enrollment verification', async () => {
    const saved = [];
    let completionAttempts = 0;
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        layerBLimiterForTests: frozenLayerB(0),
        enrollmentManager: {
          completeBySpki: () => {
            completionAttempts += 1;
            return { ok: false };
          },
        },
        bootstrap: {
          trustStoreStorageForTests: {
            save: (store, filePath) => saved.push([store, filePath]),
            load: () => {
              throw new Error('the bootstrap must not be reached');
            },
          },
        },
      },
    );
    try {
      // Even a well-formed completion carrying a plausible secret is refused: the
      // refusal is a BOUND, not a judgement about the secret, so the pending table
      // and the durable trust store are never touched.
      const res = await httpsRequest(port, {
        requestPath: '/enroll/complete',
        body: JSON.stringify({ secret: 'a'.repeat(64) }),
      });
      assert.equal(res.status, 429, JSON.stringify(res));
      assert.equal(completionAttempts, 0, 'no secret was ever verified');
      assert.equal(saved.length, 0, 'no durable write was attempted');
      assert.equal(gateway.getEnrolledDeviceCount(), 0);
      assert.equal(gateway.isEnrollmentStorageFailed(), false);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-55: Layer B runs after mTLS and before any session or MCP work', async () => {
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        layerBLimiterForTests: frozenLayerB(0),
      },
    );
    try {
      // A /mcp POST that would otherwise be answered by the deny-only placeholder
      // is refused by Layer B instead.
      const res = await httpsRequest(port, { requestPath: '/mcp', body: '{"jsonrpc":"2.0"}' });
      assert.equal(res.status, 429);
      assert.equal(res.body, 'Too Many Requests\n');

      // A peer with NO client certificate never gets this far at all: Layer B is
      // behind the handshake, so it cannot be reached without mTLS.
      const noCert = await httpsRequest(port, { requestPath: '/mcp', client: null });
      assert.equal(noCert.status, null, 'a failed handshake produces no HTTP response at all');
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-58: an IPv4 peer and its mapped IPv6 peer share ONE Layer B budget', async () => {
    // Two listeners, ONE limiter: the plain IPv4 listener reports `127.0.0.1`
    // and the mapped listener reports `::ffff:127.0.0.1` for the SAME client. If
    // normalization were missing these would be two keys, and the peer would get
    // two budgets from one machine.
    const shared = frozenLayerB(2);
    const ipv4 = await startGateway(
      { bindHost: '127.0.0.1' },
      { admissionLimiterForTests: nonInterferingLayerA(), layerBLimiterForTests: shared },
    );
    const mapped = await startGateway(
      { bindHost: '::ffff:127.0.0.1' },
      { admissionLimiterForTests: nonInterferingLayerA(), layerBLimiterForTests: shared },
    );
    try {
      for (let i = 0; i < 2; i += 1) {
        const res = await httpsRequest(ipv4.port, { requestPath: '/mcp', body: '{}' });
        assert.equal(res.status, 401, `ipv4 request ${i}: ${JSON.stringify(res)}`);
      }
      const acrossSpelling = await httpsRequest(mapped.port, { requestPath: '/mcp', body: '{}' });
      assert.equal(acrossSpelling.status, 429, JSON.stringify(acrossSpelling));
      assert.equal(acrossSpelling.body, 'Too Many Requests\n');
      assert.deepEqual(shared.getRetainedKeysForTests(), ['127.0.0.1']);
    } finally {
      await ipv4.gateway.stop();
      await mapped.gateway.stop();
    }
  });

  test('RC05-NEG-59: rotating inside one /64 buys no extra Layer B budget', () => {
    const limiter = new BoundedRequestLimiter({
      requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
      burst: LAYER_B_BURST,
      maxKeys: MAX_LAYER_B_KEYS,
    });
    // 30 requests, each from a DIFFERENT address inside 2001:db8:abcd:12::/64 —
    // the shape an IPv6 rotation attempt takes.
    let admitted = 0;
    for (let i = 0; i < LAYER_B_BURST; i += 1) {
      const key = normalizePeerNetwork(`2001:db8:abcd:12::${i.toString(16)}`);
      assert.equal(key, '2001:db8:abcd:12::/64');
      if (limiter.consume(key).consumed) admitted += 1;
    }
    assert.equal(admitted, LAYER_B_BURST);
    assert.equal(limiter.getRetainedKeyCount(), 1, 'one /64 is one bucket');

    const rotated = normalizePeerNetwork('2001:0db8:abcd:0012:dead:beef:cafe:1');
    const refused = limiter.consume(rotated);
    assert.equal(refused.consumed, false);
    assert.equal(refused.reason, 'RATE_LIMIT');
  });

  test('RC05-NEG-57: Layer B retains at most 2048 keys under source churn', () => {
    const clock = makeClock();
    const limiter = new BoundedRequestLimiter({
      requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
      burst: LAYER_B_BURST,
      maxKeys: MAX_LAYER_B_KEYS,
      getMonotonicTimeMs: clock.now,
    });
    for (let i = 0; i < MAX_LAYER_B_KEYS; i += 1) {
      assert.equal(limiter.consume(`peer-key-${i}`).consumed, true);
    }
    assert.equal(limiter.getRetainedKeyCount(), MAX_LAYER_B_KEYS);
    for (let i = 0; i < 64; i += 1) {
      const decision = limiter.consume(`attacker-key-${i}`);
      assert.equal(decision.consumed, false);
      assert.equal(decision.reason, 'TABLE_SATURATED');
    }
    assert.equal(limiter.getRetainedKeyCount(), MAX_LAYER_B_KEYS);
    assert.equal(limiter.getRetainedKeysForTests().length, MAX_LAYER_B_KEYS);
  });

  test('RC05-NEG-57: Layer B reclaims idle peers after 60 s', () => {
    const clock = makeClock();
    const limiter = new BoundedRequestLimiter({
      requestsPerMinute: LAYER_B_REQUESTS_PER_MINUTE,
      burst: LAYER_B_BURST,
      maxKeys: 2,
      getMonotonicTimeMs: clock.now,
    });
    limiter.consume('192.0.2.1');
    limiter.consume('198.51.100.1');
    assert.equal(limiter.consume('203.0.113.1').consumed, false);
    clock.advance(RATE_LIMITER_IDLE_EVICTION_MS);
    assert.equal(limiter.consume('203.0.113.1').consumed, true);
    assert.equal(limiter.getRetainedKeyCount(), 1);
  });
});

// ---------------------------------------------------------------------------
// §21.1 Layer C and §26 C-3 — authenticated session limits
// ---------------------------------------------------------------------------

/** Canonical SPKI pin shape. */
function pin(seed) {
  return crypto.createHash('sha256').update(`bounds-pin-${seed}`, 'utf8').digest('hex');
}

/** Counts SecurityKernel evaluations, which are the first step of the pipeline. */
class KernelSpy {
  constructor(inner) {
    this.inner = inner;
    this.evaluateCalls = 0;
  }
  async evaluate(context) {
    this.evaluateCalls += 1;
    return this.inner.evaluate(context);
  }
  loadPolicy(rules) {
    return this.inner.loadPolicy(rules);
  }
}

const DENY_READ_POLICY = `version: '1.0'
rules:
  - id: 'deny-read'
    effect: 'DENY'
    tools: ['read_file']
`;

/**
 * The real server plus the real bridge over a test-owned trust store.
 *
 * The bridge is composed exactly as `ArcMcpServer.start()` composes it: the
 * server's ONE `SessionManager`, a resolver reading the CURRENT trust store on
 * every call, and the server itself as the shared RC-04 pipeline sink. The Layer
 * C limiter is injected so a case can drive a deterministic clock and observe
 * the exact session key.
 *
 * `kernel.evaluateCalls` is the proof that the shared pipeline was or was not
 * entered: policy evaluation is its FIRST step, so a count of zero proves that
 * neither policy nor any subsystem ran.
 */
function makeHarness({ policy, authenticatedLimiter } = {}) {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', workspaceDir);

  const kernel = new KernelSpy(new SecurityKernel(registry));
  const filesystem = new FilesystemSubsystem();
  const git = new GitSubsystem();
  const audit = new AuditLogger();

  const server = new ArcMcpServer(registry, kernel, audit, filesystem, git, {
    transport: 'stdio',
    authorizedRoots: [],
    defaultWorkspaceId: 'ws',
    ...(policy === undefined ? {} : { policy }),
  });

  const store = DeviceTrustStore.createEmpty();
  const bridge = new RemoteExecutionBridge({
    sessionManager: server.sessionManager,
    resolveActiveDeviceIdentity: (spkiPin) => resolveActiveDeviceIdentity(store, spkiPin),
    sink: server,
    ...(authenticatedLimiter === undefined ? {} : { authenticatedLimiter }),
  });

  return { server, bridge, store, kernel, filesystem, git, audit };
}

/** Enrolls a device and returns its record plus pin. */
function enroll(harness, seed) {
  const spkiPin = pin(seed);
  const { device } = harness.store.enrollDevice({
    clientId: `agent-${seed}`,
    clientType: 'claude-code',
    pin: spkiPin,
  });
  return { device, spkiPin };
}

/** Establishes a real server-issued session for a device's SPKI pin. */
function establishSession(harness, spkiPin) {
  const identity = resolveActiveDeviceIdentity(harness.store, spkiPin);
  assert.ok(identity, 'the fixture device must resolve before a session can be issued');
  const sessionId = harness.server.sessionManager.createSessionIdGenerator()();
  const issuance = harness.server.sessionManager.issueSession({ sessionId, identity });
  return { identity, sessionId, deviceId: identity.deviceId, token: issuance.token };
}

/** One remote tool call through the real bridge. */
function remoteCall(harness, spkiPin, session, toolName, parameters) {
  return harness.bridge.executeRemoteToolCall({
    trustedSpkiPin: spkiPin,
    presentedSessionId: session === null ? null : session.sessionId,
    authorizationHeader: session === null ? null : `Bearer ${session.token}`,
    toolName,
    parameters,
  });
}

/** A sink that holds every admitted request open, so outstanding work is observable. */
function holdingSink() {
  const held = [];
  return {
    held,
    sink: {
      executeAuthenticatedToolCall: (actor, toolName, parameters) =>
        new Promise((resolve) => held.push({ actor, toolName, parameters, resolve })),
    },
  };
}

/** Lets the event loop run so held promises are actually in flight. */
function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

describe('RC-05 Task 7: §21.1 Layer C and §26 C-3 authenticated session limits', () => {
  test('RC05-NEG-56: Layer C is 300 req/min, burst 60, 1024 keys, 4 outstanding', () => {
    assert.equal(LAYER_C_REQUESTS_PER_MINUTE, 300);
    assert.equal(LAYER_C_BURST, 60);
    assert.equal(MAX_LAYER_C_KEYS, 1024);
    assert.equal(MAX_OUTSTANDING_REQUESTS_PER_SESSION, 4);
  });

  test('RC05-NEG-56: the Layer C default limiter carries the frozen bounds', () => {
    const limiter = createAuthenticatedRequestLimiter();
    const key = 'device-1:session-1';
    for (let i = 0; i < LAYER_C_BURST; i += 1) {
      assert.equal(limiter.consume(key).consumed, true, `request ${i}`);
    }
    const refused = limiter.consume(key);
    assert.equal(refused.consumed, false);
    assert.equal(refused.reason, 'RATE_LIMIT');
    assert.equal(limiter.getRetainedKeyCount(), 1);
  });

  test('RC05-NEG-56: Layer C refills at 300/min and never banks more than one burst', () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const key = 'device-1:session-1';
    for (let i = 0; i < LAYER_C_BURST + 1; i += 1) limiter.consume(key);
    assert.equal(limiter.getBucket(key).tokens, 0);

    clock.advance(200); // 300/min ⇒ one token per 200 ms
    assert.equal(limiter.consume(key).consumed, true);
    assert.equal(limiter.consume(key).consumed, false);

    clock.advance(24 * 60 * 60_000);
    limiter.consume(key);
    assert.equal(limiter.getBucket(key).tokens, LAYER_C_BURST - 1);
  });

  test('RC05-NEG-56: the Layer C key is server-derived and carries no session token', () => {
    assert.equal(sessionRateLimitKey({ deviceId: 'dev-a', sessionId: 'sess-b' }), 'dev-a:sess-b');

    const harness = makeHarness();
    const { device, spkiPin } = enroll(harness, 'key');
    const session = establishSession(harness, spkiPin);
    const realKey = sessionRateLimitKey(session);
    assert.equal(realKey, `${device.deviceId}:${session.sessionId}`);
    assert.equal(realKey.includes(session.token), false, 'the raw token is never a key');
    assert.equal(realKey.includes(spkiPin), false, 'the SPKI pin is never a key');
  });

  test('RC05-NEG-56: the 61st authenticated call is refused before policy runs', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({
      policy: { sourceText: DENY_READ_POLICY, format: 'yaml' },
      authenticatedLimiter: limiter,
    });
    const { spkiPin } = enroll(harness, 'flood');
    const session = establishSession(harness, spkiPin);

    // All 60 burst requests pass the rate layer and reach the shared pipeline,
    // where the loaded policy denies them — so the kernel really ran each time.
    for (let i = 0; i < LAYER_C_BURST; i += 1) {
      const result = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(result.isError, true, `call ${i}`);
    }
    assert.equal(harness.kernel.evaluateCalls, LAYER_C_BURST);

    const err = await failure(
      remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
    );
    assert.equal(err.name, 'ArcError');
    assert.equal(err.code, 'RATE_LIMIT_EXCEEDED');
    assert.equal(err.category, 'RESOURCE');
    assert.equal(err.retryable, true);
    // The refusal is a BOUND: policy was not consulted a 61st time, and nothing
    // about the key, the device, or the session is disclosed.
    assert.equal(harness.kernel.evaluateCalls, LAYER_C_BURST, 'policy was not reached again');
    assert.equal(err.message.includes(session.token), false);
    assert.equal(err.message.includes(session.deviceId), false);
    assert.equal(err.message.includes(session.sessionId), false);
  });

  test('RC05-NEG-56: a rate refusal never revokes the session', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const { spkiPin } = enroll(harness, 'no-revoke');
    const session = establishSession(harness, spkiPin);

    for (let i = 0; i < LAYER_C_BURST; i += 1) {
      await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
    }
    const refused = await failure(
      remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
    );
    assert.equal(refused.code, 'RATE_LIMIT_EXCEEDED');
    // The session survives the refusal: a rate bound is not a revocation.
    assert.equal(harness.server.sessionManager.hasSession(session.sessionId), true);

    // After the bucket refills, the SAME token works again: the refusal did not
    // spend the session, and the call reached the shared pipeline unchanged.
    clock.advance(200);
    const allowed = await remoteCall(harness, spkiPin, session, 'read_file', {
      path: 'README.md',
    });
    assert.equal(allowed.isError, undefined, 'the call ran again and succeeded');
    assert.equal(Array.isArray(allowed.content), true);
    assert.equal(harness.server.sessionManager.hasSession(session.sessionId), true);
  });

  test('RC05-NEG-56: at most 4 requests are outstanding per session, and the 5th never queues', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const { spkiPin } = enroll(harness, 'concurrency');
    const session = establishSession(harness, spkiPin);
    const key = sessionRateLimitKey(session);

    const { held, sink } = holdingSink();
    harness.bridge.deps.sink = sink;

    const inFlight = [];
    for (let i = 0; i < MAX_OUTSTANDING_REQUESTS_PER_SESSION; i += 1) {
      inFlight.push(remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }));
    }
    await settle();
    assert.equal(held.length, MAX_OUTSTANDING_REQUESTS_PER_SESSION);
    assert.equal(limiter.getHolderCount(key), MAX_OUTSTANDING_REQUESTS_PER_SESSION);

    // The 5th request fails IMMEDIATELY: it does not wait for a slot, so no
    // unbounded backlog can accumulate behind a session.
    const before = clock.now();
    const err = await failure(
      remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
    );
    assert.equal(err.code, 'RATE_LIMIT_EXCEEDED');
    assert.equal(clock.now(), before, 'the refusal cost no time: nothing was queued');
    assert.equal(held.length, MAX_OUTSTANDING_REQUESTS_PER_SESSION, 'the pipeline saw 4 calls');
    assert.equal(limiter.getHolderCount(key), MAX_OUTSTANDING_REQUESTS_PER_SESSION);

    // Releasing ONE admitted request frees exactly one slot, which is reused.
    held[0].resolve({ content: [{ type: 'text', text: '{}' }] });
    await inFlight[0];
    assert.equal(limiter.getHolderCount(key), MAX_OUTSTANDING_REQUESTS_PER_SESSION - 1);

    const next = remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
    await settle();
    assert.equal(held.length, MAX_OUTSTANDING_REQUESTS_PER_SESSION + 1, 'the slot was reused');

    for (const entry of held.slice(1)) {
      entry.resolve({ content: [{ type: 'text', text: '{}' }] });
    }
    await Promise.all([...inFlight.slice(1), next]);
    assert.equal(limiter.getHolderCount(key), 0, 'every slot was released');
  });

  test('RC05-NEG-56: a concurrency refusal is indistinguishable from a rate refusal', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const { spkiPin } = enroll(harness, 'oracle');
    const session = establishSession(harness, spkiPin);

    const { held, sink } = holdingSink();
    harness.bridge.deps.sink = sink;
    const inFlight = [];
    for (let i = 0; i < MAX_OUTSTANDING_REQUESTS_PER_SESSION; i += 1) {
      inFlight.push(remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }));
    }
    await settle();

    const concurrencyRefusal = await failure(
      remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
    );
    const rateRefusal = remoteRateLimitFailure();
    assert.equal(concurrencyRefusal.code, rateRefusal.code);
    assert.equal(concurrencyRefusal.category, rateRefusal.category);
    assert.equal(concurrencyRefusal.retryable, rateRefusal.retryable);
    assert.equal(
      concurrencyRefusal.message,
      rateRefusal.message,
      'one bounded error for both bounds: the response is not a probe',
    );

    for (const entry of held) entry.resolve({ content: [{ type: 'text', text: '{}' }] });
    await Promise.all(inFlight);
  });

  test('RC05-NEG-56: a slot is released on EVERY completion path', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const { spkiPin } = enroll(harness, 'release');
    const session = establishSession(harness, spkiPin);
    const key = sessionRateLimitKey(session);

    const paths = {
      success: () => ({ content: [{ type: 'text', text: '{}' }] }),
      'policy denial': () => ({
        isError: true,
        content: [{ type: 'text', text: JSON.stringify({ code: 'POLICY_DENIED' }) }],
      }),
      'approval requirement': () => ({
        isError: true,
        content: [
          { type: 'text', text: JSON.stringify({ code: 'APPROVAL_REQUIRED', approvalId: 'ap-1' }) },
        ],
      }),
      'approval rejection': () => ({
        isError: true,
        content: [{ type: 'text', text: JSON.stringify({ code: 'APPROVAL_REJECTED' }) }],
      }),
      'subsystem error': () => ({
        isError: true,
        content: [{ type: 'text', text: JSON.stringify({ code: 'SUBSYSTEM_ERROR' }) }],
      }),
      'thrown internal error': () => {
        throw new Error('internal failure');
      },
      'rejected internal error': () => Promise.reject(new Error('internal rejection')),
    };

    for (const [name, run] of Object.entries(paths)) {
      harness.bridge.deps.sink = { executeAuthenticatedToolCall: async () => run() };
      // A path either resolves or throws; both are legitimate outcomes here, and
      // what this case measures is the concurrency accounting afterwards.
      try {
        await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      } catch {
        // The two throwing paths are the point of their own cases.
      }
      assert.equal(limiter.getHolderCount(key), 0, `${name} leaked a concurrency slot`);
    }

    // After every path the session still holds its budget and the slot
    // accounting is clean, so nothing was poisoned.
    harness.bridge.deps.sink = {
      executeAuthenticatedToolCall: async () => ({ content: [{ type: 'text', text: '{}' }] }),
    };
    const ok = await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
    assert.equal(ok.isError, undefined);
    assert.equal(limiter.getHolderCount(key), 0);
  });

  test('RC05-NEG-56: concurrent sessions are independent', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const first = enroll(harness, 'session-a');
    const second = enroll(harness, 'session-b');
    const sessionA = establishSession(harness, first.spkiPin);
    const sessionB = establishSession(harness, second.spkiPin);

    const heldA = [];
    harness.bridge.deps.sink = {
      executeAuthenticatedToolCall: (actor) =>
        new Promise((resolve) => {
          if (actor.deviceId === first.device.deviceId) heldA.push(resolve);
          else resolve({ content: [{ type: 'text', text: '{}' }] });
        }),
    };

    const inFlight = [];
    for (let i = 0; i < MAX_OUTSTANDING_REQUESTS_PER_SESSION; i += 1) {
      inFlight.push(
        remoteCall(harness, first.spkiPin, sessionA, 'read_file', { path: 'README.md' }),
      );
    }
    await settle();
    assert.equal(
      limiter.getHolderCount(sessionRateLimitKey(sessionA)),
      MAX_OUTSTANDING_REQUESTS_PER_SESSION,
    );

    // Session B is untouched by session A's saturation.
    for (let i = 0; i < MAX_OUTSTANDING_REQUESTS_PER_SESSION; i += 1) {
      const result = await remoteCall(harness, second.spkiPin, sessionB, 'read_file', {
        path: 'README.md',
      });
      assert.equal(result.isError, undefined, `session B call ${i}`);
    }
    assert.equal(limiter.getHolderCount(sessionRateLimitKey(sessionB)), 0);

    for (const resolve of heldA) resolve({ content: [{ type: 'text', text: '{}' }] });
    await Promise.all(inFlight);
  });

  test('RC05-NEG-57: Layer C retains at most 1024 session keys', () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    for (let i = 0; i < MAX_LAYER_C_KEYS; i += 1) {
      assert.equal(limiter.consume(`session-key-${i}`).consumed, true);
    }
    assert.equal(limiter.getRetainedKeyCount(), MAX_LAYER_C_KEYS);
    for (let i = 0; i < 32; i += 1) {
      const decision = limiter.consume(`attacker-key-${i}`);
      assert.equal(decision.consumed, false);
      assert.equal(decision.reason, 'TABLE_SATURATED');
    }
    assert.equal(limiter.getRetainedKeyCount(), MAX_LAYER_C_KEYS);
  });

  test('RC05-NEG-56: an unauthenticated request never touches Layer C', async () => {
    const clock = makeClock();
    const limiter = createAuthenticatedRequestLimiter({ getMonotonicTimeMs: clock.now });
    const harness = makeHarness({ authenticatedLimiter: limiter });
    const { spkiPin } = enroll(harness, 'noauth');

    for (let i = 0; i < 8; i += 1) {
      const err = await failure(
        remoteCall(harness, spkiPin, null, 'read_file', { path: 'README.md' }),
      );
      assert.equal(err.code, 'UNAUTHENTICATED');
    }
    // Layer C is keyed on an authenticated session, so there was nothing to key
    // on: no bucket was created, no budget was spent, and the pipeline never ran.
    assert.equal(limiter.getRetainedKeyCount(), 0);
    assert.equal(harness.kernel.evaluateCalls, 0);
  });
});

// ---------------------------------------------------------------------------
// §20 — request and body bounds
// ---------------------------------------------------------------------------

/** Starts a real HTTP server that reads its body through the bounded reader. */
async function startBodyServer({ maxBytes, bodyReadTimeoutMsForTests } = {}) {
  const state = {
    kind: null,
    rawAtRefusal: 0,
    calls: 0,
    bodies: [],
    declaredLength: null,
  };
  const server = http.createServer((req, res) => {
    state.calls += 1;
    state.declaredLength = req.headers['content-length'] ?? null;
    let raw = 0;
    // Counted independently of the reader, so "how much had arrived when the
    // refusal happened" is measured from the wire rather than self-reported.
    req.on('data', (chunk) => {
      raw += chunk.length;
    });
    const respond = (status, payload) => {
      try {
        if (!res.writableEnded && !res.destroyed) {
          res.statusCode = status;
          res.end(payload);
        }
      } catch {
        // The reader may already have destroyed the socket; nothing to send.
      }
    };
    readBoundedRequestBody(req, {
      maxBytes,
      ...(bodyReadTimeoutMsForTests === undefined ? {} : { bodyReadTimeoutMsForTests }),
    })
      .then((body) => {
        state.bodies.push(body);
        respond(200, `ok:${Buffer.byteLength(body, 'utf8')}`);
      })
      .catch((err) => {
        state.kind = err instanceof RequestBodyError ? err.kind : 'UNKNOWN';
        state.rawAtRefusal = raw;
        if (state.kind === 'PAYLOAD_TOO_LARGE') respond(413, `refused:${state.kind}`);
        else if (state.kind === 'UNSUPPORTED_CONTENT_ENCODING') {
          respond(415, `refused:${state.kind}`);
        } else respond(400, `refused:${state.kind}`);
      });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, state, port: server.address().port };
}

/** Streams up to `totalBytes` and resolves when the server answers or the socket dies. */
function streamUntilAnswered(port, totalBytes, { headers = {} } = {}) {
  return new Promise((resolve) => {
    const chunk = Buffer.alloc(65536, 0x79);
    let sent = 0;
    let clientFinished = false;
    let settled = false;
    const done = (outcome) => {
      if (settled) return;
      settled = true;
      resolve({ ...outcome, clientFinished, sent });
    };
    const req = http.request(
      { host: '127.0.0.1', port, method: 'POST', path: '/', headers },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          data += c;
        });
        res.on('end', () => done({ status: res.statusCode, body: data }));
      },
    );
    req.on('error', (err) => done({ status: null, body: '', error: err }));
    const pump = () => {
      if (settled) return;
      if (sent >= totalBytes) {
        clientFinished = true;
        req.end();
        return;
      }
      const size = Math.min(chunk.length, totalBytes - sent);
      sent += size;
      if (req.write(chunk.subarray(0, size))) setImmediate(pump);
      else req.once('drain', pump);
    };
    pump();
  });
}

describe('RC-05 Task 7: §20 request and body bounds', () => {
  test('RC05-NEG-60: the frozen §20 values are exactly as specified', () => {
    assert.equal(MAX_REMOTE_BODY_BYTES, 4_194_304);
    assert.equal(MAX_REQUEST_HEADER_BYTES, 16 * 1024);
    assert.equal(MAX_REQUEST_TARGET_BYTES, 2 * 1024);
    assert.equal(BODY_READ_TIMEOUT_MS, 10_000);
    assert.equal(TOTAL_REQUEST_TIMEOUT_MS, 60_000);
  });

  test('RC05-NEG-61: the deadline seam may only SHORTEN the frozen 10 s', () => {
    assert.equal(resolveBodyReadTimeoutMs(undefined), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(1), 1);
    assert.equal(resolveBodyReadTimeoutMs(BODY_READ_TIMEOUT_MS - 1), BODY_READ_TIMEOUT_MS - 1);
    // A seam that tries to LENGTHEN the bound is ignored, as is any value that is
    // not a positive integer.
    assert.equal(resolveBodyReadTimeoutMs(BODY_READ_TIMEOUT_MS), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(BODY_READ_TIMEOUT_MS + 1), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(1_000_000), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(0), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(-5), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(1.5), BODY_READ_TIMEOUT_MS);
    assert.equal(resolveBodyReadTimeoutMs(Number.NaN), BODY_READ_TIMEOUT_MS);
  });

  test('RC05-NEG-60: exactly 4 MiB of chunked body is accepted in full', async () => {
    const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
    try {
      const outcome = await streamUntilAnswered(port, MAX_REMOTE_BODY_BYTES);
      assert.equal(outcome.status, 200, JSON.stringify(outcome));
      assert.equal(outcome.body, `ok:${MAX_REMOTE_BODY_BYTES}`);
      assert.equal(state.bodies[0].length, MAX_REMOTE_BODY_BYTES);
      assert.equal(state.kind, null);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(
      await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0),
      true,
      'no deadline was left armed',
    );
  });

  test('RC05-NEG-60: one byte over 4 MiB is refused DURING the read', async () => {
    const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
    try {
      const outcome = await streamUntilAnswered(port, MAX_REMOTE_BODY_BYTES + 1);
      assert.equal(state.kind, 'PAYLOAD_TOO_LARGE', JSON.stringify(outcome));
      // The reader stopped AT the crossing point, and no body was ever handed on.
      assert.equal(state.rawAtRefusal > MAX_REMOTE_BODY_BYTES, true);
      assert.equal(state.bodies.length, 0, 'no partial body was produced');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
  });

  test('RC05-NEG-60: a 16 MiB chunked body is refused mid-stream, unannounced', async () => {
    const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
    try {
      const total = 16 * 1024 * 1024;
      const outcome = await streamUntilAnswered(port, total);
      assert.equal(state.kind, 'PAYLOAD_TOO_LARGE', JSON.stringify({ state, outcome }));
      // The request declared NO length: the bound held on measured bytes alone,
      // so a declaration is never what enforces it.
      assert.equal(state.declaredLength, null, 'the request was chunked, not declared');
      // The client was still streaming when the body was refused, so the whole
      // 16 MiB never reached the process, let alone a parser.
      assert.equal(outcome.clientFinished, false, 'the client never finished sending');
      assert.equal(
        state.rawAtRefusal < total / 2,
        true,
        `the read stopped at the bound (${state.rawAtRefusal} of ${total})`,
      );
      assert.equal(state.bodies.length, 0);
      if (outcome.status !== null) {
        assert.equal(outcome.status, 413);
        assert.equal(outcome.body, 'refused:PAYLOAD_TOO_LARGE');
      }
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
  });

  test('RC05-NEG-60: a declared Content-Length over the bound is refused before any byte', async () => {
    const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
    try {
      const outcome = await new Promise((resolve) => {
        const req = http.request(
          {
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/',
            headers: { 'content-length': String(MAX_REMOTE_BODY_BYTES + 1) },
          },
          (res) => {
            let data = '';
            res.setEncoding('utf8');
            res.on('data', (c) => {
              data += c;
            });
            res.on('end', () => resolve({ status: res.statusCode, body: data }));
          },
        );
        req.on('error', (err) => resolve({ status: null, error: err }));
        // The declaration is sent and the body deliberately is NOT: the refusal
        // must not wait for bytes that will never arrive.
        req.flushHeaders();
      });
      assert.equal(state.rawAtRefusal, 0, 'not a single body byte was read');
      assert.equal(state.kind, 'PAYLOAD_TOO_LARGE');
      if (outcome.status !== null) assert.equal(outcome.status, 413, JSON.stringify(outcome));
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
  });

  test('RC05-NEG-60: every Content-Encoding is refused, with no decompression path', async () => {
    for (const encoding of ['gzip', 'br', 'deflate', 'identity', 'GZIP', 'gzip, br']) {
      const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
      try {
        const outcome = await streamUntilAnswered(port, 1024, {
          headers: { 'content-encoding': encoding },
        });
        assert.equal(state.kind, 'UNSUPPORTED_CONTENT_ENCODING', `${encoding}`);
        assert.equal(state.bodies.length, 0, 'no body was ever handed to a decoder');
        if (outcome.status !== null) {
          assert.equal(outcome.status, 415, `${encoding}: ${JSON.stringify(outcome)}`);
        }
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    }

    // A real compression bomb is refused on the CONTENT-ENCODING header, so its
    // decoded size is never computed: a payload that would expand to many times
    // the bound costs the process nothing.
    const { server, state, port } = await startBodyServer({ maxBytes: MAX_REMOTE_BODY_BYTES });
    try {
      const bomb = zlib.gzipSync(Buffer.alloc(16 * 1024 * 1024, 0x41));
      assert.equal(bomb.length < MAX_REMOTE_BODY_BYTES, true, 'the bomb is small on the wire');
      const outcome = await streamUntilAnswered(port, bomb.length, {
        headers: { 'content-encoding': 'gzip' },
      });
      assert.equal(state.kind, 'UNSUPPORTED_CONTENT_ENCODING');
      // The decoded size is never computed: no body was produced, so nothing was
      // inflated and the 16 MiB of expansion costs the process nothing.
      assert.equal(state.bodies.length, 0);
      if (outcome.status !== null) assert.equal(outcome.status, 415);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0), true);
  });

  test('RC05-NEG-60: the body reader contains no decompression path at all', () => {
    // The compressed-request refusal is only meaningful if nothing downstream
    // could decode. The module is pure stream accounting over Node's HTTP
    // request object: no zlib, no brotli, no stream pipeline.
    const source = fs.readFileSync(
      new URL('../apps/mcp-server/src/remote-request-bounds.ts', import.meta.url),
      'utf8',
    );
    for (const forbidden of [
      'zlib',
      'gunzip',
      'inflate',
      'brotli',
      'createGunzip',
      'node:stream',
      'pipeline(',
    ]) {
      assert.equal(source.includes(forbidden), false, `the reader must not use ${forbidden}`);
    }
  });

  test('RC05-NEG-61: a stalled body is aborted by the body-read deadline', async () => {
    const { server, state, port } = await startBodyServer({
      maxBytes: MAX_REMOTE_BODY_BYTES,
      bodyReadTimeoutMsForTests: 60,
    });
    try {
      const outcome = await new Promise((resolve) => {
        const req = http.request(
          {
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/',
            headers: { 'content-length': '64' },
          },
          () => resolve({ answered: true }),
        );
        req.on('error', (err) => resolve({ answered: false, error: err }));
        req.write('partial');
        // The body never completes: the server must abort rather than wait out
        // the frozen production bound.
        setTimeout(() => resolve({ answered: false, stalled: true }), 1500).unref();
      });
      assert.equal(outcome.answered, false, 'the stalled request was aborted, not answered');
      assert.equal(outcome.stalled, undefined, 'the abort came from the deadline');
      assert.equal(state.calls, 1);
      assert.equal(state.kind, 'READ_TIMEOUT');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
    assert.equal(
      await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0),
      true,
      'the read deadline was released',
    );
  });

  test('RC05-NEG-60: requestTargetBytes measures the received target exactly', () => {
    assert.equal(requestTargetBytes('/mcp'), 4);
    assert.equal(
      requestTargetBytes(`/${'a'.repeat(MAX_REQUEST_TARGET_BYTES - 1)}`),
      MAX_REQUEST_TARGET_BYTES,
    );
    assert.equal(requestTargetBytes(undefined), 0);
  });

  test('RC05-NEG-60: hasContentEncoding is true for any declared encoding', () => {
    assert.equal(hasContentEncoding({ headers: { 'content-encoding': 'gzip' } }), true);
    assert.equal(hasContentEncoding({ headers: { 'content-encoding': 'identity' } }), true);
    assert.equal(hasContentEncoding({ headers: {} }), false);
    assert.equal(hasContentEncoding({ headers: { 'content-encoding': '' } }), false);
  });
});

// ---------------------------------------------------------------------------
// §20 — the bounds as enforced by the live gateway
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: §20 bounds enforced at the gateway', () => {
  test('RC05-NEG-60: enrollment keeps its 4 KiB ceiling while the generic bound is 4 MiB', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      // Exactly 4096 bytes is WITHIN the bootstrap ceiling, so it reaches the
      // enrollment verifier and fails as an ordinary attempt.
      const atLimit = await httpsRequest(port, { body: bodyOfBytes(4096) });
      assert.equal(atLimit.status, 400, JSON.stringify(atLimit));
      assert.equal(atLimit.body, JSON.stringify({ error: 'Enrollment failed' }));

      const oneUnder = await httpsRequest(port, { body: bodyOfBytes(4095) });
      assert.equal(oneUnder.status, 400);

      // One byte more is a payload bound, refused before any verification.
      const overLimit = await httpsRequest(port, { body: bodyOfBytes(4097) });
      assert.equal(overLimit.status, 413, JSON.stringify(overLimit));
      assert.equal(overLimit.body, JSON.stringify({ error: 'Payload too large' }));
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-60: a compressed enrollment request is refused before verification', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      // The gateway refuses the encoding BEFORE routing, so the endpoint's own
      // JSON body is never produced: a compressed request cannot even reach the
      // bootstrap, let alone the enrollment verifier.
      const res = await httpsRequest(port, {
        body: JSON.stringify({ secret: 'a'.repeat(64) }),
        headers: { 'content-encoding': 'gzip' },
      });
      assert.equal(res.status, 413, JSON.stringify(res));
      assert.equal(res.body, 'Payload Too Large\n');
      assert.equal(res.headers['content-type'], 'text/plain; charset=utf-8');
      assert.equal(res.body.includes('Enrollment failed'), false);
      assert.equal(res.body.includes('Payload too large'), false);
      assert.equal(gateway.getEnrolledDeviceCount(), 0);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-60: a header block beyond 16 KiB never reaches the handler', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      const requestLine = 'POST /enroll/complete HTTP/1.1\r\n';
      const hostLine = `Host: 127.0.0.1:${port}\r\n`;
      const padPrefix = 'X-Pad: ';
      const overhead = Buffer.byteLength(`${requestLine}${hostLine}${padPrefix}\r\n\r\n`);

      // A head of exactly 16 KiB is within the bound and is routed normally.
      const atBound = await rawTlsRequest(
        port,
        `${requestLine}${hostLine}${padPrefix}${'a'.repeat(
          MAX_REQUEST_HEADER_BYTES - overhead,
        )}\r\n\r\n`,
      );
      assert.match(atBound.statusLine, /^HTTP\/1\.1 400 /, atBound.statusLine);
      assert.equal(atBound.raw.includes('Enrollment failed'), true);

      // A head 4 KiB past the bound is refused by the PARSER, so the request
      // handler never runs and no endpoint response is produced at all.
      const overBound = await rawTlsRequest(
        port,
        `${requestLine}${hostLine}${padPrefix}${'a'.repeat(
          MAX_REQUEST_HEADER_BYTES + 4096,
        )}\r\n\r\n`,
      );
      assert.match(overBound.statusLine, /^HTTP\/1\.1 431 /, overBound.statusLine);
      assert.equal(overBound.raw.includes('Enrollment failed'), false);
      assert.equal(overBound.raw.includes('Payload too large'), false);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-60: a request target beyond 2 KiB is refused before routing', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      const padLength = MAX_REQUEST_TARGET_BYTES - Buffer.byteLength('/enroll/complete?pad=');
      const underTarget = `/enroll/complete?pad=${'a'.repeat(padLength)}`;
      assert.equal(Buffer.byteLength(underTarget), MAX_REQUEST_TARGET_BYTES);
      const routed = await httpsRequest(port, { requestPath: underTarget, body: '{}' });
      // The target bound did NOT fire: the router answered, in JSON.
      assert.equal(routed.status, 400, JSON.stringify(routed));
      assert.equal(routed.headers['content-type'], 'application/json');

      const overTarget = `/enroll/complete?pad=${'a'.repeat(padLength + 1)}`;
      assert.equal(Buffer.byteLength(overTarget) > MAX_REQUEST_TARGET_BYTES, true);
      const refused = await httpsRequest(port, { requestPath: overTarget, body: '{}' });
      assert.equal(refused.status, 414, JSON.stringify(refused));
      assert.equal(refused.body, 'URI Too Long\n');
      assert.equal(refused.headers['content-type'], 'text/plain; charset=utf-8');
      assert.equal(refused.headers.connection, 'close');
      // The JSON router did not run: no enrollment answer at all.
      assert.equal(refused.body.includes('{'), false);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-60: a compressed request is refused before the router', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      for (const requestPath of ['/enroll/complete', '/mcp', '/anything']) {
        const res = await httpsRequest(port, {
          requestPath,
          body: '{}',
          headers: { 'content-encoding': 'deflate' },
        });
        assert.equal(res.status, 413, `${requestPath}: ${JSON.stringify(res)}`);
        assert.equal(res.body, 'Payload Too Large\n');
        assert.equal(res.headers['content-type'], 'text/plain; charset=utf-8');
        // Neither the enrollment body nor the /mcp deny-only body was produced.
        assert.equal(res.body.includes('Enrollment failed'), false);
        assert.equal(res.body.includes('UNAUTHENTICATED'), false);
      }
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-61: the total request deadline is the frozen 60 s and only shortens', async () => {
    const frozen = await startGateway({}, { admissionLimiterForTests: nonInterferingLayerA() });
    try {
      assert.equal(TOTAL_REQUEST_TIMEOUT_MS, 60_000);
      assert.equal(frozen.gateway.totalRequestTimeoutMs, TOTAL_REQUEST_TIMEOUT_MS);
    } finally {
      await frozen.gateway.stop();
    }

    for (const seam of [
      TOTAL_REQUEST_TIMEOUT_MS,
      TOTAL_REQUEST_TIMEOUT_MS + 1,
      0,
      -1,
      1.5,
      Number.NaN,
    ]) {
      const { gateway } = await startGateway(
        {},
        { admissionLimiterForTests: nonInterferingLayerA(), totalRequestTimeoutMsForTests: seam },
      );
      try {
        assert.equal(gateway.totalRequestTimeoutMs, TOTAL_REQUEST_TIMEOUT_MS, `seam ${seam}`);
      } finally {
        await gateway.stop();
      }
    }

    const shortened = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA(), totalRequestTimeoutMsForTests: 120 },
    );
    try {
      assert.equal(shortened.gateway.totalRequestTimeoutMs, 120);
    } finally {
      await shortened.gateway.stop();
    }
  });

  test('RC05-NEG-61: a request still open at the total deadline is aborted', async () => {
    // The body-read deadline is left near its frozen 10 s so the TOTAL deadline
    // is unambiguously the one that fires: the request is admitted, its body
    // never completes, and the connection is destroyed rather than held.
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        totalRequestTimeoutMsForTests: 120,
        bodyReadTimeoutMsForTests: 9_000,
      },
    );
    try {
      const outcome = await new Promise((resolve) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/enroll/complete',
            servername: publicHostname,
            ca: [fs.readFileSync(pki.trustedCaCertPath)],
            rejectUnauthorized: false,
            ...clientMaterial(),
            headers: { 'content-length': '64' },
          },
          () => resolve({ answered: true }),
        );
        req.on('error', (err) => resolve({ answered: false, error: err }));
        req.write('{"secret":');
        setTimeout(() => resolve({ answered: false, stalled: true }), 3000).unref();
      });
      assert.equal(outcome.answered, false, 'the stalled request was aborted');
      assert.equal(outcome.stalled, undefined, 'the abort came from the deadline, not the budget');
    } finally {
      await gateway.stop();
    }
    assert.equal(
      await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0),
      true,
      'the abort released the body-read deadline',
    );
  });

  test('RC05-NEG-61: a peer that vanishes mid-body releases the deadline at once', async () => {
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        // Far longer than the case: the release must come from the terminal
        // stream event, not from the deadline expiring.
        bodyReadTimeoutMsForTests: 9_000,
      },
    );
    try {
      const socket = tls.connect({
        host: '127.0.0.1',
        port,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(),
        rejectUnauthorized: false,
      });
      await new Promise((resolve) => socket.once('secureConnect', resolve));
      socket.write(
        'POST /enroll/complete HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\npartial',
      );
      assert.equal(
        await waitFor(() => getActiveBodyReadDeadlineCountForTests() >= 1, 1500),
        true,
        'the read is armed while the body is incomplete',
      );

      // The peer disappears mid-body. The reader must release its listeners and
      // its deadline on the terminal event rather than waiting out the bound.
      socket.destroy();
      assert.equal(
        await waitFor(() => getActiveBodyReadDeadlineCountForTests() === 0, 2000),
        true,
        'the deadline was released when the peer vanished',
      );
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-61: an incomplete header block is aborted by the header-read deadline', async () => {
    // §20 slowloris, HEADER phase. The header block is NEVER completed, so the
    // request handler, the router, and the body reader are none of them reached:
    // the only mechanism that can end this connection is the header-read bound.
    //
    // The seam shortens the frozen 10 s so the case runs quickly; the TOTAL
    // request deadline is left at its production 60 s, so an abort that arrives
    // promptly cannot be the total deadline expiring.
    const layerA = nonInterferingLayerA();
    const layerB = frozenLayerB(4096);
    let enrollmentCalls = 0;
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: layerA,
        layerBLimiterForTests: layerB,
        enrollmentManager: {
          completeBySpki: () => {
            enrollmentCalls += 1;
            return { ok: false };
          },
        },
        headerReadTimeoutMsForTests: 150,
      },
    );
    try {
      assert.equal(gateway.totalRequestTimeoutMs, TOTAL_REQUEST_TIMEOUT_MS);
      assert.equal(gateway.headerReadTimeoutMs, 150);

      // (1) A REAL TLS 1.3 mutual-authentication handshake completes. The server
      // only reaches its post-handshake admission once it has validated the
      // client certificate, so a held live-connection slot proves the handshake
      // was accepted rather than merely attempted.
      const socket = tls.connect({
        host: '127.0.0.1',
        port,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(),
        rejectUnauthorized: false,
      });
      await new Promise((resolve) => socket.once('secureConnect', resolve));
      assert.equal(
        await waitFor(() => layerA.getLiveConnectionCount() === 1, 1500),
        true,
        'the mTLS connection was admitted',
      );

      // (2)/(3) The request head is STARTED and deliberately left incomplete: a
      // request line and one header, with no terminating blank line, and no
      // further bytes ever written. This is exactly the slowloris shape.
      const startedAt = Date.now();
      socket.write('POST /enroll/complete HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ');

      const outcome = await new Promise((resolve) => {
        let raw = '';
        let settled = false;
        const finish = (result) => {
          if (settled) return;
          settled = true;
          resolve(result);
        };
        socket.on('data', (chunk) => {
          raw += chunk.toString('utf8');
        });
        // A server-side abort destroys the socket, which surfaces on this side
        // as `close` (and possibly `error` first).
        socket.on('close', () => finish({ raw, elapsedMs: Date.now() - startedAt }));
        socket.on('error', () => {});
        setTimeout(
          () => finish({ raw, elapsedMs: Date.now() - startedAt, budget: true }),
          6000,
        ).unref();
      });

      // (5) The connection was ABORTED, and by the header-read deadline rather
      // than by the test budget or the 60 s total request deadline.
      assert.equal(outcome.budget, undefined, 'the abort came from a deadline, not the budget');
      assert.equal(
        outcome.elapsedMs >= 150,
        true,
        `aborted no earlier than the deadline: ${outcome.elapsedMs} ms`,
      );
      assert.equal(
        outcome.elapsedMs < 5_000,
        true,
        `aborted long before the 60 s total request deadline: ${outcome.elapsedMs} ms`,
      );

      // The peer never receives a routed answer. Node refuses the stalled header
      // block itself (408) and destroys the socket; it never produces any of the
      // gateway's endpoint bodies, because no endpoint ever ran.
      assert.equal(
        outcome.raw === '' || outcome.raw.startsWith('HTTP/1.1 408 '),
        true,
        `unexpected bytes from a header-timeout abort: ${JSON.stringify(outcome.raw)}`,
      );
      assert.equal(outcome.raw.includes('Enrollment failed'), false);
      assert.equal(outcome.raw.includes('UNAUTHENTICATED'), false);

      // (6) The request handler and the router were NEVER reached. Layer B's
      // `consume` is the first accounting step `handleRequest` performs, and the
      // enrollment verifier sits behind routing, so neither having been touched
      // is a direct proof that no complete request ever existed.
      assert.equal(layerB.getRetainedKeyCount(), 0, 'the handler never ran');
      assert.equal(enrollmentCalls, 0, 'the router never ran');
      assert.equal(gateway.getEnrolledDeviceCount(), 0);

      // (7) Connection and admission state are RELEASED. Both slots an admitted
      // connection holds — the in-flight handshake slot and the live connection
      // slot — return to zero, so the abort leaves no leaked capacity behind.
      assert.equal(
        await waitFor(
          () => layerA.getLiveConnectionCount() === 0 && layerA.getInFlightHandshakeCount() === 0,
          3000,
        ),
        true,
        'the admission slots were released after the abort',
      );

      // The capacity is genuinely reusable: the same peer is admitted again.
      const next = tls.connect({
        host: '127.0.0.1',
        port,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(),
        rejectUnauthorized: false,
      });
      await new Promise((resolve) => next.once('secureConnect', resolve));
      assert.equal(await waitFor(() => layerA.getLiveConnectionCount() === 1, 1500), true);
      next.destroy();
      assert.equal(await waitFor(() => layerA.getLiveConnectionCount() === 0, 1500), true);
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-61: a longer-than-production seam cannot weaken the frozen 10 s', async () => {
    // Every one of these seams is at or above the frozen bound, or is not a
    // positive integer at all. None of them may widen the header-read window:
    // the resolved deadline stays the frozen 10 s and the check granularity
    // stays derived from it.
    for (const seam of [
      HEADER_READ_TIMEOUT_MS,
      HEADER_READ_TIMEOUT_MS + 1,
      60_000,
      600_000,
      Number.MAX_SAFE_INTEGER,
      0,
      -1,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      assert.equal(
        resolveHeaderReadTimeoutMs(seam),
        HEADER_READ_TIMEOUT_MS,
        `the seam ${seam} must not widen the header-read deadline`,
      );
      const { gateway } = await startGateway(
        {},
        { admissionLimiterForTests: nonInterferingLayerA(), headerReadTimeoutMsForTests: seam },
      );
      try {
        assert.equal(gateway.headerReadTimeoutMs, HEADER_READ_TIMEOUT_MS, `seam ${seam}`);
        assert.equal(gateway.headerReadCheckIntervalMs, HEADER_READ_CHECK_INTERVAL_MS);
      } finally {
        await gateway.stop();
      }
    }

    // Production, with no seam at all: the frozen 10 s and its 1 s granularity.
    assert.equal(resolveHeaderReadTimeoutMs(undefined), 10_000);
    assert.equal(HEADER_READ_TIMEOUT_MS, 10_000);
    assert.equal(HEADER_READ_CHECK_INTERVAL_MS, 1_000);
    assert.equal(resolveHeaderReadCheckIntervalMs(HEADER_READ_TIMEOUT_MS), 1_000);
    // A shortened deadline tightens the sweep with it, never the reverse.
    assert.equal(resolveHeaderReadCheckIntervalMs(150), 150);
    assert.equal(resolveHeaderReadCheckIntervalMs(60_000), 1_000);

    // LIVE proof, at the real frozen 10 s: with a 600 s seam supplied, an
    // incomplete header block is still aborted at ~10 s. If the seam had been
    // honoured, this connection would have stayed open for ten minutes.
    const { gateway, port } = await startGateway(
      {},
      {
        admissionLimiterForTests: nonInterferingLayerA(),
        headerReadTimeoutMsForTests: 600_000,
      },
    );
    try {
      assert.equal(gateway.headerReadTimeoutMs, 10_000, 'the 600 s seam was ignored');
      assert.notEqual(gateway.headerReadTimeoutMs, 600_000);

      const socket = tls.connect({
        host: '127.0.0.1',
        port,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        ...clientMaterial(),
        rejectUnauthorized: false,
      });
      await new Promise((resolve) => socket.once('secureConnect', resolve));
      const startedAt = Date.now();
      socket.write('POST /enroll/complete HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ');

      const outcome = await new Promise((resolve) => {
        let settled = false;
        const finish = (result) => {
          if (settled) return;
          settled = true;
          resolve(result);
        };
        socket.on('close', () => finish({ elapsedMs: Date.now() - startedAt }));
        socket.on('data', () => {});
        socket.on('error', () => {});
        setTimeout(
          () => finish({ elapsedMs: Date.now() - startedAt, budget: true }),
          14_000,
        ).unref();
      });

      assert.equal(outcome.budget, undefined, 'the connection was aborted, not left open');
      // Aborted at the frozen 10 s, plus at most one 1 s sweep — and nowhere
      // near the 600 s the seam asked for, nor the 60 s total request deadline.
      assert.equal(
        outcome.elapsedMs >= 10_000 && outcome.elapsedMs < 13_000,
        true,
        `aborted at the frozen 10 s bound, not the 600 s seam: ${outcome.elapsedMs} ms`,
      );
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-60: the gateway wires the frozen parser bounds', () => {
    const source = fs.readFileSync(
      new URL('../apps/mcp-server/src/remote-gateway.ts', import.meta.url),
      'utf8',
    );
    // The parser limits are passed as the frozen constants: not as literals that
    // could drift, and not as anything a configuration could supply.
    assert.equal(source.includes('maxHeaderSize: MAX_REQUEST_HEADER_BYTES'), true);
    assert.equal(source.includes('requestTimeout: TOTAL_REQUEST_TIMEOUT_MS'), true);
    // §20/RC05-NEG-61: the header-read deadline is its OWN frozen 10 s bound, not
    // the 60 s total request deadline reused. It is supplied together with the
    // sweep interval that makes it enforceable, because `headersTimeout` alone
    // is evaluated on a periodic sweep rather than at the deadline itself.
    assert.equal(source.includes('headersTimeout: this.headerReadTimeoutMs'), true);
    assert.equal(
      source.includes('headersTimeout: TOTAL_REQUEST_TIMEOUT_MS'),
      false,
      'the header phase must not be bounded by the 60 s total request deadline',
    );
    assert.equal(
      source.includes('connectionsCheckingInterval: this.headerReadCheckIntervalMs'),
      true,
    );
    assert.equal(source.includes('handshakeTimeout: this.handshakeTimeoutMs'), true);
    // No bound is read from the environment, a file, or a request.
    for (const forbidden of ['process.env', 'JSON.parse', 'readFileSync']) {
      assert.equal(source.includes(forbidden), false, `the gateway must not use ${forbidden}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Shutdown and reset
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: limiter state is volatile and reset on shutdown', () => {
  test('RC05-NEG-57: gateway shutdown clears Layer A and Layer B state', async () => {
    const layerA = new AdmissionLimiter();
    const layerB = frozenLayerB(LAYER_B_BURST);
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: layerA, layerBLimiterForTests: layerB },
    );
    await httpsRequest(port, { requestPath: '/mcp', body: '{}' });
    assert.equal(layerA.getRetainedPeerKeyCount(), 1);
    assert.equal(layerB.getRetainedKeyCount(), 1);

    await gateway.stop();
    assert.equal(layerA.getRetainedPeerKeyCount(), 0, 'Layer A state was dropped');
    assert.equal(layerB.getRetainedKeyCount(), 0, 'Layer B state was dropped');
    assert.equal(layerA.getLiveConnectionCount(), 0);
    assert.equal(layerA.getInFlightHandshakeCount(), 0);
  });

  test('RC05-NEG-57: nothing about limiter state survives a restart', async () => {
    const config = await baseConfig();
    const before = fs.readdirSync(tempRoot).sort();

    const first = new RemoteGateway(config, { admissionLimiterForTests: nonInterferingLayerA() });
    await first.start();
    // Exhaust the pre-session budget, so the state that must NOT survive is a
    // SATURATED one. The loop is bounded rather than fixed-length because the
    // gateway's own Layer B refills on real time.
    let sawRefusal = false;
    for (let i = 0; i < 200 && !sawRefusal; i += 1) {
      const res = await httpsRequest(first.getBoundPort(), { requestPath: '/mcp', body: '{}' });
      if (res.status === 429) sawRefusal = true;
    }
    assert.equal(sawRefusal, true, 'the pre-session budget was exhausted');
    await first.stop();

    // A restart on the same configuration gets a clean pre-session budget.
    const second = new RemoteGateway(config, { admissionLimiterForTests: nonInterferingLayerA() });
    await second.start();
    try {
      const fresh = await httpsRequest(second.getBoundPort(), { requestPath: '/mcp', body: '{}' });
      assert.equal(fresh.status, 401, JSON.stringify(fresh));
      assert.equal(second.getEnrolledDeviceCount(), 0);
    } finally {
      await second.stop();
    }

    // Nothing was persisted: the process left the filesystem exactly as it found
    // it, so no limiter state and no enrollment state can outlive a restart.
    assert.deepEqual(fs.readdirSync(tempRoot).sort(), before);
  });

  test('RC05-NEG-57: the composed server owns exactly one Layer C limiter and resets it', () => {
    const source = fs.readFileSync(
      new URL('../apps/mcp-server/src/index.ts', import.meta.url),
      'utf8',
    );
    // One process-wide instance, created once and injected into the bridge, and
    // created with NO arguments: the frozen bounds are not parameterized, so no
    // configuration, environment, CLI, HTTP, MCP, or JSON value can pick a
    // weaker rate, burst, key ceiling, or concurrency limit.
    assert.equal(source.split('createAuthenticatedRequestLimiter()').length - 1, 1);
    assert.equal(source.includes('createAuthenticatedRequestLimiter({'), false);
    assert.equal(source.includes('authenticatedLimiter: this.authenticatedRequestLimiter'), true);
    assert.equal(source.includes('this.authenticatedRequestLimiter.reset();'), true);
    for (const forbidden of ['requestsPerMinute', 'rateLimit']) {
      assert.equal(source.includes(forbidden), false, `index.ts must not carry ${forbidden}`);
    }
  });
});

// ---------------------------------------------------------------------------
// Frozen, non-configurable bounds and the Task-8 boundary
// ---------------------------------------------------------------------------

describe('RC-05 Task 7: bounds are frozen and the Task-8 boundary is intact', () => {
  test('RC05-NEG-57: no bound is reachable from configuration or the environment', () => {
    for (const file of [
      '../apps/mcp-server/src/remote-resource-limits.ts',
      '../apps/mcp-server/src/remote-request-bounds.ts',
    ]) {
      const source = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
      // No bound may be read from a launch configuration, the environment, or
      // any parsed input: the modules import nothing from the configuration
      // surface and never parse anything.
      for (const forbidden of [
        'process.env',
        'JSON.parse',
        "from './remote-config",
        "from './index",
        "from './remote-gateway",
      ]) {
        assert.equal(source.includes(forbidden), false, `${file} must not use ${forbidden}`);
      }
    }
    // The remote configuration surface exposes no rate or bound knob at all.
    const config = fs.readFileSync(
      new URL('../apps/mcp-server/src/remote-config.ts', import.meta.url),
      'utf8',
    );
    for (const forbidden of ['requestsPerMinute', 'burst', 'maxKeys', 'maxBodyBytes']) {
      assert.equal(config.includes(forbidden), false, `RemoteConfig must not expose ${forbidden}`);
    }
  });

  test('RC05-NEG-55: /mcp stays deny-only and composes no SDK transport', async () => {
    const { gateway, port } = await startGateway(
      {},
      { admissionLimiterForTests: nonInterferingLayerA() },
    );
    try {
      // A POST that looks exactly like an MCP frame is answered by the deny-only
      // placeholder: no session is created, no token is issued, nothing runs.
      const ready = await httpsRequest(port, {
        requestPath: '/mcp',
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      });
      assert.equal(ready.status, 401, JSON.stringify(ready));
      assert.equal(
        ready.body,
        JSON.stringify({ code: 'UNAUTHENTICATED', message: 'Authentication failed' }),
      );
      assert.equal(ready.headers['mcp-session-id'], undefined);
      assert.equal(ready.headers['arc-session-token'], undefined);
      assert.equal(ready.headers.connection, 'close');

      // Every other method on /mcp is refused the same way.
      for (const method of ['GET', 'DELETE', 'PUT', 'PATCH']) {
        const res = await httpsRequest(port, { method, requestPath: '/mcp' });
        assert.equal(res.status, 401, `${method}: ${JSON.stringify(res)}`);
        assert.equal(res.headers['mcp-session-id'], undefined);
      }
    } finally {
      await gateway.stop();
    }
  });

  test('RC05-NEG-55: the SDK transport surface stays confined to the one Task-8 module', () => {
    // Task 8 intentionally crosses this boundary: exactly ONE remote MCP
    // transport now exists. The security property is not "no transport anywhere"
    // but "exactly one transport, in exactly one module, and none of the
    // forbidden transports anywhere". Containment is therefore asserted two
    // ways: the surface strings may appear ONLY in `remote-mcp-surface.ts`, and
    // the client transport, the deprecated SSE transport, and any `eventStore`
    // (which would add resumability/replay §3 forbids) must appear NOWHERE.
    const srcDir = new URL('../apps/mcp-server/src/', import.meta.url);
    const files = fs.readdirSync(srcDir).filter((name) => name.endsWith('.ts'));
    assert.equal(files.length > 0, true);

    const SURFACE_MODULE = 'remote-mcp-surface.ts';
    const surfaceOnly = ['StreamableHTTPServerTransport', 'streamableHttp', 'sessionIdGenerator'];
    const forbiddenEverywhere = [
      'StreamableHTTPClientTransport',
      'SSEServerTransport',
      'eventStore',
      'Arc-Session-Token',
      "setHeader('Mcp-Session-Id'",
      'setHeader("Mcp-Session-Id"',
    ];

    const composing = [];
    for (const name of files) {
      const source = fs.readFileSync(new URL(name, srcDir), 'utf8');
      for (const forbidden of forbiddenEverywhere) {
        assert.equal(source.includes(forbidden), false, `${name} must not contain ${forbidden}`);
      }
      if (surfaceOnly.some((marker) => source.includes(marker))) {
        composing.push(name);
      }
    }

    // ONE module composes a remote transport. A second one would mean a second
    // listener, a second dispatcher, or a shadow session authority.
    assert.deepEqual(composing, [SURFACE_MODULE]);
  });

  test('RC05-NEG-55: the Layer C refusal discloses no limiter internals', () => {
    // The single client-facing Layer C failure is fixed text: it carries no key,
    // no peer address, no bucket level, no remaining-token count, and no retry
    // hint, so a client cannot probe the limiter through the response.
    const err = remoteRateLimitFailure();
    assert.equal(err.code, 'RATE_LIMIT_EXCEEDED');
    assert.equal(Object.keys(err).includes('key'), false);
    assert.equal(Object.keys(err).includes('remaining'), false);
    assert.equal(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/.test(err.message), false);
    assert.equal(err.message.includes(':'), false);
    assert.equal(err.message.includes('/64'), false);
    assert.equal(err.message.includes('unknown-peer'), false);
  });
});
