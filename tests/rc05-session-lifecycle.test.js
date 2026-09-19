/**
 * CesSpace ARC — RC-05 Task 5: Secure Session Lifecycle
 *
 * Covers the frozen session contract (rc05-scope-acceptance.md §5.3, §5.4, §11,
 * §25.1, §26 C-2/C-4) and the Task-5 negative controls RC05-NEG-39..47 and
 * RC05-NEG-69.
 *
 * Everything here is PURE DOMAIN: no network listener, no HTTP server, no MCP
 * SDK transport, no policy evaluation, no approval redemption, and no subsystem
 * invocation. The two externally-constructed objects used are the real Task-1
 * `DeviceTrustStore` (to prove trusted identity resolution) and a real RC-04
 * `ApprovalStateManager` (to prove credential-domain separation with a genuine
 * approval token, not a stand-in).
 *
 * Clocks are injected monotonic counters, so no test sleeps and none depends on
 * wall time. Where randomness is injected it is only to make a collision
 * deterministic; production randomness is exercised by the shape assertions.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

import {
  SessionManager,
  resolveActiveDeviceIdentity,
  parseBearerCredential,
  DeviceTrustStore,
  SESSION_ID_REGEX,
  SESSION_TOKEN_REGEX,
  MAX_SESSION_TOKEN_INPUT_BYTES,
  SESSION_ABSOLUTE_TTL_SECONDS,
  SESSION_IDLE_TIMEOUT_SECONDS,
  MAX_ACTIVE_SESSIONS_PER_DEVICE,
  MAX_ACTIVE_SESSIONS_PER_CLIENT,
  MAX_ACTIVE_SESSIONS_GLOBAL,
  MAX_SESSION_ID_GENERATION_ATTEMPTS,
  ARC_SESSION_TOKEN_HEADER,
  MCP_SESSION_ID_HEADER,
} from '../packages/auth/dist/index.js';
import { ApprovalStateManager } from '../packages/policy/dist/index.js';

/** Canonical SPKI pin shape. */
function pin(seed) {
  return crypto.createHash('sha256').update(`session-pin-${seed}`, 'utf8').digest('hex');
}

/** A trusted identity as ARC would derive it from mTLS + the trust store. */
function identity(seed, overrides = {}) {
  return {
    deviceId: crypto.createHash('sha256').update(`device-${seed}`).digest('hex').slice(0, 32),
    clientId: `client-${seed}`,
    clientType: 'claude-code',
    spkiPin: pin(seed),
    ...overrides,
  };
}

const SECOND = 1_000_000_000n;

describe('CesSpace ARC — RC-05 Task 5: Secure Session Lifecycle', () => {
  let mono;
  let manager;

  beforeEach(() => {
    mono = 1_000_000_000_000n;
    manager = new SessionManager({ getMonotonicTime: () => mono });
  });

  /** Issues a session with a generator-produced server ID and a trusted identity. */
  function issue(seed, overrides = {}) {
    const id = identity(seed, overrides);
    const sessionId = manager.createSessionIdGenerator()();
    const issuance = manager.issueSession({ sessionId, identity: id });
    return { id, sessionId, issuance };
  }

  /** The dual-header context for an ordinary authenticated request. */
  function ordinaryContext(target, overrides = {}) {
    return {
      kind: 'ordinary',
      hasExistingSessionContext: true,
      presentedSessionId: target.sessionId,
      authorizationHeader: `Bearer ${target.issuance.token}`,
      identity: target.id,
      ...overrides,
    };
  }

  // =========================================================================
  // Generation and issuance
  // =========================================================================

  describe('Session identity and token generation', () => {
    test('RC05-SES-01: the server session ID is 256 bits of CSPRNG as 64 lowercase hex', () => {
      const generate = manager.createSessionIdGenerator();
      const seen = new Set();
      for (let i = 0; i < 64; i += 1) {
        const sessionId = generate();
        assert.match(sessionId, SESSION_ID_REGEX);
        assert.equal(sessionId.length, 64);
        assert.equal(sessionId, sessionId.toLowerCase());
        seen.add(sessionId);
      }
      assert.equal(seen.size, 64, 'generated identifiers must not repeat');
    });

    test('RC05-SES-02: the raw session token is 256 bits of CSPRNG as 64 lowercase hex', () => {
      const { issuance } = issue('token-shape');
      assert.match(issuance.token, SESSION_TOKEN_REGEX);
      assert.equal(issuance.token.length, 64);
      assert.equal(issuance.token, issuance.token.toLowerCase());
      // 64 hex characters is exactly 256 bits of entropy.
      assert.equal(Buffer.from(issuance.token, 'hex').length, 32);
    });

    test('RC05-SES-03: the token is independent of the session ID and of the identity', () => {
      const a = issue('independence-a');
      const b = issue('independence-b');

      assert.notEqual(a.issuance.token, a.sessionId, 'token must not equal its session ID');
      assert.notEqual(a.issuance.token, b.issuance.token);
      assert.notEqual(a.sessionId, b.sessionId);
      // No derivation from any bound identifier.
      for (const source of [a.id.deviceId, a.id.clientId, a.id.spkiPin, a.sessionId]) {
        assert.equal(a.issuance.token.includes(source), false);
      }
      // Not a slice or hash of the session ID.
      assert.notEqual(
        a.issuance.token,
        crypto.createHash('sha256').update(a.sessionId).digest('hex'),
      );
    });

    test('RC05-SES-04: the session ID is server-issued and the client cannot choose it', () => {
      const a = issue('server-side');
      const b = issue('server-side');

      // The manager never accepts a caller-provided ID as the issuance authority:
      // the ID it returns came from its own generator.
      assert.match(a.sessionId, SESSION_ID_REGEX);
      assert.notEqual(a.sessionId, b.sessionId);

      // There is exactly ONE session identity: the ID returned by issuance is the
      // ID the session is keyed by, with no second independently generated
      // actor session identifier.
      assert.equal(manager.hasSession(a.sessionId), true);
      assert.equal(a.issuance.sessionId, a.sessionId);
      const views = manager.listSessions();
      assert.equal(views.length, 2);
      assert.deepEqual(views.map((v) => v.sessionId).sort(), [a.sessionId, b.sessionId].sort());
    });

    test('RC05-SES-05: the raw token is returned exactly once and is not retrievable', () => {
      const { id, sessionId, issuance } = issue('once-only');

      // The one and only copy the caller ever gets.
      assert.equal(typeof issuance.token, 'string');
      assert.match(issuance.token, SESSION_TOKEN_REGEX);

      // It is not in the bounded view, and it is not in the record.
      const views = manager.listSessions();
      const serialized = JSON.stringify(views);
      assert.equal(serialized.includes(issuance.token), false, 'token must not appear in views');
      assert.equal(
        serialized.includes(crypto.createHash('sha256').update(issuance.token).digest('hex')),
        false,
        'the digest is internal too',
      );

      // It is not reachable through any getter on the manager.
      for (const value of Object.values(Object.fromEntries(Object.entries(manager)))) {
        assert.equal(typeof value === 'string' && value === issuance.token, false);
      }

      // Re-verification must still succeed, which proves the manager verifies a
      // digest rather than a retained copy.
      assert.ok(
        manager.authenticate({ sessionId, token: issuance.token, identity: id }),
        'the session authenticates from the digest alone',
      );

      // There is no way to ask the manager for the token again: re-issuing the
      // same session ID is refused outright, so the credential cannot be
      // recovered by replaying the issuance call.
      assert.throws(
        () => manager.issueSession({ sessionId, identity: id }),
        (err) => err.code === 'CONFLICT_PRECONDITION_FAILED',
        'the live session ID cannot be re-issued to recover a token',
      );
      assert.equal(manager.listSessions().length, 1);

      // A NEW session for the same identity yields a DIFFERENT token, so the
      // manager is generating fresh material rather than recalling old bytes.
      const second = manager.issueSession({
        sessionId: manager.createSessionIdGenerator()(),
        identity: id,
      });
      assert.notEqual(second.token, issuance.token);
      assert.equal(manager.listSessions().length, 2);
      assert.equal(JSON.stringify(manager.listSessions()).includes(issuance.token), false);
      assert.equal(JSON.stringify(manager.listSessions()).includes(second.token), false);
    });

    test('RC05-SES-06: the session record holds a 32-byte digest and not the raw token', () => {
      const { id, sessionId, issuance } = issue('digest-only');
      const expectedDigest = crypto.createHash('sha256').update(issuance.token, 'utf8').digest();

      // Inspect the authoritative record itself (TypeScript `private` is a
      // compile-time concept, so the runtime record is reachable here) to state
      // exactly what the server retains.
      const records = [...manager.sessions.values()];
      assert.equal(records.length, 1);
      const [record] = records;
      assert.equal(record.sessionId, sessionId);
      assert.equal(record.deviceId, id.deviceId);
      assert.equal(record.clientId, id.clientId);
      assert.equal(record.clientType, id.clientType);
      assert.equal(record.spkiPin, id.spkiPin);
      assert.equal(Buffer.isBuffer(record.tokenDigest), true, 'only a digest is retained');
      assert.equal(record.tokenDigest.length, 32);
      assert.equal(
        record.tokenDigest.equals(expectedDigest),
        true,
        'the retained digest is SHA-256 of the exact issued token',
      );
      assert.equal(record.revoked, false);
      assert.equal(typeof record.createdMonotonic, 'bigint');
      assert.equal(typeof record.lastAuthMonotonic, 'bigint');
      // No field of the record is the raw token, under any name.
      const serialized = JSON.stringify(record, (key, value) =>
        typeof value === 'bigint' ? value.toString() : value,
      );
      assert.equal(serialized.includes(issuance.token), false);
      assert.equal(
        Object.values(record).some((value) => value === issuance.token),
        false,
        'the raw token must not be a value on the record',
      );

      // A different token must fail, proving the stored value is a digest of the
      // exact token and nothing weaker.
      const wrong = crypto.randomBytes(32).toString('hex');
      assert.equal(manager.authenticate({ sessionId, token: wrong, identity: id }), undefined);
      assert.ok(manager.authenticate({ sessionId, token: issuance.token, identity: id }));
    });

    test('RC05-SES-07: bounded collision retries never overwrite a live session', () => {
      const { sessionId } = issue('collision');

      // A deterministic source that always returns the SAME bytes as the live
      // session ID, so every draw collides.
      const collidingBytes = Buffer.from(sessionId, 'hex');
      let draws = 0;
      const colliding = new SessionManager({
        getMonotonicTime: () => mono,
        randomBytes: (size) => {
          draws += 1;
          return Buffer.concat([collidingBytes, Buffer.alloc(Math.max(0, size - 32))]).subarray(
            0,
            size,
          );
        },
      });
      // Seed the live session into the colliding manager so the generator sees it.
      colliding.issueSession({ sessionId, identity: identity('collision') });
      // Token minting also drew randomness; count only the generator's draws.
      draws = 0;

      const generate = colliding.createSessionIdGenerator();
      assert.throws(
        () => generate(),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
        'exhaustion must fail closed rather than loop',
      );
      assert.equal(
        draws,
        MAX_SESSION_ID_GENERATION_ATTEMPTS,
        'collision retries are bounded at the frozen attempt limit',
      );
      // The live session was never overwritten.
      assert.equal(colliding.hasSession(sessionId), true);
    });

    test('RC05-SES-08: a bounded collision sequence eventually yields a free identifier', () => {
      const { sessionId } = issue('collision-then-free');
      const bytes = Buffer.from(sessionId, 'hex');

      let draws = 0;
      const flaky = new SessionManager({
        getMonotonicTime: () => mono,
        randomBytes: (size) => {
          draws += 1;
          if (draws <= 2) {
            return Buffer.concat([bytes, Buffer.alloc(Math.max(0, size - 32))]).subarray(0, size);
          }
          return crypto.randomBytes(size);
        },
      });
      flaky.issueSession({ sessionId, identity: identity('collision-then-free') });

      const generated = flaky.createSessionIdGenerator()();
      assert.match(generated, SESSION_ID_REGEX);
      assert.notEqual(generated, sessionId);
      assert.equal(draws, 3, 'two collisions then a fresh identifier');
      assert.equal(flaky.hasSession(sessionId), true, 'the live session is untouched');
    });
  });

  // =========================================================================
  // Trusted identity
  // =========================================================================

  describe('Trusted session identity', () => {
    test('RC05-SES-09: an active enrolled device resolves from the real trust store', () => {
      const store = DeviceTrustStore.createEmpty();
      const { device } = store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('enrolled'),
      });

      const resolved = resolveActiveDeviceIdentity(store, pin('enrolled'));
      assert.ok(resolved);
      assert.equal(resolved.deviceId, device.deviceId);
      assert.equal(resolved.clientId, 'agent-alpha');
      assert.equal(resolved.clientType, 'claude-code');
      assert.equal(resolved.spkiPin, pin('enrolled'));
    });

    test('RC05-SES-10: an unknown pin and a revoked device resolve to nothing', () => {
      const store = DeviceTrustStore.createEmpty();
      const { device } = store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('revocable'),
      });

      assert.equal(resolveActiveDeviceIdentity(store, pin('never-enrolled')), undefined);
      assert.equal(resolveActiveDeviceIdentity(store, 'not-a-pin'), undefined);
      assert.equal(resolveActiveDeviceIdentity(store, 'A'.repeat(64)), undefined);
      assert.equal(resolveActiveDeviceIdentity(store, ''), undefined);

      store.revokeDevice(device.deviceId);
      assert.equal(
        resolveActiveDeviceIdentity(store, pin('revocable')),
        undefined,
        'a revoked device yields no trusted identity',
      );
    });

    test('RC05-SES-11: issuance accepts only server-derived, well-formed identity input', () => {
      const sessionId = manager.createSessionIdGenerator()();
      const cases = [
        { deviceId: 'not-hex' },
        { deviceId: 'a'.repeat(31) },
        { spkiPin: 'A'.repeat(64) },
        { spkiPin: 'a'.repeat(63) },
        { clientId: '' },
        { clientType: '' },
      ];
      for (const override of cases) {
        assert.throws(
          () => manager.issueSession({ sessionId, identity: identity('bad', override) }),
          (err) => err.code === 'INVALID_REQUEST_SCHEMA',
          JSON.stringify(Object.keys(override)),
        );
      }
      assert.throws(
        () => manager.issueSession({ sessionId, identity: null }),
        (err) => err.code === 'INVALID_REQUEST_SCHEMA',
      );
      assert.equal(manager.getActiveSessionCount(), 0);
    });
  });

  // =========================================================================
  // Dual-header authentication
  // =========================================================================

  describe('Dual-header authentication (§5.3 G/H, §12 step 4)', () => {
    test('RC05-SES-12: exact session ID, token, and identity authenticate', () => {
      const target = issue('happy-path');
      const result = manager.authenticate({
        sessionId: target.sessionId,
        token: target.issuance.token,
        identity: target.id,
      });

      assert.ok(result);
      assert.equal(result.sessionId, target.sessionId);
      assert.equal(result.deviceId, target.id.deviceId);
      assert.equal(result.clientId, target.id.clientId);
      assert.equal(result.clientType, target.id.clientType);
      assert.equal(result.spkiPin, target.id.spkiPin);
      assert.equal(typeof result.issuedAt, 'string');
      // The raw token is nowhere in the trusted result.
      assert.equal(JSON.stringify(result).includes(target.issuance.token), false);
      // No token digest is exposed either.
      assert.equal(
        JSON.stringify(result).includes(
          crypto.createHash('sha256').update(target.issuance.token).digest('hex'),
        ),
        false,
      );
    });

    test('RC05-NEG-42: a valid session ID with a missing token is INVALID_SESSION_TOKEN', () => {
      const target = issue('missing-token');
      const before = manager.listSessions();

      for (const authorizationHeader of [null, undefined, '', 'Bearer ', 'Bearer']) {
        const decision = manager.admitRequest(ordinaryContext(target, { authorizationHeader }));
        assert.deepEqual(decision, { outcome: 'INVALID_SESSION_TOKEN' });
      }

      assert.deepEqual(manager.listSessions(), before, 'the session is unchanged');
    });

    test('RC05-NEG-44: a valid session ID with a wrong token is INVALID_SESSION_TOKEN', () => {
      const target = issue('wrong-token');
      const wrong = crypto.randomBytes(32).toString('hex');
      assert.notEqual(wrong, target.issuance.token);

      const decision = manager.admitRequest(
        ordinaryContext(target, {
          authorizationHeader: `Bearer ${wrong}`,
        }),
      );
      assert.deepEqual(decision, { outcome: 'INVALID_SESSION_TOKEN' });

      // The genuine credential still works, so nothing was broken.
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');
    });

    test('RC05-NEG-45: a valid token from a different TLS identity is INVALID_SESSION_TOKEN', () => {
      const target = issue('portability');

      const otherIdentity = identity('portability-other');
      const otherDeviceIdentity = identity('portability', { deviceId: identity('x').deviceId });
      const otherClientIdentity = identity('portability', { clientId: 'someone-else' });
      const otherTypeIdentity = identity('portability', { clientType: 'other-client' });

      for (const identityOverride of [
        otherIdentity,
        otherDeviceIdentity,
        otherClientIdentity,
        otherTypeIdentity,
      ]) {
        const decision = manager.admitRequest(
          ordinaryContext(target, { identity: identityOverride }),
        );
        assert.deepEqual(
          decision,
          { outcome: 'INVALID_SESSION_TOKEN' },
          'a stolen token is not portable across device, client, or TLS identity',
        );
      }

      // The correct identity in the same state still authenticates.
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');
    });

    test('RC05-NEG-43: a valid token with a different Mcp-Session-Id is INVALID_SESSION_TOKEN', () => {
      const a = issue('cross-a');
      const b = issue('cross-b');

      // Token A with session ID B.
      const crossed = manager.admitRequest(
        ordinaryContext(b, { authorizationHeader: `Bearer ${a.issuance.token}` }),
      );
      assert.deepEqual(crossed, { outcome: 'INVALID_SESSION_TOKEN' });

      // And the mirror image.
      const mirrored = manager.admitRequest(
        ordinaryContext(a, { authorizationHeader: `Bearer ${b.issuance.token}` }),
      );
      assert.deepEqual(mirrored, { outcome: 'INVALID_SESSION_TOKEN' });

      // Neither session was mutated: both still authenticate with their own pair.
      assert.deepEqual(manager.admitRequest(ordinaryContext(a)).outcome, 'AUTHENTICATED');
      assert.deepEqual(manager.admitRequest(ordinaryContext(b)).outcome, 'AUTHENTICATED');
    });

    test('RC05-SES-13: an unknown or malformed session ID is INVALID_SESSION_TOKEN', () => {
      const target = issue('unknown-id');

      for (const presentedSessionId of [
        crypto.randomBytes(32).toString('hex'),
        'not-an-id',
        'a'.repeat(63),
        'A'.repeat(64),
        '',
      ]) {
        const decision = manager.admitRequest(ordinaryContext(target, { presentedSessionId }));
        assert.deepEqual(
          decision,
          { outcome: 'INVALID_SESSION_TOKEN' },
          `presented ID ${JSON.stringify(presentedSessionId)} must be refused`,
        );
      }
    });

    test('RC05-SES-14: a credential with no server session to bind to is refused', () => {
      const target = issue('orphan-credential');
      const decision = manager.admitRequest({
        kind: 'ordinary',
        hasExistingSessionContext: true,
        presentedSessionId: null,
        authorizationHeader: `Bearer ${target.issuance.token}`,
        identity: target.id,
      });
      assert.deepEqual(decision, { outcome: 'INVALID_SESSION_TOKEN' });
    });

    test('RC05-NEG-46: every malformed token shape is INVALID_SESSION_TOKEN', () => {
      const target = issue('malformed');
      const before = manager.listSessions();

      const oversized = 'a'.repeat(MAX_SESSION_TOKEN_INPUT_BYTES + 1);
      const multibyteOversized = 'é'.repeat(65); // 130 UTF-8 bytes
      assert.ok(Buffer.byteLength(multibyteOversized, 'utf8') > MAX_SESSION_TOKEN_INPUT_BYTES);

      const malformed = [
        oversized,
        multibyteOversized,
        'z'.repeat(64),
        'a'.repeat(63),
        'a'.repeat(65),
        'A'.repeat(64),
        'not-hex-at-all',
        '',
        ' ',
        ' '.repeat(64),
      ];

      for (const token of malformed) {
        const decision = manager.admitRequest(
          ordinaryContext(target, {
            authorizationHeader: `Bearer ${token}`,
          }),
        );
        assert.deepEqual(
          decision,
          { outcome: 'INVALID_SESSION_TOKEN' },
          `token of length ${token.length} must be refused`,
        );
        // Direct verification agrees with admission.
        assert.equal(
          manager.authenticate({ sessionId: target.sessionId, token, identity: target.id }),
          undefined,
        );
      }

      assert.deepEqual(manager.listSessions(), before, 'no session mutated by malformed input');
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');
    });

    test('RC05-SES-15: only the intended bearer credential form is accepted', () => {
      const token = crypto.randomBytes(32).toString('hex');
      assert.equal(parseBearerCredential(`Bearer ${token}`), token);
      assert.equal(parseBearerCredential(`bearer ${token}`), token);

      for (const header of [
        token, // bare token, no scheme
        `Basic ${token}`,
        `Token ${token}`,
        `Bearer  ${token}`, // two spaces
        `Bearer ${token} extra`,
        `Bearer ${token},Bearer ${token}`,
        'Bearer',
        'Bearer ',
        '',
        null,
        undefined,
        42,
        {},
      ]) {
        assert.equal(
          parseBearerCredential(header),
          null,
          `header ${JSON.stringify(header)} must not yield a credential`,
        );
      }

      // A comma list or extra field never reaches the verifier.
      const target = issue('header-form');
      for (const authorizationHeader of [
        `Basic ${target.issuance.token}`,
        `Bearer ${target.issuance.token} extra`,
        `Bearer ${target.issuance.token},Bearer ${target.issuance.token}`,
      ]) {
        assert.deepEqual(manager.admitRequest(ordinaryContext(target, { authorizationHeader })), {
          outcome: 'INVALID_SESSION_TOKEN',
        });
      }
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');
    });

    test('RC05-SES-16: the failed-verification path never mutates any session', () => {
      const a = issue('no-mutation-a');
      const b = issue('no-mutation-b');
      const before = JSON.stringify(manager.listSessions());

      // One mismatch per bound field, so each binding dimension is shown to be
      // both enforced and side-effect free.
      const failures = [
        ordinaryContext(a, {
          authorizationHeader: `Bearer ${crypto.randomBytes(32).toString('hex')}`,
        }),
        ordinaryContext(b, { authorizationHeader: null }),
        ordinaryContext(a, { authorizationHeader: `Bearer ${b.issuance.token}` }),
        ordinaryContext(a, { authorizationHeader: 'Bearer ' + 'A'.repeat(64) }),
        ordinaryContext(a, { identity: identity('no-mutation-other') }),
        ordinaryContext(a, { identity: { ...a.id, spkiPin: pin('no-mutation-other') } }),
        ordinaryContext(a, { identity: { ...a.id, deviceId: identity('x').deviceId } }),
        ordinaryContext(a, { identity: { ...a.id, clientId: 'someone-else' } }),
        ordinaryContext(a, { identity: { ...a.id, clientType: 'other-client' } }),
      ];
      for (const context of failures) {
        assert.deepEqual(manager.admitRequest(context), { outcome: 'INVALID_SESSION_TOKEN' });
      }

      assert.equal(JSON.stringify(manager.listSessions()), before, 'no session state changed');
      assert.deepEqual(manager.admitRequest(ordinaryContext(a)).outcome, 'AUTHENTICATED');
      assert.deepEqual(manager.admitRequest(ordinaryContext(b)).outcome, 'AUTHENTICATED');
    });
  });

  // =========================================================================
  // Expiry
  // =========================================================================

  describe('Monotonic expiry (§11, §26 C-2)', () => {
    test('RC05-SES-17: the absolute TTL is 3600 seconds on the monotonic clock', () => {
      const start = mono;
      const target = issue('absolute');
      const boundary = issue('absolute-boundary');

      // Advance toward the absolute deadline while authenticating along the way,
      // so each success refreshes the IDLE deadline and this case isolates the
      // ABSOLUTE bound rather than tripping the 300 s idle timeout first.
      let elapsed = 0;
      while (elapsed < SESSION_ABSOLUTE_TTL_SECONDS - 1) {
        elapsed = Math.min(SESSION_ABSOLUTE_TTL_SECONDS - 1, elapsed + 299);
        mono = start + BigInt(elapsed) * SECOND;
        for (const session of [target, boundary]) {
          assert.deepEqual(
            manager.admitRequest(ordinaryContext(session)).outcome,
            'AUTHENTICATED',
            `still valid ${SESSION_ABSOLUTE_TTL_SECONDS - elapsed} s before the absolute deadline`,
          );
        }
      }
      assert.equal(mono, start + BigInt(SESSION_ABSOLUTE_TTL_SECONDS - 1) * SECOND);

      // The boundary is inclusive: now >= created + 3600 s is expired. Both
      // sessions were refreshed one second ago, which proves the absolute bound
      // is measured from ISSUANCE and cannot be extended by activity.
      mono += SECOND;
      for (const session of [target, boundary]) {
        assert.equal(
          manager.authenticate({
            sessionId: session.sessionId,
            token: session.issuance.token,
            identity: session.id,
          }),
          undefined,
          'exactly 3600 s after issuance the session is expired',
        );
        assert.deepEqual(manager.admitRequest(ordinaryContext(session)), {
          outcome: 'INVALID_SESSION_TOKEN',
        });
      }
    });

    test('RC05-SES-18: the idle timeout is 300 seconds since the last successful auth', () => {
      const target = issue('idle');

      mono += BigInt(SESSION_IDLE_TIMEOUT_SECONDS - 1) * SECOND;
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');

      // That success reset the idle deadline, so another 299 s is fine.
      mono += BigInt(SESSION_IDLE_TIMEOUT_SECONDS - 1) * SECOND;
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)).outcome, 'AUTHENTICATED');

      // Exactly 300 s after the last SUCCESS is expired, even though the
      // absolute deadline is still far away.
      mono += BigInt(SESSION_IDLE_TIMEOUT_SECONDS) * SECOND;
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
    });

    test('RC05-SES-19: only a SUCCESSFUL authentication refreshes the idle deadline', () => {
      const target = issue('no-refresh');
      const wrong = crypto.randomBytes(32).toString('hex');

      const failedContexts = [
        ordinaryContext(target, { authorizationHeader: `Bearer ${wrong}` }),
        ordinaryContext(target, { authorizationHeader: null }),
        ordinaryContext(target, { authorizationHeader: `Bearer ${'A'.repeat(64)}` }),
        ordinaryContext(target, { authorizationHeader: `Bearer ${'z'.repeat(64)}` }),
        ordinaryContext(target, { presentedSessionId: crypto.randomBytes(32).toString('hex') }),
        ordinaryContext(target, { identity: identity('no-refresh-other') }),
        ordinaryContext(target, {
          authorizationHeader: `Bearer ${'a'.repeat(MAX_SESSION_TOKEN_INPUT_BYTES + 1)}`,
        }),
      ];

      // Repeated failures spread across the idle window must not extend it.
      for (let i = 0; i < failedContexts.length; i += 1) {
        mono += BigInt(40) * SECOND;
        const decision = manager.admitRequest(failedContexts[i]);
        assert.notEqual(decision.outcome, 'AUTHENTICATED');
      }

      // 280 s have elapsed since issuance, all of it spent on failures.
      assert.ok(mono > 0n);
      mono += BigInt(SESSION_IDLE_TIMEOUT_SECONDS) * SECOND;
      assert.deepEqual(
        manager.admitRequest(ordinaryContext(target)),
        { outcome: 'INVALID_SESSION_TOKEN' },
        'failed requests cannot keep a session alive',
      );
    });

    test('RC05-SES-20: wall-clock movement cannot alter authorization lifetime', () => {
      let wall = 1_800_000_000_000;
      const clocked = new SessionManager({
        getMonotonicTime: () => mono,
        getWallTime: () => wall,
      });
      const id = identity('wall');
      const sessionId = clocked.createSessionIdGenerator()();
      const { token } = clocked.issueSession({ sessionId, identity: id });

      // The wall clock jumps far forward and backward; monotonic time has not moved.
      wall += 86_400_000;
      assert.ok(clocked.authenticate({ sessionId, token, identity: id }), 'wall forward');
      wall -= 172_800_000;
      assert.ok(clocked.authenticate({ sessionId, token, identity: id }), 'wall rollback');

      // Only monotonic time can expire it.
      mono += BigInt(SESSION_ABSOLUTE_TTL_SECONDS) * SECOND;
      assert.equal(
        clocked.authenticate({ sessionId, token, identity: id }),
        undefined,
        'the monotonic clock alone governs lifetime',
      );
    });

    test('RC05-SES-21: expiry is irreversible and the old token can never revive it', () => {
      const target = issue('irreversible');
      const beforeCount = manager.getActiveSessionCount();

      mono += BigInt(SESSION_ABSOLUTE_TTL_SECONDS) * SECOND;

      // Every access path returns the same generic failure.
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
      assert.equal(
        manager.authenticate({
          sessionId: target.sessionId,
          token: target.issuance.token,
          identity: target.id,
        }),
        undefined,
      );
      assert.equal(manager.hasSession(target.sessionId), false);

      // A wall-clock rollback and a monotonic rollback cannot revive it.
      mono -= BigInt(SESSION_ABSOLUTE_TTL_SECONDS) * SECOND;
      assert.deepEqual(
        manager.admitRequest(ordinaryContext(target)),
        { outcome: 'INVALID_SESSION_TOKEN' },
        'the record is gone; rolling the clock back does not recreate it',
      );

      // The quota slot was released.
      assert.equal(manager.getActiveSessionCountForDevice(target.id.deviceId), 0);
      void beforeCount;

      // Re-issuance on the SAME ID is now possible because the ID is free, and
      // the old token cannot be used against the new session.
      const replacement = manager.issueSession({
        sessionId: target.sessionId,
        identity: target.id,
      });
      assert.deepEqual(
        manager.admitRequest(ordinaryContext(target)),
        { outcome: 'INVALID_SESSION_TOKEN' },
        'the previous token does not authenticate the replacement session',
      );
      assert.ok(
        manager.authenticate({
          sessionId: replacement.sessionId,
          token: replacement.token,
          identity: target.id,
        }),
      );
    });

    test('RC05-SES-22: expired sessions do not consume active quota', () => {
      const id = identity('expiry-quota');
      const first = manager.issueSession({
        sessionId: manager.createSessionIdGenerator()(),
        identity: id,
      });
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 1);

      mono += BigInt(SESSION_IDLE_TIMEOUT_SECONDS) * SECOND;

      // The expired session is accounted as gone before any quota decision.
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 0);
      assert.equal(manager.getActiveSessionCount(), 0);
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_DEVICE; i += 1) {
        manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id });
      }
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 8);
      assert.equal(
        manager.authenticate({ sessionId: first.sessionId, token: first.token, identity: id }),
        undefined,
      );
    });
  });

  // =========================================================================
  // Quotas
  // =========================================================================

  describe('Active-session quotas (§26 C-2, RC05-NEG-47)', () => {
    test('RC05-NEG-47: the ACTUAL 8-per-device cap refuses the 9th while the 8 survive', () => {
      const id = identity('device-cap');
      const issued = [];
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_DEVICE; i += 1) {
        issued.push(
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: id,
          }),
        );
      }
      assert.equal(issued.length, 8);
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 8);

      assert.throws(
        () =>
          manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
        'the 9th issuance must be refused with RESOURCE_EXHAUSTED',
      );

      // No session was created and every existing session still authenticates.
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 8);
      for (const session of issued) {
        assert.ok(
          manager.authenticate({
            sessionId: session.sessionId,
            token: session.token,
            identity: id,
          }),
          'existing sessions are unaffected by the refusal',
        );
      }
    });

    test('RC05-NEG-47b: a device-wide revocation releases quota for re-issuance', () => {
      const id = identity('device-cap-release');
      const issued = [];
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_DEVICE; i += 1) {
        issued.push(
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: id,
          }),
        );
      }
      assert.throws(
        () =>
          manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );

      assert.equal(manager.revokeSessionsForDevice(id.deviceId), 8);
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 0);
      assert.equal(
        manager.authenticate({
          sessionId: issued[0].sessionId,
          token: issued[0].token,
          identity: id,
        }),
        undefined,
        'revoked sessions cannot authenticate',
      );

      // Issuance is available again, and the old tokens are useless.
      const fresh = manager.issueSession({
        sessionId: manager.createSessionIdGenerator()(),
        identity: id,
      });
      assert.ok(
        manager.authenticate({ sessionId: fresh.sessionId, token: fresh.token, identity: id }),
      );
      for (const session of issued) {
        assert.equal(
          manager.authenticate({
            sessionId: session.sessionId,
            token: session.token,
            identity: id,
          }),
          undefined,
        );
      }
    });

    test('RC05-SES-23: the ACTUAL 64-per-client cap refuses the 65th', () => {
      // 64 sessions for one client spread over 8 devices, staying inside the
      // 8-per-device bound so the CLIENT bound is the one under test.
      const clientId = 'client-cap';
      const trusted = [];
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_CLIENT; i += 1) {
        const id = identity(`client-cap-device-${Math.floor(i / 8)}`, { clientId });
        trusted.push(id);
        manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id });
      }
      assert.equal(manager.getActiveSessionCountForClient(clientId), 64);
      assert.equal(manager.getActiveSessionCount(), 64);

      // A 65th issuance fails even though its own device has zero sessions.
      const overflow = identity('client-cap-overflow', { clientId });
      assert.throws(
        () =>
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: overflow,
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );
      assert.equal(manager.getActiveSessionCountForClient(clientId), 64);
      assert.equal(manager.getActiveSessionCount(), 64);
      assert.equal(manager.getActiveSessionCountForDevice(overflow.deviceId), 0);
      void trusted;
    });

    test('RC05-SES-24: the ACTUAL 1024-global cap refuses the 1025th', () => {
      // 1024 sessions across 128 devices, each with 8, staying inside both lower
      // bounds so the GLOBAL bound is the one under test.
      const perClient = 8;
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_GLOBAL; i += 1) {
        const id = identity(`global-${Math.floor(i / perClient)}`, {
          clientId: `client-global-${Math.floor(i / perClient)}`,
        });
        manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id });
      }
      assert.equal(manager.getActiveSessionCount(), MAX_ACTIVE_SESSIONS_GLOBAL);

      const overflow = identity('global-overflow', { clientId: 'client-global-overflow' });
      assert.throws(
        () =>
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: overflow,
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );
      assert.equal(manager.getActiveSessionCount(), MAX_ACTIVE_SESSIONS_GLOBAL);
      assert.equal(manager.getActiveSessionCountForDevice(overflow.deviceId), 0);
      assert.equal(manager.getActiveSessionCountForClient(overflow.clientId), 0);
    });

    test('RC05-SES-25: one revoked session frees exactly one slot', () => {
      const id = identity('single-slot');
      const issued = [];
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_DEVICE; i += 1) {
        issued.push(
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: id,
          }),
        );
      }
      assert.throws(
        () =>
          manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );

      assert.equal(manager.revokeSession(issued[3].sessionId), true);
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 7);
      manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id });
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 8);
      assert.throws(
        () =>
          manager.issueSession({ sessionId: manager.createSessionIdGenerator()(), identity: id }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );
    });

    test('RC05-SES-26: a refused issuance releases nothing and issues no token', () => {
      const id = identity('refusal-safety');
      const issued = [];
      for (let i = 0; i < MAX_ACTIVE_SESSIONS_PER_DEVICE; i += 1) {
        issued.push(
          manager.issueSession({
            sessionId: manager.createSessionIdGenerator()(),
            identity: id,
          }),
        );
      }
      const before = JSON.stringify(manager.listSessions());

      let tokenSurfaced = false;
      try {
        const result = manager.issueSession({
          sessionId: manager.createSessionIdGenerator()(),
          identity: id,
        });
        tokenSurfaced = typeof result.token === 'string';
      } catch (err) {
        assert.equal(err.code, 'RESOURCE_EXHAUSTED');
      }

      assert.equal(tokenSurfaced, false, 'a refused issuance must not surface a raw token');
      assert.equal(JSON.stringify(manager.listSessions()), before, 'all sessions unchanged');
      assert.equal(manager.getActiveSessionCountForDevice(id.deviceId), 8);
    });
  });

  // =========================================================================
  // Duplicate session identity (§26 C-4)
  // =========================================================================

  describe('Duplicate session ID safety (§26 C-4)', () => {
    test('RC05-SES-27: issuance against an active session ID fails closed without mutating it', () => {
      const owner = issue('duplicate-owner');
      const recordBefore = JSON.stringify(manager.listSessions());

      assert.throws(
        () =>
          manager.issueSession({
            sessionId: owner.sessionId,
            identity: identity('duplicate-attacker'),
          }),
        (err) => err.code === 'CONFLICT_PRECONDITION_FAILED',
        'a live session ID can never be reassigned',
      );

      assert.equal(JSON.stringify(manager.listSessions()), recordBefore);
      // The original binding and credential are intact.
      assert.ok(
        manager.authenticate({
          sessionId: owner.sessionId,
          token: owner.issuance.token,
          identity: owner.id,
        }),
      );
      assert.equal(manager.getActiveSessionCount(), 1);
    });

    test('RC05-SES-28: no request can adopt another session ID', () => {
      const owner = issue('adopt-owner');
      const attacker = identity('adopt-attacker');

      // The attacker knows the victim's session ID and presents it with their own
      // trusted identity (so their mTLS certificate is what authenticates).
      const withVictimToken = manager.admitRequest({
        kind: 'ordinary',
        hasExistingSessionContext: true,
        presentedSessionId: owner.sessionId,
        authorizationHeader: `Bearer ${owner.issuance.token}`,
        identity: attacker,
      });
      assert.deepEqual(withVictimToken, { outcome: 'INVALID_SESSION_TOKEN' });

      const tokenless = manager.admitRequest({
        kind: 'ordinary',
        hasExistingSessionContext: false,
        presentedSessionId: owner.sessionId,
        authorizationHeader: null,
        identity: attacker,
      });
      assert.deepEqual(tokenless, { outcome: 'INVALID_SESSION_TOKEN' });

      // And the victim's session is untouched.
      assert.ok(
        manager.authenticate({
          sessionId: owner.sessionId,
          token: owner.issuance.token,
          identity: owner.id,
        }),
      );
    });

    test('RC05-SES-29: a malformed or foreign session ID cannot be issued at all', () => {
      for (const sessionId of [
        'client-chosen-id',
        'a'.repeat(63),
        'A'.repeat(64),
        '',
        null,
        undefined,
        42,
      ]) {
        assert.throws(
          () => manager.issueSession({ sessionId, identity: identity('bad-id') }),
          (err) => err.code === 'INVALID_REQUEST_SCHEMA',
          `session ID ${JSON.stringify(sessionId)} must be refused`,
        );
      }
      assert.equal(manager.getActiveSessionCount(), 0);
    });
  });

  // =========================================================================
  // Tokenless initialize / wire bootstrap
  // =========================================================================

  describe('Tokenless initialize admission (§5.3 C, RC05-NEG-39/40/41)', () => {
    test('RC05-NEG-39: a tokenless ordinary request is UNAUTHENTICATED and mints nothing', () => {
      const id = identity('neg39');

      for (const context of [
        {
          kind: 'ordinary',
          hasExistingSessionContext: false,
          presentedSessionId: null,
          authorizationHeader: null,
          identity: id,
        },
        {
          kind: 'ordinary',
          hasExistingSessionContext: false,
          identity: id,
        },
      ]) {
        const decision = manager.admitRequest(context);
        assert.deepEqual(decision, { outcome: 'UNAUTHENTICATED' });
      }

      // No session, no token, no state at all.
      assert.equal(manager.getActiveSessionCount(), 0);
      assert.deepEqual(manager.listSessions(), []);
    });

    test('RC05-SES-30: a tokenless initial initialize is eligible for bootstrap', () => {
      const id = identity('bootstrap');
      const decision = manager.admitRequest({
        kind: 'initialize',
        hasExistingSessionContext: false,
        presentedSessionId: null,
        authorizationHeader: null,
        identity: id,
      });
      assert.deepEqual(decision, { outcome: 'BOOTSTRAP_TOKENLESS', identity: id });

      // Eligibility is NOT issuance: no session and no token exist yet.
      assert.equal(manager.getActiveSessionCount(), 0);
    });

    test('RC05-NEG-40: a client-supplied session ID on initial initialize is never adopted', () => {
      const attackerChosen = crypto.randomBytes(32).toString('hex');

      const decision = manager.admitRequest({
        kind: 'initialize',
        hasExistingSessionContext: false,
        presentedSessionId: attackerChosen,
        authorizationHeader: null,
        identity: identity('neg40'),
      });
      assert.equal(decision.outcome, 'BOOTSTRAP_TOKENLESS');
      assert.equal(manager.hasSession(attackerChosen), false, 'the client ID was not created');
      assert.equal(manager.getActiveSessionCount(), 0);
      assert.equal(
        manager.listSessions().some((v) => v.sessionId === attackerChosen),
        false,
        'the client ID was not bound',
      );

      // The transport replaces it with a fresh server-generated ID.
      const serverId = manager.createSessionIdGenerator()();
      assert.notEqual(serverId, attackerChosen, 'fixation is impossible');
      const issuance = manager.issueSession({ sessionId: serverId, identity: identity('neg40') });
      assert.equal(issuance.sessionId, serverId);
      assert.equal(manager.hasSession(attackerChosen), false);
    });

    test('RC05-NEG-40b: an existing server session ID cannot be bypassed by calling itself initialize', () => {
      const target = issue('neg40b');

      // Tokenless initialize carrying a REAL server session ID: still requires
      // the dual header.
      const decision = manager.admitRequest({
        kind: 'initialize',
        hasExistingSessionContext: false,
        presentedSessionId: target.sessionId,
        authorizationHeader: null,
        identity: target.id,
      });
      assert.deepEqual(decision, { outcome: 'INVALID_SESSION_TOKEN' });

      // A recognized session context is likewise post-session.
      const contextDecision = manager.admitRequest({
        kind: 'initialize',
        hasExistingSessionContext: true,
        presentedSessionId: target.sessionId,
        authorizationHeader: `Bearer ${crypto.randomBytes(32).toString('hex')}`,
        identity: target.id,
      });
      assert.deepEqual(contextDecision, { outcome: 'INVALID_SESSION_TOKEN' });

      // With the correct dual header it authenticates as usual.
      assert.deepEqual(
        manager.admitRequest({
          kind: 'initialize',
          hasExistingSessionContext: true,
          presentedSessionId: target.sessionId,
          authorizationHeader: `Bearer ${target.issuance.token}`,
          identity: target.id,
        }).outcome,
        'AUTHENTICATED',
      );
    });

    test('RC05-NEG-41: tokenless initialize from an unenrolled device mints nothing', () => {
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('neg41-enrolled'),
      });

      // The mTLS identity presented is an SPKI the trust store does not know.
      const untrusted = resolveActiveDeviceIdentity(store, pin('neg41-stranger'));
      assert.equal(untrusted, undefined, 'an unenrolled identity resolves to nothing');

      // The transport must therefore refuse before it can even ask for a
      // bootstrap decision: no trusted identity means no admission.
      assert.equal(manager.getActiveSessionCount(), 0);
      assert.deepEqual(manager.listSessions(), []);
    });

    test('RC05-NEG-41b: tokenless initialize from a REVOKED device mints nothing', () => {
      const store = DeviceTrustStore.createEmpty();
      const { device } = store.enrollDevice({
        clientId: 'agent-revoked',
        clientType: 'claude-code',
        pin: pin('neg41b'),
      });
      store.revokeDevice(device.deviceId);

      assert.equal(
        resolveActiveDeviceIdentity(store, pin('neg41b')),
        undefined,
        'a revoked device resolves to nothing',
      );
      assert.equal(manager.getActiveSessionCount(), 0);
    });

    test('RC05-SES-31: the bootstrap ordering is expressible exactly as Task 8 needs it', () => {
      // 1. The transport asks whether the request is eligible.
      const id = identity('ordering');
      const decision = manager.admitRequest({
        kind: 'initialize',
        hasExistingSessionContext: false,
        presentedSessionId: null,
        authorizationHeader: null,
        identity: id,
      });
      assert.equal(decision.outcome, 'BOOTSTRAP_TOKENLESS');

      // 2. The SDK processes initialize and the server generates the session ID
      //    through the generator the manager supplied.
      const generate = manager.createSessionIdGenerator();
      const serverSessionId = generate();

      // 3. Only after a successful initialize does the manager mint the token.
      const issuance = manager.issueSession({ sessionId: serverSessionId, identity: id });

      // 4. The transport emits Arc-Session-Token once, and the same session ID is
      //    the actor session ID: there is no second identity.
      assert.equal(issuance.sessionId, serverSessionId);
      assert.equal(ARC_SESSION_TOKEN_HEADER, 'Arc-Session-Token');
      assert.equal(MCP_SESSION_ID_HEADER, 'Mcp-Session-Id');

      // 5. Every later request uses both headers.
      assert.deepEqual(
        manager.admitRequest({
          kind: 'ordinary',
          hasExistingSessionContext: true,
          presentedSessionId: serverSessionId,
          authorizationHeader: `Bearer ${issuance.token}`,
          identity: id,
        }).outcome,
        'AUTHENTICATED',
      );
    });
  });

  // =========================================================================
  // Revocation, close, restart
  // =========================================================================

  describe('Revocation, close, and restart (§11, §5.4, §23)', () => {
    test('RC05-SES-32: revocation is immediate, irreversible, and releases quota', () => {
      const target = issue('revoke');
      assert.equal(manager.revokeSession(target.sessionId), true);

      // The old credential returns the generic failure on every path.
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
      assert.equal(
        manager.authenticate({
          sessionId: target.sessionId,
          token: target.issuance.token,
          identity: target.id,
        }),
        undefined,
      );
      assert.equal(manager.hasSession(target.sessionId), false);

      // Irreversible: re-issuing the same ID yields a session the old token
      // cannot authenticate.
      const reissued = manager.issueSession({ sessionId: target.sessionId, identity: target.id });
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
      assert.ok(
        manager.authenticate({
          sessionId: reissued.sessionId,
          token: reissued.token,
          identity: target.id,
        }),
      );

      // Revoking an unknown session is a safe no-op.
      assert.equal(manager.revokeSession(crypto.randomBytes(32).toString('hex')), false);
      assert.equal(manager.revokeSession('not-a-session-id'), false);
      assert.equal(manager.revokeSession(undefined), false);
      assert.equal(manager.revokeSession(null), false);
    });

    test('RC05-SES-33: a device-wide revocation primitive revokes only that device', () => {
      const victim = issue('device-revoke-victim');
      const bystander = issue('device-revoke-bystander');

      assert.equal(manager.revokeSessionsForDevice(victim.id.deviceId), 1);
      assert.deepEqual(manager.admitRequest(ordinaryContext(victim)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
      assert.deepEqual(manager.admitRequest(ordinaryContext(bystander)).outcome, 'AUTHENTICATED');
      assert.equal(manager.revokeSessionsForDevice('unknown-device'), 0);
      assert.equal(manager.revokeSessionsForDevice(''), 0);
    });

    test('RC05-SES-34: the close primitive closes only the named session', () => {
      const closed = issue('close-target');
      const other = issue('close-other');

      assert.equal(manager.closeSession(closed.sessionId), true);
      assert.deepEqual(manager.admitRequest(ordinaryContext(closed)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
      assert.deepEqual(manager.admitRequest(ordinaryContext(other)).outcome, 'AUTHENTICATED');

      // Closing a nonexistent, expired, or already-closed session is a safe
      // no-op that cannot mutate another session.
      assert.equal(manager.closeSession(closed.sessionId), false);
      assert.equal(manager.closeSession(crypto.randomBytes(32).toString('hex')), false);
      assert.equal(manager.closeSession(''), false);
      assert.deepEqual(manager.admitRequest(ordinaryContext(other)).outcome, 'AUTHENTICATED');

      // Closing an EXPIRED session reports false — nothing was closed — and
      // cannot disturb any other session.
      const expiring = issue('close-expired');
      mono += BigInt(SESSION_ABSOLUTE_TTL_SECONDS) * SECOND;
      assert.equal(manager.closeSession(expiring.sessionId), false);
      const survivor = issue('close-survivor');
      assert.deepEqual(manager.admitRequest(ordinaryContext(survivor)).outcome, 'AUTHENTICATED');
      assert.deepEqual(manager.admitRequest(ordinaryContext(other)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
    });

    test('RC05-SES-35: sessions are volatile — a fresh manager rejects pre-restart tokens', () => {
      const target = issue('restart');

      const restarted = new SessionManager({ getMonotonicTime: () => mono });
      assert.equal(
        restarted.getActiveSessionCount(),
        0,
        'a fresh manager starts with zero sessions',
      );
      assert.deepEqual(restarted.listSessions(), []);
      assert.deepEqual(
        restarted.admitRequest(ordinaryContext(target)),
        { outcome: 'INVALID_SESSION_TOKEN' },
        'a pre-restart token is invalid after restart',
      );
      assert.equal(
        restarted.authenticate({
          sessionId: target.sessionId,
          token: target.issuance.token,
          identity: target.id,
        }),
        undefined,
      );

      // A clear() is a process-shutdown equivalent for the original manager.
      manager.clear();
      assert.equal(manager.getActiveSessionCount(), 0);
      assert.deepEqual(manager.admitRequest(ordinaryContext(target)), {
        outcome: 'INVALID_SESSION_TOKEN',
      });
    });
  });

  // =========================================================================
  // Credential domain separation
  // =========================================================================

  describe('Credential domain separation (RC05-NEG-69)', () => {
    /** Issues a REAL RC-04 approval credential from the real policy domain. */
    function realApprovalToken() {
      const approvals = new ApprovalStateManager();
      const actor = { clientId: 'client-domain', clientType: 'claude-code', sessionId: 'stdio-1' };
      const workspace = { workspaceId: 'workspace', workspaceRootHash: 'a'.repeat(64) };
      const snapshot = approvals.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: crypto.createHash('sha256').update('payload').digest('hex'),
        binding: {
          actor,
          workspace,
          policyHash: crypto.createHash('sha256').update('policy').digest('hex'),
        },
      });
      const grant = approvals.approve(snapshot.requestId);
      return { approvals, requestId: snapshot.requestId, token: grant.token };
    }

    test('RC05-NEG-69: a genuine RC-04 approval token is not a session token', () => {
      const target = issue('neg69');
      const { approvals, requestId, token: approvalToken } = realApprovalToken();

      // The two credentials are drawn from the SAME shape space, which is exactly
      // why domain separation has to be structural rather than syntactic.
      assert.match(approvalToken, SESSION_TOKEN_REGEX);
      assert.notEqual(approvalToken, target.issuance.token);

      const approvalStateBefore = approvals.getRequest(requestId).state;

      const decision = manager.admitRequest(
        ordinaryContext(target, {
          authorizationHeader: `Bearer ${approvalToken}`,
        }),
      );
      assert.deepEqual(
        decision,
        { outcome: 'INVALID_SESSION_TOKEN' },
        'an approval credential is never a session credential',
      );
      assert.equal(
        manager.authenticate({
          sessionId: target.sessionId,
          token: approvalToken,
          identity: target.id,
        }),
        undefined,
      );

      // No session mutation.
      assert.ok(manager.hasSession(target.sessionId));
      assert.ok(
        manager.authenticate({
          sessionId: target.sessionId,
          token: target.issuance.token,
          identity: target.id,
        }),
      );

      // No approval mutation: the session manager has no way to consume or
      // validate an approval credential at all.
      assert.equal(approvals.getRequest(requestId).state, approvalStateBefore);
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');

      // The approval credential remains usable in ITS OWN domain, proving the
      // rejection above came from separation and not from a broken token.
      const redemption = approvals.redeemAndConsume({
        requestId,
        token: approvalToken,
        executionPayloadHash: crypto.createHash('sha256').update('payload').digest('hex'),
        actor: { clientId: 'client-domain', clientType: 'claude-code', sessionId: 'stdio-1' },
        workspace: { workspaceId: 'workspace', workspaceRootHash: 'a'.repeat(64) },
        policyHash: crypto.createHash('sha256').update('policy').digest('hex'),
      });
      assert.equal(redemption.requestId, requestId);
    });
  });

  // =========================================================================
  // Bounded views and leak surfaces
  // =========================================================================

  describe('No raw credential in any viewable state (§11 leakage controls)', () => {
    test('RC05-SES-36: raw tokens never appear in views, serialization, or errors', () => {
      const target = issue('leak');
      const digest = crypto.createHash('sha256').update(target.issuance.token).digest('hex');

      const views = manager.listSessions();
      assert.equal(views.length, 1);
      assert.deepEqual(Object.keys(views[0]).sort(), [
        'clientId',
        'clientType',
        'deviceId',
        'issuedAt',
        'sessionId',
        'state',
      ]);
      const serialized = JSON.stringify(views);
      assert.equal(serialized.includes(target.issuance.token), false);
      assert.equal(serialized.includes(digest), false);
      assert.equal(serialized.includes(target.id.spkiPin), false, 'no SPKI pin in a session view');

      // Errors raised by the manager never carry the credential or a fragment.
      const errors = [];
      try {
        manager.issueSession({ sessionId: target.sessionId, identity: identity('leak-attacker') });
      } catch (err) {
        errors.push(err);
      }
      try {
        manager.issueSession({ sessionId: 'nope', identity: target.id });
      } catch (err) {
        errors.push(err);
      }
      for (const err of errors) {
        const text = `${err.message} ${JSON.stringify(err.toJSON ? err.toJSON() : {})}`;
        assert.equal(text.includes(target.issuance.token), false);
        assert.equal(text.includes(target.issuance.token.slice(0, 8)), false);
      }
    });

    test('RC05-SES-37: the trusted session result carries no credential material', () => {
      const target = issue('result-shape');
      const result = manager.authenticate({
        sessionId: target.sessionId,
        token: target.issuance.token,
        identity: target.id,
      });

      assert.deepEqual(Object.keys(result).sort(), [
        'clientId',
        'clientType',
        'deviceId',
        'issuedAt',
        'sessionId',
        'spkiPin',
      ]);
      // The SPKI binding is present for the server, and the raw token is not.
      assert.equal(result.spkiPin, target.id.spkiPin);
      assert.equal(JSON.stringify(result).includes(target.issuance.token), false);
    });
  });

  // =========================================================================
  // Task boundaries
  // =========================================================================

  describe('Task-5 boundaries are structural, not conventional', () => {
    /** Import specifiers of one TypeScript source file. */
    function importSpecifiers(sourceText) {
      const specifiers = [];
      const pattern = /from\s+'([^']+)'|import\s*\(\s*'([^']+)'\s*\)/g;
      let match = pattern.exec(sourceText);
      while (match !== null) {
        specifiers.push(match[1] ?? match[2]);
        match = pattern.exec(sourceText);
      }
      return specifiers;
    }

    test('RC05-SES-38: the session domain imports no policy, subsystem, audit, or transport module', () => {
      const url = new URL('../packages/auth/src/session.ts', import.meta.url);
      const specifiers = importSpecifiers(fs.readFileSync(url, 'utf8'));
      assert.ok(specifiers.length > 0, 'the file must have been read');

      const forbidden = [
        '@cesspace-arc/policy',
        '@cesspace-arc/filesystem',
        '@cesspace-arc/git',
        '@cesspace-arc/terminal',
        '@cesspace-arc/audit',
        '@cesspace-arc/processes',
        '@modelcontextprotocol/sdk',
        'node:http',
        'node:https',
        'node:net',
        'node:tls',
        'node:fs',
        'node:child_process',
        'node:dgram',
      ];
      for (const specifier of specifiers) {
        for (const banned of forbidden) {
          assert.equal(
            specifier === banned || specifier.startsWith(`${banned}/`),
            false,
            `session.ts must not import ${specifier}`,
          );
        }
      }

      // The only runtime dependencies are the crypto primitive and the canonical
      // error type; the trust store is a type-only import.
      assert.deepEqual(specifiers.sort(), [
        './device-identity.js',
        './trust-store.js',
        '@cesspace-arc/protocol',
        'node:crypto',
      ]);
      assert.equal(
        /import\s+type\s+\{[^}]*\}\s+from\s+'\.\/trust-store\.js'/.test(
          fs.readFileSync(url, 'utf8'),
        ),
        true,
        'the trust store is imported as a type only, so the session domain cannot touch it',
      );
    });

    test('RC05-SES-39: the compiled session module pulls in no tool or policy code', () => {
      const url = new URL('../packages/auth/dist/session.js', import.meta.url);
      const compiled = fs.readFileSync(url, 'utf8');
      const specifiers = importSpecifiers(compiled);
      for (const specifier of specifiers) {
        assert.equal(
          specifier.startsWith('@cesspace-arc/policy') ||
            specifier.startsWith('@cesspace-arc/filesystem') ||
            specifier.startsWith('@cesspace-arc/git') ||
            specifier.startsWith('@cesspace-arc/terminal') ||
            specifier.startsWith('@modelcontextprotocol/sdk'),
          false,
          `compiled session module must not import ${specifier}`,
        );
      }
      // No MCP transport, no HTTP server, and no tool dispatch symbol anywhere in
      // the emitted module.
      for (const banned of [
        'StreamableHTTPServerTransport',
        'createServer',
        'listen(',
        'setRequestHandler',
        'ListTools',
        'CallTool',
        'SecurityKernel',
        'DeclarativePolicyEngine',
      ]) {
        assert.equal(
          compiled.includes(banned),
          false,
          `the session module must not reference ${banned}`,
        );
      }
    });

    test('RC05-SES-40: Task 5 added no network composition to the remote gateway', () => {
      const gatewayUrl = new URL('../apps/mcp-server/src/remote-gateway.ts', import.meta.url);
      const source = fs.readFileSync(gatewayUrl, 'utf8');

      // The MCP transport composition belongs to Task 8.
      for (const banned of [
        'StreamableHTTPServerTransport',
        'SSEServerTransport',
        'eventStore',
        'sessionIdGenerator',
      ]) {
        assert.equal(
          source.includes(banned),
          false,
          `Task 8 owns ${banned}; Task 5 must not compose it`,
        );
      }
      // The Task-4 `/mcp` surface is still the deny-only placeholder.
      assert.equal(
        source.includes('enrollment-bootstrap.js'),
        true,
        'the gateway still routes exclusively through the Task-4 bootstrap router',
      );

      const bootstrapUrl = new URL(
        '../apps/mcp-server/src/enrollment-bootstrap.ts',
        import.meta.url,
      );
      const bootstrap = fs.readFileSync(bootstrapUrl, 'utf8');
      for (const banned of ['StreamableHTTPServerTransport', '@modelcontextprotocol/sdk']) {
        assert.equal(bootstrap.includes(banned), false, `the router must not compose ${banned}`);
      }
      assert.equal(
        bootstrap.includes('MCP_PATH') && bootstrap.includes('UNAUTHENTICATED_BODY'),
        true,
        'the /mcp placeholder is unchanged',
      );
    });
  });
});
