/**
 * CesSpace ARC — RC-05 Task 2: Pending Enrollment Lifecycle
 *
 * Covers the pure enrollment-domain contract (rc05-scope-acceptance.md §9,
 * E-1..E-12, §9.2) and the RC05-NEG-33..37 controls at their domain level.
 *
 * Task 4 will additionally verify the remote `POST /enroll/complete` HTTP 400
 * manifestations of these same invariants. Nothing here performs network I/O,
 * and nothing here activates a device into the persistent trust store.
 *
 * All clocks are injected; no test sleeps and none depends on wall time.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  DeviceTrustStore,
  EnrollmentManager,
  deriveOperatorId,
  ENROLLMENT_TTL_SECONDS,
  ENROLLMENT_SECRET_REGEX,
  ENROLLMENT_ID_REGEX,
  MAX_PENDING_ENROLLMENTS_GLOBAL,
  MAX_PENDING_ENROLLMENTS_PER_OPERATOR,
} from '../packages/auth/dist/index.js';

/** Canonical pin shape: SHA-256 of DER SPKI, 64 lowercase hex. */
function pin(seed) {
  return crypto.createHash('sha256').update(`pin-${seed}`, 'utf8').digest('hex');
}

const CLIENT = { clientId: 'agent-alpha', clientType: 'claude-code' };

describe('CesSpace ARC — RC-05 Task 2: Pending Enrollment Lifecycle', () => {
  let mono;
  let manager;
  let operatorId;

  beforeEach(() => {
    mono = 1_000_000_000_000n;
    manager = new EnrollmentManager({ getMonotonicTime: () => mono });
    operatorId = crypto.createHash('sha256').update('operator-key', 'utf8').digest('hex');
  });

  /** Creates a challenge with sane defaults. */
  function create(overrides = {}) {
    return manager.create({
      clientId: CLIENT.clientId,
      clientType: CLIENT.clientType,
      spkiPin: pin('a'),
      operatorId,
      ...overrides,
    });
  }

  // =========================================================================
  // Creation and bounded view
  // =========================================================================

  describe('Challenge creation', () => {
    test('RC05-ENR-01: creation returns a bounded view plus a one-time secret', () => {
      const created = create({ displayLabel: 'laptop' });

      assert.match(created.enrollment.enrollmentId, ENROLLMENT_ID_REGEX);
      assert.match(created.secret, ENROLLMENT_SECRET_REGEX);
      assert.equal(created.enrollment.clientId, CLIENT.clientId);
      assert.equal(created.enrollment.clientType, CLIENT.clientType);
      assert.equal(created.enrollment.spkiPin, pin('a'));
      assert.equal(created.enrollment.displayLabel, 'laptop');
      assert.equal(created.enrollment.failedAttempts, 0);
      assert.equal(created.enrollment.remainingSeconds, ENROLLMENT_TTL_SECONDS);
      assert.equal(manager.getPendingCount(), 1);
    });

    test('RC05-ENR-02: the secret is never retained in the pending record', () => {
      const created = create();
      const view = manager.get(created.enrollment.enrollmentId);

      const serialized = JSON.stringify(view);
      assert.ok(!serialized.includes(created.secret), 'raw secret must never be readable');
      // Only the digest is held, so the record exposes no reusable material.
      assert.equal(Object.prototype.hasOwnProperty.call(view, 'secret'), false);
      assert.equal(Object.prototype.hasOwnProperty.call(view, 'secretDigest'), false);
    });

    test('RC05-ENR-03: two creations produce distinct identifiers and secrets', () => {
      const a = create();
      const b = create({ spkiPin: pin('b') });
      assert.notEqual(a.enrollment.enrollmentId, b.enrollment.enrollmentId);
      assert.notEqual(a.secret, b.secret);
    });

    test('RC05-ENR-04: identifiers are server-generated and never caller-supplied', () => {
      // A caller cannot pass an identifier, deviceId, timestamp, counter, or
      // deadline: the input type has no such field, and supplying one has no
      // effect on the generated value.
      const injected = create({
        enrollmentId: 'f'.repeat(32),
        deviceId: 'e'.repeat(32),
        failedAttempts: 99,
        monotonicDeadline: 0n,
      });
      assert.notEqual(injected.enrollment.enrollmentId, 'f'.repeat(32));
      assert.match(injected.enrollment.enrollmentId, ENROLLMENT_ID_REGEX);
      assert.equal(injected.enrollment.failedAttempts, 0);
    });

    test('RC05-ENR-05: malformed operator identity is refused', () => {
      for (const bad of [undefined, '', 'not-hex', 'A'.repeat(64), 'a'.repeat(63)]) {
        assert.throws(
          () => create({ operatorId: bad }),
          (err) => err.code === 'INVALID_REQUEST_SCHEMA',
        );
      }
      assert.equal(manager.getPendingCount(), 0);
    });

    test('RC05-ENR-06: invalid client identifiers and pins are refused', () => {
      const cases = [
        { clientId: '' },
        { clientId: '   ' },
        { clientType: '' },
        { spkiPin: 'a'.repeat(63) },
        { spkiPin: 'A'.repeat(64) },
        { spkiPin: 'z'.repeat(64) },
        { clientId: 'x'.repeat(129) },
        { displayLabel: 'y'.repeat(65) },
      ];
      for (const override of cases) {
        assert.throws(
          () => create(override),
          (err) => err.code === 'INVALID_REQUEST_SCHEMA',
          `${JSON.stringify(Object.keys(override))} must be rejected`,
        );
      }
      assert.equal(manager.getPendingCount(), 0);
    });

    test('RC05-ENR-07: a derived operator id is stable and reveals no key material', () => {
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      const first = deriveOperatorId(publicKey);
      const second = deriveOperatorId(publicKey);
      assert.equal(first, second);
      assert.match(first, /^[0-9a-f]{64}$/);
      const publicDer = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
      assert.ok(!first.includes(publicDer), 'the raw operator key must not be recoverable');
    });
  });

  // =========================================================================
  // RC05-NEG-33 .. RC05-NEG-37
  // =========================================================================

  describe('RC05-NEG-33..37 (Task-2 domain coverage)', () => {
    test('RC05-NEG-33: a wrong one-time secret is counted and leaves state otherwise unchanged', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;
      const before = manager.get(id);

      const outcome = manager.verifyAndConsume(id, 'f'.repeat(64));
      assert.equal(outcome.ok, false);
      assert.equal(outcome.reason, 'SECRET_MISMATCH');
      assert.equal(outcome.counted, true);

      const after = manager.get(id);
      assert.ok(after, 'the challenge must remain pending after the first failure');
      assert.equal(after.failedAttempts, 1);
      assert.equal(after.clientId, before.clientId);
      assert.equal(after.spkiPin, before.spkiPin);
      assert.equal(after.expiresAt, before.expiresAt, 'a failure must not move the deadline');
      assert.equal(after.remainingSeconds, before.remainingSeconds);
      assert.equal(manager.getPendingCount(), 1);
    });

    test('RC05-NEG-33b: a malformed secret submission is counted, not free', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;
      const outcomes = ['', 'not-hex', 'a'.repeat(63), 'A'.repeat(64), 42, null, undefined].map(
        (malformed) => manager.verifyAndConsume(id, malformed),
      );
      for (const outcome of outcomes) {
        assert.equal(outcome.ok, false);
      }
      // The first three malformed probes are counted against the live challenge;
      // they are not a free oracle. The third purges it.
      assert.deepEqual(
        outcomes.slice(0, 3).map((o) => o.reason),
        ['SECRET_MISMATCH', 'SECRET_MISMATCH', 'LOCKED_OUT'],
      );
      assert.deepEqual(
        outcomes.slice(0, 3).map((o) => o.counted),
        [true, true, true],
        'malformed input must not be a free probe while the challenge is live',
      );
      // Everything after the purge is simply an unknown challenge.
      assert.deepEqual(
        outcomes.slice(3).map((o) => o.reason),
        Array(outcomes.length - 3).fill('UNKNOWN_ENROLLMENT'),
      );
      assert.equal(manager.get(id), undefined, 'three attempts purge the challenge');
    });

    test('RC05-NEG-34: the third failed attempt purges the challenge immediately', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;
      const wrong = 'f'.repeat(64);

      const first = manager.verifyAndConsume(id, wrong);
      assert.equal(first.reason, 'SECRET_MISMATCH');
      assert.ok(manager.get(id), 'still pending after failure 1');

      const second = manager.verifyAndConsume(id, wrong);
      assert.equal(second.reason, 'SECRET_MISMATCH');
      assert.ok(manager.get(id), 'still pending after failure 2');

      const third = manager.verifyAndConsume(id, wrong);
      assert.equal(third.reason, 'LOCKED_OUT');
      assert.equal(manager.get(id), undefined, 'purged on failure 3');
      assert.equal(manager.getPendingCount(), 0);

      // A subsequent attempt cannot revive it, and the correct secret is now
      // useless too — the challenge is gone, not merely marked.
      const afterPurge = manager.verifyAndConsume(id, created.secret);
      assert.equal(afterPurge.ok, false);
      assert.equal(afterPurge.reason, 'UNKNOWN_ENROLLMENT');
    });

    test('RC05-NEG-35: an attempt after the 300-second deadline is rejected and purged', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;

      // Exactly at the deadline the challenge is already expired.
      mono += BigInt(ENROLLMENT_TTL_SECONDS) * 1_000_000_000n;

      const outcome = manager.verifyAndConsume(id, created.secret);
      assert.equal(outcome.ok, false);
      assert.equal(outcome.reason, 'EXPIRED', 'expiry wins over a correct secret');
      assert.equal(manager.get(id), undefined);
      assert.equal(manager.getPendingCount(), 0);
    });

    test('RC05-NEG-35b: inspection and retry never extend the lifetime', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;
      const deadline = manager.get(id).expiresAt;

      // Repeated inspection and a failed attempt, with time advancing.
      mono += 100_000_000_000n; // 100 s
      manager.get(id);
      manager.list();
      manager.verifyAndConsume(id, 'f'.repeat(64));
      mono += 100_000_000_000n; // 200 s
      manager.get(id);
      manager.purgeExpired();
      assert.ok(manager.get(id), 'still pending before the deadline');
      assert.equal(manager.get(id).expiresAt, deadline, 'the deadline never moves');

      mono += 100_000_000_001n; // past 300 s
      manager.purgeExpired();
      assert.equal(manager.get(id), undefined, 'expired despite repeated inspection');
    });

    test('RC05-NEG-35c: wall-clock movement has no effect on expiry', () => {
      let wall = 1_800_000_000_000;
      const clocked = new EnrollmentManager({
        getMonotonicTime: () => mono,
        getWallTime: () => wall,
      });
      const created = clocked.create({
        clientId: CLIENT.clientId,
        clientType: CLIENT.clientType,
        spkiPin: pin('c'),
        operatorId,
      });

      // The wall clock jumps far forward and backward; monotonic time has not moved.
      wall += 86_400_000;
      assert.ok(clocked.get(created.enrollment.enrollmentId), 'wall forward must not expire it');
      wall -= 172_800_000;
      assert.ok(clocked.get(created.enrollment.enrollmentId), 'wall rollback must not revive it');

      const outcome = clocked.verifyAndConsume(created.enrollment.enrollmentId, created.secret);
      assert.equal(outcome.ok, true, 'consumption is governed by the monotonic clock alone');
    });

    test('RC05-NEG-36: a consumed secret cannot be replayed and the trust store is untouched', () => {
      // A real trust store stands in for the persistent state Task 4 owns.
      const trustStore = DeviceTrustStore.createEmpty();
      assert.equal(trustStore.getDeviceCount(), 0);

      const created = create();
      const id = created.enrollment.enrollmentId;

      const consumed = manager.verifyAndConsume(id, created.secret);
      assert.equal(consumed.ok, true);
      assert.equal(consumed.enrollment.enrollmentId, id);

      const replay = manager.verifyAndConsume(id, created.secret);
      assert.equal(replay.ok, false);
      assert.equal(replay.reason, 'UNKNOWN_ENROLLMENT', 'the record is gone, not merely marked');
      assert.equal(manager.getPendingCount(), 0);

      // Task 2 never activates a device: the trust store is still empty.
      assert.equal(trustStore.getDeviceCount(), 0);
      assert.equal(trustStore.getDevices().length, 0);
    });

    test('RC05-NEG-37: the 17th global challenge is refused without mutating state', () => {
      const created = [];
      for (let i = 0; i < MAX_PENDING_ENROLLMENTS_GLOBAL; i++) {
        // Distinct operators so the per-operator quota is not the binding limit.
        created.push(
          create({
            spkiPin: pin(`global-${i}`),
            operatorId: crypto.createHash('sha256').update(`op-${i}`).digest('hex'),
          }),
        );
      }
      assert.equal(manager.getPendingCount(), MAX_PENDING_ENROLLMENTS_GLOBAL);

      const snapshot = JSON.stringify(manager.list());

      assert.throws(
        () =>
          create({
            spkiPin: pin('global-overflow'),
            operatorId: crypto.createHash('sha256').update('op-overflow').digest('hex'),
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );

      assert.equal(manager.getPendingCount(), MAX_PENDING_ENROLLMENTS_GLOBAL);
      assert.equal(JSON.stringify(manager.list()), snapshot, 'existing state must be unchanged');
      // Every pre-existing challenge remains consumable.
      for (const entry of created) {
        assert.ok(manager.get(entry.enrollment.enrollmentId));
      }
    });

    test('RC05-NEG-37b: the 5th challenge for one operator is refused without mutating state', () => {
      for (let i = 0; i < MAX_PENDING_ENROLLMENTS_PER_OPERATOR; i++) {
        create({ spkiPin: pin(`perop-${i}`) });
      }
      assert.equal(
        manager.getPendingCountForOperator(operatorId),
        MAX_PENDING_ENROLLMENTS_PER_OPERATOR,
      );

      const snapshot = JSON.stringify(manager.list());

      assert.throws(
        () => create({ spkiPin: pin('perop-overflow') }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );

      assert.equal(JSON.stringify(manager.list()), snapshot, 'existing state must be unchanged');
      assert.equal(
        manager.getPendingCountForOperator(operatorId),
        MAX_PENDING_ENROLLMENTS_PER_OPERATOR,
      );
    });

    test('RC05-NEG-37c: released quota becomes reusable and per-operator quota is isolated', () => {
      // Fill the operator quota.
      const filled = [];
      for (let i = 0; i < MAX_PENDING_ENROLLMENTS_PER_OPERATOR; i++) {
        filled.push(create({ spkiPin: pin(`release-${i}`) }));
      }
      assert.throws(() => create({ spkiPin: pin('release-blocked') }));

      // Cancellation releases quota.
      assert.equal(manager.cancel(filled[0].enrollment.enrollmentId), true);
      const replacement = create({ spkiPin: pin('release-ok') });
      assert.ok(replacement.enrollment.enrollmentId);

      // Expiry releases quota.
      mono += BigInt(ENROLLMENT_TTL_SECONDS) * 1_000_000_000n;
      manager.purgeExpired();
      assert.equal(manager.getPendingCountForOperator(operatorId), 0);
      create({ spkiPin: pin('after-expiry') });

      // A different operator has its own independent budget.
      const otherOperator = crypto.createHash('sha256').update('other-op').digest('hex');
      create({ spkiPin: pin('other-op-pin'), operatorId: otherOperator });
      assert.equal(manager.getPendingCountForOperator(otherOperator), 1);
    });
  });

  // =========================================================================
  // Cancellation
  // =========================================================================

  describe('Cancellation', () => {
    test('RC05-ENR-20: cancellation removes the challenge and permanently disables its secret', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;

      assert.equal(manager.cancel(id), true);
      assert.equal(manager.get(id), undefined);
      assert.equal(manager.getPendingCount(), 0);

      const outcome = manager.verifyAndConsume(id, created.secret);
      assert.equal(outcome.ok, false);
      assert.equal(outcome.reason, 'UNKNOWN_ENROLLMENT');
    });

    test('RC05-ENR-21: cancelling an unknown, expired, or consumed id is uniformly false', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;

      // Unknown and malformed identifiers.
      assert.equal(manager.cancel('0'.repeat(32)), false);
      assert.equal(manager.cancel('not-an-id'), false);
      assert.equal(manager.cancel('A'.repeat(32)), false);

      // Consumed.
      assert.equal(manager.verifyAndConsume(id, created.secret).ok, true);
      assert.equal(manager.cancel(id), false, 'no existence oracle for a consumed challenge');

      // Expired.
      const second = create({ spkiPin: pin('expire-cancel') });
      mono += BigInt(ENROLLMENT_TTL_SECONDS) * 1_000_000_000n;
      assert.equal(manager.cancel(second.enrollment.enrollmentId), false);
      assert.equal(
        manager.cancel(second.enrollment.enrollmentId),
        false,
        'repeat cancellation is not a different answer',
      );
    });

    test('RC05-ENR-22: Task 2 never mutates the persistent trust store', () => {
      const trustStore = DeviceTrustStore.createEmpty();
      const created = create();
      assert.equal(trustStore.getDeviceCount(), 0, 'creation must not enroll');
      manager.cancel(created.enrollment.enrollmentId);
      assert.equal(trustStore.getDeviceCount(), 0, 'cancellation must not mutate the store');
      assert.equal(trustStore.getDevices().length, 0);
    });
  });

  // =========================================================================
  // Concurrency / race semantics
  // =========================================================================

  describe('Race and atomicity semantics', () => {
    test('RC05-ENR-30: two simultaneous valid consumptions — exactly one succeeds', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;

      // Every EnrollmentManager transition is synchronous and contains no await,
      // so no other task in the single-threaded event loop can interleave inside
      // it. Two "simultaneous" callers are therefore observed as an ordered
      // sequence, and the guarantee holds regardless of which runs first.
      const first = manager.verifyAndConsume(id, created.secret);
      const second = manager.verifyAndConsume(id, created.secret);

      assert.equal(first.ok, true);
      assert.equal(second.ok, false);
      assert.equal(second.reason, 'UNKNOWN_ENROLLMENT');
      assert.equal([first, second].filter((r) => r.ok).length, 1);
    });

    test('RC05-ENR-31: interleaved failures can never exceed three usable attempts', () => {
      const created = create();
      const id = created.enrollment.enrollmentId;

      // Attempts interleave with inspections and cancellations, which must not
      // reset or advance the counter.
      const outcomes = [];
      outcomes.push(manager.verifyAndConsume(id, 'f'.repeat(64)));
      manager.get(id);
      manager.list();
      outcomes.push(manager.verifyAndConsume(id, 'f'.repeat(64)));
      manager.get(id);
      outcomes.push(manager.verifyAndConsume(id, 'f'.repeat(64)));

      assert.deepEqual(
        outcomes.map((o) => o.reason),
        ['SECRET_MISMATCH', 'SECRET_MISMATCH', 'LOCKED_OUT'],
      );
      assert.equal(manager.get(id), undefined);
      // A fourth attempt is not a fourth attempt against the same challenge.
      assert.equal(manager.verifyAndConsume(id, created.secret).reason, 'UNKNOWN_ENROLLMENT');
    });

    test('RC05-ENR-32: cancel versus consume yields at most one terminal outcome', () => {
      // Consume wins.
      const consumedFirst = create({ spkiPin: pin('race-a') });
      assert.equal(
        manager.verifyAndConsume(consumedFirst.enrollment.enrollmentId, consumedFirst.secret).ok,
        true,
      );
      assert.equal(manager.cancel(consumedFirst.enrollment.enrollmentId), false);

      // Cancel wins.
      const cancelledFirst = create({ spkiPin: pin('race-b') });
      assert.equal(manager.cancel(cancelledFirst.enrollment.enrollmentId), true);
      assert.equal(
        manager.verifyAndConsume(cancelledFirst.enrollment.enrollmentId, cancelledFirst.secret).ok,
        false,
      );
    });

    test('RC05-ENR-33: expiry is evaluated before the secret, at the exact boundary', () => {
      // Both challenges are created at the same instant so they share a deadline.
      const created = create();
      const second = create({ spkiPin: pin('boundary') });

      // One nanosecond before the deadline the correct secret still works.
      mono += BigInt(ENROLLMENT_TTL_SECONDS) * 1_000_000_000n - 1n;
      assert.equal(
        manager.verifyAndConsume(created.enrollment.enrollmentId, created.secret).ok,
        true,
      );

      // Exactly at the deadline it does not: expiry is checked first.
      mono += 1n;
      assert.equal(
        manager.verifyAndConsume(second.enrollment.enrollmentId, second.secret).reason,
        'EXPIRED',
      );
    });

    test('RC05-ENR-34: quota admission cannot race past the global bound', () => {
      let admitted = 0;
      let refused = 0;
      for (let i = 0; i < MAX_PENDING_ENROLLMENTS_GLOBAL + 5; i++) {
        try {
          create({
            spkiPin: pin(`race-quota-${i}`),
            operatorId: crypto.createHash('sha256').update(`op-race-${i}`).digest('hex'),
          });
          admitted += 1;
        } catch (err) {
          assert.equal(err.code, 'RESOURCE_EXHAUSTED');
          refused += 1;
        }
      }
      assert.equal(admitted, MAX_PENDING_ENROLLMENTS_GLOBAL);
      assert.equal(refused, 5);
      assert.equal(manager.getPendingCount(), MAX_PENDING_ENROLLMENTS_GLOBAL);
    });

    test('RC05-ENR-35: restart semantics — a new manager starts empty', () => {
      create();
      assert.equal(manager.getPendingCount(), 1);

      // A restart constructs a fresh manager. Pending state is volatile and
      // there is no recovery file, so nothing survives.
      const restarted = new EnrollmentManager({ getMonotonicTime: () => mono });
      assert.equal(restarted.getPendingCount(), 0);
      assert.equal(restarted.list().length, 0);
    });
  });

  // =========================================================================
  // Task-1 duplicate invariants remain enforced (regression)
  // =========================================================================

  describe('Task-1 duplicate-enrollment invariants', () => {
    test('RC05-ENR-40: the same pin and clientId reconnect rather than duplicate', () => {
      const store = DeviceTrustStore.createEmpty();
      const first = store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('dup'),
      });
      assert.equal(first.reconnected, false);
      assert.equal(store.getDeviceCount(), 1);

      const second = store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('dup'),
      });
      assert.equal(second.reconnected, true, 'same pin + same clientId must reuse the record');
      assert.equal(second.device.deviceId, first.device.deviceId);
      assert.equal(store.getDeviceCount(), 1, 'no second device record');
    });

    test('RC05-ENR-41: a pin bound to another clientId is rejected', () => {
      const store = DeviceTrustStore.createEmpty();
      store.enrollDevice({
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        pin: pin('conflict'),
      });

      assert.throws(
        () =>
          store.enrollDevice({
            clientId: 'agent-beta',
            clientType: 'claude-code',
            pin: pin('conflict'),
          }),
        (err) => err.code === 'INVALID_REQUEST_SCHEMA',
      );
      assert.equal(store.getDeviceCount(), 1, 'the existing binding is unchanged');
    });
  });
});
