/**
 * CesSpace ARC — RC-05 Task 9: Device and Session Administration CLI
 *
 * Covers `arc devices ...` and `arc sessions ...` on the EXISTING operator CLI:
 * the same `--admin-socket` / `--admin-key-fd` inherited-descriptor credential
 * model, the same one-operation-per-connection admin protocol, and strict
 * pre-IPC validation of every operator-supplied identifier.
 *
 * The CLI adds no credential source and no admin transport. Its validation is a
 * convenience, never the authority: the server re-validates the same bounds
 * authoritatively, so a client that skipped these checks could not reach a
 * weaker code path. Every case here therefore asserts BOTH the local refusal and
 * that no admin request was sent.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { exportPrivateKeyB64, exportPublicKeyB64 } from '../packages/protocol/dist/index.js';
import { EXIT_FAILURE, EXIT_OK, EXIT_USAGE, runCli } from '../apps/cli/dist/index.js';

let tempRoot;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-task9-cli-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

const DEVICE_ID = 'a'.repeat(32);
const SESSION_ID = 'b'.repeat(64);
const SPKI_PIN = 'c'.repeat(64);

const ADMIN_ARGS = ['--admin-socket', '/tmp/fake-admin.sock', '--admin-key-fd', '7'];

/** Runs the CLI capturing stdout and stderr separately. */
async function run(argv, dependencies = {}) {
  let out = '';
  let err = '';
  const exitCode = await runCli(argv, {
    stdout: (text) => {
      out += text;
    },
    stderr: (text) => {
      err += text;
    },
    env: {},
    ...dependencies,
  });
  return { exitCode, out, err };
}

/** A fake admin client that records the calls it receives. */
function fakeClient(result, calls = []) {
  return ({ endpoint, privateKey }) => ({
    async request(method, params) {
      calls.push({ endpoint, method, params, privateKey });
      return result;
    },
  });
}

function operatorKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKey,
    privateKeyB64: exportPrivateKeyB64(privateKey),
    publicKeyB64: exportPublicKeyB64(publicKey),
  };
}

/** Runs an admin command against a recording fake client. */
async function runAdmin(args, result) {
  const calls = [];
  const key = operatorKey();
  const outcome = await run([...args, ...ADMIN_ARGS], {
    readPrivateKeyFromFd: () => key.privateKey,
    createAdminClient: fakeClient(result, calls),
  });
  return { ...outcome, calls, key };
}

const DEVICE_A = {
  deviceId: DEVICE_ID,
  clientId: 'agent-alpha',
  clientType: 'claude-code',
  displayLabel: 'alpha-laptop',
  enrolledAt: '2026-01-01T00:00:00.000Z',
  revoked: false,
  activePinCount: 1,
};

describe('CesSpace ARC — RC-05 Task 9: Device and Session CLI', () => {
  // =========================================================================
  // devices list / inspect
  // =========================================================================

  describe('devices list and inspect', () => {
    test('RC05-T9-CLI-01: devices list sends one request and renders bounded metadata', async () => {
      const { exitCode, out, err, calls } = await runAdmin(['devices', 'list'], {
        ok: true,
        result: { devices: [DEVICE_A] },
      });

      assert.equal(exitCode, EXIT_OK, err);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'devices.list');
      assert.deepEqual(calls[0].params, {});
      assert.equal(calls[0].endpoint, '/tmp/fake-admin.sock');

      assert.ok(out.includes(DEVICE_ID));
      assert.ok(out.includes('agent-alpha'));
      assert.ok(out.includes('alpha-laptop'));
      assert.ok(out.includes('ACTIVE'));
      assert.ok(!out.includes('REVOKED'));
      assert.equal(err, '');
    });

    test('RC05-T9-CLI-02: a revoked device is rendered as revoked', async () => {
      const { exitCode, out } = await runAdmin(['devices', 'list'], {
        ok: true,
        result: { devices: [{ ...DEVICE_A, revoked: true, displayLabel: '' }] },
      });
      assert.equal(exitCode, EXIT_OK);
      assert.ok(out.includes('REVOKED'));
      // An empty display label renders as a placeholder, never as a blank line
      // that could be mistaken for a missing field.
      assert.ok(out.includes('Label:    -'));
    });

    test('RC05-T9-CLI-03: devices inspect sends the identifier and shows the active pins', async () => {
      const { exitCode, out, calls } = await runAdmin(['devices', 'inspect', DEVICE_ID], {
        ok: true,
        result: { ...DEVICE_A, pins: [SPKI_PIN] },
      });

      assert.equal(exitCode, EXIT_OK);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'devices.inspect');
      assert.deepEqual(calls[0].params, { deviceId: DEVICE_ID });
      assert.ok(out.includes(SPKI_PIN));
    });

    test('RC05-T9-CLI-04: list and inspect reject surplus arguments before any IPC', async () => {
      for (const args of [
        ['devices', 'list', 'extra'],
        ['devices', 'inspect'],
        ['devices', 'inspect', DEVICE_ID, 'extra'],
        ['sessions', 'list', 'extra'],
        ['sessions', 'revoke'],
        ['sessions', 'revoke', SESSION_ID, 'extra'],
        ['devices', 'nonsense'],
        ['sessions', 'nonsense'],
      ]) {
        const { exitCode, err, calls } = await runAdmin(args, { ok: true, result: {} });
        assert.equal(exitCode, EXIT_USAGE, args.join(' '));
        assert.equal(calls.length, 0, `${args.join(' ')} must not reach the admin channel`);
        assert.notEqual(err, '');
      }
    });
  });

  // =========================================================================
  // Pre-IPC identifier validation
  // =========================================================================

  describe('identifier validation', () => {
    test('RC05-T9-CLI-05: deviceId must be exactly 32 lowercase hex characters', async () => {
      for (const deviceId of [
        'A'.repeat(32),
        'a'.repeat(31),
        'a'.repeat(33),
        'g'.repeat(32),
        '',
        `${DEVICE_ID} `,
      ]) {
        for (const sub of ['inspect', 'revoke']) {
          const { exitCode, err, calls } = await runAdmin(['devices', sub, deviceId], {
            ok: true,
            result: {},
          });
          assert.equal(exitCode, EXIT_USAGE, `${sub} ${JSON.stringify(deviceId)}`);
          assert.equal(calls.length, 0, `${sub} must not reach the admin channel`);
          assert.match(err, /deviceId/);
        }
      }
    });

    test('RC05-T9-CLI-06: sessionId must be exactly 64 lowercase hex characters', async () => {
      for (const sessionId of [
        'B'.repeat(64),
        'b'.repeat(63),
        'b'.repeat(65),
        'z'.repeat(64),
        '',
        SESSION_ID.slice(0, 32),
      ]) {
        const { exitCode, err, calls } = await runAdmin(['sessions', 'revoke', sessionId], {
          ok: true,
          result: {},
        });
        assert.equal(exitCode, EXIT_USAGE, JSON.stringify(sessionId));
        assert.equal(calls.length, 0, 'no admin request may be sent');
        assert.match(err, /sessionId/);
      }
    });

    test('RC05-T9-CLI-07: --spki-pin must be exactly 64 lowercase hex characters', async () => {
      for (const spkiPin of [
        'C'.repeat(64),
        'c'.repeat(63),
        'c'.repeat(65),
        'not-hex',
        '',
        `0x${'c'.repeat(64)}`,
      ]) {
        for (const sub of ['pin-add', 'pin-remove']) {
          const { exitCode, err, calls } = await runAdmin(
            ['devices', sub, DEVICE_ID, '--spki-pin', spkiPin],
            { ok: true, result: {} },
          );
          assert.equal(exitCode, EXIT_USAGE, `${sub} ${JSON.stringify(spkiPin)}`);
          assert.equal(calls.length, 0, 'no admin request may be sent');
          assert.match(err, /--spki-pin/);
        }
      }
    });

    test('RC05-T9-CLI-08: a display label is bounded at 64 UTF-8 bytes and rejects NUL', async () => {
      // Exactly 64 ASCII bytes and exactly 64 multi-byte bytes are both accepted.
      for (const label of ['x'.repeat(64), 'é'.repeat(32)]) {
        const { exitCode, calls } = await runAdmin(
          ['devices', 'rename', DEVICE_ID, '--label', label],
          { ok: true, result: { deviceId: DEVICE_ID, displayLabel: label } },
        );
        assert.equal(exitCode, EXIT_OK, JSON.stringify(label));
        assert.equal(calls.length, 1);
        assert.equal(calls[0].method, 'device.rename');
        assert.deepEqual(calls[0].params, { deviceId: DEVICE_ID, displayLabel: label });
      }

      for (const label of ['x'.repeat(65), 'é'.repeat(33), 'nul\u0000label']) {
        const { exitCode, err, calls } = await runAdmin(
          ['devices', 'rename', DEVICE_ID, '--label', label],
          { ok: true, result: {} },
        );
        assert.equal(exitCode, EXIT_USAGE, JSON.stringify(label));
        assert.equal(calls.length, 0, 'no admin request may be sent');
        assert.match(err, /--label/);
      }
    });
  });

  // =========================================================================
  // Option handling
  // =========================================================================

  describe('option handling', () => {
    test('RC05-T9-CLI-09: unknown options and surplus positionals are rejected', async () => {
      const cases = [
        ['devices', 'list', '--nope'],
        ['devices', 'revoke', DEVICE_ID, '--label', 'x'],
        ['devices', 'rename', DEVICE_ID, '--label', 'x', '--spki-pin', SPKI_PIN],
        ['devices', 'pin-add', DEVICE_ID, '--label', 'x'],
        ['devices', 'pin-add', DEVICE_ID, '--spki-pin', SPKI_PIN, 'extra'],
        ['devices', 'rename', DEVICE_ID, 'extra', '--label', 'x'],
      ];
      for (const args of cases) {
        const { exitCode, err, calls } = await runAdmin(args, { ok: true, result: {} });
        assert.equal(exitCode, EXIT_USAGE, args.join(' '));
        assert.equal(calls.length, 0, `${args.join(' ')} must not reach the admin channel`);
        assert.notEqual(err, '');
      }
    });

    test('RC05-T9-CLI-10: a missing required option is a usage failure, not a request', async () => {
      for (const args of [
        ['devices', 'rename', DEVICE_ID],
        ['devices', 'pin-add', DEVICE_ID],
        ['devices', 'pin-remove', DEVICE_ID],
        ['devices', 'rename', DEVICE_ID, '--label'],
        ['devices', 'pin-add', DEVICE_ID, '--spki-pin'],
      ]) {
        const { exitCode, calls } = await runAdmin(args, { ok: true, result: {} });
        assert.equal(exitCode, EXIT_USAGE, args.join(' '));
        assert.equal(calls.length, 0, `${args.join(' ')} must not reach the admin channel`);
      }
    });

    test('RC05-T9-CLI-11: the inherited-FD credential model is unchanged', async () => {
      // The endpoint and FD number may come from the environment, exactly as for
      // every other admin command. The KEY never may.
      const key = operatorKey();
      const calls = [];
      let fdRequested;
      const outcome = await run(['devices', 'list'], {
        env: {
          CESSPACE_ARC_ADMIN_SOCKET: '/tmp/from-env.sock',
          CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD: '9',
        },
        readPrivateKeyFromFd: (fd) => {
          fdRequested = fd;
          return key.privateKey;
        },
        createAdminClient: fakeClient({ ok: true, result: { devices: [] } }, calls),
      });

      assert.equal(outcome.exitCode, EXIT_OK);
      assert.equal(fdRequested, 9);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].endpoint, '/tmp/from-env.sock');
      assert.equal(calls[0].privateKey, key.privateKey);

      // A missing endpoint or FD is a usage failure before any key is read.
      let reads = 0;
      const missing = await run(['devices', 'list'], {
        env: {},
        readPrivateKeyFromFd: () => {
          reads += 1;
          return key.privateKey;
        },
        createAdminClient: fakeClient({ ok: true, result: {} }, []),
      });
      assert.equal(missing.exitCode, EXIT_USAGE);
      assert.equal(reads, 0, 'the private key must not be read without a configured channel');
    });
  });

  // =========================================================================
  // Failure reporting
  // =========================================================================

  describe('failure reporting', () => {
    test('RC05-T9-CLI-12: every bounded admin failure maps to a nonzero exit', async () => {
      const cases = [
        ['AUTHENTICATION_FAILED', /authentication failed/i],
        ['INVALID_ADMIN_REQUEST', /rejected as invalid/i],
        ['ADMINISTRATION_UNAVAILABLE', /administration is unavailable/i],
      ];
      for (const [code, pattern] of cases) {
        const { exitCode, err, out } = await runAdmin(['devices', 'list'], {
          ok: false,
          error: { code },
        });
        assert.equal(exitCode, EXIT_FAILURE, code);
        assert.match(err, pattern);
        assert.equal(out, '', 'no stdout on failure');
      }
    });

    test('RC05-T9-CLI-13: device and session refusals use their own bounded wording', async () => {
      const notFound = await runAdmin(['devices', 'inspect', DEVICE_ID], {
        ok: false,
        error: { code: 'NOT_FOUND_OR_NOT_PENDING' },
      });
      assert.equal(notFound.exitCode, EXIT_FAILURE);
      assert.match(notFound.err, /No enrolled device/);

      const sessionNotFound = await runAdmin(['sessions', 'revoke', SESSION_ID], {
        ok: false,
        error: { code: 'NOT_FOUND_OR_NOT_PENDING' },
      });
      assert.equal(sessionNotFound.exitCode, EXIT_FAILURE);
      assert.match(sessionNotFound.err, /No live session/);

      const exhausted = await runAdmin(['devices', 'pin-add', DEVICE_ID, '--spki-pin', SPKI_PIN], {
        ok: false,
        error: { code: 'RESOURCE_EXHAUSTED' },
      });
      assert.equal(exhausted.exitCode, EXIT_FAILURE);
      assert.match(exhausted.err, /two active SPKI pin limit/);
    });

    test('RC05-T9-CLI-14: a malformed admin response is not rendered as success', async () => {
      for (const result of [undefined, null, 'not-an-object', {}, { devices: 'nope' }]) {
        const { exitCode, err, out, calls } = await runAdmin(['devices', 'list'], {
          ok: true,
          result,
        });
        // An empty device list is the only well-formed 'nothing enrolled' shape.
        if (result !== undefined && JSON.stringify(result) === '{}') {
          assert.equal(exitCode, EXIT_FAILURE);
          assert.match(err, /malformed/i);
        } else {
          assert.equal(exitCode, EXIT_FAILURE, JSON.stringify(result));
          assert.equal(out, '', JSON.stringify(result));
        }
        assert.equal(calls.length, 1);
      }
    });
  });

  // =========================================================================
  // Mutation rendering and output safety
  // =========================================================================

  describe('mutation rendering', () => {
    test('RC05-T9-CLI-15: revoke, rename, and pin mutations render bounded outcomes', async () => {
      const revoked = await runAdmin(['devices', 'revoke', DEVICE_ID], {
        ok: true,
        result: { deviceId: DEVICE_ID, revoked: true, sessionsRevoked: 2, transportsClosed: 2 },
      });
      assert.equal(revoked.exitCode, EXIT_OK);
      assert.equal(revoked.calls[0].method, 'device.revoke');
      assert.deepEqual(revoked.calls[0].params, { deviceId: DEVICE_ID });
      assert.ok(revoked.out.includes(DEVICE_ID));
      assert.ok(revoked.out.includes('Sessions revoked:   2'));

      const renamed = await runAdmin(['devices', 'rename', DEVICE_ID, '--label', 'renamed'], {
        ok: true,
        result: { deviceId: DEVICE_ID, displayLabel: 'renamed' },
      });
      assert.equal(renamed.exitCode, EXIT_OK);
      assert.equal(renamed.calls[0].method, 'device.rename');
      assert.ok(renamed.out.includes('renamed'));

      const pinned = await runAdmin(['devices', 'pin-add', DEVICE_ID, '--spki-pin', SPKI_PIN], {
        ok: true,
        result: { deviceId: DEVICE_ID, activePinCount: 2 },
      });
      assert.equal(pinned.exitCode, EXIT_OK);
      assert.equal(pinned.calls[0].method, 'device.pin.add');
      assert.deepEqual(pinned.calls[0].params, { deviceId: DEVICE_ID, spkiPin: SPKI_PIN });
      assert.ok(pinned.out.includes('Active pins: 2'));

      const unpinned = await runAdmin(
        ['devices', 'pin-remove', DEVICE_ID, '--spki-pin', SPKI_PIN],
        { ok: true, result: { deviceId: DEVICE_ID, activePinCount: 1 } },
      );
      assert.equal(unpinned.exitCode, EXIT_OK);
      assert.equal(unpinned.calls[0].method, 'device.pin.remove');
      assert.ok(unpinned.out.includes('pin removed'));
    });

    test('RC05-T9-CLI-16: sessions list renders live sessions and no credential material', async () => {
      const tokenLike = 'd'.repeat(64);
      const listed = await runAdmin(['sessions', 'list'], {
        ok: true,
        result: {
          sessions: [
            {
              sessionId: SESSION_ID,
              deviceId: DEVICE_ID,
              clientId: 'agent-alpha',
              clientType: 'claude-code',
              issuedAt: '2026-01-01T00:00:00.000Z',
              state: 'ACTIVE',
            },
          ],
        },
      });

      assert.equal(listed.exitCode, EXIT_OK);
      assert.equal(listed.calls[0].method, 'sessions.list');
      assert.deepEqual(listed.calls[0].params, {});
      assert.ok(listed.out.includes(SESSION_ID));
      assert.ok(listed.out.includes(DEVICE_ID));
      assert.ok(listed.out.includes('ACTIVE'));

      // Nothing credential-shaped is ever printed by a session command.
      for (const forbidden of [tokenLike, 'Bearer', 'Authorization', 'digest', 'token']) {
        assert.ok(!listed.out.includes(forbidden), `${forbidden} must not be printed`);
      }
    });

    test('RC05-T9-CLI-17: sessions revoke sends exactly one identifier', async () => {
      const { exitCode, out, calls } = await runAdmin(['sessions', 'revoke', SESSION_ID], {
        ok: true,
        result: { sessionId: SESSION_ID, state: 'REVOKED', transportClosed: true },
      });
      assert.equal(exitCode, EXIT_OK);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'session.revoke');
      assert.deepEqual(calls[0].params, { sessionId: SESSION_ID });
      assert.ok(out.includes(SESSION_ID));
      assert.ok(out.includes('REVOKED'));
    });

    test('RC05-T9-CLI-18: the help text documents every Task-9 command', async () => {
      const { exitCode, out } = await run(['--help'], {});
      assert.equal(exitCode, EXIT_OK);
      for (const command of [
        'devices list',
        'devices inspect <deviceId>',
        'devices revoke <deviceId>',
        'devices rename <deviceId> --label <text>',
        'devices pin-add <deviceId> --spki-pin <64hex>',
        'devices pin-remove <deviceId> --spki-pin <64hex>',
        'sessions list',
        'sessions revoke <sessionId>',
      ]) {
        assert.ok(out.includes(command), `${command} must be documented`);
      }
      // The help text states the local-only boundary explicitly.
      assert.match(out, /local authenticated admin channel/);
    });
  });
});
