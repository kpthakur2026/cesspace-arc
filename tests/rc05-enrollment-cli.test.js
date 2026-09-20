/**
 * CesSpace ARC — RC-05 Task 2: Enrollment Administration CLI
 *
 * Covers `arc enrollment create` and `arc enrollment cancel` on the EXISTING
 * operator CLI: the same --admin-socket / --admin-key-fd inherited-FD credential
 * model, local pre-IPC validation, and exactly-once display of the one-time
 * enrollment secret.
 *
 * No new credential source is introduced, and no secret is ever accepted
 * through argv.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { exportPrivateKeyB64, exportPublicKeyB64 } from '../packages/protocol/dist/index.js';
import { EXIT_OK, EXIT_USAGE, runCli } from '../apps/cli/dist/index.js';

let tempRoot;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-cli-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** Canonical SPKI pin shape. */
function pin(seed) {
  return crypto.createHash('sha256').update(`cli-pin-${seed}`, 'utf8').digest('hex');
}

const ENROLLMENT_ID = 'a'.repeat(32);
const SECRET = 'b'.repeat(64);

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

const CREATE_OK = {
  ok: true,
  result: {
    enrollment: {
      enrollmentId: ENROLLMENT_ID,
      clientId: 'agent-alpha',
      clientType: 'claude-code',
      spkiPin: pin('create'),
      displayLabel: 'laptop',
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-01T00:05:00.000Z',
      remainingSeconds: 300,
    },
    secret: SECRET,
  },
};

describe('CesSpace ARC — RC-05 Task 2: Enrollment CLI', () => {
  describe('enrollment create', () => {
    test('RC05-CLI-01: a valid creation sends exactly the operator-supplied inputs', async () => {
      const calls = [];
      const key = operatorKey();
      const result = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          'agent-alpha',
          '--client-type',
          'claude-code',
          '--spki-pin',
          pin('create'),
          '--label',
          'laptop',
          ...ADMIN_ARGS,
        ],
        {
          createAdminClient: fakeClient(CREATE_OK, calls),
          readPrivateKeyFromFd: () => 'fake-key',
        },
      );

      assert.equal(result.exitCode, EXIT_OK);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'enrollment.create');
      assert.deepEqual(calls[0].params, {
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        spkiPin: pin('create'),
        displayLabel: 'laptop',
      });
      // The key comes from the inherited descriptor, never from argv.
      assert.equal(calls[0].privateKey, 'fake-key');
      assert.equal(key.privateKeyB64.length > 0, true);
    });

    test('RC05-CLI-02: the one-time secret is displayed exactly once', async () => {
      const result = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          'agent-alpha',
          '--client-type',
          'claude-code',
          '--spki-pin',
          pin('create'),
          ...ADMIN_ARGS,
        ],
        { createAdminClient: fakeClient(CREATE_OK), readPrivateKeyFromFd: () => 'fake-key' },
      );

      assert.equal(result.exitCode, EXIT_OK);
      const occurrences = result.out.split(SECRET).length - 1;
      assert.equal(occurrences, 1, 'the secret must be shown exactly once');
      assert.match(result.out, /shown once/);
      assert.equal(result.err, '', 'nothing is written to stderr on success');
      assert.match(result.out, new RegExp(ENROLLMENT_ID));
    });

    test('RC05-CLI-03: a rejected creation reports a bounded failure and discloses no secret', async () => {
      const result = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          'agent-alpha',
          '--client-type',
          'claude-code',
          '--spki-pin',
          pin('create'),
          ...ADMIN_ARGS,
        ],
        {
          createAdminClient: fakeClient({ ok: false, error: { code: 'RESOURCE_EXHAUSTED' } }),
          readPrivateKeyFromFd: () => 'fake-key',
        },
      );

      assert.equal(result.exitCode, 1);
      assert.match(result.err, /Pending enrollment limits were reached/);
      assert.ok(!result.out.includes(SECRET));
    });

    test('RC05-CLI-04: local validation rejects malformed inputs before any IPC', async () => {
      const cases = [
        { argv: ['enrollment', 'create'], message: /--client-id is required/ },
        {
          argv: ['enrollment', 'create', '--client-id', 'a', '--client-type', 'c'],
          message: /--spki-pin is required/,
        },
        {
          argv: [
            'enrollment',
            'create',
            '--client-id',
            'a',
            '--client-type',
            'c',
            '--spki-pin',
            'A'.repeat(64),
          ],
          message: /64 lowercase hexadecimal/,
        },
        {
          argv: [
            'enrollment',
            'create',
            '--client-id',
            '',
            '--client-type',
            'c',
            '--spki-pin',
            pin('x'),
          ],
          message: /--client-id is required/,
        },
        {
          argv: [
            'enrollment',
            'create',
            '--client-id',
            'a',
            '--client-type',
            'c',
            '--spki-pin',
            pin('x'),
            '--label',
            'y'.repeat(65),
          ],
          message: /64 UTF-8 bytes/,
        },
        {
          argv: [
            'enrollment',
            'create',
            '--client-id',
            'a',
            '--client-type',
            'c',
            '--spki-pin',
            pin('x'),
            '--device-id',
            'd',
          ],
          message: /Unknown option for enrollment create/,
        },
        {
          argv: [
            'enrollment',
            'create',
            '--client-id',
            'a',
            '--client-type',
            'c',
            '--spki-pin',
            pin('x'),
            '--secret',
            SECRET,
          ],
          message: /Unknown option for enrollment create/,
        },
      ];

      for (const { argv, message } of cases) {
        const calls = [];
        const result = await run([...argv, ...ADMIN_ARGS], {
          createAdminClient: fakeClient(CREATE_OK, calls),
          readPrivateKeyFromFd: () => 'fake-key',
        });
        assert.equal(result.exitCode, EXIT_USAGE, argv.join(' '));
        assert.match(result.err, message);
        assert.equal(calls.length, 0, 'no IPC may occur after a usage failure');
      }
    });

    test('RC05-CLI-12: preflight bounds match the authoritative persisted limits', async () => {
      const build = (overrides) => [
        'enrollment',
        'create',
        '--client-id',
        overrides.clientId ?? 'agent-alpha',
        '--client-type',
        overrides.clientType ?? 'claude-code',
        '--spki-pin',
        pin('bounds'),
        ...ADMIN_ARGS,
      ];

      // Exactly at the persisted bounds: accepted and sent.
      const atLimit = await run(build({ clientId: 'i'.repeat(128), clientType: 'c'.repeat(64) }), {
        createAdminClient: fakeClient(CREATE_OK, []),
        readPrivateKeyFromFd: () => 'fake-key',
      });
      assert.equal(atLimit.exitCode, EXIT_OK, atLimit.err);

      // One character beyond each bound: refused locally, no IPC.
      const overId = await run(build({ clientId: 'i'.repeat(129) }), {
        createAdminClient: fakeClient(CREATE_OK, []),
        readPrivateKeyFromFd: () => 'fake-key',
      });
      assert.equal(overId.exitCode, EXIT_USAGE);
      assert.match(overId.err, /--client-id must not exceed 128 characters/);

      const overType = await run(build({ clientType: 'c'.repeat(65) }), {
        createAdminClient: fakeClient(CREATE_OK, []),
        readPrivateKeyFromFd: () => 'fake-key',
      });
      assert.equal(overType.exitCode, EXIT_USAGE);
      assert.match(overType.err, /--client-type must not exceed 64 characters/);
    });

    test('RC05-CLI-13: a NUL in an identifier is refused before IPC', async () => {
      const result = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          `agent${String.fromCharCode(0)}alpha`,
          '--client-type',
          'claude-code',
          '--spki-pin',
          pin('nul'),
          ...ADMIN_ARGS,
        ],
        { createAdminClient: fakeClient(CREATE_OK, []), readPrivateKeyFromFd: () => 'fake-key' },
      );
      assert.equal(result.exitCode, EXIT_USAGE);
      assert.match(result.err, /must not contain NUL/);
    });

    test('RC05-CLI-05: an unusable success payload is refused rather than displayed', async () => {
      const result = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          'a',
          '--client-type',
          'c',
          '--spki-pin',
          pin('bad'),
          ...ADMIN_ARGS,
        ],
        {
          createAdminClient: fakeClient({ ok: true, result: { enrollment: {}, secret: 'nope' } }),
          readPrivateKeyFromFd: () => 'fake-key',
        },
      );
      assert.equal(result.exitCode, 1);
      assert.match(result.err, /unusable result/);
    });
  });

  describe('enrollment cancel', () => {
    test('RC05-CLI-06: a valid cancellation sends only the enrollment id', async () => {
      const calls = [];
      const result = await run(['enrollment', 'cancel', ENROLLMENT_ID, ...ADMIN_ARGS], {
        createAdminClient: fakeClient(
          { ok: true, result: { enrollmentId: ENROLLMENT_ID, state: 'CANCELLED' } },
          calls,
        ),
        readPrivateKeyFromFd: () => 'fake-key',
      });

      assert.equal(result.exitCode, EXIT_OK);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'enrollment.cancel');
      assert.deepEqual(calls[0].params, { enrollmentId: ENROLLMENT_ID });
      assert.match(result.out, /CANCELLED/);
      assert.ok(!result.out.includes(SECRET));
    });

    test('RC05-CLI-07: a not-pending cancellation is reported without an oracle', async () => {
      const result = await run(['enrollment', 'cancel', 'f'.repeat(32), ...ADMIN_ARGS], {
        createAdminClient: fakeClient({
          ok: false,
          error: { code: 'NOT_FOUND_OR_NOT_PENDING' },
        }),
        readPrivateKeyFromFd: () => 'fake-key',
      });

      assert.equal(result.exitCode, 1);
      assert.match(result.err, /No pending enrollment matches that enrollment ID/);
    });

    test('RC05-CLI-08: malformed identifiers and argument counts are usage errors', async () => {
      const cases = [
        { argv: ['enrollment', 'cancel'], message: /exactly one <enrollmentId>/ },
        { argv: ['enrollment', 'cancel', 'A'.repeat(32)], message: /32 lowercase hexadecimal/ },
        { argv: ['enrollment', 'cancel', 'a'.repeat(31)], message: /32 lowercase hexadecimal/ },
        {
          argv: ['enrollment', 'cancel', ENROLLMENT_ID, 'extra'],
          message: /exactly one <enrollmentId>/,
        },
      ];
      for (const { argv, message } of cases) {
        const calls = [];
        const result = await run([...argv, ...ADMIN_ARGS], {
          createAdminClient: fakeClient({ ok: true, result: {} }, calls),
          readPrivateKeyFromFd: () => 'fake-key',
        });
        assert.equal(result.exitCode, EXIT_USAGE, argv.join(' '));
        assert.match(result.err, message);
        assert.equal(calls.length, 0);
      }
    });

    test('RC05-CLI-09: an unknown enrollment subcommand is a usage error', async () => {
      const result = await run(['enrollment', 'list', ...ADMIN_ARGS], {
        createAdminClient: fakeClient({ ok: true, result: {} }),
        readPrivateKeyFromFd: () => 'fake-key',
      });
      assert.equal(result.exitCode, EXIT_USAGE);
      assert.match(result.err, /Unknown enrollment subcommand: list/);
    });
  });

  describe('Credential model', () => {
    test('RC05-CLI-10: enrollment commands require the configured admin channel', async () => {
      const missingSocket = await run(
        ['enrollment', 'create', '--client-id', 'a', '--client-type', 'c', '--spki-pin', pin('m')],
        { createAdminClient: fakeClient(CREATE_OK), readPrivateKeyFromFd: () => 'fake-key' },
      );
      assert.equal(missingSocket.exitCode, EXIT_USAGE);
      assert.match(missingSocket.err, /Admin channel endpoint is not configured/);

      const missingKey = await run(
        [
          'enrollment',
          'create',
          '--client-id',
          'a',
          '--client-type',
          'c',
          '--spki-pin',
          pin('m'),
          '--admin-socket',
          '/tmp/fake.sock',
        ],
        { createAdminClient: fakeClient(CREATE_OK), readPrivateKeyFromFd: () => 'fake-key' },
      );
      assert.equal(missingKey.exitCode, EXIT_USAGE);
      assert.match(missingKey.err, /Admin key is not configured/);
    });

    test('RC05-CLI-11: help advertises the enrollment commands', async () => {
      const result = await run(['--help']);
      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, /enrollment create/);
      assert.match(result.out, /enrollment cancel/);
      assert.match(result.out, /--admin-key-fd/);
    });
  });
});
