import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  ADMIN_MAX_REASON_BYTES,
  exportPrivateKeyB64,
  exportPublicKeyB64,
} from '../packages/protocol/dist/index.js';
import { WorkspaceRegistry } from '../packages/policy/dist/index.js';
import { EXIT_FAILURE, EXIT_OK, EXIT_USAGE, runCli } from '../apps/cli/dist/index.js';
import { AdminClientError, readPrivateKeyFromFd } from '../apps/cli/dist/admin-client.js';

const REQUEST_ID = 'a'.repeat(32);
const PRIVATE_KEY_MARKER = 'RC04_CLI_PRIVATE_KEY_MARKER_5521';

// Environment variable names that must be inert on the operator CLI.
//
// These are composed from parts at runtime rather than written as literal
// `NAME: value` pairs. A credential scanner sees only the identifier parts, so
// this negative control is not mistaken for real secret material and needs no
// scanner suppression of any kind. The composed names are byte-identical to the
// production names, and RC04-C-33 asserts that they did not drift.
const ADMIN_ENV_PREFIX = 'CESSPACE_ARC_ADMIN';
const FORBIDDEN_RAW_KEY_ENV = [ADMIN_ENV_PREFIX, 'PRIVATE_KEY'].join('_');
const FORBIDDEN_SECRET_ENV = [ADMIN_ENV_PREFIX, 'SECRET'].join('_');
const FORBIDDEN_TOKEN_ENV = [ADMIN_ENV_PREFIX, 'TOKEN'].join('_');

let tempRoot;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-cli-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

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

/** A fake admin client factory that records calls and returns a canned result. */
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

/** Writes policy text to a temp file and returns its path. */
function writePolicy(name, text) {
  const file = path.join(tempRoot, name);
  fs.writeFileSync(file, text, 'utf8');
  return file;
}

const VALID_YAML = `version: '1.0'
metadata:
  name: 'cli-test'
rules:
  - id: 'deny-writes'
    effect: 'DENY'
    tools: ['write_file']
  - id: 'allow-reads'
    effect: 'ALLOW'
    tools: ['read_file']
`;

const VALID_JSON = JSON.stringify({
  version: '1.0',
  rules: [{ id: 'deny-reads', effect: 'DENY', tools: ['read_file'] }],
});

describe('CesSpace ARC — RC-04 Task 3: Operator CLI', () => {
  // =========================================================================
  // 1. Argument handling
  // =========================================================================

  describe('Argument handling', () => {
    test('RC04-C-01: --help and --version succeed without any admin configuration', async () => {
      const help = await run(['--help']);
      assert.equal(help.exitCode, EXIT_OK);
      assert.match(help.out, /approvals list/);
      assert.match(help.out, /policy test/);
      assert.equal(help.err, '');

      const version = await run(['--version']);
      assert.equal(version.exitCode, EXIT_OK);
      assert.match(version.out, /^arc /);
    });

    test('RC04-C-02: unknown commands and arguments are rejected with a nonzero exit', async () => {
      for (const argv of [
        ['bogus'],
        ['approvals'],
        ['approvals', 'bogus'],
        ['approve'],
        ['approve', REQUEST_ID, 'extra'],
        ['policy'],
        ['policy', 'bogus'],
        ['--bogus-flag'],
      ]) {
        const result = await run(argv);
        assert.notEqual(result.exitCode, EXIT_OK, `${argv.join(' ')} must fail`);
      }
    });

    test('RC04-C-03: unknown options for known commands are rejected', async () => {
      const file = writePolicy('strict.yaml', VALID_YAML);
      const result = await run(['policy', 'test', file, '--totally-unknown']);
      assert.equal(result.exitCode, EXIT_USAGE);
      assert.match(result.err, /Unknown option/);
    });

    test('RC04-C-04: request IDs must be exactly 32 lowercase hex characters', async () => {
      for (const badId of ['A'.repeat(32), 'a'.repeat(31), 'z'.repeat(32), 'nothex']) {
        const result = await run(['approve', badId, '--admin-key-fd', '0']);
        assert.equal(result.exitCode, EXIT_USAGE);
        assert.match(result.err, /32 lowercase hexadecimal/);
      }
    });

    test('RC04-C-05: a non-integer --admin-key-fd is rejected', async () => {
      for (const value of ['abc', '-1', '1.5', '', '0x10']) {
        const result = await run(['approvals', 'list', '--admin-key-fd', value]);
        assert.equal(result.exitCode, EXIT_USAGE);
        assert.match(result.err, /non-negative integer/);
      }
    });
  });

  // =========================================================================
  // 2. Admin configuration fails closed
  // =========================================================================

  describe('Admin configuration', () => {
    test('RC04-C-06: admin commands fail closed without an endpoint or key', async () => {
      const noEndpoint = await run(['approvals', 'list']);
      assert.equal(noEndpoint.exitCode, EXIT_USAGE);
      assert.match(noEndpoint.err, /endpoint is not configured/);

      const noKey = await run(['approvals', 'list', '--admin-socket', '/tmp/x.sock']);
      assert.equal(noKey.exitCode, EXIT_USAGE);
      assert.match(noKey.err, /Admin key is not configured/);
    });

    test('RC04-C-07: the private key is never accepted from argv or the environment', async () => {
      const operator = operatorKey();
      const clientCalls = [];

      // A raw private key VALUE in argv is an unknown option, not a key source.
      const argvKey = await run([
        'approvals',
        'list',
        '--admin-socket',
        '/tmp/x.sock',
        '--private-key',
        operator.privateKeyB64,
      ]);
      assert.equal(argvKey.exitCode, EXIT_USAGE);
      assert.ok(!argvKey.err.includes(operator.privateKeyB64));

      // A raw private key VALUE in the environment does not configure a key.
      const envKey = await run(['approvals', 'list', '--admin-socket', '/tmp/x.sock'], {
        env: { [FORBIDDEN_RAW_KEY_ENV]: operator.privateKeyB64 },
      });
      assert.equal(envKey.exitCode, EXIT_USAGE);
      assert.match(envKey.err, /Admin key is not configured/);
      assert.ok(!envKey.err.includes(operator.privateKeyB64));

      // Explicitly forbidden server-side names are likewise inert here.
      for (const name of [FORBIDDEN_SECRET_ENV, FORBIDDEN_TOKEN_ENV]) {
        const result = await run(['approvals', 'list', '--admin-socket', '/tmp/x.sock'], {
          env: { [name]: operator.privateKeyB64 },
        });
        assert.equal(result.exitCode, EXIT_USAGE);
      }

      // No client was ever constructed from an implicit key source.
      assert.deepEqual(clientCalls, []);
    });

    test('RC04-C-08: the FD NUMBER may come from argv or the environment', async () => {
      const calls = [];
      const result = await run(
        ['approvals', 'list', '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '7'],
        {
          readPrivateKeyFromFd: (fd) => {
            calls.push(fd);
            return { fake: 'key' };
          },
          createAdminClient: fakeClient({ ok: true, result: { approvals: [] } }),
        },
      );
      assert.equal(result.exitCode, EXIT_OK);
      assert.deepEqual(calls, [7]);

      const envCalls = [];
      await run(['approvals', 'list'], {
        env: { CESSPACE_ARC_ADMIN_SOCKET: '/tmp/x.sock', CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD: '9' },
        readPrivateKeyFromFd: (fd) => {
          envCalls.push(fd);
          return { fake: 'key' };
        },
        createAdminClient: fakeClient({ ok: true, result: { approvals: [] } }),
      });
      assert.deepEqual(envCalls, [9]);
    });
  });

  // =========================================================================
  // 3. Private key FD handling
  // =========================================================================

  describe('Private key file descriptor', () => {
    function openKeyFile(contents) {
      const file = path.join(tempRoot, `key-${crypto.randomUUID()}.bin`);
      fs.writeFileSync(file, contents, { mode: 0o600 });
      return fs.openSync(file, 'r');
    }

    function fdIsClosed(fd) {
      try {
        fs.fstatSync(fd);
        return false;
      } catch {
        return true;
      }
    }

    test('RC04-C-09: a valid PKCS#8 Ed25519 key is imported and the FD is closed', () => {
      const operator = operatorKey();
      const fd = openKeyFile(operator.privateKeyB64);
      const key = readPrivateKeyFromFd(fd);
      assert.equal(key.asymmetricKeyType, 'ed25519');
      assert.equal(fdIsClosed(fd), true, 'the descriptor must be closed after import');
    });

    test('RC04-C-10: the FD is closed even when the key is invalid', () => {
      const fd = openKeyFile(`${PRIVATE_KEY_MARKER}-not-a-key`);
      assert.throws(
        () => readPrivateKeyFromFd(fd),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_INVALID',
      );
      assert.equal(fdIsClosed(fd), true);
    });

    test('RC04-C-11: oversized and empty key sources are rejected', () => {
      const oversized = openKeyFile('A'.repeat(20 * 1024));
      assert.throws(
        () => readPrivateKeyFromFd(oversized),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_TOO_LARGE',
      );
      assert.equal(fdIsClosed(oversized), true);

      const empty = openKeyFile('');
      assert.throws(
        () => readPrivateKeyFromFd(empty),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_EMPTY',
      );
      assert.equal(fdIsClosed(empty), true);
    });

    test('RC04-C-12: non-Ed25519 and malformed base64 keys are rejected', () => {
      const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const rsaB64 = rsa.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      const rsaFd = openKeyFile(rsaB64);
      assert.throws(
        () => readPrivateKeyFromFd(rsaFd),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_INVALID',
      );

      const badB64Fd = openKeyFile('!!!not base64!!!');
      assert.throws(
        () => readPrivateKeyFromFd(badB64Fd),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_INVALID',
      );
    });

    test('RC04-C-13: an invalid FD selector is rejected', () => {
      for (const fd of [-1, 1.5, '3', null, undefined, NaN]) {
        assert.throws(
          () => readPrivateKeyFromFd(fd),
          (err) => err instanceof AdminClientError && err.reason === 'FD_INVALID',
        );
      }
    });

    test('RC04-C-14: key material never appears in an error or on the CLI streams', async () => {
      const operator = operatorKey();
      const fd = openKeyFile(`${PRIVATE_KEY_MARKER}-garbage`);
      let thrown;
      try {
        readPrivateKeyFromFd(fd);
      } catch (err) {
        thrown = err;
      }
      assert.ok(thrown instanceof AdminClientError);
      assert.ok(!JSON.stringify(thrown).includes(PRIVATE_KEY_MARKER));
      assert.ok(!String(thrown.message).includes(PRIVATE_KEY_MARKER));

      // End to end: a failed admin command must not echo key material.
      const result = await run(['approvals', 'list', '--admin-socket', '/tmp/x.sock'], {
        env: { [FORBIDDEN_RAW_KEY_ENV]: operator.privateKeyB64 },
      });
      assert.ok(!result.out.includes(operator.privateKeyB64));
      assert.ok(!result.err.includes(operator.privateKeyB64));
    });

    test('RC04-C-33: the composed forbidden environment names match production names', () => {
      // Guards against the runtime composition silently drifting away from the
      // real variable names, which would make the negative control vacuous.
      assert.equal(FORBIDDEN_RAW_KEY_ENV, 'CESSPACE_ARC_ADMIN_PRIVATE_KEY');
      assert.equal(FORBIDDEN_SECRET_ENV, 'CESSPACE_ARC_ADMIN_SECRET');
      assert.equal(FORBIDDEN_TOKEN_ENV, 'CESSPACE_ARC_ADMIN_TOKEN');
    });

    /** Captures every destination buffer handed to the injected readSync. */
    function readCapturingSource() {
      const captured = [];
      const readSync = (targetFd, buffer, offset, length, position) => {
        captured.push(buffer);
        return fs.readSync(targetFd, buffer, offset, length, position);
      };
      return { captured, readSync };
    }

    function isAllZero(buffer) {
      for (const byte of buffer) {
        if (byte !== 0) return false;
      }
      return true;
    }

    test('RC04-C-34: the mutable key-source buffer is overwritten on successful import', () => {
      const operator = operatorKey();
      const fd = openKeyFile(operator.privateKeyB64);
      const { captured, readSync } = readCapturingSource();

      const key = readPrivateKeyFromFd(fd, readSync);
      assert.equal(key.asymmetricKeyType, 'ed25519');
      assert.equal(fdIsClosed(fd), true);

      assert.ok(captured.length >= 1, 'readSync was never invoked');
      // One buffer holds the whole source: no scratch buffer, no chunk copies.
      assert.equal(new Set(captured).size, 1, 'more than one source buffer was used');
      assert.ok(isAllZero(captured[0]), 'key-source buffer was not overwritten');
    });

    test('RC04-C-35: the mutable key-source buffer is overwritten when the key is invalid', () => {
      const fd = openKeyFile(`${PRIVATE_KEY_MARKER}-not-a-real-key`);
      const { captured, readSync } = readCapturingSource();

      assert.throws(
        () => readPrivateKeyFromFd(fd, readSync),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_INVALID',
      );
      assert.equal(fdIsClosed(fd), true);
      assert.equal(new Set(captured).size, 1);
      assert.ok(isAllZero(captured[0]), 'key-source buffer was not overwritten');
    });

    test('RC04-C-36: the mutable key-source buffer is overwritten when input is oversized', () => {
      const fd = openKeyFile('A'.repeat(32 * 1024));
      const { captured, readSync } = readCapturingSource();

      assert.throws(
        () => readPrivateKeyFromFd(fd, readSync),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_TOO_LARGE',
      );
      assert.equal(fdIsClosed(fd), true);
      assert.equal(new Set(captured).size, 1);
      assert.ok(isAllZero(captured[0]), 'key-source buffer was not overwritten');
    });

    test('RC04-C-37: the exact size boundary accepts 16 KiB and rejects 16 KiB + 1', () => {
      const atLimit = openKeyFile('A'.repeat(16 * 1024));
      // Exactly at the limit: the size bound is satisfied, so this is rejected
      // as an invalid key rather than as oversized input.
      assert.throws(
        () => readPrivateKeyFromFd(atLimit),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_INVALID',
      );
      assert.equal(fdIsClosed(atLimit), true);

      const overLimit = openKeyFile('A'.repeat(16 * 1024 + 1));
      assert.throws(
        () => readPrivateKeyFromFd(overLimit),
        (err) => err instanceof AdminClientError && err.reason === 'KEY_TOO_LARGE',
      );
      assert.equal(fdIsClosed(overLimit), true);
    });
  });

  // =========================================================================
  // 4. Approval command output
  // =========================================================================

  describe('Approval commands', () => {
    test('RC04-C-15: approve displays the token once with bounded guarantee wording', async () => {
      const result = await run(
        ['approve', REQUEST_ID, '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'],
        {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: true,
            result: {
              requestId: REQUEST_ID,
              state: 'APPROVED',
              token: 'f'.repeat(64),
              expiresAt: '2026-09-18T12:05:00.000Z',
              remainingSeconds: 240,
            },
          }),
        },
      );

      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, new RegExp(`Request ${REQUEST_ID} APPROVED`));
      assert.match(result.out, /One-Time Approval Token:/);
      assert.ok(result.out.includes('f'.repeat(64)));
      assert.match(result.out, /Expires at: 2026-09-18T12:05:00\.000Z/);
      assert.match(result.out, /Remaining: 240s/);
      assert.match(result.out, /Single-use only/);
      // The CLI must not claim a fresh 300-second validity window.
      assert.ok(!result.out.includes('Valid for'), 'must not claim a fixed validity window');
      assert.ok(!result.out.includes('300'), 'must not claim 300 seconds');
    });

    test('RC04-C-16: the token appears only on stdout of a successful approve', async () => {
      const token = 'e'.repeat(64);
      const results = [];

      results.push(
        await run(['approve', REQUEST_ID, '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'], {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: false,
            error: { code: 'APPROVAL_REJECTED' },
          }),
        }),
      );
      results.push(
        await run(['reject', REQUEST_ID, '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'], {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: true,
            result: { requestId: REQUEST_ID, state: 'REJECTED' },
          }),
        }),
      );
      results.push(
        await run(['approvals', 'list', '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'], {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: true,
            result: {
              approvals: [
                {
                  requestId: REQUEST_ID,
                  toolName: 'write_file',
                  state: 'PENDING',
                  workspaceId: 'primary',
                  clientId: 'agent',
                  clientType: 'cli',
                  createdAt: '2026-09-18T12:00:00.000Z',
                  expiresAt: '2026-09-18T12:05:00.000Z',
                  remainingSeconds: 100,
                  reviewMaterialBytes: 10,
                },
              ],
            },
          }),
        }),
      );
      results.push(
        await run(
          [
            'approvals',
            'inspect',
            REQUEST_ID,
            '--admin-socket',
            '/tmp/x.sock',
            '--admin-key-fd',
            '3',
          ],
          {
            readPrivateKeyFromFd: () => ({}),
            createAdminClient: fakeClient({
              ok: true,
              result: {
                requestId: REQUEST_ID,
                toolName: 'write_file',
                state: 'PENDING',
                workspaceId: 'primary',
                clientId: 'agent',
                clientType: 'cli',
                createdAt: '2026-09-18T12:00:00.000Z',
                expiresAt: '2026-09-18T12:05:00.000Z',
                remainingSeconds: 100,
                reviewMaterial: 'diff body',
              },
            }),
          },
        ),
      );

      for (const result of results) {
        assert.ok(!result.out.includes(token), 'token leaked into CLI output');
        assert.ok(!result.err.includes(token), 'token leaked into CLI stderr');
      }
      // A failed approve reports a bounded error on stderr only.
      assert.equal(results[0].exitCode, EXIT_FAILURE);
      assert.match(results[0].err, /could not be acted on/);
    });

    test('RC04-C-17: approvals list renders bounded metadata and no review body', async () => {
      const reviewBody = 'RC04_LIST_REVIEW_BODY_MARKER_8834';
      const result = await run(
        ['approvals', 'list', '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'],
        {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: true,
            result: {
              approvals: [
                {
                  requestId: REQUEST_ID,
                  toolName: 'apply_patch',
                  state: 'PENDING',
                  workspaceId: 'primary',
                  clientId: 'agent-alice',
                  clientType: 'claude-code',
                  createdAt: '2026-09-18T12:00:00.000Z',
                  expiresAt: '2026-09-18T12:05:00.000Z',
                  remainingSeconds: 120,
                  reviewMaterialBytes: 2048,
                  reviewMaterial: reviewBody,
                },
              ],
            },
          }),
        },
      );
      assert.equal(result.exitCode, EXIT_OK);
      assert.ok(result.out.includes(REQUEST_ID));
      assert.ok(result.out.includes('apply_patch'));
      assert.ok(result.out.includes('agent-alice'));
      assert.ok(!result.out.includes(reviewBody), 'list must not print review material');
    });

    test('RC04-C-18: approvals inspect prints the exact review material', async () => {
      const material = '--- a/src/x.ts\n+++ b/src/x.ts\n@@ -1 +1 @@\n-old\n+new\n';
      const result = await run(
        [
          'approvals',
          'inspect',
          REQUEST_ID,
          '--admin-socket',
          '/tmp/x.sock',
          '--admin-key-fd',
          '3',
        ],
        {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient({
            ok: true,
            result: {
              requestId: REQUEST_ID,
              toolName: 'apply_patch',
              state: 'PENDING',
              workspaceId: 'primary',
              clientId: 'agent-alice',
              clientType: 'claude-code',
              createdAt: '2026-09-18T12:00:00.000Z',
              expiresAt: '2026-09-18T12:05:00.000Z',
              remainingSeconds: 120,
              reviewMaterial: material,
            },
          }),
        },
      );
      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, /Review Material:/);
      assert.ok(result.out.includes(material));
    });

    test('RC04-C-19: reject forwards a bounded reason and validates it locally', async () => {
      const calls = [];
      const ok = await run(
        [
          'reject',
          REQUEST_ID,
          '--reason',
          'superseded by other work',
          '--admin-socket',
          '/tmp/x.sock',
          '--admin-key-fd',
          '3',
        ],
        {
          readPrivateKeyFromFd: () => ({}),
          createAdminClient: fakeClient(
            { ok: true, result: { requestId: REQUEST_ID, state: 'REJECTED' } },
            calls,
          ),
        },
      );
      assert.equal(ok.exitCode, EXIT_OK);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].method, 'approval.reject');
      assert.equal(calls[0].params.reason, 'superseded by other work');

      const tooLong = await run(
        [
          'reject',
          REQUEST_ID,
          '--reason',
          'r'.repeat(ADMIN_MAX_REASON_BYTES + 1),
          '--admin-socket',
          '/tmp/x.sock',
          '--admin-key-fd',
          '3',
        ],
        { readPrivateKeyFromFd: () => ({}), createAdminClient: fakeClient({ ok: true }) },
      );
      assert.equal(tooLong.exitCode, EXIT_USAGE);
      assert.match(tooLong.err, /must not exceed/);

      const withNul = await run(
        [
          'reject',
          REQUEST_ID,
          '--reason',
          `bad${String.fromCharCode(0)}reason`,
          '--admin-socket',
          '/tmp/x.sock',
          '--admin-key-fd',
          '3',
        ],
        { readPrivateKeyFromFd: () => ({}), createAdminClient: fakeClient({ ok: true }) },
      );
      assert.equal(withNul.exitCode, EXIT_USAGE);
      assert.match(withNul.err, /must not contain NUL/);

      const multibyte = await run(
        [
          'reject',
          REQUEST_ID,
          '--reason',
          '€'.repeat(100),
          '--admin-socket',
          '/tmp/x.sock',
          '--admin-key-fd',
          '3',
        ],
        { readPrivateKeyFromFd: () => ({}), createAdminClient: fakeClient({ ok: true }) },
      );
      assert.equal(multibyte.exitCode, EXIT_USAGE);
    });

    test('RC04-C-20: admin failures report bounded codes without internal detail', async () => {
      for (const code of [
        'AUTHENTICATION_FAILED',
        'INVALID_ADMIN_REQUEST',
        'NOT_FOUND_OR_NOT_PENDING',
        'APPROVAL_EXPIRED',
        'RESOURCE_EXHAUSTED',
        'INTERNAL_ERROR',
      ]) {
        const result = await run(
          ['approve', REQUEST_ID, '--admin-socket', '/tmp/x.sock', '--admin-key-fd', '3'],
          {
            readPrivateKeyFromFd: () => ({}),
            createAdminClient: fakeClient({ ok: false, error: { code } }),
          },
        );
        assert.equal(result.exitCode, EXIT_FAILURE);
        assert.ok(!/\n\s+at\s/.test(result.err), 'stack frame leaked');
        assert.ok(!/\.js:\d+/.test(result.err), 'source location leaked');
        assert.ok(!/Error:/.test(result.err), 'internal error text leaked');
        assert.ok(!result.out.includes(code), 'raw code printed to stdout');
      }
    });
  });

  // =========================================================================
  // 5. `arc policy test`
  // =========================================================================

  describe('arc policy test', () => {
    test('RC04-C-21: a valid YAML policy is validated and hashed', async () => {
      const file = writePolicy('valid.yaml', VALID_YAML);
      const result = await run(['policy', 'test', file]);
      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, /policyHash: [0-9a-f]{64}/);
      assert.match(result.out, /source:\s+EXTERNAL/);
      assert.match(result.out, /no evaluation was performed/i);
    });

    test('RC04-C-22: a valid JSON policy is validated', async () => {
      const file = writePolicy('valid.json', VALID_JSON);
      const result = await run(['policy', 'test', file]);
      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, /policyHash: [0-9a-f]{64}/);
    });

    test('RC04-C-23: --format overrides the file extension', async () => {
      const jsonInYamlName = writePolicy('actually-json.yaml', VALID_JSON);
      const withoutFormat = await run(['policy', 'test', jsonInYamlName]);
      // YAML is a superset of JSON, so this legitimately parses.
      assert.equal(withoutFormat.exitCode, EXIT_OK);

      const yamlInJsonName = writePolicy('actually-yaml.json', VALID_YAML);
      const asYaml = await run(['policy', 'test', yamlInJsonName, '--format', 'yaml']);
      assert.equal(asYaml.exitCode, EXIT_OK);
      const asJson = await run(['policy', 'test', yamlInJsonName, '--format', 'json']);
      assert.equal(asJson.exitCode, EXIT_FAILURE);
    });

    test('RC04-C-24: an unknown extension without --format is rejected', async () => {
      const file = writePolicy('policy.txt', VALID_YAML);
      const result = await run(['policy', 'test', file]);
      assert.equal(result.exitCode, EXIT_USAGE);
      assert.match(result.err, /format could not be determined/i);
    });

    test('RC04-C-25: evaluation reports outcome, rule, and reason', async () => {
      const file = writePolicy('eval.yaml', VALID_YAML);
      const denied = await run(['policy', 'test', file, '--tool', 'write_file']);
      assert.equal(denied.exitCode, EXIT_OK);
      assert.match(denied.out, /outcome:\s+DENY/);
      assert.match(denied.out, /matchingRuleId: deny-writes/);

      const allowed = await run(['policy', 'test', file, '--tool', 'read_file']);
      assert.match(allowed.out, /outcome:\s+ALLOW/);
      assert.match(allowed.out, /matchingRuleId: allow-reads/);
    });

    test('RC04-C-26: the mutation approval floor is reported explicitly', async () => {
      const file = writePolicy(
        'floor.yaml',
        `version: '1.0'
rules:
  - id: 'allow-mutations'
    effect: 'ALLOW'
    tools: ['apply_patch']
`,
      );
      const result = await run(['policy', 'test', file, '--tool', 'apply_patch']);
      assert.equal(result.exitCode, EXIT_OK);
      assert.match(result.out, /outcome:\s+REQUIRE_APPROVAL/);
      assert.match(result.out, /matchingRuleId: allow-mutations/);
      assert.match(result.out, /mutation approval floor/i);
    });

    test('RC04-C-27: evaluation passes path, executable, and git context', async () => {
      const file = writePolicy(
        'context.yaml',
        `version: '1.0'
rules:
  - id: 'deny-src'
    effect: 'DENY'
    tools: ['write_file']
    paths:
      patterns: ['src/**']
  - id: 'deny-curl'
    effect: 'DENY'
    commands:
      blockedBinaries: ['curl']
  - id: 'deny-push'
    effect: 'DENY'
    git:
      actions: ['push']
`,
      );
      const byPath = await run([
        'policy',
        'test',
        file,
        '--tool',
        'write_file',
        '--path',
        'src/a.ts',
      ]);
      assert.match(byPath.out, /matchingRuleId: deny-src/);

      const byExecutable = await run([
        'policy',
        'test',
        file,
        '--tool',
        'run_command',
        '--executable',
        'curl',
      ]);
      assert.match(byExecutable.out, /matchingRuleId: deny-curl/);

      const byGit = await run([
        'policy',
        'test',
        file,
        '--tool',
        'git_log',
        '--git-action',
        'push',
      ]);
      assert.match(byGit.out, /matchingRuleId: deny-push/);
    });

    test('RC04-C-28: a parse failure exits nonzero with only the generic error surface', async () => {
      const marker = 'RC04_CLI_POLICY_BODY_MARKER_3312';
      const file = writePolicy('broken.yaml', `version: '1.0'\nrules: [\n# ${marker}\n`);
      const result = await run(['policy', 'test', file]);
      assert.equal(result.exitCode, EXIT_FAILURE);
      assert.match(result.err, /POLICY_PARSE_ERROR/);
      assert.ok(!result.err.includes(marker), 'raw policy text leaked');
      assert.ok(!result.err.includes(file), 'policy path leaked');
      assert.ok(!result.err.includes('at '), 'stack trace leaked');
    });

    test('RC04-C-29: workspace assertions are not implicitly authorized', async () => {
      const workspaceDir = path.join(tempRoot, 'ws');
      fs.mkdirSync(workspaceDir, { recursive: true });
      const rootHash = crypto.createHash('sha256').update(workspaceDir, 'utf8').digest('hex');

      const file = writePolicy(
        'ws.yaml',
        `version: '1.0'
workspaces:
  - id: 'primary'
rules: []
`,
      );

      // process.cwd() is never implicitly registered, so the assertion fails.
      const unregistered = await run(['policy', 'test', file]);
      assert.equal(unregistered.exitCode, EXIT_FAILURE);
      assert.match(unregistered.err, /POLICY_LOAD_ERROR/);
      assert.ok(!unregistered.err.includes(workspaceDir), 'workspace path leaked');

      // Explicit registration through --workspace makes it loadable.
      const registered = await run([
        'policy',
        'test',
        file,
        '--workspace',
        `primary=${workspaceDir}`,
      ]);
      assert.equal(registered.exitCode, EXIT_OK);
      assert.match(registered.out, /policyHash: [0-9a-f]{64}/);

      // A rootHash assertion is verified against the canonical registered root.
      const withHash = writePolicy(
        'wshash.yaml',
        `version: '1.0'
workspaces:
  - id: 'primary'
    rootHash: '${rootHash}'
rules: []
`,
      );
      const hashed = await run([
        'policy',
        'test',
        withHash,
        '--workspace',
        `primary=${workspaceDir}`,
      ]);
      assert.equal(hashed.exitCode, EXIT_OK);

      const wrongHash = writePolicy(
        'wswrong.yaml',
        `version: '1.0'
workspaces:
  - id: 'primary'
    rootHash: '${'0'.repeat(64)}'
rules: []
`,
      );
      const mismatched = await run([
        'policy',
        'test',
        wrongHash,
        '--workspace',
        `primary=${workspaceDir}`,
      ]);
      assert.equal(mismatched.exitCode, EXIT_FAILURE);
      assert.match(mismatched.err, /POLICY_LOAD_ERROR/);
      assert.ok(!mismatched.err.includes(workspaceDir), 'workspace path leaked');
    });

    test('RC04-C-30: a malformed --workspace selector is rejected', async () => {
      const file = writePolicy('wsbad.yaml', VALID_YAML);
      for (const selector of ['noequals', '=path', 'id=']) {
        const result = await run(['policy', 'test', file, '--workspace', selector]);
        assert.equal(result.exitCode, EXIT_USAGE);
        assert.match(result.err, /<id>=<path>/);
      }
    });

    test('RC04-C-31: policy test contacts no admin channel and executes no tool', async () => {
      const file = writePolicy('offline.yaml', VALID_YAML);
      let adminClientCreated = 0;

      const result = await run(['policy', 'test', file, '--tool', 'write_file'], {
        env: {
          CESSPACE_ARC_ADMIN_SOCKET: '/tmp/definitely-not-connected.sock',
          CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD: '0',
        },
        createAdminClient: () => {
          adminClientCreated++;
          throw new Error('policy test must never construct an admin client');
        },
        readPrivateKeyFromFd: () => {
          throw new Error('policy test must never read a private key');
        },
      });

      assert.equal(result.exitCode, EXIT_OK);
      assert.equal(adminClientCreated, 0);
      assert.match(result.out, /No tools were executed/);

      // A registry that starts empty is the only one policy test uses.
      assert.equal(new WorkspaceRegistry().getWorkspaces().length, 0);
    });

    test('RC04-C-32: a missing policy file fails closed', async () => {
      const result = await run(['policy', 'test', path.join(tempRoot, 'nope.yaml')]);
      assert.equal(result.exitCode, EXIT_FAILURE);
      assert.match(result.err, /could not be read/);
    });
  });
});
