/**
 * CesSpace ARC — RC-05 Final Acceptance Negative Controls Suite
 *
 * Standalone acceptance catalog and verification harness for all 79 frozen RC-05
 * negative controls defined in docs/architecture/rc05-scope-acceptance.md §34.
 *
 * Requirements:
 * - Exactly 79 IDs: contiguous RC05-NEG-01 through RC05-NEG-79
 * - No missing IDs, no duplicates, no fabricated IDs (no RC05-NEG-80)
 * - Closed authoritative manifest mapping every NEG ID to executable test evidence
 * - Validates presence and non-skipped/non-todo execution in underlying suites
 * - Executes underlying RC-05 security test suites and asserts clean exit code
 * - Fails on any underlying test failure or disabled test
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

/**
 * Closed authoritative manifest of all 79 frozen RC-05 negative controls.
 * Every entry maps to its authoritative executable regression test suite.
 */
export const RC05_NEGATIVE_CONTROLS = Object.freeze([
  {
    id: 'RC05-NEG-01',
    description: 'Plain HTTP request to the remote port',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-02',
    description: 'Request to a non-configured path',
    suite: 'tests/rc05-streamable-gateway.test.js',
  },
  {
    id: 'RC05-NEG-03',
    description: 'Request to a legacy SSE endpoint',
    suite: 'tests/rc05-streamable-gateway.test.js',
  },
  {
    id: 'RC05-NEG-04',
    description: 'Unknown HTTP method',
    suite: 'tests/rc05-streamable-gateway.test.js',
  },
  {
    id: 'RC05-NEG-05',
    description: 'Wildcard bind without opt-in flag',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-06',
    description: 'Stateless transport (sessionIdGenerator omitted)',
    suite: 'tests/rc05-streamable-gateway.test.js',
  },
  {
    id: 'RC05-NEG-07',
    description: 'TLS 1.2 handshake attempt',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-08',
    description: 'Connection with no client certificate',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-09',
    description: 'Client certificate from an unknown CA',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-10',
    description: 'Expired client certificate',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-11',
    description: 'Malformed certificate',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-12',
    description: 'Server cert/key mismatch at startup',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-13',
    description: 'Server certificate expired at startup',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-14',
    description: 'Server certificate SAN does not match hostname',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-15',
    description: 'Server certificate expires during runtime',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-16',
    description: 'Valid chain, but SPKI not pinned to any device',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-17',
    description: 'Pin rotated: old pin inside window, then after removal',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-18',
    description: 'Malformed pin configuration at startup',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-19',
    description: 'Two devices sharing one pin at startup',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-20',
    description: 'Device enrollment adding a 3rd active pin',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-21',
    description: 'Enrolling device beyond 256 global device limit',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-22',
    description: 'Enrollment request with display label > 64 bytes',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-23',
    description: 'Trust-store file is a symlink',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-24',
    description: 'Trust store is group/world writable',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-25',
    description: 'Trust store owned by wrong UID',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-26',
    description: 'Trust store file corrupted or exceeds 256 KiB',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-27',
    description: 'Atomic write failure during trust store update',
    suite: 'tests/rc05-device-trust-store.test.js',
  },
  {
    id: 'RC05-NEG-28',
    description: 'Client CA file is symlink or group/world writable',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-29',
    description: 'Unauthenticated/tokenless attempt to perform remote enrollment',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-30',
    description: 'POST /enroll/complete without client cert mTLS',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-31',
    description: 'POST /enroll/complete with no matching pending record',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-32',
    description: 'POST /enroll/complete with mismatched SPKI pin',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-33',
    description: 'POST /enroll/complete with incorrect one-time secret',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-34',
    description: 'Secret attempts exceed 3 failed tries on a challenge',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-35',
    description: 'POST /enroll/complete after 300 s monotonic expiry',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-36',
    description: 'Single-use enrollment secret replayed',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-37',
    description: 'Pending enrollment quota exceeded (16 global/4 operator)',
    suite: 'tests/rc05-enrollment-admin-ipc.test.js',
  },
  {
    id: 'RC05-NEG-38',
    description: 'Gateway with 0 devices: ordinary /mcp tool request',
    suite: 'tests/rc05-enrollment-bootstrap.test.js',
  },
  {
    id: 'RC05-NEG-39',
    description: 'Tokenless ordinary tool request to /mcp',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-40',
    description: 'Client-supplied Mcp-Session-Id on initial initialize',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-41',
    description: 'Tokenless initialize from unenrolled/revoked device',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-42',
    description: 'Request with valid Mcp-Session-Id but missing token',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-43',
    description: 'Request with valid token but wrong Mcp-Session-Id',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-44',
    description: 'Request with valid Mcp-Session-Id but wrong token',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-45',
    description: 'Valid session token presented from different device/SPKI',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-46',
    description: 'Malformed session token (> 128 bytes or non-hex)',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-47',
    description: 'Tokenless initialize flood exceeding active cap (64)',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-48',
    description: 'Request supplies clientId / clientType / deviceId in JSON-RPC parameters',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-49',
    description: 'Request supplies sessionId in JSON-RPC parameters',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-50',
    description: '_arcApproval object carries actor fields',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-51',
    description: 'Actor context reaching executionPayloadHash',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-52',
    description:
      'Client re-authenticates to new session B and attempts to redeem approval from session A',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-53',
    description: 'Layer A: Connection flood exceeding 60 conn/min',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-54',
    description: 'Layer A: Concurrent handshakes exceeding 64 global bound',
    suite: 'tests/rc05-tls-admission.test.js',
  },
  {
    id: 'RC05-NEG-55',
    description: 'Layer B: Pre-session HTTP flood exceeding 120 req/min',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-56',
    description: 'Layer C: Authenticated flood exceeding 300 req/min',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-57',
    description: 'Source-IP churn attack against rate limiters',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-58',
    description: 'IPv4-mapped IPv6 address used to bypass IPv4 limiter',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-59',
    description: 'IPv6 rotation within /64 subnet to bypass limiter',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-60',
    description: 'Request body exceeding 4 MiB during chunked read',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-61',
    description: 'Slowloris attack (headers/body read exceeding 10 s)',
    suite: 'tests/rc05-resource-bounds.test.js',
  },
  {
    id: 'RC05-NEG-62',
    description: 'Unenrolled device authentication failure',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-63',
    description: 'Revoked device authentication failure pre-session',
    suite: 'tests/rc05-gateway-admission.test.js',
  },
  {
    id: 'RC05-NEG-64',
    description: 'Revoked device presenting existing session token',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-65',
    description: 'Unauthenticated remote request that would be ALLOWed',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-66',
    description: 'Unauthenticated remote request targeting mutation tool',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-67',
    description: 'Authenticated session hitting a DENY policy',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-68',
    description: 'Session token used as an approval token',
    suite: 'tests/rc05-remote-actor-pipeline.test.js',
  },
  {
    id: 'RC05-NEG-69',
    description: 'Approval token used as a session token in header',
    suite: 'tests/rc05-session-lifecycle.test.js',
  },
  {
    id: 'RC05-NEG-70',
    description: 'Restart: sessions cleared, approvals invalidated',
    suite: 'tests/rc05-streamable-gateway.test.js',
  },
  {
    id: 'RC05-NEG-71',
    description: 'Audit log inspection after session bootstrap',
    suite: 'tests/rc05-gateway-audit.test.js',
  },
  {
    id: 'RC05-NEG-72',
    description: 'Audit log inspection after enrollment completion',
    suite: 'tests/rc05-gateway-audit.test.js',
  },
  {
    id: 'RC05-NEG-73',
    description: 'Audit log inspection for private keys / cert material',
    suite: 'tests/rc05-gateway-audit.test.js',
  },
  {
    id: 'RC05-NEG-74',
    description: 'Remote client attempts approve action via MCP',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
  {
    id: 'RC05-NEG-75',
    description: 'Remote client attempts reject action via MCP',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
  {
    id: 'RC05-NEG-76',
    description: 'Remote client attempts approval list/inspect via MCP',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
  {
    id: 'RC05-NEG-77',
    description: 'Remote client attempts device enroll/revoke via MCP',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
  {
    id: 'RC05-NEG-78',
    description: 'Remote client attempts policy modification via MCP',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
  {
    id: 'RC05-NEG-79',
    description: 'Remote client attempts session revocation for another',
    suite: 'tests/rc05-remote-admin-isolation.test.js',
  },
]);

describe('CesSpace ARC — RC-05 All 79 Negative Controls Acceptance Suite', () => {
  test('Completeness: exactly 79 contiguous controls RC05-NEG-01..79 without gaps or duplicates', () => {
    assert.equal(RC05_NEGATIVE_CONTROLS.length, 79, 'must contain exactly 79 negative controls');

    const seenIds = new Set();
    for (let i = 1; i <= 79; i += 1) {
      const expectedId = `RC05-NEG-${String(i).padStart(2, '0')}`;
      const control = RC05_NEGATIVE_CONTROLS[i - 1];

      assert.equal(control.id, expectedId, `Index ${i - 1} must have id ${expectedId}`);
      assert.ok(control.description, `${expectedId} must have a description`);
      assert.ok(control.suite, `${expectedId} must specify an authoritative suite`);

      assert.equal(seenIds.has(control.id), false, `Duplicate ID detected: ${control.id}`);
      seenIds.add(control.id);
    }

    assert.equal(seenIds.size, 79, 'must have exactly 79 distinct IDs');
    assert.equal(seenIds.has('RC05-NEG-80'), false, 'must NOT have fabricated RC05-NEG-80');
    assert.equal(seenIds.has('RC05-NEG-00'), false, 'must NOT have fabricated RC05-NEG-00');
  });

  test('Authoritative mapping: every control maps to an existing suite containing the test', () => {
    const cwd = process.cwd();
    for (const control of RC05_NEGATIVE_CONTROLS) {
      const fullPath = path.resolve(cwd, control.suite);
      assert.equal(fs.existsSync(fullPath), true, `Suite file missing: ${control.suite}`);

      const content = fs.readFileSync(fullPath, 'utf8');
      assert.ok(
        content.includes(control.id),
        `Authoritative suite ${control.suite} does not contain test ID ${control.id}`,
      );
    }
  });

  test('No disabled or deferred tests across all mapped negative control suites', () => {
    const cwd = process.cwd();
    const uniqueSuites = [...new Set(RC05_NEGATIVE_CONTROLS.map((c) => c.suite))];
    const forbiddenPatterns = [
      'test' + '.skip',
      'test' + '.todo',
      'describe' + '.skip',
      'it' + '.skip',
      '.' + 'only',
    ];

    for (const suite of uniqueSuites) {
      const fullPath = path.resolve(cwd, suite);
      const content = fs.readFileSync(fullPath, 'utf8');

      for (const pattern of forbiddenPatterns) {
        assert.equal(
          content.includes(pattern),
          false,
          `Forbidden marker '${pattern}' found in ${suite}`,
        );
      }
    }
  });

  describe('Execution integrity: all mapped test suites exit with code 0', () => {
    const uniqueSuites = [...new Set(RC05_NEGATIVE_CONTROLS.map((c) => c.suite))];

    for (const suite of uniqueSuites) {
      test(`Executes suite ${suite}`, { timeout: 120_000 }, () => {
        const env = { ...process.env };
        delete env.NODE_TEST_CONTEXT;
        delete env.NODE_TEST_WORKER_ID;

        const result = execFileSync(process.execPath, ['--test', suite], {
          cwd: process.cwd(),
          env,
          stdio: 'pipe',
          encoding: 'utf8',
        });

        assert.ok(
          result.includes('✔') || result.includes('ok ') || result.includes('pass'),
          `Suite ${suite} did not report any passing tests`,
        );
        assert.equal(
          result.includes('✖') && !result.includes('fail 0'),
          false,
          `Suite ${suite} reported test failures`,
        );
      });
    }
  });
});
