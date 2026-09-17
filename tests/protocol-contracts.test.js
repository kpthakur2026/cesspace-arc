import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

describe('CesSpace ARC — Architecture & Contract Verifications (RC-00)', () => {
  test('Policy precedence invariant: DENY must strictly override APPROVAL and ALLOW', () => {
    // Numerically in our design: DENY = 0, REQUIRE_APPROVAL = 1, ALLOW = 2
    // Lower numerical value represents higher priority.
    const DENY = 0;
    const REQUIRE_APPROVAL = 1;
    const ALLOW = 2;

    assert.ok(DENY < REQUIRE_APPROVAL, 'DENY must have higher precedence than REQUIRE_APPROVAL');
    assert.ok(REQUIRE_APPROVAL < ALLOW, 'REQUIRE_APPROVAL must have higher precedence than ALLOW');
    assert.ok(DENY < ALLOW, 'DENY must have higher precedence than ALLOW');

    // Precedence resolution function simulation
    function resolvePrecedence(outcomes) {
      return Math.min(...outcomes);
    }

    assert.equal(resolvePrecedence([ALLOW, REQUIRE_APPROVAL, DENY]), DENY);
    assert.equal(resolvePrecedence([ALLOW, DENY]), DENY);
    assert.equal(resolvePrecedence([ALLOW, REQUIRE_APPROVAL]), REQUIRE_APPROVAL);
    assert.equal(resolvePrecedence([ALLOW]), ALLOW);
  });

  test('Workspace package integrity and naming conventions', () => {
    const packages = [
      'protocol',
      'policy',
      'audit',
      'auth',
      'filesystem',
      'git',
      'terminal',
      'processes',
    ];

    for (const pkg of packages) {
      const pkgJsonPath = path.resolve('packages', pkg, 'package.json');
      assert.ok(fs.existsSync(pkgJsonPath), `Missing package.json for package: ${pkg}`);
      const content = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      assert.equal(content.name, `@cesspace-arc/${pkg}`);
      assert.equal(content.license, 'Apache-2.0');
    }

    const apps = ['mcp-server', 'cli'];
    for (const app of apps) {
      const appJsonPath = path.resolve('apps', app, 'package.json');
      assert.ok(fs.existsSync(appJsonPath), `Missing package.json for app: ${app}`);
      const content = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
      assert.equal(content.name, `@cesspace-arc/${app}`);
      assert.equal(content.license, 'Apache-2.0');
    }
  });

  test('Default Deny fallback invariant', () => {
    // If no matching rule exists, the fallback MUST be DENY
    function evaluateWithDefaultDeny(rules, operation) {
      const matched = rules.filter(r => r.matches(operation));
      if (matched.length === 0) {
        return 'DENY'; // Default Deny
      }
      if (matched.some(r => r.effect === 'DENY')) return 'DENY';
      if (matched.some(r => r.effect === 'REQUIRE_APPROVAL')) return 'REQUIRE_APPROVAL';
      return 'ALLOW';
    }

    const rules = [];
    assert.equal(evaluateWithDefaultDeny(rules, 'unknown_tool'), 'DENY');
  });

  test('Canonical Path Jail Logic Simulation', () => {
    const authorizedRoot = '/home/user/workspace/repo';

    function isPathContained(root, candidate) {
      const normalizedRoot = path.normalize(root);
      const normalizedCandidate = path.normalize(candidate);
      return (
        normalizedCandidate === normalizedRoot ||
        normalizedCandidate.startsWith(normalizedRoot + path.sep)
      );
    }

    // Positive cases
    assert.ok(isPathContained(authorizedRoot, '/home/user/workspace/repo/src/index.ts'));
    assert.ok(isPathContained(authorizedRoot, '/home/user/workspace/repo'));

    // Negative cases (path traversal attempts)
    assert.strictEqual(isPathContained(authorizedRoot, '/home/user/workspace/repo/../../etc/passwd'), false);
    assert.strictEqual(isPathContained(authorizedRoot, '/home/user/.ssh/id_rsa'), false);
    assert.strictEqual(isPathContained(authorizedRoot, '/home/user/workspace/repo-other'), false);
  });
});
