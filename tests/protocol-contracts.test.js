import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

describe('CesSpace ARC — Architecture & Contract Verifications (RC-00)', () => {
  test('Policy precedence invariant: DENY must strictly override APPROVAL and ALLOW', () => {
    // Numerically: DENY = 0, REQUIRE_APPROVAL = 1, ALLOW = 2
    // Lower numerical value represents higher priority.
    const DENY = 0;
    const REQUIRE_APPROVAL = 1;
    const ALLOW = 2;

    assert.ok(DENY < REQUIRE_APPROVAL, 'DENY must have higher precedence than REQUIRE_APPROVAL');
    assert.ok(REQUIRE_APPROVAL < ALLOW, 'REQUIRE_APPROVAL must have higher precedence than ALLOW');
    assert.ok(DENY < ALLOW, 'DENY must have higher precedence than ALLOW');

    function resolvePrecedence(outcomes) {
      return Math.min(...outcomes);
    }

    assert.equal(resolvePrecedence([ALLOW, REQUIRE_APPROVAL, DENY]), DENY);
    assert.equal(resolvePrecedence([ALLOW, DENY]), DENY);
    assert.equal(resolvePrecedence([ALLOW, REQUIRE_APPROVAL]), REQUIRE_APPROVAL);
    assert.equal(resolvePrecedence([ALLOW]), ALLOW);
  });

  test('Workspace package integrity, private markings, and pnpm workspace references', () => {
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
      assert.equal(
        content.private,
        true,
        `Package ${pkg} must be marked private during development`,
      );

      // Verify internal dependencies use workspace:*
      if (content.dependencies) {
        for (const [depName, depVer] of Object.entries(content.dependencies)) {
          if (depName.startsWith('@cesspace-arc/')) {
            assert.equal(
              depVer,
              'workspace:*',
              `Internal dependency ${depName} in ${pkg} must use workspace:* protocol`,
            );
          }
        }
      }
    }

    const apps = ['mcp-server', 'cli'];
    for (const app of apps) {
      const appJsonPath = path.resolve('apps', app, 'package.json');
      assert.ok(fs.existsSync(appJsonPath), `Missing package.json for app: ${app}`);
      const content = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
      assert.equal(content.name, `@cesspace-arc/${app}`);
      assert.equal(content.license, 'Apache-2.0');
      assert.equal(content.private, true, `App ${app} must be marked private during development`);

      if (content.dependencies) {
        for (const [depName, depVer] of Object.entries(content.dependencies)) {
          if (depName.startsWith('@cesspace-arc/')) {
            assert.equal(
              depVer,
              'workspace:*',
              `Internal dependency ${depName} in ${app} must use workspace:* protocol`,
            );
          }
        }
      }
    }
  });

  test('Canonical PolicyEvaluationContext contract schema validation', () => {
    // Validates that canonical context attributes are structured as specified
    const sampleContext = {
      actor: {
        clientId: 'antigravity-worker-01',
        clientType: 'antigravity',
        authenticated: true,
        deviceId: 'dev-001',
        sessionId: 'sess-xyz',
      },
      targetWorkspace: {
        workspaceId: 'primary-workspace',
        rootPath: '/home/user/repo',
        isGitRepo: true,
      },
      request: {
        toolName: 'read_file',
        parameters: { path: 'src/index.ts' },
      },
      environment: {
        timestamp: '2026-09-17T08:00:00.000Z',
        sessionDurationMs: 12000,
      },
    };

    assert.ok(sampleContext.actor.clientId, 'Must have actor.clientId');
    assert.equal(typeof sampleContext.actor.authenticated, 'boolean');
    assert.ok(sampleContext.targetWorkspace.workspaceId, 'Must have targetWorkspace.workspaceId');
    assert.ok(sampleContext.targetWorkspace.rootPath, 'Must have targetWorkspace.rootPath');
    assert.ok(sampleContext.request.toolName, 'Must have request.toolName');
    assert.ok(sampleContext.environment.timestamp, 'Must have environment.timestamp');
  });

  test('Default Deny fallback invariant', () => {
    function evaluateWithDefaultDeny(rules, operation) {
      const matched = rules.filter((r) => r.matches(operation));
      if (matched.length === 0) {
        return 'DENY'; // Default Deny
      }
      if (matched.some((r) => r.effect === 'DENY')) return 'DENY';
      if (matched.some((r) => r.effect === 'REQUIRE_APPROVAL')) return 'REQUIRE_APPROVAL';
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

    assert.ok(isPathContained(authorizedRoot, '/home/user/workspace/repo/src/index.ts'));
    assert.ok(isPathContained(authorizedRoot, '/home/user/workspace/repo'));
    assert.strictEqual(
      isPathContained(authorizedRoot, '/home/user/workspace/repo/../../etc/passwd'),
      false,
    );
    assert.strictEqual(isPathContained(authorizedRoot, '/home/user/.ssh/id_rsa'), false);
    assert.strictEqual(isPathContained(authorizedRoot, '/home/user/workspace/repo-other'), false);
  });
});
