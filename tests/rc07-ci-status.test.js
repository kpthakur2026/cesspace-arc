/**
 * CesSpace ARC — RC-07 Task 6 Authoritative Test Suite
 *
 * Covers:
 * - Negative Controls: RC07-NEG-047 through RC07-NEG-053
 * - Positive Acceptance Flows: RC07-FLOW-13
 * - Invariant Regressions: Tool count (24), zero network egress, GITHUB_TOKEN isolation,
 *   read-only non-execution, built-in policy ALLOW, external policy DENY override, 64 KiB cap.
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import child_process, { execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

import {
  createArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  TOOL_SCHEMAS,
} from '../apps/mcp-server/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';
import { DeclarativePolicyEngine, WorkspaceRegistry } from '../packages/policy/dist/index.js';

function makeSafeActor() {
  return {
    clientId: 'test-client-task6',
    clientType: 'agent',
    sessionId: 'sess-task6-1',
    deviceId: 'dev-task6-1',
    authenticated: true,
  };
}

function runGit(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Alice Engineer',
      GIT_AUTHOR_EMAIL: 'alice@example.com',
      GIT_COMMITTER_NAME: 'Alice Engineer',
      GIT_COMMITTER_EMAIL: 'alice@example.com',
    },
  }).trim();
}

function parseResponse(res) {
  assert.ok(res.content && res.content.length > 0, 'Response must have content array');
  return JSON.parse(res.content[0].text);
}

describe('CesSpace ARC — RC-07 Task 6: arc_ci_status Test Suite', () => {
  let tempRoot;
  let workspaceDir;
  let server;
  const safeActor = makeSafeActor();

  before(async () => {
    tempRoot = mkdtempSync(join(tmpdir(), 'arc-task6-test-'));
    workspaceDir = join(tempRoot, 'workspace');
    mkdirSync(workspaceDir, { recursive: true });

    // Initialize clean git repository
    runGit(['init', '-b', 'main'], workspaceDir);
    runGit(['config', 'user.name', 'Alice Engineer'], workspaceDir);
    runGit(['config', 'user.email', 'alice@example.com'], workspaceDir);

    writeFileSync(join(workspaceDir, 'README.md'), '# ARC Test Workspace\n');
    runGit(['add', 'README.md'], workspaceDir);
    runGit(['commit', '-m', 'Initial commit'], workspaceDir);

    server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws-task6', path: workspaceDir }],
      defaultWorkspaceId: 'ws-task6',
    });
  });

  after(() => {
    try {
      rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // =========================================================================
  // 1. Negative Controls (RC07-NEG-047 .. RC07-NEG-053)
  // =========================================================================

  describe('RC-07 Task 6: Negative Controls (RC07-NEG-047..053)', () => {
    test('RC07-NEG-047: arc_ci_status initiates zero outbound network requests', async () => {
      // Set up workflow in workspace
      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });
      writeFileSync(
        join(workflowsDir, 'build.yml'),
        'name: Build\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n',
      );

      // Track network calls
      let networkCallsCount = 0;
      const originalHttpRequest = http.request;
      const originalHttpsRequest = https.request;
      const originalNetConnect = net.connect;
      const originalTlsConnect = tls.connect;
      const originalFetch = globalThis.fetch;

      http.request = (..._args) => {
        networkCallsCount++;
        throw new Error('Unexpected http.request call in zero-network arc_ci_status');
      };
      https.request = (..._args) => {
        networkCallsCount++;
        throw new Error('Unexpected https.request call in zero-network arc_ci_status');
      };
      net.connect = (..._args) => {
        networkCallsCount++;
        throw new Error('Unexpected net.connect call in zero-network arc_ci_status');
      };
      tls.connect = (..._args) => {
        networkCallsCount++;
        throw new Error('Unexpected tls.connect call in zero-network arc_ci_status');
      };
      globalThis.fetch = (..._args) => {
        networkCallsCount++;
        throw new Error('Unexpected fetch call in zero-network arc_ci_status');
      };

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        const data = parseResponse(res);
        assert.equal(data.localSimulationMode, true);
        assert.equal(data.remoteQueryDeferred, true);
        assert.equal(networkCallsCount, 0, 'Must make zero outbound network requests');
      } finally {
        http.request = originalHttpRequest;
        https.request = originalHttpsRequest;
        net.connect = originalNetConnect;
        tls.connect = originalTlsConnect;
        globalThis.fetch = originalFetch;
      }
    });

    test('RC07-NEG-048: GITHUB_TOKEN and GH_TOKEN environment variables are isolated and not reported', async () => {
      const originalGithubToken = process.env.GITHUB_TOKEN;
      const originalGhToken = process.env.GH_TOKEN;

      process.env.GITHUB_TOKEN = 'ghp_secretTokenForGitHubActions12345';
      process.env.GH_TOKEN = 'gho_secretTokenForGitHubCli67890';

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        const serialized = JSON.stringify(res);

        assert.ok(
          !serialized.includes('ghp_secretTokenForGitHubActions12345'),
          'GITHUB_TOKEN must not leak',
        );
        assert.ok(
          !serialized.includes('gho_secretTokenForGitHubCli67890'),
          'GH_TOKEN must not leak',
        );

        const data = parseResponse(res);
        assert.equal(data.localSimulationMode, true);
        assert.equal(data.remoteQueryDeferred, true);
      } finally {
        if (originalGithubToken !== undefined) {
          process.env.GITHUB_TOKEN = originalGithubToken;
        } else {
          delete process.env.GITHUB_TOKEN;
        }
        if (originalGhToken !== undefined) {
          process.env.GH_TOKEN = originalGhToken;
        } else {
          delete process.env.GH_TOKEN;
        }
      }
    });

    test('RC07-NEG-049: workflow path outside .github/workflows/ rejected with PATH_OUTSIDE_WORKSPACE', async () => {
      const fsSubsystem = new FilesystemSubsystem();

      // 1. Directory traversal attempt
      await assert.rejects(
        async () => {
          await fsSubsystem.validateWorkflowPath(workspaceDir, '../../outside.yml');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // 2. Absolute escape attempt
      await assert.rejects(
        async () => {
          await fsSubsystem.validateWorkflowPath(workspaceDir, '/etc/passwd');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // 3. Path inside workspace but outside .github/workflows/
      await assert.rejects(
        async () => {
          await fsSubsystem.validateWorkflowPath(workspaceDir, 'src/workflow.yml');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // 4. Symlink inside .github/workflows pointing outside workspace (unconditional on POSIX)
      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });
      const outsideWorkflow = join(tempRoot, 'outside-secret.yml');
      writeFileSync(outsideWorkflow, 'name: Outside\non: push\njobs: {}\n');

      const escapingSymlink = join(workflowsDir, 'escaping.yml');
      symlinkSync(outsideWorkflow, escapingSymlink);

      try {
        await assert.rejects(
          async () => {
            await fsSubsystem.listWorkflowFiles(workspaceDir);
          },
          (err) => {
            assert.ok(err instanceof ArcError);
            assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
            return true;
          },
        );

        await assert.rejects(
          async () => {
            await fsSubsystem.validateWorkflowPath(workspaceDir, '.github/workflows/escaping.yml');
          },
          (err) => {
            assert.ok(err instanceof ArcError);
            assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
            return true;
          },
        );

        const toolRes = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        assert.equal(toolRes.isError, true);
        const parsed = JSON.parse(toolRes.content[0].text);
        assert.equal(parsed.code, 'PATH_OUTSIDE_WORKSPACE');
      } finally {
        rmSync(escapingSymlink, { force: true });
        rmSync(outsideWorkflow, { force: true });
      }

      // 5. MANDATORY REAL REGRESSION:
      // Symlink whose target remains inside workspace but leaves .github/workflows/
      // workspace/
      //   .github/
      //     workflows/
      //       leak.yml -> ../../config/internal.yml
      //   config/
      //     internal.yml
      const configDir = join(workspaceDir, 'config');
      mkdirSync(configDir, { recursive: true });
      const internalYmlPath = join(configDir, 'internal.yml');
      const internalYmlContent =
        'name: SHOULD_NOT_BE_VISIBLE\non: push\njobs:\n  secret_job:\n    runs-on: ubuntu-latest\n';
      writeFileSync(internalYmlPath, internalYmlContent);

      const leakSymlink = join(workflowsDir, 'leak.yml');
      symlinkSync('../../config/internal.yml', leakSymlink);

      // Directly prove corrected validateWorkflowPath fails with PATH_OUTSIDE_WORKSPACE
      await assert.rejects(
        async () => {
          await fsSubsystem.validateWorkflowPath(workspaceDir, '.github/workflows/leak.yml');
        },
        (err) => {
          assert.ok(err instanceof ArcError);
          assert.equal(err.code, 'PATH_OUTSIDE_WORKSPACE');
          return true;
        },
      );

      // Track network calls and process spawns during arc_ci_status invocation
      let networkCalls = 0;
      const originalHttp = http.request;
      const originalHttps = https.request;
      const originalNet = net.connect;
      const originalTls = tls.connect;
      const originalFetch = globalThis.fetch;

      http.request = (..._args) => {
        networkCalls++;
        throw new Error('Network call forbidden in zero-network arc_ci_status');
      };
      https.request = (..._args) => {
        networkCalls++;
        throw new Error('Network call forbidden in zero-network arc_ci_status');
      };
      net.connect = (..._args) => {
        networkCalls++;
        throw new Error('Network call forbidden in zero-network arc_ci_status');
      };
      tls.connect = (..._args) => {
        networkCalls++;
        throw new Error('Network call forbidden in zero-network arc_ci_status');
      };
      globalThis.fetch = (..._args) => {
        networkCalls++;
        throw new Error('Network call forbidden in zero-network arc_ci_status');
      };

      let spawnCalls = 0;
      const originalSpawn = child_process.spawn;
      const originalExecFile = child_process.execFile;
      child_process.spawn = (...args) => {
        spawnCalls++;
        return originalSpawn.apply(child_process, args);
      };
      child_process.execFile = (...args) => {
        spawnCalls++;
        return originalExecFile.apply(child_process, args);
      };

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });

        // 1. Invocation fails closed
        assert.equal(res.isError, true, 'Invocation must fail closed');

        // 2. Error code is PATH_OUTSIDE_WORKSPACE
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'PATH_OUTSIDE_WORKSPACE');

        // 3. Complete raw MCP wire response checks
        const rawWire = JSON.stringify(res);
        assert.equal(
          rawWire.includes('SHOULD_NOT_BE_VISIBLE'),
          false,
          '"SHOULD_NOT_BE_VISIBLE" must be absent from wire response',
        );
        assert.equal(
          rawWire.includes('secret_job'),
          false,
          '"secret_job" must be absent from wire response',
        );
        assert.equal(
          rawWire.includes('workflowsFound'),
          false,
          'outside target content must not be returned as workflowsFound',
        );

        // 4. Zero network calls occurred
        assert.equal(networkCalls, 0, 'No network call occurred');

        // 5. Zero processes spawned
        assert.equal(spawnCalls, 0, 'No process was spawned');
      } finally {
        http.request = originalHttp;
        https.request = originalHttps;
        net.connect = originalNet;
        tls.connect = originalTls;
        globalThis.fetch = originalFetch;
        child_process.spawn = originalSpawn;
        child_process.execFile = originalExecFile;

        rmSync(leakSymlink, { force: true });
        rmSync(internalYmlPath, { force: true });
        rmSync(configDir, { recursive: true, force: true });
      }
    });

    test('RC07-NEG-050: malformed YAML workflow fails closed with sanitized INTERNAL_ERROR and no crash', async () => {
      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });
      const brokenYmlPath = join(workflowsDir, 'broken.yml');
      writeFileSync(brokenYmlPath, 'name: [unclosed list\njobs: {');

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        assert.ok(res.isError, 'Malformed YAML must result in an error');
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'INTERNAL_ERROR');
        assert.equal(parsed.message, 'CI workflow YAML could not be parsed.');
        // Verify no stack trace or absolute host path leaked
        assert.ok(!res.content[0].text.includes(tempRoot), 'Must not leak host paths in error');
        assert.ok(!res.content[0].text.includes('at '), 'Must not leak stack traces in error');
      } finally {
        rmSync(brokenYmlPath, { force: true });
      }
    });

    test('RC07-NEG-051: clean worktree never fabricates localVerificationMatch: true', async () => {
      // Ensure worktree is completely clean
      runGit(['reset', '--hard', 'HEAD'], workspaceDir);
      runGit(['clean', '-fd'], workspaceDir);

      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });
      writeFileSync(
        join(workflowsDir, 'ci.yml'),
        'name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n',
      );
      runGit(['add', '.github/workflows/ci.yml'], workspaceDir);
      runGit(['commit', '-m', 'Add CI workflow'], workspaceDir);

      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-task6',
      });
      assert.ok(!res.isError);
      const data = parseResponse(res);

      assert.equal(data.workingTreeClean, true, 'Working tree should be clean');
      assert.equal(
        data.localVerificationMatch,
        false,
        'Anti-fabrication: localVerificationMatch must be false',
      );
      assert.equal(data.localSimulationMode, true);
      assert.equal(data.remoteQueryDeferred, true);
      assert.equal(
        data.remoteNotice,
        'Remote CI status was not queried. RC-07 reports local simulation only.',
      );
    });

    test('RC07-NEG-052: workflow actions and commands are strictly inert and never executed locally', async () => {
      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });
      const markerPath = join(workspaceDir, 'malicious-marker.txt');
      if (existsSync(markerPath)) rmSync(markerPath, { force: true });

      const maliciousYml = `
name: Malicious Workflow
on: [push, pull_request]
jobs:
  exploit:
    runs-on: ubuntu-latest
    steps:
      - name: Create Marker
        run: echo "pwned" > "${markerPath}"
      - uses: actions/checkout@v4
`;
      writeFileSync(join(workflowsDir, 'malicious.yml'), maliciousYml);

      try {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        assert.ok(!res.isError);
        const data = parseResponse(res);

        // Marker file must NOT have been created
        assert.equal(existsSync(markerPath), false, 'Workflow script must NOT have executed');

        // Inert inspection data extracted truthfully
        const maliciousWf = data.workflowsFound.find((w) => w.name === 'Malicious Workflow');
        assert.ok(maliciousWf, 'Must inspect workflow as inert data');
        assert.equal(maliciousWf.jobCount, 1);
        assert.deepEqual(maliciousWf.triggers, ['pull_request', 'push']);
      } finally {
        rmSync(join(workflowsDir, 'malicious.yml'), { force: true });
        if (existsSync(markerPath)) rmSync(markerPath, { force: true });
      }
    });

    test('RC07-NEG-053: response size exceeding 64 KiB fails closed with PAYLOAD_TOO_LARGE', async () => {
      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });

      // Create many workflow files with large names to exceed 64 KiB serialized payload
      const createdFiles = [];
      try {
        for (let i = 0; i < 400; i++) {
          const fileName = `wf-${String(i).padStart(4, '0')}.yml`;
          const filePath = join(workflowsDir, fileName);
          const wfContent = `name: ${'Workflow_Name_Padding_'.repeat(8)}_${i}\non:\n  - push\n  - pull_request\n  - workflow_dispatch\njobs:\n  build:\n    runs-on: ubuntu-latest\n  test:\n    runs-on: ubuntu-latest\n`;
          writeFileSync(filePath, wfContent);
          createdFiles.push(filePath);
        }

        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
        });
        assert.ok(res.isError, 'Oversized response must fail closed');
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'PAYLOAD_TOO_LARGE');
        assert.ok(
          parsed.message.includes('exceeds maximum 64 KiB limit') ||
            parsed.message.includes('PAYLOAD_TOO_LARGE'),
        );
      } finally {
        for (const file of createdFiles) {
          rmSync(file, { force: true });
        }
      }
    });
  });

  // =========================================================================
  // 2. Positive Acceptance Flows (RC07-FLOW-13)
  // =========================================================================

  describe('RC-07 Task 6: Positive Acceptance Flows (RC07-FLOW-13)', () => {
    test('RC07-FLOW-13: Local CI simulation status with multiple workflows, triggers, and filtering', async () => {
      // Clean git state
      runGit(['reset', '--hard', 'HEAD'], workspaceDir);
      runGit(['clean', '-fd'], workspaceDir);

      const workflowsDir = join(workspaceDir, '.github', 'workflows');
      mkdirSync(workflowsDir, { recursive: true });

      // Workflow 1: standard CI with multiple triggers
      writeFileSync(
        join(workflowsDir, 'ci.yml'),
        `name: Continuous Integration
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  lint:
    runs-on: ubuntu-latest
  test:
    runs-on: ubuntu-latest
`,
      );

      // Workflow 2: Release workflow with single trigger and string on
      writeFileSync(
        join(workflowsDir, 'release.yml'),
        `name: Production Release
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-latest
`,
      );

      // Commit workflows
      runGit(['add', '.github/workflows/'], workspaceDir);
      runGit(['commit', '-m', 'Add CI and release workflows'], workspaceDir);

      const expectedHeadSha = runGit(['rev-parse', 'HEAD'], workspaceDir);
      const expectedBranch = runGit(['branch', '--show-current'], workspaceDir);

      // 1. Query all workflows without filter
      const resAll = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-task6',
      });
      assert.ok(!resAll.isError);
      const dataAll = parseResponse(resAll);

      assert.equal(dataAll.localSimulationMode, true);
      assert.equal(dataAll.remoteQueryDeferred, true);
      assert.equal(
        dataAll.remoteNotice,
        'Remote CI status was not queried. RC-07 reports local simulation only.',
      );
      assert.equal(dataAll.localVerificationMatch, false);
      assert.equal(dataAll.localBranch, expectedBranch);
      assert.equal(dataAll.headSha, expectedHeadSha);
      assert.equal(dataAll.workingTreeClean, true);

      assert.equal(dataAll.workflowsFound.length, 2);

      const ciWf = dataAll.workflowsFound.find((w) => w.name === 'Continuous Integration');
      assert.ok(ciWf);
      assert.equal(ciWf.path, '.github/workflows/ci.yml');
      assert.equal(ciWf.jobCount, 2);
      assert.deepEqual(ciWf.triggers, ['pull_request', 'push']);

      const relWf = dataAll.workflowsFound.find((w) => w.name === 'Production Release');
      assert.ok(relWf);
      assert.equal(relWf.path, '.github/workflows/release.yml');
      assert.equal(relWf.jobCount, 1);
      assert.deepEqual(relWf.triggers, ['workflow_dispatch']);

      // 2. Query with workflowName filter
      const resFilter = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-task6',
        workflowName: 'Continuous Integration',
      });
      assert.ok(!resFilter.isError);
      const dataFilter = parseResponse(resFilter);
      assert.equal(dataFilter.workflowsFound.length, 1);
      assert.equal(dataFilter.workflowsFound[0].name, 'Continuous Integration');

      // 3. Query with non-matching workflowName
      const resNoMatch = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-task6',
        workflowName: 'NonExistentWorkflow',
      });
      assert.ok(!resNoMatch.isError);
      const dataNoMatch = parseResponse(resNoMatch);
      assert.equal(dataNoMatch.workflowsFound.length, 0);

      // 4. Dirty worktree truthfully reported
      writeFileSync(join(workspaceDir, 'uncommitted.txt'), 'dirty worktree state');
      const resDirty = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-task6',
      });
      assert.ok(!resDirty.isError);
      const dataDirty = parseResponse(resDirty);
      assert.equal(dataDirty.workingTreeClean, false);

      // Clean up dirty file
      rmSync(join(workspaceDir, 'uncommitted.txt'), { force: true });
    });

    test('RC07-FLOW-13b: Workspace without .github/workflows directory reports empty workflowsFound cleanly', async () => {
      // Temporary workspace without .github directory
      const emptyWsDir = join(tempRoot, 'empty-ws');
      mkdirSync(emptyWsDir, { recursive: true });
      runGit(['init', '-b', 'main'], emptyWsDir);
      runGit(['config', 'user.name', 'Alice Engineer'], emptyWsDir);
      runGit(['config', 'user.email', 'alice@example.com'], emptyWsDir);
      writeFileSync(join(emptyWsDir, 'README.md'), '# Empty\n');
      runGit(['add', 'README.md'], emptyWsDir);
      runGit(['commit', '-m', 'Init'], emptyWsDir);

      const emptyServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-empty', path: emptyWsDir }],
        defaultWorkspaceId: 'ws-empty',
      });

      const res = await emptyServer.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-empty',
      });
      assert.ok(!res.isError);
      const data = parseResponse(res);
      assert.deepEqual(data.workflowsFound, []);
      assert.equal(data.localSimulationMode, true);
      assert.equal(data.workingTreeClean, true);
    });
  });

  // =========================================================================
  // 3. Invariants, Discovery & Quality Regressions
  // =========================================================================

  describe('RC-07 Task 6: Invariants, Discovery & Quality Regressions', () => {
    test('Discovery: Production tool count is exactly 24 (including arc_ci_status)', () => {
      assert.equal(ALL_TOOL_DEFINITIONS.length, 24);
      const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);

      assert.ok(names.includes('arc_ci_status'), 'arc_ci_status must be advertised');
      assert.ok(names.includes('arc_test'));
      assert.ok(names.includes('arc_verify'));
      assert.ok(names.includes('arc_review_diff'));
      assert.ok(names.includes('arc_repo_status'));
      assert.ok(names.includes('arc_worktree_status'));

      // Task 7 tool remains absent
      assert.equal(
        names.includes('arc_stage_evidence'),
        false,
        'arc_stage_evidence must remain absent',
      );
    });

    test('Discovery: arc_ci_status is present in TOOL_SCHEMAS with strict validation', () => {
      assert.ok(TOOL_SCHEMAS.arc_ci_status !== undefined);
      // Valid input
      const valid = TOOL_SCHEMAS.arc_ci_status.safeParse({
        workflowName: 'CI',
        workspaceId: 'ws-1',
      });
      assert.equal(valid.success, true);

      // Unknown property rejected
      const invalid = TOOL_SCHEMAS.arc_ci_status.safeParse({
        workflowName: 'CI',
        path: '/etc/passwd',
      });
      assert.equal(invalid.success, false);
    });

    test('Policy: Built-in declarative policy evaluates arc_ci_status as ALLOW', async () => {
      const reg = new WorkspaceRegistry();
      reg.registerWorkspace('ws-task6', workspaceDir);
      const engine = DeclarativePolicyEngine.builtIn(reg);

      const decision = await engine.evaluate({
        toolName: 'arc_ci_status',
        workspaceId: 'ws-task6',
      });

      assert.equal(decision.effect, 'ALLOW');
      assert.equal(decision.matchingRuleId, 'builtin-allow-rc07-read-only');
    });

    test('Policy: External declarative policy DENY rule overrides and refuses arc_ci_status', async () => {
      const reg = new WorkspaceRegistry();
      reg.registerWorkspace('ws-task6', workspaceDir);

      const denyPolicyYaml = `
version: "1.0"
workspaces:
  - id: ws-task6
rules:
  - id: deny-ci-status
    effect: DENY
    tools:
      - arc_ci_status
`;
      const engine = DeclarativePolicyEngine.fromExternalText(reg, denyPolicyYaml.trim(), 'yaml');
      const decision = await engine.evaluate({
        toolName: 'arc_ci_status',
        workspaceId: 'ws-task6',
      });

      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, 'deny-ci-status');
    });

    test('Security: Request with arbitrary parameters rejected with INVALID_REQUEST_SCHEMA', async () => {
      const disallowedParams = [
        { path: '../workflows/ci.yml' },
        { workflowPath: 'ci.yml' },
        { repository: 'owner/repo' },
        { token: 'secret-token' },
        { githubToken: 'secret-token' },
        { run: 'bash' },
        { command: 'sh' },
        { execute: true },
      ];

      for (const extra of disallowedParams) {
        const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
          workspaceId: 'ws-task6',
          ...extra,
        });
        assert.ok(res.isError, `Parameter ${Object.keys(extra)[0]} must be rejected`);
        const parsed = JSON.parse(res.content[0].text);
        assert.equal(parsed.code, 'INVALID_REQUEST_SCHEMA');
      }
    });

    test('Security: Unregistered workspaceId rejected with WORKSPACE_UNREGISTERED', async () => {
      const res = await server.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'unregistered-workspace-id',
      });
      assert.ok(res.isError);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'WORKSPACE_UNREGISTERED');
    });

    test('Security: Non-git directory rejected with GIT_REPOSITORY_NOT_FOUND', async () => {
      const nonGitDir = join(tempRoot, 'non-git-dir');
      mkdirSync(nonGitDir, { recursive: true });

      const nonGitServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws-nongit', path: nonGitDir }],
        defaultWorkspaceId: 'ws-nongit',
      });

      const res = await nonGitServer.executeAuthenticatedToolCall(safeActor, 'arc_ci_status', {
        workspaceId: 'ws-nongit',
      });
      assert.ok(res.isError);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.code, 'GIT_REPOSITORY_NOT_FOUND');
    });
  });
});
