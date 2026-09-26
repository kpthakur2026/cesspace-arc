import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

import {
  ArcMcpServer,
  RC01_TOOL_DEFINITIONS,
  RC02_TOOL_DEFINITIONS,
  RC03_TOOL_DEFINITIONS,
  ALL_TOOL_DEFINITIONS,
  TOOL_SCHEMAS,
  sanitizePathForAudit,
  sanitizeMutationAuditParameters,
  sanitizePreValidationMutationParameters,
} from '../apps/mcp-server/dist/index.js';
import {
  WorkspaceRegistry,
  SecurityKernel,
  RC03_MUTATION_TOOLS,
} from '../packages/policy/dist/index.js';
import { PolicyOutcome } from '../packages/protocol/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';

describe('CesSpace ARC — RC-03 MCP Policy & Audit Integration', () => {
  let tempDir;
  let workspaceDir;
  let server;
  let auditLogger;
  let processRegistry;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc03-mcp-'));
    workspaceDir = path.join(tempDir, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Initialize fixture git repo
    execFileSync('git', ['init', '-b', 'main'], { cwd: workspaceDir });
    execFileSync('git', ['config', 'user.name', 'P Thakur'], { cwd: workspaceDir });
    execFileSync(
      'git',
      ['config', 'user.email', '321108211+kpthakur2026@users.noreply.github.com'],
      {
        cwd: workspaceDir,
      },
    );
    fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# RC-03 MCP Audit Test Fixture\n');
    execFileSync('git', ['add', '.'], { cwd: workspaceDir });
    execFileSync('git', ['commit', '-m', 'chore: rc-03 mcp audit test fixture'], {
      cwd: workspaceDir,
    });

    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('test-ws', workspaceDir);

    auditLogger = new AuditLogger();
    processRegistry = new ProcessRegistry();
    const kernel = new SecurityKernel(registry, processRegistry);
    const filesystem = new FilesystemSubsystem();
    const git = new GitSubsystem();
    const terminal = new ControlledProcessRunner(processRegistry);

    server = new ArcMcpServer(
      registry,
      kernel,
      auditLogger,
      filesystem,
      git,
      {
        defaultWorkspaceId: 'test-ws',
      },
      terminal,
      processRegistry,
    );
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  // ==========================================================================
  // SECTION 1: TOOL REGISTRATION — 18 TOOLS IN LIST_TOOLS
  // ==========================================================================

  describe('Section 1: Tool Registration', () => {
    test('RC03-REG-01: total tool definitions count is 18 (9 RC01 + 4 RC02 + 5 RC03)', () => {
      const total =
        RC01_TOOL_DEFINITIONS.length + RC02_TOOL_DEFINITIONS.length + RC03_TOOL_DEFINITIONS.length;
      assert.equal(total, 18, `Expected 18 tools total, got ${total}`);
    });

    test('RC03-REG-02: RC03_TOOL_DEFINITIONS contains exactly the 5 mutation tools', () => {
      const names = RC03_TOOL_DEFINITIONS.map((t) => t.name).sort();
      assert.deepEqual(names, [
        'apply_patch',
        'create_file',
        'delete_file',
        'move_file',
        'write_file',
      ]);
    });

    test('RC03-REG-03: RC01_TOOL_DEFINITIONS contains exactly 9 read-only tools', () => {
      assert.equal(RC01_TOOL_DEFINITIONS.length, 9);
    });

    test('RC03-REG-04: RC02_TOOL_DEFINITIONS contains exactly 4 execution tools', () => {
      assert.equal(RC02_TOOL_DEFINITIONS.length, 4);
    });

    test('RC03-REG-05: all 5 mutation tool names present in TOOL_SCHEMAS', () => {
      for (const name of RC03_MUTATION_TOOLS) {
        assert.ok(
          TOOL_SCHEMAS[name] !== undefined,
          `TOOL_SCHEMAS missing entry for mutation tool '${name}'`,
        );
      }
    });

    test('RC03-REG-06: RC03_MUTATION_TOOLS export is the canonical 5-element list', () => {
      const sorted = [...RC03_MUTATION_TOOLS].sort();
      assert.deepEqual(sorted, [
        'apply_patch',
        'create_file',
        'delete_file',
        'move_file',
        'write_file',
      ]);
    });
  });

  // ==========================================================================
  // SECTION 2: SCHEMA ADMISSION GATES — MUTATION TOOLS REQUIRE EXACT INPUT
  // ==========================================================================

  describe('Section 2: Schema Admission Gates', () => {
    test('RC03-SCHEMA-01: create_file with missing content fails schema admission', async () => {
      const res = await server.dispatchToolCall('create_file', { path: 'foo.txt' });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-02: create_file with missing path fails schema admission', async () => {
      const res = await server.dispatchToolCall('create_file', { content: 'hello' });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-03: write_file without expectedHash fails schema admission', async () => {
      const res = await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'new',
        overwrite: true,
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-04: write_file without overwrite:true fails schema admission', async () => {
      const res = await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'new',
        expectedHash: 'a'.repeat(64),
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-05: write_file with invalid expectedHash (short) fails schema admission', async () => {
      const res = await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'new',
        expectedHash: 'abc',
        overwrite: true,
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-06: delete_file without expectedHash fails schema admission', async () => {
      const res = await server.dispatchToolCall('delete_file', { path: 'README.md' });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-07: move_file without expectedSourceHash fails schema admission', async () => {
      const res = await server.dispatchToolCall('move_file', {
        sourcePath: 'src.txt',
        destinationPath: 'dst.txt',
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-08: apply_patch without patch field fails schema admission', async () => {
      const res = await server.dispatchToolCall('apply_patch', { dryRun: true });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-SCHEMA-09: apply_patch with empty patch fails schema admission', async () => {
      const res = await server.dispatchToolCall('apply_patch', { patch: '' });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
      assert.notEqual(body.code, 'APPROVAL_REQUIRED', 'Empty patch must not reach policy');
    });

    test('RC03-SCHEMA-09B: apply_patch with whitespace-only patch fails schema admission', async () => {
      const res = await server.dispatchToolCall('apply_patch', { patch: '   \n\t' });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
      assert.notEqual(
        body.code,
        'APPROVAL_REQUIRED',
        'Whitespace-only patch must not reach policy',
      );
    });

    test('RC03-SCHEMA-09C: valid patch whitespace structure is preserved unmodified', () => {
      const validPatch =
        '--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,1 @@\n-# RC-03 MCP Audit Test Fixture\n+   leading space line\n';
      const parsed = TOOL_SCHEMAS.apply_patch.safeParse({ patch: validPatch });
      assert.ok(parsed.success, 'Valid patch with whitespace must pass schema');
      assert.equal(
        parsed.data.patch,
        validPatch,
        'Patch content must not be trimmed or transformed',
      );
    });

    test('RC03-SCHEMA-10: create_file with extra unknown property fails strict schema', async () => {
      const res = await server.dispatchToolCall('create_file', {
        path: 'test.txt',
        content: 'hello',
        unknownField: true,
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-01: approvalToken field is rejected by schema', async () => {
      const res = await server.dispatchToolCall('create_file', {
        path: 'test.txt',
        content: 'hello',
        approvalToken: 'bypass-token-123',
      });
      assert.ok(res.isError);
      assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-02: approved boolean is rejected by schema', async () => {
      const res = await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'new',
        expectedHash: 'a'.repeat(64),
        overwrite: true,
        approved: true,
      });
      assert.ok(res.isError);
      assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-03: bypassApproval is rejected by schema', async () => {
      const res = await server.dispatchToolCall('delete_file', {
        path: 'README.md',
        expectedHash: 'b'.repeat(64),
        bypassApproval: true,
      });
      assert.ok(res.isError);
      assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-04: autoApprove is rejected by schema', async () => {
      const res = await server.dispatchToolCall('apply_patch', {
        patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n',
        autoApprove: true,
      });
      assert.ok(res.isError);
      assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-05: force flag is rejected by schema', async () => {
      const res = await server.dispatchToolCall('delete_file', {
        path: 'README.md',
        expectedHash: 'c'.repeat(64),
        force: true,
      });
      assert.ok(res.isError);
      assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
    });

    test('RC03-BACKDOOR-06: admin and sudo flags are rejected by schema', async () => {
      for (const flag of ['admin', 'sudo']) {
        const res = await server.dispatchToolCall('move_file', {
          sourcePath: 'README.md',
          destinationPath: 'README2.md',
          expectedSourceHash: 'd'.repeat(64),
          [flag]: true,
        });
        assert.ok(res.isError);
        assert.equal(JSON.parse(res.content[0].text).code, 'INVALID_REQUEST_SCHEMA');
      }
    });

    test('RC03-BACKDOOR-07: table-driven coverage pass of all backdoor fields across all mutation tools', async () => {
      const backdoorFields = [
        'approvalToken',
        'approved',
        'bypassApproval',
        'autoApprove',
        'force',
        'admin',
        'sudo',
      ];
      const validMutationInputs = {
        create_file: { path: 'test.txt', content: 'hello' },
        write_file: {
          path: 'README.md',
          content: 'new',
          expectedHash: 'e'.repeat(64),
          overwrite: true,
        },
        delete_file: { path: 'README.md', expectedHash: 'f'.repeat(64) },
        move_file: {
          sourcePath: 'README.md',
          destinationPath: 'README2.md',
          expectedSourceHash: '0'.repeat(64),
        },
        apply_patch: {
          patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n',
        },
      };

      for (const [tool, baseParams] of Object.entries(validMutationInputs)) {
        for (const backdoor of backdoorFields) {
          const res = await server.dispatchToolCall(tool, {
            ...baseParams,
            [backdoor]: 'malicious_override_attempt',
          });
          assert.ok(res.isError, `Expected isError for ${tool} with ${backdoor}`);
          const body = JSON.parse(res.content[0].text);
          assert.equal(
            body.code,
            'INVALID_REQUEST_SCHEMA',
            `Expected INVALID_REQUEST_SCHEMA for ${tool} with ${backdoor}, got ${body.code}`,
          );
        }
      }
    });
  });

  // ==========================================================================
  // SECTION 3: POLICY GATE — REQUIRE_APPROVAL, NOT POLICY_DENIED
  // ==========================================================================

  describe('Section 3: Policy — APPROVAL_REQUIRED (not POLICY_DENIED)', () => {
    test('RC03-POLICY-01: create_file valid params returns APPROVAL_REQUIRED error code', async () => {
      const res = await server.dispatchToolCall('create_file', {
        path: 'newfile.txt',
        content: 'hello world',
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED', `Expected APPROVAL_REQUIRED, got: ${body.code}`);
    });

    test('RC03-POLICY-02: write_file valid params returns APPROVAL_REQUIRED error code', async () => {
      const res = await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'updated content',
        expectedHash: 'a'.repeat(64),
        overwrite: true,
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED', `Expected APPROVAL_REQUIRED, got: ${body.code}`);
    });

    test('RC03-POLICY-03: delete_file valid params returns APPROVAL_REQUIRED error code', async () => {
      const res = await server.dispatchToolCall('delete_file', {
        path: 'README.md',
        expectedHash: 'b'.repeat(64),
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED', `Expected APPROVAL_REQUIRED, got: ${body.code}`);
    });

    test('RC03-POLICY-04: move_file valid params returns APPROVAL_REQUIRED error code', async () => {
      const res = await server.dispatchToolCall('move_file', {
        sourcePath: 'README.md',
        destinationPath: 'README-moved.md',
        expectedSourceHash: 'c'.repeat(64),
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED', `Expected APPROVAL_REQUIRED, got: ${body.code}`);
    });

    test('RC03-POLICY-05: apply_patch valid params returns APPROVAL_REQUIRED error code', async () => {
      const res = await server.dispatchToolCall('apply_patch', {
        patch: '--- a/foo.txt\n+++ b/foo.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n',
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'APPROVAL_REQUIRED', `Expected APPROVAL_REQUIRED, got: ${body.code}`);
    });

    test('RC03-POLICY-06: APPROVAL_REQUIRED error is NOT POLICY_DENIED for create_file', async () => {
      const res = await server.dispatchToolCall('create_file', {
        path: 'newfile.txt',
        content: 'hello world',
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.notEqual(
        body.code,
        'POLICY_DENIED',
        'APPROVAL_REQUIRED must not collapse to POLICY_DENIED',
      );
    });

    test('RC03-POLICY-07: APPROVAL_REQUIRED error is NOT POLICY_DENIED for apply_patch', async () => {
      const res = await server.dispatchToolCall('apply_patch', {
        patch: '--- a/x.txt\n+++ b/x.txt\n@@ -1 +1 @@\n-x\n+y\n',
      });
      assert.ok(res.isError, 'Expected isError=true');
      const body = JSON.parse(res.content[0].text);
      assert.notEqual(
        body.code,
        'POLICY_DENIED',
        'APPROVAL_REQUIRED must not collapse to POLICY_DENIED',
      );
    });
  });

  // ==========================================================================
  // SECTION 4: AUDIT INTEGRITY — MUTATION TOOLS PRODUCE AUDIT RECORDS
  // ==========================================================================

  describe('Section 4: Audit Integrity', () => {
    test('RC03-AUDIT-01: create_file invocation produces an audit record', async () => {
      const countBefore = auditLogger.getRecords().length;
      await server.dispatchToolCall('create_file', { path: 'audit-test.txt', content: 'hello' });
      const countAfter = auditLogger.getRecords().length;
      assert.ok(
        countAfter > countBefore,
        'Expected at least one new audit record after create_file',
      );
    });

    test('RC03-AUDIT-02: create_file audit record has decision REQUIRE_APPROVAL', async () => {
      await server.dispatchToolCall('create_file', { path: 'audit-test2.txt', content: 'data' });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      assert.equal(
        last.policy.decision,
        'REQUIRE_APPROVAL',
        `Expected REQUIRE_APPROVAL audit decision, got: ${last.policy.decision}`,
      );
    });

    test('RC03-AUDIT-03: create_file audit record has error.code APPROVAL_REQUIRED', async () => {
      await server.dispatchToolCall('create_file', { path: 'audit-test3.txt', content: 'data' });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      assert.ok(last.error, 'Expected error field in audit record');
      assert.equal(last.error.code, 'APPROVAL_REQUIRED');
    });

    test('RC03-AUDIT-04: apply_patch audit record has decision REQUIRE_APPROVAL', async () => {
      await server.dispatchToolCall('apply_patch', {
        patch: '--- a/r.txt\n+++ b/r.txt\n@@ -1 +1 @@\n-old\n+new\n',
      });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      assert.equal(last.policy.decision, 'REQUIRE_APPROVAL');
    });

    test('RC03-AUDIT-05: audit record for create_file has ruleId require-approval-file-mutation', async () => {
      await server.dispatchToolCall('create_file', { path: 'rule-test.txt', content: 'x' });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      assert.equal(last.policy.ruleId, 'require-approval-file-mutation');
    });

    test('RC03-AUDIT-06: audit chain integrity verified after multiple mutation invocations', async () => {
      await server.dispatchToolCall('create_file', { path: 'chain1.txt', content: 'a' });
      await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'b',
        expectedHash: 'd'.repeat(64),
        overwrite: true,
      });
      await server.dispatchToolCall('delete_file', {
        path: 'README.md',
        expectedHash: 'e'.repeat(64),
      });
      const integrityValid = await auditLogger.verifyIntegrity();
      assert.ok(
        integrityValid,
        'Audit chain integrity must be maintained across mutation invocations',
      );
    });

    test('RC03-AUDIT-07: audit parametersRedacted for create_file does NOT contain raw content', async () => {
      const sensitiveContent = 'top-secret-payload-12345';
      await server.dispatchToolCall('create_file', {
        path: 'sensitive.txt',
        content: sensitiveContent,
      });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      const serialized = JSON.stringify(last.invocation.parametersRedacted);
      assert.ok(
        !serialized.includes(sensitiveContent),
        'Raw content must NOT appear in audit parametersRedacted',
      );
    });

    test('RC03-AUDIT-08: audit parametersRedacted for create_file contains contentBytes (not raw content)', async () => {
      await server.dispatchToolCall('create_file', {
        path: 'bytes-check.txt',
        content: 'hello world',
      });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      const params = last.invocation.parametersRedacted;
      assert.ok(
        'contentBytes' in params,
        'Expected contentBytes in audit parametersRedacted for create_file',
      );
      assert.equal(typeof params.contentBytes, 'number');
    });

    test('RC03-AUDIT-09: audit parametersRedacted for apply_patch does NOT contain raw patch content', async () => {
      const secretPatch = '--- a/secret.txt\n+++ b/secret.txt\n@@ -1 +1 @@\n-hidden\n+visible\n';
      await server.dispatchToolCall('apply_patch', { patch: secretPatch });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      const serialized = JSON.stringify(last.invocation.parametersRedacted);
      assert.ok(!serialized.includes('hidden'), 'Raw patch lines must NOT appear in audit');
      assert.ok(!serialized.includes('visible'), 'Raw patch lines must NOT appear in audit');
    });

    test('RC03-AUDIT-10: audit parametersRedacted for apply_patch contains patchBytes', async () => {
      await server.dispatchToolCall('apply_patch', {
        patch: '--- a/x.txt\n+++ b/x.txt\n@@ -1 +1 @@\n-old\n+new\n',
      });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      const params = last.invocation.parametersRedacted;
      assert.ok(
        'patchBytes' in params,
        'Expected patchBytes in audit parametersRedacted for apply_patch',
      );
      assert.equal(typeof params.patchBytes, 'number');
    });

    test('RC03-AUDIT-11: audit parametersRedacted for write_file does NOT contain raw content', async () => {
      const sensitive = 'my-secret-write-content';
      await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: sensitive,
        expectedHash: 'f'.repeat(64),
        overwrite: true,
      });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      const serialized = JSON.stringify(last.invocation.parametersRedacted);
      assert.ok(!serialized.includes(sensitive), 'Raw write content must NOT appear in audit');
    });

    test('RC03-AUDIT-12: audit record status is DENIED for mutation tools', async () => {
      await server.dispatchToolCall('create_file', { path: 'status-check.txt', content: 'z' });
      const records = auditLogger.getRecords();
      const last = records[records.length - 1];
      assert.equal(last.execution.status, 'DENIED');
    });
  });

  // ==========================================================================
  // SECTION 5: FAIL-CLOSED INVARIANTS — NO FILESYSTEM MUTATION EXECUTES
  // ==========================================================================

  describe('Section 5: Fail-Closed — Filesystem Mutation Never Executes', () => {
    test('RC03-FAILCLOSED-01: create_file does NOT create any file on disk', async () => {
      const targetPath = path.join(workspaceDir, 'should-not-exist.txt');
      assert.ok(!fs.existsSync(targetPath), 'Precondition: file must not exist');
      await server.dispatchToolCall('create_file', {
        path: 'should-not-exist.txt',
        content: 'boom',
      });
      assert.ok(!fs.existsSync(targetPath), 'create_file must NOT create files in RC-03');
    });

    test('RC03-FAILCLOSED-02: delete_file does NOT delete any file on disk', async () => {
      const targetPath = path.join(workspaceDir, 'README.md');
      assert.ok(fs.existsSync(targetPath), 'Precondition: README.md must exist');
      await server.dispatchToolCall('delete_file', {
        path: 'README.md',
        expectedHash: '0'.repeat(64),
      });
      assert.ok(fs.existsSync(targetPath), 'delete_file must NOT delete files in RC-03');
    });

    test('RC03-FAILCLOSED-03: write_file does NOT overwrite any file on disk', async () => {
      const targetPath = path.join(workspaceDir, 'README.md');
      const originalContent = fs.readFileSync(targetPath, 'utf8');
      await server.dispatchToolCall('write_file', {
        path: 'README.md',
        content: 'OVERWRITTEN CONTENT',
        expectedHash: '1'.repeat(64),
        overwrite: true,
      });
      const currentContent = fs.readFileSync(targetPath, 'utf8');
      assert.equal(currentContent, originalContent, 'write_file must NOT modify files in RC-03');
    });

    test('RC03-FAILCLOSED-04: move_file does NOT move any file on disk', async () => {
      const sourcePath = path.join(workspaceDir, 'README.md');
      const destPath = path.join(workspaceDir, 'README-moved.md');
      assert.ok(fs.existsSync(sourcePath), 'Precondition: source must exist');
      assert.ok(!fs.existsSync(destPath), 'Precondition: destination must not exist');
      await server.dispatchToolCall('move_file', {
        sourcePath: 'README.md',
        destinationPath: 'README-moved.md',
        expectedSourceHash: '2'.repeat(64),
      });
      assert.ok(fs.existsSync(sourcePath), 'move_file must NOT move source in RC-03');
      assert.ok(!fs.existsSync(destPath), 'move_file must NOT create destination in RC-03');
    });

    test('RC03-FAILCLOSED-05: apply_patch does NOT modify any file on disk', async () => {
      const targetPath = path.join(workspaceDir, 'README.md');
      const originalContent = fs.readFileSync(targetPath, 'utf8');
      await server.dispatchToolCall('apply_patch', {
        patch:
          '--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,1 @@\n-# RC-03 MCP Audit Test Fixture\n+# PATCHED CONTENT\n',
      });
      const currentContent = fs.readFileSync(targetPath, 'utf8');
      assert.equal(currentContent, originalContent, 'apply_patch must NOT modify files in RC-03');
    });
  });

  // ==========================================================================
  // SECTION 6: sanitizePathForAudit — UNIT TESTS
  // ==========================================================================

  describe('Section 6: sanitizePathForAudit', () => {
    test('RC03-PATH-01: safe relative path passes through unchanged', () => {
      const result = sanitizePathForAudit('src/index.ts');
      assert.equal(result, 'src/index.ts');
    });

    test('RC03-PATH-02: absolute Unix path is rejected with pathOmitted:true', () => {
      const result = sanitizePathForAudit('/etc/passwd');
      assert.equal(typeof result, 'object');
      assert.ok(result.pathOmitted, 'Expected pathOmitted:true for absolute path');
    });

    test('RC03-PATH-03: path traversal attempt (../../etc) is rejected', () => {
      const result = sanitizePathForAudit('../../etc/passwd');
      assert.equal(typeof result, 'object');
      assert.ok(result.pathOmitted, 'Expected pathOmitted:true for traversal attempt');
    });

    test('RC03-PATH-04: Windows absolute path is rejected', () => {
      const result = sanitizePathForAudit('C:\\Windows\\System32');
      assert.equal(typeof result, 'object');
      assert.ok(result.pathOmitted, 'Expected pathOmitted:true for Windows absolute path');
    });

    test('RC03-PATH-05: path with null byte is rejected', () => {
      const result = sanitizePathForAudit('foo\0bar.txt');
      assert.equal(typeof result, 'object');
      assert.ok(result.pathOmitted, 'Expected pathOmitted:true for null-byte path');
    });

    test('RC03-PATH-06: non-string input returns pathType metadata', () => {
      const result = sanitizePathForAudit(42);
      assert.equal(typeof result, 'object');
      assert.ok(result.pathOmitted, 'Expected pathOmitted:true for non-string input');
    });

    test('RC03-PATH-07: nested safe relative path passes through', () => {
      const result = sanitizePathForAudit('packages/protocol/src/errors.ts');
      assert.equal(result, 'packages/protocol/src/errors.ts');
    });
  });

  // ==========================================================================
  // SECTION 7: sanitizeMutationAuditParameters — UNIT TESTS
  // ==========================================================================

  describe('Section 7: sanitizeMutationAuditParameters', () => {
    test('RC03-SANITIZE-01: create_file sanitization removes raw content', () => {
      const params = { path: 'foo.txt', content: 'secret-content-abc', workspaceId: 'ws1' };
      const result = sanitizeMutationAuditParameters('create_file', params);
      assert.ok(
        !JSON.stringify(result).includes('secret-content-abc'),
        'Raw content must be omitted',
      );
    });

    test('RC03-SANITIZE-02: create_file sanitization records contentBytes', () => {
      const content = 'hello world';
      const params = { path: 'foo.txt', content };
      const result = sanitizeMutationAuditParameters('create_file', params);
      assert.equal(result.contentBytes, Buffer.byteLength(content, 'utf8'));
    });

    test('RC03-SANITIZE-03: create_file sanitization records safe path', () => {
      const params = { path: 'src/utils.ts', content: 'data' };
      const result = sanitizeMutationAuditParameters('create_file', params);
      assert.equal(result.path, 'src/utils.ts');
    });

    test('RC03-SANITIZE-04: create_file sanitization rejects hostile path', () => {
      const params = { path: '/etc/passwd', content: 'data' };
      const result = sanitizeMutationAuditParameters('create_file', params);
      assert.ok(result.path !== '/etc/passwd', 'Hostile path must be sanitized in audit output');
    });

    test('RC03-SANITIZE-05: write_file sanitization removes raw content', () => {
      const params = {
        path: 'README.md',
        content: 'private-write',
        expectedHash: 'a'.repeat(64),
        overwrite: true,
      };
      const result = sanitizeMutationAuditParameters('write_file', params);
      assert.ok(
        !JSON.stringify(result).includes('private-write'),
        'Raw write content must be omitted',
      );
    });

    test('RC03-SANITIZE-06: write_file sanitization preserves expectedHash', () => {
      const hash = 'abcdef1234567890'.repeat(4);
      const params = { path: 'README.md', content: 'x', expectedHash: hash, overwrite: true };
      const result = sanitizeMutationAuditParameters('write_file', params);
      assert.equal(result.expectedHash, hash);
    });

    test('RC03-SANITIZE-07: apply_patch sanitization removes raw patch content', () => {
      const params = { patch: '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n', dryRun: false };
      const result = sanitizeMutationAuditParameters('apply_patch', params);
      assert.ok(!JSON.stringify(result).includes('old'), 'Raw patch lines must be omitted');
      assert.ok(!JSON.stringify(result).includes('new\n'), 'Raw patch lines must be omitted');
    });

    test('RC03-SANITIZE-08: apply_patch sanitization records patchBytes', () => {
      const patch = '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n';
      const params = { patch };
      const result = sanitizeMutationAuditParameters('apply_patch', params);
      assert.equal(result.patchBytes, Buffer.byteLength(patch, 'utf8'));
    });

    test('RC03-SANITIZE-09: delete_file sanitization records safe path and hash', () => {
      const hash = 'dead'.repeat(16);
      const params = { path: 'to-delete.txt', expectedHash: hash };
      const result = sanitizeMutationAuditParameters('delete_file', params);
      assert.equal(result.path, 'to-delete.txt');
      assert.equal(result.expectedHash, hash);
    });

    test('RC03-SANITIZE-10: move_file sanitization records both sanitized paths', () => {
      const params = {
        sourcePath: 'src/old.ts',
        destinationPath: 'src/new.ts',
        expectedSourceHash: 'beef'.repeat(16),
      };
      const result = sanitizeMutationAuditParameters('move_file', params);
      assert.equal(result.sourcePath, 'src/old.ts');
      assert.equal(result.destinationPath, 'src/new.ts');
    });

    test('RC03-SANITIZE-11: move_file sanitization rejects hostile sourcePath', () => {
      const params = {
        sourcePath: '/etc/passwd',
        destinationPath: 'dest.txt',
        expectedSourceHash: 'cafe'.repeat(16),
      };
      const result = sanitizeMutationAuditParameters('move_file', params);
      assert.ok(
        result.sourcePath !== '/etc/passwd',
        'Hostile sourcePath must be sanitized in audit output',
      );
    });

    test('RC03-SANITIZE-12: contentBytes uses Buffer.byteLength (not JS .length) for multibyte chars', () => {
      // €  is 3 bytes in UTF-8 but 1 character in JS string length
      const content = '\u20AC\u20AC\u20AC'; // 3 euro signs = 9 UTF-8 bytes but length 3
      const params = { path: 'unicode.txt', content };
      const result = sanitizeMutationAuditParameters('create_file', params);
      assert.equal(result.contentBytes, Buffer.byteLength(content, 'utf8'));
      assert.notEqual(result.contentBytes, content.length); // must NOT be JS character length
    });
  });

  // ==========================================================================
  // SECTION 8: HEALTH RESPONSE — VERSION AND STAGE
  // ==========================================================================

  describe('Section 8: Health Response', () => {
    test('RC03-HEALTH-01: health response reports the current RC-06 version', async () => {
      const res = await server.dispatchToolCall('health', {});
      assert.ok(!res.isError, 'health must succeed');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.version, '0.6.0-rc06');
    });

    test('RC03-HEALTH-02: health response reports stage RC-06', async () => {
      const res = await server.dispatchToolCall('health', {});
      assert.ok(!res.isError, 'health must succeed');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.stage, 'RC-06');
    });
  });

  // ==========================================================================
  // SECTION 9: EXISTING CONTROLS REMAIN INTACT
  // ==========================================================================

  describe('Section 9: Existing Read-Only Controls Remain Intact', () => {
    test('RC03-COMPAT-01: health tool still returns HEALTHY', async () => {
      const res = await server.dispatchToolCall('health', {});
      assert.ok(!res.isError, 'health must succeed');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.status, 'HEALTHY');
    });

    test('RC03-COMPAT-02: list_directory still works in RC-03', async () => {
      const res = await server.dispatchToolCall('list_directory', {});
      assert.ok(!res.isError, `list_directory must succeed: ${res.content[0].text}`);
    });

    test('RC03-COMPAT-03: read_file still works in RC-03', async () => {
      const res = await server.dispatchToolCall('read_file', { path: 'README.md' });
      assert.ok(!res.isError, `read_file must succeed: ${res.content[0].text}`);
    });

    test('RC03-COMPAT-04: unregistered tool still returns POLICY_DENIED (not APPROVAL_REQUIRED)', async () => {
      const res = await server.dispatchToolCall('nonexistent_tool', {});
      assert.ok(res.isError, 'Unknown tool must be denied');
      const body = JSON.parse(res.content[0].text);
      assert.equal(body.code, 'POLICY_DENIED');
    });

    test('RC03-COMPAT-05: system_status still succeeds in RC-03', async () => {
      const res = await server.dispatchToolCall('system_status', {});
      assert.ok(!res.isError, `system_status must succeed: ${res.content[0].text}`);
    });
  });

  // ==========================================================================
  // SECTION 10: DEDICATED sanitizePreValidationMutationParameters TESTS
  // ==========================================================================

  describe('Section 10: sanitizePreValidationMutationParameters', () => {
    test('RC03-PREVAL-01: records only safe facts, no raw path, content, or hash', () => {
      const hostile = {
        path: '/etc/shadow/malicious',
        content: 'NEVER_STORE_THIS_FILE_BODY_8472',
        expectedHash: 'abcdef123456',
        workspaceId: 'evil-ws-id-1234',
        UNKNOWN_ATTACKER_KEY: 'malicious-data',
      };
      const sanitized = sanitizePreValidationMutationParameters('create_file', hostile);
      assert.equal(sanitized.propertyCount, 5);
      assert.equal(sanitized.extraPropertyCount, 2);
      assert.equal(sanitized.pathType, 'string');
      assert.equal(sanitized.pathLength, hostile.path.length);
      assert.equal(sanitized.contentType, 'string');
      assert.equal(sanitized.contentBytes, Buffer.byteLength(hostile.content, 'utf8'));
      assert.equal(sanitized.workspaceIdType, 'string');
      assert.equal(sanitized.workspaceIdLength, hostile.workspaceId.length);

      const serialized = JSON.stringify(sanitized);
      assert.ok(!serialized.includes('/etc/shadow/malicious'), 'Raw path must not appear');
      assert.ok(
        !serialized.includes('NEVER_STORE_THIS_FILE_BODY_8472'),
        'Raw content must not appear',
      );
      assert.ok(!serialized.includes('evil-ws-id-1234'), 'Raw workspaceId must not appear');
      assert.ok(!serialized.includes('UNKNOWN_ATTACKER_KEY'), 'Unknown key must not appear');
      assert.ok(!serialized.includes('malicious-data'), 'Unknown value must not appear');
    });

    test('RC03-PREVAL-02: apply_patch pre-validation records patchType and patchBytes only', () => {
      const hostile = {
        patch:
          '--- a/evil\n+++ b/evil\n@@ -1 +1 @@\n-NEVER_STORE_THIS_PATCH_BODY_6291\n+injected\n',
        dryRun: false,
        fuzz: 0,
        EVIL_KEY: true,
      };
      const sanitized = sanitizePreValidationMutationParameters('apply_patch', hostile);
      assert.equal(sanitized.propertyCount, 4);
      assert.equal(sanitized.extraPropertyCount, 1);
      assert.equal(sanitized.patchType, 'string');
      assert.equal(sanitized.patchBytes, Buffer.byteLength(hostile.patch, 'utf8'));
      assert.equal(sanitized.dryRunType, 'boolean');
      assert.equal(sanitized.fuzzType, 'number');

      const serialized = JSON.stringify(sanitized);
      assert.ok(
        !serialized.includes('NEVER_STORE_THIS_PATCH_BODY_6291'),
        'Raw patch must not appear',
      );
      assert.ok(!serialized.includes('EVIL_KEY'), 'Extra property key must not appear');
    });

    test('RC03-PREVAL-03: move_file pre-validation records sourcePathType and destinationPathType only', () => {
      const hostile = {
        sourcePath: '/absolute/path/src',
        destinationPath: '/absolute/path/dst',
        expectedSourceHash: '0'.repeat(64),
      };
      const sanitized = sanitizePreValidationMutationParameters('move_file', hostile);
      assert.equal(sanitized.sourcePathType, 'string');
      assert.equal(sanitized.sourcePathLength, hostile.sourcePath.length);
      assert.equal(sanitized.destinationPathType, 'string');
      assert.equal(sanitized.destinationPathLength, hostile.destinationPath.length);
      assert.equal(sanitized.expectedSourceHashType, 'string');
      assert.equal(sanitized.expectedSourceHashLength, 64);

      const serialized = JSON.stringify(sanitized);
      assert.ok(!serialized.includes('/absolute/path/src'), 'Raw sourcePath must not appear');
      assert.ok(!serialized.includes('/absolute/path/dst'), 'Raw destinationPath must not appear');
      assert.ok(!serialized.includes('0'.repeat(64)), 'Raw hash must not appear');
    });
  });

  // ==========================================================================
  // SECTION 11: EXACT LEAKAGE REGRESSIONS (PATHWAYS A, B, AND C)
  // ==========================================================================

  describe('Section 11: Exact Leakage Regressions (Pathways A, B, and C)', () => {
    const FILE_MARKER = 'NEVER_STORE_THIS_FILE_BODY_8472';
    const PATCH_MARKER = 'NEVER_STORE_THIS_PATCH_BODY_6291';
    const ABSOLUTE_ATTACKER_PATH = '/etc/shadow/attacker_probe';
    const MALFORMED_EXTRA_PROP = 'ATTACKER_EVIL_EXTRA_KEY_7733';

    test('RC03-LEAK-01: Pathway A (valid mutation -> REQUIRE_APPROVAL) zero marker leakage', async () => {
      const recordsBefore = auditLogger.getRecords().length;

      const res1 = await server.dispatchToolCall('create_file', {
        path: 'leak-test-valid.txt',
        content: `header ${FILE_MARKER} footer`,
      });
      assert.ok(res1.isError);
      assert.equal(JSON.parse(res1.content[0].text).code, 'APPROVAL_REQUIRED');

      const res2 = await server.dispatchToolCall('apply_patch', {
        patch: `--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,1 @@\n-# RC-03 Fixture\n+${PATCH_MARKER}\n`,
      });
      assert.ok(res2.isError);
      assert.equal(JSON.parse(res2.content[0].text).code, 'APPROVAL_REQUIRED');

      const records = auditLogger.getRecords().slice(recordsBefore);
      assert.ok(records.length >= 2, 'Expected at least 2 audit records');

      for (const record of records) {
        const serialized = JSON.stringify(record);
        assert.ok(
          !serialized.includes(FILE_MARKER),
          'FILE_MARKER must not appear in Pathway A audit',
        );
        assert.ok(
          !serialized.includes(PATCH_MARKER),
          'PATCH_MARKER must not appear in Pathway A audit',
        );
        assert.ok(
          !serialized.includes('# RC-03 Fixture'),
          'Raw patch context line must not appear in audit',
        );
        assert.ok(
          !serialized.includes(`+${PATCH_MARKER}`),
          'Raw inserted patch line must not appear in audit',
        );
        assert.ok(!serialized.includes('.arc-tmp-'), 'Temporary prefix .arc-tmp- must not appear');
      }
    });

    test('RC03-LEAK-02: Pathway B (schema-invalid mutation) zero marker/path/prop leakage', async () => {
      const recordsBefore = auditLogger.getRecords().length;

      const res1 = await server.dispatchToolCall('create_file', {
        path: ABSOLUTE_ATTACKER_PATH,
        content: `bad ${FILE_MARKER} bad`,
        [MALFORMED_EXTRA_PROP]: 'attacker_val',
      });
      assert.ok(res1.isError);
      assert.equal(JSON.parse(res1.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

      const res2 = await server.dispatchToolCall('apply_patch', {
        patch: `   \n\t${PATCH_MARKER}`,
        [MALFORMED_EXTRA_PROP]: 'attacker_val2',
      });
      assert.ok(res2.isError);
      assert.equal(JSON.parse(res2.content[0].text).code, 'INVALID_REQUEST_SCHEMA');

      const records = auditLogger.getRecords().slice(recordsBefore);
      assert.ok(records.length >= 2, 'Expected at least 2 audit records for Pathway B');

      for (const record of records) {
        const serialized = JSON.stringify(record);
        assert.ok(
          !serialized.includes(FILE_MARKER),
          'FILE_MARKER must not appear in Pathway B audit',
        );
        assert.ok(
          !serialized.includes(PATCH_MARKER),
          'PATCH_MARKER must not appear in Pathway B audit',
        );
        assert.ok(
          !serialized.includes(ABSOLUTE_ATTACKER_PATH),
          'Absolute attacker path must not appear in Pathway B audit',
        );
        assert.ok(
          !serialized.includes(MALFORMED_EXTRA_PROP),
          'Attacker extra property name must not appear in Pathway B audit',
        );
        assert.ok(!serialized.includes('.arc-tmp-'), 'Temporary prefix .arc-tmp- must not appear');
      }
    });

    test('RC03-LEAK-03: Pathway C (policy-DENY mutation) zero marker leakage', async () => {
      const recordsBefore = auditLogger.getRecords().length;

      const res1 = await server.dispatchToolCall('create_file', {
        path: '.git/HEAD',
        content: `sensitive ${FILE_MARKER} deny`,
      });
      assert.ok(res1.isError);
      assert.equal(JSON.parse(res1.content[0].text).code, 'POLICY_DENIED');

      const res2 = await server.dispatchToolCall('write_file', {
        path: '.envlocal',
        content: `secret ${FILE_MARKER} deny`,
        expectedHash: '0'.repeat(64),
        overwrite: true,
      });
      assert.ok(res2.isError);
      assert.equal(JSON.parse(res2.content[0].text).code, 'POLICY_DENIED');

      const records = auditLogger.getRecords().slice(recordsBefore);
      assert.ok(records.length >= 2, 'Expected at least 2 audit records for Pathway C');

      for (const record of records) {
        const serialized = JSON.stringify(record);
        assert.ok(
          !serialized.includes(FILE_MARKER),
          'FILE_MARKER must not appear in Pathway C audit',
        );
        assert.ok(
          !serialized.includes(PATCH_MARKER),
          'PATCH_MARKER must not appear in Pathway C audit',
        );
        assert.ok(!serialized.includes('.arc-tmp-'), 'Temporary prefix .arc-tmp- must not appear');
      }
    });
  });

  // ==========================================================================
  // SECTION 12: DIRECT POLICY PRECEDENCE (SecurityKernel.evaluate)
  // ==========================================================================

  describe('Section 12: Direct Policy Precedence (SecurityKernel.evaluate)', () => {
    let directKernel;
    let validContextBase;

    before(() => {
      const reg = new WorkspaceRegistry();
      reg.registerWorkspace('prec-ws', workspaceDir);
      const procReg = new ProcessRegistry();
      directKernel = new SecurityKernel(reg, procReg);

      validContextBase = {
        actor: {
          clientId: 'test-client',
          clientType: 'mcp-client',
          sessionId: 'test-sess',
          deviceId: 'test-dev',
          authenticated: true,
        },
        targetWorkspace: {
          workspaceId: 'prec-ws',
          rootPath: workspaceDir,
          isGitRepo: true,
        },
        environment: {
          timestamp: new Date().toISOString(),
        },
      };
    });

    test('RC03-PREC-01: valid create_file evaluates to REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: { toolName: 'create_file', parameters: { path: 'valid.txt', content: 'abc' } },
      });
      assert.equal(decision.outcome, PolicyOutcome.REQUIRE_APPROVAL);
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'require-approval-file-mutation');
    });

    test('RC03-PREC-02: valid write_file evaluates to REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'write_file',
          parameters: {
            path: 'README.md',
            content: 'abc',
            expectedHash: '0'.repeat(64),
            overwrite: true,
          },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.REQUIRE_APPROVAL);
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'require-approval-file-mutation');
    });

    test('RC03-PREC-03: valid apply_patch evaluates to REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'apply_patch',
          parameters: { patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n' },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.REQUIRE_APPROVAL);
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'require-approval-file-mutation');
    });

    test('RC03-PREC-04: valid delete_file evaluates to REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'delete_file',
          parameters: { path: 'README.md', expectedHash: '0'.repeat(64) },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.REQUIRE_APPROVAL);
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'require-approval-file-mutation');
    });

    test('RC03-PREC-05: valid move_file evaluates to REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'move_file',
          parameters: {
            sourcePath: 'src.txt',
            destinationPath: 'dst.txt',
            expectedSourceHash: '0'.repeat(64),
          },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.REQUIRE_APPROVAL);
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'require-approval-file-mutation');
    });

    test('RC03-PREC-06: unauthenticated caller -> higher-priority DENY over REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        actor: { ...validContextBase.actor, authenticated: false },
        request: { toolName: 'create_file', parameters: { path: 'valid.txt', content: 'abc' } },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-unauthenticated-caller');
    });

    test('RC03-PREC-07: unregistered workspace -> higher-priority DENY over REQUIRE_APPROVAL', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        targetWorkspace: {
          workspaceId: 'unregistered-ws',
          rootPath: '/tmp/nonexistent',
          isGitRepo: false,
        },
        request: {
          toolName: 'write_file',
          parameters: {
            path: 'README.md',
            content: 'abc',
            expectedHash: '0'.repeat(64),
            overwrite: true,
          },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-unregistered-workspace');
    });

    test('RC03-PREC-08: conflicting workspace selectors -> higher-priority DENY', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        targetWorkspace: {
          workspaceId: 'deny-conflicting-workspace-selectors',
          rootPath: '',
          isGitRepo: false,
        },
        request: { toolName: 'create_file', parameters: { path: 'valid.txt', content: 'abc' } },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-conflicting-workspace-selectors');
    });

    test('RC03-PREC-09: target .git/HEAD -> higher-priority DENY for create/write/delete', async () => {
      for (const tool of ['create_file', 'write_file', 'delete_file']) {
        const decision = await directKernel.evaluate({
          ...validContextBase,
          request: {
            toolName: tool,
            parameters: {
              path: '.git/HEAD',
              content: 'x',
              expectedHash: '0'.repeat(64),
              overwrite: true,
            },
          },
        });
        assert.equal(
          decision.outcome,
          PolicyOutcome.DENY,
          `Expected DENY for ${tool} targeting .git/HEAD`,
        );
        assert.equal(decision.matchingRuleId, 'deny-mutation-sensitive-path');
      }
    });

    test('RC03-PREC-10: target .git/refs/heads/main -> higher-priority DENY', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'create_file',
          parameters: { path: '.git/refs/heads/main', content: 'x' },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-mutation-sensitive-path');
    });

    test('RC03-PREC-11: target .envlocal -> higher-priority DENY', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: { toolName: 'create_file', parameters: { path: '.envlocal', content: 'x' } },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-mutation-sensitive-path');
    });

    test('RC03-PREC-12: move_file sourcePath .git/HEAD -> higher-priority DENY', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'move_file',
          parameters: {
            sourcePath: '.git/HEAD',
            destinationPath: 'safe.txt',
            expectedSourceHash: '0'.repeat(64),
          },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-mutation-sensitive-path');
    });

    test('RC03-PREC-13: move_file destinationPath .envlocal -> higher-priority DENY', async () => {
      const decision = await directKernel.evaluate({
        ...validContextBase,
        request: {
          toolName: 'move_file',
          parameters: {
            sourcePath: 'safe.txt',
            destinationPath: '.envlocal',
            expectedSourceHash: '0'.repeat(64),
          },
        },
      });
      assert.equal(decision.outcome, PolicyOutcome.DENY);
      assert.equal(decision.matchingRuleId, 'deny-mutation-sensitive-path');
    });
  });

  // ==========================================================================
  // SECTION 13: FILESYSTEM SPY — ZERO INVOCATIONS
  // ==========================================================================

  describe('Section 13: Filesystem Spy — Zero Subsystem Invocations', () => {
    class FilesystemSpy extends FilesystemSubsystem {
      createFileCount = 0;
      writeFileCount = 0;
      applyPatchCount = 0;
      deleteFileCount = 0;
      moveFileCount = 0;

      async createFile(...args) {
        this.createFileCount++;
        return super.createFile(...args);
      }
      async writeFile(...args) {
        this.writeFileCount++;
        return super.writeFile(...args);
      }
      async applyPatch(...args) {
        this.applyPatchCount++;
        return super.applyPatch(...args);
      }
      async deleteFile(...args) {
        this.deleteFileCount++;
        return super.deleteFile(...args);
      }
      async moveFile(...args) {
        this.moveFileCount++;
        return super.moveFile(...args);
      }
    }

    test('RC03-SPY-01: valid MCP requests for all 5 mutation tools yield exactly 0 subsystem calls', async () => {
      const spyFs = new FilesystemSpy();
      const spyReg = new WorkspaceRegistry();
      spyReg.registerWorkspace('spy-ws', workspaceDir);
      const spyProc = new ProcessRegistry();
      const spyKernel = new SecurityKernel(spyReg, spyProc);
      const spyAudit = new AuditLogger();
      const spyGit = new GitSubsystem();

      const spyServer = new ArcMcpServer(
        spyReg,
        spyKernel,
        spyAudit,
        spyFs,
        spyGit,
        { defaultWorkspaceId: 'spy-ws' },
        undefined,
        spyProc,
      );

      const validCalls = [
        { tool: 'create_file', params: { path: 'spy1.txt', content: 'hello' } },
        {
          tool: 'write_file',
          params: {
            path: 'README.md',
            content: 'new',
            expectedHash: '0'.repeat(64),
            overwrite: true,
          },
        },
        {
          tool: 'apply_patch',
          params: { patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n' },
        },
        { tool: 'delete_file', params: { path: 'README.md', expectedHash: '0'.repeat(64) } },
        {
          tool: 'move_file',
          params: {
            sourcePath: 'README.md',
            destinationPath: 'README2.md',
            expectedSourceHash: '0'.repeat(64),
          },
        },
      ];

      for (const { tool, params } of validCalls) {
        const res = await spyServer.dispatchToolCall(tool, params);
        assert.ok(res.isError, `Expected isError for ${tool}`);
        const body = JSON.parse(res.content[0].text);
        assert.equal(
          body.code,
          'APPROVAL_REQUIRED',
          `Expected APPROVAL_REQUIRED for ${tool}, got ${body.code}`,
        );
      }

      assert.equal(spyFs.createFileCount, 0, 'createFile count must be exactly 0');
      assert.equal(spyFs.writeFileCount, 0, 'writeFile count must be exactly 0');
      assert.equal(spyFs.applyPatchCount, 0, 'applyPatch count must be exactly 0');
      assert.equal(spyFs.deleteFileCount, 0, 'deleteFile count must be exactly 0');
      assert.equal(spyFs.moveFileCount, 0, 'moveFile count must be exactly 0');
    });
  });

  // ==========================================================================
  // SECTION 14: FORCED-ALLOW BACKSTOP TEST — MANDATORY
  // ==========================================================================

  describe('Section 14: Forced-ALLOW Defense-in-Depth Backstop', () => {
    class FilesystemSpyForced extends FilesystemSubsystem {
      createFileCount = 0;
      writeFileCount = 0;
      applyPatchCount = 0;
      deleteFileCount = 0;
      moveFileCount = 0;

      async createFile(...args) {
        this.createFileCount++;
        return super.createFile(...args);
      }
      async writeFile(...args) {
        this.writeFileCount++;
        return super.writeFile(...args);
      }
      async applyPatch(...args) {
        this.applyPatchCount++;
        return super.applyPatch(...args);
      }
      async deleteFile(...args) {
        this.deleteFileCount++;
        return super.deleteFile(...args);
      }
      async moveFile(...args) {
        this.moveFileCount++;
        return super.moveFile(...args);
      }
    }

    test('RC03-BACKSTOP-01: all 5 mutation tools remain fail-closed when Layer 1 is forced to ALLOW — zero subsystem calls', async () => {
      const forcedFs = new FilesystemSpyForced();
      const forcedReg = new WorkspaceRegistry();
      forcedReg.registerWorkspace('forced-ws', workspaceDir);
      const forcedAudit = new AuditLogger();
      const forcedGit = new GitSubsystem();

      const forcedAllowKernel = {
        evaluate: async () => ({
          outcome: PolicyOutcome.ALLOW,
          effect: 'ALLOW',
          matchingRuleId: 'test-forced-allow',
          reason: 'forced test allow',
        }),
      };

      const forcedServer = new ArcMcpServer(
        forcedReg,
        forcedAllowKernel,
        forcedAudit,
        forcedFs,
        forcedGit,
        { defaultWorkspaceId: 'forced-ws' },
      );

      const testFile = path.join(workspaceDir, 'backstop-test.txt');
      assert.ok(!fs.existsSync(testFile), 'Precondition: file does not exist');

      const validCalls = [
        { tool: 'create_file', params: { path: 'backstop-test.txt', content: 'dangerous' } },
        {
          tool: 'write_file',
          params: {
            path: 'README.md',
            content: 'dangerous',
            expectedHash: '0'.repeat(64),
            overwrite: true,
          },
        },
        {
          tool: 'apply_patch',
          params: { patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n' },
        },
        { tool: 'delete_file', params: { path: 'README.md', expectedHash: '0'.repeat(64) } },
        {
          tool: 'move_file',
          params: {
            sourcePath: 'README.md',
            destinationPath: 'README-forced.md',
            expectedSourceHash: '0'.repeat(64),
          },
        },
      ];

      for (const { tool, params } of validCalls) {
        const res = await forcedServer.dispatchToolCall(tool, params);
        assert.ok(res.isError, `Expected isError for forced ${tool}`);
        const body = JSON.parse(res.content[0].text);
        // RC-04 preserves the invariant: a mutation never executes without
        // verified human approval. The permanent floor clamps the forced ALLOW
        // to REQUIRE_APPROVAL, and the reserved control object is absent, so an
        // approval is requested and nothing is executed.
        assert.equal(body.code, 'APPROVAL_REQUIRED');
        assert.ok(!body.message.includes('token'), 'no token may be disclosed');
      }

      assert.equal(forcedFs.createFileCount, 0, 'createFile must remain 0 under forced ALLOW');
      assert.equal(forcedFs.writeFileCount, 0, 'writeFile must remain 0 under forced ALLOW');
      assert.equal(forcedFs.applyPatchCount, 0, 'applyPatch must remain 0 under forced ALLOW');
      assert.equal(forcedFs.deleteFileCount, 0, 'deleteFile must remain 0 under forced ALLOW');
      assert.equal(forcedFs.moveFileCount, 0, 'moveFile must remain 0 under forced ALLOW');

      assert.ok(!fs.existsSync(testFile), 'File must NOT have been created on disk');

      // Task 5 adds APPROVAL_REQUESTED lifecycle records alongside the ordinary
      // invocation records. Select the ordinary invocation records for the
      // original assertions; strength is unchanged.
      const records = forcedAudit
        .getRecords()
        .filter((record) => record.approval?.eventType === undefined);
      assert.equal(records.length, 5);
      for (const record of records) {
        assert.equal(record.policy.decision, 'REQUIRE_APPROVAL');
        // The built-in Layer-2 policy already requires approval for all five
        // mutation tools, so the floor is not even reached here.
        assert.equal(record.policy.ruleId, 'builtin-require-approval-file-mutation');
        assert.equal(
          record.execution.status,
          'DENIED',
          'Execution status must be DENIED, never SUCCESS',
        );
        assert.ok(record.error, 'Audit record must have error info');
        assert.equal(record.error.code, 'APPROVAL_REQUIRED');
      }
    });
  });

  // ==========================================================================
  // SECTION 15: ACTUAL TOOL DISCOVERY SOURCE & ENUMERATION
  // ==========================================================================

  describe('Section 15: Actual Tool Discovery Source & Enumeration', () => {
    test('RC03-DISC-01: ALL_TOOL_DEFINITIONS matches ListTools authoritative source with exactly 25 tools', () => {
      assert.equal(ALL_TOOL_DEFINITIONS.length, 25, 'Total tool definitions must be exactly 25');
      assert.equal(
        server.getRegisteredTools().length,
        25,
        'server.getRegisteredTools() must return 25 tools',
      );
    });

    test('RC03-DISC-02: all 25 tool names are distinct with zero duplicates', () => {
      const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);
      const uniqueNames = new Set(names);
      assert.equal(uniqueNames.size, 25, 'Must have exactly 25 unique tool names');
      assert.equal(
        names.length,
        uniqueNames.size,
        'No duplicates permitted in registered tool list',
      );
    });

    test('RC03-DISC-03: contains exactly the 5 canonical mutation tools', () => {
      const registeredNames = new Set(ALL_TOOL_DEFINITIONS.map((t) => t.name));
      const expectedMutations = [
        'create_file',
        'write_file',
        'apply_patch',
        'delete_file',
        'move_file',
      ];
      for (const tool of expectedMutations) {
        assert.ok(registeredNames.has(tool), `Tool list must contain mutation tool '${tool}'`);
      }
    });

    test('RC03-DISC-04: contains exactly the 9 RC-01 inspection tools and 4 RC-02 execution tools', () => {
      const registeredNames = new Set(ALL_TOOL_DEFINITIONS.map((t) => t.name));
      const expectedRc01 = [
        'health',
        'system_status',
        'list_directory',
        'read_file',
        'search_files',
        'search_text',
        'git_status',
        'git_diff',
        'git_log',
      ];
      const expectedRc02 = ['run_command', 'process_status', 'process_output', 'terminate_process'];
      for (const tool of [...expectedRc01, ...expectedRc02]) {
        assert.ok(registeredNames.has(tool), `Tool list must contain '${tool}'`);
      }
    });
  });
});
