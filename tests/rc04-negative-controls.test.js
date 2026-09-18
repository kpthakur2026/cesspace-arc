/**
 * CesSpace ARC — RC-04 Final Acceptance Negative Controls
 *
 * Standalone acceptance catalog for the 38 frozen RC-04 negative controls
 * defined in docs/architecture/rc04-scope-acceptance.md §35.
 *
 * Every case below exercises PUBLIC runtime/API behaviour. Nothing here
 * inspects or imports test source from other suites, and nothing depends on
 * wall-clock sleeping, network access, real credentials, or external services.
 * Token and key material is generated at runtime; no static secret-shaped
 * literal appears in this file.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  ArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  createArcMcpServer,
} from '../apps/mcp-server/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  DeclarativePolicyEngine,
} from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tempRoot;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-neg-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** Creates a workspace directory with fixed seed files. */
function makeWorkspace(label) {
  const dir = path.join(tempRoot, label);
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(dir, 'README.md'), 'line1\nline2\nline3\n');
  fs.writeFileSync(path.join(dir, 'keep.txt'), 'keep\n');
  return dir;
}

/** Records every filesystem mutation invocation, so "zero execution" is provable. */
class FilesystemSpy extends FilesystemSubsystem {
  constructor() {
    super();
    this.calls = [];
  }
  async createFile(root, request) {
    this.calls.push({ method: 'createFile' });
    return super.createFile(root, request);
  }
  async writeFile(root, request) {
    this.calls.push({ method: 'writeFile' });
    return super.writeFile(root, request);
  }
  async deleteFile(root, request) {
    this.calls.push({ method: 'deleteFile' });
    return super.deleteFile(root, request);
  }
  async moveFile(root, request) {
    this.calls.push({ method: 'moveFile' });
    return super.moveFile(root, request);
  }
  async applyPatch(root, request) {
    this.calls.push({ method: 'applyPatch' });
    return super.applyPatch(root, request);
  }
}

/** Builds a real MCP server over a real workspace, with an optional policy. */
function makeServer({ label = 'ws', policy, manager, filesystem, kernel } = {}) {
  const dir = makeWorkspace(label);
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', dir);

  const approvals = manager ?? new ApprovalStateManager();
  const fsSpy = filesystem ?? new FilesystemSpy();
  const audit = new AuditLogger();

  const server = new ArcMcpServer(
    registry,
    kernel ?? new SecurityKernel(registry),
    audit,
    fsSpy,
    new GitSubsystem(),
    {
      transport: 'stdio',
      authorizedRoots: [],
      defaultWorkspaceId: 'ws',
      ...(policy === undefined ? {} : { policy }),
    },
    undefined,
    undefined,
    approvals,
  );
  return { server, registry, approvals, filesystem: fsSpy, audit, dir };
}

function body(res) {
  return JSON.parse(res.content[0].text);
}

/** Generates a fresh, unique runtime marker. No static secret-shaped literal. */
function marker(prefix) {
  return `${prefix}-${crypto.randomBytes(10).toString('hex')}`;
}

/** Requests approval, approves out of band, and redeems in one call. */
async function approveAndRedeem(server, approvals, toolName, params, actor) {
  const first = await server.dispatchToolCall(toolName, { ...params }, actor);
  const firstBody = body(first);
  assert.equal(
    firstBody.code,
    'APPROVAL_REQUIRED',
    `expected APPROVAL_REQUIRED, got ${firstBody.code}`,
  );
  const requestId = firstBody.details.approvalRequestId;
  assert.match(requestId, /^[0-9a-f]{32}$/);
  const grant = approvals.approve(requestId);
  assert.match(grant.token, /^[0-9a-f]{64}$/);
  const second = await server.dispatchToolCall(
    toolName,
    { ...params, _arcApproval: { requestId, token: grant.token } },
    actor,
  );
  return { requestId, token: grant.token, first, firstBody, second, secondBody: body(second) };
}

const REQUIRE_READ_POLICY = `version: '1.0'
metadata:
  name: 'require-read'
rules:
  - id: 'require-read'
    effect: 'REQUIRE_APPROVAL'
    tools: ['read_file']
`;

const DENY_READ_POLICY = `version: '1.0'
metadata:
  name: 'deny-read'
rules:
  - id: 'deny-read'
    effect: 'DENY'
    tools: ['read_file']
`;

/** Builds a policy document with metadata plus one rule. */
function policyText({
  name = 'p',
  description = 'd',
  lastModified = '2026-01-01',
  tool = 'read_file',
  effect = 'DENY',
  extraRule = '',
}) {
  return `version: '1.0'
metadata:
  name: '${name}'
  description: '${description}'
  lastModified: '${lastModified}'
rules:
  - id: 'rule-a'
    effect: '${effect}'
    tools: ['${tool}']
${extraRule}`;
}

describe('CesSpace ARC — RC-04 Final Acceptance Negative Controls', () => {
  // =========================================================================
  // NEG-01 .. NEG-21 — runtime authorization, admission and binding
  // =========================================================================

  describe('Runtime negative controls', () => {
    test('RC04-NEG-01: MCP cannot administer approvals, and no approval state is created', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg01' });

      // Every administrative surface is unreachable from the MCP tool list...
      const toolNames = ALL_TOOL_DEFINITIONS.map((t) => t.name);
      for (const forbidden of [
        'approve',
        'reject',
        'approvals',
        'admin',
        'policy_test',
        'approval',
      ]) {
        assert.equal(toolNames.includes(forbidden), false, `${forbidden} must not be an MCP tool`);
      }

      // ...and every attempt to invoke one is denied without touching state.
      for (const name of [
        'approval.approve',
        'approval.reject',
        'approvals.list',
        'approvals.inspect',
        'admin',
        'policy_test',
      ]) {
        const res = await server.dispatchToolCall(name, { requestId: 'a'.repeat(32) });
        assert.equal(body(res).code, 'POLICY_DENIED', `${name} must be POLICY_DENIED`);
      }

      assert.equal(approvals.listActive().length, 0, 'no approval record may be created');
      assert.equal(approvals.getRequest('a'.repeat(32)), undefined);
      assert.equal(filesystem.calls.length, 0);
      assert.equal(
        fs.readdirSync(dir).filter((f) => f.endsWith('.txt') && f !== 'keep.txt').length,
        0,
      );
    });

    test('RC04-NEG-02: a valid token cannot override a Layer 1 DENY and stays unconsumed', async () => {
      const manager = new ApprovalStateManager();
      const { server, filesystem } = makeServer({
        label: 'neg02',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const grant = manager.approve(requestId);

      const res = await server.dispatchToolCall(
        'read_file',
        { ...params, _arcApproval: { requestId, token: grant.token } },
        { authenticated: false },
      );
      assert.equal(body(res).code, 'POLICY_DENIED');
      assert.equal(manager.getRequest(requestId).state, 'APPROVED', 'token must remain unconsumed');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-NEG-03: a valid token cannot override a Layer 2 DENY and stays unconsumed', async () => {
      const manager = new ApprovalStateManager();
      const permissive = makeServer({
        label: 'neg03',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const first = await permissive.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const grant = manager.approve(requestId);

      const denying = makeServer({
        label: 'neg03',
        manager,
        policy: { sourceText: DENY_READ_POLICY, format: 'yaml' },
      });
      const res = await denying.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(res).code, 'POLICY_DENIED');
      assert.equal(manager.getRequest(requestId).state, 'APPROVED', 'token must remain unconsumed');
      assert.equal(denying.filesystem.calls.length, 0);
    });

    test('RC04-NEG-04: a declarative ALLOW on a mutation is clamped to REQUIRE_APPROVAL', async () => {
      const allowPolicy = policyText({
        name: 'allow-create',
        tool: 'create_file',
        effect: 'ALLOW',
      });
      const { server, approvals, filesystem, dir } = makeServer({
        label: 'neg04',
        policy: { sourceText: allowPolicy, format: 'yaml' },
      });

      const res = await server.dispatchToolCall('create_file', {
        path: 'clamped.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      assert.equal(body(res).code, 'APPROVAL_REQUIRED', 'ALLOW must be clamped');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'clamped.txt')), false);
      assert.equal(approvals.listActive().length, 1);
      assert.equal(approvals.listActive()[0].state, 'PENDING');
    });

    test('RC04-NEG-05: a mutation without _arcApproval requires approval and mutates nothing', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg05' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'nope.txt',
        content: 'x',
        workspaceId: 'ws',
      });

      assert.equal(body(res).code, 'APPROVAL_REQUIRED');
      assert.ok(!JSON.stringify(body(res)).includes('"token"'), 'no token may be disclosed');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'nope.txt')), false);
      assert.equal(approvals.listActive().length, 1);
    });

    test('RC04-NEG-06: a missing token fails schema admission and creates no approval', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg06' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'x.txt',
        content: 'x',
        workspaceId: 'ws',
        _arcApproval: { requestId: 'a'.repeat(32) },
      });

      assert.equal(body(res).code, 'INVALID_REQUEST_SCHEMA');
      assert.equal(approvals.listActive().length, 0, 'schema rejection must not create state');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-NEG-07: an unknown canonical requestId is rejected without new approval', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg07' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'x.txt',
        content: 'x',
        workspaceId: 'ws',
        _arcApproval: { requestId: 'a'.repeat(32), token: 'b'.repeat(64) },
      });

      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(approvals.listActive().length, 0, 'no new approval may be created');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-NEG-08: a wrong token is rejected and the record stays APPROVED', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg08' });
      const params = { path: 'wrong.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      approvals.approve(requestId);

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: 'f'.repeat(64) },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-NEG-09: an expired approval is rejected with APPROVAL_EXPIRED and executes nothing', async () => {
      let mono = 1_000_000n;
      const manager = new ApprovalStateManager({ getMonotonicTime: () => mono });
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg09', manager });
      const params = { path: 'exp.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const grant = approvals.approve(requestId);

      // 301 seconds of monotonic time: past the frozen 300-second TTL.
      mono += 301_000n * 1_000_000n;

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(res).code, 'APPROVAL_EXPIRED');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'exp.txt')), false);
    });

    test('RC04-NEG-10: an operator-rejected request cannot be redeemed', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg10' });
      const params = { path: 'rej.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      approvals.reject(requestId);
      assert.equal(approvals.getRequest(requestId).state, 'REJECTED');

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: 'a'.repeat(64) },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'rej.txt')), false);
    });

    test('RC04-NEG-11: replaying a CONSUMED token is rejected without a second execution', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg11' });
      const params = { path: 'once.txt', content: 'x', workspaceId: 'ws' };

      const { requestId, token } = await approveAndRedeem(server, approvals, 'create_file', params);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
      assert.equal(filesystem.calls.length, 1);

      const replay = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'the subsystem must not run twice');
      assert.equal(fs.readFileSync(path.join(dir, 'once.txt'), 'utf8'), 'x');
    });

    test('RC04-NEG-12: concurrent redemption executes at most once', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg12' });
      const params = { path: 'race.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const envelope = { ...params, _arcApproval: { requestId, token } };
      const [a, b] = await Promise.all([
        server.dispatchToolCall('create_file', { ...envelope }),
        server.dispatchToolCall('create_file', { ...envelope }),
      ]);

      const failures = [body(a), body(b)].filter((r) => r.code !== undefined);
      assert.equal(failures.length, 1, 'exactly one redemption may fail');
      assert.equal(failures[0].code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'the tool executes at most once');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
    });

    test('RC04-NEG-13: content and patch tampering invalidate the binding', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg13' });
      const params = { path: 'content.txt', content: 'original-body', workspaceId: 'ws' };

      const { requestId } = await approveAndRedeem(server, approvals, 'create_file', params);
      assert.equal(filesystem.calls.length, 1);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');

      // A second approval, then tampering with the body that was reviewed.
      const second = await server.dispatchToolCall('create_file', {
        path: 'tamper.txt',
        content: 'reviewed-body',
        workspaceId: 'ws',
      });
      const tamperId = body(second).details.approvalRequestId;
      const tamperToken = approvals.approve(tamperId).token;

      const res = await server.dispatchToolCall('create_file', {
        path: 'tamper.txt',
        content: 'TAMPERED-body',
        workspaceId: 'ws',
        _arcApproval: { requestId: tamperId, token: tamperToken },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'tampered content must not execute');
      assert.equal(fs.existsSync(path.join(dir, 'tamper.txt')), false);

      // The same binding covers patch text.
      const patchA = '--- a/p.txt\n+++ b/p.txt\n@@ -1 +1 @@\n-old\n+reviewed\n';
      const patchB = '--- a/p.txt\n+++ b/p.txt\n@@ -1 +1 @@\n-old\n+TAMPERED\n';
      const p1 = await server.dispatchToolCall('apply_patch', { patch: patchA, workspaceId: 'ws' });
      const patchId = body(p1).details.approvalRequestId;
      const patchToken = approvals.approve(patchId).token;

      const patched = await server.dispatchToolCall('apply_patch', {
        patch: patchB,
        workspaceId: 'ws',
        _arcApproval: { requestId: patchId, token: patchToken },
      });
      assert.equal(body(patched).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'tampered patch must not execute');

      // Neither tampered attempt consumed its approval, and neither produced a
      // new one: a rejected redemption leaves the reviewed record intact.
      assert.equal(approvals.getRequest(tamperId).state, 'APPROVED');
      assert.equal(approvals.getRequest(patchId).state, 'APPROVED');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
    });

    test('RC04-NEG-14: path tampering invalidates the binding', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ label: 'neg14' });
      const first = await server.dispatchToolCall('create_file', {
        path: 'reviewed.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const res = await server.dispatchToolCall('create_file', {
        path: 'redirected.txt',
        content: 'x',
        workspaceId: 'ws',
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'redirected.txt')), false);
    });

    test('RC04-NEG-15: an actor mismatch is rejected and nothing executes', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg15' });
      const params = { path: 'actor.txt', content: 'x', workspaceId: 'ws' };
      const owner = { clientId: 'owner-client', clientType: 'claude-code', sessionId: 's-owner' };

      const first = await server.dispatchToolCall('create_file', { ...params }, owner);
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      for (const impostor of [
        { clientId: 'other-client', clientType: 'claude-code', sessionId: 's-owner' },
        { clientId: 'owner-client', clientType: 'claude-code', sessionId: 's-other' },
        {
          clientId: 'owner-client',
          clientType: 'claude-code',
          sessionId: 's-owner',
          deviceId: 'd-other',
        },
      ]) {
        const res = await server.dispatchToolCall(
          'create_file',
          { ...params, _arcApproval: { requestId, token } },
          impostor,
        );
        assert.equal(body(res).code, 'APPROVAL_REJECTED');
      }
      assert.equal(filesystem.calls.length, 0);
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');
    });

    test('RC04-NEG-16: a workspace mismatch never executes in the redirected workspace', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg16' });
      const otherRoot = makeWorkspace('neg16-other');
      server.workspaceRegistry.registerWorkspace('ws-other', otherRoot);

      const params = { path: 'x.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        workspaceId: 'ws-other',
        _arcApproval: { requestId, token },
      });
      const code = body(res).code;
      assert.ok(
        code === 'APPROVAL_REJECTED' || code === 'POLICY_DENIED',
        `expected APPROVAL_REJECTED or POLICY_DENIED, got ${code}`,
      );
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(otherRoot, 'x.txt')), false);
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');
    });

    test('RC04-NEG-17: a policy change invalidates permanently and does not consume the token', async () => {
      const manager = new ApprovalStateManager();
      const original = makeServer({
        label: 'neg17',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const first = await original.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = manager.approve(requestId).token;

      // Same manager, semantically different policy: a different policyHash.
      const changed = makeServer({
        label: 'neg17',
        manager,
        policy: {
          sourceText: policyText({
            name: 'require-read-v2',
            tool: 'read_file',
            effect: 'REQUIRE_APPROVAL',
          }),
          format: 'yaml',
        },
      });

      const res = await changed.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');
      assert.notEqual(
        manager.getRequest(requestId).state,
        'CONSUMED',
        'token must not be consumed',
      );
      assert.equal(changed.filesystem.calls.length, 0);
    });

    test('RC04-NEG-18: reverting the policy does not revive an INVALIDATED record', async () => {
      const manager = new ApprovalStateManager();
      const original = makeServer({
        label: 'neg18',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const first = await original.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = manager.approve(requestId).token;

      const changed = makeServer({
        label: 'neg18',
        manager,
        policy: {
          sourceText: policyText({ name: 'v2', tool: 'read_file', effect: 'REQUIRE_APPROVAL' }),
          format: 'yaml',
        },
      });
      await changed.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');

      // Restore the EXACT original policy text: the hash matches again.
      const reverted = makeServer({
        label: 'neg18',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const again = await reverted.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(again).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED', 'no revival is possible');
      assert.equal(reverted.filesystem.calls.length, 0);
    });

    test('RC04-NEG-19: a case-modified token is rejected', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg19' });
      const params = { path: 'case.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      const modified = token.toUpperCase();
      assert.notEqual(modified, token, 'the mutation must actually change the token');

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: modified },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');
    });

    test('RC04-NEG-20: a token within 128 characters but over 128 UTF-8 bytes is rejected', async () => {
      const { server, approvals } = makeServer({ label: 'neg20' });
      // 100 characters, 200 UTF-8 bytes: under the character bound, over the byte bound.
      const multibyte = 'é'.repeat(100);
      assert.equal(multibyte.length, 100);
      assert.equal(Buffer.byteLength(multibyte, 'utf8'), 200);

      const res = await server.dispatchToolCall('create_file', {
        path: 'x.txt',
        content: 'x',
        workspaceId: 'ws',
        _arcApproval: { requestId: 'a'.repeat(32), token: multibyte },
      });
      assert.equal(body(res).code, 'INVALID_REQUEST_SCHEMA');
      assert.equal(approvals.listActive().length, 0);
    });

    test('RC04-NEG-21: an uppercase 32-hex requestId fails schema admission', async () => {
      const { server, approvals } = makeServer({ label: 'neg21' });
      const uppercase = 'A'.repeat(32);
      assert.match(uppercase, /^[0-9A-F]{32}$/);

      const res = await server.dispatchToolCall('create_file', {
        path: 'x.txt',
        content: 'x',
        workspaceId: 'ws',
        _arcApproval: { requestId: uppercase, token: 'b'.repeat(64) },
      });
      assert.equal(body(res).code, 'INVALID_REQUEST_SCHEMA');
      assert.equal(approvals.listActive().length, 0);
    });
  });

  // =========================================================================
  // NEG-22 .. NEG-30 — declarative policy acceptance
  // =========================================================================

  describe('Policy negative controls', () => {
    let policyDir;
    let policyRegistry;

    before(() => {
      policyDir = makeWorkspace('neg-policy');
      policyRegistry = new WorkspaceRegistry();
      policyRegistry.registerWorkspace('ws', policyDir);
    });

    const hashOf = (text, format = 'yaml') =>
      DeclarativePolicyEngine.fromExternalText(policyRegistry, text, format).getPolicyHash();

    test('RC04-NEG-22: metadata-only changes do not change policyHash', () => {
      const a = policyText({ name: 'alpha', description: 'first', lastModified: '2026-01-01' });
      const b = policyText({ name: 'beta', description: 'second', lastModified: '2026-09-18' });

      assert.equal(hashOf(a), hashOf(b), 'metadata must not participate in the hash');
      assert.match(hashOf(a), /^[0-9a-f]{64}$/);
    });

    test('RC04-NEG-23: semantic changes alter policyHash', () => {
      const metadata = { name: 'alpha', description: 'first', lastModified: '2026-01-01' };
      const base = policyText({ ...metadata, tool: 'read_file' });
      const otherTool = policyText({ ...metadata, tool: 'write_file' });
      const otherEffect = policyText({
        ...metadata,
        tool: 'read_file',
        effect: 'REQUIRE_APPROVAL',
      });

      assert.notEqual(hashOf(base), hashOf(otherTool));
      assert.notEqual(hashOf(base), hashOf(otherEffect));
    });

    test('RC04-NEG-24: unknown workspace or mismatched rootHash fails closed with UNHEALTHY', async () => {
      const unknownWs = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: policyDir }],
        defaultWorkspaceId: 'ws',
        policy: {
          sourceText: `version: '1.0'\nworkspaces:\n  - id: 'not-registered'\nrules: []\n`,
          format: 'yaml',
        },
      });
      const unknownHealth = body(await unknownWs.dispatchToolCall('health', {}));
      assert.equal(unknownHealth.status, 'UNHEALTHY');
      assert.equal(unknownHealth.policyEngineActive, false);

      const badHash = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: policyDir }],
        defaultWorkspaceId: 'ws',
        policy: {
          sourceText: `version: '1.0'\nworkspaces:\n  - id: 'ws'\n    rootHash: '${'0'.repeat(64)}'\nrules: []\n`,
          format: 'yaml',
        },
      });
      const badHashHealth = body(await badHash.dispatchToolCall('health', {}));
      assert.equal(badHashHealth.status, 'UNHEALTHY');
      assert.equal(badHashHealth.policyEngineActive, false);

      // No built-in fallback exists: the engine is absent, not degraded.
      assert.throws(
        () =>
          DeclarativePolicyEngine.fromExternalText(
            policyRegistry,
            `version: '1.0'\nworkspaces:\n  - id: 'not-registered'\nrules: []\n`,
            'yaml',
          ),
        (err) => err.code === 'POLICY_LOAD_ERROR',
      );
    });

    test('RC04-NEG-25: a workspace assertion declaring a path is rejected', () => {
      for (const key of ['path', 'rootPath', 'directory']) {
        const text = `version: '1.0'\nworkspaces:\n  - id: 'ws'\n    ${key}: '/etc'\nrules: []\n`;
        assert.throws(
          () => hashOf(text),
          (err) => err.code === 'POLICY_PARSE_ERROR' && err.details.reason === 'UNKNOWN_PROPERTY',
          `${key} must be rejected`,
        );
      }
    });

    test('RC04-NEG-26: YAML anchors, aliases and merge keys are rejected', () => {
      const anchor = `version: '1.0'\nrules:\n  - id: &a 'x'\n    effect: 'DENY'\n    tools: ['read_file']\n`;
      const alias = `version: '1.0'\nx: &a 'read_file'\nrules:\n  - id: 'x'\n    effect: 'DENY'\n    tools: [*a]\n`;
      const merge = `version: '1.0'\na: &b {id: 'x'}\nrules:\n  - <<: *b\n    effect: 'DENY'\n    tools: ['read_file']\n`;

      for (const text of [anchor, alias, merge]) {
        assert.throws(
          () => hashOf(text),
          (err) =>
            err.code === 'POLICY_PARSE_ERROR' &&
            String(err.details.reason).startsWith('FORBIDDEN_YAML'),
        );
      }
    });

    test('RC04-NEG-27: nesting deeper than 32 is rejected', () => {
      let nested = 'leaf';
      for (let i = 0; i < 40; i++) {
        nested = `[${nested}]`;
      }
      const text = `version: '1.0'\nmetadata:\n  name: 'deep'\nextra: ${nested}\nrules: []\n`;

      assert.throws(
        () => hashOf(text),
        (err) => err.code === 'POLICY_PARSE_ERROR' && err.details.reason === 'DEPTH_LIMIT_EXCEEDED',
      );
    });

    test('RC04-NEG-28: an embedded ** inside a path segment is rejected', () => {
      const text = policyText({
        extraRule: ``,
      }).replace("tools: ['read_file']", "tools: ['read_file']\n    paths: ['src/a**b.ts']");

      assert.throws(
        () => hashOf(text),
        (err) => err.code === 'POLICY_PARSE_ERROR' && err.details.reason === 'INVALID_MATCHER',
      );
    });

    test('RC04-NEG-29: unsupported glob syntax is rejected', () => {
      const patterns = [
        'src/{a,b}.ts', // brace expansion
        'src/@(a|b).ts', // extglob
        '/[a-z]+\\.ts/', // regex literal
        '/etc/passwd', // leading slash
        '../secret', // traversal
      ];
      for (const pattern of patterns) {
        const text = policyText({}).replace(
          "tools: ['read_file']",
          `tools: ['read_file']\n    paths: ['${pattern}']`,
        );
        assert.throws(
          () => hashOf(text),
          (err) => err.code === 'POLICY_PARSE_ERROR' && err.details.reason === 'INVALID_MATCHER',
          `${pattern} must be rejected`,
        );
      }
    });

    test('RC04-NEG-30: specifying allowedBinaries and blockedBinaries together is rejected', () => {
      const text = `version: '1.0'
metadata:
  name: 'both'
rules:
  - id: 'rule-a'
    effect: 'DENY'
    tools: ['run_command']
    allowedBinaries: ['ls']
    blockedBinaries: ['rm']
`;

      assert.throws(
        () => hashOf(text),
        (err) => err.code === 'POLICY_PARSE_ERROR',
      );
    });
  });

  // =========================================================================
  // NEG-31 .. NEG-38 — lifecycle, quota, audit and restart
  // =========================================================================

  describe('Lifecycle, quota, audit and restart controls', () => {
    function binding(overrides = {}) {
      return {
        actor: { clientId: 'neg-client', clientType: 'claude-code', ...(overrides.actor ?? {}) },
        workspace: {
          workspaceId: 'ws',
          workspaceRootHash: 'b'.repeat(64),
          ...(overrides.workspace ?? {}),
        },
        policyHash: 'c'.repeat(64),
        ...(overrides.rest ?? {}),
      };
    }

    test('RC04-NEG-31: 16 concurrent identical requests produce one record and one requestId', async () => {
      const { server, approvals } = makeServer({ label: 'neg31' });
      const params = { path: 'concurrent.txt', content: 'x', workspaceId: 'ws' };

      const responses = await Promise.all(
        Array.from({ length: 16 }, () => server.dispatchToolCall('create_file', { ...params })),
      );
      const ids = new Set(responses.map((r) => body(r).details.approvalRequestId));

      assert.equal(ids.size, 1, 'exactly one requestId may be issued');
      assert.equal(approvals.listActive().length, 1, 'exactly one active record may exist');
      const requestId = [...ids][0];
      assert.match(requestId, /^[0-9a-f]{32}$/);
    });

    test('RC04-NEG-32: a repeat while APPROVED reuses the record without new allocation or TTL reset', async () => {
      const { server, approvals } = makeServer({ label: 'neg32' });
      const params = { path: 'reuse.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const deadline = approvals.getRequest(requestId).expiresAt;
      const createdAt = approvals.getRequest(requestId).createdAt;

      approvals.approve(requestId);
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');

      const second = await server.dispatchToolCall('create_file', { ...params });
      assert.equal(body(second).details.approvalRequestId, requestId);
      assert.equal(approvals.listActive().length, 1, 'no duplicate record may be allocated');
      assert.equal(
        approvals.getRequest(requestId).expiresAt,
        deadline,
        'the TTL must not be reset',
      );
      assert.equal(approvals.getRequest(requestId).createdAt, createdAt);
    });

    test('RC04-NEG-33: a wall-clock rollback cannot extend the monotonic deadline', () => {
      let mono = 1_000_000n;
      let wall = 1_800_000_000_000;
      const manager = new ApprovalStateManager({
        getMonotonicTime: () => mono,
        getWallTime: () => wall,
      });
      const request = manager.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: binding(),
        reviewMaterial: 'x',
      });
      const deadline = manager.getRequest(request.requestId).expiresAt;

      // The wall clock jumps far BACKWARDS while monotonic time moves on.
      wall -= 86_400_000;
      mono += 301_000n * 1_000_000n;

      // Expiry is driven by the monotonic clock, so the rollback changes nothing.
      manager.purgeExpired();
      assert.equal(manager.getRequest(request.requestId).state, 'EXPIRED');
      assert.equal(
        manager.getRequest(request.requestId).expiresAt,
        deadline,
        'the displayed deadline is a stable projection, not recomputed from a rolled-back clock',
      );
      assert.throws(
        () => manager.approve(request.requestId),
        (err) => err.code === 'APPROVAL_EXPIRED',
      );
    });

    test('RC04-NEG-34: quota exhaustion is rejected with RESOURCE_EXHAUSTED and preserves state', () => {
      const manager = new ApprovalStateManager({ maxActiveApprovalsPerActor: 1 });
      const first = manager.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: binding(),
        reviewMaterial: 'x',
      });
      const before = manager.getRequest(first.requestId);

      assert.throws(
        () =>
          manager.createOrReusePending({
            toolName: 'write_file',
            executionPayloadHash: 'b'.repeat(64),
            binding: binding(),
            reviewMaterial: 'y',
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );

      // The pre-existing record is untouched by the refused admission.
      assert.equal(manager.listActive().length, 1);
      assert.equal(manager.getRequest(first.requestId).state, 'PENDING');
      assert.equal(manager.getRequest(first.requestId).expiresAt, before.expiresAt);

      // The byte quota is a second, independent bound.
      const byteManager = new ApprovalStateManager({ maxReviewBytesPerRecord: 32 });
      assert.throws(
        () =>
          byteManager.createOrReusePending({
            toolName: 'write_file',
            executionPayloadHash: 'a'.repeat(64),
            binding: binding(),
            reviewMaterial: 'z'.repeat(64),
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );
      assert.equal(byteManager.listActive().length, 0);
    });

    test('RC04-NEG-35: no raw approval token ever reaches a serialized AuditRecord', async () => {
      const { server, approvals, audit } = makeServer({ label: 'neg35' });
      const params = { path: 'audit.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const grant = approvals.approve(requestId);
      const digest = crypto.createHash('sha256').update(grant.token, 'utf8').digest('hex');

      await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      // Also drive a rejection so the failure records are covered too.
      await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      await server.flushAudit();

      const records = audit.getRecords();
      const serialized = JSON.stringify(records);
      assert.ok(records.length >= 4, 'the lifecycle must have produced records');
      assert.equal(serialized.includes(grant.token), false, 'raw token must never be stored');
      assert.equal(serialized.includes(digest), false, 'token digest must never be stored');
      assert.equal(serialized.includes(grant.token.slice(0, 16)), false);
    });

    test('RC04-NEG-36: raw file content and patch lines never reach an AuditRecord', async () => {
      const { server, approvals, audit } = makeServer({ label: 'neg36' });
      const contentMarker = marker('NEG36-CONTENT');
      const patchMarker = marker('NEG36-PATCH');

      const createParams = { path: 'body.txt', content: contentMarker, workspaceId: 'ws' };
      const { second } = await approveAndRedeem(server, approvals, 'create_file', createParams);
      assert.notEqual(body(second).code, 'APPROVAL_REJECTED');

      const patch = `--- a/kept.txt\n+++ b/kept.txt\n@@ -1 +1 @@\n-keep\n+${patchMarker}\n`;
      const first = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      await server.dispatchToolCall('apply_patch', {
        patch,
        workspaceId: 'ws',
        _arcApproval: { requestId, token },
      });
      await server.flushAudit();

      const serialized = JSON.stringify(audit.getRecords());
      assert.equal(serialized.includes(contentMarker), false, 'file content must not be stored');
      assert.equal(serialized.includes(patchMarker), false, 'patch text must not be stored');
      assert.equal(serialized.includes('@@ -1 +1 @@'), false, 'patch headers must not be stored');
    });

    test('RC04-NEG-37: bypass fields remain rejected by schema admission', async () => {
      const { server, approvals, filesystem } = makeServer({ label: 'neg37' });
      for (const field of ['approvalToken', 'bypassApproval', 'sudo', 'force']) {
        const res = await server.dispatchToolCall('create_file', {
          path: 'x.txt',
          content: 'x',
          workspaceId: 'ws',
          [field]: true,
        });
        assert.equal(body(res).code, 'INVALID_REQUEST_SCHEMA', `${field} must be rejected`);
      }
      assert.equal(approvals.listActive().length, 0);
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-NEG-38: a restart purges approvals and makes old tokens unusable', async () => {
      const first = makeServer({ label: 'neg38' });
      const params = { path: 'restart.txt', content: 'x', workspaceId: 'ws' };

      const requested = await first.server.dispatchToolCall('create_file', { ...params });
      const requestId = body(requested).details.approvalRequestId;
      const token = first.approvals.approve(requestId).token;
      assert.equal(first.approvals.getRequest(requestId).state, 'APPROVED');

      // A fresh process would have a fresh in-memory manager and a fresh chain.
      const second = makeServer({ label: 'neg38' });
      assert.equal(second.approvals.getRequest(requestId), undefined, 'no persisted authority');
      assert.equal(second.approvals.listActive().length, 0);

      // The token carries no authority anywhere: not in the new instance...
      const afterRestart = await second.server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(afterRestart).code, 'APPROVAL_REJECTED');
      assert.equal(second.filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(second.dir, 'restart.txt')), false);

      // ...and not as a newly minted request either.
      const reminted = await second.server.dispatchToolCall('create_file', { ...params });
      assert.equal(body(reminted).code, 'APPROVAL_REQUIRED');
      assert.notEqual(body(reminted).details.approvalRequestId, requestId);
      assert.equal(second.filesystem.calls.length, 0);
    });
  });
});
