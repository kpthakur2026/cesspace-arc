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
  canonicalJson,
  sha256Hex,
  DeclarativePolicyEngine,
} from '../packages/policy/dist/index.js';
import {
  computeExecutionPayloadHash,
  extractArcApproval,
  extractPolicyTargets,
  normalizeTargetPathForPolicy,
} from '../apps/mcp-server/dist/approval-gate.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tempRoot;
let workspaceDir;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-mcp-'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), 'line1\nline2\nline3\n');
  fs.writeFileSync(path.join(workspaceDir, '.env'), 'SECRET=1\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** Records every filesystem mutation invocation for isolation assertions. */
class FilesystemSpy extends FilesystemSubsystem {
  constructor() {
    super();
    this.calls = [];
  }
  async createFile(root, request) {
    this.calls.push({ method: 'createFile', request });
    return super.createFile(root, request);
  }
  async writeFile(root, request) {
    this.calls.push({ method: 'writeFile', request });
    return super.writeFile(root, request);
  }
  async deleteFile(root, request) {
    this.calls.push({ method: 'deleteFile', request });
    return super.deleteFile(root, request);
  }
  async moveFile(root, request) {
    this.calls.push({ method: 'moveFile', request });
    return super.moveFile(root, request);
  }
  async applyPatch(root, request) {
    this.calls.push({ method: 'applyPatch', request });
    return super.applyPatch(root, request);
  }
}

/** Builds a server with a real workspace and an optional external policy. */
function makeServer({ policy, workspaceName = 'ws', manager, fsSpy, kernelOverride } = {}) {
  const registry = new WorkspaceRegistry();
  const dir = path.join(tempRoot, workspaceName);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.git', 'config'), '[core]\n');
    fs.writeFileSync(path.join(dir, 'README.md'), 'line1\nline2\nline3\n');
    fs.writeFileSync(path.join(dir, 'keep.txt'), 'keep\n');
  }
  registry.registerWorkspace('ws', dir);

  const approvals = manager ?? new ApprovalStateManager();
  const filesystem = fsSpy ?? new FilesystemSpy();
  const audit = new AuditLogger();
  const kernel = kernelOverride ?? new SecurityKernel(registry);

  const config = {
    transport: 'stdio',
    authorizedRoots: [],
    defaultWorkspaceId: 'ws',
    ...(policy === undefined ? {} : { policy }),
  };

  const server = new ArcMcpServer(
    registry,
    kernel,
    audit,
    filesystem,
    new GitSubsystem(),
    config,
    undefined,
    undefined,
    approvals,
  );
  return { server, registry, approvals, filesystem, audit, dir };
}

function body(res) {
  return JSON.parse(res.content[0].text);
}

/** Runs a request, approves it out of band, and redeems the token in one call. */
async function requestApproveRedeem(server, approvals, toolName, params, actorOverride) {
  const first = await server.dispatchToolCall(toolName, { ...params }, actorOverride);
  const firstBody = body(first);
  assert.equal(
    firstBody.code,
    'APPROVAL_REQUIRED',
    `expected APPROVAL_REQUIRED, got ${firstBody.code}`,
  );
  const requestId = firstBody.details.approvalRequestId;
  assert.match(requestId, /^[0-9a-f]{32}$/);
  assert.ok(!JSON.stringify(firstBody).includes('"token"'), 'no token may be disclosed');

  const grant = approvals.approve(requestId);
  assert.match(grant.token, /^[0-9a-f]{64}$/);

  const second = await server.dispatchToolCall(
    toolName,
    { ...params, _arcApproval: { requestId, token: grant.token } },
    actorOverride,
  );
  return { requestId, token: grant.token, first, firstBody, second, secondBody: body(second) };
}

const READ_APPROVAL_POLICY = `version: '1.0'
rules:
  - id: 'require-read'
    effect: 'REQUIRE_APPROVAL'
    tools: ['read_file']
`;

const DENY_READ_POLICY = `version: '1.0'
rules:
  - id: 'deny-read'
    effect: 'DENY'
    tools: ['read_file']
`;

describe('CesSpace ARC — RC-04 Task 4: MCP Approval, Redemption & Controlled Mutation', () => {
  // =========================================================================
  // 1. Reserved control-object admission
  // =========================================================================

  describe('Reserved control object', () => {
    test('RC04-M-01: _arcApproval is advertised on all 20 tool schemas and added nowhere else', () => {
      assert.equal(ALL_TOOL_DEFINITIONS.length, 20);
      for (const tool of ALL_TOOL_DEFINITIONS) {
        assert.ok(
          tool.inputSchema.properties._arcApproval,
          `${tool.name} must advertise the reserved control object`,
        );
      }
      // The admin surface is still absent from the MCP tool list.
      const names = ALL_TOOL_DEFINITIONS.map((t) => t.name);
      for (const forbidden of ['approve', 'reject', 'approvals', 'admin', 'policy_test']) {
        assert.ok(!names.includes(forbidden), `${forbidden} must not be an MCP tool`);
      }
    });

    test('RC04-M-02: malformed control objects are rejected with INVALID_REQUEST_SCHEMA and create no state', async () => {
      const { server, approvals, filesystem } = makeServer();
      const malformed = [
        { _arcApproval: null },
        { _arcApproval: [] },
        { _arcApproval: 'string' },
        { _arcApproval: {} },
        { _arcApproval: { requestId: 'a'.repeat(32) } },
        { _arcApproval: { token: 't'.repeat(16) } },
        { _arcApproval: { requestId: 'A'.repeat(32), token: 'x' } },
        { _arcApproval: { requestId: 'a'.repeat(31), token: 'x' } },
        { _arcApproval: { requestId: 'a'.repeat(33), token: 'x' } },
        { _arcApproval: { requestId: 5, token: 'x' } },
        { _arcApproval: { requestId: 'a'.repeat(32), token: '' } },
        { _arcApproval: { requestId: 'a'.repeat(32), token: 7 } },
        { _arcApproval: { requestId: 'a'.repeat(32), token: 'x'.repeat(129) } },
        { _arcApproval: { requestId: 'a'.repeat(32), token: '€'.repeat(50) } },
        { _arcApproval: { requestId: 'a'.repeat(32), token: 'x', extra: 1 } },
      ];

      for (const params of malformed) {
        const res = await server.dispatchToolCall('create_file', {
          path: 'x.txt',
          content: 'x',
          workspaceId: 'ws',
          ...params,
        });
        const parsed = body(res);
        assert.equal(
          parsed.code,
          'INVALID_REQUEST_SCHEMA',
          `expected schema rejection for ${JSON.stringify(params._arcApproval)}`,
        );
        assert.ok(
          !JSON.stringify(parsed).includes('_arcApproval'),
          'control object must not be echoed',
        );
      }

      assert.equal(approvals.listActive().length, 0, 'no approval state may be created');
      assert.equal(filesystem.calls.length, 0, 'no subsystem call may occur');
    });

    test('RC04-M-03: a token of <=128 characters but >128 UTF-8 bytes is rejected', () => {
      const multibyte = '€'.repeat(50); // 50 characters, 150 UTF-8 bytes
      assert.ok(multibyte.length <= 128);
      assert.ok(Buffer.byteLength(multibyte, 'utf8') > 128);
      const extracted = extractArcApproval({
        requestId: 'a'.repeat(32),
        _arcApproval: { requestId: 'a'.repeat(32), token: multibyte },
      });
      assert.equal(extracted.malformed, true);
      assert.equal(extracted.control, null);
    });

    test('RC04-M-04: the control object is removed before business schema validation', () => {
      const extracted = extractArcApproval({
        path: 'a.txt',
        content: 'x',
        _arcApproval: { requestId: 'a'.repeat(32), token: 'tok' },
      });
      assert.deepEqual(extracted.businessParameters, { path: 'a.txt', content: 'x' });
      assert.equal(extracted.control.requestId, 'a'.repeat(32));
      assert.equal(extracted.malformed, false);
    });

    test('RC04-M-05: unofficial bypass fields remain unknown business parameters', async () => {
      const { server, approvals, filesystem } = makeServer();
      for (const field of [
        'approvalToken',
        'approved',
        'bypassApproval',
        'autoApprove',
        'force',
        'admin',
        'sudo',
      ]) {
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
  });

  // =========================================================================
  // 2. Execution payload hash
  // =========================================================================

  describe('Execution payload hash', () => {
    const base = {
      toolName: 'create_file',
      businessParameters: { path: 'a.txt', content: 'x' },
      actor: { clientId: 'c1', clientType: 't1', sessionId: 's1', deviceId: 'd1' },
      workspaceId: 'ws',
      workspaceRootHash: 'b'.repeat(64),
      policyHash: 'c'.repeat(64),
    };

    test('RC04-M-06: the hash is canonical JSON + SHA-256 with the frozen shape', () => {
      const expected = sha256Hex(
        canonicalJson({
          schemaVersion: '1.0',
          toolName: 'create_file',
          parameters: { path: 'a.txt', content: 'x' },
          actor: { clientId: 'c1', clientType: 't1', sessionId: 's1', deviceId: 'd1' },
          workspaceId: 'ws',
          workspaceRootHash: 'b'.repeat(64),
          policyHash: 'c'.repeat(64),
        }),
      );
      assert.equal(computeExecutionPayloadHash(base), expected);
    });

    test('RC04-M-07: the hash changes for every semantic component', () => {
      const original = computeExecutionPayloadHash(base);
      const variants = [
        { ...base, toolName: 'write_file' },
        { ...base, businessParameters: { path: 'b.txt', content: 'x' } },
        { ...base, businessParameters: { path: 'a.txt', content: 'y' } },
        { ...base, actor: { ...base.actor, clientId: 'c2' } },
        { ...base, actor: { ...base.actor, clientType: 't2' } },
        { ...base, actor: { ...base.actor, sessionId: 's2' } },
        { ...base, actor: { ...base.actor, deviceId: 'd2' } },
        { ...base, workspaceId: 'other' },
        { ...base, workspaceRootHash: 'd'.repeat(64) },
        { ...base, policyHash: 'e'.repeat(64) },
      ];
      for (const variant of variants) {
        assert.notEqual(computeExecutionPayloadHash(variant), original);
      }
    });

    test('RC04-M-08: optional identity components are bound by exact presence', () => {
      const withoutSession = computeExecutionPayloadHash({
        ...base,
        actor: { clientId: 'c1', clientType: 't1', deviceId: 'd1' },
      });
      const withSession = computeExecutionPayloadHash(base);
      assert.notEqual(withoutSession, withSession);
      // `authenticated` is deliberately not part of the binding.
      const withAuthenticated = computeExecutionPayloadHash({
        ...base,
        actor: { ...base.actor, authenticated: true },
      });
      assert.equal(withAuthenticated, computeExecutionPayloadHash(base));
    });

    test('RC04-M-09: the same business request hashes identically at request and redemption', async () => {
      const { server, approvals, filesystem, dir } = makeServer();
      const params = { path: 'hash.txt', content: 'content', workspaceId: 'ws' };
      const { secondBody } = await requestApproveRedeem(server, approvals, 'create_file', params);
      assert.equal(secondBody.code, undefined, `expected success, got ${secondBody.code}`);
      assert.equal(fs.readFileSync(path.join(dir, 'hash.txt'), 'utf8'), 'content');
      assert.equal(filesystem.calls.length, 1);
    });
  });

  // =========================================================================
  // 3. Target extraction and normalization
  // =========================================================================

  describe('Target extraction', () => {
    test('RC04-M-10: paths are normalized to canonical workspace-relative form', () => {
      assert.equal(normalizeTargetPathForPolicy('/ws', 'a/b.txt'), 'a/b.txt');
      assert.equal(normalizeTargetPathForPolicy('/ws', './a/b.txt'), 'a/b.txt');
      assert.equal(normalizeTargetPathForPolicy('/ws', 'a/./b.txt'), 'a/b.txt');
      assert.equal(normalizeTargetPathForPolicy('/ws', 'a/../b.txt'), 'b.txt');
      assert.equal(normalizeTargetPathForPolicy('/ws', 'a/b.txt/'), 'a/b.txt');
      assert.equal(normalizeTargetPathForPolicy('/ws', undefined), undefined);

      // A safe workspace-root selector yields the root sentinel, not a denial.
      assert.equal(normalizeTargetPathForPolicy('/ws', '.'), '');
      assert.equal(normalizeTargetPathForPolicy('/ws', './'), '');

      // Unsafe targets still fail closed, including ABSOLUTE paths that happen
      // to point inside the workspace root.
      const unsafe = [
        '../x',
        '../../etc/passwd',
        '/etc/passwd',
        '/ws/a.txt',
        'a' + String.fromCharCode(0) + 'b',
        'a\\b',
        'C:/ws/a.txt',
      ];
      for (const bad of unsafe) {
        assert.equal(normalizeTargetPathForPolicy('/ws', bad), null, `expected unsafe: ${bad}`);
      }
    });

    test('RC04-M-11: move_file and apply_patch produce one target per path', () => {
      const move = extractPolicyTargets(
        'move_file',
        { sourcePath: 'a.txt', destinationPath: 'b.txt' },
        '/ws',
      );
      assert.deepEqual(
        move.map((t) => t.path),
        ['a.txt', 'b.txt'],
      );

      const patch = extractPolicyTargets('apply_patch', {}, '/ws', ['one.txt', 'two.txt']);
      assert.deepEqual(
        patch.map((t) => t.path),
        ['one.txt', 'two.txt'],
      );
    });

    test('RC04-M-12: run_command uses the normalized executable basename', () => {
      const targets = extractPolicyTargets('run_command', { executable: '  NPM  ' }, '/ws');
      assert.equal(targets[0].executableBasename, 'npm');
    });
  });

  // =========================================================================
  // 4. All five mutation tools: request -> approve -> redeem -> execute -> replay
  // =========================================================================

  describe('Mutation end-to-end', () => {
    test('RC04-M-13: create_file full lifecycle', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'e2e-create' });
      const target = path.join(dir, 'created.txt');
      const params = { path: 'created.txt', content: 'hello', workspaceId: 'ws' };

      const a = await server.dispatchToolCall('create_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      assert.equal(fs.existsSync(target), false, 'A: nothing may be created before approval');

      const { requestId, token, second, secondBody } = await requestApproveRedeem(
        server,
        approvals,
        'create_file',
        params,
      );
      assert.equal(second.isError, undefined);
      assert.equal(secondBody.path, 'created.txt');
      assert.equal(fs.readFileSync(target, 'utf8'), 'hello');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
      assert.equal(filesystem.calls.length, 1);

      // D: replay is rejected and executes nothing further.
      const replay = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'no second subsystem invocation');
      assert.equal(fs.readFileSync(target, 'utf8'), 'hello');
    });

    test('RC04-M-14: write_file full lifecycle', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'e2e-write' });
      const target = path.join(dir, 'README.md');
      const original = fs.readFileSync(target);
      const expectedHash = crypto.createHash('sha256').update(original).digest('hex');
      const params = {
        path: 'README.md',
        content: 'replaced\n',
        expectedHash,
        overwrite: true,
        workspaceId: 'ws',
      };

      const a = await server.dispatchToolCall('write_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      assert.deepEqual(fs.readFileSync(target), original, 'A: unchanged');

      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'write_file',
        params,
      );
      assert.equal(fs.readFileSync(target, 'utf8'), 'replaced\n');
      assert.equal(filesystem.calls.length, 1);

      const replay = await server.dispatchToolCall('write_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1);
    });

    test('RC04-M-15: delete_file full lifecycle', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'e2e-delete' });
      fs.writeFileSync(path.join(dir, 'doomed.txt'), 'bye\n');
      const target = path.join(dir, 'doomed.txt');
      const expectedHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(target))
        .digest('hex');
      const params = { path: 'doomed.txt', expectedHash, workspaceId: 'ws' };

      const a = await server.dispatchToolCall('delete_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      assert.equal(fs.existsSync(target), true, 'A: still present');

      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'delete_file',
        params,
      );
      assert.equal(fs.existsSync(target), false, 'C: deleted');
      assert.equal(filesystem.calls.length, 1);

      const replay = await server.dispatchToolCall('delete_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1);
    });

    test('RC04-M-16: move_file full lifecycle', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'e2e-move' });
      fs.writeFileSync(path.join(dir, 'src.txt'), 'move me\n');
      const sourceHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.join(dir, 'src.txt')))
        .digest('hex');
      const params = {
        sourcePath: 'src.txt',
        destinationPath: 'dst.txt',
        expectedSourceHash: sourceHash,
        workspaceId: 'ws',
      };

      const a = await server.dispatchToolCall('move_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      assert.equal(fs.existsSync(path.join(dir, 'dst.txt')), false, 'A: no destination');

      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'move_file',
        params,
      );
      assert.equal(fs.existsSync(path.join(dir, 'src.txt')), false);
      assert.equal(fs.readFileSync(path.join(dir, 'dst.txt'), 'utf8'), 'move me\n');
      assert.equal(filesystem.calls.length, 1);

      const replay = await server.dispatchToolCall('move_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1);
    });

    test('RC04-M-17: apply_patch full lifecycle', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'e2e-patch' });
      const target = path.join(dir, 'README.md');
      const patch =
        '--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n-line1\n+LINE1\n line2\n line3\n';
      const params = { patch, workspaceId: 'ws' };

      const a = await server.dispatchToolCall('apply_patch', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      assert.equal(fs.readFileSync(target, 'utf8'), 'line1\nline2\nline3\n', 'A: unchanged');

      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'apply_patch',
        params,
      );
      assert.equal(fs.readFileSync(target, 'utf8'), 'LINE1\nline2\nline3\n');
      assert.equal(filesystem.calls.length, 1);

      const replay = await server.dispatchToolCall('apply_patch', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1);
    });

    test('RC04-M-18: apply_patch dryRun still requires approval and still consumes', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'e2e-dryrun' });
      const patch =
        '--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n-line1\n+DRY\n line2\n line3\n';
      const params = { patch, dryRun: true, workspaceId: 'ws' };
      const a = await server.dispatchToolCall('apply_patch', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED', 'no dry-run approval bypass');

      const { requestId } = await requestApproveRedeem(server, approvals, 'apply_patch', params);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
    });
  });

  // =========================================================================
  // 5. Layer 1 / Layer 2 DENY before token validation
  // =========================================================================

  describe('DENY precedes token validation', () => {
    test('RC04-M-19: a valid approved token cannot override a current Layer-2 DENY', async () => {
      // The approval is minted under a permissive policy, then the effective
      // policy changes to DENY before redemption.
      const manager = new ApprovalStateManager();
      // Mint under a policy that requires approval for the read...
      const permissive = makeServer({
        workspaceName: 'deny-l2',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const a = await permissive.server.dispatchToolCall('read_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      const requestId = body(a).details.approvalRequestId;
      const grant = manager.approve(requestId);
      assert.equal(manager.getRequest(requestId).state, 'APPROVED');

      // Swap in a policy that DENYs the tool, sharing the same manager.
      const denying = makeServer({
        workspaceName: 'deny-l2',
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

    test('RC04-M-20: a valid approved token cannot override a Layer-1 DENY', async () => {
      const manager = new ApprovalStateManager();
      const permissive = makeServer({
        workspaceName: 'deny-l1',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const a = await permissive.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(a).details.approvalRequestId;
      const grant = manager.approve(requestId);

      // Layer 1 denies unauthenticated callers regardless of any token.
      const res = await permissive.server.dispatchToolCall(
        'read_file',
        { ...params, _arcApproval: { requestId, token: grant.token } },
        { authenticated: false },
      );
      assert.equal(body(res).code, 'POLICY_DENIED');
      assert.equal(manager.getRequest(requestId).state, 'APPROVED');
      assert.equal(permissive.filesystem.calls.length, 0);
    });

    test('RC04-M-21: an unnecessary but valid token on an ALLOW operation is not consumed', async () => {
      const manager = new ApprovalStateManager();
      const { server, approvals, filesystem, dir } = makeServer({
        workspaceName: 'unnecessary',
        manager,
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      // Mint an approval under a policy that requires it...
      const requiring = makeServer({
        workspaceName: 'unnecessary',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const a = await requiring.server.dispatchToolCall('read_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      const requestId = body(a).details.approvalRequestId;
      const grant = manager.approve(requestId);

      // ...then invoke under the built-in policy, where the same read is ALLOW.
      const res = await server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(res.isError, undefined, 'the read executes normally');
      assert.equal(
        manager.getRequest(requestId).state,
        'APPROVED',
        'an unnecessary token must not be inspected or consumed',
      );
      assert.equal(filesystem.calls.length, 0, 'read_file is not a mutation');
      void dir;
      void approvals;
    });
  });

  // =========================================================================
  // 6. Policy mismatch, tampering, replay, concurrency
  // =========================================================================

  describe('Redemption integrity', () => {
    test('RC04-M-22: a policy change invalidates an approved record permanently', async () => {
      const manager = new ApprovalStateManager();
      const original = makeServer({
        workspaceName: 'policy-change',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const a = await original.server.dispatchToolCall('read_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      const requestId = body(a).details.approvalRequestId;
      const grant = manager.approve(requestId);

      // Current policy still requires approval, but its hash differs.
      const changed = makeServer({
        workspaceName: 'policy-change',
        manager,
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'require-read-v2'\n    effect: 'REQUIRE_APPROVAL'\n    tools: ['read_file']\n`,
          format: 'yaml',
        },
      });

      const res = await changed.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');

      // Reverting to the original policy must not revive it.
      const reverted = makeServer({
        workspaceName: 'policy-change',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const again = await reverted.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(again).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');
    });

    test('RC04-M-23: parameter tampering is rejected and creates no new request', async () => {
      const tampered = [{ content: 'different' }, { path: 'other.txt' }];
      for (const change of tampered) {
        const { server, approvals, filesystem } = makeServer({
          workspaceName: 'tamper',
        });
        const params = { path: 'tamper.txt', content: 'original', workspaceId: 'ws' };
        const { requestId, token } = await requestApproveRedeem(
          server,
          approvals,
          'create_file',
          params,
        );
        // The first redemption above already consumed the token; mint a fresh
        // request so the tamper is the only variable under test.
        const freshParams = { path: 'tamper2.txt', content: 'original', workspaceId: 'ws' };
        const a = await server.dispatchToolCall('create_file', { ...freshParams });
        const freshId = body(a).details.approvalRequestId;
        const freshToken = approvals.approve(freshId).token;
        const before = approvals.listActive().length;

        const res = await server.dispatchToolCall('create_file', {
          ...freshParams,
          ...change,
          _arcApproval: { requestId: freshId, token: freshToken },
        });
        assert.equal(
          body(res).code,
          'APPROVAL_REJECTED',
          `expected rejection for ${JSON.stringify(change)}`,
        );
        assert.equal(
          approvals.getRequest(freshId).state,
          'APPROVED',
          'a binding mismatch must not consume the approval',
        );
        assert.equal(approvals.listActive().length, before, 'no new request may be created');
        assert.equal(filesystem.calls.length, 1, 'only the first redemption executed');
        void requestId;
        void token;
      }
    });

    test('RC04-M-24: an actor mismatch is rejected for each identity component', async () => {
      for (const change of [
        { clientId: 'someone-else' },
        { sessionId: 'other-session' },
        { deviceId: 'other-device' },
        { clientType: 'other-client' },
      ]) {
        const { server, approvals, filesystem } = makeServer({ workspaceName: 'actor' });
        const params = { path: 'actor.txt', content: 'x', workspaceId: 'ws' };
        const actor = { clientId: 'alice', clientType: 'cli', sessionId: 's1', deviceId: 'd1' };

        const a = await server.dispatchToolCall('create_file', { ...params }, actor);
        const requestId = body(a).details.approvalRequestId;
        const token = approvals.approve(requestId).token;

        const res = await server.dispatchToolCall(
          'create_file',
          { ...params, _arcApproval: { requestId, token } },
          { ...actor, ...change },
        );
        assert.equal(
          body(res).code,
          'APPROVAL_REJECTED',
          `expected rejection for ${JSON.stringify(change)}`,
        );
        assert.equal(filesystem.calls.length, 0);
      }
    });

    test('RC04-M-25: a workspace mismatch never executes in the other workspace', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'ws-a' });
      const secondDir = path.join(tempRoot, 'ws-b');
      fs.mkdirSync(secondDir, { recursive: true });
      server.workspaceRegistry.registerWorkspace('ws-b', secondDir);

      // The server's own workspace is registered as 'ws'; 'ws-b' is a second
      // authorized root that the approval must never be usable against.
      const params = { path: 'x.txt', content: 'x', workspaceId: 'ws' };
      const a = await server.dispatchToolCall('create_file', { ...params });
      assert.equal(body(a).code, 'APPROVAL_REQUIRED');
      const requestId = body(a).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        workspaceId: 'ws-b',
        _arcApproval: { requestId, token },
      });
      const code = body(res).code;
      assert.ok(
        code === 'APPROVAL_REJECTED' || code === 'POLICY_DENIED',
        `expected rejection, got ${code}`,
      );
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.existsSync(path.join(tempRoot, 'ws-b', 'x.txt')), false);
    });

    test('RC04-M-26: a case-modified token is rejected', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'case' });
      const params = { path: 'case.txt', content: 'x', workspaceId: 'ws' };
      const a = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(a).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      const upper = token.toUpperCase();
      assert.notEqual(upper, token);

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: upper },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-M-27: a PENDING request presented as a token neither mints nor executes', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'pending' });
      const params = { path: 'pending.txt', content: 'x', workspaceId: 'ws' };
      const a = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(a).details.approvalRequestId;

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: 'f'.repeat(64) },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(approvals.getRequest(requestId).state, 'PENDING');
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-M-28: concurrent redemption of one token consumes exactly once', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'race' });
      const params = { path: 'race.txt', content: 'x', workspaceId: 'ws' };
      const a = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(a).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const envelope = { ...params, _arcApproval: { requestId, token } };
      const [first, second] = await Promise.all([
        server.dispatchToolCall('create_file', { ...envelope }),
        server.dispatchToolCall('create_file', { ...envelope }),
      ]);

      const codes = [body(first).code, body(second).code].filter((c) => c !== undefined);
      assert.equal(codes.length, 1, 'exactly one redemption may succeed');
      assert.equal(codes[0], 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'the subsystem is invoked at most once');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
      assert.ok(fs.existsSync(path.join(dir, 'race.txt')));
    });

    test('RC04-M-29: execution failure after consumption leaves the token consumed', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'fail' });
      const params = {
        path: 'README.md',
        content: 'x',
        expectedHash: '0'.repeat(64), // deliberately wrong -> precondition conflict
        overwrite: true,
        workspaceId: 'ws',
      };

      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'write_file',
        params,
      );
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
      assert.equal(filesystem.calls.length, 1, 'the subsystem was invoked once');

      const second = await server.dispatchToolCall('write_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(second).code, 'APPROVAL_REJECTED');
      assert.equal(filesystem.calls.length, 1, 'no second invocation');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
    });
  });

  // =========================================================================
  // 7. Multi-target and sensitive-path controls
  // =========================================================================

  describe('Multi-target and sensitive paths', () => {
    test('RC04-M-30: a two-file patch with one DENYd target is denied regardless of ordering', async () => {
      const policy = `version: '1.0'
rules:
  - id: 'deny-second'
    effect: 'DENY'
    tools: ['apply_patch']
    paths:
      patterns: ['two.txt']
`;

      for (const order of [
        ['one.txt', 'two.txt'],
        ['two.txt', 'one.txt'],
      ]) {
        const { server, approvals, filesystem } = makeServer({
          workspaceName: 'multi-patch',
          policy: { sourceText: policy, format: 'yaml' },
        });
        const hunks = order
          .map(
            (file) =>
              `--- a/${file}\n+++ b/${file}\n@@ -1,3 +1,3 @@\n-line1\n+CHANGED\n line2\n line3\n`,
          )
          .join('');
        const a = await server.dispatchToolCall('apply_patch', { patch: hunks, workspaceId: 'ws' });
        assert.equal(body(a).code, 'POLICY_DENIED', `ordering ${order.join(',')} must be denied`);
        assert.equal(approvals.listActive().length, 0, 'no approval may be created');
        assert.equal(filesystem.calls.length, 0);
      }
    });

    test('RC04-M-31: a move with a DENYd destination is denied as a whole', async () => {
      const policy = `version: '1.0'
rules:
  - id: 'deny-destination'
    effect: 'DENY'
    tools: ['move_file']
    paths:
      patterns: ['forbidden.txt']
`;
      const { server, approvals, filesystem } = makeServer({
        workspaceName: 'multi-move',
        policy: { sourceText: policy, format: 'yaml' },
      });
      const a = await server.dispatchToolCall('move_file', {
        sourcePath: 'README.md',
        destinationPath: 'forbidden.txt',
        expectedSourceHash: '0'.repeat(64),
        workspaceId: 'ws',
      });
      assert.equal(body(a).code, 'POLICY_DENIED');
      assert.equal(approvals.listActive().length, 0);
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-M-32: a patch targeting a permanent sensitive path is denied before token consumption', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'sensitive' });
      const params = {
        patch: '--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-[core]\n+[evil]\n',
        workspaceId: 'ws',
      };

      // Mint an approval for the same patch parameters first via a permissive
      // path, then prove Layer 1 still denies and the token stays APPROVED.
      const manager = approvals;
      const seed = await server.dispatchToolCall('apply_patch', { ...params });
      const seedCode = body(seed).code;
      // If Layer 1 already denies the seed request, that is the strongest
      // outcome: the sensitive target never even reaches approval creation.
      if (seedCode === 'POLICY_DENIED') {
        assert.equal(manager.listActive().length, 0);
        assert.equal(filesystem.calls.length, 0);
        return;
      }

      const requestId = body(seed).details.approvalRequestId;
      const token = manager.approve(requestId).token;
      const res = await server.dispatchToolCall('apply_patch', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'POLICY_DENIED');
      assert.equal(manager.getRequest(requestId).state, 'APPROVED', 'token must remain unconsumed');
      assert.equal(filesystem.calls.length, 0);
      assert.equal(fs.readFileSync(path.join(workspaceDir, '.git', 'config'), 'utf8'), '[core]\n');
    });
  });

  // =========================================================================
  // 8. Deduplication, external policy, invalid policy
  // =========================================================================

  describe('Deduplication and external policy', () => {
    test('RC04-M-33: identical requests reuse one record with a stable deadline', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'dedup' });
      const params = { path: 'dedup.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const second = await server.dispatchToolCall('create_file', { ...params });
      const firstBody = body(first);
      const secondBody = body(second);

      assert.equal(firstBody.details.approvalRequestId, secondBody.details.approvalRequestId);
      assert.equal(approvals.listActive().length, 1);
      const deadline = approvals.getRequest(firstBody.details.approvalRequestId).expiresAt;

      // Approving then repeating the ordinary request still reuses the record.
      approvals.approve(firstBody.details.approvalRequestId);
      const third = await server.dispatchToolCall('create_file', { ...params });
      assert.equal(body(third).details.approvalRequestId, firstBody.details.approvalRequestId);
      assert.equal(
        approvals.getRequest(firstBody.details.approvalRequestId).expiresAt,
        deadline,
        'the TTL must not be reset',
      );
      assert.equal(approvals.getRequest(firstBody.details.approvalRequestId).state, 'APPROVED');
    });

    test('RC04-M-34: an external ALLOW rule permits a read, DENY blocks it, no-match denies', async () => {
      const allowPolicy = `version: '1.0'
rules:
  - id: 'allow-read'
    effect: 'ALLOW'
    tools: ['read_file']
`;
      const allowed = makeServer({
        workspaceName: 'ext-allow',
        policy: { sourceText: allowPolicy, format: 'yaml' },
      });
      const ok = await allowed.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      assert.equal(ok.isError, undefined, 'external ALLOW read executes');

      const denied = makeServer({
        workspaceName: 'ext-deny',
        policy: { sourceText: DENY_READ_POLICY, format: 'yaml' },
      });
      const blocked = await denied.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      assert.equal(body(blocked).code, 'POLICY_DENIED');

      // No matching rule in an external policy is default-deny.
      const nomatch = makeServer({
        workspaceName: 'ext-nomatch',
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'other'\n    effect: 'ALLOW'\n    tools: ['git_status']\n`,
          format: 'yaml',
        },
      });
      const miss = await nomatch.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      assert.equal(body(miss).code, 'POLICY_DENIED');
    });

    test('RC04-M-35: an external ALLOW rule still cannot auto-allow a mutation', async () => {
      const policy = `version: '1.0'
rules:
  - id: 'allow-mutations'
    effect: 'ALLOW'
    tools: ['create_file']
`;
      const { server, approvals } = makeServer({
        workspaceName: 'ext-floor',
        policy: { sourceText: policy, format: 'yaml' },
      });
      const res = await server.dispatchToolCall('create_file', {
        path: 'floor.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      assert.equal(body(res).code, 'APPROVAL_REQUIRED', 'the mutation floor still applies');
      assert.equal(approvals.listActive().length, 1);
    });

    test('RC04-M-36: the policyHash bound into the approval equals the engine hash', async () => {
      const manager = new ApprovalStateManager();
      const { server, approvals } = makeServer({
        workspaceName: 'hash-bind',
        manager,
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const engine = DeclarativePolicyEngine.fromExternalText(
        server.workspaceRegistry,
        READ_APPROVAL_POLICY,
        'yaml',
      );
      const a = await server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      const requestId = body(a).details.approvalRequestId;
      assert.equal(approvals.getRequest(requestId).binding.policyHash, engine.getPolicyHash());
      assert.equal(server.effectivePolicyEngine.getPolicyHash(), engine.getPolicyHash());
    });

    test('RC04-M-37: an invalid external policy fails closed with no built-in fallback', async () => {
      const marker = 'RC04_MCP_POLICY_MARKER_6612';
      const bad = makeServer({
        workspaceName: 'bad-policy',
        policy: {
          sourceText: `version: '1.0'\nrules: [\n# ${marker}\n`,
          format: 'yaml',
        },
      });

      assert.equal(bad.server.effectivePolicyEngine, undefined);
      assert.ok(bad.server.policyInitializationFailure);

      // health remains callable and truthfully reports UNHEALTHY.
      const health = await bad.server.dispatchToolCall('health', {});
      const healthBody = body(health);
      assert.equal(healthBody.status, 'UNHEALTHY');
      assert.equal(healthBody.policyEngineActive, false);
      assert.equal(healthBody.stage, 'RC-06');

      // Every non-diagnostic operation fails closed with no approval creation.
      for (const [tool, params] of [
        ['read_file', { path: 'README.md', workspaceId: 'ws' }],
        ['create_file', { path: 'x.txt', content: 'x', workspaceId: 'ws' }],
        ['run_command', { executable: 'ls', workspaceId: 'ws' }],
      ]) {
        const res = await bad.server.dispatchToolCall(tool, params);
        const parsed = body(res);
        assert.equal(parsed.code, 'POLICY_LOAD_ERROR', `${tool} must fail closed`);
        assert.ok(!JSON.stringify(parsed).includes(marker), 'raw policy text must not leak');
      }
      assert.equal(bad.approvals.listActive().length, 0);
      assert.equal(bad.filesystem.calls.length, 0);
      assert.ok(
        !JSON.stringify(bad.audit.getRecords()).includes(marker),
        'raw policy text must not reach audit',
      );
    });
  });

  // =========================================================================
  // 9. Leakage and isolation
  // =========================================================================

  describe('Leakage and subsystem isolation', () => {
    test('RC04-M-38: tokens, content, and patch bodies never reach audit or responses', async () => {
      const contentMarker = 'RC04_CONTENT_MARKER_9911';
      const patchMarker = 'RC04_PATCH_MARKER_2277';
      const { server, approvals, audit, filesystem } = makeServer({ workspaceName: 'leak' });

      const params = { path: 'leak.txt', content: contentMarker, workspaceId: 'ws' };
      const { requestId, token } = await requestApproveRedeem(
        server,
        approvals,
        'create_file',
        params,
      );

      // A patch approval whose review material carries its own marker.
      const patch = `--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n-line1\n+${patchMarker}\n line2\n line3\n`;
      const p = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const patchRequestId = body(p).details.approvalRequestId;
      const patchToken = approvals.approve(patchRequestId).token;

      const auditText = JSON.stringify(audit.getRecords());
      assert.ok(!auditText.includes(token), 'token leaked into audit');
      assert.ok(!auditText.includes(patchToken), 'token leaked into audit');
      assert.ok(!auditText.includes(contentMarker), 'raw content leaked into audit');
      assert.ok(!auditText.includes(patchMarker), 'raw patch leaked into audit');
      assert.ok(!auditText.includes('_arcApproval'), 'control object leaked into audit');

      // Responses after the fact must not carry the token either.
      const after = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.ok(!JSON.stringify(body(after)).includes(token), 'token leaked into a rejection');

      // The subsystem received only its own request shape.
      for (const call of filesystem.calls) {
        const keys = Object.keys(call.request);
        assert.ok(!keys.includes('_arcApproval'), '_arcApproval reached the subsystem');
        assert.ok(!keys.includes('token'), 'token reached the subsystem');
        assert.ok(!keys.includes('requestId'), 'requestId reached the subsystem');
        assert.ok(!JSON.stringify(call.request).includes(token));
      }
    });

    test('RC04-M-39: review summary is safe metadata and never contains raw material', async () => {
      const contentMarker = 'RC04_SUMMARY_MARKER_5566';
      const { server, approvals } = makeServer({ workspaceName: 'summary' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'summary.txt',
        content: contentMarker,
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const snapshot = approvals.getRequest(requestId);

      assert.deepEqual(snapshot.reviewSummary.targetPaths, ['summary.txt']);
      assert.equal(typeof snapshot.reviewSummary.contentBytes, 'number');
      assert.match(snapshot.reviewSummary.contentHash, /^[0-9a-f]{64}$/);
      assert.ok(
        !JSON.stringify(snapshot.reviewSummary).includes(contentMarker),
        'the summary must never carry raw content',
      );
      // Raw material is available only through the operator-only pending view.
      assert.equal(approvals.inspectPending(requestId), contentMarker);
    });

    test('RC04-M-40: a 1 MiB mutation body is accepted without review-header overflow', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'bigbody' });
      const content = 'A'.repeat(1_048_576);
      assert.equal(Buffer.byteLength(content, 'utf8'), 1_048_576);

      const res = await server.dispatchToolCall('create_file', {
        path: 'big.txt',
        content,
        workspaceId: 'ws',
      });
      const requestBody = body(res);
      assert.equal(
        requestBody.code,
        'APPROVAL_REQUIRED',
        'a legal 1 MiB body must not fail because ARC added metadata',
      );
      assert.equal(approvals.listActive().length, 1);
    });

    test('RC04-M-41: a fresh server has fresh approval state (restart semantics)', async () => {
      const first = makeServer({ workspaceName: 'restart' });
      const params = { path: 'restart.txt', content: 'x', workspaceId: 'ws' };
      const a = await first.server.dispatchToolCall('create_file', { ...params });
      const requestId = body(a).details.approvalRequestId;
      const token = first.approvals.approve(requestId).token;

      const second = makeServer({ workspaceName: 'restart' });
      const res = await second.server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(second.filesystem.calls.length, 0);
    });

    test('RC04-M-42: createArcMcpServer exposes no admin MCP tool and no admin listener', () => {
      const server = createArcMcpServer({ transport: 'stdio', authorizedRoots: [] });
      const names = server.getRegisteredTools().map((t) => t.name);
      for (const forbidden of ['approve', 'reject', 'approvals', 'admin', 'policy_test']) {
        assert.ok(!names.includes(forbidden));
      }
      assert.equal(server.adminIpcServer, undefined);
      assert.ok(server.approvalStateManager instanceof ApprovalStateManager);
      assert.equal(server.effectivePolicyEngine.getSourceMode(), 'BUILTIN');
    });

    test('RC04-M-43: no mutation executes without an invocation-local consumption flag', async () => {
      // Directly exercise the defense-in-depth backstop: a forced ALLOW kernel
      // plus a Layer-1-only path still cannot reach a mutation execution case.
      const registry = new WorkspaceRegistry();
      registry.registerWorkspace('ws', workspaceDir);
      const spy = new FilesystemSpy();
      const forcedAllowKernel = {
        evaluate: async () => ({
          outcome: 2,
          effect: 'ALLOW',
          matchingRuleId: 'forced-allow',
          reason: 'forced',
        }),
      };
      const server = new ArcMcpServer(
        registry,
        forcedAllowKernel,
        new AuditLogger(),
        spy,
        new GitSubsystem(),
        { transport: 'stdio', authorizedRoots: [], defaultWorkspaceId: 'ws' },
        undefined,
        undefined,
        new ApprovalStateManager(),
      );

      for (const [tool, params] of [
        ['create_file', { path: 'backstop.txt', content: 'x', workspaceId: 'ws' }],
        [
          'write_file',
          {
            path: 'README.md',
            content: 'x',
            expectedHash: '0'.repeat(64),
            overwrite: true,
            workspaceId: 'ws',
          },
        ],
        ['delete_file', { path: 'README.md', expectedHash: '0'.repeat(64), workspaceId: 'ws' }],
        [
          'move_file',
          {
            sourcePath: 'README.md',
            destinationPath: 'z.txt',
            expectedSourceHash: '0'.repeat(64),
            workspaceId: 'ws',
          },
        ],
        [
          'apply_patch',
          { patch: '--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n', workspaceId: 'ws' },
        ],
      ]) {
        const res = await server.dispatchToolCall(tool, params);
        assert.ok(res.isError, `${tool} must not execute`);
        assert.equal(body(res).code, 'APPROVAL_REQUIRED');
      }
      assert.equal(spy.calls.length, 0, 'no mutation may reach the subsystem');
    });
  });

  // =========================================================================
  // 10. Non-mutation REQUIRE_APPROVAL
  // =========================================================================

  describe('Non-mutation approval', () => {
    test('RC04-M-44: an external policy can require approval for a read and redemption executes it', async () => {
      const { server, approvals, filesystem } = makeServer({
        workspaceName: 'read-approval',
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('read_file', { ...params });
      assert.equal(body(first).code, 'APPROVAL_REQUIRED');
      const requestId = body(first).details.approvalRequestId;
      assert.match(String(body(first).details.expiresInSeconds), /^[0-9]+$/);

      const token = approvals.approve(requestId).token;
      const second = await server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(second.isError, undefined, 'the approved read executes');
      assert.equal(body(second).content, 'line1\nline2\nline3\n');
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
      assert.equal(filesystem.calls.length, 0, 'a read is not a mutation');
    });

    test('RC04-M-45: an invalid redemption never fabricates a new pending request', async () => {
      const { server, approvals } = makeServer({
        workspaceName: 'no-fabricate',
        policy: { sourceText: READ_APPROVAL_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };

      const before = approvals.listActive().length;
      for (const control of [
        { requestId: 'f'.repeat(32), token: 'f'.repeat(64) },
        { requestId: '0'.repeat(32), token: '0'.repeat(64) },
      ]) {
        const res = await server.dispatchToolCall('read_file', {
          ...params,
          _arcApproval: control,
        });
        assert.equal(body(res).code, 'APPROVAL_REJECTED');
      }
      assert.equal(approvals.listActive().length, before, 'no request may be created');
    });
  });
  // =========================================================================
  // 11. Task 4.1 blocker regressions
  // =========================================================================

  describe('Startup order, review visibility, root compatibility', () => {
    test('RC04-M-46: createArcMcpServer initializes the external policy AFTER registering configured roots', () => {
      const dir = fs.mkdtempSync(path.join(tempRoot, 'factory-ok-'));
      fs.writeFileSync(path.join(dir, 'README.md'), 'hello\n');
      const canonicalRoot = fs.realpathSync(dir);
      const rootHash = sha256Hex(canonicalRoot);

      const policy = `version: '1.0'
workspaces:
  - id: 'ws'
    rootHash: '${rootHash}'
rules:
  - id: 'allow-read'
    effect: 'ALLOW'
    tools: ['read_file']
`;
      // The REAL factory, not a helper with a pre-populated registry.
      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: dir }],
        defaultWorkspaceId: 'ws',
        policy: { sourceText: policy, format: 'yaml' },
      });

      assert.ok(server.effectivePolicyEngine, 'external policy must load');
      assert.equal(server.effectivePolicyEngine.getSourceMode(), 'EXTERNAL');
      assert.equal(server.policyInitializationFailure, undefined);
      assert.equal(server.workspaceRegistry.getWorkspace('ws').rootPath, canonicalRoot);
    });

    test('RC04-M-47: a factory-loaded external policy governs execution and health', async () => {
      const dir = fs.mkdtempSync(path.join(tempRoot, 'factory-run-'));
      fs.writeFileSync(path.join(dir, 'README.md'), 'external\n');
      const rootHash = sha256Hex(fs.realpathSync(dir));

      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: dir }],
        defaultWorkspaceId: 'ws',
        policy: {
          sourceText: `version: '1.0'
workspaces:
  - id: 'ws'
    rootHash: '${rootHash}'
rules:
  - id: 'allow-health'
    effect: 'ALLOW'
    tools: ['health']
  - id: 'allow-read'
    effect: 'ALLOW'
    tools: ['read_file']
`,
          format: 'yaml',
        },
      });

      const health = await server.dispatchToolCall('health', {});
      const healthBody = JSON.parse(health.content[0].text);
      assert.equal(healthBody.status, 'HEALTHY');
      assert.equal(healthBody.policyEngineActive, true);
      assert.equal(healthBody.stage, 'RC-06');

      // The external rule permits the read...
      const read = await server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      assert.equal(read.isError, undefined, JSON.stringify(read.content[0].text));
      // ...and does not permit anything it does not name.
      const other = await server.dispatchToolCall('list_directory', { workspaceId: 'ws' });
      assert.equal(JSON.parse(other.content[0].text).code, 'POLICY_DENIED');
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('RC04-M-48: a factory workspace rootHash mismatch stays fail-closed with no fallback', async () => {
      const dir = fs.mkdtempSync(path.join(tempRoot, 'factory-bad-'));
      fs.writeFileSync(path.join(dir, 'README.md'), 'x\n');
      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: dir }],
        defaultWorkspaceId: 'ws',
        policy: {
          sourceText: `version: '1.0'
workspaces:
  - id: 'ws'
    rootHash: '${'0'.repeat(64)}'
rules: []
`,
          format: 'yaml',
        },
      });

      assert.equal(server.effectivePolicyEngine, undefined, 'no engine on failure');
      assert.equal(server.policyInitializationFailure.reason, 'POLICY_LOAD_ERROR');

      const health = await server.dispatchToolCall('health', {});
      const healthBody = JSON.parse(health.content[0].text);
      assert.equal(healthBody.status, 'UNHEALTHY');
      assert.equal(healthBody.policyEngineActive, false);

      // Every non-diagnostic operation fails closed, with no built-in fallback.
      const read = await server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      assert.equal(JSON.parse(read.content[0].text).code, 'POLICY_LOAD_ERROR');
      const mutation = await server.dispatchToolCall('create_file', {
        path: 'n.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      assert.equal(JSON.parse(mutation.content[0].text).code, 'POLICY_LOAD_ERROR');
      assert.equal(server.approvalStateManager.listActive().length, 0);
      assert.equal(fs.existsSync(path.join(dir, 'n.txt')), false);
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('RC04-M-49: the operator can see the target path for create/write before approving', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'vis-create' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'visible.txt',
        content: 'body',
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;

      assert.deepEqual(summary.targetPaths, ['visible.txt']);
      assert.equal(summary.contentBytes, 4);
      assert.match(summary.contentHash, /^[0-9a-f]{64}$/);
      assert.ok(!JSON.stringify(summary).includes('body'), 'summary must not carry raw content');
      assert.equal(approvals.inspectPending(requestId), 'body');
    });

    test('RC04-M-50: the operator can see the delete target path and expected hash', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'vis-delete' });
      const hash = 'a'.repeat(64);
      const res = await server.dispatchToolCall('delete_file', {
        path: 'gone.txt',
        expectedHash: hash,
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, ['gone.txt']);
      assert.equal(summary.expectedHash, hash);
    });

    test('RC04-M-51: the operator can see both move paths and the source hash', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'vis-move' });
      const hash = 'b'.repeat(64);
      const res = await server.dispatchToolCall('move_file', {
        sourcePath: 'from.txt',
        destinationPath: 'to.txt',
        expectedSourceHash: hash,
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, ['from.txt', 'to.txt']);
      assert.equal(summary.expectedSourceHash, hash);
    });

    test('RC04-M-52: the operator can see every apply_patch target before approving', async () => {
      const { server, approvals, dir } = makeServer({ workspaceName: 'vis-patch' });
      fs.writeFileSync(path.join(dir, 'one.txt'), 'line1\nline2\nline3\n');
      fs.writeFileSync(path.join(dir, 'two.txt'), 'line1\nline2\nline3\n');
      const patch =
        '--- a/one.txt\n+++ b/one.txt\n@@ -1,3 +1,3 @@\n-line1\n+ONE\n line2\n line3\n' +
        '--- a/two.txt\n+++ b/two.txt\n@@ -1,3 +1,3 @@\n-line1\n+TWO\n line2\n line3\n';

      const res = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, ['one.txt', 'two.txt']);
      assert.equal(typeof summary.patchBytes, 'number');
      assert.match(summary.patchHash, /^[0-9a-f]{64}$/);
      assert.ok(!JSON.stringify(summary).includes('line1'), 'summary must not carry patch text');
      assert.equal(approvals.inspectPending(requestId), patch);
    });

    test('RC04-M-53: a valid workspace-relative target longer than 512 characters stays visible', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'vis-long' });
      // Multiple short segments so no OS component limit is approached.
      const longPath = Array.from(
        { length: 100 },
        (_, i) => `seg${String(i).padStart(3, '0')}`,
      ).join('/');
      assert.ok(longPath.length > 512 && longPath.length <= 1024, `length ${longPath.length}`);

      const res = await server.dispatchToolCall('create_file', {
        path: longPath,
        content: 'x',
        workspaceId: 'ws',
      });
      const parsed = body(res);
      assert.equal(parsed.code, 'APPROVAL_REQUIRED');
      const summary = approvals.getRequest(parsed.details.approvalRequestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, [longPath], 'a legal long path must not be dropped');
    });

    test('RC04-M-54: an absolute mutation path creates no approval and executes nothing', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'abs-path' });
      const absoluteInside = path.join(dir, 'abs.txt');
      for (const candidate of [absoluteInside, `/etc/passwd`, `C:/ws/abs.txt`]) {
        const res = await server.dispatchToolCall('create_file', {
          path: candidate,
          content: 'x',
          workspaceId: 'ws',
        });
        const parsed = body(res);
        assert.equal(parsed.code, 'POLICY_DENIED', `expected denial for ${candidate}`);
        assert.ok(
          !JSON.stringify(parsed).includes(candidate),
          'the absolute input must not be echoed',
        );
        assert.ok(!JSON.stringify(parsed).includes(dir), 'the host path must not be echoed');
      }
      assert.equal(approvals.listActive().length, 0, 'zero pending approvals');
      assert.equal(filesystem.calls.length, 0, 'zero subsystem execution');
      assert.equal(fs.existsSync(absoluteInside), false);
    });

    test('RC04-M-55: BUILTIN accepts an explicit workspace-root selector, traversal stays denied', async () => {
      const { server, dir } = makeServer({ workspaceName: 'root-compat' });
      fs.writeFileSync(path.join(dir, 'a.txt'), 'x\n');

      const listing = await server.dispatchToolCall('list_directory', {
        path: '.',
        recursive: true,
        maxDepth: 2,
        workspaceId: 'ws',
      });
      assert.equal(listing.isError, undefined, JSON.stringify(listing.content[0].text));
      const entries = JSON.parse(listing.content[0].text).entries;
      assert.ok(entries.some((e) => e.name === 'a.txt'));

      // Traversal and other unsafe targets remain denied.
      for (const bad of ['../outside', '../../etc/passwd', 'a\\b']) {
        const res = await server.dispatchToolCall('list_directory', {
          path: bad,
          workspaceId: 'ws',
        });
        assert.equal(body(res).code, 'POLICY_DENIED', `expected denial for ${bad}`);
      }
    });

    test('RC04-M-56: an EXTERNAL policy still fails an explicit root selector closed', async () => {
      const { server } = makeServer({
        workspaceName: 'root-external',
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'allow-list'\n    effect: 'ALLOW'\n    tools: ['list_directory']\n`,
          format: 'yaml',
        },
      });
      // The frozen v1 external grammar cannot express the workspace root, so the
      // target is unrepresentable and the request fails closed rather than
      // silently dropping the path (which would let a `paths` rule miss).
      const res = await server.dispatchToolCall('list_directory', { path: '.', workspaceId: 'ws' });
      assert.equal(body(res).code, 'POLICY_DENIED');
    });

    test('RC04-M-57: reviewSummary never carries raw material, a token, or a host path', async () => {
      const contentMarker = 'RC04_SUMMARY_LEAK_MARKER_7733';
      const patchMarker = 'RC04_SUMMARY_PATCH_MARKER_8844';
      const { server, approvals } = makeServer({ workspaceName: 'summary-leak' });

      const create = await server.dispatchToolCall('create_file', {
        path: 'leak.txt',
        content: contentMarker,
        workspaceId: 'ws',
      });
      const createId = body(create).details.approvalRequestId;
      const patch = `--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n-line1\n+${patchMarker}\n line2\n line3\n`;
      const patchRes = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const patchId = body(patchRes).details.approvalRequestId;

      for (const requestId of [createId, patchId]) {
        const snapshot = approvals.getRequest(requestId);
        const serialized = JSON.stringify(snapshot.reviewSummary);
        assert.ok(!serialized.includes(contentMarker), 'raw content must not appear');
        assert.ok(!serialized.includes(patchMarker), 'raw patch text must not appear');
        assert.ok(!serialized.includes(tempRoot), 'an absolute host path must not appear');
        assert.ok(!serialized.includes('token'), 'no token field may appear');
        // Only the two documented digest fields may be 64-hex values.
        for (const [key, value] of Object.entries(snapshot.reviewSummary)) {
          if (typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)) {
            assert.ok(
              ['contentHash', 'patchHash'].includes(key),
              `unexpected 64-hex field '${key}' in reviewSummary`,
            );
          }
        }
      }
    });
  });
  // =========================================================================
  // 12. Task 4.2: canonical review targets and move fail-closed completeness
  // =========================================================================

  describe('Canonical review targets', () => {
    test('RC04-M-58: move_file fails the WHOLE request closed when either path is unsafe', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'move-block' });
      fs.writeFileSync(path.join(dir, 'from.txt'), 'move me\n');
      const absoluteInside = path.join(dir, 'abs.txt');
      const nulName = `bad${String.fromCharCode(0)}name.txt`;

      const unsafeOperands = [
        absoluteInside,
        '/etc/passwd',
        'C:/ws/x.txt',
        '../outside.txt',
        '../../etc/passwd',
        'bad\\name.txt',
        nulName,
      ];

      let index = 0;
      for (const unsafe of unsafeOperands) {
        for (const side of ['source', 'destination']) {
          index++;
          const safe = `safe-${index}.txt`;
          const params =
            side === 'source'
              ? { sourcePath: unsafe, destinationPath: safe, expectedSourceHash: '0'.repeat(64) }
              : {
                  sourcePath: 'from.txt',
                  destinationPath: unsafe,
                  expectedSourceHash: '0'.repeat(64),
                };

          const res = await server.dispatchToolCall('move_file', { ...params, workspaceId: 'ws' });
          const parsed = body(res);
          assert.equal(
            parsed.code,
            'POLICY_DENIED',
            `${side}=${JSON.stringify(unsafe)} must deny the whole request`,
          );
          assert.ok(!JSON.stringify(parsed).includes(dir), 'host path must not be echoed');
          assert.ok(parsed.message !== undefined);
        }
      }

      // Zero approvals, zero consumption, zero filesystem invocation.
      assert.equal(approvals.listActive().length, 0, 'no approval may be created');
      assert.equal(filesystem.calls.length, 0, 'no subsystem invocation');
      assert.equal(fs.existsSync(path.join(dir, 'from.txt')), true, 'source untouched');
      assert.equal(filesystem.calls.filter((c) => c.method === 'moveFile').length, 0);
    });

    test('RC04-M-59: an absolute move source or destination never creates an approval', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'move-abs' });
      fs.writeFileSync(path.join(dir, 'from.txt'), 'x\n');
      const absolute = path.join(dir, 'from.txt');

      // Absolute source, safe destination.
      const forward = await server.dispatchToolCall('move_file', {
        sourcePath: absolute,
        destinationPath: 'safe.txt',
        expectedSourceHash: '0'.repeat(64),
        workspaceId: 'ws',
      });
      assert.equal(body(forward).code, 'POLICY_DENIED');

      // Safe source, absolute destination.
      const reverse = await server.dispatchToolCall('move_file', {
        sourcePath: 'from.txt',
        destinationPath: absolute,
        expectedSourceHash: '0'.repeat(64),
        workspaceId: 'ws',
      });
      assert.equal(body(reverse).code, 'POLICY_DENIED');

      assert.equal(approvals.listActive().length, 0);
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-M-60: reviewSummary shows the canonical target, not the raw spelling', async () => {
      const { server, approvals, dir } = makeServer({ workspaceName: 'canon-create' });
      const res = await server.dispatchToolCall('create_file', {
        path: 'dir/../actual.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, ['actual.txt'], 'the operator reviews the real target');
      void dir;
    });

    test('RC04-M-61: move_file reviewSummary shows both canonical targets', async () => {
      const { server, approvals, dir } = makeServer({ workspaceName: 'canon-move' });
      fs.writeFileSync(path.join(dir, 'from.txt'), 'x\n');
      const res = await server.dispatchToolCall('move_file', {
        sourcePath: 'src/../from.txt',
        destinationPath: 'tmp/../to.txt',
        expectedSourceHash: '0'.repeat(64),
        workspaceId: 'ws',
      });
      const requestId = body(res).details.approvalRequestId;
      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(summary.targetPaths, ['from.txt', 'to.txt']);
    });

    test('RC04-M-62: apply_patch reviewSummary keeps parser-derived canonical targets', async () => {
      const { server, approvals, dir } = makeServer({ workspaceName: 'canon-patch' });
      fs.writeFileSync(path.join(dir, 'p.txt'), 'line1\nline2\nline3\n');
      const patch = '--- a/p.txt\n+++ b/p.txt\n@@ -1,3 +1,3 @@\n-line1\n+P\n line2\n line3\n';
      const res = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const requestId = body(res).details.approvalRequestId;
      assert.deepEqual(approvals.getRequest(requestId).reviewSummary.targetPaths, ['p.txt']);
    });

    test('RC04-M-63: a non-canonical but legal path is reviewed canonically and executes there', async () => {
      const { server, approvals, filesystem, dir } = makeServer({ workspaceName: 'canon-exec' });
      fs.mkdirSync(path.join(dir, 'nested'), { recursive: true });

      // The filesystem accepts `nested/../actual.txt`; the operator must be shown
      // the canonical `actual.txt` BEFORE approving.
      const params = { path: 'nested/../actual.txt', content: 'landed\n', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const firstBody = body(first);
      assert.equal(firstBody.code, 'APPROVAL_REQUIRED');
      const requestId = firstBody.details.approvalRequestId;

      const summary = approvals.getRequest(requestId).reviewSummary;
      assert.deepEqual(
        summary.targetPaths,
        ['actual.txt'],
        'human-reviewed target must be the canonical target',
      );
      assert.equal(fs.existsSync(path.join(dir, 'actual.txt')), false, 'nothing yet');

      const token = approvals.approve(requestId).token;
      const second = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(second.isError, undefined, JSON.stringify(body(second)));
      assert.equal(fs.readFileSync(path.join(dir, 'actual.txt'), 'utf8'), 'landed\n');
      assert.equal(filesystem.calls.length, 1);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');
    });

    test('RC04-M-64: executionPayloadHash still binds the exact validated business parameters', async () => {
      const { server, approvals } = makeServer({ workspaceName: 'canon-hash' });

      // Two spellings that canonicalize to the SAME review target are still two
      // DIFFERENT business requests, so they must not collide in the approval
      // binding or dedup.
      const plain = await server.dispatchToolCall('create_file', {
        path: 'same.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      const spelled = await server.dispatchToolCall('create_file', {
        path: './same.txt',
        content: 'x',
        workspaceId: 'ws',
      });

      const plainId = body(plain).details.approvalRequestId;
      const spelledId = body(spelled).details.approvalRequestId;
      assert.notEqual(plainId, spelledId, 'distinct business requests must not dedup');

      // ...while both present the SAME canonical target to the operator.
      assert.deepEqual(approvals.getRequest(plainId).reviewSummary.targetPaths, ['same.txt']);
      assert.deepEqual(approvals.getRequest(spelledId).reviewSummary.targetPaths, ['same.txt']);
      assert.equal(approvals.listActive().length, 2);

      // The stored hashes differ, proving the raw validated params are bound.
      assert.notEqual(
        approvals.getRequest(plainId).executionPayloadHash,
        approvals.getRequest(spelledId).executionPayloadHash,
      );
    });
  });
  // =========================================================================
  // 13. Task 4.3: no target-less mutation approval
  // =========================================================================

  describe('Root mutation targets are blocked', () => {
    test('RC04-M-65: BUILTIN create/write/delete with a root selector is denied with no approval', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'root-mut-block' });

      const requests = [
        ['create_file', { path: '.', content: 'x' }],
        ['create_file', { path: './', content: 'x' }],
        ['write_file', { path: '.', content: 'x', expectedHash: '0'.repeat(64), overwrite: true }],
        ['delete_file', { path: '.', expectedHash: '0'.repeat(64) }],
      ];

      for (const [tool, params] of requests) {
        const res = await server.dispatchToolCall(tool, { ...params, workspaceId: 'ws' });
        const parsed = body(res);
        assert.equal(
          parsed.code,
          'POLICY_DENIED',
          `${tool} ${JSON.stringify(params.path)} must be denied, got ${parsed.code}`,
        );
      }

      assert.equal(approvals.listActive().length, 0, 'zero approval records');
      assert.equal(filesystem.calls.length, 0, 'zero subsystem calls');
    });

    test('RC04-M-66: BUILTIN list_directory with a root selector still succeeds', async () => {
      const { server, dir } = makeServer({ workspaceName: 'root-mut-compat' });
      fs.writeFileSync(path.join(dir, 'visible.txt'), 'x\n');

      const res = await server.dispatchToolCall('list_directory', {
        path: '.',
        recursive: true,
        maxDepth: 2,
        workspaceId: 'ws',
      });
      assert.equal(res.isError, undefined, JSON.stringify(res.content[0].text));
      const entries = JSON.parse(res.content[0].text).entries;
      assert.ok(entries.some((e) => e.name === 'visible.txt'));
    });

    test('RC04-M-67: move_file root operands and unrepresentable patch targets stay denied', async () => {
      const { server, approvals, filesystem } = makeServer({ workspaceName: 'root-mut-others' });

      for (const params of [
        { sourcePath: '.', destinationPath: 'x.txt', expectedSourceHash: '0'.repeat(64) },
        { sourcePath: 'x.txt', destinationPath: '.', expectedSourceHash: '0'.repeat(64) },
        { sourcePath: '.', destinationPath: '.', expectedSourceHash: '0'.repeat(64) },
      ]) {
        const res = await server.dispatchToolCall('move_file', { ...params, workspaceId: 'ws' });
        assert.equal(body(res).code, 'POLICY_DENIED', JSON.stringify(params));
      }

      // A patch whose declared target is the root or otherwise unrepresentable.
      for (const patch of [
        '--- a/.\n+++ b/.\n@@ -1 +1 @@\n-a\n+b\n',
        '--- a/../outside.txt\n+++ b/../outside.txt\n@@ -1 +1 @@\n-a\n+b\n',
      ]) {
        const res = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
        // The authoritative parser accepts both spellings; the canonical-target
        // derivation then blocks them, so the denial is POLICY_DENIED.
        assert.equal(body(res).code, 'POLICY_DENIED', patch.split('\n')[0]);
      }

      assert.equal(approvals.listActive().length, 0);
      assert.equal(filesystem.calls.length, 0);
    });

    test('RC04-M-68: every mutation approval carries a complete review target list', async () => {
      const { server, approvals, dir } = makeServer({ workspaceName: 'target-invariant' });
      fs.writeFileSync(path.join(dir, 'inv.txt'), 'line1\nline2\nline3\n');
      fs.writeFileSync(path.join(dir, 'inv2.txt'), 'line1\nline2\nline3\n');

      const twoFilePatch =
        '--- a/inv.txt\n+++ b/inv.txt\n@@ -1,3 +1,3 @@\n-line1\n+A\n line2\n line3\n' +
        '--- a/inv2.txt\n+++ b/inv2.txt\n@@ -1,3 +1,3 @@\n-line1\n+B\n line2\n line3\n';

      const cases = [
        ['create_file', { path: 'inv-new.txt', content: 'x' }, 1],
        [
          'write_file',
          { path: 'inv.txt', content: 'y', expectedHash: '0'.repeat(64), overwrite: true },
          1,
        ],
        ['delete_file', { path: 'inv.txt', expectedHash: '0'.repeat(64) }, 1],
        [
          'move_file',
          {
            sourcePath: 'inv.txt',
            destinationPath: 'moved.txt',
            expectedSourceHash: '0'.repeat(64),
          },
          2,
        ],
        ['apply_patch', { patch: twoFilePatch }, 2],
      ];

      for (const [tool, params, expectedTargetCount] of cases) {
        const res = await server.dispatchToolCall(tool, { ...params, workspaceId: 'ws' });
        const parsed = body(res);
        assert.equal(parsed.code, 'APPROVAL_REQUIRED', `${tool} must require approval`);

        const snapshot = approvals.getRequest(parsed.details.approvalRequestId);
        assert.ok(snapshot.reviewSummary, `${tool}: reviewSummary must be present`);
        assert.ok(
          Array.isArray(snapshot.reviewSummary.targetPaths),
          `${tool}: targetPaths must be present`,
        );
        assert.ok(
          snapshot.reviewSummary.targetPaths.length >= 1,
          `${tool}: a mutation approval must never be target-less`,
        );
        assert.equal(
          snapshot.reviewSummary.targetPaths.length,
          expectedTargetCount,
          `${tool}: every required mutation target must be listed`,
        );
        for (const path of snapshot.reviewSummary.targetPaths) {
          assert.ok(path.length > 0, `${tool}: target path must be non-empty`);
          assert.ok(!path.startsWith('/'), `${tool}: target path must be workspace-relative`);
        }
      }
    });

    test('RC04-M-69: advertised MCP server metadata reports the RC-04 version', () => {
      const { server } = makeServer({ workspaceName: 'server-identity' });

      // The SDK `Server` instance holds the metadata that every connecting MCP
      // client receives in the `initialize` result. `server.server` is the
      // constructed SDK object; the field is read directly because exposing a
      // production getter solely for a test would widen the server's surface.
      const sdkServer = server.server;
      assert.ok(sdkServer !== undefined, 'the MCP SDK server instance must exist');

      const serverInfo = sdkServer._serverInfo;
      assert.ok(
        serverInfo !== null && typeof serverInfo === 'object',
        'the SDK server instance must carry its advertised identity metadata',
      );
      assert.equal(serverInfo.name, 'cesspace-arc');
      assert.equal(
        serverInfo.version,
        '0.6.0-rc06',
        'the advertised MCP server metadata must report the RC-06 stage version',
      );
      assert.notEqual(
        serverInfo.version,
        '0.5.0-rc05',
        'the advertised MCP server metadata must not still report the RC-05 version',
      );
    });
  });
});
