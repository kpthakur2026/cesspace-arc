import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import {
  ArcMcpServer,
  ProcessAuditSink,
  createArcMcpServer,
} from '../apps/mcp-server/dist/index.js';
import {
  ApprovalAuditSink,
  MAX_PENDING_LIFECYCLE_EVENTS,
} from '../apps/mcp-server/dist/approval-audit.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  attachApprovalFailureReason,
  getApprovalFailureReason,
  sha256Hex,
} from '../packages/policy/dist/index.js';
import { AuditLogger, canonicalJson, computeSha256 } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

let tempRoot;
const created = [];

/** Creates a fresh real workspace directory for a test. */
function makeWorkspace(label) {
  const dir = fs.mkdtempSync(path.join(tempRoot, `${label}-`));
  fs.writeFileSync(path.join(dir, 'README.md'), 'line1\nline2\nline3\n');
  fs.writeFileSync(path.join(dir, 'keep.txt'), 'keep\n');
  created.push(dir);
  return dir;
}

/** Builds a server with a real workspace, controllable clock and audit capture. */
function makeServer({ label = 'ws', manager, policy } = {}) {
  const dir = makeWorkspace(label);
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', dir);

  const audit = new AuditLogger();
  const approvals = manager ?? new ApprovalStateManager();
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    audit,
    new FilesystemSubsystem(),
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
  return { server, registry, approvals, audit, dir };
}

function body(res) {
  return JSON.parse(res.content[0].text);
}

/** Lifecycle records only (Task-5 additions). */
function lifecycle(audit) {
  return audit.getRecords().filter((r) => r.approval?.eventType !== undefined);
}

/** Ordinary invocation records only. */
function invocations(audit) {
  return audit.getRecords().filter((r) => r.approval?.eventType === undefined);
}

function eventsOf(audit) {
  return lifecycle(audit).map((r) => r.approval.eventType);
}

/** Runs request -> operator approve -> redeem, returning the identifiers. */
async function approveAndRedeem(server, approvals, toolName, params, actorOverride) {
  const first = await server.dispatchToolCall(toolName, { ...params }, actorOverride);
  const firstBody = body(first);
  assert.equal(firstBody.code, 'APPROVAL_REQUIRED');
  const requestId = firstBody.details.approvalRequestId;
  const token = approvals.approve(requestId).token;
  const second = await server.dispatchToolCall(
    toolName,
    { ...params, _arcApproval: { requestId, token } },
    actorOverride,
  );
  return { requestId, token, second, secondBody: body(second) };
}

const REQUIRE_READ_POLICY = `version: '1.0'
rules:
  - id: 'require-read'
    effect: 'REQUIRE_APPROVAL'
    tools: ['read_file']
`;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-audit-'));
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

describe('CesSpace ARC — RC-04 Task 5: Security Hardening & Approval Audit Lifecycle', () => {
  // =========================================================================
  // 1. Lifecycle exactness
  // =========================================================================

  describe('Lifecycle event exactness', () => {
    test('RC04-S-01: APPROVAL_REQUESTED is emitted exactly once for a new record', async () => {
      const { server, audit } = makeServer({ label: 'req-once' });
      const params = { path: 'n.txt', content: 'x', workspaceId: 'ws' };

      await server.dispatchToolCall('create_file', { ...params });
      assert.deepEqual(eventsOf(audit), ['APPROVAL_REQUESTED']);

      // Deduplicated retries must NOT produce a second lifecycle REQUESTED.
      await server.dispatchToolCall('create_file', { ...params });
      await server.dispatchToolCall('create_file', { ...params });
      assert.deepEqual(eventsOf(audit), ['APPROVAL_REQUESTED']);
      // The ordinary invocation record is still written for each retry.
      assert.equal(invocations(audit).length, 3);

      const record = lifecycle(audit)[0];
      assert.equal(record.approval.source, 'MCP');
      assert.equal(record.target.workspacePath, '');
      assert.match(record.target.workspaceRootHash, /^[0-9a-f]{64}$/);
    });

    test('RC04-S-02: no second APPROVAL_REQUESTED while APPROVED', async () => {
      const { server, approvals, audit } = makeServer({ label: 'req-approved' });
      const params = { path: 'n.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      approvals.approve(requestId);

      await server.dispatchToolCall('create_file', { ...params });
      assert.deepEqual(eventsOf(audit), ['APPROVAL_REQUESTED', 'APPROVAL_GRANTED']);
    });

    test('RC04-S-03: a terminal transition emits exactly one lifecycle event', async () => {
      const { server, approvals, audit, dir } = makeServer({ label: 'terminal-once' });
      const params = { path: 'once.txt', content: 'x', workspaceId: 'ws' };
      const { requestId } = await approveAndRedeem(server, approvals, 'create_file', params);

      // Repeated reads of a terminal record must not emit again.
      for (let i = 0; i < 3; i++) {
        approvals.getRequest(requestId);
        approvals.listActive();
        approvals.purgeExpired();
      }
      assert.deepEqual(eventsOf(audit), [
        'APPROVAL_REQUESTED',
        'APPROVAL_GRANTED',
        'APPROVAL_CONSUMED',
        'APPROVED_EXECUTION_SUCCEEDED',
      ]);
      assert.equal(fs.readFileSync(path.join(dir, 'once.txt'), 'utf8'), 'x');
    });

    test('RC04-S-04: expiry is emitted exactly once regardless of which API discovers it', async () => {
      let mono = 1_000_000n;
      const manager = new ApprovalStateManager({ getMonotonicTime: () => mono });
      const { server, audit } = makeServer({ label: 'expiry-once', manager });
      const params = { path: 'e.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;

      mono += 301_000n * 1_000_000n;
      manager.getRequest(requestId);
      manager.listActive();
      manager.inspectPending(requestId);
      manager.purgeExpired();
      manager.purgeExpired();

      // The sink buffers synchronously; flush before asserting on the chain.
      await server.flushAudit();

      const expired = eventsOf(audit).filter((e) => e === 'APPROVAL_EXPIRED');
      assert.equal(expired.length, 1, 'exactly one APPROVAL_EXPIRED');
      assert.equal(eventsOf(audit).includes('APPROVAL_REJECTED'), false);
    });

    test('RC04-S-05: approved execution emits SUCCEEDED once, with correlation', async () => {
      const { server, approvals, audit } = makeServer({ label: 'exec-success' });
      const params = { path: 'ok.txt', content: 'done', workspaceId: 'ws' };
      const { requestId } = await approveAndRedeem(server, approvals, 'create_file', params);

      assert.deepEqual(eventsOf(audit), [
        'APPROVAL_REQUESTED',
        'APPROVAL_GRANTED',
        'APPROVAL_CONSUMED',
        'APPROVED_EXECUTION_SUCCEEDED',
      ]);
      for (const record of lifecycle(audit)) {
        assert.equal(record.approval.requestId, requestId, 'same requestId correlation');
        assert.equal(record.policy.approvalId, requestId);
      }
      // The ordinary execution record is not pretending to be an ALLOW.
      const exec = invocations(audit).at(-1);
      assert.equal(exec.policy.decision, 'REQUIRE_APPROVAL');
      assert.equal(exec.policy.approvalId, requestId);
    });

    test('RC04-S-06: approved execution failure emits FAILED once and stays CONSUMED', async () => {
      const { server, approvals, audit } = makeServer({ label: 'exec-fail' });
      const params = {
        path: 'README.md',
        content: 'x',
        expectedHash: '0'.repeat(64),
        overwrite: true,
        workspaceId: 'ws',
      };
      const { requestId, token } = await approveAndRedeem(server, approvals, 'write_file', params);

      assert.deepEqual(eventsOf(audit), [
        'APPROVAL_REQUESTED',
        'APPROVAL_GRANTED',
        'APPROVAL_CONSUMED',
        'APPROVED_EXECUTION_FAILED',
      ]);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');

      const replay = await server.dispatchToolCall('write_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(eventsOf(audit).filter((e) => e.startsWith('APPROVED_EXECUTION')).length, 1);
    });

    test('RC04-S-07: operator rejection emits one LOCAL_OPERATOR APPROVAL_REJECTED', async () => {
      const { server, approvals, audit } = makeServer({ label: 'reject-once' });
      const first = await server.dispatchToolCall('create_file', {
        path: 'r.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      const requestId = body(first).details.approvalRequestId;

      approvals.reject(requestId, 'operator supplied secret-ish text');
      await server.flushAudit();

      const rejected = lifecycle(audit).filter((r) => r.approval.eventType === 'APPROVAL_REJECTED');
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].approval.source, 'LOCAL_OPERATOR');
      // The raw operator reason is never retained anywhere.
      assert.ok(
        !JSON.stringify(audit.getRecords()).includes('operator supplied secret-ish text'),
        'raw operator reason must not be audited',
      );
    });
  });

  // =========================================================================
  // 2. Internal diagnostics vs anti-oracle
  // =========================================================================

  describe('Internal diagnostics', () => {
    test('RC04-S-08: reason codes are attached internally and never serialized', () => {
      const err = attachApprovalFailureReason(ArcError.approvalRejected(), 'TOKEN_MISMATCH');
      assert.equal(getApprovalFailureReason(err), 'TOKEN_MISMATCH');
      assert.equal(JSON.stringify(err).includes('TOKEN_MISMATCH'), false);
      assert.equal(JSON.stringify(err.toJSON()).includes('TOKEN_MISMATCH'), false);
      assert.equal(Object.keys(err.details ?? {}).includes('reasonCode'), false);
      assert.equal(getApprovalFailureReason({}), undefined);
      assert.equal(getApprovalFailureReason(null), undefined);
      assert.equal(getApprovalFailureReason('nope'), undefined);
    });

    test('RC04-S-09: each tampering class maps to the frozen internal reason code', async () => {
      const { server, approvals } = makeServer({ label: 'reasons' });
      const params = { path: 'r.txt', content: 'x', workspaceId: 'ws' };
      const actor = { clientId: 'alice', clientType: 'cli', sessionId: 's1', deviceId: 'd1' };

      const first = await server.dispatchToolCall('create_file', { ...params }, actor);
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      // NOTE: an actor change through the MCP path reports
      // PAYLOAD_BINDING_MISMATCH, because the actor identity is bound INTO
      // executionPayloadHash and that check runs first. ACTOR_BINDING_MISMATCH
      // is the manager-level defense-in-depth check, exercised in S-09b.
      const cases = [
        [
          'wrong token',
          { ...params, _arcApproval: { requestId, token: 'f'.repeat(64) } },
          actor,
          'TOKEN_MISMATCH',
        ],
        [
          'payload change',
          { ...params, content: 'tampered', _arcApproval: { requestId, token } },
          actor,
          'PAYLOAD_BINDING_MISMATCH',
        ],
        [
          'actor change',
          { ...params, _arcApproval: { requestId, token } },
          { ...actor, sessionId: 's2' },
          'PAYLOAD_BINDING_MISMATCH',
        ],
      ];

      for (const [label, callParams, callActor, expectedReason] of cases) {
        const res = await server.dispatchToolCall('create_file', callParams, callActor);
        const parsed = body(res);
        assert.equal(parsed.code, 'APPROVAL_REJECTED', label);
        assert.equal(
          JSON.stringify(parsed).includes(expectedReason),
          false,
          `${label}: leaked reason`,
        );
        assert.equal(label.length > 0, true);

        const failed = invocations(server.auditLogger).filter(
          (r) => r.approval?.reasonCode !== undefined,
        );
        assert.ok(
          failed.some((r) => r.approval.reasonCode === expectedReason),
          `${label}: expected internal reason ${expectedReason}`,
        );
      }
    });

    test('RC04-S-09b: the manager reports ACTOR and WORKSPACE binding mismatches directly', () => {
      const binding = {
        actor: { clientId: 'alice', clientType: 'cli', sessionId: 's1', deviceId: 'd1' },
        workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
        policyHash: 'c'.repeat(64),
      };

      // Actor mismatch with a deliberately MATCHING payload hash, so the actor
      // check is the one that fails. This is reachable only at the manager
      // level, since the MCP path binds the actor into the payload hash.
      const actorManager = new ApprovalStateManager();
      const actorRequest = actorManager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: 'a'.repeat(64),
        binding,
      });
      const actorToken = actorManager.approve(actorRequest.requestId).token;
      let actorErr;
      try {
        actorManager.redeemAndConsume({
          requestId: actorRequest.requestId,
          token: actorToken,
          executionPayloadHash: 'a'.repeat(64),
          actor: { ...binding.actor, sessionId: 'DIFFERENT' },
          workspace: binding.workspace,
          policyHash: binding.policyHash,
        });
      } catch (err) {
        actorErr = err;
      }
      assert.equal(getApprovalFailureReason(actorErr), 'ACTOR_BINDING_MISMATCH');
      assert.equal(JSON.stringify(actorErr).includes('ACTOR_BINDING_MISMATCH'), false);

      const wsManager = new ApprovalStateManager();
      const wsRequest = wsManager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: 'd'.repeat(64),
        binding,
      });
      const wsToken = wsManager.approve(wsRequest.requestId).token;
      let wsErr;
      try {
        wsManager.redeemAndConsume({
          requestId: wsRequest.requestId,
          token: wsToken,
          executionPayloadHash: 'd'.repeat(64),
          actor: binding.actor,
          workspace: { workspaceId: 'ws', workspaceRootHash: 'e'.repeat(64) },
          policyHash: binding.policyHash,
        });
      } catch (err) {
        wsErr = err;
      }
      assert.equal(getApprovalFailureReason(wsErr), 'WORKSPACE_BINDING_MISMATCH');
      assert.equal(JSON.stringify(wsErr).includes('WORKSPACE_BINDING_MISMATCH'), false);
    });

    test('RC04-S-10: ALREADY_CONSUMED is the internal reason for a replay', async () => {
      const { server, approvals } = makeServer({ label: 'consumed-reason' });
      const params = { path: 'c.txt', content: 'x', workspaceId: 'ws' };
      const { requestId, token } = await approveAndRedeem(server, approvals, 'create_file', params);

      const replay = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.ok(!JSON.stringify(body(replay)).includes('ALREADY_CONSUMED'));

      const reasons = invocations(server.auditLogger)
        .map((r) => r.approval?.reasonCode)
        .filter(Boolean);
      assert.ok(reasons.includes('ALREADY_CONSUMED'));
    });

    test('RC04-S-11: WORKSPACE_BINDING_MISMATCH is internal, and never executes elsewhere', async () => {
      const { server, approvals, dir } = makeServer({ label: 'ws-reason' });
      const otherDir = fs.mkdtempSync(path.join(tempRoot, 'other-ws-'));
      created.push(otherDir);
      server.workspaceRegistry.registerWorkspace('other', otherDir);

      const params = { path: 'w.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;

      const res = await server.dispatchToolCall('create_file', {
        ...params,
        workspaceId: 'other',
        _arcApproval: { requestId, token },
      });
      const code = body(res).code;
      assert.ok(code === 'APPROVAL_REJECTED' || code === 'POLICY_DENIED');
      assert.equal(fs.existsSync(path.join(otherDir, 'w.txt')), false);
      assert.equal(fs.existsSync(path.join(dir, 'w.txt')), false);
    });
  });

  // =========================================================================
  // 3. Concurrency and races
  // =========================================================================

  describe('Concurrency and races', () => {
    test('RC04-S-12: 16-way concurrent redemption consumes exactly once', async () => {
      const { server, approvals, audit } = makeServer({ label: 'race-16' });
      const params = { path: 'race.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      await server.flushAudit();

      const envelope = { ...params, _arcApproval: { requestId, token } };
      const results = await Promise.all(
        Array.from({ length: 16 }, () => server.dispatchToolCall('create_file', { ...envelope })),
      );

      const succeeded = results.filter((r) => r.isError === undefined);
      const rejected = results.filter((r) => body(r).code === 'APPROVAL_REJECTED');
      assert.equal(succeeded.length, 1, 'exactly one redemption may succeed');
      assert.equal(rejected.length, 15);

      const events = eventsOf(audit);
      assert.equal(events.filter((e) => e === 'APPROVAL_CONSUMED').length, 1);
      assert.equal(events.filter((e) => e.startsWith('APPROVED_EXECUTION')).length, 1);
      assert.equal(approvals.getRequest(requestId).state, 'CONSUMED');

      // Every losing attempt records ALREADY_CONSUMED internally.
      const consumedReasons = invocations(audit).filter(
        (r) => r.approval?.reasonCode === 'ALREADY_CONSUMED',
      );
      assert.ok(consumedReasons.length >= 1);
    });

    test('RC04-S-13: 16-way concurrent identical creation yields one record and one event', async () => {
      const { server, approvals, audit } = makeServer({ label: 'race-create' });
      const params = { path: 'same.txt', content: 'x', workspaceId: 'ws' };

      const results = await Promise.all(
        Array.from({ length: 16 }, () => server.dispatchToolCall('create_file', { ...params })),
      );
      const ids = new Set(results.map((r) => body(r).details.approvalRequestId));
      assert.equal(ids.size, 1, 'one requestId');
      assert.equal(approvals.listActive().length, 1, 'one active record');
      assert.equal(eventsOf(audit).filter((e) => e === 'APPROVAL_REQUESTED').length, 1);
      assert.equal(invocations(audit).length, 16);
    });

    test('RC04-S-14: approve/reject race yields exactly one terminal outcome', () => {
      const manager = new ApprovalStateManager();
      const snapshot = manager.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'c', clientType: 't' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        },
      });

      let approved = 0;
      let rejected = 0;
      for (let i = 0; i < 16; i++) {
        try {
          if (i % 2 === 0) {
            manager.approve(snapshot.requestId);
            approved++;
          } else {
            manager.reject(snapshot.requestId);
            rejected++;
          }
        } catch {
          // losing attempts fail safely
        }
      }
      assert.equal(approved + rejected, 1, 'exactly one terminal action wins');
      const state = manager.getRequest(snapshot.requestId).state;
      assert.ok(state === 'APPROVED' || state === 'REJECTED');
    });

    test('RC04-S-15: expiry beats approval and consumption at the exact deadline', async () => {
      let mono = 5_000_000n;
      const manager = new ApprovalStateManager({ getMonotonicTime: () => mono });
      const { server, audit } = makeServer({ label: 'deadline', manager });
      const params = { path: 'd.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;

      mono += 300_000n * 1_000_000n; // exactly at the deadline
      assert.throws(
        () => manager.approve(requestId),
        (err) => err.code === 'APPROVAL_EXPIRED',
      );
      assert.equal(manager.getRequest(requestId).state, 'EXPIRED');
      await server.flushAudit();

      // A later attempt cannot change the terminal state. The manager reports the
      // record's actual expired condition rather than a fresh rejection.
      assert.throws(
        () => manager.reject(requestId),
        (err) => err.code === 'APPROVAL_EXPIRED',
      );
      assert.equal(
        eventsOf(audit).filter((e) => e === 'APPROVAL_EXPIRED').length,
        1,
        'exactly one APPROVAL_EXPIRED',
      );
      assert.ok(!eventsOf(audit).includes('APPROVAL_GRANTED'));
    });

    test('RC04-S-16: wall-clock rollback cannot extend the TTL', async () => {
      let mono = 1_000n * 1_000_000n;
      let wall = 1_700_000_000_000;
      const manager = new ApprovalStateManager({
        getMonotonicTime: () => mono,
        getWallTime: () => wall,
      });
      const { server, audit } = makeServer({ label: 'rollback', manager });
      const params = { path: 'rb.txt', content: 'x', workspaceId: 'ws' };
      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;

      // Move the DISPLAY clock far back, then advance the monotonic clock.
      wall -= 86_400_000;
      mono += 300_000n * 1_000_000n;

      assert.throws(
        () => manager.approve(requestId),
        (err) => err.code === 'APPROVAL_EXPIRED',
      );
      assert.equal(manager.getRequest(requestId).state, 'EXPIRED');
      await server.flushAudit();
      assert.equal(eventsOf(audit).filter((e) => e === 'APPROVAL_EXPIRED').length, 1);
    });
  });

  // =========================================================================
  // 4. Policy invalidation
  // =========================================================================

  describe('Policy invalidation', () => {
    test('RC04-S-17: policy mismatch invalidates once and reversion cannot revive it', async () => {
      const manager = new ApprovalStateManager();
      const original = makeServer({
        label: 'policy-inval',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };
      const first = await original.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = manager.approve(requestId).token;
      await original.server.flushAudit();

      // Same manager, same requirement, DIFFERENT policy hash.
      const changed = makeServer({
        label: 'policy-inval',
        manager,
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'require-read-v2'\n    effect: 'REQUIRE_APPROVAL'\n    tools: ['read_file']\n`,
          format: 'yaml',
        },
      });
      const res = await changed.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');

      const invalidated = lifecycle(changed.audit).filter(
        (r) => r.approval.eventType === 'APPROVAL_INVALIDATED',
      );
      assert.equal(invalidated.length, 1);
      assert.equal(invalidated[0].approval.reasonCode, 'POLICY_BINDING_MISMATCH');

      // Reverting the policy must not revive it, nor emit a second event.
      const reverted = makeServer({
        label: 'policy-inval',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const again = await reverted.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(again).code, 'APPROVAL_REJECTED');
      assert.equal(manager.getRequest(requestId).state, 'INVALIDATED');
      assert.equal(
        lifecycle(reverted.audit).filter((r) => r.approval.eventType === 'APPROVAL_INVALIDATED')
          .length,
        0,
        'no second invalidation event',
      );
    });
  });

  // =========================================================================
  // 5. Audit leakage controls
  // =========================================================================

  describe('Audit leakage controls', () => {
    test('RC04-S-18: raw token and token digest never appear in any audit record', async () => {
      const { server, approvals, audit } = makeServer({ label: 'token-leak' });
      const params = { path: 't.txt', content: 'x', workspaceId: 'ws' };
      const { requestId, token } = await approveAndRedeem(server, approvals, 'create_file', params);

      const tokenDigest = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
      const serialized = JSON.stringify(audit.getRecords());

      assert.ok(!serialized.includes(token), 'raw token must never be audited');
      assert.ok(!serialized.includes(tokenDigest), 'token digest must never be audited');
      assert.ok(!serialized.includes(token.slice(0, 16)), 'token prefix must never be audited');
      for (const record of audit.getRecords()) {
        const keys = JSON.stringify(record.approval ?? {});
        assert.ok(!keys.includes('Digest'), 'no digest field in approval metadata');
        assert.ok(!keys.includes('candidateDigest'));
      }
      void requestId;
    });

    test('RC04-S-19: raw content and patch text never appear in any audit record', async () => {
      const contentMarker = 'RC04_AUDIT_CONTENT_MARKER_3141';
      const patchMarker = 'RC04_AUDIT_PATCH_MARKER_2718';
      const { server, approvals, audit, dir } = makeServer({ label: 'content-leak' });

      await approveAndRedeem(server, approvals, 'create_file', {
        path: 'm.txt',
        content: contentMarker,
        workspaceId: 'ws',
      });

      const patch = `--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n-line1\n+${patchMarker}\n line2\n line3\n`;
      const p = await server.dispatchToolCall('apply_patch', { patch, workspaceId: 'ws' });
      const patchId = body(p).details.approvalRequestId;
      const patchToken = approvals.approve(patchId).token;
      await server.dispatchToolCall('apply_patch', {
        patch,
        workspaceId: 'ws',
        _arcApproval: { requestId: patchId, token: patchToken },
      });
      await server.flushAudit();

      const serialized = JSON.stringify(audit.getRecords());
      assert.ok(!serialized.includes(contentMarker), 'raw content must never be audited');
      assert.ok(!serialized.includes(patchMarker), 'raw patch text must never be audited');
      assert.ok(!serialized.includes('line1') || !serialized.includes(patchMarker));
      assert.equal(fs.readFileSync(path.join(dir, 'm.txt'), 'utf8'), contentMarker);
    });

    test('RC04-S-20: environment values never appear in any audit record', async () => {
      const envMarker = 'RC04_AUDIT_ENV_MARKER_1618';
      // run_command is ALLOW under the built-in policy, so an external policy is
      // required to reach the approval lifecycle at all (rc04 §55).
      const { server, approvals, audit } = makeServer({
        label: 'env-leak',
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'require-cmd'\n    effect: 'REQUIRE_APPROVAL'\n    tools: ['run_command']\n`,
          format: 'yaml',
        },
      });
      const params = {
        executable: 'git',
        args: ['--version'],
        // CI is the only env key RC-02 admits; its VALUE must still never be audited.
        env: { CI: envMarker },
        workspaceId: 'ws',
      };
      const first = await server.dispatchToolCall('run_command', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      await server.dispatchToolCall('run_command', {
        ...params,
        _arcApproval: { requestId, token },
      });
      await server.flushAudit();

      const serialized = JSON.stringify(audit.getRecords());
      assert.ok(!serialized.includes(envMarker), 'env VALUE must never be audited');
    });

    test('RC04-S-21: the absolute workspace root never appears in any audit record', async () => {
      const { server, approvals, audit, dir } = makeServer({ label: 'root-leak' });
      const marker = dir;

      // Ordinary read, approval request, grant, consumption and approved mutation.
      await server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      await approveAndRedeem(server, approvals, 'create_file', {
        path: 'a.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      await server.flushAudit();

      const serialized = JSON.stringify(audit.getRecords());
      assert.ok(!serialized.includes(marker), 'raw absolute workspace root must never be audited');
      for (const record of audit.getRecords()) {
        assert.equal(record.target.workspacePath, '', 'target.workspacePath must be minimized');
      }
      // The digest IS permitted.
      const withHash = audit.getRecords().filter((r) => r.target.workspaceRootHash !== undefined);
      assert.ok(withHash.length > 0);
      assert.equal(withHash[0].target.workspaceRootHash, sha256Hex(dir));
    });
  });

  // =========================================================================
  // 6. AuditLogger hardening (package level)
  // =========================================================================

  describe('AuditLogger hardening', () => {
    test('RC04-S-22: central redaction removes unsafe fields regardless of the caller', async () => {
      const logger = new AuditLogger();
      const marker = 'RC04_AUDIT_DEFENSE_MARKER_9999';

      await logger.log({
        timestamp: new Date().toISOString(),
        actor: { clientId: 'c', clientType: 't', deviceId: 'd', sessionId: 's' },
        target: { workspaceId: 'ws', workspacePath: `/home/${marker}/workspace` },
        invocation: {
          toolName: 'create_file',
          parametersRedacted: {
            content: marker,
            patch: marker,
            env: { NAME: marker },
            _arcApproval: { token: marker },
          },
          payloadHash: '',
        },
        policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
      });

      const stored = logger.getRecords()[0];
      const serialized = JSON.stringify(stored);
      assert.ok(!serialized.includes(marker), 'raw caller values must not survive redaction');
      assert.equal(stored.target.workspacePath, '');
      assert.match(stored.target.workspaceRootHash, /^[0-9a-f]{64}$/);
      // The fallback hash is derived from REDACTED data, never from raw secrets.
      assert.notEqual(
        stored.invocation.payloadHash,
        computeSha256(canonicalJson({ content: marker })),
      );
    });

    test('RC04-S-23: getRecords returns defensive snapshots', async () => {
      const { server, audit } = makeServer({ label: 'snapshot' });
      await server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });

      const before = audit.getRecords()[0].policy.ruleId;
      const borrowed = audit.getRecords();
      borrowed[0].policy.ruleId = 'TAMPERED';
      borrowed[0].actor.clientId = 'TAMPERED';

      const fresh = audit.getRecords();
      assert.equal(fresh[0].policy.ruleId, before, 'authoritative record must be unchanged');
      assert.notEqual(fresh[0].actor.clientId, 'TAMPERED');
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-24: logger does not retain mutable caller references', async () => {
      const logger = new AuditLogger();
      const actor = { clientId: 'orig', clientType: 't', deviceId: 'd', sessionId: 's' };
      const target = { workspaceId: 'orig-ws', workspacePath: '' };
      const policy = { decision: 'ALLOW', ruleId: 'orig-rule', evaluationDurationMs: 0 };

      await logger.log({
        timestamp: new Date().toISOString(),
        actor,
        target,
        invocation: { toolName: 'read_file', parametersRedacted: { a: 1 }, payloadHash: 'h' },
        policy,
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
      });

      actor.clientId = 'MUTATED';
      target.workspaceId = 'MUTATED';
      policy.ruleId = 'MUTATED';

      const stored = logger.getRecords()[0];
      assert.equal(stored.actor.clientId, 'orig');
      assert.equal(stored.target.workspaceId, 'orig-ws');
      assert.equal(stored.policy.ruleId, 'orig-rule');
      assert.equal(await logger.verifyIntegrity(), true);
    });

    test('RC04-S-25: 32 concurrent appends keep the chain contiguous', async () => {
      const logger = new AuditLogger();
      await Promise.all(
        Array.from({ length: 32 }, (_, i) =>
          logger.log({
            timestamp: new Date().toISOString(),
            actor: { clientId: `c${i}`, clientType: 't', deviceId: 'd', sessionId: 's' },
            target: { workspaceId: 'ws', workspacePath: '' },
            invocation: { toolName: 'read_file', parametersRedacted: { i }, payloadHash: '' },
            policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 0 },
            execution: {
              status: 'SUCCESS',
              startTime: new Date().toISOString(),
              endTime: new Date().toISOString(),
              durationMs: 0,
            },
          }),
        ),
      );

      const records = logger.getRecords();
      assert.equal(records.length, 32);
      const sequences = records.map((r) => r.sequenceNumber);
      assert.deepEqual(
        sequences,
        Array.from({ length: 32 }, (_, i) => i + 1),
        'sequence numbers must be unique and contiguous',
      );
      assert.equal(new Set(sequences).size, 32, 'no duplicate sequence numbers');
      assert.equal(await logger.verifyIntegrity(), true);
    });

    test('RC04-S-26: clear() resets the chain deterministically', async () => {
      const logger = new AuditLogger();
      for (let i = 0; i < 3; i++) {
        await logger.log({
          timestamp: new Date().toISOString(),
          actor: { clientId: 'c', clientType: 't', deviceId: 'd', sessionId: 's' },
          target: { workspaceId: 'ws', workspacePath: '' },
          invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: 'h' },
          policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 0 },
          execution: {
            status: 'SUCCESS',
            startTime: new Date().toISOString(),
            endTime: new Date().toISOString(),
            durationMs: 0,
          },
        });
      }
      logger.clear();
      assert.equal(logger.getRecords().length, 0);
      assert.equal(await logger.verifyIntegrity(), true);

      await logger.log({
        timestamp: new Date().toISOString(),
        actor: { clientId: 'c', clientType: 't', deviceId: 'd', sessionId: 's' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: 'h' },
        policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
      });
      const after = logger.getRecords()[0];
      assert.equal(after.sequenceNumber, 1);
      assert.equal(
        after.integrity.previousRecordHash,
        '0'.repeat(64),
        'genesis previous hash is reset',
      );
    });
  });

  // =========================================================================
  // 7. Hash chain over a mixed lifecycle stream
  // =========================================================================

  describe('Hash chain integrity', () => {
    test('RC04-S-27: integrity holds across a full mixed lifecycle stream', async () => {
      const { server, approvals, audit } = makeServer({ label: 'chain' });

      // REQUESTED + GRANTED + CONSUMED + SUCCEEDED
      await approveAndRedeem(server, approvals, 'create_file', {
        path: 'ok.txt',
        content: 'x',
        workspaceId: 'ws',
      });

      // APPROVED_EXECUTION_FAILED
      await approveAndRedeem(server, approvals, 'write_file', {
        path: 'README.md',
        content: 'x',
        expectedHash: '0'.repeat(64),
        overwrite: true,
        workspaceId: 'ws',
      });

      // APPROVAL_REJECTED
      const rejected = await server.dispatchToolCall('create_file', {
        path: 'rej.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      approvals.reject(body(rejected).details.approvalRequestId);

      // APPROVAL_INVALIDATED: the same manager is re-hosted under a server whose
      // external policy has a DIFFERENT hash but still requires approval.
      const invalidationManager = new ApprovalStateManager();
      const before = makeServer({
        label: 'chain-inval-a',
        manager: invalidationManager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const invalidation = await before.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      const invalidationId = body(invalidation).details.approvalRequestId;
      const invalidationToken = invalidationManager.approve(invalidationId).token;
      await before.server.flushAudit();

      const after = makeServer({
        label: 'chain-inval-a',
        manager: invalidationManager,
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'require-read-v2'\n    effect: 'REQUIRE_APPROVAL'\n    tools: ['read_file']\n`,
          format: 'yaml',
        },
      });
      const invalidated = await after.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
        _arcApproval: { requestId: invalidationId, token: invalidationToken },
      });
      assert.equal(body(invalidated).code, 'APPROVAL_REJECTED');

      // APPROVAL_EXPIRED via an injected clock manager
      let mono = 1n;
      const clockManager = new ApprovalStateManager({ getMonotonicTime: () => mono });
      const expired = makeServer({ label: 'chain-expiry', manager: clockManager });
      const expiring = await expired.server.dispatchToolCall('create_file', {
        path: 'exp.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      mono += 301_000n * 1_000_000_000n;
      clockManager.getRequest(body(expiring).details.approvalRequestId);
      await expired.server.flushAudit();

      await server.flushAudit();

      const seen = new Set(eventsOf(audit));
      for (const required of [
        'APPROVAL_REQUESTED',
        'APPROVAL_GRANTED',
        'APPROVAL_CONSUMED',
        'APPROVED_EXECUTION_SUCCEEDED',
        'APPROVED_EXECUTION_FAILED',
        'APPROVAL_REJECTED',
      ]) {
        assert.ok(seen.has(required), `missing lifecycle event ${required}`);
      }
      assert.ok(eventsOf(expired.audit).includes('APPROVAL_EXPIRED'));
      assert.ok(eventsOf(after.audit).includes('APPROVAL_INVALIDATED'));

      assert.equal(await audit.verifyIntegrity(), true, 'hash chain must remain valid');
      assert.equal(await expired.audit.verifyIntegrity(), true);
      assert.equal(await after.audit.verifyIntegrity(), true);

      const records = audit.getRecords();
      const sequences = records.map((r) => r.sequenceNumber);
      assert.deepEqual(
        sequences,
        Array.from({ length: records.length }, (_, i) => i + 1),
      );
    });

    test('RC04-S-28: a tampered copy fails integrity while the original passes', async () => {
      const { server, audit } = makeServer({ label: 'tamper-detect' });
      await server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      await server.flushAudit();
      assert.equal(await audit.verifyIntegrity(), true);

      const snapshot = audit.getRecords();
      assert.ok(snapshot.length >= 1);

      for (const index of [0, snapshot.length - 1]) {
        const original = snapshot[index];
        const forged = structuredClone(original);

        // Change a field that participates in the record hash.
        forged.policy.ruleId = 'FORGED_RULE';
        assert.notEqual(forged.policy.ruleId, original.policy.ruleId, 'copy must diverge');

        // Recompute the canonical hash EXACTLY as the logger does, using the
        // record's own previousRecordHash, and prove the stored digest no longer
        // matches the tampered content. This is what makes the copy detectably
        // forged rather than merely different.
        const recomputed = computeSha256(
          canonicalJson({
            ...forged,
            integrity: { previousRecordHash: forged.integrity.previousRecordHash },
          }),
        );
        assert.notEqual(
          recomputed,
          forged.integrity.recordHash,
          'tampered content must not reproduce the stored hash',
        );

        // The pristine snapshot still reproduces its own stored hash, so the
        // mismatch above comes from the tampering and not from a hashing quirk.
        assert.equal(
          computeSha256(
            canonicalJson({
              ...original,
              integrity: { previousRecordHash: original.integrity.previousRecordHash },
            }),
          ),
          original.integrity.recordHash,
        );
      }

      // The authoritative chain is untouched by any of the above.
      assert.equal(await audit.verifyIntegrity(), true);
    });
  });

  // =========================================================================
  // 8. Resource accounting and release
  // =========================================================================

  describe('Resource accounting', () => {
    test('RC04-S-29: failed admission emits no APPROVAL_REQUESTED and leaves state unchanged', () => {
      const manager = new ApprovalStateManager({ maxActiveApprovalsPerActor: 1 });
      const binding = {
        actor: { clientId: 'c', clientType: 't' },
        workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
        policyHash: 'c'.repeat(64),
      };
      manager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: '1'.repeat(64),
        binding,
        reviewMaterial: 'x',
      });

      const seen = [];
      manager.registerLifecycleSink({
        onApprovalLifecycleEvent: (event) => seen.push(event.eventType),
      });

      assert.throws(
        () =>
          manager.createOrReusePending({
            toolName: 'create_file',
            executionPayloadHash: '2'.repeat(64),
            binding,
            reviewMaterial: 'y',
          }),
        (err) => err.code === 'RESOURCE_EXHAUSTED',
      );
      assert.deepEqual(seen, [], 'no lifecycle event for a failed admission');
      assert.equal(manager.listActive().length, 1, 'existing record unchanged');
    });

    test('RC04-S-30: dedup retries do not double-charge review bytes', () => {
      const manager = new ApprovalStateManager({ maxReviewBytesPerActor: 4096 });
      // Two genuinely different 2000-byte records fit (4000 <= 4096); six
      // charges would not, so a double-charge on retry would be detected.
      const binding = {
        actor: { clientId: 'c', clientType: 't' },
        workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
        policyHash: 'c'.repeat(64),
      };
      const body2000 = 'A'.repeat(2000);

      manager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: '1'.repeat(64),
        binding,
        reviewMaterial: body2000,
      });
      // Retrying the SAME request must not charge the quota a second time.
      for (let i = 0; i < 5; i++) {
        manager.createOrReusePending({
          toolName: 'create_file',
          executionPayloadHash: '1'.repeat(64),
          binding,
          reviewMaterial: body2000,
        });
      }

      // A second, genuinely different request of the same size still fits.
      manager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: '2'.repeat(64),
        binding,
        reviewMaterial: body2000,
      });
      assert.equal(manager.listActive().length, 2);
    });

    test('RC04-S-31: review memory is released on every terminal state', () => {
      for (const terminal of ['APPROVED', 'REJECTED', 'CONSUMED', 'INVALIDATED']) {
        const manager = new ApprovalStateManager({ maxReviewBytesPerActor: 2048 });
        const binding = {
          actor: { clientId: 'c', clientType: 't' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'c'.repeat(64),
        };
        const request = manager.createOrReusePending({
          toolName: 'create_file',
          executionPayloadHash: '1'.repeat(64),
          binding,
          reviewMaterial: 'B'.repeat(1024),
        });

        if (terminal === 'APPROVED') {
          manager.approve(request.requestId);
        } else if (terminal === 'REJECTED') {
          manager.reject(request.requestId);
        } else if (terminal === 'CONSUMED') {
          const token = manager.approve(request.requestId).token;
          manager.redeemAndConsume({
            requestId: request.requestId,
            token,
            executionPayloadHash: '1'.repeat(64),
            actor: binding.actor,
            workspace: binding.workspace,
            policyHash: binding.policyHash,
          });
        } else {
          const token = manager.approve(request.requestId).token;
          assert.throws(() =>
            manager.redeemAndConsume({
              requestId: request.requestId,
              token,
              executionPayloadHash: '1'.repeat(64),
              actor: binding.actor,
              workspace: binding.workspace,
              policyHash: 'f'.repeat(64),
            }),
          );
        }

        // Capacity was released: a fresh request of the same size is admitted.
        manager.createOrReusePending({
          toolName: 'create_file',
          executionPayloadHash: '9'.repeat(64),
          binding,
          reviewMaterial: 'B'.repeat(1024),
        });
      }
    });

    test('RC04-S-31b: a real expiry releases review quota on the SAME manager', () => {
      let mono = 1_000_000n;
      // 1024 bytes of review per request against a 2048-byte actor cap: the
      // first request fits, and a second cannot be admitted until it expires.
      const manager = new ApprovalStateManager({
        getMonotonicTime: () => mono,
        maxReviewBytesPerActor: 2048,
      });
      const binding = {
        actor: { clientId: 'c', clientType: 't' },
        workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
        policyHash: 'c'.repeat(64),
      };

      const first = manager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: '1'.repeat(64),
        binding,
        reviewMaterial: 'E'.repeat(1024),
      });
      assert.equal(manager.getRequest(first.requestId).state, 'PENDING');

      // The quota is genuinely held: a second request that would exceed it is
      // refused while the first is still live.
      assert.throws(() =>
        manager.createOrReusePending({
          toolName: 'create_file',
          executionPayloadHash: '2'.repeat(64),
          binding,
          reviewMaterial: 'E'.repeat(1536),
        }),
      );
      assert.equal(manager.getRequest(first.requestId).state, 'PENDING');

      // Advance past the exact deadline and let a real API drive the expiry.
      mono += 301_000n * 1_000_000n;
      manager.purgeExpired();
      assert.equal(
        manager.getRequest(first.requestId).state,
        'EXPIRED',
        'the same record must really be EXPIRED',
      );

      // No clear(), no second manager: the released bytes must be reusable here.
      const second = manager.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: '3'.repeat(64),
        binding,
        reviewMaterial: 'E'.repeat(1536),
      });
      assert.equal(manager.getRequest(second.requestId).state, 'PENDING');
      assert.equal(manager.listActive().length, 1);
    });
  });

  // =========================================================================
  // 9. DENY precedence still wins over any token
  // =========================================================================

  describe('DENY precedence', () => {
    test('RC04-S-32: a valid token cannot override a Layer-2 DENY, and emits no lifecycle events', async () => {
      const manager = new ApprovalStateManager();
      const requiring = makeServer({
        label: 'deny-audit',
        manager,
        policy: { sourceText: REQUIRE_READ_POLICY, format: 'yaml' },
      });
      const params = { path: 'README.md', workspaceId: 'ws' };
      const first = await requiring.server.dispatchToolCall('read_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = manager.approve(requestId).token;
      await requiring.server.flushAudit();

      const denying = makeServer({
        label: 'deny-audit',
        manager,
        policy: {
          sourceText: `version: '1.0'\nrules:\n  - id: 'deny-read'\n    effect: 'DENY'\n    tools: ['read_file']\n`,
          format: 'yaml',
        },
      });
      const res = await denying.server.dispatchToolCall('read_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      assert.equal(body(res).code, 'POLICY_DENIED');
      assert.equal(manager.getRequest(requestId).state, 'APPROVED', 'token not consumed');

      const events = eventsOf(denying.audit);
      assert.ok(!events.includes('APPROVAL_CONSUMED'));
      assert.ok(!events.some((e) => e.startsWith('APPROVED_EXECUTION')));
      const reasons = invocations(denying.audit)
        .map((r) => r.approval?.reasonCode)
        .filter(Boolean);
      assert.equal(reasons.length, 0, 'DENY must not consult token state');
    });
  });

  // =========================================================================
  // 10. Admin channel lifecycle evidence
  // =========================================================================

  describe('Admin channel lifecycle audit', () => {
    test('RC04-S-33: createArcMcpServer keeps one chain and flushes lifecycle evidence', async () => {
      const dir = makeWorkspace('factory-chain');
      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: dir }],
        defaultWorkspaceId: 'ws',
      });

      const first = await server.dispatchToolCall('create_file', {
        path: 'f.txt',
        content: 'x',
        workspaceId: 'ws',
      });
      assert.equal(body(first).code, 'APPROVAL_REQUIRED');
      const requestId = body(first).details.approvalRequestId;
      server.approvalStateManager.approve(requestId);
      await server.flushAudit();

      const records = server.auditLogger.getRecords();
      const events = records.filter((r) => r.approval?.eventType).map((r) => r.approval.eventType);
      assert.ok(events.includes('APPROVAL_REQUESTED'));
      assert.ok(events.includes('APPROVAL_GRANTED'));
      assert.equal(await server.auditLogger.verifyIntegrity(), true);
      const sequences = records.map((r) => r.sequenceNumber);
      assert.deepEqual(
        sequences,
        Array.from({ length: records.length }, (_, i) => i + 1),
      );
    });
  });

  // =========================================================================
  // Audit failure is fail-closed (rc04 §40, §76)
  // =========================================================================

  describe('Audit failure fails the initiating action closed', () => {
    const SINK_EVENT = {
      requestId: 'req-sink',
      toolName: 'create_file',
      actor: { clientId: 'client', clientType: 'MCP_CLIENT' },
      workspaceId: 'ws',
      policyHash: 'p'.repeat(64),
    };

    test('RC04-S-34: a full queue latches overflow instead of silently dropping evidence', async () => {
      const audit = new AuditLogger();
      const sink = new ApprovalAuditSink(audit);
      const rootHash = sha256Hex('ws-root');

      for (let i = 0; i <= MAX_PENDING_LIFECYCLE_EVENTS; i++) {
        sink.onApprovalLifecycleEvent({
          ...SINK_EVENT,
          eventType: 'APPROVAL_REQUESTED',
          state: 'PENDING',
          workspaceRootHash: rootHash,
          occurredAt: new Date().toISOString(),
        });
      }

      assert.equal(sink.hasOverflowed, true, 'overflow must be latched, never ignored');
      assert.equal(
        sink.pendingCount,
        MAX_PENDING_LIFECYCLE_EVENTS,
        'the queue itself must stay bounded',
      );
      await assert.rejects(
        () => sink.flush(),
        (err) => {
          assert.equal(err.reason, 'QUEUE_OVERFLOW');
          return true;
        },
        'losing evidence must fail the flush',
      );
      // Every event that WAS buffered is still committed: overflow must not
      // strand writeable evidence behind the latch.
      assert.equal(
        audit.getRecords().length,
        MAX_PENDING_LIFECYCLE_EVENTS,
        'buffered evidence is committed, not stranded',
      );
      assert.equal(sink.pendingCount, 0);
      // The latch is permanent: later flushes keep failing rather than
      // forgetting that evidence was lost, so the chain is never mistaken for
      // a complete record of the window.
      await assert.rejects(() => sink.flush());
      assert.equal(audit.getRecords().length, MAX_PENDING_LIFECYCLE_EVENTS);
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-35: a failed write keeps evidence queued and reports WRITE_FAILED', async () => {
      const written = [];
      let chainAvailable = false;
      const sink = new ApprovalAuditSink({
        log: async (record) => {
          if (!chainAvailable) {
            throw new Error('chain unavailable');
          }
          written.push(record);
          return record;
        },
      });

      sink.onApprovalLifecycleEvent({
        ...SINK_EVENT,
        eventType: 'APPROVAL_CONSUMED',
        state: 'CONSUMED',
        workspaceRootHash: sha256Hex('ws-root'),
        occurredAt: new Date().toISOString(),
      });

      await assert.rejects(
        () => sink.flush(),
        (err) => {
          assert.equal(err.reason, 'WRITE_FAILED');
          return true;
        },
      );
      assert.equal(sink.pendingCount, 1, 'unwritten evidence is retained, not discarded');

      chainAvailable = true;
      await sink.flush();
      assert.equal(sink.pendingCount, 0);
      assert.equal(written.length, 1, 'the retained event is committed exactly once');
    });

    test('RC04-S-36: an approved execution whose evidence cannot be written is failed closed', async () => {
      const { server, approvals, audit, dir } = makeServer({ label: 'fail-closed' });
      const params = { path: 'fc.txt', content: 'bytes', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      await server.flushAudit();

      // The chain refuses ONLY the execution lifecycle write.
      const realLog = audit.log.bind(audit);
      audit.log = async (record) => {
        if (record.approval?.eventType === 'APPROVED_EXECUTION_SUCCEEDED') {
          throw new Error('chain unavailable');
        }
        return realLog(record);
      };

      const second = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      const secondBody = body(second);

      assert.equal(second.isError, true, 'a success result must never be returned');
      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.equal(secondBody.message, 'Required approval audit evidence could not be recorded.');
      // The mutation itself is not rolled back and is not reported as evidence.
      assert.equal(fs.readFileSync(path.join(dir, 'fc.txt'), 'utf8'), 'bytes');
      assert.equal(eventsOf(audit).includes('APPROVED_EXECUTION_SUCCEEDED'), false);

      // The evidence is retained, not dropped: restoring the chain commits it.
      audit.log = realLog;
      await server.flushAudit();
      assert.equal(eventsOf(audit).includes('APPROVED_EXECUTION_SUCCEEDED'), true);
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-40: a stored error message is redacted centrally, for every caller', async () => {
      const logger = new AuditLogger();
      const marker = `rc0428-${crypto.randomBytes(8).toString('hex')}`;
      const secret = `ghp_${'A'.repeat(36)}`;
      const posixPath = `/tmp/${marker}/file.txt`;
      const windowsPath = `C:\\Users\\${marker}\\file.txt`;

      const baseRecord = (message, code) => ({
        timestamp: new Date().toISOString(),
        actor: { clientId: 'c', clientType: 't', deviceId: 'd', sessionId: 's' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: { toolName: 'read_file', parametersRedacted: {}, payloadHash: 'h' },
        policy: { decision: 'ALLOW', ruleId: 'r', evaluationDurationMs: 0 },
        execution: {
          status: 'ERROR',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
        error: { code, message },
      });

      await logger.log(baseRecord(`failure at ${posixPath} and ${secret}`, 'TEST'));
      await logger.log(baseRecord(`windows failure at ${windowsPath}`, 'TEST'));

      const stored = logger.getRecords();
      const serialized = JSON.stringify(stored);
      assert.ok(!serialized.includes(marker), 'no raw path fragment may be stored');
      assert.ok(!serialized.includes(posixPath));
      assert.ok(!serialized.includes(windowsPath));
      assert.ok(!serialized.includes(secret), 'high-confidence secret must not be stored');
      assert.ok(serialized.includes('[REDACTED_PATH]'));
      assert.ok(serialized.includes('[REDACTED_SECRET]'));
      // The bounded code is retained; only the message is redacted.
      assert.equal(stored[0].error.code, 'TEST');
      assert.equal(await logger.verifyIntegrity(), true);
    });

    test('RC04-S-41: a process lifecycle event cannot leak a host path', async () => {
      const root = makeWorkspace('proc-redact');
      const registry = new WorkspaceRegistry();
      registry.registerWorkspace('ws', root);
      const audit = new AuditLogger();
      const sink = new ProcessAuditSink(audit, registry);

      const marker = `rc0429-${crypto.randomBytes(8).toString('hex')}`;
      const hostPath = `/home/${marker}/bin/exec`;

      await sink.onProcessEvent({
        eventType: 'PROCESS_SPAWN_FAILED',
        timestamp: new Date().toISOString(),
        processId: 'proc-1',
        workspaceId: 'ws',
        actor: { clientId: 'c', clientType: 't', deviceId: 'd', sessionId: 's' },
        executable: hostPath,
        durationMs: 5,
        error: `spawn failed for ${hostPath}`,
      });

      const records = audit.getRecords();
      assert.equal(records.length, 1);
      const record = records[0];

      // Every surface: the parameter projection, the top-level error message,
      // the target, and the whole serialized record.
      assert.ok(!JSON.stringify(record.invocation.parametersRedacted).includes(marker));
      assert.ok(!record.error.message.includes(marker));
      assert.ok(!JSON.stringify(record).includes(marker));
      assert.ok(!JSON.stringify(record).includes(hostPath));
      assert.ok(!JSON.stringify(record).includes(root));
      assert.equal(record.target.workspacePath, '', 'raw workspace root is dropped');
      assert.match(record.target.workspaceRootHash, /^[0-9a-f]{64}$/);
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-38b: logger.log returns a defensive snapshot, not the stored object', async () => {
      const logger = new AuditLogger();
      const returned = await logger.log({
        timestamp: new Date().toISOString(),
        actor: { clientId: 'orig', clientType: 't', deviceId: 'd', sessionId: 's' },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: { toolName: 'read_file', parametersRedacted: { a: 1 }, payloadHash: 'h' },
        policy: { decision: 'ALLOW', ruleId: 'orig-rule', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
      });

      // The returned object must be a SNAPSHOT. Mutating it (including nested
      // objects) must not rewrite stored, hash-chained evidence.
      returned.policy.ruleId = 'TAMPERED';
      returned.actor.clientId = 'TAMPERED';
      returned.invocation.parametersRedacted.a = 999;
      returned.target.workspaceId = 'TAMPERED';
      returned.integrity.recordHash = 'f'.repeat(64);

      const stored = logger.getRecords()[0];
      assert.equal(stored.policy.ruleId, 'orig-rule');
      assert.equal(stored.actor.clientId, 'orig');
      assert.equal(stored.invocation.parametersRedacted.a, 1);
      assert.equal(stored.target.workspaceId, 'ws');
      assert.notEqual(stored.integrity.recordHash, 'f'.repeat(64));
      assert.equal(await logger.verifyIntegrity(), true, 'stored chain is untouched');
    });

    test('RC04-S-38: a returned audit snapshot recomputes to the stored hash', async () => {
      const { server, approvals, audit } = makeServer({ label: 'hash-faithful' });
      const params = { path: 'hf.txt', content: 'x', workspaceId: 'ws' };
      await approveAndRedeem(server, approvals, 'create_file', params);

      const records = audit.getRecords();
      assert.ok(records.length >= 4);

      // An external auditor recomputes each hash from the PUBLIC snapshot. The
      // snapshot must therefore be hash-faithful, or a false failure is reported.
      let prevHash = '0'.repeat(64);
      for (const record of records) {
        assert.equal(record.integrity.previousRecordHash, prevHash);
        const recomputed = computeSha256(
          canonicalJson({ ...record, integrity: { previousRecordHash: prevHash } }),
        );
        assert.equal(recomputed, record.integrity.recordHash);
        prevHash = record.integrity.recordHash;
      }
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-42: expiry evidence that cannot be written fails closed, state preserved', async () => {
      let mono = 1_000_000n;
      const manager = new ApprovalStateManager({ getMonotonicTime: () => mono });
      const { server, approvals, audit, dir } = makeServer({ label: 'expiry-dup', manager });
      const params = { path: 'exp.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      const token = approvals.approve(requestId).token;
      await server.flushAudit();

      // Only the expiry lifecycle write is refused.
      const realLog = audit.log.bind(audit);
      audit.log = async (record) => {
        if (record.approval?.eventType === 'APPROVAL_EXPIRED') {
          throw new Error('chain unavailable');
        }
        return realLog(record);
      };

      mono += 301_000n * 1_000_000n;
      const second = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token },
      });
      const secondBody = body(second);

      // The semantic APPROVAL_EXPIRED outcome must NOT be reported while its
      // required lifecycle evidence is missing.
      assert.equal(second.isError, true);
      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.notEqual(secondBody.code, 'APPROVAL_EXPIRED');
      // State is committed and NOT rolled back, and nothing executed.
      assert.equal(approvals.getRequest(requestId).state, 'EXPIRED');
      assert.equal(fs.existsSync(path.join(dir, 'exp.txt')), false);
      assert.equal(eventsOf(audit).includes('APPROVAL_EXPIRED'), false);

      // The evidence was retained, not dropped: a later flush commits it.
      audit.log = realLog;
      await server.flushAudit();
      const expired = eventsOf(audit).filter((e) => e === 'APPROVAL_EXPIRED');
      assert.equal(expired.length, 1);
      assert.equal(approvals.getRequest(requestId).state, 'EXPIRED');
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-43: invalidation evidence that cannot be written fails closed, state preserved', async () => {
      const { server, approvals, audit, dir } = makeServer({ label: 'inval-dup' });
      const params = { path: 'inv.txt', content: 'x', workspaceId: 'ws' };

      // A record bound to a policy hash the live policy can never match.
      const seeded = approvals.createOrReusePending({
        toolName: 'create_file',
        executionPayloadHash: 'a'.repeat(64),
        binding: {
          actor: { clientId: 'c', clientType: 't' },
          workspace: { workspaceId: 'ws', workspaceRootHash: 'b'.repeat(64) },
          policyHash: 'f'.repeat(64),
        },
        reviewMaterial: 'x',
      });
      const token = approvals.approve(seeded.requestId).token;
      await server.flushAudit();

      const realLog = audit.log.bind(audit);
      audit.log = async (record) => {
        if (record.approval?.eventType === 'APPROVAL_INVALIDATED') {
          throw new Error('chain unavailable');
        }
        return realLog(record);
      };

      const second = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId: seeded.requestId, token },
      });
      const secondBody = body(second);

      assert.equal(second.isError, true);
      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.notEqual(secondBody.code, 'APPROVAL_REJECTED');
      // A policy-binding mismatch is permanent: the record stays INVALIDATED.
      assert.equal(approvals.getRequest(seeded.requestId).state, 'INVALIDATED');
      assert.equal(fs.existsSync(path.join(dir, 'inv.txt')), false);
      assert.equal(eventsOf(audit).includes('APPROVAL_INVALIDATED'), false);

      audit.log = realLog;
      await server.flushAudit();
      assert.equal(
        eventsOf(audit).filter((e) => e === 'APPROVAL_INVALIDATED').length,
        1,
        'the retained invalidation evidence is committed exactly once',
      );
      assert.equal(await audit.verifyIntegrity(), true);
    });

    test('RC04-S-44: an ordinary invalid redemption keeps the generic rejection', async () => {
      const { server, approvals, audit } = makeServer({ label: 'ordinary-deny' });
      const params = { path: 'ord.txt', content: 'x', workspaceId: 'ws' };

      const first = await server.dispatchToolCall('create_file', { ...params });
      const requestId = body(first).details.approvalRequestId;
      approvals.approve(requestId);
      await server.flushAudit();

      const before = eventsOf(audit).length;
      // Wrong token: NO lifecycle transition is caused, so the generic
      // rejection remains correct and no lifecycle event is owed.
      const second = await server.dispatchToolCall('create_file', {
        ...params,
        _arcApproval: { requestId, token: '0'.repeat(64) },
      });
      assert.equal(body(second).code, 'APPROVAL_REJECTED');
      assert.equal(body(second).code !== 'INTERNAL_ERROR', true);
      assert.equal(eventsOf(audit).length, before, 'no lifecycle transition was caused');
      assert.equal(approvals.getRequest(requestId).state, 'APPROVED');

      // The internal reason stays on the ordinary record only.
      const ordinary = invocations(audit).at(-1);
      assert.equal(ordinary.approval.reasonCode, 'TOKEN_MISMATCH');
      assert.equal(JSON.stringify(second).includes('TOKEN_MISMATCH'), false);
    });
  });
});
