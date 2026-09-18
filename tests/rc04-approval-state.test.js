import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  ApprovalStateManager,
  APPROVAL_TTL_SECONDS,
  MAX_ACTIVE_APPROVALS_GLOBAL,
  MAX_ACTIVE_APPROVALS_PER_ACTOR,
  MAX_REVIEW_BYTES_PER_RECORD,
  MAX_REVIEW_BYTES_PER_ACTOR,
  MAX_REVIEW_BYTES_GLOBAL,
  MAX_TOKEN_BYTES,
  TERMINAL_APPROVAL_STATES,
} from '../packages/policy/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

describe('CesSpace ARC — RC-04 Task 1: Approval State Machine Core', () => {
  // Helper to construct a valid base input
  function createSampleInput(overrides = {}) {
    return {
      toolName: 'create_file',
      executionPayloadHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      binding: {
        actor: {
          clientId: 'agent-alice',
          clientType: 'antigravity',
          sessionId: 'session-001',
          deviceId: 'device-001',
        },
        workspace: {
          workspaceId: 'primary-ws',
          workspaceRootHash: '1111111111111111111111111111111111111111111111111111111111111111',
        },
        policyHash: '2222222222222222222222222222222222222222222222222222222222222222',
      },
      reviewMaterial: 'patch-or-content-body-review-preview',
      ...overrides,
    };
  }

  // --- Group 1: Protocol Constants & Schema Validation ---
  test('Group 1: Protocol default limits and terminal states', () => {
    assert.equal(APPROVAL_TTL_SECONDS, 300);
    assert.equal(MAX_ACTIVE_APPROVALS_GLOBAL, 1024);
    assert.equal(MAX_ACTIVE_APPROVALS_PER_ACTOR, 64);
    assert.equal(MAX_REVIEW_BYTES_PER_RECORD, 1048576);
    assert.equal(MAX_REVIEW_BYTES_PER_ACTOR, 8 * 1024 * 1024);
    assert.equal(MAX_REVIEW_BYTES_GLOBAL, 64 * 1024 * 1024);
    assert.equal(MAX_TOKEN_BYTES, 128);

    assert.deepEqual(
      [...TERMINAL_APPROVAL_STATES],
      ['REJECTED', 'EXPIRED', 'CONSUMED', 'INVALIDATED'],
    );
  });

  test('Group 1: Injected limits cannot exceed production maximums (fail-closed)', () => {
    assert.throws(
      () => new ApprovalStateManager({ maxActiveApprovalsGlobal: 1025 }),
      /maxActiveApprovalsGlobal cannot exceed/,
    );
    assert.throws(
      () => new ApprovalStateManager({ maxActiveApprovalsPerActor: 65 }),
      /maxActiveApprovalsPerActor cannot exceed/,
    );
    assert.throws(
      () => new ApprovalStateManager({ maxReviewBytesPerRecord: 1048577 }),
      /maxReviewBytesPerRecord cannot exceed/,
    );
    assert.throws(
      () => new ApprovalStateManager({ maxReviewBytesPerActor: 8 * 1024 * 1024 + 1 }),
      /maxReviewBytesPerActor cannot exceed/,
    );
    assert.throws(
      () => new ApprovalStateManager({ maxReviewBytesGlobal: 64 * 1024 * 1024 + 1 }),
      /maxReviewBytesGlobal cannot exceed/,
    );

    // Stricter limits are permitted
    const strictManager = new ApprovalStateManager({
      maxActiveApprovalsGlobal: 2,
      maxActiveApprovalsPerActor: 1,
      maxReviewBytesPerRecord: 100,
      maxReviewBytesPerActor: 200,
      maxReviewBytesGlobal: 500,
    });
    assert.ok(strictManager);
  });

  test('Group 1: Input validation on createOrReusePending', () => {
    const manager = new ApprovalStateManager();

    assert.throws(
      () => manager.createOrReusePending(null),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );
    assert.throws(
      () => manager.createOrReusePending({ ...createSampleInput(), toolName: '' }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );
    assert.throws(
      () =>
        manager.createOrReusePending({
          ...createSampleInput(),
          executionPayloadHash: 'not-64-hex',
        }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );
    assert.throws(
      () =>
        manager.createOrReusePending({
          ...createSampleInput(),
          executionPayloadHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    ); // uppercase rejected
    assert.throws(
      () => manager.createOrReusePending({ ...createSampleInput(), binding: null }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );

    const badActor = createSampleInput();
    badActor.binding.actor.clientId = '';
    assert.throws(
      () => manager.createOrReusePending(badActor),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );

    const badWsRoot = createSampleInput();
    badWsRoot.binding.workspace.workspaceRootHash = 'bad';
    assert.throws(
      () => manager.createOrReusePending(badWsRoot),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );

    const badPolicy = createSampleInput();
    badPolicy.binding.policyHash = 'bad';
    assert.throws(
      () => manager.createOrReusePending(badPolicy),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  // --- Group 2: Request ID and Token Generation ---
  test('Group 2: Request ID generation properties (length 32, lowercase hex, unique)', () => {
    const manager = new ApprovalStateManager();
    const req1 = manager.createOrReusePending(
      createSampleInput({ executionPayloadHash: '1'.repeat(64) }),
    );
    const req2 = manager.createOrReusePending(
      createSampleInput({ executionPayloadHash: '2'.repeat(64) }),
    );

    assert.equal(req1.requestId.length, 32);
    assert.match(req1.requestId, /^[0-9a-f]{32}$/);
    assert.equal(req2.requestId.length, 32);
    assert.match(req2.requestId, /^[0-9a-f]{32}$/);
    assert.notEqual(req1.requestId, req2.requestId);
  });

  test('Group 2: Token generation properties (length 64, lowercase hex, timing-safe 32-byte digest)', () => {
    const manager = new ApprovalStateManager();
    const snap = manager.createOrReusePending(createSampleInput());
    const grant = manager.approve(snap.requestId);

    assert.equal(typeof grant.token, 'string');
    assert.equal(grant.token.length, 64);
    assert.match(grant.token, /^[0-9a-f]{64}$/);
    assert.equal(grant.snapshot.state, 'APPROVED');

    // Token must not be re-returned by approve() on already-approved request
    assert.throws(
      () => manager.approve(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });

  // --- Group 3: State Transitions ---
  test('Group 3: Transition PENDING -> APPROVED -> CONSUMED', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    assert.equal(snap.state, 'PENDING');

    const grant = manager.approve(snap.requestId);
    assert.equal(grant.snapshot.state, 'APPROVED');

    const consumeResult = manager.redeemAndConsume({
      requestId: snap.requestId,
      token: grant.token,
      executionPayloadHash: input.executionPayloadHash,
      actor: input.binding.actor,
      workspace: input.binding.workspace,
      policyHash: input.binding.policyHash,
    });

    assert.equal(consumeResult.consumed, true);
    assert.equal(consumeResult.requestId, snap.requestId);
    assert.equal(consumeResult.toolName, input.toolName);

    const postRecord = manager.getRequest(snap.requestId);
    assert.equal(postRecord.state, 'CONSUMED');
  });

  test('Group 3: Transition PENDING -> REJECTED', () => {
    const manager = new ApprovalStateManager();
    const snap = manager.createOrReusePending(createSampleInput());
    assert.equal(snap.state, 'PENDING');

    const rejectedSnap = manager.reject(snap.requestId, 'Operator declined file write');
    assert.equal(rejectedSnap.state, 'REJECTED');

    // Re-rejecting or approving a rejected request must fail
    assert.throws(
      () => manager.reject(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
    assert.throws(
      () => manager.approve(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });

  test('Group 3: Transition PENDING -> EXPIRED on lazy timeout', () => {
    let fakeNowMono = 1_000_000_000n;
    let fakeNowWall = 1_700_000_000_000;
    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeNowMono,
      getWallTime: () => fakeNowWall,
    });

    const snap = manager.createOrReusePending(createSampleInput());
    assert.equal(snap.state, 'PENDING');
    assert.equal(snap.remainingSeconds, 300);

    // Advance 300 seconds
    fakeNowMono += 300_000_000_000n;
    fakeNowWall += 300_000;

    // Approving after expiry fails with APPROVAL_EXPIRED and generates no token
    assert.throws(
      () => manager.approve(snap.requestId),
      (err) => err.code === 'APPROVAL_EXPIRED',
    );

    const req = manager.getRequest(snap.requestId);
    assert.equal(req.state, 'EXPIRED');
    assert.equal(req.remainingSeconds, 0);
  });

  test('Group 3: Transition APPROVED -> EXPIRED on lazy timeout before consumption', () => {
    let fakeNowMono = 1_000_000_000n;
    let fakeNowWall = 1_700_000_000_000;
    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeNowMono,
      getWallTime: () => fakeNowWall,
    });

    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);
    assert.equal(grant.snapshot.state, 'APPROVED');

    // Advance past monotonic 300s deadline
    fakeNowMono += 300_000_000_000n;

    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_EXPIRED',
    );

    const record = manager.getRequest(snap.requestId);
    assert.equal(record.state, 'EXPIRED');
  });

  test('Group 3: Transition PENDING -> INVALIDATED and APPROVED -> INVALIDATED on policy mismatch', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();

    // 1. PENDING -> INVALIDATED
    const snapPending = manager.createOrReusePending(input);
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snapPending.requestId,
          token: 'a'.repeat(64),
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: '9'.repeat(64), // Mismatched policyHash
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
    assert.equal(manager.getRequest(snapPending.requestId).state, 'INVALIDATED');

    // 2. APPROVED -> INVALIDATED
    const input2 = createSampleInput({ executionPayloadHash: 'b'.repeat(64) });
    const snapApproved = manager.createOrReusePending(input2);
    const grant2 = manager.approve(snapApproved.requestId);

    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snapApproved.requestId,
          token: grant2.token,
          executionPayloadHash: input2.executionPayloadHash,
          actor: input2.binding.actor,
          workspace: input2.binding.workspace,
          policyHash: '9'.repeat(64), // Mismatched policyHash
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
    assert.equal(manager.getRequest(snapApproved.requestId).state, 'INVALIDATED');
  });

  test('Group 3: Invalid transitions are strictly forbidden (fail closed)', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // APPROVED -> REJECTED is forbidden
    assert.throws(
      () => manager.reject(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // Consume it
    manager.redeemAndConsume({
      requestId: snap.requestId,
      token: grant.token,
      executionPayloadHash: input.executionPayloadHash,
      actor: input.binding.actor,
      workspace: input.binding.workspace,
      policyHash: input.binding.policyHash,
    });

    // Zero transitions out of CONSUMED
    assert.throws(
      () => manager.approve(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
    assert.throws(
      () => manager.reject(snap.requestId),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });

  // --- Group 4: Cryptographic Bindings & Tampering Defense ---
  test('Group 4: Execution payload hash mismatch fails redemption with APPROVAL_REJECTED', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: 'f'.repeat(64), // Tampered payload hash
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // State remains APPROVED until valid consumption or expiry
    assert.equal(manager.getRequest(snap.requestId).state, 'APPROVED');
  });

  test('Group 4: Actor binding mismatch (clientId, clientType, session, device) fails redemption', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // ClientId mismatch
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: { ...input.binding.actor, clientId: 'attacker-client' },
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // ClientType mismatch
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: { ...input.binding.actor, clientType: 'unauthorized-type' },
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // SessionId mismatch (different value or undefined)
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: { ...input.binding.actor, sessionId: 'other-session' },
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // DeviceId mismatch
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: { ...input.binding.actor, deviceId: undefined },
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });

  test('Group 4: Workspace binding mismatch (workspaceId, workspaceRootHash) fails redemption', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // workspaceId mismatch
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: { ...input.binding.workspace, workspaceId: 'other-ws' },
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // workspaceRootHash mismatch
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: { ...input.binding.workspace, workspaceRootHash: 'f'.repeat(64) },
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });

  test('Group 4: Token validation: wrong token, case-modified token, empty, oversized', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // Wrong token
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: '0'.repeat(64),
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // Case-modified token (uppercase) must fail timing-safe comparison
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token.toUpperCase(),
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    // Empty token
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: '',
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );

    // Oversized token (>128 UTF-8 bytes)
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: 'a'.repeat(129),
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );

    // Multibyte string whose character count <= 128 but byte count > 128
    // E.g. 70 copies of '🔒' (each emoji is 4 UTF-8 bytes = 280 bytes, char length 140 or 70 pairs)
    const multibyteOversized = '🔒'.repeat(40); // 40 * 4 = 160 bytes, length is 80 code units
    assert.ok(multibyteOversized.length <= 128);
    assert.ok(Buffer.byteLength(multibyteOversized, 'utf8') > 128);
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: multibyteOversized,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'INVALID_REQUEST_SCHEMA',
    );
  });

  test('Group 4: Policy reversion does NOT revive an INVALIDATED approval', () => {
    const manager = new ApprovalStateManager();
    const originalPolicy = '1'.repeat(64);
    const updatedPolicy = '2'.repeat(64);

    const input = createSampleInput({
      binding: {
        ...createSampleInput().binding,
        policyHash: originalPolicy,
      },
    });

    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // Redeem under updated policy -> transitions to INVALIDATED
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: updatedPolicy,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    assert.equal(manager.getRequest(snap.requestId).state, 'INVALIDATED');

    // Operator reverts policy back to originalPolicy -> record remains INVALIDATED
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: originalPolicy,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );

    assert.equal(manager.getRequest(snap.requestId).state, 'INVALIDATED');
  });

  // --- Group 5: Deduplication Semantics ---
  test('Group 5: PENDING deduplication preserves original record, TTL, and review buffer', () => {
    let fakeNowMono = 10_000_000_000n;
    let fakeNowWall = 1_700_000_000_000;
    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeNowMono,
      getWallTime: () => fakeNowWall,
    });

    const input = createSampleInput({ reviewMaterial: 'hello-review' });
    const snap1 = manager.createOrReusePending(input);

    // Advance 50 seconds
    fakeNowMono += 50_000_000_000n;
    fakeNowWall += 50_000;

    const snap2 = manager.createOrReusePending(input);

    assert.equal(snap1.requestId, snap2.requestId);
    assert.equal(snap2.createdAt, snap1.createdAt);
    assert.equal(snap2.remainingSeconds, 250); // Decreased accurately, did not reset to 300
    assert.equal(manager.listActive().length, 1);
  });

  test('Group 5: APPROVED deduplication returns existing requestId without minting new token or resetting TTL', () => {
    let fakeNowMono = 10_000_000_000n;
    let fakeNowWall = 1_700_000_000_000;
    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeNowMono,
      getWallTime: () => fakeNowWall,
    });

    const input = createSampleInput();
    const snap1 = manager.createOrReusePending(input);
    const grant = manager.approve(snap1.requestId);
    assert.equal(grant.snapshot.state, 'APPROVED');

    // Advance 30 seconds
    fakeNowMono += 30_000_000_000n;
    fakeNowWall += 30_000;

    // Subsequent createOrReusePending returns existing APPROVED snapshot
    const snap2 = manager.createOrReusePending(input);
    assert.equal(snap2.requestId, snap1.requestId);
    assert.equal(snap2.state, 'APPROVED');
    assert.equal(snap2.remainingSeconds, 270);

    // No raw token is leaked in the snapshot
    assert.equal(snap2.token, undefined);

    // Still consumable with original token
    const result = manager.redeemAndConsume({
      requestId: snap1.requestId,
      token: grant.token,
      executionPayloadHash: input.executionPayloadHash,
      actor: input.binding.actor,
      workspace: input.binding.workspace,
      policyHash: input.binding.policyHash,
    });
    assert.equal(result.consumed, true);
  });

  test('Group 5: Terminal state frees deduplication slot allowing fresh request', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();

    const snap1 = manager.createOrReusePending(input);
    manager.reject(snap1.requestId);
    assert.equal(manager.getRequest(snap1.requestId).state, 'REJECTED');

    // Slot is now released: identical input creates a fresh request with new requestId
    const snap2 = manager.createOrReusePending(input);
    assert.notEqual(snap2.requestId, snap1.requestId);
    assert.equal(snap2.state, 'PENDING');
  });

  // --- Group 6: Quotas & Resource Management ---
  test('Group 6: Global and per-actor record quotas enforce RESOURCE_EXHAUSTED', () => {
    const manager = new ApprovalStateManager({
      maxActiveApprovalsGlobal: 3,
      maxActiveApprovalsPerActor: 2,
    });

    const actorA = { clientId: 'alice', clientType: 'cli' };
    const actorB = { clientId: 'bob', clientType: 'cli' };

    // Actor A creates 2 records (reaches per-actor limit)
    manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '1'.repeat(64),
        binding: { ...createSampleInput().binding, actor: actorA },
      }),
    );
    manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '2'.repeat(64),
        binding: { ...createSampleInput().binding, actor: actorA },
      }),
    );

    // 3rd attempt for Actor A throws RESOURCE_EXHAUSTED
    assert.throws(
      () =>
        manager.createOrReusePending(
          createSampleInput({
            executionPayloadHash: '3'.repeat(64),
            binding: { ...createSampleInput().binding, actor: actorA },
          }),
        ),
      (err) => err.code === 'RESOURCE_EXHAUSTED',
    );

    // Actor B can create 1 record (reaching global limit of 3)
    manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '4'.repeat(64),
        binding: { ...createSampleInput().binding, actor: actorB },
      }),
    );

    // Global quota reached: Actor B attempt throws RESOURCE_EXHAUSTED
    assert.throws(
      () =>
        manager.createOrReusePending(
          createSampleInput({
            executionPayloadHash: '5'.repeat(64),
            binding: { ...createSampleInput().binding, actor: actorB },
          }),
        ),
      (err) => err.code === 'RESOURCE_EXHAUSTED',
    );
  });

  test('Group 6: Per-record, per-actor, and global review byte quotas', () => {
    const manager = new ApprovalStateManager({
      maxReviewBytesPerRecord: 100,
      maxReviewBytesPerActor: 150,
      maxReviewBytesGlobal: 250,
    });

    const actorA = { clientId: 'alice', clientType: 'cli' };

    // Per-record byte limit exceeded
    assert.throws(
      () =>
        manager.createOrReusePending(
          createSampleInput({
            reviewMaterial: 'x'.repeat(101),
          }),
        ),
      (err) => err.code === 'RESOURCE_EXHAUSTED',
    );

    // Admitting 80 bytes for actor A succeeds
    const snap1 = manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '1'.repeat(64),
        binding: { ...createSampleInput().binding, actor: actorA },
        reviewMaterial: 'x'.repeat(80),
      }),
    );
    assert.equal(snap1.reviewMaterialBytes, 80);

    // Admitting another 80 bytes for actor A exceeds per-actor limit of 150
    assert.throws(
      () =>
        manager.createOrReusePending(
          createSampleInput({
            executionPayloadHash: '2'.repeat(64),
            binding: { ...createSampleInput().binding, actor: actorA },
            reviewMaterial: 'x'.repeat(80),
          }),
        ),
      (err) => err.code === 'RESOURCE_EXHAUSTED',
    );
  });

  test('Group 6: Review material is dropped immediately upon approval, rejection, or expiry', () => {
    const manager = new ApprovalStateManager({
      maxReviewBytesPerActor: 100,
    });

    const marker = 'RC04_REVIEW_MATERIAL_MARKER_4817';

    // 1. Drop on approval
    const snap1 = manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '1'.repeat(64),
        reviewMaterial: marker,
      }),
    );
    assert.equal(manager.inspectPending(snap1.requestId), marker);

    manager.approve(snap1.requestId);
    assert.equal(manager.inspectPending(snap1.requestId), undefined);
    assert.equal(manager.getRequest(snap1.requestId).reviewMaterialBytes, 0);

    // 2. Drop on rejection
    const snap2 = manager.createOrReusePending(
      createSampleInput({
        executionPayloadHash: '2'.repeat(64),
        reviewMaterial: marker,
      }),
    );
    assert.equal(manager.inspectPending(snap2.requestId), marker);
    manager.reject(snap2.requestId);
    assert.equal(manager.inspectPending(snap2.requestId), undefined);
  });

  test('Group 6: Quotas are released on terminal state transition allowing subsequent admissions', () => {
    const manager = new ApprovalStateManager({
      maxActiveApprovalsGlobal: 1,
    });

    const snap1 = manager.createOrReusePending(
      createSampleInput({ executionPayloadHash: '1'.repeat(64) }),
    );

    // Global limit reached
    assert.throws(
      () =>
        manager.createOrReusePending(createSampleInput({ executionPayloadHash: '2'.repeat(64) })),
      (err) => err.code === 'RESOURCE_EXHAUSTED',
    );

    // Reject record 1 -> releases slot
    manager.reject(snap1.requestId);

    // Now record 2 can be admitted
    const snap2 = manager.createOrReusePending(
      createSampleInput({ executionPayloadHash: '2'.repeat(64) }),
    );
    assert.ok(snap2);
  });

  // --- Group 7: Monotonic Clock & Wall-Clock Rollback Resistance ---
  test('Group 7: Wall-clock rollback simulation does NOT extend monotonic TTL', () => {
    let fakeMono = 100_000_000_000n; // 100s
    let fakeWall = 1_700_000_000_000;

    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeMono,
      getWallTime: () => fakeWall,
    });

    const snap = manager.createOrReusePending(createSampleInput());

    // Monotonic clock advances 300 seconds (lifetime expired)
    fakeMono += 300_000_000_000n;

    // Attacker simulates wall-clock rollback by rolling back wall time 2 hours
    fakeWall -= 7_200_000;

    // Despite wall clock being in the past, monotonic deadline expired
    assert.throws(
      () => manager.approve(snap.requestId),
      (err) => err.code === 'APPROVAL_EXPIRED',
    );
  });

  test('Group 7: purgeExpired actively purges unapproved expired requests', () => {
    let fakeMono = 0n;
    const manager = new ApprovalStateManager({
      getMonotonicTime: () => fakeMono,
    });

    manager.createOrReusePending(createSampleInput({ executionPayloadHash: '1'.repeat(64) }));
    manager.createOrReusePending(createSampleInput({ executionPayloadHash: '2'.repeat(64) }));
    assert.equal(manager.listActive().length, 2);

    fakeMono += 300_000_000_000n;
    const purged = manager.purgeExpired();
    assert.equal(purged, 2);
    assert.equal(manager.listActive().length, 0);
  });

  // --- Group 8: Concurrency & Process-Local Atomicity ---
  test('Group 8: Concurrent consumption race executes tool at most once', async () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    // Fire 10 simultaneous redemptions
    const attempts = Array.from({ length: 10 }).map(async () => {
      try {
        return manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        });
      } catch (err) {
        return err;
      }
    });

    const results = await Promise.all(attempts);

    const successes = results.filter((r) => r && r.consumed === true);
    const failures = results.filter((r) => r instanceof ArcError && r.code === 'APPROVAL_REJECTED');

    assert.equal(successes.length, 1, 'Exactly one concurrent redemption must succeed');
    assert.equal(failures.length, 9, 'All other concurrent redemptions must be rejected');
    assert.equal(manager.getRequest(snap.requestId).state, 'CONSUMED');
  });

  test('Group 8: Concurrent duplicate creation requests produce exactly one active record', async () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();

    const attempts = Array.from({ length: 10 }).map(async () => {
      return manager.createOrReusePending(input);
    });

    const results = await Promise.all(attempts);
    const firstId = results[0].requestId;

    for (const res of results) {
      assert.equal(res.requestId, firstId);
    }
    assert.equal(manager.listActive().length, 1);
  });

  // --- Group 9: Defensive Copying & Immutability ---
  test('Group 9: Caller mutating input objects after creation does NOT mutate stored state', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();

    const snap = manager.createOrReusePending(input);

    // Mutate caller's original objects
    input.binding.actor.clientId = 'hacked-client';
    input.binding.workspace.workspaceId = 'hacked-workspace';
    input.binding.policyHash = 'f'.repeat(64);

    const stored = manager.getRequest(snap.requestId);
    assert.equal(stored.binding.actor.clientId, 'agent-alice');
    assert.equal(stored.binding.workspace.workspaceId, 'primary-ws');
    assert.equal(stored.binding.policyHash, '2'.repeat(64));
  });

  test('Group 9: Caller mutating snapshot objects returned from getRequest/listActive does NOT affect manager', () => {
    const manager = new ApprovalStateManager();
    const snap = manager.createOrReusePending(createSampleInput());

    const retrieved1 = manager.getRequest(snap.requestId);
    retrieved1.binding.actor.clientId = 'mutated-client';

    const retrieved2 = manager.getRequest(snap.requestId);
    assert.equal(retrieved2.binding.actor.clientId, 'agent-alice');
  });

  // --- Group 10: Zero Leakage of Raw Secrets ---
  test('Group 10: Raw token and review material are absent from all public outputs and errors', () => {
    const manager = new ApprovalStateManager();
    const marker = 'RC04_REVIEW_MATERIAL_MARKER_4817';
    const input = createSampleInput({ reviewMaterial: marker });

    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);
    const token = grant.token;

    // Public snapshots from getRequest and listActive must not contain the raw token or review marker
    const serializedReq = JSON.stringify(manager.getRequest(snap.requestId));
    assert.equal(
      serializedReq.includes(token),
      false,
      'Raw token must not appear in getRequest snapshot',
    );
    assert.equal(
      serializedReq.includes(marker),
      false,
      'Raw review material must not appear in snapshot',
    );

    const serializedList = JSON.stringify(manager.listActive());
    assert.equal(
      serializedList.includes(token),
      false,
      'Raw token must not appear in listActive snapshots',
    );
    assert.equal(
      serializedList.includes(marker),
      false,
      'Raw review material must not appear in listActive',
    );

    // Post-approval inspection must not return marker
    assert.equal(manager.inspectPending(snap.requestId), undefined);

    // Redemption consumption result must not contain token
    const consumeRes = manager.redeemAndConsume({
      requestId: snap.requestId,
      token,
      executionPayloadHash: input.executionPayloadHash,
      actor: input.binding.actor,
      workspace: input.binding.workspace,
      policyHash: input.binding.policyHash,
    });
    const serializedConsume = JSON.stringify(consumeRes);
    assert.equal(
      serializedConsume.includes(token),
      false,
      'Raw token must not appear in consumption result',
    );

    // Thrown error on replay must not leak token or hash
    try {
      manager.redeemAndConsume({
        requestId: snap.requestId,
        token,
        executionPayloadHash: input.executionPayloadHash,
        actor: input.binding.actor,
        workspace: input.binding.workspace,
        policyHash: input.binding.policyHash,
      });
      assert.fail('Should have thrown');
    } catch (err) {
      const serializedErr = JSON.stringify(err);
      assert.equal(
        serializedErr.includes(token),
        false,
        'Raw token must not appear in thrown error JSON',
      );
    }
  });

  // --- Group 11: Clear / Reset Semantics ---
  test('Group 11: clear() resets all approval records, dedup, and quotas', () => {
    const manager = new ApprovalStateManager();
    const input = createSampleInput();
    const snap = manager.createOrReusePending(input);
    const grant = manager.approve(snap.requestId);

    manager.clear();

    assert.equal(manager.listActive().length, 0);
    assert.equal(manager.getRequest(snap.requestId), undefined);

    // Old token redemption fails
    assert.throws(
      () =>
        manager.redeemAndConsume({
          requestId: snap.requestId,
          token: grant.token,
          executionPayloadHash: input.executionPayloadHash,
          actor: input.binding.actor,
          workspace: input.binding.workspace,
          policyHash: input.binding.policyHash,
        }),
      (err) => err.code === 'APPROVAL_REJECTED',
    );
  });
});
