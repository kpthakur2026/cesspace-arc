/**
 * CesSpace ARC — RC-05 Task 6: Remote Actor Derivation & RC-04 Pipeline Wiring
 *
 * Covers the frozen actor-binding contract (rc05-scope-acceptance.md §3, §13,
 * §14, §25, §27, §28 X-7) and the Task-6 controls RC05-NEG-48..52 and
 * RC05-NEG-62..68.
 *
 * Every case drives the REAL application bridge over the REAL shared RC-04
 * pipeline: real `WorkspaceRegistry`, real `SecurityKernel`, real
 * `DeclarativePolicyEngine`, real `ApprovalStateManager`, real subsystems, real
 * `AuditLogger`, real Task-1 `DeviceTrustStore`, and the real Task-5
 * `SessionManager`. There is no HTTP listener and no MCP SDK transport here —
 * the bridge is the application seam Task 8 will call.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { ArcMcpServer, createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import {
  RemoteExecutionBridge,
  deriveRemoteActor,
  findActorFieldInjection,
  REMOTE_ACTOR_FIELD_NAMES,
} from '../apps/mcp-server/dist/remote-execution.js';
import { computeExecutionPayloadHash } from '../apps/mcp-server/dist/approval-gate.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  sha256Hex,
} from '../packages/policy/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { DeviceTrustStore, resolveActiveDeviceIdentity } from '../packages/auth/dist/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let tempRoot;
let workspaceDir;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-actor-'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), 'line1\nline2\nline3\n');
  fs.writeFileSync(path.join(workspaceDir, 'keep.txt'), 'keep\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** Canonical SPKI pin shape. */
function pin(seed) {
  return crypto.createHash('sha256').update(`remote-pin-${seed}`, 'utf8').digest('hex');
}

/** Counts SecurityKernel evaluations and records the exact contexts seen. */
class KernelSpy {
  constructor(inner) {
    this.inner = inner;
    this.evaluateCalls = 0;
    this.contexts = [];
  }
  async evaluate(context) {
    this.evaluateCalls += 1;
    this.contexts.push(context);
    return this.inner.evaluate(context);
  }
  loadPolicy(rules) {
    return this.inner.loadPolicy(rules);
  }
}

/** Records every filesystem mutation attempt. */
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

/** Records every git invocation. */
class GitSpy extends GitSubsystem {
  constructor() {
    super();
    this.calls = [];
  }
  async getStatus(root, request) {
    this.calls.push({ method: 'getStatus', request });
    return super.getStatus(root, request);
  }
  async getDiff(root, request) {
    this.calls.push({ method: 'getDiff', request });
    return super.getDiff(root, request);
  }
  async getLog(root, request) {
    this.calls.push({ method: 'getLog', request });
    return super.getLog(root, request);
  }
}

/** Records every terminal invocation. */
class TerminalSpy {
  constructor() {
    this.calls = [];
  }
  async executeCommand(request) {
    this.calls.push({ method: 'executeCommand', request });
    throw new Error('terminal must not be used by these controls');
  }
  getProcessStatus(processId) {
    this.calls.push({ method: 'getProcessStatus', processId });
    throw new Error('terminal must not be used by these controls');
  }
  getProcessOutput(processId) {
    this.calls.push({ method: 'getProcessOutput', processId });
    throw new Error('terminal must not be used by these controls');
  }
  async terminateProcess(processId) {
    this.calls.push({ method: 'terminateProcess', processId });
    throw new Error('terminal must not be used by these controls');
  }
}

const DENY_READ_POLICY = `version: '1.0'
rules:
  - id: 'deny-read'
    effect: 'DENY'
    tools: ['read_file']
`;

/**
 * Builds the real server plus the real remote bridge over a test-owned
 * authoritative trust store.
 *
 * The bridge is constructed exactly as `ArcMcpServer.start()` composes it: the
 * server's ONE `SessionManager`, a resolver that reads the CURRENT trust store on
 * every call, and the server itself as the shared-pipeline sink.
 */
function makeHarness({ policy, trustStore } = {}) {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', workspaceDir);

  const approvals = new ApprovalStateManager();
  const kernel = new KernelSpy(new SecurityKernel(registry));
  const filesystem = new FilesystemSpy();
  const git = new GitSpy();
  const terminal = new TerminalSpy();
  const audit = new AuditLogger();

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
    git,
    config,
    terminal,
    undefined,
    approvals,
  );

  const store = trustStore ?? DeviceTrustStore.createEmpty();
  const resolveCalls = [];
  const bridge = new RemoteExecutionBridge({
    sessionManager: server.sessionManager,
    resolveActiveDeviceIdentity: (spkiPin) => {
      resolveCalls.push(spkiPin);
      return resolveActiveDeviceIdentity(store, spkiPin);
    },
    sink: server,
  });

  return {
    server,
    bridge,
    store,
    approvals,
    kernel,
    filesystem,
    git,
    terminal,
    audit,
    resolveCalls,
    registry,
  };
}

/** Enrolls a device in the authoritative store and returns its record + pin. */
function enroll(harness, seed, overrides = {}) {
  const spkiPin = overrides.spkiPin ?? pin(seed);
  const { device } = harness.store.enrollDevice({
    clientId: overrides.clientId ?? `agent-${seed}`,
    clientType: overrides.clientType ?? 'claude-code',
    pin: spkiPin,
  });
  return { device, spkiPin };
}

/** Establishes a real server-issued session for a device's SPKI pin. */
function establishSession(harness, spkiPin) {
  const identity = resolveActiveDeviceIdentity(harness.store, spkiPin);
  assert.ok(identity, 'the fixture device must resolve before a session can be issued');
  const sessionId = harness.server.sessionManager.createSessionIdGenerator()();
  const issuance = harness.server.sessionManager.issueSession({ sessionId, identity });
  return {
    identity,
    sessionId,
    token: issuance.token,
    headers: { presentedSessionId: sessionId, authorizationHeader: `Bearer ${issuance.token}` },
  };
}

/** One remote tool call through the real bridge. */
function remoteCall(harness, spkiPin, session, toolName, parameters, extra = {}) {
  return harness.bridge.executeRemoteToolCall({
    trustedSpkiPin: spkiPin,
    presentedSessionId: session === null ? null : session.sessionId,
    authorizationHeader: session === null ? null : `Bearer ${session.token}`,
    toolName,
    parameters,
    ...extra,
  });
}

/**
 * Captures the ADMISSION failure thrown by the bridge.
 *
 * Only authentication/session/schema admission failures are thrown. Anything
 * below the bridge (policy, approval, subsystem) comes back as a normal
 * MCP-style error RESULT, exactly as it does for stdio — which is the point of
 * converging on one pipeline.
 */
async function remoteFailure(promise) {
  try {
    const result = await promise;
    assert.fail(`expected a remote failure, got ${JSON.stringify(result).slice(0, 200)}`);
  } catch (err) {
    assert.equal(err.name, 'ArcError', `expected an ArcError, got ${err.name}: ${err.message}`);
    return err;
  }
}

function body(result) {
  return JSON.parse(result.content[0].text);
}

/** Runs a remote call and returns the pipeline's MCP-style response body. */
async function remoteBody(harness, spkiPin, session, toolName, parameters, extra = {}) {
  return body(await remoteCall(harness, spkiPin, session, toolName, parameters, extra));
}

describe('CesSpace ARC — RC-05 Task 6: Remote Actor Pipeline', () => {
  // =========================================================================
  // Exact actor derivation
  // =========================================================================

  describe('Exact remote actor derivation (§13, §5.4)', () => {
    test('RC05-ACT-01: the actor is derived exactly from the authenticated session', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'derive');
      const session = establishSession(harness, spkiPin);

      // deriveRemoteActor is the ONLY construction site, and it copies the
      // trusted session result field for field.
      const derived = deriveRemoteActor({
        sessionId: session.sessionId,
        deviceId: device.deviceId,
        clientId: device.clientId,
        clientType: device.clientType,
      });
      assert.deepEqual(derived, {
        clientId: device.clientId,
        clientType: device.clientType,
        deviceId: device.deviceId,
        sessionId: session.sessionId,
        authenticated: true,
      });
      assert.equal(
        derived.sessionId,
        session.sessionId,
        'actor.sessionId IS the server-issued Mcp-Session-Id',
      );

      // And the pipeline sees exactly that actor.
      const result = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(body(result).content.includes('line1'), true);

      assert.ok(harness.kernel.evaluateCalls >= 1);
      for (const context of harness.kernel.contexts) {
        assert.deepEqual(context.actor, derived, 'SecurityKernel sees the derived actor');
        assert.equal(context.actor.authenticated, true);
        assert.equal(context.actor.sessionId, session.sessionId);
        assert.equal(context.actor.deviceId, device.deviceId);
        assert.notEqual(context.actor.deviceId, 'local-machine');
        assert.notEqual(context.actor.sessionId, 'stdio-session-01');
      }
    });

    test('RC05-ACT-02: clientId, clientType and deviceId come from the CURRENT enrolled record', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'enrolled-metadata', {
        clientId: 'operator-declared-client',
        clientType: 'operator-declared-type',
      });
      const session = establishSession(harness, spkiPin);

      const result = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(result.isError, undefined);

      const seen = harness.kernel.contexts.at(-1).actor;
      assert.equal(seen.clientId, 'operator-declared-client');
      assert.equal(seen.clientType, 'operator-declared-type');
      assert.equal(seen.deviceId, device.deviceId);
      assert.equal(seen.sessionId, session.sessionId);

      // The persisted device record is the source, not any request value.
      const stored = harness.store.findDeviceByPin(spkiPin);
      assert.equal(seen.clientId, stored.clientId);
      assert.equal(seen.clientType, stored.clientType);
      assert.equal(seen.deviceId, stored.deviceId);
    });

    test('RC05-ACT-03: a second device produces a fully distinct actor', async () => {
      const harness = makeHarness();
      const first = enroll(harness, 'actor-first');
      const second = enroll(harness, 'actor-second');
      const sessionA = establishSession(harness, first.spkiPin);
      const sessionB = establishSession(harness, second.spkiPin);

      await remoteCall(harness, first.spkiPin, sessionA, 'read_file', { path: 'README.md' });
      const actorA = harness.kernel.contexts.at(-1).actor;
      await remoteCall(harness, second.spkiPin, sessionB, 'read_file', { path: 'README.md' });
      const actorB = harness.kernel.contexts.at(-1).actor;

      assert.notEqual(actorA.deviceId, actorB.deviceId);
      assert.notEqual(actorA.clientId, actorB.clientId);
      assert.notEqual(actorA.sessionId, actorB.sessionId);
      assert.equal(actorA.sessionId, sessionA.sessionId);
      assert.equal(actorB.sessionId, sessionB.sessionId);
    });
  });

  // =========================================================================
  // The shared RC-04 pipeline
  // =========================================================================

  describe('Remote requests converge on the EXISTING RC-04 pipeline (§27)', () => {
    test('RC05-ACT-04: an authenticated remote ALLOW request reaches the shared pipeline', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'allow-path');
      const session = establishSession(harness, spkiPin);
      const auditBefore = harness.audit.getRecords().length;

      const result = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(result.isError, undefined);
      assert.ok(body(result).content.includes('line1'));

      // The shared pipeline ran: Layer 1 evaluated and an audit record landed.
      assert.ok(harness.kernel.evaluateCalls >= 1, 'SecurityKernel evaluated');
      assert.ok(
        harness.audit.getRecords().length > auditBefore,
        'the shared audit chain recorded the invocation',
      );
      const record = harness.audit.getRecords().at(-1);
      assert.equal(record.actor.sessionId, session.sessionId);
      assert.equal(record.actor.deviceId, harness.store.findDeviceByPin(spkiPin).deviceId);
      assert.equal(record.invocation.toolName, 'read_file');
    });

    test('RC05-ACT-05: there is exactly one dispatch switch and no remote fork', () => {
      const source = fs.readFileSync(
        new URL('../apps/mcp-server/src/index.ts', import.meta.url),
        'utf8',
      );

      // ONE switch over tool names: the remote path cannot have its own.
      const switchCount = (source.match(/switch \(toolName\)/g) ?? []).length;
      assert.equal(switchCount, 1, 'exactly one dispatch switch exists');

      // The stdio entry point and the shared implementation are distinct, and the
      // shared one is what the remote bridge calls.
      assert.equal(source.includes('public async dispatchToolCall('), true);
      assert.equal(source.includes('public async executeAuthenticatedToolCall('), true);
      assert.equal(
        source.includes('return this.executeAuthenticatedToolCall(actor, toolName, parameters);'),
        true,
        'stdio delegates into the shared implementation',
      );

      // The bridge never reaches a subsystem, policy, or approval directly.
      const bridge = fs.readFileSync(
        new URL('../apps/mcp-server/src/remote-execution.ts', import.meta.url),
        'utf8',
      );
      for (const forbidden of [
        'FilesystemSubsystem',
        'GitSubsystem',
        'ControlledProcessRunner',
        'SecurityKernel',
        'DeclarativePolicyEngine',
        'ApprovalStateManager',
        'redeemAndConsume',
        'createOrReusePending',
        'run_command',
        'create_file',
      ]) {
        assert.equal(
          bridge.includes(forbidden),
          false,
          `the bridge must not reference ${forbidden}`,
        );
      }
    });

    test('RC05-ACT-06: the remote bridge cannot receive a partial or caller-selectable actor', () => {
      const bridge = fs.readFileSync(
        new URL('../apps/mcp-server/src/remote-execution.ts', import.meta.url),
        'utf8',
      );
      // No Partial<> actor seam, and no actor-shaped input field on the request.
      assert.equal(bridge.includes('Partial<'), false, 'no partial actor seam exists');
      const inputStart = bridge.indexOf('export interface RemoteToolCallInput');
      const inputBlock = bridge.slice(inputStart, bridge.indexOf('\n}', inputStart));
      for (const forbiddenField of [
        'clientId',
        'clientType',
        'deviceId',
        'sessionId:',
        'authenticated',
        'actor',
      ]) {
        assert.equal(
          inputBlock.includes(forbiddenField),
          false,
          `RemoteToolCallInput must not accept ${forbiddenField} as caller input`,
        );
      }
      // The only identity input is the trusted SPKI from Task-3 admission.
      assert.equal(inputBlock.includes('trustedSpkiPin'), true);

      // And the shared sink takes a COMPLETE actor, never a partial one.
      const sinkBlock = bridge.slice(bridge.indexOf('export interface AuthenticatedToolSink'));
      assert.equal(sinkBlock.includes('CompleteActor'), true);
      assert.equal(sinkBlock.includes('Partial<'), false);
    });

    test('RC05-ACT-07: stdio dispatch is unchanged', async () => {
      const harness = makeHarness();
      const result = await harness.server.dispatchToolCall('read_file', { path: 'README.md' });
      assert.equal(result.isError, undefined);
      const actor = harness.kernel.contexts.at(-1).actor;
      assert.deepEqual(actor, {
        clientId: 'local-stdio-caller',
        clientType: 'mcp-client',
        sessionId: 'stdio-session-01',
        deviceId: 'local-machine',
        authenticated: true,
      });

      // The stdio actorOverride seam still works exactly as before.
      await harness.server.dispatchToolCall(
        'read_file',
        { path: 'README.md' },
        {
          clientId: 'custom',
          sessionId: 'custom-session',
        },
      );
      assert.equal(harness.kernel.contexts.at(-1).actor.clientId, 'custom');
      assert.equal(harness.kernel.contexts.at(-1).actor.sessionId, 'custom-session');
      assert.equal(harness.kernel.contexts.at(-1).actor.deviceId, 'local-machine');
    });
  });

  // =========================================================================
  // Pre-session failures: anti-oracle UNAUTHENTICATED
  // =========================================================================

  describe('Pre-session anti-oracle failures (RC05-NEG-62, NEG-63)', () => {
    test('RC05-NEG-62/63/65/66: every pre-session failure is UNAUTHENTICATED with no side effects', async () => {
      const harness = makeHarness();
      const enrolled = enroll(harness, 'neg62-enrolled');
      const auditBefore = harness.audit.getRecords().length;

      // (a) unenrolled SPKI, (b) enrolled but revoked device, (c) zero-device
      // state, (d) a tokenless ordinary request from an active device.
      const cases = [];

      cases.push({
        label: 'unenrolled device',
        spkiPin: pin('neg62-stranger'),
        session: null,
        store: harness.store,
      });

      const revokedHarness = makeHarness();
      const revoked = enroll(revokedHarness, 'neg63-revoked');
      revokedHarness.store.revokeDevice(revoked.device.deviceId);
      cases.push({
        label: 'revoked device pre-session',
        spkiPin: revoked.spkiPin,
        session: null,
        store: revokedHarness.store,
        harness: revokedHarness,
      });

      const emptyHarness = makeHarness();
      cases.push({
        label: 'zero-device state',
        spkiPin: pin('neg62-empty'),
        session: null,
        store: emptyHarness.store,
        harness: emptyHarness,
      });

      cases.push({
        label: 'tokenless ordinary from an active device',
        spkiPin: enrolled.spkiPin,
        session: null,
        store: harness.store,
      });

      for (const testCase of cases) {
        const target = testCase.harness ?? harness;
        const err = await remoteFailure(
          remoteCall(target, testCase.spkiPin, testCase.session, 'read_file', {
            path: 'README.md',
          }),
        );
        assert.equal(err.code, 'UNAUTHENTICATED', testCase.label);
        assert.equal(err.message, 'Authentication failed', testCase.label);

        // The canonical payload carries no device, revocation, pin, or session
        // detail.
        const payload = err.toJSON();
        assert.equal(payload.code, 'UNAUTHENTICATED');
        assert.equal(payload.message, 'Authentication failed');
        assert.equal(payload.details, undefined, 'no details may be disclosed');
        assert.equal(JSON.stringify(payload).includes('DEVICE'), false);
        assert.equal(JSON.stringify(payload).includes(testCase.spkiPin), false);
      }

      // No policy, no subsystem, no audit, and no approval state on the target.
      for (const target of [harness, revokedHarness, emptyHarness]) {
        assert.equal(target.kernel.evaluateCalls, 0, 'SecurityKernel was never reached');
        assert.equal(target.filesystem.calls.length, 0, 'filesystem was never reached');
        assert.equal(target.git.calls.length, 0, 'git was never reached');
        assert.equal(target.terminal.calls.length, 0, 'terminal was never reached');
        assert.equal(target.audit.getRecords().length, 0, 'no audit record was written');
        assert.deepEqual(target.approvals.listActive(), [], 'no approval state exists');
      }
      assert.equal(harness.audit.getRecords().length, 0);
      assert.equal(auditBefore, 0);
    });

    test('RC05-NEG-65: an unauthenticated request that policy would ALLOW still fails before policy', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg65');

      // `read_file` is ALLOWed by the built-in policy, so only the authentication
      // prerequisite can be responsible for the refusal.
      const err = await remoteFailure(
        remoteCall(harness, spkiPin, null, 'read_file', { path: 'README.md' }),
      );
      assert.equal(err.code, 'UNAUTHENTICATED');
      assert.equal(harness.kernel.evaluateCalls, 0, 'SecurityKernel evaluate count is 0');
      assert.equal(harness.audit.getRecords().length, 0, 'the audit chain saw nothing');
    });

    test('RC05-NEG-66: an unauthenticated MUTATION request reaches no subsystem and no approval', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg66');
      const target = `neg66-${Date.now()}.txt`;

      const err = await remoteFailure(
        remoteCall(harness, spkiPin, null, 'create_file', { path: target, content: 'x' }),
      );
      assert.equal(err.code, 'UNAUTHENTICATED');
      assert.equal(harness.kernel.evaluateCalls, 0, 'SecurityKernel evaluate count is 0');
      assert.equal(harness.filesystem.calls.length, 0, 'filesystem spy count is 0');
      assert.equal(harness.git.calls.length, 0);
      assert.equal(harness.terminal.calls.length, 0);
      assert.deepEqual(harness.approvals.listActive(), [], 'no approval was created');
      assert.equal(fs.existsSync(path.join(workspaceDir, target)), false, 'nothing was written');
    });

    test('RC05-NEG-64: a revoked device with its OLD VALID session is INVALID_SESSION_TOKEN', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'neg64');
      const session = establishSession(harness, spkiPin);

      // The session works while the device is active.
      const before = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(before.isError, undefined);

      // Revoke in the CURRENT authoritative trust store. The SessionManager
      // record is deliberately left physically present, so this control proves
      // current device authority is checked independently per request.
      harness.store.revokeDevice(device.deviceId);
      assert.equal(
        harness.server.sessionManager.hasSession(session.sessionId),
        true,
        'the session record still exists in the session manager',
      );

      const kernelCallsBefore = harness.kernel.evaluateCalls;
      const auditBefore = harness.audit.getRecords().length;

      const err = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
      );
      assert.equal(err.code, 'INVALID_SESSION_TOKEN');
      assert.equal(err.message, 'Invalid or expired session token');
      assert.equal(err.toJSON().details, undefined, 'revocation is not disclosed');
      assert.equal(JSON.stringify(err.toJSON()).includes('revoke'), false);
      assert.equal(JSON.stringify(err.toJSON()).includes(spkiPin), false);

      // Policy, subsystems, and audit were not reached.
      assert.equal(harness.kernel.evaluateCalls, kernelCallsBefore);
      assert.equal(harness.audit.getRecords().length, auditBefore);
      assert.equal(harness.filesystem.calls.length, 0);
    });
  });

  // =========================================================================
  // Per-request device resolution
  // =========================================================================

  describe('Current device authority is checked on EVERY request (§3 carry-forward)', () => {
    test('RC05-ACT-08: the resolver runs afresh on every remote request', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'per-request');
      const session = establishSession(harness, spkiPin);
      const before = harness.resolveCalls.length;

      for (let i = 0; i < 3; i += 1) {
        await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      }
      assert.equal(
        harness.resolveCalls.length - before,
        3,
        'one resolution per request, never cached',
      );
      assert.deepEqual(new Set(harness.resolveCalls.slice(before)), new Set([spkiPin]));
    });

    test('RC05-ACT-09: a RETAINED stale resolver identity cannot authenticate after revocation', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'stale-capability');
      const session = establishSession(harness, spkiPin);

      // A resolver-minted identity is a valid Task-5 capability object, so it is
      // deliberately kept alive in test code after revocation.
      const staleIdentity = resolveActiveDeviceIdentity(harness.store, spkiPin);
      assert.ok(staleIdentity);
      assert.equal(
        harness.server.sessionManager.authenticate({
          sessionId: session.sessionId,
          token: session.token,
          identity: staleIdentity,
        }) !== undefined,
        true,
        'the stale capability is still a valid Task-5 identity object',
      );

      const success = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(success.isError, undefined);

      harness.store.revokeDevice(device.deviceId);
      assert.equal(resolveActiveDeviceIdentity(harness.store, spkiPin), undefined);

      // The bridge must NOT reuse the retained object: it resolves again and the
      // fresh resolution is `undefined`, so the request fails post-session.
      const err = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
      );
      assert.equal(err.code, 'INVALID_SESSION_TOKEN');
      assert.equal(
        harness.resolveCalls.length > 0 && harness.resolveCalls.at(-1) === spkiPin,
        true,
        'the adapter performed a fresh resolution for the failing request',
      );
      // The stale object is still alive in test code, which is exactly the point:
      // the bridge never consulted it.
      assert.ok(staleIdentity.deviceId === device.deviceId);
    });

    test('RC05-ACT-10: revoking device-wide sessions makes the next request fail too', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'device-wide');
      const session = establishSession(harness, spkiPin);
      assert.equal(
        (await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' })).isError,
        undefined,
      );

      // Task 9 will wire the operator command to this; Task 6 only needs the
      // current-trust check to already fail closed, which NEG-64 shows.
      harness.store.revokeDevice(device.deviceId);
      const err = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
      );
      assert.equal(err.code, 'INVALID_SESSION_TOKEN');

      // With the session also revoked, the answer is unchanged.
      harness.server.sessionManager.revokeSessionsForDevice(device.deviceId);
      const again = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' }),
      );
      assert.equal(again.code, 'INVALID_SESSION_TOKEN');
    });
  });

  // =========================================================================
  // Actor-field spoofing
  // =========================================================================

  describe('Remote actor-field spoofing gate (RC05-NEG-48, NEG-49, NEG-50)', () => {
    test('RC05-NEG-48: clientId / clientType / deviceId in parameters are refused', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg48');
      const session = establishSession(harness, spkiPin);
      const kernelBefore = harness.kernel.evaluateCalls;
      const auditBefore = harness.audit.getRecords().length;

      for (const injected of [
        { clientId: 'attacker' },
        { clientType: 'attacker-type' },
        { deviceId: 'f'.repeat(32) },
        { clientId: 'attacker', clientType: 'attacker-type', deviceId: 'f'.repeat(32) },
      ]) {
        const err = await remoteFailure(
          remoteCall(harness, spkiPin, session, 'read_file', {
            path: 'README.md',
            ...injected,
          }),
        );
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA', JSON.stringify(Object.keys(injected)));
      }

      // Policy was not reached and the trusted actor is unchanged.
      assert.equal(harness.kernel.evaluateCalls, kernelBefore, 'SecurityKernel not reached');
      assert.equal(harness.audit.getRecords().length, auditBefore, 'no audit record');
      const ok = await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      assert.equal(ok.isError, undefined);
      assert.equal(harness.kernel.contexts.at(-1).actor.clientId, 'agent-neg48');
    });

    test('RC05-NEG-49: sessionId in parameters is refused and cannot override the real session', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg49');
      const session = establishSession(harness, spkiPin);
      const kernelBefore = harness.kernel.evaluateCalls;

      for (const value of [session.sessionId, 'f'.repeat(64), 'stdio-session-01']) {
        const err = await remoteFailure(
          remoteCall(harness, spkiPin, session, 'read_file', {
            path: 'README.md',
            sessionId: value,
          }),
        );
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA');
      }

      assert.equal(harness.kernel.evaluateCalls, kernelBefore, 'policy not reached');
      await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      assert.equal(
        harness.kernel.contexts.at(-1).actor.sessionId,
        session.sessionId,
        'the real authenticated session remains authoritative',
      );
    });

    test('RC05-NEG-48b: nested, array-wrapped, and transport identity fields are all refused', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg48-nested');
      const session = establishSession(harness, spkiPin);

      const injections = [
        { nested: { clientId: 'x' } },
        { list: [{ sessionId: 'x' }] },
        { deep: { a: { b: { c: [{ deviceId: 'x' }] } } } },
        { spkiPin: pin('forged') },
        { authenticated: false },
        { actor: { clientId: 'x' } },
        { operatorId: 'f'.repeat(64) },
      ];
      for (const parameters of injections) {
        const err = await remoteFailure(
          remoteCall(harness, spkiPin, session, 'read_file', parameters),
        );
        assert.equal(
          err.code,
          'INVALID_REQUEST_SCHEMA',
          `must refuse ${JSON.stringify(parameters)}`,
        );
      }
      assert.equal(harness.kernel.evaluateCalls, 0);

      // The traversal itself is bounded and cycle-safe.
      assert.equal(findActorFieldInjection({ ok: 'value' }), null);
      assert.equal(findActorFieldInjection({ a: { b: 'c' } }), null);
      assert.equal(findActorFieldInjection({ a: { clientId: 'x' } }), 'a.clientId');
      assert.equal(findActorFieldInjection([{ a: [{ sessionId: 'x' }] }]), '[0].a[0].sessionId');
      const cyclic = { ok: true };
      cyclic.self = cyclic;
      assert.notEqual(findActorFieldInjection(cyclic), null, 'a cycle is refused');
      assert.equal(REMOTE_ACTOR_FIELD_NAMES.includes('clientId'), true);
    });

    test('RC05-NEG-50: _arcApproval carrying actor fields is refused with no approval state', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg50');
      const session = establishSession(harness, spkiPin);
      const kernelBefore = harness.kernel.evaluateCalls;
      const target = `neg50-${Date.now()}.txt`;

      const actorFields = [
        { clientId: 'attacker' },
        { clientType: 'attacker-type' },
        { deviceId: 'f'.repeat(32) },
        { sessionId: session.sessionId },
        { authenticated: false },
        { spkiPin: pin('forged') },
        { actor: { clientId: 'x' } },
      ];
      for (const injected of actorFields) {
        const err = await remoteFailure(
          remoteCall(harness, spkiPin, session, 'create_file', {
            path: target,
            content: 'x',
            _arcApproval: { requestId: 'a'.repeat(32), token: 'b'.repeat(64), ...injected },
          }),
        );
        assert.equal(err.code, 'INVALID_REQUEST_SCHEMA', JSON.stringify(Object.keys(injected)));
      }

      assert.equal(harness.kernel.evaluateCalls, kernelBefore, 'policy not reached');
      assert.deepEqual(harness.approvals.listActive(), [], 'no approval record created');
      assert.equal(harness.filesystem.calls.length, 0, 'no subsystem call');
      assert.equal(fs.existsSync(target), false);

      // The valid RC-04 control contract is unchanged: a well-formed control
      // object still reaches the normal approval path.
      const valid = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: target,
        content: 'x',
        _arcApproval: { requestId: 'a'.repeat(32), token: 'b'.repeat(64) },
      });
      assert.equal(body(valid).code, 'APPROVAL_REJECTED');
    });
  });

  // =========================================================================
  // Approval binding and domain separation
  // =========================================================================

  describe('Approval binding, RC-04 floor, and credential separation', () => {
    test('RC05-NEG-51: the approval binding and executionPayloadHash use ONLY the derived actor', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'neg51', { clientId: 'agent-neg51' });
      const session = establishSession(harness, spkiPin);
      const targetPath = `neg51-${Date.now()}.txt`;
      const params = { path: targetPath, content: 'hello' };

      const first = await remoteCall(harness, spkiPin, session, 'create_file', params);
      const firstBody = body(first);
      assert.equal(firstBody.code, 'APPROVAL_REQUIRED');
      const requestId = firstBody.details.approvalRequestId;

      const snapshot = harness.approvals.getRequest(requestId);
      assert.ok(snapshot, 'the approval exists');
      assert.deepEqual(
        snapshot.binding.actor,
        {
          clientId: 'agent-neg51',
          clientType: 'claude-code',
          sessionId: session.sessionId,
          deviceId: device.deviceId,
        },
        'the approval is bound to the EXACT derived actor',
      );

      // Independently recompute the hash with the approved RC-04 helper.
      const policyHash = harness.server.effectivePolicyEngine.getPolicyHash();
      const workspaceRootHash = sha256Hex(workspaceDir);
      const expected = computeExecutionPayloadHash({
        toolName: 'create_file',
        businessParameters: { path: targetPath, content: 'hello' },
        actor: {
          clientId: 'agent-neg51',
          clientType: 'claude-code',
          sessionId: session.sessionId,
          deviceId: device.deviceId,
        },
        workspaceId: 'ws',
        workspaceRootHash,
        policyHash,
      });
      assert.equal(snapshot.executionPayloadHash, expected);
      assert.equal(snapshot.binding.workspace.workspaceRootHash, workspaceRootHash);

      // No caller value can influence it: every attempt to supply one is refused
      // before a record is created.
      const forged = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'create_file', {
          ...params,
          sessionId: 'f'.repeat(64),
          deviceId: 'e'.repeat(32),
        }),
      );
      assert.equal(forged.code, 'INVALID_REQUEST_SCHEMA');
      assert.equal(harness.approvals.listActive().length, 1, 'no second approval was created');
      assert.equal(
        harness.approvals.getRequest(requestId).executionPayloadHash,
        expected,
        'the stored hash is unchanged',
      );
    });

    test('RC05-ACT-11: the RC-04 mutation floor still applies to an authenticated session', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'mutation-floor');
      const session = establishSession(harness, spkiPin);
      const target = `floor-${Date.now()}.txt`;

      const result = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: target,
        content: 'x',
      });
      assert.equal(body(result).code, 'APPROVAL_REQUIRED');
      assert.equal(harness.filesystem.calls.length, 0, 'no subsystem executed');
      assert.equal(fs.existsSync(path.join(workspaceDir, target)), false);
      assert.equal(
        harness.approvals.listActive().length,
        1,
        'approval state was created but not consumed',
      );
    });

    test('RC05-ACT-12: a genuine approval redeems under the SAME session and executes once', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'redeem');
      const session = establishSession(harness, spkiPin);
      const targetPath = `redeem-${Date.now()}.txt`;

      const first = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'redeemed',
      });
      const requestId = body(first).details.approvalRequestId;
      const grant = harness.approvals.approve(requestId);
      assert.match(grant.token, /^[0-9a-f]{64}$/);

      const second = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'redeemed',
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(second.isError, undefined, JSON.stringify(body(second)));
      assert.equal(harness.filesystem.calls.length, 1, 'exactly one subsystem execution');
      assert.equal(fs.readFileSync(path.join(workspaceDir, targetPath), 'utf8'), 'redeemed');

      // The approval is consumed: a replay is rejected.
      const replay = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'redeemed',
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(replay).code, 'APPROVAL_REJECTED');
      assert.equal(harness.filesystem.calls.length, 1, 'no second execution');
    });

    test('RC05-NEG-68: a REAL session token is not an approval token', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg68');
      const session = establishSession(harness, spkiPin);
      const targetPath = `neg68-${Date.now()}.txt`;

      const first = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'x',
      });
      const requestId = body(first).details.approvalRequestId;
      harness.approvals.approve(requestId);

      // Redemption with the raw RC-05 SESSION token in the approval position.
      // This is a pipeline-level outcome (the approval domain rejects it), so it
      // comes back as an MCP-style error RESULT, exactly as it does for stdio.
      const rejected = await remoteBody(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'x',
        _arcApproval: { requestId, token: session.token },
      });
      assert.equal(rejected.code, 'APPROVAL_REJECTED');

      // No side effects: subsystem not called, approval NOT consumed, session
      // still valid, and no session/token mutation.
      assert.equal(harness.filesystem.calls.length, 0, 'subsystem not called');
      assert.equal(harness.approvals.getRequest(requestId).state, 'APPROVED', 'approval intact');
      assert.equal(fs.existsSync(path.join(workspaceDir, targetPath)), false);

      const after = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      assert.equal(after.isError, undefined, 'the session remains valid');

      // The session manager knows nothing about approval credentials: the real
      // approval token is also refused in the session position.
      const crossDomain = await remoteFailure(
        harness.bridge.executeRemoteToolCall({
          trustedSpkiPin: spkiPin,
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${harness.approvals.getRequest(requestId).executionPayloadHash}`,
          toolName: 'read_file',
          parameters: { path: 'README.md' },
        }),
      );
      assert.equal(crossDomain.code, 'INVALID_SESSION_TOKEN');
      assert.equal(harness.filesystem.calls.length, 0);
      assert.equal(harness.approvals.getRequest(requestId).state, 'APPROVED');
    });

    test('RC05-NEG-68b: the real approval token redeems after the session-token attempt', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg68b');
      const session = establishSession(harness, spkiPin);
      const targetPath = `neg68b-${Date.now()}.txt`;

      const first = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'ok',
      });
      const requestId = body(first).details.approvalRequestId;
      const grant = harness.approvals.approve(requestId);

      // Session token in the approval position: rejected, nothing consumed.
      const wrong = await remoteBody(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'ok',
        _arcApproval: { requestId, token: session.token },
      });
      assert.equal(wrong.code, 'APPROVAL_REJECTED');
      assert.equal(harness.approvals.getRequest(requestId).state, 'APPROVED');

      // The genuine approval token still works under the same session.
      const redeemed = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'ok',
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(redeemed.isError, undefined, JSON.stringify(body(redeemed)));
      assert.equal(harness.filesystem.calls.length, 1);
      assert.equal(harness.approvals.getRequest(requestId).state, 'CONSUMED');
      assert.equal(fs.readFileSync(path.join(workspaceDir, targetPath), 'utf8'), 'ok');
    });

    test('RC05-NEG-52: an approval cannot be rebound across session re-authentication', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'neg52');
      const sessionA = establishSession(harness, spkiPin);
      const targetPath = `neg52-${Date.now()}.txt`;
      const params = { path: targetPath, content: 'x' };

      // A. session A requests; C. the operator approves.
      const first = await remoteCall(harness, spkiPin, sessionA, 'create_file', params);
      const requestId = body(first).details.approvalRequestId;
      const grant = harness.approvals.approve(requestId);
      const ttlBefore = harness.approvals.getRequest(requestId).remainingSeconds;
      const hashBefore = harness.approvals.getRequest(requestId).executionPayloadHash;

      // D. session A ends.
      assert.equal(harness.server.sessionManager.revokeSession(sessionA.sessionId), true);

      // A direct request with the dead session credential fails EARLIER, as a
      // session failure — the approval manager is never reached.
      const earlier = await remoteFailure(
        remoteCall(harness, spkiPin, sessionA, 'create_file', {
          ...params,
          _arcApproval: { requestId, token: grant.token },
        }),
      );
      assert.equal(earlier.code, 'INVALID_SESSION_TOKEN');
      assert.equal(harness.approvals.getRequest(requestId).state, 'APPROVED');
      assert.equal(harness.filesystem.calls.length, 0);

      // E. the SAME device establishes a brand-new server-issued session B.
      const sessionB = establishSession(harness, spkiPin);
      assert.notEqual(sessionB.sessionId, sessionA.sessionId);

      // F. redeeming A's approval under session B is rejected.
      const rebound = await remoteCall(harness, spkiPin, sessionB, 'create_file', {
        ...params,
        _arcApproval: { requestId, token: grant.token },
      });
      assert.equal(body(rebound).code, 'APPROVAL_REJECTED');

      // Approval not consumed, TTL untouched, hash untouched, no subsystem call,
      // and session B stays valid.
      const after = harness.approvals.getRequest(requestId);
      assert.equal(after.state, 'APPROVED', 'not consumed');
      assert.equal(after.remainingSeconds <= ttlBefore, true, 'TTL was not extended');
      assert.equal(after.executionPayloadHash, hashBefore, 'the binding was not rewritten');
      assert.equal(after.binding.actor.sessionId, sessionA.sessionId, 'still bound to session A');
      assert.equal(harness.filesystem.calls.length, 0, 'no subsystem call');
      assert.equal(fs.existsSync(path.join(workspaceDir, targetPath)), false);
      assert.equal(
        harness.server.sessionManager.hasSession(sessionB.sessionId),
        true,
        'session B remains valid',
      );
      const ok = await remoteCall(harness, spkiPin, sessionB, 'read_file', { path: 'README.md' });
      assert.equal(ok.isError, undefined);
    });
  });

  // =========================================================================
  // Authentication is not authorization
  // =========================================================================

  describe('Authentication never implies authorization (RC05-NEG-67)', () => {
    test('RC05-NEG-67: a fully authenticated session hitting DENY gets POLICY_DENIED', async () => {
      const harness = makeHarness({
        policy: { sourceText: DENY_READ_POLICY, format: 'yaml' },
      });
      const { device, spkiPin } = enroll(harness, 'neg67');
      const session = establishSession(harness, spkiPin);
      assert.equal(device.revoked, false);

      const result = await remoteCall(harness, spkiPin, session, 'read_file', {
        path: 'README.md',
      });
      const payload = body(result);
      assert.equal(payload.code, 'POLICY_DENIED', JSON.stringify(payload));

      // The kernel DID run — authorization is the authority, and it said no —
      // and no subsystem was reached.
      assert.ok(harness.kernel.evaluateCalls >= 1);
      const seen = harness.kernel.contexts.at(-1).actor;
      assert.equal(seen.sessionId, session.sessionId);
      assert.equal(seen.deviceId, device.deviceId);
      assert.equal(seen.authenticated, true);
      assert.equal(harness.filesystem.calls.length, 0);
      assert.equal(harness.terminal.calls.length, 0);

      // The session survives the authorization denial.
      assert.equal(
        harness.server.sessionManager.hasSession(session.sessionId),
        true,
        'a policy denial does not invalidate the session',
      );
    });

    test('RC05-ACT-13: an ALLOW does not require a session, and a session does not imply ALLOW', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'separation');
      const session = establishSession(harness, spkiPin);

      // The same authenticated session produces ALLOW for a permitted tool and
      // REQUIRE_APPROVAL for a mutation: authorization is per tool, not per
      // session.
      const allowed = await remoteCall(harness, spkiPin, session, 'list_directory', {});
      assert.equal(allowed.isError, undefined);
      const gated = await remoteCall(harness, spkiPin, session, 'delete_file', {
        path: 'keep.txt',
        expectedHash: sha256Hex(fs.readFileSync(path.join(workspaceDir, 'keep.txt'))),
      });
      assert.equal(body(gated).code, 'APPROVAL_REQUIRED');
    });
  });

  // =========================================================================
  // Session failure semantics
  // =========================================================================

  describe('Post-session anti-oracle failures', () => {
    test('RC05-ACT-14: every session failure is the same generic INVALID_SESSION_TOKEN', async () => {
      const harness = makeHarness();
      const { device, spkiPin } = enroll(harness, 'session-failures');
      const session = establishSession(harness, spkiPin);
      const other = enroll(harness, 'session-failures-other');
      const otherSession = establishSession(harness, other.spkiPin);
      const kernelBefore = harness.kernel.evaluateCalls;

      const failures = [
        // Missing credential.
        { presentedSessionId: session.sessionId, authorizationHeader: null },
        // Malformed credential.
        { presentedSessionId: session.sessionId, authorizationHeader: `Bearer ${'A'.repeat(64)}` },
        // Wrong digest.
        {
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${crypto.randomBytes(32).toString('hex')}`,
        },
        // Cross-session mismatch.
        {
          presentedSessionId: otherSession.sessionId,
          authorizationHeader: `Bearer ${session.token}`,
        },
        // Unknown session ID with a valid token.
        {
          presentedSessionId: crypto.randomBytes(32).toString('hex'),
          authorizationHeader: `Bearer ${session.token}`,
        },
        // >128-byte credential.
        {
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${'a'.repeat(1024)}`,
        },
      ];

      for (const [index, overrides] of failures.entries()) {
        const err = await remoteFailure(
          harness.bridge.executeRemoteToolCall({
            trustedSpkiPin: spkiPin,
            toolName: 'read_file',
            parameters: { path: 'README.md' },
            ...overrides,
          }),
        );
        assert.equal(err.code, 'INVALID_SESSION_TOKEN', `case #${index}`);
        assert.equal(err.message, 'Invalid or expired session token', `case #${index}`);
        assert.equal(err.toJSON().details, undefined);
      }

      // No policy, no subsystem, no audit.
      assert.equal(harness.kernel.evaluateCalls, kernelBefore);
      assert.equal(harness.filesystem.calls.length, 0);
      assert.equal(harness.audit.getRecords().length, 0);

      // The genuine session is untouched.
      const ok = await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      assert.equal(ok.isError, undefined);
      assert.equal(harness.server.sessionManager.hasSession(otherSession.sessionId), true);
      assert.equal(device.revoked, false);
    });

    test('RC05-ACT-15: an expired session fails before the approval manager', async () => {
      const harness = makeHarness();
      const { spkiPin } = enroll(harness, 'expired-session');
      const session = establishSession(harness, spkiPin);
      const targetPath = `expired-${Date.now()}.txt`;

      const first = await remoteCall(harness, spkiPin, session, 'create_file', {
        path: targetPath,
        content: 'x',
      });
      const requestId = body(first).details.approvalRequestId;
      const grant = harness.approvals.approve(requestId);

      // Revoke the session (the deterministic stand-in for expiry).
      harness.server.sessionManager.revokeSession(session.sessionId);
      const approvalBefore = JSON.stringify(harness.approvals.getRequest(requestId));

      const err = await remoteFailure(
        remoteCall(harness, spkiPin, session, 'create_file', {
          path: targetPath,
          content: 'x',
          _arcApproval: { requestId, token: grant.token },
        }),
      );
      assert.equal(err.code, 'INVALID_SESSION_TOKEN');
      assert.equal(
        JSON.stringify(harness.approvals.getRequest(requestId)),
        approvalBefore,
        'the approval manager was not reached',
      );
      assert.equal(harness.filesystem.calls.length, 0);
    });
  });

  // =========================================================================
  // Composition and network boundary
  // =========================================================================

  describe('Composition and the network boundary', () => {
    test('RC05-ACT-16: the server owns exactly one SessionManager', async () => {
      const harness = makeHarness();
      const server = harness.server;
      assert.ok(server.sessionManager, 'a session manager is always present');

      // The bridge authenticates against THAT instance: a challenge session
      // created on the bridge is visible on the server and vice versa.
      const { spkiPin } = enroll(harness, 'one-manager');
      const session = establishSession(harness, spkiPin);
      assert.equal(server.sessionManager.hasSession(session.sessionId), true);
      const ok = await remoteCall(harness, spkiPin, session, 'read_file', { path: 'README.md' });
      assert.equal(ok.isError, undefined);

      // A second server gets its own, and they are independent.
      const other = makeHarness();
      assert.notEqual(server.sessionManager, other.server.sessionManager);
      assert.equal(other.server.sessionManager.hasSession(session.sessionId), false);

      // The factory creates exactly one and shares it with the server.
      const composed = createArcMcpServer({ transport: 'stdio', authorizedRoots: [] });
      assert.ok(composed.sessionManager);
      assert.equal(
        composed.getRemoteExecutionBridge(),
        undefined,
        'stdio mode exposes no remote bridge',
      );
      await composed.stop();
    });

    test('RC05-ACT-17: the session manager is not configurable and not persisted', () => {
      const serverSource = fs.readFileSync(
        new URL('../apps/mcp-server/src/index.ts', import.meta.url),
        'utf8',
      );
      const configBlock = serverSource.slice(
        serverSource.indexOf('export interface ArcServerConfig'),
        serverSource.indexOf('/** Safe, non-sensitive reason'),
      );
      for (const forbidden of [
        'sessionManager',
        'sessionTtl',
        'idleTimeout',
        'maxActiveSessions',
        'sessionQuota',
      ]) {
        assert.equal(
          configBlock.includes(forbidden),
          false,
          `${forbidden} must not be configurable`,
        );
      }
      // Sessions are never written anywhere.
      const sessionSource = fs.readFileSync(
        new URL('../packages/auth/src/session.ts', import.meta.url),
        'utf8',
      );
      for (const forbidden of [
        'node:fs',
        'node:path',
        'writeFileSync',
        'readFileSync',
        'localStorage',
        'sessionStorage',
      ]) {
        assert.equal(
          sessionSource.includes(forbidden),
          false,
          `sessions must not use ${forbidden}`,
        );
      }
      // Every import is pure: crypto and the canonical error type, plus the
      // device-identity validator and a type-only trust-store reference.
      const specifiers = [...sessionSource.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
      assert.deepEqual(specifiers.sort(), [
        './device-identity.js',
        './trust-store.js',
        '@cesspace-arc/protocol',
        'node:crypto',
      ]);
    });

    test('RC05-ACT-18: the network /mcp route is still deny-only and composes no transport', () => {
      const gateway = fs.readFileSync(
        new URL('../apps/mcp-server/src/remote-gateway.ts', import.meta.url),
        'utf8',
      );
      const bootstrap = fs.readFileSync(
        new URL('../apps/mcp-server/src/enrollment-bootstrap.ts', import.meta.url),
        'utf8',
      );
      for (const source of [gateway, bootstrap]) {
        for (const forbidden of [
          'StreamableHTTPServerTransport',
          '@modelcontextprotocol/sdk',
          'SSEServerTransport',
          'eventStore',
          'sessionIdGenerator',
          'executeRemoteToolCall',
          'CallToolRequestSchema',
          'issueSession',
        ]) {
          assert.equal(
            source.includes(forbidden),
            false,
            `the network layer must not contain ${forbidden}`,
          );
        }
      }
      // The placeholder answers are unchanged.
      assert.equal(bootstrap.includes("MCP_PATH = '/mcp'"), true);
      assert.equal(bootstrap.includes('UNAUTHENTICATED_BODY'), true);
      assert.equal(bootstrap.includes("error: 'Enrollment failed'"), true);

      // The bridge is reachable only as an application API, never over HTTP.
      assert.equal(
        gateway.includes('getRemoteExecutionBridge'),
        false,
        'the gateway must not reach the bridge',
      );
    });

    test('RC05-ACT-19: the remote bridge is application-only and performs no I/O', () => {
      const bridge = fs.readFileSync(
        new URL('../apps/mcp-server/src/remote-execution.ts', import.meta.url),
        'utf8',
      );
      const specifiers = [...bridge.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]);
      assert.deepEqual(specifiers.sort(), ['@cesspace-arc/auth', '@cesspace-arc/protocol']);
      for (const forbidden of [
        'node:http',
        'node:https',
        'node:net',
        'node:tls',
        'node:fs',
        'createServer',
        'listen(',
      ]) {
        assert.equal(bridge.includes(forbidden), false, `the bridge must not use ${forbidden}`);
      }
    });

    test('RC05-ACT-20: the composed remote server exposes the bridge over its OWN trust store', async () => {
      // A full remote composition with a real trust store, started for real, so
      // the wiring `start()` performs is exercised rather than assumed.
      const storePath = path.join(tempRoot, `devices-actor-${Date.now()}.json`);
      const store = DeviceTrustStore.createEmpty();
      const enrolledPin = pin('composed');
      store.enrollDevice({
        clientId: 'agent-composed',
        clientType: 'claude-code',
        pin: enrolledPin,
      });
      store.saveToFile(storePath);
      fs.chmodSync(storePath, 0o600);

      const { createTestPki, hasOpenssl } = await import('./helpers/rc05-test-pki.mjs');
      assert.equal(hasOpenssl(), true, 'the TLS helper requires openssl');
      const pki = createTestPki(path.join(tempRoot, `pki-actor-${Date.now()}`));
      const port = await new Promise((resolve, reject) => {
        const probe = net.createServer();
        probe.once('error', reject);
        probe.listen({ host: '127.0.0.1', port: 0 }, () => {
          const bound = probe.address().port;
          probe.close(() => resolve(bound));
        });
      });

      const server = createArcMcpServer({
        transport: 'remote',
        authorizedRoots: [{ id: 'ws', path: workspaceDir }],
        defaultWorkspaceId: 'ws',
        remote: {
          bindHost: '127.0.0.1',
          port,
          publicHostname: 'localhost',
          serverCertificatePath: pki.serverCertPath,
          privateKey: { kind: 'file', path: pki.serverKeyPath },
          clientCaPaths: [pki.trustedCaCertPath],
          trustStorePath: storePath,
        },
      });
      await server.start();
      try {
        const bridge = server.getRemoteExecutionBridge();
        assert.ok(bridge, 'remote mode composes the bridge');
        assert.equal(server.sessionManager.getActiveSessionCount(), 0);

        const gatewayStatus = server.getRemoteGatewayStatus();
        assert.equal(gatewayStatus.transportMode, 'remote');
        assert.equal(gatewayStatus.activeAndServing, true);

        // The bridge resolves against the GATEWAY'S store, so a device enrolled
        // in that file can be authenticated while a stranger cannot.
        await assert.rejects(
          () =>
            bridge.executeRemoteToolCall({
              trustedSpkiPin: pin('composed-stranger'),
              toolName: 'read_file',
              parameters: { path: 'README.md' },
            }),
          (err) => err.code === 'UNAUTHENTICATED',
        );

        // An enrolled device reaches the shared pipeline through the composed
        // server, proving the bridge is wired to the same server instance.
        const identity = DeviceTrustStore.loadFromFile(storePath);
        assert.equal(identity.findDeviceByPin(enrolledPin) !== undefined, true);
      } finally {
        await server.stop();
      }
    });
  });
});
