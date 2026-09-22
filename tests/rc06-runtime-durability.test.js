/**
 * CesSpace ARC — RC-06 Task 6: Universal Lifecycle & Full-History Startup Engine
 *
 * The production-composition regression suite. Tasks 1-5 built the primitives —
 * persistent append storage, torn-tail recovery, rotation, signed checkpoints
 * and external anchoring. This file proves that the ONE authoritative production
 * startup/runtime path composes them without weakening any boundary they own.
 *
 * Every test in here drives the REAL composition:
 *
 *   `ArcMcpServer.start()` -> `openAuditRuntime()` -> the frozen twelve-step
 *   sequence -> one writer lock, one verified store, one persistent primary
 *   chain -> the shared stdio/remote execution pipeline.
 *
 * Faults are injected only through the audit package's own internal capability
 * seams (`packages/audit/dist/internal/runtime-testing.js`), which are reachable
 * by direct relative path and are not in the package's `exports` map. No seam
 * here can fabricate a record, skip verification, advance a cursor or weaken a
 * boundary: `failAppendPhase` can only make a write fail, `failStartupStage` can
 * only make a stage fail closed, and `onStartupStage` only observes.
 *
 * Determinism: no network, no real anchor retry backoff (the frozen 31-second
 * vector is replaced by an instant `sleep`), no wall-clock dependence.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { RemoteExecutionBridge } from '../apps/mcp-server/dist/remote-execution.js';
// The gateway sink is reached through its own module rather than the package
// root: it is memoized per audit chain, so this is the SAME instance the server
// composed, and the test drives the production emitter rather than a copy.
import { getGatewayAuditSink } from '../apps/mcp-server/dist/gateway-audit.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { DeviceTrustStore, resolveActiveDeviceIdentity } from '../packages/auth/dist/index.js';
import { AuditLogger } from '../packages/audit/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { ProcessRegistry } from '../packages/processes/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';

import {
  ACTIVE_SEGMENT_FILENAME,
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_IDEMPOTENCY_HEADER,
  CHECKPOINT_FILENAME,
  CHECKPOINT_INTERVAL,
  LOCK_FILENAME,
  MAX_ARCHIVE_SEGMENTS,
  MAX_PENDING_ANCHOR_CHECKPOINTS,
  MAX_TORN_TAIL_BYTES,
  AUDIT_STARTUP_STAGE_ORDER,
  TOTAL_AUDIT_BUDGET_BYTES,
  openAuditRuntime,
  parseAndValidateCheckpointLineV1,
  parseAndValidateRecordLineV1,
  parseRotatedSegmentFilename,
  scanAuditStorePhysicalBytes,
  serializeAnchorReceiptV1,
  verifyCheckpointSignature,
  verifyRetainedPrimaryHistory,
  getProcessUid,
} from '../packages/audit/dist/index.js';

import { createTestAuditRuntime } from '../packages/audit/dist/internal/runtime-testing.js';
import { signTestAnchorReceipt } from '../packages/audit/dist/internal/anchor-testing.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENDPOINT = 'https://anchor.example.invalid/v1/anchor';
const EXPECTED_UID = getProcessUid();

/* -------------------------------------------------------------------------- *
 * Fixtures
 * -------------------------------------------------------------------------- */

let tempRoot;
let workspaceDir;
/** Every server this file started, torn down in reverse order. */
const startedServers = [];
/** Every runtime this file opened directly, closed after the suite. */
const openRuntimes = [];
let fixtureCounter = 0;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc06-task6-'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), 'line1\nline2\nline3\n');
  fs.writeFileSync(path.join(workspaceDir, 'keep.txt'), 'keep\n');
});

after(async () => {
  for (const server of startedServers.reverse()) {
    try {
      await server.stop();
    } catch {
      // ignore
    }
  }
  for (const runtime of openRuntimes) {
    try {
      await runtime.close();
    } catch {
      // ignore
    }
  }
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

/** A fresh, private directory below the suite's temp root. */
function newRoot(label) {
  fixtureCounter += 1;
  const dir = path.join(tempRoot, `${label}-${fixtureCounter}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  return dir;
}

/** Generates an Ed25519 keypair as 0600 PKCS#8 / SPKI PEM files. */
function writeKeyPair(dir, name) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const signingKeyPath = path.join(dir, `${name}-signing.pem`);
  const publicKeyPath = path.join(dir, `${name}-public.pem`);
  fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    mode: 0o600,
  });
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
    mode: 0o600,
  });
  fs.chmodSync(signingKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o600);
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKey,
    publicPem: fs.readFileSync(publicKeyPath, 'utf8'),
    signingKeyPath,
    publicKeyPath,
    fingerprint: crypto.createHash('sha256').update(spkiDer).digest('hex'),
  };
}

/**
 * The frozen production `AuditConfig` for a fresh fixture.
 *
 * `anchor` adds the Tier-3 half — an endpoint and a receipt verification key —
 * which is the ONLY way `anchorMode` becomes ENABLED. There is no `enabled`
 * flag, no key material, and nothing here is reachable from an environment
 * variable, a command-line argument, an MCP parameter or a request body.
 */
function makeAuditConfig(label, { anchor = false } = {}) {
  const root = newRoot(label);
  const keyDir = path.join(root, 'keys');
  const checkpoint = writeKeyPair(keyDir, 'checkpoint');
  const anchorMaterial = anchor ? writeKeyPair(keyDir, 'anchor') : null;
  const config = {
    directory: path.join(root, 'store'),
    signingKeyPath: checkpoint.signingKeyPath,
    publicKeyPath: checkpoint.publicKeyPath,
  };
  if (anchorMaterial !== null) {
    config.anchorEndpoint = ENDPOINT;
    config.anchorReceiptPublicKeyPath = anchorMaterial.publicKeyPath;
  }
  return { root, config, checkpoint, anchorMaterial, auditDir: config.directory, keyDir };
}

/** A valid persistent record candidate, minus the persistence-owned fields. */
function sampleRecordCandidate(overrides = {}) {
  return {
    eventId: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    timestamp: '2026-09-21T00:00:00.000Z',
    actor: {
      clientId: 'test-client',
      clientType: 'admin',
      deviceId: 'a'.repeat(32),
      sessionId: 'b'.repeat(64),
    },
    target: {
      workspaceId: 'ws-test',
      workspacePath: '',
      workspaceRootHash: 'c'.repeat(64),
    },
    invocation: {
      toolName: 'read_file',
      parametersRedacted: { path: 'test.txt' },
      payloadHash: 'd'.repeat(64),
    },
    policy: { decision: 'ALLOW', ruleId: 'rule-test-01', evaluationDurationMs: 1.5 },
    execution: {
      status: 'SUCCESS',
      startTime: '2026-09-21T00:00:00.000Z',
      endTime: '2026-09-21T00:00:00.010Z',
      durationMs: 10,
    },
    ...overrides,
  };
}

/** The active-segment path of an audit directory. */
function activeSegmentPath(auditDir) {
  return path.join(auditDir, ACTIVE_SEGMENT_FILENAME);
}

/**
 * Reads the active segment exactly as it is on disk.
 *
 * `parseAndValidateRecordLineV1` requires each line to END with `\n`, so the raw
 * bytes are split on the terminator and the terminator is re-appended. The file
 * is never trimmed: an unterminated trailing line is exactly the torn-tail
 * condition the suite needs to observe.
 */
function readActiveRecordLines(auditDir) {
  const file = activeSegmentPath(auditDir);
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, 'utf8');
  if (raw.length === 0) return [];
  return raw
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => `${line}\n`);
}

/** Every valid record in the active segment, in chain order. */
function readActiveRecords(auditDir) {
  return readActiveRecordLines(auditDir).map((line) => parseAndValidateRecordLineV1(line).record);
}

/** Raw byte size and complete-line count, tolerant of a torn trailing line. */
function rawActiveStats(auditDir) {
  const file = activeSegmentPath(auditDir);
  if (!fs.existsSync(file)) return { bytes: 0, completeLines: 0 };
  const raw = fs.readFileSync(file, 'utf8');
  return {
    bytes: Buffer.byteLength(raw, 'utf8'),
    completeLines: (raw.match(/\n/g) ?? []).length,
  };
}

/** Every checkpoint artifact line, terminator preserved. */
function readCheckpointRecords(auditDir) {
  const file = path.join(auditDir, CHECKPOINT_FILENAME);
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, 'utf8');
  if (raw.length === 0) return [];
  assert.ok(raw.endsWith('\n'), 'a checkpoint artifact must be LF-terminated');
  return raw
    .slice(0, -1)
    .split('\n')
    .map((line) => parseAndValidateCheckpointLineV1(`${line}\n`).checkpoint);
}

/** Canonical rotated-segment filenames currently present, in directory order. */
function rotatedSegmentNames(auditDir) {
  if (!fs.existsSync(auditDir)) return [];
  return fs
    .readdirSync(auditDir)
    .filter((name) => parseRotatedSegmentFilename(name) !== null)
    .sort();
}

/** The store identifier recorded in the store metadata. */
function readStoreId(auditDir) {
  return JSON.parse(fs.readFileSync(path.join(auditDir, 'audit-store.json'), 'utf8')).storeId;
}

/**
 * Seeds a REAL production-shaped store by running the real startup sequence and
 * appending through the real runtime, then closing it.
 *
 * This is the only way the suite builds a store: metadata, key fingerprints,
 * trust roots, the lock, the active segment and the hash chain are all produced
 * by the same code production runs.
 */
async function seedStore(fixture, options = {}) {
  const {
    records = 0,
    perRecord = null,
    rotateAt = [],
    anchorHooks,
    hooks,
    checkpointHooks,
  } = options;
  const runtime = await createTestAuditRuntime(fixture.config, {
    ...(hooks === undefined ? {} : { hooks }),
    ...(checkpointHooks === undefined ? {} : { checkpointHooks }),
    anchorHooks: anchorHooks ?? { sleep: async () => {} },
  });
  openRuntimes.push(runtime);

  const appended = [];
  for (let index = 1; index <= records; index += 1) {
    const candidate = perRecord === null ? sampleRecordCandidate() : perRecord(index);
    const record = await runtime.appendRecord(candidate);
    appended.push(record);
    if (rotateAt.includes(index)) {
      await runtime.store.rotateNow('SIZE_THRESHOLD');
    }
  }
  return { runtime, appended };
}

/** Closes a runtime and removes it from the suite-wide cleanup list. */
async function closeRuntime(runtime) {
  const at = openRuntimes.indexOf(runtime);
  if (at >= 0) openRuntimes.splice(at, 1);
  await runtime.close();
}

/**
 * A Tier-3 transport that refuses every submission, so nothing is ever
 * acknowledged and every genuine checkpoint stays spooled.
 */
const FAILING_ANCHOR_HOOKS = Object.freeze({
  transport: async () => ({ statusCode: 500, body: Buffer.from('no', 'utf8') }),
  sleep: async () => {},
});

/**
 * Seeds a store holding exactly ONE genuine, unacknowledged checkpoint.
 *
 * The store is built by the real runtime: append, force a size-triggered
 * rotation (which seals a real signed checkpoint and hands it to Tier 3, where
 * the failing transport spools it), then append again. The result on disk is the
 * precondition both anchor reconciliation states share — a checkpoint artifact,
 * a durable spool entry, and no receipt.
 */
async function seedUnacknowledgedCheckpoint(fixture) {
  const runtime = await createTestAuditRuntime(fixture.config, {
    anchorHooks: FAILING_ANCHOR_HOOKS,
  });
  await runtime.appendRecord(sampleRecordCandidate());
  await runtime.store.rotateNow('SIZE_THRESHOLD');
  await runtime.appendRecord(sampleRecordCandidate());
  await closeRuntime(runtime);

  const checkpoints = readCheckpointRecords(fixture.auditDir);
  assert.equal(checkpoints.length, 1, 'the fixture must hold exactly one genuine checkpoint');
  assert.equal(
    fs.existsSync(
      path.join(fixture.auditDir, ANCHOR_SPOOL_DIRNAME, `${checkpoints[0].checkpointHash}.json`),
    ),
    true,
    'the unacknowledged checkpoint must have spooled durably',
  );
  return checkpoints[0];
}

/**
 * Every artifact class startup is allowed to mutate, read from disk.
 *
 * This is the observation the authority-boundary regressions compare: stage
 * NAMES prove nothing about authority, while these six values change exactly
 * when — and only when — the stage that owns each artifact has run.
 */
function artifactSnapshot(auditDir) {
  const spoolDir = path.join(auditDir, ANCHOR_SPOOL_DIRNAME);
  const checkpointFile = path.join(auditDir, CHECKPOINT_FILENAME);
  const receiptFile = path.join(auditDir, ANCHOR_RECEIPT_FILENAME);
  const active = rawActiveStats(auditDir);
  return {
    activeBytes: active.bytes,
    activeLines: active.completeLines,
    checkpointBytes: fs.existsSync(checkpointFile)
      ? fs.readFileSync(checkpointFile).toString('base64')
      : null,
    receiptBytes: fs.existsSync(receiptFile)
      ? fs.readFileSync(receiptFile).toString('base64')
      : null,
    receiptLines: receiptLineCount(auditDir),
    spoolDirExists: fs.existsSync(spoolDir),
    spoolEntries: fs.existsSync(spoolDir) ? fs.readdirSync(spoolDir).sort() : [],
  };
}

/** Complete receipt lines currently durable in the ledger (0 when absent). */
function receiptLineCount(auditDir) {
  const file = path.join(auditDir, ANCHOR_RECEIPT_FILENAME);
  if (!fs.existsSync(file)) return 0;
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.length > 0).length;
}

/** The spool directory of an audit directory. */
function spoolDirOf(auditDir) {
  return path.join(auditDir, ANCHOR_SPOOL_DIRNAME);
}

/**
 * Waits until the process registry has recorded the child's terminal transition.
 *
 * A spawn that never happened still produces a truthful control plane: the
 * registry reports `PROCESS_SPAWN_FAILED` from the child's `error` event (which
 * is what the tool response is produced from), and the child's `close` event
 * lands on a later tick and drives the terminal `PROCESS_EXITED` transition.
 * Reading the chain between the two would race that emission, so the fixture
 * waits for the transition the registry itself records before it reads anything.
 */
async function awaitProcessTerminalTransition(processRegistry, processId) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const record = processRegistry.getProcess(processId);
    // `exitCode` is written by the terminal transition and by nothing else.
    if (record !== undefined && record.exitCode !== undefined) {
      return;
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 5);
    });
  }
  throw new Error(`process ${processId} never reached a terminal transition`);
}

/**
 * Proves a record list is ONE contiguous chain: a gapless sequence starting at
 * 1 that re-verifies from genesis under the frozen verifier.
 *
 * A second ledger, or a category of evidence written to a private chain with its
 * own numbering, cannot satisfy this — and neither can a chain whose records
 * only look well-formed.
 */
async function assertOneSequence(fixture, records) {
  assert.deepEqual(
    records.map((record) => record.sequenceNumber),
    records.map((_, index) => index + 1),
    'the primary sequence must be gapless from 1',
  );
  const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, EXPECTED_UID);
  assert.equal(verification.status, 'VERIFIED');
  assert.equal(verification.recordCount, records.length, 'every record must be on the one chain');
  assert.equal(verification.terminalSequence, records.length);
  assert.equal(verification.nextSequence, records.length + 1);
}

/** The bounded audit-persistence refusal the caller must be answered with. */
const AUDIT_PERSISTENCE_FAILURE_MESSAGE =
  'The refusal could not be recorded durably: durable audit evidence could not be secured. Privileged operations are halted until restart.';

/** The bounded refusal a latched process answers every privileged request with. */
const AUDIT_GATE_REFUSAL_MESSAGE =
  'Privileged operations are halted: durable audit evidence could not be secured.';

/** Counts real filesystem subsystem invocations, split into reads and mutations. */
class FilesystemSpy extends FilesystemSubsystem {
  constructor() {
    super();
    this.reads = 0;
    this.mutations = 0;
    this.calls = [];
    this.onCall = null;
  }

  #observe(method, request, kind) {
    this.calls.push({ method, request, kind });
    this.onCall?.({ method, request, kind, reads: this.reads, mutations: this.mutations });
  }

  async listDirectory(root, request) {
    this.reads += 1;
    this.#observe('listDirectory', request, 'read');
    return super.listDirectory(root, request);
  }

  async readFile(root, request) {
    this.reads += 1;
    this.#observe('readFile', request, 'read');
    return super.readFile(root, request);
  }

  async searchFiles(root, request) {
    this.reads += 1;
    this.#observe('searchFiles', request, 'read');
    return super.searchFiles(root, request);
  }

  async searchText(root, request) {
    this.reads += 1;
    this.#observe('searchText', request, 'read');
    return super.searchText(root, request);
  }

  async createFile(root, request) {
    this.mutations += 1;
    this.#observe('createFile', request, 'mutation');
    return super.createFile(root, request);
  }

  async writeFile(root, request) {
    this.mutations += 1;
    this.#observe('writeFile', request, 'mutation');
    return super.writeFile(root, request);
  }

  async deleteFile(root, request) {
    this.mutations += 1;
    this.#observe('deleteFile', request, 'mutation');
    return super.deleteFile(root, request);
  }

  async moveFile(root, request) {
    this.mutations += 1;
    this.#observe('moveFile', request, 'mutation');
    return super.moveFile(root, request);
  }

  async applyPatch(root, request) {
    this.mutations += 1;
    this.#observe('applyPatch', request, 'mutation');
    return super.applyPatch(root, request);
  }
}

/** Counts real Git subsystem invocations. */
class GitSpy extends GitSubsystem {
  constructor() {
    super();
    this.reads = 0;
    this.calls = [];
  }
  async getStatus(root, request) {
    this.reads += 1;
    this.calls.push({ method: 'getStatus', request });
    return super.getStatus(root, request);
  }
}

/**
 * The production server with a controlled audit-runtime composition.
 *
 * The ONLY override is `openAuditRuntimeForProcess`, the documented `@internal`
 * protected seam. Production is exactly `super.openAuditRuntimeForProcess`, and
 * an override still has to return a runtime produced by the audit package's own
 * capability-gated entry point — there is no path that skips the frozen
 * startup sequence.
 */
class DurabilityServer extends ArcMcpServer {
  constructor(parts, runtimeOptions, terminalSubsystem, processRegistry) {
    super(
      parts.registry,
      parts.kernel,
      parts.audit,
      parts.filesystem,
      parts.git,
      parts.config,
      terminalSubsystem,
      processRegistry,
      parts.approvals,
    );
    this.runtimeOptions = runtimeOptions;
  }

  async openAuditRuntimeForProcess(config) {
    if (this.runtimeOptions === undefined) {
      return super.openAuditRuntimeForProcess(config);
    }
    return createTestAuditRuntime(config, this.runtimeOptions);
  }
}

/**
 * Builds a server over a real workspace with a real store.
 *
 * `processRegistry` composes the real process-lifecycle path — the same
 * registry/runner pair the production entry point composes — so a regression can
 * prove that a genuine process lifecycle record reaches the persistent primary
 * chain. Every other caller keeps the process-free composition.
 */
function buildServer(fixture, options = {}) {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', workspaceDir);

  const processRegistry = options.processRegistry;
  const kernel = new SecurityKernel(registry, processRegistry);
  const audit = new AuditLogger();
  const filesystem = options.filesystem ?? new FilesystemSpy();
  const git = options.git ?? new GitSpy();
  const approvals = options.approvals ?? new ApprovalStateManager();

  const config = {
    transport: 'stdio',
    authorizedRoots: [],
    defaultWorkspaceId: 'ws',
    audit: fixture.config,
    ...(options.policy === undefined ? {} : { policy: options.policy }),
  };

  const server = new DurabilityServer(
    { registry, kernel, audit, filesystem, git, approvals, config },
    options.runtimeOptions,
    options.terminalSubsystem,
    processRegistry,
  );
  return {
    server,
    registry,
    kernel,
    audit,
    filesystem,
    git,
    approvals,
    config,
    processRegistry,
  };
}

/** Starts a server and registers it for teardown. */
async function startServer(parts) {
  await parts.server.start();
  startedServers.push(parts.server);
  return parts;
}

/** The parsed MCP response body. */
function body(result) {
  return JSON.parse(result.content[0].text);
}

/** Reads the bounded `audit` block from the `health` tool. */
async function auditHealth(parts) {
  const health = body(await parts.server.dispatchToolCall('health', {}));
  assert.ok(health.audit, 'a started server must report a bounded audit block');
  return health.audit;
}

/** Runs a request, approves it out of band, and redeems the token. */
async function requestApproveRedeem(parts, toolName, params) {
  const first = await parts.server.dispatchToolCall(toolName, { ...params });
  const firstBody = body(first);
  assert.equal(
    firstBody.code,
    'APPROVAL_REQUIRED',
    `expected APPROVAL_REQUIRED, got ${firstBody.code}`,
  );
  const requestId = firstBody.details.approvalRequestId;
  const grant = parts.approvals.approve(requestId);
  const second = await parts.server.dispatchToolCall(toolName, {
    ...params,
    _arcApproval: { requestId, token: grant.token },
  });
  return { requestId, first, firstBody, second, secondBody: body(second) };
}

/** A directory-tree digest, for byte-for-byte target-state comparisons. */
function treeDigest(dir) {
  const hash = crypto.createHash('sha256');
  const walk = (current, prefix) => {
    for (const entry of fs
      .readdirSync(current, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const rel = `${prefix}${entry.name}`;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        hash.update(`D:${rel}\n`);
        walk(full, `${rel}/`);
      } else {
        const contents = fs.readFileSync(full);
        hash.update(`F:${rel}:${contents.length}\n`);
        hash.update(contents);
      }
    }
  };
  walk(dir, '');
  return hash.digest('hex');
}

/** Open file descriptors this process holds into a directory. */
function openDescriptorCount(dir) {
  if (!fs.existsSync('/proc/self/fd')) return null;
  let count = 0;
  for (const fd of fs.readdirSync('/proc/self/fd')) {
    try {
      const target = fs.readlinkSync(path.join('/proc/self/fd', fd));
      if (target === dir || target.startsWith(`${dir}${path.sep}`)) count += 1;
    } catch {
      // A descriptor closed between readdir and readlink; not a leak.
    }
  }
  return count;
}

/** Canonical SPKI pin for a remote fixture device. */
function pinFor(seed) {
  return crypto.createHash('sha256').update(`rc06-t6-pin-${seed}`, 'utf8').digest('hex');
}

/* -------------------------------------------------------------------------- *
 * Suite
 * -------------------------------------------------------------------------- */

describe('CesSpace ARC — RC-06 Task 6: Universal Lifecycle & Full-History Startup', () => {
  /* ======================================================================== *
   * 1. Production startup order
   * ======================================================================== */

  describe('Production startup order', () => {
    test('RC06-T6-REG-01: the full-history startup sequence runs in the exact frozen order, mutating the store only at stage 8 and appending recovery only at stage 10', async () => {
      const fixture = makeAuditConfig('reg01');
      const danglingOperationId = crypto.randomUUID();

      // A realistic damaged store: five ordinary records, a sixth record that
      // STARTED and never reached a terminal phase, and a permitted torn active
      // tail below `MAX_TORN_TAIL_BYTES`.
      const { runtime } = await seedStore(fixture, {
        records: 6,
        perRecord: (index) =>
          index === 6
            ? sampleRecordCandidate({
                lifecycle: { operationId: danglingOperationId, phase: 'STARTED' },
                invocation: {
                  toolName: 'create_file',
                  parametersRedacted: { path: 'dangling.txt' },
                  payloadHash: 'e'.repeat(64),
                },
              })
            : sampleRecordCandidate(),
      });
      await closeRuntime(runtime);

      const tornBytes = Buffer.from('{"eventId":"torn-tail-fragment",', 'utf8');
      assert.ok(tornBytes.length < MAX_TORN_TAIL_BYTES);
      fs.appendFileSync(activeSegmentPath(fixture.auditDir), tornBytes);
      const torn = rawActiveStats(fixture.auditDir);
      assert.equal(torn.completeLines, 6);
      assert.ok(torn.bytes > 6 * 100, 'the fixture must hold six real record lines');

      const observations = [];
      const observedRuntime = await createTestAuditRuntime(fixture.config, {
        hooks: {
          onStartupStage: (stage) => {
            const stats = rawActiveStats(fixture.auditDir);
            observations.push({ stage, bytes: stats.bytes, completeLines: stats.completeLines });
          },
        },
      });
      openRuntimes.push(observedRuntime);

      // (a) The stage sequence is exactly the frozen one.
      assert.deepEqual(
        observations.map((entry) => entry.stage),
        [...AUDIT_STARTUP_STAGE_ORDER],
      );
      assert.deepEqual(
        [...AUDIT_STARTUP_STAGE_ORDER],
        [
          'PLATFORM_SECURITY_PRIMITIVES',
          'SINGLE_WRITER_LOCK',
          'STORE_METADATA_AND_TRUST_ROOTS',
          'PRIMARY_HISTORY_VERIFICATION',
          'CHECKPOINT_CHAIN_VERIFICATION',
          'ANCHOR_RECEIPT_VERIFICATION',
          'ANCHOR_SPOOL_RECONCILIATION',
          'TORN_TAIL_RECOVERY',
          'DANGLING_OPERATION_DETECTION',
          'RECOVERY_APPEND_DURABILITY',
          'RUNTIME_CURSORS',
        ],
      );

      const at = (stage) => observations.find((entry) => entry.stage === stage);
      const indexOf = (stage) => observations.findIndex((entry) => entry.stage === stage);

      // (b) No authority boundary is crossed early: the anchor spool is
      //     reconciled after the receipt ledger, which is verified after the
      //     checkpoint chain, which is verified after the primary history.
      assert.ok(indexOf('PRIMARY_HISTORY_VERIFICATION') < indexOf('CHECKPOINT_CHAIN_VERIFICATION'));
      assert.ok(indexOf('CHECKPOINT_CHAIN_VERIFICATION') < indexOf('ANCHOR_RECEIPT_VERIFICATION'));
      assert.ok(indexOf('ANCHOR_RECEIPT_VERIFICATION') < indexOf('ANCHOR_SPOOL_RECONCILIATION'));
      assert.ok(indexOf('ANCHOR_SPOOL_RECONCILIATION') < indexOf('TORN_TAIL_RECOVERY'));
      assert.ok(indexOf('TORN_TAIL_RECOVERY') < indexOf('DANGLING_OPERATION_DETECTION'));
      assert.ok(indexOf('DANGLING_OPERATION_DETECTION') < indexOf('RECOVERY_APPEND_DURABILITY'));
      assert.ok(indexOf('RECOVERY_APPEND_DURABILITY') < indexOf('RUNTIME_CURSORS'));

      // (c) NO torn-tail mutation happens before stage 8. Every stage up to and
      //     including the entry of `TORN_TAIL_RECOVERY` sees the exact bytes the
      //     damaged store had.
      for (const stage of [
        'PLATFORM_SECURITY_PRIMITIVES',
        'SINGLE_WRITER_LOCK',
        'STORE_METADATA_AND_TRUST_ROOTS',
        'PRIMARY_HISTORY_VERIFICATION',
        'CHECKPOINT_CHAIN_VERIFICATION',
        'ANCHOR_RECEIPT_VERIFICATION',
        'ANCHOR_SPOOL_RECONCILIATION',
        'TORN_TAIL_RECOVERY',
      ]) {
        assert.equal(at(stage).bytes, torn.bytes, `${stage} must not mutate the active segment`);
      }

      // (d) The tail IS isolated and truncated by the time stage 9 begins.
      assert.ok(
        at('DANGLING_OPERATION_DETECTION').bytes < torn.bytes,
        'stage 8 must have truncated the torn tail',
      );
      assert.equal(at('DANGLING_OPERATION_DETECTION').completeLines, 6);

      // (e) The recovery append happens at stage 10 — after dangling detection
      //     at stage 9 — and is durable before the cursor stage.
      assert.equal(at('DANGLING_OPERATION_DETECTION').completeLines, 6);
      assert.equal(at('RECOVERY_APPEND_DURABILITY').completeLines, 6);
      assert.equal(at('RUNTIME_CURSORS').completeLines, 7);

      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.length, 7);
      const recovery = records[6];
      assert.equal(recovery.lifecycle.phase, 'RECOVERY_INDETERMINATE');
      assert.equal(recovery.lifecycle.operationId, danglingOperationId);
      assert.equal(recovery.sequenceNumber, 7);
      assert.equal(recovery.actor.clientType, 'SYSTEM');
      assert.equal(recovery.invocation.toolName, 'create_file');
      assert.equal(observedRuntime.getIndeterminateRecoveryCount(), 1);
    });

    test('RC06-T6-REG-04: a permitted torn active tail is classified as recoverable and mutates nothing before stage 8', async () => {
      const fixture = makeAuditConfig('reg04');
      const { runtime } = await seedStore(fixture, { records: 3 });
      await closeRuntime(runtime);

      const good = rawActiveStats(fixture.auditDir);
      fs.appendFileSync(activeSegmentPath(fixture.auditDir), '{"sequenceNumber":4,"integ');

      // A naive `recoverPersistentAuditStorage() -> verify` composition sees the
      // same classification; what it cannot do is prove that nothing was mutated
      // before the classification was reached.
      const observed = [];
      const observedRuntime = await createTestAuditRuntime(fixture.config, {
        hooks: {
          onStartupStage: (stage) =>
            observed.push({ stage, bytes: rawActiveStats(fixture.auditDir).bytes }),
        },
      });
      openRuntimes.push(observedRuntime);

      const beforeRepair = observed.filter(
        (entry) =>
          AUDIT_STARTUP_STAGE_ORDER.indexOf(entry.stage) <=
          AUDIT_STARTUP_STAGE_ORDER.indexOf('TORN_TAIL_RECOVERY'),
      );
      assert.equal(beforeRepair.length, 8);
      for (const entry of beforeRepair) {
        assert.equal(entry.bytes > good.bytes, true, `${entry.stage} must see the torn bytes`);
      }

      // The isolated tail is preserved in the frozen sidecar, not discarded.
      const sidecar = fs
        .readdirSync(fixture.auditDir)
        .find((name) => name.startsWith(`${ACTIVE_SEGMENT_FILENAME}.torn.`));
      assert.ok(sidecar, 'the torn tail must be isolated to the frozen sidecar');
      assert.equal(
        fs.readFileSync(path.join(fixture.auditDir, sidecar), 'utf8'),
        '{"sequenceNumber":4,"integ',
      );
      assert.equal(rawActiveStats(fixture.auditDir).bytes, good.bytes);
      assert.equal(observedRuntime.getIndeterminateRecoveryCount(), 0);
    });

    test('RC06-T6-REG-05: primary history is re-verified from the beginning after the tail is repaired', async () => {
      const fixture = makeAuditConfig('reg05');
      const { runtime, appended } = await seedStore(fixture, { records: 4 });
      await closeRuntime(runtime);
      fs.appendFileSync(activeSegmentPath(fixture.auditDir), 'not-json-at-all');

      const reopened = await createTestAuditRuntime(fixture.config);
      openRuntimes.push(reopened);

      const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, EXPECTED_UID);
      assert.equal(verification.status, 'VERIFIED');
      assert.equal(verification.terminalSequence, 4);
      assert.equal(verification.terminalRecordHash, appended[3].integrity.recordHash);
      assert.equal(verification.nextSequence, 5);
      assert.equal(verification.previousRecordHash, appended[3].integrity.recordHash);
      assert.equal(reopened.getNextSequence(), 5);
      assert.equal(reopened.getLastRecordHash(), appended[3].integrity.recordHash);

      // Reading the repaired segment back through the frozen parser yields
      // exactly the four records that were durable before the tear.
      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.length, 4);
      assert.deepEqual(
        records.map((record) => record.integrity.recordHash),
        appended.map((record) => record.integrity.recordHash),
      );
    });

    test('RC06-T6-REG-06: dangling recovery evidence is durable before service begins', async () => {
      const fixture = makeAuditConfig('reg06');
      const operationId = crypto.randomUUID();
      const { runtime } = await seedStore(fixture, {
        records: 2,
        perRecord: (index) =>
          index === 2
            ? sampleRecordCandidate({
                lifecycle: { operationId, phase: 'STARTED' },
                invocation: {
                  toolName: 'create_file',
                  parametersRedacted: { path: 'dangling.txt' },
                  payloadHash: 'e'.repeat(64),
                },
              })
            : sampleRecordCandidate(),
      });
      await closeRuntime(runtime);

      const parts = buildServer(fixture);
      await startServer(parts);

      // The recovery record is durable on disk BEFORE any privileged call is
      // served: it is read straight from the segment, not inferred from health.
      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.length, 3);
      const recovery = records[2];
      assert.equal(recovery.lifecycle.operationId, operationId);
      assert.equal(recovery.lifecycle.phase, 'RECOVERY_INDETERMINATE');
      assert.equal(recovery.invocation.toolName, 'create_file');
      assert.equal(recovery.actor.clientType, 'SYSTEM');
      assert.equal((await auditHealth(parts)).indeterminateRecoveries, 1);
    });

    test('RC06-T6-REG-07: the runtime cursor resumes at the exact next sequence and the exact last verified record hash', async () => {
      const fixture = makeAuditConfig('reg07');
      const { runtime } = await seedStore(fixture, { records: 3 });
      await closeRuntime(runtime);

      const seeded = readActiveRecords(fixture.auditDir);
      assert.equal(seeded.length, 3);
      const terminal = seeded[seeded.length - 1];
      assert.equal(terminal.sequenceNumber, 3);

      const parts = buildServer(fixture);
      await startServer(parts);

      // The cursor is the sequence the NEXT durable record will carry, so it
      // must be exactly one past the verified terminal record — not a
      // file-size guess, not a reset to 1, and not a synthetic genesis record.
      assert.equal((await auditHealth(parts)).sequence, terminal.sequenceNumber + 1);

      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });

      // The resumed record is located by its ABSOLUTE sequence, never by an
      // offset into whatever the active segment happens to hold right now.
      //
      // A restart does not make a segment young: the store restores an existing
      // active segment's origin from its FIRST record's timestamp, so once this
      // fixture is older than the frozen 24-hour rotation interval the very
      // first append after restart legitimately seals the seeded records into a
      // rotated archive BEFORE sequence 4 is written. Both outcomes are correct
      // production behavior — the chain and the cursor are identical either
      // way, and only the segment the seeded records live in differs — so this
      // assertion must hold under either one.
      const resumedSequence = terminal.sequenceNumber + 1;
      const active = readActiveRecords(fixture.auditDir);
      const resumed = active.find((record) => record.sequenceNumber === resumedSequence);
      assert.ok(
        resumed,
        `the active segment must carry sequence ${resumedSequence} after the restart`,
      );
      assert.equal(
        resumed.sequenceNumber,
        resumedSequence,
        'the resumed chain must continue at the next sequence',
      );
      assert.equal(
        resumed.integrity.previousRecordHash,
        terminal.integrity.recordHash,
        'the resumed chain must be bound to the last VERIFIED record hash',
      );

      // Full-history verification is the authority for "one chain, from
      // genesis, nothing reused" — it spans the rotated archives and the active
      // segment alike, whichever side of the rotation boundary they fall on.
      const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, EXPECTED_UID);
      assert.equal(verification.status, 'VERIFIED');

      // The records this call appended, read from the verified whole-history
      // view rather than from any single segment.
      const appended = verification.recentRecords.filter(
        (record) => record.sequenceNumber >= resumedSequence,
      );
      assert.ok(appended.length > 0, 'the tool call must have appended durable records');
      assert.equal(
        appended[0].sequenceNumber,
        resumedSequence,
        'the first appended record must be the resumed STARTED record',
      );
      assert.deepEqual(
        appended.map((record) => record.sequenceNumber),
        appended.map((_, index) => resumedSequence + index),
        'the appended records must be contiguous, with no sequence reused or skipped',
      );
      assert.equal(
        appended[0].integrity.previousRecordHash,
        terminal.integrity.recordHash,
        'the verified chain binds the resumed record to the pre-restart terminal hash',
      );
      assert.equal(
        verification.recordCount,
        seeded.length + appended.length,
        'the retained history is exactly the seeded records plus the appended ones',
      );
      assert.equal(
        verification.recentRecords.length,
        verification.recordCount,
        'the whole retained chain must fit the verification cache for the checks below',
      );
      assert.equal(
        verification.recentRecords.filter((record) => record.sequenceNumber === 1).length,
        1,
        'no sequence may be reused and no second genesis record may appear',
      );
      assert.equal(
        verification.terminalSequence,
        appended[appended.length - 1].sequenceNumber,
        'the retained chain terminates at the last record the tool call appended',
      );
      assert.equal(
        verification.nextSequence,
        verification.terminalSequence + 1,
        'the next append must continue one past the terminal record',
      );
      assert.equal(verification.previousRecordHash, verification.terminalRecordHash);
    });
  });

  /* ======================================================================== *
   * 2. No privileged service before step 12
   * ======================================================================== */

  describe('No privileged service before step 12', () => {
    test('RC06-T6-REG-02: a failure before step 12 halts startup fail closed and binds no transport', async () => {
      const fixture = makeAuditConfig('reg02');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failStartupStage: 'RUNTIME_CURSORS' } },
      });

      await assert.rejects(
        () => parts.server.start(),
        (err) => {
          // The failure is reported as a bounded code only: the underlying stage
          // fault, its cause and any host path never reach the caller.
          assert.match(err.message, /Audit runtime startup failed \(AUDIT_RUNTIME_STAGE_FAILED\)/);
          assert.equal(/\/|\.pem|store-|stack/i.test(err.message), false);
          return true;
        },
      );

      // No stdio surface exists: `this.transport` is assigned only after the
      // startup sequence and the admin channel have both succeeded.
      assert.equal(parts.server.transport, undefined);
      assert.equal(parts.server.getRemoteGatewayStatus(), undefined);
      assert.equal(parts.server.transportMode, 'stdio');

      // Nothing was written, and the store remains independently verifiable.
      assert.deepEqual(readActiveRecordLines(fixture.auditDir), []);
      const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, EXPECTED_UID);
      assert.equal(verification.status, 'VERIFIED');
      assert.equal(verification.recordCount, 0);

      // The failure released the writer lock: a second process can open it.
      const reopened = await openAuditRuntime(fixture.config);
      await reopened.close();
      await parts.server.stop();
    });

    test('RC06-T6-REG-21: a failed startup leaves no privileged service reachable for either transport', async () => {
      const stdioFixture = makeAuditConfig('reg21-stdio');
      const stdioParts = buildServer(stdioFixture, {
        runtimeOptions: { hooks: { failStartupStage: 'PRIMARY_HISTORY_VERIFICATION' } },
      });
      await assert.rejects(() => stdioParts.server.start());
      assert.equal(stdioParts.server.transport, undefined);

      // Remote mode: the gateway is constructed strictly below the startup
      // sequence, so a stage failure means no listener, no session authority and
      // no remote execution bridge was ever composed.
      const remoteFixture = makeAuditConfig('reg21-remote');
      const remoteParts = buildServer(remoteFixture, {
        runtimeOptions: { hooks: { failStartupStage: 'RUNTIME_CURSORS' } },
      });
      remoteParts.config.transport = 'remote';
      const remoteServer = new DurabilityServer(
        {
          registry: remoteParts.registry,
          kernel: remoteParts.kernel,
          audit: remoteParts.audit,
          filesystem: remoteParts.filesystem,
          git: remoteParts.git,
          approvals: remoteParts.approvals,
          config: {
            ...remoteParts.config,
            transport: 'remote',
            remote: { publicHostname: 'localhost' },
          },
        },
        { hooks: { failStartupStage: 'RUNTIME_CURSORS' } },
      );
      await assert.rejects(() => remoteServer.start());
      assert.equal(remoteServer.transport, undefined);
      assert.equal(remoteServer.getRemoteGatewayStatus(), undefined);
      assert.equal(remoteServer.getRemoteExecutionBridge(), undefined);

      await stdioParts.server.stop();
      await remoteServer.stop();
    });
  });

  /* ======================================================================== *
   * 3. One writer lock, deterministic shutdown
   * ======================================================================== */

  describe('Single writer lock and shutdown', () => {
    test('RC06-T6-REG-03: one lock is held across verification and the whole runtime, and no unlocked verification gap exists', async () => {
      const fixture = makeAuditConfig('reg03');
      const parts = buildServer(fixture);
      await startServer(parts);

      const lockPath = path.join(fixture.auditDir, LOCK_FILENAME);
      assert.equal(fs.existsSync(lockPath), true, 'the writer lock must exist while serving');

      // A second opener of the SAME store fails closed — this is the observable
      // proof that verification did not run unlocked and that no second
      // persistent writer can be created.
      await assert.rejects(
        () => openAuditRuntime(fixture.config),
        (err) => {
          assert.equal(err.code, 'AUDIT_STORE_LOCKED');
          return true;
        },
      );

      // The lock is still held after a served request, so it spans the runtime
      // and not merely startup.
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      await assert.rejects(
        () => openAuditRuntime(fixture.config),
        (err) => {
          assert.equal(err.code, 'AUDIT_STORE_LOCKED');
          return true;
        },
      );

      await parts.server.stop();
      const reopened = await openAuditRuntime(fixture.config);
      await reopened.close();
    });

    test('RC06-T6-REG-20: clean shutdown releases the lock and every audit descriptor', async () => {
      const fixture = makeAuditConfig('reg03-shutdown');
      const parts = buildServer(fixture);

      const baseline = openDescriptorCount(fixture.auditDir);
      await startServer(parts);
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      const during = openDescriptorCount(fixture.auditDir);

      await parts.server.stop();
      startedServers.splice(startedServers.indexOf(parts.server), 1);

      const afterShutdown = openDescriptorCount(fixture.auditDir);
      if (baseline !== null) {
        assert.ok(during > baseline, 'the running runtime must hold audit descriptors');
        assert.equal(afterShutdown, baseline, 'no audit descriptor may leak after shutdown');
      }
      // The lock FILE may remain as a released artifact; what matters is that the
      // exclusion it represents is gone, so a second writer can acquire it.
      assert.equal(fs.existsSync(path.join(fixture.auditDir, ACTIVE_SEGMENT_FILENAME)), true);

      const reopened = await openAuditRuntime(fixture.config);
      await reopened.close();

      // Shutdown is idempotent.
      await parts.server.stop();
    });
  });

  /* ======================================================================== *
   * 4. Production checkpoint and anchor composition
   * ======================================================================== */

  describe('Checkpoint and anchor handoff sequencing', () => {
    test('RC06-T6-REG-08: the production composition installs the real Tier-2 engine as the mandatory rotation sealer', async () => {
      const fixture = makeAuditConfig('reg08');
      const runtime = await openAuditRuntime(fixture.config);
      openRuntimes.push(runtime);

      await runtime.appendRecord(sampleRecordCandidate());
      await runtime.store.rotateNow('SIZE_THRESHOLD');
      // The handoff is drained by the next durable-primary operation, exactly as
      // the production composition does it.
      await runtime.appendRecord(sampleRecordCandidate());

      const checkpoints = readCheckpointRecords(fixture.auditDir);
      assert.ok(checkpoints.length >= 1, 'rotation must seal a real checkpoint');
      assert.equal(runtime.getLastCheckpointSequence(), 1);

      // A real Tier-2 artifact: canonical, chain-bound, and signed by the
      // configured checkpoint key. A synthetic or no-op sealer cannot produce
      // this.
      const sealed = checkpoints[0];
      assert.equal(sealed.sequenceStart, 1);
      assert.equal(sealed.sequenceEnd, 1);
      assert.equal(sealed.publicKeyFingerprint, fixture.checkpoint.fingerprint);
      assert.equal(
        verifyCheckpointSignature(
          sealed,
          crypto.createPublicKey(fs.readFileSync(fixture.config.publicKeyPath)),
        ),
        true,
        'the sealed checkpoint must verify under the key configured on disk',
      );
      assert.equal(sealed.previousCheckpointHash, '0'.repeat(64));
    });

    test('RC06-T6-REG-09: a synthetic or no-op rotation sealer is not production-selectable', async () => {
      const auditPackage = await import('../packages/audit/dist/index.js');
      const suspicious = Object.keys(auditPackage).filter((name) =>
        /synthetic|noop|no_op|fake|stub/i.test(name),
      );
      assert.deepEqual(suspicious, [], 'the package root must export no substitute sealer');

      // The store refuses to exist without a sealer at all, so no code path can
      // rotate a production segment with a no-op.
      const fixture = makeAuditConfig('reg09');
      const runtime = await openAuditRuntime(fixture.config);
      openRuntimes.push(runtime);

      // `RotatingAuditStore` is constructed by the composition with a mandatory
      // sealer; the composition exposes no option to omit or replace it, and the
      // frozen `AuditConfig` has no sealer field.
      assert.deepEqual(Object.keys(fixture.config).sort(), [
        'directory',
        'publicKeyPath',
        'signingKeyPath',
      ]);

      // The engine reached through the composed store is the same one the
      // production factory built: it holds a real checkpoint state, not a stub.
      const state = runtime.getLastCheckpointSequence();
      assert.equal(state, null, 'a fresh store has no checkpoint yet');
      assert.equal(runtime.isAnchorEnabled(), false);
    });

    test('RC06-T6-REG-10: an interval checkpoint is handed to Tier 3 immediately, before any later append can emit another', async () => {
      const fixture = makeAuditConfig('reg10', { anchor: true });
      const storeId = await (async () => {
        const runtime = await createTestAuditRuntime(fixture.config, {
          anchorHooks: { sleep: async () => {} },
        });
        await closeRuntime(runtime);
        return readStoreId(fixture.auditDir);
      })();

      const dispatches = [];
      const checkpointsSeen = [];
      const transport = async (request) => {
        const hash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
        dispatches.push(hash);
        const full = readCheckpointRecords(fixture.auditDir);
        const match = full.find((candidate) => candidate.checkpointHash === hash);
        if (match === undefined) return { statusCode: 400, body: Buffer.from('unknown', 'utf8') };
        if (!checkpointsSeen.includes(hash)) checkpointsSeen.push(hash);
        return {
          statusCode: 200,
          body: Buffer.from(
            JSON.stringify(
              signTestAnchorReceipt(
                {
                  version: 1,
                  storeId,
                  receiptId: crypto.randomUUID(),
                  checkpointHash: hash,
                  anchorTimestamp: '2026-09-21T00:00:00.000Z',
                  anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
                },
                fixture.anchorMaterial.privateKey,
              ),
            ),
            'utf8',
          ),
        };
      };

      const runtime = await createTestAuditRuntime(fixture.config, {
        anchorHooks: { transport, sleep: async () => {} },
      });
      openRuntimes.push(runtime);

      for (let index = 0; index < CHECKPOINT_INTERVAL; index += 1) {
        await runtime.appendRecord(sampleRecordCandidate());
      }

      // The interval boundary at sequence 1000 emitted exactly one checkpoint,
      // and it was handed to Tier 3 within the very append that produced it.
      assert.equal(runtime.getLastCheckpointSequence(), CHECKPOINT_INTERVAL);
      assert.deepEqual(
        dispatches,
        [checkpointsSeen[0]],
        'the interval checkpoint must be dispatched once, immediately',
      );
      assert.equal(runtime.getUnanchoredCheckpointCount(), 0);

      const health = runtime.getHealth();
      assert.equal(health.anchorState, 'HEALTHY');
      assert.equal(health.unanchoredCheckpoints, 0);
      assert.equal(health.lastCheckpointSequence, CHECKPOINT_INTERVAL);
    });

    test('RC06-T6-REG-11 and RC06-T6-REG-12: two successive genuine checkpoints are both handed over in order, with no stale anchor boundary', async () => {
      const fixture = makeAuditConfig('reg11', { anchor: true });
      const runtime = await createTestAuditRuntime(fixture.config, {
        anchorHooks: {
          transport: async () => ({ statusCode: 500, body: Buffer.from('later') }),
          sleep: async () => {},
        },
      });
      await closeRuntime(runtime);
      const storeId = readStoreId(fixture.auditDir);

      const dispatches = [];
      const transport = async (request) => {
        const hash = request.headers[ANCHOR_IDEMPOTENCY_HEADER];
        dispatches.push(hash);
        const match = readCheckpointRecords(fixture.auditDir).find(
          (candidate) => candidate.checkpointHash === hash,
        );
        if (match === undefined) {
          return { statusCode: 409, body: Buffer.from('not-current', 'utf8') };
        }
        return {
          statusCode: 200,
          body: Buffer.from(
            JSON.stringify(
              signTestAnchorReceipt(
                {
                  version: 1,
                  storeId,
                  receiptId: crypto.randomUUID(),
                  checkpointHash: hash,
                  anchorTimestamp: '2026-09-21T00:00:00.000Z',
                  anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
                },
                fixture.anchorMaterial.privateKey,
              ),
            ),
            'utf8',
          ),
        };
      };

      const composed = await createTestAuditRuntime(fixture.config, {
        anchorHooks: { transport, sleep: async () => {} },
      });
      openRuntimes.push(composed);

      // Two successive size-triggered rotations, each producing a genuine
      // checkpoint, driven through the production append path. A composition
      // that advanced the anchor boundary from stale state — or that let the
      // second checkpoint be emitted while the first was still unseen — would
      // surface as `ANCHOR_CHECKPOINT_NOT_CURRENT` or a silently skipped
      // checkpoint. Neither may happen.
      const big = () =>
        sampleRecordCandidate({
          invocation: {
            toolName: 'read_file',
            parametersRedacted: { blob: 'x'.repeat(60_000) },
            payloadHash: 'd'.repeat(64),
          },
        });

      let rotations = 0;
      let guard = 0;
      while (rotations < 2 && guard < 400) {
        guard += 1;
        const before = rotatedSegmentNames(fixture.auditDir).length;
        await composed.appendRecord(big());
        if (rotatedSegmentNames(fixture.auditDir).length > before) rotations += 1;
      }
      assert.equal(rotations, 2, 'two genuine rotations must have been forced');

      const sealed = readCheckpointRecords(fixture.auditDir);
      assert.equal(sealed.length, 2, 'each rotation must seal exactly one checkpoint');
      assert.deepEqual(
        dispatches,
        sealed.map((checkpoint) => checkpoint.checkpointHash),
        'both checkpoints must have been handed to Tier 3, in chain order',
      );
      assert.equal(composed.getUnanchoredCheckpointCount(), 0);
      assert.equal(composed.getHealth().anchorState, 'HEALTHY');
      assert.equal(composed.getHealth().lastCheckpointSequence, sealed[1].sequenceEnd);
      // The two checkpoints are genuinely successive, and the anchor boundary
      // advanced with them rather than staying at the first.
      assert.equal(sealed[1].previousCheckpointHash, sealed[0].checkpointHash);
      assert.ok(sealed[1].sequenceEnd > sealed[0].sequenceEnd);
    });
  });

  /* ======================================================================== *
   * 5. Storage and backpressure gates
   * ======================================================================== */

  describe('Storage and backpressure gates', () => {
    test('RC06-T6-REG-13: a full anchor spool blocks privileged reads and mutations with zero subsystem work', async () => {
      const fixture = makeAuditConfig('reg13', { anchor: true });
      const failing = await createTestAuditRuntime(fixture.config, {
        anchorHooks: {
          transport: async () => ({ statusCode: 500, body: Buffer.from('no') }),
          sleep: async () => {},
        },
      });
      openRuntimes.push(failing);

      // Genuine checkpoints, produced the only way a real store produces them,
      // and a genuinely failing anchor that spools every one of them.
      const rotations = MAX_PENDING_ANCHOR_CHECKPOINTS - 1;
      for (let index = 0; index < rotations; index += 1) {
        await failing.appendRecord(sampleRecordCandidate());
        await failing.store.rotateNow('SIZE_THRESHOLD');
      }
      // The interval boundary lands the hundredth entry, which is what latches
      // the frozen `FULL` backpressure state.
      for (let index = 0; index < CHECKPOINT_INTERVAL + 1; index += 1) {
        await failing.appendRecord(sampleRecordCandidate());
      }
      assert.equal(failing.getHealth().anchorState, 'FULL');
      assert.equal(failing.getUnanchoredCheckpointCount(), MAX_PENDING_ANCHOR_CHECKPOINTS);
      const spoolEntries = fs.readdirSync(path.join(fixture.auditDir, ANCHOR_SPOOL_DIRNAME));
      assert.equal(spoolEntries.length, MAX_PENDING_ANCHOR_CHECKPOINTS);
      await closeRuntime(failing);

      const parts = buildServer(fixture);
      await startServer(parts);
      assert.equal((await auditHealth(parts)).anchorState, 'FULL');

      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;
      const treeBefore = treeDigest(workspaceDir);

      const read = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(read.code, 'RESOURCE_EXHAUSTED');

      // The backpressure gate runs BEFORE policy evaluation and before any
      // approval record exists, so a mutation is refused with the capacity
      // refusal rather than ever reaching `APPROVAL_REQUIRED`.
      const mutation = body(
        await parts.server.dispatchToolCall('create_file', {
          path: 'blocked.txt',
          content: 'x',
          workspaceId: 'ws',
        }),
      );
      assert.equal(mutation.code, 'RESOURCE_EXHAUSTED');
      assert.notEqual(mutation.code, 'APPROVAL_REQUIRED');
      assert.equal(parts.approvals.listActive().length, 0);

      assert.equal(parts.filesystem.reads, readsBefore, 'no read may reach the subsystem');
      assert.equal(
        parts.filesystem.mutations,
        mutationsBefore,
        'no mutation may reach the subsystem',
      );
      assert.equal(treeDigest(workspaceDir), treeBefore, 'the workspace must be unchanged');

      // No evidence was deleted to make room.
      assert.equal(
        fs.readdirSync(path.join(fixture.auditDir, ANCHOR_SPOOL_DIRNAME)).length,
        MAX_PENDING_ANCHOR_CHECKPOINTS,
      );
    });

    test('RC06-T6-REG-14: exhausting the frozen audit storage budget blocks privileged reads and mutations', async () => {
      const fixture = makeAuditConfig('reg14');
      const parts = buildServer(fixture);
      await startServer(parts);
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');

      // A canonical retained archive whose physical size reaches the frozen
      // total budget. Nothing is deleted and no log wraps: the gate refuses.
      const name = 'audit-20260921T000000Z-seq1-seq1.jsonl.gz';
      assert.notEqual(parseRotatedSegmentFilename(name), null, 'fixture name must be canonical');
      const archivePath = path.join(fixture.auditDir, name);
      const handle = fs.openSync(archivePath, 'w', 0o600);
      try {
        fs.ftruncateSync(handle, TOTAL_AUDIT_BUDGET_BYTES);
      } finally {
        fs.closeSync(handle);
      }
      assert.ok(
        scanAuditStorePhysicalBytes(fixture.auditDir, EXPECTED_UID) >= TOTAL_AUDIT_BUDGET_BYTES,
      );

      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;
      const treeBefore = treeDigest(workspaceDir);

      const read = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(read.code, 'RESOURCE_EXHAUSTED');

      const mutation = body(
        await parts.server.dispatchToolCall('create_file', {
          path: 'exhausted.txt',
          content: 'x',
          workspaceId: 'ws',
        }),
      );
      assert.equal(mutation.code, 'RESOURCE_EXHAUSTED');
      assert.equal(parts.approvals.listActive().length, 0);

      assert.equal(parts.filesystem.reads, readsBefore);
      assert.equal(parts.filesystem.mutations, mutationsBefore);
      assert.equal(treeDigest(workspaceDir), treeBefore);
      assert.equal(fs.existsSync(archivePath), true, 'evidence must never be deleted to reclaim');
      assert.ok(MAX_ARCHIVE_SEGMENTS > 1);
    });
  });

  /* ======================================================================== *
   * 6. Health metadata
   * ======================================================================== */

  describe('Health metadata', () => {
    test('RC06-T6-REG-15: health reports a bounded, truthful audit state', async () => {
      const fixture = makeAuditConfig('reg15');
      const parts = buildServer(fixture);
      await parts.server.start();
      startedServers.push(parts.server);

      const health = body(await parts.server.dispatchToolCall('health', {}));
      assert.deepEqual(Object.keys(health.audit).sort(), [
        'anchorState',
        'indeterminateRecoveries',
        'integrity',
        'lastCheckpointSequence',
        'persistence',
        'sequence',
        'unanchoredCheckpoints',
      ]);
      assert.equal(health.audit.persistence, 'ACTIVE');
      assert.equal(health.audit.integrity, 'VERIFIED');
      // `sequence` is the chain cursor: the sequence the next durable record
      // will carry. An empty retained history has its first record at 1.
      assert.equal(health.audit.sequence, 1);
      assert.equal(health.audit.lastCheckpointSequence, null);
      assert.equal(health.audit.unanchoredCheckpoints, 0);
      assert.equal(health.audit.anchorState, 'DISABLED');
      assert.equal(health.audit.indeterminateRecoveries, 0);
      assert.equal(health.status, 'HEALTHY');

      // The counters track the one durable chain, not a copy of it.
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      const after = await auditHealth(parts);
      assert.equal(after.sequence, 3, 'one STARTED and one COMPLETED record occupy 1 and 2');
      assert.equal(after.persistence, 'ACTIVE');
      assert.equal(readActiveRecords(fixture.auditDir).length, 2);
    });

    test('RC06-T6-REG-16: health discloses no audit path, key path, key body, endpoint, receipt or spool detail', async () => {
      const fixture = makeAuditConfig('reg16', { anchor: true });
      const parts = buildServer(fixture);
      await startServer(parts);
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });

      const serialized = JSON.stringify(body(await parts.server.dispatchToolCall('health', {})));
      const forbidden = [
        fixture.auditDir,
        fixture.keyDir,
        fixture.config.signingKeyPath,
        fixture.config.publicKeyPath,
        fixture.config.anchorReceiptPublicKeyPath,
        ENDPOINT,
        ANCHOR_SPOOL_DIRNAME,
        ANCHOR_RECEIPT_FILENAME,
        CHECKPOINT_FILENAME,
        ACTIVE_SEGMENT_FILENAME,
        LOCK_FILENAME,
        'PRIVATE KEY',
        'BEGIN PUBLIC KEY',
        fixture.checkpoint.fingerprint,
        fixture.anchorMaterial.fingerprint,
        workspaceDir,
      ];
      for (const needle of forbidden) {
        assert.equal(
          serialized.includes(needle),
          false,
          `health must not disclose ${needle.slice(0, 32)}`,
        );
      }
      assert.equal(serialized.includes('"'), true);
    });
  });

  /* ======================================================================== *
   * 7. stdio / remote convergence
   * ======================================================================== */

  describe('stdio and remote convergence', () => {
    test('RC06-T6-REG-17: the same privileged tool receives durable STARTED -> subsystem -> durable COMPLETED under both transport-entry paths', async () => {
      const fixture = makeAuditConfig('reg17');
      const parts = buildServer(fixture);
      await startServer(parts);

      // The real remote execution bridge over the server's ONE session
      // authority, composed exactly as `start()` composes it in remote mode.
      const store = DeviceTrustStore.createEmpty();
      const spkiPin = pinFor('reg17');
      store.enrollDevice({ clientId: 'agent-reg17', clientType: 'claude-code', pin: spkiPin });
      const bridge = new RemoteExecutionBridge({
        sessionManager: parts.server.sessionManager,
        resolveActiveDeviceIdentity: (pin) => resolveActiveDeviceIdentity(store, pin),
        sink: parts.server,
      });
      const identity = resolveActiveDeviceIdentity(store, spkiPin);
      const sessionId = parts.server.sessionManager.createSessionIdGenerator()();
      const issuance = parts.server.sessionManager.issueSession({ sessionId, identity });

      const stdio = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(stdio.isError, undefined);

      const remote = body(
        await bridge.executeRemoteToolCall({
          trustedSpkiPin: spkiPin,
          presentedSessionId: sessionId,
          authorizationHeader: `Bearer ${issuance.token}`,
          toolName: 'read_file',
          parameters: { path: 'README.md', workspaceId: 'ws' },
        }),
      );
      assert.equal(remote.isError, undefined);

      // Both invocations are in the ONE persistent primary chain: one segment,
      // contiguous sequences, two distinct lifecycle binders, one tool.
      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.length, 4);
      assert.deepEqual(
        records.map((record) => record.sequenceNumber),
        [1, 2, 3, 4],
      );
      const started = records.filter((record) => record.lifecycle.phase === 'STARTED');
      const completed = records.filter((record) => record.lifecycle.phase === 'COMPLETED');
      assert.equal(started.length, 2);
      assert.equal(completed.length, 2);
      assert.equal(new Set(started.map((r) => r.lifecycle.operationId)).size, 2);
      assert.deepEqual(
        started.map((r) => r.lifecycle.operationId).sort(),
        completed.map((r) => r.lifecycle.operationId).sort(),
      );
      for (const record of records) {
        assert.equal(record.invocation.toolName, 'read_file');
      }

      // Audit durability is identical; authentication is what stays
      // remote-specific.
      assert.equal(records[0].actor.clientType, 'mcp-client');
      assert.equal(records[2].actor.clientType, 'claude-code');
      assert.notEqual(records[0].actor.clientId, records[2].actor.clientId);
    });
  });

  /* ======================================================================== *
   * 8. Concurrency and sequence integrity
   * ======================================================================== */

  describe('Concurrency and sequence integrity', () => {
    test('RC06-T6-REG-18: concurrent reads and mutations preserve one contiguous sequence and one unbroken hash chain, with every mutation ordered after its own STARTED', async () => {
      const fixture = makeAuditConfig('reg18');
      const filesystem = new FilesystemSpy();
      const startedCreateFilePaths = new Set();
      filesystem.onCall = ({ method, request }) => {
        if (method !== 'createFile') return;
        for (const record of readActiveRecords(fixture.auditDir)) {
          if (record.lifecycle?.phase !== 'STARTED') continue;
          if (record.invocation.toolName !== 'create_file') continue;
          startedCreateFilePaths.add(record.invocation.parametersRedacted.path);
        }
        assert.ok(
          startedCreateFilePaths.has(request.path),
          `mutation of ${request.path} reached the subsystem before its own STARTED was durable`,
        );
      };

      const parts = buildServer(fixture, { filesystem });
      await startServer(parts);

      const READERS = 6;
      const WRITERS = 4;
      const tasks = [];
      for (let index = 0; index < READERS; index += 1) {
        tasks.push(
          parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
        );
      }
      for (let index = 0; index < WRITERS; index += 1) {
        tasks.push(
          requestApproveRedeem(parts, 'create_file', {
            path: `concurrent-${index}.txt`,
            content: `payload-${index}`,
            workspaceId: 'ws',
          }),
        );
      }
      await Promise.all(tasks);

      assert.equal(filesystem.mutations, WRITERS);
      for (let index = 0; index < WRITERS; index += 1) {
        assert.equal(
          fs.readFileSync(path.join(workspaceDir, `concurrent-${index}.txt`), 'utf8'),
          `payload-${index}`,
        );
      }

      const records = readActiveRecords(fixture.auditDir);
      assert.deepEqual(
        records.map((record) => record.sequenceNumber),
        records.map((_, index) => index + 1),
        'the global sequence must be contiguous with no duplicate or gap',
      );
      for (let index = 1; index < records.length; index += 1) {
        assert.equal(
          records[index].integrity.previousRecordHash,
          records[index - 1].integrity.recordHash,
        );
      }
      assert.equal(records[0].integrity.previousRecordHash, '0'.repeat(64));

      const byOperation = new Map();
      for (const record of records) {
        if (record.lifecycle === undefined) continue;
        assert.match(
          record.lifecycle.operationId,
          /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        );
        const entry = byOperation.get(record.lifecycle.operationId) ?? {};
        entry[record.lifecycle.phase] = record.sequenceNumber;
        byOperation.set(record.lifecycle.operationId, entry);
      }

      let completions = 0;
      for (const [, entry] of byOperation) {
        if (entry.COMPLETED !== undefined) {
          completions += 1;
          assert.ok(
            entry.STARTED !== undefined && entry.STARTED < entry.COMPLETED,
            'every COMPLETED must be preceded by its own durable STARTED',
          );
        }
        if (entry.STARTED !== undefined) {
          assert.equal(entry.DENIED, undefined, 'STARTED -> DENIED must never occur');
        }
      }
      assert.equal(completions, READERS + WRITERS);
    });
  });

  /* ======================================================================== *
   * 9. Production crash-indeterminate reconciliation
   * ======================================================================== */

  describe('Crash-indeterminate reconciliation (Flow 21)', () => {
    test('RC06-T6-REG-25: production startup reconciles an execution whose COMPLETED was lost, exactly once, under the same operationId', async () => {
      const fixture = makeAuditConfig('reg19');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      const { secondBody } = await requestApproveRedeem(parts, 'create_file', {
        path: 'crashed.txt',
        content: 'durable',
        workspaceId: 'ws',
      });
      // The mutation executed; its terminal evidence could not be secured.
      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.equal(fs.readFileSync(path.join(workspaceDir, 'crashed.txt'), 'utf8'), 'durable');
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');

      const before = readActiveRecords(fixture.auditDir);
      const dangling = before.filter((record) => record.lifecycle?.phase === 'STARTED');
      assert.equal(dangling.length, 1);
      const operationId = dangling[0].lifecycle.operationId;
      assert.equal(
        before.filter((record) => record.lifecycle?.phase === 'COMPLETED').length,
        0,
        'no false terminal record may be invented',
      );

      // The process can no longer discharge that operation, so it halts. Only a
      // restart with successful frozen startup reconciliation can resolve it.
      await parts.server.stop();
      startedServers.splice(startedServers.indexOf(parts.server), 1);

      const restarted = buildServer(fixture);
      await startServer(restarted);
      assert.equal((await auditHealth(restarted)).indeterminateRecoveries, 1);
      assert.equal((await auditHealth(restarted)).persistence, 'ACTIVE');

      const after = readActiveRecords(fixture.auditDir);
      const recoveries = after.filter(
        (record) => record.lifecycle?.phase === 'RECOVERY_INDETERMINATE',
      );
      assert.equal(recoveries.length, 1);
      assert.equal(recoveries[0].lifecycle.operationId, operationId);
      assert.equal(recoveries[0].actor.clientType, 'SYSTEM');
      assert.equal(recoveries[0].invocation.toolName, 'create_file');
    });
  });

  /* ======================================================================== *
   * 10. Pre-dispatch durability — RC06-NEG-40, RC06-NEG-41
   * ======================================================================== */

  describe('Pre-dispatch durability', () => {
    test('RC06-NEG-40: a privileged read whose STARTED persistence fails reaches the subsystem zero times and appends no later phase', async () => {
      const fixture = makeAuditConfig('neg40');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'STARTED' } },
      });
      await startServer(parts);

      const before = readActiveRecordLines(fixture.auditDir);
      const linesBefore = before.length;

      // The spy is the REAL subsystem boundary, so "zero calls" is observed
      // where the call would actually happen, not inferred from a response.
      const readsBefore = parts.filesystem.reads;
      const result = await parts.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      const parsed = body(result);

      assert.equal(parts.filesystem.reads, readsBefore, 'the subsystem must receive ZERO calls');
      assert.equal(result.isError, true);
      assert.equal(parsed.code, 'INTERNAL_ERROR');
      assert.equal(parsed.category, 'INTERNAL');
      assert.equal(
        parsed.message,
        'Privileged operations are halted: durable audit evidence could not be secured.',
      );
      assert.equal(/[/\\]|README|\.pem|store|spool|sequence/i.test(parsed.message), false);

      // No later phase was appended: no COMPLETED record exists for an operation
      // whose STARTED never became durable.
      const after = readActiveRecords(fixture.auditDir);
      assert.equal(readActiveRecordLines(fixture.auditDir).length, linesBefore);
      assert.equal(
        after.filter((record) => record.lifecycle?.phase === 'COMPLETED').length,
        0,
        'no terminal phase may follow a failed STARTED',
      );

      // A later privileged read is refused the same way, with zero calls.
      const secondReads = parts.filesystem.reads;
      const second = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(second.code, 'INTERNAL_ERROR');
      assert.equal(parts.filesystem.reads, secondReads);
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');
    });

    test('RC06-NEG-41: a privileged mutation whose STARTED persistence fails leaves the target byte-for-byte unchanged', async () => {
      const fixture = makeAuditConfig('neg41');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'STARTED' } },
      });
      await startServer(parts);

      const target = path.join(workspaceDir, 'denied-mutation.txt');
      assert.equal(fs.existsSync(target), false);
      const treeBefore = treeDigest(workspaceDir);
      const mutationsBefore = parts.filesystem.mutations;

      const { secondBody } = await requestApproveRedeem(parts, 'create_file', {
        path: 'denied-mutation.txt',
        content: 'must-not-exist',
        workspaceId: 'ws',
      });

      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.equal(parts.filesystem.mutations, mutationsBefore, 'zero mutation subsystem calls');
      assert.equal(fs.existsSync(target), false, 'no side effect may exist');
      assert.equal(
        treeDigest(workspaceDir),
        treeBefore,
        'target state must be structurally unchanged',
      );

      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.filter((record) => record.lifecycle?.phase === 'COMPLETED').length, 0);
      // The pre-dispatch REQUIRE_APPROVAL denial is the only evidence written,
      // and it is a terminal DENIED branch with its own operationId — never a
      // STARTED for an execution that did not happen.
      const denied = records.filter((record) => record.lifecycle?.phase === 'DENIED');
      assert.equal(denied.length, 1);
      assert.equal(denied[0].execution.status, 'DENIED');
      assert.equal(denied[0].policy.decision, 'REQUIRE_APPROVAL');
      assert.equal(records.filter((record) => record.lifecycle?.phase === 'STARTED').length, 0);
    });
  });

  /* ======================================================================== *
   * 11. Post-dispatch durability — RC06-NEG-42, RC06-NEG-43
   * ======================================================================== */

  describe('Post-dispatch durability', () => {
    test('RC06-NEG-42: a read whose COMPLETED persistence fails executes exactly once and latches the process-wide degraded state', async () => {
      const fixture = makeAuditConfig('neg42');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      const readsBefore = parts.filesystem.reads;
      const result = await parts.server.dispatchToolCall('read_file', {
        path: 'README.md',
        workspaceId: 'ws',
      });
      const parsed = body(result);

      assert.equal(parts.filesystem.reads, readsBefore + 1, 'the read ran exactly once');
      assert.equal(result.isError, true);
      assert.equal(parsed.code, 'INTERNAL_ERROR');

      // The read result is NOT used as evidence that auditing is healthy.
      const health = await auditHealth(parts);
      assert.equal(health.persistence, 'DEGRADED');
      assert.equal(health.integrity, 'VERIFIED');
      const fullHealth = body(await parts.server.dispatchToolCall('health', {}));
      assert.equal(fullHealth.status, 'DEGRADED');

      // Later privileged work is gated before the subsystem boundary.
      const gatedReads = parts.filesystem.reads;
      const gated = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(gated.code, 'INTERNAL_ERROR');
      assert.equal(parts.filesystem.reads, gatedReads, 'no later subsystem work may run');

      // The durable STARTED is the truthful record; no terminal phase exists.
      const records = readActiveRecords(fixture.auditDir);
      const started = records.filter((record) => record.lifecycle?.phase === 'STARTED');
      assert.equal(started.length, 1);
      assert.equal(records.filter((record) => record.lifecycle?.phase === 'COMPLETED').length, 0);
      assert.equal(started[0].invocation.toolName, 'read_file');
    });

    test('RC06-NEG-43: a mutation whose COMPLETED persistence fails is never rolled back, never falsely terminated, and halts the runtime', async () => {
      const fixture = makeAuditConfig('neg43');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      const target = path.join(workspaceDir, 'uncertain.txt');
      const mutationsBefore = parts.filesystem.mutations;

      const { secondBody } = await requestApproveRedeem(parts, 'create_file', {
        path: 'uncertain.txt',
        content: 'side-effect',
        workspaceId: 'ws',
      });

      assert.equal(secondBody.code, 'INTERNAL_ERROR');
      assert.equal(
        parts.filesystem.mutations,
        mutationsBefore + 1,
        'the mutation ran exactly once',
      );
      // No rollback is invented: the subsystem has none, so the side effect
      // stands and the durable STARTED is what makes it recoverable.
      assert.equal(fs.readFileSync(target, 'utf8'), 'side-effect');
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');

      const records = readActiveRecords(fixture.auditDir);
      const started = records.filter((record) => record.lifecycle?.phase === 'STARTED');
      assert.equal(started.length, 1);
      assert.equal(started[0].invocation.toolName, 'create_file');
      assert.equal(
        records.filter((record) => record.lifecycle?.phase === 'COMPLETED').length,
        0,
        'no false SUCCESS terminal record',
      );
      // The only DENIED branch is the pre-dispatch approval denial, which has
      // its own operationId and is not a terminal for this execution.
      const denied = records.filter((record) => record.lifecycle?.phase === 'DENIED');
      assert.equal(denied.length, 1);
      assert.notEqual(denied[0].lifecycle.operationId, started[0].lifecycle.operationId);

      const readsBefore = parts.filesystem.reads;
      const gated = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(gated.code, 'INTERNAL_ERROR');
      assert.equal(parts.filesystem.reads, readsBefore, 'future privileged dispatch halts');
    });
  });

  /* ======================================================================== *
   * 12. Global degraded latch — RC06-NEG-44, RC06-NEG-45
   * ======================================================================== */

  describe('Global degraded latch', () => {
    test('RC06-NEG-44: after the latch, every privileged read is rejected before dispatch with no approval state created or redeemed', async () => {
      const fixture = makeAuditConfig('neg44');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      // Latch the process through a real executed read.
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');

      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;
      const activeBefore = parts.approvals.listActive().length;
      const recordsBefore = readActiveRecords(fixture.auditDir).length;

      // A read-only availability bypass must not exist.
      for (const [tool, params] of [
        ['read_file', { path: 'README.md', workspaceId: 'ws' }],
        ['system_status', { workspaceId: 'ws' }],
        ['list_directory', { path: '.', workspaceId: 'ws' }],
        ['git_status', { workspaceId: 'ws' }],
      ]) {
        const parsed = body(await parts.server.dispatchToolCall(tool, params));
        assert.equal(parsed.code, 'INTERNAL_ERROR', `${tool} must be refused while latched`);
      }
      assert.equal(parts.filesystem.reads, readsBefore, 'zero subsystem work');
      assert.equal(parts.git.reads, 0, 'zero git work');

      // A mutation that would REQUIRE_APPROVAL never even creates the request,
      // so no token can be redeemed and no approval state is consumed.
      const mutation = body(
        await parts.server.dispatchToolCall('create_file', {
          path: 'latched.txt',
          content: 'x',
          workspaceId: 'ws',
        }),
      );
      assert.equal(mutation.code, 'INTERNAL_ERROR');
      assert.notEqual(mutation.code, 'APPROVAL_REQUIRED');
      assert.equal(parts.approvals.listActive().length, activeBefore);
      assert.equal(parts.filesystem.mutations, mutationsBefore);
      assert.equal(fs.existsSync(path.join(workspaceDir, 'latched.txt')), false);

      // A rejected operation is not a lifecycle branch: nothing new is written.
      assert.equal(readActiveRecords(fixture.auditDir).length, recordsBefore);

      // The one non-dispatching surface stays informational, and does NOT
      // re-enable anything.
      const health = body(await parts.server.dispatchToolCall('health', {}));
      assert.equal(health.status, 'DEGRADED');
      assert.equal(health.audit.persistence, 'DEGRADED');
      const stillGated = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(stillGated.code, 'INTERNAL_ERROR');
    });

    test('RC06-NEG-45: the latch is process-wide across transports and sessions, with no token consumption and no per-session escape', async () => {
      const fixture = makeAuditConfig('neg45');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      const store = DeviceTrustStore.createEmpty();
      const bridge = new RemoteExecutionBridge({
        sessionManager: parts.server.sessionManager,
        resolveActiveDeviceIdentity: (pin) => resolveActiveDeviceIdentity(store, pin),
        sink: parts.server,
      });
      const sessions = ['a', 'b'].map((seed) => {
        const spkiPin = pinFor(`neg45-${seed}`);
        store.enrollDevice({ clientId: `agent-${seed}`, clientType: 'claude-code', pin: spkiPin });
        const identity = resolveActiveDeviceIdentity(store, spkiPin);
        const sessionId = parts.server.sessionManager.createSessionIdGenerator()();
        const issuance = parts.server.sessionManager.issueSession({ sessionId, identity });
        return { spkiPin, sessionId, token: issuance.token };
      });
      const call = (session, toolName, parameters) =>
        bridge.executeRemoteToolCall({
          trustedSpkiPin: session.spkiPin,
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${session.token}`,
          toolName,
          parameters,
        });

      // The remote path reaches the SAME pipeline as stdio: the very first
      // remote call is admitted, evaluated and answered with a real approval
      // request on the one durable chain.
      const firstRemote = body(
        await call(sessions[0], 'create_file', {
          path: 'remote.txt',
          content: 'x',
          workspaceId: 'ws',
        }),
      );
      assert.equal(firstRemote.code, 'APPROVAL_REQUIRED');
      const pendingRequestId = firstRemote.details.approvalRequestId;
      const grant = parts.approvals.approve(pendingRequestId);

      // Latch the process through the stdio path.
      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');

      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;

      for (const session of sessions) {
        const readBody = body(
          await call(session, 'read_file', { path: 'README.md', workspaceId: 'ws' }),
        );
        assert.equal(readBody.code, 'INTERNAL_ERROR', 'no transport-specific or session escape');
        const mutationBody = body(
          await call(session, 'create_file', {
            path: 'remote.txt',
            content: 'x',
            workspaceId: 'ws',
          }),
        );
        assert.equal(mutationBody.code, 'INTERNAL_ERROR');
      }

      // A remote mutation presenting a REAL approval token still cannot redeem
      // it: the global gate runs before any approval state is touched, so the
      // token is neither consumed nor invalidated by the refusal.
      const withToken = body(
        await call(sessions[1], 'create_file', {
          path: 'remote.txt',
          content: 'x',
          workspaceId: 'ws',
          _arcApproval: { requestId: pendingRequestId, token: grant.token },
        }),
      );
      assert.equal(withToken.code, 'INTERNAL_ERROR');
      assert.equal(
        parts.approvals.getRequest(pendingRequestId).state,
        'APPROVED',
        'a rejected operation must not consume an approval token',
      );

      assert.equal(parts.filesystem.reads, readsBefore);
      assert.equal(parts.filesystem.mutations, mutationsBefore);
      assert.equal(fs.existsSync(path.join(workspaceDir, 'remote.txt')), false);
    });

    test('RC06-T6-REG-19: the latch is never cleared in-process, across sessions created before and after it and across many later operations', async () => {
      const fixture = makeAuditConfig('reg19');
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'COMPLETED' } },
      });
      await startServer(parts);

      const store = DeviceTrustStore.createEmpty();
      const bridge = new RemoteExecutionBridge({
        sessionManager: parts.server.sessionManager,
        resolveActiveDeviceIdentity: (pin) => resolveActiveDeviceIdentity(store, pin),
        sink: parts.server,
      });
      const openSession = (seed) => {
        const spkiPin = pinFor(`reg19-${seed}`);
        store.enrollDevice({ clientId: `agent-${seed}`, clientType: 'claude-code', pin: spkiPin });
        const identity = resolveActiveDeviceIdentity(store, spkiPin);
        const sessionId = parts.server.sessionManager.createSessionIdGenerator()();
        const issuance = parts.server.sessionManager.issueSession({ sessionId, identity });
        return { spkiPin, sessionId, token: issuance.token };
      };
      const call = (session, toolName, parameters) =>
        bridge.executeRemoteToolCall({
          trustedSpkiPin: session.spkiPin,
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${session.token}`,
          toolName,
          parameters,
        });

      // A session that exists BEFORE the latch.
      const before = openSession('before');

      await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');

      // A session admitted AFTER the latch. Admission is remote-specific and
      // still succeeds; the audit latch is not.
      const after = openSession('after');

      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;

      // Many later operations, interleaved across both transports and both
      // sessions, with an `await` boundary between every one of them. The latch
      // must survive every one: it is a process-wide state, and there is no
      // in-process clear anywhere — recovery requires a restart.
      for (let round = 0; round < 5; round += 1) {
        const stdio = body(
          await parts.server.dispatchToolCall('read_file', {
            path: 'README.md',
            workspaceId: 'ws',
          }),
        );
        assert.equal(stdio.code, 'INTERNAL_ERROR');
        const remote = body(
          await call(round % 2 === 0 ? before : after, 'read_file', {
            path: 'README.md',
            workspaceId: 'ws',
          }),
        );
        assert.equal(remote.code, 'INTERNAL_ERROR');
        const mutation = body(
          await call(after, 'create_file', { path: 'reg19.txt', content: 'x', workspaceId: 'ws' }),
        );
        assert.equal(mutation.code, 'INTERNAL_ERROR');

        // A non-dispatching health read is the ONLY surface still answering, and
        // it must keep reporting the latched state rather than clearing it.
        const health = await auditHealth(parts);
        assert.equal(health.persistence, 'DEGRADED', `round ${round} must not clear the latch`);
        assert.equal(
          health.integrity,
          'VERIFIED',
          'the latch is a durability state, not corruption',
        );
      }

      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');
      assert.equal(parts.filesystem.reads, readsBefore, 'no privileged read may run while latched');
      assert.equal(
        parts.filesystem.mutations,
        mutationsBefore,
        'no mutation may run while latched',
      );
      assert.equal(fs.existsSync(path.join(workspaceDir, 'reg19.txt')), false);

      // Only a restart with successful frozen startup verification clears it —
      // and that is a new process-level runtime, not an in-process reset.
      await parts.server.stop();
      startedServers.splice(startedServers.indexOf(parts.server), 1);
      const restarted = buildServer(fixture);
      await startServer(restarted);
      assert.equal((await auditHealth(restarted)).persistence, 'ACTIVE');
      assert.equal(
        (await auditHealth(restarted)).indeterminateRecoveries,
        1,
        'the durable STARTED is what made the lost terminal recoverable',
      );
    });
  });

  /* ======================================================================== *
   * 13. Task-7 surfaces and frozen public surface
   * ======================================================================== */

  describe('Task-7 absence and frozen public surface', () => {
    test('RC06-T6-REG-22: Task-7 audit CLI and offline verifier surfaces remain absent', async () => {
      const serverPackage = await import('../apps/mcp-server/dist/index.js');
      const auditPackage = await import('../packages/audit/dist/index.js');
      const forbidden =
        /^(auditStatus|auditVerify|auditInspect|auditExport|verifyAuditStore|openOfflineVerifier|exportAuditEvidence|inspectAuditStore|runAuditCommand)$/;
      for (const name of Object.keys(serverPackage)) {
        assert.equal(forbidden.test(name), false, `mcp-server must not export ${name}`);
      }
      for (const name of Object.keys(auditPackage)) {
        assert.equal(forbidden.test(name), false, `audit package must not export ${name}`);
      }

      // The CLI has no `audit` command head: invoking one is a usage error and
      // never reaches the admin channel.
      let cliFailure = null;
      try {
        execFileSync(
          process.execPath,
          [path.join(REPO_ROOT, 'apps/cli/dist/index.js'), 'audit', 'status'],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
        );
      } catch (err) {
        cliFailure = err;
      }
      assert.notEqual(cliFailure, null, 'the CLI must reject an unknown `audit` command');
      assert.match(
        `${cliFailure.stdout ?? ''}${cliFailure.stderr ?? ''}`,
        /usage|unknown|unrecognized|expected/i,
      );
    });

    test('RC06-T6-REG-23: the public RC version and stage are unchanged by Task 6', async () => {
      const rootPackage = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
      const serverPackage = JSON.parse(
        fs.readFileSync(path.join(REPO_ROOT, 'apps/mcp-server/package.json'), 'utf8'),
      );
      const auditPackageJson = JSON.parse(
        fs.readFileSync(path.join(REPO_ROOT, 'packages/audit/package.json'), 'utf8'),
      );
      assert.equal(rootPackage.version, '0.5.0-rc05');
      assert.equal(serverPackage.version, '0.5.0-rc05');
      assert.equal(auditPackageJson.version, '0.0.0-rc00');

      const fixture = makeAuditConfig('reg23');
      const parts = buildServer(fixture);
      await startServer(parts);
      const health = body(await parts.server.dispatchToolCall('health', {}));
      assert.equal(health.version, '0.5.0-rc05');
      assert.equal(health.stage, 'RC-05');

      // No `enabled` flag exists on the frozen audit configuration: auditing is
      // mandatory in production.
      assert.deepEqual(Object.keys(fixture.config).sort(), [
        'directory',
        'publicKeyPath',
        'signingKeyPath',
      ]);
      const withoutAudit = buildServer(fixture);
      const bare = new DurabilityServer(
        {
          registry: withoutAudit.registry,
          kernel: withoutAudit.kernel,
          audit: withoutAudit.audit,
          filesystem: withoutAudit.filesystem,
          git: withoutAudit.git,
          approvals: withoutAudit.approvals,
          config: { transport: 'stdio', authorizedRoots: [], defaultWorkspaceId: 'ws' },
        },
        undefined,
      );
      await assert.rejects(() => bare.start(), /Audit configuration is required/);
      await bare.stop();
    });
  });

  /* ======================================================================== *
   * 14. Test-seam and capability isolation
   * ======================================================================== */

  describe('Public and test-seam isolation', () => {
    test('RC06-T6-REG-24: the production composition exposes no runtime seam through its public surface', async () => {
      const auditPackage = await import('../packages/audit/dist/index.js');
      const runtimeTesting = await import('../packages/audit/dist/internal/runtime-testing.js');
      const auditCapability = await import('../packages/audit/dist/internal/runtime-capability.js');

      // The seams exist only under the package-internal module.
      assert.equal(typeof runtimeTesting.createTestAuditRuntime, 'function');
      assert.equal(typeof auditCapability.AUDIT_RUNTIME_TEST_TOKEN, 'symbol');
      for (const name of [
        'createTestAuditRuntime',
        'AUDIT_RUNTIME_TEST_TOKEN',
        'AuditRuntimeTestHooks',
        'AuditRuntimeCompositionSeams',
      ]) {
        assert.equal(name in auditPackage, false, `${name} must not be exported from the root`);
      }

      // The package `exports` map still has exactly one subpath.
      const manifest = JSON.parse(
        fs.readFileSync(path.join(REPO_ROOT, 'packages/audit/package.json'), 'utf8'),
      );
      assert.deepEqual(Object.keys(manifest.exports), ['.']);

      // The ROOT declaration — the only declaration a consumer of the package
      // can reach — names none of the seams or capability tokens.
      const declaration = fs.readFileSync(
        path.join(REPO_ROOT, 'packages/audit/dist/index.d.ts'),
        'utf8',
      );
      for (const name of [
        'AUDIT_RUNTIME_TEST_TOKEN',
        'createTestAuditRuntime',
        'AuditRuntimeTestHooks',
        'AuditRuntimeCompositionSeams',
        'failAppendPhase',
        'failStartupStage',
        'onStartupStage',
        'markStartupComplete',
        'noteAnchorHandoffFailure',
      ]) {
        assert.equal(declaration.includes(name), false, `index.d.ts must not name ${name}`);
      }

      // The runtime a caller receives exposes no cursor setter, no verified-state
      // constructor and no lock handoff token.
      const fixture = makeAuditConfig('reg24');
      const runtime = await openAuditRuntime(fixture.config);
      openRuntimes.push(runtime);
      const surface = [];
      for (
        let proto = Object.getPrototypeOf(runtime);
        proto !== null && proto !== Object.prototype;
        proto = Object.getPrototypeOf(proto)
      ) {
        surface.push(...Object.getOwnPropertyNames(proto));
      }
      const surfaceSet = new Set(surface.filter((name) => name !== 'constructor'));
      assert.deepEqual(
        [...surfaceSet].filter((name) =>
          /set|force|override|internal|test|handoff|unlock/i.test(name),
        ),
        [],
      );
      assert.equal(surfaceSet.has('markStartupComplete'), false);
      assert.equal(surfaceSet.has('noteAnchorHandoffFailure'), false);
      // The observation the startup-order regression reads is the only
      // underscore-prefixed member, and it is declared `@internal`.
      assert.deepEqual(
        [...surfaceSet].filter((name) => name.startsWith('_')),
        ['_getStartupStages', '_isStartupComplete'],
      );
      assert.equal(surfaceSet.has('appendRecord'), true);
      assert.equal(surfaceSet.has('assertPrivilegedOperationsAllowed'), true);
      assert.equal(surfaceSet.has('latchDegradedAuditFailure'), true);
    });
  });

  /* ======================================================================== *
   * 15. Anchor authority boundaries — stage 6 verifies, stage 7 reconciles
   *
   * The frozen startup order gives receipt verification (6) and spool
   * reconciliation (7) separate stages. Stage names prove nothing about
   * authority: an implementation that reconciles inside stage 6 satisfies any
   * assertion made about the order the names are entered in. Every assertion
   * below therefore reads the ARTIFACTS — active primary bytes, the checkpoint
   * artifact, the receipt ledger, the spool directory and its entries, the
   * recovery append and service readiness — and a failure is injected at
   * stage-7 ENTRY so that "no reconciliation happened before stage 7" is
   * observed rather than asserted.
   * ======================================================================== */

  describe('Anchor authority boundaries', () => {
    test('RC06-T6-REG-26: a missing spool entry (State C) is reconstructed by stage 7 alone, and a failure at stage-7 entry leaves the spool absent', async () => {
      const fixture = makeAuditConfig('reg26', { anchor: true });
      const checkpoint = await seedUnacknowledgedCheckpoint(fixture);
      const entryName = `${checkpoint.checkpointHash}.json`;

      // State C: the checkpoint artifact and the receipt ledger are exactly as
      // the store left them; only the spool artifact is gone.
      fs.rmSync(spoolDirOf(fixture.auditDir), { recursive: true, force: true });
      const before = artifactSnapshot(fixture.auditDir);
      assert.equal(before.spoolDirExists, false, 'the fixture must start from State C');
      assert.equal(before.receiptLines, 0, 'an unacknowledged checkpoint has no receipt');

      // (1) FAIL AT STAGE-7 ENTRY. `failStartupStage` raises before any line of
      //     stage 7 can run, so a spool directory — or a reconstructed entry —
      //     existing afterwards could only have been produced by stage 6 (or by
      //     the engine construction stage 6 performs). Neither may.
      const failingParts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: { failStartupStage: 'ANCHOR_SPOOL_RECONCILIATION' },
        },
      });
      await assert.rejects(() => failingParts.server.start());
      assert.equal(failingParts.server.transport, undefined);
      await failingParts.server.stop();

      assert.deepEqual(
        artifactSnapshot(fixture.auditDir),
        before,
        'no artifact class may change before stage 7 runs',
      );
      assert.equal(
        fs.existsSync(path.join(spoolDirOf(fixture.auditDir), entryName)),
        false,
        'stage 6 must not reconstruct a spool entry',
      );
      assert.equal(fs.existsSync(spoolDirOf(fixture.auditDir)), false);

      // (2) RUN NORMALLY. Stage 7 is the first and only place the spool is
      //     rebuilt — and the observation taken at stage-7 entry proves the
      //     reconstruction had not happened when stage 7 began.
      const observed = [];
      const parts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: {
            onStartupStage: (stage) =>
              observed.push({ stage, ...artifactSnapshot(fixture.auditDir) }),
          },
        },
      });
      await startServer(parts);

      assert.deepEqual(
        observed.map((entry) => entry.stage),
        [...AUDIT_STARTUP_STAGE_ORDER],
      );
      const at = (stage) => observed.find((entry) => entry.stage === stage);

      assert.equal(
        at('ANCHOR_RECEIPT_VERIFICATION').spoolDirExists,
        false,
        'stage 6 owns the receipt ledger, not the spool',
      );
      assert.deepEqual(at('ANCHOR_RECEIPT_VERIFICATION').spoolEntries, []);
      assert.equal(
        at('ANCHOR_SPOOL_RECONCILIATION').spoolDirExists,
        false,
        'stage-7 entry must precede every spool mutation',
      );
      assert.deepEqual(at('ANCHOR_SPOOL_RECONCILIATION').spoolEntries, []);
      assert.equal(
        at('TORN_TAIL_RECOVERY').spoolDirExists,
        true,
        'stage 7 must have reconstructed the spool directory',
      );
      assert.deepEqual(at('TORN_TAIL_RECOVERY').spoolEntries, [entryName]);
      assert.deepEqual(at('RUNTIME_CURSORS').spoolEntries, [entryName]);

      // The reconstruction is the canonical durable checkpoint the verified
      // checkpoint chain implies, byte for byte — not a placeholder.
      const reconstructed = JSON.parse(
        fs.readFileSync(path.join(spoolDirOf(fixture.auditDir), entryName), 'utf8'),
      );
      assert.deepEqual(reconstructed, checkpoint);

      // Nothing outside the spool was touched by the anchor stages.
      assert.equal(at('RUNTIME_CURSORS').checkpointBytes, before.checkpointBytes);
      assert.equal(at('RUNTIME_CURSORS').receiptLines, 0, 'no receipt may be invented');
      assert.equal(at('RUNTIME_CURSORS').activeLines, before.activeLines);
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');
    });

    test('RC06-T6-REG-27: a stale spool entry (State D) is removed by stage 7 alone, and a failure at stage-7 entry leaves it in place', async () => {
      const fixture = makeAuditConfig('reg27', { anchor: true });
      const checkpoint = await seedUnacknowledgedCheckpoint(fixture);
      const entryName = `${checkpoint.checkpointHash}.json`;
      const entryPath = path.join(spoolDirOf(fixture.auditDir), entryName);

      // State D: the checkpoint now HAS a valid, durable receipt — signed by the
      // key the store is pinned to, for the store's own id — so the spool entry
      // the store already holds is stale.
      const receiptPath = path.join(fixture.auditDir, ANCHOR_RECEIPT_FILENAME);
      fs.writeFileSync(
        receiptPath,
        serializeAnchorReceiptV1(
          signTestAnchorReceipt(
            {
              version: 1,
              storeId: readStoreId(fixture.auditDir),
              receiptId: crypto.randomUUID(),
              checkpointHash: checkpoint.checkpointHash,
              anchorTimestamp: '2026-09-21T00:00:00.000Z',
              anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
            },
            fixture.anchorMaterial.privateKey,
          ),
        ),
        { mode: 0o600 },
      );
      fs.chmodSync(receiptPath, 0o600);

      const before = artifactSnapshot(fixture.auditDir);
      assert.deepEqual(before.spoolEntries, [entryName], 'the fixture must start from State D');
      assert.equal(before.receiptLines, 1);

      // (1) FAIL AT STAGE-7 ENTRY: the stale entry must still be there, and no
      //     other artifact class may have moved either.
      const failingParts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: { failStartupStage: 'ANCHOR_SPOOL_RECONCILIATION' },
        },
      });
      await assert.rejects(() => failingParts.server.start());
      await failingParts.server.stop();

      assert.equal(
        fs.existsSync(entryPath),
        true,
        'no stage before 7 may remove a stale spool entry',
      );
      assert.deepEqual(
        artifactSnapshot(fixture.auditDir),
        before,
        'no artifact class may change before stage 7 runs',
      );

      // (2) RUN NORMALLY: stage 7 removes exactly the stale entry, and the
      //     receipt that made it stale is untouched.
      const observed = [];
      const parts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: {
            onStartupStage: (stage) =>
              observed.push({ stage, ...artifactSnapshot(fixture.auditDir) }),
          },
        },
      });
      await startServer(parts);

      const at = (stage) => observed.find((entry) => entry.stage === stage);
      assert.deepEqual(
        observed.map((entry) => entry.stage),
        [...AUDIT_STARTUP_STAGE_ORDER],
      );
      assert.deepEqual(
        at('ANCHOR_RECEIPT_VERIFICATION').spoolEntries,
        [entryName],
        'stage 6 verifies the receipt without removing the entry it makes stale',
      );
      assert.deepEqual(
        at('ANCHOR_SPOOL_RECONCILIATION').spoolEntries,
        [entryName],
        'stage-7 entry must precede the removal',
      );
      assert.deepEqual(
        at('TORN_TAIL_RECOVERY').spoolEntries,
        [],
        'stage 7 must have removed the stale entry',
      );
      assert.equal(fs.existsSync(entryPath), false);
      assert.equal(at('RUNTIME_CURSORS').receiptBytes, before.receiptBytes, 'no receipt discarded');
      assert.equal(at('RUNTIME_CURSORS').checkpointBytes, before.checkpointBytes);
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');
    });

    test('RC06-T6-REG-28: authority boundaries hold across every mutable artifact class, with a stage-7 failure proving no spool work happened first', async () => {
      const fixture = makeAuditConfig('reg28', { anchor: true });
      const danglingOperationId = crypto.randomUUID();

      // One damaged store carrying every artifact class startup touches: a
      // genuine unacknowledged checkpoint (spool entry, no receipt), a valid
      // receipt that makes that entry stale, and — in the ACTIVE segment, where
      // the torn-tail and dangling stages can see them — a torn tail and a
      // dangling STARTED record.
      const runtime = await createTestAuditRuntime(fixture.config, {
        anchorHooks: FAILING_ANCHOR_HOOKS,
      });
      await runtime.appendRecord(sampleRecordCandidate());
      await runtime.store.rotateNow('SIZE_THRESHOLD');
      await runtime.appendRecord(
        sampleRecordCandidate({
          invocation: {
            toolName: 'create_file',
            parametersRedacted: { path: 'dangling.txt' },
            payloadHash: 'e'.repeat(64),
          },
          lifecycle: { operationId: danglingOperationId, phase: 'STARTED' },
        }),
      );
      await closeRuntime(runtime);

      const checkpoints = readCheckpointRecords(fixture.auditDir);
      assert.equal(checkpoints.length, 1);
      const entryName = `${checkpoints[0].checkpointHash}.json`;
      const receiptPath = path.join(fixture.auditDir, ANCHOR_RECEIPT_FILENAME);
      fs.writeFileSync(
        receiptPath,
        serializeAnchorReceiptV1(
          signTestAnchorReceipt(
            {
              version: 1,
              storeId: readStoreId(fixture.auditDir),
              receiptId: crypto.randomUUID(),
              checkpointHash: checkpoints[0].checkpointHash,
              anchorTimestamp: '2026-09-21T00:00:00.000Z',
              anchorKeyFingerprint: fixture.anchorMaterial.fingerprint,
            },
            fixture.anchorMaterial.privateKey,
          ),
        ),
        { mode: 0o600 },
      );
      fs.chmodSync(receiptPath, 0o600);

      const tornBytes = Buffer.from('{"eventId":"torn-tail-fragment",', 'utf8');
      assert.ok(tornBytes.length < MAX_TORN_TAIL_BYTES);
      fs.appendFileSync(activeSegmentPath(fixture.auditDir), tornBytes);

      const damaged = artifactSnapshot(fixture.auditDir);
      assert.equal(damaged.activeLines, 1, 'the active segment holds the dangling STARTED record');
      assert.deepEqual(damaged.spoolEntries, [entryName]);
      assert.equal(damaged.receiptLines, 1);

      // (1) STAGE-7 FAILURE. Every artifact class — including the receipt ledger
      //     and the spool — must be byte-identical afterwards. If ANY stage-7
      //     authority had already run inside stage 6, the stale entry would be
      //     gone here.
      const failingParts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: { failStartupStage: 'ANCHOR_SPOOL_RECONCILIATION' },
        },
      });
      await assert.rejects(() => failingParts.server.start());
      await failingParts.server.stop();
      assert.deepEqual(
        artifactSnapshot(fixture.auditDir),
        damaged,
        'a failure at stage-7 entry must leave every artifact class untouched',
      );

      // (2) OBSERVED RUN. Every mutable artifact class is read at the entry of
      //     every stage, so each boundary is proven by the artifact that moves
      //     across it — and by which stage it has not moved at yet.
      const observed = [];
      const parts = buildServer(fixture, {
        runtimeOptions: {
          anchorHooks: FAILING_ANCHOR_HOOKS,
          hooks: {
            onStartupStage: (stage) =>
              observed.push({
                stage,
                ...artifactSnapshot(fixture.auditDir),
                transportBound: parts.server.transport !== undefined,
                runtimeBound: parts.server.auditRuntime !== undefined,
              }),
          },
        },
      });
      await startServer(parts);

      assert.deepEqual(
        observed.map((entry) => entry.stage),
        [...AUDIT_STARTUP_STAGE_ORDER],
      );
      const at = (stage) => observed.find((entry) => entry.stage === stage);

      // (a) The checkpoint artifact is never rewritten by any stage: the
      //     verified checkpoint chain is an input to startup, not an output.
      for (const entry of observed) {
        assert.equal(
          entry.checkpointBytes,
          damaged.checkpointBytes,
          `${entry.stage} rewrote the checkpoint artifact`,
        );
      }

      // (b) The receipt ledger is verified, never appended to: no receipt is
      //     written by any stage of startup.
      for (const entry of observed) {
        assert.equal(
          entry.receiptBytes,
          damaged.receiptBytes,
          `${entry.stage} wrote the receipt ledger`,
        );
      }

      // (c) The spool is the stage-7 artifact, and stage 7 is the FIRST stage
      //     that touches it: the stale entry is present through stage-7 entry
      //     and gone by stage-8 entry.
      for (const stage of AUDIT_STARTUP_STAGE_ORDER.slice(
        0,
        AUDIT_STARTUP_STAGE_ORDER.indexOf('ANCHOR_SPOOL_RECONCILIATION') + 1,
      )) {
        assert.deepEqual(at(stage).spoolEntries, [entryName], `${stage} must not touch the spool`);
      }
      assert.deepEqual(at('TORN_TAIL_RECOVERY').spoolEntries, []);

      // (d) The active primary segment is the torn-tail artifact: unchanged
      //     through stage-7 entry, truncated by stage 8, appended to exactly
      //     once by stage 10.
      for (const stage of AUDIT_STARTUP_STAGE_ORDER.slice(
        0,
        AUDIT_STARTUP_STAGE_ORDER.indexOf('TORN_TAIL_RECOVERY') + 1,
      )) {
        assert.equal(
          at(stage).activeBytes,
          damaged.activeBytes,
          `${stage} must not mutate the active segment`,
        );
      }
      assert.ok(at('DANGLING_OPERATION_DETECTION').activeBytes < damaged.activeBytes);
      assert.equal(at('DANGLING_OPERATION_DETECTION').activeLines, 1);
      assert.equal(at('RECOVERY_APPEND_DURABILITY').activeLines, 1);
      assert.equal(
        at('RUNTIME_CURSORS').activeLines,
        2,
        'stage 10 appends the recovery exactly once',
      );

      // (e) Service readiness: no transport and no runtime cursor is bound in
      //     ANY stage — readiness is not a stage artifact.
      for (const entry of observed) {
        assert.equal(entry.transportBound, false, `${entry.stage} bound a transport`);
        assert.equal(entry.runtimeBound, false, `${entry.stage} exposed the durable runtime`);
      }
      assert.equal(parts.server.transport !== undefined, true);
      assert.equal(parts.server.auditRuntime !== undefined, true);

      // The recovery append is the dangling operation's own evidence, and the
      // whole store — the archived first record included — re-verifies end to
      // end afterwards.
      const records = readActiveRecords(fixture.auditDir);
      assert.equal(records.length, 2);
      assert.equal(records[1].lifecycle.phase, 'RECOVERY_INDETERMINATE');
      assert.equal(records[1].lifecycle.operationId, danglingOperationId);
      assert.deepEqual(
        records.map((record) => record.sequenceNumber),
        [2, 3],
        'the active segment continues the archived history rather than restarting it',
      );
      const verification = await verifyRetainedPrimaryHistory(fixture.auditDir, EXPECTED_UID);
      assert.equal(verification.status, 'VERIFIED');
      assert.equal(verification.recordCount, 3);
      assert.equal(verification.terminalSequence, 3);
    });
  });

  /* ======================================================================== *
   * 16. One persistent primary sequence for every production emitter
   *
   * A durable tool chain with a separate in-memory gateway/approval/process
   * chain is two audit truths. These regressions read the STORE, never
   * `AuditLogger.getRecords()`: an emitter that still writes only to the
   * in-memory mirror produces records that are absent from disk, and an emitter
   * that writes to both without converging on one authority produces records
   * that are present twice.
   * ======================================================================== */

  describe('One persistent primary sequence', () => {
    test('RC06-T6-REG-29: gateway lifecycle evidence reaches the persistent primary chain exactly once, in the frozen safe projection', async () => {
      const fixture = makeAuditConfig('reg29');
      const parts = buildServer(fixture);
      await startServer(parts);

      const read = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(read.isError, undefined, 'the fixture read must succeed');

      const spkiPin = 'a'.repeat(64);
      const deviceId = 'b'.repeat(32);
      const mcpSessionId = 'c'.repeat(64);
      const sink = getGatewayAuditSink(parts.audit);
      sink.emit({ eventType: 'GATEWAY_STARTED', transportMode: 'remote' });
      sink.emit({
        eventType: 'AUTH_SUCCEEDED',
        clientId: 'agent-alpha',
        clientType: 'claude-code',
        deviceId,
        spkiPin,
        mcpSessionId,
        admissionLayer: 'A',
        transportMode: 'remote',
      });
      sink.emit({
        eventType: 'AUTH_FAILED',
        reason: 'SECRET_MISMATCH',
        admissionLayer: 'A',
        transportMode: 'remote',
      });
      sink.emit({
        eventType: 'RATE_LIMITED',
        reason: 'QUOTA_EXCEEDED',
        admissionLayer: 'C',
        transportMode: 'remote',
      });
      await sink.flush();

      const records = readActiveRecords(fixture.auditDir);
      const gatewayRecords = records.filter((record) => record.gateway !== undefined);
      assert.deepEqual(
        gatewayRecords.map((record) => record.gateway.eventType),
        ['GATEWAY_STARTED', 'AUTH_SUCCEEDED', 'AUTH_FAILED', 'RATE_LIMITED'],
        'the allow and denial transitions must all be durable, in emission order',
      );

      for (const type of ['GATEWAY_STARTED', 'AUTH_SUCCEEDED', 'AUTH_FAILED', 'RATE_LIMITED']) {
        assert.equal(
          gatewayRecords.filter((record) => record.gateway.eventType === type).length,
          1,
          `${type} must appear exactly once on disk`,
        );
      }

      // The frozen safe projection: only bounded, server-derived fields, and no
      // credential shape anywhere on the record.
      const allowedGatewayKeys = [
        'admissionLayer',
        'clientId',
        'clientType',
        'deviceId',
        'enrollmentId',
        'eventType',
        'mcpSessionId',
        'reason',
        'spkiPin',
        'transportMode',
      ];
      for (const record of gatewayRecords) {
        assert.deepEqual(
          Object.keys(record.gateway).filter((key) => !allowedGatewayKeys.includes(key)),
          [],
        );
        const raw = JSON.stringify(record);
        // No credential FIELD of any kind: the record has no place to put an
        // `Authorization` value, a session token, an enrollment secret or a
        // private key, so no such key may exist at any depth.
        const keys = [];
        const collectKeys = (value) => {
          if (value === null || typeof value !== 'object') return;
          if (Array.isArray(value)) {
            value.forEach(collectKeys);
            return;
          }
          for (const [key, child] of Object.entries(value)) {
            keys.push(key);
            collectKeys(child);
          }
        };
        collectKeys(record);
        assert.deepEqual(
          keys.filter((key) => /token|secret|password|authorization|credential|header/i.test(key)),
          [],
          'a gateway record must carry no credential field',
        );
        assert.equal(/bearer\s|BEGIN [A-Z ]*PRIVATE KEY/i.test(raw), false);
        // No host address of any form: the gateway records expose no network
        // location, so nothing in the record may parse as an IPv4 literal.
        assert.equal(
          /\b\d{1,3}(\.\d{1,3}){3}\b/.test(raw.replace(/T[0-9:.]+Z/g, '')),
          false,
          'a gateway record must carry no peer address',
        );
      }
      const succeeded = gatewayRecords.find((r) => r.gateway.eventType === 'AUTH_SUCCEEDED');
      const failed = gatewayRecords.find((r) => r.gateway.eventType === 'AUTH_FAILED');
      assert.equal(succeeded.policy.decision, 'ALLOW');
      assert.equal(failed.policy.decision, 'DENY');
      assert.equal(failed.execution.status, 'DENIED');
      assert.equal(succeeded.gateway.spkiPin, spkiPin);
      assert.equal(succeeded.gateway.deviceId, deviceId);
      assert.equal(succeeded.gateway.mcpSessionId, mcpSessionId);
      assert.equal(succeeded.actor.deviceId, deviceId);

      // ONE sequence: the gateway records share their numbering with the tool
      // lifecycle records rather than sitting on a chain of their own.
      assert.ok(records.some((record) => record.lifecycle?.phase === 'COMPLETED'));
      assert.ok(
        records.findIndex((record) => record.gateway !== undefined) >
          records.findIndex((record) => record.lifecycle?.phase === 'COMPLETED'),
        'gateway evidence must be appended after the tool evidence it followed',
      );
      await assertOneSequence(fixture, records);

      // The historical in-memory chain is a mirror of that ONE truth.
      assert.deepEqual(
        parts.audit.getRecords().map((record) => record.eventId),
        records.map((record) => record.eventId),
      );
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');
    });

    test('RC06-T6-REG-30: approval lifecycle evidence joins the same persistent sequence exactly once, with no token or review material on disk', async () => {
      const fixture = makeAuditConfig('reg30');
      const parts = buildServer(fixture);
      await startServer(parts);

      const sink = getGatewayAuditSink(parts.audit);
      sink.emit({ eventType: 'GATEWAY_STARTED', transportMode: 'remote' });
      await sink.flush();

      const target = path.join(workspaceDir, 'approval-evidence.json');
      const params = {
        path: 'approval-evidence.json',
        content: 'approved-evidence-content',
        workspaceId: 'ws',
      };
      const first = body(await parts.server.dispatchToolCall('create_file', { ...params }));
      assert.equal(first.code, 'APPROVAL_REQUIRED');
      const requestId = first.details.approvalRequestId;
      const grant = parts.approvals.approve(requestId);
      assert.equal(typeof grant.token, 'string');
      const second = body(
        await parts.server.dispatchToolCall('create_file', {
          ...params,
          _arcApproval: { requestId, token: grant.token },
        }),
      );
      assert.equal(second.isError, undefined, 'the approved mutation must execute');
      await parts.server.flushAudit();
      assert.equal(fs.readFileSync(target, 'utf8'), 'approved-evidence-content');

      const records = readActiveRecords(fixture.auditDir);
      const approvalRecords = records.filter((record) => record.approval?.eventType !== undefined);
      assert.deepEqual(
        approvalRecords.map((record) => record.approval.eventType).slice(0, 3),
        ['APPROVAL_REQUESTED', 'APPROVAL_GRANTED', 'APPROVAL_CONSUMED'],
        'the real approval lifecycle must be durable, in order',
      );
      const lifecyclePairs = approvalRecords.map(
        (record) => `${record.approval.requestId}:${record.approval.eventType}`,
      );
      assert.equal(
        new Set(lifecyclePairs).size,
        lifecyclePairs.length,
        'no approval lifecycle event may be recorded twice',
      );
      assert.deepEqual(
        [...new Set(approvalRecords.map((record) => record.approval.requestId))],
        [requestId],
      );

      // The bounded lifecycle projection carries no review material: only the
      // frozen field set, and no operator-supplied text.
      const allowedApprovalKeys = [
        'eventType',
        'operatorReasonProvided',
        'reasonCode',
        'requestId',
        'source',
        'state',
      ];
      for (const record of approvalRecords) {
        assert.deepEqual(
          Object.keys(record.approval).filter((key) => !allowedApprovalKeys.includes(key)),
          [],
        );
      }
      assert.deepEqual(
        Object.keys(approvalRecords[0].invocation.parametersRedacted).filter(
          (key) => !['eventType', 'requestId', 'state', 'workspaceId', 'reasonCode'].includes(key),
        ),
        [],
      );

      // The approved EXECUTION record is bound to the same request on the same
      // chain, so the tool evidence and the approval evidence cannot diverge.
      const executed = records.find((record) => record.lifecycle?.phase === 'COMPLETED');
      assert.equal(executed.policy.approvalId, requestId);
      assert.equal(executed.approval.requestId, requestId);
      assert.equal(executed.approval.state, 'CONSUMED');

      // No authorization material on disk: not the redemption token, not the
      // file content that was approved.
      const rawChain = readActiveRecordLines(fixture.auditDir).join('');
      assert.equal(rawChain.includes(grant.token), false, 'no approval token may reach the store');
      assert.equal(
        rawChain.includes('approved-evidence-content'),
        false,
        'no approved content may reach the store',
      );

      // Same global sequence as the tool and gateway evidence.
      assert.ok(records.some((record) => record.gateway !== undefined));
      assert.ok(records.some((record) => record.lifecycle?.phase === 'COMPLETED'));
      await assertOneSequence(fixture, records);
      assert.deepEqual(
        parts.audit.getRecords().map((record) => record.eventId),
        records.map((record) => record.eventId),
      );
      assert.equal((await auditHealth(parts)).persistence, 'ACTIVE');
    });

    test('RC06-T6-REG-31: a real process lifecycle record is committed to the same persistent chain exactly once', async () => {
      const fixture = makeAuditConfig('reg31');
      const processRegistry = new ProcessRegistry();
      const terminal = new ControlledProcessRunner(processRegistry, undefined, {
        resolveExecutable: () => '/usr/bin/ces-nonexistent-rc06-process-bin',
      });
      const parts = buildServer(fixture, { processRegistry, terminalSubsystem: terminal });
      await startServer(parts);
      assert.equal(parts.processRegistry, processRegistry);

      const result = body(
        await parts.server.dispatchToolCall(
          'run_command',
          { executable: 'node', args: ['--version'], runInBackground: true },
          { clientId: 'rc06-process-client', sessionId: 'rc06-process-session' },
        ),
      );
      assert.equal(result.state, 'FAILED', 'the fixture must produce a truthful failed spawn');
      await awaitProcessTerminalTransition(processRegistry, result.processId);
      await parts.server.flushAudit();

      const records = readActiveRecords(fixture.auditDir);
      const processRecords = records.filter((record) =>
        record.invocation.toolName.startsWith('PROCESS_'),
      );
      // The spawn attempt contributes exactly two lifecycle records — the
      // failure and the terminal close, each exactly once — and no other
      // process event of any kind.
      assert.deepEqual(
        processRecords.map((record) => record.invocation.toolName),
        ['PROCESS_SPAWN_FAILED', 'PROCESS_EXITED'],
        'the spawn attempt must be recorded exactly once, end to end',
      );
      const failure = processRecords[0];
      assert.equal(failure.policy.ruleId, 'process-lifecycle-event');
      assert.equal(failure.execution.status, 'ERROR');
      assert.equal(failure.invocation.parametersRedacted.processId, result.processId);
      for (const record of processRecords) {
        assert.equal(
          record.invocation.parametersRedacted.processId,
          result.processId,
          'every process record must belong to the process the tool reported',
        );
      }
      assert.equal(
        records.some((record) => record.invocation.toolName === 'PROCESS_SPAWN_SUCCEEDED'),
        false,
        'no success may be recorded for a spawn that never happened',
      );
      // The lifecycle records share the chain — and the hash chain — with the
      // tool invocation that produced them.
      assert.ok(records.some((record) => record.lifecycle !== undefined));
      await assertOneSequence(fixture, records);
      assert.deepEqual(
        parts.audit.getRecords().map((record) => record.eventId),
        records.map((record) => record.eventId),
      );
    });

    test('RC06-T6-REG-32: the combined tool, gateway, approval and process history survives a restart', async () => {
      const fixture = makeAuditConfig('reg32');
      const processRegistry = new ProcessRegistry();
      const terminal = new ControlledProcessRunner(processRegistry, undefined, {
        resolveExecutable: () => '/usr/bin/ces-nonexistent-rc06-restart-bin',
      });
      const first = buildServer(fixture, { processRegistry, terminalSubsystem: terminal });
      await startServer(first);

      await first.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' });
      const sink = getGatewayAuditSink(first.audit);
      sink.emit({ eventType: 'GATEWAY_STARTED', transportMode: 'remote' });
      sink.emit({
        eventType: 'AUTH_FAILED',
        reason: 'SECRET_MISMATCH',
        admissionLayer: 'A',
        transportMode: 'remote',
      });
      await sink.flush();
      const redeemed = await requestApproveRedeem(first, 'create_file', {
        path: 'restart-evidence.txt',
        content: 'durable-across-restart',
        workspaceId: 'ws',
      });
      assert.equal(redeemed.secondBody.isError, undefined);
      const processResult = body(
        await first.server.dispatchToolCall(
          'run_command',
          { executable: 'node', args: ['--version'], runInBackground: true },
          { clientId: 'rc06-restart-client', sessionId: 'rc06-restart-session' },
        ),
      );
      await awaitProcessTerminalTransition(processRegistry, processResult.processId);
      await first.server.flushAudit();

      const classify = (records) => ({
        toolLifecycle: records.filter((record) => record.lifecycle !== undefined).length,
        gateway: records.filter((record) => record.gateway !== undefined).length,
        approval: records.filter((record) => record.approval !== undefined).length,
        process: records.filter((record) => record.invocation.toolName.startsWith('PROCESS_'))
          .length,
      });
      const before = readActiveRecords(fixture.auditDir);
      const beforeCounts = classify(before);
      for (const [category, count] of Object.entries(beforeCounts)) {
        assert.ok(count > 0, `${category} evidence must exist before the restart`);
      }
      await assertOneSequence(fixture, before);

      await first.server.stop();
      startedServers.splice(startedServers.indexOf(first.server), 1);
      assert.equal(
        fs.existsSync(path.join(fixture.auditDir, LOCK_FILENAME)),
        false,
        'shutdown must release the single writer lock',
      );

      const second = buildServer(fixture);
      await startServer(second);
      assert.equal((await auditHealth(second)).persistence, 'ACTIVE');

      const after = readActiveRecords(fixture.auditDir);
      assert.ok(after.length >= before.length);
      assert.deepEqual(
        after.slice(0, before.length).map((record) => record.eventId),
        before.map((record) => record.eventId),
        'the recorded history must be intact and in order after the restart',
      );
      assert.deepEqual(
        classify(after.slice(0, before.length)),
        beforeCounts,
        'no evidence category may disappear on restart merely because it existed only in memory',
      );
      await assertOneSequence(fixture, after);
    });
  });

  /* ======================================================================== *
   * 17. Denied-refusal persistence failure
   *
   * A refused operation IS evidence, and a process that answers with the
   * ordinary policy or schema denial has told the caller the refusal is on the
   * record. When the durable append fails, that answer would be false — at the
   * exact moment the process became unfit to serve. The refusal the caller
   * receives must then be the audit-persistence failure, and the process must
   * be latched.
   * ======================================================================== */

  describe('Denied-refusal persistence failure', () => {
    /** Runs one denial whose durable DENIED append fails, and proves the contract. */
    async function assertDeniedPersistenceFailure(label, controlBody, call) {
      const fixture = makeAuditConfig(label);
      const parts = buildServer(fixture, {
        runtimeOptions: { hooks: { failAppendPhase: 'DENIED' } },
      });
      await startServer(parts);

      const linesBefore = readActiveRecordLines(fixture.auditDir).length;
      const readsBefore = parts.filesystem.reads;
      const mutationsBefore = parts.filesystem.mutations;
      const approvalsBefore = parts.approvals.listActive().length;

      const parsed = body(await call(parts));

      // (1) The response is the bounded audit-persistence failure — never the
      //     ordinary denial the same request produces on a healthy chain.
      assert.equal(parsed.code, 'INTERNAL_ERROR');
      assert.equal(parsed.category, 'INTERNAL');
      assert.equal(parsed.message, AUDIT_PERSISTENCE_FAILURE_MESSAGE);
      assert.notEqual(parsed.code, controlBody.code, 'the ordinary denial must not be the answer');
      assert.equal(
        /[/\\]|README|passwd|\.pem|store|spool|sequence|inode/i.test(parsed.message),
        false,
      );

      // (2) Zero privileged subsystem work and zero approval side effects: the
      //     failure happens at the denial boundary, before either.
      assert.equal(parts.filesystem.reads, readsBefore, 'zero subsystem reads');
      assert.equal(parts.filesystem.mutations, mutationsBefore, 'zero subsystem mutations');
      assert.equal(parts.approvals.listActive().length, approvalsBefore, 'zero approval requests');

      // (3) No durable DENIED record was invented, and nothing else was written.
      const records = readActiveRecords(fixture.auditDir);
      assert.equal(
        records.filter((record) => record.lifecycle?.phase === 'DENIED').length,
        0,
        'a failed append must not be papered over with an invented DENIED record',
      );
      assert.equal(readActiveRecordLines(fixture.auditDir).length, linesBefore);

      // (4) The runtime is latched degraded, and the latch is what answers the
      //     NEXT privileged request — before policy, before approval, before any
      //     subsystem.
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');
      const latchedReads = parts.filesystem.reads;
      const latchedApprovals = parts.approvals.listActive().length;
      const gated = body(
        await parts.server.dispatchToolCall('read_file', { path: 'README.md', workspaceId: 'ws' }),
      );
      assert.equal(gated.code, 'INTERNAL_ERROR');
      assert.equal(gated.message, AUDIT_GATE_REFUSAL_MESSAGE);
      assert.equal(parts.filesystem.reads, latchedReads);
      assert.equal(parts.approvals.listActive().length, latchedApprovals);
      const afterGate = body(
        await parts.server.dispatchToolCall('create_file', {
          path: 'never-created.txt',
          content: 'x',
          workspaceId: 'ws',
        }),
      );
      assert.equal(afterGate.code, 'INTERNAL_ERROR');
      assert.notEqual(afterGate.code, 'APPROVAL_REQUIRED');
      assert.equal(parts.filesystem.mutations, mutationsBefore);
      assert.equal(readActiveRecordLines(fixture.auditDir).length, linesBefore);
      assert.equal((await auditHealth(parts)).persistence, 'DEGRADED');
    }

    /** The SAME schema denial on a healthy chain, for the control comparison. */
    async function schemaDenialControl() {
      const fixture = makeAuditConfig('neg46-control');
      const parts = buildServer(fixture);
      await startServer(parts);
      const parsed = body(
        await parts.server.dispatchToolCall('read_file', {
          path: 'README.md',
          workspaceId: 'ws',
          // Above the frozen 1 MiB read ceiling: a schema denial decided before
          // any subsystem, policy or approval work.
          length: 2_000_000,
        }),
      );
      await parts.server.stop();
      startedServers.splice(startedServers.indexOf(parts.server), 1);
      return parsed;
    }

    test('RC06-T6-REG-33: a schema denial whose durable DENIED append fails answers with the bounded audit persistence failure', async () => {
      const control = await schemaDenialControl();
      assert.equal(control.code, 'PAYLOAD_TOO_LARGE');

      await assertDeniedPersistenceFailure('neg46', control, (parts) =>
        parts.server.dispatchToolCall('read_file', {
          path: 'README.md',
          workspaceId: 'ws',
          length: 2_000_000,
        }),
      );
    });

    test('RC06-T6-REG-34: a policy denial whose durable DENIED append fails answers with the bounded audit persistence failure', async () => {
      const controlFixture = makeAuditConfig('neg47-control');
      const controlParts = buildServer(controlFixture);
      await startServer(controlParts);
      const control = body(
        await controlParts.server.dispatchToolCall('read_file', {
          // A traversal target: the request fails the workspace boundary at the
          // policy layer, before any subsystem or approval work.
          path: '../neg47-outside.txt',
          workspaceId: 'ws',
        }),
      );
      await controlParts.server.stop();
      startedServers.splice(startedServers.indexOf(controlParts.server), 1);
      assert.equal(control.code, 'POLICY_DENIED');

      await assertDeniedPersistenceFailure('neg47', control, (parts) =>
        parts.server.dispatchToolCall('read_file', {
          path: '../neg47-outside.txt',
          workspaceId: 'ws',
        }),
      );
    });
  });
});
