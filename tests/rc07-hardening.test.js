/**
 * CesSpace ARC — RC-07 Task 8 Authoritative Test Suite
 *
 * Covers:
 * - Negative Controls: RC07-NEG-062 through RC07-NEG-075 (all 14 Task 8 negative controls)
 * - Positive Acceptance Flows: RC07-FLOW-16 through RC07-FLOW-19
 * - Security hardening, process lifecycle, secret scrubbing, transport parity,
 *   concurrency limits, client disconnect abortion, and orphan process cleanup.
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import * as https from 'node:https';
import { spawn, execFileSync } from 'node:child_process';

import { createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import {
  DeviceTrustStore,
  deriveSpkiPin,
  resolveActiveDeviceIdentity,
} from '../packages/auth/dist/index.js';
import {
  sweepOrphanProcesses,
  scrubOutput,
  getProcessStatStartTime,
} from '../packages/processes/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

function makeSafeActor() {
  return {
    clientId: 'test-client-task8',
    clientType: 'agent',
    sessionId: 'sess-task8-1',
    deviceId: 'dev-task8-1',
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

function makeHttpsRequest(
  port,
  pki,
  clientCertPem,
  clientKeyPem,
  method,
  reqPath,
  headers = {},
  body = undefined,
) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: reqPath,
        servername: 'localhost',
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: clientCertPem,
        key: clientKeyPem,
        rejectUnauthorized: true,
        headers: {
          Host: 'localhost:' + port,
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

describe('CesSpace ARC — RC-07 Task 8: Security Hardening & Acceptance Suite', () => {
  let tempRoot;
  let workspaceDir;
  let auditConfig;
  let pki;
  let trustStorePath;
  let trustStore;
  let clientCertPem;
  let clientKeyPem;
  let clientSpkiPin;
  let serverPort;
  let remoteServer;
  const safeActor = makeSafeActor();

  function createTestSession() {
    const identity = resolveActiveDeviceIdentity(trustStore, clientSpkiPin);
    assert.ok(identity, 'Identity must resolve for enrolled device');
    const sessionId = remoteServer.sessionManager.createSessionIdGenerator()();
    const issuance = remoteServer.sessionManager.issueSession({ sessionId, identity });
    return {
      sessionId,
      sessionToken: issuance.token,
    };
  }

  before(async () => {
    assert.equal(hasOpenssl(), true, 'TLS hardening tests require openssl');
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc07-task8-'));
    workspaceDir = path.join(tempRoot, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });

    // Initialize clean git repository in workspaceDir
    runGit(['init', '-b', 'main'], workspaceDir);
    runGit(['config', 'user.name', 'Alice Engineer'], workspaceDir);
    runGit(['config', 'user.email', 'alice@example.com'], workspaceDir);

    fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# RC-07 Hardening\nInitial content\n');
    fs.writeFileSync(
      path.join(workspaceDir, 'package.json'),
      JSON.stringify({ name: 'test-ws', type: 'module' }, null, 2),
    );
    fs.writeFileSync(
      path.join(workspaceDir, 'test.js'),
      "import test from 'node:test';\nimport assert from 'node:assert';\ntest('passing test', () => { assert.ok(true); });\n",
    );
    runGit(['add', '.'], workspaceDir);
    runGit(['commit', '-m', 'Initial commit'], workspaceDir);

    // Setup PKI and device trust store
    pki = createTestPki(path.join(tempRoot, 'pki'));
    clientCertPem = fs.readFileSync(pki.clientCertPath, 'utf8');
    clientKeyPem = fs.readFileSync(pki.clientKeyPath, 'utf8');
    clientSpkiPin = deriveSpkiPin(clientCertPem);

    trustStorePath = path.join(tempRoot, 'trusted-devices.json');
    trustStore = DeviceTrustStore.createEmpty();
    trustStore.enrollDevice({
      clientId: 'task8-agent',
      clientType: 'agent',
      pin: clientSpkiPin,
      displayLabel: 'Task 8 Test Client',
    });
    trustStore.saveToFile(trustStorePath);
    fs.chmodSync(trustStorePath, 0o600);

    // Find free port for remote server
    serverPort = await new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.once('error', reject);
      probe.listen({ host: '127.0.0.1', port: 0 }, () => {
        const bound = probe.address().port;
        probe.close(() => resolve(bound));
      });
    });

    auditConfig = createAuditConfig(tempRoot, 'rc07-task8-audit');
    remoteServer = createArcMcpServer({
      transport: 'remote',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      audit: auditConfig,
      remote: {
        bindHost: '127.0.0.1',
        port: serverPort,
        publicHostname: 'localhost',
        serverCertificatePath: pki.serverCertPath,
        privateKey: { kind: 'file', path: pki.serverKeyPath },
        clientCaPaths: [pki.trustedCaCertPath],
        trustStorePath,
      },
    });

    await remoteServer.start();
  });

  after(async () => {
    if (remoteServer) {
      await remoteServer.stop();
    }
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-062
  // ---------------------------------------------------------------------------
  test('RC07-NEG-062: Composite invocation over remote Streamable HTTP passes authenticated Layer C admission and spends exactly ONE token', async () => {
    const bridge = remoteServer.getRemoteExecutionBridge();
    assert.ok(bridge, 'Remote execution bridge must be active');

    const limiter = remoteServer.authenticatedRequestLimiter;
    let consumeCount = 0;
    const origConsume = limiter.consume.bind(limiter);
    limiter.consume = (key) => {
      consumeCount++;
      return origConsume(key);
    };

    try {
      const session = createTestSession();

      // Execute composite tool arc_repo_status via bridge
      const result = await bridge.executeRemoteToolCall({
        trustedSpkiPin: clientSpkiPin,
        presentedSessionId: session.sessionId,
        authorizationHeader: `Bearer ${session.sessionToken}`,
        toolName: 'arc_repo_status',
        parameters: {},
      });

      assert.equal(result.isError, undefined);
      assert.equal(consumeCount, 1, 'Admission must charge exactly ONE Layer C rate token');

      // Attempting to invoke with a fake or forged admission lease is rejected
      await assert.rejects(
        () =>
          bridge.executeRemoteToolCall({
            trustedSpkiPin: clientSpkiPin,
            toolName: 'arc_repo_status',
            parameters: {},
            admission: {
              session: {
                outcome: 'AUTHENTICATED',
                session: {
                  sessionId: 'forged',
                  sessionToken: 'token',
                  deviceId: 'fake',
                  clientId: 'fake',
                  clientType: 'agent',
                  expiresAt: Date.now() + 60000,
                  lastSeenAt: Date.now(),
                },
              },
              spkiPin: clientSpkiPin,
              release: () => {},
            },
          }),
        (err) => err.code === 'UNAUTHENTICATED',
      );
    } finally {
      limiter.consume = origConsume;
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-063
  // ---------------------------------------------------------------------------
  test('RC07-NEG-063: Remote client presents revoked session token to composite tool', async () => {
    const bridge = remoteServer.getRemoteExecutionBridge();
    assert.ok(bridge);

    // Create an authenticated session in sessionManager
    const session = createTestSession();

    // Explicitly revoke the session
    remoteServer.sessionManager.revokeSession(session.sessionId);

    // Call composite tool with revoked session token
    await assert.rejects(
      () =>
        bridge.executeRemoteToolCall({
          trustedSpkiPin: clientSpkiPin,
          presentedSessionId: session.sessionId,
          authorizationHeader: `Bearer ${session.sessionToken}`,
          toolName: 'arc_repo_status',
          parameters: {},
        }),
      (err) => {
        assert.equal(err.code, 'INVALID_SESSION_TOKEN');
        return true;
      },
    );
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-064
  // ---------------------------------------------------------------------------
  test('RC07-NEG-064: Remote client attempts to invoke composite tool without valid device enrollment', async () => {
    const bridge = remoteServer.getRemoteExecutionBridge();
    assert.ok(bridge);

    // Generate an unenrolled client pin
    const { publicKey: dummyKey } = crypto.generateKeyPairSync('ed25519');
    const unenrolledPin = deriveSpkiPin(dummyKey);

    await assert.rejects(
      () =>
        bridge.executeRemoteToolCall({
          trustedSpkiPin: unenrolledPin,
          toolName: 'arc_repo_status',
          parameters: {},
        }),
      (err) => {
        assert.equal(err.code, 'UNAUTHENTICATED');
        return true;
      },
    );
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-065
  // ---------------------------------------------------------------------------
  test('RC07-NEG-065: Discrepancy between stdio and remote response schema for any composite tool', async () => {
    const bridge = remoteServer.getRemoteExecutionBridge();

    // 1. Invoke arc_repo_status via stdio
    const stdioRes = await remoteServer.dispatchToolCall('arc_repo_status', {});
    assert.equal(stdioRes.isError, undefined);
    const stdioObj = parseResponse(stdioRes);

    // 2. Invoke arc_repo_status via remote bridge
    const session = createTestSession();
    const remoteRes = await bridge.executeRemoteToolCall({
      trustedSpkiPin: clientSpkiPin,
      presentedSessionId: session.sessionId,
      authorizationHeader: `Bearer ${session.sessionToken}`,
      toolName: 'arc_repo_status',
      parameters: {},
    });
    assert.equal(remoteRes.isError, undefined);
    const remoteObj = parseResponse(remoteRes);

    // Assert exact key parity
    const stdioKeys = Object.keys(stdioObj).sort();
    const remoteKeys = Object.keys(remoteObj).sort();
    assert.deepEqual(stdioKeys, remoteKeys, 'Stdio and remote response keys must be identical');

    // Assert type parity for each property
    for (const key of stdioKeys) {
      assert.equal(
        typeof stdioObj[key],
        typeof remoteObj[key],
        `Field '${key}' type mismatch between stdio and remote`,
      );
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-066
  // ---------------------------------------------------------------------------
  test('RC07-NEG-066: Direct child_process import/use detected in any RC-07 production composite implementation modules', async () => {
    const compositeFiles = [
      'apps/mcp-server/src/composite-framework.ts',
      'apps/mcp-server/src/internal/repo-worktree-status.ts',
      'apps/mcp-server/src/internal/review-diff.ts',
      'apps/mcp-server/src/internal/verify.ts',
      'apps/mcp-server/src/internal/test.ts',
      'apps/mcp-server/src/internal/ci-status.ts',
      'apps/mcp-server/src/internal/stage-evidence.ts',
    ];

    const childProcessImportPattern =
      /(?:from\s+['"]node:child_process['"]|from\s+['"]child_process['"]|require\(['"]node:child_process['"]\)|require\(['"]child_process['"]\))/;

    for (const file of compositeFiles) {
      const fullPath = path.resolve(file);
      assert.ok(fs.existsSync(fullPath), `File ${file} must exist`);
      const content = fs.readFileSync(fullPath, 'utf8');
      assert.equal(
        childProcessImportPattern.test(content),
        false,
        `RC-07 composite module ${file} must NEVER directly import child_process`,
      );
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-067
  // ---------------------------------------------------------------------------
  test('RC07-NEG-067: Direct fs / fs/promises import bypassing FilesystemSubsystem detected in RC-07 production implementation modules', async () => {
    const compositeFiles = [
      'apps/mcp-server/src/composite-framework.ts',
      'apps/mcp-server/src/internal/repo-worktree-status.ts',
      'apps/mcp-server/src/internal/review-diff.ts',
      'apps/mcp-server/src/internal/verify.ts',
      'apps/mcp-server/src/internal/test.ts',
      'apps/mcp-server/src/internal/ci-status.ts',
      'apps/mcp-server/src/internal/stage-evidence.ts',
    ];

    const fsImportPattern =
      /(?:from\s+['"]node:fs['"]|from\s+['"]node:fs\/promises['"]|from\s+['"]fs['"]|from\s+['"]fs\/promises['"])/;

    for (const file of compositeFiles) {
      const fullPath = path.resolve(file);
      assert.ok(fs.existsSync(fullPath), `File ${file} must exist`);
      const content = fs.readFileSync(fullPath, 'utf8');
      assert.equal(
        fsImportPattern.test(content),
        false,
        `RC-07 composite module ${file} must NEVER directly import node:fs or node:fs/promises`,
      );
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-068
  // ---------------------------------------------------------------------------
  test('RC07-NEG-068: RC-07 production execution path attempts to invoke a mutating Git operation', async () => {
    // Record HEAD commit and status before invoking tools
    const headBefore = runGit(['rev-parse', 'HEAD'], workspaceDir);
    const statusBefore = runGit(['status', '--porcelain'], workspaceDir);

    // Call all read-only RC-07 git tools
    await remoteServer.dispatchToolCall('arc_repo_status', {});
    await remoteServer.dispatchToolCall('arc_worktree_status', {});
    await remoteServer.dispatchToolCall('arc_review_diff', {});

    // Verify git state is completely untouched
    const headAfter = runGit(['rev-parse', 'HEAD'], workspaceDir);
    const statusAfter = runGit(['status', '--porcelain'], workspaceDir);
    assert.equal(headBefore, headAfter, 'HEAD commit must remain untouched');
    assert.equal(statusBefore, statusAfter, 'Git working tree status must remain untouched');

    // Static check in GitSubsystem: confirm only non-mutating subcommands are executed
    const gitSubsystemSrc = fs.readFileSync(path.resolve('packages/git/src/index.ts'), 'utf8');
    const mutatingCommands = [
      'commit',
      'push',
      'pull',
      'checkout',
      'switch',
      'reset',
      'clean',
      'merge',
      'rebase',
      'cherry-pick',
    ];
    for (const cmd of mutatingCommands) {
      const pattern = new RegExp(`['"]${cmd}['"]`);
      assert.equal(
        pattern.test(gitSubsystemSrc),
        false,
        `GitSubsystem must not invoke mutating subcommand '${cmd}'`,
      );
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-069
  // ---------------------------------------------------------------------------
  test('RC07-NEG-069: Failure of a child operation causes parent composite to hang indefinitely', async () => {
    // Create a test file that sleeps longer than 300ms
    const slowTestFile = path.join(workspaceDir, 'slow.test.js');
    fs.writeFileSync(
      slowTestFile,
      "import test from 'node:test';\ntest('slow', async () => { await new Promise(r => setTimeout(r, 3000)); });\n",
    );

    try {
      // Invoke arc_test to obtain approval request with maxDurationMs: 300
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'slow.test.js',
        maxDurationMs: 300,
      });
      assert.equal(reqRes.isError, true);
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const reqId = reqPayload.details.approvalRequestId;
      const app = remoteServer.approvalStateManager.approve(reqId);

      const startTime = Date.now();
      const res = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'slow.test.js',
        maxDurationMs: 300,
        _arcApproval: { requestId: reqId, token: app.token },
      });
      const duration = Date.now() - startTime;

      assert.ok(duration < 2500, `Execution should terminate promptly; took ${duration}ms`);
      assert.equal(res.isError, undefined);
      assert.ok(res.content && res.content.length > 0);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.status, 'TIMED_OUT');
    } finally {
      try {
        fs.unlinkSync(slowTestFile);
      } catch {
        /* ignore */
      }
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-070
  // ---------------------------------------------------------------------------
  test('RC07-NEG-070: Crash during composite execution leaves orphan process in host OS', async () => {
    const processStateDir = path.join(tempRoot, 'orphan-sweep-test-state');
    fs.mkdirSync(processStateDir, { recursive: true, mode: 0o700 });

    // 1. Spawn a genuine background child process
    const child = spawn('node', ['-e', 'setInterval(() => {}, 1000);'], {
      detached: true,
      stdio: 'ignore',
    });
    const orphanPid = child.pid;
    assert.ok(orphanPid, 'Child process must have PID');

    // Get real start time from /proc/[pid]/stat on Linux
    const realStartTime = getProcessStatStartTime(orphanPid);

    // Write durable state file for this genuine orphan
    const orphanState = {
      processId: 'arc-proc-orphan-001',
      pid: orphanPid,
      statStartTime: realStartTime,
      executable: 'node',
      startedAt: new Date().toISOString(),
      workspaceId: 'ws',
    };
    fs.writeFileSync(
      path.join(processStateDir, 'arc-proc-orphan-001.json'),
      JSON.stringify(orphanState, null, 2),
      { mode: 0o600 },
    );

    // 2. Write a state file for a simulated recycled PID (our own PID with mismatched start time)
    const recycledState = {
      processId: 'arc-proc-recycled-002',
      pid: process.pid,
      statStartTime: '99999999', // Impossible start time for our running process
      executable: 'node',
      startedAt: new Date().toISOString(),
      workspaceId: 'ws',
    };
    fs.writeFileSync(
      path.join(processStateDir, 'arc-proc-recycled-002.json'),
      JSON.stringify(recycledState, null, 2),
      { mode: 0o600 },
    );

    // Verify child is currently alive
    let childAliveBefore = false;
    try {
      process.kill(orphanPid, 0);
      childAliveBefore = true;
    } catch {
      /* ignore */
    }
    assert.equal(childAliveBefore, true, 'Orphan child must be alive before sweep');

    // 3. Run sweepOrphanProcesses
    const auditEvents = [];
    const report = await sweepOrphanProcesses(processStateDir, {
      gracePeriodMs: 200,
      auditSink: (event) => {
        auditEvents.push(event);
      },
    });

    // 4. Assert genuine orphan was swept
    assert.equal(report.swept.length, 1, 'Exactly one genuine orphan must be swept');
    assert.equal(report.swept[0].processId, 'arc-proc-orphan-001');
    assert.equal(report.swept[0].pid, orphanPid);

    // Assert recycled PID was skipped and left untouched
    assert.equal(report.skipped.length, 1, 'Recycled PID must be skipped');
    assert.equal(report.skipped[0].processId, 'arc-proc-recycled-002');
    assert.equal(report.skipped[0].pid, process.pid);

    // Verify genuine orphan child process is now dead
    let childAliveAfter;
    try {
      process.kill(orphanPid, 0);
      childAliveAfter = true;
    } catch {
      childAliveAfter = false;
    }
    assert.equal(childAliveAfter, false, 'Orphan child process must be dead after sweep');

    // Verify audit event was recorded
    assert.ok(auditEvents.length >= 1, 'Audit cleanup event must be emitted');
    assert.equal(auditEvents[0].eventType, 'PROCESS_ORPHAN_CLEANUP');

    // Verify state files were cleaned up
    assert.equal(fs.existsSync(path.join(processStateDir, 'arc-proc-orphan-001.json')), false);
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-071
  // ---------------------------------------------------------------------------
  test('RC07-NEG-071: Redaction pipeline fails to redact sensitive pattern in error message of composite tool', async () => {
    // Test secret scrubbing on error messages
    const simulatedGhp = 'ghp_' + '0123456789abcdef0123456789abcdef0123';
    const simulatedAkia = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const secretMsg = `Process failed with credential ${simulatedGhp} and key ${simulatedAkia}`;
    const scrubbed = scrubOutput(secretMsg);

    assert.equal(scrubbed.includes(simulatedGhp), false);
    assert.equal(scrubbed.includes(simulatedAkia), false);
    assert.ok(scrubbed.includes('[REDACTED_SECRET]'));

    // Execute arc_verify on suite
    const res = await remoteServer.dispatchToolCall('arc_verify', {
      suite: 'all',
    });
    // Response must not contain any sensitive pattern
    const text = res.content[0].text;
    const ghpPattern = new RegExp('ghp_' + '[a-zA-Z0-9]{36}');
    const akiaPattern = new RegExp('AKIA' + '[0-9A-Z]{16}');
    assert.equal(ghpPattern.test(text), false);
    assert.equal(akiaPattern.test(text), false);
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-072
  // ---------------------------------------------------------------------------
  test('RC07-NEG-072: Ambient credentials present in environment when composite tools execute', async () => {
    // Inject ambient sensitive environment variables into host process
    process.env.AWS_SECRET_ACCESS_KEY = 'secret-aws-key-ambient-test';
    process.env.GITHUB_TOKEN = 'ghp_dummytokenambienttest1234567890';
    process.env.GH_TOKEN = 'ghp_dummytokenambienttest1234567890';
    process.env.AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
    process.env.NPM_TOKEN = 'npm_dummytokenambienttest1234567890';

    try {
      // Execute a test via arc_test that checks process.env
      const envTestFile = path.join(workspaceDir, 'check-env.test.js');
      fs.writeFileSync(
        envTestFile,
        `import test from 'node:test';
import assert from 'node:assert';
test('env check', () => {
  assert.equal(process.env.AWS_SECRET_ACCESS_KEY, undefined, 'AWS_SECRET_ACCESS_KEY must be stripped');
  assert.equal(process.env.GITHUB_TOKEN, undefined, 'GITHUB_TOKEN must be stripped');
  assert.equal(process.env.GH_TOKEN, undefined, 'GH_TOKEN must be stripped');
  assert.equal(process.env.AWS_ACCESS_KEY_ID, undefined, 'AWS_ACCESS_KEY_ID must be stripped');
  assert.equal(process.env.NPM_TOKEN, undefined, 'NPM_TOKEN must be stripped');
  assert.equal(process.env.NODE_ENV, 'test');
});
`,
      );

      // Invoke arc_test to obtain approval request
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'check-env.test.js',
      });
      assert.equal(reqRes.isError, true);
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const reqId = reqPayload.details.approvalRequestId;
      const app = remoteServer.approvalStateManager.approve(reqId);

      const res = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'check-env.test.js',
        _arcApproval: { requestId: reqId, token: app.token },
      });
      assert.equal(res.isError, undefined);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.status, 'PASSED', 'Subprocess must observe stripped environment');
    } finally {
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.GITHUB_TOKEN;
      delete process.env.GH_TOKEN;
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.NPM_TOKEN;
      try {
        fs.unlinkSync(path.join(workspaceDir, 'check-env.test.js'));
      } catch {
        /* ignore */
      }
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-073
  // ---------------------------------------------------------------------------
  test('RC07-NEG-073: Concurrent execution of arc_verify and arc_test exceeds aggregate process pool limit', async () => {
    const registry = remoteServer.processRegistry;
    assert.ok(registry, 'ProcessRegistry must be available');

    // Register 4 mock running processes in the workspace to saturate maxPerWorkspaceRunning (4)
    const proc1 = registry.registerProcess({
      workspaceId: 'ws',
      actor: safeActor,
      executable: 'node',
      sanitizedArgs: ['-e', '1'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    const proc2 = registry.registerProcess({
      workspaceId: 'ws',
      actor: safeActor,
      executable: 'node',
      sanitizedArgs: ['-e', '2'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    const proc3 = registry.registerProcess({
      workspaceId: 'ws',
      actor: safeActor,
      executable: 'node',
      sanitizedArgs: ['-e', '3'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });
    const proc4 = registry.registerProcess({
      workspaceId: 'ws',
      actor: safeActor,
      executable: 'node',
      sanitizedArgs: ['-e', '4'],
      cwd: workspaceDir,
      startedAt: new Date().toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    try {
      // 5th attempt must fail with concurrency limit
      assert.throws(
        () => registry.checkConcurrency(safeActor.sessionId, 'ws'),
        (err) => {
          assert.equal(err.code, 'RESOURCE_EXHAUSTED');
          return true;
        },
      );

      // And executing arc_test when pool is saturated fails closed
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const reqId = reqPayload.details.approvalRequestId;
      const app = remoteServer.approvalStateManager.approve(reqId);

      const res = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'test.js',
        _arcApproval: { requestId: reqId, token: app.token },
      });
      assert.equal(res.isError, true);
      const parsed = JSON.parse(res.content[0].text);
      assert.ok(parsed.code === 'CONCURRENCY_EXCEEDED' || parsed.code === 'RESOURCE_EXHAUSTED');
    } finally {
      // Clean up mock processes
      registry.markCompleted(proc1.processId, 0, null);
      registry.markCompleted(proc2.processId, 0, null);
      registry.markCompleted(proc3.processId, 0, null);
      registry.markCompleted(proc4.processId, 0, null);
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-074
  // ---------------------------------------------------------------------------
  test('RC07-NEG-074: Client disconnects during streaming composite response', async () => {
    const controller = new AbortController();

    // Create a long test file
    const abortTestFile = path.join(workspaceDir, 'abort.test.js');
    fs.writeFileSync(
      abortTestFile,
      "import test from 'node:test';\ntest('sleep', async () => { await new Promise(r => setTimeout(r, 5000)); });\n",
    );

    try {
      // Obtain approval for arc_test
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'abort.test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const reqId = reqPayload.details.approvalRequestId;
      const app = remoteServer.approvalStateManager.approve(reqId);

      // Trigger abort shortly after launch
      setTimeout(() => {
        controller.abort();
      }, 150);

      const startTime = Date.now();
      const res = await remoteServer.executeAuthenticatedToolCall(
        makeSafeActor(),
        'arc_test',
        {
          testPath: 'abort.test.js',
          _arcApproval: { requestId: reqId, token: app.token },
        },
        { signal: controller.signal },
      );
      const duration = Date.now() - startTime;

      assert.ok(duration < 2500, `Aborted execution must return promptly; took ${duration}ms`);
      assert.ok(res.content && res.content.length > 0);
      const parsed = JSON.parse(res.content[0].text);
      assert.equal(parsed.status, 'TIMED_OUT');
    } finally {
      try {
        fs.unlinkSync(abortTestFile);
      } catch {
        /* ignore */
      }
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-075
  // ---------------------------------------------------------------------------
  test('RC07-NEG-075: Tampered or incorrect approval bearer token presented for composite execution', async () => {
    // Request approval for arc_test
    const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
      testPath: 'test.js',
    });
    assert.equal(reqRes.isError, true);
    const reqPayload = JSON.parse(reqRes.content[0].text);
    assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
    const requestId = reqPayload.details.approvalRequestId;

    // Operator approves request
    const approval = remoteServer.approvalStateManager.approve(requestId);

    // Tamper token by flipping last byte
    const tamperedToken =
      approval.token.slice(0, -2) + (approval.token.slice(-2) === 'aa' ? 'bb' : 'aa');

    // Attempt redemption with tampered token
    const execRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
      testPath: 'test.js',
      _arcApproval: {
        requestId,
        token: tamperedToken,
      },
    });

    assert.equal(execRes.isError, true);
    const body = JSON.parse(execRes.content[0].text);
    assert.equal(body.code, 'APPROVAL_REJECTED');

    // Verify zero project processes spawned
    const activeProcesses = remoteServer.processRegistry.countRunning();
    assert.equal(activeProcesses, 0, 'Zero project processes may spawn on token mismatch');
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-16
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-16: Remote Streamable HTTP Parity', async () => {
    // 1. Initialize session over real TLS 1.3
    const initRes = await makeHttpsRequest(
      serverPort,
      pki,
      clientCertPem,
      clientKeyPem,
      'POST',
      '/mcp',
      {},
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'task8-client', version: '1.0' },
        },
      }),
    );
    assert.equal(initRes.statusCode, 200);
    const sessionId = initRes.headers['mcp-session-id'];
    const sessionToken = initRes.headers['arc-session-token'];
    assert.ok(sessionId && sessionToken);

    // 2. Call arc_repo_status over real remote HTTPS / TLS 1.3
    const callRes = await makeHttpsRequest(
      serverPort,
      pki,
      clientCertPem,
      clientKeyPem,
      'POST',
      '/mcp',
      {
        'Mcp-Session-Id': sessionId,
        Authorization: `Bearer ${sessionToken}`,
      },
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'arc_repo_status',
          arguments: {},
        },
      }),
    );
    assert.equal(callRes.statusCode, 200);
    const dataLine = callRes.body.split('\n').find((l) => l.startsWith('data:'));
    assert.ok(dataLine);
    const parsedPayload = JSON.parse(dataLine.slice(5).trim());
    const toolContent = JSON.parse(parsedPayload.result.content[0].text);
    assert.equal(toolContent.branch, 'main');
    assert.equal(toolContent.isClean, true);
    assert.ok(toolContent.headCommit && toolContent.headCommit.hash.length >= 7);
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-17
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-17: Stdio Transport Parity', async () => {
    const stdioAuditConfig = createAuditConfig(tempRoot, 'rc07-stdio-parity-audit');
    const stdioServer = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      audit: stdioAuditConfig,
    });
    await stdioServer.start();

    try {
      const toolList = stdioServer.getRegisteredTools();
      assert.equal(toolList.length, 25, 'Must report exactly 25 tools');

      const res = await stdioServer.dispatchToolCall('arc_repo_status', {});
      assert.equal(res.isError, undefined);
      const parsed = parseResponse(res);
      assert.equal(parsed.branch, 'main');
      assert.equal(parsed.isClean, true);
    } finally {
      await stdioServer.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-18
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-18: Process Interruption and SIGKILL Escalation', async () => {
    const stubbornScriptPath = path.join(workspaceDir, 'stubborn.test.js');
    fs.writeFileSync(
      stubbornScriptPath,
      `import { spawn } from 'node:child_process';
import test from 'node:test';

test('stubborn test requiring SIGKILL escalation', async () => {
  const childScript = \`
    const fs = require('node:fs');
    process.on('SIGTERM', () => {});
    fs.writeSync(1, 'STUBBORN_PID:' + process.pid + '\\\\n');
    setInterval(() => {}, 10000);
  \`;
  const child = spawn(process.execPath, ['-e', childScript], {
    stdio: ['ignore', 'inherit', 'ignore'],
  });
  await new Promise((resolve) => setTimeout(resolve, 10000));
});
`,
    );

    // Register lifecycle sink on remoteServer.processRegistry to truthfully observe lifecycle events
    const lifecycleEvents = [];
    const procRegistry = remoteServer.processRegistry;
    procRegistry.registerLifecycleSink({
      onProcessEvent(evt) {
        lifecycleEvents.push(evt);
      },
    });

    try {
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'stubborn.test.js',
        maxDurationMs: 1200,
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');

      const approval = remoteServer.approvalStateManager.approve(
        reqPayload.details.approvalRequestId,
      );

      const execRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'stubborn.test.js',
        maxDurationMs: 1200,
        _arcApproval: {
          requestId: reqPayload.details.approvalRequestId,
          token: approval.token,
        },
      });

      assert.equal(execRes.isError, undefined);
      const body = JSON.parse(execRes.content[0].text);
      assert.equal(body.status, 'TIMED_OUT');
      assert.ok(body.processId);

      const match = /STUBBORN_PID:(\d+)/.exec(body.outputExcerpt);
      assert.ok(match, 'Must capture stubborn process PID from output excerpt');
      const stubbornPid = parseInt(match[1], 10);
      assert.ok(Number.isInteger(stubbornPid) && stubbornPid > 0);

      // Wait beyond the 1000ms SIGKILL escalation grace period
      await new Promise((resolve) => setTimeout(resolve, 1300));

      let stubbornAlive = true;
      try {
        process.kill(stubbornPid, 0);
      } catch (err) {
        if (err && err.code === 'ESRCH') {
          stubbornAlive = false;
        }
      }
      assert.equal(
        stubbornAlive,
        false,
        `Stubborn child PID ${stubbornPid} must be reaped by SIGKILL escalation`,
      );

      const opEvents = lifecycleEvents.filter((e) => e.processId === body.processId);
      const eventTypes = opEvents.map((e) => e.eventType);
      assert.ok(
        eventTypes.includes('PROCESS_TIMEOUT'),
        `Lifecycle events must contain PROCESS_TIMEOUT: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.includes('PROCESS_SIGTERM_SENT'),
        `Lifecycle events must contain PROCESS_SIGTERM_SENT: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.includes('PROCESS_SIGKILL_ESCALATED'),
        `Lifecycle events must contain PROCESS_SIGKILL_ESCALATED: ${JSON.stringify(eventTypes)}`,
      );
    } finally {
      try {
        fs.unlinkSync(stubbornScriptPath);
      } catch {
        /* ignore */
      }
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-19
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-19: High-Concurrency Isolation', async () => {
    // Run multiple read-only composite tools concurrently across:
    // arc_repo_status, arc_worktree_status, arc_review_diff, arc_ci_status, arc_stage_evidence
    const [repoRes, worktreeRes, diffRes, ciRes, stageRes] = await Promise.all([
      remoteServer.dispatchToolCall('arc_repo_status', {}),
      remoteServer.dispatchToolCall('arc_worktree_status', {}),
      remoteServer.dispatchToolCall('arc_review_diff', {}),
      remoteServer.dispatchToolCall('arc_ci_status', {}),
      remoteServer.dispatchToolCall('arc_stage_evidence', { targetStage: 'RC-06' }),
    ]);

    assert.equal(repoRes.isError, undefined);
    assert.equal(worktreeRes.isError, undefined);
    assert.equal(diffRes.isError, undefined);
    assert.equal(ciRes.isError, undefined);
    assert.ok(stageRes.content && stageRes.content.length > 0);

    const repoObj = parseResponse(repoRes);
    const worktreeObj = parseResponse(worktreeRes);
    const diffObj = parseResponse(diffRes);
    const ciObj = parseResponse(ciRes);

    assert.equal(repoObj.branch, 'main');
    assert.equal(worktreeObj.isWorktree, false);
    assert.equal(worktreeObj.branch, 'main');
    assert.ok(diffObj.diff !== undefined);
    assert.ok(Array.isArray(ciObj.workflowsFound));
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-20
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-20: Release Candidate Verification Integrity', async () => {
    const scriptPath = path.resolve('scripts/verify-rc07.sh');
    assert.ok(fs.existsSync(scriptPath), 'verify-rc07.sh must exist');

    // Check executable bit
    fs.accessSync(scriptPath, fs.constants.X_OK);

    const scriptContent = fs.readFileSync(scriptPath, 'utf8');

    // Check required header & configuration
    assert.ok(scriptContent.includes('set -euo pipefail'), 'Must enforce strict error handling');
    assert.ok(scriptContent.includes('FEATURE_BRANCH="feat/rc-07-engineering-aware-tools"'));
    assert.ok(scriptContent.includes('EXPECTED_VERSION="0.7.0-rc07"'));
    assert.ok(scriptContent.includes('EXPECTED_STAGE="RC-07"'));

    // Check all 25 gates are present
    for (let g = 1; g <= 25; g++) {
      assert.ok(scriptContent.includes(`Gate ${g}:`), `verify-rc07.sh must contain Gate ${g}`);
    }

    // Check zero error-masking fallback
    assert.equal(
      scriptContent.includes('||' + ' true'),
      false,
      'verify-rc07.sh must not contain error-masking fallbacks',
    );

    // Verify exactly 25 tools advertised on server
    const tools = remoteServer.getRegisteredTools();
    assert.equal(tools.length, 25, 'Expected exactly 25 tools advertised');

    const advertisedNames = new Set(tools.map((t) => t.name));
    const expectedRc07Tools = [
      'arc_repo_status',
      'arc_worktree_status',
      'arc_review_diff',
      'arc_verify',
      'arc_test',
      'arc_ci_status',
      'arc_stage_evidence',
    ];
    for (const toolName of expectedRc07Tools) {
      assert.ok(advertisedNames.has(toolName), `Tool ${toolName} must be advertised`);
    }

    // Verify deterministic execution registry contains exactly 5 entries
    const { createProductionDeterministicRegistry } =
      await import('../apps/mcp-server/dist/composite-framework.js');
    const registry = createProductionDeterministicRegistry();
    const deterministicKeys = registry.listEntryIds();
    assert.equal(
      deterministicKeys.length,
      5,
      'Deterministic registry must contain exactly 5 entries',
    );
    const expectedIdentities = [
      'verify-format-v1',
      'verify-lint-v1',
      'verify-typecheck-v1',
      'verify-test-v1',
      'arc-test-node-v1',
    ];
    for (const id of expectedIdentities) {
      assert.ok(deterministicKeys.includes(id), `Missing identity: ${id}`);
    }
  });
});
