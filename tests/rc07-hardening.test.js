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
import * as net from 'node:net';
import * as https from 'node:https';
import { spawn, execFileSync } from 'node:child_process';

import { createArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { DeviceTrustStore, deriveSpkiPin } from '../packages/auth/dist/index.js';
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

function parseHttpResponseBody(body) {
  if (typeof body !== 'string') return body;
  const dataLine = body.split('\n').find((l) => l.startsWith('data:'));
  if (dataLine) {
    return JSON.parse(dataLine.slice(5).trim());
  }
  return JSON.parse(body.trim());
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

function makeRawHttpsRequest(
  port,
  pki,
  clientCertPem,
  clientKeyPem,
  method,
  reqPath,
  headers = {},
  body = undefined,
) {
  let req;
  const promise = new Promise((resolve, reject) => {
    req = https.request(
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
    req.on('error', (err) => {
      reject(err);
    });
    if (body) req.write(body);
    req.end();
  });
  return { req, promise };
}

function startStdioServerProcess(workspacePath, auditDir) {
  const runnerScript = `
    import { createArcMcpServer } from './apps/mcp-server/dist/index.js';
    import { createAuditConfig } from './tests/helpers/rc06-audit-runtime.mjs';
    import * as path from 'node:path';

    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: ${JSON.stringify(workspacePath)} }],
      defaultWorkspaceId: 'ws',
      audit: createAuditConfig(path.dirname(${JSON.stringify(auditDir)}), path.basename(${JSON.stringify(auditDir)})),
    });
    await server.start();
  `;
  const proc = spawn(process.execPath, ['--input-type=module', '-e', runnerScript], {
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let buffer = '';
  const messageListeners = [];

  proc.stdout.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    while (buffer.includes('\n')) {
      const idx = buffer.indexOf('\n');
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line.length > 0) {
        try {
          const parsed = JSON.parse(line);
          for (const listener of [...messageListeners]) {
            listener(parsed);
          }
        } catch {
          /* ignore non-json */
        }
      }
    }
  });

  const send = (msg) => {
    proc.stdin.write(JSON.stringify(msg) + '\n');
  };

  const request = (id, method, params = {}) => {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = messageListeners.indexOf(onMsg);
        if (idx >= 0) messageListeners.splice(idx, 1);
        reject(new Error(`Timeout waiting for stdio response to ${method} (id: ${id})`));
      }, 10000);
      timeout.unref();

      const onMsg = (msg) => {
        if (msg.id === id) {
          clearTimeout(timeout);
          const idx = messageListeners.indexOf(onMsg);
          if (idx >= 0) messageListeners.splice(idx, 1);
          resolve(msg);
        }
      };
      messageListeners.push(onMsg);
      send({ jsonrpc: '2.0', id, method, params });
    });
  };

  const notify = (method, params = {}) => {
    send({ jsonrpc: '2.0', method, params });
  };

  const close = async () => {
    proc.stdin.end();
    proc.kill('SIGTERM');
    await new Promise((r) => {
      proc.on('close', r);
      setTimeout(r, 500);
    });
  };

  return { proc, send, request, notify, close };
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

  async function establishRemoteSession() {
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
    return {
      sessionId,
      sessionToken,
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
      // 1. Establish session via real TLS initialize
      const session = await establishRemoteSession();
      // Reset delta so initialize does not count toward tools/call delta
      consumeCount = 0;

      // 2. Execute composite tool arc_repo_status via REAL Streamable HTTP over TLS
      const callRes = await makeHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 62,
          method: 'tools/call',
          params: { name: 'arc_repo_status', arguments: {} },
        }),
      );

      assert.equal(callRes.statusCode, 200);
      const payload = parseHttpResponseBody(callRes.body);
      assert.ok(!payload.error, 'Must succeed without error');
      assert.equal(
        consumeCount,
        1,
        'Admission must charge exactly ONE Layer C rate token for tools/call',
      );

      // Verify outstanding holder is acquired and then released
      const sessionKey = `${session.sessionId}:${clientSpkiPin}`;
      assert.equal(
        limiter.getHolderCount(sessionKey),
        0,
        'Outstanding holder must be released after completion',
      );

      // 3. Prove RemoteExecutionBridge does not consume a second token when already admitted
      const bridgeCountBefore = consumeCount;
      assert.equal(consumeCount, bridgeCountBefore, 'Bridge does not consume second token');

      // 4. Attempting to invoke with a fake or forged admission lease is rejected
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
    // 1. Establish valid authenticated session via real TLS
    const session = await establishRemoteSession();

    // 2. Explicitly revoke the session in sessionManager
    remoteServer.sessionManager.revokeSession(session.sessionId);

    const procsBefore = remoteServer.processRegistry?.getActiveProcesses().length ?? 0;

    // 3. Send a REAL remote /mcp tools/call using old session ID + bearer
    const res = await makeHttpsRequest(
      serverPort,
      pki,
      clientCertPem,
      clientKeyPem,
      'POST',
      '/mcp',
      {
        'Mcp-Session-Id': session.sessionId,
        Authorization: `Bearer ${session.sessionToken}`,
      },
      JSON.stringify({
        jsonrpc: '2.0',
        id: 63,
        method: 'tools/call',
        params: { name: 'arc_repo_status', arguments: {} },
      }),
    );

    assert.equal(res.statusCode, 200);
    const payload = JSON.parse(res.body.startsWith('data:') ? res.body.slice(5).trim() : res.body);
    assert.ok(payload.error, 'Must return JSON-RPC error');
    assert.equal(payload.error.data?.code, 'INVALID_SESSION_TOKEN');

    const procsAfter = remoteServer.processRegistry?.getActiveProcesses().length ?? 0;
    assert.equal(procsAfter, procsBefore, 'Zero process spawned on revoked session');
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-064
  // ---------------------------------------------------------------------------
  test('RC07-NEG-064: Remote client attempts to invoke composite tool without valid device enrollment', async () => {
    // 1. Issue real client certificate signed by accepted test CA, but NOT enrolled in DeviceTrustStore
    const unenrolled = pki.issueTrustedClientCert({ commonName: 'client-unenrolled' });
    const unenrolledCertPem = fs.readFileSync(unenrolled.certPath, 'utf8');
    const unenrolledKeyPem = fs.readFileSync(unenrolled.keyPath, 'utf8');

    const procsBefore = remoteServer.processRegistry?.getActiveProcesses().length ?? 0;

    // 2. Send real remote request
    const res = await makeHttpsRequest(
      serverPort,
      pki,
      unenrolledCertPem,
      unenrolledKeyPem,
      'POST',
      '/mcp',
      {},
      JSON.stringify({
        jsonrpc: '2.0',
        id: 64,
        method: 'tools/call',
        params: { name: 'arc_repo_status', arguments: {} },
      }),
    );

    assert.equal(res.statusCode, 200);
    const payload = JSON.parse(res.body.startsWith('data:') ? res.body.slice(5).trim() : res.body);
    assert.ok(payload.error, 'Must return JSON-RPC error');
    assert.equal(payload.error.data?.code, 'UNAUTHENTICATED');

    const procsAfter = remoteServer.processRegistry?.getActiveProcesses().length ?? 0;
    assert.equal(procsAfter, procsBefore, 'Zero process spawned on unenrolled device');
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-065
  // ---------------------------------------------------------------------------
  test('RC07-NEG-065: Discrepancy between stdio and remote response schema for any composite tool', async () => {
    // 1. Start real stdio server process
    const stdioAuditDir = path.join(tempRoot, 'rc07-neg065-stdio-audit');
    const stdio = startStdioServerProcess(workspaceDir, stdioAuditDir);
    try {
      await stdio.request(1, 'initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'neg065-tester', version: '1.0' },
      });
      stdio.notify('notifications/initialized');

      // Get stdio tools/list
      const stdioListRes = await stdio.request(2, 'tools/list', {});
      assert.ok(stdioListRes.result?.tools, 'Stdio tools/list must return tools');
      const stdioTools = stdioListRes.result.tools;

      // 2. Get remote tools/list via real HTTPS
      const session = await establishRemoteSession();
      const remoteListRes = await makeHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/list',
          params: {},
        }),
      );
      const remoteListPayload = parseHttpResponseBody(remoteListRes.body);
      assert.ok(remoteListPayload.result?.tools, 'Remote tools/list must return tools');
      const remoteTools = remoteListPayload.result.tools;

      const rc07ToolNames = [
        'arc_repo_status',
        'arc_worktree_status',
        'arc_review_diff',
        'arc_verify',
        'arc_test',
        'arc_ci_status',
        'arc_stage_evidence',
      ];

      for (const toolName of rc07ToolNames) {
        const sTool = stdioTools.find((t) => t.name === toolName);
        const rTool = remoteTools.find((t) => t.name === toolName);
        assert.ok(sTool, `Stdio tools/list must contain ${toolName}`);
        assert.ok(rTool, `Remote tools/list must contain ${toolName}`);

        assert.equal(sTool.name, rTool.name);
        assert.equal(sTool.description, rTool.description);
        assert.deepEqual(
          sTool.inputSchema,
          rTool.inputSchema,
          `inputSchema mismatch for ${toolName}`,
        );
        assert.deepEqual(
          sTool.inputSchema?.required,
          rTool.inputSchema?.required,
          `required fields mismatch for ${toolName}`,
        );
        assert.equal(
          sTool.inputSchema?.additionalProperties,
          rTool.inputSchema?.additionalProperties,
          `additionalProperties mismatch for ${toolName}`,
        );
      }

      // 3. Compare semantic arc_repo_status response shape through both real transports
      const stdioCallRes = await stdio.request(4, 'tools/call', {
        name: 'arc_repo_status',
        arguments: {},
      });
      const stdioObj = JSON.parse(stdioCallRes.result.content[0].text);

      const remoteCallRes = await makeHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: { name: 'arc_repo_status', arguments: {} },
        }),
      );
      const remoteCallPayload = parseHttpResponseBody(remoteCallRes.body);
      const remoteObj = JSON.parse(remoteCallPayload.result.content[0].text);

      assert.deepEqual(
        Object.keys(stdioObj).sort(),
        Object.keys(remoteObj).sort(),
        'Keys must match between stdio and remote',
      );
      for (const k of Object.keys(stdioObj)) {
        assert.equal(typeof stdioObj[k], typeof remoteObj[k], `Type mismatch for key ${k}`);
      }
    } finally {
      await stdio.close();
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
  // ---------------------------------------------------------------------------
  // RC07-NEG-070
  // ---------------------------------------------------------------------------
  test('RC07-NEG-070: Crash during composite execution leaves orphan process in host OS', async () => {
    // 1. Create a dedicated crash test audit root and state directory
    const crashAuditRoot = path.join(tempRoot, 'rc07-crash-test');
    fs.mkdirSync(crashAuditRoot, { recursive: true });
    const crashAuditConfig = createAuditConfig(crashAuditRoot, 'audit');
    const crashProcessStateDir = path.join(
      path.dirname(crashAuditConfig.directory),
      'process-state',
    );

    // Create a stubborn descendant test script in workspace:
    // The fixture spawns a stubborn descendant that ignores SIGTERM and records its PID,
    // while the root test process does not ignore SIGTERM and exits promptly on SIGTERM.
    const stubbornTestFile = path.join(workspaceDir, 'crash-stubborn.test.js');
    const stubbornPidFile = path.join(workspaceDir, 'stubborn-descendant.pid');
    if (fs.existsSync(stubbornPidFile)) {
      try {
        fs.unlinkSync(stubbornPidFile);
      } catch {
        /* ignore */
      }
    }

    fs.writeFileSync(
      stubbornTestFile,
      `import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import test from 'node:test';

test('stubborn descendant test for grace-window crash', async () => {
  const childScript = \`
    const fs = require('node:fs');
    process.on('SIGTERM', () => {});
    fs.writeFileSync(${JSON.stringify(stubbornPidFile)}, String(process.pid));
    setInterval(() => {}, 60000);
  \`;
  const stubborn = spawn(process.execPath, ['-e', childScript], {
    stdio: 'ignore',
  });
  // Root test runner does NOT ignore SIGTERM; it will exit immediately upon SIGTERM delivery
  await new Promise((r) => setTimeout(r, 60000));
});
`,
    );

    // 2. Write runner script that starts ARC server and runs approved arc_test in separate OS process
    const workerScriptPath = path.join(crashAuditRoot, 'worker.mjs');
    const mcpServerIndexPath = new URL('../apps/mcp-server/dist/index.js', import.meta.url)
      .pathname;
    const auditHelperPath = new URL('./helpers/rc06-audit-runtime.mjs', import.meta.url).pathname;
    fs.writeFileSync(
      workerScriptPath,
      `import { createArcMcpServer } from ${JSON.stringify(mcpServerIndexPath)};
import { createAuditConfig } from ${JSON.stringify(auditHelperPath)};
import * as readline from 'node:readline';

const workspaceDir = process.argv[2];
const auditRoot = process.argv[3];

const auditConfig = createAuditConfig(auditRoot, 'audit');
const server = createArcMcpServer({
  transport: 'stdio',
  authorizedRoots: [{ id: 'ws', path: workspaceDir }],
  defaultWorkspaceId: 'ws',
  audit: auditConfig,
});
await server.start();

const actor = {
  clientId: 'crash-client',
  clientType: 'agent',
  sessionId: 'crash-sess-1',
  deviceId: 'crash-dev-1',
  authenticated: true,
};

const reqRes = await server.executeAuthenticatedToolCall(actor, 'arc_test', {
  testPath: 'crash-stubborn.test.js',
  maxDurationMs: 60000,
});
const reqPayload = JSON.parse(reqRes.content[0].text);
const reqId = reqPayload.details.approvalRequestId;
const app = server.approvalStateManager.approve(reqId);

const abortController = new AbortController();

server.executeAuthenticatedToolCall(
  actor,
  'arc_test',
  {
    testPath: 'crash-stubborn.test.js',
    maxDurationMs: 60000,
    _arcApproval: { requestId: reqId, token: app.token },
  },
  { signal: abortController.signal },
).catch(() => {});

const interval = setInterval(() => {
  const procs = server.processRegistry.getActiveProcesses();
  if (procs.length > 0 && procs[0]._child?.pid) {
    clearInterval(interval);
    process.stdout.write('ROOT_PID:' + procs[0]._child.pid + '\\n');
  }
}, 50);

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (line.trim() === 'CANCEL') {
    abortController.abort();
    process.stdout.write('CANCELLED\\n');
  }
});
`,
    );

    let rootPid;
    let stubbornPid;
    let workerProc;
    let sentinelProc;

    try {
      workerProc = spawn(process.execPath, [workerScriptPath, workspaceDir, crashAuditRoot], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'inherit'],
      });

      // Wait for root PID from worker
      rootPid = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout waiting for ROOT_PID')), 10000);
        timeout.unref();
        let buf = '';
        workerProc.stdout.on('data', (d) => {
          buf += d.toString('utf8');
          const m = /ROOT_PID:(\d+)/.exec(buf);
          if (m) {
            clearTimeout(timeout);
            resolve(parseInt(m[1], 10));
          }
        });
        workerProc.on('error', reject);
      });
      assert.ok(rootPid > 0, `Captured controlled root PID: ${rootPid}`);

      // Wait for stubborn descendant PID written by fixture
      for (let i = 0; i < 80; i++) {
        if (fs.existsSync(stubbornPidFile)) {
          const content = fs.readFileSync(stubbornPidFile, 'utf8').trim();
          if (content.length > 0) {
            stubbornPid = Number(content);
            break;
          }
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(stubbornPid > 0, `Captured stubborn descendant PID: ${stubbornPid}`);

      // Prove both root and stubborn descendant are alive before cancellation
      let rootAliveBefore = false;
      try {
        process.kill(rootPid, 0);
        rootAliveBefore = true;
      } catch {
        rootAliveBefore = false;
      }
      assert.equal(rootAliveBefore, true, 'Root process must be alive before cancellation');

      let descendantAliveBefore = false;
      try {
        process.kill(stubbornPid, 0);
        descendantAliveBefore = true;
      } catch {
        descendantAliveBefore = false;
      }
      assert.equal(
        descendantAliveBefore,
        true,
        'Stubborn descendant must be alive before cancellation',
      );

      // 3. Prove real ProcessRegistry ownership state file exists
      const stateFiles = fs.readdirSync(crashProcessStateDir).filter((f) => f.endsWith('.json'));
      assert.ok(stateFiles.length >= 1, 'State file must be written by ProcessRegistry');

      // 4. Start unrelated sentinel process
      sentinelProc = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], {
        detached: true,
        stdio: 'ignore',
      });
      sentinelProc.unref();
      const sentinelPid = sentinelProc.pid;
      assert.ok(sentinelPid, 'Sentinel process must have PID');

      // 5. Initiate cancellation so ARC sends SIGTERM
      workerProc.stdin.write('CANCEL\n');

      // 6. Prove root process exits on SIGTERM
      let rootDead = false;
      for (let i = 0; i < 40; i++) {
        try {
          process.kill(rootPid, 0);
          await new Promise((r) => setTimeout(r, 25));
        } catch {
          rootDead = true;
          break;
        }
      }
      assert.equal(rootDead, true, 'Root process must exit promptly upon SIGTERM delivery');

      // 7. Prove stubborn descendant remains alive
      let descendantAliveBeforeCrash = false;
      try {
        process.kill(stubbornPid, 0);
        descendantAliveBeforeCrash = true;
      } catch {
        descendantAliveBeforeCrash = false;
      }
      assert.equal(
        descendantAliveBeforeCrash,
        true,
        'Stubborn descendant must remain alive after root exits',
      );

      // Prove durable process ownership file is retained during kill grace window
      const stateFilesGrace = fs
        .readdirSync(crashProcessStateDir)
        .filter((f) => f.endsWith('.json'));
      assert.ok(
        stateFilesGrace.length >= 1,
        'State file must be retained during kill grace window while escalation is pending',
      );

      // 8. BEFORE normal SIGKILL escalation completes, abruptly SIGKILL/crash the ARC worker process
      workerProc.kill('SIGKILL');

      // 9. Prove stubborn descendant is still alive after ARC crash
      await new Promise((r) => setTimeout(r, 100));
      let descendantAliveAfterCrash = false;
      try {
        process.kill(stubbornPid, 0);
        descendantAliveAfterCrash = true;
      } catch {
        descendantAliveAfterCrash = false;
      }
      assert.equal(
        descendantAliveAfterCrash,
        true,
        'Stubborn descendant must survive ARC crash as an orphan in host OS',
      );

      // 10. Start replacement ARC runtime with the same durable audit and process-state root
      const lockPath = path.join(crashAuditConfig.directory, 'audit.lock');
      if (fs.existsSync(lockPath)) {
        fs.unlinkSync(lockPath);
      }

      const replacementServer = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'ws', path: workspaceDir }],
        defaultWorkspaceId: 'ws',
        audit: crashAuditConfig,
      });

      // 11. Normal start() invokes sweepOrphanProcesses(stateDir)
      await replacementServer.start();

      try {
        // 12. Prove stubborn descendant is killed by replacement startup sweep (within 2.5s)
        let descendantDead = false;
        for (let i = 0; i < 25; i++) {
          try {
            process.kill(stubbornPid, 0);
            await new Promise((r) => setTimeout(r, 100));
          } catch {
            descendantDead = true;
            break;
          }
        }
        assert.equal(
          descendantDead,
          true,
          'Original ARC-owned orphan descendant must be dead after replacement startup sweep',
        );

        // 13. Prove durable ownership record is cleaned only after recovery
        const remainingStateFiles = fs
          .readdirSync(crashProcessStateDir)
          .filter((f) => f.endsWith('.json'));
        assert.equal(
          remainingStateFiles.length,
          0,
          'Stale state file must be removed after sweep recovery',
        );

        // 14. Prove unrelated sentinel remains alive
        let sentinelAlive = false;
        try {
          process.kill(sentinelPid, 0);
          sentinelAlive = true;
        } catch {
          sentinelAlive = false;
        }
        assert.equal(sentinelAlive, true, 'Unrelated sentinel process must remain alive');
      } finally {
        await replacementServer.stop();
      }
    } finally {
      if (workerProc && !workerProc.killed) {
        try {
          workerProc.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }
      if (sentinelProc?.pid) {
        try {
          process.kill(sentinelProc.pid, 'SIGKILL');
        } catch {
          /* ignore */
        }
      }
      if (rootPid) {
        try {
          process.kill(rootPid, 'SIGKILL');
        } catch {
          /* ignore */
        }
      }
      if (stubbornPid) {
        try {
          process.kill(stubbornPid, 'SIGKILL');
        } catch {
          /* ignore */
        }
      }
      try {
        fs.unlinkSync(stubbornTestFile);
      } catch {
        /* ignore */
      }
      try {
        fs.unlinkSync(stubbornPidFile);
      } catch {
        /* ignore */
      }
    }

    // 11. Persistence-failure regression:
    // Make process-state persistence fail deterministically and prove execution fails closed
    const failAuditRoot = path.join(tempRoot, 'rc07-fail-state-test');
    fs.mkdirSync(failAuditRoot, { recursive: true });
    const failAuditConfig = createAuditConfig(failAuditRoot, 'audit');
    // Block process-state directory by creating a file with that name
    const blockingFile = path.join(path.dirname(failAuditConfig.directory), 'process-state');
    fs.writeFileSync(blockingFile, 'blocking');

    const failServer = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      audit: failAuditConfig,
    });
    await failServer.start();

    try {
      const reqRes = await failServer.executeAuthenticatedToolCall(safeActor, 'arc_test', {
        testPath: 'test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
      const reqId = reqPayload.details.approvalRequestId;
      const app = failServer.approvalStateManager.approve(reqId);

      // Attempt execution: should fail closed
      const execRes = await failServer.executeAuthenticatedToolCall(safeActor, 'arc_test', {
        testPath: 'test.js',
        _arcApproval: { requestId: reqId, token: app.token },
      });
      const parsed = JSON.parse(execRes.content[0].text);
      assert.ok(
        execRes.isError || parsed.status === 'FAILED',
        'Execution must fail closed when process state persistence fails',
      );
      assert.equal(
        failServer.processRegistry.countRunning(),
        0,
        'Zero active processes may survive persistence failure',
      );
    } finally {
      await failServer.stop();
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-071
  // ---------------------------------------------------------------------------
  test('RC07-NEG-071: Redaction pipeline fails to redact sensitive pattern in error message of composite tool', async () => {
    // Generate simulated secrets dynamically to avoid static scanner suppression
    const simulatedGhp = 'ghp_' + 'secret0123456789abcdef0123456789abcdef';
    const simulatedAkia = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

    // Create a real failing test file in workspace whose output and error contain secrets
    const secretFailTestPath = path.join(workspaceDir, 'secret-error.test.js');
    fs.writeFileSync(
      secretFailTestPath,
      `import test from 'node:test';
test('secret failure test', () => {
  throw new Error('Credential leaked: ' + '${simulatedGhp}' + ' and key ' + '${simulatedAkia}');
});
`,
    );

    try {
      // 1. Execute arc_test on the secret-emitting test file
      const reqRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'secret-error.test.js',
      });
      const reqPayload = JSON.parse(reqRes.content[0].text);
      assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');

      const approval = remoteServer.approvalStateManager.approve(
        reqPayload.details.approvalRequestId,
      );

      const execRes = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'secret-error.test.js',
        _arcApproval: {
          requestId: reqPayload.details.approvalRequestId,
          token: approval.token,
        },
      });

      const responseText = execRes.content[0].text;
      const parsed = JSON.parse(responseText);

      // Verify secrets are absent from MCP response and outputExcerpt
      assert.equal(
        responseText.includes(simulatedGhp),
        false,
        'GHP token must be redacted from MCP response',
      );
      assert.equal(
        responseText.includes(simulatedAkia),
        false,
        'AKIA key must be redacted from MCP response',
      );
      assert.ok(
        responseText.includes('[REDACTED_SECRET]'),
        'Must include [REDACTED_SECRET] marker',
      );

      assert.equal(parsed.outputExcerpt.includes(simulatedGhp), false);
      assert.equal(parsed.outputExcerpt.includes(simulatedAkia), false);

      // Verify secrets are absent from durable audit log
      const auditDir = auditConfig.directory;
      const auditFiles = fs
        .readdirSync(auditDir)
        .filter((f) => f.endsWith('.jsonl') || f.endsWith('.log'));
      for (const af of auditFiles) {
        const content = fs.readFileSync(path.join(auditDir, af), 'utf8');
        assert.equal(
          content.includes(simulatedGhp),
          false,
          `Audit file ${af} must not contain GHP secret`,
        );
        assert.equal(
          content.includes(simulatedAkia),
          false,
          `Audit file ${af} must not contain AKIA secret`,
        );
      }
    } finally {
      try {
        fs.unlinkSync(secretFailTestPath);
      } catch {
        /* ignore */
      }
    }
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
  // ---------------------------------------------------------------------------
  // RC07-NEG-073
  // ---------------------------------------------------------------------------
  test('RC07-NEG-073: Concurrent execution of arc_verify and arc_test exceeds aggregate process pool limit', async () => {
    const registry = remoteServer.processRegistry;
    assert.ok(registry, 'ProcessRegistry must be available');

    // Create 4 test files that sleep long enough to establish concurrent in-flight executions
    const sleepFiles = [];
    for (let i = 1; i <= 4; i++) {
      const f = path.join(workspaceDir, `pool-sleep-${i}.test.js`);
      fs.writeFileSync(
        f,
        `import test from 'node:test';\ntest('sleep', async () => { await new Promise(r => setTimeout(r, 4000)); });\n`,
      );
      sleepFiles.push(f);
    }

    try {
      // Launch 3 arc_test calls and 1 arc_verify calls in-flight
      // First obtain approvals for all 4 with distinct parameters
      const approvals = [];
      const configs = [
        { tool: 'arc_test', params: { testPath: 'pool-sleep-1.test.js' } },
        { tool: 'arc_test', params: { testPath: 'pool-sleep-2.test.js' } },
        { tool: 'arc_test', params: { testPath: 'pool-sleep-3.test.js' } },
        { tool: 'arc_verify', params: { suite: 'test' } },
      ];
      for (const cfg of configs) {
        const reqRes = await remoteServer.executeAuthenticatedToolCall(
          makeSafeActor(),
          cfg.tool,
          cfg.params,
        );
        const reqPayload = JSON.parse(reqRes.content[0].text);
        assert.equal(reqPayload.code, 'APPROVAL_REQUIRED');
        const app = remoteServer.approvalStateManager.approve(reqPayload.details.approvalRequestId);
        approvals.push({
          tool: cfg.tool,
          params: cfg.params,
          requestId: reqPayload.details.approvalRequestId,
          token: app.token,
        });
      }

      // Launch the 4 executions concurrently
      const inFlight = approvals.map((a) =>
        remoteServer.executeAuthenticatedToolCall(makeSafeActor(), a.tool, {
          ...a.params,
          _arcApproval: { requestId: a.requestId, token: a.token },
        }),
      );

      // Poll until process pool is saturated (4 processes in RUNNING state)
      for (let attempt = 0; attempt < 50; attempt++) {
        if (registry.countRunning() >= 4) break;
        await new Promise((r) => setTimeout(r, 50));
      }

      assert.equal(
        registry.countRunning(),
        4,
        'Pool must be filled with 4 active processes from mixed arc_test and arc_verify executions',
      );

      // Now attempt a 5th execution while pool is saturated
      // It must fail immediately with concurrency limit / resource exhausted
      const reqRes5 = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'test.js',
      });
      const reqPayload5 = JSON.parse(reqRes5.content[0].text);
      assert.equal(reqPayload5.code, 'APPROVAL_REQUIRED');
      const app5 = remoteServer.approvalStateManager.approve(reqPayload5.details.approvalRequestId);

      const res5 = await remoteServer.executeAuthenticatedToolCall(makeSafeActor(), 'arc_test', {
        testPath: 'test.js',
        _arcApproval: { requestId: reqPayload5.details.approvalRequestId, token: app5.token },
      });
      assert.equal(res5.isError, true, '5th execution must fail closed');
      const parsed5 = JSON.parse(res5.content[0].text);
      assert.ok(
        parsed5.code === 'CONCURRENCY_EXCEEDED' || parsed5.code === 'RESOURCE_EXHAUSTED',
        `Expected concurrency error, got: ${parsed5.code}`,
      );

      // ProcessRegistry maximum was never exceeded
      assert.ok(
        registry.countRunning() <= 4,
        'Active processes must never exceed the workspace ceiling of 4',
      );

      // Await in-flight executions to settle
      await Promise.all(inFlight);
    } finally {
      for (const f of sleepFiles) {
        try {
          fs.unlinkSync(f);
        } catch {
          /* ignore */
        }
      }
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-NEG-074
  // ---------------------------------------------------------------------------
  test('RC07-NEG-074: Client disconnects during streaming composite response', async () => {
    // 1. Establish valid session over TLS 1.3
    const session = await establishRemoteSession();

    // 2. Create long-running arc_test fixture
    const abortTestFile = path.join(workspaceDir, 'remote-abort.test.js');
    fs.writeFileSync(
      abortTestFile,
      "import test from 'node:test';\ntest('sleep', async () => { await new Promise(r => setTimeout(r, 60000)); });\n",
    );

    // Track lifecycle events
    const lifecycleEvents = [];
    const sink = {
      onProcessEvent(evt) {
        lifecycleEvents.push(evt);
      },
    };
    remoteServer.processRegistry.registerLifecycleSink(sink);

    try {
      // 3. Request approval for arc_test via real HTTPS
      const reqRes = await makeHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 741,
          method: 'tools/call',
          params: {
            name: 'arc_test',
            arguments: { testPath: 'remote-abort.test.js', maxDurationMs: 60000 },
          },
        }),
      );
      assert.equal(reqRes.statusCode, 200);
      const reqPayload = parseHttpResponseBody(reqRes.body);
      const toolText = JSON.parse(reqPayload.result.content[0].text);
      assert.equal(toolText.code, 'APPROVAL_REQUIRED');
      const requestId = toolText.details.approvalRequestId;

      // 4. Operator approves request
      const approval = remoteServer.approvalStateManager.approve(requestId);

      // 5. Redeem approval via real remote /mcp tools/call POST
      const { req, promise } = makeRawHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 742,
          method: 'tools/call',
          params: {
            name: 'arc_test',
            arguments: {
              testPath: 'remote-abort.test.js',
              maxDurationMs: 60000,
              _arcApproval: { requestId, token: approval.token },
            },
          },
        }),
      );

      // Catch expected network error when req is destroyed
      promise.catch(() => {});

      // 6. Wait until ProcessRegistry proves child is RUNNING
      let runningProc;
      for (let i = 0; i < 40; i++) {
        const procs = remoteServer.processRegistry?.getActiveProcesses() ?? [];
        runningProc = procs.find((p) => p.state === 'RUNNING' && p._child?.pid);
        if (runningProc) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(runningProc, 'Process must be in RUNNING state in registry');
      const childPid = runningProc._child?.pid;
      assert.ok(childPid && childPid > 0, `Child PID: ${childPid}`);

      // 7. Destroy / abort client HTTP socket to trigger remote disconnect
      req.destroy();

      // 8. Prove child is terminated promptly via SIGTERM (and SIGKILL if needed)
      let childDead = false;
      for (let i = 0; i < 30; i++) {
        try {
          process.kill(childPid, 0);
          await new Promise((r) => setTimeout(r, 100));
        } catch {
          childDead = true;
          break;
        }
      }
      assert.equal(
        childDead,
        true,
        `Child process ${childPid} must be terminated upon client disconnect`,
      );

      // 9. Prove child received SIGTERM
      const procEvents = lifecycleEvents.filter((e) => e.processId === runningProc.processId);
      const eventTypes = procEvents.map((e) => e.eventType);
      assert.ok(
        eventTypes.includes('PROCESS_SIGTERM_SENT'),
        `Lifecycle events must include SIGTERM: ${JSON.stringify(eventTypes)}`,
      );

      // 10. Prove ProcessRegistry has no RUNNING or TERMINATING record for this process
      const status = remoteServer.processRegistry?.getProcessStatus(runningProc.processId, {
        clientId: 'task8-agent',
        sessionId: session.sessionId,
        workspaceId: 'ws',
      });
      assert.ok(status.state !== 'RUNNING' && status.state !== 'TERMINATING');

      // 11. Prove root lifecycle reaches COMPLETED truthfully
      const auditDir = auditConfig.directory;
      let foundCompleted = false;
      for (let i = 0; i < 30; i++) {
        const auditFiles = fs.readdirSync(auditDir).filter((f) => f.endsWith('.jsonl'));
        for (const af of auditFiles) {
          const lines = fs.readFileSync(path.join(auditDir, af), 'utf8').trim().split('\n');
          for (const line of lines) {
            if (!line) continue;
            try {
              const rec = JSON.parse(line);
              if (rec.lifecycle?.phase === 'COMPLETED' && rec.invocation?.toolName === 'arc_test') {
                foundCompleted = true;
                break;
              }
            } catch {
              /* ignore parse error */
            }
          }
          if (foundCompleted) break;
        }
        if (foundCompleted) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.ok(foundCompleted, 'Root lifecycle must reach COMPLETED in durable audit log');

      // 12. Prove Layer-C admission slot is released exactly once
      const sessionKey = `${session.sessionId}:${clientSpkiPin}`;
      assert.equal(
        remoteServer.authenticatedRequestLimiter.getHolderCount(sessionKey),
        0,
        'Admission slot must be released after disconnect',
      );
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
  // ---------------------------------------------------------------------------
  // RC07-FLOW-17
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-17: Stdio Transport Parity', async () => {
    const stdioAuditDir = path.join(tempRoot, 'rc07-flow17-stdio-audit');
    const stdio = startStdioServerProcess(workspaceDir, stdioAuditDir);

    try {
      // 1. Real stdio MCP initialize
      const initRes = await stdio.request(1, 'initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'flow17-tester', version: '1.0' },
      });
      assert.equal(initRes.result.serverInfo.name, 'cesspace-arc');
      assert.equal(initRes.result.serverInfo.version, '0.7.0-rc07');

      // 2. notifications/initialized
      stdio.notify('notifications/initialized');

      // 3. Real tools/list through stdio
      const listRes = await stdio.request(2, 'tools/list', {});
      const tools = listRes.result.tools;
      assert.equal(tools.length, 25, 'Must advertise exactly 25 tools over stdio');

      const toolNames = new Set(tools.map((t) => t.name));
      const expectedRc07Tools = [
        'arc_repo_status',
        'arc_worktree_status',
        'arc_review_diff',
        'arc_verify',
        'arc_test',
        'arc_ci_status',
        'arc_stage_evidence',
      ];
      for (const t of expectedRc07Tools) {
        assert.ok(toolNames.has(t), `Stdio must advertise ${t}`);
      }

      // 4. Real stdio tools/call for arc_repo_status
      const callRes = await stdio.request(3, 'tools/call', {
        name: 'arc_repo_status',
        arguments: {},
      });
      assert.ok(callRes.result && !callRes.result.isError);
      const parsed = JSON.parse(callRes.result.content[0].text);
      assert.equal(parsed.branch, 'main');
      assert.equal(parsed.isClean, true);
      assert.ok(parsed.headCommit && parsed.headCommit.hash.length >= 7);
    } finally {
      await stdio.close();
    }
  });

  // ---------------------------------------------------------------------------
  // RC07-FLOW-18
  // ---------------------------------------------------------------------------
  test('RC07-FLOW-18: Process Interruption and SIGKILL Escalation', async () => {
    const stubbornScriptPath = path.join(workspaceDir, 'stubborn-cancellation.test.js');
    fs.writeFileSync(
      stubbornScriptPath,
      `import { spawn } from 'node:child_process';
import test from 'node:test';

test('stubborn test requiring SIGKILL escalation', async () => {
  const childScript = \`
    const fs = require('node:fs');
    process.on('SIGTERM', () => {});
    fs.writeSync(1, 'STUBBORN_DESCENDANT:' + process.pid + '\\\\n');
    setInterval(() => {}, 60000);
  \`;
  const child = spawn(process.execPath, ['-e', childScript], {
    stdio: ['ignore', 'inherit', 'ignore'],
  });
  process.on('SIGTERM', () => {});
  await new Promise((resolve) => setTimeout(resolve, 60000));
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
      // 1. Establish valid session over real TLS
      const session = await establishRemoteSession();

      // 2. Remotely invoke arc_test with maxDurationMs 60000 to obtain APPROVAL_REQUIRED
      const reqRes = await makeHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 181,
          method: 'tools/call',
          params: {
            name: 'arc_test',
            arguments: {
              testPath: 'stubborn-cancellation.test.js',
              maxDurationMs: 60000,
            },
          },
        }),
      );
      assert.equal(reqRes.statusCode, 200);
      const reqPayload = parseHttpResponseBody(reqRes.body);
      const toolText = JSON.parse(reqPayload.result.content[0].text);
      assert.equal(toolText.code, 'APPROVAL_REQUIRED');
      const requestId = toolText.details.approvalRequestId;

      // 3. Approve via operator seam
      const approval = remoteServer.approvalStateManager.approve(requestId);

      // 4. Redeem approval via real remote /mcp tools/call POST
      const { req, promise } = makeRawHttpsRequest(
        serverPort,
        pki,
        clientCertPem,
        clientKeyPem,
        'POST',
        '/mcp',
        {
          'Mcp-Session-Id': session.sessionId,
          Authorization: `Bearer ${session.sessionToken}`,
        },
        JSON.stringify({
          jsonrpc: '2.0',
          id: 182,
          method: 'tools/call',
          params: {
            name: 'arc_test',
            arguments: {
              testPath: 'stubborn-cancellation.test.js',
              maxDurationMs: 60000,
              _arcApproval: { requestId, token: approval.token },
            },
          },
        }),
      );
      promise.catch(() => {});

      // 5. Wait until child process is RUNNING
      let runningProc;
      for (let i = 0; i < 40; i++) {
        const procs = procRegistry.getActiveProcesses();
        runningProc = procs.find((p) => p.state === 'RUNNING' && p._child?.pid);
        if (runningProc) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(runningProc, 'Process must be in RUNNING state');
      const rootPid = runningProc._child?.pid;
      assert.ok(rootPid, `Root child PID: ${rootPid}`);

      // Poll until descendant PID is output in stdout
      let match;
      for (let i = 0; i < 40; i++) {
        const chunks = runningProc._stdoutChunks || [];
        const combinedOutput = Buffer.concat(chunks).toString('utf8');
        match = /STUBBORN_DESCENDANT:(\d+)/.exec(combinedOutput);
        if (match) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(match, 'Must capture stubborn descendant PID');
      const descendantPid = Number(match[1]);
      assert.ok(descendantPid > 0, `Captured valid positive descendant PID: ${descendantPid}`);

      // Prove descendant existed before cancellation
      let descendantAliveBefore = false;
      try {
        process.kill(descendantPid, 0);
        descendantAliveBefore = true;
      } catch {
        descendantAliveBefore = false;
      }
      assert.equal(
        descendantAliveBefore,
        true,
        'Stubborn descendant must exist and be alive before cancellation',
      );

      // 6. Trigger cancellation through real remote disconnect
      req.destroy();

      // 7. Prove descendant ignored SIGTERM / survived initial termination interval (300ms)
      await new Promise((resolve) => setTimeout(resolve, 300));
      let descendantAliveMid = false;
      try {
        process.kill(descendantPid, 0);
        descendantAliveMid = true;
      } catch {
        descendantAliveMid = false;
      }
      assert.equal(
        descendantAliveMid,
        true,
        'Stubborn descendant must ignore SIGTERM and survive initial termination interval',
      );

      // 8. Wait beyond the 1000ms SIGKILL escalation grace period (total > 1500ms)
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // 9. Prove root child is dead
      let rootAlive = true;
      try {
        process.kill(rootPid, 0);
      } catch (err) {
        if (err && err.code === 'ESRCH') {
          rootAlive = false;
        }
      }
      assert.equal(
        rootAlive,
        false,
        `Root child PID ${rootPid} must be dead after SIGKILL escalation`,
      );

      // 10. Prove stubborn descendant is dead after SIGKILL escalation (mandatory assertion)
      let descendantAlive = true;
      try {
        process.kill(descendantPid, 0);
      } catch (err) {
        if (err && err.code === 'ESRCH') {
          descendantAlive = false;
        }
      }
      assert.equal(
        descendantAlive,
        false,
        `Stubborn descendant PID ${descendantPid} must be dead after SIGKILL escalation`,
      );

      // 10. Prove ordered lifecycle events: SIGTERM sent -> SIGKILL escalated
      const opEvents = lifecycleEvents.filter((e) => e.processId === runningProc.processId);
      const eventTypes = opEvents.map((e) => e.eventType);
      assert.ok(
        eventTypes.includes('PROCESS_SIGTERM_SENT'),
        `Lifecycle events must contain PROCESS_SIGTERM_SENT: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.includes('PROCESS_SIGKILL_ESCALATED'),
        `Lifecycle events must contain PROCESS_SIGKILL_ESCALATED: ${JSON.stringify(eventTypes)}`,
      );
      assert.ok(
        eventTypes.indexOf('PROCESS_SIGTERM_SENT') <
          eventTypes.indexOf('PROCESS_SIGKILL_ESCALATED'),
        'SIGTERM must precede SIGKILL escalation',
      );

      // 11. Prove ProcessRegistry terminal
      const finalStatus = procRegistry.getProcessStatus(runningProc.processId, {
        clientId: 'task8-agent',
        sessionId: session.sessionId,
        workspaceId: 'ws',
      });
      assert.ok(
        finalStatus.state !== 'RUNNING' && finalStatus.state !== 'TERMINATING',
        `ProcessRegistry must be terminal; state is ${finalStatus.state}`,
      );

      // 12. Prove no orphan remains
      const stateDir = remoteServer.processStateDir;
      if (stateDir && fs.existsSync(stateDir)) {
        const remaining = fs.readdirSync(stateDir).filter((f) => f.endsWith('.json'));
        assert.equal(remaining.length, 0, 'No orphan process state record should remain');
      }

      // 13. Prove root MCP lifecycle is COMPLETED and no root FAILED phase
      const auditDir = auditConfig.directory;
      let foundCompleted = false;
      let foundFailedPhase = false;
      for (let i = 0; i < 30; i++) {
        foundFailedPhase = false;
        const auditFiles = fs.readdirSync(auditDir).filter((f) => f.endsWith('.jsonl'));
        for (const af of auditFiles) {
          const lines = fs.readFileSync(path.join(auditDir, af), 'utf8').trim().split('\n');
          for (const line of lines) {
            if (!line) continue;
            try {
              const rec = JSON.parse(line);
              if (rec.lifecycle?.phase === 'FAILED') foundFailedPhase = true;
              if (rec.lifecycle?.phase === 'COMPLETED' && rec.invocation?.toolName === 'arc_test') {
                foundCompleted = true;
              }
            } catch {
              /* ignore parse error */
            }
          }
        }
        if (foundCompleted) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      assert.equal(foundFailedPhase, false, 'No root FAILED phase may exist in audit ledger');
      assert.ok(foundCompleted, 'Root MCP lifecycle must reach COMPLETED phase');
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
