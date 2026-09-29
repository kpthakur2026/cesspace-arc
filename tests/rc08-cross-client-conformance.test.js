/**
 * CesSpace ARC — RC-08 Task 1 Authoritative Test Suite
 * Cross-Client MCP Conformance Harness
 *
 * Covers:
 * - Negative Controls: RC08-NEG-001 through RC08-NEG-010 (all 10 Task 1 negative controls)
 * - Positive Acceptance Flows: RC08-FLOW-01 through RC08-FLOW-04 (all 4 Task 1 positive flows)
 *
 * Exercises:
 * A. Official @modelcontextprotocol/sdk stdio client
 * B. Official @modelcontextprotocol/sdk Streamable HTTP client over TLS 1.3 / mTLS
 * C. Independent raw JSON-RPC stdio client harness with ZERO internal framework imports
 * D. Concurrent remote client sessions with isolated state
 */

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as net from 'node:net';
import { Client } from '../apps/mcp-server/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import { StdioClientTransport } from '../apps/mcp-server/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js';
import { StreamableHTTPClientTransport } from '../apps/mcp-server/node_modules/@modelcontextprotocol/sdk/dist/esm/client/streamableHttp.js';
import { ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import {
  spawnArcStdioServerProcess,
  RawJsonRpcStdioClient,
  createMtlsFetch,
  startTestRemoteServer,
  makeRawHttpsRequest,
  parseMcpResponse,
} from './helpers/rc08-mcp-client-harness.mjs';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rc08-task1-conformance-'));
let pki;

before(() => {
  assert.ok(hasOpenssl(), 'OpenSSL is required for RC-08 conformance testing');
  pki = createTestPki(tempRoot);
});

after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

// ============================================================================
// Negative Security Controls: RC08-NEG-001 through RC08-NEG-010
// ============================================================================

describe('RC-08 Task 1: Negative Controls (RC08-NEG-001..RC08-NEG-010)', () => {
  test('RC08-NEG-001: Client sends tools/call before protocol initialization (initialize) - rejected with INVALID_INITIALIZATION_ORDER', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-001',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      // Attempt tools/call without calling initialize
      const response = await client.request('tools/call', {
        name: 'health',
        arguments: {},
      });

      assert.ok(response.error, 'Must return JSON-RPC error');
      assert.equal(response.error.code, -32600, 'Error code must be -32600 (Invalid Request)');
      assert.match(
        response.error.message,
        /INVALID_INITIALIZATION_ORDER|Invalid initialization order/i,
        'Error message must indicate initialization order violation',
      );
      assert.equal(
        response.error.data?.code,
        'INVALID_INITIALIZATION_ORDER',
        'Error data.code must be INVALID_INITIALIZATION_ORDER',
      );

      // Attempt tools/list before initialize as well
      const listResponse = await client.request('tools/list', {});
      assert.ok(listResponse.error, 'tools/list before initialize must return error');
      assert.equal(listResponse.error.code, -32600);
      assert.equal(listResponse.error.data?.code, 'INVALID_INITIALIZATION_ORDER');
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-002: Client negotiates unsupported MCP protocol version - rejected with UNSUPPORTED_PROTOCOL_VERSION', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-002',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      const response = await client.request('initialize', {
        protocolVersion: '1999-01-01',
        capabilities: {},
        clientInfo: { name: 'legacy-client', version: '0.1' },
      });

      assert.ok(response.error, 'Must return JSON-RPC error for unsupported version');
      assert.equal(response.error.code, -32602, 'Error code must be -32602 (Invalid Params)');
      assert.match(
        response.error.message,
        /Unsupported protocol version/i,
        'Error message must describe unsupported version',
      );
      assert.equal(
        response.error.data?.code,
        'UNSUPPORTED_PROTOCOL_VERSION',
        'data.code must be UNSUPPORTED_PROTOCOL_VERSION',
      );
      assert.equal(response.error.data?.requestedVersion, '1999-01-01');
      assert.ok(Array.isArray(response.error.data?.supportedVersions));
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-003: Client sends JSON-RPC notification for call-only method (tools/call without id) - discarded without execution', async () => {
    const { proc, workspaceDir, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-003',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      const targetFileName = 'mutation-should-not-exist.txt';
      const targetFilePath = path.join(workspaceDir, targetFileName);

      // Send notification for tools/call targeting mutation tool create_file
      client.notify('tools/call', {
        name: 'create_file',
        arguments: {
          path: targetFileName,
          content: 'unauthorized mutation content via notification',
        },
      });

      // Use a subsequent successful protocol round-trip as the processing barrier (zero blind sleep)
      const initRes = await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0' },
      });
      assert.ok(
        initRes.result,
        'Server must accept legitimate initialize after discarded notification',
      );

      // Prove target file does NOT exist and no mutation occurred
      assert.strictEqual(
        fs.existsSync(targetFilePath),
        false,
        'Target file must NOT exist: notification must not execute mutation tool',
      );

      // Prove no response was emitted for the notification
      assert.strictEqual(
        client.incomingQueue.length,
        0,
        'No reply should be emitted for notification',
      );

      // Confirm protocol lifecycle
      client.notify('notifications/initialized', {});

      // Subsequent legitimate safe tool call succeeds
      const callRes = await client.request('tools/call', {
        name: 'health',
        arguments: {},
      });
      assert.ok(callRes.result, 'Server must respond to legitimate tools/call');
      assert.strictEqual(callRes.error, undefined);
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-004: Client sends batch JSON-RPC request - rejected atomically per-request without session corruption', async () => {
    // 1. Over stdio transport
    const {
      proc,
      workspaceDir: stdioWs,
      cleanup: stdioCleanup,
    } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-004-stdio',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      const stdioBatchFile = path.join(stdioWs, 'stdio-batch-file.txt');

      // Send mixed wire-level batch: one valid request calling create_file + one structurally invalid member
      const batchPayload = JSON.stringify([
        {
          jsonrpc: '2.0',
          id: 101,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: { path: 'stdio-batch-file.txt', content: 'batch' },
          },
        },
        { id: 102, method: 'ping' }, // structurally invalid: missing jsonrpc: "2.0"
      ]);
      client.sendRaw(batchPayload);

      // Observe SDK 1.30.0 stdio behavior: SDK stdio parser rejects batch array as invalid JSON-RPC message,
      // discarding it without executing any member.
      // Use subsequent valid initialize round-trip as the deterministic barrier (no blind sleep).
      const initRes = await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'recovery-client', version: '1.0' },
      });
      assert.ok(
        initRes.result,
        'Stdio server must process subsequent requests cleanly after batch attempt',
      );

      // Prove no unauthorized member execution occurred
      assert.strictEqual(
        fs.existsSync(stdioBatchFile),
        false,
        'Batch member must NOT have executed mutation',
      );

      client.notify('notifications/initialized', {});

      // Prove no protocol/session corruption: subsequent valid request succeeds
      const pingRes = await client.request('ping', {}, 104);
      assert.deepEqual(pingRes.result, {}, 'Subsequent valid ping request must succeed');
    } finally {
      client.close();
      await stdioCleanup();
    }

    // 2. Over Streamable HTTP transport
    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'neg-004-http',
      enrolledClientCertPaths: [pki.clientCertPath],
    });

    try {
      const customFetch = createMtlsFetch({
        caPath: pki.trustedCaCertPath,
        certPath: pki.clientCertPath,
        keyPath: pki.clientKeyPath,
      });

      // Establish session first
      const initRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-11-25',
            capabilities: {},
            clientInfo: { name: 'test-batch', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);

      const httpBatchFile = path.join(remote.workspaceDir, 'http-batch-file.txt');

      // Send mixed wire-level batch: 1 valid tool call + 1 structurally invalid member
      const mixedBatchBody = JSON.stringify([
        {
          jsonrpc: '2.0',
          id: 201,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: { path: 'http-batch-file.txt', content: 'batch' },
          },
        },
        { id: 202, method: 'ping' }, // missing jsonrpc
      ]);

      const res = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: mixedBatchBody,
      });

      // Prove one fail-closed batch refusal: HTTP 200 (MCP_POST_REPLY_STATUS), -32600, INVALID_REQUEST_SCHEMA
      assert.equal(res.status, 200, 'Batch refusal is framed as MCP JSON-RPC reply');
      const data = await res.json();
      assert.ok(data.error, 'Batch request must return JSON-RPC error');
      assert.equal(data.error.code, -32600, 'Batch refusal code is -32600 (Invalid Request)');
      assert.equal(data.error.data?.code, 'INVALID_REQUEST_SCHEMA');
      assert.match(data.error.message, /batch/i);

      // Prove no batch member executes
      assert.strictEqual(
        fs.existsSync(httpBatchFile),
        false,
        'Batch member must NOT have created file',
      );

      // Prove session remains intact: subsequent valid request succeeds
      const pingRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 203,
          method: 'ping',
          params: {},
        }),
      });
      assert.equal(pingRes.status, 200, 'Subsequent request must succeed');
      const pingData = await parseMcpResponse(pingRes);
      assert.deepEqual(pingData.result, {}, 'Ping result must be empty object');
    } finally {
      await remote.cleanup();
    }
  });

  test('RC08-NEG-005: Client requests unknown MCP method outside protocol specification - rejected with METHOD_NOT_FOUND / -32601', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-005',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0' },
      });
      client.notify('notifications/initialized', {});

      // 1. Unknown protocol method
      const unknownMethodRes = await client.request('arc/nonExistentProtocolMethod', {});
      assert.ok(unknownMethodRes.error, 'Unknown protocol method must return error');
      assert.equal(
        unknownMethodRes.error.code,
        -32601,
        'Unknown protocol method must return -32601 (Method not found)',
      );

      // 2. Unknown tool name via tools/call
      const unknownToolRes = await client.request('tools/call', {
        name: 'non_existent_production_tool_xyz',
        arguments: {},
      });
      assert.ok(unknownToolRes.error, 'Unknown tool name must return error');
      assert.equal(
        unknownToolRes.error.code,
        -32601,
        'Unknown tool name must return -32601 (Method not found / unknown tool)',
      );
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-006: Client sends duplicate concurrent request IDs over stdio - handled deterministically without state corruption', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-006',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0' },
      });
      client.notify('notifications/initialized', {});

      // Use two requests with IDENTICAL IDs but clearly different result shapes:
      // A: tools/call health
      // B: tools/list
      const duplicateId = 42;
      const reqA = {
        jsonrpc: '2.0',
        id: duplicateId,
        method: 'tools/call',
        params: { name: 'health', arguments: {} },
      };
      const reqB = {
        jsonrpc: '2.0',
        id: duplicateId,
        method: 'tools/list',
        params: {},
      };

      // Send both concurrently
      client.sendRaw(JSON.stringify(reqA));
      client.sendRaw(JSON.stringify(reqB));

      // Receive both responses without assuming arrival order
      const resp1 = await client.readNext(5000);
      const resp2 = await client.readNext(5000);

      // Prove both have the duplicate ID
      assert.equal(resp1.id, duplicateId, 'First response must carry duplicate ID');
      assert.equal(resp2.id, duplicateId, 'Second response must carry duplicate ID');

      // Disambiguate responses by result shape
      const responses = [resp1, resp2];
      const healthResp = responses.find((r) => r.result && r.result.content !== undefined);
      const listResp = responses.find((r) => r.result && Array.isArray(r.result.tools));

      assert.ok(healthResp, 'Exactly one response must be a health result');
      assert.ok(listResp, 'Exactly one response must be a tools/list result');

      // Health result inspection
      assert.equal(healthResp.error, undefined, 'Health response must not contain error');
      const healthParsed = JSON.parse(healthResp.result.content[0].text);
      assert.equal(healthParsed.status, 'HEALTHY', 'Health status must be HEALTHY');

      // Tools/list result inspection
      assert.equal(listResp.error, undefined, 'Tools/list response must not contain error');
      assert.equal(listResp.result.tools.length, 25, 'tools/list must contain exactly 25 tools');

      // A later request using a NEW ID succeeds
      const newId = 1001;
      const pingRes = await client.request('ping', {}, newId);
      assert.equal(pingRes.id, newId, 'Ping response must carry new ID');
      assert.deepEqual(pingRes.result, {}, 'Ping result must be empty object');
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-007: Client disconnects during tools/call processing - server handles clean disconnect without hung promises', async () => {
    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'neg-007-disconnect',
      enrolledClientCertPaths: [pki.clientCertPath],
    });

    const customFetch = createMtlsFetch({
      caPath: pki.trustedCaCertPath,
      certPath: pki.clientCertPath,
      keyPath: pki.clientKeyPath,
    });

    const abortTestFile = path.join(remote.workspaceDir, 'remote-abort.test.js');

    try {
      // 1. Establish session over Streamable HTTP
      const initRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-11-25',
            capabilities: {},
            clientInfo: { name: 'disconnect-test', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);
      const sessionId = customFetch.getSessionId();
      const sessionToken = customFetch.getSessionToken();
      assert.ok(sessionId && sessionToken);

      // 2. Create long-running node:test fixture
      fs.writeFileSync(
        abortTestFile,
        "import test from 'node:test';\ntest('sleep', async () => { await new Promise((r) => setTimeout(r, 60000)); });\n",
      );

      // Track lifecycle events from process registry
      const lifecycleEvents = [];
      remote.server.processRegistry?.registerLifecycleSink({
        onProcessEvent(evt) {
          lifecycleEvents.push(evt);
        },
      });

      // 3. Request approval for arc_test via real HTTPS
      const reqRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 701,
          method: 'tools/call',
          params: {
            name: 'arc_test',
            arguments: { testPath: 'remote-abort.test.js', maxDurationMs: 60000 },
          },
        }),
      });
      assert.equal(reqRes.status, 200);
      const reqPayload = await parseMcpResponse(reqRes);
      const toolText = JSON.parse(reqPayload.result.content[0].text);
      assert.equal(toolText.code, 'APPROVAL_REQUIRED');
      const requestId = toolText.details.approvalRequestId;

      // 4. Operator approves request
      const approval = remote.server.approvalStateManager.approve(requestId);

      // 5. Redeem approval via real raw HTTPS request with exposed ClientRequest
      const { req, promise } = makeRawHttpsRequest({
        port: remote.port,
        caPath: pki.trustedCaCertPath,
        certPath: pki.clientCertPath,
        keyPath: pki.clientKeyPath,
        method: 'POST',
        reqPath: '/mcp',
        headers: {
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 702,
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
      });

      // Swallow expected socket error on abort
      promise.catch(() => {});

      // 6. Synchronize until ProcessRegistry proves child state RUNNING
      let runningProc;
      for (let i = 0; i < 60; i++) {
        const procs = remote.server.processRegistry?.getActiveProcesses() ?? [];
        runningProc = procs.find((p) => p.state === 'RUNNING' && p._child?.pid);
        if (runningProc) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(runningProc, 'Process must reach RUNNING state in ProcessRegistry');
      const childPid = runningProc._child?.pid;
      assert.ok(childPid && childPid > 0, `Child PID must be valid: ${childPid}`);

      // 7. Destroy the actual client HTTP/socket connection while execution is active
      req.destroy();

      // 8. Prove within bounded deadline that child process terminates
      let childDead = false;
      for (let i = 0; i < 60; i++) {
        try {
          process.kill(childPid, 0);
          await new Promise((r) => setTimeout(r, 50));
        } catch {
          childDead = true;
          break;
        }
      }
      assert.strictEqual(
        childDead,
        true,
        `Child process ${childPid} must be terminated upon client disconnect`,
      );

      // Prove ProcessRegistry no longer reports RUNNING or TERMINATING
      const procRecord = remote.server.processRegistry?.getProcess(runningProc.processId);
      assert.ok(procRecord, 'Process record must exist in ProcessRegistry');
      assert.ok(
        procRecord.state !== 'RUNNING' && procRecord.state !== 'TERMINATING',
        `Process state must not be RUNNING or TERMINATING (got: ${procRecord.state})`,
      );
      const procStatus = remote.server.processRegistry?.getProcessStatus(runningProc.processId, {
        clientId: procRecord.actor.clientId,
        sessionId: procRecord.actor.sessionId,
        workspaceId: procRecord.workspaceId,
      });
      assert.ok(
        procStatus.state !== 'TERMINATING',
        `Process status must not be TERMINATING (got: ${procStatus.state})`,
      );

      // Prove lifecycle/audit reaches truthful terminal state
      let foundCompleted = false;
      for (let i = 0; i < 60; i++) {
        const auditFiles = fs
          .readdirSync(remote.audit.directory)
          .filter((f) => f.endsWith('.jsonl'));
        for (const af of auditFiles) {
          const lines = fs
            .readFileSync(path.join(remote.audit.directory, af), 'utf8')
            .trim()
            .split('\n');
          for (const line of lines) {
            if (!line) continue;
            try {
              const rec = JSON.parse(line);
              if (rec.lifecycle?.phase === 'COMPLETED' && rec.invocation?.toolName === 'arc_test') {
                foundCompleted = true;
                break;
              }
            } catch {
              // ignore parse errors
            }
          }
          if (foundCompleted) break;
        }
        if (foundCompleted) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.ok(foundCompleted, 'Audit log must truthfully record COMPLETED lifecycle phase');

      // Prove Layer-C admission slot is released and ARC server remains operational
      const healthRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 703,
          method: 'tools/call',
          params: { name: 'health', arguments: {} },
        }),
      });
      assert.equal(
        healthRes.status,
        200,
        'ARC server must remain operational after client disconnect',
      );
      const healthData = await parseMcpResponse(healthRes);
      assert.ok(healthData.result, 'Health result must be returned');
    } finally {
      try {
        fs.unlinkSync(abortTestFile);
      } catch {
        // ignore unlink error
      }
      await remote.cleanup();
    }
  });

  test('RC08-NEG-008: Client supplies invalid or corrupted cursor in tools/list - rejected with INVALID_PAGINATION_TOKEN / -32602', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-008',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0' },
      });
      client.notify('notifications/initialized', {});

      const response = await client.request('tools/list', {
        cursor: 'corrupted-page-token-0xdeadbeef',
      });

      assert.ok(response.error, 'Must return JSON-RPC error for corrupted pagination token');
      assert.equal(response.error.code, -32602, 'Error code must be -32602 (Invalid Params)');
      assert.equal(
        response.error.data?.code,
        'INVALID_PAGINATION_TOKEN',
        'data.code must be INVALID_PAGINATION_TOKEN',
      );
      assert.match(response.error.message, /corrupted-page-token-0xdeadbeef/);

      // Verify recovery after bad cursor: send valid tools/list with no cursor
      const validListRes = await client.request('tools/list', {});
      assert.equal(validListRes.error, undefined, 'Must not return error for valid tools/list');
      assert.ok(Array.isArray(validListRes.result?.tools), 'Must return tools array');
      assert.equal(
        validListRes.result.tools.length,
        25,
        'Must return exactly 25 tools after recovering from bad cursor',
      );
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-009: Independent raw JSON-RPC client omits required protocol envelopes - server rejects with INVALID_REQUEST / -32600', async () => {
    // 1. Over Streamable HTTP:
    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'neg-009-http',
      enrolledClientCertPaths: [pki.clientCertPath],
    });

    try {
      const customFetch = createMtlsFetch({
        caPath: pki.trustedCaCertPath,
        certPath: pki.clientCertPath,
        keyPath: pki.clientKeyPath,
      });

      // Initialize session first
      const initRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-11-25',
            capabilities: {},
            clientInfo: { name: 'test', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);

      // Case A: Syntactically valid JSON with invalid JSON-RPC envelope (missing jsonrpc: "2.0")
      // MUST produce -32600 Invalid Request
      const missingEnvelopeRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          id: 2,
          method: 'ping',
        }),
      });

      assert.equal(missingEnvelopeRes.status, 400);
      const envelopeError = await missingEnvelopeRes.json();
      assert.ok(envelopeError.error, 'Must return JSON-RPC error');
      assert.equal(
        envelopeError.error.code,
        -32600,
        'Syntactically valid JSON with invalid envelope must return -32600 (Invalid Request)',
      );
      assert.equal(envelopeError.id, 2, 'Error response must echo request id');

      // Case B: Truly malformed JSON syntax
      // MUST produce -32700 Parse Error
      const malformedJsonRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: '{"id": 3, "method": "ping", invalid-json...',
      });

      assert.equal(malformedJsonRes.status, 400);
      const malformedError = await malformedJsonRes.json();
      assert.ok(malformedError.error, 'Must return JSON-RPC error');
      assert.equal(
        malformedError.error.code,
        -32700,
        'Malformed JSON syntax must return -32700 (Parse Error)',
      );

      // Prove that after rejection, a subsequent valid request succeeds
      const recoveryRes = await customFetch(`https://localhost:${remote.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'ping',
          params: {},
        }),
      });
      assert.equal(recoveryRes.status, 200, 'Subsequent valid request must succeed');
      const recoveryData = await parseMcpResponse(recoveryRes);
      assert.deepEqual(recoveryData.result, {});
    } finally {
      await remote.cleanup();
    }

    // 2. Over stdio: missing required parameters envelope in tools/call
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'neg-009-stdio',
    });
    const client = new RawJsonRpcStdioClient(proc);

    try {
      await client.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'test', version: '1.0' },
      });
      client.notify('notifications/initialized', {});

      // Omit required params envelope in tools/call
      const res = await client.request('tools/call', undefined, 202);
      assert.ok(res.error, 'Omission of required params envelope must produce error');
      assert.ok(
        res.error.code === -32600 || res.error.code === -32602 || res.error.code === -32603,
        'Error code must be standard JSON-RPC protocol error',
      );

      // Process must remain responsive to valid request
      const validRes = await client.request('tools/call', { name: 'health', arguments: {} }, 203);
      assert.ok(validRes.result, 'Server must remain responsive to valid requests');
    } finally {
      client.close();
      await cleanup();
    }
  });

  test('RC08-NEG-010: Unauthenticated client attempts rapid reconnection storm - terminated without FD leakage, subsequent legitimate client succeeds', async () => {
    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'neg-010-storm',
      enrolledClientCertPaths: [pki.clientCertPath],
    });

    try {
      // Launch 15 rapid unauthenticated raw TCP connections (within Layer A burst cap of 20)
      const stormSize = 15;
      const stormSockets = [];
      const stormPromises = [];

      for (let i = 0; i < stormSize; i++) {
        stormPromises.push(
          new Promise((resolve) => {
            const socket = net.createConnection({ port: remote.port, host: '127.0.0.1' }, () => {
              // Send random unauthenticated non-TLS junk bytes
              socket.write(`GARBAGE_PAYLOAD_${i}\r\n\r\n`);
            });
            stormSockets.push(socket);
            socket.on('error', () => resolve());
            socket.on('close', () => resolve());
          }),
        );
      }

      await Promise.all(stormPromises);

      // Explicitly destroy all storm sockets
      for (const sock of stormSockets) {
        try {
          sock.destroy();
        } catch {
          // ignore destroy errors
        }
      }

      // Prove using bounded condition polling that gateway resources return to baseline
      let status;
      for (let i = 0; i < 60; i++) {
        status = remote.server.getRemoteGatewayStatus();
        if (
          status &&
          status.liveConnections === 0 &&
          status.inFlightHandshakes === 0 &&
          status.activeAndServing === true
        ) {
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }

      assert.ok(status, 'Must obtain remote gateway status');
      assert.strictEqual(
        status.liveConnections,
        0,
        `liveConnections must return to zero (got: ${status.liveConnections})`,
      );
      assert.strictEqual(
        status.inFlightHandshakes,
        0,
        `inFlightHandshakes must return to zero (got: ${status.inFlightHandshakes})`,
      );
      assert.strictEqual(
        status.activeAndServing,
        true,
        'Remote gateway must remain active and serving',
      );

      // Verify that following the storm, an authenticated client succeeds
      const customFetch = createMtlsFetch({
        caPath: pki.trustedCaCertPath,
        certPath: pki.clientCertPath,
        keyPath: pki.clientKeyPath,
      });

      const transport = new StreamableHTTPClientTransport(
        new URL(`https://localhost:${remote.port}/mcp`),
        { fetch: customFetch },
      );

      const client = new Client(
        { name: 'post-storm-client', version: '1.0.0' },
        { capabilities: {} },
      );
      await client.connect(transport);

      const healthRes = await client.callTool({ name: 'health', arguments: {} });
      assert.ok(healthRes.content[0].text, 'Authenticated tool call must succeed post-storm');
      const parsedHealth = JSON.parse(healthRes.content[0].text);
      assert.equal(parsedHealth.status, 'HEALTHY');
      assert.equal(parsedHealth.remoteGatewayActive, true);

      await client.close();
    } finally {
      await remote.cleanup();
    }
  });
});

// ============================================================================
// Positive Acceptance Flows: RC08-FLOW-01 through RC08-FLOW-04
// ============================================================================

describe('RC-08 Task 1: Positive Acceptance Flows (RC08-FLOW-01..RC08-FLOW-04)', () => {
  test('RC08-FLOW-01: Official MCP SDK Stdio Session - initialize, 25 tools listed, health tool execution, clean exit', async () => {
    const ws = path.join(tempRoot, 'flow-01-ws');
    fs.mkdirSync(ws, { recursive: true });
    const auditConfig = createAuditConfig(tempRoot, 'flow-01');

    const runnerCode = `
      import { createArcMcpServer } from './apps/mcp-server/dist/index.js';
      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'workspace', path: ${JSON.stringify(ws)} }],
        defaultWorkspaceId: 'workspace',
        audit: ${JSON.stringify(auditConfig)}
      });
      await server.start();
    `;

    const transport = new StdioClientTransport({
      command: 'node',
      args: ['--input-type=module', '-e', runnerCode],
      cwd: process.cwd(),
    });

    const client = new Client(
      { name: 'official-sdk-stdio-client', version: '1.0.0' },
      { capabilities: {} },
    );
    await client.connect(transport);

    // 1. List tools and verify exact 25 production tools
    const toolsResult = await client.listTools();
    assert.equal(toolsResult.tools.length, 25, 'Must advertise exactly 25 production tools');

    const expectedNames = ALL_TOOL_DEFINITIONS.map((t) => t.name).sort();
    const actualNames = toolsResult.tools.map((t) => t.name).sort();
    assert.deepEqual(
      actualNames,
      expectedNames,
      'Advertised tool names must match production catalog',
    );

    // 2. Call health tool
    const healthResult = await client.callTool({ name: 'health', arguments: {} });
    assert.ok(healthResult.content && healthResult.content.length > 0);
    const parsedHealth = JSON.parse(healthResult.content[0].text);
    assert.equal(parsedHealth.status, 'HEALTHY');
    assert.equal(parsedHealth.version, '0.8.0-rc08');
    assert.equal(parsedHealth.stage, 'RC-08');
    assert.equal(parsedHealth.transportMode, 'stdio');
    assert.equal(parsedHealth.remoteGatewayActive, false);
    assert.equal(parsedHealth.policyEngineActive, true);
    assert.equal(parsedHealth.auditActive, true);

    // 3. Clean exit
    await client.close();
  });

  test('RC08-FLOW-02: Official MCP SDK Streamable HTTP Session - mTLS TLS 1.3, session establish, 25 tools listed, health execution, clean close', async () => {
    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'flow-02',
      enrolledClientCertPaths: [pki.clientCertPath],
    });

    try {
      const customFetch = createMtlsFetch({
        caPath: pki.trustedCaCertPath,
        certPath: pki.clientCertPath,
        keyPath: pki.clientKeyPath,
      });

      const transport = new StreamableHTTPClientTransport(
        new URL(`https://localhost:${remote.port}/mcp`),
        { fetch: customFetch },
      );

      const client = new Client(
        { name: 'official-sdk-http-client', version: '1.0.0' },
        { capabilities: {} },
      );
      await client.connect(transport);

      // Verify session was minted and captured
      assert.ok(customFetch.getSessionId(), 'Session ID must be established on mTLS initialize');
      assert.ok(
        customFetch.getSessionToken(),
        'Session token must be established on mTLS initialize',
      );

      // 1. List tools
      const toolsResult = await client.listTools();
      assert.equal(
        toolsResult.tools.length,
        25,
        'Remote client must receive exactly 25 production tools',
      );

      // 2. Call health tool over remote transport
      const healthResult = await client.callTool({ name: 'health', arguments: {} });
      const parsedHealth = JSON.parse(healthResult.content[0].text);
      assert.equal(parsedHealth.status, 'HEALTHY');
      assert.equal(parsedHealth.version, '0.8.0-rc08');
      assert.equal(parsedHealth.stage, 'RC-08');
      assert.equal(parsedHealth.transportMode, 'remote');
      assert.equal(parsedHealth.remoteGatewayActive, true);
      assert.equal(parsedHealth.authenticationActive, true);
      assert.equal(parsedHealth.enrolledDevicesCount, 1);
      assert.equal(parsedHealth.activeSessionsCount, 1);

      // 3. Clean close
      await client.close();
    } finally {
      await remote.cleanup();
    }
  });

  test('RC08-FLOW-03: Independent Raw JSON-RPC Client Flow - zero SDK imports, full protocol verification, 25 tool schemas, clean exit', async () => {
    const { proc, cleanup } = spawnArcStdioServerProcess({
      tempDir: tempRoot,
      label: 'flow-03',
    });
    const rawClient = new RawJsonRpcStdioClient(proc);

    try {
      // 1. JSON-RPC Handshake negotiation
      const initRes = await rawClient.request('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'raw-cleanroom-client', version: '1.0.0' },
      });

      assert.equal(initRes.jsonrpc, '2.0', 'Envelop must be JSON-RPC 2.0');
      assert.ok(initRes.result, 'Handshake must yield result');
      assert.equal(initRes.result.protocolVersion, '2025-11-25');
      assert.equal(initRes.result.serverInfo?.name, 'cesspace-arc');
      assert.equal(initRes.result.serverInfo?.version, '0.8.0-rc08');
      assert.ok(initRes.result.capabilities?.tools, 'Server must advertise tools capability');

      // Send initialized notification per MCP specification
      rawClient.notify('notifications/initialized', {});

      // 2. Query tools/list and validate JSON schema compliance
      const toolsRes = await rawClient.request('tools/list', {});
      assert.equal(toolsRes.jsonrpc, '2.0');
      assert.ok(Array.isArray(toolsRes.result?.tools));
      assert.equal(toolsRes.result.tools.length, 25, 'Raw client must discover exactly 25 tools');

      for (const tool of toolsRes.result.tools) {
        assert.ok(
          typeof tool.name === 'string' && tool.name.length > 0,
          'Tool must have valid name',
        );
        assert.ok(typeof tool.description === 'string', 'Tool must have valid description');
        assert.ok(
          tool.inputSchema && typeof tool.inputSchema === 'object',
          'Tool must have inputSchema',
        );
        assert.equal(tool.inputSchema.type, 'object', 'Tool inputSchema type must be object');
      }

      // 3. Execute health tool call
      const healthRes = await rawClient.request('tools/call', {
        name: 'health',
        arguments: {},
      });
      assert.equal(healthRes.jsonrpc, '2.0');
      assert.ok(healthRes.result?.content, 'Tool call must return content array');
      const payload = JSON.parse(healthRes.result.content[0].text);
      assert.equal(payload.status, 'HEALTHY');
      assert.equal(payload.version, '0.8.0-rc08');
      assert.equal(payload.stage, 'RC-08');
      assert.equal(payload.transportMode, 'stdio');
    } finally {
      rawClient.close();
      await cleanup();
    }
  });

  test('RC08-FLOW-04: Multi-Session Client Concurrency - multiple concurrent remote sessions, isolated execution without cross-talk', async () => {
    // Generate two additional client certificates for concurrency test
    const clientCert2 = pki.issueTrustedClientCert({ commonName: 'client-concurrency-2' });
    const clientCert3 = pki.issueTrustedClientCert({ commonName: 'client-concurrency-3' });

    const remote = await startTestRemoteServer({
      tempDir: tempRoot,
      pki,
      tag: 'flow-04',
      enrolledClientCertPaths: [pki.clientCertPath, clientCert2.certPath, clientCert3.certPath],
    });

    try {
      const clientConfigs = [
        { cert: pki.clientCertPath, key: pki.clientKeyPath, name: 'concurrent-client-1' },
        { cert: clientCert2.certPath, key: clientCert2.keyPath, name: 'concurrent-client-2' },
        { cert: clientCert3.certPath, key: clientCert3.keyPath, name: 'concurrent-client-3' },
      ];

      // Run 3 independent clients concurrently
      const sessionResults = await Promise.all(
        clientConfigs.map(async (cfg) => {
          const customFetch = createMtlsFetch({
            caPath: pki.trustedCaCertPath,
            certPath: cfg.cert,
            keyPath: cfg.key,
          });

          const transport = new StreamableHTTPClientTransport(
            new URL(`https://localhost:${remote.port}/mcp`),
            { fetch: customFetch },
          );

          const client = new Client({ name: cfg.name, version: '1.0.0' }, { capabilities: {} });
          await client.connect(transport);

          const sessionId = customFetch.getSessionId();
          const sessionToken = customFetch.getSessionToken();

          const toolsRes = await client.listTools();
          const healthRes = await client.callTool({ name: 'health', arguments: {} });
          const parsed = JSON.parse(healthRes.content[0].text);

          await client.close();

          return {
            clientName: cfg.name,
            sessionId,
            sessionToken,
            toolsCount: toolsRes.tools.length,
            status: parsed.status,
            activeSessions: parsed.activeSessionsCount,
          };
        }),
      );

      // Verify all 3 sessions succeeded
      assert.equal(sessionResults.length, 3);
      const sessionIds = new Set(sessionResults.map((r) => r.sessionId));
      assert.equal(sessionIds.size, 3, 'Each concurrent client must receive a distinct session ID');

      for (const res of sessionResults) {
        assert.equal(res.toolsCount, 25, 'Each client must discover exactly 25 tools');
        assert.equal(res.status, 'HEALTHY', 'Each client must receive healthy status');
      }
    } finally {
      await remote.cleanup();
    }
  });
});
