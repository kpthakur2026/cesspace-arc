/**
 * CesSpace ARC — ChatGPT Remote MCP Integration Test Suite
 *
 * Covers:
 * - TASK 7: Security Negative Controls (Controls 1 through 22)
 *   - NEG-01 to NEG-15: Baseline transport, boundary, and catalog controls
 *   - NEG-16 to NEG-22: Server-authoritative session, anti-synthesis, and credential binding controls
 * - TASK 8: Positive Flows (Flows 1 through 6)
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile as execFileCallback, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

import {
  createArcMcpServer,
  ALL_TOOL_DEFINITIONS,
  ChatGptAuthBridge,
  ChatGptRemoteAdapter,
  resolveChatGptRemoteConfig,
} from '../apps/mcp-server/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';

const execFile = promisify(execFileCallback);

let tempRoot;
let workspaceDir;
let authTokenPath;
let validToken;
let auditConfig;

before(() => {
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-chatgpt-test-'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });

  // Initialize a real git workspace
  execFileSync('git', ['init', '-b', 'main', '--quiet'], { cwd: workspaceDir });
  execFileSync('git', ['config', 'user.name', 'ARC ChatGPT Test'], { cwd: workspaceDir });
  execFileSync('git', ['config', 'user.email', 'arc-chatgpt@example.invalid'], {
    cwd: workspaceDir,
  });
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# ChatGPT Integration Test\n');
  fs.writeFileSync(path.join(workspaceDir, 'sample.txt'), 'hello from arc workspace\n');
  execFileSync('git', ['add', '.'], { cwd: workspaceDir });
  execFileSync('git', ['commit', '--quiet', '-m', 'initial commit'], { cwd: workspaceDir });

  // Create token file with secure permissions (mode 0600)
  validToken = `test-bearer-token-${crypto.randomBytes(16).toString('hex')}`;
  authTokenPath = path.join(tempRoot, 'chatgpt-token.txt');
  fs.writeFileSync(authTokenPath, `${validToken}\n`, { mode: 0o600 });
  fs.chmodSync(authTokenPath, 0o600);

  auditConfig = createAuditConfig(tempRoot, 'chatgpt-audit');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
});

/**
 * Helper to make HTTP requests to the ChatGPT adapter.
 */
function sendHttpRequest(port, options = {}) {
  const { method = 'POST', path: reqPath = '/mcp', headers = {}, body = null } = options;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk.toString('utf8');
        });
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = JSON.parse(raw);
          } catch {
            // non-json body
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            raw,
            body: parsed,
          });
        });
      },
    );

    req.on('error', (err) => {
      reject(err);
    });

    if (body !== null) {
      if (typeof body === 'string') {
        req.write(body);
      } else {
        req.write(JSON.stringify(body));
      }
    }

    req.end();
  });
}

/**
 * Helper to initialize a server-authoritative MCP session.
 */
async function initializeSession(port, token = validToken) {
  const res = await sendHttpRequest(port, {
    headers: { Authorization: `Bearer ${token}` },
    body: {
      jsonrpc: '2.0',
      id: 'init-handshake',
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {} },
    },
  });
  assert.equal(res.statusCode, 200);
  const sessionId = res.headers['mcp-session-id'] || res.body?.result?.sessionId;
  assert.ok(sessionId, 'initialize must yield server-generated Mcp-Session-Id');
  return sessionId;
}

describe('TASK 7 — Security Negative Controls', () => {
  test('NEG-01: remote profile disabled by default and opens no listener', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
    });
    await server.start();
    try {
      const chatgptStatus = server.getChatGptAdapterStatus();
      assert.equal(typeof chatgptStatus, 'undefined');
    } finally {
      await server.stop();
    }
  });

  test('NEG-02: listener cannot start with incomplete or insecure auth configuration', () => {
    // Missing authTokenPath
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          port: 4040,
        }),
      /authTokenPath.*required/i,
    );

    // Non-existent token file
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          port: 4040,
          authTokenPath: path.join(tempRoot, 'does-not-exist.txt'),
        }),
      /ENOENT|missing or unreadable|does not exist/i,
    );

    // Insecure token file permissions (mode 0666)
    const insecureTokenPath = path.join(tempRoot, 'insecure-token.txt');
    fs.writeFileSync(insecureTokenPath, 'secret\n', { mode: 0o666 });
    fs.chmodSync(insecureTokenPath, 0o666);
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          port: 4040,
          authTokenPath: insecureTokenPath,
        }),
      /mode 0600\/0400 required|readable or writable by group/i,
    );

    // Empty token file
    const emptyTokenPath = path.join(tempRoot, 'empty-token.txt');
    fs.writeFileSync(emptyTokenPath, '', { mode: 0o600 });
    fs.chmodSync(emptyTokenPath, 0o600);
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          port: 4040,
          authTokenPath: emptyTokenPath,
        }),
      /empty/i,
    );

    // Prohibited wildcard bind (0.0.0.0 or ::)
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          bindHost: '0.0.0.0',
          port: 4040,
          authTokenPath,
        }),
      /wildcard.*prohibited/i,
    );
  });

  test('NEG-03: unauthenticated request is denied with 401 UNAUTHENTICATED', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();
    assert.ok(status && status.active);

    try {
      const res = await sendHttpRequest(status.port, {
        body: {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: {},
        },
      });
      assert.equal(res.statusCode, 401);
      assert.equal(res.body?.error?.message, 'UNAUTHENTICATED');
    } finally {
      await server.stop();
    }
  });

  test('NEG-04: invalid session token or invalid session header is denied', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      // Wrong bearer token
      const resWrongToken = await sendHttpRequest(status.port, {
        headers: { Authorization: 'Bearer definitely-invalid-token' },
        body: {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/list',
          params: {},
        },
      });
      assert.equal(resWrongToken.statusCode, 401);

      // Malformed Mcp-Session-Id header with valid token
      const resBadSession = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': 'illegal;session!id*with*punctuation',
        },
        body: {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/list',
          params: {},
        },
      });
      assert.equal(resBadSession.statusCode, 400);
      assert.equal(resBadSession.body?.error?.message, 'INVALID_SESSION_TOKEN');
    } finally {
      await server.stop();
    }
  });

  test('NEG-05: workspace escape is denied by security kernel', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: {
              path: '../../../../etc/passwd',
            },
          },
        },
      });

      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, true);
      const text = res.body?.result?.content?.[0]?.text ?? '';
      assert.match(
        text,
        /PATH_ESCAPES_ROOT|ACCESS_DENIED|POLICY_DENIED|canonical workspace-relative form/i,
      );
    } finally {
      await server.stop();
    }
  });

  test('NEG-06: protected branch mutation is denied by policy engine', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: {
            name: 'create_file',
            arguments: {
              path: 'unapproved.txt',
              content: 'should be denied without approval token',
            },
          },
        },
      });

      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, true);
      const text = res.body?.result?.content?.[0]?.text ?? '';
      assert.match(text, /APPROVAL_REQUIRED|POLICY_DENIED/i);
    } finally {
      await server.stop();
    }
  });

  test('NEG-07: direct subsystem bypass is impossible (adapter has no direct subsystem references)', () => {
    const bridge = new ChatGptAuthBridge({
      expectedToken: validToken,
      sink: {
        executeAuthenticatedToolCall: async () => ({ content: [] }),
      },
    });
    const adapter = new ChatGptRemoteAdapter({
      config: {
        enabled: false,
        port: 8443,
        authTokenPath,
      },
      bridge,
    });

    assert.equal(typeof adapter.filesystemSubsystem, 'undefined');
    assert.equal(typeof adapter.gitSubsystem, 'undefined');
    assert.equal(typeof adapter.terminalSubsystem, 'undefined');
    assert.equal(typeof adapter.processRegistry, 'undefined');
  });

  test('NEG-08: audit failure blocks privileged execution', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);

      // Force degrade audit runtime
      const access = server['auditRuntime'];
      if (access && typeof access.latchDegradedAuditFailure === 'function') {
        access.latchDegradedAuditFailure();
      }

      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 6,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });

      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, true);
    } finally {
      await server.stop();
    }
  });

  test('NEG-09: oversized request is rejected with 413 Payload Too Large', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
        maxRequestBodyBytes: 2048, // 2 KiB limit for testing
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const largePayload = 'a'.repeat(4096);
      const res = await sendHttpRequest(status.port, {
        headers: { Authorization: `Bearer ${validToken}` },
        body: {
          jsonrpc: '2.0',
          id: 7,
          method: 'tools/list',
          padding: largePayload,
        },
      });
      assert.equal(res.statusCode, 413);
    } finally {
      await server.stop();
    }
  });

  test('NEG-10: unknown tool is rejected with -32601 tool not found', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 8,
          method: 'tools/call',
          params: {
            name: 'unknown_and_unregistered_tool',
            arguments: {},
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.error?.code, -32601);
      assert.match(res.body?.error?.message ?? '', /unknown_and_unregistered_tool/i);
    } finally {
      await server.stop();
    }
  });

  test('NEG-11: malformed MCP payloads (non-JSON, batching, deep nesting) are rejected', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      // 1. Non-JSON body -> -32700
      const resParseError = await sendHttpRequest(status.port, {
        headers: { Authorization: `Bearer ${validToken}` },
        body: '{ malformed json: not valid ]',
      });
      assert.equal(resParseError.statusCode, 400);
      assert.equal(resParseError.body?.error?.code, -32700);

      // 2. Batching array -> -32600
      const resBatch = await sendHttpRequest(status.port, {
        headers: { Authorization: `Bearer ${validToken}` },
        body: [
          { jsonrpc: '2.0', id: 1, method: 'ping' },
          { jsonrpc: '2.0', id: 2, method: 'ping' },
        ],
      });
      assert.equal(resBatch.statusCode, 400);
      assert.equal(resBatch.body?.error?.code, -32600);
      assert.match(resBatch.body?.error?.message ?? '', /batching is not supported/i);

      // 3. Deeply nested JSON -> -32600
      let deepObj = { leaf: true };
      for (let i = 0; i < 70; i++) {
        deepObj = { nest: deepObj };
      }
      const resDeep = await sendHttpRequest(status.port, {
        headers: { Authorization: `Bearer ${validToken}` },
        body: deepObj,
      });
      assert.equal(resDeep.statusCode, 400);
      assert.equal(resDeep.body?.error?.code, -32600);
      assert.match(resDeep.body?.error?.message ?? '', /nesting exceeds/i);
    } finally {
      await server.stop();
    }
  });

  test('NEG-12: remote request cannot override authorized root', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 9,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: {
              path: 'sample.txt',
              workspaceId: 'unauthorized-random-workspace-id',
            },
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, true);
      const text = res.body?.result?.content?.[0]?.text ?? '';
      assert.match(
        text,
        /unauthorized-random-workspace-id|ACCESS_DENIED|POLICY_DENIED|Workspace selector is not registered/i,
      );
    } finally {
      await server.stop();
    }
  });

  test('NEG-13: secrets are not accepted in unsafe CLI/argv locations', async () => {
    const secretValue = 'synthetic-secret-token-abcdef123456';
    for (const flag of ['--token', '--chatgpt-token', '--bearer', '--secret']) {
      try {
        await execFile(process.execPath, ['apps/cli/dist/index.js', flag, secretValue], {
          encoding: 'utf8',
        });
        assert.fail(`CLI should have rejected flag ${flag}`);
      } catch (err) {
        assert.notEqual(err.code, 0);
        // Secret must not be echoed in error output
        const combined = `${err.stdout ?? ''} ${err.stderr ?? ''}`;
        assert.equal(combined.includes(secretValue), false);
      }
    }
  });

  test('NEG-14: local stdio mode remains unchanged and operational', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
    });
    assert.equal(server.getTransportMode(), 'stdio');
    const tools = server.getRegisteredTools();
    assert.equal(tools.length, 25);
  });

  test('NEG-15: remote adapter does not create a second tool catalog', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 10,
          method: 'tools/list',
          params: {},
        },
      });

      assert.equal(res.statusCode, 200);
      const exposedTools = res.body?.result?.tools;
      assert.ok(Array.isArray(exposedTools));
      assert.equal(exposedTools.length, 25);

      const exposedNames = exposedTools.map((t) => t.name).sort();
      const canonicalNames = ALL_TOOL_DEFINITIONS.map((t) => t.name).sort();
      assert.deepEqual(exposedNames, canonicalNames);
    } finally {
      await server.stop();
    }
  });

  test('NEG-16: arbitrary client-supplied Mcp-Session-Id is rejected', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      // Client presents an arbitrary unminted session ID without calling initialize
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': 'client-invented-untrusted-session-id',
        },
        body: {
          jsonrpc: '2.0',
          id: 16,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.body?.error?.message, 'INVALID_SESSION_TOKEN');
    } finally {
      await server.stop();
    }
  });

  test('NEG-17: unknown session rejected', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': 'chatgpt-sess-0000000000000000',
        },
        body: {
          jsonrpc: '2.0',
          id: 17,
          method: 'tools/list',
          params: {},
        },
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.body?.error?.message, 'INVALID_SESSION_TOKEN');
    } finally {
      await server.stop();
    }
  });

  test('NEG-18: deleted/revoked session cannot execute', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);

      // Close the session via DELETE /mcp
      const delRes = await sendHttpRequest(status.port, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
      });
      assert.equal(delRes.statusCode, 200);
      assert.equal(delRes.body?.result?.sessionClosed, true);

      // Attempting to execute tool with the closed session must fail
      const toolRes = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 18,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });
      assert.equal(toolRes.statusCode, 400);
      assert.equal(toolRes.body?.error?.message, 'INVALID_SESSION_TOKEN');
    } finally {
      await server.stop();
    }
  });

  test('NEG-19: bearer token alone does not allow adapter to synthesize CompleteActor', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      // Calling tools/call without Mcp-Session-Id must not execute
      const res = await sendHttpRequest(status.port, {
        headers: { Authorization: `Bearer ${validToken}` },
        body: {
          jsonrpc: '2.0',
          id: 19,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.body?.error?.message, 'INVALID_SESSION_TOKEN');
    } finally {
      await server.stop();
    }
  });

  test('NEG-20: adapter source contains no authenticated:true actor construction', () => {
    const adapterSource = fs.readFileSync(
      path.join(process.cwd(), 'apps/mcp-server/src/chatgpt-remote-adapter.ts'),
      'utf8',
    );
    // Strip comments to ensure code lines contain no actor synthesis
    const codeOnly = adapterSource.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '');
    assert.equal(
      /authenticated\s*:\s*true/.test(codeOnly),
      false,
      'chatgpt-remote-adapter.ts must not contain authenticated: true',
    );
    assert.equal(
      /CompleteActor/.test(codeOnly),
      false,
      'chatgpt-remote-adapter.ts must not reference CompleteActor',
    );
  });

  test('NEG-21: forged clientId/deviceId/sessionId parameters remain rejected', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 21,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: {
              path: 'sample.txt',
              clientId: 'spoofed-admin-client',
              deviceId: 'spoofed-root-device',
            },
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.error?.code, -32602);
      assert.match(res.body?.error?.message ?? '', /reserved actor or transport/i);
    } finally {
      await server.stop();
    }
  });

  test('NEG-22: session is bound to the authenticated transport credential/context', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);

      // Presenting a valid session ID with wrong authorization header fails
      const resWrongToken = await sendHttpRequest(status.port, {
        headers: {
          Authorization: 'Bearer wrong-bearer-token',
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 22,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });
      assert.equal(resWrongToken.statusCode, 401);
      assert.equal(resWrongToken.body?.error?.message, 'UNAUTHENTICATED');
    } finally {
      await server.stop();
    }
  });
});

describe('TASK 8 — Positive Acceptance Flows', () => {
  test('FLOW-01: authenticated remote health request succeeds', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      // 1. Health probe on /health
      const probeRes = await sendHttpRequest(status.port, {
        path: '/health',
        method: 'GET',
        headers: { Authorization: `Bearer ${validToken}` },
      });
      assert.equal(probeRes.statusCode, 200);
      assert.equal(probeRes.body?.status, 'ok');
      assert.equal(probeRes.body?.profile, 'chatgpt-remote');

      // 2. Health tool via JSON-RPC
      const sessionId = await initializeSession(status.port);
      const toolRes = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 101,
          method: 'tools/call',
          params: {
            name: 'health',
            arguments: {},
          },
        },
      });
      assert.equal(toolRes.statusCode, 200);
      assert.equal(toolRes.body?.result?.isError, false);
      const healthData = JSON.parse(toolRes.body?.result?.content?.[0]?.text ?? '{}');
      assert.equal(healthData.status, 'HEALTHY');
    } finally {
      await server.stop();
    }
  });

  test('FLOW-02: authenticated tool listing returns all 25 tools', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 102,
          method: 'tools/list',
          params: {},
        },
      });
      assert.equal(res.statusCode, 200);
      const tools = res.body?.result?.tools;
      assert.equal(tools.length, 25);
    } finally {
      await server.stop();
    }
  });

  test('FLOW-03: read-only file operation inside authorized workspace succeeds', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 103,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'sample.txt' },
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, false);
      const payload = JSON.parse(res.body?.result?.content?.[0]?.text ?? '{}');
      assert.equal(payload.content, 'hello from arc workspace\n');
    } finally {
      await server.stop();
    }
  });

  test('FLOW-04: git status read operation succeeds', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 104,
          method: 'tools/call',
          params: {
            name: 'git_status',
            arguments: {},
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, false);
    } finally {
      await server.stop();
    }
  });

  test('FLOW-05: approved/bounded execution flow records audit with remote actor', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
      chatgpt: {
        enabled: true,
        bindHost: '127.0.0.1',
        port: 0,
        authTokenPath,
      },
    });
    await server.start();
    const status = server.getChatGptAdapterStatus();

    try {
      const sessionId = await initializeSession(status.port);
      const res = await sendHttpRequest(status.port, {
        headers: {
          Authorization: `Bearer ${validToken}`,
          'Mcp-Session-Id': sessionId,
        },
        body: {
          jsonrpc: '2.0',
          id: 105,
          method: 'tools/call',
          params: {
            name: 'list_directory',
            arguments: {},
          },
        },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body?.result?.isError, false);

      // Verify audit trail captured the operation with server-generated session ID
      await server.flushAudit();
      const records = server.auditLogger.getRecords();
      const listRecord = records.find((r) => r.invocation?.toolName === 'list_directory');
      assert.ok(listRecord, 'Audit trail must contain list_directory record');
      assert.equal(listRecord.actor?.clientType, 'chatgpt-remote');
      assert.equal(listRecord.actor?.clientId, 'chatgpt-client');
      assert.equal(listRecord.actor?.sessionId, sessionId);
      assert.equal(listRecord.actor?.deviceId, 'chatgpt-tunnel-gateway');
    } finally {
      await server.stop();
    }
  });

  test('FLOW-06: stdio regression check succeeds', async () => {
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: workspaceDir }],
      defaultWorkspaceId: 'workspace',
      audit: auditConfig,
    });
    await server.start();

    try {
      const res = await server.dispatchToolCall('read_file', { path: 'sample.txt' });
      assert.equal(res.isError, undefined);
      const payload = JSON.parse(res.content[0].text);
      assert.equal(payload.content, 'hello from arc workspace\n');
    } finally {
      await server.stop();
    }
  });
});
