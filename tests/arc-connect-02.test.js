import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  loadClaudeConfig,
  planClaudeConfig,
  planClaudeDisconnect,
  resolveClaudeDesktopConfigPath,
} from '../scripts/arc-connect-claude.mjs';
import {
  forwardMcpMessage,
  readPrivateBearerToken,
  resolveClaudeProxyConfig,
} from '../scripts/arc-connect-claude-proxy.mjs';

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

test('ARC-CONNECT-02: resolves the Claude Desktop local config path without network or account state', () => {
  const root = tempRoot('arc-connect02-path-');
  try {
    assert.equal(
      resolveClaudeDesktopConfigPath({ HOME: root }, 'linux'),
      path.join(root, '.config', 'Claude', 'claude_desktop_config.json'),
    );
    const xdg = path.join(root, 'xdg');
    assert.equal(
      resolveClaudeDesktopConfigPath({ HOME: root, XDG_CONFIG_HOME: xdg }, 'linux'),
      path.join(xdg, 'Claude', 'claude_desktop_config.json'),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-CONNECT-02: merges only the cesspace-arc entry and writes no secret-bearing client configuration', () => {
  const launcher = '/home/example/.local/cesspace-arc/bin/cesspace-arc';
  const original = {
    theme: 'dark',
    mcpServers: {
      existing: { command: '/usr/bin/example', args: ['serve'] },
    },
  };
  const plan = planClaudeConfig({ config: original, launcherPath: launcher });
  assert.equal(plan.changed, true);
  assert.deepEqual(plan.config.theme, 'dark');
  assert.deepEqual(plan.config.mcpServers.existing, original.mcpServers.existing);
  assert.deepEqual(plan.config.mcpServers['cesspace-arc'], {
    command: launcher,
    args: ['proxy', 'claude'],
  });
  assert.equal('env' in plan.config.mcpServers['cesspace-arc'], false);
  const serialized = JSON.stringify(plan.config);
  assert.doesNotMatch(serialized, /Bearer|token|secret|api[_-]?key/i);
});

test('ARC-CONNECT-02: idempotent connect and owned-only disconnect preserve unrelated MCP entries', () => {
  const launcher = '/opt/cesspace-arc/bin/cesspace-arc';
  const first = planClaudeConfig({ config: { mcpServers: {} }, launcherPath: launcher });
  const second = planClaudeConfig({ config: first.config, launcherPath: launcher });
  assert.equal(second.changed, false);

  const withOther = {
    ...first.config,
    mcpServers: {
      ...first.config.mcpServers,
      other: { command: '/bin/other' },
    },
  };
  const disconnected = planClaudeDisconnect({ config: withOther, launcherPath: launcher });
  assert.equal(disconnected.changed, true);
  assert.equal('cesspace-arc' in disconnected.config.mcpServers, false);
  assert.deepEqual(disconnected.config.mcpServers.other, { command: '/bin/other' });

  assert.throws(
    () =>
      planClaudeDisconnect({
        config: {
          mcpServers: {
            'cesspace-arc': { command: '/tmp/not-ours', args: [] },
          },
        },
        launcherPath: launcher,
      }),
    /Refusing to remove/,
  );
});

test('ARC-CONNECT-02: conflicting Claude entry requires explicit force', () => {
  const launcher = '/opt/cesspace-arc/bin/cesspace-arc';
  const config = {
    mcpServers: {
      'cesspace-arc': { command: '/tmp/custom-wrapper', args: ['custom'] },
    },
  };
  assert.throws(
    () => planClaudeConfig({ config, launcherPath: launcher }),
    /already has a different cesspace-arc MCP entry/,
  );
  const forced = planClaudeConfig({ config, launcherPath: launcher, force: true });
  assert.deepEqual(forced.config.mcpServers['cesspace-arc'], {
    command: launcher,
    args: ['proxy', 'claude'],
  });
});

test('ARC-CONNECT-02: refuses unsafe Claude config files and accepts an owner-safe config', () => {
  const root = tempRoot('arc-connect02-config-');
  try {
    const dir = path.join(root, 'Claude');
    fs.mkdirSync(dir);
    const config = path.join(dir, 'claude_desktop_config.json');
    fs.writeFileSync(config, '{}\n', { mode: 0o600 });
    fs.chmodSync(config, 0o600);
    assert.deepEqual(loadClaudeConfig(config).config, {});

    fs.chmodSync(config, 0o666);
    assert.throws(() => loadClaudeConfig(config), /must not be group\/world writable/);
    fs.chmodSync(config, 0o600);

    const link = path.join(dir, 'linked.json');
    fs.symlinkSync(config, link);
    assert.throws(() => loadClaudeConfig(link), /regular non-linked/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-CONNECT-02: local proxy accepts only loopback /mcp targets and owner-only token files', () => {
  const root = tempRoot('arc-connect02-proxy-');
  try {
    const tokenPath = path.join(root, 'arc-token');
    const token = 'a'.repeat(64);
    fs.writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    fs.chmodSync(tokenPath, 0o600);
    assert.equal(readPrivateBearerToken(tokenPath), token);

    assert.deepEqual(
      resolveClaudeProxyConfig({
        HOME: root,
        CESSPACE_ARC_CLAUDE_TOKEN_FILE: tokenPath,
        CESSPACE_ARC_CLAUDE_PROXY_ENDPOINT: 'http://127.0.0.1:4318/mcp',
      }),
      { endpoint: 'http://127.0.0.1:4318/mcp', tokenFile: tokenPath },
    );
    assert.throws(
      () =>
        resolveClaudeProxyConfig({
          HOME: root,
          CESSPACE_ARC_CLAUDE_TOKEN_FILE: tokenPath,
          CESSPACE_ARC_CLAUDE_PROXY_ENDPOINT: 'https://example.com/mcp',
        }),
      /loopback HTTP \/mcp URL/,
    );

    fs.chmodSync(tokenPath, 0o644);
    assert.throws(() => readPrivateBearerToken(tokenPath), /owner-only permissions/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-CONNECT-02: stdio bridge forwards authentication and server-generated MCP session state', async () => {
  const calls = [];
  const fetchImpl = async (_url, options) => {
    calls.push(options);
    const request = JSON.parse(options.body);
    if (request.method === 'initialize') {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: request.id,
          result: {
            protocolVersion: '2024-11-05',
            serverInfo: { name: 'cesspace-arc', version: '1.0.0' },
            capabilities: { tools: {} },
          },
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Mcp-Session-Id': 'chatgpt-sess-test123',
          },
        },
      );
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { tools: [] } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const init = await forwardMcpMessage({
    endpoint: 'http://127.0.0.1:4318/mcp',
    token: 'b'.repeat(64),
    sessionId: null,
    message: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    fetchImpl,
  });
  assert.equal(init.sessionId, 'chatgpt-sess-test123');

  await forwardMcpMessage({
    endpoint: 'http://127.0.0.1:4318/mcp',
    token: 'b'.repeat(64),
    sessionId: init.sessionId,
    message: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    fetchImpl,
  });

  assert.equal(calls[0].headers.Authorization, `Bearer ${'b'.repeat(64)}`);
  assert.equal('Mcp-Session-Id' in calls[0].headers, false);
  assert.equal(calls[1].headers['Mcp-Session-Id'], 'chatgpt-sess-test123');
});

test('ARC-CONNECT-02: installed launcher preserves stdio default and exposes Claude connect/status/disconnect/proxy commands', () => {
  const source = fs.readFileSync(path.resolve('scripts/arc10-distribution-lib.mjs'), 'utf8');
  assert.match(source, /arc-connect-claude\.mjs/);
  assert.match(source, /arc-connect-claude-proxy\.mjs/);
  assert.match(source, /cesspace-arc connect <chatgpt\|claude>/);
  assert.match(source, /\$ACTION claude/);
  assert.match(source, /Usage: cesspace-arc proxy claude/);
  assert.match(source, /arc-integration-stdio\.mjs/);
});

test('ARC-CONNECT-02: server-owned credentials produce distinct ChatGPT and Claude actors', async () => {
  const { ChatGptAuthBridge } = await import('../apps/mcp-server/dist/chatgpt-auth-bridge.js');
  const bridge = new ChatGptAuthBridge({
    expectedToken: 'chatgpt-credential',
    additionalCredentials: [
      {
        expectedToken: 'claude-credential',
        actor: {
          clientId: 'claude-client',
          clientType: 'claude-local',
          deviceId: 'claude-desktop-local',
        },
        sessionPrefix: 'claude-sess',
      },
    ],
    sink: {
      async executeAuthenticatedToolCall() {
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    },
  });

  const chatgpt = bridge.createSession('Bearer chatgpt-credential');
  const claude = bridge.createSession('Bearer claude-credential');
  assert.match(chatgpt.sessionId, /^chatgpt-sess-/);
  assert.match(claude.sessionId, /^claude-sess-/);

  const chatgptRecord = bridge.validateSession(chatgpt.sessionId, 'Bearer chatgpt-credential');
  const claudeRecord = bridge.validateSession(claude.sessionId, 'Bearer claude-credential');
  assert.deepEqual(chatgptRecord.actor, {
    clientId: 'chatgpt-client',
    clientType: 'chatgpt-remote',
    deviceId: 'chatgpt-tunnel-gateway',
  });
  assert.deepEqual(claudeRecord.actor, {
    clientId: 'claude-client',
    clientType: 'claude-local',
    deviceId: 'claude-desktop-local',
  });
  assert.throws(
    () => bridge.validateSession(claude.sessionId, 'Bearer chatgpt-credential'),
    /credential binding mismatch|Authentication required/i,
  );
});

test('ARC-CONNECT-02: private adapter launcher has clean signal shutdown and optional Claude credential wiring', () => {
  const source = fs.readFileSync(
    path.resolve('scripts/arc-integration-chatgpt-private.mjs'),
    'utf8',
  );
  assert.match(source, /CESSPACE_ARC_CLAUDE_TOKEN_FILE/);
  assert.match(source, /process\.once\('SIGTERM'/);
  assert.match(source, /await server\.stop\(\)/);
});

test('ARC-CONNECT-02: private profile validates a distinct owner-only Claude token selector', async () => {
  const { resolveChatGptRemoteConfig } = await import('../apps/mcp-server/dist/chatgpt-profile.js');
  const root = tempRoot('arc-connect02-profile-');
  try {
    const chatgptToken = path.join(root, 'chatgpt-token');
    const claudeToken = path.join(root, 'claude-token');
    fs.writeFileSync(chatgptToken, 'a'.repeat(64) + '\n', { mode: 0o600 });
    fs.writeFileSync(claudeToken, 'b'.repeat(64) + '\n', { mode: 0o600 });
    fs.chmodSync(chatgptToken, 0o600);
    fs.chmodSync(claudeToken, 0o600);

    const resolved = resolveChatGptRemoteConfig({
      enabled: true,
      bindHost: '127.0.0.1',
      port: 4318,
      authTokenPath: chatgptToken,
      claudeLocalAuthTokenPath: claudeToken,
    });
    assert.equal(resolved.expectedToken, 'a'.repeat(64));
    assert.equal(resolved.expectedClaudeLocalToken, 'b'.repeat(64));

    fs.writeFileSync(claudeToken, 'a'.repeat(64) + '\n', { mode: 0o600 });
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          bindHost: '127.0.0.1',
          port: 4318,
          authTokenPath: chatgptToken,
          claudeLocalAuthTokenPath: claudeToken,
        }),
      /must be distinct/,
    );

    fs.writeFileSync(claudeToken, 'b'.repeat(64) + '\n', { mode: 0o644 });
    fs.chmodSync(claudeToken, 0o644);
    assert.throws(
      () =>
        resolveChatGptRemoteConfig({
          enabled: true,
          bindHost: '127.0.0.1',
          port: 4318,
          authTokenPath: chatgptToken,
          claudeLocalAuthTokenPath: claudeToken,
        }),
      /owner-only permissions/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
