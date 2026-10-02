import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { resolvePrivateChatGptProfile } from '../scripts/arc-integration-chatgpt-private.mjs';

const root = process.cwd();

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

test('ARC-INTEGRATION-01: private ChatGPT profile requires a token-file selector', () => {
  assert.throws(
    () => resolvePrivateChatGptProfile({}),
    /CESSPACE_ARC_CHATGPT_TOKEN_FILE is required/,
  );
});

test('ARC-INTEGRATION-01: ChatGPT profile contains connection selectors only', () => {
  const resolved = resolvePrivateChatGptProfile({
    CESSPACE_ARC_CHATGPT_TOKEN_FILE: '/tmp/token-file',
    CESSPACE_ARC_CHATGPT_PORT: '4318',
    CESSPACE_ARC_CHATGPT_TUNNEL_HOSTNAME: 'arc.example.private',
  });

  assert.equal(resolved.enabled, true);
  assert.equal(resolved.bindHost, '127.0.0.1');
  assert.equal(resolved.port, 4318);
  assert.equal(resolved.authTokenPath, path.resolve('/tmp/token-file'));
  assert.equal(resolved.tunnelHostname, 'arc.example.private');
  assert.equal('expectedToken' in resolved, false);
  assert.equal('token' in resolved, false);
  assert.equal('workspace' in resolved, false);
  assert.equal('audit' in resolved, false);
});

test('ARC-INTEGRATION-01: launcher rejects malformed port selectors', () => {
  for (const value of ['0', '65536', '-1', 'abc', '43.18']) {
    assert.throws(
      () =>
        resolvePrivateChatGptProfile({
          CESSPACE_ARC_CHATGPT_TOKEN_FILE: '/tmp/token-file',
          CESSPACE_ARC_CHATGPT_PORT: value,
        }),
      /port|integer|between/i,
      value,
    );
  }
});

test('ARC-INTEGRATION-01: local MCP example launches from validated Core state', () => {
  const json = JSON.parse(read('examples/integrations/claude-local.mcp.json'));
  const profile = json.mcpServers?.['cesspace-arc'];
  assert.ok(profile);
  assert.equal(profile.command, 'node');
  assert.deepEqual(profile.args, [
    '/absolute/path/to/arc-prefix/runtime/scripts/arc-integration-stdio.mjs',
    '/absolute/path/to/arc-core-state',
  ]);
  assert.equal('env' in profile, false);
  assert.equal(JSON.stringify(profile).includes('token'), false);
});

test('ARC-INTEGRATION-01: both launchers use the neutral Core-state preflight projection', () => {
  const core = read('scripts/arc-integration-core-config.mjs');
  const stdio = read('scripts/arc-integration-stdio.mjs');
  const chatgpt = read('scripts/arc-integration-chatgpt-private.mjs');

  assert.match(core, /preflightCoreState/);
  assert.match(core, /toArcServerConfig/);
  assert.match(core, /require a Core state configured for stdio transport/);
  assert.match(core, /processStateDir/);
  assert.match(stdio, /resolveIntegrationCoreServerConfig/);
  assert.match(chatgpt, /resolveIntegrationCoreServerConfig/);

  for (const source of [core, stdio, chatgpt]) {
    assert.doesNotMatch(source, /CESSPACE_WORKSPACE/);
    assert.doesNotMatch(
      source,
      /signingKeyPath\s*=\s*process\.env|publicKeyPath\s*=\s*process\.env/,
    );
  }
});

test('ARC-INTEGRATION-01: integration docs preserve product and security truth', () => {
  const index = read('docs/integrations/README.md');
  const claude = read('docs/integrations/claude-local.md');
  const chatgpt = read('docs/integrations/chatgpt-private.md');

  for (const source of [index, chatgpt]) {
    assert.match(source, /not .*App Directory|not a public ChatGPT App Directory listing/i);
    assert.match(source, /not .*hosted|not a CesSpace-hosted connector/i);
  }

  assert.match(index, /ARC Core 1\.0\.0/);
  assert.match(index, /without a CesSpace account/);
  assert.match(claude, /Core state directory/);
  assert.match(claude, /stdio/i);
  assert.match(chatgpt, /disabled by default/);
  assert.match(chatgpt, /owner-only regular file/i);
  assert.match(chatgpt, /policy, approval, containment, and audit/i);
  assert.match(chatgpt, /Core preflight/);
  assert.doesNotMatch(chatgpt, /OAuth|OIDC|Central Login/i);
});

test('ARC-INTEGRATION-01: example env file contains connection selectors only', () => {
  const env = read('examples/integrations/chatgpt-private.env.example');
  assert.match(env, /^CESSPACE_ARC_CHATGPT_TOKEN_FILE=/m);
  assert.doesNotMatch(env, /^CESSPACE_WORKSPACE=/m);
  assert.doesNotMatch(env, /^CESSPACE_ARC_CHATGPT_TOKEN=/m);
  assert.doesNotMatch(env, /^AUTHORIZATION=/im);
  assert.doesNotMatch(env, /AUDIT.*KEY.*=/i);
});
