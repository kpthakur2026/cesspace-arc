import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  TUNNEL_CLIENT_VERSION,
  assertPrivateRegularFile,
  resolveConnectionPaths,
  validateTunnelId,
} from '../scripts/arc-connect-chatgpt.mjs';

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

test('ARC-CONNECT-01: accepts only opaque OpenAI tunnel IDs', () => {
  assert.equal(
    validateTunnelId('tunnel_6abf9dc5a8a481919f0aaab404a10e48'),
    'tunnel_6abf9dc5a8a481919f0aaab404a10e48',
  );
  for (const value of ['', 'abc', 'tunnel_', 'tunnel_bad/value', ' https://example.com ']) {
    assert.throws(() => validateTunnelId(value), /Tunnel ID must have the form/);
  }
});

test('ARC-CONNECT-01: keeps connection state and secrets under user-owned local roots', () => {
  const root = tempRoot('arc-connect01-paths-');
  try {
    const paths = resolveConnectionPaths({ HOME: root });
    assert.equal(
      paths.configRoot,
      path.join(root, '.config', 'cesspace-arc', 'connect', 'chatgpt'),
    );
    assert.equal(
      paths.stateRoot,
      path.join(root, '.local', 'state', 'cesspace-arc', 'connect', 'chatgpt'),
    );
    assert.equal(paths.apiKeyFile, path.join(paths.configRoot, 'openai-api-key'));
    assert.equal(paths.arcTokenFile, path.join(paths.configRoot, 'arc-token'));
    assert.equal(
      paths.arcAuthorizationHeaderFile,
      path.join(paths.configRoot, 'arc-authorization-header'),
    );
    assert.equal('tunnelBinary' in paths, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-CONNECT-01: rejects weak secret files and symlinks', () => {
  const root = tempRoot('arc-connect01-secret-');
  try {
    const privateFile = path.join(root, 'private');
    fs.writeFileSync(privateFile, 'secret\n', { mode: 0o600 });
    fs.chmodSync(privateFile, 0o600);
    assert.equal(assertPrivateRegularFile(privateFile, 'private file'), privateFile);

    const weakFile = path.join(root, 'weak');
    fs.writeFileSync(weakFile, 'secret\n', { mode: 0o644 });
    fs.chmodSync(weakFile, 0o644);
    assert.throws(() => assertPrivateRegularFile(weakFile, 'weak file'), /must not be accessible/);

    const link = path.join(root, 'link');
    fs.symlinkSync(privateFile, link);
    assert.throws(() => assertPrivateRegularFile(link, 'link'), /regular non-symlink/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-CONNECT-01: supports one reviewed external tunnel-client version without bundling it', () => {
  assert.equal(TUNNEL_CLIENT_VERSION, '0.0.15');
  const source = fs.readFileSync(path.resolve('scripts/arc-connect-chatgpt.mjs'), 'utf8');
  assert.doesNotMatch(source, /https?:\/\/(?:[^/]+\.)?(?:openai\.com|anthropic\.com)/i);
  assert.doesNotMatch(source, /OPENAI_API_KEY|CONTROL_PLANE_API_KEY/);
  assert.doesNotMatch(source, /downloadFile|extractZipMember|TUNNEL_CLIENT_URL/);
});

test('ARC-CONNECT-01: CLI exposes file-backed API key selection but no API-key value argument', () => {
  const root = tempRoot('arc-connect01-help-');
  try {
    const script = path.resolve('scripts/arc-connect-chatgpt.mjs');
    const result = spawnSync(process.execPath, [script, '--help'], {
      encoding: 'utf8',
      env: { ...process.env, HOME: root },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /cesspace-arc connect chatgpt/);
    assert.match(result.stdout, /--api-key-file/);
    assert.match(result.stdout, /--tunnel-client/);
    assert.doesNotMatch(result.stdout, /--api-key\s/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
