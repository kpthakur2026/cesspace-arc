import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { initializeCoreState } from '../scripts/arc-core-init.mjs';
import { preflightCoreState } from '../packages/config/dist/index.js';
import { DeviceTrustStore } from '../packages/auth/dist/index.js';

function tempRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), label));
}

function writeManifest(filePath) {
  fs.writeFileSync(
    filePath,
    `${JSON.stringify({
      format: 'cesspace-arc-install-ownership-v1',
      version: '1.0.0',
      stage: 'ARC-1.0',
      sourceCommit: '1'.repeat(40),
      sourceTree: '2'.repeat(40),
      profile: 'core',
      files: ['bin/cesspace-arc', 'bin/cesspace-arc-setup', 'bin/cesspace-arc-chatgpt'],
      trees: ['runtime'],
    })}\n`,
    { mode: 0o600 },
  );
}

test('ARC-DIST-01: first-run setup creates a verified local Core state with no account or billing dependency', async () => {
  const root = tempRoot('arc-dist01-init-');
  try {
    const workspace = path.join(root, 'workspace');
    const state = path.join(root, 'state');
    const manifest = path.join(root, '.cesspace-arc-install.json');
    fs.mkdirSync(workspace, { mode: 0o700 });
    fs.writeFileSync(path.join(workspace, 'README.md'), 'workspace\n');
    writeManifest(manifest);

    const result = await initializeCoreState({
      installManifestPath: manifest,
      workspacePath: workspace,
      stateDirectory: state,
    });

    assert.equal(result.version, '1.0.0');
    assert.equal(result.auditStatus, 'VERIFIED');
    assert.equal(result.devices, 0);
    assert.equal(result.workspace, fs.realpathSync(workspace));

    const config = JSON.parse(fs.readFileSync(path.join(state, 'core-config.json'), 'utf8'));
    assert.equal(config.transport.kind, 'stdio');
    assert.equal(config.workspaces.length, 1);
    assert.equal(config.defaultWorkspaceId, 'workspace');
    assert.equal('account' in config, false);
    assert.equal('login' in config, false);
    assert.equal('billing' in config, false);
    assert.equal('payment' in config, false);
    assert.equal('subscription' in config, false);
    assert.equal('licenseKey' in config, false);

    const signingKey = fs.statSync(path.join(state, 'secrets', 'audit-signing.pem'));
    assert.equal(signingKey.mode & 0o777, 0o600);

    const trustStore = DeviceTrustStore.loadFromFile(path.join(state, 'auth', 'devices.json'));
    assert.equal(trustStore.getDeviceCount(), 0);

    const verified = await preflightCoreState(state, { environment: {} });
    assert.equal(verified.audit.status, 'VERIFIED');
    assert.equal(verified.devices, 0);

    const policy = JSON.parse(fs.readFileSync(path.join(state, 'policy', 'policy.json'), 'utf8'));
    const mutation = policy.rules.find(
      (rule) => rule.id === 'default-require-approval-file-mutation',
    );
    assert.equal(mutation.effect, 'REQUIRE_APPROVAL');
    assert.deepEqual(
      [...mutation.tools].sort(),
      ['apply_patch', 'create_file', 'delete_file', 'move_file', 'write_file'].sort(),
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-DIST-01: setup refuses to overwrite an existing state directory', async () => {
  const root = tempRoot('arc-dist01-existing-');
  try {
    const workspace = path.join(root, 'workspace');
    const state = path.join(root, 'state');
    const manifest = path.join(root, '.cesspace-arc-install.json');
    fs.mkdirSync(workspace);
    fs.mkdirSync(state);
    fs.writeFileSync(path.join(state, 'sentinel'), 'keep');
    writeManifest(manifest);

    await assert.rejects(
      initializeCoreState({
        installManifestPath: manifest,
        workspacePath: workspace,
        stateDirectory: state,
      }),
      /already exists/i,
    );
    assert.equal(fs.readFileSync(path.join(state, 'sentinel'), 'utf8'), 'keep');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('ARC-DIST-01: setup refuses malformed install identity before state creation', async () => {
  const root = tempRoot('arc-dist01-identity-');
  try {
    const workspace = path.join(root, 'workspace');
    const state = path.join(root, 'state');
    const manifest = path.join(root, '.cesspace-arc-install.json');
    fs.mkdirSync(workspace);
    fs.writeFileSync(
      manifest,
      JSON.stringify({
        format: 'cesspace-arc-install-ownership-v1',
        version: '9.9.9',
        stage: 'UNKNOWN',
        sourceCommit: '1'.repeat(40),
        sourceTree: '2'.repeat(40),
        profile: 'core',
      }),
    );

    await assert.rejects(
      initializeCoreState({
        installManifestPath: manifest,
        workspacePath: workspace,
        stateDirectory: state,
      }),
      /not supported/i,
    );
    assert.equal(fs.existsSync(state), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
