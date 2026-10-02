#!/usr/bin/env node
/**
 * ARC-DIST-01 — first-run Core state initializer.
 *
 * This command creates only local operator-owned state. It never contacts
 * CesSpace, requires no account, login, license key, subscription, or payment.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { DeviceTrustStore } from '../packages/auth/dist/index.js';
import { openAuditRuntime } from '../packages/audit/dist/index.js';
import {
  RC01_ALLOWED_TOOLS,
  RC02_ALLOWED_TOOLS,
  RC03_MUTATION_TOOLS,
  RC07_READ_ONLY_TOOLS,
  RC07_TASK4_EXECUTION_TOOLS,
  RC07_TASK5_EXECUTION_TOOLS,
  DeclarativePolicyEngine,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { preflightCoreState } from '../packages/config/dist/index.js';

const DEFAULT_STATE_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || '',
  '.config',
  'cesspace-arc',
  'state',
);

function fail(message) {
  throw new Error(message);
}

function assertSha(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40,64}$/.test(value)) {
    fail(`${label} is missing or invalid in the ARC install manifest.`);
  }
}

function readInstallIdentity(manifestPath) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    fail('ARC install ownership manifest is missing or invalid.');
  }
  if (raw?.format !== 'cesspace-arc-install-ownership-v1' || raw.profile !== 'core') {
    fail('ARC install ownership manifest is not a Core installation.');
  }
  if (raw.version !== '1.0.0' || raw.stage !== 'ARC-1.0') {
    fail('ARC install identity is not supported by this initializer.');
  }
  assertSha(raw.sourceCommit, 'sourceCommit');
  assertSha(raw.sourceTree, 'sourceTree');
  return {
    version: raw.version,
    sourceCommit: raw.sourceCommit,
    sourceTree: raw.sourceTree,
  };
}

function ensureWorkspace(workspacePath) {
  if (typeof workspacePath !== 'string' || workspacePath.trim().length === 0) {
    fail('A workspace path is required.');
  }
  const resolved = fs.realpathSync(path.resolve(workspacePath));
  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) fail('The selected workspace must be a directory.');
  return resolved;
}

function writeJson(filePath, value, mode = 0o600) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: 'utf8',
    mode,
    flag: 'wx',
  });
  fs.chmodSync(filePath, mode);
}

function buildDefaultPolicy() {
  const rc02Additional = RC02_ALLOWED_TOOLS.filter((tool) => !RC01_ALLOWED_TOOLS.includes(tool));
  return {
    version: '1.0',
    metadata: {
      name: 'cesspace-arc-core-default',
      description:
        'Conservative local Core policy: inspection and bounded process supervision allowed; mutations and deterministic execution require approval.',
    },
    workspaces: [{ id: 'workspace' }],
    rules: [
      {
        id: 'default-allow-inspection',
        effect: 'ALLOW',
        tools: [...RC01_ALLOWED_TOOLS],
      },
      {
        id: 'default-allow-controlled-execution',
        effect: 'ALLOW',
        tools: rc02Additional,
      },
      {
        id: 'default-require-approval-file-mutation',
        effect: 'REQUIRE_APPROVAL',
        tools: [...RC03_MUTATION_TOOLS],
      },
      {
        id: 'default-require-approval-verify',
        effect: 'REQUIRE_APPROVAL',
        tools: [...RC07_TASK4_EXECUTION_TOOLS],
      },
      {
        id: 'default-require-approval-test',
        effect: 'REQUIRE_APPROVAL',
        tools: [...RC07_TASK5_EXECUTION_TOOLS],
      },
      {
        id: 'default-allow-engineering-read-only',
        effect: 'ALLOW',
        tools: [...RC07_READ_ONLY_TOOLS],
      },
    ],
  };
}

export async function initializeCoreState({
  installManifestPath,
  workspacePath,
  stateDirectory = DEFAULT_STATE_DIR,
}) {
  const identity = readInstallIdentity(path.resolve(installManifestPath));
  const workspace = ensureWorkspace(workspacePath);
  const state = path.resolve(stateDirectory);

  if (!state.startsWith(path.parse(state).root) || state === path.parse(state).root) {
    fail('State directory must be a non-root absolute path.');
  }

  if (fs.existsSync(state)) {
    fail('ARC Core state directory already exists; refusing to overwrite it.');
  }

  const parent = path.dirname(state);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const created = [];
  try {
    fs.mkdirSync(state, { mode: 0o700 });
    created.push(state);

    const dirs = ['secrets', 'keys', 'auth', 'processes', 'policy', 'runtime'];
    for (const name of dirs) {
      const dir = path.join(state, name);
      fs.mkdirSync(dir, { mode: 0o700 });
      created.push(dir);
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const signingKeyPath = path.join(state, 'secrets', 'audit-signing.pem');
    const publicKeyPath = path.join(state, 'keys', 'audit-public.pem');
    fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
      flag: 'wx',
    });
    fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
      flag: 'wx',
    });
    fs.chmodSync(signingKeyPath, 0o600);
    fs.chmodSync(publicKeyPath, 0o600);

    const trustStorePath = path.join(state, 'auth', 'devices.json');
    DeviceTrustStore.createEmpty().saveToFile(trustStorePath);

    const policyPath = path.join(state, 'policy', 'policy.json');
    const policyDocument = buildDefaultPolicy();
    const registry = new WorkspaceRegistry();
    registry.registerWorkspace('workspace', workspace);
    DeclarativePolicyEngine.fromExternalText(registry, JSON.stringify(policyDocument), 'json');
    writeJson(policyPath, policyDocument);

    const auditConfig = {
      directory: path.join(state, 'audit'),
      signingKeyPath,
      publicKeyPath,
    };
    const auditRuntime = await openAuditRuntime(auditConfig);
    await auditRuntime.close();

    writeJson(path.join(state, 'core-config.json'), {
      schemaVersion: 2,
      productVersion: '1.0.0',
      profile: 'core',
      transport: { kind: 'stdio' },
      workspaces: [{ id: 'workspace', root: workspace }],
      defaultWorkspaceId: 'workspace',
      policy: { path: 'policy/policy.json' },
      audit: {
        directory: 'audit',
        signingKeyPath: 'secrets/audit-signing.pem',
        publicKeyPath: 'keys/audit-public.pem',
      },
      state: {
        trustStorePath: 'auth/devices.json',
        processDirectory: 'processes',
      },
      observability: { logLevel: 'info' },
    });

    writeJson(path.join(state, 'state-metadata.json'), {
      format: 'cesspace-arc-core-state',
      stateSchemaVersion: 2,
      configSchemaVersion: 2,
      productVersion: identity.version,
      sourceCommit: identity.sourceCommit,
      sourceTree: identity.sourceTree,
      profile: 'core',
      migrationVersion: 1,
    });

    const verified = await preflightCoreState(state, { environment: {} });
    if (verified.audit.status !== 'VERIFIED') {
      fail('ARC Core state audit verification did not complete successfully.');
    }

    return {
      stateDirectory: state,
      workspace,
      auditStatus: verified.audit.status,
      devices: verified.devices,
      version: identity.version,
    };
  } catch (error) {
    if (created.length > 0) {
      fs.rmSync(state, { recursive: true, force: true });
    }
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [manifestPath, workspacePath, stateDirectory] = process.argv.slice(2);
  if (!manifestPath || !workspacePath) {
    process.stderr.write('Usage: arc-core-init <install-manifest> <workspace> [state-directory]\n');
    process.exit(2);
  }

  initializeCoreState({
    installManifestPath: manifestPath,
    workspacePath,
    ...(stateDirectory ? { stateDirectory } : {}),
  })
    .then((result) => {
      process.stdout.write(
        `CesSpace ARC Core ready.\nState: ${result.stateDirectory}\nWorkspace: ${result.workspace}\nAudit: ${result.auditStatus}\nAccount: not required\nPayment: not required\n`,
      );
    })
    .catch((error) => {
      process.stderr.write(`ARC Core setup failed: ${error.message}\n`);
      process.exit(1);
    });
}
