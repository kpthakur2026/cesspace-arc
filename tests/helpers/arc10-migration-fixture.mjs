import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { openAuditRuntime, verifyOfflineStore } from '../../packages/audit/dist/index.js';
import { atomicPersistTrustStore } from '../../packages/auth/dist/index.js';

export const LEGACY_PRODUCT_VERSION = '0.8.0-rc08';
export const PRODUCT_VERSION = '1.0.0';

function writeJson(filePath, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode });
  fs.chmodSync(filePath, mode);
}

function auditRecord(index) {
  return {
    eventId: crypto.randomUUID(),
    timestamp: new Date(1_780_000_000_000 + index).toISOString(),
    actor: {
      clientId: 'arc10-migration-client',
      clientType: 'test',
      deviceId: 'a'.repeat(32),
      sessionId: 'b'.repeat(64),
    },
    target: {
      workspaceId: 'workspace',
      workspacePath: '',
      workspaceRootHash: 'c'.repeat(64),
    },
    invocation: {
      toolName: 'health',
      parametersRedacted: {},
      payloadHash: 'd'.repeat(64),
    },
    policy: { decision: 'ALLOW', ruleId: 'arc10-migration-fixture', evaluationDurationMs: 1 },
    execution: {
      status: 'SUCCESS',
      startTime: new Date(1_780_000_000_000 + index).toISOString(),
      endTime: new Date(1_780_000_000_001 + index).toISOString(),
      durationMs: 1,
    },
  };
}

export async function createMigrationFixture({ schemaVersion = 1, auditRecords = 3 } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'arc10-migration-'));
  const live = path.join(root, 'state');
  const workspace = path.join(root, 'workspace');
  for (const directory of [live, workspace])
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(workspace, 'sentinel.txt'), 'workspace-authority\n');

  const secrets = path.join(live, 'secrets');
  const keys = path.join(live, 'keys');
  const auth = path.join(live, 'auth');
  const processes = path.join(live, 'processes');
  const policy = path.join(live, 'policy');
  const runtime = path.join(live, 'runtime');
  for (const directory of [secrets, keys, auth, processes, policy, runtime])
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const pair = crypto.generateKeyPairSync('ed25519');
  const signingKeyPath = path.join(secrets, 'audit-signing.pem');
  const publicKeyPath = path.join(keys, 'audit-public.pem');
  fs.writeFileSync(signingKeyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), {
    mode: 0o600,
  });
  fs.writeFileSync(publicKeyPath, pair.publicKey.export({ type: 'spki', format: 'pem' }), {
    mode: 0o600,
  });
  fs.chmodSync(signingKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o600);

  const operator = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(
    path.join(keys, 'operator-public.pem'),
    operator.publicKey.export({ type: 'spki', format: 'pem' }),
    { mode: 0o600 },
  );
  writeJson(path.join(policy, 'policy.json'), { default: 'DENY', rules: [] });

  const trustStorePath = path.join(auth, 'devices.json');
  atomicPersistTrustStore(trustStorePath, {
    version: 1,
    devices: [
      {
        deviceId: '1'.repeat(32),
        clientId: 'arc10-device-client',
        clientType: 'desktop',
        pins: ['2'.repeat(64)],
        enrolledAt: '2026-09-29T00:00:00.000Z',
        displayLabel: 'ARC 1.0 migration fixture',
        revoked: false,
      },
    ],
  });

  const auditConfig = {
    directory: path.join(live, 'audit'),
    signingKeyPath,
    publicKeyPath,
  };
  const auditRuntime = await openAuditRuntime(auditConfig);
  for (let index = 0; index < auditRecords; index += 1)
    await auditRuntime.appendRecord(auditRecord(index));
  await auditRuntime.close();

  const commonConfig = {
    schemaVersion,
    productVersion: schemaVersion === 1 ? LEGACY_PRODUCT_VERSION : PRODUCT_VERSION,
    ...(schemaVersion === 2 ? { profile: 'core' } : {}),
    transport: { kind: 'stdio' },
    workspaces: [{ id: 'workspace', root: workspace }],
    defaultWorkspaceId: 'workspace',
    policy: { path: 'policy/policy.json' },
    audit: {
      directory: 'audit',
      signingKeyPath: 'secrets/audit-signing.pem',
      publicKeyPath: 'keys/audit-public.pem',
    },
    admin: {
      socketPath: 'runtime/admin.sock',
      operatorPublicKeyPath: 'keys/operator-public.pem',
    },
    state: { trustStorePath: 'auth/devices.json', processDirectory: 'processes' },
    observability: { logLevel: 'info' },
  };
  writeJson(path.join(live, 'core-config.json'), commonConfig);
  const stateMetadata = {
    format: 'cesspace-arc-core-state',
    stateSchemaVersion: schemaVersion,
    configSchemaVersion: schemaVersion,
    productVersion: schemaVersion === 1 ? LEGACY_PRODUCT_VERSION : PRODUCT_VERSION,
    sourceCommit: '3'.repeat(40),
    sourceTree: '4'.repeat(40),
    profile: 'core',
    ...(schemaVersion === 2 ? { migrationVersion: 1 } : {}),
  };
  writeJson(path.join(live, 'state-metadata.json'), stateMetadata);

  const audit = await verifyOfflineStore({
    directory: auditConfig.directory,
    checkpointPublicKeyPath: publicKeyPath,
    workspacePaths: [workspace],
  });
  return {
    root,
    live,
    workspace,
    signingKeyPath,
    publicKeyPath,
    trustStorePath,
    configPath: path.join(live, 'core-config.json'),
    metadataPath: path.join(live, 'state-metadata.json'),
    audit,
  };
}

export function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

export function writeFixtureJson(filePath, value, mode = 0o600) {
  writeJson(filePath, value, mode);
}

export function removeFixture(fixture) {
  fs.rmSync(fixture.root, { recursive: true, force: true });
}
