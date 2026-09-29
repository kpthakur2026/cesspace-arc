import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  CORE_ENVIRONMENT_ALLOWLIST,
  CORE_MIGRATION_DIRECTORY,
  CORE_MIGRATION_JOURNAL_FILENAME,
  CORE_MIGRATION_LOCK_FILENAME,
  assertStateCompatibility,
  digestCoreState,
  migrateCoreState,
  preflightCoreState,
  recoverCoreMigration,
  rollbackCoreState,
} from '../packages/config/dist/index.js';
import { migrateCoreStateWithPreCommitFault } from '../packages/config/dist/testing.js';
import { DeviceTrustStore } from '../packages/auth/dist/index.js';
import { verifyOfflineStore } from '../packages/audit/dist/index.js';
import { runCli } from '../apps/cli/dist/index.js';
import {
  createMigrationFixture,
  readJson,
  removeFixture,
  writeFixtureJson,
} from './helpers/arc10-migration-fixture.mjs';

const execFile = promisify(childProcess.execFile);
const fixtures = [];

async function fixture(options) {
  const value = await createMigrationFixture(options);
  fixtures.push(value);
  return value;
}

test.after(() => {
  for (const value of fixtures) removeFixture(value);
});

function codeIs(code) {
  return (error) => error?.code === code;
}

function migrationPath(value, name) {
  return path.join(value.root, CORE_MIGRATION_DIRECTORY, name);
}

async function captureExec(file, args) {
  try {
    const result = await execFile(file, args, {
      cwd: path.resolve(import.meta.dirname, '..'),
      maxBuffer: 1024 * 1024,
    });
    return { status: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return {
      status: error.code,
      stdout: String(error.stdout ?? ''),
      stderr: String(error.stderr ?? ''),
    };
  }
}

test('ARC10-NEG-013: unknown security configuration is rejected before listener, IPC, process, workspace, or audit startup', async () => {
  const value = await fixture({ schemaVersion: 2 });
  const config = readJson(value.configPath);
  Object.assign(config, {
    allowAll: true,
    disableAudit: true,
    trustedIssuer: 'https://attacker.invalid',
    workspaceRootOverride: '/tmp/escape',
    shell: true,
  });
  writeFixtureJson(value.configPath, config);

  let listenerBinds = 0;
  let processSpawns = 0;
  const originalListen = net.Server.prototype.listen;
  const originalSpawn = childProcess.spawn;
  net.Server.prototype.listen = function (...args) {
    listenerBinds += 1;
    return originalListen.apply(this, args);
  };
  childProcess.spawn = function (...args) {
    processSpawns += 1;
    return originalSpawn.apply(this, args);
  };
  const auditBefore = fs.statSync(path.join(value.live, 'audit')).mtimeNs;
  try {
    await assert.rejects(preflightCoreState(value.live), codeIs('UNKNOWN_CONFIG_FIELD'));
  } finally {
    net.Server.prototype.listen = originalListen;
    childProcess.spawn = originalSpawn;
  }
  assert.equal(listenerBinds, 0);
  assert.equal(processSpawns, 0);
  assert.equal(fs.statSync(path.join(value.live, 'audit')).mtimeNs, auditBefore);
  assert.equal(fs.existsSync(path.join(value.live, 'runtime', 'admin.sock')), false);
});

test('ARC10-NEG-014: insecure secret modes, symlinks, and non-regular files fail before secret consumption', async () => {
  const value = await fixture({ schemaVersion: 2 });
  for (const mode of [0o644, 0o664, 0o666]) {
    fs.chmodSync(value.signingKeyPath, mode);
    await assert.rejects(preflightCoreState(value.live), codeIs('SECRET_FILE_INSECURE'));
  }
  for (const mode of [0o400, 0o600]) {
    fs.chmodSync(value.signingKeyPath, mode);
    assert.equal((await preflightCoreState(value.live)).audit.status, 'VERIFIED');
  }
  const realKey = `${value.signingKeyPath}.real`;
  fs.renameSync(value.signingKeyPath, realKey);
  fs.symlinkSync(realKey, value.signingKeyPath);
  await assert.rejects(preflightCoreState(value.live), codeIs('SECRET_FILE_INSECURE'));
  fs.rmSync(value.signingKeyPath);
  fs.mkdirSync(value.signingKeyPath, { mode: 0o700 });
  await assert.rejects(preflightCoreState(value.live), codeIs('SECRET_FILE_INSECURE'));
});

test('ARC10-NEG-015: only the frozen non-secret environment allowlist can alter effective configuration', async () => {
  const value = await fixture({ schemaVersion: 2 });
  assert.deepEqual([...CORE_ENVIRONMENT_ALLOWLIST], ['CESSPACE_ARC_LOG_LEVEL']);
  const poisoned = await preflightCoreState(value.live, {
    environment: {
      ARC_ALLOW_ALL: 'true',
      ARC_POLICY_BYPASS: 'true',
      ARC_WORKSPACE_OVERRIDE: '/tmp/escape',
      ARC_TRUSTED_ISSUER: 'https://attacker.invalid',
      ARC_TLS_PRIVATE_KEY: 'raw-secret',
      CESSPACE_WORKSPACE_BYPASS: '/tmp/escape',
    },
  });
  assert.equal(poisoned.resolved.config.observability.logLevel, 'info');
  assert.equal(poisoned.resolved.config.policy.path, 'policy/policy.json');
  assert.equal(poisoned.resolved.config.workspaces[0].root, value.workspace);
  const overridden = await preflightCoreState(value.live, {
    environment: { CESSPACE_ARC_LOG_LEVEL: 'warn' },
  });
  assert.equal(overridden.resolved.config.observability.logLevel, 'warn');
  await assert.rejects(
    preflightCoreState(value.live, { environment: { CESSPACE_ARC_LOG_LEVEL: 'verbose' } }),
    codeIs('ENV_OVERRIDE_INVALID'),
  );
});

test('ARC10-NEG-016: secret-bearing ordinary CLI arguments are refused without connection, migration, or echo', async () => {
  const marker = `synthetic-secret-${'a'.repeat(48)}`;
  for (const option of ['--private-key', '--token', '--session-token', '--approval-token']) {
    const observed = await captureExec(process.execPath, [
      'scripts/arc10-migrate.mjs',
      option,
      marker,
    ]);
    assert.notEqual(observed.status, 0);
    assert.equal(`${observed.stdout}${observed.stderr}`.includes(marker), false);
  }
  let adminConnections = 0;
  let output = '';
  const exit = await runCli(['--private-key', marker], {
    stdout: (text) => {
      output += text;
    },
    stderr: (text) => {
      output += text;
    },
    createAdminClient: () => {
      adminConnections += 1;
      throw new Error('must not connect');
    },
  });
  assert.notEqual(exit, 0);
  assert.equal(adminConnections, 0);
  assert.equal(output.includes(marker), false);
});

test('ARC10-NEG-017: pre-commit interruption leaves the original valid and recovery removes staged state and lock', async () => {
  const publicDeclarations = fs.readFileSync(
    path.resolve(import.meta.dirname, '../packages/config/dist/index.d.ts'),
    'utf8',
  );
  assert.equal(publicDeclarations.includes('PreCommitFault'), false);
  assert.equal(publicDeclarations.includes('migrateCoreStateInternal'), false);
  assert.equal(publicDeclarations.includes('MIGRATION_TEST_TOKEN'), false);
  const value = await fixture();
  const before = digestCoreState(value.live);
  fs.mkdirSync(path.join(value.root, CORE_MIGRATION_DIRECTORY), { mode: 0o700 });
  fs.writeFileSync(migrationPath(value, CORE_MIGRATION_LOCK_FILENAME), 'occupied\n', {
    mode: 0o600,
  });
  await assert.rejects(migrateCoreState(value.root), codeIs('MIGRATION_LOCKED'));
  fs.rmSync(migrationPath(value, CORE_MIGRATION_LOCK_FILENAME));
  writeFixtureJson(migrationPath(value, CORE_MIGRATION_LOCK_FILENAME), {
    format: 'cesspace-arc-migration-lock-v1',
    pid: 2_147_483_647,
    startTime: '0',
  });
  await assert.rejects(
    migrateCoreStateWithPreCommitFault(value.root),
    codeIs('MIGRATION_FAULT_INJECTED'),
  );
  assert.equal(digestCoreState(value.live), before);
  assert.equal(readJson(value.metadataPath).stateSchemaVersion, 1);
  assert.equal(fs.existsSync(migrationPath(value, CORE_MIGRATION_LOCK_FILENAME)), false);
  assert.equal((await recoverCoreMigration(value.root)).result, 'ORIGINAL_RESTORED');
  assert.equal(fs.existsSync(migrationPath(value, 'staged')), false);
  assert.equal(fs.existsSync(migrationPath(value, CORE_MIGRATION_JOURNAL_FILENAME)), false);
});

test('ARC10-NEG-018: migration replay is a truthful no-op with identical state, device, and audit evidence', async () => {
  const value = await fixture();
  const first = await migrateCoreState(value.root);
  const firstDigest = digestCoreState(value.live);
  const firstDeviceData = DeviceTrustStore.loadFromFile(
    path.join(value.live, 'auth', 'devices.json'),
  ).toData();
  const firstAudit = await verifyOfflineStore({
    directory: path.join(value.live, 'audit'),
    checkpointPublicKeyPath: path.join(value.live, 'keys', 'audit-public.pem'),
    workspacePaths: [value.workspace],
  });
  const second = await migrateCoreState(value.root);
  assert.equal(first.result, 'MIGRATED');
  assert.equal(second.result, 'ALREADY_CURRENT');
  assert.equal(second.stateDigest, firstDigest);
  assert.deepEqual(
    DeviceTrustStore.loadFromFile(path.join(value.live, 'auth', 'devices.json')).toData(),
    firstDeviceData,
  );
  const secondAudit = await verifyOfflineStore({
    directory: path.join(value.live, 'audit'),
    checkpointPublicKeyPath: path.join(value.live, 'keys', 'audit-public.pem'),
    workspacePaths: [value.workspace],
  });
  assert.equal(secondAudit.primary.terminalSequence, firstAudit.primary.terminalSequence);
  assert.equal(secondAudit.primary.terminalRecordHash, firstAudit.primary.terminalRecordHash);
});

test('ARC10-NEG-019: a newer unsupported state schema is refused without rewrite or audit reset', async () => {
  const value = await fixture({ schemaVersion: 2 });
  const metadata = readJson(value.metadataPath);
  metadata.stateSchemaVersion = 3;
  writeFixtureJson(value.metadataPath, metadata);
  const before = fs.readFileSync(value.metadataPath);
  const auditBefore = fs.readFileSync(path.join(value.live, 'audit', 'audit-active.jsonl'));
  assert.throws(() => assertStateCompatibility(value.live), codeIs('UNSUPPORTED_STATE_VERSION'));
  assert.deepEqual(fs.readFileSync(value.metadataPath), before);
  assert.deepEqual(
    fs.readFileSync(path.join(value.live, 'audit', 'audit-active.jsonl')),
    auditBefore,
  );
});

test('ARC10-NEG-020: irreversible or incompatible rollback is refused before live state or backup mutation', async () => {
  const value = await fixture();
  await migrateCoreState(value.root);
  const liveBefore = digestCoreState(value.live);
  const backup = migrationPath(value, 'backup');
  const backupBefore = digestCoreState(backup);
  const journalPath = migrationPath(value, CORE_MIGRATION_JOURNAL_FILENAME);
  const journal = readJson(journalPath);
  journal.reversible = false;
  writeFixtureJson(journalPath, journal);
  await assert.rejects(rollbackCoreState(value.root), codeIs('ROLLBACK_INCOMPATIBLE'));
  assert.equal(digestCoreState(value.live), liveBefore);
  assert.equal(digestCoreState(backup), backupBefore);
});

test('ARC10-NEG-021: malicious legacy migration inputs are rejected before backup, commit, or outside mutation', async () => {
  const base = await fixture();
  const attacks = [
    (config) => {
      config.policy.path = '../outside';
    },
    (config) => {
      config.policy.path = '/etc/shadow';
    },
    (config) => {
      config.policy.path = `policy/${'x'.repeat(5000)}`;
    },
    (config) => {
      config.policy.path = 'policy/evil\u0000.json';
    },
    (config) => {
      config.transport.kind = 'shell';
    },
    (config) => {
      config.workspaces.push({ ...config.workspaces[0] });
    },
    (config) => {
      config.sessionToken = `synthetic-secret-${'b'.repeat(48)}`;
    },
    (config) => {
      config.security = { nested: { nested: { nested: { shell: true } } } };
    },
  ];
  for (const [index, attack] of attacks.entries()) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `arc10-malicious-${index}-`));
    fs.cpSync(base.root, root, { recursive: true, preserveTimestamps: true });
    const live = path.join(root, 'state');
    const configPath = path.join(live, 'core-config.json');
    const config = readJson(configPath);
    attack(config);
    writeFixtureJson(configPath, config);
    const sentinel = path.join(root, 'outside-sentinel');
    fs.writeFileSync(sentinel, 'unchanged');
    let observed;
    try {
      await migrateCoreState(root);
    } catch (error) {
      observed = error;
    }
    assert.ok(observed);
    assert.equal(observed.message.includes('synthetic-secret-'), false);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'unchanged');
    assert.equal(fs.existsSync(path.join(root, CORE_MIGRATION_DIRECTORY, 'backup')), false);
    fs.rmSync(root, { recursive: true, force: true });
  }

  const symlinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc10-malicious-symlink-'));
  fs.cpSync(base.root, symlinkRoot, { recursive: true });
  const symlinkLive = path.join(symlinkRoot, 'state');
  const config = readJson(path.join(symlinkLive, 'core-config.json'));
  config.policy.path = 'policy/escape/policy.json';
  writeFixtureJson(path.join(symlinkLive, 'core-config.json'), config);
  fs.symlinkSync(path.dirname(base.root), path.join(symlinkLive, 'policy', 'escape'));
  await assert.rejects(migrateCoreState(symlinkRoot));
  assert.equal(fs.existsSync(path.join(symlinkRoot, CORE_MIGRATION_DIRECTORY, 'backup')), false);
  fs.rmSync(symlinkRoot, { recursive: true, force: true });

  const workLinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc10-malicious-work-link-'));
  fs.cpSync(base.root, workLinkRoot, { recursive: true });
  const outsideWork = fs.mkdtempSync(path.join(os.tmpdir(), 'arc10-outside-work-'));
  const outsideSentinel = path.join(outsideWork, 'sentinel');
  fs.writeFileSync(outsideSentinel, 'unchanged');
  fs.symlinkSync(outsideWork, path.join(workLinkRoot, CORE_MIGRATION_DIRECTORY));
  await assert.rejects(migrateCoreState(workLinkRoot), codeIs('MIGRATION_PATH_INVALID'));
  assert.equal(fs.readFileSync(outsideSentinel, 'utf8'), 'unchanged');
  assert.deepEqual(fs.readdirSync(outsideWork), ['sentinel']);
  fs.rmSync(workLinkRoot, { recursive: true, force: true });
  fs.rmSync(outsideWork, { recursive: true, force: true });
});

test('ARC10-NEG-022: corrupt durable audit evidence blocks migration without creating a new genesis', async () => {
  const value = await fixture({ auditRecords: 8 });
  const activePath = path.join(value.live, 'audit', 'audit-active.jsonl');
  const original = fs.readFileSync(activePath);
  fs.writeFileSync(activePath, original.subarray(0, original.length - 7), { mode: 0o600 });
  await assert.rejects(migrateCoreState(value.root));
  assert.deepEqual(fs.readFileSync(activePath), original.subarray(0, original.length - 7));
  assert.equal(fs.existsSync(migrationPath(value, 'backup')), false);
  assert.equal(fs.existsSync(migrationPath(value, 'staged')), false);
});

test('ARC10-FLOW-04: RC-08 state upgrades transactionally with config, device, and audit semantics preserved', async () => {
  const value = await fixture({ auditRecords: 1000 });
  const sourceConfig = readJson(value.configPath);
  const sourceDevices = DeviceTrustStore.loadFromFile(value.trustStorePath).toData();
  const result = await migrateCoreState(value.root);
  assert.equal(result.result, 'MIGRATED');
  const preflight = await preflightCoreState(value.live);
  assert.equal(preflight.state.stateSchemaVersion, 2);
  assert.equal(preflight.resolved.config.schemaVersion, 2);
  assert.equal(preflight.resolved.config.productVersion, '0.8.0-rc08');
  assert.equal(preflight.resolved.config.profile, 'core');
  assert.deepEqual(preflight.resolved.config.workspaces, sourceConfig.workspaces);
  assert.deepEqual(preflight.resolved.config.policy, sourceConfig.policy);
  assert.deepEqual(
    DeviceTrustStore.loadFromFile(path.join(value.live, 'auth', 'devices.json')).toData(),
    sourceDevices,
  );
  assert.equal(preflight.audit.storeId, value.audit.storeId);
  assert.equal(preflight.audit.primary.terminalSequence, value.audit.primary.terminalSequence);
  assert.equal(preflight.audit.primary.terminalRecordHash, value.audit.primary.terminalRecordHash);
  assert.equal(preflight.audit.checkpoints.checkpointCount, 1);
  assert.equal(
    preflight.audit.checkpoints.lastCheckpointHash,
    value.audit.checkpoints.lastCheckpointHash,
  );
  assert.equal(result.evidence.lifecycle, 'COMMITTED');
  assert.equal(result.evidence.backupDigest, result.evidence.sourceDigest);
  assert.equal(fs.existsSync(migrationPath(value, 'backup')), true);
  const checked = await captureExec(process.execPath, [
    'scripts/arc10-config-check.mjs',
    value.live,
  ]);
  assert.equal(checked.status, 0);
  assert.deepEqual(JSON.parse(checked.stdout), {
    audit: 'VERIFIED',
    configSchemaVersion: 2,
    devices: 1,
    productVersion: '0.8.0-rc08',
    stateSchemaVersion: 2,
  });
});

test('ARC10-FLOW-05: interruption recovery completes cleanly and compatible rollback restores the exact source state', async () => {
  const value = await fixture({ auditRecords: 12 });
  const sourceDigest = digestCoreState(value.live);
  const sourceDevices = DeviceTrustStore.loadFromFile(value.trustStorePath).toData();
  let networkAttempts = 0;
  const originals = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpsRequest: https.request,
    netConnect: net.connect,
  };
  const refuseNetwork = () => {
    networkAttempts += 1;
    throw new Error('network forbidden in migration lifecycle');
  };
  globalThis.fetch = refuseNetwork;
  http.request = refuseNetwork;
  https.request = refuseNetwork;
  net.connect = refuseNetwork;
  let recovery;
  let migrated;
  let rolledBack;
  try {
    await assert.rejects(
      migrateCoreStateWithPreCommitFault(value.root),
      codeIs('MIGRATION_FAULT_INJECTED'),
    );
    recovery = await recoverCoreMigration(value.root);
    migrated = await migrateCoreState(value.root);
    rolledBack = await rollbackCoreState(value.root);
  } finally {
    globalThis.fetch = originals.fetch;
    http.request = originals.httpRequest;
    https.request = originals.httpsRequest;
    net.connect = originals.netConnect;
  }
  assert.equal(networkAttempts, 0);
  assert.equal(recovery.result, 'ORIGINAL_RESTORED');
  assert.equal(migrated.result, 'MIGRATED');
  assert.equal(rolledBack.stateDigest, sourceDigest);
  assert.equal(readJson(value.metadataPath).stateSchemaVersion, 1);
  assert.deepEqual(DeviceTrustStore.loadFromFile(value.trustStorePath).toData(), sourceDevices);
  const audit = await verifyOfflineStore({
    directory: path.join(value.live, 'audit'),
    checkpointPublicKeyPath: path.join(value.live, 'keys', 'audit-public.pem'),
    workspacePaths: [value.workspace],
  });
  assert.equal(audit.primary.terminalSequence, value.audit.primary.terminalSequence);
  assert.equal(audit.primary.terminalRecordHash, value.audit.primary.terminalRecordHash);
  assert.equal(fs.existsSync(migrationPath(value, CORE_MIGRATION_LOCK_FILENAME)), false);
  assert.equal(fs.existsSync(migrationPath(value, 'staged')), false);
  assert.equal(fs.existsSync(migrationPath(value, 'retired')), false);
  assert.equal(
    readJson(migrationPath(value, CORE_MIGRATION_JOURNAL_FILENAME)).lifecycle,
    'ROLLED_BACK',
  );
});
