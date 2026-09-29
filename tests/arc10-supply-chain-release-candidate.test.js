import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { promisify } from 'node:util';
import {
  ARC_STAGE,
  ARC_VERSION,
  MANIFEST_FILE,
  PROVENANCE_FILE,
  RELEASE_PROFILE_FILE,
  SIGNATURE_FILE,
  buildDistribution,
  canonicalJson,
  installDistribution,
  sha256,
  signManifest,
  uninstallDistribution,
  verifyDistribution,
} from '../scripts/arc10-distribution-lib.mjs';
import {
  assertArtifactStateCompatibility,
  assertDependencyCompleteness,
  assertNoReleaseSigningPrivateKey,
  assertPlatformConsistency,
  auditCoreOnlySurface,
  evaluateVulnerabilityPolicy,
  verifyCoreReleaseCandidate,
} from '../scripts/arc10-release-candidate-lib.mjs';
import { validateReleaseProfile } from '../scripts/arc10-release-profile-lib.mjs';
import {
  InstalledStdioClient,
  cloneDirectory,
  createCleanSourceFixture,
  createSigningKeyPair,
} from './helpers/arc10-distribution-fixture.mjs';

const execFile = promisify(execFileCallback);
const require = createRequire(import.meta.url);
const repositoryRoot = process.cwd();
const cleanup = [];
const keys = createSigningKeyPair();
let sourceRoot;
let bundleDir;
let verified;
let cleanAudit;

async function temporaryDirectory(prefix) {
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
  cleanup.push(directory);
  return directory;
}

async function copyBundle() {
  const copy = await cloneDirectory(bundleDir);
  cleanup.push(copy);
  return copy;
}

async function writeCanonical(filePath, value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`);
  await fs.promises.writeFile(filePath, bytes);
  return bytes;
}

async function makeAuthenticOlderBundle() {
  const copy = await copyBundle();
  const profilePath = path.join(copy, RELEASE_PROFILE_FILE);
  const provenancePath = path.join(copy, PROVENANCE_FILE);
  const manifestPath = path.join(copy, MANIFEST_FILE);
  const profile = JSON.parse(await fs.promises.readFile(profilePath, 'utf8'));
  profile.schemas.config = 1;
  profile.schemas.state = 1;
  const profileBytes = await writeCanonical(profilePath, profile);
  const provenance = JSON.parse(await fs.promises.readFile(provenancePath, 'utf8'));
  provenance.materials.releaseProfileSha256 = sha256(profileBytes);
  const provenanceBytes = await writeCanonical(provenancePath, provenance);
  const manifest = JSON.parse(await fs.promises.readFile(manifestPath, 'utf8'));
  manifest.configSchemaVersion = 1;
  manifest.stateSchemaVersion = 1;
  manifest.artifacts[RELEASE_PROFILE_FILE] = sha256(profileBytes);
  manifest.artifacts[PROVENANCE_FILE] = sha256(provenanceBytes);
  const manifestBytes = await writeCanonical(manifestPath, manifest);
  await fs.promises.writeFile(
    path.join(copy, SIGNATURE_FILE),
    `${signManifest(manifestBytes, keys.privateKey)}\n`,
  );
  return copy;
}

async function withNetworkTraps(operation) {
  const modules = [
    require('node:http'),
    require('node:https'),
    require('node:net'),
    require('node:tls'),
  ];
  const names = [
    ['request', 'get'],
    ['request', 'get'],
    ['connect', 'createConnection'],
    ['connect'],
  ];
  const originals = [];
  let attempts = 0;
  for (let index = 0; index < modules.length; index += 1) {
    for (const name of names[index]) {
      originals.push([modules[index], name, modules[index][name]]);
      modules[index][name] = () => {
        attempts += 1;
        throw new Error('NETWORK_FORBIDDEN');
      };
    }
  }
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    attempts += 1;
    throw new Error('NETWORK_FORBIDDEN');
  };
  try {
    const result = await operation();
    return { attempts, result };
  } finally {
    globalThis.fetch = originalFetch;
    for (const [module, name, original] of originals) module[name] = original;
  }
}

before(async () => {
  sourceRoot = await createCleanSourceFixture(repositoryRoot);
  cleanup.push(sourceRoot);
  const outputParent = await temporaryDirectory('arc10-rc-output-');
  bundleDir = path.join(outputParent, 'bundle');
  await buildDistribution({ sourceRoot, outputDir: bundleDir, privateKey: keys.privateKey });
  verified = await verifyDistribution({ bundleDir, trustedPublicKey: keys.publicKey });
  cleanAudit = {
    format: 'cesspace-arc-vulnerability-report-v1',
    lockfileSha256: verified.manifest.lockfileSha256,
    findings: [],
  };
});

after(async () => {
  await Promise.all(
    cleanup.map((entry) => fs.promises.rm(entry, { recursive: true, force: true })),
  );
});

test('ARC10-NEG-068 rejects a malicious dependency artifact before lifecycle execution or release acceptance', async () => {
  const root = await temporaryDirectory('arc10-integrity-');
  const packageRoot = path.join(root, 'package');
  const consumerRoot = path.join(root, 'consumer');
  const marker = path.join(root, 'lifecycle-marker');
  await fs.promises.mkdir(packageRoot);
  await fs.promises.mkdir(consumerRoot);
  await fs.promises.writeFile(
    path.join(packageRoot, 'package.json'),
    JSON.stringify({
      name: 'arc-integrity-fixture',
      version: '1.0.0',
      scripts: { install: 'node install.cjs' },
    }),
  );
  await fs.promises.writeFile(
    path.join(packageRoot, 'install.cjs'),
    "require('node:fs').writeFileSync(process.env.ARC_INTEGRITY_MARKER, 'executed')\n",
  );
  await execFile('npm', ['pack', packageRoot, '--pack-destination', consumerRoot], {
    cwd: root,
    env: { ...process.env, npm_config_ignore_scripts: 'true' },
  });
  const tarball = path.join(consumerRoot, 'arc-integrity-fixture-1.0.0.tgz');
  await fs.promises.writeFile(
    path.join(consumerRoot, 'package.json'),
    JSON.stringify({
      name: 'arc-integrity-consumer',
      version: '1.0.0',
      dependencies: { 'arc-integrity-fixture': 'file:arc-integrity-fixture-1.0.0.tgz' },
    }),
  );
  await execFile('pnpm', ['install', '--lockfile-only', '--ignore-scripts', '--offline'], {
    cwd: consumerRoot,
  });
  const bytes = await fs.promises.readFile(tarball);
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  await fs.promises.writeFile(tarball, bytes);
  await assert.rejects(
    execFile('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts', '--offline'], {
      cwd: consumerRoot,
      env: { ...process.env, ARC_INTEGRITY_MARKER: marker },
    }),
    /integrity|checksum|tarball|ERR_PNPM/u,
  );
  assert.equal(fs.existsSync(marker), false);
  assert.equal(fs.existsSync(path.join(root, 'install-prefix')), false);
});

test('ARC10-NEG-069 proves release signing private keys are absent from tracked and bundled release surfaces', () => {
  const result = assertNoReleaseSigningPrivateKey({ repositoryRoot, bundleDir });
  assert.ok(result.repositoryFiles > 0);
  assert.equal(result.bundleFiles, 7);
  for (const name of fs.readdirSync(bundleDir)) {
    assert.equal(
      fs.readFileSync(path.join(bundleDir, name)).includes(Buffer.from(keys.privateKey)),
      false,
    );
  }
  const workflow = fs.readFileSync(path.join(repositoryRoot, '.github/workflows/ci.yml'), 'utf8');
  assert.match(workflow, /Gitleaks Secret Scanner/u);
});

test('ARC10-NEG-070 rejects forged signed-domain release manifest fields before acceptance', async () => {
  const mutations = [
    (manifest) => (manifest.version = '9.9.9'),
    (manifest) => (manifest.stage = 'FORGED'),
    (manifest) => (manifest.artifacts['source.arcsrc'] = '0'.repeat(64)),
    (manifest) => (manifest.source.commit = '0'.repeat(40)),
    (manifest) => manifest.platforms.supported.push('linux-arm64'),
    (manifest) => (manifest.expectedProductionTools = 26),
    (manifest) => (manifest.expectedDeterministicRegistryEntries = 6),
  ];
  for (const mutate of mutations) {
    const copy = await copyBundle();
    const manifestPath = path.join(copy, MANIFEST_FILE);
    const manifest = JSON.parse(await fs.promises.readFile(manifestPath, 'utf8'));
    mutate(manifest);
    await writeCanonical(manifestPath, manifest);
    await assert.rejects(
      verifyDistribution({ bundleDir: copy, trustedPublicKey: keys.publicKey }),
      (error) => error.code === 'INVALID_SIGNATURE',
    );
  }
});

test('ARC10-NEG-071 blocks an authentic older artifact against newer authoritative state', async () => {
  const olderBundle = await makeAuthenticOlderBundle();
  const authentic = await verifyDistribution({
    bundleDir: olderBundle,
    trustedPublicKey: keys.publicKey,
  });
  assert.equal(authentic.manifest.stateSchemaVersion, 1);
  await assert.rejects(
    async () =>
      assertArtifactStateCompatibility(authentic.manifest, {
        format: 'cesspace-arc-core-state',
        stateSchemaVersion: 2,
      }),
    (error) => error.code === 'UNSAFE_DOWNGRADE',
  );
  assert.equal(verified.manifest.stateSchemaVersion, 2);
});

test('ARC10-NEG-072 blocks critical and high vulnerability findings without filtering lesser findings', () => {
  for (const severity of ['critical', 'high']) {
    assert.throws(
      () =>
        evaluateVulnerabilityPolicy(
          {
            format: 'cesspace-arc-vulnerability-report-v1',
            lockfileSha256: verified.manifest.lockfileSha256,
            findings: [{ package: 'controlled-fixture', severity }],
          },
          verified.manifest.lockfileSha256,
        ),
      (error) => error.code === 'VULNERABILITY_RELEASE_BLOCKED',
    );
  }
  const recorded = evaluateVulnerabilityPolicy(
    {
      format: 'cesspace-arc-vulnerability-report-v1',
      lockfileSha256: verified.manifest.lockfileSha256,
      findings: [{ severity: 'moderate' }, { severity: 'low' }],
    },
    verified.manifest.lockfileSha256,
  );
  assert.deepEqual(recorded.severities, {
    critical: 0,
    high: 0,
    moderate: 1,
    low: 1,
    info: 0,
    unknown: 0,
  });
  assert.equal(JSON.parse(fs.readFileSync('package.json', 'utf8')).version, ARC_VERSION);
});

test('ARC10-NEG-073 rejects license or lockfile provenance omissions from dependency evidence', () => {
  const complete = assertDependencyCompleteness(verified);
  assert.ok(complete.dependencies > 0);
  assert.equal(complete.unresolvedLicenses, 0);
  for (const mutate of [
    (candidate) => (candidate.inventory.dependencies[0].license = 'UNKNOWN'),
    (candidate) => delete candidate.inventory.dependencies[0].source,
  ]) {
    const candidate = structuredClone(verified);
    mutate(candidate);
    assert.throws(
      () => assertDependencyCompleteness(candidate),
      (error) => error.code === 'DEPENDENCY_EVIDENCE_INCOMPLETE',
    );
  }
});

test('ARC10-NEG-074 proves no directory credential, vendor integration, or outbound directory request exists', async () => {
  assert.deepEqual(auditCoreOnlySurface(repositoryRoot, verified), { findings: 0 });
  const prefixParent = await temporaryDirectory('arc10-core-install-');
  const prefix = path.join(prefixParent, 'prefix');
  const workspace = await temporaryDirectory('arc10-core-workspace-');
  let directoryRequests = 0;
  const server = http.createServer((_request, response) => {
    directoryRequests += 1;
    response.writeHead(500).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const endpoint = `http://127.0.0.1:${server.address().port}/directory`;
  try {
    await installDistribution({ bundleDir, trustedPublicKey: keys.publicKey, prefix });
    const client = new InstalledStdioClient(
      path.join(prefix, 'runtime/apps/mcp-server/dist/index.js'),
      workspace,
      { OPENAI_DIRECTORY_ENDPOINT: endpoint, ANTHROPIC_DIRECTORY_ENDPOINT: endpoint },
    );
    try {
      const health = await client.health();
      assert.equal(health.version, ARC_VERSION);
      assert.equal(health.stage, ARC_STAGE);
    } finally {
      await client.close();
    }
    assert.equal(directoryRequests, 0);
    await uninstallDistribution({ prefix });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('ARC10-NEG-075 rejects a supported-platform claim without executable evidence', () => {
  const forged = structuredClone(verified.releaseProfile);
  const arm = forged.platforms.find((entry) => entry.target === 'linux-arm64');
  arm.classification = 'SUPPORTED';
  arm.evidence = 'EVIDENCE_EXECUTED';
  assert.throws(
    () => validateReleaseProfile(forged, { requireArtifactSource: true }),
    (error) => error.code === 'PLATFORM_EVIDENCE_INVALID',
  );
  assert.deepEqual(assertPlatformConsistency(verified.manifest, verified.releaseProfile), {
    supported: ['linux-x64'],
    developmentCompatible: ['wsl-linux-x64'],
    validationOnly: ['linux-arm64', 'darwin-arm64', 'darwin-x64'],
    unsupported: ['win32'],
  });
});

test('ARC10-FLOW-15 consumer verifies the Core artifact offline against exact source and independent trust', async () => {
  const observed = await withNetworkTraps(() =>
    verifyCoreReleaseCandidate({
      repositoryRoot,
      bundleDir,
      trustedPublicKey: keys.publicKey,
      vulnerabilityReport: cleanAudit,
      stateMetadata: { format: 'cesspace-arc-core-state', stateSchemaVersion: 2 },
    }),
  );
  const expectedCommit = (
    await execFile('git', ['rev-parse', 'HEAD'], { cwd: sourceRoot })
  ).stdout.trim();
  const expectedTree = (
    await execFile('git', ['rev-parse', 'HEAD^{tree}'], { cwd: sourceRoot })
  ).stdout.trim();
  assert.equal(observed.attempts, 0);
  assert.equal(observed.result.status, 'PASS');
  assert.equal(observed.result.gates.length, 12);
  assert.deepEqual(observed.result.source, { commit: expectedCommit, tree: expectedTree });
  assert.equal(observed.result.dependencyEvidence.unresolvedLicenses, 0);
  assert.equal(observed.result.hosted.findings, 0);
  assert.equal(observed.result.compatibility.decision, 'COMPATIBLE');
  const evidenceRoot = await temporaryDirectory('arc10-consumer-evidence-');
  const publicKeyPath = path.join(evidenceRoot, 'trusted-public.pem');
  const auditPath = path.join(evidenceRoot, 'audit.json');
  const statePath = path.join(evidenceRoot, 'state.json');
  await fs.promises.writeFile(publicKeyPath, keys.publicKey);
  await fs.promises.writeFile(auditPath, JSON.stringify(cleanAudit));
  await fs.promises.writeFile(
    statePath,
    JSON.stringify({ format: 'cesspace-arc-core-state', stateSchemaVersion: 2 }),
  );
  const cli = await execFile(
    process.execPath,
    ['scripts/verify-arc10-rc.mjs', bundleDir, publicKeyPath, auditPath, statePath],
    { cwd: repositoryRoot },
  );
  const report = JSON.parse(cli.stdout);
  assert.equal(report.status, 'PASS');
  assert.equal(report.gateCount, 12);
  assert.equal(report.networkRequired, false);
  assert.equal(report.published, false);
});

test('ARC10-FLOW-16 compatibility matrix reports only Linux x86-64 as evidence-backed supported', () => {
  const matrix = Object.fromEntries(
    verified.releaseProfile.platforms.map((entry) => [entry.target, entry]),
  );
  assert.deepEqual(
    [matrix['linux-x64'].classification, matrix['linux-x64'].evidence],
    ['SUPPORTED', 'EVIDENCE_EXECUTED'],
  );
  assert.deepEqual(
    [matrix['wsl-linux-x64'].classification, matrix['wsl-linux-x64'].evidence],
    ['DEVELOPMENT_COMPATIBLE', 'DECLARED_DEVELOPMENT_COMPATIBLE'],
  );
  for (const target of ['linux-arm64', 'darwin-arm64', 'darwin-x64']) {
    assert.deepEqual(
      [matrix[target].classification, matrix[target].evidence],
      ['VALIDATION_ONLY', 'DECLARED_VALIDATION_ONLY'],
    );
  }
  assert.deepEqual(
    [matrix.win32.classification, matrix.win32.evidence],
    ['UNSUPPORTED', 'UNSUPPORTED'],
  );
  assert.equal(matrix['linux-x64'].requirements.length, 5);
  assert.equal(verified.releaseProfile.profile, 'core');
  assert.equal(Object.values(verified.releaseProfile.capabilities).some(Boolean), false);
});
