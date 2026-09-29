import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { promisify } from 'node:util';
import {
  ARCHIVE_FILE,
  ARC_STAGE,
  ARC_VERSION,
  EXPECTED_REGISTRY_COUNT,
  EXPECTED_TOOL_COUNT,
  INVENTORY_FILE,
  MANIFEST_FILE,
  OWNERSHIP_FILE,
  PROVENANCE_FILE,
  SBOM_FILE,
  SIGNATURE_FILE,
  buildDistribution,
  canonicalJson,
  classifyPlatform,
  installDistribution,
  sha256,
  uninstallDistribution,
  verifyDistribution,
} from '../scripts/arc10-distribution-lib.mjs';
import {
  InstalledStdioClient,
  attachInstalledDependencies,
  cloneDirectory,
  createCleanSourceFixture,
  createSigningKeyPair,
  resignBundle,
} from './helpers/arc10-distribution-fixture.mjs';
import { ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import { createProductionDeterministicRegistry } from '../apps/mcp-server/dist/composite-framework.js';

const execFile = promisify(execFileCallback);
const repositoryRoot = process.cwd();
const cleanupPaths = [];
const keys = createSigningKeyPair();
let fixtureRoot;
let secondBuilderRoot;
let bundle;
let secondBundle;
let baseline;

async function temporaryDirectory(prefix) {
  const value = await fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
  cleanupPaths.push(value);
  return value;
}

async function copyBundle() {
  const value = await cloneDirectory(bundle);
  cleanupPaths.push(value);
  return value;
}

async function cloneSourceFixture(prefix) {
  const destination = await temporaryDirectory(prefix);
  await execFile('git', ['clone', '--quiet', '--no-hardlinks', fixtureRoot, destination], {
    maxBuffer: 32 * 1024 * 1024,
  });
  await attachInstalledDependencies(repositoryRoot, destination);
  return destination;
}

async function rewriteArtifact(bundleDir, artifactName, value, mutateManifest = () => {}) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`);
  await fs.promises.writeFile(path.join(bundleDir, artifactName), bytes);
  await resignBundle(bundleDir, keys.privateKey, async (manifest) => {
    manifest.artifacts[artifactName] = sha256(bytes);
    mutateManifest(manifest);
  });
  return bytes;
}

async function installedHealth(prefix, workspace) {
  const serverFile = path.join(prefix, 'runtime/apps/mcp-server/dist/index.js');
  const client = new InstalledStdioClient(serverFile, workspace);
  try {
    return await client.health();
  } finally {
    await client.close();
  }
}

before(async () => {
  fixtureRoot = await createCleanSourceFixture(repositoryRoot);
  cleanupPaths.push(fixtureRoot);
  bundle = await temporaryDirectory('arc10-output-parent-');
  bundle = path.join(bundle, 'bundle');
  baseline = await buildDistribution({
    sourceRoot: fixtureRoot,
    outputDir: bundle,
    privateKey: keys.privateKey,
  });

  secondBuilderRoot = await temporaryDirectory('arc10-second-builder-');
  await execFile('git', ['clone', '--quiet', '--no-hardlinks', fixtureRoot, secondBuilderRoot], {
    maxBuffer: 32 * 1024 * 1024,
  });
  await attachInstalledDependencies(repositoryRoot, secondBuilderRoot);
  const secondParent = await temporaryDirectory('arc10-second-output-');
  secondBundle = path.join(secondParent, 'bundle');
  await buildDistribution({
    sourceRoot: secondBuilderRoot,
    outputDir: secondBundle,
    privateKey: keys.privateKey,
  });
});

after(async () => {
  for (const target of cleanupPaths.reverse()) {
    await fs.promises.rm(target, { recursive: true, force: true });
  }
});

test('ARC10-NEG-001 rejects unsigned or invalidly signed artifacts before extraction or install', async () => {
  const candidate = await copyBundle();
  await fs.promises.rm(path.join(candidate, SIGNATURE_FILE));
  const prefixParent = await temporaryDirectory('arc10-neg001-');
  const prefix = path.join(prefixParent, 'install');
  const sentinel = path.join(prefixParent, 'sentinel');
  await fs.promises.writeFile(sentinel, 'unchanged');
  await assert.rejects(
    installDistribution({ bundleDir: candidate, trustedPublicKey: keys.publicKey, prefix }),
    (error) => error.code === 'SIGNATURE_REQUIRED',
  );
  assert.equal(await fs.promises.readFile(sentinel, 'utf8'), 'unchanged');
  await assert.rejects(fs.promises.access(prefix), { code: 'ENOENT' });
});

test('ARC10-NEG-002 rejects a post-signing artifact checksum mismatch without payload disclosure', async () => {
  const candidate = await copyBundle();
  await fs.promises.appendFile(path.join(candidate, ARCHIVE_FILE), Buffer.from([0]));
  await assert.rejects(
    verifyDistribution({ bundleDir: candidate, trustedPublicKey: keys.publicKey }),
    (error) => error.code === 'CHECKSUM_MISMATCH' && !error.message.includes('base64'),
  );
});

test('ARC10-NEG-003 rejects a validly signed provenance record for a different subject', async () => {
  const candidate = await copyBundle();
  const provenance = JSON.parse(await fs.promises.readFile(path.join(candidate, PROVENANCE_FILE)));
  provenance.subject.sha256 = '0'.repeat(64);
  await rewriteArtifact(candidate, PROVENANCE_FILE, provenance);
  await assert.rejects(
    verifyDistribution({ bundleDir: candidate, trustedPublicKey: keys.publicKey }),
    (error) => error.code === 'PROVENANCE_SUBJECT_MISMATCH',
  );
});

test('ARC10-NEG-004 rejects a validly signed SBOM that omits a locked production dependency', async () => {
  const candidate = await copyBundle();
  const sbom = JSON.parse(await fs.promises.readFile(path.join(candidate, SBOM_FILE)));
  assert.ok(sbom.packages.length > 1);
  sbom.packages.pop();
  await rewriteArtifact(candidate, SBOM_FILE, sbom);
  await assert.rejects(
    verifyDistribution({ bundleDir: candidate, trustedPublicKey: keys.publicKey }),
    (error) => error.code === 'SBOM_RECONCILIATION_FAILED',
  );
});

test('ARC10-NEG-005 blocks traversal, absolute, normalized, and link archive entries with zero outside writes', async () => {
  for (const unsafeEntry of [
    { path: '../outside', type: 'file' },
    { path: '../../escape', type: 'file' },
    { path: '/absolute', type: 'file' },
    { path: 'safe/../../escape', type: 'file' },
    { path: 'link', type: 'symlink' },
  ]) {
    const candidate = await copyBundle();
    const archive = JSON.parse(await fs.promises.readFile(path.join(candidate, ARCHIVE_FILE)));
    const data = Buffer.from('attack');
    archive.entries.push({
      data: data.toString('base64'),
      mode: '0644',
      path: unsafeEntry.path,
      sha256: sha256(data),
      size: data.length,
      type: unsafeEntry.type,
    });
    const archiveBytes = await rewriteArtifact(candidate, ARCHIVE_FILE, archive, (manifest) => {
      manifest.files.push({
        mode: '0644',
        path: unsafeEntry.path,
        sha256: sha256(data),
        size: data.length,
      });
    });
    const provenance = JSON.parse(
      await fs.promises.readFile(path.join(candidate, PROVENANCE_FILE)),
    );
    provenance.subject.sha256 = sha256(archiveBytes);
    await rewriteArtifact(candidate, PROVENANCE_FILE, provenance);
    const root = await temporaryDirectory('arc10-neg005-');
    const outside = path.join(root, 'outside');
    await fs.promises.writeFile(outside, 'sentinel');
    await assert.rejects(
      installDistribution({
        bundleDir: candidate,
        trustedPublicKey: keys.publicKey,
        prefix: path.join(root, 'prefix'),
      }),
      (error) => ['UNSAFE_ARCHIVE_PATH', 'UNSAFE_ARCHIVE_ENTRY'].includes(error.code),
    );
    assert.equal(await fs.promises.readFile(outside, 'utf8'), 'sentinel');
    assert.deepEqual((await fs.promises.readdir(root)).sort(), ['outside']);
  }
});

test('ARC10-NEG-006 rejects secret-contaminated source artifacts with sanitized diagnostics', async () => {
  const secrets = [
    ['ghp', 'A'.repeat(30)].join('_'),
    `Bearer ${'b'.repeat(32)}`,
    `-----BEGIN PRIVATE KEY-----\n${'Q'.repeat(48)}\n-----END PRIVATE KEY-----`,
    `approval_token=${'c'.repeat(40)}`,
  ];
  for (const [index, secret] of secrets.entries()) {
    const contaminated = await temporaryDirectory(`arc10-secret-source-${index}-`);
    await execFile('git', ['clone', '--quiet', '--no-hardlinks', fixtureRoot, contaminated]);
    await fs.promises.mkdir(path.join(contaminated, 'docs/distribution'), { recursive: true });
    await fs.promises.writeFile(
      path.join(contaminated, 'docs/distribution/contamination.md'),
      secret,
    );
    await execFile('git', ['add', '.'], { cwd: contaminated });
    await execFile(
      'git',
      [
        '-c',
        'user.name=ARC Test',
        '-c',
        'user.email=arc@example.invalid',
        'commit',
        '--quiet',
        '-m',
        'contaminate',
      ],
      { cwd: contaminated },
    );
    let observed;
    try {
      await buildDistribution({
        sourceRoot: contaminated,
        outputDir: path.join(contaminated, 'out'),
        privateKey: keys.privateKey,
      });
    } catch (error) {
      observed = error;
    }
    assert.equal(observed.code, 'ARTIFACT_SECRET_DETECTED');
    assert.equal(observed.message.includes(secret), false);
  }
});

test('ARC10-NEG-007 detects a reproducibility-relevant source perturbation in the actual archive digest', async () => {
  const first = await fs.promises.readFile(path.join(bundle, ARCHIVE_FILE));
  const second = await fs.promises.readFile(path.join(secondBundle, ARCHIVE_FILE));
  assert.deepEqual(first, second);
  await fs.promises.appendFile(
    path.join(secondBuilderRoot, 'README.md'),
    '\nReproducibility input perturbation.\n',
  );
  await execFile('git', ['add', 'README.md'], { cwd: secondBuilderRoot });
  await execFile(
    'git',
    [
      '-c',
      'user.name=ARC Test',
      '-c',
      'user.email=arc@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'perturb',
    ],
    { cwd: secondBuilderRoot },
  );
  const parent = await temporaryDirectory('arc10-perturbed-output-');
  const perturbed = await buildDistribution({
    sourceRoot: secondBuilderRoot,
    outputDir: path.join(parent, 'bundle'),
    privateKey: keys.privateKey,
  });
  assert.notEqual(perturbed.normalizedDigest, baseline.normalizedDigest);
});

test('source provenance excludes untracked and ignored eligible files from the declared HEAD archive', async () => {
  const untrackedSource = await cloneSourceFixture('arc10-untracked-source-');
  const untrackedPath = 'apps/mcp-server/src/untracked-provenance-injection.ts';
  await fs.promises.writeFile(path.join(untrackedSource, untrackedPath), 'untracked injection\n');
  const untrackedParent = await temporaryDirectory('arc10-untracked-output-');
  const untrackedBundle = path.join(untrackedParent, 'bundle');
  const untrackedResult = await buildDistribution({
    sourceRoot: untrackedSource,
    outputDir: untrackedBundle,
    privateKey: keys.privateKey,
  });
  const untrackedArchive = JSON.parse(
    await fs.promises.readFile(path.join(untrackedBundle, ARCHIVE_FILE), 'utf8'),
  );
  assert.equal(
    untrackedArchive.entries.some((entry) => entry.path === untrackedPath),
    false,
  );
  assert.equal(
    untrackedResult.manifest.source.commit,
    (await execFile('git', ['rev-parse', 'HEAD'], { cwd: untrackedSource })).stdout.trim(),
  );
  assert.equal(
    untrackedResult.manifest.source.tree,
    (await execFile('git', ['rev-parse', 'HEAD^{tree}'], { cwd: untrackedSource })).stdout.trim(),
  );

  const ignoredSource = await cloneSourceFixture('arc10-ignored-source-');
  const ignoredPath = 'docs/distribution/ignored-provenance-injection.md';
  await fs.promises.appendFile(path.join(ignoredSource, '.gitignore'), `\n${ignoredPath}\n`);
  await execFile('git', ['add', '.gitignore'], { cwd: ignoredSource });
  await execFile(
    'git',
    [
      '-c',
      'user.name=ARC Test',
      '-c',
      'user.email=arc@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'ignore provenance fixture',
    ],
    { cwd: ignoredSource },
  );
  await fs.promises.writeFile(path.join(ignoredSource, ignoredPath), 'ignored injection\n');
  const ignoredParent = await temporaryDirectory('arc10-ignored-output-');
  const ignoredBundle = path.join(ignoredParent, 'bundle');
  await buildDistribution({
    sourceRoot: ignoredSource,
    outputDir: ignoredBundle,
    privateKey: keys.privateKey,
  });
  const ignoredArchive = JSON.parse(
    await fs.promises.readFile(path.join(ignoredBundle, ARCHIVE_FILE), 'utf8'),
  );
  assert.equal(
    ignoredArchive.entries.some((entry) => entry.path === ignoredPath),
    false,
  );
});

test('source provenance refuses tracked unstaged and staged-but-uncommitted changes', async () => {
  for (const staged of [false, true]) {
    const source = await cloneSourceFixture(
      staged ? 'arc10-staged-source-' : 'arc10-unstaged-source-',
    );
    await fs.promises.appendFile(
      path.join(source, 'README.md'),
      '\nuncommitted provenance change\n',
    );
    if (staged) await execFile('git', ['add', 'README.md'], { cwd: source });
    const outputParent = await temporaryDirectory(
      staged ? 'arc10-staged-output-' : 'arc10-unstaged-output-',
    );
    await assert.rejects(
      buildDistribution({
        sourceRoot: source,
        outputDir: path.join(outputParent, 'bundle'),
        privateKey: keys.privateKey,
      }),
      (error) => error.code === 'DIRTY_SOURCE',
    );
  }
});

test('source archive bytes and executable modes equal representative exact HEAD objects', async () => {
  const archive = JSON.parse(await fs.promises.readFile(path.join(bundle, ARCHIVE_FILE), 'utf8'));
  for (const relativePath of [
    'package.json',
    'apps/mcp-server/src/index.ts',
    'scripts/arc10-build-distribution.mjs',
  ]) {
    const entry = archive.entries.find((candidate) => candidate.path === relativePath);
    assert.ok(entry, `${relativePath} must be selected from HEAD`);
    const headBlob = (
      await execFile('git', ['show', `HEAD:${relativePath}`], {
        cwd: fixtureRoot,
        encoding: 'buffer',
        maxBuffer: 32 * 1024 * 1024,
      })
    ).stdout;
    assert.deepEqual(Buffer.from(entry.data, 'base64'), headBlob);
    const treeMetadata = (
      await execFile('git', ['ls-tree', 'HEAD', '--', relativePath], { cwd: fixtureRoot })
    ).stdout;
    assert.equal(entry.mode, treeMetadata.startsWith('100755 ') ? '0755' : '0644');
  }
});

test('ARC10-NEG-008 enforces authoritative Linux x86-64 platform support without partial install', async () => {
  assert.deepEqual(classifyPlatform({ platform: 'linux', arch: 'x64' }), {
    accepted: true,
    classification: 'supported',
    target: 'linux-x64',
  });
  assert.equal(
    classifyPlatform({ platform: 'linux', arch: 'arm64' }).classification,
    'validation-only',
  );
  assert.equal(
    classifyPlatform({ platform: 'darwin', arch: 'arm64' }).classification,
    'validation-only',
  );
  assert.equal(classifyPlatform({ platform: 'win32', arch: 'x64' }).classification, 'unsupported');
  const root = await temporaryDirectory('arc10-neg008-');
  const prefix = path.join(root, 'prefix');
  await assert.rejects(
    installDistribution({
      bundleDir: bundle,
      trustedPublicKey: keys.publicKey,
      prefix,
      platform: { platform: 'win32', arch: 'x64' },
    }),
    (error) => error.code === 'UNSUPPORTED_PLATFORM',
  );
  await assert.rejects(fs.promises.access(prefix), { code: 'ENOENT' });
});

test('ARC10-NEG-009 refuses privileged system prefixes before command or filesystem mutation', async () => {
  let commands = 0;
  for (const prefix of ['/usr/local/cesspace-arc', '/etc/cesspace-arc', '/opt/cesspace-arc']) {
    await assert.rejects(
      installDistribution({
        bundleDir: bundle,
        trustedPublicKey: keys.publicKey,
        prefix,
        commandRunner: async () => {
          commands++;
          throw new Error('must not run');
        },
      }),
      (error) => error.code === 'PRIVILEGED_INSTALL_REFUSED',
    );
  }
  assert.equal(commands, 0);
});

test('ARC10-NEG-010 safe uninstall removes only owned artifacts and preserves workspace, config, audit, and unrelated data', async () => {
  const root = await temporaryDirectory('arc10-neg010-');
  const prefix = path.join(root, 'prefix');
  await installDistribution({ bundleDir: bundle, trustedPublicKey: keys.publicKey, prefix });
  for (const name of ['workspace', 'config', 'audit', 'unrelated']) {
    await fs.promises.mkdir(path.join(prefix, name));
    await fs.promises.writeFile(path.join(prefix, name, 'sentinel'), `${name}-data`);
  }
  await uninstallDistribution({ prefix });
  for (const name of ['workspace', 'config', 'audit', 'unrelated']) {
    assert.equal(
      await fs.promises.readFile(path.join(prefix, name, 'sentinel'), 'utf8'),
      `${name}-data`,
    );
  }
  await assert.rejects(fs.promises.access(path.join(prefix, OWNERSHIP_FILE)), { code: 'ENOENT' });
  await assert.rejects(fs.promises.access(path.join(prefix, 'runtime')), { code: 'ENOENT' });
});

test('ARC10-NEG-011 binds the exact lockfile and permits no unlocked dependency fallback', async () => {
  const candidate = await copyBundle();
  const archive = JSON.parse(await fs.promises.readFile(path.join(candidate, ARCHIVE_FILE)));
  const lock = archive.entries.find((entry) => entry.path === 'pnpm-lock.yaml');
  const altered = Buffer.from(`${Buffer.from(lock.data, 'base64').toString('utf8')}\n# drift\n`);
  lock.data = altered.toString('base64');
  lock.sha256 = sha256(altered);
  lock.size = altered.length;
  const archiveBytes = await rewriteArtifact(candidate, ARCHIVE_FILE, archive);
  const provenance = JSON.parse(await fs.promises.readFile(path.join(candidate, PROVENANCE_FILE)));
  provenance.subject.sha256 = sha256(archiveBytes);
  await rewriteArtifact(candidate, PROVENANCE_FILE, provenance);
  await assert.rejects(
    verifyDistribution({ bundleDir: candidate, trustedPublicKey: keys.publicKey }),
    (error) => error.code === 'LOCKFILE_MISMATCH',
  );

  const commands = [];
  const root = await temporaryDirectory('arc10-neg011-');
  await installDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
    prefix: path.join(root, 'prefix'),
    commandRunner: async (file, args) => {
      commands.push([file, ...args]);
      return { stdout: '', stderr: '' };
    },
  });
  assert.deepEqual(commands[0], [
    'pnpm',
    'install',
    '--prefer-offline',
    '--frozen-lockfile',
    '--ignore-scripts',
  ]);
  assert.equal(commands.flat().includes('--no-frozen-lockfile'), false);
});

test('ARC10-NEG-012 preserves package, CLI, health, distribution, tool, and registry identity', async () => {
  const verified = await verifyDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
  });
  for (const manifest of [
    'package.json',
    'apps/mcp-server/package.json',
    'apps/cli/package.json',
  ]) {
    assert.equal(
      JSON.parse(await fs.promises.readFile(path.join(repositoryRoot, manifest))).version,
      ARC_VERSION,
    );
  }
  const cli = await fs.promises.readFile(
    path.join(repositoryRoot, 'apps/cli/src/index.ts'),
    'utf8',
  );
  const server = await fs.promises.readFile(
    path.join(repositoryRoot, 'apps/mcp-server/src/index.ts'),
    'utf8',
  );
  assert.match(cli, /CLI_VERSION = '0\.8\.0-rc08'/u);
  assert.match(server, /version: '0\.8\.0-rc08'/u);
  assert.match(server, /stage: 'RC-08'/u);
  assert.equal(verified.manifest.version, ARC_VERSION);
  assert.equal(verified.manifest.stage, ARC_STAGE);
  assert.equal(verified.provenance.source.commit, verified.manifest.source.commit);
  assert.equal(ALL_TOOL_DEFINITIONS.length, EXPECTED_TOOL_COUNT);
  assert.equal(
    createProductionDeterministicRegistry().listEntryIds().length,
    EXPECTED_REGISTRY_COUNT,
  );
  const root = await temporaryDirectory('arc10-neg012-');
  const installed = await installDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
    prefix: path.join(root, 'prefix'),
    commandRunner: async () => ({ stdout: '', stderr: '' }),
  });
  assert.equal(installed.ownership.version, ARC_VERSION);
  assert.equal(installed.ownership.stage, ARC_STAGE);
  assert.equal(installed.ownership.sourceCommit, verified.manifest.source.commit);
});

test('ARC10-FLOW-01 performs verified frozen source installation, real health startup, shutdown, and uninstall', async () => {
  const root = await temporaryDirectory('arc10-flow01-');
  const prefix = path.join(root, 'prefix');
  const workspace = path.join(root, 'workspace');
  await fs.promises.mkdir(workspace);
  const verified = await verifyDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
  });
  const installed = await installDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
    prefix,
  });
  assert.equal(installed.ownership.sourceCommit, verified.manifest.source.commit);
  const health = await installedHealth(prefix, workspace);
  assert.equal(health.version, ARC_VERSION);
  assert.equal(health.stage, ARC_STAGE);
  await uninstallDistribution({ prefix });
  await assert.rejects(fs.promises.access(path.join(prefix, 'runtime')), { code: 'ENOENT' });
});

test('ARC10-FLOW-02 produces equivalent normalized release evidence in independent clean builders', async () => {
  const names = [ARCHIVE_FILE, MANIFEST_FILE, SBOM_FILE, INVENTORY_FILE, PROVENANCE_FILE];
  const digests = {};
  for (const name of names) {
    const first = await fs.promises.readFile(path.join(bundle, name));
    const second = await fs.promises.readFile(path.join(secondBundle, name));
    assert.deepEqual(first, second, `${name} differs between clean builders`);
    digests[name] = sha256(first);
  }
  await verifyDistribution({ bundleDir: bundle, trustedPublicKey: keys.publicKey });
  await verifyDistribution({ bundleDir: secondBundle, trustedPublicKey: keys.publicKey });
  const firstManifest = JSON.parse(await fs.promises.readFile(path.join(bundle, MANIFEST_FILE)));
  const secondManifest = JSON.parse(
    await fs.promises.readFile(path.join(secondBundle, MANIFEST_FILE)),
  );
  assert.deepEqual(firstManifest.source, secondManifest.source);
  assert.equal(
    firstManifest.source.commit,
    (await execFile('git', ['rev-parse', 'HEAD'], { cwd: fixtureRoot })).stdout.trim(),
  );
  assert.equal(
    firstManifest.source.tree,
    (await execFile('git', ['rev-parse', 'HEAD^{tree}'], { cwd: fixtureRoot })).stdout.trim(),
  );
  process.stdout.write(`ARC10 reproducible digests ${JSON.stringify(digests)}\n`);
});

test('ARC10-FLOW-03 clean uninstall preserves data and permits verified reinstall with unchanged health identity', async () => {
  const root = await temporaryDirectory('arc10-flow03-');
  const prefix = path.join(root, 'prefix');
  const workspace = path.join(root, 'workspace');
  const config = path.join(root, 'config');
  const audit = path.join(root, 'audit');
  for (const directory of [workspace, config, audit]) await fs.promises.mkdir(directory);
  await fs.promises.writeFile(path.join(workspace, 'sentinel'), 'workspace-data');
  await fs.promises.writeFile(path.join(config, 'sentinel'), 'config-data');
  await fs.promises.writeFile(path.join(audit, 'sentinel'), 'audit-data');
  const first = await installDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
    prefix,
  });
  const firstHealth = await installedHealth(prefix, workspace);
  await uninstallDistribution({ prefix });
  assert.equal(
    await fs.promises.readFile(path.join(workspace, 'sentinel'), 'utf8'),
    'workspace-data',
  );
  assert.equal(await fs.promises.readFile(path.join(config, 'sentinel'), 'utf8'), 'config-data');
  assert.equal(await fs.promises.readFile(path.join(audit, 'sentinel'), 'utf8'), 'audit-data');
  const second = await installDistribution({
    bundleDir: bundle,
    trustedPublicKey: keys.publicKey,
    prefix,
  });
  const secondHealth = await installedHealth(prefix, workspace);
  assert.deepEqual(secondHealth, firstHealth);
  assert.equal(second.ownership.sourceCommit, first.ownership.sourceCommit);
  await uninstallDistribution({ prefix });
});
