import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);

export const DISTRIBUTION_FORMAT = 'cesspace-arc-source-distribution-v1';
export const ARCHIVE_FORMAT = 'cesspace-arc-source-archive-v1';
export const MANIFEST_FILE = 'manifest.json';
export const SIGNATURE_FILE = 'manifest.sig';
export const ARCHIVE_FILE = 'source.arcsrc';
export const SBOM_FILE = 'sbom.spdx.json';
export const INVENTORY_FILE = 'dependencies.json';
export const PROVENANCE_FILE = 'provenance.json';
export const OWNERSHIP_FILE = '.cesspace-arc-install.json';
export const ARC_VERSION = '0.8.0-rc08';
export const ARC_STAGE = 'RC-08';
export const EXPECTED_TOOL_COUNT = 25;
export const EXPECTED_REGISTRY_COUNT = 5;

const SOURCE_PATTERNS = [
  /^(?:LICENSE|README\.md|SECURITY\.md|package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|tsconfig(?:\.base)?\.json)$/,
  /^(?:apps|packages)\/[^/]+\/(?:package\.json|tsconfig\.json|src\/.*)$/,
  /^scripts\/arc10-[^/]+\.mjs$/,
  /^docs\/distribution\/.*$/,
];

const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----[\s\S]{8,}?-----END (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----/u,
  /\bgh[opusr]_[A-Za-z0-9]{20,}\b/u,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b/iu,
  /\b(?:session|approval)[_-]?(?:token)?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{24,}/iu,
];

export class DistributionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DistributionError';
    this.code = code;
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function normalizeRelativePath(input) {
  if (
    typeof input !== 'string' ||
    input.length === 0 ||
    input.length > 4096 ||
    input.includes('\0')
  ) {
    throw new DistributionError('UNSAFE_ARCHIVE_PATH', 'Archive contains an invalid path');
  }
  if (input.includes('\\') || path.posix.isAbsolute(input)) {
    throw new DistributionError('UNSAFE_ARCHIVE_PATH', 'Archive contains an unsafe path');
  }
  const normalized = path.posix.normalize(input);
  if (
    normalized !== input ||
    normalized === '.' ||
    normalized === '..' ||
    normalized.startsWith('../')
  ) {
    throw new DistributionError('UNSAFE_ARCHIVE_PATH', 'Archive path escapes the staging root');
  }
  return normalized;
}

function assertNoSecrets(name, bytes) {
  const text = bytes.toString('utf8');
  if (SECRET_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new DistributionError(
      'ARTIFACT_SECRET_DETECTED',
      `Release secret gate rejected ${path.posix.basename(name)}`,
    );
  }
}

async function command(commandRunner, file, args, options = {}) {
  const runner = commandRunner ?? execFile;
  return runner(file, args, { ...options, maxBuffer: 32 * 1024 * 1024 });
}

async function gitValue(root, args, commandRunner) {
  const result = await command(commandRunner, 'git', ['-C', root, ...args]);
  return result.stdout.trim();
}

function flattenDependencyTree(roots) {
  const packages = new Map();
  const visit = (node, requiredBy) => {
    for (const [name, dependency] of Object.entries(node.dependencies ?? {})) {
      const version = String(dependency.version ?? 'UNKNOWN').replace(/^link:/u, 'workspace:');
      if (!version.startsWith('workspace:')) {
        const key = `${name}@${version}`;
        const current = packages.get(key) ?? { name, version, requiredBy: new Set() };
        current.requiredBy.add(requiredBy);
        packages.set(key, current);
      }
      visit(dependency, name);
    }
  };
  for (const root of roots) visit(root, root.name ?? 'cesspace-arc');
  return [...packages.values()]
    .map((entry) => ({ ...entry, requiredBy: [...entry.requiredBy].sort() }))
    .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

function licenseLookup(report) {
  const lookup = new Map();
  const add = (license, item) => {
    if (!item?.name || !item?.version) return;
    const key = `${item.name}@${item.version}`;
    if (!lookup.has(key)) lookup.set(key, license || 'UNKNOWN');
  };
  if (Array.isArray(report)) {
    for (const item of report) add(item.license, item);
  } else {
    for (const [license, items] of Object.entries(report ?? {})) {
      for (const item of Array.isArray(items) ? items : []) add(license, item);
    }
  }
  return lookup;
}

export async function createDependencyEvidence(sourceRoot, lockfileSha256, options = {}) {
  const listed = await command(
    options.commandRunner,
    'pnpm',
    ['list', '--prod', '--recursive', '--json', '--depth', 'Infinity'],
    { cwd: sourceRoot },
  );
  const licensed = await command(
    options.commandRunner,
    'pnpm',
    ['licenses', 'list', '--prod', '--json'],
    { cwd: sourceRoot },
  );
  const dependencies = flattenDependencyTree(JSON.parse(listed.stdout));
  const licenses = licenseLookup(JSON.parse(licensed.stdout));
  for (const dependency of dependencies) {
    dependency.license = licenses.get(`${dependency.name}@${dependency.version}`) ?? 'UNKNOWN';
  }
  const inventory = {
    format: 'cesspace-arc-dependency-inventory-v1',
    lockfileSha256,
    profile: 'core',
    dependencies,
  };
  const sbom = {
    SPDXID: 'SPDXRef-DOCUMENT',
    creationInfo: {
      created: '1970-01-01T00:00:00Z',
      creators: ['Tool: CesSpace-ARC-distribution-v1'],
    },
    dataLicense: 'CC0-1.0',
    documentNamespace: `https://cesspace.dev/spdx/arc/${lockfileSha256}`,
    name: `CesSpace ARC ${ARC_VERSION} core`,
    packages: dependencies.map((dependency, index) => ({
      SPDXID: `SPDXRef-Package-${index + 1}`,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: dependency.license,
      name: dependency.name,
      versionInfo: dependency.version,
    })),
    spdxVersion: 'SPDX-2.3',
  };
  return { inventory, sbom };
}

export async function createSourceArchive(sourceRoot, options = {}) {
  const treeResult = await command(
    options.commandRunner,
    'git',
    ['-C', sourceRoot, 'ls-tree', '-rz', '--full-tree', 'HEAD'],
    { encoding: 'buffer' },
  );
  const records = treeResult.stdout.toString('utf8').split('\0').filter(Boolean);
  const entries = [];
  for (const record of records) {
    const match = /^(\d{6}) (\S+) ([0-9a-f]+)\t(.+)$/u.exec(record);
    if (!match) {
      throw new DistributionError('INVALID_SOURCE_TREE', 'Git returned malformed tree metadata');
    }
    const [, gitMode, gitType, objectId, relativePath] = match;
    if (!SOURCE_PATTERNS.some((pattern) => pattern.test(relativePath))) continue;
    const normalized = normalizeRelativePath(relativePath);
    if (gitType !== 'blob' || !['100644', '100755'].includes(gitMode)) {
      throw new DistributionError(
        'UNSAFE_SOURCE_ENTRY',
        `Selected source entry is not a regular file: ${path.posix.basename(normalized)}`,
      );
    }
    const blobResult = await command(
      options.commandRunner,
      'git',
      ['-C', sourceRoot, 'cat-file', 'blob', objectId],
      { encoding: 'buffer' },
    );
    const bytes = blobResult.stdout;
    assertNoSecrets(normalized, bytes);
    entries.push({
      data: bytes.toString('base64'),
      mode: gitMode === '100755' ? '0755' : '0644',
      path: normalized,
      sha256: sha256(bytes),
      size: bytes.length,
      type: 'file',
    });
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const archive = { entries, format: ARCHIVE_FORMAT };
  return { archive, bytes: Buffer.from(`${canonicalJson(archive)}\n`) };
}

export function signManifest(manifestBytes, privateKey) {
  const key = createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new DistributionError(
      'INVALID_SIGNING_KEY',
      'An Ed25519 private signing key is required',
    );
  }
  return cryptoSign(null, Buffer.from(sha256(manifestBytes), 'hex'), key).toString('base64');
}

export function verifyManifestSignature(manifestBytes, signature, trustedPublicKey) {
  const key = createPublicKey(trustedPublicKey);
  if (key.asymmetricKeyType !== 'ed25519') return false;
  return cryptoVerify(
    null,
    Buffer.from(sha256(manifestBytes), 'hex'),
    key,
    Buffer.from(signature.trim(), 'base64'),
  );
}

export async function buildDistribution({ sourceRoot, outputDir, privateKey, commandRunner }) {
  if (!privateKey) throw new DistributionError('SIGNING_KEY_REQUIRED', 'A signing key is required');
  const sourceCommit = await gitValue(sourceRoot, ['rev-parse', 'HEAD'], commandRunner);
  const sourceTree = await gitValue(sourceRoot, ['rev-parse', 'HEAD^{tree}'], commandRunner);
  const dirty = await gitValue(
    sourceRoot,
    ['status', '--porcelain=v1', '--untracked-files=no', '--ignore-submodules=none'],
    commandRunner,
  );
  if (dirty)
    throw new DistributionError('DIRTY_SOURCE', 'Distribution source must be committed and clean');

  const { archive, bytes: archiveBytes } = await createSourceArchive(sourceRoot, { commandRunner });
  const packageEntry = archive.entries.find((entry) => entry.path === 'package.json');
  if (!packageEntry)
    throw new DistributionError(
      'PACKAGE_MANIFEST_REQUIRED',
      'The tracked package manifest is required',
    );
  const packageJson = JSON.parse(Buffer.from(packageEntry.data, 'base64').toString('utf8'));
  if (packageJson.version !== ARC_VERSION) {
    throw new DistributionError(
      'VERSION_MISMATCH',
      'Source version does not match the distribution contract',
    );
  }
  const lockEntry = archive.entries.find((entry) => entry.path === 'pnpm-lock.yaml');
  if (!lockEntry)
    throw new DistributionError('LOCKFILE_REQUIRED', 'The exact pnpm lockfile is required');
  const { inventory, sbom } = await createDependencyEvidence(sourceRoot, lockEntry.sha256, {
    commandRunner,
  });
  const inventoryBytes = Buffer.from(`${canonicalJson(inventory)}\n`);
  const sbomBytes = Buffer.from(`${canonicalJson(sbom)}\n`);
  const provenance = {
    buildType: DISTRIBUTION_FORMAT,
    builder: { node: packageJson.engines.node, pnpm: packageJson.packageManager },
    materials: {
      dependencyInventorySha256: sha256(inventoryBytes),
      lockfileSha256: lockEntry.sha256,
      sbomSha256: sha256(sbomBytes),
    },
    profile: 'core',
    source: { commit: sourceCommit, tree: sourceTree },
    subject: { name: ARCHIVE_FILE, sha256: sha256(archiveBytes) },
  };
  const provenanceBytes = Buffer.from(`${canonicalJson(provenance)}\n`);
  const manifest = {
    format: DISTRIBUTION_FORMAT,
    profile: 'core',
    version: ARC_VERSION,
    stage: ARC_STAGE,
    source: { commit: sourceCommit, tree: sourceTree },
    toolchain: { node: packageJson.engines.node, pnpm: packageJson.packageManager },
    platforms: {
      supported: ['linux-x64'],
      developmentCompatible: ['wsl-linux-x64'],
      validationOnly: ['linux-arm64', 'darwin-arm64', 'darwin-x64'],
      unsupported: ['win32'],
    },
    expectedProductionTools: EXPECTED_TOOL_COUNT,
    expectedDeterministicRegistryEntries: EXPECTED_REGISTRY_COUNT,
    files: archive.entries.map(({ path: entryPath, mode, sha256: digest, size }) => ({
      mode,
      path: entryPath,
      sha256: digest,
      size,
    })),
    artifacts: {
      [ARCHIVE_FILE]: sha256(archiveBytes),
      [INVENTORY_FILE]: sha256(inventoryBytes),
      [PROVENANCE_FILE]: sha256(provenanceBytes),
      [SBOM_FILE]: sha256(sbomBytes),
    },
    lockfileSha256: lockEntry.sha256,
  };
  const manifestBytes = Buffer.from(`${canonicalJson(manifest)}\n`);
  const signature = signManifest(manifestBytes, privateKey);
  const parent = path.dirname(outputDir);
  await fs.promises.mkdir(parent, { recursive: true });
  try {
    await fs.promises.access(outputDir);
    throw new DistributionError('OUTPUT_EXISTS', 'Distribution output path must not already exist');
  } catch (error) {
    if (error instanceof DistributionError) throw error;
    if (error.code !== 'ENOENT') throw error;
  }
  const staging = await fs.promises.mkdtemp(path.join(parent, '.arc-dist-'));
  try {
    await Promise.all([
      fs.promises.writeFile(path.join(staging, ARCHIVE_FILE), archiveBytes, { mode: 0o644 }),
      fs.promises.writeFile(path.join(staging, INVENTORY_FILE), inventoryBytes, { mode: 0o644 }),
      fs.promises.writeFile(path.join(staging, SBOM_FILE), sbomBytes, { mode: 0o644 }),
      fs.promises.writeFile(path.join(staging, PROVENANCE_FILE), provenanceBytes, { mode: 0o644 }),
      fs.promises.writeFile(path.join(staging, MANIFEST_FILE), manifestBytes, { mode: 0o644 }),
      fs.promises.writeFile(path.join(staging, SIGNATURE_FILE), `${signature}\n`, { mode: 0o644 }),
    ]);
    await fs.promises.rename(staging, outputDir);
  } catch (error) {
    await fs.promises.rm(staging, { recursive: true, force: true });
    throw error;
  }
  return { manifest, normalizedDigest: sha256(archiveBytes) };
}

function parseCanonicalFile(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new DistributionError('INVALID_DISTRIBUTION', `${label} is not valid JSON`);
  }
}

export async function verifyDistribution({ bundleDir, trustedPublicKey }) {
  if (!trustedPublicKey) {
    throw new DistributionError(
      'TRUSTED_KEY_REQUIRED',
      'An independently trusted public key is required',
    );
  }
  let manifestBytes;
  let signature;
  try {
    manifestBytes = await fs.promises.readFile(path.join(bundleDir, MANIFEST_FILE));
    signature = await fs.promises.readFile(path.join(bundleDir, SIGNATURE_FILE), 'utf8');
  } catch {
    throw new DistributionError('SIGNATURE_REQUIRED', 'Distribution signature is missing');
  }
  if (!verifyManifestSignature(manifestBytes, signature, trustedPublicKey)) {
    throw new DistributionError('INVALID_SIGNATURE', 'Distribution signature verification failed');
  }
  const manifest = parseCanonicalFile(manifestBytes, MANIFEST_FILE);
  if (manifest.format !== DISTRIBUTION_FORMAT || manifest.profile !== 'core') {
    throw new DistributionError(
      'INVALID_DISTRIBUTION',
      'Unsupported distribution format or profile',
    );
  }
  const artifactBytes = {};
  for (const artifact of [ARCHIVE_FILE, INVENTORY_FILE, PROVENANCE_FILE, SBOM_FILE]) {
    let bytes;
    try {
      bytes = await fs.promises.readFile(path.join(bundleDir, artifact));
    } catch {
      throw new DistributionError('ARTIFACT_MISSING', `Required artifact ${artifact} is missing`);
    }
    if (sha256(bytes) !== manifest.artifacts?.[artifact]) {
      throw new DistributionError('CHECKSUM_MISMATCH', `Digest mismatch for ${artifact}`);
    }
    artifactBytes[artifact] = bytes;
  }
  const archive = parseCanonicalFile(artifactBytes[ARCHIVE_FILE], ARCHIVE_FILE);
  const inventory = parseCanonicalFile(artifactBytes[INVENTORY_FILE], INVENTORY_FILE);
  const provenance = parseCanonicalFile(artifactBytes[PROVENANCE_FILE], PROVENANCE_FILE);
  const sbom = parseCanonicalFile(artifactBytes[SBOM_FILE], SBOM_FILE);
  if (archive.format !== ARCHIVE_FORMAT || !Array.isArray(archive.entries)) {
    throw new DistributionError('INVALID_ARCHIVE', 'Source archive format is invalid');
  }
  if (
    provenance.subject?.name !== ARCHIVE_FILE ||
    provenance.subject?.sha256 !== sha256(artifactBytes[ARCHIVE_FILE]) ||
    provenance.source?.commit !== manifest.source?.commit ||
    provenance.source?.tree !== manifest.source?.tree
  ) {
    throw new DistributionError(
      'PROVENANCE_SUBJECT_MISMATCH',
      'Provenance does not bind this source artifact',
    );
  }
  const entryNames = new Set();
  for (const entry of archive.entries) {
    const normalized = normalizeRelativePath(entry.path);
    if (
      entryNames.has(normalized) ||
      entry.type !== 'file' ||
      !['0644', '0755'].includes(entry.mode)
    ) {
      throw new DistributionError(
        'UNSAFE_ARCHIVE_ENTRY',
        'Archive contains an unsafe or duplicate entry',
      );
    }
    entryNames.add(normalized);
    const bytes = Buffer.from(entry.data, 'base64');
    if (bytes.length !== entry.size || sha256(bytes) !== entry.sha256) {
      throw new DistributionError(
        'CHECKSUM_MISMATCH',
        `Archive entry digest mismatch for ${path.posix.basename(normalized)}`,
      );
    }
    assertNoSecrets(normalized, bytes);
  }
  const lockEntry = archive.entries.find((entry) => entry.path === 'pnpm-lock.yaml');
  if (!lockEntry || lockEntry.sha256 !== manifest.lockfileSha256) {
    throw new DistributionError(
      'LOCKFILE_MISMATCH',
      'Distribution lockfile identity does not match',
    );
  }
  if (
    inventory.lockfileSha256 !== manifest.lockfileSha256 ||
    provenance.materials?.lockfileSha256 !== manifest.lockfileSha256
  ) {
    throw new DistributionError(
      'LOCKFILE_MISMATCH',
      'Dependency evidence is not bound to the lockfile',
    );
  }
  const inventorySet = new Set(
    (inventory.dependencies ?? []).map((dependency) => `${dependency.name}@${dependency.version}`),
  );
  const sbomSet = new Set(
    (sbom.packages ?? []).map((dependency) => `${dependency.name}@${dependency.versionInfo}`),
  );
  if (
    inventorySet.size !== sbomSet.size ||
    [...inventorySet].some((dependency) => !sbomSet.has(dependency))
  ) {
    throw new DistributionError(
      'SBOM_RECONCILIATION_FAILED',
      'SBOM does not match the locked dependency inventory',
    );
  }
  if (
    manifest.version !== ARC_VERSION ||
    manifest.stage !== ARC_STAGE ||
    manifest.expectedProductionTools !== EXPECTED_TOOL_COUNT ||
    manifest.expectedDeterministicRegistryEntries !== EXPECTED_REGISTRY_COUNT
  ) {
    throw new DistributionError(
      'IDENTITY_MISMATCH',
      'Distribution identity does not match ARC Core',
    );
  }
  return { archive, inventory, manifest, provenance, sbom };
}

export async function extractVerifiedArchive(archive, destination) {
  await fs.promises.mkdir(destination, { recursive: true, mode: 0o700 });
  const root = await fs.promises.realpath(destination);
  try {
    for (const entry of archive.entries) {
      const normalized = normalizeRelativePath(entry.path);
      if (entry.type !== 'file') {
        throw new DistributionError('UNSAFE_ARCHIVE_ENTRY', 'Only regular files may be extracted');
      }
      const target = path.join(root, ...normalized.split('/'));
      const relative = path.relative(root, target);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new DistributionError(
          'UNSAFE_ARCHIVE_PATH',
          'Archive entry escapes the staging root',
        );
      }
      const parent = path.dirname(target);
      await fs.promises.mkdir(parent, { recursive: true, mode: 0o755 });
      let cursor = parent;
      while (cursor !== root) {
        const stat = await fs.promises.lstat(cursor);
        if (stat.isSymbolicLink()) {
          throw new DistributionError('UNSAFE_ARCHIVE_PATH', 'Archive parent is a symlink');
        }
        cursor = path.dirname(cursor);
      }
      await fs.promises.writeFile(target, Buffer.from(entry.data, 'base64'), {
        flag: 'wx',
        mode: entry.mode === '0755' ? 0o755 : 0o644,
      });
    }
  } catch (error) {
    await fs.promises.rm(destination, { recursive: true, force: true });
    throw error;
  }
  return root;
}

export function classifyPlatform({ platform, arch, isWsl = false }) {
  if (platform === 'linux' && arch === 'x64') {
    return isWsl
      ? { accepted: true, classification: 'development-compatible', target: 'wsl-linux-x64' }
      : { accepted: true, classification: 'supported', target: 'linux-x64' };
  }
  if ((platform === 'linux' && arch === 'arm64') || platform === 'darwin') {
    return { accepted: false, classification: 'validation-only', target: `${platform}-${arch}` };
  }
  return { accepted: false, classification: 'unsupported', target: `${platform}-${arch}` };
}

function validateInstallPrefix(prefix) {
  const resolved = path.resolve(prefix);
  const forbidden = ['/usr', '/usr/local', '/etc', '/opt', '/bin', '/sbin', '/var', '/'];
  if (
    forbidden.some((root) => resolved === root || (root !== '/' && resolved.startsWith(`${root}/`)))
  ) {
    throw new DistributionError(
      'PRIVILEGED_INSTALL_REFUSED',
      'System installation requires a separate operator workflow',
    );
  }
  return resolved;
}

export async function installDistribution({
  bundleDir,
  trustedPublicKey,
  prefix,
  platform = { platform: process.platform, arch: process.arch, isWsl: false },
  commandRunner,
}) {
  const verified = await verifyDistribution({ bundleDir, trustedPublicKey });
  const support = classifyPlatform(platform);
  if (!support.accepted || support.classification !== 'supported') {
    throw new DistributionError(
      'UNSUPPORTED_PLATFORM',
      `Installation target ${support.target} is not supported`,
    );
  }
  const installPrefix = validateInstallPrefix(prefix);
  try {
    await fs.promises.access(path.join(installPrefix, OWNERSHIP_FILE));
    throw new DistributionError('INSTALL_EXISTS', 'ARC is already installed at this prefix');
  } catch (error) {
    if (error instanceof DistributionError) throw error;
    if (error.code !== 'ENOENT') throw error;
  }
  const prefixParent = path.dirname(installPrefix);
  await fs.promises.mkdir(prefixParent, { recursive: true });
  const prefixStage = await fs.promises.mkdtemp(path.join(prefixParent, '.cesspace-arc-prefix-'));
  const sourceStage = path.join(prefixStage, 'runtime');
  try {
    await extractVerifiedArchive(verified.archive, sourceStage);
    await command(
      commandRunner,
      'pnpm',
      ['install', '--prefer-offline', '--frozen-lockfile', '--ignore-scripts'],
      {
        cwd: sourceStage,
      },
    );
    await command(commandRunner, 'pnpm', ['build'], { cwd: sourceStage });
    const launcherDir = path.join(prefixStage, 'bin');
    await fs.promises.mkdir(launcherDir, { recursive: true });
    await fs.promises.symlink(
      '../runtime/apps/mcp-server/dist/index.js',
      path.join(launcherDir, 'cesspace-arc'),
    );
    const ownership = {
      format: 'cesspace-arc-install-ownership-v1',
      version: ARC_VERSION,
      stage: ARC_STAGE,
      sourceCommit: verified.manifest.source.commit,
      sourceTree: verified.manifest.source.tree,
      profile: 'core',
      files: ['bin/cesspace-arc'],
      trees: ['runtime'],
    };
    await fs.promises.writeFile(
      path.join(prefixStage, OWNERSHIP_FILE),
      `${canonicalJson(ownership)}\n`,
      { mode: 0o600 },
    );
    await fs.promises.mkdir(prefixParent, { recursive: true });
    try {
      await fs.promises.access(installPrefix);
      const entries = await fs.promises.readdir(installPrefix);
      if (entries.length > 0)
        throw new DistributionError('INSTALL_PREFIX_NOT_EMPTY', 'Install prefix must be empty');
      await fs.promises.rmdir(installPrefix);
    } catch (error) {
      if (error instanceof DistributionError) throw error;
      if (error.code !== 'ENOENT') throw error;
    }
    await fs.promises.rename(prefixStage, installPrefix);
    return { ownership, prefix: installPrefix, support };
  } catch (error) {
    await fs.promises.rm(prefixStage, { recursive: true, force: true });
    throw error;
  }
}

export async function uninstallDistribution({ prefix }) {
  const installPrefix = validateInstallPrefix(prefix);
  let ownership;
  try {
    ownership = JSON.parse(
      await fs.promises.readFile(path.join(installPrefix, OWNERSHIP_FILE), 'utf8'),
    );
  } catch {
    throw new DistributionError(
      'OWNERSHIP_MANIFEST_REQUIRED',
      'ARC ownership manifest is missing or invalid',
    );
  }
  if (
    ownership.format !== 'cesspace-arc-install-ownership-v1' ||
    !Array.isArray(ownership.files) ||
    !Array.isArray(ownership.trees) ||
    canonicalJson(ownership.files) !== canonicalJson(['bin/cesspace-arc']) ||
    canonicalJson(ownership.trees) !== canonicalJson(['runtime'])
  ) {
    throw new DistributionError('OWNERSHIP_MANIFEST_INVALID', 'ARC ownership manifest is invalid');
  }
  for (const relative of ownership.files) {
    const normalized = normalizeRelativePath(relative);
    const target = path.join(installPrefix, ...normalized.split('/'));
    const bounded = path.relative(installPrefix, target);
    if (bounded.startsWith('..') || path.isAbsolute(bounded)) {
      throw new DistributionError(
        'OWNERSHIP_MANIFEST_INVALID',
        'Ownership path escapes install prefix',
      );
    }
    await fs.promises.rm(target, { force: true });
  }
  for (const relative of ownership.trees) {
    const normalized = normalizeRelativePath(relative);
    const target = path.join(installPrefix, ...normalized.split('/'));
    const bounded = path.relative(installPrefix, target);
    if (bounded.startsWith('..') || path.isAbsolute(bounded)) {
      throw new DistributionError(
        'OWNERSHIP_MANIFEST_INVALID',
        'Ownership tree escapes install prefix',
      );
    }
    await fs.promises.rm(target, { recursive: true, force: true });
  }
  await fs.promises.rm(path.join(installPrefix, OWNERSHIP_FILE), { force: true });
  const directories = [];
  const collectDirectories = async (directory) => {
    for (const entry of await fs.promises.readdir(directory, { withFileTypes: true })) {
      const child = path.join(directory, entry.name);
      if (entry.isDirectory()) await collectDirectories(child);
    }
    directories.push(directory);
  };
  await collectDirectories(installPrefix);
  for (const directory of directories) {
    try {
      await fs.promises.rmdir(directory);
    } catch (error) {
      if (!['ENOTEMPTY', 'ENOENT'].includes(error.code)) throw error;
    }
  }
  return {
    removedOwnedFiles: ownership.files.length,
    removedOwnedTrees: ownership.trees.length,
  };
}
