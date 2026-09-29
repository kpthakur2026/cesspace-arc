import { createPrivateKey, createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  ARC_STAGE,
  ARC_VERSION,
  EXPECTED_REGISTRY_COUNT,
  EXPECTED_TOOL_COUNT,
  sha256,
  verifyDistribution,
} from './arc10-distribution-lib.mjs';
import { validateReleaseProfile } from './arc10-release-profile-lib.mjs';

const PRIVATE_KEY_PATTERN =
  /-----BEGIN (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----/gu;
const HOSTED_PATH_PATTERN =
  /(?:^|\/)(?:oauth|oidc|accounts?|tenants?|relay|hosted|billing|metering|subscriptions?|directory-publish(?:ing)?)(?:\/|\.|$)/iu;
const HOSTED_CREDENTIAL_PATTERN =
  /\b(?:OPENAI|ANTHROPIC|MARKETPLACE|DIRECTORY|BILLING|RELAY|OAUTH|OIDC)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CLIENT_ID|CLIENT_SECRET|WEBHOOK|ENDPOINT|ISSUER)\b/u;
const VENDOR_ENDPOINT_PATTERN =
  /https?:\/\/(?:[^/]+\.)?(?:openai\.com|anthropic\.com)\/(?:[^\s"']*)/iu;
const FORBIDDEN_DEPENDENCIES = /^(?:@openai\/|@anthropic-ai\/|openai$|stripe$)/u;

export class ReleaseCandidateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReleaseCandidateError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new ReleaseCandidateError(code, message);
}

function walkFiles(root, relative = '') {
  const files = [];
  const directory = path.join(root, relative);
  for (const name of fs.readdirSync(directory).sort()) {
    if (['dist', 'node_modules'].includes(name)) continue;
    const childRelative = relative ? `${relative}/${name}` : name;
    const full = path.join(root, childRelative);
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) files.push(...walkFiles(root, childRelative));
    else if (stat.isFile()) files.push(childRelative);
  }
  return files;
}

function hasParseablePrivateKey(bytes) {
  const text = bytes.toString('utf8');
  for (const match of text.matchAll(PRIVATE_KEY_PATTERN)) {
    try {
      createPrivateKey(match[0]);
      return true;
    } catch {
      // Synthetic redaction fixtures are not signing keys.
    }
  }
  return false;
}

export function assertNoReleaseSigningPrivateKey({ repositoryRoot, bundleDir }) {
  const repositoryFiles = [
    ...walkFiles(path.join(repositoryRoot, 'apps')).map((file) => `apps/${file}`),
    ...walkFiles(path.join(repositoryRoot, 'packages')).map((file) => `packages/${file}`),
    ...walkFiles(path.join(repositoryRoot, 'release')).map((file) => `release/${file}`),
    ...walkFiles(path.join(repositoryRoot, 'scripts'))
      .filter((file) => file.startsWith('arc10-') || file === 'verify-arc10-rc.mjs')
      .map((file) => `scripts/${file}`),
  ];
  for (const file of repositoryFiles) {
    if (hasParseablePrivateKey(fs.readFileSync(path.join(repositoryRoot, file)))) {
      fail('RELEASE_SIGNING_KEY_EXPOSED', 'A release signing private key is tracked');
    }
  }
  for (const file of walkFiles(bundleDir)) {
    if (hasParseablePrivateKey(fs.readFileSync(path.join(bundleDir, file)))) {
      fail('RELEASE_SIGNING_KEY_EXPOSED', 'A release signing private key entered the bundle');
    }
  }
  return { repositoryFiles: repositoryFiles.length, bundleFiles: walkFiles(bundleDir).length };
}

export function evaluateVulnerabilityPolicy(report, expectedLockfileSha256) {
  const severities = { critical: 0, high: 0, moderate: 0, low: 0, info: 0, unknown: 0 };
  if (report?.format === 'cesspace-arc-vulnerability-report-v1') {
    if (report.lockfileSha256 !== expectedLockfileSha256 || !Array.isArray(report.findings)) {
      fail('VULNERABILITY_EVIDENCE_INVALID', 'Vulnerability evidence is not lockfile-bound');
    }
    for (const finding of report.findings) {
      const severity = String(finding?.severity ?? 'unknown').toLowerCase();
      if (!(severity in severities)) severities.unknown += 1;
      else severities[severity] += 1;
    }
  } else if (report?.metadata?.vulnerabilities) {
    for (const key of Object.keys(severities)) {
      const value = report.metadata.vulnerabilities[key];
      if (value !== undefined) {
        if (!Number.isSafeInteger(value) || value < 0)
          fail('VULNERABILITY_EVIDENCE_INVALID', 'Vulnerability counts are malformed');
        severities[key] = value;
      }
    }
  } else {
    fail('VULNERABILITY_EVIDENCE_INVALID', 'Vulnerability evidence format is unsupported');
  }
  if (severities.critical > 0 || severities.high > 0 || severities.unknown > 0) {
    fail('VULNERABILITY_RELEASE_BLOCKED', 'Critical, high, or unknown findings block release');
  }
  return {
    decision: 'PASS',
    severities,
    policy: { critical: 'BLOCK', high: 'BLOCK', moderate: 'RECORD', low: 'RECORD' },
  };
}

export function assertDependencyCompleteness(verified) {
  const dependencies = verified.inventory?.dependencies;
  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    fail('DEPENDENCY_EVIDENCE_INCOMPLETE', 'Dependency inventory is empty');
  }
  const sbomByIdentity = new Map(
    (verified.sbom?.packages ?? []).map((item) => [`${item.name}@${item.versionInfo}`, item]),
  );
  for (const dependency of dependencies) {
    const identity = `${dependency.name}@${dependency.version}`;
    const sbom = sbomByIdentity.get(identity);
    if (
      typeof dependency.license !== 'string' ||
      ['UNKNOWN', 'NOASSERTION', ''].includes(dependency.license) ||
      dependency.source?.type !== 'pnpm-lock' ||
      dependency.source?.locator !== identity ||
      dependency.source?.lockfileSha256 !== verified.manifest.lockfileSha256 ||
      sbom?.licenseDeclared !== dependency.license
    ) {
      fail(
        'DEPENDENCY_EVIDENCE_INCOMPLETE',
        'Dependency license or lockfile provenance is incomplete',
      );
    }
  }
  return { dependencies: dependencies.length, unresolvedLicenses: 0 };
}

export function assertArtifactStateCompatibility(manifest, stateMetadata) {
  if (
    stateMetadata?.format !== 'cesspace-arc-core-state' ||
    !Number.isSafeInteger(stateMetadata.stateSchemaVersion)
  ) {
    fail('STATE_COMPATIBILITY_INVALID', 'Core state metadata is invalid');
  }
  if (manifest.stateSchemaVersion < stateMetadata.stateSchemaVersion) {
    fail('UNSAFE_DOWNGRADE', 'Artifact schema is older than authoritative Core state');
  }
  if (manifest.stateSchemaVersion > stateMetadata.stateSchemaVersion) {
    fail('MIGRATION_REQUIRED', 'State requires an explicit verified migration');
  }
  return { decision: 'COMPATIBLE', stateSchemaVersion: stateMetadata.stateSchemaVersion };
}

export function auditCoreOnlySurface(repositoryRoot, verified) {
  const findings = [];
  for (const area of ['apps', 'packages']) {
    for (const relative of walkFiles(path.join(repositoryRoot, area))) {
      const repositoryPath = `${area}/${relative}`;
      if (HOSTED_PATH_PATTERN.test(repositoryPath)) findings.push(`path:${repositoryPath}`);
      const bytes = fs.readFileSync(path.join(repositoryRoot, repositoryPath));
      const text = bytes.toString('utf8');
      if (HOSTED_CREDENTIAL_PATTERN.test(text)) findings.push(`credential:${repositoryPath}`);
      if (VENDOR_ENDPOINT_PATTERN.test(text)) findings.push(`endpoint:${repositoryPath}`);
      if (relative.endsWith('package.json')) {
        const manifest = JSON.parse(text);
        for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) {
          if (FORBIDDEN_DEPENDENCIES.test(name)) findings.push(`dependency:${name}`);
        }
      }
    }
  }
  for (const entry of verified.archive.entries) {
    if (HOSTED_PATH_PATTERN.test(entry.path)) findings.push(`artifact-path:${entry.path}`);
    const text = Buffer.from(entry.data, 'base64').toString('utf8');
    if (HOSTED_CREDENTIAL_PATTERN.test(text)) findings.push(`artifact-credential:${entry.path}`);
    if (VENDOR_ENDPOINT_PATTERN.test(text)) findings.push(`artifact-endpoint:${entry.path}`);
  }
  if (findings.length > 0) {
    fail(
      'HOSTED_SURFACE_PRESENT',
      `Core-only surface contains ${findings.length} hosted finding(s)`,
    );
  }
  return { findings: 0 };
}

export function assertPlatformConsistency(manifest, profile) {
  const expected = {
    supported: profile.platforms
      .filter((entry) => entry.classification === 'SUPPORTED')
      .map((entry) => entry.target),
    developmentCompatible: profile.platforms
      .filter((entry) => entry.classification === 'DEVELOPMENT_COMPATIBLE')
      .map((entry) => entry.target),
    validationOnly: profile.platforms
      .filter((entry) => entry.classification === 'VALIDATION_ONLY')
      .map((entry) => entry.target),
    unsupported: profile.platforms
      .filter((entry) => entry.classification === 'UNSUPPORTED')
      .map((entry) => entry.target),
  };
  for (const key of Object.keys(expected)) {
    if (JSON.stringify(manifest.platforms?.[key]) !== JSON.stringify(expected[key])) {
      fail('PLATFORM_EVIDENCE_INVALID', 'Manifest and compatibility matrix disagree');
    }
  }
  return expected;
}

export async function verifyCoreReleaseCandidate({
  repositoryRoot,
  bundleDir,
  trustedPublicKey,
  vulnerabilityReport,
  stateMetadata,
}) {
  const gates = [];
  const verified = await verifyDistribution({ bundleDir, trustedPublicKey });
  gates.push('SIGNED_DISTRIBUTION_VERIFIED');
  validateReleaseProfile(verified.releaseProfile, { requireArtifactSource: true });
  gates.push('CORE_PROFILE_VERIFIED');
  if (
    verified.manifest.source.commit !== verified.releaseProfile.artifactSource.commit ||
    verified.manifest.source.tree !== verified.releaseProfile.artifactSource.tree
  )
    fail('SOURCE_BINDING_INVALID', 'Release profile source identity is inconsistent');
  gates.push('SOURCE_PROVENANCE_VERIFIED');
  const dependencyEvidence = assertDependencyCompleteness(verified);
  gates.push('DEPENDENCY_LICENSE_PROVENANCE_VERIFIED');
  const vulnerability = evaluateVulnerabilityPolicy(
    vulnerabilityReport,
    verified.manifest.lockfileSha256,
  );
  gates.push('VULNERABILITY_POLICY_VERIFIED');
  const platforms = assertPlatformConsistency(verified.manifest, verified.releaseProfile);
  gates.push('PLATFORM_MATRIX_VERIFIED');
  const hosted = auditCoreOnlySurface(repositoryRoot, verified);
  gates.push('HOSTED_SURFACE_ABSENT');
  const privateKeys = assertNoReleaseSigningPrivateKey({ repositoryRoot, bundleDir });
  gates.push('SIGNING_PRIVATE_KEY_ABSENT');
  const { ALL_TOOL_DEFINITIONS } = await import('../apps/mcp-server/dist/index.js');
  const { createProductionDeterministicRegistry } =
    await import('../apps/mcp-server/dist/composite-framework.js');
  if (ALL_TOOL_DEFINITIONS.length !== EXPECTED_TOOL_COUNT)
    fail('TOOL_CATALOG_MISMATCH', 'Production tool count is not frozen at 25');
  gates.push('TOOL_CATALOG_VERIFIED');
  if (createProductionDeterministicRegistry().listEntryIds().length !== EXPECTED_REGISTRY_COUNT)
    fail('REGISTRY_MISMATCH', 'Deterministic registry count is not frozen at five');
  gates.push('DETERMINISTIC_REGISTRY_VERIFIED');
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'),
  );
  if (
    packageJson.version !== ARC_VERSION ||
    verified.manifest.version !== ARC_VERSION ||
    verified.manifest.stage !== ARC_STAGE ||
    ARC_VERSION === '1.0.0'
  )
    fail('PROMOTION_FORBIDDEN', 'Task 7 cannot promote the stable product identity');
  gates.push('VERSION_STAGE_VERIFIED');
  const compatibility = stateMetadata
    ? assertArtifactStateCompatibility(verified.manifest, stateMetadata)
    : { decision: 'NOT_REQUESTED' };
  gates.push('STATE_COMPATIBILITY_VERIFIED');
  if (gates.length !== 12) fail('RELEASE_GATE_COUNT_INVALID', 'Release gate count changed');
  return {
    status: 'PASS',
    profile: 'core',
    gates,
    source: verified.manifest.source,
    dependencyEvidence,
    vulnerability,
    platforms,
    hosted,
    privateKeys,
    compatibility,
    artifactDigest: sha256(fs.readFileSync(path.join(bundleDir, 'source.arcsrc'))),
  };
}

export function sha256File(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}
