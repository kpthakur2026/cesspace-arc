const CAPABILITY_KEYS = [
  'hostedConnectivity',
  'oauthOidc',
  'multiTenantAccounts',
  'relay',
  'publicMcpHosting',
  'directoryPublishing',
  'metering',
  'billing',
  'subscriptions',
];

const PLATFORM_POLICY = new Map([
  ['linux-x64', ['SUPPORTED', 'EVIDENCE_EXECUTED']],
  ['wsl-linux-x64', ['DEVELOPMENT_COMPATIBLE', 'DECLARED_DEVELOPMENT_COMPATIBLE']],
  ['linux-arm64', ['VALIDATION_ONLY', 'DECLARED_VALIDATION_ONLY']],
  ['darwin-arm64', ['VALIDATION_ONLY', 'DECLARED_VALIDATION_ONLY']],
  ['darwin-x64', ['VALIDATION_ONLY', 'DECLARED_VALIDATION_ONLY']],
  ['win32', ['UNSUPPORTED', 'UNSUPPORTED']],
]);

export class ReleaseProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReleaseProfileError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new ReleaseProfileError(code, message);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('RELEASE_PROFILE_INVALID', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail('RELEASE_PROFILE_INVALID', `${label} has an unexpected field set`);
  }
}

function assertHash(value, length, label) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length}}$`, 'u').test(value)) {
    fail('RELEASE_PROFILE_INVALID', `${label} is not a canonical Git identity`);
  }
}

export function validateReleaseProfile(profile, { requireArtifactSource = false } = {}) {
  const keys = [
    'format',
    'profile',
    'reason',
    'reviewedSource',
    ...(requireArtifactSource ? ['artifactSource'] : []),
    'productVersion',
    'healthStage',
    'expectedProductionTools',
    'expectedDeterministicRegistryEntries',
    'distributionFormat',
    'schemas',
    'capabilities',
    'platforms',
    'controlAccounting',
  ];
  exactKeys(profile, keys, 'release profile');
  if (
    profile.format !== 'cesspace-arc-release-profile-v1' ||
    profile.profile !== 'core' ||
    profile.reason !== 'hosted profile not shipped' ||
    profile.productVersion !== '1.0.0' ||
    profile.healthStage !== 'ARC-1.0' ||
    profile.expectedProductionTools !== 25 ||
    profile.expectedDeterministicRegistryEntries !== 5 ||
    profile.distributionFormat !== 'cesspace-arc-source-distribution-v1'
  ) {
    fail('RELEASE_PROFILE_INVALID', 'Core release identity is inconsistent');
  }
  exactKeys(profile.reviewedSource, ['commit', 'tree'], 'reviewed source');
  assertHash(profile.reviewedSource.commit, 40, 'reviewed source commit');
  assertHash(profile.reviewedSource.tree, 40, 'reviewed source tree');
  if (requireArtifactSource) {
    exactKeys(profile.artifactSource, ['commit', 'tree'], 'artifact source');
    assertHash(profile.artifactSource.commit, 40, 'artifact source commit');
    assertHash(profile.artifactSource.tree, 40, 'artifact source tree');
  }
  exactKeys(profile.schemas, ['config', 'state', 'migration'], 'schema identity');
  const permittedSchemaVersions = requireArtifactSource ? [1, 2] : [2];
  if (
    !permittedSchemaVersions.includes(profile.schemas.config) ||
    profile.schemas.state !== profile.schemas.config ||
    profile.schemas.migration !== 1
  ) {
    fail('RELEASE_PROFILE_INVALID', 'Core schema identity is inconsistent');
  }
  exactKeys(profile.capabilities, CAPABILITY_KEYS, 'capability accounting');
  if (CAPABILITY_KEYS.some((key) => profile.capabilities[key] !== false)) {
    fail('HOSTED_PROFILE_DECLARED', 'The Core profile cannot enable hosted capabilities');
  }
  if (!Array.isArray(profile.platforms) || profile.platforms.length !== PLATFORM_POLICY.size) {
    fail('PLATFORM_EVIDENCE_INVALID', 'Compatibility matrix has an unexpected target set');
  }
  const seen = new Set();
  for (const entry of profile.platforms) {
    exactKeys(entry, ['target', 'classification', 'evidence', 'requirements'], 'platform entry');
    const expected = PLATFORM_POLICY.get(entry.target);
    if (
      !expected ||
      seen.has(entry.target) ||
      entry.classification !== expected[0] ||
      entry.evidence !== expected[1] ||
      !Array.isArray(entry.requirements)
    ) {
      fail('PLATFORM_EVIDENCE_INVALID', 'Platform claim lacks its frozen evidence class');
    }
    if (entry.target === 'linux-x64' && entry.requirements.length !== 5) {
      fail('PLATFORM_EVIDENCE_INVALID', 'Linux x64 support evidence is incomplete');
    }
    if (entry.target !== 'linux-x64' && entry.requirements.length !== 0) {
      fail('PLATFORM_EVIDENCE_INVALID', 'Non-authoritative target fabricates executed evidence');
    }
    seen.add(entry.target);
  }
  exactKeys(
    profile.controlAccounting,
    [
      'implementedNegative',
      'implementedFlows',
      'profileNotShippedNegative',
      'profileNotShippedFlows',
    ],
    'control accounting',
  );
  const accounting = profile.controlAccounting;
  if (
    JSON.stringify(accounting.implementedNegative) !==
      JSON.stringify(['ARC10-NEG-001..022', 'ARC10-NEG-068..080']) ||
    JSON.stringify(accounting.implementedFlows) !==
      JSON.stringify(['ARC10-FLOW-01..05', 'ARC10-FLOW-15..18']) ||
    accounting.profileNotShippedNegative?.[0]?.range !== 'ARC10-NEG-023..067' ||
    accounting.profileNotShippedNegative?.[0]?.classification !== 'PROFILE_NOT_SHIPPED' ||
    accounting.profileNotShippedFlows?.[0]?.range !== 'ARC10-FLOW-06..14' ||
    accounting.profileNotShippedFlows?.[0]?.classification !== 'NOT_APPLICABLE_TO_CORE_RELEASE'
  ) {
    fail('CONTROL_ACCOUNTING_INVALID', 'Core-only control accounting is incomplete');
  }
  return profile;
}

export function resolveReleaseProfile(template, distributionManifest) {
  validateReleaseProfile(template);
  const resolved = {
    ...template,
    artifactSource: {
      commit: distributionManifest.source.commit,
      tree: distributionManifest.source.tree,
    },
  };
  return validateReleaseProfile(resolved, { requireArtifactSource: true });
}

export function assertPlatformClaim(profile, target, classification, evidence) {
  validateReleaseProfile(profile, { requireArtifactSource: 'artifactSource' in profile });
  const entry = profile.platforms.find((candidate) => candidate.target === target);
  if (!entry || entry.classification !== classification || entry.evidence !== evidence) {
    fail('PLATFORM_EVIDENCE_INVALID', `Platform claim for ${target} is unsupported`);
  }
  return entry;
}

export const CORE_CAPABILITY_KEYS = Object.freeze([...CAPABILITY_KEYS]);
