import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const TASK7_PARENT = 'f094b1bbad325e102792b3c568e21a3bd83e2bcf';
export const TASK7_TREE = '3fbbc499a3dd4b2d3fabd2cecbccf980f1eabfc5';
export const STABLE_VERSION = '1.0.0';
export const STABLE_STAGE = 'ARC-1.0';

export const EXPECTED_TOOL_NAMES = Object.freeze([
  'health',
  'system_status',
  'list_directory',
  'read_file',
  'search_files',
  'search_text',
  'git_status',
  'git_diff',
  'git_log',
  'run_command',
  'process_status',
  'process_output',
  'terminate_process',
  'create_file',
  'write_file',
  'delete_file',
  'move_file',
  'apply_patch',
  'arc_repo_status',
  'arc_worktree_status',
  'arc_review_diff',
  'arc_verify',
  'arc_test',
  'arc_ci_status',
  'arc_stage_evidence',
]);

export const EXPECTED_REGISTRY_IDS = Object.freeze([
  'verify-format-v1',
  'verify-lint-v1',
  'verify-typecheck-v1',
  'verify-test-v1',
  'arc-test-node-v1',
]);

const ABSENCE_PREDICATES = Object.freeze([
  'NO_OAUTH_OIDC_AUTHORIZATION_SERVER',
  'NO_CONFIDENTIAL_OAUTH_CLIENT_SECRET',
  'NO_ACCOUNT_OR_TENANT_AUTHORITY',
  'NO_HOSTED_IDENTITY_MTLS_BYPASS',
  'NO_RELAY_TRANSPORT',
  'NO_PAIRING_OR_ROUTE_BROKER',
  'NO_HOSTED_ROUTING_OR_RELAY_LISTENER',
  'NO_TENANT_DATASTORE_OR_CACHE',
  'NO_HOSTED_PAYLOAD_OR_TELEMETRY_STORE',
  'NO_HOSTED_DEPROVISION_OR_SERVICE_AUDIT',
  'NO_HOSTED_CONTROL_PLANE',
  'NO_HOSTED_RESOURCE_OR_METRICS_BACKEND',
  'NO_HOSTED_RETRY_SERVICE',
]);

export class FinalVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FinalVerificationError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new FinalVerificationError(code, message);
}

function sorted(values) {
  return [...values].sort();
}

function exactSet(actual, expected, code, label) {
  if (
    actual.length !== expected.length ||
    new Set(actual).size !== actual.length ||
    JSON.stringify(sorted(actual)) !== JSON.stringify(sorted(expected))
  ) {
    fail(code, `${label} differs from its frozen exact set`);
  }
}

export function verifyToolCatalog(names) {
  exactSet(names, EXPECTED_TOOL_NAMES, 'TOOL_CATALOG_DRIFT', 'Production tool catalog');
  return { count: names.length, names: [...names] };
}

export function verifyRegistryIds(ids) {
  exactSet(ids, EXPECTED_REGISTRY_IDS, 'REGISTRY_DRIFT', 'Deterministic registry');
  return { count: ids.length, ids: [...ids] };
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function testNames(repositoryRoot) {
  const names = [];
  for (const file of fs
    .readdirSync(path.join(repositoryRoot, 'tests'))
    .filter((name) => /^arc10-.*\.test\.js$/u.test(name))
    .sort()) {
    const source = fs.readFileSync(path.join(repositoryRoot, 'tests', file), 'utf8');
    const pattern = /test\(\s*['"`]([^'"`\n]+)['"`]/gu;
    let match;
    while ((match = pattern.exec(source)) !== null)
      names.push({ file: `tests/${file}`, name: match[1] });
  }
  return names;
}

export function verifyAcceptanceOwnership(repositoryRoot, manifestOverride) {
  const manifest =
    manifestOverride ??
    readJson(path.join(repositoryRoot, 'release/arc10-acceptance-ownership.json'));
  if (
    manifest.format !== 'cesspace-arc-acceptance-ownership-v1' ||
    manifest.releaseProfile !== 'core'
  )
    fail('OWNERSHIP_INVALID', 'Acceptance ownership identity is invalid');
  const negatives = manifest.negativeControls;
  const flows = manifest.positiveFlows;
  if (!Array.isArray(negatives) || !Array.isArray(flows))
    fail('OWNERSHIP_INVALID', 'Acceptance ownership collections are missing');
  const expectedNegatives = Array.from(
    { length: 80 },
    (_, index) => `ARC10-NEG-${String(index + 1).padStart(3, '0')}`,
  );
  const expectedFlows = Array.from(
    { length: 18 },
    (_, index) => `ARC10-FLOW-${String(index + 1).padStart(2, '0')}`,
  );
  exactSet(
    negatives.map((entry) => entry.id),
    expectedNegatives,
    'OWNERSHIP_INCOMPLETE',
    'Negative controls',
  );
  exactSet(
    flows.map((entry) => entry.id),
    expectedFlows,
    'OWNERSHIP_INCOMPLETE',
    'Positive flows',
  );
  const discovered = testNames(repositoryRoot);
  for (const entry of [...negatives, ...flows]) {
    if (/SKIP|TODO/u.test(String(entry.status)))
      fail('OWNERSHIP_DISABLED', `${entry.id} is skipped or deferred`);
    if (entry.status === 'EXECUTED') {
      if (entry.releaseApplicability !== 'CORE' || !entry.executableEvidence?.startsWith('tests/'))
        fail('OWNERSHIP_INVALID', `${entry.id} lacks executable Core ownership`);
      const owners = discovered.filter(
        (test) => test.file === entry.executableEvidence && test.name.includes(entry.id),
      );
      if (owners.length !== 1)
        fail('OWNERSHIP_EVIDENCE_MISSING', `${entry.id} does not have exactly one executable test`);
    } else if (entry.id.startsWith('ARC10-NEG-')) {
      if (
        entry.status !== 'PROFILE_NOT_SHIPPED' ||
        entry.releaseApplicability !== 'HOSTED_PROFILE_NOT_SHIPPED' ||
        entry.executableEvidence !==
          'scripts/arc10-final-verification-lib.mjs#verifyHostedAbsence' ||
        !ABSENCE_PREDICATES.includes(entry.absencePredicate)
      )
        fail('OWNERSHIP_ABSENCE_EVIDENCE_MISSING', `${entry.id} lacks hosted-absence evidence`);
    } else if (
      entry.status !== 'NOT_APPLICABLE_TO_CORE_RELEASE' ||
      entry.releaseApplicability !== 'HOSTED_PROFILE_NOT_SHIPPED' ||
      entry.executableEvidence !== 'scripts/arc10-final-verification-lib.mjs#verifyHostedAbsence'
    ) {
      fail('OWNERSHIP_HOSTED_FLOW_INVALID', `${entry.id} falsely claims hosted execution`);
    }
  }
  return {
    negativeControls: negatives.length,
    positiveFlows: flows.length,
    executed: [...negatives, ...flows].filter((entry) => entry.status === 'EXECUTED').length,
    profileNotShipped: negatives.filter((entry) => entry.status === 'PROFILE_NOT_SHIPPED').length,
    notApplicable: flows.filter((entry) => entry.status === 'NOT_APPLICABLE_TO_CORE_RELEASE')
      .length,
    duplicates: 0,
    missing: 0,
    outOfRange: 0,
  };
}

function walk(root, relative = '') {
  const result = [];
  for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
    if (['dist', 'node_modules'].includes(name)) continue;
    const child = relative ? `${relative}/${name}` : name;
    const stat = fs.lstatSync(path.join(root, child));
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) result.push(...walk(root, child));
    else if (stat.isFile()) result.push(child);
  }
  return result;
}

export function verifyHostedAbsence(repositoryRoot, profileOverride) {
  const profile =
    profileOverride ?? readJson(path.join(repositoryRoot, 'release/arc10-release-profile.json'));
  if (profile.profile !== 'core' || Object.values(profile.capabilities ?? {}).some(Boolean))
    fail('HOSTED_PROFILE_PRESENT', 'Core profile enables a hosted capability');
  const applicationNames = fs.readdirSync(path.join(repositoryRoot, 'apps')).sort();
  const packageNames = fs.readdirSync(path.join(repositoryRoot, 'packages')).sort();
  exactSet(applicationNames, ['cli', 'mcp-server'], 'HOSTED_SURFACE_PRESENT', 'Application set');
  if (
    packageNames.some((name) =>
      /oauth|oidc|account|tenant|relay|hosted|billing|meter|directory/iu.test(name),
    )
  )
    fail('HOSTED_SURFACE_PRESENT', 'A hosted service package exists');
  const credential =
    /\b(?:OPENAI|ANTHROPIC|MARKETPLACE|DIRECTORY|BILLING|RELAY|OAUTH|OIDC)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CLIENT_ID|CLIENT_SECRET|WEBHOOK|ENDPOINT|ISSUER)\b/u;
  const endpoint = /https?:\/\/(?:[^/]+\.)?(?:openai\.com|anthropic\.com)\//iu;
  const forbiddenDependency = /^(?:@openai\/|@anthropic-ai\/|openai$|stripe$)/u;
  for (const area of ['apps', 'packages']) {
    for (const relative of walk(path.join(repositoryRoot, area))) {
      const filePath = path.join(repositoryRoot, area, relative);
      const source = fs.readFileSync(filePath, 'utf8');
      if (credential.test(source) || endpoint.test(source))
        fail('HOSTED_SURFACE_PRESENT', 'A hosted credential or vendor endpoint surface exists');
      if (relative.endsWith('package.json')) {
        const packageJson = JSON.parse(source);
        const dependencies = Object.keys({
          ...packageJson.dependencies,
          ...packageJson.devDependencies,
        });
        if (dependencies.some((name) => forbiddenDependency.test(name)))
          fail('HOSTED_SURFACE_PRESENT', 'A hosted vendor dependency exists');
      }
    }
  }
  return {
    profile: 'core',
    hostedCapabilities: 0,
    predicates: Object.fromEntries(ABSENCE_PREDICATES.map((predicate) => [predicate, true])),
  };
}

function gitShow(repositoryRoot, commit, file) {
  return execFileSync('git', ['show', `${commit}:${file}`], {
    cwd: repositoryRoot,
    encoding: 'utf8',
  });
}

export function verifyParentPromotionBaseline(repositoryRoot) {
  const root = JSON.parse(gitShow(repositoryRoot, TASK7_PARENT, 'package.json'));
  const cli = JSON.parse(gitShow(repositoryRoot, TASK7_PARENT, 'apps/cli/package.json'));
  const mcp = JSON.parse(gitShow(repositoryRoot, TASK7_PARENT, 'apps/mcp-server/package.json'));
  const profile = JSON.parse(
    gitShow(repositoryRoot, TASK7_PARENT, 'release/arc10-release-profile.json'),
  );
  const server = gitShow(repositoryRoot, TASK7_PARENT, 'apps/mcp-server/src/index.ts');
  if (
    root.version !== '0.8.0-rc08' ||
    cli.version !== '0.8.0-rc08' ||
    mcp.version !== '0.8.0-rc08' ||
    profile.productVersion !== '0.8.0-rc08' ||
    profile.healthStage !== 'RC-08' ||
    !server.includes("version: '0.8.0-rc08'") ||
    !server.includes("stage: 'RC-08'")
  )
    fail('PARENT_PROMOTION_INVALID', 'Task-7 parent was not consistently pre-promotion');
  return { commit: TASK7_PARENT, tree: TASK7_TREE, version: '0.8.0-rc08', stage: 'RC-08' };
}

export function readStableIdentitySurfaces(repositoryRoot) {
  const root = readJson(path.join(repositoryRoot, 'package.json'));
  const cliPackage = readJson(path.join(repositoryRoot, 'apps/cli/package.json'));
  const mcpPackage = readJson(path.join(repositoryRoot, 'apps/mcp-server/package.json'));
  const profile = readJson(path.join(repositoryRoot, 'release/arc10-release-profile.json'));
  const cliSource = fs.readFileSync(path.join(repositoryRoot, 'apps/cli/src/index.ts'), 'utf8');
  const serverSource = fs.readFileSync(
    path.join(repositoryRoot, 'apps/mcp-server/src/index.ts'),
    'utf8',
  );
  const configSource = fs.readFileSync(
    path.join(repositoryRoot, 'packages/config/src/index.ts'),
    'utf8',
  );
  const distribution = fs.readFileSync(
    path.join(repositoryRoot, 'scripts/arc10-distribution-lib.mjs'),
    'utf8',
  );
  return {
    rootPackage: root.version,
    cliPackage: cliPackage.version,
    mcpPackage: mcpPackage.version,
    cliRuntime: /CLI_VERSION = '([^']+)'/u.exec(cliSource)?.[1],
    healthVersion: /version: '([^']+)',\n\s+stage: 'ARC-1\.0'/u.exec(serverSource)?.[1],
    healthStage: /stage: '(ARC-1\.0)'/u.exec(serverSource)?.[1],
    configProduct: /CORE_PRODUCT_VERSION = '([^']+)'/u.exec(configSource)?.[1],
    configStage: /CORE_HEALTH_STAGE = '([^']+)'/u.exec(configSource)?.[1],
    distributionVersion: /ARC_VERSION = '([^']+)'/u.exec(distribution)?.[1],
    distributionStage: /ARC_STAGE = '([^']+)'/u.exec(distribution)?.[1],
    profileVersion: profile.productVersion,
    profileStage: profile.healthStage,
  };
}

export function verifyStableIdentity(repositoryRoot, surfacesOverride) {
  const surfaces = surfacesOverride ?? readStableIdentitySurfaces(repositoryRoot);
  const expected = {
    rootPackage: STABLE_VERSION,
    cliPackage: STABLE_VERSION,
    mcpPackage: STABLE_VERSION,
    cliRuntime: STABLE_VERSION,
    healthVersion: STABLE_VERSION,
    healthStage: STABLE_STAGE,
    configProduct: STABLE_VERSION,
    configStage: STABLE_STAGE,
    distributionVersion: STABLE_VERSION,
    distributionStage: STABLE_STAGE,
    profileVersion: STABLE_VERSION,
    profileStage: STABLE_STAGE,
  };
  if (JSON.stringify(surfaces) !== JSON.stringify(expected))
    fail('PROMOTION_INCONSISTENT', 'Stable identity surfaces are inconsistent');
  return surfaces;
}

export function verifySecurityReview(repositoryRoot) {
  const review = readJson(path.join(repositoryRoot, 'release/arc10-security-review.json'));
  if (
    review.format !== 'cesspace-arc-security-review-v1' ||
    review.reviewedSource.commit !== TASK7_PARENT ||
    review.reviewedSource.tree !== TASK7_TREE ||
    review.unresolvedCritical !== 0 ||
    review.unresolvedHigh !== 0 ||
    review.releaseAuthorityStatus !== 'PENDING_INDEPENDENT_APPROVAL' ||
    !Array.isArray(review.lowerSeverityFindings)
  )
    fail('SECURITY_REVIEW_INVALID', 'Project final security-review record is incomplete');
  return review;
}

export const HOSTED_ABSENCE_PREDICATES = ABSENCE_PREDICATES;
