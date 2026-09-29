/** ARC 1.0 Task 8 — Final Verification & Stable Promotion. */
import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { promisify } from 'node:util';

import { ALL_TOOL_DEFINITIONS } from '../apps/mcp-server/dist/index.js';
import {
  DeterministicExecutionRegistry,
  createProductionDeterministicRegistry,
  validateStepAgainstRegistry,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  ARC_STAGE,
  ARC_VERSION,
  buildDistribution,
  installDistribution,
  uninstallDistribution,
  verifyDistribution,
} from '../scripts/arc10-distribution-lib.mjs';
import {
  EXPECTED_REGISTRY_IDS,
  EXPECTED_TOOL_NAMES,
  TASK7_PARENT,
  TASK7_TREE,
  verifyAcceptanceOwnership,
  verifyHostedAbsence,
  verifyParentPromotionBaseline,
  verifyRegistryIds,
  verifySecurityReview,
  verifyStableIdentity,
  verifyToolCatalog,
} from '../scripts/arc10-final-verification-lib.mjs';
import { validateReleaseProfile } from '../scripts/arc10-release-profile-lib.mjs';
import {
  InstalledStdioClient,
  createCleanSourceFixture,
  createSigningKeyPair,
} from './helpers/arc10-distribution-fixture.mjs';

const execFile = promisify(execFileCallback);
const repositoryRoot = process.cwd();
const cleanup = [];
const keys = createSigningKeyPair();
let sourceRoot;
let bundleDir;
let verified;

async function temporaryDirectory(prefix) {
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), prefix));
  cleanup.push(directory);
  return directory;
}

function ownershipManifest() {
  return JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, 'release/arc10-acceptance-ownership.json'), 'utf8'),
  );
}

before(async () => {
  sourceRoot = await createCleanSourceFixture(repositoryRoot);
  cleanup.push(sourceRoot);
  const outputRoot = await temporaryDirectory('arc10-final-bundle-');
  bundleDir = path.join(outputRoot, 'bundle');
  await buildDistribution({ sourceRoot, outputDir: bundleDir, privateKey: keys.privateKey });
  verified = await verifyDistribution({ bundleDir, trustedPublicKey: keys.publicKey });
});

after(async () => {
  await Promise.all(
    cleanup.map((entry) => fs.promises.rm(entry, { recursive: true, force: true })),
  );
});

test('ARC10-NEG-076 rejects tool catalog drift and proves the exact production 25-name catalog', () => {
  const names = ALL_TOOL_DEFINITIONS.map((tool) => tool.name);
  assert.deepEqual(verifyToolCatalog(names), { count: 25, names });
  assert.deepEqual([...names].sort(), [...EXPECTED_TOOL_NAMES].sort());
  assert.throws(() => verifyToolCatalog([...names, 'hidden_hosted_tool']), {
    code: 'TOOL_CATALOG_DRIFT',
  });
  assert.throws(() => verifyToolCatalog(names.slice(1)), { code: 'TOOL_CATALOG_DRIFT' });
});

test('ARC10-NEG-077 rejects deterministic registry drift, unknown IDs, shell strings, paths, and a sixth entry', () => {
  const registry = createProductionDeterministicRegistry();
  const ids = registry.listEntryIds();
  assert.deepEqual(verifyRegistryIds(ids), { count: 5, ids });
  assert.deepEqual([...ids].sort(), [...EXPECTED_REGISTRY_IDS].sort());
  assert.throws(
    () =>
      new DeterministicExecutionRegistry([
        {
          registryId: 'sixth-dynamic-entry',
          executable: 'node',
          permittedArgvTemplate: ['--version'],
          sideEffectClass: 'READ_ONLY',
          projectCodeExecution: false,
          timeoutCeilingMs: 1_000,
          maxOutputBytesCeiling: 1_024,
          allowCwdSubdirectory: false,
        },
      ]),
    /unauthorized deterministic registry entry/u,
  );
  for (const attempted of [
    { id: 'unknown-package', executable: 'pnpm', argv: ['run', 'test'] },
    { id: 'unknown-path', executable: '/bin/sh', argv: ['-c', 'true'] },
    { id: 'unknown-shell', executable: 'node; true', argv: [] },
  ]) {
    assert.throws(
      () =>
        validateStepAgainstRegistry(
          {
            toolRegistryId: attempted.id,
            executable: attempted.executable,
            argv: attempted.argv,
            sideEffectClass: 'READ_ONLY',
            projectCodeExecution: false,
            timeoutMs: 1_000,
            maxOutputBytes: 1_024,
          },
          registry,
        ),
      /Registry violation/u,
    );
  }
});

test('ARC10-NEG-078 rejects incomplete, duplicate, out-of-range, skipped, and falsely executed acceptance ownership', () => {
  const result = verifyAcceptanceOwnership(repositoryRoot);
  assert.deepEqual(result, {
    negativeControls: 80,
    positiveFlows: 18,
    executed: 44,
    profileNotShipped: 45,
    notApplicable: 9,
    duplicates: 0,
    missing: 0,
    outOfRange: 0,
  });
  const mutations = [
    (value) => value.negativeControls.pop(),
    (value) => value.negativeControls.push(structuredClone(value.negativeControls[0])),
    (value) => (value.negativeControls[0].id = 'ARC10-NEG-081'),
    (value) => (value.negativeControls[0].status = 'TODO'),
    (value) => (value.negativeControls[0].executableEvidence = 'docs/architecture.md'),
    (value) => delete value.negativeControls[22].absencePredicate,
    (value) => (value.positiveFlows[5].status = 'EXECUTED'),
  ];
  for (const mutate of mutations) {
    const candidate = ownershipManifest();
    mutate(candidate);
    assert.throws(() => verifyAcceptanceOwnership(repositoryRoot, candidate));
  }
});

test('ARC10-NEG-079 proves the Task-7 parent was RC-08 and rejects every representative partial stable promotion', () => {
  assert.deepEqual(verifyParentPromotionBaseline(repositoryRoot), {
    commit: TASK7_PARENT,
    tree: TASK7_TREE,
    version: '0.8.0-rc08',
    stage: 'RC-08',
  });
  const stable = verifyStableIdentity(repositoryRoot);
  for (const field of [
    'rootPackage',
    'cliPackage',
    'healthVersion',
    'healthStage',
    'profileVersion',
    'distributionVersion',
    'configProduct',
  ]) {
    const partial = { ...stable, [field]: field.endsWith('Stage') ? 'RC-08' : '0.8.0-rc08' };
    assert.throws(() => verifyStableIdentity(repositoryRoot, partial), {
      code: 'PROMOTION_INCONSISTENT',
    });
  }
});

test('ARC10-NEG-080 proves the 30-gate verifier fails closed for injection, invalid context, and masking patterns', async () => {
  const verifier = fs.readFileSync(path.join(repositoryRoot, 'scripts/verify-arc10.sh'), 'utf8');
  assert.match(verifier, /^set -euo pipefail$/mu);
  assert.equal(verifier.includes('|| true'), false);
  assert.equal((verifier.match(/^run_gate /gmu) ?? []).length, 30);
  const context = path.join(repositoryRoot, 'scripts/verify-arc10-context.sh');
  await execFile('bash', [context, 'feat/arc-1.0-scope', 'candidate', TASK7_PARENT], {
    cwd: repositoryRoot,
  });
  await assert.rejects(
    execFile('bash', [context, 'arc10-invalid-branch', 'candidate', TASK7_PARENT], {
      cwd: repositoryRoot,
    }),
  );
  await assert.rejects(
    execFile('bash', ['scripts/verify-arc10.sh'], {
      cwd: repositoryRoot,
      env: { ...process.env, ARC10_VERIFY_FAIL_GATE: '1' },
    }),
    (error) => error.code === 97 && /Injected mandatory gate failure/u.test(error.stderr),
  );
});

test('ARC10-FLOW-17 validates complete Core ownership, hosted absence, security review, profile, identity, and final report', () => {
  const profile = validateReleaseProfile(
    JSON.parse(fs.readFileSync(path.join(repositoryRoot, 'release/arc10-release-profile.json'))),
  );
  assert.equal(profile.profile, 'core');
  assert.equal(profile.productVersion, '1.0.0');
  assert.equal(profile.healthStage, 'ARC-1.0');
  assert.equal(verifyAcceptanceOwnership(repositoryRoot).negativeControls, 80);
  assert.equal(verifyHostedAbsence(repositoryRoot).hostedCapabilities, 0);
  const review = verifySecurityReview(repositoryRoot);
  assert.equal(review.unresolvedCritical, 0);
  assert.equal(review.unresolvedHigh, 0);
  const report = JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, 'release/arc10-final-verification.json')),
  );
  assert.equal(report.gateCount, 30);
  assert.equal(report.releaseAuthorityStatus, 'PENDING_INDEPENDENT_APPROVAL');
  assert.equal(report.publicationAuthorized, false);
});

test('ARC10-FLOW-18 builds, verifies, installs, starts, exercises, and cleanly uninstalls the stable Core artifact', async () => {
  const prefixRoot = await temporaryDirectory('arc10-final-install-');
  const prefix = path.join(prefixRoot, 'prefix');
  const workspace = path.join(prefixRoot, 'workspace');
  const operatorData = path.join(prefixRoot, 'operator-data');
  await fs.promises.mkdir(workspace);
  await fs.promises.mkdir(operatorData);
  await fs.promises.writeFile(path.join(workspace, 'sentinel.txt'), 'stable-core-read\n');
  await fs.promises.writeFile(path.join(operatorData, 'config'), 'preserve\n');
  await fs.promises.writeFile(path.join(operatorData, 'audit'), 'preserve\n');
  const installed = await installDistribution({
    bundleDir,
    trustedPublicKey: keys.publicKey,
    prefix,
  });
  assert.equal(installed.ownership.sourceCommit, verified.manifest.source.commit);
  assert.equal(installed.ownership.sourceTree, verified.manifest.source.tree);
  const client = new InstalledStdioClient(
    path.join(prefix, 'runtime/apps/mcp-server/dist/index.js'),
    workspace,
  );
  try {
    const health = await client.health();
    assert.equal(health.status, 'HEALTHY');
    assert.equal(health.version, ARC_VERSION);
    assert.equal(health.stage, ARC_STAGE);
    const response = await client.request('tools/call', {
      name: 'read_file',
      arguments: { path: 'sentinel.txt' },
    });
    assert.equal(response.error, undefined);
    assert.equal(JSON.parse(response.result.content[0].text).content, 'stable-core-read\n');
  } finally {
    await client.close();
  }
  await uninstallDistribution({ prefix });
  assert.equal(fs.existsSync(path.join(prefix, 'runtime')), false);
  assert.equal(fs.readFileSync(path.join(operatorData, 'config'), 'utf8'), 'preserve\n');
  assert.equal(fs.readFileSync(path.join(operatorData, 'audit'), 'utf8'), 'preserve\n');
});
