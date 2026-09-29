#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {
  verifyAcceptanceOwnership,
  verifyHostedAbsence,
  verifyParentPromotionBaseline,
  verifyRegistryIds,
  verifySecurityReview,
  verifyStableIdentity,
  verifyToolCatalog,
} from './arc10-final-verification-lib.mjs';
import { validateReleaseProfile } from './arc10-release-profile-lib.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const command = process.argv[2];

try {
  let result;
  if (command === 'identity') {
    result = {
      parent: verifyParentPromotionBaseline(repositoryRoot),
      current: verifyStableIdentity(repositoryRoot),
    };
  } else if (command === 'profile') {
    result = validateReleaseProfile(
      JSON.parse(
        fs.readFileSync(path.join(repositoryRoot, 'release/arc10-release-profile.json'), 'utf8'),
      ),
    );
  } else if (command === 'ownership') {
    result = verifyAcceptanceOwnership(repositoryRoot);
  } else if (command === 'hosted-absence') {
    result = verifyHostedAbsence(repositoryRoot);
  } else if (command === 'catalogs') {
    const { ALL_TOOL_DEFINITIONS } = await import('../apps/mcp-server/dist/index.js');
    const { createProductionDeterministicRegistry } =
      await import('../apps/mcp-server/dist/composite-framework.js');
    result = {
      tools: verifyToolCatalog(ALL_TOOL_DEFINITIONS.map((tool) => tool.name)),
      registry: verifyRegistryIds(createProductionDeterministicRegistry().listEntryIds()),
    };
  } else if (command === 'security-review') {
    result = verifySecurityReview(repositoryRoot);
  } else if (command === 'report') {
    const report = JSON.parse(
      fs.readFileSync(path.join(repositoryRoot, 'release/arc10-final-verification.json'), 'utf8'),
    );
    if (
      report.format !== 'cesspace-arc-final-verification-v1' ||
      report.gateCount !== 30 ||
      report.negativeControls !== 80 ||
      report.positiveFlows !== 18 ||
      report.hostedProfile !== 'NOT_SHIPPED' ||
      report.publicationAuthorized !== false
    )
      throw new Error('Final verification report identity is invalid');
    result = report;
  } else {
    process.stderr.write(
      'Usage: node scripts/arc10-final-check.mjs <identity|profile|ownership|hosted-absence|catalogs|security-review|report>\n',
    );
    process.exitCode = 2;
  }
  if (result !== undefined) process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`ARC 1.0 final check failed (${error?.code ?? 'FINAL_CHECK_FAILED'}).\n`);
  process.exitCode = 1;
}
