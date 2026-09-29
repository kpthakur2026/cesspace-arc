#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { verifyCoreReleaseCandidate } from './arc10-release-candidate-lib.mjs';

const args = process.argv.slice(2);
if (args.length < 3 || args.length > 4 || args.some((value) => value.startsWith('-'))) {
  process.stderr.write(
    'Usage: pnpm run verify:arc10:rc -- <bundle> <trusted-public-key> <pnpm-audit-json> [state-metadata]\n',
  );
  process.exitCode = 2;
} else {
  try {
    const [bundleDir, publicKeyPath, auditPath, stateMetadataPath] = args;
    const result = await verifyCoreReleaseCandidate({
      repositoryRoot: path.resolve(import.meta.dirname, '..'),
      bundleDir,
      trustedPublicKey: fs.readFileSync(publicKeyPath, 'utf8'),
      vulnerabilityReport: JSON.parse(fs.readFileSync(auditPath, 'utf8')),
      ...(stateMetadataPath === undefined
        ? {}
        : { stateMetadata: JSON.parse(fs.readFileSync(stateMetadataPath, 'utf8')) }),
    });
    process.stdout.write(
      `${JSON.stringify({
        status: result.status,
        profile: result.profile,
        gateCount: result.gates.length,
        source: result.source,
        networkRequired: false,
        published: false,
      })}\n`,
    );
  } catch (error) {
    process.stderr.write(
      `ARC 1.0 Core release-candidate verification failed (${error?.code ?? 'RELEASE_CANDIDATE_FAILED'}).\n`,
    );
    process.exitCode = 1;
  }
}
