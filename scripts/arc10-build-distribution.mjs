#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { buildDistribution } from './arc10-distribution-lib.mjs';

const [outputDir, signingKeyFile, sourceRoot = process.cwd()] = process.argv.slice(2);
if (!outputDir || !signingKeyFile) {
  console.error(
    'Usage: arc10-build-distribution <output-dir> <ed25519-private-key-file> [source-root]',
  );
  process.exitCode = 2;
} else {
  const privateKey = await fs.promises.readFile(signingKeyFile, 'utf8');
  const result = await buildDistribution({
    outputDir: path.resolve(outputDir),
    privateKey,
    sourceRoot: path.resolve(sourceRoot),
  });
  console.log(
    JSON.stringify({ normalizedDigest: result.normalizedDigest, source: result.manifest.source }),
  );
}
