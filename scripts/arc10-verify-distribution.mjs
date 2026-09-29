#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { verifyDistribution } from './arc10-distribution-lib.mjs';

const [bundleDir, publicKeyFile] = process.argv.slice(2);
if (!bundleDir || !publicKeyFile) {
  console.error('Usage: arc10-verify-distribution <bundle-dir> <trusted-ed25519-public-key-file>');
  process.exitCode = 2;
} else {
  const trustedPublicKey = await fs.promises.readFile(publicKeyFile, 'utf8');
  const result = await verifyDistribution({ bundleDir: path.resolve(bundleDir), trustedPublicKey });
  console.log(
    JSON.stringify({
      verified: true,
      source: result.manifest.source,
      version: result.manifest.version,
    }),
  );
}
