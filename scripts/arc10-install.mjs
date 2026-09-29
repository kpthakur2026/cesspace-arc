#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { installDistribution } from './arc10-distribution-lib.mjs';

const [bundleDir, publicKeyFile, prefix] = process.argv.slice(2);
if (!bundleDir || !publicKeyFile || !prefix) {
  console.error(
    'Usage: arc10-install <bundle-dir> <trusted-ed25519-public-key-file> <user-prefix>',
  );
  process.exitCode = 2;
} else {
  const trustedPublicKey = await fs.promises.readFile(publicKeyFile, 'utf8');
  const result = await installDistribution({
    bundleDir: path.resolve(bundleDir),
    prefix: path.resolve(prefix),
    trustedPublicKey,
  });
  console.log(
    JSON.stringify({ installed: true, prefix: result.prefix, version: result.ownership.version }),
  );
}
