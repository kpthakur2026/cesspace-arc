#!/usr/bin/env node
import path from 'node:path';
import { uninstallDistribution } from './arc10-distribution-lib.mjs';

const [prefix] = process.argv.slice(2);
if (!prefix) {
  console.error('Usage: arc10-uninstall <user-prefix>');
  process.exitCode = 2;
} else {
  const result = await uninstallDistribution({ prefix: path.resolve(prefix) });
  console.log(JSON.stringify({ removedOwnedFiles: result.removedOwnedFiles, uninstalled: true }));
}
