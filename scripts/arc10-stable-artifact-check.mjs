#!/usr/bin/env node
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARC_STAGE,
  ARC_VERSION,
  buildDistribution,
  installDistribution,
  sha256,
  uninstallDistribution,
  verifyDistribution,
} from './arc10-distribution-lib.mjs';
import { verifyCoreReleaseCandidate } from './arc10-release-candidate-lib.mjs';
import { InstalledStdioClient } from '../tests/helpers/arc10-distribution-fixture.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const temporaryRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'arc10-stable-'));

try {
  const pair = generateKeyPairSync('ed25519');
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const bundleDir = path.join(temporaryRoot, 'bundle');
  const prefix = path.join(temporaryRoot, 'prefix');
  const workspace = path.join(temporaryRoot, 'workspace');
  const preserved = path.join(temporaryRoot, 'operator-data');
  await fs.promises.mkdir(workspace, { recursive: true });
  await fs.promises.mkdir(preserved, { recursive: true });
  await fs.promises.writeFile(path.join(workspace, 'sentinel.txt'), 'stable-core-read\n');
  await fs.promises.writeFile(path.join(preserved, 'config-sentinel'), 'preserved\n');
  await fs.promises.writeFile(path.join(preserved, 'audit-sentinel'), 'preserved\n');

  await buildDistribution({ sourceRoot: repositoryRoot, outputDir: bundleDir, privateKey });
  const verified = await verifyDistribution({ bundleDir, trustedPublicKey: publicKey });
  const candidate = await verifyCoreReleaseCandidate({
    repositoryRoot,
    bundleDir,
    trustedPublicKey: publicKey,
    vulnerabilityReport: {
      format: 'cesspace-arc-vulnerability-report-v1',
      lockfileSha256: verified.manifest.lockfileSha256,
      findings: [],
    },
    stateMetadata: { format: 'cesspace-arc-core-state', stateSchemaVersion: 2 },
  });
  const installed = await installDistribution({ bundleDir, trustedPublicKey: publicKey, prefix });
  const client = new InstalledStdioClient(
    path.join(prefix, 'runtime/apps/mcp-server/dist/index.js'),
    workspace,
  );
  let health;
  let read;
  try {
    health = await client.health();
    const response = await client.request('tools/call', {
      name: 'read_file',
      arguments: { path: 'sentinel.txt' },
    });
    if (response.error) throw new Error('Installed read_file failed');
    read = JSON.parse(response.result.content.find((item) => item.type === 'text').text);
  } finally {
    await client.close();
  }
  if (
    health.version !== ARC_VERSION ||
    health.stage !== ARC_STAGE ||
    read.content !== 'stable-core-read\n'
  )
    throw new Error('Installed stable identity or representative MCP read is invalid');
  await uninstallDistribution({ prefix });
  if (
    fs.existsSync(path.join(prefix, 'runtime')) ||
    fs.readFileSync(path.join(preserved, 'config-sentinel'), 'utf8') !== 'preserved\n' ||
    fs.readFileSync(path.join(preserved, 'audit-sentinel'), 'utf8') !== 'preserved\n'
  )
    throw new Error('Stable uninstall ownership or preservation failed');
  const digests = {};
  for (const name of (await fs.promises.readdir(bundleDir)).sort())
    digests[name] = sha256(await fs.promises.readFile(path.join(bundleDir, name)));
  process.stdout.write(
    `${JSON.stringify({
      status: 'PASS',
      source: verified.manifest.source,
      version: health.version,
      stage: health.stage,
      readFile: read.content,
      installSource: {
        commit: installed.ownership.sourceCommit,
        tree: installed.ownership.sourceTree,
      },
      candidateGates: candidate.gates.length,
      digests,
      uninstalled: true,
      preservedOperatorData: true,
      signingKeyPersisted: false,
      published: false,
    })}\n`,
  );
} catch (error) {
  process.stderr.write(
    `Stable artifact verification failed (${error?.code ?? 'STABLE_ARTIFACT_FAILED'}).\n`,
  );
  process.exitCode = 1;
} finally {
  await fs.promises.rm(temporaryRoot, { recursive: true, force: true });
}
