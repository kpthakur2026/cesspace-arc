import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export async function resolveIntegrationCoreServerConfig(
  stateDirectory,
  environment = process.env,
) {
  if (typeof stateDirectory !== 'string' || !stateDirectory.trim()) {
    throw new Error('A Core state directory is required.');
  }

  const { preflightCoreState, toArcServerConfig } =
    await import('../packages/config/dist/index.js');
  const preflight = await preflightCoreState(path.resolve(stateDirectory), { environment });
  const base = toArcServerConfig(preflight);

  if (base.transport !== 'stdio') {
    throw new Error(
      'ARC client integration launchers require a Core state configured for stdio transport.',
    );
  }

  const policyPath = preflight.resolved.policyPath;
  const extension = path.extname(policyPath).toLowerCase();
  const policyFormat =
    extension === '.json' ? 'json' : extension === '.yaml' || extension === '.yml' ? 'yaml' : null;
  if (policyFormat === null) {
    throw new Error('Core policy path must end in .json, .yaml, or .yml.');
  }
  const policy = {
    sourceText: fs.readFileSync(policyPath, 'utf8'),
    format: policyFormat,
  };

  let admin;
  if (preflight.resolved.adminSocketPath || preflight.resolved.operatorPublicKeyPath) {
    if (!preflight.resolved.adminSocketPath || !preflight.resolved.operatorPublicKeyPath) {
      throw new Error('Core admin configuration is incomplete.');
    }
    const publicKey = crypto.createPublicKey(
      fs.readFileSync(preflight.resolved.operatorPublicKeyPath),
    );
    const operatorPublicKeyB64 = publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');
    admin = {
      endpoint: preflight.resolved.adminSocketPath,
      operatorPublicKeyB64,
    };
  }

  return {
    ...base,
    policy,
    processStateDir: preflight.resolved.processDirectory,
    ...(admin ? { admin } : {}),
  };
}
