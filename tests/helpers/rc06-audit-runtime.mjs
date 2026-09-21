/**
 * CesSpace ARC — ephemeral RC-06 production audit configuration for tests.
 *
 * RC-06 Task 6 makes the durable audit runtime a mandatory part of the
 * production composition: `ArcMcpServer.start()` refuses to bind any transport
 * until the frozen §22.1 startup sequence has reached step 12. Every existing
 * suite that starts a REAL server therefore has to hand it a real
 * `AuditConfig`, exactly as an operator's launcher would.
 *
 * This helper produces that configuration the way the frozen model requires:
 *
 *  - a real Ed25519 keypair, generated per call with `node:crypto`, written as
 *    a 0600 PKCS#8 private key and a 0600 SPKI public key — the exact shape the
 *    hardened Task-4 key authority accepts (mode exactly 0600, real UID,
 *    link count 1, no symlinked component);
 *  - an audit directory path that does not exist yet, so Task-1's directory
 *    authority creates it at 0700 and the store starts empty;
 *  - an anchor-free configuration, because these suites exercise policy,
 *    approval, gateway and admission behavior rather than Tier-3 anchoring.
 *
 * Nothing here is reachable from production code, no key is committed, and the
 * whole tree lives under the calling suite's temporary directory and is removed
 * with it.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Builds one ephemeral, production-shaped `AuditConfig`.
 *
 * @param {string} baseDir An existing temporary directory owned by this process.
 * @param {string} [label] Distinguishes several stores inside the same base.
 * @returns {{ directory: string, signingKeyPath: string, publicKeyPath: string }}
 */
export function createAuditConfig(baseDir, label = 'audit') {
  // `realpath` because the hardened key authority refuses a path whose parent
  // chain contains a symbolic link and because `os.tmpdir()` is itself a
  // symlink on some platforms.
  const root = path.join(fs.realpathSync(baseDir), `rc06-${label}`);
  const keyDir = path.join(root, 'keys');
  fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  fs.chmodSync(keyDir, 0o700);

  const signingKeyPath = path.join(keyDir, 'checkpoint-signing.pem');
  const publicKeyPath = path.join(keyDir, 'checkpoint-public.pem');

  // Reuse an existing pair when the same label is asked for twice. A store
  // records its checkpoint trust root durably, so minting a second key over the
  // same store would be refused as `AUDIT_CHECKPOINT_KEY_MISMATCH` — and a
  // fixture that reshuffled its own trust root between two starts would be
  // testing the wrong thing.
  if (!fs.existsSync(signingKeyPath) || !fs.existsSync(publicKeyPath)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(signingKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
    });
    fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), {
      mode: 0o600,
    });
  }
  // `mode` on `writeFileSync` is masked by the process umask, so the exact
  // 0600 authority is asserted explicitly rather than assumed.
  fs.chmodSync(signingKeyPath, 0o600);
  fs.chmodSync(publicKeyPath, 0o600);

  return {
    directory: path.join(root, 'store'),
    signingKeyPath,
    publicKeyPath,
  };
}
