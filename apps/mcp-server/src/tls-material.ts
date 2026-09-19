/**
 * CesSpace ARC — RC-05 Task 3 TLS Material Validation
 *
 * Startup validation of the server private key, the server certificate, and the
 * client CA trust roots. Authoritative contract: §6 (T-1..T-11), §18, §17 K-1..K-7.
 *
 * Design rules:
 * - Private-key and certificate BYTES never appear in an error, a log line, or a
 *   returned status object. Only bounded failure reasons cross this boundary.
 * - Every rejection is a startup failure. Nothing here degrades or falls back.
 */

import fs from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { RemoteConfigError, type RemoteFailureReason } from './remote-errors.js';
import { MAX_CLIENT_CA_BYTES, type PrivateKeySource } from './remote-config.js';

/**
 * Minimal file facts needed by the integrity checks.
 *
 * The stat object is obtained with `lstatSync` so a symlink is never followed,
 * and only these non-secret fields are ever retained.
 */
interface FileFacts {
  isFile: boolean;
  isSymbolicLink: boolean;
  uid: number;
  mode: number;
  size: number;
}

function lstatFacts(filePath: string, reason: RemoteFailureReason): FileFacts {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    throw new RemoteConfigError('Required file is missing or unreadable.', reason);
  }
  return {
    isFile: stat.isFile(),
    isSymbolicLink: stat.isSymbolicLink(),
    uid: stat.uid,
    mode: stat.mode & 0o7777,
    size: stat.size,
  };
}

/** Current process UID, or undefined on platforms without POSIX ownership. */
function currentUid(): number | undefined {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}

/**
 * Validates a private-key FILE per §17 K-6.
 *
 * Regular file, not a symlink, owned by the process UID, and not readable or
 * writable by group or other. These are the same properties the RC-04 admin
 * channel already requires of operator key material.
 */
function validatePrivateKeyFile(filePath: string): Buffer {
  const facts = lstatFacts(filePath, 'PRIVATE_KEY_UNREADABLE');
  if (facts.isSymbolicLink || !facts.isFile) {
    throw new RemoteConfigError(
      'Server private key must be a regular file, not a symlink.',
      'PRIVATE_KEY_INSECURE',
    );
  }
  const uid = currentUid();
  if (uid !== undefined && facts.uid !== uid) {
    throw new RemoteConfigError(
      'Server private key must be owned by the process user.',
      'PRIVATE_KEY_INSECURE',
    );
  }
  if ((facts.mode & 0o077) !== 0) {
    throw new RemoteConfigError(
      'Server private key must not be readable or writable by group or other.',
      'PRIVATE_KEY_INSECURE',
    );
  }

  let contents: Buffer;
  try {
    contents = fs.readFileSync(filePath);
  } catch {
    throw new RemoteConfigError('Server private key is unreadable.', 'PRIVATE_KEY_UNREADABLE');
  }
  return contents;
}

/**
 * Loads the server private key.
 *
 * The decoded key material is consumed immediately; the caller receives only a
 * KeyObject, which is not an exportable byte string in any error path.
 */
export interface LoadedPrivateKey {
  /** Parsed key, used only for the certificate/key match check. */
  key: KeyObject;
  /**
   * PEM bytes of the same key. The TLS layer consumes this synchronously when
   * the listener is created, after which the caller MUST overwrite it. Node's
   * TLS options do not accept a bare KeyObject, so the encoded form must be
   * handed over rather than the parsed object.
   */
  pem: Buffer;
}

export function loadServerPrivateKey(source: PrivateKeySource): LoadedPrivateKey {
  let pem: Buffer;
  if (source.kind === 'file') {
    pem = validatePrivateKeyFile(source.path);
  } else {
    // Inherited descriptor: the launcher already holds the material, so ARC
    // never had it in argv or the environment.
    let stat: fs.Stats;
    try {
      stat = fs.fstatSync(source.fd);
    } catch {
      throw new RemoteConfigError(
        'Private-key file descriptor is not open.',
        'PRIVATE_KEY_UNREADABLE',
      );
    }
    if (!stat.isFile()) {
      throw new RemoteConfigError(
        'Private-key file descriptor must reference a regular file.',
        'PRIVATE_KEY_INSECURE',
      );
    }
    const chunks: Buffer[] = [];
    const scratch = Buffer.alloc(8192);
    try {
      for (;;) {
        const read = fs.readSync(source.fd, scratch, 0, scratch.length, null);
        if (read <= 0) break;
        chunks.push(Buffer.from(scratch.subarray(0, read)));
      }
    } catch {
      throw new RemoteConfigError('Private key is unreadable.', 'PRIVATE_KEY_UNREADABLE');
    } finally {
      scratch.fill(0);
    }
    pem = Buffer.concat(chunks);
  }

  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    pem.fill(0);
    throw new RemoteConfigError('Server private key is malformed.', 'PRIVATE_KEY_MALFORMED');
  }
  return { key, pem };
}

/**
 * Validates a client CA / trust-root file per §6 T-11.
 *
 * Returns the certificate PEM text, which is public material.
 */
export function loadClientCaFile(filePath: string): string {
  const facts = lstatFacts(filePath, 'CLIENT_CA_UNREADABLE');
  if (facts.isSymbolicLink || !facts.isFile) {
    throw new RemoteConfigError(
      'Client CA must be a regular file, not a symlink.',
      'CLIENT_CA_INSECURE',
    );
  }
  const uid = currentUid();
  // Root-owned trust anchors are the platform norm, so root is permitted here.
  if (uid !== undefined && facts.uid !== uid && facts.uid !== 0) {
    throw new RemoteConfigError(
      'Client CA must be owned by the process user or root.',
      'CLIENT_CA_INSECURE',
    );
  }
  if ((facts.mode & 0o022) !== 0) {
    throw new RemoteConfigError(
      'Client CA must not be group- or world-writable.',
      'CLIENT_CA_INSECURE',
    );
  }
  if (facts.size > MAX_CLIENT_CA_BYTES) {
    throw new RemoteConfigError(
      `Client CA exceeds the maximum size of ${MAX_CLIENT_CA_BYTES} bytes.`,
      'CLIENT_CA_TOO_LARGE',
    );
  }
  if (facts.size === 0) {
    throw new RemoteConfigError('Client CA file is empty.', 'CLIENT_CA_MALFORMED');
  }

  let pem: string;
  try {
    pem = fs.readFileSync(filePath, 'utf8');
  } catch {
    throw new RemoteConfigError('Client CA is unreadable.', 'CLIENT_CA_UNREADABLE');
  }
  if (!/-----BEGIN CERTIFICATE-----/.test(pem)) {
    throw new RemoteConfigError('Client CA is not a PEM certificate.', 'CLIENT_CA_MALFORMED');
  }
  try {
    // Parse before accepting: an unparseable root must fail startup rather than
    // be skipped, or the effective trust set would silently shrink.
    new X509Certificate(pem);
  } catch {
    throw new RemoteConfigError('Client CA is malformed.', 'CLIENT_CA_MALFORMED');
  }
  return pem;
}

/** Loads and validates every configured client CA root. */
export function loadClientCaRoots(paths: readonly string[]): string[] {
  return paths.map((caPath) => loadClientCaFile(caPath));
}

/** Validated server certificate plus the non-secret facts callers need. */
export interface ServerCertificateFacts {
  /** Parsed certificate. Public material only. */
  certificate: X509Certificate;
  /** Validity window start, in epoch milliseconds. */
  validFromMs: number;
  /** Validity window end, in epoch milliseconds. */
  validToMs: number;
}

/**
 * Validates the server certificate against the configured public hostname.
 *
 * Hostname verification uses the platform's own X.509 checker
 * (`checkServerIdentity`) rather than a hand-written SAN matcher, so DNS names
 * and IP literals follow the same rules a real client would apply. The
 * certificate is validated as if ARC were the client connecting to its own
 * public hostname, which is exactly the claim §6 T-5 permits ARC to check.
 */
export function loadServerCertificate(
  certificatePath: string,
  publicHostname: string,
  getWallTime: () => number,
): ServerCertificateFacts {
  const facts = lstatFacts(certificatePath, 'SERVER_CERTIFICATE_UNREADABLE');
  if (facts.isSymbolicLink || !facts.isFile) {
    throw new RemoteConfigError(
      'Server certificate must be a regular file, not a symlink.',
      'SERVER_CERTIFICATE_INVALID',
    );
  }

  let pem: string;
  try {
    pem = fs.readFileSync(certificatePath, 'utf8');
  } catch {
    throw new RemoteConfigError(
      'Server certificate is unreadable.',
      'SERVER_CERTIFICATE_UNREADABLE',
    );
  }

  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(pem);
  } catch {
    throw new RemoteConfigError(
      'Server certificate is not a parseable X.509 certificate.',
      'SERVER_CERTIFICATE_MALFORMED',
    );
  }

  const validFromMs = Date.parse(certificate.validFrom);
  const validToMs = Date.parse(certificate.validTo);
  if (!Number.isFinite(validFromMs) || !Number.isFinite(validToMs)) {
    throw new RemoteConfigError(
      'Server certificate has an unreadable validity window.',
      'SERVER_CERTIFICATE_MALFORMED',
    );
  }

  const now = getWallTime();
  if (now < validFromMs) {
    throw new RemoteConfigError(
      'Server certificate is not yet valid.',
      'SERVER_CERTIFICATE_NOT_YET_VALID',
    );
  }
  if (now >= validToMs) {
    throw new RemoteConfigError('Server certificate has expired.', 'SERVER_CERTIFICATE_EXPIRED');
  }

  // SAN verification through the platform X.509 checker rather than a
  // hand-written wildcard matcher. `subject: 'never'` restricts the match to
  // Subject Alternative Name entries, which is exactly the claim §6 T-5 makes;
  // a CN-only certificate must not be accepted here.
  let matchedSan: string | undefined;
  try {
    matchedSan = certificate.checkHost(publicHostname, { subject: 'never' });
  } catch {
    matchedSan = undefined;
  }
  if (matchedSan === undefined) {
    throw new RemoteConfigError(
      'Server certificate does not match the configured public hostname.',
      'SERVER_CERTIFICATE_SAN_MISMATCH',
    );
  }

  return { certificate, validFromMs, validToMs };
}

/**
 * Proves the private key and certificate are the same key pair.
 *
 * Comparison is over DER SubjectPublicKeyInfo digests; no key bytes are
 * returned or logged.
 */
export function assertKeyMatchesCertificate(
  privateKey: KeyObject,
  certificate: X509Certificate,
): void {
  let publicFromKey: KeyObject;
  let publicFromCertificate: KeyObject;
  try {
    publicFromKey = createPublicKey(privateKey);
    publicFromCertificate = certificate.publicKey;
  } catch {
    throw new RemoteConfigError(
      'Server private key does not match the server certificate.',
      'SERVER_KEY_AND_CERTIFICATE_MISMATCH',
    );
  }
  if (publicFromKey.asymmetricKeyType !== publicFromCertificate.asymmetricKeyType) {
    throw new RemoteConfigError(
      'Server private key does not match the server certificate.',
      'SERVER_KEY_AND_CERTIFICATE_MISMATCH',
    );
  }
  const keyDer = publicFromKey.export({ format: 'der', type: 'spki' });
  const certDer = publicFromCertificate.export({ format: 'der', type: 'spki' });
  if (!keyDer.equals(certDer)) {
    throw new RemoteConfigError(
      'Server private key does not match the server certificate.',
      'SERVER_KEY_AND_CERTIFICATE_MISMATCH',
    );
  }
}
