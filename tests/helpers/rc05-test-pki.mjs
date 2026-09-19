/**
 * CesSpace ARC — RC-05 Task 3 test PKI helper.
 *
 * Generates an EPHEMERAL test PKI (root CA, server leaf, client leaves) inside a
 * caller-supplied temporary directory using the platform `openssl` binary.
 *
 * Nothing here is committed, reusable, or secret in any real sense: every key is
 * generated at test time under the OS temp directory and removed with it. The
 * repository contains no certificate or private-key fixture, so no scanner
 * suppression or allowlist is needed or permitted.
 *
 * This module is a helper, not a test: it is not part of the `pnpm run test`
 * file list and defines no cases.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

/**
 * True when the platform provides `openssl`.
 *
 * The RC-05 Task-3 suite generates its own X.509 material rather than shipping
 * fixtures, so certificate generation is a genuine environment requirement
 * rather than an optional nicety.
 */
export function hasOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function run(args, cwd) {
  return execFileSync('openssl', args, {
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
  });
}

/** Writes a fresh 0600 private key. */
function generateKey(file, cwd) {
  run(['genpkey', '-algorithm', 'ed25519', '-out', file], cwd);
  fs.chmodSync(path.join(cwd, file), 0o600);
  return path.join(cwd, file);
}

/** Creates a self-signed root CA. */
function createRootCa(cwd, name) {
  const key = `${name}.key`;
  const cert = `${name}.pem`;
  generateKey(key, cwd);
  run(['req', '-x509', '-key', key, '-out', cert, '-days', '3650', '-subj', `/CN=${name}`], cwd);
  fs.chmodSync(path.join(cwd, cert), 0o644);
  return { keyPath: path.join(cwd, key), certPath: path.join(cwd, cert) };
}

/** Writes the `openssl ca` configuration used for leaf issuance. */
function writeCaConfig(cwd, ca, { serverName, san }) {
  const config = `[ ca ]
default_ca = CA_default
[ CA_default ]
dir = .
database = ./${ca.dbFile}
new_certs_dir = ./${ca.newCertsDir}
serial = ./${ca.serialFile}
certificate = ./${path.basename(ca.certPath)}
private_key = ./${path.basename(ca.keyPath)}
default_md = default
policy = policy_any
x509_extensions = leaf_ext
copy_extensions = none
[ policy_any ]
commonName = supplied
[ leaf_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = ${san}
`;
  const configPath = path.join(cwd, `${serverName}.cnf`);
  fs.writeFileSync(configPath, config, { mode: 0o600 });
  return configPath;
}

/**
 * Issues a leaf certificate with an explicit validity window.
 *
 * `startdate`/`enddate` are OpenSSL YYMMDDHHMMSSZ values, which is what makes a
 * deterministically expired client certificate possible without freezing time.
 */
function issueLeaf(cwd, { configPath, commonName, keyFile, certFile, startdate, enddate }) {
  const csr = `${certFile}.csr`;
  run(['req', '-new', '-key', keyFile, '-out', csr, '-subj', `/CN=${commonName}`], cwd);
  run(
    [
      'ca',
      '-batch',
      '-config',
      configPath,
      '-in',
      csr,
      '-out',
      certFile,
      '-startdate',
      startdate,
      '-enddate',
      enddate,
    ],
    cwd,
  );
  fs.chmodSync(path.join(cwd, certFile), 0o644);
  return path.join(cwd, certFile);
}

/** OpenSSL date string `days` from now, in UTC. */
function opensslDate(offsetDays) {
  const date = new Date(Date.now() + offsetDays * 86_400_000);
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${String(date.getUTCFullYear()).slice(2)}` +
    `${pad(date.getUTCMonth() + 1)}` +
    `${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}` +
    `${pad(date.getUTCMinutes())}` +
    `${pad(date.getUTCSeconds())}Z`
  );
}

function makeCa(cwd, name) {
  const ca = createRootCa(cwd, name);
  fs.writeFileSync(path.join(cwd, `${name}.index`), '');
  fs.writeFileSync(path.join(cwd, `${name}.serial`), '1000\n');
  fs.mkdirSync(path.join(cwd, `${name}.newcerts`), { recursive: true });
  return {
    ...ca,
    dbFile: `${name}.index`,
    serialFile: `${name}.serial`,
    newCertsDir: `${name}.newcerts`,
  };
}

/**
 * Generates the full ephemeral PKI for the Task-3 suite.
 *
 * @param {string} dir Temporary directory owned by the caller.
 */
export function createTestPki(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const cwd = dir;

  const trustedCa = makeCa(cwd, 'trusted-ca');
  const untrustedCa = makeCa(cwd, 'untrusted-ca');

  const san = 'DNS:localhost,IP:127.0.0.1';
  const trustedConfig = writeCaConfig(cwd, trustedCa, { serverName: 'trusted-server', san });
  const untrustedConfig = writeCaConfig(cwd, untrustedCa, { serverName: 'untrusted-server', san });

  // Server leaf: valid now, SAN covers localhost and 127.0.0.1.
  const serverKeyPath = generateKey('server.key', cwd);
  const serverCertPath = issueLeaf(cwd, {
    configPath: trustedConfig,
    commonName: 'localhost',
    keyFile: 'server.key',
    certFile: 'server.pem',
    startdate: opensslDate(-1),
    enddate: opensslDate(30),
  });

  // A second server key that does NOT match the server certificate.
  const wrongServerKeyPath = generateKey('server-wrong.key', cwd);

  // Server leaf whose SAN does not cover the configured public hostname.
  const sanMismatchKeyPath = generateKey('server-sanmismatch.key', cwd);
  const sanMismatchCertPath = issueLeaf(cwd, {
    configPath: writeCaConfig(cwd, trustedCa, {
      serverName: 'san-mismatch',
      san: 'DNS:other.example.invalid',
    }),
    commonName: 'other.example.invalid',
    keyFile: 'server-sanmismatch.key',
    certFile: 'server-sanmismatch.pem',
    startdate: opensslDate(-1),
    enddate: opensslDate(30),
  });

  // Client leaf signed by the trusted CA, valid now.
  const clientKeyPath = generateKey('client.key', cwd);
  const clientCertPath = issueLeaf(cwd, {
    configPath: trustedConfig,
    commonName: 'client-valid',
    keyFile: 'client.key',
    certFile: 'client.pem',
    startdate: opensslDate(-1),
    enddate: opensslDate(30),
  });

  // Client leaf signed by the trusted CA, already expired.
  const expiredClientKeyPath = generateKey('client-expired.key', cwd);
  const expiredClientCertPath = issueLeaf(cwd, {
    configPath: trustedConfig,
    commonName: 'client-expired',
    keyFile: 'client-expired.key',
    certFile: 'client-expired.pem',
    startdate: opensslDate(-30),
    enddate: opensslDate(-1),
  });

  // Client leaf signed by the trusted CA, not yet valid.
  const futureClientKeyPath = generateKey('client-future.key', cwd);
  const futureClientCertPath = issueLeaf(cwd, {
    configPath: trustedConfig,
    commonName: 'client-future',
    keyFile: 'client-future.key',
    certFile: 'client-future.pem',
    startdate: opensslDate(1),
    enddate: opensslDate(30),
  });

  // Client leaf signed by an UNTRUSTED CA.
  const unknownCaClientKeyPath = generateKey('client-unknownca.key', cwd);
  const unknownCaClientCertPath = issueLeaf(cwd, {
    configPath: untrustedConfig,
    commonName: 'client-unknown-ca',
    keyFile: 'client-unknownca.key',
    certFile: 'client-unknownca.pem',
    startdate: opensslDate(-1),
    enddate: opensslDate(30),
  });

  // Malformed / non-certificate CA inputs.
  const malformedCaPath = path.join(cwd, 'malformed-ca.pem');
  fs.writeFileSync(
    malformedCaPath,
    '-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n',
    {
      mode: 0o644,
    },
  );
  const notACertificatePath = path.join(cwd, 'not-a-cert.pem');
  fs.writeFileSync(notACertificatePath, 'this file is not a certificate at all\n', { mode: 0o644 });

  return {
    dir: cwd,
    trustedCaCertPath: trustedCa.certPath,
    untrustedCaCertPath: untrustedCa.certPath,
    serverKeyPath,
    serverCertPath,
    wrongServerKeyPath,
    sanMismatchKeyPath,
    sanMismatchCertPath,
    clientKeyPath,
    clientCertPath,
    expiredClientKeyPath,
    expiredClientCertPath,
    futureClientKeyPath,
    futureClientCertPath,
    unknownCaClientKeyPath,
    unknownCaClientCertPath,
    malformedCaPath,
    notACertificatePath,
  };
}

/** Creates a symlink to a CA file, for the symlink-rejection control. */
export function symlinkTo(target, linkPath) {
  fs.symlinkSync(target, linkPath);
  return linkPath;
}

/** Creates an oversized CA file, for the size-bound control. */
export function oversizedCaFile(target, targetPath) {
  const contents = fs.readFileSync(target, 'utf8');
  const padding = `#${'p'.repeat(70 * 1024)}\n`;
  fs.writeFileSync(targetPath, contents + padding, { mode: 0o644 });
  return targetPath;
}
