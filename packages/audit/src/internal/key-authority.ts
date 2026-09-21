/**
 * Cryptographic key and trust-root file authority (RC-06 Task 4, §13).
 *
 * Every Ed25519 key ARC reads — the checkpoint signing key, the checkpoint
 * verification trust root, and (from Task 5 on) the anchor receipt trust root —
 * is a security-sensitive file even when its contents are public. This module is
 * the single place where such a file is opened, validated, bounded, parsed and
 * released, so the authority rules exist once rather than once per caller:
 *
 *  - regular file, mode exactly `0600`, owned by the expected real UID,
 *    `nlink === 1`, never a symbolic link (`O_NOFOLLOW`),
 *  - opened with `O_NOFOLLOW`, then validated through `fstat()` on the resulting
 *    descriptor — never by validating a pathname and reopening it,
 *  - read at most `MAX_SIGNING_KEY_BYTES + 1` bytes, so an oversize file is
 *    established by the read itself rather than by a `stat()` that could lie,
 *  - algorithm fixed to Ed25519 by both the PEM label and
 *    `asymmetricKeyType`, with no negotiation and no fallback.
 *
 * The purpose label parameterizes the loader for the future anchor-receipt trust
 * root. It does not weaken anything: both purposes enforce identical filesystem
 * authority and identical Ed25519-only parsing. Task 4 deliberately does not
 * implement anchor receipt verification.
 *
 * @internal
 */

import crypto from 'node:crypto';
import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';

import { MAX_SIGNING_KEY_BYTES } from './checkpoint-constants.js';
import { createCodedError } from './errors.js';
import { getProcessUid, validateFileDescriptorAuthority } from '../storage.js';

/** Which trust root a load is for. Both currently enforce identical authority. */
export type TrustRootPurpose = 'CHECKPOINT' | 'ANCHOR_RECEIPT';

/** A validated Ed25519 trust root and the identity metadata derived from it. */
export interface LoadedTrustRoot {
  /** The parsed public key. */
  publicKey: crypto.KeyObject;
  /** `SHA-256(SPKI DER)` as 64 lowercase hex. */
  fingerprint: string;
  /** The SPKI DER the fingerprint was computed over. */
  spkiDer: Buffer;
}

/** A validated Ed25519 signing key and the public identity it implies. */
export interface LoadedSigningKey {
  /** The parsed private key. */
  privateKey: crypto.KeyObject;
  /** The public key derived from it. */
  derivedPublicKey: crypto.KeyObject;
  /** `SHA-256(SPKI DER)` of the derived public key. */
  derivedFingerprint: string;
}

/** The untrusted channels key material must never arrive through (rc06 §13.1). */
export type SigningKeySource =
  'argv' | 'environment' | 'mcp-header' | 'mcp-tool-argument' | 'configuration-literal' | 'log';

const SOURCE_LABELS: Record<SigningKeySource, string> = {
  argv: 'argv',
  environment: 'an ambient environment variable',
  'mcp-header': 'an MCP header',
  'mcp-tool-argument': 'an MCP tool argument',
  'configuration-literal': 'a configuration literal',
  log: 'a log sink',
};

/** PKCS#8 private key PEM label. The only accepted private-key encoding. */
const PRIVATE_KEY_PEM_LABEL = 'PRIVATE KEY';

/** SPKI public key PEM label. The only accepted public-key encoding. */
const PUBLIC_KEY_PEM_LABEL = 'PUBLIC KEY';

const PEM_BLOCK_REGEX = /-----BEGIN ([A-Z0-9 ]+)-----/g;

/**
 * Shape of a PEM private-key block header.
 *
 * Matches `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE
 * KEY` and `OPENSSH PRIVATE KEY`, so the forbidden-source guard cannot be walked
 * past by relabelling the block.
 */
const PRIVATE_KEY_PEM_SHAPE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

/* -------------------------------------------------------------------------- *
 * Private-key loader invocation probe (test-only)
 * -------------------------------------------------------------------------- */

let privateKeyLoadProbeEnabled = false;
let privateKeyLoadCount = 0;

/**
 * Enables counting of signing-key loads, for the §84 assertion that the
 * public-key-only verification path never opens the private key.
 *
 * Off by default, so production pays at most one boolean test per key load and
 * no counter is ever incremented.
 *
 * @internal
 */
export function enablePrivateKeyLoadProbe(): void {
  privateKeyLoadProbeEnabled = true;
  privateKeyLoadCount = 0;
}

/** The number of signing-key loads observed since the probe was enabled. @internal */
export function getPrivateKeyLoadCount(): number {
  return privateKeyLoadCount;
}

/* -------------------------------------------------------------------------- *
 * Descriptor authority
 * -------------------------------------------------------------------------- */

/**
 * Opens a key file with `O_NOFOLLOW` and proves its authority on the descriptor.
 *
 * The caller must close the returned descriptor. Nothing here is done by
 * pathname after the open, so a swap between validation and use is not possible.
 */
function openKeyFile(
  filePath: string,
  expectedUid: number,
  label: string,
): { fd: number; stats: fs.Stats } {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path is required`);
  }
  if (!path.isAbsolute(filePath)) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path must be absolute`);
  }

  let fd: number;
  try {
    fd = fs.openSync(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (err: unknown) {
    const code = (err as { code?: string } | null)?.code;
    if (code === 'ELOOP') {
      throw createCodedError('SYMLINK_DETECTED', `${label} is a symbolic link`);
    }
    if (code === 'ENOENT') {
      throw createCodedError('AUDIT_KEY_FILE_MISSING', `${label} does not exist`);
    }
    throw createCodedError('AUDIT_KEY_FILE_UNAVAILABLE', `${label} could not be opened safely`, {
      cause: err,
    });
  }

  try {
    // fstat on the validated descriptor: regular file, mode exactly 0600, real
    // UID, nlink 1. A symlink never reaches here because O_NOFOLLOW refused it.
    const stats = validateFileDescriptorAuthority(fd, 0o600, expectedUid);
    return { fd, stats };
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
}

/**
 * Reads at most `MAX_SIGNING_KEY_BYTES + 1` bytes and rejects anything larger.
 *
 * The bound is enforced by the read, not by `fstat().size`: a file that reports
 * a small size but yields more bytes is still rejected, and a genuinely large
 * file is never read past the first byte that proves it is oversize.
 */
function readBoundedKeyBytes(fd: number, label: string): { buffer: Buffer; byteLength: number } {
  const buffer = Buffer.alloc(MAX_SIGNING_KEY_BYTES + 1);
  let offset = 0;

  while (offset < buffer.length) {
    const read = fs.readSync(fd, buffer, offset, buffer.length - offset, null);
    if (read <= 0) break;
    offset += read;
  }

  if (offset > MAX_SIGNING_KEY_BYTES) {
    buffer.fill(0);
    throw createCodedError(
      'AUDIT_KEY_TOO_LARGE',
      `${label} exceeds MAX_SIGNING_KEY_BYTES (${MAX_SIGNING_KEY_BYTES})`,
    );
  }

  return { buffer, byteLength: offset };
}

/**
 * Requires the PEM text to contain exactly one block with the expected label.
 *
 * This is what keeps a certificate, an OpenSSH key, a PKCS#1 RSA key or a
 * nested PEM bundle from being accepted as "a public key": `createPublicKey`
 * happily extracts a key out of a certificate, so the encoding has to be
 * checked before parsing rather than inferred from the parse succeeding.
 */
function assertSinglePemBlock(text: string, expectedLabel: string, label: string): void {
  const labels: string[] = [];
  PEM_BLOCK_REGEX.lastIndex = 0;
  let match = PEM_BLOCK_REGEX.exec(text);
  while (match !== null) {
    labels.push(match[1]);
    match = PEM_BLOCK_REGEX.exec(text);
  }

  if (labels.length !== 1 || labels[0] !== expectedLabel) {
    throw createCodedError(
      'AUDIT_KEY_ENCODING_FORBIDDEN',
      `${label} must be exactly one ${expectedLabel} PEM block`,
    );
  }

  if (!text.includes(`-----END ${expectedLabel}-----`)) {
    throw createCodedError(
      'AUDIT_KEY_ENCODING_FORBIDDEN',
      `${label} is a truncated ${expectedLabel} PEM block`,
    );
  }
}

/* -------------------------------------------------------------------------- *
 * Fingerprints
 * -------------------------------------------------------------------------- */

/**
 * `SHA-256` of the key's SPKI DER encoding, as 64 lowercase hex (rc06 §13.3).
 *
 * Fingerprinting the DER rather than the PEM text is what makes the digest a
 * property of the cryptographic key: PEM line wrapping, leading or trailing
 * whitespace and header spelling cannot change it.
 */
export function computePublicKeyFingerprint(publicKey: crypto.KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto
    .createHash('sha256')
    .update(der as unknown as Buffer)
    .digest('hex');
}

/* -------------------------------------------------------------------------- *
 * Public trust root
 * -------------------------------------------------------------------------- */

/**
 * Loads, validates and fingerprints an Ed25519 public trust root.
 *
 * Reusable by Task 5 for the anchor receipt trust root: the purpose label
 * selects only the wording, never the authority rules or the accepted algorithm.
 */
export function loadEd25519TrustRootFile(
  filePath: string,
  options: { purpose: TrustRootPurpose; expectedUid?: number },
): LoadedTrustRoot {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = options.purpose === 'ANCHOR_RECEIPT' ? 'anchor receipt public key' : 'public key';

  const { fd } = openKeyFile(filePath, expectedUid, label);
  try {
    const { buffer, byteLength } = readBoundedKeyBytes(fd, label);
    const text = buffer.subarray(0, byteLength).toString('utf8');
    assertSinglePemBlock(text, PUBLIC_KEY_PEM_LABEL, label);

    let publicKey: crypto.KeyObject;
    try {
      publicKey = crypto.createPublicKey({ key: buffer.subarray(0, byteLength), format: 'pem' });
    } catch (cause) {
      throw createCodedError('AUDIT_KEY_MALFORMED', `${label} is not a parseable public key`, {
        cause,
      });
    }

    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw createCodedError(
        'AUDIT_KEY_ALGORITHM_FORBIDDEN',
        `${label} must be Ed25519 (got ${String(publicKey.asymmetricKeyType)})`,
      );
    }

    const spkiDer = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }) as Buffer);
    return {
      publicKey,
      spkiDer,
      fingerprint: crypto.createHash('sha256').update(spkiDer).digest('hex'),
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Computes the fingerprint of a configured checkpoint public key file.
 *
 * This is the §46 fresh-store helper: Task 1 must persist the pinned fingerprint
 * into `audit-store.json` before the store accepts its first record, and it can
 * do so through this function without ever touching a private key.
 */
export function computeTrustRootFingerprintFromFile(
  filePath: string,
  options: { purpose: TrustRootPurpose; expectedUid?: number },
): string {
  return loadEd25519TrustRootFile(filePath, options).fingerprint;
}

/* -------------------------------------------------------------------------- *
 * Signing key
 * -------------------------------------------------------------------------- */

/**
 * Loads, validates and parses a PKCS#8 Ed25519 signing key.
 *
 * The PEM bytes are read into a mutable `Buffer` and zeroized in a `finally`
 * block whether parsing succeeded or failed, so the raw key text does not
 * outlive this call. The returned `KeyObject` is what the engine signs with.
 */
export function loadEd25519SigningKeyFile(
  filePath: string,
  options: { expectedUid?: number } = {},
): LoadedSigningKey {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = 'signing key';

  const { fd } = openKeyFile(filePath, expectedUid, label);
  try {
    const { buffer, byteLength } = readBoundedKeyBytes(fd, label);
    try {
      if (privateKeyLoadProbeEnabled) {
        privateKeyLoadCount++;
      }

      const text = buffer.subarray(0, byteLength).toString('utf8');
      assertSinglePemBlock(text, PRIVATE_KEY_PEM_LABEL, label);

      let privateKey: crypto.KeyObject;
      try {
        privateKey = crypto.createPrivateKey({
          key: buffer.subarray(0, byteLength),
          format: 'pem',
        });
      } catch (cause) {
        throw createCodedError('AUDIT_KEY_MALFORMED', `${label} is not a parseable private key`, {
          cause,
        });
      }

      if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw createCodedError(
          'AUDIT_KEY_ALGORITHM_FORBIDDEN',
          `${label} must be Ed25519 (got ${String(privateKey.asymmetricKeyType)})`,
        );
      }

      const derivedPublicKey = crypto.createPublicKey(privateKey);
      return {
        privateKey,
        derivedPublicKey,
        derivedFingerprint: computePublicKeyFingerprint(derivedPublicKey),
      };
    } finally {
      // Memory hygiene (rc06 §13.1): the transient PEM buffer never survives this
      // call, on the success path or any failure path.
      buffer.fill(0);
    }
  } finally {
    fs.closeSync(fd);
  }
}

/* -------------------------------------------------------------------------- *
 * Workspace isolation (rc06 §13.1)
 * -------------------------------------------------------------------------- */

/**
 * Rejects a signing key that a workspace boundary contains, is contained by, or
 * coincides with.
 *
 * Task 4 does not own workspace discovery, so the caller supplies the
 * authenticated set of workspace paths; Task 6 supplies the production ones.
 * Both directions are checked, because a key path that is an *ancestor* of a
 * workspace exposes the key to everything the workspace can reach just as
 * surely as a key inside it.
 *
 * The message names no path: an operator gets the rule, and no absolute host
 * path is echoed into a log.
 */
export function assertSigningKeyOutsideWorkspaces(
  signingKeyPath: string,
  workspacePaths: readonly string[],
): void {
  const keyPath = path.resolve(signingKeyPath);

  for (const workspacePath of workspacePaths) {
    const workspace = path.resolve(workspacePath);
    if (
      keyPath === workspace ||
      keyPath.startsWith(workspace + path.sep) ||
      workspace.startsWith(keyPath + path.sep)
    ) {
      throw createCodedError(
        'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
        'checkpoint signing key must reside outside every agent workspace',
      );
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Forbidden private-key sources (rc06 §13.1, Task 4 §48/§49)
 * -------------------------------------------------------------------------- */

/**
 * True when a candidate value carries raw private-key material.
 *
 * Two shapes are detected, both of which are how key material actually travels:
 * PEM text, wherever in the string it sits, and the same PEM text wrapped in a
 * Base64 envelope. A bare 64-hex digest, an absolute path and an ordinary
 * identifier are all deliberately NOT detected — those are ordinary
 * configuration values, and flagging them would make the guard unusable rather
 * than safer.
 */
function carriesRawKeyMaterial(value: unknown): boolean {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return value.length >= 32;
  }
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  if (PRIVATE_KEY_PEM_SHAPE.test(value)) {
    return true;
  }

  const trimmed = value.trim();
  if (trimmed.length < 44 || !/^[A-Za-z0-9+/_=-]+$/.test(trimmed)) {
    return false;
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(trimmed, 'base64');
  } catch {
    return false;
  }
  return decoded.length >= 32 && PRIVATE_KEY_PEM_SHAPE.test(decoded.toString('latin1'));
}

/**
 * Rejects raw private-key material supplied through an untrusted channel.
 *
 * Production configuration carries a filesystem PATH and nothing else. This
 * guard is the reusable enforcement point for future production composition:
 * Task 6 owns server startup and remote input wiring, so it supplies the
 * candidate values and this rejects them before any of them can reach a key
 * parser.
 *
 * The failure message is source-oriented and never contains the candidate, so a
 * rejection cannot itself become the leak it exists to prevent.
 */
export function assertNoRawSigningKeyMaterial(
  candidates: readonly { source: SigningKeySource; value: unknown }[],
): void {
  for (const candidate of candidates) {
    if (carriesRawKeyMaterial(candidate.value)) {
      throw createCodedError(
        'AUDIT_SIGNING_KEY_SOURCE_FORBIDDEN',
        `signing key material from ${SOURCE_LABELS[candidate.source]} is forbidden`,
      );
    }
  }
}
