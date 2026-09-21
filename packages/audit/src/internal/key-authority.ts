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
 *  - **no symbolic link anywhere in the path**, not merely in its final
 *    component: a `O_NOFOLLOW` final open still follows a symlinked *parent*, so
 *    a path such as `/safe/keys-link/signing.pem` reaches whatever
 *    `/safe/keys-link` points at while the final component stays a regular file,
 *  - opened with `O_NOFOLLOW`, then validated through `fstat()` on the resulting
 *    descriptor — never by validating a pathname and reopening it,
 *  - the validated pathname and the opened descriptor proven to be the same
 *    object (`dev`/`ino` agreement), so the authority check cannot be satisfied
 *    by one file while a different one is read,
 *  - read at most `MAX_SIGNING_KEY_BYTES + 1` bytes, so an oversize file is
 *    established by the read itself rather than by a `stat()` that could lie,
 *  - the file's whole content constrained to exactly one PEM block of the
 *    expected label plus optional surrounding ASCII whitespace. Nothing else is
 *    tolerated, because `node:crypto` will happily extract a key out of a file
 *    that carries arbitrary text before and after the block,
 *  - algorithm fixed to Ed25519 by both the PEM label and
 *    `asymmetricKeyType`, with no negotiation and no fallback.
 *
 * Workspace isolation is evaluated on the same canonical, symlink-free identity
 * the file is actually opened through, so a symlink alias cannot make a key
 * inside a workspace merely *appear* to be outside one.
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

/** ASCII whitespace permitted before and after the one PEM block. */
const PEM_WHITESPACE_BYTES: ReadonlySet<number> = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]);

const PEM_BEGIN_PREFIX = '-----BEGIN ';
const PEM_END_PREFIX = '-----END ';

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

/* -------------------------------------------------------------------------- *
 * Canonical, symlink-free path authority
 * -------------------------------------------------------------------------- */

/**
 * Resolves a key path to the canonical location it is actually reached through,
 * refusing any symbolic link in any component.
 *
 * `O_NOFOLLOW` protects only the final component. A symlinked *parent* directory
 * is followed by the kernel exactly like a real directory, so `O_NOFOLLOW` alone
 * cannot establish where a key really lives — and the workspace rule is a
 * statement about location, not about the last path segment. Every component is
 * therefore inspected with `lstat` before the file is opened.
 *
 * The returned path is proven canonical twice over: no component is a symbolic
 * link, and the filesystem's own `realpath` agrees with it. The caller may use
 * it for policy comparisons, but must still bind it to the descriptor it opens —
 * a check on a pathname is not a check on a file.
 *
 * The error messages deliberately name no host path: a rejected key location
 * must not become a disclosure of the operator's filesystem layout.
 */
function resolveCanonicalKeyPath(filePath: string, label: string): string {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path is required`);
  }
  if (filePath.includes('~')) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path must not contain a literal ~`);
  }
  if (!path.isAbsolute(filePath)) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path must be absolute`);
  }

  const canonicalPath = path.normalize(filePath);
  if (
    canonicalPath !== filePath ||
    canonicalPath === path.sep ||
    canonicalPath.endsWith(path.sep) ||
    canonicalPath.split(path.sep).includes('..')
  ) {
    throw createCodedError(
      'AUDIT_KEY_PATH_INVALID',
      `${label} path must be canonical and free of traversal segments`,
    );
  }

  const segments = canonicalPath.split(path.sep);
  let current = '';
  for (let i = 1; i < segments.length; i++) {
    current += path.sep + segments[i];
    let stats: fs.Stats;
    try {
      stats = fs.lstatSync(current);
    } catch (cause: unknown) {
      const code = (cause as { code?: string } | null)?.code;
      if (code === 'ENOENT') {
        throw createCodedError('AUDIT_KEY_FILE_MISSING', `${label} does not exist`);
      }
      throw createCodedError(
        'AUDIT_KEY_FILE_UNAVAILABLE',
        `${label} could not be inspected safely`,
        { cause },
      );
    }
    if (stats.isSymbolicLink()) {
      throw createCodedError(
        'SYMLINK_DETECTED',
        `${label} path contains a symbolic link component`,
      );
    }
  }

  // Redundant with the walk above, and deliberately so: it is the filesystem's
  // own answer to "where does this path actually lead", and any disagreement
  // means the path is not the stable, canonical location the rules require.
  let realPath: string;
  try {
    realPath = fs.realpathSync(canonicalPath);
  } catch (cause: unknown) {
    const code = (cause as { code?: string } | null)?.code;
    if (code === 'ENOENT') {
      throw createCodedError('AUDIT_KEY_FILE_MISSING', `${label} does not exist`);
    }
    throw createCodedError('AUDIT_KEY_FILE_UNAVAILABLE', `${label} could not be resolved safely`, {
      cause,
    });
  }
  if (realPath !== canonicalPath) {
    throw createCodedError(
      'AUDIT_KEY_PATH_INVALID',
      `${label} path is not a stable canonical location`,
    );
  }

  return canonicalPath;
}

/**
 * Opens a canonical key path and proves the descriptor and the pathname are the
 * same object.
 *
 * The caller must close the returned descriptor. The `dev`/`ino` comparison is
 * what closes the window between "this path is authoritative" and "this is the
 * file being read": a pathname swapped for another regular file after the
 * authority check satisfies every pathname-level rule while handing back a
 * different inode.
 */
function openAuthoritativeKeyFile(
  canonicalPath: string,
  expectedUid: number,
  label: string,
): { fd: number; stats: fs.Stats } {
  let fd: number;
  try {
    fd = fs.openSync(canonicalPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
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

    let pathStats: fs.Stats;
    try {
      pathStats = fs.lstatSync(canonicalPath);
    } catch (cause: unknown) {
      throw createCodedError(
        'AUDIT_KEY_FILE_UNAVAILABLE',
        `${label} path could not be re-inspected after opening`,
        { cause },
      );
    }
    if (pathStats.isSymbolicLink()) {
      throw createCodedError('SYMLINK_DETECTED', `${label} is a symbolic link`);
    }
    if (
      Number(pathStats.dev) !== Number(stats.dev) ||
      Number(pathStats.ino) !== Number(stats.ino)
    ) {
      throw createCodedError(
        'AUDIT_KEY_PATH_INVALID',
        `${label} path does not identify the opened file`,
      );
    }

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

/** True when every byte in `[from, to)` is permitted surrounding whitespace. */
function isPemWhitespace(bytes: Buffer, from: number, to: number): boolean {
  for (let i = from; i < to; i++) {
    if (!PEM_WHITESPACE_BYTES.has(bytes[i])) return false;
  }
  return true;
}

/**
 * Requires the file to be exactly one PEM block of the expected label, plus
 * optional surrounding ASCII whitespace, and returns its byte span.
 *
 * Counting labels is not enough. `node:crypto` extracts a key from a PEM block
 * embedded in arbitrary text — an unrelated prefix, an unrelated suffix, or both
 * are all accepted, and two concatenated blocks are accepted by taking the
 * first. So "the file contains one `PUBLIC KEY` block" says nothing about what
 * else the file contains, and a file that carries an attacker-chosen preamble is
 * not the artifact the key authority rules describe.
 *
 * The whole file is therefore accounted for: exactly one `BEGIN`, exactly one
 * `END`, the expected label on both, and nothing but ASCII whitespace outside
 * the span. Only the span is handed to `node:crypto`, so even a future parser
 * that tolerated framing could not widen the accepted input.
 *
 * The check is byte-oriented so a private key is never materialized as a
 * long-lived immutable JavaScript string.
 */
function assertExactPemFile(
  bytes: Buffer,
  expectedLabel: string,
  label: string,
): { start: number; end: number } {
  const beginMarker = Buffer.from(`-----BEGIN ${expectedLabel}-----`, 'latin1');
  const endMarker = Buffer.from(`-----END ${expectedLabel}-----`, 'latin1');
  const anyBeginMarker = Buffer.from(PEM_BEGIN_PREFIX, 'latin1');
  const anyEndMarker = Buffer.from(PEM_END_PREFIX, 'latin1');

  const forbidden = (reason: string): never => {
    throw createCodedError('AUDIT_KEY_ENCODING_FORBIDDEN', `${label} ${reason}`);
  };

  const begin = bytes.indexOf(beginMarker);
  if (begin === -1) {
    forbidden(`must be exactly one ${expectedLabel} PEM block`);
  }

  // Exactly one BEGIN in the whole file, and it is ours. A BEGIN of another
  // label before ours shifts the first match; one after ours is a second block.
  if (bytes.indexOf(anyBeginMarker) !== begin) {
    forbidden('must contain no PEM block other than its own');
  }
  if (bytes.indexOf(anyBeginMarker, begin + beginMarker.length) !== -1) {
    forbidden('must contain exactly one PEM block');
  }

  const end = bytes.indexOf(endMarker, begin + beginMarker.length);
  if (end === -1) {
    forbidden(`is a truncated ${expectedLabel} PEM block`);
  }
  if (bytes.indexOf(anyEndMarker) !== end) {
    forbidden('must contain no PEM end marker other than its own');
  }
  if (bytes.indexOf(anyEndMarker, end + endMarker.length) !== -1) {
    forbidden('must contain exactly one PEM block');
  }

  if (!isPemWhitespace(bytes, 0, begin)) {
    forbidden(`${expectedLabel} PEM block must not be preceded by other content`);
  }
  if (!isPemWhitespace(bytes, end + endMarker.length, bytes.length)) {
    forbidden(`${expectedLabel} PEM block must not be followed by other content`);
  }

  return { start: begin, end: end + endMarker.length };
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

  const canonicalPath = resolveCanonicalKeyPath(filePath, label);
  const { fd } = openAuthoritativeKeyFile(canonicalPath, expectedUid, label);
  try {
    const { buffer, byteLength } = readBoundedKeyBytes(fd, label);
    const view = buffer.subarray(0, byteLength);
    const span = assertExactPemFile(view, PUBLIC_KEY_PEM_LABEL, label);

    let publicKey: crypto.KeyObject;
    try {
      publicKey = crypto.createPublicKey({
        key: view.subarray(span.start, span.end),
        format: 'pem',
      });
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
  options: { expectedUid?: number; workspacePaths?: readonly string[] } = {},
): LoadedSigningKey {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = 'signing key';
  const workspacePaths = options.workspacePaths ?? [];

  // Canonicalize, then establish workspace non-overlap, then open, then bind the
  // descriptor to the validated path — and only then read key bytes. The
  // ordering is enforced here rather than left to the caller, so no code path
  // can consume a private key before the workspace rule has been applied to the
  // location it actually came from.
  const canonicalPath = resolveCanonicalKeyPath(filePath, label);
  assertCanonicalOutsideWorkspaces(canonicalPath, workspacePaths);

  const { fd } = openAuthoritativeKeyFile(canonicalPath, expectedUid, label);
  try {
    const { buffer, byteLength } = readBoundedKeyBytes(fd, label);
    try {
      if (privateKeyLoadProbeEnabled) {
        privateKeyLoadCount++;
      }

      const view = buffer.subarray(0, byteLength);
      const span = assertExactPemFile(view, PRIVATE_KEY_PEM_LABEL, label);

      let privateKey: crypto.KeyObject;
      try {
        privateKey = crypto.createPrivateKey({
          key: view.subarray(span.start, span.end),
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
  const canonicalKeyPath = resolveCanonicalKeyPath(signingKeyPath, 'signing key');
  assertCanonicalOutsideWorkspaces(canonicalKeyPath, workspacePaths);
}

/**
 * Compares two already-canonical locations.
 *
 * Both sides are canonical filesystem locations, which is what makes the
 * comparison a statement about where the key really is. Comparing lexical paths
 * would let a symlinked alias make a key inside a workspace look like a key
 * outside one — the containment test would pass on the alias while the
 * filesystem resolved it straight back into the workspace.
 *
 * A workspace that cannot be resolved is compared at its lexical location: an
 * unresolvable workspace boundary cannot be shown to contain anything, and
 * failing the whole load because an unrelated workspace is absent would make the
 * rule unusable without making it safer.
 */
function assertCanonicalOutsideWorkspaces(
  canonicalKeyPath: string,
  workspacePaths: readonly string[],
): void {
  for (const workspacePath of workspacePaths) {
    let workspace: string;
    try {
      workspace = fs.realpathSync(workspacePath);
    } catch {
      workspace = path.resolve(workspacePath);
    }

    if (
      canonicalKeyPath === workspace ||
      canonicalKeyPath.startsWith(workspace + path.sep) ||
      workspace.startsWith(canonicalKeyPath + path.sep)
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
