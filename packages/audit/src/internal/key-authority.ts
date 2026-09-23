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
 *    component: an `O_NOFOLLOW` final open still follows a symlinked *parent*, so
 *    a path such as `/safe/keys-link/signing.pem` reaches whatever
 *    `/safe/keys-link` points at while the final component stays a regular file,
 *  - **traversed by descriptor, not by pathname**. Every component is opened
 *    relative to the descriptor of the directory already proven to contain it —
 *    the parent is never re-resolved from its path — so a parent directory
 *    replaced *after* it was checked cannot redirect the walk. Node has no
 *    `openat(2)`, but Linux exposes open descriptors under `/proc/self/fd`, and
 *    opening `<bridge>/<parentFd>/<component>` is exactly that call. A host
 *    without the bridge refuses with `AUDIT_PLATFORM_UNSUPPORTED` rather than
 *    falling back to the pathname validation this replaced,
 *  - each directory component validated through `fstat()` on its own descriptor
 *    and retained until the next component has been opened through it,
 *  - the final descriptor's location taken from the kernel's own answer for that
 *    descriptor, so "the key is at this path" and "this is the file being read"
 *    are one fact rather than two checks a race can separate,
 *  - read at most `MAX_SIGNING_KEY_BYTES + 1` bytes, so an oversize file is
 *    established by the read itself rather than by a `stat()` that could lie,
 *  - the file's whole content constrained to exactly one PEM block of the
 *    expected label plus optional surrounding ASCII whitespace. Nothing else is
 *    tolerated, because `node:crypto` will happily extract a key out of a file
 *    that carries arbitrary text before and after the block,
 *  - algorithm fixed to Ed25519 by both the PEM label and
 *    `asymmetricKeyType`, with no negotiation and no fallback.
 *
 * Workspace isolation is evaluated on the location of the descriptor that is
 * about to be read, against workspace boundaries resolved by the same pinned
 * walk, so a symlink alias cannot make a key inside a workspace merely *appear*
 * to be outside one — and no private key byte is consumed before that decision
 * has been made.
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
import { createCodedError, type CodedError } from './errors.js';
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
 * Descriptor-pinned, symlink-free path authority
 * -------------------------------------------------------------------------- */

/**
 * The descriptor bridge used to open a child relative to an already-open parent.
 *
 * Node exposes no `openat(2)`, but Linux exposes every open descriptor here, and
 * opening `<bridge>/<parentFd>/<component>` is an `openat(parentFd, component)`:
 * the resolution of `component` happens relative to the *descriptor*, never
 * relative to a pathname that could have been replaced in the meantime.
 */
const PROC_SELF_FD = '/proc/self/fd';

/** Kernel suffix reported for a descriptor whose file is no longer linked. */
const DELETED_SUFFIX = ' (deleted)';

/**
 * Proves the host can traverse by descriptor rather than by pathname.
 *
 * Checking a pathname and then opening it is not a security boundary: a parent
 * directory can be replaced by a symbolic link in between, and the kernel
 * follows a symlinked *parent* exactly like a real directory, so `O_NOFOLLOW`
 * on the final component proves nothing about where the file came from. The
 * remedy is to open each component relative to the descriptor of a directory
 * that was already proven — which is only possible through this bridge.
 *
 * When the bridge is absent the loader refuses rather than silently falling
 * back to the pathname-only validation it exists to replace.
 */
function assertDescriptorPinnedTraversalAvailable(): void {
  const unsupported = (cause?: unknown): CodedError =>
    createCodedError(
      'AUDIT_PLATFORM_UNSUPPORTED',
      'host platform lacks the descriptor-pinned path traversal required for key authority',
      cause === undefined ? undefined : { cause },
    );

  if (process.platform !== 'linux') {
    throw unsupported();
  }

  let probe: number | null = null;
  try {
    probe = fs.openSync(PROC_SELF_FD, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  } catch (cause) {
    throw unsupported(cause);
  } finally {
    if (probe !== null) {
      fs.closeSync(probe);
    }
  }
}

/**
 * Validates the *shape* of a configured key path, lexically only.
 *
 * This decides nothing about authority. It exists so the component walk below
 * has a well-defined, absolute, traversal-free path to walk; every statement
 * about where the file actually is comes from the descriptors that walk yields.
 *
 * The error messages deliberately name no host path: a rejected key location
 * must not become a disclosure of the operator's filesystem layout.
 */
function assertKeyPathShape(filePath: string, label: string): string {
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

  return canonicalPath;
}

/** The path components of a canonical absolute path, outermost first. */
function pathComponents(canonicalPath: string, label: string): string[] {
  const components = canonicalPath.split(path.sep).filter((segment) => segment.length > 0);
  for (const component of components) {
    if (component === '.' || component === '' || component.includes('\0')) {
      throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path contains an invalid segment`);
    }
  }
  return components;
}

/**
 * Classifies one component of a pinned parent without following it.
 *
 * Used only to choose an error code. `lstat` through `/proc/self/fd` never
 * dereferences the component, so a symlink is observed as a symlink. A component
 * that cannot be examined at all is reported as "not a symbolic link", which
 * sends the caller down the `ENOENT` / not-a-directory branch rather than
 * inventing a symlink finding it did not observe.
 */
function pinnedComponentIsSymlink(parentFd: number, component: string): boolean {
  try {
    return fs.lstatSync(`${PROC_SELF_FD}/${parentFd}/${component}`).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Turns a failed pinned open into the bounded error that describes it.
 *
 * A symbolic link is reported as `ENOTDIR` once `O_DIRECTORY` is in play, so the
 * component is classified with a non-following `lstat` through the *same* pinned
 * parent. That classification chooses the error text only — it is never the
 * authority, which is the descriptor this function failed to produce.
 */
function pinnedOpenError(
  parentFd: number,
  component: string,
  cause: unknown,
  label: string,
): CodedError {
  const code = (cause as { code?: string } | null)?.code;

  if (code === 'ELOOP' || code === 'ENOENT' || code === 'ENOTDIR') {
    if (pinnedComponentIsSymlink(parentFd, component)) {
      return createCodedError(
        'SYMLINK_DETECTED',
        `${label} path contains a symbolic link component`,
      );
    }
    if (code === 'ENOENT') {
      return createCodedError('AUDIT_KEY_FILE_MISSING', `${label} does not exist`);
    }
    return createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path component is not a directory`);
  }

  return createCodedError('AUDIT_KEY_FILE_UNAVAILABLE', `${label} could not be opened safely`, {
    cause,
  });
}

/** Opens one path component relative to an already-authoritative parent. */
function openPinnedComponent(
  parentFd: number,
  component: string,
  directory: boolean,
  label: string,
): number {
  const flags = directory
    ? fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
    : fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW;

  try {
    return fs.openSync(`${PROC_SELF_FD}/${parentFd}/${component}`, flags);
  } catch (cause) {
    throw pinnedOpenError(parentFd, component, cause, label);
  }
}

/**
 * Opens a key file by walking its path one descriptor at a time.
 *
 * Each intermediate component is opened relative to the descriptor of the
 * directory already proven to contain it, with `O_NOFOLLOW` so a symbolic link
 * is refused rather than followed, and `O_DIRECTORY` so a non-directory cannot
 * stand in for one. The directory descriptor is then validated by `fstat` —
 * never by a pathname — and retained until the next component has been opened
 * through it, so no step of the walk can be redirected after the fact.
 *
 * Directory descriptors are released as soon as the key descriptor exists. The
 * caller owns the returned descriptor.
 *
 * `beforeFinalOpen` runs after the parent chain is pinned and immediately before
 * the final component is opened. It exists so a test can attempt to substitute a
 * parent *pathname* in exactly that window; it cannot redirect the walk, because
 * the walk no longer reads a pathname.
 */
function openDescriptorPinnedKeyFile(
  canonicalPath: string,
  label: string,
  beforeFinalOpen?: () => void,
): number {
  assertDescriptorPinnedTraversalAvailable();

  const components = pathComponents(canonicalPath, label);
  if (components.length === 0) {
    throw createCodedError('AUDIT_KEY_PATH_INVALID', `${label} path names no file`);
  }

  const directoryFds: number[] = [];
  let keyFd: number | null = null;

  try {
    const rootFd = fs.openSync(
      path.sep,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    directoryFds.push(rootFd);

    let parentFd = rootFd;
    for (let i = 0; i < components.length - 1; i++) {
      const directoryFd = openPinnedComponent(parentFd, components[i], true, label);

      let stats: fs.Stats;
      try {
        stats = fs.fstatSync(directoryFd);
      } catch (cause) {
        fs.closeSync(directoryFd);
        throw createCodedError(
          'AUDIT_KEY_FILE_UNAVAILABLE',
          `${label} directory could not be validated`,
          { cause },
        );
      }
      if (!stats.isDirectory()) {
        fs.closeSync(directoryFd);
        throw createCodedError(
          'AUDIT_KEY_PATH_INVALID',
          `${label} path component is not a directory`,
        );
      }

      directoryFds.push(directoryFd);
      parentFd = directoryFd;
    }

    beforeFinalOpen?.();
    keyFd = openPinnedComponent(parentFd, components[components.length - 1], false, label);
    return keyFd;
  } catch (err) {
    if (keyFd !== null) {
      fs.closeSync(keyFd);
    }
    throw err;
  } finally {
    for (const directoryFd of directoryFds) {
      fs.closeSync(directoryFd);
    }
  }
}

/**
 * The kernel's own answer for the location a descriptor names.
 *
 * This is the step that turns the pinned walk into a statement about *the opened
 * file*: the workspace rule is decided against where this descriptor actually
 * lives, not against the pathname that was configured. A descriptor whose file
 * has been unlinked still resolves here, with a kernel suffix, and is refused —
 * a key that is no longer linked into the filesystem is not the file the
 * configured path names.
 */
function descriptorLocation(fd: number, label: string): string {
  let target: string;
  try {
    target = fs.readlinkSync(`${PROC_SELF_FD}/${fd}`);
  } catch (cause) {
    throw createCodedError('AUDIT_KEY_FILE_UNAVAILABLE', `${label} location could not be read`, {
      cause,
    });
  }

  if (target.endsWith(DELETED_SUFFIX)) {
    throw createCodedError(
      'AUDIT_KEY_FILE_UNAVAILABLE',
      `${label} is no longer linked into the filesystem`,
    );
  }

  return target;
}

/**
 * Establishes the authoritative key descriptor and the location it names.
 *
 * The caller must close the returned descriptor. The location is derived from
 * the descriptor itself, so "the key is at this path" and "this is the file
 * being read" are the same fact rather than two checks that a race can separate.
 */
function openAuthoritativeKeyFile(
  canonicalPath: string,
  expectedUid: number,
  label: string,
  beforeFinalOpen?: () => void,
): { fd: number; location: string } {
  const fd = openDescriptorPinnedKeyFile(canonicalPath, label, beforeFinalOpen);

  try {
    const location = descriptorLocation(fd, label);
    if (location !== canonicalPath) {
      throw createCodedError(
        'AUDIT_KEY_PATH_INVALID',
        `${label} path does not identify the opened file`,
      );
    }

    // fstat on the descriptor: regular file, mode exactly 0600, real UID,
    // nlink 1. A symlink never reaches here because every component was opened
    // with O_NOFOLLOW.
    validateFileDescriptorAuthority(fd, 0o600, expectedUid);

    return { fd, location };
  } catch (err) {
    fs.closeSync(fd);
    throw err;
  }
}

/* -------------------------------------------------------------------------- *
 * Workspace isolation on canonical filesystem identity
 * -------------------------------------------------------------------------- */

/**
 * A workspace boundary as resolved for comparison: either the descriptor-pinned
 * location it really names, or the canonical spelling of a boundary that does
 * not exist at all.
 */
type CanonicalWorkspace = { kind: 'PINNED' | 'ABSENT'; location: string };

/** The one bounded error for "workspace isolation could not be established". */
function workspaceAuthorityError(): CodedError {
  return createCodedError(
    'AUDIT_SIGNING_KEY_WORKSPACE_OVERLAP',
    'the signing key workspace isolation rule could not be satisfied',
  );
}

/**
 * Resolves an authenticated workspace boundary to the location it really names.
 *
 * A workspace is an authenticated input, so it is resolved by the same
 * descriptor-pinned walk the key path uses: a boundary reached through a symlink
 * could otherwise make a key inside it look like a key outside it, which is
 * exactly the comparison this rule exists to make.
 *
 * A boundary that does not exist contains nothing — no existing path lies
 * beneath a directory that is not there — so it is resolved as absent instead of
 * refusing the load. A boundary that exists but cannot be pinned refuses: falling
 * back to its lexical spelling would silently downgrade the comparison.
 */
function canonicalizeWorkspacePath(workspacePath: string): CanonicalWorkspace {
  if (typeof workspacePath !== 'string' || workspacePath.length === 0) {
    throw workspaceAuthorityError();
  }

  const canonicalPath = path.normalize(workspacePath);
  if (
    !path.isAbsolute(workspacePath) ||
    canonicalPath !== workspacePath ||
    canonicalPath === path.sep ||
    canonicalPath.endsWith(path.sep)
  ) {
    throw workspaceAuthorityError();
  }

  const components = canonicalPath.split(path.sep).filter((segment) => segment.length > 0);
  if (components.length === 0 || components.includes('..') || components.includes('.')) {
    throw workspaceAuthorityError();
  }

  assertDescriptorPinnedTraversalAvailable();

  const directoryFds: number[] = [];
  try {
    const rootFd = fs.openSync(
      path.sep,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
    );
    directoryFds.push(rootFd);

    let parentFd = rootFd;
    for (const component of components) {
      let directoryFd: number;
      try {
        directoryFd = openPinnedComponent(parentFd, component, true, 'workspace');
      } catch (cause) {
        if ((cause as { code?: string } | null)?.code === 'AUDIT_KEY_FILE_MISSING') {
          return { kind: 'ABSENT', location: canonicalPath };
        }
        throw workspaceAuthorityError();
      }

      let stats: fs.Stats;
      try {
        stats = fs.fstatSync(directoryFd);
      } catch {
        fs.closeSync(directoryFd);
        throw workspaceAuthorityError();
      }
      if (!stats.isDirectory()) {
        fs.closeSync(directoryFd);
        throw workspaceAuthorityError();
      }

      directoryFds.push(directoryFd);
      parentFd = directoryFd;
    }

    return { kind: 'PINNED', location: canonicalPath };
  } finally {
    for (const directoryFd of directoryFds) {
      fs.closeSync(directoryFd);
    }
  }
}

/**
 * Applies the frozen containment rule to a key's actual opened location.
 *
 * Both sides are real filesystem locations, which is what makes this a statement
 * about where the key is rather than about how its path was spelled. The three
 * frozen relations are refused: the key equals a workspace, lies beneath one, or
 * contains one.
 */
function assertLocationOutsideWorkspaces(
  location: string,
  workspacePaths: readonly string[],
): void {
  for (const workspacePath of workspacePaths) {
    const workspace = canonicalizeWorkspacePath(workspacePath);
    if (
      location === workspace.location ||
      location.startsWith(workspace.location + path.sep) ||
      workspace.location.startsWith(location + path.sep)
    ) {
      throw workspaceAuthorityError();
    }
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
/**
 * Loads, validates and fingerprints an Ed25519 public trust root from an open descriptor.
 *
 * Validates descriptor authority (mode 0600, expectedUid, regular file, nlink 1),
 * bounds file size, asserts exact PEM format with no surrounding content, and requires
 * Ed25519 algorithm. Does NOT close fd; caller owns fd.
 */
export function loadEd25519TrustRootFromDescriptor(
  fd: number,
  options: { purpose: TrustRootPurpose; expectedUid?: number },
): LoadedTrustRoot {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = options.purpose === 'ANCHOR_RECEIPT' ? 'anchor receipt public key' : 'public key';

  validateFileDescriptorAuthority(fd, 0o600, expectedUid);
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
}

export function loadEd25519TrustRootFile(
  filePath: string,
  options: { purpose: TrustRootPurpose; expectedUid?: number },
): LoadedTrustRoot {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = options.purpose === 'ANCHOR_RECEIPT' ? 'anchor receipt public key' : 'public key';

  const canonicalPath = assertKeyPathShape(filePath, label);
  const { fd } = openAuthoritativeKeyFile(canonicalPath, expectedUid, label);
  try {
    return loadEd25519TrustRootFromDescriptor(fd, options);
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
 *
 * The ordering below is the authority rule, and it is enforced here rather than
 * left to each caller:
 *
 * ```text
 * validate the path's shape
 * → descriptor-pinned walk to an authoritative key descriptor
 * → the location that descriptor actually names
 * → workspace non-overlap against authenticated boundaries
 * → only then read private PEM bytes
 * ```
 *
 * Nothing is decided from a pathname that could be replaced between the check
 * and the open, and no private key byte is consumed before workspace isolation
 * has been settled about the file that was really opened.
 *
 * `beforeFinalKeyOpen` is a deterministic race seam for the test suite. It runs
 * after the parent chain has been pinned and immediately before the final
 * component is opened. It cannot widen authority: the walk it interrupts no
 * longer consults a pathname, and the workspace decision still runs after it.
 */
export function loadEd25519SigningKeyFile(
  filePath: string,
  options: {
    expectedUid?: number;
    workspacePaths?: readonly string[];
    beforeFinalKeyOpen?: () => void;
  } = {},
): LoadedSigningKey {
  const expectedUid = options.expectedUid ?? getProcessUid();
  const label = 'signing key';
  const workspacePaths = options.workspacePaths ?? [];

  const canonicalPath = assertKeyPathShape(filePath, label);
  const { fd, location } = openAuthoritativeKeyFile(
    canonicalPath,
    expectedUid,
    label,
    options.beforeFinalKeyOpen,
  );
  try {
    assertLocationOutsideWorkspaces(location, workspacePaths);

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
 * This is an *earlier* check than the one {@link loadEd25519SigningKeyFile}
 * performs, and it is defense in depth rather than the boundary: a caller that
 * validates here and then loads separately leaves a window between the two. The
 * loader is the boundary, because it decides against the descriptor it is about
 * to read.
 *
 * The message names no path: an operator gets the rule, and no absolute host
 * path is echoed into a log.
 */
export function assertSigningKeyOutsideWorkspaces(
  signingKeyPath: string,
  workspacePaths: readonly string[],
): void {
  const canonicalKeyPath = assertKeyPathShape(signingKeyPath, 'signing key');
  const fd = openDescriptorPinnedKeyFile(canonicalKeyPath, 'signing key');
  try {
    assertLocationOutsideWorkspaces(descriptorLocation(fd, 'signing key'), workspacePaths);
  } finally {
    fs.closeSync(fd);
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
