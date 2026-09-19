/**
 * CesSpace ARC — RC-05 Task 3 Remote Gateway Configuration
 *
 * Bounded, trusted configuration for the TLS 1.3 / mTLS admission listener.
 * Authoritative contract: docs/architecture/rc05-scope-acceptance.md §5, §6, §18.
 *
 * Validation here is STARTUP validation: every rejection is a hard failure and
 * leaves no listener, no socket, and no partially active gateway.
 *
 * The configuration deliberately contains only SELECTORS — hosts, ports, and
 * file paths. It can never carry private-key or certificate BYTES: §17 K-4/K-7
 * forbid private-key material in argv, environment values, configuration
 * strings, or source defaults.
 */

import net from 'node:net';
import { RemoteConfigError, type RemoteFailureReason } from './remote-errors.js';

/** Default bind host: loopback only (§5). */
export const DEFAULT_REMOTE_BIND_HOST = '127.0.0.1';

/** Frozen maximum number of client CA trust roots (§6 T-11). */
export const MAX_CLIENT_CA_ROOTS = 4;

/** Frozen maximum size of a single client CA file, in bytes (§6 T-11). */
export const MAX_CLIENT_CA_BYTES = 64 * 1024;

/**
 * Frozen TLS handshake timeout, in milliseconds (§20).
 *
 * This is a SECURITY value and is deliberately NOT configurable on the
 * production surface: it may only be shortened through the internal test seam
 * on RemoteGatewayOptions.
 */
export const TLS_HANDSHAKE_TIMEOUT_MS = 5000;

/**
 * Conservative DNS hostname grammar.
 *
 * Hostnames are supported, but only this shape is: dot-separated labels of
 * letters, digits and hyphens, 1-63 characters each, no leading or trailing
 * hyphen, at most 253 characters total.
 */
const HOSTNAME_LABEL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

/**
 * Characters that can only appear in a numeric address.
 *
 * A value made only of these characters is an address ATTEMPT. If it is not a
 * valid address it is rejected rather than reinterpreted as a hostname, because
 * such strings are ambiguous (`1.2.3`, `999.1.1.1`) and letting the platform
 * resolve them is exactly the ambiguity §18 forbids.
 */
const ADDRESS_ATTEMPT_REGEX = /^[0-9a-fA-F:.]+$/;

/**
 * Expands an IPv6 literal to its eight 16-bit groups.
 *
 * Handles `::` compression and an embedded IPv4 suffix. Returns undefined when
 * the literal is not a well-formed IPv6 address.
 */
function expandIpv6(address: string): number[] | undefined {
  let working = address;

  // An IPv4-mapped or IPv4-embedded suffix becomes two hextets.
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4 = working.slice(lastColon + 1);
    if (net.isIP(v4) !== 4) {
      return undefined;
    }
    const octets = v4.split('.').map((part) => Number.parseInt(part, 10));
    const high = ((octets[0] as number) << 8) | (octets[1] as number);
    const low = ((octets[2] as number) << 8) | (octets[3] as number);
    working = `${working.slice(0, lastColon)}:${high.toString(16)}:${low.toString(16)}`;
  }

  const doubleColonCount = working.split('::').length - 1;
  if (doubleColonCount > 1) {
    return undefined;
  }

  let groups: string[];
  if (doubleColonCount === 1) {
    const [head, tail] = working.split('::');
    const headGroups = head === '' ? [] : head.split(':');
    const tailGroups = tail === '' ? [] : tail.split(':');
    const missing = 8 - headGroups.length - tailGroups.length;
    if (missing < 1) {
      return undefined;
    }
    groups = [...headGroups, ...Array<string>(missing).fill('0'), ...tailGroups];
  } else {
    groups = working.split(':');
  }

  if (groups.length !== 8) {
    return undefined;
  }
  const parsed: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      return undefined;
    }
    parsed.push(Number.parseInt(group, 16));
  }
  return parsed;
}

/**
 * True when the literal is the IPv6 unspecified address (`::`) in ANY spelling.
 *
 * Detection is semantic: every syntactic form that expands to eight zero groups
 * is recognised, including the fully expanded
 * `0000:0000:0000:0000:0000:0000:0000:0000`. A spelling list cannot do this.
 */
export function isIpv6Unspecified(address: string): boolean {
  const groups = expandIpv6(address);
  if (groups === undefined) {
    return false;
  }
  return groups.every((group) => group === 0);
}

/**
 * True when the literal denotes an IPv4 unspecified address, including the
 * IPv4-mapped IPv6 form `::ffff:0.0.0.0`.
 */
export function isIpv4Unspecified(address: string): boolean {
  if (net.isIP(address) === 4) {
    return address === '0.0.0.0';
  }
  const groups = expandIpv6(address);
  if (groups === undefined) {
    return false;
  }
  // ::ffff:a.b.c.d  ->  first five groups zero, sixth 0xffff, last two = octets
  const mappedPrefix = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  return mappedPrefix && groups[6] === 0 && groups[7] === 0;
}

/**
 * How a server private key reaches the process.
 *
 * Both forms are approved by §17 K-6. Raw key material is not representable.
 */
export type PrivateKeySource = { kind: 'file'; path: string } | { kind: 'fd'; fd: number };

/**
 * Bounded remote gateway configuration.
 *
 * This is PRODUCTION configuration and carries trusted selectors only: hosts,
 * ports, and file paths. It deliberately exposes no testing seams — no wall
 * clock, no handshake-timeout override, and no limiter override. Those live
 * solely on the internal RemoteGatewayOptions seam, so no configuration file or
 * environment value can weaken a frozen security value.
 */
export interface RemoteConfig {
  /** Bind host. Defaults to loopback. */
  bindHost?: string;
  /** Explicit TCP port. Required. */
  port: number;
  /**
   * Public hostname this gateway is reached by. Used for server-certificate
   * SAN validation (§6 T-5) and, later, for client-side hostname verification.
   */
  publicHostname: string;
  /** Server certificate chain, as a validated file path (PEM). */
  serverCertificatePath: string;
  /** Server private-key source. Never raw bytes. */
  privateKey: PrivateKeySource;
  /** Client CA trust roots. At least one, at most {@link MAX_CLIENT_CA_ROOTS}. */
  clientCaPaths: readonly string[];
  /** Explicit opt-in required before a wildcard bind is permitted (§18). */
  allowWildcardBind?: boolean;
  /**
   * Device trust-store path. REQUIRED in remote mode.
   *
   * Remote mode performs durable device activation, so it needs an explicit
   * persistent authentication root: there is no implicit path, no in-memory
   * fallback, and no silently created empty store. A store that exists and is
   * valid but holds zero devices is allowed — that is the first-enrollment case.
   */
  trustStorePath: string;
}

/** Fully resolved, validated remote configuration. */
export interface ResolvedRemoteConfig {
  readonly bindHost: string;
  readonly port: number;
  readonly publicHostname: string;
  readonly serverCertificatePath: string;
  readonly privateKey: PrivateKeySource;
  readonly clientCaPaths: readonly string[];
  readonly trustStorePath: string;
}

/**
 * True when the host is a wildcard address that exposes the listener beyond the
 * local host.
 *
 * Detection is SEMANTIC, not a spelling list: the IPv6 unspecified address has
 * many syntactically valid spellings that all bind identically, so the address
 * is parsed and its groups examined instead of being string-matched.
 */
export function isWildcardBindHost(host: string): boolean {
  if (net.isIP(host) === 0) {
    return false;
  }
  return isIpv6Unspecified(host) || isIpv4Unspecified(host);
}

/**
 * Validates a bind host.
 *
 * Only literal IPv4/IPv6 addresses and DNS hostnames are accepted. A value that
 * could be interpreted as an interface name, a protocol prefix, a URL, or an
 * empty string is rejected rather than silently resolved by the platform.
 */
function validateBindHost(host: unknown): string {
  if (host === undefined) {
    return DEFAULT_REMOTE_BIND_HOST;
  }
  if (typeof host !== 'string' || host.length === 0) {
    throw new RemoteConfigError(
      'Remote bind host must be a non-empty string.',
      'BIND_HOST_INVALID',
    );
  }
  if (host !== host.trim() || host.includes('\u0000') || host.includes('/')) {
    throw new RemoteConfigError(
      'Remote bind host must be a literal address or hostname.',
      'BIND_HOST_INVALID',
    );
  }
  if (host.includes('://') || host.includes(' ')) {
    throw new RemoteConfigError(
      'Remote bind host must not be a URL or contain whitespace.',
      'BIND_HOST_INVALID',
    );
  }
  if (host.length > 253) {
    throw new RemoteConfigError('Remote bind host is too long.', 'BIND_HOST_INVALID');
  }

  // Strip the brackets an IPv6 literal may be written with.
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (bare.length === 0) {
    throw new RemoteConfigError('Remote bind host must not be empty.', 'BIND_HOST_INVALID');
  }

  if (net.isIP(bare) !== 0) {
    return bare;
  }

  // An address-shaped string that is not a valid address is ambiguous: reject it
  // rather than letting the platform resolve it into something else.
  if (ADDRESS_ATTEMPT_REGEX.test(bare)) {
    throw new RemoteConfigError('Remote bind host is not a valid IP address.', 'BIND_HOST_INVALID');
  }

  // Otherwise it must satisfy the conservative hostname grammar.
  for (const label of bare.split('.')) {
    if (!HOSTNAME_LABEL_REGEX.test(label)) {
      throw new RemoteConfigError(
        'Remote bind host is not a valid address or hostname.',
        'BIND_HOST_INVALID',
      );
    }
  }
  return bare;
}

/** Validates an explicit TCP port. No default, no service-name resolution. */
function validatePort(port: unknown): number {
  if (typeof port !== 'number' || !Number.isInteger(port)) {
    throw new RemoteConfigError(
      'Remote port must be an explicit integer TCP port.',
      'PORT_INVALID',
    );
  }
  if (port < 1 || port > 65535) {
    throw new RemoteConfigError('Remote port must be between 1 and 65535.', 'PORT_INVALID');
  }
  return port;
}

/**
 * Validates the configured public hostname used for SAN comparison.
 *
 * DNS names and IP literals are both permitted; the platform X.509 checker is
 * used for the actual comparison, so this only rejects values that could not be
 * a hostname or IP at all.
 */
function validatePublicHostname(hostname: unknown): string {
  if (typeof hostname !== 'string' || hostname.trim().length === 0) {
    throw new RemoteConfigError(
      'Remote mode requires an explicit public hostname for SAN validation.',
      'PUBLIC_HOSTNAME_INVALID',
    );
  }
  if (hostname !== hostname.trim() || hostname.includes('\u0000') || hostname.includes('/')) {
    throw new RemoteConfigError('Public hostname is malformed.', 'PUBLIC_HOSTNAME_INVALID');
  }
  if (hostname.includes('://') || hostname.includes(' ')) {
    throw new RemoteConfigError('Public hostname is malformed.', 'PUBLIC_HOSTNAME_INVALID');
  }
  return hostname;
}

function validatePath(value: unknown, label: string, reason: RemoteFailureReason): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RemoteConfigError(`${label} must be a non-empty file path.`, reason);
  }
  if (value.includes('\u0000')) {
    throw new RemoteConfigError(`${label} must not contain NUL.`, reason);
  }
  return value;
}

/**
 * Resolves and validates remote configuration.
 *
 * Every check here happens BEFORE any listener is created, so a rejected
 * configuration cannot leave a partially bound server behind.
 */
export function resolveRemoteConfig(config: RemoteConfig): ResolvedRemoteConfig {
  if (config === null || typeof config !== 'object') {
    throw new RemoteConfigError('Remote configuration is required.', 'REMOTE_CONFIG_MISSING');
  }

  const bindHost = validateBindHost(config.bindHost);
  const port = validatePort(config.port);
  const publicHostname = validatePublicHostname(config.publicHostname);

  if (isWildcardBindHost(bindHost) && config.allowWildcardBind !== true) {
    throw new RemoteConfigError(
      'Refusing to bind a wildcard address without an explicit opt-in.',
      'WILDCARD_BIND_NOT_OPTED_IN',
    );
  }

  const serverCertificatePath = validatePath(
    config.serverCertificatePath,
    'Server certificate path',
    'SERVER_CERTIFICATE_INVALID',
  );

  const privateKey = config.privateKey;
  if (privateKey === null || typeof privateKey !== 'object') {
    throw new RemoteConfigError(
      'Remote mode requires a server private-key source.',
      'PRIVATE_KEY_SOURCE_INVALID',
    );
  }
  if (privateKey.kind === 'file') {
    validatePath(privateKey.path, 'Private-key path', 'PRIVATE_KEY_SOURCE_INVALID');
  } else if (privateKey.kind === 'fd') {
    if (!Number.isInteger(privateKey.fd) || privateKey.fd < 0) {
      throw new RemoteConfigError(
        'Private-key file descriptor must be a non-negative integer.',
        'PRIVATE_KEY_SOURCE_INVALID',
      );
    }
  } else {
    throw new RemoteConfigError(
      'Private-key source must be a validated file path or an inherited file descriptor.',
      'PRIVATE_KEY_SOURCE_INVALID',
    );
  }

  const clientCaPaths = config.clientCaPaths;
  if (!Array.isArray(clientCaPaths) || clientCaPaths.length === 0) {
    // mTLS without a trust root would either reject every client or accept any
    // client. Neither is acceptable, so an empty set fails startup (§18).
    throw new RemoteConfigError(
      'Remote mode requires at least one client CA trust root.',
      'CLIENT_CA_EMPTY',
    );
  }
  if (clientCaPaths.length > MAX_CLIENT_CA_ROOTS) {
    throw new RemoteConfigError(
      `At most ${MAX_CLIENT_CA_ROOTS} client CA roots may be configured.`,
      'CLIENT_CA_TOO_MANY',
    );
  }
  const seenCaPaths = new Set<string>();
  for (const caPath of clientCaPaths) {
    const resolved = validatePath(caPath, 'Client CA path', 'CLIENT_CA_PATH_INVALID');
    if (seenCaPaths.has(resolved)) {
      throw new RemoteConfigError('Duplicate client CA path.', 'CLIENT_CA_PATH_INVALID');
    }
    seenCaPaths.add(resolved);
  }

  // Required, not optional: remote mode has a durable authentication root or it
  // does not start.
  const trustStorePath = validatePath(
    config.trustStorePath,
    'Trust-store path',
    'TRUST_STORE_PATH_INVALID',
  );

  return {
    bindHost,
    port,
    publicHostname,
    serverCertificatePath,
    privateKey,
    clientCaPaths: [...clientCaPaths],
    trustStorePath,
  };
}
