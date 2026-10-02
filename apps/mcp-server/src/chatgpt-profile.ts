/**
 * CesSpace ARC — ChatGPT Remote Integration Profile
 *
 * Dedicated, opt-in integration profile for ChatGPT-compatible remote MCP
 * connections over private tunnels or reverse proxies.
 *
 * Invariant:
 * - Disabled by default.
 * - No listener starts unless explicitly configured.
 * - No secrets accepted via argv or stored in config; tokens reside in restricted files.
 * - Preserves existing ARC Core security invariants, policy, audit, and tool catalogs.
 */

import fs from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import { isIpv4Unspecified, isIpv6Unspecified } from './remote-config.js';

export const DEFAULT_CHATGPT_BIND_HOST = '127.0.0.1';
export const DEFAULT_CHATGPT_PATH = '/mcp';
export const DEFAULT_CHATGPT_BODY_CEILING_BYTES = 1024 * 1024; // 1 MiB
export const MIN_CHATGPT_BODY_CEILING_BYTES = 1024; // 1 KiB
export const MAX_CHATGPT_BODY_CEILING_BYTES = 4 * 1024 * 1024; // 4 MiB

const HOSTNAME_LABEL_REGEX = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

/**
 * Validates a hostname for the tunnel Host header verification.
 */
function isValidHostname(hostname: string): boolean {
  if (typeof hostname !== 'string' || hostname.length === 0 || hostname.length > 253) {
    return false;
  }
  const labels = hostname.split('.');
  return labels.every((label) => HOSTNAME_LABEL_REGEX.test(label));
}

/**
 * Opt-in configuration for the ChatGPT remote MCP integration profile.
 *
 * Note: Only selectors are permitted. Raw bearer tokens, secrets, or keys must NEVER
 * appear directly in this configuration structure.
 */
export interface ChatGptRemoteConfig {
  /** Explicit opt-in flag. Remote listener starts ONLY when true. */
  enabled: boolean;
  /** Local bind host (defaults to '127.0.0.1'). Wildcards (0.0.0.0, ::) are strictly forbidden. */
  bindHost?: string;
  /** Local listener port (1-65535, or 0 for ephemeral/test). */
  port: number;
  /** Expected public tunnel hostname for Host header validation and DNS rebinding defense. */
  tunnelHostname?: string;
  /**
   * File path selector containing the shared authentication bearer token.
   * Required when enabled. The file must be a regular file with mode 0600/0400
   * owned by the running process user.
   */
  authTokenPath: string;
  /**
   * Optional owner-only bearer-token file for the local Claude stdio bridge.
   * This is a selector only; the token bytes never enter config or argv.
   */
  claudeLocalAuthTokenPath?: string;
  /** Transport endpoint path (defaults to '/mcp'). */
  path?: string;
  /** Request body ceiling in bytes (defaults to 1 MiB, bounded between 1 KiB and 4 MiB). */
  maxRequestBodyBytes?: number;
}

export interface ResolvedChatGptRemoteConfig {
  enabled: boolean;
  bindHost: string;
  port: number;
  tunnelHostname?: string;
  authTokenPath: string;
  expectedToken: string;
  claudeLocalAuthTokenPath?: string;
  expectedClaudeLocalToken?: string;
  path: string;
  maxRequestBodyBytes: number;
}

const ALLOWED_CONFIG_KEYS = new Set([
  'enabled',
  'bindHost',
  'port',
  'tunnelHostname',
  'authTokenPath',
  'claudeLocalAuthTokenPath',
  'path',
  'maxRequestBodyBytes',
]);

/**
 * Validates and resolves the ChatGPT remote profile configuration.
 * Fails closed on any unknown key, insecure permission, missing secret, or wildcard bind.
 */
export function resolveChatGptRemoteConfig(input: unknown): ResolvedChatGptRemoteConfig {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new Error('ChatGPT remote configuration must be a non-null object.');
  }

  const record = input as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!ALLOWED_CONFIG_KEYS.has(key)) {
      throw new Error(`Unknown configuration field in chatgpt profile: '${key}'.`);
    }
  }

  if (typeof record.enabled !== 'boolean') {
    throw new Error("Field 'enabled' in chatgpt configuration must be a boolean.");
  }

  if (!record.enabled) {
    return {
      enabled: false,
      bindHost: DEFAULT_CHATGPT_BIND_HOST,
      port: 0,
      authTokenPath: '',
      expectedToken: '',
      path: DEFAULT_CHATGPT_PATH,
      maxRequestBodyBytes: DEFAULT_CHATGPT_BODY_CEILING_BYTES,
    };
  }

  // Enabled: strictly validate port, bindHost, and authTokenPath
  if (
    typeof record.port !== 'number' ||
    !Number.isInteger(record.port) ||
    record.port < 0 ||
    record.port > 65535
  ) {
    throw new Error(
      "Field 'port' in chatgpt configuration must be an integer between 0 and 65535.",
    );
  }

  const bindHost =
    typeof record.bindHost === 'string' && record.bindHost.trim().length > 0
      ? record.bindHost.trim()
      : DEFAULT_CHATGPT_BIND_HOST;

  if (isIpv4Unspecified(bindHost) || isIpv6Unspecified(bindHost) || bindHost === '0.0.0.0') {
    throw new Error(
      `Wildcard bind host '${bindHost}' is prohibited for ChatGPT remote adapter. ARC must bind to loopback or private interface behind a secure tunnel.`,
    );
  }

  let tunnelHostname: string | undefined;
  if (record.tunnelHostname !== undefined) {
    if (typeof record.tunnelHostname !== 'string') {
      throw new Error("Field 'tunnelHostname' must be a valid string if provided.");
    }
    const trimmed = record.tunnelHostname.trim();
    if (trimmed.length > 0) {
      if (!isValidHostname(trimmed) && net.isIP(trimmed) === 0) {
        throw new Error(
          `Field 'tunnelHostname' is not a valid hostname or IP address: '${trimmed}'.`,
        );
      }
      tunnelHostname = trimmed;
    }
  }

  if (typeof record.authTokenPath !== 'string' || record.authTokenPath.trim().length === 0) {
    throw new Error("Field 'authTokenPath' is required when chatgpt remote profile is enabled.");
  }
  const authTokenPath = record.authTokenPath.trim();

  // Validate the token file security facts (regular file, not symlink, owner-only permissions)
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(authTokenPath);
  } catch {
    throw new Error(`ChatGPT auth token file is missing or unreadable: ${authTokenPath}`);
  }

  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(
      `ChatGPT auth token file must be a regular file, not a symlink: ${authTokenPath}`,
    );
  }

  if (typeof process.getuid === 'function') {
    const currentUid = process.getuid();
    if (stat.uid !== currentUid) {
      throw new Error(
        `ChatGPT auth token file must be owned by the process user (expected UID ${currentUid}, got ${stat.uid}).`,
      );
    }
  }

  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `ChatGPT auth token file must not be readable or writable by group or other (mode 0600/0400 required, found 0${(stat.mode & 0o777).toString(8)}).`,
    );
  }

  let tokenContents: string;
  try {
    tokenContents = fs.readFileSync(authTokenPath, 'utf8');
  } catch {
    throw new Error(`Failed to read ChatGPT auth token file: ${authTokenPath}`);
  }

  const expectedToken = tokenContents.trim();
  if (expectedToken.length === 0) {
    throw new Error(`ChatGPT auth token file is empty: ${authTokenPath}`);
  }

  let claudeLocalAuthTokenPath: string | undefined;
  let expectedClaudeLocalToken: string | undefined;
  if (record.claudeLocalAuthTokenPath !== undefined) {
    if (
      typeof record.claudeLocalAuthTokenPath !== 'string' ||
      record.claudeLocalAuthTokenPath.trim().length === 0
    ) {
      throw new Error("Field 'claudeLocalAuthTokenPath' must be a non-empty string if provided.");
    }
    claudeLocalAuthTokenPath = record.claudeLocalAuthTokenPath.trim();
    let claudeStat: fs.Stats;
    try {
      claudeStat = fs.lstatSync(claudeLocalAuthTokenPath);
    } catch {
      throw new Error(
        `Claude local auth token file is missing or unreadable: ${claudeLocalAuthTokenPath}`,
      );
    }
    if (claudeStat.isSymbolicLink() || !claudeStat.isFile()) {
      throw new Error(
        `Claude local auth token file must be a regular file, not a symlink: ${claudeLocalAuthTokenPath}`,
      );
    }
    if (typeof process.getuid === 'function' && claudeStat.uid !== process.getuid()) {
      throw new Error('Claude local auth token file must be owned by the process user.');
    }
    if ((claudeStat.mode & 0o077) !== 0) {
      throw new Error('Claude local auth token file must have owner-only permissions.');
    }
    let claudeContents: string;
    try {
      claudeContents = fs.readFileSync(claudeLocalAuthTokenPath, 'utf8');
    } catch {
      throw new Error(`Failed to read Claude local auth token file: ${claudeLocalAuthTokenPath}`);
    }
    expectedClaudeLocalToken = claudeContents.trim();
    if (expectedClaudeLocalToken.length === 0) {
      throw new Error(`Claude local auth token file is empty: ${claudeLocalAuthTokenPath}`);
    }
    if (expectedClaudeLocalToken === expectedToken) {
      throw new Error('Claude local and ChatGPT transport tokens must be distinct.');
    }
  }

  let pathStr = DEFAULT_CHATGPT_PATH;
  if (record.path !== undefined) {
    if (typeof record.path !== 'string' || !record.path.startsWith('/')) {
      throw new Error("Field 'path' must be a string starting with '/'.");
    }
    pathStr = record.path.trim();
  }

  let maxRequestBodyBytes = DEFAULT_CHATGPT_BODY_CEILING_BYTES;
  if (record.maxRequestBodyBytes !== undefined) {
    if (
      typeof record.maxRequestBodyBytes !== 'number' ||
      !Number.isInteger(record.maxRequestBodyBytes) ||
      record.maxRequestBodyBytes < MIN_CHATGPT_BODY_CEILING_BYTES ||
      record.maxRequestBodyBytes > MAX_CHATGPT_BODY_CEILING_BYTES
    ) {
      throw new Error(
        `Field 'maxRequestBodyBytes' must be an integer between ${MIN_CHATGPT_BODY_CEILING_BYTES} and ${MAX_CHATGPT_BODY_CEILING_BYTES}.`,
      );
    }
    maxRequestBodyBytes = record.maxRequestBodyBytes;
  }

  return {
    enabled: true,
    bindHost,
    port: record.port,
    tunnelHostname,
    authTokenPath,
    expectedToken,
    ...(claudeLocalAuthTokenPath ? { claudeLocalAuthTokenPath, expectedClaudeLocalToken } : {}),
    path: pathStr,
    maxRequestBodyBytes,
  };
}

/**
 * Constant-time comparison for incoming HTTP Authorization bearer tokens.
 * Protects against timing side-channel attacks.
 */
export function verifyBearerToken(
  presentedHeader: string | undefined | null,
  expectedToken: string,
): boolean {
  if (typeof presentedHeader !== 'string' || !presentedHeader.startsWith('Bearer ')) {
    return false;
  }

  const presentedToken = presentedHeader.slice(7).trim();
  if (presentedToken.length === 0) {
    return false;
  }

  const presentedBuf = Buffer.from(presentedToken, 'utf8');
  const expectedBuf = Buffer.from(expectedToken, 'utf8');

  if (presentedBuf.length !== expectedBuf.length) {
    // Perform dummy timing-safe comparison to equalize execution time
    crypto.timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }

  return crypto.timingSafeEqual(presentedBuf, expectedBuf);
}
