#!/usr/bin/env node
/**
 * ARC-CONNECT-02 — Claude/local stdio bridge.
 *
 * This process has no ARC tool implementation and no host authority. It only
 * translates newline-delimited stdio MCP messages into authenticated loopback
 * MCP requests to the already-running ARC private adapter. The bearer token is
 * read from an owner-only local file and is never accepted through argv.
 */

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';

const DEFAULT_ENDPOINT = 'http://127.0.0.1:4318/mcp';
const MAX_LINE_BYTES = 4 * 1024 * 1024;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function defaultTokenFile(env = process.env) {
  const home = env.HOME?.trim();
  if (!home || !path.isAbsolute(home)) fail('HOME_REQUIRED', 'HOME must be an absolute path.');
  return path.join(home, '.config', 'cesspace-arc', 'connect', 'chatgpt', 'claude-token');
}

export function resolveClaudeProxyConfig(env = process.env) {
  const endpoint = env.CESSPACE_ARC_CLAUDE_PROXY_ENDPOINT?.trim() || DEFAULT_ENDPOINT;
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    fail('PROXY_ENDPOINT_INVALID', 'Claude proxy endpoint is invalid.');
  }
  if (
    parsed.protocol !== 'http:' ||
    !['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname) ||
    parsed.pathname !== '/mcp' ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    fail('PROXY_ENDPOINT_INVALID', 'Claude proxy endpoint must be a loopback HTTP /mcp URL.');
  }
  const tokenFile = path.resolve(
    env.CESSPACE_ARC_CLAUDE_TOKEN_FILE?.trim() || defaultTokenFile(env),
  );
  return { endpoint: parsed.toString(), tokenFile };
}

export function readPrivateBearerToken(filePath) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    fail('ARC_TOKEN_MISSING', 'ARC local adapter token file is missing.');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    fail('ARC_TOKEN_INVALID', 'ARC local adapter token must be a regular non-linked file.');
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    fail('ARC_TOKEN_OWNER', 'ARC local adapter token must be owned by the current user.');
  }
  if ((stat.mode & 0o077) !== 0) {
    fail('ARC_TOKEN_PERMISSIONS', 'ARC local adapter token must have owner-only permissions.');
  }
  if (stat.size < 1 || stat.size > 4096) {
    fail('ARC_TOKEN_INVALID', 'ARC local adapter token has an invalid size.');
  }
  const token = fs.readFileSync(filePath, 'utf8').trim();
  if (!/^[A-Fa-f0-9]{64}$/.test(token)) fail('ARC_TOKEN_INVALID', 'ARC local adapter token is invalid.');
  return token;
}

function writeProtocol(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function boundedParse(line) {
  if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) {
    return {
      error: { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Payload Too Large' } },
    };
  }
  try {
    const parsed = JSON.parse(line);
    if (Array.isArray(parsed) || typeof parsed !== 'object' || parsed === null) {
      return {
        error: { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } },
      };
    }
    return { parsed };
  } catch {
    return {
      error: { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
    };
  }
}

export async function forwardMcpMessage({
  endpoint,
  token,
  sessionId,
  message,
  fetchImpl = fetch,
}) {
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  };
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;
  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(message),
  });
  const nextSessionId = response.headers.get('mcp-session-id') || sessionId || null;
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      fail('PROXY_RESPONSE_INVALID', 'ARC local adapter returned malformed JSON.');
    }
  }
  if (!response.ok) {
    if (body && typeof body === 'object') return { sessionId: nextSessionId, body };
    fail('PROXY_REQUEST_FAILED', `ARC local adapter returned HTTP ${response.status}.`);
  }
  return { sessionId: nextSessionId, body };
}

async function closeSession(endpoint, token, sessionId, fetchImpl = fetch) {
  if (!sessionId) return;
  try {
    await fetchImpl(endpoint, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
        'Mcp-Session-Id': sessionId,
      },
    });
  } catch {
    // Session cleanup is best-effort during client shutdown.
  }
}

export async function runClaudeStdioProxy({
  env = process.env,
  input = process.stdin,
  fetchImpl = fetch,
} = {}) {
  const { endpoint, tokenFile } = resolveClaudeProxyConfig(env);
  const token = readPrivateBearerToken(tokenFile);
  let sessionId = null;
  const lines = readline.createInterface({ input, crlfDelay: Infinity, terminal: false });
  try {
    for await (const line of lines) {
      if (!line.trim()) continue;
      const decoded = boundedParse(line);
      if (decoded.error) {
        writeProtocol(decoded.error);
        continue;
      }
      const message = decoded.parsed;
      const hasId = Object.prototype.hasOwnProperty.call(message, 'id');
      try {
        const result = await forwardMcpMessage({
          endpoint,
          token,
          sessionId,
          message,
          fetchImpl,
        });
        sessionId = result.sessionId;
        if (hasId && result.body !== null) writeProtocol(result.body);
      } catch (error) {
        if (hasId) {
          writeProtocol({
            jsonrpc: '2.0',
            id: message.id ?? null,
            error: { code: -32000, message: 'ARC local bridge unavailable' },
          });
        }
        process.stderr.write(`CesSpace ARC Claude bridge error: ${error.message}\n`);
      }
    }
  } finally {
    await closeSession(endpoint, token, sessionId, fetchImpl);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runClaudeStdioProxy().catch((error) => {
    process.stderr.write(
      `Failed to start CesSpace ARC Claude/local stdio bridge${error.code ? ` [${error.code}]` : ''}: ${error.message}\n`,
    );
    process.exit(1);
  });
}
