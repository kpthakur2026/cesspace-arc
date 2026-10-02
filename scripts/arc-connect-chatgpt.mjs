#!/usr/bin/env node
/**
 * ARC-CONNECT-01 — one-command ChatGPT connection helper.
 *
 * This helper never grants host authority. It validates the existing Core state,
 * starts the reviewed loopback-only ChatGPT adapter, and connects that adapter
 * to an operator-created OpenAI Secure MCP Tunnel. ARC policy, approvals,
 * workspace containment, and durable audit remain authoritative.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { resolveIntegrationCoreServerConfig } from './arc-integration-core-config.mjs';

export const TUNNEL_CLIENT_VERSION = '0.0.15';
export const DEFAULT_PORT = 4318;
export const PROFILE_NAME = 'cesspace-arc';

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

export function validateTunnelId(value) {
  const tunnelId = value?.trim();
  if (!tunnelId || !/^tunnel_[A-Za-z0-9]+$/.test(tunnelId)) {
    fail('INVALID_TUNNEL_ID', 'Tunnel ID must have the form tunnel_<opaque-id>.');
  }
  return tunnelId;
}

function homeDirectory(env = process.env) {
  const home = env.HOME?.trim();
  if (!home || !path.isAbsolute(home)) fail('HOME_REQUIRED', 'HOME must be an absolute path.');
  return home;
}

export function resolveConnectionPaths(env = process.env) {
  const home = homeDirectory(env);
  const configRoot = path.join(home, '.config', 'cesspace-arc', 'connect', 'chatgpt');
  const stateRoot = path.join(home, '.local', 'state', 'cesspace-arc', 'connect', 'chatgpt');
  return {
    home,
    configRoot,
    stateRoot,
    arcTokenFile: path.join(configRoot, 'arc-token'),
    arcAuthorizationHeaderFile: path.join(configRoot, 'arc-authorization-header'),
    apiKeyFile: path.join(configRoot, 'openai-api-key'),
    connectionFile: path.join(configRoot, 'connection.json'),
    adapterPidFile: path.join(stateRoot, 'adapter.pid'),
    adapterLogFile: path.join(stateRoot, 'adapter.log'),
    tunnelPidFile: path.join(stateRoot, 'tunnel-client.pid'),
    tunnelLogFile: path.join(stateRoot, 'tunnel-client.log'),
    healthUrlFile: path.join(stateRoot, 'health-url'),
  };
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

export function assertPrivateRegularFile(filePath, label) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    fail('SECRET_FILE_MISSING', `${label} is missing.`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail('SECRET_FILE_INVALID', `${label} must be a regular non-symlink file.`);
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    fail('SECRET_FILE_OWNER', `${label} must be owned by the current user.`);
  }
  if ((stat.mode & 0o077) !== 0) {
    fail('SECRET_FILE_PERMISSIONS', `${label} must not be accessible by group or other users.`);
  }
  if (stat.size < 1 || stat.size > 16 * 1024) {
    fail('SECRET_FILE_INVALID', `${label} has an invalid size.`);
  }
  return filePath;
}

function writePrivateFile(filePath, content) {
  ensurePrivateDirectory(path.dirname(filePath));
  const temp = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(temp, content, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(temp, 0o600);
  fs.renameSync(temp, filePath);
  fs.chmodSync(filePath, 0o600);
}

function readSavedTunnelId(connectionFile) {
  try {
    const parsed = JSON.parse(fs.readFileSync(connectionFile, 'utf8'));
    return validateTunnelId(parsed.tunnelId);
  } catch {
    return null;
  }
}

function saveConnection(connectionFile, tunnelId) {
  writePrivateFile(
    connectionFile,
    `${JSON.stringify({ format: 'cesspace-arc-chatgpt-connection-v1', tunnelId }, null, 2)}\n`,
  );
}

function parseArguments(argv) {
  const result = { tunnelId: null, apiKeyFile: null, stateDirectory: null, tunnelClient: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--tunnel-id') result.tunnelId = argv[++index];
    else if (arg === '--api-key-file') result.apiKeyFile = argv[++index];
    else if (arg === '--state-directory') result.stateDirectory = argv[++index];
    else if (arg === '--tunnel-client') result.tunnelClient = argv[++index];
    else if (arg === '--help' || arg === '-h') result.help = true;
    else fail('INVALID_ARGUMENT', `Unknown argument: ${arg}`);
  }
  return result;
}

function readSecretFromTty(prompt) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    fail(
      'API_KEY_REQUIRED',
      'Platform API key is required. Re-run interactively or use --api-key-file <0600-file>.',
    );
  }
  return new Promise((resolve, reject) => {
    process.stdout.write(prompt);
    const input = process.stdin;
    const wasRaw = input.isRaw;
    let value = '';
    input.setEncoding('utf8');
    input.setRawMode(true);
    input.resume();
    const cleanup = () => {
      input.off('data', onData);
      input.setRawMode(Boolean(wasRaw));
      input.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\u0003') {
          cleanup();
          reject(Object.assign(new Error('Cancelled.'), { code: 'CANCELLED' }));
          return;
        }
        if (char === '\r' || char === '\n') {
          cleanup();
          resolve(value.trim());
          return;
        }
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else if (char >= ' ') value += char;
      }
    };
    input.on('data', onData);
  });
}

async function resolveApiKeyFile(paths, selectedFile) {
  if (selectedFile)
    return assertPrivateRegularFile(path.resolve(selectedFile), 'OpenAI API key file');
  if (fs.existsSync(paths.apiKeyFile))
    return assertPrivateRegularFile(paths.apiKeyFile, 'OpenAI API key file');
  const secret = await readSecretFromTty('Paste Platform API key (hidden; stored locally 0600): ');
  if (!secret || secret.length < 16 || /[\r\n]/.test(secret))
    fail('API_KEY_INVALID', 'OpenAI API key is invalid.');
  writePrivateFile(paths.apiKeyFile, `${secret}\n`);
  return assertPrivateRegularFile(paths.apiKeyFile, 'OpenAI API key file');
}

function ensureArcSecrets(paths) {
  if (!fs.existsSync(paths.arcTokenFile))
    writePrivateFile(paths.arcTokenFile, `${crypto.randomBytes(32).toString('hex')}\n`);
  assertPrivateRegularFile(paths.arcTokenFile, 'ARC ChatGPT token file');
  const token = fs.readFileSync(paths.arcTokenFile, 'utf8').trim();
  if (!/^[A-Fa-f0-9]{64}$/.test(token))
    fail('ARC_TOKEN_INVALID', 'ARC ChatGPT token file is invalid.');
  writePrivateFile(paths.arcAuthorizationHeaderFile, `Bearer ${token}`);
  assertPrivateRegularFile(paths.arcAuthorizationHeaderFile, 'ARC Authorization header file');
}

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { ...options, shell: false });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => (stdout += chunk.toString()));
    child.stderr?.on('data', (chunk) => (stderr += chunk.toString()));
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else {
        reject(
          Object.assign(new Error(stderr.trim() || `${file} exited ${code}`), {
            code: 'COMMAND_FAILED',
            exitCode: code,
            stdout,
            stderr,
          }),
        );
      }
    });
  });
}

function executableCandidate(candidate) {
  if (!candidate || !path.isAbsolute(candidate)) return null;
  let stat;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return null;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) return null;
  if ((stat.mode & 0o022) !== 0) return null;
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid() && stat.uid !== 0)
    return null;
  if ((stat.mode & 0o111) === 0) return null;
  return candidate;
}

function pathCandidates(env, home) {
  const candidates = [];
  for (const directory of (env.PATH || '').split(path.delimiter)) {
    if (!directory) continue;
    const absolute = path.isAbsolute(directory) ? directory : path.resolve(directory);
    candidates.push(path.join(absolute, 'tunnel-client'));
  }
  candidates.push(path.join(home, '.local', 'bin', 'tunnel-client'));
  return [...new Set(candidates)];
}

async function resolveTunnelClient(selectedPath, env, home) {
  const candidates = selectedPath ? [path.resolve(selectedPath)] : pathCandidates(env, home);
  for (const candidate of candidates) {
    const executable = executableCandidate(candidate);
    if (!executable) continue;
    try {
      const version = await run(executable, ['--version'], { stdio: ['ignore', 'pipe', 'pipe'] });
      if (version.stdout.startsWith(TUNNEL_CLIENT_VERSION)) return executable;
    } catch {
      // Continue to the next operator-installed candidate.
    }
  }
  fail(
    'TUNNEL_CLIENT_REQUIRED',
    `A supported tunnel-client ${TUNNEL_CLIENT_VERSION} executable is required. Install it from your platform tunnel settings or pass --tunnel-client <absolute-path>.`,
  );
}

function removeFileIfExists(filePath) {
  try {
    fs.rmSync(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function readPid(filePath) {
  try {
    const pid = Number.parseInt(fs.readFileSync(filePath, 'utf8').trim(), 10);
    return Number.isInteger(pid) && pid > 1 ? pid : null;
  } catch {
    return null;
  }
}

function processCommandLine(pid) {
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ');
  } catch {
    return '';
  }
}

function processAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function stopManagedProcess(pidFile, expectedFragment) {
  const pid = readPid(pidFile);
  if (!processAlive(pid)) {
    removeFileIfExists(pidFile);
    return;
  }
  const commandLine = processCommandLine(pid);
  if (!commandLine.includes(expectedFragment))
    fail('PID_OWNERSHIP_MISMATCH', `Refusing to stop unexpected process recorded in ${pidFile}.`);
  process.kill(pid, 'SIGTERM');
  removeFileIfExists(pidFile);
}

function spawnDetached(file, args, { env, logFile, pidFile }) {
  ensurePrivateDirectory(path.dirname(logFile));
  const fd = fs.openSync(logFile, 'a', 0o600);
  fs.chmodSync(logFile, 0o600);
  const child = spawn(file, args, { env, detached: true, shell: false, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  child.unref();
  writePrivateFile(pidFile, `${child.pid}\n`);
  return child.pid;
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail('STARTUP_TIMEOUT', `${label} did not become ready within ${timeoutMs}ms.`);
}

async function probeArc(tokenFile, port = DEFAULT_PORT) {
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'arc-connect-probe',
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'cesspace-arc-connect', version: '1.0' },
      },
    }),
  });
  if (response.status !== 200 || !response.headers.get('mcp-session-id')) return false;
  return true;
}

async function startAdapter({ prefix, stateDirectory, paths }) {
  const script = path.join(prefix, 'runtime', 'scripts', 'arc-integration-chatgpt-private.mjs');
  if (!fs.existsSync(script))
    fail('INSTALL_INCOMPLETE', 'Installed ARC runtime is missing the private ChatGPT adapter.');
  const existingPid = readPid(paths.adapterPidFile);
  if (
    processAlive(existingPid) &&
    processCommandLine(existingPid).includes('arc-integration-chatgpt-private.mjs')
  ) {
    if (await probeArc(paths.arcTokenFile)) return existingPid;
    fail(
      'ADAPTER_AUTH_MISMATCH',
      'A helper-managed ARC adapter is already running but did not accept the stored connection token. Refusing to terminate it automatically.',
    );
  }
  const env = {
    ...process.env,
    CESSPACE_ARC_CHATGPT_TOKEN_FILE: paths.arcTokenFile,
    CESSPACE_ARC_CHATGPT_PORT: String(DEFAULT_PORT),
    CESSPACE_ARC_CHATGPT_BIND_HOST: '127.0.0.1',
  };
  const pid = spawnDetached(process.execPath, [script, stateDirectory], {
    env,
    logFile: paths.adapterLogFile,
    pidFile: paths.adapterPidFile,
  });
  await waitFor(
    async () => {
      if (!processAlive(pid)) {
        const log = fs.existsSync(paths.adapterLogFile)
          ? fs.readFileSync(paths.adapterLogFile, 'utf8').trim().split('\n').at(-1)
          : '';
        fail('ADAPTER_START_FAILED', log || 'ARC private ChatGPT adapter exited during startup.');
      }
      return probeArc(paths.arcTokenFile).catch(() => false);
    },
    10000,
    'ARC private ChatGPT adapter',
  );
  return pid;
}

async function startTunnel({ tunnelBinary, tunnelId, apiKeyFile, paths }) {
  const profileDir = path.join(paths.home, '.config', 'tunnel-client');
  ensurePrivateDirectory(profileDir);
  await run(
    tunnelBinary,
    [
      'init',
      '--force',
      '--profile',
      PROFILE_NAME,
      '--tunnel-id',
      tunnelId,
      '--mcp-server-url',
      `http://127.0.0.1:${DEFAULT_PORT}/mcp`,
      '--control-plane-api-key-ref',
      `file:${apiKeyFile}`,
      '--health-listen-addr',
      '127.0.0.1:0',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const tunnelEnv = {
    ...process.env,
    MCP_EXTRA_HEADERS: `Authorization: file:${paths.arcAuthorizationHeaderFile}`,
    MCP_DISCOVERY_EXTRA_HEADERS: `Authorization: file:${paths.arcAuthorizationHeaderFile}`,
  };
  const doctor = await run(tunnelBinary, ['doctor', '--profile', PROFILE_NAME], {
    env: tunnelEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (!doctor.stdout.includes('RESULT ok'))
    fail('TUNNEL_DOCTOR_FAILED', 'OpenAI tunnel-client doctor did not report RESULT ok.');
  stopManagedProcess(paths.tunnelPidFile, 'tunnel-client run');
  removeFileIfExists(paths.healthUrlFile);
  const pid = spawnDetached(
    tunnelBinary,
    [
      'run',
      '--profile',
      PROFILE_NAME,
      '--health.listen-addr',
      '127.0.0.1:0',
      '--health.url-file',
      paths.healthUrlFile,
    ],
    { env: tunnelEnv, logFile: paths.tunnelLogFile, pidFile: paths.tunnelPidFile },
  );
  await waitFor(
    async () => {
      if (!processAlive(pid) || !fs.existsSync(paths.healthUrlFile)) return false;
      const healthUrl = fs.readFileSync(paths.healthUrlFile, 'utf8').trim();
      if (!healthUrl.startsWith('http://127.0.0.1:')) return false;
      const ready = await fetch(`${healthUrl}/readyz`).catch(() => null);
      if (!ready?.ok) return false;
      const log = fs.existsSync(paths.tunnelLogFile)
        ? fs.readFileSync(paths.tunnelLogFile, 'utf8')
        : '';
      return log.includes('mcp session initialized') && log.includes('tunnel-client started');
    },
    20000,
    'OpenAI Secure MCP Tunnel',
  );
  return pid;
}

export async function connectChatGpt({ argv = process.argv.slice(2), env = process.env } = {}) {
  const args = parseArguments(argv);
  if (args.help) return { help: true };
  const paths = resolveConnectionPaths(env);
  ensurePrivateDirectory(paths.configRoot);
  ensurePrivateDirectory(paths.stateRoot);
  const tunnelId = validateTunnelId(args.tunnelId || readSavedTunnelId(paths.connectionFile));
  const stateDirectory = path.resolve(
    args.stateDirectory ||
      env.CESSPACE_ARC_STATE_DIR ||
      path.join(paths.home, '.config', 'cesspace-arc', 'state'),
  );
  const prefix = path.resolve(
    env.CESSPACE_ARC_INSTALL_PREFIX || path.join(paths.home, '.local', 'cesspace-arc'),
  );
  const { preflightCoreState } = await import('../packages/config/dist/index.js');
  const preflight = await preflightCoreState(stateDirectory, { environment: env });
  if (preflight.audit.status !== 'VERIFIED')
    fail('CORE_PREFLIGHT_FAILED', 'ARC Core audit verification did not pass.');
  await resolveIntegrationCoreServerConfig(stateDirectory, env);
  const apiKeyFile = await resolveApiKeyFile(paths, args.apiKeyFile);
  ensureArcSecrets(paths);
  const tunnelBinary = await resolveTunnelClient(args.tunnelClient, env, paths.home);
  await startAdapter({ prefix, stateDirectory, paths });
  await startTunnel({ tunnelBinary, tunnelId, apiKeyFile, paths });
  saveConnection(paths.connectionFile, tunnelId);
  return { tunnelId, stateDirectory, prefix, auditStatus: preflight.audit.status, paths };
}

function printHelp() {
  process.stdout.write(
    `Usage:\n  cesspace-arc connect chatgpt --tunnel-id tunnel_... [--tunnel-client <absolute-path>] [--api-key-file <0600-file>] [--state-directory <path>]\n\nThe Platform API key is never accepted as a command-line value. If no protected key file exists, the helper prompts for the key with hidden input and stores it locally with mode 0600. ARC Core does not download or bundle the external tunnel runtime.\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  connectChatGpt()
    .then((result) => {
      if (result.help) {
        printHelp();
        return;
      }
      process.stdout.write(
        `CesSpace ARC ChatGPT connection ready.\nTunnel: ${result.tunnelId}\nCore state: ${result.stateDirectory}\nAudit: ${result.auditStatus}\nARC endpoint: private loopback only\n\nIn ChatGPT custom MCP settings use:\n  Connection: Tunnel\n  Tunnel ID: ${result.tunnelId}\n  Authentication: No authentication\n\nARC policy, approvals, workspace containment, and audit remain authoritative on this machine.\n`,
      );
    })
    .catch((error) => {
      process.stderr.write(
        `ARC ChatGPT connection failed${error.code ? ` [${error.code}]` : ''}: ${error.message}\n`,
      );
      process.exit(1);
    });
}
