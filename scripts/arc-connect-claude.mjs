#!/usr/bin/env node
/**
 * ARC-CONNECT-02 — one-command Claude Desktop/local MCP connection helper.
 *
 * Claude is configured only as a local stdio client. The generated client entry
 * launches the ARC stdio bridge, which forwards into the single loopback ARC
 * adapter. ARC Core remains the sole policy, approval, workspace, and audit
 * authority, and no bearer secret is written into Claude configuration.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import {
  DEFAULT_PORT,
  assertPrivateRegularFile,
  resolveConnectionPaths,
} from './arc-connect-chatgpt.mjs';
import { resolveIntegrationCoreServerConfig } from './arc-integration-core-config.mjs';

const SERVER_KEY = 'cesspace-arc';
const CONFIG_MAX_BYTES = 1024 * 1024;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function homeDirectory(env = process.env) {
  const home = env.HOME?.trim();
  if (!home || !path.isAbsolute(home)) fail('HOME_REQUIRED', 'HOME must be an absolute path.');
  return home;
}

export function resolveClaudeDesktopConfigPath(
  env = process.env,
  platform = process.platform,
) {
  const home = homeDirectory(env);
  if (platform === 'linux') {
    const base = env.XDG_CONFIG_HOME?.trim()
      ? path.resolve(env.XDG_CONFIG_HOME)
      : path.join(home, '.config');
    return path.join(base, 'Claude', 'claude_desktop_config.json');
  }
  if (platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  }
  if (platform === 'win32') {
    const appData = env.APPDATA?.trim();
    if (!appData || !path.isAbsolute(appData)) {
      fail('APPDATA_REQUIRED', 'APPDATA must be an absolute path on Windows.');
    }
    return path.join(appData, 'Claude', 'claude_desktop_config.json');
  }
  fail('CLAUDE_PLATFORM_UNSUPPORTED', 'Claude Desktop configuration path is unsupported on this platform.');
}

function assertSafeConfigFile(filePath) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return { exists: false, mode: 0o600 };
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    fail('CLAUDE_CONFIG_UNSAFE', 'Claude Desktop config must be a regular non-linked file.');
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    fail('CLAUDE_CONFIG_OWNER', 'Claude Desktop config must be owned by the current user.');
  }
  if ((stat.mode & 0o022) !== 0) {
    fail('CLAUDE_CONFIG_PERMISSIONS', 'Claude Desktop config must not be group/world writable.');
  }
  if (stat.size > CONFIG_MAX_BYTES) {
    fail('CLAUDE_CONFIG_TOO_LARGE', 'Claude Desktop config exceeds the supported size bound.');
  }
  return { exists: true, mode: stat.mode & 0o777 };
}

function parseConfigText(text) {
  let config;
  try {
    config = JSON.parse(text);
  } catch {
    fail('CLAUDE_CONFIG_INVALID', 'Claude Desktop config is not valid JSON.');
  }
  if (typeof config !== 'object' || config === null || Array.isArray(config)) {
    fail('CLAUDE_CONFIG_INVALID', 'Claude Desktop config must be a JSON object.');
  }
  for (const key of ['__proto__', 'prototype', 'constructor']) {
    if (Object.prototype.hasOwnProperty.call(config, key)) {
      fail('CLAUDE_CONFIG_INVALID', 'Claude Desktop config contains a reserved object key.');
    }
  }
  if (
    config.mcpServers !== undefined &&
    (typeof config.mcpServers !== 'object' ||
      config.mcpServers === null ||
      Array.isArray(config.mcpServers))
  ) {
    fail('CLAUDE_CONFIG_INVALID', 'Claude Desktop mcpServers must be a JSON object.');
  }
  return config;
}

export function loadClaudeConfig(filePath) {
  const absolute = path.resolve(filePath);
  const parent = path.dirname(absolute);
  let parentStat;
  try {
    parentStat = fs.statSync(parent);
  } catch {
    fail(
      'CLAUDE_CONFIG_DIR_MISSING',
      'Claude Desktop config directory is missing. Install and launch Claude Desktop once, then retry.',
    );
  }
  if (!parentStat.isDirectory()) fail('CLAUDE_CONFIG_DIR_INVALID', 'Claude config parent is not a directory.');
  const state = assertSafeConfigFile(absolute);
  if (!state.exists) return { path: absolute, mode: 0o600, config: {} };
  return {
    path: absolute,
    mode: state.mode,
    config: parseConfigText(fs.readFileSync(absolute, 'utf8')),
  };
}

function atomicWriteConfig(filePath, config, mode = 0o600) {
  const temp = `${filePath}.cesspace-arc-${process.pid}.tmp`;
  const bytes = `${JSON.stringify(config, null, 2)}\n`;
  if (Buffer.byteLength(bytes, 'utf8') > CONFIG_MAX_BYTES) {
    fail('CLAUDE_CONFIG_TOO_LARGE', 'Updated Claude Desktop config exceeds the supported size bound.');
  }
  fs.writeFileSync(temp, bytes, { mode: 0o600, flag: 'wx' });
  try {
    fs.chmodSync(temp, Math.min(mode, 0o600));
    fs.renameSync(temp, filePath);
    fs.chmodSync(filePath, Math.min(mode, 0o600));
  } catch (error) {
    try {
      fs.rmSync(temp, { force: true });
    } catch {
      // Best-effort cleanup of our own temporary file.
    }
    throw error;
  }
}

function expectedClaudeEntry(launcherPath) {
  return {
    command: launcherPath,
    args: ['proxy', 'claude'],
  };
}

function sameEntry(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function planClaudeConfig({ config, launcherPath, force = false }) {
  const entry = expectedClaudeEntry(launcherPath);
  const servers = { ...(config.mcpServers ?? {}) };
  const current = servers[SERVER_KEY];
  if (current !== undefined && !sameEntry(current, entry) && !force) {
    fail(
      'CLAUDE_ENTRY_CONFLICT',
      'Claude Desktop already has a different cesspace-arc MCP entry. Re-run with --force only after reviewing it.',
    );
  }
  servers[SERVER_KEY] = entry;
  return {
    changed: !sameEntry(current, entry),
    config: { ...config, mcpServers: servers },
    entry,
  };
}

export function planClaudeDisconnect({ config, launcherPath }) {
  const servers = { ...(config.mcpServers ?? {}) };
  const current = servers[SERVER_KEY];
  if (current === undefined) return { changed: false, config };
  const expected = expectedClaudeEntry(launcherPath);
  if (!sameEntry(current, expected)) {
    fail(
      'CLAUDE_ENTRY_CONFLICT',
      'Refusing to remove a cesspace-arc entry that is not owned by this ARC installation.',
    );
  }
  delete servers[SERVER_KEY];
  return { changed: true, config: { ...config, mcpServers: servers } };
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

function writePrivateFile(filePath, content) {
  ensurePrivateDirectory(path.dirname(filePath));
  const temp = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(temp, content, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(temp, 0o600);
  fs.renameSync(temp, filePath);
  fs.chmodSync(filePath, 0o600);
}

function ensureAdapterSecrets(paths) {
  if (!fs.existsSync(paths.arcTokenFile)) {
    writePrivateFile(paths.arcTokenFile, `${crypto.randomBytes(32).toString('hex')}\n`);
  }
  if (!fs.existsSync(paths.claudeTokenFile)) {
    writePrivateFile(paths.claudeTokenFile, `${crypto.randomBytes(32).toString('hex')}\n`);
  }
  assertPrivateRegularFile(paths.arcTokenFile, 'ARC ChatGPT token file');
  assertPrivateRegularFile(paths.claudeTokenFile, 'ARC Claude local token file');
  const chatgptToken = fs.readFileSync(paths.arcTokenFile, 'utf8').trim();
  const claudeToken = fs.readFileSync(paths.claudeTokenFile, 'utf8').trim();
  if (!/^[A-Fa-f0-9]{64}$/.test(chatgptToken) || !/^[A-Fa-f0-9]{64}$/.test(claudeToken)) {
    fail('ARC_TOKEN_INVALID', 'ARC local transport token is invalid.');
  }
  if (chatgptToken === claudeToken) {
    fail('ARC_TOKEN_INVALID', 'ChatGPT and Claude local transport tokens must be distinct.');
  }
  writePrivateFile(paths.arcAuthorizationHeaderFile, `Bearer ${chatgptToken}`);
  assertPrivateRegularFile(paths.arcAuthorizationHeaderFile, 'ARC Authorization header file');
  return { chatgptToken, claudeToken };
}

function readPid(filePath) {
  try {
    const pid = Number.parseInt(fs.readFileSync(filePath, 'utf8').trim(), 10);
    return Number.isInteger(pid) && pid > 1 ? pid : null;
  } catch {
    return null;
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

function processCommandLine(pid) {
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean).join(' ');
  } catch {
    return '';
  }
}

function removeFileIfExists(filePath) {
  try {
    fs.rmSync(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function probeAdapter(token, fetchImpl = fetch) {
  const response = await fetchImpl(`http://127.0.0.1:${DEFAULT_PORT}/health`, {
    headers: { Authorization: `Bearer ${token}` },
  }).catch(() => null);
  return Boolean(response?.ok);
}

function spawnDetached(file, args, { env, logFile, pidFile }) {
  ensurePrivateDirectory(path.dirname(logFile));
  const fd = fs.openSync(logFile, 'a', 0o600);
  fs.chmodSync(logFile, 0o600);
  const child = spawn(file, args, {
    env,
    detached: true,
    shell: false,
    stdio: ['ignore', fd, fd],
  });
  fs.closeSync(fd);
  child.unref();
  writePrivateFile(pidFile, `${child.pid}\n`);
  return child.pid;
}

async function waitForAdapter(pid, tokens, paths) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (!processAlive(pid)) {
      const log = fs.existsSync(paths.adapterLogFile)
        ? fs.readFileSync(paths.adapterLogFile, 'utf8').trim().split('\n').at(-1)
        : '';
      fail('ADAPTER_START_FAILED', log || 'ARC private loopback adapter exited during startup.');
    }
    const readiness = await Promise.all([
      probeAdapter(tokens.chatgptToken),
      probeAdapter(tokens.claudeToken),
    ]);
    if (readiness.every(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail('ADAPTER_START_TIMEOUT', 'ARC private loopback adapter did not become healthy in time.');
}

async function ensureSharedAdapter({ prefix, stateDirectory, paths }) {
  ensurePrivateDirectory(paths.configRoot);
  ensurePrivateDirectory(paths.stateRoot);
  const tokens = ensureAdapterSecrets(paths);
  const pid = readPid(paths.adapterPidFile);
  if (processAlive(pid)) {
    if (!processCommandLine(pid).includes('arc-integration-chatgpt-private.mjs')) {
      fail('PID_OWNERSHIP_MISMATCH', 'ARC adapter PID file refers to an unexpected process.');
    }
    const chatgptHealthy = await probeAdapter(tokens.chatgptToken);
    const claudeHealthy = await probeAdapter(tokens.claudeToken);
    if (chatgptHealthy && claudeHealthy) return { pid, reused: true };
    if (chatgptHealthy && !claudeHealthy) {
      fail(
        'ADAPTER_RESTART_REQUIRED',
        'The running ARC adapter predates Claude-local credential support. Stop it cleanly before reconnecting so ARC can restart with both server-owned credentials.',
      );
    }
    fail(
      'ADAPTER_AUTH_MISMATCH',
      'The running ARC adapter did not accept the stored transport credentials. Refusing to replace it.',
    );
  }
  removeFileIfExists(paths.adapterPidFile);
  const script = path.join(prefix, 'runtime', 'scripts', 'arc-integration-chatgpt-private.mjs');
  if (!fs.existsSync(script)) {
    fail('INSTALL_INCOMPLETE', 'Installed ARC runtime is missing the private loopback adapter.');
  }
  const env = {
    ...process.env,
    CESSPACE_ARC_CHATGPT_TOKEN_FILE: paths.arcTokenFile,
    CESSPACE_ARC_CLAUDE_TOKEN_FILE: paths.claudeTokenFile,
    CESSPACE_ARC_CHATGPT_PORT: String(DEFAULT_PORT),
    CESSPACE_ARC_CHATGPT_BIND_HOST: '127.0.0.1',
  };
  const startedPid = spawnDetached(process.execPath, [script, stateDirectory], {
    env,
    logFile: paths.adapterLogFile,
    pidFile: paths.adapterPidFile,
  });
  await waitForAdapter(startedPid, tokens, paths);
  return { pid: startedPid, reused: false };
}

function validateLauncher(prefix) {
  const launcher = path.join(prefix, 'bin', 'cesspace-arc');
  let stat;
  try {
    stat = fs.lstatSync(launcher);
  } catch {
    fail('INSTALL_INCOMPLETE', 'Installed cesspace-arc launcher is missing.');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) {
    fail('INSTALL_INCOMPLETE', 'Installed cesspace-arc launcher is not a safe executable file.');
  }
  return path.resolve(launcher);
}

function parseArguments(argv) {
  const result = { action: 'connect', configPath: null, force: false, stateDirectory: null };
  if (argv[0] && !argv[0].startsWith('-')) result.action = argv.shift();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--config') result.configPath = argv[++index];
    else if (arg === '--state-directory') result.stateDirectory = argv[++index];
    else if (arg === '--force') result.force = true;
    else if (arg === '--help' || arg === '-h') result.help = true;
    else fail('INVALID_ARGUMENT', `Unknown argument: ${arg}`);
  }
  if (!['connect', 'status', 'disconnect'].includes(result.action)) {
    fail('INVALID_ACTION', 'Action must be connect, status, or disconnect.');
  }
  return result;
}

function selectConfigPath(args, env) {
  if (!args.configPath) return resolveClaudeDesktopConfigPath(env);
  if (!path.isAbsolute(args.configPath)) {
    fail('CLAUDE_CONFIG_PATH', '--config must be an absolute path.');
  }
  return path.resolve(args.configPath);
}

export async function manageClaudeConnection({
  argv = process.argv.slice(2),
  env = process.env,
} = {}) {
  const args = parseArguments([...argv]);
  if (args.help) return { help: true };
  const home = homeDirectory(env);
  const prefix = path.resolve(
    env.CESSPACE_ARC_INSTALL_PREFIX || path.join(home, '.local', 'cesspace-arc'),
  );
  const stateDirectory = path.resolve(
    args.stateDirectory ||
      env.CESSPACE_ARC_STATE_DIR ||
      path.join(home, '.config', 'cesspace-arc', 'state'),
  );
  const launcherPath = validateLauncher(prefix);
  const configPath = selectConfigPath(args, env);
  const loaded = loadClaudeConfig(configPath);

  if (args.action === 'disconnect') {
    const plan = planClaudeDisconnect({ config: loaded.config, launcherPath });
    if (plan.changed) atomicWriteConfig(loaded.path, plan.config, loaded.mode);
    return { action: 'disconnect', changed: plan.changed, configPath, launcherPath };
  }

  const current = loaded.config.mcpServers?.[SERVER_KEY];
  const configured = sameEntry(current, expectedClaudeEntry(launcherPath));
  const paths = resolveConnectionPaths(env);

  if (args.action === 'status') {
    let adapterHealthy = false;
    if (fs.existsSync(paths.claudeTokenFile)) {
      try {
        const token = fs.readFileSync(
          assertPrivateRegularFile(paths.claudeTokenFile, 'ARC Claude local token file'),
          'utf8',
        ).trim();
        adapterHealthy = await probeAdapter(token);
      } catch {
        adapterHealthy = false;
      }
    }
    return { action: 'status', configured, adapterHealthy, configPath, launcherPath };
  }

  const { preflightCoreState } = await import('../packages/config/dist/index.js');
  const preflight = await preflightCoreState(stateDirectory, { environment: env });
  if (preflight.audit.status !== 'VERIFIED') {
    fail('CORE_PREFLIGHT_FAILED', 'ARC Core audit verification did not pass.');
  }
  await resolveIntegrationCoreServerConfig(stateDirectory, env);
  const plan = planClaudeConfig({
    config: loaded.config,
    launcherPath,
    force: args.force,
  });
  const adapter = await ensureSharedAdapter({ prefix, stateDirectory, paths });
  if (plan.changed) atomicWriteConfig(loaded.path, plan.config, loaded.mode);
  return {
    action: 'connect',
    changed: plan.changed,
    configPath,
    launcherPath,
    adapterReused: adapter.reused,
    auditStatus: preflight.audit.status,
  };
}

function printHelp() {
  process.stdout.write(
    'Usage:\n' +
      '  cesspace-arc connect claude [--config <absolute-path>] [--state-directory <path>] [--force]\n' +
      '  cesspace-arc status claude [--config <absolute-path>]\n' +
      '  cesspace-arc disconnect claude [--config <absolute-path>]\n\n' +
      'Claude is configured as a local stdio MCP client. No ARC bearer token is written into Claude configuration.\n',
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  manageClaudeConnection()
    .then((result) => {
      if (result.help) {
        printHelp();
        return;
      }
      if (result.action === 'status') {
        process.stdout.write(
          `CesSpace ARC Claude status.\nConfigured: ${result.configured ? 'yes' : 'no'}\nAdapter healthy: ${result.adapterHealthy ? 'yes' : 'no'}\nConfig: ${result.configPath}\n`,
        );
        return;
      }
      if (result.action === 'disconnect') {
        process.stdout.write(
          `CesSpace ARC Claude connection ${result.changed ? 'removed' : 'was not configured'}.\nConfig: ${result.configPath}\n`,
        );
        return;
      }
      process.stdout.write(
        `CesSpace ARC Claude connection ready.\nConfig: ${result.configPath}\nAudit: ${result.auditStatus}\nShared ARC adapter: ${result.adapterReused ? 'reused' : 'started'}\nSecrets in Claude config: none\n\nFully quit and reopen Claude Desktop, then open Connectors to verify CesSpace ARC tools.\n`,
      );
    })
    .catch((error) => {
      process.stderr.write(
        `ARC Claude connection failed${error.code ? ` [${error.code}]` : ''}: ${error.message}\n`,
      );
      process.exit(1);
    });
}
