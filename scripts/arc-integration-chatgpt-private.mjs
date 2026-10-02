#!/usr/bin/env node
/**
 * ARC-INTEGRATION-01 — private ChatGPT-compatible MCP launcher.
 *
 * The Core state directory remains authoritative for workspace, policy, audit,
 * process-state, and optional admin configuration. The ChatGPT-specific
 * environment contains connection selectors only; the bearer token itself is
 * selected by restricted file path and is never accepted through argv or an
 * environment value.
 */

import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { resolveIntegrationCoreServerConfig } from './arc-integration-core-config.mjs';

const DEFAULT_PORT = 4318;
const DEFAULT_BIND_HOST = '127.0.0.1';

function optionalPort(name, rawValue, fallback) {
  const raw = rawValue?.trim();
  if (!raw) return fallback;
  if (!/^[0-9]{1,5}$/.test(raw)) throw new Error(`${name} must be an integer port.`);
  const port = Number.parseInt(raw, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be between 1 and 65535.`);
  }
  return port;
}

export function resolvePrivateChatGptProfile(env = process.env) {
  const authTokenPath = env.CESSPACE_ARC_CHATGPT_TOKEN_FILE?.trim();
  if (!authTokenPath) {
    throw new Error('CESSPACE_ARC_CHATGPT_TOKEN_FILE is required.');
  }

  const bindHost = env.CESSPACE_ARC_CHATGPT_BIND_HOST?.trim() || DEFAULT_BIND_HOST;
  const port = optionalPort(
    'CESSPACE_ARC_CHATGPT_PORT',
    env.CESSPACE_ARC_CHATGPT_PORT,
    DEFAULT_PORT,
  );
  const tunnelHostname = env.CESSPACE_ARC_CHATGPT_TUNNEL_HOSTNAME?.trim() || undefined;
  const claudeLocalAuthTokenPath = env.CESSPACE_ARC_CLAUDE_TOKEN_FILE?.trim() || undefined;

  return {
    enabled: true,
    bindHost,
    port,
    authTokenPath: path.resolve(authTokenPath),
    ...(claudeLocalAuthTokenPath
      ? { claudeLocalAuthTokenPath: path.resolve(claudeLocalAuthTokenPath) }
      : {}),
    ...(tunnelHostname ? { tunnelHostname } : {}),
  };
}

export async function startPrivateChatGptIntegration(stateDirectory, env = process.env) {
  const coreConfig = await resolveIntegrationCoreServerConfig(stateDirectory, env);
  const chatgpt = resolvePrivateChatGptProfile(env);
  const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
  const server = createArcMcpServer({ ...coreConfig, chatgpt });

  await server.start();
  const status = server.getChatGptAdapterStatus();
  if (!status?.active) {
    await server.stop();
    throw new Error('ChatGPT-compatible MCP adapter did not become active.');
  }

  return { server, status };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const stateDirectory = process.argv[2];
  if (!stateDirectory) {
    process.stderr.write('Usage: arc-integration-chatgpt-private <core-state-directory>\n');
    process.exit(2);
  }

  startPrivateChatGptIntegration(stateDirectory)
    .then(({ server, status }) => {
      process.stderr.write(
        `CesSpace ARC private ChatGPT-compatible MCP adapter listening on ${status.bindHost}:${status.port}${status.path}\n`,
      );
      let stopping = false;
      const shutdown = async (signal) => {
        if (stopping) return;
        stopping = true;
        try {
          await server.stop();
          process.stderr.write(`CesSpace ARC private adapter stopped cleanly on ${signal}.\n`);
          process.exit(0);
        } catch (error) {
          process.stderr.write(`Failed to stop private adapter cleanly: ${error.message}\n`);
          process.exit(1);
        }
      };
      process.once('SIGTERM', () => void shutdown('SIGTERM'));
      process.once('SIGINT', () => void shutdown('SIGINT'));
    })
    .catch((error) => {
      process.stderr.write(
        `Failed to start private ChatGPT-compatible integration: ${error.message}\n`,
      );
      process.exit(1);
    });
}
