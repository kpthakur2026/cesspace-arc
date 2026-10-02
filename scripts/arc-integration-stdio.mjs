#!/usr/bin/env node
/**
 * ARC-INTEGRATION-01 — local stdio launcher for standards-conformant MCP clients.
 *
 * The sole positional argument is the existing ARC Core state directory.
 * All security-sensitive workspace, policy, audit, and admin selectors come
 * from the validated Core configuration inside that state.
 */

import { pathToFileURL } from 'node:url';

import { resolveIntegrationCoreServerConfig } from './arc-integration-core-config.mjs';

export async function startLocalStdioIntegration(stateDirectory, environment = process.env) {
  const serverConfig = await resolveIntegrationCoreServerConfig(stateDirectory, environment);
  const { createArcMcpServer } = await import('../apps/mcp-server/dist/index.js');
  const server = createArcMcpServer(serverConfig);
  await server.start();
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const stateDirectory = process.argv[2];
  if (!stateDirectory) {
    process.stderr.write('Usage: arc-integration-stdio <core-state-directory>\n');
    process.exit(2);
  }

  startLocalStdioIntegration(stateDirectory).catch((error) => {
    process.stderr.write(`Failed to start local ARC MCP integration: ${error.message}\n`);
    process.exit(1);
  });
}
