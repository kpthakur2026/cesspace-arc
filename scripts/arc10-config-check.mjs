#!/usr/bin/env node
import { preflightCoreState } from '../packages/config/dist/index.js';

function usage() {
  process.stderr.write('Usage: pnpm run config:check -- <state-root>\n');
}

const args = process.argv.slice(2);
if (args.length !== 1 || args[0].startsWith('-')) {
  usage();
  process.exitCode = 2;
} else {
  try {
    const result = await preflightCoreState(args[0], { environment: process.env });
    process.stdout.write(
      `${JSON.stringify({
        audit: result.audit.status,
        configSchemaVersion: result.resolved.config.schemaVersion,
        devices: result.devices,
        productVersion: result.resolved.config.productVersion,
        stateSchemaVersion: result.state.stateSchemaVersion,
      })}\n`,
    );
  } catch (error) {
    process.stderr.write(`Configuration check failed (${error?.code ?? 'CONFIG_CHECK_FAILED'}).\n`);
    process.exitCode = 1;
  }
}
