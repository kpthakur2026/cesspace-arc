#!/usr/bin/env node
import { rollbackCoreState } from '../packages/config/dist/index.js';

const args = process.argv.slice(2);
if (args.length !== 1 || args[0].startsWith('-')) {
  process.stderr.write('Usage: pnpm run rollback:arc10 -- <migration-root>\n');
  process.exitCode = 2;
} else {
  try {
    const result = await rollbackCoreState(args[0]);
    process.stdout.write(
      `${JSON.stringify({ result: result.result, stateDigest: result.stateDigest })}\n`,
    );
  } catch (error) {
    process.stderr.write(`Rollback failed (${error?.code ?? 'ROLLBACK_FAILED'}).\n`);
    process.exitCode = 1;
  }
}
