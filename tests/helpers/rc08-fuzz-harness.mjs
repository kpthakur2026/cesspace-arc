import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_FUZZ_SEED = 1_592_639_710;
export const NORMAL_FUZZ_RUNS = 100;
export const EXTENDED_FUZZ_RUNS = 5_000;
export const MAX_GENERATED_PAYLOAD_BYTES = 2 * 1024 * 1024;
export const MAX_GENERATED_DEPTH = 10;
export const MAX_GENERATED_ARRAY_LENGTH = 10_000;
export const MAX_GENERATED_STRING_BYTES = 1024 * 1024;
export const MAX_FAILURE_ARTIFACT_BYTES = 16 * 1024;

const FAILURE_DIRECTORY = fileURLToPath(
  new URL('../fixtures/fuzz-corpus/failures/', import.meta.url),
);

function parseSeed(raw) {
  if (raw === undefined || raw === '') return DEFAULT_FUZZ_SEED;
  if (!/^-?\d+$/.test(raw)) {
    throw new Error('FUZZ_SEED must be a base-10 signed 32-bit integer.');
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < -2_147_483_648 || parsed > 2_147_483_647) {
    throw new Error('FUZZ_SEED must be a base-10 signed 32-bit integer.');
  }
  return parsed;
}

export const FUZZ_SEED = parseSeed(process.env.FUZZ_SEED);
export const FUZZ_PATH = process.env.FUZZ_PATH || undefined;
export const FUZZ_RUNS =
  process.env.RC08_FUZZ_EXTENDED === '1' ? EXTENDED_FUZZ_RUNS : NORMAL_FUZZ_RUNS;

export function fastCheckParameters(overrides = {}) {
  return {
    seed: FUZZ_SEED,
    numRuns: FUZZ_RUNS,
    endOnFailure: true,
    ...(FUZZ_PATH === undefined ? {} : { path: FUZZ_PATH }),
    ...overrides,
  };
}

function summarize(value, depth = 0) {
  if (depth >= 6) return '<depth-limit>';
  if (typeof value === 'string') {
    const redacted = value
      .replace(
        /\b(?:token|secret|password|credential|private[_ -]?key)\b\s*[:=]\s*\S+/gi,
        '[REDACTED]',
      )
      .replace(/\/(?:home|Users|root)\/[^\s"']+/g, '[REDACTED_PATH]');
    if (Buffer.byteLength(redacted, 'utf8') <= 512) return redacted;
    return {
      payloadClass: 'oversized-string',
      byteLength: Buffer.byteLength(redacted, 'utf8'),
      sha256: createHash('sha256').update(redacted).digest('hex'),
      prefix: redacted.slice(0, 128),
    };
  }
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) {
    return {
      payloadClass: 'array',
      length: value.length,
      sample: value.slice(0, 16).map((item) => summarize(item, depth + 1)),
    };
  }
  if (value && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value).sort().slice(0, 32)) {
      output[/token|secret|password|credential|private.?key/i.test(key) ? '[REDACTED_KEY]' : key] =
        /token|secret|password|credential|private.?key/i.test(key)
          ? '[REDACTED]'
          : summarize(value[key], depth + 1);
    }
    return output;
  }
  return String(value);
}

export function reproductionCommand(seed, propertyPath) {
  const pathPart = propertyPath ? ` FUZZ_PATH=${JSON.stringify(propertyPath)}` : '';
  return `FUZZ_SEED=${seed}${pathPart} pnpm run test:fuzz:rc08`;
}

export function persistUnexpectedFailure(control, result) {
  const artifact = {
    control,
    seed: result.seed ?? FUZZ_SEED,
    path: result.counterexamplePath ?? FUZZ_PATH ?? null,
    case: summarize(result.counterexample ?? result),
    reproduce: reproductionCommand(result.seed ?? FUZZ_SEED, result.counterexamplePath),
  };
  const serialized = `${JSON.stringify(artifact, null, 2)}\n`;
  assert.ok(
    Buffer.byteLength(serialized, 'utf8') <= MAX_FAILURE_ARTIFACT_BYTES,
    'sanitized failure artifact exceeded its frozen bound',
  );
  fs.mkdirSync(FAILURE_DIRECTORY, { recursive: true });
  const stableName = `${control.toLowerCase().replace(/[^a-z0-9-]/g, '-')}.json`;
  fs.writeFileSync(path.join(FAILURE_DIRECTORY, stableName), serialized, { mode: 0o600 });
}

export function assertFuzzProperty(fc, control, property, overrides = {}) {
  const result = fc.check(property, fastCheckParameters(overrides));
  if (result.failed) {
    persistUnexpectedFailure(control, result);
    assert.fail(
      `${control} failed (seed=${result.seed}, path=${result.counterexamplePath}); ` +
        reproductionCommand(result.seed, result.counterexamplePath),
    );
  }
  return result;
}

export function reportFuzzConfiguration() {
  const profile = FUZZ_RUNS === EXTENDED_FUZZ_RUNS ? 'extended' : 'normal';
  process.stdout.write(
    `RC08 fuzz seed=${FUZZ_SEED} runs=${FUZZ_RUNS} profile=${profile}` +
      (FUZZ_PATH ? ` path=${FUZZ_PATH}` : '') +
      '\n',
  );
}
