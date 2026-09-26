/**
 * Package-internal deterministic execution seam for @cesspace-arc/terminal.
 *
 * This module is NOT exported from the package root (packages/terminal/src/index.ts)
 * and is NEVER accessible from the public runtime surface.
 * @internal
 */

import { existsSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import { MAX_OUTPUT_READ_BYTES } from '@cesspace-arc/processes';
import type {
  ControlledProcessRunner,
  DeterministicExecutionStep,
  DeterministicStepResult,
} from '../index.js';
import { spawnAndControlProcess } from './process-machinery.js';

export const TERMINAL_EXECUTION_SEAM_TOKEN = Symbol('arc.terminal.executionSeamToken');

const seamRequire = createRequire(import.meta.url);

function resolveServerCliEntrypoint(pkgName: string, subpath: string): string {
  try {
    const pkgJsonPath = seamRequire.resolve(`${pkgName}/package.json`);
    const entrypoint = resolve(dirname(pkgJsonPath), subpath);
    if (existsSync(entrypoint)) {
      return entrypoint;
    }
  } catch {
    // fail closed below
  }
  throw ArcError.internalError(
    `Server-approved tool entrypoint for '${pkgName}' could not be resolved.`,
  );
}

function resolveServerTypecheckEntrypoint(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(currentDir, 'solution-typecheck.js'),
    resolve(currentDir, '../dist/internal/solution-typecheck.js'),
    resolve(currentDir, '../../dist/internal/solution-typecheck.js'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw ArcError.internalError(
    'Server-approved solution typecheck entrypoint could not be resolved.',
  );
}

/**
 * Executes a deterministic step by dispatching to the terminal subsystem's low-level
 * controlled-process machinery and ProcessRegistry.
 *
 * Owns workspace jailing, CWD canonicalization, trusted executable resolution,
 * and environment sanitization.
 */
export async function executeDeterministicStepCore(
  runner: ControlledProcessRunner,
  step: DeterministicExecutionStep,
  actor: PolicyEvaluationContext['actor'],
  targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  token: symbol,
): Promise<DeterministicStepResult> {
  if (token !== TERMINAL_EXECUTION_SEAM_TOKEN) {
    throw ArcError.forbiddenCommand(
      'Access denied: execution seam requires internal capability token.',
    );
  }

  const workspaceRoot = targetWorkspace.rootPath;

  if (
    !actor.clientId ||
    !actor.sessionId ||
    actor.clientId.trim().length === 0 ||
    actor.sessionId.trim().length === 0
  ) {
    throw ArcError.unauthenticated(
      'Access denied: internal deterministic execution requires verified caller identity (clientId and sessionId).',
    );
  }

  if (!workspaceRoot || !existsSync(workspaceRoot)) {
    throw ArcError.noWorkspaceConfigured('Authorized workspace root is required for execution.');
  }

  // 1. Resolve and Validate Working Directory (cwd)
  let executionCwd = workspaceRoot;
  if (step.cwd && step.cwd.trim().length > 0) {
    const rawCwd = step.cwd.trim();
    const resolvedCwd = resolve(workspaceRoot, rawCwd);
    if (!existsSync(resolvedCwd)) {
      throw ArcError.fileNotFound(`Execution working directory does not exist: '${rawCwd}'.`);
    }
    let canonicalCwd: string;
    try {
      canonicalCwd = realpathSync(resolvedCwd);
    } catch {
      throw ArcError.pathEscapesRoot('Failed to canonicalize execution working directory.');
    }
    if (canonicalCwd !== workspaceRoot && !canonicalCwd.startsWith(workspaceRoot + sep)) {
      throw ArcError.pathEscapesRoot(
        'Security violation: Working directory resolves outside authorized workspace.',
      );
    }
    executionCwd = canonicalCwd;
  }

  let physicalExecutable = step.executable;
  let physicalArgs = step.args || [];

  if (step.executable === 'prettier') {
    physicalExecutable = 'node';
    const entrypoint = resolveServerCliEntrypoint('prettier', 'bin/prettier.cjs');
    physicalArgs = [entrypoint, ...(step.args || [])];
  } else if (step.executable === 'eslint') {
    physicalExecutable = 'node';
    const entrypoint = resolveServerCliEntrypoint('eslint', 'bin/eslint.js');
    physicalArgs = [entrypoint, ...(step.args || [])];
  } else if (step.executable === 'tsc') {
    physicalExecutable = 'node';
    const entrypoint = resolveServerTypecheckEntrypoint();
    physicalArgs = [entrypoint, ...(step.args || [])];
  }

  // 2. Executable resolution via runner's resolver
  const resolvedExecutable = runner.executableResolver.resolveExecutable(
    physicalExecutable,
    workspaceRoot,
  );

  // 3. Environment Sanitization (fixed sanitized environment; no ambient secrets)
  const trustedPath = '/usr/bin:/bin:/usr/local/bin';
  const sanitizedEnv: NodeJS.ProcessEnv = {
    PATH: trustedPath,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NODE_ENV: 'test',
  };

  if (basename(resolvedExecutable).toLowerCase() === 'git') {
    sanitizedEnv.GIT_OPTIONAL_LOCKS = '0';
    sanitizedEnv.GIT_CONFIG_GLOBAL = '/dev/null';
    sanitizedEnv.GIT_CONFIG_NOSYSTEM = '1';
  }

  const timeoutMs = Math.min(Math.max(100, step.timeoutMs ?? 30000), 120000);
  const maxOutputBytes = Math.min(
    Math.max(1024, step.outputLimitBytes ?? MAX_OUTPUT_READ_BYTES),
    MAX_OUTPUT_READ_BYTES,
  );

  // 4. Dispatch to the shared low-level controlled process engine
  const result = await spawnAndControlProcess(runner.processRegistry, {
    workspaceId: targetWorkspace.workspaceId,
    actor: {
      clientId: actor.clientId,
      clientType: actor.clientType || 'agent',
      sessionId: actor.sessionId,
      deviceId: actor.deviceId,
    },
    resolvedExecutable,
    rawExecutableName: step.executable,
    args: physicalArgs,
    executionCwd,
    env: sanitizedEnv,
    timeoutMs,
    outputLimitBytes: maxOutputBytes,
    runInBackground: false,
    signal: step.signal,
  });

  return {
    stepId: step.stepId,
    processId: result.processId,
    exitCode: result.exitCode,
    signal: result.signal,
    stdout: result.stdout,
    stderr: result.stderr,
    durationMs: result.durationMs,
    timedOut: result.timedOut,
    truncated: result.truncated,
  };
}
