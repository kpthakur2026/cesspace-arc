/**
 * Package-internal deterministic execution seam for @cesspace-arc/terminal.
 *
 * This module is NOT exported from the package root (packages/terminal/src/index.ts)
 * and is NEVER accessible from the public runtime surface.
 * @internal
 */

import { existsSync, realpathSync } from 'node:fs';
import { basename, resolve, sep } from 'node:path';

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import { MAX_OUTPUT_READ_BYTES } from '@cesspace-arc/processes';
import type {
  ControlledProcessRunner,
  DeterministicExecutionStep,
  DeterministicStepResult,
} from '../index.js';
import { spawnAndControlProcess } from './process-machinery.js';

export const TERMINAL_EXECUTION_SEAM_TOKEN = Symbol('arc.terminal.executionSeamToken');

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

  const args = step.args || [];

  // 2. Executable resolution via runner's resolver
  const resolvedExecutable = runner.executableResolver.resolveExecutable(
    step.executable,
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
    args,
    executionCwd,
    env: sanitizedEnv,
    timeoutMs,
    outputLimitBytes: maxOutputBytes,
    runInBackground: false,
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
  };
}
