/**
 * Package-internal execution authority for deterministic composite steps.
 *
 * This module and its symbols are STRICTLY package-internal and NEVER exported
 * from the public package root or package exports map.
 * @internal
 */

import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { basename, resolve, sep } from 'node:path';

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import { MAX_OUTPUT_READ_BYTES } from '@cesspace-arc/processes';
import type {
  ControlledProcessRunner,
  DeterministicExecutionStep,
  DeterministicStepResult,
  IInternalDeterministicExecutor,
} from '@cesspace-arc/terminal';

import {
  AUTHORIZED_INTERNAL_EXECUTORS,
  getActiveCompositeAdmissionTicket,
  isValidServerAdmissionTicket,
} from '../composite-framework.js';

export class ServerDeterministicExecutor implements IInternalDeterministicExecutor {
  constructor(private readonly runner: ControlledProcessRunner) {
    AUTHORIZED_INTERNAL_EXECUTORS.add(this);
  }

  public async executeDeterministicStep(
    step: DeterministicExecutionStep,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<DeterministicStepResult> {
    // 0. Active Server Admission Ticket verification (Proof D, Proof E)
    const activeTicket = getActiveCompositeAdmissionTicket();
    if (!activeTicket || !isValidServerAdmissionTicket(activeTicket) || activeTicket.consumed) {
      throw ArcError.policyDenied(
        'Access denied: privileged deterministic execution requires active server admission ticket.',
      );
    }
    if (activeTicket.workspaceId !== targetWorkspace.workspaceId) {
      throw ArcError.policyDenied('Access denied: composite admission ticket workspace mismatch.');
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
    const resolvedExecutable = this.runner.executableResolver.resolveExecutable(
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

    const startTime = Date.now();
    const record = this.runner.processRegistry.registerProcess({
      workspaceId: targetWorkspace.workspaceId,
      actor: {
        clientId: actor.clientId,
        clientType: actor.clientType || 'agent',
        sessionId: actor.sessionId,
        deviceId: actor.deviceId,
      },
      executable: step.executable,
      sanitizedArgs: args,
      cwd: executionCwd,
      startedAt: new Date(startTime).toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    let child: ChildProcess;
    let spawnSucceeded = false;
    try {
      child = spawn(resolvedExecutable, args, {
        cwd: executionCwd,
        env: sanitizedEnv,
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      record._child = child;

      child.once('spawn', () => {
        spawnSucceeded = true;
        this.runner.processRegistry.notifySpawnSuccess(record.processId);
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.runner.processRegistry.markSpawnFailed(record.processId, errMsg);
      throw ArcError.internalError(`Failed to spawn process: ${errMsg}`);
    }

    child.stdout?.on('data', (chunk: Buffer) => {
      this.runner.processRegistry.appendOutput(record.processId, 'stdout', chunk);
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      this.runner.processRegistry.appendOutput(record.processId, 'stderr', chunk);
    });

    record._timeoutTimer = setTimeout(() => {
      this.runner.processRegistry.markTimedOut(record.processId);
      try {
        if (child.pid && process.platform !== 'win32') {
          process.kill(-child.pid, 'SIGTERM');
        } else {
          child.kill('SIGTERM');
        }
      } catch {
        // ignore
      }
      record._killTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            if (child.pid && process.platform !== 'win32') {
              process.kill(-child.pid, 'SIGKILL');
            } else {
              child.kill('SIGKILL');
            }
          }
        } catch {
          // ignore
        }
      }, 1000);
      record._killTimer.unref();
    }, timeoutMs);
    record._timeoutTimer.unref();

    child.on('close', (code, signal) => {
      this.runner.processRegistry.markCompleted(record.processId, code, signal);
    });

    child.on('error', (err) => {
      if (!spawnSucceeded) {
        this.runner.processRegistry.markSpawnFailed(record.processId, err.message);
      } else {
        this.runner.processRegistry.markCompleted(record.processId, 1, null);
      }
    });

    await new Promise<void>((resolvePromise) => {
      child.on('close', () => resolvePromise());
      child.on('error', () => resolvePromise());
    });

    const status = this.runner.processRegistry.getProcessStatus(record.processId, {
      clientId: actor.clientId,
      sessionId: actor.sessionId,
      workspaceId: targetWorkspace.workspaceId,
    });
    const output = this.runner.processRegistry.getProcessOutput(
      record.processId,
      0,
      maxOutputBytes,
      {
        clientId: actor.clientId,
        sessionId: actor.sessionId,
        workspaceId: targetWorkspace.workspaceId,
      },
    );

    return {
      stepId: step.stepId,
      processId: record.processId,
      exitCode: status.exitCode ?? null,
      signal: (status.signal as NodeJS.Signals | null) ?? null,
      stdout: output.stdoutChunk,
      stderr: output.stderrChunk,
      durationMs: status.durationMs,
      timedOut: status.timedOut,
    };
  }
}

export function createServerDeterministicExecutor(
  runner: ControlledProcessRunner,
): IInternalDeterministicExecutor {
  return new ServerDeterministicExecutor(runner);
}
