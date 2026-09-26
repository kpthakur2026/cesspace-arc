/**
 * Package-internal low-level process spawning and supervision engine.
 *
 * This is the ONE shared low-level controlled-process machinery for @cesspace-arc/terminal.
 * It is NEVER exported from the package root or public package exports.
 * @internal
 */

import { type ChildProcess, spawn } from 'node:child_process';
import { ArcError } from '@cesspace-arc/protocol';
import type { ProcessRegistry } from '@cesspace-arc/processes';

export interface InternalProcessExecutionSpec {
  workspaceId: string;
  actor: {
    clientId: string;
    clientType?: string;
    sessionId: string;
    deviceId?: string;
  };
  resolvedExecutable: string;
  rawExecutableName: string;
  args: string[];
  executionCwd: string;
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  outputLimitBytes: number;
  runInBackground?: boolean;
  signal?: AbortSignal;
}

export interface InternalProcessExecutionResult {
  processId: string;
  state: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TERMINATED' | 'TIMED_OUT';
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
  truncated?: boolean;
}

/**
 * One shared low-level controlled-process execution engine.
 * Handles ProcessRegistry registration, spawn, output streaming, timeout handling,
 * signal escalation, and completion for all terminal subsystem execution paths.
 */
export async function spawnAndControlProcess(
  processRegistry: ProcessRegistry,
  spec: InternalProcessExecutionSpec,
): Promise<InternalProcessExecutionResult> {
  const startTime = Date.now();

  const record = processRegistry.registerProcess({
    workspaceId: spec.workspaceId,
    actor: {
      clientId: spec.actor.clientId,
      clientType: spec.actor.clientType || 'agent',
      sessionId: spec.actor.sessionId,
      deviceId: spec.actor.deviceId,
    },
    executable: spec.rawExecutableName,
    sanitizedArgs: spec.args,
    cwd: spec.executionCwd,
    startedAt: new Date(startTime).toISOString(),
    state: 'RUNNING',
    timedOut: false,
  });

  let child: ChildProcess;
  let spawnSucceeded = false;
  try {
    child = spawn(spec.resolvedExecutable, spec.args, {
      cwd: spec.executionCwd,
      env: spec.env,
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    record._child = child;

    // Asynchronous spawn event handling (P2):
    // Only emit PROCESS_SPAWN_SUCCEEDED after the child process actually emits the Node 'spawn' event.
    // An asynchronous spawn failure must never produce a false success event.
    child.once('spawn', () => {
      spawnSucceeded = true;
      if (child.pid && typeof processRegistry.persistProcessState === 'function') {
        processRegistry.persistProcessState(record, child.pid);
      }
      processRegistry.notifySpawnSuccess(record.processId);
    });
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    processRegistry.markSpawnFailed(record.processId, errMsg);
    throw ArcError.internalError(`Failed to spawn process: ${errMsg}`);
  }

  // Output Stream Plumbing
  child.stdout?.on('data', (chunk: Buffer) => {
    processRegistry.appendOutput(record.processId, 'stdout', chunk);
  });

  child.stderr?.on('data', (chunk: Buffer) => {
    processRegistry.appendOutput(record.processId, 'stderr', chunk);
  });

  const terminateChildWithEscalation = () => {
    if (record.timedOut || record._killTimer) {
      return;
    }

    processRegistry.markTimedOut(record.processId);
    try {
      if (child.pid && process.platform !== 'win32') {
        process.kill(-child.pid, 'SIGTERM');
      } else {
        child.kill('SIGTERM');
      }
    } catch {
      // ignore
    }
    processRegistry.notifySigtermSent(record.processId);

    record._killTimer = setTimeout(() => {
      try {
        if (child.pid && process.platform !== 'win32') {
          processRegistry.notifySigkillEscalated(record.processId);
          process.kill(-child.pid, 'SIGKILL');
        } else if (child.exitCode === null && child.signalCode === null) {
          processRegistry.notifySigkillEscalated(record.processId);
          child.kill('SIGKILL');
        }
      } catch {
        // ESRCH / already-dead process group should be handled harmlessly
      } finally {
        record._killTimer = undefined;
      }
    }, 1000);
    record._killTimer.unref();
  };

  // Timeout Setup
  record._timeoutTimer = setTimeout(terminateChildWithEscalation, spec.timeoutMs);
  record._timeoutTimer.unref();

  // AbortSignal Setup
  if (spec.signal) {
    if (spec.signal.aborted) {
      terminateChildWithEscalation();
    } else {
      const onAbort = () => {
        terminateChildWithEscalation();
      };
      spec.signal.addEventListener('abort', onAbort, { once: true });
      child.on('close', () => {
        spec.signal?.removeEventListener('abort', onAbort);
      });
    }
  }

  child.on('close', (code, signal) => {
    processRegistry.markCompleted(record.processId, code, signal);
  });

  child.on('error', (err) => {
    if (!spawnSucceeded) {
      processRegistry.markSpawnFailed(record.processId, err.message);
    } else {
      processRegistry.markCompleted(record.processId, 1, null);
    }
  });

  if (spec.runInBackground) {
    // Ensure the spawn event or spawn error has been emitted before returning
    // so PROCESS_SPAWN_SUCCEEDED is reliably emitted and available in audit sinks.
    if (!spawnSucceeded && !child.killed && child.exitCode === null && record.state === 'RUNNING') {
      await new Promise<void>((resolvePromise) => {
        const cleanup = () => {
          clearTimeout(timer);
          child.removeListener('spawn', onSpawn);
          child.removeListener('error', onError);
        };
        const onSpawn = () => {
          cleanup();
          resolvePromise();
        };
        const onError = () => {
          cleanup();
          resolvePromise();
        };
        const onTimeout = () => {
          cleanup();
          resolvePromise();
        };
        const timer: NodeJS.Timeout = setTimeout(onTimeout, Math.min(spec.timeoutMs, 5000));
        timer.unref();
        child.once('spawn', onSpawn);
        child.once('error', onError);
      });
    }

    // If spawn failed or child encountered an asynchronous error before spawn, fail closed / report truthful state
    if (!spawnSucceeded || record.state === 'FAILED') {
      if (
        record.state !== 'FAILED' &&
        record.state !== 'COMPLETED' &&
        record.state !== 'TERMINATED'
      ) {
        processRegistry.markSpawnFailed(record.processId, 'Process failed to spawn');
      }
      const status = processRegistry.getProcessStatus(record.processId, {
        clientId: spec.actor.clientId,
        sessionId: spec.actor.sessionId,
        workspaceId: spec.workspaceId,
      });
      const output = processRegistry.getProcessOutput(record.processId, 0, spec.outputLimitBytes, {
        clientId: spec.actor.clientId,
        sessionId: spec.actor.sessionId,
        workspaceId: spec.workspaceId,
      });
      const isTruncated = output.truncated || !output.complete;
      return {
        processId: record.processId,
        state: status.state,
        exitCode: status.exitCode ?? null,
        signal: (status.signal as NodeJS.Signals | null) ?? null,
        stdout: output.stdoutChunk,
        stderr: output.stderrChunk,
        timedOut: status.timedOut,
        durationMs: status.durationMs,
        truncated: isTruncated,
      };
    }

    return {
      processId: record.processId,
      state: 'RUNNING',
      exitCode: null,
      signal: null,
      stdout: '',
      stderr: '',
      timedOut: false,
      durationMs: 0,
      truncated: false,
    };
  }

  // Await completion or timeout
  await new Promise<void>((resolvePromise) => {
    child.on('close', () => resolvePromise());
    child.on('error', () => resolvePromise());
  });

  const status = processRegistry.getProcessStatus(record.processId, {
    clientId: spec.actor.clientId,
    sessionId: spec.actor.sessionId,
    workspaceId: spec.workspaceId,
  });
  const output = processRegistry.getProcessOutput(record.processId, 0, spec.outputLimitBytes, {
    clientId: spec.actor.clientId,
    sessionId: spec.actor.sessionId,
    workspaceId: spec.workspaceId,
  });
  const isTruncated = output.truncated || !output.complete;

  return {
    processId: record.processId,
    state: status.state,
    exitCode: status.exitCode ?? null,
    signal: (status.signal as NodeJS.Signals | null) ?? null,
    stdout: output.stdoutChunk,
    stderr: output.stderrChunk,
    timedOut: status.timedOut,
    durationMs: status.durationMs,
    truncated: isTruncated,
  };
}
