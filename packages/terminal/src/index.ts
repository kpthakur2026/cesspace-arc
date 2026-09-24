import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { resolve, basename, sep } from 'node:path';
import {
  ArcError,
  type RunCommandRequest,
  type RunCommandResponse,
  type ProcessStatusResponse,
  type ProcessOutputResponse,
  type TerminateProcessResponse,
  type PolicyEvaluationContext,
  validateCommandRequest,
  RC02_PERMITTED_EXECUTABLES,
  RC02_FORBIDDEN_EXECUTABLES,
  ALLOWED_ENV_KEYS,
  FORBIDDEN_ENV_PATTERNS,
} from '@cesspace-arc/protocol';
import { ProcessRegistry, MAX_OUTPUT_READ_BYTES } from '@cesspace-arc/processes';

export {
  RC02_PERMITTED_EXECUTABLES as ALLOWED_EXECUTABLES,
  RC02_FORBIDDEN_EXECUTABLES as DENIED_EXECUTABLES,
  ALLOWED_ENV_KEYS,
  FORBIDDEN_ENV_PATTERNS,
};

export interface ICommandPolicy {
  validateCommand(
    executable: string,
    args: string[],
    env: Record<string, string> | undefined,
    cwd: string | undefined,
    workspaceRoot: string,
  ): void;
}

export class CommandPolicy implements ICommandPolicy {
  public validateCommand(
    executable: string,
    args: string[] = [],
    env: Record<string, string> | undefined,
    cwd: string | undefined,
    workspaceRoot: string,
  ): void {
    const result = validateCommandRequest(executable, args, env, cwd, workspaceRoot);
    if (!result.valid) {
      if (
        result.ruleId === 'deny-invalid-argument' ||
        result.ruleId === 'deny-invalid-env-value' ||
        result.ruleId === 'deny-invalid-executable'
      ) {
        throw ArcError.invalidRequestSchema(result.reason || 'Invalid command request schema.');
      }
      throw ArcError.policyDenied(result.reason || 'Command violates security policy.');
    }
  }
}

export interface IExecutableResolver {
  resolveExecutable(name: string, workspaceRoot?: string): string;
}

export class ExecutableResolver implements IExecutableResolver {
  private trustedDirs: string[];
  private allowCurrentNodeRuntime: boolean;
  private nodeCandidate: string;

  constructor(
    customTrustedDirs?: string[],
    allowCurrentNodeRuntime?: boolean,
    customNodeCandidate?: string,
  ) {
    this.trustedDirs = customTrustedDirs || ['/usr/bin', '/bin', '/usr/local/bin'];
    this.allowCurrentNodeRuntime =
      allowCurrentNodeRuntime !== undefined ? allowCurrentNodeRuntime : !customTrustedDirs;
    this.nodeCandidate = customNodeCandidate || process.execPath;
  }

  private validateKernelBoundNodeLinux(untrustedRoots: string[]): string | null {
    if (process.platform !== 'linux') return null;

    const procExe = '/proc/self/exe';
    try {
      if (!existsSync(procExe)) return null;

      // ── Step 1: resolve canonical paths ─────────────────────────────────────
      // Both paths are resolved in the same VFS namespace so they are directly
      // comparable even when overlayfs or bind-mounts are present.
      const candidate = this.nodeCandidate; // defaults to process.execPath
      if (!candidate || typeof candidate !== 'string' || !existsSync(candidate)) return null;

      const realProcExe = realpathSync(procExe);
      const realCandidate = realpathSync(candidate);

      // ── Step 2: both basenames must be 'node' ────────────────────────────────
      if (basename(realProcExe).toLowerCase() !== 'node') return null;
      if (basename(realCandidate).toLowerCase() !== 'node') return null;
      // Also check the raw candidate basename (catches symlink names like 'node18')
      if (basename(candidate).toLowerCase() !== 'node') return null;

      // ── Step 3: stat both targets ────────────────────────────────────────────
      // statSync follows symlinks — for /proc/self/exe it resolves to the actual
      // binary on disk, so the stat reflects the real file's metadata.
      const procStat = statSync(procExe);
      const candidateStat = statSync(candidate);

      // Both must be regular executable files.
      if (!procStat.isFile() || (procStat.mode & 0o111) === 0) return null;
      if (!candidateStat.isFile() || (candidateStat.mode & 0o111) === 0) return null;

      // ── Step 4: triple kernel identity proof ─────────────────────────────────
      // Require ALL three to agree: canonical path, device, and inode.
      // The GitHub diagnostics confirmed these match (dev=2049, ino=557445)
      // even when the binary happens to carry mode 0777.
      if (realProcExe !== realCandidate) return null;
      if (procStat.dev !== candidateStat.dev || procStat.ino !== candidateStat.ino) return null;

      // ── Step 5: untrusted-root guard ─────────────────────────────────────────
      // Reject if the resolved path lands inside workspace, cwd, or
      // node_modules — even if the kernel identifies it as the active runtime.
      //
      // The caller intentionally passes only workspace and cwd as untrustedRoots
      // (preserving root provenance without passing HOME), so HOME alone does not
      // veto the exact kernel-bound current Node runtime. However, if workspaceRoot
      // or cwd equals or contains the path, that security boundary is strictly enforced.
      const isUntrusted = untrustedRoots.some(
        (root) => realProcExe === root || realProcExe.startsWith(root + sep),
      );
      if (
        isUntrusted ||
        realProcExe.includes(`${sep}node_modules${sep}`) ||
        realProcExe.endsWith(`${sep}node_modules`)
      ) {
        return null;
      }

      // ── Decision ─────────────────────────────────────────────────────────────
      // All three identity proofs passed. The active Node runtime is already
      // part of ARC's trusted computing base; granting execution through
      // /proc/self/exe does not extend trust to any other path, directory,
      // sibling, or toolcache location.
      //
      // World-writable / group-writable checks are intentionally NOT applied
      // here: the trust source is kernel identity, not filesystem permissions.
      // This exception is ONLY valid because:
      //   (a) we are on Linux,
      //   (b) the executable is exactly "node",
      //   (c) /proc/self/exe is the kernel-authoritative identity of the process
      //       that is already executing ARC,
      //   (d) realpath, dev, and ino all confirm it is the same physical file.
      //
      // Return /proc/self/exe — not process.execPath — so the kernel resolves
      // the target at exec() time with no PATH lookup.
      return procExe;
    } catch {
      return null;
    }
  }

  public resolveExecutable(name: string, workspaceRoot?: string): string {
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      throw ArcError.invalidRequestSchema('Executable name must be a non-empty string.');
    }

    const trimmed = name.trim();

    // Reject path separators in executable name (must not be relative/absolute path)
    if (trimmed.includes('/') || trimmed.includes('\\')) {
      throw ArcError.forbiddenCommand(
        `Direct path invocation for executable '${trimmed}' is forbidden. Provide bare executable name.`,
      );
    }

    // Preserve provenance across untrusted roots:
    // - Kernel-bound active Node validation requires workspaceRoot and cwd boundaries,
    //   but HOME alone must not veto the active runtime.
    // - Generic lookup requires all boundaries: workspaceRoot, HOME, and cwd.
    const workspaceRootCanonical = workspaceRoot ? resolve(workspaceRoot) : null;
    const homeRootCanonical = process.env.HOME ? resolve(process.env.HOME) : null;
    const cwdRootCanonical = resolve(process.cwd());

    const kernelUntrustedRoots: string[] = [];
    if (workspaceRootCanonical) kernelUntrustedRoots.push(workspaceRootCanonical);
    kernelUntrustedRoots.push(cwdRootCanonical);

    // 1. On Linux, prefer kernel-bound current Node runtime identity (/proc/self/exe)
    if (trimmed === 'node' && this.allowCurrentNodeRuntime && process.platform === 'linux') {
      const kernelNode = this.validateKernelBoundNodeLinux(kernelUntrustedRoots);
      if (kernelNode) {
        return kernelNode;
      }
    }

    const genericUntrustedRoots: string[] = [...kernelUntrustedRoots];
    if (homeRootCanonical) genericUntrustedRoots.push(homeRootCanonical);

    // 2. Search Fixed Trusted System Locations ONLY
    for (const dir of this.trustedDirs) {
      if (!existsSync(dir)) continue;

      let dirStat;
      try {
        dirStat = statSync(dir);
      } catch {
        continue;
      }
      if (!dirStat.isDirectory()) continue;

      // On POSIX, reject directory if world-writable or group-writable by non-root
      if (process.platform !== 'win32') {
        if ((dirStat.mode & 0o002) !== 0) {
          // World writable directory is untrusted
          continue;
        }
        if ((dirStat.mode & 0o020) !== 0 && dirStat.uid !== 0) {
          // Group writable by non-root is untrusted
          continue;
        }
      }

      const candidate = resolve(dir, trimmed);
      if (existsSync(candidate)) {
        try {
          const stat = statSync(candidate);
          if (!stat.isFile() || (stat.mode & 0o111) === 0) {
            continue;
          }

          // On POSIX, reject candidate if world-writable or group-writable by non-root
          if (process.platform !== 'win32') {
            if ((stat.mode & 0o002) !== 0) {
              continue;
            }
            if ((stat.mode & 0o020) !== 0 && stat.uid !== 0) {
              continue;
            }
          }

          const real = realpathSync(candidate);

          // Verify realpath does not resolve into untrusted roots or node_modules
          const isUntrusted = genericUntrustedRoots.some(
            (root) => real === root || real.startsWith(root + sep),
          );
          if (
            isUntrusted ||
            real.includes(`${sep}node_modules${sep}`) ||
            real.endsWith(`${sep}node_modules`)
          ) {
            continue;
          }

          // Verify target realpath file permissions as well
          const realStat = statSync(real);
          if (process.platform !== 'win32') {
            if (
              (realStat.mode & 0o002) !== 0 ||
              ((realStat.mode & 0o020) !== 0 && realStat.uid !== 0)
            ) {
              continue;
            }
          }

          return real;
        } catch {
          // ignore unresolvable
        }
      }
    }

    throw ArcError.forbiddenCommand(
      `Executable '${trimmed}' could not be resolved from trusted system locations.`,
    );
  }
}

export interface ITerminalSubsystem {
  executeCommand(
    request: RunCommandRequest,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<RunCommandResponse>;
  getProcessStatus(
    processId: string,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): ProcessStatusResponse;
  getProcessOutput(
    processId: string,
    optionsOrOffset:
      | number
      | {
          offset?: number;
          stdoutCursor?: number;
          stderrCursor?: number;
          maxBytes?: number;
          workspaceId?: string;
        }
      | undefined,
    maxBytes: number | undefined,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): ProcessOutputResponse;
  terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' | undefined,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<TerminateProcessResponse>;
}

/**
 * Type-level representation of the non-forgeable internal execution authority.
 * Deliberately possesses no public factory (.create()) or constructible API.
 */
export class InternalExecutionCapability {
  private constructor() {
    throw new TypeError('InternalExecutionCapability cannot be instantiated directly');
  }
}

/**
 * A server-materialized deterministic execution step for higher-level composite tools.
 */
export interface DeterministicExecutionStep {
  stepId: string;
  executable: string;
  args: string[];
  cwd: string; // workspace-relative path or empty string for workspace root
  timeoutMs: number;
  outputLimitBytes: number;
  projectCodeExecution: boolean;
  sideEffectClass: 'READ_ONLY' | 'EXECUTION';
}

/**
 * Outcome of executing a deterministic step.
 */
export interface DeterministicStepResult {
  stepId: string;
  processId: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Separate internal authority interface for deterministic composite execution.
 * Held privately by trusted server composition; never exposed on public ITerminalSubsystem.
 */
export interface IInternalDeterministicExecutor {
  executeDeterministicStep(
    step: DeterministicExecutionStep,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<DeterministicStepResult>;
}

interface InternalProcessExecutionSpec {
  workspaceId: string;
  actor: {
    clientId: string;
    clientType: string;
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
}

interface InternalProcessExecutionResult {
  processId: string;
  state: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TERMINATED' | 'TIMED_OUT';
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export class ControlledProcessRunner implements ITerminalSubsystem {
  constructor(
    public readonly processRegistry: ProcessRegistry,
    public readonly commandPolicy: ICommandPolicy = new CommandPolicy(),
    public readonly executableResolver: IExecutableResolver = new ExecutableResolver(),
  ) {}

  public async executeCommand(
    request: RunCommandRequest,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<RunCommandResponse> {
    const workspaceRoot = targetWorkspace.rootPath;

    if (
      !actor.clientId ||
      !actor.sessionId ||
      actor.clientId.trim().length === 0 ||
      actor.sessionId.trim().length === 0
    ) {
      throw ArcError.policyDenied(
        'Access denied: run_command requires verified caller identity (clientId and sessionId).',
      );
    }

    if (!workspaceRoot || !existsSync(workspaceRoot)) {
      throw ArcError.noWorkspaceConfigured('Authorized workspace root is required for execution.');
    }

    // 1. Resolve and Validate Working Directory (cwd)
    let executionCwd = workspaceRoot;
    if (request.cwd) {
      const rawCwd = request.cwd.trim();
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

    const args = request.args || [];

    // 2. Command Policy Pre-Admission Validation
    this.commandPolicy.validateCommand(
      request.executable,
      args,
      request.env,
      request.cwd,
      workspaceRoot,
    );

    // 3. Trusted Executable Resolution
    const resolvedExecutable = this.executableResolver.resolveExecutable(
      request.executable,
      workspaceRoot,
    );

    // 4. Environment Sanitization
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

    if (request.env) {
      for (const [key, val] of Object.entries(request.env)) {
        sanitizedEnv[key] = val;
      }
    }

    // 5. Concurrency Check & Registration
    const timeoutMs = Math.min(Math.max(100, request.timeoutMs ?? 30000), 300000);

    const result = await this.#spawnAndControlProcess({
      workspaceId: targetWorkspace.workspaceId,
      actor: {
        clientId: actor.clientId,
        clientType: actor.clientType,
        sessionId: actor.sessionId,
        deviceId: actor.deviceId,
      },
      resolvedExecutable,
      rawExecutableName: request.executable,
      args,
      executionCwd,
      env: sanitizedEnv,
      timeoutMs,
      outputLimitBytes: MAX_OUTPUT_READ_BYTES,
      runInBackground: request.runInBackground,
    });

    return {
      processId: result.processId,
      state: result.state,
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: result.stdout,
      stderr: result.stderr,
      timedOut: result.timedOut,
      durationMs: result.durationMs,
    };
  }

  /**
   * One shared private controlled-process execution core.
   * Handles ProcessRegistry registration, spawn, output streaming, timeout handling,
   * signal escalation, and completion for both public and internal paths.
   */
  async #spawnAndControlProcess(
    spec: InternalProcessExecutionSpec,
  ): Promise<InternalProcessExecutionResult> {
    const startTime = Date.now();

    const record = this.processRegistry.registerProcess({
      workspaceId: spec.workspaceId,
      actor: spec.actor,
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
        this.processRegistry.notifySpawnSuccess(record.processId);
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.processRegistry.markSpawnFailed(record.processId, errMsg);
      throw ArcError.internalError(`Failed to spawn process: ${errMsg}`);
    }

    // Output Stream Plumbing
    child.stdout?.on('data', (chunk: Buffer) => {
      this.processRegistry.appendOutput(record.processId, 'stdout', chunk);
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      this.processRegistry.appendOutput(record.processId, 'stderr', chunk);
    });

    // Timeout Setup
    record._timeoutTimer = setTimeout(() => {
      this.processRegistry.markTimedOut(record.processId);
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
    }, spec.timeoutMs);
    record._timeoutTimer.unref();

    child.on('close', (code, signal) => {
      this.processRegistry.markCompleted(record.processId, code, signal);
    });

    child.on('error', (err) => {
      if (!spawnSucceeded) {
        this.processRegistry.markSpawnFailed(record.processId, err.message);
      } else {
        this.processRegistry.markCompleted(record.processId, 1, null);
      }
    });

    if (spec.runInBackground) {
      // Ensure the spawn event or spawn error has been emitted before returning
      // so PROCESS_SPAWN_SUCCEEDED is reliably emitted and available in audit sinks.
      if (
        !spawnSucceeded &&
        !child.killed &&
        child.exitCode === null &&
        record.state === 'RUNNING'
      ) {
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
          this.processRegistry.markSpawnFailed(record.processId, 'Process failed to spawn');
        }
        const status = this.processRegistry.getProcessStatus(record.processId, {
          clientId: spec.actor.clientId,
          sessionId: spec.actor.sessionId,
          workspaceId: spec.workspaceId,
        });
        const output = this.processRegistry.getProcessOutput(
          record.processId,
          0,
          spec.outputLimitBytes,
          {
            clientId: spec.actor.clientId,
            sessionId: spec.actor.sessionId,
            workspaceId: spec.workspaceId,
          },
        );
        return {
          processId: record.processId,
          state: status.state,
          exitCode: status.exitCode ?? null,
          signal: (status.signal as NodeJS.Signals | null) ?? null,
          stdout: output.stdoutChunk,
          stderr: output.stderrChunk,
          timedOut: status.timedOut,
          durationMs: status.durationMs,
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
      };
    }

    // Await completion or timeout
    await new Promise<void>((resolvePromise) => {
      child.on('close', () => resolvePromise());
      child.on('error', () => resolvePromise());
    });

    const status = this.processRegistry.getProcessStatus(record.processId, {
      clientId: spec.actor.clientId,
      sessionId: spec.actor.sessionId,
      workspaceId: spec.workspaceId,
    });
    const output = this.processRegistry.getProcessOutput(
      record.processId,
      0,
      spec.outputLimitBytes,
      {
        clientId: spec.actor.clientId,
        sessionId: spec.actor.sessionId,
        workspaceId: spec.workspaceId,
      },
    );

    return {
      processId: record.processId,
      state: status.state,
      exitCode: status.exitCode ?? null,
      signal: (status.signal as NodeJS.Signals | null) ?? null,
      stdout: output.stdoutChunk,
      stderr: output.stderrChunk,
      timedOut: status.timedOut,
      durationMs: status.durationMs,
    };
  }

  public getProcessStatus(
    processId: string,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): ProcessStatusResponse {
    return this.processRegistry.getProcessStatus(processId, {
      clientId: actor.clientId,
      sessionId: actor.sessionId || '',
      workspaceId: targetWorkspace?.workspaceId,
    });
  }

  public getProcessOutput(
    processId: string,
    optionsOrOffset:
      | number
      | {
          offset?: number;
          stdoutCursor?: number;
          stderrCursor?: number;
          maxBytes?: number;
          workspaceId?: string;
        }
      | undefined,
    maxBytes: number | undefined,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): ProcessOutputResponse {
    return this.processRegistry.getProcessOutput(processId, optionsOrOffset, maxBytes, {
      clientId: actor.clientId,
      sessionId: actor.sessionId || '',
      workspaceId: targetWorkspace?.workspaceId,
    });
  }

  public async terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' | undefined,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace?: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<TerminateProcessResponse> {
    return this.processRegistry.terminateProcess(processId, signal, {
      clientId: actor.clientId,
      sessionId: actor.sessionId || '',
      workspaceId: targetWorkspace?.workspaceId,
    });
  }
}
