import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { resolve, basename, dirname, sep } from 'node:path';
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

  private validateExactNodeCandidate(candidate: string, untrustedRoots: string[]): string | null {
    if (!candidate || typeof candidate !== 'string') return null;

    try {
      if (!existsSync(candidate)) return null;

      const stat = statSync(candidate);
      if (!stat.isFile() || (stat.mode & 0o111) === 0) return null;

      // Check candidate permissions on POSIX
      if (process.platform !== 'win32') {
        if ((stat.mode & 0o002) !== 0) return null; // world-writable
        if ((stat.mode & 0o020) !== 0 && stat.uid !== 0) return null; // group-writable by non-root
      }

      const real = realpathSync(candidate);
      const realStat = statSync(real);
      if (!realStat.isFile() || (realStat.mode & 0o111) === 0) return null;

      // Check realpath permissions on POSIX
      if (process.platform !== 'win32') {
        if ((realStat.mode & 0o002) !== 0) return null;
        if ((realStat.mode & 0o020) !== 0 && realStat.uid !== 0) return null;
      }

      // Check parent directory permissions on POSIX
      const parentDir = dirname(real);
      if (!existsSync(parentDir)) return null;
      const parentStat = statSync(parentDir);
      if (!parentStat.isDirectory()) return null;
      if (process.platform !== 'win32') {
        if ((parentStat.mode & 0o002) !== 0) return null;
        if ((parentStat.mode & 0o020) !== 0 && parentStat.uid !== 0) return null;
      }

      // Must NOT resolve under workspace, HOME, current directory, or node_modules
      const isUntrusted = untrustedRoots.some(
        (root) => real === root || real.startsWith(root + sep),
      );
      if (
        isUntrusted ||
        real.includes(`${sep}node_modules${sep}`) ||
        real.endsWith(`${sep}node_modules`)
      ) {
        return null;
      }

      // Preserve exact executable identity (must be 'node' or 'node.exe')
      const base = basename(real).toLowerCase();
      if (base !== 'node' && base !== 'node.exe') {
        return null;
      }

      return real;
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

    // Never trust workspace, HOME, current directory, or node_modules
    const untrustedRoots: string[] = [];
    if (workspaceRoot) untrustedRoots.push(resolve(workspaceRoot));
    if (process.env.HOME) untrustedRoots.push(resolve(process.env.HOME));
    untrustedRoots.push(resolve(process.cwd()));

    // 1. Search Fixed Trusted System Locations ONLY
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
          const isUntrusted = untrustedRoots.some(
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

    // 2. Exact current Node runtime fallback (for 'node' executable only)
    if (trimmed === 'node' && this.allowCurrentNodeRuntime) {
      const validatedNode = this.validateExactNodeCandidate(this.nodeCandidate, untrustedRoots);
      if (validatedNode) {
        return validatedNode;
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
    const startTime = Date.now();
    const workspaceRoot = targetWorkspace.rootPath;

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

    const record = this.processRegistry.registerProcess({
      workspaceId: targetWorkspace.workspaceId,
      actor: {
        clientId: actor.clientId,
        clientType: actor.clientType,
        sessionId: actor.sessionId || 'default-session',
        deviceId: actor.deviceId,
      },
      executable: request.executable,
      sanitizedArgs: args,
      cwd: executionCwd,
      startedAt: new Date(startTime).toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    // 6. Spawn Child Process (shell: false, detached: true on POSIX for process group kill)
    let child: ChildProcess;
    try {
      child = spawn(resolvedExecutable, args, {
        cwd: executionCwd,
        env: sanitizedEnv,
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      record._child = child;
      this.processRegistry.notifySpawnSuccess(record.processId);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      this.processRegistry.markSpawnFailed(record.processId, errMsg);
      throw ArcError.internalError(`Failed to spawn process: ${errMsg}`);
    }

    // 7. Output Stream Plumbing
    child.stdout?.on('data', (chunk: Buffer) => {
      this.processRegistry.appendOutput(record.processId, 'stdout', chunk);
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      this.processRegistry.appendOutput(record.processId, 'stderr', chunk);
    });

    // 8. Timeout Setup
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
    }, timeoutMs);
    record._timeoutTimer.unref();

    child.on('close', (code, signal) => {
      this.processRegistry.markCompleted(record.processId, code, signal);
    });

    child.on('error', (err) => {
      if (record.state === 'RUNNING' && !child.pid) {
        this.processRegistry.markSpawnFailed(record.processId, err.message);
      } else {
        this.processRegistry.markCompleted(record.processId, 1, null);
      }
    });

    // 9. Synchronous vs Background Return
    if (request.runInBackground) {
      return {
        processId: record.processId,
        state: 'RUNNING',
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
      clientId: actor.clientId,
      sessionId: actor.sessionId || '',
      workspaceId: targetWorkspace.workspaceId,
    });
    const output = this.processRegistry.getProcessOutput(
      record.processId,
      0,
      MAX_OUTPUT_READ_BYTES,
      {
        clientId: actor.clientId,
        sessionId: actor.sessionId || '',
        workspaceId: targetWorkspace.workspaceId,
      },
    );

    return {
      processId: record.processId,
      state: status.state,
      exitCode: status.exitCode,
      signal: status.signal,
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
