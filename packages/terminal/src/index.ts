import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { resolve, dirname, basename, sep } from 'node:path';
import {
  ArcError,
  type RunCommandRequest,
  type RunCommandResponse,
  type ProcessStatusResponse,
  type ProcessOutputResponse,
  type TerminateProcessResponse,
  type PolicyEvaluationContext,
} from '@cesspace-arc/protocol';
import { ProcessRegistry, MAX_OUTPUT_READ_BYTES } from '@cesspace-arc/processes';

/**
 * Approved development executables for RC-02.
 */
export const ALLOWED_EXECUTABLES = [
  'node',
  'npm',
  'pnpm',
  'npx',
  'git',
  'tsc',
  'eslint',
  'prettier',
  'vitest',
  'pytest',
] as const;

/**
 * Explicitly denied commands and command classes.
 */
export const DENIED_EXECUTABLES = [
  'sudo',
  'su',
  'doas',
  'pkexec',
  'bash',
  'sh',
  'zsh',
  'fish',
  'dash',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'rm',
  'rmdir',
  'mkfs',
  'fdisk',
  'parted',
  'mount',
  'umount',
  'dd',
  'shutdown',
  'reboot',
  'poweroff',
  'halt',
  'curl',
  'wget',
  'ssh',
  'scp',
  'sftp',
  'nc',
  'netcat',
  'socat',
  'docker',
  'kubectl',
  'terraform',
  'aws',
  'gcloud',
  'az',
  'systemctl',
  'service',
  'crontab',
  'python',
  'python3',
  'perl',
  'ruby',
  'php',
] as const;

/**
 * Permitted environment override keys.
 */
export const ALLOWED_ENV_KEYS = ['CI', 'FORCE_COLOR', 'NO_COLOR', 'DEBUG', 'NODE_ENV'] as const;

/**
 * Forbidden environment variable patterns (credentials, tokens, hijacking).
 */
export const FORBIDDEN_ENV_PATTERNS = [
  /^AWS_/i,
  /^GOOGLE_/i,
  /^GCP_/i,
  /^AZURE_/i,
  /^ANTHROPIC_/i,
  /^OPENAI_/i,
  /.*TOKEN$/i,
  /.*KEY$/i,
  /.*SECRET$/i,
  /.*AUTH/i,
  /DATABASE_URL/i,
  /SSH_AUTH_SOCK/i,
  /LD_PRELOAD/i,
  /LD_LIBRARY_PATH/i,
  /NODE_OPTIONS/i,
  /^PATH$/i,
  /^HOME$/i,
  /^PYTHONPATH$/i,
  /^SHELL$/i,
  /^USER$/i,
  /^SUDO_USER$/i,
];

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
    _cwd: string | undefined,
    _workspaceRoot: string,
  ): void {
    const rawName = basename(executable).toLowerCase();

    // 1. Explicitly Denied Commands
    if ((DENIED_EXECUTABLES as readonly string[]).includes(rawName)) {
      throw ArcError.forbiddenCommand(
        `Command '${rawName}' is explicitly forbidden by security policy (privilege escalation, raw shell, or destructive operation).`,
      );
    }

    // 2. Allowlist Enforcement (Default-Deny)
    if (!(ALLOWED_EXECUTABLES as readonly string[]).includes(rawName)) {
      throw ArcError.policyDenied(
        `Executable '${rawName}' is not in the approved RC-02 development tool allowlist.`,
      );
    }

    // 3. Shell and Metacharacter Injection Guard
    for (const arg of args) {
      if (typeof arg !== 'string') {
        throw ArcError.invalidRequestSchema('Command arguments must be strings.');
      }
      // Check for command substitution or shell execution flags
      if (
        arg === '-c' ||
        arg === '/c' ||
        arg.startsWith('--command') ||
        arg.includes('`') ||
        arg.includes('$(') ||
        arg.includes('\n') ||
        arg.includes('\r')
      ) {
        throw ArcError.forbiddenCommand(
          `Argument '${arg}' contains forbidden shell execution or command substitution syntax.`,
        );
      }
      // Check for host escape paths in configuration or output flags
      if (
        (arg.startsWith('--config=') ||
          arg.startsWith('--output=') ||
          arg.startsWith('--project=') ||
          arg.startsWith('-p=')) &&
        (arg.includes('/etc/') ||
          arg.includes('/root/') ||
          arg.includes('/tmp/') ||
          arg.includes('/var/') ||
          arg.includes('..'))
      ) {
        throw ArcError.forbiddenCommand(
          `Argument '${arg}' attempts to target a path outside the authorized workspace.`,
        );
      }
    }

    // 4. Per-Executable Specific Argument Policies
    if (rawName === 'git') {
      const allowedGitSubcommands = [
        'status',
        'diff',
        'log',
        'rev-parse',
        'show',
        'describe',
        'branch',
      ];
      const deniedGitSubcommands = [
        'commit',
        'push',
        'pull',
        'fetch',
        'checkout',
        'switch',
        'reset',
        'clean',
        'stash',
        'config',
        'tag',
        'remote',
        'merge',
        'rebase',
        'cherry-pick',
        'clone',
        'init',
        'apply',
      ];

      const firstNonFlag = args.find((a) => !a.startsWith('-'));
      if (!firstNonFlag || !allowedGitSubcommands.includes(firstNonFlag.toLowerCase())) {
        throw ArcError.forbiddenCommand(
          `Git subcommand '${firstNonFlag || 'unknown'}' is not allowed in RC-02 (read-only Git inspection only).`,
        );
      }

      if (deniedGitSubcommands.includes(firstNonFlag.toLowerCase())) {
        throw ArcError.forbiddenCommand(
          `Git mutating subcommand '${firstNonFlag}' is strictly forbidden in RC-02.`,
        );
      }

      for (const arg of args) {
        if (
          arg.startsWith('--config') ||
          arg.startsWith('-c') ||
          arg.startsWith('--exec-path') ||
          arg.startsWith('--upload-pack') ||
          arg.startsWith('--receive-pack')
        ) {
          throw ArcError.forbiddenCommand(
            `Git configuration or execution flag '${arg}' is forbidden by policy.`,
          );
        }
      }
    } else if (rawName === 'node') {
      // Forbid inline code evaluation and remote debuggers
      const forbiddenNodeFlags = [
        '-e',
        '--eval',
        '-p',
        '--print',
        '--inspect',
        '--inspect-brk',
        '--inspect-port',
        '--expose-internals',
        '-r',
        '--require',
        '--import',
        '--loader',
      ];

      for (const arg of args) {
        const flagName = arg.split('=')[0];
        if (forbiddenNodeFlags.includes(flagName)) {
          throw ArcError.forbiddenCommand(
            `Node flag '${arg}' is forbidden by policy (arbitrary code execution or debugging forbidden).`,
          );
        }
      }
    } else if (rawName === 'npm' || rawName === 'pnpm') {
      const deniedNpmSubcommands = [
        'install',
        'i',
        'add',
        'update',
        'upgrade',
        'audit',
        'publish',
        'login',
        'logout',
        'token',
        'config',
        'link',
        'init',
        'create',
        'uninstall',
        'rm',
      ];

      const firstNonFlag = args.find((a) => !a.startsWith('-'));
      if (firstNonFlag && deniedNpmSubcommands.includes(firstNonFlag.toLowerCase())) {
        throw ArcError.forbiddenCommand(
          `Package manager command '${firstNonFlag}' is forbidden in RC-02 (package installation or mutation forbidden).`,
        );
      }

      for (const arg of args) {
        if (arg === '-g' || arg === '--global' || arg.startsWith('--prefix')) {
          throw ArcError.forbiddenCommand(
            `Package manager global flag '${arg}' is forbidden by policy.`,
          );
        }
      }
    }

    // 5. Environment Overrides Policy (Default-Deny)
    if (env) {
      for (const [key, value] of Object.entries(env)) {
        if (!(ALLOWED_ENV_KEYS as readonly string[]).includes(key)) {
          throw ArcError.forbiddenCommand(
            `Environment variable override '${key}' is forbidden by security policy.`,
          );
        }
        for (const pattern of FORBIDDEN_ENV_PATTERNS) {
          if (pattern.test(key)) {
            throw ArcError.forbiddenCommand(
              `Environment variable '${key}' matches forbidden credential or system pattern.`,
            );
          }
        }
        if (typeof value !== 'string' || value.length > 512) {
          throw ArcError.invalidRequestSchema(
            `Environment variable value for '${key}' must be a string <= 512 characters.`,
          );
        }
      }
    }
  }
}

export interface IExecutableResolver {
  resolveExecutable(name: string, workspaceRoot: string): string;
}

export class ExecutableResolver implements IExecutableResolver {
  private trustedDirs: string[];

  constructor(customTrustedDirs?: string[]) {
    this.trustedDirs = customTrustedDirs || [
      '/usr/bin',
      '/bin',
      '/usr/local/bin',
      dirname(process.execPath),
    ];
  }

  public resolveExecutable(name: string, workspaceRoot: string): string {
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

    // 1. Search Fixed Trusted System Locations
    for (const dir of this.trustedDirs) {
      const candidate = resolve(dir, trimmed);
      if (existsSync(candidate)) {
        try {
          const stat = statSync(candidate);
          if (stat.isFile() && (stat.mode & 0o111) !== 0) {
            return realpathSync(candidate);
          }
        } catch {
          // ignore unresolvable
        }
      }
    }

    // 2. Check Project-Local node_modules/.bin (Strictly Contained)
    const localBin = resolve(workspaceRoot, 'node_modules', '.bin', trimmed);
    if (existsSync(localBin)) {
      try {
        const canonicalLocal = realpathSync(localBin);
        if (canonicalLocal === workspaceRoot || canonicalLocal.startsWith(workspaceRoot + sep)) {
          const stat = statSync(canonicalLocal);
          if (stat.isFile() && (stat.mode & 0o111) !== 0) {
            return canonicalLocal;
          }
        }
      } catch {
        // ignore
      }
    }

    throw ArcError.forbiddenCommand(
      `Executable '${trimmed}' could not be resolved from trusted system locations or authorized workspace bin.`,
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
  ): ProcessStatusResponse;
  getProcessOutput(
    processId: string,
    offset: number | undefined,
    maxBytes: number | undefined,
    actor: PolicyEvaluationContext['actor'],
  ): ProcessOutputResponse;
  terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' | undefined,
    actor: PolicyEvaluationContext['actor'],
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
        sessionId: actor.sessionId || 'default-session',
      },
      executable: request.executable,
      sanitizedArgs: args,
      cwd: executionCwd,
      startedAt: new Date(startTime).toISOString(),
      state: 'RUNNING',
      timedOut: false,
    });

    // 6. Spawn Child Process (shell: false)
    let child: ChildProcess;
    try {
      child = spawn(resolvedExecutable, args, {
        cwd: executionCwd,
        env: sanitizedEnv,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      record._child = child;
    } catch (err: unknown) {
      this.processRegistry.markCompleted(record.processId, 1, null);
      const errMsg = err instanceof Error ? err.message : String(err);
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
        child.kill('SIGTERM');
      } catch {
        // ignore
      }
      record._killTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
          }
        } catch {
          // ignore
        }
      }, 1000);
      record._killTimer.unref();
    }, timeoutMs);
    record._timeoutTimer.unref();

    child.on('close', (code, signal) => {
      if (!record.timedOut && record.state !== 'TERMINATED') {
        this.processRegistry.markCompleted(record.processId, code, signal);
      }
    });

    child.on('error', () => {
      this.processRegistry.markCompleted(record.processId, 1, null);
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

    const status = this.processRegistry.getProcessStatus(record.processId, actor.sessionId);
    const output = this.processRegistry.getProcessOutput(
      record.processId,
      0,
      MAX_OUTPUT_READ_BYTES,
      actor.sessionId,
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
  ): ProcessStatusResponse {
    return this.processRegistry.getProcessStatus(processId, actor.sessionId);
  }

  public getProcessOutput(
    processId: string,
    offset: number | undefined,
    maxBytes: number | undefined,
    actor: PolicyEvaluationContext['actor'],
  ): ProcessOutputResponse {
    return this.processRegistry.getProcessOutput(processId, offset, maxBytes, actor.sessionId);
  }

  public async terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' | undefined,
    actor: PolicyEvaluationContext['actor'],
  ): Promise<TerminateProcessResponse> {
    return this.processRegistry.terminateProcess(processId, signal, actor.sessionId);
  }
}
