import { realpathSync, existsSync } from 'node:fs';
import { resolve, sep, basename } from 'node:path';
import {
  PolicyOutcome,
  type PolicyEffect,
  type PolicyEvaluationContext,
  type PolicyDecisionResult,
  type PolicyRule,
} from '@cesspace-arc/protocol';

/**
 * Interface definition for the CesSpace ARC Policy Engine.
 */
export interface IPolicyEngine {
  evaluate(context: PolicyEvaluationContext): Promise<PolicyDecisionResult>;
  loadPolicy(rules: PolicyRule[]): void;
}

/**
 * The 9 tools explicitly allowed in RC-01.
 */
export const RC01_ALLOWED_TOOLS = [
  'health',
  'list_directory',
  'read_file',
  'search_files',
  'search_text',
  'git_status',
  'git_diff',
  'git_log',
  'system_status',
] as const;

export type Rc01AllowedTool = (typeof RC01_ALLOWED_TOOLS)[number];

/**
 * The 13 tools explicitly allowed in RC-02 (RC-01 read-only core + controlled execution).
 */
export const RC02_ALLOWED_TOOLS = [
  ...RC01_ALLOWED_TOOLS,
  'run_command',
  'process_status',
  'process_output',
  'terminate_process',
] as const;

export type Rc02AllowedTool = (typeof RC02_ALLOWED_TOOLS)[number];

export const ALLOWED_COMMANDS = [
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

export const DENIED_COMMANDS = [
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
 * Registered workspace record.
 */
export interface WorkspaceRecord {
  id: string;
  rootPath: string; // Canonical absolute path
  isGitRepo: boolean;
}

/**
 * Authorized-Workspace Registry.
 * Enforces that all targets resolve to pre-registered canonical workspace roots.
 */
export class WorkspaceRegistry {
  private workspacesById = new Map<string, WorkspaceRecord>();
  private workspacesByPath = new Map<string, WorkspaceRecord>();

  /**
   * Register an authorized workspace root.
   * Resolves the path to its real canonical path and verifies it exists.
   * Throws an error if the path does not exist or cannot be resolved.
   */
  public registerWorkspace(id: string, rawPath: string): WorkspaceRecord {
    if (!id || typeof id !== 'string' || id.trim().length === 0) {
      throw new Error('Workspace ID must be a non-empty string');
    }
    if (!rawPath || typeof rawPath !== 'string' || rawPath.trim().length === 0) {
      throw new Error('Workspace path must be a non-empty string');
    }
    const resolvedPath = resolve(rawPath);
    if (!existsSync(resolvedPath)) {
      throw new Error(`Workspace root path does not exist: ${resolvedPath}`);
    }
    let canonicalPath: string;
    try {
      canonicalPath = realpathSync(resolvedPath);
    } catch (err: unknown) {
      throw new Error(
        `Failed to resolve canonical path for workspace root: ${resolvedPath} (${(err as Error).message})`,
        { cause: err },
      );
    }

    const isGitRepo =
      existsSync(resolve(canonicalPath, '.git')) || existsSync(resolve(canonicalPath, 'HEAD'));

    const record: WorkspaceRecord = {
      id: id.trim(),
      rootPath: canonicalPath,
      isGitRepo,
    };

    this.workspacesById.set(record.id, record);
    this.workspacesByPath.set(canonicalPath, record);
    return record;
  }

  public getWorkspace(id: string): WorkspaceRecord | undefined {
    return this.workspacesById.get(id);
  }

  public getWorkspaces(): WorkspaceRecord[] {
    return Array.from(this.workspacesById.values());
  }

  public findWorkspaceForPath(targetPath: string): WorkspaceRecord | undefined {
    if (!targetPath || typeof targetPath !== 'string') {
      return undefined;
    }
    let resolved: string;
    try {
      resolved = realpathSync(resolve(targetPath));
    } catch {
      return undefined;
    }

    // Exact match
    const exact = this.workspacesByPath.get(resolved);
    if (exact) {
      return exact;
    }

    // Prefix match
    for (const ws of this.workspacesById.values()) {
      if (resolved === ws.rootPath || resolved.startsWith(ws.rootPath + sep)) {
        return ws;
      }
    }
    return undefined;
  }

  public clear(): void {
    this.workspacesById.clear();
    this.workspacesByPath.clear();
  }
}

/**
 * Minimal Security Kernel (RC-01).
 * Single unified policy decision path enforcing default-deny admission.
 */
export class SecurityKernel implements IPolicyEngine {
  private rules: PolicyRule[] = [];

  constructor(private workspaceRegistry: WorkspaceRegistry) {}

  public loadPolicy(rules: PolicyRule[]): void {
    this.rules = [...rules];
  }

  /**
   * Evaluates an incoming tool request context.
   * Precedence Rule: DENY (0) > REQUIRE_APPROVAL (1) > ALLOW (2).
   */
  public async evaluate(context: PolicyEvaluationContext): Promise<PolicyDecisionResult> {
    const { actor, targetWorkspace, request } = context;
    const toolName = request.toolName;

    // 1. Mandatory Tool Allowlist Gate (Default-Deny)
    const isAllowedTool = (RC02_ALLOWED_TOOLS as readonly string[]).includes(toolName);
    if (!isAllowedTool) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'default-deny-unregistered-tool',
        reason: `Tool '${toolName}' is not permitted in RC-02 stage (read-only inspection and controlled execution only).`,
      };
    }

    // 2. Caller Authentication Gate
    if (!actor.authenticated) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'deny-unauthenticated-caller',
        reason: 'Caller is not authenticated.',
      };
    }

    // 3. System Tools & Process Supervision Exemption from Workspace Target
    if (toolName === 'health' || toolName === 'system_status') {
      return {
        outcome: PolicyOutcome.ALLOW,
        effect: 'ALLOW',
        matchingRuleId: 'allow-system-read',
        reason: 'Safe read-only system inspection allowed.',
      };
    }

    if (
      toolName === 'process_status' ||
      toolName === 'process_output' ||
      toolName === 'terminate_process'
    ) {
      const processId = request.parameters.processId;
      if (!processId || typeof processId !== 'string' || !processId.startsWith('arc-proc-')) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-invalid-process-id',
          reason: 'Invalid or missing process identifier.',
        };
      }
      return {
        outcome: PolicyOutcome.ALLOW,
        effect: 'ALLOW',
        matchingRuleId: 'allow-process-lifecycle',
        reason: `Controlled process lifecycle operation '${toolName}' admitted for authenticated caller.`,
      };
    }

    // 4. Workspace Binding Gate
    if (targetWorkspace.workspaceId === 'deny-conflicting-workspace-selectors') {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'deny-conflicting-workspace-selectors',
        reason: 'Conflicting workspace selectors provided in request parameters.',
      };
    }

    if (targetWorkspace.workspaceId === 'deny-unregistered-workspace') {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'deny-unregistered-workspace',
        reason: `Workspace selector is not registered in authorized workspaces.`,
      };
    }

    const rootPath = targetWorkspace.rootPath;
    if (!rootPath || rootPath.trim().length === 0) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'deny-no-workspace-configured',
        reason: 'Operation requires an authorized workspace, but none was configured.',
      };
    }

    // Verify root is known to workspace registry
    const registeredWs = this.workspaceRegistry.getWorkspace(targetWorkspace.workspaceId);

    if (!registeredWs || registeredWs.rootPath !== rootPath) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'deny-unregistered-workspace',
        reason: 'Target workspace is not registered in authorized workspaces.',
      };
    }

    // Explicit caller parameters check to ensure policy matches execution context
    if (request.parameters.workspaceRoot) {
      const explicitWs =
        this.workspaceRegistry.findWorkspaceForPath(String(request.parameters.workspaceRoot)) ||
        this.workspaceRegistry.getWorkspace(String(request.parameters.workspaceRoot));
      if (!explicitWs || explicitWs.id !== registeredWs.id) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-unregistered-workspace',
          reason: 'Requested workspaceRoot is not authorized.',
        };
      }
    }
    if (request.parameters.workspaceId) {
      const explicitWs = this.workspaceRegistry.getWorkspace(
        String(request.parameters.workspaceId),
      );
      if (!explicitWs || explicitWs.id !== registeredWs.id) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-unregistered-workspace',
          reason: 'Requested workspaceId is not authorized.',
        };
      }
    }

    // 5. Sensitive Path Pre-Check
    const rawPath =
      (request.parameters.path as string | undefined) ||
      (request.parameters.subPath as string | undefined) ||
      (request.parameters.target as string | undefined);

    if (rawPath) {
      const sensitivePatterns = [
        /(^|[/\\])\.env($|\..*)/i,
        /(^|[/\\])\.ssh([/\\]|$)/i,
        /(^|[/\\])\.aws([/\\]|$)/i,
        /(^|[/\\])\.gnupg([/\\]|$)/i,
        /(^|[/\\])\.kube([/\\]|$)/i,
        /(^|[/\\])\.git[/\\]config$/i,
        /(^|[/\\])\.git[/\\]hooks([/\\]|$)/i,
        /(^|[/\\])id_rsa/i,
        /(^|[/\\])id_ed25519/i,
        /\.(pem|key|p12|pfx)$/i,
      ];

      for (const pattern of sensitivePatterns) {
        if (pattern.test(rawPath)) {
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-sensitive-path-pattern',
            reason: `Target path matches sensitive credential pattern.`,
          };
        }
      }
    }

    // 6. Git Subsystem Safety Check
    if (toolName === 'git_status' || toolName === 'git_diff' || toolName === 'git_log') {
      if (!registeredWs.isGitRepo) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-not-git-repository',
          reason: 'Target workspace is not a Git repository.',
        };
      }

      // Check for argument injection in git revision or target
      const revision = request.parameters.revision as string | undefined;
      const target = request.parameters.target as string | undefined;
      for (const arg of [revision, target]) {
        if (arg && (arg.startsWith('-') || arg.startsWith('--'))) {
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-git-argument-injection',
            reason: 'Flag injection detected in git parameter.',
          };
        }
      }
    }

    // 7. Command Policy Validation for Controlled Execution (RC-02)
    if (toolName === 'run_command') {
      const executable = String(request.parameters.executable || '').trim();
      if (!executable) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-invalid-executable',
          reason: 'Executable name must be a non-empty string.',
        };
      }

      const rawName = basename(executable).toLowerCase();

      // Check explicitly denied commands
      if ((DENIED_COMMANDS as readonly string[]).includes(rawName)) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-forbidden-command',
          reason: `Command '${rawName}' is explicitly forbidden by security policy.`,
        };
      }

      // Check allowlist
      if (!(ALLOWED_COMMANDS as readonly string[]).includes(rawName)) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-unapproved-executable',
          reason: `Executable '${rawName}' is not in the approved RC-02 development tool allowlist.`,
        };
      }

      const args = Array.isArray(request.parameters.args)
        ? (request.parameters.args as string[])
        : [];

      // Check arguments
      for (const arg of args) {
        if (typeof arg !== 'string') {
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-invalid-argument',
            reason: 'Command arguments must be strings.',
          };
        }
        if (
          arg === '-c' ||
          arg === '/c' ||
          arg.startsWith('--command') ||
          arg.includes('`') ||
          arg.includes('$(') ||
          arg.includes('\n') ||
          arg.includes('\r')
        ) {
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-shell-injection',
            reason: `Argument '${arg}' contains forbidden shell execution or command substitution syntax.`,
          };
        }
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
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-argument-path-escape',
            reason: `Argument '${arg}' attempts to target a path outside the authorized workspace.`,
          };
        }
      }

      // Per-executable restrictions
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
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-git-mutation',
            reason: `Git subcommand '${firstNonFlag || 'unknown'}' is not allowed in RC-02 (read-only Git inspection only).`,
          };
        }
        if (deniedGitSubcommands.includes(firstNonFlag.toLowerCase())) {
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-git-mutation',
            reason: `Git mutating subcommand '${firstNonFlag}' is strictly forbidden in RC-02.`,
          };
        }
      } else if (rawName === 'node') {
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
            return {
              outcome: PolicyOutcome.DENY,
              effect: 'DENY',
              matchingRuleId: 'deny-forbidden-node-flag',
              reason: `Node flag '${arg}' is forbidden by policy (arbitrary code execution or debugging forbidden).`,
            };
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
          return {
            outcome: PolicyOutcome.DENY,
            effect: 'DENY',
            matchingRuleId: 'deny-package-install',
            reason: `Package manager command '${firstNonFlag}' is forbidden in RC-02 (package installation or mutation forbidden).`,
          };
        }
      }

      // Check environment overrides
      if (request.parameters.env && typeof request.parameters.env === 'object') {
        const env = request.parameters.env as Record<string, string>;
        const allowedEnvKeys = ['CI', 'FORCE_COLOR', 'NO_COLOR', 'DEBUG', 'NODE_ENV'];
        const forbiddenEnvPatterns = [
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

        for (const [key, val] of Object.entries(env)) {
          if (!allowedEnvKeys.includes(key)) {
            return {
              outcome: PolicyOutcome.DENY,
              effect: 'DENY',
              matchingRuleId: 'deny-forbidden-env',
              reason: `Environment variable override '${key}' is forbidden by security policy.`,
            };
          }
          for (const pattern of forbiddenEnvPatterns) {
            if (pattern.test(key)) {
              return {
                outcome: PolicyOutcome.DENY,
                effect: 'DENY',
                matchingRuleId: 'deny-forbidden-env',
                reason: `Environment variable '${key}' matches forbidden credential or system pattern.`,
              };
            }
          }
          if (typeof val !== 'string' || val.length > 512) {
            return {
              outcome: PolicyOutcome.DENY,
              effect: 'DENY',
              matchingRuleId: 'deny-invalid-env-value',
              reason: `Environment variable value for '${key}' must be a string <= 512 characters.`,
            };
          }
        }
      }

      // Check working directory
      if (request.parameters.cwd && typeof request.parameters.cwd === 'string') {
        const cwd = request.parameters.cwd;
        if (cwd.includes('..') || cwd.startsWith('/') || cwd.startsWith('\\')) {
          const resolved = resolve(registeredWs.rootPath, cwd);
          if (
            resolved !== registeredWs.rootPath &&
            !resolved.startsWith(registeredWs.rootPath + sep)
          ) {
            return {
              outcome: PolicyOutcome.DENY,
              effect: 'DENY',
              matchingRuleId: 'deny-cwd-escape',
              reason: 'Working directory escapes authorized workspace root.',
            };
          }
        }
      }

      return {
        outcome: PolicyOutcome.ALLOW,
        effect: 'ALLOW',
        matchingRuleId: 'allow-controlled-command',
        reason: `Command '${rawName}' admitted under controlled execution policy for workspace '${registeredWs.id}'.`,
      };
    }

    // 8. Admitted by Default Allow for Read-Only Inspection
    return {
      outcome: PolicyOutcome.ALLOW,
      effect: 'ALLOW',
      matchingRuleId: 'allow-rc01-read-inspection',
      reason: `Authorized read-only tool '${toolName}' admitted within workspace '${registeredWs.id}'.`,
    };
  }
}

export {
  PolicyOutcome,
  type PolicyEffect,
  type PolicyEvaluationContext,
  type PolicyDecisionResult,
  type PolicyRule,
};
