import { resolve, sep } from 'node:path';

/**
 * Canonical Command Policy and Executable Profile Models for CesSpace ARC.
 * Single source of truth for command authorization across SecurityKernel and Terminal subsystems.
 */

export interface ExecutableProfile {
  executable: string;
  allowedOperations: readonly string[];
  allowedArgumentShapes: readonly RegExp[];
  mayExecuteProjectCode: boolean;
  mayWriteWorkspace: boolean;
  mayUseNetwork: boolean;
  allowedConfigPaths?: readonly string[];
}

/**
 * Approved executable profiles for RC-02.
 * Conservative capability-profile model:
 * Informational operations (e.g. --version, --help) and specifically constrained read-only subcommands only.
 * Generic node <script>, npx *, npm run/start/test/exec, pnpm run/exec/dlx are strictly excluded.
 */
export const RC02_EXECUTABLE_PROFILES: Readonly<Record<string, ExecutableProfile>> = {
  git: {
    executable: 'git',
    allowedOperations: [
      'status',
      'diff',
      'log',
      'rev-parse',
      'show',
      'describe',
      'branch',
      'version',
      '--version',
      'help',
      '--help',
    ],
    allowedArgumentShapes: [
      /^(status|diff|log|rev-parse|show|describe|branch|version|--version|help|--help)$/i,
      /^--porcelain(=v[12])?$/,
      /^--oneline$/,
      /^--name-only$/,
      /^--name-status$/,
      /^--stat$/,
      /^--short$/,
      /^--branch$/,
      /^--show-toplevel$/,
      /^(--cached|--staged)$/,
      /^--$/,
      /^-[0-9]+$/,
      /^--max-count=[0-9]+$/,
      /^-n$/,
      /^--format=[a-zA-Z0-9_%: -]+$/,
      /^-[a-zA-Z0-9_./@^~-]+$/,
      /^[a-zA-Z0-9_./@^~-]+$/,
    ],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  node: {
    executable: 'node',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  npm: {
    executable: 'npm',
    allowedOperations: ['--version', '-v', 'version', '--help', '-h', 'help'],
    allowedArgumentShapes: [/^(-v|--version|version|-h|--help|help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  pnpm: {
    executable: 'pnpm',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  tsc: {
    executable: 'tsc',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  eslint: {
    executable: 'eslint',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  prettier: {
    executable: 'prettier',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  vitest: {
    executable: 'vitest',
    allowedOperations: ['--version', '-v', '--help', '-h'],
    allowedArgumentShapes: [/^(-v|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
  pytest: {
    executable: 'pytest',
    allowedOperations: ['--version', '-V', '--help', '-h'],
    allowedArgumentShapes: [/^(-V|--version|-h|--help)$/],
    mayExecuteProjectCode: false,
    mayWriteWorkspace: false,
    mayUseNetwork: false,
  },
};

/**
 * List of permitted executable names in RC-02.
 */
export const RC02_PERMITTED_EXECUTABLES = Object.keys(
  RC02_EXECUTABLE_PROFILES,
) as readonly string[];

/**
 * Explicitly forbidden executables matrix in RC-02.
 */
export const RC02_FORBIDDEN_EXECUTABLES = [
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
  'npx', // Explicitly removed per P0-02
] as const;

/**
 * Explicitly denied command prefixes and subcommand patterns.
 */
export const RC02_DENIED_COMMAND_PREFIXES = [
  {
    executable: 'npm',
    subcommands: [
      'run',
      'start',
      'test',
      'exec',
      'x',
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
    ],
  },
  {
    executable: 'pnpm',
    subcommands: [
      'run',
      'start',
      'test',
      'exec',
      'dlx',
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
    ],
  },
  {
    executable: 'git',
    subcommands: [
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
    ],
  },
] as const;

/**
 * Permitted environment override keys in RC-02.
 */
export const ALLOWED_ENV_KEYS = ['CI', 'FORCE_COLOR', 'NO_COLOR', 'DEBUG', 'NODE_ENV'] as const;

/**
 * Forbidden environment variable patterns.
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
] as const;

export interface CommandValidationResult {
  valid: boolean;
  ruleId?: string;
  reason?: string;
}

/**
 * Single canonical command authorization validator for CesSpace ARC.
 * Shared across SecurityKernel and Terminal subsystems.
 */
export function validateCommandRequest(
  executable: string,
  args: string[] = [],
  env?: Record<string, string>,
  cwd?: string,
  workspaceRoot?: string,
): CommandValidationResult {
  const trimmed = (executable || '').trim();
  if (!trimmed) {
    return {
      valid: false,
      ruleId: 'deny-invalid-executable',
      reason: 'Executable name must be a non-empty string.',
    };
  }

  // Reject path separators in executable name (must not be relative/absolute path)
  if (trimmed.includes('/') || trimmed.includes('\\')) {
    return {
      valid: false,
      ruleId: 'deny-invalid-executable',
      reason: 'Direct path invocation for executable is forbidden. Provide bare executable name.',
    };
  }

  const rawName = trimmed.toLowerCase();

  // 1. Explicitly Denied Executables
  if ((RC02_FORBIDDEN_EXECUTABLES as readonly string[]).includes(rawName)) {
    return {
      valid: false,
      ruleId: 'deny-forbidden-command',
      reason: `Command '${rawName}' is explicitly forbidden by security policy.`,
    };
  }

  // 2. Allowlist Check (Default-Deny)
  const profile = RC02_EXECUTABLE_PROFILES[rawName];
  if (!profile) {
    return {
      valid: false,
      ruleId: 'deny-unapproved-executable',
      reason: `Executable '${rawName}' is not in the approved RC-02 development tool allowlist.`,
    };
  }

  // 3. Shell & Metacharacter Injection Guard (data minimization: no raw arg values in reason)
  for (const arg of args) {
    if (typeof arg !== 'string') {
      return {
        valid: false,
        ruleId: 'deny-invalid-argument',
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
        valid: false,
        ruleId: 'deny-shell-injection',
        reason: 'Argument contains forbidden shell execution or command substitution syntax.',
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
        valid: false,
        ruleId: 'deny-argument-path-escape',
        reason: 'Argument attempts to target a path outside the authorized workspace.',
      };
    }
  }

  // 4. Executable Profile and Operation Rules
  if (rawName === 'git') {
    if (args.length === 0) {
      return {
        valid: false,
        ruleId: 'deny-git-mutation',
        reason: 'Git requires an approved read-only subcommand or --version/--help.',
      };
    }

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
    if (firstNonFlag) {
      const lower = firstNonFlag.toLowerCase();
      if (!profile.allowedOperations.includes(lower) || deniedGitSubcommands.includes(lower)) {
        return {
          valid: false,
          ruleId: 'deny-git-mutation',
          reason: 'Git mutating or unapproved operation is strictly forbidden in RC-02.',
        };
      }
    } else {
      // Flags only - ensure only informational operations like --version or --help
      const hasSafeFlag = args.some(
        (a) => a === '--version' || a === '-v' || a === '--help' || a === '-h',
      );
      if (!hasSafeFlag) {
        return {
          valid: false,
          ruleId: 'deny-git-mutation',
          reason: 'Git requires an approved read-only subcommand or --version/--help.',
        };
      }
    }

    // Check forbidden git flags
    for (const arg of args) {
      if (
        arg.startsWith('--config') ||
        arg.startsWith('-c') ||
        arg.startsWith('--exec-path') ||
        arg.startsWith('--upload-pack') ||
        arg.startsWith('--receive-pack')
      ) {
        return {
          valid: false,
          ruleId: 'deny-git-config-flag',
          reason: 'Git configuration or execution override flag is forbidden by policy.',
        };
      }

      const matchesShape = profile.allowedArgumentShapes.some((r) => r.test(arg));
      if (!matchesShape) {
        return {
          valid: false,
          ruleId: 'deny-argument-shape',
          reason: 'Argument does not conform to allowed git argument shapes.',
        };
      }
    }
  } else {
    // All other executables: node, npm, pnpm, tsc, eslint, prettier, vitest, pytest
    // RC-02 strictly limits these to safe informational operations (--version, --help)
    if (args.length === 0) {
      return {
        valid: false,
        ruleId: 'deny-unapproved-operation',
        reason: `Executable '${rawName}' requires an approved operation (--version, --help).`,
      };
    }

    for (const arg of args) {
      const matchesShape = profile.allowedArgumentShapes.some((r) => r.test(arg));
      if (!matchesShape) {
        return {
          valid: false,
          ruleId: 'deny-unapproved-operation',
          reason: `Operation for '${rawName}' is not allowed in RC-02 (safe informational operations only).`,
        };
      }
    }
  }

  // 5. Environment Overrides Validation
  if (env && typeof env === 'object') {
    for (const [key, val] of Object.entries(env)) {
      if (
        !(ALLOWED_ENV_KEYS as readonly string[]).includes(key as (typeof ALLOWED_ENV_KEYS)[number])
      ) {
        return {
          valid: false,
          ruleId: 'deny-forbidden-env',
          reason: `Environment variable override '${key}' is forbidden by security policy.`,
        };
      }
      for (const pattern of FORBIDDEN_ENV_PATTERNS) {
        if (pattern.test(key)) {
          return {
            valid: false,
            ruleId: 'deny-forbidden-env',
            reason: `Environment variable '${key}' matches forbidden credential or system pattern.`,
          };
        }
      }
      if (typeof val !== 'string' || val.length > 512) {
        return {
          valid: false,
          ruleId: 'deny-invalid-env-value',
          reason: `Environment variable value for '${key}' must be a string <= 512 characters.`,
        };
      }
    }
  }

  // 6. Working Directory Escape Validation
  if (cwd && typeof cwd === 'string' && workspaceRoot) {
    if (cwd.includes('..') || cwd.startsWith('/') || cwd.startsWith('\\')) {
      const resolved = resolve(workspaceRoot, cwd);
      if (resolved !== workspaceRoot && !resolved.startsWith(workspaceRoot + sep)) {
        return {
          valid: false,
          ruleId: 'deny-cwd-escape',
          reason: 'Working directory escapes authorized workspace root.',
        };
      }
    }
  }

  return { valid: true };
}
