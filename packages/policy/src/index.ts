import { realpathSync, existsSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import {
  PolicyOutcome,
  type PolicyEffect,
  type PolicyEvaluationContext,
  type PolicyDecisionResult,
  type PolicyRule,
  validateCommandRequest,
  RC02_PERMITTED_EXECUTABLES,
  RC02_FORBIDDEN_EXECUTABLES,
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

/**
 * The 5 file mutation tools introduced in RC-03.
 * These tools require explicit human approval and remain non-executable in RC-03.
 */
export const RC03_MUTATION_TOOLS = [
  'create_file',
  'write_file',
  'apply_patch',
  'delete_file',
  'move_file',
] as const;

export type Rc03MutationTool = (typeof RC03_MUTATION_TOOLS)[number];

/**
 * The 18 tools recognized in the RC-03 control plane.
 * (9 RC-01 read-only inspection + 4 RC-02 process supervision + 5 RC-03 file mutation).
 */
export const RC03_REGISTERED_TOOLS = [...RC02_ALLOWED_TOOLS, ...RC03_MUTATION_TOOLS] as const;

export const RC03_POLICY_TOOLS = RC03_REGISTERED_TOOLS;
export type Rc03RegisteredTool = (typeof RC03_REGISTERED_TOOLS)[number];

export const ALLOWED_COMMANDS = RC02_PERMITTED_EXECUTABLES;

export const DENIED_COMMANDS = RC02_FORBIDDEN_EXECUTABLES;

export interface IProcessOwnershipVerifier {
  assertOwnership(
    processId: string,
    owner?: { clientId: string; sessionId: string; workspaceId?: string },
  ): unknown;
}

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

  constructor(
    private workspaceRegistry: WorkspaceRegistry,
    private processVerifier?: IProcessOwnershipVerifier,
  ) {}

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
    const isRegisteredTool = (RC03_REGISTERED_TOOLS as readonly string[]).includes(toolName);
    if (!isRegisteredTool) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'default-deny-unregistered-tool',
        reason: `Tool '${toolName}' is not permitted in RC-03 stage.`,
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

      if (!this.processVerifier) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-missing-process-verifier',
          reason: 'Process ownership verifier is unavailable.',
        };
      }

      if (
        request.parameters.workspaceId &&
        request.parameters.workspaceId !== targetWorkspace.workspaceId
      ) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-process-ownership-mismatch',
          reason: 'Access denied: Requested workspaceId does not match process workspace.',
        };
      }

      try {
        this.processVerifier.assertOwnership(processId, {
          clientId: actor.clientId,
          sessionId: actor.sessionId || '',
          workspaceId: targetWorkspace.workspaceId,
        });
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: 'deny-process-ownership-mismatch',
          reason: errMsg,
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

    const isMutationTool = (RC03_MUTATION_TOOLS as readonly string[]).includes(toolName);

    // 5. Sensitive Path Pre-Check
    if (isMutationTool) {
      const mutationCandidatePaths: string[] = [];
      if (typeof request.parameters.path === 'string') {
        mutationCandidatePaths.push(request.parameters.path);
      }
      if (typeof request.parameters.sourcePath === 'string') {
        mutationCandidatePaths.push(request.parameters.sourcePath);
      }
      if (typeof request.parameters.destinationPath === 'string') {
        mutationCandidatePaths.push(request.parameters.destinationPath);
      }

      const mutationSensitivePatterns = [
        /(^|[/\\])\.git([/\\]|$)/i,
        /(^|[/\\])\.env[^/\\]*([/\\]|$)/i,
        /(^|[/\\])\.ssh([/\\]|$)/i,
        /(^|[/\\])\.aws([/\\]|$)/i,
        /(^|[/\\])\.gnupg([/\\]|$)/i,
        /(^|[/\\])\.kube([/\\]|$)/i,
        /(^|[/\\])id_rsa/i,
        /(^|[/\\])id_ed25519/i,
        /\.(pem|key|p12|pfx)$/i,
        /^[/\\]?(etc|proc|sys|root|dev)([/\\]|$)/i,
      ];

      for (const p of mutationCandidatePaths) {
        for (const pattern of mutationSensitivePatterns) {
          if (pattern.test(p)) {
            return {
              outcome: PolicyOutcome.DENY,
              effect: 'DENY',
              matchingRuleId: 'deny-mutation-sensitive-path',
              reason:
                'Target mutation path touches forbidden sensitive credential or Git internal path.',
            };
          }
        }
      }
    } else {
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
      const executable = String(request.parameters.executable || '');
      const args = Array.isArray(request.parameters.args)
        ? (request.parameters.args as string[])
        : [];
      const env = request.parameters.env as Record<string, string> | undefined;
      const cwd = request.parameters.cwd as string | undefined;

      const validation = validateCommandRequest(executable, args, env, cwd, registeredWs.rootPath);

      if (!validation.valid) {
        return {
          outcome: PolicyOutcome.DENY,
          effect: 'DENY',
          matchingRuleId: validation.ruleId || 'deny-command-policy',
          reason: validation.reason || 'Command violates security policy.',
        };
      }

      return {
        outcome: PolicyOutcome.ALLOW,
        effect: 'ALLOW',
        matchingRuleId: 'allow-controlled-command',
        reason: `Command '${executable.trim().toLowerCase()}' admitted under controlled execution policy for workspace '${registeredWs.id}'.`,
      };
    }

    // 8. RC-03 Mutation Policy Gate: Register but Require Explicit Human Approval
    if (isMutationTool) {
      return {
        outcome: PolicyOutcome.REQUIRE_APPROVAL,
        effect: 'REQUIRE_APPROVAL',
        matchingRuleId: 'require-approval-file-mutation',
        reason:
          'File mutation requires explicit human approval. Approval redemption is not available in RC-03.',
      };
    }

    // 9. Admitted by Default Allow for Read-Only Inspection
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
