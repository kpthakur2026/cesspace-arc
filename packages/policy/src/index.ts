import { realpathSync, existsSync } from 'node:fs';
import { resolve, sep } from 'node:path';
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
 * All other tools are denied at admission by the Minimal Security Kernel.
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
    const isAllowedTool = (RC01_ALLOWED_TOOLS as readonly string[]).includes(toolName);
    if (!isAllowedTool) {
      return {
        outcome: PolicyOutcome.DENY,
        effect: 'DENY',
        matchingRuleId: 'default-deny-unregistered-tool',
        reason: `Tool '${toolName}' is not permitted in RC-01 stage (read-only inspection core only).`,
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

    // 3. System Tools Exemption from Workspace Target
    if (toolName === 'health' || toolName === 'system_status') {
      return {
        outcome: PolicyOutcome.ALLOW,
        effect: 'ALLOW',
        matchingRuleId: 'allow-system-read',
        reason: 'Safe read-only system inspection allowed.',
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

    // 7. Admitted by Default Allow for Read-Only Inspection
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
