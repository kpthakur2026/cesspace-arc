/**
 * Policy evaluation outcomes with formal numeric precedence.
 * Invariant: Lower numeric value indicates higher precedence.
 * Precedence Rule: DENY (0) > REQUIRE_APPROVAL (1) > ALLOW (2).
 */
export enum PolicyOutcome {
  DENY = 0,
  REQUIRE_APPROVAL = 1,
  ALLOW = 2,
}

/**
 * String literal representation of policy effects.
 */
export type PolicyEffect = 'DENY' | 'REQUIRE_APPROVAL' | 'ALLOW';

/**
 * Contextual information supplied to the policy engine for every evaluation.
 */
export interface PolicyEvaluationContext {
  actor: {
    clientId: string;
    clientType: string;
    authenticated: boolean;
  };
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  request: {
    toolName: string;
    parameters: Record<string, unknown>;
  };
  timestamp: string;
}

/**
 * Result emitted by policy evaluation.
 */
export interface PolicyDecisionResult {
  outcome: PolicyOutcome;
  effect: PolicyEffect;
  matchingRuleId: string;
  reason: string;
  approvalRequestId?: string;
}

/**
 * Policy rule definition schema.
 */
export interface PolicyRule {
  id: string;
  effect: PolicyEffect;
  description: string;
  tools?: string[];
  paths?: {
    patterns: string[];
  };
  commands?: {
    blockedBinaries?: string[];
    allowedBinaries?: string[];
  };
  git?: {
    protectedBranches?: string[];
    actions?: string[];
  };
}
