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
 * Canonical Policy Evaluation Context for CesSpace ARC.
 * Formally separates cryptographic authentication identity from authorization evaluation.
 */
export interface PolicyEvaluationContext {
  actor: {
    clientId: string; // Unique client/agent identifier (e.g. "antigravity-worker-01")
    clientType: string; // e.g. "antigravity", "claude-code", "codex", "opencode"
    authenticated: boolean; // Must be verified by auth subsystem prior to policy
    deviceId?: string; // Machine / client device identifier
    sessionId?: string; // Authenticated session identifier
  };
  targetWorkspace: {
    workspaceId: string; // Explicit workspace identifier
    rootPath: string; // Canonical absolute path of approved workspace
    isGitRepo: boolean; // True if workspace is a git repo
  };
  request: {
    toolName: string; // e.g. "read_file", "run_command"
    parameters: Record<string, unknown>; // Tool arguments
  };
  environment: {
    timestamp: string; // ISO 8601 evaluation timestamp
    sessionDurationMs?: number; // Monotonic session duration in milliseconds
  };
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
  description?: string;
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

/**
 * Metadata associated with a declarative policy document.
 * Non-semantic: excluded from canonical policyHash.
 */
export interface PolicyMetadata {
  name?: string;
  description?: string;
  lastModified?: string;
}

/**
 * Declarative workspace assertion in an operator policy document.
 * Asserts expected canonical workspace root identity.
 * Invariant: Policy never authorizes filesystem paths; 'path' and 'rootPath' are forbidden.
 */
export interface PolicyWorkspaceAssertion {
  id: string;
  rootHash?: string;
}

/**
 * Top-level declarative policy document schema (Version 1.0).
 */
export interface PolicyDocument {
  version: '1.0';
  metadata?: PolicyMetadata;
  workspaces?: PolicyWorkspaceAssertion[];
  rules: PolicyRule[];
}

/**
 * Canonical normalized policy representation.
 * Represents strictly security-relevant semantics for policyHash derivation.
 * Non-semantic metadata and descriptions are excluded.
 */
export interface NormalizedPolicy {
  schemaVersion: '1.0';
  workspaces: Array<{
    id: string;
    rootHash?: string;
  }>;
  rules: Array<{
    id: string;
    effect: PolicyEffect;
    tools?: string[];
    paths?: {
      patterns?: string[];
    };
    commands?: {
      allowedBinaries?: string[];
      blockedBinaries?: string[];
    };
    git?: {
      protectedBranches?: string[];
      actions?: string[];
    };
  }>;
}
