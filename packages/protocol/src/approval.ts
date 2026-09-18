/**
 * Canonical Approval State Machine and Binding Contracts for CesSpace ARC (RC-04).
 */

/**
 * Canonical Approval States.
 */
export type ApprovalState =
  'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CONSUMED' | 'INVALIDATED';

/**
 * Terminal states in the Approval State Machine.
 * Once entered, zero transitions out are permitted.
 */
export const TERMINAL_APPROVAL_STATES: readonly ApprovalState[] = [
  'REJECTED',
  'EXPIRED',
  'CONSUMED',
  'INVALIDATED',
] as const;

/**
 * Actor context bound immutably to an approval record.
 * Exact presence or absence of optional fields is preserved.
 */
export interface ApprovalActorBinding {
  clientId: string;
  clientType: string;
  sessionId?: string;
  deviceId?: string;
}

/**
 * Target workspace bound immutably to an approval record.
 */
export interface ApprovalWorkspaceBinding {
  workspaceId: string;
  workspaceRootHash: string; // 64 lowercase hexadecimal characters (SHA-256)
}

/**
 * Complete cryptographic and contextual binding for an approval request.
 */
export interface ApprovalBinding {
  actor: ApprovalActorBinding;
  workspace: ApprovalWorkspaceBinding;
  policyHash: string; // 64 lowercase hexadecimal characters (SHA-256)
}

/**
 * Internal representation of an approval request record.
 */
export interface ApprovalRequest {
  requestId: string;
  state: ApprovalState;
  toolName: string;
  executionPayloadHash: string;
  binding: ApprovalBinding;
  createdAt: string; // ISO 8601 string
  expiresAt: string; // ISO 8601 string
  reviewMaterial?: string;
}

/**
 * Safe public snapshot of an approval request.
 * Excludes raw tokens, token digests, monotonic deadline internals, and raw review material.
 */
export interface ApprovalRequestSnapshot {
  requestId: string;
  state: ApprovalState;
  toolName: string;
  executionPayloadHash: string;
  binding: ApprovalBinding;
  createdAt: string;
  expiresAt: string;
  remainingSeconds: number;
  reviewMaterialBytes: number;
}

/**
 * Reserved client control object for token redemption.
 * Formal type contract only in Task 1.
 */
export interface ArcApprovalControlObject {
  requestId: string;
  token: string;
}

/**
 * Result returned by approve() granting human elevation.
 * Returns the 64-character raw hex token once only.
 */
export interface ApprovalGrant {
  token: string;
  snapshot: ApprovalRequestSnapshot;
}

/**
 * Input for token redemption and consumption.
 */
export interface ApprovalRedemptionInput {
  requestId: string;
  token: string;
  executionPayloadHash: string;
  actor: ApprovalActorBinding;
  workspace: ApprovalWorkspaceBinding;
  policyHash: string;
}

/**
 * Result returned upon successful atomic consumption of an approval.
 */
export interface ApprovalConsumptionResult {
  consumed: true;
  requestId: string;
  toolName: string;
  executionPayloadHash: string;
  consumedAt: string;
}

/**
 * Structured audit event types for approval lifecycle.
 */
export type ApprovalAuditEventType =
  | 'APPROVAL_REQUESTED'
  | 'APPROVAL_GRANTED'
  | 'APPROVAL_REJECTED'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_CONSUMED'
  | 'APPROVAL_INVALIDATED'
  | 'APPROVED_EXECUTION_SUCCEEDED'
  | 'APPROVED_EXECUTION_FAILED';

/**
 * Enumerated internal failure reason codes for diagnostic logging.
 * Anti-oracle rule: these are never exposed directly to calling MCP agents.
 */
export type ApprovalFailureReasonCode =
  | 'TOKEN_MISMATCH'
  | 'PAYLOAD_BINDING_MISMATCH'
  | 'ACTOR_BINDING_MISMATCH'
  | 'WORKSPACE_BINDING_MISMATCH'
  | 'POLICY_BINDING_MISMATCH'
  | 'ALREADY_CONSUMED';

/**
 * Default limits and resource quotas for RC-04 approval state.
 */
export const APPROVAL_TTL_SECONDS = 300;
export const MAX_ACTIVE_APPROVALS_GLOBAL = 1024;
export const MAX_ACTIVE_APPROVALS_PER_ACTOR = 64;
export const MAX_REVIEW_BYTES_PER_RECORD = 1_048_576; // 1 MiB
export const MAX_REVIEW_BYTES_PER_ACTOR = 8 * 1024 * 1024; // 8 MiB
export const MAX_REVIEW_BYTES_GLOBAL = 64 * 1024 * 1024; // 64 MiB
export const MAX_TOKEN_BYTES = 128;
