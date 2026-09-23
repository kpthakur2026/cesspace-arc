/**
 * Canonical Approval State Machine and Binding Contracts for CesSpace ARC (RC-04).
 */

/**
 * Canonical Approval States.
 */
export type ApprovalState =
  'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CONSUMED' | 'INVALIDATED';

export const APPROVAL_STATES = [
  'PENDING',
  'APPROVED',
  'REJECTED',
  'EXPIRED',
  'CONSUMED',
  'INVALIDATED',
] as const;

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
  /** Safe bounded metadata. Never raw material. */
  reviewSummary?: ApprovalReviewSummary;
}

/**
 * Safe structured review metadata for an approval request (RC-04 Task 4).
 *
 * This is bounded, non-sensitive metadata derived from already-validated
 * business parameters. It is NOT raw review material and never contains a raw
 * token, an absolute host path, raw file content, raw patch lines, or raw
 * environment values.
 */
export interface ApprovalReviewSummary {
  /** Workspace-relative target paths. Bounded to MAX_REVIEW_SUMMARY_PATHS. */
  targetPaths?: string[];
  contentBytes?: number;
  contentHash?: string;
  patchBytes?: number;
  patchHash?: string;
  expectedHash?: string;
  expectedSourceHash?: string;
  overwrite?: boolean;
  dryRun?: boolean;
  fuzz?: number;
  executable?: string;
  argumentCount?: number;
  insertions?: number;
  deletions?: number;
  // RC-07 composite plan review fields (bounded, safe)
  planId?: string;
  planHash?: string;
  stepCount?: number;
}

/** Maximum number of target paths retained in a review summary. */
export const MAX_REVIEW_SUMMARY_PATHS = 10;
/** Maximum length of any single string retained in a review summary. */
export const MAX_REVIEW_SUMMARY_STRING_LENGTH = 512;
/**
 * Maximum length of a workspace-relative target path retained in a review
 * summary. Deliberately matches the business path bound (1024) rather than the
 * generic string bound, so a legal target path is never silently dropped from
 * operator review.
 */
export const MAX_REVIEW_SUMMARY_PATH_LENGTH = 1024;

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

export const APPROVAL_AUDIT_EVENT_TYPES = [
  'APPROVAL_REQUESTED',
  'APPROVAL_GRANTED',
  'APPROVAL_REJECTED',
  'APPROVAL_EXPIRED',
  'APPROVAL_CONSUMED',
  'APPROVAL_INVALIDATED',
  'APPROVED_EXECUTION_SUCCEEDED',
  'APPROVED_EXECUTION_FAILED',
] as const;

/**
 * Safe, bounded approval lifecycle event emitted synchronously by
 * ApprovalStateManager at the moment a state transition is committed.
 *
 * This carries ONLY what is needed to write an audit record. It deliberately
 * excludes the raw token, the token digest, review material, file content,
 * patch text, the absolute host root path, environment values, private key and
 * signature material, and the monotonic deadline.
 *
 * `executionPayloadHash` is intentionally omitted: audit correlation uses the
 * approval `requestId` instead.
 */
export interface ApprovalLifecycleEvent {
  eventType: ApprovalAuditEventType;
  requestId: string;
  state: ApprovalState;
  toolName: string;
  actor: ApprovalActorBinding;
  workspaceId: string;
  workspaceRootHash: string;
  policyHash: string;
  /** Server wall-clock ISO display time. Never used for TTL decisions. */
  occurredAt: string;
  /** Frozen enum only, when applicable. Never attacker-controlled text. */
  reasonCode?: ApprovalFailureReasonCode;
  /** Safe boolean: whether an operator supplied a reason. The text is never kept. */
  operatorReasonProvided?: boolean;
}

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

export const APPROVAL_FAILURE_REASON_CODES = [
  'TOKEN_MISMATCH',
  'PAYLOAD_BINDING_MISMATCH',
  'ACTOR_BINDING_MISMATCH',
  'WORKSPACE_BINDING_MISMATCH',
  'POLICY_BINDING_MISMATCH',
  'ALREADY_CONSUMED',
] as const;

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
