import type { PolicyEffect } from './policy.js';
import type {
  ApprovalAuditEventType,
  ApprovalFailureReasonCode,
  ApprovalState,
} from './approval.js';

/** Bounded approval correlation metadata. Never raw material or a token. */
export interface AuditApprovalMetadata {
  eventType?: ApprovalAuditEventType;
  requestId?: string;
  state?: ApprovalState;
  source?: 'MCP' | 'LOCAL_OPERATOR' | 'SYSTEM';
  /** Internal diagnostic only. Never surfaced to an MCP client. */
  reasonCode?: ApprovalFailureReasonCode;
  operatorReasonProvided?: boolean;
}

/**
 * The frozen RC-05 gateway audit event catalog (rc05-scope-acceptance.md §24).
 *
 * Exactly fourteen names, in the frozen order. This is a CLOSED catalog: there is
 * no alias list, no alternate spelling, and no second taxonomy. A gateway
 * lifecycle event that is not in this array cannot be represented in an audit
 * record, and the projection in `@cesspace-arc/audit` rejects anything else.
 */
export const GATEWAY_AUDIT_EVENT_TYPES = [
  'GATEWAY_STARTED',
  'GATEWAY_STOPPED',
  'DEVICE_ENROLLMENT_REQUESTED',
  'DEVICE_ENROLLED',
  'DEVICE_ENROLLMENT_REJECTED',
  'DEVICE_REVOKED',
  'AUTH_SUCCEEDED',
  'AUTH_FAILED',
  'SESSION_ISSUED',
  'SESSION_EXPIRED',
  'SESSION_REVOKED',
  'SESSION_CLOSED',
  'RATE_LIMITED',
  'REMOTE_DISCONNECTED',
] as const;

/** One frozen RC-05 gateway audit event name. */
export type GatewayAuditEventType = (typeof GATEWAY_AUDIT_EVENT_TYPES)[number];

/**
 * Bounded refusal/transition categories for gateway events.
 *
 * A category is a fixed vocabulary word, never a raw exception message, a
 * limiter key, or a caller-supplied string, so an audit record can never become
 * an oracle for what a caller presented.
 */
export const GATEWAY_AUDIT_REASONS = [
  'EXPIRED',
  'LOCKED_OUT',
  'SECRET_MISMATCH',
  'NO_PENDING_RECORD',
  'INVALID_REQUEST',
  'PIN_MISMATCH',
  'ACTIVATION_FAILED',
  'CANCELLED',
  'QUOTA_EXCEEDED',
  'DEVICE_REVOKED',
  'SESSION_REVOKED',
  'SHUTDOWN',
] as const;

export type GatewayAuditReason = (typeof GATEWAY_AUDIT_REASONS)[number];

/** The three frozen admission layers (§21.1) a refusal can come from. */
export type GatewayAuditAdmissionLayer = 'A' | 'B' | 'C';

/**
 * Bounded gateway lifecycle metadata (rc05 §24 safe-field rule).
 *
 * Carries safe identifiers and closed vocabulary only. There is no field for a
 * credential of any kind: no session token or its digest, no enrollment secret,
 * no SPKI pin body beyond the device's own already-public identity digest, no
 * certificate material, no peer address, and no raw limiter key. A value that
 * must be referenced is referenced by the identifier the server itself issued.
 */
export interface AuditGatewayMetadata {
  /** The frozen event name. */
  eventType: GatewayAuditEventType;
  /** Closed-vocabulary category, when the event has one. */
  reason?: GatewayAuditReason;
  /** Which admission layer refused, for `RATE_LIMITED` only. */
  admissionLayer?: GatewayAuditAdmissionLayer;
  /** Server-issued MCP session identifier (§5.4). Never the session credential. */
  mcpSessionId?: string;
  /** Opaque enrolled-device identifier (32 lowercase hex). */
  deviceId?: string;
  /**
   * Canonical SPKI pin of the connection's client certificate.
   *
   * A SHA-256 digest of the client's PUBLIC key — the approved trust-identity
   * digest of §7/§8, already transmitted in every TLS handshake and already
   * stored as the device's identity. It is a digest, never private material, and
   * it is the only identifier a connection-scoped event can carry: the gateway
   * has not resolved a device record at that layer.
   */
  spkiPin?: string;
  /** Operator-visible client identifier. */
  clientId?: string;
  /** Operator-visible client type. */
  clientType?: string;
  /** Pending-enrollment identifier. Never the one-time secret. */
  enrollmentId?: string;
  /** Transport mode at the moment of the transition. */
  transportMode?: 'stdio' | 'remote';
}

/**
 * Structured audit record representing an immutable event in the control plane.
 */
export interface AuditRecord {
  eventId: string;
  timestamp: string;
  sequenceNumber: number;
  actor: {
    clientId: string;
    clientType: string;
    deviceId: string;
    sessionId: string;
  };
  target: {
    workspaceId: string;
    /**
     * Always empty in stored records: AuditLogger centrally replaces a raw
     * absolute host path with its digest. Retained for protocol compatibility.
     */
    workspacePath: string;
    /** SHA-256 of the canonical supplied workspace path, when one was supplied. */
    workspaceRootHash?: string;
  };
  invocation: {
    toolName: string;
    parametersRedacted: Record<string, unknown>;
    payloadHash: string;
  };
  policy: {
    decision: PolicyEffect;
    ruleId: string;
    evaluationDurationMs: number;
    approvalId?: string;
  };
  execution: {
    status: 'SUCCESS' | 'ERROR' | 'DENIED' | 'TIMEOUT' | 'CANCELLED';
    startTime: string;
    endTime: string;
    durationMs: number;
    exitCode?: number;
    bytesRead?: number;
    bytesWritten?: number;
    changedFiles?: string[];
  };
  error?: {
    code: string;
    message: string;
  };
  /** Bounded approval correlation metadata. */
  approval?: AuditApprovalMetadata;
  /**
   * Bounded RC-05 gateway lifecycle metadata (rc05 §24).
   *
   * Present only on gateway lifecycle records; `undefined` on every ordinary MCP
   * and approval record. The key itself is always emitted so the canonical form
   * of a record is stable between append and integrity verification.
   */
  gateway?: AuditGatewayMetadata;
  integrity: {
    previousRecordHash: string;
    recordHash: string;
  };
}

/**
 * Closed lifecycle phase vocabulary for RC-06 universal auditability.
 *
 * All privileged operations record a pre-dispatch STARTED event and a terminal
 * COMPLETED or DENIED event, or RECOVERY_INDETERMINATE upon startup crash reconciliation.
 */
export type AuditLifecyclePhase = 'STARTED' | 'COMPLETED' | 'DENIED' | 'RECOVERY_INDETERMINATE';

/**
 * Server-generated correlation metadata for privileged operation lifecycle events.
 * Never caller-supplied.
 */
export interface AuditLifecycleMetadata {
  operationId: string;
  phase: AuditLifecyclePhase;
}

/**
 * Authoritative persistent audit record under schema version 1.
 */
export interface PersistentAuditRecordV1 extends AuditRecord {
  schemaVersion: 1;
  lifecycle?: AuditLifecycleMetadata;
}

/**
 * Protected persistent store metadata stored in audit-store.json.
 */
export interface AuditStoreMetadataV1 {
  version: 1;
  storeId: string;
  createdAt: string;
  checkpointPublicKeyFingerprint: string;
  anchorMode: 'DISABLED' | 'ENABLED';
  anchorReceiptPublicKeyFingerprint?: string;
}

/**
 * Maximum serialized size of a single persistent JSONL line in bytes,
 * including terminating newline.
 */
export const MAX_RECORD_BYTES = 65_536;
