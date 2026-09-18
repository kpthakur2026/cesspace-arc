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
  integrity: {
    previousRecordHash: string;
    recordHash: string;
  };
}
