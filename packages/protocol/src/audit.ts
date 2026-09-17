import type { PolicyEffect } from './policy.js';

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
    workspacePath: string;
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
  integrity: {
    previousRecordHash: string;
    recordHash: string;
  };
}
