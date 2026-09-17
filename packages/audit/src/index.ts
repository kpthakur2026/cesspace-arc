import type { AuditRecord } from '@cesspace-arc/protocol';

/**
 * Interface definition for the CesSpace ARC Audit Logger.
 * Implementation target: RC-06.
 */
export interface IAuditLogger {
  log(record: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>): Promise<AuditRecord>;
  redact(payload: Record<string, unknown>): Record<string, unknown>;
  verifyIntegrity(logFilePath: string): Promise<boolean>;
}

export type { AuditRecord };
