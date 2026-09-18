import { createHash, randomUUID } from 'node:crypto';
import type { AuditRecord } from '@cesspace-arc/protocol';

/**
 * Interface definition for the CesSpace ARC Audit Logger.
 * Minimal structured audit sink for RC-01 with hash chaining and redaction.
 */
export interface IAuditLogger {
  log(record: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>): Promise<AuditRecord>;
  redact(payload: Record<string, unknown>): Record<string, unknown>;
  verifyIntegrity(logFilePath?: string): Promise<boolean>;
  getRecords(): AuditRecord[];
  clear(): void;
}

export const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /auth(orization)?/i,
  /credential/i,
  /private[_-]?key/i,
  /bearer/i,
  /cert(ificate)?/i,
];

export const SENSITIVE_VALUE_REGEXES = [
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[a-zA-Z0-9]{36}/g,
  /gho_[a-zA-Z0-9]{36}/g,
  /sk-[a-zA-Z0-9]{20,}/g,
  /Bearer\s+[a-zA-Z0-9._-]+/gi,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
];

export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') {
    let sanitized = value;
    for (const pattern of SENSITIVE_VALUE_REGEXES) {
      sanitized = sanitized.replace(pattern, '[REDACTED_SECRET]');
    }
    return sanitized;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }
  if (value !== null && typeof value === 'object') {
    return redactRecord(value as Record<string, unknown>);
  }
  return value;
}

export function redactRecord(payload: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(payload)) {
    if (key.toLowerCase() === 'content' && typeof val === 'string') {
      result[key] = `[FILE_CONTENT_OMITTED: ${val.length} bytes]`;
      continue;
    }
    if (
      key.toLowerCase() === 'env' &&
      val !== null &&
      typeof val === 'object' &&
      !Array.isArray(val)
    ) {
      const redactedEnv: Record<string, string> = {};
      for (const envKey of Object.keys(val as Record<string, unknown>)) {
        redactedEnv[envKey] = '[REDACTED_ENV_VALUE]';
      }
      result[key] = redactedEnv;
      continue;
    }
    if (
      (key.toLowerCase() === 'stdout' || key.toLowerCase() === 'stderr') &&
      typeof val === 'string'
    ) {
      result[key] = `[OUTPUT_OMITTED: ${val.length} bytes]`;
      continue;
    }
    const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((p) => p.test(key));
    if (isSensitiveKey) {
      result[key] = '[REDACTED_BY_NAME]';
    } else {
      result[key] = redactValue(val);
    }
  }
  return result;
}

export function computeSha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

export function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJson((obj as Record<string, unknown>)[k])}`,
  );
  return '{' + entries.join(',') + '}';
}

/**
 * In-memory structured stream sink with sequential SHA-256 hash chaining.
 */
export class AuditLogger implements IAuditLogger {
  private records: AuditRecord[] = [];
  private sequence = 1;
  private lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';

  public async log(
    recordData: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
  ): Promise<AuditRecord> {
    const eventId = randomUUID();
    const sequenceNumber = this.sequence++;
    const previousRecordHash = this.lastRecordHash;

    const baseRecord: AuditRecord = {
      eventId,
      timestamp: recordData.timestamp,
      sequenceNumber,
      actor: recordData.actor,
      target: recordData.target,
      invocation: {
        toolName: recordData.invocation.toolName,
        parametersRedacted: this.redact(recordData.invocation.parametersRedacted),
        payloadHash:
          recordData.invocation.payloadHash ||
          computeSha256(canonicalJson(recordData.invocation.parametersRedacted)),
      },
      policy: recordData.policy,
      execution: recordData.execution,
      error: recordData.error,
      integrity: {
        previousRecordHash,
        recordHash: '',
      },
    };

    const recordToHash = {
      ...baseRecord,
      integrity: {
        previousRecordHash,
      },
    };
    const currentHash = computeSha256(canonicalJson(recordToHash));
    baseRecord.integrity.recordHash = currentHash;
    this.lastRecordHash = currentHash;

    this.records.push(baseRecord);
    return baseRecord;
  }

  public redact(payload: Record<string, unknown>): Record<string, unknown> {
    return redactRecord(payload);
  }

  public async verifyIntegrity(): Promise<boolean> {
    let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < this.records.length; i++) {
      const rec = this.records[i];
      if (rec.sequenceNumber !== i + 1) {
        return false;
      }
      if (rec.integrity.previousRecordHash !== prevHash) {
        return false;
      }
      const recordToHash = {
        ...rec,
        integrity: {
          previousRecordHash: prevHash,
        },
      };
      const expectedHash = computeSha256(canonicalJson(recordToHash));
      if (rec.integrity.recordHash !== expectedHash) {
        return false;
      }
      prevHash = rec.integrity.recordHash;
    }
    return true;
  }

  public getRecords(): AuditRecord[] {
    return [...this.records];
  }

  public clear(): void {
    this.records = [];
    this.sequence = 1;
    this.lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
  }
}

export type { AuditRecord };
