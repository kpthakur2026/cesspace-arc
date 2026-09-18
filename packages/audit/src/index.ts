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

/**
 * Obvious absolute host path prefixes. Central defense-in-depth so callers that
 * mistakenly pass a raw host path cannot leak it into a stored record.
 */
export const ABSOLUTE_PATH_REGEXES = [
  /\/(?:home|tmp|root|Users|var|private|opt|etc|usr|bin|sbin|lib|lib64|mnt|media|srv)(?:\/[^\s'",;:)\]]*)*/g,
  /[a-zA-Z]:\\[^\s'",;:)\]]*/g,
];

export const ABSOLUTE_PATH_PLACEHOLDER = '[REDACTED_PATH]';

/** Replaces obvious absolute host path text with a fixed placeholder. */
export function redactAbsolutePaths(value: string): string {
  let sanitized = value;
  for (const pattern of ABSOLUTE_PATH_REGEXES) {
    sanitized = sanitized.replace(pattern, ABSOLUTE_PATH_PLACEHOLDER);
  }
  return sanitized;
}

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
    let sanitized = redactAbsolutePaths(value);
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

/**
 * Central string redaction for free-text fields that reach a stored record.
 *
 * Applies the same absolute-path and secret-pattern redaction used for
 * parameter values, so any string a caller supplies is sanitized in one place.
 */
export function redactString(value: string): string {
  const redacted = redactValue(value);
  return typeof redacted === 'string' ? redacted : value;
}

/**
 * Copies a bounded, known record shape so a caller mutating its input object
 * after log() cannot alter historical chain content (rc04 §64).
 *
 * The copy is HASH-FAITHFUL: it preserves every own key, including keys whose
 * value is `undefined`. `canonicalJson` renders an `undefined` value literally,
 * so dropping such a key would change the canonical form of a record and make an
 * external recomputation of `integrity.recordHash` disagree with the stored
 * value, reporting a false integrity failure.
 */
function copyBounded<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => copyBounded(item)) as unknown as T;
  }
  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(source)) {
    out[key] = copyBounded(source[key]);
  }
  return out as unknown as T;
}

export function redactRecord(payload: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(payload)) {
    if (key.toLowerCase() === 'content') {
      const byteLen = typeof val === 'string' ? Buffer.byteLength(val, 'utf8') : 0;
      result[key] = `[FILE_CONTENT_OMITTED: ${byteLen} bytes]`;
      continue;
    }
    if (key.toLowerCase() === 'patch') {
      const byteLen = typeof val === 'string' ? Buffer.byteLength(val, 'utf8') : 0;
      result[key] = `[PATCH_CONTENT_OMITTED: ${byteLen} bytes]`;
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
  private appendInProgress = false;
  private sequence = 1;
  private lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';

  public async log(
    recordData: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
  ): Promise<AuditRecord> {
    return this.appendSerialized(recordData);
  }

  /**
   * Explicitly serialized append (rc04 §67).
   *
   * The hash chain must never interleave: sequence numbers must be unique and
   * contiguous, and each `previousRecordHash` must equal the prior
   * `recordHash`. `appendRecord` performs no `await`, so appends are atomic
   * within the single-threaded event loop; the re-entrancy guard below makes
   * that invariant explicit and fails loudly if a future change ever introduces
   * an await inside the critical section.
   */
  private appendSerialized(
    recordData: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
  ): AuditRecord {
    if (this.appendInProgress) {
      throw new Error('AuditLogger append re-entered: the hash chain is not serialized.');
    }
    this.appendInProgress = true;
    try {
      return this.appendRecord(recordData);
    } finally {
      this.appendInProgress = false;
    }
  }

  private appendRecord(
    recordData: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
  ): AuditRecord {
    const eventId = randomUUID();
    const sequenceNumber = this.sequence++;
    const previousRecordHash = this.lastRecordHash;

    // Build the REDACTED/minimized parameter representation FIRST, then derive
    // any fallback payload hash from it. A fallback hash must never be computed
    // from raw content, patch text, environment values, or a token (rc04 §33).
    const parametersRedacted = this.redact(recordData.invocation.parametersRedacted);
    const fallbackPayloadHash = computeSha256(canonicalJson(parametersRedacted));

    // Central defense-in-depth for the top-level error message. Redaction is
    // applied HERE, for every caller, so a writer that forgets cannot leak an
    // absolute host path or a high-confidence secret into a stored record. This
    // covers ProcessAuditSink and any future writer, not only ArcMcpServer.
    const errorRecord = recordData.error ? copyBounded(recordData.error) : undefined;
    if (errorRecord !== undefined) {
      errorRecord.message = redactString(errorRecord.message);
    }

    const baseRecord: AuditRecord = {
      eventId,
      timestamp: recordData.timestamp,
      sequenceNumber,
      actor: copyBounded(recordData.actor),
      target: this.minimizeTarget(recordData.target),
      invocation: {
        toolName: recordData.invocation.toolName,
        parametersRedacted,
        payloadHash: recordData.invocation.payloadHash || fallbackPayloadHash,
      },
      policy: copyBounded(recordData.policy),
      execution: copyBounded(recordData.execution),
      error: errorRecord,
      approval: recordData.approval ? copyBounded(recordData.approval) : undefined,
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
    // The AUTHORITATIVE record is retained internally; the caller receives a
    // defensive, hash-faithful snapshot. Returning `baseRecord` itself would
    // hand out a live reference into the hash chain, so a caller could mutate
    // `returned.policy.ruleId` (or any nested object) and silently rewrite
    // stored evidence while `verifyIntegrity()` still reported the tampered
    // content as valid.
    return copyBounded(baseRecord);
  }

  public redact(payload: Record<string, unknown>): Record<string, unknown> {
    return redactRecord(payload);
  }

  /**
   * Central audit target minimization (rc04 §31, §32, §56).
   *
   * A raw absolute workspace path MUST NOT be retained. A non-empty trusted
   * `workspacePath` is replaced by its SHA-256 digest; the raw text is dropped
   * for every caller without anyone having to remember to redact it.
   */
  private minimizeTarget(target: AuditRecord['target']): AuditRecord['target'] {
    const workspaceId = typeof target?.workspaceId === 'string' ? target.workspaceId : '';
    const workspacePath = typeof target?.workspacePath === 'string' ? target.workspacePath : '';

    // An explicitly supplied digest is always safe and is retained even when no
    // raw path was given (approval lifecycle records carry only the digest).
    const suppliedHash =
      typeof target.workspaceRootHash === 'string' &&
      /^[0-9a-f]{64}$/.test(target.workspaceRootHash)
        ? target.workspaceRootHash
        : undefined;

    if (workspacePath.length === 0) {
      return {
        workspaceId,
        workspacePath: '',
        ...(suppliedHash === undefined ? {} : { workspaceRootHash: suppliedHash }),
      };
    }

    return {
      workspaceId,
      workspacePath: '',
      workspaceRootHash: suppliedHash ?? computeSha256(workspacePath),
    };
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

  /**
   * Returns defensive snapshots (rc04 §65). Callers cannot mutate the
   * authoritative in-memory chain by mutating the returned objects.
   */
  public getRecords(): AuditRecord[] {
    return this.records.map((record) => copyBounded(record));
  }

  public clear(): void {
    this.records = [];
    this.sequence = 1;
    this.lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
  }
}

export type { AuditRecord };
