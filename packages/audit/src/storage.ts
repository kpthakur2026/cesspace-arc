import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import {
  APPROVAL_AUDIT_EVENT_TYPES,
  APPROVAL_FAILURE_REASON_CODES,
  APPROVAL_STATES,
  GATEWAY_AUDIT_EVENT_TYPES,
  GATEWAY_AUDIT_REASONS,
  MAX_RECORD_BYTES,
  type ApprovalAuditEventType,
  type ApprovalFailureReasonCode,
  type ApprovalState,
  type AuditRecord,
  type AuditStoreMetadataV1,
  type PersistentAuditRecordV1,
} from '@cesspace-arc/protocol';
import {
  METADATA_FILENAME,
  createStoreMetadataFile,
  loadStoreMetadataFile,
  normalizeStoreMetadataConfig,
  validateStoreMetadataConsistency,
} from './metadata.js';
import { acquireWriterLock, type AuditLockAcquisition } from './lock.js';

export const DEFAULT_AUDIT_DIR = path.join(os.homedir(), '.cesspace-arc', 'audit');
export const ACTIVE_SEGMENT_FILENAME = 'audit-active.jsonl';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-f]{64}$/;
const HEX32_REGEX = /^[0-9a-f]{32}$/;
const PRINTABLE_ASCII_128_REGEX = /^[\x20-\x7e]{1,128}$/;
const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const POLICY_DECISION_SET = new Set(['ALLOW', 'DENY', 'REQUIRE_APPROVAL']);
const EXECUTION_STATUS_SET = new Set(['SUCCESS', 'ERROR', 'DENIED', 'TIMEOUT', 'CANCELLED']);
const LIFECYCLE_PHASE_SET = new Set(['STARTED', 'COMPLETED', 'DENIED', 'RECOVERY_INDETERMINATE']);
const APPROVAL_EVENT_TYPE_SET = new Set(APPROVAL_AUDIT_EVENT_TYPES);
const APPROVAL_STATE_SET = new Set(APPROVAL_STATES);
const APPROVAL_FAILURE_REASON_CODE_SET = new Set(APPROVAL_FAILURE_REASON_CODES);
const APPROVAL_SOURCE_SET = new Set(['MCP', 'LOCAL_OPERATOR', 'SYSTEM']);
const GATEWAY_AUDIT_EVENT_SET = new Set(GATEWAY_AUDIT_EVENT_TYPES);
const GATEWAY_AUDIT_REASON_SET = new Set(GATEWAY_AUDIT_REASONS);
const GATEWAY_ADMISSION_LAYER_SET = new Set(['A', 'B', 'C']);
const GATEWAY_TRANSPORT_MODE_SET = new Set(['stdio', 'remote']);

export const PERSISTENT_RECORD_V1_ALLOWED_KEYS = new Set([
  'eventId',
  'timestamp',
  'sequenceNumber',
  'actor',
  'target',
  'invocation',
  'policy',
  'execution',
  'error',
  'approval',
  'gateway',
  'lifecycle',
  'integrity',
  'schemaVersion',
]);

export const ACTOR_ALLOWED_KEYS = new Set(['clientId', 'clientType', 'deviceId', 'sessionId']);
export const TARGET_ALLOWED_KEYS = new Set(['workspaceId', 'workspacePath', 'workspaceRootHash']);
export const INVOCATION_ALLOWED_KEYS = new Set(['toolName', 'parametersRedacted', 'payloadHash']);
export const POLICY_ALLOWED_KEYS = new Set([
  'decision',
  'ruleId',
  'evaluationDurationMs',
  'approvalId',
]);
export const EXECUTION_ALLOWED_KEYS = new Set([
  'status',
  'startTime',
  'endTime',
  'durationMs',
  'exitCode',
  'bytesRead',
  'bytesWritten',
  'changedFiles',
]);
export const ERROR_ALLOWED_KEYS = new Set(['code', 'message']);
export const LIFECYCLE_ALLOWED_KEYS = new Set(['operationId', 'phase']);
export const APPROVAL_ALLOWED_KEYS = new Set([
  'eventType',
  'requestId',
  'state',
  'source',
  'reasonCode',
  'operatorReasonProvided',
]);
export const GATEWAY_ALLOWED_KEYS = new Set([
  'eventType',
  'reason',
  'admissionLayer',
  'mcpSessionId',
  'deviceId',
  'spkiPin',
  'clientId',
  'clientType',
  'enrollmentId',
  'transportMode',
]);
export const INTEGRITY_ALLOWED_KEYS = new Set(['previousRecordHash', 'recordHash']);

export interface CodedError extends Error {
  code?: string;
}

export function createCodedError(
  code: string,
  message: string,
  options?: { cause?: unknown },
): CodedError {
  const err = new Error(`${code}: ${message}`, options) as CodedError;
  err.code = code;
  return err;
}

export function getProcessUid(): number {
  return typeof process.getuid === 'function' ? process.getuid() : -1;
}

export interface PlatformCapabilities {
  hasGetUid: boolean;
  isPosixPlatform: boolean;
  hasONoFollow: boolean;
  hasOCreatExcl: boolean;
  hasFstat: boolean;
  hasFsync: boolean;
}

export function detectPlatformCapabilities(): PlatformCapabilities {
  return {
    hasGetUid: typeof process.getuid === 'function',
    isPosixPlatform: process.platform !== 'win32',
    hasONoFollow: typeof fsConstants.O_NOFOLLOW === 'number',
    hasOCreatExcl:
      typeof fsConstants.O_CREAT === 'number' && typeof fsConstants.O_EXCL === 'number',
    hasFstat: typeof fs.fstatSync === 'function',
    hasFsync: typeof fs.fsyncSync === 'function',
  };
}

export function validatePlatformCapabilities(probe?: Partial<PlatformCapabilities>): void {
  const current = { ...detectPlatformCapabilities(), ...probe };
  if (
    !current.hasGetUid ||
    !current.isPosixPlatform ||
    !current.hasONoFollow ||
    !current.hasOCreatExcl ||
    !current.hasFstat ||
    !current.hasFsync
  ) {
    throw createCodedError(
      'AUDIT_PLATFORM_UNSUPPORTED',
      'host platform lacks required POSIX audit security primitives',
    );
  }
}

export function validateAuditDirectory(
  auditDir: string,
  options: {
    createIfMissing?: boolean;
    workspacePaths?: string[];
    expectedUid?: number;
  } = {},
): fs.Stats {
  const { createIfMissing = false, workspacePaths = [], expectedUid = getProcessUid() } = options;

  if (typeof auditDir !== 'string' || auditDir.length === 0) {
    throw createCodedError('INVALID_AUDIT_PATH', 'audit directory path is required');
  }

  if (auditDir.includes('~')) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      'literal ~ is not allowed in audit directory path',
    );
  }

  if (!path.isAbsolute(auditDir)) {
    throw createCodedError('INVALID_AUDIT_PATH', `path must be absolute: "${auditDir}"`);
  }

  const normalized = path.normalize(auditDir);
  if (normalized !== auditDir || auditDir.includes('..')) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      `directory traversal is forbidden in path: "${auditDir}"`,
    );
  }

  for (const ws of workspacePaths) {
    const normWs = path.resolve(ws);
    const normDir = path.resolve(auditDir);
    if (
      normDir === normWs ||
      normDir.startsWith(normWs + path.sep) ||
      normWs.startsWith(normDir + path.sep)
    ) {
      throw createCodedError(
        'INVALID_AUDIT_PATH',
        `audit directory overlaps agent workspace: "${auditDir}"`,
      );
    }
  }

  const segments = path.resolve(auditDir).split(path.sep);
  let currentPath = '';
  for (let i = 1; i < segments.length - 1; i++) {
    currentPath += path.sep + segments[i];
    if (fs.existsSync(currentPath)) {
      try {
        const lstat = fs.lstatSync(currentPath);
        if (lstat.isSymbolicLink()) {
          throw createCodedError(
            'SYMLINK_DETECTED',
            `parent component is a symbolic link: "${currentPath}"`,
          );
        }
      } catch (err: unknown) {
        if (
          typeof err === 'object' &&
          err !== null &&
          'code' in err &&
          (err as { code: unknown }).code === 'SYMLINK_DETECTED'
        ) {
          throw err;
        }
      }
    }
  }

  if (!fs.existsSync(auditDir)) {
    if (!createIfMissing) {
      throw createCodedError('INVALID_AUDIT_PATH', `directory does not exist: "${auditDir}"`);
    }
    try {
      fs.mkdirSync(auditDir, { mode: 0o700, recursive: true });
      fs.chmodSync(auditDir, 0o700);
    } catch (cause) {
      throw createCodedError(
        'INVALID_AUDIT_PATH',
        `failed to create audit directory: "${auditDir}"`,
        { cause },
      );
    }
  }

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(auditDir);
  } catch (cause) {
    throw createCodedError('INVALID_AUDIT_PATH', `cannot stat audit directory: "${auditDir}"`, {
      cause,
    });
  }

  if (stats.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', `audit directory is a symbolic link: "${auditDir}"`);
  }

  if (!stats.isDirectory()) {
    throw createCodedError(
      'INVALID_AUDIT_PATH',
      `audit directory path is not a directory: "${auditDir}"`,
    );
  }

  if (stats.uid !== expectedUid) {
    throw createCodedError(
      'OWNERSHIP_MISMATCH',
      `audit directory owner (${stats.uid}) does not match process UID (${expectedUid})`,
    );
  }

  const mode = stats.mode & 0o777;
  if (mode !== 0o700) {
    throw createCodedError(
      'INSECURE_PERMISSIONS',
      `directory permissions 0${mode.toString(8)} wider than 0700`,
    );
  }

  return stats;
}

export function validateFileDescriptorAuthority(
  fd: number,
  expectedMode = 0o600,
  expectedUid = getProcessUid(),
): fs.Stats {
  const stats = fs.fstatSync(fd);

  if (!stats.isFile()) {
    throw createCodedError('NOT_REGULAR_FILE', 'target audit path is not a regular file');
  }

  if (stats.uid !== expectedUid) {
    throw createCodedError(
      'OWNERSHIP_MISMATCH',
      `file owner (${stats.uid}) does not match required UID (${expectedUid})`,
    );
  }

  const mode = stats.mode & 0o777;
  if (mode !== expectedMode) {
    throw createCodedError(
      'INSECURE_PERMISSIONS',
      `file permissions 0${mode.toString(8)} wider than expected 0${expectedMode.toString(8)}`,
    );
  }

  if (stats.nlink !== 1) {
    throw createCodedError('HARD_LINK_DETECTED', `file has hard link count ${stats.nlink} > 1`);
  }

  return stats;
}

export function canonicalJsonV1(val: unknown, seen: Set<object> = new Set()): string {
  if (val === undefined) {
    throw createCodedError(
      'CANONICAL_JSON_UNDEFINED',
      'undefined is not permitted in canonical JSON V1',
    );
  }

  if (typeof val === 'number') {
    if (!Number.isFinite(val)) {
      throw createCodedError(
        'CANONICAL_JSON_INVALID_NUMBER',
        `non-finite number ${val} is not permitted`,
      );
    }
    return JSON.stringify(val);
  }

  if (typeof val === 'string' || typeof val === 'boolean' || val === null) {
    return JSON.stringify(val);
  }

  if (typeof val === 'bigint' || typeof val === 'symbol' || typeof val === 'function') {
    throw createCodedError('CANONICAL_JSON_UNSUPPORTED_TYPE', `unsupported type ${typeof val}`);
  }

  if (typeof val === 'object') {
    if (seen.has(val)) {
      throw createCodedError('CANONICAL_JSON_CIRCULAR', 'circular object structure detected');
    }
    seen.add(val);
    try {
      if (Array.isArray(val)) {
        const elements = val.map((item) => {
          if (item === undefined) {
            throw createCodedError(
              'CANONICAL_JSON_UNDEFINED',
              'undefined is not permitted in arrays',
            );
          }
          return canonicalJsonV1(item, seen);
        });
        return '[' + elements.join(',') + ']';
      }

      const proto = Object.getPrototypeOf(val);
      if (proto !== null && proto !== Object.prototype) {
        throw createCodedError('CANONICAL_JSON_EXOTIC_OBJECT', 'only plain objects are supported');
      }

      const keys = Object.keys(val as Record<string, unknown>).sort();
      const parts: string[] = [];
      for (const key of keys) {
        const propVal = (val as Record<string, unknown>)[key];
        if (propVal === undefined) {
          continue;
        }
        parts.push(`${JSON.stringify(key)}:${canonicalJsonV1(propVal, seen)}`);
      }
      return '{' + parts.join(',') + '}';
    } finally {
      seen.delete(val);
    }
  }

  throw createCodedError('CANONICAL_JSON_UNSUPPORTED_VALUE', 'unsupported value');
}

export function validateIntegrityObjectV1(integrity: unknown, requireRecordHash = true): void {
  if (typeof integrity !== 'object' || integrity === null || Array.isArray(integrity)) {
    throw createCodedError('INVALID_RECORD', 'integrity must be a plain object');
  }
  const obj = integrity as Record<string, unknown>;
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!INTEGRITY_ALLOWED_KEYS.has(k)) {
      throw createCodedError(
        'UNKNOWN_FIELD',
        `unknown field "${k}" in integrity object outside V1 schema`,
      );
    }
  }

  if (!('previousRecordHash' in obj)) {
    throw createCodedError('INVALID_RECORD', 'integrity missing previousRecordHash');
  }
  if (typeof obj.previousRecordHash !== 'string' || !HEX64_REGEX.test(obj.previousRecordHash)) {
    throw createCodedError(
      'INVALID_RECORD',
      'integrity.previousRecordHash must be exactly 64 lowercase hex characters',
    );
  }

  if (requireRecordHash) {
    if (!('recordHash' in obj)) {
      throw createCodedError('INVALID_RECORD', 'integrity missing recordHash');
    }
    if (typeof obj.recordHash !== 'string' || !HEX64_REGEX.test(obj.recordHash)) {
      throw createCodedError(
        'INVALID_RECORD',
        'integrity.recordHash must be exactly 64 lowercase hex characters',
      );
    }
  }
}

export function computeRecordHashPreimageV1(record: PersistentAuditRecordV1): string {
  validateIntegrityObjectV1(record.integrity, false);
  const { recordHash: _recordHash, ...integrityWithoutRecordHash } = record.integrity;
  void _recordHash;
  const preimageRecord = {
    ...record,
    integrity: integrityWithoutRecordHash,
  };
  return canonicalJsonV1(preimageRecord);
}

export function computeRecordHashV1(record: PersistentAuditRecordV1): string {
  const preimage = computeRecordHashPreimageV1(record);
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}

export function serializeRecordV1(record: PersistentAuditRecordV1): string {
  return canonicalJsonV1(record) + '\n';
}

function hasUnescapedControlChars(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) < 0x20) {
      return true;
    }
  }
  return false;
}

export function validatePersistentRecordV1(input: unknown, requireRecordHash = true): void {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw createCodedError('INVALID_RECORD', 'record must be a plain JSON object');
  }
  const rec = input as Record<string, unknown>;

  if (!('schemaVersion' in rec)) {
    throw createCodedError(
      'MISSING_SCHEMA_VERSION',
      'record is missing mandatory schemaVersion field',
    );
  }
  if (rec.schemaVersion !== 1) {
    throw createCodedError(
      'UNSUPPORTED_SCHEMA_VERSION',
      `schemaVersion must be 1 (got ${String(rec.schemaVersion)})`,
    );
  }

  for (const k of Object.keys(rec)) {
    if (!PERSISTENT_RECORD_V1_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown top-level field "${k}" outside V1 schema`);
    }
  }

  const requiredFields = [
    'eventId',
    'timestamp',
    'sequenceNumber',
    'actor',
    'target',
    'invocation',
    'policy',
    'execution',
    'integrity',
  ];
  for (const field of requiredFields) {
    if (!(field in rec) || rec[field] === undefined) {
      throw createCodedError('INVALID_RECORD', `missing required field "${field}"`);
    }
  }

  // eventId
  if (typeof rec.eventId !== 'string' || !UUID_REGEX.test(rec.eventId)) {
    throw createCodedError('INVALID_RECORD', 'eventId must be a valid UUID');
  }

  // timestamp
  if (
    typeof rec.timestamp !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(rec.timestamp) ||
    isNaN(Date.parse(rec.timestamp)) ||
    new Date(rec.timestamp).toISOString() !== rec.timestamp
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'timestamp must be a canonical UTC ISO-8601 string (YYYY-MM-DDTHH:mm:ss.sssZ)',
    );
  }

  // sequenceNumber
  if (
    typeof rec.sequenceNumber !== 'number' ||
    !Number.isSafeInteger(rec.sequenceNumber) ||
    rec.sequenceNumber < 1
  ) {
    throw createCodedError('INVALID_RECORD', 'sequenceNumber must be a safe integer >= 1');
  }

  // actor
  if (typeof rec.actor !== 'object' || rec.actor === null || Array.isArray(rec.actor)) {
    throw createCodedError('INVALID_RECORD', 'actor must be a plain object');
  }
  const actor = rec.actor as Record<string, unknown>;
  for (const k of Object.keys(actor)) {
    if (!ACTOR_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in actor`);
    }
  }
  for (const k of ['clientId', 'clientType', 'deviceId', 'sessionId']) {
    if (typeof actor[k] !== 'string') {
      throw createCodedError('INVALID_RECORD', `actor.${k} must be a string`);
    }
  }

  // target
  if (typeof rec.target !== 'object' || rec.target === null || Array.isArray(rec.target)) {
    throw createCodedError('INVALID_RECORD', 'target must be a plain object');
  }
  const target = rec.target as Record<string, unknown>;
  for (const k of Object.keys(target)) {
    if (!TARGET_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in target`);
    }
  }
  if (typeof target.workspaceId !== 'string') {
    throw createCodedError('INVALID_RECORD', 'target.workspaceId must be a string');
  }
  if (typeof target.workspacePath !== 'string') {
    throw createCodedError('INVALID_RECORD', 'target.workspacePath must be a string');
  }
  if (
    target.workspaceRootHash !== undefined &&
    (typeof target.workspaceRootHash !== 'string' || !HEX64_REGEX.test(target.workspaceRootHash))
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'target.workspaceRootHash must be 64 lowercase hex characters',
    );
  }

  // invocation
  if (
    typeof rec.invocation !== 'object' ||
    rec.invocation === null ||
    Array.isArray(rec.invocation)
  ) {
    throw createCodedError('INVALID_RECORD', 'invocation must be a plain object');
  }
  const inv = rec.invocation as Record<string, unknown>;
  for (const k of Object.keys(inv)) {
    if (!INVOCATION_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in invocation`);
    }
  }
  if (typeof inv.toolName !== 'string') {
    throw createCodedError('INVALID_RECORD', 'invocation.toolName must be a string');
  }
  if (typeof inv.payloadHash !== 'string' || !HEX64_REGEX.test(inv.payloadHash)) {
    throw createCodedError(
      'INVALID_RECORD',
      'invocation.payloadHash must be 64 lowercase hex characters',
    );
  }
  if (
    typeof inv.parametersRedacted !== 'object' ||
    inv.parametersRedacted === null ||
    Array.isArray(inv.parametersRedacted)
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'invocation.parametersRedacted must be a plain object',
    );
  }
  canonicalJsonV1(inv.parametersRedacted);

  // policy
  if (typeof rec.policy !== 'object' || rec.policy === null || Array.isArray(rec.policy)) {
    throw createCodedError('INVALID_RECORD', 'policy must be a plain object');
  }
  const policy = rec.policy as Record<string, unknown>;
  for (const k of Object.keys(policy)) {
    if (!POLICY_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in policy`);
    }
  }
  if (typeof policy.decision !== 'string' || !POLICY_DECISION_SET.has(policy.decision)) {
    throw createCodedError(
      'INVALID_RECORD',
      'policy.decision must be ALLOW, DENY, or REQUIRE_APPROVAL',
    );
  }
  if (typeof policy.ruleId !== 'string') {
    throw createCodedError('INVALID_RECORD', 'policy.ruleId must be a string');
  }
  if (
    typeof policy.evaluationDurationMs !== 'number' ||
    !Number.isFinite(policy.evaluationDurationMs) ||
    policy.evaluationDurationMs < 0
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'policy.evaluationDurationMs must be a finite non-negative number',
    );
  }
  if (policy.approvalId !== undefined && typeof policy.approvalId !== 'string') {
    throw createCodedError('INVALID_RECORD', 'policy.approvalId must be a string');
  }

  // execution
  if (typeof rec.execution !== 'object' || rec.execution === null || Array.isArray(rec.execution)) {
    throw createCodedError('INVALID_RECORD', 'execution must be a plain object');
  }
  const exec = rec.execution as Record<string, unknown>;
  for (const k of Object.keys(exec)) {
    if (!EXECUTION_ALLOWED_KEYS.has(k)) {
      throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in execution`);
    }
  }
  if (typeof exec.status !== 'string' || !EXECUTION_STATUS_SET.has(exec.status)) {
    throw createCodedError('INVALID_RECORD', 'execution.status has invalid value');
  }
  if (
    typeof exec.startTime !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(exec.startTime) ||
    isNaN(Date.parse(exec.startTime)) ||
    new Date(exec.startTime).toISOString() !== exec.startTime
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'execution.startTime must be a canonical ISO timestamp',
    );
  }
  if (
    typeof exec.endTime !== 'string' ||
    !ISO_TIMESTAMP_REGEX.test(exec.endTime) ||
    isNaN(Date.parse(exec.endTime)) ||
    new Date(exec.endTime).toISOString() !== exec.endTime
  ) {
    throw createCodedError('INVALID_RECORD', 'execution.endTime must be a canonical ISO timestamp');
  }
  if (
    typeof exec.durationMs !== 'number' ||
    !Number.isFinite(exec.durationMs) ||
    exec.durationMs < 0
  ) {
    throw createCodedError('INVALID_RECORD', 'execution.durationMs must be a non-negative number');
  }
  if (
    exec.exitCode !== undefined &&
    (typeof exec.exitCode !== 'number' || !Number.isSafeInteger(exec.exitCode))
  ) {
    throw createCodedError('INVALID_RECORD', 'execution.exitCode must be an integer');
  }
  if (
    exec.bytesRead !== undefined &&
    (typeof exec.bytesRead !== 'number' ||
      !Number.isSafeInteger(exec.bytesRead) ||
      exec.bytesRead < 0)
  ) {
    throw createCodedError('INVALID_RECORD', 'execution.bytesRead must be a non-negative integer');
  }
  if (
    exec.bytesWritten !== undefined &&
    (typeof exec.bytesWritten !== 'number' ||
      !Number.isSafeInteger(exec.bytesWritten) ||
      exec.bytesWritten < 0)
  ) {
    throw createCodedError(
      'INVALID_RECORD',
      'execution.bytesWritten must be a non-negative integer',
    );
  }
  if (
    exec.changedFiles !== undefined &&
    (!Array.isArray(exec.changedFiles) || !exec.changedFiles.every((f) => typeof f === 'string'))
  ) {
    throw createCodedError('INVALID_RECORD', 'execution.changedFiles must be an array of strings');
  }

  // error (optional)
  if (rec.error !== undefined) {
    if (typeof rec.error !== 'object' || rec.error === null || Array.isArray(rec.error)) {
      throw createCodedError('INVALID_RECORD', 'error must be a plain object');
    }
    const errObj = rec.error as Record<string, unknown>;
    for (const k of Object.keys(errObj)) {
      if (!ERROR_ALLOWED_KEYS.has(k)) {
        throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in error`);
      }
    }
    if (typeof errObj.code !== 'string' || typeof errObj.message !== 'string') {
      throw createCodedError('INVALID_RECORD', 'error.code and error.message must be strings');
    }
  }

  // lifecycle (optional)
  if (rec.lifecycle !== undefined) {
    if (
      typeof rec.lifecycle !== 'object' ||
      rec.lifecycle === null ||
      Array.isArray(rec.lifecycle)
    ) {
      throw createCodedError('INVALID_RECORD', 'lifecycle must be a plain object');
    }
    const lc = rec.lifecycle as Record<string, unknown>;
    for (const k of Object.keys(lc)) {
      if (!LIFECYCLE_ALLOWED_KEYS.has(k)) {
        throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in lifecycle`);
      }
    }
    if (typeof lc.operationId !== 'string' || !UUID_V4_REGEX.test(lc.operationId)) {
      throw createCodedError('INVALID_RECORD', 'lifecycle.operationId must be a valid UUIDv4');
    }
    if (typeof lc.phase !== 'string' || !LIFECYCLE_PHASE_SET.has(lc.phase)) {
      throw createCodedError('INVALID_RECORD', 'lifecycle.phase has invalid value');
    }
  }

  // approval (optional)
  if (rec.approval !== undefined) {
    if (typeof rec.approval !== 'object' || rec.approval === null || Array.isArray(rec.approval)) {
      throw createCodedError('INVALID_RECORD', 'approval must be a plain object');
    }
    const app = rec.approval as Record<string, unknown>;
    for (const k of Object.keys(app)) {
      if (!APPROVAL_ALLOWED_KEYS.has(k)) {
        throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in approval`);
      }
    }
    if (
      app.eventType !== undefined &&
      (typeof app.eventType !== 'string' ||
        !APPROVAL_EVENT_TYPE_SET.has(app.eventType as ApprovalAuditEventType))
    ) {
      throw createCodedError('INVALID_RECORD', 'approval.eventType has invalid value');
    }
    if (app.requestId !== undefined && typeof app.requestId !== 'string') {
      throw createCodedError('INVALID_RECORD', 'approval.requestId must be a string');
    }
    if (
      app.state !== undefined &&
      (typeof app.state !== 'string' || !APPROVAL_STATE_SET.has(app.state as ApprovalState))
    ) {
      throw createCodedError('INVALID_RECORD', 'approval.state has invalid value');
    }
    if (
      app.source !== undefined &&
      (typeof app.source !== 'string' || !APPROVAL_SOURCE_SET.has(app.source))
    ) {
      throw createCodedError('INVALID_RECORD', 'approval.source has invalid value');
    }
    if (
      app.reasonCode !== undefined &&
      (typeof app.reasonCode !== 'string' ||
        !APPROVAL_FAILURE_REASON_CODE_SET.has(app.reasonCode as ApprovalFailureReasonCode))
    ) {
      throw createCodedError('INVALID_RECORD', 'approval.reasonCode has invalid value');
    }
    if (
      app.operatorReasonProvided !== undefined &&
      typeof app.operatorReasonProvided !== 'boolean'
    ) {
      throw createCodedError('INVALID_RECORD', 'approval.operatorReasonProvided must be a boolean');
    }
  }

  // gateway (optional)
  if (rec.gateway !== undefined) {
    if (typeof rec.gateway !== 'object' || rec.gateway === null || Array.isArray(rec.gateway)) {
      throw createCodedError('INVALID_RECORD', 'gateway must be a plain object');
    }
    const gw = rec.gateway as Record<string, unknown>;
    for (const k of Object.keys(gw)) {
      if (!GATEWAY_ALLOWED_KEYS.has(k)) {
        throw createCodedError('UNKNOWN_FIELD', `unknown field "${k}" in gateway`);
      }
    }
    if (
      typeof gw.eventType !== 'string' ||
      !GATEWAY_AUDIT_EVENT_SET.has(gw.eventType as (typeof GATEWAY_AUDIT_EVENT_TYPES)[number])
    ) {
      throw createCodedError('INVALID_RECORD', 'gateway.eventType has invalid value');
    }
    if (
      gw.reason !== undefined &&
      (typeof gw.reason !== 'string' ||
        !GATEWAY_AUDIT_REASON_SET.has(gw.reason as (typeof GATEWAY_AUDIT_REASONS)[number]))
    ) {
      throw createCodedError('INVALID_RECORD', 'gateway.reason has invalid value');
    }
    if (
      gw.admissionLayer !== undefined &&
      (typeof gw.admissionLayer !== 'string' || !GATEWAY_ADMISSION_LAYER_SET.has(gw.admissionLayer))
    ) {
      throw createCodedError('INVALID_RECORD', 'gateway.admissionLayer has invalid value');
    }
    if (
      gw.mcpSessionId !== undefined &&
      (typeof gw.mcpSessionId !== 'string' || !HEX64_REGEX.test(gw.mcpSessionId))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.mcpSessionId must be exactly 64 lowercase hex characters',
      );
    }
    if (
      gw.deviceId !== undefined &&
      (typeof gw.deviceId !== 'string' || !HEX32_REGEX.test(gw.deviceId))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.deviceId must be exactly 32 lowercase hex characters',
      );
    }
    if (
      gw.spkiPin !== undefined &&
      (typeof gw.spkiPin !== 'string' || !HEX64_REGEX.test(gw.spkiPin))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.spkiPin must be exactly 64 lowercase hex characters',
      );
    }
    if (
      gw.enrollmentId !== undefined &&
      (typeof gw.enrollmentId !== 'string' || !HEX32_REGEX.test(gw.enrollmentId))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.enrollmentId must be exactly 32 lowercase hex characters',
      );
    }
    if (
      gw.clientId !== undefined &&
      (typeof gw.clientId !== 'string' || !PRINTABLE_ASCII_128_REGEX.test(gw.clientId))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.clientId must be printable ASCII with length between 1 and 128',
      );
    }
    if (
      gw.clientType !== undefined &&
      (typeof gw.clientType !== 'string' || !PRINTABLE_ASCII_128_REGEX.test(gw.clientType))
    ) {
      throw createCodedError(
        'INVALID_RECORD',
        'gateway.clientType must be printable ASCII with length between 1 and 128',
      );
    }
    if (
      gw.transportMode !== undefined &&
      (typeof gw.transportMode !== 'string' || !GATEWAY_TRANSPORT_MODE_SET.has(gw.transportMode))
    ) {
      throw createCodedError('INVALID_RECORD', 'gateway.transportMode has invalid value');
    }
  }

  validateIntegrityObjectV1(rec.integrity, requireRecordHash);
}

export function parseAndValidateRecordLineV1(line: string): {
  record: PersistentAuditRecordV1;
  computedHash: string;
} {
  if (!line.endsWith('\n')) {
    throw createCodedError('INVALID_LINE', 'line missing terminating newline');
  }

  if (line.includes('\r')) {
    throw createCodedError('INVALID_LINE', 'line contains carriage return character');
  }

  const byteLength = Buffer.byteLength(line, 'utf8');
  if (byteLength > MAX_RECORD_BYTES) {
    throw createCodedError(
      'RECORD_TOO_LARGE',
      `line exceeds maximum size of ${MAX_RECORD_BYTES} bytes (actual: ${byteLength})`,
    );
  }

  const text = line.slice(0, -1);
  if (hasUnescapedControlChars(text)) {
    throw createCodedError('INVALID_LINE', 'line contains unescaped control characters');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw createCodedError('MALFORMED_JSON', 'line contains malformed JSON', { cause });
  }

  validatePersistentRecordV1(parsed, true);

  const record = parsed as unknown as PersistentAuditRecordV1;

  const expectedLine = canonicalJsonV1(record) + '\n';
  if (line !== expectedLine) {
    throw createCodedError(
      'NON_CANONICAL_RECORD',
      'record JSON formatting is not strictly canonical JSONL',
    );
  }

  const computedHash = computeRecordHashV1(record);
  if (record.integrity.recordHash !== computedHash) {
    throw createCodedError(
      'HASH_MISMATCH',
      `recordHash ${record.integrity.recordHash} does not match computed hash ${computedHash}`,
    );
  }

  return { record, computedHash };
}

export type StorageState = 'UNINITIALIZED' | 'ACTIVE' | 'FAILED' | 'CLOSED';

export interface PersistentAuditStorageConfig {
  directory?: string;
  metadata: {
    checkpointPublicKeyFingerprint: string;
    anchorMode?: 'DISABLED' | 'ENABLED';
    anchorReceiptPublicKeyFingerprint?: string;
  };
  createIfMissing?: boolean;
  workspacePaths?: string[];
  expectedUid?: number;
  platformProbe?: Partial<PlatformCapabilities>;
}

import {
  RECOVERY_HANDOFF_TOKEN,
  type VerifiedRecoveryHandoff,
} from './internal/recovery-capability.js';
import {
  STORAGE_TEST_TOKEN,
  type StorageTestFaults,
  type StorageTestHooks,
} from './internal/storage-capability.js';
import {
  ROTATION_CAPABILITY_TOKEN,
  type RotationStorageCapability,
} from './internal/rotation-capability.js';
import { isValidRotatedSegmentFilename } from './rotation-filename.js';

export class PersistentAuditStorage {
  /** @internal Package-private recovery bootstrap */
  public static _fromVerifiedRecovery(
    token: symbol,
    config: PersistentAuditStorageConfig,
    handoff: VerifiedRecoveryHandoff,
    internalHooks?: StorageTestHooks,
  ): PersistentAuditStorage {
    if (token !== RECOVERY_HANDOFF_TOKEN) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'unauthorized recovery handoff');
    }
    const storage = new (
      PersistentAuditStorage as unknown as {
        new (
          config: PersistentAuditStorageConfig,
          token: symbol,
          hooks?: StorageTestHooks,
        ): PersistentAuditStorage;
      }
    )(config, STORAGE_TEST_TOKEN, internalHooks);
    storage.lock = handoff.lock;
    storage.metadata = handoff.metadata;
    storage.activeFd = handoff.activeFd;
    storage.currentSequence = handoff.terminalSequence > 0 ? handoff.terminalSequence + 1 : 1;
    storage.lastRecordHash = handoff.terminalRecordHash;
    storage.state = 'ACTIVE';
    return storage;
  }
  private readonly auditDir: string;
  private readonly activePath: string;
  private readonly config: PersistentAuditStorageConfig;
  private readonly expectedUid: number;
  private lock: AuditLockAcquisition | null = null;
  private activeFd: number | null = null;
  private metadata: AuditStoreMetadataV1 | null = null;
  private currentSequence = 1;
  private lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
  private appendInProgress = false;
  private state: StorageState = 'UNINITIALIZED';
  private readonly _testFaults?: StorageTestFaults;
  private readonly _testHooks?: StorageTestHooks;

  constructor(config: PersistentAuditStorageConfig);
  constructor(config: PersistentAuditStorageConfig, ...rest: unknown[]) {
    if (rest.length > 0) {
      const [token, internalHooks] = rest;
      if (token !== STORAGE_TEST_TOKEN) {
        throw createCodedError(
          'AUDIT_STORAGE_INVALID_CONFIG',
          'Unexpected constructor arguments; test hooks require internal capability',
        );
      }
      const hooks = internalHooks as StorageTestHooks | undefined;
      this._testFaults = hooks?.testFaults;
      this._testHooks = hooks;
    }
    this.config = config;
    this.expectedUid = config.expectedUid ?? getProcessUid();
    this.auditDir = config.directory ?? DEFAULT_AUDIT_DIR;
    this.activePath = path.join(this.auditDir, ACTIVE_SEGMENT_FILENAME);
  }

  public getState(): StorageState {
    return this.state;
  }

  public initialize(): void {
    if (this.state !== 'UNINITIALIZED') {
      throw createCodedError(
        'AUDIT_STORAGE_INVALID_STATE',
        `cannot initialize from state ${this.state}`,
      );
    }

    validatePlatformCapabilities(this.config.platformProbe);

    validateAuditDirectory(this.auditDir, {
      createIfMissing: this.config.createIfMissing ?? false,
      workspacePaths: this.config.workspacePaths,
      expectedUid: this.expectedUid,
    });

    const normalizedMetadata = normalizeStoreMetadataConfig(this.config.metadata);

    this.lock = acquireWriterLock({
      auditDir: this.auditDir,
      expectedUid: this.expectedUid,
    });

    try {
      const metadataPath = path.join(this.auditDir, METADATA_FILENAME);

      if (!fs.existsSync(metadataPath)) {
        if (fs.existsSync(this.activePath)) {
          const lstat = fs.lstatSync(this.activePath);
          if (lstat.isSymbolicLink()) {
            throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
          }

          let probeFd: number;
          try {
            probeFd = fs.openSync(this.activePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
          } catch (err: unknown) {
            const errCode =
              typeof err === 'object' && err !== null && 'code' in err
                ? (err as { code: unknown }).code
                : undefined;

            if (errCode === 'ELOOP') {
              throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
            }
            throw err;
          }

          try {
            const probeStats = validateFileDescriptorAuthority(probeFd, 0o600, this.expectedUid);
            if (probeStats.size > 0) {
              throw createCodedError(
                'METADATA_MISSING',
                'audit-store.json missing on non-empty store',
              );
            }
          } finally {
            fs.closeSync(probeFd);
          }
        }

        const freshMetadata: AuditStoreMetadataV1 = {
          version: 1,
          storeId: randomUUID(),
          createdAt: new Date().toISOString(),
          checkpointPublicKeyFingerprint: normalizedMetadata.checkpointPublicKeyFingerprint,
          anchorMode: normalizedMetadata.anchorMode,
          ...(normalizedMetadata.anchorMode === 'ENABLED' &&
          normalizedMetadata.anchorReceiptPublicKeyFingerprint
            ? {
                anchorReceiptPublicKeyFingerprint:
                  normalizedMetadata.anchorReceiptPublicKeyFingerprint,
              }
            : {}),
        };

        createStoreMetadataFile(this.auditDir, freshMetadata, this.expectedUid);
        this.metadata = freshMetadata;
      } else {
        const loaded = loadStoreMetadataFile(this.auditDir, this.expectedUid);
        validateStoreMetadataConsistency(loaded, normalizedMetadata);
        this.metadata = loaded;
      }

      this._testHooks?.beforeFinalOpen?.();

      let fd: number;
      try {
        fd = fs.openSync(
          this.activePath,
          fsConstants.O_CREAT |
            fsConstants.O_APPEND |
            fsConstants.O_WRONLY |
            fsConstants.O_NOFOLLOW,
          0o600,
        );
      } catch (err: unknown) {
        const errCode =
          typeof err === 'object' && err !== null && 'code' in err
            ? (err as { code: unknown }).code
            : undefined;

        if (errCode === 'ELOOP') {
          throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
        }
        throw err;
      }

      try {
        const stats = validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);

        if (stats.size > 0) {
          throw createCodedError(
            'AUDIT_RECOVERY_REQUIRED',
            'active audit segment is non-empty; recovery required before append',
          );
        }

        this.activeFd = fd;

        const parentFd = fs.openSync(this.auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
        try {
          fs.fsyncSync(parentFd);
        } finally {
          fs.closeSync(parentFd);
        }
      } catch (err) {
        this.activeFd = null;
        fs.closeSync(fd);
        throw err;
      }

      this.currentSequence = 1;
      this.lastRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
      this.state = 'ACTIVE';
    } catch (err) {
      if (this.activeFd !== null) {
        try {
          fs.closeSync(this.activeFd);
        } catch {
          // ignore
        }
        this.activeFd = null;
      }
      if (this.lock !== null) {
        try {
          this.lock.release();
        } catch {
          // ignore
        }
        this.lock = null;
      }
      throw err;
    }
  }

  public async append(
    recordCandidate: Omit<
      PersistentAuditRecordV1,
      'sequenceNumber' | 'integrity' | 'schemaVersion'
    >,
  ): Promise<PersistentAuditRecordV1> {
    if (this.state === 'UNINITIALIZED') {
      throw createCodedError('AUDIT_STORAGE_UNINITIALIZED', 'storage is uninitialized');
    }
    if (this.state === 'CLOSED') {
      throw createCodedError('AUDIT_STORAGE_CLOSED', 'storage is closed');
    }
    if (this.state === 'FAILED') {
      throw createCodedError('AUDIT_STORAGE_FAILED', 'storage is in a failed state');
    }
    if (this.state !== 'ACTIVE' || this.activeFd === null) {
      throw createCodedError('AUDIT_STORAGE_CLOSED', 'storage is not active');
    }

    if (this.appendInProgress) {
      throw createCodedError('APPEND_REENTRANT', 'concurrent or re-entrant append rejected');
    }

    this.appendInProgress = true;
    try {
      const { candidate, recordHash, buf } = this.buildSignedRecord(recordCandidate);

      if (this._testFaults?.writeFault === 'error') {
        this.state = 'FAILED';
        throw createCodedError('SIMULATED_WRITE_FAILURE', 'disk write failed');
      }

      if (this._testFaults?.writeFault === 'enospc') {
        // The cursor is deliberately NOT advanced: the record never became
        // durable, so the in-memory chain must not claim it did. The storage
        // moves to FAILED, which is fail-closed for every subsequent append.
        this.state = 'FAILED';
        throw createCodedError('ENOSPC', 'no space left on device');
      }

      let offset = 0;
      const writeLimit =
        this._testFaults?.writeFault === 'partial' ? Math.floor(buf.length / 2) : buf.length;

      try {
        while (offset < writeLimit) {
          const toWrite = Math.min(buf.length - offset, writeLimit - offset);
          const written = fs.writeSync(this.activeFd, buf, offset, toWrite, null);
          if (written <= 0) {
            throw createCodedError('SHORT_WRITE', 'zero bytes written to active segment');
          }
          offset += written;
        }
        if (this._testFaults?.writeFault === 'partial') {
          throw createCodedError('SHORT_WRITE', 'partial write simulated');
        }
      } catch (err) {
        this.state = 'FAILED';
        throw err;
      }

      try {
        if (this._testFaults?.fdatasyncFault) {
          throw createCodedError('SIMULATED_SYNC_FAILURE', 'fdatasync failed');
        }
        fs.fdatasyncSync(this.activeFd);
      } catch (err) {
        this.state = 'FAILED';
        throw err;
      }

      this.currentSequence++;
      this.lastRecordHash = recordHash;

      return JSON.parse(JSON.stringify(candidate)) as PersistentAuditRecordV1;
    } finally {
      this.appendInProgress = false;
    }
  }

  /**
   * Builds, hashes and serializes the record the next append would write,
   * without mutating any cursor and without writing any byte.
   *
   * Shared by `append()` and by the rotation coordinator's capacity preflight,
   * so the projected byte length and the written byte length can never diverge.
   */
  private buildSignedRecord(
    recordCandidate: Omit<
      PersistentAuditRecordV1,
      'sequenceNumber' | 'integrity' | 'schemaVersion'
    >,
  ): { candidate: PersistentAuditRecordV1; recordHash: string; buf: Buffer } {
    const candidate: PersistentAuditRecordV1 = {
      ...(recordCandidate as AuditRecord),
      schemaVersion: 1,
      sequenceNumber: this.currentSequence,
      integrity: {
        previousRecordHash: this.lastRecordHash,
        recordHash: '0000000000000000000000000000000000000000000000000000000000000000',
      },
    };

    validatePersistentRecordV1(candidate, false);

    const recordHash = computeRecordHashV1(candidate);
    candidate.integrity.recordHash = recordHash;

    validatePersistentRecordV1(candidate, true);

    const line = serializeRecordV1(candidate);
    const byteLen = Buffer.byteLength(line, 'utf8');
    if (byteLen > MAX_RECORD_BYTES) {
      throw createCodedError(
        'RECORD_TOO_LARGE',
        `record line (${byteLen} bytes) exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES})`,
      );
    }

    return { candidate, recordHash, buf: Buffer.from(line, 'utf8') };
  }

  /**
   * @internal Package-private rotation capability.
   *
   * Returns a narrow, descriptor-level authority for the rotation coordinator.
   * It is NOT a cursor setter: rotation preserves `currentSequence` and
   * `lastRecordHash` by construction, so the next append continues the chain
   * across the segment boundary (rc06 §73). The token is unforgeable and is
   * never exported from the package root or any public package subpath.
   */
  public _rotationCapability(token: symbol): RotationStorageCapability {
    if (token !== ROTATION_CAPABILITY_TOKEN) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'unauthorized rotation capability');
    }

    return {
      auditDir: this.auditDir,
      activePath: this.activePath,
      expectedUid: this.expectedUid,

      isActive: () => this.state === 'ACTIVE',
      isClosed: () => this.state === 'CLOSED',
      isFailed: () => this.state === 'FAILED',

      getActiveFd: () => this.activeFd,
      getActiveByteSize: () => {
        if (this.activeFd === null) return null;
        const stats = validateFileDescriptorAuthority(this.activeFd, 0o600, this.expectedUid);
        return stats.size;
      },

      projectSerializedBytes: (candidate) =>
        this.buildSignedRecord(
          candidate as Omit<
            PersistentAuditRecordV1,
            'sequenceNumber' | 'integrity' | 'schemaVersion'
          >,
        ).buf.byteLength,

      markRotationFailed: () => {
        this.state = 'FAILED';
      },

      rotateActiveSegmentPhysical: (archiveName: string) =>
        this.rotateActiveSegmentPhysical(archiveName),
    };
  }

  /**
   * The single synchronous physical rotation critical section.
   *
   * Ordering is load-bearing and matches the frozen rotation order:
   *
   *   1. finalize the active descriptor (fdatasync, then close);
   *   2. install the finalized bytes under `archiveName` WITHOUT overwriting;
   *   3. fsync the parent directory so the new name is durable;
   *   4. create the fresh active segment with `O_CREAT | O_EXCL` and validate
   *      descriptor authority;
   *   5. fsync the parent directory again.
   *
   * `link()` + `unlink()` is used instead of `rename()` because Node exposes no
   * `renameat2(RENAME_NOREPLACE)`: `rename()` would silently clobber an
   * existing archive, which RC06-NEG-53 forbids outright. `link()` fails with
   * `EEXIST` when the target exists, so the no-overwrite guarantee is provided
   * by the kernel rather than by a check-then-act race.
   *
   * The transient window in which the archived inode has `nlink === 2` is a
   * fail-closed state, not a correctness hazard: `validateFileDescriptorAuthority`
   * requires `nlink === 1`, so no reader can mistake that inode for a canonical
   * artifact while both names exist, and the source name is removed before this
   * method returns.
   *
   * `currentSequence` and `lastRecordHash` are intentionally left untouched.
   */
  private rotateActiveSegmentPhysical(archiveName: string): {
    archivedPath: string;
    newActiveFd: number;
  } {
    if (this.state !== 'ACTIVE' || this.activeFd === null) {
      throw createCodedError('AUDIT_STORAGE_INVALID_STATE', 'storage is not active');
    }
    if (!isValidRotatedSegmentFilename(archiveName)) {
      throw createCodedError(
        'AUDIT_ROTATION_INVALID_TARGET',
        `refusing to install a non-canonical rotated segment name: ${archiveName}`,
      );
    }

    const archivedPath = path.join(this.auditDir, archiveName);

    const previousFd = this.activeFd;
    this.activeFd = null;

    try {
      fs.fdatasyncSync(previousFd);
      fs.closeSync(previousFd);

      // No-overwrite installation. `EEXIST` propagates and aborts rotation with
      // the source segment still intact and still named as the active segment.
      fs.linkSync(this.activePath, archivedPath);
      fs.unlinkSync(this.activePath);
    } catch (err) {
      this.state = 'FAILED';
      throw err;
    }

    try {
      this.syncDirectory();
    } catch (err) {
      this.state = 'FAILED';
      throw err;
    }

    let fd: number;
    try {
      fd = fs.openSync(
        this.activePath,
        fsConstants.O_CREAT | fsConstants.O_APPEND | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
    } catch (err: unknown) {
      const errCode =
        typeof err === 'object' && err !== null && 'code' in err
          ? (err as { code: unknown }).code
          : undefined;

      this.state = 'FAILED';
      if (errCode === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
      }
      throw err;
    }

    try {
      const stats = validateFileDescriptorAuthority(fd, 0o600, this.expectedUid);
      if (stats.size !== 0) {
        throw createCodedError(
          'AUDIT_ROTATION_TARGET_NOT_EMPTY',
          'freshly created active segment is not empty',
        );
      }
      this.activeFd = fd;
      this.syncDirectory();
    } catch (err) {
      if (this.activeFd === null) {
        fs.closeSync(fd);
      }
      this.state = 'FAILED';
      throw err;
    }

    return { archivedPath, newActiveFd: fd };
  }

  /** fsyncs the audit directory so a name creation/removal is durable. */
  private syncDirectory(): void {
    const parentFd = fs.openSync(this.auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try {
      fs.fsyncSync(parentFd);
    } finally {
      fs.closeSync(parentFd);
    }
  }

  public getMetadata(): AuditStoreMetadataV1 | null {
    return this.metadata;
  }

  public getCurrentSequence(): number {
    return this.currentSequence;
  }

  public getLastRecordHash(): string {
    return this.lastRecordHash;
  }

  public getActivePath(): string {
    return this.activePath;
  }

  public close(): void {
    if (this.state === 'CLOSED') return;
    this.state = 'CLOSED';

    let errorToThrow: unknown = null;

    if (this.activeFd !== null) {
      try {
        fs.closeSync(this.activeFd);
      } catch (err) {
        errorToThrow = errorToThrow ?? err;
      }
      this.activeFd = null;
    }

    if (this.lock !== null) {
      try {
        this.lock.release();
      } catch (err) {
        errorToThrow = errorToThrow ?? err;
      }
      this.lock = null;
    }

    if (errorToThrow) {
      throw createCodedError('STORAGE_CLOSE_FAILED', 'failed to cleanly close storage', {
        cause: errorToThrow,
      });
    }
  }
}
