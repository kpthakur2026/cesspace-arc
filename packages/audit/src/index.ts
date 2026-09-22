import { createHash, randomUUID } from 'node:crypto';
import {
  GATEWAY_AUDIT_EVENT_TYPES,
  GATEWAY_AUDIT_REASONS,
  type AuditGatewayMetadata,
  type AuditRecord,
  type GatewayAuditAdmissionLayer,
  type GatewayAuditEventType,
  type GatewayAuditReason,
} from '@cesspace-arc/protocol';

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

/**
 * High-confidence secret shapes removed from ANY string that reaches a stored
 * record, whatever key it arrived under (rc05 §24, RC05-NEG-73).
 *
 * Two families, both deterministic and both bounded:
 *
 * - Private-key blocks (`-----BEGIN [A-Z ]+PRIVATE KEY-----`), which cover RSA,
 *   EC, OPENSSH, and the unqualified `PRIVATE KEY` form.
 * - Certificate blocks (`-----BEGIN CERTIFICATE-----`), so a full PEM
 *   certificate blob cannot reach a record even when a caller puts it under an
 *   innocent key name such as `detail` or `notes`. The `cert(ificate)?` KEY
 *   pattern only helps when the field is honestly NAMED for what it holds; this
 *   covers the value wherever it lands.
 *
 * Deliberately NOT included: a bare 64-character hexadecimal string. SHA-256
 * digests are intentional, safe audit references — the trust store's workspace
 * root digest, the session token DIGEST, and every SPKI pin are all exactly that
 * shape — so redacting that shape would destroy legitimate evidence rather than
 * protect anything. Secrets reach this layer as VALUES under a sensitive key
 * name (caught by {@link SENSITIVE_KEY_PATTERNS}) or as one of the block forms
 * above, never as a bare digest that ARC minted itself.
 */
export const SENSITIVE_VALUE_REGEXES = [
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[a-zA-Z0-9]{36}/g,
  /gho_[a-zA-Z0-9]{36}/g,
  /sk-[a-zA-Z0-9]{20,}/g,
  /Bearer\s+[a-zA-Z0-9._-]+/gi,
  /Arc-Session-Token[:\s=]+[a-zA-Z0-9._-]+/gi,
  /Authorization[:\s=]+[a-zA-Z0-9._-]+/gi,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
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

// ---------------------------------------------------------------------------
// Central gateway-event projection (rc05 §24)
// ---------------------------------------------------------------------------

/**
 * Maximum length of an operator-visible client identifier or client type in a
 * gateway record.
 *
 * Matches the Task-1 `MAX_CLIENT_ID_CHARS` bound; redeclared here because
 * `packages/audit` depends only on `packages/protocol` and must not reach into
 * `packages/auth` for a constant.
 */
export const MAX_GATEWAY_IDENTIFIER_CHARS = 128;

/** Opaque 32-lowercase-hex identifier: device and enrollment identifiers. */
const GATEWAY_HEX32_REGEX = /^[0-9a-f]{32}$/;

/** Server-issued 64-lowercase-hex identifier: the `Mcp-Session-Id` value. */
const GATEWAY_HEX64_REGEX = /^[0-9a-f]{64}$/;

/** Printable ASCII, no control character and no NUL, bounded in length. */
const GATEWAY_IDENTIFIER_REGEX = new RegExp(`^[\\x20-\\x7e]{1,${MAX_GATEWAY_IDENTIFIER_CHARS}}$`);

const GATEWAY_ADMISSION_LAYERS: readonly GatewayAuditAdmissionLayer[] = ['A', 'B', 'C'];

function isGatewayEventType(value: unknown): value is GatewayAuditEventType {
  return (
    typeof value === 'string' && (GATEWAY_AUDIT_EVENT_TYPES as readonly string[]).includes(value)
  );
}

function isGatewayReason(value: unknown): value is GatewayAuditReason {
  return typeof value === 'string' && (GATEWAY_AUDIT_REASONS as readonly string[]).includes(value);
}

/**
 * Reduces arbitrary input to the bounded, closed gateway metadata shape.
 *
 * This is CENTRAL defense-in-depth, not a convention callers are trusted to
 * follow. Every field is validated against the frozen vocabulary or a fixed
 * identifier shape, and any key this function does not know is DROPPED rather
 * than copied. A caller therefore cannot widen the gateway block into a carrier
 * for a token, a secret, a certificate, a peer address, or a raw limiter key,
 * however the input object was built.
 *
 * Returns `undefined` — dropping the whole block — when the required
 * `eventType` is absent or is not one of the fourteen frozen names. A record can
 * never claim a gateway event outside the catalog, and an unknown event is never
 * silently relabelled as a known one.
 */
export function projectGatewayMetadata(metadata: unknown): AuditGatewayMetadata | undefined {
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return undefined;
  }
  const source = metadata as Record<string, unknown>;
  if (!isGatewayEventType(source.eventType)) {
    return undefined;
  }

  const projected: AuditGatewayMetadata = { eventType: source.eventType };

  if (isGatewayReason(source.reason)) {
    projected.reason = source.reason;
  }
  if (
    typeof source.admissionLayer === 'string' &&
    GATEWAY_ADMISSION_LAYERS.includes(source.admissionLayer as GatewayAuditAdmissionLayer)
  ) {
    projected.admissionLayer = source.admissionLayer as GatewayAuditAdmissionLayer;
  }
  if (typeof source.mcpSessionId === 'string' && GATEWAY_HEX64_REGEX.test(source.mcpSessionId)) {
    projected.mcpSessionId = source.mcpSessionId;
  }
  if (typeof source.deviceId === 'string' && GATEWAY_HEX32_REGEX.test(source.deviceId)) {
    projected.deviceId = source.deviceId;
  }
  if (typeof source.spkiPin === 'string' && GATEWAY_HEX64_REGEX.test(source.spkiPin)) {
    projected.spkiPin = source.spkiPin;
  }
  if (typeof source.enrollmentId === 'string' && GATEWAY_HEX32_REGEX.test(source.enrollmentId)) {
    projected.enrollmentId = source.enrollmentId;
  }
  if (typeof source.clientId === 'string' && GATEWAY_IDENTIFIER_REGEX.test(source.clientId)) {
    projected.clientId = source.clientId;
  }
  if (typeof source.clientType === 'string' && GATEWAY_IDENTIFIER_REGEX.test(source.clientType)) {
    projected.clientType = source.clientType;
  }
  if (source.transportMode === 'stdio' || source.transportMode === 'remote') {
    projected.transportMode = source.transportMode;
  }

  return projected;
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

    // Central gateway-metadata projection and redaction, applied HERE for every
    // caller (rc05 §24). The allowlist projection runs first, so only the
    // bounded, closed-vocabulary fields can survive; the redaction pass then
    // runs over the survivors, so even an allowlisted field whose value happens
    // to carry a credential shape is sanitized before it is stored. Neither step
    // depends on the writer having remembered to sanitize anything.
    const projectedGateway = projectGatewayMetadata(recordData.gateway);
    const gatewayRecord =
      projectedGateway === undefined
        ? undefined
        : (this.redact(
            projectedGateway as unknown as Record<string, unknown>,
          ) as unknown as AuditGatewayMetadata);

    // Every remaining record section goes through the SAME central redaction
    // pass as the parameters above (rc05 §24, RC05-NEG-73). `copyBounded` alone
    // preserves a value verbatim, so a caller that put PEM key material, a
    // certificate blob, an Authorization value, or an absolute host path into
    // `actor`, `policy`, `execution`, or `approval` would have stored it. The
    // pass is central, so no writer has to remember it, and it is monotone: it
    // can only remove material, never introduce it. Every own key is preserved
    // (see {@link copyBounded}), so the canonical form and therefore the hash
    // chain are unaffected for the ordinary values these sections carry —
    // identifiers, timestamps, enumerations, and counts.
    const baseRecord: AuditRecord = {
      eventId,
      timestamp: recordData.timestamp,
      sequenceNumber,
      actor: this.redact(
        recordData.actor as unknown as Record<string, unknown>,
      ) as AuditRecord['actor'],
      target: this.minimizeTarget(recordData.target),
      invocation: {
        toolName: recordData.invocation.toolName,
        parametersRedacted,
        payloadHash: recordData.invocation.payloadHash || fallbackPayloadHash,
      },
      policy: this.redact(
        recordData.policy as unknown as Record<string, unknown>,
      ) as AuditRecord['policy'],
      execution: this.redact(
        recordData.execution as unknown as Record<string, unknown>,
      ) as AuditRecord['execution'],
      error: errorRecord,
      approval:
        recordData.approval === undefined
          ? undefined
          : (this.redact(
              recordData.approval as unknown as Record<string, unknown>,
            ) as AuditRecord['approval']),
      gateway: gatewayRecord,
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

export {
  DEFAULT_AUDIT_DIR,
  ACTIVE_SEGMENT_FILENAME,
  UUID_V4_REGEX,
  PERSISTENT_RECORD_V1_ALLOWED_KEYS,
  ACTOR_ALLOWED_KEYS,
  TARGET_ALLOWED_KEYS,
  INVOCATION_ALLOWED_KEYS,
  POLICY_ALLOWED_KEYS,
  EXECUTION_ALLOWED_KEYS,
  ERROR_ALLOWED_KEYS,
  LIFECYCLE_ALLOWED_KEYS,
  APPROVAL_ALLOWED_KEYS,
  GATEWAY_ALLOWED_KEYS,
  INTEGRITY_ALLOWED_KEYS,
  type CodedError,
  createCodedError,
  getProcessUid,
  type PlatformCapabilities,
  detectPlatformCapabilities,
  validatePlatformCapabilities,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  canonicalJsonV1,
  validateIntegrityObjectV1,
  computeRecordHashPreimageV1,
  computeRecordHashV1,
  serializeRecordV1,
  validatePersistentRecordV1,
  parseAndValidateRecordLineV1,
  type StorageState,
  type PersistentAuditStorageConfig,
  PersistentAuditStorage,
} from './storage.js';
export * from './metadata.js';
export * from './lock.js';
export {
  MAX_TORN_TAIL_BYTES,
  type TrustedPrimaryChainBoundary,
  type DanglingOperation,
  type VerifiedStreamResult,
  type TornTailStreamResult,
  type ActiveStreamVerificationResult,
  type StreamVerificationOptions,
  verifyActiveStream,
  type AuditRecoveryResult,
  type AuditRecoveryOptions,
  recoverPersistentAuditStorage,
} from './recovery.js';
export {
  SEGMENT_SIZE_THRESHOLD,
  ROTATION_INTERVAL,
  ROTATION_INTERVAL_MS,
  MAX_ARCHIVE_SEGMENTS,
  TOTAL_AUDIT_BUDGET_BYTES,
  RECENT_RECORDS_CACHE_LIMIT,
  type RotationSealBoundary,
  type RotationCheckpointSealer,
  validateRotationSealBoundary,
  type ArchiveInventoryEntry,
  type PhysicalArchiveRepresentation,
  type LogicalArchiveEntry,
  type SegmentRotationReason,
  type RotationResult,
  type SegmentDigest,
  type RetainedPrimaryHistoryVerificationOptions,
  type RetainedPrimaryHistoryVerificationResult,
  verifyRetainedPrimaryHistory,
  listArchiveInventory,
  listLogicalArchiveInventory,
  countLogicalArchives,
  scanAuditStorePhysicalBytes,
  assertAuditStorageCapacity,
  assertArchiveCapacityAvailable,
  type RotatingAuditStoreOptions,
  RotatingAuditStore,
} from './rotation.js';
export {
  CHECKPOINT_INTERVAL,
  MAX_SIGNING_KEY_BYTES,
  CHECKPOINT_FILENAME,
  CHECKPOINT_SIGNATURE_DOMAIN,
  CHECKPOINT_ALLOWED_KEYS,
  CHECKPOINT_FORBIDDEN_EVENT_KEYS,
  type AuditCheckpointV1,
  type UnsignedAuditCheckpointV1,
  validateCheckpointV1,
  computeCheckpointSignaturePreimage,
  computeCheckpointHashPreimage,
  computeCheckpointHash,
  serializeCheckpointV1,
  verifyCheckpointSignature,
  parseAndValidateCheckpointLineV1,
  type CheckpointHistoryVerificationResult,
  type CheckpointHistoryVerificationOptions,
  verifyCheckpointHistory,
  type Tier2CheckpointEngineConfig,
  type CheckpointEngineState,
  Tier2CheckpointEngine,
  openTier2CheckpointEngine,
  computeCheckpointPublicKeyFingerprint,
  type TrustRootPurpose,
  type SigningKeySource,
  computePublicKeyFingerprint,
  computeTrustRootFingerprintFromFile,
  assertNoRawSigningKeyMaterial,
} from './checkpoint.js';
export {
  ANCHOR_RECEIPT_FILENAME,
  ANCHOR_SPOOL_DIRNAME,
  ANCHOR_RECEIPT_SIGNATURE_DOMAIN,
  ANCHOR_SPOOL_FILENAME_REGEX,
  ANCHOR_SPOOL_FILE_MODE,
  ANCHOR_SPOOL_DIRECTORY_MODE,
  MAX_ANCHOR_RECEIPT_BYTES,
  MAX_ANCHOR_ENDPOINT_BYTES,
  MAX_ANCHOR_SPOOL_BYTES,
  MAX_ANCHOR_SPOOL_ENTRY_BYTES,
  MAX_PENDING_ANCHOR_CHECKPOINTS,
  MAX_ANCHOR_ATTEMPTS,
  ANCHOR_RETRY_BACKOFF_MS,
  ANCHOR_REQUEST_TIMEOUT_MS,
  ANCHOR_IDEMPOTENCY_HEADER,
  ANCHOR_ACKNOWLEDGING_STATUS_CODES,
  ANCHOR_RECEIPT_ALLOWED_KEYS,
  type AnchorReceiptV1,
  type UnsignedAnchorReceiptV1,
  validateAnchorReceiptV1,
  computeAnchorReceiptSignaturePreimage,
  verifyAnchorReceiptSignature,
  ReceiptEvidenceWalk,
  walkReceiptEvidence,
  serializeAnchorReceiptV1,
  parseAndValidateAnchorReceiptLineV1,
  computeAnchorReceiptPublicKeyFingerprint,
  validateAnchorEndpoint,
  type AnchorState,
  type AnchorStatus,
  type AnchorDispatchResult,
  type Tier3AnchorEngineConfig,
  Tier3AnchorEngine,
  openTier3AnchorEngine,
} from './anchor.js';
export {
  ROTATED_SEGMENT_PREFIX,
  ROTATED_SEGMENT_PLAIN_SUFFIX,
  ROTATED_SEGMENT_COMPRESSED_SUFFIX,
  ROTATED_SEGMENT_REGEX,
  MAX_SEQUENCE_NUMBER,
  type ParsedRotatedSegmentFilename,
  formatRotationTimestamp,
  formatRotatedSegmentFilename,
  parseRotatedSegmentFilename,
  isValidRotatedSegmentFilename,
} from './rotation-filename.js';

/* -------------------------------------------------------------------------- *
 * RC-06 Task 6 — the production audit runtime composition.
 *
 * The ONLY production surface Task 6 adds. Everything else Task 6 composes is
 * already exported by the Task that owns it, and the deterministic seams live in
 * `./internal/runtime-testing.js`, which is deliberately absent from the
 * package's `exports` map so no consumer can import them by subpath.
 * -------------------------------------------------------------------------- */
export {
  AUDIT_STARTUP_STAGE_ORDER,
  openAuditRuntime,
  type AuditConfig,
  type AuditHealthMetadata,
  type AuditRuntime,
  type AuditStartupStage,
} from './startup.js';

/* -------------------------------------------------------------------------- *
 * RC-06 Task 7 — the local operator verifier and evidence exporter.
 *
 * Both are READ ONLY and PUBLIC-KEY ONLY: neither opens the store for writing,
 * takes the writer lock, repairs evidence, or reads a private signing key. The
 * names here are deliberately distinct from any runtime/administrative surface,
 * so a consumer can never mistake an offline observation for a live operation.
 * -------------------------------------------------------------------------- */
export {
  MAX_INSPECT_RECORDS,
  type EvidenceIdentity,
  snapshotEvidenceInventory,
  assertInventoryUnchanged,
  type RetainedSegmentSource,
  listRetainedSegmentSources,
  streamRetainedRecords,
  type OfflineAnchorOutcome,
  type OfflineVerificationOptions,
  type OfflineVerificationResult,
  verifyOfflineStore,
  type OfflineAuditStatus,
  readOfflineAuditStatus,
  type InspectOptions,
  inspectRetainedRecords,
  validateInspectRange,
} from './verify.js';
export {
  MAX_EXPORT_BYTES,
  BUNDLE_MANIFEST_FILENAME,
  BUNDLE_AUDIT_DIRNAME,
  BUNDLE_CHECKPOINTS_DIRNAME,
  BUNDLE_ANCHORS_DIRNAME,
  BUNDLE_PUBLIC_KEYS_DIRNAME,
  BUNDLE_CHECKPOINT_KEY_FILENAME,
  BUNDLE_ANCHOR_KEY_FILENAME,
  type ManifestFileEntry,
  type ExportManifest,
  type ExportEvidenceOptions,
  type ExportEvidenceResult,
  type BundleDirectoryAuthority,
  createBundleDirectoryAuthority,
  assertExportWithinBudget,
  MIN_CANONICAL_RECORD_BYTES,
  MAX_MANIFEST_CHECKPOINT_REFS,
  MAX_MANIFEST_RECEIPT_REFS,
  assertManifestReferenceWithinBound,
  exportEvidenceBundle,
  type VerifyBundleResult,
  verifyEvidenceBundleAuthoritative,
  verifyEvidenceBundle,
} from './export.js';
