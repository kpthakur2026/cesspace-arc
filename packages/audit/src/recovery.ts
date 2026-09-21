import fs, { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  MAX_RECORD_BYTES,
  type AuditRecord,
  type AuditStoreMetadataV1,
  type PersistentAuditRecordV1,
} from '@cesspace-arc/protocol';
import {
  ACTIVE_SEGMENT_FILENAME,
  DEFAULT_AUDIT_DIR,
  PersistentAuditStorage,
  createCodedError,
  type CodedError,
  getProcessUid,
  parseAndValidateRecordLineV1,
  type PersistentAuditStorageConfig,
  validateAuditDirectory,
  validateFileDescriptorAuthority,
  validatePlatformCapabilities,
} from './storage.js';
import { RECOVERY_HANDOFF_TOKEN } from './internal/recovery-capability.js';
import type { RecoveryTestHooks } from './internal/recovery-testing.js';
import { MAX_TORN_TAIL_BYTES, classifyTrailingBytes } from './internal/torn-tail.js';
import { acquireWriterLock } from './lock.js';
import {
  METADATA_FILENAME,
  createStoreMetadataFile,
  loadStoreMetadataFile,
  normalizeStoreMetadataConfig,
  validateStoreMetadataConsistency,
} from './metadata.js';

/**
 * Re-exported so the frozen constant keeps its existing public home while its
 * definition, and the torn-tail rule built on it, live in one shared place.
 */
export { MAX_TORN_TAIL_BYTES } from './internal/torn-tail.js';

export interface TrustedPrimaryChainBoundary {
  sequenceNumber: number;
  recordHash: string;
}

export interface DanglingOperation {
  operationId: string;
  startedSequenceNumber: number;
  target: unknown;
  invocation: unknown;
  policy: unknown;
  approval?: unknown;
}

export interface VerifiedStreamResult {
  status: 'VERIFIED';
  recordCount: number;
  terminalSequence: number;
  terminalRecordHash: string;
  nextSequence: number;
  previousRecordHash: string;
  verifiedByteLength: number;
  activeIdentity: { dev: number; ino: number };
  danglingOperations: DanglingOperation[];
}

export interface TornTailStreamResult {
  status: 'RECOVERABLE_TORN_ACTIVE_TAIL';
  lastVerifiedByteOffset: number;
  tornBytes: Buffer;
  terminalSequence: number;
  terminalRecordHash: string;
  nextSequence: number;
  previousRecordHash: string;
  activeIdentity: { dev: number; ino: number };
  danglingOperations: DanglingOperation[];
}

export type ActiveStreamVerificationResult = VerifiedStreamResult | TornTailStreamResult;

export interface StreamVerificationOptions {
  trustedBoundary?: TrustedPrimaryChainBoundary;
}

/** @internal Lifecycle state carried across segment boundaries by rotation. */
export interface LifecycleTrackingEntry {
  phase: 'STARTED' | 'COMPLETED' | 'DENIED' | 'RECOVERY_INDETERMINATE';
  startedSequenceNumber?: number;
  startedRecordContext?: DanglingOperation;
}

/** @internal Shared lifecycle transition rules, used by the rotation verifier. */
export function updateLifecycle(
  lifecycleMap: Map<string, LifecycleTrackingEntry>,
  record: PersistentAuditRecordV1,
): void {
  const lc = record.lifecycle;
  if (!lc) return;
  const opId = lc.operationId;
  const phase = lc.phase;

  const existing = lifecycleMap.get(opId);
  if (!existing) {
    if (phase === 'COMPLETED') {
      throw createCodedError(
        'AUDIT_LIFECYCLE_CORRUPTION',
        `COMPLETED without prior STARTED for operationId ${opId}`,
      );
    }
    if (phase === 'RECOVERY_INDETERMINATE') {
      throw createCodedError(
        'AUDIT_LIFECYCLE_CORRUPTION',
        `RECOVERY_INDETERMINATE without prior STARTED for operationId ${opId}`,
      );
    }
    if (phase === 'DENIED') {
      lifecycleMap.set(opId, { phase: 'DENIED' });
      return;
    }
    if (phase === 'STARTED') {
      lifecycleMap.set(opId, {
        phase: 'STARTED',
        startedSequenceNumber: record.sequenceNumber,
        startedRecordContext: {
          operationId: opId,
          startedSequenceNumber: record.sequenceNumber,
          target: JSON.parse(JSON.stringify(record.target)),
          invocation: JSON.parse(JSON.stringify(record.invocation)),
          policy: JSON.parse(JSON.stringify(record.policy)),
          ...(record.approval !== undefined
            ? { approval: JSON.parse(JSON.stringify(record.approval)) }
            : {}),
        },
      });
      return;
    }
    throw createCodedError('AUDIT_LIFECYCLE_CORRUPTION', `Unknown lifecycle phase "${phase}"`);
  }

  if (
    existing.phase === 'DENIED' ||
    existing.phase === 'COMPLETED' ||
    existing.phase === 'RECOVERY_INDETERMINATE'
  ) {
    throw createCodedError(
      'AUDIT_LIFECYCLE_CORRUPTION',
      `Lifecycle record with phase ${phase} after terminal phase ${existing.phase} for operationId ${opId}`,
    );
  }

  if (existing.phase === 'STARTED') {
    if (phase === 'STARTED') {
      throw createCodedError(
        'AUDIT_LIFECYCLE_CORRUPTION',
        `Duplicate STARTED phase for operationId ${opId}`,
      );
    }
    if (phase === 'DENIED') {
      throw createCodedError(
        'AUDIT_LIFECYCLE_CORRUPTION',
        `Invalid phase transition STARTED -> DENIED for operationId ${opId}`,
      );
    }
    if (phase === 'COMPLETED' || phase === 'RECOVERY_INDETERMINATE') {
      existing.phase = phase;
      existing.startedRecordContext = undefined;
      return;
    }
  }

  throw createCodedError(
    'AUDIT_LIFECYCLE_CORRUPTION',
    `Invalid lifecycle transition from ${existing.phase} to ${phase} for operationId ${opId}`,
  );
}

/** @internal Shared dangling-operation extraction, used by the rotation verifier. */
export function extractDanglingOperations(
  lifecycleMap: Map<string, LifecycleTrackingEntry>,
): DanglingOperation[] {
  const dangling: DanglingOperation[] = [];
  for (const entry of lifecycleMap.values()) {
    if (entry.phase === 'STARTED' && entry.startedRecordContext) {
      dangling.push(entry.startedRecordContext);
    }
  }
  dangling.sort((a, b) => a.startedSequenceNumber - b.startedSequenceNumber);
  return dangling;
}

export function verifyActiveStream(
  activePath: string,
  expectedUid: number,
  options?: StreamVerificationOptions,
): ActiveStreamVerificationResult {
  const trustedBoundary = options?.trustedBoundary;
  if (trustedBoundary !== undefined) {
    if (
      typeof trustedBoundary.sequenceNumber !== 'number' ||
      !Number.isSafeInteger(trustedBoundary.sequenceNumber) ||
      trustedBoundary.sequenceNumber < 1 ||
      typeof trustedBoundary.recordHash !== 'string' ||
      !/^[0-9a-f]{64}$/.test(trustedBoundary.recordHash)
    ) {
      throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'Invalid trusted boundary specification');
    }
  }

  if (!fs.existsSync(activePath)) {
    throw createCodedError('AUDIT_CORRUPTION_DETECTED', 'Active audit segment does not exist');
  }

  const lstat = fs.lstatSync(activePath);
  if (lstat.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', 'Active audit segment is a symbolic link');
  }

  let fd: number | null = null;
  try {
    try {
      fd = fs.openSync(activePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (err: unknown) {
      const errCode = (err as { code?: string })?.code;
      if (errCode === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', 'Active audit segment is a symbolic link');
      }
      throw err;
    }

    const stats = validateFileDescriptorAuthority(fd, 0o600, expectedUid);
    const activeIdentity = { dev: stats.dev, ino: stats.ino };

    if (stats.size === 0) {
      if (trustedBoundary !== undefined) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          `Empty stream cannot satisfy trusted boundary sequence ${trustedBoundary.sequenceNumber}`,
        );
      }
      return {
        status: 'VERIFIED',
        recordCount: 0,
        terminalSequence: 0,
        terminalRecordHash: '0000000000000000000000000000000000000000000000000000000000000000',
        nextSequence: 1,
        previousRecordHash: '0000000000000000000000000000000000000000000000000000000000000000',
        verifiedByteLength: 0,
        activeIdentity,
        danglingOperations: [],
      };
    }

    const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
    const lifecycleMap = new Map<string, LifecycleTrackingEntry>();

    let lastVerifiedByteOffset = 0;
    let recordCount = 0;
    let terminalSequence = 0;
    let terminalRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
    let nextSequence = 1;
    let previousRecordHash = '0000000000000000000000000000000000000000000000000000000000000000';
    let trustedBoundaryMatched = false;

    const CHUNK_SIZE = 16384;
    const readChunkBuffer = Buffer.alloc(CHUNK_SIZE);
    let accumulated = Buffer.alloc(0);
    let atEof = false;

    while (true) {
      if (!atEof) {
        const bytesRead = fs.readSync(fd, readChunkBuffer, 0, CHUNK_SIZE, null);
        if (bytesRead === 0) {
          atEof = true;
        } else {
          accumulated = Buffer.concat([accumulated, readChunkBuffer.subarray(0, bytesRead)]);
        }
      }

      const newlineIdx = accumulated.indexOf(0x0a);

      if (newlineIdx !== -1) {
        const lineBytes = accumulated.subarray(0, newlineIdx + 1);
        const remainingBytes = accumulated.subarray(newlineIdx + 1);

        if (lineBytes.length > MAX_RECORD_BYTES) {
          throw createCodedError(
            'AUDIT_CORRUPTION_DETECTED',
            `Record line exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES})`,
          );
        }

        let isMalformedJson = false;
        let decodedLine = '';
        try {
          decodedLine = utf8Decoder.decode(lineBytes);
          JSON.parse(decodedLine.slice(0, -1));
        } catch {
          isMalformedJson = true;
        }

        if (isMalformedJson) {
          let hasMoreBytes = remainingBytes.length > 0;
          if (!hasMoreBytes && !atEof) {
            const probe = Buffer.alloc(1);
            const n = fs.readSync(fd, probe, 0, 1, null);
            if (n > 0) {
              hasMoreBytes = true;
            } else {
              atEof = true;
            }
          }

          if (hasMoreBytes) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              'Malformed JSON line in active audit segment before EOF',
            );
          }

          const tailClassification = classifyTrailingBytes(lineBytes, { allowTornTail: true });
          if (!tailClassification.recoverable) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              tailClassification.rejection === 'TORN_TAIL_TOO_LARGE'
                ? `Torn tail exceeds MAX_TORN_TAIL_BYTES (${MAX_TORN_TAIL_BYTES})`
                : 'Malformed JSON line in active audit segment before EOF',
            );
          }

          if (trustedBoundary !== undefined && !trustedBoundaryMatched) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `Trusted boundary sequence ${trustedBoundary.sequenceNumber} not satisfied before candidate torn tail`,
            );
          }

          return {
            status: 'RECOVERABLE_TORN_ACTIVE_TAIL',
            lastVerifiedByteOffset,
            tornBytes: tailClassification.tornBytes,
            terminalSequence,
            terminalRecordHash,
            nextSequence,
            previousRecordHash,
            activeIdentity,
            danglingOperations: extractDanglingOperations(lifecycleMap),
          };
        }

        let parseResult: { record: PersistentAuditRecordV1; computedHash: string };
        try {
          parseResult = parseAndValidateRecordLineV1(decodedLine);
        } catch (err: unknown) {
          const code = (err as CodedError)?.code;
          if (code === 'INVALID_RECORD' && (err as Error)?.message?.includes('lifecycle')) {
            throw createCodedError('AUDIT_LIFECYCLE_CORRUPTION', (err as Error).message, {
              cause: err,
            });
          }
          throw createCodedError(
            'AUDIT_CORRUPTION_DETECTED',
            (err as Error)?.message ?? 'Record validation failed',
            { cause: err },
          );
        }

        const { record } = parseResult;

        if (recordCount === 0) {
          if (record.sequenceNumber !== 1) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `First record sequenceNumber must be 1 (actual: ${record.sequenceNumber})`,
            );
          }
          if (
            record.integrity.previousRecordHash !==
            '0000000000000000000000000000000000000000000000000000000000000000'
          ) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              'First record previousRecordHash must be 64 zeroes',
            );
          }
        } else {
          if (record.sequenceNumber !== nextSequence) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `Sequence discontinuity: expected ${nextSequence}, got ${record.sequenceNumber}`,
            );
          }
          if (record.integrity.previousRecordHash !== previousRecordHash) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `previousRecordHash mismatch at sequence ${record.sequenceNumber}`,
            );
          }
        }

        if (record.lifecycle !== undefined) {
          updateLifecycle(lifecycleMap, record);
        }

        if (
          trustedBoundary !== undefined &&
          record.sequenceNumber === trustedBoundary.sequenceNumber
        ) {
          if (record.integrity.recordHash !== trustedBoundary.recordHash) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `Trusted boundary hash mismatch at sequence ${trustedBoundary.sequenceNumber}: expected ${trustedBoundary.recordHash}, got ${record.integrity.recordHash}`,
            );
          }
          trustedBoundaryMatched = true;
        }

        recordCount++;
        terminalSequence = record.sequenceNumber;
        terminalRecordHash = record.integrity.recordHash;
        nextSequence = record.sequenceNumber + 1;
        previousRecordHash = record.integrity.recordHash;
        lastVerifiedByteOffset += lineBytes.length;

        accumulated = Buffer.from(remainingBytes);
        continue;
      }

      if (atEof) {
        if (accumulated.length === 0) {
          if (trustedBoundary !== undefined && !trustedBoundaryMatched) {
            throw createCodedError(
              'AUDIT_CORRUPTION_DETECTED',
              `Trusted boundary sequence ${trustedBoundary.sequenceNumber} was not found in verified history`,
            );
          }
          return {
            status: 'VERIFIED',
            recordCount,
            terminalSequence,
            terminalRecordHash,
            nextSequence,
            previousRecordHash,
            verifiedByteLength: lastVerifiedByteOffset,
            activeIdentity,
            danglingOperations: extractDanglingOperations(lifecycleMap),
          };
        }

        // An unterminated final fragment is a torn-tail candidate purely on the
        // shared rule. It is deliberately NOT required to be undecodable: a
        // complete record that merely lost its newline is just as much a crash
        // artifact as a half-written one.
        const tailClassification = classifyTrailingBytes(accumulated, { allowTornTail: true });
        if (!tailClassification.recoverable) {
          throw createCodedError(
            'AUDIT_CORRUPTION_DETECTED',
            `Unterminated torn tail exceeds MAX_TORN_TAIL_BYTES (${MAX_TORN_TAIL_BYTES})`,
          );
        }

        if (trustedBoundary !== undefined && !trustedBoundaryMatched) {
          throw createCodedError(
            'AUDIT_CORRUPTION_DETECTED',
            `Trusted boundary sequence ${trustedBoundary.sequenceNumber} lies in candidate torn tail or beyond EOF`,
          );
        }

        return {
          status: 'RECOVERABLE_TORN_ACTIVE_TAIL',
          lastVerifiedByteOffset,
          tornBytes: tailClassification.tornBytes,
          terminalSequence,
          terminalRecordHash,
          nextSequence,
          previousRecordHash,
          activeIdentity,
          danglingOperations: extractDanglingOperations(lifecycleMap),
        };
      }

      if (accumulated.length > MAX_RECORD_BYTES) {
        throw createCodedError(
          'AUDIT_CORRUPTION_DETECTED',
          `Record line exceeds MAX_RECORD_BYTES (${MAX_RECORD_BYTES}) without newline`,
        );
      }
    }
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/**
 * Isolates a permitted torn active tail to a sidecar, truncates the active
 * segment back to its last verified record, and fsyncs both.
 *
 * Extracted so Task-2 restart recovery and the Task-6 production startup engine
 * repair a torn tail through EXACTLY ONE implementation. There is no second
 * truncation path, no second sidecar naming family, no second collision rule and
 * no second durability ordering: the sidecar is created exclusively and made
 * durable, the directory is fsynced, the descriptor identity and expected length
 * are re-proved immediately before `ftruncate`, and the truncated descriptor is
 * fdatasynced before the function returns.
 *
 * The caller supplies the post-repair verification authority, because "the
 * active segment re-verified from the beginning" means different things to the
 * two callers: Task-2 recovery re-verifies the active segment alone against its
 * trusted boundary, while the Task-6 full-history engine re-verifies the whole
 * retained primary history, which is the only correct re-verification for a
 * store that has rotated archives. The bytes on disk are touched by one
 * implementation either way.
 *
 * @internal
 */
export async function repairTornActiveTailInternal(
  auditDir: string,
  expectedUid: number,
  classification: {
    lastVerifiedByteOffset: number;
    tornBytes: Buffer;
    activeIdentity: { dev: number; ino: number };
  },
  verifyAfterRepair: () => Promise<void>,
  testHooks?: RecoveryTestHooks,
): Promise<string> {
  const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);

  try {
    const now = new Date();
    const isoTime = testHooks?.sidecarTimestamp ?? now.toISOString().replace(/:/g, '-');
    let sidecarFilename = `${ACTIVE_SEGMENT_FILENAME}.torn.${isoTime}`;
    let sidecarCandidate = path.join(auditDir, sidecarFilename);

    let sidecarFd: number | null = null;
    let counter = 0;
    while (sidecarFd === null) {
      try {
        if (testHooks?.failSidecarCreation) {
          throw createCodedError(
            'SIMULATED_SIDECAR_CREATION_FAILURE',
            'Simulated sidecar creation failure',
          );
        }
        sidecarFd = fs.openSync(
          sidecarCandidate,
          fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
          0o600,
        );
      } catch (err: unknown) {
        const code = (err as { code?: string })?.code;
        if (code === 'EEXIST') {
          counter++;
          if (counter > 10) {
            throw createCodedError(
              'AUDIT_RECOVERY_FAILED',
              `Unable to find collision-free torn sidecar filename after ${counter} attempts`,
              { cause: err },
            );
          }
          sidecarFilename = `${ACTIVE_SEGMENT_FILENAME}.torn.${isoTime}.${counter}`;
          sidecarCandidate = path.join(auditDir, sidecarFilename);
          continue;
        }
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          `Failed to create torn sidecar file: ${(err as Error)?.message}`,
          { cause: err },
        );
      }
    }

    const sidecarPath = sidecarCandidate;

    try {
      const sidecarStats = validateFileDescriptorAuthority(sidecarFd, 0o600, expectedUid);
      if (!sidecarStats.isFile() || sidecarStats.nlink !== 1) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          'Insecure sidecar file descriptor authority',
        );
      }

      if (testHooks?.failSidecarWrite) {
        throw createCodedError(
          'SIMULATED_SIDECAR_WRITE_FAILURE',
          'Simulated sidecar write failure',
        );
      }

      let written = 0;
      const tornBytes = classification.tornBytes;
      while (written < tornBytes.length) {
        const n = fs.writeSync(sidecarFd, tornBytes, written, tornBytes.length - written, null);
        if (n <= 0) {
          throw createCodedError(
            'AUDIT_RECOVERY_FAILED',
            'Short write writing torn bytes to sidecar',
          );
        }
        written += n;
      }

      if (testHooks?.failSidecarSync) {
        throw createCodedError('SIMULATED_SIDECAR_SYNC_FAILURE', 'Simulated sidecar sync failure');
      }

      fs.fsyncSync(sidecarFd);
    } finally {
      fs.closeSync(sidecarFd);
    }

    const dirFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }

    if (testHooks?.beforeTruncate) {
      testHooks.beforeTruncate();
    }

    const truncFd = fs.openSync(activePath, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW);
    try {
      const truncStats = validateFileDescriptorAuthority(truncFd, 0o600, expectedUid);
      if (
        truncStats.dev !== classification.activeIdentity.dev ||
        truncStats.ino !== classification.activeIdentity.ino
      ) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          'Active file identity changed between classification and truncation',
        );
      }

      const classifiedFileSize =
        classification.lastVerifiedByteOffset + classification.tornBytes.length;
      if (truncStats.size !== classifiedFileSize) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          `Active file size changed unexpectedly before truncation (expected: ${classifiedFileSize}, actual: ${truncStats.size})`,
        );
      }

      if (testHooks?.failTruncation) {
        throw createCodedError('SIMULATED_TRUNCATION_FAILURE', 'Simulated truncation failure');
      }

      fs.ftruncateSync(truncFd, classification.lastVerifiedByteOffset);
      fs.fdatasyncSync(truncFd);
    } finally {
      fs.closeSync(truncFd);
    }

    // The repaired segment must verify from the beginning before anything else
    // proceeds. A repair that does not produce verifiable bytes is not a repair.
    await verifyAfterRepair();

    return sidecarPath;
  } catch (err: unknown) {
    const code = (err as CodedError)?.code;
    if (
      code === 'AUDIT_CORRUPTION_DETECTED' ||
      code === 'AUDIT_LIFECYCLE_CORRUPTION' ||
      code === 'AUDIT_RECOVERY_FAILED'
    ) {
      throw err;
    }
    throw createCodedError(
      'AUDIT_RECOVERY_FAILED',
      `Torn tail recovery failed: ${(err as Error)?.message}`,
      { cause: err },
    );
  }
}

/**
 * Builds the canonical `RECOVERY_INDETERMINATE` record for one dangling
 * operation (§7.3.5, §7.3.6, §7.3.7).
 *
 * Extracted so the Task-2 restart path and the Task-6 production full-history
 * startup engine append byte-identical recovery evidence. The construction is
 * closed: the canonical SYSTEM actor, the fixed `execution` block, the fixed
 * `error` block, and the copied `target`/`invocation`/`policy`/`approval`
 * context are all defined here and nowhere else. No caller can supply an actor,
 * an execution status, an error message, or a `gateway` block for a recovery
 * record.
 *
 * @internal
 */
export function buildRecoveryIndeterminateRecord(
  danglingOp: DanglingOperation,
  recoveryTimestamp: string,
): Omit<PersistentAuditRecordV1, 'sequenceNumber' | 'integrity' | 'schemaVersion'> {
  return {
    eventId: randomUUID(),
    timestamp: recoveryTimestamp,
    actor: {
      clientId: 'system',
      clientType: 'SYSTEM',
      deviceId: '',
      sessionId: '',
    },
    lifecycle: {
      operationId: danglingOp.operationId,
      phase: 'RECOVERY_INDETERMINATE',
    },
    execution: {
      status: 'ERROR',
      startTime: recoveryTimestamp,
      endTime: recoveryTimestamp,
      durationMs: 0,
    },
    error: {
      code: 'AUDIT_OUTCOME_INDETERMINATE',
      message: 'Prior operation outcome is indeterminate after crash recovery.',
    },
    target: danglingOp.target as AuditRecord['target'],
    invocation: danglingOp.invocation as AuditRecord['invocation'],
    policy: danglingOp.policy as AuditRecord['policy'],
    ...(danglingOp.approval !== undefined
      ? { approval: danglingOp.approval as AuditRecord['approval'] }
      : {}),
  };
}

export interface AuditRecoveryResult {
  storage: PersistentAuditStorage;
  recoveredTornTail: boolean;
  tornSidecarPath?: string;
  indeterminateRecoveries: number;
  terminalSequence: number;
  terminalRecordHash: string;
  nextSequence: number;
}

export interface AuditRecoveryOptions {
  trustedBoundary?: TrustedPrimaryChainBoundary;
}

/**
 * Internal implementation of restart recovery coordinating verification,
 * torn tail recovery, and dangling operation reconciliation.
 *
 * Test hooks are supplied strictly through package-internal test entry points.
 * @internal
 */
export async function executeAuditRecoveryInternal(
  config: PersistentAuditStorageConfig,
  trustedBoundary?: TrustedPrimaryChainBoundary,
  testHooks?: RecoveryTestHooks,
): Promise<AuditRecoveryResult> {
  validatePlatformCapabilities(config.platformProbe);

  const auditDir = config.directory ?? DEFAULT_AUDIT_DIR;
  const expectedUid = config.expectedUid ?? getProcessUid();

  validateAuditDirectory(auditDir, {
    createIfMissing: config.createIfMissing ?? false,
    workspacePaths: config.workspacePaths,
    expectedUid,
  });

  const normalizedMetadataConfig = normalizeStoreMetadataConfig(config.metadata);

  const lock = acquireWriterLock({
    auditDir,
    expectedUid,
  });

  let activeFd: number | null = null;
  let storage: PersistentAuditStorage | null = null;

  try {
    const metadataPath = path.join(auditDir, METADATA_FILENAME);
    const activePath = path.join(auditDir, ACTIVE_SEGMENT_FILENAME);

    let metadata: AuditStoreMetadataV1;
    if (!fs.existsSync(metadataPath)) {
      if (fs.existsSync(activePath)) {
        const lstat = fs.lstatSync(activePath);
        if (lstat.isSymbolicLink()) {
          throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
        }
        let probeFd: number;
        try {
          probeFd = fs.openSync(activePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
        } catch (err: unknown) {
          const errCode = (err as { code?: string })?.code;
          if (errCode === 'ELOOP') {
            throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
          }
          throw err;
        }

        try {
          const probeStats = validateFileDescriptorAuthority(probeFd, 0o600, expectedUid);
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

      if (config.createIfMissing) {
        const freshMetadata: AuditStoreMetadataV1 = {
          version: 1,
          storeId: randomUUID(),
          createdAt: new Date().toISOString(),
          checkpointPublicKeyFingerprint: normalizedMetadataConfig.checkpointPublicKeyFingerprint,
          anchorMode: normalizedMetadataConfig.anchorMode,
          ...(normalizedMetadataConfig.anchorMode === 'ENABLED' &&
          normalizedMetadataConfig.anchorReceiptPublicKeyFingerprint
            ? {
                anchorReceiptPublicKeyFingerprint:
                  normalizedMetadataConfig.anchorReceiptPublicKeyFingerprint,
              }
            : {}),
        };
        createStoreMetadataFile(auditDir, freshMetadata, expectedUid);
        metadata = freshMetadata;
      } else {
        throw createCodedError('METADATA_MISSING', 'audit-store.json missing');
      }
    } else {
      const loaded = loadStoreMetadataFile(auditDir, expectedUid);
      validateStoreMetadataConsistency(loaded, normalizedMetadataConfig);
      metadata = loaded;
    }

    if (!fs.existsSync(activePath)) {
      const initFd = fs.openSync(
        activePath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
      fs.closeSync(initFd);
      const dirFd = fs.openSync(auditDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
    }

    const verifyResult = verifyActiveStream(activePath, expectedUid, {
      trustedBoundary,
    });

    let recoveredTornTail = false;
    let tornSidecarPath: string | undefined = undefined;
    let verifiedStream!: VerifiedStreamResult;

    if (verifyResult.status === 'RECOVERABLE_TORN_ACTIVE_TAIL') {
      recoveredTornTail = true;
      tornSidecarPath = await repairTornActiveTailInternal(
        auditDir,
        expectedUid,
        {
          lastVerifiedByteOffset: verifyResult.lastVerifiedByteOffset,
          tornBytes: verifyResult.tornBytes,
          activeIdentity: verifyResult.activeIdentity,
        },
        async () => {
          const reverifyResult = verifyActiveStream(activePath, expectedUid, {
            trustedBoundary,
          });
          if (reverifyResult.status !== 'VERIFIED') {
            throw createCodedError(
              'AUDIT_RECOVERY_FAILED',
              'Re-verification of active segment failed after torn tail truncation',
            );
          }
          verifiedStream = reverifyResult;
        },
        testHooks,
      );
    } else {
      verifiedStream = verifyResult;
    }

    if (testHooks?.beforeFinalAppendOpen) {
      testHooks.beforeFinalAppendOpen();
    }

    try {
      activeFd = fs.openSync(
        activePath,
        fsConstants.O_APPEND | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600,
      );
    } catch (err: unknown) {
      const errCode = (err as { code?: string })?.code;
      if (errCode === 'ELOOP') {
        throw createCodedError('SYMLINK_DETECTED', 'active segment is a symbolic link');
      }
      throw err;
    }

    const appendStats = validateFileDescriptorAuthority(activeFd, 0o600, expectedUid);
    if (
      appendStats.dev !== verifiedStream.activeIdentity.dev ||
      appendStats.ino !== verifiedStream.activeIdentity.ino
    ) {
      throw createCodedError(
        'AUDIT_RECOVERY_FAILED',
        'Active file replacement detected before activating storage',
      );
    }
    if (appendStats.size !== verifiedStream.verifiedByteLength) {
      throw createCodedError(
        'AUDIT_RECOVERY_FAILED',
        'Active file length mismatch between verification and activation',
      );
    }

    storage = PersistentAuditStorage._fromVerifiedRecovery(
      RECOVERY_HANDOFF_TOKEN,
      config,
      {
        lock,
        metadata,
        activeFd,
        terminalSequence: verifiedStream.terminalSequence,
        terminalRecordHash: verifiedStream.terminalRecordHash,
        verifiedActiveIdentity: { dev: appendStats.dev, ino: appendStats.ino },
      },
      testHooks?.storageTestFaults ? { testFaults: testHooks.storageTestFaults } : undefined,
    );

    let indeterminateRecoveries = 0;
    const danglingOps = verifiedStream.danglingOperations;
    let opIndex = 0;

    for (const danglingOp of danglingOps) {
      const recoveryTimestamp = new Date().toISOString();
      const recoveryCandidate = buildRecoveryIndeterminateRecord(danglingOp, recoveryTimestamp);

      try {
        if (
          testHooks?.failRecoveryAppendAtIndex !== undefined &&
          opIndex === testHooks.failRecoveryAppendAtIndex
        ) {
          throw createCodedError(
            'SIMULATED_RECOVERY_APPEND_FAILURE',
            `Simulated recovery append failure at index ${opIndex}`,
          );
        }

        await storage.append(recoveryCandidate);
        indeterminateRecoveries++;
        opIndex++;
      } catch (appendErr: unknown) {
        throw createCodedError(
          'AUDIT_RECOVERY_FAILED',
          `Failed to append recovery record for dangling operation ${danglingOp.operationId}`,
          { cause: appendErr },
        );
      }
    }

    return {
      storage,
      recoveredTornTail,
      ...(tornSidecarPath ? { tornSidecarPath } : {}),
      indeterminateRecoveries,
      terminalSequence: storage.getCurrentSequence() - 1,
      terminalRecordHash: storage.getLastRecordHash(),
      nextSequence: storage.getCurrentSequence(),
    };
  } catch (err: unknown) {
    if (storage !== null) {
      try {
        storage.close();
      } catch {
        // ignore
      }
    } else {
      if (activeFd !== null) {
        try {
          fs.closeSync(activeFd);
        } catch {
          // ignore
        }
      }
      try {
        lock.release();
      } catch {
        // ignore
      }
    }
    throw err;
  }
}

/**
 * Recovers persistent audit storage on restart.
 *
 * Public production API: accepts only production configuration and optional
 * trusted primary-chain boundary. Exposes zero test callbacks or fault flags.
 */
export async function recoverPersistentAuditStorage(
  config: PersistentAuditStorageConfig,
  options?: AuditRecoveryOptions,
): Promise<AuditRecoveryResult> {
  return executeAuditRecoveryInternal(config, options?.trustedBoundary);
}
