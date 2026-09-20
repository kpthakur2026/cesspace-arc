/**
 * CesSpace ARC — RC-05 Task 10 Gateway Lifecycle Audit Sink
 *
 * Commits the fourteen frozen gateway lifecycle events (rc05 §24) into the ONE
 * EXISTING `AuditLogger` chain — the same append-only SHA-256 chain that already
 * carries ordinary MCP tool records and RC-04 approval lifecycle records. There
 * is no second logger, no gateway-only chain, no file-backed ledger, and no
 * external anchoring: RC-06 owns persistent and anchored audit storage.
 *
 *   RemoteGateway / RemoteMcpSurface / EnrollmentBootstrap / AdminIpcServer
 *     -> bounded, safe GatewayLifecycleEvent
 *     -> GatewayAuditSink buffers it (bounded)
 *     -> serialized drain writes it into AuditLogger
 *     -> AuditLogger appends to the existing chain
 *
 * The sink holds only bounded, safe lifecycle facts. It has no execution
 * authority of any kind, and it cannot record a value that §24 forbids: the
 * metadata projection it applies is the same central one the logger applies, so
 * an event carrying a credential shape is sanitized rather than stored.
 */

import type {
  AuditGatewayMetadata,
  AuditRecord,
  GatewayAuditAdmissionLayer,
  GatewayAuditEventType,
  GatewayAuditReason,
} from '@cesspace-arc/protocol';
import {
  canonicalJson,
  computeSha256,
  projectGatewayMetadata,
  type AuditLogger,
} from '@cesspace-arc/audit';

/**
 * Maximum buffered gateway events awaiting an audit write.
 *
 * Deliberately conservative. Gateway events are emitted at most a handful per
 * request, and the drain runs continuously rather than at a caller-chosen flush
 * point, so this bound is only ever approached under a sustained storm. The
 * queue is never allowed to grow without limit, and evidence is never silently
 * dropped — see {@link GatewayAuditSink.flush}.
 */
export const MAX_PENDING_GATEWAY_EVENTS = 4096;

/**
 * One bounded gateway lifecycle event, as emitted by a lifecycle owner.
 *
 * Every field is a server-derived identifier or a closed-vocabulary word. There
 * is deliberately no field for a credential: an emitter physically cannot pass a
 * session token, an enrollment secret, a private key, a certificate, an
 * `Authorization` value, or a peer address through this type.
 */
export interface GatewayLifecycleEvent {
  eventType: GatewayAuditEventType;
  reason?: GatewayAuditReason;
  admissionLayer?: GatewayAuditAdmissionLayer;
  mcpSessionId?: string;
  deviceId?: string;
  spkiPin?: string;
  clientId?: string;
  clientType?: string;
  enrollmentId?: string;
  transportMode?: 'stdio' | 'remote';
}

/** @internal Clock seam for deterministic tests. Production uses the wall clock. */
export interface GatewayAuditSinkOptions {
  getWallTime?: () => number;
}

/**
 * Fixed `ruleId` on every gateway lifecycle record.
 *
 * A gateway lifecycle transition is not an RC-04 authorization decision: no
 * policy evaluator ran, which is exactly what `evaluationDurationMs: 0` records.
 * The `policy.decision` field on such a record is the bounded GATEWAY admission
 * disposition — `ALLOW` when the transition proceeded, `DENY` when the gateway
 * refused it — and never a substitute for an authorization result.
 */
const GATEWAY_RULE_ID = 'gateway-lifecycle';

/** Bounded execution status per event. */
const STATUS_BY_EVENT: Readonly<Record<GatewayAuditEventType, AuditRecord['execution']['status']>> =
  {
    GATEWAY_STARTED: 'SUCCESS',
    GATEWAY_STOPPED: 'SUCCESS',
    DEVICE_ENROLLMENT_REQUESTED: 'SUCCESS',
    DEVICE_ENROLLED: 'SUCCESS',
    DEVICE_ENROLLMENT_REJECTED: 'CANCELLED',
    DEVICE_REVOKED: 'SUCCESS',
    AUTH_SUCCEEDED: 'SUCCESS',
    AUTH_FAILED: 'DENIED',
    SESSION_ISSUED: 'SUCCESS',
    SESSION_EXPIRED: 'TIMEOUT',
    SESSION_REVOKED: 'CANCELLED',
    SESSION_CLOSED: 'SUCCESS',
    RATE_LIMITED: 'DENIED',
    REMOTE_DISCONNECTED: 'SUCCESS',
  };

/** Bounded gateway admission disposition per event. Never an authorization result. */
const DECISION_BY_EVENT: Readonly<Record<GatewayAuditEventType, 'ALLOW' | 'DENY'>> = {
  GATEWAY_STARTED: 'ALLOW',
  GATEWAY_STOPPED: 'ALLOW',
  DEVICE_ENROLLMENT_REQUESTED: 'ALLOW',
  DEVICE_ENROLLED: 'ALLOW',
  DEVICE_ENROLLMENT_REJECTED: 'DENY',
  DEVICE_REVOKED: 'ALLOW',
  AUTH_SUCCEEDED: 'ALLOW',
  AUTH_FAILED: 'DENY',
  SESSION_ISSUED: 'ALLOW',
  SESSION_EXPIRED: 'ALLOW',
  SESSION_REVOKED: 'ALLOW',
  SESSION_CLOSED: 'ALLOW',
  RATE_LIMITED: 'DENY',
  REMOTE_DISCONNECTED: 'ALLOW',
};

/**
 * Bounded fixed error strings for refusal events. A raw exception message is
 * never inserted: the reason vocabulary in the metadata is the whole of it.
 */
const ERROR_BY_EVENT: Partial<
  Readonly<Record<GatewayAuditEventType, { code: string; message: string }>>
> = {
  AUTH_FAILED: { code: 'UNAUTHENTICATED', message: 'Authentication failed' },
  RATE_LIMITED: {
    code: 'RATE_LIMIT_EXCEEDED',
    message: 'Request rate limit exceeded.',
  },
  DEVICE_ENROLLMENT_REJECTED: {
    code: 'ENROLLMENT_FAILED',
    message: 'Enrollment failed',
  },
};

/** Raised when required gateway lifecycle evidence could not be written. */
export class GatewayAuditError extends Error {
  constructor(
    message: string,
    public readonly reason: 'QUEUE_OVERFLOW' | 'WRITE_FAILED',
  ) {
    super(message);
    this.name = 'GatewayAuditError';
  }
}

/**
 * One sink per audit chain.
 *
 * The gateway, the MCP surface, the enrollment bootstrap, and the local admin
 * channel all emit into the SAME chain. Two sinks over one logger would each
 * hold their own queue over the same sequence counter, so a single lifecycle
 * transition observed by both could be written twice — indistinguishable from
 * two genuine transitions and undetectable by integrity verification, because
 * each duplicate record is individually well-formed and correctly chained.
 * Memoizing per logger makes "one chain, one sink" structural.
 */
const sinksByLogger = new WeakMap<AuditLogger, GatewayAuditSink>();

/** Returns the single gateway lifecycle sink bound to the given audit chain. */
export function getGatewayAuditSink(
  auditLogger: AuditLogger,
  options: GatewayAuditSinkOptions = {},
): GatewayAuditSink {
  let sink = sinksByLogger.get(auditLogger);
  if (sink === undefined) {
    sink = new GatewayAuditSink(auditLogger, options);
    sinksByLogger.set(auditLogger, sink);
  }
  return sink;
}

export class GatewayAuditSink {
  private readonly queue: GatewayLifecycleEvent[] = [];
  private drainTail: Promise<void> = Promise.resolve();
  private overflowed = false;
  private writeFailed = false;

  constructor(
    private readonly auditLogger: AuditLogger,
    private readonly options: GatewayAuditSinkOptions = {},
  ) {}

  /**
   * Records one gateway lifecycle event.
   *
   * Synchronous by contract: it performs no I/O, so a lifecycle owner — a socket
   * callback, a handshake handler, a rate-limiter refusal — can emit without
   * becoming asynchronous or blocking on the audit chain.
   *
   * An event whose `eventType` is not one of the fourteen frozen names is
   * DROPPED rather than stored under a substitute name: the catalog is closed,
   * so there is nothing truthful to write.
   */
  public emit(event: GatewayLifecycleEvent): void {
    const projected = projectGatewayMetadata(event);
    if (projected === undefined) {
      return;
    }
    if (this.queue.length >= MAX_PENDING_GATEWAY_EVENTS) {
      // Bounded queue. Evidence must never be silently discarded, so the sink
      // latches an overflow that flush() turns into a fail-closed error.
      this.overflowed = true;
      return;
    }
    this.queue.push(this.freezeEvent(projected));
    this.scheduleDrain();
  }

  /** Number of lifecycle events awaiting an audit write. */
  public get pendingCount(): number {
    return this.queue.length;
  }

  /** True when the bounded queue overflowed and evidence was not enqueued. */
  public get hasOverflowed(): boolean {
    return this.overflowed;
  }

  /** True when a queued event could not be written into the chain. */
  public get hasWriteFailed(): boolean {
    return this.writeFailed;
  }

  /**
   * Waits until every event emitted so far has been written into the chain.
   *
   * Fails closed when evidence could not be enqueued or written. It never
   * discards queued evidence and never restores any lifecycle state: the
   * transition being described has already happened and must remain intact.
   *
   * Overflow still fails the flush. The queue is drained FIRST, though, so
   * evidence that was buffered and is still writable is committed rather than
   * stranded behind a permanent latch.
   */
  public async flush(): Promise<void> {
    await this.drainTail;
    if (this.writeFailed) {
      throw new GatewayAuditError('Gateway lifecycle audit write failed.', 'WRITE_FAILED');
    }
    if (this.overflowed) {
      throw new GatewayAuditError(
        'Gateway lifecycle audit queue overflowed; required evidence was not recorded.',
        'QUEUE_OVERFLOW',
      );
    }
  }

  /**
   * Copies the projected metadata into a fresh frozen object.
   *
   * A lifecycle owner keeps no reference the sink later reads, so an emitter
   * cannot mutate an event after it was queued and change what is written.
   */
  private freezeEvent(projected: AuditGatewayMetadata): GatewayLifecycleEvent {
    return Object.freeze({
      eventType: projected.eventType,
      ...(projected.reason === undefined ? {} : { reason: projected.reason }),
      ...(projected.admissionLayer === undefined
        ? {}
        : { admissionLayer: projected.admissionLayer }),
      ...(projected.mcpSessionId === undefined ? {} : { mcpSessionId: projected.mcpSessionId }),
      ...(projected.deviceId === undefined ? {} : { deviceId: projected.deviceId }),
      ...(projected.spkiPin === undefined ? {} : { spkiPin: projected.spkiPin }),
      ...(projected.clientId === undefined ? {} : { clientId: projected.clientId }),
      ...(projected.clientType === undefined ? {} : { clientType: projected.clientType }),
      ...(projected.enrollmentId === undefined ? {} : { enrollmentId: projected.enrollmentId }),
      ...(projected.transportMode === undefined ? {} : { transportMode: projected.transportMode }),
    });
  }

  /**
   * Arms the serialized drain.
   *
   * Drains are SERIALIZED. Without this, two concurrent drains can both read the
   * same queue[0] across the await inside the loop and each write it, producing
   * duplicate lifecycle evidence for a single transition and interleaving the
   * chain. Each drain waits for every prior drain and then empties the queue, so
   * events are written in emission order.
   *
   * The rejection handler is not error masking: it latches the failure so
   * {@link flush} reports it, and it exists so an emission from a callback that
   * has no way to await the drain cannot become an unhandled rejection.
   */
  private scheduleDrain(): void {
    this.drainTail = this.drainTail.then(
      () => this.drainUntilEmpty(),
      () => this.drainUntilEmpty(),
    );
    void this.drainTail.catch(() => {
      this.writeFailed = true;
    });
  }

  /**
   * Writes buffered events in order until the queue is empty.
   *
   * A write failure leaves the remaining events buffered and latches the
   * failure, so a caller that flushes observes it rather than being told the
   * evidence was recorded.
   */
  private async drainUntilEmpty(): Promise<void> {
    while (this.queue.length > 0) {
      const event = this.queue[0];
      try {
        await this.auditLogger.log(this.toAuditRecord(event));
      } catch {
        this.writeFailed = true;
        throw new GatewayAuditError('Gateway lifecycle audit write failed.', 'WRITE_FAILED');
      }
      this.queue.shift();
    }
  }

  /**
   * Maps a lifecycle event to an ordinary audit record.
   *
   * The record contains only bounded facts, and it is built from the SAME
   * projected metadata the logger will project again on the way in, so there is
   * one definition of the safe gateway shape rather than two that could drift.
   */
  private toAuditRecord(
    event: GatewayLifecycleEvent,
  ): Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'> {
    const occurredAt = new Date(this.options.getWallTime?.() ?? Date.now()).toISOString();
    const parametersRedacted: Record<string, unknown> = {
      eventType: event.eventType,
      ...(event.reason === undefined ? {} : { reason: event.reason }),
      ...(event.admissionLayer === undefined ? {} : { admissionLayer: event.admissionLayer }),
    };

    return {
      timestamp: occurredAt,
      actor: {
        clientId: event.clientId ?? '',
        clientType: event.clientType ?? '',
        deviceId: event.deviceId ?? '',
        sessionId: event.mcpSessionId ?? '',
      },
      target: {
        workspaceId: '',
        workspacePath: '',
      },
      invocation: {
        toolName: `gateway:${event.eventType}`,
        parametersRedacted,
        // Derived from the already-bounded representation above, never from raw
        // input: the fallback hash cannot become a digest of a secret.
        payloadHash: computeSha256(canonicalJson(parametersRedacted)),
      },
      policy: {
        decision: DECISION_BY_EVENT[event.eventType],
        ruleId: GATEWAY_RULE_ID,
        evaluationDurationMs: 0,
      },
      execution: {
        status: STATUS_BY_EVENT[event.eventType],
        startTime: occurredAt,
        endTime: occurredAt,
        durationMs: 0,
      },
      gateway: {
        eventType: event.eventType,
        ...(event.reason === undefined ? {} : { reason: event.reason }),
        ...(event.admissionLayer === undefined ? {} : { admissionLayer: event.admissionLayer }),
        ...(event.deviceId === undefined ? {} : { deviceId: event.deviceId }),
        ...(event.spkiPin === undefined ? {} : { spkiPin: event.spkiPin }),
        ...(event.clientId === undefined ? {} : { clientId: event.clientId }),
        ...(event.clientType === undefined ? {} : { clientType: event.clientType }),
        ...(event.enrollmentId === undefined ? {} : { enrollmentId: event.enrollmentId }),
        ...(event.mcpSessionId === undefined ? {} : { mcpSessionId: event.mcpSessionId }),
        ...(event.transportMode === undefined ? {} : { transportMode: event.transportMode }),
      },
      ...(ERROR_BY_EVENT[event.eventType] === undefined
        ? {}
        : { error: ERROR_BY_EVENT[event.eventType] }),
    };
  }
}
