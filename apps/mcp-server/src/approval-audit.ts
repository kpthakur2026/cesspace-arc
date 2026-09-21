/**
 * CesSpace ARC — RC-04 Task 5 Approval Lifecycle Audit Sink
 *
 * Bridges the synchronous approval state machine to the asynchronous audit
 * chain without making packages/policy depend on Promises or on packages/audit.
 *
 *   ApprovalStateManager
 *     -> synchronous, safe ApprovalLifecycleEvent
 *     -> ApprovalAuditSink buffers it (bounded)
 *     -> the ONE production write authority drains it (AuditWriteAuthority)
 *     -> the durable primary chain, with the in-memory chain as a mirror
 *
 * The sink holds only bounded, safe lifecycle facts: no token, no token digest,
 * no review material, no content, no patch text, no environment value, and no
 * absolute host path. It has no execution authority of any kind.
 */

import type { ApprovalLifecycleEvent, AuditRecord } from '@cesspace-arc/protocol';
import { canonicalJson, computeSha256, type AuditLogger } from '@cesspace-arc/audit';
import type { IApprovalLifecycleSink } from '@cesspace-arc/policy';
import {
  getAuditWriteAuthority,
  resolveAuditWriteAuthority,
  type AuditChainLike,
  type AuditWriteAuthority,
} from './audit-write-authority.js';

/**
 * Maximum buffered lifecycle events awaiting an audit write.
 *
 * Deliberately conservative: the approval manager already caps active records
 * at 1024 globally, so 4096 gives generous headroom while remaining bounded. The
 * queue is never allowed to grow without limit, and evidence is never silently
 * dropped — see {@link ApprovalAuditSink.flush}.
 */
export const MAX_PENDING_LIFECYCLE_EVENTS = 4096;

/** Bounded audit source classification (rc04 §76). */
export type ApprovalAuditSource = 'MCP' | 'LOCAL_OPERATOR' | 'SYSTEM';

const SOURCE_BY_EVENT: Readonly<Record<string, ApprovalAuditSource>> = {
  APPROVAL_REQUESTED: 'MCP',
  APPROVAL_GRANTED: 'LOCAL_OPERATOR',
  APPROVAL_REJECTED: 'LOCAL_OPERATOR',
  APPROVAL_EXPIRED: 'SYSTEM',
  APPROVAL_CONSUMED: 'MCP',
  APPROVAL_INVALIDATED: 'MCP',
  APPROVED_EXECUTION_SUCCEEDED: 'MCP',
  APPROVED_EXECUTION_FAILED: 'MCP',
};

/**
 * Bounded fixed error strings. Raw exception messages are never inserted
 * (rc04 §80).
 */
const ERROR_BY_EVENT: Readonly<Record<string, { code: string; message: string }>> = {
  APPROVAL_REJECTED: { code: 'APPROVAL_REJECTED', message: 'Approval request was rejected.' },
  APPROVAL_EXPIRED: { code: 'APPROVAL_EXPIRED', message: 'Approval request expired.' },
  APPROVAL_INVALIDATED: {
    code: 'APPROVAL_REJECTED',
    message: 'Approval request was invalidated.',
  },
  APPROVED_EXECUTION_FAILED: {
    code: 'APPROVED_EXECUTION_FAILED',
    message: 'Approved execution failed.',
  },
};

/** Bounded execution status per lifecycle event. */
const STATUS_BY_EVENT: Readonly<Record<string, AuditRecord['execution']['status']>> = {
  APPROVAL_REQUESTED: 'DENIED',
  APPROVAL_GRANTED: 'SUCCESS',
  APPROVAL_REJECTED: 'CANCELLED',
  APPROVAL_EXPIRED: 'TIMEOUT',
  APPROVAL_CONSUMED: 'SUCCESS',
  APPROVAL_INVALIDATED: 'CANCELLED',
  APPROVED_EXECUTION_SUCCEEDED: 'SUCCESS',
  APPROVED_EXECUTION_FAILED: 'ERROR',
};

/** Raised when required lifecycle evidence cannot be enqueued or written. */
export class ApprovalAuditError extends Error {
  constructor(
    message: string,
    public readonly reason: 'QUEUE_OVERFLOW' | 'WRITE_FAILED',
  ) {
    super(message);
    this.name = 'ApprovalAuditError';
  }
}

/**
 * One sink per audit chain.
 *
 * A sink is a buffer that is drained into one {@link AuditLogger}. Two sinks
 * over the SAME logger would each be registered as a separate lifecycle
 * observer, and the manager emits one event per registered sink, so a single
 * state transition would be written to the chain TWICE — indistinguishable from
 * two genuine grants, and undetectable by integrity verification because each
 * duplicate record is individually well-formed and correctly chained.
 *
 * Composing a server and an admin channel over one logger must therefore share
 * one sink, so the sink is memoized per logger here.
 */
const sinksByLogger = new WeakMap<AuditLogger, ApprovalAuditSink>();

/** Returns the single lifecycle sink bound to the given audit chain. */
export function getApprovalAuditSink(auditLogger: AuditLogger): ApprovalAuditSink {
  let sink = sinksByLogger.get(auditLogger);
  if (sink === undefined) {
    // The sink drains through the ONE production write authority for this chain,
    // so approval evidence lands in the same persistent primary sequence as tool,
    // gateway and process evidence.
    sink = new ApprovalAuditSink(getAuditWriteAuthority(auditLogger));
    sinksByLogger.set(auditLogger, sink);
  }
  return sink;
}

export class ApprovalAuditSink implements IApprovalLifecycleSink {
  private readonly queue: ApprovalLifecycleEvent[] = [];
  private flushTail: Promise<void> = Promise.resolve();
  private overflowed = false;

  private readonly authority: AuditWriteAuthority;

  /**
   * Accepts the ONE production write authority, or the bare in-memory chain the
   * historical callers and pre-RC-06 tests compose a sink over. Both are
   * normalized to one `write`, so there is never a second way into the chain.
   */
  constructor(target: AuditWriteAuthority | AuditChainLike) {
    this.authority = resolveAuditWriteAuthority(target);
  }

  /**
   * Receives one synchronous lifecycle event. Enqueue only: never performs I/O,
   * so it can never block or throw work back into the state machine.
   */
  public onApprovalLifecycleEvent(event: ApprovalLifecycleEvent): void {
    if (this.queue.length >= MAX_PENDING_LIFECYCLE_EVENTS) {
      // Bounded queue. Evidence must never be silently discarded, so the sink
      // latches an overflow that flush() turns into a fail-closed error.
      this.overflowed = true;
      return;
    }
    this.queue.push(event);
  }

  /** Number of lifecycle events awaiting an audit write. */
  public get pendingCount(): number {
    return this.queue.length;
  }

  /** True when the bounded queue overflowed and evidence was not enqueued. */
  public get hasOverflowed(): boolean {
    return this.overflowed;
  }

  /**
   * Writes every buffered lifecycle event into the audit chain, in event order.
   *
   * Fails closed when evidence could not be enqueued or written. It never
   * discards queued evidence and never restores approval state: the state
   * machine's truth is already committed and must remain intact (rc04 §38, §40).
   *
   * Overflow still fails the flush. The queue is drained FIRST, though, so
   * evidence that was buffered and is still writable is committed rather than
   * stranded behind a permanent latch.
   */
  public flush(): Promise<void> {
    // Flushes are SERIALIZED. Without this, two concurrent callers can both read
    // the same queue[0] across the await inside the drain loop and each write
    // it, producing duplicate lifecycle evidence for a single state transition.
    // Each flush waits for every prior flush and then drains to empty, so a
    // caller's own events are always committed before it returns.
    const run = this.flushTail.then(
      () => this.drainUntilEmpty(),
      () => this.drainUntilEmpty(),
    );
    this.flushTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * Writes buffered events in order until the queue is empty.
   *
   * Only ever invoked through the serialized {@link flush}. A write failure
   * leaves the remaining events buffered and propagates, so the control plane
   * can fail the initiating action closed without losing evidence.
   */
  private async drainUntilEmpty(): Promise<void> {
    while (this.queue.length > 0) {
      const event = this.queue[0];
      try {
        await this.authority.write(this.toAuditRecord(event));
      } catch {
        throw new ApprovalAuditError('Approval lifecycle audit write failed.', 'WRITE_FAILED');
      }
      this.queue.shift();
    }
    if (this.overflowed) {
      throw new ApprovalAuditError(
        'Approval lifecycle audit queue overflowed; required evidence was not recorded.',
        'QUEUE_OVERFLOW',
      );
    }
  }

  /**
   * Maps a lifecycle event to an ordinary audit record.
   *
   * The record contains only bounded facts. No token, token digest, review
   * material, content, patch text, environment value, or absolute host path can
   * appear here, and the target carries the workspace root DIGEST rather than
   * the raw root.
   */
  private toAuditRecord(
    event: ApprovalLifecycleEvent,
  ): Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'> {
    const source: ApprovalAuditSource = SOURCE_BY_EVENT[event.eventType] ?? 'MCP';
    const parametersRedacted: Record<string, unknown> = {
      eventType: event.eventType,
      requestId: event.requestId,
      state: event.state,
      workspaceId: event.workspaceId,
      ...(event.reasonCode === undefined ? {} : { reasonCode: event.reasonCode }),
      ...(event.operatorReasonProvided === undefined
        ? {}
        : { operatorReasonProvided: event.operatorReasonProvided }),
    };

    return {
      timestamp: event.occurredAt,
      actor: {
        clientId: event.actor.clientId,
        clientType: event.actor.clientType,
        deviceId: event.actor.deviceId ?? '',
        sessionId: event.actor.sessionId ?? '',
      },
      target: {
        workspaceId: event.workspaceId,
        workspacePath: '',
        workspaceRootHash: event.workspaceRootHash,
      },
      invocation: {
        toolName: event.toolName,
        parametersRedacted,
        // Derived from the already-bounded parameter representation above.
        payloadHash: computeSha256(canonicalJson(parametersRedacted)),
      },
      policy: {
        decision: 'REQUIRE_APPROVAL',
        ruleId: 'approval-lifecycle',
        evaluationDurationMs: 0,
        approvalId: event.requestId,
      },
      execution: {
        status: STATUS_BY_EVENT[event.eventType] ?? 'SUCCESS',
        startTime: event.occurredAt,
        endTime: event.occurredAt,
        durationMs: 0,
      },
      approval: {
        eventType: event.eventType,
        requestId: event.requestId,
        state: event.state,
        source,
        ...(event.reasonCode === undefined ? {} : { reasonCode: event.reasonCode }),
        ...(event.operatorReasonProvided === undefined
          ? {}
          : { operatorReasonProvided: event.operatorReasonProvided }),
      },
      error: ERROR_BY_EVENT[event.eventType],
    };
  }
}
