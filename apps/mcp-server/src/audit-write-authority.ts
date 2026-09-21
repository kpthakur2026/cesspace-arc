/**
 * CesSpace ARC — RC-06 Task 6 production audit write authority
 *
 * The ONE place a production audit record is committed. Before RC-06 there was
 * exactly one audit chain — the in-memory `AuditLogger` — and every emitter wrote
 * to it directly. RC-06 adds a second, authoritative, durable primary chain, and
 * having some emitters write to the durable chain while others still wrote only
 * to the in-memory one would produce two audit truths that disagree about what
 * happened: a store whose persisted history is missing every gateway
 * authentication failure, approval transition and process exit, with nothing on
 * disk to say so.
 *
 * This module is the single convergence point that prevents that.
 *
 *   GatewayAuditSink / ApprovalAuditSink / ProcessAuditSink / ArcMcpServer
 *     -> AuditWriteAuthority.write(body, lifecycle?)
 *     -> AuditLogger.log(body)          // THE central minimization/redaction
 *     -> AuditRuntime.appendRecord(...) // THE persistent primary authority
 *
 * Three properties follow from the shape rather than from discipline:
 *
 *   - The minimization happens in the SAME `AuditLogger.log()` call every
 *     emitter has always used, so there is no weaker second serialization path.
 *     The durable record is built from the minimized record, never from raw
 *     input.
 *   - There is exactly ONE authority per audit chain, memoized here per
 *     `AuditLogger`, so a composition that constructs a server and an admin
 *     channel over one logger cannot produce two writers over one chain.
 *   - A durable append failure PROPAGATES to the emitter. It is never absorbed
 *     into a successful in-memory-only write: a caller that believes evidence was
 *     recorded when only the mirror has it is the exact failure this exists to
 *     make impossible.
 *
 * The interface the sinks hold is deliberately narrow — one `write` method. No
 * sink, gateway, enrollment controller or admin channel is handed the
 * `AuditRuntime`; a subsystem cannot read the chain, select a sequence, choose a
 * checkpoint or clear the degraded latch through this object.
 */

import type {
  AuditLifecycleMetadata,
  AuditRecord,
  PersistentAuditRecordV1,
} from '@cesspace-arc/protocol';
import type { AuditRuntime } from '@cesspace-arc/audit';

/**
 * One production audit record, before the persistence-owned fields are added.
 *
 * `eventId`, `sequenceNumber` and `integrity` belong to whichever chain writes
 * the record. An emitter supplies facts; it never supplies a position in a
 * sequence or a hash-chain link.
 */
export type AuditWriteBody = Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>;

/**
 * The in-memory chain, as every pre-RC-06 caller already holds it.
 *
 * This is exactly the one method the sinks ever used: the centralized
 * minimization/redaction projection. It is named structurally rather than as
 * `AuditLogger` so a caller that composes a sink over a bare chain — the
 * historical compatibility mirror, and the pre-RC-06 tests that pass a minimal
 * in-memory chain — keeps working unchanged.
 */
export interface AuditChainLike {
  log(record: AuditWriteBody): Promise<AuditRecord>;
}

/**
 * One authority per audit chain.
 *
 * Keyed by the chain object because that object already IS the chain identity in
 * this codebase: the sinks are memoized per logger for the same reason, and a
 * second identity would let one chain acquire two writers.
 */
const authoritiesByLogger = new WeakMap<AuditChainLike, AuditWriteAuthority>();

/** Returns the single write authority bound to the given audit chain. */
export function getAuditWriteAuthority(chain: AuditChainLike): AuditWriteAuthority {
  let authority = authoritiesByLogger.get(chain);
  if (authority === undefined) {
    authority = new AuditWriteAuthority(chain);
    authoritiesByLogger.set(chain, authority);
  }
  return authority;
}

/**
 * Normalizes a sink's write target.
 *
 * A sink is constructed either with the ONE production write authority — which
 * the composition root builds, binds to the durable runtime, and shares with
 * every other sink over the same chain — or with a bare in-memory chain, which
 * is the historical shape. Both become the same single `write`, so a sink never
 * has two ways to commit a record.
 */
export function resolveAuditWriteAuthority(
  target: AuditWriteAuthority | AuditChainLike,
): AuditWriteAuthority {
  return target instanceof AuditWriteAuthority ? target : getAuditWriteAuthority(target);
}

export class AuditWriteAuthority {
  /**
   * The durable primary chain, bound by the composition root once startup has
   * verified it.
   *
   * `null` means no durable runtime has been established for this chain, which is
   * only reachable on an object that was never started — the sinks are built in
   * the constructor and the runtime is opened in `start()`, so the binding cannot
   * happen earlier. In that state a write is the historical in-memory-only write,
   * which is what every pre-RC-06 caller and test expects.
   */
  #runtime: AuditRuntime | null = null;

  /** @internal Constructed only through {@link getAuditWriteAuthority}. */
  constructor(private readonly chain: AuditChainLike) {}

  /**
   * Binds the durable primary chain. Idempotent for the SAME runtime.
   *
   * Replacing one runtime with another is refused rather than ignored: two
   * different durable chains behind one authority would make "which chain holds
   * this record" depend on timing, and a rebind after a failed restart could
   * silently redirect evidence for a chain that was already verified.
   *
   * @internal Called by the composition root during startup, never by a subsystem.
   */
  public bindDurableRuntime(runtime: AuditRuntime): void {
    if (this.#runtime !== null && this.#runtime !== runtime) {
      throw new Error(
        'Audit write authority is already bound to a durable runtime and cannot be rebound.',
      );
    }
    this.#runtime = runtime;
  }

  /** True once the durable primary chain is bound. */
  public get isDurable(): boolean {
    return this.#runtime !== null;
  }

  /**
   * Commits one production audit record.
   *
   * The record is produced by the central `AuditLogger` projection FIRST, so the
   * persistent chain receives exactly the minimized, redacted record the
   * in-memory chain always received. Only the persistence-owned fields are
   * stripped, and the caller's lifecycle block — when it supplies one — is added.
   *
   * `AuditRuntime.appendRecord` resolving IS durability: the record is written
   * and `fdatasync`ed, and every checkpoint the cadence implies is durable and
   * handed to Tier 3, before this resolves. A rejection therefore means the
   * evidence is NOT secured, and it is propagated rather than degraded into a
   * successful write.
   */
  public async write(
    body: AuditWriteBody,
    lifecycle?: AuditLifecycleMetadata,
  ): Promise<PersistentAuditRecordV1 | null> {
    const minimized = await this.chain.log(body);
    const runtime = this.#runtime;
    if (runtime === null) {
      return null;
    }
    return runtime.appendRecord({
      eventId: minimized.eventId,
      timestamp: minimized.timestamp,
      actor: minimized.actor,
      target: minimized.target,
      invocation: minimized.invocation,
      policy: minimized.policy,
      execution: minimized.execution,
      ...(minimized.error === undefined ? {} : { error: minimized.error }),
      ...(minimized.approval === undefined ? {} : { approval: minimized.approval }),
      ...(minimized.gateway === undefined ? {} : { gateway: minimized.gateway }),
      ...(lifecycle === undefined ? {} : { lifecycle }),
    });
  }
}
