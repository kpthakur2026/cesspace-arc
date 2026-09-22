/**
 * Frozen bounds for manifest references and export budgets (RC-06 §24.1).
 *
 * Placed in an internal module so both `anchor.ts` and `export.ts` can consume
 * them without circular dependencies.
 *
 * @internal
 */

import { MAX_ARCHIVE_SEGMENTS, TOTAL_AUDIT_BUDGET_BYTES } from '../rotation.js';
import { CHECKPOINT_INTERVAL } from '../checkpoint.js';
import { createCodedError } from './errors.js';

/**
 * A conservative floor on the canonical size of one persistent audit record.
 *
 * A record carries a UUID, an ISO-8601 timestamp, four 64-character hex fields
 * (device id, session id, workspace root hash, payload hash), a second UUID and
 * a nested actor/target/invocation/policy/execution structure. Its canonical
 * JSON cannot approach this figure; the floor is deliberately far below the
 * ~950 bytes a real record occupies, so the derived bound below is an
 * over-estimate rather than an under-estimate.
 */
export const MIN_CANONICAL_RECORD_BYTES = 256;

/**
 * The finite maximum number of checkpoint references one manifest may carry.
 *
 * Derived from frozen limits, not chosen for convenience. A retained checkpoint
 * is mandatory at every rotation boundary — at most `MAX_ARCHIVE_SEGMENTS` —
 * and on the interval cadence, one per `CHECKPOINT_INTERVAL` records. The record
 * count is itself bounded by the frozen storage budget:
 *
 *   TOTAL_AUDIT_BUDGET_BYTES / MIN_CANONICAL_RECORD_BYTES / CHECKPOINT_INTERVAL
 *
 * plus the rotation boundaries. Worst-case manifest memory is therefore
 * MAX_MANIFEST_CHECKPOINT_REFS x (64 hex + JSON quoting and separator) — about
 * 285 KB, not something proportional to a 1 GiB history.
 */
export const MAX_MANIFEST_CHECKPOINT_REFS =
  MAX_ARCHIVE_SEGMENTS +
  Math.ceil(TOTAL_AUDIT_BUDGET_BYTES / MIN_CANONICAL_RECORD_BYTES / CHECKPOINT_INTERVAL);

/**
 * The finite maximum number of receipt references one manifest may carry.
 *
 * At most one receipt is consumed per checkpoint, so the checkpoint bound holds
 * here too. A receipt id is capped separately by the Task-5 receipt schema
 * (<= 256 UTF-8 bytes), so worst-case memory is likewise bounded.
 */
export const MAX_MANIFEST_RECEIPT_REFS = MAX_MANIFEST_CHECKPOINT_REFS;

/**
 * Refuses a manifest reference beyond the frozen bound.
 *
 * Called BEFORE a reference is accumulated, so memory cannot grow past the
 * documented maximum: the bound is enforced at the point of growth rather than
 * discovered after the fact.
 */
export function assertManifestReferenceWithinBound(
  count: number,
  bound: number,
  noun: string,
): void {
  if (count > bound) {
    throw createCodedError(
      'EXPORT_MANIFEST_LIMIT_EXCEEDED',
      `the manifest cannot reference more than ${bound} ${noun}`,
    );
  }
}
