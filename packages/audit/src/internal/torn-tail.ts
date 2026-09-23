/**
 * The single definition of a recoverable torn tail (RC-06 Task 2 / Task 3).
 *
 * Task 2 recovers a torn tail from the live active segment; Task 3 must accept
 * exactly the same trailing byte runs while verifying the retained history. Two
 * separate implementations of "what counts as a torn tail" would inevitably
 * drift, and the direction of drift is dangerous both ways: too strict and a
 * legitimate crash is reported as corruption, too lax and corruption is
 * silently accepted as a crash artifact.
 *
 * Both call sites therefore route the *decision* through
 * {@link classifyTrailingBytes}, and the rule lives here once. Each caller keeps
 * its own wording for the resulting error, because the two surfaces report to
 * different operators, but neither caller may re-decide the question.
 *
 * The rule, stated explicitly because the negative case is the one that is easy
 * to get wrong:
 *
 *  - A trailing byte run is a recoverable torn tail when torn tails are
 *    permitted for that artifact and the run is at most
 *    {@link MAX_TORN_TAIL_BYTES} long.
 *  - Decodability is NOT part of the rule. A trailing fragment is a torn tail
 *    whether it fails strict UTF-8, whether it is an incomplete JSON prefix such
 *    as `{"schemaVersion":1,"eventId":`, or whether it happens to be a complete
 *    syntactically valid record that merely lost its terminating newline.
 *    Whether the bytes happen to decode says nothing about whether the write
 *    completed, so it must not be allowed to decide the classification.
 *  - A finalized rotated segment never carries a torn tail: it was sealed and
 *    archived only at a complete, verified record boundary, so a truncated tail
 *    there is corruption rather than a crash artifact.
 *
 * This module deliberately has no imports, so both `recovery.ts` and
 * `rotation.ts` can depend on it without creating a cycle.
 *
 * @internal
 */

/** Largest trailing byte run that may be recovered as a torn tail. */
export const MAX_TORN_TAIL_BYTES = 65536;

/** Why a trailing byte run is not recoverable. */
export type TrailingBytesRejection = 'TORN_TAIL_NOT_PERMITTED' | 'TORN_TAIL_TOO_LARGE';

/** The verdict for a trailing byte run. */
export type TrailingBytesClassification =
  | { readonly recoverable: true; readonly tornBytes: Buffer }
  | { readonly recoverable: false; readonly rejection: TrailingBytesRejection };

/**
 * Classifies the trailing bytes of a primary segment.
 *
 * `bytes` is either an unterminated final fragment (no trailing LF) or a
 * newline-terminated line that failed to parse as a record. Both reach this
 * function for the same decision, because Task 2 treats them identically once
 * nothing follows them in the stream.
 */
export function classifyTrailingBytes(
  bytes: Buffer,
  options: { allowTornTail: boolean },
): TrailingBytesClassification {
  if (!options.allowTornTail) {
    return { recoverable: false, rejection: 'TORN_TAIL_NOT_PERMITTED' };
  }
  if (bytes.length > MAX_TORN_TAIL_BYTES) {
    return { recoverable: false, rejection: 'TORN_TAIL_TOO_LARGE' };
  }
  return { recoverable: true, tornBytes: Buffer.from(bytes) };
}
