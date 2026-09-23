/**
 * The coded-error primitive, in a module that imports nothing (RC-06).
 *
 * `createCodedError` is used by every layer of the audit package, including
 * leaf modules that must not import `storage.ts`. Keeping the definition here —
 * rather than in `storage.ts`, which is the largest and most-depended-on module
 * in the package — lets those leaf modules share one error constructor instead
 * of each carrying a private copy that can drift from this one.
 *
 * `storage.ts` re-exports both names, so the public surface of
 * `@cesspace-arc/audit` is unchanged and existing importers need no edit.
 *
 * @internal
 */

/** An `Error` carrying a stable machine-readable `code`. */
export interface CodedError extends Error {
  code?: string;
}

/**
 * Builds an `Error` whose `message` is prefixed with its `code`.
 *
 * The prefix is deliberate: audit errors are surfaced to operators reading
 * logs, and the code must be legible even when only the message is copied.
 */
export function createCodedError(
  code: string,
  message: string,
  options?: { cause?: unknown },
): CodedError {
  const err = new Error(`${code}: ${message}`, options) as CodedError;
  err.code = code;
  return err;
}
