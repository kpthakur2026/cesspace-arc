/**
 * RC-04 Restricted Path Glob Matcher
 *
 * Implements the frozen RC-04 v1 path glob grammar (rc04-scope-acceptance.md §9.1).
 *
 * Design constraints:
 * - Matching is purely in-memory: no filesystem access, no stat syscalls, no
 *   directory traversal.
 * - No delegation to an unrestricted glob/regex package, and no compilation of
 *   untrusted patterns into raw regular expressions. Segment matching uses a
 *   bounded dynamic program over literal characters, which cannot backtrack.
 * - Every rejection is deterministic and fail-closed: unsupported syntax is
 *   rejected at policy load time rather than silently reinterpreted.
 */

/**
 * Maximum length of a single path pattern or glob string (rc04 §8.2).
 */
export const MAX_PATTERN_LENGTH = 1024;

/**
 * Maximum length of a target path accepted by the matcher.
 *
 * Resource bound only. Together with MAX_PATTERN_LENGTH this caps total matcher
 * work at approximately |pattern| x |target| character comparisons.
 */
export const MAX_TARGET_PATH_LENGTH = 4096;

/**
 * Deterministic machine-readable reason codes for pattern rejection.
 * Coarse categories only: they describe the operator's own document shape and
 * never include pattern text.
 */
export type PathPatternInvalidReason =
  | 'NOT_A_STRING'
  | 'EMPTY_PATTERN'
  | 'PATTERN_TOO_LONG'
  | 'NUL_BYTE'
  | 'BACKSLASH_FORBIDDEN'
  | 'LEADING_SLASH'
  | 'EMPTY_SEGMENT'
  | 'TRAVERSAL_SEGMENT'
  | 'DOT_SEGMENT'
  | 'EMBEDDED_DOUBLE_STAR'
  | 'UNSUPPORTED_SYNTAX';

/**
 * Characters that introduce unsupported glob/regex syntax in RC-04 v1:
 * - `[` `]` character sets/ranges
 * - `{` `}` brace expansion
 * - `(` `)` extglob ( `@( )`, `!( )`, `+( )`, `?( )` ) and regex groups
 *
 * The exclamation mark `!` alone carries NO negation semantics and is treated
 * as an ordinary literal character (rc04 §9.1.6).
 */
const UNSUPPORTED_SYNTAX_CHARS = new Set(['[', ']', '{', '}', '(', ')']);

/**
 * Validates a single path pattern against the frozen RC-04 v1 grammar.
 * Returns null when the pattern is valid, otherwise a reason code.
 */
export function validatePathPattern(pattern: unknown): PathPatternInvalidReason | null {
  if (typeof pattern !== 'string') {
    return 'NOT_A_STRING';
  }
  if (pattern.length === 0) {
    return 'EMPTY_PATTERN';
  }
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return 'PATTERN_TOO_LONG';
  }
  if (pattern.includes('\u0000')) {
    return 'NUL_BYTE';
  }
  if (pattern.includes('\\')) {
    return 'BACKSLASH_FORBIDDEN';
  }
  if (pattern.startsWith('/')) {
    return 'LEADING_SLASH';
  }

  const segments = pattern.split('/');
  for (const segment of segments) {
    if (segment.length === 0) {
      return 'EMPTY_SEGMENT';
    }
    if (segment === '..') {
      return 'TRAVERSAL_SEGMENT';
    }
    if (segment === '.') {
      return 'DOT_SEGMENT';
    }
    if (segment !== '**' && segment.includes('**')) {
      // `**` is legal ONLY as a complete path segment (rc04 §9.1.4).
      return 'EMBEDDED_DOUBLE_STAR';
    }
    for (const ch of segment) {
      if (UNSUPPORTED_SYNTAX_CHARS.has(ch)) {
        return 'UNSUPPORTED_SYNTAX';
      }
    }
  }

  return null;
}

/**
 * Normalizes a target path for matching.
 *
 * Returns null when the path is not already in safe, normalized,
 * workspace-relative form. The matcher never reinterprets an unsafe host path
 * into an authorized relative path (rc04 §9.1.3 and Task 2 §24).
 */
export function normalizeTargetPath(targetPath: unknown): string | null {
  if (typeof targetPath !== 'string') {
    return null;
  }
  if (targetPath.length === 0 || targetPath.length > MAX_TARGET_PATH_LENGTH) {
    return null;
  }
  if (targetPath.includes('\u0000')) {
    return null;
  }
  if (targetPath.includes('\\')) {
    return null;
  }
  if (targetPath.startsWith('/')) {
    return null;
  }

  const segments = targetPath.split('/');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      return null;
    }
  }

  return targetPath;
}

/**
 * Segments a validated path pattern. Throws on invalid patterns.
 */
export function compilePathPattern(pattern: string): string[] {
  const reason = validatePathPattern(pattern);
  if (reason !== null) {
    throw new Error(`Invalid RC-04 path pattern: ${reason}`);
  }
  return pattern.split('/');
}

/**
 * Bounded dynamic program matching a single path segment.
 *
 * `*` matches zero or more characters, `?` matches exactly one character.
 * The `/` separator can never appear here because callers match pre-split
 * segments, which is what guarantees `*` cannot cross a path separator.
 *
 * Work is bounded by pattern.length x text.length. There is no backtracking.
 */
export function matchSegment(pattern: string, text: string): boolean {
  const patternLength = pattern.length;
  const textLength = text.length;

  // Two rolling rows are allocated once and swapped, so allocation is constant
  // per call rather than one row per pattern character.
  let previous = new Array<boolean>(textLength + 1).fill(false);
  let current = new Array<boolean>(textLength + 1).fill(false);
  previous[0] = true;

  for (let i = 1; i <= patternLength; i++) {
    const patternChar = pattern[i - 1];

    if (patternChar === '*') {
      current[0] = previous[0];
      for (let j = 1; j <= textLength; j++) {
        current[j] = previous[j] || current[j - 1];
      }
    } else if (patternChar === '?') {
      current[0] = false;
      for (let j = 1; j <= textLength; j++) {
        current[j] = previous[j - 1];
      }
    } else {
      current[0] = false;
      for (let j = 1; j <= textLength; j++) {
        current[j] = previous[j - 1] && text[j - 1] === patternChar;
      }
    }

    const swap = previous;
    previous = current;
    current = swap;
  }

  return previous[textLength];
}

/**
 * Matches pre-compiled pattern segments against a normalized target path.
 *
 * `**` matches zero or more COMPLETE path segments (rc04 §9.1.4).
 */
export function matchCompiledPattern(
  patternSegments: readonly string[],
  normalizedTargetPath: string,
): boolean {
  const targetSegments = normalizedTargetPath.split('/');
  const patternCount = patternSegments.length;
  const targetCount = targetSegments.length;

  let hasDoubleStar = false;
  for (let i = 0; i < patternCount; i++) {
    if (patternSegments[i] === '**') {
      hasDoubleStar = true;
      break;
    }
  }

  // Fast path: without `**` the segments correspond one-to-one, so no
  // dynamic program is needed at all.
  if (!hasDoubleStar) {
    if (patternCount !== targetCount) {
      return false;
    }
    for (let i = 0; i < patternCount; i++) {
      if (!matchSegment(patternSegments[i], targetSegments[i])) {
        return false;
      }
    }
    return true;
  }

  // next[j] === true when patternSegments[i+1..] matches targetSegments[j..]
  // Only two rolling rows are retained; the previous implementation allocated
  // a full (pattern x target) matrix on every call.
  let next = new Array<boolean>(targetCount + 1).fill(false);
  let current = new Array<boolean>(targetCount + 1).fill(false);
  next[targetCount] = true;

  for (let i = patternCount - 1; i >= 0; i--) {
    const patternSegment = patternSegments[i];
    if (patternSegment === '**') {
      // Zero segments (`next[j]`), or consume one and stay on `**`.
      current[targetCount] = next[targetCount];
      for (let j = targetCount - 1; j >= 0; j--) {
        current[j] = next[j] || current[j + 1];
      }
    } else {
      // An ordinary segment always consumes exactly one target segment, so
      // current[targetCount] stays false.
      current[targetCount] = false;
      for (let j = targetCount - 1; j >= 0; j--) {
        current[j] = matchSegment(patternSegment, targetSegments[j]) && next[j + 1];
      }
    }
    const swap = next;
    next = current;
    current = swap;
  }

  return next[0];
}

/**
 * Convenience entry point: validates and matches in one step.
 *
 * Returns false (fail-closed) when either the pattern or the target path is not
 * valid under the RC-04 v1 grammar. Evaluation paths that need peak performance
 * should pre-compile with compilePathPattern() instead.
 */
export function matchPathGlob(pattern: string, targetPath: string): boolean {
  const reason = validatePathPattern(pattern);
  if (reason !== null) {
    return false;
  }
  const normalizedTarget = normalizeTargetPath(targetPath);
  if (normalizedTarget === null) {
    return false;
  }
  return matchCompiledPattern(compilePathPattern(pattern), normalizedTarget);
}
