/**
 * RC-06 rotated-segment filename schema (Task 3).
 *
 * Canonical form, exactly as frozen in the RC-06 architecture:
 *
 *   audit-<YYYYMMDDTHHMMSSZ>-seq<sequenceStart>-seq<sequenceEnd>.jsonl
 *   audit-<YYYYMMDDTHHMMSSZ>-seq<sequenceStart>-seq<sequenceEnd>.jsonl.gz
 *
 * Properties this module enforces:
 *
 *  - UTC only. No local time, no timezone offset suffix, no sub-second field.
 *  - `:` is never permitted in a rotated segment filename, so the name is safe
 *    on every supported filesystem.
 *  - Exactly ONE canonical spelling per sequence range. Leading zeros are
 *    rejected (`seq007` is not a valid spelling of `seq7`), so two names can
 *    never describe the same range while comparing unequal.
 *  - The sequence range is the authoritative ordering and identity key. The
 *    timestamp is operational metadata only: it is never used to order, to
 *    resolve duplicates, to detect overlaps, or to decide authority.
 *
 * This module deliberately has no imports. Both `storage.ts` (defensive
 * validation of a rotation target name) and `rotation.ts` (inventory and
 * enumeration) depend on it, and keeping it leaf-level avoids an import cycle.
 */

/** Prefix shared by every rotated segment filename. */
export const ROTATED_SEGMENT_PREFIX = 'audit-';

/** Suffix of an uncompressed rotated segment. */
export const ROTATED_SEGMENT_PLAIN_SUFFIX = '.jsonl';

/** Suffix of a compressed rotated segment. */
export const ROTATED_SEGMENT_COMPRESSED_SUFFIX = '.jsonl.gz';

/**
 * Strict rotated-segment filename schema.
 *
 * Capture groups: year, month, day, hour, minute, second, sequenceStart,
 * sequenceEnd, and the optional `.gz` marker.
 */
export const ROTATED_SEGMENT_REGEX =
  /^audit-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z-seq(0|[1-9]\d*)-seq(0|[1-9]\d*)\.jsonl(\.gz)?$/;

/** Largest sequence number representable without loss of integer precision. */
export const MAX_SEQUENCE_NUMBER = Number.MAX_SAFE_INTEGER;

/** A successfully parsed rotated-segment filename. */
export interface ParsedRotatedSegmentFilename {
  /** The original filename, exactly as it appeared on disk. */
  filename: string;
  /** The canonical UTC rotation timestamp component: `YYYYMMDDTHHMMSSZ`. */
  rotationTimestamp: string;
  /** First global sequence number contained in the segment (inclusive). */
  sequenceStart: number;
  /** Last global sequence number contained in the segment (inclusive). */
  sequenceEnd: number;
  /** True for `.jsonl.gz`, false for plain `.jsonl`. */
  compressed: boolean;
}

const DAYS_PER_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function isValidUtcCalendar(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
): boolean {
  if (month < 1 || month > 12) return false;
  // No leap-second representation exists in the canonical schema.
  if (hour > 23 || minute > 59 || second > 59) return false;

  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_PER_MONTH[month - 1];
  return day >= 1 && day <= maxDay;
}

/**
 * Renders a canonical UTC rotation timestamp component from a `Date`.
 *
 * Always UTC, never local time, and never carrying a sub-second field, so the
 * component round-trips through {@link parseRotatedSegmentFilename} exactly.
 */
export function formatRotationTimestamp(instant: Date): string {
  const year = instant.getUTCFullYear().toString().padStart(4, '0');
  const month = (instant.getUTCMonth() + 1).toString().padStart(2, '0');
  const day = instant.getUTCDate().toString().padStart(2, '0');
  const hour = instant.getUTCHours().toString().padStart(2, '0');
  const minute = instant.getUTCMinutes().toString().padStart(2, '0');
  const second = instant.getUTCSeconds().toString().padStart(2, '0');
  return `${year}${month}${day}T${hour}${minute}${second}Z`;
}

/**
 * Strictly parses a rotated-segment filename.
 *
 * Returns `null` when the name is not a canonical rotated segment. A `null`
 * result is NOT a license to ignore the entry: the caller decides whether an
 * unparseable entry is an auxiliary store file (the lock and metadata files)
 * or an unrecognized entry that must fail closed.
 */
export function parseRotatedSegmentFilename(filename: string): ParsedRotatedSegmentFilename | null {
  if (typeof filename !== 'string') return null;

  const match = ROTATED_SEGMENT_REGEX.exec(filename);
  if (match === null) return null;

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, startText, endText, gz] =
    match;

  if (
    !isValidUtcCalendar(
      Number(yearText),
      Number(monthText),
      Number(dayText),
      Number(hourText),
      Number(minuteText),
      Number(secondText),
    )
  ) {
    return null;
  }

  const sequenceStart = Number(startText);
  const sequenceEnd = Number(endText);

  // `>= 1` because virtual genesis is never a retained record: the first
  // retained record of the store is sequence 1 (rc06 §24).
  if (!Number.isSafeInteger(sequenceStart) || sequenceStart < 1) return null;
  if (!Number.isSafeInteger(sequenceEnd) || sequenceEnd < 1) return null;
  if (sequenceEnd < sequenceStart) return null;

  return {
    filename,
    rotationTimestamp: `${yearText}${monthText}${dayText}T${hourText}${minuteText}${secondText}Z`,
    sequenceStart,
    sequenceEnd,
    compressed: gz === '.gz',
  };
}

/** Convenience predicate over {@link parseRotatedSegmentFilename}. */
export function isValidRotatedSegmentFilename(filename: string): boolean {
  return parseRotatedSegmentFilename(filename) !== null;
}

/**
 * Renders the canonical filename for a rotated segment.
 *
 * The caller supplies the timestamp component already formatted (see
 * {@link formatRotationTimestamp}) so that name construction is a pure,
 * deterministic function of its inputs.
 */
export function formatRotatedSegmentFilename(parts: {
  rotationTimestamp: string;
  sequenceStart: number;
  sequenceEnd: number;
  compressed: boolean;
}): string {
  const { rotationTimestamp, sequenceStart, sequenceEnd, compressed } = parts;
  const suffix = compressed ? ROTATED_SEGMENT_COMPRESSED_SUFFIX : ROTATED_SEGMENT_PLAIN_SUFFIX;
  return `${ROTATED_SEGMENT_PREFIX}${rotationTimestamp}-seq${sequenceStart}-seq${sequenceEnd}${suffix}`;
}
