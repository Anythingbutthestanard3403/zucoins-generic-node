// the one canonical Unix-time conversion for protocol formation code.
//
// (fractional unix_time_secs string integer-SECONDS decimal
// Text); step 6; exact partial only the byte-exact signing rule.
//
// Every conversion here is BigInt, mirroring the idiom the independently reviewed,
// AST-pinned transactions.ts already uses for the same quantity (`BigInt(integerPart) *
// 1000n`, `BigInt(text) * 1000n`). The formation sites this replaces each hand-rolled
// `Math.floor(clockMs / 1000)` and `String(secs + window)`: IEEE-754 division and numeric
// coercion applied to a value that is then frozen into a signing preimage. Routing all of
// them through one BigInt conversion is what keeps asserting zero rather than
// re-deriving float seconds in four places.

/**
 * 2020-09-13. A Unix timestamp in SECONDS mistakenly passed where MILLISECONDS are
 * expected truncates far below this — the shared plausibility floor.
 */
export const MIN_PLAUSIBLE_UNIX_SECS = 1_600_000_000n;

/**
 * Canonical fractional unix_time_secs string integer-SECONDS decimal text for a node clock in Unix MILLISECONDS,
 * optionally advanced by a whole-second window.
 *
 * `context` names the calling deriver so the thrown diagnostic stays as specific as the
 * hand-rolled guards it replaces. All arithmetic is BigInt: for the plausible range
 * enforced below the operand is positive, so BigInt's truncation toward zero is exactly
 * the floor the callers previously took with `Math.floor`.
 */
export function unixSecsTextFromClockMs(
  context: string,
  clockMs: number,
  plusSecs = 0,
): string {
  if (!Number.isSafeInteger(clockMs)) {
    throw new RangeError(
      `${context}: clock must be a safe-integer Unix timestamp in MILLISECONDS`,
    );
  }
  if (!Number.isSafeInteger(plusSecs) || plusSecs < 0) {
    throw new RangeError(`${context}: added seconds must be a non-negative safe integer`);
  }
  const secs = BigInt(clockMs) / 1000n;
  if (secs < MIN_PLAUSIBLE_UNIX_SECS) {
    throw new RangeError(`${context}: clock must be a Unix timestamp in MILLISECONDS`);
  }
  return (secs + BigInt(plusSecs)).toString();
}

function pad(value: bigint, width: number): string {
  return value.toString().padStart(width, "0");
}

/**
 * Civil date from a count of days since the Unix epoch — Howard Hinnant's `civil_from_days`,
 * carried out entirely in BigInt. Used instead of `new Date(secs * 1000)` so the projection
 * below needs no `Number` coercion of a protocol timestamp.
 */
function civilFromDays(days: bigint): {
  readonly year: bigint;
  readonly month: bigint;
  readonly day: bigint;
} {
  const shifted = days + 719_468n;
  const era = (shifted >= 0n ? shifted : shifted - 146_096n) / 146_097n;
  const dayOfEra = shifted - era * 146_097n;
  const yearOfEra =
    (dayOfEra - dayOfEra / 1460n + dayOfEra / 36_524n - dayOfEra / 146_096n) / 365n;
  const dayOfYear = dayOfEra - (365n * yearOfEra + yearOfEra / 4n - yearOfEra / 100n);
  const monthPrime = (5n * dayOfYear + 2n) / 153n;
  const day = dayOfYear - (153n * monthPrime + 2n) / 5n + 1n;
  const month = monthPrime + (monthPrime < 10n ? 3n : -9n);
  return { year: yearOfEra + era * 400n + (month <= 2n ? 1n : 0n), month, day };
}

/**
 * Whole-second RFC3339 (`YYYY-MM-DDTHH:MM:SS.000Z`) projection of a fractional unix_time_secs string integer-seconds
 * string, byte-identical to `new Date(secs * 1000).toISOString` over the representable
 * range — see the equivalence oracle in unix-secs.test.ts, which cross-checks this against
 * the platform `Date` so the hand-rolled calendar arithmetic cannot silently drift.
 *
 * Non-authoritative: only ever a display/index projection. The signed inner expiry is the
 * single source of truth.
 */
export function rfc3339FromUnixSecsText(context: string, unixSecs: string): string {
  if (!/^[0-9]+$/.test(unixSecs)) {
    throw new RangeError(`${context}: expected an integer-seconds decimal string`);
  }
  const secs = BigInt(unixSecs);
  const days = secs / 86_400n;
  const secondOfDay = secs - days * 86_400n;
  const { year, month, day } = civilFromDays(days);
  const date = `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}`;
  const time = `${pad(secondOfDay / 3600n, 2)}:${pad((secondOfDay / 60n) % 60n, 2)}:${pad(
    secondOfDay % 60n,
    2,
  )}`;
  return `${date}T${time}.000Z`;
}
