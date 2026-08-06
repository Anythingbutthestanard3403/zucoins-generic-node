// RECEIVE_EXTERNAL payer-code TTL policy: bounds, clamping, and
// absolute-expiry derivation.
//
// `expires_in_seconds` is optional and node-clamped to the configured minimum/maximum;
// the clamped result is persisted as `operations.expiry_unix_time_secs` and on `receive_codes`.
// Canonical: receive TTL policy (this policy), pre-formed sender transfer code (SplitChain future-time ceiling)
// (integer-SECONDS string), destination binding (freeze at formation).
//
// This module is pure policy arithmetic and holds no configuration of its own: the
// node shell supplies the bounds from RECEIVE_TTL_DEFAULT_SECS / _MIN_SECS / _MAX_SECS,
// which are frozen at boot so a formed code's expiry is always derived under the same
// policy that formed it. The derived string is byte-frozen into the signed transfer
// code — it is never re-derived, re-rendered, or reformatted afterwards (the byte-exact signing rule).

import { unixSecsTextFromClockMs } from "./unix-secs.js";

/**
 * a transfer code's `expiry__unix_time_secs` may sit at most this far ahead of
 * block time. A configured maximum above it forms codes the live gateway rejects, so
 * this is an invariant on the policy, not a policy choice.
 */
export const SPLITCHAIN_FUTURE_TIME_CEILING_SECS = 59_999_880;

export interface ReceiveTtlBounds {
  /** TTL applied when the request omits `expires_in_seconds`. */
  readonly defaultSecs: number;
  readonly minSecs: number;
  readonly maxSecs: number;
}

/**
 * Boot-time validation of the configured policy. Called by `clampReceiveTtlSecs` on
 * every use so a policy that was never validated at boot cannot silently clamp to a
 * nonsensical window.
 */
export function assertReceiveTtlBounds(bounds: ReceiveTtlBounds): void {
  for (const field of ["minSecs", "defaultSecs", "maxSecs"] as const) {
    const value = bounds[field];
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(
        `receive TTL ${field} must be a positive safe integer number of seconds`,
      );
    }
  }
  if (bounds.minSecs > bounds.defaultSecs || bounds.defaultSecs > bounds.maxSecs) {
    throw new RangeError("receive TTL bounds must satisfy minSecs <= defaultSecs <= maxSecs");
  }
  if (bounds.maxSecs > SPLITCHAIN_FUTURE_TIME_CEILING_SECS) {
    throw new RangeError(
      `receive TTL maxSecs must not exceed the SplitChain future-time ceiling of ${SPLITCHAIN_FUTURE_TIME_CEILING_SECS} seconds`,
    );
  }
}

/**
 * Clamp — never reject — a request-supplied TTL into the configured window. An absent
 * `expires_in_seconds` takes the configured default.
 *
 * This sits DOWNSTREAM of the request-boundary shape guard and does not weaken it: a
 * value that is not a positive safe integer never had a defensible clamp target, so it
 * throws rather than being coerced into one.
 */
export function clampReceiveTtlSecs(
  requestedSecs: number | undefined,
  bounds: ReceiveTtlBounds,
): number {
  assertReceiveTtlBounds(bounds);
  if (requestedSecs === undefined) return bounds.defaultSecs;
  if (!Number.isSafeInteger(requestedSecs) || requestedSecs < 1) {
    throw new RangeError("expires_in_seconds must be a positive safe integer number of seconds");
  }
  return Math.min(Math.max(requestedSecs, bounds.minSecs), bounds.maxSecs);
}

/**
 * Derive the absolute `expiry_unix_time_secs` at code formation from the clamped TTL.
 *
 * Called at formation, never at admission: a receive that queues waits
 * an unbounded time for a pool wallet, and pre-computing the expiry at admission would
 * hand the payer a code that is already part-expired, or dead, on arrival.
 *
 * Returns the fractional unix_time_secs string integer-SECONDS decimal string — the exact bytes persisted to
 * `operations.expiry_unix_time_secs` / `receive_codes.expiry_unix_time_secs` and signed
 * into the transfer code.
 */
export function deriveExpiryUnixTimeSecs(nowUnixMs: number, ttlSecs: number): string {
  if (!Number.isSafeInteger(ttlSecs) || ttlSecs < 1) {
    throw new RangeError(
      "deriveExpiryUnixTimeSecs: ttlSecs must be a positive safe integer number of seconds",
    );
  }
  return unixSecsTextFromClockMs("deriveExpiryUnixTimeSecs", nowUnixMs, ttlSecs);
}
