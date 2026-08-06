// SEND_EXTERNAL T2 redemption-expiry derivation.
//
// Field 13; SEND_EXTERNAL expiry single-source.
//
// T2 is materialized exactly once at sign-intent formation as
// `floor(node_clock_ms / 1000) + SEND_REDEMPTION_WINDOW_SECS`, an integer-SECONDS
// decimal string. It is frozen inside `inner_preimage_text` and never recomputed on
// redelivery or recovery. T1 (approval-challenge freshness) plays no part.

import { rfc3339FromUnixSecsText, unixSecsTextFromClockMs } from "./unix-secs.js";

/** Step 6: fixed 300s redemption window, anchored to formation clock. */
export const SEND_REDEMPTION_WINDOW_SECS = 300 as const;

/**
 * Derive the signed `inner.expiry__unix_time_secs` at formation.
 *
 * Returns an integer-SECONDS string (never ms, never a JS number). Call exactly once
 * at sign-intent formation; persist the result inside the preimage and never recompute.
 */
export function deriveSendRedemptionExpiryUnixSecs(nodeClockMs: number): string {
  return unixSecsTextFromClockMs(
    "deriveSendRedemptionExpiryUnixSecs",
    nodeClockMs,
    SEND_REDEMPTION_WINDOW_SECS,
  );
}

/**
 * Whole-second RFC3339 projection of a T2 integer-seconds string for
 * `external_send_sign_intents.redemption_expiry_at`. Non-authoritative —
 * the signed inner expiry is the single source.
 */
export function redemptionExpiryAtFromSecs(expiryUnixSecs: string): string {
  return rfc3339FromUnixSecsText("redemptionExpiryAtFromSecs", expiryUnixSecs);
}
