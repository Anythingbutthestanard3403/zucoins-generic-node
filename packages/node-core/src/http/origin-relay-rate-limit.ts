// Per-source-IP request-volume throttle for POST /v1/receivers/origin-relay (ZTR-1216).
//
// The origin-relay route is anonymous by design (no credential to check). ZTR-1188
// bounded memory via a per-lane inbox cap; this limiter bounds REQUEST VOLUME from
// one source address so a flood cannot burn decode/CPU budget at the cap cliff.
//
// Non-oracular: a shed request still answers 204 with the same empty body as every
// other deposit outcome. The throttle reason is counted only on the metrics scrape
// (`gn_candidate_intake_refused_total{reason="rate_limited"}`); nothing on the wire
// distinguishes throttle from malformed, full, or accepted.
//
// Mechanism is the node's one general-purpose limiter (InMemoryReportingRateLimiter,
// fixed window) — same shape as login-rate-limit.ts — so "am I throttled" has exactly
// one answer everywhere.
//
// Ceiling: in-memory per process. An N-replica deployment gives a caller N× the budget
// before any window sheds. Keyed on the socket peer alone (never X-Forwarded-For): the
// route is fire-and-forget and must not let a client rotate the throttle key.

import { InMemoryReportingRateLimiter } from "../reporting/in-memory-rate-limiter.js";

export const ORIGIN_RELAY_RATE_WINDOW_MS = 60_000;

// 120 deposits/minute/IP. A legitimate origin (one payer hop, occasional retry) sits
// far inside this. A spray that would otherwise thrash decode+inbox at the cap is
// cut ~10× before the cap is even the binding constraint.
export const ORIGIN_RELAY_RATE_MAX_REQUESTS = 120;

// The limiter's first key dimension namespaces buckets across nodes; this instance
// serves exactly one node's origin-relay surface, so a fixed literal carries the
// same information a node id would.
const ORIGIN_RELAY_BUCKET_NAMESPACE = "origin-relay";

let limiter = new InMemoryReportingRateLimiter(
  ORIGIN_RELAY_RATE_WINDOW_MS,
  ORIGIN_RELAY_RATE_MAX_REQUESTS,
);

/**
 * Records one origin-relay deposit against its source address and reports whether
 * it is within budget. `false` means shed (still answer 204). A null address (no
 * socket peer) shares one bucket, matching login-rate-limit.ts's `"unknown"` convention.
 */
export function consumeOriginRelayAttempt(ip: string | null, atMs: number = Date.now()): boolean {
  return limiter.consume(ORIGIN_RELAY_BUCKET_NAMESPACE, ip ?? "unknown", atMs);
}

/** Test helper — forget all per-IP origin-relay windows. Not for production call sites. */
export function _resetOriginRelayRateLimitForTests(): void {
  limiter = new InMemoryReportingRateLimiter(
    ORIGIN_RELAY_RATE_WINDOW_MS,
    ORIGIN_RELAY_RATE_MAX_REQUESTS,
  );
}
