// Per-source-IP request-volume throttle for POST /admin/v1/login — the complement
// to the per-(IP, username) failure lockout in ip-lockout.ts.
//
// The two controls are distinct and neither subsumes the other. The lockout bounds
// FAILED password attempts against ONE account, so it stops an attacker grinding a
// single operator. It is blind to a spray: 5 guesses each against 400 usernames
// never trips any pair. This limiter bounds REQUEST VOLUME from one source address
// regardless of outcome, which is the only shape that sees a spray.
//
// Keyed on the source IP ALONE. Adding the username to the key would make the 429 an
// account-existence oracle — a 429 that only fires for real usernames names them —
// and the auth surface is deliberately non-oracular.
//
// Mechanism is the node's one general-purpose limiter (InMemoryReportingRateLimiter,
// fixed window) rather than a second differently-shaped one, so "am I throttled" has
// exactly one answer everywhere.
//
// Ceiling: in-memory per process, exactly like ip-lockout.ts — an N-replica
// deployment gives a caller N x the budget before any window sheds. The upgrade path
// is the durable leg (SqlReportingRateLimiter), same as the reporting surface.
//
// Single production call site: apps/generic-node admin-router POST /admin/v1/login,
// BEFORE body decode (ZTR-1218). handleAdminLogin must not call consumeLoginAttempt
// again — that would be a second limiter hop on the well-formed path (ZTR-1201 AC5).

import { InMemoryReportingRateLimiter } from "../reporting/in-memory-rate-limiter.js";

export const LOGIN_RATE_WINDOW_MS = 60_000;

// 30 requests/minute/IP. A human operator signs in once or twice; a whole office
// behind one NAT address stays far inside this. Against bcrypt (~10 attempts/s
// achievable) it is a ~20x reduction in guess throughput, and it holds whether the
// attacker targets one username or four hundred.
export const LOGIN_RATE_MAX_REQUESTS = 30;

// The limiter's first key dimension namespaces buckets across nodes; this instance
// serves exactly one node's admin surface, so a fixed literal carries the same
// information a node id would.
const LOGIN_BUCKET_NAMESPACE = "admin-login";

let limiter = new InMemoryReportingRateLimiter(LOGIN_RATE_WINDOW_MS, LOGIN_RATE_MAX_REQUESTS);

/**
 * Records one login request against its source address and reports whether it is
 * within budget. `false` means shed. A null address (no socket peer) shares one
 * bucket, matching ip-lockout.ts's `"unknown"` convention.
 */
export function consumeLoginAttempt(ip: string | null, atMs: number = Date.now()): boolean {
  return limiter.consume(LOGIN_BUCKET_NAMESPACE, ip ?? "unknown", atMs);
}

/** Test helper — forget all per-IP login windows. Not for production call sites. */
export function _resetLoginRateLimitForTests(): void {
  limiter = new InMemoryReportingRateLimiter(LOGIN_RATE_WINDOW_MS, LOGIN_RATE_MAX_REQUESTS);
}
