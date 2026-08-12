// Per-source-IP request-volume throttle for POST /v1/integration-requests.
// Copy of the login-rate-limit pattern (InMemoryReportingRateLimiter fixed window).
// Keyed on source IP alone — never username/body fields (non-oracular).

import { InMemoryReportingRateLimiter } from "../reporting/in-memory-rate-limiter.js";

export const INTEGRATION_REQUEST_RATE_WINDOW_MS = 60_000;

// 10 intakes/minute/IP. Platforms self-serve occasionally; a spray that would
// otherwise fill the PENDING table is cut before the global cap is the only gate.
export const INTEGRATION_REQUEST_RATE_MAX_REQUESTS = 10;

const BUCKET_NAMESPACE = "integration-request-intake";

let limiter = new InMemoryReportingRateLimiter(
  INTEGRATION_REQUEST_RATE_WINDOW_MS,
  INTEGRATION_REQUEST_RATE_MAX_REQUESTS,
);

export function consumeIntegrationRequestAttempt(
  ip: string | null,
  atMs: number = Date.now(),
): boolean {
  return limiter.consume(BUCKET_NAMESPACE, ip ?? "unknown", atMs);
}

/** Test helper — forget all per-IP intake windows. Not for production call sites. */
export function _resetIntegrationRequestRateLimitForTests(): void {
  limiter = new InMemoryReportingRateLimiter(
    INTEGRATION_REQUEST_RATE_WINDOW_MS,
    INTEGRATION_REQUEST_RATE_MAX_REQUESTS,
  );
}
