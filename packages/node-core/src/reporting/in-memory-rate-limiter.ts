// InMemoryReportingRateLimiter, the single-process fixed-window
// reference limiter for the bounded_rate pre-burn check, keyed on (nodeId, presented key
// id). Split out of in-memory-store.ts for the file-size budget — no logic change. The
// window and ceiling are runtime configuration (the contract fixes the check's pre-burn
// position, not a numeric policy). Reference-adapter scope: buckets are never evicted (the
// unknown-key rejection is the actual pre-registration bound); the durable/ops slice owns
// eviction and any node-global ceiling.: a principal-varying flood (distinct
// key ids, never reused) grows this map unboundedly; MAX_TRACKED_PRINCIPALS caps the heap by
// clearing the whole map once the cap is hit. Clearing, not denying: a clear can only ever
// widen admission for a moment, never falsely reject a legitimate principal, so it cannot
// become a denial-of-service vector against real traffic. The durable leg
// (SqlReportingRateLimiter) is unaffected by this clear and remains the cross-instance
// authority for every registered principal.

import type { ReportingRateLimiter } from "./store.js";

const joinKey = (...parts: readonly string[]): string => parts.join(":");

const MAX_TRACKED_PRINCIPALS = 100_000;

export class InMemoryReportingRateLimiter implements ReportingRateLimiter {
  private readonly buckets = new Map<string, { readonly windowStart: number; count: number }>();

  constructor(
    private readonly windowMs: number,
    private readonly maxRequests: number,
  ) {}

  consume(nodeId: string, principal: string, atMs: number): boolean {
    const key = joinKey(nodeId, principal);
    const windowStart = Math.floor(atMs / this.windowMs) * this.windowMs;
    const bucket = this.buckets.get(key);
    if (bucket === undefined || bucket.windowStart !== windowStart) {
      if (bucket === undefined && this.buckets.size >= MAX_TRACKED_PRINCIPALS) {
        this.buckets.clear();
      }
      this.buckets.set(key, { windowStart, count: 1 });
      return true;
    }
    bucket.count += 1;
    return bucket.count <= this.maxRequests;
  }
}
