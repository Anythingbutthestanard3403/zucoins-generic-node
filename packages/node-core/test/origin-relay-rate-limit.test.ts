/**
 * POST /v1/receivers/origin-relay request-volume throttle (ZTR-1216).
 *
 * Subject: packages/node-core/src/http/origin-relay-rate-limit.ts
 *
 * Properties pinned here:
 *   - over-rate callers are shed (`false`);
 *   - an under-rate caller is never shed, and one IP's flood never sheds another's;
 *   - a null peer shares one "unknown" bucket (no forgeable key).
 *
 * The HTTP non-oracular 204 answer is pinned in apps/generic-node/test/runtime-listener.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ORIGIN_RELAY_RATE_MAX_REQUESTS,
  ORIGIN_RELAY_RATE_WINDOW_MS,
  _resetOriginRelayRateLimitForTests,
  consumeOriginRelayAttempt,
} from "../src/http/index.js";

const IP_A = "203.0.113.50";
const IP_B = "203.0.113.51";

function spend(ip: string | null, units: number = ORIGIN_RELAY_RATE_MAX_REQUESTS): void {
  for (let i = 0; i < units; i += 1) {
    expect(consumeOriginRelayAttempt(ip)).toBe(true);
  }
}

describe("origin-relay volume throttle — per source IP (ZTR-1216)", () => {
  beforeEach(() => {
    _resetOriginRelayRateLimitForTests();
    vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    _resetOriginRelayRateLimitForTests();
  });

  it("admits the last request inside the budget and sheds the next", () => {
    spend(IP_A, ORIGIN_RELAY_RATE_MAX_REQUESTS - 1);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(true);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(false);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(false);
  });

  it("isolates budgets across source addresses", () => {
    spend(IP_A);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(false);
    expect(consumeOriginRelayAttempt(IP_B)).toBe(true);
  });

  it("resets at the next fixed window", () => {
    spend(IP_A);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(false);
    vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000 + ORIGIN_RELAY_RATE_WINDOW_MS);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(true);
  });

  it("null peers share one unknown bucket", () => {
    spend(null);
    expect(consumeOriginRelayAttempt(null)).toBe(false);
    expect(consumeOriginRelayAttempt(IP_A)).toBe(true);
  });
});
