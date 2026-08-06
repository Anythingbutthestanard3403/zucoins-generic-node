// RECEIVE_EXTERNAL payer-code TTL policy: clamp arithmetic, boot-time bounds
// validation, and absolute-expiry derivation.
//
// Governing spec: the API contract (`expires_in_seconds` optional and node-clamped),
// operation flows (clamp at admission, derive at formation).
// Canonical: this policy, SplitChain future-time ceiling
// (integer-SECONDS string), freeze at formation.

import { describe, expect, it } from "vitest";

import { CreateReceiveBody } from "../src/api/index.js";
import {
  assertReceiveTtlBounds,
  clampReceiveTtlSecs,
  deriveExpiryUnixTimeSecs,
  SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
  type ReceiveTtlBounds,
} from "../src/protocol/index.js";

// The shipped defaults (apps/generic-node/src/config/constants.ts). Every clamp case below is
// stated against these, so a silent change to the shipped policy trips this file.
const BOUNDS: ReceiveTtlBounds = { defaultSecs: 300, minSecs: 60, maxSecs: 3600 };

describe("clampReceiveTtlSecs (clamp, never reject)", () => {
  it("takes the configured default when expires_in_seconds is absent", () => {
    expect(clampReceiveTtlSecs(undefined, BOUNDS)).toBe(300);
  });

  it("clamps UP to minSecs — the control under test", () => {
    // 1s and 59s are both below the 60s floor: a code formed at 1s expires before any human
    // payer could redeem it, which is exactly what the floor exists to prevent.
    expect(clampReceiveTtlSecs(1, BOUNDS)).toBe(60);
    expect(clampReceiveTtlSecs(59, BOUNDS)).toBe(60);
  });

  it("clamps DOWN to maxSecs — the control under test", () => {
    expect(clampReceiveTtlSecs(3601, BOUNDS)).toBe(3600);
    expect(clampReceiveTtlSecs(86_400, BOUNDS)).toBe(3600);
    // Right at the ceiling: still clamped, never rejected and never passed through.
    expect(clampReceiveTtlSecs(SPLITCHAIN_FUTURE_TIME_CEILING_SECS, BOUNDS)).toBe(3600);
  });

  it("passes an in-window TTL through unchanged, bounds inclusive", () => {
    expect(clampReceiveTtlSecs(60, BOUNDS)).toBe(60);
    expect(clampReceiveTtlSecs(600, BOUNDS)).toBe(600);
    expect(clampReceiveTtlSecs(3600, BOUNDS)).toBe(3600);
  });

  it("never returns a value outside the window for any input", () => {
    for (const requested of [1, 2, 59, 60, 61, 300, 3599, 3600, 3601, 100_000, 2 ** 40]) {
      const clamped = clampReceiveTtlSecs(requested, BOUNDS);
      expect(clamped, `requested=${requested}`).toBeGreaterThanOrEqual(BOUNDS.minSecs);
      expect(clamped, `requested=${requested}`).toBeLessThanOrEqual(BOUNDS.maxSecs);
    }
  });

  it("throws rather than coercing a value that has no defensible clamp target", () => {
    // Downstream of the request-boundary shape guard, which this does not weaken:
    // a non-positive or non-integer TTL is a shape failure, not an out-of-window TTL.
    for (const bad of [0, -1, -3600, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 60]) {
      expect(() => clampReceiveTtlSecs(bad, BOUNDS), `requested=${bad}`).toThrow(RangeError);
    }
  });
});

describe("assertReceiveTtlBounds (invariant, not policy)", () => {
  it("accepts the shipped policy", () => {
    expect(() => assertReceiveTtlBounds(BOUNDS)).not.toThrow();
  });

  it("refuses an unordered policy instead of silently reordering it", () => {
    expect(() => assertReceiveTtlBounds({ defaultSecs: 300, minSecs: 3600, maxSecs: 60 })).toThrow(
      /minSecs <= defaultSecs <= maxSecs/,
    );
    // Default outside the window: clamping every request to a window the operator never meant.
    expect(() => assertReceiveTtlBounds({ defaultSecs: 30, minSecs: 60, maxSecs: 3600 })).toThrow(
      /minSecs <= defaultSecs <= maxSecs/,
    );
    expect(() => assertReceiveTtlBounds({ defaultSecs: 7200, minSecs: 60, maxSecs: 3600 })).toThrow(
      /minSecs <= defaultSecs <= maxSecs/,
    );
  });

  it("refuses a maximum above the SplitChain future-time ceiling", () => {
    expect(() =>
      assertReceiveTtlBounds({
        defaultSecs: 300,
        minSecs: 60,
        maxSecs: SPLITCHAIN_FUTURE_TIME_CEILING_SECS + 1,
      }),
    ).toThrow(/future-time ceiling/);
    // Exactly at the ceiling is legal — the invariant is "not above", not "well below".
    expect(() =>
      assertReceiveTtlBounds({
        defaultSecs: 300,
        minSecs: 60,
        maxSecs: SPLITCHAIN_FUTURE_TIME_CEILING_SECS,
      }),
    ).not.toThrow();
  });

  it("refuses non-positive or non-integer bounds", () => {
    expect(() => assertReceiveTtlBounds({ defaultSecs: 300, minSecs: 0, maxSecs: 3600 })).toThrow(
      /minSecs/,
    );
    expect(() =>
      assertReceiveTtlBounds({ defaultSecs: 300.5, minSecs: 60, maxSecs: 3600 }),
    ).toThrow(/defaultSecs/);
  });

  it("is enforced on every clamp, not only at boot", () => {
    // A policy that was never validated at boot cannot silently clamp into a nonsensical window.
    expect(() =>
      clampReceiveTtlSecs(600, { defaultSecs: 300, minSecs: 3600, maxSecs: 60 }),
    ).toThrow(RangeError);
  });
});

describe("deriveExpiryUnixTimeSecs (absolute seconds string)", () => {
  // 2026-07-25T00:00:00Z.
  const NOW_MS = 1_784_937_600_000;
  const NOW_SECS = 1_784_937_600;

  it("returns now + ttl as an integer-SECONDS decimal string", () => {
    expect(deriveExpiryUnixTimeSecs(NOW_MS, 300)).toBe(String(NOW_SECS + 300));
    // A string, never a number — the exact bytes persisted and signed.
    expect(typeof deriveExpiryUnixTimeSecs(NOW_MS, 300)).toBe("string");
  });

  it("emits only the digits the data model column CHECK accepts", () => {
    for (const ttl of [60, 300, 3600, SPLITCHAIN_FUTURE_TIME_CEILING_SECS]) {
      expect(deriveExpiryUnixTimeSecs(NOW_MS, ttl)).toMatch(/^[0-9]+$/);
    }
  });

  it("floors sub-second wall time rather than emitting a fraction", () => {
    expect(deriveExpiryUnixTimeSecs(NOW_MS + 999, 60)).toBe(String(NOW_SECS + 60));
  });

  it("rejects a wall clock handed in SECONDS where MILLISECONDS are required", () => {
    // The column CHECK cannot catch this — both renderings are digits (confusion class).
    expect(() => deriveExpiryUnixTimeSecs(NOW_SECS, 300)).toThrow(/MILLISECONDS/);
  });

  it("rejects a non-positive or non-integer TTL", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => deriveExpiryUnixTimeSecs(NOW_MS, bad), `ttl=${bad}`).toThrow(RangeError);
    }
  });

  it("derives from the clamped TTL, so an out-of-window request cannot widen the window", () => {
    const expiry = deriveExpiryUnixTimeSecs(NOW_MS, clampReceiveTtlSecs(86_400, BOUNDS));
    expect(expiry).toBe(String(NOW_SECS + 3600));
  });
});

describe("request boundary carries no policy ceiling of its own", () => {
  const body = (expiresInSeconds: unknown) => ({
    amount_zkz: "1.5",
    anchor: "receive-ttl-anchor",
    expires_in_seconds: expiresInSeconds,
    after_landing: { kind: "HOLD", destination_id: null },
  });

  it("accepts an out-of-policy TTL at the boundary so the clamp can act on it", () => {
    // The former `.max(86400)` was an invented policy reject standing in front of the clamp.
    expect(CreateReceiveBody.safeParse(body(86_401)).success).toBe(true);
    expect(CreateReceiveBody.safeParse(body(SPLITCHAIN_FUTURE_TIME_CEILING_SECS)).success).toBe(
      true,
    );
  });

  it("still rejects what no policy could ever honour (the ceiling)", () => {
    expect(CreateReceiveBody.safeParse(body(SPLITCHAIN_FUTURE_TIME_CEILING_SECS + 1)).success).toBe(
      false,
    );
  });

  it("keeps the positive-safe-integer shape guard", () => {
    for (const bad of [0, -1, 1.5, "300", null]) {
      expect(CreateReceiveBody.safeParse(body(bad)).success, `expires_in_seconds=${bad}`).toBe(
        false,
      );
    }
  });

  it("leaves expires_in_seconds optional so the configured default applies", () => {
    const parsed = CreateReceiveBody.safeParse({
      amount_zkz: "1.5",
      anchor: "receive-ttl-anchor",
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.expires_in_seconds).toBeUndefined();
      expect(clampReceiveTtlSecs(parsed.data.expires_in_seconds, BOUNDS)).toBe(300);
    }
  });
});
