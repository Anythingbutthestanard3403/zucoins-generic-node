import { describe, it, expect } from "vitest";
import { planScaleUp, SCALE_UP_ADVISORY_LOCK_NAMESPACE, CAP_COUNT_UNDER_LOCK_SQL } from "./scaling.js";

describe("planScaleUp — hard-cap and bounded batch", () => {
  it("mints only up to remaining cap headroom", () => {
    expect(planScaleUp({ openSessions: 50, capCountUnderLock: 48, poolCap: 50 })).toBe(2);
  });
  it("mints nothing at cap (hard-cap check, fail-closed)", () => {
    expect(planScaleUp({ openSessions: 50, capCountUnderLock: 50, poolCap: 50 })).toBe(0);
  });
});

describe("scale-up serialization — re-read count under the advisory lock (the frozen rule CAS)", () => {
  it("SERIALIZED scalers never exceed cap", () => {
    const poolCap = 50;
    const openSessions = 50; // target clamps to 50
    let capCount = 48;
    const a = planScaleUp({ openSessions, capCountUnderLock: capCount, poolCap });
    capCount += a; // A committed under the lock
    const b = planScaleUp({ openSessions, capCountUnderLock: capCount, poolCap }); // B re-reads
    capCount += b;
    expect(a).toBe(2);
    expect(b).toBe(0);
    expect(capCount).toBe(50);
    expect(capCount).toBeLessThanOrEqual(poolCap);
  });
  it("NAIVE scalers on a stale count would double-mint past cap — NEGATIVE (why the lock exists)", () => {
    const poolCap = 50;
    const openSessions = 50;
    const staleCount = 48;
    const a = planScaleUp({ openSessions, capCountUnderLock: staleCount, poolCap });
    const b = planScaleUp({ openSessions, capCountUnderLock: staleCount, poolCap }); // both see stale 48
    const finalCount = staleCount + a + b;
    expect(finalCount).toBe(52);
    expect(finalCount).toBeGreaterThan(poolCap);
  });
});

describe("scale-up — frozen data", () => {
  it("freezes the advisory-lock namespace and the count-under-lock SQL", () => {
    expect(SCALE_UP_ADVISORY_LOCK_NAMESPACE).toBe("pool_scale_up");
    expect(CAP_COUNT_UNDER_LOCK_SQL).toBe("SELECT count(*) AS cap_count FROM wallets");
  });
});
