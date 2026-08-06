import { describe, it, expect } from "vitest";
import { computeProvisioningTarget, computeMintBatch } from "./sizing.js";
import { POOL_FLOOR, MINT_BATCH_LIMIT } from "./constants.js";

describe("computeProvisioningTarget — exact-integer proportional headroom (the receive-queue backpressure rule 1)", () => {
  it("clamps up to POOL_FLOOR at low load", () => {
    expect(computeProvisioningTarget(0, 50)).toBe(POOL_FLOOR);
    expect(computeProvisioningTarget(4, 50)).toBe(5);
  });
  it("computes ceil(open_sessions * 11 / 10) in range", () => {
    expect(computeProvisioningTarget(5, 50)).toBe(6); // ceil(5.5)
    expect(computeProvisioningTarget(6, 50)).toBe(7); // ceil(6.6)
    expect(computeProvisioningTarget(50, 500)).toBe(55);
    expect(computeProvisioningTarget(100, 500)).toBe(110);
    expect(computeProvisioningTarget(110, 500)).toBe(121);
    expect(computeProvisioningTarget(200, 500)).toBe(220);
  });
  it("clamps down to pool_cap", () => {
    expect(computeProvisioningTarget(50, 50)).toBe(50);
    expect(computeProvisioningTarget(55, 50)).toBe(50);
    expect(computeProvisioningTarget(500, 500)).toBe(500);
    expect(computeProvisioningTarget(600, 500)).toBe(500);
  });
});

describe("computeProvisioningTarget — the float form is rejected (NEGATIVE, the frozen rule)", () => {
  it("open_sessions * 1.10 over-mints by 1 at {50,100,110,200}; the exact integer form does not", () => {
    for (const openSessions of [50, 100, 110, 200]) {
      const exact = computeProvisioningTarget(openSessions, 500);
      const floatForm = Math.ceil(openSessions * 1.1);
      expect(exact).toBe(openSessions + openSessions / 10); // true proportional headroom
      expect(floatForm).toBe(exact + 1); // representation error mints one permanent key too many
      expect(exact).not.toBe(floatForm);
    }
  });
});

describe("computeMintBatch — bounded, fail-closed at cap (the receive-queue backpressure rule rules 2-4)", () => {
  it("mints the batch limit from an empty pool", () => {
    expect(computeMintBatch(55, 0, 500)).toBe(MINT_BATCH_LIMIT);
  });
  it("mints only the deficit when it is under the batch limit", () => {
    expect(computeMintBatch(55, 53, 500)).toBe(2);
  });
  it("mints nothing at or above target (RETIRED wallets inflate capCount, never restore capacity)", () => {
    expect(computeMintBatch(55, 55, 500)).toBe(0);
    expect(computeMintBatch(55, 60, 500)).toBe(0);
  });
  it("minting STOPS at cap even under pressure (fail-closed)", () => {
    expect(computeMintBatch(50, 50, 50)).toBe(0);
  });
  it("is bounded by remaining cap headroom", () => {
    expect(computeMintBatch(50, 48, 50)).toBe(2);
  });
});
