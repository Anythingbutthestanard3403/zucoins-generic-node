import { describe, it, expect } from "vitest";
import { inspectForeignAmount } from "./foreign.js";

describe("inspectForeignAmount — the byte-exact signing rule, never reformat foreign bytes", () => {
  it("returns a legitimately non-canonical foreign form byte-for-byte (no round-trip)", () => {
    const result = inspectForeignAmount("2.50");
    expect(result.wellFormed).toBe(true);
    expect(result.anomaly).toBeNull();
    // The critical assertion: the trailing zero is preserved, NOT canonicalized to "2.5".
    expect(result.bytes).toBe("2.50");
    expect(result.bytes).not.toBe("2.5");
  });
  it("passes an already-canonical foreign amount through unchanged", () => {
    expect(inspectForeignAmount("2.5")).toEqual({ bytes: "2.5", wellFormed: true, anomaly: null });
    expect(inspectForeignAmount("0")).toEqual({ bytes: "0", wellFormed: true, anomaly: null });
  });
  it("flags a malformed foreign amount as an anomaly without rewriting or dropping it", () => {
    for (const bad of ["1e5", "-1", "abc", "100000000", `0.${"1".repeat(33)}`]) {
      const result = inspectForeignAmount(bad);
      expect(result.wellFormed).toBe(false);
      expect(result.anomaly).toBe("foreign_amount_grammar_violation");
      // Evidence preserved exactly — the malformed bytes are returned as-is.
      expect(result.bytes).toBe(bad);
    }
  });
});
