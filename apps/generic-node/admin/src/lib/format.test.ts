import { describe, expect, it } from "vitest";
import { truncatePubkey } from "./format.js";

describe("truncatePubkey", () => {
  it("keeps short keys", () => {
    expect(truncatePubkey("abc")).toBe("abc");
  });
  it("truncates long keys", () => {
    expect(truncatePubkey("zkz1qabcdefghijklmnop", 6, 4)).toBe("zkz1qa…mnop");
  });
});
