/** @vitest-environment node */
import { describe, expect, test } from "vitest";
import { NEEDS_ATTENTION_KEY } from "./needs-attention.js";

describe("needs-attention shared key", () => {
  test("sole key is needs-attention", () => {
    expect(NEEDS_ATTENTION_KEY).toEqual(["needs-attention"]);
  });
});
