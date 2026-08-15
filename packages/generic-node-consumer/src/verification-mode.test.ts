import { describe, expect, it } from "vitest";

import {
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
  VerificationModeDriftError,
  isVerificationMode,
  parseVerificationMode,
} from "./verification-mode.js";

describe("verification_mode vocabulary", () => {
  it("matches contracts INDEPENDENT | NODE_VERIFIED with INDEPENDENT default", () => {
    expect(VERIFICATION_MODES).toEqual(["INDEPENDENT", "NODE_VERIFIED"]);
    expect(DEFAULT_VERIFICATION_MODE).toBe("INDEPENDENT");
  });

  it("parses omitted / null as INDEPENDENT", () => {
    expect(parseVerificationMode(undefined)).toBe("INDEPENDENT");
    expect(parseVerificationMode(null)).toBe("INDEPENDENT");
  });

  it("accepts both closed-set tokens", () => {
    expect(parseVerificationMode("INDEPENDENT")).toBe("INDEPENDENT");
    expect(parseVerificationMode("NODE_VERIFIED")).toBe("NODE_VERIFIED");
    expect(isVerificationMode("NODE_VERIFIED")).toBe(true);
  });

  it("fails closed on unknown tokens", () => {
    expect(() => parseVerificationMode("HYBRID")).toThrow(VerificationModeDriftError);
    expect(() => parseVerificationMode("independent")).toThrow(VerificationModeDriftError);
    expect(() => parseVerificationMode(1)).toThrow(VerificationModeDriftError);
    expect(isVerificationMode("HYBRID")).toBe(false);
  });
});
