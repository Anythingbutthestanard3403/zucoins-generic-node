import { describe, it, expect } from "vitest";
import {
  isPostBoundaryResolutionLegal,
  isInvariantBreach,
  FOLD_OUT_ALLOWED,
  UNATTRIBUTED_SUCCESSOR_DISPOSITION,
} from "./resolution.js";

describe("isPostBoundaryResolutionLegal — RECEIVE_LANDED or INDETERMINATE only", () => {
  it("permits the two legal resolutions", () => {
    expect(isPostBoundaryResolutionLegal("RECEIVE_LANDED")).toBe(true);
    expect(isPostBoundaryResolutionLegal("INDETERMINATE")).toBe(true);
  });
  it("NEGATIVE: EXPIRED as a post-boundary resolution is illegal", () => {
    expect(isPostBoundaryResolutionLegal("EXPIRED")).toBe(false);
  });
  it("NEGATIVE: the frozen rule fold-out (PROVEN_NOT_LANDED) is illegal", () => {
    expect(isPostBoundaryResolutionLegal("PROVEN_NOT_LANDED")).toBe(false);
    expect(FOLD_OUT_ALLOWED).toBe(false);
  });
});

describe("isInvariantBreach — unattributed deep successor quarantines", () => {
  it("an unattributed deep successor is an invariant breach", () => {
    expect(isInvariantBreach(true, false)).toBe(true);
    expect(UNATTRIBUTED_SUCCESSOR_DISPOSITION).toBe("INVARIANT_BREACH_QUARANTINE");
  });
  it("an attributed successor, or none observed, is not a breach", () => {
    expect(isInvariantBreach(true, true)).toBe(false);
    expect(isInvariantBreach(false, false)).toBe(false);
  });
});
