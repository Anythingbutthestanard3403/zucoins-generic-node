import { describe, it, expect } from "vitest";
import {
  FORBIDDEN_SHORTCUTS,
  EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED,
  releaseShortcutViolation,
  evidenceDisposalViolation,
  leaseDropViolation,
} from "./shortcuts.js";

const fullyProven = { reconcileCompleted: true, t0Unchanged: true, groupAcknowledgementsComplete: true };

describe("forbidden shortcuts — census", () => {
  it("freezes the three forbidden shortcuts", () => {
    expect(Object.keys(FORBIDDEN_SHORTCUTS).sort()).toEqual([
      "evidence_disposal_on_expiry",
      "lease_drop_before_disposition",
      "post_boundary_release_on_reconcile",
    ]);
  });
});

describe("releaseShortcutViolation — MONEY-LOSS (the receive-expiry rule): the 'fully proven' combination is itself the shortcut", () => {
  it("the exact reconcile-first + T0-unchanged + complete-acks combination is flagged, not treated as safe", () => {
    expect(releaseShortcutViolation(fullyProven)).toBe("post_boundary_release_on_reconcile");
  });
  it("not yet reconciled is not (yet) the release shortcut", () => {
    expect(releaseShortcutViolation({ ...fullyProven, reconcileCompleted: false })).toBeNull();
  });
  it("T0 moved (a landing occurred) or acks incomplete is not the release shortcut — it never resembled a release", () => {
    expect(releaseShortcutViolation({ ...fullyProven, t0Unchanged: false })).toBeNull();
    expect(releaseShortcutViolation({ ...fullyProven, groupAcknowledgementsComplete: false })).toBeNull();
  });
});

describe("evidenceDisposalViolation — evidence is never disposed on expiry", () => {
  it("NEGATIVE: disposing evidence on expiry is detected", () => {
    expect(EVIDENCE_DISPOSAL_ON_EXPIRY_ALLOWED).toBe(false);
    expect(evidenceDisposalViolation(true)).toBe("evidence_disposal_on_expiry");
  });
  it("retaining evidence is not a violation", () => {
    expect(evidenceDisposalViolation(false)).toBeNull();
  });
});

describe("leaseDropViolation — the lease is never dropped before a disposition", () => {
  it("NEGATIVE: dropping the lease before a disposition is detected", () => {
    expect(leaseDropViolation(true, false)).toBe("lease_drop_before_disposition");
  });
  it("dropping after a disposition, or not dropping, is fine", () => {
    expect(leaseDropViolation(true, true)).toBeNull();
    expect(leaseDropViolation(false, false)).toBeNull();
  });
});
