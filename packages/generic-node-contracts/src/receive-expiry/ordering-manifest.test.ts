import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { expiryOrderingContract } from "./ordering-manifest.js"; // contract-allow:ordering-manifest-module-path
import { postBoundaryExpiryDisposition, leaseDropAllowed } from "./ordering.js"; // contract-allow:ordering-module-path
import { isPostBoundaryResolutionLegal } from "./resolution.js";

const snapshotPath = fileURLToPath(new URL("../../gen/receive-expiry-ordering.json", import.meta.url)); // contract-allow:frozen-golden-path-citation

describe("expiry sequencing manifest — snapshot sync (3-tier)", () => {
  it("the gen snapshot equals the as-const expiryOrderingContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(expiryOrderingContract);
  });
});

describe("expiry sequencing manifest — census", () => {
  it("freezes the sequence, dispositions, and forbidden shortcuts — no release proof shape", () => {
    expect(expiryOrderingContract.order[2]).toBe("reconcile_first"); // contract-allow:frozen-contract-field-name
    expect(expiryOrderingContract).not.toHaveProperty("releaseProof");
    expect(expiryOrderingContract.dispositions).toEqual(["RECEIVE_LANDED", "INDETERMINATE"]);
    expect(expiryOrderingContract.evidenceDisposalOnExpiryAllowed).toBe(false);
  });
});

describe("MONEY-LOSS (the receive-expiry rule): the consumer's safe-terminal release branch is unreachable from a post-boundary reconcile", () => {
  it("the exact 'fully proven' combination (reconcile-first, T0 unchanged, complete acks) never yields a release disposition — it stays held or resolves INDETERMINATE, never RECEIVE_LANDED's release sibling", () => {
    const fullyProvenNotYetInconclusive = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: false,
      t0Unchanged: true,
      groupAcknowledgementsComplete: true,
      durablyInconclusive: false,
    });
    expect(fullyProvenNotYetInconclusive).toEqual({ kind: "held", attentionReason: "POST_EXPIRY_RECONCILING" });

    const fullyProvenDurablyInconclusive = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: false,
      t0Unchanged: true,
      groupAcknowledgementsComplete: true,
      durablyInconclusive: true,
    });
    expect(fullyProvenDurablyInconclusive).toEqual({ kind: "resolved", resolution: "INDETERMINATE" });
    expect(leaseDropAllowed(fullyProvenDurablyInconclusive)).toBe(false);
  });
});

describe("cross-file consistency — .2's resolved output domain is exactly .1's POST_BOUNDARY_RESOLUTIONS", () => {
  it("every 'resolved' disposition .2 can produce is a legal .1 resolution (RECEIVE_LANDED or INDETERMINATE — never a third value)", () => {
    const landed = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: true,
      t0Unchanged: false,
      groupAcknowledgementsComplete: false,
      durablyInconclusive: false,
    });
    const indeterminate = postBoundaryExpiryDisposition({
      reconcileCompleted: true,
      landingObserved: false,
      t0Unchanged: false,
      groupAcknowledgementsComplete: false,
      durablyInconclusive: true,
    });
    expect(landed.kind).toBe("resolved");
    expect(indeterminate.kind).toBe("resolved");
    if (landed.kind === "resolved") expect(isPostBoundaryResolutionLegal(landed.resolution)).toBe(true);
    if (indeterminate.kind === "resolved") {
      expect(isPostBoundaryResolutionLegal(indeterminate.resolution)).toBe(true);
    }
  });
});
