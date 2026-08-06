import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  walletStateContract,
  walletStateConcernManifest,
  WALLET_STATE_INVARIANTS,
} from "./manifest.js";

const snapshotPath = fileURLToPath(new URL("../../gen/wallet-state.json", import.meta.url));

describe("wallet-state manifest — snapshot sync (3-tier)", () => {
  it("gen/wallet-state.json equals the as-const walletStateContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(walletStateContract);
  });
});

describe("wallet-state manifest — invariant + vocabulary census", () => {
  it("freezes the five wallet-state invariants", () => {
    expect(Object.keys(WALLET_STATE_INVARIANTS)).toEqual([
      "projectionIsSoleSource",
      "leasedIsNeverAvailable",
      "oneInFlightPerWallet",
      "noStateChangeWithoutLeaseEvent",
      "leaseHoldPrecedenceOverExpiry",
    ]);
  });
  it("derives its state set from the named concern and freezes the lease vocabulary", () => {
    expect(walletStateContract.states).toEqual(["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"]);
    expect(walletStateContract.leaseRoles).toContain("RECONCILIATION");
    expect(walletStateContract.operationLeaseRoles).not.toContain("RECONCILIATION");
    expect(walletStateContract.leaseEvents).toHaveLength(5);
  });
  it("records the concern provenance (C-02 / the receive-expiry rule / the recovery-gate rule)", () => {
    expect(walletStateConcernManifest.concern).toBe("wallet-state");
    expect(walletStateConcernManifest.governedBy).toEqual([
      "C-02",
      "receive-expiry-prevention-rule",
      "recovery-gate-rule",
    ]);
  });
});
