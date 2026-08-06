import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { receiveExpiryContract, receiveExpiryConcernManifest } from "./manifest.js";
import { isExpiryToExpiredLegal } from "./lifecycle.js";
import { LIVE_CHAIN_PREMISE } from "./assumptions.js";
import { canExpiryReleaseReceiveLease } from "../wallet-state/legality.js";

const snapshotPath = fileURLToPath(new URL("../../gen/receive-expiry.json", import.meta.url));

describe("receive-expiry manifest — snapshot sync (3-tier)", () => {
  it("gen/receive-expiry.json equals the as-const receiveExpiryContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(receiveExpiryContract);
  });
});

describe("receive-expiry manifest — census", () => {
  it("aggregates boundary, lifecycle, resolution, consumer, and the live-chain premise", () => {
    expect(Object.keys(receiveExpiryContract).sort()).toEqual([
      "boundary",
      "consumer",
      "lifecycle",
      "liveChainPremise",
      "resolution",
    ]);
    expect(receiveExpiryContract.boundary.source).toBe("operation_transactions");
    expect(receiveExpiryContract.lifecycle.newAttentionReason).toBe("POST_EXPIRY_RECONCILING");
    expect(receiveExpiryContract.resolution.foldOutAllowed).toBe(false);
  });
  it("freezes the live-chain premise as a load-bearing assumption pointing at live-gateway acceptance", () => {
    expect(LIVE_CHAIN_PREMISE.status).toBe("load_bearing_assumption");
    expect(LIVE_CHAIN_PREMISE.acceptanceGate).toBe("live-gateway-acceptance");
    expect(receiveExpiryConcernManifest.frozenBy).toBe("receive-expiry-freeze");
  });
});

describe("consistency with wallet-state lease-hold precedence (cross-concern)", () => {
  it("post-boundary: neither the lease releases nor the receive terminally expires", () => {
    expect(canExpiryReleaseReceiveLease(true)).toBe(false);
    expect(isExpiryToExpiredLegal("READY", true)).toBe(false);
  });
  it("pre-boundary: both the lease may release and the receive may terminally expire", () => {
    expect(canExpiryReleaseReceiveLease(false)).toBe(true);
    expect(isExpiryToExpiredLegal("READY", false)).toBe(true);
  });
});
