import { describe, expect, it } from "vitest";

import golden from "./gen/receive-expiry.json" with { type: "json" };
import { receiveExpiryConcernManifest, receiveExpiryContract } from "./manifest.ts";

describe("receive-expiry concern manifest freeze", () => {
  it("the frozen receive-expiry contract matches the committed gen snapshot", () => {
    expect(JSON.parse(JSON.stringify(receiveExpiryContract))).toEqual(golden);
  });

  it("declares its freeze authority and governing rules", () => {
    expect(receiveExpiryConcernManifest.concern).toBe("receive-expiry");
    expect(receiveExpiryConcernManifest.frozenBy).toBe("receive-expiry-freeze");
    expect(receiveExpiryConcernManifest.governedBy).toEqual([
      "receive-expiry-freeze",
      "durable-candidate-boundary",
      "lease-hold-precedence",
      "released-wallet-safety",
    ]);
  });
});
