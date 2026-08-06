// the presentation-scope concern.2 census: the frozen capability manifest and its explicit non-capability exclusions.
// Covers the frozen capability manifest; instruction-origin identity.
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  CAPABILITY_IDS,
  CAPABILITY_MANIFEST,
  NON_CAPABILITIES,
  capabilityDescriptor,
  isCapabilityId,
  isFrozenAvailable,
  isNonCapability,
  type CapabilityId,
} from "./capability-manifest.contract.ts";

describe("the presentation-scope concern.2 census: CAPABILITY_IDS is the exact closed set", () => {
  it("matches the frozen membership", () => {
    assertClosedSet(CAPABILITY_IDS, ["ARTIFACT_VERIFICATION", "IDENTITY_PIN_CHECK", "PROOF_MATERIAL_ACCESS"]);
  });

  it("CAPABILITY_MANIFEST covers exactly CAPABILITY_IDS, in the same sequence", () => {
    assertFieldOrder(
      CAPABILITY_MANIFEST.map((c) => c.id),
      CAPABILITY_IDS,
    );
  });
});

describe("the presentation-scope concern.2 census: two capabilities are frozen available today, one is deferred", () => {
  it("ARTIFACT_VERIFICATION is frozen available and owned by the artifacts concern", () => {
    expect(isFrozenAvailable("ARTIFACT_VERIFICATION")).toBe(true);
    expect(capabilityDescriptor("ARTIFACT_VERIFICATION").ownerConcern).toBe("artifacts");
    expect(capabilityDescriptor("ARTIFACT_VERIFICATION").exportedSymbols.length).toBeGreaterThan(0);
    //  CONTRACT_FREEZE amendment: verifyExpectedArtifact now takes an injected
    // ArtifactVerificationCrypto, so the frozen capability surface exports that interface type.
    expect(capabilityDescriptor("ARTIFACT_VERIFICATION").exportedSymbols).toContain(
      "ArtifactVerificationCrypto",
    );
  });

  it("IDENTITY_PIN_CHECK is frozen available and owned by the presentation-scope concern.1", () => {
    expect(isFrozenAvailable("IDENTITY_PIN_CHECK")).toBe(true);
    expect(capabilityDescriptor("IDENTITY_PIN_CHECK").ownerConcern).toBe("identity-pin");
    expect(capabilityDescriptor("IDENTITY_PIN_CHECK").exportedSymbols.length).toBeGreaterThan(0);
  });

  it("PROOF_MATERIAL_ACCESS is DEFERRED to the landing-proof concern with no fabricated interface", () => {
    expect(isFrozenAvailable("PROOF_MATERIAL_ACCESS")).toBe(false);
    const descriptor = capabilityDescriptor("PROOF_MATERIAL_ACCESS");
    expect(descriptor.status).toBe("DEFERRED");
    expect(descriptor.ownerConcern).toBe("landing-proof");
    expect(descriptor.exportedSymbols).toEqual([]);
  });
});

describe("the presentation-scope concern.2 census: NON_CAPABILITIES is the exact closed set and disjoint from CAPABILITY_IDS", () => {
  it("matches the frozen membership", () => {
    assertClosedSet(NON_CAPABILITIES, [
      "CUSTOMER_INSTRUCTION_UI",
      "ORIGIN_POLICY_DECISION",
      "PIN_DISTRIBUTION_CHANNEL",
      "KEY_ROTATION_UX",
    ]);
  });

  it("no id is both a capability and a non-capability", () => {
    for (const id of CAPABILITY_IDS) {
      expect(isNonCapability(id)).toBe(false);
    }
    for (const id of NON_CAPABILITIES) {
      expect(isCapabilityId(id)).toBe(false);
    }
  });
});

describe("the presentation-scope concern.2 mandatory negative: a non-capability may never be claimed as a capability", () => {
  it("isCapabilityId rejects every frozen non-capability id", () => {
    for (const id of NON_CAPABILITIES) {
      expect(isCapabilityId(id)).toBe(false);
    }
  });

  it("capabilityDescriptor throws on an undeclared 4th capability id", () => {
    expectRejects(
      () => "CUSTOMER_INSTRUCTION_UI" as unknown as CapabilityId,
      (mutated) => capabilityDescriptor(mutated),
    );
  });
});
