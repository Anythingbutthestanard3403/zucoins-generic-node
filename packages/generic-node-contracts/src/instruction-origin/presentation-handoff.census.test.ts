// the presentation scope audit census: the presentation-handoff shape and the substitution-threat decision table.
// Covers the presentation-handoff contract and its substitution-threat table; the
// instruction-origin identity rule.
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import type { ArtifactEnvelope } from "../artifacts/verify.ts";
import { identityKeyFingerprint, type NodeIdentityPin } from "./identity-pin.contract.ts";
import {
  DISCOVERY_PATH,
  PRESENTATION_HANDOFF_FIELDS,
  SUBSTITUTION_THREAT_TABLE,
  isThreatTableRowConsistent,
  isValidPresentationHandoffShape,
  type PresentationHandoff,
} from "./presentation-handoff.contract.ts";

const validEnvelope: ArtifactEnvelope = {
  key_id: "key-1",
  preimage_text: "zp-receive-expected-v1\n{}",
  preimage_sha256: "0".repeat(64),
  signature: "0".repeat(43) + "=",
};

const validPinPublicKeyB64 = "A".repeat(43) + "=";

const validPin: NodeIdentityPin = {
  keyId: "key-1",
  publicKeyB64: validPinPublicKeyB64,
  fingerprintSha256: identityKeyFingerprint(validPinPublicKeyB64),
  validFromUnixMs: 0,
  validUntilUnixMs: null,
};

const validHandoff: PresentationHandoff = {
  operationId: "11111111-1111-4111-8111-111111111111",
  artifactPurpose: "zp-receive-expected-v1",
  artifactEnvelope: validEnvelope,
  nodeIdentityPin: validPin,
  discoveryPath: DISCOVERY_PATH,
  originClass: "node-origin",
};

describe("the presentation scope audit census: PRESENTATION_HANDOFF_FIELDS is the exact closed set, in sequence", () => {
  it("matches the frozen membership and sequence", () => {
    assertFieldOrder(PRESENTATION_HANDOFF_FIELDS, [
      "operationId",
      "artifactPurpose",
      "artifactEnvelope",
      "nodeIdentityPin",
      "discoveryPath",
      "originClass",
    ]);
  });
});

describe("the presentation scope audit positive: a genuine handoff passes shape validation", () => {
  it("isValidPresentationHandoffShape accepts", () => {
    expect(isValidPresentationHandoffShape(validHandoff)).toBe(true);
  });
});

describe("the presentation scope audit mandatory negative (C-05): a handoff carrying wallet key material is rejected", () => {
  it("an extra field smuggling wallet key material fails shape validation", () => {
    const withKeyMaterial = { ...validHandoff, walletPrivateKey: "not-actually-a-key-but-shape-is-the-point" };
    expect(isValidPresentationHandoffShape(withKeyMaterial)).toBe(false);
  });

  it("expectRejects: any field outside the frozen closed set is caught", () => {
    expectRejects(
      () => ({ ...validHandoff, signingSeed: "0".repeat(64) }),
      (mutated) => expect(isValidPresentationHandoffShape(mutated)).toBe(true),
    );
  });

  it("a field missing entirely also fails (closed set is exact, not a superset check)", () => {
    const { originClass: _drop, ...withoutOriginClass } = validHandoff;
    expect(isValidPresentationHandoffShape(withoutOriginClass)).toBe(false);
  });

  it("an undeclared originClass value fails shape (closed field values, not just field names)", () => {
    expect(isValidPresentationHandoffShape({ ...validHandoff, originClass: "attacker-origin" })).toBe(false);
    expect(isValidPresentationHandoffShape({ ...validHandoff, originClass: "" })).toBe(false);
  });
});

describe("the presentation scope audit census: SUBSTITUTION_THREAT_TABLE agrees with isSubstitutionProof everywhere", () => {
  it("every frozen row is internally consistent", () => {
    for (const row of SUBSTITUTION_THREAT_TABLE) {
      expect(isThreatTableRowConsistent(row)).toBe(true);
    }
  });

  it("the table contains no platform-hosted row claiming substitution-proof", () => {
    const offendingRows = SUBSTITUTION_THREAT_TABLE.filter(
      (row) => row.originClass === "platform-hosted" && row.substitutionProof === true,
    );
    assertClosedSet(offendingRows, []);
  });

  it("the table covers at least one substitution-proof row per frozen origin class (node-origin, implementer-controlled-origin)", () => {
    for (const originClass of ["node-origin", "implementer-controlled-origin"] as const) {
      const provenRow = SUBSTITUTION_THREAT_TABLE.find(
        (row) => row.originClass === originClass && row.substitutionProof === true,
      );
      expect(provenRow).toBeDefined();
    }
  });
});

describe("the presentation scope audit mandatory negative: a platform-hosted origin claiming substitution-proof is rejected", () => {
  it("a fabricated row claiming platform-hosted defeats the substitution threat fails the consistency check", () => {
    const fabricated = {
      scenario: "fabricated: platform-hosted claims substitution-proof",
      originClass: "platform-hosted",
      independentPinVerified: true,
      nodeArtifactValid: true,
      substitutionProof: true,
      rationale: "invalid — used only to prove the consistency check catches this",
    } as const;
    expect(isThreatTableRowConsistent(fabricated)).toBe(false);
  });

  it("expectRejects: the fabricated row is caught, not silently accepted", () => {
    expectRejects(
      () => ({
        scenario: "fabricated",
        originClass: "platform-hosted" as const,
        independentPinVerified: true,
        nodeArtifactValid: true,
        substitutionProof: true,
        rationale: "invalid",
      }),
      (mutated) => expect(isThreatTableRowConsistent(mutated)).toBe(true),
    );
  });
});
