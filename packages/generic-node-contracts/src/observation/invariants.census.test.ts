import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import { RECORD_INVARIANTS, RECORD_INVARIANT_IDS } from "./invariants.contract.ts";

describe("record invariant set is frozen (the observation dedup freeze; record CHECK constraints)", () => {
  it("invariant ids — exact members and sequence", () => {
    assertFieldOrder(RECORD_INVARIANT_IDS, [
      "ENUM_DOMAINS",
      "FIELD_A_FINGERPRINT_IFF_VERIFIED",
      "FIELD_B_STATE_CHANGED_IFF_VERIFIED",
      "FIELD_C_HEAD_MATERIAL_IFF_HEAD",
      "FIELD_D_GENESIS_SHAPE",
      "FIELD_E_HEAD_SHAPE",
      "FIELD_F_NONVERIFIED_SHAPE",
      "SCALAR_FORMATS",
    ]);
  });

  it("the id list is derived from the invariant table (no drift between the two)", () => {
    assertFieldOrder(
      RECORD_INVARIANT_IDS,
      RECORD_INVARIANTS.map((invariant) => invariant.id),
    );
  });

  it("every invariant carries a non-empty rule statement", () => {
    for (const invariant of RECORD_INVARIANTS) {
      expect(invariant.rule.length).toBeGreaterThan(0);
    }
  });
});
