import { describe, expect, it } from "vitest";

import { expectRejects } from "../testkit/freeze.ts";
import { CORE_CAPABILITIES, ABSENT_CAPABILITIES, LAUNCH_EXCLUSIONS } from "./capabilities.contract.ts";

describe("capabilities census", () => {
  it("freezes what the generic core supplies", () => {
    expect(CORE_CAPABILITIES).toEqual([
      "NODE_IDENTITY",
      "DISCOVERY",
      "EXPECTED_ARTIFACT_VERIFICATION",
    ]);
  });

  it("freezes WALLET_IMPORT and IMPORTED_DRAIN as absent (launch deferral)", () => {
    expect(ABSENT_CAPABILITIES).toEqual({
      WALLET_IMPORT: "absent",
      IMPORTED_DRAIN: "absent",
    });
  });

  it("freezes the launch-exclusion list", () => {
    expect(LAUNCH_EXCLUSIONS).toHaveLength(9);
  });

  it("rejects wallet import becoming present (negative path)", () => {
    expectRejects(
      () => ({ ...ABSENT_CAPABILITIES, WALLET_IMPORT: "present" }),
      (mutated) => expect(mutated).toEqual(ABSENT_CAPABILITIES),
    );
  });
});
