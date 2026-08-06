import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { AFTER_LANDING_KINDS, CHILD_LINK_FIELD, LIFECYCLE_RULES } from "./lifecycle.contract.ts";

describe("lifecycle census (the generic-core scan concern.2, the three-generic-operation rule)", () => {
  it("freezes the after_landing kinds, in sequence", () => {
    assertFieldOrder(AFTER_LANDING_KINDS, ["HOLD", "INTERNAL_MOVE"]);
  });

  it("freezes the child-link field name", () => {
    expect(CHILD_LINK_FIELD).toBe("spawned_from_operation_id");
  });

  it("freezes exactly one after-landing child, no workflow graph", () => {
    expect(LIFECYCLE_RULES).toEqual({
      parentOperation: "RECEIVE_EXTERNAL",
      childOperation: "MOVE_INTERNAL",
      maxChildrenPerReceive: 1,
      childLinkField: "spawned_from_operation_id",
      workflowGraphSupported: false,
    });
  });

  it("rejects a second child link (negative path)", () => {
    expectRejects(
      () => ({ ...LIFECYCLE_RULES, maxChildrenPerReceive: 2 }),
      (mutated) => expect(mutated).toEqual(LIFECYCLE_RULES),
    );
  });
});
