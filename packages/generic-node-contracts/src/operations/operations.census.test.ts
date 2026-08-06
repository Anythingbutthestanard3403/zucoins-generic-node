import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { OPERATION_KINDS, CHILD_LINK, WORKFLOW_GRAPH_SUPPORTED } from "./operations.contract.ts";

describe("operations census", () => {
  it("freezes exactly the three frozen operation kinds, in sequence", () => {
    assertFieldOrder(OPERATION_KINDS, ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"]);
  });

  it("freezes the one-child link contract", () => {
    expect(CHILD_LINK).toEqual({
      parent: "RECEIVE_EXTERNAL",
      spawns: "MOVE_INTERNAL",
      via: "spawned_from_operation_id",
      maxChildrenPerReceive: 1,
    });
  });

  it("has no generic workflow engine", () => {
    expect(WORKFLOW_GRAPH_SUPPORTED).toBe(false);
  });

  it("rejects a fourth operation kind (negative path)", () => {
    const fourthOperationKind = "PAYMENT"; // contract-allow:fourth-op-negative-fixture
    expectRejects(
      () => [...OPERATION_KINDS, fourthOperationKind],
      (mutated) => assertFieldOrder(mutated, OPERATION_KINDS),
    );
  });
});
