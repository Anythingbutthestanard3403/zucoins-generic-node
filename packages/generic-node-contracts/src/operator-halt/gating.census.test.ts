import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { OPERATION_KINDS, type OperationKind } from "../operations/operations.contract.ts";
import {
  SIGNING_TRIGGERS,
  MONEY_MUTATION_HALT_MAP,
  isHaltGated,
  describeHaltGating,
} from "./gating.contract.ts";

describe("money-mutation halt gating census (the named concern, the frozen rule)", () => {
  it("freezes the exhaustive OPERATION_KINDS x SIGNING_TRIGGERS enumeration", () => {
    expect(MONEY_MUTATION_HALT_MAP).toHaveLength(OPERATION_KINDS.length * SIGNING_TRIGGERS.length);
  });

  it("covers every frozen operation kind for every signing trigger exactly once (type + runtime exhaustiveness)", () => {
    for (const operationKind of OPERATION_KINDS) {
      for (const trigger of SIGNING_TRIGGERS) {
        const matches = MONEY_MUTATION_HALT_MAP.filter(
          (row) => row.operationKind === operationKind && row.trigger === trigger,
        );
        expect(matches).toHaveLength(1);
      }
      // Compile-time exhaustiveness: throws only if the switch stops covering every kind.
      expect(() => describeHaltGating(operationKind)).not.toThrow();
    }
  });

  it("gates MOVE_INTERNAL and SEND_EXTERNAL on both triggers", () => {
    for (const operationKind of ["MOVE_INTERNAL", "SEND_EXTERNAL"] as const) {
      expect(isHaltGated(operationKind, "FRESH_ADMISSION")).toBe(true);
      expect(isHaltGated(operationKind, "RECOVERY_RESUMED_FIRST_FORMATION")).toBe(true);
    }
  });

  it("never gates RECEIVE_EXTERNAL, fresh or recovery-resumed", () => {
    expect(isHaltGated("RECEIVE_EXTERNAL", "FRESH_ADMISSION")).toBe(false);
    expect(isHaltGated("RECEIVE_EXTERNAL", "RECOVERY_RESUMED_FIRST_FORMATION")).toBe(false);
  });

  it("freezes the signing-trigger vocabulary, in sequence", () => {
    assertFieldOrder(SIGNING_TRIGGERS, ["FRESH_ADMISSION", "RECOVERY_RESUMED_FIRST_FORMATION"]);
  });

  it("fails closed (throws, never defaults open) for an uncovered operation kind (negative path)", () => {
    const fourthOperationKind = "REFUND_LIKE_THING" as OperationKind; // synthetic, not a real product term
    expect(() => isHaltGated(fourthOperationKind, "FRESH_ADMISSION")).toThrow();
  });

  it("rejects a reordered trigger list (negative path)", () => {
    expectRejects(
      () => [...SIGNING_TRIGGERS].reverse(),
      (mutated) => assertFieldOrder(mutated, SIGNING_TRIGGERS),
    );
  });
});
