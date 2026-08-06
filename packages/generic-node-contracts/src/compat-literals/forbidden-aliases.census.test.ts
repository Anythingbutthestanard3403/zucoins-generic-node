import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { FORBIDDEN_STATE_ALIASES as OPERATIONS_FORBIDDEN_STATE_ALIASES } from "../operations/states.contract.ts";
import { FORBIDDEN_EVENT_ALIASES as OPERATIONS_FORBIDDEN_EVENT_ALIASES } from "../operations/events.contract.ts";
import { AFTER_LANDING_KINDS } from "../operations/lifecycle.contract.ts";
import { ZP_V1_PURPOSES } from "./compat-literals.contract.ts";
import {
  FORBIDDEN_STATE_ALIASES,
  FORBIDDEN_EVENT_ALIASES,
  FORBIDDEN_EVENT_GLOBS,
  FORBIDDEN_ALIAS_EXCEPTIONS,
} from "./forbidden-aliases.contract.ts";

describe("forbidden-aliases census", () => {
  it("re-exports the operations-owned forbidden state alias set unchanged (single source of truth)", () => {
    assertFieldOrder(FORBIDDEN_STATE_ALIASES, OPERATIONS_FORBIDDEN_STATE_ALIASES);
    expect(FORBIDDEN_STATE_ALIASES).toHaveLength(10);
  });

  it("re-exports the operations-owned forbidden event alias set unchanged (single source of truth)", () => {
    assertFieldOrder(FORBIDDEN_EVENT_ALIASES, OPERATIONS_FORBIDDEN_EVENT_ALIASES);
    expect(FORBIDDEN_EVENT_ALIASES).toHaveLength(4);
  });

  it("freezes the event-name glob half, not previously frozen anywhere else, in canonical sequence", () => {
    assertFieldOrder(FORBIDDEN_EVENT_GLOBS, ["reservation.*", "payment.*", "checkout.*", "refund.*"]);
  });

  it("freezes the two documented exceptions, sourced from their own owning contracts", () => {
    expect(FORBIDDEN_ALIAS_EXCEPTIONS.executionPhaseOnly).toBe("SUBMIT_STARTED");
    expect(FORBIDDEN_ALIAS_EXCEPTIONS.afterLandingKindOnly).toBe(AFTER_LANDING_KINDS[0]);
  });

  it("does not double-freeze an exception value as a forbidden alias", () => {
    expect(FORBIDDEN_STATE_ALIASES as readonly string[]).not.toContain(
      FORBIDDEN_ALIAS_EXCEPTIONS.executionPhaseOnly,
    );
    expect(FORBIDDEN_STATE_ALIASES as readonly string[]).not.toContain(
      FORBIDDEN_ALIAS_EXCEPTIONS.afterLandingKindOnly,
    );
  });

  it("rejects a forbidden event glob reordering (negative path)", () => {
    expectRejects(
      () => [...FORBIDDEN_EVENT_GLOBS].reverse(),
      (mutated) => assertFieldOrder(mutated, FORBIDDEN_EVENT_GLOBS),
    );
  });

  it("rejects a forbidden event glob smuggled into the compat purpose set (negative path)", () => {
    const forbiddenSample = FORBIDDEN_EVENT_GLOBS[0];
    expect(ZP_V1_PURPOSES as readonly string[]).not.toContain(forbiddenSample);
    expectRejects(
      () => [...ZP_V1_PURPOSES, forbiddenSample],
      (mutated) => assertFieldOrder(mutated, ZP_V1_PURPOSES),
    );
  });
});
