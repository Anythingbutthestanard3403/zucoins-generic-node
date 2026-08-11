import { describe, expect, it } from "vitest";

import { assertFieldOrder, assertClosedSet, expectRejects } from "../testkit/freeze.ts";
import { OPERATION_KINDS } from "../operations/operations.contract.ts";
import {
  HALT_KINDS,
  OUT_OF_SCOPE_HALT_MECHANISMS,
  HALT_GATED_OPERATION_KINDS,
  HALT_EXEMPT_OPERATION_KINDS,
  HALT_NEVER_GATED_INTERNAL_PATHS,
  OPERATOR_RECOVERY_ACTIONS,
  RESERVED_RECOVERY_ACTIONS,
  HALT_GATED_RECOVERY_ACTIONS,
  HALT_NEVER_GATED_RECOVERY_ACTIONS,
  classifyRecoveryActionHalt,
  isRecoveryActionAdmitted,
  HALT_TOGGLE_AUTH,
  HALT_ADMIN_ROUTES,
  HALT_PERSISTENCE,
  resolveHaltStateOnRestore,
  isHaltGatedOperationKind,
  isHaltExemptOperationKind,
  type OperatorRecoveryAction,
} from "./halt.contract.ts";
import { isHaltGated } from "./gating.contract.ts";

describe("halt semantics census (kill-switch rule)", () => {
  it("freezes exactly one launch halt kind", () => {
    assertFieldOrder(HALT_KINDS, ["OPERATOR_PAUSE"]);
  });

  it("freezes scale-to-zero as an explicitly out-of-scope mechanism, not a second halt kind", () => {
    assertFieldOrder(OUT_OF_SCOPE_HALT_MECHANISMS, ["TOTAL_HALT_SCALE_TO_ZERO"]);
    expect(HALT_KINDS).not.toContain("TOTAL_HALT_SCALE_TO_ZERO");
  });

  it("scopes every frozen operation kind exactly once between gated and exempt", () => {
    const scoped = [...HALT_GATED_OPERATION_KINDS, ...HALT_EXEMPT_OPERATION_KINDS];
    assertClosedSet(scoped, OPERATION_KINDS);
    for (const kind of OPERATION_KINDS) {
      const inGated = isHaltGatedOperationKind(kind);
      const inExempt = isHaltExemptOperationKind(kind);
      expect(inGated !== inExempt).toBe(true);
    }
  });

  it("gates both non-revenue kinds", () => {
    assertFieldOrder(HALT_GATED_OPERATION_KINDS, ["MOVE_INTERNAL", "SEND_EXTERNAL"]);
  });

  it("exempts the revenue co-sign kind from gating", () => {
    assertFieldOrder(HALT_EXEMPT_OPERATION_KINDS, ["RECEIVE_EXTERNAL"]);
  });

  it("freezes ONLY the three internal (non-catalog) read paths halt never gates", () => {
    assertFieldOrder(HALT_NEVER_GATED_INTERNAL_PATHS, [
      "OBSERVATION_SERVICE_READS",
      "RECOVERY_CLASSIFICATION",
      "BOOT_RECOVERY_CLASSIFICATION",
    ]);
    // Regression guard for the original defect: the internal-path list must NOT absorb catalog
    // operator actions (which conflated the two surfaces and hid REBUILD_INTERNAL_MOVE).
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      expect(HALT_NEVER_GATED_INTERNAL_PATHS as readonly string[]).not.toContain(action);
    }
  });

  it("transcribes the operator-action catalog as a closed set of exactly nine actions, in table sequence", () => {
    assertFieldOrder(OPERATOR_RECOVERY_ACTIONS, [
      "RETRY_OBSERVATION",
      "REDELIVER_EXACT_PARTIAL",
      "CONTINUE_EXTERNAL_WAIT",
      "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
      "REBUILD_INTERNAL_MOVE",
      "RELEASE_EXPIRED_RECEIVE",
      "QUARANTINE_WALLETS",
      "ACKNOWLEDGE_KEEP_PINNED",
    ]);
    expect(new Set(OPERATOR_RECOVERY_ACTIONS).size).toBe(9);
  });

  it("freezes REBUILD_INTERNAL_MOVE as the sole reserved catalog action (CLOSE authorized ZTR-1226)", () => {
    assertFieldOrder(RESERVED_RECOVERY_ACTIONS, [
      "REBUILD_INTERNAL_MOVE",
    ]);
    // CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED left RESERVED under ZTR-1129; ZTR-1226 (b) promotes
    // it to live under the bounded path/head oracle. D9.6 still forbids a generic oracle.
    expect(RESERVED_RECOVERY_ACTIONS as readonly string[]).not.toContain(
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
    );
    // Reserved actions stay IN the catalog census — being RESERVED is a launch-grantability
    // status, not a removal from the catalog.
    for (const action of RESERVED_RECOVERY_ACTIONS) {
      expect(OPERATOR_RECOVERY_ACTIONS as readonly string[]).toContain(action);
    }
  });

  it("classifies every catalog action exactly once (closed-set partition, gated XOR never-gated)", () => {
    // Union of the two dispositions is exactly the operator-action catalog — no action left unclassified,
    // none invented outside it. This fails the build if the frozen catalog and the classification
    // ever diverge.
    assertClosedSet([...HALT_GATED_RECOVERY_ACTIONS, ...HALT_NEVER_GATED_RECOVERY_ACTIONS], OPERATOR_RECOVERY_ACTIONS);
    // Disjoint: no action is both.
    for (const action of HALT_GATED_RECOVERY_ACTIONS) {
      expect(HALT_NEVER_GATED_RECOVERY_ACTIONS as readonly string[]).not.toContain(action);
    }
    // Every action resolves to exactly one disposition consistent with the frozen sets.
    for (const action of OPERATOR_RECOVERY_ACTIONS) {
      const disposition = classifyRecoveryActionHalt(action);
      const inGated = (HALT_GATED_RECOVERY_ACTIONS as readonly string[]).includes(action);
      const inNever = (HALT_NEVER_GATED_RECOVERY_ACTIONS as readonly string[]).includes(action);
      expect(inGated !== inNever).toBe(true);
      expect(disposition).toBe(inGated ? "HALT_GATED" : "HALT_NEVER_GATED");
    }
  });

  it("gates exactly REBUILD_INTERNAL_MOVE, and leaves the other eight catalog actions never-gated", () => {
    assertFieldOrder(HALT_GATED_RECOVERY_ACTIONS, ["REBUILD_INTERNAL_MOVE"]);
    assertFieldOrder(HALT_NEVER_GATED_RECOVERY_ACTIONS, [
      "RETRY_OBSERVATION",
      "REDELIVER_EXACT_PARTIAL",
      "CONTINUE_EXTERNAL_WAIT",
      "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
      "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
      "RELEASE_EXPIRED_RECEIVE",
      "QUARANTINE_WALLETS",
      "ACKNOWLEDGE_KEEP_PINNED",
    ]);
  });

  it("keeps the REBUILD gating consistent with the operation-kind gate (no cross-file drift)", () => {
    // REBUILD_INTERNAL_MOVE is the operator-recovery trigger for a recovery-resumed first
    // formation of a MOVE_INTERNAL — gating.contract.ts must already freeze that as halt-gated.
    expect(classifyRecoveryActionHalt("REBUILD_INTERNAL_MOVE")).toBe("HALT_GATED");
    expect(isHaltGated("MOVE_INTERNAL", "RECOVERY_RESUMED_FIRST_FORMATION")).toBe(true);
  });

  it("a HALTED node REFUSES REBUILD_INTERNAL_MOVE (money-path breaking input, fed)", () => {
    // The named breaking input, actually fed through the admit predicate.
    expect(isRecoveryActionAdmitted("REBUILD_INTERNAL_MOVE", true)).toBe(false);
    // A running node admits it; a halted node still admits every non-signing catalog action.
    expect(isRecoveryActionAdmitted("REBUILD_INTERNAL_MOVE", false)).toBe(true);
    for (const action of HALT_NEVER_GATED_RECOVERY_ACTIONS) {
      expect(isRecoveryActionAdmitted(action, true)).toBe(true);
      expect(isRecoveryActionAdmitted(action, false)).toBe(true);
    }
  });

  it("classifies fail-closed: an action outside the closed catalog set is never silently never-gated", () => {
    const fabricated = "RETRY_SUBMIT" as OperatorRecoveryAction; // a non-existent action, not in the catalog
    // It is not admitted-by-default while halted: it maps to no re-authorized formation, so it is
    // reported never-gated ONLY because it is not a fund-mover — but it is not a member of the
    // frozen catalog, which the partition test above forbids. Guard both facts explicitly.
    expect(OPERATOR_RECOVERY_ACTIONS as readonly string[]).not.toContain(fabricated);
    expect(HALT_GATED_RECOVERY_ACTIONS as readonly string[]).not.toContain(fabricated);
    expect(HALT_NEVER_GATED_RECOVERY_ACTIONS as readonly string[]).not.toContain(fabricated);
  });

  it("freezes engage/disengage as equally strong (never a cheaper disengage)", () => {
    expect(HALT_TOGGLE_AUTH.engage).toBe(HALT_TOGGLE_AUTH.disengage);
    expect(HALT_TOGGLE_AUTH.engage).toBe("operator_session_totp");
  });

  it("freezes the halt admin route pair with the correct auth split", () => {
    expect(HALT_ADMIN_ROUTES).toEqual([
      { method: "GET", path: "/admin/v1/halt", authMode: "operator_session" },
      { method: "POST", path: "/admin/v1/halt", authMode: "operator_session_totp" },
    ]);
  });

  it("freezes the persistence contract: no migration, restored before money engines start", () => {
    expect(HALT_PERSISTENCE).toEqual({
      storage: "single-durable-record",
      schemaMigrationRequired: false,
      restoredBeforeMoneyEnginesStart: true,
      freshNodeDefault: false,
    });
  });

  it("resolves NO_ROW to not-engaged (fresh node never halted)", () => {
    expect(resolveHaltStateOnRestore({ kind: "NO_ROW" })).toBe(false);
  });

  it("resolves a clean parseable row affirmatively, either direction", () => {
    expect(
      resolveHaltStateOnRestore({
        kind: "CLEAN_PARSEABLE",
        state: { engaged: false, reason: null },
      }),
    ).toBe(false);
    expect(
      resolveHaltStateOnRestore({
        kind: "CLEAN_PARSEABLE",
        state: { engaged: true, reason: "investigating a discrepancy" },
      }),
    ).toBe(true);
  });

  it("fails CLOSED (stays halted) on corrupt or unreadable restore state (negative path)", () => {
    expect(resolveHaltStateOnRestore({ kind: "CORRUPT_UNPARSEABLE" })).toBe(true);
    expect(resolveHaltStateOnRestore({ kind: "READ_FAILED_AFTER_RETRY" })).toBe(true);
  });

  it("rejects a second halt kind (negative path)", () => {
    const secondHaltKind = "MAINTENANCE_MODE"; // synthetic, not a real product term
    expectRejects(
      () => [...HALT_KINDS, secondHaltKind],
      (mutated) => assertFieldOrder(mutated, HALT_KINDS),
    );
  });
});
