import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { OPERATION_KINDS } from "../operations/operations.contract.ts";
import { resolveHaltStateOnRestore } from "./halt.contract.ts";
import {
  HALT_RACE_PHASES,
  PHASE_APPLICABILITY,
  HALT_RACE_TABLE,
  CONCURRENT_TOGGLE_RESOLUTION,
  resolveConcurrentToggle,
} from "./races.contract.ts";

describe("halt-flag precedence over in-flight intents (kill-switch rule)", () => {
  it("covers every operation kind's applicable phases exactly once", () => {
    const expectedLength = OPERATION_KINDS.reduce(
      (total, kind) => total + PHASE_APPLICABILITY[kind].length,
      0,
    );
    expect(HALT_RACE_TABLE).toHaveLength(expectedLength);
    for (const operationKind of OPERATION_KINDS) {
      for (const phaseAtEngage of PHASE_APPLICABILITY[operationKind]) {
        const matches = HALT_RACE_TABLE.filter(
          (row) => row.operationKind === operationKind && row.phaseAtEngage === phaseAtEngage,
        );
        expect(matches).toHaveLength(1);
      }
    }
  });

  it("blocks MOVE_INTERNAL/SEND_EXTERNAL only at NOT_STARTED, never past it", () => {
    for (const operationKind of ["MOVE_INTERNAL", "SEND_EXTERNAL"] as const) {
      const rows = HALT_RACE_TABLE.filter((row) => row.operationKind === operationKind);
      const blocked = rows.filter((row) => row.action === "BLOCKED_FROM_STARTING");
      expect(blocked).toEqual([{ operationKind, phaseAtEngage: "NOT_STARTED", action: "BLOCKED_FROM_STARTING" }]);
      const pastNotStarted = rows.filter((row) => row.phaseAtEngage !== "NOT_STARTED");
      for (const row of pastNotStarted) {
        expect(row.action).toBe("COMPLETES_NO_ABORT");
      }
    }
  });

  it("never gates RECEIVE_EXTERNAL at any phase, including NOT_STARTED", () => {
    const rows = HALT_RACE_TABLE.filter((row) => row.operationKind === "RECEIVE_EXTERNAL");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.action).toBe("NEVER_GATED");
    }
  });

  it("freezes the execution-phase quotation, in sequence", () => {
    assertFieldOrder(HALT_RACE_PHASES, [
      "NOT_STARTED",
      "PREIMAGE_PERSISTED",
      "SIGNED_PERSISTED",
      "DELIVERED",
      "SUBMIT_STARTED",
      "SUBMIT_RETURNED",
      "LANDED_VERIFIED",
    ]);
  });

  it("rejects a fabricated action outside the closed set (negative path)", () => {
    const fabricatedAction = "SILENTLY_ABORTED"; // synthetic, not a real contract value
    expectRejects(
      () => [...new Set(HALT_RACE_TABLE.map((row) => row.action)), fabricatedAction],
      (mutated) =>
        assertFieldOrder(
          mutated,
          [...new Set(HALT_RACE_TABLE.map((row) => row.action))],
        ),
    );
  });
});

describe("corrupted/unreadable halt state fails CLOSED (kill-switch rule)", () => {
  it("stays halted on a corrupt-unparseable row", () => {
    expect(resolveHaltStateOnRestore({ kind: "CORRUPT_UNPARSEABLE" })).toBe(true);
  });

  it("stays halted when the read fails after bounded retry", () => {
    expect(resolveHaltStateOnRestore({ kind: "READ_FAILED_AFTER_RETRY" })).toBe(true);
  });

  it("is the ONLY two outcomes that can force halted=true regardless of any prior engaged=false", () => {
    const forcedHaltedOutcomes = [
      { kind: "CORRUPT_UNPARSEABLE" as const },
      { kind: "READ_FAILED_AFTER_RETRY" as const },
    ];
    for (const outcome of forcedHaltedOutcomes) {
      expect(resolveHaltStateOnRestore(outcome)).toBe(true);
    }
    // Negative path: a clean row previously disengaged never gets forced back to halted.
    expect(
      resolveHaltStateOnRestore({ kind: "CLEAN_PARSEABLE", state: { engaged: false, reason: null } }),
    ).toBe(false);
  });
});

describe("atomic monotonic-CAS on the halt toggle (extrapolated from guarded CAS mutation)", () => {
  it("freezes atomic CAS + strict-monotonic increment with no directional bias", () => {
    expect(CONCURRENT_TOGGLE_RESOLUTION).toEqual({
      mechanism: "compare-and-swap-on-expected-prior-version",
      sequenceDiscipline: "strict-monotonic-increment",
      biasedTowardEngage: false,
      biasedTowardDisengage: false,
      loserAction: "REJECT_AND_REQUIRE_REREAD",
    });
  });

  it("admits a toggle whose CAS matches AND strictly increments the version by one", () => {
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 3, currentPersistedVersion: 3, nextVersion: 4 }),
    ).toBe(true);
  });

  it("rejects a toggle racing against a stale version, for either engage or disengage (negative path)", () => {
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 3, currentPersistedVersion: 4, nextVersion: 4 }),
    ).toBe(false);
    // Direction-agnostic: it never inspects which action the caller intended, only the version —
    // so an engage-vs-disengage race and an engage-vs-engage race resolve identically on the same
    // version mismatch. A stale disengage therefore cannot clobber a newer engage.
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 4, currentPersistedVersion: 3, nextVersion: 5 }),
    ).toBe(false);
  });

  it("rejects a non-monotonic write even when the CAS matches (negative path — monotonicity has teeth)", () => {
    // No advance (would let a writer re-apply the same version).
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 3, currentPersistedVersion: 3, nextVersion: 3 }),
    ).toBe(false);
    // Backwards (would rewind the sequence).
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 3, currentPersistedVersion: 3, nextVersion: 2 }),
    ).toBe(false);
    // Skips ahead by more than one (breaks the total monotonic sequence the invariant guarantees).
    expect(
      resolveConcurrentToggle({ expectedPriorVersion: 3, currentPersistedVersion: 3, nextVersion: 5 }),
    ).toBe(false);
  });
});
