import { describe, expect, it } from "vitest";

import { assertClosedSet } from "../testkit/freeze.ts";
import {
  READINESS_CHECKS,
  GATING_CHECK_IDS,
  NON_GATING_CHECK_IDS,
  READINESS_LEADERSHIP_SEPARATION,
  RECONCILIATION,
  RESTORE_HOLD_READINESS,
} from "./readiness-checks.contract.ts";
import { verifyReadinessCheckRegistry } from "./verifiers.ts";

describe("readiness-check registry is frozen and unambiguous (the readiness concern)", () => {
  it("every check has exactly one stamping authority and an assertion scope", () => {
    expect(verifyReadinessCheckRegistry(READINESS_CHECKS)).toEqual([]);
    for (const check of READINESS_CHECKS) {
      expect(check.stampingAuthority.length).toBeGreaterThan(0);
      expect(check.asserts.length).toBeGreaterThan(0);
      expect(check.doesNotAssert.length).toBeGreaterThan(0);
    }
  });

  it("no two checks share a stamping authority (a false value has one owner)", () => {
    const authorities = READINESS_CHECKS.map((check) => check.stampingAuthority);
    expect(new Set(authorities).size).toBe(authorities.length);
  });

  it("partitions into the frozen gating and non-gating sets; leadership is non-gating", () => {
    assertClosedSet(GATING_CHECK_IDS, [
      "schema_migrated",
      "database_reachable",
      "vault_available",
      "observation_read_capable",
      "restore_hold_clear",
    ]);
    assertClosedSet(NON_GATING_CHECK_IDS, ["signer_leadership"]);
    const leadership = READINESS_CHECKS.find((check) => check.id === "signer_leadership");
    expect(leadership?.gating).toBe(false);
  });

  it("no gating check asserts signer leadership (the decoupling is data)", () => {
    for (const id of GATING_CHECK_IDS) {
      const check = READINESS_CHECKS.find((candidate) => candidate.id === id);
      expect(check?.asserts.includes("leadership")).toBe(false);
    }
    expect(READINESS_LEADERSHIP_SEPARATION.readiness_requires_leadership).toBe(false);
    expect(READINESS_LEADERSHIP_SEPARATION.signing_requires_leadership).toBe(true);
    expect(READINESS_LEADERSHIP_SEPARATION.leadership_is_wallet_sequencing_authority).toBe(false);
    expect(READINESS_LEADERSHIP_SEPARATION.leadership_is_node_level_writer_role).toBe(true);
    expect(READINESS_LEADERSHIP_SEPARATION.liveness_may_be_true_while_readiness_false).toBe(true);
  });

  it("records the draft clauses the readiness-leadership decoupling rule supersedes", () => {
    expect(RECONCILIATION.canonical).toBe("startup-sequence");
    expect(RECONCILIATION.supersedes_draft_clauses.length).toBe(3);
  });

  it("records the ZTR-1172 restore_hold readiness decision as machine-readable data", () => {
    expect(RESTORE_HOLD_READINESS.restore_hold_gates_readiness).toBe(true);
    expect(RESTORE_HOLD_READINESS.check_id).toBe("restore_hold_clear");
    expect(GATING_CHECK_IDS).toContain("restore_hold_clear");
    const check = READINESS_CHECKS.find((c) => c.id === "restore_hold_clear");
    expect(check?.gating).toBe(true);
    expect(check?.stampingAuthority).toBe("RESTORE_HOLD_PROBE");
  });

  it("rejects a check with no stamping authority (negative path)", () => {
    const broken = [
      ...READINESS_CHECKS,
      { id: "orphan", gating: true, stampingAuthority: "", asserts: "x", doesNotAssert: ["y"] },
    ];
    expect(verifyReadinessCheckRegistry(broken)).toContain("CHECK_WITHOUT_STAMPING_AUTHORITY");
  });

  it("rejects two checks that share a stamping authority (negative path)", () => {
    const broken = [
      ...READINESS_CHECKS,
      {
        id: "shadow",
        gating: true,
        stampingAuthority: "MIGRATION_RUNNER",
        asserts: "x",
        doesNotAssert: ["y"],
      },
    ];
    expect(verifyReadinessCheckRegistry(broken)).toContain("DUPLICATE_STAMPING_AUTHORITY");
  });

  it("rejects a check with an empty assertion scope (negative path)", () => {
    const broken = [
      {
        id: "vague",
        gating: true,
        stampingAuthority: "SOLE_OWNER",
        asserts: "",
        doesNotAssert: [],
      },
    ];
    expect(verifyReadinessCheckRegistry(broken)).toContain("CHECK_WITHOUT_ASSERTION_SCOPE");
  });
});
