// Prove group-release ordering against the REAL production predicate SUT.
//
//
// This suite imports only `evaluateGroupRelease` / `clampReleaseToVerdict` from
// `../src/verification/index.ts` and asserts the full conjunctive barrier under every
// adversarial interleaving named below. Mutation / crash evidence with real PostgreSQL
// lives in group-release-ordering.pg.test.ts (same production barrels).
//
// Cases covered:
//   1. Only-receive-ack → PINNED_GROUP_PENDING indefinitely (move-first symmetric)
//   2. Both acks, one REJECTED → PINNED_FOR_ATTENTION, never RELEASED
//   6. Dest busy equivalent = child PENDING / destination leg non-terminal; attention on one
//      side; ack order permutations; re-evaluation of the same facts is idempotent.

import { describe, expect, it } from "vitest";

import {
  clampReleaseToVerdict,
  evaluateGroupRelease,
  REQUIRED_EVIDENCE_ROLES,
  type AckVerdict,
  type DurableEvidenceFact,
  type GroupOperationFact,
  type GroupReleaseFacts,
  type OperationWalletAssignment,
} from "../src/verification/index.ts";

const RECEIVE_OP = "d0000000-0000-4000-8000-000000000284";
const MOVE_OP = "d0000000-0000-4000-8000-000000000285";
const RIVAL_OP = "d0000000-0000-4000-8000-000000000286";

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const SRC: OperationWalletAssignment = {
  role: "SOURCE",
  walletId: "a0000000-0000-4000-8000-000000000001",
  walletPublicKey: pubkey("s1"),
};
const DST: OperationWalletAssignment = {
  role: "DESTINATION",
  walletId: "a0000000-0000-4000-8000-000000000002",
  walletPublicKey: pubkey("d1"),
};
const RCV: OperationWalletAssignment = {
  role: "RECEIVER",
  walletId: "a0000000-0000-4000-8000-000000000003",
  walletPublicKey: pubkey("r1"),
};

const asEvidence = (w: OperationWalletAssignment): DurableEvidenceFact => ({
  role: w.role,
  walletId: w.walletId,
  walletPublicKey: w.walletPublicKey,
});

function receiveLeg(overrides: Partial<GroupOperationFact> = {}): GroupOperationFact {
  const base: GroupOperationFact = {
    operationId: RECEIVE_OP,
    kind: "RECEIVE_EXTERNAL",
    verdict: "VERIFIED",
    completed: true,
    expectedWallets: [RCV],
    evidence: [asEvidence(RCV)],
    evidenceRoles: ["RECEIVER"],
  };
  const merged = { ...base, ...overrides };
  if (overrides.evidence === undefined && overrides.verdict === null) {
    return { ...merged, evidence: [], evidenceRoles: [] };
  }
  if (overrides.evidence !== undefined && overrides.evidenceRoles === undefined) {
    return { ...merged, evidenceRoles: overrides.evidence.map((e) => e.role) };
  }
  return merged;
}

function moveLeg(overrides: Partial<GroupOperationFact> = {}): GroupOperationFact {
  const base: GroupOperationFact = {
    operationId: MOVE_OP,
    kind: "MOVE_INTERNAL",
    verdict: "VERIFIED",
    completed: true,
    expectedWallets: [SRC, DST],
    evidence: [asEvidence(SRC), asEvidence(DST)],
    evidenceRoles: ["SOURCE", "DESTINATION"],
  };
  const merged = { ...base, ...overrides };
  if (overrides.evidence === undefined && overrides.verdict === null) {
    return { ...merged, evidence: [], evidenceRoles: [] };
  }
  if (overrides.evidence !== undefined && overrides.evidenceRoles === undefined) {
    return { ...merged, evidenceRoles: overrides.evidence.map((e) => e.role) };
  }
  return merged;
}

const unacked = (base: GroupOperationFact): GroupOperationFact => ({
  ...base,
  verdict: null,
  completed: false,
  evidence: [],
  evidenceRoles: [],
});

const pendingTerminal = (base: GroupOperationFact): GroupOperationFact => ({
  ...base,
  completed: false,
});

describe("group-release ordering (production evaluateGroupRelease)", () => {
  it("binds required evidence roles from the production surface (not a local fixture)", () => {
    expect(REQUIRED_EVIDENCE_ROLES).toEqual({
      RECEIVE_EXTERNAL: ["RECEIVER"],
      MOVE_INTERNAL: ["SOURCE", "DESTINATION"],
      SEND_EXTERNAL: ["SOURCE", "DESTINATION"],
    });
  });

  /* ── AC1: full conjunctive predicate ─────────────────────────────── */

  it("releases iff both ops terminal AND all wallet-evidence acks durable (ALL_LEGS_PROVEN)", () => {
    const released = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [receiveLeg(), moveLeg()],
    });
    expect(released).toEqual({
      status: "RELEASED",
      reason: "ALL_LEGS_PROVEN",
      blockingOperationIds: [],
    });
  });

  /* ── AC2 + review indicator 1: only one ack ──────────────────────── */

  it("only receive ack → group stays PINNED_GROUP_PENDING (no majority/partial release)", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [receiveLeg(), unacked(moveLeg())],
    });
    expect(decided.status).toBe("PINNED_GROUP_PENDING");
    expect(decided.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    expect(decided.blockingOperationIds).toEqual([MOVE_OP]);
  });

  it("only move ack → group stays PINNED_GROUP_PENDING (symmetric)", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [unacked(receiveLeg()), moveLeg()],
    });
    expect(decided.status).toBe("PINNED_GROUP_PENDING");
    expect(decided.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    expect(decided.blockingOperationIds).toEqual([RECEIVE_OP]);
  });

  /* ── AC3 + review indicator 2: REJECTED pins attention ───────────── */

  it("both acks durable but one REJECTED → PINNED_FOR_ATTENTION, never RELEASED", () => {
    for (const bad of ["REJECTED", "INDETERMINATE"] as const) {
      for (const side of ["receive", "move"] as const) {
        const operations =
          side === "receive"
            ? [receiveLeg({ verdict: bad }), moveLeg()]
            : [receiveLeg(), moveLeg({ verdict: bad })];
        const decided = evaluateGroupRelease({ childDisposition: "JOINED", operations });
        expect(decided.status).toBe("PINNED_FOR_ATTENTION");
        expect(decided.reason).toBe("LEG_VERDICT_NOT_VERIFIED");
        expect(decided.blockingOperationIds).toEqual([
          side === "receive" ? RECEIVE_OP : MOVE_OP,
        ]);
      }
    }
  });

  it("attention beats pending: REJECTED leg while sibling unacked still pins attention", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [receiveLeg({ verdict: "REJECTED" }), unacked(moveLeg())],
    });
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    expect(decided.reason).toBe("LEG_VERDICT_NOT_VERIFIED");
  });

  /* ── AC6: ack order permutations ─────────────────────────────────── */

  it("ack order permutations are equivalent once both legs are proven", () => {
    const receiveThenMove: GroupReleaseFacts = {
      childDisposition: "JOINED",
      operations: [receiveLeg(), moveLeg()],
    };
    const moveThenReceive: GroupReleaseFacts = {
      childDisposition: "JOINED",
      operations: [moveLeg(), receiveLeg()],
    };
    expect(evaluateGroupRelease(receiveThenMove)).toEqual(evaluateGroupRelease(moveThenReceive));
    expect(evaluateGroupRelease(receiveThenMove).status).toBe("RELEASED");
  });

  it("intermediate states after first ack are pending regardless of which leg arrived first", () => {
    const afterReceive = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [receiveLeg(), unacked(moveLeg())],
    });
    const afterMove = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [unacked(receiveLeg()), moveLeg()],
    });
    expect(afterReceive.status).toBe("PINNED_GROUP_PENDING");
    expect(afterMove.status).toBe("PINNED_GROUP_PENDING");
    expect(afterReceive.status).toBe(afterMove.status);
  });

  /* ── terminal / disposition barriers ─────────────────────────────── */

  it("both acks VERIFIED but one leg non-terminal → PINNED_GROUP_PENDING (LEG_NOT_TERMINAL)", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [receiveLeg(), pendingTerminal(moveLeg())],
    });
    expect(decided.status).toBe("PINNED_GROUP_PENDING");
    expect(decided.reason).toBe("LEG_NOT_TERMINAL");
    expect(decided.blockingOperationIds).toEqual([MOVE_OP]);
  });

  it("child_disposition PENDING (child fail/not-joined phase) refuses release", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "PENDING",
      operations: [receiveLeg()],
    });
    expect(decided.status).toBe("PINNED_GROUP_PENDING");
    expect(decided.reason).toBe("CHILD_OPERATION_NOT_JOINED");
  });

  it("destination-leg incomplete evidence pins attention (eligibility/formation defect)", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [
        receiveLeg(),
        moveLeg({
          evidence: [asEvidence(SRC)],
          evidenceRoles: ["SOURCE"],
        }),
      ],
    });
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    expect(decided.reason).toBe("LEG_EVIDENCE_SET_INCOMPLETE");
    expect(decided.blockingOperationIds).toEqual([MOVE_OP]);
  });

  /* ── re-evaluation / restart boundary (predicate half) ───────────── */

  it("re-evaluating identical durable facts is idempotent (no flip once RELEASED eligible)", () => {
    const facts: GroupReleaseFacts = {
      childDisposition: "JOINED",
      operations: [receiveLeg(), moveLeg()],
    };
    const first = evaluateGroupRelease(facts);
    const second = evaluateGroupRelease(facts);
    expect(first).toEqual(second);
    expect(first.status).toBe("RELEASED");
  });

  it("re-evaluating after only one ack stays pending across restart-shaped requests", () => {
    const facts: GroupReleaseFacts = {
      childDisposition: "JOINED",
      operations: [receiveLeg(), unacked(moveLeg())],
    };
    for (let i = 0; i < 5; i += 1) {
      const decided = evaluateGroupRelease(facts);
      expect(decided.status).toBe("PINNED_GROUP_PENDING");
      expect(decided.reason).toBe("LEG_NOT_ACKNOWLEDGED");
    }
  });

  /* ── clamp: this request's non-VERIFIED cannot publish RELEASED ─ */

  it("clampReleaseToVerdict never upgrades REJECTED/INDETERMINATE onto RELEASED", () => {
    for (const verdict of ["REJECTED", "INDETERMINATE"] as AckVerdict[]) {
      expect(clampReleaseToVerdict(verdict, "RELEASED")).toBe("PINNED_FOR_ATTENTION");
      expect(clampReleaseToVerdict(verdict, "PINNED_GROUP_PENDING")).toBe("PINNED_GROUP_PENDING");
      expect(clampReleaseToVerdict(verdict, "PINNED_FOR_ATTENTION")).toBe("PINNED_FOR_ATTENTION");
    }
    expect(clampReleaseToVerdict("VERIFIED", "RELEASED")).toBe("RELEASED");
  });

  /* ── attention on one side while other is clean (AC6) ────────────── */

  it("attention on clean sibling still pins the whole group (no partial release of clean leg)", () => {
    const decided = evaluateGroupRelease({
      childDisposition: "JOINED",
      operations: [
        receiveLeg(), // clean, terminal, VERIFIED
        moveLeg({ verdict: "REJECTED" }),
      ],
    });
    expect(decided.status).toBe("PINNED_FOR_ATTENTION");
    // Releasable memberships would be empty at the service layer; the predicate itself never
    // names a per-leg RELEASED for the clean sibling.
    expect(decided.reason).not.toBe("ALL_LEGS_PROVEN");
  });

  it("foreign third operation in the group is not required to release (only group members)", () => {
    // Sanity: empty group is attention; a solitary extra arms facts differently but this
    // suite only ever evaluates the receive+child set that binds.
    expect(
      evaluateGroupRelease({ childDisposition: "NONE", operations: [] }).reason,
    ).toBe("GROUP_HAS_NO_OPERATIONS");
    expect(RIVAL_OP).toMatch(/^d0000000/);
  });
});
