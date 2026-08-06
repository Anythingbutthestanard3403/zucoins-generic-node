import { describe, expect, it } from "vitest";

import * as retentionModule from "./retention.js";
import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  PROOF_ACCESS_HTTP,
  PROOF_ACCESS_VERDICTS,
  decideProofAccess,
  isLandedTerminalStatus,
  resolveVerificationMaterialAccess,
  verificationMaterialAvailableUntilMs,
  type ProofAccessQuery,
} from "./retention.js";
import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";

const DAY = 24 * 60 * 60 * 1000;
const TERMINAL_AT = 1_700_000_000_000;

// The landed-terminal status for each kind, and a representative pre-terminal status for each.
// Keys are unquoted OperationKind members (import the frozen union — do not redeclare it; three public money operations).
const LANDED: Record<OperationKind, string> = {
  RECEIVE_EXTERNAL: "RECEIVE_LANDED",
  MOVE_INTERNAL: "INTERNAL_MOVE_LANDED",
  SEND_EXTERNAL: "EXTERNAL_SEND_LANDED",
};
const PRE_TERMINAL: Record<OperationKind, readonly string[]> = {
  RECEIVE_EXTERNAL: ["CREATED", "READY", "EXPIRED"],
  MOVE_INTERNAL: ["CREATED", "NEEDS_ATTENTION"],
  SEND_EXTERNAL: ["CREATED", "APPROVED", "AWAITING_REDEMPTION", "REJECTED", "NEEDS_ATTENTION"],
};
const KINDS = OPERATION_KINDS;

function landedQuery(
  kind: (typeof KINDS)[number],
  nowMs: number,
  windowMs: number = DEFAULT_PROOF_ACCESS_WINDOW_MS,
): ProofAccessQuery {
  return {
    kind,
    status: LANDED[kind],
    verificationMaterialAvailableUntilMs: verificationMaterialAvailableUntilMs(TERMINAL_AT, windowMs),
    nowMs,
  };
}

describe("verificationMaterialAvailableUntilMs (terminal + window)", () => {
  it("defaults to terminal plus 30 days", () => {
    expect(verificationMaterialAvailableUntilMs(TERMINAL_AT)).toBe(TERMINAL_AT + 30 * DAY);
    expect(DEFAULT_PROOF_ACCESS_WINDOW_MS).toBe(30 * DAY);
  });

  it("honours an explicit window", () => {
    expect(verificationMaterialAvailableUntilMs(TERMINAL_AT, DAY)).toBe(TERMINAL_AT + DAY);
    expect(verificationMaterialAvailableUntilMs(TERMINAL_AT, 0)).toBe(TERMINAL_AT);
  });

  it("rejects non-finite / negative inputs (does not silently produce NaN windows)", () => {
    expect(() => verificationMaterialAvailableUntilMs(Number.NaN)).toThrow(RangeError);
    expect(() => verificationMaterialAvailableUntilMs(TERMINAL_AT, -1)).toThrow(RangeError);
    expect(() => verificationMaterialAvailableUntilMs(TERMINAL_AT, Number.POSITIVE_INFINITY)).toThrow(
      RangeError,
    );
  });
});

describe("decideProofAccess — 409 / 200 / 410 across all three kinds", () => {
  it("serves ACCESSIBLE (200) at a landed terminal before the window passes, for every kind", () => {
    for (const kind of KINDS) {
      const query = landedQuery(kind, TERMINAL_AT + 1); // 1ms after terminal, deep inside window
      expect(decideProofAccess(query)).toBe("ACCESSIBLE");
      expect(resolveVerificationMaterialAccess(query).http).toBe(200);
    }
  });

  it("returns EXPIRED (410) at and after the window boundary, for every kind", () => {
    for (const kind of KINDS) {
      const until = verificationMaterialAvailableUntilMs(TERMINAL_AT);
      // Exactly at the boundary: "available until X" means access has ended at X.
      expect(decideProofAccess(landedQuery(kind, until))).toBe("EXPIRED");
      // Well past the boundary.
      expect(decideProofAccess(landedQuery(kind, until + DAY))).toBe("EXPIRED");
      expect(resolveVerificationMaterialAccess(landedQuery(kind, until + DAY)).http).toBe(410);
    }
  });

  it("NEVER serves pre-terminal: returns NOT_READY (409) for every pre-terminal status, even with a stray window", () => {
    for (const kind of KINDS) {
      for (const status of PRE_TERMINAL[kind]) {
        // Adversarial: a non-null window on a non-landed row must still be 409.
        const query: ProofAccessQuery = {
          kind,
          status,
          verificationMaterialAvailableUntilMs: TERMINAL_AT + 30 * DAY,
          nowMs: TERMINAL_AT + 1,
        };
        expect(isLandedTerminalStatus(kind, status)).toBe(false);
        expect(decideProofAccess(query)).toBe("NOT_READY");
        expect(resolveVerificationMaterialAccess(query).http).toBe(409);
      }
    }
  });

  it("landed but window unpopulated (null) is NOT_READY (409), not silently accessible", () => {
    for (const kind of KINDS) {
      const query: ProofAccessQuery = {
        kind,
        status: LANDED[kind],
        verificationMaterialAvailableUntilMs: null,
        nowMs: TERMINAL_AT + 1,
      };
      expect(decideProofAccess(query)).toBe("NOT_READY");
    }
  });

  it("HTTP projection is byte-aligned with the frozen error-envelope codes", () => {
    expect(PROOF_ACCESS_HTTP.NOT_READY).toEqual({ http: 409, code: "verification_material_not_ready" });
    expect(PROOF_ACCESS_HTTP.ACCESSIBLE).toEqual({ http: 200, code: null });
    expect(PROOF_ACCESS_HTTP.EXPIRED).toEqual({ http: 410, code: "verification_material_expired" });
    expect([...PROOF_ACCESS_VERDICTS]).toEqual(["NOT_READY", "ACCESSIBLE", "EXPIRED"]);
  });
});

describe("decideProofAccess — fail-closed on non-finite clock/column", () => {
  // Empirical probes that pin the consumer-side asymmetry with the producer RangeError checks.
  // Without Number.isFinite, `NaN >= until` is false → ACCESSIBLE forever.

  function landedReceive(
    until: number | null,
    nowMs: number,
  ): ProofAccessQuery {
    return {
      kind: "RECEIVE_EXTERNAL",
      status: LANDED.RECEIVE_EXTERNAL,
      verificationMaterialAvailableUntilMs: until,
      nowMs,
    };
  }

  it("nowMs = NaN is EXPIRED (never ACCESSIBLE)", () => {
    const until = verificationMaterialAvailableUntilMs(TERMINAL_AT);
    expect(decideProofAccess(landedReceive(until, Number.NaN))).toBe("EXPIRED");
    expect(resolveVerificationMaterialAccess(landedReceive(until, Number.NaN)).http).toBe(410);
  });

  it("until = NaN is EXPIRED (never ACCESSIBLE)", () => {
    expect(decideProofAccess(landedReceive(Number.NaN, TERMINAL_AT + 1))).toBe("EXPIRED");
    expect(resolveVerificationMaterialAccess(landedReceive(Number.NaN, TERMINAL_AT + 1)).http).toBe(410);
  });

  it("until = undefined (runtime hole past number | null) is EXPIRED (never ACCESSIBLE)", () => {
    const query = landedReceive(
      undefined as unknown as number | null,
      TERMINAL_AT + 1,
    );
    expect(decideProofAccess(query)).toBe("EXPIRED");
    expect(resolveVerificationMaterialAccess(query).http).toBe(410);
  });

  it("±Infinity on nowMs or until is EXPIRED (never ACCESSIBLE forever)", () => {
    const until = verificationMaterialAvailableUntilMs(TERMINAL_AT);
    expect(decideProofAccess(landedReceive(until, Number.POSITIVE_INFINITY))).toBe("EXPIRED");
    expect(decideProofAccess(landedReceive(until, Number.NEGATIVE_INFINITY))).toBe("EXPIRED");
    expect(decideProofAccess(landedReceive(Number.POSITIVE_INFINITY, TERMINAL_AT + 1))).toBe("EXPIRED");
    expect(decideProofAccess(landedReceive(Number.NEGATIVE_INFINITY, TERMINAL_AT + 1))).toBe("EXPIRED");
  });
});

describe("410 revokes access only — no purge, no deletion of canonical evidence", () => {
  it("a cleanly-landed op that has EXPIRED revokes access but the gate performs no mutation and is pure", () => {
    const until = verificationMaterialAvailableUntilMs(TERMINAL_AT);
    const query = landedQuery("MOVE_INTERNAL", until + DAY);
    // Called twice: identical verdict, no side effect, no throw — nothing is deleted or archived.
    expect(decideProofAccess(query)).toBe("EXPIRED");
    expect(decideProofAccess(query)).toBe("EXPIRED");
    expect(resolveVerificationMaterialAccess(query).verdict).toBe("EXPIRED");
  });

  it("an anomaly / NEEDS_ATTENTION op is never expired away: NOT_READY regardless of clock (no time-based deletion path)", () => {
    // A NEEDS_ATTENTION operation is pre-terminal; its ambiguous canonical evidence is pinned
    // permanent. Even with a window far in the past, the gate returns NOT_READY — it never flips
    // to EXPIRED and there is no code path that could purge the evidence.
    for (const kind of ["MOVE_INTERNAL", "SEND_EXTERNAL"] as const) {
      const query: ProofAccessQuery = {
        kind,
        status: "NEEDS_ATTENTION",
        verificationMaterialAvailableUntilMs: TERMINAL_AT - 365 * DAY,
        nowMs: TERMINAL_AT + 365 * DAY,
      };
      expect(decideProofAccess(query)).toBe("NOT_READY");
    }
  });

  it("the module exposes no purge/delete/reap/archive lifecycle at all (D1: forbidden purge removed)", () => {
    const surface = retentionModule as Record<string, unknown>;
    for (const forbidden of [
      "reap",
      "RETENTION_STATES",
      "RETENTION_CLASSES",
      "InMemoryRetentionService",
      "RetentionService",
      "ReapSummary",
      "DEFAULT_EPHEMERAL_RETENTION_MS",
    ]) {
      expect(surface[forbidden]).toBeUndefined();
    }
    // No exported value is a class/function whose name hints at deletion.
    const deletionNamed = Object.keys(surface).filter((k) => /purge|reap|delete|archiv|ephemeral/i.test(k));
    expect(deletionNamed).toEqual([]);
  });
});
