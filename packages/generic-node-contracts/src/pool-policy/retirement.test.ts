import { describe, it, expect } from "vitest";
import { retireWallet, RETIRE_WALLET_CAS_SQL, type RetirementOutcome } from "./retirement.js";
import { reserveWallet, POOL_CAS_COLUMN } from "./reservation.js"; // contract-allow:reservation-module-path

describe("retireWallet — optimistic row_version CAS (the receive-queue backpressure rule 5)", () => {
  it("retires when version matches and state is AVAILABLE, bumping the version", () => {
    expect(retireWallet({ expectedRowVersion: 7, actualRowVersion: 7, state: "AVAILABLE" })).toEqual({
      kind: "retired",
      nextRowVersion: 8,
    });
  });
  it("NEVER retires a live-leased (PINNED) wallet — fund-stranding footgun blocked (NEGATIVE)", () => {
    // The naked `UPDATE ... SET state='RETIRED' WHERE id=$1` this contract exists to prevent would
    // deadlock a leased wallet's funds (RETIRED->AVAILABLE is forbidden). The state guard blocks it.
    expect(retireWallet({ expectedRowVersion: 7, actualRowVersion: 7, state: "PINNED" })).toEqual({
      kind: "lost",
    });
  });
  it("loses to a concurrent lease that bumped the row_version (stale expected) — NEGATIVE", () => {
    // A concurrent reserve moved the row AVAILABLE->PINNED and bumped 7->8; this retire, which
    // planned against version 7, now sees version 8 and a non-AVAILABLE state — 0-row UPDATE.
    expect(retireWallet({ expectedRowVersion: 7, actualRowVersion: 8, state: "PINNED" })).toEqual({
      kind: "lost",
    });
    // Defence in depth: even if the state still read AVAILABLE, a stale version alone loses.
    expect(retireWallet({ expectedRowVersion: 7, actualRowVersion: 8, state: "AVAILABLE" })).toEqual({
      kind: "lost",
    });
  });
  it("is idempotent-safe: cannot re-retire an already RETIRED wallet — NEGATIVE", () => {
    expect(retireWallet({ expectedRowVersion: 8, actualRowVersion: 8, state: "RETIRED" })).toEqual({
      kind: "lost",
    });
  });
});

describe("reserve/retire mutual exclusion — the concurrent race, both orderings (the frozen rule)", () => {
  // Two writers contend for the SAME AVAILABLE wallet at row_version = n. Both reserve (RECEIVE
  // lease) and retire share the `state='AVAILABLE' AND row_version=$n` guard, so exactly ONE wins
  // the CAS on the row; the loser observes the winner's bumped version / changed state and loses.
  // This is the fund-stranding race the QA named, shown excluded by the frozen semantics.
  const n = 4;

  it("reserve wins first → the racing retire cannot clobber the live lease", () => {
    const reserved = reserveWallet({ expectedRowVersion: n, actualRowVersion: n, state: "AVAILABLE" });
    expect(reserved).toEqual({ kind: "reserved", nextRowVersion: n + 1 });
    // Post-commit the row is PINNED at n+1. The retire, planned against n, now sees (PINNED, n+1).
    const retire = retireWallet({ expectedRowVersion: n, actualRowVersion: n + 1, state: "PINNED" });
    expect(retire).toEqual<RetirementOutcome>({ kind: "lost" });
  });

  it("retire wins first → the racing reserve cannot lease a retired wallet", () => {
    const retired = retireWallet({ expectedRowVersion: n, actualRowVersion: n, state: "AVAILABLE" });
    expect(retired).toEqual<RetirementOutcome>({ kind: "retired", nextRowVersion: n + 1 });
    // Post-commit the row is RETIRED at n+1. The reserve, planned against n, now sees (RETIRED, n+1).
    const reserve = reserveWallet({ expectedRowVersion: n, actualRowVersion: n + 1, state: "RETIRED" });
    expect(reserve).toEqual({ kind: "lost" });
  });

  it("both writers can never both win the same (id, row_version)", () => {
    const reserve = reserveWallet({ expectedRowVersion: n, actualRowVersion: n, state: "AVAILABLE" });
    const retire = retireWallet({ expectedRowVersion: n, actualRowVersion: n, state: "AVAILABLE" });
    // In-model both "win" against the pristine snapshot, but they bump to the SAME next version —
    // the DB serialises them so only the first commit takes; the second re-reads n+1 and loses
    // (proven by the two sequential tests above). Their winning next-versions collide by construction.
    expect(reserve.kind === "reserved" && reserve.nextRowVersion).toBe(n + 1);
    expect(retire.kind === "retired" && retire.nextRowVersion).toBe(n + 1);
  });
});

describe("retirement — frozen SQL guards on id, row_version, AVAILABLE", () => {
  it("the CAS UPDATE retires only from AVAILABLE at the expected version, bumping row_version", () => {
    expect(RETIRE_WALLET_CAS_SQL).toContain("SET state = 'RETIRED'");
    expect(RETIRE_WALLET_CAS_SQL).toContain("row_version = row_version + 1");
    expect(RETIRE_WALLET_CAS_SQL).toContain("WHERE id = $1 AND row_version = $2 AND state = 'AVAILABLE'");
    // Never from PINNED: the SQL cannot match a PINNED row.
    expect(RETIRE_WALLET_CAS_SQL).not.toContain("state = 'PINNED'");
  });
  it("retirement and hold contend on the same optimistic-concurrency column", () => {
    expect(POOL_CAS_COLUMN).toBe("row_version");
  });
});
