import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { poolTransactionsContract } from "./transactions-manifest.js";

const snapshotPath = fileURLToPath(new URL("../../gen/pool-transactions.json", import.meta.url));

describe("pool transactions manifest — snapshot sync (3-tier)", () => {
  it("gen/pool-transactions.json equals the as-const poolTransactionsContract", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(poolTransactionsContract);
  });
});

describe("pool transactions manifest — census", () => {
  it("aggregates the selection, hold, retirement, and scale-up contracts", () => {
    expect(Object.keys(poolTransactionsContract).sort()).toEqual([
      "reservation", // contract-allow:frozen-contract-field-name
      "retirement",
      "scaleUp",
      "selection",
    ]);
  });
  it("carries the SKIP LOCKED selection, row_version CAS, and advisory-lock namespace", () => {
    expect(poolTransactionsContract.selection.lock).toBe("FOR UPDATE SKIP LOCKED");
    expect(poolTransactionsContract.reservation.casColumn).toBe("row_version"); // contract-allow:frozen-contract-field-name
    expect(poolTransactionsContract.scaleUp.advisoryLockNamespace).toBe("pool_scale_up");
  });
  it("freezes the retirement CAS on the same row_version column, never from PINNED (the receive-queue backpressure rule 5)", () => {
    expect(poolTransactionsContract.retirement.casColumn).toBe("row_version");
    expect(poolTransactionsContract.retirement.sql).toContain("SET state = 'RETIRED'");
    expect(poolTransactionsContract.retirement.sql).toContain("state = 'AVAILABLE'");
    expect(poolTransactionsContract.retirement.sql).not.toContain("state = 'PINNED'");
  });
  it("freezes the open_sessions demand read, symmetric with cap count and excluding send-side pins (the receive-queue backpressure rule 1)", () => {
    expect(poolTransactionsContract.scaleUp.openSessionsSql).toContain("open_sessions");
    expect(poolTransactionsContract.scaleUp.openSessionsSql).toContain("lease_role = 'RECEIVE'");
    expect(poolTransactionsContract.scaleUp.openSessionsComposition).toEqual({
      includes: [
        "RECEIVE-pinned pool wallets",
        "unassigned CREATED receive operations awaiting a wallet",
      ],
      excludes: [
        "a wallet pin held for a node-internal transfer between two node-controlled wallets",
        "a wallet pin held to form a partial for an external recipient to co-sign",
      ],
    });
  });
});
