import { describe, it, expect } from "vitest";
import {
  selectAssignableWallet,
  SELECT_ASSIGNABLE_WALLET_SQL,
  WALLET_SELECTION_LOCK,
  type SelectableWallet,
} from "./selection.js";

function wallet(over: Partial<SelectableWallet> & { id: string; createdAt: string }): SelectableWallet {
  return {
    keyOrigin: "node_generated",
    recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
    state: "AVAILABLE",
    ...over,
  };
}

const w1 = wallet({ id: "w1", createdAt: "2026-07-19T00:00:01.000Z" });
const w2 = wallet({ id: "w2", createdAt: "2026-07-19T00:00:02.000Z" });
const w3 = wallet({ id: "w3", createdAt: "2026-07-19T00:00:03.000Z" });

describe("selectAssignableWallet — sequence + eligibility (the recovery-gated eligibility rule)", () => {
  it("selects the oldest eligible wallet", () => {
    expect(selectAssignableWallet([w3, w1, w2], new Set())?.id).toBe("w1");
  });
  it("never selects a recovery-unverified wallet, even if oldest (NEGATIVE)", () => {
    const unverifiedOldest = wallet({ id: "w0", createdAt: "2026-07-19T00:00:00.000Z", recoveryVerifiedAt: null });
    expect(selectAssignableWallet([unverifiedOldest, w1, w2], new Set())?.id).toBe("w1");
  });
  it("never selects a non-AVAILABLE wallet (NEGATIVE)", () => {
    const pinnedOldest = wallet({ id: "wp", createdAt: "2026-07-19T00:00:00.000Z", state: "PINNED" });
    const retiredOldest = wallet({ id: "wr", createdAt: "2026-07-19T00:00:00.500Z", state: "RETIRED" });
    expect(selectAssignableWallet([pinnedOldest, retiredOldest, w1], new Set())?.id).toBe("w1");
  });
});

describe("selectAssignableWallet — SKIP LOCKED contention (no double-claim)", () => {
  it("skips a row locked by another transaction", () => {
    expect(selectAssignableWallet([w1, w2, w3], new Set(["w1"]))?.id).toBe("w2");
  });
  it("two concurrent selectors claim different wallets", () => {
    const a = selectAssignableWallet([w1, w2, w3], new Set());
    // selector B runs while A holds A's row lock:
    const b = selectAssignableWallet([w1, w2, w3], new Set([a?.id ?? ""]));
    expect(a?.id).toBe("w1");
    expect(b?.id).toBe("w2");
    expect(a?.id).not.toBe(b?.id);
  });
  it("returns null when every eligible row is locked (falls through to the queue)", () => {
    expect(selectAssignableWallet([w1, w2, w3], new Set(["w1", "w2", "w3"]))).toBeNull();
  });
});

describe("selection SQL — frozen contract text", () => {
  it("encodes the recovery-gated eligibility rule eligibility conjunction, selection sequence, and SKIP LOCKED", () => {
    expect(SELECT_ASSIGNABLE_WALLET_SQL).toContain(
      "key_origin = 'node_generated' AND recovery_verified_at IS NOT NULL AND state = 'AVAILABLE'",
    );
    expect(SELECT_ASSIGNABLE_WALLET_SQL).toContain("ORDER BY created_at ASC, id ASC"); // contract-allow:frozen-sql-text
    expect(SELECT_ASSIGNABLE_WALLET_SQL).toContain(WALLET_SELECTION_LOCK);
    expect(SELECT_ASSIGNABLE_WALLET_SQL).toContain("LIMIT 1");
  });
});
