import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { computeProvisioningTarget, computeMintBatch } from "./sizing.js";
import { planScaleUp } from "./scaling.js";
import { receiveAdmissionDecision } from "./queue.js";
import { RECEIVE_QUEUE_RETRY_AFTER_SECONDS } from "./constants.js";
import { selectAssignableWallet, type SelectableWallet } from "./selection.js";
import { isAssignable, reserveWallet, REPLENISHMENT_CRASH_SAFETY } from "./reservation.js"; // contract-allow:reservation-module-path
import { retireWallet } from "./retirement.js";
import { isValidPoolTransition, countsTowardCap, POOL_KEY_DELETION_ALLOWED, POOL_WALLET_TRANSITIONS } from "./states.js";
import { availableWalletCount, capCount, type PoolWalletDescriptor } from "./eligibility.js";
import { POOL_PRESSURE_SCENARIOS } from "./scenarios.js";

function w(over: Partial<SelectableWallet> & { id: string }): SelectableWallet {
  return {
    keyOrigin: "node_generated",
    recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
    state: "AVAILABLE",
    createdAt: `2026-07-19T00:00:${over.id.slice(1).padStart(2, "0")}.000Z`,
    ...over,
  };
}

function simulateBurst(input: { availableVerified: number; receives: number; poolCap: number }) {
  let available = input.availableVerified;
  let queueDepth = 0;
  const out = { assigned: 0, queued: 0, rejected: 0 };
  for (let i = 0; i < input.receives; i += 1) {
    const d = receiveAdmissionDecision({ availableVerifiedCount: available, queueDepth, poolCap: input.poolCap });
    if (d.kind === "assign") {
      out.assigned += 1;
      available -= 1;
    } else if (d.kind === "queue") {
      out.queued += 1;
      queueDepth += 1;
    } else {
      out.rejected += 1;
    }
  }
  return out;
}

describe("pressure: empty pool — born-blocked", () => {
  it("the first receive on a fresh node queues (no verified wallet)", () => {
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 0, poolCap: 50 }).kind).toBe("queue");
  });
  it("NEGATIVE: minting from empty does not make receives assignable (mint != availability)", () => {
    expect(planScaleUp({ openSessions: 1, capCountUnderLock: 0, poolCap: 50 })).toBe(5);
    const minted = Array.from({ length: 5 }, (_, i) => w({ id: `m${i}`, recoveryVerifiedAt: null }));
    expect(availableWalletCount(minted)).toBe(0);
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 0, poolCap: 50 }).kind).toBe("queue");
  });
});

describe("pressure: burst admission — FIFO then queue", () => {
  it("assigns the verified wallets then queues the rest", () => {
    expect(simulateBurst({ availableVerified: 3, receives: 5, poolCap: 50 })).toEqual({
      assigned: 3,
      queued: 2,
      rejected: 0,
    });
  });
  it("NEGATIVE: a receive past the verified set is queued, never assigned", () => {
    const afterExhaustion = receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 3, poolCap: 50 });
    expect(afterExhaustion.kind).not.toBe("assign");
  });
});

describe("pressure: pinned saturation", () => {
  const pinned = [w({ id: "p1", state: "PINNED" }), w({ id: "p2", state: "PINNED" }), w({ id: "p3", state: "PINNED" })];
  it("no wallet is selectable and none are available", () => {
    expect(selectAssignableWallet(pinned, new Set())).toBeNull();
    expect(availableWalletCount(pinned)).toBe(0);
  });
  it("NEGATIVE: receives queue then 503 at cap; minting cannot relieve pinned pressure", () => {
    const result = simulateBurst({ availableVerified: 0, receives: 60, poolCap: 50 });
    expect(result).toEqual({ assigned: 0, queued: 50, rejected: 10 });
  });
});

describe("pressure: cap exhaustion — fail-closed", () => {
  it("mints nothing at cap", () => {
    expect(planScaleUp({ openSessions: 100, capCountUnderLock: 50, poolCap: 50 })).toBe(0);
  });
  it("NEGATIVE: minting never exceeds cap and a full queue rejects 503 with a Retry-After", () => {
    expect(computeMintBatch(computeProvisioningTarget(100, 50), 50, 50)).toBe(0);
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 50, poolCap: 50 })).toEqual({
      kind: "reject",
      httpStatus: 503,
      reason: "receive_queue_full",
      retryAfterSeconds: RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
    });
    expect(RECEIVE_QUEUE_RETRY_AFTER_SECONDS).toBe(30);
  });
});

describe("pressure: concurrent scalers", () => {
  it("serialized scalers (re-read under lock) never exceed cap", () => {
    let capCountUnderLock = 48;
    const a = planScaleUp({ openSessions: 50, capCountUnderLock, poolCap: 50 });
    capCountUnderLock += a;
    const b = planScaleUp({ openSessions: 50, capCountUnderLock, poolCap: 50 });
    expect(a + b).toBe(2);
    expect(capCountUnderLock + b).toBe(50);
  });
  it("NEGATIVE: naive stale-count scalers over-mint past cap", () => {
    const a = planScaleUp({ openSessions: 50, capCountUnderLock: 48, poolCap: 50 });
    const b = planScaleUp({ openSessions: 50, capCountUnderLock: 48, poolCap: 50 });
    expect(48 + a + b).toBeGreaterThan(50);
  });
});

describe("pressure: retirement with active evidence", () => {
  const pool = [w({ id: "a1" }), w({ id: "r1", state: "RETIRED" })];
  it("RETIRED is excluded from selection but still counts toward cap", () => {
    expect(selectAssignableWallet(pool, new Set())?.id).toBe("a1");
    expect(countsTowardCap("RETIRED")).toBe(true);
    expect(capCount(pool)).toBe(2);
    expect(availableWalletCount(pool)).toBe(1);
  });
  it("NEGATIVE: cannot retire a live-leased (PINNED) wallet — policy predicate AND write CAS", () => {
    expect(isValidPoolTransition("AVAILABLE", "RETIRED")).toBe(true);
    expect(isValidPoolTransition("PINNED", "RETIRED")).toBe(false);
    // The frozen WRITE mechanism enforces the same guard: retiring a PINNED row is a 0-row UPDATE.
    expect(retireWallet({ expectedRowVersion: 3, actualRowVersion: 3, state: "PINNED" }).kind).toBe("lost");
    expect(retireWallet({ expectedRowVersion: 3, actualRowVersion: 3, state: "AVAILABLE" })).toEqual({
      kind: "retired",
      nextRowVersion: 4,
    });
  });
  it("NEGATIVE: concurrent reserve vs retire on one AVAILABLE wallet — only one wins, funds never stranded", () => {
    // reserve wins first: the retire, planned at v3, sees the leased row at (PINNED, v4) and loses,
    // so a live lease is never clobbered into an un-un-retireable RETIRED state.
    expect(reserveWallet({ expectedRowVersion: 3, actualRowVersion: 3, state: "AVAILABLE" })).toEqual({
      kind: "reserved",
      nextRowVersion: 4,
    });
    expect(retireWallet({ expectedRowVersion: 3, actualRowVersion: 4, state: "PINNED" }).kind).toBe("lost");
    // retire wins first: the reserve sees (RETIRED, v4) and loses — no lease on a retired wallet.
    expect(retireWallet({ expectedRowVersion: 3, actualRowVersion: 3, state: "AVAILABLE" }).kind).toBe(
      "retired",
    );
    expect(reserveWallet({ expectedRowVersion: 3, actualRowVersion: 4, state: "RETIRED" }).kind).toBe("lost");
  });
});

describe("pressure: restart / crash recovery", () => {
  const restored: PoolWalletDescriptor = {
    keyOrigin: "node_generated",
    recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
    state: "AVAILABLE",
  };
  it("a wallet with a decryptable secret is assignable after boot", () => {
    expect(isAssignable(restored, true)).toBe(true);
    expect(REPLENISHMENT_CRASH_SAFETY.quarantineUndecryptableBeforeSelection).toBe(true);
  });
  it("NEGATIVE: a restored wallet failing the secret probe is quarantined, not assignable", () => {
    expect(isAssignable(restored, false)).toBe(false);
  });
});

describe("pressure: no key deletion — permanence", () => {
  it("key deletion is forbidden and there is no delete transition", () => {
    expect(POOL_KEY_DELETION_ALLOWED).toBe(false);
    for (const [, to] of POOL_WALLET_TRANSITIONS) expect(to).not.toBe("DELETED");
  });
  it("NEGATIVE: a RETIRED wallet is never removed from the cap count (retire->mint frees nothing)", () => {
    expect(countsTowardCap("RETIRED")).toBe(true);
  });
});

describe("pressure: broken-run demo — fail-closed backpressure is load-bearing", () => {
  // A deliberately BROKEN admission with fail-closed backpressure DISABLED: it assigns off the raw
  // pool (minted-but-unverified and PINNED wallets counted as assignable, dropping the recovery-gated eligibility rule
  // recovery gate) and never rejects at cap. Firing the burst, pinned-saturation, and
  // cap-exhaustion scenarios through it at once shows every invariant the real policy holds is held
  // only BECAUSE of the guards — a regression that drops them mis-assigns real ZKZ.
  function brokenAdmission(input: { rawPoolCount: number }): "assign" | "queue" {
    return input.rawPoolCount > 0 ? "assign" : "queue"; // BUG: no recovery gate, no 503 at cap.
  }

  it("fires burst + pinned-saturation + cap-exhaustion at once: broken assigns where the real policy defends", () => {
    // burst off an unverified pool: real policy queues (mint != availability); broken assigns.
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 0, poolCap: 50 }).kind).toBe("queue");
    expect(brokenAdmission({ rawPoolCount: 5 })).toBe("assign");

    // pinned-saturation: real policy queues (0 verified); broken would re-lease a PINNED wallet.
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 3, poolCap: 50 }).kind).toBe("queue");
    expect(brokenAdmission({ rawPoolCount: 3 })).toBe("assign");

    // cap-exhaustion: real policy rejects 503 at cap; broken never fails closed.
    expect(receiveAdmissionDecision({ availableVerifiedCount: 0, queueDepth: 50, poolCap: 50 }).kind).toBe("reject");
    expect(brokenAdmission({ rawPoolCount: 3 })).toBe("assign");
  });
});

const snapshotPath = fileURLToPath(new URL("../../gen/pool-scenarios.json", import.meta.url));

describe("pressure-scenario catalog — snapshot sync + census", () => {
  it("gen/pool-scenarios.json equals POOL_PRESSURE_SCENARIOS", () => {
    expect(JSON.parse(readFileSync(snapshotPath, "utf8"))).toEqual(POOL_PRESSURE_SCENARIOS);
  });
  it("covers all eight pressure-scenario classes with a frozen invariant each", () => {
    expect(POOL_PRESSURE_SCENARIOS.map((s) => s.class)).toEqual([
      "empty_pool",
      "burst_admission",
      "pinned_saturation",
      "cap_exhaustion",
      "concurrent_scalers",
      "retirement",
      "restart_recovery",
      "key_permanence",
    ]);
    for (const scenario of POOL_PRESSURE_SCENARIOS) {
      expect(scenario.invariant.length).toBeGreaterThan(0);
    }
  });
});
