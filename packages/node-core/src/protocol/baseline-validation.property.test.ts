// parity / property coverage for shared MOVE/SEND baseline-validation primitives.
// Absolute post-transfer balances. Proves equivalent shared inputs → equivalent predicate outcomes, and that both
// adapters map those predicates without rewriting reason codes or non-noun detail wording.

import { describe, expect, it } from "vitest";
import { LEASE_ROLES, type LeaseRole } from "@zucoins/generic-node-contracts/wallet-state";

import {
  evaluateActiveLeaseRole,
  evaluatePositiveOperationAmount,
  evaluateSourceBalanceAgainstAmount,
} from "./baseline-validation.js";
import { captureDualBaselines, type DualBaselineInput } from "./move-baseline.js";
import { captureSendBaselines, type SendBaselineInput } from "./send-baseline.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "./wallet-role.js";

const SOURCE = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";

function senderProjection(b: string): WalletStateProjection {
  return { role: "sender", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function moveInput(overrides: Partial<DualBaselineInput> = {}): DualBaselineInput {
  return {
    operationId: "op-move",
    sourceWalletPublicKey: SOURCE,
    destinationWalletPublicKey: DEST,
    sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
    destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
    sourceBaseline: senderProjection("10"),
    destinationBaseline: senderProjection("5"),
    amountZkz: "1",
    capturedAt: 1_700_000_000_000,
    ...overrides,
  };
}

function sendInput(overrides: Partial<SendBaselineInput> = {}): SendBaselineInput {
  return {
    operationId: "op-send",
    sourceWalletPublicKey: SOURCE,
    destinationAddress: DEST,
    sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
    sourceBaseline: senderProjection("10"),
    destinationBaseline: GENESIS_PROJECTION,
    amountZkz: "1",
    capturedAt: 1_700_000_000_000,
    ...overrides,
  };
}

// Deterministic seeded PRNG (mulberry32) — same convention as economic-predicates.property.test.ts.
function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(0x8540a001);

function randomCanonicalPositive(): string {
  const intDigits = 1 + Math.floor(rng() * 6);
  let intPart = String(1 + Math.floor(rng() * 9));
  for (let i = 1; i < intDigits; i += 1) intPart += String(Math.floor(rng() * 10));
  const fracDigits = Math.floor(rng() * 8);
  if (fracDigits === 0) return intPart;
  let frac = "";
  for (let i = 0; i < fracDigits; i += 1) frac += String(Math.floor(rng() * 10));
  frac = frac.replace(/0+$/, "");
  return frac ? `${intPart}.${frac}` : intPart;
}

describe("baseline-validation — source balance primitive", () => {
  it("accepts B0 >= amount and returns canonical re-emit", () => {
    const result = evaluateSourceBalanceAgainstAmount("2.50", "2.5", "move");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.balanceCanonical).toBe("2.5");
  });

  it("rejects invalid observed balance without throwing", () => {
    const result = evaluateSourceBalanceAgainstAmount("not-a-number", "1", "send");
    expect(result).toEqual({
      ok: false,
      reason: "source_baseline_balance_invalid",
      detail: 'source baseline balance "not-a-number" is not a grammar-valid ZKZ amount',
    });
  });

  it("embeds only the operation noun in the insufficient-balance detail", () => {
    const move = evaluateSourceBalanceAgainstAmount("0.5", "1", "move");
    const send = evaluateSourceBalanceAgainstAmount("0.5", "1", "send");
    expect(move).toEqual({
      ok: false,
      reason: "source_insufficient_balance",
      detail: "source balance 0.5 is less than move amount 1",
    });
    expect(send).toEqual({
      ok: false,
      reason: "source_insufficient_balance",
      detail: "source balance 0.5 is less than send amount 1",
    });
  });
});

describe("baseline-validation — positive amount primitive", () => {
  it.each(["0", "0.0", `0.${"0".repeat(32)}`, "3.50", "-1", 3.5])(
    "rejects %j with the shared invalid_amount detail shape",
    (amount) => {
      const result = evaluatePositiveOperationAmount(amount);
      expect(result.ok).toBe(false);
      if (result.ok) return;
      if (typeof amount === "string") {
        expect(result.detail).toBe(
          `amount_zkz "${amount}" is not a canonical positive ZKZ amount`,
        );
      } else {
        expect(result.detail).toBe(
          "amount_zkz is number, expected a canonical positive ZKZ amount string",
        );
      }
    },
  );

  it("accepts a canonical positive amount", () => {
    expect(evaluatePositiveOperationAmount("1.25").ok).toBe(true);
  });
});

describe("baseline-validation — active lease role primitive", () => {
  it("accepts ACTIVE + expected role", () => {
    expect(
      evaluateActiveLeaseRole({ role: "MOVE_SOURCE", lifecycle: "ACTIVE" }, "MOVE_SOURCE", "source")
        .ok,
    ).toBe(true);
  });

  it("labels side in lifecycle and role details", () => {
    const inactive = evaluateActiveLeaseRole(
      { role: "SEND_SOURCE", lifecycle: "RELEASED" },
      "SEND_SOURCE",
      "source",
    );
    expect(inactive).toEqual({
      ok: false,
      kind: "not_active",
      detail: "source lease lifecycle is RELEASED, expected ACTIVE",
    });

    const wrong = evaluateActiveLeaseRole(
      { role: "RECONCILIATION", lifecycle: "ACTIVE" },
      "MOVE_DESTINATION",
      "destination",
    );
    expect(wrong).toEqual({
      ok: false,
      kind: "role_invalid",
      detail: "destination lease role is RECONCILIATION, expected MOVE_DESTINATION",
    });
  });
});

describe("MOVE/SEND adapter parity — shared source-balance + amount", () => {
  const sharedBalanceCases: ReadonlyArray<{
    readonly b: string;
    readonly amount: string;
    readonly sharedReason:
      | "source_insufficient_balance"
      | "source_baseline_balance_invalid"
      | null;
  }> = [
    { b: "10", amount: "1", sharedReason: null },
    { b: "1", amount: "1", sharedReason: null },
    { b: "0.5", amount: "1", sharedReason: "source_insufficient_balance" },
    { b: "2.50", amount: "2.5", sharedReason: null },
    { b: "abc", amount: "1", sharedReason: "source_baseline_balance_invalid" },
    { b: "", amount: "1", sharedReason: "source_baseline_balance_invalid" },
    { b: GENESIS_PROJECTION.B, amount: "0.001", sharedReason: "source_insufficient_balance" },
  ];

  it.each(sharedBalanceCases)(
    "B=$b amount=$amount → same reason on both adapters ($sharedReason)",
    ({ b, amount, sharedReason }) => {
      const move = captureDualBaselines(
        moveInput({ sourceBaseline: senderProjection(b), amountZkz: amount }),
      );
      const send = captureSendBaselines(
        sendInput({ sourceBaseline: senderProjection(b), amountZkz: amount }),
      );

      if (sharedReason === null) {
        expect(move.ok).toBe(true);
        expect(send.ok).toBe(true);
        return;
      }

      expect(move.ok).toBe(false);
      expect(send.ok).toBe(false);
      if (move.ok || send.ok) return;
      expect(move.reason).toBe(sharedReason);
      expect(send.reason).toBe(sharedReason);

      const primitive = evaluateSourceBalanceAgainstAmount(b, amount, "move");
      expect(primitive.ok).toBe(false);
      if (primitive.ok) return;
      expect(primitive.reason).toBe(sharedReason);
      // MOVE detail matches shared primitive with noun "move"; SEND differs only by noun.
      expect(move.detail).toBe(primitive.detail);
      expect(send.detail).toBe(primitive.detail.replace(" move amount ", " send amount "));
    },
  );

  it("invalid_amount detail is byte-identical across MOVE and SEND", () => {
    for (const amount of ["0", "0.0", "3.50", "-1", ""] as const) {
      const move = captureDualBaselines(moveInput({ amountZkz: amount }));
      const send = captureSendBaselines(sendInput({ amountZkz: amount }));
      expect(move.ok).toBe(false);
      expect(send.ok).toBe(false);
      if (move.ok || send.ok) return;
      expect(move.reason).toBe("invalid_amount");
      expect(send.reason).toBe("invalid_amount");
      expect(move.detail).toBe(send.detail);
      const primitive = evaluatePositiveOperationAmount(amount);
      expect(primitive.ok).toBe(false);
      if (primitive.ok) return;
      expect(move.detail).toBe(primitive.detail);
    }
  });

  it("source lease not_active / role_invalid map identically for the source side", () => {
    const releasedMove = captureDualBaselines(
      moveInput({ sourceLease: { role: "MOVE_SOURCE", lifecycle: "RELEASED" } }),
    );
    const releasedSend = captureSendBaselines(
      sendInput({ sourceLease: { role: "SEND_SOURCE", lifecycle: "RELEASED" } }),
    );
    expect(releasedMove.ok).toBe(false);
    expect(releasedSend.ok).toBe(false);
    if (releasedMove.ok || releasedSend.ok) return;
    expect(releasedMove.reason).toBe("source_lease_not_active");
    expect(releasedSend.reason).toBe("source_lease_not_active");
    expect(releasedMove.detail).toBe(releasedSend.detail);

    const wrongMove = captureDualBaselines(
      moveInput({ sourceLease: { role: "RECONCILIATION", lifecycle: "ACTIVE" } }),
    );
    const wrongSend = captureSendBaselines(
      sendInput({ sourceLease: { role: "RECONCILIATION", lifecycle: "ACTIVE" } }),
    );
    expect(wrongMove.ok).toBe(false);
    expect(wrongSend.ok).toBe(false);
    if (wrongMove.ok || wrongSend.ok) return;
    expect(wrongMove.reason).toBe("source_lease_role_invalid");
    expect(wrongSend.reason).toBe("source_lease_role_invalid");
    // Details differ only by expected role token (MOVE_SOURCE vs SEND_SOURCE).
    expect(wrongMove.detail.replace("MOVE_SOURCE", "SEND_SOURCE")).toBe(wrongSend.detail);
  });
});

describe("property — shared balance predicate vs both adapters", () => {
  it("random canonical B/amount pairs agree on accept/reject reason across MOVE, SEND, and primitive", () => {
    for (let i = 0; i < 200; i += 1) {
      const b = randomCanonicalPositive();
      const amount = randomCanonicalPositive();
      const movePrim = evaluateSourceBalanceAgainstAmount(b, amount, "move");
      const sendPrim = evaluateSourceBalanceAgainstAmount(b, amount, "send");

      // Outcome ok/reason identical; detail differs only by operation noun when insufficient.
      expect(movePrim.ok).toBe(sendPrim.ok);
      if (!movePrim.ok && !sendPrim.ok) {
        expect(movePrim.reason).toBe(sendPrim.reason);
        if (movePrim.reason === "source_insufficient_balance") {
          expect(movePrim.detail.replace(" move amount ", " send amount ")).toBe(sendPrim.detail);
        } else {
          expect(movePrim.detail).toBe(sendPrim.detail);
        }
      }

      // Adapters preserve the shared reason when balance/amount is the first failing check.
      // amount is always canonical ZKZ amount contract-canonical positive here, so amount structure never fails first.
      const move = captureDualBaselines(
        moveInput({ sourceBaseline: senderProjection(b), amountZkz: amount }),
      );
      const send = captureSendBaselines(
        sendInput({ sourceBaseline: senderProjection(b), amountZkz: amount }),
      );
      if (movePrim.ok) {
        expect(move.ok).toBe(true);
        expect(send.ok).toBe(true);
      } else if (!sendPrim.ok) {
        expect(move.ok).toBe(false);
        expect(send.ok).toBe(false);
        if (move.ok || send.ok) return;
        expect(move.reason).toBe(movePrim.reason);
        expect(send.reason).toBe(sendPrim.reason);
        expect(move.detail).toBe(movePrim.detail);
        expect(send.detail).toBe(sendPrim.detail);
      } else {
        throw new Error("move/send primitive ok mismatch");
      }
    }
  });

  it("every non-matching lease role yields role_invalid with expectedRole in the detail", () => {
    for (const expected of ["MOVE_SOURCE", "MOVE_DESTINATION", "SEND_SOURCE"] as const) {
      for (const role of LEASE_ROLES.filter((r: LeaseRole) => r !== expected)) {
        const result = evaluateActiveLeaseRole(
          { role, lifecycle: "ACTIVE" },
          expected,
          expected === "MOVE_DESTINATION" ? "destination" : "source",
        );
        expect(result.ok).toBe(false);
        if (result.ok) return;
        expect(result.kind).toBe("role_invalid");
        expect(result.detail).toContain(`expected ${expected}`);
      }
    }
  });
});
