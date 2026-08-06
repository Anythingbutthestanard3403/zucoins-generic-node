import { describe, expect, it } from "vitest";

import {
  isOperationRole,
  LEASE_ROLES,
  type LeaseRole,
  type WalletLease,
} from "@zucoins/generic-node-contracts/wallet-state";

import { constructMoveInner } from "./move-inner.js";
import { captureDualBaselines, type DualBaselineInput } from "./move-baseline.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "./wallet-role.js";

// Valid wallet public keys (same fixtures as move-form-inner) so constructMoveInner can run.
const SOURCE = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DEST = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";

/** Valid padded Ed25519 signature — shared S so role cannot change formed bytes. */
const HEAD_S =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";

const NODE_CLOCK_MS = 1_784_332_800_000;

const activeSourceLease: WalletLease = { role: "MOVE_SOURCE", lifecycle: "ACTIVE" };
const activeDestLease: WalletLease = { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" };

function senderProjection(b: string): WalletStateProjection {
  return { role: "sender", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function receiverProjection(b: string): WalletStateProjection {
  return { role: "receiver", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function headProjection(
  role: "sender" | "receiver",
  b: string,
  s: string = HEAD_S,
): WalletStateProjection {
  return { role, S: s, P: s, B: b, I: "digest" };
}

function inputOf(overrides: Partial<DualBaselineInput> = {}): DualBaselineInput {
  return {
    operationId: "op-1",
    sourceWalletPublicKey: SOURCE,
    destinationWalletPublicKey: DEST,
    sourceLease: activeSourceLease,
    destinationLease: activeDestLease,
    sourceBaseline: senderProjection("10"),
    destinationBaseline: receiverProjection("5"),
    amountZkz: "3.5",
    capturedAt: 1700000000000,
    ...overrides,
  };
}

describe("captureDualBaselines — step 3 predicates", () => {
  it("captures both baselines when every precondition holds", () => {
    const result = captureDualBaselines(inputOf());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.capture.operationId).toBe("op-1");
    expect(result.capture.sourceBaseline.B).toBe("10");
    expect(result.capture.destinationBaseline.B).toBe("5");
    expect(result.capture.amountZkz).toBe("3.5");
    expect(result.capture.capturedAt).toBe(1700000000000);
  });

  it("rejects a genesis source baseline for any positive amount (B0 = 0)", () => {
    const result = captureDualBaselines(
      inputOf({
        sourceBaseline: GENESIS_PROJECTION,
        destinationBaseline: GENESIS_PROJECTION,
        amountZkz: "0.001",
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_insufficient_balance");
  });

  it("accepts a genesis destination against a funded source", () => {
    const result = captureDualBaselines(
      inputOf({ destinationBaseline: GENESIS_PROJECTION, amountZkz: "1" }),
    );
    expect(result.ok).toBe(true);
  });

  it("carries the amount into the capture verbatim", () => {
    // The artifact is built from the capture, so the capture must hold the exact text the
    // operation carries — the canonical ZKZ amount contract parser validates and brands, it never rewrites.
    const result = captureDualBaselines(inputOf({ amountZkz: "0.00000001" }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.capture.amountZkz).toBe("0.00000001");
  });
});

describe("lease preconditions — the one-in-flight-per-wallet rule", () => {
  it("rejects a released source lease", () => {
    const result = captureDualBaselines(
      inputOf({ sourceLease: { role: "MOVE_SOURCE", lifecycle: "RELEASED" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_not_active");
  });

  it("rejects a released destination lease", () => {
    const result = captureDualBaselines(
      inputOf({ destinationLease: { role: "MOVE_DESTINATION", lifecycle: "RELEASED" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("destination_lease_not_active");
  });

  // RECONCILIATION is observation-only and never pins a wallet, so an ACTIVE RECONCILIATION pair
  // would admit a move that holds no wallet at all. Lifecycle alone cannot see that.
  const wrongSourceRoles = LEASE_ROLES.filter((role) => role !== "MOVE_SOURCE");
  it.each(wrongSourceRoles)("rejects an ACTIVE %s lease on the source", (role: LeaseRole) => {
    const result = captureDualBaselines(inputOf({ sourceLease: { role, lifecycle: "ACTIVE" } }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_role_invalid");
  });

  const wrongDestRoles = LEASE_ROLES.filter((role) => role !== "MOVE_DESTINATION");
  it.each(wrongDestRoles)("rejects an ACTIVE %s lease on the destination", (role: LeaseRole) => {
    const result = captureDualBaselines(
      inputOf({ destinationLease: { role, lifecycle: "ACTIVE" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("destination_lease_role_invalid");
  });

  // Parity guard: the two roles this module demands must both still be pinning operation roles
  // in the frozen vocabulary. If either were ever reclassified observation-only, requiring it
  // would stop enforcing the one-in-flight-per-wallet rule and this fails instead of passing silently.
  it("requires two roles that the frozen contract classifies as pinning", () => {
    expect(isOperationRole("MOVE_SOURCE")).toBe(true);
    expect(isOperationRole("MOVE_DESTINATION")).toBe(true);
    expect(isOperationRole("RECONCILIATION")).toBe(false);
  });
});

describe("amount contract", () => {
  // Verbatim the canonical ZKZ amount contract clause-1 zero-form set: each is `<> '0'` as a string while being
  // mathematically zero, which a hand-rolled decimal grammar accepts.
  const zeroForms = ["0", "0.0", "0.00000000", `0.${"0".repeat(32)}`];
  it.each(zeroForms)("rejects the zero-valued amount %s", (amount) => {
    const result = captureDualBaselines(inputOf({ amountZkz: amount }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("invalid_amount");
  });

  const outOfContract = [
    "100000000", // == UPPER_BOUND_EXCLUSIVE
    `1.${"1".repeat(33)}`, // 33 fractional digits
    "3.50", // non-canonical spelling of a node-authored amount
    "-1",
    "1e3",
    "01",
    "",
    " 1",
  ];
  it.each(outOfContract)("rejects the out-of-contract amount %j", (amount) => {
    const result = captureDualBaselines(inputOf({ amountZkz: amount }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("invalid_amount");
  });

  it("rejects a non-string amount", () => {
    const result = captureDualBaselines(inputOf({ amountZkz: 3.5 as unknown as string }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("invalid_amount");
  });

  it("accepts the largest in-contract amount", () => {
    const result = captureDualBaselines(
      inputOf({ sourceBaseline: senderProjection("99999999.9"), amountZkz: "99999999.9" }),
    );
    expect(result.ok).toBe(true);
  });
});

describe("exact-decimal balance comparison — step 3", () => {
  it("accepts B0 == amount", () => {
    const result = captureDualBaselines(
      inputOf({ sourceBaseline: senderProjection("2.5"), amountZkz: "2.5" }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects B0 one smallest unit below amount", () => {
    const result = captureDualBaselines(
      inputOf({
        sourceBaseline: senderProjection(`2.${"0".repeat(31)}9`),
        amountZkz: "2.1",
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_insufficient_balance");
  });

  it("compares by value, not by lexical text", () => {
    // "10" < "9" lexically; 10 > 9 numerically. A string comparison would reject this.
    const result = captureDualBaselines(
      inputOf({ sourceBaseline: senderProjection("10"), amountZkz: "9" }),
    );
    expect(result.ok).toBe(true);
  });

  it("accepts a non-canonical observed balance spelling without re-judging it", () => {
    // Foreign-signed bytes may legitimately read "2.50" (the byte-exact signing rule); the node
    // re-emits canonically for arithmetic rather than treating the spelling as invalid.
    const result = captureDualBaselines(
      inputOf({ sourceBaseline: senderProjection("2.50"), amountZkz: "2.5" }),
    );
    expect(result.ok).toBe(true);
  });

  const unusableBalances = ["", "abc", "1.2.3", "-4"];
  it.each(unusableBalances)("rejects rather than throws on the unusable balance %j", (b) => {
    const result = captureDualBaselines(inputOf({ sourceBaseline: senderProjection(b) }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_baseline_balance_invalid");
  });
});

describe("wallet and projection preconditions", () => {
  it("rejects a self-move", () => {
    const result = captureDualBaselines(inputOf({ destinationWalletPublicKey: SOURCE }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("same_wallet");
  });

  it.each(["sender", "receiver", "genesis"] as const)(
    "accepts a source baseline whose role is %s when balance is sufficient",
    (role) => {
      const sourceBaseline =
        role === "genesis"
          ? { ...GENESIS_PROJECTION, B: "10" }
          : headProjection(role, "10");
      const result = captureDualBaselines(inputOf({ sourceBaseline }));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.capture.sourceBaseline.role).toBe(role);
    },
  );

  it.each(["sender", "receiver", "genesis"] as const)(
    "accepts a destination baseline whose role is %s",
    (role) => {
      const destinationBaseline =
        role === "genesis" ? GENESIS_PROJECTION : headProjection(role, "5");
      const result = captureDualBaselines(inputOf({ destinationBaseline }));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.capture.destinationBaseline.role).toBe(role);
    },
  );

  it("forms a byte-identical inner whether the source head projects sender or receiver", () => {
    const senderCapture = captureDualBaselines(
      inputOf({
        sourceBaseline: headProjection("sender", "10"),
        destinationBaseline: GENESIS_PROJECTION,
      }),
    );
    const receiverCapture = captureDualBaselines(
      inputOf({
        sourceBaseline: headProjection("receiver", "10"),
        destinationBaseline: GENESIS_PROJECTION,
      }),
    );
    expect(senderCapture.ok).toBe(true);
    expect(receiverCapture.ok).toBe(true);
    if (!senderCapture.ok || !receiverCapture.ok) return;

    const senderInner = constructMoveInner({
      capture: senderCapture.capture,
      nodeClockMs: NODE_CLOCK_MS,
    });
    const receiverInner = constructMoveInner({
      capture: receiverCapture.capture,
      nodeClockMs: NODE_CLOCK_MS,
    });
    expect(receiverInner.innerPreimageText).toBe(senderInner.innerPreimageText);
    expect(receiverInner.innerSha256).toBe(senderInner.innerSha256);
  });

  it("checks the lease before the amount, so a wrong-role lease is never masked", () => {
    const result = captureDualBaselines(
      inputOf({ sourceLease: { role: "RECONCILIATION", lifecycle: "ACTIVE" }, amountZkz: "0" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_role_invalid");
  });
});
