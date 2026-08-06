import { describe, expect, it } from "vitest";

import { type SettledSplitChainTransaction, type SplitChainInnerV2 } from "./inner.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "./wallet-role.js";
import {
  evaluateExternalSendDelta,
  evaluateInternalMoveDelta,
  evaluateReceiveDelta,
} from "./economic-predicates.js";

const RECEIVER = "receiver-pubkey";
const SOURCE = "source-pubkey";
const DESTINATION = "destination-pubkey";
const PAYER = "payer-pubkey";
const EXTERNAL_ADDRESS = "external-address-pubkey";

function innerOf(overrides: Partial<SplitChainInnerV2>): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: PAYER,
    step_2_key_public__base64urlsafe: RECEIVER,
    step_1_state: { amount: "0" },
    step_2_state: { amount: "0" },
    previous_step_1_state_signature: "",
    previous_step_2_state_signature: "",
    ...overrides,
  };
}

function txOf(inner: SplitChainInnerV2, stepTwoSig = "step-2-sig"): SettledSplitChainTransaction {
  return { inner, step_1_signature: "step-1-sig", step_2_signature: stepTwoSig };
}

describe("evaluateReceiveDelta — receive delta rules", () => {
  const operation = { amountZkz: "3.5", receiverPubkey: RECEIVER };

  it("accepts exact P1==S0 and B1-B0==amount from genesis", () => {
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: "3.5" }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({ baseline: GENESIS_PROJECTION, candidateTx, reservedWalletPublicKey: RECEIVER, operation });
    expect(result).toEqual({ ok: true });
  });

  it("accepts a non-genesis baseline chained by S/P", () => {
    const baseline: WalletStateProjection = { role: "receiver", S: "prior-head-sig", P: "", B: "10", I: "digest" };
    const candidateTx = txOf(
      innerOf({
        step_2_key_public__base64urlsafe: RECEIVER,
        step_2_state: { amount: "13.5" },
        previous_step_2_state_signature: "prior-head-sig",
      }),
    );
    const result = evaluateReceiveDelta({ baseline, candidateTx, reservedWalletPublicKey: RECEIVER, operation });
    expect(result).toEqual({ ok: true });
  });

  it("NEGATIVE: rejects a one-unit-at-32dp balance mismatch", () => {
    // "3.5" is 3.5000...0 (32 fractional digits); this differs by exactly one unit in the
    // 32nd (last) decimal place — exactly the vector the amount grammar requires.
    const wrongAmount = "3." + "5" + "0".repeat(30) + "1";
    expect(wrongAmount.split(".")[1]).toHaveLength(32);
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: wrongAmount }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({ baseline: GENESIS_PROJECTION, candidateTx, reservedWalletPublicKey: RECEIVER, operation });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("balance_delta_mismatch");
  });

  it("NEGATIVE: wrong predecessor (stale-head / changed-later-head projection) is chain_link_mismatch", () => {
    const candidateTx = txOf(
      innerOf({
        step_2_key_public__base64urlsafe: RECEIVER,
        step_2_state: { amount: "3.5" },
        previous_step_2_state_signature: "some-other-head",
      }),
    );
    const result = evaluateReceiveDelta({ baseline: GENESIS_PROJECTION, candidateTx, reservedWalletPublicKey: RECEIVER, operation });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("chain_link_mismatch");
  });

  it("NEGATIVE: wrong wallet queried against the candidate transaction is wallet_role_invalid", () => {
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: "3.5" }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({
      baseline: GENESIS_PROJECTION,
      candidateTx,
      reservedWalletPublicKey: "not-the-receiver",
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
  });

  it("NEGATIVE: candidate transaction's step_2 key does not equal operation.receiver_pubkey is artifact_binding_mismatch", () => {
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: "3.5" }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({
      baseline: GENESIS_PROJECTION,
      candidateTx,
      reservedWalletPublicKey: RECEIVER,
      operation: { amountZkz: "3.5", receiverPubkey: "someone-else" },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("artifact_binding_mismatch");
  });

  it("NEGATIVE: an operation amount of \"0\" fails invalid_operation_amount (strictly positive per the amount grammar)", () => {
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: "0" }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({
      baseline: GENESIS_PROJECTION,
      candidateTx,
      reservedWalletPublicKey: RECEIVER,
      operation: { amountZkz: "0", receiverPubkey: RECEIVER },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_operation_amount");
  });
});

describe("evaluateInternalMoveDelta — internal-move delta rules", () => {
  const operation = { amountZkz: "2", sourcePubkey: SOURCE, destinationPubkey: DESTINATION };
  const sourceBaseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "5", I: "d" };
  const destinationBaseline: WalletStateProjection = { role: "receiver", S: "dest-prior-sig", P: "", B: "1", I: "d" };

  function movePairFor(overrides: { sourceAmount?: string; destinationAmount?: string; sourcePrev?: string; destPrev?: string; stepTwoSig?: string } = {}) {
    const inner = innerOf({
      step_1_key_public__base64urlsafe: SOURCE,
      step_2_key_public__base64urlsafe: DESTINATION,
      step_1_state: { amount: overrides.sourceAmount ?? "3" },
      step_2_state: { amount: overrides.destinationAmount ?? "3" },
      previous_step_1_state_signature: overrides.sourcePrev ?? "source-prior-sig",
      previous_step_2_state_signature: overrides.destPrev ?? "dest-prior-sig",
    });
    return txOf(inner, overrides.stepTwoSig ?? "move-step-2-sig");
  }

  it("accepts exact dual delta with matching P/S chains on both legs", () => {
    const candidateTx = movePairFor();
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result).toEqual({ ok: true });
  });

  it("accepts a spawned move whose previous_step_1_state_signature matches the parent receive's step_2_signature", () => {
    const candidateTx = movePairFor({ sourcePrev: "parent-receive-step-2-sig" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: { ...sourceBaseline, S: "parent-receive-step-2-sig" }, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
      spawnedFromReceive: { receiveTransactionStepTwoSignature: "parent-receive-step-2-sig" },
    });
    expect(result).toEqual({ ok: true });
  });

  it("NEGATIVE: spawned move continuity mismatch when previous_step_1 does not equal the parent's step_2_signature", () => {
    const candidateTx = movePairFor({ sourcePrev: "source-prior-sig" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
      spawnedFromReceive: { receiveTransactionStepTwoSignature: "parent-receive-step-2-sig" },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("spawn_continuity_mismatch");
  });

  it("NEGATIVE: dual-wallet equality — source and destination observed in different transactions is same_transaction_mismatch", () => {
    const sourceTx = movePairFor({ stepTwoSig: "sig-A" });
    const destinationTx = movePairFor({ stepTwoSig: "sig-B" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx: sourceTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx: destinationTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("same_transaction_mismatch");
  });

  it("NEGATIVE: wrong predecessor on the source leg is chain_link_mismatch", () => {
    const candidateTx = movePairFor({ sourcePrev: "wrong-prior-sig" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("chain_link_mismatch");
  });

  it("NEGATIVE: source and destination delta mismatch is balance_delta_mismatch", () => {
    const candidateTx = movePairFor({ destinationAmount: "2.99" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("balance_delta_mismatch");
  });

  it("NEGATIVE: querying the wrong wallet for a leg is wallet_role_invalid", () => {
    const candidateTx = movePairFor();
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: "not-the-source" },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
  });

  it("NEGATIVE: destination wallet resolving to a non-receiver role is wallet_role_invalid, attributed to the destination leg", () => {
    // The source leg is untouched and valid (walletPublicKey: SOURCE resolves "sender" on
    // this tx) — only the destination leg is queried with SOURCE's own key, which resolves
    // to "sender" (step_1) rather than "receiver" (step_2) on the SAME shared transaction.
    // This exercises economic-predicates.ts's destination-leg branch
    // (`if (destinationProjected.projection.role !== "receiver")`), which the source-leg
    // test above never reaches — that one fails earlier, inside the source-leg check.
    //
    // craftedDestinationBaseline is chosen so that if the destination-role guard were
    // removed, projectRoleRelativeState's "sender" projection (S=step_2_signature,
    // P=previous_step_1_state_signature="source-prior-sig", B=step_1_state.amount="3") would
    // satisfy BOTH the chain-link check (P == baseline.S) and the exact-delta check
    // (candidate.B - baseline.B == operation.amountZkz, i.e. "3" - "1" == "2") — so a guard
    // removal doesn't just change the rejection reason, it flips the whole call to ok:true.
    const candidateTx = movePairFor();
    const craftedDestinationBaseline: WalletStateProjection = {
      role: "receiver",
      S: "source-prior-sig",
      P: "",
      B: "1",
      I: "d",
    };
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: craftedDestinationBaseline, candidateTx, walletPublicKey: SOURCE },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
    expect(!result.ok && result.detail).toContain("destination wallet must be step-2 receiver");
  });

  it("NEGATIVE: source step_1 key != operation.sourcePubkey is artifact_binding_mismatch", () => {
    // innerOf defaults step_1_key to PAYER, but movePairFor overrides to SOURCE.
    // Override to a wrong key to trigger the source-binding check.
    const inner = innerOf({
      step_1_key_public__base64urlsafe: "wrong-source-key",
      step_2_key_public__base64urlsafe: DESTINATION,
      step_1_state: { amount: "3" },
      step_2_state: { amount: "3" },
      previous_step_1_state_signature: "source-prior-sig",
      previous_step_2_state_signature: "dest-prior-sig",
    });
    const candidateTx = txOf(inner, "move-step-2-sig");
    // Source wallet must resolve to "sender" role — use the wrong key as the wallet identity
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: "wrong-source-key" },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("artifact_binding_mismatch");
  });

  it("NEGATIVE: destination step_2 key != operation.destinationPubkey is artifact_binding_mismatch", () => {
    const inner = innerOf({
      step_1_key_public__base64urlsafe: SOURCE,
      step_2_key_public__base64urlsafe: "wrong-destination-key",
      step_1_state: { amount: "3" },
      step_2_state: { amount: "3" },
      previous_step_1_state_signature: "source-prior-sig",
      previous_step_2_state_signature: "dest-prior-sig",
    });
    const candidateTx = txOf(inner, "move-step-2-sig");
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: {
        baseline: destinationBaseline,
        candidateTx,
        walletPublicKey: "wrong-destination-key",
      },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("artifact_binding_mismatch");
  });

  it("NEGATIVE: source-leg debit mismatch (B0-B1 != amount) is balance_delta_mismatch", () => {
    // Source baseline B=5, source candidate post-state should be 3 (debit 2), but set to 3.01
    const candidateTx = movePairFor({ sourceAmount: "3.01" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("balance_delta_mismatch");
  });

  it("NEGATIVE: destination-leg wrong predecessor is chain_link_mismatch", () => {
    // Source chain passes (sourcePrev matches sourceBaseline.S),
    // but destination previous_step_2_state_signature does NOT match destinationBaseline.S
    const candidateTx = movePairFor({ destPrev: "wrong-dest-prior-sig" });
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("chain_link_mismatch");
  });

  it("NEGATIVE: operation amount \"0\" fails invalid_operation_amount", () => {
    const candidateTx = movePairFor();
    const result = evaluateInternalMoveDelta({
      source: { baseline: sourceBaseline, candidateTx, walletPublicKey: SOURCE },
      destination: { baseline: destinationBaseline, candidateTx, walletPublicKey: DESTINATION },
      operation: { amountZkz: "0", sourcePubkey: SOURCE, destinationPubkey: DESTINATION },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_operation_amount");
  });
});

describe("evaluateExternalSendDelta — external-send delta rules", () => {
  const operation = { amountZkz: "4", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS };
  const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "10", I: "d" };

  it("accepts exact B0-B1==amount with the external destination bound", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "6" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({ baseline, candidateTx, sourceWalletPublicKey: SOURCE, operation });
    expect(result).toEqual({ ok: true });
  });

  it("NEGATIVE: destination address mismatch is artifact_binding_mismatch", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: "a-different-address",
        step_1_state: { amount: "6" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({ baseline, candidateTx, sourceWalletPublicKey: SOURCE, operation });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("artifact_binding_mismatch");
  });

  it("NEGATIVE: debit mismatch (B0-B1 != amount) is balance_delta_mismatch", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "6.01" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({ baseline, candidateTx, sourceWalletPublicKey: SOURCE, operation });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("balance_delta_mismatch");
  });

  it("NEGATIVE: wrong predecessor (baseline.S != candidate.P) is chain_link_mismatch", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "6" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "wrong-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({ baseline, candidateTx, sourceWalletPublicKey: SOURCE, operation });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("chain_link_mismatch");
  });

  it("NEGATIVE: source step_1 key != operation.sourcePubkey is artifact_binding_mismatch", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: "wrong-source-key",
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "6" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: "wrong-source-key",
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("artifact_binding_mismatch");
  });

  it("NEGATIVE: operation amount \"0\" fails invalid_operation_amount", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "10" },
        step_2_state: { amount: "10" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "0", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_operation_amount");
  });

  it("NEGATIVE: wrong wallet queried (not sender) is wallet_role_invalid", () => {
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "6" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: "not-the-sender",
      operation,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
  });
});

// money-path defense-in-depth: `checkExactDelta` re-validates BOTH delta operands as
// non-negative canonical balance scalars, so a signed-but-negative balance scalar cannot make a
// difference "land" on the operation amount and approve an overspend. Zero remains legitimate
// (validateBalanceAmount, not validateOperationAmount) for genesis / swept wallets.
describe("balance-scalar non-negativity in checkExactDelta", () => {
  it("NEGATIVE: a negative candidate post-state balance is rejected invalid_balance_scalar (overspend PoC)", () => {
    // Breaking input: baseline.B="3", amount="4", candidate.B="-1" ⇒ subtractAmounts("3","-1")="4"
    // once satisfied the delta equality and returned ok:true — a 4-ZKZ send from a 3-ZKZ balance.
    const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "3", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "-1" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "4", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_balance_scalar");
  });

  it("NEGATIVE: a negative baseline.B (caller-supplied operand) is rejected invalid_balance_scalar", () => {
    const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "-1", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "5" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "4", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_balance_scalar");
  });

  it("accepts a full-balance send leaving candidate post-state \"0\" (zero subtrahend not false-rejected)", () => {
    const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "4", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "0" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "4", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result).toEqual({ ok: true });
  });

  it("accepts a genesis receive with baseline.B \"0\" (zero caller-supplied operand not false-rejected)", () => {
    const candidateTx = txOf(
      innerOf({ step_2_key_public__base64urlsafe: RECEIVER, step_2_state: { amount: "3.5" }, previous_step_2_state_signature: "" }),
    );
    const result = evaluateReceiveDelta({
      baseline: GENESIS_PROJECTION,
      candidateTx,
      reservedWalletPublicKey: RECEIVER,
      operation: { amountZkz: "3.5", receiverPubkey: RECEIVER },
    });
    expect(result).toEqual({ ok: true });
  });
});

// the delta predicate's balance operands (a baseline.B projection and a candidate
// post-state) are OBSERVED foreign-signed scalars, so checkExactDelta validates them by the
// grammar ALONE (pattern; the byte-exact signing rule): a legitimately non-canonical spelling
// such as "2.50" is admitted rather than false-rejected into a stuck settlement, while the grammar
// still rejects sign/exponent/out-of-range forms (preserving the overspend defense). The
// delta comparison itself remains exact numeric equality, so formatting can never hide a mismatch.
describe("grammar-only balance validation at the observation boundary", () => {
  it("accepts a non-canonical observed baseline balance \"2.50\" (previously rejected non-canonical)", () => {
    const baseline: WalletStateProjection = { role: "receiver", S: "prior-head-sig", P: "", B: "2.50", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_2_key_public__base64urlsafe: RECEIVER,
        step_2_state: { amount: "4" },
        previous_step_2_state_signature: "prior-head-sig",
      }),
    );
    const result = evaluateReceiveDelta({
      baseline,
      candidateTx,
      reservedWalletPublicKey: RECEIVER,
      operation: { amountZkz: "1.5", receiverPubkey: RECEIVER },
    });
    expect(result).toEqual({ ok: true });
  });

  it("accepts the specific foreign-signed \"7.50\" balance flowing through the observation boundary", () => {
    const baseline: WalletStateProjection = { role: "receiver", S: "prior-head-sig", P: "", B: "7.50", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_2_key_public__base64urlsafe: RECEIVER,
        step_2_state: { amount: "9" },
        previous_step_2_state_signature: "prior-head-sig",
      }),
    );
    const result = evaluateReceiveDelta({
      baseline,
      candidateTx,
      reservedWalletPublicKey: RECEIVER,
      operation: { amountZkz: "1.5", receiverPubkey: RECEIVER },
    });
    expect(result).toEqual({ ok: true });
  });

  it("accepts a non-canonical observed baseline \"3.50\" on the send (debit) leg", () => {
    const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "3.50", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "1" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "2.5", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result).toEqual({ ok: true });
  });

  it("NEGATIVE: a grammar-invalid observed baseline balance is still rejected invalid_balance_scalar", () => {
    const baseline: WalletStateProjection = { role: "sender", S: "source-prior-sig", P: "", B: "1e5", I: "d" };
    const candidateTx = txOf(
      innerOf({
        step_1_key_public__base64urlsafe: SOURCE,
        step_2_key_public__base64urlsafe: EXTERNAL_ADDRESS,
        step_1_state: { amount: "1" },
        step_2_state: { amount: "4" },
        previous_step_1_state_signature: "source-prior-sig",
      }),
    );
    const result = evaluateExternalSendDelta({
      baseline,
      candidateTx,
      sourceWalletPublicKey: SOURCE,
      operation: { amountZkz: "2.5", sourcePubkey: SOURCE, destinationAddress: EXTERNAL_ADDRESS },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("invalid_balance_scalar");
  });
});
