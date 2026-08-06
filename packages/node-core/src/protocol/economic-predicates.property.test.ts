import { describe, expect, it } from "vitest";
import { addAmounts, compareAmounts, subtractAmounts } from "@zucoins/generic-node-contracts";

import { type SplitChainInnerV2 } from "./inner.js";
import {
  evaluateExternalSendDelta,
  evaluateInternalMoveDelta,
  evaluateReceiveDelta,
} from "./economic-predicates.js";

// property/invariant coverage for the receive predicate over a random
// random walk of baselines and amounts. Deterministic seeded PRNG (mulberry32), matching the
// convention in packages/generic-node-contracts/src/amounts/property.test.ts — zero new
// dependencies, reproducible, CI-stable. Fixture arithmetic reuses the frozen
// bignumber.js-backed `addAmounts` (never re-derives decimal math by hand).
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

const rng = mulberry32(0x2545f491);
const RECEIVER = "receiver-pubkey";

function baseInner(overrides: Partial<SplitChainInnerV2>): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: "payer-pubkey",
    step_2_key_public__base64urlsafe: RECEIVER,
    step_1_state: { amount: "0" },
    step_2_state: { amount: "0" },
    previous_step_1_state_signature: "",
    previous_step_2_state_signature: "",
    ...overrides,
  };
}

function randomAmount(maxIntDigits: number): string {
  const intDigits = 1 + Math.floor(rng() * maxIntDigits);
  let intPart = String(1 + Math.floor(rng() * 9));
  for (let i = 1; i < intDigits; i += 1) intPart += String(Math.floor(rng() * 10));
  const fracDigits = 1 + Math.floor(rng() * 32);
  let frac = "";
  for (let i = 0; i < fracDigits; i += 1) frac += String(Math.floor(rng() * 10));
  frac = frac.replace(/0+$/, "");
  return frac ? `${intPart}.${frac}` : intPart;
}

function candidateTxWith(b1: string, previousStepTwo: string) {
  return {
    inner: baseInner({ step_2_state: { amount: b1 }, previous_step_2_state_signature: previousStepTwo }),
    step_1_signature: "s1",
    step_2_signature: "s2",
  };
}

describe("property — evaluateReceiveDelta over a random baseline/amount walk", () => {
  it("B0 + amount as B1, chained by the true prior head, always accepts", () => {
    for (let i = 0; i < 300; i += 1) {
      const b0 = randomAmount(6);
      const amount = randomAmount(2);
      const priorHead = `head-${i}`;
      const b1 = addAmounts(b0, amount);
      const baseline = { role: "receiver" as const, S: priorHead, P: "", B: b0, I: "d" };
      const result = evaluateReceiveDelta({
        baseline,
        candidateTx: candidateTxWith(b1, priorHead),
        reservedWalletPublicKey: RECEIVER,
        operation: { amountZkz: amount, receiverPubkey: RECEIVER },
      });
      expect(result.ok, `b0=${b0} amount=${amount} b1=${b1}`).toBe(true);
    }
  });

  it("any predecessor other than the true prior head always rejects with chain_link_mismatch", () => {
    for (let i = 0; i < 200; i += 1) {
      const b0 = randomAmount(6);
      const amount = randomAmount(2);
      const priorHead = `head-${i}`;
      const wrongPredecessor = `not-${priorHead}`;
      const b1 = addAmounts(b0, amount);
      const baseline = { role: "receiver" as const, S: priorHead, P: "", B: b0, I: "d" };
      const result = evaluateReceiveDelta({
        baseline,
        candidateTx: candidateTxWith(b1, wrongPredecessor),
        reservedWalletPublicKey: RECEIVER,
        operation: { amountZkz: amount, receiverPubkey: RECEIVER },
      });
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("chain_link_mismatch");
    }
  });

  it("crediting one unit more than the operation amount always rejects with balance_delta_mismatch", () => {
    for (let i = 0; i < 200; i += 1) {
      const b0 = randomAmount(4);
      const amount = randomAmount(2);
      const excess = randomAmount(1);
      const priorHead = `head-${i}`;
      const wrongB1 = addAmounts(addAmounts(b0, amount), excess);
      const baseline = { role: "receiver" as const, S: priorHead, P: "", B: b0, I: "d" };
      const result = evaluateReceiveDelta({
        baseline,
        candidateTx: candidateTxWith(wrongB1, priorHead),
        reservedWalletPublicKey: RECEIVER,
        operation: { amountZkz: amount, receiverPubkey: RECEIVER },
      });
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("balance_delta_mismatch");
    }
  });
});

const SOURCE_PROP = "source-pubkey-prop";
const DESTINATION_PROP = "destination-pubkey-prop";

function moveInnerFor(overrides: Partial<SplitChainInnerV2>): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: SOURCE_PROP,
    step_2_key_public__base64urlsafe: DESTINATION_PROP,
    step_1_state: { amount: "0" },
    step_2_state: { amount: "0" },
    previous_step_1_state_signature: "",
    previous_step_2_state_signature: "",
    ...overrides,
  };
}

describe("property — evaluateInternalMoveDelta over random baseline/amount walks", () => {
  it("correct dual-delta with matching chains always accepts", () => {
    for (let i = 0; i < 200; i += 1) {
      const srcB0 = randomAmount(5);
      const dstB0 = randomAmount(5);
      const amount = randomAmount(2);
      const srcPrior = `src-head-${i}`;
      const dstPrior = `dst-head-${i}`;
      // Partial-debit: srcB0 has up to 5 integer digits and amount up to 2, so amount is
      // almost always strictly less than srcB0 — clamp the rare overshoot down to srcB0 (a
      // full debit) so subtractAmounts never goes negative. This exercises the general
      // partial-debit case (srcB1 > "0") the prior full-debit-only fixture never covered.
      const srcAmount = compareAmounts(amount, srcB0) === 1 ? srcB0 : amount;
      const srcB1 = subtractAmounts(srcB0, srcAmount); // B0 - amount
      const dstB1 = addAmounts(dstB0, srcAmount); // destination receives srcAmount

      const srcBaseline = { role: "sender" as const, S: srcPrior, P: "", B: srcB0, I: "d" };
      const dstBaseline = { role: "receiver" as const, S: dstPrior, P: "", B: dstB0, I: "d" };

      const candidateTx = {
        inner: moveInnerFor({
          step_1_state: { amount: srcB1 },
          step_2_state: { amount: dstB1 },
          previous_step_1_state_signature: srcPrior,
          previous_step_2_state_signature: dstPrior,
        }),
        step_1_signature: "s1",
        step_2_signature: "move-sig",
      };

      const result = evaluateInternalMoveDelta({
        source: { baseline: srcBaseline, candidateTx, walletPublicKey: SOURCE_PROP },
        destination: { baseline: dstBaseline, candidateTx, walletPublicKey: DESTINATION_PROP },
        operation: { amountZkz: srcAmount, sourcePubkey: SOURCE_PROP, destinationPubkey: DESTINATION_PROP },
      });
      expect(result.ok, `srcB0=${srcB0} amount=${srcAmount} dstB1=${dstB1}`).toBe(true);
    }
  });

  it("wrong source predecessor always rejects with chain_link_mismatch", () => {
    for (let i = 0; i < 100; i += 1) {
      const srcPrior = `src-head-${i}`;
      const wrongPrior = `not-${srcPrior}`;
      const srcBaseline = { role: "sender" as const, S: srcPrior, P: "", B: "5", I: "d" };
      const dstBaseline = { role: "receiver" as const, S: "dst-prior", P: "", B: "1", I: "d" };

      const candidateTx = {
        inner: moveInnerFor({
          step_1_state: { amount: "3" },
          step_2_state: { amount: "3" },
          previous_step_1_state_signature: wrongPrior,
          previous_step_2_state_signature: "dst-prior",
        }),
        step_1_signature: "s1",
        step_2_signature: "move-sig",
      };

      const result = evaluateInternalMoveDelta({
        source: { baseline: srcBaseline, candidateTx, walletPublicKey: SOURCE_PROP },
        destination: { baseline: dstBaseline, candidateTx, walletPublicKey: DESTINATION_PROP },
        operation: { amountZkz: "2", sourcePubkey: SOURCE_PROP, destinationPubkey: DESTINATION_PROP },
      });
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("chain_link_mismatch");
    }
  });
});

describe("property — evaluateExternalSendDelta over random baseline/amount walks", () => {
  const EXTERNAL = "external-addr-prop";

  it("correct debit with matching chain always accepts", () => {
    for (let i = 0; i < 200; i += 1) {
      const b0 = randomAmount(5);
      const amount = b0; // full-debit: B1 = "0"
      const priorHead = `send-head-${i}`;
      const baseline = { role: "sender" as const, S: priorHead, P: "", B: b0, I: "d" };
      const candidateTx = {
        inner: moveInnerFor({
          step_1_key_public__base64urlsafe: SOURCE_PROP,
          step_2_key_public__base64urlsafe: EXTERNAL,
          step_1_state: { amount: "0" },
          step_2_state: { amount: b0 },
          previous_step_1_state_signature: priorHead,
        }),
        step_1_signature: "s1",
        step_2_signature: "send-sig",
      };
      const result = evaluateExternalSendDelta({
        baseline,
        candidateTx,
        sourceWalletPublicKey: SOURCE_PROP,
        operation: { amountZkz: amount, sourcePubkey: SOURCE_PROP, destinationAddress: EXTERNAL },
      });
      expect(result.ok, `b0=${b0} amount=${amount}`).toBe(true);
    }
  });

  it("wrong chain link always rejects with chain_link_mismatch", () => {
    for (let i = 0; i < 100; i += 1) {
      const priorHead = `send-head-${i}`;
      const wrongPrior = `not-${priorHead}`;
      const baseline = { role: "sender" as const, S: priorHead, P: "", B: "5", I: "d" };
      const candidateTx = {
        inner: moveInnerFor({
          step_1_key_public__base64urlsafe: SOURCE_PROP,
          step_2_key_public__base64urlsafe: EXTERNAL,
          step_1_state: { amount: "3" },
          step_2_state: { amount: "2" },
          previous_step_1_state_signature: wrongPrior,
        }),
        step_1_signature: "s1",
        step_2_signature: "send-sig",
      };
      const result = evaluateExternalSendDelta({
        baseline,
        candidateTx,
        sourceWalletPublicKey: SOURCE_PROP,
        operation: { amountZkz: "2", sourcePubkey: SOURCE_PROP, destinationAddress: EXTERNAL },
      });
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("chain_link_mismatch");
    }
  });
});
