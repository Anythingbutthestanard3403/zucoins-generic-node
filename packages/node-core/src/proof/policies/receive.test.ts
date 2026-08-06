// Item 1 for RECEIVE_EXTERNAL: "receive accepts exact
// `previous_step_2 == S0` and exact `B1-B0`; rejects one-unit-at-32dp mismatch", plus one
// falsification per frozen predicate. Every transaction here is really Ed25519-signed
// over its real preimages (test-transactions.ts), so a mutation that should fail fails
// because the cryptography says so, not because a fixture was edited to say so.
import { transferCodeSha256 } from "@zucoins/generic-node-contracts/transfer-code";
import { describe, expect, it } from "vitest";

import { verifySettledTransaction } from "../../verifier/transaction-verify.js";
import { RECEIVE_EXTERNAL_POLICY } from "../policies.js";
import type { PredicateId } from "../types.js";
import { evaluateReceiveProof, type ReceivePolicyInput, type ReceiverBaseline } from "./receive.js";
import { buildTransaction, parseSettled, publicKeyFromSeed, signText } from "./test-transactions.js";

const RECEIVER_SEED = 0x02;
const RECEIVER = publicKeyFromSeed(RECEIVER_SEED);
const DISCRIMINATOR = "33333333-3333-4333-8333-333333333333";
const ANCHOR = "ord_7YQ3";
const TRANSFER_CODE = "eyJhbW91bnQiOiIwLjUifQ";
const EXPIRY = "1784336400";
const OBSERVED_AT = 1_784_332_800;
const ONE_UNIT_AT_32DP = `0.${"0".repeat(31)}1`;

// The receiver's prior accepted state: a real earlier transaction crediting it 10 ZKZ.
const PREDECESSOR = buildTransaction({
  senderSeed: 0x03,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "10",
});

function baselineFrom(built: typeof PREDECESSOR): ReceiverBaseline {
  const verdict = verifySettledTransaction(built.parsed, RECEIVER);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture did not verify: ${verdict.verdict}`);
  return {
    projection: verdict.projection,
    semanticFingerprint: verdict.semanticFingerprint,
    isGenesis: false,
    historyHasNonGenesis: true,
    acceptedStateSignatureHistory: [verdict.projection.S],
  };
}

const BASELINE = baselineFrom(PREDECESSOR);

const CANDIDATE = buildTransaction({
  senderSeed: 0x04,
  receiverSeed: RECEIVER_SEED,
  senderBalanceAfter: "1",
  receiverBalanceAfter: "10.5",
  previousStep2Signature: PREDECESSOR.step2Signature,
  expiry: EXPIRY,
  message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
});

function baseInput(overrides: Partial<ReceivePolicyInput> = {}): ReceivePolicyInput {
  return {
    reservedWalletPublicKey: RECEIVER,
    candidate: CANDIDATE.parsed,
    baseline: BASELINE,
    artifact: {
      amount_zkz: "0.5",
      receiver_pubkey: RECEIVER,
      discriminator: DISCRIMINATOR,
      anchor: ANCHOR,
      transfer_code_sha256: transferCodeSha256(TRANSFER_CODE),
      code_expiry__unix_time_secs: 1_784_336_400,
    },
    artifactVerification: { ok: true, purpose: "receive-expected-artifact", digest: "d".repeat(64) },
    exactTransferCodeString: TRANSFER_CODE,
    observedAtUnixSecs: OBSERVED_AT,
    ...overrides,
  };
}

function detailOf(input: ReceivePolicyInput, predicate: PredicateId): string {
  const found = evaluateReceiveProof(input).predicates.find((p) => p.predicate === predicate);
  if (found === undefined) throw new Error(`policy produced no result for ${predicate}`);
  return found.detail;
}

describe("evaluateReceiveProof — RECEIVE_EXTERNAL", () => {
  it("verifies an exact receive: previous_step_2 == S0 and B1-B0 == amount", () => {
    const result = evaluateReceiveProof(baseInput());
    expect(result.verdict.outcome).toBe("VERIFIED");
    expect(result.verdict.failedPredicates).toEqual([]);
  });

  it("reports every frozen predicate, in policy sequence", () => {
    const result = evaluateReceiveProof(baseInput());
    expect(result.predicates.map((p) => p.predicate)).toEqual(
      RECEIVE_EXTERNAL_POLICY.verificationSteps.map((step) => step.predicate),
    );
    expect(result.predicates.every((p) => p.passed && p.determinate)).toBe(true);
  });

  it("rejects a one-unit-at-32dp credit mismatch", () => {
    // The chain credits exactly 0.5; the artifact claims one 32-dp unit more.
    const input = baseInput({
      artifact: { ...baseInput().artifact, amount_zkz: `0.5000000000000000000000000000000${"1"}` },
    });
    const result = evaluateReceiveProof(input);
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toEqual(["amount_exact"]);
  });

  it("rejects a credit that is short by one unit at 32dp", () => {
    const short = buildTransaction({
      senderSeed: 0x04,
      receiverSeed: RECEIVER_SEED,
      senderBalanceAfter: "1",
      receiverBalanceAfter: `10.4${"9".repeat(31)}`,
      previousStep2Signature: PREDECESSOR.step2Signature,
      expiry: EXPIRY,
      message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
    });
    const result = evaluateReceiveProof(baseInput({ candidate: short.parsed }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toEqual(["amount_exact"]);
    expect(detailOf(baseInput({ candidate: short.parsed }), "amount_exact")).toContain("B1-B0");
  });

  it("accepts a credit of exactly one unit at 32dp", () => {
    const dust = buildTransaction({
      senderSeed: 0x04,
      receiverSeed: RECEIVER_SEED,
      senderBalanceAfter: "1",
      receiverBalanceAfter: `10.${"0".repeat(31)}1`,
      previousStep2Signature: PREDECESSOR.step2Signature,
      expiry: EXPIRY,
      message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
    });
    const result = evaluateReceiveProof(
      baseInput({
        candidate: dust.parsed,
        artifact: { ...baseInput().artifact, amount_zkz: ONE_UNIT_AT_32DP },
      }),
    );
    expect(result.verdict.outcome).toBe("VERIFIED");
  });

  it("rejects a broken backlink and leaves the delta predicate undecided, not mismatched", () => {
    const orphan = buildTransaction({
      senderSeed: 0x04,
      receiverSeed: RECEIVER_SEED,
      senderBalanceAfter: "1",
      receiverBalanceAfter: "10.5",
      previousStep2Signature: signText("not the accepted head", 0x09),
      expiry: EXPIRY,
      message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
    });
    const input = baseInput({ candidate: orphan.parsed });
    const result = evaluateReceiveProof(input);
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("predecessor_signature_bindsource");
    // The delta evaluator short-circuits at chain_link_mismatch — it never reached the
    // amount comparison, so the record must not claim a determinate amount mismatch.
    const amount = result.predicates.find((p) => p.predicate === "amount_exact");
    expect(amount).toMatchObject({ passed: false, determinate: false });
    expect(result.verdict.failedPredicates).not.toContain("amount_exact");
  });

  it("rejects a tampered step-2 signature", () => {
    const tampered = parseSettled(
      CANDIDATE.settledText.replace(
        CANDIDATE.step2Signature,
        signText(`${CANDIDATE.innerPreimageText} `, RECEIVER_SEED),
      ),
    );
    const result = evaluateReceiveProof(baseInput({ candidate: tampered }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("dual_signatures_verify");
  });

  it("rejects a step-1 signature made by the wrong key", () => {
    const forged = buildTransaction({
      senderSeed: 0x04,
      receiverSeed: RECEIVER_SEED,
      senderBalanceAfter: "1",
      receiverBalanceAfter: "10.5",
      previousStep2Signature: PREDECESSOR.step2Signature,
      expiry: EXPIRY,
      message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
      step1SigningSeed: 0x0a,
    });
    const result = evaluateReceiveProof(baseInput({ candidate: forged.parsed }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("dual_signatures_verify");
  });

  it("rejects an inner that breaks the frozen protocol constants", () => {
    const mutated = CANDIDATE.settledText.replace('"signer_steps":2', '"signer_steps":3');
    const result = evaluateReceiveProof(baseInput({ candidate: parseSettled(mutated) }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("version_constants");
    // Shape rejected before any signature byte was read.
    expect(result.predicates.find((p) => p.predicate === "dual_signatures_verify")).toMatchObject({
      determinate: false,
    });
  });

  it("rejects a wallet that is not the step-2 receiver", () => {
    const result = evaluateReceiveProof(
      baseInput({ reservedWalletPublicKey: publicKeyFromSeed(0x04) }),
    );
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("receiver_role_match");
  });

  it("rejects a step-2 key that is not the artifact's receiver_pubkey", () => {
    const result = evaluateReceiveProof(
      baseInput({ artifact: { ...baseInput().artifact, receiver_pubkey: publicKeyFromSeed(0x05) } }),
    );
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("receiver_pubkey_match");
  });

  it("rejects a message whose discriminator or anchor is not the artifact's", () => {
    const result = evaluateReceiveProof(
      baseInput({ artifact: { ...baseInput().artifact, anchor: "ord_OTHER" } }),
    );
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("message_discriminator");
  });

  it("rejects an observation made after the transfer code expired", () => {
    const result = evaluateReceiveProof(baseInput({ observedAtUnixSecs: 1_784_336_401 }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("expiry_constraints");
  });

  it("rejects a transfer-code digest that is not the digest of the issued code", () => {
    const result = evaluateReceiveProof(baseInput({ exactTransferCodeString: `${TRANSFER_CODE}x` }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toEqual(["artifact_digest_verify"]);
  });

  it("rejects a rejected artifact envelope", () => {
    const result = evaluateReceiveProof(
      baseInput({ artifactVerification: { ok: false, reason: "signature_invalid" } }),
    );
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toEqual(["artifact_digest_verify"]);
  });

  it("rejects a candidate that does not succeed the accepted state", () => {
    // A sibling of the predecessor: same backlink, so sees a fork, not a successor.
    const sibling = buildTransaction({
      senderSeed: 0x06,
      receiverSeed: RECEIVER_SEED,
      senderBalanceAfter: "1",
      receiverBalanceAfter: "10.5",
      expiry: EXPIRY,
      message: `zp1:${DISCRIMINATOR}:${ANCHOR}`,
    });
    const result = evaluateReceiveProof(baseInput({ candidate: sibling.parsed }));
    expect(result.verdict.outcome).toBe("REJECTED");
    expect(result.verdict.failedPredicates).toContain("successor_relationship");
  });

  describe("indeterminate, not rejected", () => {
    it("returns INDETERMINATE when the gateway confirmation is missing", () => {
      const result = evaluateReceiveProof(baseInput({ candidate: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("gateway_confirmation");
    });

    it("returns INDETERMINATE when the accepted baseline is missing", () => {
      const result = evaluateReceiveProof(baseInput({ baseline: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("observation_match");
    });

    it("treats a sender corroboration naming another transaction as a contradiction", () => {
      const input = baseInput({
        senderCorroboration: { stepTwoSignature: PREDECESSOR.step2Signature },
      });
      const result = evaluateReceiveProof(input);
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.failedPredicates).toEqual([]);
      expect(detailOf(input, "successor_relationship")).toContain("contradiction");
    });
  });
});
