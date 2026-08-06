// Send requires persisted partial identity, source delta, destination binding, and a valid
// recipient step 2, plus one falsification per frozen send predicate.
//
// The named attack: a second partial, byte-different from the one the node persisted, whose
// economics match exactly. Same amount, same wallets, same baselines — a different signed
// object handed to the gateway. The policy calls that a determinate fault, because it is the
// shape a matching-amount check waves through while the one-in-flight rule punishes it.
import { describe, expect, it } from "vitest";

import { narrowSplitChainInner } from "../../verifier/inner-shape.js";
import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import { verifySettledTransaction } from "../../verifier/transaction-verify.js";
import { SEND_EXTERNAL_POLICY } from "../policies.js";
import type { PredicateId } from "../types.js";
import {
  evaluateSendProof,
  type DeliveredPartial,
  type SendPolicyInput,
  type SendRecipientConfirmation,
  type SendSubmitEvidence,
  type SignIntentRow,
  type TotpApproval,
} from "./send.js";
import { buildTransaction, parseSettled, publicKeyFromSeed, signText } from "./test-transactions.js";

type Built = ReturnType<typeof buildTransaction>;

/** The two step amounts, read through the real shape narrower rather than off `unknown`. */
function stateAmounts(built: Built): { readonly step1: string; readonly step2: string } {
  const narrowing = narrowSplitChainInner(built.parsed.inner);
  if (!narrowing.ok) throw new Error(`unexpected inner shape: ${JSON.stringify(narrowing.rejection)}`);
  return {
    step1: narrowing.inner.step_1_state.amount,
    step2: narrowing.inner.step_2_state.amount,
  };
}

const SOURCE_SEED = 0x20;
const RECIPIENT_SEED = 0x21;
const SOURCE = publicKeyFromSeed(SOURCE_SEED);
const RECIPIENT = publicKeyFromSeed(RECIPIENT_SEED);
const SOURCE_OBSERVATION_ID = "obs_src_9c1";
const DESTINATION_OBSERVATION_ID = "obs_dst_4e7";
const APPROVAL_ID = "apr_1f04";
const DECOY_SIGNATURE = signText("some other transaction", 0x29);

// The source wallet holds 10 ZKZ; the external recipient's own accepted state carries 1 ZKZ.
const SOURCE_PREDECESSOR = buildTransaction({
  senderSeed: 0x22,
  receiverSeed: SOURCE_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "10",
});
const RECIPIENT_PREDECESSOR = buildTransaction({
  senderSeed: 0x23,
  receiverSeed: RECIPIENT_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "1",
});
const RECIPIENT_OTHER_PREDECESSOR = buildTransaction({
  senderSeed: 0x24,
  receiverSeed: RECIPIENT_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "1",
});

function baselineOf(built: Built, walletPublicKey: string): WalletStateProjection {
  const verdict = verifySettledTransaction(parseSettled(built.settledText), walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture did not verify: ${verdict.verdict}`);
  return verdict.projection;
}

const SOURCE_BASELINE = baselineOf(SOURCE_PREDECESSOR, SOURCE);
const RECIPIENT_BASELINE = baselineOf(RECIPIENT_PREDECESSOR, RECIPIENT);

/** E: 4 ZKZ out of node custody, to the approved external address. */
function buildSend(overrides: Partial<Parameters<typeof buildTransaction>[0]> = {}): Built {
  return buildTransaction({
    senderSeed: SOURCE_SEED,
    receiverSeed: RECIPIENT_SEED,
    senderBalanceAfter: "6",
    receiverBalanceAfter: "5",
    previousStep1Signature: SOURCE_PREDECESSOR.step2Signature,
    previousStep2Signature: RECIPIENT_PREDECESSOR.step2Signature,
    ...overrides,
  });
}

const SEND = buildSend();

const APPROVAL: TotpApproval = {
  approvalId: APPROVAL_ID,
  consumedAtUnixMs: 1_784_332_800_000,
  deviceSignatureRequired: true,
  deviceSignatureVerified: true,
};

function intentFor(built: Built, overrides: Partial<SignIntentRow> = {}): SignIntentRow {
  return {
    approvalId: APPROVAL_ID,
    amountZkz: "4",
    destinationAddress: RECIPIENT,
    sourceBaselineObservationId: SOURCE_OBSERVATION_ID,
    destinationBaselineObservationId: DESTINATION_OBSERVATION_ID,
    step1PreimageText: built.innerPreimageText,
    step1Signature: built.step1Signature,
    ...overrides,
  };
}

const partialFor = (built: Built): DeliveredPartial => ({
  step1PreimageText: built.innerPreimageText,
  step1Signature: built.step1Signature,
});

function submitEvidenceFor(
  built: Built = SEND,
  overrides: Partial<SendSubmitEvidence> = {},
): SendSubmitEvidence {
  return {
    sourceWalletPublicKey: SOURCE,
    sourceBaseline: SOURCE_BASELINE,
    sourceBaselineObservationId: SOURCE_OBSERVATION_ID,
    completed: parseSettled(built.settledText),
    signIntents: [intentFor(built)],
    deliveredPartials: [partialFor(built)],
    sourceAcceptedHeadStepTwoSignature: built.step2Signature,
    approval: APPROVAL,
    ...overrides,
  };
}

function recipientConfirmation(
  overrides: Partial<SendRecipientConfirmation> = {},
): SendRecipientConfirmation {
  return {
    destinationBaseline: RECIPIENT_BASELINE,
    destinationBaselineObservationId: DESTINATION_OBSERVATION_ID,
    approvedDestinationAddress: RECIPIENT,
    ...overrides,
  };
}

function baseInput(overrides: Partial<SendPolicyInput> = {}): SendPolicyInput {
  return {
    artifact: { amount_zkz: "4", source_pubkey: SOURCE, destination_address: RECIPIENT },
    artifactVerification: { ok: true, purpose: "send-expected-artifact", digest: "b".repeat(64) },
    submitEvidence: submitEvidenceFor(),
    recipientConfirmation: recipientConfirmation(),
    ...overrides,
  };
}

function detailOf(input: SendPolicyInput, predicate: PredicateId): string {
  const found = evaluateSendProof(input).predicates.find((p) => p.predicate === predicate);
  if (found === undefined) throw new Error(`policy produced no result for ${predicate}`);
  return found.detail;
}

describe("evaluateSendProof — SEND_EXTERNAL", () => {
  it("verifies a send whose landed bytes are the persisted sign-intent bytes", () => {
    const result = evaluateSendProof(baseInput());
    expect(result.verdict.outcome).toBe("VERIFIED");
    expect(result.verdict.failedPredicates).toEqual([]);
  });

  it("reports every frozen predicate, in policy sequence", () => {
    const result = evaluateSendProof(baseInput());
    expect(result.predicates.map((p) => p.predicate)).toEqual(
      SEND_EXTERNAL_POLICY.verificationSteps.map((step) => step.predicate),
    );
    expect(result.predicates.every((p) => p.passed && p.determinate)).toBe(true);
  });

  describe("item 4 — persisted partial identity", () => {
    it("rejects a second delivered partial whose bytes differ but whose economics match", () => {
      const twin = buildSend({ unixTimeSecs: "1784332801.750" });
      expect(twin.innerPreimageText).not.toBe(SEND.innerPreimageText);
      expect(stateAmounts(twin)).toEqual(stateAmounts(SEND));

      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          deliveredPartials: [partialFor(SEND), partialFor(twin)],
        }),
      });
      const result = evaluateSendProof(input);

      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["single_partial_delivery"]);
      expect(detailOf(input, "single_partial_delivery")).toBe(
        "1 of 2 delivered partial(s) differ from the persisted exact bytes",
      );
    });

    it("rejects a re-signed partial that carries the same preimage text", () => {
      // Same bytes signed again by the same key would be identical for Ed25519, so a second
      // signature over the same preimage can only come from somewhere else.
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          deliveredPartials: [
            { step1PreimageText: SEND.innerPreimageText, step1Signature: DECOY_SIGNATURE },
          ],
        }),
      });
      expect(evaluateSendProof(input).verdict.failedPredicates).toEqual(["single_partial_delivery"]);
    });

    it("rejects landed bytes that are not the bytes the sign-intent committed to", () => {
      const twin = buildSend({ unixTimeSecs: "1784332801.750" });
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          // The node persisted its commitment to `twin`, but `SEND` is what landed.
          signIntents: [intentFor(twin)],
          deliveredPartials: [partialFor(twin)],
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["preimage_exact_match"]);
    });

    it("leaves the byte predicates undecided when no delivery record is held", () => {
      const result = evaluateSendProof(
        baseInput({ submitEvidence: submitEvidenceFor(SEND, { deliveredPartials: [] }) }),
      );
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.predicates.find((p) => p.predicate === "single_partial_delivery")).toMatchObject({
        determinate: false,
      });
    });
  });

  describe("approval and sign-intent binding", () => {
    it("rejects an approval that was never consumed", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          approval: { ...APPROVAL, consumedAtUnixMs: null },
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["approval_consumed"]);
      expect(detailOf(input, "approval_consumed")).toContain("never consumed");
    });

    it("rejects a required device signature that did not verify", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          approval: { ...APPROVAL, deviceSignatureVerified: false },
        }),
      });
      expect(evaluateSendProof(input).verdict.failedPredicates).toEqual(["approval_consumed"]);
    });

    it("rejects two sign-intents for one approval", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          signIntents: [intentFor(SEND), intentFor(SEND)],
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["sign_intent_bind"]);
      expect(detailOf(input, "sign_intent_bind")).toBe(
        `2 of 2 sign-intents bind approval ${APPROVAL_ID} to this artifact and both baselines`,
      );
      // With no single intent, the byte predicates have nothing to compare against.
      for (const predicate of ["preimage_exact_match", "single_partial_delivery"] as const) {
        expect(evaluateSendProof(input).predicates.find((p) => p.predicate === predicate)).toMatchObject(
          { determinate: false },
        );
      }
    });

    it.each([
      ["approval", { approvalId: "apr_other" }],
      ["amount", { amountZkz: "5" }],
      ["destination", { destinationAddress: publicKeyFromSeed(0x2a) }],
      ["source baseline", { sourceBaselineObservationId: "obs_src_other" }],
      ["destination baseline", { destinationBaselineObservationId: "obs_dst_other" }],
      ["nothing at all", undefined],
    ])("rejects a sign-intent not bound to this %s", (_label, intentOverride) => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          signIntents: intentOverride === undefined ? [] : [intentFor(SEND, intentOverride)],
        }),
      });
      expect(evaluateSendProof(input).verdict.failedPredicates).toEqual(["sign_intent_bind"]);
    });
  });

  describe("source delta and destination binding", () => {
    it("rejects a source debit short by one unit at 32dp", () => {
      const shorted = buildSend({ senderBalanceAfter: `6.${"0".repeat(31)}1` });
      const input = baseInput({ submitEvidence: submitEvidenceFor(shorted) });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["source_sender_bind"]);
      expect(detailOf(input, "source_sender_bind")).toContain("B0-B1");
    });

    it("rejects a landed transaction that does not link to the source's accepted head", () => {
      const orphan = buildSend({ previousStep1Signature: DECOY_SIGNATURE });
      const input = baseInput({ submitEvidence: submitEvidenceFor(orphan) });
      expect(evaluateSendProof(input).verdict.failedPredicates).toEqual(["source_sender_bind"]);
    });

    it("rejects a wallet that is not the step-1 sender of the landed transaction", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, { sourceWalletPublicKey: RECIPIENT }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toContain("source_sender_bind");
    });

    it("rejects a step-2 key that is not the approved destination address", () => {
      const input = baseInput({
        recipientConfirmation: recipientConfirmation({
          approvedDestinationAddress: publicKeyFromSeed(0x2a),
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_key_approved"]);
    });

    it("rejects a recipient step 2 that does not link onto the recipient's accepted state", () => {
      const input = baseInput({
        recipientConfirmation: recipientConfirmation({
          destinationBaseline: baselineOf(RECIPIENT_OTHER_PREDECESSOR, RECIPIENT),
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_predecessor_consistent"]);
      expect(detailOf(input, "destination_predecessor_consistent")).toContain("does not equal");
    });

    it("rejects a recipient credit that is not exactly the artifact amount", () => {
      // The source is debited exactly 4; the recipient's step 2 credits 4.5.
      const skewed = buildSend({ receiverBalanceAfter: "5.5" });
      const input = baseInput({ submitEvidence: submitEvidenceFor(skewed) });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_predecessor_consistent"]);
    });
  });

  describe("the source head", () => {
    it("does not treat a mismatched head as determinate non-landing", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, {
          sourceAcceptedHeadStepTwoSignature: DECOY_SIGNATURE,
        }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.failedPredicates).toEqual([]);
      expect(result.predicates.find((p) => p.predicate === "source_exact_head")).toMatchObject({
        passed: false,
        determinate: false,
      });
      expect(detailOf(input, "source_exact_head")).toContain("non-landing is not proven");
    });

    it("does not treat a failed head read as proof of non-landing", () => {
      const input = baseInput({
        submitEvidence: submitEvidenceFor(SEND, { sourceAcceptedHeadStepTwoSignature: null }),
      });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.failedPredicates).toEqual([]);
      expect(detailOf(input, "source_exact_head")).toContain("non-landing is not proven");
    });
  });

  describe("the artifact envelope and missing evidence", () => {
    it("rejects a rejected artifact envelope", () => {
      const result = evaluateSendProof(
        baseInput({ artifactVerification: { ok: false, reason: "unknown_key" } }),
      );
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["send_artifact_verify"]);
    });

    it("rejects a completed transaction whose signature does not verify", () => {
      const tampered = parseSettled(
        SEND.settledText.replace(SEND.step2Signature, signText("other bytes", RECIPIENT_SEED)),
      );
      const input = baseInput({ submitEvidence: submitEvidenceFor(SEND, { completed: tampered }) });
      const result = evaluateSendProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toContain("source_sender_bind");
      expect(detailOf(input, "source_sender_bind")).toContain("step 2 signature did not verify");
      for (const predicate of [
        "preimage_exact_match",
        "destination_key_approved",
        "destination_predecessor_consistent",
      ] as const) {
        expect(result.predicates.find((p) => p.predicate === predicate)).toMatchObject({
          determinate: false,
        });
      }
    });

    it("returns INDETERMINATE when no submit evidence is held", () => {
      const result = evaluateSendProof(baseInput({ submitEvidence: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("submit_evidence");
      expect(result.verdict.failedPredicates).toEqual([]);
    });

    it("returns INDETERMINATE when the recipient side was not confirmed", () => {
      const result = evaluateSendProof(baseInput({ recipientConfirmation: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("recipient_confirmation");
    });
  });
});
