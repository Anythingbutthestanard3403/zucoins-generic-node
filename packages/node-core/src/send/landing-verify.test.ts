// independently falsifiable nine-predicate landing tests.
//
// Structural checks:
// * flip exactly one predicate → FAILED at that specific id
// * byte-identical-looking but not-actually-identical preimage fails predicate 4
// * incomplete / absent source path → INDETERMINATE (never false landing)
// * both AWAITING_REDEMPTION and NEEDS_ATTENTION entry points reach VERIFIED

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { SplitChainInnerV2, SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import type { WalletStateProjection } from "../protocol/wallet-role.js";
import {
  SEND_LANDING_PREDICATES,
  verifyExternalSendLanding,
  type SendLandingEvidence,
} from "./landing-verify.js";

const SOURCE = "source-pubkey-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DEST = "dest-pubkey-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const AMOUNT = "4";
const OP_ID = "11111111-1111-1111-1111-111111111111";
const APPROVAL_ID = "22222222-2222-2222-2222-222222222222";
const SOURCE_T0_OBS = "33333333-3333-3333-3333-333333333333";
const DEST_T0_OBS = "44444444-4444-4444-4444-444444444444";
const HEAD_OBS = "55555555-5555-5555-5555-555555555555";

const STEP1_SIG =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const STEP2_SIG =
  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function goodInner(): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: SOURCE,
    step_2_key_public__base64urlsafe: DEST,
    step_1_state: { amount: "6" },
    step_2_state: { amount: "4" },
    previous_step_1_state_signature: "source-prior-sig",
    previous_step_2_state_signature: "dest-prior-sig",
  };
}

function goodTx(inner: SplitChainInnerV2 = goodInner()): SettledSplitChainTransaction {
  return {
    inner,
    step_1_signature: STEP1_SIG,
    step_2_signature: STEP2_SIG,
  };
}

function sourceT0(): WalletStateProjection {
  return { role: "sender", S: "source-prior-sig", P: "", B: "10", I: "d0" };
}

function destT0(): WalletStateProjection {
  return { role: "receiver", S: "dest-prior-sig", P: "", B: "0", I: "d1" };
}

function baseEvidence(overrides: Partial<SendLandingEvidence> = {}): SendLandingEvidence {
  const inner = goodInner();
  const preimage = JSON.stringify(inner);
  const tx = goodTx(inner);
  const bodyText = JSON.stringify(tx);
  const bodySha = sha256Hex(bodyText);
  const innerSha = sha256Hex(preimage);

  const base: SendLandingEvidence = {
    operationId: OP_ID,
    entryStatus: "AWAITING_REDEMPTION",
    economic: {
      operationId: OP_ID,
      sourceWalletId: "66666666-6666-6666-6666-666666666666",
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    expectedArtifactVerified: true,
    expectedArtifact: {
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    approval: {
      approvalId: APPROVAL_ID,
      totpConsumed: true,
      deviceSignatureRequired: false,
      deviceSignatureVerified: false,
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    signIntent: {
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_T0_OBS,
      destinationT0ObservationId: DEST_T0_OBS,
      innerPreimageText: preimage,
      innerSha256: innerSha,
    },
    signIntentRowCount: 1,
    partial: {
      innerSha256: innerSha,
      step1Signature: STEP1_SIG,
      transferCodeSha256: sha256Hex("transfer-code"),
      deliveredTransferCodeSha256: sha256Hex("transfer-code"),
      otherDeliveredPartialSha256: [],
    },
    sourceT0: { observationId: SOURCE_T0_OBS, projection: sourceT0() },
    destinationT0: { observationId: DEST_T0_OBS, projection: destT0() },
    candidate: {
      completedTransaction: tx,
      completedTransactionText: bodyText,
      completedTransactionSha256: bodySha,
      step1PreimageText: preimage,
      step1Signature: STEP1_SIG,
      step2Signature: STEP2_SIG,
      step2SignatureVerified: true,
    },
    sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: HEAD_OBS,
      depth: 0,
    }),
    sourcePathProofIncomplete: false,
    sourceLeaseActive: true,
  };

  return { ...base, ...overrides };
}

describe("SEND_LANDING_PREDICATES vocabulary", () => {
  it("is exactly the nine SEND_EXTERNAL_POLICY predicates in their frozen sequence", () => {
    expect([...SEND_LANDING_PREDICATES]).toEqual([
      "send_artifact_verify",
      "approval_consumed",
      "sign_intent_bind",
      "preimage_exact_match",
      "source_sender_bind",
      "destination_key_approved",
      "destination_predecessor_consistent",
      "source_exact_head",
      "single_partial_delivery",
    ]);
  });
});

describe("verifyExternalSendLanding — happy paths", () => {
  it("VERIFIED from AWAITING_REDEMPTION with LANDED_EXACT", () => {
    const verdict = verifyExternalSendLanding(baseEvidence({ entryStatus: "AWAITING_REDEMPTION" }));
    expect(verdict.kind).toBe("VERIFIED");
    if (verdict.kind === "VERIFIED") {
      expect(verdict.entryStatus).toBe("AWAITING_REDEMPTION");
      expect(verdict.proof.kind).toBe("LANDED_EXACT");
      expect(verdict.proofVerdict.outcome).toBe("VERIFIED");
      expect(verdict.terminalObservationId).toBe(HEAD_OBS);
    }
  });

  it("VERIFIED from NEEDS_ATTENTION (late reconciliation entry)", () => {
    const verdict = verifyExternalSendLanding(baseEvidence({ entryStatus: "NEEDS_ATTENTION" }));
    expect(verdict.kind).toBe("VERIFIED");
    if (verdict.kind === "VERIFIED") {
      expect(verdict.entryStatus).toBe("NEEDS_ATTENTION");
    }
  });

  it("VERIFIED under landing-path oracle LANDED_COMPLETE_PATH (buried landing)", () => {
    const bodySha = baseEvidence().candidate!.completedTransactionSha256;
    const verdict = verifyExternalSendLanding(
      baseEvidence({
        sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: (bodySha + "-head"),
      freshHeadObservationId: HEAD_OBS,
      depth: 3,
    }),
      }),
    );
    expect(verdict.kind).toBe("VERIFIED");
    if (verdict.kind === "VERIFIED") {
      expect(verdict.proof.kind).toBe("LANDED_COMPLETE_PATH");
      expect(verdict.proof.depth).toBe(3);
    }
  });
});

describe("verifyExternalSendLanding — independently falsifiable predicates", () => {
  it("predicate 1 send_artifact_verify", () => {
    const v = verifyExternalSendLanding(baseEvidence({ expectedArtifactVerified: false }));
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("send_artifact_verify");
  });

  it("predicate 2 approval_consumed — missing TOTP", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      approval: { ...base.approval, totpConsumed: false },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("approval_consumed");
  });

  it("predicate 2 approval_consumed — required device signature missing", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      approval: {
        ...base.approval,
        deviceSignatureRequired: true,
        deviceSignatureVerified: false,
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("approval_consumed");
  });

  it("predicate 3 sign_intent_bind — zero sign-intent rows", () => {
    const v = verifyExternalSendLanding(
      baseEvidence({ signIntent: null, signIntentRowCount: 0 }),
    );
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("sign_intent_bind");
  });

  it("predicate 3 sign_intent_bind — economic field drift on artifact", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      expectedArtifact: { ...base.expectedArtifact, amountZkz: "4.01" },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("sign_intent_bind");
  });

  it("predicate 4 preimage_exact_match — single-char preimage re-encode fails byte compare", () => {
    const base = baseEvidence();
    // Same logical object, different bytes (trailing space) — proves no parsed-object equality.
    const v = verifyExternalSendLanding({
      ...base,
      candidate: {
        ...base.candidate!,
        step1PreimageText: base.candidate!.step1PreimageText + " ",
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") {
      expect(v.failedPredicate).toBe("preimage_exact_match");
      expect(v.detail).toMatch(/byte-identical/);
    }
  });

  it("predicate 4 preimage_exact_match — step-1 signature mismatch", () => {
    const base = baseEvidence();
    const otherSig =
      "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==";
    const v = verifyExternalSendLanding({
      ...base,
      candidate: { ...base.candidate!, step1Signature: otherSig },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("preimage_exact_match");
  });

  it("predicate 4 preimage_exact_match — E.inner diverges from matched preimage strings", () => {
    // String fields still equal intent; only the object under E.inner drifts (unix_time).
    // Proves pred 4 re-derives JSON.stringify(E.inner), not caller string equality alone.
    const base = baseEvidence();
    const divergedInner = {
      ...base.candidate!.completedTransaction.inner,
      unix_time_secs: "9999999999",
    };
    const v = verifyExternalSendLanding({
      ...base,
      candidate: {
        ...base.candidate!,
        completedTransaction: {
          ...base.candidate!.completedTransaction,
          inner: divergedInner,
        },
        // keep step1PreimageText / sha / path proof as honest baseline
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") {
      expect(v.failedPredicate).toBe("preimage_exact_match");
      expect(v.detail).toMatch(/JSON\.stringify\(E\.inner\)/);
    }
  });

  it("predicate 4 preimage_exact_match — preimage re-hash must equal intent.innerSha256", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      signIntent: {
        ...base.signIntent!,
        // preimage text still matches candidate; only the stored hash is wrong
        innerSha256: "0".repeat(64),
      },
      partial: {
        ...base.partial!,
        innerSha256: "0".repeat(64),
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") {
      expect(v.failedPredicate).toBe("preimage_exact_match");
      expect(v.detail).toMatch(/sha256\(step-1 preimage\)/);
    }
  });

  it("predicate 5 source_sender_bind — balance delta mismatch", () => {
    // Spread-override keeps `step_1_state` in its original key position, so the preimage below
    // stays byte-for-byte the golden ordering with exactly one field changed.
    const inner = { ...goodInner(), step_1_state: { amount: "7" } }; // B0-B1 would be 3, not 4
    const preimage = JSON.stringify(inner);
    const tx = goodTx(inner);
    const bodyText = JSON.stringify(tx);
    const bodySha = sha256Hex(bodyText);
    const innerSha = sha256Hex(preimage);
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      signIntent: {
        ...base.signIntent!,
        innerPreimageText: preimage,
        innerSha256: innerSha,
      },
      partial: { ...base.partial!, innerSha256: innerSha },
      candidate: {
        completedTransaction: tx,
        completedTransactionText: bodyText,
        completedTransactionSha256: bodySha,
        step1PreimageText: preimage,
        step1Signature: STEP1_SIG,
        step2Signature: STEP2_SIG,
        step2SignatureVerified: true,
      },
      sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: HEAD_OBS,
      depth: 0,
    }),
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("source_sender_bind");
  });

  it("predicate 6 destination_key_approved", () => {
    const wrongDest = "wrong-dest-CCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
    // Keep economic destination as DEST but put wrong key in tx → evaluateExternalSendDelta
    // rejects as artifact_binding_mismatch on step_2, mapped to destination_key_approved.
    // Direct override of step_2 key with matching economic would fail economic check first.
    const inner = { ...goodInner(), step_2_key_public__base64urlsafe: wrongDest };
    const preimage = JSON.stringify(inner);
    const tx = goodTx(inner);
    const bodyText = JSON.stringify(tx);
    const bodySha = sha256Hex(bodyText);
    const innerSha = sha256Hex(preimage);
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      signIntent: {
        ...base.signIntent!,
        innerPreimageText: preimage,
        innerSha256: innerSha,
      },
      partial: { ...base.partial!, innerSha256: innerSha },
      candidate: {
        completedTransaction: tx,
        completedTransactionText: bodyText,
        completedTransactionSha256: bodySha,
        step1PreimageText: preimage,
        step1Signature: STEP1_SIG,
        step2Signature: STEP2_SIG,
        step2SignatureVerified: true,
      },
      sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: HEAD_OBS,
      depth: 0,
    }),
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("destination_key_approved");
  });

  it("predicate 7 destination_predecessor_consistent — wrong Td0.S", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      destinationT0: {
        observationId: DEST_T0_OBS,
        projection: { ...destT0(), S: "not-the-dest-prior" },
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("destination_predecessor_consistent");
  });

  it("predicate 7 destination_predecessor_consistent — step-2 signature not verified", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      candidate: { ...base.candidate!, step2SignatureVerified: false },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("destination_predecessor_consistent");
  });

  it("predicate 8 source_exact_head — proof bound to wrong body", () => {
    const v = verifyExternalSendLanding(
      baseEvidence({
        sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: "0".repeat(64),
      freshHeadBodySha256: "0".repeat(64),
      freshHeadObservationId: HEAD_OBS,
      depth: 0,
    }),
      }),
    );
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("source_exact_head");
  });

  it("predicate 9 single_partial_delivery — foreign partial delivered", () => {
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      partial: {
        ...base.partial!,
        otherDeliveredPartialSha256: [sha256Hex("some-other-partial")],
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") expect(v.failedPredicate).toBe("single_partial_delivery");
  });

  it("predicate 8 source_exact_head — settled body text unbound from honest E sha (EVIL)", () => {
    // Defect 1: honest E + matching path sha + non-empty garbage text must not VERIFIED.
    const base = baseEvidence();
    const v = verifyExternalSendLanding({
      ...base,
      candidate: {
        ...base.candidate!,
        completedTransactionText: "EVIL",
      },
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") {
      expect(v.failedPredicate).toBe("source_exact_head");
      expect(v.detail).toMatch(/JSON\.stringify\(E\)|sha256\(completedTransactionText\)/);
    }
  });

  it("predicate 8 source_exact_head — text hashes to sha but is not JSON.stringify(E)", () => {
    // Text/sha agree; path proof uses that sha; economics still run on honest E.
    const base = baseEvidence();
    const evilText = '{"not":"settled-E"}';
    const evilSha = sha256Hex(evilText);
    const v = verifyExternalSendLanding({
      ...base,
      candidate: {
        ...base.candidate!,
        completedTransactionText: evilText,
        completedTransactionSha256: evilSha,
      },
      sourcePathProof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: evilSha,
      freshHeadBodySha256: evilSha,
      freshHeadObservationId: HEAD_OBS,
      depth: 0,
    }),
    });
    expect(v.kind).toBe("FAILED");
    if (v.kind === "FAILED") {
      expect(v.failedPredicate).toBe("source_exact_head");
      expect(v.detail).toMatch(/JSON\.stringify\(E\)/);
    }
  });
});

describe("verifyExternalSendLanding — INDETERMINATE (never false land)", () => {
  it("absent source path proof (callback/ACK/bare head alone cannot land)", () => {
    const v = verifyExternalSendLanding(baseEvidence({ sourcePathProof: null }));
    expect(v.kind).toBe("INDETERMINATE");
    if (v.kind === "INDETERMINATE") expect(v.reason).toBe("SOURCE_PATH_PROOF_ABSENT");
  });

  it("incomplete source path (gap/regression) → INDETERMINATE, not re-form", () => {
    const v = verifyExternalSendLanding(
      baseEvidence({ sourcePathProof: null, sourcePathProofIncomplete: true }),
    );
    expect(v.kind).toBe("INDETERMINATE");
    if (v.kind === "INDETERMINATE") expect(v.reason).toBe("SOURCE_PATH_PROOF_INCOMPLETE");
  });

  it("inactive source lease → INDETERMINATE without releasing", () => {
    const v = verifyExternalSendLanding(baseEvidence({ sourceLeaseActive: false }));
    expect(v.kind).toBe("INDETERMINATE");
    if (v.kind === "INDETERMINATE") expect(v.reason).toBe("SOURCE_LEASE_NOT_ACTIVE");
  });

  it("missing candidate → INDETERMINATE", () => {
    const v = verifyExternalSendLanding(baseEvidence({ candidate: null }));
    expect(v.kind).toBe("INDETERMINATE");
    if (v.kind === "INDETERMINATE") expect(v.reason).toBe("CANDIDATE_ABSENT");
  });
});
