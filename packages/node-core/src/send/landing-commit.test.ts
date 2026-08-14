// landing commit: atomic transition, event, lease held, dual entry.

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { SplitChainInnerV2, SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import {
  commitExternalSendLanding,
  EXTERNAL_SEND_LANDED_EVENT,
  EXTERNAL_SEND_LANDED_STATUS,
  LANDED_VERIFIED_PHASE,
  SETTLED_BODY_PERSISTED_PHASE,
} from "./landing-commit.js";
import { InMemoryExternalSendLandingStore } from "./landing-sql-store.js";
import {
  verifyExternalSendLanding,
  type SendLandingEvidence,
  type SendLandingVerdict,
} from "./landing-verify.js";

const SOURCE = "source-pubkey-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DEST = "dest-pubkey-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const AMOUNT = "4";
const OP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const WALLET_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const APPROVAL_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const SOURCE_T0_OBS = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const DEST_T0_OBS = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const HEAD_OBS = "ffffffff-ffff-ffff-ffff-ffffffffffff";
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
  return { inner, step_1_signature: STEP1_SIG, step_2_signature: STEP2_SIG };
}

function verifiedVerdict(
  entryStatus: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION" = "AWAITING_REDEMPTION",
): SendLandingVerdict {
  const inner = goodInner();
  const preimage = JSON.stringify(inner);
  const tx = goodTx(inner);
  const bodyText = JSON.stringify(tx);
  const bodySha = sha256Hex(bodyText);
  const innerSha = sha256Hex(preimage);

  const evidence: SendLandingEvidence = {
    operationId: OP_ID,
    entryStatus,
    economic: {
      operationId: OP_ID,
      sourceWalletId: WALLET_ID,
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
      transferCodeSha256: sha256Hex("code"),
      deliveredTransferCodeSha256: sha256Hex("code"),
      otherDeliveredPartialSha256: [],
    },
    sourceT0: {
      observationId: SOURCE_T0_OBS,
      projection: { role: "sender", S: "source-prior-sig", P: "", B: "10", I: "d0" },
    },
    destinationT0: {
      observationId: DEST_T0_OBS,
      projection: { role: "receiver", S: "dest-prior-sig", P: "", B: "0", I: "d1" },
    },
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

  const verdict = verifyExternalSendLanding(evidence);
  expect(verdict.kind).toBe("VERIFIED");
  return verdict;
}

describe("commitExternalSendLanding", () => {
  it("rejects non-VERIFIED verdicts (FAILED never lands)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID);
    const outcome = await commitExternalSendLanding(
      {
        kind: "FAILED",
        operationId: OP_ID,
        failedPredicate: "send_artifact_verify",
        detail: "no",
        predicateResults: [],
        proofVerdict: {
          outcome: "REJECTED",
          operationType: "SEND_EXTERNAL",
          failedPredicates: ["send_artifact_verify"],
          missingEvidence: [],
        },
      },
      store,
    );
    expect(outcome.outcome).toBe("REJECTED");
    expect(store.records).toHaveLength(0);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("rejects INDETERMINATE (path gap cannot land)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID);
    const outcome = await commitExternalSendLanding(
      {
        kind: "INDETERMINATE",
        operationId: OP_ID,
        reason: "SOURCE_PATH_PROOF_INCOMPLETE",
        detail: "gap",
        predicateResults: [],
      },
      store,
    );
    expect(outcome.outcome).toBe("REJECTED");
    expect(store.events).toHaveLength(0);
  });

  it("AWAITING_REDEMPTION → EXTERNAL_SEND_LANDED with settled body, event, proof access, lease held", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const verdict = verifiedVerdict("AWAITING_REDEMPTION");
    const landedAtMs = 1_700_000_000_000;
    const outcome = await commitExternalSendLanding(verdict, store, { landedAtMs });

    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;

    expect(outcome.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(store.leases.has(WALLET_ID)).toBe(true);

    expect(outcome.record.attemptPhase).toBe(SETTLED_BODY_PERSISTED_PHASE);
    expect(outcome.record.publicExecutionPhase).toBe(LANDED_VERIFIED_PHASE);
    expect(outcome.record.completedTransactionText.length).toBeGreaterThan(0);
    expect(outcome.record.terminalObservationId).toBe(HEAD_OBS);
    expect(outcome.record.verificationMaterialAvailableUntilMs).toBeGreaterThan(landedAtMs);

    expect(outcome.event.eventType).toBe(EXTERNAL_SEND_LANDED_EVENT);
    expect(outcome.event.dataText).toContain("terminal_observation_id");
    expect(outcome.event.dataText).toContain("landed_at");

    expect(store.operations.get(OP_ID)?.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(store.records).toHaveLength(1);
    expect(store.events).toHaveLength(1);
  });

  it("NEEDS_ATTENTION → EXTERNAL_SEND_LANDED (late reconciliation)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const verdict = verifiedVerdict("NEEDS_ATTENTION");
    const outcome = await commitExternalSendLanding(verdict, store);
    expect(outcome.outcome).toBe("APPLIED");
    expect(store.operations.get(OP_ID)?.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("idempotent second land is CONFLICT ALREADY_LANDED; lease still held", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const verdict = verifiedVerdict();
    const first = await commitExternalSendLanding(verdict, store);
    expect(first.outcome).toBe("APPLIED");
    const second = await commitExternalSendLanding(verdict, store);
    expect(second.outcome).toBe("CONFLICT");
    if (second.outcome === "CONFLICT") expect(second.reason).toBe("ALREADY_LANDED");
    expect(store.records).toHaveLength(1);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("INDEPENDENT accidental mid-commit drop still reports APPLIED with sourceLeaseStillHeld false (store authority)", async () => {
    // ZTR-1304: commit no longer rejects stillHeld=false; the store owns intentional
    // NODE_VERIFIED release. This flag only simulates a broken store for diagnostics.
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    store.releaseLeaseOnLand = true;
    const verdict = verifiedVerdict();
    const outcome = await commitExternalSendLanding(verdict, store);
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.sourceLeaseStillHeld).toBe(false);
  });

  it("NODE_VERIFIED: APPLIED with sourceLeaseStillHeld false (same-TX release)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true, {
      verificationMode: "NODE_VERIFIED",
    });
    const verdict = verifiedVerdict();
    const outcome = await commitExternalSendLanding(verdict, store);
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.sourceLeaseStillHeld).toBe(false);
    expect(store.leases.has(WALLET_ID)).toBe(false);
    expect(store.operations.get(OP_ID)!.receiveReleaseStatus).toBe("RELEASED_NODE_VERIFIED");
  });

  it("INDEPENDENT: APPLIED keeps source lease held", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true, {
      verificationMode: "INDEPENDENT",
    });
    const verdict = verifiedVerdict();
    const outcome = await commitExternalSendLanding(verdict, store);
    expect(outcome.outcome).toBe("APPLIED");
    if (outcome.outcome !== "APPLIED") return;
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("wrong entry status is STATUS_GUARD_MISMATCH (no partial write)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    // Operation is NEEDS_ATTENTION but verdict expects AWAITING_REDEMPTION
    store.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const verdict = verifiedVerdict("AWAITING_REDEMPTION");
    const outcome = await commitExternalSendLanding(verdict, store);
    expect(outcome.outcome).toBe("CONFLICT");
    expect(store.records).toHaveLength(0);
    expect(store.events).toHaveLength(0);
  });

  it("rejects VERIFIED bag whose settled body text is unbound from E (commit fail-closed)", async () => {
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const honest = verifiedVerdict();
    if (honest.kind !== "VERIFIED") throw new Error("fixture");
    // Simulate a composition-root bug that swaps text after verify — commit must still refuse.
    const forged: SendLandingVerdict = {
      ...honest,
      candidate: {
        ...honest.candidate,
        completedTransactionText: "EVIL",
      },
    };
    const outcome = await commitExternalSendLanding(forged, store);
    expect(outcome.outcome).toBe("REJECTED");
    if (outcome.outcome === "REJECTED") {
      expect(outcome.reason).toBe("SETTLED_BODY_INTEGRITY");
    }
    expect(store.records).toHaveLength(0);
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
  });
});
