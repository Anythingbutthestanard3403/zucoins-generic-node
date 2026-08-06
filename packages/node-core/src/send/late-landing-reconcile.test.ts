// late-landing reconciliation after SEND_EXTERNAL post-delivery expiry.
//
// Structural checks:
// * depth-0 / depth-1 / depth-N → EXTERNAL_SEND_LANDED + SETTLED_BODY_PERSISTED
// * missing hop → INDETERMINATE, never land
// * endpoint conflict → fail closed
// * restart mid-reconcile resumes without duplicate positive proof
// * proof-then-commit crash recovers land (never false ALREADY_LANDED while NEEDS_ATTENTION)
// * attempted terminal close while incomplete → REFUSED_CLOSE
// * expiry/silence/unchanged head never release lease or terminal-reject

import { createHash, createPrivateKey, sign, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import type { PathObservation } from "../protocol/reconcile/observation-input.js";
import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../verifier/gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "../verifier/landing-path-oracle.js";
import { proveSendLanding } from "../verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../verifier/transaction-verify.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";

import {
  EXTERNAL_SEND_LANDED_EVENT,
  EXTERNAL_SEND_LANDED_STATUS,
  SETTLED_BODY_PERSISTED_PHASE,
} from "./landing-commit.js";
import { InMemoryExternalSendLandingStore } from "./landing-sql-store.js";
import {
  InMemorySendLateLandingProofStore,
  applyLateLandingCycle,
  assertLateLandingSqlCatalogueSafe,
  classifyLateLandingCycle,
  lateLandingAttentionReason,
  refusesTerminalClose,
  type LateLandingOperationFacts,
} from "./late-landing-reconcile.js";
import type { SendLandingEvidence } from "./landing-verify.js";

const GEN_DIR = new URL(
  "../../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const SOURCE = MANIFEST.public_keys.seed_02 as string;
const DEST = MANIFEST.public_keys.seed_03 as string;
const AMOUNT = "2.25";
const OP_ID = "30730730-7307-4307-8307-307307307307";
const WALLET_ID = "30730730-7307-4307-8307-307307307308";
const APPROVAL_ID = "30730730-7307-4307-8307-307307307309";
const SOURCE_T0_OBS = "30730730-7307-4307-8307-30730730730a";
const DEST_T0_OBS = "30730730-7307-4307-8307-30730730730b";
const OBSERVER_ID = "30730730-7307-4307-8307-30730730730c";
const TRANSFER_CODE = "transfer-code-fixture";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const keyFromSeed = (byte: number) => {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
};

const signText = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

function headEnvelope(settledText: string, observationId?: string): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return {
    observationId: observationId ?? `obs-${settledText.length}`,
    envelope: parseGatewayEnvelope(bytes),
  };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope");
  return verdict.parsed;
}

const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");
const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);

/** Hop after TARGET: seed_02 spends 1.00 more to seed_03 (depth-1 burial). */
function buildHop(prevStep2: string, amountOut: string, remaining: string, time: string) {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: time,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: SOURCE,
    step_2_key_public__base64urlsafe: DEST,
    step_1_state: { amount: remaining },
    step_2_state: { amount: amountOut },
    previous_step_1_state_signature: prevStep2,
    previous_step_2_state_signature: prevStep2,
  };
  const step1 = JSON.stringify(inner);
  const step1Sig = signText(step1, seed02);
  const step2Pre = JSON.stringify({ inner, step_1_signature: step1Sig });
  const step2Sig = signText(step2Pre, seed03);
  const text = JSON.stringify({
    inner,
    step_1_signature: step1Sig,
    step_2_signature: step2Sig,
  });
  return { text, body: parsedBody(text) };
}

const HOP3 = buildHop(TARGET.step_2_signature, "1.00", "6.75", "1784332900");
const HOP4 = buildHop(HOP3.body.step_2_signature, "0.50", "6.25", "1784332910");
const HOP5 = buildHop(HOP4.body.step_2_signature, "0.25", "6.00", "1784332920");

interface BuiltCandidate {
  readonly tx: SettledSplitChainTransaction;
  readonly preimage: string;
  readonly bodyText: string;
  readonly bodySha: string;
  readonly innerSha: string;
  readonly transferCodeSha256: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
}

function buildCandidate(): BuiltCandidate {
  const verified = verifySettledTransaction(TARGET, SOURCE);
  if (verified.verdict !== "VERIFIED") {
    throw new Error(`TARGET must verify under SOURCE: ${verified.verdict}`);
  }
  const preimage = verified.innerPreimageText;
  return {
    tx: verified.transaction,
    preimage,
    bodyText: TARGET_TEXT,
    bodySha: sha256Hex(TARGET_TEXT),
    innerSha: sha256Hex(preimage),
    transferCodeSha256: sha256Hex(TRANSFER_CODE),
    step1Signature: verified.transaction.step_1_signature,
    step2Signature: verified.transaction.step_2_signature,
  };
}

function baseEvidence(c: BuiltCandidate): SendLandingEvidence {
  return {
    operationId: OP_ID,
    entryStatus: "NEEDS_ATTENTION",
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
      innerPreimageText: c.preimage,
      innerSha256: c.innerSha,
    },
    signIntentRowCount: 1,
    partial: {
      innerSha256: c.innerSha,
      step1Signature: c.step1Signature,
      transferCodeSha256: c.transferCodeSha256,
      deliveredTransferCodeSha256: c.transferCodeSha256,
      otherDeliveredPartialSha256: [],
    },
    sourceT0: {
      observationId: SOURCE_T0_OBS,
      projection: {
        role: "sender",
        S: PREDECESSOR.step_2_signature,
        P: "",
        B: "10",
        I: "d0",
      },
    },
    destinationT0: {
      observationId: DEST_T0_OBS,
      projection: { role: "receiver", S: "", P: "", B: "0", I: "d1" },
    },
    candidate: {
      completedTransaction: c.tx,
      completedTransactionText: c.bodyText,
      completedTransactionSha256: c.bodySha,
      step1PreimageText: c.preimage,
      step1Signature: c.step1Signature,
      step2Signature: c.step2Signature,
      step2SignatureVerified: true,
    },
    sourcePathProof: null,
    sourcePathProofIncomplete: false,
    sourceLeaseActive: true,
  };
}

function facts(c: BuiltCandidate): LateLandingOperationFacts {
  const ev = baseEvidence(c);
  const { candidate, sourcePathProof, sourcePathProofIncomplete, entryStatus, ...rest } = ev;
  return {
    operationId: OP_ID,
    sendAttemptId: OP_ID,
    sourceWalletId: WALLET_ID,
    sourcePubkey: SOURCE,
    destinationAddress: DEST,
    amountZkz: AMOUNT,
    transferCodeSha256: c.transferCodeSha256,
    status: "NEEDS_ATTENTION",
    sourceLeaseActive: true,
    expectedBody: TARGET,
    expectedBodyText: TARGET_TEXT,
    t0Body: PREDECESSOR,
    landingEvidenceBase: rest,
    candidateFromExpected: candidate!,
    verifierObserverId: OBSERVER_ID,
  };
}

function staticReader(settledText: string, obsId?: string): ReadFreshHead & { calls: () => number } {
  let calls = 0;
  const read: ReadFreshHead = async () => {
    calls += 1;
    return headEnvelope(settledText, obsId ?? `obs-head-${calls}`);
  };
  return Object.assign(read, { calls: () => calls });
}

function dualEndpointReaders(
  a: string,
  b: string,
): { readA: ReadFreshHead; readB: ReadFreshHead } {
  return {
    readA: async () => headEnvelope(a, "obs-endpoint-a"),
    readB: async () => headEnvelope(b, "obs-endpoint-b"),
  };
}

describe("SQL catalogue never admits release/close/second-partial", () => {
  it("allowed SQL set is free of lease DELETE, EXPIRED, REJECTED, second partial", () => {
    expect(() => assertLateLandingSqlCatalogueSafe()).not.toThrow();
  });
});

describe("proveSendLanding depth matrix", () => {
  it("depth-0: expected body is fresh head → LANDED_EXACT", async () => {
    const outcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      staticReader(TARGET_TEXT),
    );
    expect(outcome.kind).toBe("LANDED_EXACT");
    if (outcome.kind === "LANDED_EXACT") {
      expect(outcome.depth).toBe(0);
      expect(outcome.walletPubkeyBase64Urlsafe).toBe(SOURCE);
    }
  });

  it("depth-1: one intermediate body → LANDED_COMPLETE_PATH", async () => {
    const outcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [HOP3.body],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      staticReader(HOP3.text),
    );
    expect(outcome.kind).toBe("LANDED_COMPLETE_PATH");
    if (outcome.kind === "LANDED_COMPLETE_PATH") {
      expect(outcome.depth).toBe(1);
    }
  });

  it("depth-N: several intermediate bodies all verified → LANDED_COMPLETE_PATH", async () => {
    const outcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [HOP3.body, HOP4.body, HOP5.body],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      staticReader(HOP5.text),
    );
    expect(outcome.kind).toBe("LANDED_COMPLETE_PATH");
    if (outcome.kind === "LANDED_COMPLETE_PATH") {
      expect(outcome.depth).toBe(3);
    }
  });

  it("missing intermediate hop → MISSING_BODY/GAP, never positive", async () => {
    // Head is HOP5 but only HOP3 supplied (HOP4 missing) → gap.
    const outcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [HOP3.body],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      staticReader(HOP5.text),
    );
    expect(outcome.kind).toBe("PROOF_INCOMPLETE");
    if (outcome.kind === "PROOF_INCOMPLETE") {
      expect(["GAP", "MISSING_BODY"]).toContain(outcome.fault);
    }
  });

  it("budget exhaustion → BUDGET_EXHAUSTED", async () => {
    const outcome = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [HOP3.body, HOP4.body],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
        maxDepth: 0,
      },
      staticReader(HOP4.text),
    );
    expect(outcome).toEqual({ kind: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" });
  });
});

describe("late landing from NEEDS_ATTENTION", () => {
  it("depth-0 late landing → EXTERNAL_SEND_LANDED + SETTLED_BODY_PERSISTED; lease held", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    const proofObs: PathObservation = {
      result: "PROOF",
      proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: c.bodySha,
      freshHeadBodySha256: c.bodySha,
      freshHeadObservationId: "obs-terminal-d0",
      depth: 0,
    }),
    };

    const outcome = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_000_000 },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("LANDED");
    if (outcome.kind !== "LANDED") return;
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(outcome.commit.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(outcome.commit.record.attemptPhase).toBe(SETTLED_BODY_PERSISTED_PHASE);
    expect(outcome.commit.record.entryStatus).toBe("NEEDS_ATTENTION");
    expect(outcome.commit.event.eventType).toBe(EXTERNAL_SEND_LANDED_EVENT);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
    expect(outcome.proofProgress.landingProof.verdict).toBe("LANDED_EXACT");
    expect(outcome.proofProgress.landingProof.requiredPathCount).toBe(1);
    expect(outcome.proofProgress.bodies).toHaveLength(1);
    expect(outcome.proofProgress.bodies[0]?.path_index).toBe(0);
    expect(outcome.proofProgress.pathProof?.body_count).toBe(1);
    expect(outcome.proofProgress.pathProof?.path_depth).toBe(0);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).toBe(
      c.bodySha,
    );
    expect(outcome.proofProgress.pathProof?.expected_completed_transaction_sha256).toBe(c.bodySha);
    expect(outcome.proofProgress.landingProof.declaredBodyCount).toBe(1);
    expect(outcome.proofProgress.landingProof.declaredTotalBodyBytes).toBe(
      Buffer.byteLength(TARGET_TEXT, "utf8"),
    );
  });

  it("depth-1 via proveSendLanding → LANDED_COMPLETE_PATH land", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();
    const reader = staticReader(HOP3.text, "obs-hop3");

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: reader,
        nowMs: 1_700_000_000_100,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("LANDED");
    if (outcome.kind !== "LANDED") return;
    expect(outcome.classification.sourcePath.kind).toBe("LANDED_COMPLETE_PATH");
    expect(outcome.classification.sourcePath.depth).toBe(1);
    expect(outcome.proofProgress.landingProof.verdict).toBe("LANDED_COMPLETE_PATH");
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);

    // Durable complete-path: bodies 0..1, head = terminal hop (not expectedSha).
    const hop3Sha = sha256Hex(HOP3.text);
    expect(outcome.proofProgress.bodies).toHaveLength(2);
    expect(outcome.proofProgress.pathProof?.body_count).toBe(2);
    expect(outcome.proofProgress.pathProof?.path_depth).toBe(1);
    expect(outcome.proofProgress.landingProof.declaredBodyCount).toBe(2);
    expect(outcome.proofProgress.bodies.map((b) => b.path_index)).toEqual([0, 1]);
    expect(outcome.proofProgress.bodies[0]?.completed_transaction_sha256).toBe(c.bodySha);
    expect(outcome.proofProgress.bodies[1]?.completed_transaction_sha256).toBe(hop3Sha);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).toBe(
      hop3Sha,
    );
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).not.toBe(
      c.bodySha,
    );
    const sumBytes = outcome.proofProgress.bodies.reduce(
      (n, b) => n + b.completed_transaction_octets,
      0,
    );
    expect(outcome.proofProgress.landingProof.declaredTotalBodyBytes).toBe(sumBytes);
    expect(sumBytes).toBeGreaterThan(outcome.proofProgress.bodies[0]!.completed_transaction_octets);
  });

  it("depth-N via oracle → land with COMPLETE_PATH", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();
    const successors = [HOP3, HOP4, HOP5];

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
        successorBodies: successors.map((h) => h.body),
        readFreshHead: staticReader(HOP5.text, "obs-hop5"),
        nowMs: 1_700_000_000_200,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("LANDED");
    if (outcome.kind !== "LANDED") return;
    expect(outcome.classification.sourcePath.depth).toBe(3);
    expect(landingStore.operations.get(OP_ID)?.status).toBe(EXTERNAL_SEND_LANDED_STATUS);

    // Durable: bodies.length === depth+1 === body_count; head = HOP5 digest.
    const depth = 3;
    const hop5Sha = sha256Hex(HOP5.text);
    expect(outcome.proofProgress.bodies).toHaveLength(depth + 1);
    expect(outcome.proofProgress.pathProof?.body_count).toBe(depth + 1);
    expect(outcome.proofProgress.pathProof?.path_depth).toBe(depth);
    expect(outcome.proofProgress.landingProof.declaredBodyCount).toBe(depth + 1);
    expect(outcome.proofProgress.bodies.map((b) => b.path_index)).toEqual([0, 1, 2, 3]);
    expect(outcome.proofProgress.bodies[0]?.source_kind).toBe("EXPECTED_OPERATION");
    expect(outcome.proofProgress.bodies[0]?.completed_transaction_sha256).toBe(c.bodySha);
    expect(outcome.proofProgress.bodies[1]?.completed_transaction_sha256).toBe(sha256Hex(HOP3.text));
    expect(outcome.proofProgress.bodies[2]?.completed_transaction_sha256).toBe(sha256Hex(HOP4.text));
    expect(outcome.proofProgress.bodies[3]?.completed_transaction_sha256).toBe(hop5Sha);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).toBe(
      hop5Sha,
    );
    expect(outcome.proofProgress.pathProof?.expected_completed_transaction_sha256).toBe(c.bodySha);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).not.toBe(
      c.bodySha,
    );
    const sumBytes = outcome.proofProgress.bodies.reduce(
      (n, b) => n + b.completed_transaction_octets,
      0,
    );
    expect(outcome.proofProgress.landingProof.declaredTotalBodyBytes).toBe(sumBytes);
    expect(sumBytes).toBe(
      Buffer.byteLength(TARGET_TEXT, "utf8") +
        Buffer.byteLength(HOP3.text, "utf8") +
        Buffer.byteLength(HOP4.text, "utf8") +
        Buffer.byteLength(HOP5.text, "utf8"),
    );
  });
});

describe("fail-closed negatives", () => {
  it("missing hop remains NEEDS_ATTENTION; lease held; no landing record", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body], // head is HOP5 → gap
        readFreshHead: staticReader(HOP5.text),
        nowMs: 1_700_000_000_300,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("REMAIN_ATTENTION");
    if (outcome.kind !== "REMAIN_ATTENTION") return;
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(outcome.classification.kind).toBe("INDETERMINATE");
    expect(landingStore.operations.get(OP_ID)?.status).toBe("NEEDS_ATTENTION");
    expect(landingStore.records).toHaveLength(0);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
  });

  it("unchanged head (NO_SUCCESSOR) → WAITING; never REJECTED; lease held", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "NO_SUCCESSOR" },
        nowMs: 1_700_000_000_400,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("REMAIN_ATTENTION");
    if (outcome.kind !== "REMAIN_ATTENTION") return;
    expect(outcome.classification.kind).toBe("WAITING");
    expect(refusesTerminalClose(outcome.classification)).toBe(true);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
    expect(landingStore.records).toHaveLength(0);
  });

  it("endpoint conflict: two gateways disagree → both fail closed; no land", async () => {
    const c = buildCandidate();
    const { readA, readB } = dualEndpointReaders(TARGET_TEXT, HOP3.text);

    const a = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      readA,
    );
    const b = await proveSendLanding(
      {
        walletPubkeyBase64Urlsafe: SOURCE,
        t0Body: PREDECESSOR,
        expectedBody: TARGET,
        successorBodies: [],
        operation: { amountZkz: AMOUNT, sourcePubkey: SOURCE, destinationAddress: DEST },
      },
      readB,
    );

    // A: depth-0 exact head matches → positive. B: head is HOP3 without successor body → incomplete.
    expect(a.kind).toBe("LANDED_EXACT");
    expect(b.kind).toBe("PROOF_INCOMPLETE");

    // Money decision requires agreement: when endpoints disagree, do not land from the
    // incomplete stream; a caller that sees conflict must park (closing paragraph).
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    // Present the incomplete endpoint's observation — fail closed.
    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "PROOF_INCOMPLETE", fault: "CONFLICT" },
        nowMs: 1_700_000_000_500,
      },
      { landingStore, proofStore },
    );
    expect(outcome.kind).toBe("REMAIN_ATTENTION");
    expect(landingStore.records).toHaveLength(0);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
  });

  it("budget exhaustion stays INDETERMINATE; refuses terminal close", async () => {
    const c = buildCandidate();
    const classification = await classifyLateLandingCycle({
      facts: facts(c),
      sourceObservation: { result: "NO_SUCCESSOR" },
      successorBodies: [HOP3.body],
      readFreshHead: staticReader(HOP3.text),
      maxDepth: 0,
    });
    expect(classification.kind).toBe("INDETERMINATE");
    if (classification.kind === "INDETERMINATE") {
      expect(classification.reason).toEqual({
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "BUDGET_EXHAUSTED",
      });
    }
    expect(refusesTerminalClose(classification)).toBe(true);
    if (classification.kind === "INDETERMINATE") {
      expect(lateLandingAttentionReason(classification)).toBe("VERIFICATION_RESOURCE_EXHAUSTED");
    }
  });
});

describe("restart + no duplicate positive proof", () => {
  it("restart mid-reconcile resumes from staged INDETERMINATE progress without losing id", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    const first = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
        nowMs: 1_700_000_000_600,
      },
      { landingStore, proofStore },
    );
    expect(first.kind).toBe("REMAIN_ATTENTION");
    if (first.kind !== "REMAIN_ATTENTION" || first.proofProgress === null) {
      throw new Error("expected staged indeterminate progress");
    }
    const stagedId = first.proofProgress.landingProof.id;

    const second = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "PROOF_INCOMPLETE", fault: "GAP" },
        nowMs: 1_700_000_000_700,
      },
      { landingStore, proofStore },
    );
    expect(second.kind).toBe("REMAIN_ATTENTION");
    if (second.kind !== "REMAIN_ATTENTION" || second.proofProgress === null) {
      throw new Error("expected resumed progress");
    }
    expect(second.proofProgress.landingProof.id).toBe(stagedId);
    expect(proofStore.byOperation.size).toBe(1);
  });

  it("second land after success is ALREADY_LANDED; single positive proof row", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();
    const proofObs: PathObservation = {
      result: "PROOF",
      proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: c.bodySha,
      freshHeadBodySha256: c.bodySha,
      freshHeadObservationId: "obs-once",
      depth: 0,
    }),
    };

    const first = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_000_800 },
      { landingStore, proofStore },
    );
    expect(first.kind).toBe("LANDED");

    const second = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_000_900 },
      { landingStore, proofStore },
    );
    expect(second.kind).toBe("ALREADY_LANDED");
    expect(proofStore.byOperation.size).toBe(1);
    expect(landingStore.events).toHaveLength(1);
    expect(landingStore.records).toHaveLength(1);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
  });
});

describe("proof-then-commit dual-write recovery", () => {
  it("commit fails once after positive proof; second cycle lands (never false ALREADY_LANDED)", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();
    const proofObs: PathObservation = {
      result: "PROOF",
      proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: c.bodySha,
      freshHeadBodySha256: c.bodySha,
      freshHeadObservationId: "obs-commit-fail",
      depth: 0,
    }),
    };

    let commitCalls = 0;
    const original = landingStore.commitLanding.bind(landingStore);
    landingStore.commitLanding = async (command) => {
      commitCalls += 1;
      if (commitCalls === 1) {
        // Simulate crash / CAS miss after proof INSERT: status stays NEEDS_ATTENTION.
        return {
          applied: false,
          reason: "STATUS_GUARD_MISMATCH",
          sourceLeaseStillHeld: true,
        };
      }
      return original(command);
    };

    const first = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_001_100 },
      { landingStore, proofStore },
    );
    // First cycle wrote positive proof; land CAS failed → remain attention, not ALREADY_LANDED.
    expect(first.kind).toBe("REMAIN_ATTENTION");
    expect(first.sourceLeaseStillHeld).toBe(true);
    expect(proofStore.byOperation.size).toBe(1);
    const positive = proofStore.byOperation.get(OP_ID);
    expect(positive?.landingProof.verdict).toBe("LANDED_EXACT");
    expect(landingStore.operations.get(OP_ID)?.status).toBe("NEEDS_ATTENTION");
    expect(landingStore.records).toHaveLength(0);

    const second = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_001_200 },
      { landingStore, proofStore },
    );
    // Recovery must complete the land — never terminal false ALREADY_LANDED while entry-set.
    expect(second.kind).toBe("LANDED");
    if (second.kind !== "LANDED") return;
    expect(second.commit.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(second.sourceLeaseStillHeld).toBe(true);
    expect(landingStore.operations.get(OP_ID)?.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(proofStore.byOperation.size).toBe(1);
    expect(landingStore.records).toHaveLength(1);
    expect(landingStore.events).toHaveLength(1);
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
    expect(commitCalls).toBe(2);

    // Third cycle: now truly already landed.
    const third = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_001_300 },
      { landingStore, proofStore },
    );
    expect(third.kind).toBe("ALREADY_LANDED");
    expect(proofStore.byOperation.size).toBe(1);
    expect(landingStore.records).toHaveLength(1);
  });

  it("ALREADY_POSITIVE with status still NEEDS_ATTENTION completes land (UNIQUE ≠ landed)", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const durable = new InMemorySendLateLandingProofStore();
    const proofObs: PathObservation = {
      result: "PROOF",
      proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: c.bodySha,
      freshHeadBodySha256: c.bodySha,
      freshHeadObservationId: "obs-unique-recover",
      depth: 0,
    }),
    };

    // Seed a durable positive proof as if a prior process wrote it then died before commit.
    const seed = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_001_400 },
      {
        landingStore: {
          commitLanding: async () => ({
            applied: false,
            reason: "STATUS_GUARD_MISMATCH",
            sourceLeaseStillHeld: true,
          }),
        },
        proofStore: durable,
      },
    );
    expect(seed.kind).toBe("REMAIN_ATTENTION");
    expect(durable.byOperation.size).toBe(1);
    expect(landingStore.operations.get(OP_ID)?.status).toBe("NEEDS_ATTENTION");
    const existingId = durable.byOperation.get(OP_ID)!.landingProof.id;

    // Simulate process restart where loadAttempt1 misses once (empty mem) but INSERT
    // races UNIQUE → ALREADY_POSITIVE; recovery must still land.
    let loads = 0;
    const racingStore = {
      async loadAttempt1(operationId: string) {
        loads += 1;
        // First load (top gate) misses; reload after ALREADY_POSITIVE hits durable.
        if (loads === 1) return null;
        return durable.loadAttempt1(operationId);
      },
      async saveIndeterminateProgress() {},
      async savePositiveProof() {
        return { kind: "ALREADY_POSITIVE" as const, existingId };
      },
    };

    const recovered = await applyLateLandingCycle(
      { facts: facts(c), sourceObservation: proofObs, nowMs: 1_700_000_001_500 },
      { landingStore, proofStore: racingStore },
    );
    expect(recovered.kind).toBe("LANDED");
    if (recovered.kind !== "LANDED") return;
    expect(landingStore.operations.get(OP_ID)?.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(durable.byOperation.size).toBe(1);
    expect(recovered.sourceLeaseStillHeld).toBe(true);
    expect(loads).toBeGreaterThanOrEqual(2);
  });
});

describe("terminal close refused while incomplete", () => {
  it("attempted CLOSE while path incomplete → REFUSED_CLOSE; lease held", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c),
        sourceObservation: { result: "NO_SUCCESSOR" },
        nowMs: 1_700_000_001_000,
      },
      { landingStore, proofStore },
      { attemptTerminalClose: true },
    );

    expect(outcome.kind).toBe("REFUSED_CLOSE");
    if (outcome.kind !== "REFUSED_CLOSE") return;
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(refusesTerminalClose(outcome.classification)).toBe(true);
    expect(landingStore.operations.get(OP_ID)?.status).toBe("NEEDS_ATTENTION");
    expect(landingStore.leases.has(WALLET_ID)).toBe(true);
  });

  it("silence / expiry evidence never yields REJECTED status via this module", async () => {
    const c = buildCandidate();
    const landingStore = new InMemoryExternalSendLandingStore();
    landingStore.seed(OP_ID, "NEEDS_ATTENTION", WALLET_ID, true);
    const proofStore = new InMemorySendLateLandingProofStore();

    for (const obs of [
      { result: "NO_SUCCESSOR" } as PathObservation,
      { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" } as PathObservation,
      { result: "ANOMALY", anomaly: "TRANSPORT_ERROR" } as PathObservation,
    ]) {
      const o = await applyLateLandingCycle(
        { facts: facts(c), sourceObservation: obs, nowMs: Date.now() },
        { landingStore, proofStore },
      );
      expect(o.kind === "REMAIN_ATTENTION" || o.kind === "REFUSED_CLOSE").toBe(true);
      expect(landingStore.operations.get(OP_ID)?.status).toBe("NEEDS_ATTENTION");
    }
    expect(landingStore.records).toHaveLength(0);
  });
});

describe("structural no-submit / no-lease-release", () => {
  it("module never wires gateway submit or a lease-release call site", async () => {
    const src = readFileSync(
      fileURLToPath(new URL("./late-landing-reconcile.ts", import.meta.url)),
      "utf8",
    );
    // Strip line comments so documentation of rejected patterns does not trip the gate.
    const code = src
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("//"))
      .join("\n");
    expect(code).not.toMatch(/from ["'].*gateway\/submit/);
    expect(code).not.toMatch(/releaseSendSourceLease\s*\(/);
    expect(code).not.toMatch(/query\([^)]*DELETE\s+FROM\s+wallet_active_leases/i);
    // No grace-window branch that refuses a verified late landing.
    expect(code).not.toMatch(/source:\s*["']LATE_LANDING_OUTSIDE_WINDOW["']/);
    // No unadopted one-hop mint.
    expect(code).not.toMatch(/["']LANDED_DIRECT_SUCCESSOR["']/);
    expect(randomUUID().length).toBeGreaterThan(0);
  });
});
