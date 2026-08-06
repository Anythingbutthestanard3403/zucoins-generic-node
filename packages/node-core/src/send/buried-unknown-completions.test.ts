// adversarial buried / unknown completion suite for SEND_EXTERNAL.
//
// landing-path oracle (any-depth complete-path landing oracle; no PROVEN_NOT_LANDED;
// LANDED_DIRECT_SUCCESSOR one-hop shortcut is NOT implemented)
//
// Non-vacuity rules this suite enforces (against break review):
// 1. Burial ACCEPT uses a real multi-hop body walk on the SOURCE wallet, producing a
// LANDED_COMPLETE_PATH bound to the SEND candidate body; the same pipeline with a
// dropped intermediate body fails closed (no silent oracle early-return).
// 2. Relationship classes are produced by classifyRelationship from prior/next states, then
// mapped to PathObservation tiers with distinct recovery asserts.
// 3. Cross-gateway: two conflicting proofs presented BEFORE first commit; no APPLIED.
// 4. Malformed wire never enters verify with a pre-minted good proof.
// 5. Parent exit: negative matrix + structural no-submit on monitor/verify/commit sources.

import { createHash, createPrivateKey, sign, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  classifyRelationship,
  establishesOrdinaryHead,
  isAnomalousRelationship,
  type VerifiedSemanticState,
} from "../observation/classifier.js";
import type { SettledSplitChainTransaction } from "../protocol/inner.js";
import {
  type LandingPathProof,
  type LandingProofFault,
  type LandingProofOutcome,
} from "../protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import type { PathObservation } from "../protocol/reconcile/observation-input.js";
import { classifySendReconcile } from "../protocol/reconcile/send.js";
import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../verifier/gateway-envelope.js";
import { verifySettledTransaction } from "../verifier/transaction-verify.js";
import {
  classifySendCompletionPoll,
  monitorSendCompletion,
  type CandidateCompletedTx,
  type MonitoredSendDescriptor,
  type SendCompletionPollInput,
  type SendCompletionVerdict,
} from "../workers/send-completion-monitor.js";
import {
  commitExternalSendLanding,
  EXTERNAL_SEND_LANDED_EVENT,
  EXTERNAL_SEND_LANDED_STATUS,
} from "./landing-commit.js";
import { InMemoryExternalSendLandingStore } from "./landing-sql-store.js";
import {
  verifyExternalSendLanding,
  type SendLandingEvidence,
  type SendLandingVerdict,
} from "./landing-verify.js";

// ─── real SEND candidate from receive-golden TARGET (seed_02 → seed_03, 2.25 ZKZ) ─

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
const OP_ID = "30530530-5305-4305-8305-305305305305";
const WALLET_ID = "30530530-5305-4305-8305-305305305306";
const APPROVAL_ID = "30530530-5305-4305-8305-305305305307";
const SOURCE_T0_OBS = "30530530-5305-4305-8305-305305305308";
const DEST_T0_OBS = "30530530-5305-4305-8305-305305305309";
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

function headEnvelope(settledText: string): {
  readonly observationId: string;
  readonly envelope: ReturnType<typeof parseGatewayEnvelope>;
} {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return { observationId: `obs-${settledText.length}`, envelope: parseGatewayEnvelope(bytes) };
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

// Hop-3: seed_02 spends 1.00 more to seed_03 after TARGET — real Ed25519 over A.8 seeds.
const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);
const hop3Inner = {
  type: "unique_combinable" as const,
  version: "2" as const,
  unix_time_secs: "1784332900",
  signer_steps: 2 as const,
  step_1_signer: "sender" as const,
  step_2_signer: "receiver" as const,
  step_1_key_public__base64urlsafe: SOURCE,
  step_2_key_public__base64urlsafe: DEST,
  step_1_state: { amount: "6.75" },
  step_2_state: { amount: "3.25" },
  previous_step_1_state_signature: TARGET.step_2_signature,
  previous_step_2_state_signature: TARGET.step_2_signature,
};
const hop3Step1 = JSON.stringify(hop3Inner);
const hop3Step1Sig = signText(hop3Step1, seed02);
const hop3Step2Pre = JSON.stringify({ inner: hop3Inner, step_1_signature: hop3Step1Sig });
const hop3Step2Sig = signText(hop3Step2Pre, seed03);
const HOP3_TEXT = JSON.stringify({
  inner: hop3Inner,
  step_1_signature: hop3Step1Sig,
  step_2_signature: hop3Step2Sig,
});
const HOP3 = parsedBody(HOP3_TEXT);

/**
 * Source-wallet landing-path oracle path walk (same gap/back-link/head-anchor rules as proveReceiveLanding).
 * Uses production verifySettledTransaction + mintLandingPathProofFromOracle. Mutation of the body
 * sequence (drop intermediate) must fail closed on this same function.
 */
function proveSourcePath(input: {
  readonly wallet: string;
  readonly expected: ParsedSettledTransaction;
  readonly successors: readonly ParsedSettledTransaction[];
  readonly headText: string;
  readonly maxDepth?: number;
}): LandingProofOutcome {
  const depth = input.successors.length;
  const maxDepth = input.maxDepth ?? 64;
  if (depth > maxDepth) {
    return { kind: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" };
  }

  const anchorRead = headEnvelope(input.headText);
  const confirmRead = headEnvelope(input.headText);
  const env = anchorRead.envelope;
  if (env.classification === "GENESIS") {
    return { kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" };
  }
  if (env.classification !== "HEAD") {
    return { kind: "PROOF_INCOMPLETE", fault: "MALFORMED_BODY" };
  }
  const anchorV = verifySettledTransaction(env.parsed, input.wallet);
  if (anchorV.verdict !== "VERIFIED") {
    return {
      kind: "PROOF_INCOMPLETE",
      fault:
        anchorV.verdict === "MALFORMED_TRANSACTION" ? "MALFORMED_BODY" : "ANOMALOUS_OR_CONTRADICTORY",
    };
  }

  const bodies = [input.expected, ...input.successors];
  const seenB = new Set<string>();
  const seenS = new Set<string>();
  let prevS: string | undefined;
  let expectedSha: string | undefined;
  let lastSha: string | undefined;

  for (const body of bodies) {
    const v = verifySettledTransaction(body, input.wallet);
    if (v.verdict !== "VERIFIED") {
      return {
        kind: "PROOF_INCOMPLETE",
        fault: v.verdict === "MALFORMED_TRANSACTION" ? "MALFORMED_BODY" : "ANOMALOUS_OR_CONTRADICTORY",
      };
    }
    if (seenB.has(v.completedTransactionSha256)) {
      return { kind: "PROOF_INCOMPLETE", fault: "DUPLICATE" };
    }
    if (seenS.has(v.projection.S)) {
      return { kind: "PROOF_INCOMPLETE", fault: "CYCLE" };
    }
    if (prevS !== undefined && v.projection.P !== prevS) {
      return { kind: "PROOF_INCOMPLETE", fault: "GAP" };
    }
    seenB.add(v.completedTransactionSha256);
    seenS.add(v.projection.S);
    expectedSha ??= v.completedTransactionSha256;
    prevS = v.projection.S;
    lastSha = v.completedTransactionSha256;
  }

  if (expectedSha === undefined || lastSha === undefined) {
    return { kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" };
  }
  if (lastSha !== anchorV.completedTransactionSha256) {
    return { kind: "PROOF_INCOMPLETE", fault: depth === 0 ? "MISSING_BODY" : "GAP" };
  }

  const confEnv = confirmRead.envelope;
  if (confEnv.classification !== "HEAD") {
    return { kind: "PROOF_INCOMPLETE", fault: "MALFORMED_BODY" };
  }
  const confV = verifySettledTransaction(confEnv.parsed, input.wallet);
  if (confV.verdict !== "VERIFIED") {
    return { kind: "PROOF_INCOMPLETE", fault: "ANOMALOUS_OR_CONTRADICTORY" };
  }
  if (confV.completedTransactionSha256 !== anchorV.completedTransactionSha256) {
    return { kind: "PROOF_INCOMPLETE", fault: "CONFLICT" };
  }

  return mintLandingPathProofFromOracle({
    walletPubkeyBase64Urlsafe: input.wallet,
    expectedBodySha256: expectedSha,
    freshHeadBodySha256: confV.completedTransactionSha256,
    freshHeadObservationId: confirmRead.observationId,
    depth,
  });
}

function landingProofToPathObservation(outcome: LandingProofOutcome): PathObservation {
  return outcome.kind === "PROOF_INCOMPLETE"
    ? { result: "PROOF_INCOMPLETE", fault: outcome.fault }
    : { result: "PROOF", proof: outcome };
}

// ─── SEND candidate + nine-predicate evidence bound to TARGET ─────────────────

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
  const bodyText = TARGET_TEXT;
  return {
    tx: verified.transaction,
    preimage,
    bodyText,
    bodySha: sha256Hex(bodyText),
    innerSha: sha256Hex(preimage),
    transferCodeSha256: sha256Hex(TRANSFER_CODE),
    step1Signature: verified.transaction.step_1_signature,
    step2Signature: verified.transaction.step_2_signature,
  };
}

function baseEvidence(
  c: BuiltCandidate,
  overrides: Partial<SendLandingEvidence> = {},
): SendLandingEvidence {
  const base: SendLandingEvidence = {
    operationId: OP_ID,
    entryStatus: "AWAITING_REDEMPTION",
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
  return { ...base, ...overrides };
}

function descriptor(c: BuiltCandidate): MonitoredSendDescriptor {
  return {
    sendAttemptId: OP_ID,
    sourceWalletId: WALLET_ID,
    sourceWalletPubkeyBase64Urlsafe: SOURCE,
    expectedBodySha256: c.bodySha,
    transferCodeSha256: c.transferCodeSha256,
    innerSha256: c.innerSha,
    step1Signature: c.step1Signature,
  };
}

function boundCandidate(c: BuiltCandidate): CandidateCompletedTx {
  return {
    innerSha256: c.innerSha,
    step1Signature: c.step1Signature,
    step2Signature: c.step2Signature,
    transferCodeSha256: c.transferCodeSha256,
  };
}

function pollInput(
  c: BuiltCandidate,
  observation: PathObservation,
  candidate: CandidateCompletedTx | null = boundCandidate(c),
): SendCompletionPollInput {
  return {
    descriptor: descriptor(c),
    observation,
    observedAt: "2026-07-26T00:00:00.000Z",
    candidate,
    capture: { responseSha256: sha256Hex("wire") },
  };
}

async function runLandingPipeline(
  c: BuiltCandidate,
  observation: PathObservation,
  options: {
    readonly store?: InMemoryExternalSendLandingStore;
    readonly entryStatus?: "AWAITING_REDEMPTION" | "NEEDS_ATTENTION";
  } = {},
): Promise<{
  readonly monitor: SendCompletionVerdict | null;
  readonly verify: SendLandingVerdict | null;
  readonly commit: Awaited<ReturnType<typeof commitExternalSendLanding>> | null;
  readonly store: InMemoryExternalSendLandingStore;
}> {
  const store = options.store ?? new InMemoryExternalSendLandingStore();
  if (!store.operations.has(OP_ID)) {
    store.seed(OP_ID, options.entryStatus ?? "AWAITING_REDEMPTION", WALLET_ID, true);
  }

  const monitor = classifySendCompletionPoll(pollInput(c, observation));

  if (monitor === null || monitor.kind !== "CANDIDATE_MATCH") {
    return { monitor, verify: null, commit: null, store };
  }

  const evidence = baseEvidence(c, {
    entryStatus: options.entryStatus ?? "AWAITING_REDEMPTION",
    sourcePathProof: monitor.proof,
    sourcePathProofIncomplete: false,
  });
  const verify = verifyExternalSendLanding(evidence);
  if (verify.kind !== "VERIFIED") {
    return { monitor, verify, commit: null, store };
  }
  const commit = await commitExternalSendLanding(verify, store, { landedAtMs: 1_700_000_000_000 });
  return { monitor, verify, commit, store };
}

function relationshipToPathObservation(
  relationship: ReturnType<typeof classifyRelationship>["relationship"],
  boundProof: LandingPathProof | null,
): PathObservation {
  switch (relationship) {
    case "SUCCESSOR":
      if (boundProof === null) throw new Error("SUCCESSOR fixture requires a bound proof");
      return { result: "PROOF", proof: boundProof };
    case "FIRST":
      return { result: "NO_SUCCESSOR" };
    case "EQUIVALENT_STATE_DIFFERENT_ENVELOPE":
      if (boundProof === null) throw new Error("EQUIVALENT fixture requires a bound proof");
      return { result: "PROOF", proof: boundProof };
    case "REGRESSION":
    case "GENESIS_AFTER_HISTORY":
    case "SIGNATURE_COLLISION":
      return { result: "ANOMALY", anomaly: relationship };
    case "UNEXPLAINED_JUMP":
      return { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" };
    default: {
      const _x: never = relationship;
      throw new Error(`unhandled relationship ${String(_x)}`);
    }
  }
}

const head = (
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
): VerifiedSemanticState => ({
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
});

describe("exact-head landing (SUCCESSOR baseline)", () => {
  it("real source walk LANDED_EXACT → monitor → nine-predicate VERIFIED → EXTERNAL_SEND_LANDED", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    expect(walk.kind).toBe("LANDED_EXACT");
    if (walk.kind === "PROOF_INCOMPLETE") {
      throw new Error(`exact-head walk must complete: ${walk.fault}`);
    }
    expect(walk.depth).toBe(0);
    expect(walk.expectedBodySha256).toBe(c.bodySha);
    expect(walk.walletPubkeyBase64Urlsafe).toBe(SOURCE);

    const { monitor, verify, commit, store } = await runLandingPipeline(
      c,
      landingProofToPathObservation(walk),
    );

    expect(monitor?.kind).toBe("CANDIDATE_MATCH");
    expect(verify?.kind).toBe("VERIFIED");
    if (verify?.kind === "VERIFIED") {
      expect(verify.proof.kind).toBe("LANDED_EXACT");
      expect(verify.proof.depth).toBe(0);
    }
    expect(commit?.outcome).toBe("APPLIED");
    if (commit?.outcome === "APPLIED") {
      expect(commit.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
      expect(commit.event.eventType).toBe(EXTERNAL_SEND_LANDED_EVENT);
      expect(commit.sourceLeaseStillHeld).toBe(true);
    }
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.records).toHaveLength(1);
    expect(store.events).toHaveLength(1);
  });

  it("NEGATIVE: bare head change without bound candidate cannot land (callback/ACK alone)", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);

    const monitor = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF", proof: walk }, null),
    );
    expect(monitor).toBeNull();

    const verify = verifyExternalSendLanding(baseEvidence(c, { sourcePathProof: null }));
    expect(verify.kind).toBe("INDETERMINATE");
    if (verify.kind === "INDETERMINATE") {
      expect(verify.reason).toBe("SOURCE_PATH_PROOF_ABSENT");
    }
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const commit = await commitExternalSendLanding(verify, store);
    expect(commit.outcome).toBe("REJECTED");
    expect(store.records).toHaveLength(0);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });
});

describe("buried landing (complete path vs one-hop shortcut)", () => {
  it("ACCEPT: genuine multi-hop body walk → LANDED_COMPLETE_PATH on same SEND pipeline", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [HOP3],
      headText: HOP3_TEXT,
    });
    expect(walk.kind).toBe("LANDED_COMPLETE_PATH");
    if (walk.kind === "PROOF_INCOMPLETE") {
      throw new Error(`burial walk must complete: ${walk.fault}`);
    }
    expect(walk.depth).toBe(1);
    expect(walk.expectedBodySha256).toBe(c.bodySha);
    expect(walk.walletPubkeyBase64Urlsafe).toBe(SOURCE);

    const { monitor, verify, commit, store } = await runLandingPipeline(
      c,
      landingProofToPathObservation(walk),
    );
    expect(monitor?.kind).toBe("CANDIDATE_MATCH");
    if (monitor?.kind === "CANDIDATE_MATCH") {
      expect(monitor.proof.kind).toBe("LANDED_COMPLETE_PATH");
      expect(monitor.proof.depth).toBe(1);
      expect(monitor.proof.expectedBodySha256).toBe(c.bodySha);
    }
    expect(verify?.kind).toBe("VERIFIED");
    if (verify?.kind === "VERIFIED") {
      expect(verify.proof.kind).toBe("LANDED_COMPLETE_PATH");
      expect(verify.proof.depth).toBe(1);
      expect(verify.proof.expectedBodySha256).toBe(c.bodySha);
    }
    expect(commit?.outcome).toBe("APPLIED");
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.records).toHaveLength(1);
  });

  it("REFUSE: drop intervening body on same pipeline → MISSING_BODY, never land", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: HOP3_TEXT,
    });
    expect(walk).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" });

    const observation = landingProofToPathObservation(walk);
    const { monitor, verify, commit, store } = await runLandingPipeline(c, observation);
    expect(monitor?.kind).toBe("INDETERMINATE");
    if (monitor?.kind === "INDETERMINATE") {
      expect(monitor.reason).toEqual({
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "MISSING_BODY",
      });
    }
    expect(verify).toBeNull();
    expect(commit).toBeNull();
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    expect(store.records).toHaveLength(0);
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.events).toHaveLength(0);
  });

  it("REFUSE: path that stops short of head is not a one-hop land", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: HOP3_TEXT,
    });
    expect(walk.kind).toBe("PROOF_INCOMPLETE");
    if (walk.kind === "PROOF_INCOMPLETE") {
      expect(walk.fault).toBe("MISSING_BODY");
    }

    const gapWalk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [PREDECESSOR],
      headText: HOP3_TEXT,
    });
    expect(gapWalk.kind).toBe("PROOF_INCOMPLETE");
    if (gapWalk.kind === "PROOF_INCOMPLETE") {
      expect(["GAP", "DUPLICATE", "ANOMALOUS_OR_CONTRADICTORY", "CYCLE"]).toContain(gapWalk.fault);
    }
    const { monitor, commit, store } = await runLandingPipeline(
      c,
      landingProofToPathObservation(gapWalk),
    );
    expect(monitor?.kind).not.toBe("CANDIDATE_MATCH");
    expect(commit).toBeNull();
    expect(store.records).toHaveLength(0);
  });

  it("REFUSE: structural path-proof impostor (incl. unadopted kinds) is not an issued capability", () => {
    const c = buildCandidate();
    const foreign = {
      kind: "LANDED_DIRECT_SUCCESSOR",
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: c.bodySha,
      freshHeadBodySha256: c.bodySha,
      freshHeadObservationId: "obs-foreign",
      depth: 0,
    } as unknown as LandingPathProof;
    const verify = verifyExternalSendLanding(baseEvidence(c, { sourcePathProof: foreign }));
    // unissued structural objects never reach the kind-discriminator fail path —
    // they fail closed before stage-2 authority as src-path blocking INDETERMINATE.
    expect(verify.kind).toBe("INDETERMINATE");
    if (verify.kind === "INDETERMINATE") {
      expect(verify.reason).toBe("SOURCE_PATH_PROOF_ABSENT");
      expect(verify.detail).toMatch(/issued oracle capability/);
    }
  });

  it("reconcile DELIVERED: complete-path proof → LANDED_VERIFIED; gap → INDETERMINATE", () => {
    const c = buildCandidate();
    const complete = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [HOP3],
      headText: HOP3_TEXT,
    });
    if (complete.kind === "PROOF_INCOMPLETE") throw new Error(complete.fault);

    const landed = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: c.transferCodeSha256,
      sourceObservation: { result: "PROOF", proof: complete },
    });
    expect(landed.kind).toBe("LANDED_VERIFIED");

    const gap = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: c.transferCodeSha256,
      sourceObservation: { result: "PROOF_INCOMPLETE", fault: "GAP" },
    });
    expect(gap.kind).toBe("INDETERMINATE");
  });
});

describe("relationship classes (SEND_EXTERNAL)", () => {
  const A = head("sigA", "", "fpA");
  const B = head("sigB", "sigA", "fpB");
  const C = head("sigC", "sigB", "fpC");
  const A_PRIME = head("sigA", "", "fpA");
  const GENESIS: VerifiedSemanticState = {
    isGenesis: true,
    sSignature: "",
    pSignature: "",
    semanticFingerprint: "fpGen",
  };

  it("SUCCESSOR (classifier + real exact-head proof) is the only class that lands", async () => {
    const classified = classifyRelationship({
      prior: A,
      next: B,
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(classified.relationship).toBe("SUCCESSOR");
    expect(establishesOrdinaryHead(classified)).toBe(true);
    expect(isAnomalousRelationship(classified.relationship)).toBe(false);

    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);

    const observation = relationshipToPathObservation(classified.relationship, walk);
    const { commit } = await runLandingPipeline(c, observation);
    expect(commit?.outcome).toBe("APPLIED");
  });

  it("EQUIVALENT_STATE_DIFFERENT_ENVELOPE: classifier + re-fetch does not double-land", async () => {
    const classified = classifyRelationship({
      prior: A,
      next: A_PRIME,
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["sigA"],
    });
    expect(classified.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(classified.stateChanged).toBe(false);
    expect(establishesOrdinaryHead(classified)).toBe(false);

    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);

    const first = await runLandingPipeline(
      c,
      relationshipToPathObservation("SUCCESSOR", walk),
      { store },
    );
    expect(first.commit?.outcome).toBe("APPLIED");

    const secondMonitor = classifySendCompletionPoll({
      ...pollInput(c, relationshipToPathObservation(classified.relationship, walk)),
      capture: { responseSha256: sha256Hex("wire-envelope-B") },
    });
    expect(secondMonitor?.kind).toBe("CANDIDATE_MATCH");
    if (first.verify?.kind !== "VERIFIED") throw new Error("fixture");
    const secondCommit = await commitExternalSendLanding(first.verify, store);
    expect(secondCommit.outcome).toBe("CONFLICT");
    if (secondCommit.outcome === "CONFLICT") {
      expect(secondCommit.reason).toBe("ALREADY_LANDED");
    }
    expect(store.records).toHaveLength(1);
    expect(store.events).toHaveLength(1);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it.each([
    {
      name: "REGRESSION" as const,
      classify: () =>
        classifyRelationship({
          prior: C,
          next: A,
          priorHistoryHasNonGenesis: true,
          acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
        }),
      opsEffect: "park affected operations; page operator; never release or rebuild",
      expectedMonitor: "INVARIANT_BREACH" as const,
    },
    {
      name: "GENESIS_AFTER_HISTORY" as const,
      classify: () =>
        classifyRelationship({
          prior: C,
          next: GENESIS,
          priorHistoryHasNonGenesis: true,
          acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
        }),
      opsEffect: "quarantine wallet and stop its money paths",
      expectedMonitor: "INVARIANT_BREACH" as const,
    },
    {
      name: "SIGNATURE_COLLISION" as const,
      classify: () =>
        classifyRelationship({
          prior: A,
          next: head("sigA", "sigX", "fpCollision"),
          priorHistoryHasNonGenesis: true,
          acceptedStateSignatureHistory: ["sigA"],
        }),
      opsEffect: "stop all money engines and escalate as a protocol/security incident",
      expectedMonitor: "INVARIANT_BREACH" as const,
    },
  ])(
    "$name via classifyRelationship → $expectedMonitor (OPS: $opsEffect)",
    async ({ name, classify, expectedMonitor }) => {
      const classified = classify();
      expect(classified.relationship).toBe(name);
      expect(isAnomalousRelationship(classified.relationship)).toBe(true);
      expect(establishesOrdinaryHead(classified)).toBe(false);

      const c = buildCandidate();
      const observation = relationshipToPathObservation(classified.relationship, null);
      const monitor = classifySendCompletionPoll(pollInput(c, observation));
      expect(monitor?.kind).toBe(expectedMonitor);
      if (monitor?.kind === "INVARIANT_BREACH") {
        expect(monitor.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly: name });
      }

      const reconcile = classifySendReconcile({
        boundary: "DELIVERED",
        sendAttemptId: OP_ID,
        sourceWalletId: WALLET_ID,
        sourceLeaseState: "ACTIVE",
        transferCodeSha256: sha256Hex(TRANSFER_CODE),
        sourceObservation: observation,
      });
      expect(reconcile.kind).toBe("INVARIANT_BREACH");

      const store = new InMemoryExternalSendLandingStore();
      store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
      const { commit, verify } = await runLandingPipeline(c, observation, { store });
      expect(verify).toBeNull();
      expect(commit).toBeNull();
      expect(store.leases.has(WALLET_ID)).toBe(true);
      expect(store.records).toHaveLength(0);
      expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    },
  );

  it("UNEXPLAINED_JUMP via classifyRelationship → INDETERMINATE park (not breach quarantine)", async () => {
    const classified = classifyRelationship({
      prior: C,
      next: head("sigD", "sigUnknown", "fpD"),
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["sigA", "sigB", "sigC"],
    });
    expect(classified.relationship).toBe("UNEXPLAINED_JUMP");
    expect(isAnomalousRelationship(classified.relationship)).toBe(true);
    expect(establishesOrdinaryHead(classified)).toBe(false);

    const c = buildCandidate();
    const observation = relationshipToPathObservation(classified.relationship, null);
    const monitor = classifySendCompletionPoll(pollInput(c, observation));
    expect(monitor?.kind).toBe("INDETERMINATE");
    if (monitor?.kind === "INDETERMINATE") {
      expect(monitor.reason).toEqual({
        source: "OBSERVATION_ANOMALY",
        anomaly: "UNEXPLAINED_JUMP",
      });
    }

    const reconcile = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: sha256Hex(TRANSFER_CODE),
      sourceObservation: observation,
    });
    expect(reconcile.kind).toBe("INDETERMINATE");
    expect(reconcile.kind).not.toBe("WAITING");

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const { commit } = await runLandingPipeline(c, observation, { store });
    expect(commit).toBeNull();
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
  });

  it.each([
    "TRANSPORT_ERROR",
    "MALFORMED_ENVELOPE",
    "MALFORMED_TRANSACTION",
    "UNVERIFIED_SIGNATURE",
    "WALLET_ROLE_INVALID",
  ] as const)(
    "park-class parse anomaly %s → INDETERMINATE (never land, never release, never WAITING)",
    async (anomaly) => {
      const c = buildCandidate();
      const monitor = classifySendCompletionPoll(
        pollInput(c, { result: "ANOMALY", anomaly }),
      );
      expect(monitor?.kind).toBe("INDETERMINATE");
      if (monitor?.kind === "INDETERMINATE") {
        expect(monitor.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly });
      }
      const reconcile = classifySendReconcile({
        boundary: "DELIVERED",
        sendAttemptId: OP_ID,
        sourceWalletId: WALLET_ID,
        sourceLeaseState: "ACTIVE",
        transferCodeSha256: sha256Hex(TRANSFER_CODE),
        sourceObservation: { result: "ANOMALY", anomaly },
      });
      expect(reconcile.kind).toBe("INDETERMINATE");
      const store = new InMemoryExternalSendLandingStore();
      store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
      expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
      expect(store.leases.has(WALLET_ID)).toBe(true);
    },
  );

  it("UNATTRIBUTED_SUCCESSOR_UNDER_LEASE → INVARIANT_BREACH (custody)", () => {
    const c = buildCandidate();
    const monitor = classifySendCompletionPoll(
      pollInput(c, { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" }),
    );
    expect(monitor?.kind).toBe("INVARIANT_BREACH");
    if (monitor?.kind === "INVARIANT_BREACH") {
      expect(monitor.reason.source).toBe("UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE");
    }
  });

  it("FIRST via classifyRelationship is not a landing class — silence stays WAITING", () => {
    const classified = classifyRelationship({
      prior: null,
      next: A,
      priorHistoryHasNonGenesis: false,
      acceptedStateSignatureHistory: [],
    });
    expect(classified.relationship).toBe("FIRST");
    expect(establishesOrdinaryHead(classified)).toBe(false);

    const observation = relationshipToPathObservation(classified.relationship, null);
    expect(observation).toEqual({ result: "NO_SUCCESSOR" });

    const outcome = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: sha256Hex(TRANSFER_CODE),
      sourceObservation: observation,
    });
    expect(outcome.kind).toBe("WAITING");
    if (outcome.kind === "WAITING") {
      expect(outcome.redeliverableTransferCodeSha256).toBe(sha256Hex(TRANSFER_CODE));
    }
  });
});

describe("missing body before observation", () => {
  it("real incomplete path (drop body) → MISSING_BODY on SEND pipeline; lease held", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: HOP3_TEXT,
    });
    expect(walk).toEqual({ kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" });

    const { monitor, verify, commit, store } = await runLandingPipeline(
      c,
      landingProofToPathObservation(walk),
    );
    expect(monitor?.kind).toBe("INDETERMINATE");
    if (monitor?.kind === "INDETERMINATE") {
      expect(monitor.reason).toEqual({
        source: "LANDING_PROOF_INCOMPLETE",
        fault: "MISSING_BODY",
      });
    }
    expect(verify).toBeNull();
    expect(commit).toBeNull();
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.events).toHaveLength(0);
  });

  it("real path short of head with supplied non-linking body → not CANDIDATE_MATCH", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [PREDECESSOR],
      headText: HOP3_TEXT,
    });
    expect(walk.kind).toBe("PROOF_INCOMPLETE");
    const { monitor, commit, store } = await runLandingPipeline(
      c,
      landingProofToPathObservation(walk),
    );
    expect(monitor?.kind).not.toBe("CANDIDATE_MATCH");
    expect(commit).toBeNull();
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it.each(["GAP", "BUDGET_EXHAUSTED", "CONFLICT"] as const)(
    "proof fault %s → monitor INDETERMINATE; never EXTERNAL_SEND_LANDED; lease held",
    async (fault: LandingProofFault) => {
      const c = buildCandidate();
      const monitor = classifySendCompletionPoll(
        pollInput(c, { result: "PROOF_INCOMPLETE", fault }),
      );
      expect(monitor?.kind).toBe("INDETERMINATE");
      if (monitor?.kind === "INDETERMINATE") {
        expect(monitor.reason).toEqual({
          source: "LANDING_PROOF_INCOMPLETE",
          fault,
        });
      }

      const store = new InMemoryExternalSendLandingStore();
      store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
      const { verify, commit } = await runLandingPipeline(
        c,
        { result: "PROOF_INCOMPLETE", fault },
        { store },
      );
      expect(verify).toBeNull();
      expect(commit).toBeNull();
      expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
      expect(store.leases.has(WALLET_ID)).toBe(true);
      expect(store.events).toHaveLength(0);
    },
  );

  it("BUDGET_EXHAUSTED produced by real walk maxDepth=0 with successor", () => {
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [HOP3],
      headText: HOP3_TEXT,
      maxDepth: 0,
    });
    expect(walk).toEqual({ kind: "PROOF_INCOMPLETE", fault: "BUDGET_EXHAUSTED" });
  });
});

describe("recipient stale refusal (no on-chain completion)", () => {
  it("NO_SUCCESSOR keeps monitor polling and reconcile WAITING — no attention, no land", async () => {
    const c = buildCandidate();
    const poll = classifySendCompletionPoll(pollInput(c, { result: "NO_SUCCESSOR" }));
    expect(poll).toBeNull();

    const reconcile = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: c.transferCodeSha256,
      sourceObservation: { result: "NO_SUCCESSOR" },
    });
    expect(reconcile.kind).toBe("WAITING");
    if (reconcile.kind === "WAITING") {
      expect(reconcile.redeliverableTransferCodeSha256).toBe(c.transferCodeSha256);
    }

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
    const recorder = {
      records: [] as unknown[],
      async recordCompletionEvidence(evidence: unknown): Promise<void> {
        this.records.push(evidence);
      },
    };
    let clock = 0;
    const verdict = await monitorSendCompletion(descriptor(c), {
      poll: async () => pollInput(c, { result: "NO_SUCCESSOR" }),
      recorder,
      sleep: async () => undefined,
      nowMs: () => {
        clock += 60_000;
        return clock;
      },
      nowIso: () => "2026-07-26T00:00:00.000Z",
      config: { maxPolls: 3, pollIntervalMs: 0, windowMs: 120_000 },
    });
    expect(verdict.kind).toBe("TIMED_OUT");
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    expect(store.leases.has(WALLET_ID)).toBe(true);
    expect(store.records).toHaveLength(0);
    expect(recorder.records).toHaveLength(1);
  });

  it("NEGATIVE: silence is never classified as FAILED or EXTERNAL_SEND_LANDED", async () => {
    const c = buildCandidate();
    const verify = verifyExternalSendLanding(baseEvidence(c, { candidate: null }));
    expect(verify.kind).toBe("INDETERMINATE");
    if (verify.kind === "INDETERMINATE") expect(verify.reason).toBe("CANDIDATE_ABSENT");
    expect(verify.kind).not.toBe("FAILED");
    expect(verify.kind).not.toBe("VERIFIED");
  });
});

describe("malformed completion", () => {
  it.each([
    "MALFORMED_ENVELOPE",
    "MALFORMED_TRANSACTION",
    "UNVERIFIED_SIGNATURE",
  ] as const)(
    "%s is anomaly path → monitor INDETERMINATE; verify never sees a minted proof",
    async (anomaly) => {
      const c = buildCandidate();
      const observation: PathObservation = { result: "ANOMALY", anomaly };
      const monitor = classifySendCompletionPoll(pollInput(c, observation));
      expect(monitor?.kind).toBe("INDETERMINATE");
      if (monitor?.kind === "INDETERMINATE") {
        expect(monitor.reason).toEqual({ source: "OBSERVATION_ANOMALY", anomaly });
      }

      const { verify, commit, store } = await runLandingPipeline(c, observation);
      expect(verify).toBeNull();
      expect(commit).toBeNull();
      expect(store.records).toHaveLength(0);
      expect(store.leases.has(WALLET_ID)).toBe(true);
      expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    },
  );

  it("broken settled-text candidate alone fails without a positive proof", () => {
    const c = buildCandidate();
    const verify = verifyExternalSendLanding(
      baseEvidence(c, {
        sourcePathProof: null,
        candidate: {
          completedTransaction: c.tx,
          completedTransactionText: "{not-valid-settled",
          completedTransactionSha256: c.bodySha,
          step1PreimageText: c.preimage,
          step1Signature: c.step1Signature,
          step2Signature: c.step2Signature,
          step2SignatureVerified: true,
        },
      }),
    );
    expect(verify.kind).not.toBe("VERIFIED");
    expect(["INDETERMINATE", "FAILED"]).toContain(verify.kind);
  });

  it("source path walk on garbage head never yields a positive path proof", () => {
    const garbageBytes = new TextEncoder().encode(
      `{"status":true,"code":"success","message":"","data":[{"not":"a-settled-tx"}]}`,
    );
    const envelope = parseGatewayEnvelope(garbageBytes);
    expect(envelope.classification).not.toBe("HEAD");

    const garbageHead = `{"not":"a-settled-tx"}`;
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: garbageHead,
    });
    expect(walk.kind).toBe("PROOF_INCOMPLETE");
    if (walk.kind === "PROOF_INCOMPLETE") {
      expect(["MALFORMED_BODY", "MISSING_BODY", "ANOMALOUS_OR_CONTRADICTORY"]).toContain(
        walk.fault,
      );
    }
  });
});

describe("endpoint lag / cross-gateway disagreement", () => {
  it("two conflicting proofs before first commit: neither stream lands; lease held", async () => {
    const c = buildCandidate();
    const honestWalk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (honestWalk.kind === "PROOF_INCOMPLETE") throw new Error(honestWalk.fault);

    const foreignBodySha = "f".repeat(64);
    const foreignProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: foreignBodySha,
      freshHeadBodySha256: foreignBodySha,
      freshHeadObservationId: randomUUID(),
      depth: 0,
    });

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);

    const monitorA = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF", proof: honestWalk }),
    );
    const monitorB = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF", proof: foreignProof }),
    );

    expect(monitorA?.kind).toBe("CANDIDATE_MATCH");
    expect(monitorB).toBeNull();

    const verifyB = verifyExternalSendLanding(
      baseEvidence(c, { sourcePathProof: foreignProof }),
    );
    expect(verifyB.kind).toBe("FAILED");
    if (verifyB.kind === "FAILED") {
      expect(verifyB.failedPredicate).toBe("source_exact_head");
    }

    expect(store.records).toHaveLength(0);
    expect(store.events).toHaveLength(0);
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    expect(store.leases.has(WALLET_ID)).toBe(true);

    if (monitorA?.kind !== "CANDIDATE_MATCH") throw new Error("fixture");
    const verifyA = verifyExternalSendLanding(
      baseEvidence(c, { sourcePathProof: monitorA.proof }),
    );
    expect(verifyA.kind).toBe("VERIFIED");
    const commitA = await commitExternalSendLanding(verifyA, store, {
      landedAtMs: 1_700_000_000_000,
    });
    expect(commitA.outcome).toBe("APPLIED");

    const commitB = await commitExternalSendLanding(verifyB, store);
    expect(commitB.outcome).toBe("REJECTED");
    expect(store.records).toHaveLength(1);
    expect(store.events).toHaveLength(1);
    expect(store.records[0]!.completedTransactionSha256).toBe(c.bodySha);
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("pre-land dual INDETERMINATE: CONFLICT fault + foreign proof → no APPLIED, lease held", async () => {
    const c = buildCandidate();
    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);

    const streamConflict = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF_INCOMPLETE", fault: "CONFLICT" }),
    );
    expect(streamConflict?.kind).toBe("INDETERMINATE");

    const foreignProof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: "e".repeat(64),
      freshHeadBodySha256: "e".repeat(64),
      freshHeadObservationId: randomUUID(),
      depth: 0,
    });
    const streamForeign = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF", proof: foreignProof }),
    );
    expect(streamForeign).toBeNull();

    expect(store.records).toHaveLength(0);
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
    expect(store.leases.has(WALLET_ID)).toBe(true);

    const reconcile = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: c.transferCodeSha256,
      sourceObservation: { result: "PROOF_INCOMPLETE", fault: "CONFLICT" },
    });
    expect(reconcile.kind).toBe("INDETERMINATE");
  });
});

describe("restart mid-verification", () => {
  it("crash between CANDIDATE_MATCH and SETTLED_BODY_PERSISTED: resume lands once", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);

    const monitor = classifySendCompletionPoll(
      pollInput(c, { result: "PROOF", proof: walk }),
    );
    expect(monitor?.kind).toBe("CANDIDATE_MATCH");
    if (monitor?.kind !== "CANDIDATE_MATCH") throw new Error("expected match");

    const verify = verifyExternalSendLanding(
      baseEvidence(c, { sourcePathProof: monitor.proof }),
    );
    expect(verify.kind).toBe("VERIFIED");
    expect(store.records).toHaveLength(0);
    expect(store.events).toHaveLength(0);
    expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");

    const postRestartVerify = verifyExternalSendLanding(
      baseEvidence(c, { sourcePathProof: monitor.proof }),
    );
    expect(postRestartVerify.kind).toBe("VERIFIED");

    const first = await commitExternalSendLanding(postRestartVerify, store, {
      landedAtMs: 1_700_000_000_100,
    });
    expect(first.outcome).toBe("APPLIED");

    const second = await commitExternalSendLanding(postRestartVerify, store, {
      landedAtMs: 1_700_000_000_200,
    });
    expect(second.outcome).toBe("CONFLICT");
    if (second.outcome === "CONFLICT") expect(second.reason).toBe("ALREADY_LANDED");

    expect(store.records).toHaveLength(1);
    expect(store.events).toHaveLength(1);
    expect(store.events.filter((e) => e.eventType === EXTERNAL_SEND_LANDED_EVENT)).toHaveLength(
      1,
    );
    expect(store.leases.has(WALLET_ID)).toBe(true);
  });

  it("re-running monitor after land does not emit a second external_send.landed", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [],
      headText: TARGET_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);

    const store = new InMemoryExternalSendLandingStore();
    store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);

    const pipeline = await runLandingPipeline(
      c,
      { result: "PROOF", proof: walk },
      { store },
    );
    expect(pipeline.commit?.outcome).toBe("APPLIED");

    const again = classifySendCompletionPoll(pollInput(c, { result: "PROOF", proof: walk }));
    expect(again?.kind).toBe("CANDIDATE_MATCH");
    if (pipeline.verify?.kind !== "VERIFIED") throw new Error("fixture");
    const recommit = await commitExternalSendLanding(pipeline.verify, store);
    expect(recommit.outcome).toBe("CONFLICT");
    expect(store.events).toHaveLength(1);
  });
});

describe("no false landed / no false terminal non-landing", () => {
  it("NEGATIVE matrix: none of callback/silence/ACK/bare-anomaly classes produce EXTERNAL_SEND_LANDED", async () => {
    const c = buildCandidate();
    const observations: PathObservation[] = [
      { result: "NO_SUCCESSOR" },
      { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
      { result: "PROOF_INCOMPLETE", fault: "GAP" },
      { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" },
      { result: "ANOMALY", anomaly: "REGRESSION" },
      { result: "ANOMALY", anomaly: "MALFORMED_ENVELOPE" },
      { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
      {
        result: "PROOF",
        proof: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: SOURCE,
      expectedBodySha256: "0".repeat(64),
      freshHeadBodySha256: "0".repeat(64),
      freshHeadObservationId: "obs-x",
      depth: 0,
    }),
      },
    ];

    for (const observation of observations) {
      const store = new InMemoryExternalSendLandingStore();
      store.seed(OP_ID, "AWAITING_REDEMPTION", WALLET_ID, true);
      const { monitor, commit } = await runLandingPipeline(c, observation, { store });
      if (monitor === null || monitor.kind !== "CANDIDATE_MATCH") {
        expect(commit).toBeNull();
        expect(store.operations.get(OP_ID)?.status).toBe("AWAITING_REDEMPTION");
        expect(store.events).toHaveLength(0);
      } else {
        expect(commit?.outcome).not.toBe("APPLIED");
      }
      expect(store.leases.has(WALLET_ID)).toBe(true);
    }
  });

  it("NEGATIVE: silence/gap never yield a REJECTED operation status (no false non-landing terminal)", () => {
    for (const observation of [
      { result: "NO_SUCCESSOR" } as const,
      { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" } as const,
      { result: "ANOMALY", anomaly: "UNEXPLAINED_JUMP" } as const,
    ]) {
      const outcome = classifySendReconcile({
        boundary: "DELIVERED",
        sendAttemptId: OP_ID,
        sourceWalletId: WALLET_ID,
        sourceLeaseState: "ACTIVE",
        transferCodeSha256: sha256Hex(TRANSFER_CODE),
        sourceObservation: observation,
      });
      expect(outcome.kind).not.toBe("LANDED_VERIFIED");
      expect(["WAITING", "INDETERMINATE", "INVARIANT_BREACH"]).toContain(outcome.kind);
    }
  });

  it("parent exit criterion: only operation-bound landing-path oracle proof + nine predicates land", async () => {
    const c = buildCandidate();
    const walk = proveSourcePath({
      wallet: SOURCE,
      expected: TARGET,
      successors: [HOP3],
      headText: HOP3_TEXT,
    });
    if (walk.kind === "PROOF_INCOMPLETE") throw new Error(walk.fault);
    const { commit, store } = await runLandingPipeline(c, {
      result: "PROOF",
      proof: walk,
    });
    expect(commit?.outcome).toBe("APPLIED");
    expect(store.events).toHaveLength(1);
    expect(store.events[0]!.eventType).toBe(EXTERNAL_SEND_LANDED_EVENT);
  });

  it("parent exit: monitor/verify/commit sources never import a gateway submit surface", () => {
    const here = import.meta.url;
    const monitorSrc = readFileSync(
      fileURLToPath(new URL("../workers/send-completion-monitor.ts", here)),
      "utf8",
    );
    const verifySrc = readFileSync(fileURLToPath(new URL("./landing-verify.ts", here)), "utf8");
    const commitSrc = readFileSync(fileURLToPath(new URL("./landing-commit.ts", here)), "utf8");

    // Production surfaces only — scanning this suite would self-match the forbidden literals.
    for (const [label, src] of [
      ["send-completion-monitor", monitorSrc],
      ["landing-verify", verifySrc],
      ["landing-commit", commitSrc],
    ] as const) {
      expect(src, label).not.toMatch(/from ["'].*gateway\/submit/);
      expect(src, label).not.toMatch(/submitGatewayActionOnce/);
      expect(src, label).not.toMatch(/submitGatewayRequestOnce/);
      expect(src, label).not.toMatch(/\bSUBMIT_ACTION_NAME\b/);
    }
    // Suite itself imports only observation/monitor/verify/commit — no gateway module.
    const suiteImports = readFileSync(fileURLToPath(new URL(here)), "utf8")
      .split("\n")
      .filter((line) => /^import\s/.test(line));
    for (const line of suiteImports) {
      expect(line).not.toMatch(/gateway\//);
      expect(line).not.toMatch(/submit/i);
    }
  });
});
