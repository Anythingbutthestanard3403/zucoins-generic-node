// vectors for the RECEIVE_EXTERNAL landing DB-TX.
//
// Driven by the same frozen golden pair the landing-path oracle vectors use: for wallet
// seed_02, `predecessor` credits it 10 ZKZ from genesis and `target` then spends 2.25, so
// `target.P(seed_02) == predecessor.S(seed_02)`. Every signature is a real Ed25519 signature
// over real signed bytes — no body is hand-assembled and no digest is hardcoded.
//
// Each rejection below is reached by evidence that fails exactly one cross-check while the
// others hold, so no assertion here can be satisfied vacuously.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verificationMaterialAvailableUntilMs } from "../data/retention.js";
import {
  type LandingProofOutcome,
} from "../protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../protocol/reconcile/landing-oracle-mint.fixture.js";
import { parseGatewayEnvelope, type ParsedSettledTransaction } from "../verifier/gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "../verifier/landing-path-oracle.js";
import {
  RECEIVE_LANDED_EVENT,
  buildPathManifestText,
  buildReceiveLandingPath,
  commitReceiveLanding,
  sha256HexUtf8,
  verifyAndCommitReceiveLanding,
  type CommitReceiveLandingInput,
} from "./landing-commit.js";
import { InMemoryReceiveLandingStore } from "./landing-sql-store.js";

const GEN_DIR = new URL("../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const RECEIVER_KEY = MANIFEST.public_keys.seed_02 as string;
const UNRELATED_KEY = MANIFEST.public_keys.seed_03 as string;
const TERMINAL_OBS = "44444444-4444-4444-8444-444444444444";

function headEnvelope(settledText: string): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  // Terminal confirm-read id must match commitReceiveLanding's terminalObservationId (R2).
  return { observationId: TERMINAL_OBS, envelope: parseGatewayEnvelope(bytes) };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope verdict");
  return verdict.parsed;
}

function staticReader(settledText: string): ReadFreshHead {
  return async () => headEnvelope(settledText);
}

function movingReader(first: string, rest: string): ReadFreshHead {
  let calls = 0;
  return async () => {
    calls += 1;
    return headEnvelope(calls === 1 ? first : rest);
  };
}

/** Swap in another body's step_2_signature: shape and scalars pass, Ed25519 does not. */
function withForeignStepTwoSignature(settledText: string, donorText: string): string {
  const marker = ',"step_2_signature":"';
  const donorStart = donorText.indexOf(marker) + marker.length;
  const donorSignature = donorText.slice(donorStart, donorText.indexOf('"', donorStart));
  const start = settledText.indexOf(marker) + marker.length;
  const end = settledText.indexOf('"', start);
  return settledText.slice(0, start) + donorSignature + settledText.slice(end);
}

const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");
const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);

// Real digests, re-derived from the exact signed text rather than pinned as literals.
function digestOf(body: ParsedSettledTransaction, wallet = RECEIVER_KEY): string {
  const built = buildReceiveLandingPath([body], wallet);
  if ("unverifiedIndex" in built) throw new Error("fixture failed to verify");
  return built.path[0]!.completedTransactionSha256;
}
const PREDECESSOR_SHA = digestOf(PREDECESSOR);
const TARGET_SHA = digestOf(TARGET);

const OPERATION_ID = "11111111-1111-4111-8111-111111111111";
const WALLET_ROW_ID = "22222222-2222-4222-8222-222222222222";
const T0_OBS = "33333333-3333-4333-8333-333333333333";
const LANDED_AT_MS = 1_700_000_000_000;
const WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

function commitInput(
  bodies: readonly ParsedSettledTransaction[],
  overrides: Partial<CommitReceiveLandingInput> = {},
): CommitReceiveLandingInput {
  return {
    operationId: OPERATION_ID,
    expectedRowVersion: 1,
    walletPubkeyBase64Urlsafe: RECEIVER_KEY,
    t0ObservationId: T0_OBS,
    terminalObservationId: TERMINAL_OBS,
    bodies,
    landedAtMs: LANDED_AT_MS,
    proofAccessWindowMs: WINDOW_MS,
    ...overrides,
  };
}

function seededStore(): InMemoryReceiveLandingStore {
  const store = new InMemoryReceiveLandingStore();
  store.seed(OPERATION_ID, "READY", WALLET_ROW_ID, 1);
  return store;
}

const exactProof: LandingProofOutcome = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: PREDECESSOR_SHA,
      freshHeadBodySha256: PREDECESSOR_SHA,
      freshHeadObservationId: TERMINAL_OBS,
      depth: 0,
    });
const buriedProof: LandingProofOutcome = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: PREDECESSOR_SHA,
      freshHeadBodySha256: TARGET_SHA,
      freshHeadObservationId: TERMINAL_OBS,
      depth: 1,
    });

describe("receive landing commit — positive landings persist the complete ordered path", () => {
  it("lands LANDED_EXACT: one body, SETTLED_BODY_PERSISTED/LANDED_VERIFIED, proof-access expiry", async () => {
    const store = seededStore();
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.status).toBe("RECEIVE_LANDED");
    expect(result.proof.attemptPhase).toBe("SETTLED_BODY_PERSISTED");
    expect(result.proof.publicExecutionPhase).toBe("LANDED_VERIFIED");
    expect(result.proof.pathRole).toBe("RECEIVER");
    expect(result.proof.verdict).toBe("LANDED_EXACT");
    expect(result.proof.bodyCount).toBe(1);
    expect(result.proof.pathDepth).toBe(0);
    // Depth 0 means the expected attempt IS the fresh head.
    expect(result.proof.expectedCompletedTransactionSha256).toBe(PREDECESSOR_SHA);
    expect(result.proof.freshHeadCompletedTransactionSha256).toBe(PREDECESSOR_SHA);
    expect(result.proof.verificationMaterialAvailableUntilMs).toBe(
      verificationMaterialAvailableUntilMs(LANDED_AT_MS, WINDOW_MS),
    );

    // The ordered path is persisted, not just its shape.
    expect(result.path).toHaveLength(1);
    expect(result.path[0]!.pathIndex).toBe(0);
    expect(result.path[0]!.sourceKind).toBe("EXPECTED_OPERATION");
    expect(result.path[0]!.completedTransactionText).toBe(PREDECESSOR_TEXT);
    expect(result.path[0]!.completedTransactionOctets).toBe(
      Buffer.byteLength(PREDECESSOR_TEXT, "utf8"),
    );

    expect(store.operations.get(OPERATION_ID)!.status).toBe("RECEIVE_LANDED");
    expect(store.operations.get(OPERATION_ID)!.rowVersion).toBe(2);
    expect(store.proofs).toHaveLength(1);
    expect(store.pathBodies[0]).toHaveLength(1);
    expect(store.events).toHaveLength(1);
  });

  it("lands LANDED_COMPLETE_PATH: both hops persisted in sequence, backlinked, head last", async () => {
    const store = seededStore();
    const result = await commitReceiveLanding(
      buriedProof,
      commitInput([PREDECESSOR, TARGET]),
      store,
    );

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.proof.verdict).toBe("LANDED_COMPLETE_PATH");
    expect(result.proof.bodyCount).toBe(2);
    expect(result.proof.pathDepth).toBe(1);
    // The proof still identifies the EXPECTED attempt, never the head's own body — the
    // misidentification, barred here by construction.
    expect(result.proof.expectedCompletedTransactionSha256).toBe(PREDECESSOR_SHA);
    expect(result.proof.freshHeadCompletedTransactionSha256).toBe(TARGET_SHA);
    expect(result.proof.expectedCompletedTransactionSha256).not.toBe(
      result.proof.freshHeadCompletedTransactionSha256,
    );

    expect(result.path.map((b) => b.pathIndex)).toEqual([0, 1]);
    expect(result.path.map((b) => b.sourceKind)).toEqual([
      "EXPECTED_OPERATION",
      "FRESH_GATEWAY_HEAD",
    ]);
    expect(result.path[1]!.pSignature).toBe(result.path[0]!.sSignature);
    expect(result.path[1]!.completedTransactionText).toBe(TARGET_TEXT);
  });

  it("appends receive.landed exactly once, byte-stable, co-committed with the landing", async () => {
    const store = seededStore();
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.event.eventType).toBe(RECEIVE_LANDED_EVENT);
    expect(result.event.dataText).toBe(
      JSON.stringify({
        terminal_observation_id: TERMINAL_OBS,
        landed_at: new Date(LANDED_AT_MS).toISOString(),
      }),
    );
    // The event exists only alongside the landing record — never one without the other.
    expect(store.events).toHaveLength(store.proofs.length);
  });

  it("persists a manifest an independent verifier re-derives from the stored rows", async () => {
    const store = seededStore();
    const result = await commitReceiveLanding(
      buriedProof,
      commitInput([PREDECESSOR, TARGET]),
      store,
    );

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(sha256HexUtf8(result.proof.pathManifestText)).toBe(result.proof.pathManifestSha256);
    // Re-derivation from the persisted path alone reproduces the digest byte for byte.
    const rederived = buildPathManifestText(
      buriedProof as Extract<LandingProofOutcome, { kind: "LANDED_COMPLETE_PATH" }>,
      TARGET_SHA,
      store.pathBodies[0]!,
    );
    expect(sha256HexUtf8(rederived)).toBe(result.proof.pathManifestSha256);
  });
});

describe("receive landing commit — nothing lands without its own evidence", () => {
  it("refuses a PROOF_INCOMPLETE outcome and writes nothing", async () => {
    const store = seededStore();
    const result = await commitReceiveLanding(
      { kind: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
      commitInput([PREDECESSOR]),
      store,
    );

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.proofs).toHaveLength(0);
    expect(store.events).toHaveLength(0);
  });

  it("refuses a proof minted for a different wallet", async () => {
    const store = seededStore();
    const foreign = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: UNRELATED_KEY,
      expectedBodySha256: PREDECESSOR_SHA,
      freshHeadBodySha256: PREDECESSOR_SHA,
      freshHeadObservationId: "obs",
      depth: 0,
    });
    const result = await commitReceiveLanding(foreign, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "WALLET_MISMATCH" });
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses when the body count does not match the proof depth", async () => {
    const store = seededStore();
    // Depth 1 demands two bodies; only the expected attempt is supplied.
    const result = await commitReceiveLanding(buriedProof, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PATH_DEPTH_MISMATCH" });
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses when path index 0 is not the attempt the proof names", async () => {
    const store = seededStore();
    const mismatched = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: TARGET_SHA,
      freshHeadBodySha256: TARGET_SHA,
      freshHeadObservationId: "obs",
      depth: 0,
    });
    const result = await commitReceiveLanding(mismatched, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({
      outcome: "REJECTED",
      reason: "PATH_EXPECTED_ANCHOR_MISMATCH",
    });
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses a buried path that terminates at the expected attempt itself", async () => {
    const store = seededStore();
    // Two bodies satisfying the depth, both the expected attempt: the head anchor collapses
    // onto the expected anchor, which only LANDED_EXACT may do.
    const result = await commitReceiveLanding(
      buriedProof,
      commitInput([PREDECESSOR, PREDECESSOR]),
      store,
    );

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PATH_HEAD_ANCHOR_MISMATCH" });
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses a path whose backlink does not hold at some hop", async () => {
    const store = seededStore();
    // TARGET then PREDECESSOR: both verify for this wallet, the anchors are distinct, but
    // PREDECESSOR.P (genesis-adjacent, "") is not TARGET.S.
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: TARGET_SHA,
      freshHeadBodySha256: PREDECESSOR_SHA,
      freshHeadObservationId: TERMINAL_OBS,
      depth: 1,
    });
    const result = await commitReceiveLanding(proof, commitInput([TARGET, PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PATH_BACKLINK_BROKEN" });
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses a path body that does not reverify at persist time", async () => {
    const store = seededStore();
    const forged = parsedBody(withForeignStepTwoSignature(TARGET_TEXT, PREDECESSOR_TEXT));
    const result = await commitReceiveLanding(
      buriedProof,
      commitInput([PREDECESSOR, forged]),
      store,
    );

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PATH_BODY_UNVERIFIED" });
    expect(store.proofs).toHaveLength(0);
  });
});

describe("receive landing commit — the CAS is the arbiter, and the lease is untouched", () => {
  it("lands once: the second attempt conflicts and no second event is appended", async () => {
    const store = seededStore();
    const first = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);
    expect(first.outcome).toBe("APPLIED");

    const second = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);
    expect(second).toMatchObject({ outcome: "CONFLICT", reason: "ALREADY_LANDED" });
    expect(store.events).toHaveLength(1);
    expect(store.proofs).toHaveLength(1);
  });

  it("refuses a stale row_version even while the status still reads READY", async () => {
    const store = seededStore();
    // The caller read the row at version 1; a concurrent writer has since bumped it.
    store.operations.get(OPERATION_ID)!.rowVersion = 2;
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "CONFLICT", reason: "STATUS_GUARD_MISMATCH" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.events).toHaveLength(0);
  });

  it("refuses a status other than READY", async () => {
    const store = new InMemoryReceiveLandingStore();
    store.seed(OPERATION_ID, "CREATED", WALLET_ROW_ID, 1);
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "CONFLICT", reason: "STATUS_GUARD_MISMATCH" });
    expect(store.proofs).toHaveLength(0);
  });

  it("leaves the receiver lease exactly as it found it", async () => {
    const store = seededStore();
    const before = [...store.leases];
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.receiverLeaseStillHeld).toBe(true);
    expect([...store.leases]).toEqual(before);
  });

  it("NODE_VERIFIED + HOLD: APPLIED with receiverLeaseStillHeld false (same-TX release)", async () => {
    const store = new InMemoryReceiveLandingStore();
    store.seed(OPERATION_ID, "READY", WALLET_ROW_ID, 1, true, {
      verificationMode: "NODE_VERIFIED",
      afterLanding: "HOLD",
    });
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.receiverLeaseStillHeld).toBe(false);
    expect(store.leases.has(WALLET_ROW_ID)).toBe(false);
    expect(store.operations.get(OPERATION_ID)!.receiveReleaseStatus).toBe(
      "RELEASED_NODE_VERIFIED",
    );
  });

  it("NODE_VERIFIED + INTERNAL_MOVE: APPLIED keeps receiver lease for child handoff", async () => {
    const store = new InMemoryReceiveLandingStore();
    store.seed(OPERATION_ID, "READY", WALLET_ROW_ID, 1, true, {
      verificationMode: "NODE_VERIFIED",
      afterLanding: "INTERNAL_MOVE",
    });
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.receiverLeaseStillHeld).toBe(true);
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
    expect(store.operations.get(OPERATION_ID)!.receiveReleaseStatus).toBeNull();
  });

  it("refuses to land when the receiver lease is already gone", async () => {
    const store = new InMemoryReceiveLandingStore();
    store.seed(OPERATION_ID, "READY", WALLET_ROW_ID, 1, false);
    const result = await commitReceiveLanding(exactProof, commitInput([PREDECESSOR]), store);

    expect(result).toMatchObject({ outcome: "CONFLICT", reason: "LEASE_MISSING" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
  });

  it("refuses a command whose persisted path is shorter than its declared body count", async () => {
    const store = seededStore();
    const applied = await commitReceiveLanding(buriedProof, commitInput([PREDECESSOR, TARGET]), store);
    expect(applied.outcome).toBe("APPLIED");
    if (applied.outcome !== "APPLIED") return;

    // Re-issue the same landing against a fresh row with one body dropped: the store's
    // completeness guard refuses it (the deferred DB trigger's in-memory mirror).
    const fresh = seededStore();
    const short = await fresh.commitLanding({
      operationId: OPERATION_ID,
      expectedRowVersion: 1,
      expectedStatus: "READY",
      proof: applied.proof,
      path: applied.path.slice(0, 1),
      event: applied.event,
    });
    expect(short).toMatchObject({ applied: false, reason: "PATH_INCOMPLETE" });
    expect(fresh.operations.get(OPERATION_ID)!.status).toBe("READY");
  });

  it("refuses structural impostor outcome (not an issued capability)", async () => {
    const store = seededStore();
    const impostor = {
      kind: "LANDED_EXACT",
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: PREDECESSOR_SHA,
      freshHeadBodySha256: PREDECESSOR_SHA,
      freshHeadObservationId: "obs-forged",
      depth: 0,
    } as LandingProofOutcome;
    const result = await commitReceiveLanding(impostor, commitInput([PREDECESSOR]), store);
    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.proofs).toHaveLength(0);
  });

  it("refuses when terminalObservationId is unbound from proof freshHeadObservationId", async () => {
    const store = seededStore();
    const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: RECEIVER_KEY,
      expectedBodySha256: PREDECESSOR_SHA,
      freshHeadBodySha256: PREDECESSOR_SHA,
      freshHeadObservationId: "obs-head-unbound",
      depth: 0,
    });
    const result = await commitReceiveLanding(proof, commitInput([PREDECESSOR]), store);
    expect(result).toMatchObject({
      outcome: "REJECTED",
      reason: "PATH_HEAD_ANCHOR_MISMATCH",
    });
    expect(store.proofs).toHaveLength(0);
    expect(store.events).toHaveLength(0);
  });
});

describe("receive landing commit — F end to end", () => {
  const oracleInput = {
    walletPubkeyBase64Urlsafe: RECEIVER_KEY,
    t0Body: null,
    expectedBody: PREDECESSOR,
    successorBodies: [] as readonly ParsedSettledTransaction[],
    operation: { amountZkz: "10", receiverPubkey: RECEIVER_KEY },
  };
  const tail = {
    operationId: OPERATION_ID,
    expectedRowVersion: 1,
    t0ObservationId: T0_OBS,
    terminalObservationId: TERMINAL_OBS,
    landedAtMs: LANDED_AT_MS,
    proofAccessWindowMs: WINDOW_MS,
  };

  it("verifies against a live confirm-read and commits the landing it proves", async () => {
    const store = seededStore();
    const result = await verifyAndCommitReceiveLanding(
      oracleInput,
      tail,
      staticReader(PREDECESSOR_TEXT),
      store,
    );

    expect(result.outcome).toBe("APPLIED");
    expect(store.operations.get(OPERATION_ID)!.status).toBe("RECEIVE_LANDED");
    expect(store.events).toHaveLength(1);
  });

  it("commits a buried landing only across the supplied complete path", async () => {
    const store = seededStore();
    const result = await verifyAndCommitReceiveLanding(
      { ...oracleInput, successorBodies: [TARGET] },
      tail,
      staticReader(TARGET_TEXT),
      store,
    );

    expect(result.outcome).toBe("APPLIED");
    if (result.outcome !== "APPLIED") return;
    expect(result.proof.verdict).toBe("LANDED_COMPLETE_PATH");
    expect(store.pathBodies[0]).toHaveLength(2);
  });

  it("writes nothing when the head moves mid-verification (INDETERMINATE, never stale)", async () => {
    const store = seededStore();
    const result = await verifyAndCommitReceiveLanding(
      oracleInput,
      tail,
      movingReader(PREDECESSOR_TEXT, TARGET_TEXT),
      store,
    );

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.proofs).toHaveLength(0);
    expect(store.events).toHaveLength(0);
    // The lease survives an INDETERMINATE outcome untouched (possible landing
    // retains the lease).
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });

  it("writes nothing when the attempt is buried and no bridging body was supplied", async () => {
    const store = seededStore();
    const result = await verifyAndCommitReceiveLanding(
      oracleInput,
      tail,
      staticReader(TARGET_TEXT),
      store,
    );

    expect(result).toMatchObject({ outcome: "REJECTED", reason: "PROOF_NOT_POSITIVE" });
    expect(store.operations.get(OPERATION_ID)!.status).toBe("READY");
    expect(store.leases.has(WALLET_ROW_ID)).toBe(true);
  });
});
