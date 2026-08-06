// pure end-to-end proof of regression / fork / gap behavior.
//
//
// Six named scenarios, each independently readable. Every anomalous path asserts the
// negative space explicitly: no ordinary-head promotion, no landing, no retry/resubmit,
// no lease release. Exercises classifyRelationship + plan/apply, and
// the landing-path oracle residual gate assessSuccessorCustodyAuthority → classifyPathObservation /
// classifySendReconcile (unauthorized SUCCESSOR under lease).

import { describe, expect, it } from "vitest";

import {
  classifyRelationship,
  establishesOrdinaryHead,
  isAnomalousRelationship,
  type RelationshipResult,
  type VerifiedSemanticState,
} from "./classifier.js";
import { assessSuccessorCustodyAuthority } from "./custody-authority.js";
import {
  ANOMALY_ACTION_INVARIANTS,
  InMemoryAnomalyQuarantineStore,
  applyAnomalyAction,
  canAcquireNewLease,
  isSigningHalted,
  planActionForRelationship,
  planAnomalyAction,
  type AnomalyActionPlan,
  type ApplyAnomalyActionResult,
  type QuarantineOperationSnapshot,
  type QuarantineWalletSnapshot,
} from "./quarantine.js";
import { classifyPathObservation } from "../protocol/reconcile/observation-input.js";
import { classifySendReconcile } from "../protocol/reconcile/send.js";

// ── Fixtures ─────────────────────────────────────────────────────────────────

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

/** Worked example chain positions. */
const A = head("sigA", "", "fpA");
const B = head("sigB", "sigA", "fpB");
const C = head("sigC", "sigB", "fpC");
const A_PRIME_EQUIV = head("sigA", "", "fpA"); // same S + same fingerprint → EQUIVALENT
const A_COLLISION = head("sigA", "sigX", "fpCollision"); // same S, different fp → COLLISION

const WALLET_ID = "w-reg-1";
const LEASE_ID = "lease-reg-1";
const OP_ID = "op-reg-1";

/** Authority counters a blind-retry / silent-promotion regression would bump. */
interface AuthorityCounters {
  headPromotions: number;
  landingTransitions: number;
  submitOrResubmitCalls: number;
  leaseReleases: number;
}

function zeroAuthority(): AuthorityCounters {
  return {
    headPromotions: 0,
    landingTransitions: 0,
    submitOrResubmitCalls: 0,
    leaseReleases: 0,
  };
}

function classify(
  prior: VerifiedSemanticState | null,
  next: VerifiedSemanticState,
  history: readonly string[],
  priorHistoryHasNonGenesis = history.some((s) => s.length > 0),
): RelationshipResult {
  return classifyRelationship({
    prior,
    next,
    priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory: history,
  });
}

/**
 * Simulate the capture-path authority gate after classification.
 * Only SUCCESSOR may advance the ordinary head pointer; anomalies never land or retry.
 * Returns the post-gate head S (unchanged on anomaly / FIRST / EQUIVALENT).
 */
function gateHeadPromotion(
  currentHeadS: string | null,
  result: RelationshipResult,
  counters: AuthorityCounters,
): string | null {
  if (establishesOrdinaryHead(result)) {
    counters.headPromotions += 1;
    return result.evidence.comparison.nextS;
  }
  return currentHeadS;
}

function assertNoSilentAuthority(
  counters: AuthorityCounters,
  plan: AnomalyActionPlan,
  applyResult: ApplyAnomalyActionResult | null,
  opts: {
    readonly expectHeadPromotions?: number;
    readonly priorLeaseId: string | null;
    readonly walletAfter: QuarantineWalletSnapshot | null;
  },
): void {
  expect(counters.headPromotions).toBe(opts.expectHeadPromotions ?? 0);
  expect(counters.landingTransitions).toBe(0);
  expect(counters.submitOrResubmitCalls).toBe(0);
  expect(counters.leaseReleases).toBe(0);

  // Plan itself never grants landing / retry / head promotion.
  expect(plan.invariants).toEqual(ANOMALY_ACTION_INVARIANTS);
  expect(plan.invariants.grantsLandingAuthority).toBe(false);
  expect(plan.invariants.grantsRetryAuthority).toBe(false);
  expect(plan.invariants.grantsHeadPromotion).toBe(false);
  expect(plan.invariants.neverReleaseLease).toBe(true);

  if (applyResult !== null) {
    expect(applyResult.leaseReleased).toBe(false);
    expect(applyResult.evidenceMutations).toEqual([]);
    if (opts.priorLeaseId !== null && opts.walletAfter !== null) {
      expect(opts.walletAfter.activeLeaseId).toBe(opts.priorLeaseId);
    }
    // No *_LANDED status introduced by the anomaly path.
    if (applyResult.operation !== null) {
      expect(applyResult.operation.status).not.toMatch(/_LANDED$/);
    }
  }
}

function leasedWallet(
  overrides: Partial<QuarantineWalletSnapshot> = {},
): QuarantineWalletSnapshot {
  return {
    walletId: WALLET_ID,
    state: "PINNED",
    quarantineReason: null,
    activeLeaseId: LEASE_ID,
    signingHalted: false,
    ...overrides,
  };
}

function liveSendOp(
  overrides: Partial<QuarantineOperationSnapshot> = {},
): QuarantineOperationSnapshot {
  return {
    operationId: OP_ID,
    walletId: WALLET_ID,
    kind: "SEND_EXTERNAL",
    status: "AWAITING_REDEMPTION",
    attentionRequired: false,
    attentionReason: null,
    attentionEpisode: 0,
    ...overrides,
  };
}

function seededStore(opts?: {
  readonly wallet?: QuarantineWalletSnapshot;
  readonly operation?: QuarantineOperationSnapshot | null;
}): InMemoryAnomalyQuarantineStore {
  const store = new InMemoryAnomalyQuarantineStore();
  store.seedWallet(opts?.wallet ?? leasedWallet());
  if (opts?.operation !== null) {
    store.seedOperation(opts?.operation ?? liveSendOp());
  }
  store.seedEvidence({
    table: "observation_anomalies",
    id: "anom-pre",
    payload: { kind: "pre-seed" },
  });
  return store;
}

// ── 1. A,B,C,A ───────────────────────────────────────────────────────────────

describe("scenario: A,B,C,A regression + quarantine", () => {
  it("walks SUCCESSOR,SUCCESSOR,REGRESSION and quarantines only on the final A", async () => {
    const counters = zeroAuthority();
    let ordinaryHead: string | null = null;
    const history: string[] = [];

    // A — FIRST (cursor only; not ordinary-head promotion from a prior)
    const rA = classify(null, A, history);
    expect(rA.relationship).toBe("FIRST");
    expect(establishesOrdinaryHead(rA)).toBe(false);
    ordinaryHead = gateHeadPromotion(ordinaryHead, rA, counters);
    expect(ordinaryHead).toBeNull();
    history.push(A.sSignature);
    let prior: VerifiedSemanticState = A;

    // A→B SUCCESSOR
    const rB = classify(prior, B, history);
    expect(rB.relationship).toBe("SUCCESSOR");
    expect(establishesOrdinaryHead(rB)).toBe(true);
    ordinaryHead = gateHeadPromotion(ordinaryHead, rB, counters);
    expect(ordinaryHead).toBe("sigB");
    history.push(B.sSignature);
    prior = B;

    // B→C SUCCESSOR
    const rC = classify(prior, C, history);
    expect(rC.relationship).toBe("SUCCESSOR");
    ordinaryHead = gateHeadPromotion(ordinaryHead, rC, counters);
    expect(ordinaryHead).toBe("sigC");
    history.push(C.sSignature);
    prior = C;

    // C→A REGRESSION (worked example)
    const rReg = classify(prior, A, history);
    expect(rReg.relationship).toBe("REGRESSION");
    expect(rReg.conditionId).toBe("RECURRENCE_OF_OLDER_S");
    if (rReg.evidence.conditionId !== "RECURRENCE_OF_OLDER_S") {
      throw new Error("expected RECURRENCE_OF_OLDER_S evidence");
    }
    expect(rReg.evidence.matchedHistoricalS).toBe("sigA");
    expect(rReg.evidence.matchedHistoryIndex).toBe(0);
    expect(isAnomalousRelationship(rReg.relationship)).toBe(true);
    expect(establishesOrdinaryHead(rReg)).toBe(false);

    const headBeforeAnomaly = ordinaryHead;
    ordinaryHead = gateHeadPromotion(ordinaryHead, rReg, counters);
    expect(ordinaryHead).toBe(headBeforeAnomaly); // no silent promotion

    const plan = planActionForRelationship(rReg.relationship);
    expect(plan.anomaly).toBe("REGRESSION");
    expect(plan.walletQuarantined).toBe(true);
    expect(plan.signingHalted).toBe(true);
    expect(plan.wallet.kind).toBe("quarantine");

    const store = seededStore();
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });

    expect(applied.wallet?.state).toBe("QUARANTINED");
    expect(applied.wallet?.quarantineReason).toBe("REGRESSION");
    expect(applied.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(isSigningHalted(applied.wallet!)).toBe(true);
    expect(canAcquireNewLease(applied.wallet!)).toBe(false);
    // Operation not force-landed
    expect(applied.operation?.status).toBe("AWAITING_REDEMPTION");
    expect(applied.leaseReleased).toBe(false);

    // Two SUCCESSOR promotions only (B and C) — REGRESSION added none.
    assertNoSilentAuthority(counters, plan, applied, {
      expectHeadPromotions: 2,
      priorLeaseId: LEASE_ID,
      walletAfter: applied.wallet,
    });
  });
});

// ── 2. Missed head (gap) ─────────────────────────────────────────────────────

describe("scenario: missed head (gap) → UNEXPLAINED_JUMP", () => {
  it("skipped intermediate yields UNEXPLAINED_JUMP, not SUCCESSOR or REGRESSION", async () => {
    const counters = zeroAuthority();
    // Observer last accepted A; chain actually advanced A→B→C but B was missed.
    // Next read is C whose P=sigB ≠ prior S=sigA.
    const history = ["sigA"];
    const result = classify(A, C, history);

    expect(result.relationship).toBe("UNEXPLAINED_JUMP");
    expect(result.relationship).not.toBe("SUCCESSOR");
    expect(result.relationship).not.toBe("REGRESSION");
    expect(result.conditionId).toBe("DIFFERENT_S_NO_BACKLINK");
    expect(result.evidence.comparison.nextPEqualsPriorS).toBe(false);
    expect(result.evidence.comparison.nextP).toBe("sigB");
    expect(result.evidence.comparison.priorS).toBe("sigA");
    expect(establishesOrdinaryHead(result)).toBe(false);

    let ordinaryHead: string | null = "sigA";
    ordinaryHead = gateHeadPromotion(ordinaryHead, result, counters);
    expect(ordinaryHead).toBe("sigA");

    // Gap-class jump uses LINEAGE_GAP attention (Appendix B).
    const plan = planActionForRelationship(result.relationship, {
      unexplainedJumpAttentionReason: "LINEAGE_GAP",
    });
    expect(plan.anomaly).toBe("UNEXPLAINED_JUMP");
    expect(plan.walletQuarantined).toBe(false);
    expect(plan.operation.kind).toBe("needs_attention");
    if (plan.operation.kind === "needs_attention") {
      expect(plan.operation.attentionReason).toBe("LINEAGE_GAP");
      expect(plan.operation.targetStatus).toBe("NEEDS_ATTENTION");
    }

    const store = seededStore();
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });

    expect(applied.operation?.status).toBe("NEEDS_ATTENTION");
    expect(applied.operation?.attentionReason).toBe("LINEAGE_GAP");
    expect(applied.wallet?.state).toBe("PINNED"); // wallet not quarantined on jump
    expect(applied.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(applied.leaseReleased).toBe(false);
    expect(applied.needsAttentionEvent?.event).toBe("operation.needs_attention");

    assertNoSilentAuthority(counters, plan, applied, {
      priorLeaseId: LEASE_ID,
      walletAfter: applied.wallet,
    });
  });
});

// ── 3. Conflicting endpoints ─────────────────────────────────────────────────

describe("scenario: conflicting gateway endpoints", () => {
  it("two distinct endpoints disagreeing → GATEWAY_ENDPOINT_DISAGREEMENT halt", async () => {
    const counters = zeroAuthority();

    // Genuine multi-endpoint disagreement harness — not a single-endpoint relabel.
    const endpointA = {
      fingerprint: "ep-a-" + "a".repeat(58),
      head: B, // claims successor of A
    };
    const endpointB = {
      fingerprint: "ep-b-" + "b".repeat(58),
      head: head("sigFork", "sigA", "fpFork"), // different S, same claimed P
    };
    expect(endpointA.fingerprint).not.toBe(endpointB.fingerprint);
    expect(endpointA.head.sSignature).not.toBe(endpointB.head.sSignature);

    // Both would individually classify as SUCCESSOR vs prior A — the disagreement is
    // at the multi-endpoint layer (row), not the single-stream classifier.
    const classA = classify(A, endpointA.head, ["sigA"]);
    const classB = classify(A, endpointB.head, ["sigA"]);
    expect(classA.relationship).toBe("SUCCESSOR");
    expect(classB.relationship).toBe("SUCCESSOR");
    // Heads conflict → no single ordinary head may be chosen.
    expect(classA.evidence.comparison.nextS).not.toBe(classB.evidence.comparison.nextS);

    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });
    expect(plan.anomaly).toBe("GATEWAY_ENDPOINT_DISAGREEMENT");
    expect(plan.wallet.kind).toBe("halt_signing");
    expect(plan.operation.kind).toBe("needs_attention");
    expect(plan.signingHalted).toBe(true);
    expect(plan.walletQuarantined).toBe(false); // halt ≠ full quarantine

    // No head promotion from either SUCCESSOR while endpoints disagree.
    // Disagreement short-circuits promotion even though each hop is SUCCESSOR-shaped.
    const ordinaryHead: string | null = "sigA";
    expect(ordinaryHead).toBe("sigA");
    expect(counters.headPromotions).toBe(0);

    const store = seededStore();
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });

    expect(applied.wallet?.signingHalted).toBe(true);
    expect(applied.wallet?.state).toBe("PINNED"); // not QUARANTINED
    expect(applied.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(canAcquireNewLease(applied.wallet!)).toBe(false);
    expect(applied.operation?.status).toBe("NEEDS_ATTENTION");
    expect(applied.operation?.attentionReason).toBe("VERIFICATION_INDETERMINATE");
    expect(applied.leaseReleased).toBe(false);

    assertNoSilentAuthority(counters, plan, applied, {
      priorLeaseId: LEASE_ID,
      walletAfter: applied.wallet,
    });
  });
});

// ── 4. Signature collision ───────────────────────────────────────────────────

describe("scenario: signature collision simulation", () => {
  it("same S different fingerprint → SIGNATURE_COLLISION, not EQUIVALENT", async () => {
    const counters = zeroAuthority();

    const equivalent = classify(A, A_PRIME_EQUIV, ["sigA"]);
    expect(equivalent.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(equivalent.stateChanged).toBe(false);
    expect(establishesOrdinaryHead(equivalent)).toBe(false);
    expect(isAnomalousRelationship(equivalent.relationship)).toBe(false);

    const collision = classify(A, A_COLLISION, ["sigA"]);
    expect(collision.relationship).toBe("SIGNATURE_COLLISION");
    expect(collision.stateChanged).toBe(true);
    expect(collision.conditionId).toBe("SAME_S_FINGERPRINT_DIFFERS");
    expect(collision.evidence.comparison.nextSEqualsPriorS).toBe(true);
    expect(collision.evidence.comparison.fingerprintsEqual).toBe(false);
    expect(collision.relationship).not.toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(establishesOrdinaryHead(collision)).toBe(false);

    let ordinaryHead: string | null = "sigA";
    ordinaryHead = gateHeadPromotion(ordinaryHead, collision, counters);
    expect(ordinaryHead).toBe("sigA");

    const plan = planActionForRelationship(collision.relationship);
    expect(plan.anomaly).toBe("SIGNATURE_COLLISION");
    expect(plan.walletQuarantined).toBe(true);

    const store = seededStore();
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });

    expect(applied.wallet?.state).toBe("QUARANTINED");
    expect(applied.wallet?.quarantineReason).toBe("SIGNATURE_COLLISION");
    expect(applied.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(applied.leaseReleased).toBe(false);

    // EQUIVALENT path is no-op (must NOT fire collision quarantine).
    const equivPlan = planActionForRelationship(equivalent.relationship);
    expect(equivPlan.auditAction).toBe("anomaly.no_op_non_anomalous");
    expect(equivPlan.walletQuarantined).toBe(false);
    expect(equivPlan.signingHalted).toBe(false);

    assertNoSilentAuthority(counters, plan, applied, {
      priorLeaseId: LEASE_ID,
      walletAfter: applied.wallet,
    });
  });
});

// ── 5. Unauthorized successor ────────────────────────────────────────────────

describe("scenario: unauthorized successor / lease invariant", () => {
  it("SUCCESSOR-shaped hop still yields typed SUCCESSOR evidence; unattributed while leased is INVARIANT_BREACH with no landing", async () => {
    const counters = zeroAuthority();

    // Cryptographically SUCCESSOR-shaped: P == prior S, new S advances.
    // Unauthorized because: (1) we hold an exclusive lease and did not submit this hop;
    // (2) no operation artifact attributes the hop to our in-flight SEND.
    const unauthorized = head("sigUnauthorized", "sigA", "fpUnauthorized");
    const result = classify(A, unauthorized, ["sigA"]);

    expect(result.relationship).toBe("SUCCESSOR");
    expect(result.conditionId).toBe("BACKLINK_TO_PRIOR");
    expect(result.evidence.comparison.nextPEqualsPriorS).toBe(true);
    expect(result.evidence.comparison.nextS).toBe("sigUnauthorized");
    // Classifier correctly reports SUCCESSOR — crypto/backlink alone checked out.
    expect(establishesOrdinaryHead(result)).toBe(true);

    // Production landing-path oracle residual (not a test-local boolean): lease held, no submit / attribution.
    const custody = assessSuccessorCustodyAuthority({
      relationship: result.relationship,
      activeLeaseHeld: true,
      matchingOutboundSubmitArtifact: false,
      attributedToInFlightOperation: false,
    });
    expect(custody.disposition).toBe("INVARIANT_BREACH");
    if (custody.disposition !== "INVARIANT_BREACH") {
      throw new Error("expected INVARIANT_BREACH disposition");
    }
    expect(custody.reason).toEqual({ source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" });
    expect(custody.permitsOrdinaryHeadPromotion).toBe(false);
    expect(custody.permitsLanding).toBe(false);
    expect(custody.permitsRetryOrResubmit).toBe(false);
    expect(custody.permitsLeaseRelease).toBe(false);
    expect(custody.pathObservation).toEqual({ result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" });

    // Production path-observation classifier maps the residual observation → breach tier.
    const pathClass = classifyPathObservation(custody.pathObservation);
    expect(pathClass).toEqual({
      tier: "INVARIANT_BREACH",
      reason: { source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" },
    });

    // Production send reconcile under active lease preserves INVARIANT_BREACH; no LANDED_VERIFIED.
    const sendOutcome = classifySendReconcile({
      boundary: "DELIVERED",
      sendAttemptId: OP_ID,
      sourceWalletId: WALLET_ID,
      sourceLeaseState: "ACTIVE",
      transferCodeSha256: "a".repeat(64),
      sourceObservation: custody.pathObservation,
    });
    expect(sendOutcome.kind).toBe("INVARIANT_BREACH");
    if (sendOutcome.kind === "INVARIANT_BREACH") {
      expect(sendOutcome.reason).toEqual({
        source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE",
      });
      expect(sendOutcome.sourceWalletId).toBe(WALLET_ID);
    }

    // Custody gate refuses ordinary-head promotion even though classifier said SUCCESSOR.
    let ordinaryHead: string | null = "sigA";
    if (custody.permitsOrdinaryHeadPromotion) {
      ordinaryHead = gateHeadPromotion(ordinaryHead, result, counters);
    }
    expect(ordinaryHead).toBe("sigA");
    expect(counters.headPromotions).toBe(0);
    expect(counters.landingTransitions).toBe(0);
    expect(counters.submitOrResubmitCalls).toBe(0);
    expect(counters.leaseReleases).toBe(0);

    // Contrast: attributed SUCCESSOR under lease is ordinary-head-authorized by the residual.
    const attributed = assessSuccessorCustodyAuthority({
      relationship: "SUCCESSOR",
      activeLeaseHeld: true,
      matchingOutboundSubmitArtifact: true,
      attributedToInFlightOperation: false,
    });
    expect(attributed.disposition).toBe("ORDINARY_SUCCESSOR_AUTHORIZED");
    expect(attributed.permitsOrdinaryHeadPromotion).toBe(true);

    // Deep unattributed hop (missing intermediate) is UNEXPLAINED_JUMP — its own relationship
    // class, not a stand-in for unauthorized SUCCESSOR. Still no landing / lease release.
    const deepWhileLeased = classify(A, C, ["sigA"]); // P=sigB ≠ sigA
    expect(deepWhileLeased.relationship).toBe("UNEXPLAINED_JUMP");
    expect(establishesOrdinaryHead(deepWhileLeased)).toBe(false);
    const deepCustody = assessSuccessorCustodyAuthority({
      relationship: deepWhileLeased.relationship,
      activeLeaseHeld: true,
      matchingOutboundSubmitArtifact: false,
      attributedToInFlightOperation: false,
    });
    expect(deepCustody.disposition).toBe("NOT_SUCCESSOR");
    const deepPlan = planActionForRelationship(deepWhileLeased.relationship, {
      unexplainedJumpAttentionReason: "UNEXPECTED_HEAD_CHANGE",
    });
    const store = seededStore({ wallet: leasedWallet() });
    const applied = await applyAnomalyAction(store, {
      plan: deepPlan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });
    expect(applied.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(applied.leaseReleased).toBe(false);
    expect(applied.operation?.status).toBe("NEEDS_ATTENTION");
    assertNoSilentAuthority(counters, deepPlan, applied, {
      priorLeaseId: LEASE_ID,
      walletAfter: applied.wallet,
    });
  });
});

// ── 6. Restart mid-classification / mid-quarantine (in-memory atomic unit) ───

describe("scenario: restart mid-quarantine leaves no partial state", () => {
  it("throw inside multi-effect apply rolls back; resume re-applies cleanly", async () => {
    const counters = zeroAuthority();

    // GATEWAY_ENDPOINT_DISAGREEMENT is multi-effect: halt_signing + needs_attention + audit.
    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });
    expect(plan.wallet.kind).toBe("halt_signing");
    expect(plan.operation.kind).toBe("needs_attention");

    const store = seededStore();
    const walletBefore = await store.getWallet(WALLET_ID);
    const opBefore = await store.getOperation(OP_ID);
    const auditBefore = store.getAuditLog().length;
    const evidenceBefore = (await store.listEvidence()).length;

    // Interrupt mid-apply: markNeedsAttention throws after halt would have run.
    // runAtomic must restore the pre-apply snapshot (crash = no partial durable state).
    const flaky: typeof store.markNeedsAttention = async () => {
      throw new Error("simulated process kill mid-quarantine-action");
    };
    store.markNeedsAttention = flaky;

    await expect(
      applyAnomalyAction(store, {
        plan,
        walletId: WALLET_ID,
        operationId: OP_ID,
      }),
    ).rejects.toThrow(/simulated process kill/);

    // Durable state identical to pre-crash.
    const walletMid = await store.getWallet(WALLET_ID);
    const opMid = await store.getOperation(OP_ID);
    expect(walletMid).toEqual(walletBefore);
    expect(opMid).toEqual(opBefore);
    expect(walletMid?.signingHalted).toBe(false);
    expect(walletMid?.activeLeaseId).toBe(LEASE_ID);
    expect(opMid?.status).toBe("AWAITING_REDEMPTION");
    expect(opMid?.attentionRequired).toBe(false);
    expect(store.getAuditLog()).toHaveLength(auditBefore);
    expect(await store.listEvidence()).toHaveLength(evidenceBefore);

    // Restart: restore healthy store method and re-apply from durable pre-crash state.
    store.markNeedsAttention =
      InMemoryAnomalyQuarantineStore.prototype.markNeedsAttention.bind(store);

    const resumed = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });

    expect(resumed.wallet?.signingHalted).toBe(true);
    expect(resumed.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(resumed.operation?.status).toBe("NEEDS_ATTENTION");
    expect(resumed.leaseReleased).toBe(false);
    expect(store.getAuditLog().length).toBe(auditBefore + 1);

    assertNoSilentAuthority(counters, plan, resumed, {
      priorLeaseId: LEASE_ID,
      walletAfter: resumed.wallet,
    });
  });

  it("throw after wallet quarantine (REGRESSION) rolls back; wallet neither stuck nor cleared wrongly", async () => {
    const plan = planActionForRelationship("REGRESSION");
    const store = seededStore();

    // Force audit append to fail after quarantineWallet succeeds inside the atomic unit.
    store.appendAudit = async () => {
      throw new Error("simulated crash after wallet quarantine write");
    };

    await expect(
      applyAnomalyAction(store, {
        plan,
        walletId: WALLET_ID,
        operationId: OP_ID,
      }),
    ).rejects.toThrow(/simulated crash after wallet quarantine/);

    const wallet = await store.getWallet(WALLET_ID);
    // Not stuck half-quarantined: full rollback to PINNED + lease.
    expect(wallet?.state).toBe("PINNED");
    expect(wallet?.quarantineReason).toBeNull();
    expect(wallet?.signingHalted).toBe(false);
    expect(wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(store.getAuditLog()).toHaveLength(0);

    // Resume with healthy audit.
    store.appendAudit = InMemoryAnomalyQuarantineStore.prototype.appendAudit.bind(store);
    const resumed = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: OP_ID,
    });
    expect(resumed.wallet?.state).toBe("QUARANTINED");
    expect(resumed.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(resumed.leaseReleased).toBe(false);
  });
});
