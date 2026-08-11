// Fail-closed anomaly quarantine action tests.
//
// This suite asserts:
// 1. Each row has a test asserting the exact node action.
// 2. A quarantined wallet cannot be acquired by a new lease.
// 3. An active lease is still held after REGRESSION / GENESIS_AFTER_HISTORY.
// 4. A previously LANDED operation is unchanged after a later anomaly.
// 5. No quarantine action deletes or edits observation_anomalies / gateway_observations.
// Negative path: non-anomalous relationships produce a no-op plan (no landing/retry authority).

import { describe, expect, it } from "vitest";

import {
  CLASSIFIER_RELATIONSHIPS,
  isAnomalousRelationship,
} from "./classifier.js";
import {
  ANOMALY_ACTION_INVARIANTS,
  CLASSIFIER_ANOMALY_KINDS,
  InMemoryAnomalyQuarantineStore,
  OBS15_ANOMALY_KINDS,
  applyAnomalyAction,
  canAcquireNewLease,
  isSigningHalted,
  planActionForRelationship,
  planAnomalyAction,
  type AnomalyActionPlan,
  type Obs15AnomalyKind,
  type QuarantineOperationSnapshot,
  type QuarantineWalletSnapshot,
} from "./quarantine.js";

const WALLET_ID = "wallet-1";
const LEASE_ID = "lease-1";
const OP_ID = "op-1";
const LANDED_OP_ID = "op-landed";

function leasedWallet(overrides: Partial<QuarantineWalletSnapshot> = {}): QuarantineWalletSnapshot {
  return {
    walletId: WALLET_ID,
    state: "PINNED",
    quarantineReason: null,
    activeLeaseId: LEASE_ID,
    signingHalted: false,
    ...overrides,
  };
}

function availableWallet(overrides: Partial<QuarantineWalletSnapshot> = {}): QuarantineWalletSnapshot {
  return {
    walletId: WALLET_ID,
    state: "AVAILABLE",
    quarantineReason: null,
    activeLeaseId: null,
    signingHalted: false,
    ...overrides,
  };
}

function liveOp(
  status: QuarantineOperationSnapshot["status"] = "AWAITING_REDEMPTION",
  overrides: Partial<QuarantineOperationSnapshot> = {},
): QuarantineOperationSnapshot {
  return {
    operationId: OP_ID,
    walletId: WALLET_ID,
    kind: "SEND_EXTERNAL",
    status,
    attentionRequired: false,
    attentionReason: null,
    attentionEpisode: 0,
    ...overrides,
  };
}

function receiveOp(
  status: QuarantineOperationSnapshot["status"] = "READY",
  overrides: Partial<QuarantineOperationSnapshot> = {},
): QuarantineOperationSnapshot {
  return liveOp(status, { kind: "RECEIVE_EXTERNAL", ...overrides });
}

function moveOp(
  status: QuarantineOperationSnapshot["status"] = "CREATED",
  overrides: Partial<QuarantineOperationSnapshot> = {},
): QuarantineOperationSnapshot {
  return liveOp(status, { kind: "MOVE_INTERNAL", ...overrides });
}

function seededStore(opts?: {
  readonly wallet?: QuarantineWalletSnapshot;
  readonly operation?: QuarantineOperationSnapshot | null;
  readonly landed?: QuarantineOperationSnapshot;
}): InMemoryAnomalyQuarantineStore {
  const store = new InMemoryAnomalyQuarantineStore();
  store.seedWallet(opts?.wallet ?? leasedWallet());
  if (opts?.operation !== null) {
    store.seedOperation(opts?.operation ?? liveOp());
  }
  if (opts?.landed) {
    store.seedOperation(opts.landed);
  }
  store.seedEvidence({
    table: "observation_anomalies",
    id: "anom-1",
    payload: { kind: "REGRESSION", wallet_seq: 4 },
  });
  store.seedEvidence({
    table: "gateway_observations",
    id: "obs-1",
    payload: { raw_sha256: "abc", relationship: "REGRESSION" },
  });
  return store;
}

async function apply(
  anomaly: Obs15AnomalyKind,
  store: InMemoryAnomalyQuarantineStore = seededStore(),
  ids: { walletId?: string | null; operationId?: string | null } = {},
) {
  const plan = planAnomalyAction({ anomaly });
  return {
    store,
    plan,
    result: await applyAnomalyAction(store, {
      plan,
      walletId: ids.walletId === undefined ? WALLET_ID : ids.walletId,
      operationId: ids.operationId === undefined ? OP_ID : ids.operationId,
      nowMs: 1_700_000_000_000,
    }),
  };
}

function assertFailClosedInvariants(plan: AnomalyActionPlan): void {
  expect(plan.invariants).toEqual(ANOMALY_ACTION_INVARIANTS);
  expect(plan.invariants.neverReleaseLease).toBe(true);
  expect(plan.invariants.neverDeleteEvidence).toBe(true);
  expect(plan.invariants.neverRewriteVerdict).toBe(true);
  expect(plan.invariants.neverMutateTerminalHistoricOp).toBe(true);
  expect(plan.invariants.grantsLandingAuthority).toBe(false);
  expect(plan.invariants.grantsRetryAuthority).toBe(false);
  expect(plan.invariants.grantsHeadPromotion).toBe(false);
}

describe("node-action table (one test per row)", () => {
  it("transport/read failure → bounded read-only retry; keep lease", async () => {
    const { plan, result, store } = await apply("TRANSPORT_READ_FAILURE");
    expect(plan.nodeActionSummary).toBe("bounded read-only retry; keep lease");
    expect(plan.wallet.kind).toBe("none");
    expect(plan.operation.kind).toBe("keep_verification_pending");
    expect(result.leaseReleased).toBe(false);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.wallet?.state).toBe("PINNED");
    assertFailClosedInvariants(plan);
    expect(store.getAuditLog()).toHaveLength(1);
    expect(store.getAuditLog()[0]!.action).toBe("anomaly.bounded_retry_keep_lease");
  });

  it("malformed envelope/transaction → retain raw bytes; alert; no sign/settle/retry", async () => {
    const { plan, result } = await apply("MALFORMED_ENVELOPE");
    expect(plan.nodeActionSummary).toBe("retain raw bytes; alert; no sign/settle/retry");
    expect(plan.operation.kind).toBe("refuse_acceptance");
    expect(plan.signingHalted).toBe(true);
    expect(result.leaseReleased).toBe(false);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    assertFailClosedInvariants(plan);
  });

  it("invalid step signature → quarantine candidate; no co-sign/settle", async () => {
    const { plan, result } = await apply("INVALID_STEP_SIGNATURE");
    expect(plan.nodeActionSummary).toBe("quarantine candidate; no co-sign/settle");
    expect(plan.wallet.kind).toBe("quarantine_candidate");
    // Grades this below wallet quarantine — refuse acceptance only.
    expect(plan.walletQuarantined).toBe(false);
    expect(plan.operation.kind).toBe("refuse_acceptance");
    // Plan-level no-cosign (refuse_acceptance), not wallets.state / wallet signingHalted.
    expect(plan.signingHalted).toBe(true);
    expect(result.wallet?.state).toBe("PINNED");
    expect(result.wallet?.state).not.toBe("QUARANTINED");
    expect(result.wallet?.quarantineReason).toBeNull();
    expect(result.wallet?.signingHalted).toBe(false);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    // Acquisition blocked only while PINNED/leased — not because quarantined.
    expect(canAcquireNewLease(result.wallet!)).toBe(false);
    expect(isSigningHalted(result.wallet!)).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("invalid step signature on AVAILABLE wallet does not quarantine or block new leases", async () => {
    const store = seededStore({ wallet: availableWallet(), operation: null });
    const { plan, result } = await apply("INVALID_STEP_SIGNATURE", store, {
      operationId: null,
    });
    expect(plan.wallet.kind).toBe("quarantine_candidate");
    expect(plan.walletQuarantined).toBe(false);
    expect(result.wallet?.state).toBe("AVAILABLE");
    expect(result.wallet?.signingHalted).toBe(false);
    expect(canAcquireNewLease(result.wallet!)).toBe(true);
    expect(isSigningHalted(result.wallet!)).toBe(false);
  });

  it("wallet role invalid/self-transfer → no operation acceptance", async () => {
    const { plan, result } = await apply("WALLET_ROLE_INVALID");
    expect(plan.nodeActionSummary).toBe("no operation acceptance");
    expect(plan.operation.kind).toBe("refuse_acceptance");
    expect(plan.wallet.kind).toBe("none");
    expect(result.wallet?.state).toBe("PINNED");
    expect(result.leaseReleased).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("equivalent state/different envelope → retain, no head promotion", async () => {
    const { plan, result } = await apply("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    expect(plan.nodeActionSummary).toBe("retain, no head promotion");
    expect(plan.wallet.kind).toBe("none");
    expect(plan.operation.kind).toBe("none");
    expect(plan.invariants.grantsHeadPromotion).toBe(false);
    expect(result.wallet?.state).toBe("PINNED");
    expect(result.leaseReleased).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("regression → quarantine wallet, preserve lease, halt signing", async () => {
    const { plan, result } = await apply("REGRESSION");
    expect(plan.nodeActionSummary).toBe(
      "quarantine wallet, preserve lease, halt signing from wallet",
    );
    expect(plan.wallet.kind).toBe("quarantine");
    expect(result.wallet?.state).toBe("QUARANTINED");
    expect(result.wallet?.quarantineReason).toBe("REGRESSION");
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    expect(isSigningHalted(result.wallet!)).toBe(true);
    expect(canAcquireNewLease(result.wallet!)).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("genesis after history → quarantine wallet, preserve lease, halt signing", async () => {
    const { plan, result } = await apply("GENESIS_AFTER_HISTORY");
    expect(plan.nodeActionSummary).toBe(
      "quarantine wallet, preserve lease, halt signing from wallet",
    );
    expect(result.wallet?.state).toBe("QUARANTINED");
    expect(result.wallet?.quarantineReason).toBe("GENESIS_AFTER_HISTORY");
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    expect(isSigningHalted(result.wallet!)).toBe(true);
    assertFailClosedInvariants(plan);
  });

  it("signature collision → quarantine wallet, preserve lease, halt signing (fail-closed)", async () => {
    const { plan, result } = await apply("SIGNATURE_COLLISION");
    expect(plan.wallet.kind).toBe("quarantine");
    expect(result.wallet?.state).toBe("QUARANTINED");
    expect(result.wallet?.quarantineReason).toBe("SIGNATURE_COLLISION");
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("unexplained jump → NEEDS_ATTENTION; do not infer landing/non-landing", async () => {
    const { plan, result } = await apply("UNEXPLAINED_JUMP");
    expect(plan.nodeActionSummary).toBe("NEEDS_ATTENTION; do not infer landing/non-landing");
    expect(plan.operation.kind).toBe("needs_attention");
    if (plan.operation.kind !== "needs_attention") throw new Error("expected needs_attention");
    expect(plan.operation.attentionReason).toBe("UNEXPECTED_HEAD_CHANGE");
    expect(plan.operation.targetStatus).toBe("NEEDS_ATTENTION");
    expect(plan.operation.emitEvent).toBe("operation.needs_attention");
    expect(result.operation?.status).toBe("NEEDS_ATTENTION");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.operation?.attentionReason).toBe("UNEXPECTED_HEAD_CHANGE");
    expect(result.needsAttentionEvent?.event).toBe("operation.needs_attention");
    expect(result.needsAttentionEvent?.data.operator_action_required).toBe(true);
    expect(result.needsAttentionEvent?.data.attention_episode).toBe(1);
    // Lease preserved; landing not inferred.
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    expect(plan.invariants.grantsLandingAuthority).toBe(false);
    assertFailClosedInvariants(plan);
  });

  it("unexplained jump may use LINEAGE_GAP attention_reason when caller supplies it", () => {
    const plan = planAnomalyAction({
      anomaly: "UNEXPLAINED_JUMP",
      unexplainedJumpAttentionReason: "LINEAGE_GAP",
    });
    expect(plan.operation.kind).toBe("needs_attention");
    if (plan.operation.kind !== "needs_attention") throw new Error("expected needs_attention");
    expect(plan.operation.attentionReason).toBe("LINEAGE_GAP");
  });

  it("node/platform semantic disagreement → do not release verification barrier", async () => {
    const { plan, result } = await apply("NODE_PLATFORM_DISAGREEMENT");
    expect(plan.nodeActionSummary).toBe("do not release verification barrier automatically");
    expect(plan.operation.kind).toBe("hold_verification_barrier");
    expect(result.leaseReleased).toBe(false);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    assertFailClosedInvariants(plan);
  });

  it("two independent gateway endpoints disagree → halt affected wallet/operation", async () => {
    const { plan, result } = await apply("GATEWAY_ENDPOINT_DISAGREEMENT");
    expect(plan.nodeActionSummary).toBe("halt affected wallet/operation");
    expect(plan.wallet.kind).toBe("halt_signing");
    expect(plan.operation.kind).toBe("needs_attention");
    expect(result.wallet?.signingHalted).toBe(true);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.operation?.status).toBe("NEEDS_ATTENTION");
    expect(result.operation?.attentionReason).toBe("VERIFICATION_INDETERMINATE");
    expect(isSigningHalted(result.wallet!)).toBe(true);
    expect(canAcquireNewLease(result.wallet!)).toBe(false);
    assertFailClosedInvariants(plan);
  });
});

describe("review indicators — lease, historic LANDED, evidence, acquisition", () => {
  it("active lease is still held immediately after REGRESSION quarantine", async () => {
    const store = seededStore({ wallet: leasedWallet() });
    const { result } = await apply("REGRESSION", store);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
    const after = await store.getWallet(WALLET_ID);
    expect(after?.activeLeaseId).toBe(LEASE_ID);
    expect(after?.state).toBe("QUARANTINED");
  });

  it("active lease is still held immediately after GENESIS_AFTER_HISTORY quarantine", async () => {
    const store = seededStore({ wallet: leasedWallet() });
    const { result } = await apply("GENESIS_AFTER_HISTORY", store);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.leaseReleased).toBe(false);
  });

  it("quarantined wallet cannot be acquired by a new lease", async () => {
    const store = seededStore({ wallet: availableWallet() });
    const { result } = await apply("REGRESSION", store, { operationId: null });
    expect(result.wallet?.state).toBe("QUARANTINED");
    expect(canAcquireNewLease(result.wallet!)).toBe(false);
    // Fresh AVAILABLE control still can.
    expect(canAcquireNewLease(availableWallet({ walletId: "other" }))).toBe(true);
  });

  it("PINNED (leased) wallet is not newly acquirable even before quarantine (one in-flight claim per wallet)", () => {
    expect(canAcquireNewLease(leasedWallet())).toBe(false);
  });

  it("previously LANDED operation is unchanged after a later anomaly on the same wallet", async () => {
    const landed: QuarantineOperationSnapshot = {
      operationId: LANDED_OP_ID,
      walletId: WALLET_ID,
      kind: "SEND_EXTERNAL",
      status: "EXTERNAL_SEND_LANDED",
      attentionRequired: false,
      attentionReason: null,
      attentionEpisode: 0,
    };
    const store = seededStore({
      wallet: leasedWallet(),
      operation: liveOp("AWAITING_REDEMPTION"),
      landed,
    });
    // Anomaly parks the *current* op and quarantines the wallet; historic LANDED untouched.
    await apply("REGRESSION", store, { operationId: OP_ID });
    const historic = await store.getOperation(LANDED_OP_ID);
    expect(historic).toEqual(landed);
    expect(["RECEIVE_LANDED","INTERNAL_MOVE_LANDED","EXTERNAL_SEND_LANDED","REJECTED","EXPIRED"]).toContain(historic!.status);

    // Direct attempt to NEEDS_ATTENTION a terminal op is refused (mutated: false).
    const refused = await store.markNeedsAttention(LANDED_OP_ID, "UNEXPECTED_HEAD_CHANGE");
    expect(refused.mutated).toBe(false);
    expect(refused.operation.status).toBe("EXTERNAL_SEND_LANDED");
    expect(refused.operation.attentionRequired).toBe(false);
  });

  it("UNEXPLAINED_JUMP on a terminal historic op does not rewrite it", async () => {
    const landed: QuarantineOperationSnapshot = {
      operationId: LANDED_OP_ID,
      walletId: WALLET_ID,
      kind: "RECEIVE_EXTERNAL",
      status: "RECEIVE_LANDED",
      attentionRequired: false,
      attentionReason: null,
      attentionEpisode: 0,
    };
    const store = seededStore({
      wallet: leasedWallet(),
      operation: null,
      landed,
    });
    const plan = planAnomalyAction({ anomaly: "UNEXPLAINED_JUMP" });
    const result = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: LANDED_OP_ID,
      nowMs: 1,
    });
    expect(result.operation?.status).toBe("RECEIVE_LANDED");
    expect(result.operation?.attentionRequired).toBe(false);
    expect(result.needsAttentionEvent).toBeNull();
  });

  it("no quarantine action deletes or edits observation_anomalies or gateway_observations", async () => {
    const store = seededStore();
    const before = await store.listEvidence();
    expect(before).toHaveLength(2);

    for (const anomaly of OBS15_ANOMALY_KINDS) {
      const plan = planAnomalyAction({ anomaly });
      const result = await applyAnomalyAction(store, {
        plan,
        walletId: WALLET_ID,
        operationId: plan.operation.kind === "needs_attention" ? OP_ID : OP_ID,
        nowMs: 1,
      });
      expect(result.evidenceMutations).toEqual([]);
      expect(result.leaseReleased).toBe(false);
    }

    const after = await store.listEvidence();
    expect(after).toEqual(before);
    // Exact payload bytes preserved.
    expect(after[0]).toEqual({
      table: "observation_anomalies",
      id: "anom-1",
      payload: { kind: "REGRESSION", wallet_seq: 4 },
    });
    expect(after[1]).toEqual({
      table: "gateway_observations",
      id: "obs-1",
      payload: { raw_sha256: "abc", relationship: "REGRESSION" },
    });
  });
});

describe("classifier → action routing", () => {
  it("every classifier anomaly kind is in the set and plans fail-closed", () => {
    for (const kind of CLASSIFIER_ANOMALY_KINDS) {
      expect(OBS15_ANOMALY_KINDS).toContain(kind);
      expect(isAnomalousRelationship(kind)).toBe(true);
      const plan = planActionForRelationship(kind);
      assertFailClosedInvariants(plan);
      expect(plan.anomaly).toBe(kind);
    }
  });

  it("REGRESSION / GENESIS_AFTER_HISTORY / SIGNATURE_COLLISION quarantine; JUMP needs attention", () => {
    expect(planActionForRelationship("REGRESSION").walletQuarantined).toBe(true);
    expect(planActionForRelationship("GENESIS_AFTER_HISTORY").walletQuarantined).toBe(true);
    expect(planActionForRelationship("SIGNATURE_COLLISION").walletQuarantined).toBe(true);
    const jump = planActionForRelationship("UNEXPLAINED_JUMP");
    expect(jump.walletQuarantined).toBe(false);
    expect(jump.operation.kind).toBe("needs_attention");
  });

  it("NEGATIVE: non-anomalous relationships produce a no-op plan (no landing/retry/head authority)", () => {
    const nonAnomalous = CLASSIFIER_RELATIONSHIPS.filter(
      (r) => !isAnomalousRelationship(r),
    );
    expect(nonAnomalous.length).toBeGreaterThan(0);
    for (const rel of nonAnomalous) {
      const plan = planActionForRelationship(rel);
      expect(plan.auditAction).toBe("anomaly.no_op_non_anomalous");
      expect(plan.wallet.kind).toBe("none");
      expect(plan.operation.kind).toBe("none");
      expect(plan.walletQuarantined).toBe(false);
      expect(plan.signingHalted).toBe(false);
      assertFailClosedInvariants(plan);
    }
  });

  it("SUCCESSOR does not quarantine and grants no action authority from this layer", () => {
    const plan = planActionForRelationship("SUCCESSOR");
    expect(plan.walletQuarantined).toBe(false);
    expect(plan.invariants.grantsHeadPromotion).toBe(false);
    // Head promotion is owned by the classifier (establishesOrdinaryHead), not this layer.
  });
});

describe("closing rule — operator resolution never frees lease / creates submit authority", () => {
  it("every planned action stamps neverReleaseLease and never grants retry/landing", () => {
    for (const anomaly of OBS15_ANOMALY_KINDS) {
      const plan = planAnomalyAction({ anomaly });
      expect(plan.invariants.neverReleaseLease).toBe(true);
      expect(plan.invariants.grantsLandingAuthority).toBe(false);
      expect(plan.invariants.grantsRetryAuthority).toBe(false);
      if (plan.wallet.kind !== "none") {
        expect(plan.wallet.preserveLease).toBe(true);
      }
    }
  });

  it("apply always returns leaseReleased: false even when wallet had no lease", async () => {
    const store = seededStore({ wallet: availableWallet(), operation: liveOp("CREATED") });
    const { result } = await apply("REGRESSION", store);
    expect(result.leaseReleased).toBe(false);
    expect(result.wallet?.activeLeaseId).toBeNull();
  });
});

describe("receive attention without status rewrite (D1/D2)", () => {
  it("UNEXPLAINED_JUMP on RECEIVE_EXTERNAL READY sets attention and keeps status READY", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: receiveOp("READY"),
    });
    const { result } = await apply("UNEXPLAINED_JUMP", store);
    expect(result.operation?.kind).toBe("RECEIVE_EXTERNAL");
    expect(result.operation?.status).toBe("READY");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.operation?.attentionReason).toBe("UNEXPECTED_HEAD_CHANGE");
    expect(result.operation?.attentionEpisode).toBe(1);
    expect(result.needsAttentionEvent?.event).toBe("operation.needs_attention");
    expect(result.needsAttentionEvent?.data.current_state).toBe("READY");
    expect(result.needsAttentionEvent?.data.operator_action_required).toBe(true);
    expect(result.leaseReleased).toBe(false);
  });

  it("UNEXPLAINED_JUMP on RECEIVE_EXTERNAL CREATED sets attention and keeps status CREATED", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: receiveOp("CREATED"),
    });
    const { result } = await apply("UNEXPLAINED_JUMP", store);
    expect(result.operation?.status).toBe("CREATED");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.needsAttentionEvent?.data.current_state).toBe("CREATED");
  });

  it("UNEXPLAINED_JUMP on EXPIRED receive sets attention while status stays EXPIRED", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: receiveOp("EXPIRED"),
    });
    const { result } = await apply("UNEXPLAINED_JUMP", store);
    expect(result.operation?.status).toBe("EXPIRED");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.operation?.attentionReason).toBe("UNEXPECTED_HEAD_CHANGE");
    expect(result.needsAttentionEvent?.data.current_state).toBe("EXPIRED");
    expect(result.needsAttentionEvent?.data.attention_episode).toBe(1);
  });

  it("GATEWAY_ENDPOINT_DISAGREEMENT on READY receive halts wallet and keeps READY", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: receiveOp("READY"),
    });
    const { result } = await apply("GATEWAY_ENDPOINT_DISAGREEMENT", store);
    expect(result.wallet?.signingHalted).toBe(true);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.operation?.status).toBe("READY");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.operation?.attentionReason).toBe("VERIFICATION_INDETERMINATE");
    expect(result.needsAttentionEvent?.data.current_state).toBe("READY");
  });

  it("MOVE_INTERNAL CREATED → NEEDS_ATTENTION status rewrite", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: moveOp("CREATED"),
    });
    const { result } = await apply("UNEXPLAINED_JUMP", store);
    expect(result.operation?.status).toBe("NEEDS_ATTENTION");
    expect(result.operation?.attentionRequired).toBe(true);
    expect(result.needsAttentionEvent?.data.current_state).toBe("NEEDS_ATTENTION");
  });

  it("SEND_EXTERNAL AWAITING_REDEMPTION → NEEDS_ATTENTION", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: liveOp("AWAITING_REDEMPTION"),
    });
    const { result } = await apply("UNEXPLAINED_JUMP", store);
    expect(result.operation?.kind).toBe("SEND_EXTERNAL");
    expect(result.operation?.status).toBe("NEEDS_ATTENTION");
    expect(result.needsAttentionEvent?.data.current_state).toBe("NEEDS_ATTENTION");
  });

  it("EXPIRED is not refused as historic terminal for attention (store markNeedsAttention)", async () => {
    const store = seededStore({
      operation: receiveOp("EXPIRED"),
    });
    const marked = await store.markNeedsAttention(OP_ID, "UNEXPECTED_HEAD_CHANGE");
    expect(marked.mutated).toBe(true);
    expect(marked.operation.status).toBe("EXPIRED");
    expect(marked.operation.attentionRequired).toBe(true);
  });
});

describe("lease-preservation enforce at apply boundary (D3)", () => {
  it("throws when a store drops a non-null activeLeaseId during quarantine", async () => {
    const store = seededStore({ wallet: leasedWallet() });
    const original = store.quarantineWallet.bind(store);
    store.quarantineWallet = async (walletId, reason, opts) => {
      const next = await original(walletId, reason, opts);
      // Deliberately bad store: clear the lease after "quarantine".
      const broken = { ...next, activeLeaseId: null };
      store.seedWallet(broken);
      return broken;
    };
    await expect(apply("REGRESSION", store)).rejects.toThrow(/must preserve active lease/);
    // No success audit for a refused apply.
    expect(store.getAuditLog()).toHaveLength(0);
  });

  it("throws when a store drops lease during halt_signing", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: liveOp("AWAITING_REDEMPTION"),
    });
    const original = store.haltWalletSigning.bind(store);
    store.haltWalletSigning = async (walletId) => {
      const next = await original(walletId);
      const broken = { ...next, activeLeaseId: null };
      store.seedWallet(broken);
      return broken;
    };
    await expect(apply("GATEWAY_ENDPOINT_DISAGREEMENT", store)).rejects.toThrow(
      /must preserve active lease/,
    );
    expect(store.getAuditLog()).toHaveLength(0);
    // Atomic rollback — orphan halt must not survive the throw.
    const after = await store.getWallet(WALLET_ID);
    expect(after?.signingHalted).toBe(false);
    expect(after?.activeLeaseId).toBe(LEASE_ID);
    const op = await store.getOperation(OP_ID);
    expect(op?.attentionRequired).toBe(false);
    expect(op?.status).toBe("AWAITING_REDEMPTION");
  });

  it("does not throw when wallet had no lease and stays unleased", async () => {
    const store = seededStore({ wallet: availableWallet(), operation: null });
    const { result } = await apply("REGRESSION", store, { operationId: null });
    expect(result.wallet?.activeLeaseId).toBeNull();
    expect(result.leaseReleased).toBe(false);
  });
});

describe("multi-effect apply atomicity (D5)", () => {
  it("GATEWAY + operationId null applies wallet halt + audit; skips attention stamp", async () => {
    const store = seededStore({
      wallet: leasedWallet({ signingHalted: false }),
      operation: liveOp("AWAITING_REDEMPTION"),
    });
    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });
    const result = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: null,
      nowMs: 1_700_000_000_000,
    });

    // Wallet/audit portions must still land so evidence transactions never roll back for
    // missing operation context (ZTR-1127 Q5 / JUMP class).
    expect(result.wallet?.signingHalted).toBe(true);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.needsAttentionEvent).toBeNull();
    const op = await store.getOperation(OP_ID);
    expect(op?.attentionRequired).toBe(false);
    expect(op?.status).toBe("AWAITING_REDEMPTION");
    expect(store.getAuditLog()).toHaveLength(1);
    expect(store.getAuditLog()[0]!.action).toBe("anomaly.halt_wallet_operation");
  });

  it("UNEXPLAINED_JUMP + operationId null audits without throwing", async () => {
    const store = seededStore({
      wallet: leasedWallet(),
      operation: liveOp("READY"),
    });
    const plan = planAnomalyAction({ anomaly: "UNEXPLAINED_JUMP" });
    const result = await applyAnomalyAction(store, {
      plan,
      walletId: WALLET_ID,
      operationId: null,
      nowMs: 1_700_000_000_000,
    });
    expect(result.needsAttentionEvent).toBeNull();
    expect(result.leaseReleased).toBe(false);
    expect(store.getAuditLog()).toHaveLength(1);
    expect(store.getAuditLog()[0]!.action).toBe("anomaly.needs_attention");
    const op = await store.getOperation(OP_ID);
    expect(op?.attentionRequired).toBe(false);
  });

  it("GATEWAY + unknown operationId throws with zero durable mutation", async () => {
    const store = seededStore({
      wallet: leasedWallet({ signingHalted: false }),
      operation: liveOp("AWAITING_REDEMPTION"),
    });
    const plan = planAnomalyAction({ anomaly: "GATEWAY_ENDPOINT_DISAGREEMENT" });
    await expect(
      applyAnomalyAction(store, {
        plan,
        walletId: WALLET_ID,
        operationId: "op-missing",
        nowMs: 1_700_000_000_000,
      }),
    ).rejects.toThrow(/operation op-missing not found/);

    const wallet = await store.getWallet(WALLET_ID);
    expect(wallet?.signingHalted).toBe(false);
    expect(wallet?.activeLeaseId).toBe(LEASE_ID);
    const op = await store.getOperation(OP_ID);
    expect(op?.attentionRequired).toBe(false);
    expect(store.getAuditLog()).toHaveLength(0);
  });

  it("GATEWAY happy path still halts wallet + sets attention + one audit", async () => {
    const { store, result } = await apply("GATEWAY_ENDPOINT_DISAGREEMENT");
    expect(result.wallet?.signingHalted).toBe(true);
    expect(result.wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(result.operation?.status).toBe("NEEDS_ATTENTION");
    expect(result.operation?.attentionReason).toBe("VERIFICATION_INDETERMINATE");
    expect(result.needsAttentionEvent?.event).toBe("operation.needs_attention");
    expect(store.getAuditLog()).toHaveLength(1);
    expect(store.getAuditLog()[0]?.action).toBe("anomaly.halt_wallet_operation");
  });

  it("rolls back halt when markNeedsAttention throws mid-apply", async () => {
    const store = seededStore({
      wallet: leasedWallet({ signingHalted: false }),
      operation: liveOp("AWAITING_REDEMPTION"),
    });
    store.markNeedsAttention = async () => {
      throw new Error("simulated markNeedsAttention failure");
    };
    await expect(apply("GATEWAY_ENDPOINT_DISAGREEMENT", store)).rejects.toThrow(
      /simulated markNeedsAttention failure/,
    );
    const wallet = await store.getWallet(WALLET_ID);
    expect(wallet?.signingHalted).toBe(false);
    expect(wallet?.activeLeaseId).toBe(LEASE_ID);
    expect(store.getAuditLog()).toHaveLength(0);
  });
});
