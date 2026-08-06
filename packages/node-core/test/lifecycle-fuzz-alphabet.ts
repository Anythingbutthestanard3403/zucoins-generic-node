/**
 * lifecycle/recovery sequence fuzzer: ACTION ALPHABET + drivers.
 *
 * Two composed lanes under one seed:
 *   (1) reconcile-classifier lane — pure classify{Receive,Move,Send}Reconcile over fuzzed
 *       inputs (all three operation kinds; RELEASED-lease-during-reconcile; anomaly variants).
 *   (2) crash-replay lane — the SEND_EXTERNAL in-memory harness driven to each durable residue,
 *       crashed, recovered. HeadObservation alphabet EXCLUDES PROVEN_NOT_LANDED (JC1.4).
 *   (3) wallet-lease admission model — the one-in-flight-per-wallet rule (one in-flight op per wallet), keyed on
 *       wallet identity across all operation roles; RECONCILIATION exempt.
 *
 * amendment 8: Action objects carry ONLY opaque short ids — never a preimage/signature/secret.
 * amendment 9: no Date.now()/Math.random(); the clock is an injected fixture constant.
 *
 * TEST-ONLY. Frozen contracts reached via direct relative source import.
 */
import fc from "fast-check";

import { OBSERVATION_ANOMALY_KINDS } from "../../generic-node-contracts/src/observation/enums.contract.ts";
import {
  LEASE_ROLES,
  activeOperationLeases,
  isOperationRole,
  type LeaseLifecycleState,
  type LeaseRole,
  type WalletLease,
} from "../../generic-node-contracts/src/wallet-state/leases.ts";
import {
  LANDING_PROOF_FAULTS,
} from "../src/protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import { type PathObservation } from "../src/protocol/reconcile/observation-input.js";
import {
  type ReceiveReconcileInput,
  type MoveReconcileInput,
  type SendReconcileInput,
} from "../src/protocol/reconcile/index.js";
import {
  APPROVAL_ID,
  OPERATION_ID,
  baselinePlan,
  freshObservationPlan,
  FORMATION_CLOCK_SECS,
  T2_SECS,
  KEY_SEED_BYTE,
} from "./crash-replay-fixtures.ts";
import { addSecs, type Scenario, type UnixSecsString } from "./crash-replay-model.ts";
import {
  createScenario,
  crashAndRecover,
  driveToDurableState,
  type LaunchReachableHeadObservation,
} from "./crash-replay-driver.ts";
import { recoverOperation, snapshotDurable, type OracleContext } from "./crash-replay-recovery.ts";

// ---------------------------------------------------------------------------
// Shared arbitraries — opaque ids only.
// ---------------------------------------------------------------------------
const leaseArb: fc.Arbitrary<LeaseLifecycleState> = fc.constantFrom("ACTIVE", "RELEASED");
const faultArb = fc.constantFrom(...LANDING_PROOF_FAULTS);
const anomalyArb = fc.constantFrom(...OBSERVATION_ANOMALY_KINDS);

const landedProofArb = fc.oneof(
  fc.constant(mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub-1",
      expectedBodySha256: "body-1",
      freshHeadBodySha256: "body-1",
      freshHeadObservationId: "obs-1",
      depth: 0,
    })),
  fc
    .integer({ min: 1, max: 5 })
    .map((depth) => mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "pub-1",
      expectedBodySha256: "body-1",
      freshHeadBodySha256: "body-1-head",
      freshHeadObservationId: "obs-1",
      depth: depth,
    })),
);

export const pathObservationArb: fc.Arbitrary<PathObservation> = fc.oneof(
  landedProofArb.map((proof) => ({ result: "PROOF" as const, proof })),
  faultArb.map((fault) => ({ result: "PROOF_INCOMPLETE" as const, fault })),
  anomalyArb.map((anomaly) => ({ result: "ANOMALY" as const, anomaly })),
  fc.constant({ result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" as const }),
  fc.constant({ result: "NO_SUCCESSOR" as const }),
);

// ---------------------------------------------------------------------------
// Reconcile-input arbitraries (all three kinds, both boundaries).
// ---------------------------------------------------------------------------
export const receiveInputArb: fc.Arbitrary<ReceiveReconcileInput> = fc.oneof(
  fc.record({
    boundary: fc.constant("PRE_SUBMIT" as const),
    receiveOperationId: fc.constant("op-1"),
    formationComplete: fc.boolean(),
    step2SignaturePersisted: fc.boolean(),
    signerAuditIndicatesUse: fc.boolean(),
  }),
  fc.record({
    boundary: fc.constant("POST_SUBMIT" as const),
    receiveAttemptId: fc.constant("att-1"),
    receiverWalletId: fc.constant("w-1"),
    receiverLeaseState: leaseArb,
    receiverObservation: pathObservationArb,
  }),
);

export const moveInputArb: fc.Arbitrary<MoveReconcileInput> = fc.oneof(
  fc.record({
    boundary: fc.constant("PRE_SUBMIT" as const),
    moveAttemptId: fc.constant("mv-1"),
    preimagePersisted: fc.boolean(),
    signaturesComplete: fc.boolean(),
    signerAuditIndicatesCall: fc.boolean(),
  }),
  fc.record({
    boundary: fc.constant("POST_SUBMIT" as const),
    moveAttemptId: fc.constant("mv-1"),
    sourceWalletId: fc.constant("w-src"),
    destinationWalletId: fc.constant("w-dst"),
    expectedMoveBodySha256: fc.constant("body-1"),
    sourceLeaseState: leaseArb,
    destinationLeaseState: leaseArb,
    sourceObservation: pathObservationArb,
    destinationObservation: pathObservationArb,
  }),
);

export const sendInputArb: fc.Arbitrary<SendReconcileInput> = fc.oneof(
  fc.record({
    boundary: fc.constant("PRE_DELIVERY" as const),
    sendOperationId: fc.constant("sn-1"),
    signIntentPersisted: fc.boolean(),
    step1SignaturePersisted: fc.boolean(),
    signerAuditIndicatesCall: fc.boolean(),
  }),
  fc.record({
    boundary: fc.constant("DELIVERED" as const),
    sendAttemptId: fc.constant("att-1"),
    sourceWalletId: fc.constant("w-src"),
    sourceLeaseState: leaseArb,
    transferCodeSha256: fc.constant("code-1"),
    sourceObservation: pathObservationArb,
  }),
);

// ---------------------------------------------------------------------------
// Crash-replay lane — durable-residue alphabet + compatible observation. PROVEN_NOT_LANDED is
// deliberately absent (JC1.4). Each state is a crash boundary (amendment 10.ii coverage floor).
// ---------------------------------------------------------------------------
export const DURABLE_STATES = [
  "APPROVAL_PENDING_NO_SIGN_INTENT",
  "APPROVAL_CONSUMED_NO_SIGN_INTENT",
  "SIGNING_CLAIMED_NO_PARTIAL",
  "PARTIAL_COMMITTED_UNDELIVERED",
  "PARTIAL_DELIVERED_HEAD_UNCHANGED",
  "PARTIAL_DELIVERED_EXPECTED_AT_HEAD",
  "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
  "PARTIAL_EXPIRED",
] as const;
export type DurableStateToken = (typeof DURABLE_STATES)[number];

export const ANOMALOUS_VARIANTS = ["unrelated", "regressed", "unverifiable"] as const;
export type AnomalousVariant = (typeof ANOMALOUS_VARIANTS)[number];

export interface CrashReplayAction {
  readonly durableState: DurableStateToken;
  readonly anomalousVariant: AnomalousVariant;
}

export const crashReplayActionArb: fc.Arbitrary<CrashReplayAction> = fc.record({
  durableState: fc.constantFrom(...DURABLE_STATES),
  anomalousVariant: fc.constantFrom(...ANOMALOUS_VARIANTS),
});

// The residues where a durable partial ALREADY exists before recovery — the regime in which the
// "never replace/refresh/re-sign an existing partial" forbidden effects are meaningful. (For the
// pre-partial residues, legitimate first-formation recovery forms and delivers the FIRST partial,
// which correctly trips the new-code/new-intent detectors — those are row-specific, not universal.)
export const PARTIAL_EXISTS_STATES = [
  "PARTIAL_COMMITTED_UNDELIVERED",
  "PARTIAL_DELIVERED_HEAD_UNCHANGED",
  "PARTIAL_DELIVERED_EXPECTED_AT_HEAD",
  "PARTIAL_DELIVERED_HEAD_ANOMALOUS",
  "PARTIAL_EXPIRED",
] as const satisfies readonly DurableStateToken[];

export const partialExistsActionArb: fc.Arbitrary<CrashReplayAction> = fc.record({
  durableState: fc.constantFrom(...PARTIAL_EXISTS_STATES),
  anomalousVariant: fc.constantFrom(...ANOMALOUS_VARIANTS),
});

const HEALTHY_NOW: UnixSecsString = addSecs(FORMATION_CLOCK_SECS, 60); // < T2 (+300)
const PAST_EXPIRY_NO_MARGIN: UnixSecsString = addSecs(T2_SECS, 1); // past T2, < aging margin

/** Picks the recovery observation + clock compatible with a durable residue. Typed as
 *  LaunchReachableHeadObservation so PROVEN_NOT_LANDED is structurally unrepresentable here
 *  (JC1.4) — terminalization/lease-release is never reachable through this fuzzer. */
export function observationFor(action: CrashReplayAction): {
  observation: LaunchReachableHeadObservation;
  nowSecs: UnixSecsString;
} {
  switch (action.durableState) {
    case "PARTIAL_DELIVERED_EXPECTED_AT_HEAD":
      return { observation: { kind: "EXPECTED_AT_HEAD" }, nowSecs: HEALTHY_NOW };
    case "PARTIAL_DELIVERED_HEAD_ANOMALOUS":
      return {
        observation: { kind: "HEAD_ANOMALOUS", variant: action.anomalousVariant },
        nowSecs: HEALTHY_NOW,
      };
    case "PARTIAL_EXPIRED":
      return { observation: { kind: "NO_POSITIVE_PROOF" }, nowSecs: PAST_EXPIRY_NO_MARGIN };
    default:
      return { observation: { kind: "HEAD_UNCHANGED" }, nowSecs: HEALTHY_NOW };
  }
}

export interface CrashReplayRun {
  readonly scenario: Scenario;
  readonly ctx: OracleContext;
  readonly outcome: ReturnType<typeof recoverOperation>;
  readonly durableState: DurableStateToken;
  readonly observation: LaunchReachableHeadObservation;
}

/** Drive to a residue, crash, recover — mirrors crash-replay.matrix.test.ts runRecoveryPass. */
export function runCrashReplay(action: CrashReplayAction): CrashReplayRun {
  const approvalConsumed = action.durableState !== "APPROVAL_PENDING_NO_SIGN_INTENT";
  const driven = createScenario({
    operationId: OPERATION_ID,
    approvalId: APPROVAL_ID,
    approvalConsumed,
    workerId: "fuzz-formation-worker",
    seedByte: KEY_SEED_BYTE,
  });
  driveToDurableState(driven, baselinePlan(), action.durableState);
  const before = snapshotDurable(driven.durable, OPERATION_ID);
  const scenario = crashAndRecover(driven);
  const { observation, nowSecs } = observationFor(action);
  const outcome = recoverOperation(scenario, freshObservationPlan(), OPERATION_ID, nowSecs, observation);
  return {
    scenario,
    outcome,
    durableState: action.durableState,
    observation,
    ctx: {
      scenario,
      operationId: OPERATION_ID,
      before,
      observation,
      nowSecs,
      classification: outcome.classification,
    },
  };
}

// ---------------------------------------------------------------------------
// Wallet-lease admission model (the one-in-flight-per-wallet rule) — wallet-wide, across every operation role.
// Oracle = the frozen leases.ts predicates (activeOperationLeases / isOperationRole). Not a
// reimplementation of DB enforcement: it tests the invariant PREDICATE the runtime relies on.
// ---------------------------------------------------------------------------
export interface AcquisitionAttempt {
  readonly walletId: string;
  readonly role: LeaseRole;
}

export const acquisitionAttemptArb: fc.Arbitrary<AcquisitionAttempt> = fc.record({
  walletId: fc.constantFrom("wallet-A", "wallet-B"),
  role: fc.constantFrom(...LEASE_ROLES),
});

export interface WalletLeaseOutcome {
  readonly admittedOperationLeases: number;
  readonly operationRoleContenders: number;
  readonly reachedSigning: string | null;
}

/** Serialize a stream of acquisition attempts under the one-active-operation-lease-per-wallet
 *  rule; RECONCILIATION never pins and never counts. Returns per-wallet outcomes. */
export function simulateWalletAcquisitions(
  attempts: readonly AcquisitionAttempt[],
): Map<string, WalletLeaseOutcome> {
  const heldByWallet = new Map<string, WalletLease[]>();
  const contenders = new Map<string, number>();
  const signer = new Map<string, string | null>();
  for (const attempt of attempts) {
    const held = heldByWallet.get(attempt.walletId) ?? [];
    if (isOperationRole(attempt.role)) {
      contenders.set(attempt.walletId, (contenders.get(attempt.walletId) ?? 0) + 1);
      // wallet-wide admission: an operation-role lease is admitted only when NO active
      // operation lease is held on this wallet (the one-in-flight-per-wallet rule).
      if (activeOperationLeases(held).length === 0) {
        held.push({ role: attempt.role, lifecycle: "ACTIVE" });
        if (signer.get(attempt.walletId) == null) signer.set(attempt.walletId, attempt.role);
      }
    } else {
      // RECONCILIATION is observation-only — always admitted, exempt from the bound.
      held.push({ role: attempt.role, lifecycle: "ACTIVE" });
    }
    heldByWallet.set(attempt.walletId, held);
  }
  const result = new Map<string, WalletLeaseOutcome>();
  for (const [walletId, held] of heldByWallet) {
    result.set(walletId, {
      admittedOperationLeases: activeOperationLeases(held).length,
      operationRoleContenders: contenders.get(walletId) ?? 0,
      reachedSigning: signer.get(walletId) ?? null,
    });
  }
  return result;
}
