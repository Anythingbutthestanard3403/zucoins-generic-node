/**
 * Residual crash/replay proof harness — formation driver + crash
 * boundary + delivery ports.
 *
 * CRASH AXIOM (enforced mechanically here): all volatile state is lost on a crash; every
 * committed write survives; every uncommitted write is discarded — a kill inside DB-TX-N
 * is equivalent to the end of DB-TX-(N-1). `crashAndRecover` (1) rolls back every pending
 * uncommitted claim, (2) performs JSON.parse(JSON.stringify(durable)) so only
 * JSON-durable bytes cross the boundary, and (3) constructs a brand-new runtime — the old
 * runtime object, with every volatile intermediate, is discarded. Recovery over the live
 * store and over its JSON clone is proven to produce identical effect logs by the matrix
 * suite.
 *
 * The ten steps of driveFormation are the frozen custody sequence in guard order
 * (FORMATION_TRANSITIONS): persist sign intent BEFORE the signer, CAS, sign the exact
 * persisted bytes, persist the partial BEFORE delivery.
 */
import { digestPreimage } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  makeAttemptRow,
  makePartialRow,
  makeSignIntentRow,
  makeTransferCodeText,
  signFixture,
  type FormationPlan,
} from "./crash-replay-fixtures.ts";
import { compareAndSwapFormationState, rollbackPendingClaims } from "./crash-replay-cas.ts";
import {
  applyOperationStatus,
  applyRegimeUpdate,
  commitInsert,
  createRuntime,
  expiryFromPersistedPreimage,
  findOperation,
  isPastRedemptionExpiry,
  mustCommit,
  partialFor,
  REFUSAL_DELIVERY_EXPIRED,
  signIntentFor,
  stringField,
  timestampFromSecs,
  transitionFormation,
  type DurableStore,
  type OperationRow,
  type Scenario,
  type UnixSecsString,
} from "./crash-replay-model.ts";
import {
  ATTEMPTS_TABLE,
  ATTEMPTS_TABLE_NAME,
  MATERIAL_DOMAINS,
  PARTIALS_TABLE,
  PARTIALS_TABLE_NAME,
  SIGN_INTENTS_TABLE,
  SIGN_INTENTS_TABLE_NAME,
} from "./crash-replay-surfaces.ts";
import { validateRowAgainstTable } from "./transaction-material-model.ts";

export const FORMATION_STEPS = [
  "ACQUIRE_LEASE",
  "OBSERVE_FRESH",
  "CONSTRUCT_INNER",
  "PERSIST_SIGN_INTENT",
  "CAS_CLAIM_SIGNING",
  "REVALIDATE_PERSISTED",
  "SIGN_PERSISTED_PREIMAGE",
  "CONSTRUCT_TRANSFER_CODE",
  "PERSIST_PARTIAL",
  "DELIVER",
] as const;
export type FormationStep = (typeof FORMATION_STEPS)[number];

export const createScenario = (options: {
  operationId: string;
  approvalId: string;
  approvalConsumed: boolean;
  workerId?: string;
  seedByte?: number;
}): Scenario => {
  const operation: OperationRow = {
    operationId: options.operationId,
    kind: "SEND_EXTERNAL",
    status: options.approvalConsumed ? "APPROVED" : "CREATED",
    formationState: options.approvalConsumed ? "APPROVED_UNSIGNED" : "APPROVAL_PENDING",
    needsAttention: false,
    terminal: false,
    leaseHeld: false,
    approvalConsumed: options.approvalConsumed,
    approvalId: options.approvalId,
  };
  return {
    durable: {
      operations: [operation],
      signIntents: [],
      attempts: [],
      partials: [],
      signerAudit: [],
      deliveries: [],
    },
    runtime: createRuntime(options.workerId ?? "worker-1", options.seedByte ?? 0x5e),
  };
};

const revalidatePersistedIntent = (durable: DurableStore, operationId: string): void => {
  const intent = signIntentFor(durable, operationId);
  if (intent === undefined) {
    throw new Error("crash-replay driver: revalidation found no persisted sign intent");
  }
  const recomputed = digestPreimage(stringField(intent, "inner_preimage_text"));
  if (recomputed !== stringField(intent, "inner_sha256")) {
    throw new Error("crash-replay driver: persisted intent digest contradiction");
  }
};

/**
 * Executes the custody ten-step formation in frozen guard order, stopping after step
 * index `stopAfterStep` (default: all ten). Steps 2/3/6/8 are volatile (observation,
 * construction, revalidation, code assembly) and leave no durable residue; the durable
 * boundaries are steps 1, 4, 5, 7 (signer-audit evidence), 9, and 10 — matching the
 * DB-TX boundaries of operation-flow step 8 and step 3.
 */
export const driveFormation = (
  scenario: Scenario,
  plan: FormationPlan,
  stopAfterStep: number = FORMATION_STEPS.length,
): void => {
  const { durable, runtime } = scenario;
  const steps: readonly FormationStep[] = FORMATION_STEPS.slice(0, stopAfterStep);
  for (const step of steps) {
    switch (step) {
      case "ACQUIRE_LEASE": {
        const operation = findOperation(durable, plan.operationId);
        if (!operation.leaseHeld) {
          operation.leaseHeld = true;
          runtime.log.leaseAcquisitions += 1;
        }
        break;
      }
      case "OBSERVE_FRESH":
      case "CONSTRUCT_INNER":
        runtime.volatileDb.innerText = plan.preimageText;
        break;
      case "PERSIST_SIGN_INTENT":
        mustCommit(
          commitInsert(
            scenario,
            SIGN_INTENTS_TABLE,
            durable.signIntents,
            makeSignIntentRow(plan),
            SIGN_INTENTS_TABLE_NAME,
            plan.operationId,
          ),
          "sign-intent persist",
        );
        mustCommit(
          commitInsert(
            scenario,
            ATTEMPTS_TABLE,
            durable.attempts,
            makeAttemptRow(plan),
            ATTEMPTS_TABLE_NAME,
            plan.operationId,
          ),
          "attempt-row persist",
        );
        break;
      case "CAS_CLAIM_SIGNING":
        if (!compareAndSwapFormationState(scenario, plan.operationId)) {
          throw new Error("crash-replay driver: single-worker formation lost its own CAS");
        }
        break;
      case "REVALIDATE_PERSISTED":
        revalidatePersistedIntent(durable, plan.operationId);
        break;
      case "SIGN_PERSISTED_PREIMAGE": {
        const intent = signIntentFor(durable, plan.operationId);
        if (intent === undefined) {
          throw new Error("crash-replay driver: signer called with no persisted intent");
        }
        const preimageText = stringField(intent, "inner_preimage_text");
        const signature = signFixture(preimageText, runtime.seedByte);
        runtime.log.signerCalls.push({ operationId: plan.operationId, preimageText, signature });
        durable.signerAudit.push({
          operationId: plan.operationId,
          preimageSha256: digestPreimage(preimageText),
          signature,
        });
        runtime.volatileDb.signature = signature;
        break;
      }
      case "CONSTRUCT_TRANSFER_CODE": {
        const intent = signIntentFor(durable, plan.operationId);
        const signature = runtime.volatileDb.signature;
        if (intent === undefined || signature === undefined) {
          throw new Error("crash-replay driver: code construction without persisted material");
        }
        runtime.volatileDb.transferCodeText = makeTransferCodeText(
          stringField(intent, "inner_preimage_text"),
          signature,
        );
        break;
      }
      case "PERSIST_PARTIAL": {
        const signature = runtime.volatileDb.signature;
        const transferCodeText = runtime.volatileDb.transferCodeText;
        if (signature === undefined || transferCodeText === undefined) {
          throw new Error("crash-replay driver: partial persist without a volatile signature");
        }
        mustCommit(
          commitInsert(
            scenario,
            PARTIALS_TABLE,
            durable.partials,
            makePartialRow(plan, signature, transferCodeText),
            PARTIALS_TABLE_NAME,
            plan.operationId,
          ),
          "partial persist",
        );
        const attempt = durable.attempts.find((row) => row["operation_id"] === plan.operationId);
        if (attempt === undefined) {
          throw new Error("crash-replay driver: no attempt row to complete");
        }
        attempt["step_1_signature"] = signature;
        attempt["attempt_phase"] = "STEP1_SIGNATURE_PERSISTED";
        const violations = validateRowAgainstTable(ATTEMPTS_TABLE, MATERIAL_DOMAINS, attempt);
        if (violations.length > 0) {
          throw new Error(
            `crash-replay driver: attempt completion violates: ${violations.join(", ")}`,
          );
        }
        transitionFormation(scenario, plan.operationId, "PARTIAL_PERSISTED");
        break;
      }
      case "DELIVER": {
        const outcome = deliverPartial(scenario, plan.operationId, plan.formationClockSecs);
        if (!outcome.delivered) {
          throw new Error(`crash-replay driver: first delivery refused: ${outcome.refusal}`);
        }
        break;
      }
    }
  }
};

export interface DeliveryOutcome {
  readonly delivered: boolean;
  readonly refusal?: string;
}

/** First delivery of the persisted partial (operation-flow step 4: only after commit). Serves
 *  FROM THE STORE. Fail-closed pre-delivery expiry gate : at or past T2 the code
 *  is NOT delivered; the caller routes to NEEDS_ATTENTION. */
export const deliverPartial = (
  scenario: Scenario,
  operationId: string,
  nowSecs: UnixSecsString,
): DeliveryOutcome => {
  const { durable, runtime } = scenario;
  const intent = signIntentFor(durable, operationId);
  const partial = partialFor(durable, operationId);
  if (intent === undefined || partial === undefined) {
    throw new Error("crash-replay driver: delivery without persisted material");
  }
  if (partial["first_delivered_at"] !== null) {
    throw new Error("crash-replay driver: first delivery twice is a caller bug");
  }
  if (isPastRedemptionExpiry(nowSecs, expiryFromPersistedPreimage(intent))) {
    runtime.log.refusals.push(REFUSAL_DELIVERY_EXPIRED);
    return { delivered: false, refusal: REFUSAL_DELIVERY_EXPIRED };
  }
  const update = applyRegimeUpdate(scenario, PARTIALS_TABLE_NAME, durable.partials, PARTIALS_TABLE, operationId, {
    first_delivered_at: timestampFromSecs(nowSecs),
  });
  if (!update.applied) {
    throw new Error("crash-replay driver: regime rejected first_delivered_at");
  }
  const servedText = stringField(partial, "transfer_code_text");
  const servedSha = stringField(partial, "transfer_code_sha256");
  durable.deliveries.push({ operationId, deliveredAtSecs: nowSecs, transferCodeSha256: servedSha });
  runtime.log.deliveriesServed.push({
    operationId,
    transferCodeText: servedText,
    transferCodeSha256: servedSha,
  });
  transitionFormation(scenario, operationId, "PARTIAL_DELIVERED");
  applyOperationStatus(scenario, operationId, "AWAITING_REDEMPTION");
  return { delivered: true };
};

/** Re-delivery (operation-flow step 5; REDELIVERY_RULE): returns the exact persisted bytes from
 *  the store and increments ONLY the delivery audit counters. Never rebuilds, never
 *  refreshes a link or expiry, never signs. */
export const redeliverPartial = (
  scenario: Scenario,
  operationId: string,
  nowSecs: UnixSecsString,
): void => {
  const { durable, runtime } = scenario;
  const partial = partialFor(durable, operationId);
  if (partial === undefined) {
    throw new Error("crash-replay driver: redelivery without a persisted partial");
  }
  if (partial["first_delivered_at"] === null) {
    throw new Error("crash-replay driver: redelivery before first delivery is a caller bug");
  }
  const count = partial["redelivery_count"];
  if (typeof count !== "number") {
    throw new Error("crash-replay driver: redelivery_count is not numeric");
  }
  const update = applyRegimeUpdate(scenario, PARTIALS_TABLE_NAME, durable.partials, PARTIALS_TABLE, operationId, {
    last_redelivered_at: timestampFromSecs(nowSecs),
    redelivery_count: count + 1,
  });
  if (!update.applied) {
    throw new Error("crash-replay driver: regime rejected redelivery counters");
  }
  const servedText = stringField(partial, "transfer_code_text");
  const servedSha = stringField(partial, "transfer_code_sha256");
  durable.deliveries.push({ operationId, deliveredAtSecs: nowSecs, transferCodeSha256: servedSha });
  runtime.log.deliveriesServed.push({
    operationId,
    transferCodeText: servedText,
    transferCodeSha256: servedSha,
  });
};

/**
 * The crash boundary. Uncommitted claims roll back (a kill inside DB-TX-N ≡ end of
 * DB-TX-(N-1)); only JSON-durable bytes cross; a brand-new runtime replaces the old one.
 */
export const crashAndRecover = (scenario: Scenario): Scenario => {
  rollbackPendingClaims(scenario.durable, scenario.runtime.volatileDb);
  const durable = JSON.parse(JSON.stringify(scenario.durable)) as DurableStore;
  return {
    durable,
    runtime: createRuntime(scenario.runtime.workerId, scenario.runtime.seedByte),
  };
};

/** Drives the formation driver to exactly the durable residue characterizing one of the
 *  eight durable states (head observation and clock are recovery INPUTS, not store
 *  content — the external world is a fixture). */
export const driveToDurableState = (
  scenario: Scenario,
  plan: FormationPlan,
  durableState: string,
): void => {
  switch (durableState) {
    case "APPROVAL_PENDING_NO_SIGN_INTENT":
      break;
    case "APPROVAL_CONSUMED_NO_SIGN_INTENT":
      driveFormation(scenario, plan, 1);
      break;
    case "SIGNING_CLAIMED_NO_PARTIAL":
      driveFormation(scenario, plan, 5);
      break;
    case "PARTIAL_COMMITTED_UNDELIVERED":
      driveFormation(scenario, plan, 9);
      break;
    case "PARTIAL_DELIVERED_HEAD_UNCHANGED":
    case "PARTIAL_DELIVERED_EXPECTED_AT_HEAD":
    case "PARTIAL_DELIVERED_HEAD_ANOMALOUS":
    case "PARTIAL_EXPIRED":
      driveFormation(scenario, plan);
      break;
    default:
      throw new Error(`crash-replay driver: unknown durable state ${durableState}`);
  }
};

/**
 * Launch-reachable head-observation kinds — the alphabet a real recovery path can observe.
 * "There is no generic PROVEN_NOT_LANDED oracle." Closed set is pinned by census
 * PROVEN_NOT_LANDED is deliberately absent.
 */
export const LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS = [
  "HEAD_UNCHANGED",
  "EXPECTED_AT_HEAD",
  "HEAD_ANOMALOUS",
  "NO_POSITIVE_PROOF",
] as const;
export type LaunchReachableHeadObservationKind =
  (typeof LAUNCH_REACHABLE_HEAD_OBSERVATION_KINDS)[number];

/** Observations a launch node can actually produce.
 *  The anomalous head has THREE sub-variants and all are fed. */
export type LaunchReachableHeadObservation =
  | { readonly kind: "HEAD_UNCHANGED" }
  | { readonly kind: "EXPECTED_AT_HEAD" }
  | { readonly kind: "HEAD_ANOMALOUS"; readonly variant: "unrelated" | "regressed" | "unverifiable" }
  | { readonly kind: "NO_POSITIVE_PROOF" };

/**
 * Pre- harness fixture for the RESERVED SEND NEEDS_ATTENTION→REJECTED transition
 * (state/event; states.contract.ts precondition = PROVEN_NOT_LANDED_ORACLE_REQUIRED).
 * NOT launch-reachable — supplies no such oracle. Construct only via
 * `notLaunchReachableProvenNotLanded()` so callers cannot casually feed it as a live oracle
 * The `notLaunchReachable: true` brand is required by the type.
 */
export type NotLaunchReachableProvenNotLanded = {
  readonly kind: "PROVEN_NOT_LANDED";
  /** Explicit brand: this observation is not emit-able by launch recovery. */
  readonly notLaunchReachable: true;
};

/** The external world a recovery pass reads, as a fixture. Union of the launch-reachable
 *  alphabet plus the explicitly-branded not-launch-reachable PROVEN_NOT_LANDED fixture. */
export type HeadObservation = LaunchReachableHeadObservation | NotLaunchReachableProvenNotLanded;

/** Sole constructor for the not-launch-reachable PROVEN_NOT_LANDED fixture. */
export const notLaunchReachableProvenNotLanded = (): NotLaunchReachableProvenNotLanded => ({
  kind: "PROVEN_NOT_LANDED",
  notLaunchReachable: true,
});

export const isLaunchReachableHeadObservation = (
  observation: HeadObservation,
): observation is LaunchReachableHeadObservation => observation.kind !== "PROVEN_NOT_LANDED";

/** Classifies the durable residue from the rows alone (independent of the frozen matrix;
 *  the matrix suite asserts every output is a censused member). A delivered-but-expired
 *  partial classifies as the expired row; an undelivered one keeps its own row and meets
 *  the pre-delivery gate. */
export const classifyDurableState = (
  durable: DurableStore,
  operationId: string,
  nowSecs: UnixSecsString,
  observation: HeadObservation,
): string => {
  const operation = findOperation(durable, operationId);
  if (!operation.approvalConsumed) {
    return "APPROVAL_PENDING_NO_SIGN_INTENT";
  }
  const intent = signIntentFor(durable, operationId);
  if (intent === undefined) {
    return "APPROVAL_CONSUMED_NO_SIGN_INTENT";
  }
  const partial = partialFor(durable, operationId);
  if (partial === undefined) {
    return "SIGNING_CLAIMED_NO_PARTIAL";
  }
  if (partial["first_delivered_at"] === null) {
    return "PARTIAL_COMMITTED_UNDELIVERED";
  }
  // F4 expiry is evaluated BEFORE the head-observation switch by design. A delivered
  // partial that is BOTH past-T2 AND observed EXPECTED_AT_HEAD classifies as PARTIAL_EXPIRED
  // (-> reconcile-first NEEDS_ATTENTION), never PARTIAL_DELIVERED_EXPECTED_AT_HEAD (-> MARK_LANDED).
  // This is the conservative, custody-safe divergence the crash-replay register requires ("past-expiry delivered =
  // NEEDS_ATTENTION + reconcile-first"): a landing that surfaces only after the redemption window
  // elapsed is an anomaly a human reconciles, not an autonomous terminalization. Expiry still
  // never releases the lease or terminalizes on its own — that needs positive non-landing proof
  // plus the aging margin (see recoverOperation's PARTIAL_EXPIRED case). Pinned by
  // crash-replay.census.test.ts (F4).
  if (isPastRedemptionExpiry(nowSecs, expiryFromPersistedPreimage(intent))) {
    return "PARTIAL_EXPIRED";
  }
  switch (observation.kind) {
    case "HEAD_UNCHANGED":
      return "PARTIAL_DELIVERED_HEAD_UNCHANGED";
    case "EXPECTED_AT_HEAD":
      return "PARTIAL_DELIVERED_EXPECTED_AT_HEAD";
    case "HEAD_ANOMALOUS":
      return "PARTIAL_DELIVERED_HEAD_ANOMALOUS";
    default:
      throw new Error(
        `crash-replay driver: observation ${observation.kind} does not classify a live head`,
      );
  }
};
