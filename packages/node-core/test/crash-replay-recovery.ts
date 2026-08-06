/**
 * Residual crash/replay proof harness — the recovery procedure under
 * test, plus the closed-set effect oracles the suites assert against.
 *
 * ANTI-TAUTOLOGY (load-bearing): recoverOperation is written from the PROSE semantics of
 * the operation flows ("Crash handling is exact"), the recovery rules
 * 4, and the frozen facts REDELIVERY_RULE / REPLACEMENT_RULE / TIMER_SEPARATION /
 * DETERMINISTIC_RESIGN / INVARIANT_BREACH_PREDICATE. It NEVER imports the frozen decision
 * table (CRASH_MATRIX / CRASH_POINTS / CRASH_DURABLE_STATES) or its lookup
 * (recoveryActionFor) — the frozen matrix is the expectation oracle only. The census suite
 * enforces this by scanning this file's source text.
 *
 * The action vocabulary returned here is harness-local; the suites never trust it — they
 * assert observable effects via PRESCRIBED_EFFECT_ASSERTERS / FORBIDDEN_EFFECT_DETECTORS,
 * closed sets keyed to the frozen action lists.
 */
import { digestPreimage } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  DETERMINISTIC_RESIGN,
  INVARIANT_BREACH_PREDICATE,
  type ForbiddenRecoveryAction,
  type RecoveryAction,
} from "../../generic-node-contracts/src/approval/crash-recovery.contract.ts";
import { compareAndSwapFormationState } from "./crash-replay-cas.ts";
import {
  classifyDurableState,
  deliverPartial,
  driveFormation,
  redeliverPartial,
  type HeadObservation,
} from "./crash-replay-driver.ts";
import { makeTransferCodeText, signFixture, type FormationPlan } from "./crash-replay-fixtures.ts";
import {
  agingMarginElapsed,
  applyOperationStatus,
  commitInsert,
  expiryFromPersistedPreimage,
  findOperation,
  isPastRedemptionExpiry,
  mustCommit,
  partialFor,
  signIntentFor,
  stringField,
  timestampFromSecs,
  transitionFormation,
  type DurableStore,
  type Scenario,
  type UnixSecsString,
} from "./crash-replay-model.ts";
import {
  ATTEMPTS_TABLE,
  MATERIAL_DOMAINS,
  PARTIALS_TABLE,
  PARTIALS_TABLE_NAME,
  SIGN_INTENTS_TABLE_NAME,
} from "./crash-replay-surfaces.ts";
import { validateRowAgainstTable } from "./transaction-material-model.ts";

export interface RecoveryOutcome {
  readonly classification: string;
  readonly action: string;
}

const markNeedsAttention = (scenario: Scenario, operationId: string, reason: string): void => {
  applyOperationStatus(scenario, operationId, "NEEDS_ATTENTION");
  scenario.runtime.log.needsAttentionMarks.push(reason);
};

const markInvariantBreach = (scenario: Scenario, operationId: string, reason: string): void => {
  markNeedsAttention(
    scenario,
    operationId,
    `${INVARIANT_BREACH_PREDICATE.classification}:${reason}`,
  );
};

/** Completes the FIRST durable formation from persisted material only (operation-flow bullet 2):
 *  the identical persisted preimage, the deterministic signature, one partial, then the
 *  gated first delivery. Never a re-formation. */
const completeFirstFormation = (
  scenario: Scenario,
  plan: FormationPlan,
  operationId: string,
  nowSecs: UnixSecsString,
): RecoveryOutcome => {
  const { durable, runtime } = scenario;
  const intent = signIntentFor(durable, operationId);
  if (intent === undefined) {
    throw new Error("crash-replay recovery: completion without a persisted intent");
  }
  const preimageText = stringField(intent, "inner_preimage_text");
  const storedDigest = stringField(intent, "inner_sha256");
  if (digestPreimage(preimageText) !== storedDigest) {
    markInvariantBreach(scenario, operationId, "persisted_preimage_unavailable_or_contradictory");
    return { classification: "SIGNING_CLAIMED_NO_PARTIAL", action: "NEEDS_ATTENTION" };
  }
  if (findOperation(durable, operationId).formationState !== "SIGNING_CLAIMED") {
    compareAndSwapFormationState(scenario, operationId);
  }
  const priorAudit = durable.signerAudit.find((entry) => entry.operationId === operationId);
  let signature: string;
  if (priorAudit === undefined) {
    signature = signFixture(preimageText, runtime.seedByte);
    runtime.log.signerCalls.push({ operationId, preimageText, signature });
    durable.signerAudit.push({ operationId, preimageSha256: storedDigest, signature });
  } else {
    if (priorAudit.preimageSha256 !== storedDigest) {
      markInvariantBreach(scenario, operationId, "signer_audit_digest_contradicts_persisted");
      return { classification: "SIGNING_CLAIMED_NO_PARTIAL", action: "NEEDS_ATTENTION" };
    }
    // DETERMINISTIC_RESIGN.recoveryByteComparesAgainstPriorSignerAuditSignatureBeforeDelivery:
    // the re-sign of the SAME persisted bytes must byte-equal the prior audit signature
    // BEFORE any delivery; a mismatch is INVARIANT_BREACH and is never delivered.
    const resigned = signFixture(preimageText, runtime.seedByte);
    runtime.log.signerCalls.push({ operationId, preimageText, signature: resigned });
    if (resigned !== priorAudit.signature) {
      markInvariantBreach(scenario, operationId, DETERMINISTIC_RESIGN.mismatchClassification);
      return { classification: "SIGNING_CLAIMED_NO_PARTIAL", action: "NEEDS_ATTENTION" };
    }
    signature = resigned;
  }
  const transferCodeText = makeTransferCodeText(preimageText, signature);
  mustCommit(
    commitInsert(
      scenario,
      PARTIALS_TABLE,
      durable.partials,
      {
        operation_id: operationId,
        approval_id: findOperation(durable, operationId).approvalId,
        inner_sha256: storedDigest,
        step_1_signature: signature,
        transfer_code_text: transferCodeText,
        transfer_code_sha256: digestPreimage(transferCodeText),
        persisted_at: timestampFromSecs(nowSecs),
        first_delivered_at: null,
        last_redelivered_at: null,
        redelivery_count: 0,
      },
      PARTIALS_TABLE_NAME,
      operationId,
    ),
    "recovery partial persist",
  );
  const attempt = durable.attempts.find((row) => row["operation_id"] === operationId);
  if (attempt !== undefined) {
    attempt["step_1_signature"] = signature;
    attempt["attempt_phase"] = "STEP1_SIGNATURE_PERSISTED";
    const violations = validateRowAgainstTable(ATTEMPTS_TABLE, MATERIAL_DOMAINS, attempt);
    if (violations.length > 0) {
      throw new Error(`crash-replay recovery: attempt completion violates: ${violations.join(", ")}`);
    }
  }
  transitionFormation(scenario, operationId, "PARTIAL_PERSISTED");
  const delivery = deliverPartial(scenario, operationId, nowSecs);
  if (!delivery.delivered) {
    markNeedsAttention(scenario, operationId, "expired_before_first_delivery");
    return { classification: "SIGNING_CLAIMED_NO_PARTIAL", action: "NEEDS_ATTENTION" };
  }
  return { classification: "SIGNING_CLAIMED_NO_PARTIAL", action: "COMPLETED_FIRST_FORMATION" };
};

/**
 * The recovery pass under test: reads ONLY durable rows (plus the injected clock and the
 * head-observation fixture), classifies the residue, and performs the one permitted
 * completion/redelivery/escalation — never a second intent, never a second partial,
 * never a refreshed byte.
 */
export const recoverOperation = (
  scenario: Scenario,
  plan: FormationPlan,
  operationId: string,
  nowSecs: UnixSecsString,
  observation: HeadObservation,
): RecoveryOutcome => {
  const { durable, runtime } = scenario;
  const classification = classifyDurableState(durable, operationId, nowSecs, observation);
  switch (classification) {
    case "APPROVAL_PENDING_NO_SIGN_INTENT":
      return { classification, action: "AWAITED" };
    case "APPROVAL_CONSUMED_NO_SIGN_INTENT": {
      // recovery / operation-flow: first formation ONLY after proving the signer was never
      // called; a signer-audit call with no persisted intent is INVARIANT_BREACH.
      if (durable.signerAudit.some((entry) => entry.operationId === operationId)) {
        markInvariantBreach(
          scenario,
          operationId,
          "no_persisted_sign_intent_row_but_signer_audit_shows_a_signing_call",
        );
        return { classification, action: "NEEDS_ATTENTION" };
      }
      driveFormation(scenario, plan);
      return { classification, action: "FIRST_FORMATION_COMPLETED" };
    }
    case "SIGNING_CLAIMED_NO_PARTIAL":
      return completeFirstFormation(scenario, plan, operationId, nowSecs);
    case "PARTIAL_COMMITTED_UNDELIVERED": {
      const delivery = deliverPartial(scenario, operationId, nowSecs);
      if (!delivery.delivered) {
        markNeedsAttention(scenario, operationId, "expired_before_first_delivery");
        return { classification, action: "NEEDS_ATTENTION" };
      }
      return { classification, action: "DELIVERED" };
    }
    case "PARTIAL_DELIVERED_HEAD_UNCHANGED":
      redeliverPartial(scenario, operationId, nowSecs);
      return { classification, action: "REDELIVERED" };
    case "PARTIAL_DELIVERED_EXPECTED_AT_HEAD":
      applyOperationStatus(scenario, operationId, "EXTERNAL_SEND_LANDED");
      return { classification, action: "MARKED_LANDED" };
    case "PARTIAL_DELIVERED_HEAD_ANOMALOUS":
      markNeedsAttention(scenario, operationId, "anomalous_head_preserve_lease_evidence");
      return { classification, action: "NEEDS_ATTENTION" };
    case "PARTIAL_EXPIRED": {
      const intent = signIntentFor(durable, operationId);
      if (intent === undefined) {
        throw new Error("crash-replay recovery: expired row without its intent");
      }
      const t2 = expiryFromPersistedPreimage(intent);
      // Expiry alone never releases the source; terminalize ONLY under the
      // positive non-landing proof once the protocol expiry plus safety margin has passed.
      // PROVEN_NOT_LANDED is NOT a launch oracle  — the harness only accepts
      // it when the observation carries the explicit notLaunchReachable brand. Without that
      // brand this branch never fires; the fuzzer alphabet also excludes the kind.
      if (
        observation.kind === "PROVEN_NOT_LANDED" &&
        observation.notLaunchReachable === true &&
        agingMarginElapsed(nowSecs, t2)
      ) {
        applyOperationStatus(scenario, operationId, "REJECTED");
        findOperation(durable, operationId).leaseHeld = false;
        runtime.log.leaseReleases += 1;
        runtime.log.terminalizations.push("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
        return { classification, action: "TERMINALIZED" };
      }
      markNeedsAttention(scenario, operationId, "expired_without_positive_non_landing_proof");
      return { classification, action: "NEEDS_ATTENTION" };
    }
    default:
      throw new Error(`crash-replay recovery: unhandled classification ${classification}`);
  }
};

// ---------------------------------------------------------------------------
// Effect oracles — closed sets keyed to the frozen action vocabularies.
// ---------------------------------------------------------------------------

export interface DurableSnapshot {
  readonly intents: number;
  readonly partials: number;
  readonly attempts: number;
  readonly auditEntries: number;
  readonly deliveries: number;
  readonly redeliveryCount: number;
  readonly intentText?: string;
  readonly intentSha?: string;
  readonly codeText?: string;
  readonly codeSha?: string;
  readonly approvalId?: string;
  readonly t2?: UnixSecsString;
}

export const snapshotDurable = (durable: DurableStore, operationId: string): DurableSnapshot => {
  const intent = signIntentFor(durable, operationId);
  const partial = partialFor(durable, operationId);
  const count = partial?.["redelivery_count"];
  const operation = durable.operations.find((row) => row.operationId === operationId);
  return {
    intents: durable.signIntents.filter((row) => row["operation_id"] === operationId).length,
    partials: durable.partials.filter((row) => row["operation_id"] === operationId).length,
    attempts: durable.attempts.filter((row) => row["operation_id"] === operationId).length,
    auditEntries: durable.signerAudit.filter((entry) => entry.operationId === operationId).length,
    deliveries: durable.deliveries.filter((entry) => entry.operationId === operationId).length,
    redeliveryCount: typeof count === "number" ? count : 0,
    intentText: intent === undefined ? undefined : stringField(intent, "inner_preimage_text"),
    intentSha: intent === undefined ? undefined : stringField(intent, "inner_sha256"),
    codeText: partial === undefined ? undefined : stringField(partial, "transfer_code_text"),
    codeSha: partial === undefined ? undefined : stringField(partial, "transfer_code_sha256"),
    approvalId: operation?.approvalId,
    t2: intent === undefined ? undefined : expiryFromPersistedPreimage(intent),
  };
};

export interface OracleContext {
  readonly scenario: Scenario;
  readonly operationId: string;
  readonly before: DurableSnapshot;
  readonly observation: HeadObservation;
  readonly nowSecs: UnixSecsString;
  readonly classification: string;
}

const proofPresent = (ctx: OracleContext): boolean =>
  ctx.observation.kind === "PROVEN_NOT_LANDED" &&
  ctx.observation.notLaunchReachable === true &&
  ctx.before.t2 !== undefined &&
  agingMarginElapsed(ctx.nowSecs, ctx.before.t2);

const committedInserts = (ctx: OracleContext): number =>
  ctx.scenario.runtime.log.insertAttempts.filter((attempt) => attempt.committed).length;

const rowCountsUnchanged = (ctx: OracleContext): boolean => {
  const after = snapshotDurable(ctx.scenario.durable, ctx.operationId);
  return (
    after.intents === ctx.before.intents &&
    after.partials === ctx.before.partials &&
    after.attempts === ctx.before.attempts &&
    after.auditEntries === ctx.before.auditEntries
  );
};

/** Every served byte string must equal the partial bytes CURRENTLY persisted in the
 *  durable store (serve FROM THE STORE — the fixture variable is out of scope). */
const servedOnlyPersistedBytes = (ctx: OracleContext): boolean => {
  const after = snapshotDurable(ctx.scenario.durable, ctx.operationId);
  return ctx.scenario.runtime.log.deliveriesServed.every(
    (served) =>
      served.transferCodeText === after.codeText && served.transferCodeSha256 === after.codeSha,
  );
};

export const PRESCRIBED_EFFECT_ASSERTERS: Record<RecoveryAction, (ctx: OracleContext) => boolean> = {
  AWAIT_APPROVAL_OR_REJECT_SAFELY: (ctx) => {
    const { log } = ctx.scenario.runtime;
    return (
      log.leaseAcquisitions === 0 &&
      log.leaseReleases === 0 &&
      log.signerCalls.length === 0 &&
      log.insertAttempts.length === 0 &&
      log.deliveriesServed.length === 0 &&
      log.operationTransitions.length === 0 &&
      log.formationTransitions.length === 0 &&
      log.needsAttentionMarks.length === 0 &&
      log.terminalizations.length === 0
    );
  },
  ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const after = snapshotDurable(ctx.scenario.durable, ctx.operationId);
    return (
      ctx.before.intents === 0 &&
      after.intents === 1 &&
      after.partials === 1 &&
      log.signerCalls.length === 1 &&
      log.signerCalls.every((call) => call.preimageText === after.intentText) &&
      log.deliveriesServed.length === 1 &&
      servedOnlyPersistedBytes(ctx) &&
      findOperation(ctx.scenario.durable, ctx.operationId).leaseHeld
    );
  },
  REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const after = snapshotDurable(ctx.scenario.durable, ctx.operationId);
    return (
      after.intents === ctx.before.intents &&
      after.partials === 1 &&
      log.signerCalls.length >= 1 &&
      log.signerCalls.every((call) => call.preimageText === ctx.before.intentText) &&
      log.deliveriesServed.length === 1 &&
      servedOnlyPersistedBytes(ctx)
    );
  },
  DELIVER_EXACT_PERSISTED_CODE: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const partial = partialFor(ctx.scenario.durable, ctx.operationId);
    return (
      log.signerCalls.length === 0 &&
      committedInserts(ctx) === 0 &&
      log.deliveriesServed.length === 1 &&
      servedOnlyPersistedBytes(ctx) &&
      partial !== undefined &&
      partial["first_delivered_at"] !== null &&
      log.leaseReleases === 0
    );
  },
  REDELIVER_EXACT_PERSISTED_CODE: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const after = snapshotDurable(ctx.scenario.durable, ctx.operationId);
    return (
      log.signerCalls.length === 0 &&
      committedInserts(ctx) === 0 &&
      log.deliveriesServed.length >= 1 &&
      servedOnlyPersistedBytes(ctx) &&
      after.redeliveryCount === ctx.before.redeliveryCount + log.deliveriesServed.length
    );
  },
  MARK_LANDED_FROM_VERIFIED_OBSERVATION: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const operation = findOperation(ctx.scenario.durable, ctx.operationId);
    return (
      operation.status === "EXTERNAL_SEND_LANDED" &&
      operation.terminal &&
      log.signerCalls.length === 0 &&
      committedInserts(ctx) === 0 &&
      log.deliveriesServed.length === 0 &&
      log.leaseReleases === 0
    );
  },
  NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const operation = findOperation(ctx.scenario.durable, ctx.operationId);
    return (
      operation.needsAttention &&
      operation.leaseHeld &&
      log.needsAttentionMarks.length >= 1 &&
      log.leaseReleases === 0 &&
      log.terminalizations.length === 0 &&
      log.signerCalls.length === 0 &&
      committedInserts(ctx) === 0 &&
      rowCountsUnchanged(ctx)
    );
  },
  TERMINALIZE_ON_POSITIVE_EXPIRY_OR_NON_LANDING: (ctx) => {
    const { log } = ctx.scenario.runtime;
    const operation = findOperation(ctx.scenario.durable, ctx.operationId);
    if (proofPresent(ctx)) {
      return (
        log.terminalizations.length === 1 &&
        log.leaseReleases === 1 &&
        operation.status === "REJECTED" &&
        operation.terminal &&
        !operation.leaseHeld &&
        log.signerCalls.length === 0 &&
        log.deliveriesServed.length === 0 &&
        committedInserts(ctx) === 0 &&
        rowCountsUnchanged(ctx)
      );
    }
    return (
      operation.needsAttention &&
      operation.leaseHeld &&
      log.terminalizations.length === 0 &&
      log.leaseReleases === 0 &&
      log.signerCalls.length === 0 &&
      committedInserts(ctx) === 0 &&
      rowCountsUnchanged(ctx)
    );
  },
};

export const FORBIDDEN_EFFECT_DETECTORS: Record<ForbiddenRecoveryAction, (ctx: OracleContext) => boolean> = {
  ACQUIRE_OR_SIGN: (ctx) => {
    const { log } = ctx.scenario.runtime;
    return log.leaseAcquisitions > 0 || log.signerCalls.length > 0;
  },
  // F3 — load-bearing, not vacuous. The STRUCTURAL guard against a second sign intent is the
  // `operation_id` PRIMARY KEY on external_send_sign_intents (a duplicate INSERT fails) plus
  // `assertCardinality` (intents <= 1) in the suites. This detector is the observable-effect
  // counterpart: it fires if recovery ever leaves MORE THAN ONE intent for the operation
  // (`after.intents > 1`), or inserts an intent when one already existed (`before.intents > 0`
  // + a sign-intent INSERT). The `after.intents > 1` disjunct is what keeps it non-vacuous on
  // the APPROVAL_CONSUMED_NO_SIGN_INTENT row, whose legitimate recovery creates exactly the
  // FIRST intent (before 0 -> after 1) and must NOT be flagged.
  CREATE_SECOND_SIGN_INTENT: (ctx) =>
    snapshotDurable(ctx.scenario.durable, ctx.operationId).intents > 1 ||
    (ctx.before.intents > 0 &&
      ctx.scenario.runtime.log.insertAttempts.some(
        (attempt) => attempt.table === SIGN_INTENTS_TABLE_NAME,
      )),
  CONSTRUCT_DIFFERENT_INNER_OR_CODE: (ctx) =>
    ctx.scenario.runtime.log.signerCalls.some((call) => call.preimageText !== ctx.before.intentText),
  RE_SIGN_OR_RE_FORM: (ctx) =>
    ctx.before.partials > 0 && ctx.scenario.runtime.log.signerCalls.length > 0,
  MINT_REPLACEMENT_PARTIAL: (ctx) =>
    (ctx.before.partials > 0 &&
      ctx.scenario.runtime.log.insertAttempts.some(
        (attempt) => attempt.table === PARTIALS_TABLE_NAME,
      )) ||
    snapshotDurable(ctx.scenario.durable, ctx.operationId).partials > 1,
  SUBMIT_OR_DELIVER_NEW_CODE: (ctx) =>
    ctx.scenario.runtime.log.deliveriesServed.some(
      (served) =>
        served.transferCodeText !== ctx.before.codeText ||
        served.transferCodeSha256 !== ctx.before.codeSha,
    ),
  INFER_NON_LANDING_OR_RETRY: (ctx) => {
    const { log } = ctx.scenario.runtime;
    if (!proofPresent(ctx) && (log.leaseReleases > 0 || log.terminalizations.length > 0)) {
      return true;
    }
    return (
      ctx.classification === "PARTIAL_DELIVERED_HEAD_ANOMALOUS" &&
      (log.signerCalls.length > 0 || committedInserts(ctx) > 0)
    );
  },
  REFRESH_EXPIRY_UNDER_OLD_APPROVAL: (ctx) => {
    const { durable } = ctx.scenario;
    const refreshedIntent = durable.signIntents.some(
      (row) =>
        row["approval_id"] === ctx.before.approvalId &&
        expiryFromPersistedPreimage(row) !== ctx.before.t2,
    );
    const refreshedPartial = durable.partials.some(
      (row) =>
        row["approval_id"] === ctx.before.approvalId &&
        stringField(row, "transfer_code_sha256") !== ctx.before.codeSha,
    );
    const expiredServedVariant =
      ctx.before.t2 !== undefined &&
      isPastRedemptionExpiry(ctx.nowSecs, ctx.before.t2) &&
      ctx.scenario.runtime.log.deliveriesServed.some(
        (served) => served.transferCodeSha256 !== ctx.before.codeSha,
      );
    return refreshedIntent || refreshedPartial || expiredServedVariant;
  },
};
