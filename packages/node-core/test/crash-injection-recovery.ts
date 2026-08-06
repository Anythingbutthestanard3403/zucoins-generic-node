/**
 * Phase-by-phase crash-injection harness — the recovery procedure under test.
 *
 * Reads ONLY the durable residue (the JSON that survived the crash) plus an injected landing
 * observation, classifies the highest durable phase, and resumes the lifecycle from the one
 * correct step:
 *
 *   no attempt row                       -> resume first formation (persist inner preimage ...)
 *   inner preimage persisted, no step-1  -> re-sign the IDENTICAL persisted inner preimage
 *   step-1 signed, no step-2 preimage    -> rebuild step-2 preimage from persisted bytes
 *   step-2 preimage persisted, no step-2 -> re-sign the IDENTICAL persisted step-2 preimage
 *   fully signed, no submit claim        -> invoke the initial submit ONCE (first submission)
 *   submit claim recorded                -> NEVER submit again; reconcile by observation
 *
 * Two kinds diverge from that map. A RECEIVE_EXTERNAL residue missing the payer-signed inner
 * bytes classifies INVARIANT_BREACH rather than "resume first formation": receive has no
 * rebuild path, so absence of those bytes is never a licence to construct replacements.
 * A SEND_EXTERNAL residue is classified against the custody crash matrix
 * instead — form the partial once, then deliver or re-deliver those exact persisted bytes,
 * never re-sign, re-form, or mint a replacement — and it has no submit phase at all.
 *
 * Deterministic Ed25519 means a re-sign of the same persisted bytes yields the same
 * signature; a signer-audit record whose signature can no longer be reproduced from the
 * persisted preimage is INVARIANT_BREACH (quarantine + needs-attention), never a re-formation.
 * The one-in-flight-per-wallet rule: the source lease is held across every ambiguous recovery and released only
 * on a verified landing. The never-blind-retry rule: a durable submit claim forbids any further submit
 * call — recovery reconciles by observation, it never blind-retries.
 */
import { digestPreimage } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  crashAndRecover,
  landStep,
  recoveryStopStepFor,
  runLifecycle,
  STEP_DELIVER_PARTIAL,
  STEP_INNER_PREIMAGE,
  STEP_SIGN_STEP1,
  STEP_SIGN_STEP2,
  STEP_STEP2_PREIMAGE,
  STEP_SUBMIT,
} from "./crash-injection-lifecycle.ts";
import {
  attemptFor,
  findOperation,
  partialFor,
  type AttemptPhase,
  type DurableStore,
  type Scenario,
  type SubmitPort,
} from "./crash-injection-model.ts";

/** The external landing observation recovery reads once a submit claim is durable. A bare
 * head mismatch or silence proves neither landed nor non-landed (recovery: acknowledgement
 *  is not settlement); only a verified settled observation lands the operation. */
export type LandingObservation =
  | { readonly kind: "LANDED_VERIFIED" }
  | { readonly kind: "NOT_LANDED_YET" }
  | { readonly kind: "ANOMALOUS" };

export type RecoveryClassification =
  | "NO_ATTEMPT_RESUME_FORMATION"
  | "INNER_PERSISTED_RESIGN_STEP1"
  | "STEP1_SIGNED_BUILD_STEP2"
  | "STEP2_PERSISTED_RESIGN_STEP2"
  | "SIGNED_SUBMIT_ONCE"
  | "SUBMITTED_RECONCILE"
  // External-send formation residues (the custody crash matrix).
  | "SIGNING_CLAIMED_FORM_PARTIAL_ONCE"
  | "PARTIAL_PERSISTED_DELIVER_ONLY"
  | "PARTIAL_DELIVERED_REDELIVER_ONLY"
  | "INVARIANT_BREACH";

export interface RecoveryOutcome {
  readonly classification: RecoveryClassification;
  readonly resumedFromStep: number;
  readonly landed: boolean;
}

const markNeedsAttention = (scenario: Scenario, operationId: string, reason: string): void => {
  const operation = findOperation(scenario.durable, operationId);
  operation.needsAttention = true;
  if (operation.status !== "LANDED") {
    scenario.runtime.log.statusTransitions.push({
      operationId,
      from: operation.status,
      to: "NEEDS_ATTENTION",
    });
    operation.status = "NEEDS_ATTENTION";
  }
  scenario.runtime.log.needsAttentionMarks.push(reason);
};

/** A signer-audit record for `step` that can no longer be reproduced from the persisted
 *  preimage is an invariant breach: the stored phases/bytes cannot arise under the contract. */
const auditContradictsPersisted = (
  durable: DurableStore,
  operationId: string,
  step: 1 | 2,
  persistedPreimageText: string | null,
): boolean => {
  const audit = durable.signerAudit.find(
    (entry) => entry.operationId === operationId && entry.step === step,
  );
  if (audit === undefined) {
    return false;
  }
  if (persistedPreimageText === null) {
    return true;
  }
  return audit.preimageSha256 !== digestPreimage(persistedPreimageText);
};

const reconcileByObservation = (
  scenario: Scenario,
  operationId: string,
  observation: LandingObservation,
): boolean => {
  if (observation.kind === "LANDED_VERIFIED") {
    // The one landing implementation, terminal-guarded — reconciliation never mints a second
    // landed event or a second lease release on top of a landing that already happened.
    landStep(scenario, operationId);
    return true;
  }
  // Acknowledgement is not settlement; silence/ambiguity parks the operation and keeps the
  // lease held (the one-in-flight-per-wallet rule). Reconciliation never resubmits and never releases the lease.
  markNeedsAttention(
    scenario,
    operationId,
    observation.kind === "ANOMALOUS" ? "anomalous_head_preserve_lease" : "awaiting_settlement_observation",
  );
  return false;
};

/** Classifies the durable residue into the highest durable phase (the recovery resume point).
 *  Kind-dependent, because the three kinds do not share a formation contract: a receive
 * residue missing the payer bytes has no rebuild path and an external send has no
 * step-2 or submit phase at all. */
export const classifyResidue = (durable: DurableStore, operationId: string): RecoveryClassification => {
  const kind = findOperation(durable, operationId).kind;
  const attempt = attemptFor(durable, operationId);
  if (attempt === undefined) {
    // Receive has no rebuild path: the node cannot reconstruct payer-signed inbound bytes, so
    // their absence is an invariant breach, never a licence to form a replacement.
    return kind === "RECEIVE_EXTERNAL" ? "INVARIANT_BREACH" : "NO_ATTEMPT_RESUME_FORMATION";
  }
  if (attempt.innerPreimageText === null || attempt.innerSha256 === null) {
    return "INVARIANT_BREACH";
  }
  if (attempt.step1Signature === null) {
    if (kind === "RECEIVE_EXTERNAL") {
      return "INVARIANT_BREACH";
    }
    return auditContradictsPersisted(durable, operationId, 1, attempt.innerPreimageText)
      ? "INVARIANT_BREACH"
      : "INNER_PERSISTED_RESIGN_STEP1";
  }
  if (kind === "SEND_EXTERNAL") {
    return classifySendResidue(durable, operationId);
  }
  if (attempt.step2PreimageText === null || attempt.step2PreimageSha256 === null) {
    return "STEP1_SIGNED_BUILD_STEP2";
  }
  if (attempt.step2Signature === null || attempt.completedTransactionText === null) {
    return auditContradictsPersisted(durable, operationId, 2, attempt.step2PreimageText)
      ? "INVARIANT_BREACH"
      : "STEP2_PERSISTED_RESIGN_STEP2";
  }
  if (!attempt.submitClaimed) {
    return "SIGNED_SUBMIT_ONCE";
  }
  return "SUBMITTED_RECONCILE";
};

/** The custody external-send crash matrix. Every row resumes at the same delivery step; the
 *  step is mint-idempotent, so none of them can produce a replacement partial. */
const classifySendResidue = (
  durable: DurableStore,
  operationId: string,
): RecoveryClassification => {
  const partial = partialFor(durable, operationId);
  if (partial === undefined) {
    return "SIGNING_CLAIMED_FORM_PARTIAL_ONCE";
  }
  return partial.deliveries === 0
    ? "PARTIAL_PERSISTED_DELIVER_ONLY"
    : "PARTIAL_DELIVERED_REDELIVER_ONLY";
};

/** The recovery pass under test. `observation` is the post-crash landing evidence. Landing is
 *  ALWAYS gated by a verified settlement observation — the submit acknowledgement is not
 * settlement — so every non-breach path reconciles landing by observation. */
export const recoverOperation = (
  scenario: Scenario,
  submitPort: SubmitPort,
  observation: LandingObservation,
): RecoveryOutcome => {
  const { durable } = scenario;
  const operation = durable.operations[0];
  if (operation === undefined) {
    throw new Error("crash-injection recovery: no operation row survived the crash");
  }
  const operationId = operation.operationId;
  const classification = classifyResidue(durable, operationId);

  if (classification === "INVARIANT_BREACH") {
    markNeedsAttention(scenario, operationId, "stored_phases_cannot_arise_under_contract");
    return { classification, resumedFromStep: -1, landed: false };
  }

  if (classification === "SUBMITTED_RECONCILE") {
    // Submit claim is durable: never submit again (the never-blind-retry rule). Reconcile by observation.
    const landed = reconcileByObservation(scenario, operationId, observation);
    return { classification, resumedFromStep: STEP_SUBMIT + 1, landed };
  }

  // Pre-submit residue: resume first formation/signing and the single initial submit, stopping
  // short of LAND (or at DELIVER_PARTIAL for an external send — which never reaches a submit
  // port). Landing is decided below by observation alone, never by acknowledgement.
  const resumedFromStep = RESUME_STEP[classification];
  runLifecycle(scenario, submitPort, resumedFromStep, recoveryStopStepFor(operation.kind));
  const landed = reconcileByObservation(scenario, operationId, observation);
  return { classification, resumedFromStep, landed };
};

const RESUME_STEP: Record<
  Exclude<RecoveryClassification, "INVARIANT_BREACH" | "SUBMITTED_RECONCILE">,
  number
> = {
  NO_ATTEMPT_RESUME_FORMATION: STEP_INNER_PREIMAGE,
  INNER_PERSISTED_RESIGN_STEP1: STEP_SIGN_STEP1,
  STEP1_SIGNED_BUILD_STEP2: STEP_STEP2_PREIMAGE,
  STEP2_PERSISTED_RESIGN_STEP2: STEP_SIGN_STEP2,
  SIGNED_SUBMIT_ONCE: STEP_SUBMIT,
  SIGNING_CLAIMED_FORM_PARTIAL_ONCE: STEP_DELIVER_PARTIAL,
  PARTIAL_PERSISTED_DELIVER_ONLY: STEP_DELIVER_PARTIAL,
  PARTIAL_DELIVERED_REDELIVER_ONLY: STEP_DELIVER_PARTIAL,
};

/** Convenience: crash the scenario at a phase boundary, then run one recovery pass over the
 *  surviving durable store. Returns the recovered scenario plus the recovery outcome. */
export const crashThenRecover = (
  crashed: Scenario,
  submitPort: SubmitPort,
  observation: LandingObservation,
): { scenario: Scenario; outcome: RecoveryOutcome } => {
  const recovered = crashAndRecover(crashed);
  const outcome = recoverOperation(recovered, submitPort, observation);
  return { scenario: recovered, outcome };
};

/** The durable residue a corruption test compares across a crash. EVERY persisted byte column
 *  is exposed — an omitted column is a byte the no-corruption matrix cannot see, which is how
 *  a divergent step-2 re-sign once passed unnoticed. Adding a byte column to AttemptRow or
 *  ExternalPartialRow means adding it here, or the assertion aperture silently narrows. */
export const snapshotDurable = (
  durable: DurableStore,
): {
  operations: number;
  attempts: number;
  signerAudit: number;
  events: number;
  attemptPhase?: AttemptPhase;
  innerPreimageText?: string;
  innerSha256?: string;
  step1Signature?: string;
  step2PreimageText?: string;
  step2PreimageSha256?: string;
  step2Signature?: string;
  completedTransactionText?: string;
  completedTransactionSha256?: string;
  partials: number;
  partialCode?: string;
  partialCodeSha256?: string;
  partialDeliveries: number;
  submitClaimed: boolean;
  leaseHeld: boolean;
  terminal: boolean;
  needsAttention: boolean;
} => {
  const attempt = durable.attempts[0];
  const operation = durable.operations[0];
  const partial = durable.externalPartials[0];
  return {
    operations: durable.operations.length,
    attempts: durable.attempts.length,
    signerAudit: durable.signerAudit.length,
    events: durable.events.length,
    attemptPhase: attempt?.attemptPhase,
    innerPreimageText: attempt?.innerPreimageText ?? undefined,
    innerSha256: attempt?.innerSha256 ?? undefined,
    step1Signature: attempt?.step1Signature ?? undefined,
    step2PreimageText: attempt?.step2PreimageText ?? undefined,
    step2PreimageSha256: attempt?.step2PreimageSha256 ?? undefined,
    step2Signature: attempt?.step2Signature ?? undefined,
    completedTransactionText: attempt?.completedTransactionText ?? undefined,
    completedTransactionSha256: attempt?.completedTransactionSha256 ?? undefined,
    partials: durable.externalPartials.length,
    partialCode: partial?.code,
    partialCodeSha256: partial?.codeSha256,
    partialDeliveries: partial?.deliveries ?? 0,
    submitClaimed: attempt?.submitClaimed ?? false,
    leaseHeld: operation?.leaseHeld ?? false,
    terminal: operation?.terminal ?? false,
    needsAttention: operation?.needsAttention ?? false,
  };
};
