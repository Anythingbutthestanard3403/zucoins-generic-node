// Read-time derivation of the public `execution_phase`.
//
// `operation_transactions.attempt_phase` is internal persistence state and is NOT the public
// `execution_phase`. The public value is derived from durable facts in precedence sequence:
// it is a coarse public diagnostic over the durable transaction, sign-intent, partial,
// submit, response, and terminal-evidence subrecords. It is not a stored `operations`
// column and never substitutes for `state`.
//
// This module is a pure function over facts. It holds no state, writes nothing, and there is
// deliberately no `execution_phase` column anywhere in src/schema — the mapping is
// derived at read time or by a tested database view; it is never an independently mutable
// status column. The tested-query half of that sentence is readTransactionMaterialFacts in
// ./transaction-material-store.ts; this is the mapping it feeds.
//
// It also does NOT copy `attempt_phase`: the five internal persistence phases stay exact
// to their transaction record, and the public phase applies the operation-kind predicate
// below. TRANSACTION_MATERIAL_PHASE_VOCABULARY freezes that the two vocabularies are distinct
// and that neither derives from the other.

import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";

/**
 * The internal persistence ladder, in ladder sequence. Never a public value.
 *
 * Declared here rather than imported from ../schema/transaction-material.contract.js: the
 * node-core dependency fence (ALLOWED_INTERNAL_IMPORTS in test/boundaries.test.ts) makes
 * `schema` a leaf that no `core` file may import, the same reason src/signing-keys declares
 * its own SqlExecutor port instead of importing one. Divergence from the frozen inventory is
 * still caught, by test/execution-phase.test.ts asserting this equal to
 * TRANSACTION_MATERIAL_PHASE_VOCABULARY.attemptPhaseLiterals — that test lives outside src/
 * and so may read the contract directly.
 */
export const ATTEMPT_PHASE_LADDER = [
  "INNER_PREIMAGE_PERSISTED",
  "STEP1_SIGNATURE_PERSISTED",
  "STEP2_PREIMAGE_PERSISTED",
  "STEP2_SIGNATURE_PERSISTED",
  "SETTLED_BODY_PERSISTED",
] as const;

export type AttemptPhase = (typeof ATTEMPT_PHASE_LADDER)[number];

/**
 * The public phases in advance sequence. A phase can only advance, except that a positively
 * proven non-landed move archives the entire attempt and begins a new attempt at
 * `NOT_STARTED`.
 */
export const EXECUTION_PHASES = [
  "NOT_STARTED",
  "PREIMAGE_PERSISTED",
  "SIGNED_PERSISTED",
  "DELIVERED",
  "SUBMIT_STARTED",
  "SUBMIT_RETURNED",
  "LANDED_VERIFIED",
] as const;

export type ExecutionPhase = (typeof EXECUTION_PHASES)[number];

/**
 * The derivation table sequence, which is PRECEDENCE sequence — the reverse of advance sequence.
 * deriveExecutionPhase evaluates exactly this sequence and returns the first phase whose
 * required durable fact holds, so a landed operation never reports a formation phase merely
 * because the formation fact is also still true.
 */
export const EXECUTION_PHASE_PRECEDENCE = [
  "LANDED_VERIFIED",
  "SUBMIT_RETURNED",
  "SUBMIT_STARTED",
  "DELIVERED",
  "SIGNED_PERSISTED",
  "PREIMAGE_PERSISTED",
  "NOT_STARTED",
] as const;

/**
 * The "applies to" column of the phase table, resolved to frozen OperationKind values. A phase
 * outside its kind's set is not a reportable value: `DELIVERED` is send-only because only an
 * external send persists a partial, and the submit phases exclude send because node code may
 * never create a submit attempt for `SEND_EXTERNAL`. deriveExecutionPhase throws
 * rather than return an inapplicable phase — publishing one would mask exactly that defect.
 */
export const EXECUTION_PHASE_APPLIES_TO: Readonly<
  Record<ExecutionPhase, readonly OperationKind[]>
> = {
  NOT_STARTED: OPERATION_KINDS,
  PREIMAGE_PERSISTED: OPERATION_KINDS,
  SIGNED_PERSISTED: OPERATION_KINDS,
  DELIVERED: ["SEND_EXTERNAL"],
  SUBMIT_STARTED: ["RECEIVE_EXTERNAL", "MOVE_INTERNAL"],
  SUBMIT_RETURNED: ["RECEIVE_EXTERNAL", "MOVE_INTERNAL"],
  LANDED_VERIFIED: OPERATION_KINDS,
} as const;

/**
 * The subrecord facts, as read back from the three tables this slice owns
 * (`external_send_sign_intents`, `operation_transactions`, `external_send_partials`).
 */
export interface TransactionMaterialFacts {
  /** `operation_transactions.attempt_phase` for the one attempt, or null when no attempt row exists. */
  readonly attemptPhase: AttemptPhase | null;
  /** An `external_send_sign_intents` row is durable (SEND_EXTERNAL only). */
  readonly signIntentPersisted: boolean;
  /** An `external_send_partials` row is durable (SEND_EXTERNAL only). */
  readonly partialPersisted: boolean;
  /** `external_send_partials.first_delivered_at IS NOT NULL`. */
  readonly partialFirstDelivered: boolean;
}

/**
 * The out-of-slice subrecord facts the derivation table also reads. Submit attempts and
 * operation verifications are owned by other schema slices, so they cross this seam as
 * booleans the caller resolves from the tables it owns — this module never queries them.
 */
export interface SubmitAndVerificationFacts {
  /** The one submit-attempt claim has `started_at`. */
  readonly submitStarted: boolean;
  /** The one submit attempt has `completed_at` and a captured outcome. */
  readonly submitReturned: boolean;
  /** An accepted operation verification exists. */
  readonly verificationAccepted: boolean;
  /** The required terminal observation references are present. */
  readonly terminalObservationsPresent: boolean;
}

export interface DurableExecutionFacts
  extends TransactionMaterialFacts,
    SubmitAndVerificationFacts {
  readonly operationKind: OperationKind;
}

const ladderIndex = (phase: AttemptPhase): number => ATTEMPT_PHASE_LADDER.indexOf(phase);

const atOrAfter = (phase: AttemptPhase | null, floor: AttemptPhase): boolean =>
  phase !== null && ladderIndex(phase) >= ladderIndex(floor);

/**
 * SIGNED_PERSISTED rule: RECEIVE is at `STEP2_SIGNATURE_PERSISTED` or later;
 * MOVE is at `STEP1_SIGNATURE_PERSISTED` or later, including `STEP2_PREIMAGE_PERSISTED` and
 * `STEP2_SIGNATURE_PERSISTED`; SEND has its external partial/node step-1 signature durable.
 *
 * The kinds differ because the NODE-produced signature differs ("The
 * node-produced signature corresponding to the persisted next-signing preimage ... are
 * durable"). For a receive the node signs step 2, so a durable step-1 signature is the PAYER's
 * and is not yet a node signature; for a move and a send the node signs step 1.
 */
const isSignedPersisted = (facts: DurableExecutionFacts): boolean => {
  switch (facts.operationKind) {
    case "RECEIVE_EXTERNAL":
      return atOrAfter(facts.attemptPhase, "STEP2_SIGNATURE_PERSISTED");
    case "MOVE_INTERNAL":
      return atOrAfter(facts.attemptPhase, "STEP1_SIGNATURE_PERSISTED");
    case "SEND_EXTERNAL":
      return facts.partialPersisted || atOrAfter(facts.attemptPhase, "STEP1_SIGNATURE_PERSISTED");
  }
};

/**
 * PREIMAGE_PERSISTED rule: RECEIVE is at `STEP2_PREIMAGE_PERSISTED` with the payer step 1
 * durable and node step 2 NULL; MOVE is at `INNER_PREIMAGE_PERSISTED` with node step 1 NULL;
 * SEND has the sign intent durable and no external partial/node step-1 signature.
 *
 * The "node signature NULL" halves need no separate test: the frozen phase CHECKs make
 * `step_1_signature IS NULL` exactly at `INNER_PREIMAGE_PERSISTED` and `step_2_signature IS
 * NULL` in the first three phases, so the phase equality already carries them.
 *
 * A receive at `STEP1_SIGNATURE_PERSISTED` therefore derives NOT_STARTED, not
 * PREIMAGE_PERSISTED: a receive attempt may be inserted there with the payer's
 * step-1 signature already durable, but the node's own next-signing preimage — the exact step-2
 * preimage — is not persisted yet, so no row of the table applies.
 */
const isPreimagePersisted = (facts: DurableExecutionFacts): boolean => {
  switch (facts.operationKind) {
    case "RECEIVE_EXTERNAL":
      return facts.attemptPhase === "STEP2_PREIMAGE_PERSISTED";
    case "MOVE_INTERNAL":
      return facts.attemptPhase === "INNER_PREIMAGE_PERSISTED";
    case "SEND_EXTERNAL":
      return (
        facts.signIntentPersisted &&
        !facts.partialPersisted &&
        !atOrAfter(facts.attemptPhase, "STEP1_SIGNATURE_PERSISTED")
      );
  }
};

/**
 * Rejects fact tuples the phase tables make unrepresentable. Each is a durable-state
 * defect somewhere upstream, and each would otherwise be laundered into a plausible-looking
 * public phase:
 *
 * * a submit fact on a SEND_EXTERNAL contradicts the frozen rule that node code cannot create
 * any submit attempt for `SEND_EXTERNAL` — the exact condition that test exists to catch;
 * * a partial on a non-send contradicts `external_send_partials` being the external-send
 * partial store (one partial per external send);
 * * `partialFirstDelivered` without `partialPersisted` contradicts the rule that delivery is
 * forbidden until the partial row commits;
 * * `submitReturned` without `submitStarted` contradicts the derivation precedence, where a
 * returned submit is a started submit that also has `completed_at`.
 *
 * Failing closed here keeps a read path from reporting progress the durable record does not
 * support. It never releases a lease, retries, or mutates anything.
 */
const assertRepresentable = (facts: DurableExecutionFacts): void => {
  const reject = (reason: string): never => {
    throw new Error(
      `execution_phase is not derivable for ${facts.operationKind}: ${reason}`,
    );
  };
  if (facts.operationKind === "SEND_EXTERNAL" && (facts.submitStarted || facts.submitReturned)) {
    reject("a submit attempt exists for an external send, which the frozen rules forbid");
  }
  if (
    facts.operationKind !== "SEND_EXTERNAL" &&
    (facts.signIntentPersisted || facts.partialPersisted || facts.partialFirstDelivered)
  ) {
    reject("sign-intent or partial material exists outside an external send");
  }
  if (facts.partialFirstDelivered && !facts.partialPersisted) {
    reject("the partial was delivered before its row committed");
  }
  if (facts.submitReturned && !facts.submitStarted) {
    reject("a submit returned that never started");
  }
};

/**
 * Derives the public `execution_phase` from durable facts, in precedence sequence. Pure:
 * the same facts always derive the same phase, and nothing is written.
 */
export function deriveExecutionPhase(facts: DurableExecutionFacts): ExecutionPhase {
  assertRepresentable(facts);

  if (facts.verificationAccepted && facts.terminalObservationsPresent) return "LANDED_VERIFIED";
  if (facts.submitReturned) return "SUBMIT_RETURNED";
  if (facts.submitStarted) return "SUBMIT_STARTED";
  if (facts.partialFirstDelivered) return "DELIVERED";
  if (isSignedPersisted(facts)) return "SIGNED_PERSISTED";
  if (isPreimagePersisted(facts)) return "PREIMAGE_PERSISTED";
  return "NOT_STARTED";
}
