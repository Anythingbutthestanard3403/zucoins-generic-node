import {
  AUTOMATIC_SINK_CONJUNCTS,
  DESTINATION_STATES,
  INTERNAL_CUSTODY_CONJUNCTS,
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
  WORKER_SINK_CONJUNCTS,
  type CustodyDenialReason,
} from "./predicates.contract.ts";

export interface CustodyPredicateFacts {
  readonly keyOrigin: unknown;
  readonly destinationState: unknown;
  readonly recoveryVerifiedAt: unknown;
  readonly walletState: unknown;
}

export interface PredicateDecision {
  readonly eligible: boolean;
  readonly denialReason: CustodyDenialReason | null;
}

const memberOf = (values: readonly string[], value: unknown): value is string =>
  typeof value === "string" && values.includes(value);

const internalCustodyDecision = (facts: CustodyPredicateFacts): PredicateDecision => {
  if (!memberOf(WALLET_KEY_ORIGINS, facts.keyOrigin)) {
    return { eligible: false, denialReason: "INVALID_KEY_ORIGIN" };
  }
  if (facts.keyOrigin !== INTERNAL_CUSTODY_CONJUNCTS.keyOrigin) {
    return { eligible: false, denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED" };
  }
  if (!memberOf(DESTINATION_STATES, facts.destinationState)) {
    return { eligible: false, denialReason: "INVALID_DESTINATION_STATE" };
  }
  if (facts.destinationState !== INTERNAL_CUSTODY_CONJUNCTS.destinationState) {
    return { eligible: false, denialReason: "DESTINATION_NOT_BLESSED" };
  }
  return { eligible: true, denialReason: null };
};

const hasValidRecoveryTimestamp = (value: unknown): boolean => {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value);
  if (match === null) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()) {
    return false;
  }
  if (Number(hourText) > 23 || Number(minuteText) > 59 || Number(secondText) > 59) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp);
};

export const verifyInternalCustody = (facts: CustodyPredicateFacts): PredicateDecision =>
  internalCustodyDecision(facts);

export const verifyAutomaticSinkEligibility = (
  facts: CustodyPredicateFacts,
): PredicateDecision => {
  const custody = internalCustodyDecision(facts);
  if (!custody.eligible) return custody;
  if (!hasValidRecoveryTimestamp(facts.recoveryVerifiedAt)) {
    return { eligible: false, denialReason: "INVALID_RECOVERY_VERIFIED_AT" };
  }
  if (!memberOf(WALLET_STATES, facts.walletState)) {
    return { eligible: false, denialReason: "INVALID_WALLET_STATE" };
  }
  if (!(AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates as readonly string[]).includes(facts.walletState)) {
    return { eligible: false, denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE" };
  }
  return { eligible: true, denialReason: null };
};

const workerSinkDecision = (facts: CustodyPredicateFacts): PredicateDecision => {
  if (!memberOf(WALLET_KEY_ORIGINS, facts.keyOrigin)) {
    return { eligible: false, denialReason: "INVALID_KEY_ORIGIN" };
  }
  if (facts.keyOrigin !== WORKER_SINK_CONJUNCTS.keyOrigin) {
    return { eligible: false, denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED" };
  }
  if (!memberOf(DESTINATION_STATES, facts.destinationState)) {
    return { eligible: false, denialReason: "INVALID_DESTINATION_STATE" };
  }
  if (facts.destinationState !== WORKER_SINK_CONJUNCTS.destinationState) {
    return { eligible: false, denialReason: "DESTINATION_NOT_WORKER" };
  }
  if (!memberOf(WALLET_STATES, facts.walletState)) {
    return { eligible: false, denialReason: "INVALID_WALLET_STATE" };
  }
  if (!(WORKER_SINK_CONJUNCTS.allowedWalletStates as readonly string[]).includes(facts.walletState)) {
    return { eligible: false, denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE" };
  }
  return { eligible: true, denialReason: null };
};

export const verifyWorkerSinkEligibility = (facts: CustodyPredicateFacts): PredicateDecision =>
  workerSinkDecision(facts);

/** Composition top-up: automatic sink (blessed + recovery) or worker sink (no recovery). */
export const verifyCompositionSinkEligibility = (
  facts: CustodyPredicateFacts,
): PredicateDecision => {
  const automatic = verifyAutomaticSinkEligibility(facts);
  if (automatic.eligible) return automatic;
  return verifyWorkerSinkEligibility(facts);
};
