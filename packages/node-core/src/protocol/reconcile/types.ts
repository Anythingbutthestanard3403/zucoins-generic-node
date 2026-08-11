// the closed reconcile-outcome vocabulary shared across all three of the
// launch node's public operation kinds (that closed trio is not repeated here, to avoid a
// text-pattern collision with the operations.drift-gate.test.ts anti-self-reference scan in
// generic-node-contracts, which this module deliberately does not re-trigger).
//
// These five names and their automatic effects are the recovery classifications; the
// per-operation recovery tables and the landing-path oracle (canonical, overrides all)
// govern their use.
//
// This is the ENTIRE closed set: no boolean `isLanded` flag stands in for it anywhere in this
// module family, and there is no sixth "definitively not landed" member — landing-path oracle is explicit:
// "There is no generic PROVEN_NOT_LANDED verdict."

import {
  type ObservationAnomalyKind,
  type ClassifierOutputRelationship,
} from "@zucoins/generic-node-contracts/observation";
import {
  type AttentionReason,
} from "@zucoins/generic-node-contracts/operations/events";

import { type LandingProofFault } from "./landing-proof.js";

export const RECONCILE_CLASSIFICATION_KINDS = [
  "LANDED_VERIFIED",
  "PROVEN_NOT_STARTED",
  "WAITING",
  "INDETERMINATE",
  "INVARIANT_BREACH",
] as const;
export type ReconcileClassificationKind = (typeof RECONCILE_CLASSIFICATION_KINDS)[number];

// Observation-relationship values that fold into INDETERMINATE per
// ("Park affected operations"/"Park for attention" — no landing,
// no non-landing, no retry/rebuild/resubmit, no release authority). Excludes the three
// relationships that instead escalate to INVARIANT_BREACH (see below).
export type IndeterminateObservationAnomaly = Extract<
  ObservationAnomalyKind,
  | "TRANSPORT_ERROR"
  | "MALFORMED_ENVELOPE"
  | "MALFORMED_TRANSACTION"
  | "UNVERIFIED_SIGNATURE"
  | "WALLET_ROLE_INVALID"
  | "UNEXPLAINED_JUMP"
>;

// REGRESSION, GENESIS_AFTER_HISTORY, and SIGNATURE_COLLISION
// each "stop money engines"/"quarantine wallet"/"escalate as a protocol/security incident" —
// the INVARIANT_BREACH automatic effect, not a park-and-retain INDETERMINATE effect.
export type InvariantBreachObservationAnomaly = Extract<
  ObservationAnomalyKind,
  "REGRESSION" | "GENESIS_AFTER_HISTORY" | "SIGNATURE_COLLISION"
>;

// Confirms the two subsets above partition ObservationAnomalyKind with no member dropped or
// duplicated (a compile-time exhaustiveness proof, checked in types.test.ts by round-tripping
// through this union).
export type ReconcilableObservationAnomaly =
  | IndeterminateObservationAnomaly
  | InvariantBreachObservationAnomaly;

// Re-exported so callers of this concern do not need a second import from
// generic-node-contracts merely to read the relationship a decision was made from.
export type { ClassifierOutputRelationship };

// Why a reconcile computation reached INDETERMINATE. Every member cites the exact spec clause
// it models; none of them authorizes retry/rebuild/resubmit/release (09-operations-recovery.md
// The INDETERMINATE row: "no retry/rebuild/resubmit, release/reuse, or non-landing
// conclusion").
export type ReconcileIndeterminateReason =
  // landing-path oracle: the any-depth complete-path proof did not complete.
  | { readonly source: "LANDING_PROOF_INCOMPLETE"; readonly fault: LandingProofFault }
  // An observation anomaly that parks rather than breaches.
  | { readonly source: "OBSERVATION_ANOMALY"; readonly anomaly: IndeterminateObservationAnomaly }
  // Last row: "One wallet appears landed and the other cannot
  // connect to the same transaction" (MOVE_INTERNAL only, but the shape is generic).
  | { readonly source: "PATH_DISAGREEMENT" }
  // reconcile-outcome.ts precedent: the one authorized fresh
  // re-submit/next-call attempt was itself indeterminate (network error / timeout / unreadable
  // envelope). Never triggers a second call from here — that would be the loop the never-blind-retry rule
  // forbids.
  | { readonly source: "SUBMIT_OUTCOME_UNKNOWN" }
  // A release, landing, or complete-path
  // predicate did not fully pass; the named predicate is the exact clause that failed.
  | { readonly source: "RELEASE_PREDICATE_UNSATISFIED"; readonly predicate: string }
  // The server-authenticated proof-body intake surface
  // rejected or closed an in-progress evidence submission.
  | { readonly source: "PROOF_INTAKE_REJECTED" }
  // Row "verified unchanged predecessor | not a generic
  // non-landing verdict | no [retry authority]": a fresh bounded read found no successor at
  // all — no landing proof, no anomaly, no contradiction. landing-path oracle: "unchanged head alone is
  // insufficient" to conclude anything; this is the ONLY indeterminate reason send.ts may
  // fold into WAITING instead of leaving as INDETERMINATE — every other reason here
  // is a positive fault/anomaly/contradiction and stays INDETERMINATE for every operation
  // kind, including send.
  | { readonly source: "NO_SUCCESSOR_OBSERVED" }
  // Gateway response failed structural validation — not interpretable as evidence (ZTR-1147).
  | { readonly source: "GATEWAY_RESPONSE_INVALID" }
  // Consecutive gateway reads exhausted GATEWAY_READ_FAILURE_BUDGET (ZTR-1147).
  | { readonly source: "GATEWAY_UNAVAILABLE_BEYOND_BUDGET" }
  // Operator deliberately parked the operation pending investigation (ZTR-1147).
  | { readonly source: "OPERATOR_PARKED" };

// Why a reconcile computation reached INVARIANT_BREACH:
// "Stored phases/bytes/leases cannot arise under the contract" — automatic effect: "Stop money
// engines, quarantine affected wallets, page operator."
export type ReconcileInvariantBreachReason =
  | { readonly source: "OBSERVATION_ANOMALY"; readonly anomaly: InvariantBreachObservationAnomaly }
  // landing-path oracle: "An unknown or unattributed deep
  // successor while the wallet remains actively leased is an invariant/custody breach."
  | { readonly source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" }
  // Last row: "Any expected exact byte record is missing while a
  // signer audit indicates use."
  | { readonly source: "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT" }
  // "the database says sign intent is absent but signer audit
  // indicates a call, or any expected exact preimage is unavailable."
  | { readonly source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" }
  // Every reconcile call presupposes the relevant wallet lease is
  // ACTIVE — reconcile evidence observed while a lease has already been RELEASED contradicts
  // that invariant outright (the lease-axis cell 06-operation-flows.md/09-operations-recovery.md
  // never populate because it cannot arise under the guarded release sequence).
  | { readonly source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" }
  // Destination retired / un-blessed mid-operation (ZTR-1147).
  | { readonly source: "DESTINATION_NO_LONGER_BLESSED" };

// The closed `attention_reason` vocabulary (imported, never retyped) is the
// operational diagnostic apps/node persists; this maps every reconcile-specific reason above
// onto it.
export function toAttentionReason(
  reason: ReconcileIndeterminateReason | ReconcileInvariantBreachReason,
): AttentionReason {
  switch (reason.source) {
    case "LANDING_PROOF_INCOMPLETE":
      switch (reason.fault) {
        case "MISSING_BODY":
        case "GAP":
          return "LINEAGE_GAP";
        case "CONFLICT":
        case "DUPLICATE":
        case "CYCLE":
        case "ANOMALOUS_OR_CONTRADICTORY":
          return "VERIFICATION_INDETERMINATE";
        case "MALFORMED_BODY":
          return "EXACT_BYTES_UNAVAILABLE";
        case "BUDGET_EXHAUSTED":
          return "VERIFICATION_RESOURCE_EXHAUSTED";
        default:
          return assertUnreachable(reason.fault);
      }
    case "OBSERVATION_ANOMALY":
      return reason.anomaly === "REGRESSION" ||
        reason.anomaly === "GENESIS_AFTER_HISTORY" ||
        reason.anomaly === "SIGNATURE_COLLISION"
        ? "LEASE_INVARIANT_VIOLATION"
        : "UNEXPECTED_HEAD_CHANGE";
    case "PATH_DISAGREEMENT":
      return "VERIFICATION_INDETERMINATE";
    case "SUBMIT_OUTCOME_UNKNOWN":
      return "SUBMIT_OUTCOME_AMBIGUOUS";
    case "RELEASE_PREDICATE_UNSATISFIED":
      return "T0_RELEASE_MISMATCH";
    case "PROOF_INTAKE_REJECTED":
      return "VERIFICATION_REJECTED";
    case "NO_SUCCESSOR_OBSERVED":
      return "UNEXPECTED_HEAD_CHANGE";
    case "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE":
      return "LEASE_INVARIANT_VIOLATION";
    case "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT":
      return "EXACT_BYTES_UNAVAILABLE";
    case "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD":
      return "SIGNING_OUTCOME_AMBIGUOUS";
    case "LEASE_NOT_ACTIVE_DURING_RECONCILE":
      return "LEASE_INVARIANT_VIOLATION";
    case "GATEWAY_RESPONSE_INVALID":
      return "GATEWAY_RESPONSE_INVALID";
    case "GATEWAY_UNAVAILABLE_BEYOND_BUDGET":
      return "GATEWAY_UNAVAILABLE_BEYOND_BUDGET";
    case "OPERATOR_PARKED":
      return "OPERATOR_PARKED";
    case "DESTINATION_NO_LONGER_BLESSED":
      return "DESTINATION_NO_LONGER_BLESSED";
    default:
      return assertUnreachable(reason);
  }
}

// Exhaustiveness helper. A `default: assertUnreachable(x)` branch on a value TypeScript has
// already narrowed to `never` is a compile error if a union member is later added and this
// call site is not updated — the standard closed-union completeness check used throughout
// this concern's decision functions.
export function assertUnreachable(value: never): never {
  throw new Error(`unreachable reconcile classification member: ${JSON.stringify(value)}`);
}
