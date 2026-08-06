// MOVE_INTERNAL reconcile outcomes.
// ("Internal-move
//
// MOVE_INTERNAL has no WAITING member (no external partial exists — the node holds both keys
// and completes the whole transaction itself) and, most importantly, NO REBUILD/SECOND-ATTEMPT
// MEMBER AT ALL: / are explicit — "Launch has one immutable transaction attempt for a
// move and no generic PROVEN_NOT_LANDED oracle... never creates attempt 2 or licenses another
// call after a submit claim began." This union has exactly one attempt identifier per outcome
// and zero fields that could carry a second attempt; see move.matrix.test.ts for the
// unrepresentability proof this guards, including a citation of a contradicting transition
// already present in the merged operations/states.contract.ts that this module deliberately
// does not import or reuse.

import {
  type LeaseLifecycleState,
} from "@zucoins/generic-node-contracts/wallet-state";

import { type LandingPathProof } from "./landing-proof.js";
import { type PathObservation, classifyPathObservation } from "./observation-input.js";
import {
  type ReconcileIndeterminateReason,
  type ReconcileInvariantBreachReason,
} from "./types.js";

export type MoveNeverCrossedBoundary = "SIGNER" | "SUBMITTER";
export type MoveResumeAction = "FIRST_FORMATION" | "SIGN_PERSISTED_PREIMAGE" | "SUBMIT_ONCE";

export type MoveReconcileOutcome =
  | {
      readonly kind: "LANDED_VERIFIED";
      readonly moveAttemptId: string;
      readonly sourcePath: LandingPathProof;
      readonly destinationPath: LandingPathProof;
    }
  | {
      readonly kind: "PROVEN_NOT_STARTED";
      readonly moveAttemptId: string;
      readonly neverCrossedBoundary: MoveNeverCrossedBoundary;
      readonly resumeAction: MoveResumeAction;
    }
  | {
      readonly kind: "INDETERMINATE";
      readonly moveAttemptId: string;
      readonly reason: ReconcileIndeterminateReason;
    }
  | {
      readonly kind: "INVARIANT_BREACH";
      readonly affectedWalletIds: readonly string[];
      readonly reason: ReconcileInvariantBreachReason;
    };

// Rows 2-4: durable evidence BEFORE any submit claim exists. The precondition "both
// leases held" is not a field here — row 1 ("one of two required wallet leases missing
// before T0 | Acquire both atomically or remain CREATED; do not read/sign") is pure admission
// logic with no chain read or sign, so it is out of this reconcile concern's input space by
// construction, not merely by a runtime check.
export interface MoveFormationEvidence {
  readonly boundary: "PRE_SUBMIT";
  readonly moveAttemptId: string;
  readonly preimagePersisted: boolean;
  readonly signaturesComplete: boolean;
  readonly signerAuditIndicatesCall: boolean;
}

// Last two rows collapse to observation-driven reconciliation once a submit call may have
// occurred; requires independently complete SOURCE and DESTINATION paths anchored to the
// same exact move body. `expectedMoveBodySha256` is the one persisted move attempt's body hash
// both paths must anchor to (point 3: "both body-0 values must byte-equal the one
// persisted move transaction").
export interface MoveObservationEvidence {
  readonly boundary: "POST_SUBMIT";
  readonly moveAttemptId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly expectedMoveBodySha256: string;
  // Both wallets' active leases are the safe-release precondition — every
  // POST_SUBMIT reconcile call presupposes both are still ACTIVE (lease-axis evidence, imported
  // from the frozen wallet-state concern, never retyped).
  readonly sourceLeaseState: LeaseLifecycleState;
  readonly destinationLeaseState: LeaseLifecycleState;
  readonly sourceObservation: PathObservation;
  readonly destinationObservation: PathObservation;
}

export type MoveReconcileInput = MoveFormationEvidence | MoveObservationEvidence;

export function classifyMoveReconcile(input: MoveReconcileInput): MoveReconcileOutcome {
  if (input.boundary === "PRE_SUBMIT") {
    const { moveAttemptId, preimagePersisted, signaturesComplete, signerAuditIndicatesCall } = input;

    if (!preimagePersisted) {
      if (signerAuditIndicatesCall) {
        return {
          kind: "INVARIANT_BREACH",
          affectedWalletIds: [],
          reason: { source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" },
        };
      }
      // Row 2: "Both leases, no preimage/sign audit | PROVEN_NOT_STARTED: perform first
      // formation."
      return {
        kind: "PROVEN_NOT_STARTED",
        moveAttemptId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "FIRST_FORMATION",
      };
    }

    if (!signaturesComplete) {
      if (signerAuditIndicatesCall) {
        return {
          kind: "INVARIANT_BREACH",
          affectedWalletIds: [],
          reason: { source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" },
        };
      }
      // Row 3: "Exact preimage persisted, signature missing | Re-sign only that exact
      // preimage under both current lease capabilities."
      return {
        kind: "PROVEN_NOT_STARTED",
        moveAttemptId,
        neverCrossedBoundary: "SIGNER",
        resumeAction: "SIGN_PERSISTED_PREIMAGE",
      };
    }

    // Row 4: "Full exact transaction persisted, no submit claim/call | Submit that exact
    // attempt once." Reachable only because `boundary` is PRE_SUBMIT — the caller has already
    // durably confirmed no submit claim exists for this attempt, so this is the FIRST call, not
    // a retry ("PROVEN_NOT_STARTED may authorize the first call only when the submit
    // boundary was durably never crossed").
    return {
      kind: "PROVEN_NOT_STARTED",
      moveAttemptId,
      neverCrossedBoundary: "SUBMITTER",
      resumeAction: "SUBMIT_ONCE",
    };
  }

  const {
    moveAttemptId,
    sourceWalletId,
    destinationWalletId,
    sourceLeaseState,
    destinationLeaseState,
    sourceObservation,
    destinationObservation,
  } = input;

  // Lease axis, checked first and decisively: reconciling either wallet while its lease has
  // already been RELEASED contradicts the lease-release precondition outright.
  if (sourceLeaseState !== "ACTIVE" || destinationLeaseState !== "ACTIVE") {
    // Accumulated by push rather than conditional array spread: the construction-safety
    // gate bans spread syntax across src/protocol/, and this quarantine list has no need of it.
    // Source is appended before destination, exactly as in the spread form it replaces.
    const affectedWalletIds: string[] = [];
    if (sourceLeaseState !== "ACTIVE") affectedWalletIds.push(sourceWalletId);
    if (destinationLeaseState !== "ACTIVE") affectedWalletIds.push(destinationWalletId);
    return {
      kind: "INVARIANT_BREACH",
      affectedWalletIds,
      reason: { source: "LEASE_NOT_ACTIVE_DURING_RECONCILE" },
    };
  }

  const source = classifyPathObservation(sourceObservation);
  const destination = classifyPathObservation(destinationObservation);

  // Either wallet in breach is decisive regardless of the other's tier: an
  // unattributed successor or an anomaly requiring quarantine stops that wallet's money paths
  // outright. Checked as two separate narrowed branches (rather than one combined boolean) so
  // each branch's `reason` comes from that branch's own already-narrowed classification.
  if (source.tier === "INVARIANT_BREACH") {
    const affectedWalletIds =
      destination.tier === "INVARIANT_BREACH" ? [sourceWalletId, destinationWalletId] : [sourceWalletId];
    return { kind: "INVARIANT_BREACH", affectedWalletIds, reason: source.reason };
  }
  if (destination.tier === "INVARIANT_BREACH") {
    return { kind: "INVARIANT_BREACH", affectedWalletIds: [destinationWalletId], reason: destination.reason };
  }

  if (source.tier === "LANDED" && destination.tier === "LANDED") {
    // Point 3: both body-0 values must byte-equal the one persisted move transaction — a
    // proof anchored to a DIFFERENT body is not a landing of THIS attempt.
    if (
      source.proof.expectedBodySha256 !== input.expectedMoveBodySha256 ||
      destination.proof.expectedBodySha256 !== input.expectedMoveBodySha256
    ) {
      return {
        kind: "INDETERMINATE",
        moveAttemptId,
        reason: { source: "PATH_DISAGREEMENT" },
      };
    }
    return {
      kind: "LANDED_VERIFIED",
      moveAttemptId,
      sourcePath: source.proof,
      destinationPath: destination.proof,
    };
  }

  // Last row: "One wallet appears landed and the other cannot connect to the same
  // transaction | INDETERMINATE; park both wallets." Any other mixed pairing (one LANDED / one
  // not, or both non-LANDED with differing reasons) is the same disagreement class.
  if (source.tier === "LANDED" || destination.tier === "LANDED") {
    return { kind: "INDETERMINATE", moveAttemptId, reason: { source: "PATH_DISAGREEMENT" } };
  }

  // Neither breach nor landed, on either leg: both classifications are narrowed to
  // `{ tier: "INDETERMINATE" }` here by elimination. Prefer the source leg's reason for a
  // stable, deterministic report.
  return { kind: "INDETERMINATE", moveAttemptId, reason: source.reason };
}
