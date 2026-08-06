// residual / landing-path oracle custody authority gate.
//
//
// Classifier SUCCESSOR only proves cryptographic backlink (P == prior S). Ordinary-head
// promotion and landing/retry/lease-release still require operation attribution when this
// node holds an exclusive lease. An unattributed SUCCESSOR-shaped hop under an active lease
// is INVARIANT_BREACH — never silent promotion because the crypto alone checked out.
//
// This module is the separate custody residual gate. It does not revise classifier output
// (establishesOrdinaryHead(SUCCESSOR) remains true) and does not mint landing proofs.

import type { ClassifierOutputRelationship } from "@zucoins/generic-node-contracts/observation";

import type { PathObservation } from "../protocol/reconcile/observation-input.js";

/** Inputs the custody residual needs beyond the pure classifier result. */
export interface SuccessorCustodyGateInput {
  /** Classifier (or equivalent) relationship for the observed hop. */
  readonly relationship: ClassifierOutputRelationship;
  /** True when this node currently holds an exclusive active lease on the wallet. */
  readonly activeLeaseHeld: boolean;
  /**
   * True when a durable egress submit / sign artifact on this node matches the hop
   * (we formed and submitted this succession ourselves).
   */
  readonly matchingOutboundSubmitArtifact: boolean;
  /**
   * True when an in-flight operation on this node already attributes the hop
   * (e.g. recipient-completed SEND body bound to our partial).
   */
  readonly attributedToInFlightOperation: boolean;
}

/**
 * Disposition of the landing-path oracle residual for a classified hop.
 *
 * - `INVARIANT_BREACH` — SUCCESSOR under lease with no attribution; refuses ordinary-head
 * promotion, landing, retry/resubmit, and lease release. Carries the PathObservation
 * variant that `classifyPathObservation` maps to the same breach reason.
 * - `ORDINARY_SUCCESSOR_AUTHORIZED` — SUCCESSOR that may proceed to ordinary-head /
 * landing adjudication (either no active lease, or hop is attributed).
 * - `NOT_SUCCESSOR` — residual does not apply; caller stays on the anomaly / non-SUCCESSOR
 * path (classifier + quarantine plan).
 */
export type SuccessorCustodyGateResult =
  | {
      readonly disposition: "INVARIANT_BREACH";
      readonly reason: { readonly source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" };
      readonly permitsOrdinaryHeadPromotion: false;
      readonly permitsLanding: false;
      readonly permitsRetryOrResubmit: false;
      readonly permitsLeaseRelease: false;
      /** Feed to classifyPathObservation / send-completion / reconcile. */
      readonly pathObservation: Extract<
        PathObservation,
        { readonly result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" }
      >;
    }
  | {
      readonly disposition: "ORDINARY_SUCCESSOR_AUTHORIZED";
      readonly permitsOrdinaryHeadPromotion: true;
    }
  | {
      readonly disposition: "NOT_SUCCESSOR";
      readonly permitsOrdinaryHeadPromotion: false;
    };

/**
 * Assess the landing-path oracle custody residual for a classified hop.
 *
 * Pure: no I/O. Callers supply lease + attribution evidence from durable stores.
 */
export function assessSuccessorCustodyAuthority(
  input: SuccessorCustodyGateInput,
): SuccessorCustodyGateResult {
  if (input.relationship !== "SUCCESSOR") {
    return {
      disposition: "NOT_SUCCESSOR",
      permitsOrdinaryHeadPromotion: false,
    };
  }

  // Residual applies only while we hold exclusive custody of the wallet.
  if (!input.activeLeaseHeld) {
    return {
      disposition: "ORDINARY_SUCCESSOR_AUTHORIZED",
      permitsOrdinaryHeadPromotion: true,
    };
  }

  const attributed =
    input.matchingOutboundSubmitArtifact || input.attributedToInFlightOperation;
  if (attributed) {
    return {
      disposition: "ORDINARY_SUCCESSOR_AUTHORIZED",
      permitsOrdinaryHeadPromotion: true,
    };
  }

  return {
    disposition: "INVARIANT_BREACH",
    reason: { source: "UNATTRIBUTED_SUCCESSOR_UNDER_ACTIVE_LEASE" },
    permitsOrdinaryHeadPromotion: false,
    permitsLanding: false,
    permitsRetryOrResubmit: false,
    permitsLeaseRelease: false,
    pathObservation: { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
  };
}
