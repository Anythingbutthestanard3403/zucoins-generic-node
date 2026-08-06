/**
 * Consumer-side direct gateway observation helpers (verification step 3: the
 * consumer's own gateway reads).
 * Part of the installable SDK (originally shipped in @zucoins/consumer-example).
 *
 * Classifies successive independent head reads with the frozen relationship
 * classifier. REGRESSION / UNEXPLAINED_JUMP never become action authority.
 */

import {
  classifyRelationship,
  isAnomalousRelationship,
  type RelationshipResult,
  type VerifiedSemanticState,
} from "@zucoins/node-core/observation";
import { deriveBaseline } from "@zucoins/node-core/verifier/consumer";
import type { WalletStateProjection } from "@zucoins/node-core";

export interface IndependentHeadRead {
  readonly rawResponseBytes: Uint8Array;
  readonly walletPublicKey: string;
  /** Consumer-pinned endpoint fingerprint that produced these bytes. */
  readonly endpointFingerprint: string;
}

export type HeadReadOutcome =
  | {
      readonly ok: true;
      readonly projection: WalletStateProjection;
    }
  | {
      readonly ok: false;
      readonly reason: "malformed_or_unverified_head" | "endpoint_fingerprint_mismatch";
      readonly detail: string;
    };

/**
 * Derive a verified head projection from the consumer's own gateway capture.
 * Never accepts a node-relayed body as the independent observation.
 */
export function readIndependentHead(
  read: IndependentHeadRead,
  expectedEndpointFingerprint: string,
): HeadReadOutcome {
  if (read.endpointFingerprint !== expectedEndpointFingerprint) {
    return {
      ok: false,
      reason: "endpoint_fingerprint_mismatch",
      detail:
        "direct gateway read endpoint fingerprint disagrees with the consumer pin; " +
        "fail closed (never prefer the node)",
    };
  }
  const projection = deriveBaseline(read.rawResponseBytes, read.walletPublicKey);
  if (projection === null) {
    return {
      ok: false,
      reason: "malformed_or_unverified_head",
      detail: "independent gateway head did not verify for the wallet",
    };
  }
  return { ok: true, projection };
}

export interface StreamClassifyInput {
  readonly prior: VerifiedSemanticState | null;
  readonly next: VerifiedSemanticState;
  readonly priorHistoryHasNonGenesis: boolean;
  readonly acceptedStateSignatureHistory: readonly string[];
}

export type StreamClassifyOutcome =
  | {
      readonly actionable: true;
      readonly relationship: RelationshipResult["relationship"];
      readonly result: RelationshipResult;
    }
  | {
      readonly actionable: false;
      readonly relationship: RelationshipResult["relationship"];
      readonly result: RelationshipResult;
      readonly reason: "anomaly_not_actionable" | "equivalent_envelope_no_transition";
    };

/**
 * Classify a newly verified independent head. Anomalous relationships
 * (REGRESSION, UNEXPLAINED_JUMP, …) are reported and never acted on.
 */
export function classifyIndependentStream(input: StreamClassifyInput): StreamClassifyOutcome {
  const result = classifyRelationship({
    prior: input.prior,
    next: input.next,
    priorHistoryHasNonGenesis: input.priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory: input.acceptedStateSignatureHistory,
  });

  if (isAnomalousRelationship(result.relationship)) {
    return {
      actionable: false,
      relationship: result.relationship,
      result,
      reason: "anomaly_not_actionable",
    };
  }
  if (result.relationship === "EQUIVALENT_STATE_DIFFERENT_ENVELOPE") {
    return {
      actionable: false,
      relationship: result.relationship,
      result,
      reason: "equivalent_envelope_no_transition",
    };
  }
  return {
    actionable: true,
    relationship: result.relationship,
    result,
  };
}

/**
 * Compare node-relayed terminal projection against the consumer's independent
 * head. Disagreement → fail closed (INDETERMINATE path), never prefer the node.
 */
export function projectionsAgree(
  independent: WalletStateProjection,
  nodeRelayed: { readonly s: string; readonly p: string; readonly b_zkz: string },
): boolean {
  return (
    independent.S === nodeRelayed.s &&
    independent.P === nodeRelayed.p &&
    independent.B === nodeRelayed.b_zkz
  );
}

export type { VerifiedSemanticState };
