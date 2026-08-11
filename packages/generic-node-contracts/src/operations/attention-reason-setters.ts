/**
 * Production-setter census for the frozen ATTENTION_REASONS vocabulary (ZTR-1147).
 *
 * Every value must either have a production writer (a live code path that persists it
 * onto operations.attention_reason) or a recorded disposition explaining why not.
 * The census test fails if a value is missing from both maps.
 */
import { ATTENTION_REASONS, type AttentionReason } from "./events.contract.ts";

/** Live production writers — path anchors for the census / review. */
export const ATTENTION_REASON_PRODUCTION_SETTERS: {
  readonly [K in AttentionReason]?: readonly string[];
} = {
  UNEXPECTED_HEAD_CHANGE: [
    "packages/node-core/src/send/expiry-attention.ts",
    "packages/node-core/src/protocol/reconcile/types.ts",
  ],
  LINEAGE_GAP: ["packages/node-core/src/protocol/reconcile/types.ts"],
  SUBMIT_OUTCOME_AMBIGUOUS: [
    "packages/node-core/src/protocol/reconcile/types.ts",
    "packages/node-core/src/core/submit-decision-claim-store.ts",
  ],
  SIGNING_OUTCOME_AMBIGUOUS: ["packages/node-core/src/protocol/reconcile/types.ts"],
  DESTINATION_NO_LONGER_BLESSED: [
    "apps/generic-node/src/money-workers/move-advanced-ports.ts",
    "packages/node-core/src/protocol/reconcile/types.ts",
  ],
  T0_RELEASE_MISMATCH: ["packages/node-core/src/receive/expiry-release.ts"],
  VERIFICATION_REJECTED: ["packages/node-core/src/protocol/reconcile/types.ts"],
  VERIFICATION_INDETERMINATE: [
    "packages/node-core/src/protocol/reconcile/types.ts",
    "apps/generic-node/src/money-workers/receive-landing-step.ts",
  ],
  VERIFICATION_RESOURCE_EXHAUSTED: ["packages/node-core/src/protocol/reconcile/types.ts"],
  LEASE_INVARIANT_VIOLATION: [
    "packages/node-core/src/protocol/reconcile/types.ts",
    "apps/generic-node/src/operations/arm-live.ts",
  ],
  EXACT_BYTES_UNAVAILABLE: ["packages/node-core/src/protocol/reconcile/types.ts"],
  OPERATOR_PARKED: [
    "apps/generic-node/src/operations/sql-operator-park-store.ts",
    "packages/node-core/src/operator/operator-park.ts",
    "packages/node-core/src/protocol/reconcile/types.ts",
  ],
  POST_EXPIRY_RECONCILING: ["packages/node-core/src/receive/expiry-release.ts"],
};

/**
 * Recorded dispositions for values that have no production setter yet.
 * Coupled tickets must land the writer; until then the enum still admits the value
 * so a future writer cannot invent a 16th reason.
 */
export const ATTENTION_REASON_DISPOSITIONS: {
  readonly [K in AttentionReason]?: {
    readonly status: "DEFERRED";
    readonly reason: string;
    readonly coupledTickets: readonly string[];
  };
} = {
  GATEWAY_RESPONSE_INVALID: {
    status: "DEFERRED",
    reason:
      "No production path persists non-verified gateway reads as operation attention today. " +
      "Becomes reachable once non-verified reads and anomalies are recorded (observation tickets). " +
      "Mapper source GATEWAY_RESPONSE_INVALID is ready; the observation→operation binder is not.",
    coupledTickets: ["ZTR-1127", "ZTR-1128"],
  },
  GATEWAY_UNAVAILABLE_BEYOND_BUDGET: {
    status: "DEFERRED",
    reason:
      "Gateway read-budget exhaustion surfaces as readiness degradation (gn_observation_degraded) " +
      "but is not yet bound to a single operation's attention_reason. Mapper source is ready.",
    coupledTickets: ["ZTR-1127", "ZTR-1128"],
  },
};

export function attentionReasonCoverage(
  reason: AttentionReason,
): "SETTER" | "DISPOSITION" | "MISSING" {
  if ((ATTENTION_REASON_PRODUCTION_SETTERS[reason] ?? []).length > 0) return "SETTER";
  if (ATTENTION_REASON_DISPOSITIONS[reason] !== undefined) return "DISPOSITION";
  return "MISSING";
}

export function assertAttentionReasonCensusComplete(): readonly AttentionReason[] {
  const missing = ATTENTION_REASONS.filter((r) => attentionReasonCoverage(r) === "MISSING");
  if (missing.length > 0) {
    throw new Error(
      `ATTENTION_REASONS without production setter or disposition: ${missing.join(", ")}`,
    );
  }
  return missing;
}
