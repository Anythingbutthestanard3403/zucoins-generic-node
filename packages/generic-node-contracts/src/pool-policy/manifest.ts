import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  POOL_FLOOR,
  SEND_POOL_FLOOR,
  POOL_CAP_DEFAULT,
  POOL_CAP_CEILING,
  MINT_BATCH_LIMIT,
  HEADROOM_NUMERATOR,
  HEADROOM_DENOMINATOR,
  RECEIVE_QUEUE_MAX_WAIT_MS,
  RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
} from "./constants.js";
import {
  POOL_WALLET_STATES,
  POOL_WALLET_TRANSITIONS,
  POOL_KEY_DELETION_ALLOWED,
} from "./states.js";
import { KEY_ORIGIN_NODE_GENERATED } from "./eligibility.js";
import {
  RECEIVE_QUEUE_DEQUEUE_ORDER,
  RECEIVE_QUEUE_PROMOTION_TRANSACTION,
  RECEIVE_QUEUE_QUEUED_PREDICATE,
} from "./queue.js";

// Constants surfaced to operator (the receive-queue backpressure rule flagged the four new numbers; the dual-run addendum flagged
// RECEIVE_QUEUE_MAX_WAIT as weakest-anchored). Recorded as DATA — the operative values in
// constants.ts are frozen and used; these notes carry the recommended alternative and status so a
// operator confirmation is a data edit, not a code hunt.
export const POOL_POLICY_FLAGS = {
  RECEIVE_QUEUE_MAX_WAIT_MS: {
    operative: 30000,
    recommended: 120000,
    status: "flagged_for_operator",
    reason:
      "30s risks a false-EXPIRED before one replenishment cycle; the dual-run recommends ~120s while remaining bounded.",
  },
  POOL_CAP_CEILING: {
    operative: 500,
    status: "flagged_for_operator",
    reason: "freezes the illustrative 500 as max permanent key material per node.",
  },
  MINT_BATCH_LIMIT: {
    operative: 5,
    status: "flagged_for_operator",
    reason: "anchored to POOL_FLOOR; bounds per-cycle permanent mint and vault-lock hold.",
  },
  RECEIVE_QUEUE_CAP: {
    operative: "pool_cap",
    status: "derived",
    reason: "derived from pool_cap, not an independent magic number.",
  },
  RECEIVE_QUEUE_RETRY_AFTER_SECONDS: {
    operative: 30,
    status: "derived",
    reason:
      "Retry-After for the 503 receive_queue_full; derived from RECEIVE_QUEUE_MAX_WAIT (30s), the soonest a queued receive expires and frees a slot. Tracks the max-wait if operator policy raises it.",
  },
} as const;

export const poolPolicyContract = {
  sizing: {
    POOL_FLOOR,
    SEND_POOL_FLOOR,
    POOL_CAP_DEFAULT,
    POOL_CAP_CEILING,
    MINT_BATCH_LIMIT,
    HEADROOM_NUMERATOR,
    HEADROOM_DENOMINATOR,
  },
  queue: {
    RECEIVE_QUEUE_MAX_WAIT_MS,
    RECEIVE_QUEUE_CAP: "pool_cap",
    RECEIVE_QUEUE_RETRY_AFTER_SECONDS,
    RECEIVE_QUEUE_DEQUEUE_ORDER: [...RECEIVE_QUEUE_DEQUEUE_ORDER],
    RECEIVE_QUEUE_QUEUED_PREDICATE,
    RECEIVE_QUEUE_PROMOTION_TRANSACTION,
  },
  states: {
    all: POOL_WALLET_STATES,
    transitions: POOL_WALLET_TRANSITIONS,
    keyDeletionAllowed: POOL_KEY_DELETION_ALLOWED,
  },
  eligibility: {
    keyOriginNodeGenerated: KEY_ORIGIN_NODE_GENERATED,
    receiveEligiblePredicate:
      "key_origin='node_generated' AND recovery_verified_at IS NOT NULL AND state='AVAILABLE'",
    capCountsAllNonDeleted: true,
  },
  flags: POOL_POLICY_FLAGS,
} as const;

export const poolPolicyConcernManifest = {
  concern: "pool-policy",
  frozenBy: "receive-queue-backpressure",
  refinedBy: "recovery-gated-eligibility",
  contract: poolPolicyContract,
} as const;

/**
 * The pool-policy concern's self-registered ConcernManifest ("the concern-manifest registry
 * leave-behind"). Wraps `poolPolicyContract` byte-identically under the canonical shape;
 * `poolPolicyConcernManifest` above is the provisional form supersedes. Registration
 * export only — the concern-manifest registry assembles `src/registry.ts`. LIVE-CUSTODY-
 * SENSITIVE: this freezes pool policy DATA only — it mints nothing and authorizes no send.
 */
export const POOL_POLICY_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "pool-policy",
  decisionRefs: ["receive-queue-backpressure", "recovery-gated-eligibility", "permanent-key-material-cap", "pool-sizing-policy", "custody-evidence-requirements"],
  frozenValues: { poolPolicyContract },
  goldenRefs: [{ path: "gen/pool-policy.json", sha256: "ba9b29db5ef968bdd358306602be586732d06f07269b81e06cfcb48ef1f8f65f" }],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "receive-queue-backpressure",
    "recovery-gated-eligibility",
    "permanent-key-material-cap",
    "pool-sizing-policy",
    "custody-evidence-requirements",
  ],
});
