// custody claim-boundary service.
//
// Enforces the four load-bearing wallet predicates, the internal_custody /
// automatic_sink_eligible custody flags, the universal lease-acquisition re-check, and
// generic-core neutrality.
//
// Precheck is advisory only. The BEFORE INSERT trigger on wallet_active_leases
// (custody-eligibility.sql) is authoritative at claim time — the one-in-flight-per-wallet rule exclusivity
// (wallet_id PRIMARY KEY) and custody claim boundary origin/blessing/recovery/state conjuncts are structural.
// This service never replaces those guards; it refuses early so callers get a typed denial
// before round-tripping to the database when the facts already fail.

import {
  AUTOMATIC_SINK_CONJUNCTS,
  verifyAutomaticSinkEligibility,
  verifyInternalCustody,
  type CustodyDenialReason,
  type CustodyPredicateFacts,
  type PredicateDecision,
} from "@zucoins/generic-node-contracts/custody";
import type { LeaseRole } from "@zucoins/generic-node-contracts/wallet-state";

export type CustodyClaimDenialReason =
  | CustodyDenialReason
  | "DESTINATION_ORIGIN_NOT_NODE_GENERATED"
  | "CLAIM_BOUNDARY_REJECTED";

export interface CustodyClaimDecision {
  readonly ok: boolean;
  readonly denialReason: CustodyClaimDenialReason | null;
}

/**
 * Full fencing column set for `wallet_active_leases`.
 * Mirrors `STATEMENTS.INSERT_ACTIVE` in leases/statements.ts — the three-column
 * (wallet_id, lease_role, acquired_at) shape is retired.
 */
export interface LeaseClaimInsertInput {
  readonly walletId: string;
  readonly leaseRole: LeaseRole;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly rootOperationId: string;
  readonly operationId: string;
  /** Positive bigint epoch; CHECK (lease_epoch > 0) on the frozen DDL. */
  readonly leaseEpoch: number | string;
  readonly ownerInstanceId: string;
  readonly acquiredAtIso?: string;
  readonly heartbeatAtIso?: string;
}

/** Service-boundary destination create guard. */
export const precheckDestinationCreate = (facts: {
  readonly keyOrigin: unknown;
}): CustodyClaimDecision => {
  if (facts.keyOrigin !== "node_generated") {
    return { ok: false, denialReason: "DESTINATION_ORIGIN_NOT_NODE_GENERATED" };
  }
  return { ok: true, denialReason: null };
};

/** Advisory precheck for internal custody. */
export const precheckInternalCustody = (facts: CustodyPredicateFacts): PredicateDecision =>
  verifyInternalCustody(facts);

/** Advisory precheck for automatic-sink eligibility. */
export const precheckAutomaticSink = (facts: CustodyPredicateFacts): PredicateDecision =>
  verifyAutomaticSinkEligibility(facts);

/**
 * Roles that require the full automatic-sink predicate at the claim boundary.
 * MOVE_DESTINATION is the structural home of the sink conjuncts (blessed dest +
 * recovery) in custody_reject_ineligible_lease (custody-eligibility.sql). Origin and
 * the lease-state allowlist are re-checked for every non-RECONCILIATION role.
 */
export const SINK_LEASE_ROLES: readonly LeaseRole[] = ["MOVE_DESTINATION"] as const;

/** Recovery-lane lease role exempt from lease-state rejection. */
export const RECOVERY_LANE_LEASE_ROLES: readonly LeaseRole[] = ["RECONCILIATION"] as const;

export const isSinkLeaseRole = (role: LeaseRole): boolean =>
  (SINK_LEASE_ROLES as readonly string[]).includes(role);

export const isRecoveryLaneLeaseRole = (role: LeaseRole): boolean =>
  (RECOVERY_LANE_LEASE_ROLES as readonly string[]).includes(role);

/**
 * Advisory precheck immediately before a lease INSERT. For sink roles this is the full
 * automatic_sink_eligible formula; for other non-recovery roles it is origin + the
 * the lease-state allowlist {AVAILABLE, PINNED}; RECONCILIATION is origin-only
 * (recovery-lane exemption). The subsequent INSERT still re-evaluates under the
 * BEFORE INSERT trigger — this function does not grant leases.
 */
export const precheckLeaseClaim = (
  facts: CustodyPredicateFacts,
  leaseRole: LeaseRole,
): CustodyClaimDecision => {
  if (facts.keyOrigin !== "node_generated") {
    return { ok: false, denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED" };
  }
  if (isSinkLeaseRole(leaseRole)) {
    const sink = verifyAutomaticSinkEligibility(facts);
    if (!sink.eligible) {
      return { ok: false, denialReason: sink.denialReason };
    }
    return { ok: true, denialReason: null };
  }
  // Non-sink, non-recovery roles: lease-state allowlist (same admitted set as
  // AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates — AVAILABLE/PINNED).
  if (!isRecoveryLaneLeaseRole(leaseRole)) {
    const allowed = AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates as readonly string[];
    if (!allowed.includes(String(facts.walletState))) {
      return { ok: false, denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE" };
    }
  }
  return { ok: true, denialReason: null };
};

const sqlTs = (iso: string | undefined, fallback: string): string =>
  iso === undefined ? fallback : `'${iso}'`;

/**
 * SQL fragment that inserts a wallet_active_leases row with the full custody schema PK
 * spelling and fencing column set. The claim boundary trigger is the authority: callers must
 * execute this statement (or an equivalent INSERT) inside the same transaction that
 * holds any precheck snapshot they care about. A TOCTOU flip between precheck and
 * this INSERT is re-rejected by the trigger (adversarial #2).
 */
export const buildLeaseClaimInsertSql = (input: LeaseClaimInsertInput): string => {
  const acquired = sqlTs(input.acquiredAtIso, "now()");
  const heartbeat = sqlTs(input.heartbeatAtIso, acquired === "now()" ? "now()" : acquired);
  return (
    `INSERT INTO wallet_active_leases (` +
    `wallet_id, membership_id, lease_group_id, root_operation_id, operation_id, ` +
    `lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id` +
    `) VALUES (` +
    `'${input.walletId}', '${input.membershipId}', '${input.leaseGroupId}', ` +
    `'${input.rootOperationId}', '${input.operationId}', ` +
    `'${input.leaseRole}', ${input.leaseEpoch}, ${acquired}, ${heartbeat}, ` +
    `'${input.ownerInstanceId}'` +
    `);`
  );
};

/**
 * Combine advisory precheck with a claim INSERT executor. If precheck fails, the
 * executor is never called. If precheck passes but the executor throws (structural
 * rejection from the BEFORE INSERT trigger), map the error to CLAIM_BOUNDARY_REJECTED
 * so callers can distinguish "precheck said no" from "claim boundary said no".
 */
export const claimWalletLease = async (
  facts: CustodyPredicateFacts,
  leaseRole: LeaseRole,
  executeInsert: (sql: string) => Promise<void>,
  claim: Omit<LeaseClaimInsertInput, "leaseRole">,
): Promise<CustodyClaimDecision> => {
  const pre = precheckLeaseClaim(facts, leaseRole);
  if (!pre.ok) return pre;
  try {
    await executeInsert(buildLeaseClaimInsertSql({ ...claim, leaseRole }));
    return { ok: true, denialReason: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // Surface known structural literals when present so adversarial tests can assert
    // the *claim boundary* rejected for the right reason, not a generic failure.
    if (message.includes("CUSTODY_LEASE_ORIGIN_REJECTED")) {
      return { ok: false, denialReason: "KEY_ORIGIN_NOT_NODE_GENERATED" };
    }
    if (message.includes("CUSTODY_LEASE_WALLET_STATE_REJECTED")) {
      return { ok: false, denialReason: "WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE" };
    }
    if (message.includes("CUSTODY_LEASE_RECOVERY_UNVERIFIED")) {
      return { ok: false, denialReason: "INVALID_RECOVERY_VERIFIED_AT" };
    }
    if (message.includes("CUSTODY_LEASE_DESTINATION_NOT_BLESSED")) {
      return { ok: false, denialReason: "DESTINATION_NOT_BLESSED" };
    }
    return { ok: false, denialReason: "CLAIM_BOUNDARY_REJECTED" };
  }
};
