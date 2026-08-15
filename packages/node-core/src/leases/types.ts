import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type { LeaseRole } from "@zucoins/generic-node-contracts/wallet-state";

export type { LeaseRole };

export const TERMINAL_POSITIVE_PROOF_KINDS = [
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "EXTERNAL_SEND_LANDED",
  "RECEIVE_EXPIRED_T0",
  "OPERATOR_QUARANTINE_RELEASE",
  "RECEIVE_OPERATOR_ACCEPTED_RISK",
  "SEND_PROVEN_NOT_LANDED_CLOSE",
  "SEND_LANDED_UNACKNOWLEDGED_CLOSE",
] as const;

export type TerminalPositiveProofKind = (typeof TERMINAL_POSITIVE_PROOF_KINDS)[number];

/**
 * The landed-proof kind an operation of each kind mints on release
 * (`lease_release_proofs.proof_kind`). The remaining kinds — RECEIVE_EXPIRED_T0,
 * OPERATOR_QUARANTINE_RELEASE, RECEIVE_OPERATOR_ACCEPTED_RISK,
 * SEND_PROVEN_NOT_LANDED_CLOSE, SEND_LANDED_UNACKNOWLEDGED_CLOSE — are not landings and have
 * no operation kind, so they are deliberately absent.
 *
 * Lives here rather than at the composition root because it is lease vocabulary, and
 * because apps/generic-node/test/submit-write-path-reach.guard.test.ts holds the app tree
 * to having no SEND surface at all.
 */
export const LANDED_PROOF_KIND_BY_OPERATION_KIND: Readonly<
  Record<OperationKind, TerminalPositiveProofKind>
> = {
  RECEIVE_EXTERNAL: "RECEIVE_LANDED",
  MOVE_INTERNAL: "INTERNAL_MOVE_LANDED",
  SEND_EXTERNAL: "EXTERNAL_SEND_LANDED",
};

export const PROOF_ISSUER_TRUSTED_VERIFIER = "TRUSTED_VERIFIER" as const;

/** Durable group child disposition (pre-formation gate). */
export const LEASE_GROUP_CHILD_DISPOSITIONS = ["NONE", "PENDING", "JOINED"] as const;
export type LeaseGroupChildDisposition = (typeof LEASE_GROUP_CHILD_DISPOSITIONS)[number];

export interface ActiveLeaseRow {
  readonly wallet_id: string;
  readonly membership_id: string;
  readonly lease_group_id: string;
  readonly root_operation_id: string;
  readonly operation_id: string;
  readonly lease_role: LeaseRole;
  readonly lease_epoch: string; // bigint as text from pg
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly owner_instance_id: string;
  readonly release_not_before: string | null;
}

export interface AcquireWalletInput {
  readonly walletId: string;
  readonly leaseRole: LeaseRole;
}

export interface AcquireLeasesParams {
  readonly wallets: readonly AcquireWalletInput[];
  readonly leaseGroupId: string;
  readonly rootOperationId: string;
  readonly operationId: string;
  readonly ownerInstanceId: string;
}

export interface AcquiredLease {
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseEpoch: bigint;
}

export interface ReleaseLeaseParams {
  readonly walletId: string;
  readonly ownerInstanceId: string;
  readonly operationId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly releaseProofId: string;
  readonly releaseReason: string;
}

export interface ReleasedLease {
  readonly membershipId: string;
  readonly releasedAt: Date;
  readonly deletedRows: number;
  /** True when this release closed the last open membership and marked the group released. */
  readonly groupReleased: boolean;
}

export interface JoinLeaseGroupParams {
  readonly leaseGroupId: string;
  readonly operationId: string;
}

/**
 * Receive → automatic child-move hand-off, phase A (step 2).
 * Closes the parent membership, opens a child membership in the same group, and
 * UPDATEs the uninterrupted active row (never DELETE). Source only — destinations are
 * phase B (`AcquireGroupDestinationLeasesParams`) in a separate transaction, so a busy
 * destination cannot roll this hand-off back (step 3).
 */
export interface TransferLeaseWithinGroupParams {
  readonly walletId: string;
  readonly ownerInstanceId: string;
  readonly leaseGroupId: string;
  readonly fromOperationId: string;
  readonly toOperationId: string;
  readonly membershipId: string;
  readonly leaseEpoch: bigint;
  /** Always MOVE_SOURCE on the canonical receive→child-move path. */
  readonly toLeaseRole: LeaseRole;
  readonly releaseProofId: string;
  readonly releaseReason: string;
}

export interface TransferredLease {
  readonly walletId: string;
  readonly previousMembershipId: string;
  readonly membershipId: string;
  readonly leaseEpoch: bigint;
  readonly leaseRole: LeaseRole;
  readonly operationId: string;
  /** Unchanged by the hand-off; carried out so phase B needs no extra read. */
  readonly rootOperationId: string;
}

/**
 * Receive → child-move hand-off, phase B (step 3): the child
 * operation named by `operationId` must already hold the source lease in `leaseGroupId`.
 * `rootOperationId` is read off that held row rather than supplied by the caller.
 */
export interface AcquireGroupDestinationLeasesParams {
  readonly leaseGroupId: string;
  readonly operationId: string;
  readonly ownerInstanceId: string;
  readonly destinations: readonly AcquireWalletInput[];
}

export interface CompleteGroupOperationParams {
  readonly leaseGroupId: string;
  readonly operationId: string;
}

export interface CreateLeaseGroupParams {
  readonly rootOperationId: string;
  /**
   * NONE (default): HOLD / single-op — no automatic child expected.
   * PENDING: receive with automatic child move not yet joined (release refuses until JOINED).
   */
  readonly childDisposition?: "NONE" | "PENDING";
}

export interface MintReleaseProofParams {
  readonly proofId: string;
  readonly walletId: string;
  readonly operationId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly proofKind: TerminalPositiveProofKind;
  readonly proofDigest: string;
}

export interface SignCapabilityParams {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseEpoch: bigint;
  readonly ownerInstanceId: string;
}

export interface SqlQueryResult<R> {
  readonly rows: R[];
  readonly rowCount?: number | null;
}

/**
 * Narrow node-postgres-shaped surface. `pg.Pool` / `pg.PoolClient` satisfy it.
 * Driver stays outside node-core.
 */
export interface SqlExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<SqlQueryResult<R>>;
}
