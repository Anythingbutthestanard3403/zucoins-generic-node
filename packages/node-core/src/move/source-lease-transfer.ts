// continuous receive→child-move source-lease transfer.
//
// Step 2 transfers the existing receiver/source lease role without deleting the lease:
// parent and child share one lease group and one continuous source lease, the active row is
// UPDATEd in place, the parent membership closes and the child membership opens under the
// same lease_group_id, and signer capability becomes the post-handoff
// (wallet, child operation, lease_epoch) tuple.
//
// Primitive: `transferLeaseWithinGroup`. This module owns the RECEIVE_WINDOW →
// MOVE_SOURCE binding, proof mint, idempotent replay, and the step-2 composition with
// atomic child create inside one caller DB-TX so a crash leaves either both
// child-row+group-join+role-transfer durable, or none.
//
// Moves only lease ownership. Parent T0 / evidence / artifacts stay on parent rows.

import { createHash, randomUUID } from "node:crypto";

import {
  assertSignCapability,
  LeaseError,
  mintReleaseProof,
  STATEMENTS,
  transferLeaseWithinGroup,
  type ActiveLeaseRow,
  type SqlExecutor,
  type TransferredLease,
} from "../leases/index.js";

import {
  createChildMoveAtomically,
  type ChildMoveCreateConfig,
  type ChildMoveCreationResult,
  type ChildMoveCreateStore,
  type ChildMoveRecord,
} from "./child-create.js";
import { SqlChildMoveCreateStore, type SqlChildMoveCreateStoreConfig } from "./child-create-sql.js";
import type { SqlTxFn } from "./sql-store.js";

export const HANDOFF_PARENT_ROLE = "RECEIVE_WINDOW" as const;
export const HANDOFF_CHILD_ROLE = "MOVE_SOURCE" as const;
export const HANDOFF_RELEASE_REASON = "RECEIVE_LANDED_HANDOFF" as const;

export type SourceLeaseTransferRejection =
  | "NO_ACTIVE_LEASE"
  | "NOT_PARENT_LEASE_HOLDER"
  | "PARENT_ROLE_NOT_RECEIVE"
  | "LEASE_GROUP_MISMATCH"
  | "CHILD_OPERATION_IS_PARENT"
  | "LEASE_OWNER_MISMATCH"
  | "TRANSFER_FAILED";

export interface TransferSourceLeaseParams {
  readonly walletId: string;
  readonly ownerInstanceId: string;
  readonly leaseGroupId: string;
  readonly parentOperationId: string;
  readonly childOperationId: string;
  /**
   * Landing-evidence digest bound into the single-use RECEIVE_LANDED proof consumed by
   * the membership close. Required when minting; ignored when `releaseProofId` is
   * supplied for a pre-minted unconsumed proof.
   */
  readonly landingProofDigest: string;
  /** Optional pre-minted proof. When omitted a fresh proof_id is minted in this TX. */
  readonly releaseProofId?: string;
  readonly releaseReason?: string;
  readonly generateId?: () => string;
}

export type TransferSourceLeaseResult =
  | {
      readonly ok: true;
      readonly status: "TRANSFERRED" | "ALREADY_TRANSFERRED";
      readonly transferred: TransferredLease;
      /** Active-row acquired_at before the hand-off (proves UPDATE-in-place, not reinsert). */
      readonly acquiredAtBefore: string;
      readonly acquiredAtAfter: string;
      readonly parentLeaseEpoch: bigint;
    }
  | {
      readonly ok: false;
      readonly reason: SourceLeaseTransferRejection;
      readonly detail: string;
    };

export interface ContinuousHandoffParams {
  readonly parentOperationId: string;
  readonly ownerInstanceId: string;
  readonly landingProofDigest: string;
  readonly releaseProofId?: string;
  readonly releaseReason?: string;
  readonly generateId?: () => string;
  readonly now?: () => number;
}

export type ContinuousHandoffResult =
  | {
      readonly ok: true;
      readonly childOutcome: "CREATED" | "ALREADY_EXISTS";
      readonly child: ChildMoveRecord;
      readonly transfer: Extract<TransferSourceLeaseResult, { ok: true }>;
    }
  | Extract<ChildMoveCreationResult, { ok: false }>
  | {
      readonly ok: false;
      readonly reason: SourceLeaseTransferRejection;
      readonly detail: string;
      readonly child: ChildMoveRecord | null;
    };

function shaLanding(digest: string): string {
  if (/^[0-9a-f]{64}$/i.test(digest)) return digest.toLowerCase();
  return createHash("sha256").update(digest, "utf8").digest("hex");
}

async function readActive(
  db: SqlExecutor,
  walletId: string,
): Promise<ActiveLeaseRow | null> {
  const result = await db.query<ActiveLeaseRow>(STATEMENTS.SELECT_ACTIVE, [walletId]);
  return result.rows[0] ?? null;
}

/**
 * RECEIVE_WINDOW → MOVE_SOURCE hand-off for a child already joined to the same group.
 * Caller holds the DB-TX. Never DELETEs the active row.
 */
export async function transferSourceReceiveToMove(
  db: SqlExecutor,
  params: TransferSourceLeaseParams,
): Promise<TransferSourceLeaseResult> {
  if (params.childOperationId === params.parentOperationId) {
    return {
      ok: false,
      reason: "CHILD_OPERATION_IS_PARENT",
      detail: "child and parent operation IDs are identical",
    };
  }

  const active = await readActive(db, params.walletId);
  if (active === null) {
    return {
      ok: false,
      reason: "NO_ACTIVE_LEASE",
      detail: `wallet ${params.walletId} holds no active lease`,
    };
  }

  const acquiredAtBefore = active.acquired_at;

  // Idempotent replay: child already owns MOVE_SOURCE on this uninterrupted row.
  if (
    active.operation_id === params.childOperationId &&
    active.lease_group_id === params.leaseGroupId &&
    active.lease_role === HANDOFF_CHILD_ROLE
  ) {
    return {
      ok: true,
      status: "ALREADY_TRANSFERRED",
      transferred: {
        walletId: active.wallet_id,
        previousMembershipId: active.membership_id,
        membershipId: active.membership_id,
        leaseEpoch: BigInt(active.lease_epoch),
        leaseRole: HANDOFF_CHILD_ROLE,
        operationId: active.operation_id,
        rootOperationId: active.root_operation_id,
      },
      acquiredAtBefore,
      acquiredAtAfter: active.acquired_at,
      parentLeaseEpoch: BigInt(active.lease_epoch),
    };
  }

  if (active.operation_id !== params.parentOperationId) {
    return {
      ok: false,
      reason: "NOT_PARENT_LEASE_HOLDER",
      detail: `active lease belongs to operation ${active.operation_id}, not parent ${params.parentOperationId}`,
    };
  }
  if (active.lease_group_id !== params.leaseGroupId) {
    return {
      ok: false,
      reason: "LEASE_GROUP_MISMATCH",
      detail: `active group ${active.lease_group_id} ≠ request ${params.leaseGroupId}`,
    };
  }
  if (active.lease_role !== HANDOFF_PARENT_ROLE) {
    return {
      ok: false,
      reason: "PARENT_ROLE_NOT_RECEIVE",
      detail: `active role ${active.lease_role}, expected ${HANDOFF_PARENT_ROLE}`,
    };
  }
  if (active.owner_instance_id !== params.ownerInstanceId) {
    return {
      ok: false,
      reason: "LEASE_OWNER_MISMATCH",
      detail: "active lease is held by a different instance",
    };
  }

  const parentEpoch = BigInt(active.lease_epoch);
  const generateId = params.generateId ?? (() => randomUUID());
  const proofId = params.releaseProofId ?? generateId();
  const releaseReason = params.releaseReason ?? HANDOFF_RELEASE_REASON;

  if (params.releaseProofId === undefined) {
    await mintReleaseProof(db, {
      proofId,
      walletId: params.walletId,
      operationId: params.parentOperationId,
      membershipId: active.membership_id,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: parentEpoch,
      proofKind: "RECEIVE_LANDED",
      proofDigest: shaLanding(params.landingProofDigest),
    });
  }

  try {
    const transferred = await transferLeaseWithinGroup(db, {
      walletId: params.walletId,
      ownerInstanceId: params.ownerInstanceId,
      leaseGroupId: params.leaseGroupId,
      fromOperationId: params.parentOperationId,
      toOperationId: params.childOperationId,
      membershipId: active.membership_id,
      leaseEpoch: parentEpoch,
      toLeaseRole: HANDOFF_CHILD_ROLE,
      releaseProofId: proofId,
      releaseReason,
    });

    const after = await readActive(db, params.walletId);
    if (after === null) {
      throw new LeaseError(
        "NO_ACTIVE_LEASE",
        "active row vanished mid hand-off (update-in-place violated)",
        params.walletId,
      );
    }

    return {
      ok: true,
      status: "TRANSFERRED",
      transferred,
      acquiredAtBefore,
      acquiredAtAfter: after.acquired_at,
      parentLeaseEpoch: parentEpoch,
    };
  } catch (err) {
    if (err instanceof LeaseError) {
      return {
        ok: false,
        reason: "TRANSFER_FAILED",
        detail: `${err.reason}: ${err.message}`,
      };
    }
    throw err;
  }
}

/**
 * Assert the child can sign under the post-handoff capability.
 * Fail-closed when the tuple does not match the uninterrupted active row.
 */
export async function assertChildSourceSignCapability(
  db: SqlExecutor,
  input: {
    readonly walletId: string;
    readonly childOperationId: string;
    readonly leaseEpoch: bigint;
    readonly ownerInstanceId: string;
  },
): Promise<ActiveLeaseRow> {
  return assertSignCapability(db, {
    walletId: input.walletId,
    operationId: input.childOperationId,
    leaseEpoch: input.leaseEpoch,
    ownerInstanceId: input.ownerInstanceId,
  });
}

/**
 * Step 2 complete: create child MOVE_INTERNAL and transfer source lease
 * continuously inside ONE database transaction. Crash at any intermediate
 * write rolls both halves back — never a child without MOVE_SOURCE, never a release gap.
 */
export async function createChildMoveWithContinuousSourceTransfer(
  withTransaction: SqlTxFn,
  sqlConfig: Omit<SqlChildMoveCreateStoreConfig, "withTransaction">,
  params: ContinuousHandoffParams,
  childConfig: ChildMoveCreateConfig = {},
): Promise<ContinuousHandoffResult> {
  const generateId = params.generateId ?? childConfig.generateId ?? (() => randomUUID());

  return withTransaction(async (tx) => {
    const store: ChildMoveCreateStore = new SqlChildMoveCreateStore({
      ...sqlConfig,
      sql: tx,
      // Nested bodies already hold the outer TX — re-entry must not BEGIN again.
      withTransaction: async (body) => body(tx),
      generateId,
    });

    const created = await createChildMoveAtomically(store, params.parentOperationId, {
      generateId,
      now: params.now ?? childConfig.now,
    });
    if (!created.ok) return created;

    const transfer = await transferSourceReceiveToMove(tx, {
      walletId: created.child.sourceWalletId,
      ownerInstanceId: params.ownerInstanceId,
      leaseGroupId: created.child.leaseGroupId,
      parentOperationId: params.parentOperationId,
      childOperationId: created.child.operationId,
      landingProofDigest: params.landingProofDigest,
      releaseProofId: params.releaseProofId,
      releaseReason: params.releaseReason,
      generateId,
    });

    if (!transfer.ok) {
      // Throw so the shared TX rolls back child insert + group join + partial lease writes.
      throw new LeaseError(
        "TRANSFER_ROLE_INVALID",
        `source lease transfer failed after child create: ${transfer.reason}: ${transfer.detail}`,
        created.child.sourceWalletId,
      );
    }

    return {
      ok: true,
      childOutcome: created.outcome,
      child: created.child,
      transfer,
    };
  });
}
