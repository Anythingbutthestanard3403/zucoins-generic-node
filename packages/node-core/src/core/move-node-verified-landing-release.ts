// NODE_VERIFIED same-TX custody close for MOVE_INTERNAL landing (ZTR-1304).
//
// Called from the composition-root move reconcile TX after persistMoveOutcome has
// CAS'd INTERNAL_MOVE_LANDED and before COMMIT. INDEPENDENT callers must not invoke
// this helper. NEEDS_ATTENTION / park paths never reach it.
//
// Releases MOVE_SOURCE + MOVE_DESTINATION with proof kind INTERNAL_MOVE_LANDED,
// minting one terminal-positive proof per membership. Completes the move group-op
// (and any sibling group-ops with no remaining active lease — e.g. a parent receive
// that already transferred RECEIVE_WINDOW → MOVE_SOURCE) so releaseLease's collective
// terminal predicate admits the dual close.

import { createHash, randomUUID } from "node:crypto";

import { RELEASED_NODE_VERIFIED } from "@zucoins/generic-node-contracts/operations";

import {
  completeGroupOperation,
  mintReleaseProof,
  releaseLease,
} from "../leases/repository.js";
import type { SqlExecutor } from "../leases/types.js";

/** Forensic release_reason on wallet_lease_memberships for NODE_VERIFIED move landing. */
export const NODE_VERIFIED_MOVE_LANDING_RELEASE_REASON = "NODE_VERIFIED_LANDING" as const;

/**
 * Byte-stable proof digest for NODE_VERIFIED move landing release. Same nvland1
 * length-prefixed shape as receive/send; binds both terminal observation anchors.
 */
export function computeNodeVerifiedMoveLandingReleaseDigest(fields: {
  readonly operationId: string;
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: bigint;
  readonly sourceTerminalObservationId: string;
  readonly destinationTerminalObservationId: string;
}): string {
  const field = (value: string): string =>
    `${new TextEncoder().encode(value).length}:${value}`;
  const text =
    field(fields.operationId) +
    field(fields.walletId) +
    field(fields.membershipId) +
    field(fields.leaseGroupId) +
    field(fields.leaseEpoch.toString()) +
    field(fields.sourceTerminalObservationId) +
    field(fields.destinationTerminalObservationId);
  return createHash("sha256").update(`nvland1:${text}`, "utf8").digest("hex");
}

const LOAD_MOVE_RELEASE_CONTEXT = `
  SELECT o.verification_mode::text AS verification_mode,
         o.source_wallet_id::text AS source_wallet_id,
         d.wallet_id::text AS destination_wallet_id
    FROM operations o
    LEFT JOIN destinations d ON d.id = o.destination_id
   WHERE o.id = $1::uuid AND o.kind = 'MOVE_INTERNAL'
`.replace(/\s+/g, " ").trim();

const LOAD_ACTIVE_LEASES_FOR_OP = `
  SELECT wallet_id::text AS wallet_id,
         membership_id::text AS membership_id,
         lease_group_id::text AS lease_group_id,
         lease_epoch::text AS lease_epoch,
         owner_instance_id::text AS owner_instance_id,
         lease_role::text AS lease_role
    FROM wallet_active_leases
   WHERE operation_id = $1::uuid
     AND lease_role IN ('MOVE_SOURCE', 'MOVE_DESTINATION')
`.replace(/\s+/g, " ").trim();

const LOAD_INCOMPLETE_GROUP_OPS = `
  SELECT operation_id::text AS operation_id
    FROM lease_group_operations
   WHERE lease_group_id = $1::uuid
     AND completed_at IS NULL
`.replace(/\s+/g, " ").trim();

const SET_RELEASE_STATUS_NODE_VERIFIED = `
  UPDATE operations SET receive_release_status = $2,
         row_version = row_version + 1, updated_at = now()
   WHERE id = $1::uuid
     AND status = 'INTERNAL_MOVE_LANDED'
     AND receive_release_status IS NULL
   RETURNING receive_release_status
`.replace(/\s+/g, " ").trim();

export interface MoveNodeVerifiedLandingReleaseInput {
  readonly operationId: string;
  readonly sourceTerminalObservationId: string;
  readonly destinationTerminalObservationId: string;
}

export type MoveNodeVerifiedLandingReleaseResult =
  | { readonly kind: "RELEASED"; readonly releasedWalletIds: readonly string[] }
  | { readonly kind: "SKIPPED_INDEPENDENT" }
  | { readonly kind: "SKIPPED_NO_LEASES" };

/**
 * If the move is NODE_VERIFIED, complete group ops + release both MOVE_* leases in
 * the caller's open transaction. Throws on partial release so the landing CAS rolls back.
 */
export async function releaseNodeVerifiedMoveLeasesOnLanding(
  tx: SqlExecutor,
  input: MoveNodeVerifiedLandingReleaseInput,
): Promise<MoveNodeVerifiedLandingReleaseResult> {
  const modeRows = await tx.query<{
    verification_mode: string;
    source_wallet_id: string | null;
    destination_wallet_id: string | null;
  }>(LOAD_MOVE_RELEASE_CONTEXT, [input.operationId]);
  const mode = modeRows.rows[0];
  if (mode === undefined || mode.verification_mode !== "NODE_VERIFIED") {
    return { kind: "SKIPPED_INDEPENDENT" };
  }

  const leaseRows = await tx.query<{
    wallet_id: string;
    membership_id: string;
    lease_group_id: string;
    lease_epoch: string;
    owner_instance_id: string;
    lease_role: string;
  }>(LOAD_ACTIVE_LEASES_FOR_OP, [input.operationId]);

  if (leaseRows.rows.length === 0) {
    return { kind: "SKIPPED_NO_LEASES" };
  }

  // All MOVE_* leases for one op share one lease_group_id.
  const leaseGroupId = leaseRows.rows[0]!.lease_group_id;

  // Complete every incomplete group-op in the group. The child MOVE is the landing
  // authority; a parent receive that already transferred out still blocks releaseLease
  // until its lease_group_operations.completed_at is stamped (collective terminal).
  const incomplete = await tx.query<{ operation_id: string }>(LOAD_INCOMPLETE_GROUP_OPS, [
    leaseGroupId,
  ]);
  for (const row of incomplete.rows) {
    await completeGroupOperation(tx, {
      leaseGroupId,
      operationId: row.operation_id,
    });
  }

  // Deterministic wallet sequence (ascending id) — same as verification-complete.
  const sequenced = [...leaseRows.rows].sort((a, b) =>
    a.wallet_id < b.wallet_id ? -1 : a.wallet_id > b.wallet_id ? 1 : 0,
  );

  const releasedWalletIds: string[] = [];
  for (const lease of sequenced) {
    const leaseEpoch = BigInt(lease.lease_epoch);
    const proofId = randomUUID();
    const proofDigest = computeNodeVerifiedMoveLandingReleaseDigest({
      operationId: input.operationId,
      walletId: lease.wallet_id,
      membershipId: lease.membership_id,
      leaseGroupId: lease.lease_group_id,
      leaseEpoch,
      sourceTerminalObservationId: input.sourceTerminalObservationId,
      destinationTerminalObservationId: input.destinationTerminalObservationId,
    });
    await mintReleaseProof(tx, {
      proofId,
      walletId: lease.wallet_id,
      operationId: input.operationId,
      membershipId: lease.membership_id,
      leaseGroupId: lease.lease_group_id,
      leaseEpoch,
      proofKind: "INTERNAL_MOVE_LANDED",
      proofDigest,
    });
    await releaseLease(tx, {
      walletId: lease.wallet_id,
      ownerInstanceId: lease.owner_instance_id,
      operationId: input.operationId,
      membershipId: lease.membership_id,
      leaseGroupId: lease.lease_group_id,
      leaseEpoch,
      releaseProofId: proofId,
      releaseReason: NODE_VERIFIED_MOVE_LANDING_RELEASE_REASON,
    });
    releasedWalletIds.push(lease.wallet_id);
  }

  const stamped = await tx.query<{ receive_release_status: string }>(
    SET_RELEASE_STATUS_NODE_VERIFIED,
    [input.operationId, RELEASED_NODE_VERIFIED],
  );
  if (stamped.rows.length !== 1) {
    throw new Error(
      `NODE_VERIFIED move receive_release_status CAS failed: ${input.operationId}`,
    );
  }

  return { kind: "RELEASED", releasedWalletIds };
}
