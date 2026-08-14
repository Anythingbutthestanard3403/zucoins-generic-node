// atomic child MOVE_INTERNAL creation from a landed receive.
//
// The MOVE_INTERNAL CHECK constrains the row shape; operation_expected_artifacts is reserved
// to a later binding (this slice is row + lease group + event). Parent and child share one
// lease group, and a receive has at most one child.
//
// After the parent receive-landing DB-TX has committed, a single new DB-TX:
// 1. rechecks the exact destination (`after_landing_destination_id`) is still node-generated,
// BLESSED, recovery-verified, wallet_state AVAILABLE, and distinct from the receiver;
// 2. creates exactly one MOVE_INTERNAL/CREATED row with spawned_from_operation_id = parent id
// (UNIQUE partial index is the sole arbiter — concurrent racers never produce a second child);
// 3. joins the child to the parent's existing lease_group_id (never a second lease group) and
// marks child_disposition JOINED;
// 4. appends internal_move.created;
// 5. commits.
//
// Parent operation ID is the internal idempotency key (step 1). Replay after a winner
// committed returns ALREADY_EXISTS with the durable child — never a second row.
//
// Source-lease role transfer composes on top via
// `createChildMoveWithContinuousSourceTransfer` in source-lease-transfer.ts (same DB-TX).
// Out of scope (sibling tickets): destination lease acquire, T0 baseline +
// expected-artifact signing, formation. No SplitChain signing call occurs here.

import { createHash, randomUUID } from "node:crypto";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid } from "../protocol/scalars.js";

import {
  isMoveDestinationEligible,
  isMoveSourceEligible,
  MOVE_OPERATION_KIND,
  type MoveDestinationRecord,
  type MoveSourceWalletRecord,
} from "./create.js";

export type ChildMoveRejectionReason =
  | "PARENT_NOT_FOUND"
  | "PARENT_NOT_LANDED"
  | "PARENT_NOT_INTERNAL_MOVE"
  | "PARENT_MISSING_DESTINATION"
  | "PARENT_LEASE_GROUP_MISSING"
  | "INVALID_AMOUNT"
  | "SOURCE_NOT_FOUND"
  | "SOURCE_NOT_ELIGIBLE"
  | "DESTINATION_NOT_FOUND"
  | "DESTINATION_INELIGIBLE"
  | "SAME_WALLET";

export interface LandedParentReceive {
  readonly parentOperationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly amountZkz: string;
  /** Receiver wallet of the parent receive — becomes the child move source. */
  readonly receiverWalletId: string;
  readonly status: string;
  readonly afterLanding: string;
  readonly afterLandingDestinationId: string | null;
  readonly leaseGroupId: string;
  /** Inherited onto the child MOVE (ZTR-1301). Defaults INDEPENDENT. */
  readonly verificationMode: import("@zucoins/generic-node-contracts/operations").VerificationMode;
}

export interface ChildMoveRecord {
  readonly operationId: string;
  readonly kind: typeof MOVE_OPERATION_KIND;
  readonly status: "CREATED";
  readonly implementerId: string;
  readonly nodeId: string;
  readonly amountZkz: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly spawnedFromOperationId: string;
  readonly referencesOperationId: string;
  readonly leaseGroupId: string;
  /** Step 1 — parent operation ID is the internal idempotency key. */
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly createdAt: number;
  readonly verificationMode: import("@zucoins/generic-node-contracts/operations").VerificationMode;
}

export type ChildMoveCreationResult =
  | { readonly ok: true; readonly outcome: "CREATED"; readonly child: ChildMoveRecord }
  | { readonly ok: true; readonly outcome: "ALREADY_EXISTS"; readonly child: ChildMoveRecord }
  | {
      readonly ok: false;
      readonly reason: ChildMoveRejectionReason;
      readonly detail: string;
    };

export type ChildMoveInsertOutcome =
  | { readonly kind: "INSERTED" }
  | { readonly kind: "SPAWN_CONFLICT"; readonly existingOperationId: string };

export interface ChildMoveInsertInput {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly amountZkz: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly spawnedFromOperationId: string;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly createdAtIso: string;
  readonly leaseGroupId: string;
  readonly verificationMode: import("@zucoins/generic-node-contracts/operations").VerificationMode;
}

/**
 * Port executed inside one DB-TX (SERIALIZABLE preferred). The UNIQUE partial index
 * `operations_one_spawn_per_parent_uidx` is the sole arbiter of concurrent spawn races —
 * `insertChild` MUST use ON CONFLICT (spawned_from_operation_id) … DO NOTHING RETURNING, never
 * a pre-read decide path.
 */
export interface ChildMoveTx {
  loadParent(parentOperationId: string): Promise<LandedParentReceive | null>;
  loadSourceWallet(walletId: string): Promise<MoveSourceWalletRecord | null>;
  loadDestination(destinationId: string): Promise<MoveDestinationRecord | null>;
  insertChild(input: ChildMoveInsertInput): Promise<ChildMoveInsertOutcome>;
  findChildByParent(parentOperationId: string): Promise<ChildMoveRecord | null>;
  joinParentLeaseGroup(input: {
    readonly leaseGroupId: string;
    readonly childOperationId: string;
    readonly joinedAtIso: string;
  }): Promise<void>;
  appendCreatedEvent(input: {
    readonly operationId: string;
    readonly nodeId: string;
    readonly implementerId: string;
    readonly sourceWalletId: string;
    readonly destinationId: string;
    readonly amountZkz: string;
    readonly createdAtIso: string;
  }): Promise<void>;
}

export interface ChildMoveCreateStore {
  withTransaction<T>(body: (tx: ChildMoveTx) => Promise<T>): Promise<T>;
}

export interface ChildMoveCreateConfig {
  readonly generateId?: () => string;
  readonly now?: () => number;
}

/** Canonical request hash for a continuous-handoff child (parent id is the identity). */
export function childMoveRequestSha256(input: {
  readonly implementerId: string;
  readonly nodeId: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly amountZkz: string;
  readonly spawnedFromOperationId: string;
}): string {
  const canonical = JSON.stringify({
    implementer_id: input.implementerId,
    node_id: input.nodeId,
    source_wallet_id: input.sourceWalletId,
    destination_id: input.destinationId,
    amount_zkz: input.amountZkz,
    spawned_from_operation_id: input.spawnedFromOperationId,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function reject(
  reason: ChildMoveRejectionReason,
  detail: string,
): ChildMoveCreationResult {
  return { ok: false, reason, detail };
}

/**
 * Step 2 — create the child MOVE_INTERNAL atomically from a landed receive.
 * Idempotent on parent operation id: second concurrent attempt loses the UNIQUE race and returns
 * ALREADY_EXISTS with the durable winner.
 */
export async function createChildMoveAtomically(
  store: ChildMoveCreateStore,
  parentOperationId: string,
  config: ChildMoveCreateConfig = {},
): Promise<ChildMoveCreationResult> {
  const generateId = config.generateId ?? (() => randomUUID());
  const now = config.now ?? (() => Date.now());

  let parsedParentId: string;
  try {
    parsedParentId = parseUuid(parentOperationId);
  } catch {
    return reject("PARENT_NOT_FOUND", "parent_operation_id is not a uuid");
  }

  return store.withTransaction(async (tx) => {
    const parent = await tx.loadParent(parsedParentId);
    if (parent === null) {
      return reject("PARENT_NOT_FOUND", `no receive operation ${parsedParentId}`);
    }

    if (parent.status !== "RECEIVE_LANDED") {
      return reject(
        "PARENT_NOT_LANDED",
        `parent status=${parent.status}; child move requires RECEIVE_LANDED`,
      );
    }

    if (parent.afterLanding !== "INTERNAL_MOVE") {
      return reject(
        "PARENT_NOT_INTERNAL_MOVE",
        `parent after_landing=${parent.afterLanding}; continuous handoff requires INTERNAL_MOVE`,
      );
    }

    if (
      parent.afterLandingDestinationId === null ||
      parent.afterLandingDestinationId.length === 0
    ) {
      return reject(
        "PARENT_MISSING_DESTINATION",
        "parent after_landing_destination_id is required for INTERNAL_MOVE",
      );
    }

    if (parent.leaseGroupId.length === 0) {
      return reject("PARENT_LEASE_GROUP_MISSING", "parent has no lease_group_id");
    }

    try {
      parsePositiveZkzAmount(parent.amountZkz);
    } catch {
      return reject(
        "INVALID_AMOUNT",
        `inherited amount_zkz failed validation: ${parent.amountZkz}`,
      );
    }

    // Existing child short-circuit (still inside TX for a consistent read of the winner).
    const existing = await tx.findChildByParent(parsedParentId);
    if (existing !== null) {
      return { ok: true, outcome: "ALREADY_EXISTS", child: existing };
    }

    const source = await tx.loadSourceWallet(parent.receiverWalletId);
    if (source === null) {
      return reject("SOURCE_NOT_FOUND", `receiver wallet ${parent.receiverWalletId}`);
    }
    // Receiver is PINNED under the continuous source lease.
    if (!isMoveSourceEligible(source, parent.nodeId, { allowPinned: true })) {
      return reject(
        "SOURCE_NOT_ELIGIBLE",
        `receiver wallet state=${source.state} key_origin=${source.keyOrigin}`,
      );
    }

    const destination = await tx.loadDestination(parent.afterLandingDestinationId);
    if (destination === null) {
      return reject(
        "DESTINATION_NOT_FOUND",
        `destination ${parent.afterLandingDestinationId}`,
      );
    }

    if (destination.walletId === parent.receiverWalletId) {
      return reject("SAME_WALLET", "destination resolves to the receive wallet");
    }

    const destOk = isMoveDestinationEligible(
      destination,
      parent.nodeId,
      parent.receiverWalletId,
    );
    if (!destOk.ok) {
      return reject(
        "DESTINATION_INELIGIBLE",
        destOk.detail ?? destOk.code,
      );
    }

    const createdAt = now();
    const createdAtIso = new Date(createdAt).toISOString();
    const operationId = generateId();
    const idempotencyKey = parsedParentId;
    const requestSha256 = childMoveRequestSha256({
      implementerId: parent.implementerId,
      nodeId: parent.nodeId,
      sourceWalletId: parent.receiverWalletId,
      destinationId: destination.destinationId,
      amountZkz: parent.amountZkz,
      spawnedFromOperationId: parsedParentId,
    });

    const insert = await tx.insertChild({
      operationId,
      implementerId: parent.implementerId,
      nodeId: parent.nodeId,
      amountZkz: parent.amountZkz,
      sourceWalletId: parent.receiverWalletId,
      destinationId: destination.destinationId,
      spawnedFromOperationId: parsedParentId,
      idempotencyKey,
      requestSha256,
      createdAtIso,
      leaseGroupId: parent.leaseGroupId,
      verificationMode: parent.verificationMode,
    });

    if (insert.kind === "SPAWN_CONFLICT") {
      const winner = await tx.findChildByParent(parsedParentId);
      if (winner === null) {
        // Race window: winner not yet visible — surface as already-exists by id alone.
        return {
          ok: true,
          outcome: "ALREADY_EXISTS",
          child: {
            operationId: insert.existingOperationId,
            kind: MOVE_OPERATION_KIND,
            status: "CREATED",
            implementerId: parent.implementerId,
            nodeId: parent.nodeId,
            amountZkz: parent.amountZkz,
            sourceWalletId: parent.receiverWalletId,
            destinationId: destination.destinationId,
            destinationWalletId: destination.walletId,
            spawnedFromOperationId: parsedParentId,
            referencesOperationId: parsedParentId,
            leaseGroupId: parent.leaseGroupId,
            idempotencyKey,
            requestSha256,
            createdAt,
            verificationMode: parent.verificationMode,
          },
        };
      }
      return { ok: true, outcome: "ALREADY_EXISTS", child: winner };
    }

    // Join existing group (no second lease_groups root) + mark disposition JOINED.
    await tx.joinParentLeaseGroup({
      leaseGroupId: parent.leaseGroupId,
      childOperationId: operationId,
      joinedAtIso: createdAtIso,
    });

    await tx.appendCreatedEvent({
      operationId,
      nodeId: parent.nodeId,
      implementerId: parent.implementerId,
      sourceWalletId: parent.receiverWalletId,
      destinationId: destination.destinationId,
      amountZkz: parent.amountZkz,
      createdAtIso,
    });

    const child: ChildMoveRecord = {
      operationId,
      kind: MOVE_OPERATION_KIND,
      status: "CREATED",
      implementerId: parent.implementerId,
      nodeId: parent.nodeId,
      amountZkz: parent.amountZkz,
      sourceWalletId: parent.receiverWalletId,
      destinationId: destination.destinationId,
      destinationWalletId: destination.walletId,
      spawnedFromOperationId: parsedParentId,
      referencesOperationId: parsedParentId,
      leaseGroupId: parent.leaseGroupId,
      idempotencyKey,
      requestSha256,
      createdAt,
      verificationMode: parent.verificationMode,
    };

    return { ok: true, outcome: "CREATED", child };
  });
}
