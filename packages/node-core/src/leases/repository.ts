// Persisted lease repository — the only sanctioned writer for
// wallet_active_leases / memberships / groups / release proofs.
//
// The one-in-flight-per-wallet and key-custody rules bind here. Driver-agnostic: the composition root injects SqlExecutor.
//
// Every mutator expects to run inside the caller's SERIALIZABLE transaction. On invariant
// violation these functions THROW LeaseError so the caller transaction rolls back.

import { createHash, randomUUID } from "node:crypto";

import { isOperationRole } from "@zucoins/generic-node-contracts/wallet-state";

import { assertLeaseFoundationReady } from "./readiness.js";
import { LeaseError } from "./errors.js";
import { sortWalletIdsAscending } from "./sort-wallets.js";
import { STATEMENTS } from "./statements.js";
import type {
  AcquireGroupDestinationLeasesParams,
  AcquireLeasesParams,
  AcquiredLease,
  ActiveLeaseRow,
  CompleteGroupOperationParams,
  CreateLeaseGroupParams,
  JoinLeaseGroupParams,
  LeaseGroupChildDisposition,
  MintReleaseProofParams,
  ReleaseLeaseParams,
  ReleasedLease,
  SignCapabilityParams,
  SqlExecutor,
  TransferLeaseWithinGroupParams,
  TransferredLease,
} from "./types.js";

type WalletLockRow = { wallet_id: string; state: string };

type ProofRow = {
  proof_id: string;
  wallet_id: string;
  operation_id: string;
  membership_id: string;
  lease_group_id: string;
  lease_epoch: string;
  proof_kind: string;
  proof_digest: string;
  issuer: string;
  consumed_at: string | null;
};

type LeaseGroupRow = {
  id: string;
  root_operation_id: string;
  created_at: string;
  child_disposition: LeaseGroupChildDisposition;
  released_at: string | null;
  release_proof_id: string | null;
};

type GroupOperationRow = {
  lease_group_id: string;
  operation_id: string;
  joined_at: string;
  completed_at: string | null;
};

type OpenMembershipRow = {
  id: string;
  lease_group_id: string;
  wallet_id: string;
  operation_id: string;
  lease_role: string;
  lease_epoch: string;
  acquired_at: string;
  released_at: string | null;
};

function sha256Text(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

async function audit(
  db: SqlExecutor,
  action: string,
  fields: {
    walletId?: string;
    operationId?: string;
    membershipId?: string;
    leaseGroupId?: string;
    leaseEpoch?: bigint;
    ownerInstanceId?: string;
    details: Record<string, string | number | boolean | null>;
  },
): Promise<void> {
  const detailsText = JSON.stringify(fields.details);
  await db.query(STATEMENTS.INSERT_AUDIT, [
    randomUUID(),
    action,
    fields.walletId ?? null,
    fields.operationId ?? null,
    fields.membershipId ?? null,
    fields.leaseGroupId ?? null,
    fields.leaseEpoch === undefined ? null : fields.leaseEpoch.toString(),
    fields.ownerInstanceId ?? null,
    detailsText,
    sha256Text(detailsText),
    new Date().toISOString(),
  ]);
}

async function lockWallet(db: SqlExecutor, walletId: string): Promise<WalletLockRow> {
  const result = await db.query<WalletLockRow>(STATEMENTS.LOCK_WALLET, [walletId]);
  const row = result.rows[0];
  if (!row) {
    throw new LeaseError("WALLET_NOT_FOUND", "no such wallet", walletId);
  }
  return row;
}

async function nextEpoch(db: SqlExecutor, walletId: string): Promise<bigint> {
  // Caller already holds wallets FOR UPDATE for this walletId.
  const hw = await db.query<{ highwater: string }>(STATEMENTS.SELECT_HIGHWATER_FOR_UPDATE, [
    walletId,
  ]);
  const fromHw = hw.rows[0]?.highwater;
  const mem = await db.query<{ max_epoch: string | null }>(STATEMENTS.SELECT_MAX_MEMBERSHIP_EPOCH, [
    walletId,
  ]);
  const fromMem = mem.rows[0]?.max_epoch;
  const a = fromHw === undefined ? 0n : BigInt(fromHw);
  const b = fromMem === null || fromMem === undefined ? 0n : BigInt(fromMem);
  const next = (a > b ? a : b) + 1n;
  await db.query(STATEMENTS.UPSERT_HIGHWATER, [walletId, next.toString()]);
  return next;
}

/**
 * Multi-wallet atomic acquisition. Sorts wallet ids ascending internally. Rejects
 * RECONCILIATION and any non-operation role before any write. Any failure throws and the
 * caller's transaction must roll back (commit all or none).
 */
export async function acquireLeases(
  db: SqlExecutor,
  params: AcquireLeasesParams,
): Promise<AcquiredLease[]> {
  await assertLeaseFoundationReady(db);

  const seen = new Set<string>();
  for (const w of params.wallets) {
    if (!isOperationRole(w.leaseRole)) {
      throw new LeaseError(
        "NON_OPERATION_ROLE",
        `role ${w.leaseRole} cannot occupy wallet_active_leases (the one-in-flight-per-wallet rule)`,
        w.walletId,
      );
    }
    const key = w.walletId.toLowerCase();
    if (seen.has(key)) {
      throw new LeaseError("DUPLICATE_WALLET_ID", "wallet listed twice in one acquisition", w.walletId);
    }
    seen.add(key);
  }

  // Lock sequence — the one sequence every lease mutator follows: lease group, then wallets
  // UUID-ascending (step 2), then that wallet's active row, then the proof.
  // Taking the group row FOR UPDATE up front is load-bearing, not defensive: both
  // INSERT_MEMBERSHIP and INSERT_ACTIVE carry an FK to lease_groups, so Postgres takes a
  // KEY SHARE lock on the same row mid-loop anyway. Acquiring wallets first and reaching the
  // group second is the reverse of releaseLease's sequence and deadlocked against it.
  const groupResult = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [
    params.leaseGroupId,
  ]);
  const group = groupResult.rows[0];
  if (!group) {
    throw new LeaseError("GROUP_OPERATION_MISSING", "lease group does not exist");
  }
  if (group.released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "cannot acquire a lease inside an already-released lease group",
    );
  }

  const byId = new Map(params.wallets.map((w) => [w.walletId, w] as const));
  const sortedIds = sortWalletIdsAscending(params.wallets.map((w) => w.walletId));
  const acquired: AcquiredLease[] = [];
  const now = new Date().toISOString();

  for (const walletId of sortedIds) {
    const input = byId.get(walletId);
    if (!input) {
      throw new LeaseError("WALLET_NOT_FOUND", "internal: sorted id missing from input map", walletId);
    }

    const wallet = await lockWallet(db, walletId);
    if (wallet.state === "QUARANTINED" || wallet.state === "RETIRED") {
      throw new LeaseError(
        "WALLET_NOT_ELIGIBLE",
        `wallet.state=${wallet.state} cannot be leased`,
        walletId,
      );
    }

    const existing = await db.query<{ wallet_id: string }>(STATEMENTS.SELECT_ACTIVE, [walletId]);
    if (existing.rows.length > 0) {
      throw new LeaseError(
        "ALREADY_LEASED",
        "wallet already has a current active lease (the one-in-flight-per-wallet rule)",
        walletId,
      );
    }

    const leaseEpoch = await nextEpoch(db, walletId);
    const membershipId = randomUUID();

    await db.query(STATEMENTS.INSERT_MEMBERSHIP, [
      membershipId,
      params.leaseGroupId,
      walletId,
      params.operationId,
      input.leaseRole,
      leaseEpoch.toString(),
      now,
    ]);

    await db.query(STATEMENTS.INSERT_ACTIVE, [
      walletId,
      membershipId,
      params.leaseGroupId,
      params.rootOperationId,
      params.operationId,
      input.leaseRole,
      leaseEpoch.toString(),
      now,
      now,
      params.ownerInstanceId,
    ]);

    if (input.leaseRole === "RECEIVE_WINDOW" && wallet.state === "AVAILABLE") {
      await db.query(STATEMENTS.PIN_WALLET, [walletId]);
    }

    await audit(db, "LEASE_ACQUIRED", {
      walletId,
      operationId: params.operationId,
      membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch,
      ownerInstanceId: params.ownerInstanceId,
      details: { lease_role: input.leaseRole },
    });

    acquired.push({ walletId, membershipId, leaseEpoch });
  }

  return acquired;
}

/** Mint a trusted-verifier terminal-positive proof. Not callable with a forgeable bearer. */
export async function mintReleaseProof(
  db: SqlExecutor,
  params: MintReleaseProofParams,
): Promise<void> {
  await assertLeaseFoundationReady(db);
  await db.query(STATEMENTS.INSERT_PROOF, [
    params.proofId,
    params.walletId,
    params.operationId,
    params.membershipId,
    params.leaseGroupId,
    params.leaseEpoch.toString(),
    params.proofKind,
    params.proofDigest,
    new Date().toISOString(),
  ]);
}


/**
 * Receive → child-move hand-off, phase A (step 2):
 * - close parent membership (proof-backed, one-way)
 * - open child membership in the same lease_group_id
 * - UPDATE the uninterrupted active row (never DELETE)
 *
 * Source only. Destination wallets are phase B — `acquireGroupDestinationLeases`, a separate
 * transaction — because step 3 requires that a busy destination leave the child
 * `CREATED` with the source lease "continuously held": bundling the destination acquire in
 * here would roll this committed hand-off back on ALREADY_LEASED instead.
 *
 * Root operation stays on the active row. Parent capability (fromOperationId +
 * leaseEpoch) is permanently invalidated; the successor epoch is required to sign.
 * Heartbeat expiry never reaches this path.
 *
 * Caller holds a SERIALIZABLE transaction; any throw rolls the whole hand-off back.
 */
export async function transferLeaseWithinGroup(
  db: SqlExecutor,
  params: TransferLeaseWithinGroupParams,
): Promise<TransferredLease> {
  await assertLeaseFoundationReady(db);

  if (!isOperationRole(params.toLeaseRole)) {
    throw new LeaseError(
      "NON_OPERATION_ROLE",
      `role ${params.toLeaseRole} cannot occupy wallet_active_leases (the one-in-flight-per-wallet rule)`,
      params.walletId,
    );
  }
  if (params.toLeaseRole === "RECEIVE_WINDOW") {
    throw new LeaseError(
      "TRANSFER_ROLE_INVALID",
      "hand-off cannot target RECEIVE_WINDOW; child move uses MOVE_SOURCE",
      params.walletId,
    );
  }
  if (params.fromOperationId === params.toOperationId) {
    throw new LeaseError(
      "TRANSFER_ROLE_INVALID",
      "hand-off requires a distinct child operation_id",
      params.walletId,
    );
  }

  // Lock sequence — byte-identical prefix to releaseLease: group → group ops → group active
  // rows → group open memberships → wallet → that wallet's active row → proof. The
  // group-scoped active/membership locks must precede the wallets row: releaseLease takes
  // them that early, and reaching them after the wallet lock here is the inversion that
  // deadlocked concurrent hand-off ∥ release on one group.
  const groupResult = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [
    params.leaseGroupId,
  ]);
  const group = groupResult.rows[0];
  if (!group) {
    throw new LeaseError(
      "GROUP_OPERATION_MISSING",
      "lease group does not exist",
      params.walletId,
    );
  }
  if (group.released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "cannot hand off inside an already-released lease group",
      params.walletId,
    );
  }

  const groupOps = await db.query<GroupOperationRow>(STATEMENTS.LOCK_GROUP_OPERATIONS, [
    params.leaseGroupId,
  ]);
  const childJoined = groupOps.rows.some((o) => o.operation_id === params.toOperationId);
  if (!childJoined) {
    throw new LeaseError(
      "TRANSFER_TARGET_NOT_JOINED",
      "child operation is not a member of this lease group; joinLeaseGroupOperation first",
      params.walletId,
    );
  }
  const parentJoined = groupOps.rows.some((o) => o.operation_id === params.fromOperationId);
  if (!parentJoined) {
    throw new LeaseError(
      "GROUP_OPERATION_MISSING",
      "parent operation is not a member of this lease group",
      params.walletId,
    );
  }

  await db.query<ActiveLeaseRow>(STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [params.leaseGroupId]);
  await db.query<OpenMembershipRow>(STATEMENTS.LOCK_GROUP_OPEN_MEMBERSHIPS, [
    params.leaseGroupId,
  ]);

  const activeResult = await db.query<ActiveLeaseRow>(STATEMENTS.SELECT_ACTIVE_FOR_UPDATE, [
    params.walletId,
  ]);
  const active = activeResult.rows[0];
  if (!active) {
    throw new LeaseError("NO_ACTIVE_LEASE", "no active lease to transfer", params.walletId);
  }
  // Wallet row last of the two, so an active row belonging to another group (mismatched
  // leaseGroupId below) cannot invert against a release holding it group-wide.
  await lockWallet(db, params.walletId);

  if (active.owner_instance_id !== params.ownerInstanceId) {
    throw new LeaseError(
      "LEASE_OWNER_MISMATCH",
      "active lease is held by a different instance",
      params.walletId,
    );
  }
  if (active.operation_id !== params.fromOperationId) {
    throw new LeaseError(
      "LEASE_OPERATION_MISMATCH",
      "fromOperationId does not match the active lease",
      params.walletId,
    );
  }
  if (active.membership_id !== params.membershipId) {
    throw new LeaseError(
      "LEASE_MEMBERSHIP_MISMATCH",
      "membership_id does not match the active lease",
      params.walletId,
    );
  }
  if (active.lease_group_id !== params.leaseGroupId) {
    throw new LeaseError(
      "LEASE_GROUP_MISMATCH",
      "lease_group_id does not match the active lease",
      params.walletId,
    );
  }
  if (BigInt(active.lease_epoch) !== params.leaseEpoch) {
    throw new LeaseError(
      "LEASE_EPOCH_MISMATCH",
      "lease_epoch does not match the active lease (stale capability)",
      params.walletId,
    );
  }
  if (active.root_operation_id !== group.root_operation_id) {
    throw new LeaseError(
      "LEASE_GROUP_MISMATCH",
      "active root_operation_id diverges from lease group root",
      params.walletId,
    );
  }

  const proofResult = await db.query<ProofRow>(STATEMENTS.LOCK_PROOF, [params.releaseProofId]);
  const proof = proofResult.rows[0];
  if (!proof) {
    throw new LeaseError("PROOF_NOT_FOUND", "release proof does not exist", params.walletId);
  }
  if (proof.issuer !== "TRUSTED_VERIFIER") {
    throw new LeaseError("PROOF_UNTRUSTED", "proof issuer is not TRUSTED_VERIFIER", params.walletId);
  }
  if (proof.consumed_at !== null) {
    throw new LeaseError("PROOF_ALREADY_CONSUMED", "proof was already consumed (replay)", params.walletId);
  }
  if (
    proof.wallet_id !== params.walletId ||
    proof.operation_id !== params.fromOperationId ||
    proof.membership_id !== params.membershipId ||
    proof.lease_group_id !== params.leaseGroupId ||
    BigInt(proof.lease_epoch) !== params.leaseEpoch
  ) {
    throw new LeaseError(
      "PROOF_FOREIGN",
      "proof tuple does not match the parent lease (foreign or stale)",
      params.walletId,
    );
  }

  const now = new Date();
  const nowIso = now.toISOString();

  // 1. Close parent membership (permanent record; exclusivity stays on active row).
  const close = await db.query(STATEMENTS.CLOSE_MEMBERSHIP, [
    params.membershipId,
    nowIso,
    params.releaseReason,
    params.releaseProofId,
  ]);
  if ((close.rowCount ?? 0) !== 1) {
    throw new LeaseError(
      "DELETE_NOT_EXACT",
      "parent membership close did not affect exactly one row",
      params.walletId,
    );
  }

  // 2. Consume the parent terminal-positive proof (single-use).
  const consume = await db.query(STATEMENTS.CONSUME_PROOF, [params.releaseProofId, nowIso]);
  if ((consume.rowCount ?? 0) !== 1) {
    throw new LeaseError(
      "PROOF_ALREADY_CONSUMED",
      "proof consume did not affect exactly one row",
      params.walletId,
    );
  }

  // 3. Open child membership at a strictly greater epoch (ABA safety).
  const nextLeaseEpoch = await nextEpoch(db, params.walletId);
  const childMembershipId = randomUUID();
  await db.query(STATEMENTS.INSERT_MEMBERSHIP, [
    childMembershipId,
    params.leaseGroupId,
    params.walletId,
    params.toOperationId,
    params.toLeaseRole,
    nextLeaseEpoch.toString(),
    nowIso,
  ]);

  // 4. Re-point the uninterrupted active row — never DELETE.
  const transferred = await db.query(STATEMENTS.TRANSFER_ACTIVE, [
    params.walletId,
    childMembershipId,
    params.toOperationId,
    params.toLeaseRole,
    nextLeaseEpoch.toString(),
    nowIso,
    params.membershipId,
    params.leaseGroupId,
    params.fromOperationId,
    params.leaseEpoch.toString(),
    params.ownerInstanceId,
  ]);
  if ((transferred.rowCount ?? 0) !== 1) {
    throw new LeaseError(
      "DELETE_NOT_EXACT",
      "active-row hand-off UPDATE did not affect exactly one row",
      params.walletId,
    );
  }

  await audit(db, "LEASE_PROOF_CONSUMED", {
    walletId: params.walletId,
    operationId: params.fromOperationId,
    membershipId: params.membershipId,
    leaseGroupId: params.leaseGroupId,
    leaseEpoch: params.leaseEpoch,
    ownerInstanceId: params.ownerInstanceId,
    details: { proof_id: params.releaseProofId, handoff: true },
  });
  await audit(db, "LEASE_TRANSFERRED", {
    walletId: params.walletId,
    operationId: params.toOperationId,
    membershipId: childMembershipId,
    leaseGroupId: params.leaseGroupId,
    leaseEpoch: nextLeaseEpoch,
    ownerInstanceId: params.ownerInstanceId,
    details: {
      from_operation_id: params.fromOperationId,
      to_operation_id: params.toOperationId,
      previous_membership_id: params.membershipId,
      previous_lease_epoch: params.leaseEpoch.toString(),
      to_lease_role: params.toLeaseRole,
      release_reason: params.releaseReason,
      root_operation_id: active.root_operation_id,
    },
  });

  return {
    walletId: params.walletId,
    previousMembershipId: params.membershipId,
    membershipId: childMembershipId,
    leaseEpoch: nextLeaseEpoch,
    leaseRole: params.toLeaseRole,
    operationId: params.toOperationId,
    rootOperationId: active.root_operation_id,
  };
}

/**
 * Receive → child-move hand-off, phase B (step 3): the child
 * operation, which already owns the source lease in this group, "atomically adds only the
 * destination after verifying group ownership".
 *
 * Deliberately its own transaction. If busy, the child remains `CREATED` and the source
 * lease remains continuously held — so a busy destination must roll back this call
 * alone and leave phase A's committed source re-point untouched. All-or-nothing across the
 * destinations themselves still holds ("If either insert conflicts, the transaction
 * rolls back and holds neither").
 *
 * Caller holds a SERIALIZABLE transaction.
 */
export async function acquireGroupDestinationLeases(
  db: SqlExecutor,
  params: AcquireGroupDestinationLeasesParams,
): Promise<AcquiredLease[]> {
  await assertLeaseFoundationReady(db);
  if (params.destinations.length === 0) return [];

  // Same lock sequence as every other mutator: group → group ops → group active rows → wallets.
  const groupResult = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [
    params.leaseGroupId,
  ]);
  const group = groupResult.rows[0];
  if (!group) {
    throw new LeaseError("GROUP_OPERATION_MISSING", "lease group does not exist");
  }
  if (group.released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "cannot join a destination to an already-released lease group",
    );
  }

  const groupOps = await db.query<GroupOperationRow>(STATEMENTS.LOCK_GROUP_OPERATIONS, [
    params.leaseGroupId,
  ]);
  if (!groupOps.rows.some((o) => o.operation_id === params.operationId)) {
    throw new LeaseError(
      "TRANSFER_TARGET_NOT_JOINED",
      "operation is not a member of this lease group; joinLeaseGroupOperation first",
    );
  }

  // Group ownership: the operation must already hold a lease here (phase A committed).
  const groupActive = await db.query<ActiveLeaseRow>(STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [
    params.leaseGroupId,
  ]);
  const owned = groupActive.rows.find((row) => row.operation_id === params.operationId);
  if (!owned) {
    throw new LeaseError(
      "GROUP_OWNERSHIP_MISSING",
      "operation holds no active lease in this group; the source hand-off must commit first",
    );
  }
  if (owned.owner_instance_id !== params.ownerInstanceId) {
    throw new LeaseError(
      "LEASE_OWNER_MISMATCH",
      "group lease is held by a different instance",
      owned.wallet_id,
    );
  }

  // root_operation_id comes off the held row, never the caller: a destination may not join
  // under a root the group does not already carry.
  return acquireLeases(db, {
    wallets: params.destinations,
    leaseGroupId: params.leaseGroupId,
    rootOperationId: owned.root_operation_id,
    operationId: params.operationId,
    ownerInstanceId: params.ownerInstanceId,
  });
}

/**
 * Join a child operation into an existing lease group (receive → automatic child move).
 * Permanent membership; does not acquire wallets. Caller holds SERIALIZABLE tx.
 */
export async function joinLeaseGroupOperation(
  db: SqlExecutor,
  params: JoinLeaseGroupParams,
): Promise<void> {
  await assertLeaseFoundationReady(db);
  const group = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [params.leaseGroupId]);
  if (!group.rows[0]) {
    throw new LeaseError("GROUP_OPERATION_MISSING", "lease group does not exist");
  }
  if (group.rows[0].released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "cannot join an operation to an already-released lease group",
    );
  }
  const now = new Date().toISOString();
  await db.query(STATEMENTS.INSERT_GROUP_OPERATION, [
    params.leaseGroupId,
    params.operationId,
    now,
  ]);
  // PENDING → JOINED once the child op row exists (formation complete).
  // NONE stays NONE (joining extra ops on a HOLD group is unusual but allowed).
  if (group.rows[0].child_disposition === "PENDING") {
    const marked = await db.query(STATEMENTS.MARK_CHILD_JOINED, [params.leaseGroupId]);
    if ((marked.rowCount ?? 0) !== 1) {
      throw new LeaseError(
        "DELETE_NOT_EXACT",
        "child disposition mark JOINED did not affect exactly one row",
      );
    }
  }
}

/**
 * Mark one group operation terminal (verification-complete durable ack). One-way.
 * Does not release wallets — release still requires proof-backed releaseLease.
 */
export async function completeGroupOperation(
  db: SqlExecutor,
  params: CompleteGroupOperationParams,
): Promise<void> {
  await assertLeaseFoundationReady(db);
  const group = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [params.leaseGroupId]);
  if (!group.rows[0]) {
    throw new LeaseError("GROUP_OPERATION_MISSING", "lease group does not exist");
  }
  if (group.rows[0].released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "lease group is already released",
    );
  }
  const now = new Date().toISOString();
  const result = await db.query(STATEMENTS.COMPLETE_GROUP_OPERATION, [
    params.leaseGroupId,
    params.operationId,
    now,
  ]);
  if ((result.rowCount ?? 0) !== 1) {
    // Either missing membership or already completed — distinguish for callers.
    const ops = await db.query<GroupOperationRow>(STATEMENTS.LOCK_GROUP_OPERATIONS, [
      params.leaseGroupId,
    ]);
    const row = ops.rows.find((o) => o.operation_id === params.operationId);
    if (!row) {
      throw new LeaseError(
        "GROUP_OPERATION_MISSING",
        "operation is not a member of this lease group",
      );
    }
    // Already completed: idempotent no-op (durable ack may retry).
  }
}

/**
 * Proof-backed release. Requires owner instance + exact tuple + unconsumed trusted proof
 * AND the collective lease-group terminal predicate: child_disposition
 * is not PENDING and every joined operation has completed_at set before any membership close,
 * proof consume, active-row DELETE, or wallet unpin. Foreign/stale/replayed proofs mutate
 * nothing. Exact-tuple DELETE must affect one row. Group release stamp is written only when
 * the last open membership closes.
 */
export async function releaseLease(
  db: SqlExecutor,
  params: ReleaseLeaseParams,
): Promise<ReleasedLease> {
  await assertLeaseFoundationReady(db);

  // Lock sequence: group → group ops → group active rows → open memberships → target active
  // row → target wallet → proof. Every mutator here follows that one sequence; an active
  // lease row is always locked before the wallets row it points at, and `wallets` is never
  // taken before the lease group. Identity/proof failures surface before GROUP_NOT_TERMINAL
  // so callers retain precise mismatch reasons; the terminal check still runs before any
  // mutation.
  const groupResult = await db.query<LeaseGroupRow>(STATEMENTS.LOCK_LEASE_GROUP, [
    params.leaseGroupId,
  ]);
  const group = groupResult.rows[0];
  if (!group) {
    throw new LeaseError(
      "GROUP_OPERATION_MISSING",
      "lease group does not exist",
      params.walletId,
    );
  }
  if (group.released_at !== null) {
    throw new LeaseError(
      "GROUP_ALREADY_RELEASED",
      "lease group is already released",
      params.walletId,
    );
  }

  const groupOps = await db.query<GroupOperationRow>(STATEMENTS.LOCK_GROUP_OPERATIONS, [
    params.leaseGroupId,
  ]);
  if (groupOps.rows.length === 0) {
    throw new LeaseError(
      "GROUP_OPERATION_MISSING",
      "lease group has no operation memberships",
      params.walletId,
    );
  }

  await db.query<ActiveLeaseRow>(STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [params.leaseGroupId]);
  const openMemberships = await db.query<OpenMembershipRow>(
    STATEMENTS.LOCK_GROUP_OPEN_MEMBERSHIPS,
    [params.leaseGroupId],
  );

  const activeResult = await db.query<ActiveLeaseRow>(STATEMENTS.SELECT_ACTIVE_FOR_UPDATE, [
    params.walletId,
  ]);
  const active = activeResult.rows[0];
  if (!active) {
    throw new LeaseError("NO_ACTIVE_LEASE", "no active lease to release", params.walletId);
  }
  const wallet = await lockWallet(db, params.walletId);

  if (active.owner_instance_id !== params.ownerInstanceId) {
    throw new LeaseError(
      "LEASE_OWNER_MISMATCH",
      "active lease is held by a different instance",
      params.walletId,
    );
  }
  if (active.operation_id !== params.operationId) {
    throw new LeaseError(
      "LEASE_OPERATION_MISMATCH",
      "operation_id does not match the active lease",
      params.walletId,
    );
  }
  if (active.membership_id !== params.membershipId) {
    throw new LeaseError(
      "LEASE_MEMBERSHIP_MISMATCH",
      "membership_id does not match the active lease",
      params.walletId,
    );
  }
  if (active.lease_group_id !== params.leaseGroupId) {
    throw new LeaseError(
      "LEASE_GROUP_MISMATCH",
      "lease_group_id does not match the active lease",
      params.walletId,
    );
  }
  if (BigInt(active.lease_epoch) !== params.leaseEpoch) {
    throw new LeaseError(
      "LEASE_EPOCH_MISMATCH",
      "lease_epoch does not match the active lease (stale capability)",
      params.walletId,
    );
  }

  const proofResult = await db.query<ProofRow>(STATEMENTS.LOCK_PROOF, [params.releaseProofId]);
  const proof = proofResult.rows[0];
  if (!proof) {
    throw new LeaseError("PROOF_NOT_FOUND", "release proof does not exist", params.walletId);
  }
  if (proof.issuer !== "TRUSTED_VERIFIER") {
    throw new LeaseError("PROOF_UNTRUSTED", "proof issuer is not TRUSTED_VERIFIER", params.walletId);
  }
  if (proof.consumed_at !== null) {
    throw new LeaseError("PROOF_ALREADY_CONSUMED", "proof was already consumed (replay)", params.walletId);
  }
  if (
    proof.wallet_id !== params.walletId ||
    proof.operation_id !== params.operationId ||
    proof.membership_id !== params.membershipId ||
    proof.lease_group_id !== params.leaseGroupId ||
    BigInt(proof.lease_epoch) !== params.leaseEpoch
  ) {
    throw new LeaseError(
      "PROOF_FOREIGN",
      "proof tuple does not match the active lease (foreign or stale)",
      params.walletId,
    );
  }

  // Collective predicate: refuse while a declared child is still pre-formation
  // (PENDING) or any joined group operation is non-terminal. HOLD/NONE with only the
  // root op complete remains releasable.
  if (group.child_disposition === "PENDING") {
    throw new LeaseError(
      "GROUP_NOT_TERMINAL",
      "lease group awaits child operation formation (child_disposition=PENDING)",
      params.walletId,
    );
  }
  const incomplete = groupOps.rows.filter((op) => op.completed_at === null);
  if (incomplete.length > 0) {
    throw new LeaseError(
      "GROUP_NOT_TERMINAL",
      `lease group is not terminal; incomplete operations: ${incomplete
        .map((o) => o.operation_id)
        .join(",")}`,
      params.walletId,
    );
  }

  const now = new Date();
  const nowIso = now.toISOString();

  const close = await db.query(STATEMENTS.CLOSE_MEMBERSHIP, [
    params.membershipId,
    nowIso,
    params.releaseReason,
    params.releaseProofId,
  ]);
  if ((close.rowCount ?? 0) !== 1) {
    throw new LeaseError("DELETE_NOT_EXACT", "membership close did not affect exactly one row", params.walletId);
  }

  const consume = await db.query(STATEMENTS.CONSUME_PROOF, [params.releaseProofId, nowIso]);
  if ((consume.rowCount ?? 0) !== 1) {
    throw new LeaseError("PROOF_ALREADY_CONSUMED", "proof consume did not affect exactly one row", params.walletId);
  }

  const del = await db.query(STATEMENTS.DELETE_ACTIVE_EXACT, [
    params.walletId,
    params.membershipId,
    params.leaseGroupId,
    params.operationId,
    params.leaseEpoch.toString(),
    params.ownerInstanceId,
  ]);
  const deletedRows = del.rowCount ?? 0;
  if (deletedRows !== 1) {
    throw new LeaseError(
      "DELETE_NOT_EXACT",
      `exact-tuple DELETE affected ${deletedRows} rows; required 1`,
      params.walletId,
    );
  }

  // Ops are all terminal (checked above), so this wallet may leave the exclusive table and
  // unpin. Sibling wallets remain held until their own proof-backed release. Stamp the group
  // released only when no open memberships remain after this close (one-way fields).
  const remainingOpen = openMemberships.rows.filter((m) => m.id !== params.membershipId);
  const groupFullyReleased = remainingOpen.length === 0;

  if (wallet.state === "PINNED") {
    await db.query(STATEMENTS.UNPIN_WALLET, [params.walletId]);
  }

  if (groupFullyReleased) {
    const groupRelease = await db.query(STATEMENTS.RELEASE_LEASE_GROUP, [
      params.leaseGroupId,
      nowIso,
      params.releaseProofId,
    ]);
    if ((groupRelease.rowCount ?? 0) !== 1) {
      throw new LeaseError(
        "DELETE_NOT_EXACT",
        "lease group release stamp did not affect exactly one row",
        params.walletId,
      );
    }
  }

  await audit(db, "LEASE_PROOF_CONSUMED", {
    walletId: params.walletId,
    operationId: params.operationId,
    membershipId: params.membershipId,
    leaseGroupId: params.leaseGroupId,
    leaseEpoch: params.leaseEpoch,
    ownerInstanceId: params.ownerInstanceId,
    details: { proof_id: params.releaseProofId },
  });
  await audit(db, "LEASE_RELEASED", {
    walletId: params.walletId,
    operationId: params.operationId,
    membershipId: params.membershipId,
    leaseGroupId: params.leaseGroupId,
    leaseEpoch: params.leaseEpoch,
    ownerInstanceId: params.ownerInstanceId,
    details: {
      release_reason: params.releaseReason,
      deleted_rows: deletedRows,
      group_released: groupFullyReleased,
    },
  });

  return {
    membershipId: params.membershipId,
    releasedAt: now,
    deletedRows,
    groupReleased: groupFullyReleased,
  };
}

/**
 * Signer capability check: locks the active lease row and validates wallet/operation/epoch/owner
 * before any private-key use. Non-interleavable with key use when the caller holds this
 * transaction open across the sign call. Private keys remain outside the hosted platform.
 */
export async function assertSignCapability(
  db: SqlExecutor,
  params: SignCapabilityParams,
): Promise<ActiveLeaseRow> {
  await assertLeaseFoundationReady(db);
  // Active row before the wallets row, matching releaseLease. The reverse sequence raced a
  // concurrent release of this very wallet into a deadlock on the signing path.
  const activeResult = await db.query<ActiveLeaseRow>(STATEMENTS.SELECT_ACTIVE_FOR_UPDATE, [
    params.walletId,
  ]);
  const active = activeResult.rows[0];
  if (!active) {
    throw new LeaseError("NO_ACTIVE_LEASE", "no active lease for sign capability", params.walletId);
  }
  await lockWallet(db, params.walletId);
  if (active.owner_instance_id !== params.ownerInstanceId) {
    throw new LeaseError("LEASE_OWNER_MISMATCH", "sign owner mismatch", params.walletId);
  }
  if (active.operation_id !== params.operationId) {
    throw new LeaseError("LEASE_OPERATION_MISMATCH", "sign operation mismatch", params.walletId);
  }
  if (BigInt(active.lease_epoch) !== params.leaseEpoch) {
    throw new LeaseError(
      "SIGN_CAPABILITY_MISMATCH",
      "sign epoch mismatch (stale capability / ABA)",
      params.walletId,
    );
  }
  await audit(db, "LEASE_SIGN_CLAIM", {
    walletId: params.walletId,
    operationId: params.operationId,
    membershipId: active.membership_id,
    leaseGroupId: active.lease_group_id,
    leaseEpoch: params.leaseEpoch,
    ownerInstanceId: params.ownerInstanceId,
    details: { claimed: true },
  });
  return active;
}

export async function renewLeaseHeartbeat(
  db: SqlExecutor,
  walletId: string,
  ownerInstanceId: string,
): Promise<void> {
  await assertLeaseFoundationReady(db);
  const result = await db.query(STATEMENTS.HEARTBEAT, [
    walletId,
    ownerInstanceId,
    new Date().toISOString(),
  ]);
  if ((result.rowCount ?? 0) !== 1) {
    throw new LeaseError(
      "NO_ACTIVE_LEASE",
      "no active lease owned by this instance to renew",
      walletId,
    );
  }
  await audit(db, "LEASE_HEARTBEAT", {
    walletId,
    ownerInstanceId,
    details: { renewed: true },
  });
}

export async function createLeaseGroup(
  db: SqlExecutor,
  rootOperationIdOrParams: string | CreateLeaseGroupParams,
): Promise<string> {
  await assertLeaseFoundationReady(db);
  const params: CreateLeaseGroupParams =
    typeof rootOperationIdOrParams === "string"
      ? { rootOperationId: rootOperationIdOrParams }
      : rootOperationIdOrParams;
  const childDisposition: LeaseGroupChildDisposition =
    params.childDisposition === "PENDING" ? "PENDING" : "NONE";
  const id = randomUUID();
  const now = new Date().toISOString();
  await db.query(STATEMENTS.INSERT_LEASE_GROUP, [
    id,
    params.rootOperationId,
    now,
    childDisposition,
  ]);
  await db.query(STATEMENTS.INSERT_GROUP_OPERATION, [id, params.rootOperationId, now]);
  return id;
}

export { isOperationRole, sortWalletIdsAscending };
