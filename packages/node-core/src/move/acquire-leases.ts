// MOVE_INTERNAL dual-lease acquisition (step 1).
//
// Two-wallet acquisition is atomic and sequenced by ascending binary UUID value. If either
// wallet cannot be leased, neither lease is acquired, and that sequencing is mandatory in
// every worker recovery path: operations needing two wallets acquire both rows in ascending
// `wallet_id` byte sequence inside one database transaction. If either insert conflicts the
// transaction rolls back and holds neither.
//
// The sort, the all-or-nothing insert loop, the eligibility gate and the group-ownership
// read all live in the lease repository (src/leases) — the single canonical
// implementation every two-wallet operation shares. Re-sorting here would be a second
// comparator, which is precisely the deadlock class that sequencing rule forbids.
//
// What this module adds is the MOVE binding:
// 1. path selection — a top-level move acquires BOTH wallets; a receive-spawned child
// already owns the source in its group and adds ONLY the destination;
// 2. the transaction boundary — a LeaseError has already rolled the transaction back
// before it becomes a typed outcome here, so no caller can commit a half-acquired
// pair by handling a return value;
// 3. the API mapping — a busy explicitly-selected wallet becomes `wallet_busy`
// (409), while an automatic child stays `CREATED` and visibly queued instead.
//
// The one-in-flight-per-wallet rule (one in-flight transaction per wallet) is what all of the above defends.
// No private key is touched here (the key-custody rule): the lease is the capability the signer
// is later handed, never the key.

import {
  LeaseError,
  STATEMENTS as LEASE_STATEMENTS,
  acquireGroupDestinationLeases,
  acquireLeases,
} from "../leases/index.js";
import type {
  AcquiredLease,
  ActiveLeaseRow,
  LeaseErrorReason,
  SqlExecutor,
} from "../leases/index.js";

import type { MoveRejectionCode } from "./create.js";

/**
 * Transaction port (node-core carries no SQL driver). Typed over the lease
 * repository's `SqlExecutor` rather than the admission store's: this is the executor the
 * lease mutators actually run on, and one BEGIN/COMMIT must wrap the whole pair.
 */
export type MoveLeaseTxFn = <T>(body: (tx: SqlExecutor) => Promise<T>) => Promise<T>;

/** A move leases source and destination — both, before either T0 read. */
export const MOVE_SOURCE_LEASE_ROLE = "MOVE_SOURCE" as const;
export const MOVE_DESTINATION_LEASE_ROLE = "MOVE_DESTINATION" as const;

export interface HeldMoveLease {
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseEpoch: bigint;
}

export interface MoveLeaseRequest {
  readonly operationId: string;
  /** Created by admission: a fresh group, or the parent receive's group. */
  readonly leaseGroupId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly ownerInstanceId: string;
  /**
   * Non-null ⇒ receive-spawned child: the source lease is already held by this
   * operation inside `leaseGroupId`, so only the destination is inserted.
   */
  readonly spawnedFromOperationId: string | null;
}

export type MoveLeaseOutcome =
  | {
      readonly outcome: "HELD";
      readonly source: HeldMoveLease;
      readonly destination: HeldMoveLease;
    }
  /** Public path: an explicitly selected wallet is already leased → 409. */
  | { readonly outcome: "WALLET_BUSY"; readonly walletId: string }
  /** Automatic-child path, step 3: stay CREATED; the source stays continuously held. */
  | { readonly outcome: "CHILD_WAITING"; readonly walletId: string }
  /** Child path invariant: the group does not hold the source for this operation. */
  | { readonly outcome: "SOURCE_NOT_HELD"; readonly walletId: string; readonly detail: string }
  | {
      readonly outcome: "NOT_ELIGIBLE";
      readonly walletId: string | null;
      readonly reason: LeaseErrorReason | "CUSTODY_REJECTED";
      readonly detail: string;
    };

/**
 * Step 1. Runs its OWN transaction: every failure path below has already been
 * rolled back by the time it is returned as a value, so "commit all or none" cannot be
 * defeated by a caller that treats the outcome as ordinary control flow.
 */
export async function acquireMoveLeases(
  withTransaction: MoveLeaseTxFn,
  request: MoveLeaseRequest,
): Promise<MoveLeaseOutcome> {
  const isChild = request.spawnedFromOperationId !== null;
  try {
    const held = await withTransaction(async (tx) =>
      isChild ? acquireChildDestination(tx, request) : acquireBothWallets(tx, request),
    );
    return { outcome: "HELD", source: held.source, destination: held.destination };
  } catch (err) {
    return classifyAcquisitionFailure(err, request, isChild);
  }
}

interface HeldPair {
  readonly source: HeldMoveLease;
  readonly destination: HeldMoveLease;
}

/**
 * Top-level move: both rows inside one transaction. The wallets are listed source-first
 * for readability only — `acquireLeases` sorts them by ascending raw UUID bytes
 * before touching anything, so two operations taking the same pair from opposite
 * request orderings still lock it in the same sequence.
 */
async function acquireBothWallets(tx: SqlExecutor, request: MoveLeaseRequest): Promise<HeldPair> {
  const acquired = await acquireLeases(tx, {
    wallets: [
      { walletId: request.sourceWalletId, leaseRole: MOVE_SOURCE_LEASE_ROLE },
      { walletId: request.destinationWalletId, leaseRole: MOVE_DESTINATION_LEASE_ROLE },
    ],
    leaseGroupId: request.leaseGroupId,
    rootOperationId: request.operationId,
    operationId: request.operationId,
    ownerInstanceId: request.ownerInstanceId,
  });
  return {
    source: pick(acquired, request.sourceWalletId),
    destination: pick(acquired, request.destinationWalletId),
  };
}

/**
 * Receive-spawned child (step 3 / step 1): "child already owns source lease in
 * group atomically adds only destination verifying group ownership". The source is never
 * re-inserted — that would hit the `wallet_active_leases` primary key and roll back a
 * hand-off that already committed.
 */
async function acquireChildDestination(
  tx: SqlExecutor,
  request: MoveLeaseRequest,
): Promise<HeldPair> {
  const acquired = await acquireGroupDestinationLeases(tx, {
    leaseGroupId: request.leaseGroupId,
    operationId: request.operationId,
    ownerInstanceId: request.ownerInstanceId,
    destinations: [
      { walletId: request.destinationWalletId, leaseRole: MOVE_DESTINATION_LEASE_ROLE },
    ],
  });

  // acquireGroupDestinationLeases proves the operation owns SOME lease in the group; a move
  // additionally requires that lease to be the declared source, or the signer would later be
  // handed a capability for a wallet this operation never leased. Read AFTER the acquire on
  // purpose: that call already holds the group's active rows FOR UPDATE, so this repeats an
  // owned lock instead of inverting the group → wallets sequence every lease mutator follows.
  const groupActive = await tx.query<ActiveLeaseRow>(LEASE_STATEMENTS.LOCK_GROUP_ACTIVE_LEASES, [
    request.leaseGroupId,
  ]);
  const sourceRow = groupActive.rows.find(
    (row) => row.wallet_id === request.sourceWalletId && row.operation_id === request.operationId,
  );
  if (sourceRow === undefined) {
    throw new LeaseError(
      "GROUP_OWNERSHIP_MISSING",
      "child move does not hold the source lease in this lease group",
      request.sourceWalletId,
    );
  }

  return {
    source: {
      walletId: sourceRow.wallet_id,
      membershipId: sourceRow.membership_id,
      leaseEpoch: BigInt(sourceRow.lease_epoch),
    },
    destination: pick(acquired, request.destinationWalletId),
  };
}

function pick(acquired: readonly AcquiredLease[], walletId: string): HeldMoveLease {
  const found = acquired.find((lease) => lease.walletId === walletId);
  if (found === undefined) {
    throw new LeaseError("NO_ACTIVE_LEASE", "acquisition returned no lease for wallet", walletId);
  }
  return {
    walletId: found.walletId,
    membershipId: found.membershipId,
    leaseEpoch: found.leaseEpoch,
  };
}

/**
 * Receive-gate enforcement: the `BEFORE INSERT` custody trigger is the structural backstop that fires
 * whichever application query reached the insert. Its RAISE is an eligibility verdict, not an
 * internal fault, so it must not collapse into a generic 503.
 */
function custodyRejectionDetail(err: unknown): string | null {
  const message = err instanceof Error ? err.message : String(err);
  return /CUSTODY_[A-Z_]+/.test(message) ? message : null;
}

function classifyAcquisitionFailure(
  err: unknown,
  request: MoveLeaseRequest,
  isChild: boolean,
): MoveLeaseOutcome {
  if (err instanceof LeaseError) {
    switch (err.reason) {
      case "ALREADY_LEASED":
        // "Explicitly selected busy wallets return 409 wallet_busy; the node does
        // not create a second operation to wait invisibly behind an active wallet. An
        // automatic child remains CREATED and is visibly queued within its existing lease
        // group." The child's source lease is untouched — this call rolled back only itself.
        return isChild
          ? { outcome: "CHILD_WAITING", walletId: err.walletId ?? request.destinationWalletId }
          : { outcome: "WALLET_BUSY", walletId: err.walletId ?? request.sourceWalletId };
      case "GROUP_OWNERSHIP_MISSING":
        return {
          outcome: "SOURCE_NOT_HELD",
          walletId: request.sourceWalletId,
          detail: err.message,
        };
      case "WALLET_NOT_ELIGIBLE":
      case "WALLET_NOT_FOUND":
      case "NON_OPERATION_ROLE":
      case "DUPLICATE_WALLET_ID":
        return {
          outcome: "NOT_ELIGIBLE",
          walletId: err.walletId ?? null,
          reason: err.reason,
          detail: err.message,
        };
      default:
        // Group missing / released / not joined are sequencing faults, not admission
        // verdicts. Surfacing them as an outcome would let a caller retry into a lie.
        throw err;
    }
  }
  const custody = custodyRejectionDetail(err);
  if (custody !== null) {
    return {
      outcome: "NOT_ELIGIBLE",
      walletId: null,
      reason: "CUSTODY_REJECTED",
      detail: custody,
    };
  }
  throw err;
}

/**
 * API mapping for the PUBLIC create path. `HELD` and `CHILD_WAITING` are not rejections —
 * the automatic child stays `CREATED` and visibly queued — so both map to null and the caller
 * leaves the operation alone. Every other outcome is thrown by the caller as a
 * `MoveAdmissionError`, which the operation route already renders through the frozen
 * taxonomy (`wallet_busy` → 409, eligibility → 422 `protocol_predicate_failed`).
 */
export function moveLeaseRejectionCode(
  outcome: MoveLeaseOutcome,
  sourceWalletId: string,
): MoveRejectionCode | null {
  switch (outcome.outcome) {
    case "HELD":
    case "CHILD_WAITING":
      return null;
    case "WALLET_BUSY":
      return "wallet_busy";
    case "SOURCE_NOT_HELD":
      return "source_wallet_not_eligible";
    case "NOT_ELIGIBLE":
      return outcome.walletId === sourceWalletId
        ? "source_wallet_not_eligible"
        : "destination_not_eligible";
  }
}
