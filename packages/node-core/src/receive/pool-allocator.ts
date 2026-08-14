// Bounded receive-pool allocator.
//
// Request admission and wallet assignment under the four pool limits and the five-step
// admission ladder, with the attention hold, the recovery_verified_at gate, and
// receive-gate enforcement.
//
// Three surfaces:
// admitReceive — cap gate, 202 or 503, zero partial rows.
// assignReceiveWallet — frozen eligibility select + the one DB-TX.
// promoteQueuedReceives — FIFO promotion by (created_at, operation_id).
//
// The one-in-flight-per-wallet rule is not re-implemented here: it is enforced structurally by
// wallet_active_leases.wallet_id PRIMARY KEY and by operation_wallets'
// UNIQUE (operation_id, operation_role). This module's job is to route every receive
// assignment through those constraints and never around them. The key-custody rule holds
// trivially — no key material is read, derived or written on this path.
//
// Driver-agnostic: the composition root injects SqlExecutor; every mutator runs
// inside the caller's SERIALIZABLE transaction and throws so that transaction rolls back.

/**
 * Narrow node-postgres-shaped surface. `pg.Pool` / `pg.PoolClient` satisfy it. Declared
 * locally rather than imported: `receive` is a leaf in the node-core dependency map
 * (test/boundaries.test.ts), and receive/arm-sql.ts declares its own executor the same way.
 */
export interface SqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[]; readonly rowCount?: number | null }>;
}

/**
 * The lease-foundation calls this allocator makes, injected for the same leaf-module reason
 * as SqlExecutor above. The composition root binds node-core's lease repository
 * (`createLeaseGroup` / `acquireLeases`); nothing here reaches into that module directly.
 */
export interface ReceiveLeasePort {
  /** Creates the receive's own lease group and returns its id. */
  readonly createLeaseGroup: (db: SqlExecutor, rootOperationId: string) => Promise<string>;
  /**
   * Acquires the wallet's `RECEIVE_WINDOW` lease: membership row, the exclusive
   * wallet_active_leases row, then `AVAILABLE → PINNED`. That internal sequence is
   * normative and belongs to the lease foundation, not to this module.
   */
  readonly acquireReceiveWindowLease: (
    db: SqlExecutor,
    params: {
      readonly walletId: string;
      readonly leaseGroupId: string;
      readonly operationId: string;
      readonly ownerInstanceId: string;
    },
  ) => Promise<{ readonly membershipId: string; readonly leaseEpoch: bigint }>;
}

/**
 * Allocator-side failures. Distinct from the lease foundation's own error type on purpose:
 * these describe the receive's standing, not the wallet's, and callers switch on `reason`
 * to pick an HTTP shape. Thrown inside the caller's transaction so it rolls back.
 */
export type ReceiveAllocatorErrorReason =
  | "RECEIVE_NOT_FOUND"
  | "RECEIVE_NOT_CREATED"
  | "RECEIVE_ALREADY_ASSIGNED"
  | "QUEUE_CAP_INVALID"
  | "LEASE_ACQUISITION_EMPTY";

export class ReceiveAllocatorError extends Error {
  readonly reason: ReceiveAllocatorErrorReason;
  readonly operationId: string | undefined;

  constructor(reason: ReceiveAllocatorErrorReason, detail: string, operationId?: string) {
    super(
      `ReceiveAllocatorError[${reason}]${operationId ? ` operation=${operationId}` : ""}: ${detail}`,
    );
    this.name = "ReceiveAllocatorError";
    this.reason = reason;
    this.operationId = operationId;
  }
}

/**
 * Canonical allocator SQL against the frozen surfaces. Exported so tests and any
 * in-process fake executor match on the exact strings — a silent statement drift then fails
 * loudly rather than quietly widening the predicate.
 */
export const RECEIVE_ALLOCATOR_STATEMENTS = {
  /**
   * Freezes this literal as the canonical assignment-time form.
   * The three positive conjuncts are the recovery_verified_at gate/B-08 receive-eligibility predicate
   * verbatim. attention hold adds one permanent exclusion: a wallet with durable receive-expiry
   * release evidence must never become a later operation's T0 baseline
   * (release-then-retire, never release-then-reassign).
   *
   * `SKIP LOCKED` is load-bearing, not a throughput tweak: without it a second allocator
   * blocks on the row the first one already locked instead of independently taking the
   * next free wallet, which under load either serialises the whole pool onto one row or
   * reports a false "pool exhausted".
   *
   * This predicate is deliberately NOT the automatic-sink predicate — that one
   * additionally requires BLESSED as a positive conjunct. Dest exclusion here is
   * "already a BLESSED sink", not "any dest row". Dest-on-mint PENDING is
   * blessability, not custody, and must not exclude a receive worker. Requiring
   * BLESSED would reject every legitimate receive. Finding no eligible row never
   * licenses widening any conjunct: assignment simply fails and the receive falls
   * through the backpressure ladder (receive-gate enforcement).
   */
  SELECT_ELIGIBLE_WALLET: `
SELECT w.id
  FROM wallets w
 WHERE w.key_origin = 'node_generated'
   AND w.recovery_verified_at IS NOT NULL
   AND w.state = 'AVAILABLE'
   AND w.allow_external_receive IS TRUE
   AND NOT EXISTS (
         SELECT 1
           FROM destinations d
          WHERE d.wallet_id = w.id
            AND d.state = 'BLESSED')
   AND NOT EXISTS (
         SELECT 1
           FROM receive_release_proofs rrp
           JOIN operation_wallets ow
             ON ow.operation_id = rrp.operation_id
            AND ow.operation_role = 'RECEIVER'
          WHERE ow.wallet_id = w.id)
   AND NOT EXISTS (
         SELECT 1
           FROM lease_release_proofs lrp
          WHERE lrp.wallet_id = w.id
            AND lrp.proof_kind = 'RECEIVE_EXPIRED_T0')
 FOR UPDATE SKIP LOCKED
 LIMIT 1`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * The lost-update guard. Locking the operation row inside the assignment transaction is
   * what makes "receive is still CREATED and unassigned" and "lease acquired" one decision
   * rather than two: a concurrent allocator that read the same row before the lease existed
   * blocks here and then sees the RECEIVER attachment. Without this lock the loser races
   * past the recheck on a stale read and only dies later on operation_wallets' UNIQUE —
   * correct by accident, and one wasted lease acquisition rolled back per collision.
   */
  LOCK_RECEIVE_OPERATION: `
SELECT id::text AS operation_id,
       status::text AS status,
       receiver_wallet_id::text AS receiver_wallet_id
  FROM operations
 WHERE id = $1
   AND kind = 'RECEIVE_EXTERNAL'
 FOR UPDATE`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Wallet↔operation binding for step 2. This — not operations.receiver_wallet_id — is
   * the step-2 attachment: the CHECK on operations refuses a RECEIVE_EXTERNAL row that
   * carries receiver_wallet_id without expiry_unix_time_secs and t0_observation_id, and both
   * of those are only derived at and 8, after T0. UNIQUE (operation_id,
   * operation_role) makes a second RECEIVER attach fail in the database.
   */
  ATTACH_RECEIVER_ROLE: `
INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
VALUES ($1, $2, 'RECEIVER')`
    .replace(/\s+/g, " ")
    .trim(),

  /** Present iff this operation already holds a step-2 wallet attachment. */
  SELECT_RECEIVER_ATTACHMENT: `
SELECT wallet_id::text AS wallet_id
  FROM operation_wallets
 WHERE operation_id = $1
   AND operation_role = 'RECEIVER'`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Queue depth = unassigned CREATED receives ("maximum unassigned CREATED
   * receives"). A receive that took a wallet immediately never occupies the queue, so the
   * cap bounds only the waiting set.
   */
  COUNT_UNASSIGNED_RECEIVES: `
SELECT count(*)::int AS depth
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'
   AND o.receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = o.id
            AND ow.operation_role = 'RECEIVER')`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * FIFO by the exact tuple `(created_at, operation_id)`, never by insertion
   * sequence. The id tiebreak is what makes the sort total: receives created inside the same
   * clock tick would otherwise promote arbitrarily and irreproducibly.
   */
  SELECT_QUEUED_RECEIVES_FIFO: `
SELECT o.id::text AS operation_id
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'
   AND o.receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = o.id
            AND ow.operation_role = 'RECEIVER')
 ORDER BY o.created_at, o.id /* contract-allow:order:frozen-sql-text */
 LIMIT $1`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Serialises the read-count-then-admit window. Transaction-scoped, so it is released by
   * COMMIT or ROLLBACK with no unlock path to forget. Without it two admissions that both
   * observe `depth = cap - 1` both insert and the queue overshoots its cap.
   */
  LOCK_ADMISSION_QUEUE: `SELECT pg_advisory_xact_lock($1) AS locked`,
} as const;

/**
 * Advisory-lock key for the receive admission queue. Arbitrary but fixed and namespaced to
 * this module; nothing else in the schema takes an advisory lock.
 */
export const RECEIVE_ADMISSION_LOCK_KEY = 2640551 as const;

/** The two limits this allocator honours. Pool sizing limits belong to. */
export interface ReceiveQueueLimits {
  /** `RECEIVE_QUEUE_CAP` — maximum unassigned `CREATED` receives. */
  readonly receiveQueueCap: number;
  /** `RECEIVE_QUEUE_MAX_WAIT` seconds — longest a receive may wait without a wallet. */
  readonly receiveQueueMaxWaitSecs: number;
}

export interface AdmitReceiveParams {
  readonly limits: ReceiveQueueLimits;
  /**
   * Inserts the `RECEIVE_EXTERNAL/CREATED` row. Called only once the cap gate has passed, on
   * the caller's transaction, which is how "no partial row survives a rejected admission"
   * holds structurally rather than by cleanup: on rejection nothing is ever inserted.
   */
  readonly insertOperation: (db: SqlExecutor) => Promise<void>;
}

export type AdmitReceiveOutcome =
  | { readonly kind: "ADMITTED"; readonly httpStatus: 202; readonly queueDepth: number }
  | {
      readonly kind: "QUEUE_FULL";
      readonly httpStatus: 503;
      readonly errorCode: "receive_queue_full";
      readonly retryAfterSecs: number;
      readonly queueDepth: number;
    };

export interface AssignReceiveWalletParams {
  readonly operationId: string;
  readonly ownerInstanceId: string;
  readonly leases: ReceiveLeasePort;
  /**
   * The receive's lease group. Omitted for a receive that has not formed one yet (the
   * common case for a queued receive) — the assignment transaction then creates it with
   * this receive as root, so the lease still lands under exactly one group.
   */
  readonly leaseGroupId?: string;
  /**
   * hard gate for EXTERNAL receive: the receiver wallet must hold an ACTIVE
   * push subscription. When injected, called after wallet selection and before lease
   * acquisition. A thrown PushSubscriptionRequiredError is caught and mapped to
   * NO_ELIGIBLE_WALLET so the queue promotion loop continues. MOVE_INTERNAL must NOT
   * inject this port.
   */
  readonly requireActiveSubscription?: (walletId: string) => Promise<void>;
}

export type AssignReceiveWalletOutcome =
  | {
      readonly kind: "ASSIGNED";
      readonly walletId: string;
      readonly membershipId: string;
      readonly leaseGroupId: string;
      readonly leaseEpoch: bigint;
    }
  /** No eligible wallet. Never a licence to widen the predicate — fall through the ladder. */
  | { readonly kind: "NO_ELIGIBLE_WALLET" };

export interface PromoteQueuedReceivesResult {
  readonly promoted: readonly string[];
  /** Queued operations examined but left waiting because the pool ran empty. */
  readonly remaining: readonly string[];
}

type OperationLockRow = {
  operation_id: string;
  status: string;
  receiver_wallet_id: string | null;
};

/**
 * The bounded admission gate.
 *
 * Runs inside the caller's transaction: take the queue lock, measure the unassigned queue,
 * and either delegate the insert or refuse with `503 receive_queue_full`. `Retry-After` is
 * `RECEIVE_QUEUE_MAX_WAIT`, the only bound the node can honestly offer — it is the longest a
 * receive admitted right now could wait before expiring unassigned.
 */
export async function admitReceive(
  db: SqlExecutor,
  params: AdmitReceiveParams,
): Promise<AdmitReceiveOutcome> {
  const cap = params.limits.receiveQueueCap;
  if (!Number.isInteger(cap) || cap < 0) {
    throw new ReceiveAllocatorError(
      "QUEUE_CAP_INVALID",
      `RECEIVE_QUEUE_CAP must be a non-negative integer, got ${String(cap)}`,
    );
  }

  await db.query(RECEIVE_ALLOCATOR_STATEMENTS.LOCK_ADMISSION_QUEUE, [RECEIVE_ADMISSION_LOCK_KEY]);
  const depth = await countUnassignedReceives(db);

  if (depth >= cap) {
    return {
      kind: "QUEUE_FULL",
      httpStatus: 503,
      errorCode: "receive_queue_full",
      retryAfterSecs: params.limits.receiveQueueMaxWaitSecs,
      queueDepth: depth,
    };
  }

  await params.insertOperation(db);
  return { kind: "ADMITTED", httpStatus: 202, queueDepth: depth + 1 };
}

/** Current unassigned `CREATED` receive count (`RECEIVE_QUEUE_CAP` subject). */
export async function countUnassignedReceives(db: SqlExecutor): Promise<number> {
  const result = await db.query<{ depth: number }>(
    RECEIVE_ALLOCATOR_STATEMENTS.COUNT_UNASSIGNED_RECEIVES,
  );
  return Number(result.rows[0]?.depth ?? 0);
}

/**
 * Select one eligible wallet and bind it to the receive, atomically.
 *
 * The sequence inside the transaction is normative and cannot be relaxed:
 * 1. lock the operation row (lost-update guard);
 * 2. select an eligible wallet FOR UPDATE SKIP LOCKED;
 * 3. acquire the RECEIVE_WINDOW lease, which inserts the exclusive row while the wallet is
 * still AVAILABLE and only then pins it;
 * 4. attach the RECEIVER operation role.
 *
 * The whole thing commits before the caller's fresh head read. Leasing after the T0
 * observation would leave a window in which a second allocator takes the same wallet
 * between the read and the lease.
 */
export async function assignReceiveWallet(
  db: SqlExecutor,
  params: AssignReceiveWalletParams,
): Promise<AssignReceiveWalletOutcome> {
  const operation = await lockReceiveOperation(db, params.operationId);

  if (operation.status !== "CREATED") {
    throw new ReceiveAllocatorError(
      "RECEIVE_NOT_CREATED",
      `receive is ${operation.status}, not CREATED — cannot assign a wallet`,
      params.operationId,
    );
  }
  if (operation.receiver_wallet_id !== null) {
    throw new ReceiveAllocatorError(
      "RECEIVE_ALREADY_ASSIGNED",
      "receive already carries receiver_wallet_id",
      params.operationId,
    );
  }
  const attached = await db.query<{ wallet_id: string }>(
    RECEIVE_ALLOCATOR_STATEMENTS.SELECT_RECEIVER_ATTACHMENT,
    [params.operationId],
  );
  if (attached.rows.length > 0) {
    throw new ReceiveAllocatorError(
      "RECEIVE_ALREADY_ASSIGNED",
      "receive already has a RECEIVER wallet attached",
      params.operationId,
    );
  }

  const eligible = await db.query<{ id: string }>(
    RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET,
  );
  const walletId = eligible.rows[0]?.id;
  if (walletId === undefined) {
    return { kind: "NO_ELIGIBLE_WALLET" };
  }

  // hard gate — the selected wallet must hold an ACTIVE push subscription.
  // Caught and mapped to NO_ELIGIBLE_WALLET so the promotion loop continues to the next
  // candidate rather than crashing the whole pass.
  if (params.requireActiveSubscription) {
    try {
      await params.requireActiveSubscription(walletId);
    } catch {
      return { kind: "NO_ELIGIBLE_WALLET" };
    }
  }

  const leaseGroupId =
    params.leaseGroupId ?? (await params.leases.createLeaseGroup(db, params.operationId));

  const lease = await params.leases.acquireReceiveWindowLease(db, {
    walletId,
    leaseGroupId,
    operationId: params.operationId,
    ownerInstanceId: params.ownerInstanceId,
  });
  if (lease === undefined) {
    throw new ReceiveAllocatorError(
      "LEASE_ACQUISITION_EMPTY",
      `lease acquisition returned no membership for wallet ${walletId}`,
      params.operationId,
    );
  }

  await db.query(RECEIVE_ALLOCATOR_STATEMENTS.ATTACH_RECEIVER_ROLE, [params.operationId, walletId]);

  return {
    kind: "ASSIGNED",
    walletId,
    membershipId: lease.membershipId,
    leaseGroupId,
    leaseEpoch: lease.leaseEpoch,
  };
}

/**
 * Steps 2→3 sequencing, enforced rather than documented.
 *
 * `observe` is the caller's `OBSERVE(receiver_pubkey, RECEIVE_T0)`. It runs only after
 * `acquire` has resolved, so there is no code path on which a T0 read precedes the lease.
 * Callers that want the T0 read at all must come through here.
 */
export async function assignReceiveWalletThenObserve<T>(
  acquire: () => Promise<AssignReceiveWalletOutcome>,
  observe: (assigned: Extract<AssignReceiveWalletOutcome, { kind: "ASSIGNED" }>) => Promise<T>,
): Promise<{ readonly assignment: AssignReceiveWalletOutcome; readonly observation: T | null }> {
  const assignment = await acquire();
  if (assignment.kind !== "ASSIGNED") {
    return { assignment, observation: null };
  }
  return { assignment, observation: await observe(assignment) };
}

/**
 * Promote queued receives FIFO while capacity exists.
 *
 * `allocate` runs one receive's assignment in its own transaction (is one DB-TX
 * per receive, so one wallet-less receive cannot roll back its predecessors). The pass stops
 * at the first `NO_ELIGIBLE_WALLET`: the pool is empty, and continuing would only churn the
 * remaining queue into a different sequence than the next pass would use.
 */
export async function promoteQueuedReceives(
  db: SqlExecutor,
  params: {
    readonly limits: ReceiveQueueLimits;
    readonly allocate: (operationId: string) => Promise<AssignReceiveWalletOutcome>;
  },
): Promise<PromoteQueuedReceivesResult> {
  const queued = await selectQueuedReceivesFifo(db, params.limits.receiveQueueCap);
  const promoted: string[] = [];

  for (let i = 0; i < queued.length; i += 1) {
    const operationId = queued[i]!;
    const outcome = await params.allocate(operationId);
    if (outcome.kind !== "ASSIGNED") {
      return { promoted, remaining: queued.slice(i) };
    }
    promoted.push(operationId);
  }

  return { promoted, remaining: [] };
}

/** Queued receives in `(created_at, operation_id)` sequence — the exact tuple. */
export async function selectQueuedReceivesFifo(
  db: SqlExecutor,
  limit: number,
): Promise<string[]> {
  const result = await db.query<{ operation_id: string }>(
    RECEIVE_ALLOCATOR_STATEMENTS.SELECT_QUEUED_RECEIVES_FIFO,
    [limit],
  );
  return result.rows.map((r) => r.operation_id);
}

async function lockReceiveOperation(
  db: SqlExecutor,
  operationId: string,
): Promise<OperationLockRow> {
  const result = await db.query<OperationLockRow>(
    RECEIVE_ALLOCATOR_STATEMENTS.LOCK_RECEIVE_OPERATION,
    [operationId],
  );
  const row = result.rows[0];
  if (!row) {
    throw new ReceiveAllocatorError(
      "RECEIVE_NOT_FOUND",
      "no such RECEIVE_EXTERNAL operation",
      operationId,
    );
  }
  return row;
}
