// The durable PostgreSQL-backed ReceiveAdmissionStore.
//
// Idempotency and the one-in-flight-per-wallet rule. Schema contract:
// src/schema/receive-admission.sql (+ .contract.ts); real-PostgreSQL drills:
// test/receive-admission-pg.test.ts.
//
// DRIVER-AGNOSTIC: this file never imports `pg`. node-core is network-contained
// and depends on no database driver; the pg Pool is injected at the composition root, which
// is the only layer that touches a socket. The store issues exactly the parameterized
// statements catalogued in STATEMENTS.
//
// The insert is the arbiter. `INSERT_IN_PROGRESS` targets the idempotency UNIQUE constraint
// with ON CONFLICT DO NOTHING, so a losing racer returns zero rows instead of raising — but
// it deliberately does NOT swallow the two one-in-flight-per-wallet partial unique indexes, whose
// unique_violation propagates and is mapped to WALLET_IN_FLIGHT by constraint name. There is
// no pre-read anywhere in this file that could decide either outcome ahead of the database.

import type {
  ReceiveAdmissionStore,
  ReceiveDestinationRecord,
  ReceiveDestinationState,
  ReceiveInsertOutcome,
  ReceiveOperation,
  ReceiveQueuedInsertOutcome,
  ReceiveWalletState,
  StoredReceiveOperation,
} from "./admission.js";
import { RECEIVE_ADMISSION_LOCK_KEY } from "./pool-allocator.js";

// The narrow node-postgres-shaped query surface the store depends on. `pg.Pool` and
// `pg.PoolClient` both satisfy it structurally; a test double implements it in-process.
export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

/**
 * Opens BEGIN/COMMIT around `fn`; ROLLBACK on throw. Required for RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL: the advisory
 * lock, depth read, and insert MUST share one transaction so the depth statement takes a
 * fresh READ COMMITTED snapshot after the lock is held (a single-statement CTE snapshots
 * before the lock wait and overshoots under concurrency — the defect D-B1 named).
 * `pg.Pool#connect` + BEGIN/COMMIT satisfies this; in-process tests pass the same executor.
 */
export interface SqlTxFactory {
  withTransaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T>;
}

export const SQLSTATE_UNIQUE_VIOLATION = "23505";

// Constraint names carried by src/schema/receive-admission.sql. The store maps by exact
// name, so a renamed constraint surfaces as an unmapped error rather than being silently
// reclassified as a different rejection.
export const IDEMPOTENCY_SCOPE_CONSTRAINT = "receive_operations_idempotency_scope";
export const DESTINATION_IN_FLIGHT_INDEX = "receive_operations_one_unsettled_per_destination";
export const RECEIVER_IN_FLIGHT_INDEX = "receive_operations_one_unsettled_per_wallet";

// The exact column sequence the table stores and this store selects. Kept as one constant so
// the INSERT column list, the SELECT projection, and the row mapper cannot drift apart.
export const OPERATION_COLUMNS = [
  "operation_id",
  "implementer_id",
  "node_id",
  "kind",
  "status",
  "http_method",
  "route",
  "idempotency_key",
  "request_sha256",
  "amount_zkz",
  "anchor",
  "ttl_ms",
  "after_landing_kind",
  "destination_wallet_id",
  "destination_id",
  "wallet_id",
  "created_at",
] as const;

const SELECT_COLUMNS = [...OPERATION_COLUMNS, "completed_at", "response_status", "response_body"].join(
  ", ",
);

// created_at arrives as epoch milliseconds and is written through to_timestamp so the column
// stays a real timestamptz; every other value binds directly.
const INSERT_VALUES = OPERATION_COLUMNS.map((column, i) =>
  column === "created_at" ? `to_timestamp($${i + 1} / 1000.0)` : `$${i + 1}`,
).join(", ");

export const STATEMENTS = {
  INSERT_IN_PROGRESS: `INSERT INTO receive_operations (${OPERATION_COLUMNS.join(
    ", ",
  )}) VALUES (${INSERT_VALUES}) ON CONFLICT ON CONSTRAINT ${IDEMPOTENCY_SCOPE_CONSTRAINT} DO NOTHING RETURNING operation_id`,
  SELECT_BY_IDEMPOTENCY: `SELECT ${SELECT_COLUMNS} FROM receive_operations WHERE implementer_id = $1 AND http_method = $2 AND route = $3 AND idempotency_key = $4`,
  // Tenant predicate in the WHERE — cross-tenant ids return zero rows.
  SELECT_BY_OPERATION_ID: `SELECT ${SELECT_COLUMNS} FROM receive_operations WHERE operation_id = $1 AND implementer_id = $2`,
  // join live operations so GET surfaces post-land status/row_version (CAS for
  // verification-complete). Idempotency/create paths keep the admission-only SELECT.
  SELECT_BY_OPERATION_ID_WITH_LIVE: `SELECT r.operation_id, r.implementer_id, r.node_id, r.kind, r.status,
    r.http_method, r.route, r.idempotency_key, r.request_sha256, r.amount_zkz, r.anchor, r.ttl_ms,
    r.after_landing_kind, r.destination_wallet_id, r.destination_id, r.wallet_id, r.created_at,
    r.completed_at, r.response_status, r.response_body,
    o.status::text AS live_status,
    o.row_version::bigint AS live_row_version,
    o.updated_at AS live_updated_at,
    o.terminal_at AS live_terminal_at,
    o.verification_material_available_until AS live_vm_until,
    o.attention_required AS live_attention_required,
    o.attention_reason AS live_attention_reason
  FROM receive_operations r
  JOIN operations o ON o.id = r.operation_id
  WHERE r.operation_id = $1 AND r.implementer_id = $2`,
  SELECT_DESTINATION: `SELECT d.id AS destination_id, d.state AS destination_state, w.id AS wallet_id, w.node_id, w.public_key, w.key_origin, w.state AS wallet_state, w.recovery_verified_at FROM destinations d JOIN wallets w ON w.id = d.wallet_id WHERE d.id = $1`,
  COMPLETE_OPERATION: `UPDATE receive_operations SET completed_at = now(), response_status = $2, response_body = $3 WHERE operation_id = $1 AND completed_at IS NULL RETURNING operation_id`,
  // "maximum unassigned CREATED receives", per node. `wallet_id IS NULL`
  // is stated rather than inferred from the no-receiver-while-CREATED CHECK, so the depth
  // stays correct if that CHECK is ever widened. Observability / tests only — admit uses
  // insertQueuedIfCapAllows (lock → count → insert in one TX) so the cap cannot race.
  COUNT_QUEUED: `SELECT count(*)::int AS depth FROM receive_operations WHERE node_id = $1 AND status = 'CREATED' AND wallet_id IS NULL`,
  // Same key + statement as pool-allocator admitReceive (RECEIVE_ADMISSION_LOCK_KEY).
  LOCK_ADMISSION_QUEUE: `SELECT pg_advisory_xact_lock($1) AS locked`,
} as const;

interface OperationRow {
  readonly operation_id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly kind: string;
  readonly status: string;
  readonly http_method: string;
  readonly route: string;
  readonly idempotency_key: string;
  readonly request_sha256: string;
  readonly amount_zkz: string;
  readonly anchor: string;
  readonly ttl_ms: number;
  readonly after_landing_kind: string;
  readonly destination_wallet_id: string | null;
  readonly destination_id: string | null;
  readonly wallet_id: string | null;
  readonly created_at: string | Date;
  readonly completed_at: string | Date | null;
  readonly response_status: number | null;
  readonly response_body: string | null;
  readonly live_status?: string | null;
  readonly live_row_version?: string | number | null;
  readonly live_updated_at?: string | Date | null;
  readonly live_terminal_at?: string | Date | null;
  readonly live_vm_until?: string | Date | null;
  readonly live_attention_required?: boolean | null;
  readonly live_attention_reason?: string | null;
}

interface DestinationRow {
  readonly destination_id: string;
  readonly destination_state: string;
  readonly wallet_id: string;
  readonly node_id: string;
  readonly key_origin: string;
  readonly wallet_state: string;
  readonly recovery_verified_at: string | Date | null;
}

const epochMs = (value: string | Date): number =>
  value instanceof Date ? value.getTime() : Date.parse(value);

const RECEIVE_STATUSES = new Set(["CREATED", "READY", "RECEIVE_LANDED", "EXPIRED"] as const);
type ReceiveStatus = "CREATED" | "READY" | "RECEIVE_LANDED" | "EXPIRED";

function asReceiveStatus(value: string): ReceiveStatus {
  if (!RECEIVE_STATUSES.has(value as ReceiveStatus)) {
    throw new Error(`receive_operations.status out of vocabulary: ${value}`);
  }
  return value as ReceiveStatus;
}

function toIsoOrUndefined(value: string | Date | null | undefined): string | undefined {
  if (value === null || value === undefined) return undefined;
  return value instanceof Date ? value.toISOString() : String(value);
}

function toStoredOperation(row: OperationRow): StoredReceiveOperation {
  const base: StoredReceiveOperation = {
    operationId: row.operation_id,
    implementerId: row.implementer_id,
    nodeId: row.node_id,
    // kind/http_method/route are fixed by this slice's CHECKs; status is the full
    // RECEIVE_EXTERNAL vocabulary (sibling assignment writes READY).
    kind: "RECEIVE_EXTERNAL",
    status: asReceiveStatus(row.status),
    httpMethod: "POST",
    route: "/v1/receives",
    amountZkz: row.amount_zkz,
    anchor: row.anchor,
    ttlMs: Number(row.ttl_ms),
    afterLanding:
      row.after_landing_kind === "INTERNAL_MOVE"
        ? { kind: "INTERNAL_MOVE", destinationId: row.destination_id as string }
        : { kind: "HOLD", destinationId: null },
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    destinationWalletId: row.destination_wallet_id,
    walletId: row.wallet_id,
    createdAt: epochMs(row.created_at),
    responseStatus: row.response_status === null ? null : Number(row.response_status),
    responseBody: row.response_body,
  };
  if (row.live_status === undefined || row.live_status === null) {
    return base;
  }
  const liveTerminal = row.live_terminal_at;
  const liveVm = row.live_vm_until;
  return {
    ...base,
    liveStatus: String(row.live_status),
    liveRowVersion: Number(row.live_row_version),
    liveUpdatedAt: toIsoOrUndefined(row.live_updated_at) ?? new Date(base.createdAt).toISOString(),
    liveTerminalAt:
      liveTerminal === null || liveTerminal === undefined
        ? null
        : toIsoOrUndefined(liveTerminal) ?? null,
    liveVerificationMaterialAvailableUntil:
      liveVm === null || liveVm === undefined ? null : toIsoOrUndefined(liveVm) ?? null,
    liveAttentionRequired: Boolean(row.live_attention_required),
    liveAttentionReason:
      row.live_attention_reason === null || row.live_attention_reason === undefined
        ? null
        : String(row.live_attention_reason),
  };
}

function toDestination(row: DestinationRow): ReceiveDestinationRecord {
  return {
    destinationId: row.destination_id,
    destinationState: row.destination_state as ReceiveDestinationState,
    wallet: {
      walletId: row.wallet_id,
      nodeId: row.node_id,
      keyOrigin: row.key_origin === "imported" ? "imported" : "node_generated",
      state: row.wallet_state as ReceiveWalletState,
      recoveryVerifiedAt: row.recovery_verified_at === null ? null : epochMs(row.recovery_verified_at),
    },
  };
}

// node-postgres attaches `code` and `constraint` to the thrown error; a partial unique index
// reports the index name as the constraint.
function constraintOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const err = error as { code?: unknown; constraint?: unknown };
  if (err.code !== SQLSTATE_UNIQUE_VIOLATION) return undefined;
  return typeof err.constraint === "string" ? err.constraint : undefined;
}

export class SqlReceiveAdmissionStore implements ReceiveAdmissionStore {
  private readonly sql: SqlExecutor;
  private readonly txFactory: SqlTxFactory;

  /**
   * @param sql - Autocommit executor for reads / unconstrained inserts.
   * @param txFactory - Transaction factory for the RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL gated admit. Required: the
   * advisory lock, depth read, and insert MUST share one BEGIN/COMMIT so the depth
   * statement takes a fresh READ COMMITTED snapshot after the lock is held. A Pool
   * without a real factory (PoolClient BEGIN/COMMIT) lets the lock release between
   * statements and the queue overshoots under concurrency. In-process test fakes pass
   * `{ withTransaction: (fn) => fn(sql) }` — single-threaded, so identity is correct.
   */
  constructor(sql: SqlExecutor, txFactory: SqlTxFactory) {
    this.sql = sql;
    this.txFactory = txFactory;
  }

  async findDestination(destinationId: string): Promise<ReceiveDestinationRecord | null> {
    const result = await this.sql.query<DestinationRow>(STATEMENTS.SELECT_DESTINATION, [
      destinationId,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toDestination(row);
  }

  private operationInsertParams(operation: ReceiveOperation): unknown[] {
    const destinationId =
      operation.afterLanding.kind === "INTERNAL_MOVE" ? operation.afterLanding.destinationId : null;
    return [
      operation.operationId,
      operation.implementerId,
      operation.nodeId,
      operation.kind,
      operation.status,
      operation.httpMethod,
      operation.route,
      operation.idempotencyKey,
      operation.requestSha256,
      operation.amountZkz,
      operation.anchor,
      operation.ttlMs,
      operation.afterLanding.kind,
      operation.destinationWalletId,
      destinationId,
      operation.walletId,
      operation.createdAt,
    ];
  }

  private mapInsertError(error: unknown, operation: ReceiveOperation): ReceiveInsertOutcome {
    const constraint = constraintOf(error);
    if (constraint === DESTINATION_IN_FLIGHT_INDEX) {
      return { kind: "WALLET_IN_FLIGHT", walletId: operation.destinationWalletId as string };
    }
    if (constraint === RECEIVER_IN_FLIGHT_INDEX) {
      return { kind: "WALLET_IN_FLIGHT", walletId: operation.walletId as string };
    }
    throw error;
  }

  private async insertOn(
    executor: SqlExecutor,
    operation: ReceiveOperation,
  ): Promise<ReceiveInsertOutcome> {
    const params = this.operationInsertParams(operation);
    try {
      const result = await executor.query<{ operation_id: string }>(
        STATEMENTS.INSERT_IN_PROGRESS,
        params,
      );
      // ON CONFLICT DO NOTHING targets the idempotency constraint only, so zero rows means
      // another caller already holds this key.
      return result.rows.length === 0 ? { kind: "IDEMPOTENCY_CONFLICT" } : { kind: "INSERTED" };
    } catch (error) {
      return this.mapInsertError(error, operation);
    }
  }

  async insertInProgress(operation: ReceiveOperation): Promise<ReceiveInsertOutcome> {
    return this.insertOn(this.sql, operation);
  }

  async insertQueuedIfCapAllows(
    operation: ReceiveOperation,
    queueCap: number,
  ): Promise<ReceiveQueuedInsertOutcome> {
    if (!Number.isInteger(queueCap) || queueCap < 0) {
      throw new Error(`RECEIVE_QUEUE_CAP must be a non-negative integer, got ${String(queueCap)}`);
    }
    // Mirror pool-allocator admitReceive: lock → fresh depth read → insert-or-refuse.
    // Separate statements inside one TX so the depth SELECT's snapshot is taken AFTER the
    // lock is held (READ COMMITTED). A single-statement CTE would snapshot before the lock
    // wait and let N concurrent admits each observe depth = cap-1 and all insert.
    //
    // One-in-flight unique_violation aborts the PG transaction: let it throw out of withTransaction
    // (so the factory ROLLBACKs) and map the error here. Catching inside the TX and
    // returning WALLET_IN_FLIGHT would leave the session aborted and fail COMMIT.
    try {
      return await this.txFactory.withTransaction(async (tx) => {
        await tx.query(STATEMENTS.LOCK_ADMISSION_QUEUE, [RECEIVE_ADMISSION_LOCK_KEY]);
        const depthResult = await tx.query<{ depth: number }>(STATEMENTS.COUNT_QUEUED, [
          operation.nodeId,
        ]);
        const depth = Number(depthResult.rows[0]?.depth ?? 0);
        if (depth >= queueCap) return { kind: "QUEUE_FULL" as const };
        const result = await tx.query<{ operation_id: string }>(
          STATEMENTS.INSERT_IN_PROGRESS,
          this.operationInsertParams(operation),
        );
        return result.rows.length === 0
          ? ({ kind: "IDEMPOTENCY_CONFLICT" } as const)
          : ({ kind: "INSERTED" } as const);
      });
    } catch (error) {
      return this.mapInsertError(error, operation);
    }
  }

  async findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredReceiveOperation | null> {
    const result = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_IDEMPOTENCY, [
      implementerId,
      httpMethod,
      route,
      idempotencyKey,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toStoredOperation(row);
  }

  async completeOperation(
    operationId: string,
    responseStatus: number,
    responseBody: string,
  ): Promise<boolean> {
    const result = await this.sql.query<{ operation_id: string }>(STATEMENTS.COMPLETE_OPERATION, [
      operationId,
      responseStatus,
      responseBody,
    ]);
    return result.rows.length === 1;
  }

  async findByOperationId(
    operationId: string,
    implementerId: string,
  ): Promise<StoredReceiveOperation | null> {
    // Prefer the live join so GET /v1/receives carries operations.row_version after land
    // (verification-complete CAS). Fall back to admission-only if operations is
    // missing (admission race before mirror) so create/tests still resolve.
    const live = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_OPERATION_ID_WITH_LIVE, [
      operationId,
      implementerId,
    ]);
    if (live.rows[0] !== undefined) {
      return toStoredOperation(live.rows[0]);
    }
    const result = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_OPERATION_ID, [
      operationId,
      implementerId,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toStoredOperation(row);
  }

  async countQueuedReceives(nodeId: string): Promise<number> {
    const result = await this.sql.query<{ depth: number }>(STATEMENTS.COUNT_QUEUED, [nodeId]);
    return Number(result.rows[0]?.depth ?? 0);
  }
}
