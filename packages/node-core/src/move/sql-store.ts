// durable PostgreSQL-backed MoveCreateStore.
//
// schema contracts: operations.sql, custody-eligibility.sql, lease-foundation.sql.
//
// DRIVER-AGNOSTIC: never imports `pg`. Composition root injects SqlExecutor /
// SqlTxFn. The insert TX is the arbiter for idempotency via ON CONFLICT DO NOTHING on
// UNIQUE (implementer_id, kind, idempotency_key). Eligibility reads are pure SELECTs.
//
// Lease acquisition is OUT OF SCOPE. This store creates or joins a lease_groups
// row so the admitted operation has a durable group identity; it never writes
// wallet_active_leases. Event append is a port (full zp-node-event-v1 signing is /
// reporting); the port runs inside the same TX so a rolled-back admit leaves no event.

import { randomUUID } from "node:crypto";

import type {
  MoveAdmitInsert,
  MoveCreateStore,
  MoveDestinationRecord,
  MoveDestinationState,
  MoveInsertOutcome,
  MoveSourceWalletRecord,
  MoveWalletState,
  StoredMoveOperation,
} from "./create.js";
import { MOVE_OPERATION_KIND } from "./create.js";

export interface SqlQueryResult<R> {
  readonly rows: R[];
  readonly rowCount?: number;
}

export interface SqlExecutor {
  query<R>(text: string, params?: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

/** Transaction port — one BEGIN/COMMIT around the admission multi-write. */
export type SqlTxFn = <T>(body: (tx: SqlExecutor) => Promise<T>) => Promise<T>;

/**
 * Appends `internal_move.created` inside the admission TX. Production wires the node
 * event-list / implementer-event log; tests assert the port was invoked with the operation id.
 */
export type MoveCreatedEventAppender = (
  tx: SqlExecutor,
  input: {
    readonly operationId: string;
    readonly nodeId: string;
    readonly implementerId: string;
    readonly sourceWalletId: string;
    readonly destinationId: string;
    readonly amountZkz: string;
    readonly createdAt: string;
  },
) => Promise<void>;

export const SQLSTATE_UNIQUE_VIOLATION = "23505";

export const STATEMENTS = {
  SELECT_SOURCE_WALLET:
    `SELECT id AS wallet_id, node_id, public_key, key_origin, state ` +
    `FROM wallets WHERE id = $1`,

  // destinations ⨝ wallets — destination_id is the public handle; wallet facts come from
  // the referenced wallet's custody predicates. recovery_verified_at is the recovery gate.
  SELECT_DESTINATION:
    `SELECT d.id AS destination_id, d.node_id, d.wallet_id, d.state AS destination_state, ` +
    `w.public_key, w.key_origin, w.state AS wallet_state, ` +
    `w.recovery_verified_at::text AS recovery_verified_at ` +
    `FROM destinations d JOIN wallets w ON w.id = d.wallet_id WHERE d.id = $1`,

  SELECT_ACTIVE_LEASE: `SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1`,

  // MOVE_INTERNAL shape: source_wallet_id + destination_id set; destination_address /
  // receiver_wallet_id / after_landing NULL; formation_state NOT_REQUIRED.
  INSERT_OPERATION:
    `INSERT INTO operations (` +
    `id, node_id, implementer_id, kind, status, amount_zkz, ` +
    `source_wallet_id, destination_id, spawned_from_operation_id, ` +
    `idempotency_key, request_sha256, formation_state` +
    `) VALUES (` +
    `$1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL'::operation_kind, ` +
    `'CREATED'::operation_status, $4, ` +
    `$5::uuid, $6::uuid, $7::uuid, ` +
    `$8, $9, 'NOT_REQUIRED'::external_formation_state` +
    `) ON CONFLICT (implementer_id, kind, idempotency_key) DO NOTHING ` +
    `RETURNING id`,

  INSERT_LEASE_GROUP:
    `INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition) ` +
    `VALUES ($1::uuid, $2::uuid, $3::timestamptz, 'NONE')`,

  INSERT_GROUP_OPERATION:
    `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at) ` +
    `VALUES ($1::uuid, $2::uuid, $3::timestamptz)`,

  MARK_CHILD_JOINED:
    `UPDATE lease_groups SET child_disposition = 'JOINED' ` +
    `WHERE id = $1::uuid AND child_disposition = 'PENDING'`,

  // Slice-local durable event row for admission. Full zp-node-event-v1 chain is the
  // event-ledger path; this table proves the create TX co-commits the event type.
  INSERT_ADMISSION_EVENT:
    `INSERT INTO move_admission_events (` +
    `event_id, operation_id, node_id, implementer_id, event_type, ` +
    `source_wallet_id, destination_id, amount_zkz, created_at` +
    `) VALUES (` +
    `$1::uuid, $2::uuid, $3::uuid, $4::uuid, 'internal_move.created', ` +
    `$5::uuid, $6::uuid, $7, $8::timestamptz` +
    `)`,

  SELECT_BY_IDEMPOTENCY:
    `SELECT o.id, o.implementer_id, o.node_id, o.kind::text AS kind, o.status::text AS status, ` +
    `o.row_version, o.attention_required, o.source_wallet_id, o.destination_id, ` +
    `d.wallet_id AS destination_wallet_id, o.amount_zkz, o.spawned_from_operation_id, ` +
    `lgo.lease_group_id, o.idempotency_key, o.request_sha256, ` +
    `EXTRACT(EPOCH FROM o.created_at) * 1000 AS created_at_ms, ` +
    `EXTRACT(EPOCH FROM o.updated_at) * 1000 AS updated_at_ms ` +
    `FROM operations o ` +
    `JOIN destinations d ON d.id = o.destination_id ` +
    `LEFT JOIN lease_group_operations lgo ON lgo.operation_id = o.id ` +
    `WHERE o.implementer_id = $1 AND o.kind = 'MOVE_INTERNAL'::operation_kind ` +
    `AND o.idempotency_key = $2`,

  SELECT_BY_OPERATION_ID:
    `SELECT o.id, o.implementer_id, o.node_id, o.kind::text AS kind, o.status::text AS status, ` +
    `o.row_version, o.attention_required, o.source_wallet_id, o.destination_id, ` +
    `d.wallet_id AS destination_wallet_id, o.amount_zkz, o.spawned_from_operation_id, ` +
    `lgo.lease_group_id, o.idempotency_key, o.request_sha256, ` +
    `EXTRACT(EPOCH FROM o.created_at) * 1000 AS created_at_ms, ` +
    `EXTRACT(EPOCH FROM o.updated_at) * 1000 AS updated_at_ms ` +
    `FROM operations o ` +
    `JOIN destinations d ON d.id = o.destination_id ` +
    `LEFT JOIN lease_group_operations lgo ON lgo.operation_id = o.id ` +
    `WHERE o.id = $1 AND o.kind = 'MOVE_INTERNAL'::operation_kind`,
} as const;

/**
 * DDL fragment applied by the real-PG drill. Not a frozen data-model contract — a slice-local
 * evidence table that co-commits with the operation row. event_type is closed to the one
 * value this admission path emits.
 */
export const MOVE_ADMISSION_EVENTS_DDL = `
CREATE TABLE IF NOT EXISTS move_admission_events (
  event_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type = 'internal_move.created'),
  source_wallet_id uuid NOT NULL,
  destination_id uuid NOT NULL,
  amount_zkz text NOT NULL,
  created_at timestamptz NOT NULL
);
`;

interface WalletRow {
  readonly wallet_id: string;
  readonly node_id: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly state: string;
}

interface DestinationRow {
  readonly destination_id: string;
  readonly node_id: string;
  readonly wallet_id: string;
  readonly destination_state: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly wallet_state: string;
  readonly recovery_verified_at: string | null;
}

interface OperationRow {
  readonly id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly kind: string;
  readonly status: string;
  readonly row_version: string | number;
  readonly attention_required: boolean;
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly destination_wallet_id: string;
  readonly amount_zkz: string;
  readonly spawned_from_operation_id: string | null;
  readonly lease_group_id: string | null;
  readonly idempotency_key: string;
  readonly request_sha256: string;
  readonly created_at_ms: string | number;
  readonly updated_at_ms: string | number;
}

function toSource(row: WalletRow): MoveSourceWalletRecord {
  return {
    walletId: row.wallet_id,
    nodeId: row.node_id,
    publicKey: row.public_key,
    keyOrigin: row.key_origin as MoveSourceWalletRecord["keyOrigin"],
    state: row.state as MoveWalletState,
  };
}

function toDestination(row: DestinationRow): MoveDestinationRecord {
  return {
    destinationId: row.destination_id,
    nodeId: row.node_id,
    walletId: row.wallet_id,
    publicKey: row.public_key,
    keyOrigin: row.key_origin as MoveDestinationRecord["keyOrigin"],
    walletState: row.wallet_state as MoveWalletState,
    destinationState: row.destination_state as MoveDestinationState,
    recoveryVerifiedAt: row.recovery_verified_at,
  };
}

function pgBool(value: unknown): boolean {
  return value === true || value === "t" || value === "true" || value === "1";
}

function toStored(row: OperationRow): StoredMoveOperation {
  return {
    operationId: row.id,
    implementerId: row.implementer_id,
    nodeId: row.node_id,
    kind: MOVE_OPERATION_KIND,
    status: row.status,
    rowVersion: Number(row.row_version),
    // psql text / node-pg both land here — coerce 't'/'f' as well as real booleans.
    attentionRequired: pgBool(row.attention_required),
    sourceWalletId: row.source_wallet_id,
    destinationId: row.destination_id,
    destinationWalletId: row.destination_wallet_id,
    amountZkz: row.amount_zkz,
    spawnedFromOperationId: row.spawned_from_operation_id,
    leaseGroupId: row.lease_group_id,
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    createdAt: Number(row.created_at_ms),
    updatedAt: Number(row.updated_at_ms),
  };
}

/** Default event appender: writes the slice-local move_admission_events row. */
export function defaultMoveCreatedEventAppender(
  generateId: () => string = () => randomUUID(),
): MoveCreatedEventAppender {
  return async (tx, input) => {
    await tx.query(STATEMENTS.INSERT_ADMISSION_EVENT, [
      generateId(),
      input.operationId,
      input.nodeId,
      input.implementerId,
      input.sourceWalletId,
      input.destinationId,
      input.amountZkz,
      input.createdAt,
    ]);
  };
}

export interface SqlMoveCreateStoreConfig {
  readonly sql: SqlExecutor;
  /** Optional TX port. When omitted, multi-writes run sequentially on `sql` (unit tests). */
  readonly withTransaction?: SqlTxFn;
  readonly appendCreatedEvent?: MoveCreatedEventAppender;
  readonly generateId?: () => string;
}

export class SqlMoveCreateStore implements MoveCreateStore {
  private readonly sql: SqlExecutor;
  private readonly withTransaction: SqlTxFn;
  private readonly appendCreatedEvent: MoveCreatedEventAppender;
  private readonly generateId: () => string;

  constructor(config: SqlMoveCreateStoreConfig) {
    this.sql = config.sql;
    this.withTransaction =
      config.withTransaction ?? (async (body) => body(config.sql));
    this.generateId = config.generateId ?? (() => randomUUID());
    this.appendCreatedEvent =
      config.appendCreatedEvent ?? defaultMoveCreatedEventAppender(this.generateId);
  }

  async findSourceWallet(walletId: string): Promise<MoveSourceWalletRecord | null> {
    const result = await this.sql.query<WalletRow>(STATEMENTS.SELECT_SOURCE_WALLET, [
      walletId,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toSource(row);
  }

  async findDestination(destinationId: string): Promise<MoveDestinationRecord | null> {
    const result = await this.sql.query<DestinationRow>(STATEMENTS.SELECT_DESTINATION, [
      destinationId,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toDestination(row);
  }

  async hasActiveLease(walletId: string): Promise<boolean> {
    const result = await this.sql.query<{ "?column?": number }>(
      STATEMENTS.SELECT_ACTIVE_LEASE,
      [walletId],
    );
    return result.rows.length > 0;
  }

  async insertAdmitted(input: MoveAdmitInsert): Promise<MoveInsertOutcome> {
    return this.withTransaction(async (tx) => {
      const op = input.operation;
      const inserted = await tx.query<{ id: string }>(STATEMENTS.INSERT_OPERATION, [
        op.operationId,
        op.nodeId,
        op.implementerId,
        op.amountZkz,
        op.sourceWalletId,
        op.destinationId,
        op.spawnedFromOperationId,
        op.idempotencyKey,
        op.requestSha256,
      ]);
      if (inserted.rows[0] === undefined) {
        // ON CONFLICT DO NOTHING — another creator holds this idempotency scope.
        return { kind: "IDEMPOTENCY_CONFLICT" };
      }

      const nowIso = new Date(op.createdAt).toISOString();
      let leaseGroupId: string;

      if (input.createLeaseGroup) {
        leaseGroupId = op.leaseGroupId;
        await tx.query(STATEMENTS.INSERT_LEASE_GROUP, [
          leaseGroupId,
          op.operationId,
          nowIso,
        ]);
        await tx.query(STATEMENTS.INSERT_GROUP_OPERATION, [
          leaseGroupId,
          op.operationId,
          nowIso,
        ]);
      } else {
        leaseGroupId = input.parentLeaseGroupId as string;
        await tx.query(STATEMENTS.INSERT_GROUP_OPERATION, [
          leaseGroupId,
          op.operationId,
          nowIso,
        ]);
        // PENDING → JOINED when this is the automatic receive child.
        await tx.query(STATEMENTS.MARK_CHILD_JOINED, [leaseGroupId]);
      }

      await this.appendCreatedEvent(tx, {
        operationId: op.operationId,
        nodeId: op.nodeId,
        implementerId: op.implementerId,
        sourceWalletId: op.sourceWalletId,
        destinationId: op.destinationId,
        amountZkz: op.amountZkz,
        createdAt: nowIso,
      });

      return { kind: "INSERTED", leaseGroupId };
    });
  }

  async findByIdempotency(
    implementerId: string,
    _kind: typeof MOVE_OPERATION_KIND,
    idempotencyKey: string,
  ): Promise<StoredMoveOperation | null> {
    const result = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_IDEMPOTENCY, [
      implementerId,
      idempotencyKey,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toStored(row);
  }

  async findByOperationId(operationId: string): Promise<StoredMoveOperation | null> {
    const result = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_OPERATION_ID, [
      operationId,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toStored(row);
  }
}
