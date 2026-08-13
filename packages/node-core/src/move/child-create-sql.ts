// durable PostgreSQL-backed ChildMoveCreateStore.
//
// Driver-agnostic: no `pg` import. Composition root injects SqlExecutor / SqlTxFn.
// Spawn races are decided solely by UNIQUE INDEX operations_one_spawn_per_parent_uidx via
// ON CONFLICT (spawned_from_operation_id) WHERE spawned_from_operation_id IS NOT NULL DO NOTHING.

import { randomUUID } from "node:crypto";

import type {
  MoveDestinationRecord,
  MoveDestinationState,
  MoveSourceWalletRecord,
  MoveWalletState,
} from "./create.js";
import { MOVE_OPERATION_KIND } from "./create.js";
import type {
  ChildMoveCreateStore,
  ChildMoveRecord,
  ChildMoveTx,
  LandedParentReceive,
} from "./child-create.js";
import type { SqlExecutor, SqlTxFn, MoveCreatedEventAppender } from "./sql-store.js";
import {
  defaultMoveCreatedEventAppender,
  STATEMENTS as MOVE_STATEMENTS,
  SQLSTATE_UNIQUE_VIOLATION,
} from "./sql-store.js";

function isUniqueViolation(err: unknown): boolean {
  if (err === null || typeof err !== "object") return false;
  const e = err as { code?: string; message?: string };
  if (e.code === SQLSTATE_UNIQUE_VIOLATION) return true;
  // psql-session harness surfaces errors as Error(message) without .code.
  return typeof e.message === "string" && /\b23505\b/.test(e.message);
}

export const CHILD_MOVE_STATEMENTS = {
  // Landed receive + its lease group. JOIN lease_group_operations so the parent's
  // group id is byte-identical to what the child later records.
  SELECT_PARENT_RECEIVE:
    `SELECT o.id AS parent_operation_id, o.implementer_id, o.node_id, o.amount_zkz, ` +
    `o.receiver_wallet_id, o.status::text AS status, ` +
    `o.after_landing::text AS after_landing, ` +
    `o.after_landing_destination_id, ` +
    `lgo.lease_group_id ` +
    `FROM operations o ` +
    `JOIN lease_group_operations lgo ON lgo.operation_id = o.id ` +
    `WHERE o.id = $1::uuid AND o.kind = 'RECEIVE_EXTERNAL'::operation_kind`,

  SELECT_SOURCE_WALLET: MOVE_STATEMENTS.SELECT_SOURCE_WALLET,

  SELECT_DESTINATION: MOVE_STATEMENTS.SELECT_DESTINATION,

  // Arbiter: partial unique index on spawned_from_operation_id. Losers RETURN zero rows.
  INSERT_CHILD:
    `INSERT INTO operations (` +
    `id, node_id, implementer_id, kind, status, amount_zkz, ` +
    `source_wallet_id, destination_id, spawned_from_operation_id, ` +
    `idempotency_key, request_sha256, formation_state` +
    `) VALUES (` +
    `$1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL'::operation_kind, ` +
    `'CREATED'::operation_status, $4, ` +
    `$5::uuid, $6::uuid, $7::uuid, ` +
    `$8, $9, 'NOT_REQUIRED'::external_formation_state` +
    `) ON CONFLICT (spawned_from_operation_id) WHERE spawned_from_operation_id IS NOT NULL ` +
    `DO NOTHING RETURNING id`,

  SELECT_CHILD_BY_PARENT:
    `SELECT o.id, o.implementer_id, o.node_id, o.status::text AS status, ` +
    `o.amount_zkz, o.source_wallet_id, o.destination_id, ` +
    `d.wallet_id AS destination_wallet_id, o.spawned_from_operation_id, ` +
    `lgo.lease_group_id, o.idempotency_key, o.request_sha256, ` +
    `EXTRACT(EPOCH FROM o.created_at) * 1000 AS created_at_ms ` +
    `FROM operations o ` +
    `JOIN destinations d ON d.id = o.destination_id ` +
    `LEFT JOIN lease_group_operations lgo ON lgo.operation_id = o.id ` +
    `WHERE o.spawned_from_operation_id = $1::uuid ` +
    `AND o.kind = 'MOVE_INTERNAL'::operation_kind ` +
    `LIMIT 1`,

  SELECT_SPAWNED_ID:
    `SELECT id FROM operations WHERE spawned_from_operation_id = $1::uuid LIMIT 1`,

  INSERT_GROUP_OPERATION: MOVE_STATEMENTS.INSERT_GROUP_OPERATION,

  MARK_CHILD_JOINED: MOVE_STATEMENTS.MARK_CHILD_JOINED,
} as const;

interface ParentRow {
  readonly parent_operation_id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly amount_zkz: string;
  readonly receiver_wallet_id: string;
  readonly status: string;
  readonly after_landing: string;
  readonly after_landing_destination_id: string | null;
  readonly lease_group_id: string;
}

interface WalletRow {
  readonly wallet_id: string;
  readonly node_id: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly state: string;
  readonly allow_internal_move: boolean | string;
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
  readonly allow_internal_move: boolean | string;
}

interface ChildRow {
  readonly id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly status: string;
  readonly amount_zkz: string;
  readonly source_wallet_id: string;
  readonly destination_id: string;
  readonly destination_wallet_id: string;
  readonly spawned_from_operation_id: string;
  readonly lease_group_id: string | null;
  readonly idempotency_key: string;
  readonly request_sha256: string;
  readonly created_at_ms: string | number;
}

function pgBool(value: unknown): boolean {
  return value === true || value === "t" || value === "true" || value === "1";
}

function toSource(row: WalletRow): MoveSourceWalletRecord {
  return {
    walletId: row.wallet_id,
    nodeId: row.node_id,
    publicKey: row.public_key,
    keyOrigin: row.key_origin as MoveSourceWalletRecord["keyOrigin"],
    state: row.state as MoveWalletState,
    allowInternalMove: pgBool(row.allow_internal_move),
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
    allowInternalMove: pgBool(row.allow_internal_move),
  };
}

function toChild(row: ChildRow): ChildMoveRecord {
  const parentId = row.spawned_from_operation_id;
  return {
    operationId: row.id,
    kind: MOVE_OPERATION_KIND,
    status: "CREATED",
    implementerId: row.implementer_id,
    nodeId: row.node_id,
    amountZkz: row.amount_zkz,
    sourceWalletId: row.source_wallet_id,
    destinationId: row.destination_id,
    destinationWalletId: row.destination_wallet_id,
    spawnedFromOperationId: parentId,
    referencesOperationId: parentId,
    leaseGroupId: row.lease_group_id ?? "",
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    createdAt: Number(row.created_at_ms),
  };
}

function toParent(row: ParentRow): LandedParentReceive {
  return {
    parentOperationId: row.parent_operation_id,
    implementerId: row.implementer_id,
    nodeId: row.node_id,
    amountZkz: row.amount_zkz,
    receiverWalletId: row.receiver_wallet_id,
    status: row.status,
    afterLanding: row.after_landing,
    afterLandingDestinationId: row.after_landing_destination_id,
    leaseGroupId: row.lease_group_id,
  };
}

function buildTx(sql: SqlExecutor, appender: MoveCreatedEventAppender): ChildMoveTx {
  return {
    loadParent: async (parentOperationId) => {
      const result = await sql.query<ParentRow>(CHILD_MOVE_STATEMENTS.SELECT_PARENT_RECEIVE, [
        parentOperationId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : toParent(row);
    },
    loadSourceWallet: async (walletId) => {
      const result = await sql.query<WalletRow>(CHILD_MOVE_STATEMENTS.SELECT_SOURCE_WALLET, [
        walletId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : toSource(row);
    },
    loadDestination: async (destinationId) => {
      const result = await sql.query<DestinationRow>(CHILD_MOVE_STATEMENTS.SELECT_DESTINATION, [
        destinationId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : toDestination(row);
    },
    insertChild: async (input) => {
      // Concurrent losers may surface on either UNIQUE: the spawn partial index (preferred
      // ON CONFLICT target) or the (implementer, kind, idempotency_key) scope when the parent
      // id is reused as the idempotency key. A throwing 23505 aborts the TX in PostgreSQL —
      // wrap the INSERT in a SAVEPOINT so losers can SELECT the winner and return cleanly.
      await sql.query(`SAVEPOINT child_move_create_child_spawn`, []);
      let inserted: { rows: Array<{ id: string }> };
      try {
        inserted = await sql.query<{ id: string }>(CHILD_MOVE_STATEMENTS.INSERT_CHILD, [
          input.operationId,
          input.nodeId,
          input.implementerId,
          input.amountZkz,
          input.sourceWalletId,
          input.destinationId,
          input.spawnedFromOperationId,
          input.idempotencyKey,
          input.requestSha256,
        ]);
        await sql.query(`RELEASE SAVEPOINT child_move_create_child_spawn`, []);
      } catch (err) {
        try {
          await sql.query(`ROLLBACK TO SAVEPOINT child_move_create_child_spawn`, []);
        } catch {
          /* session may already be clean */
        }
        if (!isUniqueViolation(err)) throw err;
        inserted = { rows: [] };
      }
      if (inserted.rows[0] !== undefined) {
        return { kind: "INSERTED" };
      }
      const existing = await sql.query<{ id: string }>(CHILD_MOVE_STATEMENTS.SELECT_SPAWNED_ID, [
        input.spawnedFromOperationId,
      ]);
      const winner = existing.rows[0];
      return {
        kind: "SPAWN_CONFLICT",
        existingOperationId: winner?.id ?? input.operationId,
      };
    },

    findChildByParent: async (parentOperationId) => {
      const result = await sql.query<ChildRow>(CHILD_MOVE_STATEMENTS.SELECT_CHILD_BY_PARENT, [
        parentOperationId,
      ]);
      const row = result.rows[0];
      return row === undefined ? null : toChild(row);
    },
    joinParentLeaseGroup: async (input) => {
      await sql.query(CHILD_MOVE_STATEMENTS.INSERT_GROUP_OPERATION, [
        input.leaseGroupId,
        input.childOperationId,
        input.joinedAtIso,
      ]);
      await sql.query(CHILD_MOVE_STATEMENTS.MARK_CHILD_JOINED, [input.leaseGroupId]);
    },
    appendCreatedEvent: async (input) => {
      await appender(sql, {
        operationId: input.operationId,
        nodeId: input.nodeId,
        implementerId: input.implementerId,
        sourceWalletId: input.sourceWalletId,
        destinationId: input.destinationId,
        amountZkz: input.amountZkz,
        createdAt: input.createdAtIso,
      });
    },
  };
}

export interface SqlChildMoveCreateStoreConfig {
  readonly sql: SqlExecutor;
  readonly withTransaction?: SqlTxFn;
  readonly appendCreatedEvent?: MoveCreatedEventAppender;
  readonly generateId?: () => string;
}

export class SqlChildMoveCreateStore implements ChildMoveCreateStore {
  private readonly sql: SqlExecutor;
  private readonly withTx: SqlTxFn;
  private readonly appendCreatedEvent: MoveCreatedEventAppender;

  constructor(config: SqlChildMoveCreateStoreConfig) {
    this.sql = config.sql;
    this.withTx = config.withTransaction ?? (async (body) => body(config.sql));
    const generateId = config.generateId ?? (() => randomUUID());
    this.appendCreatedEvent =
      config.appendCreatedEvent ?? defaultMoveCreatedEventAppender(generateId);
  }

  withTransaction<T>(body: (tx: ChildMoveTx) => Promise<T>): Promise<T> {
    return this.withTx(async (sql) => body(buildTx(sql, this.appendCreatedEvent)));
  }
}
