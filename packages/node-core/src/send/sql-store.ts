// the durable PostgreSQL-backed SendCreateStore.
//
// (idempotency) and (the one-in-flight-per-wallet rule). Schema
// contract: src/schema/send-external-create.sql (+ .contract.ts); real-PostgreSQL drills:
// test/send-external-create-pg.test.ts.
//
// DRIVER-AGNOSTIC: this file never imports `pg`. node-core is network-contained
// and depends on no database driver; the pg Pool is injected at the composition root, which
// is the only layer that touches a socket. The store issues exactly the parameterized
// statements catalogued in STATEMENTS.
//
// The insert is the arbiter. step 3 requires the operation row and its one expected artifact
// to be created in a single DB-TX; a data-modifying CTE gives that atomically, and the
// artifact insert selects FROM the operation CTE, so no artifact can exist without the
// operation row that produced it. When a dual-chain event appender is wired, the same TX
// also appends `external_send.created` on both signed chains so a rolled-back create leaves
// no tenant-visible event (ZTR-1146).
// `ON CONFLICT DO NOTHING` targets the idempotency UNIQUE constraint only, so a losing racer
// yields zero rows instead of raising — it deliberately does NOT swallow the one-in-flight-per-wallet
// partial unique index, whose unique_violation propagates and is mapped to WALLET_IN_FLIGHT
// by constraint name. There is no pre-read anywhere in this file that could decide either
// outcome ahead of the database.

import type {
  SendCreateStore,
  SendExpectedArtifact,
  SendInsertOutcome,
  SendOperation,
  SendSourceWalletRecord,
  SendWalletState,
  StoredSendOperation,
} from "./create.js";

// The narrow node-postgres-shaped query surface the store depends on. `pg.Pool` and
// `pg.PoolClient` both satisfy it structurally; a test double implements it in-process.
export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

/** Transaction port — one BEGIN/COMMIT around create + dual-chain event append. */
export type SqlTxFn = <T>(body: (tx: SqlExecutor) => Promise<T>) => Promise<T>;

/**
 * Appends `external_send.created` inside the create TX. Production wires the dual-chain
 * appender; unit tests may omit the port (slice-local create drills still pass).
 */
export type SendCreatedEventAppender = (
  tx: SqlExecutor,
  input: {
    readonly operationId: string;
    readonly nodeId: string;
    readonly implementerId: string;
    readonly sourceWalletId: string;
    readonly destinationAddress: string;
    readonly amountZkz: string;
    readonly createdAt: string;
  },
) => Promise<void>;

export const SQLSTATE_UNIQUE_VIOLATION = "23505";

// Constraint names carried by src/schema/send-external-create.sql. The store maps by exact
// name, so a renamed constraint surfaces as an unmapped error rather than being silently
// reclassified as a different rejection.
export const IDEMPOTENCY_SCOPE_CONSTRAINT = "send_operations_idempotency_scope";
export const SOURCE_IN_FLIGHT_INDEX = "send_operations_one_unsettled_per_source_wallet";

// The exact column sequence the operation table stores and this store selects. Kept as one
// constant so the INSERT column list, the SELECT projection, and the row mapper cannot drift
// apart.
export const OPERATION_COLUMNS = [
  "operation_id",
  "implementer_id",
  "node_id",
  "kind",
  "status",
  "row_version",
  "attention_required",
  "formation_state",
  "http_method",
  "route",
  "idempotency_key",
  "request_sha256",
  "source_wallet_id",
  "destination_address",
  "amount_zkz",
  "references_operation_id",
  "client_reference",
  "description",
  "created_at",
] as const;

export const ARTIFACT_COLUMNS = [
  "artifact_id",
  "operation_id",
  "purpose",
  "canonical_version",
  "signing_key_id",
  "preimage_text",
  "preimage_sha256",
  "signature",
] as const;

const SELECT_OPERATION_COLUMNS = [
  ...OPERATION_COLUMNS,
  "completed_at",
  "response_status",
  "response_body",
].join(", ");

// created_at arrives as epoch milliseconds and is written through to_timestamp so the column
// stays a real timestamptz; every other value binds directly.
const OPERATION_VALUES = OPERATION_COLUMNS.map((column, i) =>
  column === "created_at" ? `to_timestamp($${i + 1} / 1000.0)` : `$${i + 1}`,
).join(", ");

// operation_id is taken from the CTE, not from a parameter: an artifact row can only exist
// for an operation row this same statement actually inserted. The placeholder counter
// therefore skips it — PREPARE cannot infer a type for an unreferenced parameter, so the
// numbering must stay contiguous.
let artifactPlaceholder = OPERATION_COLUMNS.length;
const ARTIFACT_VALUES = ARTIFACT_COLUMNS.map((column) =>
  column === "operation_id" ? "created_operation.operation_id" : `$${++artifactPlaceholder}`,
).join(", ");

// Artifact-side projection for the join read. `operation_id` and `created_at` exist on both
// tables, so the artifact copies are left out rather than silently shadowing the operation's.
const SELECT_ARTIFACT_COLUMNS = ARTIFACT_COLUMNS.filter((column) => column !== "operation_id")
  .map((column) => `a.${column}`)
  .join(", ");

export const STATEMENTS = {
  INSERT_CREATED:
    `WITH created_operation AS (` +
    `INSERT INTO send_operations (${OPERATION_COLUMNS.join(", ")}) VALUES (${OPERATION_VALUES}) ` +
    `ON CONFLICT ON CONSTRAINT ${IDEMPOTENCY_SCOPE_CONSTRAINT} DO NOTHING RETURNING operation_id` +
    `) INSERT INTO send_operation_expected_artifacts (${ARTIFACT_COLUMNS.join(", ")}) ` +
    `SELECT ${ARTIFACT_VALUES} FROM created_operation RETURNING operation_id`,
  SELECT_BY_IDEMPOTENCY: `SELECT ${SELECT_OPERATION_COLUMNS} FROM send_operations WHERE implementer_id = $1 AND http_method = $2 AND route = $3 AND idempotency_key = $4`,
  SELECT_BY_OPERATION_ID: `SELECT o.${OPERATION_COLUMNS.join(
    ", o.",
  )}, o.completed_at, o.response_status, o.response_body, ${SELECT_ARTIFACT_COLUMNS} FROM send_operations o JOIN send_operation_expected_artifacts a ON a.operation_id = o.operation_id WHERE o.operation_id = $1`,
  SELECT_SOURCE_WALLET: `SELECT id AS wallet_id, node_id, public_key, key_origin, state, allow_external_send FROM wallets WHERE id = $1`,
  // Step 2: the CURRENT blessed internal set, re-read per request —
  // never a cached or precomputed list.
  // wallets PK is `id`; destinations.wallet_id FKs wallets(id).
  SELECT_BLESSED_INTERNAL: `SELECT 1 FROM destinations d JOIN wallets w ON w.id = d.wallet_id WHERE w.public_key = $1 AND d.state = 'BLESSED'`,
  COMPLETE_OPERATION: `UPDATE send_operations SET completed_at = now(), response_status = $2, response_body = $3 WHERE operation_id = $1 AND completed_at IS NULL RETURNING operation_id`,
} as const;

interface OperationRow {
  readonly operation_id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly kind: string;
  readonly status: string;
  readonly row_version: string | number;
  readonly attention_required: boolean;
  readonly formation_state: string;
  readonly http_method: string;
  readonly route: string;
  readonly idempotency_key: string;
  readonly request_sha256: string;
  readonly source_wallet_id: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id: string | null;
  readonly client_reference: string | null;
  readonly description: string | null;
  readonly created_at: string | Date;
  readonly completed_at: string | Date | null;
  readonly response_status: number | null;
  readonly response_body: string | null;
}

interface ArtifactRow {
  readonly artifact_id: string;
  readonly purpose: string;
  readonly canonical_version: number;
  readonly signing_key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

interface WalletRow {
  readonly wallet_id: string;
  readonly node_id: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly state: string;
  readonly allow_external_send: boolean | string;
}

const epochMs = (value: string | Date): number =>
  value instanceof Date ? value.getTime() : Date.parse(value);

function toStoredOperation(row: OperationRow): StoredSendOperation {
  return {
    operationId: row.operation_id,
    implementerId: row.implementer_id,
    nodeId: row.node_id,
    // Guaranteed by the kind / http_method / route CHECKs.
    kind: "SEND_EXTERNAL",
    status: row.status,
    rowVersion: Number(row.row_version),
    attentionRequired: row.attention_required,
    formationState: row.formation_state,
    httpMethod: "POST",
    route: "/v1/external-sends",
    sourceWalletId: row.source_wallet_id,
    destinationAddress: row.destination_address,
    amountZkz: row.amount_zkz,
    referencesOperationId: row.references_operation_id,
    clientReference: row.client_reference,
    description: row.description,
    idempotencyKey: row.idempotency_key,
    requestSha256: row.request_sha256,
    createdAt: epochMs(row.created_at),
    responseStatus: row.response_status === null ? null : Number(row.response_status),
    responseBody: row.response_body,
  };
}

// The storage column signing_key_id maps to wire field key_id exactly, and
// no second aliased field is exposed.
function toArtifact(operationId: string, row: ArtifactRow): SendExpectedArtifact {
  return {
    artifactId: row.artifact_id,
    operationId,
    purpose: "zp-send-external-expected-v1",
    canonicalVersion: 1,
    keyId: row.signing_key_id,
    preimageText: row.preimage_text,
    preimageSha256: row.preimage_sha256,
    signature: row.signature,
  };
}

function pgBool(value: unknown): boolean {
  return value === true || value === "t" || value === "true" || value === "1";
}

function toWallet(row: WalletRow): SendSourceWalletRecord {
  return {
    walletId: row.wallet_id,
    nodeId: row.node_id,
    publicKey: row.public_key,
    keyOrigin: row.key_origin === "imported" ? "imported" : "node_generated",
    state: row.state as SendWalletState,
    allowExternalSend: pgBool(row.allow_external_send),
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

export interface SqlSendCreateStoreConfig {
  readonly sql: SqlExecutor;
  /** Optional TX port. Required when `appendCreatedEvent` is set so create + event co-commit. */
  readonly withTransaction?: SqlTxFn;
  readonly appendCreatedEvent?: SendCreatedEventAppender;
}

function isSqlExecutorOnly(
  value: SqlExecutor | SqlSendCreateStoreConfig,
): value is SqlExecutor {
  return typeof (value as SqlExecutor).query === "function" && !("sql" in value);
}

export class SqlSendCreateStore implements SendCreateStore {
  private readonly sql: SqlExecutor;
  private readonly withTransaction: SqlTxFn;
  private readonly appendCreatedEvent: SendCreatedEventAppender | undefined;

  constructor(sqlOrConfig: SqlExecutor | SqlSendCreateStoreConfig) {
    // Back-compat: existing call sites pass the executor alone.
    if (isSqlExecutorOnly(sqlOrConfig)) {
      this.sql = sqlOrConfig;
      this.withTransaction = async (body) => body(sqlOrConfig);
      this.appendCreatedEvent = undefined;
    } else {
      this.sql = sqlOrConfig.sql;
      this.withTransaction =
        sqlOrConfig.withTransaction ?? (async (body) => body(sqlOrConfig.sql));
      this.appendCreatedEvent = sqlOrConfig.appendCreatedEvent;
    }
  }

  async findSourceWallet(walletId: string): Promise<SendSourceWalletRecord | null> {
    const result = await this.sql.query<WalletRow>(STATEMENTS.SELECT_SOURCE_WALLET, [walletId]);
    const row = result.rows[0];
    return row === undefined ? null : toWallet(row);
  }

  async isBlessedInternalAddress(address: string): Promise<boolean> {
    const result = await this.sql.query<{ readonly "?column?": number }>(
      STATEMENTS.SELECT_BLESSED_INTERNAL,
      [address],
    );
    return result.rows.length > 0;
  }

  async insertCreated(
    operation: SendOperation,
    artifact: SendExpectedArtifact,
  ): Promise<SendInsertOutcome> {
    const params = [
      operation.operationId,
      operation.implementerId,
      operation.nodeId,
      operation.kind,
      operation.status,
      operation.rowVersion,
      operation.attentionRequired,
      operation.formationState,
      operation.httpMethod,
      operation.route,
      operation.idempotencyKey,
      operation.requestSha256,
      operation.sourceWalletId,
      operation.destinationAddress,
      operation.amountZkz,
      operation.referencesOperationId,
      operation.clientReference,
      operation.description,
      operation.createdAt,
      // ARTIFACT_COLUMNS sequence, minus operation_id which the statement takes from the CTE.
      artifact.artifactId,
      artifact.purpose,
      artifact.canonicalVersion,
      artifact.keyId,
      artifact.preimageText,
      artifact.preimageSha256,
      artifact.signature,
    ];

    const runInsert = async (tx: SqlExecutor): Promise<SendInsertOutcome> => {
      try {
        const result = await tx.query<{ operation_id: string }>(
          STATEMENTS.INSERT_CREATED,
          params,
        );
        // ON CONFLICT DO NOTHING targets the idempotency constraint only, so an empty
        // created_operation CTE means another caller already holds this key — and the artifact
        // insert selecting FROM that CTE writes nothing either.
        if (result.rows.length === 0) return { kind: "IDEMPOTENCY_CONFLICT" };
        if (this.appendCreatedEvent !== undefined) {
          await this.appendCreatedEvent(tx, {
            operationId: operation.operationId,
            nodeId: operation.nodeId,
            implementerId: operation.implementerId,
            sourceWalletId: operation.sourceWalletId,
            destinationAddress: operation.destinationAddress,
            amountZkz: operation.amountZkz,
            createdAt: new Date(operation.createdAt).toISOString(),
          });
        }
        return { kind: "INSERTED" };
      } catch (error) {
        if (constraintOf(error) === SOURCE_IN_FLIGHT_INDEX) {
          return { kind: "WALLET_IN_FLIGHT", walletId: operation.sourceWalletId };
        }
        throw error;
      }
    };

    // Dual-chain append needs a real TX so a failed event rolls back the create. Without an
    // appender the single-statement CTE remains atomic on its own (unit / DDL drills).
    if (this.appendCreatedEvent !== undefined) {
      return this.withTransaction(runInsert);
    }
    return runInsert(this.sql);
  }

  async findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredSendOperation | null> {
    const result = await this.sql.query<OperationRow>(STATEMENTS.SELECT_BY_IDEMPOTENCY, [
      implementerId,
      httpMethod,
      route,
      idempotencyKey,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : toStoredOperation(row);
  }

  async findByOperationId(
    operationId: string,
  ): Promise<{ operation: StoredSendOperation; artifact: SendExpectedArtifact } | null> {
    const result = await this.sql.query<OperationRow & ArtifactRow>(
      STATEMENTS.SELECT_BY_OPERATION_ID,
      [operationId],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return { operation: toStoredOperation(row), artifact: toArtifact(row.operation_id, row) };
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
}
