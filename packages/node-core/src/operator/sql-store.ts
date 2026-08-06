// PostgreSQL-backed ports for the CAS + idempotent-create surface.
//
// Compare-and-swap on operation_id / expected status /
// row_version; idempotency rules 1–5; operations UNIQUE
// (implementer_id, kind, idempotency_key) + request_sha256. Schema contract:
// src/schema/operations.sql.
//
// DRIVER-AGNOSTIC: never imports `pg`. The composition root injects SqlExecutor.
// The database is the arbiter — every mutation is a single guarded statement. There is no
// SELECT-then-UPDATE path that could open a TOCTOU window under concurrent racers.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type {
  CasTransitionResult,
  OperationRecord,
  OperationStateStore,
  OperationStatus,
} from "./cas.js";

export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

export const SQLSTATE_UNIQUE_VIOLATION = "23505";

/**
 * Narrow unique-constraint detector: SQLSTATE 23505 only.
 * Never match a bare "unique" substring — a missing ON CONFLICT target surfaces as
 * "there is no unique or exclusion constraint matching the ON CONFLICT specification"
 * and must propagate hard, not be treated as spawn_already_exists.
 */
export function isUniqueViolation(err: unknown): boolean {
  if (typeof err === "object" && err !== null && "code" in err) {
    if (String((err as { code?: unknown }).code) === SQLSTATE_UNIQUE_VIOLATION) {
      return true;
    }
  }
  // psql -v VERBOSITY=verbose surfaces SQLSTATE as "ERROR: 23505: ..."
  const message = err instanceof Error ? err.message : String(err);
  return /\b23505\b/.test(message);
}

/** Terminal statuses that refuse further CAS transitions (kind-agnostic closed set). */
export const TERMINAL_OPERATION_STATUSES = Object.freeze([
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "EXTERNAL_SEND_LANDED",
  "EXPIRED",
  "REJECTED",
] as const);

export type TerminalOperationStatus = (typeof TERMINAL_OPERATION_STATUSES)[number];

export function isTerminalOperationStatus(status: string): status is TerminalOperationStatus {
  return (TERMINAL_OPERATION_STATUSES as readonly string[]).includes(status);
}

// ─── CAS store ────────────────────────────────────────────────────────────────

interface CasRow {
  readonly id: string;
  readonly status: string;
  readonly row_version: string | number;
}

export const CAS_STATEMENTS = {
  READ:
    "SELECT id, status::text AS status, row_version FROM operations WHERE id = $1",
  // Single-statement CAS: identity + expected status + expected row_version. A loser matches
  // zero rows. Terminal statuses are excluded so a retry after landing cannot reopen the row.
  // formation_state advances in lockstep for SEND_EXTERNAL: CREATED→APPROVED
  // requires APPROVED_UNSIGNED; AWAITING_REDEMPTION/EXTERNAL_SEND_LANDED via this CAS lands on
  // PARTIAL_DELIVERED (delivery-complete pairing; the money-path form-and-sign CAS may enter
  // AWAITING_REDEMPTION at PARTIAL_PERSISTED before delivery). Non-send kinds keep NOT_REQUIRED.
  COMPARE_AND_SWAP:
    "UPDATE operations SET status = $4::operation_status, row_version = row_version + 1, " +
    "formation_state = CASE " +
    "  WHEN kind = 'SEND_EXTERNAL' AND $4::text = 'APPROVED' THEN 'APPROVED_UNSIGNED'::external_formation_state " +
    "  WHEN kind = 'SEND_EXTERNAL' AND $4::text IN ('AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED') " +
    "    THEN 'PARTIAL_DELIVERED'::external_formation_state " +
    "  WHEN kind = 'SEND_EXTERNAL' AND $4::text IN ('REJECTED','NEEDS_ATTENTION') THEN formation_state " +
    "  ELSE formation_state " +
    "END, " +
    "updated_at = now() " +
    "WHERE id = $1 AND status = $2::operation_status AND row_version = $3 " +
    "AND status::text NOT IN (" +
    TERMINAL_OPERATION_STATUSES.map((s) => `'${s}'`).join(", ") +
    ") " +
    "RETURNING id, status::text AS status, row_version",
} as const;

export class SqlOperationStateStore<S extends OperationStatus = OperationStatus>
  implements OperationStateStore<S>
{
  constructor(private readonly sql: SqlExecutor) {}

  async read(operationId: string): Promise<OperationRecord<S> | null> {
    const result = await this.sql.query<CasRow>(CAS_STATEMENTS.READ, [operationId]);
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      operationId: row.id,
      status: row.status as S,
      rowVersion: Number(row.row_version),
    };
  }

  async compareAndSwap(
    operationId: string,
    expectedStatus: S,
    expectedRowVersion: number,
    newStatus: S,
  ): Promise<CasTransitionResult<S>> {
    const result = await this.sql.query<CasRow>(CAS_STATEMENTS.COMPARE_AND_SWAP, [
      operationId,
      expectedStatus,
      expectedRowVersion,
      newStatus,
    ]);
    const won = result.rows[0];
    if (won !== undefined) {
      return {
        ok: true,
        operationId: won.id,
        newStatus: won.status as S,
        newRowVersion: Number(won.row_version),
      };
    }
    const current = await this.read(operationId);
    if (current === null) {
      return { ok: false, operationId, actualStatus: "" as S, actualRowVersion: 0 };
    }
    return {
      ok: false,
      operationId,
      actualStatus: current.status,
      actualRowVersion: current.rowVersion,
    };
  }
}

// ─── Idempotent create against operations ─────────────────────────────────────

export interface OperationCreateRequest {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly kind: OperationKind;
  readonly status: string;
  readonly amountZkz: string;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly sourceWalletId?: string | null;
  readonly receiverWalletId?: string | null;
  readonly destinationId?: string | null;
  readonly destinationAddress?: string | null;
  readonly afterLanding?: "HOLD" | "INTERNAL_MOVE" | null;
  readonly afterLandingDestinationId?: string | null;
  readonly spawnedFromOperationId?: string | null;
  readonly formationState?: string;
  readonly discriminator?: string | null;
  readonly anchor?: string | null;
}

export type OperationCreateOutcome =
  | {
      readonly outcome: "CREATED";
      readonly operationId: string;
      readonly idempotencyReplayed: false;
    }
  | {
      readonly outcome: "IDEMPOTENT_REPLAY";
      readonly operationId: string;
      readonly status: string;
      readonly rowVersion: number;
      readonly requestSha256: string;
      readonly idempotencyReplayed: true;
      readonly httpStatus: 200;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: "idempotency_key_reused";
      readonly httpStatus: 409;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: "idempotency_in_progress";
      readonly httpStatus: 409;
      readonly retryAfterSeconds: number;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: "spawn_already_exists";
      readonly httpStatus: 409;
      readonly existingOperationId: string;
    };

interface ExistingOpRow {
  readonly id: string;
  readonly status: string;
  readonly row_version: string | number;
  readonly request_sha256: string;
}

export const IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS = 1;

export const OPERATION_CREATE_STATEMENTS = {
  INSERT_CREATED:
    "INSERT INTO operations (" +
    "id, node_id, implementer_id, kind, status, amount_zkz, " +
    "source_wallet_id, receiver_wallet_id, destination_id, destination_address, " +
    "after_landing, after_landing_destination_id, spawned_from_operation_id, " +
    "discriminator, anchor, idempotency_key, request_sha256, formation_state" +
    ") VALUES (" +
    "$1,$2,$3,$4::operation_kind,$5::operation_status,$6," +
    "$7,$8,$9,$10," +
    "$11,$12,$13," +
    "$14,$15,$16,$17,$18::external_formation_state" +
    ") ON CONFLICT (implementer_id, kind, idempotency_key) DO NOTHING " +
    "RETURNING id",
  SELECT_BY_IDEMPOTENCY:
    "SELECT id, status::text AS status, row_version, request_sha256 " +
    "FROM operations WHERE implementer_id = $1 AND kind = $2::operation_kind AND idempotency_key = $3",
  SELECT_SPAWNED_CHILD:
    "SELECT id FROM operations WHERE spawned_from_operation_id = $1 LIMIT 1",
} as const;

function insertParams(request: OperationCreateRequest): unknown[] {
  const formation =
    request.formationState ??
    (request.kind === "SEND_EXTERNAL" ? "APPROVAL_PENDING" : "NOT_REQUIRED");
  return [
    request.id,
    request.nodeId,
    request.implementerId,
    request.kind,
    request.status,
    request.amountZkz,
    request.sourceWalletId ?? null,
    request.receiverWalletId ?? null,
    request.destinationId ?? null,
    request.destinationAddress ?? null,
    request.afterLanding ?? null,
    request.afterLandingDestinationId ?? null,
    request.spawnedFromOperationId ?? null,
    request.discriminator ?? null,
    request.anchor ?? null,
    request.idempotencyKey,
    request.requestSha256,
    formation,
  ];
}

export class SqlOperationCreateStore {
  constructor(private readonly sql: SqlExecutor) {}

  async create(request: OperationCreateRequest): Promise<OperationCreateOutcome> {
    // Spawn writes must go through the single-child arbiter. create never writes
    // spawned_from_operation_id under the idempotency UNIQUE alone (bypass closed).
    if (request.spawnedFromOperationId !== null && request.spawnedFromOperationId !== undefined) {
      return this.spawnChild(request);
    }
    const inserted = await this.sql.query<{ id: string }>(
      OPERATION_CREATE_STATEMENTS.INSERT_CREATED,
      insertParams(request),
    );
    if (inserted.rows[0] !== undefined) {
      return {
        outcome: "CREATED",
        operationId: inserted.rows[0].id,
        idempotencyReplayed: false,
      };
    }
    return this.resolveIdempotencyConflict(request);
  }

  /**
   * Parent→child spawn race: at most one MOVE_INTERNAL may reference a given parent via
   * `spawned_from_operation_id`. Arbiter is the partial unique index
   * `operations_one_spawn_per_parent_uidx` — ON CONFLICT DO NOTHING so losers return zero rows.
   */
  async spawnChild(request: OperationCreateRequest): Promise<OperationCreateOutcome> {
    if (request.spawnedFromOperationId === null || request.spawnedFromOperationId === undefined) {
      throw new Error("spawnChild requires spawnedFromOperationId");
    }
    const parentId = request.spawnedFromOperationId;
    // Arbiter is UNIQUE INDEX operations_one_spawn_per_parent_uidx (partial on
    // spawned_from_operation_id IS NOT NULL). ON CONFLICT DO NOTHING yields zero rows for
    // losers; concurrent racers never double-insert.
    try {
      const inserted = await this.sql.query<{ id: string }>(
        "INSERT INTO operations (" +
          "id, node_id, implementer_id, kind, status, amount_zkz, " +
          "source_wallet_id, destination_id, spawned_from_operation_id, " +
          "idempotency_key, request_sha256, formation_state" +
          ") VALUES (" +
          "$1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL'::operation_kind, " +
          "'CREATED'::operation_status, $4, $5::uuid, $6::uuid, $7::uuid, " +
          "$8, $9, 'NOT_REQUIRED'::external_formation_state" +
          ") ON CONFLICT (spawned_from_operation_id) WHERE spawned_from_operation_id IS NOT NULL " +
          "DO NOTHING RETURNING id",
        [
          request.id,
          request.nodeId,
          request.implementerId,
          request.amountZkz,
          request.sourceWalletId ?? null,
          request.destinationId ?? null,
          parentId,
          request.idempotencyKey,
          request.requestSha256,
        ],
      );
      if (inserted.rows[0] !== undefined) {
        return {
          outcome: "CREATED",
          operationId: inserted.rows[0].id,
          idempotencyReplayed: false,
        };
      }
    } catch (err) {
      // Some drivers surface unique_violation instead of DO NOTHING; treat as already-exists.
      // SQLSTATE 23505 only — never a bare "unique" substring (missing ON CONFLICT target
      // must surface hard, not look like spawn_already_exists / idempotency_in_progress).
      if (!isUniqueViolation(err)) throw err;
    }
    const existing = await this.sql.query<{ id: string }>(
      OPERATION_CREATE_STATEMENTS.SELECT_SPAWNED_CHILD,
      [parentId],
    );
    const child = existing.rows[0];
    if (child === undefined) {
      return {
        outcome: "REJECTED",
        code: "idempotency_in_progress",
        httpStatus: 409,
        retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
      };
    }
    return {
      outcome: "REJECTED",
      code: "spawn_already_exists",
      httpStatus: 409,
      existingOperationId: child.id,
    };
  }

  private async resolveIdempotencyConflict(
    request: OperationCreateRequest,
  ): Promise<OperationCreateOutcome> {
    const found = await this.sql.query<ExistingOpRow>(
      OPERATION_CREATE_STATEMENTS.SELECT_BY_IDEMPOTENCY,
      [request.implementerId, request.kind, request.idempotencyKey],
    );
    const existing = found.rows[0];
    if (existing === undefined) {
      return {
        outcome: "REJECTED",
        code: "idempotency_in_progress",
        httpStatus: 409,
        retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
      };
    }
    if (existing.request_sha256 !== request.requestSha256) {
      return {
        outcome: "REJECTED",
        code: "idempotency_key_reused",
        httpStatus: 409,
      };
    }
    return {
      outcome: "IDEMPOTENT_REPLAY",
      operationId: existing.id,
      status: existing.status,
      rowVersion: Number(existing.row_version),
      requestSha256: existing.request_sha256,
      idempotencyReplayed: true,
      httpStatus: 200,
    };
  }
}
