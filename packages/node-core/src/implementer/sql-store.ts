// Durable ImplementerRegistry over Postgres. Driver-agnostic SqlExecutor
// (pg.Pool / PoolClient both satisfy). Create/retire write audit_log in the
// same statement so a surrounding TX rolls both back together.

import { createHash, randomUUID } from "node:crypto";

import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerRetireInput,
} from "./types.js";

export interface ImplementerSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

interface ImplementerRow extends Record<string, unknown> {
  readonly id: string;
  readonly name: string;
  readonly created_at: unknown;
  readonly retired_at: unknown;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toRecord(row: ImplementerRow): ImplementerRecord {
  return {
    id: row.id,
    name: row.name,
    created_at: toIso(row.created_at),
    retired_at: row.retired_at === null || row.retired_at === undefined ? null : toIso(row.retired_at),
  };
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function normalizeName(raw: string): string {
  const name = raw.trim();
  if (name.length === 0 || name.length > 128) {
    throw new ImplementerRegistryError(
      "name must be 1–128 characters after trim",
      "IMPLEMENTER_NAME_INVALID",
    );
  }
  return name;
}

const LIST_SQL = `SELECT id::text AS id, name, created_at, retired_at
  FROM implementers
  ORDER BY created_at ASC, id ASC`; // contract-allow:order:frozen-sql-text

const GET_SQL = `SELECT id::text AS id, name, created_at, retired_at
  FROM implementers WHERE id = $1::uuid`;

const GET_ACTIVE_SQL = `SELECT id::text AS id, name, created_at, retired_at
  FROM implementers WHERE id = $1::uuid AND retired_at IS NULL`;

const GENESIS_SQL = `SELECT id::text AS id
  FROM implementers
  WHERE retired_at IS NULL
  ORDER BY created_at ASC, id ASC
  LIMIT 1`; // contract-allow:order:frozen-sql-text

// Insert implementer + audit in one statement (both-or-neither).
const CREATE_SQL = `WITH inserted AS (
  INSERT INTO implementers (id, name)
  VALUES ($1::uuid, $2)
  RETURNING id::text AS id, name, created_at, retired_at
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
  $6, NULL, NULL, $7, $8, inserted.created_at
FROM inserted
RETURNING
  (SELECT id FROM inserted) AS id,
  (SELECT name FROM inserted) AS name,
  (SELECT created_at FROM inserted) AS created_at,
  (SELECT retired_at FROM inserted) AS retired_at`;

// Set retired_at only when currently active; return the row for audit details.
const RETIRE_SQL = `WITH locked AS (
  SELECT id, name, created_at, retired_at
    FROM implementers
   WHERE id = $1::uuid
   FOR UPDATE
), updated AS (
  UPDATE implementers i
     SET retired_at = now()
    FROM locked
   WHERE i.id = locked.id
     AND locked.retired_at IS NULL
  RETURNING i.id::text AS id, i.name, i.created_at, i.retired_at
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $2::uuid, $3::uuid, 'OPERATOR_SESSION', $4,
  $5, NULL, NULL, $6, $7, updated.retired_at
FROM updated
RETURNING
  (SELECT id FROM updated) AS id,
  (SELECT name FROM updated) AS name,
  (SELECT created_at FROM updated) AS created_at,
  (SELECT retired_at FROM updated) AS retired_at`;

export class SqlImplementerRegistry implements ImplementerRegistry {
  constructor(private readonly sql: ImplementerSqlExecutor) {}

  async list(): Promise<readonly ImplementerRecord[]> {
    const { rows } = await this.sql.query<ImplementerRow>(LIST_SQL);
    return rows.map(toRecord);
  }

  async get(id: string): Promise<ImplementerRecord | null> {
    const { rows } = await this.sql.query<ImplementerRow>(GET_SQL, [id]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }

  async getActive(id: string): Promise<ImplementerRecord | null> {
    const { rows } = await this.sql.query<ImplementerRow>(GET_ACTIVE_SQL, [id]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }

  async resolveGenesisId(): Promise<string | null> {
    const { rows } = await this.sql.query<{ id: string }>(GENESIS_SQL);
    return rows[0]?.id ?? null;
  }

  async create(input: ImplementerCreateInput): Promise<ImplementerRecord> {
    const name = normalizeName(input.name);
    const id = randomUUID();
    const auditId = randomUUID();
    const detailsText = JSON.stringify({ id, name });
    const { rows } = await this.sql.query<ImplementerRow>(CREATE_SQL, [
      id,
      name,
      auditId,
      input.nodeId,
      input.actorId,
      IMPLEMENTER_AUDIT_CREATED,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined) {
      throw new Error("implementer create returned no row");
    }
    return toRecord(rows[0]);
  }

  async retire(input: ImplementerRetireInput): Promise<ImplementerRecord> {
    const existing = await this.get(input.id);
    if (existing === null) {
      throw new ImplementerRegistryError("implementer not found", "IMPLEMENTER_NOT_FOUND");
    }
    if (existing.retired_at !== null) {
      throw new ImplementerRegistryError(
        "implementer already retired",
        "IMPLEMENTER_ALREADY_RETIRED",
      );
    }
    const auditId = randomUUID();
    const detailsText = JSON.stringify({ id: existing.id, name: existing.name });
    const { rows } = await this.sql.query<ImplementerRow>(RETIRE_SQL, [
      input.id,
      auditId,
      input.nodeId,
      input.actorId,
      IMPLEMENTER_AUDIT_RETIRED,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined) {
      // Race: another session retired between get and update.
      throw new ImplementerRegistryError(
        "implementer already retired",
        "IMPLEMENTER_ALREADY_RETIRED",
      );
    }
    return toRecord(rows[0]);
  }
}

export function createSqlImplementerRegistry(sql: ImplementerSqlExecutor): ImplementerRegistry {
  return new SqlImplementerRegistry(sql);
}
