// Durable ImplementerRegistry over Postgres. Driver-agnostic SqlExecutor
// (pg.Pool / PoolClient both satisfy). Create/retire/setFundingWallet write
// audit_log in the same statement so a surrounding TX rolls both back together.

import { createHash, randomUUID } from "node:crypto";

import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerRetireInput,
  type ImplementerSetFundingWalletInput,
  type ImplementerSetFundingWalletOutcome,
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
  readonly funding_wallet_id: string | null;
  readonly funding_wallet_public_key: string | null;
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
    funding_wallet_id: row.funding_wallet_id ?? null,
    funding_wallet_public_key: row.funding_wallet_public_key ?? null,
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

// SELECT projection: left join wallets for public_key when funding_wallet_id set.
const IMPLEMENTER_SELECT = `SELECT i.id::text AS id,
    i.name,
    i.created_at,
    i.retired_at,
    i.funding_wallet_id::text AS funding_wallet_id,
    w.public_key AS funding_wallet_public_key
  FROM implementers i
  LEFT JOIN wallets w ON w.id = i.funding_wallet_id`;

const LIST_SQL = `${IMPLEMENTER_SELECT}
  ORDER BY i.created_at ASC, i.id ASC`; // contract-allow:order:frozen-sql-text

const GET_SQL = `${IMPLEMENTER_SELECT}
  WHERE i.id = $1::uuid`;

const GET_ACTIVE_SQL = `${IMPLEMENTER_SELECT}
  WHERE i.id = $1::uuid AND i.retired_at IS NULL`;

const GENESIS_SQL = `SELECT id::text AS id
  FROM implementers
  WHERE retired_at IS NULL
  ORDER BY created_at ASC, id ASC /* contract-allow:order:frozen-sql-text */
  LIMIT 1`;

// Insert implementer + audit in one statement (both-or-neither).
// New rows start with funding_wallet_id NULL (node default).
const CREATE_SQL = `WITH inserted AS (
  INSERT INTO implementers (id, name)
  VALUES ($1::uuid, $2)
  RETURNING id::text AS id, name, created_at, retired_at,
            funding_wallet_id::text AS funding_wallet_id
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
  (SELECT retired_at FROM inserted) AS retired_at,
  (SELECT funding_wallet_id FROM inserted) AS funding_wallet_id,
  NULL::text AS funding_wallet_public_key`;

// Set retired_at only when currently active; return the row for audit details.
const RETIRE_SQL = `WITH locked AS (
  SELECT id, name, created_at, retired_at, funding_wallet_id
    FROM implementers
   WHERE id = $1::uuid
   FOR UPDATE
), updated AS (
  UPDATE implementers i
     SET retired_at = now()
    FROM locked
   WHERE i.id = locked.id
     AND locked.retired_at IS NULL
  RETURNING i.id::text AS id, i.name, i.created_at, i.retired_at,
            i.funding_wallet_id::text AS funding_wallet_id
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
  (SELECT retired_at FROM updated) AS retired_at,
  (SELECT funding_wallet_id FROM updated) AS funding_wallet_id,
  NULL::text AS funding_wallet_public_key`;

const LOCK_IMPLEMENTER_SQL = `SELECT id::text AS id, name, created_at, retired_at,
       funding_wallet_id::text AS funding_wallet_id
  FROM implementers
 WHERE id = $1::uuid
 FOR UPDATE`;

const WALLET_LOOKUP_SQL = `SELECT id::text AS id, public_key, state::text AS state,
       retired_at
  FROM wallets
 WHERE id = $1::uuid`;

const SET_FUNDING_SQL = `WITH updated AS (
  UPDATE implementers
     SET funding_wallet_id = $2::uuid
   WHERE id = $1::uuid
  RETURNING id::text AS id, name, created_at, retired_at,
            funding_wallet_id::text AS funding_wallet_id
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
  $6, NULL, $7::uuid, $8, $9, now()
FROM updated
RETURNING
  (SELECT id FROM updated) AS id,
  (SELECT name FROM updated) AS name,
  (SELECT created_at FROM updated) AS created_at,
  (SELECT retired_at FROM updated) AS retired_at,
  (SELECT funding_wallet_id FROM updated) AS funding_wallet_id`;

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
    // Re-fetch for joined public_key (retire clears nothing on funding pin).
    return (await this.get(input.id)) ?? toRecord(rows[0]);
  }

  async setFundingWallet(
    input: ImplementerSetFundingWalletInput,
  ): Promise<ImplementerSetFundingWalletOutcome> {
    const mode = input.mode;
    if (mode !== "DEFAULT" && mode !== "WALLET_ID" && mode !== "CREATE") {
      return { ok: false, reason: "invalid_mode" };
    }

    const locked = await this.sql.query<{
      id: string;
      name: string;
      created_at: unknown;
      retired_at: unknown;
      funding_wallet_id: string | null;
    }>(LOCK_IMPLEMENTER_SQL, [input.implementerId]);
    const current = locked.rows[0];
    if (current === undefined) {
      return { ok: false, reason: "implementer_not_found" };
    }
    if (current.retired_at !== null && current.retired_at !== undefined) {
      return { ok: false, reason: "implementer_retired" };
    }

    let nextWalletId: string | null = null;
    let nextPublicKey: string | null = null;

    if (mode === "DEFAULT") {
      nextWalletId = null;
      nextPublicKey = null;
    } else {
      // WALLET_ID and CREATE both attach an existing wallets row.
      // CREATE path: caller mints first (vault-backed), then passes walletId.
      const walletId = input.walletId?.trim() ?? "";
      if (walletId.length === 0) {
        return {
          ok: false,
          reason: mode === "CREATE" ? "create_not_supported" : "wallet_id_required",
        };
      }
      const wallets = await this.sql.query<{
        id: string;
        public_key: string;
        state: string;
        retired_at: unknown;
      }>(WALLET_LOOKUP_SQL, [walletId]);
      const wallet = wallets.rows[0];
      if (wallet === undefined) {
        return { ok: false, reason: "wallet_not_found" };
      }
      if (wallet.retired_at !== null && wallet.retired_at !== undefined) {
        return { ok: false, reason: "wallet_retired" };
      }
      if (wallet.state === "RETIRED") {
        return { ok: false, reason: "wallet_retired" };
      }
      nextWalletId = wallet.id;
      nextPublicKey = wallet.public_key;
    }

    const previousId = current.funding_wallet_id ?? null;
    const auditId = randomUUID();
    const detailsText = JSON.stringify({
      implementer_id: current.id,
      mode,
      previous_funding_wallet_id: previousId,
      next_funding_wallet_id: nextWalletId,
    });
    const { rows } = await this.sql.query<{
      id: string;
      name: string;
      created_at: unknown;
      retired_at: unknown;
      funding_wallet_id: string | null;
    }>(SET_FUNDING_SQL, [
      input.implementerId,
      nextWalletId,
      auditId,
      input.nodeId,
      input.actorId,
      IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
      nextWalletId,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined) {
      return { ok: false, reason: "implementer_not_found" };
    }
    return {
      ok: true,
      implementer: {
        id: rows[0].id,
        name: rows[0].name,
        created_at: toIso(rows[0].created_at),
        retired_at:
          rows[0].retired_at === null || rows[0].retired_at === undefined
            ? null
            : toIso(rows[0].retired_at),
        funding_wallet_id: nextWalletId,
        funding_wallet_public_key: nextPublicKey,
      },
    };
  }
}

export function createSqlImplementerRegistry(sql: ImplementerSqlExecutor): ImplementerRegistry {
  return new SqlImplementerRegistry(sql);
}
