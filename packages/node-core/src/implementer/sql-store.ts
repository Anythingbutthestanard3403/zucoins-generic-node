// Durable ImplementerRegistry over Postgres. Driver-agnostic SqlExecutor
// (pg.Pool / PoolClient both satisfy). Create/retire/setFundingWallet write
// audit_log in the same statement so a surrounding TX rolls both back together.

import { createHash, randomUUID } from "node:crypto";

import {
  IMPLEMENTER_AUDIT_CREATED,
  IMPLEMENTER_AUDIT_CUSTOM_ROUTING_CHANGED,
  IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED,
  IMPLEMENTER_AUDIT_RESERVE_WALLETS_CHANGED,
  IMPLEMENTER_AUDIT_RETIRED,
  ImplementerRegistryError,
  type ImplementerCreateInput,
  type ImplementerRecord,
  type ImplementerRegistry,
  type ImplementerReserveWallet,
  type ImplementerRetireInput,
  type ImplementerSetCustomRoutingInput,
  type ImplementerSetCustomRoutingOutcome,
  type ImplementerSetFundingWalletInput,
  type ImplementerSetFundingWalletOutcome,
  type ImplementerSetReserveWalletsInput,
  type ImplementerSetReserveWalletsOutcome,
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
  readonly allow_custom_routing: boolean | null;
  readonly reserve_wallets: unknown;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseReserveWallets(value: unknown): readonly ImplementerReserveWallet[] {
  let raw = value;
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw) as unknown;
    } catch {
      return [];
    }
  }
  if (!Array.isArray(raw)) return [];
  const out: ImplementerReserveWallet[] = [];
  for (const item of raw) {
    if (item === null || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    out.push({
      wallet_id: String(row.wallet_id),
      public_key: row.public_key == null ? null : String(row.public_key),
      display_label: row.display_label == null ? null : String(row.display_label),
      is_default: row.is_default === true,
    });
  }
  return out;
}

function toRecord(row: ImplementerRow): ImplementerRecord {
  return {
    id: row.id,
    name: row.name,
    created_at: toIso(row.created_at),
    retired_at: row.retired_at === null || row.retired_at === undefined ? null : toIso(row.retired_at),
    funding_wallet_id: row.funding_wallet_id ?? null,
    funding_wallet_public_key: row.funding_wallet_public_key ?? null,
    allow_custom_routing: row.allow_custom_routing === true,
    reserve_wallets: parseReserveWallets(row.reserve_wallets),
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
    w.public_key AS funding_wallet_public_key,
    i.allow_custom_routing,
    COALESCE((
      SELECT json_agg(json_build_object(
        'wallet_id', irw.wallet_id::text,
        'public_key', rw.public_key,
        'display_label', rw.display_label,
        'is_default', irw.is_default
      ) ORDER BY irw.is_default DESC, irw.wallet_id) -- contract-allow:order:frozen structural vocabulary
      FROM implementer_reserve_wallets irw
      JOIN wallets rw ON rw.id = irw.wallet_id
      WHERE irw.implementer_id = i.id
    ), '[]'::json) AS reserve_wallets
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
  NULL::text AS funding_wallet_public_key,
  false AS allow_custom_routing,
  '[]'::json AS reserve_wallets`;

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
            i.funding_wallet_id::text AS funding_wallet_id,
            i.allow_custom_routing
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
  NULL::text AS funding_wallet_public_key,
  COALESCE((SELECT allow_custom_routing FROM updated), false) AS allow_custom_routing,
  '[]'::json AS reserve_wallets`;

const LOCK_IMPLEMENTER_SQL = `SELECT id::text AS id, name, created_at, retired_at,
       funding_wallet_id::text AS funding_wallet_id,
       allow_custom_routing
  FROM implementers
 WHERE id = $1::uuid
 FOR UPDATE`;

const WALLET_LOOKUP_SQL = `SELECT id::text AS id, public_key, state::text AS state,
       retired_at, display_label, node_id::text AS node_id,
       allow_internal_move
  FROM wallets
 WHERE id = $1::uuid`;

const SET_FUNDING_SQL = `WITH updated AS (
  UPDATE implementers
     SET funding_wallet_id = $2::uuid
   WHERE id = $1::uuid
  RETURNING id::text AS id
), cleared AS (
  DELETE FROM implementer_reserve_wallets
   WHERE implementer_id = $1::uuid
     AND EXISTS (SELECT 1 FROM updated)
  RETURNING 1
), inserted AS (
  INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default)
  SELECT $1::uuid, $2::uuid, true
   WHERE $2::uuid IS NOT NULL
     AND EXISTS (SELECT 1 FROM updated)
     AND (SELECT count(*) FROM cleared) >= 0
  RETURNING 1
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
  $6, NULL, $7::uuid, $8, $9, now()
FROM updated
WHERE (SELECT count(*) FROM inserted) >= 0
RETURNING (SELECT id FROM updated) AS id`;

const SET_RESERVE_SQL = `WITH locked AS (
  SELECT id::text AS id, retired_at
    FROM implementers
   WHERE id = $1::uuid
   FOR UPDATE
), wanted AS (
  SELECT DISTINCT unnest(COALESCE($3::uuid[], ARRAY[]::uuid[])) AS wallet_id
), matched AS (
  SELECT w.id::text AS wallet_id,
         (w.node_id = $2::uuid) AS same_node,
         (w.retired_at IS NULL AND w.state::text <> 'RETIRED') AS live,
         (w.allow_internal_move IS TRUE) AS movable
    FROM wanted q
    JOIN wallets w ON w.id = q.wallet_id
), decision AS (
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM locked) THEN 'implementer_not_found'
    WHEN (SELECT retired_at FROM locked) IS NOT NULL THEN 'implementer_retired'
    WHEN (SELECT count(*) FROM wanted) = 0 AND $4::uuid IS NOT NULL THEN 'default_mismatch'
    WHEN (SELECT count(*) FROM wanted) > 0 AND (
      $4::uuid IS NULL
      OR NOT EXISTS (SELECT 1 FROM wanted WHERE wallet_id = $4::uuid)
    ) THEN 'default_mismatch'
    WHEN (SELECT count(*) FROM wanted) <> (SELECT count(*) FROM matched) THEN 'wallet_not_found'
    WHEN EXISTS (SELECT 1 FROM matched WHERE NOT same_node) THEN 'wallet_not_found'
    WHEN EXISTS (SELECT 1 FROM matched WHERE NOT live) THEN 'wallet_retired'
    WHEN EXISTS (SELECT 1 FROM matched WHERE NOT movable) THEN 'wallet_ineligible'
    ELSE 'ok'
  END AS reason
), cleared AS (
  DELETE FROM implementer_reserve_wallets irw
   WHERE irw.implementer_id = $1::uuid
     AND (SELECT reason FROM decision) = 'ok'
  RETURNING 1
), inserted AS (
  INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default)
  SELECT $1::uuid, m.wallet_id::uuid, (m.wallet_id = $4::text)
    FROM matched m
   WHERE (SELECT reason FROM decision) = 'ok'
     AND (SELECT count(*) FROM cleared) >= 0
  RETURNING 1
), updated AS (
  UPDATE implementers i
     SET funding_wallet_id = CASE
           WHEN (SELECT count(*) FROM wanted) = 0 THEN NULL
           ELSE $4::uuid
         END
    FROM decision d
   WHERE i.id = $1::uuid
     AND d.reason = 'ok'
     AND (SELECT count(*) FROM inserted) >= 0
  RETURNING i.id
), audited AS (
  INSERT INTO audit_log (
    id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
    details_text, details_sha256, created_at
  )
  SELECT
    $5::uuid, $2::uuid, 'OPERATOR_SESSION', $6,
    $7, NULL, $4::uuid, $8, $9, now()
  FROM decision d
  WHERE d.reason = 'ok'
    AND EXISTS (SELECT 1 FROM updated)
  RETURNING 1
)
SELECT (SELECT reason FROM decision) AS reason,
       (SELECT count(*) FROM audited) AS audited`;

const SET_CUSTOM_ROUTING_SQL = `WITH updated AS (
  UPDATE implementers
     SET allow_custom_routing = $2::boolean
   WHERE id = $1::uuid
     AND retired_at IS NULL
  RETURNING id::text AS id
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
  $6, NULL, NULL, $7, $8, now()
FROM updated
RETURNING (SELECT id FROM updated) AS id`;

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

    if (mode === "DEFAULT") {
      nextWalletId = null;
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
    }

    const previousId = current.funding_wallet_id ?? null;
    const auditId = randomUUID();
    const detailsText = JSON.stringify({
      implementer_id: current.id,
      mode,
      previous_funding_wallet_id: previousId,
      next_funding_wallet_id: nextWalletId,
    });
    const { rows } = await this.sql.query<{ id: string }>(SET_FUNDING_SQL, [
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
    const reloaded = await this.get(input.implementerId);
    if (reloaded === null) {
      return { ok: false, reason: "implementer_not_found" };
    }
    return { ok: true, implementer: reloaded };
  }

  async setReserveWallets(
    input: ImplementerSetReserveWalletsInput,
  ): Promise<ImplementerSetReserveWalletsOutcome> {
    const ids = [...new Set(input.walletIds.map((id) => id.trim()).filter((id) => id.length > 0))];
    const auditId = randomUUID();
    const detailsText = JSON.stringify({
      implementer_id: input.implementerId,
      wallet_ids: ids,
      default_wallet_id: input.defaultWalletId,
    });
    const { rows } = await this.sql.query<{ reason: string }>(SET_RESERVE_SQL, [
      input.implementerId,
      input.nodeId,
      ids,
      input.defaultWalletId,
      auditId,
      input.actorId,
      IMPLEMENTER_AUDIT_RESERVE_WALLETS_CHANGED,
      detailsText,
      detailsSha256(detailsText),
    ]);
    const reason = rows[0]?.reason;
    if (reason === undefined) {
      return { ok: false, reason: "implementer_not_found" };
    }
    if (reason !== "ok") {
      if (
        reason === "implementer_not_found" ||
        reason === "implementer_retired" ||
        reason === "wallet_not_found" ||
        reason === "wallet_retired" ||
        reason === "wallet_ineligible" ||
        reason === "default_mismatch"
      ) {
        return { ok: false, reason };
      }
      return { ok: false, reason: "wallet_not_found" };
    }
    const reloaded = await this.get(input.implementerId);
    if (reloaded === null) return { ok: false, reason: "implementer_not_found" };
    return { ok: true, implementer: reloaded };
  }

  async setCustomRouting(
    input: ImplementerSetCustomRoutingInput,
  ): Promise<ImplementerSetCustomRoutingOutcome> {
    const locked = await this.sql.query<{ id: string; retired_at: unknown }>(
      `SELECT id::text AS id, retired_at FROM implementers WHERE id = $1::uuid`,
      [input.implementerId],
    );
    const current = locked.rows[0];
    if (current === undefined) return { ok: false, reason: "implementer_not_found" };
    if (current.retired_at !== null && current.retired_at !== undefined) {
      return { ok: false, reason: "implementer_retired" };
    }
    const auditId = randomUUID();
    const detailsText = JSON.stringify({
      implementer_id: input.implementerId,
      allow_custom_routing: input.allowCustomRouting,
    });
    const { rows } = await this.sql.query<{ id: string }>(SET_CUSTOM_ROUTING_SQL, [
      input.implementerId,
      input.allowCustomRouting,
      auditId,
      input.nodeId,
      input.actorId,
      IMPLEMENTER_AUDIT_CUSTOM_ROUTING_CHANGED,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined) return { ok: false, reason: "implementer_retired" };
    const reloaded = await this.get(input.implementerId);
    if (reloaded === null) return { ok: false, reason: "implementer_not_found" };
    return { ok: true, implementer: reloaded };
  }
}

export function createSqlImplementerRegistry(sql: ImplementerSqlExecutor): ImplementerRegistry {
  return new SqlImplementerRegistry(sql);
}
