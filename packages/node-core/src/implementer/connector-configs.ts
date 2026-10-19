// Connector configuration store (ZTR-1330). One row per implementer.
// Capability labels, hook target, and recorded verification posture.
// The node stores the hook target and does not fetch it.

import { CONNECTOR_SCOPES, type ConnectorScope } from "../credential/connector-scopes.js";

export type ConnectorPolicyMode = "NODE_VERIFIED" | "LEGACY";

export interface ConnectorConfigRecord {
  readonly implementer_id: string;
  readonly display_name: string;
  readonly scopes: readonly ConnectorScope[];
  readonly webhook_url: string | null;
  readonly webhook_enabled: boolean;
  readonly policy_mode: ConnectorPolicyMode;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface ConnectorConfigUpsertInput {
  readonly implementerId: string;
  readonly displayName: string;
  readonly scopes: readonly string[];
  readonly webhookUrl: string | null;
  readonly webhookEnabled: boolean;
  readonly policyMode?: ConnectorPolicyMode;
}

export interface ConnectorConfigPatchInput {
  readonly implementerId: string;
  readonly displayName?: string;
  readonly scopes?: readonly string[];
  readonly webhookUrl?: string | null;
  readonly webhookEnabled?: boolean;
  readonly policyMode?: ConnectorPolicyMode;
}

export interface ConnectorConfigStore {
  list(): Promise<readonly ConnectorConfigRecord[]>;
  get(implementerId: string): Promise<ConnectorConfigRecord | null>;
  upsert(input: ConnectorConfigUpsertInput): Promise<ConnectorConfigRecord>;
  patch(input: ConnectorConfigPatchInput): Promise<ConnectorConfigRecord | null>;
}

export interface ConnectorConfigSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

const SCOPE_SET = new Set<string>(CONNECTOR_SCOPES);

export function normalizeConnectorScopes(raw: readonly string[]): ConnectorScope[] | null {
  if (raw.length === 0) return null;
  const out: ConnectorScope[] = [];
  for (const scope of raw) {
    if (!SCOPE_SET.has(scope) || out.includes(scope as ConnectorScope)) return null;
    out.push(scope as ConnectorScope);
  }
  return out;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function scopesOf(raw: unknown): readonly ConnectorScope[] {
  let parsed = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(parsed)) return [];
  const out: ConnectorScope[] = [];
  for (const item of parsed) {
    if (typeof item === "string" && SCOPE_SET.has(item)) out.push(item as ConnectorScope);
  }
  return out;
}

interface Row extends Record<string, unknown> {
  readonly implementer_id: string;
  readonly display_name: string;
  readonly scopes: unknown;
  readonly webhook_url: string | null;
  readonly webhook_enabled: boolean;
  readonly policy_mode: string;
  readonly created_at: unknown;
  readonly updated_at: unknown;
}

function toRecord(row: Row): ConnectorConfigRecord {
  const mode: ConnectorPolicyMode = row.policy_mode === "LEGACY" ? "LEGACY" : "NODE_VERIFIED";
  return {
    implementer_id: row.implementer_id,
    display_name: row.display_name,
    scopes: scopesOf(row.scopes),
    webhook_url: row.webhook_url,
    webhook_enabled: row.webhook_enabled === true,
    policy_mode: mode,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

const SELECT_COLS = `implementer_id::text AS implementer_id,
  display_name,
  scopes,
  webhook_url,
  webhook_enabled,
  policy_mode,
  created_at,
  updated_at`;

const LIST_SQL = `SELECT ${SELECT_COLS}
  FROM connector_configs`;

const GET_SQL = `SELECT ${SELECT_COLS}
  FROM connector_configs
  WHERE implementer_id = $1::uuid`;

const UPSERT_SQL = `INSERT INTO connector_configs (
  implementer_id, display_name, scopes, webhook_url, webhook_enabled, policy_mode, created_at, updated_at
) VALUES (
  $1::uuid, $2, $3::text, $4, $5, $6, now(), now()
)
ON CONFLICT (implementer_id) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  scopes = EXCLUDED.scopes,
  webhook_url = EXCLUDED.webhook_url,
  webhook_enabled = EXCLUDED.webhook_enabled,
  policy_mode = EXCLUDED.policy_mode,
  updated_at = now()
RETURNING ${SELECT_COLS}`;

const PATCH_SQL = `UPDATE connector_configs SET
  display_name = COALESCE($2, display_name),
  scopes = COALESCE($3::text, scopes),
  webhook_url = CASE WHEN $4::boolean THEN $5 ELSE webhook_url END,
  webhook_enabled = COALESCE($6, webhook_enabled),
  policy_mode = COALESCE($7, policy_mode),
  updated_at = now()
WHERE implementer_id = $1::uuid
RETURNING ${SELECT_COLS}`;

export class SqlConnectorConfigStore implements ConnectorConfigStore {
  constructor(private readonly sql: ConnectorConfigSqlExecutor) {}

  async list(): Promise<readonly ConnectorConfigRecord[]> {
    const { rows } = await this.sql.query<Row>(LIST_SQL, []);
    return rows.map(toRecord);
  }

  async get(implementerId: string): Promise<ConnectorConfigRecord | null> {
    const { rows } = await this.sql.query<Row>(GET_SQL, [implementerId]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }

  async upsert(input: ConnectorConfigUpsertInput): Promise<ConnectorConfigRecord> {
    const scopes = normalizeConnectorScopes(input.scopes);
    if (scopes === null) {
      throw new Error("connector scopes are invalid");
    }
    const { rows } = await this.sql.query<Row>(UPSERT_SQL, [
      input.implementerId,
      input.displayName,
      JSON.stringify(scopes),
      input.webhookUrl,
      input.webhookEnabled,
      input.policyMode ?? "NODE_VERIFIED",
    ]);
    const row = rows[0];
    if (row === undefined) throw new Error("connector upsert returned no row");
    return toRecord(row);
  }

  async patch(input: ConnectorConfigPatchInput): Promise<ConnectorConfigRecord | null> {
    const scopes = input.scopes === undefined ? null : normalizeConnectorScopes(input.scopes);
    if (input.scopes !== undefined && scopes === null) {
      throw new Error("connector scopes are invalid");
    }
    const { rows } = await this.sql.query<Row>(PATCH_SQL, [
      input.implementerId,
      input.displayName ?? null,
      scopes === null ? null : JSON.stringify(scopes),
      input.webhookUrl !== undefined,
      input.webhookUrl === undefined ? null : input.webhookUrl,
      input.webhookEnabled ?? null,
      input.policyMode ?? null,
    ]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }
}

export function createSqlConnectorConfigStore(
  sql: ConnectorConfigSqlExecutor,
): ConnectorConfigStore {
  return new SqlConnectorConfigStore(sql);
}

export class InMemoryConnectorConfigStore implements ConnectorConfigStore {
  readonly rows = new Map<string, ConnectorConfigRecord>();

  async list(): Promise<readonly ConnectorConfigRecord[]> {
    return [...this.rows.values()];
  }

  async get(implementerId: string): Promise<ConnectorConfigRecord | null> {
    return this.rows.get(implementerId) ?? null;
  }

  async upsert(input: ConnectorConfigUpsertInput): Promise<ConnectorConfigRecord> {
    const scopes = normalizeConnectorScopes(input.scopes);
    if (scopes === null) throw new Error("connector scopes are invalid");
    const now = new Date().toISOString();
    const prev = this.rows.get(input.implementerId);
    const next: ConnectorConfigRecord = {
      implementer_id: input.implementerId,
      display_name: input.displayName,
      scopes,
      webhook_url: input.webhookUrl,
      webhook_enabled: input.webhookEnabled,
      policy_mode: input.policyMode ?? "NODE_VERIFIED",
      created_at: prev?.created_at ?? now,
      updated_at: now,
    };
    this.rows.set(next.implementer_id, next);
    return next;
  }

  async patch(input: ConnectorConfigPatchInput): Promise<ConnectorConfigRecord | null> {
    const prev = this.rows.get(input.implementerId);
    if (prev === undefined) return null;
    const scopes = input.scopes === undefined ? prev.scopes : normalizeConnectorScopes(input.scopes);
    if (scopes === null) throw new Error("connector scopes are invalid");
    const next: ConnectorConfigRecord = {
      ...prev,
      display_name: input.displayName ?? prev.display_name,
      scopes,
      webhook_url: input.webhookUrl === undefined ? prev.webhook_url : input.webhookUrl,
      webhook_enabled: input.webhookEnabled ?? prev.webhook_enabled,
      policy_mode: input.policyMode ?? prev.policy_mode,
      updated_at: new Date().toISOString(),
    };
    this.rows.set(next.implementer_id, next);
    return next;
  }
}
