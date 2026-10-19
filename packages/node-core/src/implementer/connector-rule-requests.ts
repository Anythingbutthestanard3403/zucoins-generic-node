// Spend-rule request store (ZTR-1331).
// Rows stay PENDING until an operator admits or declines them.
// The pending cap is enforced inside the insert statement.
// Audit is written in the same statement. Hook targets are not fetched.

import { createHash, randomUUID } from "node:crypto";

export const CONNECTOR_RULE_REQUEST_PENDING_CAP = 10 as const;
export const CONNECTOR_RULE_REQUEST_CREATED_ACTION = "connector_rule_request.created" as const;
export const CONNECTOR_RULE_REQUEST_APPROVED_ACTION = "connector_rule_request.approved" as const;
export const CONNECTOR_RULE_REQUEST_REJECTED_ACTION = "connector_rule_request.rejected" as const;

export type ConnectorRuleRequestStatus = "PENDING" | "APPROVED" | "REJECTED";
export type ConnectorRuleRequestStoreErrorCode = "RATE_LIMITED" | "NOT_FOUND" | "NOT_PENDING";

export class ConnectorRuleRequestStoreError extends Error {
  readonly code: ConnectorRuleRequestStoreErrorCode;

  constructor(code: ConnectorRuleRequestStoreErrorCode, message: string) {
    super(message);
    this.name = "ConnectorRuleRequestStoreError";
    this.code = code;
  }
}

export interface ConnectorRuleRequestRecord {
  readonly request_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly rule_id: string;
  readonly label: string;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly status: ConnectorRuleRequestStatus;
  readonly webhook_enabled: boolean;
  readonly created_at: string;
  readonly decided_at: string | null;
  readonly decided_by: string | null;
}

export interface ConnectorRuleRequestCreateInput {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly ruleId: string;
  readonly label: string;
  readonly reserveWalletId: string | null;
  readonly totalCapZkz: string | null;
  readonly perSendMaxZkz: string;
  readonly perSendMinZkz: string | null;
  readonly windowHours: number;
  readonly windowCapZkz: string;
  readonly expiresAt: string | null;
  readonly webhookEnabled: boolean;
  readonly actorId: string;
}

export interface ConnectorRuleRequestDecideInput {
  readonly requestId: string;
  readonly nodeId: string;
  readonly decision: "APPROVED" | "REJECTED";
  readonly actorId: string;
  readonly reserveWalletId?: string | null;
  readonly totalCapZkz?: string | null;
  readonly perSendMaxZkz?: string;
  readonly windowHours?: number;
  readonly windowCapZkz?: string;
  readonly expiresAt?: string | null;
}

export interface ConnectorRuleRequestListFilter {
  readonly nodeId?: string;
  readonly implementerId?: string;
  readonly status?: ConnectorRuleRequestStatus;
}

export interface ConnectorRuleRequestAudit {
  readonly action: string;
  readonly actorKind: "IMPLEMENTER" | "OPERATOR_SESSION";
  readonly actorId: string;
  readonly nodeId: string;
  readonly detailsText: string;
}

export interface ConnectorRuleRequestStore {
  list(filter?: ConnectorRuleRequestListFilter): Promise<readonly ConnectorRuleRequestRecord[]>;
  get(requestId: string): Promise<ConnectorRuleRequestRecord | null>;
  create(input: ConnectorRuleRequestCreateInput): Promise<ConnectorRuleRequestRecord>;
  decide(input: ConnectorRuleRequestDecideInput): Promise<ConnectorRuleRequestRecord>;
}

export interface ConnectorRuleRequestSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

function toIso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function auditDetails(row: Pick<ConnectorRuleRequestRecord, "request_id" | "rule_id" | "status" | "webhook_enabled">): string {
  return JSON.stringify({
    request_id: row.request_id,
    rule_id: row.rule_id,
    status: row.status,
    webhook_enabled: row.webhook_enabled,
  });
}

interface Row extends Record<string, unknown> {
  readonly request_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly rule_id: string;
  readonly label: string;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number | string;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly status: string;
  readonly webhook_enabled: boolean;
  readonly created_at: unknown;
  readonly decided_at: unknown;
  readonly decided_by: string | null;
}

function toRecord(row: Row): ConnectorRuleRequestRecord {
  const status: ConnectorRuleRequestStatus =
    row.status === "APPROVED" || row.status === "REJECTED" ? row.status : "PENDING";
  return {
    request_id: row.request_id,
    node_id: row.node_id,
    implementer_id: row.implementer_id,
    rule_id: row.rule_id,
    label: row.label,
    reserve_wallet_id: row.reserve_wallet_id,
    total_cap_zkz: row.total_cap_zkz,
    per_send_max_zkz: row.per_send_max_zkz,
    per_send_min_zkz: row.per_send_min_zkz,
    window_hours: Number(row.window_hours),
    window_cap_zkz: row.window_cap_zkz,
    expires_at: row.expires_at,
    status,
    webhook_enabled: row.webhook_enabled === true,
    created_at: toIso(row.created_at) ?? new Date(0).toISOString(),
    decided_at: toIso(row.decided_at),
    decided_by: row.decided_by,
  };
}

const SELECT_COLS = `request_id::text AS request_id,
  node_id::text AS node_id,
  implementer_id::text AS implementer_id,
  rule_id,
  label,
  reserve_wallet_id::text AS reserve_wallet_id,
  total_cap_zkz,
  per_send_max_zkz,
  per_send_min_zkz,
  window_hours,
  window_cap_zkz,
  expires_at,
  status,
  webhook_enabled,
  created_at,
  decided_at,
  decided_by::text AS decided_by`;

const LIST_SQL = `SELECT ${SELECT_COLS}
  FROM connector_rule_requests
  WHERE ($1::uuid IS NULL OR node_id = $1::uuid)
    AND ($2::uuid IS NULL OR implementer_id = $2::uuid)
    AND ($3::text IS NULL OR status = $3)`;

const GET_SQL = `SELECT ${SELECT_COLS}
  FROM connector_rule_requests
  WHERE request_id = $1::uuid`;

const CREATE_RETURNING = `SELECT
  inserted.request_id::text AS request_id,
  inserted.node_id::text AS node_id,
  inserted.implementer_id::text AS implementer_id,
  inserted.rule_id,
  inserted.label,
  inserted.reserve_wallet_id::text AS reserve_wallet_id,
  inserted.total_cap_zkz,
  inserted.per_send_max_zkz,
  inserted.per_send_min_zkz,
  inserted.window_hours,
  inserted.window_cap_zkz,
  inserted.expires_at,
  inserted.status,
  inserted.webhook_enabled,
  inserted.created_at,
  inserted.decided_at,
  inserted.decided_by::text AS decided_by
FROM inserted
JOIN audited ON true`;

const CREATE_STATEMENT = `WITH room AS (
  SELECT count(*)::int AS n
    FROM connector_rule_requests
   WHERE implementer_id = $1::uuid
     AND status = 'PENDING'
),
inserted AS (
  INSERT INTO connector_rule_requests (
    request_id, node_id, implementer_id, rule_id, label,
    reserve_wallet_id, total_cap_zkz, per_send_max_zkz, per_send_min_zkz,
    window_hours, window_cap_zkz, expires_at, status, webhook_enabled, created_at
  )
  SELECT
    $2::uuid, $3::uuid, $1::uuid, $4, $5,
    $6::uuid, $7, $8, $9,
    $10::int, $11, $12, 'PENDING', $13::boolean, now()
  FROM room
  WHERE room.n < $14::int
  RETURNING *
),
audited AS (
  INSERT INTO audit_log (
    id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
    details_text, details_sha256, created_at
  )
  SELECT
    $15::uuid, inserted.node_id, 'IMPLEMENTER', $16,
    $17, NULL, NULL, $18, $19, now()
  FROM inserted
  RETURNING 1 AS ok
)
${CREATE_RETURNING}`;

const APPROVE_STATEMENT = `WITH updated AS (
  UPDATE connector_rule_requests SET
    status = 'APPROVED',
    decided_at = now(),
    decided_by = $3::uuid,
    reserve_wallet_id = $4::uuid,
    total_cap_zkz = $5,
    per_send_max_zkz = $6,
    window_hours = $7::int,
    window_cap_zkz = $8,
    expires_at = $9
  WHERE request_id = $1::uuid
    AND node_id = $2::uuid
    AND status = 'PENDING'
  RETURNING *
),
audited AS (
  INSERT INTO audit_log (
    id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
    details_text, details_sha256, created_at
  )
  SELECT
    $10::uuid, updated.node_id, 'OPERATOR_SESSION', $11,
    $12, NULL, NULL, $13, $14, now()
  FROM updated
  RETURNING 1 AS ok
)
SELECT
  updated.request_id::text AS request_id,
  updated.node_id::text AS node_id,
  updated.implementer_id::text AS implementer_id,
  updated.rule_id,
  updated.label,
  updated.reserve_wallet_id::text AS reserve_wallet_id,
  updated.total_cap_zkz,
  updated.per_send_max_zkz,
  updated.per_send_min_zkz,
  updated.window_hours,
  updated.window_cap_zkz,
  updated.expires_at,
  updated.status,
  updated.webhook_enabled,
  updated.created_at,
  updated.decided_at,
  updated.decided_by::text AS decided_by
FROM updated
JOIN audited ON true`;

const REJECT_STATEMENT = `WITH updated AS (
  UPDATE connector_rule_requests SET
    status = 'REJECTED',
    decided_at = now(),
    decided_by = $3::uuid
  WHERE request_id = $1::uuid
    AND node_id = $2::uuid
    AND status = 'PENDING'
  RETURNING *
),
audited AS (
  INSERT INTO audit_log (
    id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
    details_text, details_sha256, created_at
  )
  SELECT
    $4::uuid, updated.node_id, 'OPERATOR_SESSION', $5,
    $6, NULL, NULL, $7, $8, now()
  FROM updated
  RETURNING 1 AS ok
)
SELECT
  updated.request_id::text AS request_id,
  updated.node_id::text AS node_id,
  updated.implementer_id::text AS implementer_id,
  updated.rule_id,
  updated.label,
  updated.reserve_wallet_id::text AS reserve_wallet_id,
  updated.total_cap_zkz,
  updated.per_send_max_zkz,
  updated.per_send_min_zkz,
  updated.window_hours,
  updated.window_cap_zkz,
  updated.expires_at,
  updated.status,
  updated.webhook_enabled,
  updated.created_at,
  updated.decided_at,
  updated.decided_by::text AS decided_by
FROM updated
JOIN audited ON true`;

export class SqlConnectorRuleRequestStore implements ConnectorRuleRequestStore {
  constructor(private readonly sql: ConnectorRuleRequestSqlExecutor) {}

  async list(filter: ConnectorRuleRequestListFilter = {}): Promise<readonly ConnectorRuleRequestRecord[]> {
    const { rows } = await this.sql.query<Row>(LIST_SQL, [
      filter.nodeId ?? null,
      filter.implementerId ?? null,
      filter.status ?? null,
    ]);
    return rows.map(toRecord);
  }

  async get(requestId: string): Promise<ConnectorRuleRequestRecord | null> {
    const { rows } = await this.sql.query<Row>(GET_SQL, [requestId]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }

  async create(input: ConnectorRuleRequestCreateInput): Promise<ConnectorRuleRequestRecord> {
    const requestId = randomUUID();
    const draft: ConnectorRuleRequestRecord = {
      request_id: requestId,
      node_id: input.nodeId,
      implementer_id: input.implementerId,
      rule_id: input.ruleId,
      label: input.label,
      reserve_wallet_id: input.reserveWalletId,
      total_cap_zkz: input.totalCapZkz,
      per_send_max_zkz: input.perSendMaxZkz,
      per_send_min_zkz: input.perSendMinZkz,
      window_hours: input.windowHours,
      window_cap_zkz: input.windowCapZkz,
      expires_at: input.expiresAt,
      status: "PENDING",
      webhook_enabled: input.webhookEnabled,
      created_at: "",
      decided_at: null,
      decided_by: null,
    };
    const details = auditDetails(draft);
    const { rows } = await this.sql.query<Row>(CREATE_STATEMENT, [
      input.implementerId,
      requestId,
      input.nodeId,
      input.ruleId,
      input.label,
      input.reserveWalletId,
      input.totalCapZkz,
      input.perSendMaxZkz,
      input.perSendMinZkz,
      input.windowHours,
      input.windowCapZkz,
      input.expiresAt,
      input.webhookEnabled,
      CONNECTOR_RULE_REQUEST_PENDING_CAP,
      randomUUID(),
      input.actorId,
      CONNECTOR_RULE_REQUEST_CREATED_ACTION,
      details,
      detailsSha256(details),
    ]);
    const row = rows[0];
    if (row === undefined) {
      throw new ConnectorRuleRequestStoreError(
        "RATE_LIMITED",
        "pending rule request cap is reached",
      );
    }
    return toRecord(row);
  }

  async decide(input: ConnectorRuleRequestDecideInput): Promise<ConnectorRuleRequestRecord> {
    const existing = await this.get(input.requestId);
    const webhookEnabled = existing?.webhook_enabled === true;
    const ruleId = existing?.rule_id ?? "";
    const details = auditDetails({
      request_id: input.requestId,
      rule_id: ruleId,
      status: input.decision,
      webhook_enabled: webhookEnabled,
    });
    const sha = detailsSha256(details);
    const { rows } =
      input.decision === "APPROVED"
        ? await this.sql.query<Row>(APPROVE_STATEMENT, [
            input.requestId,
            input.nodeId,
            input.actorId,
            input.reserveWalletId ?? null,
            input.totalCapZkz ?? null,
            input.perSendMaxZkz ?? existing?.per_send_max_zkz ?? "",
            input.windowHours ?? existing?.window_hours ?? 1,
            input.windowCapZkz ?? existing?.window_cap_zkz ?? "",
            input.expiresAt === undefined ? (existing?.expires_at ?? null) : input.expiresAt,
            randomUUID(),
            input.actorId,
            CONNECTOR_RULE_REQUEST_APPROVED_ACTION,
            details,
            sha,
          ])
        : await this.sql.query<Row>(REJECT_STATEMENT, [
            input.requestId,
            input.nodeId,
            input.actorId,
            randomUUID(),
            input.actorId,
            CONNECTOR_RULE_REQUEST_REJECTED_ACTION,
            details,
            sha,
          ]);
    const row = rows[0];
    if (row !== undefined) return toRecord(row);
    if (existing === null || existing.node_id !== input.nodeId) {
      throw new ConnectorRuleRequestStoreError("NOT_FOUND", "rule request not found");
    }
    throw new ConnectorRuleRequestStoreError("NOT_PENDING", "rule request is not pending");
  }
}

export function createSqlConnectorRuleRequestStore(
  sql: ConnectorRuleRequestSqlExecutor,
): ConnectorRuleRequestStore {
  return new SqlConnectorRuleRequestStore(sql);
}

export class InMemoryConnectorRuleRequestStore implements ConnectorRuleRequestStore {
  readonly rows = new Map<string, ConnectorRuleRequestRecord>();
  readonly audits: ConnectorRuleRequestAudit[] = [];

  async list(filter: ConnectorRuleRequestListFilter = {}): Promise<readonly ConnectorRuleRequestRecord[]> {
    const out: ConnectorRuleRequestRecord[] = [];
    for (const row of this.rows.values()) {
      if (filter.nodeId !== undefined && row.node_id !== filter.nodeId) continue;
      if (filter.implementerId !== undefined && row.implementer_id !== filter.implementerId) continue;
      if (filter.status !== undefined && row.status !== filter.status) continue;
      out.push(row);
    }
    return out;
  }

  async get(requestId: string): Promise<ConnectorRuleRequestRecord | null> {
    return this.rows.get(requestId) ?? null;
  }

  async create(input: ConnectorRuleRequestCreateInput): Promise<ConnectorRuleRequestRecord> {
    let pending = 0;
    for (const row of this.rows.values()) {
      if (row.implementer_id === input.implementerId && row.status === "PENDING") pending += 1;
    }
    if (pending >= CONNECTOR_RULE_REQUEST_PENDING_CAP) {
      throw new ConnectorRuleRequestStoreError(
        "RATE_LIMITED",
        "pending rule request cap is reached",
      );
    }
    const now = new Date().toISOString();
    const record: ConnectorRuleRequestRecord = {
      request_id: randomUUID(),
      node_id: input.nodeId,
      implementer_id: input.implementerId,
      rule_id: input.ruleId,
      label: input.label,
      reserve_wallet_id: input.reserveWalletId,
      total_cap_zkz: input.totalCapZkz,
      per_send_max_zkz: input.perSendMaxZkz,
      per_send_min_zkz: input.perSendMinZkz,
      window_hours: input.windowHours,
      window_cap_zkz: input.windowCapZkz,
      expires_at: input.expiresAt,
      status: "PENDING",
      webhook_enabled: input.webhookEnabled,
      created_at: now,
      decided_at: null,
      decided_by: null,
    };
    this.rows.set(record.request_id, record);
    this.audits.push({
      action: CONNECTOR_RULE_REQUEST_CREATED_ACTION,
      actorKind: "IMPLEMENTER",
      actorId: input.actorId,
      nodeId: input.nodeId,
      detailsText: auditDetails(record),
    });
    return record;
  }

  async decide(input: ConnectorRuleRequestDecideInput): Promise<ConnectorRuleRequestRecord> {
    const existing = this.rows.get(input.requestId);
    if (existing === undefined || existing.node_id !== input.nodeId) {
      throw new ConnectorRuleRequestStoreError("NOT_FOUND", "rule request not found");
    }
    if (existing.status !== "PENDING") {
      throw new ConnectorRuleRequestStoreError("NOT_PENDING", "rule request is not pending");
    }
    const now = new Date().toISOString();
    const next: ConnectorRuleRequestRecord =
      input.decision === "APPROVED"
        ? {
            ...existing,
            status: "APPROVED",
            decided_at: now,
            decided_by: input.actorId,
            reserve_wallet_id:
              input.reserveWalletId !== undefined ? input.reserveWalletId : existing.reserve_wallet_id,
            total_cap_zkz: input.totalCapZkz !== undefined ? input.totalCapZkz : existing.total_cap_zkz,
            per_send_max_zkz: input.perSendMaxZkz ?? existing.per_send_max_zkz,
            window_hours: input.windowHours ?? existing.window_hours,
            window_cap_zkz: input.windowCapZkz ?? existing.window_cap_zkz,
            expires_at: input.expiresAt !== undefined ? input.expiresAt : existing.expires_at,
          }
        : {
            ...existing,
            status: "REJECTED",
            decided_at: now,
            decided_by: input.actorId,
          };
    this.rows.set(next.request_id, next);
    this.audits.push({
      action:
        input.decision === "APPROVED"
          ? CONNECTOR_RULE_REQUEST_APPROVED_ACTION
          : CONNECTOR_RULE_REQUEST_REJECTED_ACTION,
      actorKind: "OPERATOR_SESSION",
      actorId: input.actorId,
      nodeId: input.nodeId,
      detailsText: auditDetails(next),
    });
    return next;
  }
}
