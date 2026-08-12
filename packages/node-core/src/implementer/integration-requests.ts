// Integration-request operator store (ZTR-1240).
// List PENDING + CAS approve/decline. Create-implementer + policy write stay in
// the admin TX caller (module graph: implementer must not import send/).

import { createHash, randomUUID } from "node:crypto";

export const INTEGRATION_REQUEST_APPROVED_ACTION =
  "integration_request.approved" as const;
export const INTEGRATION_REQUEST_DECLINED_ACTION =
  "integration_request.declined" as const;

export type IntegrationRequestListingStatus =
  | "PENDING"
  | "APPROVED"
  | "DECLINED"
  | "EXPIRED"
  | "CLAIMED";

export interface IntegrationRequestRecord {
  readonly id: string;
  readonly node_id: string;
  readonly display_name: string;
  readonly requested_scopes: readonly string[];
  readonly proposed_rule_json: string;
  readonly approved_rule_json: string | null;
  readonly status: IntegrationRequestListingStatus;
  readonly row_version: number;
  readonly created_at: string;
  readonly expires_at: string;
  readonly decided_at: string | null;
  readonly decided_by: string | null;
  readonly implementer_id: string | null;
}

export interface IntegrationRequestListFilter {
  readonly nodeId: string;
  readonly status?: IntegrationRequestListingStatus;
}

export interface IntegrationRequestApproveInput {
  readonly id: string;
  readonly nodeId: string;
  readonly expectedRowVersion: number;
  /** Canonical approved rule JSON (operator-final; includes stamped implementer_id). */
  readonly approvedRuleJson: string;
  readonly implementerId: string;
  /** admin_operators.id — schema decided_by. */
  readonly decidedBy: string;
  /** Audit actor (OPERATOR_SESSION). Prefer operator id for consistency with policy writes. */
  readonly actorId: string;
}

export interface IntegrationRequestDeclineInput {
  readonly id: string;
  readonly nodeId: string;
  readonly expectedRowVersion: number;
  readonly decidedBy: string;
  readonly actorId: string;
}

export type IntegrationRequestStoreErrorCode =
  | "NOT_FOUND"
  | "CAS_MISS"
  | "WRONG_NODE"
  | "INVALID_STATE";

export class IntegrationRequestStoreError extends Error {
  constructor(
    message: string,
    readonly code: IntegrationRequestStoreErrorCode,
  ) {
    super(message);
    this.name = "IntegrationRequestStoreError";
  }
}

/**
 * Operator-facing integration request port. Writers are CAS on
 * (status, row_version); losers throw CAS_MISS so the surrounding TX rolls back.
 */
export interface IntegrationRequestStore {
  list(filter: IntegrationRequestListFilter): Promise<readonly IntegrationRequestRecord[]>;
  get(id: string): Promise<IntegrationRequestRecord | null>;
  /**
   * CAS PENDING→APPROVED. Caller must have already created implementer_id and
   * written the policy rule on the same TX client.
   */
  approve(input: IntegrationRequestApproveInput): Promise<IntegrationRequestRecord>;
  /** CAS PENDING→DECLINED. No implementer / policy side effects. */
  decline(input: IntegrationRequestDeclineInput): Promise<IntegrationRequestRecord>;
}

export interface IntegrationRequestSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

interface Row extends Record<string, unknown> {
  readonly id: string;
  readonly node_id: string;
  readonly display_name: string;
  readonly requested_scopes: unknown;
  readonly proposed_rule_json: string;
  readonly approved_rule_json: string | null;
  readonly status: string;
  readonly row_version: string | number;
  readonly created_at: unknown;
  readonly expires_at: unknown;
  readonly decided_at: unknown;
  readonly decided_by: string | null;
  readonly implementer_id: string | null;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

function scopesOf(raw: unknown): readonly string[] {
  if (Array.isArray(raw)) return raw.map(String);
  return [];
}

function toRecord(row: Row): IntegrationRequestRecord {
  return {
    id: row.id,
    node_id: row.node_id,
    display_name: row.display_name,
    requested_scopes: scopesOf(row.requested_scopes),
    proposed_rule_json: row.proposed_rule_json,
    approved_rule_json: row.approved_rule_json,
    status: row.status as IntegrationRequestListingStatus,
    row_version: Number(row.row_version),
    created_at: toIso(row.created_at),
    expires_at: toIso(row.expires_at),
    decided_at: toIsoOrNull(row.decided_at),
    decided_by: row.decided_by,
    implementer_id: row.implementer_id,
  };
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const SELECT_COLS = `id::text AS id,
  node_id::text AS node_id,
  display_name,
  requested_scopes,
  proposed_rule_json,
  approved_rule_json,
  status,
  row_version,
  created_at,
  expires_at,
  decided_at,
  decided_by::text AS decided_by,
  implementer_id::text AS implementer_id`;

const LIST_SQL = `SELECT ${SELECT_COLS}
  FROM integration_requests
  WHERE node_id = $1::uuid
    AND ($2::text IS NULL OR status = $2)
  ORDER BY created_at ASC, id ASC`; // contract-allow:order:frozen-sql-text

const GET_SQL = `SELECT ${SELECT_COLS}
  FROM integration_requests WHERE id = $1::uuid`;

// CAS PENDING→APPROVED + audit in one statement (both-or-neither).
const APPROVE_SQL = `WITH updated AS (
  UPDATE integration_requests
     SET status = 'APPROVED',
         row_version = row_version + 1,
         approved_rule_json = $3,
         decided_at = now(),
         decided_by = $4::uuid,
         implementer_id = $5::uuid
   WHERE id = $1::uuid
     AND node_id = $2::uuid
     AND status = 'PENDING'
     AND row_version = $6::bigint
  RETURNING ${SELECT_COLS}
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $7::uuid, $2::uuid, 'OPERATOR_SESSION', $8,
  $9, NULL, NULL, $10, $11, now()
FROM updated
RETURNING
  (SELECT id FROM updated) AS id,
  (SELECT node_id FROM updated) AS node_id,
  (SELECT display_name FROM updated) AS display_name,
  (SELECT requested_scopes FROM updated) AS requested_scopes,
  (SELECT proposed_rule_json FROM updated) AS proposed_rule_json,
  (SELECT approved_rule_json FROM updated) AS approved_rule_json,
  (SELECT status FROM updated) AS status,
  (SELECT row_version FROM updated) AS row_version,
  (SELECT created_at FROM updated) AS created_at,
  (SELECT expires_at FROM updated) AS expires_at,
  (SELECT decided_at FROM updated) AS decided_at,
  (SELECT decided_by FROM updated) AS decided_by,
  (SELECT implementer_id FROM updated) AS implementer_id`;

const DECLINE_SQL = `WITH updated AS (
  UPDATE integration_requests
     SET status = 'DECLINED',
         row_version = row_version + 1,
         decided_at = now(),
         decided_by = $3::uuid
   WHERE id = $1::uuid
     AND node_id = $2::uuid
     AND status = 'PENDING'
     AND row_version = $4::bigint
  RETURNING ${SELECT_COLS}
)
INSERT INTO audit_log (
  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
  details_text, details_sha256, created_at
)
SELECT
  $5::uuid, $2::uuid, 'OPERATOR_SESSION', $6,
  $7, NULL, NULL, $8, $9, now()
FROM updated
RETURNING
  (SELECT id FROM updated) AS id,
  (SELECT node_id FROM updated) AS node_id,
  (SELECT display_name FROM updated) AS display_name,
  (SELECT requested_scopes FROM updated) AS requested_scopes,
  (SELECT proposed_rule_json FROM updated) AS proposed_rule_json,
  (SELECT approved_rule_json FROM updated) AS approved_rule_json,
  (SELECT status FROM updated) AS status,
  (SELECT row_version FROM updated) AS row_version,
  (SELECT created_at FROM updated) AS created_at,
  (SELECT expires_at FROM updated) AS expires_at,
  (SELECT decided_at FROM updated) AS decided_at,
  (SELECT decided_by FROM updated) AS decided_by,
  (SELECT implementer_id FROM updated) AS implementer_id`;

export class SqlIntegrationRequestStore implements IntegrationRequestStore {
  constructor(private readonly sql: IntegrationRequestSqlExecutor) {}

  async list(
    filter: IntegrationRequestListFilter,
  ): Promise<readonly IntegrationRequestRecord[]> {
    const { rows } = await this.sql.query<Row>(LIST_SQL, [
      filter.nodeId,
      filter.status ?? null,
    ]);
    return rows.map(toRecord);
  }

  async get(id: string): Promise<IntegrationRequestRecord | null> {
    const { rows } = await this.sql.query<Row>(GET_SQL, [id]);
    return rows[0] === undefined ? null : toRecord(rows[0]);
  }

  async approve(input: IntegrationRequestApproveInput): Promise<IntegrationRequestRecord> {
    const detailsText = JSON.stringify({
      request_id: input.id,
      implementer_id: input.implementerId,
      approved_rule_sha256: detailsSha256(input.approvedRuleJson),
    });
    const { rows } = await this.sql.query<Row>(APPROVE_SQL, [
      input.id,
      input.nodeId,
      input.approvedRuleJson,
      input.decidedBy,
      input.implementerId,
      input.expectedRowVersion,
      randomUUID(),
      input.actorId,
      INTEGRATION_REQUEST_APPROVED_ACTION,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined || rows[0].id === null) {
      // Distinguish missing vs CAS miss for clearer 404/409.
      const existing = await this.get(input.id);
      if (existing === null) {
        throw new IntegrationRequestStoreError("integration request not found", "NOT_FOUND");
      }
      if (existing.node_id !== input.nodeId) {
        throw new IntegrationRequestStoreError("integration request wrong node", "WRONG_NODE");
      }
      throw new IntegrationRequestStoreError(
        "integration request CAS miss (not PENDING or row_version mismatch)",
        "CAS_MISS",
      );
    }
    return toRecord(rows[0]);
  }

  async decline(input: IntegrationRequestDeclineInput): Promise<IntegrationRequestRecord> {
    const detailsText = JSON.stringify({ request_id: input.id });
    const { rows } = await this.sql.query<Row>(DECLINE_SQL, [
      input.id,
      input.nodeId,
      input.decidedBy,
      input.expectedRowVersion,
      randomUUID(),
      input.actorId,
      INTEGRATION_REQUEST_DECLINED_ACTION,
      detailsText,
      detailsSha256(detailsText),
    ]);
    if (rows[0] === undefined || rows[0].id === null) {
      const existing = await this.get(input.id);
      if (existing === null) {
        throw new IntegrationRequestStoreError("integration request not found", "NOT_FOUND");
      }
      if (existing.node_id !== input.nodeId) {
        throw new IntegrationRequestStoreError("integration request wrong node", "WRONG_NODE");
      }
      throw new IntegrationRequestStoreError(
        "integration request CAS miss (not PENDING or row_version mismatch)",
        "CAS_MISS",
      );
    }
    return toRecord(rows[0]);
  }
}

export function createSqlIntegrationRequestStore(
  sql: IntegrationRequestSqlExecutor,
): IntegrationRequestStore {
  return new SqlIntegrationRequestStore(sql);
}

/** In-process store for unit tests. */
export class InMemoryIntegrationRequestStore implements IntegrationRequestStore {
  readonly rows = new Map<string, IntegrationRequestRecord>();
  readonly audit: Array<{
    readonly action: string;
    readonly actorId: string;
    readonly detailsText: string;
  }> = [];
  private readonly now: () => Date;

  constructor(now: () => Date = () => new Date()) {
    this.now = now;
  }

  seed(row: IntegrationRequestRecord): void {
    this.rows.set(row.id, { ...row, requested_scopes: [...row.requested_scopes] });
  }

  async list(
    filter: IntegrationRequestListFilter,
  ): Promise<readonly IntegrationRequestRecord[]> {
    return [...this.rows.values()]
      .filter((r) => r.node_id === filter.nodeId)
      .filter((r) => filter.status === undefined || r.status === filter.status)
      .sort((a, b) => {
        if (a.created_at !== b.created_at) return a.created_at < b.created_at ? -1 : 1;
        return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
      });
  }

  async get(id: string): Promise<IntegrationRequestRecord | null> {
    return this.rows.get(id) ?? null;
  }

  async approve(input: IntegrationRequestApproveInput): Promise<IntegrationRequestRecord> {
    const existing = this.rows.get(input.id);
    if (existing === undefined) {
      throw new IntegrationRequestStoreError("integration request not found", "NOT_FOUND");
    }
    if (existing.node_id !== input.nodeId) {
      throw new IntegrationRequestStoreError("integration request wrong node", "WRONG_NODE");
    }
    if (existing.status !== "PENDING" || existing.row_version !== input.expectedRowVersion) {
      throw new IntegrationRequestStoreError(
        "integration request CAS miss (not PENDING or row_version mismatch)",
        "CAS_MISS",
      );
    }
    const decidedAt = this.now().toISOString();
    const next: IntegrationRequestRecord = {
      ...existing,
      status: "APPROVED",
      row_version: existing.row_version + 1,
      approved_rule_json: input.approvedRuleJson,
      decided_at: decidedAt,
      decided_by: input.decidedBy,
      implementer_id: input.implementerId,
    };
    this.rows.set(next.id, next);
    const detailsText = JSON.stringify({
      request_id: input.id,
      implementer_id: input.implementerId,
      approved_rule_sha256: detailsSha256(input.approvedRuleJson),
    });
    this.audit.push({
      action: INTEGRATION_REQUEST_APPROVED_ACTION,
      actorId: input.actorId,
      detailsText,
    });
    return next;
  }

  async decline(input: IntegrationRequestDeclineInput): Promise<IntegrationRequestRecord> {
    const existing = this.rows.get(input.id);
    if (existing === undefined) {
      throw new IntegrationRequestStoreError("integration request not found", "NOT_FOUND");
    }
    if (existing.node_id !== input.nodeId) {
      throw new IntegrationRequestStoreError("integration request wrong node", "WRONG_NODE");
    }
    if (existing.status !== "PENDING" || existing.row_version !== input.expectedRowVersion) {
      throw new IntegrationRequestStoreError(
        "integration request CAS miss (not PENDING or row_version mismatch)",
        "CAS_MISS",
      );
    }
    const decidedAt = this.now().toISOString();
    const next: IntegrationRequestRecord = {
      ...existing,
      status: "DECLINED",
      row_version: existing.row_version + 1,
      decided_at: decidedAt,
      decided_by: input.decidedBy,
    };
    this.rows.set(next.id, next);
    this.audit.push({
      action: INTEGRATION_REQUEST_DECLINED_ACTION,
      actorId: input.actorId,
      detailsText: JSON.stringify({ request_id: input.id }),
    });
    return next;
  }
}
