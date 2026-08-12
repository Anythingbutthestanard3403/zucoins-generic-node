// Durable IntegrationRequestStore over Postgres. Claim path issues the
// implementer credential in the same TX as APPROVED→CLAIMED (ZTR-1239).

import { createHash, randomUUID } from "node:crypto";

import {
  generateRawKey,
  hashCredential,
  PUBLIC_PREFIX_LENGTH,
  type ImplementerScope,
  type StoredCredential,
} from "../credential/types.js";
import { CREDENTIAL_COLUMNS } from "../credential/sql-store.js";
import type {
  ClaimOutcome,
  IntegrationRequestIntakeInput,
  IntegrationRequestRow,
  IntegrationRequestStore,
} from "./types.js";
import { claimTokenHashesEqual } from "./token.js";

export interface IntegrationRequestSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

export type IntegrationRequestTxFn = <T>(
  body: (sql: IntegrationRequestSqlExecutor) => Promise<T>,
) => Promise<T>;

interface RequestRow extends Record<string, unknown> {
  readonly id: string;
  readonly node_id: string;
  readonly display_name: string;
  readonly requested_scopes: string[] | unknown;
  readonly proposed_rule_json: string;
  readonly approved_rule_json: string | null;
  readonly status: string;
  readonly row_version: string | number;
  readonly claim_token_hash: string;
  readonly created_at: unknown;
  readonly expires_at: unknown;
  readonly decided_at: unknown;
  readonly decided_by: string | null;
  readonly implementer_id: string | null;
  readonly issued_credential_id: string | null;
  readonly claimed_at: unknown;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

function scopesOf(raw: unknown): readonly ImplementerScope[] {
  if (Array.isArray(raw)) return raw as ImplementerScope[];
  return [];
}

function toRow(r: RequestRow): IntegrationRequestRow {
  return {
    id: r.id,
    node_id: r.node_id,
    display_name: r.display_name,
    requested_scopes: scopesOf(r.requested_scopes),
    proposed_rule_json: r.proposed_rule_json,
    approved_rule_json: r.approved_rule_json,
    status: r.status as IntegrationRequestRow["status"],
    row_version: Number(r.row_version),
    claim_token_hash: r.claim_token_hash,
    created_at: toIso(r.created_at),
    expires_at: toIso(r.expires_at),
    decided_at: toIsoOrNull(r.decided_at),
    decided_by: r.decided_by,
    implementer_id: r.implementer_id,
    issued_credential_id: r.issued_credential_id,
    claimed_at: toIsoOrNull(r.claimed_at),
  };
}

const SELECT_COLS = `id::text AS id, node_id::text AS node_id, display_name,
  requested_scopes, proposed_rule_json, approved_rule_json, status,
  row_version, claim_token_hash, created_at, expires_at, decided_at,
  decided_by::text AS decided_by, implementer_id::text AS implementer_id,
  issued_credential_id::text AS issued_credential_id, claimed_at`;

const COUNT_PENDING_SQL = `SELECT count(*)::text AS n FROM integration_requests WHERE status = 'PENDING'`;

const INSERT_SQL = `INSERT INTO integration_requests (
  id, node_id, display_name, requested_scopes, proposed_rule_json, status,
  row_version, claim_token_hash, created_at, expires_at
) VALUES (
  $1::uuid, $2::uuid, $3, $4::text[], $5, 'PENDING', 1, $6, $7::timestamptz, $8::timestamptz
) RETURNING ${SELECT_COLS}`;

const FIND_SQL = `SELECT ${SELECT_COLS} FROM integration_requests WHERE id = $1::uuid`;

const LAZY_EXPIRE_SQL = `UPDATE integration_requests SET
  status = 'EXPIRED',
  row_version = row_version + 1
WHERE id = $1::uuid
  AND status IN ('PENDING', 'APPROVED')
  AND expires_at <= $2::timestamptz
  AND issued_credential_id IS NULL
RETURNING ${SELECT_COLS}`;

const CLAIM_CAS_SQL = `UPDATE integration_requests SET
  status = 'CLAIMED',
  row_version = row_version + 1,
  issued_credential_id = $3::uuid,
  claimed_at = $4::timestamptz
WHERE id = $1::uuid
  AND status = 'APPROVED'
  AND row_version = $2::bigint
  AND claim_token_hash = $5
RETURNING ${SELECT_COLS}`;

const INSERT_PLACEHOLDERS = CREDENTIAL_COLUMNS.map((_, i) => `$${i + 1}`).join(", ");

const ISSUE_CREDENTIAL_SQL = `WITH issued AS (
  INSERT INTO implementer_credentials (${CREDENTIAL_COLUMNS.join(", ")})
  VALUES (${INSERT_PLACEHOLDERS})
  RETURNING id
)
INSERT INTO audit_log
  (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id, details_text, details_sha256, created_at)
SELECT $15, $16, $17, $18, $19, NULL, NULL, $20, $21, $22
FROM issued
RETURNING id`;

function credentialParams(row: StoredCredential): readonly unknown[] {
  return [
    row.id,
    row.implementer_id,
    row.public_prefix,
    row.credential_hash,
    row.scopes,
    row.status,
    row.key_version,
    row.issued_at,
    row.expires_at,
    row.revoked_at,
    row.rotated_from_id,
    row.rotated_to_id,
    row.rotated_at,
    row.rotation_grace_until,
  ];
}

function auditParams(
  credentialId: string,
  implementerId: string,
  nodeId: string,
  issuedAt: string,
  auditId: string,
): readonly unknown[] {
  const detailsText = JSON.stringify({
    credential_id: credentialId,
    replacement_credential_id: null,
    source: "integration_request_claim",
  });
  const detailsSha256 = createHash("sha256").update(detailsText, "utf8").digest("hex");
  return [
    auditId,
    nodeId,
    "IMPLEMENTER",
    implementerId,
    "IMPLEMENTER_CREDENTIAL_ISSUED",
    detailsText,
    detailsSha256,
    issuedAt,
  ];
}

export class SqlIntegrationRequestStore implements IntegrationRequestStore {
  constructor(
    private readonly sql: IntegrationRequestSqlExecutor,
    private readonly withTransaction: IntegrationRequestTxFn,
  ) {}

  async countPending(): Promise<number> {
    const { rows } = await this.sql.query<{ n: string }>(COUNT_PENDING_SQL, []);
    return Number(rows[0]?.n ?? 0);
  }

  async insertPending(input: IntegrationRequestIntakeInput): Promise<IntegrationRequestRow> {
    const now = input.now ?? new Date();
    const ttlMs = input.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    const id = input.requestId ?? randomUUID();
    const { rows } = await this.sql.query<RequestRow>(INSERT_SQL, [
      id,
      input.nodeId,
      input.displayName,
      input.requestedScopes,
      input.proposedRuleJson,
      input.claimTokenHash,
      createdAt,
      expiresAt,
    ]);
    const row = rows[0];
    if (row === undefined) {
      throw new Error("integration request insert returned no row");
    }
    return toRow(row);
  }

  async findById(id: string): Promise<IntegrationRequestRow | null> {
    const { rows } = await this.sql.query<RequestRow>(FIND_SQL, [id]);
    return rows[0] === undefined ? null : toRow(rows[0]);
  }

  async lazyExpire(id: string, now: Date): Promise<IntegrationRequestRow | null> {
    const { rows } = await this.sql.query<RequestRow>(LAZY_EXPIRE_SQL, [
      id,
      now.toISOString(),
    ]);
    if (rows[0] !== undefined) return toRow(rows[0]);
    return this.findById(id);
  }

  async claimApproved(input: {
    readonly id: string;
    readonly claimTokenHash: string;
    readonly nodeId: string;
    readonly now: Date;
  }): Promise<ClaimOutcome> {
    // Authenticate outside TX first (uniform not_found on miss/wrong token).
    const existing = await this.findById(input.id);
    if (existing === null) return { kind: "not_found" };
    if (!claimTokenHashesEqual(existing.claim_token_hash, input.claimTokenHash)) {
      return { kind: "not_found" };
    }

    if (existing.status === "CLAIMED") {
      return { kind: "status", status: "CLAIMED" };
    }
    if (existing.status !== "APPROVED") {
      return { kind: "status", status: existing.status };
    }

    const implementerId = existing.implementer_id;
    if (implementerId === null) {
      // Consistency CHECK should forbid this; treat as not claimable.
      return { kind: "status", status: existing.status };
    }

    const rawKey = generateRawKey();
    const issuedAt = input.now.toISOString();
    const credentialId = randomUUID();
    const auditId = randomUUID();
    const scopes = existing.requested_scopes;
    const stored: StoredCredential = {
      id: credentialId,
      implementer_id: implementerId,
      public_prefix: rawKey.slice(0, PUBLIC_PREFIX_LENGTH),
      credential_hash: hashCredential(rawKey),
      scopes,
      status: "ACTIVE",
      key_version: 1,
      issued_at: issuedAt,
      expires_at: null,
      revoked_at: null,
      rotated_from_id: null,
      rotated_to_id: null,
      rotated_at: null,
      rotation_grace_until: null,
    };

    try {
      return await this.withTransaction(async (tx) => {
        // Re-read under TX for row_version.
        const { rows: locked } = await tx.query<RequestRow>(FIND_SQL, [input.id]);
        const live = locked[0] === undefined ? null : toRow(locked[0]);
        if (live === null) return { kind: "not_found" as const };
        if (!claimTokenHashesEqual(live.claim_token_hash, input.claimTokenHash)) {
          return { kind: "not_found" as const };
        }
        if (live.status === "CLAIMED") {
          return { kind: "status" as const, status: "CLAIMED" as const };
        }
        if (live.status !== "APPROVED" || live.implementer_id === null) {
          return { kind: "status" as const, status: live.status };
        }

        await tx.query(ISSUE_CREDENTIAL_SQL, [
          ...credentialParams(stored),
          ...auditParams(credentialId, live.implementer_id, input.nodeId, issuedAt, auditId),
        ]);

        const { rows: claimed } = await tx.query<RequestRow>(CLAIM_CAS_SQL, [
          input.id,
          live.row_version,
          credentialId,
          issuedAt,
          input.claimTokenHash,
        ]);
        if (claimed[0] === undefined) {
          // CAS loser — roll back credential insert by throwing to abort TX,
          // then surface status-only CLAIMED (or current status) outside.
          throw new ClaimCasMissError();
        }

        let approvedRule: unknown = null;
        try {
          approvedRule = JSON.parse(live.approved_rule_json ?? "null");
        } catch {
          approvedRule = live.approved_rule_json;
        }

        return {
          kind: "key" as const,
          status: "CLAIMED" as const,
          api_key: rawKey,
          public_prefix: stored.public_prefix,
          scopes: live.requested_scopes,
          approved_rule: approvedRule,
          implementer_id: live.implementer_id,
          credential_id: credentialId,
        };
      });
    } catch (err) {
      if (err instanceof ClaimCasMissError) {
        const after = await this.findById(input.id);
        if (after === null) return { kind: "not_found" };
        return { kind: "status", status: after.status };
      }
      throw err;
    }
  }
}

class ClaimCasMissError extends Error {
  constructor() {
    super("integration request claim CAS miss");
    this.name = "ClaimCasMissError";
  }
}

