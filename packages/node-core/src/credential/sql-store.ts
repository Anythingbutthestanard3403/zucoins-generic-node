import { createHash } from "node:crypto";

import type { SqlExecutor } from "../proof-body/sql-store.js";
import type {
  CredentialAuditEntry,
  CredentialStatus,
  CredentialStore,
  ImplementerScope,
  StoredCredential,
} from "./types.js";

export const CREDENTIAL_COLUMNS = [
  "id",
  "implementer_id",
  "public_prefix",
  "credential_hash",
  "scopes",
  "status",
  "key_version",
  "issued_at",
  "expires_at",
  "revoked_at",
  "rotated_from_id",
  "rotated_to_id",
  "rotated_at",
  "rotation_grace_until",
] as const;

const CREDENTIAL_SELECT = CREDENTIAL_COLUMNS.join(", ");
const INSERT_PLACEHOLDERS = CREDENTIAL_COLUMNS.map(
  (_, index) => `$${index + 1}`,
).join(", ");

export const CREDENTIAL_STATEMENTS = {
  ISSUE: `WITH issued AS (
    INSERT INTO implementer_credentials (${CREDENTIAL_COLUMNS.join(", ")})
    VALUES (${INSERT_PLACEHOLDERS})
    RETURNING id
  )
  INSERT INTO audit_log
    (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id, details_text, details_sha256, created_at)
  SELECT $15, $16, $17, $18, $19, NULL, NULL, $20, $21, $22
  FROM issued
  RETURNING id`,
  SELECT_BY_HASH: `SELECT ${CREDENTIAL_SELECT} FROM implementer_credentials WHERE credential_hash = $1`,
  SELECT_BY_ID: `SELECT ${CREDENTIAL_SELECT} FROM implementer_credentials WHERE id = $1 AND implementer_id = $2`,
  SELECT_BY_IMPLEMENTER: `SELECT ${CREDENTIAL_SELECT} FROM implementer_credentials WHERE implementer_id = $1 ORDER BY issued_at DESC`, // contract-allow:frozen-sql-text
  ROTATE: `WITH locked AS (
    SELECT id FROM implementer_credentials
    WHERE id = $1 AND implementer_id = $2 AND status = 'ACTIVE'
    FOR UPDATE
  ), retired AS (
    UPDATE implementer_credentials
    SET status = 'GRACE', rotated_to_id = $3, rotated_at = $17,
        rotation_grace_until = $18, revoked_at = $18
    WHERE id IN (SELECT id FROM locked)
    RETURNING id
  ), replacement AS (
  INSERT INTO implementer_credentials (${CREDENTIAL_COLUMNS.join(", ")})
  SELECT ${INSERT_PLACEHOLDERS.split(", ").map((placeholder, index) => `$${index + 3}`).join(", ")}
  WHERE EXISTS (SELECT 1 FROM retired)
  RETURNING id
  ), audited AS (
    INSERT INTO audit_log
    (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id, details_text, details_sha256, created_at)
    SELECT $19, $20, $21, $22, $23, NULL, NULL, $24, $25, $26
    FROM replacement
    RETURNING id
  )
  SELECT id FROM replacement WHERE EXISTS (SELECT 1 FROM audited)`,
  REVOKE: `WITH revoked AS (
    UPDATE implementer_credentials
    SET status = 'REVOKED', revoked_at = $3
    WHERE id = $1 AND implementer_id = $2 AND status IN ('ACTIVE', 'GRACE')
    RETURNING id
  ), audited AS (
    INSERT INTO audit_log
      (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id, details_text, details_sha256, created_at)
    SELECT $4, $5, $6, $7, $8, NULL, NULL, $9, $10, $11
    FROM revoked
    RETURNING id
  )
  SELECT id FROM revoked WHERE EXISTS (SELECT 1 FROM audited)`,
} as const;

interface CredentialRow {
  readonly id: string;
  readonly implementer_id: string;
  readonly public_prefix: string;
  readonly credential_hash: string;
  readonly scopes: string[];
  readonly status: CredentialStatus;
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly rotated_from_id: string | null;
  readonly rotated_to_id: string | null;
  readonly rotated_at: string | null;
  readonly rotation_grace_until: string | null;
}

function toStoredCredential(row: CredentialRow): StoredCredential {
  return {
    ...row,
    scopes: row.scopes as ImplementerScope[],
  };
}

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
  entry: CredentialAuditEntry,
  nodeId: string,
): readonly unknown[] {
  const detailsText = JSON.stringify({
    credential_id: entry.credential_id,
    replacement_credential_id: entry.replacement_credential_id,
  });
  const detailsSha256 = createHash("sha256")
    .update(detailsText, "utf8")
    .digest("hex");
  // P1#2: when an operator session principal is supplied, the audit row names THAT
  // principal (OPERATOR_SESSION), not the target implementer. The legacy IMPLEMENTER principal
  // is retained for bootstrap/cli paths that have no session.
  const actorKind = entry.operator_session_id !== undefined && entry.operator_session_id !== null
    ? "OPERATOR_SESSION"
    : "IMPLEMENTER";
  const actorId = entry.operator_session_id !== undefined && entry.operator_session_id !== null
    ? entry.operator_session_id
    : entry.implementer_id;
  return [
    entry.id,
    nodeId,
    actorKind,
    actorId,
    entry.action,
    detailsText,
    detailsSha256,
    entry.created_at,
  ];
}

export class SqlCredentialStore implements CredentialStore {
  constructor(
    private readonly sql: SqlExecutor,
    private readonly nodeId: string,
  ) {}

  async issue(
    row: StoredCredential,
    audit: CredentialAuditEntry,
  ): Promise<void> {
    await this.sql.query(CREDENTIAL_STATEMENTS.ISSUE, [
      ...credentialParams(row),
      ...auditParams(audit, this.nodeId),
    ]);
  }

  async findByHash(credentialHash: string): Promise<StoredCredential | null> {
    const { rows } = await this.sql.query<CredentialRow>(
      CREDENTIAL_STATEMENTS.SELECT_BY_HASH,
      [credentialHash],
    );
    return rows[0] === undefined ? null : toStoredCredential(rows[0]);
  }

  async findById(
    credentialId: string,
    implementerId: string,
  ): Promise<StoredCredential | null> {
    const { rows } = await this.sql.query<CredentialRow>(
      CREDENTIAL_STATEMENTS.SELECT_BY_ID,
      [credentialId, implementerId],
    );
    return rows[0] === undefined ? null : toStoredCredential(rows[0]);
  }

  async listByImplementer(implementerId: string): Promise<StoredCredential[]> {
    const { rows } = await this.sql.query<CredentialRow>(
      CREDENTIAL_STATEMENTS.SELECT_BY_IMPLEMENTER,
      [implementerId],
    );
    return rows.map(toStoredCredential);
  }

  async rotate(
    credentialId: string,
    implementerId: string,
    replacement: StoredCredential,
    rotatedAt: string,
    graceUntil: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const { rows } = await this.sql.query<{ readonly id: string }>(
      CREDENTIAL_STATEMENTS.ROTATE,
      [
        credentialId,
        implementerId,
        ...credentialParams(replacement),
        rotatedAt,
        graceUntil,
        ...auditParams(audit, this.nodeId),
      ],
    );
    return rows.length > 0;
  }

  async revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const { rows } = await this.sql.query<{ readonly id: string }>(
      CREDENTIAL_STATEMENTS.REVOKE,
      [
        credentialId,
        implementerId,
        revokedAt,
        ...auditParams(audit, this.nodeId),
      ],
    );
    return rows.length > 0;
  }
}
