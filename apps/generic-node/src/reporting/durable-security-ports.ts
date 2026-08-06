import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";

import { InMemoryReportingRateLimiter } from "@zucoins/node-core";
import type {
  ReportingRateLimiter,
  VaultAccessAuditEntry,
  VaultAccessAuditLog,
  VerificationAccessWindowRecord,
  VerificationAccessWindowStore,
} from "@zucoins/node-core";

export function createPoolSqlExecutor(pool: Pick<Pool, "query">) {
  return {
    async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
      const result = await pool.query(text, params as unknown[]);
      return { rows: result.rows as R[] };
    },
  };
}

export function createPoolSqlTransactionRunner(pool: Pick<Pool, "connect">) {
  return {
    async transaction<T>(body: (sql: ReturnType<typeof createPoolSqlExecutor>) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await body(createPoolSqlExecutor(client));
        await client.query("COMMIT");
        return result;
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch { /* preserve original error */ }
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

/**
 * Two-leg fixed-window counter. Leg 1 is a volatile in-memory pre-filter
 * that can only deny, never grant: it never widens what the durable leg would have admitted.
 * Leg 2 is the durable, cross-instance counter, gated by a WHERE EXISTS registration check so
 * that an unregistered principal never accumulates a durable row. This is not an existence
 * oracle — leg 1 decides the same verdict for registered and unregistered principals, and an
 * unregistered principal is rejected downstream at admitReportingKey regardless.
 */
export class SqlReportingRateLimiter implements ReportingRateLimiter {
  private readonly inMemoryLeg: InMemoryReportingRateLimiter;

  constructor(
    private readonly pool: Pick<Pool, "query">,
    private readonly windowMs: number,
    private readonly maxRequests: number,
  ) {
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) throw new Error("windowMs must be positive");
    if (!Number.isSafeInteger(maxRequests) || maxRequests <= 0) throw new Error("maxRequests must be positive");
    this.inMemoryLeg = new InMemoryReportingRateLimiter(windowMs, maxRequests);
  }

  async consume(nodeId: string, principal: string, atMs: number): Promise<boolean> {
    if (!this.inMemoryLeg.consume(nodeId, principal, atMs)) return false;

    const windowStartMs = Math.floor(atMs / this.windowMs) * this.windowMs;
    const result = await this.pool.query<{ request_count: string | number }>(
      `INSERT INTO reporting_rate_limit_buckets
         (node_id, principal, window_start_ms, request_count, updated_at)
       SELECT $1::uuid, $2, $3::bigint, 1, to_timestamp($4::double precision / 1000.0)
       WHERE EXISTS (
         SELECT 1 FROM implementer_reporting_keys k
          WHERE k.node_id = $1::uuid AND k.id::text = lower($2)
       )
       ON CONFLICT (node_id, principal) DO UPDATE
         SET request_count = CASE
               WHEN EXCLUDED.window_start_ms > reporting_rate_limit_buckets.window_start_ms THEN 1
               ELSE reporting_rate_limit_buckets.request_count + 1 END,
             window_start_ms = GREATEST(reporting_rate_limit_buckets.window_start_ms,
                                        EXCLUDED.window_start_ms),
             updated_at = EXCLUDED.updated_at
       RETURNING request_count`,
      [nodeId, principal, windowStartMs, atMs],
    );
    if (result.rows.length === 0) return true;
    const count = Number(result.rows[0]?.request_count);
    if (!Number.isSafeInteger(count) || count < 1) throw new Error("rate limiter counter returned invalid count");
    return count <= this.maxRequests;
  }
}

export interface VerificationAccessWindowInput {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly nonceHash: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

export interface VerificationAccessWindow {
  readonly status: "OPEN" | "EXPIRED" | "REVOKED";
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
}

/** Durable access-control projection; expiry/revocation never deletes evidence bytes. */
export class SqlVerificationAccessStore implements VerificationAccessWindowStore {
  constructor(private readonly pool: Pick<Pool, "query">) {}

  async open(input: VerificationAccessWindowInput): Promise<void> {
    await this.pool.query(
      `INSERT INTO verification_material_access_windows
         (id,node_id,implementer_id,operation_id,status,nonce_hash,issued_at,expires_at,revoked_at)
       VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,'OPEN',$5,$6,$7,NULL)`,
      [input.id, input.nodeId, input.implementerId, input.operationId, input.nonceHash, input.issuedAt, input.expiresAt],
    );
  }

  async save(record: VerificationAccessWindowRecord): Promise<void> {
    await this.open({
      id: record.id, nodeId: record.nodeId, implementerId: record.implementerId,
      operationId: record.operationId, nonceHash: record.nonceHash,
      issuedAt: new Date(record.issuedAtMs), expiresAt: new Date(record.expiresAtMs),
    });
  }

  async findByOperation(operationId: string, implementerId: string): Promise<VerificationAccessWindowRecord | null> {
    const result = await this.pool.query(`SELECT id::text,node_id::text,implementer_id::text,
              operation_id::text,status,nonce_hash,issued_at,expires_at,revoked_at
         FROM verification_material_access_windows
        WHERE operation_id=$1::uuid AND implementer_id=$2::uuid`, [operationId, implementerId]);
    return result.rows[0] === undefined ? null : this.toRecord(result.rows[0]);
  }

  async findByNonceHash(nonceHash: string): Promise<VerificationAccessWindowRecord | null> {
    const result = await this.pool.query(`SELECT id::text,node_id::text,implementer_id::text,
              operation_id::text,status,nonce_hash,issued_at,expires_at,revoked_at
         FROM verification_material_access_windows WHERE nonce_hash=$1`, [nonceHash]);
    return result.rows[0] === undefined ? null : this.toRecord(result.rows[0]);
  }

  async updateStatus(operationId: string, status: VerificationAccessWindowRecord["status"], revokedAtMs: number | null): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE verification_material_access_windows SET status=$2, revoked_at=$3 WHERE operation_id=$1::uuid`,
      [operationId, status, revokedAtMs === null ? null : new Date(revokedAtMs)],
    );
    return (result.rowCount ?? 0) === 1;
  }

  private toRecord(row: Record<string, unknown>): VerificationAccessWindowRecord {
    return {
      id: String(row.id), nodeId: String(row.node_id), implementerId: String(row.implementer_id),
      operationId: String(row.operation_id), status: row.status as VerificationAccessWindowRecord["status"],
      nonceHash: String(row.nonce_hash), issuedAtMs: new Date(row.issued_at as string | Date).getTime(),
      expiresAtMs: new Date(row.expires_at as string | Date).getTime(),
      revokedAtMs: row.revoked_at === null ? null : new Date(row.revoked_at as string | Date).getTime(),
    };
  }

  async read(operationId: string, atMs: number): Promise<VerificationAccessWindow | null> {
    const result = await this.pool.query<{
      status: "OPEN" | "EXPIRED" | "REVOKED";
      expires_at: Date;
      revoked_at: Date | null;
    }>(
      `SELECT CASE WHEN status='OPEN' AND expires_at <= to_timestamp($2::double precision / 1000.0)
                   THEN 'EXPIRED' ELSE status END AS status,
              expires_at, revoked_at
         FROM verification_material_access_windows WHERE operation_id=$1::uuid`,
      [operationId, atMs],
    );
    const row = result.rows[0];
    return row === undefined ? null : { status: row.status, expiresAt: row.expires_at, revokedAt: row.revoked_at };
  }

  async revoke(operationId: string, at: Date): Promise<void> {
    const result = await this.pool.query(
      `UPDATE verification_material_access_windows
          SET status='REVOKED', revoked_at=$2
        WHERE operation_id=$1::uuid AND status='OPEN'`,
      [operationId, at],
    );
    if ((result.rowCount ?? 0) !== 1) throw new Error("verification access window is not open");
  }
}

/** Append-only, secret-free adapter for every wallet vault decrypt attempt. */
export class SqlVaultAccessAuditLog implements VaultAccessAuditLog {
  constructor(
    private readonly pool: Pick<Pool, "query">,
    private readonly nodeId: string,
    private readonly newId: () => string = randomUUID,
  ) {}

  async record(entry: VaultAccessAuditEntry): Promise<void> {
    const detailsText = JSON.stringify({
      key_version: entry.keyVersion,
      purpose: entry.purpose,
      outcome: entry.outcome,
    });
    const digest = createHash("sha256").update(detailsText, "utf8").digest("hex");
    await this.pool.query(
      `INSERT INTO audit_log
         (id,node_id,actor_kind,actor_id,action,operation_id,wallet_id,details_text,details_sha256,created_at)
       VALUES ($1::uuid,$2::uuid,'SYSTEM',NULL,'VAULT_ACCESS',NULL,$3::uuid,$4,$5,$6)`,
      [this.newId(), this.nodeId, entry.walletId, detailsText, digest, entry.at],
    );
  }
}
