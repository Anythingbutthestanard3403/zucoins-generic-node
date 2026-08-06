// Durable admin session store.
//
// Survives process restart so a valid __Host- cookie remains live within absolute
// TTL + idle window. Two processes (multi-replica) share the same PG rows —
// cookie verification always hits the DB, never process-local memory.
//
// Operational DDL (same class as admin_operators / admin_totp_burns). Frozen money
// pack may already declare admin_sessions; ensureSchema is additive
// (IF NOT EXISTS + ADD COLUMN IF NOT EXISTS) and does not alter contract text.
// Shape aligned with pack: user_id uuid, ip inet, temporal CHECK (expires_at >
// created_at). Revoke is hard DELETE (v1 parity) so mutability stays last_seen_at /
// expires_at only — no revoked_at UPDATE path.
// Sessions are carried in a `__Host-` prefixed cookie.

import { isIP } from "node:net";

import type { AdminSession, AdminSessionStore } from "./admin-session.js";

export interface AdminSessionSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

/**
 * Value safe to bind to a Postgres `inet` column (v1 `ipForDb`).
 * Multi-hop raw X-Forwarded-For fails a bare inet cast — peel the rightmost
 * trusted hop (default depth 1), then accept only syntactically valid IPv4/IPv6;
 * anything else becomes NULL so INSERT never 22P02s.
 */
export function ipForDb(ip: string | null | undefined): string | null {
  if (ip == null) return null;
  const parts = ip
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return null;
  const candidate = parts[parts.length - 1]!;
  return isIP(candidate) !== 0 ? candidate : null;
}

/** Parameterized SQL constants — tests bind an InProcess executor against these. */
export const ADMIN_SESSION_SQL = {
  SAVE: `
INSERT INTO admin_sessions (
  id, user_id, node_id, csrf_token, expires_at, created_at, last_seen_at, ip, user_agent
) VALUES (
  $1, $2, $3, $4,
  to_timestamp($5::double precision / 1000.0),
  to_timestamp($6::double precision / 1000.0),
  to_timestamp($7::double precision / 1000.0),
  $8::inet, $9
)
ON CONFLICT (id) DO UPDATE SET
  last_seen_at = EXCLUDED.last_seen_at,
  expires_at = EXCLUDED.expires_at
`,
  FIND: `
SELECT id, user_id, node_id, csrf_token, expires_at, created_at, last_seen_at, ip, user_agent
  FROM admin_sessions
 WHERE id = $1
`,
  TOUCH: `
UPDATE admin_sessions
   SET last_seen_at = to_timestamp($2::double precision / 1000.0)
 WHERE id = $1
`,
  REVOKE: `
DELETE FROM admin_sessions WHERE id = $1
`,
  IS_REVOKED: `
SELECT 1 AS ok FROM admin_sessions WHERE FALSE AND id = $1
`,
  REVOKE_OTHER_FOR_USER: `
DELETE FROM admin_sessions
 WHERE user_id = $1 AND id <> $2
 RETURNING id
`,
  REVOKE_ALL_FOR_USER: `
DELETE FROM admin_sessions
 WHERE user_id = $1
 RETURNING id
`,
} as const;

function msFrom(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number") return value;
  return new Date(String(value)).getTime();
}

function rowToSession(row: Record<string, unknown>): AdminSession {
  const ip = row["ip"];
  const ua = row["user_agent"];
  return {
    sessionId: String(row["id"]),
    userId: String(row["user_id"]),
    nodeId: String(row["node_id"] ?? ""),
    csrfToken: String(row["csrf_token"]),
    createdAt: msFrom(row["created_at"]),
    expiresAt: msFrom(row["expires_at"]),
    lastSeenAt: msFrom(row["last_seen_at"]),
    ip: ip === null || ip === undefined ? null : String(ip),
    userAgent: ua === null || ua === undefined ? null : String(ua),
  };
}

/**
 * Postgres-backed AdminSessionStore. Call {@link ensureSchema} once at boot
 * (alongside admin_operators) so a cold node accepts cookies issued pre-restart.
 */
export class SqlAdminSessionStore implements AdminSessionStore {
  constructor(private readonly db: AdminSessionSqlExecutor) {}

  async ensureSchema(): Promise<void> {
    // DDL owned by apps/generic-node/src/db/migrate.ts. No runtime DDL here.
  }

  async save(session: AdminSession): Promise<void> {
    await this.db.query(ADMIN_SESSION_SQL.SAVE, [
      session.sessionId,
      session.userId,
      session.nodeId,
      session.csrfToken,
      session.expiresAt,
      session.createdAt,
      session.lastSeenAt,
      ipForDb(session.ip),
      session.userAgent,
    ]);
  }

  async find(sessionId: string): Promise<AdminSession | null> {
    const { rows } = await this.db.query(ADMIN_SESSION_SQL.FIND, [sessionId]);
    const row = rows[0];
    return row === undefined ? null : rowToSession(row);
  }

  async touch(sessionId: string, lastSeenAt: number): Promise<void> {
    await this.db.query(ADMIN_SESSION_SQL.TOUCH, [sessionId, lastSeenAt]);
  }

  async revoke(sessionId: string): Promise<void> {
    await this.db.query(ADMIN_SESSION_SQL.REVOKE, [sessionId]);
  }

  /**
   * Hard DELETE leaves no tombstone — missing rows are unknownSession, not a
   * durable revoke flag. Always false (v1 delete-parity).
   */
  async isRevoked(_sessionId: string): Promise<boolean> {
    return false;
  }

  async revokeOtherForUser(userId: string, keepSessionId: string): Promise<number> {
    const { rows } = await this.db.query(ADMIN_SESSION_SQL.REVOKE_OTHER_FOR_USER, [
      userId,
      keepSessionId,
    ]);
    return rows.length;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const { rows } = await this.db.query(ADMIN_SESSION_SQL.REVOKE_ALL_FOR_USER, [userId]);
    return rows.length;
  }
}

/** Wrap a pg Pool (or compatible) as AdminSessionSqlExecutor. */
export function createPoolAdminSessionExecutor(pool: {
  query: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[] }>;
}): AdminSessionSqlExecutor {
  return {
    async query<T extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
    ) {
      const result = await pool.query(sql, params === undefined ? undefined : [...params]);
      return { rows: result.rows as T[] };
    },
  };
}
