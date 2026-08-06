// Durable admin operator + TOTP factor store (Review B defect 4).
//
// In-memory factors are wiped on reboot while money SQL stays live; this store
// persists operator posture and the factor secret so enrol → reboot → money
// still resolves the same active secret. Seal-at-rest (operator surface) remains
// DEFERRED_NO_SEAL_RUNTIME — durability first; sealing lands with.
//
// Table is operational (apps composition root ensures DDL). Not part of the
// frozen money-schema pack census — same class as harness ops tables.

import type { AdminTotpFactorState, AdminUser, AdminUserStore } from "./admin-session.js";

export interface AdminUserSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

function rowToUser(row: Record<string, unknown>): AdminUser {
  const disabled = row["disabled_at"];
  return {
    id: String(row["id"]),
    username: String(row["username"]),
    passwordHash: String(row["password_hash"]),
    role: row["role"] === "viewer" ? "viewer" : "admin",
    mustChangePassword: Boolean(row["must_change_password"]),
    mustEnrolTotp: Boolean(row["must_enrol_totp"]),
    disabledAt:
      disabled === null || disabled === undefined
        ? null
        : disabled instanceof Date
          ? disabled.getTime()
          : new Date(String(disabled)).getTime(),
    createdAt:
      row["created_at"] instanceof Date
        ? row["created_at"].getTime()
        : new Date(String(row["created_at"])).getTime(),
  };
}

function rowToFactor(row: Record<string, unknown>): AdminTotpFactorState {
  const status = String(row["totp_status"] ?? "none");
  const secret = row["totp_secret_base32"];
  if (status === "pending" && typeof secret === "string" && secret.length > 0) {
    return { status: "pending", secretBase32: secret };
  }
  if (status === "active" && typeof secret === "string" && secret.length > 0) {
    return { status: "active", secretBase32: secret };
  }
  return { status: "none" };
}

/**
 * Postgres-backed AdminUserStore. Call {@link ensureSchema} once at boot before
 * bootstrapInitialAdmin so a cold node does not re-seed after every reboot.
 */
export class SqlAdminUserStore implements AdminUserStore {
  constructor(private readonly db: AdminUserSqlExecutor) {}

  async ensureSchema(): Promise<void> {
    // DDL owned by apps/generic-node/src/db/migrate.ts. No runtime DDL here.
  }

  async findById(id: string): Promise<AdminUser | null> {
    const { rows } = await this.db.query(`SELECT * FROM admin_operators WHERE id = $1`, [id]);
    const row = rows[0];
    return row === undefined ? null : rowToUser(row);
  }

  async findByUsername(username: string): Promise<AdminUser | null> {
    const { rows } = await this.db.query(`SELECT * FROM admin_operators WHERE username = $1`, [
      username,
    ]);
    const row = rows[0];
    return row === undefined ? null : rowToUser(row);
  }

  async anyExists(): Promise<boolean> {
    const { rows } = await this.db.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM admin_operators`,
    );
    return Number(rows[0]?.["n"] ?? 0) > 0;
  }

  async insert(user: AdminUser): Promise<void> {
    await this.db.query(
      `INSERT INTO admin_operators (
         id, username, password_hash, role,
         must_change_password, must_enrol_totp, disabled_at, created_at,
         totp_status, totp_secret_base32
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8::double precision / 1000.0),'none',NULL)`,
      [
        user.id,
        user.username,
        user.passwordHash,
        user.role,
        user.mustChangePassword,
        user.mustEnrolTotp,
        user.disabledAt === null ? null : new Date(user.disabledAt).toISOString(),
        user.createdAt,
      ],
    );
  }

  async updatePassword(
    id: string,
    passwordHash: string,
    mustChangePassword: boolean,
  ): Promise<void> {
    await this.db.query(
      `UPDATE admin_operators
          SET password_hash = $2, must_change_password = $3
        WHERE id = $1`,
      [id, passwordHash, mustChangePassword],
    );
  }

  async setMustEnrolTotp(id: string, mustEnrolTotp: boolean): Promise<void> {
    await this.db.query(`UPDATE admin_operators SET must_enrol_totp = $2 WHERE id = $1`, [
      id,
      mustEnrolTotp,
    ]);
  }

  async setDisabledAt(id: string, disabledAt: number | null): Promise<void> {
    await this.db.query(`UPDATE admin_operators SET disabled_at = $2 WHERE id = $1`, [
      id,
      disabledAt === null ? null : new Date(disabledAt).toISOString(),
    ]);
  }

  async count(): Promise<number> {
    const { rows } = await this.db.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM admin_operators`,
    );
    return Number(rows[0]?.["n"] ?? 0);
  }

  async getTotpFactor(id: string): Promise<AdminTotpFactorState> {
    const { rows } = await this.db.query(
      `SELECT totp_status, totp_secret_base32 FROM admin_operators WHERE id = $1`,
      [id],
    );
    const row = rows[0];
    if (row === undefined) return { status: "none" };
    return rowToFactor(row);
  }

  async setPendingTotpSecret(
    id: string,
    secretBase32: string,
  ): Promise<"ok" | "already_active" | "missing"> {
    const { rows } = await this.db.query(
      `SELECT totp_status FROM admin_operators WHERE id = $1`,
      [id],
    );
    const row = rows[0];
    if (row === undefined) return "missing";
    if (String(row["totp_status"]) === "active") return "already_active";
    await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'pending', totp_secret_base32 = $2
        WHERE id = $1 AND totp_status <> 'active'`,
      [id, secretBase32],
    );
    return "ok";
  }

  async activateTotpEnrolment(id: string): Promise<"ok" | "no_pending" | "missing"> {
    const { rows } = await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'active', must_enrol_totp = false
        WHERE id = $1 AND totp_status = 'pending' AND totp_secret_base32 IS NOT NULL
        RETURNING id`,
      [id],
    );
    if (rows[0] !== undefined) return "ok";
    const exists = await this.findById(id);
    if (exists === null) return "missing";
    return "no_pending";
  }

  async setActiveTotpSecret(id: string, secretBase32: string): Promise<"ok" | "missing"> {
    const { rows } = await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'active', totp_secret_base32 = $2, must_enrol_totp = false
        WHERE id = $1
        RETURNING id`,
      [id, secretBase32],
    );
    return rows[0] === undefined ? "missing" : "ok";
  }
}

/** Wrap a pg Pool (or compatible) as AdminUserSqlExecutor. */
export function createPoolAdminUserExecutor(pool: {
  query: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[] }>;
}): AdminUserSqlExecutor {
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
