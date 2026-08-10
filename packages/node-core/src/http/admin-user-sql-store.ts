// Durable admin operator + sealed TOTP factor store (ZTR-1134).
//
// TOTP shared secrets are AES-256-GCM sealed under the vault root
// (packages/node-core/src/totp/seal.ts — registry TOTP_SECRET). The
// admin_operators.totp_secret_sealed column holds only the opaque envelope;
// plaintext base32 never persists. Opening reconstructs AAD from the operator id.
//
// Table is operational (apps composition root ensures DDL). Not part of the
// frozen money-schema pack census — same class as harness ops tables.

import type { AdminTotpFactorState, AdminUser, AdminUserStore } from "./admin-session.js";
import { encodeBase32, totpSecretBytes } from "../totp/secret.js";
import { openTotpSecret, sealTotpSecret } from "../totp/seal.js";

export interface AdminUserSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

/**
 * Root-key supplier for TOTP seal/open. Production wires the process vault root
 * buffer (same reference boot unlock mutates in place on salt rederive).
 */
export type TotpVaultRootKey = Uint8Array | (() => Uint8Array);

function resolveRootKey(root: TotpVaultRootKey): Uint8Array {
  return typeof root === "function" ? root() : root;
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

function openFactor(
  rootKey: Uint8Array,
  adminId: string,
  status: string,
  sealed: unknown,
): AdminTotpFactorState {
  if (typeof sealed !== "string" || sealed.length === 0) {
    return { status: "none" };
  }
  if (status !== "pending" && status !== "active") {
    return { status: "none" };
  }
  const raw = openTotpSecret(rootKey, adminId, sealed);
  try {
    const secretBase32 = encodeBase32(raw);
    if (status === "pending") return { status: "pending", secretBase32 };
    return { status: "active", secretBase32 };
  } finally {
    raw.fill(0);
  }
}

function sealSecretBase32(rootKey: Uint8Array, adminId: string, secretBase32: string): string {
  const bytes = totpSecretBytes(secretBase32);
  if (bytes === null) {
    throw new Error("invalid TOTP secret base32");
  }
  try {
    return sealTotpSecret(rootKey, adminId, bytes);
  } finally {
    // totpSecretBytes returns a fresh Uint8Array; wipe when it's a Buffer-like.
    if (bytes instanceof Uint8Array) {
      bytes.fill(0);
    }
  }
}

/**
 * Postgres-backed AdminUserStore. Call {@link ensureSchema} once at boot before
 * bootstrapInitialAdmin so a cold node does not re-seed after every reboot.
 *
 * Requires a vault root key so TOTP factors seal at rest (registry TOTP_SECRET).
 */
export class SqlAdminUserStore implements AdminUserStore {
  constructor(
    private readonly db: AdminUserSqlExecutor,
    private readonly vaultRootKey: TotpVaultRootKey,
  ) {}

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
         totp_status, totp_secret_sealed
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
      `SELECT totp_status, totp_secret_sealed FROM admin_operators WHERE id = $1`,
      [id],
    );
    const row = rows[0];
    if (row === undefined) return { status: "none" };
    return openFactor(
      resolveRootKey(this.vaultRootKey),
      id,
      String(row["totp_status"] ?? "none"),
      row["totp_secret_sealed"],
    );
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
    const sealed = sealSecretBase32(resolveRootKey(this.vaultRootKey), id, secretBase32);
    await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'pending', totp_secret_sealed = $2
        WHERE id = $1 AND totp_status <> 'active'`,
      [id, sealed],
    );
    return "ok";
  }

  async activateTotpEnrolment(id: string): Promise<"ok" | "no_pending" | "missing"> {
    const { rows } = await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'active', must_enrol_totp = false
        WHERE id = $1 AND totp_status = 'pending' AND totp_secret_sealed IS NOT NULL
        RETURNING id`,
      [id],
    );
    if (rows[0] !== undefined) return "ok";
    const exists = await this.findById(id);
    if (exists === null) return "missing";
    return "no_pending";
  }

  async setActiveTotpSecret(id: string, secretBase32: string): Promise<"ok" | "missing"> {
    const sealed = sealSecretBase32(resolveRootKey(this.vaultRootKey), id, secretBase32);
    const { rows } = await this.db.query(
      `UPDATE admin_operators
          SET totp_status = 'active', totp_secret_sealed = $2, must_enrol_totp = false
        WHERE id = $1
        RETURNING id`,
      [id, sealed],
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
