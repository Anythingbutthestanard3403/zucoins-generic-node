// Postgres-backed VaultStore over the `vault` table (src/schema/vault.sql).
//
// Canonical authority: the wallet-vault model.
//
// DRIVER-AGNOSTIC, like src/proof-body/sql-store.ts: node-core is network-contained
// and imports no database driver, so the pg Pool is injected at the composition root. The
// structural SqlExecutor port is redeclared here rather than imported from proof-body — the
// module boundary gate (test/boundaries.test.ts) keeps vault importing nothing; `pg.Pool`
// satisfies both shapes structurally.
//
// This store moves SEALED bytes only. It never holds, derives, or logs a plaintext key,
// a DEK, or the master key (the key-custody rule); opening is EncryptedWalletKeyStore's job and
// happens after the row is read.

import type { VaultRecord, VaultStore } from "./store.js";

export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface SqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

// The exact column sequence the table stores and this store selects. One constant so the
// INSERT column list, the SELECT projection, and the row mapper cannot drift apart.
export const VAULT_COLUMNS = [
  "wallet_id",
  "key_version",
  "ciphertext",
  "nonce",
  "auth_tag",
  "ciphertext_sha256",
  "created_at",
  "rotated_at",
] as const;

// guard 4: the read is by primary key with NO FOR UPDATE / FOR SHARE. Signing must
// never take a row lock on `vault` — wallet_active_leases is the sole serialization point
// for one-in-flight-per-wallet, and a second lock here would only add a deadlock edge.
export const STATEMENTS = {
  insert: `INSERT INTO vault (${VAULT_COLUMNS.join(", ")})
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
  findByWalletId: `SELECT ${VAULT_COLUMNS.join(", ")}
     FROM vault
    WHERE wallet_id = $1`,
  update: `UPDATE vault
        SET key_version = $2,
            ciphertext = $3,
            nonce = $4,
            auth_tag = $5,
            ciphertext_sha256 = $6,
            rotated_at = $7
      WHERE wallet_id = $1
  RETURNING wallet_id`,
} as const;

interface VaultRow {
  readonly wallet_id: string;
  readonly key_version: number;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly auth_tag: Uint8Array;
  readonly ciphertext_sha256: string;
  readonly created_at: Date;
  readonly rotated_at: Date | null;
}

const toRecord = (row: VaultRow): VaultRecord => ({
  walletId: row.wallet_id,
  keyVersion: Number(row.key_version),
  ciphertext: row.ciphertext,
  nonce: row.nonce,
  authTag: row.auth_tag,
  ciphertextSha256: row.ciphertext_sha256,
  createdAt: row.created_at,
  rotatedAt: row.rotated_at,
});

export class VaultSqlStore implements VaultStore {
  constructor(private readonly sql: SqlExecutor) {}

  // The duplicate-nonce and foreign-key rejections are the database's, not this method's:
  // a repeat (key_version, nonce) surfaces as the driver's unique_violation (23505) and is
  // deliberately not caught here — nonce reuse must abort the seal, never be absorbed.
  async insert(record: VaultRecord): Promise<void> {
    await this.sql.query(STATEMENTS.insert, [
      record.walletId,
      record.keyVersion,
      record.ciphertext,
      record.nonce,
      record.authTag,
      record.ciphertextSha256,
      record.createdAt,
      record.rotatedAt,
    ]);
  }

  async findByWalletId(walletId: string): Promise<VaultRecord | null> {
    const { rows } = await this.sql.query<VaultRow>(STATEMENTS.findByWalletId, [walletId]);
    const row = rows[0];
    return row === undefined ? null : toRecord(row);
  }

  async update(record: VaultRecord): Promise<void> {
    const { rows } = await this.sql.query<{ wallet_id: string }>(STATEMENTS.update, [
      record.walletId,
      record.keyVersion,
      record.ciphertext,
      record.nonce,
      record.authTag,
      record.ciphertextSha256,
      record.rotatedAt,
    ]);
    if (rows.length === 0) {
      throw new Error(`no vault row for wallet ${record.walletId}`);
    }
  }
}
