// One-shot plaintext → sealed migration for admin_operators TOTP factors (ZTR-1134).
// Runs after vault unlock so the root key is available. Idempotent.

import { totpSecretBytes } from "./secret.js";
import { openTotpSecret, sealTotpSecret } from "./seal.js";

export interface TotpPlaintextMigrationExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

export interface TotpPlaintextMigrationResult {
  /** Rows that held plaintext and were sealed (or already had a matching sealed envelope). */
  readonly migrated: number;
  /** Rows already sealed with no plaintext residual. */
  readonly alreadySealed: number;
  /** True when totp_secret_base32 column was dropped (or already absent). */
  readonly plaintextColumnDropped: boolean;
}

/**
 * Seal every residual plaintext TOTP secret, clear plaintext cells, then drop
 * `totp_secret_base32` when empty. Fail-closed on undecodable secrets.
 */
export async function migrateTotpSecretsAtRest(input: {
  readonly db: TotpPlaintextMigrationExecutor;
  readonly rootKey: Uint8Array;
}): Promise<TotpPlaintextMigrationResult> {
  const { db, rootKey } = input;

  const col = await db.query<{ column_name: string }>(
    `SELECT column_name
       FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'admin_operators'
        AND column_name IN ('totp_secret_base32', 'totp_secret_sealed')`,
  );
  const names = new Set(col.rows.map((r) => String(r["column_name"])));
  if (!names.has("totp_secret_sealed")) {
    throw new Error(
      "migrateTotpSecretsAtRest: totp_secret_sealed column missing — apply drizzle 0007 first",
    );
  }

  let migrated = 0;
  let alreadySealed = 0;

  if (names.has("totp_secret_base32")) {
    const { rows } = await db.query<{
      id: string;
      totp_secret_base32: string | null;
      totp_secret_sealed: string | null;
    }>(
      `SELECT id, totp_secret_base32, totp_secret_sealed
         FROM admin_operators
        WHERE totp_secret_base32 IS NOT NULL
          AND length(btrim(totp_secret_base32)) > 0`,
    );

    for (const row of rows) {
      const id = String(row["id"]);
      const plain = String(row["totp_secret_base32"] ?? "").trim();
      const existingSealed =
        typeof row["totp_secret_sealed"] === "string" && row["totp_secret_sealed"].length > 0
          ? row["totp_secret_sealed"]
          : null;

      const bytes = totpSecretBytes(plain);
      if (bytes === null) {
        throw new Error(
          `migrateTotpSecretsAtRest: undecodable plaintext TOTP secret for operator ${id}`,
        );
      }
      try {
        if (existingSealed !== null) {
          // Prove existing envelope matches plaintext before clearing.
          const opened = openTotpSecret(rootKey, id, existingSealed);
          try {
            if (
              opened.length !== bytes.length ||
              !opened.every((b, i) => b === bytes[i])
            ) {
              throw new Error(
                `migrateTotpSecretsAtRest: sealed envelope disagrees with plaintext for ${id}`,
              );
            }
          } finally {
            opened.fill(0);
          }
        } else {
          const sealed = sealTotpSecret(rootKey, id, bytes);
          await db.query(
            `UPDATE admin_operators
                SET totp_secret_sealed = $2
              WHERE id = $1`,
            [id, sealed],
          );
        }
        await db.query(
          `UPDATE admin_operators
              SET totp_secret_base32 = NULL
            WHERE id = $1`,
          [id],
        );
        migrated += 1;
      } finally {
        bytes.fill(0);
      }
    }

    // Drop plaintext column once no residual values remain.
    const residual = await db.query<{ n: string }>(
      `SELECT count(*)::text AS n
         FROM admin_operators
        WHERE totp_secret_base32 IS NOT NULL
          AND length(btrim(totp_secret_base32)) > 0`,
    );
    if (Number(residual.rows[0]?.["n"] ?? 0) > 0) {
      throw new Error("migrateTotpSecretsAtRest: residual plaintext TOTP secrets remain");
    }
    await db.query(`ALTER TABLE admin_operators DROP COLUMN IF EXISTS totp_secret_base32`);
  } else {
    const sealedRows = await db.query<{ n: string }>(
      `SELECT count(*)::text AS n
         FROM admin_operators
        WHERE totp_secret_sealed IS NOT NULL
          AND length(btrim(totp_secret_sealed)) > 0`,
    );
    alreadySealed = Number(sealedRows.rows[0]?.["n"] ?? 0);
  }

  // Confirm column gone.
  const after = await db.query<{ column_name: string }>(
    `SELECT column_name
       FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'admin_operators'
        AND column_name = 'totp_secret_base32'`,
  );
  if (after.rows.length > 0) {
    throw new Error("migrateTotpSecretsAtRest: totp_secret_base32 still present after drop");
  }

  return {
    migrated,
    alreadySealed,
    plaintextColumnDropped: true,
  };
}
