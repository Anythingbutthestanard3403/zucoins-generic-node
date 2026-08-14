// Node-wide default funding wallet setting (ZTR-1287).
//
// Durable home: node_settings key integration.default_funding_wallet_id
// (uuid text). Absent row ⇒ no default configured. Mutations bump row_version
// and append audit_log. Funding wallet is reserve/proof — never send/source.
//
// Constant lives here (implementer module) — not imported from schema/ — so the
// boundary graph stays implementer ↛ schema (peer dual-control keeps its key
// in send/). The schema contract freezes the same literal independently.

import { createHash, randomUUID } from "node:crypto";

/** node_settings key for the node-wide default funding wallet id (uuid text). */
export const DEFAULT_FUNDING_WALLET_SETTING_KEY =
  "integration.default_funding_wallet_id" as const;

export const DEFAULT_FUNDING_WALLET_AUDIT_ACTION =
  "ops.default_funding_wallet_changed" as const;

export interface DefaultFundingWalletSqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: readonly R[] }>;
}

export interface DefaultFundingWalletSnapshot {
  /** Configured default wallet id, or null when unset. */
  readonly wallet_id: string | null;
  /** wallets.public_key when wallet_id resolves; null when unset/missing. */
  readonly public_key: string | null;
  /** node_settings.row_version (0 when row absent). */
  readonly row_version: number;
}

export type DefaultFundingWalletSetRejectReason =
  | "wallet_not_found"
  | "wallet_retired"
  | "conflict"
  | "invalid_wallet_id";

export type DefaultFundingWalletSetOutcome =
  | { readonly ok: true; readonly result: DefaultFundingWalletSnapshot }
  | { readonly ok: false; readonly reason: DefaultFundingWalletSetRejectReason };

export interface DefaultFundingWalletSetInput {
  /** Null clears the node default. */
  readonly walletId: string | null;
  readonly expectedRowVersion: number;
  readonly actorId: string;
  readonly nodeId: string;
}

export interface DefaultFundingWalletPort {
  get(): Promise<DefaultFundingWalletSnapshot>;
  set(input: DefaultFundingWalletSetInput): Promise<DefaultFundingWalletSetOutcome>;
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * In-memory default funding wallet for tests.
 */
export class InMemoryDefaultFundingWallet implements DefaultFundingWalletPort {
  private walletId: string | null = null;
  private publicKey: string | null = null;
  private rowVersion = 0;
  readonly wallets = new Map<string, { public_key: string; retired?: boolean }>();
  readonly auditEntries: Array<{
    readonly previous: string | null;
    readonly next: string | null;
    readonly actorId: string;
    readonly nodeId: string;
  }> = [];

  seedWallet(id: string, publicKey: string, retired = false): void {
    this.wallets.set(id, { public_key: publicKey, retired });
  }

  async get(): Promise<DefaultFundingWalletSnapshot> {
    return {
      wallet_id: this.walletId,
      public_key: this.publicKey,
      row_version: this.rowVersion,
    };
  }

  async set(input: DefaultFundingWalletSetInput): Promise<DefaultFundingWalletSetOutcome> {
    if (this.rowVersion !== input.expectedRowVersion) {
      return { ok: false, reason: "conflict" };
    }
    let nextId: string | null = input.walletId;
    let nextKey: string | null = null;
    if (nextId !== null) {
      if (!UUID_RE.test(nextId)) {
        return { ok: false, reason: "invalid_wallet_id" };
      }
      const w = this.wallets.get(nextId);
      if (w === undefined) return { ok: false, reason: "wallet_not_found" };
      if (w.retired === true) return { ok: false, reason: "wallet_retired" };
      nextKey = w.public_key;
    }
    const previous = this.walletId;
    this.walletId = nextId;
    this.publicKey = nextKey;
    // Match SQL: clear deletes the settings row (row_version 0); set bumps or inserts at 1.
    if (nextId === null) {
      this.rowVersion = 0;
    } else {
      this.rowVersion = this.rowVersion === 0 ? 1 : this.rowVersion + 1;
    }
    this.auditEntries.push({
      previous,
      next: nextId,
      actorId: input.actorId,
      nodeId: input.nodeId,
    });
    return {
      ok: true,
      result: {
        wallet_id: this.walletId,
        public_key: this.publicKey,
        row_version: this.rowVersion,
      },
    };
  }
}

/**
 * SQL-backed port over node_settings + wallets + audit_log.
 * Bound to admin-mutation PoolClient so CAS + audit ride the outer TX.
 */
export function createSqlDefaultFundingWallet(
  sql: DefaultFundingWalletSqlExecutor,
  opts?: { readonly newId?: () => string },
): DefaultFundingWalletPort {
  const newId = opts?.newId ?? (() => randomUUID());

  async function readSetting(): Promise<{
    readonly value: string | null;
    readonly row_version: number;
  }> {
    const result = await sql.query<{ setting_value: string; row_version: string | number }>(
      `SELECT setting_value, row_version
         FROM node_settings
        WHERE setting_key = $1`,
      [DEFAULT_FUNDING_WALLET_SETTING_KEY],
    );
    const row = result.rows[0];
    if (row === undefined) {
      return { value: null, row_version: 0 };
    }
    return {
      value: row.setting_value,
      row_version: Number(row.row_version),
    };
  }

  async function resolvePublicKey(walletId: string | null): Promise<string | null> {
    if (walletId === null) return null;
    const result = await sql.query<{ public_key: string }>(
      `SELECT public_key FROM wallets WHERE id = $1::uuid AND retired_at IS NULL AND state <> 'RETIRED'`,
      [walletId],
    );
    return result.rows[0]?.public_key ?? null;
  }

  return {
    async get(): Promise<DefaultFundingWalletSnapshot> {
      const setting = await readSetting();
      const walletId =
        setting.value !== null && UUID_RE.test(setting.value) ? setting.value : null;
      // Absent / corrupt stored value both surface as unset (operator re-pins).
      if (setting.value !== null && walletId === null) {
        return { wallet_id: null, public_key: null, row_version: setting.row_version };
      }
      const publicKey = await resolvePublicKey(walletId);
      // Stale id (wallet gone) still reports the configured id so operators can clear it;
      // public_key null signals the pin no longer resolves.
      return {
        wallet_id: walletId,
        public_key: publicKey,
        row_version: setting.row_version,
      };
    },

    async set(input: DefaultFundingWalletSetInput): Promise<DefaultFundingWalletSetOutcome> {
      const current = await readSetting();
      if (current.row_version !== input.expectedRowVersion) {
        return { ok: false, reason: "conflict" };
      }

      let nextValue: string | null = input.walletId;
      let nextPublicKey: string | null = null;
      if (nextValue !== null) {
        if (!UUID_RE.test(nextValue)) {
          return { ok: false, reason: "invalid_wallet_id" };
        }
        const wallets = await sql.query<{
          id: string;
          public_key: string;
          state: string;
          retired_at: unknown;
        }>(
          `SELECT id::text AS id, public_key, state::text AS state, retired_at
             FROM wallets WHERE id = $1::uuid`,
          [nextValue],
        );
        const wallet = wallets.rows[0];
        if (wallet === undefined) return { ok: false, reason: "wallet_not_found" };
        if (
          (wallet.retired_at !== null && wallet.retired_at !== undefined) ||
          wallet.state === "RETIRED"
        ) {
          return { ok: false, reason: "wallet_retired" };
        }
        nextPublicKey = wallet.public_key;
      }

      const previous =
        current.value !== null && UUID_RE.test(current.value) ? current.value : null;
      const details =
        `setting_key=${DEFAULT_FUNDING_WALLET_SETTING_KEY}` +
        `;previous=${previous ?? ""}` +
        `;next=${nextValue ?? ""}` +
        `;previous_row_version=${input.expectedRowVersion}`;
      const detailsSha = detailsSha256(details);

      // Clear path: DELETE the settings row so get() returns row_version 0 again.
      // Set path: upsert with CAS on expected row_version (0 = insert only when absent).
      if (nextValue === null) {
        if (current.row_version === 0) {
          // Already unset — still audit for operator intent visibility.
          await sql.query(
            `INSERT INTO audit_log (
               id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
               details_text, details_sha256, created_at
             ) VALUES (
               $1::uuid, $2::uuid, 'OPERATOR_SESSION', $3,
               $4, NULL, NULL, $5, $6, now()
             )`,
            [
              newId(),
              input.nodeId,
              input.actorId,
              DEFAULT_FUNDING_WALLET_AUDIT_ACTION,
              details,
              detailsSha,
            ],
          );
          return {
            ok: true,
            result: { wallet_id: null, public_key: null, row_version: 0 },
          };
        }
        const del = await sql.query<{ setting_key: string }>(
          `WITH deleted AS (
             DELETE FROM node_settings
              WHERE setting_key = $1 AND row_version = $2
             RETURNING setting_key
           )
           INSERT INTO audit_log (
             id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
             details_text, details_sha256, created_at
           )
           SELECT
             $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
             $6, NULL, NULL, $7, $8, now()
           FROM deleted
           RETURNING (SELECT setting_key FROM deleted) AS setting_key`,
          [
            DEFAULT_FUNDING_WALLET_SETTING_KEY,
            input.expectedRowVersion,
            newId(),
            input.nodeId,
            input.actorId,
            DEFAULT_FUNDING_WALLET_AUDIT_ACTION,
            details,
            detailsSha,
          ],
        );
        if (del.rows[0] === undefined) {
          return { ok: false, reason: "conflict" };
        }
        return {
          ok: true,
          result: { wallet_id: null, public_key: null, row_version: 0 },
        };
      }

      // Insert (row_version 0) or CAS update.
      if (input.expectedRowVersion === 0) {
        const ins = await sql.query<{ row_version: string | number }>(
          `WITH upserted AS (
             INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
             VALUES ($1, $2, 1, now())
             ON CONFLICT (setting_key) DO NOTHING
             RETURNING row_version
           )
           INSERT INTO audit_log (
             id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
             details_text, details_sha256, created_at
           )
           SELECT
             $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
             $6, NULL, $7::uuid, $8, $9, now()
           FROM upserted
           RETURNING (SELECT row_version FROM upserted) AS row_version`,
          [
            DEFAULT_FUNDING_WALLET_SETTING_KEY,
            nextValue,
            newId(),
            input.nodeId,
            input.actorId,
            DEFAULT_FUNDING_WALLET_AUDIT_ACTION,
            nextValue,
            details,
            detailsSha,
          ],
        );
        if (ins.rows[0] === undefined) {
          return { ok: false, reason: "conflict" };
        }
        return {
          ok: true,
          result: {
            wallet_id: nextValue,
            public_key: nextPublicKey,
            row_version: Number(ins.rows[0].row_version),
          },
        };
      }

      const upd = await sql.query<{ row_version: string | number }>(
        `WITH upserted AS (
           UPDATE node_settings
              SET setting_value = $2,
                  row_version = row_version + 1,
                  updated_at = now()
            WHERE setting_key = $1 AND row_version = $3
           RETURNING row_version
         )
         INSERT INTO audit_log (
           id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
           details_text, details_sha256, created_at
         )
         SELECT
           $4::uuid, $5::uuid, 'OPERATOR_SESSION', $6,
           $7, NULL, $8::uuid, $9, $10, now()
         FROM upserted
         RETURNING (SELECT row_version FROM upserted) AS row_version`,
        [
          DEFAULT_FUNDING_WALLET_SETTING_KEY,
          nextValue,
          input.expectedRowVersion,
          newId(),
          input.nodeId,
          input.actorId,
          DEFAULT_FUNDING_WALLET_AUDIT_ACTION,
          nextValue,
          details,
          detailsSha,
        ],
      );
      if (upd.rows[0] === undefined) {
        return { ok: false, reason: "conflict" };
      }
      return {
        ok: true,
        result: {
          wallet_id: nextValue,
          public_key: nextPublicKey,
          row_version: Number(upd.rows[0].row_version),
        },
      };
    },
  };
}
