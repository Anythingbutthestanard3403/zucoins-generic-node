// Production SQL RecoveryLiveDatabase.
//
// stampRecoveryVerification is ONE atomic statement: audit_log INSERT +
// wallet_recovery_verifications INSERT + wallets two-column stamp. Least privilege:
// no other live writes. Never carries private keys (the key-custody rule).
//
// DRIVER-AGNOSTIC: pg Pool is injected at the composition root.

import { createHash, randomUUID } from "node:crypto";

import type {
  RecoveryCeremonySummary,
  RecoveryLiveDatabase,
  RecoveryStampInput,
  RecoveryWalletRow,
} from "./types.js";

export interface SqlQueryResult<R> {
  readonly rows: R[];
}

export interface RecoverySqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>>;
}

export const RECOVERY_STAMP_SQL = {
  READ_WALLETS: `SELECT id AS wallet_id, public_key,
      recovery_verified_at
     FROM wallets`,
  HAS_VERIFICATION: `SELECT 1 AS ok
     FROM wallet_recovery_verifications
    WHERE wallet_id = $1::uuid AND export_sha256 = $2
    LIMIT 1`,
  STAMP: `WITH audit AS (
      INSERT INTO audit_log
        (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
         details_text, details_sha256, created_at)
      VALUES (
        $1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, 'RECOVERY_VERIFIED',
        NULL, $4::uuid, $5, $6, $7::timestamptz
      )
      RETURNING id
    ), verif AS (
      INSERT INTO wallet_recovery_verifications
        (id, wallet_id, method, public_key, export_sha256, audit_event_id,
         verified_at, verifier_identity)
      SELECT $8::uuid, $4::uuid, 'AUDITED_EXPORT', $9, $10, audit.id,
             $7::timestamptz, $3
        FROM audit
      RETURNING id
    )
    UPDATE wallets
       SET recovery_verified_at = $7::timestamptz,
           recovery_verification_id = verif.id
      FROM verif
     WHERE wallets.id = $4::uuid
       AND wallets.recovery_verified_at IS NULL
       AND wallets.public_key = $9
    RETURNING wallets.id AS wallet_id`,
  SUMMARY: `INSERT INTO audit_log
      (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
       details_text, details_sha256, created_at)
    VALUES (
      $1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, 'RECOVERY_CEREMONY_SUMMARY',
      NULL, NULL, $4, $5, $6::timestamptz
    )`,
} as const;

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function toIso(value: Date | string | null): string | null {
  if (value === null) return null;
  return typeof value === "string" ? value : value.toISOString();
}

function buildStampDetails(input: RecoveryStampInput): string {
  return JSON.stringify({
    ceremony_id: input.ceremonyId,
    wallet_id: input.walletId,
    method: input.method,
    public_key: input.publicKey,
    key_version: input.keyVersion,
    export_id: input.exportId,
    export_sha256: input.exportSha256,
    census_matched_restored: input.censusMatchedRestored,
    census_matched_live: input.censusMatchedLive,
    archived_proof_verified: input.archivedProofVerified,
    probe_preimage_sha256: input.probePreimageSha256,
    probe_signature: input.probeSignature,
    probe_verified: input.probeVerified,
  });
}

export interface SqlRecoveryLiveDatabaseDeps {
  readonly sql: RecoverySqlExecutor;
  readonly nodeId: string;
  readonly proveCurrentKeyPossession: () => Promise<boolean>;
  readonly now?: () => Date;
  readonly newId?: () => string;
}

export function createSqlRecoveryLiveDatabase(
  deps: SqlRecoveryLiveDatabaseDeps,
): RecoveryLiveDatabase {
  const now = deps.now ?? (() => new Date());
  const newId = deps.newId ?? (() => randomUUID());

  return {
    async readWallets() {
      const result = await deps.sql.query<{
        wallet_id: string;
        public_key: string;
        recovery_verified_at: Date | string | null;
      }>(RECOVERY_STAMP_SQL.READ_WALLETS, []);
      const map = new Map<string, RecoveryWalletRow>();
      for (const row of result.rows) {
        map.set(row.wallet_id, {
          walletId: row.wallet_id,
          publicKey: row.public_key,
          recoveryVerifiedAt: toIso(row.recovery_verified_at),
        });
      }
      return map;
    },

    proveCurrentKeyPossession: () => deps.proveCurrentKeyPossession(),

    async hasRecoveryVerification(walletId, exportSha256) {
      const result = await deps.sql.query<{ ok: number }>(RECOVERY_STAMP_SQL.HAS_VERIFICATION, [
        walletId,
        exportSha256,
      ]);
      return result.rows[0] !== undefined;
    },

    async stampRecoveryVerification(input: RecoveryStampInput) {
      if (input.method !== "AUDITED_EXPORT") {
        throw new Error("recovery stamp method must be AUDITED_EXPORT");
      }
      if (
        !input.censusMatchedRestored ||
        !input.censusMatchedLive ||
        !input.archivedProofVerified ||
        !input.probeVerified
      ) {
        throw new Error("recovery stamp refuses incomplete census/probe flags");
      }

      const verifiedAt = now().toISOString();
      const auditId = newId();
      const verificationId = newId();
      const detailsText = buildStampDetails(input);
      const detailsSha = sha256HexUtf8(detailsText);

      const result = await deps.sql.query<{ wallet_id: string }>(RECOVERY_STAMP_SQL.STAMP, [
        auditId,
        deps.nodeId,
        input.verifierIdentity,
        input.walletId,
        detailsText,
        detailsSha,
        verifiedAt,
        verificationId,
        input.publicKey,
        input.exportSha256,
      ]);

      if (result.rows[0] === undefined) {
        // Monotonic stamp: a concurrent/prior ceremony may have set recovery_verified_at.
        // Treat already-stamped as a successful no-op so a fresh-export re-run can finish
        // stamping still-null siblings. Public-key mismatch still fails closed via census
        // before this write; missing wallet is not recoverable here.
        const existing = await deps.sql.query<{ recovery_verified_at: Date | string | null }>(
          `SELECT recovery_verified_at FROM wallets WHERE id = $1::uuid AND public_key = $2`,
          [input.walletId, input.publicKey],
        );
        if (existing.rows[0]?.recovery_verified_at != null) {
          return;
        }
        throw new Error(
          "recovery stamp did not apply (public_key mismatch, missing wallet, or concurrent conflict)",
        );
      }
    },

    async appendCeremonySummary(summary: RecoveryCeremonySummary) {
      const createdAt = now().toISOString();
      const detailsText = JSON.stringify({
        ceremony_id: summary.ceremonyId,
        export_id: summary.exportId,
        manifest_sha256: summary.manifestSha256,
        stamped: summary.stamped,
        failed_closed: summary.failedClosed,
        skipped: summary.skipped,
        born_blocked: summary.bornBlocked,
      });
      await deps.sql.query(RECOVERY_STAMP_SQL.SUMMARY, [
        newId(),
        deps.nodeId,
        summary.verifierIdentity,
        detailsText,
        sha256HexUtf8(detailsText),
        createdAt,
      ]);
    },
  };
}
