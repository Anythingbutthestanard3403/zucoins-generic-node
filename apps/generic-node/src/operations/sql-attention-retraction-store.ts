// SQL-backed AttentionRetractionStore for the operator-driven attention
// retraction endpoint. Invariants: attention_required / attention_reason
// co-presence; audit-log.sql (append-only provenance).
//
// Deliberately separate from sql-recovery-store.ts (RecoveryActionStore /
// RecoveryInspectionStore, owned by the recovery-inspection slices): retraction has no recovery-nonce or
// TOTP step (auth is session + CSRF via runGuardedAdminMutation, not a burned recovery
// nonce), so it does not belong in that file's transaction shapes. This file mirrors its
// idioms (client-per-call transaction, BEGIN/COMMIT, ROLLBACK-then-rethrow, audit insert
// inside the same transaction as the mutation) without touching or importing from it.

import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";

import { sha256HexUtf8, type AttentionRetractionStore } from "@zucoins/node-core";

// Row is locked (FOR UPDATE) before any check so the not-found / not-flagged / conflict
// verdicts and the captured prior_attention_reason all observe the same consistent row,
// and no concurrent retraction or re-raise can interleave between the check and the CAS
// update below.
const SQL_LOCK_OPERATION = `
  SELECT node_id::text AS node_id, attention_required, attention_reason, row_version::int AS row_version
    FROM operations
   WHERE id = $1::uuid
   FOR UPDATE
`;

const SQL_CLEAR_ATTENTION = `
  UPDATE operations
     SET attention_required = false,
         attention_reason = NULL,
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid AND row_version = $2
  RETURNING row_version::int AS row_version, updated_at::text AS updated_at
`;

// Columns match audit-log.sql / sql-recovery-store.ts's SQL_INSERT_AUDIT_LOG
// exactly, same positions: (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
// details_text, details_sha256, created_at). wallet_id is NULL — retraction is not
// wallet-scoped.
const SQL_INSERT_AUDIT_LOG = `
  INSERT INTO audit_log (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
                          details_text, details_sha256, created_at)
  VALUES ($1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, $4, $5::uuid, NULL, $6, $7, now())
`;

export function createSqlAttentionRetractionStore(pool: Pool): AttentionRetractionStore {
  return {
    async commit(input) {
      const client: PoolClient = await pool.connect();
      try {
        await client.query("BEGIN");

        const lockResult = await client.query<{
          node_id: string;
          attention_required: boolean;
          attention_reason: string | null;
          row_version: number;
        }>(SQL_LOCK_OPERATION, [input.operationId]);
        const row = lockResult.rows[0];
        if (row === undefined) {
          await client.query("ROLLBACK");
          return { ok: false, reason: "operation_not_found" };
        }
        if (!row.attention_required || row.attention_reason === null) {
          await client.query("ROLLBACK");
          return { ok: false, reason: "not_flagged" };
        }
        if (row.row_version !== input.expectedRowVersion) {
          await client.query("ROLLBACK");
          return { ok: false, reason: "conflict" };
        }

        const priorAttentionReason = row.attention_reason;

        const clearResult = await client.query<{ row_version: number; updated_at: string }>(
          SQL_CLEAR_ATTENTION, [input.operationId, input.expectedRowVersion],
        );
        const clearedRow = clearResult.rows[0];
        if (clearedRow === undefined) {
          // Row was locked and version-checked above, so this is unreachable outside a
          // concurrent DDL/vacuum oddity. Fail closed rather than fabricate a result.
          await client.query("ROLLBACK");
          return { ok: false, reason: "conflict" };
        }

        // Provenance: the original attention_reason is preserved verbatim in the
        // append-only audit_log details_text (audit_log rejects UPDATE/DELETE/TRUNCATE at
        // the trigger level) before it is cleared from the mutable operations row, along
        // with the operator's rationale and optional superseding reference.
        const details = `action=operation.attention_retracted;operation_id=${input.operationId};` +
          `prior_attention_reason=${priorAttentionReason};reason=${input.reason};` +
          `superseded_by=${input.supersededBy ?? ""}`;
        await client.query(SQL_INSERT_AUDIT_LOG, [
          randomUUID(), row.node_id, input.actorId, "operation.attention_retracted",
          input.operationId, details, sha256HexUtf8(details),
        ]);

        await client.query("COMMIT");
        return {
          ok: true,
          rowVersion: clearedRow.row_version,
          retractedAt: clearedRow.updated_at,
          priorAttentionReason,
        };
      } catch (err) {
        try { await client.query("ROLLBACK"); } catch { /* keep original error */ }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
