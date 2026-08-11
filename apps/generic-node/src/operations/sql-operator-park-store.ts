// SQL OperatorParkStore — audited operator park into OPERATOR_PARKED (ZTR-1147).
// Invariants: attention_required / attention_reason co-presence CHECK; first
// episode wins (already_flagged); row_version CAS; audit_log provenance.

import { randomUUID } from "node:crypto";

import type { Pool, PoolClient } from "pg";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";
import {
  sha256HexUtf8,
  type OperatorParkCommitted,
  type OperatorParkStore,
} from "@zucoins/node-core";

const SQL_LOCK = `
  SELECT node_id::text AS node_id,
         attention_required,
         row_version::int AS row_version
    FROM operations
   WHERE id = $1::uuid
   FOR UPDATE`;

const SQL_PARK = `
  UPDATE operations
     SET attention_required = true,
         attention_reason = $2,
         attention_detail = $3,
         attention_episode = attention_episode + 1,
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND attention_required = false
     AND row_version = $4
  RETURNING id::text AS id,
            row_version::int AS row_version,
            updated_at::text AS updated_at`;

const SQL_INSERT_AUDIT_LOG = `
  INSERT INTO audit_log (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
                          details_text, details_sha256, created_at)
  VALUES ($1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, $4, $5::uuid, NULL, $6, $7, now())
`;

export function createSqlOperatorParkStore(
  pool: Pool,
  options: { readonly moneyPathStatementTimeoutMs?: number } = {},
): OperatorParkStore {
  const statementTimeoutMs =
    options.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  return {
    async commitPark(input) {
      const client: PoolClient = await pool.connect();
      try {
        await client.query("BEGIN");
        await applyMoneyPathStatementTimeout(client, statementTimeoutMs);

        const loaded = await client.query<{
          node_id: string;
          attention_required: boolean;
          row_version: number;
        }>(SQL_LOCK, [input.operationId]);
        const row = loaded.rows[0];
        if (row === undefined) {
          await client.query("ROLLBACK");
          return { kind: "not_found" };
        }
        if (row.attention_required) {
          await client.query("ROLLBACK");
          return { kind: "already_flagged" };
        }
        if (row.row_version !== input.expectedRowVersion) {
          await client.query("ROLLBACK");
          return { kind: "conflict" };
        }

        const updated = await client.query<{
          id: string;
          row_version: number;
          updated_at: string;
        }>(SQL_PARK, [
          input.operationId,
          input.attentionReason,
          input.note,
          input.expectedRowVersion,
        ]);
        const parked = updated.rows[0];
        if (parked === undefined) {
          await client.query("ROLLBACK");
          return { kind: "conflict" };
        }

        const details =
          `action=operation.operator_parked;operation_id=${input.operationId};` +
          `attention_reason=${input.attentionReason};note=${input.note}`;
        await client.query(SQL_INSERT_AUDIT_LOG, [
          randomUUID(),
          row.node_id,
          input.actorId,
          "operation.operator_parked",
          input.operationId,
          details,
          sha256HexUtf8(details),
        ]);

        await client.query("COMMIT");
        const body: OperatorParkCommitted = {
          operationId: parked.id,
          attentionReason: input.attentionReason,
          rowVersion: parked.row_version,
          parkedAt: parked.updated_at,
        };
        return { kind: "committed", committed: body };
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* keep original */
        }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
