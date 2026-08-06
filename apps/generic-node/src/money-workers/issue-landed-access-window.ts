// Issue the verification-material access window at land.
// Gated material source (createGatedTableVerificationMaterialSource) returns 409 until
// verification_material_access_windows has an OPEN row; operations.verification_material_available_until
// alone is not enough once the window store is wired.

import {
  issueVerificationAccessWindow,
  type OperationKind,
  type SqlQueryFn,
  type VerificationAccessWindowRecord,
  type VerificationAccessWindowStore,
} from "@zucoins/node-core";

function queryBackedAccessWindowStore(query: SqlQueryFn): VerificationAccessWindowStore {
  return {
    async save(record: VerificationAccessWindowRecord): Promise<void> {
      await query(
        `INSERT INTO verification_material_access_windows
           (id, node_id, implementer_id, operation_id, status, nonce_hash, issued_at, expires_at, revoked_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'OPEN', $5,
                 to_timestamp($6::double precision / 1000.0),
                 to_timestamp($7::double precision / 1000.0),
                 NULL)
         ON CONFLICT (operation_id) DO NOTHING`,
        [
          record.id,
          record.nodeId,
          record.implementerId,
          record.operationId,
          record.nonceHash,
          record.issuedAtMs,
          record.expiresAtMs,
        ],
      );
    },
    async findByOperation(operationId, implementerId) {
      const rows = await query(
        `SELECT id::text AS id, node_id::text AS node_id, implementer_id::text AS implementer_id,
                operation_id::text AS operation_id, status, nonce_hash,
                (extract(epoch FROM issued_at) * 1000)::bigint AS issued_at_ms,
                (extract(epoch FROM expires_at) * 1000)::bigint AS expires_at_ms,
                CASE WHEN revoked_at IS NULL THEN NULL
                     ELSE (extract(epoch FROM revoked_at) * 1000)::bigint END AS revoked_at_ms
           FROM verification_material_access_windows
          WHERE operation_id = $1::uuid AND implementer_id = $2::uuid`,
        [operationId, implementerId],
      );
      const row = rows[0] as
        | {
            id: string;
            node_id: string;
            implementer_id: string;
            operation_id: string;
            status: VerificationAccessWindowRecord["status"];
            nonce_hash: string;
            issued_at_ms: string | number;
            expires_at_ms: string | number;
            revoked_at_ms: string | number | null;
          }
        | undefined;
      if (row === undefined) return null;
      return {
        id: row.id,
        nodeId: row.node_id,
        implementerId: row.implementer_id,
        operationId: row.operation_id,
        status: row.status,
        nonceHash: row.nonce_hash,
        issuedAtMs: Number(row.issued_at_ms),
        expiresAtMs: Number(row.expires_at_ms),
        revokedAtMs: row.revoked_at_ms === null || row.revoked_at_ms === undefined
          ? null
          : Number(row.revoked_at_ms),
      };
    },
    async findByNonceHash() {
      return null;
    },
    async updateStatus() {
      return false;
    },
  };
}

/**
 * Idempotent: opens the access window for a just-landed operation inside the land TX.
 * Reads node/implementer/kind/status from operations so callers need only the op id + terminal ms.
 */
export async function issueLandedAccessWindow(
  query: SqlQueryFn,
  operationId: string,
  terminalAtMs: number,
): Promise<void> {
  const rows = await query(
    `SELECT node_id::text AS node_id,
            implementer_id::text AS implementer_id,
            kind::text AS kind,
            status::text AS status
       FROM operations
      WHERE id = $1::uuid`,
    [operationId],
  );
  const row = rows[0] as
    | { node_id: string; implementer_id: string; kind: string; status: string }
    | undefined;
  if (row === undefined) {
    throw new Error(`issueLandedAccessWindow: operation ${operationId} not found`);
  }

  const existing = await query(
    `SELECT 1 AS ok FROM verification_material_access_windows
      WHERE operation_id = $1::uuid AND implementer_id = $2::uuid`,
    [operationId, row.implementer_id],
  );
  if (existing[0] !== undefined) return;

  await issueVerificationAccessWindow(queryBackedAccessWindowStore(query), {
    nodeId: row.node_id,
    implementerId: row.implementer_id,
    operationId,
    kind: row.kind as OperationKind,
    status: row.status,
    terminalAtMs,
  });
}
