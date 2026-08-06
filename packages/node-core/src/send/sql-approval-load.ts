// SQL loader for Admin ApprovalOperationSnapshot (live admin money mount).

import type { ApprovalOperationSnapshot } from "./approve.js";
import type { SqlExecutor } from "./sql-store.js";

export const APPROVAL_LOAD_SQL = {
  BY_OPERATION_ID: `SELECT o.operation_id,
      o.node_id,
      o.status,
      o.row_version,
      o.source_wallet_id,
      w.public_key AS source_pubkey,
      o.destination_address,
      o.amount_zkz,
      o.references_operation_id
     FROM send_operations o
     JOIN wallets w ON w.id = o.source_wallet_id
    WHERE o.operation_id = $1::uuid`,
} as const;

interface ApprovalOpRow {
  readonly operation_id: string;
  readonly node_id: string;
  readonly status: string;
  readonly row_version: string | number;
  readonly source_wallet_id: string;
  readonly source_pubkey: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id: string | null;
}

export function createSqlApprovalOperationLoader(
  sql: SqlExecutor,
): (operationId: string) => Promise<ApprovalOperationSnapshot | null> {
  return async (operationId) => {
    const result = await sql.query<ApprovalOpRow>(APPROVAL_LOAD_SQL.BY_OPERATION_ID, [
      operationId,
    ]);
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      operationId: row.operation_id,
      nodeId: row.node_id,
      status: row.status,
      rowVersion: Number(row.row_version),
      sourceWalletId: row.source_wallet_id,
      sourcePubkey: row.source_pubkey,
      destinationAddress: row.destination_address,
      amountZkz: row.amount_zkz,
      referencesOperationId: row.references_operation_id,
    };
  };
}
