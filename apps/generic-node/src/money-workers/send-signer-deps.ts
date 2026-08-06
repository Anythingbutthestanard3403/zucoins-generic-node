// SQL lease reader for money-path SignerBoundaryDeps.
// The noop signer audit log that used to live here was deleted — MOVE and SEND now
// share createSqlSignerAuditLog (packages/node-core/src/core/sql-signer-audit-log.ts), the same
// durable adapter RECEIVE uses, so boot recovery's signer_audit evidence is operation-kind-
// independent.

import type { Pool } from "pg";

import type { ActiveLeaseRecord, LeaseReader } from "@zucoins/node-core";

export function createSqlLeaseReader(pool: Pool): LeaseReader {
  return {
    async readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
      const result = await pool.query<{
        wallet_id: string;
        operation_id: string;
        lease_epoch: string;
        lease_role: string;
      }>(
        // FOR SHARE for the same reason the RECEIVE settle reader takes it — the
        // release path holds this row FOR UPDATE, so an unlocked read hands the signer a lease
        // that is already being released. Shared by SEND and MOVE, so both serialize the same way.
        `SELECT wallet_id::text AS wallet_id,
                operation_id::text AS operation_id,
                lease_epoch::text AS lease_epoch,
                lease_role::text AS lease_role
           FROM wallet_active_leases
          WHERE wallet_id = $1::uuid
          LIMIT 1
            FOR SHARE`,
        [walletId],
      );
      const row = result.rows[0];
      if (row === undefined) return null;
      return {
        walletId: row.wallet_id,
        operationId: row.operation_id,
        epoch: BigInt(row.lease_epoch),
        role: row.lease_role as ActiveLeaseRecord["role"],
        lifecycle: "ACTIVE",
      };
    },
  };
}
