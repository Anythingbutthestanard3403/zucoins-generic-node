// SQL lease reader + transaction-scoped sign surface for money-path SignerBoundaryDeps.
// The noop signer audit log that used to live here was deleted — MOVE and SEND now
// share createSqlSignerAuditLog (packages/node-core/src/core/sql-signer-audit-log.ts), the same
// durable adapter RECEIVE uses, so boot recovery's signer_audit evidence is operation-kind-
// independent.
//
// ZTR-1160: the lease row is locked FOR UPDATE inside an explicit transaction on a pinned
// client, and that transaction stays open across vaultSigner.sign and the SIGNED audit
// append. Autocommit FOR SHARE (the previous wiring) released the lock at statement end and
// left a TOCTOU window before the signature existed. Release paths take the same row FOR
// UPDATE, so they block until the sign transaction commits — which is the guarantee the
// prior comment claimed but did not deliver.

import type { Pool, PoolClient } from "pg";

import {
  createSqlSignerAuditLog,
  type ActiveLeaseRecord,
  type LeaseReader,
  type SignUnderLeaseTransactionFn,
  type SignUnderLeaseTxPorts,
  type SqlQueryFn,
} from "@zucoins/node-core";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";

/** FOR UPDATE — one-in-flight-per-wallet: two concurrent signers must not both proceed. */
const SELECT_ACTIVE_LEASE_FOR_UPDATE = `
  SELECT wallet_id::text AS wallet_id,
         operation_id::text AS operation_id,
         lease_epoch::text AS lease_epoch,
         lease_role::text AS lease_role
    FROM wallet_active_leases
   WHERE wallet_id = $1::uuid
   LIMIT 1
     FOR UPDATE`;

function mapLeaseRow(
  row:
    | {
        wallet_id: string;
        operation_id: string;
        lease_epoch: string;
        lease_role: string;
      }
    | undefined,
): ActiveLeaseRecord | null {
  if (row === undefined) return null;
  return {
    walletId: row.wallet_id,
    operationId: row.operation_id,
    epoch: BigInt(row.lease_epoch),
    role: row.lease_role as ActiveLeaseRecord["role"],
    // A row in wallet_active_leases is by construction the active one; a released lease is
    // deleted from this table rather than flagged, so presence is the lifecycle answer.
    lifecycle: "ACTIVE",
  };
}

/**
 * Lease reader bound to a query surface (pool autocommit OR a pinned transaction client).
 * Production signing MUST call this through {@link createSqlSignUnderLeaseTransaction} so the
 * FOR UPDATE is held for the whole sign critical section — not via bare pool.query autocommit.
 */
export function createSqlLeaseReader(queryable: {
  query: (
    text: string,
    values?: unknown[],
  ) => Promise<{ rows: ReadonlyArray<Record<string, unknown>> }>;
}): LeaseReader {
  return {
    async readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
      const result = await queryable.query(SELECT_ACTIVE_LEASE_FOR_UPDATE, [walletId]);
      const row = result.rows[0] as
        | {
            wallet_id: string;
            operation_id: string;
            lease_epoch: string;
            lease_role: string;
          }
        | undefined;
      return mapLeaseRow(row);
    },
  };
}

/** @deprecated Prefer {@link createSqlLeaseReader} over a SqlQueryFn adapter when possible. */
export function createSqlLeaseReaderFromQueryFn(query: SqlQueryFn): LeaseReader {
  return {
    async readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
      const rows = await query(SELECT_ACTIVE_LEASE_FOR_UPDATE, [walletId]);
      const row = rows[0] as
        | {
            wallet_id: string;
            operation_id: string;
            lease_epoch: string;
            lease_role: string;
          }
        | undefined;
      return mapLeaseRow(row);
    },
  };
}

function txPortsFromClient(client: PoolClient): SignUnderLeaseTxPorts {
  const query: SqlQueryFn = async (text, values) => {
    const result = await client.query(text, values as unknown[]);
    return result.rows as readonly Record<string, unknown>[];
  };
  return {
    leaseReader: createSqlLeaseReader(client),
    auditLog: createSqlSignerAuditLog(query),
  };
}

/**
 * Pin one client: BEGIN → body(lease FOR UPDATE + sign + audit) → COMMIT.
 * Matches arm-wallet-gate.ts ("One client is pinned for the whole critical section so FOR
 * UPDATE is meaningful"). Isolation is READ COMMITTED + covering ROW_LOCK — CONVENTIONS.md
 * §1.1 accepts this when the lock covers the decision rows and the body may call the vault
 * (SERIALIZABLE + withSerializationRetry forbids non-DB work inside the retried body).
 *
 * After BEGIN, applies a transaction-local statement_timeout so a stuck sign cannot hold the
 * lease row forever (ZTR-1156).
 */
export function createSqlSignUnderLeaseTransaction(
  pool: Pool,
  options: { readonly statementTimeoutMs?: number } = {},
): SignUnderLeaseTransactionFn {
  const statementTimeoutMs =
    options.statementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  return async function withSignTransaction<T>(
    body: (tx: SignUnderLeaseTxPorts) => Promise<T>,
  ): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applyMoneyPathStatementTimeout(client, statementTimeoutMs);
      const value = await body(txPortsFromClient(client));
      await client.query("COMMIT");
      return value;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        // surface the original error
      }
      throw err;
    } finally {
      client.release();
    }
  };
}
