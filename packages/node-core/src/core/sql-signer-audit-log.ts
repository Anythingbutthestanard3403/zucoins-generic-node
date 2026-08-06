// the one durable signer-audit sink.
//
// Promoted out of apps/generic-node/src/money-workers/receive-settle-step.ts, where it
// started as a private, RECEIVE-only helper. MOVE and SEND instead wired createNoopSignerAuditLog
// so recovery's `signer_audit_present` check (sql-boot-recovery.ts) was always false
// for those two operation kinds regardless of whether a real signing call occurred — recovery
// could not distinguish "signer never called" from "call occurred before signature persistence"
//. One shared adapter closes that gap for every operation kind at once.

import { randomUUID } from "node:crypto";

import type { SignerAuditEntry, SignerAuditLog } from "./signer-boundary.js";
import type { SqlQueryFn } from "./sql-query-fn.js";

/**
 * The signer_audit CHECK vocabulary (packages/node-core/src/schema/signer-support.sql) is a
 * different closed set from the signer boundary's. Neither is free to drift onto the other, so
 * the two mappings are explicit and total — a new boundary outcome or purpose fails to compile
 * here rather than failing the INSERT at runtime.
 */
const AUDIT_OUTCOME: Readonly<Record<SignerAuditEntry["outcome"], string>> = {
  SIGNED: "SUCCEEDED",
  REJECTED: "FAILED",
};
const AUDIT_PURPOSE: Readonly<Record<SignerAuditEntry["purpose"], string>> = {
  SPLITCHAIN_STEP_1: "STEP_1",
  SPLITCHAIN_STEP_2: "STEP_2",
};

const INSERT_SIGNER_AUDIT = `
  INSERT INTO signer_audit
    (id, node_id, operation_id, lease_group_id, lease_epoch,
     preimage_sha256, called_at, outcome, purpose)
  SELECT $1::uuid, o.node_id, $2::uuid, NULL, $3::bigint, $4, $5::timestamptz, $6, $7
    FROM operations o WHERE o.id = $2::uuid`;

/**
 * append throws on write failure and never catches: a swallowed audit write must not let a
 * signature be treated as durably audited. signUnderLease (signer-boundary.ts) awaits append
 * with no surrounding try/catch, so an INSERT failure here fails the whole sign call closed.
 */
export function createSqlSignerAuditLog(query: SqlQueryFn): SignerAuditLog {
  return {
    async append(entry: SignerAuditEntry): Promise<void> {
      await query(INSERT_SIGNER_AUDIT, [
        randomUUID(),
        entry.operationId,
        entry.leaseEpoch.toString(),
        entry.preimageSha256,
        entry.timestamp,
        AUDIT_OUTCOME[entry.outcome],
        AUDIT_PURPOSE[entry.purpose],
      ]);
    },
  };
}
