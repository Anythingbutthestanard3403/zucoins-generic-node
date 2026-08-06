#!/usr/bin/env node
// READ-ONLY provenance dump for the orphaned wallet_active_leases row that
// quarantines generic-node on every boot. No writes,
// no gateway calls, no key material touched.
//
// Pulls every fact boot-recovery's auditActiveLeases()/listNonterminalOperations() would
// have seen for the target wallet's lease: the active-lease row itself, the operations row
// its operation_id points at (if any), every phase-evidence table that row could carry
// (operation_wallets, operation_transactions, receive_codes, signer_audit, audit_log), and
// the lease-group / membership / lease-audit trail. Emits one JSON object to stdout;
// nothing else touches stdout so it can be redirected straight to a file for grep.
//
// Usage: DATABASE_URL="postgres://..." node scripts/lease-provenance.mjs <walletId>
//        node scripts/lease-provenance.mjs --dry-run   # print queries, touch nothing

import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const TARGET_WALLET_ID = "36a79a46-22c2-4f61-9c44-d265b4279077";

export const QUERIES = {
  activeLease: `SELECT * FROM wallet_active_leases WHERE wallet_id = $1`,
  wallet: `SELECT id, state FROM wallets WHERE id = $1`,
  membership: `SELECT * FROM wallet_lease_memberships WHERE wallet_id = $1 ORDER BY acquired_at`,
  leaseAuditEvents: `SELECT * FROM lease_audit_events WHERE wallet_id = $1 ORDER BY created_at`,
  operation: `SELECT * FROM operations WHERE id = $1`,
  operationWallets: `SELECT * FROM operation_wallets WHERE operation_id = $1`,
  operationTransactions: `SELECT * FROM operation_transactions WHERE operation_id = $1 ORDER BY attempt_no`,
  receiveCodes: `SELECT * FROM receive_codes WHERE operation_id = $1`,
  signerAudit: `SELECT * FROM signer_audit WHERE operation_id = $1 ORDER BY called_at`,
  auditLog: `SELECT * FROM audit_log WHERE operation_id = $1 ORDER BY created_at`,
  leaseGroup: `SELECT * FROM lease_groups WHERE id = $1`,
  leaseGroupOperations: `SELECT * FROM lease_group_operations WHERE lease_group_id = $1 ORDER BY joined_at`,
};

// This targets gn-pg-v3 (generic-node's DB), so pg resolves via apps/generic-node's
// graph, not apps/node's — same fallback shape as scripts/check-phantom-settles.mjs
// (which targets apps/node for its own, different ticket).
async function loadPg() {
  try {
    return await import("pg");
  } catch (error) {
    if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  }
  const genericNodeManifest = fileURLToPath(new URL("../apps/generic-node/package.json", import.meta.url));
  return createRequire(genericNodeManifest)("pg");
}

async function fetchProvenance(client, walletId) {
  const one = async (query, params) => (await client.query(query, params)).rows;

  const activeLease = await one(QUERIES.activeLease, [walletId]);
  const wallet = await one(QUERIES.wallet, [walletId]);
  const membership = await one(QUERIES.membership, [walletId]);
  const leaseAuditEvents = await one(QUERIES.leaseAuditEvents, [walletId]);

  const operationId = activeLease[0]?.operation_id ?? null;
  const leaseGroupId = activeLease[0]?.lease_group_id ?? null;

  const operation = operationId ? await one(QUERIES.operation, [operationId]) : [];
  const operationWallets = operationId ? await one(QUERIES.operationWallets, [operationId]) : [];
  const operationTransactions = operationId ? await one(QUERIES.operationTransactions, [operationId]) : [];
  const receiveCodes = operationId ? await one(QUERIES.receiveCodes, [operationId]) : [];
  const signerAudit = operationId ? await one(QUERIES.signerAudit, [operationId]) : [];
  const auditLog = operationId ? await one(QUERIES.auditLog, [operationId]) : [];
  const leaseGroup = leaseGroupId ? await one(QUERIES.leaseGroup, [leaseGroupId]) : [];
  const leaseGroupOperations = leaseGroupId ? await one(QUERIES.leaseGroupOperations, [leaseGroupId]) : [];

  return {
    walletId,
    activeLease,
    wallet,
    membership,
    leaseAuditEvents,
    operationId,
    operationExists: operation.length > 0,
    operation,
    operationWallets,
    operationTransactions,
    receiveCodes,
    signerAudit,
    auditLog,
    leaseGroupId,
    leaseGroup,
    leaseGroupOperations,
  };
}

export async function main({ argv = process.argv, env = process.env } = {}) {
  const args = argv.slice(2);
  const walletId = args.find((a) => !a.startsWith("--")) ?? TARGET_WALLET_ID;

  if (args.includes("--dry-run")) {
    console.log(JSON.stringify(QUERIES, null, 2));
    return 0;
  }

  const connectionString = env.DATABASE_URL;
  if (!connectionString) {
    console.error("lease-provenance: DATABASE_URL is not set. Exit 2 (error, not a clean pass).");
    return 2;
  }

  let client;
  try {
    const { Client } = await loadPg();
    client = new Client({ connectionString });
    await client.connect();
    const report = await fetchProvenance(client, walletId);
    console.log(JSON.stringify(report, null, 2));
    return 0;
  } catch (error) {
    console.error(`lease-provenance: ERROR — ${error.message}`);
    return 2;
  } finally {
    if (client) await client.end().catch(() => {});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main({});
}
