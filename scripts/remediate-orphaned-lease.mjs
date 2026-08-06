#!/usr/bin/env node
// Proof-backed remediation for an orphaned wallet_active_leases row (no matching
// operation phase evidence). ABSOLUTE rule: never a raw DELETE FROM wallet_active_leases. This
// mints an OPERATOR_QUARANTINE_RELEASE row in lease_release_proofs and consumes it through
// node-core's own completeGroupOperation -> mintReleaseProof -> releaseLease sequence (the exact
// pattern receive/expiry-release.ts uses), all inside one transaction.
//
// Refuses (exit 1) if the operation has gained ANY phase evidence since the orphan was found —
// reuses the same evidence-table set as scripts/lease-provenance.mjs (operations,
// operation_wallets, operation_transactions, receive_codes, signer_audit, audit_log). Idempotent:
// a rerun after a real release finds no active-lease row and is a clean no-op.
//
// Refuses FIRST, and independently, when the lease's operation has reached a terminal
// status. That lease is not orphaned: it is legitimately held until the consumer's
// verification-complete acknowledgement releases it, proof-backed. Releasing it here would call
// completeGroupOperation — documented as the "verification-complete durable ack" — and so forge
// protocol evidence no consumer ever produced, then mint a lease_release_proofs manifest whose
// six `predicates` are all false for a landed operation. The release-proof vocabulary has no
// FORCE_RELEASE action.
//
// And refuses separately, with its own outcome, when the status is not in node-core's
// closed operation_status vocabulary at all. "Not terminal" then only means "absent from a list
// this build carries", which is no evidence the lease is orphaned.
//
// This guard deliberately does NOT ride EVIDENCE_QUERY_KEYS. Both predicates happen to fire on a
// landed operation today (its `operations` row is itself evidence), but a future relaxation of
// the evidence list must not silently arm a force-release against a landed wallet.
//
// Default mode is --dry-run: runs the full plan inside a real transaction (so refusal predicates
// are checked against live state) then ROLLBACK. --execute runs the identical plan and COMMITs.
//
// Precondition: packages/node-core must be built (dist/ present) — `pnpm --filter @zucoins/node-core build`.
// Usage: DATABASE_URL="postgres://..." node scripts/remediate-orphaned-lease.mjs [walletId] [--execute]

import { createHash, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

import { QUERIES } from "./lease-provenance.mjs";
import { loadNodeCore, loadPg } from "./remediate-orphaned-lease-loaders.mjs";

const TARGET_WALLET_ID = "36a79a46-22c2-4f61-9c44-d265b4279077";
const RELEASE_REASON = "OPERATOR_QUARANTINE_RELEASE";

// Fixed insertion sequence: this digest is durable proof evidence (mirrors
// releaseProofManifest() in receive/expiry-release.ts).
function releaseProofManifest({ walletId, operationId, leaseGroupId, membershipId, leaseEpoch }) {
  return JSON.stringify({
    release_kind: RELEASE_REASON,
    wallet_id: walletId,
    operation_id: operationId,
    lease_group_id: leaseGroupId,
    membership_id: membershipId,
    lease_epoch: leaseEpoch,
    predicates: {
      no_operation_row: true,
      no_operation_wallets: true,
      no_operation_transactions: true,
      no_receive_codes: true,
      no_signer_audit: true,
      no_audit_log: true,
    },
  });
}

// The same evidence-table set the provenance script defines, minus the wallet/lease-side rows —
// this is what "refuses if the operation gains phase evidence" checks against.
const EVIDENCE_QUERY_KEYS = [
  "operation",
  "operationWallets",
  "operationTransactions",
  "receiveCodes",
  "signerAudit",
  "auditLog",
];

async function findPhaseEvidence(client, operationId) {
  const found = [];
  for (const key of EVIDENCE_QUERY_KEYS) {
    const { rows } = await client.query(QUERIES[key], [operationId]);
    if (rows.length > 0) found.push({ table: key, rowCount: rows.length });
  }
  return found;
}

// Classifies the operation's status against node-core's closed operation_status vocabulary
// (protocol/operation-states.ts) — the same lists boot-recovery's census SQL interpolates.
//
// "Terminal" and "not terminal" are not an exhaustive split. A status the loaded build
// has never heard of means the DB vocabulary has drifted past this script, and a status that
// cannot be classified cannot be shown to be safe to force-release — so it gets its own outcome
// and refuses, rather than falling through to the evidence sweep on the strength of a `false`
// that only meant "absent from a list". Either predicate missing on the injected module means the
// guard cannot be evaluated at all, and an unevaluated custody guard fails closed.
async function classifyOperationStatus(client, nodeCore, operationId) {
  for (const predicate of ["isTerminalOperationState", "isKnownOperationState"]) {
    if (typeof nodeCore[predicate] !== "function") {
      throw new Error(
        `remediate-orphaned-lease: node-core supplied no ${predicate} — refusing to run ` +
          "the release plan without the terminal-status guard.",
      );
    }
  }
  const { rows } = await client.query(
    `SELECT status::text AS status FROM operations WHERE id = $1`,
    [operationId],
  );
  const status = rows[0]?.status ?? null;
  if (status === null) return { kind: "absent", status: null };
  if (nodeCore.isTerminalOperationState(status)) return { kind: "terminal", status };
  if (!nodeCore.isKnownOperationState(status)) return { kind: "unrecognised", status };
  return { kind: "nonterminal", status };
}

export async function planRelease(client, nodeCore, walletId) {
  const before = await client.query(
    `SELECT * FROM wallet_active_leases WHERE wallet_id = $1`,
    [walletId],
  );
  if (before.rows.length === 0) {
    return { outcome: "already_clear", before: null, evidence: [] };
  }

  const lease = before.rows[0];
  const operationStatus = await classifyOperationStatus(client, nodeCore, lease.operation_id);
  if (operationStatus.kind === "terminal") {
    return { outcome: "refused_operation_terminal", before: lease, status: operationStatus.status, evidence: [] };
  }
  if (operationStatus.kind === "unrecognised") {
    return { outcome: "refused_status_unrecognised", before: lease, status: operationStatus.status, evidence: [] };
  }

  const evidence = await findPhaseEvidence(client, lease.operation_id);
  if (evidence.length > 0) {
    return { outcome: "refused_evidence_present", before: lease, evidence };
  }

  const leaseEpoch = BigInt(lease.lease_epoch);
  const proofId = randomUUID();
  const manifest = releaseProofManifest({
    walletId: lease.wallet_id,
    operationId: lease.operation_id,
    leaseGroupId: lease.lease_group_id,
    membershipId: lease.membership_id,
    leaseEpoch: leaseEpoch.toString(),
  });
  const proofDigest = createHash("sha256").update(manifest, "utf8").digest("hex");

  await nodeCore.completeGroupOperation(client, {
    leaseGroupId: lease.lease_group_id,
    operationId: lease.operation_id,
  });
  await nodeCore.mintReleaseProof(client, {
    proofId,
    walletId: lease.wallet_id,
    operationId: lease.operation_id,
    membershipId: lease.membership_id,
    leaseGroupId: lease.lease_group_id,
    leaseEpoch,
    proofKind: RELEASE_REASON,
    proofDigest,
  });
  const released = await nodeCore.releaseLease(client, {
    walletId: lease.wallet_id,
    ownerInstanceId: lease.owner_instance_id,
    operationId: lease.operation_id,
    membershipId: lease.membership_id,
    leaseGroupId: lease.lease_group_id,
    leaseEpoch,
    releaseProofId: proofId,
    releaseReason: RELEASE_REASON,
  });

  const after = await client.query(
    `SELECT * FROM wallet_active_leases WHERE wallet_id = $1`,
    [walletId],
  );
  return { outcome: "released", before: lease, after: after.rows[0] ?? null, proofId, released, evidence: [] };
}

export async function main({ argv = process.argv, env = process.env } = {}) {
  const args = argv.slice(2);
  const walletId = args.find((a) => !a.startsWith("--")) ?? TARGET_WALLET_ID;
  const execute = args.includes("--execute");

  const connectionString = env.DATABASE_URL;
  if (!connectionString) {
    console.error("remediate-orphaned-lease: DATABASE_URL is not set. Exit 2 (error, not a clean pass).");
    return 2;
  }

  let client;
  try {
    const { Client } = await loadPg();
    const nodeCore = await loadNodeCore();
    client = new Client({ connectionString });
    await client.connect();
    await client.query("BEGIN");

    let plan;
    try {
      plan = await planRelease(client, nodeCore, walletId);
    } catch (error) {
      await client.query("ROLLBACK");
      // A LeaseError (e.g. GROUP_NOT_TERMINAL) is an expected, safe refusal — exit 1. Anything
      // else (network blip mid-transaction, etc.) is a genuine unexpected failure — exit 2, same
      // convention as lease-provenance.mjs / check-phantom-settles.mjs.
      if (error.name === "LeaseError") {
        console.error(
          JSON.stringify({ outcome: "refused_error", walletId, reason: error.reason }, null, 2),
        );
        return 1;
      }
      throw error;
    }

    if (plan.outcome === "already_clear") {
      await client.query("ROLLBACK");
      console.log(JSON.stringify({ outcome: "already_clear", walletId }, null, 2));
      return 0;
    }
    if (plan.outcome === "refused_operation_terminal") {
      await client.query("ROLLBACK");
      console.log(
        JSON.stringify(
          {
            outcome: "refused_operation_terminal",
            walletId,
            operationStatus: plan.status,
            before: plan.before,
            disposition:
              "Lease is legitimately held, not orphaned. It releases only through the consumer's " +
              "verification-complete acknowledgement (POST /v1/operations/:id/verification-complete). " +
              "No operator action clears it.",
          },
          null,
          2,
        ),
      );
      return 1;
    }
    if (plan.outcome === "refused_status_unrecognised") {
      await client.query("ROLLBACK");
      console.log(
        JSON.stringify(
          {
            outcome: "refused_status_unrecognised",
            walletId,
            operationStatus: plan.status,
            before: plan.before,
            disposition:
              "The operation carries a status that is not in node-core's closed operation_status " +
              "vocabulary, so this build cannot tell whether the lease is legitimately held. " +
              "Classify the status terminal-or-not in " +
              "packages/node-core/src/protocol/operation-states.ts (the census test in " +
              "packages/node-core/test/operation-states.census.test.ts enforces it), rebuild " +
              "node-core, and rerun.",
          },
          null,
          2,
        ),
      );
      return 1;
    }
    if (plan.outcome === "refused_evidence_present") {
      await client.query("ROLLBACK");
      console.log(
        JSON.stringify(
          { outcome: "refused_evidence_present", walletId, before: plan.before, evidence: plan.evidence },
          null,
          2,
        ),
      );
      return 1;
    }

    await client.query(execute ? "COMMIT" : "ROLLBACK");
    console.log(
      JSON.stringify(
        {
          outcome: execute ? "released" : "dry_run_would_release",
          executed: execute,
          walletId,
          before: plan.before,
          after: execute ? plan.after : null,
          proofId: plan.proofId,
        },
        null,
        2,
      ),
    );
    return 0;
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error(`remediate-orphaned-lease: ERROR — ${error.message}`);
    return 2;
  } finally {
    if (client) await client.end().catch(() => {});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main({});
}
