// real-PostgreSQL behaviours for scripts/remediate-orphaned-lease.mjs's proof-backed
// release: mint + consume an OPERATOR_QUARANTINE_RELEASE row through node-core's own
// completeGroupOperation -> mintReleaseProof -> releaseLease sequence (One-in-flight: no raw DELETE).
// Governing: operations recovery (boot-recovery / lease quarantine); lease-foundation.sql.
// Connectivity: TEST_DATABASE_URL (vitest.global-setup) or PG_REQUIRED fail-closed.

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  NONTERMINAL_OPERATION_STATES,
  isKnownOperationState,
  isTerminalOperationState,
} from "../src/protocol/operation-states.ts";
import {
  acquireLeases,
  completeGroupOperation,
  createLeaseGroup,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
} from "../src/leases/index.ts";
import { PsqlExecutor, psqlMust, runPsql, withDatabase, withTx } from "./psql-harness.ts";

// planRelease is dependency-injected (client, nodeCore, walletId) — importing it here never
// touches gn-pg-v3 or the module's own loadPg()/loadNodeCore()/main(), which only run when this
// script is invoked as a CLI entrypoint.
import { planRelease } from "../../../scripts/remediate-orphaned-lease.mjs";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;
const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = resolve(HERE, "../src/schema");

const NODE = "50000000-0000-4000-8000-000000000001";
const WALLET = "50000000-0000-4000-8000-000000000002";
const RECOVERY = "50000000-0000-4000-8000-000000000003";
const OWNER = "50000000-0000-4000-8000-000000000004";
const SHA = "f".repeat(64);
const PUBKEY = `${"Z".repeat(43)}=`;

const nodeCore = {
  completeGroupOperation,
  mintReleaseProof,
  releaseLease,
  isTerminalOperationState,
  isKnownOperationState,
};

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

const TRUNCATE_LEASE_STATE = `
TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
         lease_groups, lease_release_proofs, lease_audit_events,
         wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
UPDATE wallets SET state = 'AVAILABLE';`;

async function seedOrphanLease(operationId: string): Promise<void> {
  const groupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, operationId));
  await withTx(dbUrl, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId: WALLET, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId: groupId,
      rootOperationId: operationId,
      operationId,
      ownerInstanceId: OWNER,
    }),
  );
}

describe("remediate-orphaned-lease.mjs proof-backed release (real PG)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is missing");
      }
      return;
    }

    dbName = `remediate_orphaned_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);

    psqlMust(dbUrl, readFileSync(resolve(SCHEMA, "base-enums-domains.sql"), "utf8"));
    psqlMust(dbUrl, `CREATE TABLE nodes (id uuid PRIMARY KEY);`);
    psqlMust(dbUrl, readFileSync(resolve(SCHEMA, "custody-eligibility.sql"), "utf8"));
    await migrateLeaseFoundation(db);

    // Minimal evidence-table stubs — only what scripts/lease-provenance.mjs's QUERIES
    // (reused by the remediation script's findPhaseEvidence) select on. The real operations.sql
    // business CHECK-constraint web is out of scope: this test proves evidence presence/absence
    // gates the release, not operations.sql's own invariants.
    psqlMust(
      dbUrl,
      `CREATE TABLE operations (id uuid PRIMARY KEY, status text);
       CREATE TABLE operation_wallets (operation_id uuid NOT NULL);
       CREATE TABLE operation_transactions (operation_id uuid NOT NULL, attempt_no integer NOT NULL DEFAULT 1);
       CREATE TABLE receive_codes (operation_id uuid NOT NULL);
       CREATE TABLE signer_audit (operation_id uuid NOT NULL, called_at timestamptz NOT NULL DEFAULT now());
       CREATE TABLE audit_log (operation_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now());`,
    );

    psqlMust(
      dbUrl,
      `INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ('${WALLET}', '${NODE}', '${PUBKEY}', 'node_generated', 'AVAILABLE');
       INSERT INTO wallet_recovery_verifications (
         id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity
       ) VALUES (
         '${RECOVERY}', '${WALLET}', 'AUDITED_EXPORT', '${SHA}', '${PUBKEY}', '${RECOVERY}', now(), 'remediate-orphaned-test'
       );
       UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${RECOVERY}'
         WHERE id = '${WALLET}';`,
    );
  }, 60_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  });

  it.skipIf(!live)(
    "releases an orphan lease that has gained no phase evidence",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const op = randomUUID();
      await seedOrphanLease(op);

      const result = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

      expect(result.outcome).toBe("released");
      expect(result.after).toBeNull();
      expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");
      expect(psqlMust(dbUrl, `SELECT state FROM wallets WHERE id = '${WALLET}'`).trim()).toBe(
        "AVAILABLE",
      );
    },
    60_000,
  );

  it.skipIf(!live)(
    "refuses when the operation has gained phase evidence",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const op = randomUUID();
      await seedOrphanLease(op);
      psqlMust(dbUrl, `INSERT INTO operations (id) VALUES ('${op}')`);

      const result = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

      expect(result.outcome).toBe("refused_evidence_present");
      expect(result.evidence).toEqual([{ table: "operation", rowCount: 1 }]);
      expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
    },
    60_000,
  );

  // The terminal-status guard. A lease on a landed operation is not orphaned: it is
  // held until the consumer's verification-complete acknowledgement releases it. The
  // script must refuse with a diagnostic that says so, rather than the misleading
  // `refused_evidence_present` ("already fixed") that cost the lane an investigation.
  it.skipIf(!live)(
    "refuses distinctly when the lease's operation has reached a terminal status",
    async () => {
      for (const status of ["RECEIVE_LANDED", "INTERNAL_MOVE_LANDED", "EXTERNAL_SEND_LANDED", "EXPIRED", "REJECTED"]) {
        psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
        const op = randomUUID();
        await seedOrphanLease(op);
        psqlMust(dbUrl, `INSERT INTO operations (id, status) VALUES ('${op}', '${status}')`);

        const result = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

        expect(result.outcome).toBe("refused_operation_terminal");
        expect(result.status).toBe(status);
        // Nothing was written: the lease stays held and no release proof was minted.
        expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
        expect(psqlMust(dbUrl, `SELECT count(*) FROM lease_release_proofs`).trim()).toBe("0");
        expect(psqlMust(dbUrl, `SELECT count(*) FROM lease_group_operations WHERE completed_at IS NOT NULL`).trim()).toBe("0");
      }
    },
    60_000,
  );

  // The guard must not ride EVIDENCE_QUERY_KEYS: relaxing the evidence list must never silently
  // arm a force-release against a landed wallet. Proven by making the evidence check structurally
  // unable to fire — no evidence tables carry a row — while the operation is still terminal.
  it.skipIf(!live)(
    "the terminal-status refusal is independent of the phase-evidence list",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const op = randomUUID();
      await seedOrphanLease(op);
      psqlMust(dbUrl, `INSERT INTO operations (id, status) VALUES ('${op}', 'RECEIVE_LANDED')`);

      const seenQueries: string[] = [];
      const result = await withTx(dbUrl, (tx) =>
        planRelease(
          {
            query: (text: string, params?: readonly unknown[]) => {
              seenQueries.push(text);
              // Every phase-evidence lookup reports nothing, as a fully relaxed list would.
              if (/FROM (operation_wallets|operation_transactions|receive_codes|signer_audit|audit_log)/.test(text)) {
                return Promise.resolve({ rows: [] });
              }
              if (/SELECT \* FROM operations/.test(text)) return Promise.resolve({ rows: [] });
              return tx.query(text, params as never);
            },
          },
          nodeCore,
          WALLET,
        ),
      );

      expect(result.outcome).toBe("refused_operation_terminal");
      expect(result.status).toBe("RECEIVE_LANDED");
      expect(psqlMust(dbUrl, `SELECT count(*) FROM lease_release_proofs`).trim()).toBe("0");
      // The guard ran BEFORE the evidence sweep — its own status query is what refused.
      expect(seenQueries.some((q) => /status.*FROM operations/s.test(q))).toBe(true);
    },
    60_000,
  );

  // A status outside node-core's closed operation_status vocabulary means the DB
  // vocabulary has drifted past this build. "Not terminal" is then only "absent from a list", not
  // a finding that the lease is orphaned, so the guard must refuse with its own outcome instead of
  // handing the wallet to the evidence sweep. The stub `operations.status` column is plain text,
  // which is exactly how a drifted deployment would present a status this build cannot classify.
  it.skipIf(!live)(
    "refuses distinctly when the operation carries a status outside the closed vocabulary",
    async () => {
      for (const status of ["SETTLED", "PARTIALLY_LANDED", "receive_landed"]) {
        psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
        const op = randomUUID();
        await seedOrphanLease(op);
        psqlMust(dbUrl, `INSERT INTO operations (id, status) VALUES ('${op}', '${status}')`);

        const result = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

        expect(result.outcome).toBe("refused_status_unrecognised");
        expect(result.status).toBe(status);
        expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
        expect(psqlMust(dbUrl, `SELECT count(*) FROM lease_release_proofs`).trim()).toBe("0");
        expect(
          psqlMust(dbUrl, `SELECT count(*) FROM lease_group_operations WHERE completed_at IS NOT NULL`).trim(),
        ).toBe("0");
      }
    },
    60_000,
  );

  // The other half of that split: a status that IS in the vocabulary and is not terminal still
  // reaches the evidence sweep, so the new refusal has not quietly frozen the whole script. The
  // `operations` row itself is phase evidence, hence refused_evidence_present rather than a
  // release — what matters is which refusal fires.
  it.skipIf(!live)(
    "a known nonterminal status still falls through to the phase-evidence sweep",
    async () => {
      for (const status of NONTERMINAL_OPERATION_STATES) {
        psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
        const op = randomUUID();
        await seedOrphanLease(op);
        psqlMust(dbUrl, `INSERT INTO operations (id, status) VALUES ('${op}', '${status}')`);

        const result = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

        expect(result.outcome, `${status} should not be refused as unrecognised`).toBe(
          "refused_evidence_present",
        );
      }
    },
    60_000,
  );

  // An unevaluated custody guard fails closed rather than falling through to the release path —
  // for EITHER predicate. A build that still exports isTerminalOperationState but not
  // isKnownOperationState is precisely the earlier shape the guard must not run under.
  it.skipIf(!live)(
    "refuses to run at all when node-core supplies no terminal-status predicate",
    async () => {
      for (const [missing, injected] of [
        ["isTerminalOperationState", {}],
        ["isKnownOperationState", { isTerminalOperationState }],
      ] as const) {
        psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
        const op = randomUUID();
        await seedOrphanLease(op);

        await expect(
          withTx(dbUrl, (tx) =>
            planRelease(
              tx,
              { completeGroupOperation, mintReleaseProof, releaseLease, ...injected },
              WALLET,
            ),
          ),
        ).rejects.toThrow(new RegExp(missing));
        expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("1");
        expect(psqlMust(dbUrl, `SELECT count(*) FROM lease_release_proofs`).trim()).toBe("0");
      }
    },
    60_000,
  );

  it.skipIf(!live)(
    "is idempotent — a replay after a real release is a clean no-op",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const op = randomUUID();
      await seedOrphanLease(op);
      await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

      const replay = await withTx(dbUrl, (tx) => planRelease(tx, nodeCore, WALLET));

      expect(replay.outcome).toBe("already_clear");
      expect(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim()).toBe("0");
    },
    60_000,
  );
});
