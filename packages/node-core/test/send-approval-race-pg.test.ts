/**
 * send-approval-race-pg.test.ts
 *
 * The adversarial half of proves, against a REAL PostgreSQL
 * database running the REAL frozen DDL (src/schema/send-external-create.sql after its
 * prerequisite custody-eligibility.sql), that the pre-approval decisions cannot be raced into
 * an inconsistent state.
 *
 * The system under test is production code, not a model. Every decision below is issued by
 * src/send/decide.ts's own `rejectSendOperation` / `commitSendApproval` running against
 * `SqlSendDecisionStore`, whose statements reach PostgreSQL through a psql-backed SqlExecutor.
 * Nothing in this file re-implements a transition or arbitrates a race: the arbiter is the
 * `status = 'CREATED' AND row_version = $2` guard inside the frozen statement text, and a
 * loser is a zero-row UPDATE decided by the database.
 *
 * Concurrency is real. Each `query()` spawns its own psql process — its own connection, its
 * own backend, its own transaction — and the racing decisions are released together through
 * `Promise.all`. A sequential simulation cannot fail for the reason this suite exists, so
 * there is none here.
 *
 * Drills:
 *   1. (c) N concurrent approve + reject decisions on one CREATED operation — exactly one
 *      applies, row_version advances by exactly one, and every loser gets the same conflict.
 *   2. (c) a reject racing a committed approval never produces APPROVED→REJECTED; the closed
 * transition graph holds under contention.
 *   3. (d) a stale expected_row_version fails closed on both arms and changes nothing.
 * 4. signing custody — unknown operation, wrong state and stale version are byte-indistinguishable:
 *      the conflict never reveals which guard rejected it.
 *   5. Parent exit criterion — a decision cannot carry an economic change: the frozen
 *      send_operations_immutable_fields_guard trigger raises SEND_IMMUTABLE_FIELD_REJECTED,
 *      and the four economic fields survive drill 1 byte-identical.
 * 6. (e) signing custody crash matrix, row "approval pending, no sign intent" — a backend killed
 *      after the guarded UPDATE but before COMMIT leaves the operation safely CREATED at its
 *      original row_version, and a retry then succeeds.
 * 7. operations recovery — no source lease and no SplitChain attempt exists at any point before
 *      approval, confirming this slice never reaches into territory.
 *
 * Not proven here: the challenge-refresh race (a) and the duplicate-TOTP race (b). Both are
 * arbitrated by approval_challenges_one_issued_per_operation and
 * operation_approvals_totp_single_use, and neither table has a frozen.sql
 * artifact in this package yet. Racing them against a table this file
 * invented would prove nothing about the real constraint, so they are recorded as open
 * obligations in test/crash-replay-obligations.ts instead.
 *
 * Harness: hermetic scratch database named for this suite — nothing outside the send_approval_race_pg_
 * prefix is created or dropped, because the server is shared with other lanes. psql runs as a
 * child process, which keeps the in-process network-containment guard intact. Shape
 * mirrors test/send-external-create-pg.test.ts and custody-eligibility-lease-pk.test.ts: the
 * suite probes the maintenance database itself and fails closed under PG_REQUIRED=1.
 */
import { execFile, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { OPERATION_COLUMNS } from "../src/send/sql-store.js";
import type { SqlExecutor, SqlQueryResult } from "../src/send/sql-store.js";
import {
  commitSendApproval,
  rejectSendOperation,
  SEND_DECISION_CONFLICT,
  SqlSendDecisionStore,
} from "../src/send/decide.js";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

/* ─── constants ───────────────────────────────────────────────────── */

const MAINTENANCE_DB = "postgres";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const SQLSTATE_RAISE_EXCEPTION = "P0001";
const EXPECTED_DRILL_COUNT = 7;
const RACERS = 8;

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

// VERBOSITY=verbose is unconditional for async runners that assert SQLSTATE: the
// machine-readable `ERROR:  <sqlstate>:` line it puts on stderr is what the trigger drill
// asserts, and the default verbosity never emits it. -qAt is tuples-only, so command tags
// never contaminate the row parse.
const runPsqlAsync = (db: string, sql: string): Promise<PsqlOutcome> =>
  new Promise((resolve) => {
    execFile(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 20_000 },
      (err, stdout, stderr) => {
        resolve({ ok: err === null, stdout: stdout ?? "", stderr: stderr ?? String(err) });
      },
    );
  });

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = async (db: string, sql: string): Promise<string> => {
  const outcome = await runPsqlAsync(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const psqlMustSync = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const lit = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

/* ─── the production SqlExecutor port, backed by real psql connections ─── */

// One psql process per query: a fresh backend, a fresh transaction, and — because the racing
// decisions are launched together — genuine overlap rather than an in-process interleaving
// this file could have staged. PREPARE resolves the statement against the live catalog and
// gives $1/$2 their real column types, so a statement referring to a renamed column or a
// dropped table fails here instead of degrading into a silent zero-row "conflict".
//
// The port hands back rows keyed by column name; a tuples-only psql emits values only, so the
// RETURNING projection is supplied once at construction. Both decision statements return the
// same three columns.
class PsqlExecutor implements SqlExecutor {
  constructor(
    private readonly db: string,
    private readonly returning: readonly string[],
  ) {}

  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const sql =
      `PREPARE zp_decision AS ${text}; EXECUTE zp_decision(${params.map(lit).join(", ")});`;
    const outcome = await runPsqlAsync(this.db, sql);
    if (!outcome.ok) {
      throw new Error(`psql query failed: ${outcome.stderr.trim() || "unknown error"}`);
    }
    const rows = outcome.stdout
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const values = line.split("|");
        return Object.fromEntries(this.returning.map((column, i) => [column, values[i]])) as R;
      });
    return { rows };
  }
}

const DECISION_RETURNING = ["operation_id", "status", "row_version"] as const;

/* ─── real frozen DDL, in prerequisite sequence ───────────────────── */

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

// Custody is prerequisite-bound (base enums/domains + nodes).
const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const CUSTODY_DDL = readSchema("custody-eligibility.sql");
const SEND_DDL = readSchema("send-external-create.sql");

const applyDdl = (db: string, ddl: string, label: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: ddl,
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${label} DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "e1000000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "e1000000-0000-4000-8000-000000000002";
const SIGNING_KEY_ID = "e1000000-0000-4000-8000-000000000003";
const SHA_A = "a".repeat(64);
const DESTINATION = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const AMOUNT = "2.25";
const PREIMAGE_TEXT = "zp-send-external-expected-v1\n{}";
const SIGNATURE = `${"A".repeat(86)}==`;

// public_key is padded_base64url_pubkey; export_sha256 is sha256_hex.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'send-approval-race-pg-approval-race', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

// Recovery is stamped by UPDATE because wallets.recovery_verification_id foreign-keys
// wallet_recovery_verifications, which itself references wallets.
const seedVerifiedWallet = (walletId: string, recoveryId: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${NODE_ID}', '${pubkey(walletId.replace(/-/g, "").slice(0, 8))}', 'node_generated', 'AVAILABLE'); ` +
  `INSERT INTO wallet_recovery_verifications ` +
  `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
  `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA_A}', '${pubkey(walletId.replace(/-/g, "").slice(0, 8))}', ` +
  `'${recoveryId}', now(), 'send-approval-race-pg-test'); ` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
  `WHERE id = '${walletId}';`;

const insertCreatedOperation = (operationId: string, sourceWalletId: string): string =>
  `INSERT INTO send_operations (${OPERATION_COLUMNS.join(", ")}) VALUES (${[
    lit(operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("SEND_EXTERNAL"),
    lit("CREATED"),
    lit(1),
    lit(false),
    lit("APPROVAL_PENDING"),
    lit("POST"),
    lit("/v1/external-sends"),
    lit(`race-${operationId}`),
    lit(SHA_A),
    lit(sourceWalletId),
    lit(DESTINATION),
    lit(AMOUNT),
    lit(null),
    lit(null),
    lit(null),
  ].join(", ")}, now(), 'INDEPENDENT'); ` +
  `INSERT INTO send_operation_expected_artifacts ` +
  `(artifact_id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature) ` +
  `VALUES ('${randomUUID()}', '${operationId}', 'zp-send-external-expected-v1', 1, '${SIGNING_KEY_ID}', ` +
  `'${PREIMAGE_TEXT}', '${SHA_A}', '${SIGNATURE}');`;

/* ─── lifecycle ───────────────────────────────────────────────────── */

const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

const scratchDb = `send_approval_race_pg_approval_race_${Date.now()}_${process.pid}`;
let assertionsRun = 0;

/* ─── per-drill fixture ───────────────────────────────────────────── */

// A fresh wallet per operation: send_operations_one_unsettled_per_source_wallet holds one
// unsettled send per source wallet, so reusing a wallet would have an earlier drill's
// operation reject the next drill's seed for the wrong reason.
const seedOperation = async (): Promise<{ operationId: string; walletId: string }> => {
  const walletId = randomUUID();
  const operationId = randomUUID();
  await psqlMust(scratchDb, seedVerifiedWallet(walletId, randomUUID()));
  await psqlMust(scratchDb, insertCreatedOperation(operationId, walletId));
  return { operationId, walletId };
};

const readOperation = async (
  operationId: string,
): Promise<{ status: string; rowVersion: string; economics: string }> => {
  const row = await psqlMust(
    scratchDb,
    `SELECT status, row_version, source_wallet_id || '|' || destination_address || '|' || ` +
      `amount_zkz || '|' || coalesce(references_operation_id::text, 'null') ` +
      `FROM send_operations WHERE operation_id = '${operationId}';`,
  );
  const [status, rowVersion, ...economics] = row.trim().split("|");
  return { status: status ?? "", rowVersion: rowVersion ?? "", economics: economics.join("|") };
};

const store = (): SqlSendDecisionStore =>
  new SqlSendDecisionStore(new PsqlExecutor(scratchDb, DECISION_RETURNING));

/* ─── suite ───────────────────────────────────────────────────────── */

describeIfPg(
  "approval and rejection races against real PostgreSQL",
  { timeout: 120_000 },
  () => {
    beforeAll(() => {
      psqlMustSync(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
      // prerequisite chain, then custody, then send-external.
      applyDdl(scratchDb, prerequisiteDdl, "base-enums+nodes");
      applyDdl(scratchDb, CUSTODY_DDL, "custody-eligibility");
      applyDdl(scratchDb, SEND_DDL, "send-external-create");
      applyDdl(scratchDb, verificationModeFixtureSql(), "verification-mode");
      psqlMustSync(scratchDb, seedNode());
    }, 60_000);

    afterAll(() => {
      // Scoped teardown: only the database this suite created. The server is shared.
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    });

    it("exactly one of N concurrent approve/reject decisions applies", async () => {
      const { operationId } = await seedOperation();
      const before = await readOperation(operationId);

      // Alternating arms so neither decision can win by being the only contender, all
      // carrying the same expected_row_version and all released together.
      const decisions = Array.from({ length: RACERS }, (_, i) =>
        i % 2 === 0
          ? commitSendApproval({ operationId, expectedRowVersion: 1 }, store())
          : rejectSendOperation({ operationId, expectedRowVersion: 1 }, store()),
      );
      const outcomes = await Promise.all(decisions);

      const applied = outcomes.filter((o) => o.outcome === "APPLIED");
      expect(applied).toHaveLength(1);
      const losers = outcomes.filter((o) => o.outcome === "CONFLICT");
      expect(losers).toHaveLength(RACERS - 1);
      for (const loser of losers) {
        expect(loser).toEqual(SEND_DECISION_CONFLICT);
      }

      const winner = applied[0];
      if (winner?.outcome !== "APPLIED") throw new Error("unreachable");
      const after = await readOperation(operationId);
      // The observed status is the winner's own, whichever arm won — asserted against the
      // outcome the race produced, never against a hardcoded expectation.
      expect(after.status).toBe(winner.status);
      // Exactly one advance: a lost update would leave row_version at 2 with two transitions
      // applied, or above 2 with several.
      expect(after.rowVersion).toBe("2");
      expect(winner.rowVersion).toBe(2);
      // Parent exit criterion, under concurrency: source, destination, amount and
      // reference are byte-identical to their created values.
      expect(after.economics).toBe(before.economics);
      assertionsRun += 1;
    });

    it("a reject racing a committed approval never produces APPROVED to REJECTED", async () => {
      const { operationId } = await seedOperation();
      const approved = await commitSendApproval(
        { operationId, expectedRowVersion: 1 },
        store(),
      );
      expect(approved.outcome).toBe("APPLIED");

      // Both a stale version and the operation's true current version: the status guard, not
      // just the CAS, has to be what stops this.
      const rejects = await Promise.all([
        ...Array.from({ length: RACERS / 2 }, () =>
          rejectSendOperation({ operationId, expectedRowVersion: 1 }, store()),
        ),
        ...Array.from({ length: RACERS / 2 }, () =>
          rejectSendOperation({ operationId, expectedRowVersion: 2 }, store()),
        ),
      ]);
      for (const outcome of rejects) {
        expect(outcome).toEqual(SEND_DECISION_CONFLICT);
      }

      const after = await readOperation(operationId);
      expect(after.status).toBe("APPROVED");
      expect(after.rowVersion).toBe("2");
      assertionsRun += 1;
    });

    it("a stale expected_row_version fails closed on both arms and changes nothing", async () => {
      const { operationId } = await seedOperation();

      expect(await rejectSendOperation({ operationId, expectedRowVersion: 99 }, store())).toEqual(
        SEND_DECISION_CONFLICT,
      );
      expect(await commitSendApproval({ operationId, expectedRowVersion: 99 }, store())).toEqual(
        SEND_DECISION_CONFLICT,
      );

      const after = await readOperation(operationId);
      expect(after.status).toBe("CREATED");
      expect(after.rowVersion).toBe("1");
      assertionsRun += 1;
    });

    it("unknown operation, wrong state and stale version are indistinguishable conflicts", async () => {
      const { operationId } = await seedOperation();
      await commitSendApproval({ operationId, expectedRowVersion: 1 }, store());

      const unknown = await rejectSendOperation(
        { operationId: randomUUID(), expectedRowVersion: 1 },
        store(),
      );
      const wrongState = await rejectSendOperation(
        { operationId, expectedRowVersion: 2 },
        store(),
      );
      const staleVersion = await rejectSendOperation(
        { operationId, expectedRowVersion: 1 },
        store(),
      );

      // signing custody: the operator learns that the decision did not apply and nothing else — no
      // field, no code and no HTTP status separates the three rejection reasons.
      expect(JSON.stringify(unknown)).toBe(JSON.stringify(wrongState));
      expect(JSON.stringify(wrongState)).toBe(JSON.stringify(staleVersion));
      expect(unknown).toEqual(SEND_DECISION_CONFLICT);
      assertionsRun += 1;
    });

    it("a decision carrying an economic change is rejected by the frozen trigger", async () => {
      const { operationId } = await seedOperation();

      // The guarded transition with one economic field smuggled into the same UPDATE. It
      // matches the CAS guard exactly, so the only thing that can stop it is the frozen
      // send_operations_immutable_fields_guard trigger.
      const smuggled = runPsql(
        scratchDb,
        `UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', ` +
          `row_version = row_version + 1, amount_zkz = '9.99' ` +
          `WHERE operation_id = '${operationId}' AND status = 'CREATED' AND row_version = 1;`,
        true,
      );
      expect(smuggled.ok).toBe(false);
      expect(extractSqlstate(smuggled.stderr)).toBe(SQLSTATE_RAISE_EXCEPTION);
      expect(smuggled.stderr).toContain("SEND_IMMUTABLE_FIELD_REJECTED");

      const after = await readOperation(operationId);
      expect(after.status).toBe("CREATED");
      expect(after.economics).toContain(AMOUNT);
      assertionsRun += 1;
    });

    it("a backend killed before COMMIT leaves the operation CREATED and a retry succeeds", async () => {
      const { operationId } = await seedOperation();

      // signing custody "approval pending, no sign intent": the guarded UPDATE runs, then the
      // backend is terminated from inside its own transaction. The write is discarded — there
      // is no half-approved row and no state for a retry to trip over.
      const killed = await runPsqlAsync(
        scratchDb,
        `BEGIN; UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', ` +
          `row_version = row_version + 1 WHERE operation_id = '${operationId}' AND status = 'CREATED' ` +
          `AND row_version = 1; SELECT pg_terminate_backend(pg_backend_pid());`,
      );
      expect(killed.ok).toBe(false);

      const afterCrash = await readOperation(operationId);
      expect(afterCrash.status).toBe("CREATED");
      expect(afterCrash.rowVersion).toBe("1");

      const retry = await commitSendApproval({ operationId, expectedRowVersion: 1 }, store());
      expect(retry).toEqual({ outcome: "APPLIED", status: "APPROVED", rowVersion: 2 });
      assertionsRun += 1;
    });

    it("no source lease exists at any point before or after a pre-approval reject", async () => {
      const { operationId, walletId } = await seedOperation();
      const leaseCount = async (): Promise<string> =>
        (
          await psqlMust(
            scratchDb,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${walletId}';`,
          )
        ).trim();

      // operations recovery: at CREATED there is no source lease and no SplitChain attempt, so reject
      // has nothing to release — and this slice must not create either.
      expect(await leaseCount()).toBe("0");
      const rejected = await rejectSendOperation({ operationId, expectedRowVersion: 1 }, store());
      expect(rejected).toEqual({ outcome: "APPLIED", status: "REJECTED", rowVersion: 2 });
      expect(await leaseCount()).toBe("0");
      assertionsRun += 1;
    });
  },
);

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Outside the gated describe, so it runs even when the suite is skipped. verify-local.sh
 * exports PG_REQUIRED=1 only after its own probe found Postgres reachable, so PG_REQUIRED=1
 * with an unusable maintenance database is a race / broken gate and is a hard failure, never
 * a silent skip. */
it("obligation guard: the real-PG race drills must execute", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: ` +
          "the approval/rejection race drills could not run and must not silently skip. " +
          "The outer runner exports PG_REQUIRED=1 only after seeing a reachable Postgres, so this " +
          "is a race / broken gate — provision the maintenance database and re-run.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the race drills did not run — undischarged obligation",
  ).toBe(EXPECTED_DRILL_COUNT);
});
