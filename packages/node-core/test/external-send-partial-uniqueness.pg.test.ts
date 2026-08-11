// DB-TEST-11: node code cannot create any submit attempt for SEND_EXTERNAL
/**
 * Governing (mandatory database test 11 / DB-TEST-11): node code cannot create any
 * submit attempt for SEND_EXTERNAL — the SEND path has no node submit function; this
 * suite proves the schema side of that rule (one partial / no second attempt under the
 * same approval) against live PostgreSQL.
 *
 * external-send-partial-uniqueness.pg.test.ts
 *
 * "no second external partial", proven against a REAL PostgreSQL database
 * rather than against an in-process double. "One approval authorizes one exact persisted
 * external partial... it never permits a second partial under the old approval." restates
 * it for the SEND expiry case. the recovery rules rate a second signed partial a P0
 * incident, so the invariant is proven here at the only layer that cannot be bypassed by a
 * mis-ordered caller: the constraint.
 *
 * What is real and what is a stub:
 *   - The tables UNDER TEST — external_send_partials, external_send_sign_intents,
 *     operation_transactions — are the frozen bytes of src/schema/transaction-material.sql,
 *     applied verbatim via psql -f. No constraint is hand-redeclared or mirrored.
 *   - Their FK PARENTS are minimal self-owned stubs (wallets/operations/operation_approvals,
 *     id-only). transaction-material.sql references wallets(id) while the frozen custody DDL
 *     spells it wallets(wallet_id) — a documented reconciliation gap (see
 *     migration-integrity.test.ts), and operations/operation_approvals have no frozen schema
 *     file at all. observation-anomaly-indexes.pg.test.ts sets the precedent: an id-only stub
 *     parent is the correct isolation for a slice whose proof lives entirely in the child.
 *
 * Scope, stated plainly (FAIL on, `tasks/reviews/-.md`):
 * this file discharges the DB-constraint and real-contention legs. It does NOT
 * race the SEND attention/reconciliation state machine, because and
 * have not landed — there is no REDELIVER_EXACT_PARTIAL, no late-landing loop and no
 * boot-recovery pass to race. The state-machine interleavings and the code-path
 * reachability assertion remain open. Nothing here asserts they are proven.
 *
 * Already proven elsewhere, deliberately not rebuilt here: concurrent lease acquisition yielding
 * exactly one holder, and concurrent same-Idempotency-Key operation INSERTs yielding exactly one
 * row, are real-PG proofs in test/pg-concurrency.test.ts.
 *
 * lease_epoch: the frozen wallet_active_leases (custody-eligibility.sql) carries no lease_epoch
 * column, so "same lease_epoch throughout" is asserted where the epoch actually
 * lives — external_send_sign_intents.lease_epoch / lease_group_id — across the contention drill.
 *
 * Byte-immutability of external_send_partials is enforced by the append-only pack slice
 * transaction-material-byte-immutability.sql (ZTR-1138). This suite still applies only
 * transaction-material.sql (constraint half). Live trigger reject is proven in
 * transaction-material-byte-immutability.pg.test.ts. Drill (i) still applies the guards
 * slice and asserts signed-byte UPDATE is rejected.
 *
 * PG_REQUIRED race guard mirrors custody-eligibility-lease-pk.test.ts: PG_REQUIRED=1 is exported
 * by verify-local.sh only after its own pg_isready probe found Postgres reachable, so within this
 * process it means "the outer runner confirmed PG was up," never "PG is optional." The
 * fail-closed guard at the bottom turns an undischarged obligation into a hard FAILURE.
 */
import { execFile, execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";

// The Postgres instance is shared between concurrent build lanes and CREATE/DROP DATABASE
// serialize on the template database. Measured at 8 s for a single CREATE under load here, so
// the per-statement ceiling is generous: a killed psql surfaces as an empty-stderr setup failure,
// which reads as a broken assertion when it is really contention.
const PSQL_TIMEOUT_MS = 90_000;

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const psqlArgs = (db: string, sql: string, verbose: boolean): readonly string[] => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  return args;
};

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", [...psqlArgs(db, sql, verbose)], {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      // The drills provoke intentional constraint violations; their psql ERROR output is
      // asserted on, not console noise.
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

// Async form — used ONLY by the contention drill, where the whole point is that N separate
// backends are in flight at the same instant. execFileSync cannot express that.
const runPsqlAsync = (db: string, sql: string): Promise<PsqlOutcome> =>
  new Promise((resolvePromise) => {
    execFile(
      "psql",
      [...psqlArgs(db, sql, true)],
      { encoding: "utf-8", timeout: PSQL_TIMEOUT_MS },
      (err, stdout, stderr) => {
        resolvePromise(
          err === null
            ? { ok: true, stdout, stderr }
            : { ok: false, stdout: stdout ?? "", stderr: stderr ?? String(err) },
        );
      },
    );
  });

// Setup/seed statements MUST succeed. A failure here is a real error and is thrown, never
// swallowed — swallowed setup is what makes a real-PG suite silently prove nothing.
const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)], {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};
const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── FK-target stubs (see header) ────────────────────────────────── */

const PARENT_STUBS = [
  "CREATE TABLE wallets (id uuid PRIMARY KEY);",
  "CREATE TABLE operations (id uuid PRIMARY KEY);",
  "CREATE TABLE operation_approvals (id uuid PRIMARY KEY);",
].join(" ");

/* ─── fixtures — values built to satisfy the frozen domains exactly ─── */

// sha256_hex is CHECK (VALUE ~ '^[0-9a-f]{64}$'); decimal digits are inside that class.
const sha256 = (seed: number): string => String(seed).padStart(64, "0");
// padded_base64url_signature is CHECK (length = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$').
const signature = (seed: number): string => `${String(seed).padStart(86, "A")}==`;

const WALLET = "a0000000-0000-4000-8000-000000000001";
const OP_1 = "0e000000-0000-4000-8000-000000000001";
const OP_2 = "0e000000-0000-4000-8000-000000000002";
const OP_RACE = "0e000000-0000-4000-8000-000000000003";
const OP_TX = "0e000000-0000-4000-8000-000000000004";
const OP_MUT = "0e000000-0000-4000-8000-000000000005";
const APPROVAL_1 = "aa000000-0000-4000-8000-000000000001";
const APPROVAL_2 = "aa000000-0000-4000-8000-000000000002";
const APPROVAL_RACE = "aa000000-0000-4000-8000-000000000003";
const APPROVAL_MUT = "aa000000-0000-4000-8000-000000000005";

const LEASE_GROUP = "1ea50000-0000-4000-8000-000000000001";
const LEASE_EPOCH = 7;

const insertPartial = (operationId: string, approvalId: string, seed: number): string =>
  `INSERT INTO external_send_partials (operation_id, approval_id, inner_sha256, ` +
  `step_1_signature, transfer_code_text, transfer_code_sha256, persisted_at) VALUES (` +
  `'${operationId}', '${approvalId}', '${sha256(seed)}', '${signature(seed)}', ` +
  `'transfer-code-${seed}', '${sha256(seed)}', now());`;

const insertSignIntent = (operationId: string, approvalId: string, seed: number): string =>
  `INSERT INTO external_send_sign_intents (operation_id, approval_id, source_wallet_id, ` +
  `source_t0_observation_id, destination_t0_observation_id, lease_group_id, lease_epoch, ` +
  `inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at) VALUES (` +
  `'${operationId}', '${approvalId}', '${WALLET}', gen_random_uuid(), gen_random_uuid(), ` +
  `'${LEASE_GROUP}', ${LEASE_EPOCH}, 'inner-preimage-${seed}', '${sha256(seed)}', ` +
  `now() + interval '1 hour', now());`;

const insertAttempt = (operationId: string, attemptNo: number, seed: number): string =>
  `INSERT INTO operation_transactions (operation_id, attempt_no, attempt_phase, ` +
  `inner_preimage_text, inner_sha256, formed_at) VALUES (` +
  `'${operationId}', ${attemptNo}, 'INNER_PREIMAGE_PERSISTED', 'inner-${seed}', ` +
  `'${sha256(seed)}', now());`;

/* ─── suite ───────────────────────────────────────────────────────── */

let assertionsRun = 0;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg(
  "no second external partial — real frozen DDL, hermetic scratch DB",
  // Never shorter than PSQL_TIMEOUT_MS: a test budget below the psql budget it awaits reports
  // contention as an assertion failure. Same reasoning as this package's vitest.config.ts
  // testTimeout/hookTimeout comment.
  { timeout: PSQL_TIMEOUT_MS + 30_000 },
  () => {
    const scratchDb = `no_second_external_no2ndpartial_${Date.now()}_${process.pid}`;

    // 180 s: CREATE DATABASE alone measured at 8 s under lane contention, and the DDL apply
    // plus seed follow it in the same hook. vitest's 10 s hook default would kill it mid-setup.
    beforeAll(() => {
      psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
      psqlMust(scratchDb, PARENT_STUBS);
      applyFile(scratchDb, "transaction-material.sql");
      psqlMust(
        scratchDb,
        `INSERT INTO wallets (id) VALUES ('${WALLET}'); ` +
          `INSERT INTO operations (id) VALUES ('${OP_1}'),('${OP_2}'),('${OP_RACE}'),` +
          `('${OP_TX}'),('${OP_MUT}'); ` +
          `INSERT INTO operation_approvals (id) VALUES ('${APPROVAL_1}'),('${APPROVAL_2}'),` +
          `('${APPROVAL_RACE}'),('${APPROVAL_MUT}');`,
      );
    }, PSQL_TIMEOUT_MS + 90_000);

    // Teardown is scoped to exactly the one database this run created — the Postgres instance
    // is shared with concurrent lanes and must never be swept broadly. It is also NON-throwing
    // (pg-concurrency.test.ts's pattern): DROP DATABASE queues behind every other lane's
    // CREATE/DROP on the template lock, so a slow drop is contention, not a failed proof, and
    // must not turn nine green drills red. Exactly ONE attempt: two would exceed the hook
    // budget below and time the hook out, which is the same false red by another route.
    afterAll(() => {
      const drop = runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
      if (!drop.ok) {
        console.warn(
          `scratch database ${scratchDb} could not be dropped (shared-instance ` +
            "contention); drop it manually",
        );
      }
    }, PSQL_TIMEOUT_MS + 30_000);

    it("(a) the frozen transaction-material DDL applied: tables and the two uniqueness constraints exist", () => {
      const tables = psqlMust(
        scratchDb,
        `SELECT string_agg(c, ',' ORDER BY c) FROM unnest(ARRAY[` +
          `to_regclass('public.external_send_partials')::text,` +
          `to_regclass('public.external_send_sign_intents')::text,` +
          `to_regclass('public.operation_transactions')::text]) AS c;`,
      );
      expect(tables.trim()).toBe(
        "external_send_partials,external_send_sign_intents,operation_transactions",
      );

      // The constraints the whole invariant rests on must exist as real indexes, not as prose.
      const constraints = psqlMust(
        scratchDb,
        `SELECT string_agg(conname, ',' ORDER BY conname) FROM pg_constraint WHERE conname IN (` +
          `'external_send_partials_pkey','external_send_partials_approval_id_key',` +
          `'external_send_sign_intents_pkey','external_send_sign_intents_approval_id_key',` +
          `'operation_transactions_pkey');`,
      );
      expect(constraints.trim()).toBe(
        "external_send_partials_approval_id_key,external_send_partials_pkey," +
          "external_send_sign_intents_approval_id_key,external_send_sign_intents_pkey," +
          "operation_transactions_pkey",
      );
      assertionsRun += 1;
    });

    it("(b) a deliberately-forced second external_send_partials INSERT for an existing operation_id is rejected (23505)", () => {
      psqlMust(scratchDb, insertPartial(OP_1, APPROVAL_1, 1));

      // Different approval, different bytes — the ONLY thing shared is operation_id, so the
      // PRIMARY KEY is the sole possible rejector.
      const second = runPsql(scratchDb, insertPartial(OP_1, APPROVAL_2, 2), true);

      expect(second.ok, "a second partial for one operation must be rejected").toBe(false);
      expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractConstraint(second.stderr)).toBe("external_send_partials_pkey");

      const surviving = psqlMust(
        scratchDb,
        `SELECT count(*)||'|'||max(inner_sha256)||'|'||max(step_1_signature) ` +
          `FROM external_send_partials WHERE operation_id = '${OP_1}';`,
      );
      expect(surviving.trim()).toBe(`1|${sha256(1)}|${signature(1)}`);
      assertionsRun += 1;
    });

    it("(c) the same approval can never authorize a second partial on another operation (23505)", () => {
      // OP_2 is a genuinely different operation reusing OP_1's already-consumed approval.
      const reuse = runPsql(scratchDb, insertPartial(OP_2, APPROVAL_1, 3), true);

      expect(reuse.ok, "an approval already bound to a partial must not bind a second").toBe(false);
      expect(extractSqlstate(reuse.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractConstraint(reuse.stderr)).toBe("external_send_partials_approval_id_key");
      assertionsRun += 1;
    });

    it("(d) a second external_send_sign_intents row for one operation_id is rejected (23505)", () => {
      psqlMust(scratchDb, insertSignIntent(OP_1, APPROVAL_1, 1));

      const second = runPsql(scratchDb, insertSignIntent(OP_1, APPROVAL_2, 4), true);

      expect(second.ok, "a second sign intent for one operation must be rejected").toBe(false);
      expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractConstraint(second.stderr)).toBe("external_send_sign_intents_pkey");
      assertionsRun += 1;
    });

    it("(e) a second external_send_sign_intents row reusing a consumed approval_id is rejected (23505)", () => {
      const reuse = runPsql(scratchDb, insertSignIntent(OP_2, APPROVAL_1, 5), true);

      expect(reuse.ok, "a consumed approval must not sign a second inner preimage").toBe(false);
      expect(extractSqlstate(reuse.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractConstraint(reuse.stderr)).toBe("external_send_sign_intents_approval_id_key");

      // The property, read straight off the database: one operation, one preimage.
      const distinctPreimages = psqlMust(
        scratchDb,
        `SELECT count(DISTINCT inner_sha256) FROM external_send_sign_intents ` +
          `WHERE operation_id = '${OP_1}';`,
      );
      expect(distinctPreimages.trim()).toBe("1");
      assertionsRun += 1;
    });

    it("(f) the one-in-flight-per-wallet rule under real contention: N concurrent backends racing one operation_id leave exactly one partial, bytes undivided", async () => {
      psqlMust(scratchDb, insertSignIntent(OP_RACE, APPROVAL_RACE, 10));
      const epochBefore = psqlMust(
        scratchDb,
        `SELECT lease_epoch||'|'||lease_group_id FROM external_send_sign_intents ` +
          `WHERE operation_id = '${OP_RACE}';`,
      );

      // Every racer carries DIFFERENT bytes. If two ever committed, the surviving-row assertion
      // below would see bytes from more than one racer — the divergence this suite forbids.
      const N = 8;
      const racers = Array.from({ length: N }, (_, i) =>
        runPsqlAsync(
          scratchDb,
          `BEGIN; ${insertPartial(OP_RACE, APPROVAL_RACE, 100 + i)} COMMIT;`,
        ),
      );
      const results = await Promise.all(racers);

      const winners = results.filter((r) => r.ok);
      const losers = results.filter((r) => !r.ok);
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(N - 1);
      for (const loser of losers) {
        expect(extractSqlstate(loser.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      }

      // Exactly one row, and its bytes are one racer's — internally consistent, not a blend.
      const row = psqlMust(
        scratchDb,
        `SELECT count(*)||'|'||max(inner_sha256)||'|'||max(step_1_signature)||'|'||` +
          `max(transfer_code_text) FROM external_send_partials WHERE operation_id = '${OP_RACE}';`,
      ).trim();
      const [count, innerSha, sig, transferCode] = row.split("|");
      expect(count).toBe("1");
      const seed = Number(innerSha);
      expect(seed).toBeGreaterThanOrEqual(100);
      expect(seed).toBeLessThan(100 + N);
      expect(sig).toBe(signature(seed));
      expect(transferCode).toBe(`transfer-code-${seed}`);

      // The lease the partial was formed under is untouched by the losing contenders.
      expect(
        psqlMust(
          scratchDb,
          `SELECT lease_epoch||'|'||lease_group_id FROM external_send_sign_intents ` +
            `WHERE operation_id = '${OP_RACE}';`,
        ),
      ).toBe(epochBefore);
      assertionsRun += 1;
    });

    it("(g) new-create race: a new operation proceeds only under its own approval and never disturbs the original partial", () => {
      const before = psqlMust(
        scratchDb,
        `SELECT inner_sha256||'|'||step_1_signature||'|'||transfer_code_sha256 ` +
          `FROM external_send_partials WHERE operation_id = '${OP_1}';`,
      );

      // "new operation, new approval": with its OWN approval the new operation forms fine.
      const independent = runPsql(scratchDb, insertPartial(OP_2, APPROVAL_2, 20));
      expect(independent.ok, independent.stderr).toBe(true);

      // ...and the original's signed bytes are byte-identical afterwards.
      expect(
        psqlMust(
          scratchDb,
          `SELECT inner_sha256||'|'||step_1_signature||'|'||transfer_code_sha256 ` +
            `FROM external_send_partials WHERE operation_id = '${OP_1}';`,
        ),
      ).toBe(before);

      // Across the whole database: one partial per operation, one operation per approval.
      const fanout = psqlMust(
        scratchDb,
        `SELECT coalesce(max(n),0) FROM (SELECT count(*) AS n FROM external_send_partials ` +
          `GROUP BY approval_id) s;`,
      );
      expect(fanout.trim()).toBe("1");
      assertionsRun += 1;
    });

    it("(h) operation_transactions structurally forbids a second attempt row, both ways (23505 / 23514)", () => {
      psqlMust(scratchDb, insertAttempt(OP_TX, 1, 30));

      const duplicate = runPsql(scratchDb, insertAttempt(OP_TX, 1, 31), true);
      expect(duplicate.ok, "a second attempt_no=1 row must be rejected").toBe(false);
      expect(extractSqlstate(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(extractConstraint(duplicate.stderr)).toBe("operation_transactions_pkey");

      const secondAttempt = runPsql(scratchDb, insertAttempt(OP_TX, 2, 32), true);
      expect(secondAttempt.ok, "attempt_no=2 must be rejected by the CHECK").toBe(false);
      expect(extractSqlstate(secondAttempt.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
      expect(extractConstraint(secondAttempt.stderr)).toBe(
        "operation_transactions_attempt_no_check",
      );
      assertionsRun += 1;
    });

    it("(i) byte-immutability trigger rejects signed-byte UPDATE on external_send_partials", () => {
      psqlMust(scratchDb, insertPartial(OP_MUT, APPROVAL_MUT, 40));
      // Tables already applied in beforeAll; attach the append-only guards slice once here.
      applyFile(scratchDb, "transaction-material-byte-immutability.sql");

      const mutate = runPsql(
        scratchDb,
        `UPDATE external_send_partials SET inner_sha256 = '${sha256(41)}' ` +
          `WHERE operation_id = '${OP_MUT}';`,
      );
      expect(mutate.ok).toBe(false);
      expect(mutate.stderr).toContain("EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE");
      assertionsRun += 1;
    });
  },
);

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level (OUTSIDE the pg-gated describe) so it runs even when the suite is skipped, mirroring
 * custody-eligibility-lease-pk.test.ts. PG unusable under PG_REQUIRED=1 is a broken gate, not an
 * absent Postgres, and fails hard; PG usable but drills not all run is an undischarged
 * obligation and fails hard. The suite can never report green having proven nothing. */
const EXPECTED_DRILLS = 9;

it("obligation guard: real-PG no-second-partial drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "the real-PG no-second-external-partial proof could not run and the local " +
          "verification lane must not silently skip a one-in-flight-per-wallet invariant.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG no-second-partial drills did not all run",
  ).toBe(EXPECTED_DRILLS);
});
