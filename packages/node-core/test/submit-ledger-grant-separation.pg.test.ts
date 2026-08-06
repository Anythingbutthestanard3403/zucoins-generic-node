// follow-up — real-PostgreSQL proof of the STRUCTURAL defence against
// raw-SQL writes to the two submit ledgers.
//
// Governing: signing custody
// ("SEND_EXTERNAL has no node submit function in its type graph"); the data model
// (submit_decisions / gateway_submit_attempts); the never-blind-retry rule (never blind-retry a submit).
//
// WHY THIS EXISTS AND WHY IT IS NOT A SOURCE SCAN. test/submit-write-path.guard.test.ts
// catches a module that NAMES either ledger in its text. A table name is launderable through
// base64, hex, String.fromCharCode, template concatenation or unicode escapes, and no text
// scan closes under all of them — each new decoder buys the demonstrated encoding and invites
// the next. PostgreSQL resolves a privilege against the table OID at execution, after every
// encoding has already been undone by the parser, so the grant below is closed under the whole
// family by construction. That is the difference between this file and the guard test.
//
// The proof is a paired control: the SAME statement, with the SAME data, run once as
// node_core_send (must be refused, SQLSTATE 42501) and once as node_core_app (must succeed).
// The positive half is what keeps MOVE_INTERNAL's and RECEIVE's submit paths honest — a
// refusal that came from bad fixture data rather than from the grant would fail it too.
// The DELETE/TRUNCATE half pairs against the database owner instead: denies node_core_app
// those two verbs as well, so it cannot serve as the positive control there.
//
// node-core links no database driver, so every statement goes through a psql
// subprocess. Each run gets its own disposable database; roles are cluster-wide and are never
// dropped (other databases may hold grants to them).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  assertPrivilegeReadiness,
  NODE_CORE_APP_ROLE,
  NODE_CORE_SEND_ROLE,
  PrivilegeReadinessError,
  SUBMIT_LEDGER_TABLES,
  type PrivilegeSqlExecutor,
} from "../src/data/privilege-readiness.ts";
import { PRIVILEGES_SCHEMA_FILE } from "../src/schema/privileges.contract.ts";
import { SUBMIT_ATTEMPTS_SCHEMA_FILE } from "../src/schema/submit-attempts.contract.ts";

import { extractSqlstate, psqlMust, runPsql, withDatabase } from "./psql-harness.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const privilegesSql = readFileSync(resolve(schemaDir, PRIVILEGES_SCHEMA_FILE), "utf8");
const submitAttemptsSql = readFileSync(resolve(schemaDir, SUBMIT_ATTEMPTS_SCHEMA_FILE), "utf8");

const baseUrl = process.env.TEST_DATABASE_URL;
const INSUFFICIENT_PRIVILEGE = "42501";

// The frozen submit ledgers reference operations(id) and operation_transactions(operation_id,
// attempt_no). Their full shapes drag in the wallets/implementers/observers closures and prove
// nothing about a grant, so the FK targets are reduced to the columns these two FKs bind.
const FK_TARGET_STUBS = `
CREATE TABLE operations (id uuid PRIMARY KEY);
CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL,
  UNIQUE (operation_id, attempt_no)
);`;

// submit_decisions carries UNIQUE (operation_id, transaction_attempt_no) and CHECK
// (transaction_attempt_no = 1), so each write that is EXPECTED to land needs its own
// operation. Writes that are expected to be refused all reuse OP_REFUSED: a permission error
// is raised before any row work, so they never reach the constraint.
const OP_REFUSED = "5f2f8f2e-0000-4000-8000-000000000001";
const OP_APP_CONTROL = "5f2f8f2e-0000-4000-8000-000000000002";
const OP_MUTATION = "5f2f8f2e-0000-4000-8000-000000000003";
const OPERATIONS = [OP_REFUSED, OP_APP_CONTROL, OP_MUTATION] as const;
const SHA = "a".repeat(64);

let db: string | null = null;
let dbUrl = "";
let ready = false;

/** One INSERT into submit_decisions. Valid data in every run — only the grant can refuse it. */
const decisionInsert = (id: string, operationId: string): string =>
  `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details)` +
  ` VALUES ('${id}', '${operationId}', 1, 'INITIAL_SINGLE_SHOT', now(), 'submit-ledger-grant proof');`;

/** One INSERT into gateway_submit_attempts bound to an existing decision row. */
const attemptInsert = (id: string, operationId: string, decisionId: string): string =>
  `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, transaction_attempt_no,` +
  ` decision_id, request_body, request_sha256, transport_outcome, started_at)` +
  ` VALUES ('${id}', '${operationId}', 1, 1, '${decisionId}',` +
  ` '\\x00'::bytea, '${SHA}', 'ACK', now());`;

/** Runs `sql` in a session that has assumed `role`. One psql process = one session. */
const asRole = (role: string, sql: string) => runPsql(dbUrl, `SET ROLE ${role}; ${sql}`);

// A DELETE whose WHERE matches no row. Postgres checks the table privilege while planning, so
// the refusal cannot come from the data — and the owner-run control below destroys no fixture.
const NO_SUCH_ROW = "5f2f8f2e-0000-4000-8000-0000000000d0";
const deleteNoMatch = (table: string): string =>
  `DELETE FROM ${table} WHERE id = '${NO_SUCH_ROW}';`;

/**
 * PrivilegeSqlExecutor over psql for the disposable database, so the boot gate itself is
 * exercised against the same live grants. Params are identifiers only ([A-Za-z0-9_]+), checked
 * before substitution — this executor never sees untrusted input.
 */
function psqlExecutor(): PrivilegeSqlExecutor {
  return {
    async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
      let sql = text;
      // Back-to-front so $10 is not partially eaten by $1.
      for (let n = params.length; n >= 1; n -= 1) {
        const value = params[n - 1];
        if (typeof value !== "string" || !/^[A-Za-z0-9_]+$/.test(value)) {
          throw new Error(`refusing non-identifier param $${n}: ${String(value)}`);
        }
        sql = sql.replaceAll(`$${n}`, `'${value}'`);
      }
      const raw = psqlMust(
        dbUrl,
        `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json) FROM (${sql}) q`,
      ).trim();
      const rows = JSON.parse(raw === "" ? "[]" : raw) as R[];
      return { rows: Array.isArray(rows) ? rows : [] };
    },
  };
}

describe.skipIf(baseUrl === undefined)(
  "submit-ledger grant separation (real Postgres)",
  () => {
    beforeAll(() => {
      const maintenance = withDatabase(baseUrl as string, "postgres");
      if (!runPsql(maintenance, "SELECT 1").ok) return;

      db = `submit_ledger_grant_grants_${Date.now()}`;
      psqlMust(maintenance, `CREATE DATABASE "${db}"`);
      dbUrl = withDatabase(baseUrl as string, db);

      // 1. privileges.sql before the DDL — the ordering that leaves the ledger REVOKEs as
      //    to_regclass no-ops, i.e. the fail-open case the boot gate is there to catch.
      psqlMust(dbUrl, privilegesSql);
      const rolesExist =
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM pg_roles WHERE rolname IN ('${NODE_CORE_APP_ROLE}', '${NODE_CORE_SEND_ROLE}')`,
        ).trim() === "2";
      // No CREATEROLE on this connection: privileges.sql degraded to NOTICE by design. The
      // unit suite still covers the refusal branches; there is nothing to prove here.
      if (!rolesExist) return;

      // Membership so a non-superuser creator can SET ROLE. A superuser needs neither and the
      // grant is harmless; failure here is not fatal, the SET ROLE below reports it.
      runPsql(dbUrl, `GRANT ${NODE_CORE_APP_ROLE}, ${NODE_CORE_SEND_ROLE} TO CURRENT_USER`);

      // 2. the frozen ledger DDL, on reduced FK targets.
      psqlMust(dbUrl, FK_TARGET_STUBS);
      psqlMust(dbUrl, submitAttemptsSql);
      for (const operationId of OPERATIONS) {
        psqlMust(
          dbUrl,
          `INSERT INTO operations (id) VALUES ('${operationId}');` +
            ` INSERT INTO operation_transactions (operation_id, attempt_no) VALUES ('${operationId}', 1);`,
        );
      }

      // 3. re-apply privileges.sql — the documented ops path. The tables now exist, so this
      //    time the REVOKEs attach. Idempotent: this is the second apply of the same file.
      psqlMust(dbUrl, privilegesSql);
      // Tables created after the first apply inherit node_core_app's grants only via ALTER
      // DEFAULT PRIVILEGES, which does not attach when the creating role differs; grant the
      // positive control explicitly so a refusal cannot be mistaken for a missing grant.
      psqlMust(
        dbUrl,
        `GRANT SELECT, INSERT, UPDATE ON submit_decisions, gateway_submit_attempts TO ${NODE_CORE_APP_ROLE}`,
      );
      ready = true;
    });

    afterAll(() => {
      if (db === null) return;
      const maintenance = withDatabase(baseUrl as string, "postgres");
      runPsql(maintenance, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    });

    it("refuses a SEND-path INSERT into submit_decisions with SQLSTATE 42501", (ctx) => {
      if (!ready) ctx.skip();
      const refused = asRole(
        NODE_CORE_SEND_ROLE,
        decisionInsert("5f2f8f2e-0000-4000-8000-0000000000a1", OP_REFUSED),
      );
      expect(refused.ok, "the SEND role must not be able to write submit_decisions").toBe(false);
      expect(extractSqlstate(refused.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
      expect(psqlMust(dbUrl, "SELECT count(*) FROM submit_decisions").trim()).toBe("0");
    });

    it("refuses a SEND-path UPDATE of submit_decisions with SQLSTATE 42501", (ctx) => {
      if (!ready) ctx.skip();
      const refused = asRole(
        NODE_CORE_SEND_ROLE,
        "UPDATE submit_decisions SET details = 'rewritten';",
      );
      expect(refused.ok).toBe(false);
      expect(extractSqlstate(refused.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
    });

    it("allows the MOVE_INTERNAL/RECEIVE role the same write (positive control)", (ctx) => {
      if (!ready) ctx.skip();
      const allowed = asRole(
        NODE_CORE_APP_ROLE,
        decisionInsert("5f2f8f2e-0000-4000-8000-0000000000b1", OP_APP_CONTROL),
      );
      expect(allowed.ok, allowed.stderr).toBe(true);
      expect(psqlMust(dbUrl, "SELECT count(*) FROM submit_decisions").trim()).toBe("1");
    });

    it("refuses a SEND-path INSERT into gateway_submit_attempts, allows the app role", (ctx) => {
      if (!ready) ctx.skip();
      // Bound to the decision row the positive control above landed, so the only thing that
      // can refuse either statement is the grant.
      const decisionId = "5f2f8f2e-0000-4000-8000-0000000000b1";
      const refused = asRole(
        NODE_CORE_SEND_ROLE,
        attemptInsert("5f2f8f2e-0000-4000-8000-0000000000a2", OP_APP_CONTROL, decisionId),
      );
      expect(refused.ok, "the SEND role must not be able to write the attempt ledger").toBe(false);
      expect(extractSqlstate(refused.stderr)).toBe(INSUFFICIENT_PRIVILEGE);

      const allowed = asRole(
        NODE_CORE_APP_ROLE,
        attemptInsert("5f2f8f2e-0000-4000-8000-0000000000b2", OP_APP_CONTROL, decisionId),
      );
      expect(allowed.ok, allowed.stderr).toBe(true);
    });

    // The negative control: remove the defence and the refusals above stop
    // holding. If this test ever passes with the REVOKE still in place, the three assertions
    // above were proving something other than the grant.
    it("mutation: re-granting INSERT to the SEND role makes the refused write succeed", (ctx) => {
      if (!ready) ctx.skip();
      psqlMust(dbUrl, `GRANT INSERT ON submit_decisions TO ${NODE_CORE_SEND_ROLE}`);
      const nowAllowed = asRole(
        NODE_CORE_SEND_ROLE,
        decisionInsert("5f2f8f2e-0000-4000-8000-0000000000c1", OP_MUTATION),
      );
      // Restore the defence BEFORE asserting, so a failure here cannot leak the mutation into
      // the boot-gate test below.
      psqlMust(dbUrl, `REVOKE INSERT ON submit_decisions FROM ${NODE_CORE_SEND_ROLE}`);
      expect(nowAllowed.ok, nowAllowed.stderr).toBe(true);

      const refusedAgain = asRole(
        NODE_CORE_SEND_ROLE,
        decisionInsert("5f2f8f2e-0000-4000-8000-0000000000c2", OP_REFUSED),
      );
      expect(refusedAgain.ok).toBe(false);
      expect(extractSqlstate(refusedAgain.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
    });

    // INSERT/UPDATE is only half the subtraction. A role that cannot write a submit decision
    // but CAN delete or truncate the ledger destroys the same record by another verb, and
    // the never-blind-retry rule's reconcile reads the ledger to decide whether a submit already happened.
    // privileges.sql revokes DELETE/TRUNCATE from node_core_send on every public table; these
    // two tests are the runtime proof of that half, and the two mutations below are its
    // falsification.
    it("refuses a SEND-path DELETE from either submit ledger with SQLSTATE 42501", (ctx) => {
      if (!ready) ctx.skip();
      for (const table of SUBMIT_LEDGER_TABLES) {
        const refused = asRole(NODE_CORE_SEND_ROLE, deleteNoMatch(table));
        expect(refused.ok, `the SEND role must not be able to DELETE ${table}`).toBe(false);
        expect(extractSqlstate(refused.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
        // Control: the identical statement run by the database owner succeeds (0 rows), so
        // what refused the SEND role is the grant, not the statement. node_core_app is NOT the
        // control here — denies it DELETE too, deliberately.
        psqlMust(dbUrl, deleteNoMatch(table));
      }
    });

    it("refuses a SEND-path TRUNCATE of either submit ledger with SQLSTATE 42501", (ctx) => {
      if (!ready) ctx.skip();
      const decisionsBefore = psqlMust(dbUrl, "SELECT count(*) FROM submit_decisions").trim();
      for (const table of SUBMIT_LEDGER_TABLES) {
        const refused = asRole(NODE_CORE_SEND_ROLE, `TRUNCATE ${table};`);
        expect(refused.ok, `the SEND role must not be able to TRUNCATE ${table}`).toBe(false);
        expect(extractSqlstate(refused.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
      }
      // Nothing was truncated. The privilege is checked before the FK-dependency check, so
      // submit_decisions is refused 42501 rather than "referenced in a foreign key constraint" —
      // a refusal that came from the FK graph instead of the grant would show a different state.
      expect(psqlMust(dbUrl, "SELECT count(*) FROM submit_decisions").trim()).toBe(decisionsBefore);
      expect(Number(decisionsBefore)).toBeGreaterThan(0);
    });

    it("mutation: re-granting DELETE to the SEND role lets the delete through and refuses boot", async (ctx) => {
      if (!ready) ctx.skip();
      psqlMust(dbUrl, `GRANT DELETE ON submit_decisions TO ${NODE_CORE_SEND_ROLE}`);
      const nowAllowed = asRole(NODE_CORE_SEND_ROLE, deleteNoMatch("submit_decisions"));
      const bootDuring = await assertPrivilegeReadiness(psqlExecutor()).then(
        () => null,
        (err: unknown) => err as Error,
      );
      // Restore before asserting so a failure cannot leak the mutation into later tests.
      psqlMust(dbUrl, `REVOKE DELETE ON submit_decisions FROM ${NODE_CORE_SEND_ROLE}`);

      expect(nowAllowed.ok, nowAllowed.stderr).toBe(true);
      expect(bootDuring).toBeInstanceOf(PrivilegeReadinessError);
      expect(bootDuring?.message).toMatch(/"node_core_send" holds revoked privileges/);
      expect(bootDuring?.message).toMatch(/submit_decisions \(DELETE\)/);

      const refusedAgain = asRole(NODE_CORE_SEND_ROLE, deleteNoMatch("submit_decisions"));
      expect(refusedAgain.ok).toBe(false);
      expect(extractSqlstate(refusedAgain.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
      await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();
    });

    it("mutation: re-granting TRUNCATE to the SEND role lets the truncate through and refuses boot", async (ctx) => {
      if (!ready) ctx.skip();
      // gateway_submit_attempts, not submit_decisions: nothing references it, so a permitted
      // TRUNCATE actually runs instead of stopping on the FK dependency error, which would
      // make the mutation prove nothing about the grant.
      psqlMust(dbUrl, `GRANT TRUNCATE ON gateway_submit_attempts TO ${NODE_CORE_SEND_ROLE}`);
      const nowAllowed = asRole(NODE_CORE_SEND_ROLE, "TRUNCATE gateway_submit_attempts;");
      const bootDuring = await assertPrivilegeReadiness(psqlExecutor()).then(
        () => null,
        (err: unknown) => err as Error,
      );
      psqlMust(dbUrl, `REVOKE TRUNCATE ON gateway_submit_attempts FROM ${NODE_CORE_SEND_ROLE}`);

      expect(nowAllowed.ok, nowAllowed.stderr).toBe(true);
      expect(bootDuring).toBeInstanceOf(PrivilegeReadinessError);
      expect(bootDuring?.message).toMatch(/gateway_submit_attempts \(TRUNCATE\)/);

      const refusedAgain = asRole(NODE_CORE_SEND_ROLE, "TRUNCATE gateway_submit_attempts;");
      expect(refusedAgain.ok).toBe(false);
      expect(extractSqlstate(refusedAgain.stderr)).toBe(INSUFFICIENT_PRIVILEGE);
      await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();
    });

    it("boot refuses while the SEND role can write a ledger, and allows once revoked", async (ctx) => {
      if (!ready) ctx.skip();
      await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();

      psqlMust(dbUrl, `GRANT UPDATE ON gateway_submit_attempts TO ${NODE_CORE_SEND_ROLE}`);
      await expect(assertPrivilegeReadiness(psqlExecutor())).rejects.toThrow(
        /gateway_submit_attempts \(UPDATE\)/,
      );
      await expect(assertPrivilegeReadiness(psqlExecutor())).rejects.toBeInstanceOf(
        PrivilegeReadinessError,
      );

      psqlMust(dbUrl, `REVOKE UPDATE ON gateway_submit_attempts FROM ${NODE_CORE_SEND_ROLE}`);
      await expect(assertPrivilegeReadiness(psqlExecutor())).resolves.toBeUndefined();
    });
  },
);

// Loud fail under PG_REQUIRED=1 when global-setup did not assign a URL (pattern).
describe("submit-ledger grant separation PG gate", () => {
  it("is assigned TEST_DATABASE_URL when PG_REQUIRED=1", () => {
    if (process.env.PG_REQUIRED === "1" && baseUrl === undefined) {
      throw new Error(
        "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisions it when Postgres is reachable",
      );
    }
    expect(true).toBe(true);
  });
});
