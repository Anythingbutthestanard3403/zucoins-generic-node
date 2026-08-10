/**
 * Real-PostgreSQL proof that transaction-material-byte-immutability.sql attaches
 * BEFORE UPDATE/DELETE/TRUNCATE guards on the three exact SplitChain transaction-
 * material tables (doc 04 §9 / 04:760-767; ZTR-1138).
 *
 * Tables come from the frozen transaction-material.sql CREATE surface; triggers from
 * the append-only pack slice. FK parents are id-only stubs (same isolation pattern as
 * external-send-partial-uniqueness.pg.test.ts).
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  SCHEMA_TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_OBLIGATIONS,
  TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_INVARIANTS,
  TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_SCHEMA_FILE,
} from "../src/schema/transaction-material-byte-immutability.contract.ts";
import { TRANSACTION_MATERIAL_SCHEMA_FILE } from "../src/schema/transaction-material.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const guardsSqlPath = resolve(schemaDir, TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_SCHEMA_FILE);
const guardsSql = readFileSync(guardsSqlPath, "utf8");

const MAINTENANCE_DB = "postgres";
const PSQL_TIMEOUT_MS = 90_000;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: PSQL_TIMEOUT_MS, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
      { encoding: "utf-8", timeout: PSQL_TIMEOUT_MS, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

const sha256 = (seed: number): string => String(seed).padStart(64, "0");
const signature = (seed: number): string => `${String(seed).padStart(86, "A")}==`;

const WALLET = "a0000000-0000-4000-8000-000000000001";
const OP_SI = "0e000000-0000-4000-8000-000000000011";
const OP_TX = "0e000000-0000-4000-8000-000000000012";
const OP_PART = "0e000000-0000-4000-8000-000000000013";
const APPROVAL_SI = "aa000000-0000-4000-8000-000000000011";
const APPROVAL_PART = "aa000000-0000-4000-8000-000000000013";
const LEASE_GROUP = "1ea50000-0000-4000-8000-000000000001";

const PARENT_STUBS = [
  "CREATE TABLE wallets (id uuid PRIMARY KEY);",
  "CREATE TABLE operations (id uuid PRIMARY KEY);",
  "CREATE TABLE operation_approvals (id uuid PRIMARY KEY);",
].join(" ");

let assertionsRun = 0;
const EXPECTED_DRILLS = 8;

describe("transaction-material-byte-immutability census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_INVARIANTS.filter(
      (invariant) => !guardsSql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_OBLIGATIONS.length).toBeGreaterThanOrEqual(
      4,
    );
    for (const obligation of SCHEMA_TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("does not recreate the tables (append-only trigger slice)", () => {
    // Strip line comments so the header's "CREATE TABLE surface" prose cannot match.
    const withoutComments = guardsSql.replace(/--[^\n]*/g, "");
    expect(withoutComments).not.toMatch(/CREATE\s+TABLE\b/i);
    expect(guardsSql).toMatch(/CREATE FUNCTION external_send_sign_intents_reject_mutation\b/);
    expect(guardsSql).toMatch(/CREATE FUNCTION operation_transactions_reject_byte_mutation\b/);
    expect(guardsSql).toMatch(/CREATE FUNCTION external_send_partials_reject_byte_mutation\b/);
  });
});

describeIfPg(
  "transaction-material byte-immutability — real triggers on hermetic scratch DB",
  { timeout: PSQL_TIMEOUT_MS + 30_000 },
  () => {
    const scratchDb = `tx_byte_immut_${Date.now()}_${process.pid}`;

    beforeAll(() => {
      psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
      psqlMust(scratchDb, PARENT_STUBS);
      applyFile(scratchDb, TRANSACTION_MATERIAL_SCHEMA_FILE);
      applyFile(scratchDb, TRANSACTION_MATERIAL_BYTE_IMMUTABILITY_SCHEMA_FILE);
      psqlMust(
        scratchDb,
        `INSERT INTO wallets (id) VALUES ('${WALLET}'); ` +
          `INSERT INTO operations (id) VALUES ('${OP_SI}'),('${OP_TX}'),('${OP_PART}'); ` +
          `INSERT INTO operation_approvals (id) VALUES ('${APPROVAL_SI}'),('${APPROVAL_PART}');`,
      );
      psqlMust(
        scratchDb,
        `INSERT INTO external_send_sign_intents (` +
          `operation_id, approval_id, source_wallet_id, source_t0_observation_id, ` +
          `destination_t0_observation_id, lease_group_id, lease_epoch, ` +
          `inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at) VALUES (` +
          `'${OP_SI}', '${APPROVAL_SI}', '${WALLET}', gen_random_uuid(), gen_random_uuid(), ` +
          `'${LEASE_GROUP}', 1, 'inner-preimage-si', '${sha256(1)}', ` +
          `now() + interval '1 hour', now());`,
      );
      psqlMust(
        scratchDb,
        `INSERT INTO operation_transactions (` +
          `operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at` +
          `) VALUES ('${OP_TX}', 1, 'INNER_PREIMAGE_PERSISTED', 'inner-tx', '${sha256(2)}', now());`,
      );
      psqlMust(
        scratchDb,
        `INSERT INTO external_send_partials (` +
          `operation_id, approval_id, inner_sha256, step_1_signature, ` +
          `transfer_code_text, transfer_code_sha256, persisted_at) VALUES (` +
          `'${OP_PART}', '${APPROVAL_PART}', '${sha256(3)}', '${signature(3)}', ` +
          `'transfer-code-3', '${sha256(3)}', now());`,
      );
    }, PSQL_TIMEOUT_MS + 90_000);

    afterAll(() => {
      const drop = runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
      if (!drop.ok) {
        console.warn(
          `scratch database ${scratchDb} could not be dropped (shared-instance contention)`,
        );
      }
    }, PSQL_TIMEOUT_MS + 30_000);

    it("1. external_send_sign_intents UPDATE is rejected (insert-only)", () => {
      const rejected = runPsql(
        scratchDb,
        `UPDATE external_send_sign_intents SET inner_preimage_text = 'mutated' ` +
          `WHERE operation_id = '${OP_SI}'`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY");
      expect(
        psqlMust(
          scratchDb,
          `SELECT inner_preimage_text FROM external_send_sign_intents WHERE operation_id='${OP_SI}'`,
        ).trim(),
      ).toBe("inner-preimage-si");
      assertionsRun += 1;
    });

    it("2. external_send_sign_intents DELETE is rejected", () => {
      const rejected = runPsql(
        scratchDb,
        `DELETE FROM external_send_sign_intents WHERE operation_id = '${OP_SI}'`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY");
      assertionsRun += 1;
    });

    it("3. operation_transactions one-way fill of step_1_signature succeeds", () => {
      const ok = runPsql(
        scratchDb,
        `UPDATE operation_transactions SET ` +
          `attempt_phase = 'STEP1_SIGNATURE_PERSISTED', ` +
          `step_1_signature = '${signature(20)}' ` +
          `WHERE operation_id = '${OP_TX}' AND attempt_no = 1 ` +
          `AND attempt_phase = 'INNER_PREIMAGE_PERSISTED' AND step_1_signature IS NULL`,
      );
      expect(ok.ok, ok.stderr).toBe(true);
      assertionsRun += 1;
    });

    it("4. operation_transactions overwrite of filled step_1_signature is rejected", () => {
      const rejected = runPsql(
        scratchDb,
        `UPDATE operation_transactions SET step_1_signature = '${signature(99)}' ` +
          `WHERE operation_id = '${OP_TX}' AND attempt_no = 1`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("OPERATION_TRANSACTIONS_BYTE_IMMUTABLE");
      expect(
        psqlMust(
          scratchDb,
          `SELECT step_1_signature FROM operation_transactions WHERE operation_id='${OP_TX}'`,
        ).trim(),
      ).toBe(signature(20));
      assertionsRun += 1;
    });

    it("5. operation_transactions overwrite of insert-time inner_preimage_text is rejected", () => {
      const rejected = runPsql(
        scratchDb,
        `UPDATE operation_transactions SET inner_preimage_text = 'rewritten' ` +
          `WHERE operation_id = '${OP_TX}' AND attempt_no = 1`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("OPERATION_TRANSACTIONS_BYTE_IMMUTABLE");
      assertionsRun += 1;
    });

    it("6. external_send_partials signed-byte UPDATE is rejected", () => {
      const rejected = runPsql(
        scratchDb,
        `UPDATE external_send_partials SET inner_sha256 = '${sha256(41)}' ` +
          `WHERE operation_id = '${OP_PART}'`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE");
      expect(
        psqlMust(
          scratchDb,
          `SELECT inner_sha256 FROM external_send_partials WHERE operation_id='${OP_PART}'`,
        ).trim(),
      ).toBe(sha256(3));
      assertionsRun += 1;
    });

    it("7. external_send_partials delivery-counter UPDATE still succeeds", () => {
      const ok = runPsql(
        scratchDb,
        `UPDATE external_send_partials SET ` +
          `first_delivered_at = now(), last_redelivered_at = now(), redelivery_count = 1 ` +
          `WHERE operation_id = '${OP_PART}'`,
      );
      expect(ok.ok, ok.stderr).toBe(true);
      expect(
        psqlMust(
          scratchDb,
          `SELECT redelivery_count FROM external_send_partials WHERE operation_id='${OP_PART}'`,
        ).trim(),
      ).toBe("1");
      assertionsRun += 1;
    });

    it("8. external_send_partials DELETE is rejected", () => {
      const rejected = runPsql(
        scratchDb,
        `DELETE FROM external_send_partials WHERE operation_id = '${OP_PART}'`,
      );
      expect(rejected.ok).toBe(false);
      expect(rejected.stderr).toContain("EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE");
      assertionsRun += 1;
    });
  },
);

it("obligation guard: real-PG byte-immutability drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: ` +
          "the transaction-material byte-immutability proof could not run.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG byte-immutability drills did not all run",
  ).toBe(EXPECTED_DRILLS);
});
