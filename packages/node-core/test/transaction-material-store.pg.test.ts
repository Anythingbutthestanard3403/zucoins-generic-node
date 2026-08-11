// Real-PostgreSQL discharge of the data model transaction-material obligations
// Governing: the data model ("Exact SplitChain transaction material", mandatory database
// tests 7-11, the reference scalar domains); the state-event reference (public execution
// phase); the byte-exact signing and never-blind-retry rules.
//
// transaction-material.contract.ts records these as SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS —
// "live-database proofs this package cannot run" — because no database harness existed in the
// CONTRACT_FREEZE phase. One exists now (vitest.global-setup.ts provisions TEST_DATABASE_URL and
// migration-integrity.test.ts / submit-decision-claim-store.pg.test.ts already use it), so the
// five NEGATIVE obligations are discharged here against a real server rather than left to a
// parsed-SQL model. The `guards` obligation — installing BEFORE UPDATE/DELETE triggers — is NOT
// discharged here and stays deferred to the schema-apply phase: the contract freezes no
// trigger DDL, and inventing some here would put this slice at odds with both that
// inventory and the sibling stores. Until the triggers land, the regimes are enforced by the store's statement set,
// which transaction-material-store.test.ts asserts and which this suite exercises end to end.
//
// The DDL applied below is the frozen contract text of src/schema/transaction-material.sql,
// verbatim — never retyped. operations / operation_approvals / wallets are the FK targets no
// slice in this package creates (the documented schema-apply sequence gap, see
// migration-integrity.test.ts) and are stubbed to exactly the columns the FKs reference.
//
// psql runs as a child process (node:child_process), which keeps the in-process
// network-containment guard intact.
// DB-TEST-07: exact artifact approval preimage transaction partial observation event bytes round-trip
// DB-TEST-08: JSONB is absent from all authoritative-byte columns
// DB-TEST-09: persisted external partial cannot be replaced even after expiry or crash


import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  ATTEMPT_PHASE_LADDER,
  deriveExecutionPhase,
  type AttemptPhase,
} from "../src/core/execution-phase.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import {
  PHASE_ADDITIONS,
  advanceAttemptPhase,
  insertPartial,
  insertSignIntent,
  insertTransactionAttempt,
  readTransactionMaterialFacts,
  recordPartialDelivery,
  type AdvancePhase,
} from "../src/core/transaction-material-store.ts";
import {
  SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS,
  TRANSACTION_MATERIAL_MUTABILITY_REGIMES,
  TRANSACTION_MATERIAL_SCHEMA_FILE,
} from "../src/schema/transaction-material.contract.ts";
import {
  WALLET_INNER_PREIMAGE_SHA256,
  WALLET_INNER_PREIMAGE_TEXT,
  WALLET_SETTLED_TRANSACTION_SHA256,
  WALLET_SETTLED_TRANSACTION_TEXT,
  WALLET_STEP_1_SIGNATURE,
  WALLET_STEP_2_PREIMAGE_SHA256,
  WALLET_STEP_2_PREIMAGE_TEXT,
  WALLET_STEP_2_SIGNATURE,
  NON_ASCII_INNER_PREIMAGE_SHA256,
  NON_ASCII_INNER_PREIMAGE_TEXT,
} from "./fixtures/splitchain-v2-byte-evidence.ts";

const here = dirname(fileURLToPath(import.meta.url));
const contractSql = readFileSync(
  resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE),
  "utf8",
);

const SCHEMA = "transaction_material_transaction_material";
const CHECK_VIOLATION = "23514";
const UNIQUE_VIOLATION = "23505";
const FK_VIOLATION = "23503";

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): NodeJS.ProcessEnv => {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
};

interface PsqlResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

// Test-only stand-in for a driver's parameter binding, as submit-decision-claim-store.pg.test.ts
// does: psql has no wire parameters, so each $n becomes a psql variable reference, which psql
// quotes and escapes. Byte values therefore reach the server through psql's own quoting, never
// through string concatenation in this file.
function psql(sql: string, values: readonly unknown[] = []): Promise<PsqlResult> {
  const args = ["-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) {
      args.push("-v", `p${index + 1}=${String(value)}`);
    }
  });
  args.push("-f", "-");
  const bound = sql.replace(/\$(\d+)/g, (_match, position: string) => {
    const value = values[Number(position) - 1];
    return value === null || value === undefined ? "NULL" : `:'p${position}'`;
  });
  return new Promise((settle, fail) => {
    const child = spawn("psql", args, { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", fail);
    child.on("close", (code) => settle({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(`${sql.trimEnd().endsWith(";") ? bound : `${bound};`}\n`);
  });
}

async function psqlOk(sql: string, values: readonly unknown[] = []): Promise<string> {
  const result = await psql(sql, values);
  if (result.code !== 0) throw new Error(result.stderr.trim());
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

const query: SqlQueryFn = async (text, values) => {
  const wrapped = `WITH q AS (${text}) SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM q`;
  const stdout = await psqlOk(inSchema(wrapped), values);
  const line = stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
  return JSON.parse(line) as Record<string, unknown>[];
};

const scalar = async (sql: string): Promise<string> => (await psqlOk(inSchema(sql))).trim();

/** Runs a statement expected to be REJECTED, returning its SQLSTATE and constraint name. */
async function rejected(
  sql: string,
  values: readonly unknown[] = [],
): Promise<{ readonly sqlstate: string; readonly constraint: string }> {
  const result = await psql(inSchema(sql), values);
  expect(result.code, `statement should have been rejected: ${sql}`).not.toBe(0);
  const sqlstate = /ERROR:\s+(\d{5}):/.exec(result.stderr)?.[1] ?? "";
  const constraint = /CONSTRAINT NAME:\s+(\S+)/.exec(result.stderr)?.[1] ?? "";
  return { sqlstate, constraint };
}

const sha256 = (text: string): string =>
  createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");

const hexOf = (text: string): string => Buffer.from(text, "utf8").toString("hex");

// ── valid domain-conforming filler for the phase-nullability matrix ─────────────────────────
const VALID: Record<string, string> = {
  step_1_signature: WALLET_STEP_1_SIGNATURE,
  step_2_preimage_text: WALLET_STEP_2_PREIMAGE_TEXT,
  step_2_preimage_sha256: WALLET_STEP_2_PREIMAGE_SHA256,
  step_2_signature: WALLET_STEP_2_SIGNATURE,
  completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
  completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
  settled_at: "2026-07-26T00:00:09.000Z",
};

/** The seven columns the frozen phase CHECKs gate, in declaration order. */
const GATED_COLUMNS = Object.keys(VALID);

/**
 * The columns that must be NOT NULL at `phase`, derived cumulatively from the store's
 * PHASE_ADDITIONS ladder rather than hand-copied from the CHECKs — so the expectation and the
 * write path cannot drift apart.
 */
const requiredAt = (phase: AttemptPhase): string[] => {
  const upTo = ATTEMPT_PHASE_LADDER.indexOf(phase);
  return ATTEMPT_PHASE_LADDER.slice(1, upTo + 1).flatMap((step) => [
    ...PHASE_ADDITIONS[step as AdvancePhase],
  ]);
};

const TIMESTAMP_GATED = ["settled_at"];

/** A full INSERT for `phase` with the seven gated columns set exactly as `values` says. */
const attemptInsert = (
  operationId: string,
  phase: AttemptPhase,
  values: Readonly<Record<string, string | null>>,
): string => {
  const cells = GATED_COLUMNS.map((column) => {
    const value = values[column];
    if (value === null || value === undefined) return "NULL";
    const literal = `'${value.replaceAll("'", "''")}'`;
    return TIMESTAMP_GATED.includes(column) ? `${literal}::timestamptz` : literal;
  });
  return `INSERT INTO operation_transactions
    (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
     ${GATED_COLUMNS.join(", ")}, formed_at)
    VALUES ('${operationId}', 1, '${phase}', '${WALLET_INNER_PREIMAGE_TEXT.replaceAll("'", "''")}',
     '${WALLET_INNER_PREIMAGE_SHA256}', ${cells.join(", ")}, now())`;
};

/** The phase-correct gated-column values for `phase`. */
const correctValues = (phase: AttemptPhase): Record<string, string | null> => {
  const required = requiredAt(phase);
  return Object.fromEntries(
    GATED_COLUMNS.map((column) => [column, required.includes(column) ? VALID[column]! : null]),
  );
};

let reachable = false;
const seeded: string[] = [];

/** Seeds one operation (and its approval) and returns their ids. */
async function seedOperation(): Promise<{ operationId: string; approvalId: string }> {
  const operationId = randomUUID();
  const approvalId = randomUUID();
  await psqlOk(
    inSchema(
      `INSERT INTO operations (id) VALUES ('${operationId}');
       INSERT INTO operation_approvals (id) VALUES ('${approvalId}');`,
    ),
  );
  seeded.push(operationId);
  return { operationId, approvalId };
}

const WALLET_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

const signIntentFor = (operationId: string, approvalId: string) => ({
  operationId,
  approvalId,
  sourceWalletId: WALLET_ID,
  sourceT0ObservationId: randomUUID(),
  destinationT0ObservationId: randomUUID(),
  leaseGroupId: randomUUID(),
  leaseEpoch: "4",
  innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
  innerSha256: WALLET_INNER_PREIMAGE_SHA256,
  redemptionExpiryAt: "2026-07-26T00:05:00.000Z",
  preparedAt: "2026-07-26T00:00:00.000Z",
});

const partialFor = (operationId: string, approvalId: string) => ({
  operationId,
  approvalId,
  innerSha256: WALLET_INNER_PREIMAGE_SHA256,
  step1Signature: WALLET_STEP_1_SIGNATURE,
  transferCodeText: WALLET_STEP_2_PREIMAGE_TEXT,
  transferCodeSha256: WALLET_STEP_2_PREIMAGE_SHA256,
  persistedAt: "2026-07-26T00:00:05.000Z",
});

// Which schema-apply obligation each negative block discharges. Asserted total at the end of the suite.
const DISCHARGED = new Set<string>();
const discharges = (fragment: string): void => {
  const obligation = SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS.find((entry) => entry.includes(fragment));
  if (obligation === undefined) throw new Error(`no schema-apply obligation contains: ${fragment}`);
  DISCHARGED.add(obligation);
};

describe.skipIf(databaseUrl === undefined)(
  "the data model transaction material against a live PostgreSQL",
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          // Exactly the columns 's FKs reference. transaction-material.sql declares its own
          // two domains, so base-enums-domains.sql is deliberately NOT applied here.
          `CREATE TABLE operations (id uuid PRIMARY KEY);
           CREATE TABLE operation_approvals (id uuid PRIMARY KEY);
           CREATE TABLE wallets (id uuid PRIMARY KEY);
           INSERT INTO wallets (id) VALUES ('${WALLET_ID}');
           ${contractSql}`,
        ),
      );
      reachable = true;
    });

    afterAll(async () => {
      if (reachable) await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
    });

    it("the frozen contract text applies verbatim and materializes all three tables plus both domains", async () => {
      expect(
        await scalar(
          `SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables
             WHERE schemaname = '${SCHEMA}'
               AND tablename IN ('external_send_partials','external_send_sign_intents','operation_transactions')`,
        ),
      ).toBe("external_send_partials,external_send_sign_intents,operation_transactions");
      expect(
        await scalar(
          `SELECT string_agg(typname, ',' ORDER BY typname) FROM pg_type t
             JOIN pg_namespace n ON n.oid = t.typnamespace
             WHERE n.nspname = '${SCHEMA}' AND t.typtype = 'd'`,
        ),
      ).toBe("padded_base64url_signature,sha256_hex");
    });

    // mandatory database test 8 — JSONB is absent from all authoritative-byte columns.
    it("DB-TEST-08: JSONB is absent from all authoritative-byte columns", async () => {
      expect(
        await scalar(
          `SELECT coalesce(string_agg(table_name || '.' || column_name || ':' || data_type, ','), 'none')
             FROM information_schema.columns
            WHERE table_schema = '${SCHEMA}'
              AND table_name IN ('external_send_sign_intents','operation_transactions','external_send_partials')
              AND data_type IN ('json','jsonb','bytea')`,
        ),
      ).toBe("none");
      // Every exact-body column is plain text (a domain would report USER-DEFINED). Qualified by
      // table because inner_preimage_text exists on the sign-intent AND the attempt row.
      expect(
        await scalar(
          `SELECT string_agg(table_name || '.' || column_name || ':' || data_type, ','
                             ORDER BY table_name, column_name)
             FROM information_schema.columns
            WHERE table_schema = '${SCHEMA}'
              AND column_name IN ('inner_preimage_text','step_2_preimage_text',
                                  'completed_transaction_text','transfer_code_text')`,
        ),
      ).toBe(
        [
          "external_send_partials.transfer_code_text:text",
          "external_send_sign_intents.inner_preimage_text:text",
          "operation_transactions.completed_transaction_text:text",
          "operation_transactions.inner_preimage_text:text",
          "operation_transactions.step_2_preimage_text:text",
        ].join(","),
      );
    });

    // Introspection indicator: execution_phase is derived, never stored.
    it("no execution_phase column exists on any of the three tables — it is derived at read time", async () => {
      expect(
        await scalar(
          `SELECT count(*) FROM information_schema.columns
             WHERE table_schema = '${SCHEMA}' AND column_name = 'execution_phase'`,
        ),
      ).toBe("0");
      expect(contractSql).not.toContain("execution_phase");
    });

    // mandatory database test 7 — exact preimage, transaction and partial bytes survive round-trip.
    it("DB-TEST-07: exact artifact approval preimage transaction partial observation event bytes round-trip", async () => {
      const { operationId, approvalId } = await seedOperation();
      await insertSignIntent(query, signIntentFor(operationId, approvalId));
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
        innerSha256: WALLET_INNER_PREIMAGE_SHA256,
        formedAt: "2026-07-26T00:00:01.000Z",
      });
      await advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      });
      await advanceAttemptPhase(query, operationId, "STEP2_PREIMAGE_PERSISTED", {
        step_2_preimage_text: WALLET_STEP_2_PREIMAGE_TEXT,
        step_2_preimage_sha256: WALLET_STEP_2_PREIMAGE_SHA256,
      });
      await advanceAttemptPhase(query, operationId, "STEP2_SIGNATURE_PERSISTED", {
        step_2_signature: WALLET_STEP_2_SIGNATURE,
        completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
        completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
      });
      await insertPartial(query, partialFor(operationId, approvalId));

      // Compared as hex of the server-side UTF-8 encoding: a byte difference cannot hide behind
      // a driver's string handling, and nothing here parses or re-stringifies the JSON.
      const persisted = await scalar(
        `SELECT encode(convert_to(t.inner_preimage_text, 'UTF8'), 'hex')
             || '|' || encode(convert_to(t.step_2_preimage_text, 'UTF8'), 'hex')
             || '|' || encode(convert_to(t.completed_transaction_text, 'UTF8'), 'hex')
             || '|' || t.step_1_signature || '|' || t.step_2_signature
             || '|' || encode(convert_to(i.inner_preimage_text, 'UTF8'), 'hex')
             || '|' || encode(convert_to(p.transfer_code_text, 'UTF8'), 'hex')
             || '|' || p.step_1_signature
           FROM operation_transactions t
           JOIN external_send_sign_intents i USING (operation_id)
           JOIN external_send_partials p USING (operation_id)
          WHERE t.operation_id = '${operationId}'`,
      );
      expect(persisted).toBe(
        [
          hexOf(WALLET_INNER_PREIMAGE_TEXT),
          hexOf(WALLET_STEP_2_PREIMAGE_TEXT),
          hexOf(WALLET_SETTLED_TRANSACTION_TEXT),
          WALLET_STEP_1_SIGNATURE,
          WALLET_STEP_2_SIGNATURE,
          hexOf(WALLET_INNER_PREIMAGE_TEXT),
          hexOf(WALLET_STEP_2_PREIMAGE_TEXT),
          WALLET_STEP_1_SIGNATURE,
        ].join("|"),
      );
      // The stored digests are the digests OF the stored bytes, recomputed here from what came
      // back — so a silently re-encoded body could not agree with its own frozen digest.
      expect(sha256(WALLET_INNER_PREIMAGE_TEXT)).toBe(WALLET_INNER_PREIMAGE_SHA256);
      expect(sha256(WALLET_SETTLED_TRANSACTION_TEXT)).toBe(WALLET_SETTLED_TRANSACTION_SHA256);
      expect(
        await scalar(
          `SELECT encode(sha256(convert_to(completed_transaction_text, 'UTF8')), 'hex') = completed_transaction_sha256
             FROM operation_transactions WHERE operation_id = '${operationId}'`,
        ),
      ).toBe("t");
    });

    it("a non-ASCII preimage round-trips byte-identically (multi-byte UTF-8 is not re-encoded)", async () => {
      const { operationId, approvalId } = await seedOperation();
      await insertSignIntent(query, {
        ...signIntentFor(operationId, approvalId),
        innerPreimageText: NON_ASCII_INNER_PREIMAGE_TEXT,
        innerSha256: NON_ASCII_INNER_PREIMAGE_SHA256,
      });
      expect(
        await scalar(
          `SELECT encode(convert_to(inner_preimage_text, 'UTF8'), 'hex')
             FROM external_send_sign_intents WHERE operation_id = '${operationId}'`,
        ),
      ).toBe(hexOf(NON_ASCII_INNER_PREIMAGE_TEXT));
      expect(
        await scalar(
          `SELECT encode(sha256(convert_to(inner_preimage_text, 'UTF8')), 'hex') = inner_sha256
             FROM external_send_sign_intents WHERE operation_id = '${operationId}'`,
        ),
      ).toBe("t");
    });

    // The seven paired phase CHECKs, both polarities, across the full 5-phase x 7-column matrix.
    it("all five phases insert with correct nullability, and all 35 wrong-nullability rows are rejected", async () => {
      const constraintsHit = new Set<string>();
      let accepted = 0;
      let rejectedCount = 0;

      for (const phase of ATTEMPT_PHASE_LADDER) {
        const correct = correctValues(phase);
        const { operationId } = await seedOperation();
        await psqlOk(inSchema(attemptInsert(operationId, phase, correct)));
        accepted += 1;

        for (const column of GATED_COLUMNS) {
          // Flip exactly this column's nullability and keep every other one phase-correct, so the
          // rejection can only come from that column's own CHECK.
          const wrong = { ...correct, [column]: correct[column] === null ? VALID[column]! : null };
          const spare = await seedOperation();
          const outcome = await rejected(attemptInsert(spare.operationId, phase, wrong));
          expect(outcome.sqlstate, `${phase}/${column}`).toBe(CHECK_VIOLATION);
          constraintsHit.add(outcome.constraint);
          rejectedCount += 1;
        }
      }

      expect(accepted).toBe(ATTEMPT_PHASE_LADDER.length);
      expect(rejectedCount).toBe(ATTEMPT_PHASE_LADDER.length * GATED_COLUMNS.length);
      // Seven distinct CHECK constraints were reached — each of the phase biconditionals is
      // independently exercised, not merely "some CHECK fired seven times".
      expect(GATED_COLUMNS).toHaveLength(7);
      expect([...constraintsHit].sort()).toHaveLength(7);
      discharges("each of the seven paired attempt_phase CHECKs");
    });

    // mandatory database test 10 — a second transaction attempt for one operation fails, both ways.
    it("a second attempt fails: attempt_no = 2 breaks the CHECK and a duplicate attempt_no = 1 breaks the PK (mandatory database test 10)", async () => {
      const { operationId } = await seedOperation();
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
        innerSha256: WALLET_INNER_PREIMAGE_SHA256,
        formedAt: "2026-07-26T00:00:01.000Z",
      });

      const duplicate = await rejected(attemptInsert(operationId, "INNER_PREIMAGE_PERSISTED", correctValues("INNER_PREIMAGE_PERSISTED")));
      expect(duplicate.sqlstate).toBe(UNIQUE_VIOLATION);
      expect(duplicate.constraint).toBe("operation_transactions_pkey");

      const secondAttempt = await rejected(
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
           VALUES ('${operationId}', 2, 'INNER_PREIMAGE_PERSISTED', 'x', '${WALLET_INNER_PREIMAGE_SHA256}', now())`,
      );
      expect(secondAttempt.sqlstate).toBe(CHECK_VIOLATION);
      expect(secondAttempt.constraint).toBe("operation_transactions_attempt_no_check");

      // The store cannot express a second attempt either: attempt_no is a literal 1.
      await expect(
        insertTransactionAttempt(query, {
          operationId,
          innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
          innerSha256: WALLET_INNER_PREIMAGE_SHA256,
          formedAt: "2026-07-26T00:00:02.000Z",
        }),
      ).rejects.toThrow(/operation_transactions_pkey/);
      discharges("a second transaction attempt for one operation fails both ways");
    });

    // mandatory database test 9 — a persisted external partial cannot be replaced, even after expiry or crash.
    it("DB-TEST-09: persisted external partial cannot be replaced even after expiry or crash", async () => {
      const { operationId, approvalId } = await seedOperation();
      await insertPartial(query, partialFor(operationId, approvalId));

      await expect(insertPartial(query, partialFor(operationId, approvalId))).rejects.toThrow(
        /external_send_partials_pkey/,
      );

      // A different operation under the SAME approval is also refused — one partial per approval.
      const other = await seedOperation();
      const sameApproval = await rejected(
        `INSERT INTO external_send_partials
           (operation_id, approval_id, inner_sha256, step_1_signature,
            transfer_code_text, transfer_code_sha256, persisted_at)
           VALUES ('${other.operationId}', '${approvalId}', '${WALLET_INNER_PREIMAGE_SHA256}',
                   '${WALLET_STEP_1_SIGNATURE}', 'code', '${WALLET_STEP_2_PREIMAGE_SHA256}', now())`,
      );
      expect(sameApproval.sqlstate).toBe(UNIQUE_VIOLATION);
      expect(sameApproval.constraint).toBe("external_send_partials_approval_id_key");
      discharges("a persisted partial cannot be replaced");
    });

    it("a second sign intent, and a second sign intent against one approval, are both refused", async () => {
      const { operationId, approvalId } = await seedOperation();
      await insertSignIntent(query, signIntentFor(operationId, approvalId));
      await expect(insertSignIntent(query, signIntentFor(operationId, approvalId))).rejects.toThrow(
        /external_send_sign_intents_pkey/,
      );
      const other = await seedOperation();
      await expect(
        insertSignIntent(query, signIntentFor(other.operationId, approvalId)),
      ).rejects.toThrow(/external_send_sign_intents_approval_id_key/);
      discharges("one sign intent and one partial per approval");
    });

    it("domain and bound violations are rejected: bad digests, bad signatures, epoch <= 0, empty preimage, negative count", async () => {
      const { operationId, approvalId } = await seedOperation();
      const intent = (overrides: string): string =>
        `INSERT INTO external_send_sign_intents
           (operation_id, approval_id, source_wallet_id, source_t0_observation_id,
            destination_t0_observation_id, lease_group_id, lease_epoch,
            inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at)
           SELECT '${operationId}', '${approvalId}', '${WALLET_ID}', gen_random_uuid(),
                  gen_random_uuid(), gen_random_uuid(), 1, 'x',
                  '${WALLET_INNER_PREIMAGE_SHA256}', now(), now()
           ${overrides}`;

      // Domain violations report 22P02/23514 depending on form; assert the message instead of a
      // constraint name, since a domain CHECK carries the domain's own name.
      const upperHex = await psql(
        inSchema(
          intent("").replace(`'${WALLET_INNER_PREIMAGE_SHA256}'`, `'${WALLET_INNER_PREIMAGE_SHA256.toUpperCase()}'`),
        ),
      );
      expect(upperHex.code).not.toBe(0);
      expect(upperHex.stderr).toMatch(/sha256_hex/);

      const shortSignature = await psql(
        inSchema(
          `INSERT INTO external_send_partials
             (operation_id, approval_id, inner_sha256, step_1_signature,
              transfer_code_text, transfer_code_sha256, persisted_at)
             VALUES ('${operationId}', '${approvalId}', '${WALLET_INNER_PREIMAGE_SHA256}',
                     '${WALLET_STEP_1_SIGNATURE.slice(0, 87)}', 'code',
                     '${WALLET_STEP_2_PREIMAGE_SHA256}', now())`,
        ),
      );
      expect(shortSignature.code).not.toBe(0);
      expect(shortSignature.stderr).toMatch(/padded_base64url_signature/);

      for (const epoch of [0, -1]) {
        const outcome = await rejected(intent("").replace(", 1,", `, ${epoch},`));
        expect(outcome.sqlstate, `epoch ${epoch}`).toBe(CHECK_VIOLATION);
        expect(outcome.constraint, `epoch ${epoch}`).toBe(
          "external_send_sign_intents_lease_epoch_check",
        );
      }

      const emptyPreimage = await rejected(intent("").replace("1, 'x',", "1, '',"));
      expect(emptyPreimage.sqlstate).toBe(CHECK_VIOLATION);

      const negativeCount = await rejected(
        `INSERT INTO external_send_partials
           (operation_id, approval_id, inner_sha256, step_1_signature, transfer_code_text,
            transfer_code_sha256, persisted_at, redelivery_count)
           VALUES ('${operationId}', '${approvalId}', '${WALLET_INNER_PREIMAGE_SHA256}',
                   '${WALLET_STEP_1_SIGNATURE}', 'code', '${WALLET_STEP_2_PREIMAGE_SHA256}', now(), -1)`,
      );
      expect(negativeCount.sqlstate).toBe(CHECK_VIOLATION);
      expect(negativeCount.constraint).toBe("external_send_partials_redelivery_count_check");
      discharges("lease_epoch 0 or negative");
    });

    it("the FK targets are real: an unknown operation, approval or wallet is refused", async () => {
      const { approvalId } = await seedOperation();
      const unknownOperation = await rejected(
        `INSERT INTO external_send_sign_intents
           (operation_id, approval_id, source_wallet_id, source_t0_observation_id,
            destination_t0_observation_id, lease_group_id, lease_epoch,
            inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at)
           VALUES (gen_random_uuid(), '${approvalId}', '${WALLET_ID}', gen_random_uuid(),
                   gen_random_uuid(), gen_random_uuid(), 1, 'x',
                   '${WALLET_INNER_PREIMAGE_SHA256}', now(), now())`,
      );
      expect(unknownOperation.sqlstate).toBe(FK_VIOLATION);
      const { operationId } = await seedOperation();
      const unknownWallet = await rejected(
        `INSERT INTO external_send_sign_intents
           (operation_id, approval_id, source_wallet_id, source_t0_observation_id,
            destination_t0_observation_id, lease_group_id, lease_epoch,
            inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at)
           VALUES ('${operationId}', '${approvalId}', gen_random_uuid(), gen_random_uuid(),
                   gen_random_uuid(), gen_random_uuid(), 1, 'x',
                   '${WALLET_INNER_PREIMAGE_SHA256}', now(), now())`,
      );
      expect(unknownWallet.sqlstate).toBe(FK_VIOLATION);
    });

    // the data model: "immutable after insertion except for the one-way additions... Existing values can
    // never be overwritten." freezes no trigger, so this is the store's guard, proven live.
    it("one-way completion: a replayed or out-of-order advance updates zero rows and never overwrites a signature", async () => {
      const { operationId } = await seedOperation();
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
        innerSha256: WALLET_INNER_PREIMAGE_SHA256,
        formedAt: "2026-07-26T00:00:01.000Z",
      });
      await advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      });

      // A replay with DIFFERENT bytes must not land — the classic re-sign hazard.
      const forged = `${"A".repeat(86)}==`;
      await expect(
        advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
          step_1_signature: forged,
        }),
      ).rejects.toThrow(/did not advance to STEP1_SIGNATURE_PERSISTED/);
      expect(
        await scalar(
          `SELECT step_1_signature FROM operation_transactions WHERE operation_id = '${operationId}'`,
        ),
      ).toBe(WALLET_STEP_1_SIGNATURE);

      // Skipping a phase is refused: the guard demands the immediately prior phase.
      await expect(
        advanceAttemptPhase(query, operationId, "SETTLED_BODY_PERSISTED", {
          settled_at: "2026-07-26T00:00:09.000Z",
        }),
      ).rejects.toThrow(/did not advance to SETTLED_BODY_PERSISTED/);
      expect(
        await scalar(
          `SELECT attempt_phase FROM operation_transactions WHERE operation_id = '${operationId}'`,
        ),
      ).toBe("STEP1_SIGNATURE_PERSISTED");
    });

    it("the partial's byte columns are unchanged by any number of deliveries; only the three delivery columns move", async () => {
      const { operationId, approvalId } = await seedOperation();
      await insertPartial(query, partialFor(operationId, approvalId));
      const byteSnapshot = () =>
        scalar(
          `SELECT encode(convert_to(transfer_code_text, 'UTF8'), 'hex') || '|' || step_1_signature
              || '|' || inner_sha256 || '|' || transfer_code_sha256
              || '|' || to_char(persisted_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
             FROM external_send_partials WHERE operation_id = '${operationId}'`,
        );
      const before = await byteSnapshot();

      expect(await recordPartialDelivery(query, operationId, "2026-07-26T00:00:06.000Z")).toBe(0);
      expect(
        await scalar(
          `SELECT (first_delivered_at IS NOT NULL) || '/' || (last_redelivered_at IS NULL)
             FROM external_send_partials WHERE operation_id = '${operationId}'`,
        ),
        // `boolean || text` renders as true/false, not the bare-column t/f form.
      ).toBe("true/true");

      expect(await recordPartialDelivery(query, operationId, "2026-07-26T00:00:07.000Z")).toBe(1);
      expect(await recordPartialDelivery(query, operationId, "2026-07-26T00:00:08.000Z")).toBe(2);
      expect(
        await scalar(
          `SELECT to_char(first_delivered_at at time zone 'UTC', 'HH24:MI:SS') || '/'
               || to_char(last_redelivered_at at time zone 'UTC', 'HH24:MI:SS')
             FROM external_send_partials WHERE operation_id = '${operationId}'`,
        ),
      ).toBe("00:00:06/00:00:08");
      expect(await byteSnapshot()).toBe(before);

      // And the frozen regime is exactly what moved.
      const regime = TRANSACTION_MATERIAL_MUTABILITY_REGIMES.find(
        (entry) => entry.table === "external_send_partials",
      );
      expect([...(regime?.updatableColumns ?? [])].sort()).toEqual(
        ["first_delivered_at", "last_redelivered_at", "redelivery_count"].sort(),
      );
    });

    // exit criterion: "crash leaves provably not-started or resumable identical bytes."
    // Every psql call here is a separate process, so each read below already happens after the
    // writing connection is gone — the crash boundary is structural, not simulated.
    it("crash before, during and after each signer call leaves resumable identical bytes and a derived phase", async () => {
      const { operationId, approvalId } = await seedOperation();
      const kind = "SEND_EXTERNAL" as const;
      const nothingElse = {
        submitStarted: false,
        submitReturned: false,
        verificationAccepted: false,
        terminalObservationsPresent: false,
      };
      const phaseNow = async () =>
        deriveExecutionPhase({
          operationKind: kind,
          ...(await readTransactionMaterialFacts(query, operationId)),
          ...nothingElse,
        });

      // Crash before the first signer call: provably not started.
      expect(await phaseNow()).toBe("NOT_STARTED");

      // Crash after the sign intent commits, before step 1 is signed: resumable.
      await insertSignIntent(query, signIntentFor(operationId, approvalId));
      expect(await phaseNow()).toBe("PREIMAGE_PERSISTED");
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
        innerSha256: WALLET_INNER_PREIMAGE_SHA256,
        formedAt: "2026-07-26T00:00:01.000Z",
      });
      expect(await phaseNow()).toBe("PREIMAGE_PERSISTED");
      // The recovered bytes are the bytes that were persisted, not a rebuild.
      expect(
        await scalar(
          `SELECT encode(convert_to(inner_preimage_text, 'UTF8'), 'hex')
             FROM operation_transactions WHERE operation_id = '${operationId}'`,
        ),
      ).toBe(hexOf(WALLET_INNER_PREIMAGE_TEXT));

      // Crash after step 1 is persisted: resumable at SIGNED_PERSISTED, never re-signable.
      await advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      });
      expect(await phaseNow()).toBe("SIGNED_PERSISTED");

      // Crash after the partial commits but before delivery: still SIGNED_PERSISTED, and the
      // partial cannot be rebuilt (proven above), so recovery can only re-deliver these bytes.
      await insertPartial(query, partialFor(operationId, approvalId));
      expect(await phaseNow()).toBe("SIGNED_PERSISTED");
      await recordPartialDelivery(query, operationId, "2026-07-26T00:00:06.000Z");
      expect(await phaseNow()).toBe("DELIVERED");
    });

    it("the derived phase for a MOVE walks the ladder through the real read query", async () => {
      const { operationId } = await seedOperation();
      const nothingElse = {
        submitStarted: false,
        submitReturned: false,
        verificationAccepted: false,
        terminalObservationsPresent: false,
      };
      const phaseNow = async () =>
        deriveExecutionPhase({
          operationKind: "MOVE_INTERNAL",
          ...(await readTransactionMaterialFacts(query, operationId)),
          ...nothingElse,
        });

      expect(await phaseNow()).toBe("NOT_STARTED");
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: WALLET_INNER_PREIMAGE_TEXT,
        innerSha256: WALLET_INNER_PREIMAGE_SHA256,
        formedAt: "2026-07-26T00:00:01.000Z",
      });
      expect(await phaseNow()).toBe("PREIMAGE_PERSISTED");
      await advanceAttemptPhase(query, operationId, "STEP1_SIGNATURE_PERSISTED", {
        step_1_signature: WALLET_STEP_1_SIGNATURE,
      });
      expect(await phaseNow()).toBe("SIGNED_PERSISTED");
      await advanceAttemptPhase(query, operationId, "STEP2_PREIMAGE_PERSISTED", {
        step_2_preimage_text: WALLET_STEP_2_PREIMAGE_TEXT,
        step_2_preimage_sha256: WALLET_STEP_2_PREIMAGE_SHA256,
      });
      await advanceAttemptPhase(query, operationId, "STEP2_SIGNATURE_PERSISTED", {
        step_2_signature: WALLET_STEP_2_SIGNATURE,
        completed_transaction_text: WALLET_SETTLED_TRANSACTION_TEXT,
        completed_transaction_sha256: WALLET_SETTLED_TRANSACTION_SHA256,
      });
      await advanceAttemptPhase(query, operationId, "SETTLED_BODY_PERSISTED", {
        settled_at: "2026-07-26T00:00:09.000Z",
      });
      // Settlement is a persistence phase, not a landing verdict: LANDED_VERIFIED needs an
      // accepted verification plus terminal observations, which no row can supply.
      expect(await phaseNow()).toBe("SIGNED_PERSISTED");
      expect(
        deriveExecutionPhase({
          operationKind: "MOVE_INTERNAL",
          ...(await readTransactionMaterialFacts(query, operationId)),
          ...nothingElse,
          verificationAccepted: true,
          terminalObservationsPresent: true,
        }),
      ).toBe("LANDED_VERIFIED");
    });

    it("every schema-apply negative obligation for this contract is discharged by this suite", () => {
      // The two obligations that are NOT negatives: the FK execution sequence (satisfied by the
      // stubs above) and the trigger guards (explicitly still schema-apply — see this file's header).
      const notNegatives = SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS.filter(
        (obligation) =>
          obligation.startsWith("execution sequence:") || obligation.startsWith("guards:"),
      );
      const negatives = SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS.filter(
        (obligation) => !notNegatives.includes(obligation),
      );
      // mandatory database test 11 (no submit attempt for SEND_EXTERNAL) is a source-path property, not a
      // constraint on these three tables; deriveExecutionPhase enforces it as an unrepresentable
      // fact tuple (test/execution-phase.test.ts) and submit-attempts.sql owns the table side.
      const dischargeable = negatives.filter(
        (obligation) => !obligation.includes("no node code path creates a submit attempt"),
      );
      expect([...DISCHARGED].sort()).toEqual([...dischargeable].sort());
    });
  },
);

/* ─── fail-closed harness guard (pattern) ──────────────────────────────
 * Top-level, OUTSIDE the gated describe, so it runs even when that block skips itself. Under
 * PG_REQUIRED=1 an unassigned URL or an unreachable server is a BROKEN HARNESS, never "no
 * Postgres here" — so this money-path suite fails loudly instead of reporting green having
 * executed nothing. */
it("live-PostgreSQL discharge must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the discharge skipped",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never applied the schema — its assertions were skipped, not proven",
  ).toBe(true);
});
