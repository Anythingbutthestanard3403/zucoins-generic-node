// census: binds the frozen transaction-material invariant inventory to
// the literal SQL contract text, extracts the structural constraint surfaces from the real
// .sql bytes through the shared parser, and cross-binds those surfaces to the application-
// layer facts already frozen in @zucoins/generic-node-contracts — so the three
// truth carriers (inventory, SQL text, application contract) cannot drift apart silently.
// Live-database execution is a schema-apply obligation, inventoried in the contract, not omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS,
  TRANSACTION_MATERIAL_INVARIANTS,
  TRANSACTION_MATERIAL_MUTABILITY_REGIMES,
  TRANSACTION_MATERIAL_PHASE_VOCABULARY,
  TRANSACTION_MATERIAL_SCHEMA_FILE,
} from "../src/schema/transaction-material.contract.ts";
import {
  APPROVAL_CARDINALITY,
  FORMATION_STATES,
  STRUCTURAL_UNIQUENESS,
} from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import {
  parseAttemptPhaseLiterals,
  parseDomains,
  parseNumericBound,
  parseOctetLengthPositive,
  parsePhaseChecks,
  parseTables,
  phaseCheckExpectsNull,
  tableByName,
} from "./transaction-material-sql-parser.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

const tables = parseTables(sql);
const signIntents = tableByName(tables, "external_send_sign_intents");
const attempts = tableByName(tables, "operation_transactions");
const partials = tableByName(tables, "external_send_partials");
const phaseChecks = parsePhaseChecks(attempts);
const allAnchors = TRANSACTION_MATERIAL_INVARIANTS.map((invariant) => invariant.sqlAnchor).join("\n");

const nullableColumnsOf = (table: (typeof tables)[number]): string[] =>
  table.columns.filter((column) => column.nullable).map((column) => column.name);

describe("transaction-material schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = TRANSACTION_MATERIAL_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("every parsed CHECK predicate is covered verbatim by some inventory anchor", () => {
    const predicates = tables.flatMap((table) => [
      ...table.tableChecks,
      ...table.columns.flatMap((column) => column.columnChecks),
    ]);
    expect(predicates.length).toBeGreaterThanOrEqual(12);
    for (const predicate of predicates) {
      expect(allAnchors, `predicate not inventoried: ${predicate}`).toContain(predicate);
    }
  });

  it("parses exactly the three tables, in canon sequence", () => {
    expect(tables.map((table) => table.name)).toEqual([
      "external_send_sign_intents",
      "operation_transactions",
      "external_send_partials",
    ]);
  });

  it("parses exactly the two domains with their exact check bodies", () => {
    const domains = parseDomains(sql);
    expect(domains.map((domain) => domain.name)).toEqual([
      "sha256_hex",
      "padded_base64url_signature",
    ]);
    expect(domains[0]?.checkText).toBe("VALUE ~ '^[0-9a-f]{64}$'");
    expect(domains[1]?.checkText).toBe(
      "length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$'",
    );
  });

  it("statement exhaustiveness: the file contains exactly five CREATE statements and nothing else", () => {
    // The nets above bind what the file CONTAINS; this one binds what the file must NOT
    // contain. A statement appended outside the byte-contiguous block (e.g. an
    // `ALTER TABLE ... DROP CONSTRAINT` silently neutering a frozen CHECK at schema-apply
    // execution) breaks the statement count, fails the CREATE-only shape, and trips the
    // danger tokens — all three asserted here. Line comments and string literals are
    // stripped first; this file's literals carry no `--`, `;`, or escaped quotes.
    const withoutComments = sql.replace(/--[^\n]*/g, "");
    const withoutLiterals = withoutComments.replace(/'[^']*'/g, "''");
    const statements = withoutLiterals
      .split(";")
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0);
    expect(statements).toHaveLength(5); // the two domains plus the three tables
    for (const statement of statements) {
      expect(statement).toMatch(/^CREATE (DOMAIN|TABLE)\b/);
    }
    expect(
      withoutLiterals.match(
        /\b(ALTER|DROP|INSERT|UPDATE|DELETE|GRANT|REVOKE|TRUNCATE|TRIGGER)\b/gi,
      ),
    ).toBeNull();
  });

  it("extracts the primary-key and UNIQUE surfaces from the real bytes", () => {
    expect(signIntents.primaryKey).toEqual(["operation_id"]);
    expect(signIntents.uniqueColumns).toEqual(["approval_id"]);
    expect(attempts.primaryKey).toEqual(["operation_id", "attempt_no"]);
    expect(attempts.uniqueColumns).toEqual([]);
    expect(partials.primaryKey).toEqual(["operation_id"]);
    expect(partials.uniqueColumns).toEqual(["approval_id"]);
  });

  it("extracts nullability: only the one-way/delivery columns are nullable", () => {
    expect(nullableColumnsOf(signIntents)).toEqual([]);
    expect(nullableColumnsOf(attempts)).toEqual([
      "step_1_signature",
      "step_2_preimage_text",
      "step_2_preimage_sha256",
      "step_2_signature",
      "completed_transaction_text",
      "completed_transaction_sha256",
      "settled_at",
    ]);
    expect(nullableColumnsOf(partials)).toEqual(["first_delivered_at", "last_redelivered_at"]);
  });

  it("extracts the numeric column CHECKs (attempt_no, lease_epoch, redelivery_count)", () => {
    const attemptNo = attempts.columns.find((column) => column.name === "attempt_no");
    expect(parseNumericBound(attemptNo?.columnChecks[0] ?? "")).toEqual({
      column: "attempt_no",
      op: "=",
      bound: 1,
    });
    const leaseEpoch = signIntents.columns.find((column) => column.name === "lease_epoch");
    expect(parseNumericBound(leaseEpoch?.columnChecks[0] ?? "")).toEqual({
      column: "lease_epoch",
      op: ">",
      bound: 0,
    });
    const redelivery = partials.columns.find((column) => column.name === "redelivery_count");
    expect(parseNumericBound(redelivery?.columnChecks[0] ?? "")).toEqual({
      column: "redelivery_count",
      op: ">=",
      bound: 0,
    });
    expect(signIntents.tableChecks.map(parseOctetLengthPositive)).toEqual(["inner_preimage_text"]);
  });

  it("extracts the five-phase attempt_phase ladder, matching the contract vocabulary", () => {
    expect(parseAttemptPhaseLiterals(attempts)).toEqual([
      "INNER_PREIMAGE_PERSISTED",
      "STEP1_SIGNATURE_PERSISTED",
      "STEP2_PREIMAGE_PERSISTED",
      "STEP2_SIGNATURE_PERSISTED",
      "SETTLED_BODY_PERSISTED",
    ]);
    expect(parseAttemptPhaseLiterals(attempts)).toEqual([
      ...TRANSACTION_MATERIAL_PHASE_VOCABULARY.attemptPhaseLiterals,
    ]);
  });

  it("parses exactly seven biconditional phase CHECKs, negated only for settled_at", () => {
    expect(phaseChecks).toHaveLength(7);
    expect(phaseChecks.map((check) => check.column)).toEqual([
      "step_1_signature",
      "step_2_preimage_text",
      "step_2_preimage_sha256",
      "step_2_signature",
      "completed_transaction_text",
      "completed_transaction_sha256",
      "settled_at",
    ]);
    // Every check is the biconditional `=` form; only settled_at uses the negated `<>` form.
    for (const check of phaseChecks) {
      expect(check.predicate).toContain("IS NULL");
    }
    expect(phaseChecks.filter((check) => check.negated).map((check) => check.column)).toEqual([
      "settled_at",
    ]);
    // completed_transaction_* are already required at STEP2_SIGNATURE_PERSISTED (04:737-742);
    // SETTLED_BODY_PERSISTED adds only settled_at beyond it (04:743).
    const requiredNotNullAt = (phase: string): string[] =>
      phaseChecks
        .filter((check) => !phaseCheckExpectsNull(check, phase))
        .map((check) => check.column)
        .sort();
    expect(
      requiredNotNullAt("SETTLED_BODY_PERSISTED").filter(
        (column) => !requiredNotNullAt("STEP2_SIGNATURE_PERSISTED").includes(column),
      ),
    ).toEqual(["settled_at"]);
  });

  it("three-way cross-binding: parsed uniqueness surfaces equal the frozen STRUCTURAL_UNIQUENESS facts", () => {
    expect(signIntents.primaryKey).toEqual([STRUCTURAL_UNIQUENESS.signIntentUniqueBy]);
    expect(partials.primaryKey).toEqual([STRUCTURAL_UNIQUENESS.stepOnePartialUniqueBy]);
    // uniquePerLeaseEpoch is frozen false: no parsed uniqueness surface may span lease_epoch.
    expect(STRUCTURAL_UNIQUENESS.uniquePerLeaseEpoch).toBe(false);
    expect(signIntents.uniqueColumns).not.toContain("lease_epoch");
    expect(signIntents.primaryKey).not.toContain("lease_epoch");
  });

  it("three-way cross-binding: APPROVAL_CARDINALITY max-1 matches the parsed approval_id UNIQUEs", () => {
    expect(APPROVAL_CARDINALITY.signIntent.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.persistedPartial.maxPerApproval).toBe(1);
    expect(signIntents.uniqueColumns).toContain("approval_id");
    expect(partials.uniqueColumns).toContain("approval_id");
  });

  it("the three phase vocabularies are distinct (no equating, no deriving)", () => {
    expect(TRANSACTION_MATERIAL_PHASE_VOCABULARY.distinctFromFormationStates).toBe(true);
    expect(TRANSACTION_MATERIAL_PHASE_VOCABULARY.distinctFromPublicExecutionPhase).toBe(true);
    expect(TRANSACTION_MATERIAL_PHASE_VOCABULARY.derivableFromEither).toBe(false);
    const shared = parseAttemptPhaseLiterals(attempts).filter((literal) =>
      (FORMATION_STATES as readonly string[]).includes(literal),
    );
    expect(shared).toEqual([]);
  });

  it("the three mutability regimes match the parsed tables and column surfaces", () => {
    expect(TRANSACTION_MATERIAL_MUTABILITY_REGIMES.map((regime) => regime.table)).toEqual([
      "external_send_sign_intents",
      "operation_transactions",
      "external_send_partials",
    ]);
    const byTable = new Map(TRANSACTION_MATERIAL_MUTABILITY_REGIMES.map((r) => [r.table, r]));
    // Sign intents: nothing updatable (insert-only).
    expect(byTable.get("external_send_sign_intents")?.updatableColumns).toEqual([]);
    // operation_transactions: the updatable set is exactly the parsed nullable set (one-way additions).
    expect([...(byTable.get("operation_transactions")?.updatableColumns ?? [])].sort()).toEqual(
      nullableColumnsOf(attempts).sort(),
    );
    // Partials: only the delivery counters are updatable; every signed byte stays frozen.
    expect([...(byTable.get("external_send_partials")?.updatableColumns ?? [])].sort()).toEqual(
      ["first_delivered_at", "last_redelivered_at", "redelivery_count"].sort(),
    );
    const frozenPartialColumns = partials.columns
      .map((column) => column.name)
      .filter((name) => !(byTable.get("external_send_partials")?.updatableColumns ?? []).includes(name));
    expect(frozenPartialColumns).toEqual([
      "operation_id",
      "approval_id",
      "inner_sha256",
      "step_1_signature",
      "transfer_code_text",
      "transfer_code_sha256",
      "persisted_at",
    ]);
  });

  it("mutation negative: removing UNIQUE from the sign-intent approval line is caught", () => {
    const mutated = sql.replace(
      "approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),\n  source_wallet_id",
      "approval_id uuid NOT NULL REFERENCES operation_approvals(id),\n  source_wallet_id",
    );
    const missing = TRANSACTION_MATERIAL_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["SIGN_INTENT_APPROVAL_UNIQUE"]);
    const reparsed = tableByName(parseTables(mutated), "external_send_sign_intents");
    expect(reparsed.uniqueColumns).not.toContain("approval_id");
  });

  it("mutation negative: weakening the single-attempt CHECK is caught", () => {
    const mutated = sql.replace("CHECK (attempt_no = 1)", "CHECK (attempt_no >= 1)");
    const missing = TRANSACTION_MATERIAL_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["ATTEMPT_NO_SINGLE"]);
  });

  it("mutation negative: dropping a phase literal from the ladder is caught", () => {
    const mutated = sql.replace(
      "'STEP2_SIGNATURE_PERSISTED',\n     'SETTLED_BODY_PERSISTED'))",
      "'STEP2_SIGNATURE_PERSISTED'))",
    );
    const missing = TRANSACTION_MATERIAL_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["ATTEMPT_PHASE_FIVE_LADDER"]);
    const reparsed = tableByName(parseTables(mutated), "operation_transactions");
    expect(parseAttemptPhaseLiterals(reparsed)).toHaveLength(4);
  });

  it("mutation negative: weakening the non-empty-preimage CHECK is caught by anchor and parser", () => {
    const mutated = sql.replace(
      "CHECK (octet_length(inner_preimage_text) > 0)",
      "CHECK (octet_length(inner_preimage_text) >= 0)",
    );
    const missing = TRANSACTION_MATERIAL_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["SIGN_INTENT_PREIMAGE_NONEMPTY"]);
    const reparsed = tableByName(parseTables(mutated), "external_send_sign_intents");
    expect(reparsed.tableChecks.map(parseOctetLengthPositive)).toEqual([null]);
  });

  it("live-database obligations are inventoried and name every mandatory negative", () => {
    expect(SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(40);
    }
    const joined = SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS.join("\n");
    for (const negative of [
      "a persisted partial cannot be replaced",
      "a second transaction attempt for one operation fails both ways",
      "no node code path creates a submit attempt for SEND_EXTERNAL",
    ]) {
      expect(joined).toContain(negative);
    }
    for (const regime of ["insert-only", "one-way completion", "byte-immutable"]) {
      expect(joined).toContain(regime);
    }
  });
});
