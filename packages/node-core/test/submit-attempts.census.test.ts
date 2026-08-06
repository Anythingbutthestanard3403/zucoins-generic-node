// census: binds the frozen single-shot submit invariant inventory to
// the literal SQL contract text and cross-binds the transport-outcome literals to the
// gateway transport vocabulary in src/gateway/records.ts, so the three truth carriers
// (contract inventory, SQL text, transport records) cannot drift apart silently.
// Live-database execution is a schema-apply obligation, inventoried in the contract, not
// silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS,
  SUBMIT_ATTEMPTS_INVARIANTS,
  SUBMIT_ATTEMPTS_MUTABILITY_REGIMES,
  SUBMIT_ATTEMPTS_SCHEMA_FILE,
} from "../src/schema/submit-attempts.contract.ts";
import { SUBMIT_TRANSPORT_OUTCOMES } from "../src/gateway/records.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", SUBMIT_ATTEMPTS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

const parseOutcomeLiterals = (text: string): string[] => {
  const check = /transport_outcome IN\s*\(\s*'([^']+)'(?:\s*,\s*'([^']+)')*\s*\)/.exec(text);
  if (check === null) {
    return [];
  }
  return [...check[0].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("submit-attempts schema census (the data model, the never-blind-retry rule)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SUBMIT_ATTEMPTS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("SQL transport-outcome literals equal the frozen transport vocabulary (three-way identity)", () => {
    expect(parseOutcomeLiterals(sql)).toEqual([...SUBMIT_TRANSPORT_OUTCOMES]);
  });

  it("the only representable decision is INITIAL_SINGLE_SHOT at transaction attempt 1", () => {
    expect(sql).toContain("CHECK (decision = 'INITIAL_SINGLE_SHOT')");
    expect(sql).toContain("CHECK (transaction_attempt_no = 1)");
    expect(sql).not.toMatch(/SAFE_WITH_NEW_HEAD|SAFE_TO_REBUILD|PROVEN_NOT_LANDED/);
  });

  it("both non-reuse uniqueness constraints are present on gateway_submit_attempts", () => {
    expect(sql).toContain("UNIQUE (operation_id, attempt_no)");
    expect(sql).toContain("UNIQUE (operation_id, transaction_attempt_no)");
    expect(sql).toContain("decision_id uuid NOT NULL UNIQUE");
  });

  it("mutation negative: dropping the outcome CHECK is caught", () => {
    const removed = sql.replace("('ACK','REJECT','INDETERMINATE')),", "('ACK','REJECT')),");
    const missing = SUBMIT_ATTEMPTS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ATTEMPT_OUTCOME_CLOSED_SET");
  });

  it("mutation negative: dropping the per-decision uniqueness is caught", () => {
    const removed = sql.replace("decision_id uuid NOT NULL UNIQUE,", "decision_id uuid NOT NULL,");
    const missing = SUBMIT_ATTEMPTS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ATTEMPT_ONE_PER_DECISION");
  });

  it("mutation negative: dropping the composite non-reuse constraint is caught", () => {
    const removed = sql.replace("UNIQUE (operation_id, attempt_no),\n", "");
    const missing = SUBMIT_ATTEMPTS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ATTEMPT_UNIQUE_OPERATION_ATTEMPT_NO");
    expect(missing).toContain("ATTEMPT_UNIQUE_OPERATION_TRANSACTION_ATTEMPT_NO");
  });

  it("both tables are insert-only with no updatable columns", () => {
    expect(SUBMIT_ATTEMPTS_MUTABILITY_REGIMES.map((regime) => regime.table)).toEqual([
      "submit_decisions",
      "gateway_submit_attempts",
    ]);
    for (const regime of SUBMIT_ATTEMPTS_MUTABILITY_REGIMES) {
      expect(regime.regime).toBe("insert_only");
      expect(regime.updatableColumns).toEqual([]);
    }
  });

  it("schema-apply execution obligations are inventoried, including the external-send prohibition", () => {
    expect(SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_SUBMIT_ATTEMPTS_OBLIGATIONS.some((obligation) =>
        obligation.includes("never creates a submit attempt"),
      ),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
