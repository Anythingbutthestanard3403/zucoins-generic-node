// Census: binds send-operations-rule-id.contract.ts to the literal SQL (ZTR-1329).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SEND_OPERATIONS_RULE_ID_EXECUTION_OBLIGATIONS,
  SEND_OPERATIONS_RULE_ID_INVARIANTS,
  SEND_OPERATIONS_RULE_ID_SCHEMA_FILE,
} from "../src/schema/send-operations-rule-id.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", SEND_OPERATIONS_RULE_ID_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("send-operations-rule-id schema census (ZTR-1329)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SEND_OPERATIONS_RULE_ID_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("is a pure column extension — no CREATE TABLE / enum", () => {
    expect(sqlBody).toMatch(/ADD COLUMN IF NOT EXISTS rule_id text/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
  });

  it("checks the rule id grammar on both tables", () => {
    expect(sqlBody).toMatch(/send_operations_rule_id_form/);
    expect(sqlBody).toMatch(/operations_rule_id_form/);
    expect(sqlBody).toMatch(/rule_id IS NULL/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(SEND_OPERATIONS_RULE_ID_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of SEND_OPERATIONS_RULE_ID_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replaceAll(
      "ALTER TABLE send_operations\n  ADD COLUMN IF NOT EXISTS rule_id text",
      "-- removed",
    );
    const missing = SEND_OPERATIONS_RULE_ID_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["SEND_COLUMN_NULLABLE_TEXT"]);
  });
});
