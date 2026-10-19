// Census: binds connector-rule-requests.contract.ts to the literal SQL (ZTR-1331).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  CONNECTOR_RULE_REQUESTS_EXECUTION_OBLIGATIONS,
  CONNECTOR_RULE_REQUESTS_INVARIANTS,
  CONNECTOR_RULE_REQUESTS_SCHEMA_FILE,
} from "../src/schema/connector-rule-requests.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CONNECTOR_RULE_REQUESTS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("connector-rule-requests schema census (ZTR-1331)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = CONNECTOR_RULE_REQUESTS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("creates connector_rule_requests with a pending default and a window bound", () => {
    expect(sqlBody).toMatch(/CREATE TABLE connector_rule_requests \(/);
    expect(sqlBody).toMatch(/status text NOT NULL DEFAULT 'PENDING'/);
    expect(sqlBody).toMatch(/connector_rule_requests_window_hours_chk/);
    expect(sqlBody).toMatch(/REFERENCES implementers \(id\) ON DELETE CASCADE/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
    expect(sqlBody).not.toMatch(/\bORDER BY\b/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(CONNECTOR_RULE_REQUESTS_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of CONNECTOR_RULE_REQUESTS_EXECUTION_OBLIGATIONS) {
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
      "CREATE TABLE connector_rule_requests (",
      "-- removed",
    );
    const missing = CONNECTOR_RULE_REQUESTS_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["CONNECTOR_RULE_REQUESTS_TABLE"]);
  });
});
