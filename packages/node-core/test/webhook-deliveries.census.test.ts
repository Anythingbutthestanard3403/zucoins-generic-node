// Census: binds webhook-deliveries.contract.ts to the literal SQL (ZTR-1333).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  WEBHOOK_DELIVERIES_EXECUTION_OBLIGATIONS,
  WEBHOOK_DELIVERIES_INVARIANTS,
  WEBHOOK_DELIVERIES_SCHEMA_FILE,
} from "../src/schema/webhook-deliveries.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", WEBHOOK_DELIVERIES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("webhook-deliveries schema census (ZTR-1333)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = WEBHOOK_DELIVERIES_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("creates webhook_deliveries with a pending default and a source unique key", () => {
    expect(sqlBody).toMatch(/CREATE TABLE webhook_deliveries \(/);
    expect(sqlBody).toMatch(/status text NOT NULL DEFAULT 'PENDING'/);
    expect(sqlBody).toMatch(/webhook_deliveries_source_uidx/);
    expect(sqlBody).toMatch(/REFERENCES implementers \(id\) ON DELETE CASCADE/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
    expect(sqlBody).not.toMatch(/\bORDER BY\b/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(WEBHOOK_DELIVERIES_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of WEBHOOK_DELIVERIES_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replaceAll("CREATE TABLE webhook_deliveries (", "-- removed");
    const missing = WEBHOOK_DELIVERIES_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["WEBHOOK_DELIVERIES_TABLE"]);
  });
});
