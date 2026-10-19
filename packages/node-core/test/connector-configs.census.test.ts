// Census: binds connector-configs.contract.ts to the literal SQL (ZTR-1330).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  CONNECTOR_CONFIGS_EXECUTION_OBLIGATIONS,
  CONNECTOR_CONFIGS_INVARIANTS,
  CONNECTOR_CONFIGS_SCHEMA_FILE,
} from "../src/schema/connector-configs.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CONNECTOR_CONFIGS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("connector-configs schema census (ZTR-1330)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = CONNECTOR_CONFIGS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("creates connector_configs and extends integration_requests", () => {
    expect(sqlBody).toMatch(/CREATE TABLE connector_configs \(/);
    expect(sqlBody).toMatch(/policy_mode text NOT NULL DEFAULT 'NODE_VERIFIED'/);
    expect(sqlBody).toMatch(/ADD COLUMN IF NOT EXISTS requested_rules jsonb NOT NULL DEFAULT '\[\]'::jsonb/);
    expect(sqlBody).toMatch(/ADD COLUMN IF NOT EXISTS requested_webhook_url text NULL/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(CONNECTOR_CONFIGS_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of CONNECTOR_CONFIGS_EXECUTION_OBLIGATIONS) {
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
      "CREATE TABLE connector_configs (",
      "-- removed",
    );
    const missing = CONNECTOR_CONFIGS_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["CONNECTOR_CONFIGS_TABLE"]);
  });
});
