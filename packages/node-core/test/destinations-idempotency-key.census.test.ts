// Census: binds destinations-idempotency-key.contract.ts to the literal SQL (ZTR-1310).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DESTINATIONS_IDEMPOTENCY_KEY_EXECUTION_OBLIGATIONS,
  DESTINATIONS_IDEMPOTENCY_KEY_INVARIANTS,
  DESTINATIONS_IDEMPOTENCY_KEY_SCHEMA_FILE,
} from "../src/schema/destinations-idempotency-key.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", DESTINATIONS_IDEMPOTENCY_KEY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("destinations-idempotency-key schema census (ZTR-1310)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = DESTINATIONS_IDEMPOTENCY_KEY_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("is a pure column + index extension — no CREATE TABLE / enum", () => {
    expect(sqlBody).toMatch(/ADD COLUMN IF NOT EXISTS idempotency_key\b/);
    expect(sqlBody).toMatch(/CREATE UNIQUE INDEX IF NOT EXISTS destinations_node_idempotency_key_uidx\b/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
  });

  it("scopes uniqueness to (node_id, idempotency_key) when the key is present", () => {
    expect(sqlBody).toMatch(/\(node_id, idempotency_key\)/);
    expect(sqlBody).toMatch(/WHERE idempotency_key IS NOT NULL/);
  });

  it("does not invent an implementer/route ledger", () => {
    expect(sqlBody).not.toMatch(/implementer_id/);
    expect(sqlBody).not.toMatch(/http_method/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(DESTINATIONS_IDEMPOTENCY_KEY_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of DESTINATIONS_IDEMPOTENCY_KEY_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replaceAll("ADD COLUMN IF NOT EXISTS idempotency_key text", "-- removed");
    const missing = DESTINATIONS_IDEMPOTENCY_KEY_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["COLUMN_NULLABLE_TEXT"]);
  });
});
