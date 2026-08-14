// Census: binds destinations-pending-backfill.contract.ts to the literal SQL (ZTR-1306).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DESTINATIONS_PENDING_BACKFILL_EXECUTION_OBLIGATIONS,
  DESTINATIONS_PENDING_BACKFILL_INVARIANTS,
  DESTINATIONS_PENDING_BACKFILL_SCHEMA_FILE,
} from "../src/schema/destinations-pending-backfill.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", DESTINATIONS_PENDING_BACKFILL_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("destinations-pending-backfill schema census (ZTR-1306)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = DESTINATIONS_PENDING_BACKFILL_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("is a pure data INSERT — no CREATE TABLE / ALTER / enum", () => {
    expect(sqlBody).toMatch(/INSERT INTO destinations\b/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
    expect(sqlBody).not.toMatch(/ALTER TABLE\b/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
  });

  it("writes PENDING only and never BLESSED", () => {
    expect(sqlBody).toContain("'PENDING'");
    expect(sqlBody).not.toMatch(/'BLESSED'/);
    expect(sqlBody).not.toMatch(/blessed_at/);
  });

  it("scopes to node_generated wallets missing a dest row", () => {
    expect(sqlBody).toContain("key_origin = 'node_generated'");
    expect(sqlBody).toMatch(/NOT EXISTS/);
    expect(sqlBody).toMatch(/d\.wallet_id = w\.id/);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(DESTINATIONS_PENDING_BACKFILL_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of DESTINATIONS_PENDING_BACKFILL_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replaceAll("key_origin = 'node_generated'", "-- removed");
    const missing = DESTINATIONS_PENDING_BACKFILL_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["BACKFILL_NODE_GENERATED_MISSING_DEST"]);
  });
});
