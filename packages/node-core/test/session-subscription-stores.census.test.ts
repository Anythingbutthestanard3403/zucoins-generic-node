import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_SESSION_SUBSCRIPTION_STORES_OBLIGATIONS,
  SESSION_SUBSCRIPTION_STORES_INVARIANTS,
  SESSION_SUBSCRIPTION_STORES_MUTABILITY_REGIMES,
  SESSION_SUBSCRIPTION_STORES_SCHEMA_FILE,
} from "../src/schema/session-subscription-stores.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", SESSION_SUBSCRIPTION_STORES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("session-subscription-stores schema census (the API contract, B1)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SESSION_SUBSCRIPTION_STORES_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("both required tables are declared", () => {
    expect(sql).toContain("CREATE TABLE subscription_handles");
    expect(sql).toContain("CREATE TABLE admin_sessions");
  });

  it("subscription handle is store-hashed (no cleartext secret column)", () => {
    expect(sql).toContain("handle_hash sha256_hex NOT NULL");
    expect(sql).not.toMatch(/\bhandle_secret\b|\bsh_secret\b/i);
  });

  it("admin_sessions carries CSRF + sliding idle clock", () => {
    expect(sql).toContain("csrf_token text NOT NULL");
    expect(sql).toContain("last_seen_at timestamptz NOT NULL");
  });

  it("no cascading foreign-key delete/update actions on the session store", () => {
    // Strip SQL comments before scanning action clauses so prose cannot false-positive.
    const code = sql.replace(/--[^\n]*/g, " ");
    expect(code.toUpperCase()).not.toMatch(/ON\s+DELETE\s+CASCADE/);
    expect(code.toUpperCase()).not.toMatch(/ON\s+UPDATE\s+CASCADE/);
  });

  it("mutability regimes cover both tables", () => {
    expect(SESSION_SUBSCRIPTION_STORES_MUTABILITY_REGIMES.map((r) => r.table)).toEqual([
      "subscription_handles",
      "admin_sessions",
    ]);
  });

  it("schema-apply execution obligations are inventoried", () => {
    expect(SCHEMA_SESSION_SUBSCRIPTION_STORES_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_SESSION_SUBSCRIPTION_STORES_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
