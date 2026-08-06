// census: binds the frozen privileges invariant inventory to the literal
// SQL contract text so the structural DELETE/TRUNCATE grant model cannot drift from its
// inventory. Live-database discharge is inventoried in privileges.contract.ts and covered
// by privilege-readiness.pg.test.ts when TEST_DATABASE_URL is set.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SCHEMA_PRIVILEGES_OBLIGATIONS,
  PRIVILEGES_SCHEMA_FILE,
  PRIVILEGES_SCHEMA_INVARIANTS,
  PRIVILEGES_SCHEMA_SOURCE,
} from "../src/schema/privileges.contract.ts";
import { NODE_CORE_APP_ROLE } from "../src/data/privilege-readiness.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", PRIVILEGES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("privileges schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = PRIVILEGES_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("names the same role the boot check verifies", () => {
    expect(sql).toContain(`CREATE ROLE ${NODE_CORE_APP_ROLE} NOLOGIN`);
    expect(NODE_CORE_APP_ROLE).toBe("node_core_app");
  });

  it("never grants CREATEROLE, DELETE, or TRUNCATE to the app role", () => {
    // GRANT list for node_core_app must be SELECT/INSERT/UPDATE only.
    expect(sql).toMatch(
      /GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO node_core_app/,
    );
    expect(sql).toMatch(
      /REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_app/,
    );
    // No CREATEROLE grant anywhere in this contract.
    expect(sql).not.toMatch(/GRANT\s+CREATEROLE/i);
    expect(sql).not.toMatch(/CREATE ROLE node_core_app[^\n]*CREATEROLE/i);
  });

  it("degrades on insufficient_privilege and concurrent CREATE ROLE races", () => {
    expect(sql).toContain("WHEN insufficient_privilege THEN");
    expect(sql).toContain("WHEN duplicate_object THEN");
    expect(sql).toContain("WHEN unique_violation THEN");
  });

  it("mutation negative: removing the REVOKE clause is caught by the census", () => {
    const mutated = sql.replace(
      "REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_app;",
      "",
    );
    const missing = PRIVILEGES_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["REVOKE_DELETE_TRUNCATE"]);
  });

  it("Schema execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_PRIVILEGES_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_PRIVILEGES_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(PRIVILEGES_SCHEMA_SOURCE.length).toBeGreaterThan(10);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
