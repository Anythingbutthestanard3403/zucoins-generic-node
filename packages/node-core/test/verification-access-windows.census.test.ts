// Census: binds the frozen verification-access-window invariant inventory to the
// literal SQL contract text.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_VERIFICATION_ACCESS_WINDOWS_OBLIGATIONS,
  VERIFICATION_ACCESS_WINDOWS_INVARIANTS,
  VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES,
  VERIFICATION_ACCESS_WINDOWS_SCHEMA_FILE,
} from "../src/schema/verification-access-windows.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", VERIFICATION_ACCESS_WINDOWS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("verification-access-windows schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = VERIFICATION_ACCESS_WINDOWS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares the access-window table", () => {
    expect(sql).toContain("CREATE TABLE verification_material_access_windows");
  });

  it("stores the identifier hashed — no plaintext nonce/token/secret column", () => {
    expect(sql).toContain("nonce_hash sha256_hex NOT NULL");
    // Strip comments before scanning so prose cannot false-positive.
    const code = sql.replace(/--[^\n]*/g, " ");
    expect(code).not.toMatch(/\bnonce\b(?!_hash)/i);
    expect(code).not.toMatch(/\btoken\b/i);
    expect(code).not.toMatch(/\bsecret\b/i);
    expect(code).not.toMatch(/\bplaintext\b/i);
  });

  it("mirrors approval_challenges temporal + status shape", () => {
    expect(sql).toContain("CHECK (expires_at > issued_at)");
    expect(sql).toContain("CHECK (status IN ('OPEN', 'EXPIRED', 'REVOKED'))");
    expect(sql).toContain("CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))");
    expect(sql).toContain("UNIQUE (operation_id)");
    expect(sql).toContain("UNIQUE (nonce_hash)");
  });

  it("one OPEN window per operation — partial unique index present", () => {
    expect(sql).toContain("CREATE UNIQUE INDEX verification_access_windows_one_open_per_operation");
    expect(sql).toContain("WHERE status = 'OPEN';");
  });

  it("mutability regime covers the table and forbids evidence deletion", () => {
    expect(VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES.map((r) => r.table)).toEqual([
      "verification_material_access_windows",
    ]);
    expect(VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES[0]?.updatableColumns).toEqual([
      "status",
      "revoked_at",
    ]);
    expect(VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES[0]?.rule).toMatch(/never deletes/i);
  });

  it("Schema execution obligations are inventoried", () => {
    expect(SCHEMA_VERIFICATION_ACCESS_WINDOWS_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_VERIFICATION_ACCESS_WINDOWS_OBLIGATIONS) {
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
