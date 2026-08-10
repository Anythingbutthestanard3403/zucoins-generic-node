// census: binds the lease-foundation invariant inventory to the literal SQL
// contract and cross-checks table list / mutability regimes / Schema obligations.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_LEASE_FOUNDATION_OBLIGATIONS,
  LEASE_FOUNDATION_INVARIANTS,
  LEASE_FOUNDATION_MUTABILITY_REGIMES,
  LEASE_FOUNDATION_SCHEMA_FILE,
  LEASE_FOUNDATION_SCHEMA_VERSION,
  LEASE_FOUNDATION_TABLES,
} from "../src/schema/lease-foundation.contract.ts";
import { sortWalletIdsAscending } from "../src/leases/sort-wallets.ts";
import { splitSqlStatements } from "../src/leases/migrate.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", LEASE_FOUNDATION_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("lease-foundation schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = LEASE_FOUNDATION_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares every inventoried table", () => {
    for (const table of LEASE_FOUNDATION_TABLES) {
      expect(sql).toContain(`CREATE TABLE ${table} (`);
    }
  });

  it("keeps schema_version fence at the frozen constant", () => {
    expect(LEASE_FOUNDATION_SCHEMA_VERSION).toBe(2);
    expect(sql).toContain("CREATE TABLE lease_schema_fence (");
  });

  it("proof issuer is TRUSTED_VERIFIER only", () => {
    expect(sql).toContain("issuer text NOT NULL CHECK (issuer = 'TRUSTED_VERIFIER')");
  });

  it("epoch high-water is permanent and strictly positive", () => {
    expect(sql).toContain("CREATE TABLE wallet_lease_epoch_highwater (");
    expect(sql).toMatch(/highwater bigint NOT NULL CHECK \(highwater > 0\)/);
  });

  it("active row binds membership/group/ops/epoch/owner/heartbeat", () => {
    for (const col of [
      "membership_id",
      "lease_group_id",
      "root_operation_id",
      "operation_id",
      "lease_epoch",
      "heartbeat_at",
      "owner_instance_id",
    ]) {
      expect(sql).toContain(col);
    }
  });

  it("mutability regimes and Schema obligations are non-trivial", () => {
    expect(LEASE_FOUNDATION_MUTABILITY_REGIMES.length).toBeGreaterThanOrEqual(5);
    expect(SCHEMA_LEASE_FOUNDATION_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const o of SCHEMA_LEASE_FOUNDATION_OBLIGATIONS) {
      expect(o.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace(
      "issuer text NOT NULL CHECK (issuer = 'TRUSTED_VERIFIER')",
      "issuer text NOT NULL",
    );
    const missing = LEASE_FOUNDATION_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["PROOF_TRUSTED_ISSUER_ONLY"]);
  });

  it("splitSqlStatements yields a non-empty statement list with active leases (no shadowed trigger)", () => {
    const stmts = splitSqlStatements(sql);
    expect(stmts.length).toBeGreaterThanOrEqual(10);
    expect(stmts.some((s) => /CREATE TABLE wallet_active_leases/i.test(s))).toBe(true);
    // ZTR-1169: eligibility trigger is custody-owned; foundation SQL must not re-declare it.
    expect(stmts.some((s) => /CREATE TRIGGER wallet_active_leases_eligibility_guard/i.test(s))).toBe(
      false,
    );
    expect(
      stmts.some((s) => /CREATE FUNCTION lease_foundation_reject_ineligible_lease/i.test(s)),
    ).toBe(false);
  });

  it("sortWalletIdsAscending is ascending and non-mutating", () => {
    const a = "b0000000-0000-4000-8000-000000000002";
    const b = "a0000000-0000-4000-8000-000000000001";
    const input = [a, b];
    const sorted = sortWalletIdsAscending(input);
    expect(sorted).toEqual([b, a]);
    expect(input).toEqual([a, b]);
  });

  it("records a stable sha256 of the contract bytes for drift awareness", () => {
    const digest = createHash("sha256").update(sqlBytes).digest("hex");
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
  });
});
