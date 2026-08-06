import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_WALLET_SETTLED_LEDGER_OBLIGATIONS,
  WALLET_SETTLED_LEDGER_INVARIANTS,
  WALLET_SETTLED_LEDGER_MUTABILITY_REGIMES,
  WALLET_SETTLED_LEDGER_SCHEMA_FILE,
  WALLET_SETTLED_LEDGER_SPEC_RESIDUE,
} from "../src/schema/wallet-settled-ledger.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const sqlPath = resolve(schemaDir, WALLET_SETTLED_LEDGER_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
// Comment-stripped view: prose in this file's header quotes column names and vocabularies,
// so any scan for what the DDL *does* must run against code only.
const code = sql.replace(/--[^\n]*/g, " ");

describe("wallet-settled-ledger schema census (C-10)", () => {
  it("every inventoried invariant anchors to the literal SQL text", () => {
    const missing = WALLET_SETTLED_LEDGER_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the one ledger table", () => {
    expect(code.match(/CREATE TABLE (\w+)/g)).toEqual(["CREATE TABLE wallet_settled_ledger"]);
  });

  // C-10: the settled bytes are the authoritative record. jsonb normalizes key order and
  // whitespace, so it would silently break the signed byte layout.
  it("the authoritative byte columns are text, never jsonb/json or a float type", () => {
    expect(code).toContain("settled_transaction_text text NOT NULL");
    expect(code.toLowerCase()).not.toMatch(/\bjsonb?\b/);
    expect(code.toLowerCase()).not.toMatch(/\b(real|double precision|numeric\s*\()/);
  });

  // The whole point of the object: a ledger, not a balance projection.
  it("carries no materialized balance and no CAS row_version", () => {
    expect(code).not.toMatch(/\bsettled_balance\b|\brow_version\b|\brunning_balance\b/);
    expect(code).not.toMatch(/ON\s+CONFLICT/i);
  });

  it("is insert-only: no UPDATE or DELETE statement, and mutation triggers reject both", () => {
    expect(code).not.toMatch(/\bUPDATE\s+wallet_settled_ledger\b/i);
    expect(code).not.toMatch(/\bDELETE\s+FROM\s+wallet_settled_ledger\b/i);
    expect(code).toContain("BEFORE UPDATE OR DELETE ON wallet_settled_ledger");
    expect(code).toContain("BEFORE TRUNCATE ON wallet_settled_ledger");
    expect(code.toUpperCase()).not.toMatch(/ON\s+DELETE\s+CASCADE/);
    expect(code.toUpperCase()).not.toMatch(/ON\s+UPDATE\s+CASCADE/);
  });

  // explicit reconciliation requirement: adopt operation_wallets' vocabulary, do
  // not adopt lineage_path_bodies' lowercase pair, and do not mint a third spelling.
  it("the role column reuses operation_wallets.operation_role byte-for-byte", () => {
    const operations = readFileSync(resolve(schemaDir, "operations.sql"), "utf8");
    expect(operations).toContain("operation_role text NOT NULL CHECK (operation_role IN");
    expect(operations).toContain("('RECEIVER','SOURCE','DESTINATION')");
    expect(code).toContain("operation_role text NOT NULL CHECK (operation_role IN");
    expect(code).toContain("('RECEIVER','SOURCE','DESTINATION')");
    // No lowercase lineage vocabulary and no newly invented role column name.
    expect(code).not.toMatch(/'sender'|'receiver'/);
    expect(code).not.toMatch(/\bwallet_role\b|\bleg\b|\bevidence_role\b/);
  });

  // The pg drill applies this file with its CREATE DOMAIN statements stripped, because
  // base-enums-domains.sql has already created them there. That is only sound if the two
  // declarations are the same bytes.
  it("the three re-declared domains are byte-identical to base-enums-domains.sql", () => {
    const base = readFileSync(resolve(schemaDir, "base-enums-domains.sql"), "utf8");
    const domains = sql.match(/^CREATE DOMAIN [\s\S]*?;$/gm) ?? [];
    expect(domains.map((d) => d.split(" ")[2])).toEqual([
      "sha256_hex",
      "padded_base64url_pubkey",
      "zkz_amount_positive_text",
    ]);
    for (const domain of domains) {
      expect(base, domain).toContain(domain);
    }
  });

  it("the amount column binds the strictly-positive domain, never retired zkz_amount_text", () => {
    expect(code).toContain("amount_zkz zkz_amount_positive_text NOT NULL");
    expect(code).not.toMatch(/\bzkz_amount_text\b/);
    expect(code).toContain("VALUE::numeric > 0");
  });

  it("binds the settled body and the operation participant by foreign key", () => {
    expect(code).toContain("REFERENCES operation_transactions(operation_id, attempt_no)");
    expect(code).toContain("REFERENCES operation_wallets(operation_id, wallet_id)");
    expect(code).toContain("REFERENCES operations(id)");
    expect(code).toContain("REFERENCES wallets(id)");
  });

  it("uniqueness is composite wallet/signature, enforced at the database", () => {
    expect(code).toContain("UNIQUE (wallet_public_key, settled_transaction_sha256)");
    expect(code).toContain("UNIQUE (operation_id, attempt_no, operation_role)");
  });

  // The append gate compares bytes, not collated text: an equal-under-collation but
  // byte-different copy must not pass (the byte-exact signing rule). Role and pubkey are bound to the
  // authoritative participant/wallet rows so a permanent mis-label cannot land.
  it("the append gate compares the settled bytes as bytea and requires a landed verification", () => {
    expect(code).toContain("convert_to(NEW.settled_transaction_text, 'UTF8')");
    expect(code).toContain("convert_to(tx.completed_transaction_text, 'UTF8')");
    expect(code).toContain("WALLET_SETTLED_LEDGER_NOT_VERBATIM");
    expect(code).toContain("WALLET_SETTLED_LEDGER_NOT_SETTLED");
    expect(code).toContain("WALLET_SETTLED_LEDGER_NOT_LANDED");
    expect(code).toContain("FROM operation_verifications v");
    expect(code).toContain("v.verdict = 'VERIFIED'");
  });

  it("the append gate binds operation_role and wallet_public_key to the authoritative rows", () => {
    expect(code).toContain("WALLET_SETTLED_LEDGER_ROLE_MISMATCH");
    expect(code).toContain("WALLET_SETTLED_LEDGER_PUBKEY_MISMATCH");
    expect(code).toContain("FROM operation_wallets");
    expect(code).toContain("FROM wallets");
    expect(code).toContain("strict_role IS DISTINCT FROM NEW.operation_role");
    expect(code).toContain("convert_to(NEW.wallet_public_key, 'UTF8')");
  });

  // The contract records an open specification-defect escalation precisely because the
  // specification freezes no DDL here. The file must not claim an authority the
  // specification has not granted it.
  it("does not self-declare a frozen schema contract has never authored", () => {
    expect(sql).not.toMatch(/Frozen schema contract/i);
    expect(sql).toMatch(/PROVISIONAL schema contract/);
    expect(sql).toMatch(/freezes no CREATE TABLE/);
    expect(WALLET_SETTLED_LEDGER_SPEC_RESIDUE.implementerJudgement.length).toBeGreaterThan(0);
    expect(WALLET_SETTLED_LEDGER_SPEC_RESIDUE.governingLawFixes.length).toBeGreaterThan(0);
  });

  it("mutability regime covers the ledger table", () => {
    expect(WALLET_SETTLED_LEDGER_MUTABILITY_REGIMES.map((r) => r.table)).toEqual([
      "wallet_settled_ledger",
    ]);
    expect(WALLET_SETTLED_LEDGER_MUTABILITY_REGIMES[0]?.regime).toBe("insert_only");
  });

  it("Schema execution obligations are inventoried", () => {
    expect(SCHEMA_WALLET_SETTLED_LEDGER_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_WALLET_SETTLED_LEDGER_OBLIGATIONS) {
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
