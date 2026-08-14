// Census: binds implementer-funding-wallet.contract.ts invariants to the literal ALTER SQL
// (ZTR-1287). Peer of wallet-money-capability.census.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_FUNDING_WALLET_SETTING_KEY,
  IMPLEMENTER_FUNDING_WALLET_EXECUTION_OBLIGATIONS,
  IMPLEMENTER_FUNDING_WALLET_INVARIANTS,
  IMPLEMENTER_FUNDING_WALLET_SCHEMA_FILE,
} from "../src/schema/implementer-funding-wallet.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", IMPLEMENTER_FUNDING_WALLET_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("implementer funding wallet schema census (ZTR-1287)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = IMPLEMENTER_FUNDING_WALLET_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("extends implementers only — no CREATE TABLE", () => {
    expect(sqlBody).toMatch(/ALTER TABLE implementers\b/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
  });

  it("FK is RESTRICT fail-closed against wallets", () => {
    expect(sqlBody).toContain("REFERENCES wallets");
    expect(sqlBody).toContain("ON DELETE RESTRICT");
    expect(sqlBody).not.toMatch(/ON DELETE\s+CASCADE/i);
    expect(sqlBody).not.toMatch(/ON DELETE\s+SET\s+NULL/i);
  });

  it("documents the node default setting key constant", () => {
    expect(DEFAULT_FUNDING_WALLET_SETTING_KEY).toBe(
      "integration.default_funding_wallet_id",
    );
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(IMPLEMENTER_FUNDING_WALLET_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of IMPLEMENTER_FUNDING_WALLET_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replaceAll("implementers_funding_wallet_id_fkey", "-- removed");
    const missing = IMPLEMENTER_FUNDING_WALLET_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["FK_WALLETS_RESTRICT"]);
  });
});
