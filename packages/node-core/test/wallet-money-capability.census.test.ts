// Census: binds wallet-money-capability.contract.ts invariants to the literal ALTER SQL
// (ZTR-1267). Peer of integration-requests.census / approval-stores-auto-policy.census.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  WALLET_MONEY_CAPABILITY_DEFAULT_MODE,
  WALLET_MONEY_CAPABILITY_EXECUTION_OBLIGATIONS,
  WALLET_MONEY_CAPABILITY_INVARIANTS,
  WALLET_MONEY_CAPABILITY_SCHEMA_FILE,
  WALLET_MONEY_MODES,
} from "../src/schema/wallet-money-capability.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", WALLET_MONEY_CAPABILITY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("wallet money capability schema census (ZTR-1267)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = WALLET_MONEY_CAPABILITY_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("extends wallets only — no CREATE TABLE", () => {
    expect(sqlBody).toMatch(/ALTER TABLE wallets\b/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
  });

  it("closes money_mode against the four frozen presets", () => {
    for (const mode of WALLET_MONEY_MODES) {
      expect(sqlBody).toContain(`'${mode}'`);
    }
    expect(WALLET_MONEY_CAPABILITY_DEFAULT_MODE).toBe("FULL");
    expect(sqlBody).toContain("DEFAULT 'FULL'");
  });

  it("names the three consistency + closed + row_version CHECKs", () => {
    expect(sqlBody).toContain("wallets_money_mode_closed");
    expect(sqlBody).toContain("wallets_money_mode_flags_consistent");
    expect(sqlBody).toContain("wallets_row_version_positive");
  });

  it("documents FULL flag triple under money_mode = FULL", () => {
    expect(sqlBody).toMatch(
      /money_mode = 'FULL'[\s\S]*allow_external_receive IS TRUE[\s\S]*allow_external_send IS TRUE[\s\S]*allow_internal_move IS TRUE/,
    );
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(WALLET_MONEY_CAPABILITY_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of WALLET_MONEY_CAPABILITY_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replaceAll("wallets_money_mode_flags_consistent", "-- removed");
    const missing = WALLET_MONEY_CAPABILITY_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["MODE_FLAGS_CONSISTENT"]);
  });
});
