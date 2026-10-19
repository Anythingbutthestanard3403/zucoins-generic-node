// Census: binds connector-reserve-wallets.contract.ts to the literal SQL (ZTR-1324).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  CONNECTOR_RESERVE_WALLETS_EXECUTION_OBLIGATIONS,
  CONNECTOR_RESERVE_WALLETS_INVARIANTS,
  CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE,
} from "../src/schema/connector-reserve-wallets.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CONNECTOR_RESERVE_WALLETS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("connector reserve wallets schema census (ZTR-1324)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = CONNECTOR_RESERVE_WALLETS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("creates the junction and extends wallets and implementers", () => {
    expect(sql).toContain("CREATE TABLE implementer_reserve_wallets");
    expect(sql).toContain("ADD COLUMN IF NOT EXISTS display_label text NULL");
    expect(sql).toContain(
      "ADD COLUMN IF NOT EXISTS allow_custom_routing boolean NOT NULL DEFAULT false",
    );
  });

  it("wallet delete is RESTRICT and connector delete is CASCADE", () => {
    expect(sql).toContain("REFERENCES wallets (id) ON DELETE RESTRICT");
    expect(sql).toContain("REFERENCES implementers (id) ON DELETE CASCADE");
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(CONNECTOR_RESERVE_WALLETS_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of CONNECTOR_RESERVE_WALLETS_EXECUTION_OBLIGATIONS) {
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
