// Census: binds the frozen per-wallet index inventory to the literal SQL contract text so
// the two truth carriers cannot drift apart silently. Static text proof; the
// real-PostgreSQL behaviour proof (index exists, planner uses it for the wallet_id RI
// predicate, seq scan without it) is drill 11 of wallet-settled-ledger.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  WALLET_SETTLED_LEDGER_INDEXES_EXECUTION_OBLIGATIONS,
  WALLET_SETTLED_LEDGER_INDEXES_SCHEMA_FILE,
  WALLET_SETTLED_LEDGER_INDEX_INVARIANTS,
} from "../src/schema/wallet-settled-ledger-indexes.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", WALLET_SETTLED_LEDGER_INDEXES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("wallet-settled-ledger-indexes schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = WALLET_SETTLED_LEDGER_INDEX_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("mutation negative: dropping the wallet_id index is caught", () => {
    const removed = sql.replace(
      "CREATE INDEX wallet_settled_ledger_wallet_id_idx\n  ON wallet_settled_ledger(wallet_id);",
      "",
    );
    const missing = WALLET_SETTLED_LEDGER_INDEX_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(
      expect.arrayContaining([
        "WALLET_ID_INDEX",
        "WALLET_ID_INDEX_NOT_PARTIAL",
        "WALLET_ID_INDEX_SINGLE_COLUMN",
        "PURE_INDEX_EXTENSION",
      ]),
    );
  });

  // The one-column choice is the ticket's judgement call, so pin it: a suffix column added
  // later must come with the query census that justifies it, not slip in as a widening.
  it("is a pure index extension: one unqualified CREATE INDEX, no table/column/trigger", () => {
    const code = sql.replace(/--[^\n]*/g, " ");
    expect(code.match(/CREATE INDEX/g)).toEqual(["CREATE INDEX"]);
    expect(code).not.toMatch(/CREATE TABLE|ALTER TABLE|CREATE TRIGGER|CREATE DOMAIN/);
    expect(code).not.toMatch(/\bWHERE\b/i);
    expect(code).not.toMatch(/\bINCLUDE\b/i);
    expect(code).not.toMatch(/CONCURRENTLY/i);
  });

  it("execution obligations are inventoried", () => {
    expect(WALLET_SETTLED_LEDGER_INDEXES_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
