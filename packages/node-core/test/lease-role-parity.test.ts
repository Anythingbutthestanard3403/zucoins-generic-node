// outward parity test binding the custody-eligibility.sql lease_role CHECK
// vocabulary to the frozen LEASE_ROLES enum in generic-node-contracts. This is the test
// that was missing and allowed the vocabulary drift (RECEIVE vs RECEIVE_WINDOW,
// MOVE_AUTOMATIC_SINK vs MOVE_DESTINATION, missing RECONCILIATION) to be invisible.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { LEASE_ROLES } from "../../generic-node-contracts/src/wallet-state/leases.ts";
import { CUSTODY_SCHEMA_FILE } from "../src/schema/custody-eligibility.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CUSTODY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

const LEASE_ROLE_CHECK_PATTERN = /CHECK \(lease_role IN \(([^)]+)\)\)/;

const parseLeaseRoleCheck = (sqlText: string): string[] => {
  const match = LEASE_ROLE_CHECK_PATTERN.exec(sqlText);
  if (match === null) {
    throw new Error(
      "custody-eligibility.sql: lease_role CHECK constraint not found",
    );
  }
  return [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
};

describe("lease_role CHECK ↔ LEASE_ROLES parity (gate reachable)", () => {
  it("SQL CHECK vocabulary is exactly the frozen LEASE_ROLES enum (no drift)", () => {
    const sqlRoles = new Set(parseLeaseRoleCheck(sql));
    const canonRoles = new Set(LEASE_ROLES as readonly string[]);

    const inSqlNotCanon = [...sqlRoles].filter((r) => !canonRoles.has(r)).sort();
    const inCanonNotSql = [...canonRoles].filter((r) => !sqlRoles.has(r)).sort();

    expect(inSqlNotCanon, "roles in SQL CHECK but not in LEASE_ROLES").toEqual([]);
    expect(inCanonNotSql, "roles in LEASE_ROLES but not in SQL CHECK").toEqual([]);
  });

  it("SQL CHECK contains exactly 5 roles (sanity)", () => {
    const sqlRoles = parseLeaseRoleCheck(sql);
    expect(sqlRoles.length).toBe(5);
  });
});
