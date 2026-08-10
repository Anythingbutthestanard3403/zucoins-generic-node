// outward parity test binding the custody-eligibility.sql lease_role column
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
const baseEnums = readFileSync(
  resolve(here, "../src/schema/base-enums-domains.sql"),
  "utf8",
);

const LEASE_ROLE_COLUMN_PATTERN =
  /lease_role\s+wallet_lease_role\s+NOT NULL/;
const WALLET_LEASE_ROLE_ENUM_PATTERN =
  /CREATE TYPE wallet_lease_role AS ENUM \(([^)]+)\)/;

const parseWalletLeaseRoleEnum = (sqlText: string): string[] => {
  const match = WALLET_LEASE_ROLE_ENUM_PATTERN.exec(sqlText);
  if (match === null) {
    throw new Error("base-enums-domains.sql: wallet_lease_role ENUM not found");
  }
  return [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
};

describe("lease_role enum ↔ LEASE_ROLES parity (gate reachable)", () => {
  it("custody wallet_active_leases.lease_role is typed wallet_lease_role", () => {
    expect(LEASE_ROLE_COLUMN_PATTERN.test(sql)).toBe(true);
    expect(sql).not.toMatch(/lease_role text NOT NULL/);
  });

  it("wallet_lease_role ENUM vocabulary is exactly the frozen LEASE_ROLES enum (no drift)", () => {
    const sqlRoles = new Set(parseWalletLeaseRoleEnum(baseEnums));
    const canonRoles = new Set(LEASE_ROLES as readonly string[]);

    const inSqlNotCanon = [...sqlRoles].filter((r) => !canonRoles.has(r)).sort();
    const inCanonNotSql = [...canonRoles].filter((r) => !sqlRoles.has(r)).sort();

    expect(inSqlNotCanon, "roles in SQL ENUM but not in LEASE_ROLES").toEqual([]);
    expect(inCanonNotSql, "roles in LEASE_ROLES but not in SQL ENUM").toEqual([]);
  });

  it("wallet_lease_role ENUM contains exactly 5 roles (sanity)", () => {
    const sqlRoles = parseWalletLeaseRoleEnum(baseEnums);
    expect(sqlRoles.length).toBe(5);
  });
});
