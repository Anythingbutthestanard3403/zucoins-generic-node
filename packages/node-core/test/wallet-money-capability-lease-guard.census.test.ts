// Census: binds wallet-money-capability-lease-guard.contract.ts invariants to the
// literal CREATE OR REPLACE SQL (ZTR-1268).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  WALLET_MONEY_CAPABILITY_LEASE_GUARD_INVARIANTS,
  WALLET_MONEY_CAPABILITY_LEASE_GUARD_PACK_NOTES,
  WALLET_MONEY_CAPABILITY_LEASE_GUARD_SCHEMA_FILE,
  WALLET_MONEY_CAPABILITY_LEASE_GUARD_SOURCE,
} from "../src/schema/wallet-money-capability-lease-guard.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", WALLET_MONEY_CAPABILITY_LEASE_GUARD_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

describe("wallet-money-capability-lease-guard census (ZTR-1268)", () => {
  it("contract source and pack notes are non-empty", () => {
    expect(WALLET_MONEY_CAPABILITY_LEASE_GUARD_SOURCE.length).toBeGreaterThan(0);
    expect(WALLET_MONEY_CAPABILITY_LEASE_GUARD_PACK_NOTES.length).toBeGreaterThan(0);
  });

  it("every invariant sqlAnchor appears in the SQL body", () => {
    for (const inv of WALLET_MONEY_CAPABILITY_LEASE_GUARD_INVARIANTS) {
      expect(sql, inv.id).toContain(inv.sqlAnchor);
      expect(inv.rule.length).toBeGreaterThan(10);
    }
  });

  it("retains prior custody exception codes", () => {
    for (const code of [
      "CUSTODY_LEASE_ORIGIN_REJECTED",
      "CUSTODY_LEASE_WALLET_STATE_REJECTED",
      "CUSTODY_LEASE_RECOVERY_UNVERIFIED",
      "CUSTODY_LEASE_DESTINATION_NOT_BLESSED",
      "CUSTODY_LEASE_ROLE_UNKNOWN",
    ]) {
      expect(sql).toContain(code);
    }
  });

  it("adds capability exception codes for receive/send/move", () => {
    expect(sql).toContain("CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED");
    expect(sql).toContain("CUSTODY_LEASE_SEND_CAPABILITY_REJECTED");
    expect(sql).toContain("CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED");
  });
});
