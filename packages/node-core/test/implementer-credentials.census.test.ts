import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { IMPLEMENTER_SCOPES } from "@zucoins/generic-node-contracts/api-schema";

import {
  IMPLEMENTER_CREDENTIAL_AUDIT_ACTIONS,
  IMPLEMENTER_CREDENTIAL_COLUMNS,
  IMPLEMENTER_CREDENTIAL_STATUSES,
  IMPLEMENTER_CREDENTIAL_TABLE,
} from "../src/schema/implementer-credentials.contract.js";

// Pulls the quoted literals out of one SQL clause so they can be compared as a list against a
// frozen constant, rather than grepped one at a time (a grep passes even when the SQL carries
// extra members the constant does not).
function sqlLiterals(clause: RegExp): string[] {
  const matched = clause.exec(sql);
  expect(matched, `clause ${String(clause)} not found in the schema file`).not.toBeNull();
  return [...matched![1]!.matchAll(/'([^']+)'/g)].map((m) => m[1]!);
}

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  resolve(here, "../src/schema/implementer-credentials.sql"),
  "utf8",
);

describe("implementer credential schema", () => {
  it("creates the durable table with every lifecycle column", () => {
    expect(sql).toContain(`CREATE TABLE ${IMPLEMENTER_CREDENTIAL_TABLE}`);
    for (const column of IMPLEMENTER_CREDENTIAL_COLUMNS) {
      expect(sql).toMatch(new RegExp(`\\b${column}\\b`));
    }
  });

  it("closes statuses, scopes, tenant ownership, and non-recoverable fingerprint shape", () => {
    for (const status of IMPLEMENTER_CREDENTIAL_STATUSES) {
      expect(sql).toContain(`'${status}'`);
    }
    expect(sql).toContain("REFERENCES implementers(id)");
    expect(sql).toContain("credential_hash ~ '^[0-9a-f]{64}$'");
    expect(sql).toContain("cardinality(scopes) > 0");
    expect(sql).not.toMatch(/\b(raw_key|bearer_secret|secret_key)\b/);
  });

  // The engine-side scope closure must be the SAME eight values as the frozen api-contract list the
  // service validates against, in the same order — not a third hand-typed copy that can drift
  // from the contract when is amended.
  it("closes the SQL scope list against the frozen api-contract vocabulary", () => {
    expect(sqlLiterals(/scopes <@ ARRAY\[([\s\S]*?)\]::text\[\]/)).toEqual([
      ...IMPLEMENTER_SCOPES,
    ]);
  });

  // Every declared status must have a writer. EXPIRED had none — expiry is read-time, carried by
  // expires_at — so it is gone from the enum, the composite CHECK and the contract.
  it("declares exactly the writable statuses, with no unreachable EXPIRED", () => {
    expect(
      sqlLiterals(/CREATE TYPE implementer_credential_status AS ENUM\s*\(([^)]*)\)/),
    ).toEqual([...IMPLEMENTER_CREDENTIAL_STATUSES]);
    expect(sql).not.toContain("'EXPIRED'");
  });

  it("keeps the issue, rotate, and revoke audit action set closed", () => {
    expect(IMPLEMENTER_CREDENTIAL_AUDIT_ACTIONS).toEqual([
      "IMPLEMENTER_CREDENTIAL_ISSUED",
      "IMPLEMENTER_CREDENTIAL_ROTATED",
      "IMPLEMENTER_CREDENTIAL_REVOKED",
    ]);
  });
});
