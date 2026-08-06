// Census: binds the frozen approval-store invariant inventory to the literal SQL
// contract text, so the two truth carriers (contract inventory, SQL text) cannot drift
// apart silently. Live-database execution is a separate obligation, inventoried in the
// contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  APPROVAL_STORES_INVARIANTS,
  APPROVAL_STORES_MUTABILITY_REGIMES,
  APPROVAL_STORES_SCHEMA_FILE,
  SCHEMA_APPROVAL_STORES_OBLIGATIONS,
} from "../src/schema/approval-stores.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", APPROVAL_STORES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const baseSql = readFileSync(resolve(here, "../src/schema/base-enums-domains.sql"), "utf8");

describe("approval-stores schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = APPROVAL_STORES_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("exactly two approval methods are owned by the shared foundation", () => {
    expect(baseSql).toContain(
      "CREATE TYPE approval_method AS ENUM ('TOTP_ONLY', 'TOTP_AND_DEVICE');",
    );
    expect(sql).not.toContain("CREATE TYPE approval_method");
  });

  it("exactly four challenge statuses are owned by the shared foundation", () => {
    expect(baseSql).toContain(
      "CREATE TYPE approval_challenge_status AS ENUM ('ISSUED', 'CONSUMED', 'SUPERSEDED', 'EXPIRED');",
    );
    expect(sql).not.toContain("CREATE TYPE approval_challenge_status");
  });

  it("consumes shared domains from the single foundation owner", () => {
    expect(baseSql).toContain("CREATE DOMAIN sha256_hex AS text");
    expect(baseSql).toContain("CREATE DOMAIN padded_base64url_pubkey AS text");
    expect(baseSql).toContain("CREATE DOMAIN padded_base64url_signature AS text");
    expect(sql).not.toContain("CREATE DOMAIN");
  });

  it("one ISSUED challenge per operation — partial unique index present", () => {
    expect(sql).toContain(
      "CREATE UNIQUE INDEX approval_challenges_one_issued_per_operation",
    );
    expect(sql).toContain("WHERE status = 'ISSUED';");
  });

  it("TOTP single-use — partial unique index on (node_id, totp_timestep)", () => {
    expect(sql).toContain("CREATE UNIQUE INDEX operation_approvals_totp_single_use");
    expect(sql).toContain("ON operation_approvals (node_id, totp_timestep);");
  });

  it("approval operation_id is UNIQUE — one approval per operation", () => {
    expect(sql).toContain("operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),");
  });

  it("challenge_id is UNIQUE on operation_approvals", () => {
    expect(sql).toContain("challenge_id uuid NOT NULL UNIQUE,");
  });

  it("device-key biconditional CHECK is present", () => {
    expect(sql).toContain("method = 'TOTP_AND_DEVICE' AND device_key_id IS NOT NULL");
    expect(sql).toContain("method = 'TOTP_ONLY' AND device_key_id IS NULL");
  });

  it("composite FK from approval to challenge is present", () => {
    expect(sql).toContain(
      "FOREIGN KEY (challenge_id, node_id, operation_id, challenge_status)",
    );
    expect(sql).toContain(
      "REFERENCES approval_challenges(id, node_id, operation_id, status)",
    );
  });

  it("mutation negative: dropping the one-issued partial index is caught", () => {
    const removed = sql.replace(
      "CREATE UNIQUE INDEX approval_challenges_one_issued_per_operation\n  ON approval_challenges(operation_id)\n  WHERE status = 'ISSUED';",
      "",
    );
    const missing = APPROVAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("CHALLENGE_ONE_ISSUED_PER_OPERATION");
  });

  it("mutation negative: dropping the TOTP single-use index is caught", () => {
    const removed = sql.replace(
      "CREATE UNIQUE INDEX operation_approvals_totp_single_use\n  ON operation_approvals (node_id, totp_timestep);",
      "",
    );
    const missing = APPROVAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("APPROVAL_TOTP_SINGLE_USE");
  });

  it("mutation negative: dropping the device biconditional is caught", () => {
    const removed = sql.replace(
      "CHECK (\n    (method = 'TOTP_AND_DEVICE' AND device_key_id IS NOT NULL\n      AND device_signature IS NOT NULL)\n    OR\n    (method = 'TOTP_ONLY' AND device_key_id IS NULL\n      AND device_signature IS NULL)\n  ),",
      "",
    );
    const missing = APPROVAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("APPROVAL_METHOD_DEVICE_BICONDITIONAL");
  });

  it("three mutability regimes are inventoried", () => {
    expect(APPROVAL_STORES_MUTABILITY_REGIMES).toHaveLength(3);
    const tables = APPROVAL_STORES_MUTABILITY_REGIMES.map((r) => r.table);
    expect(tables).toContain("operator_device_keys");
    expect(tables).toContain("approval_challenges");
    expect(tables).toContain("operation_approvals");
  });

  it("operation_approvals is insert-only", () => {
    const approvals = APPROVAL_STORES_MUTABILITY_REGIMES.find(
      (r) => r.table === "operation_approvals",
    );
    expect(approvals?.regime).toBe("insert_only");
    expect(approvals?.updatableColumns).toEqual([]);
  });

  it("execution obligations are inventoried", () => {
    expect(SCHEMA_APPROVAL_STORES_OBLIGATIONS.length).toBeGreaterThanOrEqual(7);
    for (const obligation of SCHEMA_APPROVAL_STORES_OBLIGATIONS) {
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
