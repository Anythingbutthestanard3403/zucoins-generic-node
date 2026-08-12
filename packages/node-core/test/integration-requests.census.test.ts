import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { IMPLEMENTER_SCOPES } from "@zucoins/generic-node-contracts/api-schema";

import {
  INTEGRATION_REQUESTS_COLUMNS,
  INTEGRATION_REQUESTS_EXECUTION_OBLIGATIONS,
  INTEGRATION_REQUESTS_INVARIANTS,
  INTEGRATION_REQUESTS_SCHEMA_FILE,
  INTEGRATION_REQUESTS_TABLE,
  INTEGRATION_REQUEST_STATUSES,
  INTEGRATION_REQUEST_TRANSITIONS,
} from "../src/schema/integration-requests.contract.js";

function sqlLiterals(clause: RegExp): string[] {
  const matched = clause.exec(sql);
  expect(matched, `clause ${String(clause)} not found in the schema file`).not.toBeNull();
  return [...matched![1]!.matchAll(/'([^']+)'/g)].map((m) => m[1]!);
}

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", INTEGRATION_REQUESTS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("integration requests schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = INTEGRATION_REQUESTS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("creates the durable table with every lifecycle column", () => {
    expect(sqlBody).toContain(`CREATE TABLE ${INTEGRATION_REQUESTS_TABLE}`);
    for (const column of INTEGRATION_REQUESTS_COLUMNS) {
      expect(sqlBody).toMatch(new RegExp(`\\b${column}\\b`));
    }
  });

  it("closes statuses against the contract vocabulary", () => {
    expect(
      sqlLiterals(/status IN \(([\s\S]*?)\)/),
    ).toEqual([...INTEGRATION_REQUEST_STATUSES]);
  });

  it("closes the SQL scope list against the frozen api-contract vocabulary", () => {
    expect(sqlLiterals(/requested_scopes <@ ARRAY\[([\s\S]*?)\]::text\[\]/)).toEqual([
      ...IMPLEMENTER_SCOPES,
    ]);
  });

  it("stores only claim_token_hash - never a raw claim token or issued key", () => {
    expect(sqlBody).toContain("claim_token_hash");
    expect(sqlBody).toContain("claim_token_hash ~ '^[0-9a-f]{64}$'");
    expect(sqlBody).not.toMatch(/\b(claim_token|raw_token|bearer_secret|raw_key|secret_key)\b/);
    expect(sqlBody).not.toMatch(/\bik_[A-Za-z0-9]/);
  });

  it("documents the closed CAS transition table", () => {
    expect(INTEGRATION_REQUEST_TRANSITIONS.map((t) => `${t.from}->${t.to}`)).toEqual([
      "PENDING->APPROVED",
      "PENDING->DECLINED",
      "PENDING->EXPIRED",
      "APPROVED->EXPIRED",
      "APPROVED->CLAIMED",
    ]);
  });

  it("carries a status consistency CHECK and expiry index", () => {
    expect(sqlBody).toContain("CONSTRAINT integration_requests_status_consistency CHECK");
    expect(sqlBody).toContain("CREATE INDEX integration_requests_status_expires_at_idx");
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(INTEGRATION_REQUESTS_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(7);
    for (const obligation of INTEGRATION_REQUESTS_EXECUTION_OBLIGATIONS) {
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
    const mutated = sql.replace(
      "CREATE INDEX integration_requests_status_expires_at_idx",
      "-- removed",
    );
    const missing = INTEGRATION_REQUESTS_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["STATUS_EXPIRES_INDEX"]);
  });
});
