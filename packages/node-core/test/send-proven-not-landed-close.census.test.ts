// Census: binds send-proven-not-landed-close.contract.ts to the literal SQL (ZTR-1318).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SCHEMA_SEND_PROVEN_NOT_LANDED_CLOSE_OBLIGATIONS,
  SEND_PROVEN_NOT_LANDED_CLOSE_INVARIANTS,
  SEND_PROVEN_NOT_LANDED_CLOSE_PROOF_KIND,
  SEND_PROVEN_NOT_LANDED_CLOSE_SCHEMA_FILE,
} from "../src/schema/send-proven-not-landed-close.contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", SEND_PROVEN_NOT_LANDED_CLOSE_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const sqlBody = sql.replace(/--.*$/gm, "");

describe("send-proven-not-landed-close schema census (ZTR-1318)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SEND_PROVEN_NOT_LANDED_CLOSE_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("is a pure CHECK rewrite — no CREATE TABLE / enum", () => {
    expect(sqlBody).toMatch(/SEND_PROVEN_NOT_LANDED_CLOSE/);
    expect(sqlBody).toMatch(/lease_release_proofs_proof_kind_check/);
    expect(sqlBody).not.toMatch(/CREATE TABLE\b/);
    expect(sqlBody).not.toMatch(/ALTER TYPE\b/);
    expect(sqlBody).not.toMatch(/CREATE TYPE\b/);
  });

  it("retains EXTERNAL_SEND_LANDED as a distinct genuine-landing kind", () => {
    expect(sqlBody).toMatch(/'EXTERNAL_SEND_LANDED'/);
    expect(SEND_PROVEN_NOT_LANDED_CLOSE_PROOF_KIND).toBe("SEND_PROVEN_NOT_LANDED_CLOSE");
    expect(SEND_PROVEN_NOT_LANDED_CLOSE_PROOF_KIND).not.toBe("EXTERNAL_SEND_LANDED");
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_SEND_PROVEN_NOT_LANDED_CLOSE_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
    for (const obligation of SCHEMA_SEND_PROVEN_NOT_LANDED_CLOSE_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });

  it("mutation negative: removing the new kind is caught by the census", () => {
    const mutated = sql.replaceAll("SEND_PROVEN_NOT_LANDED_CLOSE", "-- removed");
    const missing = SEND_PROVEN_NOT_LANDED_CLOSE_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["DISTINCT_LEASE_PROOF_KIND"]);
  });
});
