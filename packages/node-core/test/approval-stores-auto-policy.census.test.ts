// Census: binds the AUTO_POLICY amendment inventory to the literal ALTER SQL.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  APPROVAL_STORES_AUTO_POLICY_EXECUTION_OBLIGATIONS,
  APPROVAL_STORES_AUTO_POLICY_INVARIANTS,
  APPROVAL_STORES_AUTO_POLICY_SCHEMA_FILE,
} from "../src/schema/approval-stores-auto-policy.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", APPROVAL_STORES_AUTO_POLICY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("approval-stores-auto-policy schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = APPROVAL_STORES_AUTO_POLICY_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("execution obligations are inventoried", () => {
    expect(APPROVAL_STORES_AUTO_POLICY_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
