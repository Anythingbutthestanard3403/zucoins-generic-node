// Census: binds the frozen reporting-rate-limit-bucket invariant inventory to the
// literal SQL contract text.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  REPORTING_SECURITY_PORTS_INVARIANTS,
  REPORTING_SECURITY_PORTS_SCHEMA_FILE,
} from "../src/schema/reporting-security-ports.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", REPORTING_SECURITY_PORTS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("reporting-security-ports schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = REPORTING_SECURITY_PORTS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares the rate-limit bucket table", () => {
    expect(sql).toContain("CREATE TABLE reporting_rate_limit_buckets");
  });

  it("C4: invariant inventory does not shrink below the frozen floor", () => {
    expect(REPORTING_SECURITY_PORTS_INVARIANTS.length).toBeGreaterThanOrEqual(6);
    for (const invariant of REPORTING_SECURITY_PORTS_INVARIANTS) {
      expect(invariant.rule.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
