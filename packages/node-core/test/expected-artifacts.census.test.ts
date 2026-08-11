// Census: binds the frozen expected-artifact invariant inventory to the literal SQL
// contract text, so the two truth carriers (contract inventory, SQL text) cannot drift
// apart silently. Live-database execution is a separate live-database obligation, inventoried in the
// contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  EXPECTED_ARTIFACTS_INVARIANTS,
  EXPECTED_ARTIFACTS_MUTABILITY_REGIMES,
  EXPECTED_ARTIFACTS_SCHEMA_FILE,
  SCHEMA_EXPECTED_ARTIFACTS_OBLIGATIONS,
} from "../src/schema/expected-artifacts.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", EXPECTED_ARTIFACTS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const baseSql = readFileSync(resolve(here, "../src/schema/base-enums-domains.sql"), "utf8");

describe("expected-artifacts schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = EXPECTED_ARTIFACTS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("exactly three frozen purpose literals are present", () => {
    expect(sql).toContain("'zp-receive-expected-v1'");
    expect(sql).toContain("'zp-move-internal-expected-v1'");
    expect(sql).toContain("'zp-send-external-expected-v1'");
  });

  it("operation_id is UNIQUE — one artifact per operation", () => {
    expect(sql).toContain("operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),");
  });

  it("canonical_version is frozen to 1", () => {
    expect(sql).toContain("CHECK (canonical_version = 1)");
  });

  it("signing_key_id maps to node_signing_keys", () => {
    expect(sql).toContain("signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),");
  });

  it("preimage nonempty check is present", () => {
    expect(sql).toContain("CHECK (octet_length(preimage_text) > 0)");
  });

  it("consumes shared domains from the single foundation owner", () => {
    expect(baseSql).toContain("CREATE DOMAIN sha256_hex AS text");
    expect(baseSql).toContain("CREATE DOMAIN padded_base64url_signature AS text");
    expect(sql).not.toContain("CREATE DOMAIN");
  });

  it("mutation negative: dropping the purpose CHECK is caught", () => {
    const removed = sql.replace(
      "CONSTRAINT operation_expected_artifacts_purpose_check CHECK (purpose IN (\n    'zp-receive-expected-v1',\n    'zp-move-internal-expected-v1',\n    'zp-send-external-expected-v1'\n  )),",
      "CHECK (purpose IN (\n    'zp-receive-expected-v1'\n  )),",
    );
    const missing = EXPECTED_ARTIFACTS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ARTIFACT_PURPOSE_CLOSED_SET");
  });

  it("mutation negative: dropping the operation_id UNIQUE is caught", () => {
    const removed = sql.replace(
      "operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),",
      "operation_id uuid NOT NULL REFERENCES operations(id),",
    );
    const missing = EXPECTED_ARTIFACTS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ARTIFACT_ONE_PER_OPERATION");
  });

  it("table is insert-only with no updatable columns", () => {
    expect(EXPECTED_ARTIFACTS_MUTABILITY_REGIMES).toHaveLength(1);
    expect(EXPECTED_ARTIFACTS_MUTABILITY_REGIMES[0].table).toBe(
      "operation_expected_artifacts",
    );
    expect(EXPECTED_ARTIFACTS_MUTABILITY_REGIMES[0].regime).toBe("insert_only");
    expect(EXPECTED_ARTIFACTS_MUTABILITY_REGIMES[0].updatableColumns).toEqual([]);
  });

  it("execution obligations are inventoried", () => {
    expect(SCHEMA_EXPECTED_ARTIFACTS_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
    for (const obligation of SCHEMA_EXPECTED_ARTIFACTS_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("owns the insert-only byte-immutability trigger", () => {
    expect(sql).toContain("BEFORE UPDATE OR DELETE ON operation_expected_artifacts");
    expect(sql).toContain("expected_artifact_reject_mutation");
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
