// census: binds the frozen raw-observation invariant inventory to the
// literal SQL contract text and cross-binds the SQL enum literals to the frozen
// observation vocabulary in @zucoins/generic-node-contracts (observation concern) and
// the raw-capture rule of the transfer-code concern, so the truth carriers (contract
// inventory, SQL text, frozen vocabularies) cannot drift apart silently.
// Live-database execution is a schema-apply obligation, inventoried in the contract, not
// silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS,
  OBSERVATION_LEDGER_INVARIANTS,
  OBSERVATION_LEDGER_SCHEMA_FILE,
} from "../src/schema/observation-ledger.contract.ts";
import {
  OBSERVATION_PARSE_RESULTS,
  OBSERVATION_RELATIONSHIPS,
  OBSERVER_DOMAINS,
  WALLET_OBSERVATION_ROLES,
} from "../../generic-node-contracts/src/observation/enums.contract.ts";
import { GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE } from "../../generic-node-contracts/src/transfer-code/candidate-intake.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OBSERVATION_LEDGER_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

const parseEnumLiterals = (text: string, typeName: string): string[] => {
  const declaration = new RegExp(`CREATE TYPE ${typeName} AS ENUM \\(([^)]*)\\)`).exec(text);
  if (declaration === null || declaration[1] === undefined) {
    return [];
  }
  return [...declaration[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("observation-ledger schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OBSERVATION_LEDGER_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("SQL enum literals equal the frozen observation vocabulary, sequence included", () => {
    expect(parseEnumLiterals(sql, "observer_domain")).toEqual([...OBSERVER_DOMAINS]);
    expect(parseEnumLiterals(sql, "observation_parse_result")).toEqual([
      ...OBSERVATION_PARSE_RESULTS,
    ]);
    expect(parseEnumLiterals(sql, "observation_relationship")).toEqual([
      ...OBSERVATION_RELATIONSHIPS,
    ]);
  });

  it("the wallet_role CHECK literals equal the frozen role vocabulary", () => {
    const roleCheck = /wallet_role IN \(([^)]*)\)/.exec(sql);
    expect(roleCheck).not.toBeNull();
    const literals = [...(roleCheck?.[1] ?? "").matchAll(/'([^']+)'/g)].map(
      (match) => match[1] ?? "",
    );
    expect(literals).toEqual([...WALLET_OBSERVATION_ROLES]);
  });

  it("raw capture before decode is structural: bytes and digest columns are NOT NULL", () => {
    expect(GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE).toBe(true);
    expect(sql).toContain("raw_response_bytes bytea NOT NULL");
    expect(sql).toContain("raw_response_sha256 sha256_hex NOT NULL");
    expect(sql).toContain("endpoint_fingerprint sha256_hex NOT NULL");
    expect(sql).toContain("gateway_endpoint_fingerprint sha256_hex NOT NULL");
  });

  it("mutation negative: dropping the raw digest column is caught", () => {
    const removed = sql.replace("raw_response_sha256 sha256_hex NOT NULL,", "raw_response_sha256 sha256_hex,");
    const missing = OBSERVATION_LEDGER_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OBSERVATION_RAW_DIGEST");
  });

  it("mutation negative: dropping the per-row endpoint fingerprint is caught", () => {
    const removed = sql.replace(
      "\n  endpoint_fingerprint sha256_hex NOT NULL,",
      "\n  endpoint_fingerprint sha256_hex,",
    );
    expect(removed).not.toBe(sql);
    const missing = OBSERVATION_LEDGER_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OBSERVATION_ENDPOINT_FINGERPRINT_COPIED");
  });

  it("schema-apply execution obligations are inventoried, including the ambiguity reconciliation", () => {
    expect(SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
    for (const obligation of SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_OBSERVATION_LEDGER_OBLIGATIONS.some((obligation) =>
        obligation.includes("transport-ambiguous"),
      ),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
