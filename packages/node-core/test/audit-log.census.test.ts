// Audit-log census: binds the frozen audit-trail invariant inventory to the literal SQL
// contract text and cross-binds the SQL actor_kind literals to the frozen actor taxonomy,
// so the truth carriers (contract inventory, SQL text, actor vocabulary) cannot drift
// apart silently. Live-database execution is a separate obligation, inventoried in the
// contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  AUDIT_LOG_ACTOR_KINDS,
  AUDIT_LOG_FORBIDDEN_SECRET_TOKENS,
  AUDIT_LOG_INVARIANTS,
  AUDIT_LOG_MUTABILITY_REGIMES,
  AUDIT_LOG_SCHEMA_FILE,
  SCHEMA_AUDIT_LOG_OBLIGATIONS,
} from "../src/schema/audit-log.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", AUDIT_LOG_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const ddl = sql
  .split("\n")
  .filter((line) => !/^\s*--/.test(line))
  .join("\n");

const parseActorKindLiterals = (text: string): string[] => {
  const check = /actor_kind IN\s*\(([^)]*)\)/.exec(text);
  if (check === null || check[1] === undefined) {
    return [];
  }
  return [...check[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("audit-log schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = AUDIT_LOG_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("SQL actor_kind literals equal the frozen actor taxonomy", () => {
    expect(parseActorKindLiterals(sql)).toEqual([...AUDIT_LOG_ACTOR_KINDS]);
  });

  it("audit details are stored as exact text plus digest, both NOT NULL", () => {
    expect(sql).toContain("details_text text NOT NULL");
    expect(sql).toContain("details_sha256 sha256_hex NOT NULL");
  });

  it("the (id, node_id) composite uniqueness is present for downstream composite FKs", () => {
    expect(sql).toContain("id uuid NOT NULL UNIQUE");
    expect(sql).toContain("UNIQUE (id, node_id)");
  });

  it("audit_log is insert-only with no updatable columns", () => {
    expect(AUDIT_LOG_MUTABILITY_REGIMES.map((regime) => regime.table)).toEqual(["audit_log"]);
    for (const regime of AUDIT_LOG_MUTABILITY_REGIMES) {
      expect(regime.regime).toBe("insert_only");
      expect(regime.updatableColumns).toEqual([]);
    }
  });

  it("secret-free schema: no key-material / credential column token in the DDL", () => {
    for (const token of AUDIT_LOG_FORBIDDEN_SECRET_TOKENS) {
      expect(ddl.toLowerCase()).not.toContain(token);
    }
  });

  it("mutation negative: dropping the details digest is caught", () => {
    const removed = sql.replace("details_sha256 sha256_hex NOT NULL,", "details_sha256 sha256_hex,");
    const missing = AUDIT_LOG_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("AUDIT_DETAILS_EXACT_PLUS_DIGEST");
  });

  it("mutation negative: dropping the actor_kind CHECK is caught", () => {
    const removed = sql.replace(
      "('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),",
      "('SYSTEM','OPERATOR_SESSION')),",
    );
    const missing = AUDIT_LOG_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("AUDIT_ACTOR_KIND_CLOSED_SET");
  });

  it("execution obligations are inventoried, including append-only and secret-free content", () => {
    expect(SCHEMA_AUDIT_LOG_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_AUDIT_LOG_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_AUDIT_LOG_OBLIGATIONS.some((obligation) => obligation.includes("append-only")),
    ).toBe(true);
    expect(
      SCHEMA_AUDIT_LOG_OBLIGATIONS.some((obligation) => obligation.includes("scrubbed")),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
