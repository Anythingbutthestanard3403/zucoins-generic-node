import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_OPERATIONAL_STORES_OBLIGATIONS,
  OPERATIONAL_STORES_INVARIANTS,
  OPERATIONAL_STORES_MUTABILITY_REGIMES,
  OPERATIONAL_STORES_SCHEMA_FILE,
} from "../src/schema/operational-stores.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OPERATIONAL_STORES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("operational-stores schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("all three tables are declared", () => {
    expect(sql).toContain("CREATE TABLE node_settings (");
    expect(sql).toContain("CREATE TABLE operator_halts (");
    expect(sql).toContain("CREATE TABLE worker_cursors (");
  });

  it("node_settings carries the house row_version CAS column", () => {
    expect(sql).toContain("row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)");
  });

  it("halt scope is a closed three-value set", () => {
    expect(sql).toContain("CHECK (scope IN ('NODE','WALLET','OPERATION'))");
  });

  it("halt engage and lift actors are present and non-empty", () => {
    expect(sql).toContain("engaged_by text NOT NULL CHECK (octet_length(engaged_by) > 0),");
    expect(sql).toContain(
      "lifted_by text CHECK (lifted_by IS NULL OR octet_length(lifted_by) > 0),",
    );
    expect(sql).toContain("reason text NOT NULL CHECK (octet_length(reason) > 0),");
    expect(sql).toContain("CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))");
  });

  it("halt temporal consistency is structurally enforced", () => {
    expect(sql).toContain("CHECK ((lifted_at IS NULL) OR (lifted_at >= halted_at))");
  });

  it("cursor position is non-negative", () => {
    expect(sql).toContain("CHECK (position >= 0)");
  });

  it("mutation negative: dropping the settings row_version CHECK is caught", () => {
    const removed = sql.replace(
      "row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),",
      "row_version bigint NOT NULL DEFAULT 1,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("SETTINGS_ROW_VERSION");
  });

  it("mutation negative: dropping engaged_by is caught", () => {
    const removed = sql.replace(
      "engaged_by text NOT NULL CHECK (octet_length(engaged_by) > 0),\n",
      "",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_ENGAGED_BY_REQUIRED");
  });

  it("mutation negative: weakening engaged_by to NOT NULL-only is caught", () => {
    const weakened = sql.replace(
      "engaged_by text NOT NULL CHECK (octet_length(engaged_by) > 0),",
      "engaged_by text NOT NULL,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !weakened.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_ENGAGED_BY_REQUIRED");
  });

  it("mutation negative: weakening reason to NOT NULL-only is caught", () => {
    const weakened = sql.replace(
      "reason text NOT NULL CHECK (octet_length(reason) > 0),",
      "reason text NOT NULL,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !weakened.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_REASON_REQUIRED");
  });

  it("mutation negative: dropping lifted_by non-empty CHECK is caught", () => {
    const weakened = sql.replace(
      "lifted_by text CHECK (lifted_by IS NULL OR octet_length(lifted_by) > 0),",
      "lifted_by text,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !weakened.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_LIFTED_BY_NULLABLE");
  });

  it("mutation negative: dropping the halt scope CHECK is caught", () => {
    const removed = sql.replace(
      "scope text NOT NULL CHECK (scope IN ('NODE','WALLET','OPERATION')),",
      "scope text NOT NULL,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_SCOPE_CLOSED_SET");
  });

  it("mutation negative: dropping the cursor position CHECK is caught", () => {
    const removed = sql.replace(
      "position bigint NOT NULL CHECK (position >= 0),",
      "position bigint NOT NULL,",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("CURSOR_POSITION_NON_NEGATIVE");
  });

  it("mutation negative: dropping the temporal CHECK is caught", () => {
    const removed = sql.replace(
      "CHECK ((lifted_at IS NULL) OR (lifted_at >= halted_at))",
      "CHECK (lifted_at IS NULL OR lifted_at IS NOT NULL)",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_LIFTED_AFTER_HALTED");
  });

  it("mutation negative: dropping the lift-actor paired CHECK is caught", () => {
    const removed = sql.replace(
      "CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))",
      "CHECK (lifted_at IS NULL OR lifted_at IS NOT NULL)",
    );
    const missing = OPERATIONAL_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("HALT_LIFT_ACTOR_PAIRED");
  });

  it("mutability regimes cover all three tables and versioned settings", () => {
    expect(OPERATIONAL_STORES_MUTABILITY_REGIMES.map((r) => r.table)).toEqual([
      "node_settings",
      "operator_halts",
      "worker_cursors",
    ]);
    const settings = OPERATIONAL_STORES_MUTABILITY_REGIMES.find(
      (r) => r.table === "node_settings",
    );
    expect(settings?.updatableColumns).toContain("row_version");
    const halts = OPERATIONAL_STORES_MUTABILITY_REGIMES.find(
      (r) => r.table === "operator_halts",
    );
    expect(halts?.updatableColumns).toEqual(["lifted_at", "lifted_by"]);
  });

  it("schema-apply execution obligations are inventoried", () => {
    expect(SCHEMA_OPERATIONAL_STORES_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_OPERATIONAL_STORES_OBLIGATIONS) {
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
