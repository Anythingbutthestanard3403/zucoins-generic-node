// Census: binds observation-stores.sql column/invariant inventory to the frozen
// WALLET_OBSERVATION_CURSOR_FIELDS sequence and OBSERVATION_STORES_INVARIANTS so the
// SQL, contract inventory, and generic-node-contracts field list cannot drift.
// Live-database constraint drills are observation-stores.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { WALLET_OBSERVATION_CURSOR_FIELDS } from "../../generic-node-contracts/src/observation/record-fields.contract.ts";
import {
  SCHEMA_OBSERVATION_STORES_OBLIGATIONS,
  OBSERVATION_STORES_INVARIANTS,
  OBSERVATION_STORES_SCHEMA_FILE,
} from "../src/schema/observation-stores.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OBSERVATION_STORES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

describe("observation-stores cursor schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OBSERVATION_STORES_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("wallet_observation_cursors column sequence matches WALLET_OBSERVATION_CURSOR_FIELDS", () => {
    const table = /CREATE TABLE wallet_observation_cursors \(([\s\S]*?)\n\);/.exec(sql);
    expect(table).not.toBeNull();
    const columns = (table?.[1] ?? "")
      .split("\n")
      .map((line) => /^\s{2}([a-z0-9_]+)\s/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined);
    expect(columns).toEqual(WALLET_OBSERVATION_CURSOR_FIELDS.map((f) => f.name));
  });

  it("does not create observation_anomalies (owns that table)", () => {
    expect(sql).not.toContain("CREATE TABLE observation_anomalies");
  });

  it("does not recreate observers or gateway_observations (observation-ledger owns those)", () => {
    expect(sql).not.toContain("CREATE TABLE observers");
    expect(sql).not.toContain("CREATE TABLE gateway_observations");
  });

  it("schema-apply obligations inventory is non-empty and names the write-path store", () => {
    expect(SCHEMA_OBSERVATION_STORES_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
    expect(
      SCHEMA_OBSERVATION_STORES_OBLIGATIONS.some((o) => o.includes("SqlStreamWriterEffects")),
    ).toBe(true);
  });

  it("mutation negative: dropping the composite PK is caught", () => {
    const removed = sql.replace(
      "PRIMARY KEY (observer_id, wallet_public_key)",
      "/* PRIMARY KEY removed */",
    );
    const missing = OBSERVATION_STORES_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("CURSOR_COMPOSITE_PRIMARY_KEY");
  });
});
