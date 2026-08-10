// Census: binds the frozen worker-poll index inventory to the literal SQL contract text so
// the two truth carriers cannot drift apart silently. Static text proof; the
// real-PostgreSQL behaviour proof (indexes exist, planner uses them for the worker-poll
// predicates, seq scan without them) is operations-indexes.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  OPERATIONS_INDEXES_EXECUTION_OBLIGATIONS,
  OPERATIONS_INDEXES_SCHEMA_FILE,
  OPERATIONS_INDEX_INVARIANTS,
} from "../src/schema/operations-indexes.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OPERATIONS_INDEXES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

const INDEX_NAMES = [
  "operations_receive_queue_created_idx",
  "operations_receive_expiry_candidates_idx",
  "operations_receive_ready_idx",
  "operations_receive_landed_handoff_idx",
  "operations_move_pending_idx",
] as const;

describe("operations-indexes schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OPERATIONS_INDEX_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("mutation negative: dropping the queue index is caught", () => {
    const removed = sql.replace(
      "CREATE INDEX operations_receive_queue_created_idx\n" +
        "  ON operations (created_at, id)\n" +
        "  WHERE kind = 'RECEIVE_EXTERNAL'\n" +
        "    AND status = 'CREATED'\n" +
        "    AND receiver_wallet_id IS NULL;",
      "",
    );
    const missing = OPERATIONS_INDEX_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(
      expect.arrayContaining([
        "RECEIVE_QUEUE_CREATED_INDEX",
        "PURE_INDEX_EXTENSION",
      ]),
    );
  });

  it("is a pure index extension: five partial CREATE INDEX, no table/column/trigger", () => {
    const code = sql.replace(/--[^\n]*/g, " ");
    expect(code.match(/CREATE INDEX/g)).toEqual([
      "CREATE INDEX",
      "CREATE INDEX",
      "CREATE INDEX",
      "CREATE INDEX",
      "CREATE INDEX",
    ]);
    for (const name of INDEX_NAMES) {
      expect(code).toContain(name);
    }
    expect(code).not.toMatch(/CREATE TABLE|ALTER TABLE|CREATE TRIGGER|CREATE DOMAIN/);
    expect(code).not.toMatch(/\bINCLUDE\b/i);
    expect(code).not.toMatch(/CONCURRENTLY/i);
    // Spawn arbiter is named only in prose as out-of-scope; never re-declared as DDL.
    expect(code).not.toMatch(/CREATE\s+(UNIQUE\s+)?INDEX\s+operations_one_spawn_per_parent_uidx/i);
  });

  it("every partial predicate cites a source worker-poll equality filter", () => {
    // The five WHERE clauses must stay partial (the whole point of this slice).
    const code = sql.replace(/--[^\n]*/g, " ");
    expect(code.match(/\bWHERE\b/gi)?.length).toBe(5);
    expect(sql).toContain("kind = 'RECEIVE_EXTERNAL'");
    expect(sql).toContain("status = 'CREATED'");
    expect(sql).toContain("receiver_wallet_id IS NULL");
    expect(sql).toContain("status IN ('CREATED', 'READY', 'EXPIRED')");
    expect(sql).toContain("receive_release_status IS NULL");
    expect(sql).toContain("status = 'READY'");
    expect(sql).toContain("status = 'RECEIVE_LANDED'");
    expect(sql).toContain("after_landing = 'INTERNAL_MOVE'");
    expect(sql).toContain("kind = 'MOVE_INTERNAL'");
    expect(sql).toContain("status IN ('CREATED', 'NEEDS_ATTENTION')");
  });

  it("execution obligations are inventoried", () => {
    expect(OPERATIONS_INDEXES_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
