// census: binds the frozen neutral-event invariant inventory to the literal SQL
// contract text and cross-binds the SQL to the frozen event vocabulary and allocation model
// in @zucoins/generic-node-contracts (the closed nine-value durable event set, the gapless
// per-node counter allocation contract, and the DDL constraint manifest), so the truth
// carriers (contract inventory, SQL text, frozen vocabularies) cannot drift apart silently.
// Live-database execution is a separate live-database obligation, inventoried in the contract, not silently
// omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  EVENT_LEDGER_INVARIANTS,
  EVENT_LEDGER_SCHEMA_FILE,
  SCHEMA_EVENT_LEDGER_OBLIGATIONS,
} from "../src/schema/event-ledger.contract.ts";
import { DURABLE_EVENTS } from "../../generic-node-contracts/src/operations/events.contract.ts";
import {
  ALLOCATION_MODEL,
  REJECTED_ALLOCATIONS,
} from "../../generic-node-contracts/src/event-sequencing/allocation.ts";
import { DDL_CONSTRAINTS } from "../../generic-node-contracts/src/event-commit/ddl.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", EVENT_LEDGER_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

const parseEventTypeLiterals = (text: string): string[] => {
  const declaration = /event_type IN \(([^)]*)\)/.exec(text);
  if (declaration === null || declaration[1] === undefined) {
    return [];
  }
  return [...declaration[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("event-ledger schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = EVENT_LEDGER_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("the event_type CHECK literals equal the closed nine-value durable event set, in the same sequence", () => {
    expect(parseEventTypeLiterals(sql)).toEqual([...DURABLE_EVENTS]);
    expect(DURABLE_EVENTS).toHaveLength(9);
  });

  it("seq is a plain per-node key sourced from the dedicated counter, never identity/serial", () => {
    // The frozen allocation model: a dedicated single-row-per-node counter, gapless and
    // rollback-safe, not an identity/serial column. makes the storage key
    // composite (node_id, seq) so two nodes sharing one DB cannot collide on equal seq.
    expect(ALLOCATION_MODEL.storage).toBe("dedicated_single_row_counter_table_per_node");
    expect(ALLOCATION_MODEL.monotonic).toBe(true);
    expect(ALLOCATION_MODEL.gapless).toBe(true);
    expect(ALLOCATION_MODEL.rollbackSafe).toBe(true);
    expect(ALLOCATION_MODEL.durableBeforeVisible).toBe(true);
    expect(DDL_CONSTRAINTS.seqSource).toBe("dedicated_per_node_counter");
    expect(DDL_CONSTRAINTS.seqRejectedSource).toBe("generated_always_as_identity");
    expect(sql).toContain("CREATE TABLE node_event_seq_counters");
    expect(sql).toContain("seq bigint NOT NULL");
    expect(sql).toContain("PRIMARY KEY (node_id, seq)");
    expect(sql).not.toContain("seq bigint PRIMARY KEY");
    expect(sql).not.toContain("GENERATED ALWAYS AS IDENTITY");
    expect(sql).not.toContain("bigserial");
    expect(
      REJECTED_ALLOCATIONS.some((m) => m.mechanism === "generated_always_as_identity"),
    ).toBe(true);
  });

  it("duplicate committed events are structurally impossible: event_id and event_hash are UNIQUE", () => {
    expect(DDL_CONSTRAINTS.uniqueEventId).toBe(true);
    expect(DDL_CONSTRAINTS.uniqueEventHash).toBe(true);
    expect(DDL_CONSTRAINTS.eventsInsertOnly).toBe(true);
    expect(sql).toContain("event_id uuid NOT NULL UNIQUE");
    expect(sql).toContain("event_hash sha256_hex NOT NULL UNIQUE");
  });

  it("mutation negative: dropping the event_hash uniqueness is caught", () => {
    const removed = sql.replace(
      "event_hash sha256_hex NOT NULL UNIQUE,",
      "event_hash sha256_hex NOT NULL,",
    );
    expect(removed).not.toBe(sql);
    const missing = EVENT_LEDGER_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("EVENT_HASH_LINKED_CHAIN");
  });

  it("mutation negative: dropping the counter positivity/monotonic CHECK is caught", () => {
    const removed = sql.replace(" CHECK (next_seq > 0)", "");
    expect(removed).not.toBe(sql);
    const missing = EVENT_LEDGER_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("COUNTER_NEXT_SEQ_MONOTONIC_POSITIVE");
    expect(missing).toContain("SEQ_FROM_DEDICATED_COUNTER_TABLE");
  });

  it("mutation negative: dropping the closed event_type CHECK is caught", () => {
    const removed = sql.replace(
      "event_type text NOT NULL CHECK (event_type IN (",
      "event_type text NOT NULL, -- CHECK (event_type IN (",
    );
    expect(removed).not.toBe(sql);
    const missing = EVENT_LEDGER_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("EVENT_TYPE_CLOSED_NINE_VALUE_SET");
  });

  it("execution obligations are inventoried, including atomic allocation and append-only guards", () => {
    expect(SCHEMA_EVENT_LEDGER_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_EVENT_LEDGER_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_EVENT_LEDGER_OBLIGATIONS.some((obligation) => obligation.includes("SELECT ... FOR UPDATE")),
    ).toBe(true);
    expect(
      SCHEMA_EVENT_LEDGER_OBLIGATIONS.some((obligation) => obligation.includes("append-only")),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
