// census: binds implementer-event-stream.contract.ts to the literal SQL text.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  IMPLEMENTER_EVENT_STREAM_INVARIANTS,
  IMPLEMENTER_EVENT_STREAM_SCHEMA_FILE,
} from "../src/schema/implementer-event-stream.contract.ts";
import { IMPLEMENTER_STREAM_EVENT_TYPES } from "../src/reporting/implementer-event-log.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", IMPLEMENTER_EVENT_STREAM_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

const parseEventTypeLiterals = (text: string): string[] => {
  const declaration = /event_type IN \(([^)]*)\)/.exec(text);
  if (declaration === null || declaration[1] === undefined) return [];
  return [...declaration[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("implementer-event-stream schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = IMPLEMENTER_EVENT_STREAM_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("event_type CHECK equals the closed nine-value set", () => {
    expect(parseEventTypeLiterals(sql)).toEqual([...IMPLEMENTER_STREAM_EVENT_TYPES]);
  });

  it("never references the node-global event stream tables", () => {
    expect(sql).not.toContain("node_events");
    expect(sql).not.toContain("zp-node-event-v1");
  });

  it("counter is dedicated composite PK, not identity", () => {
    expect(sql).toContain("CREATE TABLE implementer_event_seq_counters");
    expect(sql).not.toContain("GENERATED ALWAYS AS IDENTITY");
    expect(sql).not.toContain("bigserial");
  });
});
