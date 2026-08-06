// census: binds the frozen ALTER inventory to the literal SQL contract text,
// so the inventory and the schema contract cannot drift apart. CREATE TABLE ownership for
// move_observation_evidence is move-baseline-binding.sql — this slice is ALTER-only.
// Always-on floor; the live-Postgres suite is gated on TEST_DATABASE_URL.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SCHEMA_MOVE_OBSERVATION_EVIDENCE_OBLIGATIONS,
  MOVE_OBSERVATION_EVIDENCE_CREATE_OWNER,
  MOVE_OBSERVATION_EVIDENCE_INVARIANTS,
  MOVE_OBSERVATION_EVIDENCE_MUTABILITY_REGIMES,
  MOVE_OBSERVATION_EVIDENCE_SCHEMA_FILE,
} from "../src/schema/move-observation-evidence.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  resolve(here, "../src/schema", MOVE_OBSERVATION_EVIDENCE_SCHEMA_FILE),
  "utf8",
);
const createOwnerSql = readFileSync(
  resolve(here, "../src/schema", MOVE_OBSERVATION_EVIDENCE_CREATE_OWNER),
  "utf8",
);

describe("move-observation-evidence schema census (data-model ALTER; CREATE owned by baseline)", () => {
  it("this slice is ALTER-only — no second CREATE of the evidence relation", () => {
    // Strip line comments so prose about ownership cannot false-trigger the dual-CREATE guard.
    const active = sql.replace(/--[^\n]*/g, "");
    expect(active).not.toMatch(/CREATE\s+TABLE\s+move_observation_evidence\b/i);
    expect(active).toMatch(/ALTER\s+TABLE\s+move_observation_evidence\b/i);
    expect(createOwnerSql).toMatch(/CREATE\s+TABLE\s+move_observation_evidence\b/i);
  });

  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = MOVE_OBSERVATION_EVIDENCE_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("mutation negative: dropping any observation FK is caught", () => {
    const stripped = sql.replace(
      "  ADD FOREIGN KEY (destination_terminal_observation_id) REFERENCES gateway_observations(id);",
      "",
    );
    expect(stripped).not.toBe(sql);
    const missing = MOVE_OBSERVATION_EVIDENCE_INVARIANTS.filter(
      (invariant) => !stripped.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["DESTINATION_TERMINAL_FK"]);
  });

  it("the terminal pair is the only mutable group; operation_id and both T0 columns are frozen", () => {
    const regime = MOVE_OBSERVATION_EVIDENCE_MUTABILITY_REGIMES[0];
    expect(regime.table).toBe("move_observation_evidence");
    expect([...regime.updatableColumns]).toEqual([
      "source_terminal_observation_id",
      "destination_terminal_observation_id",
      "verified_at",
    ]);
    expect(regime.updatableColumns).not.toContain("source_t0_observation_id");
    expect(regime.updatableColumns).not.toContain("destination_t0_observation_id");
  });

  it("all four observation columns are foreign-keyed to the raw observation ledger", () => {
    const referenced = [
      ...sql.matchAll(/ADD FOREIGN KEY \((\w+)\) REFERENCES gateway_observations\(id\)/g),
    ].map((match) => match[1]);
    expect(referenced).toEqual([
      "source_t0_observation_id",
      "destination_t0_observation_id",
      "source_terminal_observation_id",
      "destination_terminal_observation_id",
    ]);
  });

  it("the live-database obligations the pg suite discharges are marked, and the rest remain open", () => {
    const discharged = SCHEMA_MOVE_OBSERVATION_EVIDENCE_OBLIGATIONS.filter((obligation) =>
      obligation.startsWith("[pg]"),
    );
    expect(discharged.length).toBe(3);
    expect(SCHEMA_MOVE_OBSERVATION_EVIDENCE_OBLIGATIONS.length).toBeGreaterThan(discharged.length);
    expect(
      SCHEMA_MOVE_OBSERVATION_EVIDENCE_OBLIGATIONS.some((o) => o.includes("no second CREATE")),
    ).toBe(true);
  });
});
