// Census: binds the frozen successor-index invariant inventory to the literal SQL
// contract text so the two truth carriers cannot drift apart silently. Static text
// proof; the real-PostgreSQL behaviour proof is send-completion-lander.pg.test.ts and
// send-late-landing-reconcile.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_EXECUTION_OBLIGATIONS,
  GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_SCHEMA_FILE,
  GATEWAY_OBSERVATION_SUCCESSOR_INDEX_INVARIANTS,
} from "../src/schema/gateway-observation-successor-indexes.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("gateway-observation-successor-indexes schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = GATEWAY_OBSERVATION_SUCCESSOR_INDEX_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("mutation negative: dropping the step-1-signature index is caught", () => {
    const removed = sql.replace(
      "CREATE INDEX gateway_observations_step_one_signature_idx\n  ON gateway_observations(wallet_public_key, step_1_signature)\n  WHERE step_1_signature IS NOT NULL;",
      "",
    );
    const missing = GATEWAY_OBSERVATION_SUCCESSOR_INDEX_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(
      expect.arrayContaining(["STEP_ONE_SIGNATURE_INDEX", "STEP_ONE_SIGNATURE_INDEX_PARTIAL"]),
    );
  });

  it("execution obligations are inventoried", () => {
    expect(GATEWAY_OBSERVATION_SUCCESSOR_INDEXES_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(3);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
