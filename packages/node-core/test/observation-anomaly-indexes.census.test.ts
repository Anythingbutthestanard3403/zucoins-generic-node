// Census: binds the frozen anomaly/index invariant inventory to the literal SQL contract
// text so the two truth carriers cannot drift apart silently. Static text proof; the
// real-PostgreSQL behaviour proof is observation-anomaly-indexes.pg.test.ts.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_OBSERVATION_ANOMALY_INDEXES_OBLIGATIONS,
  OBSERVATION_ANOMALY_INDEXES_SCHEMA_FILE,
  OBSERVATION_ANOMALY_INDEX_INVARIANTS,
} from "../src/schema/observation-anomaly-indexes.contract.ts";
import { OBSERVATION_ANOMALY_KINDS } from "../../generic-node-contracts/src/observation/enums.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OBSERVATION_ANOMALY_INDEXES_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("observation-anomaly-indexes schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OBSERVATION_ANOMALY_INDEX_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("anomaly kind CHECK contains exactly the nine frozen closed-set kinds in sequence", () => {
    const kindCheck = /kind IN \(([^)]*)\)/s.exec(sql);
    expect(kindCheck).not.toBeNull();
    const literals = [...(kindCheck?.[1] ?? "").matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
    expect(literals).toEqual([
      "TRANSPORT_ERROR",
      "MALFORMED_ENVELOPE",
      "MALFORMED_TRANSACTION",
      "UNVERIFIED_SIGNATURE",
      "WALLET_ROLE_INVALID",
      "REGRESSION",
      "UNEXPLAINED_JUMP",
      "GENESIS_AFTER_HISTORY",
      "SIGNATURE_COLLISION",
    ]);
  });

  it("the SQL kind set equals the frozen OBSERVATION_ANOMALY_KINDS vocabulary", () => {
    const kindCheck = /kind IN \(([^)]*)\)/s.exec(sql);
    const literals = [...(kindCheck?.[1] ?? "").matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
    expect([...literals].sort()).toEqual([...OBSERVATION_ANOMALY_KINDS].sort());
  });

  it("observation_anomalies has a UNIQUE constraint on observation_id", () => {
    expect(sql).toContain(
      "observation_id uuid NOT NULL UNIQUE REFERENCES gateway_observations(id)",
    );
  });

  it("the observation_anomalies column sequence is the frozen field sequence", () => {
    const table = /CREATE TABLE observation_anomalies \(([\s\S]*?)\n\);/.exec(sql);
    expect(table).not.toBeNull();
    const columns = (table?.[1] ?? "")
      .split("\n")
      .map((line) => /^\s{2}([a-z_]+)\s/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined);
    expect(columns).toEqual([
      "id",
      "observation_id",
      "observer_id",
      "wallet_id",
      "wallet_public_key",
      "kind",
      "prior_observation_id",
      "details",
      "detected_at",
    ]);
  });

  it("no observation_anomalies column carries a DEFAULT", () => {
    const table = /CREATE TABLE observation_anomalies \(([\s\S]*?)\n\);/.exec(sql);
    expect(table?.[1] ?? "").not.toContain("DEFAULT");
  });

  it("the prior-state index keys s_signature (S projection), not the step head columns", () => {
    expect(sql).toContain(
      "CREATE INDEX gateway_observations_prior_state_idx\n  ON gateway_observations(observer_id, wallet_public_key, s_signature)",
    );
    expect(sql).toContain("INCLUDE (semantic_fingerprint)");
    // Guard against the documented conflation trap: the prior-state index must not be built
    // on the raw head signatures.
    expect(sql).not.toContain(
      "gateway_observations_prior_state_idx\n  ON gateway_observations(observer_id, wallet_public_key, step_2_signature)",
    );
  });

  it("the exact-body index keys (wallet_public_key, step_2_signature)", () => {
    expect(sql).toContain(
      "CREATE INDEX gateway_observations_exact_body_idx\n  ON gateway_observations(wallet_public_key, step_2_signature)",
    );
  });

  it("the semantic-fingerprint index is stream-scoped", () => {
    expect(sql).toContain(
      "CREATE INDEX gateway_observations_semantic_fingerprint_idx\n  ON gateway_observations(observer_id, wallet_public_key, semantic_fingerprint)",
    );
  });

  it("the deferred collision guard is a DEFERRABLE INITIALLY DEFERRED constraint trigger", () => {
    expect(sql).toContain(
      "CREATE CONSTRAINT TRIGGER observation_anomaly_pairing_complete\n  AFTER INSERT ON gateway_observations\n  DEFERRABLE INITIALLY DEFERRED",
    );
  });

  it("the collision guard keys off the frozen classification carriers (relationship + parse_result)", () => {
    expect(sql).toContain("observation_anomaly_required_kind");
    for (const relationship of [
      "SIGNATURE_COLLISION",
      "REGRESSION",
      "GENESIS_AFTER_HISTORY",
      "UNEXPLAINED_JUMP",
    ]) {
      expect(sql).toContain(relationship);
    }
    expect(sql).toContain("NEW.parse_result, NEW.relationship");
  });

  it("mutation negative: dropping the UNIQUE on observation_id is caught", () => {
    const removed = sql.replace(
      "observation_id uuid NOT NULL UNIQUE REFERENCES gateway_observations(id),",
      "observation_id uuid NOT NULL REFERENCES gateway_observations(id),",
    );
    const missing = OBSERVATION_ANOMALY_INDEX_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("ANOMALY_ONE_PER_OBSERVATION");
  });

  it("mutation negative: dropping the collision-guard trigger is caught", () => {
    const removed = sql.replace(
      "CREATE CONSTRAINT TRIGGER observation_anomaly_pairing_complete",
      "CREATE TRIGGER observation_anomaly_pairing_complete",
    );
    const missing = OBSERVATION_ANOMALY_INDEX_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("COLLISION_GUARD_DEFERRED_TRIGGER");
  });

  it("schema-apply execution obligations are inventoried", () => {
    expect(SCHEMA_OBSERVATION_ANOMALY_INDEXES_OBLIGATIONS.length).toBeGreaterThanOrEqual(5);
    for (const obligation of SCHEMA_OBSERVATION_ANOMALY_INDEXES_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_OBSERVATION_ANOMALY_INDEXES_OBLIGATIONS.some((obligation) =>
        obligation.includes("append-only"),
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
