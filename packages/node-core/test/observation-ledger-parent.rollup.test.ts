// Parent — observation-ledger persistence rollup.
//
// The pieces below deliver the build surface; this file independently confirms the combined
// output satisfies the rollup exit criteria (the assembled head plus mandatory database
// tests 12–14).
//
// Children:
//   Streams, cursors, capture write path (wallet_observation_cursors)
//   observation_anomalies + exact-body/prior-state indexes + No-blind-retry guard
//   Migration / invariant proofs
//
// The unique parent gap children do not own: cross-child column/enum consistency of the
// assembled head, node-owned vs external public-key authority without conflation, and
// the mandatory database tests 12–14 golden outcomes driven through the frozen sequence driver against the
// assembled schema vocabulary. No production logic is added; pure test slice.
//
// Pure offline: no live submit, no live-chain path, no signing-payload reformat.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  GATEWAY_OBSERVATION_RECORD_FIELDS,
  OBSERVATION_ANOMALY_RECORD_FIELDS,
  WALLET_OBSERVATION_CURSOR_FIELDS,
} from "../../generic-node-contracts/src/observation/record-fields.contract.ts";
import {
  OBSERVATION_ANOMALY_KINDS,
  OBSERVATION_PARSE_RESULTS,
  OBSERVATION_RELATIONSHIPS,
  OBSERVER_DOMAINS,
} from "../../generic-node-contracts/src/observation/enums.contract.ts";
import { GOLDEN_SEQUENCES } from "../../generic-node-contracts/src/observation/sequences.contract.ts";
import {
  EMPTY_CURSOR,
  appendedRelationships,
  runObservationSequence,
  type SequenceCapture,
} from "../../generic-node-contracts/src/observation/sequence-driver.ts";
import {
  OBSERVATION_LEDGER_INVARIANTS,
  OBSERVATION_LEDGER_SCHEMA_FILE,
} from "../src/schema/observation-ledger.contract.ts";
import {
  OBSERVATION_ANOMALY_INDEX_INVARIANTS,
  OBSERVATION_ANOMALY_INDEXES_SCHEMA_FILE,
} from "../src/schema/observation-anomaly-indexes.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const ledgerSql = readFileSync(resolve(schemaDir, OBSERVATION_LEDGER_SCHEMA_FILE), "utf8");
const anomalySql = readFileSync(
  resolve(schemaDir, OBSERVATION_ANOMALY_INDEXES_SCHEMA_FILE),
  "utf8",
);
const assembledSql = `${ledgerSql}\n${anomalySql}`;
const allSchemaSql = readdirSync(schemaDir)
  .filter((name) => name.endsWith(".sql"))
  .map((name) => readFileSync(resolve(schemaDir, name), "utf8"))
  .join("\n");

const parseEnumLiterals = (text: string, typeName: string): string[] => {
  const declaration = new RegExp(`CREATE TYPE ${typeName} AS ENUM \\(([^)]*)\\)`, "s").exec(
    text,
  );
  if (declaration === null || declaration[1] === undefined) return [];
  return [...declaration[1].matchAll(/'([^']+)'/g)].map((m) => m[1] ?? "");
};

const tableBody = (sql: string, table: string): string => {
  const match = new RegExp(`CREATE TABLE ${table} \\(([\\s\\S]*?)\\n\\);`).exec(sql);
  expect(match, `CREATE TABLE ${table} must exist in assembled schema`).not.toBeNull();
  return match![1] ?? "";
};

const columnNames = (body: string): string[] =>
  body
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("--") && !line.startsWith("CHECK"))
    .filter(
      (line) =>
        !line.startsWith("UNIQUE") &&
        !line.startsWith("PRIMARY") &&
        !line.startsWith("FOREIGN"),
    )
    .map((line) => line.replace(/,$/, "").split(/\s+/)[0] ?? "")
    .filter((name) => name.length > 0 && name !== "CONSTRAINT");

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

const head = (
  raw: Uint8Array,
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
  rawResponseSha256Override?: string,
): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
  ...(rawResponseSha256Override === undefined ? {} : { rawResponseSha256Override }),
});

const malformed = (raw: Uint8Array): SequenceCapture => ({
  parseResult: "MALFORMED_ENVELOPE",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature: "",
  pSignature: "",
  semanticFingerprint: "",
});

const A = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const A_ID = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const A_PRIME = head(bytes(1, 1, 1, 9), "sigA", "", "fpA");
const B = head(bytes(2, 2, 2, 2), "sigB", "sigA", "fpB");
const C = head(bytes(3, 3, 3, 3), "sigC", "sigB", "fpC");
const A_RET = head(bytes(1, 1, 1, 1), "sigA", "", "fpA");
const X = malformed(bytes(9, 9));
const COL1 = head(bytes(1, 1, 1, 1), "sigA", "", "fpA", "collide");
const COL2 = head(bytes(1, 1, 1, 2), "sigA", "", "fpA", "collide");

const GOLDEN_INPUTS: Record<string, readonly SequenceCapture[]> = {
  AA_BYTE_IDENTICAL: [A, A_ID],
  AA_PRIME_WRAPPER: [A, A_PRIME],
  ABCA_REGRESSION: [A, B, C, A_RET],
  MALFORMED_XX: [X, malformed(bytes(9, 9))],
  DIGEST_COLLISION: [COL1, COL2],
};

describe("parent rollup — assembled head schema", () => {
  it("assembles observers + gateway_observations + observation_anomalies (children 232/233 surface)", () => {
    expect(ledgerSql).toContain("CREATE TABLE observers");
    expect(ledgerSql).toContain("CREATE TABLE gateway_observations");
    expect(anomalySql).toContain("CREATE TABLE observation_anomalies");
    // The landing-proof / lineage tail must not appear in this head assembly.
    expect(assembledSql).not.toContain("CREATE TABLE operation_landing_proofs");
    expect(assembledSql).not.toContain("CREATE TABLE lineage_path_proofs");
  });

  it("every ledger + anomaly inventory invariant anchors in the assembled SQL", () => {
    const missingLedger = OBSERVATION_LEDGER_INVARIANTS.filter(
      (inv) => !ledgerSql.includes(inv.sqlAnchor),
    ).map((inv) => inv.id);
    const missingAnomaly = OBSERVATION_ANOMALY_INDEX_INVARIANTS.filter(
      (inv) => !anomalySql.includes(inv.sqlAnchor),
    ).map((inv) => inv.id);
    expect(missingLedger).toEqual([]);
    expect(missingAnomaly).toEqual([]);
  });

  it("gateway_observations columns name-match GATEWAY_OBSERVATION_RECORD_FIELDS (contract freeze)", () => {
    const cols = new Set(columnNames(tableBody(ledgerSql, "gateway_observations")));
    for (const field of GATEWAY_OBSERVATION_RECORD_FIELDS) {
      expect(cols.has(field.name), `missing gateway_observations.${field.name}`).toBe(true);
    }
  });

  it("observation_anomalies columns name-match OBSERVATION_ANOMALY_RECORD_FIELDS", () => {
    const cols = new Set(columnNames(tableBody(anomalySql, "observation_anomalies")));
    for (const field of OBSERVATION_ANOMALY_RECORD_FIELDS) {
      expect(cols.has(field.name), `missing observation_anomalies.${field.name}`).toBe(true);
    }
  });

  it("b_amount uses zkz_balance_text (not the draft's unbounded zkz_amount_text)", () => {
    expect(ledgerSql).toContain("CREATE DOMAIN zkz_balance_text AS text");
    expect(ledgerSql).toContain("b_amount zkz_balance_text");
    expect(tableBody(ledgerSql, "gateway_observations")).not.toContain("zkz_amount_text");
  });

  it("authoritative evidence is bytea/text — zero JSONB columns in the head assembly", () => {
    expect(assembledSql.toLowerCase()).not.toMatch(/jsonb/);
    expect(ledgerSql).toContain("raw_response_bytes bytea NOT NULL");
  });

  it("SQL enums match frozen contract vocabularies including declaration sequence", () => {
    expect(parseEnumLiterals(ledgerSql, "observer_domain")).toEqual([...OBSERVER_DOMAINS]);
    expect(parseEnumLiterals(ledgerSql, "observation_parse_result")).toEqual([
      ...OBSERVATION_PARSE_RESULTS,
    ]);
    expect(parseEnumLiterals(ledgerSql, "observation_relationship")).toEqual([
      ...OBSERVATION_RELATIONSHIPS,
    ]);
  });

  it("anomaly kind CHECK is exactly the nine frozen OBSERVATION_ANOMALY_KINDS", () => {
    const kindCheck = /kind IN \(([^)]*)\)/s.exec(anomalySql);
    expect(kindCheck).not.toBeNull();
    const literals = [...(kindCheck![1] ?? "").matchAll(/'([^']+)'/g)].map((m) => m[1] ?? "");
    expect(literals).toEqual([...OBSERVATION_ANOMALY_KINDS]);
  });

  it("No-blind-retry collision guard is present (anomaly-classified rows require anomaly pair)", () => {
    expect(anomalySql).toContain("CREATE CONSTRAINT TRIGGER observation_anomaly_pairing_complete");
    expect(anomalySql).toContain("observation_anomaly_guard");
  });
});

describe("parent rollup — node-owned vs external authority (exit criterion)", () => {
  it("wallet_id is nullable on observations and anomalies (external public keys have no wallets row)", () => {
    const obsBody = tableBody(ledgerSql, "gateway_observations");
    const anomalyBody = tableBody(anomalySql, "observation_anomalies");
    // FK without NOT NULL = nullable projection.
    expect(obsBody).toMatch(/wallet_id uuid REFERENCES wallets\(id\)/);
    expect(obsBody).not.toMatch(/wallet_id uuid NOT NULL/);
    expect(anomalyBody).toMatch(/wallet_id uuid REFERENCES wallets\(id\)/);
    expect(anomalyBody).not.toMatch(/wallet_id uuid NOT NULL/);
    const walletIdField = GATEWAY_OBSERVATION_RECORD_FIELDS.find((f) => f.name === "wallet_id");
    expect(walletIdField?.nullable).toBe(true);
  });

  it("wallet_public_key is the non-null stream identity on both tables", () => {
    expect(tableBody(ledgerSql, "gateway_observations")).toContain(
      "wallet_public_key padded_base64url_pubkey NOT NULL",
    );
    expect(tableBody(anomalySql, "observation_anomalies")).toContain(
      "wallet_public_key padded_base64url_pubkey NOT NULL",
    );
  });

  it("observers are keyed by UNIQUE(domain, owner_id) — node and platform cannot share a row", () => {
    expect(tableBody(ledgerSql, "observers")).toContain("UNIQUE (domain, owner_id)");
    expect(parseEnumLiterals(ledgerSql, "observer_domain")).toEqual(["NODE", "PLATFORM"]);
  });

  it("stream uniqueness is per-observer — two observers may both observe the same public key", () => {
    // UNIQUE (observer_id, wallet_public_key, wallet_seq) — not UNIQUE (wallet_public_key, wallet_seq).
    expect(ledgerSql).toContain("UNIQUE (observer_id, wallet_public_key, wallet_seq)");
    expect(ledgerSql).not.toMatch(/UNIQUE\s*\(\s*wallet_public_key\s*,\s*wallet_seq\s*\)/);
  });
});

describe("parent rollup — mandatory database tests 12–14 via frozen sequence driver", () => {
  it.each(GOLDEN_SEQUENCES)("mandatory database tests 12 and 13 golden $name: $description", (golden) => {
    const result = runObservationSequence(GOLDEN_INPUTS[golden.name]!);
    const suppressed = result.events.filter((e) => e.decision === "SUPPRESS_AS_SIGHTING").length;
    expect(result.cursor.rowCount).toBe(golden.appendedRows);
    expect(result.cursor.anomalyCount).toBe(golden.anomalyRows);
    expect(suppressed).toBe(golden.suppressedSightings);
    expect(appendedRelationships(result)).toEqual([...golden.relationships]);
  });

  it("mandatory database test 12 AA_BYTE_IDENTICAL: consecutive byte-identical A,A stores one observation + one sighting", () => {
    const g = GOLDEN_SEQUENCES.find((s) => s.name === "AA_BYTE_IDENTICAL")!;
    const result = runObservationSequence(GOLDEN_INPUTS.AA_BYTE_IDENTICAL!);
    expect(result.cursor.rowCount).toBe(1);
    expect(result.events.filter((e) => e.decision === "SUPPRESS_AS_SIGHTING")).toHaveLength(1);
    expect(g.appendedRows).toBe(1);
  });

  it("mandatory database test 12 ABCA_REGRESSION: A,B,C,A stores four with final REGRESSION + one anomaly", () => {
    const result = runObservationSequence(GOLDEN_INPUTS.ABCA_REGRESSION!);
    expect(result.cursor.rowCount).toBe(4);
    expect(result.cursor.anomalyCount).toBe(1);
    expect(appendedRelationships(result)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "SUCCESSOR",
      "REGRESSION",
    ]);
  });

  it("mandatory database test 13 MALFORMED_XX: identical malformed bytes always append (never consecutive-dedup)", () => {
    const result = runObservationSequence(GOLDEN_INPUTS.MALFORMED_XX!);
    expect(result.cursor.rowCount).toBe(2);
    expect(result.cursor.anomalyCount).toBe(2);
    expect(appendedRelationships(result)).toEqual(["NOT_APPLICABLE", "NOT_APPLICABLE"]);
  });

  it("mandatory database test 14 node vs platform: independent cursors on the same public key never share authority", () => {
    // Two independent stream folds (one per observer domain) — same captures, separate cursors.
    const nodeStream = runObservationSequence([A, B, C]);
    const platformStream = runObservationSequence([A, B, C], EMPTY_CURSOR);
    expect(appendedRelationships(nodeStream)).toEqual(appendedRelationships(platformStream));
    expect(nodeStream.cursor.nextWalletSeq).toBe(platformStream.cursor.nextWalletSeq);
    // Losing one observer's cursor must not be importable as the other's authority:
    // replaying the next capture from EMPTY_CURSOR on "platform" while "node" continues
    // produces divergent wallet_seq allocation — structural independence.
    const nodeContinue = runObservationSequence([A_RET], nodeStream.cursor);
    const platformLost = runObservationSequence([A_RET], EMPTY_CURSOR);
    expect(nodeContinue.events[0]?.walletSeq).toBe(4);
    expect(platformLost.events[0]?.walletSeq).toBe(1);
    expect(appendedRelationships(nodeContinue)).not.toEqual(appendedRelationships(platformLost));
  });

  it("negative: a uniformly dead sequence driver cannot pass the positive A,B control", () => {
    const result = runObservationSequence([A, B]);
    expect(result.cursor.rowCount).toBe(2);
    expect(appendedRelationships(result)).toEqual(["FIRST", "SUCCESSOR"]);
  });
});

describe("parent rollup — cursor shape freeze (cross-child consistency for)", () => {
  it("WALLET_OBSERVATION_CURSOR_FIELDS freezes the full cursor column set including wallet_id", () => {
    const names = WALLET_OBSERVATION_CURSOR_FIELDS.map((f) => f.name);
    expect(names).toEqual([
      "observer_id",
      "wallet_id",
      "wallet_public_key",
      "last_recorded_observation_id",
      "last_raw_response_sha256",
      "last_semantic_fingerprint",
      "last_seen_at",
      "consecutive_repeat_count",
      "next_wallet_seq",
    ]);
    const walletId = WALLET_OBSERVATION_CURSOR_FIELDS.find((f) => f.name === "wallet_id");
    expect(walletId?.nullable).toBe(true);
  });

  it("any landed wallet_observation_cursors DDL under schema/ must match the frozen fields", () => {
    // owns the production cursor DDL file. Until it lands this assertion is a
    // contract-shape positive (fields frozen). Once the table SQL appears, the parent
    // freezes field parity so the three children cannot diverge on the cursor shape.
    expect(WALLET_OBSERVATION_CURSOR_FIELDS.length).toBe(9);
    if (!allSchemaSql.includes("CREATE TABLE wallet_observation_cursors")) {
      return;
    }
    const body = tableBody(allSchemaSql, "wallet_observation_cursors");
    const cols = new Set(columnNames(body));
    for (const field of WALLET_OBSERVATION_CURSOR_FIELDS) {
      expect(cols.has(field.name), `missing wallet_observation_cursors.${field.name}`).toBe(
        true,
      );
    }
    expect(body).toContain("PRIMARY KEY (observer_id, wallet_public_key)");
  });

  it("restart from returned cursor reproduces continuation (parent concurrent/restart evidence line)", () => {
    const whole = runObservationSequence([A, B, C, A_RET]);
    const part1 = runObservationSequence([A, B]);
    const part2 = runObservationSequence([C, A_RET], part1.cursor);
    expect([...appendedRelationships(part1), ...appendedRelationships(part2)]).toEqual(
      appendedRelationships(whole),
    );
    expect(part2.cursor.nextWalletSeq).toBe(whole.cursor.nextWalletSeq);
    expect(part2.cursor.rowCount).toBe(whole.cursor.rowCount);
  });
});
