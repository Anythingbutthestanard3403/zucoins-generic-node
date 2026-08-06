// census: binds the frozen proof-body-store invariant inventory to the
// literal SQL contract text and cross-binds the SQL wallet_role / source_kind literals and
// the documented sighting caps to the frozen ProofBodyStore vocabulary and quota constants
// in src/proof-body, so the truth carriers (contract inventory, SQL text, port vocabulary)
// cannot drift apart. Live-database execution is a schema-apply obligation, inventoried in the
// contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SCHEMA_PROOF_BODY_STORE_OBLIGATIONS,
  PROOF_BODY_STORE_FORBIDDEN_AUTHORITY_TOKENS,
  PROOF_BODY_STORE_INVARIANTS,
  PROOF_BODY_STORE_MUTABILITY_REGIMES,
  PROOF_BODY_STORE_SCHEMA_FILE,
} from "../src/schema/proof-body-store.contract.ts";
import { MAX_SIGHTINGS_PER_BODY, MAX_SIGHTINGS_PER_TENANT } from "../src/proof-body/persist.ts";
import { PROOF_BODY_SOURCE_KIND, PROOF_BODY_WALLET_ROLES } from "../src/proof-body/types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", PROOF_BODY_STORE_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

// cross-binding source of truth: the frozen lineage_path_bodies CREATE TABLE block
// this file's candidate table promotes into by verbatim byte copy (the byte-exact signing rule). Read
// from the committed frozen spec surface so drift in itself -- not just in
// proof-body-store.sql -- reddens this census.
const dataModelPath = resolve(here, "data-model.fixture.md");
const dataModel = readFileSync(dataModelPath, "utf8");
const lineagePathBodiesBlock = ((): string => {
  const match = /CREATE TABLE lineage_path_bodies \(([\s\S]*?)\n\);/.exec(dataModel);
  if (match === null) {
    throw new Error(
      "census: lineage_path_bodies CREATE TABLE block not found in data-model.fixture.md",
    );
  }
  return match[1] ?? "";
})();

// The executable DDL with comment lines removed. The non-authority absence check runs
// against this, so the header comments that EXPLAIN the absence of authority columns do not
// themselves trip the check.
const ddl = sql
  .split("\n")
  .filter((line) => !/^\s*--/.test(line))
  .join("\n");

describe("proof-body-store schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = PROOF_BODY_STORE_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("the source_kind CHECK is pinned to the frozen PROOF_CHANNEL provenance value", () => {
    expect(sql).toContain(`source_kind text NOT NULL CHECK (source_kind = '${PROOF_BODY_SOURCE_KIND}')`);
  });

  it("the wallet_role CHECK literals equal the frozen role vocabulary", () => {
    const roleCheck = /wallet_role text NOT NULL CHECK \(wallet_role IN \(([^)]*)\)\)/.exec(sql);
    expect(roleCheck).not.toBeNull();
    const literals = [...(roleCheck?.[1] ?? "").matchAll(/'([^']+)'/g)].map((m) => m[1] ?? "");
    expect(literals).toEqual([...PROOF_BODY_WALLET_ROLES]);
  });

  it("the documented sighting caps equal the frozen persist.ts quota constants", () => {
    expect(sql).toContain(`MAX_SIGHTINGS_PER_BODY = ${MAX_SIGHTINGS_PER_BODY}`);
    expect(sql).toContain(`MAX_SIGHTINGS_PER_TENANT = ${MAX_SIGHTINGS_PER_TENANT}`);
  });

  it("the durable idempotency ledger keys on the full (tenant, operation, key) tuple", () => {
    expect(sql).toContain(
      "CONSTRAINT proof_channel_candidate_bodies_tenant_op_idem_key\n    UNIQUE (tenant_id, operation_id, idempotency_key),",
    );
    // Never a key-only unique constraint (the cross-tenant collision bug).
    expect(sql).not.toMatch(/UNIQUE\s*\(\s*idempotency_key\s*\)/);
  });

  it("sightings are a bounded COUNTER, never an append table", () => {
    expect(sql).toContain("CREATE TABLE proof_body_slot_sighting_counters");
    expect(sql).toContain("CREATE TABLE proof_body_tenant_sighting_counters");
    expect(sql).toContain("sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0)");
    // No append-ledger row-per-sighting table exists.
    expect(sql).not.toMatch(/CREATE TABLE\s+\w*sightings?\b/);
  });

  it("non-authority: no authority / verdict / landing / lease token in the DDL", () => {
    for (const token of PROOF_BODY_STORE_FORBIDDEN_AUTHORITY_TOKENS) {
      expect(ddl.toLowerCase()).not.toContain(token);
    }
  });

  it("mutation negative: dropping the full-tuple idempotency unique is caught", () => {
    const removed = sql.replace(
      "CONSTRAINT proof_channel_candidate_bodies_tenant_op_idem_key\n    UNIQUE (tenant_id, operation_id, idempotency_key),",
      "",
    );
    expect(removed).not.toBe(sql);
    const missing = PROOF_BODY_STORE_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("CANDIDATE_IDEMPOTENCY_FULL_TRIPLE_UNIQUE");
  });

  it("mutation negative: dropping the slot counter table is caught", () => {
    const removed = sql.replace(
      "CREATE TABLE proof_body_slot_sighting_counters (\n  path_proof_id uuid NOT NULL,\n  path_index bigint NOT NULL CHECK (path_index >= 0),\n  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),\n  PRIMARY KEY (path_proof_id, path_index)\n);",
      "",
    );
    expect(removed).not.toBe(sql);
    const missing = PROOF_BODY_STORE_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("SLOT_SIGHTING_BOUNDED_COUNTER");
  });

  it("mutability regimes: candidate insert-only, counters upsert-only", () => {
    expect(PROOF_BODY_STORE_MUTABILITY_REGIMES.map((r) => r.table)).toEqual([
      "proof_channel_candidate_bodies",
      "proof_body_slot_sighting_counters",
      "proof_body_tenant_sighting_counters",
    ]);
    expect(PROOF_BODY_STORE_MUTABILITY_REGIMES[0]?.regime).toBe("insert_only");
    expect(PROOF_BODY_STORE_MUTABILITY_REGIMES[0]?.updatableColumns).toEqual([]);
    for (const regime of PROOF_BODY_STORE_MUTABILITY_REGIMES.slice(1)) {
      expect(regime.regime).toBe("counter_upsert_only");
      expect(regime.updatableColumns).toEqual(["sighting_count"]);
    }
  });

  it("schema-apply execution obligations are inventoried, including cross-tenant isolation and atomicity", () => {
    expect(SCHEMA_PROOF_BODY_STORE_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_PROOF_BODY_STORE_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_PROOF_BODY_STORE_OBLIGATIONS.some((o) => o.includes("cross-tenant")),
    ).toBe(true);
    expect(
      SCHEMA_PROOF_BODY_STORE_OBLIGATIONS.some((o) => o.includes("advisory lock")),
    ).toBe(true);
  });

  it("the candidate body's material columns match lineage_path_bodies verbatim (byte-faithful promotion-by-copy)", () => {
    // MATERIAL columns: promoted-by-copy from candidate into the verifier's lineage_path_bodies
    // (proof-body-store.sql header). Deliberately excludes path_proof_id (candidate omits the
    // verifier FK by design -- SCHEMA_PROOF_BODY_STORE_OBLIGATIONS "execution sequence") and
    // source_kind (allows 4 values; the candidate CHECK narrows to PROOF_CHANNEL only,
    // already censused by CANDIDATE_SOURCE_KIND_PROOF_CHANNEL_ONLY).
    const materialColumnDeclarations = [
      "path_index bigint NOT NULL CHECK (path_index >= 0),",
      "completed_transaction_text text NOT NULL,",
      "completed_transaction_sha256 sha256_hex NOT NULL,",
      "completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),",
      "wallet_role text NOT NULL CHECK (wallet_role IN ('sender','receiver')),",
      "s_signature padded_base64url_signature NOT NULL,",
      "p_signature text NOT NULL CHECK\n    (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),",
      "b_amount zkz_balance_text NOT NULL,",
      "inner_preimage_text text NOT NULL,",
      "inner_sha256 sha256_hex NOT NULL,",
      "step_1_signature padded_base64url_signature NOT NULL,",
      "step_2_signature padded_base64url_signature NOT NULL,",
      "verification_manifest_text text NOT NULL,",
      "verification_manifest_sha256 sha256_hex NOT NULL,",
    ] as const;
    const twoOctetLengthChecks = [
      "CHECK (octet_length(completed_transaction_text) = completed_transaction_octets)",
      "CHECK (octet_length(inner_preimage_text) > 0)",
    ] as const;
    const genesisOrPaddedSignatureCheck =
      "(p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),";

    // Guards the guard: fails here (not against proof-body-store.sql) if the literal
    // strings above have drifted from itself -- fix the array against, never
    // the SQL against the array.
    const missingFromDataModel = [
      ...materialColumnDeclarations,
      ...twoOctetLengthChecks,
      genesisOrPaddedSignatureCheck,
    ].filter((decl) => !lineagePathBodiesBlock.includes(decl));
    expect(missingFromDataModel).toEqual([]);

    // The actual cross-binding: if 's body-column domains ever drift from what
    // proof-body-store.sql declares (or vice versa), this reddens -- protecting the
    // byte-faithful promotion-by-copy the header comment promises.
    const missingFromCandidate = [
      ...materialColumnDeclarations,
      ...twoOctetLengthChecks,
      genesisOrPaddedSignatureCheck,
    ].filter((decl) => !sql.includes(decl));
    expect(missingFromCandidate).toEqual([]);
  });

  it("the schema document carries this file's table DDL byte-contiguously", () => {
    // closed the code-ahead-of-docs drift by transcribing the three tables into
    // the data model. This binds the two directions: reformat either side and
    // this reddens. The reference domains are excluded from the contiguous block --
    // the schema document declares them once and does not repeat them -- so they are checked
    // separately below.
    //
    // b_amount is the ONE column whose domain name may still differ
    // between SQL (always zkz_balance_text) and a pre-reissue artifact that still
    // carried the retired zkz_amount_text. When the doc still has the legacy token, apply
    // a single documented substitution so every other byte of the three intake tables
    // remains bound. When the data-model artifact has been reissued (both
    // sides zkz_balance_text), the substitution is a no-op identity. Either way the SQL
    // half must never reintroduce the retired name (asserted below).
    const tablesDdl = ddl
      .slice(ddl.indexOf("CREATE TABLE proof_channel_candidate_bodies ("))
      .split("\n")
      .filter((line, index, lines) => line.trim() !== "" || (lines[index - 1] ?? "").trim() !== "")
      .join("\n")
      .trim();
    const bAmountSql = "b_amount zkz_balance_text NOT NULL,";
    const bAmountDocLegacy = "b_amount zkz_amount_text NOT NULL,";
    expect(tablesDdl).toContain(bAmountSql);
    const docStillLegacy =
      dataModel.includes(bAmountDocLegacy) && !dataModel.includes(bAmountSql);
    const tablesDdlForDoc = docStillLegacy
      ? tablesDdl.replace(bAmountSql, bAmountDocLegacy)
      : tablesDdl;
    if (docStillLegacy) {
      expect(tablesDdlForDoc).not.toBe(tablesDdl); // substitution must fire when legacy
    }
    expect(dataModel).toContain(tablesDdlForDoc);

    // Non-amount domains must be byte-identical in the doc. The amount domain line is
    // included only when the doc has been reissued (same predicate + name);
    // under a legacy draft, carve the amount domain out of the ⊆ check — is the
    // authority for that half. Never drop the table half of this census for amount drift.
    const domainDeclarations = ddl
      .slice(0, ddl.indexOf("CREATE TABLE proof_channel_candidate_bodies ("))
      .split("\n")
      .filter((line) => line.trim() !== "");
    const amountDomainInDoc = dataModel.includes("CREATE DOMAIN zkz_balance_text AS text");
    const domainsToCheck = amountDomainInDoc
      ? domainDeclarations
      : domainDeclarations.filter(
          (line) => !line.includes("zkz_balance_text") && !line.includes("[1-9][0-9]{0,7}"),
        );
    expect(domainsToCheck.length).toBeGreaterThan(0);
    expect(domainsToCheck.filter((line) => !dataModel.includes(line))).toEqual([]);
    expect(domainDeclarations.some((line) => line.includes("CREATE DOMAIN zkz_balance_text"))).toBe(
      true,
    );
    // Executable DDL must not reintroduce the retired name (comment prose may name it).
    expect(domainDeclarations.some((line) => line.includes("zkz_amount_text"))).toBe(false);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
