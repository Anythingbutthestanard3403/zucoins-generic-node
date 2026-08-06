import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertVerificationAckEvidenceRoles,
  SCHEMA_VERIFICATION_PROOF_OBLIGATIONS,
  VERIFICATION_PROOF_ENUMS,
  VERIFICATION_PROOF_INVARIANTS,
  VERIFICATION_PROOF_TABLES,
  VERIFICATION_PROOFS_SCHEMA_FILE,
  VERIFICATION_PROOFS_SCHEMA_SOURCE,
} from "../src/schema/verification-proofs.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(
  resolve(here, "../src/schema", VERIFICATION_PROOFS_SCHEMA_FILE),
  "utf8",
);

describe("verification-proofs census", () => {
  it("identifies the frozen sources and contract-text boundary", () => {
    expect(VERIFICATION_PROOFS_SCHEMA_SOURCE).toContain(
      "data-model: enumerations and operation verification acknowledgements",
    );
    expect(sql).toContain("This is a contract artifact");
    expect(sql).toContain("forward references into the separately owned landing-proof");
  });

  it("anchors every frozen invariant in the literal SQL", () => {
    expect(
      VERIFICATION_PROOF_INVARIANTS.filter(({ sqlAnchor }) => !sql.includes(sqlAnchor)).map(
        ({ id }) => id,
      ),
    ).toEqual([]);
  });

  it("contains exactly the table census", () => {
    const tables = [...sql.matchAll(/\bCREATE TABLE ([a-z_]+)/g)].map((match) => match[1]);
    expect(tables).toEqual(VERIFICATION_PROOF_TABLES);
  });

  it("freezes all three enum vocabularies", () => {
    for (const [name, values] of Object.entries(VERIFICATION_PROOF_ENUMS)) {
      const declaration = sql.match(
        new RegExp(`CREATE TYPE ${name} AS ENUM \\(([\\s\\S]*?)\\);`),
      )?.[1];
      expect(declaration, name).toBeDefined();
      const literals = [...(declaration ?? "").matchAll(/'([^']+)'/g)].map((match) => match[1]);
      expect(literals).toEqual(values);
    }
  });

  it("binds VERIFIED to a landing proof, never an acknowledgement", () => {
    expect(sql).toContain("CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)");
    expect(sql).toContain(
      "REFERENCES operation_landing_proofs(id, operation_id, verifier_observer_id)",
    );
  });

  it("stores exact evidence in text plus sha256 columns, never JSONB", () => {
    expect(sql).toContain("proof_manifest_text text NOT NULL");
    expect(sql).toContain("proof_manifest_sha256 sha256_hex NOT NULL");
    expect(sql).not.toMatch(/\bjsonb?\b/i);
  });

  it("freezes acknowledgement idempotency and append-only controls", () => {
    expect(sql).toContain("logical_fingerprint sha256_hex GENERATED ALWAYS AS");
    expect(sql).toContain("CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent");
    expect(sql).toContain("CREATE TRIGGER reporting_acks_immutable");
    expect(sql).toContain("CREATE TRIGGER reporting_acks_no_truncate");
    expect(sql).toContain("REVOKE UPDATE, DELETE, TRUNCATE ON");
  });

  it("freezes one-role/one-wallet evidence uniqueness", () => {
    expect(sql).toContain(
      "CHECK (evidence_role IN\n    ('SOURCE','RECEIVER','DESTINATION'))",
    );
    expect(sql).toContain("PRIMARY KEY (acknowledgement_id, evidence_role)");
    expect(sql).toContain("UNIQUE (acknowledgement_id, wallet_public_key)");
  });

  it("enforces exact evidence cardinality for every operation kind", () => {
    expect(() => assertVerificationAckEvidenceRoles("RECEIVE_EXTERNAL", ["RECEIVER"])).not.toThrow();
    expect(() => assertVerificationAckEvidenceRoles("SEND_EXTERNAL", ["SOURCE"])).not.toThrow();
    expect(() =>
      assertVerificationAckEvidenceRoles("MOVE_INTERNAL", ["SOURCE", "DESTINATION"]),
    ).not.toThrow();

    for (const invalid of [
      () => assertVerificationAckEvidenceRoles("RECEIVE_EXTERNAL", []),
      () => assertVerificationAckEvidenceRoles("RECEIVE_EXTERNAL", ["RECEIVER", "SOURCE"]),
      () => assertVerificationAckEvidenceRoles("SEND_EXTERNAL", ["DESTINATION"]),
      () => assertVerificationAckEvidenceRoles("SEND_EXTERNAL", ["SOURCE", "SOURCE"]),
      () => assertVerificationAckEvidenceRoles("MOVE_INTERNAL", ["SOURCE"]),
      () => assertVerificationAckEvidenceRoles("MOVE_INTERNAL", ["SOURCE", "SOURCE"]),
      () =>
        assertVerificationAckEvidenceRoles("MOVE_INTERNAL", [
          "SOURCE",
          "DESTINATION",
          "RECEIVER",
        ]),
    ]) {
      expect(invalid).toThrow(/requires exactly/);
    }
  });

  it("mutation negative catches a transport-only VERIFIED path", () => {
    const weakened = sql.replace(
      "CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)",
      "CHECK (verdict <> 'VERIFIED' OR terminal_observation_id IS NOT NULL)",
    );
    const missing = VERIFICATION_PROOF_INVARIANTS.filter(
      ({ sqlAnchor }) => !weakened.includes(sqlAnchor),
    ).map(({ id }) => id);
    expect(missing).toContain("VERIFIED_REQUIRES_LANDING_PROOF");
  });

  it("mutation negative catches removal of append-only acknowledgement enforcement", () => {
    const weakened = sql.replace("CREATE TRIGGER reporting_acks_immutable", "CREATE TRIGGER x");
    const missing = VERIFICATION_PROOF_INVARIANTS.filter(
      ({ sqlAnchor }) => !weakened.includes(sqlAnchor),
    ).map(({ id }) => id);
    expect(missing).toContain("ACK_APPEND_ONLY");
  });

  it("records the conflicting-replay database obligations", () => {
    const obligations = SCHEMA_VERIFICATION_PROOF_OBLIGATIONS.join("\n");
    for (const phrase of [
      "Depth coverage",
      "Indeterminacy coverage",
      "Adjudication coverage",
      "conflicting replay",
      "byte comparison",
      "MOVE_INTERNAL",
    ]) {
      expect(obligations).toContain(phrase);
    }
  });
});
