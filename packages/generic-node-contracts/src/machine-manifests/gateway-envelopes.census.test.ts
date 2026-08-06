import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  GATEWAY_ACTION_FIELDS,
  GATEWAY_FORM_BODY_PARAM,
  GATEWAY_FORM_BODY_TEMPLATE,
  GATEWAY_RESPONSE_FIELDS,
  SUBMIT_OUTCOME_CATEGORIES,
} from "../transfer-code/candidate-intake.contract.ts";
import {
  GATEWAY_ACTION_FIELD_SEQUENCE,
  GATEWAY_ENVELOPE_MUTATION_RULE,
  GATEWAY_ENVELOPES_CONTRACT_VERSION,
  GATEWAY_EVIDENCE_CONTRACT,
  GATEWAY_FORM_BODY_PARAM as RESTATED_FORM_BODY_PARAM,
  GATEWAY_FORM_BODY_TEMPLATE as RESTATED_FORM_BODY_TEMPLATE,
  GATEWAY_NO_PROVEN_NOT_LANDED,
  GATEWAY_RESPONSE_FIELD_SEQUENCE,
  GATEWAY_SUBMIT_OUTCOME_CATEGORIES,
} from "./gateway-envelopes.contract.ts";

describe("gateway-envelopes census (response evidence, transport boundary; the frozen transport rule)", () => {
  it("restated form-transport literals agree with the transfer-code owner (two-source gate)", () => {
    expect(RESTATED_FORM_BODY_PARAM).toBe(GATEWAY_FORM_BODY_PARAM);
    assertFieldOrder(GATEWAY_ACTION_FIELD_SEQUENCE, [...GATEWAY_ACTION_FIELDS]);
    expect(RESTATED_FORM_BODY_TEMPLATE).toBe(GATEWAY_FORM_BODY_TEMPLATE);
    assertFieldOrder(GATEWAY_RESPONSE_FIELD_SEQUENCE, [...GATEWAY_RESPONSE_FIELDS]);
    assertFieldOrder(GATEWAY_SUBMIT_OUTCOME_CATEGORIES, [...SUBMIT_OUTCOME_CATEGORIES]);
  });

  it("freezes the response-evidence rules evidence contract: raw bytes before decode, digest-retained, unsigned", () => {
    expect(GATEWAY_EVIDENCE_CONTRACT.captureRawBytesBeforeDecode).toBe(true);
    assertFieldOrder(GATEWAY_EVIDENCE_CONTRACT.retainedWith, [
      "raw_body_bytes",
      "sha256_digest",
      "transport_metadata",
    ]);
    expect(GATEWAY_EVIDENCE_CONTRACT.signedBlob).toBe(false);
    expect(GATEWAY_EVIDENCE_CONTRACT.byteClass).toBe("unsigned-evidence");
    assertFieldOrder(GATEWAY_EVIDENCE_CONTRACT.signatureNeverAuthenticates, [
      "HTTP status",
      "gateway envelope fields",
      "whitespace",
      "field formatting outside the signed transaction",
      "transport metadata",
    ]);
  });

  it("freezes the envelope-mutation rule (protocol rule 10 v11)", () => {
    expect(GATEWAY_ENVELOPE_MUTATION_RULE.preimageVerificationAffected).toBe(false);
    expect(GATEWAY_ENVELOPE_MUTATION_RULE.changedBytesRetainedAsDistinctEvidence).toBe(true);
    expect(GATEWAY_ENVELOPE_MUTATION_RULE.unchangedSemanticHeadClassification).toBe(
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    );
    expect(GATEWAY_NO_PROVEN_NOT_LANDED).toBe(true);
  });

  it("rejects a tampered restated value (two-source drift, negative path)", () => {
    expectRejects(
      () => [...GATEWAY_RESPONSE_FIELD_SEQUENCE].reverse(),
      (mutated) => assertFieldOrder(mutated, [...GATEWAY_RESPONSE_FIELDS]),
    );
  });

  it("rejects an evidence-contract mutation (negative path)", () => {
    expectRejects(
      () => ({ ...GATEWAY_EVIDENCE_CONTRACT, signedBlob: true }),
      (mutated) => {
        if (mutated.signedBlob !== GATEWAY_EVIDENCE_CONTRACT.signedBlob) {
          throw new Error("evidence must never be a signed blob");
        }
      },
    );
  });

  it("pins the manifest version", () => {
    expect(GATEWAY_ENVELOPES_CONTRACT_VERSION).toBe(1);
  });
});
