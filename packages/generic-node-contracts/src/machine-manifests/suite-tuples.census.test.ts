import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  ARTIFACT_ENVELOPE_FIELD_SEQUENCE,
  CEREMONY_WINDOW_RULE,
  DEFERRED_IMPLEMENTER_TUPLES,
  DESTINATION_BLESS_TUPLE,
  DEVICE_ENROL_LABEL_RULES,
  DEVICE_ENROL_TUPLE,
  REPORT_REQUEST_WINDOW_MAX_SECONDS,
  SUITE_TUPLES_CONTRACT_VERSION,
  WALLET_HEAD_FINGERPRINT_EXCLUSIONS,
  WALLET_HEAD_FINGERPRINT_TUPLE,
} from "./suite-tuples.contract.ts";

const fieldNames = (tuple: { readonly fields: readonly { readonly name: string }[] }): string[] =>
  tuple.fields.map((field) => field.name);

/** The ceremony-window check (A.4.1-A.4.3): 0 < expires − issued ≤ 300s. */
const assertCeremonyWindow = (issuedAt: string, expiresAt: string): void => {
  const deltaSeconds = (Date.parse(expiresAt) - Date.parse(issuedAt)) / 1000;
  if (deltaSeconds <= 0 || deltaSeconds > CEREMONY_WINDOW_RULE.maxSeconds) {
    throw new Error("ceremony window outside (0, 300] seconds");
  }
};

describe("suite-tuples census (the fixture-provenance purposes census, A.3.4,A.4.2,A.4.3,A.6,A.7)", () => {
  it("freezes zp-destination-bless-v1's 9-field sequence (A.4.2)", () => {
    expect(DESTINATION_BLESS_TUPLE.purpose).toBe("zp-destination-bless-v1");
    expect(DESTINATION_BLESS_TUPLE.signingKeyRole).toBe("device");
    assertFieldOrder(fieldNames(DESTINATION_BLESS_TUPLE), [
      "purpose",
      "canonical_version",
      "node_id",
      "destination_id",
      "wallet_id",
      "wallet_pubkey",
      "nonce",
      "issued_at",
      "expires_at",
    ]);
  });

  it("freezes zp-device-enrol-v1's 9-field sequence (A.4.3)", () => {
    expect(DEVICE_ENROL_TUPLE.purpose).toBe("zp-device-enrol-v1");
    expect(DEVICE_ENROL_TUPLE.signingKeyRole).toBe("device");
    assertFieldOrder(fieldNames(DEVICE_ENROL_TUPLE), [
      "purpose",
      "canonical_version",
      "node_id",
      "new_device_key_id",
      "new_device_public_key",
      "label",
      "nonce",
      "issued_at",
      "expires_at",
    ]);
  });

  it("freezes the device-enrol label rules (A.4.3 field 6, Unicode 17.0 pin)", () => {
    expect(DEVICE_ENROL_LABEL_RULES.minScalars).toBe(1);
    expect(DEVICE_ENROL_LABEL_RULES.maxScalars).toBe(80);
    expect(DEVICE_ENROL_LABEL_RULES.maxUtf8Bytes).toBe(320);
    expect(DEVICE_ENROL_LABEL_RULES.normalization).toBe("none");
    expect(DEVICE_ENROL_LABEL_RULES.denylistedCategories).toHaveLength(6);
    expect(DEVICE_ENROL_LABEL_RULES.unicodeVersionPin).toBe("17.0");
  });

  it("freezes the unsigned wallet-head fingerprint's 10-field sequence (A.7)", () => {
    expect(WALLET_HEAD_FINGERPRINT_TUPLE.purpose).toBe("zp-wallet-head-fingerprint-v1");
    expect(WALLET_HEAD_FINGERPRINT_TUPLE.signed).toBe(false);
    assertFieldOrder(fieldNames(WALLET_HEAD_FINGERPRINT_TUPLE), [
      "purpose",
      "canonical_version",
      "wallet_public_key",
      "state_kind",
      "s_signature",
      "p_signature",
      "b_amount",
      "inner_sha256",
      "step_1_signature",
      "step_2_signature",
    ]);
    const nullable = WALLET_HEAD_FINGERPRINT_TUPLE.fields.filter((field) => field.nullable);
    assertFieldOrder(
      nullable.map((field) => field.name),
      ["inner_sha256", "step_1_signature", "step_2_signature"],
    );
  });

  it("freezes the fingerprint transport exclusions (A.7)", () => {
    assertFieldOrder(WALLET_HEAD_FINGERPRINT_EXCLUSIONS, [
      "gateway envelope",
      "endpoint",
      "observation time",
      "HTTP status",
      "raw-response hash",
    ]);
  });

  it("freezes the A.3.4 artifact envelope field sequence", () => {
    assertFieldOrder(ARTIFACT_ENVELOPE_FIELD_SEQUENCE, [
      "key_id",
      "preimage_text",
      "preimage_sha256",
      "signature",
    ]);
  });

  it("freezes the ceremony window rule and the tighter reporting window", () => {
    expect(CEREMONY_WINDOW_RULE.maxSeconds).toBe(300);
    expect(CEREMONY_WINDOW_RULE.checkedAgainst).toContain("signed issued_at");
    expect(REPORT_REQUEST_WINDOW_MAX_SECONDS).toBe(60);
  });

  it("freezes the C4 deferral of the three implementer tuples (A.6)", () => {
    assertFieldOrder(
      DEFERRED_IMPLEMENTER_TUPLES.map((tuple) => tuple.purpose),
      ["zp-implementer-event-v1", "zp-implementer-checkpoint-v1", "zp-implementer-keyrotation-v1"],
    );
    for (const tuple of DEFERRED_IMPLEMENTER_TUPLES) {
      expect(tuple.disposition).toBe("deferred-c4");
    }
  });

  it("the A.8 goldens' shared 300-second window satisfies the ceremony rule (boundary)", () => {
    expect(() =>
      assertCeremonyWindow("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z"),
    ).not.toThrow();
  });

  it("rejects a ceremony window over 300 seconds (negative path)", () => {
    expectRejects(
      () => ["2026-07-18T00:00:00.000Z", "2026-07-18T00:05:01.000Z"],
      ([issued, expires]) => assertCeremonyWindow(issued, expires),
    );
  });

  it("rejects a zero/negative ceremony window (negative path)", () => {
    expectRejects(
      () => ["2026-07-18T00:05:00.000Z", "2026-07-18T00:05:00.000Z"],
      ([issued, expires]) => assertCeremonyWindow(issued, expires),
    );
  });

  it("rejects a reordered tuple field sequence (negative path)", () => {
    expectRejects(
      () => [...fieldNames(DESTINATION_BLESS_TUPLE)].reverse(),
      (mutated) => assertFieldOrder(mutated, fieldNames(DESTINATION_BLESS_TUPLE)),
    );
  });

  it("rejects a dropped nullable fingerprint field (negative path)", () => {
    expectRejects(
      () => fieldNames(WALLET_HEAD_FINGERPRINT_TUPLE).filter((name) => name !== "inner_sha256"),
      (mutated) => assertFieldOrder(mutated, fieldNames(WALLET_HEAD_FINGERPRINT_TUPLE)),
    );
  });

  it("pins the manifest version", () => {
    expect(SUITE_TUPLES_CONTRACT_VERSION).toBe(1);
  });
});
