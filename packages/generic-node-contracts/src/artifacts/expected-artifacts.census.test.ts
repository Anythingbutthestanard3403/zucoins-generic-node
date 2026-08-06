import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  EXPECTED_ARTIFACT_PURPOSES,
  CANONICAL_VERSION,
  ARTIFACT_SIGNING_KEY_ROLE,
  ARTIFACT_FIELD_TYPES,
  ARTIFACT_FIELD_ROLES,
  SUITE_PREIMAGE_CONSTRUCTION,
  RECEIVE_EXPECTED,
  MOVE_INTERNAL_EXPECTED,
  SEND_EXTERNAL_EXPECTED,
} from "./expected-artifacts.contract.ts";

const nameSequence = (m: { fields: readonly { name: string }[] }): string[] => m.fields.map((f) => f.name);
const nullableNames = (m: { fields: readonly { name: string; nullable: boolean }[] }): string[] =>
  m.fields.filter((f) => f.nullable).map((f) => f.name);

describe("expected-artifact schema census (A.1, A.3, artifacts freeze)", () => {
  it("freezes the three purposes in canonical operation sequence", () => {
    assertFieldOrder(EXPECTED_ARTIFACT_PURPOSES, [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
    ]);
  });

  it("freezes canonical_version as the JSON number 1 (never the string \"1\")", () => {
    expect(CANONICAL_VERSION).toBe(1);
    expect(typeof CANONICAL_VERSION).toBe("number");
  });

  it("freezes the single signing-key role as the node identity key", () => {
    expect(ARTIFACT_SIGNING_KEY_ROLE).toBe("node_identity");
    for (const m of [RECEIVE_EXPECTED, MOVE_INTERNAL_EXPECTED, SEND_EXTERNAL_EXPECTED]) {
      expect(m.signingKeyRole).toBe("node_identity");
      expect(m.serializer).toBe("suite");
      expect(m.canonicalVersion).toBe(1);
    }
  });

  it("freezes the domain-separation construction (purpose is prefix AND field 1; suite != native)", () => {
    expect(SUITE_PREIMAGE_CONSTRUCTION.domainSeparationPrefix).toBe("purpose");
    expect(SUITE_PREIMAGE_CONSTRUCTION.purposeAppearsAsPrefixAndField1).toBe(true);
    expect(SUITE_PREIMAGE_CONSTRUCTION.splitchainNativeSharesBytes).toBe(false);
    for (const m of [RECEIVE_EXPECTED, MOVE_INTERNAL_EXPECTED, SEND_EXTERNAL_EXPECTED]) {
      expect(m.fields[0].name).toBe("purpose");
      expect(m.fields[1].name).toBe("canonical_version");
    }
  });

  it("freezes the field-type and field-role closed sets", () => {
    assertFieldOrder(ARTIFACT_FIELD_TYPES, [
      "purpose_literal",
      "canonical_version_literal",
      "uuid",
      "operation_uuid",
      "ed25519_pubkey_padded",
      "external_address_padded",
      "zkz_amount_positive",
      "anchor",
      "sha256_hex",
      "integer_string_nullable",
      "after_landing_object",
      "source_selector_object",
      "uuid_nullable",
    ]);
    assertClosedSet(ARTIFACT_FIELD_ROLES, [
      "IDENTITY",
      "PARTY",
      "AMOUNT",
      "REFERENCE",
      "POLICY",
      "BINDING",
      "EXPIRY",
    ]);
    const usedTypes = new Set(
      [RECEIVE_EXPECTED, MOVE_INTERNAL_EXPECTED, SEND_EXTERNAL_EXPECTED].flatMap((m) =>
        m.fields.map((f) => f.type),
      ),
    );
    for (const t of usedTypes) {
      expect(ARTIFACT_FIELD_TYPES).toContain(t);
    }
  });

  it("freezes zp-receive-expected-v1 field sequence and count (A.3.1)", () => {
    assertFieldOrder(nameSequence(RECEIVE_EXPECTED), [
      "purpose",
      "canonical_version",
      "node_id",
      "implementer_id",
      "operation_id",
      "receiver_wallet_id",
      "receiver_pubkey",
      "amount_zkz",
      "discriminator",
      "anchor",
      "receiver_t0_fingerprint",
      "expiry_unix_time_secs",
      "after_landing",
      "transfer_code_sha256",
    ]);
    expect(RECEIVE_EXPECTED.fields).toHaveLength(14);
    assertClosedSet(nullableNames(RECEIVE_EXPECTED), ["expiry_unix_time_secs"]);
  });

  it("freezes zp-move-internal-expected-v1 field sequence and count (A.3.2)", () => {
    assertFieldOrder(nameSequence(MOVE_INTERNAL_EXPECTED), [
      "purpose",
      "canonical_version",
      "node_id",
      "implementer_id",
      "operation_id",
      "source_wallet_id",
      "source_pubkey",
      "destination_id",
      "destination_wallet_id",
      "destination_pubkey",
      "amount_zkz",
      "spawned_from_operation_id",
      "references_operation_id",
    ]);
    expect(MOVE_INTERNAL_EXPECTED.fields).toHaveLength(13);
    assertClosedSet(nullableNames(MOVE_INTERNAL_EXPECTED), [
      "spawned_from_operation_id",
      "references_operation_id",
    ]);
  });

  it("freezes zp-send-external-expected-v1 field sequence and count (A.3.3)", () => {
    assertFieldOrder(nameSequence(SEND_EXTERNAL_EXPECTED), [
      "purpose",
      "canonical_version",
      "node_id",
      "implementer_id",
      "operation_id",
      "source_selector",
      "source_pubkey",
      "destination_address",
      "amount_zkz",
      "references_operation_id",
    ]);
    expect(SEND_EXTERNAL_EXPECTED.fields).toHaveLength(10);
    assertClosedSet(nullableNames(SEND_EXTERNAL_EXPECTED), ["references_operation_id"]);
  });

  it("send artifact carries no expiry field (its time bound lives on the separate approval tuple)", () => {
    expect(nameSequence(SEND_EXTERNAL_EXPECTED)).not.toContain("expiry_unix_time_secs");
    expect(nameSequence(MOVE_INTERNAL_EXPECTED)).not.toContain("expiry_unix_time_secs");
  });

  it("rejects a reordered receive field sequence (negative path)", () => {
    expectRejects(
      () => [...nameSequence(RECEIVE_EXPECTED)].reverse(),
      (mutated) => assertFieldOrder(mutated, nameSequence(RECEIVE_EXPECTED)),
    );
  });

  it("rejects a reordered move field sequence (negative path)", () => {
    expectRejects(
      () => {
        const seq = [...nameSequence(MOVE_INTERNAL_EXPECTED)];
        [seq[7], seq[8]] = [seq[8], seq[7]];
        return seq;
      },
      (mutated) => assertFieldOrder(mutated, nameSequence(MOVE_INTERNAL_EXPECTED)),
    );
  });

  it("rejects a fourth expected-artifact purpose (closed set, negative path)", () => {
    expectRejects(
      () => [...EXPECTED_ARTIFACT_PURPOSES, "zp-fourth-expected-v1"],
      (mutated) => assertFieldOrder(mutated, [...EXPECTED_ARTIFACT_PURPOSES]),
    );
  });
});
