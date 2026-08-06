import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  APPROVAL_PURPOSE,
  APPROVAL_CANONICAL_VERSION,
  APPROVAL_PREIMAGE_CONSTRUCTION,
  APPROVAL_AUTH,
  APPROVAL_ORDERING,
  APPROVAL_FORMATION_TIME_FACTS,
  APPROVAL_FIELD_TYPES,
  APPROVAL_FIELD_ROLES,
  APPROVAL_TUPLE,
  SOURCE_SELECTOR_SIGNED_CLOSURE,
} from "./approval-tuple.contract.ts";

const nameSequence = APPROVAL_TUPLE.fields.map((f) => f.name);
const nullableNames = APPROVAL_TUPLE.fields.filter((f) => f.nullable).map((f) => f.name);

describe("approval-tuple schema census (A.4.1, the approval-tuple freeze)", () => {
  it("freezes the approval purpose literal (a compatibility-preserved literal)", () => {
    expect(APPROVAL_PURPOSE).toBe("zp-send-external-approval-v1");
  });

  it("freezes canonical_version as the JSON number 1 (never the string \"1\")", () => {
    expect(APPROVAL_CANONICAL_VERSION).toBe(1);
    expect(typeof APPROVAL_CANONICAL_VERSION).toBe("number");
    expect(APPROVAL_TUPLE.canonicalVersion).toBe(1);
  });

  it("freezes the 12-field sequence and count (A.4.1)", () => {
    assertFieldOrder(nameSequence, [
      "purpose",
      "canonical_version",
      "node_id",
      "operation_id",
      "source_selector",
      "source_pubkey",
      "destination_address",
      "amount_zkz",
      "references_operation_id",
      "nonce",
      "issued_at",
      "expires_at",
    ]);
    expect(APPROVAL_TUPLE.fields).toHaveLength(12);
  });

  it("freezes references_operation_id as the only nullable field", () => {
    assertClosedSet(nullableNames, ["references_operation_id"]);
  });

  it("freezes the field-type and economic-intent-role closed sets", () => {
    assertFieldOrder(APPROVAL_FIELD_TYPES, [
      "purpose_literal",
      "canonical_version_literal",
      "uuid",
      "operation_uuid",
      "source_selector_object",
      "ed25519_pubkey_padded",
      "external_address_padded",
      "zkz_amount_positive",
      "uuid_nullable",
      "canonical_timestamp",
    ]);
    assertClosedSet(APPROVAL_FIELD_ROLES, [
      "IDENTITY",
      "SOURCE",
      "DESTINATION",
      "AMOUNT",
      "REFERENCE",
      "NONCE",
      "ISSUE_TIME",
      "EXPIRY",
    ]);
    for (const f of APPROVAL_TUPLE.fields) {
      expect(APPROVAL_FIELD_TYPES).toContain(f.type);
      expect(APPROVAL_FIELD_ROLES).toContain(f.role);
    }
  });

  it("binds every economic-intent role the approval-tuple freeze/R-08 name (source, destination, amount, reference, nonce, issue time, expiry)", () => {
    const rolesInUse = new Set(APPROVAL_TUPLE.fields.map((f) => f.role));
    for (const role of ["SOURCE", "DESTINATION", "AMOUNT", "REFERENCE", "NONCE", "ISSUE_TIME", "EXPIRY", "IDENTITY"]) {
      expect(rolesInUse).toContain(role);
    }
    // The exact carriers of each economic bound.
    const byName = Object.fromEntries(APPROVAL_TUPLE.fields.map((f) => [f.name, f.role]));
    expect(byName.source_selector).toBe("SOURCE");
    expect(byName.source_pubkey).toBe("SOURCE");
    expect(byName.destination_address).toBe("DESTINATION");
    expect(byName.amount_zkz).toBe("AMOUNT");
    expect(byName.nonce).toBe("NONCE");
    expect(byName.issued_at).toBe("ISSUE_TIME");
    expect(byName.expires_at).toBe("EXPIRY");
  });

  it("freezes the suite serializer: purpose is prefix AND field 1, distinct from SplitChain native bytes", () => {
    expect(APPROVAL_PREIMAGE_CONSTRUCTION.domainSeparationPrefix).toBe("purpose");
    expect(APPROVAL_PREIMAGE_CONSTRUCTION.purposeAppearsAsPrefixAndField1).toBe(true);
    expect(APPROVAL_PREIMAGE_CONSTRUCTION.splitchainNativeSharesBytes).toBe(false);
    expect(APPROVAL_TUPLE.fields[0].name).toBe("purpose");
    expect(APPROVAL_TUPLE.fields[1].name).toBe("canonical_version");
    expect(APPROVAL_TUPLE.serializer).toBe("suite");
  });

  it("freezes TOTP-authenticates-mutation semantics: TOTP is not a signature; device signing is optional additive (C-08)", () => {
    expect(APPROVAL_AUTH.mandatoryGate).toBe("fresh_single_use_totp");
    expect(APPROVAL_AUTH.totpIsDigitalSignature).toBe(false);
    expect(APPROVAL_AUTH.totpBinding).toBe("guarded_mutation");
    expect(APPROVAL_AUTH.optionalDeviceSignature).toBe(true);
    expect(APPROVAL_AUTH.deviceSignatureKind).toBe("additive_hardening");
    expect(APPROVAL_AUTH.deviceSignatureSignsExactApprovalBytes).toBe(true);
    expect(APPROVAL_AUTH.deviceSignatureReplacesTotp).toBe(false);
    expect(APPROVAL_AUTH.deviceSignatureAloneAuthorizes).toBe(false);
  });

  it("freezes the precedence: approval precedes lease acquisition and fresh formation; binds no later inner (A.4.1)", () => {
    assertFieldOrder(APPROVAL_ORDERING, ["APPROVAL", "SOURCE_LEASE_ACQUISITION", "FRESH_CHAIN_FORMATION"]);
    expect(APPROVAL_FORMATION_TIME_FACTS.sourceLeaseHeldAtApprovalTime).toBe(false);
    expect(APPROVAL_FORMATION_TIME_FACTS.splitchainInnerFormedAtApprovalTime).toBe(false);
    expect(APPROVAL_FORMATION_TIME_FACTS.bindsLaterFormedSplitchainInner).toBe(false);
    expect(APPROVAL_FORMATION_TIME_FACTS.carriesSplitInnerSha256Field).toBe(false);
    expect(nameSequence).not.toContain("split_inner_sha256");
  });

  it("rejects a reordered field sequence (negative path)", () => {
    expectRejects(
      () => {
        const seq = [...nameSequence];
        [seq[10], seq[11]] = [seq[11], seq[10]]; // swap issued_at and expires_at
        return seq;
      },
      (mutated) => assertFieldOrder(mutated, nameSequence),
    );
  });

  it("rejects an omitted nullable field (negative path)", () => {
    expectRejects(
      () => nameSequence.filter((n) => n !== "references_operation_id"),
      (mutated) => assertFieldOrder(mutated, nameSequence),
    );
  });

  it("rejects a 13th field beyond the frozen closed set (negative path)", () => {
    expectRejects(
      () => [...nameSequence, "split_inner_sha256"],
      (mutated) => assertFieldOrder(mutated, nameSequence),
    );
  });

  it("freezes the WALLET_ID closure: signed source_selector is always the exact two-key {kind,wallet_id} object", () => {
    expect(SOURCE_SELECTOR_SIGNED_CLOSURE.signedKind).toBe("WALLET_ID");
    assertFieldOrder(SOURCE_SELECTOR_SIGNED_CLOSURE.signedKeyOrder, ["kind", "wallet_id"]);
    expect(SOURCE_SELECTOR_SIGNED_CLOSURE.signedKeyCount).toBe(2);
    expect(SOURCE_SELECTOR_SIGNED_CLOSURE.onlyResolvedSelectorReachesSignedBytes).toBe(true);
  });
});
