import { describe, expect, it } from "vitest";

import {
  CANONICAL_FIELD_PINS,
  AAD_SOURCE_INJECTIVITY,
  LABEL_FIELD_COUPLING,
} from "./canonicalization.contract.ts";
import {
  isCanonicalUuid,
  isMinimalKeyVersion,
  isCanonicalPublicKey,
  isCanonicalKeyOrigin,
  isLineFeedFree,
  requiresNewLabel,
} from "./canonicalization.ts";
import { AAD_SERIALIZATION } from "./aad-serialization.ts";
import { HKDF_INFO_ENCODING } from "./hkdf-info.ts";

describe("canonical field pins and validators are frozen (the vault threat-model freeze; micro-rule)", () => {
  it("pins", () => {
    expect(CANONICAL_FIELD_PINS.key_version.pin).toBe("^[1-9][0-9]*$");
    expect(CANONICAL_FIELD_PINS.key_origin.pin).toBe("^(node_generated|imported)$");
  });

  it("UUID validator accepts lowercase hyphenated, rejects uppercase (negative)", () => {
    expect(isCanonicalUuid("11111111-1111-4111-8111-111111111111")).toBe(true);
    expect(isCanonicalUuid("11111111-1111-4111-8111-11111111111A")).toBe(false);
    expect(isCanonicalUuid("111111111111411181111111111111111")).toBe(false);
  });

  it("key_version validator is minimal base-10 (negative: leading zero / zero)", () => {
    expect(isMinimalKeyVersion("1")).toBe(true);
    expect(isMinimalKeyVersion("42")).toBe(true);
    expect(isMinimalKeyVersion("01")).toBe(false);
    expect(isMinimalKeyVersion("0")).toBe(false);
  });

  it("public_key validator is padded base64url with no +/ (negative)", () => {
    expect(isCanonicalPublicKey(`${"A".repeat(43)}=`)).toBe(true);
    expect(isCanonicalPublicKey(`${"A".repeat(42)}+=`)).toBe(false);
    expect(isCanonicalPublicKey(`${"A".repeat(43)}/`)).toBe(false);
  });

  it("key_origin validator is the exact lowercase enum (negative: uppercase)", () => {
    expect(isCanonicalKeyOrigin("node_generated")).toBe(true);
    expect(isCanonicalKeyOrigin("imported")).toBe(true);
    expect(isCanonicalKeyOrigin("NODE_GENERATED")).toBe(false);
  });

  it("line-feed-free is the injectivity precondition (negative: embedded LF)", () => {
    expect(isLineFeedFree("node_generated")).toBe(true);
    expect(isLineFeedFree("a\nb")).toBe(false);
  });
});

describe("AAD-source injectivity is frozen (the vault threat-model freeze)", () => {
  it("every source field is NOT NULL and LF-free, so the joined encoding is injective", () => {
    expect(AAD_SOURCE_INJECTIVITY.each_not_null).toBe(true);
    expect(AAD_SOURCE_INJECTIVITY.each_ascii_lf_free).toBe(true);
    expect(AAD_SOURCE_INJECTIVITY.encoding_injective).toBe(true);
    expect(AAD_SOURCE_INJECTIVITY.source_fields).toHaveLength(5);
  });
});

describe("label <-> field-set coupling structurally forbids appending under a label (the vault threat-model freeze)", () => {
  it("each label is coupled to exactly its encoding's field count", () => {
    const aad = LABEL_FIELD_COUPLING.find((c) => c.label === "zp-wallet-secret-v1");
    const dek = LABEL_FIELD_COUPLING.find((c) => c.label === "zp-wallet-dek-v1");
    expect(aad?.field_count).toBe(AAD_SERIALIZATION.field_sequence.length);
    expect(dek?.field_count).toBe(HKDF_INFO_ENCODING.field_sequence.length);
  });

  it("a 7th field under -v1 requires a NEW label (negative path)", () => {
    expect(requiresNewLabel("zp-wallet-secret-v1", 6)).toBe(false);
    expect(requiresNewLabel("zp-wallet-secret-v1", 7)).toBe(true);
    expect(requiresNewLabel("zp-wallet-dek-v1", 4)).toBe(false);
    expect(requiresNewLabel("zp-wallet-dek-v1", 5)).toBe(true);
    expect(requiresNewLabel("unknown-label", 6)).toBe(true);
  });
});
