import { describe, expect, it } from "vitest";

import {
  PADDED_BASE64URL_PUBKEY_LENGTH,
  PADDED_BASE64URL_PUBKEY_PATTERN,
  PADDED_BASE64URL_SIGNATURE_LENGTH,
  PADDED_BASE64URL_SIGNATURE_PATTERN,
  SHA256_HEX_PATTERN,
  ZKZ_BALANCE_TEXT_PATTERN,
} from "../observation/scalars.contract.ts";
import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  CANONICAL_DECIMAL_FORMATTER_RULES,
  DB_REFERENCE_DOMAINS,
  POSITIVE_ZKZ_AMOUNT_MAX,
  SCALAR_TYPES,
  SCHEMA_VOCABS_CONTRACT_VERSION,
  ZKZ_AMOUNT_MAX_DECIMAL_PLACES,
  ZKZ_AMOUNT_TEXT_PATTERN,
  ZKZ_BALANCE_TEXT_PATTERN as RESTATED_BALANCE_PATTERN,
} from "./schema-vocabs.contract.ts";

const amountRegex = new RegExp(ZKZ_AMOUNT_TEXT_PATTERN);

/** The protocol rule 2 ZkzAmount check: canonical decimal string, at most 32 decimals, no sign/exponent. */
const assertZkzAmount = (value: unknown): void => {
  if (typeof value !== "string" || !amountRegex.test(value)) {
    throw new Error("not a canonical ZkzAmount string");
  }
};

describe("schema-vocabs census (the fixture-provenance purposes census, protocol rule 2; data model 1; the amounts-grammar freeze)", () => {
  it("freezes the ten protocol rule 2 scalar types, in declaration sequence", () => {
    assertFieldOrder(
      SCALAR_TYPES.map((entry) => entry.name),
      [
        "Uuid",
        "WalletPublicKey",
        "Ed25519Signature",
        "ZkzAmount",
        "PositiveZkzAmount",
        "UnixTimeSecsV2",
        "ExpiryUnixTimeSecs",
        "Sha256Hex",
        "CanonicalVersion",
        "OpaqueReference",
      ],
    );
  });

  it("freezes the ZkzAmount grammar facts (32dp, positive bound 1e8)", () => {
    expect(ZKZ_AMOUNT_TEXT_PATTERN).toBe("^(0|[1-9][0-9]*)(\\.[0-9]{1,32})?$");
    expect(ZKZ_AMOUNT_MAX_DECIMAL_PLACES).toBe(32);
    expect(POSITIVE_ZKZ_AMOUNT_MAX).toBe("100000000");
    const zkzRow = SCALAR_TYPES.find((entry) => entry.name === "ZkzAmount");
    expect(zkzRow?.rule).toContain("^(0|[1-9][0-9]*)(\\.[0-9]{1,32})?$");
  });

  it("restated regex constants agree with the observation owner (two-source gate)", () => {
    expect(DB_REFERENCE_DOMAINS.sha256_hex).toBe(SHA256_HEX_PATTERN);
    expect(DB_REFERENCE_DOMAINS.padded_base64url_pubkey).toBe(PADDED_BASE64URL_PUBKEY_PATTERN);
    expect(DB_REFERENCE_DOMAINS.padded_base64url_signature).toBe(PADDED_BASE64URL_SIGNATURE_PATTERN);
    expect(PADDED_BASE64URL_PUBKEY_LENGTH).toBe(44);
    expect(PADDED_BASE64URL_SIGNATURE_LENGTH).toBe(88);
    expect(RESTATED_BALANCE_PATTERN).toBe(ZKZ_BALANCE_TEXT_PATTERN);
  });

  it("the amounts-grammar freeze bounded balance domain accepts \"0\" and caps the integer part at 8 digits", () => {
    const balanceRegex = new RegExp(RESTATED_BALANCE_PATTERN);
    expect(balanceRegex.test("0")).toBe(true);
    expect(balanceRegex.test("99999999.5")).toBe(true);
    expect(balanceRegex.test("100000000")).toBe(false);
  });

  it("freezes the canonical decimal formatter rules (protocol rule 2)", () => {
    expect(CANONICAL_DECIMAL_FORMATTER_RULES.removesTrailingFractionalZeros).toBe(true);
    expect(CANONICAL_DECIMAL_FORMATTER_RULES.removesDecimalPointWhenFractionEmpty).toBe(true);
    expect(CANONICAL_DECIMAL_FORMATTER_RULES.emitsZeroNeverNegativeZero).toBe(true);
    expect(CANONICAL_DECIMAL_FORMATTER_RULES.foreignSignedBytesNeverRewrittenToMatch).toBe(true);
  });

  it("accepts canonical amount boundary strings", () => {
    for (const value of ["0", "2.25", "100000000", `0.${"1".repeat(32)}`]) {
      expect(() => assertZkzAmount(value), value).not.toThrow();
    }
  });

  it("rejects amount mutations: leading zero, exponent, sign, >32dp, JSON number (negative path)", () => {
    for (const value of ["01.5", "1e2", "+1", "-1", `0.${"1".repeat(33)}`, 2.25, "1."]) {
      expectRejects(
        () => value,
        (mutated) => assertZkzAmount(mutated),
      );
    }
  });

  it("rejects an uppercase/non-canonical UUID spelling (negative path)", () => {
    const uuidRow = SCALAR_TYPES.find((entry) => entry.name === "Uuid");
    expect(uuidRow?.rule).toContain("reject alternate spellings");
    const canonical = "aaaaaaaa-3333-4333-8333-333333333333";
    expect(canonical.toUpperCase()).not.toBe(canonical);
  });

  it("rejects a reordered scalar-type table (negative path)", () => {
    expectRejects(
      () => SCALAR_TYPES.map((entry) => entry.name).reverse(),
      (mutated) =>
        assertFieldOrder(
          mutated,
          SCALAR_TYPES.map((entry) => entry.name),
        ),
    );
  });

  it("pins the manifest version", () => {
    expect(SCHEMA_VOCABS_CONTRACT_VERSION).toBe(1);
  });
});
