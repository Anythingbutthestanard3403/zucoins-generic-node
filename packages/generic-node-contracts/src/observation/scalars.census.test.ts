import { describe, expect, it } from "vitest";

import {
  SHA256_HEX_PATTERN,
  PADDED_BASE64URL_PUBKEY_PATTERN,
  PADDED_BASE64URL_PUBKEY_LENGTH,
  PADDED_BASE64URL_SIGNATURE_PATTERN,
  PADDED_BASE64URL_SIGNATURE_LENGTH,
  ZKZ_BALANCE_TEXT_PATTERN,
} from "./scalars.contract.ts";
import {
  isSha256Hex,
  isPaddedPubkey,
  isPaddedSignature,
  isEmptyOrPaddedSignature,
  isZkzBalanceText,
} from "./scalars.ts";

const SIG = "A".repeat(86) + "==";
const PUBKEY = "A".repeat(43) + "=";
const DIGEST = "a".repeat(64);

describe("scalar domain patterns are frozen (the observation dedup freeze; the amounts-grammar freeze)", () => {
  it("pattern strings match the reference scalar / amounts-grammar domains verbatim", () => {
    expect(SHA256_HEX_PATTERN).toBe("^[0-9a-f]{64}$");
    expect(PADDED_BASE64URL_PUBKEY_PATTERN).toBe("^[A-Za-z0-9_-]{43}=$");
    expect(PADDED_BASE64URL_PUBKEY_LENGTH).toBe(44);
    expect(PADDED_BASE64URL_SIGNATURE_PATTERN).toBe("^[A-Za-z0-9_-]{86}==$");
    expect(PADDED_BASE64URL_SIGNATURE_LENGTH).toBe(88);
    expect(ZKZ_BALANCE_TEXT_PATTERN).toBe("^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$");
  });
});

describe("scalar matchers accept valid and reject invalid (the observation dedup freeze)", () => {
  it("sha256_hex", () => {
    expect(isSha256Hex(DIGEST)).toBe(true);
    expect(isSha256Hex("A".repeat(64))).toBe(false);
    expect(isSha256Hex("a".repeat(63))).toBe(false);
  });

  it("padded_base64url_pubkey", () => {
    expect(isPaddedPubkey(PUBKEY)).toBe(true);
    expect(isPaddedPubkey("A".repeat(44))).toBe(false);
    expect(isPaddedPubkey("A".repeat(42) + "=")).toBe(false);
  });

  it("padded_base64url_signature and empty-or-padded", () => {
    expect(isPaddedSignature(SIG)).toBe(true);
    expect(isPaddedSignature("")).toBe(false);
    expect(isEmptyOrPaddedSignature("")).toBe(true);
    expect(isEmptyOrPaddedSignature(SIG)).toBe(true);
    expect(isEmptyOrPaddedSignature("A".repeat(88))).toBe(false);
  });

  it("zkz_balance_text accepts 0, bounded values, 32dp; rejects >=1e8, leading zero, negatives", () => {
    expect(isZkzBalanceText("0")).toBe(true);
    expect(isZkzBalanceText("2.25")).toBe(true);
    expect(isZkzBalanceText("99999999." + "9".repeat(32))).toBe(true);
    expect(isZkzBalanceText("100000000")).toBe(false);
    expect(isZkzBalanceText("01")).toBe(false);
    expect(isZkzBalanceText("-1")).toBe(false);
    expect(isZkzBalanceText("1." + "9".repeat(33))).toBe(false);
  });
});
