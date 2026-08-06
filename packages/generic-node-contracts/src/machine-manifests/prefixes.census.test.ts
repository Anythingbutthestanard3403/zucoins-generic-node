import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  COMPATIBILITY_LITERALS_OWNER,
  PREFIXES_CONTRACT_VERSION,
  RECEIVE_ANCHOR_PATTERN,
  RECEIVE_MESSAGE_FORMAT,
  RECEIVE_MESSAGE_MAX_SCALARS,
  RECEIVE_MESSAGE_PREFIX,
  SUITE_DOMAIN_SEPARATOR,
  TRANSFER_CODE_DIGEST_FORBIDDEN_PREPROCESSING,
  TRANSFER_CODE_DIGEST_RULE,
} from "./prefixes.contract.ts";

describe("prefixes census (the fixture-provenance purposes census, A.1.1,A.2)", () => {
  it("freezes the suite domain separator: purpose + one LF, no trailing LF, purpose twice", () => {
    expect(SUITE_DOMAIN_SEPARATOR.preimageTextConstruction).toBe('purpose + "\\n" + payload_json');
    expect(SUITE_DOMAIN_SEPARATOR.separatorByte).toBe("0x0a");
    expect(SUITE_DOMAIN_SEPARATOR.separatorCharCount).toBe(1);
    expect(SUITE_DOMAIN_SEPARATOR.trailingNewline).toBe(false);
    expect(SUITE_DOMAIN_SEPARATOR.purposeAppearsAsPrefixAndField1).toBe(true);
    expect(SUITE_DOMAIN_SEPARATOR.noBom).toBe(true);
    expect(SUITE_DOMAIN_SEPARATOR.noKeySorting).toBe(true);
    expect(SUITE_DOMAIN_SEPARATOR.noUnicodeNormalization).toBe(true);
  });

  it("freezes the receive-message prefix, format, anchor alphabet, and scalar limit", () => {
    expect(RECEIVE_MESSAGE_PREFIX).toBe("zp1:");
    expect(RECEIVE_MESSAGE_FORMAT).toBe('"zp1:" + discriminator + ":" + anchor');
    expect(RECEIVE_ANCHOR_PATTERN).toBe("^[A-Za-z0-9_-]{1,96}$");
    expect(RECEIVE_MESSAGE_MAX_SCALARS).toBe(256);
  });

  it("freezes the transfer-code digest input rule and its forbidden preprocessing", () => {
    expect(TRANSFER_CODE_DIGEST_RULE).toBe(
      "lowercase_hex(SHA256(UTF8(exact_transfer_code_string)))",
    );
    assertFieldOrder(TRANSFER_CODE_DIGEST_FORBIDDEN_PREPROCESSING, [
      "newline insertion",
      "URL decode",
      "base64 decode",
      "padding repair",
      "JSON parse",
    ]);
  });

  it("points at compat-literals as the zp/zupay literal owner (never duplicated)", () => {
    expect(COMPATIBILITY_LITERALS_OWNER).toBe("src/compat-literals");
  });

  it("the A.8 discriminator+anchor composition satisfies the anchor alphabet and limit", () => {
    const discriminator = "33333333-3333-4333-8333-333333333333";
    const anchor = "ord_7YQ3";
    const message = `${RECEIVE_MESSAGE_PREFIX}${discriminator}:${anchor}`;
    expect(new RegExp(RECEIVE_ANCHOR_PATTERN).test(anchor)).toBe(true);
    expect([...message].length).toBeLessThanOrEqual(RECEIVE_MESSAGE_MAX_SCALARS);
  });

  it("rejects an anchor outside the alphabet (negative path)", () => {
    expect(new RegExp(RECEIVE_ANCHOR_PATTERN).test("ord 7YQ3")).toBe(false);
    expect(new RegExp(RECEIVE_ANCHOR_PATTERN).test("a".repeat(97))).toBe(false);
    expect(new RegExp(RECEIVE_ANCHOR_PATTERN).test("")).toBe(false);
  });

  it("rejects a domain-separator mutation (negative path)", () => {
    expectRejects(
      () => ({ ...SUITE_DOMAIN_SEPARATOR, trailingNewline: true }),
      (mutated) => {
        if (mutated.trailingNewline !== SUITE_DOMAIN_SEPARATOR.trailingNewline) {
          throw new Error("trailing-newline drift");
        }
      },
    );
  });

  it("pins the manifest version", () => {
    expect(PREFIXES_CONTRACT_VERSION).toBe(1);
  });
});
