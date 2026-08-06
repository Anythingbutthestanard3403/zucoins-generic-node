import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import {
  InvalidScalarError,
  inspectForeignSignedUnixTimeSecs,
  parseCanonicalVersion,
  parseEd25519Signature,
  parseExpiryUnixTimeSecs,
  parseOpaqueReference,
  parsePreviousStateSignature,
  parseSha256Hex,
  parseUnixTimeSecsV2,
  parseUuid,
  parseWalletPublicKey,
  type ScalarFailureReason,
  type ScalarKind,
} from "../src/protocol/scalars.js";

function expectInvalid(
  operation: () => unknown,
  scalarKind: ScalarKind,
  reason?: ScalarFailureReason,
): void {
  try {
    operation();
    throw new Error("expected canonical validation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidScalarError);
    const invalid = error as InvalidScalarError;
    expect(invalid.scalarKind).toBe(scalarKind);
    if (reason !== undefined) expect(invalid.reason).toBe(reason);
  }
}

function paddedBase64Url(byteLength: number): string {
  const unpadded = Buffer.alloc(byteLength).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

describe("canonical protocol scalar trust boundaries", () => {
  it("rejects non-string coercion inputs before parsing", () => {
    const nonStrings: unknown[] = [undefined, null, 0, 1, Number.NaN, {}, [], true];
    const stringParsers = [
      parseUuid,
      parseWalletPublicKey,
      parseEd25519Signature,
      parsePreviousStateSignature,
      parseUnixTimeSecsV2,
      parseExpiryUnixTimeSecs,
      parseSha256Hex,
    ];

    for (const parser of stringParsers) {
      for (const value of nonStrings) expect(() => parser(value)).toThrow(InvalidScalarError);
    }
  });

  it("accepts lowercase UUID spelling without adding version, variant, or nil policy", () => {
    expect(parseUuid("00000000-0000-0000-0000-000000000000")).toBe(
      "00000000-0000-0000-0000-000000000000",
    );
    expect(parseUuid("ffffffff-ffff-ffff-ffff-ffffffffffff")).toBe(
      "ffffffff-ffff-ffff-ffff-ffffffffffff",
    );

    for (const value of [
      "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
      "{00000000-0000-0000-0000-000000000000}",
      "urn:uuid:00000000-0000-0000-0000-000000000000",
      "00000000000000000000000000000000",
      "00000000-0000-0000-0000-00000000000g",
    ]) {
      expectInvalid(() => parseUuid(value), "Uuid", "invalid_format");
    }
  });

  it("requires canonical padded base64url keys and signatures with exact decoded lengths", () => {
    const publicKey = paddedBase64Url(32);
    const signature = paddedBase64Url(64);
    expect(publicKey).toHaveLength(44);
    expect(signature).toHaveLength(88);
    expect(parseWalletPublicKey(publicKey)).toBe(publicKey);
    expect(parseEd25519Signature(signature)).toBe(signature);

    for (const value of [
      publicKey.replace(/=$/, ""),
      publicKey.replace("A", "+"),
      publicKey.replace("A", "/"),
      paddedBase64Url(31),
      Buffer.alloc(33).toString("base64url"),
    ]) {
      expectInvalid(() => parseWalletPublicKey(value), "WalletPublicKey");
    }
    for (const value of [
      signature.replace(/==$/, ""),
      signature.replace("A", "+"),
      paddedBase64Url(63),
      Buffer.alloc(65).toString("base64url") + "=",
    ]) {
      expectInvalid(() => parseEd25519Signature(value), "Ed25519Signature");
    }
  });

  it("rejects noncanonical pad-bit aliases that decode to the same bytes", () => {
    const publicKey = paddedBase64Url(32);
    const publicKeyAlias = `${publicKey.slice(0, -2)}B=`;
    expect(Buffer.from(publicKeyAlias, "base64url")).toEqual(Buffer.from(publicKey, "base64url"));
    expectInvalid(
      () => parseWalletPublicKey(publicKeyAlias),
      "WalletPublicKey",
      "non_canonical_encoding",
    );

    const signature = paddedBase64Url(64);
    const signatureAlias = `${signature.slice(0, -3)}B==`;
    expect(Buffer.from(signatureAlias, "base64url")).toEqual(
      Buffer.from(signature, "base64url"),
    );
    expectInvalid(
      () => parseEd25519Signature(signatureAlias),
      "Ed25519Signature",
      "non_canonical_encoding",
    );
  });

  it("keeps the empty genesis predecessor distinct from a normal signature", () => {
    const signature = paddedBase64Url(64);
    expect(parsePreviousStateSignature("")).toBe("");
    expect(parsePreviousStateSignature(signature)).toBe(signature);
    expectInvalid(() => parsePreviousStateSignature("="), "PreviousStateSignature");
  });

  it("separates wallet decimal time from integer expiry time", () => {
    const currentStyleMilliseconds = (1_784_332_800_125 / 1000).toString();
    expect(currentStyleMilliseconds).toBe("1784332800.125");
    // Node-authored CONSTRUCTION stays strict (the byte-exact signing rule): parseUnixTimeSecsV2 accepts only
    // canonical shortest form — an integer, or 1–3 fractional digits whose final digit is non-zero.
    for (const value of [
      "0",
      "0.001",
      "1",
      "1.5",
      "1784332800",
      "1784332800.5",
      "1784332800.125",
      "9999999999999.999",
    ]) {
      expect(parseUnixTimeSecsV2(value)).toBe(value);
    }
    // ...and REJECTS any trailing fractional zero, so the node never signs a non-canonical clock.
    // The FOREIGN-signed verify inspector accepts those same spellings (see the next test).
    for (const value of [
      ".5",
      "00",
      "01.2",
      "1.",
      "0.0",
      "1.000",
      "1.230",
      "1.1234",
      "1784332800.",
      "1784332800.50",
      "1784332800.500",
      "1784332800.1234",
      "10000000000000",
      "+1",
      "-0",
      "1e3",
      " 1",
      "1 ",
    ]) {
      expectInvalid(() => parseUnixTimeSecsV2(value), "UnixTimeSecsV2", "invalid_format");
    }
    expectInvalid(
      () => parseUnixTimeSecsV2("9".repeat(10_000)),
      "UnixTimeSecsV2",
      "invalid_length",
    );

    for (const value of ["0", "1", "1784336400", "999999999999999999999"]) {
      expect(parseExpiryUnixTimeSecs(value)).toBe(value);
    }
    for (const value of ["0.0", "1.5", "01", "+1", "-0", "1e3", " 1"]) {
      expectInvalid(
        () => parseExpiryUnixTimeSecs(value),
        "ExpiryUnixTimeSecs",
        "invalid_format",
      );
    }
  });

  it("accepts foreign-signed trailing-zero unix_time_secs by grammar alone, without re-canonicalizing", () => {
    // layer boundary (the byte-exact signing rule): a foreign wallet may sign a grammar-valid but
    // non-canonical trailing-zero spelling; the verify inspector accepts it verbatim, while the
    // node-authored construction parser above rejects the very same strings.
    for (const value of [
      "0",
      "0.0",
      "1",
      "1.000",
      "1.230",
      "1784332800",
      "1784332800.5",
      "1784332800.50",
      "1784332800.500",
      "9999999999999.999",
    ]) {
      const inspection = inspectForeignSignedUnixTimeSecs(value);
      expect(inspection.wellFormed).toBe(true);
      expect(inspection.anomaly).toBe(null);
      expect(inspection.exactText).toBe(value);
    }
    // The two layers provably diverge on the exact trailing-zero spellings QA flagged.
    for (const value of ["1784332800.50", "0.0", "1.000", "1.230"]) {
      expect(inspectForeignSignedUnixTimeSecs(value).wellFormed).toBe(true);
      expectInvalid(() => parseUnixTimeSecsV2(value), "UnixTimeSecsV2", "invalid_format");
    }
    // Grammar still bites: >3 fractional digits, bare dot, leading zero, over-13-digit integer,
    // sign, exponent, and whitespace are all INVALID_FORMAT.
    for (const value of [
      ".5",
      "1.",
      "01.2",
      "1.1234",
      "1784332800.1234",
      "10000000000000",
      "+1",
      "-0",
      "1e3",
      " 1",
    ]) {
      const inspection = inspectForeignSignedUnixTimeSecs(value);
      expect(inspection.wellFormed).toBe(false);
      expect(inspection.anomaly).toBe("INVALID_FORMAT");
    }
    // Non-string and over-length are distinct anomalies, still bounded by MAX length.
    expect(inspectForeignSignedUnixTimeSecs(1784332800).anomaly).toBe("NON_STRING");
    expect(inspectForeignSignedUnixTimeSecs("9".repeat(10_000)).anomaly).toBe("INVALID_LENGTH");
  });

  it("pins lowercase SHA-256 text and numeric canonical_version 1", () => {
    const digest = "a".repeat(64);
    expect(parseSha256Hex(digest)).toBe(digest);
    for (const value of ["A".repeat(64), "a".repeat(63), `${"a".repeat(63)}g`]) {
      expectInvalid(() => parseSha256Hex(value), "Sha256Hex", "invalid_format");
    }

    expect(parseCanonicalVersion(1)).toBe(1);
    for (const value of ["1", 0, 2, 1n, null]) {
      expectInvalid(() => parseCanonicalVersion(value), "CanonicalVersion", "wrong_literal");
    }
  });

  it("preserves opaque reference bytes and code points without normalization", () => {
    const decomposed = "e\u0301";
    expect(parseOpaqueReference(decomposed, { maxUtf8Bytes: 3, maxCodePoints: 2 })).toBe(
      decomposed,
    );
    expect(parseOpaqueReference("😀", { maxUtf8Bytes: 4, maxCodePoints: 1 })).toBe("😀");
    expect(parseOpaqueReference("", { maxUtf8Bytes: 0, maxCodePoints: 0 })).toBe("");

    expectInvalid(
      () => parseOpaqueReference("😀", { maxUtf8Bytes: 3, maxCodePoints: 1 }),
      "OpaqueReference",
      "limit_exceeded",
    );
    expectInvalid(
      () => parseOpaqueReference(decomposed, { maxUtf8Bytes: 3, maxCodePoints: 1 }),
      "OpaqueReference",
      "limit_exceeded",
    );
  });

  it("rejects lone UTF-16 surrogates and invalid caller limits", () => {
    for (const value of ["\ud800", "\udc00", `x\ud800`, `\udc00x`]) {
      expectInvalid(
        () => parseOpaqueReference(value, { maxUtf8Bytes: 100, maxCodePoints: 100 }),
        "OpaqueReference",
        "invalid_utf16",
      );
    }
    for (const limits of [
      { maxUtf8Bytes: -1, maxCodePoints: 1 },
      { maxUtf8Bytes: 1.5, maxCodePoints: 1 },
      { maxUtf8Bytes: 1, maxCodePoints: Number.NaN },
    ]) {
      expectInvalid(
        () => parseOpaqueReference("x", limits),
        "OpaqueReference",
        "invalid_limits",
      );
    }
    expectInvalid(
      () =>
        parseOpaqueReference(
          "x",
          null as unknown as { maxUtf8Bytes: number; maxCodePoints: number },
        ),
      "OpaqueReference",
      "invalid_limits",
    );
  });

  it("never includes the raw rejected value in typed errors", () => {
    const raw = "ATTACKER_VALUE_SHOULD_NOT_BE_LOGGED";
    try {
      parseUuid(raw);
      throw new Error("expected rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidScalarError);
      const invalid = error as InvalidScalarError;
      expect(invalid.message).not.toContain(raw);
      expect(invalid.stack).not.toContain(raw);
      expect(JSON.stringify(invalid)).not.toContain(raw);
      expect(Object.values(invalid).join("|")).not.toContain(raw);
    }
  });
});
