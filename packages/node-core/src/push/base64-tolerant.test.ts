import { describe, expect, test } from "vitest";

import { decodeTolerantBase64 } from "./base64-tolerant.js";

// the app-server public key field is base64, not actually urlsafe despite its
// name. Both encodings of the same bytes must decode identically.
describe("decodeTolerantBase64", () => {
  test("decodes standard base64 with padding", () => {
    const original = Buffer.from("hello world, this is a test key material");
    const standard = original.toString("base64");
    expect(decodeTolerantBase64(standard).equals(original)).toBe(true);
  });

  test("decodes base64url without padding the same way", () => {
    const original = Buffer.from("hello world, this is a test key material");
    const urlsafe = original.toString("base64url");
    expect(decodeTolerantBase64(urlsafe).equals(original)).toBe(true);
  });

  test("decodes a raw uncompressed P-256 point (65 bytes) in both alphabets identically", () => {
    // The app-server key is a raw EC point in production; exercise a realistic length.
    const original = Buffer.alloc(65, 0xab);
    original[0] = 0x04; // uncompressed point marker
    expect(decodeTolerantBase64(original.toString("base64")).equals(original)).toBe(true);
    expect(decodeTolerantBase64(original.toString("base64url")).equals(original)).toBe(true);
  });
});
