import { createECDH } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  P256_PRIVATE_KEY_LENGTH,
  ecdhFromPrivateKeyBytes,
  generateEcdhKeypair,
  padP256PrivateKeyBytes,
} from "./crypto.js";

describe("P-256 private scalar field width (ZTR-1219)", () => {
  it("left-pads a forced 31-byte short scalar to 32 bytes", () => {
    // Leading high byte omitted — the OpenSSL minimal-length case (~1/256 keygens).
    const short = Buffer.from(
      "46f4667a84f4b6af329c31f2eb91117265be7d1fe0610b0656f7289f492002",
      "hex",
    );
    expect(short).toHaveLength(31);

    const padded = padP256PrivateKeyBytes(short);
    expect(padded).toHaveLength(P256_PRIVATE_KEY_LENGTH);
    expect(padded[0]).toBe(0x00);
    expect(padded.subarray(1).equals(short)).toBe(true);

    // Same curve point whether loaded short or padded.
    const fromShort = createECDH("prime256v1");
    fromShort.setPrivateKey(short);
    const fromPadded = ecdhFromPrivateKeyBytes(short);
    expect(fromPadded.getPublicKey().equals(fromShort.getPublicKey())).toBe(true);
    expect(padP256PrivateKeyBytes(fromPadded.getPrivateKey())).toHaveLength(32);
  });

  it("is a no-op for an already-32-byte scalar", () => {
    const full = Buffer.alloc(32, 0xab);
    full[0] = 0x01;
    expect(padP256PrivateKeyBytes(full)).toBe(full);
  });

  it("rejects empty and over-long inputs", () => {
    expect(() => padP256PrivateKeyBytes(Buffer.alloc(0))).toThrow(/empty/);
    expect(() => padP256PrivateKeyBytes(Buffer.alloc(33))).toThrow(/at most 32/);
  });

  it("generateEcdhKeypair always returns a 32-byte private scalar", () => {
    // Sample enough draws that a short-scalar bug would almost certainly surface
    // (~1/256 raw OpenSSL outputs are 31 bytes; 512 draws → ~86% chance of ≥1 short).
    for (let i = 0; i < 512; i++) {
      const kp = generateEcdhKeypair();
      expect(kp.privateKeyBytes).toHaveLength(P256_PRIVATE_KEY_LENGTH);
      // Public half must still match the private scalar.
      const rebuilt = ecdhFromPrivateKeyBytes(kp.privateKeyBytes);
      expect(rebuilt.getPublicKey().toString("base64url")).toBe(kp.publicKeyB64url);
    }
  });
});
