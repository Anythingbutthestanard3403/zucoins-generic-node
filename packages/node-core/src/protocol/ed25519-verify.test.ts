// golden + malformed coverage for the single raw Ed25519 verifier.
// Call-site behavior (parse → raw verify) is also covered by each migrated module's
// existing suites; this file pins the shared primitive's byte semantics.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { ed25519PublicKeyObject, verifyRawEd25519 } from "./ed25519-verify.js";

const UTF8 = new TextEncoder();

// RFC 8032 section 7.1 TEST 1 (empty message).
const RFC8032_TEST1 = {
  secretKeyHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  publicKeyHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  messageHex: "",
  signatureHex:
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
} as const;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function rawPublicKeyFromPrivateSeed(seed32: Uint8Array): Uint8Array {
  // PKCS#8 prefix for Ed25519 seed (RFC 8410) + 32-byte seed.
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8 = Buffer.concat([pkcs8Prefix, Buffer.from(seed32)]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  return new Uint8Array(spki.subarray(-32));
}

function signDetached(seed32: Uint8Array, preimage: Uint8Array): Uint8Array {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8 = Buffer.concat([pkcs8Prefix, Buffer.from(seed32)]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return new Uint8Array(sign(null, Buffer.from(preimage), privateKey));
}

describe("verifyRawEd25519", () => {
  it("accepts RFC 8032 section 7.1 TEST 1 (empty preimage)", () => {
    const publicKeyBytes = hexToBytes(RFC8032_TEST1.publicKeyHex);
    const signatureBytes = hexToBytes(RFC8032_TEST1.signatureHex);
    const preimageBytes = hexToBytes(RFC8032_TEST1.messageHex);
    // Alternate construction: derive pub from seed and compare.
    expect(rawPublicKeyFromPrivateSeed(hexToBytes(RFC8032_TEST1.secretKeyHex))).toEqual(
      publicKeyBytes,
    );
    expect(
      verifyRawEd25519({ publicKeyBytes, preimageBytes, signatureBytes }),
    ).toBe(true);
  });

  it("accepts a live node:crypto signature over a UTF-8 preimage", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const preimageBytes = UTF8.encode('{"inner":{"type":"unique_combinable"},"v":2}');
    const signatureBytes = new Uint8Array(sign(null, Buffer.from(preimageBytes), privateKey));
    const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const publicKeyBytes = new Uint8Array(spki.subarray(-32));
    expect(
      verifyRawEd25519({ publicKeyBytes, preimageBytes, signatureBytes }),
    ).toBe(true);
  });

  it("rejects a tampered preimage byte", () => {
    const seed = hexToBytes(RFC8032_TEST1.secretKeyHex);
    const publicKeyBytes = rawPublicKeyFromPrivateSeed(seed);
    const preimageBytes = UTF8.encode("step_1_preimage");
    const signatureBytes = signDetached(seed, preimageBytes);
    const tampered = new Uint8Array(preimageBytes);
    tampered[0] = (tampered[0]! ^ 0xff) as number;
    expect(
      verifyRawEd25519({ publicKeyBytes, preimageBytes: tampered, signatureBytes }),
    ).toBe(false);
  });

  it("rejects a signature under a different public key", () => {
    const seedA = hexToBytes(RFC8032_TEST1.secretKeyHex);
    const seedB = new Uint8Array(32).fill(0x42);
    const preimageBytes = UTF8.encode("shared-preimage");
    const signatureBytes = signDetached(seedA, preimageBytes);
    expect(
      verifyRawEd25519({
        publicKeyBytes: rawPublicKeyFromPrivateSeed(seedB),
        preimageBytes,
        signatureBytes,
      }),
    ).toBe(false);
  });

  it("fails closed on wrong-length public key", () => {
    const sig = new Uint8Array(64);
    const pre = UTF8.encode("x");
    expect(
      verifyRawEd25519({ publicKeyBytes: new Uint8Array(31), preimageBytes: pre, signatureBytes: sig }),
    ).toBe(false);
    expect(
      verifyRawEd25519({ publicKeyBytes: new Uint8Array(33), preimageBytes: pre, signatureBytes: sig }),
    ).toBe(false);
    expect(ed25519PublicKeyObject(new Uint8Array(0))).toBeNull();
  });

  it("fails closed on wrong-length signature", () => {
    const seed = hexToBytes(RFC8032_TEST1.secretKeyHex);
    const publicKeyBytes = rawPublicKeyFromPrivateSeed(seed);
    const preimageBytes = UTF8.encode("x");
    expect(
      verifyRawEd25519({
        publicKeyBytes,
        preimageBytes,
        signatureBytes: new Uint8Array(63),
      }),
    ).toBe(false);
    expect(
      verifyRawEd25519({
        publicKeyBytes,
        preimageBytes,
        signatureBytes: new Uint8Array(65),
      }),
    ).toBe(false);
  });

  it("never throws on malformed inputs", () => {
    expect(() =>
      verifyRawEd25519({
        publicKeyBytes: new Uint8Array(32).fill(0xff),
        preimageBytes: new Uint8Array([1, 2, 3]),
        signatureBytes: new Uint8Array(64).fill(0xff),
      }),
    ).not.toThrow();
  });
});
