// Small Ed25519 helpers for the operator recovery ceremony. Never logs or returns
// private key material (the key-custody rule).

import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import { toBase64UrlPadded } from "@zucoins/node-core";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SEED_BYTES = 32;
const ED25519_SECRET_BYTES = 64;

export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== ED25519_SEED_BYTES) {
    throw new Error("ed25519 seed must be 32 bytes");
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

/** Derive padded base64url public key from a 32-byte seed. */
export function publicKeyFromSeed(seed: Uint8Array): string {
  const spki = createPublicKey(privateKeyFromSeed(seed)).export({ format: "der", type: "spki" });
  return toBase64UrlPadded(Buffer.from(spki).subarray(-ED25519_SEED_BYTES));
}

/** 64-byte libsodium secret = seed||pubkey → signed bytes. */
export function signWithSecret64(secret64: Uint8Array, preimage: Uint8Array): Uint8Array {
  if (secret64.length !== ED25519_SECRET_BYTES) {
    throw new Error("ed25519 secret must be 64 bytes");
  }
  const seed = secret64.subarray(0, ED25519_SEED_BYTES);
  const sig = nodeSign(null, Buffer.from(preimage), privateKeyFromSeed(seed));
  return new Uint8Array(sig);
}

export function signWithSeed(seed: Uint8Array, preimage: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(preimage), privateKeyFromSeed(seed)));
}

/** Padded base64url signature. */
export function signPaddedBase64Url(seed: Uint8Array, preimage: Uint8Array): string {
  return toBase64UrlPadded(signWithSeed(seed, preimage));
}
