// Narrow raw Ed25519 detached verification for node-core only.
//
// Callers retain all boundary parsing, canonicality checks, and error taxonomy.
// This module owns only RFC 8410 SPKI wrapping + node:crypto.verify over already-
// validated key / preimage / signature bytes. Fail-closed: never throws.
//
// Byte-exact JSON.stringify signing (byte-exact preimage); the v1 node shape is frozen.

import { createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import { Buffer } from "node:buffer";

// RFC 8410 DER prefix for an Ed25519 SubjectPublicKeyInfo carrying a raw 32-byte key.
const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function ed25519PublicKeyObject(rawPublicKeyBytes: Uint8Array): KeyObject | null {
  if (rawPublicKeyBytes.length !== 32) return null;
  const spkiDer = new Uint8Array(ED25519_SPKI_DER_PREFIX.length + rawPublicKeyBytes.length);
  spkiDer.set(ED25519_SPKI_DER_PREFIX, 0);
  spkiDer.set(rawPublicKeyBytes, ED25519_SPKI_DER_PREFIX.length);
  try {
    return createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

/**
 * Raw RFC 8032 Ed25519 detached verify. Inputs must already be domain-validated
 * at the caller boundary (key 32 bytes, signature 64 bytes, exact preimage bytes).
 * Wrong lengths, construction failure, or crypto throw → false. Never throws.
 */
export function verifyRawEd25519(input: {
  readonly publicKeyBytes: Uint8Array;
  readonly preimageBytes: Uint8Array;
  readonly signatureBytes: Uint8Array;
}): boolean {
  if (input.publicKeyBytes.length !== 32) return false;
  if (input.signatureBytes.length !== 64) return false;
  const keyObject = ed25519PublicKeyObject(input.publicKeyBytes);
  if (keyObject === null) return false;
  try {
    return nodeVerify(null, input.preimageBytes, keyObject, input.signatureBytes);
  } catch {
    return false;
  }
}
