// runtime crypto seam for signed reporting verification: SHA-256 helpers,
// Ed25519 SPKI wrapping for registered raw public keys, and fail-closed detached verification.
// Every function is synchronous and total — crypto failures return false/null, never throw into
// the verification pipeline: no unhandled exceptions on auth paths.
//
// The node stores public keys only, and mirrors the `reporting_logical_fingerprint` SQL byte
// for byte. Preimage builders and canonical decoders live in @zucoins/generic-node-contracts
// and are never re-derived here, so signed paths stay byte-exact.
//
// SPKI + node:crypto.verify live in protocol/ed25519-verify; this module keeps the
// reporting-facing UTF-8 preimage convenience and SHA-256 helpers.

import { createHash } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { ed25519PublicKeyObject, verifyRawEd25519 } from "../protocol/ed25519-verify.js";

const UTF8 = new TextEncoder();

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256HexUtf8(text: string): string {
  return sha256Hex(UTF8.encode(text));
}

// Wrap a registered raw 32-byte Ed25519 public key into a node:crypto KeyObject. Returns null on
// any construction failure (corrupt store bytes) so callers fail closed without a try/catch.
export function reportingPublicKeyObject(rawPublicKeyBytes: Uint8Array): KeyObject | null {
  return ed25519PublicKeyObject(rawPublicKeyBytes);
}

// Detached Ed25519 verification over the exact UTF-8 preimage bytes. Any crypto-layer failure
// (bad key bytes, malformed signature, library throw) is a verification failure, never an
// exception into the pipeline.
export function verifyDetachedEd25519(input: {
  readonly publicKeyBytes: Uint8Array;
  readonly preimageText: string;
  readonly signatureBytes: Uint8Array;
}): boolean {
  return verifyRawEd25519({
    publicKeyBytes: input.publicKeyBytes,
    preimageBytes: UTF8.encode(input.preimageText),
    signatureBytes: input.signatureBytes,
  });
}

// A.6: event_hash = SHA256(preimage_bytes || signature_bytes), lowercase hex.
export function computeNodeEventHash(preimageText: string, signatureBytes: Uint8Array): string {
  const preimageBytes = UTF8.encode(preimageText);
  const joined = new Uint8Array(preimageBytes.length + signatureBytes.length);
  joined.set(preimageBytes, 0);
  joined.set(signatureBytes, preimageBytes.length);
  return sha256Hex(joined);
}

// `reporting_logical_fingerprint`, byte for byte:
// 'm'||octet_length(method)||':'||method||'t'||octet_length(raw_target)||':'||raw_target||
// 'b64:'||body_sha256, UTF-8 encoded, SHA-256 hex. Derived from the actual inputs only — a
// caller-supplied fingerprint is never accepted (guarded uniqueness).
export function computeReportingLogicalFingerprint(
  method: string,
  rawTarget: string,
  bodySha256: string,
): string {
  const text =
    `m${UTF8.encode(method).length}:${method}` +
    `t${UTF8.encode(rawTarget).length}:${rawTarget}` +
    `b64:${bodySha256}`;
  return sha256HexUtf8(text);
}
