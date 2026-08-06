/**
 * Independent, self-contained Ed25519 + digest primitives for the artifacts concern expected-artifact
 * conformance proof (architecture layout: testkit/independentCrypto.ts).
 *
 * "Independent" is load-bearing: this module deliberately does NOT import from
 * packages/splitchain or any node runtime. It re-derives the suite primitives from the
 * workspace's pinned wallet crypto library so the reproduction proof
 * (`src/artifacts/reproduction.test.ts`) is a genuine second implementation checking
 * Appendix A's frozen bytes, not the contract validating itself.
 *
 * Crypto family: `libsodium-wrappers` — the exact package packages/splitchain depends on
 * (Ed25519 is deterministic, so the same seed reproduces the same signature). The library is
 * loaded via `createRequire` for the same upstream-packaging reason splitchain documents: the
 * ESM build does a relative `import "./libsodium.mjs"` that ships only in the separate
 * `libsodium` package, so Node's ESM resolver breaks on it; the CJS build resolves correctly.
 *
 * SHA-256 comes from `node:crypto`, not libsodium: the non-sumo `libsodium-wrappers` build does
 * not expose `crypto_hash_sha256`. SHA-256 is standard and byte-deterministic across correct
 * implementations, so this changes no frozen byte. Encoding is padded URL-safe base64, matching
 * the frozen canonical wallet key/signature spelling.
 */
import { createRequire } from "node:module";
import { createHash } from "node:crypto";

const require = createRequire(import.meta.url);
const _sodium: typeof import("libsodium-wrappers") = require("libsodium-wrappers");

/** A raw Ed25519 keypair as libsodium returns it: 32-byte public, 64-byte secret. */
export interface RawKeypair {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
}

let _readyPromise: Promise<void> | null = null;

/** Await libsodium init exactly once (memoized). Every function touching a libsodium
 *  primitive MUST `await ready()` first. Safe to call concurrently. */
export const ready = (): Promise<void> => {
  if (!_readyPromise) {
    _readyPromise = _sodium.ready;
  }
  return _readyPromise;
};

/** Exact UTF-8 bytes of `text`. No BOM, normalization, or trailing byte is added — the
 *  canonical suite preimage rules forbid all of those. */
export const utf8Bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

/** Lowercase 64-char hex SHA-256 of `bytes` (canonical suite rule 6). */
export const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/** bytes -> padded URL-safe base64 (canonical suite rule 5). Caller must have awaited
 *  `ready()`. */
export const encodeBase64Url = (bytes: Uint8Array): string =>
  _sodium.to_base64(bytes, _sodium.base64_variants.URLSAFE);

/** padded URL-safe base64 -> bytes. Caller must have awaited `ready()`. */
export const decodeBase64Url = (text: string): Uint8Array =>
  _sodium.from_base64(text, _sodium.base64_variants.URLSAFE);

/** Deterministic keypair from a 32-byte Ed25519 seed. Caller must have awaited `ready()`. */
export const keypairFromSeed = (seed: Uint8Array): RawKeypair => {
  const kp = _sodium.crypto_sign_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
};

/** Deterministic keypair from a 32-byte seed filled entirely with `seedByte` — the exact
 *  test-only key construction frozen in the golden fixtures (node identity = byte 0x00, etc.).
 *  These keys MUST never be used with live ZKZ. Caller must have awaited `ready()`. */
export const keypairFromSeedByte = (seedByte: number): RawKeypair =>
  keypairFromSeed(new Uint8Array(32).fill(seedByte));

/** Detached Ed25519 signature over `messageBytes`. Caller must have awaited `ready()`. */
export const signDetached = (messageBytes: Uint8Array, secretKey: Uint8Array): Uint8Array =>
  _sodium.crypto_sign_detached(messageBytes, secretKey);

/** Verify a detached Ed25519 signature. Caller must have awaited `ready()`. */
export const verifyDetached = (
  signature: Uint8Array,
  messageBytes: Uint8Array,
  publicKey: Uint8Array,
): boolean => _sodium.crypto_sign_verify_detached(signature, messageBytes, publicKey);

/** High-level: digest of a suite preimage string (canonical suite serializer). */
export const digestPreimage = (preimageText: string): string => sha256Hex(utf8Bytes(preimageText));

/** High-level: padded base64url detached signature over a suite preimage string. */
export const signPreimage = (preimageText: string, secretKey: Uint8Array): string =>
  encodeBase64Url(signDetached(utf8Bytes(preimageText), secretKey));

/** High-level: verify a padded base64url signature over a suite preimage string. */
export const verifyPreimageSignature = (
  preimageText: string,
  signatureB64Url: string,
  publicKey: Uint8Array,
): boolean => verifyDetached(decodeBase64Url(signatureB64Url), utf8Bytes(preimageText), publicKey);
