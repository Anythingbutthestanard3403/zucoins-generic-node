/**
 * The A.1.1 rule-6 SHA-256 digest helper (identity-pin fingerprint hardening).
 *
 * : the two node-crypto-only preimage primitives the presentation-scope concern.1's identity-pin predicate needs
 * (`utf8Bytes`, `sha256Hex`) extracted OUT of the TEST-ONLY `testkit/independentCrypto.ts` oracle
 * so `identity-pin.contract.ts` — a FROZEN contract module re-exported through the presentation-scope concern.2
 * capability surface — no longer transitively loads `node:module`(createRequire)+libsodium at
 * module eval time. These are pure SHA-256/UTF-8 helpers: no libsodium, no `createRequire`, no
 * state, no I/O, and SHA-256 is byte-deterministic across every correct implementation, so this
 * changes NO frozen byte (the byte-exact signing rule). It is deliberately NOT a `*.contract.ts`/`manifest.ts`
 * module, so the CONTRACT_FREEZE dependency boundary (../../CONTRACT.md) permits its `node:crypto`
 * import — the same tier a `verifier.ts` occupies.
 */
import { createHash } from "node:crypto";

/** Exact UTF-8 bytes of `text`. No BOM, normalization, or trailing byte is added (A.1.1). */
export const utf8Bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

/** Lowercase 64-char hex SHA-256 of `bytes` (A.1.1 rule 6). */
export const sha256Hex = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
