/**
 * The A.1.1 rule-6 SHA-256 preimage digest (rebuild-and-compare):
 * the node-crypto-only preimage digest the approval concern's `verifyApprovalPreimage` needs, extracted
 * OUT of the TEST-ONLY `testkit/independentCrypto.ts` oracle so `approval/verify.ts` — a production
 * verifier — no longer imports test code or loads `node:module`(createRequire)+libsodium at eval
 * time. Byte-identical to the oracle's `digestPreimage` (SHA-256 over `TextEncoder`-encoded UTF-8
 * bytes), so the frozen A.8 digests are unchanged (the byte-exact signing rule). Ed25519 signature verification
 * stays libsodium and is dependency-injected into `verifyApprovalDeviceSignature` — only the pure,
 * accept-set-free SHA-256 lives here.
 */
import { createHash } from "node:crypto";

/** Lowercase 64-char hex SHA-256 of the exact UTF-8 bytes of `preimageText` (A.1.1 rule 6). */
export const digestPreimage = (preimageText: string): string =>
  createHash("sha256").update(new TextEncoder().encode(preimageText)).digest("hex");
