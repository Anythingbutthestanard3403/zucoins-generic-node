// Claim-token mint + hash. Raw token is returned once at intake; only the
// unsalted SHA-256 hex is durable (same discipline as credential_hash).

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { CLAIM_TOKEN_PREFIX } from "./types.js";

export function generateClaimToken(): string {
  return CLAIM_TOKEN_PREFIX + randomBytes(32).toString("base64url");
}

export function hashClaimToken(rawToken: string): string {
  return createHash("sha256").update(rawToken, "utf8").digest("hex");
}

/** Constant-time hex hash compare. Length mismatch → false (no throw). */
export function claimTokenHashesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}
