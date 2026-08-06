/**
 * API-key generation + hashing.
 *
 * Relocated off frozen apps/node. Behaviour matches the
 * documented scheme prefixes, 15-byte lookup prefix, and REPORTING/ACTION
 * SHA-256 hash-at-rest. SITE hashing uses node-core password (bcrypt cost 12).
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { hashPassword } from "../../src/http/password.js";

export const SITE_KEY_LOOKUP_PREFIX_LENGTH = 15;

export type ApiKeyKind = "SITE" | "REPORTING" | "ACTION";

export const KEY_SCHEME_PREFIX: Readonly<Record<ApiKeyKind, string>> = Object.freeze({
  SITE: "sk_",
  REPORTING: "rk_",
  ACTION: "ak_",
});

const RANDOM_BYTES = 32;

export function kindForToken(token: string): ApiKeyKind | null {
  if (token.startsWith(KEY_SCHEME_PREFIX.SITE)) return "SITE";
  if (token.startsWith(KEY_SCHEME_PREFIX.REPORTING)) return "REPORTING";
  if (token.startsWith(KEY_SCHEME_PREFIX.ACTION)) return "ACTION";
  return null;
}

export function sha256Hex(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function lookupPrefix(token: string): string {
  return token.slice(0, SITE_KEY_LOOKUP_PREFIX_LENGTH);
}

export interface GeneratedApiKey {
  token: string;
  keyHash: string;
  keyPrefix: string;
}

export async function generateApiKey(kind: ApiKeyKind): Promise<GeneratedApiKey> {
  const token = KEY_SCHEME_PREFIX[kind] + randomBytes(RANDOM_BYTES).toString("base64url");
  const keyPrefix = lookupPrefix(token);
  const keyHash = kind === "SITE" ? await hashPassword(token) : sha256Hex(token);
  return { token, keyHash, keyPrefix };
}

export function sha256Matches(token: string, storedHex: string): boolean {
  const a = Buffer.from(sha256Hex(token), "hex");
  let b: Buffer;
  try {
    b = Buffer.from(storedHex, "hex");
  } catch {
    return false;
  }
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
