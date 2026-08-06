// Generate + encode RFC 4648 base32 TOTP secrets and otpauth URIs.
// No otplib dependency — pairs with match.ts HOTP for verify.
// Never log a returned secret.

import { randomBytes } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** New enrolments mint 20 bytes (RFC 4226 recommended). */
const DEFAULT_SECRET_BYTES = 20;

const DEFAULT_ISSUER = "ZuPayments";

export function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** Decode RFC 4648 base32 (padding optional). Returns null on invalid alphabet. */
export function decodeBase32(raw: string): Uint8Array | null {
  const cleaned = raw.replace(/=+$/u, "").replace(/\s+/gu, "").toUpperCase();
  if (cleaned.length === 0) return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Mint a fresh base32-encoded TOTP secret (never logged). */
export function generateTotpSecret(byteLength = DEFAULT_SECRET_BYTES): string {
  return encodeBase32(randomBytes(byteLength));
}

/** otpauth:// URI for authenticator apps. */
export function otpauthUri(
  username: string,
  secretBase32: string,
  issuer = DEFAULT_ISSUER,
): string {
  const label = encodeURIComponent(`${issuer}:${username}`);
  const iss = encodeURIComponent(issuer);
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${iss}&algorithm=SHA1&digits=6&period=30`;
}

/** Decode enrolled base32 to matcher bytes; null when unusable. */
export function totpSecretBytes(secretBase32: string): Uint8Array | null {
  const decoded = decodeBase32(secretBase32);
  if (decoded === null || decoded.length < 10) return null;
  return decoded;
}
