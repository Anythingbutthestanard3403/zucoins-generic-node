// Parse enrolled admin TOTP secrets from env (hex or RFC 4648 base32).
// Lab mode (ADMIN_TOTP_LAB_MODE=1) may bind a process-level secret from this parser.
// Public multi-operator path uses HTTP enrol/confirm instead.

import { decodeBase32 } from "./secret.js";

export function parseAdminTotpSecret(raw: string | undefined | null): Uint8Array | null {
  if (raw === undefined || raw === null) return null;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;

  if (/^[0-9a-fA-F]+$/u.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length >= 32) {
    const buf = Buffer.from(trimmed, "hex");
    if (buf.length >= 16) return new Uint8Array(buf);
    return null;
  }

  const decoded = decodeBase32(trimmed);
  if (decoded !== null && decoded.length >= 16) return decoded;
  return null;
}
