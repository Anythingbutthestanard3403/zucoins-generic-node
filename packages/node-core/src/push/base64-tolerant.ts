// the push-API's app-server public key field
// (`key_public__base64urlsafenopad`, `push_notification__get_app_server_public_key__v1__nozleh4wul`)
// is, despite its name, standard base64 (`+`/`/`, optionally padded), not actually
// base64url. Ported verbatim from apps/node/src/receivers/push/crypto/vapid-jwt.ts so
// node-core's gateway push actions can validate the field at fetch time.

/** Decode a value that may be standard base64, base64url, or unpadded either way into raw
 * bytes. Normalizes to the standard alphabet + re-pads (base64url re-pad base64url-repadding
 * discipline). */
export function decodeTolerantBase64(value: string): Buffer {
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}
