/**
 * SOURCE: the signing-custody-security spec the archive-envelope encoding (envelope
 * canonical encodings); the suite-tuple preimage rule; the wallet-DEK HKDF rule
 * (per-field canonical pins).
 *
 * The archive-envelope encoding canonical-form validators and encoders the archive verifier and the byte-equality
 * restore check both use. Restore byte-equality is proven by re-serializing each row/section with
 * these encoders and comparing BYTES against the archive's original bytes — never by parsed-object
 * deep-equal (the operations-recovery byte rule "never synthesize missing exact bytes from parsed JSON"; the drill matrix census rule).
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const PADDED_B64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;
const KEY_VERSION_RE = /^[1-9][0-9]*$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BIGINT_RE = /^(0|[1-9][0-9]*)$/;

export const isCanonicalUuid = (value: string): boolean => UUID_RE.test(value);
export const isSha256Hex = (value: string): boolean => SHA256_HEX_RE.test(value);
export const isPaddedBase64Url = (value: string): boolean =>
  PADDED_B64URL_RE.test(value) && value.length % 4 === 0 && !value.includes("+") && !value.includes("/");
export const isCanonicalKeyVersion = (value: string): boolean => KEY_VERSION_RE.test(value);
export const isCanonicalTimestamp = (value: string): boolean => TIMESTAMP_RE.test(value);
export const isCanonicalBigint = (value: string): boolean => BIGINT_RE.test(value);

/** Format a Date as UTC RFC 3339 with exactly three fractional digits (the archive-envelope encoding). Sub-millisecond
 *  digits are truncated. Deterministic for a fixed input instant. */
export const formatTimestamp = (instant: Date): string => {
  const iso = instant.toISOString();
  return iso.replace(/(\.\d{3})\d*Z$/, "$1Z");
};

/** The empty-table digest: the manifest/digest rules hashes the empty table as SHA-256(""). */
export const EMPTY_TABLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/**
 * Canonical row serialization for digest and restore: `JSON.stringify` over an object built in
 * schema-declared column sequence (the manifest/digest rules `row_sha256`). The caller supplies the row already built in
 * column sequence; this never reorders keys.
 */
export const serializeRow = (row: Record<string, unknown>): string => JSON.stringify(row);

export const CANONICAL_ENCODING_CONTRACT = {
  bytea: "canonical padded base64url",
  digest: "64 lowercase hex characters (sha256_hex)",
  uuid: "lowercase hyphenated RFC-4122",
  timestamp: "UTC RFC 3339, exactly three fractional digits",
  bigint: "decimal string",
  integer: "JSON number",
  boolean: "JSON true/false",
  null: "JSON null; nullable fields always present, never omitted",
  restore_equality: "byte-equality via canonical re-serialization, never parsed-object deep-equal",
} as const;
