/**
 * SOURCE: the AAD/HKDF micro-rule — the binding conditions for the two byte encodings.
 * Per-field canonical pins, the
 * AAD-source injectivity requirement, and the label<->field-set coupling that structurally forbids
 * appending a field under an existing label.
 */

/** Canonical form pins for every AAD / HKDF-info source field. */
export const CANONICAL_FIELD_PINS = {
  node_id: {
    pin: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    note: "lowercase hyphenated UUID",
  },
  wallet_id: {
    pin: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    note: "lowercase hyphenated UUID",
  },
  key_version: {
    pin: "^[1-9][0-9]*$",
    note: "minimal base-10, no leading zero, strictly positive",
  },
  public_key: {
    pin: "^[A-Za-z0-9_-]{43}=$",
    note: "padded base64url with no +/; byte-identical to wallets.public_key",
  },
  key_origin: {
    pin: "^(node_generated|imported)$",
    note: "exact lowercase enum; write-once",
  },
} as const;

/**
 * The newline-joined encoding is injective ONLY because every source field is NOT NULL and
 * contains no line feed, so no two distinct field tuples can produce the same joined string.
 * The wallets-side source columns (node_id, public_key, key_origin) are owned by the custody
 * concern; this contract records the constraint they must carry for the injectivity to hold.
 */
export const AAD_SOURCE_INJECTIVITY = {
  source_fields: ["node_id", "wallet_id", "key_version", "public_key", "key_origin"],
  each_not_null: true,
  each_ascii_lf_free: true,
  encoding_injective: true,
  wallets_side_columns_owned_by_custody_concern: ["node_id", "public_key", "key_origin"],
} as const;

/**
 * The label<->field-set coupling. Each label is coupled to EXACTLY its field count; a field-set
 * change requires a new `-vN` label and may never append under an existing label.
 */
export const LABEL_FIELD_COUPLING = [
  { label: "zp-wallet-secret-v1", purpose: "AAD", field_count: 6 },
  { label: "zp-wallet-dek-v1", purpose: "HKDF_INFO", field_count: 4 },
] as const;

export const LABEL_VERSION_RULE =
  "A FIELD-SET CHANGE REQUIRES A NEW -vN LABEL; NEVER APPEND A FIELD UNDER AN EXISTING LABEL" as const;
