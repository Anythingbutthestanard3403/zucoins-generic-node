/**
 * SOURCE: the vault-storage decision guard 2 (AAD reconstructed at open, binds key_version and
 * key_origin; decrypt->derive-pubkey->match is the primary substitution control) over the
 * drafted signing-custody form (4-field newline AAD stored as a column).
 *
 * the vault model freeze freezes the AAD INPUT FIELD SET and the binding semantics only. The exact byte
 * serialization of the 6-field AAD is the vault schema freeze's byte subcontract; this file does not
 * byte-freeze it.
 */

/** the compatibility-literal preservation rule compatibility literal; the AAD domain-separation string.*/
export const AAD_DOMAIN = "zp-wallet-secret-v1" as const;

export const AAD_BINDING = {
  domain: "zp-wallet-secret-v1",
  input_fields: ["node_id", "wallet_id", "key_version", "public_key", "key_origin"],
  reconstructed_at_open: true,
  stored_as_column: false,
  binds_key_version: true,
  binds_key_origin: true,
  exact_serialization_owner: "vault.2",
} as const;

/**
 * The primary substitution control is cryptographic identity, not the AAD: every open decrypts,
 * derives the public key, and asserts it equals wallets.public_key. The AAD is defense in depth,
 * and binding key_origin makes a B1 imported->node_generated smuggle break the envelope's own
 * decrypt (fail closed).
 */
export const SUBSTITUTION_CONTROL = {
  primary: "DECRYPT_DERIVE_PUBKEY_ASSERT_EQ_WALLETS_PUBLIC_KEY",
  aad_role: "DEFENSE_IN_DEPTH",
  key_origin_smuggle_fails_closed: true,
} as const;

/**
 * The drafted AAD this supersedes: 4 fields (omits key_version and key_origin), newline-joined,
 * persisted in an `aad_text` column. Frozen as the negative fixture — the frozen binding must
 * differ from it in exactly those three respects.
 */
export const SUPERSEDED_DRAFT_AAD = {
  input_fields: ["domain", "node_id", "wallet_id", "public_key"],
  serialization: "NEWLINE_JOINED_UTF8",
  stored_as_column: true,
} as const;
