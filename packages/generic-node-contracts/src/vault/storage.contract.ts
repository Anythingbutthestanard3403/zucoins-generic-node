/**
 * SOURCE: the canonical vault-storage decision over the drafted
 * data-model and signing-custody forms. The precursor decisions supply the frozen table
 * version names.
 *
 * the vault model freeze is the vault ARCHITECTURE decision record. It freezes storage-grain, naming
 * envelope structure, and the no-hybrid boundary at the architecture level only. The concrete
 * column schema, types, and sealing APIs are the vault schema freeze; byte serializations are the vault schema freeze/.3.
 * This file invents no cryptographic byte layout.
 */

/** v2 resolution: per-wallet envelope rows supersede the single-blob precursor. */
export const VAULT_STORAGE_GRAIN = "PER_WALLET_ENVELOPE_ROW" as const;

/** Frozen column names kept by the vault-storage decision (only the grain changed). */
export const VAULT_TABLE_NAME = "vault" as const;
export const VAULT_PRIMARY_KEY = "wallet_id" as const;
export const VAULT_VERSION_COLUMN = "key_version" as const;

/** The resolved single-vault vs per-wallet decision, with no hybrid ambiguity. */
export const STORAGE_RESOLUTION = {
  v2_grain: "PER_WALLET_ENVELOPE_ROW",
  v1_grain: "SINGLE_VAULT_ROW",
  hybrid_permitted: false,
  migration_shim: false,
  v1_v2_disjoint: true,
} as const;

/**
 * The v2 per-wallet envelope logical structure. Concrete column names/types are the vault schema freeze; here
 * only the sealed material, cipher, sizes, structural uniqueness, and the no-stored-AAD
 * decision are frozen.
 */
export const ENVELOPE_STRUCTURE = {
  sealed_material: "ED25519_SECRET_64_BYTES",
  cipher: "AES-256-GCM",
  nonce_bits: 96,
  tag_bits: 128,
  version_field: "key_version",
  carries: ["key_version", "nonce", "ciphertext", "tag"],
  structural_unique: ["key_version", "nonce"],
  stored_aad_column: false,
} as const;

/**
 * The frozen-correct vault model a proposed descriptor must match (the hardened shape).
 * vault-verifier.ts checks descriptors against exactly these values.
 */
export const REQUIRED_VAULT_MODEL = {
  grain: "PER_WALLET_ENVELOPE_ROW",
  hybridPermitted: false,
  keyDerivation: "PER_WALLET_HKDF",
  nonceSource: "CSPRNG_FRESH_PER_SEAL",
  aadSource: "RECONSTRUCTED_AT_OPEN",
  rotation: "CRASH_SAFE_RESUMABLE_KEY_RING",
} as const;

/**
 * The per-wallet envelope as literally drafted (naked master key, random shared nonce, stored
 * `aad_text` column, undefined rotation key-ring, table `wallet_secrets` / `vault_key_version`)
 * is rejected by the vault-storage decision as a net regression. Frozen here as the negative fixture vault-verifier
 * checks against, so the rejected shape can never be silently reintroduced.
 */
export const REJECTED_DRAFT_DESCRIPTOR = {
  grain: "PER_WALLET_ENVELOPE_ROW",
  table: "wallet_secrets",
  version_column: "vault_key_version",
  hybridPermitted: false,
  keyDerivation: "NAKED_MASTER_KEY",
  nonceSource: "RANDOM_SHARED",
  aadSource: "STORED_COLUMN",
  rotation: "UNDEFINED_KEY_RING",
} as const;
