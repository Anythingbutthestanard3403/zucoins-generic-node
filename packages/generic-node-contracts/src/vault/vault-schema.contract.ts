/**
 * SOURCE: the canonical vault-storage decision applied to the drafted data-model form
 * (table `wallet_secrets`). the vault schema freeze freezes the concrete per-wallet `vault` row schema on the
 * the vault model freeze architecture: table `vault`, PK `wallet_id`, `key_version` (the vault related rule names), NO stored
 * `aad_text` column, and the structural `UNIQUE(key_version, nonce)` guard. Bytea sizes match
 * the frozen AES-256-GCM 96-bit nonce / 128-bit tag from the vault model freeze's ENVELOPE_STRUCTURE.
 */

export interface VaultColumnSpec {
  readonly name: string;
  readonly type: string;
  readonly nullable: boolean;
  readonly note: string;
}

/** `vault` columns, listed in the frozen DDL column sequence. */
export const VAULT_COLUMNS = [
  { name: "wallet_id", type: "uuid", nullable: false, note: "primary key; references wallets(id)" },
  { name: "key_version", type: "integer", nullable: false, note: "per-row epoch (frozen precursor name); CHECK > 0" },
  { name: "ciphertext", type: "bytea", nullable: false, note: "AES-256-GCM sealed 64-byte Ed25519 secret" },
  { name: "nonce", type: "bytea", nullable: false, note: "96-bit CSPRNG nonce; octet_length = 12" },
  { name: "auth_tag", type: "bytea", nullable: false, note: "128-bit GCM tag; octet_length = 16" },
  { name: "ciphertext_sha256", type: "sha256_hex", nullable: false, note: "digest of ciphertext for integrity indexing" },
  { name: "created_at", type: "timestamptz", nullable: false, note: "row creation; defaults to now()" },
  { name: "rotated_at", type: "timestamptz", nullable: true, note: "last rewrap time; null until first rotation" },
] as const satisfies readonly VaultColumnSpec[];

/**
 * The frozen table constraints. `no_aad_text_column` records the vault-storage rule rejection of the drafted
 * stored-AAD column explicitly, so a reader cannot reintroduce it and call it schema-complete.
 */
export const VAULT_CONSTRAINTS = {
  table: "vault",
  primary_key: ["wallet_id"],
  unique: [["key_version", "nonce"]],
  checks: ["key_version > 0", "octet_length(nonce) = 12", "octet_length(auth_tag) = 16"],
  foreign_keys: [{ column: "wallet_id", references: "wallets(id)" }],
  no_aad_text_column: true,
} as const;

/** A vault row's key identity is (wallet_id, key_version); the DEK is derived from these plus node_id. */
export const VAULT_KEY_IDENTITY = ["wallet_id", "key_version"] as const;
