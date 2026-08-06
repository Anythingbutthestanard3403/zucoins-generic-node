// The `vault` table: one sealed envelope row per wallet, under the wallet-vault model.
//
// Frozen inventory of the structural invariants carried by vault.sql: the
// per-wallet AES-256-GCM envelope row that backs the VaultStore port. The census block in
// test/vault-store.pg.test.ts binds every entry here to the literal SQL text, and the
// live-PostgreSQL block in the same file executes the obligations below against a real
// database rather than recording them as deferred.

export const VAULT_SCHEMA_FILE = "vault.sql" as const;

export interface VaultSchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const VAULT_SCHEMA_INVARIANTS: readonly VaultSchemaInvariant[] = [
  {
    id: "VAULT_PER_WALLET_GRAIN",
    sqlAnchor: "wallet_id uuid PRIMARY KEY REFERENCES wallets (id),",
    rule: "one envelope row per wallet, keyed by the wallet it seals (PER_WALLET_ENVELOPE_ROW): the single-blob grain is superseded and no hybrid is representable.",
  },
  {
    id: "VAULT_KEY_VERSION_POSITIVE",
    sqlAnchor: "key_version integer NOT NULL CHECK (key_version > 0),",
    rule: "key_version is a positive integer: it is an AAD and HKDF-info input, so a zero or negative version could never address a derivable DEK.",
  },
  {
    id: "VAULT_NONCE_UNIQUE_PER_VERSION",
    sqlAnchor: "UNIQUE (key_version, nonce)",
    rule: "Guard 1: nonce reuse within a key version is structurally impossible, so a duplicate (key_version, nonce) INSERT is a unique_violation (SQLSTATE 23505) rather than a silently catastrophic AES-GCM keystream reuse.",
  },
  {
    id: "VAULT_NO_STORED_AAD",
    sqlAnchor: "ciphertext_sha256 sha256_hex NOT NULL,",
    rule: "Guard 2: the column set ends at the integrity digest -- there is no aad/aad_text column, because the six-field AAD is reconstructed at open from the wallet's authoritative columns and a stored copy would let a row carry an AAD that disagrees with them.",
  },
  {
    id: "VAULT_CIPHERTEXT_DIGEST_IS_INDEX_ONLY",
    sqlAnchor: "ciphertext bytea NOT NULL,",
    rule: "the sealed material is stored as raw bytes with a separate hex digest column: ciphertext_sha256 is an integrity index, never a signing or authentication substitute.",
  },
] as const;

// Executed against a real PostgreSQL by test/vault-store.pg.test.ts, not deferred.
export const VAULT_EXECUTION_OBLIGATIONS: readonly string[] = [
  "vault.sql applies onto the frozen custody-eligibility wallets base and materializes exactly the eight vault columns.",
  "A duplicate (key_version, nonce) INSERT for two distinct wallets is rejected with unique_violation 23505 on constraint vault_key_version_nonce_key.",
  "key_version <= 0 is rejected by the inline CHECK with check_violation 23514.",
  "A wallet_id with no wallets row is rejected by the foreign key with foreign_key_violation 23503.",
  "A sealed envelope survives a real INSERT/SELECT round trip byte-identically and still opens to the wallet's authoritative public key.",
  "The read path issues no FOR UPDATE / FOR SHARE clause -- signing takes no row lock on vault (guard 4).",
] as const;
