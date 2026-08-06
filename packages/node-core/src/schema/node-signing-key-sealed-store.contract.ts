// The sealed store behind node_signing_keys.vault_secret_ref, bound by the wallet-vault
// AAD and HKDF-info construction.
//
// Frozen inventory of the structural invariants carried by
// node-signing-key-sealed-store.sql — the AES-256-GCM envelope store for NODE_IDENTITY
// and EVENT_SIGNING Ed25519 seeds. Public material stays in node_signing_keys.

export const NODE_SIGNING_KEY_SEALED_STORE_SCHEMA_FILE =
  "node-signing-key-sealed-store.sql" as const;

export interface NodeSigningKeySealedStoreInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const NODE_SIGNING_KEY_SEALED_STORE_INVARIANTS: readonly NodeSigningKeySealedStoreInvariant[] =
  [
    {
      id: "NSK_SEALED_REF_PK",
      sqlAnchor: "vault_secret_ref uuid PRIMARY KEY",
      rule:
        "one envelope row per vault_secret_ref, matching node_signing_keys.vault_secret_ref (opaque uuid, no FK).",
    },
    {
      id: "NSK_SEALED_KEY_VERSION_POSITIVE",
      sqlAnchor: "key_version integer NOT NULL DEFAULT 1 CHECK (key_version > 0)",
      rule:
        "key_version is a positive integer AAD/HKDF-info input; zero or negative cannot address a DEK.",
    },
    {
      id: "NSK_SEALED_NONCE_UNIQUE_PER_VERSION",
      sqlAnchor: "UNIQUE (key_version, nonce)",
      rule:
        "nonce reuse within a key version is structurally impossible (the same AES-GCM stream-reuse guard the wallet vault uses).",
    },
    {
      id: "NSK_SEALED_NO_STORED_AAD",
      sqlAnchor: "ciphertext_sha256 sha256_hex NOT NULL",
      rule:
        "no aad column — AAD is reconstructed at open from node_signing_keys authoritative columns (node_id, purpose, public_key) plus key_version.",
    },
    {
      id: "NSK_SEALED_CIPHERTEXT_BYTES",
      sqlAnchor: "ciphertext bytea NOT NULL",
      rule:
        "sealed seed material is raw bytes with a separate hex digest; the digest is an integrity index, never a signing substitute.",
    },
    {
      id: "NSK_ONE_ACTIVE_PER_NODE_PURPOSE",
      sqlAnchor:
        "CREATE UNIQUE INDEX node_signing_keys_one_active_per_node_purpose",
      rule:
        "at most one non-retired node_signing_keys row per (node_id, purpose) — dual-active mint lost at the database.",
    },
  ] as const;

export const NODE_SIGNING_KEY_SEALED_STORE_EXECUTION_OBLIGATIONS: readonly string[] = [
  "node-signing-key-sealed-store.sql applies after sha256_hex is present and materializes vault_secret_ref + key_version + ciphertext + nonce + auth_tag + ciphertext_sha256 + created_at.",
  "A duplicate (key_version, nonce) INSERT is rejected with unique_violation 23505.",
  "key_version <= 0 is rejected by the inline CHECK with check_violation 23514.",
  "A second non-retired node_signing_keys row for the same (node_id, purpose) is rejected by node_signing_keys_one_active_per_node_purpose (unique_violation 23505).",
] as const;

export const NODE_SIGNING_KEY_SEALED_STORE_SOURCE =
  "signing-custody: node signing key sealed store" as const;
