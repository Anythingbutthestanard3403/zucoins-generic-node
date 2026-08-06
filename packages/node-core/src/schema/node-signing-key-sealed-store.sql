-- node_signing_key_sealed_store: the sealed envelope behind
-- node_signing_keys.vault_secret_ref, with cross-store HKDF domain separation.
--
-- Production seal-write runtime for NODE_SIGNING_KEYS. Public material stays in
-- node_signing_keys; private seed (32-byte Ed25519) lives only here as an AES-256-GCM
-- envelope under the process-lifetime vault root. No AAD column (reconstructed at open
-- from authoritative registry columns). No foreign key on vault_secret_ref — the registry
-- holds the opaque uuid pointer.
--
-- Pack position: appended after privileges so earlier money-pack version numbers (and
-- sql_sha256 journal entries) stay stable for already-applied greenfield DBs.

CREATE TABLE node_signing_key_sealed_store (
  vault_secret_ref uuid PRIMARY KEY,
  key_version integer NOT NULL DEFAULT 1 CHECK (key_version > 0),
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  auth_tag bytea NOT NULL,
  ciphertext_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- Structural nonce-reuse guard (mirrors the wallet vault's), scoped to this table.
  UNIQUE (key_version, nonce)
);

-- At most one non-retired node_signing_keys row per (node_id, purpose).
-- Double-mint race loses at the database instead of arming dual active identity keys.
-- Lives on this appended slice (version-stable) rather than married into the frozen
-- signing-key-registry.sql body so pre-923 pack SHA journals stay stable.
CREATE UNIQUE INDEX node_signing_keys_one_active_per_node_purpose
  ON node_signing_keys (node_id, purpose)
  WHERE retired_at IS NULL;
