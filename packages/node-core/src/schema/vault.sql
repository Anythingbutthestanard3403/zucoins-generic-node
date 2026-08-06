-- The `vault` table: one sealed envelope row per wallet, with the structural nonce-reuse
-- guard, no stored AAD, and no row lock on the read path.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it in production.
-- Every invariant below is inventoried in vault.contract.ts and executed against a real
-- PostgreSQL by test/vault-store.pg.test.ts.
--
-- No AAD column, deliberately (guard 2): the six-field AAD is reconstructed at open
-- from the wallet's authoritative columns, so a DB-write flip of key_origin or key_version
-- breaks GCM authentication instead of being replayed from a stored copy.
--
-- The foreign key targets wallets (id). Custody PK is `id`; vault's
-- own row PK column remains `wallet_id` (envelope keyed by the wallet it seals) -- that is
-- the vault column name, not the wallets primary-key name.
--
-- Nothing here takes or implies a row lock: signing reads this table by primary key only
-- (guard 4). wallet_active_leases is the sole serialization point for
-- one-in-flight-per-wallet; a second lock here would only add a deadlock edge.

CREATE TABLE vault (
  wallet_id uuid PRIMARY KEY REFERENCES wallets (id),
  key_version integer NOT NULL CHECK (key_version > 0),
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  auth_tag bytea NOT NULL,
  ciphertext_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  -- Guard 1: the structural nonce-reuse guard. Two envelopes sealed under the same
  -- key version can never share a nonce, whatever the CSPRNG does. Left unnamed exactly as
  -- Declared here; PostgreSQL derives vault_key_version_nonce_key.
  UNIQUE (key_version, nonce)
);
