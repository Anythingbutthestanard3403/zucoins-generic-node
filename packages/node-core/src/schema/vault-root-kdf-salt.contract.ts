// The `vault_root_kdf_salt` table: the per-node vault root-KDF salt (ZTR-1159).
//
// Frozen inventory of the structural invariants carried by vault-root-kdf-salt.sql — the
// single durable answer to "what salt were this node's envelopes sealed under", persisted
// beside the `vault` rows it protects so the two can never travel separately.

export const VAULT_ROOT_KDF_SALT_SCHEMA_FILE = "vault-root-kdf-salt.sql" as const;

export interface VaultRootKdfSaltInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const VAULT_ROOT_KDF_SALT_INVARIANTS: readonly VaultRootKdfSaltInvariant[] = [
  {
    id: "ROOT_SALT_PER_NODE_GRAIN",
    sqlAnchor: "node_id uuid PRIMARY KEY,",
    rule: "one salt row per node: the root key is a node-wide derivation, so a second row for the same node could only mean two disagreeing answers to a question that has exactly one.",
  },
  {
    id: "ROOT_SALT_STORED_AS_RAW_BYTES",
    sqlAnchor: "salt bytea NOT NULL,",
    rule: "the salt is stored as the bytes the KDF consumes, not as base64 text: an encoding layer would be one more place the stored value could disagree with the derived one.",
  },
  {
    id: "ROOT_SALT_MIN_LENGTH",
    sqlAnchor: "CHECK (octet_length(salt) >= 8)",
    rule: "a persisted salt is at least 8 bytes -- the same floor the master-key rotation CLI has always enforced on operator-supplied salts, now applied to every provenance.",
  },
  {
    id: "ROOT_SALT_PROVENANCE_ENUMERATED",
    sqlAnchor: "CHECK (source IN ('environment', 'historical_default', 'genesis_random'))",
    rule: "provenance is one of exactly three values: an operator-supplied VAULT_ROOT_SALT_B64, the pre-ZTR-1159 literal a legacy node has always derived under, or a salt minted at genesis on a node that had sealed nothing.",
  },
  {
    id: "ROOT_SALT_INSERT_ONLY",
    sqlAnchor: "BEFORE UPDATE ON vault_root_kdf_salt",
    rule: "an in-place salt change is an engine-level refusal (SQLSTATE 55000): a row that could be edited would still say what boot derives under while the envelopes stayed sealed under the old value -- the key-loss trap this slice exists to close.",
  },
  {
    id: "ROOT_SALT_NOT_TRUNCATABLE",
    sqlAnchor: "BEFORE TRUNCATE ON vault_root_kdf_salt",
    rule: "TRUNCATE fires no row-level DELETE trigger, so without the statement-level guard the salt could be removed in one statement and the node would silently fall back to the historical literal at the next boot.",
  },
] as const;

export const VAULT_ROOT_KDF_SALT_EXECUTION_OBLIGATIONS: readonly string[] = [
  "vault-root-kdf-salt.sql applies into an empty schema alone: it declares no foreign key and re-declares the shared immutability trigger function, so it depends on no earlier slice.",
  "A second INSERT for the same node_id is rejected by the primary key with unique_violation 23505.",
  "A salt shorter than 8 bytes is rejected by the inline CHECK with check_violation 23514.",
  "A source outside the three enumerated provenances is rejected by the inline CHECK with check_violation 23514.",
  "UPDATE, DELETE and TRUNCATE against a persisted row all raise SQLSTATE 55000 -- the row is insert-only at the engine, not by convention.",
] as const;

export const VAULT_ROOT_KDF_SALT_SOURCE = "wallet-vault model: root key derivation" as const;
