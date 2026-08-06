/**
 * The nodes and implementers root registries, plus the padded_base64url_pubkey reference
 * domain they use.
 * (gate-default anti-pattern, applied by exclusion here -- created_at is not a gate).
 *
 * Frozen inventory of the structural invariants carried by node-implementer-registry.sql
 * . The census test binds every entry here to the literal SQL text, so the
 * inventory and the schema contract cannot drift apart. No pre-existing frozen record
 * contract exists in generic-node-contracts; this inventory is the authority, bound directly to
 * This slice ships the two root registries; the parent binds the group surface. Live
 * database execution obligations are recorded below rather than silently omitted.
 */

export const NODE_IMPLEMENTER_SCHEMA_FILE = "node-implementer-registry.sql" as const;

export interface RegistrySchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const NODE_IMPLEMENTER_SCHEMA_INVARIANTS: readonly RegistrySchemaInvariant[] = [
  {
    id: "PUBKEY_DOMAIN_SELF_CONTAINED",
    sqlAnchor: "CREATE DOMAIN padded_base64url_pubkey AS text",
    rule: "the one reference domain nodes uses is re-declared in-slice so the contract applies greenfield standalone (proof-body-store / custody-eligibility self-containment pattern).",
  },
  {
    id: "BARE_ID_PRIMARY_KEY",
    sqlAnchor: "id uuid PRIMARY KEY",
    rule: "both registries key on bare `id uuid PRIMARY KEY` -- the uniform id convention every sibling relation foreign-keys against (operations REFERENCES nodes(id), implementers(id)); no surrogate node_id/implementer_id PK.",
  },
  {
    id: "NODE_DISPLAY_NAME_NOT_NULL",
    sqlAnchor: "display_name text NOT NULL",
    rule: "every node row carries a non-null display_name.",
  },
  {
    id: "NODE_IDENTITY_KEY_DOMAIN",
    sqlAnchor: "identity_public_key padded_base64url_pubkey NOT NULL",
    rule: "nodes.identity_public_key is typed by the padded_base64url_pubkey domain (44-char padded base64url), not bare text; the domain CHECK is the first boundary; the runtime re-decodes.",
  },
  {
    id: "NODE_IDENTITY_KEY_UNIQUE",
    sqlAnchor: "UNIQUE (identity_public_key)",
    rule: "at most one node per identity public key.",
  },
  {
    id: "NODE_RETIRED_AFTER_CREATED",
    sqlAnchor: "CHECK (retired_at IS NULL OR retired_at >= created_at)",
    rule: "a node is never retired before it is created.",
  },
  {
    id: "CREATED_AT_DEFAULT_NOW",
    sqlAnchor: "created_at timestamptz NOT NULL DEFAULT now()",
    rule: "created_at carries DEFAULT now(); a default is barred only on a GATE timestamp, which created_at is not.",
  },
  {
    id: "IMPLEMENTER_NAME_NOT_NULL",
    sqlAnchor: "name text NOT NULL",
    rule: "every implementer row carries a non-null name.",
  },
] as const;

/**
 * Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a real
 * Postgres before the schema contract is considered enforced. node-implementer-registry.pg.test.ts
 * discharges them when TEST_DATABASE_URL is set; migration-integrity.test.ts covers greenfield
 * apply and exact-column materialization.
 */
export const SCHEMA_EXECUTION_OBLIGATIONS = [
  "greenfield apply: node-implementer-registry.sql applies clean into an empty schema and materializes exactly nodes(id, display_name, identity_public_key, created_at, retired_at) and implementers(id, name, created_at, retired_at).",
  "domain accept: a valid 44-char padded base64url key inserts into nodes.identity_public_key.",
  "domain reject: a malformed identity_public_key (wrong length, illegal char, or missing '=' pad) is rejected by the padded_base64url_pubkey domain CHECK.",
  "unique: a second nodes row with a duplicate identity_public_key is rejected (unique_violation 23505).",
  "not null: a nodes insert with NULL display_name and an implementers insert with NULL name are rejected (not_null_violation 23502).",
  "primary key: a duplicate nodes.id (and implementers.id) insert is rejected (unique_violation 23505).",
  "check: a nodes row with retired_at earlier than created_at is rejected (check_violation 23514).",
] as const;

export const NODE_IMPLEMENTER_SCHEMA_SOURCE = "data-model: nodes and implementers root registries" as const;
