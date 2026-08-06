/**
 * The implementer_reporting_keys and node_signing_keys signing-key registries, plus the
 * padded_base64url_pubkey reference domain. The gate-default anti-pattern applies here by
 * exclusion: registered_at / activated_at are event timestamps, not recovery gates, and get
 * them no default).
 *
 * Frozen inventory of the structural invariants carried by signing-key-registry.sql (,
 * ), stacked on. The census test binds every entry here to the literal
 * SQL text, so the inventory and the schema contract cannot drift apart. No pre-existing frozen
 * record contract exists in generic-node-contracts; this inventory is the authority, bound
 * no default. This slice ships on the registry base; the parent
 * binds the group surface. Live database execution obligations are recorded below rather than
 * silently omitted.
 */

export const SIGNING_KEY_SCHEMA_FILE = "signing-key-registry.sql" as const;

export interface SigningKeySchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SIGNING_KEY_SCHEMA_INVARIANTS: readonly SigningKeySchemaInvariant[] = [
  {
    id: "PUBKEY_DOMAIN_SELF_CONTAINED",
    sqlAnchor: "CREATE DOMAIN padded_base64url_pubkey AS text",
    rule: "the one reference domain both tables use is re-declared in-slice so the contract materialises its own type when applied standalone (node-implementer-registry / proof-body-store self-containment pattern).",
  },
  {
    id: "BARE_ID_PRIMARY_KEY",
    sqlAnchor: "id uuid PRIMARY KEY",
    rule: "both tables key on bare `id uuid PRIMARY KEY` -- the uniform id convention; downstream receive_arms / lifecycle / nonce tables reference this id, never a surrogate.",
  },
  {
    id: "NODE_REFERENCE",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id)",
    rule: "implementer_reporting_keys.node_id and node_signing_keys.node_id reference the nodes(id) root registry; a key cannot cite a non-existent node.",
  },
  {
    id: "IMPLEMENTER_REFERENCE",
    sqlAnchor: "implementer_id uuid NOT NULL REFERENCES implementers(id)",
    rule: "implementer_reporting_keys.implementer_id references the implementers(id) root registry.",
  },
  {
    id: "PUBLIC_KEY_DOMAIN",
    sqlAnchor: "public_key padded_base64url_pubkey NOT NULL",
    rule: "both tables type public_key by the padded_base64url_pubkey domain (44-char padded base64url), not bare text; the domain CHECK is the first boundary; the runtime re-decodes.",
  },
  {
    id: "REGISTERED_AT_NO_DEFAULT",
    sqlAnchor: "registered_at timestamptz NOT NULL",
    rule: "reporting-key registration time is a plain NOT NULL event timestamp with no DEFAULT (verbatim; a default is barred on a gate timestamp, and this is not one).",
  },
  {
    id: "REPORTING_KEY_TENANT_PUBKEY_UNIQUE",
    sqlAnchor: "UNIQUE (node_id, implementer_id, public_key)",
    rule: "at most one reporting-key row per (node, implementer, public key).",
  },
  {
    id: "REPORTING_KEY_TENANT_COMPOSITE_UNIQUE",
    sqlAnchor: "UNIQUE (id, node_id, implementer_id)",
    rule: "the composite unique receive_arms and the lifecycle / nonce tables consume as a reference target -- pins a reporting-key id to its exact (node, implementer) tenant so a child row cannot re-tenant it.",
  },
  {
    id: "REPORTING_KEY_TENANT_REGISTERED_COMPOSITE_UNIQUE",
    sqlAnchor: "UNIQUE (id, node_id, implementer_id, registered_at)",
    rule: "the wider composite unique that rotation evidence binds so a successor identity's registered_at is pinned to its enrolment.",
  },
  {
    id: "SIGNING_KEY_PURPOSE_CHECK",
    sqlAnchor: "purpose text NOT NULL CHECK (purpose IN ('NODE_IDENTITY', 'EVENT_SIGNING'))",
    rule: "node_signing_keys.purpose is a closed inline CHECK over exactly NODE_IDENTITY and EVENT_SIGNING; no other purpose is admissible.",
  },
  {
    id: "SIGNING_KEY_VAULT_SECRET_REF",
    sqlAnchor: "vault_secret_ref uuid NOT NULL UNIQUE",
    rule: "vault_secret_ref is a bare NOT NULL UNIQUE uuid reference resolved only inside the node vault, carrying no foreign key and no key material -- only public material lives in these relational tables (the key-custody rule: the platform never touches private keys).",
  },
  {
    id: "SIGNING_KEY_ACTIVATED_AT_NO_DEFAULT",
    sqlAnchor: "activated_at timestamptz NOT NULL",
    rule: "node signing-key activation time is a plain NOT NULL event timestamp with no DEFAULT.",
  },
  {
    id: "SIGNING_KEY_TENANT_PURPOSE_PUBKEY_UNIQUE",
    sqlAnchor: "UNIQUE (node_id, purpose, public_key)",
    rule: "at most one node signing-key row per (node, purpose, public key).",
  },
  {
    id: "SIGNING_KEY_RETIRED_AFTER_ACTIVATED",
    sqlAnchor: "CHECK (retired_at IS NULL OR retired_at >= activated_at)",
    rule: "a node signing key is never retired before it is activated.",
  },
] as const;

/**
 * Live-database proofs this package cannot run in this package. The schema-apply phase
 * MUST discharge each of these against a real Postgres before the schema contract is considered
 * enforced. signing-key-registry.pg.test.ts discharges them when TEST_DATABASE_URL is set, layering
 * the two tables on the node-implementer-registry base; migration-integrity.test.ts covers
 * the prerequisite-bound greenfield-alone outcome.
 */
export const SCHEMA_EXECUTION_OBLIGATIONS = [
  "greenfield (prerequisite-bound): applied alone into an empty schema this slice fails on the missing nodes relation; layered on node-implementer-registry.sql it applies clean and materialises implementer_reporting_keys(id, node_id, implementer_id, public_key, registered_at) and node_signing_keys(id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at).",
  "reference enforce: an implementer_reporting_keys row whose node_id or implementer_id is absent from nodes / implementers is rejected (foreign_key_violation 23503); a row citing real node + implementer rows inserts.",
  "reference enforce (signing): a node_signing_keys row whose node_id is absent from nodes is rejected; a row citing a real node inserts.",
  "domain reject: a malformed public_key (wrong length, illegal char, or missing '=' pad) is rejected by the padded_base64url_pubkey domain CHECK on both tables.",
  "check reject: a node_signing_keys row with a purpose outside {NODE_IDENTITY, EVENT_SIGNING} is rejected (check_violation 23514); a retired_at earlier than activated_at is rejected.",
  "unique: a duplicate node_signing_keys.vault_secret_ref is rejected (unique_violation 23505); a duplicate (node_id, implementer_id, public_key) reporting key is rejected; the composite UNIQUE (id, node_id, implementer_id) is present so a downstream receive_arms table can reference it.",
] as const;

export const SIGNING_KEY_SCHEMA_SOURCE =
  "data-model: signing-key registries" as const;
