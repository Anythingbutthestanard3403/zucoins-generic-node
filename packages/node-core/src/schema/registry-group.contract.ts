/**
 * The registry group: nodes, implementers, implementer_reporting_keys and
 * node_signing_keys, plus the key inventory they carry.
 * parent exit criterion.
 *
 * Parent-level freeze of the four-table registry GROUP that children and
 * deliver as independent slices. Isolation/rotation scenario suite is
 * and is NOT restated here.
 *
 * Parent exit criterion (verbatim): "Wrong-purpose or expired keys cannot authorize new
 * activity while frozen historical verification remains possible."
 */

/** Ordered apply sequence for the registry group (base; then keys). */
export const REGISTRY_GROUP_SCHEMA_FILES = [
  "node-implementer-registry.sql",
  "signing-key-registry.sql",
] as const;

export type RegistryGroupSchemaFile = (typeof REGISTRY_GROUP_SCHEMA_FILES)[number];

/** The four tables that form the group — no private-key columns among them. */
export const REGISTRY_GROUP_TABLES = [
  "nodes",
  "implementers",
  "implementer_reporting_keys",
  "node_signing_keys",
] as const;

export type RegistryGroupTable = (typeof REGISTRY_GROUP_TABLES)[number];

/** Parent exit criterion, frozen so the composition census cannot drift from the ticket. */
export const REGISTRY_GROUP_EXIT_CRITERION =
  "Wrong-purpose or expired keys cannot authorize new activity while frozen historical verification remains possible." as const;

/**
 * Structural properties the group must uphold as a unit. Child slices prove each table's
 * local constraints; the parent composition census binds these cross-slice claims.
 */
export const REGISTRY_GROUP_INVARIANTS = [
  {
    id: "APPLY_ORDER",
    rule: "signing-key-registry.sql layers on node-implementer-registry.sql; applied alone it fails on the missing nodes relation.",
  },
  {
    id: "FOUR_TABLES_ONLY",
    rule: "the group is exactly nodes, implementers, implementer_reporting_keys, node_signing_keys — there is no fifth registry table.",
  },
  {
    id: "PUBLIC_MATERIAL_ONLY",
    rule: "zero private-key/secret columns across the group; node_signing_keys.vault_secret_ref is an opaque uuid pointer only (the key-custody rule).",
  },
  {
    id: "PURPOSE_BEFORE_VERIFY",
    rule: "node_signing_keys purpose comparison is exact-literal and runs before any SQL or signature verification.",
  },
  {
    id: "ACTIVE_VS_HISTORICAL",
    rule: "active resolution excludes retired/not-yet-active keys; historical resolution by exact public key remains possible after retirement.",
  },
] as const;

export const REGISTRY_GROUP_SOURCE =
  "data-model: registries; signing-custody: key inventory" as const;
