// Operational stores: the retention and mutability
// matrix's operational data, the operator halt, mutable cursor counters, and the
// signer-leadership and pool/queue settings.
//
// Frozen inventory of the structural operational-store invariants carried by
// operational-stores.sql: node_settings (versioned key-value node configuration),
// operator_halts (operator halt state with engage/disengage actors), and
// worker_cursors (worker progress positions). The census test binds every entry
// here to the literal SQL text, so the inventory and the schema contract cannot
// drift apart.

export const OPERATIONAL_STORES_SCHEMA_FILE = "operational-stores.sql" as const;

export interface OperationalStoresInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const OPERATIONAL_STORES_INVARIANTS: readonly OperationalStoresInvariant[] = [
  {
    id: "SETTINGS_KEY_PRIMARY_KEY",
    sqlAnchor: "setting_key text PRIMARY KEY,",
    rule: "each setting is uniquely identified by its key (operational state): at most one value per setting_key, upserted on change.",
  },
  {
    id: "SETTINGS_VALUE_NOT_NULL",
    sqlAnchor: "setting_value text NOT NULL,",
    rule: "a setting always carries a value: NULL is not a representable setting state - deletion removes the row.",
  },
  {
    id: "SETTINGS_ROW_VERSION",
    sqlAnchor: "row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),",
    rule: "node_settings is versioned: row_version is the house compare-and-swap counter so an operator change is auditable and a stale/rolled-back read cannot silently reactivate an old cap.",
  },
  {
    id: "SETTINGS_UPDATED_AT_TRACKED",
    sqlAnchor: "updated_at timestamptz NOT NULL DEFAULT now()",
    rule: "every setting mutation records when it occurred (operational state): the timestamp is set on insert and refreshed on update.",
  },
  {
    id: "HALT_SCOPE_CLOSED_SET",
    sqlAnchor: "scope text NOT NULL CHECK (scope IN ('NODE','WALLET','OPERATION')),",
    rule: "operator halts apply to one of three frozen scopes: NODE halts all new signing, WALLET halts a specific wallet, OPERATION halts a specific operation.",
  },
  {
    id: "HALT_REASON_REQUIRED",
    sqlAnchor: "reason text NOT NULL CHECK (octet_length(reason) > 0),",
    rule: "every halt records a non-empty why it was engaged: an unaudited or empty-reason halt is not representable.",
  },
  {
    id: "HALT_ENGAGED_BY_REQUIRED",
    sqlAnchor: "engaged_by text NOT NULL CHECK (octet_length(engaged_by) > 0),",
    rule: "every halt records who engaged it: engage is audited; an anonymous or empty-string engage is not representable.",
  },
  {
    id: "HALT_LIFTED_AT_NULLABLE",
    sqlAnchor: "lifted_at timestamptz,",
    rule: "a halt is active until explicitly lifted: lifted_at is NULL while the halt is engaged; restart remains halted until disengaged.",
  },
  {
    id: "HALT_LIFTED_BY_NULLABLE",
    sqlAnchor: "lifted_by text CHECK (lifted_by IS NULL OR octet_length(lifted_by) > 0),",
    rule: "disengage records who lifted the halt: lifted_by is NULL while engaged and a non-empty actor when set together with lifted_at; empty-string lift actor is not representable.",
  },
  {
    id: "HALT_LIFTED_AFTER_HALTED",
    sqlAnchor: "CHECK ((lifted_at IS NULL) OR (lifted_at >= halted_at))",
    rule: "a halt cannot be lifted before it was engaged: temporal consistency is structurally enforced.",
  },
  {
    id: "HALT_LIFT_ACTOR_PAIRED",
    sqlAnchor: "CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))",
    rule: "lifted_at and lifted_by are paired: a lift without an actor, or an actor without a lift timestamp, is not representable. Non-empty lift actor is enforced separately by HALT_LIFTED_BY_NULLABLE.",
  },
  {
    id: "CURSOR_COMPOSITE_PRIMARY_KEY",
    sqlAnchor: "PRIMARY KEY (worker_id, cursor_key)",
    rule: "each worker tracks at most one position per cursor key (operational state): the composite key prevents duplicate cursor state.",
  },
  {
    id: "CURSOR_POSITION_NON_NEGATIVE",
    sqlAnchor: "position bigint NOT NULL CHECK (position >= 0),",
    rule: "cursor positions are non-negative: a negative position is not representable operational state.",
  },
] as const;

export const OPERATIONAL_STORES_MUTABILITY_REGIMES = [
  {
    table: "node_settings",
    regime: "upsert",
    updatableColumns: ["setting_value", "row_version", "updated_at"] as readonly string[],
    rule: "versioned key-value store (operational state): setting_value, row_version, and updated_at are updatable; setting_key is immutable identity. Callers bump row_version on every write so stale CAS reads cannot silently restore an old cap.",
  },
  {
    table: "operator_halts",
    regime: "guarded_projection",
    updatableColumns: ["lifted_at", "lifted_by"] as readonly string[],
    rule: "halt engagement is insert-only (engaged_by frozen at insert); only lifted_at and lifted_by advance: engage and disengage are equally gated and audited.",
  },
  {
    table: "worker_cursors",
    regime: "upsert",
    updatableColumns: ["position", "updated_at"] as readonly string[],
    rule: "cursor position advances monotonically (operational state): position and updated_at are updatable; worker_id and cursor_key are immutable identity.",
  },
] as const;

export const SCHEMA_OPERATIONAL_STORES_OBLIGATIONS = [
  "execution sequence: no FK targets are required; these tables are self-contained operational infrastructure.",
  "guards: install BEFORE UPDATE enforcement on operator_halts restricting updates to lifted_at and lifted_by only (engage and disengage are equally gated); install row_version compare-and-swap on node_settings writes so a stale read cannot overwrite a newer cap; no trigger DDL is frozen in this file.",
  "negative: a second node_settings row with the same setting_key is rejected with unique_violation (23505).",
  "negative: row_version = 0 (or negative) on node_settings is rejected by the column CHECK.",
  "negative: scope outside ('NODE','WALLET','OPERATION') is rejected by the column CHECK.",
  "negative: engaged_by NULL is rejected by the column NOT NULL; engaged_by '' (empty string) is rejected by the octet_length CHECK.",
  "negative: reason NULL is rejected by the column NOT NULL; reason '' is rejected by the octet_length CHECK.",
  "negative: lifted_at < halted_at is rejected by the temporal CHECK.",
  "negative: lifted_at set with lifted_by NULL (or the reverse) is rejected by the paired-null CHECK.",
  "negative: lifted_at set with lifted_by '' (empty string) is rejected by the lifted_by octet_length CHECK.",
  "negative: a second worker_cursors row with the same (worker_id, cursor_key) is rejected with unique_violation.",
  "negative: position < 0 is rejected by the column CHECK.",
] as const;

export const OPERATIONAL_STORES_SOURCE =
  "data-model: operational settings, operator halt, and worker cursors" as const;
