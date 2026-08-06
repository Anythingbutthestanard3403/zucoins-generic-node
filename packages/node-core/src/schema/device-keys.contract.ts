// Device keys and guarded approvals: the reference scalar check and the enrolled-device
// registry the zp-device-enrol-v1 ceremony appends to.
//
// Frozen inventory of the structural enrolled-device invariants carried by
// device-keys.sql: the operator_device_keys registry the device enrolment ceremony
// appends to and device-signature verification reads at request receipt. The
// census test binds every entry here to the literal SQL text, so the inventory and the
// schema contract cannot drift apart. Execution against a live database belongs to the
// schema-apply phase, recorded below as obligations rather than silently omitted.

export const DEVICE_KEYS_SCHEMA_FILE = "device-keys.sql" as const;

export interface DeviceKeyInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const DEVICE_KEYS_INVARIANTS: readonly DeviceKeyInvariant[] = [
  {
    id: "DEVICE_KEY_DOMAIN",
    sqlAnchor: "public_key padded_base64url_pubkey NOT NULL,",
    rule: "the enrolled public key uses the padded_base64url_pubkey domain: a 44-char canonically padded base64url Ed25519 public key, the only key material the node stores (the key-custody rule).",
  },
  {
    id: "DEVICE_KEY_NODE_BINDING",
    sqlAnchor: "node_id uuid NOT NULL REFERENCES nodes(id),",
    rule: "every enrolled device key is bound to exactly one node: enrollment is per-node, so a key enrolled on one node confers no authority on another.",
  },
  {
    id: "DEVICE_KEY_UNIQUE_PER_NODE",
    sqlAnchor: "UNIQUE (node_id, public_key)",
    rule: "at most one enrollment per (node, public key): re-enrolling an already-enrolled key is a structural duplicate, rejected before any ceremony consideration.",
  },
  {
    id: "DEVICE_KEY_LABEL",
    sqlAnchor: "label text NOT NULL,",
    rule: "the human-readable device label (A.4.3 field 6) is mandatory; the A.4.3 denylist (scalar count, UTF-8 byte cap, controls/surrogates/noncharacters/BOM/BiDi) is enforced at the runtime contract layer against exact received bytes, never by this plain text column.",
  },
  {
    id: "DEVICE_KEY_ENROLLED_AT",
    sqlAnchor: "enrolled_at timestamptz NOT NULL,",
    rule: "the enrollment instant is mandatory: it anchors the permanent-authority start of the device key and is recorded once at insertion.",
  },
  {
    id: "DEVICE_KEY_REVOCATION_NULLABLE",
    sqlAnchor: "revoked_at timestamptz,",
    rule: "revocation is a nullable timestamp: NULL means the key is active; a non-NULL revoked_at means the key is revoked and is rejected even inside its own signed window.",
  },
  {
    id: "DEVICE_KEY_SURROGATE_ID",
    sqlAnchor: "id uuid PRIMARY KEY,",
    rule: "the surrogate key id is the stable reference operation_approvals.device_key_id points at; it is never the public key itself.",
  },
] as const;

// Live-database proofs this package cannot run (no database harness lands in this package). The schema-apply phase MUST discharge each of these against a
// real Postgres before the schema contract is considered enforced.
export const SCHEMA_DEVICE_KEYS_OBLIGATIONS = [
  "execution sequence: create the nodes table (this table references nodes(id)) before this file's table; the padded_base64url_pubkey domain is redeclared verbatim here, so the schema-apply phase must create it (or reuse the identical reference domain) before operator_device_keys.",
  "revocation semantics: revocation is immediate, durable, and append-only — the schema-apply phase must install BEFORE UPDATE/DELETE enforcement making operator_device_keys append-only except for a single idempotent set of revoked_at on an active row; no trigger DDL is frozen in this file.",
  "label validation: the A.4.3 label denylist is a runtime/contract-layer check over the exact received bytes (1-80 Unicode scalars, <=320 UTF-8 bytes, no C0/C1 controls, surrogates, noncharacters, line/paragraph separators, BOM/ZWNBSP, BiDi/zero-width format controls, no leading/trailing space); the plain text column does not enforce it, so the schema-apply phase must not treat column insertion as label validation.",
  "negative: a duplicate (node_id, public_key) insert is rejected with unique_violation (23505).",
  "negative: a malformed padded_base64url_pubkey value (wrong length or non-canonical encoding) is rejected by the domain.",
] as const;

export const DEVICE_KEYS_SOURCE =
  "data-model: device keys and guarded approvals" as const;
