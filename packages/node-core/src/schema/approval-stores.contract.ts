// Device keys and guarded approvals: the approval-challenge freshness timer and
// byte-exact signing (the byte-exact signing rule).
//
// Frozen inventory of the structural approval-store invariants carried by
// approval-stores.sql. The census test binds every entry here to the literal SQL text,
// so the inventory and the schema contract cannot drift apart. Execution against a live
// database belongs to the schema-apply phase, recorded below as obligations rather than
// silently omitted.

export const APPROVAL_STORES_SCHEMA_FILE = "approval-stores.sql" as const;

export interface ApprovalStoresInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const APPROVAL_STORES_INVARIANTS: readonly ApprovalStoresInvariant[] = [
  {
    id: "DEVICE_KEY_UNIQUE_PER_NODE",
    sqlAnchor: "UNIQUE (node_id, public_key)",
    rule: "one device key per (node, public_key) pair: a duplicate enrollment is a unique_violation.",
  },
  {
    id: "CHALLENGE_PURPOSE_FROZEN",
    sqlAnchor: "purpose text NOT NULL CHECK (purpose = 'zp-send-external-approval-v1'),",
    rule: "the only representable challenge purpose: any other literal is a constraint violation.",
  },
  {
    id: "CHALLENGE_CANONICAL_VERSION_ONE",
    sqlAnchor: "canonical_version integer NOT NULL CHECK (canonical_version = 1),",
    rule: "only canonical version 1 is representable.",
  },
  {
    id: "CHALLENGE_NONCE_UNIQUE",
    sqlAnchor: "nonce uuid NOT NULL UNIQUE,",
    rule: "each challenge nonce is globally unique: refresh supersedes the prior challenge and issues a fresh nonce.",
  },
  {
    id: "CHALLENGE_EXPIRY_AFTER_ISSUE",
    sqlAnchor: "CHECK (expires_at > issued_at),",
    rule: "the T1 approval-challenge freshness timer: expiry must be strictly after issue.",
  },
  {
    id: "CHALLENGE_SUPERSEDED_BICONDITIONAL",
    sqlAnchor: "CHECK ((status = 'SUPERSEDED') = (superseded_by IS NOT NULL)),",
    rule: "superseded_by is set exactly when status is SUPERSEDED: the two are biconditional.",
  },
  {
    id: "CHALLENGE_COMPOSITE_UNIQUE",
    sqlAnchor: "UNIQUE (id, node_id, operation_id, status)",
    rule: "composite uniqueness enables the FK from operation_approvals.",
  },
  {
    id: "CHALLENGE_ONE_ISSUED_PER_OPERATION",
    sqlAnchor:
      "CREATE UNIQUE INDEX approval_challenges_one_issued_per_operation\n  ON approval_challenges(operation_id)\n  WHERE status = 'ISSUED';",
    rule: "at most one ISSUED challenge per operation: a second ISSUED row for the same operation is a unique_violation; refresh supersedes first.",
  },
  {
    id: "APPROVAL_ONE_PER_OPERATION",
    sqlAnchor: "operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),",
    rule: "at most one approval per operation: a second approval for the same operation is a unique_violation.",
  },
  {
    id: "APPROVAL_CHALLENGE_UNIQUE",
    sqlAnchor: "challenge_id uuid UNIQUE,",
    rule: "at most one approval per challenge when present: UNIQUE allows multiple NULL challenge_id rows (AUTO_POLICY); a consumed challenge can never back two approvals.",
  },
  {
    id: "APPROVAL_CHALLENGE_STATUS_CONSUMED",
    sqlAnchor:
      "challenge_status approval_challenge_status NOT NULL DEFAULT 'CONSUMED'\n    CHECK (challenge_status = 'CONSUMED'),",
    rule: "the only representable challenge_status on an approval is CONSUMED: the approval exists only after consumption.",
  },
  {
    id: "APPROVAL_PURPOSE_FROZEN",
    sqlAnchor:
      "purpose text NOT NULL CHECK (purpose = 'zp-send-external-approval-v1'),\n  canonical_version integer NOT NULL CHECK (canonical_version = 1),",
    rule: "the approval purpose and version are frozen.",
  },
  {
    id: "APPROVAL_METHOD_THREE_ARMS",
    sqlAnchor:
      "CHECK (\n    (method = 'TOTP_AND_DEVICE'\n      AND challenge_id IS NOT NULL\n      AND totp_timestep IS NOT NULL\n      AND device_key_id IS NOT NULL\n      AND device_signature IS NOT NULL)\n    OR\n    (method = 'TOTP_ONLY'\n      AND challenge_id IS NOT NULL\n      AND totp_timestep IS NOT NULL\n      AND device_key_id IS NULL\n      AND device_signature IS NULL)\n    OR\n    (method = 'AUTO_POLICY'\n      AND challenge_id IS NULL\n      AND totp_timestep IS NULL\n      AND device_key_id IS NULL\n      AND device_signature IS NULL)\n  ),",
    rule: "three method arms: TOTP_AND_DEVICE requires challenge+timestep+device factors; TOTP_ONLY requires challenge+timestep and null device factors; AUTO_POLICY requires all four factor columns null (machine-committed, no fabricated TOTP/challenge evidence).",
  },
  {
    id: "APPROVAL_TOTP_SINGLE_USE",
    sqlAnchor:
      "CREATE UNIQUE INDEX operation_approvals_totp_single_use\n  ON operation_approvals (node_id, totp_timestep)\n  WHERE totp_timestep IS NOT NULL;",
    rule: "each non-null (node_id, totp_timestep) pair is globally unique: a TOTP timestep can never be consumed twice on the same node; AUTO_POLICY rows with null totp_timestep are excluded from the index.",
  },
  {
    id: "APPROVAL_FK_TO_CHALLENGE",
    sqlAnchor:
      "FOREIGN KEY (challenge_id, node_id, operation_id, challenge_status)\n    REFERENCES approval_challenges(id, node_id, operation_id, status)",
    rule: "composite FK MATCH SIMPLE: a non-null challenge_id binds the approval to exactly one consumed challenge with matching node and operation; a null challenge_id (AUTO_POLICY) makes the FK vacuously pass.",
  },
] as const;

export const APPROVAL_STORES_MUTABILITY_REGIMES = [
  {
    table: "operator_device_keys",
    regime: "insert_then_revoke",
    updatableColumns: ["revoked_at"] as readonly string[],
    rule: "insert, then revoke only: revoked_at may be set once; no other column is updatable.",
  },
  {
    table: "approval_challenges",
    regime: "insert_then_supersede",
    updatableColumns: ["status", "superseded_by"] as readonly string[],
    rule: "insert, then supersede only: refresh sets status to SUPERSEDED and fills superseded_by; nonce/preimage/expiry on the original row are never mutated.",
  },
  {
    table: "operation_approvals",
    regime: "insert_only",
    updatableColumns: [] as readonly string[],
    rule: "insert-only: the approval exists only after the guarded mutation consumes a mandatory fresh TOTP; no column is updatable or deletable.",
  },
] as const;

export const SCHEMA_APPROVAL_STORES_OBLIGATIONS = [
  "execution sequence: create the FK target relations (nodes, operations) and the sha256_hex / padded_base64url_pubkey / padded_base64url_signature domains and the approval_method / approval_challenge_status enums before this file's tables.",
  "guards: install BEFORE UPDATE/DELETE enforcement for the three mutability regimes (device keys insert-then-revoke; challenges insert-then-supersede; approvals insert-only) — the schema conventions sanction byte-immutability triggers; no trigger DDL is frozen in this file.",
  "negative: a second ISSUED approval_challenges row for the same operation_id violates the partial unique index — refresh must supersede first.",
  "negative: a second operation_approvals row for the same operation_id violates the UNIQUE constraint on operation_id.",
  "negative: a second operation_approvals row for the same challenge_id violates the UNIQUE constraint on challenge_id.",
  "negative: a second operation_approvals row for the same non-null (node_id, totp_timestep) violates the partial unique index — TOTP single-use is DB-enforced; two AUTO_POLICY rows with null totp_timestep do not collide.",
  "negative: an approval with method TOTP_ONLY but device_key_id set (or device_signature set) is rejected by the three-arm CHECK, and the converse for TOTP_AND_DEVICE with NULL device fields; AUTO_POLICY with any factor column non-NULL is rejected; TOTP arms with NULL challenge_id or totp_timestep are rejected.",
  "negative: a challenge with expires_at <= issued_at is rejected by the CHECK.",
  "negative: a challenge with status SUPERSEDED but superseded_by NULL (or the converse) is rejected by the biconditional CHECK.",
  "negative: an approval whose (challenge_id, node_id, operation_id, challenge_status) does not match an existing approval_challenges row is rejected by the composite FK.",
] as const;

export const APPROVAL_STORES_SOURCE =
  "data-model: device keys and guarded approvals; the byte-exact signing rule" as const;
