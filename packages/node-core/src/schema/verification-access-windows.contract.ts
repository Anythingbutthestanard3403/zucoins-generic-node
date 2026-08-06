// Verification-material access windows: the endpoint's not-ready/expired behaviour, the
// terminal-plus-window access default, and the retention row that revokes access only.
// Structurally modelled on approval_challenges.
//
// Frozen inventory of the structural verification-access-window invariants carried by
// verification-access-windows.sql. The census test binds every entry here to the literal
// SQL text so the inventory and the schema contract cannot drift apart.

export const VERIFICATION_ACCESS_WINDOWS_SCHEMA_FILE =
  "verification-access-windows.sql" as const;

export interface VerificationAccessWindowsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const VERIFICATION_ACCESS_WINDOWS_INVARIANTS: readonly VerificationAccessWindowsInvariant[] =
  [
    {
      id: "ACCESS_WINDOW_PRIMARY_KEY",
      sqlAnchor: "CREATE TABLE verification_material_access_windows (\n  id uuid PRIMARY KEY,",
      rule: "each access-window row has a stable uuid identity.",
    },
    {
      id: "ACCESS_WINDOW_STATUS_CLOSED_SET",
      sqlAnchor: "CHECK (status IN ('OPEN', 'EXPIRED', 'REVOKED')),",
      rule: "status is a closed three-value set mirroring approval_challenges shape (OPEN/EXPIRED/REVOKED).",
    },
    {
      id: "ACCESS_WINDOW_NONCE_HASHED",
      sqlAnchor: "nonce_hash sha256_hex NOT NULL,",
      rule: "only the SHA-256 of the random nonce is durable — plaintext identifier is never stored (the redaction posture for secret identifiers).",
    },
    {
      id: "ACCESS_WINDOW_NONCE_HASH_UNIQUE",
      sqlAnchor: "UNIQUE (nonce_hash),",
      rule: "nonce hashes are globally unique so a window identifier resolves to at most one row.",
    },
    {
      id: "ACCESS_WINDOW_ONE_PER_OPERATION",
      sqlAnchor: "UNIQUE (operation_id),",
      rule: "one access-window record per operation — the window opens once at the landed terminal milestone.",
    },
    {
      id: "ACCESS_WINDOW_EXPIRY_AFTER_ISSUE",
      sqlAnchor: "CHECK (expires_at > issued_at),",
      rule: "mirrors approval_challenges: expiry must be strictly after issue (terminal plus the configured window).",
    },
    {
      id: "ACCESS_WINDOW_REVOKED_BICONDITIONAL",
      sqlAnchor: "CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),",
      rule: "revoked_at is set exactly when status is REVOKED (mirrors approval_challenges superseded_by biconditional).",
    },
    {
      id: "ACCESS_WINDOW_ONE_OPEN_PER_OPERATION",
      sqlAnchor:
        "CREATE UNIQUE INDEX verification_access_windows_one_open_per_operation\n  ON verification_material_access_windows(operation_id)\n  WHERE status = 'OPEN';",
      rule: "at most one OPEN window per operation (defence in depth alongside UNIQUE operation_id).",
    },
    {
      id: "ACCESS_WINDOW_EXPIRES_INDEX",
      sqlAnchor:
        "CREATE INDEX verification_access_windows_expires_at_idx\n  ON verification_material_access_windows (expires_at);",
      rule: "expiry scans by expires_at must not table-scan the access-window store.",
    },
    {
      id: "ACCESS_WINDOW_NO_PLAINTEXT_NONCE_COLUMN",
      sqlAnchor: "nonce_hash sha256_hex NOT NULL,",
      rule: "there is no nonce / token / secret plaintext column — only nonce_hash (ticket review indicator).",
    },
  ] as const;

export const VERIFICATION_ACCESS_WINDOWS_MUTABILITY_REGIMES = [
  {
    table: "verification_material_access_windows",
    regime: "guarded_projection",
    updatableColumns: ["status", "revoked_at"] as readonly string[],
    rule: "window issue is insert-only; only status/revoked_at advance on explicit revoke or expiry mark. Expiry never deletes the row or any underlying evidence.",
  },
] as const;

export const SCHEMA_VERIFICATION_ACCESS_WINDOWS_OBLIGATIONS = [
  "execution sequence: no FK targets are required; table is self-contained (re-declares sha256_hex). Later slices may ADD CONSTRAINT REFERENCES operations(id)/nodes(id)/implementers(id) without rewriting the PK shape.",
  "guards: install BEFORE UPDATE enforcement restricting updates to status and revoked_at only; install BEFORE DELETE / BEFORE TRUNCATE refuse — expiry revokes access, it never deletes the window row or underlying evidence.",
  "negative: a second row with the same nonce_hash is rejected with unique_violation (23505).",
  "negative: a second row with the same operation_id is rejected with unique_violation (23505).",
  "negative: nonce_hash outside sha256_hex domain is rejected by the domain CHECK.",
  "negative: expires_at <= issued_at is rejected by the temporal CHECK.",
  "negative: status='REVOKED' with revoked_at NULL (or the inverse) is rejected by the biconditional CHECK.",
  "retention: verification_material_access_windows rows are operational access-control state (retention: verification-material endpoint access is revoke-access-only). Underlying evidence tables remain permanent and are never pruned by this window's expiry.",
  "application boundary: the plaintext nonce is never logged, never returned on the verification-material response, and never written to audit_log details (the redaction posture; audit_log.contract records the scrubbing obligation).",
] as const;
