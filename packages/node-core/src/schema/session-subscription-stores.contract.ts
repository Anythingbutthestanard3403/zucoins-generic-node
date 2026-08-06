// Subscription handles and node-origin admin sessions (with CSRF), created alongside the
// admission DB-TX.
//
// Frozen inventory of the structural session/subscription-store invariants carried by
// session-subscription-stores.sql. The census test binds every entry here to the literal
// SQL text so the inventory and the schema contract cannot drift apart.

export const SESSION_SUBSCRIPTION_STORES_SCHEMA_FILE =
  "session-subscription-stores.sql" as const;

export interface SessionSubscriptionStoresInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const SESSION_SUBSCRIPTION_STORES_INVARIANTS: readonly SessionSubscriptionStoresInvariant[] =
  [
    {
      id: "SUB_HANDLE_PRIMARY_KEY",
      sqlAnchor: "CREATE TABLE subscription_handles (\n  id uuid PRIMARY KEY,",
      rule: "each subscription handle row has a stable uuid identity.",
    },
    {
      id: "SUB_HANDLE_HASH_NOT_NULL",
      sqlAnchor: "handle_hash sha256_hex NOT NULL,",
      rule: "only the SHA-256 of the handle secret is durable -- bearer token is never stored (the handle is stored hashed).",
    },
    {
      id: "SUB_HANDLE_HASH_UNIQUE",
      sqlAnchor: "UNIQUE (handle_hash),",
      rule: "handle hashes are globally unique so a bearer token resolves to at most one row.",
    },
    {
      id: "SUB_HANDLE_ONE_PER_OPERATION",
      sqlAnchor: "UNIQUE (operation_id),",
      rule: "one active handle per operation; the handle is created with the operation.",
    },
    {
      id: "SUB_HANDLE_EXPIRES_AFTER_CREATE",
      sqlAnchor: "CHECK (expires_at > created_at),",
      rule: "handles expire after creation; a non-positive lifetime is not representable.",
    },
    {
      id: "SUB_HANDLE_EXPIRES_INDEX",
      sqlAnchor:
        "CREATE INDEX subscription_handles_expires_at_idx\n  ON subscription_handles (expires_at);",
      rule: "cleanup scans by expires_at must not table-scan the handle store.",
    },
    {
      id: "ADMIN_SESSION_TEXT_PK",
      sqlAnchor: "CREATE TABLE admin_sessions (\n  id text PRIMARY KEY,",
      rule: "session id is an opaque text token (cookie value), not a uuid.",
    },
    {
      id: "ADMIN_SESSION_CSRF_REQUIRED",
      sqlAnchor: "csrf_token text NOT NULL,",
      rule: "every admin session carries a bound CSRF token.",
    },
    {
      id: "ADMIN_SESSION_CSRF_NONEMPTY",
      sqlAnchor: "CHECK (octet_length(csrf_token) > 0),",
      rule: "empty-string CSRF tokens are not representable.",
    },
    {
      id: "ADMIN_SESSION_EXPIRES_AFTER_CREATE",
      sqlAnchor: "CHECK (expires_at > created_at)",
      rule: "absolute session cap must be strictly after creation.",
    },
    {
      id: "ADMIN_SESSION_LAST_SEEN",
      sqlAnchor: "last_seen_at timestamptz NOT NULL DEFAULT now(),",
      rule: "sliding idle clock is durable so idle timeout can be enforced.",
    },
    {
      id: "ADMIN_SESSION_EXPIRES_INDEX",
      sqlAnchor:
        "CREATE INDEX admin_sessions_expires_at_idx\n  ON admin_sessions (expires_at);",
      rule: "expired-session cleanup scans by expires_at (idx_admin_sessions_expires_at).",
    },
  ] as const;

export const SESSION_SUBSCRIPTION_STORES_MUTABILITY_REGIMES = [
  {
    table: "subscription_handles",
    regime: "guarded_projection",
    updatableColumns: ["consumed_at"] as readonly string[],
    rule: "handle issue is insert-only; only consumed_at advances when the handle is retired after terminal state.",
  },
  {
    table: "admin_sessions",
    regime: "guarded_projection",
    updatableColumns: ["last_seen_at", "expires_at"] as readonly string[],
    rule: "session create is insert-only; last_seen_at refreshes on auth; expires_at is the absolute cap fixed at create.",
  },
] as const;

export const SCHEMA_SESSION_SUBSCRIPTION_STORES_OBLIGATIONS = [
  "execution sequence: no FK targets are required; tables are self-contained. Later slices may ADD CONSTRAINT REFERENCES operations(id)/nodes(id)/admin_users(id) without rewriting the PK shape.",
  "guards: install BEFORE UPDATE enforcement on subscription_handles restricting updates to consumed_at only; install BEFORE UPDATE on admin_sessions restricting updates to last_seen_at (and never id/csrf_token/user_id).",
  "negative: a second subscription_handles row with the same handle_hash is rejected with unique_violation (23505).",
  "negative: a second subscription_handles row with the same operation_id is rejected with unique_violation (23505).",
  "negative: handle_hash outside sha256_hex domain is rejected by the domain CHECK.",
  "negative: expires_at <= created_at on either table is rejected by the temporal CHECK.",
  "negative: empty csrf_token or empty admin_sessions.id is rejected by octet_length CHECK.",
  "retention: subscription_handles rows may be deleted after expires_at (operational); admin_sessions rows may be deleted after expires_at (retention matrix). Neither table is evidence or exact-content.",
] as const;
