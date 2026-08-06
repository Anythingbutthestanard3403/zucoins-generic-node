-- ZTR-987: migration-pack ownership for operational/admin-surface DDL previously issued at
-- runtime. Moves CREATE/ALTER/INDEX statements out of
-- apps/generic-node/src/ops/admin-idempotency.ts,
-- packages/node-core/src/http/admin-session-sql-store.ts, admin-user-sql-store.ts, and
-- apps/generic-node/src/money-workers/start-money-workers.ts into the reporting-prefix drizzle
-- journal that apps/generic-node/src/db/migrate.ts owns exclusively (CONVENTIONS.md §8). All
-- statements are byte-identical to the runtime DDL they replace.
--
-- operations.response_status/response_body moved to a new appended money-schema-pack slice
-- (packages/node-core/src/schema/operations-response-columns.sql) instead of this journal:
-- operations.sql is applied by the money-schema pack AFTER this reporting-prefix journal
-- (migrate.ts, CONVENTIONS.md §8), so an ALTER on operations here would run before the table
-- exists.
--
-- admin_sessions itself is NOT touched here at all: the base table
-- (id/user_id/csrf_token/expires_at/created_at/last_seen_at/ip/user_agent, both indexes) is
-- already owned by packages/node-core/src/schema/session-subscription-stores.sql (ZTR-245,
-- GN-048.3), which this reporting-prefix journal runs BEFORE (migrate.ts applies the drizzle
-- journal first, then the money pack) — the table does not exist yet when this file runs, so
-- neither a CREATE TABLE (collides with that pack's unguarded CREATE TABLE) nor an ALTER
-- (target does not exist yet) can live here. Its missing node_id column (previously added by a
-- runtime ALTER in admin-session-sql-store.ts) is instead added by a new appended money-pack
-- slice, packages/node-core/src/schema/admin-sessions-node-id.sql, which runs after that table
-- is created (same precedent as operations-response-columns.sql).

CREATE TABLE IF NOT EXISTS admin_mutation_idempotency (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  route_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
  method text NOT NULL,
  raw_target text NOT NULL,
  body_sha256 sha256_hex NOT NULL,
  response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_bytes bytea NOT NULL,
  completed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (node_id, route_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS admin_operators (
  id text PRIMARY KEY,
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','viewer')),
  must_change_password boolean NOT NULL DEFAULT true,
  must_enrol_totp boolean NOT NULL DEFAULT true,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  totp_status text NOT NULL DEFAULT 'none'
    CHECK (totp_status IN ('none','pending','active')),
  totp_secret_base32 text
);

