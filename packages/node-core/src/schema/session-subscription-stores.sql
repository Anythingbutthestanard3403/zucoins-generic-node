-- Subscription handles and node-origin admin sessions: the subscription handle
-- stored hashed, expires after terminal state, single-operation lifecycle auth) and
-- store, the node-origin admin session with CSRF, and the admission DB-TX that creates
-- the subscription-handle hash alongside a RECEIVE_EXTERNAL/CREATED row.
-- A.10 admin_sessions column shape (lifted, GN-adapted: no admin_users FK and no
-- cascading foreign-key delete action -- admin_users is a later operator-identity slice).
-- Frozen schema contract. This file is contract text: it
-- is executed only by the schema-apply phase against a live database; nothing in this
-- package runs it. Every invariant below is inventoried in
-- session-subscription-stores.contract.ts and censused by
-- test/session-subscription-stores.census.test.ts.
--
-- Scope: the two durable stores the operational-store surface requires, so the
-- schema census reverse-traversal gate
-- is no longer green-washed via disposition=deferred:
--   1. subscription_handles  -- the hashed handle written by the admission DB-TX
--   2. admin_sessions        -- the node-origin admin session + CSRF store
-- Write paths (issue/consume handle; create/refresh session) are later API slices;
-- this file freezes the durable shape only.

-- Reference scalar (re-declared for self-contained contract text):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- 1. Subscription handles.
-- Bearer token sh_... is returned once on the original idempotent create response and
-- never re-readable. Only the SHA-256 of the secret is durable. One active handle
-- per operation; expires shortly after the operation reaches a terminal state.

CREATE TABLE subscription_handles (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  handle_hash sha256_hex NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz,
  UNIQUE (handle_hash),
  UNIQUE (operation_id),
  CHECK (expires_at > created_at),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX subscription_handles_expires_at_idx
  ON subscription_handles (expires_at);

CREATE INDEX subscription_handles_node_operation_idx
  ON subscription_handles (node_id, operation_id);

-- 2. Admin sessions.
-- id is an opaque 32-byte base64url token (cookie value), not a uuid.
-- CSRF token is session-bound. expires_at is the absolute cap; last_seen_at
-- is the sliding idle clock. No cascading foreign-key delete action -- operator
-- identity parent tables are out of this slice.

CREATE TABLE admin_sessions (
  id text PRIMARY KEY,
  user_id uuid NOT NULL,
  csrf_token text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  ip inet,
  user_agent text,
  CHECK (octet_length(id) > 0),
  CHECK (octet_length(csrf_token) > 0),
  CHECK (expires_at > created_at)
);

CREATE INDEX admin_sessions_expires_at_idx
  ON admin_sessions (expires_at);

CREATE INDEX admin_sessions_user_id_idx
  ON admin_sessions (user_id);
