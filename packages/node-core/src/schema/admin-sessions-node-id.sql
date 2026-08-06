-- Admin sessions: the node_id column (migration-pack ownership).
--
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in admin-sessions-node-id.contract.ts.
--
-- Scope: one column on the already-created admin_sessions table
-- (session-subscription-stores.sql, applied earlier in this pack; this file is an extension
-- and does not re-declare it). node_id is owned by this migration rather than by a runtime
-- `ALTER TABLE IF NOT EXISTS` in admin-session-sql-store.ts, so every piece of runtime DDL
-- is applied by migrate.ts. It cannot live in the reporting-prefix drizzle journal
-- (apps/generic-node/drizzle/0002_admin_and_operations_ownership.sql) instead: that journal
-- runs BEFORE this pack, so admin_sessions does not exist yet when it applies.
--
-- Pack position: appended after operations-response-columns so earlier money-pack version
-- numbers (and sql_sha256 journal entries) stay stable for already-applied greenfield DBs
-- (mirrors the gateway-observation-successor-indexes.sql precedent).

ALTER TABLE admin_sessions
  ADD COLUMN IF NOT EXISTS node_id text NOT NULL DEFAULT '';
