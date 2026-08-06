-- Collapses reporting_rate_limit_buckets' primary key from
-- (node_id, principal, window_start_ms) to (node_id, principal). reporting-security-ports.sql
-- is a frozen contract (byte-anchored by reporting-security-ports.census.test.ts) and already
-- shipped to production with the 3-column key, so this fix cannot edit that CREATE
-- TABLE in place: schema_migrations is keyed by version number only (sql_sha256 is recorded
-- but never compared), so an in-place edit would be a silent no-op on any database that has
-- already applied that version. This slice instead transforms the live table: dedupe down to
-- one row per (node_id, principal) — keeping the row with the latest window_start_ms, since
-- that is the only bucket still live for that principal — then swap the primary key, then
-- drop the now-pointless updated_at index (bounded by the new 1-row-per-principal cardinality).
--
-- Pack position: appended after reporting-security-ports.sql so existing pack versions stay
-- stable for already-applied databases (mirrors the operations-response-columns.sql /
-- admin-sessions-node-id.sql precedent).

DELETE FROM reporting_rate_limit_buckets a
  USING reporting_rate_limit_buckets b
 WHERE a.node_id = b.node_id
   AND a.principal = b.principal
   AND (a.window_start_ms, a.ctid) < (b.window_start_ms, b.ctid);

ALTER TABLE reporting_rate_limit_buckets
  DROP CONSTRAINT reporting_rate_limit_buckets_pkey,
  ADD CONSTRAINT reporting_rate_limit_buckets_pkey PRIMARY KEY (node_id, principal);

DROP INDEX IF EXISTS reporting_rate_limit_buckets_updated_at_idx;
