-- Operations response columns (migration-pack ownership).
--
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in operations-response-columns.contract.ts.
--
-- Scope: two nullable columns on the already-created operations table (operations.sql,
-- applied earlier in this pack; this file is an extension and does not re-declare it).
-- operations.sql is a frozen contract, so new columns cannot be added to its CREATE TABLE
-- body without breaking that test. response_status/response_body previously came from a
-- runtime `ALTER TABLE IF NOT EXISTS` in start-money-workers.ts; this file moves all runtime
-- DDL into migrate.ts-owned files.
--
-- Pack position: appended after push-subscriptions so earlier money-pack version numbers
-- (and sql_sha256 journal entries) stay stable for already-applied greenfield DBs (mirrors
-- the gateway-observation-successor-indexes.sql precedent).

ALTER TABLE operations
  ADD COLUMN IF NOT EXISTS response_status integer,
  ADD COLUMN IF NOT EXISTS response_body text;
