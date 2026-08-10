-- Worker-poll indexes on operations: the indexes the money-worker tick needs so a
-- kind/status filter does not sequential-scan a table that only grows.
--
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply
-- phase against a live database; nothing in this package runs it. Every invariant below is
-- inventoried in operations-indexes.contract.ts.
--
-- Scope: pure index extension on the already-created operations table (operations.sql,
-- applied first; this file is an extension and does not re-declare it). It creates no table,
-- no column, no trigger, no domain. It does NOT touch operations_one_spawn_per_parent_uidx
-- (operations.sql) -- that partial unique index is a correctness arbiter for the one-child-
-- per-parent rule, not a performance index, and the spawn path depends on its ON CONFLICT
-- behaviour.
--
-- Pack position: appended after wallet-settled-ledger-indexes so earlier money-pack version
-- numbers (and their schema_migrations sql_sha256 journal entries) stay stable for already-
-- applied databases. operations.sql is itself already applied, so the indexes cannot be added
-- by editing it: runMigrations pins each applied file's sql_sha256 and rejects an in-place
-- edit, which is the intended behaviour. Mirrors the wallet-settled-ledger-indexes.sql and
-- gateway-observation-successor-indexes.sql precedents (pure index extension, appended,
-- version-stable).
--
-- QUERY CENSUS (every non-test FROM operations in packages/node-core/src and
-- apps/generic-node/src was enumerated; the filters below are the ones that scan by
-- status/kind rather than by primary key or by the existing UNIQUE
-- (implementer_id, kind, idempotency_key) / spawned_from_operation_id indexes):
--
--   1. Unassigned CREATED receive queue (identical predicate on five statements):
--        pool-scaler.ts QUEUE_DEPTH_AND_OLDEST_AGE / SELECT_QUEUE_AGED_RECEIVES /
--          EXPIRE_UNASSIGNED_RECEIVE
--        pool-allocator.ts COUNT_UNASSIGNED_RECEIVES / SELECT_QUEUED_RECEIVES_FIFO
--        metrics-snapshot.ts QUEUE_DEPTH_AND_OLDEST_AGE (same text as the scaler)
--      WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED'
--        AND receiver_wallet_id IS NULL
--        [+ anti-join on operation_wallets RECEIVER]
--      ORDER BY created_at, id (FIFO / aged-expiry)
--
--   2. Receive expiry sweep (expiry-release.ts SELECT_EXPIRY_CANDIDATES):
--      WHERE kind = 'RECEIVE_EXTERNAL'
--        AND status IN ('CREATED','READY','EXPIRED')
--        AND receive_release_status IS NULL
--      ORDER BY created_at, id
--      Note: receive_release_status is added by receive-expiry-release.sql (ALTER on
--      operations after the base table). The partial predicate still matches because a
--      column added later is visible to a later pack slice.
--
--   3. READY receive settle/landing batch
--      (receive-settle-step.ts SELECT_SETTLEABLE; receive-landing-step candidates):
--      WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'READY'
--
--   4. Landed-receive child handoff
--      (receive-child-handoff-step.ts LOAD_HANDOFF_CANDIDATES_SQL):
--      WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'RECEIVE_LANDED'
--        AND after_landing = 'INTERNAL_MOVE'
--
--   5. Pending MOVE_INTERNAL worker
--      (move-internal-worker.ts LOAD_PENDING_MOVES_SQL):
--      WHERE kind = 'MOVE_INTERNAL' AND status IN ('CREATED','NEEDS_ATTENTION')
--      ORDER BY created_at
--
--   6. metrics-snapshot.ts COUNT_OPERATIONS_BY_STATUS is a full GROUP BY status over the
--      whole table. An index does not help a full aggregate; left alone on purpose.
--
--   7. Everything else is WHERE id = $1 (PK) or the existing UNIQUE
--      (implementer_id, kind, idempotency_key) / spawned_from_operation_id indexes.
--
-- INDEX SHAPE. Partial indexes, one per worker-poll working set, each carrying created_at
-- so the ORDER BY (created_at, id) on the queue/expiry/move polls is an index-ordered scan
-- rather than a sort. Partials stay tiny as terminal rows accumulate -- the defect this
-- ticket closes is that the ratio of scanned-to-useful degrades continuously on a seq scan.
-- A single non-partial (kind, status) index would still visit every historical row of that
-- kind/status pair (including landed terminals the workers never want). Column order is
-- fixed by the equality constants in each predicate, not guessed.
--
-- Partial predicates match the source queries' equality filters VERBATIM (kind/status and,
-- where present, receiver_wallet_id IS NULL / after_landing / receive_release_status IS NULL).
-- The anti-join against operation_wallets and the EXISTS on wallet_active_leases cannot live
-- in an index predicate; the partial still collapses the candidate set to the transient
-- working set those joins then filter.
--
-- NOT CONCURRENTLY, deliberately. db/migrate.ts wraps migration application in
-- `BEGIN ISOLATION LEVEL ...` and CREATE INDEX CONCURRENTLY cannot run inside a transaction
-- block, so CONCURRENTLY here would abort the migration. A plain CREATE INDEX takes a SHARE
-- lock that blocks writers for the duration of the build; that is the correct trade while
-- the table is small, and is the reason these indexes are added now rather than after the
-- table has grown large enough to make building them an operational event.

-- Unassigned CREATED receive queue (pool-scaler.ts:164-172, :190-198; pool-allocator.ts:183-191,
-- :202-210; metrics-snapshot.ts:86-94). Predicate matches the five statements' common filter
-- verbatim; created_at leads so FIFO ORDER BY created_at, id and min(created_at) are index-
-- ordered.
CREATE INDEX operations_receive_queue_created_idx
  ON operations (created_at, id)
  WHERE kind = 'RECEIVE_EXTERNAL'
    AND status = 'CREATED'
    AND receiver_wallet_id IS NULL;

-- Receive expiry sweep (expiry-release.ts:1239-1256). status IN (CREATED,READY,EXPIRED) is
-- the pre-terminal receive set the expirer walks; receive_release_status IS NULL excludes rows
-- already released. created_at leads for ORDER BY created_at, id.
CREATE INDEX operations_receive_expiry_candidates_idx
  ON operations (created_at, id)
  WHERE kind = 'RECEIVE_EXTERNAL'
    AND status IN ('CREATED', 'READY', 'EXPIRED')
    AND receive_release_status IS NULL;

-- READY receive settle/landing batch (receive-settle-step.ts:102-126;
-- receive-landing-step.ts READY candidates). Equality on kind+status only.
CREATE INDEX operations_receive_ready_idx
  ON operations (created_at, id)
  WHERE kind = 'RECEIVE_EXTERNAL'
    AND status = 'READY';

-- Landed-receive child handoff (receive-child-handoff-step.ts:30-48). after_landing =
-- 'INTERNAL_MOVE' is part of the source predicate and is stable for the life of the row.
CREATE INDEX operations_receive_landed_handoff_idx
  ON operations (created_at, id)
  WHERE kind = 'RECEIVE_EXTERNAL'
    AND status = 'RECEIVE_LANDED'
    AND after_landing = 'INTERNAL_MOVE';

-- Pending MOVE_INTERNAL worker (move-internal-worker.ts:41-65). status IN (CREATED,
-- NEEDS_ATTENTION) is the pre-terminal move set; created_at leads for ORDER BY created_at.
CREATE INDEX operations_move_pending_idx
  ON operations (created_at, id)
  WHERE kind = 'MOVE_INTERNAL'
    AND status IN ('CREATED', 'NEEDS_ATTENTION');
