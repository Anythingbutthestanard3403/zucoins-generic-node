-- node_events primary key is composite (node_id, seq).
--
-- event-ledger.sql originally shipped `seq bigint PRIMARY KEY` while the seq counter
-- (node_event_seq_counters) and every reader/writer (readTail, appendBatch, scanAfter)
-- were already per-node. Two nodes sharing one database therefore collide on
-- node_events_pkey as soon as both allocate the same seq. Dual-chain landed-event
-- appends make that collision reachable on every shared-DB topology
-- (e.g. pub-ref node on the live platform database).
--
-- schema_migrations is keyed by version number only (sql_sha256 is recorded but never
-- compared), so an in-place edit of the already-applied event-ledger CREATE TABLE would
-- be a silent no-op on any database that has already journalled that version. This slice
-- transforms the live table: drop the global-seq primary key and replace it with
-- (node_id, seq). Greenfield event-ledger.sql is updated in lockstep so fresh applies
-- never create the broken key; this ALTER is a no-op when the live key is already
-- composite (cold pack apply after the updated event-ledger CREATE).
--
-- Pack position: appended after reporting-rate-limit-buckets-pk-collapse.sql so existing
-- pack versions stay stable (mirrors the operations-response-columns.sql /
-- admin-sessions-node-id.sql / reporting-rate-limit-buckets-pk-collapse.sql precedent).
--
-- Deploy order: apply on every shared-DB topology BEFORE multi-node landed
-- dual-chain event appends run against that database. See the deploy/rollback runbook
-- SS "node_events composite PK".

DO $node_events_seq_node_events_pk$
BEGIN
  -- Fail closed when applied alone / out of pack order (greenfield characterization and
  -- operator foot-gun): event-ledger.sql must have created node_events first.
  IF to_regclass(format('%I.node_events', current_schema())) IS NULL THEN
    RAISE EXCEPTION 'relation "node_events" does not exist'
      USING ERRCODE = '42P01';
  END IF;

  -- Only rewrite when the live primary key is still the single-column `seq` form.
  -- Cold greenfield (event-ledger.sql already emits PRIMARY KEY (node_id, seq)) is a no-op.
  IF EXISTS (
    SELECT 1
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
      JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
     WHERE nsp.nspname = current_schema()
       AND rel.relname = 'node_events'
       AND c.conname = 'node_events_pkey'
       AND c.contype = 'p'
       AND (
         SELECT array_agg(att.attname::text ORDER BY u.ord)
           FROM unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord)
           JOIN pg_attribute att
             ON att.attrelid = c.conrelid AND att.attnum = u.attnum
       ) = ARRAY['seq']::text[]
  ) THEN
    ALTER TABLE node_events
      DROP CONSTRAINT node_events_pkey,
      ADD CONSTRAINT node_events_pkey PRIMARY KEY (node_id, seq);
  END IF;
END
$node_events_seq_node_events_pk$;
