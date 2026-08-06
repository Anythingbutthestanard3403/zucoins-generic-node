-- Durable neutral event stream: the reference scalar checks, the neutral node event
-- tuple, and the closed nine-value durable public event set. The per-node counter is
-- gapless; the reporting cursor tracks the dedicated seq while the node-global hash chain
-- is the gap/tamper detector; PRIMARY KEY (node_id, seq) gives one chain per node, so
-- equal seq across nodes is correct on shared-DB topologies. Frozen schema
-- contract. This file is contract text: it is executed only by the schema-apply
-- phase against a live database; nothing in this package runs it. Every invariant below
-- is inventoried in event-ledger.contract.ts and censused by test/event-ledger.census.test.ts.
-- Already-applied databases that still carry `seq` as a single-column primary key take the fix-forward
-- ALTER in node-events-seq-composite-pk.sql.
--
-- Scope: the two tables of the neutral event stream: the dedicated per-node sequence
-- counter (node_event_seq_counters) and the append-only signed event ledger (node_events).
-- The implementer-scoped continuity artifacts (zp-implementer-event-v1 / -checkpoint-v1 /
-- -keyrotation-v1) are NOT transcribed here: their byte-exact field sequence and goldens
-- live in the sibling byte-freeze slice, and the durable serve tables plus the
-- GET /v1/events `checkpoints[]` delivery channel live in implementer-event-stream.sql.

-- Reference scalar checks (verbatim; the two domains these tables use):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- Durable neutral event stream (verbatim, node_event_seq_counters and
-- node_events):

CREATE TABLE node_event_seq_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)
);

CREATE TABLE node_events (
  -- seq is per-node (allocated from node_event_seq_counters), never a fleet-wide
  -- namespace. PRIMARY KEY (node_id, seq) lets two nodes share one database without
  -- colliding when both allocate seq=1. event_id / event_hash stay table-wide UNIQUE.
  seq bigint NOT NULL,
  event_id uuid NOT NULL UNIQUE,
  purpose text NOT NULL DEFAULT 'zp-node-event-v1'
    CHECK (purpose = 'zp-node-event-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  node_id uuid NOT NULL REFERENCES nodes(id),
  operation_id uuid REFERENCES operations(id),
  wallet_id uuid REFERENCES wallets(id),
  event_type text NOT NULL CHECK (event_type IN (
    'receive.ready',
    'receive.landed',
    'internal_move.created',
    'internal_move.landed',
    'external_send.created',
    'external_send.awaiting_redemption',
    'external_send.landed',
    'operation.needs_attention',
    'operation.expired'
  )),
  data_text text NOT NULL,
  data_sha256 sha256_hex NOT NULL,
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
  signature padded_base64url_signature NOT NULL,
  previous_event_hash sha256_hex,
  event_hash sha256_hex NOT NULL UNIQUE,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, seq)
);

-- Append-only at the trigger level: the append-only triggers reject update and delete,
-- and the retention matrix records the signed node event / audit log as permanent and
-- append-only. This
-- discharges the guard obligation event-ledger.contract.ts previously carried as schema-apply work.
--
-- Application-level insert-only discipline is not the guarantee. The event ledger is the
-- node-global hash chain that is the gap/tamper detector: an attacker (or a buggy
-- retention path) that could UPDATE one row's data_text or event_hash, or DELETE a link,
-- would rewrite the chain the detector reads. Only an engine-level BEFORE UPDATE/DELETE
-- trigger stops every connection, including one holding the application role.
--
-- The function is 04's reporting_reject_immutable_change transcribed VERBATIM, including
-- its '55000' ERRCODE -- the canonical append-only rejector, consumed rather than
-- re-invented under a second name. It is re-declared here for the same reason this file
-- re-declares the reference domains: each schema fragment applies standalone, and combined
-- application onto one database de-duplicates them in the reconciliation step
-- (src/schema/CONVENTIONS.md, "ZKZ amount CHECK domains").
--
-- node_event_seq_counters is deliberately NOT guarded: it is the mutable per-node
-- allocation counter, an operational index rather than evidence, and its
-- next_seq advance is the one sanctioned mutation.

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER node_events_no_update
  BEFORE UPDATE ON node_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER node_events_no_delete
  BEFORE DELETE ON node_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

-- TRUNCATE never fires a row-level DELETE trigger, so the two guards above would leave the
-- whole ledger removable in one statement. The statement-level BEFORE TRUNCATE guard closes
-- that bypass; without it "append-only" is only true row by row.
CREATE TRIGGER node_events_no_truncate
  BEFORE TRUNCATE ON node_events
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
