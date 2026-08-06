-- Receive external landing: the landing DB-TX, the landing/lineage proof relations, the
-- node_events append, and the ancestor_proofs wire shape.
-- Frozen schema contract. Prerequisite: operations.sql (operations)
-- and lease-foundation.sql / custody-eligibility.sql (wallet_active_leases).
--
-- The RECEIVE_EXTERNAL counterpart of send-external-landing.sql. It adds no columns: the
-- The operations row already carries status, row_version, t0_observation_id,
-- terminal_observation_id, verification_material_available_until and terminal_at, so the
-- READY -> RECEIVE_LANDED transition writes only columns that already exist.
--
-- Three tables, all insert-only:
--   receive_landing_proofs      -- the landing/lineage proof header, one per operation
--   receive_landing_path_bodies -- the ORDERED complete path, one row per body
--   receive_landing_events      -- receive.landed, at most one row per operation
--
-- The receiver lease is NOT released by any statement in this file ("the
-- receiver lease stays held"). No statement here DELETEs or UPDATEs wallet_active_leases.

-- Landing proof header, collapsed to the single RECEIVER path a RECEIVE_EXTERNAL requires
-- (lineage_path_proofs.required_path_count = 1 for receive). Written only by the landing
-- DB-TX, once, on a positive proof.
CREATE TABLE receive_landing_proofs (
  operation_id uuid PRIMARY KEY REFERENCES operations (id),
  attempt_phase text NOT NULL CHECK (attempt_phase = 'SETTLED_BODY_PERSISTED'),
  public_execution_phase text NOT NULL CHECK (public_execution_phase = 'LANDED_VERIFIED'),
  path_role text NOT NULL CHECK (path_role = 'RECEIVER'),
  wallet_public_key text NOT NULL
    CHECK (length(wallet_public_key) = 44 AND wallet_public_key ~ '^[A-Za-z0-9_-]{43}=$'),
  t0_observation_id uuid NOT NULL,
  fresh_head_observation_id uuid NOT NULL,
  terminal_observation_id uuid NOT NULL,
  -- The digest of the attempt whose landing was in question, and of the freshly read
  -- authoritative head the path terminates at. Equal exactly at depth 0 (LANDED_EXACT).
  expected_completed_transaction_sha256 text NOT NULL
    CHECK (expected_completed_transaction_sha256 ~ '^[0-9a-f]{64}$'),
  fresh_head_completed_transaction_sha256 text NOT NULL
    CHECK (fresh_head_completed_transaction_sha256 ~ '^[0-9a-f]{64}$'),
  verdict text NOT NULL CHECK (verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')),
  body_count bigint NOT NULL CHECK (body_count > 0),
  path_depth bigint NOT NULL CHECK (path_depth >= 0 AND path_depth = body_count - 1),
  -- The manifest an independent verifier re-derives to walk the identical path
  -- The ancestor_proofs wire shape. Exact text plus its digest.
  path_manifest_text text NOT NULL CHECK (octet_length(path_manifest_text) > 0),
  path_manifest_sha256 text NOT NULL CHECK (path_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  landed_at timestamptz NOT NULL,
  verification_material_available_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- n=0 yields LANDED_EXACT; n>=1 yields LANDED_COMPLETE_PATH.
  CONSTRAINT receive_landing_verdict_depth
    CHECK (
      (verdict = 'LANDED_EXACT' AND path_depth = 0)
      OR (verdict = 'LANDED_COMPLETE_PATH' AND path_depth >= 1)
    ),
  -- At depth 0 the expected body IS the fresh head; at depth >= 1 it cannot be.
  CONSTRAINT receive_landing_exact_head_identity
    CHECK (
      (path_depth = 0)
      = (expected_completed_transaction_sha256 = fresh_head_completed_transaction_sha256)
    )
);

-- The ORDERED complete path, T_expected ... T_head, in exact full-body form. One row
-- per body; the primary key makes path_index unique and the constraint trigger below makes
-- the sequence contiguous, anchored at both ends and backlinked at every hop. A partial path
-- cannot be committed: the trigger fires at COMMIT and aborts the whole landing DB-TX.
-- Column set follows lineage_path_bodies.
CREATE TABLE receive_landing_path_bodies (
  operation_id uuid NOT NULL REFERENCES receive_landing_proofs (operation_id),
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind IN
    ('EXPECTED_OPERATION', 'CANONICAL_LEDGER', 'PROOF_CHANNEL', 'FRESH_GATEWAY_HEAD')),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 text NOT NULL
    CHECK (completed_transaction_sha256 ~ '^[0-9a-f]{64}$'),
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender', 'receiver')),
  s_signature text NOT NULL CHECK (s_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  -- A genesis-adjacent body carries P = ''. Every other body carries a signature.
  p_signature text NOT NULL CHECK (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  b_amount text NOT NULL CHECK (b_amount ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$'),
  inner_preimage_text text NOT NULL CHECK (octet_length(inner_preimage_text) > 0),
  inner_sha256 text NOT NULL CHECK (inner_sha256 ~ '^[0-9a-f]{64}$'),
  step_1_signature text NOT NULL CHECK (step_1_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  step_2_signature text NOT NULL CHECK (step_2_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  PRIMARY KEY (operation_id, path_index),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets)
);

CREATE INDEX receive_landing_path_bodies_state_signature_idx
  ON receive_landing_path_bodies (operation_id, s_signature);
CREATE INDEX receive_landing_path_bodies_body_digest_idx
  ON receive_landing_path_bodies (completed_transaction_sha256);

-- Indicator 1b, structural. Deferred to COMMIT so the landing DB-TX may insert the header
-- and its bodies in any sequence, but cannot commit a path that is short, gapped, mis-anchored
-- at either end, or broken at a backlink. This is the database refusing a partial path, not
-- application logic that a concurrent writer can race past.
CREATE FUNCTION receive_landing_path_complete() RETURNS trigger AS $$
DECLARE
  header receive_landing_proofs%ROWTYPE;
  actual_count bigint;
  head_index bigint;
BEGIN
  SELECT * INTO header FROM receive_landing_proofs WHERE operation_id = NEW.operation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_HEADER_MISSING';
  END IF;
  head_index := header.body_count - 1;

  SELECT count(*) INTO actual_count
    FROM receive_landing_path_bodies WHERE operation_id = NEW.operation_id;
  IF actual_count <> header.body_count THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_INCOMPLETE';
  END IF;

  -- Contiguous 0 .. body_count-1. With the primary key, matching endpoints and matching
  -- cardinality leave no room for a hole.
  IF (SELECT min(path_index) FROM receive_landing_path_bodies
        WHERE operation_id = NEW.operation_id) <> 0
     OR (SELECT max(path_index) FROM receive_landing_path_bodies
        WHERE operation_id = NEW.operation_id) <> head_index THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_NOT_CONTIGUOUS';
  END IF;

  -- Anchored at the expected attempt and at the freshly read authoritative head.
  IF (SELECT completed_transaction_sha256 FROM receive_landing_path_bodies
        WHERE operation_id = NEW.operation_id AND path_index = 0)
     <> header.expected_completed_transaction_sha256 THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_EXPECTED_ANCHOR_MISMATCH';
  END IF;
  IF (SELECT completed_transaction_sha256 FROM receive_landing_path_bodies
        WHERE operation_id = NEW.operation_id AND path_index = head_index)
     <> header.fresh_head_completed_transaction_sha256 THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_HEAD_ANCHOR_MISMATCH';
  END IF;

  -- Role-relative backlink P(W,T[i]) = S(W,T[i-1]) at every hop.
  IF EXISTS (
    SELECT 1
      FROM receive_landing_path_bodies prev
      JOIN receive_landing_path_bodies next
        ON next.operation_id = prev.operation_id
       AND next.path_index = prev.path_index + 1
     WHERE prev.operation_id = NEW.operation_id
       AND next.p_signature <> prev.s_signature
  ) THEN
    RAISE EXCEPTION 'RECEIVE_LANDING_PATH_BACKLINK_BROKEN';
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER receive_landing_path_bodies_complete
  AFTER INSERT ON receive_landing_path_bodies
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION receive_landing_path_complete();

-- The same check, attached to the HEADER. Without it a landing that inserts the header and
-- NO body rows at all escapes: an AFTER INSERT trigger on the bodies table cannot fire when
-- nothing is inserted into that table, so body_count = 2 with zero bodies would commit as
-- RECEIVE_LANDED carrying no path whatsoever. Every landing writes exactly one header row
-- (the bodies foreign-key it), so this trigger covers the zero-body case the per-body one
-- structurally cannot reach.
CREATE CONSTRAINT TRIGGER receive_landing_proofs_path_complete
  AFTER INSERT ON receive_landing_proofs
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION receive_landing_path_complete();

-- Slice-local event append for receive.landed (the node_events vocabulary and event data
-- shape). The unique index is the database's exactly-once guarantee for indicator 4: two
-- emitters that both reached this insert collide on 23505 and one transaction aborts whole.
CREATE TABLE receive_landing_events (
  event_id bigserial PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations (id),
  event_type text NOT NULL CHECK (event_type = 'receive.landed'),
  terminal_observation_id uuid NOT NULL,
  landed_at timestamptz NOT NULL,
  data_text text NOT NULL CHECK (octet_length(data_text) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX receive_landing_events_one_per_operation
  ON receive_landing_events (operation_id);

CREATE FUNCTION receive_landing_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'RECEIVE_LANDING_INSERT_ONLY';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER receive_landing_proofs_insert_only
  BEFORE UPDATE OR DELETE ON receive_landing_proofs
  FOR EACH ROW EXECUTE FUNCTION receive_landing_reject_mutation();

CREATE TRIGGER receive_landing_path_bodies_insert_only
  BEFORE UPDATE OR DELETE ON receive_landing_path_bodies
  FOR EACH ROW EXECUTE FUNCTION receive_landing_reject_mutation();

CREATE TRIGGER receive_landing_events_insert_only
  BEFORE UPDATE OR DELETE ON receive_landing_events
  FOR EACH ROW EXECUTE FUNCTION receive_landing_reject_mutation();
