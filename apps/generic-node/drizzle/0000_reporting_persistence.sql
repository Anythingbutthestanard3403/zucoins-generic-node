-- SOURCE: generic-node-redesign-v2 ratification gate; 04-data-model.md SS1 (database-wide
-- conventions / scalar domains), SS2 (enumerations + reporting_logical_fingerprint), and the
-- SS3 reporting subset (nodes/implementers/signing keys, reporting nonce burns, the lifecycle
-- event/state/head machinery, restore state, mutation idempotency, and the frozen admission
-- function reporting_lock_and_assert_admission + its REVOKE/GRANT).
--
-- Frozen reporting-persistence schema (ZTR-562 durable-store slice). This is the EXECUTABLE
-- clean-room migration applied by apps/generic-node's migration runner (src/db/migrate.ts);
-- v2 is clean-room per D9.18 and the migration numbering starts at 0000. The byte-identical
-- inert contract twin lives at packages/node-core/src/schema/reporting-persistence.sql, which
-- mirrors custody-eligibility.sql (contract text the node-core package never executes; node-core
-- gains no database dependency from it).
--
-- The statements below are copied VERBATIM from 04-data-model.md and are NOT modernized. The
-- only non-spec statement is the idempotent `node_runtime` role bootstrap immediately below:
-- the frozen REVOKE/GRANT name that role, so an executable clean-room migration must ensure it
-- exists first. It adds no object to the reporting data model.
--
-- Scope note (ZTR-562): the durable store reads/writes the reporting nonce-burn, restore-state,
-- lifecycle-head/state, and mutation-idempotency tables. Those tables' frozen REFERENCES clauses
-- require their SS3 parent tables (nodes, implementers, reporting_key_bootstrap_evidence,
-- reporting_key_lifecycle_events, reporting_key_enrolment_evidence,
-- reporting_key_state_transitions) to exist, so the full foreign-key closure is reproduced
-- verbatim. NO cursor table, NO node_events table, NO verified-events table is added here; the
-- NodeEventVerificationStore durable adapter is out of scope pending a Riley decision.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'node_runtime') THEN
    CREATE ROLE node_runtime NOLOGIN;
  END IF;
END
$$;

-- ===== SS1: database-wide scalar domains the reporting tables depend on =====

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- ===== SS2: enumerations the reporting tables use + the logical-fingerprint function =====

CREATE TYPE reporting_key_state AS ENUM (
  'PENDING',
  'ACTIVE',
  'RETIRED',
  'REVOKED'
);
CREATE TYPE reporting_key_lifecycle_event_type AS ENUM (
  'FIRST_KEY_ACTIVATED',
  'KEY_ROTATED',
  'PRIOR_KEY_RETIRED',
  'KEY_REVOKED',
  'AUTH_HOLD_SET',
  'AUTH_HOLD_RELEASED'
);
CREATE TYPE reporting_request_class AS ENUM ('READ', 'MUTATION');

CREATE FUNCTION reporting_logical_fingerprint(
  p_method text,
  p_raw_target text,
  p_body_sha256 sha256_hex
) RETURNS sha256_hex
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT encode(
    digest(
      convert_to(
        'm' || octet_length(p_method)::text || ':' || p_method ||
        't' || octet_length(p_raw_target)::text || ':' || p_raw_target ||
        'b64:' || p_body_sha256::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )::sha256_hex
$$;

-- ===== SS3: nodes, implementers, and signing keys =====

CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  display_name text NOT NULL,
  identity_public_key padded_base64url_pubkey NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  UNIQUE (identity_public_key),
  CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);

CREATE TABLE implementer_reporting_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  public_key padded_base64url_pubkey NOT NULL,
  registered_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, public_key),
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (id, node_id, implementer_id, registered_at)
);

CREATE TABLE reporting_key_bootstrap_evidence (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  new_reporting_key_id uuid NOT NULL,
  onboarding_actor_id text NOT NULL,
  operator_approval_audit_id uuid NOT NULL,
  approved_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (id, node_id, implementer_id, new_reporting_key_id),
  UNIQUE (node_id, implementer_id, new_reporting_key_id),
  FOREIGN KEY (new_reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id)
);

CREATE TABLE reporting_nonce_burn_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_burn_sequence bigint NOT NULL DEFAULT 1 CHECK (next_burn_sequence > 0)
);

CREATE TABLE reporting_request_nonces (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  nonce uuid NOT NULL,
  purpose text NOT NULL CHECK (purpose IN
    ('zp-reporting-register-v1','zp-report-request-v1')),
  route_id text,
  request_class reporting_request_class,
  reporting_key_id uuid,
  new_reporting_key_id uuid,
  bootstrap_evidence_id uuid,
  lifecycle_epoch bigint NOT NULL CHECK (lifecycle_epoch > 0),
  nonce_burn_sequence bigint NOT NULL CHECK (nonce_burn_sequence > 0),
  request_preimage_text text NOT NULL,
  request_preimage_sha256 sha256_hex NOT NULL,
  request_signature padded_base64url_signature NOT NULL,
  method text,
  raw_target text,
  body_sha256 sha256_hex,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, body_sha256)) STORED,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL,
  retention_class text NOT NULL CHECK (retention_class IN (
    'READ_NO_PRUNE_UNTIL_SAFETY_FREEZE',
    'PERMANENT_MUTATION',
    'LIFECYCLE_PERMANENT'
  )),
  UNIQUE (node_id, implementer_id, nonce),
  UNIQUE (node_id, nonce_burn_sequence),
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (id, node_id, implementer_id, purpose),
  UNIQUE (id, node_id, implementer_id, purpose, route_id),
  UNIQUE (id, node_id, implementer_id, purpose, new_reporting_key_id,
    bootstrap_evidence_id, request_preimage_text, request_preimage_sha256,
    request_signature, issued_at, expires_at),
  UNIQUE (id, node_id, implementer_id, purpose, new_reporting_key_id,
    reporting_key_id, request_preimage_text, request_preimage_sha256,
    request_signature, issued_at, expires_at),
  UNIQUE (id, node_id, implementer_id, route_id, method, raw_target,
    body_sha256, logical_fingerprint),
  UNIQUE (id, node_id, implementer_id, purpose, route_id, request_class,
    retention_class, method, raw_target, body_sha256, logical_fingerprint),
  FOREIGN KEY (reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (new_reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (bootstrap_evidence_id, node_id, implementer_id, new_reporting_key_id)
    REFERENCES reporting_key_bootstrap_evidence
      (id, node_id, implementer_id, new_reporting_key_id),
  CHECK (expires_at > issued_at),
  CHECK (
    (purpose = 'zp-report-request-v1'
      AND expires_at <= issued_at + interval '60 seconds')
    OR
    (purpose = 'zp-reporting-register-v1'
      AND expires_at <= issued_at + interval '300 seconds')
  ),
  CHECK (consumed_at >= received_at),
  CHECK (
    route_id NOT IN ('operation_armed','verification_complete')
    OR
    (request_class = 'MUTATION' AND retention_class = 'PERMANENT_MUTATION')
  ),
  CHECK (
    (purpose = 'zp-reporting-register-v1'
      AND route_id IS NULL AND request_class IS NULL
      AND new_reporting_key_id IS NOT NULL
      AND method IS NULL AND raw_target IS NULL AND body_sha256 IS NULL
      AND logical_fingerprint IS NULL
      AND retention_class = 'LIFECYCLE_PERMANENT'
      AND (
        (reporting_key_id IS NULL AND bootstrap_evidence_id IS NOT NULL)
        OR
        (reporting_key_id IS NOT NULL AND bootstrap_evidence_id IS NULL)
      ))
    OR
    (purpose = 'zp-report-request-v1'
      AND route_id IS NOT NULL AND request_class IS NOT NULL
      AND reporting_key_id IS NOT NULL AND new_reporting_key_id IS NULL
      AND bootstrap_evidence_id IS NULL
      AND method IS NOT NULL AND raw_target IS NOT NULL AND body_sha256 IS NOT NULL
      AND logical_fingerprint IS NOT NULL
      AND (
        (request_class = 'READ'
          AND retention_class = 'READ_NO_PRUNE_UNTIL_SAFETY_FREEZE')
        OR
        (request_class = 'MUTATION'
          AND retention_class = 'PERMANENT_MUTATION')
      ))
  )
);

CREATE TABLE reporting_key_enrolment_evidence (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  new_reporting_key_id uuid NOT NULL,
  supersedes_key_id uuid,
  authorizing_key_id uuid,
  bootstrap_evidence_id uuid,
  nonce_evidence_id uuid NOT NULL UNIQUE,
  registration_purpose text NOT NULL DEFAULT 'zp-reporting-register-v1'
    CHECK (registration_purpose = 'zp-reporting-register-v1'),
  proof_of_possession_preimage_text text NOT NULL,
  proof_of_possession_preimage_sha256 sha256_hex NOT NULL,
  proof_of_possession_signature padded_base64url_signature NOT NULL,
  authorizing_preimage_text text,
  authorizing_preimage_sha256 sha256_hex,
  authorizing_signature padded_base64url_signature,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (node_id, implementer_id, new_reporting_key_id),
  UNIQUE (id, node_id, implementer_id, nonce_evidence_id, new_reporting_key_id),
  FOREIGN KEY (new_reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (supersedes_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (authorizing_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (bootstrap_evidence_id, node_id, implementer_id, new_reporting_key_id)
    REFERENCES reporting_key_bootstrap_evidence
      (id, node_id, implementer_id, new_reporting_key_id),
  FOREIGN KEY (
    nonce_evidence_id, node_id, implementer_id, registration_purpose,
    new_reporting_key_id, bootstrap_evidence_id,
    proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
    proof_of_possession_signature, issued_at, expires_at
  ) REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, purpose, new_reporting_key_id,
       bootstrap_evidence_id, request_preimage_text, request_preimage_sha256,
       request_signature, issued_at, expires_at),
  FOREIGN KEY (
    nonce_evidence_id, node_id, implementer_id, registration_purpose,
    new_reporting_key_id, supersedes_key_id, proof_of_possession_preimage_text,
    proof_of_possession_preimage_sha256, proof_of_possession_signature, issued_at, expires_at
  ) REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, purpose, new_reporting_key_id,
       reporting_key_id, request_preimage_text, request_preimage_sha256,
       request_signature, issued_at, expires_at),
  CHECK (expires_at > issued_at),
  CHECK (expires_at <= issued_at + interval '300 seconds'),
  CHECK (
    (supersedes_key_id IS NULL AND authorizing_key_id IS NULL
      AND bootstrap_evidence_id IS NOT NULL
      AND authorizing_preimage_text IS NULL
      AND authorizing_preimage_sha256 IS NULL
      AND authorizing_signature IS NULL)
    OR
    (supersedes_key_id IS NOT NULL AND authorizing_key_id = supersedes_key_id
      AND bootstrap_evidence_id IS NULL
      AND authorizing_preimage_text IS NOT NULL
      AND authorizing_preimage_sha256 IS NOT NULL
      AND authorizing_signature IS NOT NULL)
  )
);

CREATE TABLE reporting_key_lifecycle_states (
  id uuid PRIMARY KEY,
  reporting_key_id uuid NOT NULL,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  lifecycle_epoch bigint NOT NULL CHECK (lifecycle_epoch >= 0),
  state reporting_key_state NOT NULL,
  lifecycle_event_id uuid,
  state_changed_at timestamptz NOT NULL,
  UNIQUE (reporting_key_id, node_id, implementer_id, lifecycle_epoch),
  UNIQUE (id, node_id, implementer_id, reporting_key_id, lifecycle_epoch, state),
  UNIQUE (lifecycle_event_id, reporting_key_id),
  FOREIGN KEY (reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  CHECK (
    (lifecycle_epoch = 0 AND state = 'PENDING' AND lifecycle_event_id IS NULL)
    OR
    (lifecycle_epoch > 0 AND state <> 'PENDING' AND lifecycle_event_id IS NOT NULL)
  )
);

CREATE TABLE reporting_key_lifecycle_events (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  epoch bigint NOT NULL CHECK (epoch > 0),
  event_type reporting_key_lifecycle_event_type NOT NULL,
  current_key_id uuid,
  prior_key_id uuid,
  overlap_expires_at timestamptz,
  auth_hold boolean NOT NULL,
  successor_registered_at timestamptz,
  nonce_evidence_id uuid NOT NULL,
  nonce_purpose text NOT NULL CHECK (nonce_purpose IN
    ('zp-reporting-register-v1','zp-report-request-v1')),
  enrolment_evidence_id uuid,
  public_evidence_text text NOT NULL,
  public_evidence_sha256 sha256_hex NOT NULL,
  previous_event_id uuid,
  previous_epoch bigint,
  previous_event_hash sha256_hex,
  event_hash sha256_hex NOT NULL UNIQUE,
  committed_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, epoch),
  UNIQUE (id, node_id, implementer_id, epoch),
  UNIQUE (id, node_id, implementer_id, epoch, event_type),
  UNIQUE (id, node_id, implementer_id, epoch, event_hash),
  UNIQUE NULLS NOT DISTINCT (
    id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
    overlap_expires_at, auth_hold
  ),
  FOREIGN KEY (current_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (prior_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (current_key_id, node_id, implementer_id, successor_registered_at)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id, registered_at),
  FOREIGN KEY (nonce_evidence_id, node_id, implementer_id, nonce_purpose)
    REFERENCES reporting_request_nonces(id, node_id, implementer_id, purpose),
  FOREIGN KEY (
    enrolment_evidence_id, node_id, implementer_id, nonce_evidence_id,
    current_key_id
  ) REFERENCES reporting_key_enrolment_evidence
      (id, node_id, implementer_id, nonce_evidence_id, new_reporting_key_id),
  FOREIGN KEY (
    previous_event_id, node_id, implementer_id, previous_epoch,
    previous_event_hash
  ) REFERENCES reporting_key_lifecycle_events
      (id, node_id, implementer_id, epoch, event_hash),
  CHECK (
    (epoch = 1 AND previous_event_id IS NULL AND previous_epoch IS NULL
      AND previous_event_hash IS NULL)
    OR
    (epoch > 1 AND previous_event_id IS NOT NULL
      AND previous_epoch = epoch - 1 AND previous_event_hash IS NOT NULL)
  ),
  CHECK (current_key_id IS NOT NULL OR (prior_key_id IS NULL AND auth_hold)),
  CHECK (
    (prior_key_id IS NULL AND overlap_expires_at IS NULL)
    OR
    (prior_key_id IS NOT NULL AND prior_key_id <> current_key_id
      AND overlap_expires_at IS NOT NULL)
  ),
  CHECK (
    (event_type IN ('FIRST_KEY_ACTIVATED','KEY_ROTATED')
      AND nonce_purpose = 'zp-reporting-register-v1'
      AND enrolment_evidence_id IS NOT NULL
      AND successor_registered_at = committed_at)
    OR
    (event_type IN
      ('PRIOR_KEY_RETIRED','KEY_REVOKED','AUTH_HOLD_SET','AUTH_HOLD_RELEASED')
      AND nonce_purpose = 'zp-report-request-v1'
      AND enrolment_evidence_id IS NULL
      AND successor_registered_at IS NULL)
  ),
  CHECK (
    (event_type = 'FIRST_KEY_ACTIVATED'
      AND epoch = 1 AND current_key_id IS NOT NULL AND prior_key_id IS NULL
      AND overlap_expires_at IS NULL AND NOT auth_hold)
    OR event_type <> 'FIRST_KEY_ACTIVATED'
  ),
  CHECK (
    (event_type = 'KEY_ROTATED'
      AND current_key_id IS NOT NULL AND prior_key_id IS NOT NULL
      AND overlap_expires_at = successor_registered_at + interval '24 hours')
    OR event_type <> 'KEY_ROTATED'
  ),
  CHECK (
    (event_type = 'PRIOR_KEY_RETIRED'
      AND current_key_id IS NOT NULL AND prior_key_id IS NULL
      AND overlap_expires_at IS NULL)
    OR event_type <> 'PRIOR_KEY_RETIRED'
  ),
  CHECK ((event_type = 'AUTH_HOLD_SET' AND auth_hold)
    OR event_type <> 'AUTH_HOLD_SET'),
  CHECK ((event_type = 'AUTH_HOLD_RELEASED' AND NOT auth_hold)
    OR event_type <> 'AUTH_HOLD_RELEASED')
);

CREATE TABLE reporting_key_state_transitions (
  lifecycle_event_id uuid NOT NULL,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  lifecycle_epoch bigint NOT NULL,
  event_type reporting_key_lifecycle_event_type NOT NULL,
  reporting_key_id uuid NOT NULL,
  from_state_row_id uuid NOT NULL,
  to_state_row_id uuid NOT NULL,
  from_lifecycle_epoch bigint NOT NULL CHECK (from_lifecycle_epoch >= 0),
  to_lifecycle_epoch bigint NOT NULL CHECK (to_lifecycle_epoch > 0),
  from_state reporting_key_state NOT NULL,
  to_state reporting_key_state NOT NULL,
  transitioned_at timestamptz NOT NULL,
  PRIMARY KEY (lifecycle_event_id, reporting_key_id),
  UNIQUE (lifecycle_event_id, node_id, implementer_id, lifecycle_epoch,
    reporting_key_id, to_state),
  FOREIGN KEY (
    lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type
  ) REFERENCES reporting_key_lifecycle_events
      (id, node_id, implementer_id, epoch, event_type),
  FOREIGN KEY (reporting_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (
    from_state_row_id, node_id, implementer_id, reporting_key_id,
    from_lifecycle_epoch, from_state
  ) REFERENCES reporting_key_lifecycle_states
      (id, node_id, implementer_id, reporting_key_id, lifecycle_epoch, state),
  FOREIGN KEY (
    to_state_row_id, node_id, implementer_id, reporting_key_id,
    to_lifecycle_epoch, to_state
  ) REFERENCES reporting_key_lifecycle_states
      (id, node_id, implementer_id, reporting_key_id, lifecycle_epoch, state),
  CHECK (
    to_lifecycle_epoch = lifecycle_epoch
    AND from_lifecycle_epoch < to_lifecycle_epoch
  ),
  CHECK (
    (event_type IN ('FIRST_KEY_ACTIVATED','KEY_ROTATED')
      AND from_state = 'PENDING' AND to_state = 'ACTIVE')
    OR
    (event_type = 'PRIOR_KEY_RETIRED'
      AND from_state = 'ACTIVE' AND to_state = 'RETIRED')
    OR
    (event_type = 'KEY_REVOKED'
      AND from_state = 'ACTIVE' AND to_state = 'REVOKED')
  )
);

ALTER TABLE reporting_key_lifecycle_states
  ADD FOREIGN KEY (lifecycle_event_id, node_id, implementer_id, lifecycle_epoch)
    REFERENCES reporting_key_lifecycle_events(id, node_id, implementer_id, epoch);

CREATE TABLE reporting_key_lifecycle_heads (
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  epoch bigint NOT NULL CHECK (epoch >= 0),
  current_key_id uuid,
  prior_key_id uuid,
  overlap_expires_at timestamptz,
  auth_hold boolean NOT NULL DEFAULT true,
  lifecycle_event_id uuid,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, implementer_id),
  FOREIGN KEY (current_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (prior_key_id, node_id, implementer_id)
    REFERENCES implementer_reporting_keys(id, node_id, implementer_id),
  FOREIGN KEY (
    lifecycle_event_id, node_id, implementer_id, epoch, current_key_id,
    prior_key_id, overlap_expires_at, auth_hold
  ) REFERENCES reporting_key_lifecycle_events
      (id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
       overlap_expires_at, auth_hold),
  CHECK (
    (epoch = 0 AND lifecycle_event_id IS NULL AND current_key_id IS NULL
      AND prior_key_id IS NULL AND overlap_expires_at IS NULL AND auth_hold)
    OR
    (epoch > 0 AND lifecycle_event_id IS NOT NULL)
  ),
  CHECK (current_key_id IS NOT NULL OR (prior_key_id IS NULL AND auth_hold)),
  CHECK (
    (prior_key_id IS NULL AND overlap_expires_at IS NULL)
    OR
    (prior_key_id IS NOT NULL AND prior_key_id <> current_key_id
      AND overlap_expires_at IS NOT NULL)
  )
);

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION reporting_guard_lifecycle_head_update()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  e reporting_key_lifecycle_events%ROWTYPE;
BEGIN
  SELECT * INTO STRICT e
    FROM reporting_key_lifecycle_events
    WHERE id = NEW.lifecycle_event_id
      AND node_id = NEW.node_id
      AND implementer_id = NEW.implementer_id;

  IF NEW.epoch <> OLD.epoch + 1
     OR NEW.current_key_id IS DISTINCT FROM e.current_key_id
     OR NEW.prior_key_id IS DISTINCT FROM e.prior_key_id
     OR NEW.overlap_expires_at IS DISTINCT FROM e.overlap_expires_at
     OR NEW.auth_hold IS DISTINCT FROM e.auth_hold
     OR (OLD.epoch = 0 AND
         (e.epoch <> 1 OR e.previous_event_id IS NOT NULL OR
          e.event_type <> 'FIRST_KEY_ACTIVATED'))
     OR (OLD.epoch > 0 AND
         (e.epoch <> NEW.epoch OR e.previous_event_id <> OLD.lifecycle_event_id))
  THEN
    RAISE EXCEPTION 'illegal reporting lifecycle head advance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION reporting_assert_lifecycle_event(p_event_id uuid)
RETURNS void LANGUAGE plpgsql
AS $$
DECLARE
  e reporting_key_lifecycle_events%ROWTYPE;
  p reporting_key_lifecycle_events%ROWTYPE;
  h reporting_key_lifecycle_heads%ROWTYPE;
  transition_count integer;
  changed_key_id uuid;
BEGIN
  SELECT * INTO STRICT e FROM reporting_key_lifecycle_events WHERE id = p_event_id;
  SELECT * INTO STRICT h FROM reporting_key_lifecycle_heads
    WHERE node_id = e.node_id AND implementer_id = e.implementer_id;

  IF h.epoch <> e.epoch OR h.lifecycle_event_id <> e.id
     OR h.current_key_id IS DISTINCT FROM e.current_key_id
     OR h.prior_key_id IS DISTINCT FROM e.prior_key_id
     OR h.overlap_expires_at IS DISTINCT FROM e.overlap_expires_at
     OR h.auth_hold IS DISTINCT FROM e.auth_hold
  THEN
    RAISE EXCEPTION 'lifecycle event/head projection mismatch'
      USING ERRCODE = '23514';
  END IF;

  IF e.epoch = 1 THEN
    IF e.event_type <> 'FIRST_KEY_ACTIVATED' OR e.previous_event_id IS NOT NULL
       OR e.auth_hold OR e.prior_key_id IS NOT NULL
    THEN
      RAISE EXCEPTION 'epoch 1 must be first activation and clear auth hold'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    SELECT * INTO STRICT p FROM reporting_key_lifecycle_events
      WHERE id = e.previous_event_id
        AND node_id = e.node_id
        AND implementer_id = e.implementer_id
        AND epoch = e.epoch - 1
        AND event_hash = e.previous_event_hash;
  END IF;

  SELECT count(*) INTO transition_count
    FROM reporting_key_state_transitions
    WHERE lifecycle_event_id = e.id;

  IF EXISTS (
    SELECT 1 FROM reporting_key_lifecycle_states s
    WHERE s.lifecycle_event_id = e.id
      AND NOT EXISTS (
        SELECT 1 FROM reporting_key_state_transitions t
        WHERE t.lifecycle_event_id = e.id AND t.to_state_row_id = s.id
      )
  ) THEN
    RAISE EXCEPTION 'event-bound key state lacks its transition edge'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM reporting_key_state_transitions t
    JOIN reporting_key_lifecycle_states fs ON fs.id = t.from_state_row_id
    WHERE t.lifecycle_event_id = e.id
      AND EXISTS (
        SELECT 1 FROM reporting_key_lifecycle_states later
        WHERE later.node_id = fs.node_id
          AND later.implementer_id = fs.implementer_id
          AND later.reporting_key_id = fs.reporting_key_id
          AND later.lifecycle_epoch > fs.lifecycle_epoch
          AND later.lifecycle_epoch < e.epoch
      )
  ) THEN
    RAISE EXCEPTION 'state transition does not start from latest key state'
      USING ERRCODE = '23514';
  END IF;

  CASE e.event_type
    WHEN 'FIRST_KEY_ACTIVATED' THEN
      IF transition_count <> 1 OR NOT EXISTS (
        SELECT 1 FROM reporting_key_state_transitions
        WHERE lifecycle_event_id = e.id
          AND reporting_key_id = e.current_key_id
          AND from_state = 'PENDING' AND to_state = 'ACTIVE'
          AND from_lifecycle_epoch = 0 AND to_lifecycle_epoch = 1
      ) THEN
        RAISE EXCEPTION 'first activation requires one PENDING-to-ACTIVE edge'
          USING ERRCODE = '23514';
      END IF;

    WHEN 'KEY_ROTATED' THEN
      IF p.prior_key_id IS NOT NULL
         OR e.prior_key_id IS DISTINCT FROM p.current_key_id
         OR e.auth_hold IS DISTINCT FROM p.auth_hold
         OR transition_count <> 1 OR NOT EXISTS (
           SELECT 1 FROM reporting_key_state_transitions
           WHERE lifecycle_event_id = e.id
             AND reporting_key_id = e.current_key_id
             AND from_state = 'PENDING' AND to_state = 'ACTIVE'
         )
      THEN
        RAISE EXCEPTION 'rotation requires an empty prior slot and one new activation'
          USING ERRCODE = '23514';
      END IF;

    WHEN 'PRIOR_KEY_RETIRED' THEN
      IF p.prior_key_id IS NULL OR e.current_key_id IS DISTINCT FROM p.current_key_id
         OR e.prior_key_id IS NOT NULL OR e.overlap_expires_at IS NOT NULL
         OR e.committed_at < p.overlap_expires_at OR transition_count <> 1
         OR NOT EXISTS (
           SELECT 1 FROM reporting_key_state_transitions
           WHERE lifecycle_event_id = e.id
             AND reporting_key_id = p.prior_key_id
             AND from_state = 'ACTIVE' AND to_state = 'RETIRED'
         )
      THEN
        RAISE EXCEPTION 'prior retirement does not match the expired active prior'
          USING ERRCODE = '23514';
      END IF;

    WHEN 'KEY_REVOKED' THEN
      IF transition_count <> 1 THEN
        RAISE EXCEPTION 'revocation requires exactly one state edge'
          USING ERRCODE = '23514';
      END IF;
      SELECT reporting_key_id INTO STRICT changed_key_id
        FROM reporting_key_state_transitions
        WHERE lifecycle_event_id = e.id
          AND from_state = 'ACTIVE' AND to_state = 'REVOKED';
      IF (changed_key_id = p.current_key_id AND
          NOT (e.current_key_id IS NULL AND e.prior_key_id IS NULL
               AND e.overlap_expires_at IS NULL AND e.auth_hold))
         OR (changed_key_id = p.prior_key_id AND
             NOT (e.current_key_id IS NOT DISTINCT FROM p.current_key_id
                  AND e.prior_key_id IS NULL AND e.overlap_expires_at IS NULL))
         OR (changed_key_id IS DISTINCT FROM p.current_key_id
             AND changed_key_id IS DISTINCT FROM p.prior_key_id)
      THEN
        RAISE EXCEPTION 'revocation result does not match the revoked active slot'
          USING ERRCODE = '23514';
      END IF;

    WHEN 'AUTH_HOLD_SET' THEN
      IF transition_count <> 0 OR p.auth_hold OR NOT e.auth_hold
         OR e.current_key_id IS DISTINCT FROM p.current_key_id
         OR e.prior_key_id IS DISTINCT FROM p.prior_key_id
         OR e.overlap_expires_at IS DISTINCT FROM p.overlap_expires_at
      THEN
        RAISE EXCEPTION 'auth hold set must change only false to true'
          USING ERRCODE = '23514';
      END IF;

    WHEN 'AUTH_HOLD_RELEASED' THEN
      IF transition_count <> 0 OR NOT p.auth_hold OR e.auth_hold
         OR e.current_key_id IS DISTINCT FROM p.current_key_id
         OR e.prior_key_id IS DISTINCT FROM p.prior_key_id
         OR e.overlap_expires_at IS DISTINCT FROM p.overlap_expires_at
      THEN
        RAISE EXCEPTION 'auth hold release must be explicit and change only true to false'
          USING ERRCODE = '23514';
      END IF;
  END CASE;
END
$$;

CREATE FUNCTION reporting_validate_lifecycle_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  event_id uuid;
BEGIN
  event_id := CASE TG_TABLE_NAME
    WHEN 'reporting_key_lifecycle_events' THEN NEW.id
    WHEN 'reporting_key_state_transitions' THEN NEW.lifecycle_event_id
    WHEN 'reporting_key_lifecycle_states' THEN NEW.lifecycle_event_id
    WHEN 'reporting_key_lifecycle_heads' THEN NEW.lifecycle_event_id
  END;
  IF event_id IS NOT NULL THEN
    PERFORM reporting_assert_lifecycle_event(event_id);
  END IF;
  RETURN NULL;
END
$$;

CREATE FUNCTION reporting_advance_lifecycle_head(p_event_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  e reporting_key_lifecycle_events%ROWTYPE;
  changed_count integer;
BEGIN
  SELECT * INTO STRICT e FROM reporting_key_lifecycle_events WHERE id = p_event_id;
  UPDATE reporting_key_lifecycle_heads
    SET epoch = e.epoch,
        current_key_id = e.current_key_id,
        prior_key_id = e.prior_key_id,
        overlap_expires_at = e.overlap_expires_at,
        auth_hold = e.auth_hold,
        lifecycle_event_id = e.id,
        updated_at = e.committed_at
    WHERE node_id = e.node_id
      AND implementer_id = e.implementer_id
      AND epoch = e.epoch - 1
      AND (e.epoch = 1 OR lifecycle_event_id = e.previous_event_id);
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  IF changed_count <> 1 THEN
    RAISE EXCEPTION 'stale or missing reporting lifecycle head'
      USING ERRCODE = '40001';
  END IF;
END
$$;

CREATE TRIGGER reporting_lifecycle_head_guard
  BEFORE UPDATE ON reporting_key_lifecycle_heads
  FOR EACH ROW EXECUTE FUNCTION reporting_guard_lifecycle_head_update();

CREATE CONSTRAINT TRIGGER reporting_lifecycle_event_complete
  AFTER INSERT ON reporting_key_lifecycle_events
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_lifecycle_deferred();
CREATE CONSTRAINT TRIGGER reporting_lifecycle_transition_complete
  AFTER INSERT ON reporting_key_state_transitions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_lifecycle_deferred();
CREATE CONSTRAINT TRIGGER reporting_lifecycle_state_complete
  AFTER INSERT ON reporting_key_lifecycle_states
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_lifecycle_deferred();
CREATE CONSTRAINT TRIGGER reporting_lifecycle_head_complete
  AFTER INSERT OR UPDATE ON reporting_key_lifecycle_heads
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_lifecycle_deferred();

CREATE TRIGGER reporting_lifecycle_events_immutable
  BEFORE UPDATE OR DELETE ON reporting_key_lifecycle_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_state_transitions_immutable
  BEFORE UPDATE OR DELETE ON reporting_key_state_transitions
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_lifecycle_states_immutable
  BEFORE UPDATE OR DELETE ON reporting_key_lifecycle_states
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_lifecycle_events_no_truncate
  BEFORE TRUNCATE ON reporting_key_lifecycle_events
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_state_transitions_no_truncate
  BEFORE TRUNCATE ON reporting_key_state_transitions
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_lifecycle_states_no_truncate
  BEFORE TRUNCATE ON reporting_key_lifecycle_states
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER reporting_key_identity_immutable
  BEFORE UPDATE OR DELETE ON implementer_reporting_keys
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_key_identity_no_truncate
  BEFORE TRUNCATE ON implementer_reporting_keys
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_bootstrap_evidence_immutable
  BEFORE UPDATE OR DELETE ON reporting_key_bootstrap_evidence
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_bootstrap_evidence_no_truncate
  BEFORE TRUNCATE ON reporting_key_bootstrap_evidence
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_enrolment_evidence_immutable
  BEFORE UPDATE OR DELETE ON reporting_key_enrolment_evidence
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_enrolment_evidence_no_truncate
  BEFORE TRUNCATE ON reporting_key_enrolment_evidence
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

REVOKE UPDATE, DELETE, TRUNCATE ON reporting_key_lifecycle_events,
  reporting_key_state_transitions, reporting_key_lifecycle_states,
  implementer_reporting_keys, reporting_key_bootstrap_evidence,
  reporting_key_enrolment_evidence
  FROM node_runtime;
REVOKE UPDATE ON reporting_key_lifecycle_heads FROM node_runtime;
REVOKE ALL ON FUNCTION reporting_advance_lifecycle_head(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reporting_advance_lifecycle_head(uuid) TO node_runtime;

CREATE TABLE reporting_mutation_idempotency (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  route_id text NOT NULL,
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
  reporting_nonce_id uuid NOT NULL UNIQUE,
  child_record_id uuid NOT NULL UNIQUE,
  method text NOT NULL,
  raw_target text NOT NULL,
  body_sha256 sha256_hex NOT NULL,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, body_sha256)) STORED,
  response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_bytes bytea NOT NULL,
  completed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  CHECK (route_id IN ('operation_armed','verification_complete')),
  UNIQUE (node_id, implementer_id, route_id, idempotency_key),
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (id, node_id, implementer_id, route_id, method, raw_target,
    body_sha256, logical_fingerprint),
  FOREIGN KEY (
    reporting_nonce_id, node_id, implementer_id, route_id, method,
    raw_target, body_sha256, logical_fingerprint
  ) REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, route_id, method, raw_target,
       body_sha256, logical_fingerprint)
);

CREATE UNIQUE INDEX reporting_mutation_guarded_fingerprint_uq
  ON reporting_mutation_idempotency
    (node_id, implementer_id, route_id, method, raw_target, body_sha256)
  WHERE route_id IN ('operation_armed','verification_complete');

CREATE TRIGGER reporting_mutation_idempotency_immutable
  BEFORE UPDATE OR DELETE ON reporting_mutation_idempotency
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_mutation_idempotency_no_truncate
  BEFORE TRUNCATE ON reporting_mutation_idempotency
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_nonce_burns_immutable
  BEFORE UPDATE OR DELETE ON reporting_request_nonces
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_nonce_burns_no_truncate
  BEFORE TRUNCATE ON reporting_request_nonces
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

REVOKE UPDATE, DELETE, TRUNCATE ON reporting_mutation_idempotency,
  reporting_request_nonces FROM node_runtime;

CREATE TABLE reporting_restore_state (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  restore_hold boolean NOT NULL DEFAULT true,
  local_lifecycle_epoch bigint CHECK
    (local_lifecycle_epoch IS NULL OR local_lifecycle_epoch > 0),
  local_nonce_burn_high_water bigint CHECK
    (local_nonce_burn_high_water IS NULL OR local_nonce_burn_high_water >= 0),
  local_event_hash sha256_hex,
  trusted_lifecycle_epoch bigint CHECK
    (trusted_lifecycle_epoch IS NULL OR trusted_lifecycle_epoch > 0),
  trusted_nonce_burn_high_water bigint CHECK
    (trusted_nonce_burn_high_water IS NULL OR trusted_nonce_burn_high_water >= 0),
  trusted_event_hash sha256_hex,
  trusted_source_id text,
  trusted_source_observed_at timestamptz,
  hold_release_evidence_sha256 sha256_hex,
  hold_released_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (
    (trusted_source_id IS NULL AND trusted_source_observed_at IS NULL
      AND trusted_lifecycle_epoch IS NULL AND trusted_nonce_burn_high_water IS NULL
      AND trusted_event_hash IS NULL)
    OR
    (trusted_source_id IS NOT NULL AND trusted_source_observed_at IS NOT NULL
      AND trusted_lifecycle_epoch IS NOT NULL AND trusted_nonce_burn_high_water IS NOT NULL
      AND trusted_event_hash IS NOT NULL)
  ),
  CHECK (
    restore_hold
    OR
    (trusted_source_id IS NOT NULL
      AND local_lifecycle_epoch IS NOT NULL
      AND local_nonce_burn_high_water IS NOT NULL
      AND local_event_hash IS NOT NULL
      AND local_lifecycle_epoch = trusted_lifecycle_epoch
      AND local_nonce_burn_high_water = trusted_nonce_burn_high_water
      AND local_event_hash = trusted_event_hash
      AND hold_release_evidence_sha256 IS NOT NULL
      AND hold_released_at IS NOT NULL)
  )
);

-- The frozen admission AUTHORITY. The durable burn transaction calls this function; it does
-- NOT replicate the lock/recheck logic in TypeScript. Raises ERRCODE '55000' (restore hold
-- active / lifecycle admission closed) and P0002 (no_data_found) on a missing restore-state
-- or lifecycle-head row; the adapter maps those to HOLD vs LIFECYCLE_RECHECK_FAILED.
CREATE FUNCTION reporting_lock_and_assert_admission(
  p_node_id uuid,
  p_implementer_id uuid,
  p_lifecycle_epoch bigint,
  p_reporting_key_id uuid,
  p_received_at timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  r reporting_restore_state%ROWTYPE;
  h reporting_key_lifecycle_heads%ROWTYPE;
BEGIN
  SELECT * INTO STRICT r FROM reporting_restore_state
    WHERE node_id = p_node_id FOR UPDATE;
  IF r.restore_hold THEN
    RAISE EXCEPTION 'reporting restore hold is active' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO STRICT h FROM reporting_key_lifecycle_heads
    WHERE node_id = p_node_id AND implementer_id = p_implementer_id
    FOR UPDATE;
  IF h.auth_hold OR h.epoch <> p_lifecycle_epoch
     OR NOT (
       p_reporting_key_id = h.current_key_id
       OR
       (p_reporting_key_id = h.prior_key_id
        AND p_received_at < h.overlap_expires_at)
     )
     OR NOT EXISTS (
       SELECT 1 FROM reporting_key_lifecycle_states s
       WHERE s.node_id = p_node_id
         AND s.implementer_id = p_implementer_id
         AND s.reporting_key_id = p_reporting_key_id
         AND s.state = 'ACTIVE'
         AND s.lifecycle_epoch = (
           SELECT max(s2.lifecycle_epoch)
           FROM reporting_key_lifecycle_states s2
           WHERE s2.node_id = s.node_id
             AND s2.implementer_id = s.implementer_id
             AND s2.reporting_key_id = s.reporting_key_id
         )
     )
  THEN
    RAISE EXCEPTION 'reporting lifecycle admission is closed'
      USING ERRCODE = '55000';
  END IF;
END
$$;

REVOKE ALL ON FUNCTION reporting_lock_and_assert_admission(
  uuid, uuid, bigint, uuid, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reporting_lock_and_assert_admission(
  uuid, uuid, bigint, uuid, timestamptz
) TO node_runtime;
