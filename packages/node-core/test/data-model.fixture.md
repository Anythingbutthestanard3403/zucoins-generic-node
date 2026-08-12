<!--
Frozen structural surface of the governing data-model specification: every
section heading, every fenced SQL block (DDL: domains, enumerations, tables),
and the public execution_phase durable-fact table. Committed as a fixture so
schema gates pin against this frozen inventory. Regenerate only when the
governing schema specification itself changes.
-->
## 1. Database-wide conventions
```sql
-- Balance layer: 0 <= amount < 1e8 ("0" legal). Operation layer: 0 < amount < 1e8 via NUMERIC positivity.
CREATE DOMAIN zkz_balance_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$');

CREATE DOMAIN zkz_amount_positive_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND VALUE::numeric > 0);

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');
```
## 2. Enumerations
```sql
CREATE TYPE operation_kind AS ENUM (
  'RECEIVE_EXTERNAL',
  'MOVE_INTERNAL',
  'SEND_EXTERNAL'
);

CREATE TYPE operation_status AS ENUM (
  'CREATED',
  'READY',
  'RECEIVE_LANDED',
  'INTERNAL_MOVE_LANDED',
  'APPROVED',
  'AWAITING_REDEMPTION',
  'EXTERNAL_SEND_LANDED',
  'EXPIRED',
  'REJECTED',
  'NEEDS_ATTENTION'
);

CREATE TYPE wallet_key_origin AS ENUM ('node_generated', 'imported');
CREATE TYPE wallet_state AS ENUM ('AVAILABLE', 'PINNED', 'QUARANTINED', 'RETIRED');
CREATE TYPE destination_state AS ENUM ('PENDING', 'BLESSED', 'RETIRED');
CREATE TYPE wallet_lease_role AS ENUM (
  'RECEIVE_WINDOW',
  'MOVE_SOURCE',
  'MOVE_DESTINATION',
  'SEND_SOURCE',
  'RECONCILIATION'
);
CREATE TYPE approval_method AS ENUM ('TOTP_ONLY', 'TOTP_AND_DEVICE', 'AUTO_POLICY');
CREATE TYPE approval_challenge_status AS ENUM ('ISSUED', 'CONSUMED', 'SUPERSEDED', 'EXPIRED');
CREATE TYPE external_formation_state AS ENUM (
  'NOT_REQUIRED',
  'APPROVAL_PENDING',
  'APPROVED_UNSIGNED',
  'SIGNING_CLAIMED',
  'PARTIAL_PERSISTED',
  'PARTIAL_DELIVERED'
);
CREATE TYPE observer_domain AS ENUM ('NODE', 'PLATFORM');
CREATE TYPE observation_parse_result AS ENUM (
  'VERIFIED_GENESIS',
  'VERIFIED_HEAD',
  'TRANSPORT_ERROR',
  'MALFORMED_ENVELOPE',
  'MALFORMED_TRANSACTION',
  'UNVERIFIED_SIGNATURE',
  'WALLET_ROLE_INVALID'
);
CREATE TYPE observation_relationship AS ENUM (
  'FIRST',
  'SUCCESSOR',
  'COMPLETE_PATH_SUCCESSOR',
  'DUPLICATE',
  'EQUIVALENT_STATE_DIFFERENT_ENVELOPE',
  'REGRESSION',
  'UNEXPLAINED_JUMP',
  'GENESIS_AFTER_HISTORY',
  'SIGNATURE_COLLISION',
  'NOT_APPLICABLE'
);
CREATE TYPE verification_verdict AS ENUM (
  'PENDING',
  'VERIFIED',
  'REJECTED',
  'INDETERMINATE'
);

CREATE TYPE lineage_proof_verdict AS ENUM (
  'LANDED_EXACT',
  'LANDED_COMPLETE_PATH',
  'INDETERMINATE',
  'INVARIANT_BREACH'
);
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
```
## 3. Nodes, implementers, and signing keys
```sql
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

CREATE TABLE node_signing_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  purpose text NOT NULL CHECK (purpose IN ('NODE_IDENTITY', 'EVENT_SIGNING')),
  public_key padded_base64url_pubkey NOT NULL,
  vault_secret_ref uuid NOT NULL UNIQUE,
  activated_at timestamptz NOT NULL,
  retired_at timestamptz,
  UNIQUE (node_id, purpose, public_key),
  CHECK (retired_at IS NULL OR retired_at >= activated_at)
);
```
## 4. Wallet custody and destinations
```sql
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  public_key padded_base64url_pubkey NOT NULL,
  key_origin wallet_key_origin NOT NULL,
  state wallet_state NOT NULL DEFAULT 'AVAILABLE',
  recovery_verified_at timestamptz,
  recovery_verification_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  quarantine_reason text,
  UNIQUE (node_id, public_key),
  CHECK ((state = 'QUARANTINED') = (quarantine_reason IS NOT NULL)),
  CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);

CREATE TABLE vault (
  wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
  key_version integer NOT NULL CHECK (key_version > 0),
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  auth_tag bytea NOT NULL,
  ciphertext_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  UNIQUE (key_version, nonce)
);

CREATE TABLE wallet_recovery_verifications (
  id uuid PRIMARY KEY,
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  method text NOT NULL CHECK (method IN ('AUDITED_EXPORT')),
  public_key padded_base64url_pubkey NOT NULL,
  export_sha256 sha256_hex NOT NULL,
  audit_event_id uuid NOT NULL,
  verified_at timestamptz NOT NULL,
  verifier_identity text NOT NULL,
  UNIQUE (wallet_id, export_sha256)
);

ALTER TABLE wallets
  ADD CONSTRAINT wallets_recovery_verification_fk
  FOREIGN KEY (recovery_verification_id)
  REFERENCES wallet_recovery_verifications(id);

CREATE TABLE destinations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  wallet_id uuid NOT NULL UNIQUE REFERENCES wallets(id),
  label text NOT NULL,
  state destination_state NOT NULL DEFAULT 'PENDING',
  blessed_at timestamptz,
  blessed_by_device_key_id uuid,
  blessing_artifact_id uuid,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((state IN ('BLESSED', 'RETIRED')) = (blessed_at IS NOT NULL)),
  CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
```
## 5. Universal wallet-level active-operation lease
```sql
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
  membership_id uuid NOT NULL UNIQUE,
  lease_group_id uuid NOT NULL,
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role wallet_lease_role NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);

CREATE INDEX wallet_active_leases_operation_idx
  ON wallet_active_leases(operation_id);
```
```sql
CREATE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
  destination_row destinations%ROWTYPE;
BEGIN
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id;

  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';
  END IF;

  -- be gated on recovery standing; a quarantined or retired wallet may still be observed.
  IF NEW.lease_role = 'RECONCILIATION' THEN
    RETURN NEW;
  END IF;

  -- custody receive_eligible predicate; key_origin is already proven above. The lease insert
  -- precedes the AVAILABLE -> PINNED transition (operation-flow step 2), so AVAILABLE is the correct
  -- state at BEFORE INSERT time.
  IF NEW.lease_role = 'RECEIVE_WINDOW' THEN
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state IS DISTINCT FROM 'AVAILABLE' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.lease_role = 'MOVE_DESTINATION' THEN
    SELECT * INTO destination_row FROM destinations WHERE wallet_id = NEW.wallet_id;
    IF destination_row.state IS DISTINCT FROM 'BLESSED' THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED';
    END IF;
    IF wallet_row.recovery_verified_at IS NULL THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED';
    END IF;
    IF wallet_row.state NOT IN ('AVAILABLE', 'PINNED') THEN
      RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED';
    END IF;
    RETURN NEW;
  END IF;

  -- coins leave these wallets, they never land.
  IF NEW.lease_role IN ('MOVE_SOURCE', 'SEND_SOURCE') THEN
    RETURN NEW;
  END IF;

  -- Fail closed. A wallet_lease_role member added to the enum without a matching branch here
  RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_active_leases_eligibility_guard
  BEFORE INSERT ON wallet_active_leases
  FOR EACH ROW EXECUTE FUNCTION custody_reject_ineligible_lease();
```
## 6. Operations
```sql
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  kind operation_kind NOT NULL,
  status operation_status NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  attention_required boolean NOT NULL DEFAULT false,
  attention_reason text,
  attention_detail text,
  amount_zkz zkz_amount_positive_text NOT NULL,
  source_wallet_id uuid REFERENCES wallets(id),
  receiver_wallet_id uuid REFERENCES wallets(id),
  destination_id uuid REFERENCES destinations(id),
  destination_address padded_base64url_pubkey,
  after_landing text CHECK (after_landing IN ('HOLD', 'INTERNAL_MOVE')),
  after_landing_destination_id uuid REFERENCES destinations(id),
  spawned_from_operation_id uuid REFERENCES operations(id),
  references_operation_id uuid REFERENCES operations(id),
  discriminator uuid,
  anchor text,
  client_reference text,
  description text,
  idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
  request_sha256 sha256_hex NOT NULL,
  expiry_unix_time_secs text CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),
  t0_observation_id uuid,
  terminal_observation_id uuid,
  formation_state external_formation_state NOT NULL DEFAULT 'NOT_REQUIRED',
  verification_verdict verification_verdict NOT NULL DEFAULT 'PENDING',
  verification_material_available_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  terminal_at timestamptz,
  UNIQUE (implementer_id, kind, idempotency_key),
  UNIQUE (id, node_id, implementer_id),
  CHECK (amount_zkz <> '0'),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL' AND discriminator IS NOT NULL AND anchor IS NOT NULL)
    OR
    (kind <> 'RECEIVE_EXTERNAL'
      AND discriminator IS NULL AND anchor IS NULL AND expiry_unix_time_secs IS NULL)
  ),
  CHECK (
    kind <> 'RECEIVE_EXTERNAL'
    OR (
      status = 'CREATED' AND receiver_wallet_id IS NULL
      AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL
    )
    OR (
      receiver_wallet_id IS NOT NULL
      AND expiry_unix_time_secs IS NOT NULL AND t0_observation_id IS NOT NULL
    )
  ),
  CHECK (kind <> 'RECEIVE_EXTERNAL' OR discriminator = id),
  CHECK (kind <> 'RECEIVE_EXTERNAL' OR anchor ~ '^[A-Za-z0-9_-]{1,96}$'),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL'
      AND source_wallet_id IS NULL AND destination_address IS NULL
      AND after_landing IS NOT NULL
      AND (
        (status = 'CREATED' AND receiver_wallet_id IS NULL)
        OR
        (receiver_wallet_id IS NOT NULL AND discriminator IS NOT NULL AND anchor IS NOT NULL)
      ))
    OR
    (kind = 'MOVE_INTERNAL' AND source_wallet_id IS NOT NULL
      AND destination_id IS NOT NULL AND destination_address IS NULL
      AND receiver_wallet_id IS NULL AND after_landing IS NULL)
    OR
    (kind = 'SEND_EXTERNAL' AND source_wallet_id IS NOT NULL
      AND destination_address IS NOT NULL AND receiver_wallet_id IS NULL
      AND destination_id IS NULL AND after_landing IS NULL)
  ),
  CHECK (
    (after_landing = 'INTERNAL_MOVE' AND after_landing_destination_id IS NOT NULL)
    OR (after_landing IS DISTINCT FROM 'INTERNAL_MOVE' AND after_landing_destination_id IS NULL)
  ),
  CHECK (
    (kind = 'RECEIVE_EXTERNAL' AND status IN
      ('CREATED','READY','RECEIVE_LANDED','EXPIRED'))
    OR
    (kind = 'MOVE_INTERNAL' AND status IN
      ('CREATED','INTERNAL_MOVE_LANDED','NEEDS_ATTENTION'))
    OR
    (kind = 'SEND_EXTERNAL' AND status IN
      ('CREATED','APPROVED','AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED',
       'REJECTED','NEEDS_ATTENTION'))
  ),
  CHECK ((kind = 'SEND_EXTERNAL') = (formation_state <> 'NOT_REQUIRED')),
  CHECK (
    kind <> 'SEND_EXTERNAL'
    OR (status = 'CREATED' AND formation_state = 'APPROVAL_PENDING')
    OR (status = 'APPROVED' AND formation_state IN
      ('APPROVED_UNSIGNED','SIGNING_CLAIMED','PARTIAL_PERSISTED'))
    OR (status IN ('AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED')
      AND formation_state = 'PARTIAL_DELIVERED')
    OR status IN ('REJECTED','NEEDS_ATTENTION')
  ),
  CHECK (attention_required = (attention_reason IS NOT NULL)),
  CHECK (terminal_at IS NULL OR terminal_at >= created_at)
);

CREATE TABLE operation_wallets (
  operation_id uuid NOT NULL REFERENCES operations(id),
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  operation_role text NOT NULL CHECK (operation_role IN ('RECEIVER','SOURCE','DESTINATION')),
  t0_observation_id uuid,
  terminal_observation_id uuid,
  PRIMARY KEY (operation_id, wallet_id),
  UNIQUE (operation_id, operation_role)
);

CREATE TABLE lease_groups (
  id uuid PRIMARY KEY,
  root_operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  created_at timestamptz NOT NULL,
  released_at timestamptz,
  release_proof_id uuid,
  CHECK ((released_at IS NULL) = (release_proof_id IS NULL))
);

CREATE TABLE lease_group_operations (
  lease_group_id uuid NOT NULL REFERENCES lease_groups(id),
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  joined_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (lease_group_id, operation_id),
  CHECK (completed_at IS NULL OR completed_at >= joined_at)
);

CREATE TABLE wallet_lease_memberships (
  id uuid PRIMARY KEY,
  lease_group_id uuid NOT NULL REFERENCES lease_groups(id),
  wallet_id uuid NOT NULL REFERENCES wallets(id),
  operation_id uuid NOT NULL REFERENCES operations(id),
  lease_role wallet_lease_role NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  released_at timestamptz,
  release_reason text,
  release_proof_id uuid,
  UNIQUE (lease_group_id, wallet_id, operation_id, lease_epoch),
  CHECK (
    (released_at IS NULL AND release_reason IS NULL AND release_proof_id IS NULL)
    OR
    (released_at IS NOT NULL AND release_reason IS NOT NULL AND release_proof_id IS NOT NULL)
  )
);

CREATE TABLE operation_observation_bindings (
  operation_id uuid NOT NULL REFERENCES operations(id),
  observation_id uuid NOT NULL,
  evidence_role text NOT NULL CHECK (evidence_role IN (
    'SOURCE_T0','SOURCE_TERMINAL','RECEIVER_T0','RECEIVER_TERMINAL',
    'DESTINATION_T0','DESTINATION_TERMINAL','COUNTERPARTY_CONFIRMATION'
  )),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  PRIMARY KEY (operation_id, evidence_role),
  UNIQUE (operation_id, observation_id)
);

ALTER TABLE wallet_active_leases
  ADD CONSTRAINT wallet_active_leases_membership_fk
    FOREIGN KEY (membership_id) REFERENCES wallet_lease_memberships(id),
  ADD CONSTRAINT wallet_active_leases_group_fk
    FOREIGN KEY (lease_group_id) REFERENCES lease_groups(id),
  ADD CONSTRAINT wallet_active_leases_root_operation_fk
    FOREIGN KEY (root_operation_id) REFERENCES operations(id),
  ADD CONSTRAINT wallet_active_leases_operation_fk
    FOREIGN KEY (operation_id) REFERENCES operations(id);
```
## 7. Exact expected artifacts
```sql
CREATE TABLE operation_expected_artifacts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  purpose text NOT NULL CHECK (purpose IN (
    'zp-receive-expected-v1',
    'zp-move-internal-expected-v1',
    'zp-send-external-expected-v1'
  )),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signature padded_base64url_signature NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(preimage_text) > 0)
);
```
```sql
SELECT signing_key_id AS key_id FROM operation_expected_artifacts;
```
## 7.1 Durable receive material and barriers
```sql
CREATE TABLE receive_codes (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  receiver_wallet_id uuid NOT NULL REFERENCES wallets(id),
  t0_observation_id uuid NOT NULL,
  expected_artifact_id uuid NOT NULL UNIQUE REFERENCES operation_expected_artifacts(id),
  discriminator uuid NOT NULL,
  anchor text NOT NULL CHECK (anchor ~ '^[A-Za-z0-9_-]{1,96}$'),
  expiry_unix_time_secs text NOT NULL CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),
  transfer_code_text text NOT NULL,
  transfer_code_sha256 sha256_hex NOT NULL,
  code_status text NOT NULL CHECK (code_status IN ('AWAITING_ARM','RELEASED','EXPIRED')),
  ready_at timestamptz NOT NULL,
  released_at timestamptz,
  CHECK (code_status <> 'RELEASED' OR released_at IS NOT NULL),
  CHECK (released_at IS NULL OR code_status IN ('RELEASED','EXPIRED'))
);

CREATE TABLE receive_arms (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES receive_codes(operation_id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  route_id text NOT NULL DEFAULT 'operation_armed'
    CHECK (route_id = 'operation_armed'),
  reporting_purpose text NOT NULL DEFAULT 'zp-report-request-v1'
    CHECK (reporting_purpose = 'zp-report-request-v1'),
  request_class reporting_request_class NOT NULL DEFAULT 'MUTATION'
    CHECK (request_class = 'MUTATION'),
  retention_class text NOT NULL DEFAULT 'PERMANENT_MUTATION'
    CHECK (retention_class = 'PERMANENT_MUTATION'),
  method text NOT NULL DEFAULT 'POST' CHECK (method = 'POST'),
  raw_target text NOT NULL,
  node_t0_observation_id uuid NOT NULL,
  acknowledged_s text NOT NULL,
  acknowledged_p text NOT NULL,
  acknowledged_b zkz_balance_text NOT NULL,
  opened_cursor bigint NOT NULL CHECK (opened_cursor >= 0),
  request_body_sha256 sha256_hex NOT NULL,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, request_body_sha256)) STORED,
  reporting_nonce_id uuid NOT NULL UNIQUE,
  mutation_idempotency_id uuid NOT NULL UNIQUE,
  armed_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, route_id, method, raw_target,
    request_body_sha256),
  FOREIGN KEY (operation_id, node_id, implementer_id)
    REFERENCES operations(id, node_id, implementer_id),
  FOREIGN KEY (
    reporting_nonce_id, node_id, implementer_id, reporting_purpose, route_id,
    request_class, retention_class, method, raw_target, request_body_sha256,
    logical_fingerprint
  )
    REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, purpose, route_id, request_class,
       retention_class, method, raw_target, body_sha256, logical_fingerprint),
  FOREIGN KEY (
    mutation_idempotency_id, node_id, implementer_id, route_id, method,
    raw_target, request_body_sha256, logical_fingerprint
  ) REFERENCES reporting_mutation_idempotency
      (id, node_id, implementer_id, route_id, method, raw_target,
       body_sha256, logical_fingerprint)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE receive_release_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  release_kind text NOT NULL CHECK (release_kind IN (
    'VERIFICATION_COMPLETE','EXPIRED_T0_UNCHANGED','EXPIRED_PROVEN_NOT_STARTED')),
  t0_observation_id uuid,
  fresh_observation_id uuid,
  verification_acknowledgement_id uuid,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  released_at timestamptz NOT NULL,
  CHECK (
    (release_kind = 'VERIFICATION_COMPLETE'
      AND verification_acknowledgement_id IS NOT NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_T0_UNCHANGED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NOT NULL AND fresh_observation_id IS NOT NULL)
    OR
    (release_kind = 'EXPIRED_PROVEN_NOT_STARTED'
      AND verification_acknowledgement_id IS NULL
      AND t0_observation_id IS NULL AND fresh_observation_id IS NULL)
  )
);

CREATE TABLE move_observation_evidence (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  source_t0_observation_id uuid NOT NULL,
  destination_t0_observation_id uuid NOT NULL,
  source_terminal_observation_id uuid,
  destination_terminal_observation_id uuid,
  verified_at timestamptz,
  CHECK (
    (source_terminal_observation_id IS NULL
      AND destination_terminal_observation_id IS NULL
      AND verified_at IS NULL)
    OR
    (source_terminal_observation_id IS NOT NULL
      AND destination_terminal_observation_id IS NOT NULL
      AND verified_at IS NOT NULL)
  ),
  CHECK (source_t0_observation_id <> destination_t0_observation_id),
  CHECK (source_terminal_observation_id IS NULL
    OR source_terminal_observation_id <> destination_terminal_observation_id)
);
```
## 8. Device keys and guarded approvals
```sql
CREATE TABLE operator_device_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  public_key padded_base64url_pubkey NOT NULL,
  label text NOT NULL,
  enrolled_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (node_id, public_key)
);

CREATE TABLE approval_challenges (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  operation_id uuid NOT NULL REFERENCES operations(id),
  status approval_challenge_status NOT NULL DEFAULT 'ISSUED',
  purpose text NOT NULL CHECK (purpose = 'zp-send-external-approval-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  nonce uuid NOT NULL UNIQUE,
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  superseded_by uuid REFERENCES approval_challenges(id),
  CHECK (expires_at > issued_at),
  CHECK ((status = 'SUPERSEDED') = (superseded_by IS NOT NULL)),
  UNIQUE (id, node_id, operation_id, status)
);

CREATE UNIQUE INDEX approval_challenges_one_issued_per_operation
  ON approval_challenges(operation_id)
  WHERE status = 'ISSUED';

CREATE TABLE operation_approvals (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  challenge_id uuid UNIQUE,
  challenge_status approval_challenge_status NOT NULL DEFAULT 'CONSUMED'
    CHECK (challenge_status = 'CONSUMED'),
  method approval_method NOT NULL,
  purpose text NOT NULL CHECK (purpose = 'zp-send-external-approval-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  device_key_id uuid REFERENCES operator_device_keys(id),
  device_signature padded_base64url_signature,
  totp_timestep bigint,
  consumed_at timestamptz NOT NULL,
  CHECK (
    (method = 'TOTP_AND_DEVICE'
      AND challenge_id IS NOT NULL
      AND totp_timestep IS NOT NULL
      AND device_key_id IS NOT NULL
      AND device_signature IS NOT NULL)
    OR
    (method = 'TOTP_ONLY'
      AND challenge_id IS NOT NULL
      AND totp_timestep IS NOT NULL
      AND device_key_id IS NULL
      AND device_signature IS NULL)
    OR
    (method = 'AUTO_POLICY'
      AND challenge_id IS NULL
      AND totp_timestep IS NULL
      AND device_key_id IS NULL
      AND device_signature IS NULL)
  ),
  FOREIGN KEY (challenge_id, node_id, operation_id, challenge_status)
    REFERENCES approval_challenges(id, node_id, operation_id, status)
);

CREATE UNIQUE INDEX operation_approvals_totp_single_use
  ON operation_approvals (node_id, totp_timestep)
  WHERE totp_timestep IS NOT NULL;
```
## 9. Exact SplitChain transaction material
```sql
CREATE TABLE external_send_sign_intents (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),
  source_wallet_id uuid NOT NULL REFERENCES wallets(id),
  source_t0_observation_id uuid NOT NULL,
  destination_t0_observation_id uuid NOT NULL,
  lease_group_id uuid NOT NULL,
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  redemption_expiry_at timestamptz NOT NULL,
  prepared_at timestamptz NOT NULL,
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no = 1),
  attempt_phase text NOT NULL CHECK (attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED',
     'STEP2_PREIMAGE_PERSISTED','STEP2_SIGNATURE_PERSISTED',
     'SETTLED_BODY_PERSISTED')),
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature,
  step_2_preimage_text text,
  step_2_preimage_sha256 sha256_hex,
  step_2_signature padded_base64url_signature,
  completed_transaction_text text,
  completed_transaction_sha256 sha256_hex,
  formed_at timestamptz NOT NULL,
  settled_at timestamptz,
  PRIMARY KEY (operation_id, attempt_no),
  CHECK ((attempt_phase = 'INNER_PREIMAGE_PERSISTED') = (step_1_signature IS NULL)),
  CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =
    (step_2_preimage_text IS NULL)),
  CHECK ((attempt_phase IN ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED')) =
    (step_2_preimage_sha256 IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (step_2_signature IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (completed_transaction_text IS NULL)),
  CHECK ((attempt_phase IN
    ('INNER_PREIMAGE_PERSISTED','STEP1_SIGNATURE_PERSISTED','STEP2_PREIMAGE_PERSISTED')) =
    (completed_transaction_sha256 IS NULL)),
  CHECK ((attempt_phase <> 'SETTLED_BODY_PERSISTED') = (settled_at IS NULL))
);

CREATE TABLE external_send_partials (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  approval_id uuid NOT NULL UNIQUE REFERENCES operation_approvals(id),
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  transfer_code_text text NOT NULL,
  transfer_code_sha256 sha256_hex NOT NULL,
  persisted_at timestamptz NOT NULL,
  first_delivered_at timestamptz,
  last_redelivered_at timestamptz,
  redelivery_count integer NOT NULL DEFAULT 0 CHECK (redelivery_count >= 0)
);
```
| Public `execution_phase` | Required durable fact |
|---|---|
| `LANDED_VERIFIED` | accepted operation verification plus required terminal observation references |
| `SUBMIT_RETURNED` | the one submit attempt has `completed_at` and a captured outcome |
| `SUBMIT_STARTED` | the one submit-attempt claim has `started_at` |
| `DELIVERED` | external partial `first_delivered_at IS NOT NULL` |
| `SIGNED_PERSISTED` | RECEIVE is at `STEP2_SIGNATURE_PERSISTED` or later; MOVE is at `STEP1_SIGNATURE_PERSISTED` or later, including `STEP2_PREIMAGE_PERSISTED` and `STEP2_SIGNATURE_PERSISTED`; SEND has its external partial/node step-1 signature durable |
| `PREIMAGE_PERSISTED` | RECEIVE is at `STEP2_PREIMAGE_PERSISTED` with the payer step 1 durable and node step 2 NULL; MOVE is at `INNER_PREIMAGE_PERSISTED` with node step 1 NULL; SEND has the sign intent durable and no external partial/node step-1 signature |
| `NOT_STARTED` | none of the above exists |
## 10. Submit attempts and retry authority
```sql
CREATE TABLE submit_decisions (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  transaction_attempt_no integer NOT NULL CHECK (transaction_attempt_no = 1),
  decision text NOT NULL CHECK (decision = 'INITIAL_SINGLE_SHOT'),
  decided_at timestamptz NOT NULL,
  details text NOT NULL,
  UNIQUE (id, operation_id, transaction_attempt_no),
  UNIQUE (operation_id, transaction_attempt_no),
  FOREIGN KEY (operation_id, transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no)
);

CREATE TABLE gateway_submit_attempts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no > 0),
  transaction_attempt_no integer NOT NULL CHECK (transaction_attempt_no > 0),
  decision_id uuid NOT NULL UNIQUE,
  request_body bytea NOT NULL,
  request_sha256 sha256_hex NOT NULL,
  response_body bytea,
  response_sha256 sha256_hex,
  transport_outcome text NOT NULL CHECK (transport_outcome IN
    ('ACK','REJECT','INDETERMINATE')),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE (operation_id, attempt_no),
  UNIQUE (operation_id, transaction_attempt_no),
  FOREIGN KEY (decision_id, operation_id, transaction_attempt_no)
    REFERENCES submit_decisions(id, operation_id, transaction_attempt_no),
  FOREIGN KEY (operation_id, transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no),
  CHECK ((response_body IS NULL) = (response_sha256 IS NULL))
);
```
## 11. Independent raw observation ledger
```sql
CREATE TABLE observers (
  id uuid PRIMARY KEY,
  domain observer_domain NOT NULL,
  owner_id uuid NOT NULL,
  gateway_endpoint_fingerprint sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (domain, owner_id)
);

CREATE TABLE gateway_observations (
  id uuid PRIMARY KEY,
  observer_id uuid NOT NULL REFERENCES observers(id),
  endpoint_fingerprint sha256_hex NOT NULL,
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  wallet_seq bigint NOT NULL CHECK (wallet_seq > 0),
  observed_at timestamptz NOT NULL,
  http_status integer,
  raw_response_bytes bytea NOT NULL,
  raw_response_sha256 sha256_hex NOT NULL,
  parse_result observation_parse_result NOT NULL,
  relationship observation_relationship NOT NULL,
  semantic_fingerprint sha256_hex,
  state_changed boolean,
  wallet_role text CHECK (wallet_role IN ('sender','receiver','genesis')),
  s_signature text,
  p_signature text,
  b_amount zkz_balance_text,
  inner_preimage_text text,
  step_1_signature text,
  step_2_signature text,
  completed_transaction_text text,
  completed_transaction_sha256 sha256_hex,
  previous_recorded_observation_id uuid REFERENCES gateway_observations(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (observer_id, wallet_public_key, wallet_seq),
  CHECK (
    (parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')) =
    (semantic_fingerprint IS NOT NULL)
  ),
  CHECK (
    (parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')) =
    (state_changed IS NOT NULL)
  ),
  CHECK (
    (parse_result = 'VERIFIED_HEAD') =
    (inner_preimage_text IS NOT NULL AND step_1_signature IS NOT NULL
      AND step_2_signature IS NOT NULL AND completed_transaction_text IS NOT NULL
      AND completed_transaction_sha256 IS NOT NULL)
  ),
  CHECK (
    parse_result <> 'VERIFIED_GENESIS'
    OR (
      wallet_role = 'genesis' AND s_signature = '' AND p_signature = '' AND b_amount = '0'
      AND inner_preimage_text IS NULL AND step_1_signature IS NULL AND step_2_signature IS NULL
      AND completed_transaction_text IS NULL AND completed_transaction_sha256 IS NULL
    )
  ),
  CHECK (
    parse_result <> 'VERIFIED_HEAD'
    OR (
      wallet_role IN ('sender','receiver')
      AND s_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$')
      AND b_amount IS NOT NULL AND octet_length(inner_preimage_text) > 0
      AND step_1_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND step_2_signature ~ '^[A-Za-z0-9_-]{86}==$'
      AND octet_length(completed_transaction_text) > 0
    )
  ),
  CHECK (
    parse_result IN ('VERIFIED_GENESIS','VERIFIED_HEAD')
    OR (
      relationship = 'NOT_APPLICABLE' AND wallet_role IS NULL
      AND s_signature IS NULL AND p_signature IS NULL AND b_amount IS NULL
      AND inner_preimage_text IS NULL AND step_1_signature IS NULL AND step_2_signature IS NULL
      AND completed_transaction_text IS NULL AND completed_transaction_sha256 IS NULL
    )
  )
);

CREATE TABLE wallet_observation_cursors (
  observer_id uuid NOT NULL REFERENCES observers(id),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  last_recorded_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  last_raw_response_sha256 sha256_hex NOT NULL,
  last_semantic_fingerprint sha256_hex,
  last_seen_at timestamptz NOT NULL,
  consecutive_repeat_count bigint NOT NULL DEFAULT 0 CHECK (consecutive_repeat_count >= 0),
  next_wallet_seq bigint NOT NULL CHECK (next_wallet_seq > 0),
  PRIMARY KEY (observer_id, wallet_public_key)
);

CREATE TABLE observation_anomalies (
  id uuid PRIMARY KEY,
  observation_id uuid NOT NULL UNIQUE REFERENCES gateway_observations(id),
  observer_id uuid NOT NULL REFERENCES observers(id),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  kind text NOT NULL CHECK (kind IN (
    'TRANSPORT_ERROR','MALFORMED_ENVELOPE','MALFORMED_TRANSACTION',
    'UNVERIFIED_SIGNATURE','WALLET_ROLE_INVALID','REGRESSION',
    'UNEXPLAINED_JUMP','GENESIS_AFTER_HISTORY','SIGNATURE_COLLISION'
  )),
  prior_observation_id uuid REFERENCES gateway_observations(id),
  details text NOT NULL,
  detected_at timestamptz NOT NULL
);

CREATE TABLE operation_landing_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  verifier_observer_id uuid NOT NULL REFERENCES observers(id),
  expected_transaction_attempt_no integer NOT NULL CHECK (expected_transaction_attempt_no = 1),
  verdict lineage_proof_verdict NOT NULL,
  required_path_count integer NOT NULL CHECK (required_path_count IN (1,2)),
  declared_body_count bigint NOT NULL CHECK (declared_body_count > 0),
  declared_total_body_bytes bigint NOT NULL CHECK (declared_total_body_bytes > 0),
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (id, operation_id, verifier_observer_id),
  FOREIGN KEY (operation_id, expected_transaction_attempt_no)
    REFERENCES operation_transactions(operation_id, attempt_no),
  CHECK ((verdict IN ('LANDED_EXACT','LANDED_COMPLETE_PATH')) = (verified_at IS NOT NULL))
);

CREATE TABLE lineage_path_proofs (
  id uuid PRIMARY KEY,
  landing_proof_id uuid NOT NULL REFERENCES operation_landing_proofs(id),
  path_role text NOT NULL CHECK (path_role IN ('RECEIVER','SOURCE','DESTINATION')),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  fresh_head_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  expected_completed_transaction_sha256 sha256_hex NOT NULL,
  fresh_head_completed_transaction_sha256 sha256_hex NOT NULL,
  body_count bigint NOT NULL CHECK (body_count > 0),
  path_depth bigint NOT NULL CHECK (path_depth >= 0 AND path_depth = body_count - 1),
  verdict lineage_proof_verdict NOT NULL,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (landing_proof_id, path_role),
  UNIQUE (landing_proof_id, wallet_public_key)
);

CREATE TABLE lineage_path_bodies (
  path_proof_id uuid NOT NULL REFERENCES lineage_path_proofs(id),
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind IN
    ('EXPECTED_OPERATION','CANONICAL_LEDGER','PROOF_CHANNEL','FRESH_GATEWAY_HEAD')),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 sha256_hex NOT NULL,
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender','receiver')),
  s_signature padded_base64url_signature NOT NULL,
  p_signature text NOT NULL CHECK
    (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  b_amount zkz_balance_text NOT NULL,
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  step_2_signature padded_base64url_signature NOT NULL,
  verification_manifest_text text NOT NULL,
  verification_manifest_sha256 sha256_hex NOT NULL,
  PRIMARY KEY (path_proof_id, path_index),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets),
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE INDEX lineage_path_bodies_state_signature_idx
  ON lineage_path_bodies(path_proof_id, s_signature);
CREATE INDEX lineage_path_bodies_backlink_idx
  ON lineage_path_bodies(path_proof_id, p_signature);
CREATE INDEX lineage_path_bodies_body_digest_idx
  ON lineage_path_bodies(completed_transaction_sha256);
CREATE INDEX lineage_path_proofs_fresh_head_idx
  ON lineage_path_proofs(fresh_head_observation_id);

CREATE TABLE observation_relationship_adjudications (
  id uuid PRIMARY KEY,
  observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  lineage_path_proof_id uuid NOT NULL UNIQUE REFERENCES lineage_path_proofs(id),
  observed_relationship observation_relationship NOT NULL
    CHECK (observed_relationship = 'UNEXPLAINED_JUMP'),
  effective_relationship observation_relationship NOT NULL
    CHECK (effective_relationship = 'COMPLETE_PATH_SUCCESSOR'),
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  adjudicated_at timestamptz NOT NULL,
  UNIQUE (observation_id, lineage_path_proof_id)
);
```
```sql
ALTER TABLE operations
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (terminal_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE operation_wallets
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (terminal_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE operation_observation_bindings
  ADD FOREIGN KEY (observation_id) REFERENCES gateway_observations(id);
ALTER TABLE external_send_sign_intents
  ADD FOREIGN KEY (source_t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (destination_t0_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE receive_codes
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE receive_arms
  ADD FOREIGN KEY (node_t0_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE receive_release_proofs
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (fresh_observation_id) REFERENCES gateway_observations(id);
ALTER TABLE move_observation_evidence
  ADD FOREIGN KEY (source_t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (destination_t0_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (source_terminal_observation_id) REFERENCES gateway_observations(id),
  ADD FOREIGN KEY (destination_terminal_observation_id) REFERENCES gateway_observations(id);
```
## 11.1 PROOF_CHANNEL candidate proof-body intake store
```sql
CREATE TABLE proof_channel_candidate_bodies (
  path_proof_id uuid NOT NULL,
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind = 'PROOF_CHANNEL'),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 sha256_hex NOT NULL,
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender','receiver')),
  s_signature padded_base64url_signature NOT NULL,
  p_signature text NOT NULL CHECK
    (p_signature = '' OR p_signature ~ '^[A-Za-z0-9_-]{86}==$'),
  b_amount zkz_balance_text NOT NULL,
  inner_preimage_text text NOT NULL,
  inner_sha256 sha256_hex NOT NULL,
  step_1_signature padded_base64url_signature NOT NULL,
  step_2_signature padded_base64url_signature NOT NULL,
  verification_manifest_text text NOT NULL,
  verification_manifest_sha256 sha256_hex NOT NULL,
  raw_bytes_sha256 sha256_hex NOT NULL,
  tenant_id text NOT NULL,
  operation_id text NOT NULL,
  idempotency_key text NOT NULL,
  persisted_at timestamptz NOT NULL,
  PRIMARY KEY (path_proof_id, path_index),
  CONSTRAINT proof_channel_candidate_bodies_tenant_op_idem_key
    UNIQUE (tenant_id, operation_id, idempotency_key),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets),
  CHECK (octet_length(inner_preimage_text) > 0)
);

CREATE INDEX proof_channel_candidate_bodies_operation_path_idx
  ON proof_channel_candidate_bodies(operation_id, path_index);
CREATE INDEX proof_channel_candidate_bodies_tenant_idx
  ON proof_channel_candidate_bodies(tenant_id);
CREATE INDEX proof_channel_candidate_bodies_tenant_role_idx
  ON proof_channel_candidate_bodies(tenant_id, wallet_role);
CREATE INDEX proof_channel_candidate_bodies_body_digest_idx
  ON proof_channel_candidate_bodies(raw_bytes_sha256);

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER proof_channel_candidate_bodies_no_update
  BEFORE UPDATE ON proof_channel_candidate_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER proof_channel_candidate_bodies_no_delete
  BEFORE DELETE ON proof_channel_candidate_bodies
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER proof_channel_candidate_bodies_no_truncate
  BEFORE TRUNCATE ON proof_channel_candidate_bodies
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TABLE proof_body_slot_sighting_counters (
  path_proof_id uuid NOT NULL,
  path_index bigint NOT NULL CHECK (path_index >= 0),
  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),
  PRIMARY KEY (path_proof_id, path_index)
);

CREATE TABLE proof_body_tenant_sighting_counters (
  tenant_id text NOT NULL,
  sighting_count bigint NOT NULL DEFAULT 0 CHECK (sighting_count >= 0),
  PRIMARY KEY (tenant_id)
);
```
### Identity binding
### Idempotency
### Deduplication, collision quarantine, and role conflict
### Bounded persistence quotas
### Live-database obligations
## 12. Operation verification and acknowledgements
```sql
CREATE TABLE operation_verifications (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  verifier_observer_id uuid NOT NULL REFERENCES observers(id),
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  terminal_observation_id uuid REFERENCES gateway_observations(id),
  landing_proof_id uuid,
  verdict verification_verdict NOT NULL,
  reason_code text NOT NULL,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (operation_id, verifier_observer_id, t0_observation_id, terminal_observation_id),
  FOREIGN KEY (landing_proof_id, operation_id, verifier_observer_id)
    REFERENCES operation_landing_proofs(id, operation_id, verifier_observer_id),
  CHECK (verdict <> 'VERIFIED' OR landing_proof_id IS NOT NULL)
);

CREATE TABLE verification_acknowledgements (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  route_id text NOT NULL DEFAULT 'verification_complete'
    CHECK (route_id = 'verification_complete'),
  reporting_purpose text NOT NULL DEFAULT 'zp-report-request-v1'
    CHECK (reporting_purpose = 'zp-report-request-v1'),
  request_class reporting_request_class NOT NULL DEFAULT 'MUTATION'
    CHECK (request_class = 'MUTATION'),
  retention_class text NOT NULL DEFAULT 'PERMANENT_MUTATION'
    CHECK (retention_class = 'PERMANENT_MUTATION'),
  method text NOT NULL DEFAULT 'POST' CHECK (method = 'POST'),
  raw_target text NOT NULL,
  consumed_cursor bigint NOT NULL CHECK (consumed_cursor >= 0),
  verdict verification_verdict NOT NULL CHECK (verdict <> 'PENDING'),
  evidence_set_sha256 sha256_hex NOT NULL,
  request_body_sha256 sha256_hex NOT NULL,
  logical_fingerprint sha256_hex GENERATED ALWAYS AS
    (reporting_logical_fingerprint(method, raw_target, request_body_sha256)) STORED,
  reporting_nonce_id uuid NOT NULL UNIQUE,
  mutation_idempotency_id uuid NOT NULL UNIQUE,
  acknowledged_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (node_id, implementer_id, route_id, method, raw_target,
    request_body_sha256),
  FOREIGN KEY (operation_id, node_id, implementer_id)
    REFERENCES operations(id, node_id, implementer_id),
  FOREIGN KEY (
    reporting_nonce_id, node_id, implementer_id, reporting_purpose, route_id,
    request_class, retention_class, method, raw_target, request_body_sha256,
    logical_fingerprint
  )
    REFERENCES reporting_request_nonces
      (id, node_id, implementer_id, purpose, route_id, request_class,
       retention_class, method, raw_target, body_sha256, logical_fingerprint),
  FOREIGN KEY (
    mutation_idempotency_id, node_id, implementer_id, route_id, method,
    raw_target, request_body_sha256, logical_fingerprint
  ) REFERENCES reporting_mutation_idempotency
      (id, node_id, implementer_id, route_id, method, raw_target,
       body_sha256, logical_fingerprint)
    DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION reporting_assert_completed_mutation(p_idempotency_id uuid)
RETURNS void LANGUAGE plpgsql
AS $$
DECLARE
  p reporting_mutation_idempotency%ROWTYPE;
  matching_children integer;
BEGIN
  SELECT * INTO STRICT p
    FROM reporting_mutation_idempotency
    WHERE id = p_idempotency_id;

  CASE p.route_id
    WHEN 'operation_armed' THEN
      SELECT count(*) INTO matching_children
      FROM receive_arms a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    WHEN 'verification_complete' THEN
      SELECT count(*) INTO matching_children
      FROM verification_acknowledgements a
      WHERE a.id = p.child_record_id
        AND a.mutation_idempotency_id = p.id
        AND a.reporting_nonce_id = p.reporting_nonce_id
        AND a.node_id = p.node_id
        AND a.implementer_id = p.implementer_id
        AND a.route_id = p.route_id
        AND a.method = p.method
        AND a.raw_target = p.raw_target
        AND a.request_body_sha256 = p.body_sha256
        AND a.logical_fingerprint = p.logical_fingerprint;
    ELSE
      RAISE EXCEPTION 'unsupported completed reporting mutation route %', p.route_id
        USING ERRCODE = '23514';
  END CASE;

  IF matching_children <> 1 THEN
    RAISE EXCEPTION 'completed idempotency/child correlation is incomplete'
      USING ERRCODE = '23514';
  END IF;
END
$$;

CREATE FUNCTION reporting_validate_mutation_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  parent_id uuid;
BEGIN
  parent_id := CASE TG_TABLE_NAME
    WHEN 'reporting_mutation_idempotency' THEN NEW.id
    ELSE NEW.mutation_idempotency_id
  END;
  PERFORM reporting_assert_completed_mutation(parent_id);
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER reporting_completed_parent_has_child
  AFTER INSERT ON reporting_mutation_idempotency
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_arm_has_completed_parent
  AFTER INSERT ON receive_arms
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();
CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent
  AFTER INSERT ON verification_acknowledgements
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION reporting_validate_mutation_deferred();

CREATE TRIGGER reporting_arms_immutable
  BEFORE UPDATE OR DELETE ON receive_arms
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_acks_immutable
  BEFORE UPDATE OR DELETE ON verification_acknowledgements
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_arms_no_truncate
  BEFORE TRUNCATE ON receive_arms
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER reporting_acks_no_truncate
  BEFORE TRUNCATE ON verification_acknowledgements
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();

REVOKE UPDATE, DELETE, TRUNCATE ON receive_arms,
  verification_acknowledgements FROM node_runtime;

CREATE TABLE verification_ack_wallet_evidence (
  acknowledgement_id uuid NOT NULL REFERENCES verification_acknowledgements(id),
  evidence_role text NOT NULL CHECK (evidence_role IN
    ('SOURCE','RECEIVER','DESTINATION')),
  wallet_id uuid REFERENCES wallets(id),
  wallet_public_key padded_base64url_pubkey NOT NULL,
  t0_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  terminal_observation_id uuid NOT NULL REFERENCES gateway_observations(id),
  PRIMARY KEY (acknowledgement_id, evidence_role),
  UNIQUE (acknowledgement_id, wallet_public_key)
);

ALTER TABLE receive_release_proofs
  ADD FOREIGN KEY (verification_acknowledgement_id)
    REFERENCES verification_acknowledgements(id);
```
## 13. Durable neutral event stream
```sql
CREATE TABLE node_event_seq_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)
);

CREATE TABLE node_events (
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
```
## 13.1 Implementer-scoped continuity stream (dual continuity)
## 14. Audit log
```sql
CREATE TABLE audit_log (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL REFERENCES nodes(id),
  actor_kind text NOT NULL CHECK (actor_kind IN
    ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),
  actor_id text,
  action text NOT NULL,
  operation_id uuid REFERENCES operations(id),
  wallet_id uuid REFERENCES wallets(id),
  details_text text NOT NULL,
  details_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (id, node_id)
);

ALTER TABLE reporting_key_bootstrap_evidence
  ADD FOREIGN KEY (operator_approval_audit_id, node_id)
    REFERENCES audit_log(id, node_id);
```
## 15. Retention and mutability matrix
## 16. Mandatory database tests
## 17. Push subscriptions (node-local, per-wallet)
```sql
-- One Web Push subscription per wallet. The private ECDH half and the auth secret are
-- sealed envelopes (vault root, same seal the wallet secrets use); no plaintext key
-- material is ever stored in this table and no read path returns the sealed text outside
-- the vault seam.
--
-- `status` starts FAILED on insert and only becomes ACTIVE once the push service has
-- acknowledged the subscribe. That ordering is deliberate: a crash between INSERT and the
-- gateway ack must never leave a row asserting a remote subscription that does not exist,
-- because the external-operation gate trusts this column.
CREATE TABLE push_subscriptions (
  wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
  node_id uuid NOT NULL,
  wallet_public_key padded_base64url_pubkey NOT NULL,

  -- handed to the third-party push service.
  endpoint_id text NOT NULL CHECK (endpoint_id ~ '^wp_[A-Za-z0-9_-]{20,64}$'),

  -- Non-secret: the subscription's `p256dh` value, published to the push service.
  receiver_ecdh_public text NOT NULL,

  receiver_ecdh_private_sealed text NOT NULL,
  receiver_auth_secret_sealed text NOT NULL,

  status text NOT NULL CHECK (status IN ('ACTIVE','FAILED')),

  -- NOT strictly urlsafe despite the field name — decode tolerantly, so no domain here.
  app_server_public_key text,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- Set only on a successful subscribe; NULL means "never yet acknowledged".
  subscribed_at timestamptz,

  CHECK ((status = 'ACTIVE') = (subscribed_at IS NOT NULL)),
  UNIQUE (wallet_id, node_id)
);

-- The inbound receiver resolves an endpoint token to its subscription on every delivery,
-- so this lookup is on the hot path. Unique because two wallets sharing a token would
-- make the inbound decrypt ambiguous.
CREATE UNIQUE INDEX push_subscriptions_by_endpoint
  ON push_subscriptions (endpoint_id);

-- The boot reconcile and the periodic sweep scan for wallets whose subscription is not
-- ACTIVE; this keeps that pass from degrading into a full table scan as the pool grows.
CREATE INDEX push_subscriptions_by_status
  ON push_subscriptions (node_id, status);
```
