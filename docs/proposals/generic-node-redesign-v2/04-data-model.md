# Data Model

**Status:** `RATIFIED — IMPLEMENTATION OPEN (D9.22); greenfield initial schema, see 00-ratification-gate.md`

This document defines the persistence contract for the generic node and the corresponding independent
platform observation store. It is a greenfield schema, not a migration plan. Canonical authority remains
[`../../DECISIONS.md`](../../DECISIONS.md).

Exact bytes are authoritative. Parsed fields exist for constraints and indexes; they never replace the
exact preimage, transaction, event, artifact, or gateway-response bytes from which they were derived.

## 1. Database-wide conventions

- PostgreSQL is the required reference database.
- All operation, wallet, destination, observation, artifact, approval, and event identifiers are `uuid`.
- Ordered stream positions and event sequence numbers are `bigint`.
- Timestamps are `timestamptz`, stored in UTC. Timestamps are not used as uniqueness or ordering keys.
- ZKZ amounts are canonical decimal `text`; no money-path column is `real`, `double precision`, or a
  JavaScript-number-derived `numeric`.
- Exact SplitChain and canonical-suite preimages are `text` because they must be valid UTF-8.
- Complete gateway bodies are `bytea` because an invalid UTF-8 response is still evidence.
- Exact-content tables are append-only or have byte-immutability triggers.
- Foreign keys are immediate unless the schema below explicitly says otherwise.
- Application code uses transactions for every status transition, event append, lease change, TOTP burn,
  and signature persistence described as atomic.

Reference scalar checks:

```sql
-- CANONICAL OVERRIDE (DEC D9.10). The draft single unbounded zkz_amount_text is retired.
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

The regexes are a first boundary only. Runtime validation MUST decode, length-check, canonically re-encode,
and compare the public key or signature. Database insertion is not proof of valid Ed25519 material.

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
CREATE TYPE approval_method AS ENUM ('TOTP_ONLY', 'TOTP_AND_DEVICE');
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

The state/event transition table is closed in
[`appendices/B-state-event-reference.md`](appendices/B-state-event-reference.md). Adding an enum value is a
contract-version change, not an application-local migration.

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

`implementer_reporting_keys` is an immutable identity table with exactly the allowlisted fields `id`,
`node_id`, `implementer_id`, `public_key`, and `registered_at`. Reporting persistence defines no private-key,
seed, secret, encrypted-secret, or vault-reference field. A first-key enrolment is distinguished
structurally from rotation: only `reporting_key_bootstrap_evidence` carries the D9.19/ZTR-411 three-gate
facts (authenticated onboarding with `implementer_id` derived from the caller, explicit node-origin
operator approval, and proof of possession). The register nonce and its exact preimage identify
`new_reporting_key_id`. The bootstrap composite foreign key binds the same nonce, tenant, purpose, new key,
ceremony evidence, exact preimage text/digest/signature, issuance, and expiry to enrolment. The rotation
composite foreign key binds those same exact fields while requiring `authorizing_key_id` to equal its
non-null `supersedes_key_id` and the nonce's `reporting_key_id`; rotation cannot carry bootstrap evidence.
Both register evidence forms expire no later than 300 seconds after issuance. Rotation and revocation
therefore remain existing-key anchored without importing bootstrap-only operator/onboarding requirements.

There is exactly one `reporting_key_lifecycle_heads` row per `(node_id, implementer_id)`. It carries the
epoch, current and optional prior key IDs, strict half-open overlap expiry, and `auth_hold`. Before first
bootstrap it is the sole epoch-zero held row with no keys or cited event; this is the row the three-gate
ceremony locks before admitting its register nonce and first activation event. Every positive-epoch head
uses one composite foreign key to the cited event's ID, tenant, epoch, current key, prior key, overlap, and
hold value. The event is therefore the full resulting head projection, not a partial narrative.

Key identity and state history are separate: the immutable five-field identity row is paired with
append-only `reporting_key_lifecycle_states` versions. Event type and key state are closed enums. The only
key-state edges are `PENDING -> ACTIVE`, `ACTIVE -> RETIRED`, and `ACTIVE -> REVOKED`; an insert-only
transition row binds its exact from/to state rows to the legal event type. The deferred constraint triggers
defined above require the event-specific edge count, require every event-bound state row to have its edge,
and reject any edge that does not start from the latest prior state. `RETIRED` and `REVOKED` therefore have
no possible outgoing edge and cannot reactivate. Events, transitions, and state versions reject
update/delete/truncate; the guarded `reporting_advance_lifecycle_head` function is the only runtime path
that advances the mutable head projection.

Admit, rotate, and revoke lock and recheck the same head; the first valid commit wins. Every transition
appends one permanent event unique by `(node_id, implementer_id, epoch)` before advancing the head. Each
event composite-references its exact predecessor ID, epoch, and hash; epoch one has no predecessor and is
only `FIRST_KEY_ACTIVATED`, which clears the epoch-zero head hold. Later hold release is possible only
through an explicit `AUTH_HOLD_RELEASED` event. First
activation and rotation events cite only a `zp-reporting-register-v1` nonce and matching enrolment;
retirement, revocation, and hold events cite only a `zp-report-request-v1` lifecycle request. A rotation
event binds the successor identity's `registered_at` to its `committed_at` and requires
`overlap_expires_at = committed_at + interval '24 hours'`. A rotation is rejected while the predecessor
event still has any prior key in its active overlap slot. The prior key is eligible from successor commit
inclusive until that timestamp exclusive, exactly 24 hours under D9.19.

`reporting_request_nonces` is the one replay ledger for both `zp-reporting-register-v1` and
`zp-report-request-v1`. Its unique key is exactly `(node_id, implementer_id, nonce)`; purpose, route, and key
are immutable evidence and never expand replay scope. A null `reporting_key_id` is legal only for a
bootstrap register burn carrying an explicit tenant-bound `bootstrap_evidence_id`; existing-key register
and request burns require their authorizing reporting key. Each burn also retains lifecycle epoch, node-wide
burn sequence, exact preimage and digest, signature, signed times, receipt/consumption times, retention
class, and, where applicable, method, opaque exact raw target, exact-body digest, and their logical
fingerprint. Request evidence expires no later than 60 seconds after issuance. `raw_target` is never decoded,
normalized, reordered, or reconstructed. A request classified as a mutation can carry only
`PERMANENT_MUTATION`; a read can carry only `READ_NO_PRUNE_UNTIL_SAFETY_FREEZE`.
`reporting_nonce_burn_counters` supplies the durable node-wide high-water compared during restore.

After bounded shape/time/size/rate checks, the node validates tenant/key binding, lifecycle eligibility,
and signature without holding either authorization row. It then invokes the actual security-definer
`reporting_lock_and_assert_admission` function in a separate short transaction. That function locks
`reporting_restore_state` followed by the shared lifecycle head and requires `restore_hold=false`,
`auth_hold=false`, the exact epoch, and an ACTIVE current key or unexpired ACTIVE prior key. The transaction
then allocates the burn sequence, inserts the nonce evidence, and commits. Invalid authentication inserts
nothing; every later authenticated 404/409/500,
handler failure, crash, or response loss retains the burn. After that commit, a completed idempotency record
is resolved first: exact replay or fingerprint conflict returns before any mutable protected-object lookup.
Only a missing idempotency record proceeds to tenant-scoped lookup and the guarded handler.

Mutation replay remains separate under exactly
`UNIQUE (node_id, implementer_id, route_id, idempotency_key)`. Keys are 16–255 visible ASCII bytes. The
logical fingerprint is a generated audit value over the frozen byte-length-prefixed method, opaque exact
`raw_target`, and `body_sha256` derivation above; callers never supply it. Nonce, key, lifecycle epoch,
times, and the unsigned idempotency header are excluded. The nonce, completed idempotency record, and
guarded child row composite-bind identical method, raw target, body digest, and derived fingerprint. For
`operation_armed` and `verification_complete`, the partial unique index uses the actual method, raw target,
and body digest columns, so changing only the unsigned header or a caller-claimed digest cannot execute the
mutation twice.

Every persisted `reporting_mutation_idempotency` row is completed and names its `reporting_nonce_id`,
route-specific `child_record_id`, status, exact `response_bytes`, and completion time at insert. No durable
pending/placeholder row exists. The actual deferred parent/child constraint triggers query the correct arm
or acknowledgement table and require exact bidirectional ID, tenant, route, nonce, method, raw target, body
digest, and fingerprint correlation at commit. The guarded child and completed parent therefore appear
together or neither commits. Actual immutable triggers reject update/delete, truncate is trigger-blocked
and privilege-revoked, and permanent mutation nonce burns have the same protection. Replay is unchanged
across fresh nonces or key rotation.

`reporting_restore_state` enters with `restore_hold=true` and every lifecycle head enters with
`auth_hold=true`. Local lifecycle epoch, nonce-burn high-water, and terminal lifecycle-event hash are
compared with the three corresponding markers loaded from a separately trusted external source; the source
and its markers may be absent and that absence stays held. Release requires exact equality for all three,
plus explicit external reconciliation evidence and release time. Regression, advancement beyond the
trusted marker, or either event-hash mismatch stays held. A local database comparison cannot create
authority, automatic release is forbidden, and clearing one hold never clears or bypasses the other.
Restore and retention rules are
in [09-operations-recovery.md](09-operations-recovery.md) §7.1; request and replay ordering are in
[05-api-contract.md](05-api-contract.md) §§1 and 2.2 and
[07-signing-custody-security.md](07-signing-custody-security.md) §4.1.

Only public material appears in the relational reporting identity/evidence tables. `vault_secret_ref`
resolves only inside the node vault for node-owned signing keys; no platform table has an equivalent
private-key reference.

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

The `vault` table follows the D8.7 names (`vault`, PK `wallet_id`, `key_version`) as kept by **D9.11**,
which resolves the v2 model to per-wallet AES-256-GCM envelope rows (D6.1's single-vault-row model stays
canonical and unchanged for v1; no node mixes the two). There is deliberately **no stored AAD column**: the
authenticated associated data is the six-field set reconstructed at open — `zp-wallet-secret-v1`, `node_id`,
`wallet_id`, `key_version`, `public_key`, `key_origin` (see
[`07-signing-custody-security.md`](07-signing-custody-security.md) §5.1) — never persisted, so a row cannot
carry an AAD that disagrees with its authoritative columns. `UNIQUE (key_version, nonce)` is the structural
nonce-reuse guard. Exact column types, the sealing/signer API, and the AAD byte serialization are frozen by
GN-011.2; this schema fixes the D9.11 names and the no-stored-AAD decision only. (This supersedes the earlier
draft's `wallet_secrets`/`vault_key_version`/`aad_text` shape.)

The `wallet_recovery_verifications` table is the evidence row written by the GN-014 backup and
recovery-verification ceremony: `method` is fixed to `AUDITED_EXPORT`, `export_sha256` is the per-wallet
export digest recomputed from the archive bytes, and `UNIQUE (wallet_id, export_sha256)` is the per-wallet
idempotency bar. Its shape and semantics are frozen by **D9.35** (backup archive envelope and coverage) and
**D9.37** (restore and recovery-verification ceremony); the row is the evidence behind the **D9.17** recovery
gate, and the ceremony is the sole writer of `wallets.recovery_verified_at`/`recovery_verification_id`
(predicate 5 below; [`07-signing-custody-security.md`](07-signing-custody-security.md) §5.5).

`destinations.label` is the operator-facing display name
[05-api-contract.md §7.1](05-api-contract.md) accepts on `POST /v1/destinations` and returns in the
creation response. It was a one-sided wire field until GN-025.2 — declared by the API contract with no
column to hold it — and takes the same `text NOT NULL` shape as §8's `operator_device_keys.label`. It is
advisory: no signed tuple binds it (`zp-destination-bless-v1` binds public key, wallet, node, nonce, and
times only, per [`appendices/A-canonical-fields.md`](appendices/A-canonical-fields.md) §A.4.2), no
predicate below reads it, and it never participates in custody classification.

Load-bearing triggers and service predicates:

1. `wallets.key_origin`, `wallets.node_id`, and `wallets.public_key` are immutable.
2. A `destinations` insert is rejected unless the referenced wallet has
   `key_origin='node_generated'`. Imported wallets can never enter `PENDING`, `BLESSED`, or `RETIRED`
   destination history.
3. **Internal custody** is exactly `key_origin='node_generated' AND destinations.state='BLESSED'`.
4. **Receive-eligibility** (D9.17) is `wallets.key_origin='node_generated' AND wallets.recovery_verified_at IS NOT NULL AND wallets.state='AVAILABLE'` — the D9.3 recovery conjunct minus blessing; every wallet exposed to inbound ZKZ (receive-pool selection, arming, `after_landing=HOLD`) must satisfy it. **Automatic sink eligibility** is receive-eligibility PLUS `destinations.state='BLESSED'` (internal custody plus a successful audited recovery export and a wallet in the `AVAILABLE` state; D9.17). Importing `BLESSED` into receive-eligibility would break the pool, because receivers are not move destinations and are never blessed (D9.17).
5. `recovery_verified_at` and `recovery_verification_id` are set together in the same transaction after a
   successful audited export whose public key equals the wallet public key. They cannot be cleared. The
   GN-014 recovery-verification ceremony (**D9.37**) is their sole writer — the **D9.17** recovery gate,
   monotonic and never cleared by rotation or restore (07 §5.5).
6. A destination cannot be blessed by TOTP alone. Blessing uses the device-key tuple in
   [`appendices/A-canonical-fields.md`](appendices/A-canonical-fields.md).

These predicates preserve the canonical recovery gate ratified as **D9.17** (the binding record for the
per-wallet audited-recovery gate; receive-eligibility and automatic-sink are the two distinct predicates)
while proposed custody classification `R-03` awaits ratification.

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

There is one current row per wallet, not one row per subsystem. `lease_group_id` preserves continuous
exclusivity across a receive and its spawned internal move: the source lease is atomically transferred to
the child `operation_id` without deleting the row, while `root_operation_id` remains the receive. The
destination lease joins the same group. A stale heartbeat never makes a lease
available by itself. Boot recovery reads the chain, reconstructs the owning operation, and either resumes,
releases on positive proof, or quarantines. `DELETE` is allowed only through the guarded release service,
which appends an audit event in the same transaction.

Operations needing two wallets acquire both rows in ascending `wallet_id` byte order inside one database
transaction. If either insert conflicts, the transaction rolls back and holds neither. Every wallet-key
signer requires the corresponding current `(wallet_id,operation_id,lease_epoch)` capability; having the
private key alone is insufficient at the service boundary.

The current row is only the exclusivity projection. The permanent `lease_groups`,
`lease_group_operations`, and `wallet_lease_memberships` tables in §6 retain ownership after active-row
release. Guarded release closes the membership once and removes only the current projection. A receive to
child-move hand-off closes the parent membership, opens the child membership in the same group, and updates
the uninterrupted active row atomically.

#### 5.1 Structural receive-gate trigger (frozen per D9.56)

D9.17 mandates a structural backstop for the recovery gate — *"`BEFORE INSERT` trigger on
`wallet_active_leases` keyed by `lease_role` + assign/arm re-checks"* — independent of whichever
application query reached the insert. **D9.56** freezes its literal form. This is contract text: it is
executed against a live database only by the GN3 schema phase (`GN-003.2`), and no migration ships under
the freeze.

```sql
CREATE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$
DECLARE
  wallet_row wallets%ROWTYPE;
  destination_row destinations%ROWTYPE;
BEGIN
  SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id;

  -- D9.25: the origin conjunct holds at EVERY claim boundary, for every role.
  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN
    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';
  END IF;

  -- G0 (D9.17): RECONCILIATION is exempt. Observation must never block, never pin, and never
  -- be gated on recovery standing; a quarantined or retired wallet may still be observed.
  IF NEW.lease_role = 'RECONCILIATION' THEN
    RETURN NEW;
  END IF;

  -- G1 (D9.17 receive-eligibility): the pool receiver. The remaining two conjuncts of the
  -- 07 §6 receive_eligible predicate; key_origin is already proven above. The lease insert
  -- precedes the AVAILABLE -> PINNED transition (06 §2.2 step 2), so AVAILABLE is the correct
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

  -- G2 (D9.3 + D9.17 automatic-sink): receive-eligibility PLUS a BLESSED destination.
  -- Allowlist-positive per ZTR-516, never a blocklist complement.
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

  -- G3 (D9.17 "sources gated defensively"): outflow roles carry the origin conjunct only;
  -- coins leave these wallets, they never land.
  IF NEW.lease_role IN ('MOVE_SOURCE', 'SEND_SOURCE') THEN
    RETURN NEW;
  END IF;

  -- Fail closed. A wallet_lease_role member added to the enum without a matching branch here
  -- is DENIED, not silently admitted (the ZTR-516 blocklist lesson, applied to the role axis).
  RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER wallet_active_leases_eligibility_guard
  BEFORE INSERT ON wallet_active_leases
  FOR EACH ROW EXECUTE FUNCTION custody_reject_ineligible_lease();
```

Frozen properties, each independently checkable:

| Property | Frozen value |
|---|---|
| Table | `wallet_active_leases` |
| Timing | `BEFORE INSERT`, `FOR EACH ROW` |
| Keyed by | `NEW.lease_role` — one branch per `wallet_lease_role` member |
| Gated roles | `RECEIVE_WINDOW` (G1), `MOVE_DESTINATION` (G2) |
| Defensive-only roles | `MOVE_SOURCE`, `SEND_SOURCE` (G3 — origin conjunct only) |
| Exempt role | `RECONCILIATION` (G0 — returns before any recovery test) |
| Unknown role | rejected — `CUSTODY_LEASE_ROLE_UNKNOWN` |
| Rejection errors | `CUSTODY_LEASE_ORIGIN_REJECTED`, `CUSTODY_LEASE_RECOVERY_UNVERIFIED`, `CUSTODY_LEASE_WALLET_STATE_REJECTED`, `CUSTODY_LEASE_DESTINATION_NOT_BLESSED`, `CUSTODY_LEASE_ROLE_UNKNOWN` — all distinct from the application-layer `409` envelope codes, so a bypass is distinguishable from a normal rejection in logs and tests |

The trigger is a backstop, not the primary gate. The primary gate is the application-layer
[06-operation-flows.md §2.2](06-operation-flows.md#22-wallet-assignment-t0-and-code-formation) step-1 SELECT
plus the §2.3 step-4 arm recheck; the trigger exists so that a code path reaching the insert by any other
route still cannot lease an ineligible wallet. Its rejection is a `plpgsql` exception, never an HTTP status:
an application that trips it has a defect, not a busy pool.

**Divergence on record (GN3 obligation).** The shipped schema contract
`packages/node-core/src/schema/custody-eligibility.sql` (GN-003.2) currently implements the
`MOVE_DESTINATION` branch and the unconditional origin conjunct only; it has **no** `RECEIVE_WINDOW`
branch, no explicit `RECONCILIATION` early return, and no unknown-role fail-closed default. Until GN3
reconciles that file with the DDL frozen above, the `after_landing=HOLD` receive path is protected by the
application-layer gate alone. That file is byte-pinned by
`packages/node-core/test/custody-eligibility.census.test.ts`, so the reconciliation is a GN3 schema-phase
change, not a freeze-phase edit.

**Negative-test obligations discharged by GN-022.3 (`ZTR-167`):**

Executable pure-model proof (CONTRACT_FREEZE — no runtime ships):
[`packages/generic-node-contracts/src/recovery-gate/exposure-model.ts`](../../../packages/generic-node-contracts/src/recovery-gate/exposure-model.ts)
+ [`exposure-proof.test.ts`](../../../packages/generic-node-contracts/src/recovery-gate/exposure-proof.test.ts).
Disposition taken by the composed GN-022.1/.2 design: **OUTRIGHT_PROHIBITION** (arm/HOLD rejected for
every recovery-unverified wallet) — not a ratified whole-vault backup cover for unverified receivers.

1. Assignment finds no eligible wallet and falls through to the
   [03-node-core.md §6](03-node-core.md#6-receive-pool-autoscale-and-backpressure) backpressure ladder
   (`CREATED` / FIFO queue / `503 receive_queue_full`) — never an ungated fallback pool.
2. Arm rejects with `409 operation_not_armable` when the leased (`PINNED`) receiver wallet is quarantined
   or retired between assignment and arm; the wallet stays pinned with attention set and no code byte is
   returned.
3. A `RECEIVE_WINDOW` or `MOVE_DESTINATION` lease-row insert that bypasses the SELECT path for a
   recovery-unverified wallet raises `CUSTODY_LEASE_RECOVERY_UNVERIFIED`.
4. A `RECONCILIATION`-role insert for the same recovery-unverified wallet is **not** rejected.

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

`operations.t0_observation_id` and `terminal_observation_id` identify the primary verification wallet:
receiver for receive, source for move/send. `operation_wallets` records both source and destination for a
move. Foreign keys to observation rows are added after §11 tables exist and MUST also verify matching
wallet and observer domain in the transition service.

`operations.expiry_unix_time_secs` is the `RECEIVE_EXTERNAL` payer-code expiry only; the CHECKs above
force it `NULL` for `MOVE_INTERNAL` and `SEND_EXTERNAL`, so it is structurally RECEIVE-only and is
never the send redemption expiry. Per D9.58 it holds the **absolute** expiry as a D8.10
integer-SECONDS decimal string — never a duration, never milliseconds — and the `^[0-9]+$` CHECK
above mirrors the identical CHECK on its §7.1 `receive_codes` twin so a millisecond rendering cannot
reach either table. A queued receive stores no expiry at all: while an unassigned `RECEIVE_EXTERNAL`
sits in `CREATED` the CHECKs above force `expiry_unix_time_secs IS NULL`, and the value is derived
fresh at code formation ([06-operation-flows.md §2.2](06-operation-flows.md)) from the clamped TTL,
so queue wait never eats into the payer's window. The requested `expires_in_seconds` is not persisted
in any column; no requested-duration column exists on `operations` and none may be added. Per D9.14, the only authoritative `SEND_EXTERNAL` expiry source is
the signed inner `expiry__unix_time_secs` byte-frozen inside
`external_send_sign_intents.inner_preimage_text` (§9); no SEND expiry column exists on `operations`
and none may be added. The API's send-redemption `available_until`
([05-api-contract.md §6.1](05-api-contract.md)) is served from the derived, non-authoritative
`external_send_sign_intents.redemption_expiry_at` column (§9) — the whole-second RFC3339-ms
projection computed exactly once from the frozen inner at sign-intent formation, persisted with the
sign-intent row, and never updated or recomputed.

`client_reference` and `description` are advisory. The node does not parse them into business semantics.
`references_operation_id` is a typed caution/reference edge; it does not make the referenced operation a
payment or refund inside the node.

`operations.idempotency_key` uses the same domain as §3's `reporting_mutation_idempotency.idempotency_key`
— `^[!-~]{16,255}$`, the 16–255 visible-ASCII rule
[05-api-contract.md §1](05-api-contract.md) states for every `Idempotency-Key`. The earlier
`length(idempotency_key) BETWEEN 1 AND 255` form accepted keys the wire contract rejects and permitted
whitespace and control bytes in a uniqueness key; GN-025.2 reconciled it to the single wire domain. There
is one idempotency-key domain in this model, not two.

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

The preimage, purpose, parsed operation id, digest, and signature are mutually checked on write. Artifact
rows are insert-only. Exact field sets and order are frozen in
[`appendices/A-canonical-fields.md`](appendices/A-canonical-fields.md) under D9.2. All three purposes are
ratified byte surfaces; changing any field/order requires a new purpose/version and new goldens.

Storage column `operation_expected_artifacts.signing_key_id` maps to wire field `key_id` exactly. The API
MUST NOT expose a second `signing_key_id` alias. The same mapping applies to event signing keys in §13:

```sql
SELECT signing_key_id AS key_id FROM operation_expected_artifacts;
```

## 7.1 Durable receive material and barriers

Queued, unassigned receives have no row in these tables. Before `CREATED → READY`, the node must commit a
complete `receive_codes` row; the database/service transition rejects READY without it.

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

`operations.discriminator` is the operation UUID and `operations.anchor` is validated and immutable from
creation. A queued unassigned receive is exactly `CREATED` with `receiver_wallet_id`, expiry, T0, and the
durable code row absent. Wallet assignment atomically fills receiver, expiry, and T0 and commits the exact
`receive_codes` code/artifact fields before READY; those assigned fields are then immutable. Arm references
the shared nonce burn and commits the one shared logical fingerprint, completed idempotency row, and
`AWAITING_ARM → RELEASED` mutation atomically; lost HTTP
responses replay the same code bytes. Release commits a permanent proof before deleting the active lease.
For a move, source and destination T0 are mandatory before signing, and both terminal references are
mandatory before `INTERNAL_MOVE_LANDED`.

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
  challenge_id uuid NOT NULL UNIQUE,
  challenge_status approval_challenge_status NOT NULL DEFAULT 'CONSUMED'
    CHECK (challenge_status = 'CONSUMED'),
  method approval_method NOT NULL,
  purpose text NOT NULL CHECK (purpose = 'zp-send-external-approval-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  device_key_id uuid REFERENCES operator_device_keys(id),
  device_signature padded_base64url_signature,
  totp_timestep bigint NOT NULL,
  consumed_at timestamptz NOT NULL,
  CHECK (
    (method = 'TOTP_AND_DEVICE' AND device_key_id IS NOT NULL
      AND device_signature IS NOT NULL)
    OR
    (method = 'TOTP_ONLY' AND device_key_id IS NULL
      AND device_signature IS NULL)
  ),
  FOREIGN KEY (challenge_id, node_id, operation_id, challenge_status)
    REFERENCES approval_challenges(id, node_id, operation_id, status)
);

CREATE UNIQUE INDEX operation_approvals_totp_single_use
  ON operation_approvals (node_id, totp_timestep);
```

`approval_challenges` persist the exact economic tuple before any TOTP is supplied. Refresh supersedes the
prior challenge and changes only nonce/issue/expiry fields. `operation_approvals` exists only after the
guarded approval mutation consumes a mandatory fresh TOTP; its preimage/digest must byte-equal the consumed
challenge. `node_id` is deliberately denormalized so the database enforces global per-node timestep use.
No TOTP code or secret is stored. Only the additive device-key option carries a signature over
`preimage_text`.

`approval_challenges.expires_at` is the T1 approval-challenge freshness timer (D9.14): refreshable
while `CREATED` via supersession, frozen at consumption, and never the redemption deadline; it is
never surfaced or signed as redemption. The T2 redemption expiry — the signed inner
`expiry__unix_time_secs` — does not exist until the post-approval sign intent forms (§9), and a T1
refresh never sets, resets, or extends it.

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

`external_send_sign_intents` is insert-only and is created only **after** approval and lease acquisition.
It binds the consumed approval, both fresh T0 observations, lease group/epoch, and exact preimage before the
signer is called. The signer must present the same lease group and epoch. `operation_transactions` exact
byte/signature columns are keyed by `(operation_id,attempt_no)` and immutable after insertion except for the
one-way additions of step 1, the exact step-2 preimage, step 2, and the completed fully signed transaction.
The completed transaction is durable before submission; only `settled_at` waits for independently verified landing.
Existing values can never be overwritten. `external_send_partials` is also byte-immutable; recovery may
update only delivery timestamps/count. Delivery is forbidden until the partial row commits.

The only authoritative `SEND_EXTERNAL` expiry source is the signed inner `expiry__unix_time_secs`
embedded in `external_send_sign_intents.inner_preimage_text` (D9.14): an integer-SECONDS string
(D8.10; never ms/JS-number), materialized once at post-approval sign-intent formation as
`floor(node_clock)+SEND_REDEMPTION_WINDOW_SECS` (D9.14, 300s), anchored to formation — not approval
time — and byte-frozen with the preimage (D9.8). `redemption_expiry_at` is the derived,
non-authoritative projection of that one signed instant: the same formation step parses the signed
inner text once — never deriving from `prepared_at`, `persisted_at`, receipt time, or wall clock —
and stores the whole-second `timestamptz` in the same insert. It is set exactly once at row
insertion; the table is insert-only, so no UPDATE path exists for it, and no API, event, recovery,
or redelivery path may recompute it. It never enters signed bytes as literal cleartext — it is
hash-committed transitively via the `zp-node-event-v1` `data_sha256` field
([appendices/A-canonical-fields.md](appendices/A-canonical-fields.md)) whenever a node event's
`data` payload carries it, e.g. `external_send.awaiting_redemption`
([appendices/B-state-event-reference.md §6.2](appendices/B-state-event-reference.md)) — and it
never enters the transfer-code envelope or the expected artifact (D9.14), and it never authorizes
re-forming with a fresh head, a second step-1 signature, or a lease release. The byte-frozen inner text remains the single immutable source
behind the column; `external_send_partials` and `operations` carry no send-expiry column.

A RECEIVE attempt may be inserted at `STEP1_SIGNATURE_PERSISTED` with the payer's step-1 signature already
durable, then must advance to `STEP2_PREIMAGE_PERSISTED` before the node signs step 2. A MOVE attempt advances
through all four formation phases in order: inner preimage, step 1, step-2 preimage, then step 2/completed
transaction. Phase advancement and its newly populated columns commit atomically.

There is exactly one transaction attempt per operation, one partial row per external send, and one partial
per approval. A code/transaction expiry, changed head, incomplete lineage path, or operator action does not
permit a second attempt or partial. A new economic action is a new operation after the old operation is
safely resolved; there is no generic same-operation rebuild contract.

`operation_transactions.attempt_phase` is internal persistence state and is not Appendix B's public
`execution_phase`. The API derives the public value from durable facts, in precedence order:

| Public `execution_phase` | Required durable fact |
|---|---|
| `LANDED_VERIFIED` | accepted operation verification plus required terminal observation references |
| `SUBMIT_RETURNED` | the one submit attempt has `completed_at` and a captured outcome |
| `SUBMIT_STARTED` | the one submit-attempt claim has `started_at` |
| `DELIVERED` | external partial `first_delivered_at IS NOT NULL` |
| `SIGNED_PERSISTED` | RECEIVE is at `STEP2_SIGNATURE_PERSISTED` or later; MOVE is at `STEP1_SIGNATURE_PERSISTED` or later, including `STEP2_PREIMAGE_PERSISTED` and `STEP2_SIGNATURE_PERSISTED`; SEND has its external partial/node step-1 signature durable |
| `PREIMAGE_PERSISTED` | RECEIVE is at `STEP2_PREIMAGE_PERSISTED` with the payer step 1 durable and node step 2 NULL; MOVE is at `INNER_PREIMAGE_PERSISTED` with node step 1 NULL; SEND has the sign intent durable and no external partial/node step-1 signature |
| `NOT_STARTED` | none of the above exists |

The mapping is derived at read time or by a tested database view; it is never an independently mutable
status column. It does not copy `operation_transactions.attempt_phase`: those internal persistence phases
and constraints remain exact to their transaction record, while the public phase applies the operation-kind
predicate above.

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

The node never creates a submit attempt for `SEND_EXTERNAL`. The composite uniqueness constraints permit
at most one gateway call for the one immutable transaction attempt. Attempt 1 requires
`INITIAL_SINGLE_SHOT`; no second decision or transaction attempt is representable. The schema deliberately
has no `positive_non_landing_proofs`, `SAFE_WITH_NEW_HEAD`, or
`SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING` contract: D9.6 ratifies a complete-path **landing** oracle, not
a generic non-landing/retry oracle. Transport failure, acknowledgement, a changed or unchanged head,
operator assertion, incomplete path, or resource exhaustion creates no repeat-submit or rebuild authority.
Decision and submit rows are append-only.

## 11. Independent raw observation ledger

The node database and platform database each instantiate this logical schema. They do not share rows,
cursors, endpoint configuration, or read credentials.

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

The observation writer obtains a transaction-scoped advisory lock over
`(observer_id,wallet_public_key)` and then locks the cursor row. It captures `raw_response_bytes` before
parse. `wallet_id` is an optional projection for node-owned wallets; externally owned payer/recipient
addresses have no `wallets` row and are still fully observable by public key.

- A verified response whose exact raw bytes equal the immediately prior response inserts no new
  observation; it increments `consecutive_repeat_count` and `last_seen_at`.
- Any byte-different verified response inserts a permanent row, even when its semantic fingerprint equals
  the previous fingerprint. Same-semantics/different-bytes is
  `EQUIVALENT_STATE_DIFFERENT_ENVELOPE` with `state_changed=false`.
- A byte-different verified semantic state inserts a permanent row with `state_changed=true`, even if the
  same state appeared earlier. Therefore byte-identical `A,A` records one row and `A,B,C,A` records four.
- Every non-verified result and every relationship anomaly inserts a permanent observation row plus a
  permanent anomaly row. Anomalies are always appended, even when their raw bytes repeat.
- A recurrence of an older state is inserted first, classified `REGRESSION`, and fails closed.
- Exact raw-byte equality is the consecutive dedup key. There is no global deduplication.
  `semantic_fingerprint` is computed only after complete verification and is used for `state_changed` and
  relationship classification, not insertion eligibility, as specified in
  [`08-observation-verification.md`](08-observation-verification.md).

All observation and anomaly rows are append-only forever. Cursor counters are mutable operational
indexes, not evidence.

`endpoint_fingerprint` identifies the actual configured endpoint selected for this read. It is copied into
every observation row so later observer reconfiguration cannot rewrite the provenance of existing evidence.

For a verified head, `completed_transaction_text` is the exact complete body used by the verifier, with
top-level order `inner`, `step_1_signature`, `step_2_signature`; its digest is recomputed and byte-compared.
It is not reconstructed later from projections. Path-body `source_kind` records provenance only and grants
no authority: the final path body must byte-equal the fresh observation's completed body, and every earlier
body remains untrusted until the D9.6 verifier accepts the entire path.

An `operation_landing_proofs` manifest freezes verifier version, operation/attempt identity, expected body
digest, ordered path ids/roles, declared total body count and bytes, configured count/byte/time budgets,
fresh-head observation ids, and final verdict/reason. Each path manifest freezes its wallet/T0/head identity
and the ordered list of `(path_index, body digest, byte length, S, P, B, role, per-body verification digest)`.
Body 0 is the exact expected completed transaction; body `n` is the fresh head; adjacent bodies must satisfy
the role-relative backlink. RECEIVE and SEND require one path. MOVE requires exactly two independently
complete paths, SOURCE and DESTINATION, whose body 0 bytes/digest are the same expected move transaction and
whose operation economics both verify against their respective T0.

Verification streams `lineage_path_bodies` in ascending `path_index` using bounded chunks; a chunk commit is
only evidence ingestion, never a partial verdict. A landed verdict commits only after all declared bodies
and bytes are present and the aggregate counts match. Duplicate indexes/signatures/bodies, cycles,
conflicting bodies for one index, gaps, missing completed bodies, inconsistent totals, anomaly references,
or count/byte/time/resource exhaustion produce a permanent `INDETERMINATE` proof and no relationship
adjudication. Exact equality always includes byte comparison; digest indexes are not equality authority.

The original `gateway_observations.relationship` is immutable. A fresh read that jumps stays
`UNEXPLAINED_JUMP`; only an accepted complete path may append
`observation_relationship_adjudications` and derive effective `COMPLETE_PATH_SUCCESSOR`. No failed or
incomplete proof changes the observed relationship. An unknown or unattributed deep successor while a node
wallet's lease remains active is recorded as `INVARIANT_BREACH`, not repaired by lease metadata. A lease is
authorization evidence, never a substitute for a missing path body.

After `gateway_observations` exists, every stored observation reference receives an actual foreign key:

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

The binding service also verifies that each observation's public key equals the owning wallet/public key
and that its observer domain is the one required by the transition. This table
holds counterparty evidence such as a `SEND_EXTERNAL` destination T0 without pretending an external key is
a node-controlled wallet or placing it in `operation_wallets`.

## 11.1 PROOF_CHANNEL candidate proof-body intake store

Section 11 models `lineage_path_bodies` as the verifier's assembly table: every row already references a
`lineage_path_proofs` row. A caller-supplied candidate body exists *before* any `lineage_path_proofs` row
does, so storing it there would fabricate the proof-path authority D9.6 forbids. This section defines the
separate durable store that accepts those candidates. It resolves the §11 body-storage deferral for the
`PROOF_CHANNEL` intake lane and for no other lane: `EXPECTED_OPERATION`, `CANONICAL_LEDGER`, and
`FRESH_GATEWAY_HEAD` bodies are node-derived, never arrive through intake, and remain in the verifier lane.

Candidate rows are inert evidence. No table here carries a verdict, landing, lease, `verified_at`, or
promotion column; `source_kind` records provenance only and grants no authority (§11, D9.6). A candidate the
D9.6 landing oracle later accepts is promoted into `lineage_path_bodies` by verbatim byte copy, never
re-serialised.

Columns `path_proof_id` through `verification_manifest_sha256` are the §11 `lineage_path_bodies`
body-column shape, byte-faithful — same domains, same CHECKs, same primary-key components — so that
promotion is a copy. Columns `raw_bytes_sha256` through `persisted_at` are request-scoped intake
bookkeeping that §11 does not model and the frozen `lineage_path_bodies` row must not carry. `tenant_id`,
`operation_id`, and `idempotency_key` are opaque request-scoped identifiers, typed `text`, not `uuid`. The
scalar domains used below are the §1 domains, declared once for the database.

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

Intake authenticates before it persists. The request's authenticated identity — `tenant_id`,
`operation_id`, `wallet_role` — must equal the corresponding declared fields of the submitted body; a
mismatch in any of the three fails closed as `IDENTITY_MISMATCH` and writes no row, no sighting, and no
counter increment. The persisted row takes those three fields from the authenticated identity, never from
the submitted body, so a body cannot name a tenant, operation, or role its submitter does not hold. The
exact raw bytes and their SHA-256 are captured before any UTF-8 decode, JSON parse, or schema validation,
so a rejected parse never discards the evidence of what was submitted.

### Idempotency

The durable idempotency ledger is the UNIQUE over the FULL `(tenant_id, operation_id, idempotency_key)`
tuple, never key-only ([`05-api-contract.md`](05-api-contract.md) §1). Two tenants presenting the same
`idempotency_key` therefore cannot collide; cross-tenant isolation is structural, not a convention. The
persistence path pre-checks the tuple and only a concurrent race reaches the constraint.

### Deduplication, collision quarantine, and role conflict

An occupied slot `(path_proof_id, path_index)` is resolved by exact raw-byte digest, never by a projection:

- Equal `raw_bytes_sha256` is a duplicate. No second row is written; the slot and tenant sighting counters
  increment and the call succeeds with the slot count
  ([`08-observation-verification.md`](08-observation-verification.md) §17.1, "appends once and increments
  the sighting counter").
- A different digest at the same slot is quarantined: the submission is rejected `DIGEST_COLLISION` and the
  occupant is untouched. Nothing overwrites a captured body.
- A sibling body at the same `(operation_id, path_index)` carrying a different `wallet_role` is rejected
  `ROLE_CONFLICT` before any body row is written.

Both rejections are terminal. Neither authorises a resubmit under the same idempotency key, and a caller
must not blind-retry either (golden rule 4).

### Bounded persistence quotas

Every quota fails closed with `QUOTA_EXCEEDED`; a body is never silently dropped. Quotas are checked before
any write, and the sighting cap is checked before the row insert so a body row is never written without its
first sighting.

| Quota | Bound |
|---|---|
| bytes per submitted body | 65 536 (64 KiB), rejected `BUDGET_EXCEEDED` before parse |
| bodies per tenant | 10 000 |
| bodies per operation | 100 |
| bodies per `(operation, wallet_role)` | 50 |
| total candidate bytes per tenant | 100 MiB |
| `path_index` depth | 1 000 |
| sightings per slot | 100 |
| sightings per tenant | 50 000 |

Sighting observability is a bounded COUNTER — one row per slot, one row per tenant, on the §11
`wallet_observation_cursors.consecutive_repeat_count` model — not an append ledger. Storage is bounded by
live slot and tenant cardinality, never by the number of duplicate, colliding, or role-conflicting
sightings. Both counters are required and complementary: the per-slot cap alone misses the role-conflict
vector, which records a sighting at the incoming `path_proof_id` even when no body row exists there, so an
attacker spraying fresh `path_proof_id` values presents a brand-new slot every time. The counters record
totals only; the per-occurrence duplicate/conflict kind is surfaced synchronously at decision time and is
not durably retained. Durable per-kind collision forensics is a named follow-up against this schema, not a
dropped requirement.

### Live-database obligations

The obligations frozen in `packages/node-core/src/schema/proof-body-store.contract.ts`
(`GN3_PROOF_BODY_STORE_OBLIGATIONS`) apply in addition to §16 and must be discharged by the GN3 schema
phase against a real PostgreSQL: the append-only `BEFORE UPDATE`/`DELETE` guards, the counter-increment
atomicity proof, the domain and CHECK negatives, and the cross-tenant idempotency positive.

One residual is documented rather than claimed closed. The store port exposes no transaction boundary, so
the composition root MUST serialise the find-then-insert idempotency critical section under a lock scoped
to the `(tenant_id, operation_id, idempotency_key)` tuple, and MUST separately serialise the per-tenant cap
check-then-increment. Without both, the per-tenant sighting cap is a soft bound that concurrent same-tenant
submissions can overshoot by up to the concurrency factor, and a raced idempotency-key insert surfaces as
`DIGEST_COLLISION` rather than `IDEMPOTENCY_CONFLICT`. Both reasons are terminal either way.

Traces to GN-102 (`.1` intake, `.2` bounded persistence), the ZTR-424 cross-tenant idempotency remediation,
and the ZTR-710 frozen schema contract.

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

Acknowledgement uses the one signed `zp-report-request-v1` HTTP request referenced through
`reporting_nonce_id`; there is no second acknowledgement signature scheme. That shared immutable request
evidence authenticates a body whose digest covers the full acknowledgement and ordered wallet-evidence set.
Receive requires receiver evidence, move requires source and destination evidence, and send requires source
plus destination/counterparty evidence as defined by the flow. Acknowledgement is idempotent only when the
method, opaque exact raw target, body digest, and logical fingerprint all match the completed record.
A conflicting replay is rejected. A receive wallet stays `PINNED` until the required acknowledgement(s)
arrive or the expired-no-payment release path positively proves the head is unchanged from T0. An
indeterminate or changed head quarantines it.

## 13. Durable neutral event stream

```sql
CREATE TABLE node_event_seq_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)
);

CREATE TABLE node_events (
  seq bigint PRIMARY KEY,
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
  created_at timestamptz NOT NULL
);
```

The event row and the operation status transition commit in the same transaction. Events are insert-only,
globally ordered by `seq`, signed over the exact tuple in
[`appendices/A-canonical-fields.md`](appendices/A-canonical-fields.md), and hash-linked. Node events are
claims and triggers; they do not substitute for platform observations.

`seq` is allocated from a dedicated per-node counter (`node_event_seq_counters`), never a
`GENERATED ALWAYS AS IDENTITY`/`bigserial` column. In the same transaction as the event insert, the writer
locks the node's counter row, takes its current `next_seq` as this event's `seq`, and increments `next_seq`.
Because the increment shares the insert's transaction, a rollback un-does it, so the sequence stays contiguous
and gapless — an identity/serial column instead allocates at insert, and a rolled-back transaction burns that
value permanently, gapping the reporting cursor and causing silent stall plus silent data loss past 500 rows
(**D8.36**). The counter is monotonic and durable-before-visible — a consumer never sees a `seq` that could
still roll back — and on restart resumes from the durable high-water without reset or reuse. The reporting
cursor tracks this dedicated sequence, not `audit_log.id`, and the node-global `previous_event_hash` chain
remains the sole authoritative gap/tamper detector (**D8.80**).

`data_text` is the exact separately stored event-data JSON text and `data_sha256` is its SHA-256. The signed
preimage stores every Appendix A §A.6 field: purpose, canonical version, node id, event id, decimal-string
sequence, nullable operation/wallet ids, event type, data digest, nullable previous hash, and canonical
creation timestamp. `signing_key_id` is exposed on the wire only as `key_id`. The writer recomputes the data
digest, exact preimage, signature, previous-link, and `event_hash` in the same serialized transaction.

**Scope note (dual continuity, ZTR-432 Option 1):** `node_events` / `zp-node-event-v1` and its node-global
`seq` are retained here unchanged, but are re-labeled operator/auditor-only. They are never served to, and
never used as a cursor for, any tenant-facing signed reporting credential. §13.1 defines the implementer-scoped
stream tenants actually consume.

## 13.1 Implementer-scoped continuity stream (dual continuity)

**Status:** architecture ratified by the ZTR-432 PROXY RULING, Option 1 (dual continuity model). Byte-exact
field order and goldens for every artifact in this section are FROZEN by the sibling byte-freeze child
**ZTR-470 (D9.36)** per binding condition **C4** — the byte contract lives in
[`packages/generic-node-contracts/src/implementer-events/CONTRACT.md`](../../../packages/generic-node-contracts/src/implementer-events/CONTRACT.md)
and `…/implementer-events/gen/`; the prose below is architecture, not a byte contract.

Each `(node_id, implementer_id)` pair gets its own private, gapless counter — `implementer_seq` — alongside
the existing node-global `seq`. Allocation is atomic with the global counter per binding condition **C2**
(verbatim): "allocate global seq and implementer_seq (both pre-sign, locked-head counters — NOT IDENTITY),
write both chain heads, the event row, and the triggering state transition in ONE DB transaction, fixed lock
order (global-head → implementer-head)… An unfillable gap is a fail-closed operator INVARIANT — never mint a
placeholder into the closed nine-value event set." The nine-value `event_type` set in
[Appendix B §6](appendices/B-state-event-reference.md#6-durable-public-events) is unchanged; dual continuity
adds a second signed cursor over the same events, not new event types.

Three new artifact families exist at the architecture level (exact columns, ordering, and goldens are
frozen by the byte-freeze child ZTR-470 / D9.36 in `implementer-events/CONTRACT.md`):

- **`zp-implementer-event-v1`** — one row per implementer per event, carrying that implementer's own
  `implementer_seq`, `implementer_id`, and the same underlying `event_id`/`data_sha256` as the corresponding
  `zp-node-event-v1` row (identical event content, independently re-signed for this cursor).
  `implementer_previous_event_hash` chains only over that implementer's own prior events — never the
  node-global chain. A non-invertible `node_event_hash` binds the row to its tenant's own global-chain
  counterpart for operator/auditor-only correlation; it is not itself a reconstruction path back to the
  global stream. Signed with the node's existing `EVENT_SIGNING` key (see [§3](#3-nodes-implementers-and-signing-keys))
  — no new custody surface is introduced (golden rule 5).
- **`zp-implementer-checkpoint-v1`** — per binding condition **C3** (verbatim): "persist the highest
  checkpoint epoch/head seen and REFUSE any lower (anti-rollback); validate the signing key against the
  seq-canonical key via the node-identity directory; conflicting equal-epoch heads = INVARIANT_BREACH (alarm,
  never pick one)." The node-identity directory named here — the `{event-signing public key ↔ implementer_seq
  canonical epoch}` binding, plus the non-equivocation / single-published-head control that stops a node
  serving divergent directory views to different tenants (invisible to per-tenant anti-rollback under **NC2**)
  — is owned by **GN-012a** and implemented in
  [`…/implementer-events/node-identity-directory.ts`](../../../packages/generic-node-contracts/src/implementer-events/node-identity-directory.ts).
- **`zp-implementer-keyrotation-v1`** — expresses retirement of an implementer's reporting key via that
  implementer's own `implementer_seq` cursor, never the node-global cursor (preserves **NC2**). Field order
  and goldens are frozen by ZTR-470 (D9.36); the exact co-signing parties remain an **open question** under
  ZTR-469 (the freeze signs with the node event key only — a future resolution adds co-signature fields
  additive-only, without changing the frozen field order).

`zp-implementer-event-v1`, `zp-implementer-checkpoint-v1`, and `zp-implementer-keyrotation-v1` are the
artifacts actually exposed to a tenant-facing signed reporting credential; see
[05-api-contract.md §§8.1–8.3](05-api-contract.md#8-events-snapshot-and-browser-status) and
[Appendix A §A.6](appendices/A-canonical-fields.md#a6-neutral-node-event).

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

Audit details never contain private keys, TOTP codes/secrets, session secrets, unredacted authorization
headers, or decrypted vault material. Money-state transitions, lease acquisition/release, approval burn,
signature formation, delivery, submit decisions, observation anomalies, destination blessing/retirement,
recovery verification, and operator resolution are all audited.

## 15. Retention and mutability matrix

| Data | Retention | Mutation rule |
|---|---|---|
| wallet ciphertext | while wallet exists; securely rewrapped on key rotation | value-preserving rotation only |
| wallet origin/blessing/recovery evidence | permanent | append-only; status may advance, never rewrite history |
| active lease projection | until positive safe release | current row may heartbeat; never time-expire automatically |
| lease group and membership history | permanent | append-only except one-way completion/release fields |
| operation | permanent | guarded forward transitions only |
| expected artifact / approval preimage | permanent | insert-only |
| reporting key and enrolment/lifecycle evidence | permanent | public-key-only; evidence/events append-only; head is a guarded projection |
| reporting nonce burn and immutable request projections | mutation/register burns permanent; read burns have no prune authority until source+margin freeze | insert-only; never restored after authenticated error/crash |
| reporting mutation idempotency and exact response bytes | permanent | completed-only insert with mutation; update/delete/truncate denied |
| SplitChain preimages/signatures/full tx | permanent, verbatim | insert then one-way completion only |
| send sign intent incl. derived `redemption_expiry_at` | permanent, verbatim | insert-only; derived column set once at insert, never updated |
| external partial | permanent, verbatim | bytes immutable; delivery counters only |
| submit attempt/decision | permanent | append-only |
| changed raw observation | permanent | append-only |
| anomaly raw observation + record | permanent | append-only |
| complete-path bodies/manifests/adjudications | permanent, including failed/incomplete proofs | append-only; accepted effective relationship is derived, never overwrites the observed relationship |
| consecutive duplicate sighting counter | operational | may increment; not evidence authority |
| PROOF_CHANNEL candidate proof-body (§11.1) | permanent, verbatim | insert-only; no column updatable or deletable |
| proof-body sighting counter (§11.1) | operational | monotonic `+1` UPSERT only; not evidence authority |
| canonical wallet ledger | permanent, verbatim | append-only |
| signed node event / audit log | permanent | append-only |
| implementer event (`zp-implementer-event-v1`) | permanent | append-only |
| implementer checkpoint (`zp-implementer-checkpoint-v1`) | permanent | anti-rollback: accepts only a strictly higher checkpoint epoch/head than previously persisted; a lower or conflicting equal-epoch head is never overwritten — it is an INVARIANT_BREACH (alarm) |
| implementer key-rotation (`zp-implementer-keyrotation-v1`) | permanent | append-only |
| verification-material endpoint access | terminal plus configured window, default 30 days | revoke access only; do not delete underlying evidence |

Restoring a database sets `reporting_restore_state.restore_hold=true` and every lifecycle-head
`auth_hold=true` before the signed reporting channel or any reporting mutation is made ready. Missing
independently trusted source/markers or any mismatch in lifecycle epoch, nonce-burn high-water, or terminal
event hash retains both holds. Exact local/trusted equality is necessary but not authority by itself.
No nonce, idempotency, enrolment, lifecycle, event, or audit evidence may be pruned while held. Read-burn
pruning is forbidden until a separate ratified contract freezes both the safety margin and its independently
trusted source. A local retention guess, wall-clock-only age, successful boot, or operator acknowledgement
is not deletion authority. Mutation burns, mutation idempotency, and lifecycle evidence are permanent.

Legal/privacy policy may redact advisory `description` or `client_reference` under a separately designed
policy, but it cannot delete or rewrite signed bytes, economic operation fields, audit proofs, wallet ledger,
changed observations, or anomalies.

## 16. Mandatory database tests

1. imported wallet cannot become a destination;
2. blessed but recovery-unverified destination is excluded from every automatic-sink query;
3. a second active lease for any wallet fails, including cross-operation-kind races;
4. two-wallet acquisition is all-or-nothing and sorted;
5. every operation-kind/status/nullable-field invalid combination fails its CHECK;
6. one idempotency key with a different request hash is a conflict, never a replay success;
7. exact artifact, approval, preimage, transaction, partial, observation, and event bytes survive round-trip;
8. JSONB is absent from all authoritative-byte columns;
9. a persisted external partial cannot be replaced, even after expiry or crash;

   > **§11.9 fixture annotation (CONTRACT_FREEZE, ZTR-149 / GN-016.3).** Fixture seed: one SEND_EXTERNAL at
   > AWAITING_REDEMPTION with §A.8.3 golden bytes. Assertions: (1) byte-column immutability trigger rejects
   > UPDATE of transfer_code_text/step_1_signature/inner_sha256/transfer_code_sha256/persisted_at;
   > (2) sign-intent insert-only (UPDATE/DELETE rejected); (3) no second partial (PK + approval_id UNIQUE);
   > (4) expiry does not unlock replacement (re-run at expiry+1 and expiry+3601); (5) crash does not unlock
   > replacement; (6) delivery-counter exception is the only mutation (last_redelivered_at, redelivery_count
   > advance; byte columns unchanged). Discharged by: EXP-REPLACE-03, EXP-REDELIVER-01, EXP-CRASH-03.

10. a second transaction attempt, submit decision, or submit call for one operation fails; no positive
    non-landing/rebuild literal or table exists;

    > **§11.9 fixture annotation (CONTRACT_FREEZE, ZTR-149 / GN-016.3).** Fixture seed: same SEND_EXTERNAL
    > with one operation_transactions (attempt_no=1). Assertions: (1) attempt_no=2 fails CHECK;
    > (2) duplicate attempt_no=1 fails PK; (3) second submit_decisions fails UNIQUE; (4) SEND_EXTERNAL has
    > zero submit rows in every phase; (5) no rebuild literal/table in source scan. Discharged by:
    > EXP-REPLACE-01, EXP-REPLACE-02, EXP-CLOSE-05.

11. node code cannot create any submit attempt for `SEND_EXTERNAL`;
12. consecutive byte-identical `A,A` stores one observation; same semantic head with a changed wrapper
    appends `EQUIVALENT_STATE_DIFFERENT_ENVELOPE`; `A,B,C,A` stores four and the final row has a regression
    anomaly;
13. malformed and unverifiable responses always append with raw bytes;
14. the node and platform use different observer rows and cannot import one another's cursor as authority;
15. observation/event/audit append-only triggers reject update and delete;
16. `verification-complete` conflicting replay fails and cannot release the wallet; and
17. zero-depth and arbitrary-depth path bodies/manifests round-trip exactly; path indexes support ordered
    bounded-chunk verification without making a partial chunk authoritative;
18. a gap, cycle, duplicate body/signature, conflicting body at one index, missing completed SEND body,
    inconsistent declared count/bytes, MOVE path disagreement, anomaly, or resource-budget exhaustion cannot
    create a landed verdict or relationship adjudication;
19. an `UNEXPLAINED_JUMP` observation remains immutable and gains effective
    `COMPLETE_PATH_SUCCESSOR` only through an accepted complete-path adjudication; and
20. retention jobs revoke proof access without deleting any permanent row;
21. one nonce claimed by `zp-reporting-register-v1` cannot be claimed by `zp-report-request-v1`, another
    route, or another key under the same `(node_id, implementer_id)`;
22. invalid/expired/revoked/bad-signature requests insert no burn, while authenticated 404/409/500,
    handler-failure, crash, and response-loss fixtures retain the committed shared burn;
23. competing rotations and request-admission-versus-revocation races lock one
    `(node_id, implementer_id)` head, advance one epoch/event, and allow only the first valid commit;
24. mutation idempotency rejects non-visible-ASCII or out-of-range keys, resolves completed replay/conflict
    after nonce commit but before mutable protected lookup, and returns exact committed status/body bytes;
25. changing only the unsigned `Idempotency-Key` cannot re-execute arm or verification-complete because the
    guarded-route partial unique index conflicts on the same non-null logical fingerprint;
26. composite foreign keys reject cross-node or cross-implementer attachment of operation, nonce,
    idempotency, bootstrap, enrolment, lifecycle, arm, or acknowledgement evidence;
27. missing trusted restore source/markers, lifecycle-epoch or nonce-high-water regression, partial backup,
    and chain-break fixtures remain hard-held; equal local markers alone never release authorization;
28. exact raw target, request preimage/digest/signature, exact-body digest, lifecycle public evidence, and
    exact response bytes survive round-trip without normalization or reconstruction; and
29. reporting key identities accept only `id`, `node_id`, `implementer_id`, `public_key`, and `registered_at`;
    custody-field injection fails, while mutation/lifecycle evidence remains permanent and read burns cannot
    prune before the separately frozen trusted source and margin exist;
30. the actual deferred lifecycle triggers reject unknown event types, illegal/latest-state edges, missing or
    extra transition rows, predecessor ID/epoch/hash breaks, event/head projection mismatch, implicit hold
    release, rotation with an occupied prior slot, and every `RETIRED`/`REVOKED` reactivation;
31. a register nonce naming another new key, any enrolment mismatch in exact preimage text/digest/signature,
    issuance, expiry, bootstrap evidence, or rotation authorizer, missing authorizing bytes, or wrong event
    nonce purpose fails;
32. request evidence beyond 60 seconds, register evidence beyond 300 seconds, or a rotation overlap not
    exactly successor `registered_at`/commit plus 24 hours fails;
33. the actual deferred route triggers reject a pending parent, arm/ack without its completed parent, parent
    without the exact route-specific `child_record_id`, or parent/child `reporting_nonce_id` mismatch; actual
    immutable triggers reject update/delete/truncate of parent, child, state history, and permanent burns;
34. nonce/idempotency/arm/ack disagreement in method, opaque exact raw target, or body digest fails, as does a
    mutation-retention downgrade, guarded duplicate under another header, or caller digest intended to
    bypass the actual-column partial unique index; and
35. missing or unequal local/trusted lifecycle epoch, nonce-burn high-water, or event hash retains
    `restore_hold`; clearing only restore hold or only lifecycle `auth_hold` never admits a request.
36. a sign-intent insert stores `redemption_expiry_at` exactly equal to the whole-second projection
    of the persisted inner's `expiry__unix_time_secs` (the test re-parses the signed text;
    production paths never do); the column is set exactly once at that insert, and every path that
    subsequently reads it — the §6.1/§6.2 API, the `external_send.awaiting_redemption` event,
    recovery reconciliation, and redelivery — returns that identical persisted value, never a
    recomputed one (an application-level invariant that no code path issues an UPDATE; the schema
    defines no CHECK, trigger, or `REVOKE` that would block one at the database level).
