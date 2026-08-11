// Minimal dual-gate reporting schema for DR drill + fault-injection fixtures.
// Extracted from the auth-hold-force PG harness so restore force paths share one DDL slice.
// ZTR-1172: drill restores a real node backup shaped like this, not a synthetic-only table.

/** Minimal dual-gate schema: restore_hold + lifecycle heads/events + admission. */
export const MINIMAL_DUAL_GATE_SCHEMA_SQL = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  display_name text NOT NULL
);

CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE implementer_reporting_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  public_key text NOT NULL,
  registered_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id)
);

CREATE TABLE reporting_nonce_burn_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_burn_sequence bigint NOT NULL DEFAULT 1
);

CREATE TABLE reporting_request_nonces (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  nonce uuid NOT NULL,
  purpose text NOT NULL,
  route_id text,
  request_class text,
  reporting_key_id uuid,
  lifecycle_epoch bigint NOT NULL,
  nonce_burn_sequence bigint NOT NULL,
  request_preimage_text text NOT NULL,
  request_preimage_sha256 text NOT NULL,
  request_signature text NOT NULL,
  method text,
  raw_target text,
  body_sha256 text,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL,
  retention_class text NOT NULL,
  UNIQUE (node_id, nonce_burn_sequence),
  UNIQUE (id, node_id, implementer_id, purpose)
);

CREATE TABLE reporting_key_lifecycle_events (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  epoch bigint NOT NULL CHECK (epoch > 0),
  event_type text NOT NULL,
  current_key_id uuid,
  prior_key_id uuid,
  overlap_expires_at timestamptz,
  auth_hold boolean NOT NULL,
  successor_registered_at timestamptz,
  nonce_evidence_id uuid NOT NULL,
  nonce_purpose text NOT NULL,
  enrolment_evidence_id uuid,
  public_evidence_text text NOT NULL,
  public_evidence_sha256 text NOT NULL,
  previous_event_id uuid,
  previous_epoch bigint,
  previous_event_hash text,
  event_hash text NOT NULL UNIQUE,
  committed_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, epoch),
  UNIQUE NULLS NOT DISTINCT (
    id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
    overlap_expires_at, auth_hold
  ),
  CHECK ((event_type = 'AUTH_HOLD_SET' AND auth_hold)
    OR event_type <> 'AUTH_HOLD_SET'),
  CHECK ((event_type = 'AUTH_HOLD_RELEASED' AND NOT auth_hold)
    OR event_type <> 'AUTH_HOLD_RELEASED')
);

CREATE TABLE reporting_key_lifecycle_states (
  id uuid PRIMARY KEY,
  reporting_key_id uuid NOT NULL,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  lifecycle_epoch bigint NOT NULL,
  state text NOT NULL,
  lifecycle_event_id uuid,
  state_changed_at timestamptz NOT NULL
);

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
  FOREIGN KEY (
    lifecycle_event_id, node_id, implementer_id, epoch, current_key_id,
    prior_key_id, overlap_expires_at, auth_hold
  ) REFERENCES reporting_key_lifecycle_events
      (id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
       overlap_expires_at, auth_hold)
);

CREATE FUNCTION reporting_guard_lifecycle_head_update()
RETURNS trigger LANGUAGE plpgsql AS $$
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
     OR (OLD.epoch > 0 AND (e.epoch <> NEW.epoch OR e.previous_event_id <> OLD.lifecycle_event_id))
  THEN
    RAISE EXCEPTION 'illegal reporting lifecycle head advance' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER reporting_lifecycle_head_guard
  BEFORE UPDATE ON reporting_key_lifecycle_heads
  FOR EACH ROW EXECUTE FUNCTION reporting_guard_lifecycle_head_update();

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
    RAISE EXCEPTION 'stale or missing reporting lifecycle head' USING ERRCODE = '40001';
  END IF;
END
$$;

CREATE TABLE reporting_restore_state (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  restore_hold boolean NOT NULL DEFAULT true,
  local_lifecycle_epoch bigint,
  local_nonce_burn_high_water bigint,
  local_event_hash text,
  trusted_lifecycle_epoch bigint,
  trusted_nonce_burn_high_water bigint,
  trusted_event_hash text,
  trusted_source_id text,
  trusted_source_observed_at timestamptz,
  hold_release_evidence_sha256 text,
  hold_released_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
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
`;
