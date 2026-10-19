-- Spend rule request rows (ZTR-1331).
--
-- A connected platform submits a rule. The row stays PENDING until an
-- operator admits or declines it. Admitted rows are copied into the
-- auto-approve document by the operator route. This slice does not fetch
-- a hook target.

DO $connector_rule_requests_prereq$
BEGIN
  IF to_regclass('implementers') IS NULL THEN
    RAISE EXCEPTION
      'connector-rule-requests requires implementers';
  END IF;
  IF to_regclass('wallets') IS NULL THEN
    RAISE EXCEPTION
      'connector-rule-requests requires wallets';
  END IF;
END
$connector_rule_requests_prereq$;

CREATE TABLE connector_rule_requests (
  request_id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL REFERENCES implementers (id) ON DELETE CASCADE,
  rule_id text NOT NULL CHECK (
    char_length(rule_id) BETWEEN 1 AND 64
    AND rule_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
  ),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
  reserve_wallet_id uuid NULL REFERENCES wallets (id),
  total_cap_zkz text NULL,
  per_send_max_zkz text NOT NULL,
  per_send_min_zkz text NULL,
  window_hours integer NOT NULL,
  window_cap_zkz text NOT NULL,
  expires_at text NULL,
  status text NOT NULL DEFAULT 'PENDING',
  webhook_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz NULL,
  decided_by uuid NULL,
  CONSTRAINT connector_rule_requests_status_chk CHECK (
    status IN ('PENDING', 'APPROVED', 'REJECTED')
  ),
  CONSTRAINT connector_rule_requests_window_hours_chk CHECK (
    window_hours BETWEEN 1 AND 720
  )
);

CREATE INDEX connector_rule_requests_status_created_idx
  ON connector_rule_requests (status, created_at DESC);
