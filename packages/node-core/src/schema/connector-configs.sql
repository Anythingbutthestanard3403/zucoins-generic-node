-- Connector configuration (ZTR-1330 / GN-202).
--
-- One row per implementer: display name, capability labels, optional hook
-- target, and the verification posture recorded at approval.
-- integration_requests gains the platform proposal for rules, hook target,
-- and capability labels. Frozen CREATE TABLE files stay untouched.
-- Pack position: appended.

DO $connector_configs_prereq$
BEGIN
  IF to_regclass('implementers') IS NULL THEN
    RAISE EXCEPTION
      'connector-configs requires implementers';
  END IF;
  IF to_regclass('integration_requests') IS NULL THEN
    RAISE EXCEPTION
      'connector-configs requires integration_requests';
  END IF;
END
$connector_configs_prereq$;

CREATE TABLE connector_configs (
  implementer_id uuid PRIMARY KEY REFERENCES implementers (id) ON DELETE CASCADE,
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  scopes text NOT NULL DEFAULT ('["receives:write","sends:write","wallets:read_linked"]'),
  webhook_url text NULL,
  webhook_enabled boolean NOT NULL DEFAULT false,
  policy_mode text NOT NULL DEFAULT 'NODE_VERIFIED',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT connector_configs_policy_mode_chk CHECK (
    policy_mode IN ('NODE_VERIFIED', 'LEGACY')
  ),
  CONSTRAINT connector_configs_scopes_chk CHECK (
    jsonb_typeof(scopes::jsonb) = 'array'
    AND jsonb_array_length(scopes::jsonb) > 0
    AND scopes::jsonb <@ '["receives:write","sends:write","wallets:read_linked","ledger:read_all"]'::jsonb
  )
);

ALTER TABLE integration_requests
  ADD COLUMN IF NOT EXISTS requested_rules jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE integration_requests
  ADD COLUMN IF NOT EXISTS requested_webhook_url text NULL;

ALTER TABLE integration_requests
  ADD COLUMN IF NOT EXISTS requested_connector_scopes jsonb NOT NULL DEFAULT '["receives:write","sends:write","wallets:read_linked"]'::jsonb;

DO $connector_configs_request_checks$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'integration_requests_requested_rules_arr_chk'
  ) THEN
    ALTER TABLE integration_requests
      ADD CONSTRAINT integration_requests_requested_rules_arr_chk
      CHECK (jsonb_typeof(requested_rules) = 'array');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'integration_requests_connector_scopes_chk'
  ) THEN
    ALTER TABLE integration_requests
      ADD CONSTRAINT integration_requests_connector_scopes_chk
      CHECK (
        jsonb_typeof(requested_connector_scopes) = 'array'
        AND requested_connector_scopes <@ '["receives:write","sends:write","wallets:read_linked","ledger:read_all"]'::jsonb
      );
  END IF;
END
$connector_configs_request_checks$;
