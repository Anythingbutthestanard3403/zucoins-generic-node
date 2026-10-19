-- Hook delivery rows (ZTR-1333).
--
-- A signed payload waits here until a background tick posts it. The target
-- address is read from the connector row at send time and is not copied here.

DO $webhook_deliveries_prereq$
BEGIN
  IF to_regclass('implementers') IS NULL THEN
    RAISE EXCEPTION
      'webhook-deliveries requires implementers';
  END IF;
END
$webhook_deliveries_prereq$;

CREATE TABLE webhook_deliveries (
  delivery_id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL REFERENCES implementers (id) ON DELETE CASCADE,
  event_type text NOT NULL CHECK (event_type IN (
    'receive.ready',
    'receive.observed',
    'receive.settled',
    'receive.expired',
    'receive.failed',
    'send.created',
    'send.approved',
    'send.settled',
    'send.cancelled',
    'send.failed',
    'connector.rule.approved',
    'connector.rule.rejected'
  )),
  operation_id uuid NULL,
  payload_text text NOT NULL,
  signature_text text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING',
  attempt_count integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status_code integer NULL,
  last_error text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz NULL,
  source_kind text NOT NULL,
  source_id uuid NOT NULL,
  CONSTRAINT webhook_deliveries_status_chk CHECK (
    status IN ('PENDING', 'DELIVERED', 'FAILED_PERMANENT')
  ),
  CONSTRAINT webhook_deliveries_attempt_chk CHECK (attempt_count BETWEEN 0 AND 5),
  CONSTRAINT webhook_deliveries_source_chk CHECK (
    source_kind IN ('DURABLE_EVENT', 'RULE_REQUEST')
  ),
  CONSTRAINT webhook_deliveries_source_uidx UNIQUE (source_kind, source_id)
);

CREATE INDEX webhook_deliveries_due_idx
  ON webhook_deliveries (status, next_attempt_at)
  WHERE status = 'PENDING';
