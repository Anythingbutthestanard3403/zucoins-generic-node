-- ZTR-798: stock SS3 reporting_validate_lifecycle_deferred used a CASE that
-- type-checks every NEW.<field> arm against the firing table's row type.
-- On reporting_key_lifecycle_events (has id, no lifecycle_event_id) COMMIT of
-- AUTH_HOLD_SET failed with: record "new" has no field "lifecycle_event_id".
-- IF/ELSIF keeps each NEW field reference in a branch scoped to one table.
CREATE OR REPLACE FUNCTION reporting_validate_lifecycle_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  event_id uuid;
BEGIN
  IF TG_TABLE_NAME = 'reporting_key_lifecycle_events' THEN
    event_id := NEW.id;
  ELSIF TG_TABLE_NAME = 'reporting_key_state_transitions' THEN
    event_id := NEW.lifecycle_event_id;
  ELSIF TG_TABLE_NAME = 'reporting_key_lifecycle_states' THEN
    event_id := NEW.lifecycle_event_id;
  ELSIF TG_TABLE_NAME = 'reporting_key_lifecycle_heads' THEN
    event_id := NEW.lifecycle_event_id;
  ELSE
    event_id := NULL;
  END IF;
  IF event_id IS NOT NULL THEN
    PERFORM reporting_assert_lifecycle_event(event_id);
  END IF;
  RETURN NULL;
END
$$;
