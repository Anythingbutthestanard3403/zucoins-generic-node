-- destination_state += WORKER (send-worker auto-scale).
--
-- Own pack slice so ALTER TYPE ... ADD VALUE commits before any later slice
-- references the new label in a CHECK or trigger (PG forbids using a newly-added
-- enum label until the adding transaction commits).
--
-- Greenfield base-enums-domains.sql still creates the 3-value enum; this slice
-- admits WORKER on already-applied and greenfield DBs alike. Appended only.
--
-- Prerequisite lookup uses to_regtype (search_path), not a global pg_type scan.

DO $destination_state_worker$
BEGIN
  IF to_regtype('destination_state') IS NULL THEN
    RAISE EXCEPTION 'destination-state-worker requires destination_state';
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_enum e
     WHERE e.enumtypid = to_regtype('destination_state')
       AND e.enumlabel = 'WORKER'
  ) THEN
    ALTER TYPE destination_state ADD VALUE 'WORKER';
  END IF;
END
$destination_state_worker$;
