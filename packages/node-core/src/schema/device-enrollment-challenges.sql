-- Node-origin enrollment challenges for zp-device-enrol-v1. There is no separately
-- frozen shape for a dedicated table, so this one is mirrored from approval_challenges
-- (status enum, unique nonce,
-- issued/expires CHECK, superseded_by) rather than inventing a new pattern.
-- Frozen schema contract text; executed only by the schema-apply phase.

-- Reuses approval_challenge_status (ISSUED, CONSUMED, SUPERSEDED, EXPIRED) from
-- base-enums-domains.sql — same lifecycle for "issue a time-bound challenge, then
-- consume it once".

CREATE TABLE device_enrollment_challenges (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  status approval_challenge_status NOT NULL DEFAULT 'ISSUED',
  purpose text NOT NULL CHECK (purpose = 'zp-device-enrol-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  nonce uuid NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  superseded_by uuid REFERENCES device_enrollment_challenges(id),
  CHECK (expires_at > issued_at),
  CHECK ((status = 'SUPERSEDED') = (superseded_by IS NOT NULL))
);

CREATE UNIQUE INDEX device_enrollment_challenges_one_issued_per_node
  ON device_enrollment_challenges(node_id)
  WHERE status = 'ISSUED';
