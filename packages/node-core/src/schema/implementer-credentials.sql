-- Implementer credentials: the bearer-credential registry behind implementer
-- authentication, keyed to the implementer registry and audited in audit_log.
--
-- Bearer material is returned once by the issue/rotate service and never enters this
-- schema. credential_hash is the issue-time SHA-256 fingerprint of a 256-bit random
-- bearer value; public_prefix is a short non-secret display/lookup hint.

-- Exactly the three states a writer can produce: ISSUE -> ACTIVE, ROTATE -> GRACE,
-- REVOKE -> REVOKED. Expiry is carried by expires_at and evaluated at read time, so there is
-- no stored EXPIRED state; declaring one would be a state no code path can reach.
CREATE TYPE implementer_credential_status AS ENUM
  ('ACTIVE', 'GRACE', 'REVOKED');

CREATE TABLE implementer_credentials (
  id uuid PRIMARY KEY,
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  public_prefix text NOT NULL CHECK (
    length(public_prefix) = 11 AND public_prefix ~ '^ik_[A-Za-z0-9_-]{8}$'
  ),
  credential_hash text NOT NULL UNIQUE CHECK (
    credential_hash ~ '^[0-9a-f]{64}$'
  ),
  scopes text[] NOT NULL CHECK (
    cardinality(scopes) > 0
    AND scopes <@ ARRAY[
      'receive:create', 'receive:read',
      'move:create', 'move:read',
      'send:create', 'send:read',
      'destination:create', 'destination:read'
    ]::text[]
  ),
  status implementer_credential_status NOT NULL,
  key_version integer NOT NULL CHECK (key_version > 0),
  issued_at timestamptz NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  rotated_from_id uuid REFERENCES implementer_credentials(id),
  rotated_to_id uuid REFERENCES implementer_credentials(id),
  rotated_at timestamptz,
  rotation_grace_until timestamptz,
  UNIQUE (id, implementer_id),
  CHECK (expires_at IS NULL OR expires_at > issued_at),
  CHECK (
    (status = 'ACTIVE' AND revoked_at IS NULL)
    OR (status = 'GRACE' AND revoked_at IS NOT NULL
        AND rotation_grace_until = revoked_at AND rotated_to_id IS NOT NULL)
    OR (status = 'REVOKED' AND revoked_at IS NOT NULL)
  ),
  CHECK (
    (rotated_to_id IS NULL AND rotated_at IS NULL AND rotation_grace_until IS NULL)
    OR (rotated_to_id IS NOT NULL AND rotated_at IS NOT NULL
        AND rotation_grace_until IS NOT NULL
        AND rotation_grace_until >= rotated_at)
  )
);

CREATE INDEX implementer_credentials_public_prefix_idx
  ON implementer_credentials (public_prefix);

CREATE INDEX implementer_credentials_implementer_status_idx
  ON implementer_credentials (implementer_id, status);
