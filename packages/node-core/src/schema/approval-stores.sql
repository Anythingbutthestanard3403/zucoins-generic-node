-- Device keys and guarded approvals: operator device keys, approval challenges, and
-- operation approvals, with the approval-challenge freshness timer and byte-exact signing
-- (the byte-exact signing rule).
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in approval-stores.contract.ts and censused by
-- test/approval-stores.census.test.ts.
-- The reference scalar domains and the closed enumerations are owned by
-- base-enums-domains.sql and consumed here without redeclaration.

-- Device keys and guarded approvals:

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
