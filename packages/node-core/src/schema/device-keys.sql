-- Device keys and guarded approvals: the reference scalar check and the enrolled-device
-- registry, feeding the signing matrix (device enrolment / destination blessing /
-- external-send approval) and the zp-device-enrol-v1 ceremony.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in device-keys.contract.ts and censused by
-- test/device-keys.census.test.ts.
--
-- Scope: the enrolled-device registry (operator_device_keys) that the device enrolment
-- ceremony appends to and that device-signature verification reads at request receipt.
-- The guarded-approval tables that reference it (approval_challenges,
-- operation_approvals) belong to the external-send approval slice and are deliberately
-- not transcribed here.

-- Reference scalar check (verbatim; the one domain operator_device_keys uses):

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- Enrolled-device registry (verbatim):

CREATE TABLE operator_device_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  public_key padded_base64url_pubkey NOT NULL,
  label text NOT NULL,
  enrolled_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (node_id, public_key)
);
