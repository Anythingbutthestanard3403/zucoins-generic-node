-- Verification-material access windows: the verification-material
-- endpoint's 409 not-ready / 410 expired behaviour, the access defaults
-- to terminal plus 30 days; expiry revokes endpoint access only); 04-data-model.md
-- and the retention rule "verification-material endpoint access | terminal plus configured
-- window, default 30 days | revoke access only; do not delete underlying evidence";
-- structurally modelled on approval_challenges (issued_at/expires_at/status/nonce).
--
-- Frozen schema contract. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this
-- package runs it. Every invariant below is inventoried in
-- verification-access-windows.contract.ts and censused by
-- test/verification-access-windows.census.test.ts.
--
-- Scope: the per-operation verification-material access-window RECORD. This is NOT a
-- second bearer credential. Auth for the endpoint remains the signed reporting
-- credential. This row is the additional per-operation gate that
-- opens at the landed terminal milestone and closes after the configured window.
-- The unique nonce is stored ONLY as its SHA-256 hex digest - never plaintext
-- (the redaction posture for secret identifiers).

-- Reference scalar (re-declared for self-contained contract text):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- Closed status vocabulary for the access window. OPEN is the only status that can
-- serve material; EXPIRED and REVOKED both deny the endpoint (410) without deleting
-- any underlying evidence row.

CREATE TABLE verification_material_access_windows (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'OPEN'
    CHECK (status IN ('OPEN', 'EXPIRED', 'REVOKED')),
  -- SHA-256 hex of the random nonce; plaintext nonce is never durable.
  nonce_hash sha256_hex NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (nonce_hash),
  UNIQUE (operation_id),
  CHECK (expires_at > issued_at),
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE UNIQUE INDEX verification_access_windows_one_open_per_operation
  ON verification_material_access_windows(operation_id)
  WHERE status = 'OPEN';

CREATE INDEX verification_access_windows_expires_at_idx
  ON verification_material_access_windows (expires_at);

CREATE INDEX verification_access_windows_node_implementer_idx
  ON verification_material_access_windows (node_id, implementer_id);
