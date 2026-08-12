-- Integration requests: durable state for platform-initiated key requests
-- (Route 2 handshake). A platform proposes scopes/caps; the operator decides;
-- the platform claims once. ZTR-1238.
--
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package opens a socket.
-- Every invariant below is inventoried in integration-requests.contract.ts.
--
-- Secret discipline (mirrors implementer-credentials / credential types):
--   * claim_token_hash is the unsalted SHA-256 hex of the one-time claim token.
--     The raw claim token never enters this schema.
--   * The issued API key never exists at rest here. Approval only records the
--     decision + implementer identity; the credential is GENERATED AT CLAIM TIME
--     and returned once (issued_credential_id points at implementer_credentials).
--
-- Lifecycle transitions are CAS-guarded on (status, row_version) by writers
-- (single UPDATE ... WHERE status = $expected AND row_version = $v ... RETURNING).
-- The engine is the arbiter - no SELECT-then-UPDATE.
--
-- Prerequisite slices: nodes + implementers (node-implementer-registry /
-- reporting-persistence) and implementer_credentials. Applied alone, greenfield
-- fails on the first missing FK target (nodes).
--
-- Pack position: after implementer-credentials (issued_credential_id FK).
-- Appended so earlier money-pack version numbers stay stable.

CREATE TABLE integration_requests (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  -- Closed against the frozen implementer scope vocabulary
  -- (generic-node-contracts api-schema auth-scopes IMPLEMENTER_SCOPES). Intake may
  -- further narrow by policy; the CHECK admits the full frozen set.
  requested_scopes text[] NOT NULL CHECK (
    cardinality(requested_scopes) > 0
    AND requested_scopes <@ ARRAY[
      'receive:create', 'receive:read',
      'move:create', 'move:read',
      'send:create', 'send:read',
      'destination:create', 'destination:read'
    ]::text[]
  ),
  -- Platform proposal, verbatim (validated at intake by the public route layer).
  proposed_rule_json text NOT NULL,
  -- Operator's final (possibly edited) rule; set at approval.
  approved_rule_json text,
  status text NOT NULL CHECK (
    status IN ('PENDING', 'APPROVED', 'DECLINED', 'EXPIRED', 'CLAIMED')
  ),
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  -- Unsalted SHA-256 hex of the claim token; raw token is never durable.
  claim_token_hash text NOT NULL UNIQUE CHECK (claim_token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  decided_at timestamptz,
  -- admin_operators.id (reporting-prefix journal; bare uuid - not money-pack owned).
  decided_by uuid,
  implementer_id uuid REFERENCES implementers(id),
  issued_credential_id uuid REFERENCES implementer_credentials(id),
  claimed_at timestamptz,
  -- Consistency: each status admits exactly the column set its transition writes.
  -- PENDING: no decision, no implementer, no credential, no claim.
  -- APPROVED: decision + implementer + approved rule; credential still absent.
  -- DECLINED: decision recorded; no credential / claim.
  -- EXPIRED: no credential / claim (decision fields optional - lazy TTL or expiry job).
  -- CLAIMED: full approval set plus issued credential + claimed_at.
  CONSTRAINT integration_requests_status_consistency CHECK (
    (
      status = 'PENDING'
      AND approved_rule_json IS NULL
      AND decided_at IS NULL
      AND decided_by IS NULL
      AND implementer_id IS NULL
      AND issued_credential_id IS NULL
      AND claimed_at IS NULL
    )
    OR (
      status = 'APPROVED'
      AND approved_rule_json IS NOT NULL
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
      AND implementer_id IS NOT NULL
      AND issued_credential_id IS NULL
      AND claimed_at IS NULL
    )
    OR (
      status = 'DECLINED'
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
      AND issued_credential_id IS NULL
      AND claimed_at IS NULL
    )
    OR (
      status = 'EXPIRED'
      AND issued_credential_id IS NULL
      AND claimed_at IS NULL
    )
    OR (
      status = 'CLAIMED'
      AND approved_rule_json IS NOT NULL
      AND decided_at IS NOT NULL
      AND decided_by IS NOT NULL
      AND implementer_id IS NOT NULL
      AND issued_credential_id IS NOT NULL
      AND claimed_at IS NOT NULL
    )
  ),
  CHECK (expires_at > created_at)
);

-- Expiry-job / lazy-expiry reads: status filter + expires_at bound.
CREATE INDEX integration_requests_status_expires_at_idx
  ON integration_requests (status, expires_at);

-- Operator list / claim-by-node lookups.
CREATE INDEX integration_requests_node_status_idx
  ON integration_requests (node_id, status);
