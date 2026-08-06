-- Signer support: append-only exact-content columns and reference domains,
-- destinations.blessing_artifact_id, the approval-challenge shape, globally single-use
-- TOTP timestep burns, rate limits per account / source IP / device / operation, and the
-- recovery surfaces
-- (signer audit evidence; recovery nonce); appendices/A-canonical-fields.md SA.4.2
-- (zp-destination-bless-v1 frozen field set).
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in signer-support.contract.ts and censused by
-- test/signer-support.census.test.ts.
--
-- Scope: the auth/authorization-adjacent support stores that
-- 04-data-model.md never freezes as tables but that recovery, blessing, and guarded
-- mutations already depend on as facts:
--   1. signer_audit              -- every internal-signer invocation attempt
--   2. destination_blessing_artifacts -- zp-destination-bless-v1 signed tuple target
--   3. recovery_nonces           -- single-use recovery-action nonce per operation
--   4. totp_timestep_burns       -- node-wide global (node_id, timestep) burn registry
--   5. api_rate_buckets          -- rate counters per account / IP / device / operation
--   6. auth_failure_state        -- failed-auth counters and lock windows
--   7. recovery_action_idempotency -- recovery-action idempotency replay ledger
-- Candidate validation manifests and gateway-read intents are deliberately omitted:
-- the former is an operation_transactions concern (implementer judgment deferred to
-- that lane); the latter is already covered by observation-cursor locking.

-- Reference scalar checks (re-declared for self-contained contract text; the schema-apply phase
-- de-duplicates against base-enums-domains.sql on combined application):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- 1. Signer audit: every internal-signer invocation attempt.
-- Distinct from gateway_submit_attempts (external gateway). Append-only. Multiple rows
-- per operation are intentional so recovery can distinguish "no call occurred" from
-- "a call occurred and the result is unknown" without collapsing attempts.

CREATE TABLE signer_audit (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_group_id uuid,
  lease_epoch bigint CHECK (lease_epoch IS NULL OR lease_epoch > 0),
  preimage_sha256 sha256_hex NOT NULL,
  called_at timestamptz NOT NULL,
  outcome text NOT NULL CHECK (outcome IN
    ('SUCCEEDED','FAILED','UNKNOWN')),
  purpose text NOT NULL CHECK (purpose IN
    ('STEP_1','STEP_2','REPORTING_ENVELOPE','DEVICE_APPROVAL','EXPECTED_ARTIFACT')),
  UNIQUE (id, node_id)
);

CREATE INDEX signer_audit_by_operation
  ON signer_audit (operation_id, called_at);

-- 2. Destination blessing artifacts (A.4.2 frozen field set + device signature).
-- destinations.blessing_artifact_id is a dangling column without this table.
-- Insert-only; UNIQUE(nonce) is the structural single-use gate. Exact preimage text and
-- digest are persisted together so the signed tuple is never re-derived.

CREATE TABLE destination_blessing_artifacts (
  id uuid PRIMARY KEY,
  purpose text NOT NULL CHECK (purpose = 'zp-destination-bless-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  node_id uuid NOT NULL,
  destination_id uuid NOT NULL,
  wallet_id uuid NOT NULL,
  wallet_pubkey padded_base64url_pubkey NOT NULL,
  nonce uuid NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  device_signature padded_base64url_signature NOT NULL,
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at),
  CHECK (EXTRACT(EPOCH FROM (expires_at - issued_at)) <= 300),
  CHECK (octet_length(preimage_text) > 0),
  UNIQUE (id, node_id)
);

-- 3. Recovery nonces: single-use, scoped per operation, consumed atomically
-- with the recovery-action mutation. Shape mirrors approval_challenges:
-- issued / consumed / superseded lifecycle with one ISSUED nonce per operation.

CREATE TABLE recovery_nonces (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN
    ('ISSUED','CONSUMED','SUPERSEDED')),
  nonce uuid NOT NULL UNIQUE,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  -- DEFERRABLE INITIALLY DEFERRED: the one-ISSUED-per-operation partial unique index
  -- (below) cannot itself be deferrable, so rotation must supersede the old row (setting
  -- superseded_by to the not-yet-inserted new row's id) before inserting that new row.
  -- Deferring FK validation to COMMIT is what makes that ordering legal.
  superseded_by uuid REFERENCES recovery_nonces (id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (expires_at > issued_at),
  CHECK ((status = 'SUPERSEDED') = (superseded_by IS NOT NULL)),
  CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
  UNIQUE (id, node_id, operation_id, status)
);

CREATE UNIQUE INDEX recovery_nonces_one_issued_per_operation
  ON recovery_nonces (operation_id)
  WHERE status = 'ISSUED';

-- 4. Cross-purpose TOTP timestep burns (globally single-use).
-- operation_approvals_totp_single_use covers only SEND_EXTERNAL approval.
-- Destination blessing and recovery actions are also fresh-TOTP-gated
-- and share this node-wide registry so a race across two mutation kinds for the same
-- (node_id, totp_timestep) cannot both succeed. purpose is metadata only; uniqueness
-- is global. No TOTP code or secret is stored.

CREATE TABLE totp_timestep_burns (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  totp_timestep bigint NOT NULL,
  purpose text NOT NULL CHECK (purpose IN
    ('SEND_EXTERNAL_APPROVAL','DESTINATION_BLESS','RECOVERY_ACTION')),
  operation_id uuid,
  burned_at timestamptz NOT NULL,
  UNIQUE (node_id, totp_timestep)
);

-- 5. API rate buckets: counters per account, source IP, device, and operation.
-- Rate limiting never replaces TOTP/nonce replay defense.

CREATE TABLE api_rate_buckets (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  dimension text NOT NULL CHECK (dimension IN
    ('ACCOUNT','SOURCE_IP','DEVICE','OPERATION')),
  dimension_key text NOT NULL,
  window_start timestamptz NOT NULL,
  request_count integer NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  UNIQUE (node_id, dimension, dimension_key, window_start)
);

-- 6. Auth-failure / lockout state (admin_users-style shape, closed vocabulary).
-- failed_login_count / locked_until track authentication failure windows per account.
-- Guarded-projection: counters and lock windows are updatable; identity keys are not.

CREATE TABLE auth_failure_state (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  account_key text NOT NULL,
  failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  locked_until timestamptz,
  last_failed_at timestamptz,
  UNIQUE (node_id, account_key)
);

-- destinations.blessing_artifact_id gains a real foreign-key target.
-- Applied after destination_blessing_artifacts exists; the destinations relation itself
-- is owned by custody-eligibility.sql. the schema-apply phase must apply that slice first.

ALTER TABLE destinations
  ADD CONSTRAINT destinations_blessing_artifact_fk
  FOREIGN KEY (blessing_artifact_id)
  REFERENCES destination_blessing_artifacts (id);

-- 7. Recovery action idempotency: stores the success
-- body of each completed recovery action so a replay with the same Idempotency-Key returns
-- the prior result without re-mutating. body is text, not jsonb: the application owns the
-- exact byte-for-byte JSON.stringify replay text; nothing here parses or re-serializes it.

CREATE TABLE recovery_action_idempotency (
  operation_id uuid NOT NULL,
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 255),
  body text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (operation_id, idempotency_key)
);
