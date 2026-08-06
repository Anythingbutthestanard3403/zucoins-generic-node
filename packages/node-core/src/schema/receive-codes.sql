-- Receive barriers: durable receive-code material. expiry_unix_time_secs is whole-second
-- text and its format CHECK mirrors the operations twin to prevent millisecond values.
--
-- Format CHECK: the check text is byte-identical to the operations.sql
-- expiry_unix_time_secs CHECK (expiry_unix_time_secs ~ '^[0-9]+$') so a millisecond
-- or signed or fractional value cannot store in this column. Expiry is a whole-second
-- decimal string, and the receive_codes twin carries the same guard.
--
-- Prerequisite slice: operations.sql and custody-eligibility.sql. This file is
-- NOT self-contained — applying it into an empty schema fails on the missing
-- operations and wallets relations, which is the documented expected outcome
-- asserted by test/migration-integrity.test.ts GREENFIELD characterization.
--
-- FKs need their target relations EARLIER in the apply sequence:
--   operations(id)  ← operations.sql
--   wallets(id)     ← custody-eligibility.sql
--   gateway_observations(id) ← observation-ledger.sql
--   operation_expected_artifacts(id) ← expected-artifacts.sql

CREATE TABLE receive_codes (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  receiver_wallet_id uuid NOT NULL REFERENCES wallets(id),
  t0_observation_id uuid NOT NULL,
  expected_artifact_id uuid NOT NULL UNIQUE REFERENCES operation_expected_artifacts(id),
  discriminator uuid NOT NULL,
  anchor text NOT NULL CHECK (anchor ~ '^[A-Za-z0-9_-]{1,96}$'),
  expiry_unix_time_secs text NOT NULL CHECK (expiry_unix_time_secs ~ '^[0-9]+$'),
  transfer_code_text text NOT NULL,
  transfer_code_sha256 sha256_hex NOT NULL,
  code_status text NOT NULL CHECK (code_status IN ('AWAITING_ARM','RELEASED','EXPIRED')),
  ready_at timestamptz NOT NULL,
  released_at timestamptz,
  CHECK (code_status <> 'RELEASED' OR released_at IS NOT NULL),
  CHECK (released_at IS NULL OR code_status IN ('RELEASED','EXPIRED'))
);

ALTER TABLE receive_codes
  ADD FOREIGN KEY (t0_observation_id) REFERENCES gateway_observations(id);
