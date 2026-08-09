-- The `vault_root_kdf_salt` table: the per-node PBKDF2 salt the vault root key is derived
-- under, persisted beside the sealed material it protects (ZTR-1159).
--
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it in production.
-- Every invariant below is inventoried in vault-root-kdf-salt.contract.ts.
--
-- Why a table at all: the salt is not secret, but it must be *correct*. Before this slice the
-- salt was a string literal copy-pasted into three composition roots plus an unvalidated
-- environment read in the master-key rotation CLI, with nothing anywhere cross-checking that
-- the value used to seal was the value used to open. Storing it next to `vault` means the
-- envelopes and the salt that opens them travel together through every backup and restore.
--
-- Insert-only, deliberately. A salt that can be edited in place is the same key-loss trap in
-- a new costume: the row would still say what boot derives under while the envelopes were
-- sealed under something else. The three guards below make an in-place change an engine-level
-- refusal rather than a silent, unrecoverable one. A node whose salt genuinely must change
-- re-seals every envelope through the rotation path; it does not rewrite this row.
--
-- No foreign key to `nodes`. This row must be readable at vault-unlock on a node whose
-- `nodes` row is written by genesis in the same boot, and the salt is meaningless to any
-- other table, so a tenant FK would buy ordering risk and nothing else.
--
-- Pack position: appended after verification-acknowledgements so earlier money-pack version
-- numbers (and sql_sha256 journal entries) stay stable for already-applied greenfield DBs.

CREATE TABLE vault_root_kdf_salt (
  node_id uuid PRIMARY KEY,
  -- Raw salt bytes. Not base64: the derivation consumes bytes, and an encoding layer here
  -- would be one more place for the stored value to disagree with the derived one.
  salt bytea NOT NULL,
  -- Provenance, so an operator reading the row can tell a genesis-minted salt from the
  -- pre-ZTR-1159 literal a legacy node has been deriving under all along.
  source text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- The floor the rotation CLI has always enforced on an operator-supplied salt.
  CONSTRAINT vault_root_kdf_salt_min_bytes CHECK (octet_length(salt) >= 8),
  CONSTRAINT vault_root_kdf_salt_source_chk
    CHECK (source IN ('environment', 'historical_default', 'genesis_random'))
);

-- Shared with audit-log.sql / event-ledger.sql; the pack loader strips this CREATE when an
-- earlier slice already registered the function.
CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER vault_root_kdf_salt_no_update
  BEFORE UPDATE ON vault_root_kdf_salt
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER vault_root_kdf_salt_no_delete
  BEFORE DELETE ON vault_root_kdf_salt
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

-- TRUNCATE never fires a row-level DELETE trigger, so the two guards above would leave the
-- salt removable in one statement -- and a node whose salt row is gone silently falls back to
-- the historical literal at the next boot. The statement-level guard closes that bypass.
CREATE TRIGGER vault_root_kdf_salt_no_truncate
  BEFORE TRUNCATE ON vault_root_kdf_salt
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
