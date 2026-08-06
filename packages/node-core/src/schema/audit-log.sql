-- Audit log: the immutable, secret-free audit trail, plus the reference scalar check it
-- depends on. Retention is permanent and append-only, and the append-only triggers reject
-- UPDATE and DELETE.
-- Frozen schema contract. This file is contract text: it is executed only by the
-- schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in audit-log.contract.ts and censused by
-- test/audit-log.census.test.ts.
--
-- Scope: the audit_log table -- the immutable, secret-free audit trail. The downstream
-- composite foreign key that reporting_key_bootstrap_evidence takes on
-- audit_log(id, node_id) belongs to the reporting-key surface and is recorded as a
-- schema-apply obligation, not transcribed here.
--
-- The audit table is transcribed verbatim, so its FKs target nodes(id), operations(id), and
-- wallets(id), and custody-eligibility.sql declares wallets(id) to match. What this file
-- needs from its host is execution sequence and domain prerequisites, not naming -- those
-- relations and the sha256_hex domain must exist before this file's table.

-- Reference scalar check (verbatim; the only domain the audit table uses):

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

-- Audit log (verbatim):

CREATE TABLE audit_log (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  node_id uuid NOT NULL REFERENCES nodes(id),
  actor_kind text NOT NULL CHECK (actor_kind IN
    ('SYSTEM','OPERATOR_SESSION','ACTION_KEY','DEVICE_KEY','IMPLEMENTER')),
  actor_id text,
  action text NOT NULL,
  operation_id uuid REFERENCES operations(id),
  wallet_id uuid REFERENCES wallets(id),
  details_text text NOT NULL,
  details_sha256 sha256_hex NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (id, node_id)
);

-- Append-only at the trigger level: the append-only triggers reject UPDATE and DELETE, and
-- the retention matrix records the signed node event / audit log as permanent and
-- append-only. This discharges the guard obligation audit-log.contract.ts previously
-- carried as schema-apply work.
--
-- Application-level insert-only discipline is not the guarantee: the audit trail is the
-- forensic record of every money-state transition, lease change, approval burn and operator
-- resolution, so the property that matters is that no connection -- including one holding
-- the application role, and including the retention path -- can rewrite or remove an entry
-- after the fact. Only an engine-level BEFORE UPDATE/DELETE trigger states that. The
-- retention policy "no audit evidence may be pruned while held" is only a sentence until
-- this exists.
--
-- The function is the canonical reporting_reject_immutable_change transcribed VERBATIM,
-- including its '55000' ERRCODE -- the canonical append-only rejector, consumed rather
-- than re-invented under a second name. It is re-declared here for the same reason this
-- file re-declares the reference scalar domain: each schema fragment applies standalone,
-- and combined application onto one database de-duplicates them at the reconciliation step
-- (src/schema/CONVENTIONS.md, "ZKZ amount CHECK domains").

CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();

-- TRUNCATE never fires a row-level DELETE trigger, so the two guards above would leave the
-- whole trail removable in one statement. The statement-level BEFORE TRUNCATE guard closes
-- that bypass; without it "append-only" is only true row by row.
CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
