-- Runtime role privileges: strict ownership (structural DELETE/TRUNCATE prohibition).
--
-- SOURCE (obligation): packages/generic-node-contracts/src/pool-policy/states.ts and
-- custody predicates: "there is NO deleted state: vault/secret rows are never deleted in any
-- state, enforced structurally at the DB grant level, not by
-- convention." This file is that structural enforcement.
--
-- `node_core_app` is the runtime role apps/generic-node connects as. It is granted
-- SELECT/INSERT/UPDATE by default on every table in the public schema (present and future, via
-- ALTER DEFAULT PRIVILEGES) but never DELETE or TRUNCATE - matching the data-model retention
-- matrix, where every table in this schema is either "permanent" or "append-only." A later
-- migration MAY grant DELETE on one specific table, but only with an explicit comment citing the
-- spec section that authorizes deleting that table's rows; it must never be a blanket grant.
--
-- CREATE ROLE requires cluster-wide CREATEROLE privilege, which a migration's own DB connection
-- may not hold on managed hosts (e.g. Railway Postgres). The DO block below creates the role when
-- the connecting role can, and degrades to a NOTICE - leaving the structural GRANT/REVOKE to apply
-- once infra provisions `node_core_app` out-of-band - when it cannot. Boot MUST still fail-closed
-- via assertPrivilegeReadiness so a silent no-op cannot open the custody
-- guarantee. No CREATEROLE is required of the production app connection.
--
-- Race: concurrent first-boot migrations can both pass IF NOT EXISTS before either commits
-- CREATE ROLE. Catch duplicate_object / unique_violation so the loser is a
-- no-op rather than aborting the migration transaction.
--
-- Frozen schema contract: executed by the schema-apply phase (and ops out-of-band provisioning);
-- nothing in this package auto-runs it. Inventory: privileges.contract.ts.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'node_core_app') THEN
    CREATE ROLE node_core_app NOLOGIN;
  END IF;
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'node_core_app role not created (connecting role lacks CREATEROLE) - '
      'provision it out-of-band before granting production traffic to this database';
  WHEN duplicate_object THEN
    NULL; -- concurrent first-boot CREATE ROLE won the race; role exists
  WHEN unique_violation THEN
    NULL; -- same race on pg_authid_rolname_index (SQLSTATE 23505)
END
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'node_core_app') THEN
    GRANT USAGE ON SCHEMA public TO node_core_app;
    GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO node_core_app;
    REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE ON TABLES TO node_core_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      REVOKE DELETE, TRUNCATE ON TABLES FROM node_core_app;
  END IF;
END
$$;

-- Structural defence for raw-SQL writes to the submit ledgers.
--
-- `node_core_send` is the role a SEND_EXTERNAL-path connection assumes (SET ROLE, same NOLOGIN
-- model as node_core_app). It carries the same reads and writes as node_core_app minus one
-- thing: no INSERT and no UPDATE on submit_decisions or gateway_submit_attempts.
-- SEND_EXTERNAL must have no node submit function in
-- its type graph. A source scan can only approximate that: a table name is launderable through
-- base64, hex, String.fromCharCode, template concatenation or unicode escapes, and no text scan
-- closes under all encodings. PostgreSQL evaluates this grant at execution against the table
-- OID, so no encoding of the name evades it - this is the structural half; the text scan in
-- test/submit-write-path.guard.test.ts is only the source-level half.
--
-- The two ledgers are created by submit-attempts.sql, which the schema-apply phase may run AFTER
-- this file; ALTER DEFAULT PRIVILEGES would then hand node_core_send INSERT/UPDATE on them.
-- `to_regclass` guards the REVOKE so an apply that predates the tables is a no-op rather than an
-- undefined_table abort, and this file is idempotent - the ops path is to re-apply it after the
-- DDL phase. Boot does not trust that ordering: assertPrivilegeReadiness re-verifies the
-- subtraction and refuses to open money surfaces when it is absent, so a
-- skipped REVOKE cannot silently leave the ledgers writable from the SEND path.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'node_core_send') THEN
    CREATE ROLE node_core_send NOLOGIN;
  END IF;
EXCEPTION
  WHEN insufficient_privilege THEN
    RAISE NOTICE 'node_core_send role not created (connecting role lacks CREATEROLE) - '
      'provision it out-of-band before granting production traffic to this database';
  WHEN duplicate_object THEN
    NULL; -- concurrent first-boot CREATE ROLE won the race; role exists
  WHEN unique_violation THEN
    NULL; -- same race on pg_authid_rolname_index (SQLSTATE 23505)
END
$$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'node_core_send') THEN
    GRANT USAGE ON SCHEMA public TO node_core_send;
    GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO node_core_send;
    REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_send;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      GRANT SELECT, INSERT, UPDATE ON TABLES TO node_core_send;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
      REVOKE DELETE, TRUNCATE ON TABLES FROM node_core_send;
    IF to_regclass('public.submit_decisions') IS NOT NULL THEN
      REVOKE INSERT, UPDATE ON public.submit_decisions FROM node_core_send;
    END IF;
    IF to_regclass('public.gateway_submit_attempts') IS NOT NULL THEN
      REVOKE INSERT, UPDATE ON public.gateway_submit_attempts FROM node_core_send;
    END IF;
  END IF;
END
$$;
