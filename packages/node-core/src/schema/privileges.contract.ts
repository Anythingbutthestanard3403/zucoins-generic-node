/**
 * Runtime role privileges: strict ownership and the structural DELETE/TRUNCATE prohibition.
 * Sources: signing custody (structural DELETE/TRUNCATE prohibition at grant level);
 * the pool-policy states + custody predicates in packages/generic-node-contracts
 * (structural DB-grant enforcement); the fail-closed boot check.
 *
 * Frozen inventory of the structural privilege invariants carried by privileges.sql
 * (follow-up). The census test binds every entry here to the literal SQL text.
 * Runtime verification is assertPrivilegeReadiness in src/data/privilege-readiness.ts — boot
 * refuses to open money surfaces when the role or the DELETE/TRUNCATE revokes are absent.
 */

export const PRIVILEGES_SCHEMA_FILE = "privileges.sql" as const;

export interface PrivilegesSchemaInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const PRIVILEGES_SCHEMA_INVARIANTS: readonly PrivilegesSchemaInvariant[] = [
  {
    id: "APP_ROLE_NAME",
    sqlAnchor: "CREATE ROLE node_core_app NOLOGIN",
    rule: "the runtime application role is named node_core_app and is NOLOGIN (sessions assume it via SET ROLE / connection role mapping, never a password login from the app).",
  },
  {
    id: "CREATEROLE_DEGRADE_NOTICE",
    sqlAnchor: "WHEN insufficient_privilege THEN",
    rule: "role creation degrades to NOTICE when the migrating connection lacks CREATEROLE — managed hosts commonly deny it; never hard-fail the migration (fail-open of the migration is deliberate; fail-closed is the boot check).",
  },
  {
    id: "DUPLICATE_ROLE_RACE",
    sqlAnchor: "WHEN duplicate_object THEN",
    rule: "concurrent first-boot CREATE ROLE races are no-ops (duplicate_object), not migration aborts.",
  },
  {
    id: "GRANT_SELECT_INSERT_UPDATE",
    sqlAnchor: "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO node_core_app",
    rule: "the app role may read and write rows but not remove them by default.",
  },
  {
    id: "REVOKE_DELETE_TRUNCATE",
    sqlAnchor: "REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_app",
    rule: "DELETE and TRUNCATE are structurally denied on every present public table — the custody-integrity guarantee the frozen pool-policy contracts require.",
  },
  {
    id: "DEFAULT_PRIVILEGES_GRANT",
    sqlAnchor:
      "ALTER DEFAULT PRIVILEGES IN SCHEMA public\n      GRANT SELECT, INSERT, UPDATE ON TABLES TO node_core_app",
    rule: "future tables inherit SELECT/INSERT/UPDATE for node_core_app.",
  },
  {
    id: "DEFAULT_PRIVILEGES_REVOKE",
    sqlAnchor:
      "ALTER DEFAULT PRIVILEGES IN SCHEMA public\n      REVOKE DELETE, TRUNCATE ON TABLES FROM node_core_app",
    rule: "future tables inherit the DELETE/TRUNCATE prohibition for node_core_app.",
  },
  {
    id: "NO_CREATEROLE_ON_APP",
    sqlAnchor: "CREATE ROLE node_core_app NOLOGIN",
    rule: "the app role is never granted CREATEROLE; production least-privilege rejects granting CREATEROLE to a production connection.",
  },
  {
    id: "SEND_ROLE_NAME",
    sqlAnchor: "CREATE ROLE node_core_send NOLOGIN",
    rule: "the SEND_EXTERNAL-path role is named node_core_send and is NOLOGIN, assumed by SET ROLE on the same terms as node_core_app.",
  },
  {
    id: "SEND_REVOKE_DELETE_TRUNCATE",
    sqlAnchor: "REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM node_core_send",
    rule: "node_core_send inherits the same custody-integrity subtraction as node_core_app: DELETE and TRUNCATE are structurally denied on every present public table. Without it the ledger-write REVOKE would be no defence — a role that cannot INSERT a submit decision but can DELETE or TRUNCATE the ledger still destroys the record.",
  },
  {
    id: "SEND_DEFAULT_PRIVILEGES_REVOKE",
    sqlAnchor:
      "ALTER DEFAULT PRIVILEGES IN SCHEMA public\n      REVOKE DELETE, TRUNCATE ON TABLES FROM node_core_send",
    rule: "future tables inherit the DELETE/TRUNCATE prohibition for node_core_send too, so a table created after this file is applied cannot open the subtraction.",
  },
  {
    id: "SEND_ROLE_NO_SUBMIT_DECISIONS_WRITE",
    sqlAnchor: "REVOKE INSERT, UPDATE ON public.submit_decisions FROM node_core_send",
    rule: "node_core_send cannot INSERT or UPDATE submit_decisions — the structural half of 'SEND_EXTERNAL has no node submit function', enforced by PostgreSQL at execution so no encoding of the table name evades it.",
  },
  {
    id: "SEND_ROLE_NO_ATTEMPT_WRITE",
    sqlAnchor: "REVOKE INSERT, UPDATE ON public.gateway_submit_attempts FROM node_core_send",
    rule: "node_core_send cannot INSERT or UPDATE gateway_submit_attempts — the same subtraction on the transport-evidence ledger.",
  },
  {
    id: "SEND_REVOKE_TABLE_GUARD",
    sqlAnchor: "IF to_regclass('public.submit_decisions') IS NOT NULL THEN",
    rule: "the ledger REVOKEs are guarded by to_regclass so an apply that predates submit-attempts.sql is a no-op, not an undefined_table abort; boot re-verifies the subtraction, so the skipped REVOKE fails closed rather than open.",
  },
] as const;

/**
 * Live-database proofs this package cannot run without a Postgres harness. The schema-apply
 * phase + assertPrivilegeReadiness discharge them. privilege-readiness.pg.test.ts covers the
 * boot-check paths when TEST_DATABASE_URL is set.
 */
export const SCHEMA_PRIVILEGES_OBLIGATIONS = [
  "role create: privileges.sql creates node_core_app when the connecting role holds CREATEROLE.",
  "role degrade: when CREATEROLE is absent, the migration emits NOTICE and continues (no abort).",
  "grant shape: node_core_app holds SELECT/INSERT/UPDATE and holds neither DELETE nor TRUNCATE on public tables.",
  "boot refuse role: assertPrivilegeReadiness throws PrivilegeReadinessError when the role is absent.",
  "boot refuse delete: assertPrivilegeReadiness throws when DELETE is re-granted on any public table.",
  "boot refuse truncate: assertPrivilegeReadiness throws when TRUNCATE is re-granted on any public table.",
  "boot allow: assertPrivilegeReadiness resolves after a clean privileges.sql apply with revokes intact.",
  "send role create: privileges.sql creates node_core_send alongside node_core_app.",
  "send ledger refusal: a session that has SET ROLE node_core_send is refused INSERT on submit_decisions and on gateway_submit_attempts with SQLSTATE 42501.",
  "app ledger write: the same INSERT under node_core_app succeeds — MOVE_INTERNAL's and RECEIVE's submit paths are unaffected.",
  "boot refuse send write: assertPrivilegeReadiness throws when INSERT or UPDATE is re-granted to node_core_send on either ledger.",
  "send delete/truncate refusal: a session that has SET ROLE node_core_send is refused DELETE and TRUNCATE on the submit ledgers with SQLSTATE 42501.",
  "boot refuse send delete/truncate: assertPrivilegeReadiness throws when DELETE or TRUNCATE is re-granted to node_core_send on any public table.",
] as const;

export const PRIVILEGES_SCHEMA_SOURCE =
  "signing-custody: structural grant prohibition; data-model: retention and append-only" as const;
