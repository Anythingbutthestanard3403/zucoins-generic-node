// (follow-up) — fail-closed boot-time privilege readiness check.
//
// privileges.sql's role creation deliberately degrades to a NOTICE when the migrating
// connection lacks cluster CREATEROLE (managed Postgres hosts commonly deny it), so the
// structural DELETE/TRUNCATE prohibition the frozen pool-policy/custody contracts cite as
// "enforced structurally at the DB grant level by " can silently NOT exist in
// production. Boot therefore VERIFIES
// the guarantee instead of trusting the migration: the consuming app (apps/generic-node)
// injects assertPrivilegeReadiness into BootLaneDeps.assertPostMigrationReadiness after
// runMigrations and before any money surface, and treats a throw as a boot refusal.
// Granting CREATEROLE to a production connection stays rejected (least-privilege);
// provisioning node_core_app out-of-band is the ops path that SATISFIES this check.
//
// DRIVER-AGNOSTIC: node-core depends on no database driver. The composition root
// adapts its Postgres client to PrivilegeSqlExecutor. Both queries need no elevated
// privilege: pg_roles is world-readable and has_table_privilege may be evaluated for any
// role by any caller. Error messages name roles/tables/privileges only — never credential
// or connection-string material.

export const NODE_CORE_APP_ROLE = "node_core_app" as const;

// (follow-up) — the role a SEND_EXTERNAL-path connection assumes. Same
// reads/writes as node_core_app minus INSERT/UPDATE on the two submit ledgers, so a raw-SQL
// write from the SEND path is refused by PostgreSQL (SQLSTATE 42501) rather than by a source
// scan an encoded table name can walk around. privileges.sql establishes it; this file is the
// fail-closed boot verification of the same subtraction.
export const NODE_CORE_SEND_ROLE = "node_core_send" as const;

// The two append-only submit ledgers. SEND_EXTERNAL writes neither of them
// (the never-blind-retry rule).
export const SUBMIT_LEDGER_TABLES = ["submit_decisions", "gateway_submit_attempts"] as const;

export interface PrivilegeSqlQueryResult<R> {
  readonly rows: R[];
}

/**
 * Narrow node-postgres-shaped query surface. `pg.Pool` and `pg.PoolClient` both satisfy it
 * structurally. Declared here (not imported from signing-keys/proof-body) so data stays a
 * boundary leaf per test/boundaries.test.ts.
 */
export interface PrivilegeSqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<PrivilegeSqlQueryResult<R>>;
}

export interface PrivilegeReadinessOptions {
  /**
   * Defaults to NODE_CORE_APP_ROLE. Overridable so tests can probe the role-absent path
   * without dropping a cluster-wide role other databases may still depend on.
   */
  readonly roleName?: string;
  /**
   * Schema whose ordinary tables must deny DELETE/TRUNCATE to the role. Defaults to
   * `public` — the schema privileges.sql grants against.
   */
  readonly schemaName?: string;
  /**
   * Defaults to NODE_CORE_SEND_ROLE. Overridable on the same terms as `roleName`.
   */
  readonly sendRoleName?: string;
}

export class PrivilegeReadinessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrivilegeReadinessError";
  }
}

type RoleExistsRow = {
  role_exists: boolean;
};

type TablePrivilegeRow = {
  tablename: string;
  can_delete: boolean;
  can_truncate: boolean;
};

type LedgerWriteRow = {
  tablename: string;
  can_insert: boolean;
  can_update: boolean;
};

/**
 * Throws PrivilegeReadinessError unless (a) both the runtime role and the SEND-path role
 * exist, (b) neither holds DELETE or TRUNCATE on any ordinary table in the target schema,
 * and (c) the SEND-path role holds neither INSERT nor UPDATE on either submit ledger — the
 * exact guarantee privileges.sql's GRANT/REVOKE + ALTER DEFAULT PRIVILEGES establish. If a later
 * migration ever grants DELETE on one specific table (the documented exception path), it
 * must extend this check's expectation in the same commit so the boot gate and the grant
 * never drift apart.
 */
export async function assertPrivilegeReadiness(
  db: PrivilegeSqlExecutor,
  options: PrivilegeReadinessOptions = {},
): Promise<void> {
  const roleName = options.roleName ?? NODE_CORE_APP_ROLE;
  const schemaName = options.schemaName ?? "public";
  const sendRoleName = options.sendRoleName ?? NODE_CORE_SEND_ROLE;
  await assertRoleExists(db, roleName);
  await assertDeleteTruncateRevoked(db, roleName, schemaName);
  await assertRoleExists(db, sendRoleName);
  // The SEND role is a second principal on the same tables, so it inherits the same
  // custody-integrity subtraction as the app role — a role that cannot INSERT a submit
  // decision but can DELETE or TRUNCATE the ledger would be no defence at all.
  await assertDeleteTruncateRevoked(db, sendRoleName, schemaName);
  await assertSubmitLedgerWriteDenied(db, sendRoleName, schemaName);
}

async function assertRoleExists(
  db: PrivilegeSqlExecutor,
  roleName: string,
): Promise<void> {
  const result = await db.query<RoleExistsRow>(
    "select exists (select 1 from pg_roles where rolname = $1) as role_exists",
    [roleName],
  );
  if (result.rows[0]?.role_exists) {
    return;
  }
  throw new PrivilegeReadinessError(
    `Privilege readiness check failed: role "${roleName}" does not exist in this cluster. ` +
      "The structural DELETE/TRUNCATE guarantee (privileges.sql) cannot be verified, so " +
      "this node refuses to boot. Provision the role out-of-band and re-apply privileges.sql " +
      "before starting.",
  );
}

async function assertDeleteTruncateRevoked(
  db: PrivilegeSqlExecutor,
  roleName: string,
  schemaName: string,
): Promise<void> {
  // Parameter $1 = role name for has_table_privilege; $2 = schema name.
  // relkind 'r' = ordinary table, 'p' = partitioned table.
  const result = await db.query<TablePrivilegeRow>(
    `select c.relname as tablename,
         has_table_privilege($1, c.oid, 'DELETE') as can_delete,
         has_table_privilege($1, c.oid, 'TRUNCATE') as can_truncate
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = $2 and c.relkind in ('r', 'p')`,
    [roleName, schemaName],
  );
  const violations = result.rows
    .filter((row) => row.can_delete || row.can_truncate)
    .map((row) => `${row.tablename} (${heldPrivileges(row).join(", ")})`);
  if (violations.length === 0) {
    return;
  }
  throw new PrivilegeReadinessError(
    `Privilege readiness check failed: role "${roleName}" holds revoked privileges on ` +
      `${schemaName} tables: ${violations.join("; ")}. The structural custody-integrity ` +
      "guarantee (privileges.sql) is absent, so this node refuses to boot. Re-apply that " +
      "file's REVOKE statements before starting.",
  );
}

/**
 * Throws unless the SEND-path role holds neither INSERT nor UPDATE on either submit ledger —
 * the subtraction privileges.sql's REVOKE establishes. Ledgers absent from the schema produce
 * no rows and no violation: a table that does not exist cannot be written. This is the boot
 * half of the structural defence; the grant itself is what a raw-SQL write actually hits.
 */
async function assertSubmitLedgerWriteDenied(
  db: PrivilegeSqlExecutor,
  sendRoleName: string,
  schemaName: string,
): Promise<void> {
  // $1 = role, $2 = schema, $3.. = the ledger names, one placeholder per SUBMIT_LEDGER_TABLES
  // entry so adding a third ledger cannot silently fall out of the IN list.
  const placeholders = SUBMIT_LEDGER_TABLES.map((_name, index) => `$${index + 3}`).join(", ");
  const result = await db.query<LedgerWriteRow>(
    `select c.relname as tablename,
         has_table_privilege($1, c.oid, 'INSERT') as can_insert,
         has_table_privilege($1, c.oid, 'UPDATE') as can_update
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = $2 and c.relkind in ('r', 'p') and c.relname in (${placeholders})`,
    [sendRoleName, schemaName, ...SUBMIT_LEDGER_TABLES],
  );
  const violations = result.rows
    .filter((row) => row.can_insert || row.can_update)
    .map((row) => `${row.tablename} (${heldWrites(row).join(", ")})`);
  if (violations.length === 0) {
    return;
  }
  throw new PrivilegeReadinessError(
    `Privilege readiness check failed: role "${sendRoleName}" holds revoked write privileges on ` +
      `${schemaName} submit ledgers: ${violations.join("; ")}. SEND_EXTERNAL must not be able to ` +
      "write either submit ledger (the never-blind-retry rule), so this " +
      "node refuses to boot. Re-apply privileges.sql after the schema phase created those tables.",
  );
}

function heldWrites(row: LedgerWriteRow): string[] {
  const held: string[] = [];
  if (row.can_insert) {
    held.push("INSERT");
  }
  if (row.can_update) {
    held.push("UPDATE");
  }
  return held;
}

function heldPrivileges(row: TablePrivilegeRow): string[] {
  const held: string[] = [];
  if (row.can_delete) {
    held.push("DELETE");
  }
  if (row.can_truncate) {
    held.push("TRUNCATE");
  }
  return held;
}
