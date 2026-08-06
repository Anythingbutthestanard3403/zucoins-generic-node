// fail-closed boot-time schema completeness check.
//
// The runtime DB role holds no DDL grant: every CREATE/ALTER lives
// in migrate.ts-owned migration files, never in application code. That means a DB that
// hasn't run the migrations (operations-response-columns.sql,
// admin-sessions-node-id.sql, apps/generic-node/drizzle/0002_admin_and_operations_ownership.sql)
// is missing tables/columns the runtime now assumes exist, and nothing in the runtime can
// self-heal that gap. Readiness must fail closed instead of discovering the gap as a query
// error mid-request (custody claim boundary).
//
// Mirrors privilege-readiness.ts's shape: one composing assert, small single-purpose
// helpers, a dedicated error naming exactly what's missing.

import type { PrivilegeSqlExecutor } from "./privilege-readiness.js";

export interface SchemaCompletenessOptions {
  readonly schemaName?: string;
}

export class SchemaCompletenessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SchemaCompletenessError";
  }
}

const REQUIRED_TABLES = ["admin_mutation_idempotency", "admin_operators"] as const;

const REQUIRED_COLUMNS = [
  { table: "operations", column: "response_status" },
  { table: "operations", column: "response_body" },
  { table: "admin_sessions", column: "node_id" },
] as const;

export async function assertSchemaCompleteness(
  db: PrivilegeSqlExecutor,
  options: SchemaCompletenessOptions = {},
): Promise<void> {
  const schemaName = options.schemaName ?? "public";
  await assertTablesExist(db, schemaName);
  await assertColumnsExist(db, schemaName);
}

async function assertTablesExist(db: PrivilegeSqlExecutor, schemaName: string): Promise<void> {
  const result = await db.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = $1 AND table_name = ANY($2::text[])`,
    [schemaName, REQUIRED_TABLES],
  );
  const found = new Set(result.rows.map((row) => row.table_name));
  const missing = REQUIRED_TABLES.filter((table) => !found.has(table));
  if (missing.length > 0) {
    throw new SchemaCompletenessError(
      `schema completeness: missing table(s) ${missing.join(", ")} in schema "${schemaName}" ` +
        `— migrations have not run against this database`,
    );
  }
}

async function assertColumnsExist(db: PrivilegeSqlExecutor, schemaName: string): Promise<void> {
  const result = await db.query<{ table_name: string; column_name: string }>(
    `SELECT table_name, column_name FROM information_schema.columns
     WHERE table_schema = $1`,
    [schemaName],
  );
  const found = new Set(result.rows.map((row) => `${row.table_name}.${row.column_name}`));
  const missing = REQUIRED_COLUMNS.filter(
    ({ table, column }) => !found.has(`${table}.${column}`),
  ).map(({ table, column }) => `${table}.${column}`);
  if (missing.length > 0) {
    throw new SchemaCompletenessError(
      `schema completeness: missing column(s) ${missing.join(", ")} in schema "${schemaName}" ` +
        `— migrations have not run against this database`,
    );
  }
}
