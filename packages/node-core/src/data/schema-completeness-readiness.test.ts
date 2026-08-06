// unit proof of the fail-closed schema completeness gate (no live Postgres).
// Mirrors privilege-readiness.test.ts's scripted-executor shape so a broken table/column
// check fails the ordinary unit suite, not only PG_REQUIRED runs.
import { describe, expect, it } from "vitest";

import type { PrivilegeSqlExecutor, PrivilegeSqlQueryResult } from "./privilege-readiness.js";
import { assertSchemaCompleteness, SchemaCompletenessError } from "./schema-completeness-readiness.js";

function scriptedExecutor(
  tableRows: ReadonlyArray<{ table_name: string }>,
  columnRows: ReadonlyArray<{ table_name: string; column_name: string }>,
): PrivilegeSqlExecutor {
  let i = 0;
  return {
    async query<R>(text: string): Promise<PrivilegeSqlQueryResult<R>> {
      const step = i;
      i += 1;
      if (step === 0) {
        if (!/information_schema\.tables/.test(text)) {
          throw new Error(`expected table-existence query first, got: ${text}`);
        }
        return { rows: tableRows as R[] };
      }
      if (step === 1) {
        if (!/information_schema\.columns/.test(text)) {
          throw new Error(`expected column-existence query second, got: ${text}`);
        }
        return { rows: columnRows as R[] };
      }
      throw new Error(`unexpected query past scripted responses: ${text}`);
    },
  };
}

const ALL_TABLES = [{ table_name: "admin_mutation_idempotency" }, { table_name: "admin_operators" }];
const ALL_COLUMNS = [
  { table_name: "operations", column_name: "response_status" },
  { table_name: "operations", column_name: "response_body" },
  { table_name: "admin_sessions", column_name: "node_id" },
];

describe("assertSchemaCompleteness", () => {
  it("allows boot when every required table and column exists", async () => {
    const db = scriptedExecutor(ALL_TABLES, ALL_COLUMNS);
    await expect(assertSchemaCompleteness(db)).resolves.toBeUndefined();
  });

  it("refuses boot (fails closed) when a required table is missing, and does not self-heal", async () => {
    await expect(
      assertSchemaCompleteness(scriptedExecutor([{ table_name: "admin_operators" }], ALL_COLUMNS)),
    ).rejects.toBeInstanceOf(SchemaCompletenessError);
    await expect(
      assertSchemaCompleteness(scriptedExecutor([{ table_name: "admin_operators" }], ALL_COLUMNS)),
    ).rejects.toThrow(/missing table\(s\) admin_mutation_idempotency/);
  });

  it("refuses boot when a required column is missing", async () => {
    const db = scriptedExecutor(ALL_TABLES, [
      { table_name: "operations", column_name: "response_status" },
      { table_name: "admin_sessions", column_name: "node_id" },
    ]);
    await expect(assertSchemaCompleteness(db)).rejects.toThrow(
      /missing column\(s\) operations\.response_body/,
    );
  });

  it("lists every missing column together", async () => {
    const db = scriptedExecutor(ALL_TABLES, []);
    await expect(assertSchemaCompleteness(db)).rejects.toThrow(
      /operations\.response_status, operations\.response_body, admin_sessions\.node_id/,
    );
  });

  it("checks tables before columns and stops at the first failure", async () => {
    const db = scriptedExecutor([], []);
    await expect(assertSchemaCompleteness(db)).rejects.toThrow(/missing table\(s\)/);
  });

  it("scopes the check to the given schema name", async () => {
    const db = scriptedExecutor(ALL_TABLES, ALL_COLUMNS);
    let sawSchema: string | undefined;
    const spied: PrivilegeSqlExecutor = {
      async query<R>(text: string, params?: readonly unknown[]) {
        sawSchema = params?.[0] as string;
        return db.query<R>(text);
      },
    };
    await assertSchemaCompleteness(spied, { schemaName: "custom_schema" });
    expect(sawSchema).toBe("custom_schema");
  });
});
