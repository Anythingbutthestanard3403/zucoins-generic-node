// Column-type convention lint (the data model database-wide conventions; mandatory database test 8
// "JSONB is absent from all authoritative-byte columns"; CONVENTIONS.md). Reuses the
// existing schema-text mechanism — parseTables from transaction-material-sql-parser.ts, the
// same parser the per-table census tests read the SQL through — rather than a new tool. It
// scans every src/schema/*.sql file and fails if any real column uses a float, arbitrary-
// precision numeric, or JSON/JSONB type: jsonb canonicalizes at rest and permanently destroys
// the signed byte layout; real/double precision/numeric lose or approximate the exact
// decimal a ZKZ amount must keep as canonical `text`. Nothing here executes SQL.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { parseTables } from "./transaction-material-sql-parser.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

// Forbidden column *type* tokens. `double precision` and `numeric(38,32)` both reduce to their
// first whitespace-delimited token in the parser (`double`, `numeric(38,32)`), so anchoring at
// the start with a trailing word boundary catches the parameterised numeric form too.
const FORBIDDEN_COLUMN_TYPE =
  /^(jsonb|json|real|numeric|decimal|float4|float8|float|double|money)\b/i;

// A `--` comment runs to end of line in PostgreSQL, and none of these schema files put `--`
// inside a string literal. Stripping every comment first keeps the single-file-tuned parser
// from choking on an in-body `-- note` and stops a forbidden word inside a comment from being
// read as a column type.
const stripSqlComments = (sql: string): string => sql.replace(/--.*$/gm, "");

interface Offender {
  readonly file: string;
  readonly location: string;
  readonly type: string;
}

const scanForbiddenColumns = (sql: string, file: string): Offender[] => {
  let tables;
  try {
    tables = parseTables(stripSqlComments(sql));
  } catch (error) {
    // A file the structural parser cannot read is itself a finding — surface it, never skip.
    return [{ file, location: `${file}:<unparseable>`, type: String(error) }];
  }
  return tables.flatMap((table) =>
    table.columns
      // Real columns are lowercase snake_case; the parser also yields pseudo-columns for
      // table-level UNIQUE/FOREIGN/CHECK/PRIMARY items (uppercase names) — drop those.
      .filter((column) => /^[a-z_][a-z0-9_]*$/.test(column.name))
      .filter((column) => FORBIDDEN_COLUMN_TYPE.test(column.typeText))
      .map((column) => ({
        file,
        location: `${table.name}.${column.name}`,
        type: column.typeText,
      })),
  );
};

const schemaFiles = readdirSync(schemaDir).filter((name) => name.endsWith(".sql"));

describe("schema column-type convention lint (the data model, mandatory database test 8; CONVENTIONS.md)", () => {
  it("scans a non-empty set of schema files", () => {
    expect(schemaFiles.length).toBeGreaterThan(0);
  });

  it("no authoritative-byte column uses a jsonb/json/real/double-precision/numeric type", () => {
    const offenders = schemaFiles.flatMap((file) =>
      scanForbiddenColumns(readFileSync(join(schemaDir, file), "utf8"), file),
    );
    expect(offenders).toEqual([]);
  });

  it("fires on a forbidden column type injected into real schema (negative path)", () => {
    const base = readFileSync(join(schemaDir, "submit-attempts.sql"), "utf8");
    // Inject a jsonb payload and a numeric money column into a live CREATE TABLE body.
    const tampered = base.replace(
      "  request_body bytea NOT NULL,",
      "  request_body bytea NOT NULL,\n  payload jsonb NOT NULL,\n  amount numeric(38,32) NOT NULL,",
    );
    expect(tampered).not.toBe(base);
    const offenders = scanForbiddenColumns(tampered, "submit-attempts.sql");
    expect(offenders.map((offender) => offender.type)).toContain("jsonb");
    expect(offenders.some((offender) => /^numeric/.test(offender.type))).toBe(true);
    // And the same bytes without the tamper are clean, proving the fire is caused by the type.
    expect(scanForbiddenColumns(base, "submit-attempts.sql")).toEqual([]);
  });
});
