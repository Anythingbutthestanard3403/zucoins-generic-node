/**
 * Row-evaluation model over the PARSED transaction-material.sql constraint surfaces
 * Every verdict here is derived from the real SQL bytes via
 * transaction-material-sql-parser.ts — no constraint is hand-redeclared. This is the
 * offline stand-in for the live negatives the mandatory database tests requires; discharging them against a real
 * database remains a schema-apply execution obligation (SCHEMA_TRANSACTION_MATERIAL_OBLIGATIONS).
 */

import {
  matchesDomain,
  parseNumericBound,
  parseOctetLengthPositive,
  parsePhaseChecks,
  phaseCheckExpectsNull,
  type ParsedDomain,
  type ParsedNumericBound,
  type ParsedTable,
} from "./transaction-material-sql-parser.ts";

export type RowValues = Readonly<Record<string, string | number | null>>;

export interface KeySet {
  readonly kind: "PRIMARY KEY" | "UNIQUE";
  readonly columns: readonly string[];
}

/** Uniqueness surfaces of a parsed table: its primary key plus each UNIQUE column. */
export const keySetsFor = (table: ParsedTable): KeySet[] => [
  { kind: "PRIMARY KEY", columns: table.primaryKey },
  ...table.uniqueColumns.map((column) => ({ kind: "UNIQUE", columns: [column] }) as const),
];

/**
 * The first uniqueness surface `candidate` collides with among `committed` rows, or null.
 * This is the structural core of the concurrency proof: a second insert that shares a key
 * set's values is the one a live database would reject.
 */
export const findKeyCollision = (
  committed: readonly RowValues[],
  candidate: RowValues,
  keySets: readonly KeySet[],
): KeySet | null => {
  for (const keySet of keySets) {
    if (keySet.columns.length === 0) {
      continue;
    }
    const collides = committed.some((row) =>
      keySet.columns.every((column) => row[column] === candidate[column]),
    );
    if (collides) {
      return keySet;
    }
  }
  return null;
};

export const evaluateNumericBound = (value: number, rule: ParsedNumericBound): boolean => {
  switch (rule.op) {
    case ">":
      return value > rule.bound;
    case ">=":
      return value >= rule.bound;
    case "<":
      return value < rule.bound;
    case "<=":
      return value <= rule.bound;
    case "=":
      return value === rule.bound;
  }
};

/**
 * Validates a candidate row against every parsed structural surface of its table:
 * nullability, domain formats, column CHECKs (numeric bounds and literal sets), the
 * octet-length table CHECK, and the biconditional phase/column CHECKs. Returns the ids of
 * the violated constraints (empty when the row would commit). Text values are ASCII in
 * every fixture, so octet length equals string length.
 */
export const validateRowAgainstTable = (
  table: ParsedTable,
  domains: readonly ParsedDomain[],
  row: RowValues,
): string[] => {
  const violations: string[] = [];
  for (const column of table.columns) {
    const value = row[column.name];
    if (value === null || value === undefined) {
      if (!column.nullable) {
        violations.push(`NOT NULL:${column.name}`);
      }
      continue;
    }
    const domain = domains.find((candidate) => candidate.name === column.typeText);
    if (domain !== undefined && typeof value === "string" && !matchesDomain(value, domain.checkText)) {
      violations.push(`DOMAIN:${column.name}`);
    }
    for (const predicate of column.columnChecks) {
      if (/\bIN\s*\(/.test(predicate)) {
        const allowed = [...predicate.matchAll(/'([A-Z0-9_]+)'/g)].map((match) => match[1]);
        if (!allowed.includes(String(value))) {
          violations.push(`PHASE_LITERAL:${column.name}`);
        }
        continue;
      }
      const bound = parseNumericBound(predicate);
      if (bound !== null && !evaluateNumericBound(Number(value), bound)) {
        violations.push(`CHECK:${column.name}`);
      }
    }
  }
  for (const predicate of table.tableChecks) {
    const octetColumn = parseOctetLengthPositive(predicate);
    if (octetColumn !== null) {
      const value = row[octetColumn];
      if (typeof value !== "string" || value.length === 0) {
        violations.push(`OCTET:${octetColumn}`);
      }
    }
  }
  const phase = row["attempt_phase"];
  if (typeof phase === "string") {
    for (const check of parsePhaseChecks(table)) {
      const value = row[check.column];
      const isNull = value === null || value === undefined;
      if (isNull !== phaseCheckExpectsNull(check, phase)) {
        violations.push(`PHASE:${check.column}`);
      }
    }
  }
  return violations;
};

export interface InsertVerdict {
  readonly committed: boolean;
  readonly violations: readonly string[];
  readonly rejectedByKey: KeySet | null;
}

/** Simulates one insert against committed rows: key collision first, then full validation. */
export const simulateInsert = (
  committed: readonly RowValues[],
  candidate: RowValues,
  table: ParsedTable,
  domains: readonly ParsedDomain[],
): InsertVerdict => {
  const rejectedByKey = findKeyCollision(committed, candidate, keySetsFor(table));
  if (rejectedByKey !== null) {
    return { committed: false, violations: [`${rejectedByKey.kind}:${rejectedByKey.columns.join("+")}`], rejectedByKey };
  }
  const violations = validateRowAgainstTable(table, domains, candidate);
  return { committed: violations.length === 0, violations, rejectedByKey: null };
};
