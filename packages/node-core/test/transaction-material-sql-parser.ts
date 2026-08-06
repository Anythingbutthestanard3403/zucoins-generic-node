/**
 * Pure, dependency-free parsing helpers over the literal transaction-material.sql text
 * The census test, the breaking-input tests, and the docs-artifact
 * test all read the SQL through these helpers, so no test carries a hand-maintained copy of
 * the constraint surfaces — the SQL file stays the single source, matched against the real
 * bytes on disk. Nothing here executes SQL; it is structural text analysis only.
 */

export interface ParsedDomain {
  readonly name: string;
  readonly baseType: string;
  readonly checkText: string;
}

export interface ParsedColumn {
  readonly name: string;
  readonly typeText: string;
  readonly nullable: boolean;
  readonly unique: boolean;
  readonly inlinePrimaryKey: boolean;
  readonly columnChecks: readonly string[];
  readonly raw: string;
}

export interface ParsedTable {
  readonly name: string;
  readonly columns: readonly ParsedColumn[];
  readonly primaryKey: readonly string[];
  readonly uniqueColumns: readonly string[];
  readonly tableChecks: readonly string[];
  readonly raw: string;
}

export interface ParsedPhaseCheck {
  readonly column: string;
  /** Phases in which the column must be NULL (see `negated`). */
  readonly phases: readonly string[];
  /** True for the `<>` form: the column must be NULL in every phase NOT listed. */
  readonly negated: boolean;
  readonly predicate: string;
}

export interface ParsedNumericBound {
  readonly column: string;
  readonly op: ">=" | "<=" | ">" | "<" | "=";
  readonly bound: number;
}

/** Extracts the content of the balanced parenthesised group starting at `openIndex`. */
const extractBalanced = (text: string, openIndex: number): string => {
  let depth = 0;
  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index];
    if (char === "(") {
      depth += 1;
    } else if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        return text.slice(openIndex + 1, index);
      }
    }
  }
  throw new Error("transaction-material parser: unbalanced parentheses");
};

/** Splits a CREATE TABLE body into items on commas at paren depth zero. */
const splitTopLevel = (body: string): string[] => {
  const items: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of body) {
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (char === "," && depth === 0) {
      items.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  const tail = current.trim();
  if (tail.length > 0) {
    items.push(tail);
  }
  return items.filter((item) => item.length > 0);
};

/** Extracts every CHECK predicate text (balanced outer content) from a definition item. */
const extractCheckPredicates = (item: string): string[] => {
  const predicates: string[] = [];
  let searchFrom = 0;
  for (;;) {
    const checkAt = item.indexOf("CHECK", searchFrom);
    if (checkAt === -1) {
      return predicates;
    }
    const openAt = item.indexOf("(", checkAt);
    if (openAt === -1) {
      return predicates;
    }
    const predicate = extractBalanced(item, openAt);
    predicates.push(predicate);
    searchFrom = openAt + predicate.length + 2;
  }
};

const TABLE_BLOCK_PATTERN = /CREATE TABLE (\w+) \(\n([\s\S]*?)\n\);/g;
const DOMAIN_BLOCK_PATTERN = /CREATE DOMAIN (\w+) AS (\w+)\n\s*CHECK \(([\s\S]*?)\);/g;

/** Parses every CREATE TABLE block into its structural constraint surfaces. */
export const parseTables = (sql: string): ParsedTable[] => {
  const tables: ParsedTable[] = [];
  for (const match of sql.matchAll(TABLE_BLOCK_PATTERN)) {
    const [, name, body] = match;
    const columns: ParsedColumn[] = [];
    const tableChecks: string[] = [];
    const primaryKey: string[] = [];
    const uniqueColumns: string[] = [];
    for (const item of splitTopLevel(body)) {
      if (/^PRIMARY KEY\b/.test(item)) {
        const columnList = extractBalanced(item, item.indexOf("("));
        primaryKey.push(...columnList.split(",").map((column) => column.trim()));
        continue;
      }
      if (/^CHECK\b/.test(item)) {
        tableChecks.push(...extractCheckPredicates(item));
        continue;
      }
      const columnName = /^(\w+)/.exec(item)?.[1];
      if (columnName === undefined) {
        throw new Error(`transaction-material parser: unrecognised item in ${name}: ${item}`);
      }
      const unique = /\bUNIQUE\b/.test(item);
      const inlinePrimaryKey = /\bPRIMARY KEY\b/.test(item);
      if (unique) uniqueColumns.push(columnName);
      if (inlinePrimaryKey) primaryKey.push(columnName);
      columns.push({
        name: columnName,
        typeText: item.slice(columnName.length).trim().split(/\s+/)[0] ?? "",
        // An inline PRIMARY KEY is implicitly NOT NULL in SQL — record it as such.
        nullable: !/\bNOT NULL\b/.test(item) && !/\bPRIMARY KEY\b/.test(item),
        unique,
        inlinePrimaryKey,
        columnChecks: extractCheckPredicates(item),
        raw: item,
      });
    }
    tables.push({ name, columns, primaryKey, uniqueColumns, tableChecks, raw: match[0] });
  }
  return tables;
};

export const tableByName = (tables: readonly ParsedTable[], name: string): ParsedTable => {
  const table = tables.find((candidate) => candidate.name === name);
  if (table === undefined) {
    throw new Error(`transaction-material parser: table ${name} not found`);
  }
  return table;
};

/** Parses every CREATE DOMAIN statement (reference scalar checks). */
export const parseDomains = (sql: string): ParsedDomain[] =>
  [...sql.matchAll(DOMAIN_BLOCK_PATTERN)].map((match) => ({
    name: match[1],
    baseType: match[2],
    checkText: match[3],
  }));

/** The attempt_phase literal ladder, parsed from the column CHECK in declaration sequence. */
export const parseAttemptPhaseLiterals = (table: ParsedTable): string[] => {
  const phaseColumn = table.columns.find((column) => column.name === "attempt_phase");
  const check = phaseColumn?.columnChecks.find((predicate) => predicate.includes("attempt_phase IN"));
  if (check === undefined) {
    throw new Error("transaction-material parser: attempt_phase IN (...) check not found");
  }
  return [...check.matchAll(/'([A-Z0-9_]+)'/g)].map((match) => match[1]);
};

const PHASE_CHECK_SINGLE = /^\(attempt_phase = '([A-Z0-9_]+)'\) = \((\w+) IS NULL\)$/;
const PHASE_CHECK_MULTI = /^\(attempt_phase IN\s*\(([\s\S]*?)\)\) =\s*\((\w+) IS NULL\)$/;
const PHASE_CHECK_NEGATED = /^\(attempt_phase <> '([A-Z0-9_]+)'\) = \((\w+) IS NULL\)$/;

/**
 * Parses the paired phase/column CHECKs. Each accepted form is biconditional (boolean `=`
 * between the phase predicate and the `IS NULL` predicate); a weakened implication form
 * matches no grammar rule and silently drops out — the census asserts the count stays 7.
 */
export const parsePhaseChecks = (table: ParsedTable): ParsedPhaseCheck[] => {
  const checks: ParsedPhaseCheck[] = [];
  for (const predicate of table.tableChecks) {
    const single = PHASE_CHECK_SINGLE.exec(predicate);
    if (single !== null) {
      checks.push({ column: single[2], phases: [single[1]], negated: false, predicate });
      continue;
    }
    const multi = PHASE_CHECK_MULTI.exec(predicate);
    if (multi !== null) {
      const phases = [...multi[1].matchAll(/'([A-Z0-9_]+)'/g)].map((match) => match[1]);
      checks.push({ column: multi[2], phases, negated: false, predicate });
      continue;
    }
    const negated = PHASE_CHECK_NEGATED.exec(predicate);
    if (negated !== null) {
      checks.push({ column: negated[2], phases: [negated[1]], negated: true, predicate });
    }
  }
  return checks;
};

/** Whether a parsed phase check requires `column` to be NULL at `phase`. */
export const phaseCheckExpectsNull = (check: ParsedPhaseCheck, phase: string): boolean =>
  check.negated ? !check.phases.includes(phase) : check.phases.includes(phase);

/** Parses a simple `column op integer` CHECK predicate (e.g. `lease_epoch > 0`). */
export const parseNumericBound = (predicate: string): ParsedNumericBound | null => {
  const match = /^(\w+)\s*(>=|<=|>|<|=)\s*(-?\d+)$/.exec(predicate);
  if (match === null) {
    return null;
  }
  return { column: match[1], op: match[2] as ParsedNumericBound["op"], bound: Number(match[3]) };
};

/** Parses an `octet_length(column) > 0` CHECK predicate into the column it guards. */
export const parseOctetLengthPositive = (predicate: string): string | null =>
  /^octet_length\((\w+)\) > 0$/.exec(predicate)?.[1] ?? null;

/** Evaluates a value against a parsed domain CHECK text (length and regex conjuncts). */
export const matchesDomain = (value: string, checkText: string): boolean =>
  checkText.split(" AND ").every((conjunct) => {
    const lengthMatch = /^length\(VALUE\) = (\d+)$/.exec(conjunct.trim());
    if (lengthMatch !== null) {
      return value.length === Number(lengthMatch[1]);
    }
    const regexMatch = /^VALUE ~ '(.*)'$/.exec(conjunct.trim());
    if (regexMatch !== null) {
      return new RegExp(regexMatch[1]).test(value);
    }
    throw new Error(`transaction-material parser: unsupported domain conjunct: ${conjunct}`);
  });
