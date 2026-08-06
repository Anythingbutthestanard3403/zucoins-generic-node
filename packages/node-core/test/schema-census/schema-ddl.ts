// Dollar-quote-aware DDL introspection for frozen node-core schema contracts.
// Parses CREATE TABLE (columns + inline FKs), ALTER TABLE ADD CONSTRAINT FK,
// CREATE INDEX, and ON DELETE / ON UPDATE actions. Used by the
// schema-object census (reverse noun→table, orphan FK, cascade safety, index).

export type CascadeAction =
  | "NO ACTION"
  | "RESTRICT"
  | "CASCADE"
  | "SET NULL"
  | "SET DEFAULT"
  | "UNSPECIFIED";

export interface ColumnDef {
  readonly name: string;
  readonly definition: string;
}

export interface ForeignKey {
  readonly sourceFile: string;
  readonly sourceTable: string;
  readonly sourceColumns: readonly string[];
  readonly targetTable: string;
  readonly targetColumns: readonly string[];
  readonly onDelete: CascadeAction;
  readonly onUpdate: CascadeAction;
  readonly constraintName: string | null;
  /** Full clause text used for definition-sensitive cascade checks. */
  readonly clause: string;
}

export interface IndexDef {
  readonly sourceFile: string;
  readonly name: string;
  readonly table: string;
  readonly columns: readonly string[];
  readonly unique: boolean;
  readonly definition: string;
}

export interface TableDef {
  readonly sourceFile: string;
  readonly name: string;
  readonly columns: readonly ColumnDef[];
  readonly primaryKey: readonly string[];
  readonly definition: string;
}

export interface SchemaModel {
  readonly files: readonly string[];
  readonly tables: ReadonlyMap<string, TableDef>;
  /** table → column names (includes PK). */
  readonly columnsByTable: ReadonlyMap<string, ReadonlySet<string>>;
  readonly foreignKeys: readonly ForeignKey[];
  readonly indexes: readonly IndexDef[];
  /** Concatenated raw SQL per file (comments stripped). */
  readonly sqlByFile: ReadonlyMap<string, string>;
}

export const stripLineComments = (sql: string): string =>
  sql
    .split("\n")
    .map((line) => {
      const idx = line.indexOf("--");
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join("\n");

const normalizeWs = (text: string): string => text.replace(/\s+/g, " ").trim();

/** Split on semicolons outside $$ ... $$ dollar quotes. */
export const splitStatements = (sql: string): string[] => {
  const statements: string[] = [];
  let current = "";
  let inDollarQuote = false;
  for (let i = 0; i < sql.length; i += 1) {
    if (sql.startsWith("$$", i)) {
      inDollarQuote = !inDollarQuote;
      current += "$$";
      i += 1;
      continue;
    }
    const char = sql[i] ?? "";
    if (char === ";" && !inDollarQuote) {
      statements.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim().length > 0) {
    statements.push(current);
  }
  return statements.map((s) => s.trim()).filter((s) => s.length > 0);
};

const parenBody = (text: string, openIdx: number): string => {
  let depth = 0;
  for (let i = openIdx; i < text.length; i += 1) {
    const char = text[i];
    if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return text.slice(openIdx + 1, i);
    }
  }
  return text.slice(openIdx + 1);
};

/** Split top-level commas (depth-aware). */
const splitTopLevel = (body: string): string[] => {
  const parts: string[] = [];
  let current = "";
  let depth = 0;
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i] ?? "";
    if (char === "(") depth += 1;
    if (char === ")") depth -= 1;
    if (char === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim().length > 0) parts.push(current.trim());
  return parts.filter((p) => p.length > 0);
};

const parseCascade = (clause: string, kind: "DELETE" | "UPDATE"): CascadeAction => {
  const re = new RegExp(`ON\\s+${kind}\\s+(CASCADE|RESTRICT|SET\\s+NULL|SET\\s+DEFAULT|NO\\s+ACTION)`, "i");
  const match = re.exec(clause);
  if (!match) return "UNSPECIFIED";
  const raw = (match[1] ?? "").toUpperCase().replace(/\s+/g, " ");
  if (raw === "SET NULL") return "SET NULL";
  if (raw === "SET DEFAULT") return "SET DEFAULT";
  if (raw === "NO ACTION") return "NO ACTION";
  if (raw === "CASCADE") return "CASCADE";
  if (raw === "RESTRICT") return "RESTRICT";
  return "UNSPECIFIED";
};

const parseColumnList = (list: string): string[] =>
  list
    .split(",")
    .map((c) => c.trim())
    .filter((c) => c.length > 0)
    .map((c) => c.replace(/^"|"$/g, ""));

const TABLE_RE = /^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(/i;
const INDEX_RE =
  /^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+ON\s+(\w+)\s*\(([^)]+)\)/i;
const ALTER_FK_RE =
  /^ALTER\s+TABLE\s+(\w+)\s+ADD\s+CONSTRAINT\s+(\w+)\s+FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)\s*\(([^)]+)\)([\s\S]*)$/i;
const ALTER_FK_ANON_RE =
  /^ALTER\s+TABLE\s+(\w+)\s+ADD\s+FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)\s*\(([^)]+)\)([\s\S]*)$/i;

const INLINE_REF_RE = /\bREFERENCES\s+(\w+)\s*\(([^)]+)\)((?:\s+ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|RESTRICT|SET\s+NULL|SET\s+DEFAULT|NO\s+ACTION))*)/i;

const isTableConstraint = (part: string): boolean => {
  const upper = part.toUpperCase();
  return (
    upper.startsWith("CONSTRAINT") ||
    upper.startsWith("PRIMARY KEY") ||
    upper.startsWith("UNIQUE") ||
    upper.startsWith("CHECK") ||
    upper.startsWith("FOREIGN KEY") ||
    upper.startsWith("EXCLUDE")
  );
};

const parsePrimaryKey = (parts: readonly string[]): string[] => {
  for (const part of parts) {
    const tablePk = /^PRIMARY\s+KEY\s*\(([^)]+)\)/i.exec(part);
    if (tablePk) return parseColumnList(tablePk[1] ?? "");
    const namedPk = /^CONSTRAINT\s+\w+\s+PRIMARY\s+KEY\s*\(([^)]+)\)/i.exec(part);
    if (namedPk) return parseColumnList(namedPk[1] ?? "");
  }
  const inline: string[] = [];
  for (const part of parts) {
    if (isTableConstraint(part)) continue;
    if (/\bPRIMARY\s+KEY\b/i.test(part)) {
      const name = /^(\w+)\s+/.exec(part)?.[1];
      if (name) inline.push(name);
    }
  }
  return inline;
};

const parseTable = (file: string, statement: string): { table: TableDef; fks: ForeignKey[] } | null => {
  const definition = normalizeWs(statement);
  const head = TABLE_RE.exec(definition);
  if (!head) return null;
  const name = head[1] ?? "";
  const open = definition.indexOf("(");
  const body = parenBody(definition, open);
  const parts = splitTopLevel(body);
  const columns: ColumnDef[] = [];
  const fks: ForeignKey[] = [];

  for (const part of parts) {
    if (isTableConstraint(part)) {
      // Table-level FOREIGN KEY (col) REFERENCES t(col)
      const tableFk =
        /^(?:CONSTRAINT\s+(\w+)\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)\s*\(([^)]+)\)([\s\S]*)$/i.exec(
          part,
        );
      if (tableFk) {
        const clause = normalizeWs(part);
        fks.push({
          sourceFile: file,
          sourceTable: name,
          sourceColumns: parseColumnList(tableFk[2] ?? ""),
          targetTable: tableFk[3] ?? "",
          targetColumns: parseColumnList(tableFk[4] ?? ""),
          onDelete: parseCascade(clause, "DELETE"),
          onUpdate: parseCascade(clause, "UPDATE"),
          constraintName: tableFk[1] ?? null,
          clause,
        });
      }
      continue;
    }
    const colName = /^(\w+)\s+/.exec(part)?.[1];
    if (!colName) continue;
    columns.push({ name: colName, definition: normalizeWs(part) });
    const ref = INLINE_REF_RE.exec(part);
    if (ref) {
      const clause = normalizeWs(part);
      fks.push({
        sourceFile: file,
        sourceTable: name,
        sourceColumns: [colName],
        targetTable: ref[1] ?? "",
        targetColumns: parseColumnList(ref[2] ?? ""),
        onDelete: parseCascade(clause, "DELETE"),
        onUpdate: parseCascade(clause, "UPDATE"),
        constraintName: null,
        clause,
      });
    }
  }

  return {
    table: {
      sourceFile: file,
      name,
      columns,
      primaryKey: parsePrimaryKey(parts),
      definition,
    },
    fks,
  };
};

const parseIndex = (file: string, statement: string): IndexDef | null => {
  const definition = normalizeWs(statement);
  const match = INDEX_RE.exec(definition);
  if (!match) return null;
  return {
    sourceFile: file,
    name: match[2] ?? "",
    table: match[3] ?? "",
    columns: parseColumnList(match[4] ?? ""),
    unique: Boolean(match[1]),
    definition,
  };
};

const parseAlterFk = (file: string, statement: string): ForeignKey | null => {
  const definition = normalizeWs(statement);
  const named = ALTER_FK_RE.exec(definition);
  if (named) {
    const clause = definition;
    return {
      sourceFile: file,
      sourceTable: named[1] ?? "",
      sourceColumns: parseColumnList(named[3] ?? ""),
      targetTable: named[4] ?? "",
      targetColumns: parseColumnList(named[5] ?? ""),
      onDelete: parseCascade(clause, "DELETE"),
      onUpdate: parseCascade(clause, "UPDATE"),
      constraintName: named[2] ?? null,
      clause,
    };
  }
  const anon = ALTER_FK_ANON_RE.exec(definition);
  if (anon) {
    const clause = definition;
    return {
      sourceFile: file,
      sourceTable: anon[1] ?? "",
      sourceColumns: parseColumnList(anon[2] ?? ""),
      targetTable: anon[3] ?? "",
      targetColumns: parseColumnList(anon[4] ?? ""),
      onDelete: parseCascade(clause, "DELETE"),
      onUpdate: parseCascade(clause, "UPDATE"),
      constraintName: null,
      clause,
    };
  }
  return null;
};

export const parseSchemaSql = (
  files: readonly { readonly name: string; readonly sql: string }[],
): SchemaModel => {
  const tables = new Map<string, TableDef>();
  const columnsByTable = new Map<string, Set<string>>();
  const foreignKeys: ForeignKey[] = [];
  const indexes: IndexDef[] = [];
  const sqlByFile = new Map<string, string>();
  const fileNames: string[] = [];

  for (const { name, sql } of files) {
    fileNames.push(name);
    const stripped = stripLineComments(sql);
    sqlByFile.set(name, stripped);
    for (const statement of splitStatements(stripped)) {
      const tableParsed = parseTable(name, statement);
      if (tableParsed) {
        // First CREATE TABLE wins for name; later re-declares (self-contained fragments)
        // only fill missing columns.
        const existing = tables.get(tableParsed.table.name);
        if (!existing) {
          tables.set(tableParsed.table.name, tableParsed.table);
          columnsByTable.set(
            tableParsed.table.name,
            new Set(tableParsed.table.columns.map((c) => c.name)),
          );
        } else {
          const cols = columnsByTable.get(tableParsed.table.name) ?? new Set<string>();
          for (const col of tableParsed.table.columns) cols.add(col.name);
          columnsByTable.set(tableParsed.table.name, cols);
        }
        foreignKeys.push(...tableParsed.fks);
        continue;
      }
      const index = parseIndex(name, statement);
      if (index) {
        indexes.push(index);
        continue;
      }
      const fk = parseAlterFk(name, statement);
      if (fk) {
        foreignKeys.push(fk);
        continue;
      }
      // ALTER TABLE ... ADD COLUMN — fold into column set when present.
      const addCol =
        /^ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\b/i.exec(
          normalizeWs(statement),
        );
      if (addCol) {
        const tableName = addCol[1] ?? "";
        const colName = addCol[2] ?? "";
        const cols = columnsByTable.get(tableName) ?? new Set<string>();
        cols.add(colName);
        columnsByTable.set(tableName, cols);
      }
    }
  }

  // UNIQUE / PRIMARY KEY constraints act as indexes for access-pattern matching.
  for (const table of tables.values()) {
    if (table.primaryKey.length > 0) {
      indexes.push({
        sourceFile: table.sourceFile,
        name: `${table.name}_pkey`,
        table: table.name,
        columns: table.primaryKey,
        unique: true,
        definition: `PRIMARY KEY (${table.primaryKey.join(", ")})`,
      });
    }
    // Scan UNIQUE (cols) in definition body.
    for (const match of table.definition.matchAll(/\bUNIQUE\s*\(([^)]+)\)/gi)) {
      indexes.push({
        sourceFile: table.sourceFile,
        name: `${table.name}_unique_${indexes.length}`,
        table: table.name,
        columns: parseColumnList(match[1] ?? ""),
        unique: true,
        definition: normalizeWs(match[0] ?? ""),
      });
    }
  }

  return {
    files: fileNames,
    tables,
    columnsByTable,
    foreignKeys,
    indexes,
    sqlByFile,
  };
};

/** Merge extra SQL strings (for negative-path injection) as synthetic files. */
export const parseSchemaFromMap = (sqlByFile: ReadonlyMap<string, string>): SchemaModel =>
  parseSchemaSql([...sqlByFile.entries()].map(([name, sql]) => ({ name, sql })));
