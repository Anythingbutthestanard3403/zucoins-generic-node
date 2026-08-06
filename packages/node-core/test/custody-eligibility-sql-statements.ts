// a single-pass, left-to-right, fail-closed lexer over custody-eligibility.sql
// This is a sibling to custody-eligibility-sql-parser.ts, not a replacement:
// that file extracts vocabulary (enum members, admitted-state lists) via targeted regex
// against the whole file; this file establishes STRUCTURE — an exhaustive statement
// inventory, a shape per statement, and a forbidden-token scan — so that a statement
// appended or substituted anywhere in the file cannot go unnoticed by the census guard.
//
// Single-pass is load-bearing: scanning left to right exactly once, closing a statement
// the instant an unmasked `;` is seen, eliminates any "strip comments, then strip strings,
// then split" ordering ambiguity. A multi-pass strip could let a `-- $$` comment pair open
// a dollar-quoted region that swallows real statements that follow it; a single pass never
// revisits text it already classified.

export interface SqlStatement {
  readonly index: number;
  readonly line: number;
  readonly raw: string;
  readonly masked: string;
  readonly canon: string;
}

const collapse = (text: string): string => text.trim().replace(/\s+/g, " ");

const lineAt = (sql: string, offset: number): number => sql.slice(0, offset).split("\n").length;

const DOLLAR_TAG_OPEN = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;

export const tokenizeCustodySql = (sql: string): SqlStatement[] => {
  if (/[^\x20-\x7e\n]/.test(sql)) {
    throw new Error("custody sql: non-ASCII byte");
  }

  const statements: SqlStatement[] = [];
  let i = 0;
  let statementStart = 0;
  let masked = "";
  let canon = "";
  let index = 0;

  const closeStatement = (endOffset: number): void => {
    if (masked.trim().length === 0) {
      throw new Error(`custody sql: empty statement at offset ${statementStart}`);
    }
    // Report the line of the statement's first non-whitespace character, not of
    // statementStart: that offset sits immediately after the previous statement's
    // terminator, so using it directly would blame the preceding line.
    const leadingWhitespace = /^\s*/.exec(sql.slice(statementStart, endOffset));
    const spanStart = statementStart + (leadingWhitespace === null ? 0 : leadingWhitespace[0].length);
    statements.push({
      index,
      line: lineAt(sql, spanStart),
      raw: sql.slice(statementStart, endOffset),
      masked: collapse(masked),
      canon: collapse(canon),
    });
    index += 1;
    masked = "";
    canon = "";
    statementStart = endOffset;
  };

  while (i < sql.length) {
    const rest = sql.slice(i);

    if (rest.startsWith("/*")) {
      throw new Error("custody sql: block comments not permitted (nesting-ambiguous)");
    }

    if (/^[EeUuBbXx]'/.test(rest) || rest.startsWith("U&'")) {
      throw new Error("custody sql: prefixed string literals not permitted");
    }

    if (rest.startsWith('"')) {
      throw new Error("custody sql: quoted identifiers not permitted");
    }

    if (rest.startsWith("\\")) {
      throw new Error("custody sql: psql backslash command not permitted");
    }

    if (rest.startsWith("--")) {
      const newlineOffset = sql.indexOf("\n", i);
      const end = newlineOffset === -1 ? sql.length : newlineOffset + 1;
      masked += "\n";
      canon += " ";
      i = end;
      continue;
    }

    if (rest.startsWith("'")) {
      const literalStart = i;
      let j = i + 1;
      let closed = false;
      while (j < sql.length) {
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") {
            j += 2;
            continue;
          }
          j += 1;
          closed = true;
          break;
        }
        j += 1;
      }
      if (!closed) {
        throw new Error(`custody sql: unterminated string literal at offset ${literalStart}`);
      }
      masked += "''";
      canon += sql.slice(literalStart, j);
      i = j;
      continue;
    }

    const dollarMatch = DOLLAR_TAG_OPEN.exec(rest);
    if (dollarMatch !== null) {
      const tag = dollarMatch[0];
      const quoteStart = i;
      const closeOffset = sql.indexOf(tag, i + tag.length);
      if (closeOffset === -1) {
        throw new Error(`custody sql: unterminated dollar-quote ${tag} at offset ${quoteStart}`);
      }
      const end = closeOffset + tag.length;
      masked += "''";
      canon += sql.slice(quoteStart, end);
      i = end;
      continue;
    }

    if (rest[0] === ";") {
      masked += ";";
      canon += ";";
      i += 1;
      closeStatement(i);
      continue;
    }

    masked += rest[0];
    canon += rest[0];
    i += 1;
  }

  if (masked.trim().length > 0) {
    throw new Error("custody sql: trailing text after final semicolon");
  }

  return statements;
};

export type StatementKind =
  | "CREATE TYPE"
  | "CREATE TABLE"
  | "ALTER TABLE ADD CONSTRAINT"
  | "CREATE FUNCTION"
  | "CREATE TRIGGER";

export interface CustodyStatementInventoryEntry {
  readonly kind: StatementKind;
  readonly objectName: string;
  readonly shape: RegExp;
}

// One shared, $-anchored shape per kind (NOT tailored per object name — the object name
// is a separate equality check the census test derives independently, so a shape match and
// a name match are two distinct signals rather than one regex doing both jobs). These are
// the exact working forms verified by running the tokenizer against the real file and
// printing each statement's `masked` text.
const SHAPE_BY_KIND: Record<StatementKind, RegExp> = {
  "CREATE TYPE": /^CREATE TYPE \w+ AS ENUM \(.*\);$/,
  "CREATE TABLE": /^CREATE TABLE \w+ \(.*\);$/,
  "ALTER TABLE ADD CONSTRAINT":
    /^ALTER TABLE \w+ ADD CONSTRAINT \w+ FOREIGN KEY \(\w+\) REFERENCES \w+ \(\w+\);$/,
  "CREATE FUNCTION": /^CREATE FUNCTION \w+\(\) RETURNS trigger AS '' LANGUAGE plpgsql;$/,
  "CREATE TRIGGER":
    /^CREATE TRIGGER \w+ BEFORE (INSERT|UPDATE) ON \w+ FOR EACH ROW EXECUTE FUNCTION \w+\(\);$/,
};

// Ordered, 11-entry inventory of every statement custody-eligibility.sql carries. The
// order, count, and interleaving of functions/triggers (positions 6-11) mirror the real
// file exactly; the ALTER at position 3 sits between the wallet_recovery_verifications and
// destinations table statements, matching the file's own ordering.
//
// The three leading CREATE TYPE statements are gone. They re-declared 04
// enumerations that base-enums-domains.sql already declares, so once this file became
// prerequisite-bound (it now references the domains, which only that same base contract
// creates) they were guaranteed "type already exists" failures at execution time.
export const CUSTODY_STATEMENT_INVENTORY: readonly CustodyStatementInventoryEntry[] = [
  { kind: "CREATE TABLE", objectName: "wallets", shape: SHAPE_BY_KIND["CREATE TABLE"] },
  {
    kind: "CREATE TABLE",
    objectName: "wallet_recovery_verifications",
    shape: SHAPE_BY_KIND["CREATE TABLE"],
  },
  {
    kind: "ALTER TABLE ADD CONSTRAINT",
    objectName: "wallets_recovery_verification_fk",
    shape: SHAPE_BY_KIND["ALTER TABLE ADD CONSTRAINT"],
  },
  { kind: "CREATE TABLE", objectName: "destinations", shape: SHAPE_BY_KIND["CREATE TABLE"] },
  {
    kind: "CREATE TABLE",
    objectName: "wallet_active_leases",
    shape: SHAPE_BY_KIND["CREATE TABLE"],
  },
  {
    kind: "CREATE FUNCTION",
    objectName: "custody_reject_wallet_mutation",
    shape: SHAPE_BY_KIND["CREATE FUNCTION"],
  },
  {
    kind: "CREATE TRIGGER",
    objectName: "wallets_custody_mutation_guard",
    shape: SHAPE_BY_KIND["CREATE TRIGGER"],
  },
  {
    kind: "CREATE FUNCTION",
    objectName: "custody_reject_destination_insert",
    shape: SHAPE_BY_KIND["CREATE FUNCTION"],
  },
  {
    kind: "CREATE TRIGGER",
    objectName: "destinations_custody_insert_guard",
    shape: SHAPE_BY_KIND["CREATE TRIGGER"],
  },
  {
    kind: "CREATE FUNCTION",
    objectName: "custody_reject_ineligible_lease",
    shape: SHAPE_BY_KIND["CREATE FUNCTION"],
  },
  {
    kind: "CREATE TRIGGER",
    objectName: "wallet_active_leases_eligibility_guard",
    shape: SHAPE_BY_KIND["CREATE TRIGGER"],
  },
] as const;

export interface ForbiddenSqlPattern {
  readonly pattern: RegExp;
  readonly reason: string;
}

// Scanned against `canon` (comments blanked, string/dollar-quote bodies retained verbatim)
// so a destructive statement smuggled inside a trigger function body is caught, not
// stripped away with the rest of the dollar-quoted text. Bare ALTER, INSERT, UPDATE, and
// EXECUTE are intentionally NOT forbidden: they occur legitimately in "BEFORE INSERT ON" /
// "BEFORE UPDATE ON" trigger declarations, "EXECUTE FUNCTION" trigger bindings, and
// statement 6's additive ALTER TABLE ... ADD CONSTRAINT. SET, PERFORM, and DISABLE TRIGGER
// do NOT appear in the frozen file and are forbidden: SET mutates session/transaction state,
// PERFORM discards SQL execution results, and DISABLE TRIGGER bypasses guard triggers.
export const FORBIDDEN_SQL_PATTERNS: readonly ForbiddenSqlPattern[] = [
  { pattern: /\bDROP\b/i, reason: "DROP is not permitted in a frozen additive-only schema contract" },
  { pattern: /\bCASCADE\b/i, reason: "CASCADE is not permitted (unbounded blast radius)" },
  { pattern: /\bTRUNCATE\b/i, reason: "TRUNCATE is not permitted" },
  { pattern: /\bDELETE\s+FROM\b/i, reason: "DELETE FROM is not permitted in a DDL-only contract" },
  { pattern: /\bINSERT\s+INTO\b/i, reason: "INSERT INTO is not permitted in a DDL-only contract" },
  { pattern: /\bUPDATE\s+\w+\s+SET\b/i, reason: "UPDATE ... SET is not permitted in a DDL-only contract" },
  { pattern: /\bGRANT\b/i, reason: "GRANT is not permitted" },
  { pattern: /\bREVOKE\b/i, reason: "REVOKE is not permitted" },
  { pattern: /\bOWNER\s+TO\b/i, reason: "OWNER TO is not permitted" },
  { pattern: /\bRENAME\b/i, reason: "RENAME is not permitted" },
  { pattern: /\bCOMMENT\s+ON\b/i, reason: "COMMENT ON is not permitted" },
  {
    pattern: /\bCREATE\s+(RULE|POLICY|INDEX|SCHEMA|EXTENSION)\b/i,
    reason: "CREATE RULE/POLICY/INDEX/SCHEMA/EXTENSION is outside the inventoried statement set",
  },
  { pattern: /\bOR\s+REPLACE\b/i, reason: "OR REPLACE is not permitted (silent redefinition)" },
  { pattern: /\bSECURITY\s+DEFINER\b/i, reason: "SECURITY DEFINER is not permitted" },
  {
    pattern: /\bLANGUAGE\s+(?!plpgsql\b)/i,
    reason: "only LANGUAGE plpgsql is permitted",
  },
  {
    pattern: /\bEXECUTE\s+(?!FUNCTION\b|PROCEDURE\b)/i,
    reason: "EXECUTE is only permitted as EXECUTE FUNCTION/PROCEDURE (trigger binding)",
  },
  { pattern: /\bCOPY\b/i, reason: "COPY is not permitted" },
  { pattern: /\bpg_read_file\b/i, reason: "pg_read_file is not permitted" },
  { pattern: /\bpg_ls_dir\b/i, reason: "pg_ls_dir is not permitted" },
  { pattern: /\blo_(import|export)\b/i, reason: "large object import/export is not permitted" },
  { pattern: /\bdblink\b/i, reason: "dblink is not permitted" },
  { pattern: /\bSET\b/i, reason: "SET is not permitted (session/transaction state mutation)" },
  { pattern: /\bPERFORM\b/i, reason: "PERFORM is not permitted (discarded SQL execution)" },
  { pattern: /\bDISABLE\s+TRIGGER\b/i, reason: "DISABLE TRIGGER is not permitted (guard bypass)" },
  { pattern: /\bCHECK\s*\(\s*true\s*\)/i, reason: "CHECK (true) is a no-op predicate (constraint neutered)" },
  { pattern: /\bOR\s+TRUE\b/i, reason: "OR TRUE weakens a predicate to a tautology" },
] as const;

// Semantic pins: critical content that must appear in a specific statement's canon. The
// per-kind shape regexes are generic (one $-anchored pattern per statement KIND, not per
// object); they confirm the statement's envelope but not its load-bearing internals. Pins
// close that gap: the PK clause enforcing the one-in-flight-per-wallet rule, the RAISE EXCEPTION tokens that
// make trigger guards actually reject, and the CHECK predicates that bind recovery-field
// invariants. Each pin is checked against `canon` (comments blanked, string/dollar-quote
// bodies verbatim) so a mutation that comments out a RAISE or replaces a CHECK predicate
// with CHECK (true) is caught even though the statement's shape still matches.
export interface SemanticPin {
  readonly statementIndex: number;
  readonly objectName: string;
  readonly anchor: string;
  readonly rule: string;
}

export const CUSTODY_SEMANTIC_PINS: readonly SemanticPin[] = [
  {
    statementIndex: 4,
    objectName: "wallet_active_leases",
    anchor: "wallet_id uuid PRIMARY KEY REFERENCES wallets (id)",
    rule: "The one-in-flight-per-wallet rule: one in-flight transaction per wallet, enforced by PK on wallet_id",
  },
  {
    statementIndex: 5,
    objectName: "custody_reject_wallet_mutation",
    anchor: "RAISE EXCEPTION 'CUSTODY_IMMUTABLE_FIELD_REJECTED'",
    rule: "wallet-mutation guard must reject immutable-field changes",
  },
  {
    statementIndex: 5,
    objectName: "custody_reject_wallet_mutation",
    anchor: "RAISE EXCEPTION 'CUSTODY_RECOVERY_NEVER_CLEARED'",
    rule: "wallet-mutation guard must reject recovery-field clearing",
  },
  {
    statementIndex: 7,
    objectName: "custody_reject_destination_insert",
    anchor: "RAISE EXCEPTION 'CUSTODY_DESTINATION_ORIGIN_REJECTED'",
    rule: "destination-insert guard must reject non-node_generated origins",
  },
  {
    statementIndex: 7,
    objectName: "custody_reject_destination_insert",
    anchor: "RAISE EXCEPTION 'CUSTODY_TENANT_MISMATCH_REJECTED'",
    rule: "destination-insert guard must reject cross-tenant rows",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED'",
    rule: "lease guard must reject imported-origin wallets at every claim boundary",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED'",
    rule: "lease guard must require BLESSED destination for automatic-sink",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED'",
    rule: "lease guard must require recovery verification for automatic-sink",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED'",
    rule: "lease guard must deny wallet states outside the allowlist for every non-RECONCILIATION role (custody rule 3)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE",
    rule: "lease eligibility trigger locks the wallet row FOR UPDATE",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "IF NEW.lease_role = 'RECEIVE_WINDOW' THEN",
    rule: "RECEIVE_WINDOW branch is present on the structural backstop",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_ROLE_UNKNOWN'",
    rule: "unknown lease_role fails closed",
  },
  {
    statementIndex: 0,
    objectName: "wallets",
    anchor: "CHECK ((recovery_verified_at IS NULL) = (recovery_verification_id IS NULL))",
    rule: "recovery fields are set together or not at all",
  },
] as const;

// Body-structure pins: each anchor must appear BEFORE the first RETURN NEW in the statement's
// canon. Semantic pins (above) prove the anchor text EXISTS in the body; body-structure pins
// prove it is REACHABLE — i.e. not dead code after an early RETURN NEW that guts the guard.
// This catches the "early RETURN NEW + RAISE preserved only in comments" mutation class that
// semantic pins alone cannot distinguish from the pristine file.
export interface BodyStructurePin {
  readonly statementIndex: number;
  readonly objectName: string;
  readonly anchor: string;
  readonly rule: string;
}

export const CUSTODY_BODY_STRUCTURE_PINS: readonly BodyStructurePin[] = [
  {
    statementIndex: 5,
    objectName: "custody_reject_wallet_mutation",
    anchor: "RAISE EXCEPTION 'CUSTODY_IMMUTABLE_FIELD_REJECTED'",
    rule: "immutable-field RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 5,
    objectName: "custody_reject_wallet_mutation",
    anchor: "RAISE EXCEPTION 'CUSTODY_RECOVERY_NEVER_CLEARED'",
    rule: "recovery-never-cleared RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 7,
    objectName: "custody_reject_destination_insert",
    anchor: "RAISE EXCEPTION 'CUSTODY_DESTINATION_ORIGIN_REJECTED'",
    rule: "destination-origin RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 7,
    objectName: "custody_reject_destination_insert",
    anchor: "RAISE EXCEPTION 'CUSTODY_TENANT_MISMATCH_REJECTED'",
    rule: "tenant-mismatch RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED'",
    rule: "lease-origin RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_DESTINATION_NOT_BLESSED'",
    rule: "destination-not-blessed RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_RECOVERY_UNVERIFIED'",
    rule: "recovery-unverified RAISE must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "SELECT * INTO wallet_row FROM wallets WHERE id = NEW.wallet_id FOR UPDATE",
    rule: "FOR UPDATE wallet lock must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "IF NEW.lease_role = 'RECEIVE_WINDOW' THEN",
    rule: "RECEIVE_WINDOW branch must precede RETURN NEW (reachable, not dead code)",
  },
  {
    statementIndex: 9,
    objectName: "custody_reject_ineligible_lease",
    anchor: "RAISE EXCEPTION 'CUSTODY_LEASE_WALLET_STATE_REJECTED'",
    rule: "wallet-state RAISE must precede RETURN NEW (reachable, not dead code)",
  },
] as const;
