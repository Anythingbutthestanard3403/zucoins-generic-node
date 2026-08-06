// adversarial coverage for the custody-eligibility.sql structural guard
// (tokenizeCustodySql + CUSTODY_STATEMENT_INVENTORY + FORBIDDEN_SQL_PATTERNS, backstopped
// by the sha256 freeze pin in custody-eligibility.census.test.ts). Every mutant here is a
// verified bypass of a naive substring-anchor guard: each is built as an in-memory string
// fixture derived from the real file text and MUST be rejected by the full structural
// guard. Nothing here is ever written to disk.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CUSTODY_SCHEMA_FILE, CUSTODY_SCHEMA_INVARIANTS } from "../src/schema/custody-eligibility.contract.ts";
import {
  CUSTODY_BODY_STRUCTURE_PINS,
  CUSTODY_SEMANTIC_PINS,
  CUSTODY_STATEMENT_INVENTORY,
  FORBIDDEN_SQL_PATTERNS,
  tokenizeCustodySql,
  type StatementKind,
} from "./custody-eligibility-sql-statements.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CUSTODY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

// Same extraction used by the census test: derives the object name a statement actually
// declares, independent of the generic per-kind shape regex.
const extractObjectName = (kind: StatementKind, masked: string): string | null => {
  switch (kind) {
    case "CREATE TYPE":
      return /^CREATE TYPE (\w+) AS ENUM/.exec(masked)?.[1] ?? null;
    case "CREATE TABLE":
      return /^CREATE TABLE (\w+) \(/.exec(masked)?.[1] ?? null;
    case "ALTER TABLE ADD CONSTRAINT":
      return /^ALTER TABLE \w+ ADD CONSTRAINT (\w+) FOREIGN KEY/.exec(masked)?.[1] ?? null;
    case "CREATE FUNCTION":
      return /^CREATE FUNCTION (\w+)\(\)/.exec(masked)?.[1] ?? null;
    case "CREATE TRIGGER":
      return /^CREATE TRIGGER (\w+) BEFORE/.exec(masked)?.[1] ?? null;
  }
};

// The STRUCTURAL guard: tokenizer success + statement count + per-index (kind, objectName,
// shape) + forbidden-pattern scan + semantic pins + body-structure pins. Returns true the
// moment ANY structural layer rejects the input; false only if the input passes every layer.
// The sha256 hash pin is deliberately EXCLUDED here — it has its own dedicated test in
// custody-eligibility.census.test.ts. This function measures ONLY the structural layers so
// mutation assertions prove those layers catch each mutant on their own merits.

// Produces a comment-stripped, whitespace-collapsed view of a statement's raw text. Operates
// on `raw` (which preserves newlines) so line-by-line comment stripping works correctly; the
// pre-collapsed `canon` is a single line where stripping from `--` to EOL would remove
// everything after the first comment. Safe for this frozen file: no string literal in
// custody-eligibility.sql contains `--`.
const strippedCanon = (raw: string): string =>
  raw
    .split("\n")
    .map((line) => {
      const idx = line.indexOf("--");
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

const guardRejects = (mutant: string): boolean => {
  let statements;
  try {
    statements = tokenizeCustodySql(mutant);
  } catch {
    return true;
  }

  if (statements.length !== CUSTODY_STATEMENT_INVENTORY.length) {
    return true;
  }

  const inventoryMismatch = CUSTODY_STATEMENT_INVENTORY.some((entry, i) => {
    const statement = statements[i];
    if (!entry.shape.test(statement.masked)) return true;
    return extractObjectName(entry.kind, statement.masked) !== entry.objectName;
  });
  if (inventoryMismatch) return true;

  const forbiddenHit = statements.some((statement) =>
    FORBIDDEN_SQL_PATTERNS.some((forbidden) => forbidden.pattern.test(statement.canon)),
  );
  if (forbiddenHit) return true;

  // Semantic pins: anchor must be present in the comment-stripped raw (so anchors
  // preserved only in comments do NOT satisfy the pin).
  const semanticPinMiss = CUSTODY_SEMANTIC_PINS.some((pin) => {
    const stripped = strippedCanon(statements[pin.statementIndex].raw);
    return !stripped.includes(pin.anchor);
  });
  if (semanticPinMiss) return true;

  // Body-structure pins: anchor must appear BEFORE the first RETURN NEW in the comment-
  // stripped raw (proving the RAISE is reachable, not dead code after an early return).
  const bodyStructureMiss = CUSTODY_BODY_STRUCTURE_PINS.some((pin) => {
    const stripped = strippedCanon(statements[pin.statementIndex].raw);
    const returnIdx = stripped.indexOf("RETURN NEW");
    if (returnIdx === -1) return true;
    const anchorIdx = stripped.indexOf(pin.anchor);
    return anchorIdx === -1 || anchorIdx > returnIdx;
  });
  return bodyStructureMiss;
};

describe("tokenizeCustodySql adversarial coverage", () => {
  it("POSITIVE CONTROL: the pristine file passes every layer of the guard", () => {
    expect(guardRejects(sql)).toBe(false);
  });

  describe("verified bypasses of a naive substring-anchor guard", () => {
    it("A1: wallet_active_leases PK moved to a new lease_id column, old PK line survives as a comment", () => {
      const mutant = sql.replace(
        "  wallet_id uuid PRIMARY KEY REFERENCES wallets (id),\n",
        "  lease_id uuid PRIMARY KEY,\n" +
          "  -- wallet_id uuid PRIMARY KEY REFERENCES wallets (id),\n" +
          "  wallet_id uuid NOT NULL REFERENCES wallets (id),\n",
      );
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A2: lease-guard trigger gains a WHEN clause that never matches", () => {
      const mutant = sql.replace(
        "CREATE TRIGGER wallet_active_leases_eligibility_guard\n  BEFORE INSERT ON wallet_active_leases\n  FOR EACH ROW EXECUTE FUNCTION custody_reject_ineligible_lease();",
        "CREATE TRIGGER wallet_active_leases_eligibility_guard\n  BEFORE INSERT ON wallet_active_leases\n  FOR EACH ROW WHEN (NEW.lease_role = 'NEVER_MATCHES') EXECUTE FUNCTION custody_reject_ineligible_lease();",
      );
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A3: a dynamic DROP ... CASCADE smuggled inside the lease-guard function body", () => {
      const mutant = sql.replace(
        "  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN\n    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';\n  END IF;",
        "  IF wallet_row.key_origin IS DISTINCT FROM 'node_generated' THEN\n    RAISE EXCEPTION 'CUSTODY_LEASE_ORIGIN_REJECTED';\n  END IF;\n" +
          "  EXECUTE 'ALTER TABLE wallet_active_leases DROP CONSTRAINT wallet_active_leases_pkey CASCADE';",
      );
      expect(mutant).not.toBe(sql);
      // Proves the forbidden scan is over `canon` (dollar-quote bodies retained verbatim),
      // not over some stripped/masked text where the injected statement would vanish.
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A4: an early RETURN NEW guts the wallet-mutation guard, RAISE anchors preserved only in comments", () => {
      // Function replacement avoids $$-mangling: in a string replacement, JS interprets $$
      // as an escape for literal $, corrupting the dollar-quote delimiter. A function
      // replacement returns the value verbatim with no special-pattern processing.
      // The mutant replaces the functional RAISE EXCEPTION lines with NULL (preserving
      // them only as comments) and adds an early RETURN NEW — the semantic pins detect
      // the absence of the RAISE EXCEPTION anchors from the function body's canon.
      const mutant = sql.replace(
        "CREATE FUNCTION custody_reject_wallet_mutation() RETURNS trigger AS $$\nBEGIN\n" +
          "  IF NEW.key_origin IS DISTINCT FROM OLD.key_origin\n" +
          "     OR NEW.node_id IS DISTINCT FROM OLD.node_id\n" +
          "     OR NEW.public_key IS DISTINCT FROM OLD.public_key THEN\n" +
          "    RAISE EXCEPTION 'CUSTODY_IMMUTABLE_FIELD_REJECTED';\n" +
          "  END IF;\n" +
          "  IF OLD.recovery_verified_at IS NOT NULL\n" +
          "     AND (NEW.recovery_verified_at IS DISTINCT FROM OLD.recovery_verified_at\n" +
          "          OR NEW.recovery_verification_id IS DISTINCT FROM OLD.recovery_verification_id) THEN\n" +
          "    RAISE EXCEPTION 'CUSTODY_RECOVERY_NEVER_CLEARED';\n" +
          "  END IF;\n" +
          "  RETURN NEW;",
        () =>
          "CREATE FUNCTION custody_reject_wallet_mutation() RETURNS trigger AS $$\nBEGIN\n" +
          "  RETURN NEW; -- early return guts the guard below\n" +
          "  -- RAISE EXCEPTION 'CUSTODY_IMMUTABLE_FIELD_REJECTED';\n" +
          "  -- RAISE EXCEPTION 'CUSTODY_RECOVERY_NEVER_CLEARED';\n" +
          "  NULL; NULL;",
      );
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A5: wallets_recovery_fields_together predicate replaced by CHECK (true), name retained", () => {
      const mutant = sql.replace(
        "CONSTRAINT wallets_recovery_fields_together\n    CHECK ((recovery_verified_at IS NULL) = (recovery_verification_id IS NULL))",
        "CONSTRAINT wallets_recovery_fields_together\n    CHECK (true)",
      );
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A6: multi-action ALTER TABLE smuggles a DROP CONSTRAINT alongside the additive one", () => {
      const mutant = sql.replace(
        "ALTER TABLE wallets\n  ADD CONSTRAINT wallets_recovery_verification_fk\n  FOREIGN KEY (recovery_verification_id)\n  REFERENCES wallet_recovery_verifications (id);",
        "ALTER TABLE wallets\n  ADD CONSTRAINT wallets_recovery_verification_fk\n  FOREIGN KEY (recovery_verification_id)\n  REFERENCES wallet_recovery_verifications (id),\n  DROP CONSTRAINT wallets_quarantine_reason_iff;",
      );
      expect(mutant).not.toBe(sql);
      // Statement count stays 11 (one comma-joined ALTER statement); the $-anchored ALTER
      // shape must reject the trailing second action.
      expect(guardRejects(mutant)).toBe(true);
    });

    it("A7: the ALTER's FOREIGN KEY replaced by a no-op CHECK (true), name retained", () => {
      const mutant = sql.replace(
        "ALTER TABLE wallets\n  ADD CONSTRAINT wallets_recovery_verification_fk\n  FOREIGN KEY (recovery_verification_id)\n  REFERENCES wallet_recovery_verifications (id);",
        "ALTER TABLE wallets\n  ADD CONSTRAINT wallets_recovery_verification_fk CHECK (true);",
      );
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("B1: a `-- $$` comment pair does not shift the single-pass lexer's statement boundaries", () => {
      const mutant =
        sql +
        "-- $$\n" +
        "ALTER TABLE wallet_active_leases DROP CONSTRAINT wallet_active_leases_pkey CASCADE;\n" +
        "-- $$\n";
      expect(mutant).not.toBe(sql);
      // A naive multi-pass "strip comments, then find $$...$$" design could treat the two
      // `-- $$` lines as a comment-then-dollar-quote pair that swallows the ALTER between
      // them. The single-pass lexer here must still see it as a live 12th statement.
      const statements = tokenizeCustodySql(mutant);
      expect(statements.length).toBe(12);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("APPEND-NO-SEMICOLON: an appended statement with no trailing semicolon is a hard failure, not a silently discarded tail", () => {
      const mutant = `${sql}DROP TABLE wallet_active_leases CASCADE`;
      expect(mutant).not.toBe(sql);
      expect(() => tokenizeCustodySql(mutant)).toThrow(/trailing text after final semicolon/);
      expect(guardRejects(mutant)).toBe(true);
    });

    it("SHADOW: an appended CREATE OR REPLACE FUNCTION silently redefines a guard", () => {
      const mutant =
        sql +
        "CREATE OR REPLACE FUNCTION custody_reject_ineligible_lease() RETURNS trigger AS $$\n" +
        "BEGIN\n  RETURN NEW;\nEND;\n$$ LANGUAGE plpgsql;\n";
      expect(mutant).not.toBe(sql);
      expect(guardRejects(mutant)).toBe(true);
    });
  });

  describe("fail-closed on disallowed lexical constructs", () => {
    it("rejects block comments (nesting-ambiguous)", () => {
      expect(() => tokenizeCustodySql("/* comment */ SELECT 1;")).toThrow(
        /block comments not permitted/,
      );
    });

    it("rejects prefixed string literals", () => {
      expect(() => tokenizeCustodySql("SELECT E'\\'';")).toThrow(
        /prefixed string literals not permitted/,
      );
    });

    it("rejects quoted identifiers", () => {
      expect(() => tokenizeCustodySql('SELECT "ident";')).toThrow(
        /quoted identifiers not permitted/,
      );
    });

    it("rejects psql backslash commands", () => {
      expect(() => tokenizeCustodySql("\\i include.sql\n")).toThrow(
        /psql backslash command not permitted/,
      );
    });

    it("rejects unterminated string literals", () => {
      expect(() => tokenizeCustodySql("SELECT 'unterminated;")).toThrow(
        /unterminated string literal/,
      );
    });

    it("rejects unterminated dollar-quotes", () => {
      expect(() => tokenizeCustodySql("SELECT $$unterminated;")).toThrow(
        /unterminated dollar-quote/,
      );
    });

    it("rejects non-ASCII bytes", () => {
      expect(() => tokenizeCustodySql("SELECT 'é';")).toThrow(/non-ASCII byte/);
    });

    it("does not treat $1$ as a dollar-quote open (a digit-led tag is a parameter reference)", () => {
      const statements = tokenizeCustodySql("SELECT $1$;");
      expect(statements.length).toBe(1);
      expect(statements[0].masked).toBe("SELECT $1$;");
    });
  });

  it("DOCUMENTING: the OLD substring-anchor style check still passes the A1 mutant — the exact hole closes", () => {
    const mutant = sql.replace(
      "  wallet_id uuid PRIMARY KEY REFERENCES wallets (id),\n",
      "  lease_id uuid PRIMARY KEY,\n" +
        "  -- wallet_id uuid PRIMARY KEY REFERENCES wallets (id),\n" +
        "  wallet_id uuid NOT NULL REFERENCES wallets (id),\n",
    );
    const oldStyleGuardPasses = CUSTODY_SCHEMA_INVARIANTS.every((invariant) =>
      mutant.includes(invariant.sqlAnchor),
    );
    expect(oldStyleGuardPasses).toBe(true);
    // The new structural guard, by contrast, rejects the same mutant.
    expect(guardRejects(mutant)).toBe(true);
  });
});
