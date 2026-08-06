// census: binds the frozen invariant inventory to the literal SQL contract text
// and cross-binds the SQL predicate literals to the generic-node-contracts custody
// vocabulary, so the three truth carriers (contracts data, SQL text, verifier) cannot
// drift apart silently. Live-database execution is a separate live-database obligation, inventoried in the
// contract, not silently omitted.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CUSTODY_SCHEMA_FILE,
  CUSTODY_SCHEMA_INVARIANTS,
  SCHEMA_EXECUTION_OBLIGATIONS,
} from "../src/schema/custody-eligibility.contract.ts";
import {
  AUTOMATIC_SINK_CONJUNCTS,
  INTERNAL_CUSTODY_CONJUNCTS,
  WALLET_STATES,
} from "../../generic-node-contracts/src/custody/predicates.contract.ts";
import { verifyAutomaticSinkEligibility } from "../../generic-node-contracts/src/custody/predicate-verifier.ts";
import {
  parseSinkLeaseAdmittedStates,
  parseWalletStateEnum,
} from "./custody-eligibility-sql-parser.ts";
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
const sqlBytes = readFileSync(sqlPath);
// custody-eligibility.sql is prerequisite-bound and no longer re-declares
// data-model's enumerations — base-enums-domains.sql is their sole declaring contract, so the
// wallet_state enum is read from there while the lease guard is still read from the SQL above.
const baseSql = readFileSync(resolve(here, "../src/schema", "base-enums-domains.sql"), "utf8");

// extracts the actual object name a statement declares, keyed by the kind
// expected at that position. Kept separate from CUSTODY_STATEMENT_INVENTORY's `shape`
// (which is a generic, kind-only pattern) so a shape match and a name match are two
// independent signals rather than one regex trying to do both jobs.
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

const FROZEN_CUSTODY_SQL_SHA256 =
  "4db5d9318efbc0a9fee146e57c3b9fd1501bf74d804c303c03080d3a0988324e";

describe("custody-eligibility schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = CUSTODY_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("recovery_verified_at carries no column default (the anti-pattern)", () => {
    const line = sql
      .split("\n")
      .find((candidate) => candidate.includes("recovery_verified_at timestamptz"));
    expect(line).toBeDefined();
    expect(line).not.toMatch(/DEFAULT/i);
    expect(sql).not.toMatch(/recovery_verified_at[^,\n]*DEFAULT/i);
  });

  it("the lease guard is BEFORE INSERT on wallet_active_leases and keyed by lease_role", () => {
    expect(sql).toMatch(
      /CREATE TRIGGER wallet_active_leases_eligibility_guard\s+BEFORE INSERT ON wallet_active_leases/,
    );
    expect(sql).toContain("IF NEW.lease_role = 'MOVE_DESTINATION' THEN");
    // custody rule 3: state allowlist applies to every non-recovery role; RECONCILIATION is exempt.
    expect(sql).toContain("IF NEW.lease_role IS DISTINCT FROM 'RECONCILIATION'");
    expect(sql).toContain("wallet_row.state NOT IN ('AVAILABLE', 'PINNED')");
  });

  it("SQL predicate literals equal the frozen contracts vocabulary (three-way identity)", () => {
    expect(sql).toContain(`'${INTERNAL_CUSTODY_CONJUNCTS.keyOrigin}'`);
    expect(sql).toContain(`'${INTERNAL_CUSTODY_CONJUNCTS.destinationState}'`);
    const denied = ["QUARANTINED", "RETIRED"].filter((state) =>
      (AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates as readonly string[]).includes(state),
    );
    expect(denied).toEqual([]);
    // the guard is now allowlist-positive (NOT IN the admitted set), not a
    // hand-maintained blocklist complement — see the full-enum parity test below for the
    // binding that actually protects this from silent drift.
    expect(sql).toContain("wallet_row.state NOT IN ('AVAILABLE', 'PINNED')");
    expect(sql).toContain("wallet_row.recovery_verified_at IS NULL");
  });

  it("SQL-admitted set and the frozen contract allowlist agree over the ENTIRE wallet_state enum (no per-state drift)", () => {
    const enumStates = parseWalletStateEnum(baseSql);
    const sqlAdmitted = new Set(parseSinkLeaseAdmittedStates(sql));
    const contractAllowed = new Set(AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates as readonly string[]);

    // Binds against the real, currently-shipped enum — not a hardcoded 4-item list — so
    // this test itself grows automatically the moment wallet_state gains a member.
    expect(enumStates).toEqual([...WALLET_STATES]);

    const diverging = enumStates
      .filter((state) => sqlAdmitted.has(state) !== contractAllowed.has(state))
      .sort();
    expect(diverging, "a state admitted by one layer and denied by the other").toEqual([]);
  });

  describe("synthetic 5th-state proof: old blocklist fail-open vs new allowlist fail-closed", () => {
    const SYNTHETIC_FIFTH_STATE = "FROZEN";

    // Historical fixture reproducing the blocklist predicate this trigger carried BEFORE
    // the allowlist-parity hardening (see git history for the exact
    // prior line: `wallet_row.state IN ('QUARANTINED', 'RETIRED')`). Preserved here ONLY to
    // prove the fail-open gap it created for any wallet_state value added later without a
    // matching blocklist update; it is not read from any live file and nothing in this
    // package executes it.
    const oldBlocklistAdmits = (state: string): boolean => !["QUARANTINED", "RETIRED"].includes(state);

    it("RED (old): a blocklist would have silently admitted an unrecognized 5th wallet_state", () => {
      expect(WALLET_STATES as readonly string[]).not.toContain(SYNTHETIC_FIFTH_STATE);
      expect(oldBlocklistAdmits(SYNTHETIC_FIFTH_STATE)).toBe(true);
    });

    it("GREEN (new): the shipped allowlist SQL denies the same unrecognized 5th wallet_state", () => {
      const sqlAdmitted = parseSinkLeaseAdmittedStates(sql);
      expect(sqlAdmitted.includes(SYNTHETIC_FIFTH_STATE)).toBe(false);
    });

    it("GREEN (new): the frozen verifier independently denies the same unrecognized 5th wallet_state", () => {
      const decision = verifyAutomaticSinkEligibility({
        keyOrigin: INTERNAL_CUSTODY_CONJUNCTS.keyOrigin,
        destinationState: INTERNAL_CUSTODY_CONJUNCTS.destinationState,
        recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
        walletState: SYNTHETIC_FIFTH_STATE,
      });
      expect(decision).toEqual({ eligible: false, denialReason: "INVALID_WALLET_STATE" });
    });
  });

  it("mutation negative: removing an anchored clause is caught", () => {
    const mutated = sql.replace("CUSTODY_LEASE_ORIGIN_REJECTED", "REMOVED_CLAUSE");
    const missing = CUSTODY_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["LEASE_ORIGIN_CONJUNCT_AT_CLAIM"]);
  });

  it("mutation negative: reintroducing a recovery default is caught", () => {
    const mutated = sql.replace(
      "recovery_verified_at timestamptz,",
      "recovery_verified_at timestamptz DEFAULT now(),",
    );
    expect(mutated).toMatch(/recovery_verified_at[^,\n]*DEFAULT/i);
  });

  it("execution obligations are inventoried and non-empty", () => {
    expect(SCHEMA_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(7);
    for (const obligation of SCHEMA_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    const raiseTokens = [...sql.matchAll(/RAISE EXCEPTION '([A-Z_]+)'/g)].map(
      (match) => match[1],
    );
    for (const token of raiseTokens) {
      const covered =
        SCHEMA_EXECUTION_OBLIGATIONS.some((obligation) => obligation.includes(token)) ||
        CUSTODY_SCHEMA_INVARIANTS.some((invariant) => invariant.sqlAnchor === token);
      expect(covered, `rejection token ${token} must be inventoried`).toBe(true);
    }
  });
});

describe("statement exhaustiveness / freeze pin", () => {
  const statements = tokenizeCustodySql(sql);

  it("tokenizes to exactly 11 statements", () => {
    expect(statements.length).toBe(11);
  });

  it("every statement matches its inventoried (kind, objectName, shape) in order", () => {
    CUSTODY_STATEMENT_INVENTORY.forEach((entry, i) => {
      const statement = statements[i];
      expect(statement, `statement at index ${i} is missing`).toBeDefined();
      const actualName = extractObjectName(entry.kind, statement.masked);
      expect(
        actualName,
        `statement [${i}] line ${statement.line}: expected ${entry.kind} ${entry.objectName}, masked was: ${statement.masked}`,
      ).toBe(entry.objectName);
      expect(
        entry.shape.test(statement.masked),
        `statement [${i}] line ${statement.line} (${entry.kind} ${entry.objectName}) does not match its shape. masked was: ${statement.masked}`,
      ).toBe(true);
    });
  });

  it("all 11 inventoried object names are unique (kills shadowing generically)", () => {
    const names = CUSTODY_STATEMENT_INVENTORY.map((entry) => entry.objectName);
    expect(new Set(names).size).toBe(names.length);
  });

  it("no statement's canon matches any forbidden SQL pattern", () => {
    for (const statement of statements) {
      for (const forbidden of FORBIDDEN_SQL_PATTERNS) {
        expect(
          forbidden.pattern.test(statement.canon),
          `statement [${statement.index}] line ${statement.line} matched forbidden pattern (${forbidden.reason}). canon was: ${statement.canon}`,
        ).toBe(false);
      }
    }
  });

  it("every semantic pin's anchor is present in its statement's comment-stripped raw", () => {
    for (const pin of CUSTODY_SEMANTIC_PINS) {
      const statement = statements[pin.statementIndex];
      const stripped = statement.raw
        .split("\n")
        .map((line) => {
          const idx = line.indexOf("--");
          return idx === -1 ? line : line.slice(0, idx);
        })
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      expect(
        stripped.includes(pin.anchor),
        `semantic pin (${pin.rule}): anchor not found in statement [${pin.statementIndex}] (${pin.objectName}). raw was: ${statement.raw}`,
      ).toBe(true);
    }
  });

  it("every body-structure pin's anchor precedes the first RETURN NEW (reachable, not dead code)", () => {
    for (const pin of CUSTODY_BODY_STRUCTURE_PINS) {
      const statement = statements[pin.statementIndex];
      const stripped = statement.raw
        .split("\n")
        .map((line) => {
          const idx = line.indexOf("--");
          return idx === -1 ? line : line.slice(0, idx);
        })
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      const returnIdx = stripped.indexOf("RETURN NEW");
      const anchorIdx = stripped.indexOf(pin.anchor);
      expect(
        returnIdx,
        `body-structure pin (${pin.rule}): no RETURN NEW in statement [${pin.statementIndex}] (${pin.objectName})`,
      ).not.toBe(-1);
      expect(
        anchorIdx,
        `body-structure pin (${pin.rule}): anchor not found in statement [${pin.statementIndex}] (${pin.objectName})`,
      ).not.toBe(-1);
      expect(
        anchorIdx < returnIdx,
        `body-structure pin (${pin.rule}): anchor appears AFTER RETURN NEW (dead code) in statement [${pin.statementIndex}] (${pin.objectName})`,
      ).toBe(true);
    }
  });

  it("FREEZE PIN: custody-eligibility.sql bytes match the pinned sha256", () => {
    const actual = createHash("sha256").update(sqlBytes).digest("hex");
    expect(
      actual,
      "custody-eligibility.sql is frozen contract text: any intentional change " +
        "requires updating FROZEN_CUSTODY_SQL_SHA256 in this test IN THE SAME COMMIT, with " +
        "freeze-lane review; the surrounding structural tests (statement count, inventory, " +
        "shape, forbidden-pattern scan) explain WHAT changed.",
    ).toBe(FROZEN_CUSTODY_SQL_SHA256);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});
