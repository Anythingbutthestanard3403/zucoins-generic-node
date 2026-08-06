// Schema-pin for ARM_SQL_STATEMENTS — every relation / enum label must resolve in
// the frozen data-model canon (data-model.fixture.md) and/or shipped
// packages/node-core/src/schema/**.
// Clears break FAIL at 251686ec (schema-divorced receive_arm_acknowledgements /
// receive_operations / status=ARMED fiction).
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ARM_SQL_STATEMENTS } from "../src/receive/arm-sql.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const dataModelPath = resolve(here, "data-model.fixture.md");

function loadSchemaCorpus(): string {
  const files = readdirSync(schemaDir).filter((f) => f.endsWith(".sql"));
  const schemaText = files.map((f) => readFileSync(resolve(schemaDir, f), "utf8")).join("\n");
  const dataModel = readFileSync(dataModelPath, "utf8");
  return `${schemaText}\n${dataModel}`;
}

/**
 * Relation targets pulled from arm DML. Prefer clause-specific captures over a
 * generic keyword alternation (INTO inside INSERT INTO is a known false-positive).
 */
function extractRelationCandidates(sql: string): string[] {
  const found = new Set<string>();
  const add = (re: RegExp) => {
    // Fresh lastIndex each call.
    const copy = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = copy.exec(sql)) !== null) {
      found.add(m[1]!.toLowerCase());
    }
  };
  add(/\bFROM\s+([a-z][a-z0-9_]*)\b/g);
  add(/\bINSERT\s+INTO\s+([a-z][a-z0-9_]*)\b/g);
  add(/\bUPDATE\s+([a-z][a-z0-9_]*)\b/g);
  add(/\bJOIN\s+([a-z][a-z0-9_]*)\b/g);
  return [...found].sort();
}

function extractStringEnumLabels(sql: string): string[] {
  const found = new Set<string>();
  const re = /'([A-Z][A-Z0-9_]*)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sql)) !== null) {
    found.add(m[1]!);
  }
  return [...found].sort();
}

function tableDeclared(corpus: string, name: string): boolean {
  return new RegExp(`CREATE TABLE\\s+${name}\\b`, "i").test(corpus);
}

describe("ARM_SQL_STATEMENTS schema-pin", () => {
  const corpus = loadSchemaCorpus();
  const allSql = Object.values(ARM_SQL_STATEMENTS).join("\n");

  it("every relation identifier resolves in schema/** or 04-data-model", () => {
    const relations = extractRelationCandidates(allSql);
    expect(relations).toEqual(
      expect.arrayContaining(["wallets", "receive_arms", "receive_codes", "operations"]),
    );
    // Closed set — no surprise identifiers.
    expect(relations).toEqual(["operations", "receive_arms", "receive_codes", "wallets"]);
    const missing = relations.filter((name) => !tableDeclared(corpus, name));
    expect(missing, `unknown relations in ARM_SQL_STATEMENTS: ${missing.join(", ")}`).toEqual(
      [],
    );
  });

  it("enum / status labels used in DML exist on frozen surfaces", () => {
    const labels = extractStringEnumLabels(allSql);
    for (const required of ["AWAITING_ARM", "RELEASED"]) {
      expect(labels).toContain(required);
    }
    expect(labels).toContain("READY");
    expect(labels).not.toContain("ARMED");

    for (const label of labels) {
      expect(corpus.includes(`'${label}'`), `label ${label} not found in schema/04 corpus`).toBe(
        true,
      );
    }
  });

  it("rejects prior schema-fiction identifiers", () => {
    expect(allSql).not.toMatch(/receive_arm_acknowledgements/i);
    expect(allSql).not.toMatch(/receive_operations/i);
    expect(allSql).not.toMatch(/status\s*=\s*'ARMED'/i);
  });

  it("INSERT targets receive_arms; release mutates receive_codes.code_status", () => {
    expect(ARM_SQL_STATEMENTS.INSERT_ARM_ACK).toMatch(/INSERT INTO receive_arms/i);
    expect(ARM_SQL_STATEMENTS.INSERT_ARM_ACK).toMatch(/ON CONFLICT \(operation_id\)/i);
    expect(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE).toMatch(
      /UPDATE receive_codes SET code_status = 'RELEASED'/i,
    );
    expect(ARM_SQL_STATEMENTS.RELEASE_RECEIVE_CODE).toMatch(/code_status = 'AWAITING_ARM'/i);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/UPDATE operations/i);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/row_version = row_version \+ 1/);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/status = 'READY'/);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).toMatch(/row_version = \$2/);
    expect(ARM_SQL_STATEMENTS.BUMP_OPERATION_ROW_VERSION).not.toMatch(/ARMED/);
    expect(ARM_SQL_STATEMENTS.LOCK_OPERATION_GATE).toMatch(/FROM operations/i);
    expect(ARM_SQL_STATEMENTS.LOCK_OPERATION_GATE).toMatch(/FOR UPDATE OF o, c/i);
    expect(ARM_SQL_STATEMENTS.LOAD_RELEASED_CODE).toMatch(/code_status = 'RELEASED'/i);
  });

  it("LOCK_WALLET_STANDING locks wallets.id FOR UPDATE", () => {
    const lock = ARM_SQL_STATEMENTS.LOCK_WALLET_STANDING;
    expect(lock).toMatch(/FROM wallets/i);
    expect(lock).toMatch(/WHERE id = \$1::uuid FOR UPDATE/i);
    expect(lock).not.toMatch(/WHERE wallet_id\s*=/i);
    expect(lock).toMatch(/SELECT id::text AS wallet_id/i);

    // Bound each wallets CREATE block at its closing `);` so we never
    // false-green on wallet_active_leases.wallet_id PK (break D2).
    // Require every wallets definition in the corpus (SQL + 04) uses id PK.
    const walletsCreates = [
      ...corpus.matchAll(/CREATE TABLE\s+wallets\s*\(([\s\S]*?)\)\s*;/gi),
    ];
    expect(walletsCreates.length, "wallets CREATE TABLE missing from schema corpus").toBeGreaterThan(
      0,
    );
    for (const m of walletsCreates) {
      const walletsBody = m[1]!;
      expect(walletsBody).toMatch(/^\s*id\s+uuid\s+PRIMARY\s+KEY\b/i);
      expect(walletsBody).not.toMatch(/\bwallet_id\b/i);
    }
  });
});
