// custody-eligibility.sql is DERIVED from the frozen data-model canon
// (data-model.fixture.md). It had silently re-forked
// its source — renaming three primary keys, dropping the `nodes` tenant FKs, and collapsing
// two domain-typed columns to bare `text` (which took the ii schema-level
// public_key CHECK with it). The census suite freezes the file's BYTES; nothing bound those
// bytes back to the doc they claim to derive from, which is exactly how the drift stayed
// invisible through two PASS verdicts.
//
// This test closes that: it reads canon and the SQL and asserts the naming contract between
// them. It fails if either side moves — a re-fork of the SQL, or a canon edit the SQL has not
// followed. Deliberately narrow: it checks the identifiers that make the two artifacts
// executable together, not the full column inventory (the statement census owns shape, and
// migration-integrity owns real-Postgres application).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CUSTODY_SCHEMA_FILE } from "../src/schema/custody-eligibility.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sql = readFileSync(resolve(here, "../src/schema", CUSTODY_SCHEMA_FILE), "utf8");
const canon = readFileSync(
  resolve(here, "data-model.fixture.md"),
  "utf8",
);

/** The first column name declared by canon's `CREATE TABLE <table>` block, with its clause. */
const canonFirstColumn = (table: string): string => {
  const match = new RegExp(`CREATE TABLE ${table} \\(\\n {2}(\\w+) ([^,\\n]+),`).exec(canon);
  if (match === null) {
    throw new Error(`data-model.fixture.md: CREATE TABLE ${table} not found`);
  }
  return `${match[1]} ${match[2]}`;
};

/** Every relation/column pair the SQL's inline and ALTER foreign keys target. */
const sqlForeignKeyTargets = (): { relation: string; column: string }[] =>
  [...sql.matchAll(/REFERENCES (\w+) \((\w+)\)/g)].map((m) => ({ relation: m[1], column: m[2] }));

describe("custody-eligibility.sql conforms to the data-model canon", () => {
  it("the four custody tables carry canon's primary-key column names", () => {
    // The drift corrected here had renamed all three of these to <table>_id.
    for (const table of ["wallets", "destinations", "wallet_recovery_verifications"]) {
      expect(canonFirstColumn(table), `canon ${table} PK`).toBe("id uuid PRIMARY KEY");
      expect(sql, `${table} must declare canon's PK column`).toMatch(
        new RegExp(`CREATE TABLE ${table} \\(\\n {2}id uuid PRIMARY KEY,`),
      );
    }
    // data-model's lease projection is the one table canon keys by wallet_id, not id — golden
    // rule 2's structural carrier.
    expect(canonFirstColumn("wallet_active_leases")).toBe(
      "wallet_id uuid PRIMARY KEY REFERENCES wallets(id)",
    );
  });

  it("every foreign key targets a relation/column canon actually declares", () => {
    const targets = sqlForeignKeyTargets();
    expect(targets.length, "the file must still carry foreign keys").toBeGreaterThan(0);
    for (const { relation, column } of targets) {
      expect(canonFirstColumn(relation), `FK target ${relation}(${column})`).toMatch(
        new RegExp(`^${column} `),
      );
    }
  });

  it("both tenant-isolation FKs to nodes(id) are present (data-model, structural not trigger-only)", () => {
    for (const table of ["wallets", "destinations"]) {
      const block = new RegExp(`CREATE TABLE ${table} \\([\\s\\S]*?\\n\\);`).exec(sql);
      expect(block, `${table} block`).not.toBeNull();
      expect(block?.[0], `${table}.node_id must FK nodes(id)`).toContain(
        "node_id uuid NOT NULL REFERENCES nodes (id)",
      );
    }
  });

  it("the domain types are referenced, never collapsed to bare text (ii)", () => {
    // public_key is one of the six AAD source columns; its schema-level CHECK is the
    // injectivity guarantee, and it exists only via the domain.
    expect(sql).toContain("public_key padded_base64url_pubkey NOT NULL");
    expect(sql).toContain("export_sha256 sha256_hex NOT NULL");
    expect(sql, "no AAD/digest column may regress to bare text").not.toMatch(
      /\b(public_key|export_sha256) text\b/,
    );
  });

  it("data-model's lease fencing columns and both UNIQUEs are present", () => {
    const block = /CREATE TABLE wallet_active_leases \([\s\S]*?\n\);/.exec(sql)?.[0] ?? "";
    for (const column of [
      "membership_id",
      "lease_group_id",
      "root_operation_id",
      "operation_id",
      "lease_epoch",
      "heartbeat_at",
      "owner_instance_id",
      "release_not_before",
    ]) {
      expect(block, `wallet_active_leases.${column}`).toMatch(new RegExp(`\\n {2}${column} `));
    }
    expect(block).toContain("UNIQUE (operation_id, wallet_id)");
    expect(block).toContain("UNIQUE (lease_group_id, wallet_id)");
  });
});
