// parent — composition surface for the four-table registry group.
// Children own slice schema + local proofs (208) and isolation/rotation scenarios
// This file binds the parent-level package surface and group inventory so the
// exit criterion cannot drift from the delivered tables + read layer.
//
// Governing: the data model; signing custody rule 8;
// parent exit criterion.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  NODE_IMPLEMENTER_SCHEMA_FILE,
  NODE_IMPLEMENTER_SCHEMA_INVARIANTS,
} from "../src/schema/node-implementer-registry.contract.ts";
import {
  REGISTRY_GROUP_EXIT_CRITERION,
  REGISTRY_GROUP_INVARIANTS,
  REGISTRY_GROUP_SCHEMA_FILES,
  REGISTRY_GROUP_TABLES,
} from "../src/schema/registry-group.contract.ts";
import {
  SIGNING_KEY_SCHEMA_FILE,
  SIGNING_KEY_SCHEMA_INVARIANTS,
} from "../src/schema/signing-key-registry.contract.ts";
import {
  NODE_SIGNING_KEY_COLUMNS,
  NODE_SIGNING_KEY_PURPOSES,
  REPORTING_KEY_COLUMNS,
  STATEMENTS,
  SigningKeyRegistry,
  UnknownSigningKeyPurposeError,
  assertExactPurpose,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/signing-keys/registry-store.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const loadSql = (file: string): string => readFileSync(resolve(schemaDir, file), "utf8");

const PRIVATE_KEY_TOKENS =
  /\bprivate_key\b|\bsecret_key\b|\bseed\b|\bencrypted_secret\b|\bkey_material\b|\bsigning_secret\b|\bsk_bytes\b|\bprivate_bytes\b|\bkeypair\b|\bmnemonic\b/i;

describe("parent registry group composition", () => {
  it("freezes the ordered two-slice apply sequence and four tables", () => {
    expect([...REGISTRY_GROUP_SCHEMA_FILES]).toEqual([
      NODE_IMPLEMENTER_SCHEMA_FILE,
      SIGNING_KEY_SCHEMA_FILE,
    ]);
    expect([...REGISTRY_GROUP_TABLES]).toEqual([
      "nodes",
      "implementers",
      "implementer_reporting_keys",
      "node_signing_keys",
    ]);
    expect(REGISTRY_GROUP_EXIT_CRITERION).toContain("Wrong-purpose or expired keys");
    expect(REGISTRY_GROUP_EXIT_CRITERION).toContain("frozen historical verification");
    expect(REGISTRY_GROUP_INVARIANTS.length).toBeGreaterThanOrEqual(5);
  });

  it("both slice contracts inventory non-empty structural invariants", () => {
    expect(NODE_IMPLEMENTER_SCHEMA_INVARIANTS.length).toBeGreaterThan(0);
    expect(SIGNING_KEY_SCHEMA_INVARIANTS.length).toBeGreaterThan(0);
    expect(
      SIGNING_KEY_SCHEMA_INVARIANTS.some((row) => row.id === "SIGNING_KEY_PURPOSE_CHECK"),
    ).toBe(true);
    expect(
      SIGNING_KEY_SCHEMA_INVARIANTS.some((row) => row.id === "SIGNING_KEY_VAULT_SECRET_REF"),
    ).toBe(true);
    expect(
      NODE_IMPLEMENTER_SCHEMA_INVARIANTS.some((row) => row.id === "NODE_IDENTITY_KEY_UNIQUE"),
    ).toBe(true);
  });

  it("SQL group materializes exactly the four tables and no private-key columns", () => {
    const base = loadSql(NODE_IMPLEMENTER_SCHEMA_FILE);
    const keys = loadSql(SIGNING_KEY_SCHEMA_FILE);
    const combined = `${base}\n${keys}`;

    for (const table of REGISTRY_GROUP_TABLES) {
      expect(combined, `missing CREATE TABLE ${table}`).toMatch(
        new RegExp(`CREATE TABLE ${table}\\b`),
      );
    }
    expect(combined).not.toMatch(/CREATE TABLE\s+\w*wallet\w*_signing/i);
    expect(combined).not.toMatch(/CREATE TABLE\s+reporting_signing_key\b/i);

    expect(PRIVATE_KEY_TOKENS.test(combined)).toBe(false);
    expect(keys).toContain("vault_secret_ref uuid NOT NULL UNIQUE");
    expect(keys).not.toMatch(/vault_secret_ref[^,]*REFERENCES/);
  });

  it("read-layer projection is public material only (no vault_secret_ref)", () => {
    expect([...NODE_SIGNING_KEY_COLUMNS]).toEqual([
      "id",
      "node_id",
      "purpose",
      "public_key",
      "activated_at",
      "retired_at",
    ]);
    expect([...REPORTING_KEY_COLUMNS]).toEqual([
      "id",
      "node_id",
      "implementer_id",
      "public_key",
      "registered_at",
    ]);
    expect(NODE_SIGNING_KEY_COLUMNS).not.toContain("vault_secret_ref");
    expect(REPORTING_KEY_COLUMNS).not.toContain("vault_secret_ref");
  });

  it("purpose comparison is exact-literal and runs before any SQL (signing custody rule 8)", async () => {
    expect([...NODE_SIGNING_KEY_PURPOSES]).toEqual(["NODE_IDENTITY", "EVENT_SIGNING"]);
    expect(assertExactPurpose("NODE_IDENTITY")).toBe("NODE_IDENTITY");
    expect(assertExactPurpose("EVENT_SIGNING")).toBe("EVENT_SIGNING");

    const calls: string[] = [];
    const executor: SqlExecutor = {
      query<R>(text: string): Promise<SqlQueryResult<R>> {
        calls.push(text);
        return Promise.reject(new Error("executor must not be reached for bad purpose"));
      },
    };
    const registry = new SigningKeyRegistry(executor);

    await expect(registry.findActiveNodeSigningKeys("n", "WALLET_SIGNING")).rejects.toBeInstanceOf(
      UnknownSigningKeyPurposeError,
    );
    await expect(registry.findNodeSigningKey("n", "node_identity", "k")).rejects.toBeInstanceOf(
      UnknownSigningKeyPurposeError,
    );
    await expect(registry.findActiveNodeSigningKeys("n", "EVENT_SIGNING ")).rejects.toBeInstanceOf(
      UnknownSigningKeyPurposeError,
    );
    expect(calls).toEqual([]);
  });

  it("active statement is both-sided; historical statement has no validity window filter", () => {
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain("purpose = $2");
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain("activated_at <= now()");
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain(
      "(retired_at IS NULL OR retired_at > now())",
    );
    // Historical lookup projects activated_at/retired_at (window visible to the caller) but
    // never filters on them — retired keys stay resolvable by exact public key forever.
    expect(STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY).toContain("public_key = $3");
    expect(STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY).not.toContain("activated_at <=");
    expect(STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY).not.toContain("retired_at IS NULL");
    expect(STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY).not.toContain("retired_at >");
  });
});
