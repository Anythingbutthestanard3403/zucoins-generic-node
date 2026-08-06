// census + real-PostgreSQL behavioural proof for signing-key-registry.sql,
// stacked on. The census block binds the frozen invariant inventory to the
// literal SQL and runs always; the live-PostgreSQL block is gated on TEST_DATABASE_URL and layers
// the two tables on the real node-implementer-registry base, then discharges the schema-apply
// execution obligations (reference enforcement to nodes/implementers, domain/CHECK/UNIQUE). psql
// runs as a child process (node:child_process), keeping the in-process network-containment
// guard (setup-network-guard.ts) intact -- exactly as migration-integrity.test.ts does.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import {
  SCHEMA_EXECUTION_OBLIGATIONS,
  SIGNING_KEY_SCHEMA_FILE,
  SIGNING_KEY_SCHEMA_INVARIANTS,
} from "../src/schema/signing-key-registry.contract.ts";
import type { SqlExecutor, SqlQueryResult } from "../src/signing-keys/registry-store.ts";
import {
  assertExactPurpose,
  NODE_SIGNING_KEY_COLUMNS,
  NODE_SIGNING_KEY_PURPOSES,
  REPORTING_KEY_COLUMNS,
  SigningKeyRegistry,
  STATEMENTS,
  UnknownSigningKeyPurposeError,
} from "../src/signing-keys/registry-store.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const sqlPath = resolve(schemaDir, SIGNING_KEY_SCHEMA_FILE);
const basePath = resolve(schemaDir, "node-implementer-registry.sql");
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("signing-key registry census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SIGNING_KEY_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the two tables and re-declares the pubkey domain", () => {
    expect(sql).toContain("CREATE TABLE implementer_reporting_keys (");
    expect(sql).toContain("CREATE TABLE node_signing_keys (");
    expect(sql).toMatch(/CREATE DOMAIN padded_base64url_pubkey AS text/);
    // The nodes/implementers root registries belong to never this slice.
    expect(sql).not.toContain("CREATE TABLE nodes");
    expect(sql).not.toContain("CREATE TABLE implementers");
  });

  it("keeps vault_secret_ref a bare uuid reference with no foreign key and no key material", () => {
    expect(sql).toContain("vault_secret_ref uuid NOT NULL UNIQUE");
    // vault_secret_ref must never gain a REFERENCES clause -- it resolves only in the node vault.
    expect(sql).not.toMatch(/vault_secret_ref[^,]*REFERENCES/);
    // No private-key / seed / secret columns -- only public material is relational (the key-custody rule).
    // The alphabet is deliberately wider than the declared columns, so a future rename
    // into any of these shapes trips the guard rather than sliding past it.
    expect(sql).not.toMatch(
      /private_key|secret_key|\bseed\b|encrypted_secret|key_material|signing_secret|sk_bytes|private_bytes|keypair|\bmnemonic\b/,
    );
  });

  it("keeps the bare-id PK (no surrogate node_id/implementer_id PK)", () => {
    expect(sql).not.toMatch(/node_id uuid PRIMARY KEY/);
    expect(sql).not.toMatch(/implementer_id uuid PRIMARY KEY/);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace(
      "vault_secret_ref uuid NOT NULL UNIQUE",
      "vault_secret_ref uuid NOT NULL",
    );
    const missing = SIGNING_KEY_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["SIGNING_KEY_VAULT_SECRET_REF"]);
  });

  it("schema-apply execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of SCHEMA_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});

// A valid padded base64url public key: 43 chars from [A-Za-z0-9_-] then '='.
const VALID_KEY = `${"A".repeat(43)}=`;
const SECOND_KEY = `${"B".repeat(43)}=`;
const THIRD_KEY = `${"C".repeat(43)}=`;
const FOURTH_KEY = `${"D".repeat(43)}=`;
const NODE_ID = "00000000-0000-0000-0000-000000000001";
const OTHER_NODE_ID = "00000000-0000-0000-0000-000000000009";
const IMPL_ID = "00000000-0000-0000-0000-000000000002";
const MISSING_ID = "00000000-0000-0000-0000-0000000000ee";
const VAULT_REF = "00000000-0000-0000-0000-0000000000a1";
const VAULT_REF_2 = "00000000-0000-0000-0000-0000000000a2";
const RKEY_ID = "00000000-0000-0000-0000-0000000000b1";
const SKEY_ID = "00000000-0000-0000-0000-0000000000c1";

// ---- read-layer fixtures -------------------------------------------------------
// One node per concern, on their own uuid page (`...0000000dXXXX`), so no resolution case
// depends on a row another case in this file inserts or on the order they run in.
const rid = (suffix: string): string => `00000000-0000-0000-0000-0000000d${suffix}`;
const pubkey = (letter: string): string => `${letter.repeat(43)}=`;

const NODE_IDENTITY_ONLY = rid("0001");
const NODE_EVENT_ONLY = rid("0002");
const NODE_BOTH_PURPOSES = rid("0003");
const NODE_EXPIRING = rid("0004");
const NODE_ROTATING = rid("0005");
const RESOLVER_NODES = [
  NODE_IDENTITY_ONLY,
  NODE_EVENT_ONLY,
  NODE_BOTH_PURPOSES,
  NODE_EXPIRING,
  NODE_ROTATING,
] as const;
// nodes.identity_public_key is UNIQUE, so each resolver node needs its own.
const NODE_SEED_KEYS = ["E", "F", "G", "H", "I"].map(pubkey);

const IMPL_B_ID = rid("0006");
const SHARED_KEY = pubkey("J"); // registered under BOTH purposes on one node
const EXPIRED_KEY = pubkey("K");
const FUTURE_RETIRE_KEY = pubkey("L");
const PENDING_KEY = pubkey("T"); // pre-registered successor whose window has not opened yet
const ROTATE_KEY_1 = pubkey("M");
const ROTATE_KEY_2 = pubkey("N");
const IDENTITY_ONLY_KEY = pubkey("P");
const EVENT_ONLY_KEY = pubkey("Q");
const REPORTING_KEY_A = pubkey("R");
const REPORTING_KEY_B = pubkey("S");

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

const SCHEMA = "signing_key_registry_signing_key_registry";
let reachable = false;
// True only after fixture seed completes — reachable is set before apply/seed.
let liveReady = false;

// Runs a statement inside the applied schema. search_path persists across -c args in one psql
// session, so a failing INSERT yields a non-zero status the negative tests assert on.
const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

// A seed insert that is REQUIRED to land. beforeAll previously issued its fixtures through
// `run` and discarded the status, so a silently rejected seed would have surfaced only as a
// confusing downstream assertion.
const seed = (statement: string): void => {
  const result = run(statement);
  expect(result.stderr, `seed must apply cleanly: ${statement}`).toBe("");
  expect(result.status, `seed must apply cleanly: ${statement}`).toBe(0);
};

// ---- a REAL-PostgreSQL SqlExecutor for the read layer ------------------------------------
// node-core is network-contained and depends on no database driver, so the registry
// takes an injected SqlExecutor. This one is backed by the same psql child process the rest of
// the file uses: it issues the registry module's OWN statement text against the live schema and
// maps the tuple output back through the module's OWN column constants. No predicate, ordering,
// validity window, or NULL handling is modelled in-process -- Postgres evaluates all of it. The
// only rewrite is substituting $n placeholders with quoted literals, because `psql -c` takes no
// bind parameters; the SELECT list, WHERE clause and ORDER BY reach the server verbatim.
// '|' is safe as a field separator here: every selected column is a uuid, a timestamp, a
// closed purpose literal, or a padded base64url key ([A-Za-z0-9_-] + '='). None can contain it.
const FIELD_SEP = "|";
const NULL_TOKEN = "<PGNULL>";

const sqlLiteral = (value: unknown): string =>
  value === null || value === undefined ? "NULL" : `'${String(value).replaceAll("'", "''")}'`;

const livePsqlExecutor: SqlExecutor = {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const statement = text.replace(/\$(\d+)/g, (_match, index: string) =>
      sqlLiteral(params[Number(index) - 1]),
    );
    const result = psql([
      "-t",
      "-A",
      "-F",
      FIELD_SEP,
      "-P",
      `null=${NULL_TOKEN}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-c",
      statement,
    ]);
    if (result.status !== 0) return Promise.reject(new Error(result.stderr));
    const columns: readonly string[] = statement.includes(" FROM node_signing_keys ")
      ? NODE_SIGNING_KEY_COLUMNS
      : REPORTING_KEY_COLUMNS;
    const rows = result.stdout
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const values = line.split(FIELD_SEP);
        return Object.fromEntries(
          columns.map((column, i) => [column, values[i] === NULL_TOKEN ? null : values[i]]),
        );
      }) as R[];
    return Promise.resolve({ rows });
  },
};

const registry = new SigningKeyRegistry(livePsqlExecutor);

// signing-key-registry re-declares padded_base64url_pubkey for standalone greenfield (proven
// prerequisite-bound in migration-integrity.test.ts). Layered on the base here, that
// domain already exists, so the re-declaration is stripped before applying the two
// tables -- the dependency-sequence application creates each domain exactly once.
const layeredSigningSql = sql.replace(/CREATE DOMAIN padded_base64url_pubkey AS text[^;]*;/, "");

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    // No silent no-op: TEST_DATABASE_URL set but unreachable FAILS the whole block loudly
    // instead of letting every case ctx.skip() itself into a green tick.
    const probe = psql(["-c", "SELECT 1"]);
    if (probe.status !== 0) {
      throw new Error(`TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${probe.stderr}`);
    }
    reachable = true;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    // base: nodes + implementers + the pubkey domain.
    const base = psql([
      "-c",
      `CREATE SCHEMA ${SCHEMA}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-f",
      basePath,
    ]);
    expect(base.stderr, "base apply should be clean").toBe("");
    expect(base.status, "base apply should succeed").toBe(0);
    // tables layered on top (the pubkey domain is already declared by the base).
    const layered = run(layeredSigningSql);
    expect(layered.stderr, "layered apply should be clean").toBe("");
    expect(layered.status, "layered apply should succeed").toBe(0);
    // Baseline reference targets + rows the negative constraint tests collide against.
    seed(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ('${NODE_ID}', 'node one', '${VALID_KEY}')`,
    );
    seed(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ('${OTHER_NODE_ID}', 'node two', '${SECOND_KEY}')`,
    );
    seed(`INSERT INTO implementers (id, name) VALUES ('${IMPL_ID}', 'impl one')`);
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${RKEY_ID}', '${NODE_ID}', '${IMPL_ID}', '${VALID_KEY}', now())`,
    );
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${SKEY_ID}', '${NODE_ID}', 'NODE_IDENTITY', '${VALID_KEY}', '${VAULT_REF}', now())`,
    );

    // ---- read-layer fixtures (one node per concern) ----
    RESOLVER_NODES.forEach((nodeId, index) => {
      seed(
        `INSERT INTO nodes (id, display_name, identity_public_key)
         VALUES ('${nodeId}', 'resolver node ${index}', '${NODE_SEED_KEYS[index]}')`,
      );
    });
    seed(`INSERT INTO implementers (id, name) VALUES ('${IMPL_B_ID}', 'impl two')`);
    // Exactly one NODE_IDENTITY key, and exactly one EVENT_SIGNING key, on separate nodes --
    // the two directions of the cross-purpose proof.
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("1001")}', '${NODE_IDENTITY_ONLY}', 'NODE_IDENTITY', '${IDENTITY_ONLY_KEY}', '${rid("9001")}', now())`,
    );
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("1002")}', '${NODE_EVENT_ONLY}', 'EVENT_SIGNING', '${EVENT_ONLY_KEY}', '${rid("9002")}', now())`,
    );
    // The abuse case the schema alone permits: ONE public key enrolled under BOTH purposes on
    // one node. The DDL accepts it; the read layer must never let one satisfy the other.
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("1003")}', '${NODE_BOTH_PURPOSES}', 'NODE_IDENTITY', '${SHARED_KEY}', '${rid("9003")}', now())`,
    );
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("1004")}', '${NODE_BOTH_PURPOSES}', 'EVENT_SIGNING', '${SHARED_KEY}', '${rid("9004")}', now())`,
    );
    // Validity windows, all three on ONE node so active resolution has to select rather than
    // just come back empty: one retired in the past, one live, one not yet activated.
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at)
       VALUES ('${rid("1005")}', '${NODE_EXPIRING}', 'EVENT_SIGNING', '${EXPIRED_KEY}', '${rid("9005")}',
               now() - interval '2 days', now() - interval '1 day')`,
    );
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at)
       VALUES ('${rid("1006")}', '${NODE_EXPIRING}', 'EVENT_SIGNING', '${FUTURE_RETIRE_KEY}', '${rid("9006")}',
               now() - interval '1 day', now() + interval '365 days')`,
    );
    // A successor pre-registered ahead of its overlap window. Nothing in the schema bars a
    // future activated_at, and CHECK (retired_at >= activated_at) accepts the pair, so only the
    // read layer's lower bound keeps this key out of the active set.
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at)
       VALUES ('${rid("1007")}', '${NODE_EXPIRING}', 'EVENT_SIGNING', '${PENDING_KEY}', '${rid("9007")}',
               now() + interval '7 days', now() + interval '400 days')`,
    );
    // Two implementers enrolled on one node -- the reporting-key tenant-scoping proof.
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${rid("2001")}', '${NODE_IDENTITY_ONLY}', '${IMPL_ID}', '${REPORTING_KEY_A}', now())`,
    );
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${rid("2002")}', '${NODE_IDENTITY_ONLY}', '${IMPL_B_ID}', '${REPORTING_KEY_B}', now())`,
    );
    liveReady = true;
  });

  afterAll(() => {
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  const columns = (table: string): string[] =>
    psql([
      "-t",
      "-A",
      "-c",
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema = '${SCHEMA}' AND table_name = '${table}'
       ORDER BY ordinal_position`,
    ])
      .stdout.trim()
      .split("\n")
      .filter(Boolean);

  it("materializes exactly the columns for both tables", (ctx) => {
    if (!reachable) ctx.skip();
    expect(columns("implementer_reporting_keys")).toEqual([
      "id",
      "node_id",
      "implementer_id",
      "public_key",
      "registered_at",
    ]);
    expect(columns("node_signing_keys")).toEqual([
      "id",
      "node_id",
      "purpose",
      "public_key",
      "vault_secret_ref",
      "activated_at",
      "retired_at",
    ]);
  });

  it("baseline seed rows applied (layered apply + valid inserts succeeded)", (ctx) => {
    if (!reachable) ctx.skip();
    expect(run("SELECT count(*) FROM implementer_reporting_keys").stdout).toContain("1");
    expect(run("SELECT count(*) FROM node_signing_keys").stdout).toContain("1");
  });

  it("reference: a reporting key citing an absent node is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('00000000-0000-0000-0000-0000000000f1', '${MISSING_ID}', '${IMPL_ID}', '${SECOND_KEY}', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/foreign key/i);
  });

  it("reference: a reporting key citing an absent implementer is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('00000000-0000-0000-0000-0000000000f2', '${NODE_ID}', '${MISSING_ID}', '${SECOND_KEY}', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/foreign key/i);
  });

  it("reference: a reporting key citing real node + implementer inserts", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('00000000-0000-0000-0000-0000000000f3', '${NODE_ID}', '${IMPL_ID}', '${SECOND_KEY}', now())`,
    );
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("reference: a signing key citing an absent node is rejected; a real node inserts", (ctx) => {
    if (!reachable) ctx.skip();
    const bad = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('00000000-0000-0000-0000-0000000000f4', '${MISSING_ID}', 'EVENT_SIGNING', '${THIRD_KEY}', '${VAULT_REF_2}', now())`,
    );
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/foreign key/i);
    const good = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('00000000-0000-0000-0000-0000000000f5', '${OTHER_NODE_ID}', 'EVENT_SIGNING', '${THIRD_KEY}', '${VAULT_REF_2}', now())`,
    );
    expect(good.stderr).toBe("");
    expect(good.status).toBe(0);
  });

  it("domain: a malformed public_key is refused on both tables", (ctx) => {
    if (!reachable) ctx.skip();
    const malformed = [`${"A".repeat(42)}=`, `${"A".repeat(42)}!=`, "A".repeat(44)];
    for (const key of malformed) {
      const rk = run(
        `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
         VALUES ('00000000-0000-0000-0000-0000000000a9', '${NODE_ID}', '${IMPL_ID}', '${key}', now())`,
      );
      expect(rk.status, `reporting key ${JSON.stringify(key)} must be rejected`).not.toBe(0);
      expect(rk.stderr).toContain("padded_base64url_pubkey");
      const sk = run(
        `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
         VALUES ('00000000-0000-0000-0000-0000000000aa', '${NODE_ID}', 'EVENT_SIGNING', '${key}', '00000000-0000-0000-0000-0000000000ab', now())`,
      );
      expect(sk.status, `signing key ${JSON.stringify(key)} must be rejected`).not.toBe(0);
      expect(sk.stderr).toContain("padded_base64url_pubkey");
    }
  });

  it("check: a purpose outside {NODE_IDENTITY, EVENT_SIGNING} is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('00000000-0000-0000-0000-0000000000b2', '${NODE_ID}', 'ROTATION', '${FOURTH_KEY}', '00000000-0000-0000-0000-0000000000b3', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/check constraint/i);
  });

  it("check: retired_at earlier than activated_at is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at)
       VALUES ('00000000-0000-0000-0000-0000000000b4', '${NODE_ID}', 'EVENT_SIGNING', '${FOURTH_KEY}',
               '00000000-0000-0000-0000-0000000000b5', '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z')`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/check constraint/i);
  });

  it("unique: a duplicate vault_secret_ref is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('00000000-0000-0000-0000-0000000000b6', '${OTHER_NODE_ID}', 'EVENT_SIGNING', '${FOURTH_KEY}', '${VAULT_REF}', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/duplicate key|unique/i);
  });

  it("unique: a duplicate (node_id, implementer_id, public_key) reporting key is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    const result = run(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('00000000-0000-0000-0000-0000000000b7', '${NODE_ID}', '${IMPL_ID}', '${VALID_KEY}', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/duplicate key|unique/i);
  });

  it("the composite UNIQUE (id, node_id, implementer_id) backs a downstream receive_arms reference", (ctx) => {
    if (!reachable) ctx.skip();
    // The exact receive_arms consumption pattern: a child references the composite key. This only
    // succeeds if UNIQUE (id, node_id, implementer_id) exists on implementer_reporting_keys.
    const result = run(
      `CREATE TABLE probe_arm (
         reporting_key_id uuid,
         node_id uuid,
         implementer_id uuid,
         FOREIGN KEY (reporting_key_id, node_id, implementer_id)
           REFERENCES implementer_reporting_keys(id, node_id, implementer_id)
       )`,
    );
    expect(result.stderr, "composite unique must back the receive_arms reference").toBe("");
    expect(result.status).toBe(0);
  });

  it("unique: a duplicate (node_id, purpose, public_key) signing key is rejected", (ctx) => {
    if (!reachable) ctx.skip();
    // Same node + same purpose + same public key as the beforeAll NODE_IDENTITY_ONLY row; only
    // the id and vault_secret_ref differ, so the ONLY constraint that can reject it is
    // UNIQUE (node_id, purpose, public_key).
    const result = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("3001")}', '${NODE_IDENTITY_ONLY}', 'NODE_IDENTITY', '${IDENTITY_ONLY_KEY}', '${rid("9101")}', now())`,
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/duplicate key|unique/i);
    // ...and the same key under the OTHER purpose is accepted, which is exactly why the read
    // layer, not the schema, has to carry purpose separation.
    const crossPurpose = run(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("3002")}', '${NODE_IDENTITY_ONLY}', 'EVENT_SIGNING', '${IDENTITY_ONLY_KEY}', '${rid("9102")}', now())`,
    );
    expect(crossPurpose.stderr).toBe("");
    expect(crossPurpose.status).toBe(0);
    // Leave the fixture as the cross-purpose resolution test found it.
    expect(run(`DELETE FROM node_signing_keys WHERE id = '${rid("3002")}'`).status).toBe(0);
  });

  it("the composite UNIQUE (id, node_id, implementer_id, registered_at) backs a rotation-evidence reference", (ctx) => {
    if (!reachable) ctx.skip();
    // The wider composite is inventoried in the contract but was never exercised against
    // Postgres: a child table can only reference the 4-tuple if that UNIQUE exists.
    const result = run(
      `CREATE TABLE probe_rotation_evidence (
         reporting_key_id uuid,
         node_id uuid,
         implementer_id uuid,
         registered_at timestamptz,
         FOREIGN KEY (reporting_key_id, node_id, implementer_id, registered_at)
           REFERENCES implementer_reporting_keys(id, node_id, implementer_id, registered_at)
       )`,
    );
    expect(result.stderr, "wider composite unique must back the rotation-evidence reference").toBe(
      "",
    );
    expect(result.status).toBe(0);
  });

  // ---- read layer, driven against this same live schema -------------------------

  it("resolves the active key of exactly the requested purpose, in both directions", async (ctx) => {
    if (!reachable) ctx.skip();
    // A node holding ONLY a NODE_IDENTITY key answers EVENT_SIGNING with nothing.
    expect(await registry.findActiveNodeSigningKeys(NODE_IDENTITY_ONLY, "EVENT_SIGNING")).toEqual(
      [],
    );
    const identity = await registry.findActiveNodeSigningKeys(NODE_IDENTITY_ONLY, "NODE_IDENTITY");
    expect(identity).toHaveLength(1);
    expect(identity[0]?.public_key).toBe(IDENTITY_ONLY_KEY);
    expect(identity[0]?.purpose).toBe("NODE_IDENTITY");

    // ...and the reverse: a node holding ONLY an EVENT_SIGNING key answers NODE_IDENTITY with
    // nothing.
    expect(await registry.findActiveNodeSigningKeys(NODE_EVENT_ONLY, "NODE_IDENTITY")).toEqual([]);
    const event = await registry.findActiveNodeSigningKeys(NODE_EVENT_ONLY, "EVENT_SIGNING");
    expect(event).toHaveLength(1);
    expect(event[0]?.public_key).toBe(EVENT_ONLY_KEY);
    expect(event[0]?.purpose).toBe("EVENT_SIGNING");
  });

  it("never crosses key class when one public key is enrolled under both purposes", async (ctx) => {
    if (!reachable) ctx.skip();
    // The schema accepts the same public key under both purposes (proven by the seed landing).
    // signing custody rule 8: an exact-literal purpose lookup must still return the row of THAT purpose.
    const asIdentity = await registry.findNodeSigningKey(
      NODE_BOTH_PURPOSES,
      "NODE_IDENTITY",
      SHARED_KEY,
    );
    const asEvent = await registry.findNodeSigningKey(
      NODE_BOTH_PURPOSES,
      "EVENT_SIGNING",
      SHARED_KEY,
    );
    expect(asIdentity?.id).toBe(rid("1003"));
    expect(asIdentity?.purpose).toBe("NODE_IDENTITY");
    expect(asEvent?.id).toBe(rid("1004"));
    expect(asEvent?.purpose).toBe("EVENT_SIGNING");
    expect(asIdentity?.id).not.toBe(asEvent?.id);

    // Active resolution is equally class-bound: one row each, never both.
    for (const purpose of NODE_SIGNING_KEY_PURPOSES) {
      const active = await registry.findActiveNodeSigningKeys(NODE_BOTH_PURPOSES, purpose);
      expect(active).toHaveLength(1);
      expect(active[0]?.purpose).toBe(purpose);
    }
  });

  it("excludes a key retired in the past from active resolution but still resolves it by exact public key", async (ctx) => {
    if (!reachable) ctx.skip();
    const active = await registry.findActiveNodeSigningKeys(NODE_EXPIRING, "EVENT_SIGNING");
    // Three EVENT_SIGNING keys exist on this node; only the one whose window is open right now
    // -- activated in the past, retirement still in the future -- is active.
    expect(active.map((row) => row.public_key)).toEqual([FUTURE_RETIRE_KEY]);

    // The retired key remains resolvable by exact public key, WITH its retirement visible --
    // historical verification of an old signature must still be able to find it.
    const historical = await registry.findNodeSigningKey(
      NODE_EXPIRING,
      "EVENT_SIGNING",
      EXPIRED_KEY,
    );
    expect(historical?.id).toBe(rid("1005"));
    expect(historical?.public_key).toBe(EXPIRED_KEY);
    expect(historical?.retired_at).not.toBeNull();
    expect(Date.parse(historical?.retired_at ?? "")).toBeLessThan(Date.now());
  });

  it("excludes a key not yet activated from active resolution but still resolves it by exact public key", async (ctx) => {
    if (!reachable) ctx.skip();
    // The window is half-open on BOTH sides. A successor pre-registered for a future activation
    // is as inadmissible as a retired predecessor: it must not be reported as currently active,
    // or a verifier would accept its signatures before its window opens.
    const active = await registry.findActiveNodeSigningKeys(NODE_EXPIRING, "EVENT_SIGNING");
    expect(active.map((row) => row.public_key)).not.toContain(PENDING_KEY);
    expect(active.map((row) => row.public_key)).toEqual([FUTURE_RETIRE_KEY]);
    // Postgres, not the assertion, decides that the row is in fact present and future-dated.
    expect(
      run(
        `SELECT CASE WHEN activated_at > now() THEN 'NOT_YET_ACTIVE' ELSE 'ALREADY_ACTIVE' END
         FROM node_signing_keys WHERE id = '${rid("1007")}'`,
      ).stdout.trim(),
    ).toContain("NOT_YET_ACTIVE");

    // ...and it stays retrievable by exact public key, exactly like a retired key: enrolment
    // evidence and rotation audit must be able to find a key outside its window in either
    // direction. Historical lookup is window-free by design.
    const historical = await registry.findNodeSigningKey(
      NODE_EXPIRING,
      "EVENT_SIGNING",
      PENDING_KEY,
    );
    expect(historical?.id).toBe(rid("1007"));
    expect(historical?.public_key).toBe(PENDING_KEY);
    expect(Date.parse(historical?.activated_at ?? "")).toBeGreaterThan(Date.now());
  });

  it("resolves activate -> rotate -> retire with no purpose-scoped uniqueness violation", async (ctx) => {
    if (!reachable) ctx.skip();
    const purpose = "EVENT_SIGNING";
    // 1. activate
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("4001")}', '${NODE_ROTATING}', '${purpose}', '${ROTATE_KEY_1}', '${rid("9201")}',
               now() - interval '2 days')`,
    );
    let active = await registry.findActiveNodeSigningKeys(NODE_ROTATING, purpose);
    expect(active.map((row) => row.public_key)).toEqual([ROTATE_KEY_1]);

    // 2. rotate: the successor activates while the predecessor is still live. Same node, same
    // purpose, different public key -- UNIQUE (node_id, purpose, public_key) does NOT fire, and
    // the overlap is visible rather than collapsed to a single arbitrary winner.
    seed(
      `INSERT INTO node_signing_keys (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ('${rid("4002")}', '${NODE_ROTATING}', '${purpose}', '${ROTATE_KEY_2}', '${rid("9202")}',
               now() - interval '1 day')`,
    );
    active = await registry.findActiveNodeSigningKeys(NODE_ROTATING, purpose);
    // Both are live during the overlap. The result is an unranked set, so compare it as one.
    expect(active.map((row) => row.public_key).sort()).toEqual(
      [ROTATE_KEY_1, ROTATE_KEY_2].sort(),
    );

    // 3. retire the predecessor.
    const retire = run(
      `UPDATE node_signing_keys SET retired_at = now() - interval '1 second' WHERE id = '${rid("4001")}'`,
    );
    expect(retire.stderr).toBe("");
    expect(retire.status).toBe(0);
    active = await registry.findActiveNodeSigningKeys(NODE_ROTATING, purpose);
    expect(active.map((row) => row.public_key)).toEqual([ROTATE_KEY_2]);

    // The retired predecessor stays resolvable by exact public key throughout.
    const retired = await registry.findNodeSigningKey(NODE_ROTATING, purpose, ROTATE_KEY_1);
    expect(retired?.id).toBe(rid("4001"));
    expect(retired?.retired_at).not.toBeNull();

    // The whole lifecycle left the other purpose empty on this node.
    expect(await registry.findActiveNodeSigningKeys(NODE_ROTATING, "NODE_IDENTITY")).toEqual([]);
  });

  it("resolves reporting keys per (node, implementer) and never across implementers", async (ctx) => {
    if (!reachable) ctx.skip();
    const forA = await registry.findReportingKeys(NODE_IDENTITY_ONLY, IMPL_ID);
    expect(forA.map((row) => row.public_key)).toEqual([REPORTING_KEY_A]);
    const forB = await registry.findReportingKeys(NODE_IDENTITY_ONLY, IMPL_B_ID);
    expect(forB.map((row) => row.public_key)).toEqual([REPORTING_KEY_B]);

    expect((await registry.findReportingKey(NODE_IDENTITY_ONLY, IMPL_ID, REPORTING_KEY_A))?.id).toBe(
      rid("2001"),
    );
    // ...and implementer B cannot reach implementer A's enrolled key.
    expect(await registry.findReportingKey(NODE_IDENTITY_ONLY, IMPL_B_ID, REPORTING_KEY_A)).toBeNull();
  });

  it("the key-custody rule: the read layer returns public material only, never vault_secret_ref", async (ctx) => {
    if (!reachable) ctx.skip();
    const rows = await registry.findActiveNodeSigningKeys(NODE_IDENTITY_ONLY, "NODE_IDENTITY");
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0] ?? {})).toEqual([...NODE_SIGNING_KEY_COLUMNS]);
    expect(Object.keys(rows[0] ?? {})).not.toContain("vault_secret_ref");
    // The vault reference is real in the table and simply not projected.
    expect(
      run(
        `SELECT vault_secret_ref FROM node_signing_keys WHERE id = '${rid("1001")}'`,
      ).stdout.trim(),
    ).toContain(rid("9001"));
  });
});

// signing custody rule 8 is an ORDERING property, so its proof must never sit behind the
// TEST_DATABASE_URL gate: this block runs on every invocation of the suite, with or without a
// database. It proves the purpose comparison happens before the statement is issued -- and
// therefore before anything downstream could reach a verifier.
describe("signing-key read layer: exact-literal purpose (signing custody rule 8)", () => {
  const rejectingExecutor = (): { executor: SqlExecutor; calls: string[] } => {
    const calls: string[] = [];
    return {
      calls,
      executor: {
        query<R>(text: string): Promise<SqlQueryResult<R>> {
          calls.push(text);
          return Promise.reject(new Error("the executor must not be reached"));
        },
      },
    };
  };

  it("accepts exactly the two admissible literals and returns them unchanged", () => {
    expect([...NODE_SIGNING_KEY_PURPOSES]).toEqual(["NODE_IDENTITY", "EVENT_SIGNING"]);
    expect(assertExactPurpose("NODE_IDENTITY")).toBe("NODE_IDENTITY");
    expect(assertExactPurpose("EVENT_SIGNING")).toBe("EVENT_SIGNING");
  });

  it("rejects every near-miss: no case-folding, trimming, or partial match", () => {
    const nearMisses = [
      "node_identity",
      "Node_Identity",
      "NODE_IDENTITY ",
      " NODE_IDENTITY",
      "NODE_IDENTITY\n",
      "NODE_IDENT",
      "NODE_IDENTITY,EVENT_SIGNING",
      "event_signing",
      "EVENT_SIGNING'",
      "ROTATION",
      "",
      "*",
    ];
    for (const presented of nearMisses) {
      expect(() => assertExactPurpose(presented), JSON.stringify(presented)).toThrow(
        UnknownSigningKeyPurposeError,
      );
    }
  });

  it("compares the purpose BEFORE issuing any statement", async () => {
    const { executor, calls } = rejectingExecutor();
    const guarded = new SigningKeyRegistry(executor);
    await expect(guarded.findActiveNodeSigningKeys("node", "event_signing")).rejects.toThrow(
      UnknownSigningKeyPurposeError,
    );
    await expect(guarded.findNodeSigningKey("node", "ROTATION", VALID_KEY)).rejects.toThrow(
      UnknownSigningKeyPurposeError,
    );
    // The statement was never issued -- an unrecognised purpose cannot reach the database, so
    // it cannot reach a verifier either.
    expect(calls).toEqual([]);
  });

  it("offers no way to express a fallback across purposes", () => {
    // Rule 8: "there is no fallback verifier that tries multiple purposes". Every entry point
    // takes ONE purpose string, so a caller cannot pass a list, a wildcard, or a regex; and the
    // literal is bound as a parameter, never concatenated into the statement text.
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain("purpose = $2");
    expect(STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY).toContain("purpose = $2");
    for (const statement of Object.values(STATEMENTS)) {
      expect(statement).not.toMatch(/purpose\s+(IN|LIKE|~|ANY)/i);
    }
  });

  it("scopes the validity window to ACTIVE resolution only", () => {
    // Active resolution carries the window, BOTH sides of it -- a one-sided bound would report a
    // key that is outside its window as currently active.
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain("activated_at <= now()");
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).toContain(
      "(retired_at IS NULL OR retired_at > now())",
    );
    // The active set is returned unranked -- see the STATEMENTS comment. Nothing may sort it
    // into an implied "the" key.
    expect(STATEMENTS.SELECT_ACTIVE_NODE_KEYS).not.toMatch(/\bBY\b|\bLIMIT\b|\bDESC\b/);
    // ...and historical resolution deliberately does not FILTER on either bound, so a key
    // outside its window -- retired OR not yet activated -- stays resolvable by its exact public
    // key forever. It still SELECTS both timestamps, so the caller can see where in its window
    // the key it just resolved sits.
    const [projection, predicate] = STATEMENTS.SELECT_NODE_KEY_BY_PUBLIC_KEY.split(" WHERE ");
    expect(projection).toContain("retired_at");
    expect(projection).toContain("activated_at");
    expect(predicate).not.toContain("retired_at");
    expect(predicate).not.toContain("activated_at");
    expect(predicate).toBe("node_id = $1 AND purpose = $2 AND public_key = $3");
    // The reporting-key statements carry no window at all: the schema gives
    // implementer_reporting_keys no activated_at/retired_at, so there is no bound to be
    // one-sided about, and their lifecycle lives in the separate reporting tables.
    for (const statement of [
      STATEMENTS.SELECT_REPORTING_KEYS,
      STATEMENTS.SELECT_REPORTING_KEY_BY_PUBLIC_KEY,
    ]) {
      expect(statement).not.toContain("now()");
    }
  });

  it("the key-custody rule: no statement selects vault_secret_ref or any private-key column", () => {
    for (const statement of Object.values(STATEMENTS)) {
      expect(statement).not.toContain("vault_secret_ref");
      expect(statement).not.toMatch(/private_key|secret_key|key_material|signing_secret/);
    }
    expect([...NODE_SIGNING_KEY_COLUMNS]).not.toContain("vault_secret_ref");
    expect([...REPORTING_KEY_COLUMNS]).toEqual([
      "id",
      "node_id",
      "implementer_id",
      "public_key",
      "registered_at",
    ]);
  });
});

registerPgRequiredGuard({
  name: "signing-key-registry live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the signing-key beforeAll never completed — registry proofs skipped, not proven",
});
