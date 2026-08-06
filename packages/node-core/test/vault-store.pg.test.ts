// census + real-PostgreSQL behavioural proof for vault.sql and VaultSqlStore
// The census block binds the frozen invariant inventory to the literal SQL and runs
// always; the live block is gated on TEST_DATABASE_URL, layers vault.sql on the
// prerequisite chain (base-enums-domains + nodes + custody-eligibility) and discharges
// every VAULT_EXECUTION_OBLIGATION against a real database — including the guard-1
// nonce-reuse constraint, which is a persistence property no in-memory Map can express.
//
// psql runs as a child process (node:child_process), keeping the in-process
// network-containment guard (setup-network-guard.ts) intact — exactly as
// migration-integrity.test.ts and signing-key-registry.pg.test.ts do.
//
// The key-custody rule: only sealed bytes cross this file's database boundary. The plaintext secret
// exists in-process to seal and to assert the round trip, is wiped after each open, and is
// never inserted, selected, or printed.
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  VAULT_EXECUTION_OBLIGATIONS,
  VAULT_SCHEMA_FILE,
  VAULT_SCHEMA_INVARIANTS,
} from "../src/schema/vault.contract.ts";
import {
  openWalletSecret,
  sealWalletSecret,
  toBase64UrlPadded,
  type SealedEnvelope,
  type VaultRecord,
  type WalletIdentity,
} from "../src/vault/index.js";
import {
  STATEMENTS,
  VAULT_COLUMNS,
  VaultSqlStore,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/vault/sql-store.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const sqlPath = resolve(schemaDir, VAULT_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

// A `--` comment runs to end of line; strip them so a word appearing only in prose (the
// header explains at length why there is no AAD column) cannot satisfy a structural check.
const sqlBody = sql.replace(/--.*$/gm, "");

/* ─── census (no database required) ───────────────────────────────── */

describe("vault schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = VAULT_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the one table and re-declares no prerequisite", () => {
    expect(sqlBody).toContain("CREATE TABLE vault (");
    expect(sqlBody.match(/CREATE TABLE/g)).toHaveLength(1);
    // wallets / domains belong to custody-eligibility + base-enums-domains (chain);
    // re-declaring either here would fork a frozen contract.
    expect(sqlBody).not.toContain("CREATE TABLE wallets");
    expect(sqlBody).not.toContain("CREATE DOMAIN");
  });

  it("carries no stored AAD column (guard 2)", () => {
    expect(sqlBody).not.toMatch(/\baad/i);
  });

  it("carries no plaintext key material column (the key-custody rule)", () => {
    // Deliberately wider than the columns the data model declares, so a future rename into any of
    // these shapes trips the guard rather than sliding past it.
    expect(sqlBody).not.toMatch(
      /private_key|secret_key|\bseed\b|plaintext|key_material|master_key|\bdek\b|sk_bytes|\bmnemonic\b/i,
    );
  });

  it("reads by primary key only — no row lock on vault (guard 4)", () => {
    expect(STATEMENTS.findByWalletId).toMatch(/WHERE wallet_id = \$1\s*$/);
    for (const statement of Object.values(STATEMENTS)) {
      expect(statement).not.toMatch(/FOR (UPDATE|NO KEY UPDATE|SHARE|KEY SHARE)/i);
    }
  });

  it("the store's column list is the table's column list, in order", () => {
    const declared = /CREATE TABLE vault \(([\s\S]*?)\n\);/.exec(sqlBody)?.[1] ?? "";
    const columns = declared
      .split("\n")
      .map((line) => /^\s{2}([a-z_][a-z0-9_]*)\s/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined);
    expect(columns).toEqual([...VAULT_COLUMNS]);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace("UNIQUE (key_version, nonce)", "-- removed");
    const missing = VAULT_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["VAULT_NONCE_UNIQUE_PER_VERSION"]);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(VAULT_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(6);
    for (const obligation of VAULT_EXECUTION_OBLIGATIONS) {
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

/* ─── psql harness ────────────────────────────────────────────────── */

const databaseUrl = process.env.TEST_DATABASE_URL;
const _MAINTENANCE_DB = "postgres";
const SCHEMA = "vault_store_vault";
// Hermetic scratch DB (sibling pattern after): shared maintenance DBs often have
// pgcrypto installed into a leftover schema, so CREATE EXTENSION IF NOT EXISTS then leaves
// digest() off search_path. A fresh database keeps base-enums-domains.sql green.
const scratchDb = `vault_store_vault_${Date.now()}_${process.pid}`;
let scratchDbUrl: string | undefined = databaseUrl;
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_FOREIGN_KEY_VIOLATION = "23503";
const SQLSTATE_CHECK_VIOLATION = "23514";
const NONCE_CONSTRAINT = "vault_key_version_nonce_key";

const pgEnv = (): Record<string, string> => {
  const url = new URL((scratchDbUrl ?? databaseUrl) as string);
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

// VERBOSITY=verbose makes psql emit the machine-readable `ERROR:  <sqlstate>:` and
// `CONSTRAINT NAME:` lines the negative drills assert on.
const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync(
      "psql",
      ["-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-q", ...args],
      { env: pgEnv(), stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
    );
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

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}, public`, "-c", statement]);

// Unaligned, tuples-only: one bare value per line, no header and no `(n rows)` footer.
const queryColumn = (statement: string): string[] => {
  const result = psql(["-t", "-A", "-c", `SET search_path TO ${SCHEMA}, public`, "-c", statement]);
  expect(result.stderr, statement).toBe("");
  return result.stdout.split("\n").filter((line) => line.length > 0);
};

const seed = (statement: string): void => {
  const result = run(statement);
  expect(result.stderr, `seed must apply cleanly: ${statement}`).toBe("");
  expect(result.status, `seed must apply cleanly: ${statement}`).toBe(0);
};

const extract = (stderr: string, pattern: RegExp): string => pattern.exec(stderr)?.[1] ?? "";
const sqlstateOf = (error: unknown): string =>
  extract(String((error as Error).message), /\bERROR:\s+([0-9A-Z]{5}):/);
const constraintOf = (error: unknown): string =>
  extract(String((error as Error).message), /CONSTRAINT NAME:\s+(\S+)/);

/* ─── a REAL-PostgreSQL SqlExecutor ───────────────────────────────── */
// node-core is network-contained and depends on no database driver, so VaultSqlStore
// takes an injected SqlExecutor. This one is backed by the same psql child process the rest of
// the file uses: it issues the store's OWN statement text against the live schema and maps the
// tuple output back through the store's OWN column constants. The only rewrites are the two
// things psql's text protocol cannot carry — `$n` bind parameters, and the value shapes
// node-postgres returns for bytea (Buffer) and timestamptz (Date).
const FIELD_SEP = "|";
const NULL_TOKEN = "<PGNULL>";
const BYTEA_COLUMNS = new Set(["ciphertext", "nonce", "auth_tag"]);
const TIMESTAMP_COLUMNS = new Set(["created_at", "rotated_at"]);

const sqlLiteral = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (value instanceof Uint8Array) return `'\\x${Buffer.from(value).toString("hex")}'::bytea`;
  if (value instanceof Date) return `'${value.toISOString()}'::timestamptz`;
  if (typeof value === "number") return String(value);
  return `'${String(value).replaceAll("'", "''")}'`;
};

// psql prints timestamptz as `2026-07-25 08:30:00.123456+00`; normalise to ISO-8601 so
// Date.parse is not relying on engine-specific leniency.
const toDate = (text: string): Date => {
  const iso = text.replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00");
  const date = new Date(iso);
  expect(Number.isNaN(date.getTime()), `unparseable timestamp: ${text}`).toBe(false);
  return date;
};

const decode = (column: string, text: string): unknown => {
  if (text === NULL_TOKEN) return null;
  if (BYTEA_COLUMNS.has(column)) return Buffer.from(text.slice(2), "hex");
  if (TIMESTAMP_COLUMNS.has(column)) return toDate(text);
  if (column === "key_version") return Number(text);
  return text;
};

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
      `SET search_path TO ${SCHEMA}, public`,
      "-c",
      statement,
    ]);
    if (result.status !== 0) return Promise.reject(new Error(result.stderr));
    const columns = statement.includes("RETURNING wallet_id") ? ["wallet_id"] : VAULT_COLUMNS;
    const rows = result.stdout
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const values = line.split(FIELD_SEP);
        return Object.fromEntries(
          columns.map((column, i) => [column, decode(column, values[i] ?? NULL_TOKEN)]),
        );
      }) as R[];
    return Promise.resolve({ rows });
  },
};

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "d0000000-0000-4000-8000-000000000001";
const WALLET_A = "d0000000-0000-4000-8000-00000000000a";
const WALLET_B = "d0000000-0000-4000-8000-00000000000b";
const WALLET_C = "d0000000-0000-4000-8000-00000000000c";
const UNKNOWN_WALLET = "d0000000-0000-4000-8000-0000000000ee";

// A 32-byte root key stands in for the PBKDF2-600k boot derivation, whose cost buys nothing
// here — deriveRootKey is covered by vault.test.ts. The master key is never DB-resident.
const ROOT_KEY = Buffer.alloc(32, 0x5a);

interface TestWallet {
  readonly secretKey: Buffer;
  readonly identity: WalletIdentity;
}

const makeWallet = (walletId: string): TestWallet => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32);
  const raw = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  return {
    secretKey: Buffer.concat([seed, raw]),
    identity: {
      nodeId: NODE_ID,
      walletId,
      keyVersion: 1,
      publicKey: toBase64UrlPadded(raw),
      keyOrigin: "node_generated",
    },
  };
};

const recordOf = (envelope: SealedEnvelope, createdAt: Date): VaultRecord => ({
  ...envelope,
  createdAt,
  rotatedAt: null,
});

// Wallets PK is `id`; public_key / identity_public_key are padded_base64url_pubkey (44-char).
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
  `('${NODE_ID}', 'vault-store-vault', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

const seedWallet = (wallet: TestWallet): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
  `('${wallet.identity.walletId}', '${NODE_ID}', '${wallet.identity.publicKey}', ` +
  `'${wallet.identity.keyOrigin}', 'AVAILABLE');`;

/* ─── live PostgreSQL ─────────────────────────────────────────────── */

let reachable = false;
let obligationsRun = 0;
// The five DATABASE-executed obligations in VAULT_EXECUTION_OBLIGATIONS (the sixth, the
// no-row-lock read shape, is a statement-text property proven in the census block above),
// plus the rewrap drill.
const EXPECTED_DRILL_COUNT = 6;

describe.skipIf(databaseUrl === undefined)(
  "vault storage against a live PostgreSQL",
  () => {
    const store = new VaultSqlStore(livePsqlExecutor);
    const walletA = makeWallet(WALLET_A);
    const walletB = makeWallet(WALLET_B);
    const walletC = makeWallet(WALLET_C);

    beforeAll(() => {
      // Probe maintenance URL first (scratch does not exist yet).
      scratchDbUrl = databaseUrl;
      reachable = psql(["-c", "SELECT 1"]).status === 0;
      if (!reachable) return;

      const created = psql(["-c", `CREATE DATABASE ${scratchDb}`]);
      expect(created.status, `scratch DB create: ${created.stderr}`).toBe(0);
      // Point subsequent psql at the hermetic DB.
      const baseUrl = new URL(databaseUrl as string);
      baseUrl.pathname = `/${scratchDb}`;
      scratchDbUrl = baseUrl.toString();

      psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
      psql(["-c", `CREATE SCHEMA ${SCHEMA}`]);

      // Custody is prerequisite-bound -- base enums/domains + nodes, then custody, then vault.
      // Lifted from frozen files (same chain as send-external / lease-lock / pg-concurrency drills).
      const base = readFileSync(resolve(schemaDir, "base-enums-domains.sql"), "utf8");
      const registry = readFileSync(resolve(schemaDir, "node-implementer-registry.sql"), "utf8");
      const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry)?.[0];
      expect(nodes, "nodes table must be liftable from node-implementer-registry.sql").toBeDefined();

      const applied = psql([
        "-c",
        `SET search_path TO ${SCHEMA}, public`,
        "-c",
        base,
        "-c",
        nodes as string,
        "-f",
        resolve(schemaDir, "custody-eligibility.sql"),
        "-f",
        sqlPath,
      ]);
      expect(applied.status, `vault.sql must apply on the custody base: ${applied.stderr}`).toBe(0);
      expect(applied.stderr, `vault.sql apply must not ERROR: ${applied.stderr}`).not.toMatch(/\bERROR:/);

      seed(seedNode());
      seed(seedWallet(walletA));
      seed(seedWallet(walletB));
      seed(seedWallet(walletC));
    });

    afterAll(() => {
      if (!reachable) return;
      // Drop only our prefix-scoped scratch database on the shared server.
      scratchDbUrl = databaseUrl;
      psql(["-c", `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`]);
    });

    it("materializes exactly the eight frozen columns", (ctx) => {
      if (!reachable) ctx.skip();
      const live = queryColumn(
        `SELECT column_name FROM information_schema.columns
          WHERE table_schema = '${SCHEMA}' AND table_name = 'vault'
          ORDER BY ordinal_position`,
      );
      expect(live).toEqual([...VAULT_COLUMNS]);
      obligationsRun += 1;
    });

    it("round-trips a sealed envelope through the database byte-identically", async (ctx) => {
      if (!reachable) ctx.skip();
      const envelope = sealWalletSecret(ROOT_KEY, walletA.identity, walletA.secretKey);
      await store.insert(recordOf(envelope, new Date("2026-07-25T00:00:00.000Z")));

      const loaded = await store.findByWalletId(WALLET_A);
      expect(loaded).not.toBeNull();
      expect(Buffer.from(loaded!.ciphertext).equals(Buffer.from(envelope.ciphertext))).toBe(true);
      expect(Buffer.from(loaded!.nonce).equals(Buffer.from(envelope.nonce))).toBe(true);
      expect(Buffer.from(loaded!.authTag).equals(Buffer.from(envelope.authTag))).toBe(true);
      expect(loaded!.ciphertextSha256).toBe(envelope.ciphertextSha256);
      expect(loaded!.keyVersion).toBe(1);
      expect(loaded!.rotatedAt).toBeNull();

      // The persisted bytes still open, and the plaintext still derives the authoritative
      // public key — the signing custody substitution control, now over a real row.
      const secret = openWalletSecret(ROOT_KEY, loaded!, walletA.identity);
      expect(Buffer.from(secret.bytes).equals(walletA.secretKey)).toBe(true);
      secret.wipe();
      obligationsRun += 1;
    });

    it("rejects a duplicate (key_version, nonce) with unique_violation (23505)", async (ctx) => {
      if (!reachable) ctx.skip();
      const first = sealWalletSecret(ROOT_KEY, walletB.identity, walletB.secretKey);
      await store.insert(recordOf(first, new Date("2026-07-25T00:00:01.000Z")));

      // A DIFFERENT wallet (so the primary key cannot be the rejector) re-using wallet B's
      // nonce at the same key version. Only UNIQUE (key_version, nonce) can refuse this.
      const collided = sealWalletSecret(ROOT_KEY, walletC.identity, walletC.secretKey);
      const duplicate = recordOf(
        { ...collided, nonce: first.nonce },
        new Date("2026-07-25T00:00:02.000Z"),
      );

      const error = await store.insert(duplicate).then(() => null, (e: unknown) => e);
      expect(error, "duplicate (key_version, nonce) must be rejected").not.toBeNull();
      expect(sqlstateOf(error)).toBe(SQLSTATE_UNIQUE_VIOLATION);
      expect(constraintOf(error)).toBe(NONCE_CONSTRAINT);

      // The colliding row did not land: wallet C still has no envelope.
      expect(await store.findByWalletId(WALLET_C)).toBeNull();
      obligationsRun += 1;
    });

    it("rejects a non-positive key_version with check_violation (23514)", async (ctx) => {
      if (!reachable) ctx.skip();
      const envelope = sealWalletSecret(ROOT_KEY, walletC.identity, walletC.secretKey);
      const invalid = recordOf({ ...envelope, keyVersion: 0 }, new Date("2026-07-25T00:00:03.000Z"));

      const error = await store.insert(invalid).catch((e: unknown) => e);
      expect(sqlstateOf(error)).toBe(SQLSTATE_CHECK_VIOLATION);
      obligationsRun += 1;
    });

    it("rejects an envelope for a wallet that does not exist (23503)", async (ctx) => {
      if (!reachable) ctx.skip();
      const orphan = makeWallet(UNKNOWN_WALLET);
      const envelope = sealWalletSecret(ROOT_KEY, orphan.identity, orphan.secretKey);
      const error = await store
        .insert(recordOf(envelope, new Date("2026-07-25T00:00:04.000Z")))
        .catch((e: unknown) => e);
      expect(sqlstateOf(error)).toBe(SQLSTATE_FOREIGN_KEY_VIOLATION);
      obligationsRun += 1;
    });

    it("rewraps an existing envelope in place and refuses one that is absent", async (ctx) => {
      if (!reachable) ctx.skip();
      const rotatedAt = new Date("2026-07-25T01:00:00.000Z");
      const resealed = sealWalletSecret(ROOT_KEY, walletA.identity, walletA.secretKey);
      await store.update({ ...resealed, createdAt: new Date(), rotatedAt });

      const loaded = await store.findByWalletId(WALLET_A);
      expect(Buffer.from(loaded!.nonce).equals(Buffer.from(resealed.nonce))).toBe(true);
      expect(loaded!.rotatedAt?.toISOString()).toBe(rotatedAt.toISOString());

      const orphan = makeWallet(UNKNOWN_WALLET);
      const missing = sealWalletSecret(ROOT_KEY, orphan.identity, orphan.secretKey);
      await expect(
        store.update({ ...missing, createdAt: new Date(), rotatedAt }),
      ).rejects.toThrow(/no vault row/);
      obligationsRun += 1;
    });
  },
);

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level, OUTSIDE the gated describe, so it runs even when that block skips itself.
 * vitest.global-setup.ts assigns TEST_DATABASE_URL whenever a Postgres maintenance database is
 * reachable, and scripts/verify-local.sh exports PG_REQUIRED=1 only after its own pg_isready
 * probe succeeded. Under PG_REQUIRED=1, an unassigned URL or an unreachable server is therefore
 * a BROKEN HARNESS, never "no Postgres here" — the exact silent-skip regression this guard
 * exists to catch, so it fails loudly instead of reporting green having executed nothing. */
it("real-PostgreSQL vault drills must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — no test database was provisioned",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — its assertions were skipped, not proven",
  ).toBe(true);
  expect(
    obligationsRun,
    "PostgreSQL was reachable but the vault drills did not run — undischarged obligations",
  ).toBe(EXPECTED_DRILL_COUNT);
});
