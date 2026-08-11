// The reporting-credential service the POST /admin/v1/reporting-keys route mounts.
// Proves, against a real Postgres, the money-substance the route wraps:
//   * issue() node-mints the credential via the SAME first-key ceremony and RETURNS
//     the raw private seed exactly once, byte-equal to the ceremony's minted key;
//   * the node persists PUBLIC material only — the seed appears in NO persisted column of any
//     reporting table (0 private/seed columns);
//   * list() surfaces the public identity + derived status and never the seed;
//   * a second issue finds the credential already ACTIVE and fails closed (409-mapped code).
// DB-TEST-28: exact raw target request preimage/digest/signature exact-body digest survive round-trip


import { execFileSync } from "node:child_process";
import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { toBase64UrlPadded } from "@zucoins/node-core";

import { issueReportingCredential } from "../src/bootstrap/reporting-key-enrol.js";
import { createSqlReportingCredentialService } from "../src/reporting-credential-service.js";

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_CREATEDB = hasClientTool("createdb");
const HAS_DROPDB = hasClientTool("dropdb");

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync(
        "pg_isready",
        ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER],
        { stdio: "ignore" },
      );
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env, cwd: fileURLToPath(new URL("..", import.meta.url)) },
    );
    return true;
  } catch {
    return false;
  }
})();

function adminClientConfig(database = "postgres") {
  return { host: PG_HOST, port: PG_PORT, user: PG_USER, database, password: process.env.PGPASSWORD };
}

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) throw new Error(`unsafe test db name: ${dbName}`);
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], { stdio: "ignore" });
    return;
  }
  const admin = new Client(adminClientConfig());
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await admin.end();
  }
}

async function dropTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_DROPDB) {
    execFileSync("dropdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName], { stdio: "ignore" });
    return;
  }
  const admin = new Client(adminClientConfig());
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
  } finally {
    await admin.end();
  }
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

function privateKeyFromSeedHex(seedHex: string): KeyObject {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

const pubOf = (privateKey: KeyObject): string =>
  toBase64UrlPadded(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32),
  );

// Every reporting-lifecycle table the first-key ceremony writes (see reporting-key-enrol wipe set).
const REPORTING_TABLES = [
  "implementer_reporting_keys",
  "reporting_key_lifecycle_heads",
  "reporting_key_lifecycle_states",
  "reporting_key_lifecycle_events",
  "reporting_key_state_transitions",
  "reporting_key_enrolment_evidence",
  "reporting_key_bootstrap_evidence",
  "reporting_request_nonces",
] as const;

describe.skipIf(!PG_AVAILABLE)("reporting-credential service (public-only persist, raw once)", () => {
  const scratchDb = `admin_reporting_keys_svc_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const IMPLEMENTER_ID = randomUUID();
  const SEED = Buffer.alloc(32, 0x51);
  const SEED_HEX = SEED.toString("hex");

  let pool: Pool;

  beforeAll(async () => {
    await createTestDatabase(scratchDb);
    process.env.DATABASE_URL ??= pgDatabaseUrl(scratchDb);
    pool = new Pool({ host: PG_HOST, port: PG_PORT, user: PG_USER, database: scratchDb, password: process.env.PGPASSWORD });
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool);

    const identityPk = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    await pool.query(`INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`, [
      NODE_ID,
      "admin-reporting-keys",
      identityPk,
    ]);
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [IMPLEMENTER_ID, "impl-1009"]);
  }, 300_000);

  afterAll(async () => {
    await pool?.end();
    try {
      await dropTestDatabase(scratchDb);
    } catch {
      /* best effort */
    }
  });

  it("DB-TEST-28: exact raw target request preimage/digest/signature exact-body digest survive round-trip", async () => {
    const issued = await issueReportingCredential(pool, {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      onboardingActorId: "operator-session-1",
      seed: SEED,
    });

    // Returned raw seed IS the ceremony's minted key (seed hex + derived public key).
    expect(issued.raw_private_key).toBe(SEED_HEX);
    expect(pubOf(privateKeyFromSeedHex(issued.raw_private_key))).toBe(issued.public_key);

    // Persisted key row carries the public key — and never the seed.
    const row = await pool.query<{ j: Record<string, unknown> }>(
      `SELECT to_jsonb(k) AS j FROM implementer_reporting_keys k WHERE id = $1::uuid`,
      [issued.id],
    );
    expect(row.rowCount).toBe(1);
    expect(row.rows[0]!.j.public_key).toBe(issued.public_key);

    // 0 private/seed columns: the seed hex is absent from every persisted reporting table.
    for (const table of REPORTING_TABLES) {
      const dump = await pool.query<{ j: unknown }>(
        `SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) AS j FROM ${table} t WHERE node_id = $1::uuid`,
        [NODE_ID],
      );
      expect(JSON.stringify(dump.rows[0]!.j), `${table} must not persist the seed`).not.toContain(SEED_HEX);
    }
  });

  it("list surfaces the public identity + ACTIVE status and never the seed", async () => {
    const svc = createSqlReportingCredentialService(pool, NODE_ID);
    const listing = await svc.list();
    expect(listing).toHaveLength(1);
    expect(listing[0]!.node_id).toBe(NODE_ID);
    expect(listing[0]!.status).toBe("ACTIVE");
    expect(pubOf(privateKeyFromSeedHex(SEED_HEX))).toBe(listing[0]!.public_key);
    expect(JSON.stringify(listing)).not.toContain(SEED_HEX);
  });

  it("a second issue finds the credential already ACTIVE and fails closed (raw shown only once)", async () => {
    const svc = createSqlReportingCredentialService(pool, NODE_ID);
    await expect(svc.issue("operator-session-2")).rejects.toMatchObject({
      code: "reporting_key_already_active",
    });
  });
});
