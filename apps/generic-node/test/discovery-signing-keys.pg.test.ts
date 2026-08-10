// Offline disposable-PG proof that GET /.well-known/zupay-node publishes the
// durable NODE_IDENTITY/EVENT_SIGNING registry (apps/generic-node/src/full-http-mount.ts)
// across boot, rotation, and restart, and that the published public key actually verifies a
// signature produced by the corresponding sealed private key — not just that ids line up.
// Node signing keys live in node_signing_keys public rows + a separate sealed store.
//
// Scaffolding mirrors test/sql-boot-recovery.pg.test.ts / test/money-workers-fundable.pg.test.ts
// (disposable createdb/dropdb database, runMigrationsOnPool in beforeAll).

import { createPublicKey, randomBytes, randomUUID, verify as edVerify } from "node:crypto";
import { execFileSync } from "node:child_process";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { deriveRootKey, ensureActiveNodeSigningKey } from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createProductionRouteSurface } from "../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "discovery-master-key-32byte!!!!!!!!!!!";
// SPKI DER prefix for a raw 32-byte Ed25519 public key (same constant used elsewhere in this
// package to verify a signature against a padded-base64url public key).
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
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
        `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
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
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName], {
      env: process.env,
    });
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
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
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName],
      { env: process.env, stdio: "ignore" },
    );
    return;
  }
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
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

function verifiesAgainstDiscoveryKey(preimage: Buffer, signature: Buffer, publicKeyB64Url: string): boolean {
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyB64Url, "base64url")]);
  return edVerify(null, preimage, createPublicKey({ key: spki, format: "der", type: "spki" }), signature);
}

// Mirrors main.ts's boot-time withTx: ensureActiveNodeSigningKey takes its advisory lock via
// pg_advisory_xact_lock, which requires a real transaction block (autocommit-per-statement
// pool.query would fail the lock and fall back to the ensure module's in-memory-harness path).
async function ensureSigningKeyInTx(
  pool: Pool,
  input: { readonly rootKey: Buffer; readonly nodeId: string; readonly purpose: "NODE_IDENTITY" | "EVENT_SIGNING" },
) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const sql = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await client.query(text, params as never);
        return { rows: result.rows as R[] };
      },
    };
    const signer = await ensureActiveNodeSigningKey({ sql, ...input });
    await client.query("COMMIT");
    return signer;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

describe.skipIf(!PG_AVAILABLE)("discovery publishes the durable signing-key registry (disposable PG)", () => {
  const dbName = `discovery_signing_keys_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;
  let nodeId: string;

  beforeAll(async () => {
    await createTestDatabase(dbName);
    pool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: dbName,
      password: process.env.PGPASSWORD,
    });
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });

    nodeId = randomUUID();
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-discovery",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    await pool?.end().catch(() => {});
    await dropTestDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it(
    "boot: discovery publishes the ensured NODE_IDENTITY/EVENT_SIGNING keys with a verifiable signature and no private material",
    async () => {
      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
      const identity = await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "NODE_IDENTITY" });
      const event = await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "EVENT_SIGNING" });

      const surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT, nodeId, pool });
      const doc = await surface.discoveryDocument();

      expect(doc.expected_artifact_public_keys).toEqual([
        { key_id: identity.signingKeyId, public_key: identity.publicKey },
      ]);
      expect(doc.event_signing_public_keys).toEqual([
        { key_id: event.signingKeyId, public_key: event.publicKey },
      ]);

      // The published key is not just an id/pubkey echo — it actually verifies a real
      // signature produced by the sealed private key ensure() loaded (the byte-exact signing and never-blind-retry rules territory:
      // the discovery surface must be usable to independently verify a real artifact).
      const preimage = Buffer.from("fixture boot verification preimage", "utf8");
      const signature = Buffer.from(identity.sign(preimage));
      expect(verifiesAgainstDiscoveryKey(preimage, signature, doc.expected_artifact_public_keys[0]!.public_key)).toBe(
        true,
      );

      const json = JSON.stringify(doc);
      expect(json).not.toContain("vault_secret_ref");
      expect(json).not.toContain("ciphertext");
      expect(json).not.toContain(MASTER);
      expect(json).not.toContain(rootKey.toString("hex"));
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "rotation: after retiring the active NODE_IDENTITY key and minting a fresh one, discovery shows the new active key PLUS the retained-valid prior key, and both signatures still verify",
    async () => {
      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
      // Self-contained precondition (does not depend on the "boot" test having run first):
      // ensure() is idempotent, so this either loads the identity minted by an earlier test
      // in this file or mints one fresh — either way there is exactly one active row after.
      const baseline = await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "NODE_IDENTITY" });

      const surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT, nodeId, pool });
      const before = await surface.discoveryDocument();
      const priorKeyId = before.expected_artifact_public_keys[0]!.key_id;
      const priorPublicKey = before.expected_artifact_public_keys[0]!.public_key;
      expect(priorKeyId).toBe(baseline.signingKeyId);

      // A signature produced BEFORE rotation, under the about-to-be-retired key — this is the
      // artifact/event a real integrator needs discovery to keep verifiable after rotation.
      const preRotationPreimage = Buffer.from("fixture pre-rotation preimage", "utf8");
      const preRotationSignature = Buffer.from(baseline.sign(preRotationPreimage));

      // retired_at = now(), never earlier: the CHECK constraint requires retired_at >=
      // activated_at, and the baseline row's activated_at can itself be `now()` from moments
      // ago in this same test.
      await pool.query(
        `UPDATE node_signing_keys SET retired_at = now()
          WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' AND retired_at IS NULL`,
        [nodeId],
      );
      const rotated = await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "NODE_IDENTITY" });
      expect(rotated.publicKey).not.toBe(priorPublicKey);

      const after = await surface.discoveryDocument();
      const afterKeyIds = after.expected_artifact_public_keys.map((k) => k.key_id);
      // Retained-valid prior key PLUS the new active key — never just the new one (AC).
      expect(afterKeyIds).toContain(priorKeyId);
      expect(afterKeyIds).toContain(rotated.signingKeyId);
      expect(after.expected_artifact_public_keys).toEqual([
        { key_id: priorKeyId, public_key: priorPublicKey },
        { key_id: rotated.signingKeyId, public_key: rotated.publicKey },
      ]);

      const priorInterval = after.key_validity_intervals.find((i) => i.key_id === priorKeyId);
      expect(priorInterval?.valid_until).not.toBeNull();
      const activeInterval = after.key_validity_intervals.find((i) => i.key_id === rotated.signingKeyId);
      expect(activeInterval?.valid_until).toBeNull();

      // The pre-rotation signature verifies from discovery's retained prior key...
      expect(
        verifiesAgainstDiscoveryKey(preRotationPreimage, preRotationSignature, priorPublicKey),
      ).toBe(true);
      // ...and a fresh signature verifies from discovery's new active key.
      const postRotationPreimage = Buffer.from("fixture post-rotation preimage", "utf8");
      const postRotationSignature = Buffer.from(rotated.sign(postRotationPreimage));
      expect(
        verifiesAgainstDiscoveryKey(postRotationPreimage, postRotationSignature, rotated.publicKey),
      ).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "restart: a fresh discoveryDocument() call (simulating process restart, no in-memory cache) reproduces the same durable keys",
    async () => {
      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
      // Self-contained precondition, same rationale as the rotation test above.
      await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "NODE_IDENTITY" });
      await ensureSigningKeyInTx(pool, { rootKey, nodeId, purpose: "EVENT_SIGNING" });

      const surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT, nodeId, pool });
      const first = await surface.discoveryDocument();

      // A brand-new surface (as boot would construct on restart) reading the same pool must
      // see byte-identical keys — proving the document comes from durable storage, not from
      // whatever a single process happened to ensure in memory at boot.
      const restartedSurface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT, nodeId, pool });
      const second = await restartedSurface.discoveryDocument();

      expect(JSON.stringify(second)).toBe(JSON.stringify(first));
      expect(first.expected_artifact_public_keys.length).toBeGreaterThan(0);
      expect(first.event_signing_public_keys.length).toBeGreaterThan(0);
    },
    PG_TEST_TIMEOUT_MS,
  );
});
