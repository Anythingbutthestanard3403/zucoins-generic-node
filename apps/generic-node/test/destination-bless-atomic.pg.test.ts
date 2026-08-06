// Destination bless/retire must be ATOMIC with the admin idempotency
// transaction. The prior defect: main.ts's destinationServiceForSql factory rebound
// only the SQL store to the tx client but reused a boot pool-bound blessingAuthorizer,
// so authorize()'s destination_blessing_artifacts INSERT + audit_log INSERT auto-
// committed on the POOL before store.bless() ran on the tx client. A post-action
// rollback then orphaned the artifact+audit, and because the artifact IS the single-
// use nonce marker, a same-nonce retry was permanently stuck on nonce_reused.
//
// The fix binds a PER-CLIENT authorizer (blessingAuthorizerForSql(client)) so
// artifact+audit+destination update all land on ONE connection. This drives a real
// bless/retire through createAtomicAdminMutationExecutor with a real per-client
// destinationServiceForSql — the exact production wiring shape from full-http-mount.ts
// — and proves: happy-path one-tx write, forced rollback leaves ZERO rows, same-nonce
// retry after rollback still blesses, and replay adds no second artifact.
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool, type PoolClient } from "pg";

import {
  buildDestinationBless,
  createDestinationService,
  createDeviceBlessingAuthorizer,
  createSqlActiveDeviceLookup,
  createSqlBlessingArtifactPersister,
  createSqlBlessingAuditAppender,
  createSqlDestinationStore,
  type BlessDestinationRequest,
  type DestinationSqlExecutor,
  type DestinationService,
  type RetireDestinationRequest,
  type Uuid,
  type WalletPublicKey,
} from "@zucoins/node-core";

import {
  SqlAdminIdempotencyStore,
  type AdminIdempotencyStore,
} from "../src/ops/admin-idempotency.js";
import { createAtomicAdminMutationExecutor } from "../src/ops/atomic-admin-mutation.js";

const PG_TEST_TIMEOUT_MS = 120_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

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
    // Fall through to the direct driver probe.
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

function adminConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function assertSafeDbName(name: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) throw new Error(`unsafe database name: ${name}`);
}

async function createDatabase(name: string): Promise<void> {
  assertSafeDbName(name);
  if (HAS_CREATEDB) {
    execFileSync("createdb", ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, name], {
      env: process.env,
    });
    return;
  }
  const admin = new Client(adminConfig());
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
}

async function dropDatabase(name: string): Promise<void> {
  assertSafeDbName(name);
  if (HAS_DROPDB) {
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", name],
      { env: process.env, stdio: "ignore" },
    );
    return;
  }
  const admin = new Client(adminConfig());
  await admin.connect();
  try {
    await admin.query(
      "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
      [name],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
  } finally {
    await admin.end();
  }
}

// --- device-signature helpers (same shape as destination-bless-e2e.test.ts) ---
const DEVICE_SEED = 0x01;
function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
function pubB64(byte: number): string {
  const pub = createPublicKey(privFromSeed(byte));
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  return Buffer.from(spki.subarray(-32)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}
function signB64(preimage: string, seedByte: number): string {
  const sig = sign(null, Buffer.from(preimage, "utf8"), privFromSeed(seedByte));
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}
const DEVICE_PUB = pubB64(DEVICE_SEED);

function fingerprint(bodySha256 = "a".repeat(64)) {
  return { method: "POST", rawTarget: "/admin/v1/destinations", bodySha256 };
}

// A store double whose pre-action findCompleted DELEGATES to the real store (so the bless/
// retire action actually RUNS and writes on the tx client), then throws from recordCompleted
// — the FIRST post-action write (atomic-admin-mutation.ts line 85) — exactly once. This forces
// the rollback AFTER the child writes, the only way to catch a pool-bound authorizer that
// auto-commits artifact+audit on a separate connection. The prior approach renamed the whole
// admin_mutation_idempotency table, which fired 42P01 at the PRE-action findCompleted (line 66)
// before the bless ever ran — so artifacts===0 passed even with the defect reintroduced. The
// throw is not a 23505, so the executor rethrows it (never miscast as an idempotency race).
// Subsequent calls delegate, so the same-key retry completes.
class ThrowOncePostWrite implements AdminIdempotencyStore {
  private armed = true;
  constructor(private readonly real: AdminIdempotencyStore) {}
  ensureSchema(): Promise<void> {
    return this.real.ensureSchema();
  }
  findCompleted(
    nodeId: string,
    routeId: string,
    idempotencyKey: string,
    tx?: { query(text: string, params?: readonly unknown[]): Promise<unknown> },
  ): ReturnType<AdminIdempotencyStore["findCompleted"]> {
    return this.real.findCompleted(nodeId, routeId, idempotencyKey, tx);
  }
  async recordCompleted(
    input: Parameters<AdminIdempotencyStore["recordCompleted"]>[0],
  ): Promise<void> {
    if (this.armed) {
      this.armed = false;
      throw new Error("injected post-write failure (recordCompleted)");
    }
    await this.real.recordCompleted(input);
  }
}

interface DestinationTxPorts {
  readonly destinationService: DestinationService;
}

describe.skipIf(!PG_AVAILABLE)("destination bless/retire atomicity (disposable PG)", () => {
  const dbName = `atomic_admin_mutation_bless_${process.pid}_${Date.now()}`;
  let pool: Pool;
  // The exact production factory shape (main.ts destinationServiceForSql): per-client
  // store AND per-client blessing authorizer, so authorize()'s artifact+audit and
  // store.bless() share one connection.
  const destinationServiceForSql = (sql: DestinationSqlExecutor): DestinationService =>
    createDestinationService({
      store: createSqlDestinationStore(sql),
      keyGenerator: {
        async generate(): Promise<{ walletId: Uuid; publicKey: WalletPublicKey }> {
          throw new Error("keyGenerator unused on bless/retire path");
        },
      },
      blessingAuthorizer: createDeviceBlessingAuthorizer({
        lookupDevice: createSqlActiveDeviceLookup(sql),
        persistArtifact: createSqlBlessingArtifactPersister(sql),
        appendAudit: createSqlBlessingAuditAppender(sql),
      }),
      clock: { now: () => new Date().toISOString() },
      ids: { destinationId: () => randomUUID() as Uuid },
    });
  let execute: ReturnType<typeof createAtomicAdminMutationExecutor<DestinationTxPorts>>;

  beforeAll(async () => {
    await createDatabase(dbName);
    pool = new Pool(adminConfig(dbName));
    await pool.query("CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$')");
    await pool.query("CREATE TABLE nodes (id uuid PRIMARY KEY)");
    await pool.query(`CREATE TABLE wallets (
      id uuid PRIMARY KEY, public_key text NOT NULL, key_origin text NOT NULL,
      state text NOT NULL, recovery_verified_at timestamptz)`);
    await pool.query(`CREATE TABLE destinations (
      id uuid PRIMARY KEY, node_id uuid NOT NULL, wallet_id uuid NOT NULL, state text NOT NULL,
      blessed_at timestamptz, blessed_by_device_key_id uuid, blessing_artifact_id uuid,
      retired_at timestamptz, created_at timestamptz NOT NULL)`);
    await pool.query(`CREATE TABLE operator_device_keys (
      id uuid PRIMARY KEY, node_id uuid NOT NULL, public_key text NOT NULL, label text NOT NULL,
      enrolled_at timestamptz NOT NULL, revoked_at timestamptz)`);
    // nonce UNIQUE is the single-use marker the blessing authorizer relies on (23505 ->
    // nonce_conflict). Without atomicity a rolled-back-but-committed nonce sticks forever.
    await pool.query(`CREATE TABLE destination_blessing_artifacts (
      id uuid PRIMARY KEY, purpose text NOT NULL, canonical_version int NOT NULL,
      node_id uuid NOT NULL, destination_id uuid NOT NULL, wallet_id uuid NOT NULL,
      wallet_pubkey text NOT NULL, nonce uuid NOT NULL UNIQUE, issued_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL, device_signature text NOT NULL, preimage_text text NOT NULL,
      preimage_sha256 text NOT NULL, created_at timestamptz NOT NULL)`);
    await pool.query(`CREATE TABLE audit_log (
      id uuid PRIMARY KEY, node_id uuid NOT NULL, actor_kind text NOT NULL, actor_id text,
      action text NOT NULL, operation_id uuid, wallet_id uuid, details_text text NOT NULL,
      details_sha256 text NOT NULL, created_at timestamptz NOT NULL)`);
    // ensureSchema is a deliberate no-op (DDL owned exclusively by migrate.ts, see
    // apps/generic-node/drizzle/0002_admin_and_operations_ownership.sql). This suite uses a
    // disposable per-run database with a hand-rolled minimal prerequisite schema rather than
    // running the full migration pack — that is this codebase's established convention for
    // every non-migrator PG test (only test/db/migrate-guards.test.ts, which tests the
    // migrator itself, runs migrate()). Column list below is byte-parity with 0002's
    // admin_mutation_idempotency definition.
    await pool.query(`CREATE TABLE admin_mutation_idempotency (
      id uuid PRIMARY KEY,
      node_id uuid NOT NULL REFERENCES nodes(id),
      route_id text NOT NULL,
      idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[!-~]{16,255}$'),
      method text NOT NULL,
      raw_target text NOT NULL,
      body_sha256 sha256_hex NOT NULL,
      response_status integer NOT NULL CHECK (response_status BETWEEN 100 AND 599),
      response_bytes bytea NOT NULL,
      completed_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (node_id, route_id, idempotency_key)
    )`);
    await new SqlAdminIdempotencyStore(pool).ensureSchema();
    execute = createAtomicAdminMutationExecutor<DestinationTxPorts>({
      pool,
      idempotencyStore: new SqlAdminIdempotencyStore(pool),
      portsFor: (client: PoolClient) => ({ destinationService: destinationServiceForSql(client) }),
    });
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    await dropDatabase(dbName).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  // Insert a node + node-generated wallet + PENDING destination + enrolled device, and
  // return a fully-signed, in-window bless request for that destination.
  async function seedBlessable(): Promise<{
    nodeId: Uuid;
    destId: Uuid;
    walletId: Uuid;
    deviceId: Uuid;
    req: BlessDestinationRequest;
  }> {
    const nodeId = randomUUID() as Uuid;
    const walletId = randomUUID() as Uuid;
    const destId = randomUUID() as Uuid;
    const deviceId = randomUUID() as Uuid;
    const walletPub = pubB64(0x03) as WalletPublicKey;
    const nowIso = new Date().toISOString();
    await pool.query("INSERT INTO nodes (id) VALUES ($1::uuid)", [nodeId]);
    await pool.query(
      "INSERT INTO wallets (id, public_key, key_origin, state, recovery_verified_at) VALUES ($1::uuid,$2,'node_generated','AVAILABLE',$3::timestamptz)",
      [walletId, walletPub, nowIso],
    );
    await pool.query(
      "INSERT INTO destinations (id, node_id, wallet_id, state, created_at) VALUES ($1::uuid,$2::uuid,$3::uuid,'PENDING',$4::timestamptz)",
      [destId, nodeId, walletId, nowIso],
    );
    await pool.query(
      "INSERT INTO operator_device_keys (id, node_id, public_key, label, enrolled_at) VALUES ($1::uuid,$2::uuid,$3,'test-device',$4::timestamptz)",
      [deviceId, nodeId, DEVICE_PUB, nowIso],
    );
    const issuedAt = new Date(Date.now() - 30_000).toISOString();
    const expiresAt = new Date(Date.now() + 240_000).toISOString();
    const nonce = randomUUID() as Uuid;
    const preimage = buildDestinationBless({
      node_id: nodeId,
      destination_id: destId,
      wallet_id: walletId,
      wallet_pubkey: walletPub,
      nonce,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });
    const req: BlessDestinationRequest = {
      nodeId,
      destinationId: destId,
      nonce,
      issuedAt,
      expiresAt,
      deviceSignature: signB64(preimage.preimageText, DEVICE_SEED),
      deviceKeyId: deviceId,
    };
    return { nodeId, destId, walletId, deviceId, req };
  }

  const blessAction = (req: BlessDestinationRequest) => async (ports: DestinationTxPorts) => {
    const r = await ports.destinationService.bless(req);
    if (r.status !== "blessed") return { outcome: "abort" as const, response: r };
    return {
      outcome: "commit" as const,
      status: 200,
      responseBody: { blessed: true, destinationId: r.destination.destinationId },
    };
  };

  async function counts(nodeId: Uuid, destId: Uuid) {
    const blessed = await pool.query(
      "SELECT state, blessed_at, retired_at FROM destinations WHERE id = $1::uuid",
      [destId],
    );
    const artifacts = await pool.query(
      "SELECT count(*)::int AS n FROM destination_blessing_artifacts WHERE destination_id = $1::uuid",
      [destId],
    );
    const audits = await pool.query(
      "SELECT count(*)::int AS n FROM audit_log WHERE node_id = $1::uuid AND action = 'destination.bless'",
      [nodeId],
    );
    return {
      state: blessed.rows[0]?.state as string | undefined,
      blessedAt: blessed.rows[0]?.blessed_at ?? null,
      retiredAt: blessed.rows[0]?.retired_at ?? null,
      artifacts: artifacts.rows[0].n as number,
      audits: audits.rows[0].n as number,
    };
  }

  it("commits bless as ONE transaction: destination blessed + exactly one artifact + one audit", async () => {
    const { nodeId, destId, req } = await seedBlessable();
    const mutation = {
      nodeId,
      routeId: "admin_destination_bless",
      idempotencyKey: `atomic-admin-mutation-bless-ok-${randomUUID()}`,
      fingerprint: fingerprint(),
    };
    const res = await execute(mutation, blessAction(req));
    expect(res.outcome).toBe("committed");
    if (res.outcome !== "committed") return;
    expect(res.status).toBe(200);
    const c = await counts(nodeId, destId);
    expect(c.state).toBe("BLESSED");
    expect(c.blessedAt).not.toBeNull();
    expect(c.artifacts).toBe(1);
    expect(c.audits).toBe(1);
  }, PG_TEST_TIMEOUT_MS);

  it("rolls back bless atomically on post-action failure, then a same-nonce+key retry still blesses", async () => {
    const { nodeId, destId, req } = await seedBlessable();
    const mutation = {
      nodeId,
      routeId: "admin_destination_bless",
      idempotencyKey: `atomic-admin-mutation-bless-rollback-${randomUUID()}`,
      fingerprint: fingerprint("b".repeat(64)),
    };
    // Force recordCompleted (which runs AFTER the bless writes on the same tx client) to
    // throw, so the whole transaction rolls back — including the artifact+audit that a
    // pool-bound authorizer would have already auto-committed on a separate connection.
    const executeThrowing = createAtomicAdminMutationExecutor<DestinationTxPorts>({
      pool,
      idempotencyStore: new ThrowOncePostWrite(new SqlAdminIdempotencyStore(pool)),
      portsFor: (client: PoolClient) => ({ destinationService: destinationServiceForSql(client) }),
    });
    await expect(executeThrowing(mutation, blessAction(req))).rejects.toThrow(/injected post-write/);
    const afterRollback = await counts(nodeId, destId);
    expect(afterRollback.state).toBe("PENDING");
    expect(afterRollback.blessedAt).toBeNull();
    expect(afterRollback.artifacts).toBe(0); // nonce marker rolled back -> nonce is free again
    expect(afterRollback.audits).toBe(0);

    // Same nonce, same device signature, same idempotency key: must NOT be stuck on
    // nonce_reused or a lingering idempotency row — the retry (recordCompleted now disarmed,
    // delegating to the real store) blesses cleanly.
    const retry = await executeThrowing(mutation, blessAction(req));
    expect(retry.outcome).toBe("committed");
    const afterRetry = await counts(nodeId, destId);
    expect(afterRetry.state).toBe("BLESSED");
    expect(afterRetry.artifacts).toBe(1);
    expect(afterRetry.audits).toBe(1);
  }, PG_TEST_TIMEOUT_MS);

  it("replays a completed bless byte-identically and writes NO second artifact", async () => {
    const { nodeId, destId, req } = await seedBlessable();
    const mutation = {
      nodeId,
      routeId: "admin_destination_bless",
      idempotencyKey: `atomic-admin-mutation-bless-replay-${randomUUID()}`,
      fingerprint: fingerprint("c".repeat(64)),
    };
    const first = await execute(mutation, blessAction(req));
    expect(first.outcome).toBe("committed");
    if (first.outcome !== "committed") return;
    const replay = await execute(mutation, async () => {
      throw new Error("replay must not re-run the bless action");
    });
    expect(replay.outcome).toBe("replay");
    if (replay.outcome !== "replay") return;
    expect(replay.responseBytes).toEqual(first.responseBytes);
    const c = await counts(nodeId, destId);
    expect(c.artifacts).toBe(1); // no second artifact from the replay
    expect(c.audits).toBe(1);
  }, PG_TEST_TIMEOUT_MS);

  it("retire rolls back atomically on post-action failure, then a retry retires (retire writes no audit — pre-existing gap)", async () => {
    // Seed straight to BLESSED (retire only requires state BLESSED).
    const nodeId = randomUUID() as Uuid;
    const walletId = randomUUID() as Uuid;
    const destId = randomUUID() as Uuid;
    const walletPub = pubB64(0x03) as WalletPublicKey;
    const nowIso = new Date().toISOString();
    await pool.query("INSERT INTO nodes (id) VALUES ($1::uuid)", [nodeId]);
    await pool.query(
      "INSERT INTO wallets (id, public_key, key_origin, state, recovery_verified_at) VALUES ($1::uuid,$2,'node_generated','AVAILABLE',$3::timestamptz)",
      [walletId, walletPub, nowIso],
    );
    await pool.query(
      "INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, created_at) VALUES ($1::uuid,$2::uuid,$3::uuid,'BLESSED',$4::timestamptz,$4::timestamptz)",
      [destId, nodeId, walletId, nowIso],
    );
    const req: RetireDestinationRequest = { nodeId, destinationId: destId };
    const retireAction = async (ports: DestinationTxPorts) => {
      const r = await ports.destinationService.retire(req);
      if (r.status !== "retired") return { outcome: "abort" as const, response: r };
      return { outcome: "commit" as const, status: 200, responseBody: { retired: true } };
    };
    const mutation = {
      nodeId,
      routeId: "admin_destination_retire",
      idempotencyKey: `atomic-admin-mutation-retire-${randomUUID()}`,
      fingerprint: fingerprint("d".repeat(64)),
    };
    // Post-write rollback via the same injection: retire's store.retire runs on the tx client,
    // then recordCompleted throws, rolling the whole transaction back.
    const executeThrowing = createAtomicAdminMutationExecutor<DestinationTxPorts>({
      pool,
      idempotencyStore: new ThrowOncePostWrite(new SqlAdminIdempotencyStore(pool)),
      portsFor: (client: PoolClient) => ({ destinationService: destinationServiceForSql(client) }),
    });
    await expect(executeThrowing(mutation, retireAction)).rejects.toThrow(/injected post-write/);
    const rolled = await pool.query(
      "SELECT state, retired_at FROM destinations WHERE id = $1::uuid",
      [destId],
    );
    expect(rolled.rows[0].state).toBe("BLESSED");
    expect(rolled.rows[0].retired_at).toBeNull();

    const retry = await executeThrowing(mutation, retireAction);
    expect(retry.outcome).toBe("committed");
    const done = await pool.query(
      "SELECT state, retired_at FROM destinations WHERE id = $1::uuid",
      [destId],
    );
    expect(done.rows[0].state).toBe("RETIRED");
    expect(done.rows[0].retired_at).not.toBeNull();
  }, PG_TEST_TIMEOUT_MS);
});
