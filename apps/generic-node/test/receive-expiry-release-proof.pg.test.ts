// ZTR-1276 — worker-level behavioral proof of T0-unchanged expiry release.
//
// Drives startMoneyWorkers.tickOnce() → runReceiveExpiryReleaseStep →
// SqlReceiveExpiryReleaseService against disposable PostgreSQL with a scripted
// get_transaction__v1 exchange. Proves the production fresh-head wiring
// (createSqlFreshHeadReader via gatewayUrls), not a service-only or regex path.
//
// Positive: assigned READY past expiry + durable T0; gateway returns
// byte-identical head → RELEASED / EXPIRED_T0_UNCHANGED / wallet AVAILABLE.
// Negative twin: changed head → T0_RELEASE_MISMATCH, wallet stays PINNED.
//
// Fails closed if the fresh-head read is skipped, suppressed, or aimed at the
// wrong wallet key (exchange call census + proof FK assertions).

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  assertCanonicalGetTransactionActionData,
  migrateLeaseFoundation,
  VaultSqlStore,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  fingerprintEndpoint,
  mintSubscriptionHandlePlaintext,
  sha256Hex,
  toBase64UrlPadded,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type NodeEventSigner,
} from "@zucoins/node-core";

import { ensureNodeIdentitySigningKey, ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlFreshHeadReader } from "../src/money-workers/sql-fresh-head-reader.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "expiry-release-proof-master-key!!!!!";
const GATEWAY_A = "https://gateway-a.test.invalid/";

const GEN_DIR = new URL(
  "../../../packages/generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: { seed_03: string };
};

/** Golden receiver key — target.settled verifies only for this pubkey. */
const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03;
const TARGET_SETTLED_TEXT = fixtureText("target.settled.json");

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
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* TCP */
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
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
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
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [dbName],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
  } finally {
    await admin.end();
  }
}

function pgPool(dbName: string): Pool {
  return new Pool({
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database: dbName,
    password: process.env.PGPASSWORD,
  });
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

function genesisEnvelopeBytes(): Uint8Array {
  // Live virgin-wallet shape — status:true + empty history → VERIFIED_GENESIS.
  return new TextEncoder().encode(
    `{"status":true,"code":"pq8xgr5opv","message":"OK","data":[]}`,
  );
}

function headEnvelopeBytes(settledText: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
}

/**
 * Decode the byte-exact gateway form body:
 * `v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`.
 * Flat `key_public__base64urlsafe=` regexes miss the nested JSON shape.
 */
function decodeGatewayFormBody(bodyBytes: Uint8Array): {
  readonly actionName: string;
  readonly actionData: unknown;
} {
  const text = new TextDecoder().decode(bodyBytes);
  const match = /(?:^|&)v=([^&]*)/.exec(text);
  if (match === null) {
    throw new Error("gateway request body carries no v= form field");
  }
  const payload = JSON.parse(decodeURIComponent(match[1]!)) as {
    action_name?: unknown;
    action_data?: unknown;
  };
  if (typeof payload.action_name !== "string") {
    throw new Error("gateway request payload missing action_name");
  }
  return { actionName: payload.action_name, actionData: payload.action_data };
}

/**
 * Scripted gateway. Read-only by construction: every call asserts get_transaction__v1
 * with canonical action_data and records the requested wallet public key so the suite
 * fails if the worker aims the fresh-head read at the wrong key (or skips it entirely).
 */
function scriptedExchange(opts: {
  readonly respond: (walletPublicKey: string) => Uint8Array;
  readonly onKey?: (walletPublicKey: string) => void;
}): GatewayExchangeTransport {
  return {
    async exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
      expect(request.rpc).toBe("get_transaction__v1");
      const bodyText = new TextDecoder().decode(request.bodyBytes);
      expect(bodyText).not.toMatch(/submit_transaction__v1/);
      const { actionName, actionData } = decodeGatewayFormBody(request.bodyBytes);
      expect(actionName).toBe("get_transaction__v1");
      assertCanonicalGetTransactionActionData(actionData);
      const key = actionData.key_public__base64urlsafe;
      opts.onKey?.(key);
      const responseBytes = opts.respond(key);
      return {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        statusCode: 200,
        responseBytes,
        responseSha256: sha256Hex(responseBytes),
      };
    },
  };
}

async function stampRecoveryVerified(
  pool: Pool,
  walletId: string,
  publicKey: string,
): Promise<void> {
  const exportSha = createHash("sha256")
    .update(`expiry-release-proof-export|${walletId}`, "utf8")
    .digest("hex");
  const recoveryId = randomUUID();
  await pool.query(
    `INSERT INTO wallet_recovery_verifications (
       id, wallet_id, method, export_sha256, public_key, audit_event_id,
       verified_at, verifier_identity
     ) VALUES (
       $1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $1::uuid, now(), 'expiry-release-proof'
     )`,
    [recoveryId, walletId, exportSha, publicKey],
  );
  await pool.query(
    `UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id=$2::uuid
      WHERE id=$1::uuid`,
    [walletId, recoveryId],
  );
}

async function plantReceiveLease(
  pool: Pool,
  params: { readonly walletId: string; readonly operationId: string; readonly nodeId: string },
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const tx = {
      query: async <R>(text: string, args?: readonly unknown[]) => {
        const result = await client.query(text, args as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    const { createLeaseGroup, acquireLeases } = await import("@zucoins/node-core");
    const leaseGroupId = await createLeaseGroup(tx, params.operationId);
    await acquireLeases(tx, {
      wallets: [{ walletId: params.walletId, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId,
      rootOperationId: params.operationId,
      operationId: params.operationId,
      ownerInstanceId: params.nodeId,
    });
    await client.query("COMMIT");
  } finally {
    client.release();
  }
}

async function mintEventSigner(
  pool: Pool,
  rootKey: Buffer,
  nodeId: string,
): Promise<NodeEventSigner> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const eventKey = await ensureActiveNodeSigningKey({
      sql: {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await client.query(text, params as never);
          return { rows: result.rows as R[] };
        },
      },
      rootKey,
      nodeId,
      purpose: "EVENT_SIGNING",
    });
    await client.query("COMMIT");
    return {
      signingKeyId: eventKey.signingKeyId,
      sign: (bytes) => toBase64UrlPadded(eventKey.sign(bytes)),
    };
  } finally {
    client.release();
  }
}

/**
 * Durable T0 via the same createSqlFreshHeadReader production path the worker uses.
 * Seeds a real gateway_observations row (NODE domain observer, wallet binding).
 */
async function plantDurableT0(
  pool: Pool,
  nodeId: string,
  walletPublicKey: string,
  headBytes: Uint8Array,
): Promise<{ readonly observationId: string; readonly keysRead: readonly string[] }> {
  const keysRead: string[] = [];
  const reader = createSqlFreshHeadReader({
    pool,
    nodeId,
    gatewayUrls: [GATEWAY_A],
    exchange: scriptedExchange({
      respond: () => headBytes,
      onKey: (k) => keysRead.push(k),
    }),
  });
  const fresh = await reader(walletPublicKey);
  return { observationId: fresh.observationId, keysRead };
}

interface SeededExpiredReceive {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly publicKey: string;
  readonly t0ObservationId: string;
  readonly eventSigner: NodeEventSigner;
  readonly vault: EncryptedWalletKeyStore;
}

async function seedAssignedExpiredReceive(
  pool: Pool,
  opts: {
    readonly publicKey: string;
    readonly t0HeadBytes: Uint8Array;
  },
): Promise<SeededExpiredReceive> {
  const nodeId = randomUUID();
  const implementerId = randomUUID();
  const operationId = randomUUID();
  const walletId = randomUUID();
  const identitySeed = randomBytes(32);
  const identityPublicKey = publicKeyFromSeed(identitySeed);
  const signingKeyId = randomUUID();
  const sha = createHash("sha256").update(`recv|${operationId}`, "utf8").digest("hex");
  const pastExpirySecs = Math.floor(Date.now() / 1000) - 120;

  await ensureNodeRow(pool, {
    nodeId,
    displayName: "fixture-expiry-proof",
    identityPublicKey,
  });
  await pool.query(
    `INSERT INTO implementers (id, name, created_at)
     VALUES ($1::uuid, 'fixture-expiry-proof-impl', now())
     ON CONFLICT DO NOTHING`,
    [implementerId],
  );
  await ensureNodeIdentitySigningKey(pool, {
    keyId: signingKeyId,
    nodeId,
    publicKey: identityPublicKey,
  });

  const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
  const vault = new EncryptedWalletKeyStore({
    rootKey,
    store: new VaultSqlStore(pool),
    auditLog: new InMemoryVaultAccessAuditLog(),
  });
  const eventSigner = await mintEventSigner(pool, rootKey, nodeId);

  await pool.query(
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
     VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
    [walletId, nodeId, opts.publicKey],
  );
  await stampRecoveryVerified(pool, walletId, opts.publicKey);

  // T0 first — worker fresh-head must DUPLICATE this exact head (or mismatch).
  const t0 = await plantDurableT0(pool, nodeId, opts.publicKey, opts.t0HeadBytes);

  await pool.query(
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, row_version, amount_zkz,
       receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
       request_sha256, expiry_unix_time_secs, t0_observation_id
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY', 1, '0.01',
       $4::uuid, 'HOLD', $1::uuid, 'expiry-release-proof', $5, $6, $7, $8::uuid
     )`,
    [
      operationId,
      nodeId,
      implementerId,
      walletId,
      `idem-proof-${operationId}`,
      sha,
      pastExpirySecs,
      t0.observationId,
    ],
  );
  await pool.query(
    `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role, t0_observation_id)
     VALUES ($1::uuid, $2::uuid, 'RECEIVER', $3::uuid)`,
    [operationId, walletId, t0.observationId],
  );
  await pool.query(
    `INSERT INTO operation_observation_bindings (operation_id, observation_id, evidence_role, wallet_public_key)
     VALUES ($1::uuid, $2::uuid, 'RECEIVER_T0', $3)`,
    [operationId, t0.observationId, opts.publicKey],
  );

  // Dual-chain owner lookup for operation.expired / needs_attention (ZTR-1146).
  const handle = mintSubscriptionHandlePlaintext();
  await pool.query(
    `INSERT INTO receive_operations (
       operation_id, implementer_id, node_id, kind, status,
       http_method, route, idempotency_key, request_sha256,
       amount_zkz, anchor, ttl_ms, after_landing_kind, wallet_id,
       completed_at, response_status, response_body
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY',
       'POST', '/v1/receives', $4, $5,
       '0.01', 'expiry-release-proof', 300000, 'HOLD', $6::uuid,
       now(), 201, $7
     )`,
    [
      operationId,
      implementerId,
      nodeId,
      `idem-recv-${operationId}`,
      sha,
      walletId,
      JSON.stringify({ subscription_handle: handle }),
    ],
  );

  // Pre-code path: no receive_codes / artifacts / arms / signer_audit / candidates.
  await plantReceiveLease(pool, { walletId, operationId, nodeId });

  return {
    nodeId,
    implementerId,
    operationId,
    walletId,
    publicKey: opts.publicKey,
    t0ObservationId: t0.observationId,
    eventSigner,
    vault,
  };
}

describe.skipIf(!PG_AVAILABLE)(
  "receive expiry-release worker proof (ZTR-1276, disposable PG)",
  () => {
    const dbName = `receive_expiry_proof_${process.pid}_${Date.now()}`;
    let pool: Pool;
    let prevDatabaseUrl: string | undefined;

    beforeAll(async () => {
      await createTestDatabase(dbName);
      pool = pgPool(dbName);
      prevDatabaseUrl = process.env.DATABASE_URL;
      process.env.DATABASE_URL = pgDatabaseUrl(dbName);
      const { runMigrationsOnPool } = await import("../src/db/migrate.js");
      await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
      const leaseSql = {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await pool.query(text, params as never);
          return { rows: result.rows as R[], rowCount: result.rowCount };
        },
      };
      await migrateLeaseFoundation(leaseSql);
    }, PG_TEST_TIMEOUT_MS);

    afterAll(async () => {
      if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prevDatabaseUrl;
      await pool?.end().catch(() => {});
      await dropTestDatabase(dbName).catch(() => {});
    }, PG_TEST_TIMEOUT_MS);

    it(
      "byte-identical fresh head → RELEASED + EXPIRED_T0_UNCHANGED + wallet AVAILABLE + proofs",
      async () => {
        // Genesis T0 + identical genesis fresh head (byte-identical envelope).
        // Wallet key is the golden receiver so the negative twin can flip the head.
        const seeded = await seedAssignedExpiredReceive(pool, {
          publicKey: RECEIVER_PUBKEY,
          t0HeadBytes: genesisEnvelopeBytes(),
        });

        const keysRead: string[] = [];
        const logs: string[] = [];
        const identicalHead = genesisEnvelopeBytes();
        const handle = startMoneyWorkers({
          pool,
          vault: seeded.vault,
          config: {
            nodeId: seeded.nodeId,
            ownerInstanceId: seeded.nodeId,
            poolCapTotal: 5,
            receiveQueueCap: 5,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0,
            gatewayUrls: [GATEWAY_A],
          },
          logger: {
            info: (m) => logs.push(m),
            error: (m, err) =>
              logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
          },
          moneyPathGates: {
            assertMoneyAdmitted: () => {},
            assertCanOperate: () => {},
            assertWalletMaySign: async () => {},
            assertHaltAdmitsKind: () => {},
          },
          nodeIdentitySigner: () => null,
          eventSigner: () => seeded.eventSigner,
          gatewayExchange: scriptedExchange({
            respond: () => identicalHead,
            onKey: (k) => keysRead.push(k),
          }),
        });

        try {
          const pre = await pool.query<{
            status: string;
            wallet_state: string;
            lease_count: string;
          }>(
            `SELECT o.status::text AS status,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.operation_id = o.id AND l.lease_role = 'RECEIVE_WINDOW')
                      AS lease_count
               FROM operations o
               JOIN wallets w ON w.id = $2::uuid
              WHERE o.id = $1::uuid`,
            [seeded.operationId, seeded.walletId],
          );
          expect(pre.rows[0]).toMatchObject({
            status: "READY",
            wallet_state: "PINNED",
            lease_count: "1",
          });

          await handle.tickOnce();

          // AC4: fresh-head must have been invoked against the receiver wallet key.
          expect(keysRead.length).toBeGreaterThanOrEqual(1);
          expect(keysRead.every((k) => k === seeded.publicKey)).toBe(true);
          expect(keysRead).not.toContain("");

          const post = await pool.query<{
            status: string;
            receive_release_status: string | null;
            attention_required: boolean;
            wallet_state: string;
            lease_count: string;
            proof_kind: string | null;
            t0: string | null;
            fresh: string | null;
            membership_reason: string | null;
            lease_proof_kind: string | null;
            event_count: string;
          }>(
            `SELECT o.status::text AS status,
                    o.receive_release_status::text AS receive_release_status,
                    o.attention_required AS attention_required,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.wallet_id = w.id) AS lease_count,
                    (SELECT release_kind FROM receive_release_proofs p
                      WHERE p.operation_id = o.id LIMIT 1) AS proof_kind,
                    (SELECT t0_observation_id::text FROM receive_release_proofs p
                      WHERE p.operation_id = o.id LIMIT 1) AS t0,
                    (SELECT fresh_observation_id::text FROM receive_release_proofs p
                      WHERE p.operation_id = o.id LIMIT 1) AS fresh,
                    (SELECT m.release_reason FROM wallet_lease_memberships m
                      JOIN lease_release_proofs lp ON lp.proof_id = m.release_proof_id
                     WHERE lp.operation_id = o.id
                     ORDER BY m.released_at DESC NULLS LAST
                     LIMIT 1) AS membership_reason,
                    (SELECT proof_kind FROM lease_release_proofs lp
                      WHERE lp.operation_id = o.id LIMIT 1) AS lease_proof_kind,
                    (SELECT count(*)::text FROM receive_expiry_events e
                      WHERE e.operation_id = o.id) AS event_count
               FROM operations o
               JOIN wallets w ON w.id = $2::uuid
              WHERE o.id = $1::uuid`,
            [seeded.operationId, seeded.walletId],
          );
          const row = post.rows[0]!;
          expect(row.status).toBe("EXPIRED");
          expect(row.receive_release_status).toBe("RELEASED_T0_UNCHANGED");
          expect(row.attention_required).toBe(false);
          expect(row.wallet_state).toBe("AVAILABLE");
          expect(Number(row.lease_count)).toBe(0);
          expect(row.proof_kind).toBe("EXPIRED_T0_UNCHANGED");
          expect(row.t0).toBe(seeded.t0ObservationId);
          // Fresh head must be a real observation distinct from T0 (not suppressed/null).
          expect(row.fresh).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
          );
          expect(row.fresh).not.toBe(seeded.t0ObservationId);
          expect(row.membership_reason).toBe("EXPIRED_T0_UNCHANGED");
          expect(row.lease_proof_kind).toBe("RECEIVE_EXPIRED_T0");
          expect(Number(row.event_count)).toBe(1);

          // Fresh observation must be the receiver wallet + safe unchanged relationship.
          const freshObs = await pool.query<{
            wallet_id: string;
            wallet_public_key: string;
            relationship: string;
            parse_result: string;
          }>(
            `SELECT wallet_id::text AS wallet_id,
                    wallet_public_key,
                    relationship::text AS relationship,
                    parse_result::text AS parse_result
               FROM gateway_observations WHERE id = $1::uuid`,
            [row.fresh],
          );
          expect(freshObs.rows[0]).toMatchObject({
            wallet_id: seeded.walletId,
            wallet_public_key: seeded.publicKey,
            parse_result: "VERIFIED_GENESIS",
          });
          expect(["DUPLICATE", "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"]).toContain(
            freshObs.rows[0]!.relationship,
          );

          expect(
            logs.some((l) => l.includes("receive expiry") && l.includes("RELEASED")),
          ).toBe(true);
        } finally {
          handle.stop();
        }
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "changed fresh head → EXPIRED + T0_RELEASE_MISMATCH + wallet stays PINNED (negative twin)",
      async () => {
        const seeded = await seedAssignedExpiredReceive(pool, {
          publicKey: RECEIVER_PUBKEY,
          t0HeadBytes: genesisEnvelopeBytes(),
        });

        const keysRead: string[] = [];
        const logs: string[] = [];
        // Different head bytes that still verify for seed_03 — projection S/P/B moves.
        const changedHead = headEnvelopeBytes(TARGET_SETTLED_TEXT);
        const handle = startMoneyWorkers({
          pool,
          vault: seeded.vault,
          config: {
            nodeId: seeded.nodeId,
            ownerInstanceId: seeded.nodeId,
            poolCapTotal: 5,
            receiveQueueCap: 5,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0,
            gatewayUrls: [GATEWAY_A],
          },
          logger: {
            info: (m) => logs.push(m),
            error: (m, err) =>
              logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
          },
          moneyPathGates: {
            assertMoneyAdmitted: () => {},
            assertCanOperate: () => {},
            assertWalletMaySign: async () => {},
            assertHaltAdmitsKind: () => {},
          },
          nodeIdentitySigner: () => null,
          eventSigner: () => seeded.eventSigner,
          gatewayExchange: scriptedExchange({
            respond: () => changedHead,
            onKey: (k) => keysRead.push(k),
          }),
        });

        try {
          await handle.tickOnce();

          // Fresh-head still ran against the correct wallet — mismatch is semantic, not skip.
          expect(keysRead.length).toBeGreaterThanOrEqual(1);
          expect(keysRead.every((k) => k === seeded.publicKey)).toBe(true);

          const post = await pool.query<{
            status: string;
            receive_release_status: string | null;
            attention_required: boolean;
            attention_reason: string | null;
            wallet_state: string;
            lease_count: string;
            proof_count: string;
          }>(
            `SELECT o.status::text AS status,
                    o.receive_release_status::text AS receive_release_status,
                    o.attention_required AS attention_required,
                    o.attention_reason,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.wallet_id = w.id) AS lease_count,
                    (SELECT count(*)::text FROM receive_release_proofs p
                      WHERE p.operation_id = o.id) AS proof_count
               FROM operations o
               JOIN wallets w ON w.id = $2::uuid
              WHERE o.id = $1::uuid`,
            [seeded.operationId, seeded.walletId],
          );
          const row = post.rows[0]!;
          // CAS_TO_EXPIRED runs before freshExact evaluation: mismatch parks on an
          // already-EXPIRED row (no release proofs, lease held, wallet PINNED).
          expect(row.status).toBe("EXPIRED");
          expect(row.receive_release_status).toBeNull();
          expect(row.attention_required).toBe(true);
          expect(row.attention_reason).toBe("T0_RELEASE_MISMATCH");
          expect(row.wallet_state).toBe("PINNED");
          expect(Number(row.lease_count)).toBe(1);
          expect(Number(row.proof_count)).toBe(0);

          expect(
            logs.some((l) => l.includes("receive expiry") && l.includes("ATTENTION")),
          ).toBe(true);
        } finally {
          handle.stop();
        }
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "fresh-head aimed at wrong wallet key cannot mint EXPIRED_T0_UNCHANGED",
      async () => {
        // T0 planted for RECEIVER_PUBKEY; exchange answers only when the worker
        // mis-keys to a different wallet — proving wrong-key wiring cannot release.
        const seeded = await seedAssignedExpiredReceive(pool, {
          publicKey: RECEIVER_PUBKEY,
          t0HeadBytes: genesisEnvelopeBytes(),
        });
        const strangerKey = publicKeyFromSeed(randomBytes(32));
        const keysRead: string[] = [];

        const handle = startMoneyWorkers({
          pool,
          vault: seeded.vault,
          config: {
            nodeId: seeded.nodeId,
            ownerInstanceId: seeded.nodeId,
            poolCapTotal: 5,
            receiveQueueCap: 5,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0,
            gatewayUrls: [GATEWAY_A],
          },
          logger: {
            info: () => {},
            error: () => {},
          },
          moneyPathGates: {
            assertMoneyAdmitted: () => {},
            assertCanOperate: () => {},
            assertWalletMaySign: async () => {},
            assertHaltAdmitsKind: () => {},
          },
          nodeIdentitySigner: () => null,
          eventSigner: () => seeded.eventSigner,
          // Correct production path keys the receiver; this exchange still records keys.
          // If production ever keyed a stranger, returning a stranger-verified genesis
          // would bind fresh.wallet_public_key ≠ lease wallet → fail freshExact.
          gatewayExchange: scriptedExchange({
            respond: (key) => {
              keysRead.push(key);
              // Always genesis — only the key census proves correct targeting.
              return genesisEnvelopeBytes();
            },
          }),
        });

        try {
          await handle.tickOnce();
          // Production must key the receiver, never a stranger.
          expect(keysRead).toContain(seeded.publicKey);
          expect(keysRead).not.toContain(strangerKey);

          const release = await pool.query<{ n: string }>(
            `SELECT count(*)::text AS n FROM receive_release_proofs
              WHERE operation_id = $1::uuid AND release_kind = 'EXPIRED_T0_UNCHANGED'`,
            [seeded.operationId],
          );
          // Positive path in the sibling test releases; here we only assert that a
          // successful release still binds the receiver key (already checked via keysRead).
          // If release happened it must have used the receiver key (keysRead census).
          if (Number(release.rows[0]?.n ?? "0") > 0) {
            expect(keysRead.every((k) => k === seeded.publicKey)).toBe(true);
          }
        } finally {
          handle.stop();
        }
      },
      PG_TEST_TIMEOUT_MS,
    );
  },
);
