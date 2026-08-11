// worker-level regression: mint → arm → advance past expiry → tick →
// assert EXPIRED + wallet AVAILABLE + proof row present.
//
// This drives startMoneyWorkers.tickOnce() against a disposable PostgreSQL,
// proving the expiry-release service is actually called by the money workers
// (not just that the service itself works — that is covered by the node-core
// receive-expiry-release.pg.test.ts suite).
//
// One-in-flight: never raw DELETE from wallet_active_leases.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  migrateLeaseFoundation,
  VaultSqlStore,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  toBase64UrlPadded,
  type NodeEventSigner,
  mintSubscriptionHandlePlaintext,
  hashSubscriptionHandle,
} from "@zucoins/node-core";

import { ensureNodeIdentitySigningKey, ensureNodeRow } from "../src/bootstrap/genesis.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";
import { publicKeyFromSeed, signPaddedBase64Url } from "../src/ops/ed25519-ops.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "expiry-wiring-master-key!!!!!!!!!!!";

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

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitFor(
  pred: () => Promise<boolean>,
  opts: { readonly timeoutMs: number; readonly intervalMs: number; readonly label: string },
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < opts.timeoutMs) {
    if (await pred()) return;
    await sleep(opts.intervalMs);
  }
  throw new Error(`timeout waiting for ${opts.label}`);
}

/** Stamp a wallet recovery-verified so custody eligibility admits a lease. */
async function stampRecoveryVerified(
  pool: Pool,
  walletId: string,
  publicKey: string,
): Promise<void> {
  const exportSha = createHash("sha256")
    .update(`receive-expiry-wiring-export|${walletId}`, "utf8")
    .digest("hex");
  const recoveryId = randomUUID();
  await pool.query(
    `INSERT INTO wallet_recovery_verifications (
       id, wallet_id, method, export_sha256, public_key, audit_event_id,
       verified_at, verifier_identity
     ) VALUES (
       $1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $1::uuid, now(), 'receive-expiry-wiring'
     )`,
    [recoveryId, walletId, exportSha, publicKey],
  );
  await pool.query(
    `UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id=$2::uuid
      WHERE id=$1::uuid`,
    [walletId, recoveryId],
  );
}

/** Plant a RECEIVE_WINDOW lease binding walletId to operationId. */
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

describe.skipIf(!PG_AVAILABLE)(
  "receive expiry-release worker wiring (disposable PG)",
  () => {
    const dbName = `receive_expiry_wiring_${process.pid}_${Date.now()}`;
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
      "past expiry → tick → formed READY holds for attention; unformed leased receive releases to AVAILABLE + proof row",
      async () => {
        const nodeId = randomUUID();
        const implementerId = randomUUID();
        const identitySeed = randomBytes(32);
        const identityPublicKey = publicKeyFromSeed(identitySeed);
        const signingKeyId = randomUUID();

        await ensureNodeRow(pool, {
          nodeId,
          displayName: "fixture-expiry",
          identityPublicKey,
        });
        await pool.query(
          `INSERT INTO implementers (id, name, created_at)
           VALUES ($1::uuid, 'fixture-impl', now())
           ON CONFLICT DO NOTHING`,
          [implementerId],
        );
        await ensureNodeIdentitySigningKey(pool, {
          keyId: signingKeyId,
          nodeId,
          publicKey: identityPublicKey,
        });
        const durableKey = await pool.query<{ id: string }>(
          `SELECT id::text AS id FROM node_signing_keys
            WHERE node_id = $1::uuid AND purpose = 'NODE_IDENTITY' AND public_key = $2
            LIMIT 1`,
          [nodeId, identityPublicKey],
        );
        const liveSigningKeyId = durableKey.rows[0]?.id ?? signingKeyId;

        const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
        const vault = new EncryptedWalletKeyStore({
          rootKey,
          store: new VaultSqlStore(pool),
          auditLog: new InMemoryVaultAccessAuditLog(),
        });

        // Sealed EVENT_SIGNING signer.
        const eventKeyClient = await pool.connect();
        let eventSigner: NodeEventSigner;
        try {
          await eventKeyClient.query("BEGIN");
          const eventKey = await ensureActiveNodeSigningKey({
            sql: {
              query: async <R>(text: string, params?: readonly unknown[]) => {
                const result = await eventKeyClient.query(text, params as never);
                return { rows: result.rows as R[] };
              },
            },
            rootKey,
            nodeId,
            purpose: "EVENT_SIGNING",
          });
          await eventKeyClient.query("COMMIT");
          eventSigner = {
            signingKeyId: eventKey.signingKeyId,
            // padded_base64url_signature domain requires the 88-char padded form;
            // Buffer's "base64url" encoding is unpadded and violates it.
            sign: (bytes) => toBase64UrlPadded(eventKey.sign(bytes)),
          };
        } finally {
          eventKeyClient.release();
        }

        const moneyPathGates = {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
          assertHaltAdmitsKind: () => {},
        };

        const logs: string[] = [];
        // Switched off in Step 7 so formation skips cleanly (no signer use) and
        // the expiry step can prove the proven-not-started release on its own.
        let identitySignerAvailable = true;
        const handle = startMoneyWorkers({
          pool,
          vault,
          config: {
            nodeId,
            ownerInstanceId: nodeId,
            poolCapTotal: 10,
            receiveQueueCap: 20,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0, // manual ticks only
            allowGenesisT0Stub: true,
            // Expiry sweep produces no events — no EVENT_SIGNING signer here. // contract-allow:sweep:frozen structural vocabulary
            allowMissingEventSigner: true,
          },
          logger: {
            info: (m) => logs.push(m),
            error: (m, err) =>
              logs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
          },
          moneyPathGates,
          nodeIdentitySigner: () =>
            identitySignerAvailable
              ? {
                  signingKeyId: liveSigningKeyId,
                  sign(preimageBytes: Uint8Array): string {
                    return signPaddedBase64Url(identitySeed, preimageBytes);
                  },
                }
              : null,
          eventSigner: () => eventSigner,
        });

        try {
          // Step 1: tick to mint pool wallets.
          await handle.tickOnce();
          await waitFor(
            async () => {
              const r = await pool.query<{ n: string }>(
                `SELECT count(*)::text AS n FROM wallets WHERE node_id = $1::uuid`,
                [nodeId],
              );
              return Number(r.rows[0]?.n ?? "0") >= 5;
            },
            { timeoutMs: 10_000, intervalMs: 100, label: "pool mint >= 5 wallets" },
          );

          // Step 2: stamp recovery verification so wallets become eligible for lease.
          const wallets = await pool.query<{ id: string; public_key: string }>(
            `SELECT id::text AS id, public_key FROM wallets
              WHERE node_id = $1::uuid AND recovery_verified_at IS NULL
              LIMIT 5`,
            [nodeId],
          );
          for (const w of wallets.rows) {
            await stampRecoveryVerified(pool, w.id, w.public_key);
          }

          // Step 3: create a receive operation and let the worker form it to READY.
          const operationId = randomUUID();
          const reqSha = createHash("sha256")
            .update(`recv|${operationId}`, "utf8")
            .digest("hex");
          // Create-time body must already carry sh_… — READY worker fail-closes without it (ZTR-1142).
          const createHandle = mintSubscriptionHandlePlaintext();
          await pool.query(
            `INSERT INTO receive_operations (
               operation_id, implementer_id, node_id, kind, status,
               http_method, route, idempotency_key, request_sha256,
               amount_zkz, anchor, ttl_ms, after_landing_kind,
               completed_at, response_status, response_body
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED',
               'POST', '/v1/receives', $4, $5,
               '0.01', 'receive-expiry-wiring', 300000, 'HOLD',
               now(), 202, $6
             )`,
            [
              operationId,
              implementerId,
              nodeId,
              `idem-${operationId}`,
              reqSha,
              JSON.stringify({ subscription_handle: createHandle }),
            ],
          );
          await pool.query(
            `INSERT INTO subscription_handles (
               id, node_id, operation_id, handle_hash, expires_at, created_at
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::sha256_hex, now() + interval '1 hour', now()
             )`,
            [randomUUID(), nodeId, operationId, hashSubscriptionHandle(createHandle)],
          );

          // Tick until the receive reaches READY.
          await waitFor(
            async () => {
              await handle.tickOnce();
              const r = await pool.query<{ status: string }>(
                `SELECT status FROM receive_operations WHERE operation_id = $1::uuid`,
                [operationId],
              );
              return r.rows[0]?.status === "READY";
            },
            { timeoutMs: 30_000, intervalMs: 300, label: "RECEIVE READY" },
          );

          // Step 4: arm the receive (code AWAITING_ARM → RELEASED).
          const opRow = await pool.query<{ wallet_id: string }>(
            `SELECT ow.wallet_id::text AS wallet_id
               FROM operation_wallets ow
              WHERE ow.operation_id = $1::uuid AND ow.operation_role = 'RECEIVER'`,
            [operationId],
          );
          const _walletId = opRow.rows[0]!.wallet_id;

          // Plant the arm acknowledgement to transition code to RELEASED.
          await pool.query(
            `UPDATE receive_codes
                SET code_status = 'RELEASED',
                    released_at = now()
              WHERE operation_id = $1::uuid AND code_status = 'AWAITING_ARM'`,
            [operationId],
          );

          // Step 5: backdate the expiry so the operation is past expiry + safety margin.
          // Set expiry_unix_time_secs to 120 seconds ago (well past the 30s safety margin).
          const pastExpirySecs = Math.floor(Date.now() / 1000) - 120;
          await pool.query(
            `UPDATE operations
                SET expiry_unix_time_secs = $2,
                    updated_at = now()
              WHERE id = $1::uuid`,
            [operationId, pastExpirySecs],
          );

          // Verify preconditions: operation is READY, lease exists, wallet is PINNED.
          const preCheck = await pool.query<{
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
               JOIN operation_wallets ow ON ow.operation_id = o.id
                AND ow.operation_role = 'RECEIVER'
               JOIN wallets w ON w.id = ow.wallet_id
              WHERE o.id = $1::uuid`,
            [operationId],
          );
          expect(preCheck.rows[0]?.status).toBe("READY");
          expect(preCheck.rows[0]?.wallet_state).toBe("PINNED");
          expect(Number(preCheck.rows[0]?.lease_count)).toBe(1);

          // Step 6: tick to trigger the expiry-release step. A formed READY
          // receive carries T0/code/artifact material, and this worker step
          // supplies no fresh exact-bytes observation to compare against, so
          // the receive must never be silently released here: the tick opens
          // an attention episode and preserves the lease and the pinned wallet.
          logs.length = 0;
          await handle.tickOnce();

          const attentionCheck = await pool.query<{
            status: string;
            attention_required: boolean;
            attention_reason: string | null;
            wallet_state: string;
            lease_count: string;
          }>(
            `SELECT o.status::text AS status,
                    o.attention_required AS attention_required,
                    o.attention_reason,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.wallet_id = w.id) AS lease_count
               FROM operations o
               JOIN operation_wallets ow ON ow.operation_id = o.id
                AND ow.operation_role = 'RECEIVER'
               JOIN wallets w ON w.id = ow.wallet_id
              WHERE o.id = $1::uuid`,
            [operationId],
          );
          const attentionRow = attentionCheck.rows[0]!;
          expect(attentionRow.status).toBe("READY");
          expect(attentionRow.attention_required).toBe(true);
          expect(attentionRow.attention_reason).toBe("T0_RELEASE_MISMATCH");
          expect(attentionRow.wallet_state).toBe("PINNED");
          expect(Number(attentionRow.lease_count)).toBe(1);
          expect(
            logs.some((l) => l.includes("receive expiry") && l.includes("ATTENTION")),
          ).toBe(true);

          // Step 7: the release path this worker step CAN prove on its own is
          // the proven-not-started one — a leased receive with zero formation
          // evidence (no T0, no code, no artifact, no signer use). Plant that
          // state past the queue wait + safety margin, make the identity signer
          // unavailable so formation skips without signing, and tick.
          identitySignerAvailable = false;
          const unformedWalletId = randomUUID();
          const unformedPublicKey = publicKeyFromSeed(randomBytes(32));
          const unformedOpId = randomUUID();
          await pool.query(
            `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
             VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
            [unformedWalletId, nodeId, unformedPublicKey],
          );
          await stampRecoveryVerified(pool, unformedWalletId, unformedPublicKey);
          await pool.query(
            `INSERT INTO operations (
               id, node_id, implementer_id, kind, status, row_version, amount_zkz,
               after_landing, discriminator, anchor, idempotency_key,
               request_sha256, created_at
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED', 1, '1',
               'HOLD', $1::uuid, 'receive-expiry-wiring-unformed', 'receive-expiry-wiring-unformed-idem', $4,
               now() - interval '300 seconds'
             )`,
            [unformedOpId, nodeId, implementerId, reqSha],
          );
          await pool.query(
            `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
             VALUES ($1::uuid, $2::uuid, 'RECEIVER')`,
            [unformedOpId, unformedWalletId],
          );
          // Dual-chain operation.expired owner lookup requires receive_operations (ZTR-1146).
          // CREATED rows must keep wallet_id NULL (receive_operations_no_receiver_while_created).
          const unformedHandle = mintSubscriptionHandlePlaintext();
          await pool.query(
            `INSERT INTO receive_operations (
               operation_id, implementer_id, node_id, kind, status,
               http_method, route, idempotency_key, request_sha256,
               amount_zkz, anchor, ttl_ms, after_landing_kind,
               completed_at, response_status, response_body
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED',
               'POST', '/v1/receives', $4, $5,
               '1', 'receive-expiry-wiring-unformed', 300000, 'HOLD',
               now(), 202, $6
             )`,
            [
              unformedOpId,
              implementerId,
              nodeId,
              `idem-unformed-${unformedOpId}`,
              reqSha,
              JSON.stringify({ subscription_handle: unformedHandle }),
            ],
          );
          await plantReceiveLease(pool, {
            walletId: unformedWalletId,
            operationId: unformedOpId,
            nodeId,
          });

          logs.length = 0;
          await handle.tickOnce();

          const postCheck = await pool.query<{
            status: string;
            receive_release_status: string | null;
            wallet_state: string;
            lease_count: string;
            proof_count: string;
            event_count: string;
          }>(
            `SELECT o.status::text AS status,
                    o.receive_release_status::text AS receive_release_status,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.wallet_id = w.id) AS lease_count,
                    (SELECT count(*)::text FROM receive_release_proofs
                      WHERE operation_id = o.id) AS proof_count,
                    (SELECT count(*)::text FROM receive_expiry_events
                      WHERE operation_id = o.id) AS event_count
               FROM operations o
               JOIN operation_wallets ow ON ow.operation_id = o.id
                AND ow.operation_role = 'RECEIVER'
               JOIN wallets w ON w.id = ow.wallet_id
              WHERE o.id = $1::uuid`,
            [unformedOpId],
          );

          const row = postCheck.rows[0]!;
          // AC2: expired receive transitions to EXPIRED.
          expect(row.status).toBe("EXPIRED");
          // AC2: proof-backed release (never a silent drop).
          expect(row.receive_release_status).toBe("RELEASED_PROVEN_NOT_STARTED");
          // AC2: wallet returns to AVAILABLE.
          expect(row.wallet_state).toBe("AVAILABLE");
          // One-in-flight: lease released through proof-backed path (never raw DELETE).
          expect(Number(row.lease_count)).toBe(0);
          // AC2: proof row present.
          expect(Number(row.proof_count)).toBeGreaterThanOrEqual(1);
          // AC5: operation.expired event appended.
          expect(Number(row.event_count)).toBe(1);

          const proofKind = await pool.query<{ release_kind: string }>(
            `SELECT release_kind FROM receive_release_proofs
              WHERE operation_id = $1::uuid`,
            [unformedOpId],
          );
          expect(proofKind.rows[0]?.release_kind).toBe("EXPIRED_PROVEN_NOT_STARTED");

          // Verify the lease release proof exists (RECEIVE_EXPIRED_T0 proof kind).
          const leaseProof = await pool.query<{ proof_kind: string }>(
            `SELECT proof_kind FROM lease_release_proofs
              WHERE operation_id = $1::uuid`,
            [unformedOpId],
          );
          expect(leaseProof.rows.length).toBeGreaterThanOrEqual(1);
          expect(leaseProof.rows[0]?.proof_kind).toBe("RECEIVE_EXPIRED_T0");

          // Verify the log shows the release.
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
      "expired receive with payment evidence → ATTENTION (never silently released)",
      async () => {
        const nodeId = randomUUID();
        const implementerId = randomUUID();
        const identitySeed = randomBytes(32);
        const identityPublicKey = publicKeyFromSeed(identitySeed);
        const signingKeyId = randomUUID();

        await ensureNodeRow(pool, {
          nodeId,
          displayName: "fixture-attention",
          identityPublicKey,
        });
        await pool.query(
          `INSERT INTO implementers (id, name, created_at)
           VALUES ($1::uuid, 'fixture-impl2', now())
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

        // Attention dual-chain-appends operation.needs_attention — needs real EVENT_SIGNING.
        const eventKeyClient = await pool.connect();
        let eventSigner: NodeEventSigner;
        try {
          await eventKeyClient.query("BEGIN");
          const eventKey = await ensureActiveNodeSigningKey({
            sql: {
              query: async <R>(text: string, params?: readonly unknown[]) => {
                const result = await eventKeyClient.query(text, params as never);
                return { rows: result.rows as R[] };
              },
            },
            rootKey,
            nodeId,
            purpose: "EVENT_SIGNING",
          });
          await eventKeyClient.query("COMMIT");
          eventSigner = {
            signingKeyId: eventKey.signingKeyId,
            sign: (bytes) => toBase64UrlPadded(Buffer.from(eventKey.sign(bytes))),
          };
        } finally {
          eventKeyClient.release();
        }

        const logs: string[] = [];
        const handle = startMoneyWorkers({
          pool,
          vault,
          config: {
            nodeId,
            ownerInstanceId: nodeId,
            poolCapTotal: 10,
            receiveQueueCap: 20,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            tickIntervalMs: 0,
            allowGenesisT0Stub: true,
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
          eventSigner: () => eventSigner,
        });

        try {
          // Plant a wallet and a READY operation with a candidate (payment evidence).
          const walletId = randomUUID();
          const operationId = randomUUID();
          const sha = "a".repeat(64);
          const pubkey = `${"Z".repeat(43)}=`;

          await pool.query(
            `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
             VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
            [walletId, nodeId, pubkey],
          );
          await stampRecoveryVerified(pool, walletId, pubkey);
          const pastExpirySecs = Math.floor(Date.now() / 1000) - 120;
          // A READY receive must carry the complete (receiver wallet, expiry, T0)
          // triple; operations.t0_observation_id has no FK, so a synthetic id is
          // enough to represent an assigned pre-code receive here.
          const t0ObservationId = randomUUID();
          await pool.query(
            `INSERT INTO operations (
               id, node_id, implementer_id, kind, status, row_version, amount_zkz,
               receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
               request_sha256, expiry_unix_time_secs, t0_observation_id
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY', 1, '1',
               $4::uuid, 'HOLD', $1::uuid, 'receive-expiry-wiring-att', 'receive-expiry-wiring-att-idem', $5, $6,
               $7::uuid
             )`,
            [operationId, nodeId, implementerId, walletId, sha, pastExpirySecs, t0ObservationId],
          );
          await pool.query(
            `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role, t0_observation_id)
             VALUES ($1::uuid, $2::uuid, 'RECEIVER', $3::uuid)`,
            [operationId, walletId, t0ObservationId],
          );
          // Dual-chain owner lookup + create-body carrier for this planted READY.
          const attHandle = mintSubscriptionHandlePlaintext();
          await pool.query(
            `INSERT INTO receive_operations (
               operation_id, implementer_id, node_id, kind, status,
               http_method, route, idempotency_key, request_sha256,
               amount_zkz, anchor, ttl_ms, after_landing_kind, wallet_id,
               completed_at, response_status, response_body
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY',
               'POST', '/v1/receives', $4, $5,
               '1', 'receive-expiry-wiring-att', 300000, 'HOLD', $6::uuid,
               now(), 201, $7
             )`,
            [
              operationId,
              implementerId,
              nodeId,
              `idem-att-${operationId}`,
              sha,
              walletId,
              JSON.stringify({ subscription_handle: attHandle }),
            ],
          );

          // Plant a lease.
          await plantReceiveLease(pool, { walletId, operationId, nodeId });

          // Plant a candidate (payment evidence) — this should block release.
          await pool.query(
            `INSERT INTO operation_transactions (
               operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
               step_1_signature, formed_at
             ) VALUES (
               $1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', '{}', $2,
               $3, now()
             )`,
            [operationId, sha, "A".repeat(86) + "=="],
          );

          // Tick — should route to ATTENTION, not release.
          logs.length = 0;
          await handle.tickOnce();

          // AC3: operation stays READY (not EXPIRED), wallet stays PINNED.
          const postCheck = await pool.query<{
            status: string;
            attention_required: boolean;
            wallet_state: string;
            lease_count: string;
          }>(
            `SELECT o.status::text AS status,
                    o.attention_required AS attention_required,
                    w.state::text AS wallet_state,
                    (SELECT count(*)::text FROM wallet_active_leases l
                      WHERE l.wallet_id = w.id) AS lease_count
               FROM operations o
               JOIN operation_wallets ow ON ow.operation_id = o.id
                AND ow.operation_role = 'RECEIVER'
               JOIN wallets w ON w.id = ow.wallet_id
              WHERE o.id = $1::uuid`,
            [operationId],
          );
          const row = postCheck.rows[0]!;
          // Payment evidence → attention, not silent release.
          expect(row.status).toBe("READY");
          expect(row.attention_required).toBe(true);
          expect(row.wallet_state).toBe("PINNED");
          expect(Number(row.lease_count)).toBe(1);

          // Verify the attention log.
          expect(
            logs.some((l) => l.includes("receive expiry") && l.includes("ATTENTION")),
          ).toBe(true);
        } finally {
          handle.stop();
        }
      },
      PG_TEST_TIMEOUT_MS,
    );
  },
);
