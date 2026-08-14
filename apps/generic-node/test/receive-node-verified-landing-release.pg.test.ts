// ZTR-1303 — NODE_VERIFIED receive landing releases the wallet lease in the same TX.
//
// Pattern: receive-expiry-release-proof.pg.test.ts / receive-landing-step.pg.test.ts —
// real migrations, real lease (createLeaseGroup + acquireLeases), scripted gateway hop only.
//
// AC1: NODE_VERIFIED + HOLD landing ⇒ RECEIVE_LANDED + lease_release_proofs(RECEIVE_LANDED)
//      + lease gone + receive_release_status=RELEASED_NODE_VERIFIED + wallet AVAILABLE.
//      Atomicity: missing lease_group_operations membership makes release fail → whole
//      landing rolls back (no RECEIVE_LANDED, no proof, lease still held).
// AC2: INDEPENDENT landing keeps receiverLeaseStillHeld (covered by receive-landing-step).
// AC3: verification-complete on NODE_VERIFIED → VerificationModeMismatchError (unit).
// AC4: NODE_VERIFIED + after_landing=INTERNAL_MOVE ⇒ no release; lease stays RECEIVE_WINDOW.
// AC5: NODE_VERIFIED parked to attention (anomalous head) releases nothing.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  acquireLeases,
  advanceAttemptPhase,
  createLeaseGroup,
  createMetricsHooks,
  createNodeMetrics,
  deriveRootKey,
  EncryptedWalletKeyStore,
  ensureActiveNodeSigningKey,
  fingerprintEndpoint,
  InMemoryVaultAccessAuditLog,
  insertTransactionAttempt,
  migrateLeaseFoundation,
  RECEIVE_LANDED_STATUS,
  RECEIVE_READY_STATUS,
  RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
  RELEASED_NODE_VERIFIED,
  sha256Hex,
  toBase64UrlPadded,
  VaultSqlStore,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type NodeEventSigner,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlFreshHeadReader } from "../src/money-workers/sql-fresh-head-reader.js";
import { createSqlReceiveLandingStore } from "../src/money-workers/sql-landing-store.js";
import {
  PARKED_ATTEMPT_PHASE,
  runReceiveLandingStep,
} from "../src/money-workers/receive-landing-step.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "node-verified-landing-release-master!!";
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
  target: { step_1_signature: string; step_2_signature: string };
};

const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03;
const TARGET_INNER_TEXT = fixtureText("target.step-1.json");
const TARGET_STEP2_PREIMAGE_TEXT = fixtureText("target.step-2.json");
const TARGET_SETTLED_TEXT = fixtureText("target.settled.json");
const RECEIVE_AMOUNT_ZKZ = "2.25";

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

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

function headEnvelopeBytes(settledText: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
}

function scriptedExchange(
  respond: (walletPublicKey: string) => Uint8Array,
): GatewayExchangeTransport {
  return {
    async exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
      const body = Buffer.from(request.bodyBytes).toString("utf8");
      expect(request.rpc).toBe("get_transaction__v1");
      expect(body).not.toMatch(/submit_transaction__v1/);
      const match = body.match(/key_public__base64urlsafe=([^&]+)/);
      const key = match ? decodeURIComponent(match[1]!) : "";
      const responseBytes = respond(key);
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

const logger = {
  lines: [] as string[],
  info(message: string) {
    this.lines.push(message);
  },
  error(message: string) {
    this.lines.push(`ERROR ${message}`);
  },
};

interface ParkedNodeVerified {
  readonly nodeId: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly implementerId: string;
  readonly eventSigner: NodeEventSigner;
}

describe.skipIf(!PG_AVAILABLE)(
  "NODE_VERIFIED receive landing lease release (ZTR-1303, disposable PG)",
  () => {
    const dbName = `nv_landing_release_${process.pid}_${Date.now()}`;
    let pool: Pool;
    let prevDatabaseUrl: string | undefined;
    let nextNodeSeqBase = 1;

    beforeAll(async () => {
      await createTestDatabase(dbName);
      pool = pgPool(dbName);
      prevDatabaseUrl = process.env.DATABASE_URL;
      process.env.DATABASE_URL = pgDatabaseUrl(dbName);
      const { runMigrationsOnPool } = await import("../src/db/migrate.js");
      await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
      await migrateLeaseFoundation({
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await pool.query(text, params as never);
          return { rows: result.rows as R[], rowCount: result.rowCount };
        },
      });
    }, PG_TEST_TIMEOUT_MS);

    afterAll(async () => {
      if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prevDatabaseUrl;
      await pool?.end().catch(() => {});
      await dropTestDatabase(dbName).catch(() => {});
    }, PG_TEST_TIMEOUT_MS);

    async function stampRecoveryVerified(walletId: string, publicKey: string): Promise<void> {
      const verificationId = randomUUID();
      await pool.query(
        `INSERT INTO wallet_recovery_verifications
           (id, wallet_id, method, public_key, export_sha256, audit_event_id,
            verified_at, verifier_identity)
         VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'ztr-1303-suite')`,
        [verificationId, walletId, publicKey, sha256HexOfText(walletId), randomUUID()],
      );
      await pool.query(
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid
          WHERE id = $1::uuid`,
        [walletId, verificationId],
      );
    }

    async function mintEventSigner(nodeId: string): Promise<NodeEventSigner> {
      const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
      // vault store required by ensureActiveNodeSigningKey path in some envs
      void new EncryptedWalletKeyStore({
        rootKey,
        store: new VaultSqlStore(pool),
        auditLog: new InMemoryVaultAccessAuditLog(),
      });
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
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* keep */
        }
        throw err;
      } finally {
        client.release();
      }
    }

    async function seedParked(opts: {
      readonly verificationMode: "INDEPENDENT" | "NODE_VERIFIED";
      readonly afterLanding: "HOLD" | "INTERNAL_MOVE";
      /** When false, omit lease_group_operations so release fails closed (atomicity). */
      readonly joinGroupOperation?: boolean;
      readonly destinationId?: string;
    }): Promise<ParkedNodeVerified> {
      const nodeId = randomUUID();
      const implementerId = randomUUID();
      const operationId = randomUUID();
      const walletId = randomUUID();
      const t0ObservationId = randomUUID();
      const joinGroup = opts.joinGroupOperation !== false;

      await ensureNodeRow(pool, {
        nodeId,
        displayName: "fixture-ztr-1303",
        identityPublicKey: publicKeyFromSeed(randomBytes(32)),
      });
      await pool.query(
        `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-1303-impl', now())`,
        [implementerId],
      );

      await pool.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
        [walletId, nodeId, RECEIVER_PUBKEY],
      );
      await stampRecoveryVerified(walletId, RECEIVER_PUBKEY);

      let destinationId: string | null = null;
      let destinationWalletId: string | null = null;
      if (opts.afterLanding === "INTERNAL_MOVE") {
        destinationId = opts.destinationId ?? randomUUID();
        destinationWalletId = randomUUID();
        // Distinct pubkey (base64url-ish padding) so UNIQUE (node_id, public_key) holds.
        const destPubkey = toBase64UrlPadded(randomBytes(32));
        await pool.query(
          `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
          [destinationWalletId, nodeId, destPubkey],
        );
        await stampRecoveryVerified(destinationWalletId, destPubkey);
        await pool.query(
          `INSERT INTO destinations (id, node_id, wallet_id, label, created_at)
           VALUES ($1::uuid, $2::uuid, $3::uuid, 'handoff-dest', now())`,
          [destinationId, nodeId, destinationWalletId],
        );
      }

      await pool.query(
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz, receiver_wallet_id,
           after_landing, after_landing_destination_id, discriminator, anchor, idempotency_key,
           request_sha256, expiry_unix_time_secs, t0_observation_id, formation_state,
           verification_mode
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', $4::operation_status, $5,
           $6::uuid, $7, $8::uuid, $1::uuid, 'recv', $9, $10, '1784336400', $11::uuid,
           'NOT_REQUIRED', $12
         )`,
        [
          operationId,
          nodeId,
          implementerId,
          RECEIVE_READY_STATUS,
          RECEIVE_AMOUNT_ZKZ,
          walletId,
          opts.afterLanding,
          destinationId,
          `idem-${operationId}`,
          sha256HexOfText(operationId),
          t0ObservationId,
          opts.verificationMode,
        ],
      );
      await pool.query(
        `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role, t0_observation_id)
         VALUES ($1::uuid, $2::uuid, 'RECEIVER', $3::uuid)`,
        [operationId, walletId, t0ObservationId],
      );
      await pool.query(
        `INSERT INTO receive_operations (
           operation_id, implementer_id, node_id, kind, status,
           http_method, route, idempotency_key, request_sha256,
           amount_zkz, anchor, ttl_ms, after_landing_kind, destination_id,
           destination_wallet_id, wallet_id,
           completed_at, response_status, response_body, verification_mode
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY',
           'POST', '/v1/receives', $4, $5,
           $6, 'recv', 300000, $7, $8::uuid,
           $9::uuid, $10::uuid,
           now(), 201, $11, $12
         )`,
        [
          operationId,
          implementerId,
          nodeId,
          `idem-${operationId}`,
          sha256HexOfText(operationId),
          RECEIVE_AMOUNT_ZKZ,
          opts.afterLanding,
          destinationId,
          destinationWalletId,
          walletId,
          JSON.stringify({
            subscription_handle: `sh_nv_${operationId.replace(/-/g, "").slice(0, 24)}`,
          }),
          opts.verificationMode,
        ],
      );

      // Production lease path: group + membership + active + PINNED.
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const tx = {
          query: async <R>(text: string, args?: readonly unknown[]) => {
            const result = await client.query(text, args as never);
            return { rows: result.rows as R[], rowCount: result.rowCount };
          },
        };
        if (joinGroup) {
          const childDisposition =
            opts.afterLanding === "INTERNAL_MOVE" ? ("PENDING" as const) : ("NONE" as const);
          const leaseGroupId = await createLeaseGroup(tx, {
            rootOperationId: operationId,
            childDisposition,
          });
          await acquireLeases(tx, {
            wallets: [{ walletId, leaseRole: "RECEIVE_WINDOW" }],
            leaseGroupId,
            rootOperationId: operationId,
            operationId,
            ownerInstanceId: nodeId,
          });
        } else {
          // Broken group: active lease without lease_group_operations — release must fail.
          const leaseGroupId = randomUUID();
          const membershipId = randomUUID();
          await client.query(
            `INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
             VALUES ($1::uuid, $2::uuid, now(), 'NONE')`,
            [leaseGroupId, operationId],
          );
          await client.query(
            `INSERT INTO wallet_lease_memberships
               (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'RECEIVE_WINDOW', 1, now())`,
            [membershipId, leaseGroupId, walletId, operationId],
          );
          await client.query(
            `INSERT INTO wallet_active_leases
               (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
                lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
                     'RECEIVE_WINDOW', 1, now(), now(), $5::uuid)`,
            [walletId, membershipId, leaseGroupId, operationId, nodeId],
          );
          await client.query(
            `UPDATE wallets SET state = 'PINNED' WHERE id = $1::uuid AND state = 'AVAILABLE'`,
            [walletId],
          );
        }
        await client.query("COMMIT");
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* keep */
        }
        throw err;
      } finally {
        client.release();
      }

      const query = async (text: string, values: readonly unknown[]) => {
        const result = await pool.query(text, values as never[]);
        return result.rows as readonly Record<string, unknown>[];
      };
      await insertTransactionAttempt(query, {
        operationId,
        innerPreimageText: TARGET_INNER_TEXT,
        innerSha256: sha256HexOfText(TARGET_INNER_TEXT),
        formedAt: new Date().toISOString(),
        payerStep1Signature: MANIFEST.target.step_1_signature,
      });
      await advanceAttemptPhase(query, operationId, "STEP2_PREIMAGE_PERSISTED", {
        step_2_preimage_text: TARGET_STEP2_PREIMAGE_TEXT,
        step_2_preimage_sha256: sha256HexOfText(TARGET_STEP2_PREIMAGE_TEXT),
      });
      await advanceAttemptPhase(
        query,
        operationId,
        PARKED_ATTEMPT_PHASE as "STEP2_SIGNATURE_PERSISTED",
        {
          step_2_signature: MANIFEST.target.step_2_signature,
          completed_transaction_text: TARGET_SETTLED_TEXT,
          completed_transaction_sha256: sha256HexOfText(TARGET_SETTLED_TEXT),
        },
      );

      nextNodeSeqBase += 1_000;
      await pool.query(
        `INSERT INTO node_event_seq_counters (node_id, next_seq) VALUES ($1::uuid, $2::bigint)`,
        [nodeId, nextNodeSeqBase],
      );

      const eventSigner = await mintEventSigner(nodeId);
      return { nodeId, operationId, walletId, implementerId, eventSigner };
    }

    function stepDeps(parked: ParkedNodeVerified, exchange: GatewayExchangeTransport) {
      return {
        pool,
        nodeId: parked.nodeId,
        logger,
        readFreshHead: createSqlFreshHeadReader({
          pool,
          nodeId: parked.nodeId,
          gatewayUrls: [GATEWAY_A],
          exchange,
        }),
        store: createSqlReceiveLandingStore(pool, parked.eventSigner),
        eventSigner: parked.eventSigner,
      };
    }

    const headExchange = () => scriptedExchange(() => headEnvelopeBytes(TARGET_SETTLED_TEXT));

    async function postState(operationId: string, walletId: string) {
      const row = await pool.query<{
        status: string;
        receive_release_status: string | null;
        attention_required: boolean;
        wallet_state: string;
        lease_count: string;
        lease_role: string | null;
        proof_kind: string | null;
        landing_proof_count: string;
        membership_reason: string | null;
      }>(
        `SELECT o.status::text AS status,
                o.receive_release_status::text AS receive_release_status,
                o.attention_required AS attention_required,
                w.state::text AS wallet_state,
                (SELECT count(*)::text FROM wallet_active_leases l
                  WHERE l.wallet_id = w.id) AS lease_count,
                (SELECT l.lease_role::text FROM wallet_active_leases l
                  WHERE l.wallet_id = w.id LIMIT 1) AS lease_role,
                (SELECT lp.proof_kind FROM lease_release_proofs lp
                  WHERE lp.operation_id = o.id LIMIT 1) AS proof_kind,
                (SELECT count(*)::text FROM receive_landing_proofs p
                  WHERE p.operation_id = o.id) AS landing_proof_count,
                (SELECT m.release_reason FROM wallet_lease_memberships m
                  JOIN lease_release_proofs lp ON lp.proof_id = m.release_proof_id
                 WHERE lp.operation_id = o.id
                 ORDER BY m.released_at DESC NULLS LAST
                 LIMIT 1) AS membership_reason
           FROM operations o
           JOIN wallets w ON w.id = $2::uuid
          WHERE o.id = $1::uuid`,
        [operationId, walletId],
      );
      return row.rows[0]!;
    }

    it(
      "AC1: NODE_VERIFIED + HOLD landing co-commits release proof + lease gone + RELEASED_NODE_VERIFIED + AVAILABLE",
      async () => {
        const parked = await seedParked({
          verificationMode: "NODE_VERIFIED",
          afterLanding: "HOLD",
        });
        const metrics = createNodeMetrics();
        const metricsHooks = createMetricsHooks(metrics);

        const result = await runReceiveLandingStep({
          ...stepDeps(parked, headExchange()),
          metricsHooks,
        });
        expect(result.landed).toEqual([parked.operationId]);

        const row = await postState(parked.operationId, parked.walletId);
        expect(row.status).toBe(RECEIVE_LANDED_STATUS);
        expect(row.receive_release_status).toBe(RELEASED_NODE_VERIFIED);
        expect(row.wallet_state).toBe("AVAILABLE");
        expect(Number(row.lease_count)).toBe(0);
        expect(row.proof_kind).toBe("RECEIVE_LANDED");
        expect(Number(row.landing_proof_count)).toBe(1);
        expect(row.membership_reason).toBe("NODE_VERIFIED_LANDING");
        expect(row.attention_required).toBe(false);
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "AC1 atomicity: release failure rolls back landing (no split TX partial land)",
      async () => {
        const parked = await seedParked({
          verificationMode: "NODE_VERIFIED",
          afterLanding: "HOLD",
          joinGroupOperation: false,
        });

        const result = await runReceiveLandingStep(stepDeps(parked, headExchange()));
        // Store throws on GROUP_OPERATION_MISSING → classified or surfaced as non-land.
        expect(result.landed).toEqual([]);

        const row = await postState(parked.operationId, parked.walletId);
        expect(row.status).toBe(RECEIVE_READY_STATUS);
        expect(row.receive_release_status).toBeNull();
        expect(Number(row.lease_count)).toBe(1);
        expect(row.proof_kind).toBeNull();
        expect(Number(row.landing_proof_count)).toBe(0);
        expect(row.wallet_state).toBe("PINNED");
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "AC4: NODE_VERIFIED + INTERNAL_MOVE keeps RECEIVE_WINDOW lease for child handoff",
      async () => {
        const parked = await seedParked({
          verificationMode: "NODE_VERIFIED",
          afterLanding: "INTERNAL_MOVE",
        });

        const result = await runReceiveLandingStep(stepDeps(parked, headExchange()));
        expect(result.landed).toEqual([parked.operationId]);

        const row = await postState(parked.operationId, parked.walletId);
        expect(row.status).toBe(RECEIVE_LANDED_STATUS);
        expect(row.receive_release_status).toBeNull();
        expect(Number(row.lease_count)).toBe(1);
        expect(row.lease_role).toBe("RECEIVE_WINDOW");
        expect(row.proof_kind).toBeNull();
        expect(row.wallet_state).toBe("PINNED");
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "AC5: NODE_VERIFIED anomalous head parks without release (negative twin)",
      async () => {
        const parked = await seedParked({
          verificationMode: "NODE_VERIFIED",
          afterLanding: "HOLD",
        });
        // Foreign settled body that is not the parked attempt — oracle cannot land.
        const wrongHead = scriptedExchange(() =>
          headEnvelopeBytes(fixtureText("predecessor.settled.json")),
        );

        const result = await runReceiveLandingStep(stepDeps(parked, wrongHead));
        expect(result.landed).toEqual([]);

        const row = await postState(parked.operationId, parked.walletId);
        expect(row.status).toBe(RECEIVE_READY_STATUS);
        expect(row.receive_release_status).toBeNull();
        expect(Number(row.lease_count)).toBe(1);
        expect(row.proof_kind).toBeNull();
        expect(Number(row.landing_proof_count)).toBe(0);
        expect(row.wallet_state).toBe("PINNED");
      },
      PG_TEST_TIMEOUT_MS,
    );
  },
);
