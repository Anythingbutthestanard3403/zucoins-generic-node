// Offline disposable-PG proof of the receive landing walk (steps 1–4).
//
// A receive parked at attempt phase STEP2_SIGNATURE_PERSISTED (the state that slice’s
// settle worker leaves behind after its single submit) is driven to a durable RECEIVE_LANDED
// through the real production pieces:
//
//   * sql-fresh-head-reader.ts   — the step-1 confirm-read + observation-ledger append,
//                                   driven by a SCRIPTED GatewayExchangeTransport (offline;
//                                   the network guard forbids sockets, and no submit RPC is
//                                   ever formed — the exchange asserts that per call).
// * node-core proveReceiveLanding / verifyAndCommitReceiveLanding — the landing oracle.
//   * sql-landing-store.ts       — the single landing DB-TX against real PostgreSQL.
//
// The signed bodies are the frozen receive-golden vectors
// (packages/generic-node-contracts/src/receive-golden/gen): seed_03 is the RECEIVER of
// `target.settled.json` with P = "" (genesis-adjacent) and B = 2.25, so the receive amount is
// exactly 2.25 ZKZ against a genesis T0. Nothing here mints a signature.
//
// Proves:
//   AC1  parked → RECEIVE_LANDED, proof header + ordered path + receive.landed committed,
//        transaction record at SETTLED_BODY_PERSISTED, receiver lease still held
//        (One-in-flight); a second run is idempotent (ALREADY_LANDED, no duplicate rows).
// AC3 a confirm-read that fails leaves the row parked and writes nothing; the
//        resumed run lands it. A head that is not the attempt lands nothing at all: no
//        landing verdict is ever minted from a bare head match.
//   AC4  the RECEIVE_LANDED status is the node-core constant, not a local literal.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  createMetricsHooks,
  createNodeMetrics,
  RECEIVE_LANDED_STATUS,
  RECEIVE_READY_STATUS,
  RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
  SqlReceiveLandingStore,
  advanceAttemptPhase,
  classifyReceiveLandingError,
  createDualChainEventAppender,
  deriveRootKey,
  EncryptedWalletKeyStore,
  ensureActiveNodeSigningKey,
  fingerprintEndpoint,
  InMemoryVaultAccessAuditLog,
  insertTransactionAttempt,
  listEvents,
  createPgImplementerEventLog,
  migrateLeaseFoundation,
  sha256Hex,
  toBase64UrlPadded,
  VaultSqlStore,
  type CommitReceiveLandingCommand,
  type NodeEventSigner,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type ReceiveLandingStore,
  type SignerLeadershipLatch,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlFreshHeadReader } from "../src/money-workers/sql-fresh-head-reader.js";
import { createSqlReceiveLandingStore } from "../src/money-workers/sql-landing-store.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";
import {
  PARKED_ATTEMPT_PHASE,
  runReceiveLandingStep,
} from "../src/money-workers/receive-landing-step.js";

const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "landing-master-key-32b!!!!!!!!!!!!!!!";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const GATEWAY_A = "https://gateway-a.test.invalid/";

const GEN_DIR = new URL(
  "../../../packages/generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: { seed_02: string; seed_03: string };
  target: { step_1_signature: string; step_2_signature: string };
};

const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03;
const TARGET_INNER_TEXT = fixtureText("target.step-1.json");
const TARGET_STEP2_PREIMAGE_TEXT = fixtureText("target.step-2.json");
const TARGET_SETTLED_TEXT = fixtureText("target.settled.json");
/** step_2_state.amount 2.25 minus a genesis receiver T0 (B0 = 0). */
const RECEIVE_AMOUNT_ZKZ = "2.25";

/** A body for a DIFFERENT wallet — a head that cannot be this receive's attempt. */
const PREDECESSOR_SETTLED_TEXT = fixtureText("predecessor.settled.json");

function sha256HexOfText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

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
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
        WHERE datname = $1 AND pid <> pg_backend_pid()`,
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

/**
 * Scripted gateway. Read-only by construction: every call asserts the RPC is
 * `get_transaction__v1` and that no submit action appears in the request bytes.
 */
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

function failingExchange(): GatewayExchangeTransport {
  return {
    async exchange(): Promise<GatewayExchangeCapture> {
      throw new Error("gateway unreachable (scripted)");
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

/** The node_events hash rule: SHA256(preimage_bytes ‖ signature_bytes). */
function eventHashOf(preimageText: string, signature: string): string {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from(preimageText, "utf8"), Buffer.from(signature, "base64url")]))
    .digest("hex");
}

/** The signed preimage's JSON body, after the purpose line. */
function payloadOf(preimageText: string): Record<string, unknown> {
  return JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
}

interface ParkedReceive {
  readonly nodeId: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly implementerId: string;
}

describe.skipIf(!PG_AVAILABLE)("receive landing commit (disposable PG)", () => {
  const dbName = `receive_landing_step_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let prevDatabaseUrl: string | undefined;
  /**
   * One real sealed EVENT_SIGNING signer per seeded node. `seedParkedReceive` mints
   * a fresh node per call, and node_signing_keys is per-node, so the landing store for a given
   * operation must be built with that operation's node signer.
   */
  const signers = new Map<string, NodeEventSigner>();
  /**
   * Per-node starting seq for this suite's node_events chains.
   *
   * `node_event_seq_counters` is keyed per node and `readTail` reads the high-water per node,
   * but `node_events.seq` is a GLOBAL primary key (event-ledger.sql:35). Two nodes in one
   * database therefore both allocate seq=1 and the second insert dies on `node_events_pkey`.
   * This suite mints a fresh node per seeded receive — the golden receiver public key plus
   * `wallets UNIQUE (node_id, public_key)` leaves no other option — so it gives each node a
   * disjoint seq range. That is a harness workaround for a schema/model contradiction that
   * predates the dual-chain landed-append (it was unreachable while only `receive.ready` appended node_events, and
   * suite uses exactly one node); the fix belongs in a migration, not here.
   */
  let nextNodeSeqBase = 1;

  /**
   * Seed the exact durable state settle worker leaves behind: a READY receive with
   * the receiver lease held and its one attempt at STEP2_SIGNATURE_PERSISTED carrying the
   * completed transaction text. Each call uses a fresh node so the wallets
   * UNIQUE (node_id, public_key) and the per-node observation stream stay disjoint.
   */
  async function seedParkedReceive(): Promise<ParkedReceive> {
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const operationId = randomUUID();
    const walletId = randomUUID();
    const leaseGroupId = randomUUID();
    const membershipId = randomUUID();
    const t0ObservationId = randomUUID();

    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-b-landing",
      identityPublicKey: publicKeyFromSeed(randomBytes(32)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-b-impl', now())`,
      [implementerId],
    );
    // recovery_verified_at is required by the G1 lease-eligibility trigger; this suite
    // never mints it on the money path, it seeds the post-ceremony state directly. The wallet
    // and its verification row reference each other, so the wallet lands unverified first and
    // the recovery pair is stamped afterwards (which the custody mutation guard permits
    // exactly once, while OLD.recovery_verified_at IS NULL).
    const verificationId = randomUUID();
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
      [walletId, nodeId, RECEIVER_PUBKEY],
    );
    await pool.query(
      `INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, public_key, export_sha256, audit_event_id,
          verified_at, verifier_identity)
       VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'fixture-b-suite')`,
      [verificationId, walletId, RECEIVER_PUBKEY, sha256HexOfText(walletId), randomUUID()],
    );
    await pool.query(
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid
        WHERE id = $1::uuid`,
      [walletId, verificationId],
    );
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz, receiver_wallet_id,
         after_landing, discriminator, anchor, idempotency_key, request_sha256,
         expiry_unix_time_secs, t0_observation_id, formation_state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', $4::operation_status, $5,
               $6::uuid, 'HOLD', $1::uuid, 'recv', $7, $8, '1784336400', $9::uuid,
               'NOT_REQUIRED')`,
      [
        operationId,
        nodeId,
        implementerId,
        RECEIVE_READY_STATUS,
        RECEIVE_AMOUNT_ZKZ,
        walletId,
        `idem-${operationId}`,
        sha256HexOfText(operationId),
        t0ObservationId,
      ],
    );
    await pool.query(
      `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role, t0_observation_id)
       VALUES ($1::uuid, $2::uuid, 'RECEIVER', $3::uuid)`,
      [operationId, walletId, t0ObservationId],
    );

    // Receiver lease — held before the landing and asserted still held after it (One-in-flight).
    await pool.query(
      `INSERT INTO lease_groups (id, root_operation_id, created_at)
       VALUES ($1::uuid, $2::uuid, now())`,
      [leaseGroupId, operationId],
    );
    await pool.query(
      `INSERT INTO wallet_lease_memberships
         (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'RECEIVE_WINDOW', 1, now())`,
      [membershipId, leaseGroupId, walletId, operationId],
    );
    await pool.query(
      `INSERT INTO wallet_active_leases
         (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
          lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
               'RECEIVE_WINDOW', 1, now(), now(), $5::uuid)`,
      [walletId, membershipId, leaseGroupId, operationId, randomUUID()],
    );

    // The attempt, advanced through the real one-way attempt store — never a hand-written row.
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
    await advanceAttemptPhase(query, operationId, PARKED_ATTEMPT_PHASE, {
      step_2_signature: MANIFEST.target.step_2_signature,
      completed_transaction_text: TARGET_SETTLED_TEXT,
      completed_transaction_sha256: sha256HexOfText(TARGET_SETTLED_TEXT),
    });

    // Disjoint node_events.seq range for this node — see `nextNodeSeqBase`. The appender's
    // ENSURE_COUNTER is ON CONFLICT DO NOTHING, so this pre-seeded row is the one it uses.
    nextNodeSeqBase += 1_000;
    await pool.query(
      `INSERT INTO node_event_seq_counters (node_id, next_seq) VALUES ($1::uuid, $2::bigint)`,
      [nodeId, nextNodeSeqBase],
    );

    // a landing appends its signed dual-chain event in the landing transaction, so
    // every node that lands needs a real sealed EVENT_SIGNING key — the same ensure production
    // boot runs, not a stub signer.
    const signingClient = await pool.connect();
    try {
      await signingClient.query("BEGIN");
      const key = await ensureActiveNodeSigningKey({
        sql: {
          query: async <R>(text: string, params?: readonly unknown[]) => {
            const result = await signingClient.query(text, params as never[]);
            return { rows: result.rows as R[], rowCount: result.rowCount };
          },
        },
        rootKey: deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT),
        nodeId,
        purpose: "EVENT_SIGNING",
      });
      await signingClient.query("COMMIT");
      signers.set(nodeId, {
        signingKeyId: key.signingKeyId,
        sign: (bytes) => toBase64UrlPadded(Buffer.from(key.sign(bytes))),
      });
    } finally {
      signingClient.release();
    }

    return { nodeId, operationId, walletId, implementerId };
  }

  /** The landing store bound to the seeded node's own EVENT_SIGNING signer. */
  function landingStoreFor(nodeId: string): ReceiveLandingStore {
    return createSqlReceiveLandingStore(pool, signers.get(nodeId));
  }

  /** Both signed chains for one operation, in append order. */
  async function dualChainRowsFor(operationId: string): Promise<{
    readonly node: readonly {
      seq: string;
      event_type: string;
      data_text: string;
      preimage_text: string;
      signature: string;
      event_hash: string;
      previous_event_hash: string | null;
    }[];
    readonly implementer: readonly { implementer_seq: string; event_type: string }[];
  }> {
    const node = await pool.query<{
      seq: string;
      event_type: string;
      data_text: string;
      preimage_text: string;
      signature: string;
      event_hash: string;
      previous_event_hash: string | null;
    }>(
      `SELECT seq::text AS seq, event_type, data_text, preimage_text, signature, event_hash,
              previous_event_hash
         FROM node_events WHERE operation_id = $1::uuid ORDER BY seq`,
      [operationId],
    );
    const implementer = await pool.query<{ implementer_seq: string; event_type: string }>(
      `SELECT i.implementer_seq::text AS implementer_seq, i.event_type
         FROM implementer_events i
         JOIN node_events n ON n.event_id = i.event_id
        WHERE n.operation_id = $1::uuid
        ORDER BY i.implementer_seq`,
      [operationId],
    );
    return { node: node.rows, implementer: implementer.rows };
  }

  function stepDeps(nodeId: string, exchange: GatewayExchangeTransport) {
    return {
      pool,
      nodeId,
      logger,
      readFreshHead: createSqlFreshHeadReader({
        pool,
        nodeId,
        gatewayUrls: [GATEWAY_A],
        exchange,
      }),
      store: landingStoreFor(nodeId),
    };
  }

  const headExchange = () => scriptedExchange(() => headEnvelopeBytes(TARGET_SETTLED_TEXT));

  async function statusOf(operationId: string): Promise<string> {
    const row = await pool.query<{ status: string }>(
      `SELECT status::text AS status FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    return row.rows[0]!.status;
  }

  async function attemptPhaseOf(operationId: string): Promise<string> {
    const row = await pool.query<{ attempt_phase: string }>(
      `SELECT attempt_phase FROM operation_transactions WHERE operation_id = $1::uuid`,
      [operationId],
    );
    return row.rows[0]!.attempt_phase;
  }

  async function leaseHeld(walletId: string): Promise<boolean> {
    const row = await pool.query(
      `SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
      [walletId],
    );
    return (row.rowCount ?? 0) === 1;
  }

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

  it(
    "AC1: parked STEP2_SIGNATURE_PERSISTED → durable RECEIVE_LANDED counts completion once; lease held; re-run idempotent",
    async () => {
      const parked = await seedParkedReceive();
      const metrics = createNodeMetrics();
      const metricsHooks = createMetricsHooks(metrics);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(PARKED_ATTEMPT_PHASE);

      const first = await runReceiveLandingStep({
        ...stepDeps(parked.nodeId, headExchange()),
        metricsHooks,
      });
      expect(first.indeterminate).toEqual([]);
      expect(first.landed).toEqual([parked.operationId]);
      expect(metrics.operationsCompleted.get({ kind: "RECEIVE_EXTERNAL" })).toBe(1);

      // Step 4 — status, phase, proof header, ordered path, event, proof-access expiry.
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(RECEIVE_SETTLED_BODY_PERSISTED_PHASE);

      const proof = await pool.query<{
        attempt_phase: string;
        public_execution_phase: string;
        path_role: string;
        verdict: string;
        body_count: string;
        path_depth: string;
        wallet_public_key: string;
        terminal_observation_id: string;
        fresh_head_observation_id: string;
        path_manifest_sha256: string;
      }>(`SELECT * FROM receive_landing_proofs WHERE operation_id = $1::uuid`, [
        parked.operationId,
      ]);
      expect(proof.rowCount).toBe(1);
      const header = proof.rows[0]!;
      expect(header.attempt_phase).toBe(RECEIVE_SETTLED_BODY_PERSISTED_PHASE);
      expect(header.public_execution_phase).toBe("LANDED_VERIFIED");
      expect(header.path_role).toBe("RECEIVER");
      expect(header.verdict).toBe("LANDED_EXACT");
      expect(Number(header.body_count)).toBe(1);
      expect(Number(header.path_depth)).toBe(0);
      expect(header.wallet_public_key).toBe(RECEIVER_PUBKEY);
      // The terminal observation is the durable confirm-read row, not a synthesized id.
      expect(header.terminal_observation_id).toBe(header.fresh_head_observation_id);
      const terminalRow = await pool.query<{ completed_transaction_text: string }>(
        `SELECT completed_transaction_text FROM gateway_observations WHERE id = $1::uuid`,
        [header.terminal_observation_id],
      );
      expect(terminalRow.rows[0]!.completed_transaction_text).toBe(TARGET_SETTLED_TEXT);

      const bodies = await pool.query<{
        path_index: string;
        source_kind: string;
        completed_transaction_text: string;
        wallet_role: string;
        p_signature: string;
      }>(
        `SELECT * FROM receive_landing_path_bodies WHERE operation_id = $1::uuid
          ORDER BY path_index`,
        [parked.operationId],
      );
      expect(bodies.rowCount).toBe(1);
      expect(bodies.rows[0]!.source_kind).toBe("EXPECTED_OPERATION");
      expect(bodies.rows[0]!.completed_transaction_text).toBe(TARGET_SETTLED_TEXT);
      expect(bodies.rows[0]!.wallet_role).toBe("receiver");
      expect(bodies.rows[0]!.p_signature).toBe("");

      const events = await pool.query<{ event_type: string; data_text: string }>(
        `SELECT event_type, data_text FROM receive_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(events.rowCount).toBe(1);
      expect(events.rows[0]!.event_type).toBe("receive.landed");
      expect(events.rows[0]!.data_text).toContain(header.terminal_observation_id);

      const opRow = await pool.query<{
        terminal_observation_id: string;
        verification_material_available_until: Date;
        row_version: string;
      }>(
        `SELECT terminal_observation_id::text AS terminal_observation_id,
                verification_material_available_until, row_version::text AS row_version
           FROM operations WHERE id = $1::uuid`,
        [parked.operationId],
      );
      expect(opRow.rows[0]!.terminal_observation_id).toBe(header.terminal_observation_id);
      expect(opRow.rows[0]!.verification_material_available_until).not.toBeNull();
      expect(Number(opRow.rows[0]!.row_version)).toBe(2);

      // One-in-flight — the receiver lease is untouched by the landing DB-TX.
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // Re-run: the candidate query no longer matches, and a forced replay would hit the CAS.
      const second = await runReceiveLandingStep({
        ...stepDeps(parked.nodeId, headExchange()),
        metricsHooks,
      });
      expect(second.landed).toEqual([]);
      expect(second.indeterminate).toEqual([]);
      expect(metrics.operationsCompleted.get({ kind: "RECEIVE_EXTERNAL" })).toBe(1);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);
      const proofCount = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(proofCount.rowCount).toBe(1);
      const eventCount = await pool.query(
        `SELECT 1 FROM receive_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(eventCount.rowCount).toBe(1);

      // wallet_settled_ledger gains exactly one RECEIVER row matching the
      // settled body digest/amount and the landing verdict.
      const ledger = await pool.query<{
        operation_role: string;
        amount_zkz: string;
        settled_transaction_sha256: string;
        settled_transaction_text: string;
        landing_verdict: string;
        wallet_id: string;
      }>(
        `SELECT operation_role, amount_zkz, settled_transaction_sha256,
                settled_transaction_text, landing_verdict, wallet_id::text AS wallet_id
           FROM wallet_settled_ledger
          WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(ledger.rowCount).toBe(1);
      expect(ledger.rows[0]!.operation_role).toBe("RECEIVER");
      expect(ledger.rows[0]!.wallet_id).toBe(parked.walletId);
      expect(ledger.rows[0]!.amount_zkz).toBe(RECEIVE_AMOUNT_ZKZ);
      expect(ledger.rows[0]!.landing_verdict).toBe("LANDED_EXACT");
      expect(ledger.rows[0]!.settled_transaction_text).toBe(TARGET_SETTLED_TEXT);
      expect(ledger.rows[0]!.settled_transaction_sha256).toBe(sha256HexOfText(TARGET_SETTLED_TEXT));
      const txMatch = await pool.query<{ match: boolean }>(
        `SELECT (l.settled_transaction_sha256 = t.completed_transaction_sha256
             AND l.settled_transaction_text = t.completed_transaction_text
             AND l.settled_at IS NOT DISTINCT FROM t.settled_at) AS match
           FROM wallet_settled_ledger l
           JOIN operation_transactions t
             ON t.operation_id = l.operation_id AND t.attempt_no = l.attempt_no
          WHERE l.operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(txMatch.rows[0]!.match).toBe(true);
      const verif = await pool.query(
        `SELECT 1 FROM operation_verifications
          WHERE operation_id = $1::uuid AND verdict = 'VERIFIED'`,
        [parked.operationId],
      );
      expect(verif.rowCount).toBe(1);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "AC3: a failed confirm-read writes nothing and leaves the row parked; the resumed run lands it",
    async () => {
      const parked = await seedParkedReceive();

      const crashed = await runReceiveLandingStep(stepDeps(parked.nodeId, failingExchange()));
      expect(crashed.landed).toEqual([]);
      expect(crashed.indeterminate).toHaveLength(1);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(PARKED_ATTEMPT_PHASE);
      const nothing = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(nothing.rowCount).toBe(0);
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // Review fix: a thrown read error is INDETERMINATE → set attention + event.
      const attOp = await pool.query<{ attention_required: boolean }>(
        `SELECT attention_required FROM operations WHERE id = $1::uuid`,
        [parked.operationId],
      );
      expect(attOp.rows[0]!.attention_required).toBe(true);
      const attEv = await pool.query(
        `SELECT 1 FROM receive_expiry_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(attEv.rowCount).toBe(1);

      // Resume — same durable row, working gateway.
      const resumed = await runReceiveLandingStep(stepDeps(parked.nodeId, headExchange()));
      expect(resumed.landed).toEqual([parked.operationId]);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(RECEIVE_SETTLED_BODY_PERSISTED_PHASE);
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "a head that is not this attempt lands nothing — no verdict from a bare head",
    async () => {
      const parked = await seedParkedReceive();

      // The head reads as a real, signature-valid settled transaction for a different wallet
      // pair. It is not the expected attempt, so the path never terminates at the head.
      const wrongHead = scriptedExchange(() => headEnvelopeBytes(PREDECESSOR_SETTLED_TEXT));
      const outcome = await runReceiveLandingStep(stepDeps(parked.nodeId, wrongHead));

      expect(outcome.landed).toEqual([]);
      expect(outcome.indeterminate).toHaveLength(1);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(PARKED_ATTEMPT_PHASE);
      const nothing = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(nothing.rowCount).toBe(0);
      // Never rebuilt, never resubmitted, lease never released.
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // Review fix: indeterminate outcome must set attention + append
      // operation.needs_attention (closing rule; one event per episode).
      const opRow = await pool.query<{ attention_required: boolean }>(
        `SELECT attention_required FROM operations WHERE id = $1::uuid`,
        [parked.operationId],
      );
      expect(opRow.rows[0]!.attention_required).toBe(true);
      const attEvents = await pool.query<{ event_type: string }>(
        `SELECT event_type FROM receive_expiry_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(attEvents.rowCount).toBe(1);
      expect(attEvents.rows[0]!.event_type).toBe("operation.needs_attention");

      // A second indeterminate observation in the same episode is idempotent — no new event.
      const outcome2 = await runReceiveLandingStep(stepDeps(parked.nodeId, wrongHead));
      expect(outcome2.indeterminate).toHaveLength(1);
      const attEvents2 = await pool.query(
        `SELECT 1 FROM receive_expiry_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(attEvents2.rowCount).toBe(1);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "review P1: byte-distinct wrappers for the same verified head land exactly once" +
      "(consecutive-change rule)",
    async () => {
      const parked = await seedParkedReceive();

      // Three byte-distinct wrappers for the SAME verified head — different `code`/`message`
      // fields produce different response bytes but the same parsed transaction.
      // The consecutive-change rule requires an append for each byte-changed response, so each read gets a different
      // observation ID. The oracle's own confirm-read is the authoritative one.
      let callCount = 0;
      const codes = ["ok", "success", "OK"];
      const byteDistinctExchange = scriptedExchange(() => {
        const code = codes[callCount % codes.length] ?? "ok";
        callCount++;
        return new TextEncoder().encode(
          `{"status":true,"code":"${code}","message":"","data":[${TARGET_SETTLED_TEXT}]}`,
        );
      });

      const outcome = await runReceiveLandingStep(
        stepDeps(parked.nodeId, byteDistinctExchange),
      );

      // The landing must succeed despite byte-distinct wrappers — the oracle binds to its own
      // final confirmed observation, not a preliminary read.
      expect(outcome.landed).toEqual([parked.operationId]);
      expect(outcome.indeterminate).toEqual([]);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);

      // The proof is bound to the oracle's final confirmed fresh-head observation.
      const proof = await pool.query<{ fresh_head_observation_id: string; terminal_observation_id: string }>(
        `SELECT fresh_head_observation_id::text, terminal_observation_id::text
           FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(proof.rowCount).toBe(1);
      expect(proof.rows[0]!.terminal_observation_id).toBe(proof.rows[0]!.fresh_head_observation_id);
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "production tick (tickOnce) wires runReceiveLandingStep —" +
      "settle OBSERVED_AT_HEAD then landing LANDED; lease held",
    async () => {
      const parked = await seedParkedReceive();
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);

      const vault = new EncryptedWalletKeyStore({
        rootKey: deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT),
        store: new VaultSqlStore(pool),
        auditLog: new InMemoryVaultAccessAuditLog(),
      });
      const tickLogs: string[] = [];
      const handle = startMoneyWorkers({
        pool,
        vault,
        config: {
          nodeId: parked.nodeId,
          ownerInstanceId: parked.nodeId,
          poolCapTotal: 5,
          // Production derives receiveQueueCap = POOL_CAP_TOTAL; keep the pair consistent.
          receiveQueueCap: 5,
          receiveQueueMaxWaitSecs: 600,
          receiveTtlDefaultSecs: 300,
          receiveTtlMinSecs: 60,
          receiveTtlMaxSecs: 3600,
          tickIntervalMs: 0,
          gatewayUrls: [GATEWAY_A],
          // Landing step only — the receive.ready append is not exercised here.
          allowMissingEventSigner: true,
        },
        logger: {
          info: (m: string) => tickLogs.push(m),
          error: (m: string, err?: unknown) =>
            tickLogs.push(`err:${m}${err instanceof Error ? ` ${err.message}` : ""}`),
        },
        moneyPathGates: {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: async () => {},
          assertHaltAdmitsKind: () => {},
        },
        nodeIdentitySigner: () => null,
        // The landing store signs its dual-chain terminal event, so the production
        // composition needs this node's EVENT_SIGNING signer. This half is wired; the other
        // half — start-money-workers.ts forwarding it to createSqlReceiveLandingStore /
        // createSqlExternalSendLandingStore — is owned by the lane and is why this
        // case is still red. It goes green the moment those two lines land.
        eventSigner: () => signers.get(parked.nodeId) ?? null,
        leadership: { held: true } satisfies SignerLeadershipLatch,
        submitGateway: {
          endpoint: GATEWAY_A,
          limits: { readTimeoutMs: 10_000, maxRequestBytes: 1_048_576, maxResponseBytes: 4_194_304 },
        },
        gatewayExchange: headExchange(),
      });

      try {
        await handle.tickOnce();
        expect(tickLogs.some((l) => l.includes("receive landing LANDED"))).toBe(true);
        expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);
        expect(await attemptPhaseOf(parked.operationId)).toBe(
          RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
        );
        const proof = await pool.query(
          `SELECT verdict FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
          [parked.operationId],
        );
        expect(proof.rowCount).toBe(1);
        expect(proof.rows[0]!.verdict).toBe("LANDED_EXACT");
        expect(await leaseHeld(parked.walletId)).toBe(true);
        const allLogs = tickLogs.join("\n");
        expect(allLogs).not.toMatch(/transfer_code[^_]/i);
        expect(allLogs).not.toMatch(/private_key|secret_key|seed_/i);
      } finally {
        handle.stop();
      }
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "(review fix): true pre-COMMIT crash — landing writes happen but COMMIT" +
      "fails; no partial rows; restart lands exactly once",
    async () => {
      const parked = await seedParkedReceive();

      // Create a crashing landing store: the pool's connect() returns a client whose
      // first COMMIT throws, simulating a process crash after the landing writes but
      // before the transaction commits. PostgreSQL rolls back the entire transaction.
      let crashOnCommit = true;
      const crashingStore: ReceiveLandingStore = {
        async commitLanding(command: CommitReceiveLandingCommand) {
          const client = await pool.connect();
          try {
            await client.query("BEGIN");
            const inner = new SqlReceiveLandingStore(
              {
                withTransaction: async (fn) =>
                  fn({
                    query: async <R>(text: string, params: readonly unknown[]) =>
                      ({ rows: (await client.query(text, params as never[])).rows as R[] }) as R,
                  }),
              },
              signers.get(parked.nodeId)!,
            );
            const result = await inner.commitLanding(command);
            if (!result.applied) {
              await client.query("ROLLBACK");
              return result;
            }
            await advanceAttemptPhase(
              async (text: string, values: readonly unknown[]) =>
                (await client.query(text, values as never[])).rows as readonly Record<string, unknown>[],
              command.operationId,
              RECEIVE_SETTLED_BODY_PERSISTED_PHASE,
              { settled_at: new Date().toISOString() },
            );
            if (crashOnCommit) {
              crashOnCommit = false;
              throw new Error("SIMULATED_CRASH_BEFORE_COMMIT");
            }
            await client.query("COMMIT");
            return result;
          } catch (err) {
            try { await client.query("ROLLBACK"); } catch { /* keep original */ }
            const classified = classifyReceiveLandingError(err);
            if (classified !== null) {
              return { applied: false, reason: classified, receiverLeaseStillHeld: true };
            }
            throw err;
          } finally {
            client.release();
          }
        },
      };

      const crashDeps = {
        pool,
        nodeId: parked.nodeId,
        logger,
        readFreshHead: createSqlFreshHeadReader({
          pool,
          nodeId: parked.nodeId,
          gatewayUrls: [GATEWAY_A],
          exchange: headExchange(),
        }),
        store: crashingStore,
      };

      // The crash: the landing attempt throws (COMMIT fails). The row stays parked.
      const crashed = await runReceiveLandingStep(crashDeps);
      expect(crashed.landed).toEqual([]);
      expect(crashed.indeterminate).toHaveLength(1);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(PARKED_ATTEMPT_PHASE);

      // No partial rows: the transaction rolled back — no proof, no event, no path.
      const noProof = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noProof.rowCount).toBe(0);
      const noEvent = await pool.query(
        `SELECT 1 FROM receive_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noEvent.rowCount).toBe(0);
      const noPath = await pool.query(
        `SELECT 1 FROM receive_landing_path_bodies WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noPath.rowCount).toBe(0);
      expect(await leaseHeld(parked.walletId)).toBe(true);
      // The signed chains rolled back with everything else. A crashed landing must
      // leave no authoritative event behind, exactly as it leaves no landed status behind.
      const crashedChains = await dualChainRowsFor(parked.operationId);
      expect(crashedChains.node).toEqual([]);
      expect(crashedChains.implementer).toEqual([]);

      // Restart: normal store, same durable row — lands exactly once.
      const resumed = await runReceiveLandingStep(stepDeps(parked.nodeId, headExchange()));
      expect(resumed.landed).toEqual([parked.operationId]);
      expect(resumed.indeterminate).toEqual([]);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(RECEIVE_SETTLED_BODY_PERSISTED_PHASE);
      // Exactly one proof — no partial row from the crashed attempt survived.
      const proofCount = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(proofCount.rowCount).toBe(1);
      expect(await leaseHeld(parked.walletId)).toBe(true);
      // And the restart that landed it appended exactly one event per chain.
      const resumedChains = await dualChainRowsFor(parked.operationId);
      expect(resumedChains.node).toHaveLength(1);
      expect(resumedChains.node[0]!.event_type).toBe("receive.landed");
      expect(resumedChains.implementer).toHaveLength(1);
    },
    PG_TEST_TIMEOUT_MS,
  );

  // ── RECEIVE landed appends the authoritative dual-chain event ────────────────

  it(
    "RECEIVE_LANDED commits with a signed receive.landed on node_events and" +
      "implementer_events, carrying the exact Appendix-B data and a verifying signature",
    async () => {
      const parked = await seedParkedReceive();
      const landed = await runReceiveLandingStep(stepDeps(parked.nodeId, headExchange()));
      expect(landed.landed).toEqual([parked.operationId]);
      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);

      const chains = await dualChainRowsFor(parked.operationId);
      expect(chains.node).toHaveLength(1);
      expect(chains.implementer).toHaveLength(1);

      const nodeRow = chains.node[0]!;
      expect(nodeRow.event_type).toBe("receive.landed");
      expect(chains.implementer[0]!.event_type).toBe("receive.landed");

      // receive.landed data: exactly {terminal_observation_id, landed_at}, and the same
      // bytes the slice-local row stored — one payload, digested twice, never rebuilt.
      const sliceRow = await pool.query<{ data_text: string; terminal_observation_id: string }>(
        `SELECT data_text, terminal_observation_id::text AS terminal_observation_id
           FROM receive_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(nodeRow.data_text).toBe(sliceRow.rows[0]!.data_text);
      const data = JSON.parse(nodeRow.data_text) as Record<string, unknown>;
      expect(Object.keys(data)).toEqual(["terminal_observation_id", "landed_at"]);
      expect(data.terminal_observation_id).toBe(sliceRow.rows[0]!.terminal_observation_id);

      // The stored hash really is SHA256(preimage_bytes ‖ signature_bytes), and the preimage
      // binds the operation and the data digest that the row carries.
      expect(eventHashOf(nodeRow.preimage_text, nodeRow.signature)).toBe(nodeRow.event_hash);
      const preimage = payloadOf(nodeRow.preimage_text);
      expect(preimage.operation_id).toBe(parked.operationId);
      expect(preimage.event_type).toBe("receive.landed");
      expect(preimage.data_sha256).toBe(sha256HexOfText(nodeRow.data_text));
      expect(preimage.wallet_id).toBe(parked.walletId);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "the landed event continues the node chain it was appended to, and the" +
      "tenant signed-pull cursor resumes onto it",
    async () => {
      const parked = await seedParkedReceive();

      // A prior event on the SAME node + implementer, minted by the existing ready-append
      // dual-chain appender. The landed event must extend this chain, not start its own.
      const priorClient = await pool.connect();
      try {
        await priorClient.query("BEGIN");
        const appender = createDualChainEventAppender({
          nodeId: parked.nodeId,
          query: async (text, values) =>
            (await priorClient.query(text, values as unknown[])).rows,
          signer: signers.get(parked.nodeId)!,
        });
        const prior = await appender.append({
          implementerId: parked.implementerId,
          eventType: "receive.ready",
          operationId: parked.operationId,
          walletId: parked.walletId,
          dataText: `{"operation_id":"${parked.operationId}","code_status":"AWAITING_ARM"}`,
          dataSha256: sha256HexOfText(`prior|${parked.operationId}`),
        });
        expect(prior.kind).toBe("APPENDED");
        await priorClient.query("COMMIT");
      } finally {
        priorClient.release();
      }

      const landedRun = await runReceiveLandingStep(stepDeps(parked.nodeId, headExchange()));
      expect(landedRun.landed).toEqual([parked.operationId]);

      const chain = await pool.query<{
        seq: string;
        event_type: string;
        event_hash: string;
        previous_event_hash: string | null;
      }>(
        `SELECT seq::text AS seq, event_type, event_hash, previous_event_hash
           FROM node_events WHERE node_id = $1::uuid ORDER BY seq`,
        [parked.nodeId],
      );
      expect(chain.rows.map((r) => r.event_type)).toEqual(["receive.ready", "receive.landed"]);
      expect(chain.rows[0]!.previous_event_hash).toBeNull();
      // Continuity: the landed event's previous_event_hash IS the prior event's event_hash.
      expect(chain.rows[1]!.previous_event_hash).toBe(chain.rows[0]!.event_hash);
      // Gapless per-node seq.
      expect(BigInt(chain.rows[1]!.seq) - BigInt(chain.rows[0]!.seq)).toBe(1n);

      // Signed-pull cursor resume: a consumer that
      // already read the prior event resumes and receives the landed one.
      const log = createPgImplementerEventLog({
        nodeId: parked.nodeId,
        query: async (text, values) => (await pool.query(text, values as unknown[])).rows,
        withTransaction: async (body) =>
          body(async (text, values) => (await pool.query(text, values as unknown[])).rows),
      });
      const firstPage = await listEvents(log, {
        implementerId: parked.implementerId,
        afterImplementerSeq: null,
        limit: 1,
      });
      expect(firstPage.events).toHaveLength(1);
      expect(firstPage.events[0]!.eventType).toBe("receive.ready");
      const resumed = await listEvents(log, {
        implementerId: parked.implementerId,
        afterImplementerSeq: firstPage.events[0]!.implementerSeq,
        limit: 10,
      });
      expect(resumed.events).toHaveLength(1);
      expect(resumed.events[0]!.eventType).toBe("receive.landed");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "two concurrent landing runs of one receive produce ONE landed status" +
      "and exactly ONE event per chain — no duplicate seq",
    async () => {
      const parked = await seedParkedReceive();

      // Two independent landing workers over the same parked row, each on its own pool
      // connection, so the race is decided at the database transaction boundary.
      await Promise.all([
        runReceiveLandingStep(stepDeps(parked.nodeId, headExchange())),
        runReceiveLandingStep(stepDeps(parked.nodeId, headExchange())),
      ]);

      expect(await statusOf(parked.operationId)).toBe(RECEIVE_LANDED_STATUS);

      // One landing ⇒ one authoritative event on each chain. The loser's CAS matched nothing,
      // so its whole transaction — including its event append — rolled back.
      const chains = await dualChainRowsFor(parked.operationId);
      expect(chains.node).toHaveLength(1);
      expect(chains.implementer).toHaveLength(1);

      // No duplicate seq anywhere on this node's chain.
      const dupes = await pool.query(
        `SELECT seq FROM node_events WHERE node_id = $1::uuid GROUP BY seq HAVING count(*) > 1`,
        [parked.nodeId],
      );
      expect(dupes.rowCount).toBe(0);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "(fail-closed): with no EVENT_SIGNING signer the landing does NOT commit —" +
      "no landed status, no proof, and no event on any chain",
    async () => {
      const parked = await seedParkedReceive();

      // The composition root's no-signer path. The store cannot produce the signed event that
      // must ride with the status CAS, so it must not land at all.
      const unsignedRun = await runReceiveLandingStep({
        ...stepDeps(parked.nodeId, headExchange()),
        store: createSqlReceiveLandingStore(pool),
      });
      expect(unsignedRun.landed).toEqual([]);
      expect(unsignedRun.indeterminate).toHaveLength(1);
      expect(unsignedRun.indeterminate[0]!.detail).toMatch(/EVENT_SIGNING/);

      expect(await statusOf(parked.operationId)).toBe(RECEIVE_READY_STATUS);
      expect(await attemptPhaseOf(parked.operationId)).toBe(PARKED_ATTEMPT_PHASE);
      const noProof = await pool.query(
        `SELECT 1 FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noProof.rowCount).toBe(0);
      const noSliceEvent = await pool.query(
        `SELECT 1 FROM receive_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noSliceEvent.rowCount).toBe(0);
      const chains = await dualChainRowsFor(parked.operationId);
      expect(chains.node).toEqual([]);
      expect(chains.implementer).toEqual([]);
      // The receiver lease is untouched by a refused landing.
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // And the same row still lands normally once a signer is present — the refusal parked
      // it, it did not poison it.
      const retried = await runReceiveLandingStep(stepDeps(parked.nodeId, headExchange()));
      expect(retried.landed).toEqual([parked.operationId]);
      const afterRetry = await dualChainRowsFor(parked.operationId);
      expect(afterRetry.node).toHaveLength(1);
      expect(afterRetry.implementer).toHaveLength(1);
    },
    PG_TEST_TIMEOUT_MS,
  );
});
