// Offline disposable-PG: READY+RELEASED → intake STEP1 → settle toward land.
import { Buffer } from "node:buffer";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as edSign,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  buildReceiveMessage,
  buildSendTransferCodeText,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type SenderPreflightObserver,
  type SqlQueryFn,
} from "@zucoins/node-core";

import {
  createCandidateIntakeInbox,
  runReceiveCandidateIntakeStep,
} from "../src/money-workers/receive-candidate-intake-step.js";
import { type ReceiveSettleStepDeps } from "../src/money-workers/receive-settle-step.js";
import { startMoneyWorkers } from "../src/money-workers/start-money-workers.js";
import {
  enqueueReceiverChannelDeposit,
  RECEIVER_CHANNEL_ACTION_NAME,
} from "../src/money-workers/receiver-channel-producer.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const SCHEMA = "receive_candidate_intake";
const IMPLEMENTER_ID = "00000000-0000-4000-8000-00000000000b";
const EXPIRY = "1893456000";
const ANCHOR = "ord_fixture";
const AMOUNT = "0.01";

const RECEIVER_SEED = Buffer.alloc(32, 0x13);
const PAYER_SEED = Buffer.alloc(32, 0x12);
const keyFromSeed = (seed: Buffer) =>
  createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    type: "pkcs8",
    format: "der",
  });
const publicKeyOf = (seed: Buffer): Buffer =>
  createPublicKey(keyFromSeed(seed)).export({ type: "spki", format: "der" }).subarray(-32);
const base64urlPadded = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const sha256Bytes = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const RECEIVER_PUBLIC = base64urlPadded(publicKeyOf(RECEIVER_SEED));
const PAYER_PUBLIC = base64urlPadded(publicKeyOf(PAYER_SEED));

function _hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const PG_AVAILABLE = (() => {
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

async function createTestDatabase(dbName: string): Promise<void> {
  const admin = new Client(adminClientConfig("postgres"));
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE ${dbName}`);
  } finally {
    await admin.end();
  }
}

async function dropTestDatabase(dbName: string): Promise<void> {
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

function buildInner(operationId: string): string {
  const message = buildReceiveMessage(operationId, ANCHOR);
  return (
    `{"type":"unique_combinable","version":"2","unix_time_secs":"1767225600","signer_steps":2` +
    `,"step_1_signer":"sender","step_2_signer":"receiver"` +
    `,"step_1_key_public__base64urlsafe":${JSON.stringify(PAYER_PUBLIC)}` +
    `,"step_2_key_public__base64urlsafe":${JSON.stringify(RECEIVER_PUBLIC)}` +
    `,"step_1_state":{"amount":"9.99"},"step_2_state":{"amount":${JSON.stringify(AMOUNT)}}` +
    `,"previous_step_1_state_signature":"","previous_step_2_state_signature":""` +
    `,"expiry__unix_time_secs":${JSON.stringify(EXPIRY)},"message":${JSON.stringify(message)}}`
  );
}
function signPayer(inner: string): string {
  return base64urlPadded(Buffer.from(edSign(null, Buffer.from(inner, "utf8"), keyFromSeed(PAYER_SEED))));
}

const schemaDir = fileURLToPath(new URL("../../../packages/node-core/src/schema/", import.meta.url));
const PACK_SLICES = [
  "base-enums-domains",
  "custody-eligibility",
  "signer-support",
  "operations",
  "transaction-material",
  "submit-attempts",
] as const;
const VERIFICATION_MODE_SLICE = readFileSync(`${schemaDir}verification-mode.sql`, "utf8");
const WALLET_MONEY_CAPABILITY_SLICE = readFileSync(
  `${schemaDir}wallet-money-capability.sql`,
  "utf8",
);

function packSql(): string {
  const declared = new Set<string>();
  const declarations: string[] = [];
  const tables = PACK_SLICES.map((slice) => readFileSync(`${schemaDir}${slice}.sql`, "utf8"))
    .join("\n")
    .replace(/^CREATE (DOMAIN|TYPE) ([a-z0-9_]+)[\s\S]*?;\n/gm, (statement, _k: string, name: string) => {
      if (!declared.has(name)) {
        declared.add(name);
        declarations.push(statement);
      }
      return "";
    });
  const extras = `
CREATE TABLE gateway_observations (
  id uuid PRIMARY KEY,
  s_signature text NOT NULL DEFAULT '',
  p_signature text NOT NULL DEFAULT '',
  b_amount text NOT NULL DEFAULT '0'
);
CREATE TABLE operation_observation_bindings (
  operation_id uuid NOT NULL,
  observation_id uuid NOT NULL,
  evidence_role text NOT NULL,
  wallet_public_key text NOT NULL,
  PRIMARY KEY (operation_id, evidence_role)
);
CREATE TABLE operation_expected_artifacts (id uuid PRIMARY KEY);
CREATE TABLE receive_codes (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  receiver_wallet_id uuid NOT NULL,
  t0_observation_id uuid NOT NULL,
  expected_artifact_id uuid NOT NULL,
  discriminator uuid NOT NULL,
  anchor text NOT NULL,
  expiry_unix_time_secs text NOT NULL,
  transfer_code_text text NOT NULL,
  transfer_code_sha256 text NOT NULL,
  code_status text NOT NULL,
  ready_at timestamptz NOT NULL,
  released_at timestamptz
);
-- Stubs so the full money-workers tick body can reach intake without a full money pack.
CREATE TABLE receive_operations (
  operation_id uuid PRIMARY KEY,
  node_id uuid,
  implementer_id uuid,
  status text NOT NULL DEFAULT 'CREATED',
  amount_zkz text,
  after_landing_kind text,
  destination_id uuid,
  wallet_id uuid,
  anchor text,
  idempotency_key text,
  request_sha256 text,
  ttl_ms bigint,
  completed_at timestamptz,
  response_status integer,
  response_body text
);
CREATE TABLE send_operations (
  operation_id uuid PRIMARY KEY,
  node_id uuid,
  implementer_id uuid,
  status text NOT NULL DEFAULT 'CREATED',
  amount_zkz text,
  source_wallet_id uuid,
  destination_address text,
  references_operation_id uuid,
  client_reference text,
  description text,
  idempotency_key text,
  request_sha256 text,
  formation_state text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS node_settings (
  setting_key text PRIMARY KEY,
  setting_value text NOT NULL,
  row_version bigint NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid PRIMARY KEY,
  action text NOT NULL
);
ALTER TABLE operations ADD COLUMN IF NOT EXISTS receive_release_status text;
`;
  return `${declarations.join("\n")}\n${tables}\n${WALLET_MONEY_CAPABILITY_SLICE}\n${extras}\n${VERIFICATION_MODE_SLICE}`;
}

async function _waitFor(
  pred: () => Promise<boolean>,
  opts: { timeoutMs: number; intervalMs: number; label: string },
): Promise<void> {
  const deadline = Date.now() + opts.timeoutMs;
  while (Date.now() < deadline) {
    if (await pred()) return;
    await new Promise((r) => setTimeout(r, opts.intervalMs));
  }
  throw new Error(`timeout waiting for ${opts.label}`);
}
const FK_TARGET_STUBS = ["nodes", "implementers", "operation_approvals"]
  .map((t) => `CREATE TABLE ${t} (id uuid PRIMARY KEY);`)
  .join("\n");

const vault: ReceiveSettleStepDeps["vault"] = {
  open: async () => {
    const bytes = Buffer.concat([RECEIVER_SEED, publicKeyOf(RECEIVER_SEED)]);
    return { bytes, wipe: () => bytes.fill(0) } as Awaited<
      ReturnType<ReceiveSettleStepDeps["vault"]["open"]>
    >;
  },
};

function makeExchange() {
  const calls: GatewayRequest[] = [];
  const transport: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      calls.push(request);
      const body =
        request.rpc === "submit_transaction__v1"
          ? '{"status":true,"code":"ok","message":"OK","data":{}}'
          : JSON.stringify({ status: true, code: "ok", message: "OK", data: [] });
      const responseBytes = new TextEncoder().encode(body);
      return {
        endpoint,
        endpointFingerprint: "offline-fp",
        requestBytes: request.bodyBytes,
        requestSha256: sha256Bytes(request.bodyBytes),
        responseBytes,
        responseSha256: sha256Bytes(responseBytes),
        statusCode: 200,
      };
    },
  };
  return { transport, submits: () => calls.filter((c) => c.rpc === "submit_transaction__v1") };
}

const senderPreflight: SenderPreflightObserver = {
  async observe() {
    return { kind: "VERIFIED", observationId: "preflight-offline-genesis", S: "", P: "", B: "10" };
  },
};

describe.runIf(PG_AVAILABLE)(
  "receive candidate intake (offline PG)",
  () => {
    const dbName = `receive_candidate_${process.pid}_${Date.now()}`;
    let pool: Pool;
    let logs: string[] = [];
    const logger = {
      info: (m: string) => void logs.push(m),
      error: (m: string, err?: unknown) =>
        void logs.push(`ERROR ${m} :: ${err instanceof Error ? err.message : String(err)}`),
    };

    const query: SqlQueryFn = async (text, values) => {
      const result = await pool.query(text, values as unknown[]);
      return result.rows as Record<string, unknown>[];
    };

    beforeAll(async () => {
      await createTestDatabase(dbName);
      pool = new Pool({
        host: PG_HOST,
        port: PG_PORT,
        user: PG_USER,
        database: dbName,
        password: process.env.PGPASSWORD,
        options: `-c search_path=${SCHEMA}`,
      });
      await pool.query(`CREATE SCHEMA ${SCHEMA}`);
      // search_path is process-default via Pool options; keep explicit SET for clarity.
      await pool.query(`SET search_path TO ${SCHEMA}`);
      await pool.query(FK_TARGET_STUBS);
      await pool.query(packSql());
      await pool.query(`INSERT INTO implementers (id) VALUES ($1::uuid)`, [IMPLEMENTER_ID]);
    }, PG_TEST_TIMEOUT_MS);

    afterAll(async () => {
      await pool?.end().catch(() => undefined);
      await dropTestDatabase(dbName).catch(() => undefined);
    }, PG_TEST_TIMEOUT_MS);

    beforeEach(async () => {
      logs = [];
      await pool.query(`SET search_path TO ${SCHEMA}`);
    });

    async function seedReadyReleased() {
      const operationId = randomUUID();
      const nodeId = randomUUID();
      const walletId = randomUUID();
      const obsId = randomUUID();
      const artId = randomUUID();
      const verificationId = randomUUID();
      await pool.query(`INSERT INTO nodes (id) VALUES ($1::uuid)`, [nodeId]);
      // Cap floor is 5 — pre-seed 5 wallets so scale-up mints nothing (no vault tables).
      for (let i = 0; i < 5; i++) {
        const id = i === 0 ? walletId : randomUUID();
        const pub =
          i === 0
            ? RECEIVER_PUBLIC
            : base64urlPadded(publicKeyOf(Buffer.alloc(32, 0x20 + i)));
        await pool.query(
          `INSERT INTO wallets (id, node_id, public_key, key_origin)
           VALUES ($1::uuid, $2::uuid, $3, 'node_generated')`,
          [id, nodeId, pub],
        );
      }
      await pool.query(
        `INSERT INTO wallet_recovery_verifications
           (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
         VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'receive-candidate')`,
        [verificationId, walletId, RECEIVER_PUBLIC, sha256(walletId), randomUUID()],
      );
      await pool.query(
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $1::uuid WHERE id = $2::uuid`,
        [verificationId, walletId],
      );
      await pool.query(
        `INSERT INTO gateway_observations (id, s_signature, p_signature, b_amount) VALUES ($1::uuid, '', '', '0')`,
        [obsId],
      );
      await pool.query(`INSERT INTO operation_expected_artifacts (id) VALUES ($1::uuid)`, [artId]);
      await pool.query(
        `INSERT INTO operations
           (id, node_id, implementer_id, kind, status, amount_zkz, receiver_wallet_id,
            discriminator, anchor, after_landing, expiry_unix_time_secs, t0_observation_id,
            idempotency_key, request_sha256)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY',
                 $4, $5::uuid, $1::uuid, $6, 'HOLD', $7, $8::uuid, $9, $10)`,
        [
          operationId, nodeId, IMPLEMENTER_ID, AMOUNT, walletId, ANCHOR, EXPIRY, obsId,
          `idem-${operationId}`, sha256(operationId),
        ],
      );
      await pool.query(
        `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
         VALUES ($1::uuid, $2::uuid, 'RECEIVER')`,
        [operationId, walletId],
      );
      await pool.query(
        `INSERT INTO operation_observation_bindings
           (operation_id, observation_id, evidence_role, wallet_public_key)
         VALUES ($1::uuid, $2::uuid, 'RECEIVER_T0', $3)`,
        [operationId, obsId, RECEIVER_PUBLIC],
      );
      await pool.query(
        `INSERT INTO receive_codes
           (operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
            discriminator, anchor, expiry_unix_time_secs, transfer_code_text, transfer_code_sha256,
            code_status, ready_at, released_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, $5, $6,
                 'code-offline', $7, 'RELEASED', now(), now())`,
        [operationId, walletId, obsId, artId, ANCHOR, EXPIRY, sha256("code-offline")],
      );
      await pool.query(
        `INSERT INTO wallet_active_leases
           (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
            lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
                 'RECEIVE_WINDOW', 7, now(), now(), $5::uuid)`,
        [walletId, randomUUID(), randomUUID(), operationId, randomUUID()],
      );
      return { operationId, nodeId, walletId };
    }

    it(
      "startMoneyWorkers tick: enqueue → intake STEP1 → settle STEP2",
      async () => {
        const { operationId } = await seedReadyReleased();
        const inner = buildInner(operationId);
        const step1 = signPayer(inner);
        const exchange = makeExchange();
        const handle = startMoneyWorkers({
          pool,
          vault: vault as never,
          config: {
            nodeId: "00000000-0000-4000-8000-00000000000a",
            ownerInstanceId: "00000000-0000-4000-8000-00000000000a",
            poolCapTotal: 5,
            receiveQueueCap: 5,
            receiveQueueMaxWaitSecs: 600,
            receiveTtlDefaultSecs: 300,
            receiveTtlMinSecs: 60,
            receiveTtlMaxSecs: 3600,
            // Manual ticks via handle.tickOnce — same leadership body as the interval.
            tickIntervalMs: 0,
            allowGenesisT0Stub: true,
            // Intake drain only — no receive.ready append in this suite. // contract-allow:drain:frozen structural vocabulary
            allowMissingEventSigner: true,
          },
          logger,
          moneyPathGates: {
            assertMoneyAdmitted: () => {},
            assertCanOperate: () => {},
            assertWalletMaySign: async () => {},
            assertHaltAdmitsKind: () => {},
          },
          nodeIdentitySigner: () => null,
          leadership: { held: true },
          senderPreflightObserver: senderPreflight,
          submitGateway: {
            endpoint: "https://gateway.offline.test",
            limits: { readTimeoutMs: 1000, maxRequestBytes: 65536, maxResponseBytes: 65536 },
            exchange: exchange.transport,
          },
        });
        try {
          // Production producer path: receiver-channel decode → handle.candidateIntake.enqueue.
          const encoded = buildSendTransferCodeText(inner, step1);
          const deposited = enqueueReceiverChannelDeposit(
            handle.candidateIntake,
            {
              action_name: RECEIVER_CHANNEL_ACTION_NAME,
              action_data: { sender_transfer_code_encoded: encoded },
            },
            "relay",
          );
          expect(deposited.enqueued, JSON.stringify(deposited)).toBe(true);
          expect(handle.candidateIntake.size()).toBe(1);

          await handle.tickOnce();
          expect(logs.join("\n"), logs.join("\n")).toMatch(
            /candidate intake ACCEPTED|accepted \d+ partial/,
          );

          const attempt = await pool.query(
            `SELECT attempt_phase, inner_preimage_text, step_1_signature
               FROM operation_transactions WHERE operation_id = $1::uuid`,
            [operationId],
          );
          expect(attempt.rows).toHaveLength(1);
          // Single leadership tick drains enqueue → STEP1 intake → settle STEP2.
          expect(attempt.rows[0]?.attempt_phase, logs.join("\n")).toBe(
            "STEP2_SIGNATURE_PERSISTED",
          );
          expect(attempt.rows[0]?.inner_preimage_text).toBe(inner);
          expect(attempt.rows[0]?.step_1_signature).toBe(step1);
          expect(exchange.submits().length).toBe(1);
        } finally {
          handle.stop();
        }
      },
      PG_TEST_TIMEOUT_MS,
    );

    it(
      "unarmed READY is refused with no durable attempt",
      async () => {
        const { operationId } = await seedReadyReleased();
        await pool.query(
          `UPDATE receive_codes SET code_status = 'AWAITING_ARM', released_at = NULL WHERE operation_id = $1::uuid`,
          [operationId],
        );
        const inner = buildInner(operationId);
        // Any per-lane cap above the single deposit this case queues.
        const inbox = createCandidateIntakeInbox(16);
        inbox.enqueue(
          {
            locate: { receiverPubkey: RECEIVER_PUBLIC, discriminator: operationId, expiry: EXPIRY },
            inner_preimage_text: inner,
            step_1_signature: signPayer(inner),
          },
          "relay",
        );
        expect(
          await runReceiveCandidateIntakeStep({ query, inbox, observeSender: senderPreflight, logger }),
        ).toBe(0);
        const rows = await pool.query(
          `SELECT count(*)::int AS n FROM operation_transactions WHERE operation_id = $1::uuid`,
          [operationId],
        );
        expect(rows.rows[0]?.n).toBe(0);
        expect(logs.join("\n")).toMatch(/UNARMED|rejected/);
      },
      PG_TEST_TIMEOUT_MS,
    );
  },
);
