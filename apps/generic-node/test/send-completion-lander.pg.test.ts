// Offline disposable-PG proof of the send landing flow (steps 1–6) for
// SEND_EXTERNAL. The composition test mirrors receive-landing-step.pg.test.ts.
//
// A send parked at AWAITING_REDEMPTION (the state formation worker leaves behind
// after step-1 persistence + delivery) is driven to a durable EXTERNAL_SEND_LANDED through
// the real production pieces:
//
//   * sql-fresh-head-reader.ts       — the step-1 source-head confirm-read, driven by a
//                                     SCRIPTED GatewayExchangeTransport (offline; no submit RPC
//                                     is ever formed — the exchange asserts that per call).
// * node-core proveSendLanding — the landing-proof rule any-depth complete-path oracle.
//   * node-core verifyExternalSendLanding — the nine-predicate landing verifier.
//   * send-sql-ports.ts             — the composition landing DB-TX (B2 operations mirror).
//
// The signed bodies are the frozen receive-golden vectors (seed_02 = SOURCE sender,
// seed_03 = DEST receiver): target.settled.json is the completed SEND (2.25 ZKZ), and
// predecessor.settled.json is the source T0 (seed_02 received 10 ZKZ from seed_05).
//
// Proves:
//   AC1  AWAITING_REDEMPTION → EXTERNAL_SEND_LANDED; landing record + event committed,
//        operations mirror synced (B2), source lease still held (One-in-flight); re-run idempotent.
//   AC3  a head that is unchanged T0 and still inside the signed redemption window → WAITING
//        (stay AWAITING_REDEMPTION, no park).
//   B4   a head that is a different transaction → PARK NEEDS_ATTENTION; genesis → INDETERMINATE.
//   AC3  gateway unreachable → INDETERMINATE (row stays AWAITING_REDEMPTION, lease untouched).
//   F1.1 unchanged T0 head PAST the signed expiry + aging margin → PARK NEEDS_ATTENTION with
//        POST_EXPIRY_RECONCILING; never terminal, lease held (ZTR-1129).
//   F2.2 a send already parked at NEEDS_ATTENTION still lands when the recipient submits late
//        — the scan covers both landing entry statuses (ZTR-1129).
//   F2.2 …and covering both statuses does NOT let the parked population starve the live one:
//        batchSize + 1 older parked sends, and a live send still lands on the first tick.

import { createHash, createPrivateKey, sign, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  buildSendExternalExpectedArtifact,
  createMetricsHooks,
  createNodeMetrics,
  createPgImplementerEventLog,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  InMemoryDeviceKeyStore,
  listEvents,
  sha256Hex,
  fingerprintEndpoint,
  toBase64UrlPadded,
  verifySettledTransaction,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type NodeEventSigner,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { publicKeyFromSeed, privateKeyFromSeed } from "../src/ops/ed25519-ops.js";
import { createSqlFreshHeadReader } from "../src/money-workers/sql-fresh-head-reader.js";
import { createSqlExternalSendLandingStore } from "../src/money-workers/send-sql-ports.js";
import {
  tickSendCompletionLander,
} from "../src/money-workers/send-completion-lander.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const GATEWAY_A = "https://gateway-a.test.invalid/";

// Dedicated cluster-level login role for the permission-revocation drill. Roles are
// cluster-wide (not per-database), so it is created once in beforeAll and reused across every
// per-test cloned database; PG_USER (the admin/migration connection) is superuser-equivalent in
// this harness, so REVOKE against it would be a no-op — this role is the only way to prove a
// genuine 42501 permission-denied fault.
const DEGRADED_LOWPRIV_ROLE = "degraded_lowpriv";
const DEGRADED_LOWPRIV_PASSWORD = "degraded-lowpriv-pw";

const GEN_DIR = new URL(
  "../../../packages/generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: { seed_02: string; seed_03: string; seed_05: string };
  target: { step_1_signature: string; step_2_signature: string };
  predecessor: { step_2_signature: string };
};

const SOURCE_PUBKEY = MANIFEST.public_keys.seed_02;
const DEST_PUBKEY = MANIFEST.public_keys.seed_03;
const TARGET_SETTLED_TEXT = fixtureText("target.settled.json");
const PREDECESSOR_SETTLED_TEXT = fixtureText("predecessor.settled.json");
const AMOUNT_ZKZ = "2.25";

const TARGET_PARSED = JSON.parse(TARGET_SETTLED_TEXT);
const TARGET_INNER = TARGET_PARSED.inner;
const TARGET_INNER_TEXT = JSON.stringify(TARGET_INNER);
const TARGET_STEP1_SIG = MANIFEST.target.step_1_signature;
const PREDECESSOR_PARSED = JSON.parse(PREDECESSOR_SETTLED_TEXT);

// Real (not fabricated) verification verdicts for the two retained fixture
// bodies, so the buried-landing drills' seeded gateway_observations rows carry fields
// `verifyHop` (ancestry-walker.ts) actually re-derives and cross-checks, not placeholders.
const PREDECESSOR_VERIFIED = verifySettledTransaction(PREDECESSOR_PARSED, SOURCE_PUBKEY);
if (PREDECESSOR_VERIFIED.verdict !== "VERIFIED") {
  throw new Error(`fixture predecessor.settled.json failed verification: ${PREDECESSOR_VERIFIED.verdict}`);
}
const PREDECESSOR_SEMANTIC_FINGERPRINT = PREDECESSOR_VERIFIED.semanticFingerprint;

const TARGET_VERIFIED = verifySettledTransaction(TARGET_PARSED, SOURCE_PUBKEY);
if (TARGET_VERIFIED.verdict !== "VERIFIED") {
  throw new Error(`fixture target.settled.json failed verification: ${TARGET_VERIFIED.verdict}`);
}
const TARGET_PROJECTION = TARGET_VERIFIED.projection;
const TARGET_SEMANTIC_FINGERPRINT = TARGET_VERIFIED.semanticFingerprint;
const TARGET_COMPLETED_TEXT = TARGET_VERIFIED.completedTransactionText;
const TARGET_COMPLETED_SHA256 = TARGET_VERIFIED.completedTransactionSha256;

const sha256HexOfText = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const keyFromSeed = (byte: number) => {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
};

const signText = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

function buildHop(prevStep2: string, amountOut: string, remaining: string, time: string) {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: time,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: SOURCE_PUBKEY,
    step_2_key_public__base64urlsafe: DEST_PUBKEY,
    step_1_state: { amount: remaining },
    step_2_state: { amount: amountOut },
    previous_step_1_state_signature: prevStep2,
    previous_step_2_state_signature: prevStep2,
  };
  const step1 = JSON.stringify(inner);
  const step1Sig = signText(step1, keyFromSeed(0x02));
  const step2Pre = JSON.stringify({ inner, step_1_signature: step1Sig });
  const step2Sig = signText(step2Pre, keyFromSeed(0x03));
  return JSON.stringify({ inner, step_1_signature: step1Sig, step_2_signature: step2Sig });
}

const CHANGED_HEAD_TEXT = buildHop(
  MANIFEST.predecessor.step_2_signature,
  "1.00",
  "6.75",
  "1784332900",
);

// a genuine successor of TARGET — backlinked to TARGET's own S
// (MANIFEST.target.step_2_signature), not the source T0's — the buried-completion shape
// the retained-body forward walk must prove.
const NEXT_HOP_TEXT = buildHop(MANIFEST.target.step_2_signature, "1.00", "1.25", "1784332950");

// Depth-walk negative: a head TWO hops beyond TARGET whose intermediate hop is never
// independently observed — no gateway_observations row exists for it, and the scripted
// exchange never returns it. resolveSuccessorByBacklink cannot find TARGET's immediate
// successor by backlink, so the walk must fail closed (INDETERMINATE, stay WAITING),
// never launder the gap into a false LANDED.
const UNRECORDED_INTERMEDIATE_TEXT = buildHop(
  MANIFEST.target.step_2_signature,
  "0.50",
  "0.75",
  "1784332950",
);
const UNPROVABLE_HEAD_TEXT = buildHop(
  (JSON.parse(UNRECORDED_INTERMEDIATE_TEXT) as { step_2_signature: string }).step_2_signature,
  "0.25",
  "0.50",
  "1784333000",
);

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

function genesisEnvelopeBytes(): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[]}`,
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
      // The wire form is `v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`
      // (gateway/request.ts), so the wallet key sits INSIDE the encoded JSON — a
      // `key_public__base64urlsafe=` scan of the raw body never matches and every caller
      // silently got "". Decode it the way the gateway does, so a drill can answer two
      // wallets differently.
      const decoded = JSON.parse(decodeURIComponent(body.replace(/^v=/, ""))) as {
        action_data?: { key_public__base64urlsafe?: string };
      };
      const responseBytes = respond(decoded.action_data?.key_public__base64urlsafe ?? "");
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

let pool: Pool;

const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const EVENT_MASTER = "send-landing-master-key-32b!!!!!!!!!!";

/** One real sealed EVENT_SIGNING signer per seeded node (node_signing_keys is per node). */
const sendSigners = new Map<string, NodeEventSigner>();

/**
 * Per-node starting seq. `node_event_seq_counters` and `readTail` are per node, but
 * `node_events.seq` is a GLOBAL primary key (event-ledger.sql:35), so two nodes in one
 * database both allocate seq=1 and collide on `node_events_pkey`. This suite mints a fresh
 * node per seeded send, so it hands each one a disjoint range. Harness workaround for a
 * schema/model contradiction that predates the dual-chain append slice; the fix belongs in a migration.
 */
let nextSendNodeSeqBase = 500_000;

/** Mint the node's EVENT_SIGNING key and reserve its seq range. */
async function provisionNodeEventSigner(nodeId: string): Promise<void> {
  nextSendNodeSeqBase += 1_000;
  await pool.query(
    `INSERT INTO node_event_seq_counters (node_id, next_seq) VALUES ($1::uuid, $2::bigint)`,
    [nodeId, nextSendNodeSeqBase],
  );
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const key = await ensureActiveNodeSigningKey({
      sql: {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await client.query(text, params as never[]);
          return { rows: result.rows as R[], rowCount: result.rowCount };
        },
      },
      rootKey: deriveRootKey(EVENT_MASTER, VAULT_ROOT_KDF_SALT),
      nodeId,
      purpose: "EVENT_SIGNING",
    });
    await client.query("COMMIT");
    sendSigners.set(nodeId, {
      signingKeyId: key.signingKeyId,
      sign: (bytes) => toBase64UrlPadded(Buffer.from(key.sign(bytes))),
    });
  } finally {
    client.release();
  }
}

/** Both signed chains for one operation. */
async function sendDualChainRows(operationId: string): Promise<{
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

interface ParkedSend {
  readonly nodeId: string;
  readonly operationId: string;
  readonly walletId: string;
  readonly implementerId: string;
}

/**
 * `sourcePubkey` overrides the golden SOURCE_PUBKEY so a drill can seed several sends whose
 * source heads the scripted exchange answers DIFFERENTLY (it dispatches on the requested
 * pubkey). Only the FIFO drill uses it, and only for filler rows that never assemble
 * evidence — the golden bodies below stay bound to SOURCE_PUBKEY.
 */
async function seedParkedSend(
  options: {
    buried?: boolean;
    sourcePubkey?: string;
    /** Pin signed redemption expiry at INSERT (sign_intents are insert-only). */
    signedExpiryUnixSecs?: number;
  } = {},
): Promise<ParkedSend> {
  const sourcePubkey = options.sourcePubkey ?? SOURCE_PUBKEY;
  const nodeId = randomUUID();
  const implementerId = randomUUID();
  const operationId = randomUUID();
  const walletId = randomUUID();
  const leaseGroupId = randomUUID();
  const membershipId = randomUUID();
  const approvalId = randomUUID();
  const artifactId = randomUUID();
  const sourceT0ObsId = randomUUID();
  const destT0ObsId = randomUUID();
  const leaseEpoch = 1;
  const nodeSeed = randomBytes(32);
  const nodeIdentityPrivateKey = privateKeyFromSeed(nodeSeed);
  const nodeIdentityPublicKey = publicKeyFromSeed(nodeSeed);

  await ensureNodeRow(pool, {
    nodeId,
    displayName: "fixture-b-landing",
    identityPublicKey: nodeIdentityPublicKey,
  });
  await pool.query(
    `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-b-impl', now())`,
    [implementerId],
  );
  await pool.query(
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
     VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'PINNED')`,
    [walletId, nodeId, sourcePubkey],
  );

  const observerId = randomUUID();
  await pool.query(
    `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
     VALUES ($1::uuid, 'NODE', $2::uuid, $3, now()) ON CONFLICT DO NOTHING`,
    [observerId, nodeId, fingerprintEndpoint(GATEWAY_A)],
  );

  const artifactPreimage = buildSendExternalExpectedArtifact({
    node_id: nodeId,
    implementer_id: implementerId,
    operation_id: operationId,
    source_selector: { kind: "WALLET_ID", wallet_id: walletId },
    source_pubkey: sourcePubkey,
    destination_address: DEST_PUBKEY,
    amount_zkz: AMOUNT_ZKZ,
    references_operation_id: null,
  } as Parameters<typeof buildSendExternalExpectedArtifact>[0]);
  const artifactSignature = signText(artifactPreimage.preimageText, nodeIdentityPrivateKey);

  await pool.query(
    `INSERT INTO gateway_observations (
       id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
       observed_at, http_status, raw_response_bytes, raw_response_sha256,
       parse_result, relationship, semantic_fingerprint, state_changed,
       wallet_role, s_signature, p_signature, b_amount,
       inner_preimage_text, step_1_signature, step_2_signature,
       completed_transaction_text, completed_transaction_sha256
     ) VALUES (
       $1::uuid, $2::uuid, $3, $4::uuid, $5, 1,
       now(), 200, $6::bytea, $7,
       'VERIFIED_HEAD', 'FIRST', $8, true,
       'receiver', $9, $10, $11,
       $12, $13, $14, $15, $16
     )`,
    [
      sourceT0ObsId, observerId, fingerprintEndpoint(GATEWAY_A), walletId, sourcePubkey,
      Buffer.from(headEnvelopeBytes(PREDECESSOR_SETTLED_TEXT)),
      sha256HexOfText(PREDECESSOR_SETTLED_TEXT),
      PREDECESSOR_SEMANTIC_FINGERPRINT,
      PREDECESSOR_PARSED.step_2_signature,
      "",
      "10",
      JSON.stringify(PREDECESSOR_PARSED.inner),
      PREDECESSOR_PARSED.step_1_signature,
      PREDECESSOR_PARSED.step_2_signature,
      PREDECESSOR_SETTLED_TEXT,
      sha256HexOfText(PREDECESSOR_SETTLED_TEXT),
    ],
  );

  await pool.query(
    `INSERT INTO gateway_observations (
       id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
       observed_at, http_status, raw_response_bytes, raw_response_sha256,
       parse_result, relationship, semantic_fingerprint, state_changed,
       wallet_role, s_signature, p_signature, b_amount
     ) VALUES (
       $1::uuid, $2::uuid, $3, $4, 1,
       now(), 200, $5::bytea, $6,
       'VERIFIED_GENESIS', 'FIRST', $7, false,
       'genesis', '', '', '0'
     )`,
    [
      destT0ObsId, observerId, fingerprintEndpoint(GATEWAY_A), DEST_PUBKEY,
      Buffer.from(genesisEnvelopeBytes()),
      sha256HexOfText(DEST_PUBKEY + "genesis"),
      sha256HexOfText(DEST_PUBKEY + "genesis-fp"),
    ],
  );

  // Seed observation cursors so the stream writer's next_wallet_seq does not collide with
  // the T0 observation rows (both T0s use wallet_seq=1; the next read must use seq=2).
  await pool.query(
    `INSERT INTO wallet_observation_cursors (
       observer_id, wallet_id, wallet_public_key, last_recorded_observation_id,
       last_raw_response_sha256, last_semantic_fingerprint, last_seen_at,
       next_wallet_seq)
     VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, now(), 2)`,
    [observerId, walletId, sourcePubkey, sourceT0ObsId,
     sha256HexOfText(PREDECESSOR_SETTLED_TEXT),
     PREDECESSOR_SEMANTIC_FINGERPRINT],
  );
  await pool.query(
    `INSERT INTO wallet_observation_cursors (
       observer_id, wallet_id, wallet_public_key, last_recorded_observation_id,
       last_raw_response_sha256, last_semantic_fingerprint, last_seen_at,
       next_wallet_seq)
     VALUES ($1::uuid, NULL, $2, $3::uuid, $4, $5, now(), 2)`,
    [observerId, DEST_PUBKEY, destT0ObsId,
     sha256HexOfText(DEST_PUBKEY + "genesis"),
     sha256HexOfText(DEST_PUBKEY + "genesis-fp")],
  );

  // Bury the SEND: pre-record TARGET itself as SOURCE_PUBKEY's own SUCCESSOR
  // observation (wallet_seq=2), the exact row `fetchRetainedBodyByStepOneSignature`
  // (retained-path-body-source-sql.ts) must resolve as `expectedBody` before the live tick
  // ever calls `walkAncestryPath`. The cursor is bumped to next_wallet_seq=3 so the tick's
  // own append of a later hop cannot collide with this row's wallet_seq=2 (the observation-ledger UNIQUE
  // (observer_id, wallet_public_key, wallet_seq)).
  if (options.buried) {
    const targetObsId = randomUUID();
    await pool.query(
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256
       ) VALUES (
         $1::uuid, $2::uuid, $3, $4::uuid, $5, 2,
         now(), 200, $6::bytea, $7,
         'VERIFIED_HEAD', 'SUCCESSOR', $8, true,
         $9, $10, $11, $12,
         $13, $14, $15, $16, $17
       )`,
      [
        targetObsId, observerId, fingerprintEndpoint(GATEWAY_A), walletId, sourcePubkey,
        Buffer.from(headEnvelopeBytes(TARGET_SETTLED_TEXT)),
        sha256HexOfText(TARGET_SETTLED_TEXT),
        TARGET_SEMANTIC_FINGERPRINT,
        TARGET_PROJECTION.role, TARGET_PROJECTION.S, TARGET_PROJECTION.P, TARGET_PROJECTION.B,
        TARGET_INNER_TEXT, TARGET_STEP1_SIG, MANIFEST.target.step_2_signature,
        TARGET_COMPLETED_TEXT, TARGET_COMPLETED_SHA256,
      ],
    );
    await pool.query(
      `UPDATE wallet_observation_cursors
          SET last_recorded_observation_id = $1::uuid, last_raw_response_sha256 = $2,
              last_semantic_fingerprint = $3, next_wallet_seq = 3, last_seen_at = now()
        WHERE observer_id = $4::uuid AND wallet_public_key = $5`,
      [targetObsId, sha256HexOfText(TARGET_SETTLED_TEXT), TARGET_SEMANTIC_FINGERPRINT,
       observerId, sourcePubkey],
    );
  }

  await pool.query(
    `INSERT INTO send_operations (
       operation_id, implementer_id, node_id, kind, status, row_version,
       attention_required, formation_state, http_method, route, idempotency_key,
       request_sha256, source_wallet_id, destination_address, amount_zkz,
       references_operation_id, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'SEND_EXTERNAL', 'AWAITING_REDEMPTION', 1,
       false, 'PARTIAL_DELIVERED', 'POST', '/v1/external-sends', $4, $5,
       $6::uuid, $7, $8, NULL, now())`,
    [operationId, implementerId, nodeId, `idem-${operationId}`,
     sha256HexOfText(operationId), walletId, DEST_PUBKEY, AMOUNT_ZKZ],
  );

  await pool.query(
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, amount_zkz,
       source_wallet_id, destination_address, references_operation_id,
       client_reference, description, idempotency_key, request_sha256, formation_state)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'SEND_EXTERNAL', 'AWAITING_REDEMPTION', $4,
       $5::uuid, $6, NULL, NULL, NULL, $7, $8, 'PARTIAL_DELIVERED')`,
    [operationId, nodeId, implementerId, AMOUNT_ZKZ, walletId, DEST_PUBKEY,
     `idem-${operationId}`, sha256HexOfText(operationId)],
  );

  await pool.query(
    `INSERT INTO send_operation_expected_artifacts (
       artifact_id, operation_id, purpose, canonical_version, signing_key_id,
       preimage_text, preimage_sha256, signature)
     VALUES ($1::uuid, $2::uuid, 'zp-send-external-expected-v1', 1, $3::uuid,
       $4, $5, $6)`,
    [artifactId, operationId, randomUUID(),
     artifactPreimage.preimageText, artifactPreimage.sha256, artifactSignature],
  );

  const challengeId = randomUUID();
  await pool.query(
    `INSERT INTO approval_challenges (
       id, node_id, operation_id, status, purpose, canonical_version,
       nonce, preimage_text, preimage_sha256, issued_at, expires_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'CONSUMED', 'zp-send-external-approval-v1', 1,
       $4, $5, $6, now(), now() + interval '5 min')`,
    [challengeId, nodeId, operationId, randomUUID(),
     `challenge-preimage-${operationId}`, sha256HexOfText(`challenge-preimage-${operationId}`)],
  );
  await pool.query(
    `INSERT INTO operation_approvals (
       id, node_id, operation_id, challenge_id, challenge_status, method, purpose,
       canonical_version, preimage_text, preimage_sha256,
       device_key_id, device_signature, totp_timestep, consumed_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'CONSUMED', 'TOTP_ONLY',
       'zp-send-external-approval-v1', 1, $5, $6, NULL, NULL, 1000, now())`,
    [approvalId, nodeId, operationId, challengeId,
     `approval-preimage-${operationId}`, sha256HexOfText(`approval-preimage-${operationId}`)],
  );

  // Byte-immutability (ZTR-1138): external_send_sign_intents is INSERT-only. Expiry drills
  // pin signed expiry here rather than UPDATEing inner_preimage_text after seed.
  const intentInnerText =
    options.signedExpiryUnixSecs !== undefined
      ? JSON.stringify({ expiry__unix_time_secs: String(options.signedExpiryUnixSecs) })
      : TARGET_INNER_TEXT;
  await pool.query(
    `INSERT INTO external_send_sign_intents (
       operation_id, approval_id, source_wallet_id,
       source_t0_observation_id, destination_t0_observation_id,
       lease_group_id, lease_epoch, inner_preimage_text, inner_sha256,
       redemption_expiry_at, prepared_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,
       $6::uuid, $7, $8, $9, now() + interval '5 min', now())`,
    [operationId, approvalId, walletId, sourceT0ObsId, destT0ObsId,
     leaseGroupId, leaseEpoch, intentInnerText, sha256HexOfText(intentInnerText)],
  );

  const transferCodeSha = sha256HexOfText("transfer-code-fixture-b");
  await pool.query(
    `INSERT INTO external_send_partials (
       operation_id, approval_id, inner_sha256, step_1_signature,
       transfer_code_text, transfer_code_sha256, persisted_at, first_delivered_at)
     VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, now(), now())`,
    [operationId, approvalId, sha256HexOfText(TARGET_INNER_TEXT),
     TARGET_STEP1_SIG, "transfer-code-fixture-b", transferCodeSha],
  );

  await pool.query(
    `INSERT INTO operation_transactions (
       operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
       step_1_signature, formed_at)
     VALUES ($1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', $2, $3, $4, now())`,
    [operationId, TARGET_INNER_TEXT, sha256HexOfText(TARGET_INNER_TEXT), TARGET_STEP1_SIG],
  );

  await pool.query(
    `INSERT INTO lease_groups (id, root_operation_id, created_at)
     VALUES ($1::uuid, $2::uuid, now())`,
    [leaseGroupId, operationId],
  );
  await pool.query(
    `INSERT INTO wallet_lease_memberships
       (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'SEND_SOURCE', $5, now())`,
    [membershipId, leaseGroupId, walletId, operationId, leaseEpoch],
  );
  await pool.query(
    `INSERT INTO wallet_active_leases
       (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
        lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $4::uuid,
             'SEND_SOURCE', $5, now(), now(), $6::uuid)`,
    [walletId, membershipId, leaseGroupId, operationId, leaseEpoch, randomUUID()],
  );

  // a landing appends its signed dual-chain event in the landing transaction, so the
  // node needs a real sealed EVENT_SIGNING key before it can land anything.
  await provisionNodeEventSigner(nodeId);

  return { nodeId, operationId, walletId, implementerId };
}

function landerDeps(
  nodeId: string,
  exchange: GatewayExchangeTransport,
  // The candidate-query pool defaults to the ambient `pool` so all 8 pre-existing
  // call sites (2 args) are unaffected; the drill tests below override it with a connection
  // that is dead or permission-stripped to exercise loadSendLandingCandidates' failure path.
  queryPool: Pool = pool,
) {
  return {
    pool: queryPool,
    logger,
    readFreshHead: createSqlFreshHeadReader({
      pool, nodeId, gatewayUrls: [GATEWAY_A], exchange,
    }),
    store: createSqlExternalSendLandingStore(pool, sendSigners.get(nodeId) ?? null),
    nodeId,
    deviceKeyStore: new InMemoryDeviceKeyStore(),
    // ZTR-1146: park path dual-chains operation.needs_attention with EVENT_SIGNING.
    eventSigner: sendSigners.get(nodeId) ?? null,
  };
}

const headExchange = () => scriptedExchange(() => headEnvelopeBytes(TARGET_SETTLED_TEXT));
const genesisExchange = () => scriptedExchange(() => genesisEnvelopeBytes());
const t0Exchange = () => scriptedExchange(() => headEnvelopeBytes(PREDECESSOR_SETTLED_TEXT));
const changedExchange = () => scriptedExchange(() => headEnvelopeBytes(CHANGED_HEAD_TEXT));
const nextHopExchange = () => scriptedExchange(() => headEnvelopeBytes(NEXT_HOP_TEXT));
const unprovableExchange = () => scriptedExchange(() => headEnvelopeBytes(UNPROVABLE_HEAD_TEXT));

async function sendStatusOf(operationId: string): Promise<string> {
  const row = await pool.query<{ status: string }>(
    `SELECT status::text AS status FROM send_operations WHERE operation_id = $1::uuid`,
    [operationId],
  );
  return row.rows[0]!.status;
}

async function opsStatusOf(operationId: string): Promise<string> {
  const row = await pool.query<{ status: string }>(
    `SELECT status::text AS status FROM operations WHERE id = $1::uuid`,
    [operationId],
  );
  return row.rows[0]!.status;
}

async function opsTerminalObsOf(operationId: string): Promise<string | null> {
  const row = await pool.query<{ terminal_observation_id: string | null }>(
    `SELECT terminal_observation_id::text AS terminal_observation_id FROM operations WHERE id = $1::uuid`,
    [operationId],
  );
  return row.rows[0]!.terminal_observation_id;
}

async function attentionReasonOf(operationId: string): Promise<string | null> {
  const row = await pool.query<{ attention_reason: string | null }>(
    `SELECT attention_reason FROM send_operations WHERE operation_id = $1::uuid`,
    [operationId],
  );
  return row.rows[0]!.attention_reason;
}


/** Put a send in the parked state F2.2 starts from, without going through the lander. */
async function parkPastExpiryByHand(operationId: string): Promise<void> {
  await pool.query(
    `UPDATE send_operations
        SET status = 'NEEDS_ATTENTION', attention_required = true,
            attention_reason = 'POST_EXPIRY_RECONCILING',
            attention_episode = attention_episode + 1,
            row_version = row_version + 1
      WHERE operation_id = $1::uuid`,
    [operationId],
  );
  await pool.query(
    `UPDATE operations o
        SET status = s.status::operation_status,
            attention_required = s.attention_required,
            attention_reason = s.attention_reason,
            row_version = s.row_version
       FROM send_operations s
      WHERE s.operation_id = $1::uuid AND o.id = s.operation_id`,
    [operationId],
  );
}

async function leaseHeld(walletId: string): Promise<boolean> {
  const row = await pool.query(
    `SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
    [walletId],
  );
  return (row.rowCount ?? 0) === 1;
}

describe.skipIf(!PG_AVAILABLE)("send completion lander (disposable PG)", () => {
  const templateDb = `landertpl_${process.pid}_${Date.now()}`;
  let prevDatabaseUrl: string | undefined;

  beforeAll(async () => {
    // Create a template database with all migrations so each test can clone it fast.
    await createTestDatabase(templateDb);
    const tplPool = pgPool(templateDb);
    prevDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(templateDb);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(tplPool, { databaseUrl: process.env.DATABASE_URL });
    const { migrateLeaseFoundation } = await import("@zucoins/node-core");
    await migrateLeaseFoundation({
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await tplPool.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    });
    await tplPool.end();
    // Mark as template so CREATE DATABASE ... TEMPLATE works.
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(`ALTER DATABASE ${templateDb} WITH IS_TEMPLATE true`);
      // Dedicated low-priv role for the permission-revocation drill; roles are
      // cluster-wide so this is created once and reused across every cloned per-test database.
      await admin.query(
        `DO $$ BEGIN
           IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DEGRADED_LOWPRIV_ROLE}') THEN
             CREATE ROLE ${DEGRADED_LOWPRIV_ROLE} LOGIN PASSWORD '${DEGRADED_LOWPRIV_PASSWORD}';
           END IF;
         END $$;`,
      );
    } finally {
      await admin.end();
    }
  }, PG_TEST_TIMEOUT_MS);

  beforeEach(async () => {
    // Each test gets a fresh database cloned from the template — no leftover data, no
    // FK/trigger cleanup issues (append-only tables are fresh too).
    const dbName = `lander_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${dbName} TEMPLATE ${templateDb}`);
    } finally {
      await admin.end();
    }
    pool = pgPool(dbName);
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
  }, PG_TEST_TIMEOUT_MS);

  afterEach(async () => {
    const dbName = pool?.options.database;
    await pool?.end().catch(() => {});
    if (dbName !== undefined) await dropTestDatabase(dbName);
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (prevDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDatabaseUrl;
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(`ALTER DATABASE ${templateDb} WITH IS_TEMPLATE false`);
      await admin.query(`DROP DATABASE IF EXISTS ${templateDb}`);
      await admin.query(`DROP ROLE IF EXISTS ${DEGRADED_LOWPRIV_ROLE}`);
    } finally {
      await admin.end();
    }
  }, PG_TEST_TIMEOUT_MS);

  it(
    "AC1: AWAITING_REDEMPTION → EXTERNAL_SEND_LANDED counts completion once; record + event + operations mirror (B2); lease held (One-in-flight); re-run idempotent",
    async () => {
      const parked = await seedParkedSend();
      const metrics = createNodeMetrics();
      const metricsHooks = createMetricsHooks(metrics);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");

      const first = await tickSendCompletionLander({
        ...landerDeps(parked.nodeId, headExchange()),
        metricsHooks,
      });
      expect(first.landed).toEqual([parked.operationId]);
      expect(first.indeterminate).toBe(0);
      expect(first.parked).toBe(0);
      expect(metrics.operationsCompleted.get({ kind: "SEND_EXTERNAL" })).toBe(1);

      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsTerminalObsOf(parked.operationId)).not.toBeNull();

      const record = await pool.query(
        `SELECT 1 FROM external_send_landing_records WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(record.rowCount).toBe(1);
      const event = await pool.query(
        `SELECT 1 FROM external_send_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(event.rowCount).toBe(1);

      expect(await leaseHeld(parked.walletId)).toBe(true);

      const second = await tickSendCompletionLander({
        ...landerDeps(parked.nodeId, headExchange()),
        metricsHooks,
      });
      expect(second.landed).toEqual([]);
      expect(second.indeterminate).toBe(0);
      expect(metrics.operationsCompleted.get({ kind: "SEND_EXTERNAL" })).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "AC3: unchanged T0 head BEFORE the signed expiry → WAITING (stay AWAITING_REDEMPTION, no park, no landing)",
    async () => {
      const parked = await seedParkedSend({
        signedExpiryUnixSecs: Math.floor(Date.now() / 1000) + 3600,
      });

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, t0Exchange()));
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(0);
      expect(result.indeterminate).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "B4: genesis head → INDETERMINATE (stay AWAITING_REDEMPTION)",
    async () => {
      const parked = await seedParkedSend();

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, genesisExchange()));
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(0);
      expect(result.indeterminate).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "F1.1: unchanged T0 head PAST expiry + aging margin → PARK NEEDS_ATTENTION/POST_EXPIRY_RECONCILING (never terminal, lease held)",
    async () => {
      // Pin past expiry at INSERT (sign_intents insert-only) so the drill states the boundary.
      const parked = await seedParkedSend({
        signedExpiryUnixSecs: Math.floor(Date.now() / 1000) - 7200,
      });

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, t0Exchange()));
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(1);
      expect(result.indeterminate).toBe(0);

      expect(await sendStatusOf(parked.operationId)).toBe("NEEDS_ATTENTION");
      expect(await opsStatusOf(parked.operationId)).toBe("NEEDS_ATTENTION");
      expect(await attentionReasonOf(parked.operationId)).toBe("POST_EXPIRY_RECONCILING");
      // Park is attention-only: the source lease is exactly where it was (golden rule 2).
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // The attention episode is appended once, not on every subsequent tick.
      const second = await tickSendCompletionLander(landerDeps(parked.nodeId, t0Exchange()));
      expect(second.parked).toBe(0);
      const ev = await pool.query(
        `SELECT 1 FROM external_send_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(ev.rowCount).toBe(1);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "F2.2: a send parked at NEEDS_ATTENTION that lands after expiry is still detected and reconciled to EXTERNAL_SEND_LANDED",
    async () => {
      const parked = await seedParkedSend();
      // The row is already parked past expiry (F1.1 owns getting it here; this drill owns
      // what happens next). The signed preimage is left exactly as formed — the
      // nine-predicate verifier reads it.
      await parkPastExpiryByHand(parked.operationId);
      expect(await sendStatusOf(parked.operationId)).toBe("NEEDS_ATTENTION");

      // The recipient submits after the deadline. The parked row is still scanned — the
      // whole point of F2.2 — and the late landing reconciles.
      const second = await tickSendCompletionLander(landerDeps(parked.nodeId, headExchange()));
      expect(second.landed).toEqual([parked.operationId]);
      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsTerminalObsOf(parked.operationId)).not.toBeNull();
      expect(await attentionReasonOf(parked.operationId)).toBeNull();
      // Landing does not release the source lease — verification-complete does.
      expect(await leaseHeld(parked.walletId)).toBe(true);

      const record = await pool.query(
        `SELECT entry_status::text AS entry_status FROM external_send_landing_records
          WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(record.rowCount).toBe(1);
      expect((record.rows[0] as { entry_status: string }).entry_status).toBe("NEEDS_ATTENTION");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "parked sends never starve the live arm: batchSize + 1 older parked sends and a live send still lands",
    async () => {
      // The failure this pins is a live send-path outage, not a slow queue. A parked send has
      // no terminal path while the close is RESERVED (CONTINUE_EXTERNAL_WAIT needs
      // !protocolExpiredPlusMargin, which the post-expiry park makes false), so it stays
      // NEEDS_ATTENTION indefinitely. Under one shared oldest-first FIFO, `batchSize` such rows
      // take every slot on every tick, forever, and external sends stop landing entirely.
      const BATCH = 2;
      const fillers: ParkedSend[] = [];
      for (let i = 0; i < BATCH + 1; i += 1) {
        // Its own source pubkey so the scripted exchange can answer it differently — a filler's
        // head reads genesis, which is what a genuinely stuck parked send looks like.
        const filler = await seedParkedSend({ sourcePubkey: paddedBase64Url(randomBytes(32)) });
        await parkPastExpiryByHand(filler.operationId);
        fillers.push(filler);
      }
      // Backdate every parked row so the shared FIFO would hand them all of `batchSize`.
      await pool.query(
        `UPDATE send_operations SET created_at = now() - interval '1 day'
          WHERE status = 'NEEDS_ATTENTION'`,
      );

      const live = await seedParkedSend();
      expect(await sendStatusOf(live.operationId)).toBe("AWAITING_REDEMPTION");

      const result = await tickSendCompletionLander({
        ...landerDeps(
          live.nodeId,
          scriptedExchange((key) =>
            key === SOURCE_PUBKEY ? headEnvelopeBytes(TARGET_SETTLED_TEXT) : genesisEnvelopeBytes(),
          ),
        ),
        batchSize: BATCH,
      });

      // The live arm got its own full budget: the send landed on the very first tick.
      expect(result.landed).toEqual([live.operationId]);
      expect(await sendStatusOf(live.operationId)).toBe("EXTERNAL_SEND_LANDED");
      // ...and the parked population is still parked, still re-scanned, still holding leases.
      for (const filler of fillers) {
        expect(await sendStatusOf(filler.operationId)).toBe("NEEDS_ATTENTION");
        expect(await leaseHeld(filler.walletId)).toBe(true);
      }
      expect(result.indeterminate).toBe(fillers.length);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "B4: changed head (different transaction) → PARK NEEDS_ATTENTION (reason + event + mirror sync + dual-chain)",
    async () => {
      const parked = await seedParkedSend();

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, changedExchange()));
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(1);
      expect(result.indeterminate).toBe(0);

      expect(await sendStatusOf(parked.operationId)).toBe("NEEDS_ATTENTION");
      expect(await opsStatusOf(parked.operationId)).toBe("NEEDS_ATTENTION");

      const ev = await pool.query<{ event_type: string }>(
        `SELECT event_type FROM external_send_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(ev.rowCount).toBe(1);
      expect(ev.rows[0]!.event_type).toBe("operation.needs_attention");

      // ZTR-1146: tenant stream must observe the park (not slice-local only).
      const chains = await sendDualChainRows(parked.operationId);
      expect(chains.node.map((r) => r.event_type)).toEqual(["operation.needs_attention"]);
      expect(chains.implementer.map((r) => r.event_type)).toEqual(["operation.needs_attention"]);
      const payload = JSON.parse(chains.node[0]!.data_text) as {
        current_state: string;
        attention_reason: string;
        operator_action_required: boolean;
      };
      expect(payload.current_state).toBe("NEEDS_ATTENTION");
      expect(payload.operator_action_required).toBe(true);
      expect(typeof payload.attention_reason).toBe("string");

      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "B4/ZTR-1146: park without EVENT_SIGNING fails closed (no NEEDS_ATTENTION, no dual-chain)",
    async () => {
      const parked = await seedParkedSend();
      const deps = {
        ...landerDeps(parked.nodeId, changedExchange()),
        eventSigner: null,
      };

      const result = await tickSendCompletionLander(deps);
      expect(result.parked).toBe(0);
      expect(result.indeterminate).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await opsStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");

      const slice = await pool.query(
        `SELECT 1 FROM external_send_attention_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(slice.rowCount).toBe(0);
      const chains = await sendDualChainRows(parked.operationId);
      expect(chains.node).toEqual([]);
      expect(chains.implementer).toEqual([]);
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "AC3: gateway unreachable → INDETERMINATE (row stays AWAITING_REDEMPTION, lease untouched)",
    async () => {
      const parked = await seedParkedSend();

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, failingExchange()));
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(0);
      expect(result.indeterminate).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "buried SEND (successor observed, depth >= 1) -> LANDED via retained-body forward walk; no exact-head match required",
    async () => {
      const parked = await seedParkedSend({ buried: true });
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");

      const result = await tickSendCompletionLander(landerDeps(parked.nodeId, nextHopExchange()));
      expect(result.landed).toEqual([parked.operationId]);
      expect(result.indeterminate).toBe(0);
      expect(result.parked).toBe(0);

      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      expect(await opsTerminalObsOf(parked.operationId)).not.toBeNull();

      const record = await pool.query(
        `SELECT 1 FROM external_send_landing_records WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(record.rowCount).toBe(1);

      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "AC3-negative: buried SEND with an unprovable successor gap -> stays WAITING/AWAITING_REDEMPTION, never laundered to LANDED",
    async () => {
      const parked = await seedParkedSend({ buried: true });

      const result = await tickSendCompletionLander(
        landerDeps(parked.nodeId, unprovableExchange()),
      );
      expect(result.landed).toEqual([]);
      expect(result.parked).toBe(0);
      expect(result.indeterminate).toBe(1);
      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  // loadSendLandingCandidates must never launder a real PostgreSQL fault into an
  // empty candidate set (No-blind-retry: a fault must never look like completed work). These three drills
  // inject genuine PG faults (not mocks) and assert the tick rejects typed instead of reporting
  // healthy idle, and that the parked send is untouched (fail-closed, One-in-flight lease intact).

  it(
    "candidate-query connection failure -> propagated TRANSIENT, never healthy idle (fail-closed)",
    async () => {
      const parked = await seedParkedSend();
      const deadDbName = `degraded_absent_${randomUUID().replace(/-/g, "")}`;
      const deadPool = pgPool(deadDbName);

      try {
        await expect(
          tickSendCompletionLander(landerDeps(parked.nodeId, headExchange(), deadPool)),
        ).rejects.toMatchObject({
          name: "SendLandingCandidateQueryError",
          kind: "TRANSIENT",
        });
      } finally {
        await deadPool.end().catch(() => {});
      }

      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "candidate-query permission revocation -> propagated STRUCTURAL 42501, never healthy idle, never landed (fail-closed)",
    async () => {
      const parked = await seedParkedSend();
      const dbName = pool.options.database as string;
      await pool.query(`GRANT CONNECT ON DATABASE ${dbName} TO ${DEGRADED_LOWPRIV_ROLE}`);
      await pool.query(`GRANT USAGE ON SCHEMA public TO ${DEGRADED_LOWPRIV_ROLE}`);
      const lowPrivPool = new Pool({
        host: PG_HOST,
        port: PG_PORT,
        database: dbName,
        user: DEGRADED_LOWPRIV_ROLE,
        password: DEGRADED_LOWPRIV_PASSWORD,
      });

      try {
        await expect(
          tickSendCompletionLander(landerDeps(parked.nodeId, headExchange(), lowPrivPool)),
        ).rejects.toMatchObject({
          name: "SendLandingCandidateQueryError",
          kind: "STRUCTURAL",
          sqlstate: "42501",
        });
      } finally {
        await lowPrivPool.end().catch(() => {});
      }

      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "candidate-query missing table -> propagated STRUCTURAL 42P01, never healthy idle (fail-closed)",
    async () => {
      const parked = await seedParkedSend();
      await pool.query(`ALTER TABLE send_operations RENAME TO send_operations_removed_fixture`);
      try {
        await expect(
          tickSendCompletionLander(landerDeps(parked.nodeId, headExchange())),
        ).rejects.toMatchObject({
          name: "SendLandingCandidateQueryError",
          kind: "STRUCTURAL",
          sqlstate: "42P01",
        });
      } finally {
        await pool.query(`ALTER TABLE send_operations_removed_fixture RENAME TO send_operations`);
      }

      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      expect(await leaseHeld(parked.walletId)).toBe(true);
    },
    PG_TEST_TIMEOUT_MS,
  );
  // ── SEND landed appends the authoritative dual-chain event ───────────────────

  it(
    "EXTERNAL_SEND_LANDED commits with a signed external_send.landed on" +
      "node_events and implementer_events, carrying the exact Appendix-B data",
    async () => {
      const parked = await seedParkedSend();
      const run = await tickSendCompletionLander(landerDeps(parked.nodeId, headExchange()));
      expect(run.landed).toEqual([parked.operationId]);
      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");

      const chains = await sendDualChainRows(parked.operationId);
      expect(chains.node).toHaveLength(1);
      expect(chains.implementer).toHaveLength(1);
      expect(chains.node[0]!.event_type).toBe("external_send.landed");
      expect(chains.implementer[0]!.event_type).toBe("external_send.landed");

      // external_send.landed data: exactly {terminal_observation_id, landed_at}, and the
      // same bytes the slice-local row stored — one payload, digested twice, never rebuilt.
      const slice = await pool.query<{ data_text: string; terminal_observation_id: string }>(
        `SELECT data_text, terminal_observation_id::text AS terminal_observation_id
           FROM external_send_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(chains.node[0]!.data_text).toBe(slice.rows[0]!.data_text);
      const data = JSON.parse(chains.node[0]!.data_text) as Record<string, unknown>;
      expect(Object.keys(data)).toEqual(["terminal_observation_id", "landed_at"]);
      expect(data.terminal_observation_id).toBe(slice.rows[0]!.terminal_observation_id);

      // The stored hash really is SHA256(preimage_bytes ‖ signature_bytes).
      const expectedHash = createHash("sha256")
        .update(
          Buffer.concat([
            Buffer.from(chains.node[0]!.preimage_text, "utf8"),
            Buffer.from(chains.node[0]!.signature, "base64url"),
          ]),
        )
        .digest("hex");
      expect(expectedHash).toBe(chains.node[0]!.event_hash);

      // The signed preimage binds this operation and the data digest the row carries.
      const preimage = JSON.parse(
        chains.node[0]!.preimage_text.slice(chains.node[0]!.preimage_text.indexOf("\n") + 1),
      ) as Record<string, unknown>;
      expect(preimage.operation_id).toBe(parked.operationId);
      expect(preimage.event_type).toBe("external_send.landed");
      expect(preimage.data_sha256).toBe(sha256HexOfText(chains.node[0]!.data_text));

      // Signed-pull: the tenant sees the terminal event on its own chain.
      const log = createPgImplementerEventLog({
        nodeId: parked.nodeId,
        query: async (text, values) => (await pool.query(text, values as unknown[])).rows,
        withTransaction: async (body) =>
          body(async (text, values) => (await pool.query(text, values as unknown[])).rows),
      });
      const page = await listEvents(log, {
        implementerId: parked.implementerId,
        afterImplementerSeq: null,
        limit: 10,
      });
      expect(page.events.map((e) => e.eventType)).toEqual(["external_send.landed"]);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "two concurrent landing ticks produce ONE landed status and exactly" +
      "ONE event per chain — no duplicate seq",
    async () => {
      const parked = await seedParkedSend();

      await Promise.all([
        tickSendCompletionLander(landerDeps(parked.nodeId, headExchange())),
        tickSendCompletionLander(landerDeps(parked.nodeId, headExchange())),
      ]);

      expect(await sendStatusOf(parked.operationId)).toBe("EXTERNAL_SEND_LANDED");
      const chains = await sendDualChainRows(parked.operationId);
      expect(chains.node).toHaveLength(1);
      expect(chains.implementer).toHaveLength(1);

      const dupes = await pool.query(
        `SELECT seq FROM node_events WHERE node_id = $1::uuid GROUP BY seq HAVING count(*) > 1`,
        [parked.nodeId],
      );
      expect(dupes.rowCount).toBe(0);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "(fail-closed): with no EVENT_SIGNING signer the send landing does NOT" +
      "commit — no landed status, no record, and no event on any chain",
    async () => {
      const parked = await seedParkedSend();

      const unsigned = await tickSendCompletionLander({
        ...landerDeps(parked.nodeId, headExchange()),
        store: createSqlExternalSendLandingStore(pool, null),
      });
      expect(unsigned.landed).toEqual([]);

      expect(await sendStatusOf(parked.operationId)).toBe("AWAITING_REDEMPTION");
      const noRecord = await pool.query(
        `SELECT 1 FROM external_send_landing_records WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noRecord.rowCount).toBe(0);
      const noSliceEvent = await pool.query(
        `SELECT 1 FROM external_send_landing_events WHERE operation_id = $1::uuid`,
        [parked.operationId],
      );
      expect(noSliceEvent.rowCount).toBe(0);
      const chains = await sendDualChainRows(parked.operationId);
      expect(chains.node).toEqual([]);
      expect(chains.implementer).toEqual([]);
      // The source lease is untouched by a refused landing (One-in-flight).
      expect(await leaseHeld(parked.walletId)).toBe(true);

      // The same row still lands normally once a signer is present.
      const retried = await tickSendCompletionLander(landerDeps(parked.nodeId, headExchange()));
      expect(retried.landed).toEqual([parked.operationId]);
      const after = await sendDualChainRows(parked.operationId);
      expect(after.node).toHaveLength(1);
      expect(after.implementer).toHaveLength(1);
    },
    PG_TEST_TIMEOUT_MS,
  );
});
