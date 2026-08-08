// Live ARM composition tests.
//
// Two layers:
//   1. no-PG composition census — the production factory binds the live arm engine and the
//      `operation_armed` route is not mapped to `failClosedReportingHandler` in source (AC1),
//      and the route refuses everything that is not a five-header signed reporting credential
//      (AC2: bare implementer bearer never reaches the handler).
//   2. real-PG offline e2e through `createProductionRouteSurface` — the SAME durable reporting
//      store mounted in production verifies the credential, the arm commits, and `receive_codes`
//      moves AWAITING_ARM → RELEASED (AC3), with the refusal paths proving no code escapes
// (AC4 t0 mismatch, AC5 recovery recheck, AC6 expected_row_version CAS).
//
// Evidence discipline: the plaintext transfer_code is asserted only against the value this test
// itself seeded; the emitted artifact carries operation id, states and transfer_code_sha256 —
// never the code bytes.

import { execFileSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  buildReportRequestPreimage,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_PURPOSE,
} from "@zucoins/generic-node-contracts";
import type { CapturedReportRequest } from "@zucoins/node-core";

import {
  createProductionRouteSurface,
  DurableReportingRequestStore,
  LIVE_ARM_ENGINE,
} from "../../src/full-http-mount.js";

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const stubPool = () =>
  ({
    query: async () => ({ rows: [] }),
    connect: async () => ({
      query: async () => ({ rows: [] }),
      release: () => {},
    }),
  }) as never;

const NODE_FOR_STUB = "11111111-1111-4111-8111-111111111111";

function armTarget(operationId: string): string {
  return `/v1/operations/${operationId}/armed`;
}

// ---------------------------------------------------------------------------
// AC1 / AC2 — composition census, no database required
// ---------------------------------------------------------------------------

describe("live ARM composition census (AC1, AC2)", () => {
  it("AC1: production source never maps operationArmed to failClosedReportingHandler", () => {
    const src = readFileSync(
      fileURLToPath(new URL("../../src/full-http-mount.ts", import.meta.url)),
      "utf8",
    );
    // The registry entry for operationArmed must bind the live handler, not `fail`.
    expect(src).toMatch(/\[REPORTING_ROUTE_IDS\.operationArmed\]:\s*liveArm/);
    expect(src).not.toMatch(/\[REPORTING_ROUTE_IDS\.operationArmed\]:\s*fail\b/);
    expect(src).toMatch(/createLiveArmRouteHandler/);
  });

  it("AC1: the surface reports operation_armed as a live reporting engine", () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    // F5: liveReportingEngines is derived from the mounted handlers map, not a bare constant.
    expect(surface.liveReportingEngines).toContain(LIVE_ARM_ENGINE);
    expect(surface.liveReportingEngines.map((e) => e.routeId)).toContain("operation_armed");
    expect(LIVE_ARM_ENGINE.routeId).toBe("operation_armed");
    // AC8 — the verifier this handler sits behind is the durable PG store.
    expect(surface.reportingStore).toBeInstanceOf(DurableReportingRequestStore);
  });

  it("AC2: no reporting headers → 401, handler never runs", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    const response = await surface.reportingHandle({
      method: "POST",
      rawTarget: armTarget(randomUUID()),
      rawHeaders: ["Idempotency-Key", "idempotency-key-0001"],
      bodyBytes: new TextEncoder().encode("{}"),
      receivedAtMs: Date.now(),
    });
    expect(response.status).toBe(401);
    expect(JSON.parse(new TextDecoder().decode(response.bodyBytes)).error.code).toBe(
      "missing_reporting_headers",
    );
  });

  it("AC2: bare implementer bearer is not a reporting credential → 401", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_FOR_STUB,
      pool: stubPool(),
      env: {},
    });
    const response = await surface.reportingHandle({
      method: "POST",
      rawTarget: armTarget(randomUUID()),
      rawHeaders: [
        "Authorization",
        "Bearer zp_live_implementer_key_that_is_not_a_reporting_credential",
        "Idempotency-Key",
        "idempotency-key-0001",
      ],
      bodyBytes: new TextEncoder().encode("{}"),
      receivedAtMs: Date.now(),
    });
    expect(response.status).toBe(401);
    expect(JSON.parse(new TextDecoder().decode(response.bodyBytes)).error.code).toBe(
      "missing_reporting_headers",
    );
  });
});

// ---------------------------------------------------------------------------
// Real-PG harness (same probe/bootstrap shape as production mount test)
// ---------------------------------------------------------------------------

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
      { stdio: "ignore", env: process.env, cwd: fileURLToPath(new URL("../..", import.meta.url)) },
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
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) throw new Error(`unsafe test db name: ${dbName}`);
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync(
      "createdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, dbName],
      { stdio: "ignore" },
    );
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
    execFileSync(
      "dropdb",
      ["-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER, "--if-exists", dbName],
      { stdio: "ignore" },
    );
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

// --- Ed25519 helpers (same idioms as the reporting module's own fixtures) ---

function keyFromSeed(byte: number): KeyObject {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_");

const pubOf = (privateKey: KeyObject): string =>
  paddedBase64Url(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32),
  );

const signPadded = (preimageText: string, privateKey: KeyObject): string =>
  paddedBase64Url(sign(null, Buffer.from(preimageText, "utf8"), privateKey));

describe.skipIf(!PG_AVAILABLE)("live ARM offline e2e (real PG)", () => {
  const scratchDb = `arm_live_composition_arm_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const IMPLEMENTER_ID = randomUUID();
  const KEY_ID = randomUUID();
  const NOW_MS = Date.parse("2026-07-29T12:00:00.000Z");
  const SEED_ISO = "2026-07-29T10:00:00.000Z";
  const EXPIRY_SECS = String(Math.floor(NOW_MS / 1000) + 3600);

  const signingKey = keyFromSeed(0x42);
  let pool: Pool;
  let surface: ReturnType<typeof createProductionRouteSurface>;

  beforeAll(async () => {
    await createTestDatabase(scratchDb);
    process.env.DATABASE_URL ??= pgDatabaseUrl(scratchDb);
    pool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: scratchDb,
      password: process.env.PGPASSWORD,
    });
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    await runMigrationsOnPool(pool);
    await seedOpenAdmission();
    surface = createProductionRouteSurface({
      nodeId: NODE_ID,
      pool,
      env: {},
      nowMs: () => NOW_MS,
    });
  }, 300_000);

  afterAll(async () => {
    await pool?.end();
    try {
      await dropTestDatabase(scratchDb);
    } catch {
      /* best effort */
    }
  });

  /** Minimal open-admission seed for reporting_lock_and_assert_admission (mirrors the production durable-store seed). */
  async function seedOpenAdmission(): Promise<void> {
    const nonceRegId = randomUUID();
    const bootstrapId = randomUUID();
    const enrolId = randomUUID();
    const pendingStateId = randomUUID();
    const activeStateId = randomUUID();
    const eventId = randomUUID();
    const preimage = "seed-register-preimage";
    const preSha = sha256Hex(preimage);
    const sig = `${"A".repeat(86)}==`;
    const eventHash = "11".repeat(32);
    const tExp = "2026-07-29T10:01:00.000Z";

    await pool.query("SET session_replication_role = replica");
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
      [NODE_ID, "arm-live-composition", `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`],
    );
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
      IMPLEMENTER_ID,
      "impl-927",
    ]);
    await pool.query(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ($1, $2, $3, $4, $5::timestamptz)`,
      [KEY_ID, NODE_ID, IMPLEMENTER_ID, pubOf(signingKey), SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_key_bootstrap_evidence (
         id, node_id, implementer_id, new_reporting_key_id,
         onboarding_actor_id, operator_approval_audit_id, approved_at, created_at
       ) VALUES ($1, $2, $3, $4, 'op', $5, $6::timestamptz, $6::timestamptz)`,
      [bootstrapId, NODE_ID, IMPLEMENTER_ID, KEY_ID, randomUUID(), SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence) VALUES ($1, 2)`,
      [NODE_ID],
    );
    await pool.query(
      `INSERT INTO reporting_request_nonces (
         id, node_id, implementer_id, nonce, purpose,
         route_id, request_class, reporting_key_id, new_reporting_key_id, bootstrap_evidence_id,
         lifecycle_epoch, nonce_burn_sequence,
         request_preimage_text, request_preimage_sha256, request_signature,
         method, raw_target, body_sha256,
         issued_at, expires_at, received_at, consumed_at, retention_class
       ) VALUES (
         $1, $2, $3, $4, 'zp-reporting-register-v1',
         NULL, NULL, NULL, $5, $6,
         1, 1,
         $7, $8, $9,
         NULL, NULL, NULL,
         $10::timestamptz, $11::timestamptz, $10::timestamptz, $10::timestamptz,
         'LIFECYCLE_PERMANENT'
       )`,
      [
        nonceRegId,
        NODE_ID,
        IMPLEMENTER_ID,
        randomUUID(),
        KEY_ID,
        bootstrapId,
        preimage,
        preSha,
        sig,
        SEED_ISO,
        tExp,
      ],
    );
    await pool.query(
      `INSERT INTO reporting_key_enrolment_evidence (
         id, node_id, implementer_id, new_reporting_key_id,
         supersedes_key_id, authorizing_key_id, bootstrap_evidence_id, nonce_evidence_id,
         proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
         proof_of_possession_signature,
         authorizing_preimage_text, authorizing_preimage_sha256, authorizing_signature,
         issued_at, expires_at, created_at
       ) VALUES (
         $1, $2, $3, $4, NULL, NULL, $5, $6,
         $7, $8, $9, NULL, NULL, NULL,
         $10::timestamptz, $11::timestamptz, $10::timestamptz
       )`,
      [
        enrolId,
        NODE_ID,
        IMPLEMENTER_ID,
        KEY_ID,
        bootstrapId,
        nonceRegId,
        preimage,
        preSha,
        sig,
        SEED_ISO,
        tExp,
      ],
    );
    await pool.query(
      `INSERT INTO reporting_key_lifecycle_states (
         id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
         state, lifecycle_event_id, state_changed_at
       ) VALUES ($1, $2, $3, $4, 0, 'PENDING', NULL, $5::timestamptz)`,
      [pendingStateId, KEY_ID, NODE_ID, IMPLEMENTER_ID, SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_key_lifecycle_events (
         id, node_id, implementer_id, epoch, event_type,
         current_key_id, prior_key_id, overlap_expires_at, auth_hold,
         successor_registered_at, nonce_evidence_id, nonce_purpose,
         enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
         previous_event_id, previous_epoch, previous_event_hash,
         event_hash, committed_at
       ) VALUES (
         $1, $2, $3, 1, 'FIRST_KEY_ACTIVATED',
         $4, NULL, NULL, false,
         $5::timestamptz, $6, 'zp-reporting-register-v1',
         $7, 'seed-first', $8,
         NULL, NULL, NULL,
         $9, $5::timestamptz
       )`,
      [
        eventId,
        NODE_ID,
        IMPLEMENTER_ID,
        KEY_ID,
        SEED_ISO,
        nonceRegId,
        enrolId,
        sha256Hex("seed-first"),
        eventHash,
      ],
    );
    await pool.query(
      `INSERT INTO reporting_key_lifecycle_states (
         id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
         state, lifecycle_event_id, state_changed_at
       ) VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, $6::timestamptz)`,
      [activeStateId, KEY_ID, NODE_ID, IMPLEMENTER_ID, eventId, SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_key_state_transitions (
         lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type,
         reporting_key_id, from_state_row_id, to_state_row_id,
         from_lifecycle_epoch, to_lifecycle_epoch, from_state, to_state, transitioned_at
       ) VALUES ($1, $2, $3, 1, 'FIRST_KEY_ACTIVATED', $4, $5, $6, 0, 1, 'PENDING', 'ACTIVE', $7::timestamptz)`,
      [eventId, NODE_ID, IMPLEMENTER_ID, KEY_ID, pendingStateId, activeStateId, SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_key_lifecycle_heads (
         node_id, implementer_id, epoch, current_key_id, prior_key_id,
         overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
       ) VALUES ($1, $2, 1, $3, NULL, NULL, false, $4, $5::timestamptz)`,
      [NODE_ID, IMPLEMENTER_ID, KEY_ID, eventId, SEED_ISO],
    );
    await pool.query(
      `INSERT INTO reporting_restore_state (
         node_id, restore_hold,
         local_lifecycle_epoch, local_nonce_burn_high_water, local_event_hash,
         trusted_lifecycle_epoch, trusted_nonce_burn_high_water, trusted_event_hash,
         trusted_source_id, trusted_source_observed_at,
         hold_release_evidence_sha256, hold_released_at, created_at, updated_at
       ) VALUES (
         $1, false, 1, 1, $2, 1, 1, $2,
         'file:/markers.json', $3::timestamptz, $4, $3::timestamptz, $3::timestamptz, $3::timestamptz
       )`,
      [NODE_ID, eventHash, SEED_ISO, "ab".repeat(32)],
    );
    await pool.query("SET session_replication_role = DEFAULT");
  }

  interface SeededReceive {
    readonly operationId: string;
    readonly walletId: string;
    readonly observationId: string;
    readonly transferCode: string;
    readonly transferCodeSha256: string;
  }

  /** A READY RECEIVE_EXTERNAL with a withheld (AWAITING_ARM) code and a durable node T0. */
  async function seedReadyReceive(): Promise<SeededReceive> {
    const operationId = randomUUID();
    const walletId = randomUUID();
    const observationId = randomUUID();
    const artifactId = randomUUID();
    const signingKeyId = randomUUID();
    const walletPublicKey = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    // Random seed — never `zp-transfer-code-<operation_id>` so transfer_code_sha256 in
    // evidence artifacts is not re-derivable from the published operation_id (adversarial probe 4).
    const transferCode = `zp-tc-${randomUUID().replace(/-/g, "")}`;
    const transferCodeSha256 = sha256Hex(transferCode);

    await pool.query("SET session_replication_role = replica");
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state,
                            recovery_verified_at, recovery_verification_id)
       VALUES ($1, $2, $3, 'node_generated', 'PINNED', $4::timestamptz, $5)`,
      [walletId, NODE_ID, walletPublicKey, SEED_ISO, randomUUID()],
    );
    // Node-owned durable RECEIVER_T0. VERIFIED_GENESIS pins the projection to ("", "", "0").
    await pool.query(
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount
       ) VALUES (
         $1, $2, $3, $4, $5, 1,
         $6::timestamptz, 200, $7::bytea, $8,
         'VERIFIED_GENESIS', 'FIRST', $9, false,
         'genesis', '', '', '0'
       )`,
      [
        observationId,
        randomUUID(),
        "cd".repeat(32),
        walletId,
        walletPublicKey,
        SEED_ISO,
        Buffer.from("{}", "utf8"),
        sha256Hex("{}"),
        "ef".repeat(32),
      ],
    );
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, row_version, amount_zkz,
         receiver_wallet_id, after_landing, discriminator, anchor,
         idempotency_key, request_sha256, expiry_unix_time_secs, t0_observation_id
       ) VALUES (
         $1, $2, $3, 'RECEIVE_EXTERNAL', 'READY', 2, '5.5',
         $4, 'HOLD', $1, 'anchor-arm-live-composition',
         $5, $6, $7, $8
       )`,
      [
        operationId,
        NODE_ID,
        IMPLEMENTER_ID,
        walletId,
        `op-idempotency-${operationId}`,
        sha256Hex(operationId),
        EXPIRY_SECS,
        observationId,
      ],
    );
    await pool.query(
      `INSERT INTO operation_expected_artifacts (
         id, operation_id, purpose, canonical_version, signing_key_id,
         preimage_text, preimage_sha256, signature
       ) VALUES ($1, $2, 'zp-receive-expected-v1', 1, $3, $4, $5, $6)`,
      [
        artifactId,
        operationId,
        signingKeyId,
        "expected-artifact-preimage",
        sha256Hex("expected-artifact-preimage"),
        `${"A".repeat(86)}==`,
      ],
    );
    await pool.query(
      `INSERT INTO receive_codes (
         operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
         discriminator, anchor, expiry_unix_time_secs,
         transfer_code_text, transfer_code_sha256, code_status, ready_at
       ) VALUES ($1, $2, $3, $4, $1, 'anchor-arm-live-composition', $5, $6, $7, 'AWAITING_ARM', $8::timestamptz)`,
      [
        operationId,
        walletId,
        observationId,
        artifactId,
        EXPIRY_SECS,
        transferCode,
        transferCodeSha256,
        SEED_ISO,
      ],
    );
    await pool.query("SET session_replication_role = DEFAULT");
    return { operationId, walletId, observationId, transferCode, transferCodeSha256 };
  }

  function armBody(input: {
    readonly observationId: string;
    readonly expectedRowVersion: number;
    readonly projection?: { s: string; p: string; b_zkz: string };
    readonly openedCursor?: string;
  }): string {
    return JSON.stringify({
      expected_row_version: input.expectedRowVersion,
      t0: {
        observation_id: input.observationId,
        projection: input.projection ?? { s: "", p: "", b_zkz: "0" },
      },
      opened_cursor: input.openedCursor ?? "1043",
    });
  }

  /** Assemble a genuine `zp-report-request-v1` POST .../armed request. */
  function signedArmRequest(input: {
    readonly operationId: string;
    readonly body: string;
    readonly signWith?: KeyObject;
    /** Pin the (unsigned) Idempotency-Key; default is a fresh key per request. */
    readonly idempotencyKey?: string;
  }): CapturedReportRequest {
    const target = armTarget(input.operationId);
    const issuedAt = new Date(NOW_MS - 1_000).toISOString();
    const expiresAt = new Date(NOW_MS + 30_000).toISOString();
    const nonce = randomUUID();
    const preimage = buildReportRequestPreimage({
      purpose: REPORT_REQUEST_PURPOSE,
      canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
      node_id: NODE_ID,
      implementer_id: IMPLEMENTER_ID,
      method: "POST",
      path: target,
      body_sha256: sha256Hex(input.body),
      nonce,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });
    return {
      method: "POST",
      rawTarget: target,
      rawHeaders: [
        "X-ZP-Reporting-Key-Id",
        KEY_ID,
        "X-ZP-Reporting-Timestamp",
        issuedAt,
        "X-ZP-Reporting-Expires-At",
        expiresAt,
        "X-ZP-Reporting-Nonce",
        nonce,
        "X-ZP-Reporting-Signature",
        signPadded(preimage, input.signWith ?? signingKey),
        "Idempotency-Key",
        input.idempotencyKey ?? `idem-${nonce}`,
      ],
      bodyBytes: new TextEncoder().encode(input.body),
      receivedAtMs: NOW_MS,
    };
  }

  const codeStatusOf = async (operationId: string): Promise<string> =>
    (
      await pool.query<{ code_status: string }>(
        `SELECT code_status FROM receive_codes WHERE operation_id = $1`,
        [operationId],
      )
    ).rows[0]!.code_status;

  it("AC7: a bad signature is refused before the arm engine runs", async () => {
    const seeded = await seedReadyReceive();
    const response = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({ observationId: seeded.observationId, expectedRowVersion: 2 }),
        signWith: keyFromSeed(0x7f),
      }),
    );
    expect(response.status).toBe(401);
    // invalid_signature is a credential-state rejection, so the wire carries only the collapsed
    // non-oracular code; the refusal itself is asserted on the server-side record and on the
    // untouched code_status below.
    expect(JSON.parse(new TextDecoder().decode(response.bodyBytes)).error.code).toBe(
      "invalid_api_key",
    );
    expect(response.collapsedRejection?.code).toBe("invalid_signature");
    expect(await codeStatusOf(seeded.operationId)).toBe("AWAITING_ARM");
  }, 60_000);

  it("AC4: mismatched t0 projection → 409 t0_mismatch and no code release", async () => {
    const seeded = await seedReadyReceive();
    const response = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({
          observationId: seeded.observationId,
          expectedRowVersion: 2,
          projection: { s: "", p: "", b_zkz: "9" },
        }),
      }),
    );
    expect(response.status).toBe(409);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes));
    expect(body.error.code).toBe("t0_mismatch");
    expect(JSON.stringify(body)).not.toContain(seeded.transferCode);
    expect(await codeStatusOf(seeded.operationId)).toBe("AWAITING_ARM");
    expect(
      (
        await pool.query(`SELECT 1 FROM receive_arms WHERE operation_id = $1`, [
          seeded.operationId,
        ])
      ).rowCount,
    ).toBe(0);
  }, 60_000);

  it("AC6: expected_row_version CAS miss fails closed without releasing code", async () => {
    const seeded = await seedReadyReceive();
    const response = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({ observationId: seeded.observationId, expectedRowVersion: 99 }),
      }),
    );
    expect(response.status).toBe(409);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes));
    expect(body.error.code).toBe("operation_version_conflict");
    expect(JSON.stringify(body)).not.toContain(seeded.transferCode);
    expect(await codeStatusOf(seeded.operationId)).toBe("AWAITING_ARM");
    expect(
      (
        await pool.query<{ row_version: string }>(
          `SELECT row_version FROM operations WHERE id = $1`,
          [seeded.operationId],
        )
      ).rows[0]!.row_version,
    ).toBe("2");
  }, 60_000);

  it("AC5: recovery-unverified receiver refuses closed and flags attention", async () => {
    const seeded = await seedReadyReceive();
    // `recovery_verified_at` is monotonic and never cleared — the
    // live risk this recheck closes is an INTERVENING QUARANTINE between lease and arm.
    await pool.query(
      `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'arm-live-composition intervening quarantine'
       WHERE id = $1`,
      [seeded.walletId],
    );
    const response = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({ observationId: seeded.observationId, expectedRowVersion: 2 }),
      }),
    );
    expect(response.status).toBe(409);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes));
    expect(body.error.code).toBe("operation_not_armable");
    expect(JSON.stringify(body)).not.toContain(seeded.transferCode);
    expect(await codeStatusOf(seeded.operationId)).toBe("AWAITING_ARM");
    const attention = await pool.query<{
      attention_required: boolean;
      attention_reason: string | null;
    }>(`SELECT attention_required, attention_reason FROM operations WHERE id = $1`, [
      seeded.operationId,
    ]);
    expect(attention.rows[0]!.attention_required).toBe(true);
    expect(attention.rows[0]!.attention_reason).toBe("LEASE_INVARIANT_VIOLATION");
  }, 60_000);

  it("READY + AWAITING_ARM + matching t0 → arm success body and durable RELEASED", async () => {
    const seeded = await seedReadyReceive();
    const captured = signedArmRequest({
      operationId: seeded.operationId,
      body: armBody({ observationId: seeded.observationId, expectedRowVersion: 2 }),
    });
    const response = await surface.reportingHandle(captured);
    expect(response.status).toBe(200);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes));

    // Arm success body, exact field set and sequence.
    expect(Object.keys(body)).toEqual([
      "operation_id",
      "state",
      "row_version",
      "code_status",
      "transfer_code",
      "transfer_code_sha256",
      "expires_at",
    ]);
    expect(body.operation_id).toBe(seeded.operationId);
    expect(body.state).toBe("READY");
    expect(body.code_status).toBe("RELEASED");
    expect(body.row_version).toBe(3);
    expect(body.transfer_code).toBe(seeded.transferCode);
    expect(body.transfer_code_sha256).toBe(seeded.transferCodeSha256);

    // Durable effects: released code, arm acknowledgement, committed idempotency parent.
    const code = await pool.query<{ code_status: string; released_at: string | null }>(
      `SELECT code_status, released_at::text AS released_at FROM receive_codes WHERE operation_id = $1`,
      [seeded.operationId],
    );
    expect(code.rows[0]!.code_status).toBe("RELEASED");
    expect(code.rows[0]!.released_at).not.toBeNull();

    const arm = await pool.query<{
      node_t0_observation_id: string;
      acknowledged_b: string;
      opened_cursor: string;
      mutation_idempotency_id: string;
    }>(
      `SELECT node_t0_observation_id::text AS node_t0_observation_id, acknowledged_b,
              opened_cursor::text AS opened_cursor, mutation_idempotency_id::text AS mutation_idempotency_id
         FROM receive_arms WHERE operation_id = $1`,
      [seeded.operationId],
    );
    expect(arm.rowCount).toBe(1);
    expect(arm.rows[0]!.node_t0_observation_id).toBe(seeded.observationId);
    expect(arm.rows[0]!.opened_cursor).toBe("1043");

    const completed = await pool.query<{ response_status: number; response_bytes: Buffer }>(
      `SELECT response_status, response_bytes FROM reporting_mutation_idempotency WHERE id = $1`,
      [arm.rows[0]!.mutation_idempotency_id],
    );
    expect(completed.rowCount).toBe(1);
    expect(completed.rows[0]!.response_status).toBe(200);
    // The frozen bytes ARE the served bytes (one serialization, Byte-exact).
    expect(completed.rows[0]!.response_bytes.toString("utf8")).toBe(
      new TextDecoder().decode(response.bodyBytes),
    );

    const operation = await pool.query<{ status: string; row_version: number }>(
      `SELECT status::text AS status, row_version FROM operations WHERE id = $1`,
      [seeded.operationId],
    );
    expect(operation.rows[0]!.status).toBe("READY");
    expect(Number(operation.rows[0]!.row_version)).toBe(3);

    // Evidence artifact — sha256 only, never the plaintext code (GR "no code in logs").
    const artifact = {
      ticket: "live ARM composition",
      route: "POST /v1/operations/:operation_id/armed",
      operation_id: seeded.operationId,
      node_id: NODE_ID,
      implementer_id: IMPLEMENTER_ID,
      before: { operation_state: "READY", code_status: "AWAITING_ARM", row_version: 2 },
      after: {
        operation_state: operation.rows[0]!.status,
        code_status: code.rows[0]!.code_status,
        row_version: Number(operation.rows[0]!.row_version),
      },
      response_status: response.status,
      transfer_code_sha256: body.transfer_code_sha256,
      // Plaintext is absent. sha256 is of a random test seed (not operation_id-derivable).
      transfer_code_present_in_artifact: false,
      transfer_code_sha256_of_random_seed: true,
      receive_arms_rows: arm.rowCount,
      reporting_mutation_idempotency_id: arm.rows[0]!.mutation_idempotency_id,
    };
    const outDir = fileURLToPath(new URL("../.artifacts/", import.meta.url));
    mkdirSync(outDir, { recursive: true });
    writeFileSync(
      `${outDir}fixture-live-arm-evidence.json`,
      `${JSON.stringify(artifact, null, 2)}\n`,
      "utf8",
    );
    expect(JSON.stringify(artifact)).not.toContain(seeded.transferCode);
  }, 120_000);

  // -------------------------------------------------------------------------
  // Guarded uniqueness on re-arm, and the
  // connection discipline every refusal path depends on.
  // -------------------------------------------------------------------------

  const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
  const errorCodeOf = (bytes: Uint8Array): string => JSON.parse(decode(bytes)).error.code;

  /** Completion parents for one operation — `raw_target` is the arm route for that id. */
  const completionRowsFor = async (operationId: string): Promise<number> =>
    (
      await pool.query(`SELECT 1 FROM reporting_mutation_idempotency WHERE raw_target = $1`, [
        armTarget(operationId),
      ])
    ).rowCount ?? 0;

  const armRowsFor = async (operationId: string): Promise<number> =>
    (await pool.query(`SELECT 1 FROM receive_arms WHERE operation_id = $1`, [operationId]))
      .rowCount ?? 0;

  const armOnce = (seeded: SeededReceive, idempotencyKey?: string) =>
    surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({ observationId: seeded.observationId, expectedRowVersion: 2 }),
        idempotencyKey,
      }),
    );

  it("arm contract: the same Idempotency-Key replays the frozen bytes, byte-identical", async () => {
    const seeded = await seedReadyReceive();
    const key = `idem-fixed-${seeded.operationId}`;
    const first = await armOnce(seeded, key);
    expect(first.status).toBe(200);

    // Fresh nonce (nonces are single-burn), same unsigned key, same body.
    const replay = await armOnce(seeded, key);
    expect(replay.status).toBe(200);
    expect(replay.headers["idempotency-replayed"]).toBe("true");
    expect(decode(replay.bodyBytes)).toBe(decode(first.bodyBytes));
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
  }, 60_000);

  it("arm contract: a different Idempotency-Key on an armed operation → 409 idempotency_conflict", async () => {
    const seeded = await seedReadyReceive();
    expect((await armOnce(seeded)).status).toBe(200);

    // Identical signed inputs, fresh unsigned Idempotency-Key: the guarded fingerprint index
    // decides, so this is a conflict rather than a second 200 carrying the plaintext code.
    const retry = await armOnce(seeded);
    expect(retry.status).toBe(409);
    expect(errorCodeOf(retry.bodyBytes)).toBe("idempotency_conflict");
    expect(retry.headers["idempotency-replayed"]).toBeUndefined();
    expect(decode(retry.bodyBytes)).not.toContain(seeded.transferCode);
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
    expect(await armRowsFor(seeded.operationId)).toBe(1);

    // A fresh key carrying a DIFFERENT signed body is refused too. This is the case a
    // guarded-fingerprint-index-only gate would miss: `body_sha256` differs, so no unique
    // index would have collided.
    const drifted = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody({
          observationId: seeded.observationId,
          expectedRowVersion: 3,
          openedCursor: "9999",
        }),
      }),
    );
    expect(drifted.status).toBe(409);
    expect(errorCodeOf(drifted.bodyBytes)).toBe("idempotency_conflict");
    expect(decode(drifted.bodyBytes)).not.toContain(seeded.transferCode);
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
  }, 60_000);

  it("arm contract: concurrent arms release one code; the loser conflicts", async () => {
    const seeded = await seedReadyReceive();
    const body = armBody({ observationId: seeded.observationId, expectedRowVersion: 2 });
    const [a, b] = await Promise.all([
      surface.reportingHandle(signedArmRequest({ operationId: seeded.operationId, body })),
      surface.reportingHandle(signedArmRequest({ operationId: seeded.operationId, body })),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    const winner = a.status === 200 ? a : b;
    const loser = a.status === 200 ? b : a;
    expect(JSON.parse(decode(winner.bodyBytes)).transfer_code).toBe(seeded.transferCode);
    expect(errorCodeOf(loser.bodyBytes)).toBe("idempotency_conflict");
    expect(decode(loser.bodyBytes)).not.toContain(seeded.transferCode);

    expect(await codeStatusOf(seeded.operationId)).toBe("RELEASED");
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
    expect(await armRowsFor(seeded.operationId)).toBe(1);
    expect(
      (
        await pool.query<{ row_version: string }>(
          `SELECT row_version FROM operations WHERE id = $1`,
          [seeded.operationId],
        )
      ).rows[0]!.row_version,
    ).toBe("3");
  }, 120_000);

  // -------------------------------------------------------------------------
  // Adversarial probe 1 — same-key concurrent probes the attack lane ran by hand.
  // -------------------------------------------------------------------------

  it("arm same-key concurrent: [200,200] byte-identical with one completion row", async () => {
    const seeded = await seedReadyReceive();
    const body = armBody({ observationId: seeded.observationId, expectedRowVersion: 2 });
    const key = `idem-same-concurrent-${seeded.operationId}`;
    const [a, b] = await Promise.all([
      surface.reportingHandle(
        signedArmRequest({ operationId: seeded.operationId, body, idempotencyKey: key }),
      ),
      surface.reportingHandle(
        signedArmRequest({ operationId: seeded.operationId, body, idempotencyKey: key }),
      ),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 200]);
    expect(decode(a.bodyBytes)).toBe(decode(b.bodyBytes));
    expect(JSON.parse(decode(a.bodyBytes)).transfer_code).toBe(seeded.transferCode);
    // At least one response is the frozen replay (header); both bodies match first-write.
    const replayed = [a, b].filter((r) => r.headers["idempotency-replayed"] === "true");
    expect(replayed.length).toBeGreaterThanOrEqual(1);
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
    expect(await armRowsFor(seeded.operationId)).toBe(1);
  }, 120_000);

  it("arm same-key different body concurrent/serial: [200,409] never re-serves code", async () => {
    const seeded = await seedReadyReceive();
    const key = `idem-diff-body-${seeded.operationId}`;
    const bodyA = armBody({
      observationId: seeded.observationId,
      expectedRowVersion: 2,
      openedCursor: "1043",
    });
    const bodyB = armBody({
      observationId: seeded.observationId,
      expectedRowVersion: 2,
      openedCursor: "9999",
    });
    // Concurrent same key + different signed body: one of the install races wins writeSlot;
    // the other collides on fingerprint at resolveCompleted or already_armed gate.
    const [a, b] = await Promise.all([
      surface.reportingHandle(
        signedArmRequest({ operationId: seeded.operationId, body: bodyA, idempotencyKey: key }),
      ),
      surface.reportingHandle(
        signedArmRequest({ operationId: seeded.operationId, body: bodyB, idempotencyKey: key }),
      ),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 409]);
    const winner = a.status === 200 ? a : b;
    const loser = a.status === 200 ? b : a;
    expect(JSON.parse(decode(winner.bodyBytes)).transfer_code).toBe(seeded.transferCode);
    expect(errorCodeOf(loser.bodyBytes)).toBe("idempotency_conflict");
    expect(decode(loser.bodyBytes)).not.toContain(seeded.transferCode);
    expect(await completionRowsFor(seeded.operationId)).toBe(1);
    expect(await armRowsFor(seeded.operationId)).toBe(1);
  }, 120_000);

  it("arm same Idempotency-Key across two ops: one completes, the other 409s", async () => {
    const a = await seedReadyReceive();
    const b = await seedReadyReceive();
    const sharedKey = `idem-cross-ops-${a.operationId}`;
    const bodyA = armBody({ observationId: a.observationId, expectedRowVersion: 2 });
    const bodyB = armBody({ observationId: b.observationId, expectedRowVersion: 2 });
    const [ra, rb] = await Promise.all([
      surface.reportingHandle(
        signedArmRequest({ operationId: a.operationId, body: bodyA, idempotencyKey: sharedKey }),
      ),
      surface.reportingHandle(
        signedArmRequest({ operationId: b.operationId, body: bodyB, idempotencyKey: sharedKey }),
      ),
    ]);
    const statuses = [ra.status, rb.status].sort();
    expect(statuses).toEqual([200, 409]);
    const winner = ra.status === 200 ? ra : rb;
    const loser = ra.status === 200 ? rb : ra;
    const winnerSeed = ra.status === 200 ? a : b;
    const loserSeed = ra.status === 200 ? b : a;
    expect(JSON.parse(decode(winner.bodyBytes)).transfer_code).toBe(winnerSeed.transferCode);
    expect(errorCodeOf(loser.bodyBytes)).toBe("idempotency_conflict");
    expect(decode(loser.bodyBytes)).not.toContain(loserSeed.transferCode);
    // Winner armed; loser left AWAITING_ARM (unique/fingerprint refuse rolled back).
    expect(await codeStatusOf(winnerSeed.operationId)).toBe("RELEASED");
    expect(await codeStatusOf(loserSeed.operationId)).toBe("AWAITING_ARM");
    expect(await armRowsFor(winnerSeed.operationId)).toBe(1);
    expect(await armRowsFor(loserSeed.operationId)).toBe(0);
  }, 120_000);

  it("arm contract: an armed operation that has left READY is not a transfer_code oracle", async () => {
    const seeded = await seedReadyReceive();
    expect((await armOnce(seeded)).status).toBe(200);
    await pool.query("SET session_replication_role = replica");
    await pool.query(`UPDATE operations SET status = 'RECEIVE_LANDED' WHERE id = $1`, [
      seeded.operationId,
    ]);
    await pool.query("SET session_replication_role = DEFAULT");

    const afterLanding = await armOnce(seeded);
    expect(afterLanding.status).toBe(409);
    expect(errorCodeOf(afterLanding.bodyBytes)).toBe("idempotency_conflict");
    expect(decode(afterLanding.bodyBytes)).not.toContain(seeded.transferCode);
  }, 60_000);

  it("the refusal path never acquires a second client while the wallet lock is held", async () => {
    // A pool of exactly one client is the smallest instance of the production hazard: the
    // wallet-lock TX pins the only client, so any pool.query issued under that lock
    // (markAttention on the recovery-unverified refusal; findByOperation / loadReleasedCode on the lost-race
    // paths) waits for a client that can never be returned. `connectionTimeoutMillis` turns
    // the wedge into a bounded failure so this is an assertion rather than a hang.
    const pinnedPool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: scratchDb,
      password: process.env.PGPASSWORD,
      max: 1,
      connectionTimeoutMillis: 2_000,
    });
    try {
      const pinnedSurface = createProductionRouteSurface({
        nodeId: NODE_ID,
        pool: pinnedPool,
        env: {},
        nowMs: () => NOW_MS,
      });
      const seeded = await seedReadyReceive();
      await pool.query(
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'arm-live-composition pool discipline'
         WHERE id = $1`,
        [seeded.walletId],
      );
      const response = await pinnedSurface.reportingHandle(
        signedArmRequest({
          operationId: seeded.operationId,
          body: armBody({ observationId: seeded.observationId, expectedRowVersion: 2 }),
        }),
      );
      // Nested pool acquisition would surface as 500 internal_error (connect timeout).
      expect(response.status).toBe(409);
      expect(errorCodeOf(response.bodyBytes)).toBe("operation_not_armable");
      expect(await codeStatusOf(seeded.operationId)).toBe("AWAITING_ARM");
      expect(
        (
          await pool.query<{ attention_required: boolean }>(
            `SELECT attention_required FROM operations WHERE id = $1`,
            [seeded.operationId],
          )
        ).rows[0]!.attention_required,
      ).toBe(true);
    } finally {
      await pinnedPool.end();
    }
  }, 120_000);
});
