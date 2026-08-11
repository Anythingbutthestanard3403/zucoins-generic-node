// Genesis reporting-key enrolment → READY→ARM→RELEASED offline E2E.
// Competing rotation / admission-vs-revocation race (DB-TEST-23) lives in
// packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts.
//
// AC:
//  1. enrolBootstrapReportingKey produces ACTIVE lifecycle + open restore without replica.
//  2. createProductionRouteSurface ARM with five reporting headers RELEASES code.
//  3. Evidence/logs assertion surface: transfer_code_sha256 only (never private seed or full code).


import { execFileSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  buildReportRequestPreimage,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_PURPOSE,
} from "@zucoins/generic-node-contracts";
import { toBase64UrlPadded, type CapturedReportRequest } from "@zucoins/node-core";

import { enrolBootstrapReportingKey } from "../../src/bootstrap/reporting-key-enrol.js";
import { createProductionRouteSurface } from "../../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

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

function privateKeyFromSeedHex(seedHex: string): KeyObject {
  const seed = Buffer.from(seedHex, "hex");
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

const signPadded = (preimageText: string, privateKey: KeyObject): string =>
  toBase64UrlPadded(sign(null, Buffer.from(preimageText, "utf8"), privateKey));

const pubOf = (privateKey: KeyObject): string =>
  toBase64UrlPadded(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32),
  );

describe.skipIf(!PG_AVAILABLE)("reporting-key enrol → ARM RELEASED offline e2e", () => {
  const scratchDb = `enrol_enrol_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const IMPLEMENTER_ID = randomUUID();
  const NOW_MS = Date.parse("2026-07-30T12:00:00.000Z");
  const SEED_ISO = "2026-07-30T10:00:00.000Z";
  const EXPIRY_SECS = String(Math.floor(NOW_MS / 1000) + 3600);
  const tmpDir = mkdtempSync(join(tmpdir(), "enrol-"));
  const keyOut = join(tmpDir, "reporting-key.json");
  const seedBytes = Buffer.alloc(32, 0x48);

  let pool: Pool;
  let surface: ReturnType<typeof createProductionRouteSurface>;
  let keyId = "";
  let signingKey: KeyObject;
  const logs: string[] = [];

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

    const identityPk = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
      [NODE_ID, "enrol", identityPk],
    );
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
      IMPLEMENTER_ID,
      "impl-948",
    ]);

    const logger = {
      info: (m: string) => {
        logs.push(m);
      },
      error: (m: string) => {
        logs.push(m);
      },
    };
    const outcome = await enrolBootstrapReportingKey(
      pool,
      {
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        reportingKeyOut: keyOut,
        seed: seedBytes,
        nowMs: () => NOW_MS - 60_000,
      },
      logger,
    );
    expect(outcome.enrolled).toBe(true);
    if (!outcome.enrolled) throw new Error("enrol failed");
    keyId = outcome.keyId;

    const file = JSON.parse(readFileSync(keyOut, "utf8")) as {
      format: string;
      reporting_key_id: string;
      public_key: string;
      seed_hex: string;
    };
    expect(file.format).toBe("zp-reporting-key-v1");
    expect(file.reporting_key_id).toBe(keyId);
    expect(file.seed_hex).toBe(seedBytes.toString("hex"));
    signingKey = privateKeyFromSeedHex(file.seed_hex);
    expect(pubOf(signingKey)).toBe(file.public_key);
    expect(outcome.publicKey).toBe(file.public_key);

    // Idempotent second call
    const again = await enrolBootstrapReportingKey(
      pool,
      {
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        reportingKeyOut: keyOut,
        seed: seedBytes,
      },
      logger,
    );
    expect(again.enrolled).toBe(false);
    if (again.enrolled) throw new Error("expected already_active");
    expect(again.reason).toBe("already_active");

    // Never log private seed or full seed hex.
    const joined = logs.join("\n");
    expect(joined).not.toContain(seedBytes.toString("hex"));
    expect(joined).not.toMatch(/seed_hex/i);
    expect(joined).toContain(keyId);
    expect(joined).toContain(outcome.publicKey);

    surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
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
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  function armTarget(operationId: string): string {
    return `/v1/operations/${operationId}/armed`;
  }

  async function seedReadyReceive(): Promise<{
    readonly operationId: string;
    readonly observationId: string;
    readonly transferCode: string;
    readonly transferCodeSha256: string;
  }> {
    const operationId = randomUUID();
    const walletId = randomUUID();
    const observationId = randomUUID();
    const artifactId = randomUUID();
    const signingKeyId = randomUUID();
    const walletPublicKey = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    const transferCode = `zp-tc-${randomUUID().replace(/-/g, "")}`;
    const transferCodeSha256 = sha256Hex(transferCode);

    await pool.query("SET session_replication_role = replica");
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state,
                            recovery_verified_at, recovery_verification_id)
       VALUES ($1, $2, $3, 'node_generated', 'PINNED', $4::timestamptz, $5)`,
      [walletId, NODE_ID, walletPublicKey, SEED_ISO, randomUUID()],
    );
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
         $1, $2, $3, 'RECEIVE_EXTERNAL', 'READY', 2, '0.01',
         $4, 'HOLD', $1, 'anchor-enrol',
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
       ) VALUES ($1, $2, $3, $4, $1, 'anchor-enrol', $5, $6, $7, 'AWAITING_ARM', $8::timestamptz)`,
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
    return { operationId, observationId, transferCode, transferCodeSha256 };
  }

  function armBody(observationId: string): string {
    return JSON.stringify({
      expected_row_version: 2,
      t0: {
        observation_id: observationId,
        projection: { s: "", p: "", b_zkz: "0" },
      },
      opened_cursor: "1043",
    });
  }

  function signedArmRequest(input: {
    readonly operationId: string;
    readonly body: string;
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
        keyId,
        "X-ZP-Reporting-Timestamp",
        issuedAt,
        "X-ZP-Reporting-Expires-At",
        expiresAt,
        "X-ZP-Reporting-Nonce",
        nonce,
        "X-ZP-Reporting-Signature",
        signPadded(preimage, signingKey),
        "Idempotency-Key",
        `idem-${nonce}`,
      ],
      bodyBytes: new TextEncoder().encode(input.body),
      receivedAtMs: NOW_MS,
    };
  }

  it("lifecycle head is ACTIVE after genesis enrol (no session_replication_role)", async () => {
    const head = await pool.query<{
      epoch: string;
      current_key_id: string;
      auth_hold: boolean;
    }>(
      `SELECT epoch::text, current_key_id::text, auth_hold
         FROM reporting_key_lifecycle_heads
        WHERE node_id = $1 AND implementer_id = $2`,
      [NODE_ID, IMPLEMENTER_ID],
    );
    expect(head.rows[0]?.epoch).toBe("1");
    expect(head.rows[0]?.current_key_id).toBe(keyId);
    expect(head.rows[0]?.auth_hold).toBe(false);
    const state = await pool.query<{ state: string }>(
      `SELECT state::text AS state FROM reporting_key_lifecycle_states
        WHERE reporting_key_id = $1 AND lifecycle_epoch = 1`,
      [keyId],
    );
    expect(state.rows[0]?.state).toBe("ACTIVE");
  });

  it("READY + AWAITING_ARM → five-header ARM → RELEASED (sha only in evidence)", async () => {
    const seeded = await seedReadyReceive();
    expect(
      (
        await pool.query<{ code_status: string }>(
          `SELECT code_status FROM receive_codes WHERE operation_id = $1`,
          [seeded.operationId],
        )
      ).rows[0]!.code_status,
    ).toBe("AWAITING_ARM");

    const response = await surface.reportingHandle(
      signedArmRequest({
        operationId: seeded.operationId,
        body: armBody(seeded.observationId),
      }),
    );
    expect(response.status).toBe(200);
    const body = JSON.parse(new TextDecoder().decode(response.bodyBytes)) as {
      code_status: string;
      transfer_code: string;
      transfer_code_sha256: string;
      operation_id: string;
    };
    expect(body.code_status).toBe("RELEASED");
    expect(body.transfer_code_sha256).toBe(seeded.transferCodeSha256);
    expect(body.transfer_code).toBe(seeded.transferCode);
    expect(body.operation_id).toBe(seeded.operationId);

    const durable = await pool.query<{ code_status: string }>(
      `SELECT code_status FROM receive_codes WHERE operation_id = $1`,
      [seeded.operationId],
    );
    expect(durable.rows[0]!.code_status).toBe("RELEASED");

    // Evidence artifact: sha only — never embed private seed or claim full code as proof trail.
    const evidence = {
      ticket: "reporting-key-enrol",
      operation_id: seeded.operationId,
      before: { code_status: "AWAITING_ARM" },
      after: { code_status: "RELEASED" },
      transfer_code_sha256: body.transfer_code_sha256,
      reporting_key_id: keyId,
    };
    expect(JSON.stringify(evidence)).not.toContain(seedBytes.toString("hex"));
    expect(JSON.stringify(evidence)).not.toContain(seeded.transferCode);
    expect(evidence.transfer_code_sha256).toHaveLength(64);
    expect(sha256Hex(seeded.transferCode)).toBe(evidence.transfer_code_sha256);
  }, 60_000);
});

describe.skipIf(!PG_AVAILABLE)("FAIL-fix: OUT-before-COMMIT + restore_hold hold", () => {
  const scratchDb = `enrol_fix_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const IMPLEMENTER_ID = randomUUID();
  const NOW_MS = Date.parse("2026-07-30T13:00:00.000Z");
  const SEED_ISO = "2026-07-30T11:00:00.000Z";
  const EXPIRY_SECS = String(Math.floor(NOW_MS / 1000) + 3600);
  const tmpDir = mkdtempSync(join(tmpdir(), "enrol-fix-"));
  const seedBytes = Buffer.alloc(32, 0x49);

  let pool: Pool;
  const quiet = {
    info: (_m: string) => {},
    error: (_m: string) => {},
  };

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

    const identityPk = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
      [NODE_ID, "enrol-fix", identityPk],
    );
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
      IMPLEMENTER_ID,
      "impl-948-fix",
    ]);
  }, 300_000);

  afterAll(async () => {
    await pool?.end();
    try {
      await dropTestDatabase(scratchDb);
    } catch {
      /* best effort */
    }
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  async function wipeLifecycle(): Promise<void> {
    await pool.query("SET session_replication_role = replica");
    await pool.query(`DELETE FROM reporting_key_state_transitions WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_key_lifecycle_events WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_key_lifecycle_states WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_key_lifecycle_heads WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_key_enrolment_evidence WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_key_bootstrap_evidence WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM reporting_request_nonces WHERE node_id = $1`, [NODE_ID]);
    await pool.query(`DELETE FROM implementer_reporting_keys WHERE node_id = $1`, [NODE_ID]);
    await pool.query("SET session_replication_role = DEFAULT");
  }

  it("OUT write fail before COMMIT rolls back — no ACTIVE, retry succeeds", async () => {
    await wipeLifecycle();
    const keyOut = join(tmpDir, "out-fail-inject.json");
    await expect(
      enrolBootstrapReportingKey(
        pool,
        {
          nodeId: NODE_ID,
          implementerId: IMPLEMENTER_ID,
          reportingKeyOut: keyOut,
          seed: seedBytes,
          nowMs: () => NOW_MS - 120_000,
          writePrivateOut: async () => {
            throw new Error("injected OUT write failure");
          },
        },
        quiet,
      ),
    ).rejects.toThrow(/injected OUT write failure/);

    const head = await pool.query<{ current_key_id: string | null }>(
      `SELECT current_key_id::text AS current_key_id
         FROM reporting_key_lifecycle_heads
        WHERE node_id = $1 AND implementer_id = $2`,
      [NODE_ID, IMPLEMENTER_ID],
    );
    // No durable ACTIVE — either no head row, or epoch-0 empty current.
    const current = head.rows[0]?.current_key_id ?? null;
    expect(current).toBeNull();

    const keys = await pool.query(
      `SELECT id FROM implementer_reporting_keys WHERE node_id = $1 AND implementer_id = $2`,
      [NODE_ID, IMPLEMENTER_ID],
    );
    expect(keys.rowCount).toBe(0);

    const recovered = await enrolBootstrapReportingKey(
      pool,
      {
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        reportingKeyOut: keyOut,
        seed: seedBytes,
        nowMs: () => NOW_MS - 60_000,
      },
      quiet,
    );
    expect(recovered.enrolled).toBe(true);
    if (!recovered.enrolled) throw new Error("recover enrol failed");
    expect(recovered.wrotePrivateOut).toBe(true);
    const file = JSON.parse(readFileSync(keyOut, "utf8")) as { reporting_key_id: string };
    expect(file.reporting_key_id).toBe(recovered.keyId);
  }, 60_000);

  it("held restore_hold row is never cleared on enrol conflict; ARM denied", async () => {
    // Isolated node so nonce_burn_sequence stays independent of prior cases.
    const heldNode = randomUUID();
    const heldImplementer = randomUUID();
    const identityPk = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
      [heldNode, "enrol-held", identityPk],
    );
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
      heldImplementer,
      "impl-948-held",
    ]);
    // Pre-seed held restore (post-DR force-upsert posture).
    await pool.query(
      `INSERT INTO reporting_restore_state (
         node_id, restore_hold, created_at, updated_at
       ) VALUES ($1::uuid, true, $2::timestamptz, $2::timestamptz)`,
      [heldNode, SEED_ISO],
    );

    const keyOut = join(tmpDir, "held-restore-key.json");
    const outcome = await enrolBootstrapReportingKey(
      pool,
      {
        nodeId: heldNode,
        implementerId: heldImplementer,
        reportingKeyOut: keyOut,
        seed: Buffer.alloc(32, 0x4a),
        nowMs: () => NOW_MS - 30_000,
      },
      quiet,
    );
    expect(outcome.enrolled).toBe(true);
    if (!outcome.enrolled) throw new Error("enrol failed under hold");

    const hold = await pool.query<{ restore_hold: boolean }>(
      `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
      [heldNode],
    );
    expect(hold.rows[0]?.restore_hold).toBe(true);

    const surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: heldNode,
      pool,
      env: {},
      nowMs: () => NOW_MS,
    });

    const operationId = randomUUID();
    const walletId = randomUUID();
    const observationId = randomUUID();
    const artifactId = randomUUID();
    const signingKeyId = randomUUID();
    const walletPublicKey = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    const transferCode = `zp-tc-${randomUUID().replace(/-/g, "")}`;
    const transferCodeSha256 = sha256Hex(transferCode);

    await pool.query("SET session_replication_role = replica");
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state,
                            recovery_verified_at, recovery_verification_id)
       VALUES ($1, $2, $3, 'node_generated', 'PINNED', $4::timestamptz, $5)`,
      [walletId, heldNode, walletPublicKey, SEED_ISO, randomUUID()],
    );
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
         $1, $2, $3, 'RECEIVE_EXTERNAL', 'READY', 2, '0.01',
         $4, 'HOLD', $1, 'anchor-enrol-held',
         $5, $6, $7, $8
       )`,
      [
        operationId,
        heldNode,
        heldImplementer,
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
       ) VALUES ($1, $2, $3, $4, $1, 'anchor-enrol-held', $5, $6, $7, 'AWAITING_ARM', $8::timestamptz)`,
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

    const target = `/v1/operations/${operationId}/armed`;
    const body = JSON.stringify({
      expected_row_version: 2,
      t0: {
        observation_id: observationId,
        projection: { s: "", p: "", b_zkz: "0" },
      },
      opened_cursor: "1043",
    });
    const issuedAt = new Date(NOW_MS - 1_000).toISOString();
    const expiresAt = new Date(NOW_MS + 30_000).toISOString();
    const nonce = randomUUID();
    const preimage = buildReportRequestPreimage({
      purpose: REPORT_REQUEST_PURPOSE,
      canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
      node_id: heldNode,
      implementer_id: heldImplementer,
      method: "POST",
      path: target,
      body_sha256: sha256Hex(body),
      nonce,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });
    const file = JSON.parse(readFileSync(keyOut, "utf8")) as { seed_hex: string };
    const signingKey = privateKeyFromSeedHex(file.seed_hex);
    const response = await surface.reportingHandle({
      method: "POST",
      rawTarget: target,
      rawHeaders: [
        "X-ZP-Reporting-Key-Id",
        outcome.keyId,
        "X-ZP-Reporting-Timestamp",
        issuedAt,
        "X-ZP-Reporting-Expires-At",
        expiresAt,
        "X-ZP-Reporting-Nonce",
        nonce,
        "X-ZP-Reporting-Signature",
        signPadded(preimage, signingKey),
        "Idempotency-Key",
        `idem-${nonce}`,
      ],
      bodyBytes: new TextEncoder().encode(body),
      receivedAtMs: NOW_MS,
    });
    expect(response.status).not.toBe(200);
    expect(response.status).toBeGreaterThanOrEqual(400);

    const durable = await pool.query<{ code_status: string }>(
      `SELECT code_status FROM receive_codes WHERE operation_id = $1`,
      [operationId],
    );
    expect(durable.rows[0]!.code_status).toBe("AWAITING_ARM");

    const holdAfter = await pool.query<{ restore_hold: boolean }>(
      `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
      [heldNode],
    );
    expect(holdAfter.rows[0]?.restore_hold).toBe(true);
  }, 60_000);

  it("already_active with missing OUT refuses silent brick path", async () => {
    // Use IO from first recovery test — ACTIVE key exists for IMPLEMENTER_ID
    // with OUT on disk; remove OUT and re-call.
    const missingOut = join(tmpDir, "definitely-not-present.json");
    try {
      rmSync(missingOut, { force: true });
    } catch {
      /* ok */
    }
    const again = await enrolBootstrapReportingKey(
      pool,
      {
        nodeId: NODE_ID,
        implementerId: IMPLEMENTER_ID,
        reportingKeyOut: missingOut,
        seed: seedBytes,
      },
      quiet,
    );
    expect(again.enrolled).toBe(false);
    if (again.enrolled) throw new Error("expected cattle path");
    expect(again.reason).toBe("already_active_private_out_missing");
  });
});

describe.skipIf(!PG_AVAILABLE)("nonce_burn_sequence atomic under concurrency", () => {
  const scratchDb = `atomicity_atom_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const NUM_CONCURRENT = 5;

  let pool: Pool;
  const quiet = {
    info: (_m: string) => {},
    error: (_m: string) => {},
  };

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

    const identityPk = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
      [NODE_ID, "atomicity", identityPk],
    );
    // Pre-create all implementers so parallel enrol only contends on the burn counter.
    for (let i = 0; i < NUM_CONCURRENT; i++) {
      const implId = randomUUID();
      await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        implId,
        `impl-1038-${i}`,
      ]);
    }
  }, 300_000);

  afterAll(async () => {
    await pool?.end();
    try {
      await dropTestDatabase(scratchDb);
    } catch {
      /* best effort */
    }
  });

  it("parallel enrol for different implementers on same node → distinct nonce_burn_sequence", async () => {
    const implementers = await pool.query<{ id: string }>(
      `SELECT id::text AS id FROM implementers WHERE name LIKE 'impl-1038-%' ORDER BY name`,
    );
    expect(implementers.rows.length).toBe(NUM_CONCURRENT);

    // Fire all enrolments concurrently against the same node.
    const outcomes = await Promise.all(
      implementers.rows.map((impl, i) =>
        enrolBootstrapReportingKey(
          pool,
          {
            nodeId: NODE_ID,
            implementerId: impl.id,
            seed: Buffer.alloc(32, 0x60 + i),
            nowMs: () => Date.parse("2026-08-01T12:00:00.000Z") - i * 1000,
          },
          quiet,
        ),
      ),
    );

    // All must succeed.
    for (const o of outcomes) {
      expect(o.enrolled).toBe(true);
    }

    // Each nonce must have a distinct burn sequence — the whole point of the burn-sequence fix.
    const nonces = await pool.query<{ nonce_burn_sequence: string }>(
      `SELECT nonce_burn_sequence::text FROM reporting_request_nonces
        WHERE node_id = $1 ORDER BY nonce_burn_sequence`,
      [NODE_ID],
    );
    const sequences = nonces.rows.map((r) => r.nonce_burn_sequence);
    expect(sequences).toHaveLength(NUM_CONCURRENT);
    const uniqueSeqs = new Set(sequences);
    expect(uniqueSeqs.size).toBe(NUM_CONCURRENT);

    // Counter must have advanced past all claimed values.
    const counter = await pool.query<{ next_burn_sequence: string }>(
      `SELECT next_burn_sequence::text FROM reporting_nonce_burn_counters WHERE node_id = $1`,
      [NODE_ID],
    );
    const nextBurn = BigInt(counter.rows[0].next_burn_sequence);
    expect(nextBurn).toBe(BigInt(NUM_CONCURRENT + 1));
  }, 60_000);
});

// Losing the genesis reporting-key seed used to brick the node forever.
// Reproduces the live incident end to end on real PG: enrol → destroy the seed → confirm the
// node is stuck → declare the key lost → recovery re-runs the ceremony under a fresh implementer
// → ARM releases a transfer code with the new key.
describe.skipIf(!PG_AVAILABLE)("reporting-key re-enrolment after genesis seed loss", () => {
  const scratchDb = `rearm_recover_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const NODE_ID = randomUUID();
  const NOW_MS = Date.parse("2026-08-01T12:00:00.000Z");
  const SEED_ISO = "2026-08-01T10:00:00.000Z";
  const EXPIRY_SECS = String(Math.floor(NOW_MS / 1000) + 3600);
  const tmpDir = mkdtempSync(join(tmpdir(), "rearm-"));
  const keyOut = join(tmpDir, "reporting-key.json");

  interface OutFile {
    readonly implementer_id: string;
    readonly reporting_key_id: string;
    readonly public_key: string;
    readonly seed_hex: string;
  }
  const readOut = (): OutFile => JSON.parse(readFileSync(keyOut, "utf8")) as OutFile;

  let pool: Pool;
  let surface: ReturnType<typeof createProductionRouteSurface>;
  const logs: string[] = [];
  const logger = {
    info: (m: string) => {
      logs.push(m);
    },
    error: (m: string) => {
      logs.push(m);
    },
  };

  let lost: OutFile;
  let recovered: OutFile;
  let signingKey: KeyObject;
  /** Lifecycle/nonce evidence for the lost key, snapshotted before recovery ran. */
  let lostEvidenceBefore: string;
  let bricked: { keyCount: number; implementerId: string };

  async function runGenesis(recoverLostReportingKeyId?: string): Promise<void> {
    const { runGenesisBootstrap } = await import("../../src/bootstrap/genesis.js");
    const { SqlCredentialStore } = await import("@zucoins/node-core");
    await runGenesisBootstrap(
      {
        pool,
        // bootstrapGenesisAdmin returns before touching the store when not production and no
        // initial password is configured, so genesis never reaches this stub.
        adminUserStore: {} as never,
        credentialStore: new SqlCredentialStore(pool, NODE_ID),
        logger,
      },
      {
        nodeId: NODE_ID,
        identityPublicKey: `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`,
        isProduction: false,
        reportingKeyOut: keyOut,
        recoverLostReportingKeyId,
      },
    );
  }

  /** Every append-only row the lost key owns, ordered, as a comparable snapshot. */
  async function lostKeyEvidence(keyId: string): Promise<string> {
    const states = await pool.query(
      `SELECT id::text, lifecycle_epoch::text, state::text, lifecycle_event_id::text
         FROM reporting_key_lifecycle_states
        WHERE reporting_key_id = $1::uuid
        ORDER BY lifecycle_epoch`,
      [keyId],
    );
    const nonces = await pool.query(
      `SELECT id::text, nonce::text, lifecycle_epoch::text, nonce_burn_sequence::text,
              request_preimage_sha256, request_signature
         FROM reporting_request_nonces
        WHERE new_reporting_key_id = $1::uuid
        ORDER BY nonce_burn_sequence`,
      [keyId],
    );
    const events = await pool.query(
      `SELECT id::text, epoch::text, event_type::text, event_hash
         FROM reporting_key_lifecycle_events
        WHERE current_key_id = $1::uuid
        ORDER BY epoch`,
      [keyId],
    );
    return JSON.stringify({ states: states.rows, nonces: nonces.rows, events: events.rows });
  }

  beforeAll(async () => {
    await createTestDatabase(scratchDb);
    pool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: scratchDb,
      password: process.env.PGPASSWORD,
    });
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: pgDatabaseUrl(scratchDb) });

    // 1. Genesis enrols the first key and writes the private half once.
    await runGenesis();
    lost = readOut();

    // 2. The container is reaped before the operator reads the file — the seed is gone for good,
    //    while the key stays durably ACTIVE. This is the live incident verbatim.
    rmSync(keyOut, { force: true });
    lostEvidenceBefore = await lostKeyEvidence(lost.reporting_key_id);

    // 3. Restarting does not help: the node is stuck on an implementer whose key nobody holds.
    await runGenesis();
    bricked = {
      keyCount: (
        await pool.query(`SELECT count(*)::int AS n FROM implementer_reporting_keys WHERE node_id = $1::uuid`, [NODE_ID])
      ).rows[0].n,
      implementerId: (
        await pool.query<{ id: string }>(`SELECT id::text AS id FROM implementers WHERE retired_at IS NULL`)
      ).rows[0].id,
    };

    // 4. The operator declares the key unrecoverable by id; genesis recovers.
    await runGenesis(lost.reporting_key_id);
    recovered = readOut();
    signingKey = privateKeyFromSeedHex(recovered.seed_hex);

    surface = createProductionRouteSurface({
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
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
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  it("without the recovery flag a lost seed leaves the node bricked", () => {
    // Non-vacuity guard: if this ever stops failing, the recovery test below proves nothing.
    expect(bricked.keyCount).toBe(1);
    expect(bricked.implementerId).toBe(lost.implementer_id);
    expect(logs.join("\n")).toContain("REPORTING_KEY_OUT missing");
  });

  it("declaring the key lost retires its implementer and enrols a fresh one", async () => {
    expect(recovered.reporting_key_id).not.toBe(lost.reporting_key_id);
    expect(recovered.implementer_id).not.toBe(lost.implementer_id);

    const retired = await pool.query<{ retired_at: string | null }>(
      `SELECT retired_at FROM implementers WHERE id = $1::uuid`,
      [lost.implementer_id],
    );
    expect(retired.rows[0]?.retired_at).not.toBeNull();

    const live = await pool.query<{ id: string }>(
      `SELECT id::text AS id FROM implementers WHERE retired_at IS NULL`,
    );
    expect(live.rows.map((r) => r.id)).toEqual([recovered.implementer_id]);

    const head = await pool.query<{ epoch: string; current_key_id: string; auth_hold: boolean }>(
      `SELECT epoch::text AS epoch, current_key_id::text AS current_key_id, auth_hold
         FROM reporting_key_lifecycle_heads
        WHERE node_id = $1::uuid AND implementer_id = $2::uuid`,
      [NODE_ID, recovered.implementer_id],
    );
    expect(head.rows[0]?.epoch).toBe("1");
    expect(head.rows[0]?.current_key_id).toBe(recovered.reporting_key_id);
    expect(head.rows[0]?.auth_hold).toBe(false);
  });

  it("the collision the ticket hit is gone — the successor claims a distinct burn sequence", async () => {
    // Composes with the atomic claim is what makes a second ceremony issuable at all.
    const burns = await pool.query<{ new_reporting_key_id: string; nonce_burn_sequence: string }>(
      `SELECT new_reporting_key_id::text AS new_reporting_key_id,
              nonce_burn_sequence::text AS nonce_burn_sequence
         FROM reporting_request_nonces
        WHERE node_id = $1::uuid AND purpose = 'zp-reporting-register-v1'
        ORDER BY nonce_burn_sequence`,
      [NODE_ID],
    );
    expect(burns.rows.map((r) => r.nonce_burn_sequence)).toEqual(["1", "2"]);
    expect(burns.rows[0].new_reporting_key_id).toBe(lost.reporting_key_id);
    expect(burns.rows[1].new_reporting_key_id).toBe(recovered.reporting_key_id);
  });

  it("the tombstone is auditable and append-only history is untouched", async () => {
    // Successor link: the new key's bootstrap evidence names the key it replaces.
    const evidence = await pool.query<{ onboarding_actor_id: string }>(
      `SELECT onboarding_actor_id FROM reporting_key_bootstrap_evidence
        WHERE new_reporting_key_id = $1::uuid`,
      [recovered.reporting_key_id],
    );
    expect(evidence.rows[0]?.onboarding_actor_id).toBe(
      `reporting-key-recovery:superseded=${lost.reporting_key_id}`,
    );

    // No delete, no edit: the lost key's evidence is byte-identical to the pre-recovery snapshot.
    expect(await lostKeyEvidence(lost.reporting_key_id)).toBe(lostEvidenceBefore);

    // Not resurrected: the lost key is no live head's current key.
    const stillCurrent = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM reporting_key_lifecycle_heads h
         JOIN implementers i ON i.id = h.implementer_id
        WHERE h.current_key_id = $1::uuid AND i.retired_at IS NULL`,
      [lost.reporting_key_id],
    );
    expect(stillCurrent.rows[0].n).toBe(0);
  });

  it("replaying the recovery with the same lost key id is inert", async () => {
    const before = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM implementer_reporting_keys WHERE node_id = $1::uuid`,
      [NODE_ID],
    );
    await runGenesis(lost.reporting_key_id);
    const after = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM implementer_reporting_keys WHERE node_id = $1::uuid`,
      [NODE_ID],
    );
    expect(after.rows[0].n).toBe(before.rows[0].n);

    const live = await pool.query<{ id: string }>(
      `SELECT id::text AS id FROM implementers WHERE retired_at IS NULL`,
    );
    expect(live.rows.map((r) => r.id)).toEqual([recovered.implementer_id]);
    expect(readOut().reporting_key_id).toBe(recovered.reporting_key_id);
  }, 60_000);

  it("ARM releases a transfer code with the recovered key (AC3)", async () => {
    const operationId = randomUUID();
    const walletId = randomUUID();
    const observationId = randomUUID();
    const artifactId = randomUUID();
    const walletPublicKey = `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;
    const transferCode = `zp-tc-${randomUUID().replace(/-/g, "")}`;

    await pool.query("SET session_replication_role = replica");
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state,
                            recovery_verified_at, recovery_verification_id)
       VALUES ($1, $2, $3, 'node_generated', 'PINNED', $4::timestamptz, $5)`,
      [walletId, NODE_ID, walletPublicKey, SEED_ISO, randomUUID()],
    );
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
         $1, $2, $3, 'RECEIVE_EXTERNAL', 'READY', 2, '0.01',
         $4, 'HOLD', $1, 'anchor-rearm',
         $5, $6, $7, $8
       )`,
      [
        operationId,
        NODE_ID,
        // The receive belongs to the RECOVERED implementer — the retired one can arm nothing.
        recovered.implementer_id,
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
        randomUUID(),
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
       ) VALUES ($1, $2, $3, $4, $1, 'anchor-rearm', $5, $6, $7, 'AWAITING_ARM', $8::timestamptz)`,
      [
        operationId,
        walletId,
        observationId,
        artifactId,
        EXPIRY_SECS,
        transferCode,
        sha256Hex(transferCode),
        SEED_ISO,
      ],
    );
    await pool.query("SET session_replication_role = DEFAULT");

    const target = `/v1/operations/${operationId}/armed`;
    const body = JSON.stringify({
      expected_row_version: 2,
      t0: { observation_id: observationId, projection: { s: "", p: "", b_zkz: "0" } },
      opened_cursor: "1043",
    });
    const issuedAt = new Date(NOW_MS - 1_000).toISOString();
    const expiresAt = new Date(NOW_MS + 30_000).toISOString();
    const nonce = randomUUID();
    const preimage = buildReportRequestPreimage({
      purpose: REPORT_REQUEST_PURPOSE,
      canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
      node_id: NODE_ID,
      implementer_id: recovered.implementer_id,
      method: "POST",
      path: target,
      body_sha256: sha256Hex(body),
      nonce,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });

    const response = await surface.reportingHandle({
      method: "POST",
      rawTarget: target,
      rawHeaders: [
        "X-ZP-Reporting-Key-Id",
        recovered.reporting_key_id,
        "X-ZP-Reporting-Timestamp",
        issuedAt,
        "X-ZP-Reporting-Expires-At",
        expiresAt,
        "X-ZP-Reporting-Nonce",
        nonce,
        "X-ZP-Reporting-Signature",
        signPadded(preimage, signingKey),
        "Idempotency-Key",
        `idem-${nonce}`,
      ],
      bodyBytes: new TextEncoder().encode(body),
      receivedAtMs: NOW_MS,
    });

    expect(response.status).toBe(200);
    const parsed = JSON.parse(new TextDecoder().decode(response.bodyBytes)) as {
      code_status: string;
      transfer_code_sha256: string;
    };
    expect(parsed.code_status).toBe("RELEASED");
    expect(parsed.transfer_code_sha256).toBe(sha256Hex(transferCode));

    // The recovered seed never reaches a log line.
    expect(logs.join("\n")).not.toContain(recovered.seed_hex);
  }, 60_000);
});
