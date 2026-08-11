// Composition + durable PG nonce replay across store instances.
// Proves custody production factory binds DurableReportingRequestStore and that
// a burned nonce rejects REPLAY after a fresh store instance on the same DB.

import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import { computeReportingLogicalFingerprint } from "@zucoins/node-core";
import type { BurnNonceEvidence, BurnNonceRequest } from "@zucoins/node-core";

import {
  createPoolReportingClient,
  createProductionRouteSurface,
  DURABLE_REPORTING_STORE,
  DurableReportingRequestStore,
} from "../../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

function adminClientConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], {
      stdio: "ignore",
    });
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
    /* fall through to TCP probe */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require('pg');const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:'postgres',password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      {
        stdio: "ignore",
        env: process.env,
        cwd: fileURLToPath(new URL("../..", import.meta.url)),
      },
    );
    return true;
  } catch {
    return false;
  }
})();

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function createTestDatabase(dbName: string): Promise<void> {
  assertSafeDbName(dbName);
  if (HAS_CREATEDB) {
    execFileSync("createdb", [dbName]);
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
    execFileSync("dropdb", ["--if-exists", dbName]);
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

const uniquePubkey = (): string => `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;

describe("production factory binds durable reporting (no PG)", () => {
  it("createProductionRouteSurface constructs DurableReportingRequestStore", () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: randomUUID(),
      pool: { query: async () => ({ rows: [] }), connect: async () => ({}) } as never,
      env: {},
    });
    expect(surface.reportingStore).toBeInstanceOf(DurableReportingRequestStore);
    expect(surface.reportingStoreKind).toEqual(DURABLE_REPORTING_STORE);
  });
});

describe.skipIf(!PG_AVAILABLE)(
  "durable reporting nonce survives new store instance (real PG)",
  () => {
    const scratchDb = `production_durable_test_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    let pool: Pool;

    beforeAll(async () => {
      await createTestDatabase(scratchDb);
      pool = pgPool(scratchDb);
      process.env.DATABASE_URL ??= pgDatabaseUrl(scratchDb);
      const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
      await runMigrationsOnPool(pool);
    }, 180_000);

    afterAll(async () => {
      await pool?.end();
      try {
        await dropTestDatabase(scratchDb);
      } catch {
        /* best-effort */
      }
    });

    /**
     * Minimal open-admission seed for reporting_lock_and_assert_admission.
     * Triggers disabled only for seed inserts (session_replication_role = replica).
     */
    async function seedOpenAdmission(
      nodeId: string,
      implementerId: string,
      keyId: string,
    ): Promise<void> {
      const event1Id = randomUUID();
      const nonceRegId = randomUUID();
      const bootstrapId = randomUUID();
      const enrolId = randomUUID();
      const pendingStateId = randomUUID();
      const activeStateId = randomUUID();
      const t0iso = "2026-07-26T10:00:00.000Z";
      const tExp = "2026-07-26T10:01:00.000Z";
      const preimage = "seed-register-preimage";
      const preSha = sha256Hex(preimage);
      const sig = `${"A".repeat(86)}==`;
      const eventHash = "11".repeat(32);
      const pubkey = uniquePubkey();

      await pool.query("SET session_replication_role = replica");
      await pool.query(
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
        [nodeId, "production-durable", uniquePubkey()],
      );
      await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        implementerId,
        "impl-926",
      ]);
      await pool.query(
        `INSERT INTO implementer_reporting_keys
           (id, node_id, implementer_id, public_key, registered_at)
         VALUES ($1, $2, $3, $4, $5::timestamptz)`,
        [keyId, nodeId, implementerId, pubkey, t0iso],
      );
      await pool.query(
        `INSERT INTO reporting_key_bootstrap_evidence (
           id, node_id, implementer_id, new_reporting_key_id,
           onboarding_actor_id, operator_approval_audit_id, approved_at, created_at
         ) VALUES ($1, $2, $3, $4, 'op', $5, $6::timestamptz, $6::timestamptz)`,
        [bootstrapId, nodeId, implementerId, keyId, randomUUID(), t0iso],
      );
      await pool.query(
        `INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence)
         VALUES ($1, 2)`,
        [nodeId],
      );
      await pool.query(
        `
        INSERT INTO reporting_request_nonces (
          id, node_id, implementer_id, nonce, purpose,
          route_id, request_class, reporting_key_id, new_reporting_key_id,
          bootstrap_evidence_id,
          lifecycle_epoch, nonce_burn_sequence,
          request_preimage_text, request_preimage_sha256, request_signature,
          method, raw_target, body_sha256,
          issued_at, expires_at, received_at, consumed_at, retention_class
        ) VALUES (
          $1, $2, $3, $4, 'zp-reporting-register-v1',
          NULL, NULL, NULL, $5,
          $6,
          1, 1,
          $7, $8, $9,
          NULL, NULL, NULL,
          $10::timestamptz, $11::timestamptz, $10::timestamptz, $10::timestamptz,
          'LIFECYCLE_PERMANENT'
        )
        `,
        [
          nonceRegId,
          nodeId,
          implementerId,
          randomUUID(),
          keyId,
          bootstrapId,
          preimage,
          preSha,
          sig,
          t0iso,
          tExp,
        ],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_enrolment_evidence (
          id, node_id, implementer_id, new_reporting_key_id,
          supersedes_key_id, authorizing_key_id, bootstrap_evidence_id,
          nonce_evidence_id,
          proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
          proof_of_possession_signature,
          authorizing_preimage_text, authorizing_preimage_sha256, authorizing_signature,
          issued_at, expires_at, created_at
        ) VALUES (
          $1, $2, $3, $4,
          NULL, NULL, $5,
          $6,
          $7, $8, $9,
          NULL, NULL, NULL,
          $10::timestamptz, $11::timestamptz, $10::timestamptz
        )
        `,
        [
          enrolId,
          nodeId,
          implementerId,
          keyId,
          bootstrapId,
          nonceRegId,
          preimage,
          preSha,
          sig,
          t0iso,
          tExp,
        ],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_lifecycle_states (
          id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
          state, lifecycle_event_id, state_changed_at
        ) VALUES ($1, $2, $3, $4, 0, 'PENDING', NULL, $5::timestamptz)
        `,
        [pendingStateId, keyId, nodeId, implementerId, t0iso],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_lifecycle_events (
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
        )
        `,
        [
          event1Id,
          nodeId,
          implementerId,
          keyId,
          t0iso,
          nonceRegId,
          enrolId,
          sha256Hex("seed-first"),
          eventHash,
        ],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_lifecycle_states (
          id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
          state, lifecycle_event_id, state_changed_at
        ) VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, $6::timestamptz)
        `,
        [activeStateId, keyId, nodeId, implementerId, event1Id, t0iso],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_state_transitions (
          lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type,
          reporting_key_id, from_state_row_id, to_state_row_id,
          from_lifecycle_epoch, to_lifecycle_epoch, from_state, to_state, transitioned_at
        ) VALUES (
          $1, $2, $3, 1, 'FIRST_KEY_ACTIVATED',
          $4, $5, $6,
          0, 1, 'PENDING', 'ACTIVE', $7::timestamptz
        )
        `,
        [event1Id, nodeId, implementerId, keyId, pendingStateId, activeStateId, t0iso],
      );
      await pool.query(
        `
        INSERT INTO reporting_key_lifecycle_heads (
          node_id, implementer_id, epoch, current_key_id, prior_key_id,
          overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
        ) VALUES ($1, $2, 1, $3, NULL, NULL, false, $4, $5::timestamptz)
        `,
        [nodeId, implementerId, keyId, event1Id, t0iso],
      );
      await pool.query(
        `
        INSERT INTO reporting_restore_state (
          node_id, restore_hold,
          local_lifecycle_epoch, local_nonce_burn_high_water, local_event_hash,
          trusted_lifecycle_epoch, trusted_nonce_burn_high_water, trusted_event_hash,
          trusted_source_id, trusted_source_observed_at,
          hold_release_evidence_sha256, hold_released_at,
          created_at, updated_at
        ) VALUES (
          $1, false,
          1, 1, $2,
          1, 1, $2,
          'file:/markers.json', '2026-07-26T00:00:00.000Z',
          $3, '2026-07-26T00:00:00.000Z',
          $4::timestamptz, $4::timestamptz
        )
        `,
        [nodeId, eventHash, "ab".repeat(32), t0iso],
      );
      await pool.query("SET session_replication_role = DEFAULT");
    }

    function burnRequest(
      nodeId: string,
      implementerId: string,
      keyId: string,
      nonce: string,
    ): BurnNonceRequest {
      const method = "GET";
      const rawTarget = "/v1/destinations";
      const bodySha256 = "00".repeat(32);
      const evidence: BurnNonceEvidence = {
        nodeId,
        implementerId,
        nonce,
        purpose: "zp-report-request-v1",
        routeId: "destinations_list",
        requestClass: "READ",
        reportingKeyId: keyId,
        lifecycleEpoch: 1n,
        requestPreimageText: "preimage-926",
        requestPreimageSha256: "cd".repeat(32),
        requestSignature: `${"B".repeat(86)}==`,
        method,
        rawTarget,
        bodySha256,
        logicalFingerprint: computeReportingLogicalFingerprint(method, rawTarget, bodySha256),
        issuedAt: "2026-07-26T10:00:00.000Z",
        expiresAt: "2026-07-26T10:00:45.000Z",
        receivedAtMs: Date.parse("2026-07-26T10:00:30.000Z"),
        consumedAtMs: Date.parse("2026-07-26T10:00:30.050Z"),
        retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
      };
      return { expectedEpoch: 1n, evidence };
    }

    it(
      "AC3: fixture burn then new DurableReportingRequestStore rejects REPLAY",
      async () => {
        const nodeId = randomUUID();
        const implementerId = randomUUID();
        const keyId = randomUUID();
        const nonce = randomUUID();
        await seedOpenAdmission(nodeId, implementerId, keyId);

        const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
          vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
          nodeId,
          pool,
          env: {},
        });
        expect(surface.reportingStore).toBeInstanceOf(DurableReportingRequestStore);

        const first = await surface.reportingStore.burnNonceAtomically(
          burnRequest(nodeId, implementerId, keyId, nonce),
        );
        expect(first.kind).toBe("BURNED");

        const store2 = new DurableReportingRequestStore(createPoolReportingClient(pool));
        const replay = await store2.burnNonceAtomically(
          burnRequest(nodeId, implementerId, keyId, nonce),
        );
        expect(replay.kind).toBe("REPLAY");
      },
      120_000,
    );
  },
);
