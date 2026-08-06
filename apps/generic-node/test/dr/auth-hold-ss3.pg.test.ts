/**
 * Integration against the stock reporting DDL (0000_reporting_persistence.sql):
 * AUTH_HOLD_SET must COMMIT with deferred constraint triggers present.
 *
 * Known stock defect: the reporting_validate_lifecycle_deferred CASE
 * aborts on events-table NEW (no lifecycle_event_id). Force path must heal
 * that body and still satisfy reporting_assert_lifecycle_event.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { applyDualGateForceAfterRestore } from "../../src/dr/auth-hold.js";
import { buildMarkersFromLocal } from "../../src/dr/markers.js";
import {
  buildRestoreHoldReleaseUpdate,
  evaluateRestoreHoldRelease,
} from "../../src/dr/restore-hold.js";

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-t", "1"], { stdio: "ignore", timeout: 2000 });
    return true;
  } catch {
    return false;
  }
})();

const HERE = dirname(fileURLToPath(import.meta.url));
const REPORTING_SQL_PATH = join(HERE, "../../drizzle/0000_reporting_persistence.sql");

function maintenanceUrl(): string {
  if (process.env.DR_TEST_TEMPLATE_URL) return process.env.DR_TEST_TEMPLATE_URL;
  const user = process.env.PGUSER ?? "postgres";
  const host = process.env.PGHOST ?? "localhost";
  if (host.startsWith("/")) {
    return `postgresql://${user}@${encodeURIComponent(host)}/postgres`;
  }
  return `postgresql://${user}@${host}:${process.env.PGPORT ?? "5432"}/postgres`;
}

function dbUrl(name: string): string {
  const base = maintenanceUrl();
  return base.replace(/\/[^/]+$/, `/${name}`);
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

const NODE_PUBKEY = `${"B".repeat(43)}=`;
const PUBKEY = `${"A".repeat(43)}=`;
const SIG = `${"A".repeat(86)}==`;
const EVENT_HASH_1 = "11".repeat(32);

async function applyStockSs3(pool: Pool): Promise<void> {
  await pool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
  const sql = readFileSync(REPORTING_SQL_PATH, "utf8");
  await pool.query(sql);
}

/**
 * Seed epoch-1 FIRST_KEY_ACTIVATED chain with auth_hold=false.
 * Triggers disabled only for seed (stock CASE deferred also breaks seed inserts);
 * re-enabled afterward so force must survive deferred validation.
 */
async function seedOpenAuthHoldHead(
  pool: Pool,
  ids: {
    nodeId: string;
    implementerId: string;
    keyId: string;
    event1Id: string;
    nonceRegId: string;
    bootstrapId: string;
    enrolId: string;
    pendingStateId: string;
    activeStateId: string;
  },
): Promise<void> {
  const {
    nodeId,
    implementerId,
    keyId,
    event1Id,
    nonceRegId,
    bootstrapId,
    enrolId,
    pendingStateId,
    activeStateId,
  } = ids;

  await pool.query("SET session_replication_role = replica");

  const t0iso = "2026-07-26T10:00:00.000Z";
  const tExp = "2026-07-26T10:01:00.000Z";
  const preimage = "seed-register-preimage";
  const preSha = sha256Hex(preimage);

  await pool.query(
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
    [nodeId, "ss3-auth-hold-src", NODE_PUBKEY],
  );
  await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
    implementerId,
    "impl-ss3",
  ]);
  await pool.query(
    `INSERT INTO implementer_reporting_keys
       (id, node_id, implementer_id, public_key, registered_at)
     VALUES ($1, $2, $3, $4, $5::timestamptz)`,
    [keyId, nodeId, implementerId, PUBKEY, t0iso],
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
      SIG,
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
      SIG,
      t0iso,
      tExp,
    ],
  );

  // PENDING first (no event FK). Event before ACTIVE state (FK to event).
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
      EVENT_HASH_1,
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
    [nodeId, EVENT_HASH_1, "ab".repeat(32), t0iso],
  );

  await pool.query("SET session_replication_role = DEFAULT");
}

describe.skipIf(!PG_AVAILABLE)(
  "stock reporting DDL: dual-gate force AUTH_HOLD_SET under deferred triggers",
  () => {
    const stamp = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const dbName = `auth_hold_force_ss3_${stamp}`;
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const keyId = randomUUID();
    const event1Id = randomUUID();
    const nonceRegId = randomUUID();
    const bootstrapId = randomUUID();
    const enrolId = randomUUID();
    const pendingStateId = randomUUID();
    const activeStateId = randomUUID();
    let pool: Pool;

    beforeAll(async () => {
      const maint = maintenanceUrl();
      execFileSync("createdb", ["--maintenance-db", maint, dbName], { stdio: "ignore" });
      pool = new Pool({ connectionString: dbUrl(dbName) });
      await applyStockSs3(pool);
      await seedOpenAuthHoldHead(pool, {
        nodeId,
        implementerId,
        keyId,
        event1Id,
        nonceRegId,
        bootstrapId,
        enrolId,
        pendingStateId,
        activeStateId,
      });

      const head = await pool.query(
        `SELECT auth_hold FROM reporting_key_lifecycle_heads WHERE node_id = $1`,
        [nodeId],
      );
      expect(head.rows[0].auth_hold).toBe(false);

      // Stock deferred function still has the CASE body (not pre-healed).
      const body = await pool.query<{ prosrc: string }>(
        `SELECT p.prosrc AS prosrc
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'reporting_validate_lifecycle_deferred'`,
      );
      expect(body.rows[0]?.prosrc ?? "").toMatch(/CASE\s+TG_TABLE_NAME/i);
    }, 120_000);

    afterAll(async () => {
      await pool?.end();
      const maint = maintenanceUrl();
      try {
        execFileSync("dropdb", ["--if-exists", "--maintenance-db", maint, dbName], {
          stdio: "ignore",
        });
      } catch {
        /* best-effort */
      }
    });

    it("applyDualGateForceAfterRestore commits AUTH_HOLD_SET; fault 9 on restore_hold-only release", async () => {
      const result = await applyDualGateForceAfterRestore(dbUrl(dbName));
      expect(result.restoreHold.applied).toBe(true);
      expect(result.authHold.applied).toBe(true);
      expect(result.authHold.headsForced).toBe(1);
      expect(result.authHold.headKeys).toEqual(
        expect.arrayContaining([{ nodeId, implementerId }]),
      );

      const hold = await pool.query(
        `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
        [nodeId],
      );
      expect(hold.rows[0].restore_hold).toBe(true);

      const head = await pool.query(
        `
        SELECT h.auth_hold AS auth_hold,
               h.epoch::text AS epoch,
               e.event_type::text AS event_type
          FROM reporting_key_lifecycle_heads h
          JOIN reporting_key_lifecycle_events e ON e.id = h.lifecycle_event_id
         WHERE h.node_id = $1 AND h.implementer_id = $2
        `,
        [nodeId, implementerId],
      );
      expect(head.rowCount).toBe(1);
      expect(head.rows[0].auth_hold).toBe(true);
      expect(head.rows[0].event_type).toBe("AUTH_HOLD_SET");
      expect(Number(head.rows[0].epoch)).toBe(2);

      // Deferred body healed to IF/ELSIF (no CASE TG_TABLE_NAME).
      const body = await pool.query<{ prosrc: string }>(
        `SELECT p.prosrc AS prosrc
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = 'reporting_validate_lifecycle_deferred'`,
      );
      expect(body.rows[0]?.prosrc ?? "").toMatch(/IF TG_TABLE_NAME/i);
      expect(body.rows[0]?.prosrc ?? "").not.toMatch(/CASE\s+TG_TABLE_NAME/i);

      // Fault 9: clear restore_hold alone → admission still closed on auth_hold.
      const eventHash2 = (
        await pool.query(
          `SELECT event_hash::text AS event_hash FROM reporting_key_lifecycle_events
            WHERE node_id = $1 AND implementer_id = $2 AND epoch = 2`,
          [nodeId, implementerId],
        )
      ).rows[0].event_hash as string;

      // After force, nonce burn high-water is at least 2 (seed used 1; force adds one).
      const burnHw = (
        await pool.query(
          `SELECT COALESCE(MAX(nonce_burn_sequence), 0)::text AS hw
             FROM reporting_request_nonces WHERE node_id = $1`,
          [nodeId],
        )
      ).rows[0].hw as string;

      const local = {
        lifecycleEpoch: 2n,
        nonceBurnHighWater: BigInt(burnHw),
        terminalEventHash: eventHash2,
      };
      const markers = buildMarkersFromLocal(local, "file:/external-markers.json");
      const decision = evaluateRestoreHoldRelease({ trusted: markers, local });
      expect(decision.release).toBe(true);
      if (!decision.release) return;

      const rel = buildRestoreHoldReleaseUpdate({
        nodeId,
        decision,
        now: new Date("2026-07-26T15:00:00.000Z"),
      });
      await pool.query(rel.sql, rel.params as unknown[]);

      const afterRelease = await pool.query(
        `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
        [nodeId],
      );
      expect(afterRelease.rows[0].restore_hold).toBe(false);

      const stillHeld = await pool.query(
        `SELECT auth_hold FROM reporting_key_lifecycle_heads WHERE node_id = $1`,
        [nodeId],
      );
      expect(stillHeld.rows[0].auth_hold).toBe(true);

      await expect(
        pool.query(
          `SELECT reporting_lock_and_assert_admission($1::uuid, $2::uuid, $3::bigint, $4::uuid, now())`,
          [nodeId, implementerId, 2, keyId],
        ),
      ).rejects.toThrow(/lifecycle admission is closed|auth/i);
    }, 120_000);
  },
);
