/**
 * Integration: restore of a ZBKP whose dump encodes lifecycle heads with
 * auth_hold=false must leave every head auth_hold=true, and releasing only
 * restore_hold must still close admission (post-restore dual gate + fault
 * injection case 9).
 *
 * Uses a minimal CHECK/FK-equivalent slice of the reporting lifecycle schema
 * so pg_dump/psql --single-transaction round-trips cleanly. The full reporting DDL
 * has a separate dump-ordering quirk unrelated to the auth-hold force path.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
// DB-TEST-27: missing trusted restore source/markers remain hard-held; equal local markers never release
// DB-TEST-35: missing or unequal local/trusted lifecycle epoch nonce-burn high-water retains restore_hold


import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "../../src/dr/encrypted-backup.js";
import {
  buildForceAuthHoldSetStatements,
  releaseDualGatesWithTrustedMarkers,
} from "../../src/dr/auth-hold.js";
import {
  buildForceRestoreHoldUpsert,
  buildRestoreHoldReleaseUpdate,
  evaluateRestoreHoldRelease,
} from "../../src/dr/restore-hold.js";
import { buildScheduledBackupMarkers } from "../../src/dr/markers.js";

const PG_AVAILABLE = (() => {
  try {
    execFileSync(
      "psql",
      [
        "-h",
        process.env.PGHOST ?? "localhost",
        "-p",
        process.env.PGPORT ?? "5432",
        "-d",
        "postgres",
        "-qAt",
        "-c",
        "SELECT 1",
      ],
      { stdio: "ignore", timeout: 2000 },
    );
    return true;
  } catch {
    return false;
  }
})();

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

/** Minimal dual-gate schema: restore_hold + lifecycle heads/events + admission. */
const MINIMAL_DUAL_GATE_SCHEMA_SQL = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  display_name text NOT NULL
);

CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE implementer_reporting_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  public_key text NOT NULL,
  registered_at timestamptz NOT NULL,
  UNIQUE (id, node_id, implementer_id)
);

CREATE TABLE reporting_nonce_burn_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_burn_sequence bigint NOT NULL DEFAULT 1
);

CREATE TABLE reporting_request_nonces (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  nonce uuid NOT NULL,
  purpose text NOT NULL,
  route_id text,
  request_class text,
  reporting_key_id uuid,
  lifecycle_epoch bigint NOT NULL,
  nonce_burn_sequence bigint NOT NULL,
  request_preimage_text text NOT NULL,
  request_preimage_sha256 text NOT NULL,
  request_signature text NOT NULL,
  method text,
  raw_target text,
  body_sha256 text,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL,
  consumed_at timestamptz NOT NULL,
  retention_class text NOT NULL,
  UNIQUE (node_id, nonce_burn_sequence),
  UNIQUE (id, node_id, implementer_id, purpose)
);

CREATE TABLE reporting_key_lifecycle_events (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  epoch bigint NOT NULL CHECK (epoch > 0),
  event_type text NOT NULL,
  current_key_id uuid,
  prior_key_id uuid,
  overlap_expires_at timestamptz,
  auth_hold boolean NOT NULL,
  successor_registered_at timestamptz,
  nonce_evidence_id uuid NOT NULL,
  nonce_purpose text NOT NULL,
  enrolment_evidence_id uuid,
  public_evidence_text text NOT NULL,
  public_evidence_sha256 text NOT NULL,
  previous_event_id uuid,
  previous_epoch bigint,
  previous_event_hash text,
  event_hash text NOT NULL UNIQUE,
  committed_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, epoch),
  UNIQUE NULLS NOT DISTINCT (
    id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
    overlap_expires_at, auth_hold
  ),
  CHECK ((event_type = 'AUTH_HOLD_SET' AND auth_hold)
    OR event_type <> 'AUTH_HOLD_SET'),
  CHECK ((event_type = 'AUTH_HOLD_RELEASED' AND NOT auth_hold)
    OR event_type <> 'AUTH_HOLD_RELEASED')
);

CREATE TABLE reporting_key_lifecycle_states (
  id uuid PRIMARY KEY,
  reporting_key_id uuid NOT NULL,
  node_id uuid NOT NULL,
  implementer_id uuid NOT NULL,
  lifecycle_epoch bigint NOT NULL,
  state text NOT NULL,
  lifecycle_event_id uuid,
  state_changed_at timestamptz NOT NULL
);

CREATE TABLE reporting_key_lifecycle_heads (
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  epoch bigint NOT NULL CHECK (epoch >= 0),
  current_key_id uuid,
  prior_key_id uuid,
  overlap_expires_at timestamptz,
  auth_hold boolean NOT NULL DEFAULT true,
  lifecycle_event_id uuid,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (node_id, implementer_id),
  FOREIGN KEY (
    lifecycle_event_id, node_id, implementer_id, epoch, current_key_id,
    prior_key_id, overlap_expires_at, auth_hold
  ) REFERENCES reporting_key_lifecycle_events
      (id, node_id, implementer_id, epoch, current_key_id, prior_key_id,
       overlap_expires_at, auth_hold)
);

CREATE FUNCTION reporting_guard_lifecycle_head_update()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  e reporting_key_lifecycle_events%ROWTYPE;
BEGIN
  SELECT * INTO STRICT e
    FROM reporting_key_lifecycle_events
   WHERE id = NEW.lifecycle_event_id
     AND node_id = NEW.node_id
     AND implementer_id = NEW.implementer_id;
  IF NEW.epoch <> OLD.epoch + 1
     OR NEW.current_key_id IS DISTINCT FROM e.current_key_id
     OR NEW.prior_key_id IS DISTINCT FROM e.prior_key_id
     OR NEW.overlap_expires_at IS DISTINCT FROM e.overlap_expires_at
     OR NEW.auth_hold IS DISTINCT FROM e.auth_hold
     OR (OLD.epoch > 0 AND (e.epoch <> NEW.epoch OR e.previous_event_id <> OLD.lifecycle_event_id))
  THEN
    RAISE EXCEPTION 'illegal reporting lifecycle head advance' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER reporting_lifecycle_head_guard
  BEFORE UPDATE ON reporting_key_lifecycle_heads
  FOR EACH ROW EXECUTE FUNCTION reporting_guard_lifecycle_head_update();

CREATE FUNCTION reporting_advance_lifecycle_head(p_event_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  e reporting_key_lifecycle_events%ROWTYPE;
  changed_count integer;
BEGIN
  SELECT * INTO STRICT e FROM reporting_key_lifecycle_events WHERE id = p_event_id;
  UPDATE reporting_key_lifecycle_heads
     SET epoch = e.epoch,
         current_key_id = e.current_key_id,
         prior_key_id = e.prior_key_id,
         overlap_expires_at = e.overlap_expires_at,
         auth_hold = e.auth_hold,
         lifecycle_event_id = e.id,
         updated_at = e.committed_at
   WHERE node_id = e.node_id
     AND implementer_id = e.implementer_id
     AND epoch = e.epoch - 1
     AND (e.epoch = 1 OR lifecycle_event_id = e.previous_event_id);
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  IF changed_count <> 1 THEN
    RAISE EXCEPTION 'stale or missing reporting lifecycle head' USING ERRCODE = '40001';
  END IF;
END
$$;

CREATE TABLE reporting_restore_state (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  restore_hold boolean NOT NULL DEFAULT true,
  local_lifecycle_epoch bigint,
  local_nonce_burn_high_water bigint,
  local_event_hash text,
  trusted_lifecycle_epoch bigint,
  trusted_nonce_burn_high_water bigint,
  trusted_event_hash text,
  trusted_source_id text,
  trusted_source_observed_at timestamptz,
  hold_release_evidence_sha256 text,
  hold_released_at timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK (
    restore_hold
    OR
    (trusted_source_id IS NOT NULL
      AND local_lifecycle_epoch IS NOT NULL
      AND local_nonce_burn_high_water IS NOT NULL
      AND local_event_hash IS NOT NULL
      AND local_lifecycle_epoch = trusted_lifecycle_epoch
      AND local_nonce_burn_high_water = trusted_nonce_burn_high_water
      AND local_event_hash = trusted_event_hash
      AND hold_release_evidence_sha256 IS NOT NULL
      AND hold_released_at IS NOT NULL)
  )
);

CREATE FUNCTION reporting_lock_and_assert_admission(
  p_node_id uuid,
  p_implementer_id uuid,
  p_lifecycle_epoch bigint,
  p_reporting_key_id uuid,
  p_received_at timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  r reporting_restore_state%ROWTYPE;
  h reporting_key_lifecycle_heads%ROWTYPE;
BEGIN
  SELECT * INTO STRICT r FROM reporting_restore_state
    WHERE node_id = p_node_id FOR UPDATE;
  IF r.restore_hold THEN
    RAISE EXCEPTION 'reporting restore hold is active' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO STRICT h FROM reporting_key_lifecycle_heads
    WHERE node_id = p_node_id AND implementer_id = p_implementer_id
    FOR UPDATE;
  IF h.auth_hold OR h.epoch <> p_lifecycle_epoch
     OR NOT (
       p_reporting_key_id = h.current_key_id
       OR
       (p_reporting_key_id = h.prior_key_id
        AND p_received_at < h.overlap_expires_at)
     )
     OR NOT EXISTS (
       SELECT 1 FROM reporting_key_lifecycle_states s
       WHERE s.node_id = p_node_id
         AND s.implementer_id = p_implementer_id
         AND s.reporting_key_id = p_reporting_key_id
         AND s.state = 'ACTIVE'
         AND s.lifecycle_epoch = (
           SELECT max(s2.lifecycle_epoch)
           FROM reporting_key_lifecycle_states s2
           WHERE s2.node_id = s.node_id
             AND s2.implementer_id = s.implementer_id
             AND s2.reporting_key_id = s.reporting_key_id
         )
     )
  THEN
    RAISE EXCEPTION 'reporting lifecycle admission is closed'
      USING ERRCODE = '55000';
  END IF;
END
$$;
`;

const EVENT_HASH_1 = "11".repeat(32);
const PUBKEY = "A".repeat(43) + "=";
const SIG = "A".repeat(86) + "==";

describe.skipIf(!PG_AVAILABLE)(
  "restore forces auth_hold=true and dual-gate admission",
  () => {
    const stamp = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const sourceDb = `auth_hold_force_auth_src_${stamp}`;
    const targetDb = `auth_hold_force_auth_tgt_${stamp}`;
    const masterKey = "test-backup-master-key-" + randomBytes(8).toString("hex");
    const nodeId = randomUUID();
    const implementerId = randomUUID();
    const keyId = randomUUID();
    const event1Id = randomUUID();
    const nonce1Id = randomUUID();
    let workDir: string;
    let sourcePool: Pool;

    beforeAll(async () => {
      workDir = await mkdtemp(join(tmpdir(), "auth-hold-force-auth-hold-"));
      const maint = maintenanceUrl();
      execFileSync("psql", ["--dbname", maint, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", `CREATE DATABASE "${sourceDb}"`], { stdio: "ignore" });
      execFileSync("psql", ["--dbname", maint, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", `CREATE DATABASE "${targetDb}"`], { stdio: "ignore" });

      sourcePool = new Pool({ connectionString: dbUrl(sourceDb) });
      await sourcePool.query(MINIMAL_DUAL_GATE_SCHEMA_SQL);

      await sourcePool.query(`INSERT INTO nodes (id, display_name) VALUES ($1, $2)`, [
        nodeId,
        "auth-hold-src",
      ]);
      await sourcePool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        implementerId,
        "impl-1",
      ]);
      await sourcePool.query(
        `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
         VALUES ($1, $2, $3, $4, now())`,
        [keyId, nodeId, implementerId, PUBKEY],
      );
      await sourcePool.query(
        `INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence) VALUES ($1, 2)`,
        [nodeId],
      );
      await sourcePool.query(
        `
        INSERT INTO reporting_request_nonces (
          id, node_id, implementer_id, nonce, purpose,
          route_id, request_class, reporting_key_id,
          lifecycle_epoch, nonce_burn_sequence,
          request_preimage_text, request_preimage_sha256, request_signature,
          method, raw_target, body_sha256,
          issued_at, expires_at, received_at, consumed_at, retention_class
        ) VALUES (
          $1, $2, $3, $4, 'zp-report-request-v1',
          'seed', 'READ', $5,
          1, 1,
          'seed', $6, $7,
          'GET', '/seed', $6,
          now(), now() + interval '30 seconds', now(), now(),
          'READ_NO_PRUNE_UNTIL_SAFETY_FREEZE'
        )
        `,
        [nonce1Id, nodeId, implementerId, randomUUID(), keyId, sha256Hex("seed"), SIG],
      );

      // Epoch-1 head event with auth_hold=false — the production-backup case.
      await sourcePool.query(
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
          now(), $5, 'zp-report-request-v1',
          NULL, 'seed-first', $6,
          NULL, NULL, NULL,
          $7, now()
        )
        `,
        [event1Id, nodeId, implementerId, keyId, nonce1Id, sha256Hex("seed-first"), EVENT_HASH_1],
      );

      await sourcePool.query(
        `
        INSERT INTO reporting_key_lifecycle_heads (
          node_id, implementer_id, epoch, current_key_id, prior_key_id,
          overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
        ) VALUES ($1, $2, 1, $3, NULL, NULL, false, $4, now())
        `,
        [nodeId, implementerId, keyId, event1Id],
      );

      await sourcePool.query(
        `
        INSERT INTO reporting_key_lifecycle_states (
          id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
          state, lifecycle_event_id, state_changed_at
        ) VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, now())
        `,
        [randomUUID(), keyId, nodeId, implementerId, event1Id],
      );

      // Released restore_hold — proves D1 force still runs alongside D2.
      await sourcePool.query(
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
          now(), now()
        )
        `,
        [nodeId, EVENT_HASH_1, "ab".repeat(32)],
      );

      const head = await sourcePool.query(
        `SELECT auth_hold FROM reporting_key_lifecycle_heads WHERE node_id = $1`,
        [nodeId],
      );
      expect(head.rows[0].auth_hold).toBe(false);
    }, 60_000);

    afterAll(async () => {
      await sourcePool?.end();
      const maint = maintenanceUrl();
      for (const db of [sourceDb, targetDb]) {
        try {
          execFileSync("psql", ["--dbname", maint, "-qAt", "-c", `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`], {
            stdio: "ignore",
          });
        } catch {
          /* best-effort */
        }
      }
      if (workDir) await rm(workDir, { recursive: true, force: true });
    });

    it("backup → restore forces auth_hold=true; restore_hold-only release keeps admission closed", async () => {
      const backupPath = join(workDir, "open-auth.zbkp");
      await exportEncryptedBackup(dbUrl(sourceDb), backupPath, masterKey);

      const result = await restoreEncryptedBackup(backupPath, dbUrl(targetDb), masterKey);

      expect(result.restoreHold.applied).toBe(true);
      expect(result.authHold.applied).toBe(true);
      expect(result.authHold.headsForced).toBe(1);
      expect(result.authHold.headKeys).toEqual(
        expect.arrayContaining([{ nodeId, implementerId }]),
      );

      const target = new Pool({ connectionString: dbUrl(targetDb) });
      try {
        const hold = await target.query(
          `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
          [nodeId],
        );
        expect(hold.rows[0].restore_hold).toBe(true);

        const head = await target.query(
          `
          SELECT h.auth_hold AS auth_hold,
                 h.epoch::text AS epoch,
                 e.event_type AS event_type
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

        // Fault 9: clear restore_hold alone → admission still closed on auth_hold.
        const local = {
          lifecycleEpoch: 2n,
          nonceBurnHighWater: 2n,
          terminalEventHash: (
            await target.query(
              `SELECT event_hash FROM reporting_key_lifecycle_events
                WHERE node_id = $1 AND implementer_id = $2 AND epoch = 2`,
              [nodeId, implementerId],
            )
          ).rows[0].event_hash as string,
        };
        const markers = buildScheduledBackupMarkers(local, {
          backupArtifactSha256: "22".repeat(32),
          backupOutputPath: "/offsite/backup.zbkp",
        });
        const decision = evaluateRestoreHoldRelease({ trusted: markers, local });
        expect(decision.release).toBe(true);
        if (!decision.release) return;

        const rel = buildRestoreHoldReleaseUpdate({
          nodeId,
          decision,
          now: new Date("2026-07-26T15:00:00.000Z"),
        });
        await target.query(rel.sql, rel.params as unknown[]);

        const afterRelease = await target.query(
          `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
          [nodeId],
        );
        expect(afterRelease.rows[0].restore_hold).toBe(false);

        const stillHeld = await target.query(
          `SELECT auth_hold FROM reporting_key_lifecycle_heads WHERE node_id = $1`,
          [nodeId],
        );
        expect(stillHeld.rows[0].auth_hold).toBe(true);

        await expect(
          target.query(
            `SELECT reporting_lock_and_assert_admission($1::uuid, $2::uuid, $3::bigint, $4::uuid, now())`,
            [nodeId, implementerId, 2, keyId],
          ),
        ).rejects.toThrow(/lifecycle admission is closed|auth/i);

        // Restore the D1 gate, then prove the shipped operator path releases D1+D2
        // atomically against the pre-restore successful-backup continuity point.
        const forceRestore = buildForceRestoreHoldUpsert({ nodeId, now: new Date() });
        await target.query(forceRestore.sql, forceRestore.params as unknown[]);
        const trusted = buildScheduledBackupMarkers(
          {
            lifecycleEpoch: 1n,
            nonceBurnHighWater: 1n,
            terminalEventHash: EVENT_HASH_1,
          },
          {
            backupArtifactSha256: "33".repeat(32),
            backupOutputPath: backupPath,
          },
        );
        const released = await releaseDualGatesWithTrustedMarkers(dbUrl(targetDb), {
          nodeId,
          trusted,
        });
        expect(released.released).toBe(true);
        if (!released.released) return;
        expect(released.authHeadsReleased).toBe(1);

        const opened = await target.query(
          `SELECT r.restore_hold, h.auth_hold, h.epoch::text, e.event_type
             FROM reporting_restore_state r
             JOIN reporting_key_lifecycle_heads h ON h.node_id = r.node_id
             JOIN reporting_key_lifecycle_events e ON e.id = h.lifecycle_event_id
            WHERE r.node_id = $1 AND h.implementer_id = $2`,
          [nodeId, implementerId],
        );
        expect(opened.rows[0]).toMatchObject({
          restore_hold: false,
          auth_hold: false,
          epoch: "3",
          event_type: "AUTH_HOLD_RELEASED",
        });
        await expect(
          target.query(
            `SELECT reporting_lock_and_assert_admission($1::uuid, $2::uuid, $3::bigint, $4::uuid, now())`,
            [nodeId, implementerId, 3, keyId],
          ),
        ).resolves.toBeDefined();
      } finally {
        await target.end();
      }
    }, 90_000);

    it("force auth-hold SQL shape rejects bare head UPDATE", () => {
      const built = buildForceAuthHoldSetStatements({
        nodeId,
        implementerId,
        priorEpoch: 1n,
        previousEventId: event1Id,
        previousEventHash: EVENT_HASH_1,
        currentKeyId: keyId,
        priorKeyId: null,
        overlapExpiresAt: null,
        now: new Date("2026-07-26T12:00:00.000Z"),
      });
      expect(built.eventSql).toMatch(/AUTH_HOLD_SET/);
      expect(built.advanceSql).toMatch(/reporting_advance_lifecycle_head/);
      expect(built.eventSql + built.advanceSql).not.toMatch(
        /UPDATE\s+reporting_key_lifecycle_heads/i,
      );
    });
  },
);
