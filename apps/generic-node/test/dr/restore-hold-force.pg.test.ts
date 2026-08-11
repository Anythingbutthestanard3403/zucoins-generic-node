/**
 * Integration: restore of a ZBKP whose dump encodes restore_hold=false must
 * still leave reporting_restore_state.restore_hold=true with release columns
 * cleared.
 *
 * Uses a minimal nodes + reporting_restore_state schema (CHECK-equivalent to
 * drizzle/0000_reporting_persistence.sql) so pg_dump/psql --single-transaction
 * round-trips cleanly. The full reporting DDL has a separate dump-ordering
 * quirk unrelated to the hold path under test.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "../../src/dr/encrypted-backup.js";
import { MINIMAL_DUAL_GATE_SCHEMA_SQL } from "../../src/dr/drill-node-schema.js";
import { buildForceRestoreHoldUpsert } from "../../src/dr/restore-hold.js";

const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-t", "1"], { stdio: "ignore", timeout: 2000 });
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

const EVIDENCE_HASH = "ab".repeat(32);
const EVENT_HASH = "cd".repeat(32);

describe.skipIf(!PG_AVAILABLE)(
  "restore forces restore_hold=true against a released dump",
  () => {
    const stamp = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const sourceDb = `auth_hold_force_src_${stamp}`;
    const targetDb = `auth_hold_force_tgt_${stamp}`;
    const masterKey = "test-backup-master-key-" + randomBytes(8).toString("hex");
    const nodeId = randomUUID();
    let workDir: string;
    let sourcePool: Pool;

    beforeAll(async () => {
      workDir = await mkdtemp(join(tmpdir(), "auth-hold-force-restore-hold-"));
      const maint = maintenanceUrl();
      execFileSync("createdb", ["--maintenance-db", maint, sourceDb], { stdio: "ignore" });
      execFileSync("createdb", ["--maintenance-db", maint, targetDb], { stdio: "ignore" });

      sourcePool = new Pool({ connectionString: dbUrl(sourceDb) });
      await sourcePool.query(MINIMAL_DUAL_GATE_SCHEMA_SQL);
      await sourcePool.query(
        `INSERT INTO nodes (id, display_name) VALUES ($1, $2)`,
        [nodeId, "restore-hold-src"],
      );

      // Dual-gate force requires lifecycle heads (ZTR-1172): seed a held head
      // so auth_hold force is a no-op apply rather than schema-absent failure.
      const implementerId = randomUUID();
      const keyId = randomUUID();
      const eventId = randomUUID();
      const nonceId = randomUUID();
      const sha = (s: string) =>
        createHash("sha256").update(s, "utf8").digest("hex");
      const PUBKEY = "A".repeat(43) + "=";
      const SIG = "A".repeat(86) + "==";
      await sourcePool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
        implementerId,
        "impl",
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
        `INSERT INTO reporting_request_nonces (
          id, node_id, implementer_id, nonce, purpose, route_id, request_class, reporting_key_id,
          lifecycle_epoch, nonce_burn_sequence, request_preimage_text, request_preimage_sha256,
          request_signature, method, raw_target, body_sha256, issued_at, expires_at, received_at,
          consumed_at, retention_class
        ) VALUES (
          $1, $2, $3, $4, 'zp-report-request-v1', 'seed', 'READ', $5, 1, 1, 'seed', $6, $7,
          'GET', '/seed', $6, now(), now() + interval '30 seconds', now(), now(),
          'READ_NO_PRUNE_UNTIL_SAFETY_FREEZE'
        )`,
        [nonceId, nodeId, implementerId, randomUUID(), keyId, sha("seed"), SIG],
      );
      await sourcePool.query(
        `INSERT INTO reporting_key_lifecycle_events (
          id, node_id, implementer_id, epoch, event_type, current_key_id, prior_key_id,
          overlap_expires_at, auth_hold, successor_registered_at, nonce_evidence_id, nonce_purpose,
          enrolment_evidence_id, public_evidence_text, public_evidence_sha256, previous_event_id,
          previous_epoch, previous_event_hash, event_hash, committed_at
        ) VALUES (
          $1, $2, $3, 1, 'FIRST_KEY_ACTIVATED', $4, NULL, NULL, true, now(), $5,
          'zp-report-request-v1', NULL, 'seed', $6, NULL, NULL, NULL, $7, now()
        )`,
        [eventId, nodeId, implementerId, keyId, nonceId, sha("seed"), "11".repeat(32)],
      );
      await sourcePool.query(
        `INSERT INTO reporting_key_lifecycle_heads (
          node_id, implementer_id, epoch, current_key_id, prior_key_id, overlap_expires_at,
          auth_hold, lifecycle_event_id, updated_at
        ) VALUES ($1, $2, 1, $3, NULL, NULL, true, $4, now())`,
        [nodeId, implementerId, keyId, eventId],
      );

      // Seed a *released* restore_hold row — the production-backup case that
      // previously survived restore via ON CONFLICT DO NOTHING.
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
          $1::uuid, false,
          7, 42, $2,
          7, 42, $2,
          'file:/markers.json', '2026-07-26T00:00:00.000Z',
          $3, '2026-07-26T00:00:00.000Z',
          now(), now()
        )
        `,
        [nodeId, EVENT_HASH, EVIDENCE_HASH],
      );

      const held = await sourcePool.query(
        `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
        [nodeId],
      );
      expect(held.rows[0].restore_hold).toBe(false);
    }, 60_000);

    afterAll(async () => {
      await sourcePool?.end();
      const maint = maintenanceUrl();
      try {
        execFileSync("dropdb", ["--if-exists", "--maintenance-db", maint, sourceDb], {
          stdio: "ignore",
        });
      } catch {
        /* best-effort */
      }
      try {
        execFileSync("dropdb", ["--if-exists", "--maintenance-db", maint, targetDb], {
          stdio: "ignore",
        });
      } catch {
        /* best-effort */
      }
      if (workDir) await rm(workDir, { recursive: true, force: true });
    });

    it("backup → restore into empty DB forces hold=true and clears release columns", async () => {
      const backupPath = join(workDir, "released.zbkp");
      await exportEncryptedBackup(dbUrl(sourceDb), backupPath, masterKey);

      const result = await restoreEncryptedBackup(backupPath, dbUrl(targetDb), masterKey);

      expect(result.restoreHold.applied).toBe(true);
      expect(result.restoreHold.nodeIds).toContain(nodeId);

      const targetPool = new Pool({ connectionString: dbUrl(targetDb) });
      try {
        const row = await targetPool.query(
          `
          SELECT restore_hold,
                 local_lifecycle_epoch,
                 local_nonce_burn_high_water,
                 local_event_hash,
                 trusted_lifecycle_epoch,
                 trusted_nonce_burn_high_water,
                 trusted_event_hash,
                 trusted_source_id,
                 trusted_source_observed_at,
                 hold_release_evidence_sha256,
                 hold_released_at
            FROM reporting_restore_state
           WHERE node_id = $1::uuid
          `,
          [nodeId],
        );
        expect(row.rowCount).toBe(1);
        const r = row.rows[0];
        expect(r.restore_hold).toBe(true);
        expect(r.local_lifecycle_epoch).toBeNull();
        expect(r.local_nonce_burn_high_water).toBeNull();
        expect(r.local_event_hash).toBeNull();
        expect(r.trusted_lifecycle_epoch).toBeNull();
        expect(r.trusted_nonce_burn_high_water).toBeNull();
        expect(r.trusted_event_hash).toBeNull();
        expect(r.trusted_source_id).toBeNull();
        expect(r.trusted_source_observed_at).toBeNull();
        expect(r.hold_release_evidence_sha256).toBeNull();
        expect(r.hold_released_at).toBeNull();
      } finally {
        await targetPool.end();
      }
    }, 60_000);

    it("force upsert SQL rejects DO NOTHING (string shape guard)", () => {
      const { sql } = buildForceRestoreHoldUpsert({
        nodeId,
        now: new Date("2026-07-26T12:00:00.000Z"),
      });
      expect(sql).toMatch(/DO UPDATE/);
      expect(sql).not.toMatch(/DO NOTHING/);
    });
  },
);
