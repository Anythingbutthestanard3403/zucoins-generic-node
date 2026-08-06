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
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "../../src/dr/encrypted-backup.js";
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

/** Minimal schema carrying the restore_hold CHECK the force-upsert must satisfy. */
const MINIMAL_SCHEMA_SQL = `
CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  display_name text NOT NULL
);

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
`;

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
      await sourcePool.query(MINIMAL_SCHEMA_SQL);
      await sourcePool.query(
        `INSERT INTO nodes (id, display_name) VALUES ($1, $2)`,
        [nodeId, "restore-hold-src"],
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
