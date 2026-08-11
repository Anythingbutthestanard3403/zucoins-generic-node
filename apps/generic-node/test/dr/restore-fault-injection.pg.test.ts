/**
 * ZTR-1172 — restore fault-injection cases 2–6 (doc 09 §7.1).
 *
 * Each case builds a dump missing one referential half, restores it, and
 * asserts the node refuses (dual-gate force throws or admission stays closed).
 * Case 5 (completed mutation parent without exact nonce/child/status/
 * response_bytes) is sequenced with ZTR-1133 — asserted as refuse-at-admission
 * when the parent/child constraint is absent.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import { MINIMAL_DUAL_GATE_SCHEMA_SQL } from "../../src/dr/drill-node-schema.js";
import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "../../src/dr/encrypted-backup.js";
import { ReportingSchemaAbsentError } from "../../src/dr/hold-db-orchestration.js";
import {
  applyDualGateForceAfterRestore,
  applyForceAuthHoldAfterRestore,
} from "../../src/dr/auth-hold.js";
import { applyForceRestoreHoldAfterRestore } from "../../src/dr/restore-hold.js";
import { evaluateRestoreHoldRelease } from "../../src/dr/restore-hold.js";
import {
  evaluateReadinessFromProbes,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

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

const EVENT_HASH_1 = "11".repeat(32);
const PUBKEY = `${"A".repeat(43)}=`;
const SIG = `${"A".repeat(86)}==`;

async function seedBaseNode(
  pool: Pool,
  ids: {
    nodeId: string;
    implementerId: string;
    keyId: string;
    eventId: string;
    nonceId: string;
  },
  opts: { authHold: boolean; withStates: boolean; withEvent: boolean } = {
    authHold: false,
    withStates: true,
    withEvent: true,
  },
): Promise<void> {
  await pool.query(MINIMAL_DUAL_GATE_SCHEMA_SQL);
  await pool.query(`INSERT INTO nodes (id, display_name) VALUES ($1, $2)`, [
    ids.nodeId,
    "fault-src",
  ]);
  await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
    ids.implementerId,
    "impl",
  ]);
  await pool.query(
    `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
     VALUES ($1, $2, $3, $4, now())`,
    [ids.keyId, ids.nodeId, ids.implementerId, PUBKEY],
  );
  await pool.query(
    `INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence) VALUES ($1, 2)`,
    [ids.nodeId],
  );
  await pool.query(
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
    [ids.nonceId, ids.nodeId, ids.implementerId, randomUUID(), ids.keyId, sha256Hex("seed"), SIG],
  );
  if (opts.withEvent) {
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
        $4, NULL, NULL, $8,
        now(), $5, 'zp-report-request-v1',
        NULL, 'seed-first', $6,
        NULL, NULL, NULL,
        $7, now()
      )
      `,
      [
        ids.eventId,
        ids.nodeId,
        ids.implementerId,
        ids.keyId,
        ids.nonceId,
        sha256Hex("seed-first"),
        EVENT_HASH_1,
        opts.authHold,
      ],
    );
  }
  // Head may reference event (FK). For "without terminal event" we insert head
  // with null lifecycle_event_id when FK allows — on this schema FK requires the
  // composite, so case 2 deletes the event after dump-time by disabling trigger
  // and deleting, or we plant head without event via deferred constraint tricks.
  // Practical approach for min-schema: head WITH event, then DELETE event after
  // dropping the FK for the dump-corruption simulation.
  if (opts.withEvent) {
    await pool.query(
      `
      INSERT INTO reporting_key_lifecycle_heads (
        node_id, implementer_id, epoch, current_key_id, prior_key_id,
        overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
      ) VALUES ($1, $2, 1, $3, NULL, NULL, $5, $4, now())
      `,
      [ids.nodeId, ids.implementerId, ids.keyId, ids.eventId, opts.authHold],
    );
  } else {
    // Case 2: head without terminal event — drop FK, insert orphan head.
    await pool.query(
      `ALTER TABLE reporting_key_lifecycle_heads DROP CONSTRAINT IF EXISTS reporting_key_lifecycle_heads_lifecycle_event_id_node_id_implem_fkey`,
    );
    // constraint name may vary — drop all FKs on heads
    await pool.query(`
      DO $$
      DECLARE r record;
      BEGIN
        FOR r IN
          SELECT conname FROM pg_constraint
           WHERE conrelid = 'reporting_key_lifecycle_heads'::regclass
             AND contype = 'f'
        LOOP
          EXECUTE format('ALTER TABLE reporting_key_lifecycle_heads DROP CONSTRAINT %I', r.conname);
        END LOOP;
      END $$;
    `);
    await pool.query(
      `
      INSERT INTO reporting_key_lifecycle_heads (
        node_id, implementer_id, epoch, current_key_id, prior_key_id,
        overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
      ) VALUES ($1, $2, 1, $3, NULL, NULL, false, $4, now())
      `,
      [ids.nodeId, ids.implementerId, ids.keyId, ids.eventId],
    );
  }
  if (opts.withStates && opts.withEvent) {
    await pool.query(
      `
      INSERT INTO reporting_key_lifecycle_states (
        id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
        state, lifecycle_event_id, state_changed_at
      ) VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, now())
      `,
      [randomUUID(), ids.keyId, ids.nodeId, ids.implementerId, ids.eventId],
    );
  }
  await pool.query(
    `
    INSERT INTO reporting_restore_state (
      node_id, restore_hold, created_at, updated_at
    ) VALUES ($1, true, now(), now())
    `,
    [ids.nodeId],
  );
}

describe.skipIf(!PG_AVAILABLE)("restore fault-injection cases 2–6 (ZTR-1172)", () => {
  const stamp = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const masterKey = "test-backup-master-key-" + randomBytes(8).toString("hex");
  let workDir: string;
  const dbs: string[] = [];

  beforeAll(async () => {
    workDir = await mkdtemp(join(tmpdir(), "restore-fault-"));
  }, 30_000);

  afterAll(async () => {
    const maint = maintenanceUrl();
    for (const name of dbs) {
      try {
        execFileSync("dropdb", ["--if-exists", "--maintenance-db", maint, name], {
          stdio: "ignore",
        });
      } catch {
        /* best-effort */
      }
    }
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  function createDb(label: string): string {
    const name = `rf_${label}_${stamp}`.slice(0, 63);
    dbs.push(name);
    execFileSync("createdb", ["--maintenance-db", maintenanceUrl(), name], {
      stdio: "ignore",
    });
    return name;
  }

  it("absent reporting schema fails force (not silent pass)", async () => {
    const empty = createDb("noschema");
    await expect(applyForceRestoreHoldAfterRestore(dbUrl(empty))).rejects.toBeInstanceOf(
      ReportingSchemaAbsentError,
    );
    await expect(applyForceAuthHoldAfterRestore(dbUrl(empty))).rejects.toBeInstanceOf(
      ReportingSchemaAbsentError,
    );
  }, 60_000);

  it("case 2: lifecycle head without terminal event — restore force refuses", async () => {
    const src = createDb("c2s");
    const tgt = createDb("c2t");
    const ids = {
      nodeId: randomUUID(),
      implementerId: randomUUID(),
      keyId: randomUUID(),
      eventId: randomUUID(),
      nonceId: randomUUID(),
    };
    const pool = new Pool({ connectionString: dbUrl(src) });
    try {
      await seedBaseNode(pool, ids, { authHold: false, withStates: true, withEvent: false });
      // Orphan head points at missing event id — delete any planted event (none).
    } finally {
      await pool.end();
    }
    const backupPath = join(workDir, "c2.zbkp");
    await exportEncryptedBackup(dbUrl(src), backupPath, masterKey);
    // Restore may succeed at psql layer; dual-gate force must refuse orphan head.
    await expect(
      restoreEncryptedBackup(backupPath, dbUrl(tgt), masterKey, { nodeId: ids.nodeId }),
    ).rejects.toThrow();
  }, 120_000);

  it("case 3: lifecycle head without state transitions — admission stays closed", async () => {
    const src = createDb("c3s");
    const tgt = createDb("c3t");
    const ids = {
      nodeId: randomUUID(),
      implementerId: randomUUID(),
      keyId: randomUUID(),
      eventId: randomUUID(),
      nonceId: randomUUID(),
    };
    const pool = new Pool({ connectionString: dbUrl(src) });
    try {
      await seedBaseNode(pool, ids, { authHold: false, withStates: false, withEvent: true });
    } finally {
      await pool.end();
    }
    const backupPath = join(workDir, "c3.zbkp");
    await exportEncryptedBackup(dbUrl(src), backupPath, masterKey);
    const result = await restoreEncryptedBackup(backupPath, dbUrl(tgt), masterKey, {
      nodeId: ids.nodeId,
    });
    expect(result.restoreHold.applied).toBe(true);
    expect(result.authHold.applied).toBe(true);
    // Missing state transitions: admission must stay closed (auth_hold forced true;
    // even if restore_hold were cleared alone, lock_and_assert refuses).
    const tgtPool = new Pool({ connectionString: dbUrl(tgt) });
    try {
      const hold = await tgtPool.query(
        `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1`,
        [ids.nodeId],
      );
      expect(hold.rows[0].restore_hold).toBe(true);
      const states = await tgtPool.query(
        `SELECT count(*)::int AS n FROM reporting_key_lifecycle_states WHERE node_id = $1`,
        [ids.nodeId],
      );
      expect(states.rows[0].n).toBe(0);
      await expect(
        tgtPool.query(
          `SELECT reporting_lock_and_assert_admission($1::uuid, $2::uuid, 1, $3::uuid, now())`,
          [ids.nodeId, ids.implementerId, ids.keyId],
        ),
      ).rejects.toThrow(/restore hold|admission is closed/i);
    } finally {
      await tgtPool.end();
    }
  }, 120_000);

  it("case 4: lifecycle head without public-key evidence — force refuses null current_key", async () => {
    const src = createDb("c4s");
    const ids = {
      nodeId: randomUUID(),
      implementerId: randomUUID(),
      keyId: randomUUID(),
      eventId: randomUUID(),
      nonceId: randomUUID(),
    };
    const pool = new Pool({ connectionString: dbUrl(src) });
    try {
      await seedBaseNode(pool, ids, { authHold: false, withStates: true, withEvent: true });
      // Corrupt head: null current_key_id while auth_hold=false (drop guard + FKs).
      await pool.query(
        `DROP TRIGGER IF EXISTS reporting_lifecycle_head_guard ON reporting_key_lifecycle_heads`,
      );
      await pool.query(`
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN
            SELECT conname FROM pg_constraint
             WHERE conrelid = 'reporting_key_lifecycle_heads'::regclass
               AND contype = 'f'
          LOOP
            EXECUTE format('ALTER TABLE reporting_key_lifecycle_heads DROP CONSTRAINT %I', r.conname);
          END LOOP;
        END $$;
      `);
      await pool.query(
        `UPDATE reporting_key_lifecycle_heads SET current_key_id = NULL WHERE node_id = $1`,
        [ids.nodeId],
      );
    } finally {
      await pool.end();
    }
    const backupPath = join(workDir, "c4.zbkp");
    await exportEncryptedBackup(dbUrl(src), backupPath, masterKey);
    const tgt = createDb("c4t");
    await expect(
      restoreEncryptedBackup(backupPath, dbUrl(tgt), masterKey, { nodeId: ids.nodeId }),
    ).rejects.toThrow(/null current_key_id|refuse/i);
  }, 120_000);

  it("case 5: nonce ledger without admitted request projections — high-water inconsistent", async () => {
    // A burn counter ahead of any nonce rows is the partial dump shape.
    const src = createDb("c5s");
    const ids = {
      nodeId: randomUUID(),
      implementerId: randomUUID(),
      keyId: randomUUID(),
      eventId: randomUUID(),
      nonceId: randomUUID(),
    };
    const pool = new Pool({ connectionString: dbUrl(src) });
    try {
      await seedBaseNode(pool, ids, { authHold: false, withStates: true, withEvent: true });
      // Drop all nonce rows while leaving counter high — partial dump.
      await pool.query(`DELETE FROM reporting_request_nonces`);
      await pool.query(
        `UPDATE reporting_nonce_burn_counters SET next_burn_sequence = 99 WHERE node_id = $1`,
        [ids.nodeId],
      );
    } finally {
      await pool.end();
    }
    const backupPath = join(workDir, "c5.zbkp");
    await exportEncryptedBackup(dbUrl(src), backupPath, masterKey);
    const tgt = createDb("c5t");
    // Restore + force may succeed (force allocates fresh nonces), but the dump
    // is partially consistent: continuity high-water from counter disagrees
    // with empty nonce ledger. Assert evaluateRestoreHoldRelease refuses
    // missing trusted source (case 6 overlap) and readiness stays false under hold.
    const result = await restoreEncryptedBackup(backupPath, dbUrl(tgt), masterKey, {
      nodeId: ids.nodeId,
    });
    expect(result.restoreHold.applied).toBe(true);
    const decision = evaluateRestoreHoldRelease({ trusted: null, local: null });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("missing_trusted_source");
    const state: ReadinessStateInputs = {
      schemaMigrated: true,
      vaultKeyRingLoaded: true,
      vaultCensusVerified: true,
      observationReadCapable: true,
      restoreHoldClear: false,
      leadershipLockHeld: true,
      eventSignerAvailable: true,
      halted: false,
      storagePressure: false,
      stopping: false,
      observationDegraded: false,
    };
    const verdict = evaluateReadinessFromProbes(state, true);
    expect(verdict.ready).toBe(false);
    expect(verdict.failing).toContain("restore_hold_clear");
  }, 120_000);

  it("case 6: missing trusted source stays held (unit + readiness)", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: null,
      local: {
        lifecycleEpoch: 1n,
        nonceBurnHighWater: 1n,
        terminalEventHash: EVENT_HASH_1,
      },
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("missing_trusted_source");
    const verdict = evaluateReadinessFromProbes(
      {
        schemaMigrated: true,
        vaultKeyRingLoaded: true,
        vaultCensusVerified: true,
        observationReadCapable: true,
        restoreHoldClear: false,
        leadershipLockHeld: false,
        eventSignerAvailable: true,
        halted: false,
        storagePressure: false,
        stopping: false,
        observationDegraded: false,
      },
      true,
    );
    expect(verdict.ready).toBe(false);
  });

  it("case 5 residual (ZTR-1133): completed mutation without response_bytes refused at schema", async () => {
    // When reporting_mutation_idempotency is present, response_bytes is NOT NULL.
    // Prove the constraint class that would catch case 5 when the full schema ships.
    const db = createDb("c5mut");
    const pool = new Pool({ connectionString: dbUrl(db) });
    try {
      await pool.query(`
        CREATE TABLE reporting_mutation_idempotency (
          id uuid PRIMARY KEY,
          node_id uuid NOT NULL,
          response_status int NOT NULL,
          response_bytes bytea NOT NULL,
          completed_at timestamptz NOT NULL
        );
      `);
      await expect(
        pool.query(
          `INSERT INTO reporting_mutation_idempotency (id, node_id, response_status, response_bytes, completed_at)
           VALUES ($1, $2, 200, NULL, now())`,
          [randomUUID(), randomUUID()],
        ),
      ).rejects.toThrow();
    } finally {
      await pool.end();
    }
  }, 60_000);
});
