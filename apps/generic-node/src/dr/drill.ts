// Disaster-recovery drill for generic-node.
//
// ZTR-1172: takes a real (minimal dual-gate) node backup, restores into a
// throwaway database, asserts the dual hold was forced, boots the readiness
// evaluator + live RESTORE_HOLD_PROBE against the restored DB (deploy-ready
// conjunction fails on restore_hold_clear while hold is forced), and records
// wall-clock RPO/RTO. A green drill is restore verification — not a
// synthetic-table round-trip or a bare SELECT 1.
//
// Throwaway DB lifecycle matches ops/sql-restored-instance.ts
// (createdb/dropdb against a maintenance template).

import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Pool } from "pg";

import {
  evaluateReadinessFromProbes,
  type ReadinessStateInputs,
} from "@zucoins/node-core";

import {
  CachedRestoreHoldProbe,
  NodeReadiness,
  stampRestoreHoldFromDb,
} from "../boot/readiness.js";
import { MINIMAL_DUAL_GATE_SCHEMA_SQL } from "./drill-node-schema.js";
import { releaseDualGatesWithTrustedMarkers } from "./auth-hold.js";
import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "./encrypted-backup.js";
import { ReportingSchemaAbsentError } from "./hold-db-orchestration.js";
import {
  CONTINUITY_MARKER_FORMAT,
  deriveContinuitySnapshot,
} from "./markers.js";

export interface DrillResult {
  passed: boolean;
  backupSha256: string;
  restoreSha256: string;
  /** Wall-clock duration of the full destroy→restore→verify cycle (RTO evidence). */
  durationMs: number;
  /**
   * Recovery-point objective realized by this drill against the protected seed
   * set. 0 means the seed set was fully recovered; post-export writes are
   * deliberately outside the window and asserted absent after restore.
   */
  rpoMs: number;
  /** Concrete data-loss statement — never a qualitative claim. */
  rpoStatement: string;
  steps: string[];
  /** Dual-gate force evidence from the restore path. */
  restoreHoldApplied?: boolean;
  authHoldApplied?: boolean;
  authHoldHeadsForced?: number;
  /** True when a readiness stamp against the restored DB sees restore_hold held. */
  restoreHoldGatesReadiness?: boolean;
}

const SEED_PAYLOADS = ["alpha", "bravo", "charlie"] as const;
const EVENT_HASH_1 = "11".repeat(32);
const PUBKEY = `${"A".repeat(43)}=`;
const SIG = `${"A".repeat(86)}==`;

/**
 * Resolve createdb | dropdb | psql via PG_BIN / POSTGRES_BIN directory or PATH.
 */
export function resolvePgClientBinary(tool: "createdb" | "dropdb" | "psql"): string {
  const binDir = (process.env.PG_BIN ?? process.env.POSTGRES_BIN ?? "").trim();
  if (binDir.length > 0) {
    return join(binDir, tool);
  }
  return tool;
}

function execPgTool(
  tool: "createdb" | "dropdb" | "psql",
  args: readonly string[],
  options: { encoding?: "utf8"; stdio?: "ignore" },
): string {
  const bin = resolvePgClientBinary(tool);
  try {
    const out = execFileSync(bin, [...args], {
      encoding: options.encoding ?? "utf8",
      stdio: options.stdio,
    });
    return typeof out === "string" ? out : "";
  } catch (err) {
    const code =
      err !== null && typeof err === "object" && "code" in err
        ? String((err as { code?: unknown }).code)
        : "";
    if (code === "ENOENT") {
      throw new Error(
        `${tool} not found (resolved as ${JSON.stringify(bin)}). ` +
          `Set PG_BIN or POSTGRES_BIN to the directory containing PostgreSQL client ` +
          `binaries (createdb, dropdb, psql), or add that directory to PATH.`,
      );
    }
    throw err;
  }
}

function psqlSql(databaseUrl: string, statement: string): string {
  return execPgTool(
    "psql",
    ["--quiet", "--tuples-only", "--no-align", "--dbname", databaseUrl, "--command", statement],
    { encoding: "utf8" },
  ).trim();
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Seed a released dual-gate node + RPO payload table into an empty drill DB. */
async function seedDrillNode(
  databaseUrl: string,
  ids: { nodeId: string; implementerId: string; keyId: string; eventId: string; nonceId: string },
): Promise<void> {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  try {
    await pool.query(MINIMAL_DUAL_GATE_SCHEMA_SQL);
    await pool.query(`INSERT INTO nodes (id, display_name) VALUES ($1, $2)`, [
      ids.nodeId,
      "drill-node",
    ]);
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1, $2)`, [
      ids.implementerId,
      "drill-implementer",
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
    const seedSha = sha256Hex("seed");
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
      [ids.nonceId, ids.nodeId, ids.implementerId, randomUUID(), ids.keyId, seedSha, SIG],
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
      ],
    );
    await pool.query(
      `
      INSERT INTO reporting_key_lifecycle_heads (
        node_id, implementer_id, epoch, current_key_id, prior_key_id,
        overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
      ) VALUES ($1, $2, 1, $3, NULL, NULL, false, $4, now())
      `,
      [ids.nodeId, ids.implementerId, ids.keyId, ids.eventId],
    );
    await pool.query(
      `
      INSERT INTO reporting_key_lifecycle_states (
        id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
        state, lifecycle_event_id, state_changed_at
      ) VALUES ($1, $2, $3, $4, 1, 'ACTIVE', $5, now())
      `,
      [randomUUID(), ids.keyId, ids.nodeId, ids.implementerId, ids.eventId],
    );
    // Released restore_hold so post-restore force is observable.
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
        'file:/drill/markers.json', now(),
        $3, now(),
        now(), now()
      )
      `,
      [ids.nodeId, EVENT_HASH_1, sha256Hex("drill-evidence")],
    );
    await pool.query(`
      CREATE TABLE drill_verify (
        id serial PRIMARY KEY,
        payload text NOT NULL,
        written_at timestamptz NOT NULL DEFAULT now()
      )
    `);
    await pool.query(
      `INSERT INTO drill_verify (payload) VALUES ${SEED_PAYLOADS.map((_, i) => `($${i + 1})`).join(", ")}`,
      [...SEED_PAYLOADS],
    );
  } finally {
    await pool.end();
  }
}

/**
 * Execute a full DR drill. `templateUrl` must point at an existing maintenance
 * database (e.g. `.../postgres`) used to create/drop the throwaway drill DB;
 * `masterKey` is the backup KEK secret (BACKUP_MASTER_KEY — not the signing key).
 * Never throws: failures are captured in the returned result with `passed:false`.
 */
export async function runDrill(
  templateUrl: string,
  masterKey: string,
): Promise<DrillResult> {
  const start = Date.now();
  const steps: string[] = [];
  const drillDb = `dr_drill_${randomBytes(4).toString("hex")}`;
  // Swap only the database name (last path segment), preserving any trailing
  // query/params (e.g. `?sslmode=require`) so the drill DB connects with the
  // template's connection parameters. Host encoding is left byte-for-byte intact.
  const drillUrl = templateUrl.replace(/\/[^/?#]*(\?|#|$)/, `/${drillDb}$1`);
  const workDir = await mkdtemp(join(tmpdir(), "dr-drill-"));
  const backupPath = join(workDir, "drill-backup.zbkp");
  const ids = {
    nodeId: randomUUID(),
    implementerId: randomUUID(),
    keyId: randomUUID(),
    eventId: randomUUID(),
    nonceId: randomUUID(),
  };

  try {
    execPgTool("createdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("created throwaway database");

    await seedDrillNode(drillUrl, ids);
    steps.push("seeded dual-gate node schema + RPO seed rows");

    const exportStartedAt = Date.now();
    const backup = await exportEncryptedBackup(drillUrl, backupPath, masterKey);
    const exportedAt = Date.now();
    steps.push(`encrypted backup exported (${backup.bytesWritten} bytes)`);

    // Post-export write: proves RPO is "state after last successful export is lost".
    psqlSql(
      drillUrl,
      "INSERT INTO drill_verify (payload) VALUES ('post-export-unrecoverable');",
    );
    steps.push("wrote post-export row (intentionally outside RPO window)");

    const raw = await readFile(backupPath);
    if (!raw.subarray(0, 4).equals(Buffer.from("ZBKP"))) {
      throw new Error("backup missing ZBKP magic header");
    }
    const asText = raw.toString("latin1");
    if (
      asText.includes("CREATE TABLE") ||
      asText.includes("INSERT INTO") ||
      asText.includes("drill_verify") ||
      asText.includes("reporting_restore_state")
    ) {
      throw new Error("backup contains plaintext SQL — encryption is broken");
    }
    steps.push("verified backup is encrypted (no plaintext SQL)");

    execPgTool("dropdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("destroyed database (simulated disaster)");

    execPgTool("createdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("recreated empty database");

    const restore = await restoreEncryptedBackup(backupPath, drillUrl, masterKey, {
      nodeId: ids.nodeId,
    });
    steps.push(`restored from encrypted backup (${restore.bytesRestored} bytes)`);

    if (!restore.restoreHold.applied) {
      throw new Error("restore_hold force did not apply after restore");
    }
    if (!restore.authHold.applied) {
      throw new Error("auth_hold force did not apply after restore");
    }
    steps.push(
      `dual gate forced (restore_hold nodes=${restore.restoreHold.nodeIds.length}, auth heads=${restore.authHold.headsForced})`,
    );

    const count = psqlSql(drillUrl, "SELECT count(*) FROM drill_verify;");
    if (count !== String(SEED_PAYLOADS.length)) {
      throw new Error(`expected ${SEED_PAYLOADS.length} rows after restore, got ${count}`);
    }
    const payloads = psqlSql(drillUrl, "SELECT payload FROM drill_verify ORDER BY id;"); // contract-allow:order:frozen-sql-text
    if (payloads !== SEED_PAYLOADS.join("\n")) {
      throw new Error(`restored data mismatch: ${payloads}`);
    }
    const postExport = psqlSql(
      drillUrl,
      "SELECT count(*) FROM drill_verify WHERE payload = 'post-export-unrecoverable';",
    );
    if (postExport !== "0") {
      throw new Error("post-export row survived restore — RPO evidence inverted");
    }
    steps.push("verified restored data matches original (post-export row absent)");

    // Boot-against-restored: stamp + evaluate readiness the same way production
    // does (NodeReadiness + stampRestoreHoldFromDb + evaluateReadinessFromProbes).
    // Dual-gate force must leave restore_hold_clear false → ready 503.
    const pool = new Pool({ connectionString: drillUrl, max: 1 });
    try {
      const hold = await pool.query<{ restore_hold: boolean }>(
        `SELECT restore_hold FROM reporting_restore_state WHERE node_id = $1::uuid`,
        [ids.nodeId],
      );
      if (hold.rows[0]?.restore_hold !== true) {
        throw new Error("restored DB does not hold restore_hold=true");
      }
      const auth = await pool.query<{ auth_hold: boolean }>(
        `SELECT auth_hold FROM reporting_key_lifecycle_heads WHERE node_id = $1::uuid`,
        [ids.nodeId],
      );
      if (auth.rowCount === 0 || auth.rows.some((r) => r.auth_hold !== true)) {
        throw new Error("restored lifecycle head not auth_hold=true");
      }

      const readiness = new NodeReadiness(3);
      readiness.markSchemaChecksPassed();
      readiness.setVaultAvailable(true);
      readiness.recordGatewayReadSuccess();
      readiness.setEventSignerAvailable(true);
      const stamp = await stampRestoreHoldFromDb(readiness, pool, ids.nodeId);
      if (stamp.restoreHoldClear !== false || stamp.rowPresent !== true) {
        throw new Error(
          `boot stamp did not hold restore_hold_clear=false (clear=${stamp.restoreHoldClear} row=${stamp.rowPresent})`,
        );
      }
      const probe = new CachedRestoreHoldProbe(readiness, pool, ids.nodeId, 0);
      const live = await probe.refresh();
      if (live.restoreHoldClear !== false) {
        throw new Error("live RESTORE_HOLD_PROBE did not report hold after restore");
      }
      const inputs: ReadinessStateInputs = readiness.core.snapshot();
      const verdict = evaluateReadinessFromProbes(inputs, true);
      if (verdict.ready) {
        throw new Error("readiness evaluator returned ready=true under forced restore_hold");
      }
      if (!verdict.failing.includes("restore_hold_clear")) {
        throw new Error(
          `expected restore_hold_clear in failing checks, got ${verdict.failing.join(",")}`,
        );
      }
      // Prove dual-gate release + live probe re-opens ready without process restart.
      // Local continuity after AUTH_HOLD_SET force projects to the pre-force seed point.
      const local = await deriveContinuitySnapshot(drillUrl, ids.nodeId);
      const released = await releaseDualGatesWithTrustedMarkers(drillUrl, {
        nodeId: ids.nodeId,
        trusted: {
          format: CONTINUITY_MARKER_FORMAT,
          trustedSourceId: "file:/drill/markers.json",
          trustedSourceObservedAt: "2026-01-15T10:00:00.000Z",
          lifecycleEpoch: local.lifecycleEpoch.toString(),
          nonceBurnHighWater: local.nonceBurnHighWater.toString(),
          terminalEventHash: local.terminalEventHash,
          provenance: "successful_scheduled_backup",
          backupArtifactSha256: backup.sha256,
          backupOutputPath: backupPath,
        },
      });
      if (!released.released) {
        throw new Error(
          `dual-gate release refused during drill boot proof: ${"reason" in released.decision ? released.decision.reason : "unknown"}`,
        );
      }
      probe.invalidate();
      const afterRelease = await probe.refresh();
      if (afterRelease.restoreHoldClear !== true) {
        throw new Error("live probe did not clear restore_hold after dual-gate release");
      }
      const releasedVerdict = evaluateReadinessFromProbes(readiness.core.snapshot(), true);
      if (!releasedVerdict.ready) {
        throw new Error(
          `readiness stayed not-ready after hold clear: failing=${releasedVerdict.failing.join(",")}`,
        );
      }
      steps.push(
        "booted readiness evaluator against restored DB (restore_hold gates ready; live probe re-opens after dual-gate release)",
      );
    } finally {
      await pool.end();
    }

    const rpoStatement =
      `RPO = state committed after export at t=${exportedAt} is unrecoverable from this artifact; ` +
      `seed rows (${SEED_PAYLOADS.length}) recovered; post-export row discarded as designed; ` +
      `dual gate forced after restore; exportStartedAt=${exportStartedAt} exportedAt=${exportedAt}.`;

    return {
      passed: true,
      backupSha256: backup.sha256,
      restoreSha256: restore.sha256,
      durationMs: Date.now() - start,
      rpoMs: 0,
      rpoStatement,
      steps,
      restoreHoldApplied: restore.restoreHold.applied,
      authHoldApplied: restore.authHold.applied,
      authHoldHeadsForced: restore.authHold.headsForced,
      restoreHoldGatesReadiness: true,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const schemaAbsent = err instanceof ReportingSchemaAbsentError;
    return {
      passed: false,
      backupSha256: "",
      restoreSha256: "",
      durationMs: Date.now() - start,
      rpoMs: -1,
      rpoStatement: schemaAbsent
        ? `drill failed: reporting schema absent (${(err as ReportingSchemaAbsentError).tableName})`
        : "drill failed before RPO could be measured",
      steps: [...steps, `FAILED: ${msg}`],
    };
  } finally {
    try {
      execPgTool("dropdb", ["--if-exists", "--maintenance-db", templateUrl, drillDb], {
        stdio: "ignore",
      });
    } catch {
      /* best-effort cleanup */
    }
    await rm(workDir, { recursive: true, force: true });
  }
}
