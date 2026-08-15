/**
 * send-external-landing-pg.test.ts
 *
 * Real PostgreSQL + real DDL drills for the landing DB-TX:
 *   1. AWAITING_REDEMPTION → EXTERNAL_SEND_LANDED co-commits body/event/proof-access; lease held
 *   2. NEEDS_ATTENTION → EXTERNAL_SEND_LANDED (distinct entry)
 *   3. Status guard: wrong status leaves zero landing rows
 *   4. Second land rejected; single event remains
 *   5. Landing record insert-only
 *   6. No DELETE FROM wallet_active_leases in the landing store
 *
 * Harness mirrors test/send-external-create-pg.test.ts.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "send_external_landing_send_landing_";
const EXPECTED_DRILL_COUNT = 6;

const NODE_ID = "a0000000-0000-4000-8000-000000000001";
const IMPL_ID = "a0000000-0000-4000-8000-000000000002";
const WALLET_ID = "a0000000-0000-4000-8000-000000000003";
const KEY_ID = "a0000000-0000-4000-8000-000000000004";
const OBS_ID = "a0000000-0000-4000-8000-000000000005";
const OP_A = "a0000000-0000-4000-8000-000000000010";
const OP_B = "a0000000-0000-4000-8000-000000000011";
const OP_C = "a0000000-0000-4000-8000-000000000012";

const DEST = `${"D".repeat(43)}=`;
const PUBKEY = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;
const SHA = "a".repeat(64);

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdlFile = (db: string, path: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", path], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${path} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const probePostgres = (): boolean => {
  try {
    execFileSync("psql", ["-d", MAINTENANCE_DB, "-c", "SELECT 1"], {
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
};

const seedNode = (db: string): void => {
  psqlMust(
    db,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
      `('${NODE_ID}', 'send-external-landing-landing', '${PUBKEY}') ON CONFLICT (id) DO NOTHING;`,
  );
};

// wallets(id) + full recovery columns; recovery stamped via UPDATE (FK cycle).
const seedWallet = (db: string, walletId: string): void => {
  const recoveryId = "a0000000-0000-4000-8000-000000000090";
  const exportSha = "e".repeat(64);
  psqlMust(
    db,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
      `VALUES ('${walletId}', '${NODE_ID}', '${PUBKEY}', 'node_generated', 'AVAILABLE'); ` +
      `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${exportSha}', '${PUBKEY}', ` +
      `'${recoveryId}', now(), 'send-external-landing-landing-test'); ` +
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
      `WHERE id = '${walletId}';`,
  );
};

let artifactSeq = 0;

const insertOp = (
  db: string,
  opId: string,
  status: string,
  idemKey: string,
  attention: boolean,
): void => {
  artifactSeq += 1;
  const artifactId = `a0000000-0000-4000-8000-${String(artifactSeq).padStart(12, "0")}`;
  // CREATED is only legal with APPROVAL_PENDING; delivered partials use PARTIAL_DELIVERED.
  const formation = status === "CREATED" ? "APPROVAL_PENDING" : "PARTIAL_DELIVERED";
  // attention_required ↔ attention_reason co-presence CHECK.
  const attentionReason = attention ? "'UNEXPECTED_HEAD_CHANGE'" : "NULL";
  const attentionEpisode = attention ? 1 : 0;
  psqlMust(
    db,
    `INSERT INTO send_operations (` +
      `operation_id, implementer_id, node_id, kind, status, row_version, ` +
      `attention_required, attention_reason, attention_episode, formation_state, ` +
      `http_method, route, idempotency_key, ` +
      `request_sha256, source_wallet_id, destination_address, amount_zkz` +
      `) VALUES (` +
      `'${opId}', '${IMPL_ID}', '${NODE_ID}', 'SEND_EXTERNAL', '${status}', 1, ` +
      `${attention}, ${attentionReason}, ${attentionEpisode}, '${formation}', ` +
      `'POST', '/v1/external-sends', '${idemKey}', ` +
      `'${SHA}', '${WALLET_ID}', '${DEST}', '1.5'` +
      `); ` +
      `INSERT INTO send_operation_expected_artifacts (` +
      `artifact_id, operation_id, purpose, canonical_version, signing_key_id, ` +
      `preimage_text, preimage_sha256, signature` +
      `) VALUES (` +
      `'${artifactId}', '${opId}', 'zp-send-external-expected-v1', 1, '${KEY_ID}', ` +
      `'preimage', '${SHA}', '${SIG}'` +
      `); ` +
      `INSERT INTO wallet_active_leases (` +
      `wallet_id, membership_id, lease_group_id, root_operation_id, operation_id, ` +
      `lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id` +
      `) VALUES (` +
      `'${WALLET_ID}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), ` +
      `'SEND_SOURCE', 1, now(), now(), gen_random_uuid()` +
      `) ON CONFLICT (wallet_id) DO NOTHING;`,
  );
};

/**
 * Atomic land mirroring SqlExternalSendLandingStore: the status UPDATE is the
 * arbiter. Zero rows updated → abort (STATUS_GUARD_MISMATCH or ALREADY_LANDED).
 */
const atomicLandSql = (opId: string, entryStatus: string): string => `
BEGIN;
CREATE TEMP TABLE _land_guard ON COMMIT DROP AS
  SELECT operation_id FROM send_operations WHERE false;
WITH u AS (
  UPDATE send_operations SET
    status = 'EXTERNAL_SEND_LANDED',
    attention_required = false,
    attention_reason = NULL,
    row_version = row_version + 1,
    verification_material_available_until = to_timestamp(1800000000000 / 1000.0),
    landed_at = to_timestamp(1700000000000 / 1000.0),
    terminal_observation_id = '${OBS_ID}'
  WHERE operation_id = '${opId}' AND status = '${entryStatus}'
  RETURNING operation_id
),
saved AS (
  INSERT INTO _land_guard SELECT operation_id FROM u RETURNING operation_id
),
ins_rec AS (
  INSERT INTO external_send_landing_records (
    operation_id, attempt_phase, public_execution_phase,
    completed_transaction_text, completed_transaction_sha256,
    terminal_observation_id, source_path_kind, source_path_depth,
    landed_at, verification_material_available_until, entry_status
  )
  SELECT operation_id, 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED',
    '{"inner":{},"step_1_signature":"x","step_2_signature":"y"}', '${SHA}',
    '${OBS_ID}', 'LANDED_EXACT', 0,
    to_timestamp(1700000000000 / 1000.0), to_timestamp(1800000000000 / 1000.0),
    '${entryStatus}'
  FROM saved
  RETURNING operation_id
)
INSERT INTO external_send_landing_events (
  operation_id, event_type, terminal_observation_id, landed_at, data_text
)
SELECT operation_id, 'external_send.landed', '${OBS_ID}',
  to_timestamp(1700000000000 / 1000.0),
  '{"terminal_observation_id":"${OBS_ID}","landed_at":"2023-11-14T22:13:20.000Z"}'
FROM ins_rec;
DO $$
DECLARE
  n int;
  cur text;
BEGIN
  SELECT count(*) INTO n FROM _land_guard;
  IF n = 0 THEN
    SELECT status INTO cur FROM send_operations WHERE operation_id = '${opId}';
    IF cur = 'EXTERNAL_SEND_LANDED' THEN
      RAISE EXCEPTION 'ALREADY_LANDED';
    END IF;
    RAISE EXCEPTION 'STATUS_GUARD_MISMATCH';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}'
  ) THEN
    RAISE EXCEPTION 'LEASE_MISSING';
  END IF;
END $$;
COMMIT;
`;

describe("send-external landing PG drills", () => {
  let db: string | null = null;
  let reachable = false;
  let drillsRun = 0;

  beforeAll(() => {
    reachable = probePostgres();
    if (!reachable) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED=1 but Postgres is unreachable");
      }
      return;
    }
    db = `${DB_PREFIX}${Date.now()}`;
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${db}"`);
    // Base enums/domains + nodes, then custody, then send-external create/landing.
    applyDdlFile(db, join(SCHEMA_DIR, "base-enums-domains.sql"));
    const registry = readFileSync(join(SCHEMA_DIR, "node-implementer-registry.sql"), "utf8");
    const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry)?.[0];
    if (nodes === undefined) {
      throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
    }
    try {
      execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", nodes], {
        encoding: "utf-8",
        timeout: 30_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      const e = err as { stderr?: string };
      throw new Error(`nodes DDL apply failed: ${(e.stderr ?? "").trim() || "unknown"}`);
    }
    applyDdlFile(db, join(SCHEMA_DIR, "custody-eligibility.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-create.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-landing.sql"));
    // attention_reason / attention_episode + co-presence CHECK.
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-expiry.sql"));
    psqlMust(db, verificationModeFixtureSql());
    seedNode(db);
    seedWallet(db, WALLET_ID);
  });

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `send-external-landing PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
      );
    }
  });

  const skip = (): boolean => {
    if (!reachable || db === null) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED but suite did not initialise");
      }
      return true;
    }
    return false;
  };

  it("1. AWAITING_REDEMPTION → EXTERNAL_SEND_LANDED co-commits; lease held", () => {
    if (skip()) return;
    drillsRun += 1;
    insertOp(db!, OP_A, "AWAITING_REDEMPTION", "idem-await-landing-001", false);
    const land = runPsql(db!, atomicLandSql(OP_A, "AWAITING_REDEMPTION"));
    expect(land.ok, land.stderr).toBe(true);

    expect(runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_A}'`).stdout.trim()).toBe(
      "EXTERNAL_SEND_LANDED",
    );
    expect(
      runPsql(
        db!,
        `SELECT attempt_phase||'|'||public_execution_phase FROM external_send_landing_records WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("SETTLED_BODY_PERSISTED|LANDED_VERIFIED");
    expect(
      runPsql(db!, `SELECT event_type FROM external_send_landing_events WHERE operation_id='${OP_A}'`)
        .stdout.trim(),
    ).toBe("external_send.landed");
    expect(
      runPsql(
        db!,
        `SELECT verification_material_available_until IS NOT NULL FROM send_operations WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("t");
    expect(
      runPsql(db!, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`).stdout.trim(),
    ).toBe("1");
  });

  it("2. NEEDS_ATTENTION → EXTERNAL_SEND_LANDED (late reconciliation entry)", () => {
    if (skip()) return;
    drillsRun += 1;
    insertOp(db!, OP_B, "NEEDS_ATTENTION", "idem-attention-landing-02", true);
    const land = runPsql(db!, atomicLandSql(OP_B, "NEEDS_ATTENTION"));
    expect(land.ok, land.stderr).toBe(true);
    expect(runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_B}'`).stdout.trim()).toBe(
      "EXTERNAL_SEND_LANDED",
    );
    expect(
      runPsql(db!, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`).stdout.trim(),
    ).toBe("1");
  });

  it("3. wrong status guard leaves zero landing rows", () => {
    if (skip()) return;
    drillsRun += 1;
    insertOp(db!, OP_C, "CREATED", "idem-created-no-land-003", false);
    // CREATED requires formation_state APPROVAL_PENDING — re-seed may have failed if insert used PARTIAL_DELIVERED
    // Fix: update formation to satisfy created constraint if needed
    runPsql(
      db!,
      `UPDATE send_operations SET formation_state='APPROVAL_PENDING' WHERE operation_id='${OP_C}' AND status='CREATED'`,
    );
    const land = runPsql(db!, atomicLandSql(OP_C, "AWAITING_REDEMPTION"));
    expect(land.ok).toBe(false);
    expect(land.stderr).toMatch(/STATUS_GUARD_MISMATCH/);
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM external_send_landing_records WHERE operation_id='${OP_C}'`,
      ).stdout.trim(),
    ).toBe("0");
    expect(runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_C}'`).stdout.trim()).toBe(
      "CREATED",
    );
  });

  it("4. second land of same op fails; single event remains", () => {
    if (skip()) return;
    drillsRun += 1;
    const again = runPsql(db!, atomicLandSql(OP_A, "AWAITING_REDEMPTION"));
    expect(again.ok).toBe(false);
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM external_send_landing_events WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("1");
  });

  it("5. landing record is insert-only", () => {
    if (skip()) return;
    drillsRun += 1;
    const upd = runPsql(
      db!,
      `UPDATE external_send_landing_records SET source_path_depth = 9 WHERE operation_id='${OP_A}'`,
    );
    expect(upd.ok).toBe(false);
    expect(upd.stderr).toMatch(/EXTERNAL_SEND_LANDING_INSERT_ONLY/);
  });

  it("6. INDEPENDENT landing path leaves SEND_SOURCE held; store has no raw DELETE", () => {
    if (skip()) return;
    drillsRun += 1;
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`).stdout.trim(),
    ).toBe("SEND_SOURCE");
    const storeSrc = readFileSync(join(HERE, "../src/send/landing-sql-store.ts"), "utf8");
    // Raw DELETE remains forbidden; NODE_VERIFIED release goes through releaseLease (ZTR-1304).
    expect(storeSrc).not.toMatch(/DELETE\s+FROM\s+wallet_active_leases/i);
    expect(storeSrc).toMatch(/SELECT_LEASE/);
    expect(storeSrc).toMatch(/NODE_VERIFIED/);
    expect(storeSrc).toMatch(/releaseLease/);
  });
});
