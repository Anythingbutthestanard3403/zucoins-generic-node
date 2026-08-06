/**
 * receive-external-landing-pg.test.ts
 *
 * Real PostgreSQL + real DDL drills for the receive landing DB-TX:
 *   1.  READY → RECEIVE_LANDED co-commits proof header, ordered path and receive.landed
 *   2.  two CONCURRENT emitters: exactly one lands, exactly one receive.landed row
 *   3.  stale row_version CAS: zero landing rows, operation stays READY
 *   4.  second land of an already-landed operation is refused; single event remains
 *   5.  a short path aborts the whole DB-TX at COMMIT (no partial path may land)
 *   6.  a backlink-broken path aborts the whole DB-TX at COMMIT
 *   7.  a path mis-anchored at the fresh head aborts the whole DB-TX at COMMIT
 *   8.  the receiver lease row is BYTE-IDENTICAL before and after the transition
 *   9.  all three landing relations are insert-only
 *   10. the unique index refuses a second receive.landed row outright
 *   11. the SQL store contains no statement that mutates wallet_active_leases
 *
 * Harness mirrors test/send-external-landing-pg.test.ts. Governing: operation flows
 * steps 4-5; observation verification; the data model.
 */
import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const execFileAsync = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "receive_external_receive_landing_";
const EXPECTED_DRILL_COUNT = 12;

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const IMPL_ID = "b0000000-0000-4000-8000-000000000002";
const OBS_T0 = "b0000000-0000-4000-8000-000000000005";
const OBS_HEAD = "b0000000-0000-4000-8000-000000000006";

const PUBKEY = `${"P".repeat(43)}=`;
const SIG_A = `${"A".repeat(86)}==`;
const SIG_B = `${"B".repeat(86)}==`;
const SIG_STEP = `${"C".repeat(86)}==`;
const SHA_EXPECTED = "a".repeat(64);
const SHA_HEAD = "b".repeat(64);
const SHA_INNER = "c".repeat(64);
const SHA_MANIFEST = "d".repeat(64);
const SHA_REQUEST = "e".repeat(64);

const LANDED_AT = 1_700_000_000_000;
const AVAILABLE_UNTIL = 1_800_000_000_000;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

/** Same shape as runPsql, but non-blocking so two emitters can genuinely overlap. */
const runPsqlAsync = async (db: string, sql: string): Promise<PsqlOutcome> => {
  try {
    const { stdout } = await execFileAsync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: 30_000 },
    );
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
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${path} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const applyDdlText = (db: string, label: string, sql: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", sql], {
      encoding: "utf-8",
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${label} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
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

/**
 * Extract one top-level `CREATE TABLE <name> ( ... );` block. operations.sql re-declares the
 * same domains and enums base-enums-domains.sql owns (combined greenfield apply is expected
 * to fail — migration-integrity.test.ts pins that), so the assembled schema takes the two
 * relations out of it rather than the whole file.
 */
const createTableBlock = (sql: string, table: string): string => {
  const block = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(sql)?.[0];
  if (block === undefined) {
    throw new Error(`CREATE TABLE ${table} block not found`);
  }
  return block;
};

const seedFixtures = (
  db: string,
  walletId: string,
  recoveryId: string,
  walletPubkey: string,
): void => {
  psqlMust(
    db,
    `INSERT INTO nodes (id, display_name, identity_public_key) ` +
      `VALUES ('${NODE_ID}', 'receive-external-receive-landing', '${PUBKEY}') ON CONFLICT (id) DO NOTHING; ` +
      `INSERT INTO implementers (id, name) ` +
      `VALUES ('${IMPL_ID}', 'receive-external-impl') ON CONFLICT (id) DO NOTHING;`,
  );
  // wallets(id) + recovery columns; recovery stamped via UPDATE (FK cycle).
  // RECEIVE_WINDOW leases demand recovery_verified_at NOT NULL and state = AVAILABLE.
  psqlMust(
    db,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
      `VALUES ('${walletId}', '${NODE_ID}', '${walletPubkey}', 'node_generated', 'AVAILABLE'); ` +
      `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA_REQUEST}', '${walletPubkey}', ` +
      `'${recoveryId}', now(), 'receive-external-landing-test'); ` +
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
      `WHERE id = '${walletId}';`,
  );
};

/** A RECEIVE_EXTERNAL operation at READY with its receiver wallet leased under RECEIVE_WINDOW. */
const insertReadyReceive = (
  db: string,
  opId: string,
  walletId: string,
  idemKey: string,
): void => {
  psqlMust(
    db,
    `INSERT INTO operations (` +
      `id, node_id, implementer_id, kind, status, row_version, amount_zkz, ` +
      `receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key, ` +
      `request_sha256, expiry_unix_time_secs, t0_observation_id` +
      `) VALUES (` +
      `'${opId}', '${NODE_ID}', '${IMPL_ID}', 'RECEIVE_EXTERNAL', 'READY', 1, '10', ` +
      `'${walletId}', 'HOLD', '${opId}', 'receive-external-anchor', '${idemKey}', ` +
      `'${SHA_REQUEST}', '1900000000', '${OBS_T0}'` +
      `); ` +
      `INSERT INTO wallet_active_leases (` +
      `wallet_id, membership_id, lease_group_id, root_operation_id, operation_id, ` +
      `lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id` +
      `) VALUES (` +
      `'${walletId}', gen_random_uuid(), gen_random_uuid(), '${opId}', '${opId}', ` +
      `'RECEIVE_WINDOW', 1, now(), now(), gen_random_uuid()` +
      `) ON CONFLICT (wallet_id) DO NOTHING;`,
  );
};

/** One row of the persisted ordered path. */
interface PathRow {
  readonly index: number;
  readonly sourceKind: string;
  readonly sha: string;
  readonly s: string;
  readonly p: string;
}

const EXACT_PATH: readonly PathRow[] = [
  { index: 0, sourceKind: "EXPECTED_OPERATION", sha: SHA_EXPECTED, s: SIG_A, p: "" },
];

const BURIED_PATH: readonly PathRow[] = [
  { index: 0, sourceKind: "EXPECTED_OPERATION", sha: SHA_EXPECTED, s: SIG_A, p: "" },
  { index: 1, sourceKind: "FRESH_GATEWAY_HEAD", sha: SHA_HEAD, s: SIG_B, p: SIG_A },
];

const pathBodyInsert = (opId: string, row: PathRow): string => {
  const text = `{"body":"${row.sha}"}`;
  return (
    `INSERT INTO receive_landing_path_bodies (` +
    `operation_id, path_index, source_kind, completed_transaction_text, ` +
    `completed_transaction_sha256, completed_transaction_octets, wallet_role, ` +
    `s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256, ` +
    `step_1_signature, step_2_signature` +
    `) VALUES ('${opId}', ${row.index}, '${row.sourceKind}', '${text}', '${row.sha}', ` +
    `octet_length('${text}'), 'receiver', '${row.s}', '${row.p}', '10', ` +
    `'{"inner":"${row.sha}"}', '${SHA_INNER}', '${SIG_STEP}', '${SIG_STEP}');`
  );
};

/**
 * The landing DB-TX, mirroring SqlReceiveLandingStore: guarded CAS → proof header → ordered
 * path → receive.landed → lease presence check → COMMIT. The deferred completeness trigger
 * fires at COMMIT, so an incomplete path aborts everything above it.
 *
 * `headSha` and `bodies` are separated on purpose: passing a head digest the path does not
 * terminate at is exactly the mis-anchored case drill 7 exercises.
 */
const landSql = (options: {
  readonly opId: string;
  readonly walletId: string;
  readonly rowVersion: number;
  readonly bodies: readonly PathRow[];
  readonly headSha?: string;
  readonly declaredBodyCount?: number;
  readonly delaySeconds?: number;
}): string => {
  const bodies = options.bodies;
  const declared = options.declaredBodyCount ?? bodies.length;
  const headSha = options.headSha ?? bodies[bodies.length - 1]!.sha;
  const depth = declared - 1;
  const verdict = depth === 0 ? "LANDED_EXACT" : "LANDED_COMPLETE_PATH";
  const delay = options.delaySeconds ?? 0;
  return `
BEGIN;
${delay > 0 ? `SELECT pg_sleep(${delay});` : ""}
CREATE TEMP TABLE _land_guard ON COMMIT DROP AS
  SELECT id FROM operations WHERE false;
WITH u AS (
  UPDATE operations SET
    status = 'RECEIVE_LANDED',
    row_version = row_version + 1,
    terminal_observation_id = '${OBS_HEAD}',
    verification_material_available_until = to_timestamp(${AVAILABLE_UNTIL} / 1000.0),
    terminal_at = now(),
    updated_at = now()
  WHERE id = '${options.opId}' AND kind = 'RECEIVE_EXTERNAL'
    AND status = 'READY' AND row_version = ${options.rowVersion}
  RETURNING id
)
INSERT INTO _land_guard SELECT id FROM u;
DO $$
DECLARE
  n int;
  cur text;
BEGIN
  SELECT count(*) INTO n FROM _land_guard;
  IF n = 0 THEN
    SELECT status INTO cur FROM operations WHERE id = '${options.opId}';
    IF cur = 'RECEIVE_LANDED' THEN
      RAISE EXCEPTION 'ALREADY_LANDED';
    END IF;
    RAISE EXCEPTION 'STATUS_GUARD_MISMATCH';
  END IF;
END $$;
INSERT INTO receive_landing_proofs (
  operation_id, attempt_phase, public_execution_phase, path_role, wallet_public_key,
  t0_observation_id, fresh_head_observation_id, terminal_observation_id,
  expected_completed_transaction_sha256, fresh_head_completed_transaction_sha256,
  verdict, body_count, path_depth, path_manifest_text, path_manifest_sha256,
  landed_at, verification_material_available_until
) VALUES (
  '${options.opId}', 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED', 'RECEIVER', '${PUBKEY}',
  '${OBS_T0}', '${OBS_HEAD}', '${OBS_HEAD}',
  '${SHA_EXPECTED}', '${headSha}',
  '${verdict}', ${declared}, ${depth}, '{"manifest":"receive-external"}', '${SHA_MANIFEST}',
  to_timestamp(${LANDED_AT} / 1000.0), to_timestamp(${AVAILABLE_UNTIL} / 1000.0)
);
${bodies.map((row) => pathBodyInsert(options.opId, row)).join("\n")}
INSERT INTO receive_landing_events (
  operation_id, event_type, terminal_observation_id, landed_at, data_text
) VALUES (
  '${options.opId}', 'receive.landed', '${OBS_HEAD}',
  to_timestamp(${LANDED_AT} / 1000.0),
  '{"terminal_observation_id":"${OBS_HEAD}","landed_at":"2023-11-14T22:13:20.000Z"}'
);
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${options.walletId}'
  ) THEN
    RAISE EXCEPTION 'LEASE_MISSING';
  END IF;
END $$;
COMMIT;
`;
};

/** md5 of the whole lease row rendered as text — byte identity across the transition. */
const leaseRowDigest = (db: string, walletId: string): string =>
  runPsql(
    db,
    `SELECT md5(l::text) FROM wallet_active_leases l WHERE wallet_id = '${walletId}'`,
  ).stdout.trim();

const countRows = (db: string, table: string, opId: string): string =>
  runPsql(db, `SELECT count(*) FROM ${table} WHERE operation_id = '${opId}'`).stdout.trim();

const statusOf = (db: string, opId: string): string =>
  runPsql(db, `SELECT status FROM operations WHERE id = '${opId}'`).stdout.trim();

let db: string | null = null;
let reachable = false;
let ready = false;
let drillsRun = 0;

describe("receive-external landing PG drills", () => {
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
    // Apply order: domains/enums, the two registry roots, custody (wallets/destinations/
    // leases), the operations relations, then this slice.
    applyDdlFile(db, join(SCHEMA_DIR, "base-enums-domains.sql"));
    const registry = readFileSync(join(SCHEMA_DIR, "node-implementer-registry.sql"), "utf8");
    applyDdlText(
      db,
      "nodes+implementers",
      `${createTableBlock(registry, "nodes")}\n${createTableBlock(registry, "implementers")}`,
    );
    applyDdlFile(db, join(SCHEMA_DIR, "custody-eligibility.sql"));
    const operations = readFileSync(join(SCHEMA_DIR, "operations.sql"), "utf8");
    applyDdlText(
      db,
      "operations+operation_wallets",
      `${createTableBlock(operations, "operations")}\n${createTableBlock(operations, "operation_wallets")}`,
    );
    applyDdlFile(db, join(SCHEMA_DIR, "receive-external-landing.sql"));
    ready = true;
  });

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `receive-external-landing PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
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

  const OP_A = "b0000000-0000-4000-8000-000000000010";
  const OP_B = "b0000000-0000-4000-8000-000000000011";
  const OP_C = "b0000000-0000-4000-8000-000000000012";
  const OP_D = "b0000000-0000-4000-8000-000000000013";
  const OP_E = "b0000000-0000-4000-8000-000000000014";
  const OP_F = "b0000000-0000-4000-8000-000000000015";
  const OP_G = "b0000000-0000-4000-8000-000000000016";
  const W_A = "b0000000-0000-4000-8000-0000000000a0";
  const W_B = "b0000000-0000-4000-8000-0000000000a1";
  const W_C = "b0000000-0000-4000-8000-0000000000a2";
  const W_D = "b0000000-0000-4000-8000-0000000000a3";
  const W_E = "b0000000-0000-4000-8000-0000000000a4";
  const W_F = "b0000000-0000-4000-8000-0000000000a5";
  const W_G = "b0000000-0000-4000-8000-0000000000a6";
  const OP_H = "b0000000-0000-4000-8000-000000000017";
  const W_H = "b0000000-0000-4000-8000-0000000000a7";

  // wallets carries UNIQUE (node_id, public_key), so every drill's wallet needs its own key.
  let walletKeySeq = 0;
  const seedOperation = (opId: string, walletId: string, recoveryId: string, idem: string): void => {
    walletKeySeq += 1;
    const walletPubkey = `${String(walletKeySeq).padStart(43, "W")}=`;
    seedFixtures(db!, walletId, recoveryId, walletPubkey);
    insertReadyReceive(db!, opId, walletId, idem);
  };

  it("1. READY → RECEIVE_LANDED co-commits proof header, ordered path and receive.landed", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_A, W_A, "b0000000-0000-4000-8000-0000000000b0", "idem-receive-external-land-0001");

    const land = runPsql(db!, landSql({ opId: OP_A, walletId: W_A, rowVersion: 1, bodies: BURIED_PATH }));
    expect(land.ok, land.stderr).toBe(true);

    expect(statusOf(db!, OP_A)).toBe("RECEIVE_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT attempt_phase||'|'||public_execution_phase||'|'||verdict||'|'||path_depth ` +
          `FROM receive_landing_proofs WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("SETTLED_BODY_PERSISTED|LANDED_VERIFIED|LANDED_COMPLETE_PATH|1");
    // The FULL ordered path is durable, in index order, backlinked at every hop.
    expect(
      runPsql(
        db!,
        `SELECT string_agg(path_index||':'||source_kind||':'||completed_transaction_sha256, ',' ` +
          `ORDER BY path_index) FROM receive_landing_path_bodies WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe(`0:EXPECTED_OPERATION:${SHA_EXPECTED},1:FRESH_GATEWAY_HEAD:${SHA_HEAD}`);
    expect(countRows(db!, "receive_landing_events", OP_A)).toBe("1");
    expect(
      runPsql(
        db!,
        `SELECT verification_material_available_until IS NOT NULL AND terminal_observation_id ` +
          `IS NOT NULL FROM operations WHERE id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("t");
  });

  it("2. two concurrent emitters: exactly one lands, exactly one receive.landed row", async () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_B, W_B, "b0000000-0000-4000-8000-0000000000b1", "idem-receive-external-race-0002");

    // Both open their transaction and sleep before touching the row, so the second emitter is
    // genuinely inside its transaction when the first takes the row lock.
    const sql = landSql({
      opId: OP_B,
      walletId: W_B,
      rowVersion: 1,
      bodies: BURIED_PATH,
      delaySeconds: 0.4,
    });
    const [first, second] = await Promise.all([
      runPsqlAsync(db!, sql),
      runPsqlAsync(db!, sql),
    ]);

    const winners = [first, second].filter((outcome) => outcome.ok);
    const losers = [first, second].filter((outcome) => !outcome.ok);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    // The loser is refused by the CAS itself, not by a later uniqueness accident.
    expect(losers[0]!.stderr).toMatch(/ALREADY_LANDED|STATUS_GUARD_MISMATCH/);

    expect(statusOf(db!, OP_B)).toBe("RECEIVE_LANDED");
    expect(countRows(db!, "receive_landing_proofs", OP_B)).toBe("1");
    expect(countRows(db!, "receive_landing_events", OP_B)).toBe("1");
    expect(countRows(db!, "receive_landing_path_bodies", OP_B)).toBe("2");
    // The CAS bumped row_version exactly once — a second successful UPDATE would show 3.
    expect(
      runPsql(db!, `SELECT row_version FROM operations WHERE id='${OP_B}'`).stdout.trim(),
    ).toBe("2");
  });

  it("3. a stale row_version leaves the operation READY with zero landing rows", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_C, W_C, "b0000000-0000-4000-8000-0000000000b2", "idem-receive-external-stale-003");

    const land = runPsql(
      db!,
      landSql({ opId: OP_C, walletId: W_C, rowVersion: 7, bodies: BURIED_PATH }),
    );
    expect(land.ok).toBe(false);
    expect(land.stderr).toMatch(/STATUS_GUARD_MISMATCH/);
    expect(statusOf(db!, OP_C)).toBe("READY");
    expect(countRows(db!, "receive_landing_proofs", OP_C)).toBe("0");
    expect(countRows(db!, "receive_landing_path_bodies", OP_C)).toBe("0");
    expect(countRows(db!, "receive_landing_events", OP_C)).toBe("0");
  });

  it("4. a second land of an already-landed operation is refused; single event remains", () => {
    if (skip()) return;
    drillsRun += 1;
    const again = runPsql(
      db!,
      landSql({ opId: OP_A, walletId: W_A, rowVersion: 1, bodies: BURIED_PATH }),
    );
    expect(again.ok).toBe(false);
    expect(again.stderr).toMatch(/ALREADY_LANDED/);
    expect(countRows(db!, "receive_landing_events", OP_A)).toBe("1");
    expect(countRows(db!, "receive_landing_proofs", OP_A)).toBe("1");
  });

  it("5. a short path aborts the whole DB-TX at COMMIT — no partial path may land", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_D, W_D, "b0000000-0000-4000-8000-0000000000b3", "idem-receive-external-short-004");

    // Header declares two bodies; only the expected attempt is inserted.
    const land = runPsql(
      db!,
      landSql({
        opId: OP_D,
        walletId: W_D,
        rowVersion: 1,
        bodies: EXACT_PATH,
        declaredBodyCount: 2,
        headSha: SHA_HEAD,
      }),
    );
    expect(land.ok).toBe(false);
    expect(land.stderr).toMatch(/RECEIVE_LANDING_PATH_INCOMPLETE/);
    expect(statusOf(db!, OP_D)).toBe("READY");
    expect(countRows(db!, "receive_landing_proofs", OP_D)).toBe("0");
    expect(countRows(db!, "receive_landing_events", OP_D)).toBe("0");
  });

  it("6. a backlink-broken path aborts the whole DB-TX at COMMIT", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_E, W_E, "b0000000-0000-4000-8000-0000000000b4", "idem-receive-external-link-0005");

    const broken: readonly PathRow[] = [
      BURIED_PATH[0]!,
      { ...BURIED_PATH[1]!, p: SIG_B },
    ];
    const land = runPsql(db!, landSql({ opId: OP_E, walletId: W_E, rowVersion: 1, bodies: broken }));
    expect(land.ok).toBe(false);
    expect(land.stderr).toMatch(/RECEIVE_LANDING_PATH_BACKLINK_BROKEN/);
    expect(statusOf(db!, OP_E)).toBe("READY");
    expect(countRows(db!, "receive_landing_path_bodies", OP_E)).toBe("0");
  });

  it("7. a path mis-anchored at the fresh head aborts the whole DB-TX at COMMIT", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_F, W_F, "b0000000-0000-4000-8000-0000000000b5", "idem-receive-external-anchor-06");

    // The header claims a head digest the terminal body does not carry.
    const land = runPsql(
      db!,
      landSql({
        opId: OP_F,
        walletId: W_F,
        rowVersion: 1,
        bodies: BURIED_PATH,
        headSha: "f".repeat(64),
      }),
    );
    expect(land.ok).toBe(false);
    expect(land.stderr).toMatch(/RECEIVE_LANDING_PATH_HEAD_ANCHOR_MISMATCH/);
    expect(statusOf(db!, OP_F)).toBe("READY");
    expect(countRows(db!, "receive_landing_proofs", OP_F)).toBe("0");
  });

  it("8. the receiver lease row is byte-identical before and after the transition", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_G, W_G, "b0000000-0000-4000-8000-0000000000b6", "idem-receive-external-lease-007");

    const before = leaseRowDigest(db!, W_G);
    expect(before).toMatch(/^[0-9a-f]{32}$/);
    const land = runPsql(db!, landSql({ opId: OP_G, walletId: W_G, rowVersion: 1, bodies: EXACT_PATH }));
    expect(land.ok, land.stderr).toBe(true);
    expect(statusOf(db!, OP_G)).toBe("RECEIVE_LANDED");

    // Byte identity over the whole row, not a field-by-field spot check.
    expect(leaseRowDigest(db!, W_G)).toBe(before);
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${W_G}'`)
        .stdout.trim(),
    ).toBe("RECEIVE_WINDOW");
    // ...and the lease is still there at all (a released lease would digest to nothing).
    expect(
      runPsql(db!, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${W_G}'`)
        .stdout.trim(),
    ).toBe("1");
  });

  it("9. all three landing relations are insert-only", () => {
    if (skip()) return;
    drillsRun += 1;
    for (const [table, column, value] of [
      ["receive_landing_proofs", "path_depth", "9"],
      ["receive_landing_path_bodies", "b_amount", "'99'"],
      ["receive_landing_events", "data_text", "'{}'"],
    ] as const) {
      const upd = runPsql(
        db!,
        `UPDATE ${table} SET ${column} = ${value} WHERE operation_id='${OP_A}'`,
      );
      expect(upd.ok, `${table} UPDATE should be refused`).toBe(false);
      expect(upd.stderr).toMatch(/RECEIVE_LANDING_INSERT_ONLY/);
      const del = runPsql(db!, `DELETE FROM ${table} WHERE operation_id='${OP_A}'`);
      expect(del.ok, `${table} DELETE should be refused`).toBe(false);
      expect(del.stderr).toMatch(/RECEIVE_LANDING_INSERT_ONLY/);
    }
  });

  it("10. the unique index refuses a second receive.landed row outright", () => {
    if (skip()) return;
    drillsRun += 1;
    const dup = runPsql(
      db!,
      `INSERT INTO receive_landing_events (operation_id, event_type, terminal_observation_id, ` +
        `landed_at, data_text) VALUES ('${OP_A}', 'receive.landed', '${OBS_HEAD}', now(), '{}')`,
    );
    expect(dup.ok).toBe(false);
    expect(dup.stderr).toMatch(/receive_landing_events_one_per_operation/);
    expect(countRows(db!, "receive_landing_events", OP_A)).toBe("1");
  });

  it("11. the landing SQL store never mutates wallet_active_leases", () => {
    if (skip()) return;
    drillsRun += 1;
    const storeSrc = readFileSync(join(HERE, "../src/receive/landing-sql-store.ts"), "utf8");
    expect(storeSrc).not.toMatch(/DELETE\s+FROM\s+wallet_active_leases/i);
    expect(storeSrc).not.toMatch(/UPDATE\s+wallet_active_leases/i);
    expect(storeSrc).not.toMatch(/INSERT\s+INTO\s+wallet_active_leases/i);
    expect(storeSrc).toMatch(/SELECT_LEASE/);
    // Comment-stripped: the slice header names the relation to say it never touches it.
    const ddl = readFileSync(join(SCHEMA_DIR, "receive-external-landing.sql"), "utf8").replace(
      /--.*$/gm,
      "",
    );
    expect(ddl).not.toMatch(/wallet_active_leases/i);
  });

  it("12. a landing with ZERO body rows aborts at COMMIT — the empty path cannot escape", () => {
    if (skip()) return;
    drillsRun += 1;
    seedOperation(OP_H, W_H, "b0000000-0000-4000-8000-0000000000b7", "idem-receive-external-empty-008");

    // Drill 5 declares two bodies and inserts ONE, so the per-body trigger fires and catches
    // it. Here the header declares two and inserts NONE: an AFTER INSERT trigger on
    // receive_landing_path_bodies cannot fire on a table nothing was inserted into, so only
    // the header-side trigger can refuse this transaction.
    const land = runPsql(
      db!,
      landSql({
        opId: OP_H,
        walletId: W_H,
        rowVersion: 1,
        bodies: [],
        declaredBodyCount: 2,
        headSha: SHA_HEAD,
      }),
    );
    expect(land.ok).toBe(false);
    // Named abort from the completeness function itself, not merely "something threw".
    expect(land.stderr).toMatch(/ERROR:\s+RECEIVE_LANDING_PATH_INCOMPLETE/);
    expect(land.stderr).toMatch(/PL\/pgSQL function receive_landing_path_complete\(\)/);

    // The whole DB-TX is gone: no landing, no proof, no event, and the operation is untouched.
    expect(statusOf(db!, OP_H)).toBe("READY");
    expect(countRows(db!, "receive_landing_proofs", OP_H)).toBe("0");
    expect(countRows(db!, "receive_landing_path_bodies", OP_H)).toBe("0");
    expect(countRows(db!, "receive_landing_events", OP_H)).toBe("0");
    expect(
      runPsql(db!, `SELECT row_version FROM operations WHERE id='${OP_H}'`).stdout.trim(),
    ).toBe("1");

    // The refusal is a deferred CONSTRAINT trigger on the header relation — the only thing
    // that can see a zero-body path. Asserted against the live catalog, not the DDL text.
    expect(
      runPsql(
        db!,
        `SELECT t.tgdeferrable||'|'||t.tginitdeferred FROM pg_trigger t ` +
          `WHERE t.tgrelid = 'receive_landing_proofs'::regclass ` +
          `AND t.tgname = 'receive_landing_proofs_path_complete'`,
      ).stdout.trim(),
    ).toBe("true|true");
  });
});

// A throwing beforeAll is reported by vitest as `skipped`, never failed. Registered
// AFTER the describe so it runs once the live block has had its chance, and fails under
// PG_REQUIRED=1 whenever that block would otherwise have silently skipped.
registerPgRequiredGuard({
  name: "receive-external landing PG drills",
  databaseUrl: process.env.TEST_DATABASE_URL,
  isReady: () => ready,
  readyMessage:
    "PG_REQUIRED=1 but the receive-landing beforeAll never completed — the landing DB-TX, concurrency and lease-identity drills were skipped, not proven",
});
