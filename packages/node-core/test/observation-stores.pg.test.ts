/**
 * observation-stores.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database:
 *   - observation-stores.sql applies cleanly after the observation-ledger prerequisites
 *     (wallets stub + observers + gateway_observations).
 *   - wallet_observation_cursors PK / CHECK constraints reject bad inserts (23505 / 23514).
 *   - SqlStreamWriterEffects is a real StreamWriterEffects: captures persist through
 *     gateway_observations + wallet_observation_cursors, and a "restart" (fresh effects
 *     instance with empty process memory) resumes from the persisted cursor with no gap
 *     or duplicate wallet_seq — including consecutive exact-byte suppression (test-12)
 *     and independent dual-observer cursors (test-14).
 *
 * Connectivity: prefers local `psql -d postgres`. Under PG_REQUIRED=1 an undischarged
 * obligation is a hard FAIL.
 */
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SequenceCapture } from "@zucoins/generic-node-contracts/observation";

import {
  createSerializedStreamWriter,
  type ObservationStreamKey,
} from "../src/observation/capture-writer.js";
import {
  createSqlStreamWriterEffects,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/observation/stream-writer-sql.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const OBSERVER_NODE = "11111111-1111-4111-8111-111111111111";
const OBSERVER_PLATFORM = "22222222-2222-4222-8222-222222222222";
const WALLET_PK = `${"A".repeat(43)}=`;
const HEX = "a".repeat(64);
const SIG = `${"A".repeat(86)}==`;
const ENDPOINT_FP = HEX;

const PG_REQUIRED = process.env.PG_REQUIRED === "1";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) args.push("-v", "VERBOSITY=verbose");
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
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

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync(
      "psql",
      ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)],
      { encoding: "utf-8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const extractSqlstate = (stderr: string): string | null => {
  const m =
    /ERROR:\s+\S+.*?\n.*?SQLSTATE:\s+(\d+)/s.exec(stderr) ?? /SQLSTATE[^\d]*(\d+)/.exec(stderr);
  if (m) return m[1] ?? null;
  if (/duplicate key|unique constraint/i.test(stderr)) return SQLSTATE_UNIQUE_VIOLATION;
  if (/check constraint|violates check/i.test(stderr)) return SQLSTATE_CHECK_VIOLATION;
  return null;
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

const sqlLiteral = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (value instanceof Date) return `'${value.toISOString()}'::timestamptz`;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return `E'\\\\x${Buffer.from(value).toString("hex")}'::bytea`;
  }
  if (typeof value === "string") return `'${value.replaceAll("'", "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
};

const makePsqlExecutor = (db: string): SqlExecutor => ({
  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    let sql = text;
    for (let n = params.length; n >= 1; n -= 1) {
      sql = sql.replaceAll(`$${n}`, sqlLiteral(params[n - 1]));
    }
    const isSelect = /^\s*(SELECT|WITH)\b/i.test(sql);
    if (!isSelect) {
      const outcome = runPsql(db, sql.trim().replace(/;\s*$/, ""));
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql write failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr) ?? undefined;
        throw err;
      }
      return { rows: [] };
    }
    const wrapped = `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text FROM (${sql.replace(/;\s*$/, "")}) q`;
    const outcome = runPsql(db, wrapped);
    if (!outcome.ok) {
      throw new Error(outcome.stderr.trim() || "psql select failed");
    }
    const raw = outcome.stdout.trim();
    const rows = JSON.parse(raw === "" ? "[]" : raw) as R[];
    for (const row of rows as Array<Record<string, unknown>>) {
      if (typeof row.raw_response_bytes === "string") {
        const s = row.raw_response_bytes as string;
        if (s.startsWith("\\x")) {
          row.raw_response_bytes = Buffer.from(s.slice(2), "hex");
        }
      }
    }
    return { rows: Array.isArray(rows) ? rows : [] };
  },
});

const fp = (label: string): string => createHash("sha256").update(label).digest("hex");

const headCapture = (opts: {
  bytes: string;
  s: string;
  p: string;
  fpLabel: string;
}): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: new TextEncoder().encode(opts.bytes),
  isGenesis: false,
  sSignature: opts.s,
  pSignature: opts.p,
  semanticFingerprint: fp(opts.fpLabel),
});

const sig = (ch: string): string => `${ch.repeat(86)}==`;

const CAP_A = headCapture({ bytes: "response-A", s: sig("A"), p: "", fpLabel: "fpA" });
const CAP_B = headCapture({
  bytes: "response-B",
  s: sig("B"),
  p: sig("A"),
  fpLabel: "fpB",
});
const CAP_C = headCapture({
  bytes: "response-C",
  s: sig("C"),
  p: sig("B"),
  fpLabel: "fpC",
});

const project = (capture: SequenceCapture) => ({
  endpointFingerprint: ENDPOINT_FP,
  walletId: null as string | null,
  httpStatus: 200,
  walletRole: "sender" as const,
  bAmount: "5.5",
  innerPreimageText: "inner",
  step1Signature: capture.sSignature,
  step2Signature: capture.sSignature,
  completedTransactionText: "body",
  completedTransactionSha256: HEX,
});

let assertionsRun = 0;

describeIfPg("observation-stores real-PG behaviour (hermetic scratch DB)", () => {
  const scratchDb = `observation_stores_stores_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-stores.sql");
    psqlMust(
      scratchDb,
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at) VALUES
         ('${OBSERVER_NODE}', 'NODE', gen_random_uuid(), '${HEX}', now()),
         ('${OBSERVER_PLATFORM}', 'PLATFORM', gen_random_uuid(), '${HEX}', now());`,
    );
  }, 60_000);

  afterAll(() => {
    if (!PG_AVAILABLE) return;
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("observation-stores.sql materializes wallet_observation_cursors", () => {
    const reg = psqlMust(scratchDb, "SELECT to_regclass('public.wallet_observation_cursors');").trim();
    expect(reg).toBe("wallet_observation_cursors");
    assertionsRun += 1;
  });

  it("NEGATIVE: duplicate (observer_id, wallet_public_key) is unique_violation (23505)", () => {
    const obs1 = randomUUID();
    const obs2 = randomUUID();
    psqlMust(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship,
         semantic_fingerprint, state_changed, wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256
       ) VALUES
       ('${obs1}', '${OBSERVER_NODE}', '${HEX}', '${WALLET_PK}', 9001, now(), E'\\\\x01', '${HEX}',
        'VERIFIED_HEAD', 'FIRST', '${HEX}', true, 'sender', '${SIG}', '${SIG}', '5.5',
        'inner', '${SIG}', '${SIG}', 'body', '${HEX}'),
       ('${obs2}', '${OBSERVER_NODE}', '${HEX}', '${WALLET_PK}', 9002, now(), E'\\\\x02', '${HEX}',
        'VERIFIED_HEAD', 'SUCCESSOR', '${HEX}', true, 'sender', '${SIG}', '${SIG}', '5.5',
        'inner', '${SIG}', '${SIG}', 'body', '${HEX}');`,
    );
    psqlMust(
      scratchDb,
      `INSERT INTO wallet_observation_cursors (
         observer_id, wallet_public_key, last_recorded_observation_id,
         last_raw_response_sha256, last_seen_at, consecutive_repeat_count, next_wallet_seq
       ) VALUES ('${OBSERVER_NODE}', '${WALLET_PK}', '${obs1}', '${HEX}', now(), 0, 2);`,
    );
    const dup = runPsql(
      scratchDb,
      `INSERT INTO wallet_observation_cursors (
         observer_id, wallet_public_key, last_recorded_observation_id,
         last_raw_response_sha256, last_seen_at, consecutive_repeat_count, next_wallet_seq
       ) VALUES ('${OBSERVER_NODE}', '${WALLET_PK}', '${obs2}', '${HEX}', now(), 0, 3);`,
      true,
    );
    expect(dup.ok, "duplicate stream cursor must be rejected").toBe(false);
    expect(extractSqlstate(dup.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("NEGATIVE: next_wallet_seq = 0 is check_violation (23514)", () => {
    const obs = randomUUID();
    const pk = `${"B".repeat(43)}=`;
    psqlMust(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES ('${obs}', '${OBSERVER_NODE}', '${HEX}', '${pk}', 1, now(), E'\\\\x00', '${HEX}',
                 'TRANSPORT_ERROR', 'NOT_APPLICABLE');`,
    );
    const bad = runPsql(
      scratchDb,
      `INSERT INTO wallet_observation_cursors (
         observer_id, wallet_public_key, last_recorded_observation_id,
         last_raw_response_sha256, last_seen_at, consecutive_repeat_count, next_wallet_seq
       ) VALUES ('${OBSERVER_NODE}', '${pk}', '${obs}', '${HEX}', now(), 0, 0);`,
      true,
    );
    expect(bad.ok).toBe(false);
    expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("NEGATIVE: consecutive_repeat_count < 0 is check_violation (23514)", () => {
    const obs = randomUUID();
    const pk = `${"C".repeat(43)}=`;
    psqlMust(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES ('${obs}', '${OBSERVER_NODE}', '${HEX}', '${pk}', 1, now(), E'\\\\x00', '${HEX}',
                 'TRANSPORT_ERROR', 'NOT_APPLICABLE');`,
    );
    const bad = runPsql(
      scratchDb,
      `INSERT INTO wallet_observation_cursors (
         observer_id, wallet_public_key, last_recorded_observation_id,
         last_raw_response_sha256, last_seen_at, consecutive_repeat_count, next_wallet_seq
       ) VALUES ('${OBSERVER_NODE}', '${pk}', '${obs}', '${HEX}', now(), -1, 2);`,
      true,
    );
    expect(bad.ok).toBe(false);
    expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("SqlStreamWriterEffects: A,A stores one observation + cursor sighting (test-12)", async () => {
    const pk = `${"D".repeat(43)}=`;
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const sql = makePsqlExecutor(scratchDb);
    const effects = createSqlStreamWriterEffects({
      sql,
      project,
      takeAdvisoryLock: false,
    });
    const writer = createSerializedStreamWriter(effects);

    const first = await writer.capture(key, CAP_A);
    const second = await writer.capture(key, CAP_A);
    expect(first.plan.kind).toBe("APPEND");
    expect(second.plan.kind).toBe("SUPPRESS_AS_SIGHTING");
    if (second.plan.kind === "SUPPRESS_AS_SIGHTING") {
      expect(second.plan.cursor.consecutiveRepeatCount).toBe(1);
    }

    const nObs = psqlMust(
      scratchDb,
      `SELECT count(*) FROM gateway_observations WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(nObs).toBe("1");
    const repeats = psqlMust(
      scratchDb,
      `SELECT consecutive_repeat_count FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(repeats).toBe("1");
    const nextSeq = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(nextSeq).toBe("2");
    assertionsRun += 1;
  });

  it("restart: fresh StreamWriterEffects resumes from persisted cursor with no gap/duplicate", async () => {
    const pk = `${"E".repeat(43)}=`;
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const sql = makePsqlExecutor(scratchDb);

    {
      const effects = createSqlStreamWriterEffects({ sql, project, takeAdvisoryLock: false });
      const writer = createSerializedStreamWriter(effects);
      const r1 = await writer.capture(key, CAP_A);
      const r2 = await writer.capture(key, CAP_B);
      expect(r1.plan.kind).toBe("APPEND");
      expect(r2.plan.kind).toBe("APPEND");
      if (r1.plan.kind === "APPEND") expect(r1.plan.observation.walletSeq).toBe(1);
      if (r2.plan.kind === "APPEND") expect(r2.plan.observation.walletSeq).toBe(2);
    }

    {
      const effects = createSqlStreamWriterEffects({ sql, project, takeAdvisoryLock: false });
      const writer = createSerializedStreamWriter(effects);
      const r3 = await writer.capture(key, CAP_C);
      expect(r3.plan.kind).toBe("APPEND");
      if (r3.plan.kind === "APPEND") {
        expect(r3.plan.observation.walletSeq).toBe(3);
        expect(r3.plan.observation.relationship).toBe("SUCCESSOR");
      }
    }

    const seqs = psqlMust(
      scratchDb,
      `SELECT string_agg(wallet_seq::text, ',' ORDER BY wallet_seq)
         FROM gateway_observations
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(seqs).toBe("1,2,3");
    const nextSeq = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(nextSeq).toBe("4");
    assertionsRun += 1;
  });

  it("test-14: two observers on the same public key keep independent cursors and sequences", async () => {
    const pk = `${"F".repeat(43)}=`;
    const sql = makePsqlExecutor(scratchDb);
    const effects = createSqlStreamWriterEffects({ sql, project, takeAdvisoryLock: false });
    const writer = createSerializedStreamWriter(effects);
    const node: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const platform: ObservationStreamKey = {
      observerId: OBSERVER_PLATFORM,
      walletPublicKey: pk,
    };

    const n = await writer.capture(node, CAP_A);
    const p = await writer.capture(platform, CAP_A);
    expect(n.plan.kind).toBe("APPEND");
    expect(p.plan.kind).toBe("APPEND");
    if (n.plan.kind === "APPEND") expect(n.plan.observation.walletSeq).toBe(1);
    if (p.plan.kind === "APPEND") expect(p.plan.observation.walletSeq).toBe(1);

    const cursors = psqlMust(
      scratchDb,
      `SELECT count(*) FROM wallet_observation_cursors WHERE wallet_public_key='${pk}';`,
    ).trim();
    expect(cursors).toBe("2");
    const nodeSeq = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    const platSeq = psqlMust(
      scratchDb,
      `SELECT next_wallet_seq FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(nodeSeq).toBe("2");
    expect(platSeq).toBe("2");
    assertionsRun += 1;
  });
});

it("obligation guard: real-PG cursor drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        "real-PG observation-stores drills could not run and the local " +
          "environment set PG_REQUIRED=1 — undischarged obligation",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG cursor drills did not all run — undischarged",
  ).toBeGreaterThanOrEqual(6);
});
