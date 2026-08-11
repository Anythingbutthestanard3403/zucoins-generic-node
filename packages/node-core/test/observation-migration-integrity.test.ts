/**
 * real-PostgreSQL proof of observation-ledger migration + invariants.
 *
 * Governing:
 * the data model
 * observation verification
 *   packages/generic-node-contracts/src/observation/CONTRACT.md (runtime-lane ownership)
 *
 * REPLACES the prior text-grep / frozen-constant-against-itself suite (QA_CODE_FAIL on
 * ). Every assertion below either executes DDL against a hermetic Postgres, issues
 * real INSERT/UPDATE/DELETE statements, or drives GOLDEN_SEQUENCES through
 * createSqlStreamWriterEffects into the migrated tables and reads COUNT(*) back.
 *
 * Connectivity: local `psql -d postgres`. Under PG_REQUIRED=1 an undischarged obligation
 * is a hard FAIL (never a silent skip).
 */
import { createHash, randomUUID } from "node:crypto";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
// DB-TEST-12: consecutive byte-identical A,A stores one observation; EQUIVALENT_STATE_DIFFERENT_ENVELOPE
// DB-TEST-13: malformed and unverifiable responses always append with raw bytes


import {
  GOLDEN_SEQUENCES,
  type SequenceCapture,
} from "@zucoins/generic-node-contracts/observation";

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
const SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE = "55000";

const OBSERVER_NODE = "11111111-1111-4111-8111-111111111111";
const OBSERVER_PLATFORM = "22222222-2222-4222-8222-222222222222";
const HEX = "a".repeat(64);
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
      timeout: 30_000,
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

/**
 * Parse SQLSTATE from psql stderr. Prefer VERBOSITY=verbose output
 * (`ERROR:  55000: ...` or trailing `SQLSTATE: 55000`). Never invent 55000 from the
 * message text alone — that would pass a wrong ERRCODE with an append-only message.
 */
const extractSqlstate = (stderr: string): string | null => {
  const m =
    /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr) ??
    /SQLSTATE:\s*([0-9A-Z]{5})/.exec(stderr) ??
    /SQLSTATE[^0-9A-Z]*([0-9A-Z]{5})/.exec(stderr);
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

/** Long-lived psql session so BEGIN..COMMIT spans loadPrior + apply (deferred anomaly guard). */
class PsqlSession {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<{ resolve: (line: string) => void; reject: (err: Error) => void }> = [];
  #buffer = "";
  #closed = false;
  #stderr = "";

  constructor(db: string) {
    this.child = spawn(
      "psql",
      ["-d", db, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      let newline = this.#buffer.indexOf("\n");
      while (newline !== -1) {
        const line = this.#buffer.slice(0, newline);
        this.#buffer = this.#buffer.slice(newline + 1);
        const waiter = this.#pending.shift();
        if (waiter) waiter.resolve(line);
        newline = this.#buffer.indexOf("\n");
      }
    });
    this.child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
    });
    this.child.on("close", () => {
      this.#closed = true;
      while (this.#pending.length > 0) {
        this.#pending.shift()!.reject(new Error(`psql session closed: ${this.#stderr}`));
      }
    });
  }

  async scalar(sql: string): Promise<string> {
    if (this.#closed) throw new Error("psql session already closed");
    const isQuery = /^\s*(SELECT|WITH)\b/i.test(sql);
    const payload = isQuery
      ? `SELECT COALESCE((${sql.replace(/;\s*$/, "")}), '') AS _v;\n`
      : `${sql.replace(/;\s*$/, "")}; SELECT 'ok';\n`;
    this.#stderr = "";
    const line = await new Promise<string>((resolve, reject) => {
      this.#pending.push({ resolve, reject });
      this.child.stdin.write(payload);
    });
    return line.trim();
  }

  async exec(sql: string): Promise<void> {
    await this.scalar(sql);
  }

  kill(): void {
    try {
      this.child.stdin.end();
    } catch {
      /* ignore */
    }
    this.child.kill("SIGKILL");
  }
}

const bindParams = (text: string, params: readonly unknown[]): string => {
  let sql = text;
  for (let n = params.length; n >= 1; n -= 1) {
    sql = sql.replaceAll(`$${n}`, sqlLiteral(params[n - 1]));
  }
  return sql;
};

const makeSessionExecutor = (session: PsqlSession): SqlExecutor => ({
  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const sql = bindParams(text, params);
    const isSelect = /^\s*(SELECT|WITH)\b/i.test(sql);
    if (!isSelect) {
      await session.exec(sql.trim().replace(/;\s*$/, ""));
      return { rows: [] };
    }
    const wrapped = `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text FROM (${sql.replace(/;\s*$/, "")}) q`;
    const raw = await session.scalar(wrapped);
    const rows = JSON.parse(raw === "" || raw === "ok" ? "[]" : raw) as R[];
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

/* ── golden sequence fixtures (valid domain values for real PG CHECKs) ── */

const bytes = (...xs: number[]): Uint8Array => Uint8Array.from(xs);
const fp = (label: string): string => createHash("sha256").update(label).digest("hex");
// padded_base64url_signature: 86 body chars + '=='
const sig = (ch: string): string => `${ch.repeat(86)}==`;

const head = (
  raw: Uint8Array,
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
  rawResponseSha256Override?: string,
): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
  ...(rawResponseSha256Override === undefined ? {} : { rawResponseSha256Override }),
});

const malformed = (raw: Uint8Array): SequenceCapture => ({
  parseResult: "MALFORMED_ENVELOPE",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature: "",
  pSignature: "",
  semanticFingerprint: "",
});

const CAP_A = head(bytes(1, 1, 1, 1), sig("A"), "", fp("fpA"));
const CAP_A_ID = head(bytes(1, 1, 1, 1), sig("A"), "", fp("fpA"));
const CAP_A_PRIME = head(bytes(1, 1, 1, 9), sig("A"), "", fp("fpA"));
const CAP_B = head(bytes(2, 2, 2, 2), sig("B"), sig("A"), fp("fpB"));
const CAP_C = head(bytes(3, 3, 3, 3), sig("C"), sig("B"), fp("fpC"));
const CAP_A_RET = head(bytes(1, 1, 1, 1), sig("A"), "", fp("fpA"));
const CAP_X = malformed(bytes(9, 9));
const CAP_COL1 = head(bytes(1, 1, 1, 1), sig("A"), "", fp("fpA"), "c".repeat(64));
const CAP_COL2 = head(bytes(1, 1, 1, 2), sig("A"), "", fp("fpA"), "c".repeat(64));

const GOLDEN_INPUTS: Record<string, readonly SequenceCapture[]> = {
  AA_BYTE_IDENTICAL: [CAP_A, CAP_A_ID],
  AA_PRIME_WRAPPER: [CAP_A, CAP_A_PRIME],
  ABCA_REGRESSION: [CAP_A, CAP_B, CAP_C, CAP_A_RET],
  MALFORMED_XX: [CAP_X, malformed(bytes(9, 9))],
  DIGEST_COLLISION: [CAP_COL1, CAP_COL2],
};

const project = (capture: SequenceCapture) => {
  const verified =
    capture.parseResult === "VERIFIED_HEAD" || capture.parseResult === "VERIFIED_GENESIS";
  if (!verified) {
    return {
      endpointFingerprint: ENDPOINT_FP,
      walletId: null as string | null,
      httpStatus: null as number | null,
      walletRole: null as "sender" | "receiver" | "genesis" | null,
      bAmount: null as string | null,
      innerPreimageText: null as string | null,
      step1Signature: null as string | null,
      step2Signature: null as string | null,
      completedTransactionText: null as string | null,
      completedTransactionSha256: null as string | null,
    };
  }
  return {
    endpointFingerprint: ENDPOINT_FP,
    walletId: null as string | null,
    httpStatus: 200,
    walletRole: "sender" as const,
    bAmount: "5.5",
    innerPreimageText: "inner",
    step1Signature: capture.sSignature || sig("Z"),
    step2Signature: capture.sSignature || sig("Z"),
    completedTransactionText: "body",
    completedTransactionSha256: HEX,
  };
};

/** One session per writer; each capture is BEGIN..loadPrior..apply..COMMIT. */
const makeWriter = (db: string) => {
  const session = new PsqlSession(db);
  const sql = makeSessionExecutor(session);
  const base = createSqlStreamWriterEffects({
    sql,
    project,
    takeAdvisoryLock: true,
    onAnomalyRequired: async ({ key, observationId, result, capture }) => {
      const kind =
        result.plan.kind === "APPEND" &&
        (result.plan.observation.relationship === "REGRESSION" ||
          result.plan.observation.relationship === "UNEXPLAINED_JUMP" ||
          result.plan.observation.relationship === "GENESIS_AFTER_HISTORY" ||
          result.plan.observation.relationship === "SIGNATURE_COLLISION")
          ? result.plan.observation.relationship
          : capture.parseResult;
      await sql.query(
        `INSERT INTO observation_anomalies (
           id, observation_id, observer_id, wallet_public_key, kind, details, detected_at
         ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)`,
        [
          randomUUID(),
          observationId,
          key.observerId,
          key.walletPublicKey,
          kind,
          `anomaly:${kind}`,
          new Date(),
        ],
      );
    },
  });
  // Wrap loadPrior/apply so the deferred anomaly pairing guard sees both INSERTs.
  const effects = {
    async loadPrior(key: ObservationStreamKey) {
      await session.exec("BEGIN");
      try {
        return await base.loadPrior(key);
      } catch (err) {
        await session.exec("ROLLBACK").catch(() => undefined);
        throw err;
      }
    },
    async apply(
      key: ObservationStreamKey,
      result: Parameters<typeof base.apply>[1],
      capture: SequenceCapture,
    ) {
      try {
        await base.apply(key, result, capture);
        await session.exec("COMMIT");
      } catch (err) {
        await session.exec("ROLLBACK").catch(() => undefined);
        throw err;
      }
    },
  };
  const writer = createSerializedStreamWriter(effects);
  return {
    capture: writer.capture.bind(writer),
    close: () => session.kill(),
  };
};

let streamCounter = 0;
const nextPk = (): string => {
  streamCounter += 1;
  return `S${String(streamCounter).padStart(42, "0")}=`;
};

let assertionsRun = 0;

describeIfPg("observation migration integrity (real PostgreSQL)", () => {
  const scratchDb = `observation_migration_mig_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // wallets stub — closed custody wallets(id); fragment still does not create wallets.
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-stores.sql");
    applyFile(scratchDb, "observation-anomaly-indexes.sql");
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
  }, 60_000);

  /* ── Indicator 1: four tables + CHECKs + zero JSONB ── */

  it("(a) all four tables materialize", () => {
    for (const t of [
      "observers",
      "gateway_observations",
      "wallet_observation_cursors",
      "observation_anomalies",
    ]) {
      expect(psqlMust(scratchDb, `SELECT to_regclass('public.${t}');`).trim()).toBe(t);
    }
    assertionsRun += 1;
  });

  it("(a2) zero JSONB/json columns anywhere in the four tables (mandatory test #8)", () => {
    const n = psqlMust(
      scratchDb,
      `SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN (
            'observers','gateway_observations','wallet_observation_cursors','observation_anomalies'
          )
          AND data_type IN ('json','jsonb');`,
    ).trim();
    expect(n).toBe("0");
    const bytea = psqlMust(
      scratchDb,
      `SELECT data_type FROM information_schema.columns
        WHERE table_name = 'gateway_observations' AND column_name = 'raw_response_bytes';`,
    ).trim();
    expect(bytea).toBe("bytea");
    assertionsRun += 1;
  });

  it("(a3) NEGATIVE: wallet_seq = 0 is check_violation (23514)", () => {
    const bad = runPsql(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES (
         '${randomUUID()}', '${OBSERVER_NODE}', '${HEX}', '${nextPk()}', 0, now(),
         E'\\\\x00', '${HEX}', 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
       );`,
      true,
    );
    expect(bad.ok).toBe(false);
    expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("(a4) NEGATIVE: duplicate (observer, wallet, wallet_seq) is unique_violation (23505)", () => {
    const pk = nextPk();
    const insert = (id: string) =>
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES (
         '${id}', '${OBSERVER_NODE}', '${HEX}', '${pk}', 1, now(),
         E'\\\\x00', '${HEX}', 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
       );`;
    // TRANSPORT_ERROR requires anomaly pair — wrap with anomaly in one tx.
    const id1 = randomUUID();
    const an1 = randomUUID();
    const ok = runPsql(
      scratchDb,
      `BEGIN;
       ${insert(id1)}
       INSERT INTO observation_anomalies (id, observation_id, observer_id, wallet_public_key, kind, details, detected_at)
         VALUES ('${an1}', '${id1}', '${OBSERVER_NODE}', '${pk}', 'TRANSPORT_ERROR', 'd', now());
       COMMIT;`,
    );
    expect(ok.ok, ok.stderr).toBe(true);
    const id2 = randomUUID();
    const an2 = randomUUID();
    const dup = runPsql(
      scratchDb,
      `BEGIN;
       ${insert(id2)}
       INSERT INTO observation_anomalies (id, observation_id, observer_id, wallet_public_key, kind, details, detected_at)
         VALUES ('${an2}', '${id2}', '${OBSERVER_NODE}', '${pk}', 'TRANSPORT_ERROR', 'd', now());
       COMMIT;`,
      true,
    );
    expect(dup.ok).toBe(false);
    expect(extractSqlstate(dup.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("(a5) NEGATIVE: malformed sha256_hex rejected by domain", () => {
    const bad = runPsql(
      scratchDb,
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ('${randomUUID()}', 'NODE', gen_random_uuid(), 'not-a-hex', now());`,
      true,
    );
    expect(bad.ok).toBe(false);
    assertionsRun += 1;
  });

  /* ── Indicator 2: append-only triggers (mandatory test #15) ── */

  it("(b) append-only triggers exist on gateway_observations + observation_anomalies", () => {
    const trg = psqlMust(
      scratchDb,
      `SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger
        WHERE tgname IN (
          'gateway_observations_no_update','gateway_observations_no_delete',
          'gateway_observations_no_truncate',
          'observation_anomalies_no_update','observation_anomalies_no_delete',
          'observation_anomalies_no_truncate',
          'observers_no_update','observers_no_delete','observers_no_truncate'
        );`,
    ).trim();
    expect(trg.split(",").filter(Boolean).length).toBe(9);
    assertionsRun += 1;
  });

  it("(b2) UPDATE/DELETE on gateway_observations rejected (55000 append-only)", () => {
    const pk = nextPk();
    const id = randomUUID();
    const an = randomUUID();
    psqlMust(
      scratchDb,
      `BEGIN;
       INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES (
         '${id}', '${OBSERVER_NODE}', '${HEX}', '${pk}', 1, now(),
         E'\\\\x01', '${HEX}', 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
       );
       INSERT INTO observation_anomalies (id, observation_id, observer_id, wallet_public_key, kind, details, detected_at)
         VALUES ('${an}', '${id}', '${OBSERVER_NODE}', '${pk}', 'TRANSPORT_ERROR', 'd', now());
       COMMIT;`,
    );
    const upd = runPsql(
      scratchDb,
      `UPDATE gateway_observations SET relationship = 'FIRST' WHERE id = '${id}';`,
      true,
    );
    expect(upd.ok).toBe(false);
    expect(upd.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(upd.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);

    const del = runPsql(scratchDb, `DELETE FROM gateway_observations WHERE id = '${id}';`, true);
    expect(del.ok).toBe(false);
    expect(del.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(del.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    assertionsRun += 1;
  });

  it("(b3) UPDATE/DELETE on observation_anomalies rejected (55000 append-only)", () => {
    const pk = nextPk();
    const id = randomUUID();
    const an = randomUUID();
    psqlMust(
      scratchDb,
      `BEGIN;
       INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, raw_response_bytes, raw_response_sha256, parse_result, relationship
       ) VALUES (
         '${id}', '${OBSERVER_NODE}', '${HEX}', '${pk}', 1, now(),
         E'\\\\x02', '${HEX}', 'TRANSPORT_ERROR', 'NOT_APPLICABLE'
       );
       INSERT INTO observation_anomalies (id, observation_id, observer_id, wallet_public_key, kind, details, detected_at)
         VALUES ('${an}', '${id}', '${OBSERVER_NODE}', '${pk}', 'TRANSPORT_ERROR', 'd', now());
       COMMIT;`,
    );
    const upd = runPsql(
      scratchDb,
      `UPDATE observation_anomalies SET details = 'rewritten' WHERE id = '${an}';`,
      true,
    );
    expect(upd.ok).toBe(false);
    expect(upd.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(upd.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);

    const del = runPsql(scratchDb, `DELETE FROM observation_anomalies WHERE id = '${an}';`, true);
    expect(del.ok).toBe(false);
    expect(del.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(del.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    assertionsRun += 1;
  });

  it("(b4) UPDATE/DELETE/TRUNCATE on observers rejected (55000 append-only)", () => {
    // Fresh observer with no child rows so FK cannot mask the append-only trigger.
    const orphan = randomUUID();
    psqlMust(
      scratchDb,
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ('${orphan}', 'NODE', gen_random_uuid(), '${HEX}', now());`,
    );

    const upd = runPsql(
      scratchDb,
      `UPDATE observers SET domain = 'PLATFORM' WHERE id = '${orphan}';`,
      true,
    );
    expect(upd.ok).toBe(false);
    expect(upd.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(upd.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);

    const del = runPsql(scratchDb, `DELETE FROM observers WHERE id = '${orphan}';`, true);
    expect(del.ok).toBe(false);
    expect(del.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(del.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);

    // CASCADE required so PG reaches the BEFORE TRUNCATE trigger (plain TRUNCATE
    // fails earlier with 0A000 FK "referenced by" before user triggers run).
    const trunc = runPsql(scratchDb, `TRUNCATE observers CASCADE;`, true);
    expect(trunc.ok).toBe(false);
    expect(trunc.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(trunc.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    assertionsRun += 1;
  });

  it("(b5) TRUNCATE on gateway_observations + observation_anomalies rejected (55000)", () => {
    const truncObs = runPsql(scratchDb, `TRUNCATE gateway_observations CASCADE;`, true);
    expect(truncObs.ok).toBe(false);
    expect(truncObs.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(truncObs.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);

    const truncAn = runPsql(scratchDb, `TRUNCATE observation_anomalies;`, true);
    expect(truncAn.ok).toBe(false);
    expect(truncAn.stderr).toMatch(/append-only/i);
    expect(extractSqlstate(truncAn.stderr)).toBe(SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    assertionsRun += 1;
  });

  /* ── Indicator 3: five GOLDEN_SEQUENCES through real migrated schema ── */

  it.each([...GOLDEN_SEQUENCES])(
    "(c) golden $name: $description — real INSERT counts match frozen expectation",
    async (golden) => {
      const pk = nextPk();
      const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
      const writer = makeWriter(scratchDb);
      try {
      const inputs = GOLDEN_INPUTS[golden.name]!;
      let suppressed = 0;
      const relationships: string[] = [];
      for (const cap of inputs) {
        const r = await writer.capture(key, cap);
        if (r.plan.kind === "SUPPRESS_AS_SIGHTING") {
          suppressed += 1;
        } else {
          relationships.push(r.plan.observation.relationship);
        }
      }

      const nObs = Number(
        psqlMust(
          scratchDb,
          `SELECT count(*) FROM gateway_observations
            WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
        ).trim(),
      );
      const nAnom = Number(
        psqlMust(
          scratchDb,
          `SELECT count(*) FROM observation_anomalies
            WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
        ).trim(),
      );
      const repeats = Number(
        psqlMust(
          scratchDb,
          `SELECT COALESCE(
             (SELECT consecutive_repeat_count FROM wallet_observation_cursors
               WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}'),
             0);`,
        ).trim(),
      );

      expect(nObs, `${golden.name} observation rows`).toBe(golden.appendedRows);
      expect(nAnom, `${golden.name} anomaly rows`).toBe(golden.anomalyRows);
      expect(suppressed, `${golden.name} suppressed sightings`).toBe(golden.suppressedSightings);
      expect(relationships).toEqual([...golden.relationships]);
      if (golden.name === "AA_BYTE_IDENTICAL") {
        expect(repeats).toBe(1);
      }
      assertionsRun += 1;
      } finally {
        writer.close();
      }
    },
  );

  /* ── Indicator 4: concurrency + restart ── */

  it("(d) serial same-stream captures: contiguous unique wallet_seq, no gap/dup", async () => {
    const pk = nextPk();
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    // Serial same-stream assignment via createSerializedStreamWriter (single-flight).
    // True multi-session concurrent same-stream barrier is
    // capture.concurrency.test.ts — this drill only proves contiguous wallet_seq under
    // the in-process serializer + DB UNIQUE.
    const writer = makeWriter(scratchDb);
    const N = 6;
    const caps = Array.from({ length: N }, (_, i) =>
      head(bytes(10 + i, 20 + i, 30 + i, 40 + i), sig(String.fromCharCode(65 + (i % 26))), "", fp(`c${i}`)),
    );
    // Sequential via writer (same-stream single-flight) — proves contiguous assignment.
    for (const c of caps) {
      const r = await writer.capture(key, c);
      expect(r.plan.kind).toBe("APPEND");
    }
    const seqs = psqlMust(
      scratchDb,
      `SELECT string_agg(wallet_seq::text, ',' ORDER BY wallet_seq)
         FROM gateway_observations
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(seqs).toBe(Array.from({ length: N }, (_, i) => i + 1).join(","));
    writer.close();
    assertionsRun += 1;
  });

  it("(d2) concurrent writers on DISTINCT streams proceed independently", async () => {
    const pk1 = nextPk();
    const pk2 = nextPk();
    const writer = makeWriter(scratchDb);
    const k1: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk1 };
    const k2: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk2 };
    const [r1, r2] = await Promise.all([
      writer.capture(k1, CAP_A),
      writer.capture(k2, CAP_A),
    ]);
    expect(r1.plan.kind).toBe("APPEND");
    expect(r2.plan.kind).toBe("APPEND");
    if (r1.plan.kind === "APPEND") expect(r1.plan.observation.walletSeq).toBe(1);
    if (r2.plan.kind === "APPEND") expect(r2.plan.observation.walletSeq).toBe(1);
    writer.close();
    assertionsRun += 1;
  });

  it("(d3) restart: fresh writer resumes from persisted cursor with no gap/duplicate", async () => {
    const pk = nextPk();
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    {
      const w = makeWriter(scratchDb);
      try {
        expect((await w.capture(key, CAP_A)).plan.kind).toBe("APPEND");
        expect((await w.capture(key, CAP_B)).plan.kind).toBe("APPEND");
      } finally {
        w.close();
      }
    }
    {
      // Fresh effects = process restart; loadPrior reads wallet_observation_cursors.
      const w = makeWriter(scratchDb);
      try {
        const r3 = await w.capture(key, CAP_C);
        expect(r3.plan.kind).toBe("APPEND");
        if (r3.plan.kind === "APPEND") {
          expect(r3.plan.observation.walletSeq).toBe(3);
          expect(r3.plan.observation.relationship).toBe("SUCCESSOR");
        }
      } finally {
        w.close();
      }
    }
    const seqs = psqlMust(
      scratchDb,
      `SELECT string_agg(wallet_seq::text, ',' ORDER BY wallet_seq)
         FROM gateway_observations
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(seqs).toBe("1,2,3");
    assertionsRun += 1;
  });

  it("(d4) node vs platform: independent cursors on the same public key (test #14)", async () => {
    const pk = nextPk();
    const writer = makeWriter(scratchDb);
    const node: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const plat: ObservationStreamKey = { observerId: OBSERVER_PLATFORM, walletPublicKey: pk };
    const n = await writer.capture(node, CAP_A);
    const p = await writer.capture(plat, CAP_A);
    expect(n.plan.kind).toBe("APPEND");
    expect(p.plan.kind).toBe("APPEND");
    const cursors = psqlMust(
      scratchDb,
      `SELECT count(*) FROM wallet_observation_cursors WHERE wallet_public_key='${pk}';`,
    ).trim();
    expect(cursors).toBe("2");
    writer.close();
    assertionsRun += 1;
  });

  /* ── Negative paths from checklist ── */

  it("(e) NEGATIVE: byte-different same-semantic envelope is NOT suppressed (AA_PRIME)", async () => {
    const pk = nextPk();
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const w = makeWriter(scratchDb);
    await w.capture(key, CAP_A);
    const second = await w.capture(key, CAP_A_PRIME);
    expect(second.plan.kind).toBe("APPEND");
    if (second.plan.kind === "APPEND") {
      expect(second.plan.observation.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
    }
    const n = psqlMust(
      scratchDb,
      `SELECT count(*) FROM gateway_observations
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}';`,
    ).trim();
    expect(n).toBe("2");
    w.close();
    assertionsRun += 1;
  });

  it("(e2) NEGATIVE: non-adjacent repeat of old state appends as REGRESSION, not silent dedup", async () => {
    const pk = nextPk();
    const key: ObservationStreamKey = { observerId: OBSERVER_NODE, walletPublicKey: pk };
    const w = makeWriter(scratchDb);
    await w.capture(key, CAP_A);
    await w.capture(key, CAP_B);
    await w.capture(key, CAP_C);
    const ret = await w.capture(key, CAP_A_RET);
    expect(ret.plan.kind).toBe("APPEND");
    if (ret.plan.kind === "APPEND") {
      expect(ret.plan.observation.relationship).toBe("REGRESSION");
      expect(ret.plan.anomalyRequired).toBe(true);
    }
    const nAnom = psqlMust(
      scratchDb,
      `SELECT count(*) FROM observation_anomalies
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}' AND kind='REGRESSION';`,
    ).trim();
    expect(nAnom).toBe("1");
    w.close();
    assertionsRun += 1;
  });
});

const EXPECTED_MIN = 15;

it("obligation guard: real-PG drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        "PG_REQUIRED=1 but PostgreSQL is unreachable — real-PG migration proof undischarged",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG migration drills did not all run — undischarged",
  ).toBeGreaterThanOrEqual(EXPECTED_MIN);
});
