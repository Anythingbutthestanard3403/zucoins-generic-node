/**
 * two-independent-observations.pg.test.ts
 *
 * observation verification two-independent-observations runtime golden suite.
 * Re-homed from (schema/identity landed this is the RUNTIME
 * golden that was never buildable against the schema package alone).
 *
 * Governing:
 * observation verification
 *     (esp. item 7: "the same response in node and platform ledgers is two
 *      independent observations, never one shared row")
 * observation verification
 *     (read stream = (observer_id, wallet_public_key); no cross-observer cursor)
 * observation verification
 *     (node claim ≠ platform verdict; semantic disagreement fails closed)
 * the design decisions (node/platform ledger independence)
 *     (node and platform ledgers, endpoints, cursors, and authority remain independent)
 *
 * What this suite proves against REAL PostgreSQL (hermetic scratch DB):
 *   1. One physical gateway response body, fed into BOTH the NODE-domain and
 *      PLATFORM-domain capture pipelines, yields TWO distinct gateway_observations
 *      rows with different observer_id values — never one shared row.
 *   2. Each stream keeps its own wallet_observation_cursors row and its own
 *      contiguous wallet_seq ladder (UNIQUE(observer_id, wallet_public_key, wallet_seq)).
 *   3. Per-read endpoint_fingerprint is the fingerprint of the endpoint that
 *      actually served THAT read — never a default/inherited value from the other
 *      observer.
 *   4. UNIQUE(domain, owner_id) on observers is enforced under concurrent
 *      registration (exactly one winner).
 * 5. Runtime agreement matrix (items 1–3) holds independently on each
 *      stream when both are fed the same physical bytes: AA suppress, A/A′
 *      EQUIVALENT_STATE_DIFFERENT_ENVELOPE with state_changed=false, A,B,C,A
 *      REGRESSION.
 *   6. Adversarial (AC3): honest dual capture from one physical body leaves
 *      DB-only dual-authority facts (distinct ids, domain join, stored bytes,
 *      FIRST previous_recorded NULL, independent cursors); a later NODE-only
 *      successor does not promote PLATFORM's cursor. PK spoof → 23505. Schema
 *      FKs on previous_recorded / cursor-last remain id-only (DDL residual),
 *      but LOAD_CURSOR requires o.observer_id = c.observer_id and loadPrior
 *      throws CrossObserverCursorError on join miss — planted residual cannot
 *      chain-through or AA-suppress on the next honest PLATFORM capture.
 *
 * Connectivity: local `psql -d postgres` (same pattern as observation-stores.pg.test
 * and capture.concurrency.test). Under PG_REQUIRED=1 an unreachable Postgres is a
 * hard FAIL, never a silent skip.
 *
 * Transaction note: each capture runs inside one BEGIN…COMMIT so the No-blind-retry deferred
 * observation_anomaly_guard (observation-anomaly-indexes.sql) sees the observation
 * row and its matching observation_anomalies row together at commit — the same
 * atomic pairing observation verification steps 8–9 require of the production writer.
 */
import { createHash, randomUUID } from "node:crypto";
import { execFile, execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SequenceCapture } from "@zucoins/generic-node-contracts/observation";

import {
  createSerializedStreamWriter,
  type CaptureWriteResult,
  type ObservationStreamKey,
} from "../src/observation/capture-writer.js";
import {
  createSqlStreamWriterEffects,
  CrossObserverCursorError,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/observation/stream-writer-sql.js";

const execFileAsync = promisify(execFile);

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";

const OBSERVER_NODE = "11111111-1111-4111-8111-111111111111";
const OBSERVER_PLATFORM = "22222222-2222-4222-8222-222222222222";
const OWNER_NODE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_PLATFORM = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

// Distinct endpoint fingerprints: NODE and PLATFORM MUST NOT share a default.
const ENDPOINT_FP_NODE = "a".repeat(64);
const ENDPOINT_FP_PLATFORM = "b".repeat(64);

// Per-test unique PKs — gateway_observations / observers / anomalies are append-only
// tests must not DELETE/TRUNCATE those tables.
let walletPkCounter = 0;
const nextWalletPk = (): string => {
  walletPkCounter += 1;
  const body = `W${String(walletPkCounter).padStart(42, "0")}`;
  return `${body}=`;
};
const SIG = `${"A".repeat(86)}==`;
const HEX = "c".repeat(64);

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
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return {
      ok: false,
      stdout: e.stdout ?? "",
      stderr: (e.stderr ?? "") || (e.message ?? ""),
    };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    const detail = [outcome.stderr, outcome.stdout].map((s) => s.trim()).filter(Boolean).join(" | ");
    throw new Error(`psql failed on ${db}: ${detail || "unknown error"}`);
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

/* ─── long-lived psql session (one connection = one transaction scope) ── */

class PsqlSession {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<{ resolve: (line: string) => void; reject: (err: Error) => void }> = [];
  #buffer = "";
  #closed = false;

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
    this.child.on("close", () => {
      this.#closed = true;
      while (this.#pending.length > 0) {
        this.#pending.shift()!.reject(new Error("psql session closed"));
      }
    });
  }

  async scalar(sql: string): Promise<string> {
    if (this.#closed) throw new Error("psql session already closed");
    const isQuery = /^\s*(SELECT|WITH)\b/i.test(sql);
    const payload = isQuery
      ? `SELECT COALESCE((${sql.replace(/;\s*$/, "")}), '') AS _v;\n`
      : `${sql.replace(/;\s*$/, "")}; SELECT 'ok';\n`;
    const line = await new Promise<string>((resolveLine, reject) => {
      this.#pending.push({ resolve: resolveLine, reject });
      this.child.stdin.write(payload);
    });
    return line.trim();
  }

  async exec(sql: string): Promise<void> {
    await this.scalar(sql);
  }

  /** SELECT returning JSON-array of row objects (empty array when no rows). */
  async queryJson(sql: string): Promise<unknown[]> {
    const wrapped = `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text FROM (${sql.replace(/;\s*$/, "")}) q`;
    // Don't wrap with COALESCE((...), '') — json text is the value.
    if (this.#closed) throw new Error("psql session already closed");
    const payload = `${wrapped};\n`;
    const line = await new Promise<string>((resolveLine, reject) => {
      this.#pending.push({ resolve: resolveLine, reject });
      this.child.stdin.write(payload);
    });
    const raw = line.trim();
    return JSON.parse(raw === "" ? "[]" : raw) as unknown[];
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

/**
 * Session-bound SqlExecutor. All queries share one psql connection so BEGIN/COMMIT
 * enclose a full capture (observation + anomaly) and the No-blind-retry deferred guard can pass.
 */
const makeSessionExecutor = (session: PsqlSession): SqlExecutor => ({
  async query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    let sql = text;
    for (let n = params.length; n >= 1; n -= 1) {
      sql = sql.replaceAll(`$${n}`, sqlLiteral(params[n - 1]));
    }
    const isSelect = /^\s*(SELECT|WITH)\b/i.test(sql);
    if (!isSelect) {
      try {
        await session.exec(sql.trim().replace(/;\s*$/, ""));
      } catch (err) {
        const e = err as Error;
        const wrapped = new Error(e.message || "psql write failed");
        (wrapped as { code?: string }).code = extractSqlstate(e.message) ?? undefined;
        throw wrapped;
      }
      return { rows: [] };
    }
    const rows = (await session.queryJson(sql)) as R[];
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
const sig = (ch: string): string => `${ch.repeat(86)}==`;

/** One physical gateway body — the same Uint8Array instance is fed to both pipelines. */
const physicalBody = (label: string): Uint8Array => new TextEncoder().encode(label);

const headCapture = (opts: {
  bytes: Uint8Array;
  s: string;
  p: string;
  fpLabel: string;
}): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: opts.bytes,
  isGenesis: false,
  sSignature: opts.s,
  pSignature: opts.p,
  semanticFingerprint: fp(opts.fpLabel),
});

// Fixed physical bodies for the matrix. CAP_A_BYTES is the "one physical read".
const CAP_A_BYTES = physicalBody("gateway-response-A");
const CAP_A_PRIME_BYTES = physicalBody("gateway-response-A-whitespace-reordered");
const CAP_B_BYTES = physicalBody("gateway-response-B");
const CAP_C_BYTES = physicalBody("gateway-response-C");

const CAP_A = headCapture({ bytes: CAP_A_BYTES, s: sig("A"), p: "", fpLabel: "fpA" });
const CAP_A_PRIME = headCapture({
  bytes: CAP_A_PRIME_BYTES,
  s: sig("A"),
  p: "",
  fpLabel: "fpA", // same semantic head, different envelope bytes → EQUIVALENT
});
const CAP_B = headCapture({
  bytes: CAP_B_BYTES,
  s: sig("B"),
  p: sig("A"),
  fpLabel: "fpB",
});
const CAP_C = headCapture({
  bytes: CAP_C_BYTES,
  s: sig("C"),
  p: sig("B"),
  fpLabel: "fpC",
});
// Byte-identical recurrence of A after A,B,C → REGRESSION (non-adjacent).
const CAP_A_REGRESSION = headCapture({
  bytes: CAP_A_BYTES,
  s: sig("A"),
  p: "",
  fpLabel: "fpA",
});

const projectFor = (endpointFingerprint: string) => (capture: SequenceCapture) => ({
  endpointFingerprint,
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

const ANOMALY_KINDS = new Set([
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "GENESIS_AFTER_HISTORY",
  "SIGNATURE_COLLISION",
  "TRANSPORT_ERROR",
  "MALFORMED_ENVELOPE",
  "MALFORMED_TRANSACTION",
  "UNVERIFIED_SIGNATURE",
  "WALLET_ROLE_INVALID",
]);

/**
 * Dual-domain capture helper. Each capture opens its OWN session + effects + BEGIN…COMMIT:
 *   - No-blind-retry deferred anomaly pairing runs at commit inside that session
 *   - NODE and PLATFORM never share a transaction, connection, or process-memory map
 *   - Concurrent Promise.all on the two domains is safe (fully isolated)
 *   - loadPrior rebuilds lastObsId from the DB cursor, so fresh effects per capture
 *     still chain previous_recorded_observation_id correctly
 */
function makeDualCapturers(db: string, walletPublicKey: string): {
  captureNode: (input: SequenceCapture) => Promise<CaptureWriteResult>;
  capturePlatform: (input: SequenceCapture) => Promise<CaptureWriteResult>;
  nodeKey: ObservationStreamKey;
  platformKey: ObservationStreamKey;
  walletPublicKey: string;
} {
  const nodeKey: ObservationStreamKey = {
    observerId: OBSERVER_NODE,
    walletPublicKey,
  };
  const platformKey: ObservationStreamKey = {
    observerId: OBSERVER_PLATFORM,
    walletPublicKey,
  };

  const runCapture = async (
    key: ObservationStreamKey,
    endpointFp: string,
    input: SequenceCapture,
  ): Promise<CaptureWriteResult> => {
    const session = new PsqlSession(db);
    try {
      await session.exec("BEGIN");
      // Per-stream serialization lock (observation verification step 1) — independent per observer.
      await session.exec(
        `SELECT pg_advisory_xact_lock(hashtext('${key.observerId}'), hashtext('${key.walletPublicKey}'))`,
      );

      const onAnomalyRequired = async (args: {
        key: ObservationStreamKey;
        observationId: string;
        result: CaptureWriteResult;
        capture: SequenceCapture;
      }): Promise<void> => {
        if (args.result.plan.kind !== "APPEND") return;
        const rel = args.result.plan.observation.relationship;
        const parseKind = args.capture.parseResult;
        const kind = ANOMALY_KINDS.has(rel)
          ? rel
          : ANOMALY_KINDS.has(parseKind)
            ? parseKind
            : "REGRESSION";
        const prior =
          args.result.plan.observation.previousRecordedSeq === null
            ? "NULL"
            : `(SELECT id FROM gateway_observations
                 WHERE observer_id='${args.key.observerId}'
                   AND wallet_public_key='${args.key.walletPublicKey}'
                   AND wallet_seq=${args.result.plan.observation.previousRecordedSeq})`;
        await session.exec(
          `INSERT INTO observation_anomalies (
             id, observation_id, observer_id, wallet_public_key, kind,
             prior_observation_id, details, detected_at
           ) VALUES (
             '${randomUUID()}', '${args.observationId}', '${args.key.observerId}',
             '${args.key.walletPublicKey}', '${kind}', ${prior},
             'fixture golden: ${kind}', now()
           )`,
        );
      };

      const effects = createSqlStreamWriterEffects({
        sql: makeSessionExecutor(session),
        project: projectFor(endpointFp),
        takeAdvisoryLock: false,
        onAnomalyRequired,
      });
      const writer = createSerializedStreamWriter(effects);
      const result = await writer.capture(key, input);
      await session.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        await session.exec("ROLLBACK");
      } catch {
        /* session may already be dead */
      }
      throw err;
    } finally {
      session.kill();
    }
  };

  return {
    captureNode: (input) => runCapture(nodeKey, ENDPOINT_FP_NODE, input),
    capturePlatform: (input) => runCapture(platformKey, ENDPOINT_FP_PLATFORM, input),
    nodeKey,
    platformKey,
    walletPublicKey,
  };
}

function countObs(db: string, observerId: string, pk: string): number {
  return Number(
    psqlMust(
      db,
      `SELECT count(*) FROM gateway_observations
        WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'`,
    ).trim(),
  );
}

function obsIds(db: string, observerId: string, pk: string): string[] {
  return psqlMust(
    db,
    `SELECT id::text FROM gateway_observations
      WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'
      ORDER BY wallet_seq`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
}

function relationships(db: string, observerId: string, pk: string): string[] {
  return psqlMust(
    db,
    `SELECT relationship::text FROM gateway_observations
      WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'
      ORDER BY wallet_seq`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
}

function endpointFingerprints(db: string, observerId: string, pk: string): string[] {
  return psqlMust(
    db,
    `SELECT endpoint_fingerprint FROM gateway_observations
      WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'
      ORDER BY wallet_seq`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
}

function rawDigests(db: string, observerId: string, pk: string): string[] {
  return psqlMust(
    db,
    `SELECT raw_response_sha256 FROM gateway_observations
      WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'
      ORDER BY wallet_seq`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
}

function stateChangedFlags(db: string, observerId: string, pk: string): string[] {
  return psqlMust(
    db,
    `SELECT COALESCE(state_changed::text, 'null') FROM gateway_observations
      WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'
      ORDER BY wallet_seq`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
}

function nextWalletSeq(db: string, observerId: string, pk: string): number {
  return Number(
    psqlMust(
      db,
      `SELECT COALESCE(
         (SELECT next_wallet_seq FROM wallet_observation_cursors
           WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'),
         0)`,
    ).trim(),
  );
}

function consecutiveRepeats(db: string, observerId: string, pk: string): number {
  return Number(
    psqlMust(
      db,
      `SELECT COALESCE(
         (SELECT consecutive_repeat_count FROM wallet_observation_cursors
           WHERE observer_id='${observerId}' AND wallet_public_key='${pk}'),
         0)`,
    ).trim(),
  );
}

function appendKind(result: CaptureWriteResult): string {
  if (result.plan.kind === "APPEND") {
    return `APPEND:${result.plan.observation.relationship}:${result.plan.observation.walletSeq}`;
  }
  return `SUPPRESS:${result.plan.cursor.consecutiveRepeatCount}`;
}

let assertionsRun = 0;

describeIfPg("observation verification two-independent-observations runtime golden (real PG)", () => {
  const scratchDb = `two_independent_dual_obs_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // wallets stub — observation-ledger FKs wallets(id).
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-anomaly-indexes.sql");
    applyFile(scratchDb, "observation-stores.sql");
    // Seed the two independent observer identities.
    psqlMust(
      scratchDb,
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at) VALUES
         ('${OBSERVER_NODE}', 'NODE', '${OWNER_NODE}', '${ENDPOINT_FP_NODE}', now()),
         ('${OBSERVER_PLATFORM}', 'PLATFORM', '${OWNER_PLATFORM}', '${ENDPOINT_FP_PLATFORM}', now());`,
    );
  }, 60_000);

  afterAll(() => {
    if (!PG_AVAILABLE) return;
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("one physical body → NODE + PLATFORM pipelines → two distinct rows, no shared cursor", async () => {
    const pk = nextWalletPk();
    const dual = makeDualCapturers(scratchDb, pk);

    // ONE physical gateway read: the same Uint8Array instance is the capture input for both.
    const physicalRead = CAP_A_BYTES;
    expect(physicalRead).toBe(CAP_A.rawResponseBytes);

    const nodeCapture: SequenceCapture = { ...CAP_A, rawResponseBytes: physicalRead };
    const platformCapture: SequenceCapture = { ...CAP_A, rawResponseBytes: physicalRead };

    const [nodeResult, platformResult] = await Promise.all([
      dual.captureNode(nodeCapture),
      dual.capturePlatform(platformCapture),
    ]);

    expect(nodeResult.plan.kind).toBe("APPEND");
    expect(platformResult.plan.kind).toBe("APPEND");
    if (nodeResult.plan.kind === "APPEND") {
      expect(nodeResult.plan.observation.walletSeq).toBe(1);
      expect(nodeResult.plan.observation.relationship).toBe("FIRST");
    }
    if (platformResult.plan.kind === "APPEND") {
      expect(platformResult.plan.observation.walletSeq).toBe(1);
      expect(platformResult.plan.observation.relationship).toBe("FIRST");
    }

    // Two distinct gateway_observations rows.
    expect(countObs(scratchDb, OBSERVER_NODE, pk)).toBe(1);
    expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(1);
    const nodeIds = obsIds(scratchDb, OBSERVER_NODE, pk);
    const platIds = obsIds(scratchDb, OBSERVER_PLATFORM, pk);
    expect(nodeIds).toHaveLength(1);
    expect(platIds).toHaveLength(1);
    expect(nodeIds[0]).not.toBe(platIds[0]);

    // Same physical digest on both rows — independent observations of one response.
    const nodeDigest = rawDigests(scratchDb, OBSERVER_NODE, pk)[0];
    const platDigest = rawDigests(scratchDb, OBSERVER_PLATFORM, pk)[0];
    expect(nodeDigest).toBe(platDigest);
    expect(nodeDigest).toBe(createHash("sha256").update(physicalRead).digest("hex"));

    // Two independent cursors — no shared cursor row, no cross-observer cursor.
    const cursorCount = Number(
      psqlMust(
        scratchDb,
        `SELECT count(*) FROM wallet_observation_cursors WHERE wallet_public_key='${pk}'`,
      ).trim(),
    );
    expect(cursorCount).toBe(2);
    expect(nextWalletSeq(scratchDb, OBSERVER_NODE, pk)).toBe(2);
    expect(nextWalletSeq(scratchDb, OBSERVER_PLATFORM, pk)).toBe(2);

    // Structural anti-equivocation: UNIQUE(observer_id, wallet_public_key, wallet_seq)
    // permits both domains to hold wallet_seq=1 for the same public key.
    const dualFirst = Number(
      psqlMust(
        scratchDb,
        `SELECT count(*) FROM gateway_observations
          WHERE wallet_public_key='${pk}' AND wallet_seq=1`,
      ).trim(),
    );
    expect(dualFirst).toBe(2);

    assertionsRun += 1;
  });

  it("per-read endpoint_fingerprint matches the endpoint that served THAT observer's read", async () => {
    const pk = nextWalletPk();
    const dual = makeDualCapturers(scratchDb, pk);

    await dual.captureNode(CAP_A);
    await dual.capturePlatform(CAP_A);

    expect(endpointFingerprints(scratchDb, OBSERVER_NODE, pk)).toEqual([ENDPOINT_FP_NODE]);
    expect(endpointFingerprints(scratchDb, OBSERVER_PLATFORM, pk)).toEqual([ENDPOINT_FP_PLATFORM]);
    // Never a default/inherited cross-observer fingerprint.
    expect(endpointFingerprints(scratchDb, OBSERVER_NODE, pk)[0]).not.toBe(ENDPOINT_FP_PLATFORM);
    expect(endpointFingerprints(scratchDb, OBSERVER_PLATFORM, pk)[0]).not.toBe(ENDPOINT_FP_NODE);

    // Observer registry fingerprints stay domain-bound too.
    const reg = psqlMust(
      scratchDb,
      `SELECT domain::text || ':' || gateway_endpoint_fingerprint FROM observers ORDER BY domain`,
    )
      .trim()
      .split("\n");
    expect(reg).toEqual([`NODE:${ENDPOINT_FP_NODE}`, `PLATFORM:${ENDPOINT_FP_PLATFORM}`]);

    assertionsRun += 1;
  });

  it("UNIQUE(domain, owner_id) under concurrent registration — exactly one winner", async () => {
    const raceOwner = randomUUID();
    const id1 = randomUUID();
    const id2 = randomUUID();

    const insertSql = (id: string): string =>
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ('${id}', 'PLATFORM', '${raceOwner}', '${HEX}', now())`;

    const psqlAsync = async (sql: string): Promise<PsqlOutcome> => {
      try {
        const { stdout, stderr } = await execFileAsync(
          "psql",
          ["-d", scratchDb, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
          { timeout: 20_000, encoding: "utf-8" },
        );
        return { ok: true, stdout: stdout ?? "", stderr: stderr ?? "" };
      } catch (err) {
        const e = err as { stdout?: string; stderr?: string };
        return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
      }
    };

    // Two concurrent psql children — Postgres arbitrates UNIQUE(domain, owner_id).
    const [r1, r2] = await Promise.all([psqlAsync(insertSql(id1)), psqlAsync(insertSql(id2))]);
    const winners = [r1, r2].filter((r) => r.ok);
    const losers = [r1, r2].filter((r) => !r.ok);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0]!.stderr).toMatch(/duplicate key|unique|23505/i);

    const count = Number(
      psqlMust(
        scratchDb,
        `SELECT count(*) FROM observers WHERE owner_id='${raceOwner}' AND domain='PLATFORM'`,
      ).trim(),
    );
    expect(count).toBe(1);

    // observers are append-only — race residue stays; seed pair still present.
    const seedCount = Number(
      psqlMust(
        scratchDb,
        `SELECT count(*) FROM observers
          WHERE id IN ('${OBSERVER_NODE}', '${OBSERVER_PLATFORM}')`,
      ).trim(),
    );
    expect(seedCount).toBe(2);

    assertionsRun += 1;
  });

  it("matrix on BOTH streams from the same physical bytes (AA / A·A′ / ABCA)", async () => {
    // --- AA: exact byte-identical → one append + sighting counter on EACH stream ---
    {
      const pk = nextWalletPk();
      const dual = makeDualCapturers(scratchDb, pk);
      const aaNode1 = await dual.captureNode(CAP_A);
      const aaNode2 = await dual.captureNode(CAP_A);
      const aaPlat1 = await dual.capturePlatform(CAP_A);
      const aaPlat2 = await dual.capturePlatform(CAP_A);

      expect(aaNode1.plan.kind).toBe("APPEND");
      expect(aaNode2.plan.kind).toBe("SUPPRESS_AS_SIGHTING");
      expect(aaPlat1.plan.kind).toBe("APPEND");
      expect(aaPlat2.plan.kind).toBe("SUPPRESS_AS_SIGHTING");
      expect(countObs(scratchDb, OBSERVER_NODE, pk)).toBe(1);
      expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(1);
      expect(consecutiveRepeats(scratchDb, OBSERVER_NODE, pk)).toBe(1);
      expect(consecutiveRepeats(scratchDb, OBSERVER_PLATFORM, pk)).toBe(1);
    }

    // --- A,A′: same head, different envelope → EQUIVALENT, state_changed=false ---
    {
      const pk = nextWalletPk();
      const dual = makeDualCapturers(scratchDb, pk);
      await dual.captureNode(CAP_A);
      const nodePrime = await dual.captureNode(CAP_A_PRIME);
      await dual.capturePlatform(CAP_A);
      const platPrime = await dual.capturePlatform(CAP_A_PRIME);

      expect(appendKind(nodePrime)).toBe("APPEND:EQUIVALENT_STATE_DIFFERENT_ENVELOPE:2");
      expect(appendKind(platPrime)).toBe("APPEND:EQUIVALENT_STATE_DIFFERENT_ENVELOPE:2");
      expect(relationships(scratchDb, OBSERVER_NODE, pk)).toEqual([
        "FIRST",
        "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      ]);
      expect(relationships(scratchDb, OBSERVER_PLATFORM, pk)).toEqual([
        "FIRST",
        "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      ]);
      expect(stateChangedFlags(scratchDb, OBSERVER_NODE, pk)).toEqual(["true", "false"]);
      expect(stateChangedFlags(scratchDb, OBSERVER_PLATFORM, pk)).toEqual(["true", "false"]);
    }

    // --- A,B,C,A → four rows, final REGRESSION, on EACH stream independently ---
    {
      const pk = nextWalletPk();
      const dual = makeDualCapturers(scratchDb, pk);
      for (const cap of [CAP_A, CAP_B, CAP_C, CAP_A_REGRESSION]) {
        await dual.captureNode(cap);
        await dual.capturePlatform(cap);
      }
      expect(countObs(scratchDb, OBSERVER_NODE, pk)).toBe(4);
      expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(4);
      expect(relationships(scratchDb, OBSERVER_NODE, pk)).toEqual([
        "FIRST",
        "SUCCESSOR",
        "SUCCESSOR",
        "REGRESSION",
      ]);
      expect(relationships(scratchDb, OBSERVER_PLATFORM, pk)).toEqual([
        "FIRST",
        "SUCCESSOR",
        "SUCCESSOR",
        "REGRESSION",
      ]);
      // Matching anomaly rows on BOTH streams (No-blind-retry).
      const nodeAnoms = Number(
        psqlMust(
          scratchDb,
          `SELECT count(*) FROM observation_anomalies
            WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}' AND kind='REGRESSION'`,
        ).trim(),
      );
      const platAnoms = Number(
        psqlMust(
          scratchDb,
          `SELECT count(*) FROM observation_anomalies
            WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}' AND kind='REGRESSION'`,
        ).trim(),
      );
      expect(nodeAnoms).toBe(1);
      expect(platAnoms).toBe(1);

      // Eight total observation rows across domains — never collapsed to four shared.
      const total = Number(
        psqlMust(
          scratchDb,
          `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${pk}'`,
        ).trim(),
      );
      expect(total).toBe(8);
    }

    assertionsRun += 1;
  });

  it("ADVERSARIAL: dual landing authority stays per-observer; cross-observer forge surface probed", async () => {
    const pk = nextWalletPk();
    const dual = makeDualCapturers(scratchDb, pk);

    // ONE physical body into both pipelines (honest path).
    const physicalRead = CAP_A_BYTES;
    const shared: SequenceCapture = {
      parseResult: "VERIFIED_HEAD",
      rawResponseBytes: physicalRead,
      isGenesis: false,
      sSignature: sig("A"),
      pSignature: "",
      semanticFingerprint: fp("fpA"),
    };

    const nodeResult = await dual.captureNode(shared);
    const platResult = await dual.capturePlatform(shared);
    expect(appendKind(nodeResult)).toBe("APPEND:FIRST:1");
    expect(appendKind(platResult)).toBe("APPEND:FIRST:1");

    // ── DB facts unit tests / pure planCapture cannot see ──────────────────
    // Distinct observation ids, domain join, stored bytes, FIRST chain null.
    const dualRows = psqlMust(
      scratchDb,
      `SELECT o.id::text,
              o.observer_id::text,
              obs.domain::text,
              o.wallet_seq::text,
              o.relationship::text,
              o.previous_recorded_observation_id IS NULL AS prev_null,
              encode(o.raw_response_bytes, 'hex') AS raw_hex,
              o.raw_response_sha256,
              o.endpoint_fingerprint
         FROM gateway_observations o
         JOIN observers obs ON obs.id = o.observer_id
        WHERE o.wallet_public_key='${pk}'
        ORDER BY obs.domain`,
    )
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [
          id,
          observerId,
          domain,
          walletSeq,
          relationship,
          prevNull,
          rawHex,
          digest,
          endpointFp,
        ] = line.split("|");
        return {
          id: id!,
          observerId: observerId!,
          domain: domain!,
          walletSeq: walletSeq!,
          relationship: relationship!,
          prevNull: prevNull!,
          rawHex: rawHex!,
          digest: digest!,
          endpointFp: endpointFp!,
        };
      });

    expect(dualRows).toHaveLength(2);
    const nodeRow = dualRows.find((r) => r.domain === "NODE");
    const platRow = dualRows.find((r) => r.domain === "PLATFORM");
    expect(nodeRow, "NODE row present via domain join").toBeDefined();
    expect(platRow, "PLATFORM row present via domain join").toBeDefined();
    expect(nodeRow!.id).not.toBe(platRow!.id);
    expect(nodeRow!.observerId).toBe(OBSERVER_NODE);
    expect(platRow!.observerId).toBe(OBSERVER_PLATFORM);
    expect(nodeRow!.walletSeq).toBe("1");
    expect(platRow!.walletSeq).toBe("1");
    expect(nodeRow!.relationship).toBe("FIRST");
    expect(platRow!.relationship).toBe("FIRST");
    // FIRST has no prior on either stream (independent empty priors → independent chains).
    expect(nodeRow!.prevNull).toBe("t");
    expect(platRow!.prevNull).toBe("t");
    // Stored bytes are the physical body on both rows (not a shared pointer).
    const physicalHex = Buffer.from(physicalRead).toString("hex");
    expect(nodeRow!.rawHex).toBe(physicalHex);
    expect(platRow!.rawHex).toBe(physicalHex);
    expect(nodeRow!.digest).toBe(platRow!.digest);
    expect(nodeRow!.digest).toBe(createHash("sha256").update(physicalRead).digest("hex"));
    // Per-observer endpoint fingerprint — never inherited across domains.
    expect(nodeRow!.endpointFp).toBe(ENDPOINT_FP_NODE);
    expect(platRow!.endpointFp).toBe(ENDPOINT_FP_PLATFORM);

    // Independent cursors each point at THEIR OWN last observation id.
    const cursors = psqlMust(
      scratchDb,
      `SELECT c.observer_id::text,
              c.last_recorded_observation_id::text,
              c.next_wallet_seq::text,
              o.observer_id::text AS last_obs_observer
         FROM wallet_observation_cursors c
         JOIN gateway_observations o ON o.id = c.last_recorded_observation_id
        WHERE c.wallet_public_key='${pk}'
        ORDER BY c.observer_id`,
    )
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [observerId, lastId, nextSeq, lastObsObserver] = line.split("|");
        return {
          observerId: observerId!,
          lastId: lastId!,
          nextSeq: nextSeq!,
          lastObsObserver: lastObsObserver!,
        };
      });
    expect(cursors).toHaveLength(2);
    for (const c of cursors) {
      // Honest writer always binds cursor.last → an observation owned by the same observer.
      expect(c.lastObsObserver).toBe(c.observerId);
      expect(c.nextSeq).toBe("2");
    }
    const nodeCursor = cursors.find((c) => c.observerId === OBSERVER_NODE)!;
    const platCursor = cursors.find((c) => c.observerId === OBSERVER_PLATFORM)!;
    expect(nodeCursor.lastId).toBe(nodeRow!.id);
    expect(platCursor.lastId).toBe(platRow!.id);
    expect(nodeCursor.lastId).not.toBe(platCursor.lastId);

    // NODE advances alone with a successor. PLATFORM's cursor must NOT move and must NOT
    // gain a row — a NODE-only landing cannot be silently treated as PLATFORM-verified
    // (observation verification: node_claim and operation_verified are separate; node/platform
    // semantic disagreement fails closed rather than releasing the barrier).
    const nodeOnly = await dual.captureNode(CAP_B);
    expect(appendKind(nodeOnly)).toBe("APPEND:SUCCESSOR:2");
    expect(countObs(scratchDb, OBSERVER_NODE, pk)).toBe(2);
    expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(1);
    expect(nextWalletSeq(scratchDb, OBSERVER_NODE, pk)).toBe(3);
    expect(nextWalletSeq(scratchDb, OBSERVER_PLATFORM, pk)).toBe(2);
    expect(relationships(scratchDb, OBSERVER_PLATFORM, pk)).toEqual(["FIRST"]);
    // PLATFORM cursor still pins its own FIRST id after the NODE-only successor.
    const platCursorAfter = psqlMust(
      scratchDb,
      `SELECT last_recorded_observation_id::text FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}'`,
    ).trim();
    expect(platCursorAfter).toBe(platRow!.id);

    // NODE successor chains previous_recorded to NODE's own FIRST — never to PLATFORM.
    const nodeChain = psqlMust(
      scratchDb,
      `SELECT wallet_seq::text || '|' ||
              COALESCE(previous_recorded_observation_id::text, 'NULL')
         FROM gateway_observations
        WHERE observer_id='${OBSERVER_NODE}' AND wallet_public_key='${pk}'
        ORDER BY wallet_seq`,
    )
      .trim()
      .split("\n");
    expect(nodeChain).toEqual([`1|NULL`, `2|${nodeRow!.id}`]);

    // ── NEGATIVE: PK spoof (shared row identity) is impossible ─────────────
    const nodeId = nodeRow!.id;
    const platId = platRow!.id;
    const spoofPk = runPsql(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256
       ) VALUES (
         '${nodeId}', '${OBSERVER_PLATFORM}', '${ENDPOINT_FP_PLATFORM}',
         '${pk}', 99, now(), 200, E'\\\\x01', '${HEX}',
         'VERIFIED_HEAD', 'FIRST', '${HEX}', true,
         'sender', '${SIG}', '${SIG}', '5.5',
         'inner', '${SIG}', '${SIG}', 'body', '${HEX}'
       )`,
      true,
    );
    expect(spoofPk.ok, "reusing NODE observation id under PLATFORM must fail").toBe(false);
    expect(spoofPk.stderr).toMatch(/duplicate key|unique|23505/i);

    // ── Cross-observer forge + writer fence (AC3 B1/B2) ────────────────────
    // DDL residual: observation-ledger.sql / observation-stores.sql FKs are
    // id-only (no same-observer CHECK) — a direct SQL adversary can plant
    // PLATFORM previous/cursor at a NODE id. Production fence is LOAD_CURSOR
    // (`o.observer_id = c.observer_id`): planted residual must NOT amplify
    // into dual-authority chain evidence or cross-observer AA suppress.
    const forgePrev = runPsql(
      scratchDb,
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256,
         previous_recorded_observation_id
       ) VALUES (
         '${randomUUID()}', '${OBSERVER_PLATFORM}', '${ENDPOINT_FP_PLATFORM}',
         '${pk}', 50, now(), 200, E'\\\\x02', '${HEX}',
         'VERIFIED_HEAD', 'SUCCESSOR', '${HEX}', true,
         'sender', '${SIG}', '${SIG}', '5.5',
         'inner', '${SIG}', '${SIG}', 'body', '${HEX}',
         '${nodeId}'
       )`,
      true,
    );
    expect(
      forgePrev.ok,
      "DDL residual: PLATFORM previous_recorded→NODE id is ALLOWED by " +
        "observation-ledger.sql FK (id only). " +
        `stderr=${forgePrev.stderr}`,
    ).toBe(true);

    const forgeCursor = runPsql(
      scratchDb,
      `UPDATE wallet_observation_cursors
          SET last_recorded_observation_id = '${nodeId}'
        WHERE observer_id = '${OBSERVER_PLATFORM}'
          AND wallet_public_key = '${pk}'`,
      true,
    );
    expect(
      forgeCursor.ok,
      "DDL residual: PLATFORM cursor last_recorded→NODE id is ALLOWED by " +
        "observation-stores.sql FK (id only). " +
        `stderr=${forgeCursor.stderr}`,
    ).toBe(true);

    const forgedCursorPoint = psqlMust(
      scratchDb,
      `SELECT last_recorded_observation_id::text,
              (SELECT observer_id::text FROM gateway_observations WHERE id = last_recorded_observation_id)
         FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}'`,
    ).trim();
    expect(forgedCursorPoint).toBe(`${nodeId}|${OBSERVER_NODE}`);

    const forgedPrevPoint = psqlMust(
      scratchDb,
      `SELECT previous_recorded_observation_id::text
         FROM gateway_observations
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_seq=50`,
    ).trim();
    expect(forgedPrevPoint).toBe(nodeId);

    // B2 — planted cursor must NOT treat NODE body as PLATFORM prior sighting.
    // LOAD_CURSOR same-observer join miss → CrossObserverCursorError (fail-closed);
    // never SUPPRESS_AS_SIGHTING against foreign observer bytes.
    const platCountBeforeB2 = countObs(scratchDb, OBSERVER_PLATFORM, pk);
    await expect(dual.capturePlatform(shared)).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof CrossObserverCursorError &&
        err.code === "CROSS_OBSERVER_CURSOR" &&
        err.lastRecordedObservationId === nodeId &&
        err.observerId === OBSERVER_PLATFORM,
    );
    // No new PLATFORM row, cursor still poisoned at NODE id (writer did not chain or suppress).
    expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(platCountBeforeB2);
    expect(consecutiveRepeats(scratchDb, OBSERVER_PLATFORM, pk)).toBe(0);
    const platCursorStillForged = psqlMust(
      scratchDb,
      `SELECT last_recorded_observation_id::text FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}'`,
    ).trim();
    expect(platCursorStillForged).toBe(nodeId);

    // No PLATFORM row gained previous_recorded → NODE from any writer path.
    const crossChainCount = psqlMust(
      scratchDb,
      `SELECT count(*)::text FROM gateway_observations
        WHERE observer_id='${OBSERVER_PLATFORM}'
          AND wallet_public_key='${pk}'
          AND previous_recorded_observation_id = '${nodeId}'
          AND wallet_seq <> 50`,
    ).trim();
    expect(crossChainCount).toBe("0");

    // B1 — same plant + CAP_B must not APPEND:SUCCESSOR with previous_recorded=NODE.
    const platCountBeforeB1 = countObs(scratchDb, OBSERVER_PLATFORM, pk);
    await expect(dual.capturePlatform(CAP_B)).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof CrossObserverCursorError &&
        err.lastRecordedObservationId === nodeId,
    );
    expect(countObs(scratchDb, OBSERVER_PLATFORM, pk)).toBe(platCountBeforeB1);
    expect(nextWalletSeq(scratchDb, OBSERVER_PLATFORM, pk)).toBe(2);
    // Cursor remains planted (fail-closed; no honest append wrote NODE into previous_recorded).
    const platCursorAfterB1 = psqlMust(
      scratchDb,
      `SELECT last_recorded_observation_id::text FROM wallet_observation_cursors
        WHERE observer_id='${OBSERVER_PLATFORM}' AND wallet_public_key='${pk}'`,
    ).trim();
    expect(platCursorAfterB1).toBe(nodeId);

    const writerCrossChain = psqlMust(
      scratchDb,
      `SELECT count(*)::text FROM gateway_observations
        WHERE observer_id='${OBSERVER_PLATFORM}'
          AND wallet_public_key='${pk}'
          AND previous_recorded_observation_id = '${nodeId}'
          AND wallet_seq <> 50`,
    ).trim();
    expect(writerCrossChain, "B1: honest writer must never chain PLATFORM previous→NODE").toBe(
      "0",
    );

    // Restore PLATFORM cursor (cursors are mutable). Forged seq=50 residue is
    // append-only DDL evidence and stays; this test's pk is unique so no bleed.
    psqlMust(
      scratchDb,
      `UPDATE wallet_observation_cursors
          SET last_recorded_observation_id = '${platId}'
        WHERE observer_id = '${OBSERVER_PLATFORM}'
          AND wallet_public_key = '${pk}'`,
    );

    assertionsRun += 1;
  });

  it("fail-closed: at least one real-PG assertion discharged", () => {
    if (PG_REQUIRED && assertionsRun === 0) {
      throw new Error("PG_REQUIRED=1 but no dual-observer assertions ran");
    }
    expect(assertionsRun).toBeGreaterThan(0);
  });
});

describe("connectivity gate", () => {
  it("under PG_REQUIRED=1 Postgres must be reachable", () => {
    if (!PG_REQUIRED) return;
    expect(PG_AVAILABLE, "PG_REQUIRED=1 but PostgreSQL is unreachable").toBe(true);
  });
});
