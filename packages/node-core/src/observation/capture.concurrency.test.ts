// real-PostgreSQL proof that serialized capture +
// exact-repeat comparator produce changed-response observation ledger append/suppress behaviour under
// concurrency and restart.
//
// Governing:
// 1
// 4
// observation ledger.md
//
// This is a proof slice only — no new production write path. Serialization is the
// Step-1 transaction-scoped lock (pg_advisory_xact_lock) around ExactRepeatService;
// the comparator itself is the production ExactRepeatService. Schema under test
// is the frozen observation-ledger.sql + observation-anomaly-indexes.sql +
// observation-stores.sql applied into a hermetic scratch database.
//
// Connectivity: prefers TEST_DATABASE_URL (vitest.global-setup.ts under root vitest);
// falls back to the local maintenance database via psql -d postgres so package-local
// `vitest --root packages/node-core` still discharges the obligation. Under PG_REQUIRED=1
// an unreachable Postgres is a hard FAIL, never a silent skip.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  ExactRepeatService,
  type ExactRepeatCandidate,
  type ExactRepeatCursorState,
  type ExactRepeatStore,
  type AnomalyAppendEntry,
  type ObservationAppendEntry,
} from "./dedup.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../schema");

const MAINTENANCE_DB = "postgres";
const OBSERVER_ID = "11111111-1111-4111-8111-111111111111";
// padded_base64url_pubkey: 43 body chars + '='. Per-test unique PKs — gateway_observations
// and observation_anomalies are append-only, so tests cannot wipe rows.
let walletPkCounter = 0;
const nextWalletPk = (): string => {
  walletPkCounter += 1;
  const body = `W${String(walletPkCounter).padStart(42, "0")}`;
  return `${body}=`;
};
const HEX = "a".repeat(64);
const SIG = `${"A".repeat(86)}==`;
const ENDPOINT_FP = HEX;

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

/* ─── psql / connectivity ─────────────────────────────────────────── */

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

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

/* ─── long-lived psql session (one connection = one transaction scope) ── */

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
    this.child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      let newline = this.#buffer.indexOf("\n");
      while (newline !== -1) {
        const line = this.#buffer.slice(0, newline);
        this.#buffer = this.#buffer.slice(newline + 1);
        // Empty lines are not replies; psql -t emits one line per row.
        const waiter = this.#pending.shift();
        if (waiter) waiter.resolve(line);
        newline = this.#buffer.indexOf("\n");
      }
    });
    this.child.on("close", () => {
      this.#closed = true;
      while (this.#pending.length > 0) {
        this.#pending.shift()!.reject(new Error(`psql session closed: ${this.#stderr}`));
      }
    });
  }

  /** Run a single-column SQL statement; returns the first result line (may be empty). */
  async scalar(sql: string): Promise<string> {
    if (this.#closed) throw new Error("psql session already closed");
    // Tag so every statement yields exactly one line even when it returns no rows.
    const wrapped = `SELECT COALESCE((${sql.replace(/;\s*$/, "")}), '') AS _v`;
    // For non-SELECT (BEGIN/COMMIT/INSERT…), use a sentinel SELECT after the statement.
    const isQuery = /^\s*(SELECT|WITH)\b/i.test(sql);
    const payload = isQuery
      ? `${wrapped};\n`
      : `${sql.replace(/;\s*$/, "")}; SELECT 'ok';\n`;
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

/* ─── byte / candidate helpers ────────────────────────────────────── */

const BODY_A = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_A_PRIME = Uint8Array.from([123, 32, 34, 115, 116, 97, 116, 117, 115, 34, 58, 116, 125]);
const BODY_B = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 102, 125]);
const BODY_C = Uint8Array.from([123, 34, 120, 34, 58, 49, 125]);
const BODY_MALFORMED = Uint8Array.from([110, 111, 116, 45, 106, 115, 111, 110]);
const BODY_GENESIS = Uint8Array.from([123, 34, 103, 101, 110, 101, 115, 105, 115, 34, 125]);

const FP_1 = "b".repeat(64);
const FP_2 = "c".repeat(64);
const FP_3 = "d".repeat(64);
const FP_GEN = "e".repeat(64);

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function byteaLiteral(bytes: Uint8Array): string {
  return `E'\\\\x${Buffer.from(bytes).toString("hex")}'`;
}

function candidate(
  bytes: Uint8Array,
  opts: {
    verified?: boolean;
    fingerprint?: string | null;
    anomalyKind?: ExactRepeatCandidate["anomalyKind"];
    anomalyDetails?: string;
  } = {},
): ExactRepeatCandidate {
  const verified = opts.verified ?? true;
  const anomalyKind =
    opts.anomalyKind !== undefined
      ? opts.anomalyKind
      : verified
        ? null
        : "MALFORMED_ENVELOPE";
  return {
    rawResponseBytes: bytes,
    verified,
    semanticFingerprint: opts.fingerprint ?? null,
    anomalyKind,
    anomalyDetails: opts.anomalyDetails ?? (anomalyKind ? `anomaly:${anomalyKind}` : ""),
  };
}

/* ─── TX-bound ExactRepeatStore over a live session ───────────────── */

class SessionExactRepeatStore implements ExactRepeatStore {
  private readonly session: PsqlSession;
  private readonly observerId: string;
  private readonly walletPk: string;
  private idCounter = 0;

  constructor(session: PsqlSession, observerId: string, walletPk: string) {
    this.session = session;
    this.observerId = observerId;
    this.walletPk = walletPk;
  }

  async loadCursor(_streamKey: string): Promise<ExactRepeatCursorState | null> {
    const row = await this.session.scalar(
      `SELECT COALESCE(
         (SELECT next_wallet_seq::text || '|' ||
                 consecutive_repeat_count::text || '|' ||
                 last_raw_response_sha256 || '|' ||
                 COALESCE(last_semantic_fingerprint, '') || '|' ||
                 last_recorded_observation_id::text || '|' ||
                 encode(o.raw_response_bytes, 'hex') || '|' ||
                 CASE WHEN o.parse_result IN ('VERIFIED_HEAD','VERIFIED_GENESIS') THEN '1' ELSE '0' END
            FROM wallet_observation_cursors c
            JOIN gateway_observations o ON o.id = c.last_recorded_observation_id
           WHERE c.observer_id = '${this.observerId}'
             AND c.wallet_public_key = '${this.walletPk}'),
         '')`,
    );
    if (row === "") return null;
    const [nextSeq, repeats, sha, fp, obsId, hexBytes, verifiedFlag] = row.split("|");
    const rawBytes = Buffer.from(hexBytes!, "hex");
    return {
      nextWalletSeq: Number(nextSeq),
      consecutiveRepeatCount: Number(repeats),
      lastRecorded: {
        verified: verifiedFlag === "1",
        rawResponseSha256: sha!,
        rawResponseOctets: rawBytes.length,
        rawResponseBytes: new Uint8Array(rawBytes),
      },
      lastSemanticFingerprint: fp === "" ? null : fp!,
      lastObservationId: obsId!,
    };
  }

  async recordSighting(_streamKey: string, state: ExactRepeatCursorState): Promise<void> {
    if (state.lastObservationId === null || state.lastRecorded === null) {
      // Empty cursor: nothing to write until an observation exists.
      return;
    }
    const fp =
      state.lastSemanticFingerprint === null
        ? "NULL"
        : `'${state.lastSemanticFingerprint}'`;
    await this.session.exec(
      `INSERT INTO wallet_observation_cursors (
         observer_id, wallet_public_key, last_recorded_observation_id,
         last_raw_response_sha256, last_semantic_fingerprint, last_seen_at,
         consecutive_repeat_count, next_wallet_seq
       ) VALUES (
         '${this.observerId}', '${this.walletPk}', '${state.lastObservationId}',
         '${state.lastRecorded.rawResponseSha256}', ${fp}, now(),
         ${state.consecutiveRepeatCount}, ${state.nextWalletSeq}
       )
       ON CONFLICT (observer_id, wallet_public_key) DO UPDATE SET
         last_recorded_observation_id = EXCLUDED.last_recorded_observation_id,
         last_raw_response_sha256 = EXCLUDED.last_raw_response_sha256,
         last_semantic_fingerprint = EXCLUDED.last_semantic_fingerprint,
         last_seen_at = EXCLUDED.last_seen_at,
         consecutive_repeat_count = EXCLUDED.consecutive_repeat_count,
         next_wallet_seq = EXCLUDED.next_wallet_seq`,
    );
  }

  async appendObservation(_streamKey: string, entry: ObservationAppendEntry): Promise<void> {
    const sha = entry.rawResponseSha256;
    const bytes = byteaLiteral(entry.rawResponseBytes);
    // Relationship is set at INSERT time (append-only — no post-INSERT rewrite).
    const relationship =
      entry.relationship ??
      (entry.verified ? (entry.walletSeq === 1 ? "FIRST" : "SUCCESSOR") : "NOT_APPLICABLE");
    if (entry.verified) {
      const fp = entry.semanticFingerprint ?? HEX;
      await this.session.exec(
        `INSERT INTO gateway_observations (
           id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
           observed_at, http_status, raw_response_bytes, raw_response_sha256,
           parse_result, relationship, semantic_fingerprint, state_changed,
           wallet_role, s_signature, p_signature, b_amount,
           inner_preimage_text, step_1_signature, step_2_signature,
           completed_transaction_text, completed_transaction_sha256
         ) VALUES (
           '${entry.observationId}', '${this.observerId}', '${ENDPOINT_FP}',
           '${this.walletPk}', ${entry.walletSeq}, now(), 200, ${bytes}, '${sha}',
           'VERIFIED_HEAD', '${relationship}', '${fp}', true,
           'sender', '${SIG}', '${SIG}', '5.5',
           'inner', '${SIG}', '${SIG}', 'body', '${HEX}'
         )`,
      );
    } else {
      await this.session.exec(
        `INSERT INTO gateway_observations (
           id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
           observed_at, raw_response_bytes, raw_response_sha256,
           parse_result, relationship
         ) VALUES (
           '${entry.observationId}', '${this.observerId}', '${ENDPOINT_FP}',
           '${this.walletPk}', ${entry.walletSeq}, now(), ${bytes}, '${sha}',
           'MALFORMED_ENVELOPE', 'NOT_APPLICABLE'
         )`,
      );
    }
  }

  async appendAnomaly(_streamKey: string, entry: AnomalyAppendEntry): Promise<void> {
    // Observation relationship is already set at INSERT (append-only). Only append the anomaly row.
    const prior =
      entry.priorObservationId === null ? "NULL" : `'${entry.priorObservationId}'`;
    const details = entry.details.replaceAll("'", "''");
    await this.session.exec(
      `INSERT INTO observation_anomalies (
         id, observation_id, observer_id, wallet_public_key, kind,
         prior_observation_id, details, detected_at
       ) VALUES (
         '${randomUUID()}', '${entry.observationId}', '${this.observerId}',
         '${this.walletPk}', '${entry.kind}', ${prior}, '${details}', now()
       )`,
    );
  }

  allocateObservationId(): string {
    this.idCounter += 1;
    // randomUUID — concurrent sessions each allocate independently; a pid/counter
    // scheme would collide across sequential lockedClassify calls that reset the store.
    return randomUUID();
  }

  nowIso(): string {
    return new Date().toISOString();
  }
}

/** Step 1: transaction-scoped stream lock + ExactRepeatService classify. */
async function lockedClassify(
  db: string,
  walletPk: string,
  cand: ExactRepeatCandidate,
  opts: { commit?: boolean } = {},
): Promise<{ decision: string; walletSeq?: number; consecutiveRepeatCount?: number }> {
  const commit = opts.commit ?? true;
  const streamKey = `${OBSERVER_ID}\x00${walletPk}`;
  const session = new PsqlSession(db);
  try {
    await session.exec("BEGIN");
    await session.exec(
      `SELECT pg_advisory_xact_lock(hashtextextended('${OBSERVER_ID}:${walletPk}', 0))`,
    );
    const store = new SessionExactRepeatStore(session, OBSERVER_ID, walletPk);
    const svc = new ExactRepeatService(store);
    const decision = await svc.classify(streamKey, cand);
    if (commit) {
      await session.exec("COMMIT");
    } else {
      await session.exec("ROLLBACK");
    }
    if (decision.kind === "EXACT_REPEAT") {
      return { decision: decision.kind, consecutiveRepeatCount: decision.consecutiveRepeatCount };
    }
    return { decision: decision.kind, walletSeq: decision.walletSeq };
  } finally {
    session.kill();
  }
}

function countObservations(db: string, walletPk: string): number {
  return Number(
    psqlMust(
      db,
      `SELECT count(*) FROM gateway_observations
        WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${walletPk}'`,
    ).trim(),
  );
}

function countAnomalies(db: string, walletPk: string): number {
  return Number(
    psqlMust(
      db,
      `SELECT count(*) FROM observation_anomalies
        WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${walletPk}'`,
    ).trim(),
  );
}

function walletSeqs(db: string, walletPk: string): number[] {
  const out = psqlMust(
    db,
    `SELECT wallet_seq FROM gateway_observations
      WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${walletPk}'`,
  )
    .trim()
    .split("\n")
    .filter(Boolean)
    .map(Number);
  return out.slice().sort((a, b) => a - b);
}

function consecutiveRepeatCount(db: string, walletPk: string): number {
  const out = psqlMust(
    db,
    `SELECT COALESCE(
       (SELECT consecutive_repeat_count FROM wallet_observation_cursors
         WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${walletPk}'),
       0)`,
  ).trim();
  return Number(out);
}

/** Persisted relationship column ordered by wallet_seq (append-only INSERT-time value). */
function observationRelationships(db: string, walletPk: string): string[] {
  const out = psqlMust(
    db,
    `SELECT relationship FROM gateway_observations
      WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${walletPk}'
      ORDER BY wallet_seq`, // contract-allow:order:frozen-sql-text
  )
    .trim()
    .split("\n")
    .filter(Boolean);
  return out;
}

/* ─── suite ───────────────────────────────────────────────────────── */

describeIfPg("capture sequencing + concurrency (real PostgreSQL)", () => {
  const scratchDb = `obs_capture_${Date.now()}_${process.pid}`;
  let assertionsRun = 0;

  beforeAll(() => {
    if (!PG_AVAILABLE) return;
    // Create hermetic scratch database.
    if (TEST_DATABASE_URL) {
      try {
        const u = new URL(TEST_DATABASE_URL);
        execFileSync(
          "psql",
          [
            "-h",
            u.hostname || "localhost",
            "-p",
            u.port || "5432",
            "-d",
            MAINTENANCE_DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            `CREATE DATABASE ${scratchDb}`,
          ],
          {
            encoding: "utf-8",
            timeout: 15_000,
            env: {
              ...process.env,
              PGUSER: decodeURIComponent(u.username) || process.env.PGUSER,
              PGPASSWORD: decodeURIComponent(u.password) || process.env.PGPASSWORD,
            },
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
      } catch {
        psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
      }
    } else {
      psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    }

    // wallets stub — observation-ledger references wallets(id); custody uses wallet_id.
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-anomaly-indexes.sql");
    applyFile(scratchDb, "observation-stores.sql");
    psqlMust(
      scratchDb,
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ('${OBSERVER_ID}', 'NODE', gen_random_uuid(), '${HEX}', now());`,
    );
  }, 60_000);

  afterAll(() => {
    if (!PG_AVAILABLE) return;
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("A,A — one gateway_observations row; consecutive_repeat_count=1", async () => {
    const pk = nextWalletPk();
    const first = await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    const second = await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    expect(first.decision).toBe("NEW_OBSERVATION");
    expect(second.decision).toBe("EXACT_REPEAT");
    expect(countObservations(scratchDb, pk)).toBe(1);
    expect(countAnomalies(scratchDb, pk)).toBe(0);
    expect(consecutiveRepeatCount(scratchDb, pk)).toBe(1);
    expect(walletSeqs(scratchDb, pk)).toEqual([1]);
    assertionsRun += 1;
  });

  it("A,A′ — two rows (byte-different envelope is not suppressed)", async () => {
    const pk = nextWalletPk();
    await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    const second = await lockedClassify(scratchDb, pk, candidate(BODY_A_PRIME, { fingerprint: FP_1 }));
    expect(second.decision).toBe("SEMANTIC_REPEAT");
    expect(countObservations(scratchDb, pk)).toBe(2);
    expect(countAnomalies(scratchDb, pk)).toBe(0);
    expect(walletSeqs(scratchDb, pk)).toEqual([1, 2]);
    expect(consecutiveRepeatCount(scratchDb, pk)).toBe(0);
    // ExactRepeatService freezes EQUIVALENT_STATE_DIFFERENT_ENVELOPE at INSERT.
    expect(observationRelationships(scratchDb, pk)).toEqual([
      "FIRST",
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    ]);
    assertionsRun += 1;
  });

  it("A,B,C,A — four rows; final A not suppressed against non-adjacent prior", async () => {
    const pk = nextWalletPk();
    await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    await lockedClassify(scratchDb, pk, candidate(BODY_B, { fingerprint: FP_2 }));
    await lockedClassify(scratchDb, pk, candidate(BODY_C, { fingerprint: FP_3 }));
    const finalA = await lockedClassify(
      scratchDb,
      pk,
      candidate(BODY_A, {
        fingerprint: FP_1,
        anomalyKind: "REGRESSION",
        anomalyDetails: "recurrence of older accepted S",
      }),
    );
    expect(finalA.decision).toBe("NEW_OBSERVATION");
    expect(finalA.walletSeq).toBe(4);
    expect(countObservations(scratchDb, pk)).toBe(4);
    expect(countAnomalies(scratchDb, pk)).toBe(1);
    expect(walletSeqs(scratchDb, pk)).toEqual([1, 2, 3, 4]);
    expect(observationRelationships(scratchDb, pk)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "SUCCESSOR",
      "REGRESSION",
    ]);
    assertionsRun += 1;
  });

  it("X,X — two observations AND two anomalies (anomaly dedup forbidden)", async () => {
    const pk = nextWalletPk();
    const c = candidate(BODY_MALFORMED, {
      verified: false,
      fingerprint: null,
      anomalyKind: "MALFORMED_ENVELOPE",
      anomalyDetails: "strict utf-8/json failed",
    });
    await lockedClassify(scratchDb, pk, c);
    await lockedClassify(scratchDb, pk, c);
    expect(countObservations(scratchDb, pk)).toBe(2);
    expect(countAnomalies(scratchDb, pk)).toBe(2);
    expect(walletSeqs(scratchDb, pk)).toEqual([1, 2]);
    assertionsRun += 1;
  });

  it("same-length different-bytes still appends (exact-byte compare; DIGEST_COLLISION golden is)", async () => {
    const pk = nextWalletPk();
    // gateway_observations is append-only so the digest-poison fixture is no longer
    // expressible by UPDATE. Prove the production path still appends same-length different bytes
    // (decideAppend falls through to exact-byte compare when digests differ). Forced equal-digest
    // collision is discharged by observation-migration-integrity.test.ts GOLDEN DIGEST_COLLISION.
    const left = Uint8Array.from([1, 2, 3, 4]);
    const right = Uint8Array.from([9, 8, 7, 6]);
    expect(left.length).toBe(right.length);
    expect(Buffer.from(left).equals(Buffer.from(right))).toBe(false);

    await lockedClassify(scratchDb, pk, candidate(left, { fingerprint: FP_1 }));
    const result = await lockedClassify(scratchDb, pk, candidate(right, { fingerprint: FP_2 }));
    expect(result.decision).not.toBe("EXACT_REPEAT");
    expect(countObservations(scratchDb, pk)).toBe(2);
    assertionsRun += 1;
  });

  it("concurrent captures receive contiguous unique wallet_seq (barrier start)", async () => {
    const pk = nextWalletPk();
    const N = 8;
    const bodies = Array.from({ length: N }, (_, i) => Uint8Array.from([i + 1, i + 2, i + 3, i + 4]));
    const fingerprints = Array.from({ length: N }, (_, i) =>
      ((i + 10).toString(16).padStart(2, "0")).repeat(32),
    );

    // Barrier: every worker constructs first, then Promise.all starts them together.
    const starters = bodies.map((body, i) => () =>
      lockedClassify(scratchDb, pk, candidate(body, { fingerprint: fingerprints[i]! })),
    );
    const results = await Promise.all(starters.map((fn) => fn()));

    expect(results.every((r) => r.decision === "NEW_OBSERVATION")).toBe(true);
    const seqs = results.map((r) => r.walletSeq!).sort((a, b) => a - b);
    expect(seqs).toEqual(Array.from({ length: N }, (_, i) => i + 1));
    expect(countObservations(scratchDb, pk)).toBe(N);
    expect(walletSeqs(scratchDb, pk)).toEqual(Array.from({ length: N }, (_, i) => i + 1));
    // UNIQUE (observer_id, wallet_public_key, wallet_seq) held — no duplicates.
    const distinct = psqlMust(
      scratchDb,
      `SELECT count(DISTINCT wallet_seq) FROM gateway_observations
        WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${pk}'`,
    ).trim();
    expect(Number(distinct)).toBe(N);
    assertionsRun += 1;
  });

  it("concurrent identical verified captures: exactly one append, rest suppress", async () => {
    const pk = nextWalletPk();
    const N = 6;
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 })),
      ),
    );
    const appends = results.filter((r) => r.decision !== "EXACT_REPEAT");
    const suppresses = results.filter((r) => r.decision === "EXACT_REPEAT");
    expect(appends).toHaveLength(1);
    expect(suppresses).toHaveLength(N - 1);
    expect(countObservations(scratchDb, pk)).toBe(1);
    expect(consecutiveRepeatCount(scratchDb, pk)).toBe(N - 1);
    assertionsRun += 1;
  });

  it("restart mid-capture: ROLLBACK leaves no partial row; resume assigns wallet_seq 1", async () => {
    const pk = nextWalletPk();
    // Capture that deliberately does not commit — models crash between write and cursor commit.
    await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }), { commit: false });
    expect(countObservations(scratchDb, pk)).toBe(0);
    expect(countAnomalies(scratchDb, pk)).toBe(0);
    const cursorRows = psqlMust(
      scratchDb,
      `SELECT count(*) FROM wallet_observation_cursors
        WHERE observer_id = '${OBSERVER_ID}' AND wallet_public_key = '${pk}'`,
    ).trim();
    expect(Number(cursorRows)).toBe(0);

    // Restart: next capture resumes from empty cursor state.
    const resumed = await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    expect(resumed.decision).toBe("NEW_OBSERVATION");
    expect(resumed.walletSeq).toBe(1);
    expect(countObservations(scratchDb, pk)).toBe(1);
    assertionsRun += 1;
  });

  it("genesis / non-genesis / genesis — 3 rows retained (capture layer)", async () => {
    const pk = nextWalletPk();
    // Capture layer treats verified genesis-shaped bytes as verified captures; classification
    // labels (GENESIS_AFTER_HISTORY) are, but the rows must all persist.
    await lockedClassify(scratchDb, pk, candidate(BODY_GENESIS, { fingerprint: FP_GEN }));
    await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    await lockedClassify(
      scratchDb,
      pk,
      candidate(BODY_GENESIS, {
        fingerprint: FP_GEN,
        anomalyKind: "GENESIS_AFTER_HISTORY",
        anomalyDetails: "genesis after history",
      }),
    );
    expect(countObservations(scratchDb, pk)).toBe(3);
    expect(countAnomalies(scratchDb, pk)).toBe(1);
    expect(walletSeqs(scratchDb, pk)).toEqual([1, 2, 3]);
    assertionsRun += 1;
  });

  it("same-S0 conflicting body — 2 rows retained (no suppress on byte change)", async () => {
    const pk = nextWalletPk();
    // Same semantic fingerprint, different bytes → both append (capture layer).
    await lockedClassify(scratchDb, pk, candidate(BODY_A, { fingerprint: FP_1 }));
    await lockedClassify(scratchDb, pk, candidate(BODY_B, { fingerprint: FP_1 }));
    expect(countObservations(scratchDb, pk)).toBe(2);
    expect(walletSeqs(scratchDb, pk)).toEqual([1, 2]);
    assertionsRun += 1;
  });

  it("NEGATIVE: UNIQUE (observer, wallet, wallet_seq) rejects a second wallet_seq=1", () => {
    // Documents the structural backstop the step-1 lock cooperates with: two first-writes
    // that both plan wallet_seq=1 cannot both land. (The lock prevents the application from
    // ever attempting this under normal capture; the constraint is the fail-closed DB edge.)
    const pk = nextWalletPk();
    const insert = (id: string, body: Uint8Array) =>
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256
       ) VALUES (
         '${id}', '${OBSERVER_ID}', '${ENDPOINT_FP}', '${pk}', 1, now(), 200,
         ${byteaLiteral(body)}, '${sha256Hex(body)}',
         'VERIFIED_HEAD', 'FIRST', '${FP_1}', true,
         'sender', '${SIG}', '${SIG}', '5.5',
         'inner', '${SIG}', '${SIG}', 'body', '${HEX}'
       )`;
    const first = runPsql(scratchDb, insert(randomUUID(), BODY_A));
    expect(first.ok, first.stderr).toBe(true);
    const second = runPsql(scratchDb, insert(randomUUID(), BODY_B), true);
    expect(second.ok, "a second wallet_seq=1 must be rejected").toBe(false);
    expect(second.stderr).toMatch(/23505|unique/i);
    expect(countObservations(scratchDb, pk)).toBe(1);
    assertionsRun += 1;
  });

  it("fail-closed: at least one real-PG assertion discharged", () => {
    if (PG_REQUIRED && assertionsRun === 0) {
      throw new Error("PG_REQUIRED=1 but no real-PG assertions ran");
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

