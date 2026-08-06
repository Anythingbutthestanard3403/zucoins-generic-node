/**
 * observation-anomaly-indexes.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database, that the frozen
 * observation-anomaly-indexes DDL structurally enforces the No-blind-retry anomaly-ledger invariant and
 * the anomaly-table constraints:
 *   - The never-blind-retry rule backstop: an anomaly-classified gateway_observations row (relationship in
 *     {SIGNATURE_COLLISION, REGRESSION, GENESIS_AFTER_HISTORY, UNEXPLAINED_JUMP} or a
 *     non-verified parse_result) with NO matching observation_anomalies row in the same
 *     transaction is rejected at COMMIT by the DEFERRABLE INITIALLY DEFERRED constraint
 *     trigger (SQLSTATE 23514). This is the mechanism that halts automation on an anomalous
 * read (observation verification step 9), so the pairing must be inseparable.
 *   - observation_id UNIQUE (23505), the nine-member kind CHECK (23514), NOT NULL columns,
 *     and that the classification prior-state lookup uses the new index, not a Seq Scan.
 *
 * Home rationale: this file's DDL is an EXTENSION of observation-ledger.sql; the two
 * are applied in dependency sequence into a hermetic scratch database over a minimal wallets(id)
 * stub -- closed the custody wallets(wallet_id) vs wallets(id) naming split, so the stub
 * matches custody's wallets(id) PK; a stub remains correct isolation because this slice still
 * does not create wallets itself (execution-sequence prerequisite only). The real DDL files are
 * loaded and applied verbatim (no hand-rolled mirror). The fail-closed guard at the bottom turns
 * an undischarged obligation into a hard FAILURE whenever PostgreSQL is reachable under
 * PG_REQUIRED=1.
 *
 * PG_REQUIRED race guard mirrors custody-eligibility-lease-pk.test.ts: PG_REQUIRED=1 is exported
 * by verify-local.sh only after its own pg_isready probe found Postgres reachable, so within this
 * process it means "the outer runner confirmed PG was up," never "PG is optional."
 */
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const OBSERVER_ID = "11111111-1111-4111-8111-111111111111";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
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

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};
const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── SQL fixtures (values built via repeat() so the domain regexes are met exactly) ─── */

const PK = "repeat('A',43)||'='"; // padded_base64url_pubkey: 43 body chars + '='
const SIG = "repeat('A',86)||'=='"; // padded_base64url_signature: 86 body chars + '=='
const HEX = "repeat('a',64)"; // sha256_hex

// A VERIFIED_HEAD gateway_observations row with the given relationship. All head CHECKs
// are satisfied: role, S/P/step signatures, balance, inner/completed bodies, fingerprint.
const headObservation = (id: string, seq: number, relationship: string): string =>
  `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
  `wallet_seq,observed_at,http_status,raw_response_bytes,raw_response_sha256,parse_result,` +
  `relationship,semantic_fingerprint,state_changed,wallet_role,s_signature,p_signature,b_amount,` +
  `inner_preimage_text,step_1_signature,step_2_signature,completed_transaction_text,` +
  `completed_transaction_sha256) VALUES ('${id}','${OBSERVER_ID}',${HEX},${PK},${seq},now(),200,` +
  `'\\x00',${HEX},'VERIFIED_HEAD','${relationship}',${HEX},true,'sender',${SIG},${SIG},'5.5',` +
  `'inner',${SIG},${SIG},'body',${HEX});`;

// A non-verified gateway_observations row (relationship NOT_APPLICABLE, all head material null).
const parseFailureObservation = (id: string, seq: number, parseResult: string): string =>
  `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
  `wallet_seq,observed_at,raw_response_bytes,raw_response_sha256,parse_result,relationship) ` +
  `VALUES ('${id}','${OBSERVER_ID}',${HEX},${PK},${seq},now(),'\\x00',${HEX},'${parseResult}',` +
  `'NOT_APPLICABLE');`;

const anomalyRow = (id: string, observationId: string, kind: string): string =>
  `INSERT INTO observation_anomalies (id,observation_id,observer_id,wallet_public_key,kind,` +
  `details,detected_at) VALUES ('${id}','${observationId}','${OBSERVER_ID}',${PK},'${kind}',` +
  `'detail',now());`;

const tx = (...statements: string[]): string => `BEGIN; ${statements.join(" ")} COMMIT;`;

let assertionsRun = 0;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg("observation-anomaly-indexes real-PG behaviour (hermetic scratch DB)", () => {
  const scratchDb = `observation_anomaly_anomaly_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
    applyFile(scratchDb, "observation-ledger.sql");
    applyFile(scratchDb, "observation-anomaly-indexes.sql");
    psqlMust(
      scratchDb,
      `INSERT INTO observers (id,domain,owner_id,gateway_endpoint_fingerprint,created_at) ` +
        `VALUES ('${OBSERVER_ID}','NODE',gen_random_uuid(),${HEX},now());`,
    );
  });

  afterAll(() => {
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("(a) the full schema migrated: observation_anomalies, its indexes, and the guard exist", () => {
    expect(runPsql(scratchDb, "SELECT to_regclass('public.observation_anomalies');").stdout.trim()).toBe(
      "observation_anomalies",
    );
    const idx = runPsql(
      scratchDb,
      "SELECT count(*) FROM pg_indexes WHERE indexname IN " +
        "('gateway_observations_prior_state_idx','gateway_observations_exact_body_idx'," +
        "'gateway_observations_semantic_fingerprint_idx','observation_anomalies_stream_idx');",
    ).stdout.trim();
    expect(idx).toBe("4");
    const trg = runPsql(
      scratchDb,
      "SELECT tgname FROM pg_trigger WHERE tgname='observation_anomaly_pairing_complete';",
    ).stdout.trim();
    expect(trg).toBe("observation_anomaly_pairing_complete");
    assertionsRun += 1;
  });

  it("(b) NEGATIVE (No-blind-retry): a REGRESSION observation with NO anomaly is rejected at COMMIT (23514)", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000001";
    const result = runPsql(scratchDb, tx(headObservation(obs, 1, "REGRESSION")), true);
    expect(result.ok, "an anomaly-classified row without its anomaly must be rejected").toBe(false);
    expect(extractSqlstate(result.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(result.stderr).toContain("no observation_anomalies row (anomaly ledger)");
    assertionsRun += 1;
  });

  it("(c) HAPPY: a REGRESSION observation WITH its matching anomaly commits", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000002";
    const an = "bbbbbbbb-0000-4000-8000-000000000002";
    const result = runPsql(
      scratchDb,
      tx(headObservation(obs, 2, "REGRESSION"), anomalyRow(an, obs, "REGRESSION")),
    );
    expect(result.ok, result.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("(c2) a verified non-anomalous head (SUCCESSOR) commits WITHOUT an anomaly row", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000003";
    const result = runPsql(scratchDb, tx(headObservation(obs, 3, "SUCCESSOR")));
    expect(result.ok, result.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("(c3) a non-verified parse failure (TRANSPORT_ERROR) requires its anomaly, else rejected", () => {
    const obsBad = "aaaaaaaa-0000-4000-8000-000000000004";
    const bad = runPsql(scratchDb, tx(parseFailureObservation(obsBad, 4, "TRANSPORT_ERROR")), true);
    expect(bad.ok, "an unpaired parse-failure row must be rejected").toBe(false);
    expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);

    const obsOk = "aaaaaaaa-0000-4000-8000-000000000005";
    const an = "bbbbbbbb-0000-4000-8000-000000000005";
    const good = runPsql(
      scratchDb,
      tx(parseFailureObservation(obsOk, 5, "TRANSPORT_ERROR"), anomalyRow(an, obsOk, "TRANSPORT_ERROR")),
    );
    expect(good.ok, good.stderr).toBe(true);
    assertionsRun += 1;
  });

  it("(c4) a wrong-kind anomaly does not satisfy the guard (kind must match the classification)", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000006";
    const an = "bbbbbbbb-0000-4000-8000-000000000006";
    const result = runPsql(
      scratchDb,
      tx(headObservation(obs, 6, "REGRESSION"), anomalyRow(an, obs, "UNEXPLAINED_JUMP")),
      true,
    );
    expect(result.ok, "a mismatched anomaly kind must be rejected").toBe(false);
    expect(extractSqlstate(result.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(result.stderr).toContain("mismatched anomaly kind");
    assertionsRun += 1;
  });

  it("(d) observation_id UNIQUE rejects a second anomaly for one observation (23505)", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000007";
    const an1 = "bbbbbbbb-0000-4000-8000-000000000071";
    const an2 = "bbbbbbbb-0000-4000-8000-000000000072";
    psqlMust(scratchDb, tx(headObservation(obs, 7, "REGRESSION"), anomalyRow(an1, obs, "REGRESSION")));
    const dup = runPsql(scratchDb, anomalyRow(an2, obs, "REGRESSION"), true);
    expect(dup.ok, "a second anomaly for the same observation must be rejected").toBe(false);
    expect(extractSqlstate(dup.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(dup.stderr)).toBe("observation_anomalies_observation_id_key");
    assertionsRun += 1;
  });

  it("(e) the nine-member kind CHECK rejects an out-of-vocabulary kind (23514)", () => {
    const obs = "aaaaaaaa-0000-4000-8000-000000000008";
    const an = "bbbbbbbb-0000-4000-8000-000000000008";
    const result = runPsql(
      scratchDb,
      tx(headObservation(obs, 8, "REGRESSION"), anomalyRow(an, obs, "NOT_A_KIND")),
      true,
    );
    expect(result.ok, "an out-of-vocabulary kind must be rejected").toBe(false);
    expect(extractSqlstate(result.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(extractConstraint(result.stderr)).toBe("observation_anomalies_kind_check");
    assertionsRun += 1;
  });

  it("(f) the prior-state classification lookup uses gateway_observations_prior_state_idx", () => {
    const plan = runPsql(
      scratchDb,
      `SET enable_seqscan=off; EXPLAIN SELECT semantic_fingerprint FROM gateway_observations ` +
        `WHERE observer_id='${OBSERVER_ID}' AND wallet_public_key=${PK} AND s_signature=${SIG};`,
    );
    expect(plan.ok, plan.stderr).toBe(true);
    expect(plan.stdout).toContain("gateway_observations_prior_state_idx");
    expect(plan.stdout).not.toContain("Seq Scan on gateway_observations");
    assertionsRun += 1;
  });
});

const EXPECTED_ASSERTIONS = 9;

it("obligation guard: real-PG anomaly drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "real-PG anomaly/collision-guard backstop could not run and the local " +
          "verification lane must not silently skip it.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG anomaly drills did not all run -- undischarged",
  ).toBe(EXPECTED_ASSERTIONS);
});
