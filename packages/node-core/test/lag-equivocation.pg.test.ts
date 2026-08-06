/**
 * lag-equivocation.pg.test.ts
 *
 * Scripted-endpoint scenarios for gateway LAG, EQUIVOCATION and
 * DISAGREEMENT, driven against the REAL implementations that ship today:
 * - src/gateway/failover.ts — createEndpointFailoverService (observation disagreement halt)
 *   - src/gateway/read.ts       — the bounded read primitive that lands one observation per
 *                                 endpoint touched
 *   - src/gateway/allowlist.ts  — endpoint-identity refusal before any exchange
 *   - src/schema/observation-ledger.sql + observation-anomaly-indexes.sql, applied VERBATIM
 *     into a hermetic scratch database
 *
 * Nothing here re-implements a classifier to test itself: the endpoints are scripted, the
 * disagreeing states are actually constructed, and the detector is observed firing through
 * the service's own public result (verificationStatus / isHalted / disagreement) and through
 * rows in a real PostgreSQL ledger.
 *
 *
 * REAL vs SYNTHETIC, stated up front so a reader is not misled:
 *   - Real: the failover/read/allowlist code paths, the PostgreSQL ledger and every frozen
 *     constraint on it, the endpoint fingerprints, the raw response bytes and their digests,
 *     the semantic fingerprints derived from those bytes.
 *   - Synthetic: the head MATERIAL columns (role, S/P and step signatures, inner preimage,
 *     completed body) are DDL-valid placeholders. This suite proves disagreement/lag/recovery
 *     mechanics, NOT Ed25519 verification — that is outside this suite's remit.
 * - In memory ONLY where no store exists: observation_anomalies has no kind for a
 *     endpoint disagreement (proved below at the database, SQLSTATE 23514), so the injected
 *     AnomalyRecorder captures in memory. src/gateway/anomaly.ts forbids minting a stand-in
 *     table for it. The observation ledger itself is real Postgres in every scenario.
 *   - wallet_observation_cursors is not transcribed in any frozen schema file (its DDL is
 * deferred), so recovery's "the cursor does not advance" is proved against the frozen stream
 *     position, MAX(wallet_seq) under UNIQUE (observer_id, wallet_public_key, wallet_seq).
 *
 * The residual limits this suite deliberately cannot close are written up in
 * lag-equivocation-oracle-limits.md, and scenario 4 asserts that document quotes the
 * specification verbatim so it cannot drift.
 *
 * PostgreSQL is REQUIRED. There is no describe.skip and no silent pass: if the maintenance
 * database is unreachable the suite fails, because a disagreement test that cannot fail is
 * worse than no test.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { GatewayRequest } from "../src/protocol/index.js";
import type { AnomalyRecorder, EndpointDisagreementAnomaly } from "../src/gateway/anomaly.js";
import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "../src/gateway/capture.js";
import {
  GatewayEndpointNotAllowedError,
  assertEndpointAllowed,
  createGatewayEndpointAllowlist,
} from "../src/gateway/allowlist.js";
import { GatewayConfigurationError, fingerprintEndpoint } from "../src/gateway/client.js";
import {
  GatewayEndpointHaltError,
  createEndpointFailoverService,
  provesT0Continuity,
  type SemanticStateReducer,
} from "../src/gateway/failover.js";
import type { ReadGatewayRequestOptions } from "../src/gateway/read.js";
import type { GatewayObservationRecord, ObservationRecorder } from "../src/gateway/records.js";
import { computeObservationHeadFingerprint } from "../src/observation/head-fingerprint.js";
import type { GatewayLimits } from "../src/gateway/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const limitsDoc = resolve(here, "lag-equivocation-oracle-limits.md");

const MAINTENANCE_DB = "postgres";
const SQLSTATE_CHECK_VIOLATION = "23514";
const OBSERVER_ID = "26026026-2600-4600-8600-260260260260";

/* ─── psql harness (mirrors observation-anomaly-indexes.pg.test.ts) ─── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Failure to *reach* PostgreSQL at all — the shared local instance is at `max_connections` because
 * several build lanes are hammering it — says nothing about the systems under test. Only that class
 * is retried, and only by matching psql's connection-establishment diagnostics. Every SQL error is
 * returned verbatim on the first attempt, so the scenarios that assert a specific SQLSTATE still see
 * exactly what the server said and no assertion can be retried into a pass.
 */
const CONNECTION_UNAVAILABLE =
  /too many clients already|could not connect to server|Connection refused|system is (starting up|shutting down)/i;

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  let last: PsqlOutcome = { ok: false, stdout: "", stderr: "" };
  for (let attempt = 1; attempt <= 12; attempt += 1) {
    try {
      const stdout = execFileSync("psql", args, {
        encoding: "utf-8",
        timeout: 60_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { ok: true, stdout, stderr: "" };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string };
      last = { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
    }
    if (!CONNECTION_UNAVAILABLE.test(last.stderr)) {
      return last;
    }
    execFileSync("sleep", ["5"], { stdio: "ignore" });
  }
  return last;
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

/**
 * Creating the scratch database is the one statement here that a *sibling* process can break: on a
 * shared local PostgreSQL, `CREATE DATABASE` from the default `template1` fails outright with
 * `source database "template1" is being accessed by other users` whenever another lane holds a
 * connection to it. `template0` has `datallowconn = false`, so it can never be contended that way.
 * The remaining risk is a slow checkpoint under load, which is retried with backoff; a client-side
 * timeout can still leave the database created server-side, so `already exists` counts as success.
 *
 * This is fixture setup only. Lane contention is environmental, never a defect in the systems under
 * test, and if creation genuinely never succeeds the suite hard-throws — it cannot degrade to a pass.
 */
const createScratchDatabase = (db: string): void => {
  let last = "";
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const outcome = runPsql(MAINTENANCE_DB, `CREATE DATABASE ${db} TEMPLATE template0`);
    if (outcome.ok || /already exists/i.test(outcome.stderr)) {
      return;
    }
    last = outcome.stderr.trim() || `attempt ${attempt} timed out`;
    execFileSync("sleep", [String(attempt * 2)], { stdio: "ignore" });
  }
  throw new Error(`could not create scratch database ${db}: ${last}`);
};

const applyFile = (db: string, file: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, file)], {
      encoding: "utf-8",
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`${file} apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const tx = (...statements: string[]): string => `BEGIN; ${statements.join(" ")} COMMIT;`;

/* ─── scripted gateway endpoints ─── */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// A scripted step: serve this body, or fail the exchange the way a network/TLS problem does.
type Step = { readonly body: string } | { readonly fail: string };

// A response envelope carrying a semantic head plus an envelope-only nonce, so "same head,
// different bytes" (the lag case) and "different head" (the split-view case) are both
// expressible.
const envelope = (head: string, nonce: string): string =>
  `{"status":true,"head":"${head}","envelope_nonce":"${nonce}"}`;

// observation semantic fingerprint, reduced to the head token and hashed. Injected into the
// failover service so an envelope-only byte difference is NOT a disagreement — the reduction
// itself is outside remit and is deliberately trivial here.
const semanticHead = (bytes: Uint8Array): string => {
  const text = decoder.decode(bytes);
  const m = /"head":"([^"]+)"/.exec(text);
  return sha256Hex(encoder.encode(m === null ? text : m[1]));
};

const headReducer: SemanticStateReducer = (capture: GatewayExchangeCapture): string =>
  semanticHead(capture.responseBytes);

// Each endpoint has a queue of steps; the LAST step is sticky, so a permanently unreachable
// endpoint needs exactly one { fail } entry. Rewritable mid-test (see the recovery scenario,
// where the primary comes back).
class EndpointScript {
  private readonly steps = new Map<string, Step[]>();
  private readonly touched: string[] = [];

  set(endpoint: string, ...steps: Step[]): this {
    this.steps.set(endpoint, [...steps]);
    return this;
  }

  endpointsTouched(): readonly string[] {
    return this.touched;
  }

  transport(): GatewayExchangeTransport {
    return {
      exchange: async (endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> => {
        this.touched.push(endpoint);
        const queue = this.steps.get(endpoint);
        if (queue === undefined || queue.length === 0) {
          throw new GatewayTransportAmbiguityError(`no script for endpoint ${endpoint}`, endpoint);
        }
        const step = queue.length === 1 ? queue[0] : (queue.shift() as Step);
        if ("fail" in step) {
          throw new GatewayTransportAmbiguityError(
            `scripted transport failure at ${endpoint}: ${step.fail}`,
            step.fail,
          );
        }
        const responseBytes = encoder.encode(step.body);
        return {
          endpoint,
          endpointFingerprint: fingerprintEndpoint(endpoint),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          responseBytes,
          responseSha256: sha256Hex(responseBytes),
          statusCode: 200,
        };
      },
    };
  }
}

/* ─── the real-PostgreSQL observation ledger ─── */

const SIG = `${"A".repeat(86)}==`;
const EMPTY_SHA256 = sha256Hex(new Uint8Array());
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

interface LedgerRow {
  readonly seq: number;
  readonly endpointFingerprint: string;
  readonly parseResult: string;
  readonly relationship: string;
  readonly semanticFingerprint: string;
}

interface PgLedger {
  readonly recorder: ObservationRecorder;
  readonly anomalyRecorder: AnomalyRecorder;
  rows(): readonly LedgerRow[];
  anomalyKinds(): readonly string[];
  // The frozen stream position standing in for wallet_observation_cursors (see the header).
  streamPosition(): number;
  rawBytesAt(seq: number): string;
  disagreements(): readonly EndpointDisagreementAnomaly[];
}

// Writes each ObservationRecorder callback into gateway_observations for real, classifying the
// relationship the only way this slice honestly can: without complete-path material no
// state change can be promoted to SUCCESSOR, so a changed semantic fingerprint is an
// UNEXPLAINED_JUMP and drags its mandatory observation_anomalies row along under the
// deferred pairing trigger. An unchanged fingerprint under different bytes is
// EQUIVALENT_STATE_DIFFERENT_ENVELOPE — retained, no anomaly, no head promotion.
const createPgLedger = (db: string, walletPublicKey: string): PgLedger => {
  let seq = 0;
  let priorFingerprint: string | null = null;
  let priorId: string | null = null;
  const captured: EndpointDisagreementAnomaly[] = [];

  const priorRef = (): string => (priorId === null ? "NULL" : `'${priorId}'`);

  const recordObservation = async (record: GatewayObservationRecord): Promise<void> => {
    seq += 1;
    const id = randomUUID();

    if (record.transportAmbiguous) {
      // The attempt itself is permanent evidence. raw_response_bytes is NOT NULL in the
      // frozen DDL while the record's bytes are null, so an ambiguous attempt maps onto empty
      // bytes plus the digest of the empty string — see limits doc.
      psqlMust(
        db,
        tx(
          `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
            `wallet_seq,observed_at,raw_response_bytes,raw_response_sha256,parse_result,relationship,` +
            `previous_recorded_observation_id) VALUES ('${id}','${OBSERVER_ID}',` +
            `'${record.endpointFingerprint}','${walletPublicKey}',${seq},'${record.observedAt}',` +
            `decode('','hex'),'${EMPTY_SHA256}','TRANSPORT_ERROR','NOT_APPLICABLE',${priorRef()});`,
          `INSERT INTO observation_anomalies (id,observation_id,observer_id,wallet_public_key,kind,` +
            `details,detected_at) VALUES ('${randomUUID()}','${id}','${OBSERVER_ID}',` +
            `'${walletPublicKey}','TRANSPORT_ERROR','scripted transport ambiguity',` +
            `'${record.observedAt}');`,
        ),
      );
      priorId = id;
      return;
    }

    const bytes = record.rawResponseBytes as Uint8Array;
    const fingerprint = semanticHead(bytes);
    const relationship =
      priorFingerprint === null
        ? "FIRST"
        : fingerprint === priorFingerprint
          ? "EQUIVALENT_STATE_DIFFERENT_ENVELOPE"
          : "UNEXPLAINED_JUMP";
    const stateChanged = relationship !== "EQUIVALENT_STATE_DIFFERENT_ENVELOPE";

    const observationInsert =
      `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
      `wallet_seq,observed_at,http_status,raw_response_bytes,raw_response_sha256,parse_result,` +
      `relationship,semantic_fingerprint,state_changed,wallet_role,s_signature,p_signature,` +
      `b_amount,inner_preimage_text,step_1_signature,step_2_signature,completed_transaction_text,` +
      `completed_transaction_sha256,previous_recorded_observation_id) VALUES ` +
      `('${id}','${OBSERVER_ID}','${record.endpointFingerprint}','${walletPublicKey}',${seq},` +
      `'${record.observedAt}',${record.httpStatus ?? "NULL"},decode('${toHex(bytes)}','hex'),` +
      `'${record.rawResponseSha256 as string}','VERIFIED_HEAD','${relationship}','${fingerprint}',` +
      `${stateChanged},'sender','${SIG}','${SIG}','1.5','inner-${seq}','${SIG}','${SIG}',` +
      `'completed-${seq}','${EMPTY_SHA256}',${priorRef()});`;

    if (relationship === "UNEXPLAINED_JUMP") {
      psqlMust(
        db,
        tx(
          observationInsert,
          `INSERT INTO observation_anomalies (id,observation_id,observer_id,wallet_public_key,kind,` +
            `details,detected_at) VALUES ('${randomUUID()}','${id}','${OBSERVER_ID}',` +
            `'${walletPublicKey}','UNEXPLAINED_JUMP','semantic fingerprint changed without ` +
            `complete-path proof','${record.observedAt}');`,
        ),
      );
    } else {
      psqlMust(db, observationInsert);
    }

    priorFingerprint = fingerprint;
    priorId = id;
  };

  const query = (sql: string): string[] => {
    const outcome = runPsql(db, sql);
    if (!outcome.ok) {
      throw new Error(`ledger query failed: ${outcome.stderr.trim()}`);
    }
    return outcome.stdout.trim() === "" ? [] : outcome.stdout.trim().split("\n");
  };

  return {
    recorder: { recordObservation },
    anomalyRecorder: {
      recordDisagreement: async (anomaly) => {
        captured.push(anomaly);
      },
    },
    rows: () =>
      query(
        `SELECT wallet_seq,endpoint_fingerprint,parse_result,relationship,` +
          `coalesce(semantic_fingerprint,'') FROM gateway_observations ` +
          `WHERE wallet_public_key='${walletPublicKey}' ORDER BY wallet_seq;`,
      ).map((line) => {
        const [s, fp, parseResult, relationship, semantic] = line.split("|");
        return {
          seq: Number(s),
          endpointFingerprint: fp,
          parseResult,
          relationship,
          semanticFingerprint: semantic,
        } as LedgerRow;
      }),
    anomalyKinds: () =>
      query(
        `SELECT a.kind FROM observation_anomalies a JOIN gateway_observations o ` +
          `ON o.id=a.observation_id WHERE o.wallet_public_key='${walletPublicKey}' ` +
          `ORDER BY o.wallet_seq;`,
      ),
    streamPosition: () =>
      Number(
        query(
          `SELECT coalesce(max(wallet_seq),0) FROM gateway_observations ` +
            `WHERE wallet_public_key='${walletPublicKey}';`,
        )[0] ?? "0",
      ),
    rawBytesAt: (wanted) =>
      query(
        `SELECT encode(raw_response_bytes,'escape') FROM gateway_observations ` +
          `WHERE wallet_public_key='${walletPublicKey}' AND wallet_seq=${wanted};`,
      )[0] ?? "",
    disagreements: () => captured,
  };
};

/* ─── shared read wiring ─── */

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 65_536,
  maxResponseBytes: 65_536,
};

const ACTION = "get_transaction__v1" as const;
const ACTION_DATA = { transaction_signature_base64urlsafe: SIG };

const readOptions = (
  recorder: ObservationRecorder,
  exchange: GatewayExchangeTransport,
): ReadGatewayRequestOptions => ({
  // Overridden per call by the failover service with its own ordered rotation.
  endpoints: [],
  limits: LIMITS,
  recorder,
  exchange,
  sleep: async () => {},
  jitter: () => 0,
  // One pass over the endpoint list per read: the failover behaviour under test is the
  // primary-fails/backup-serves switch, not the retry schedule (covered by read.ts's own tests).
  maxAttempts: 1,
});

// Wallet public keys must satisfy the padded_base64url_pubkey domain: 43 body chars + '='.
const walletKey = (tag: string): string => `${tag.padEnd(43, "Z").slice(0, 43)}=`;

// Reads the post-resolution stream state for (6b) out of the same real ledger (6a) wrote.
const streamStateOf = (
  db: string,
  wallet: string,
): { latestFingerprint: string; position: number; anomalies: number } => {
  const read = (sql: string): string => runPsql(db, sql).stdout.trim();
  return {
    latestFingerprint: read(
      `SELECT semantic_fingerprint FROM gateway_observations WHERE wallet_public_key='${wallet}' ` +
        `AND semantic_fingerprint IS NOT NULL ORDER BY wallet_seq DESC LIMIT 1;`,
    ),
    position: Number(
      read(
        `SELECT coalesce(max(wallet_seq),0) FROM gateway_observations ` +
          `WHERE wallet_public_key='${wallet}';`,
      ),
    ),
    anomalies: Number(
      read(
        `SELECT count(*) FROM observation_anomalies a JOIN gateway_observations o ` +
          `ON o.id=a.observation_id WHERE o.wallet_public_key='${wallet}';`,
      ),
    ),
  };
};

const PRIMARY = "https://primary.gateway.example/rpc";
const BACKUP = "https://backup.gateway.example/rpc";

const EXPECTED_ASSERTIONS = 14;
let assertionsRun = 0;

// Every scenario spawns several psql child processes. Under concurrent lanes the shared local
// PostgreSQL is heavily contended, so the budgets here are generous: a slow CREATE DATABASE is
// lane contention, never a defect, and must not be able to turn a real assertion into a
// timeout-shaped false failure.
describe(
  "lag, equivocation and disagreement (scripted endpoints, real PostgreSQL ledger)",
  { timeout: 120_000 },
  () => {
    const scratchDb = `lag_equivocation_lagequiv_${Date.now()}_${process.pid}`;

    beforeAll(() => {
      const probe = runPsql(MAINTENANCE_DB, "SELECT 1");
      if (!probe.ok) {
        // Deliberately a hard failure, never a skip: a disagreement suite that quietly passes
        // when its store is missing is exactly the failure mode this suite exists to catch.
        throw new Error(
          `PostgreSQL maintenance database "${MAINTENANCE_DB}" is unreachable, so the ` +
            `lag/equivocation drills cannot run against a real ledger: ${probe.stderr.trim()}`,
        );
      }
      createScratchDatabase(scratchDb);
      psqlMust(scratchDb, "CREATE TABLE wallets (id uuid PRIMARY KEY);");
      applyFile(scratchDb, "observation-ledger.sql");
      applyFile(scratchDb, "observation-anomaly-indexes.sql");
      psqlMust(
        scratchDb,
        `INSERT INTO observers (id,domain,owner_id,gateway_endpoint_fingerprint,created_at) VALUES ` +
          `('${OBSERVER_ID}','NODE',gen_random_uuid(),'${fingerprintEndpoint(PRIMARY)}',now());`,
      );
    }, 180_000);

    afterAll(() => {
      // Dropping a scratch fixture is housekeeping, not an assertion. Under concurrent lanes the drop
      // can exceed its budget; a leaked scratch database must not be able to turn a green run red.
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        if (runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`).ok) {
          return;
        }
      }
      console.warn(`leaked scratch database ${scratchDb} (drop contended)`);
    }, 240_000);

    /* ── 1. lagging replica ─────────────────────────────────────────────────────────────── */

    it("(1a) lag, same head: failover to a fresher endpoint is NOT read as a disagreement", async () => {
      const wallet = walletKey("LAG_SAME_HEAD");
      const ledger = createPgLedger(scratchDb, wallet);
      // The backup serves the SAME head under a different envelope — a lagging-but-honest replica
      // that has caught up. Byte-different, semantically identical.
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("H1", "primary-nonce") }, { fail: "replica went away" })
        .set(BACKUP, { body: envelope("H1", "backup-nonce") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      const first = await service.read(ACTION, ACTION_DATA, options);
      expect(first.verificationStatus).toBe("ACCEPTED");
      expect(first.failedOver).toBe(false);

      const second = await service.read(ACTION, ACTION_DATA, options);
      expect(second.verificationStatus).toBe("ACCEPTED");
      expect(second.failedOver).toBe(true);
      expect(second.disagreement).toBeNull();
      expect(service.isHalted()).toBe(false);
      expect(ledger.disagreements()).toHaveLength(0);

      // The ledger agrees: envelope-only difference, retained, no head promotion, no anomaly.
      const rows = ledger.rows();
      expect(rows.map((r) => r.relationship)).toEqual([
        "FIRST",
        "NOT_APPLICABLE",
        "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      ]);
      expect(rows[0].semanticFingerprint).toBe(rows[2].semanticFingerprint);
      // Only the primary's transport-ambiguity marker is anomalous — the failover itself is not.
      expect(ledger.anomalyKinds()).toEqual(["TRANSPORT_ERROR"]);
      assertionsRun += 1;
    });

    it("(1b) lag, same head: the DEFAULT raw-digest reducer WOULD halt — the reducer is load-bearing", async () => {
      const wallet = walletKey("LAG_RAW_DIGEST");
      const ledger = createPgLedger(scratchDb, wallet);
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("H1", "primary-nonce") }, { fail: "replica went away" })
        .set(BACKUP, { body: envelope("H1", "backup-nonce") });
      // No semanticState override: failover.ts falls back to the raw response sha256, which is
      // envelope-INtolerant by construction and fails closed on any byte difference.
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await service.read(ACTION, ACTION_DATA, options);
      const second = await service.read(ACTION, ACTION_DATA, options);
      expect(second.verificationStatus).toBe("INDETERMINATE");
      expect(service.isHalted()).toBe(true);
      assertionsRun += 1;
    });

    it("(1c) lag, advanced head: a fresher backup is parked INDETERMINATE, not silently accepted", async () => {
      const wallet = walletKey("LAG_AHEAD");
      const ledger = createPgLedger(scratchDb, wallet);
      // The backup is genuinely AHEAD. failover.ts cannot tell an honest fresher replica from a
      // forked endpoint, so observation applies: "a genuine landing may be safely parked
      // INDETERMINATE. Availability yields to avoiding phantom settlement or duplicate payment."
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("H1", "primary-nonce") }, { fail: "replica went away" })
        .set(BACKUP, { body: envelope("H2", "backup-nonce") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await service.read(ACTION, ACTION_DATA, options);
      const second = await service.read(ACTION, ACTION_DATA, options);
      expect(second.verificationStatus).toBe("INDETERMINATE");
      expect(second.failedOver).toBe(false);
      // Not adopted: the possibly-forked backup does not become the active endpoint.
      expect(service.activeEndpoint()).toBe(PRIMARY);
      expect(service.failoverCount()).toBe(0);
      assertionsRun += 1;
    });

    /* ── 2. honest failover ─────────────────────────────────────────────────────────────── */

    it("(2) honest failover is ordinary continuation evidence, not a gap", async () => {
      const wallet = walletKey("HONEST_FAILOVER");
      const ledger = createPgLedger(scratchDb, wallet);
      const events: string[] = [];
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("H1", "p1") }, { fail: "ECONNREFUSED" })
        .set(BACKUP, { body: envelope("H1", "b1") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        recorder: {
          recordFailover: async (event) => {
            events.push(`${event.fromEndpointFingerprint}->${event.toEndpointFingerprint}`);
          },
        },
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      const baseline = await service.read(ACTION, ACTION_DATA, options);
      const result = await service.read(ACTION, ACTION_DATA, options);

      expect(result.failedOver).toBe(true);
      expect(result.verificationStatus).toBe("ACCEPTED");
      expect(result.failover?.ambiguousFailures).toBe(1);
      expect(events).toEqual([`${fingerprintEndpoint(PRIMARY)}->${fingerprintEndpoint(BACKUP)}`]);
      // The active endpoint durably advanced: this failover is accepted, not merely tolerated.
      expect(service.activeEndpoint()).toBe(BACKUP);
      expect(service.failoverCount()).toBe(1);

      // The observation stream is contiguous across the switch: three rows, the unreachable
      // endpoint's marker between the two served reads, all from one observer's stream.
      const rows = ledger.rows();
      expect(rows.map((r) => r.seq)).toEqual([1, 2, 3]);
      expect(rows.map((r) => r.endpointFingerprint)).toEqual([
        fingerprintEndpoint(PRIMARY),
        fingerprintEndpoint(PRIMARY),
        fingerprintEndpoint(BACKUP),
      ]);
      expect(rows[1].parseResult).toBe("TRANSPORT_ERROR");

      // observation anti-laundering holds even on an honest failover: a different endpoint cannot
      // prove continuity with the baseline the primary established.
      const t0 = {
        semanticState: headReducer(baseline.capture),
        establishedByFingerprint: baseline.capture.endpointFingerprint,
      };
      expect(
        provesT0Continuity(t0, {
          semanticState: headReducer(result.capture),
          servedEndpointFingerprint: result.servedEndpointFingerprint,
        }),
      ).toBe(false);
      assertionsRun += 1;
    });

    /* ── 3. split views ─────────────────────────────────────────────────────────────────── */

    it("(3a) split views: two endpoints report different heads → INDETERMINATE oracle incident", async () => {
      const wallet = walletKey("SPLIT_VIEW");
      const ledger = createPgLedger(scratchDb, wallet);
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("FORK_A", "p1") }, { fail: "primary unreachable" })
        .set(BACKUP, { body: envelope("FORK_B", "b1") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await service.read(ACTION, ACTION_DATA, options);
      const split = await service.read(ACTION, ACTION_DATA, options);

      expect(split.verificationStatus).toBe("INDETERMINATE");
      expect(split.failedOver).toBe(false);
      expect(service.isHalted()).toBe(true);

      // Neither endpoint is silently preferred: the anomaly names BOTH fingerprints and BOTH
      // conflicting states, and the active endpoint has not moved.
      const anomaly = split.disagreement;
      expect(anomaly).not.toBeNull();
      expect(anomaly?.acceptedEndpointFingerprint).toBe(fingerprintEndpoint(PRIMARY));
      expect(anomaly?.servingEndpointFingerprint).toBe(fingerprintEndpoint(BACKUP));
      expect(anomaly?.acceptedSemanticState).toBe(sha256Hex(encoder.encode("FORK_A")));
      expect(anomaly?.servingSemanticState).toBe(sha256Hex(encoder.encode("FORK_B")));
      expect(anomaly?.acceptedSemanticState).not.toBe(anomaly?.servingSemanticState);
      expect(ledger.disagreements()).toHaveLength(1);
      expect(service.activeEndpoint()).toBe(PRIMARY);

      // Both conflicting reads are permanent in the ledger; the second is an UNEXPLAINED_JUMP
      // that dragged its mandatory anomaly row in under the deferred pairing trigger.
      const rows = ledger.rows();
      expect(rows.map((r) => r.relationship)).toEqual(["FIRST", "NOT_APPLICABLE", "UNEXPLAINED_JUMP"]);
      expect(rows[0].semanticFingerprint).not.toBe(rows[2].semanticFingerprint);
      expect(ledger.anomalyKinds()).toEqual(["TRANSPORT_ERROR", "UNEXPLAINED_JUMP"]);
      assertionsRun += 1;
    });

    it("(3b) an endpoint disagreement has NO home in the frozen anomaly vocabulary (23514)", () => {
      // Executed against the real DDL, not matched against its text: the nine-member kind CHECK
      // rejects an endpoint-disagreement anomaly, which is why the AnomalyRecorder above captures
      // in memory. Reported as a gap (limits doc), never closed by inventing a kind.
      const observation = randomUUID();
      const wallet = walletKey("KIND_VOCAB");
      const attempt = runPsql(
        scratchDb,
        tx(
          `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
            `wallet_seq,observed_at,raw_response_bytes,raw_response_sha256,parse_result,relationship) ` +
            `VALUES ('${observation}','${OBSERVER_ID}','${fingerprintEndpoint(PRIMARY)}','${wallet}',1,` +
            `now(),decode('','hex'),'${EMPTY_SHA256}','TRANSPORT_ERROR','NOT_APPLICABLE');`,
          `INSERT INTO observation_anomalies (id,observation_id,observer_id,wallet_public_key,kind,` +
            `details,detected_at) VALUES ('${randomUUID()}','${observation}','${OBSERVER_ID}',` +
            `'${wallet}','ENDPOINT_DISAGREEMENT','two endpoints disagree',now());`,
        ),
        true,
      );
      expect(attempt.ok, "ENDPOINT_DISAGREEMENT must not be an accepted anomaly kind today").toBe(false);
      expect(extractSqlstate(attempt.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
      // The kind vocabulary itself must be what refuses this row. The pairing trigger also raises
      // 23514, so SQLSTATE alone would go green on a widened CHECK; only a real CHECK violation
      // carries a CONSTRAINT NAME, which a PL/pgSQL RAISE cannot forge.
      expect(attempt.stderr).toMatch(/CONSTRAINT NAME:\s+observation_anomalies_kind_check/);
      assertionsRun += 1;
    });

    /* ── 4. consistent Byzantine fiction ────────────────────────────────────────────────── */

    it("(4) a fiction BOTH endpoints agree on is accepted — out of model, not a false green", async () => {
      const wallet = walletKey("BYZANTINE_FICTION");
      const ledger = createPgLedger(scratchDb, wallet);
      // Both endpoints lie in the same direction. Cross-endpoint comparison detects DISAGREEMENT;
      // it cannot detect agreed-upon falsehood. The assertion below is that the service ACCEPTS
      // it — asserting otherwise would be a fabricated capability.
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("FICTION", "p1") }, { fail: "primary unreachable" })
        .set(BACKUP, { body: envelope("FICTION", "b1") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await service.read(ACTION, ACTION_DATA, options);
      const result = await service.read(ACTION, ACTION_DATA, options);

      expect(result.verificationStatus).toBe("ACCEPTED");
      expect(service.isHalted()).toBe(false);
      expect(ledger.disagreements()).toHaveLength(0);
      // The fiction is promoted into the ledger as ordinary state. No mechanism here objects.
      expect(ledger.rows().map((r) => r.relationship)).toEqual([
        "FIRST",
        "NOT_APPLICABLE",
        "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      ]);
      // A ground truth the suite knows and the node cannot reach: nothing in the observation
      // stream distinguishes it from the fiction both endpoints served.
      expect(semanticHead(result.capture.responseBytes)).not.toBe(
        sha256Hex(encoder.encode("GROUND_TRUTH")),
      );
      assertionsRun += 1;
    });

    // The quotes below are the frozen observation-model residual limits, verbatim.
    it("(4b) the residual-limits document exists and carries the frozen limits verbatim", () => {
      const doc = readFileSync(limitsDoc, "utf-8");
      const quotes = [
        "It does not defeat a fully Byzantine SplitChain gateway that presents a",
        "consistent cryptographic fiction to every verifier; that requires an additional independent oracle.",
        "**Gateway equivocation:** independent node/platform observations expose some disagreement, but a gateway",
        "that lies consistently to both remains out of model.",
        "**Gateway lag:** a genuine landing may be safely parked `INDETERMINATE`. Availability yields to avoiding",
        "phantom settlement or duplicate payment.",
      ];
      for (const quote of quotes) {
        expect(doc, `limits doc no longer quotes: ${quote}`).toContain(quote);
      }
      assertionsRun += 1;
    });

    /* ── 5. TLS / endpoint-identity mismatch ────────────────────────────────────────────── */

    it("(5a) an unconfigured endpoint identity is refused before any exchange — no ledger row at all", async () => {
      const wallet = walletKey("TLS_IDENTITY");
      const ledger = createPgLedger(scratchDb, wallet);
      const impostor = "https://impostor.gateway.example/rpc";
      const allowlist = createGatewayEndpointAllowlist([PRIMARY, BACKUP]);

      expect(() => {
        assertEndpointAllowed(allowlist, impostor);
      }).toThrow(GatewayEndpointNotAllowedError);

      // The refusal happens before the read primitive is ever entered, so nothing is recorded.
      const script = new EndpointScript().set(impostor, { body: envelope("IMPOSTOR", "x") });
      expect(script.endpointsTouched()).toHaveLength(0);
      expect(ledger.rows()).toHaveLength(0);
      expect(ledger.streamPosition()).toBe(0);
      expect(
        runPsql(
          scratchDb,
          `SELECT count(*) FROM gateway_observations WHERE endpoint_fingerprint=` +
            `'${fingerprintEndpoint(impostor)}';`,
        ).stdout.trim(),
      ).toBe("0");
      assertionsRun += 1;
    });

    it("(5b) non-TLS and credential-bearing endpoints are refused at configuration time", () => {
      expect(() => createGatewayEndpointAllowlist(["http://gateway.example/rpc"])).toThrow(
        GatewayConfigurationError,
      );
      expect(() => createGatewayEndpointAllowlist(["https://user:pw@gateway.example/rpc"])).toThrow(
        GatewayConfigurationError,
      );
      // Loopback http remains permitted (local development), and must not be confused with the above.
      expect(createGatewayEndpointAllowlist(["http://127.0.0.1:8080/rpc"])).toHaveLength(1);
      assertionsRun += 1;
    });

    it("(5c) a TLS handshake failure can only land a transport marker, never an accepted head", async () => {
      const wallet = walletKey("TLS_HANDSHAKE");
      const ledger = createPgLedger(scratchDb, wallet);
      // Both endpoints fail the handshake, so the bounded read exhausts and no head is accepted.
      const script = new EndpointScript()
        .set(PRIMARY, { fail: "ERR_TLS_CERT_ALTNAME_INVALID" })
        .set(BACKUP, { fail: "SELF_SIGNED_CERT_IN_CHAIN" });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await expect(service.read(ACTION, ACTION_DATA, options)).rejects.toThrow(
        /failed with transport ambiguity/,
      );

      const rows = ledger.rows();
      expect(rows).toHaveLength(2);
      expect(rows.every((r) => r.parseResult === "TRANSPORT_ERROR")).toBe(true);
      expect(rows.every((r) => r.semanticFingerprint === "")).toBe(true);
      expect(ledger.anomalyKinds()).toEqual(["TRANSPORT_ERROR", "TRANSPORT_ERROR"]);
      // No head was accepted, so nothing can later be adopted as this stream's state.
      expect(
        runPsql(
          scratchDb,
          `SELECT count(*) FROM gateway_observations WHERE wallet_public_key='${wallet}' ` +
            `AND parse_result IN ('VERIFIED_HEAD','VERIFIED_GENESIS');`,
        ).stdout.trim(),
      ).toBe("0");
      expect(service.isHalted()).toBe(false);
      assertionsRun += 1;
    });

    /* ── 6. recovery ────────────────────────────────────────────────────────────────────── */

    it("(6a) a halt freezes the stream and only resolveHalt() lifts it", async () => {
      const wallet = walletKey("RECOVERY");
      const ledger = createPgLedger(scratchDb, wallet);
      const script = new EndpointScript()
        .set(PRIMARY, { body: envelope("H1", "p1") }, { fail: "primary unreachable" })
        .set(BACKUP, { body: envelope("FORK", "b1") });
      const service = createEndpointFailoverService({
        endpoints: [PRIMARY, BACKUP],
        observerId: OBSERVER_ID,
        anomalyRecorder: ledger.anomalyRecorder,
        semanticState: headReducer,
      });
      const options = readOptions(ledger.recorder, script.transport());

      await service.read(ACTION, ACTION_DATA, options);
      await service.read(ACTION, ACTION_DATA, options);
      expect(service.isHalted()).toBe(true);

      const frozenPosition = ledger.streamPosition();
      const frozenAnomalies = ledger.anomalyKinds().length;
      const priorBytes = ledger.rawBytesAt(frozenPosition);
      expect(priorBytes).toBe(envelope("FORK", "b1"));

      // Every automated read is refused while halted, and the stream position does not move.
      await expect(service.read(ACTION, ACTION_DATA, options)).rejects.toThrow(GatewayEndpointHaltError);
      expect(ledger.streamPosition()).toBe(frozenPosition);

      // The primary comes back healthy and AGREES with the accepted state. That still does not
      // self-clear the incident — no boot/health path may auto-clear attention.
      script.set(PRIMARY, { body: envelope("H1", "p2") });
      await expect(service.read(ACTION, ACTION_DATA, options)).rejects.toThrow(GatewayEndpointHaltError);
      expect(service.isHalted()).toBe(true);
      expect(ledger.streamPosition()).toBe(frozenPosition);

      // The authority policy resolves. Evidence survives resolution (observation: "operator resolution
      // never deletes evidence"), and reads resume through the ordinary classification path.
      service.resolveHalt();
      expect(service.isHalted()).toBe(false);
      expect(ledger.anomalyKinds()).toHaveLength(frozenAnomalies);
      expect(ledger.streamPosition()).toBe(frozenPosition);

      const resumed = await service.read(ACTION, ACTION_DATA, options);
      expect(resumed.verificationStatus).toBe("ACCEPTED");
      expect(ledger.streamPosition()).toBe(frozenPosition + 1);
      // The recovery read is classified like any other observation — it is an UNEXPLAINED_JUMP
      // back off the forked head, with its own permanent anomaly row. No flag was cleared.
      expect(ledger.rows().at(-1)?.relationship).toBe("UNEXPLAINED_JUMP");
      expect(ledger.anomalyKinds()).toHaveLength(frozenAnomalies + 1);
      assertionsRun += 1;
    });

    it("(6b) recovery cannot rewind the observed head fingerprint", () => {
      // observation / recovery: resolution moves forward. The head fingerprint folds the anomaly count and
      // the stream position, so a resolved incident can never restore a pre-incident value.
      const wallet = walletKey("RECOVERY");
      const preIncident = computeObservationHeadFingerprint({
        entries: [
          {
            walletPublicKey: wallet,
            latestSemanticFingerprint: sha256Hex(encoder.encode("H1")),
            nextWalletSeq: 2,
            consecutiveRepeatCount: 0,
            anomalyCount: 0,
          },
        ],
      });
      const rows = streamStateOf(scratchDb, wallet);
      const postResolution = computeObservationHeadFingerprint({
        entries: [
          {
            walletPublicKey: wallet,
            latestSemanticFingerprint: rows.latestFingerprint,
            nextWalletSeq: rows.position + 1,
            consecutiveRepeatCount: 0,
            anomalyCount: rows.anomalies,
          },
        ],
      });
      expect(rows.anomalies).toBeGreaterThan(0);
      expect(postResolution).not.toBe(preIncident);
      assertionsRun += 1;
    });

    it("(6c) the incident cannot be laundered: an unpaired anomaly classification is rejected (23514)", () => {
      // The only structural guarantee behind "never an ad hoc clear the flag": an
      // anomaly-classified observation without its observation_anomalies row is refused at COMMIT
      // by the real deferred trigger. Deleting an already-written anomaly row is NOT prevented by
      // the DDL — recorded as a gap in the limits doc rather than asserted away.
      const wallet = walletKey("LAUNDER");
      const attempt = runPsql(
        scratchDb,
        tx(
          `INSERT INTO gateway_observations (id,observer_id,endpoint_fingerprint,wallet_public_key,` +
            `wallet_seq,observed_at,http_status,raw_response_bytes,raw_response_sha256,parse_result,` +
            `relationship,semantic_fingerprint,state_changed,wallet_role,s_signature,p_signature,` +
            `b_amount,inner_preimage_text,step_1_signature,step_2_signature,` +
            `completed_transaction_text,completed_transaction_sha256) VALUES ` +
            `('${randomUUID()}','${OBSERVER_ID}','${fingerprintEndpoint(BACKUP)}','${wallet}',1,now(),` +
            `200,decode('','hex'),'${EMPTY_SHA256}','VERIFIED_HEAD','UNEXPLAINED_JUMP',` +
            `'${EMPTY_SHA256}',true,'sender','${SIG}','${SIG}','1.5','inner','${SIG}','${SIG}',` +
            `'completed','${EMPTY_SHA256}');`,
        ),
        true,
      );
      expect(attempt.ok, "an UNEXPLAINED_JUMP with no anomaly row must be rejected").toBe(false);
      expect(extractSqlstate(attempt.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
      assertionsRun += 1;
    });

    // Declared last so it runs after every scenario above: if a scenario is deleted, renamed
    // out of the run, or silently skipped, the count no longer matches and this fails.
    it("obligation guard: every lag/equivocation scenario must have executed", () => {
      expect(
        assertionsRun,
        "a scenario did not run — the six scripted scenarios are the deliverable",
      ).toBe(EXPECTED_ASSERTIONS);
    });
  },
);
