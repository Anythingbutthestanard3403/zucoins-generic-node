/**
 * no-second-external-partial-race.pg.test.ts
 *
 * — the STATE-MACHINE half of "no second external partial".
 *
 * The sibling file test/external-send-partial-uniqueness.pg.test.ts discharges the
 * constraint half (a deliberately-forced duplicate INSERT rejected at the schema level,
 * against the frozen transaction-material DDL with stub FK parents). This file discharges
 * what that one explicitly deferred because/ had not landed: racing the
 * real post-delivery attention state machine and the real late-landing reconciliation loop
 * against one another, against a real operation, on real PostgreSQL.
 *
 * "One approval authorizes one exact persisted external partial... it never permits a
 * second partial under the old approval." is the SEND-expiry instance. A second signed
 * partial is the P0 example in operations recovery, so it is proven at the layer no
 * mis-ordered caller can bypass — and, here, under genuine concurrency.
 *
 * Governing: operations recovery — restore AWAITING_REDEMPTION and return only identical
 * persisted bytes; the terminal close this races against but does not implement; and golden
 * rules 2 ("exactly one contender may reach signing") and 4.
 *
 * WHAT IS REAL HERE
 *   - Postgres, hermetic scratch DB, frozen DDL applied verbatim (base-enums-domains,
 *     nodes, custody-eligibility, send-external-create, send-external-landing,
 *     send-external-expiry, transaction-material). No constraint is re-declared.
 *   - The racers are the SHIPPED functions: parkPastExpiryAwaitingRedemption,
 *     continueExternalWait, redeliverExactPartial and applyLateLandingCycle
 *     plus raw SQL for the two surfaces that are deliberately NOT code paths
 *     (an idempotent create replay, and a forced second partial).
 *   - Concurrency is real, and is itself asserted rather than assumed. The SqlQueryFn is
 *     ASYNC (execFile, not execFileSync), so every racer's statements land on its own psql
 *     backend and genuinely interleave; each round asserts that more than one backend was
 *     in flight at once, so a regression to a synchronous query fn reddens the drill
 *     instead of quietly turning it into six sequential calls. That silent degradation is
 *     the exact regression this drill exists to catch.
 *
 * WHAT IS A DOUBLE, STATED PLAINLY
 *   applyLateLandingCycle's landing/proof stores are own in-memory ports. The
 *   attempted-terminal-close racer is therefore asserted on BOTH surfaces: the returned
 *   outcome must be REFUSED_CLOSE, AND the in-memory stores must be empty (a close that
 *   "succeeded" would land there, not in the DB, so a DB-only assertion would pass
 *   vacuously). The DB assertion that the operation never reached a terminal status is
 *   additional, not a substitute.
 *
 * WHAT IS NOT CLAIMED
 *   Engine-level byte-immutability triggers live in transaction-material-byte-immutability.sql
 *   and are proven in transaction-material-byte-immutability.pg.test.ts. This file proves the
 *   shipped code paths never mutate the bytes under concurrency.
 */
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import type { PathObservation } from "../src/protocol/reconcile/observation-input.ts";
import {
  SEND_EXPIRY_ATTENTION_REASON,
  continueExternalWait,
  fingerprintPartialImmutableBytes,
  loadSendExpiryOperationFacts,
  parkPastExpiryAwaitingRedemption,
  redeliverExactPartial,
} from "../src/send/expiry-attention.ts";
import { InMemoryExternalSendLandingStore } from "../src/send/landing-sql-store.ts";
import {
  InMemorySendLateLandingProofStore,
  applyLateLandingCycle,
  type LateLandingOperationFacts,
} from "../src/send/late-landing-reconcile.ts";
import type { SendLandingEvidence } from "../src/send/landing-verify.ts";
import { parseGatewayEnvelope } from "../src/verifier/gateway-envelope.ts";
import type { ParsedSettledTransaction } from "../src/verifier/gateway-envelope.ts";
import { verifySettledTransaction } from "../src/verifier/transaction-verify.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = join(HERE, "../src");
const SCHEMA_DIR = join(SRC_DIR, "schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "no_second_external_no2nd_race_";
const EXPECTED_DRILL_COUNT = 7;

const SQLSTATE_UNIQUE_VIOLATION = "23505";

/** Shared Postgres: CREATE/DROP DATABASE serialises on the template lock. */
const PSQL_TIMEOUT_MS = 90_000;

const NODE_ID = "d0000000-0000-4000-8000-000000000001";
const IMPL_ID = "d0000000-0000-4000-8000-000000000002";
const KEY_ID = "d0000000-0000-4000-8000-000000000004";
const LEASE_GROUP_ID = "d0000000-0000-4000-8000-000000000006";
const OBS_SRC = "d0000000-0000-4000-8000-000000000007";
const OBS_DST = "d0000000-0000-4000-8000-000000000008";
const OBSERVER_ID = "d0000000-0000-4000-8000-000000000009";

const OP_RACE = "d0000000-0000-4000-8000-000000000010";
const OP_AMBIGUITY = "d0000000-0000-4000-8000-000000000011";
const OP_REDELIVER = "d0000000-0000-4000-8000-000000000012";
const OP_NEW_CREATE = "d0000000-0000-4000-8000-000000000013";
const OP_NEW_CREATE_OK = "d0000000-0000-4000-8000-000000000014";

const DEST = `${"D".repeat(43)}=`;
const NODE_PUBKEY = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;
const LEASE_EPOCH = 7;

const T2_SECS = "1784333100";
const T2_ISO = new Date(Number(T2_SECS) * 1000).toISOString();
const INNER_PREIMAGE = JSON.stringify({
  expiry__unix_time_secs: T2_SECS,
  amount__str: "1.5",
  destination: DEST,
});
const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");
const INNER_SHA = sha256Hex(INNER_PREIMAGE);
const TRANSFER_CODE = `zp-send-v1:${INNER_SHA}:exact-bytes-must-not-change`;
const TRANSFER_SHA = sha256Hex(TRANSFER_CODE);

/** The one fingerprint every drill compares against. Divergence here IS the P0. */
const EXPECTED_BYTES = fingerprintPartialImmutableBytes({
  innerSha256: INNER_SHA,
  step1Signature: SIG,
  transferCodeText: TRANSFER_CODE,
  transferCodeSha256: TRANSFER_SHA,
});

/* ─── psql plumbing ──────────────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const psqlArgv = (db: string, sql: string): readonly string[] => [
  "-d",
  db,
  "-v",
  "ON_ERROR_STOP=1",
  "-v",
  "VERBOSITY=verbose",
  "-qAt",
  "-c",
  sql,
];

/**
 * Concurrency witness for the SERVICE racers — the ones that reach Postgres through the
 * SqlQueryFn (redeliverExactPartial, parkPastExpiryAwaitingRedemption,
 * continueExternalWait). Counts how many of their statements are in flight at once.
 *
 * Scoped deliberately to the query fn rather than to every psql call. Two of the six racers
 * are raw execFile by construction and would hold a global counter above 1 no matter what
 * the service racers did, which makes a global measure unfalsifiable — the mutation probe
 * that neutralises the query fn must be able to redden this.
 *
 * Timing the racer promises does NOT work and must not be reintroduced: a blocking
 * execFileSync inside an async racer still yields a microtask when it finally awaits, so
 * every racer's promise looks "open" at the same time even though the work ran strictly one
 * after another. This file shipped that weaker assertion first and the probe caught it.
 * Counting in-flight statements cannot be fooled: a synchronous call increments and
 * decrements inside itself, so nothing else can enter and the peak can never exceed 1.
 */
let queryInFlight = 0;
let queryPeakInFlight = 0;
const enterQuery = (): void => {
  queryInFlight += 1;
  if (queryInFlight > queryPeakInFlight) queryPeakInFlight = queryInFlight;
};
const leaveQuery = (): void => {
  queryInFlight -= 1;
};
const resetQueryPeak = (): void => {
  queryPeakInFlight = queryInFlight;
};

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", [...psqlArgv(db, sql)], {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      // Drills provoke intentional constraint violations; psql ERROR text is asserted on.
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

/**
 * Async psql. This is the load-bearing difference from the harness: execFileSync
 * blocks the event loop, so a Promise.all over sync-backed racers executes them strictly
 * one after another. Every concurrent claim in this file rests on this being execFile.
 */
const runPsqlAsync = (db: string, sql: string): Promise<PsqlOutcome> =>
  new Promise((resolvePromise) => {
    execFile(
      "psql",
      [...psqlArgv(db, sql)],
      { encoding: "utf-8", timeout: PSQL_TIMEOUT_MS },
      (err, stdout, stderr) => {
        resolvePromise(
          err === null
            ? { ok: true, stdout, stderr }
            : { ok: false, stdout: stdout ?? "", stderr: stderr ?? String(err) },
        );
      },
    );
  });

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const applyDdlFile = (db: string, path: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", path], {
      encoding: "utf-8",
      timeout: PSQL_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply ${path} failed: ${(e.stderr ?? "").trim() || "unknown"}`);
  }
};

const probePostgres = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};
const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

const sqlStr = (value: string): string => value.replace(/'/g, "''");

/**
 * SqlQueryFn over async psql. Mirrors the PG harness's binder (right-to-left so
 * $10 is not clobbered by $1) and its data-modifying-CTE handling, but awaits a real
 * subprocess rather than blocking, which is what makes the interleavings genuine.
 */
function makeAsyncQuery(db: string): SqlQueryFn {
  return async (text, values) => {
    let bound = text;
    for (let i = values.length; i >= 1; i -= 1) {
      const v = values[i - 1];
      let lit: string;
      if (v === null || v === undefined) lit = "NULL";
      else if (typeof v === "number" || typeof v === "bigint") lit = String(v);
      else if (typeof v === "boolean") lit = v ? "TRUE" : "FALSE";
      else lit = `'${sqlStr(String(v))}'`;
      bound = bound.replace(new RegExp(`\\$${i}(?!\\d)`, "g"), lit);
    }
    // A data-modifying WITH must stay top level; materialise through a temp table.
    const isDataModifyingCte =
      /^\s*WITH\b/i.test(bound) && /\b(UPDATE|INSERT|DELETE)\b/i.test(bound);
    const wrapped = isDataModifyingCte
      ? `BEGIN; ` +
        `CREATE TEMP TABLE _q_scratch ON COMMIT DROP AS ${bound}; ` +
        `SELECT coalesce(json_agg(row_to_json(_q_scratch)), '[]'::json)::text FROM _q_scratch; ` +
        `COMMIT;`
      : `WITH q AS (${bound}) ` +
        `SELECT coalesce(json_agg(row_to_json(q)), '[]'::json)::text FROM q`;
    enterQuery();
    let outcome: PsqlOutcome;
    try {
      outcome = await runPsqlAsync(db, wrapped);
    } finally {
      leaveQuery();
    }
    if (!outcome.ok) {
      throw new Error(outcome.stderr.trim() || `query failed: ${bound.slice(0, 200)}`);
    }
    const line = outcome.stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
    return JSON.parse(line) as Record<string, unknown>[];
  };
}

/* ─── seeding ────────────────────────────────────────────────────────────────── */

const seedNode = (db: string): void => {
  psqlMust(
    db,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
      `('${NODE_ID}', 'no-second-external-no2nd', '${NODE_PUBKEY}') ON CONFLICT (id) DO NOTHING;`,
  );
};

const seedWallet = (db: string, walletId: string): void => {
  const recoveryId = sha256Hex(`rec:${walletId}`).slice(0, 8);
  const recoveryUuid = `d1000000-0000-4000-8000-0000${recoveryId}`;
  const exportSha = sha256Hex(walletId);
  // wallets.public_key is UNIQUE — derive one per wallet.
  const pk = `${sha256Hex(`pk:${walletId}`).slice(0, 43)}=`;
  psqlMust(
    db,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
      `VALUES ('${walletId}', '${NODE_ID}', '${pk}', 'node_generated', 'AVAILABLE') ` +
      `ON CONFLICT (id) DO NOTHING; ` +
      `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `SELECT '${recoveryUuid}', '${walletId}', 'AUDITED_EXPORT', '${exportSha}', '${pk}', ` +
      `'${recoveryUuid}', now(), 'no-second-external-no2nd' ` +
      `WHERE NOT EXISTS (SELECT 1 FROM wallet_recovery_verifications v WHERE v.wallet_id = '${walletId}'); ` +
      `UPDATE wallets SET recovery_verified_at = now(), ` +
      `recovery_verification_id = COALESCE(recovery_verification_id, '${recoveryUuid}') ` +
      `WHERE id = '${walletId}' AND recovery_verified_at IS NULL;`,
  );
};

/** transaction-material.sql FKs operations(id)/operation_approvals(id); the send slice
 *  uses send_operations, so stub the two FK parents and apply the frozen material DDL. */
const applyMaterialStubs = (db: string): void => {
  psqlMust(
    db,
    `CREATE TABLE IF NOT EXISTS operations (id uuid PRIMARY KEY);
     CREATE TABLE IF NOT EXISTS operation_approvals (id uuid PRIMARY KEY, operation_id uuid NOT NULL);`,
  );
  const material = readFileSync(join(SCHEMA_DIR, "transaction-material.sql"), "utf8");
  const stripped = material
    .replace(/CREATE DOMAIN sha256_hex AS text[\s\S]*?;/g, "")
    .replace(/CREATE DOMAIN padded_base64url_signature AS text[\s\S]*?;/g, "");
  psqlMust(db, stripped);
};

let artifactSeq = 0;

const walletFor = (n: number): string =>
  `d0000000-0000-4000-8000-${String(200 + n).padStart(12, "0")}`;
const approvalFor = (n: number): string =>
  `d0000000-0000-4000-8000-${String(300 + n).padStart(12, "0")}`;

interface SeededSend {
  readonly operationId: string;
  readonly walletId: string;
  readonly approvalId: string;
  readonly idemKey: string;
}

/** One delivered, past-T2 SEND_EXTERNAL with intent + partial + held lease. */
const seedDeliveredSend = (
  db: string,
  opId: string,
  seq: number,
  opts: { readonly status?: string; readonly attention?: boolean } = {},
): SeededSend => {
  artifactSeq += 1;
  const artifactId = `d2000000-0000-4000-8000-${String(artifactSeq).padStart(12, "0")}`;
  const walletId = walletFor(seq);
  const approvalId = approvalFor(seq);
  const idemKey = `idem-no-second-external-${String(seq).padStart(4, "0")}-xxxxxxxx`;
  const status = opts.status ?? "AWAITING_REDEMPTION";
  const attention = opts.attention ?? false;
  const attentionReason = attention ? `'${SEND_EXPIRY_ATTENTION_REASON}'` : "NULL";

  seedWallet(db, walletId);

  psqlMust(
    db,
    `INSERT INTO send_operations (
       operation_id, implementer_id, node_id, kind, status, row_version,
       attention_required, attention_reason, attention_episode, formation_state,
       http_method, route, idempotency_key, request_sha256,
       source_wallet_id, destination_address, amount_zkz
     ) VALUES (
       '${opId}', '${IMPL_ID}', '${NODE_ID}', 'SEND_EXTERNAL', '${status}', 1,
       ${attention}, ${attentionReason}, ${attention ? 1 : 0}, 'PARTIAL_DELIVERED',
       'POST', '/v1/external-sends', '${idemKey}', '${"a".repeat(64)}',
       '${walletId}', '${DEST}', '1.5'
     );
     INSERT INTO send_operation_expected_artifacts (
       artifact_id, operation_id, purpose, canonical_version, signing_key_id,
       preimage_text, preimage_sha256, signature
     ) VALUES (
       '${artifactId}', '${opId}', 'zp-send-external-expected-v1', 1, '${KEY_ID}',
       'preimage', '${"a".repeat(64)}', '${SIG}'
     );
     INSERT INTO wallet_active_leases (
       wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
       lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
     ) VALUES (
       '${walletId}', gen_random_uuid(), '${LEASE_GROUP_ID}', '${opId}', '${opId}',
       'SEND_SOURCE', ${LEASE_EPOCH}, now(), now(), gen_random_uuid()
     ) ON CONFLICT (wallet_id) DO NOTHING;
     INSERT INTO operations (id) VALUES ('${opId}') ON CONFLICT DO NOTHING;
     INSERT INTO operation_approvals (id, operation_id)
       VALUES ('${approvalId}', '${opId}') ON CONFLICT DO NOTHING;
     INSERT INTO external_send_sign_intents (
       operation_id, approval_id, source_wallet_id,
       source_t0_observation_id, destination_t0_observation_id,
       lease_group_id, lease_epoch, inner_preimage_text, inner_sha256,
       redemption_expiry_at, prepared_at
     ) VALUES (
       '${opId}', '${approvalId}', '${walletId}', '${OBS_SRC}', '${OBS_DST}',
       '${LEASE_GROUP_ID}', ${LEASE_EPOCH}, '${sqlStr(INNER_PREIMAGE)}', '${INNER_SHA}',
       '${T2_ISO}', now()
     );
     INSERT INTO external_send_partials (
       operation_id, approval_id, inner_sha256, step_1_signature,
       transfer_code_text, transfer_code_sha256, persisted_at,
       first_delivered_at, last_redelivered_at, redelivery_count
     ) VALUES (
       '${opId}', '${approvalId}', '${INNER_SHA}', '${SIG}',
       '${sqlStr(TRANSFER_CODE)}', '${TRANSFER_SHA}', now(),
       '2026-07-01T00:00:00.000Z', NULL, 0
     );`,
  );

  return { operationId: opId, walletId, approvalId, idemKey };
};

/* ─── the invariant, read straight off the database ──────────────────────────── */

interface PartialCensus {
  readonly partialRows: number;
  readonly intentRows: number;
  readonly distinctInnerSha: number;
  readonly distinctStep1Sig: number;
  readonly bytes: string | null;
  readonly leaseEpoch: number | null;
  readonly status: string;
}

const censusOf = (db: string, seeded: SeededSend): PartialCensus => {
  const raw = psqlMust(
    db,
    `SELECT
       (SELECT count(*) FROM external_send_partials WHERE operation_id='${seeded.operationId}')
       ||'~'|| (SELECT count(*) FROM external_send_sign_intents WHERE operation_id='${seeded.operationId}')
       ||'~'|| (SELECT count(DISTINCT x) FROM (
                  SELECT inner_sha256 AS x FROM external_send_partials WHERE operation_id='${seeded.operationId}'
                  UNION SELECT inner_sha256 FROM external_send_sign_intents WHERE operation_id='${seeded.operationId}'
                ) s)
       ||'~'|| (SELECT count(DISTINCT step_1_signature) FROM external_send_partials WHERE operation_id='${seeded.operationId}')
       ||'~'|| coalesce((SELECT inner_sha256||'|'||step_1_signature||'|'||transfer_code_sha256||'|'||transfer_code_text
                         FROM external_send_partials WHERE operation_id='${seeded.operationId}'), '<none>')
       ||'~'|| coalesce((SELECT lease_epoch::text FROM wallet_active_leases WHERE wallet_id='${seeded.walletId}'), '<none>')
       ||'~'|| (SELECT status FROM send_operations WHERE operation_id='${seeded.operationId}');`,
  ).trim();
  const f = raw.split("~");
  return {
    partialRows: Number(f[0]),
    intentRows: Number(f[1]),
    distinctInnerSha: Number(f[2]),
    distinctStep1Sig: Number(f[3]),
    bytes: f[4] === "<none>" ? null : f[4],
    leaseEpoch: f[5] === "<none>" ? null : Number(f[5]),
    status: f[6] ?? "",
  };
};

/** Every property that must not be lost, asserted as one closed statement. */
const expectInvariantHolds = (census: PartialCensus, where: string): void => {
  expect(census.partialRows, `${where}: exactly one external_send_partials row`).toBe(1);
  expect(census.intentRows, `${where}: exactly one external_send_sign_intents row`).toBe(1);
  expect(
    census.distinctInnerSha,
    `${where}: one operation may carry exactly one inner preimage`,
  ).toBe(1);
  expect(census.distinctStep1Sig, `${where}: one operation, one step_1_signature`).toBe(1);
  expect(census.bytes, `${where}: persisted partial bytes are unchanged`).toBe(EXPECTED_BYTES);
  expect(census.leaseEpoch, `${where}: source lease held at the same epoch`).toBe(LEASE_EPOCH);
  // The lease is only held while the operation is unsettled; terminal would release it.
  expect(
    ["AWAITING_REDEMPTION", "NEEDS_ATTENTION"],
    `${where}: never terminal while the partial is unredeemed`,
  ).toContain(census.status);
};

/* ─── facts, built from the real golden bodies ───────────────────────── */

const GEN_DIR = new URL(
  "../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);
const fixtureText = (name: string): string =>
  readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");

const parsedBody = (settledText: string): ParsedSettledTransaction => {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  const envelope = parseGatewayEnvelope(bytes);
  if (envelope.classification !== "HEAD") throw new Error("expected HEAD envelope");
  return envelope.parsed;
};

/**
 * Facts for the attempted-terminal-close racer. Built from the real golden settled bodies,
 * not from a shaped literal.
 *
 * Honest scope note: on the WAITING / INDETERMINATE branches — the only branches this file
 * drives — classifyLateLandingCycle reads status, sourceLeaseActive, sendAttemptId,
 * sourceWalletId, transferCodeSha256 and (for INDETERMINATE) expectedBodyText. expectedBody,
 * t0Body, landingEvidenceBase and candidateFromExpected are structurally required by the
 * type but are NOT consulted on those branches. They are real values so that a future
 * change which does start reading them meets a real body rather than a shim.
 */
function buildLateLandingFacts(seeded: SeededSend): LateLandingOperationFacts {
  const manifest = JSON.parse(fixtureText("manifest.json")) as {
    public_keys: Record<string, string>;
  };
  const sourcePubkey = manifest.public_keys.seed_02 as string;
  const destAddress = manifest.public_keys.seed_03 as string;
  const targetText = fixtureText("target.settled.json");
  const target = parsedBody(targetText);
  const predecessor = parsedBody(fixtureText("predecessor.settled.json"));

  const verified = verifySettledTransaction(target, sourcePubkey);
  if (verified.verdict !== "VERIFIED") {
    throw new Error(`golden target must verify under seed_02: ${verified.verdict}`);
  }
  const preimage = verified.innerPreimageText;

  const evidence: SendLandingEvidence = {
    operationId: seeded.operationId,
    entryStatus: "NEEDS_ATTENTION",
    economic: {
      operationId: seeded.operationId,
      sourceWalletId: seeded.walletId,
      sourcePubkey,
      destinationAddress: destAddress,
      amountZkz: "2.25",
      referencesOperationId: null,
    },
    expectedArtifactVerified: true,
    expectedArtifact: {
      sourcePubkey,
      destinationAddress: destAddress,
      amountZkz: "2.25",
      referencesOperationId: null,
    },
    approval: {
      approvalId: seeded.approvalId,
      totpConsumed: true,
      deviceSignatureRequired: false,
      deviceSignatureVerified: false,
      sourcePubkey,
      destinationAddress: destAddress,
      amountZkz: "2.25",
      referencesOperationId: null,
    },
    signIntent: {
      approvalId: seeded.approvalId,
      sourceT0ObservationId: OBS_SRC,
      destinationT0ObservationId: OBS_DST,
      innerPreimageText: preimage,
      innerSha256: sha256Hex(preimage),
    },
    signIntentRowCount: 1,
    partial: {
      innerSha256: sha256Hex(preimage),
      step1Signature: verified.transaction.step_1_signature,
      transferCodeSha256: TRANSFER_SHA,
      deliveredTransferCodeSha256: TRANSFER_SHA,
      otherDeliveredPartialSha256: [],
    },
    sourceT0: {
      observationId: OBS_SRC,
      projection: {
        role: "sender",
        S: predecessor.step_2_signature,
        P: "",
        B: "10",
        I: "d0",
      },
    },
    destinationT0: {
      observationId: OBS_DST,
      projection: { role: "receiver", S: "", P: "", B: "0", I: "d1" },
    },
    candidate: {
      completedTransaction: verified.transaction,
      completedTransactionText: targetText,
      completedTransactionSha256: sha256Hex(targetText),
      step1PreimageText: preimage,
      step1Signature: verified.transaction.step_1_signature,
      step2Signature: verified.transaction.step_2_signature,
      step2SignatureVerified: true,
    },
    sourcePathProof: null,
    sourcePathProofIncomplete: false,
    sourceLeaseActive: true,
  };

  const { candidate, sourcePathProof, sourcePathProofIncomplete, entryStatus, ...rest } =
    evidence;
  void sourcePathProof;
  void sourcePathProofIncomplete;
  void entryStatus;

  return {
    operationId: seeded.operationId,
    sendAttemptId: seeded.operationId,
    sourceWalletId: seeded.walletId,
    sourcePubkey,
    destinationAddress: destAddress,
    amountZkz: "2.25",
    transferCodeSha256: TRANSFER_SHA,
    status: "NEEDS_ATTENTION",
    sourceLeaseActive: true,
    expectedBody: target,
    expectedBodyText: targetText,
    t0Body: predecessor,
    landingEvidenceBase: rest,
    candidateFromExpected: candidate!,
    verifierObserverId: OBSERVER_ID,
  };
}

/* ─── value-reachability walker ───────────────────────────────────────────── */

/**
 * Transitive VALUE-import closure of a module.
 *
 * "Structurally incapable of reaching the signer" is a statement about which
 * runnable bindings a module can obtain, so type-only imports are excluded: `import type`
 * is erased and can never call anything. Returns both the visited module set and the set of
 * value binding names pulled across all hops, so a caller can assert the walk was not
 * vacuous before asserting what it did not find.
 */
function valueImportClosure(entry: string): {
  readonly modules: ReadonlySet<string>;
  readonly bindings: ReadonlySet<string>;
} {
  const modules = new Set<string>();
  const bindings = new Set<string>();
  const queue = [resolve(entry)];

  while (queue.length > 0) {
    const file = queue.pop()!;
    if (modules.has(file)) continue;
    modules.add(file);

    let source: string;
    try {
      source = readFileSync(file, "utf8");
    } catch {
      continue; // package-external specifier that resolved to nothing local
    }

    // `import <clause> from "<spec>";` — clause may span lines.
    const withClause = /^import\s+(?!type\s)([\s\S]*?)\s+from\s+"([^"]+)";/gm;
    for (const m of source.matchAll(withClause)) {
      const clause = m[1];
      const spec = m[2];
      const braced = /\{([\s\S]*)\}/.exec(clause);
      if (braced !== null) {
        for (const piece of braced[1].split(",")) {
          const name = piece.trim();
          if (name === "" || name.startsWith("type ")) continue; // inline type specifier
          bindings.add(name.split(/\s+as\s+/)[0].trim());
        }
      } else if (clause.trim() !== "") {
        // default or namespace import — the whole module surface becomes callable
        bindings.add(clause.trim().replace(/^\*\s+as\s+/, ""));
      }
      const next = resolveLocal(file, spec);
      if (next !== null) queue.push(next);
    }

    // Bare side-effect imports contribute no binding but still are an edge.
    for (const m of source.matchAll(/^import\s+"([^"]+)";/gm)) {
      const next = resolveLocal(file, m[1]);
      if (next !== null) queue.push(next);
    }
  }

  return { modules, bindings };
}

/** Resolve a relative NodeNext specifier ("./x.js") back to its TypeScript source. */
function resolveLocal(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  return resolve(dirname(fromFile), spec.replace(/\.js$/, ".ts"));
}

/**
 * The SEND signing / material-insert entry points. Reaching any of these from the
 * post-expiry or late-landing modules is precisely what "ambiguity authorizes action"
 * would look like in code.
 */
const SIGNING_ENTRY_POINTS = [
  "formAndSignSendExternal",
  "signDurableSendIntent",
  "completeSigningFromDurableIntent",
  "persistSendSignIntentSql",
  "persistSendPartialSql",
] as const;

/* ─── suite ──────────────────────────────────────────────────────────────────── */

let db: string | null = null;
let reachable = false;
let drillsRun = 0;
let suiteReady = false;

const guardDatabaseUrl =
  process.env.TEST_DATABASE_URL ??
  (probePostgres() ? "psql://local-maintenance/postgres" : undefined);

describe("no second external partial under real interleavings", () => {
  beforeAll(() => {
    reachable = probePostgres();
    if (!reachable) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED=1 but Postgres is unreachable");
      }
      return;
    }
    db = `${DB_PREFIX}${Date.now()}_${process.pid}`;
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE "${db}"`);
    applyDdlFile(db, join(SCHEMA_DIR, "base-enums-domains.sql"));
    const registry = readFileSync(join(SCHEMA_DIR, "node-implementer-registry.sql"), "utf8");
    const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry)?.[0];
    if (nodes === undefined) {
      throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
    }
    psqlMust(db, nodes);
    applyDdlFile(db, join(SCHEMA_DIR, "custody-eligibility.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-create.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-landing.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-expiry.sql"));
    psqlMust(db, verificationModeFixtureSql());
    applyMaterialStubs(db);
    seedNode(db);
    suiteReady = true;
  }, PSQL_TIMEOUT_MS + 90_000);

  afterAll(() => {
    // Scoped to exactly this run's database — the instance is shared with other lanes and
    // must never be swept broadly. Non-throwing: a slow DROP is contention, not a failure.
    if (db !== null && reachable) {
      const drop = runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
      if (!drop.ok) {
        console.warn(`scratch database ${db} not dropped (contention)`);
      }
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `no-second-partial drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
      );
    }
  }, PSQL_TIMEOUT_MS + 30_000);

  const skip = (): boolean => {
    if (!reachable || db === null) {
      if (process.env.PG_REQUIRED === "1") {
        throw new Error("PG_REQUIRED=1 but suite did not initialise");
      }
      return true;
    }
    return false;
  };

  it(
    "1. six racers, every launch order: one partial survives, bytes never diverge",
    async () => {
      if (skip()) return;
      drillsRun += 1;
      const seeded = seedDeliveredSend(db!, OP_RACE, 1);
      const query = makeAsyncQuery(db!);
      const facts = buildLateLandingFacts(seeded);
      // NO_SUCCESSOR is the clean unchanged-head read → WAITING, the ambiguous state in
      // which a terminal close must never be authorised.
      const waiting: PathObservation = { result: "NO_SUCCESSOR" };

      // A racer that would break the invariant if the DB let it: a second partial with
      // DIFFERENT bytes under a DIFFERENT approval, so external_send_partials_pkey on
      // operation_id is the only possible rejector.
      const forcedSecondPartial = (round: number): string =>
        `INSERT INTO operation_approvals (id, operation_id) VALUES ` +
        `('${approvalFor(900 + round)}', '${seeded.operationId}') ON CONFLICT DO NOTHING; ` +
        `INSERT INTO external_send_partials (operation_id, approval_id, inner_sha256, ` +
        `step_1_signature, transfer_code_text, transfer_code_sha256, persisted_at) VALUES (` +
        `'${seeded.operationId}', '${approvalFor(900 + round)}', '${sha256Hex(`rogue-${round}`)}', ` +
        `'${String(round).padStart(86, "R")}==', 'rogue-code-${round}', ` +
        `'${sha256Hex(`rogue-code-${round}`)}', now());`;

      // Idempotent replay of POST /v1/external-sends on the SAME key. A DIFFERENT source
      // wallet is used deliberately: the one-in-flight-per-wallet wallet index must not be able to
      // reject this row, so send_operations_idempotency_scope is the only rejector and the
      // asserted SQLSTATE names the constraint under test.
      const replayWallet = walletFor(50);
      seedWallet(db!, replayWallet);
      const idempotentReplay = (round: number): string =>
        `INSERT INTO send_operations (
           operation_id, implementer_id, node_id, kind, status, row_version,
           attention_required, attention_reason, attention_episode, formation_state,
           http_method, route, idempotency_key, request_sha256,
           source_wallet_id, destination_address, amount_zkz
         ) VALUES (
           '${`d3000000-0000-4000-8000-${String(round).padStart(12, "0")}`}',
           '${IMPL_ID}', '${NODE_ID}', 'SEND_EXTERNAL', 'CREATED', 1,
           false, NULL, 0, 'APPROVAL_PENDING',
           'POST', '/v1/external-sends', '${seeded.idemKey}', '${"b".repeat(64)}',
           '${replayWallet}', '${DEST}', '1.5'
         );`;

      const ROUNDS = 8;
      for (let round = 0; round < ROUNDS; round += 1) {
        const landingStore = new InMemoryExternalSendLandingStore();
        const proofStore = new InMemorySendLateLandingProofStore();

        // The six racers. Labelled thunks: the launch ORDER is permuted but
        // each result is matched back by LABEL, never by probing the value's shape —
        // redeliverExactPartial and applyLateLandingCycle both return a `kind`, so a
        // shape probe silently reads the wrong racer's outcome.
        const racers: readonly { readonly label: string; readonly run: () => Promise<unknown> }[] =
          [
            {
              label: "REDELIVER_EXACT_PARTIAL",
              run: () =>
                redeliverExactPartial(query, {
                  operationId: seeded.operationId,
                  deliveredAt: new Date(1_784_400_000_000 + round).toISOString(),
                  sourceWalletId: seeded.walletId,
                }),
            },
            {
              label: "BOOT_RECOVERY_PARK", // park pass
              run: () =>
                parkPastExpiryAwaitingRedemption(query, {
                  operationId: seeded.operationId,
                  nowUnixSecs: Number(T2_SECS) + 1 + round,
                }),
            },
            {
              label: "CONTINUE_EXTERNAL_WAIT", // operator action, operations recovery
              run: () => continueExternalWait(query, { operationId: seeded.operationId }),
            },
            {
              label: "ATTEMPTED_TERMINAL_CLOSE", // ambiguous classification
              run: () =>
                applyLateLandingCycle(
                  { facts, sourceObservation: waiting },
                  { landingStore, proofStore },
                  { attemptTerminalClose: true },
                ),
            },
            {
              label: "IDEMPOTENT_REPLAY",
              run: () => runPsqlAsync(db!, idempotentReplay(round)),
            },
            {
              label: "ROGUE_SECOND_PARTIAL",
              run: () => runPsqlAsync(db!, forcedSecondPartial(round)),
            },
          ];

        // Rotate the launch order; round 0 is all-at-once in declaration order. Rotation
        // walks every racer through every position across the 8 rounds (6 positions), so
        // no racer's result depends on it being started first or last.
        const order = racers.map((_, i) => racers[(i + round) % racers.length]);
        resetQueryPeak();
        const settled = await Promise.allSettled(order.map((r) => r.run()));
        const byLabel = new Map(order.map((r, i) => [r.label, settled[i]]));

        // The service racers actually OVERLAPPED at the database. This is the assertion the
        // whole drill rests on: sequential calls cannot produce
        // any of those interleavings". If the query fn is ever switched back to a synchronous
        // one the event loop serialises every statement, the peak collapses to 1, and this
        // reddens BEFORE any invariant assertion can pass for the wrong reason.
        expect(
          queryPeakInFlight,
          `round ${round}: only ${queryPeakInFlight} service statement(s) were ever in ` +
            "flight at once — execution was serialised, so this round tested no interleaving",
        ).toBeGreaterThan(1);

        const resultOf = <T>(label: string): T => {
          const r = byLabel.get(label);
          expect(r, `round ${round}: racer ${label} did not run`).toBeDefined();
          expect(
            r!.status,
            `round ${round}: racer ${label} rejected — ` +
              (r!.status === "rejected" ? String(r!.reason) : ""),
          ).toBe("fulfilled");
          return (r as PromiseFulfilledResult<T>).value;
        };

        // The two raw-SQL racers must be rejected by the constraints they are aimed at.
        const replay = resultOf<PsqlOutcome>("IDEMPOTENT_REPLAY");
        expect(replay.ok, `round ${round}: idempotent replay must be refused`).toBe(false);
        expect(extractSqlstate(replay.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
        expect(extractConstraint(replay.stderr)).toBe("send_operations_idempotency_scope");

        const rogue = resultOf<PsqlOutcome>("ROGUE_SECOND_PARTIAL");
        expect(rogue.ok, `round ${round}: rogue second partial must be refused`).toBe(false);
        expect(extractSqlstate(rogue.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
        expect(extractConstraint(rogue.stderr)).toBe("external_send_partials_pkey");

        // The close attempt is refused on BOTH surfaces it could have used.
        const close = resultOf<{ readonly kind: string }>("ATTEMPTED_TERMINAL_CLOSE");
        expect(close.kind, `round ${round}: terminal close must be refused`).toBe(
          "REFUSED_CLOSE",
        );
        expect(landingStore.records ?? []).toHaveLength(0);
        expect(proofStore.byOperation.size).toBe(0);

        // The three service racers must all complete without throwing; a throw
        // from them is the module's own bytes-mutated / lease-changed assertion firing.
        resultOf<{ readonly kind: string }>("REDELIVER_EXACT_PARTIAL");
        resultOf<{ readonly kind: string }>("BOOT_RECOVERY_PARK");
        resultOf<{ readonly kind: string }>("CONTINUE_EXTERNAL_WAIT");

        expectInvariantHolds(censusOf(db!, seeded), `round ${round}`);
      }

      // Across the whole run: still exactly one row, still the seeded bytes.
      const finalCensus = censusOf(db!, seeded);
      expectInvariantHolds(finalCensus, "after all rounds");
      expect(
        psqlMust(
          db!,
          `SELECT count(*) FROM send_operations WHERE idempotency_key='${seeded.idemKey}';`,
        ).trim(),
        "the idempotency key admitted exactly one operation across every replay",
      ).toBe("1");
    },
    PSQL_TIMEOUT_MS + 120_000,
  );

  it("2. every ambiguous classification refuses close and writes nothing", async () => {
    if (skip()) return;
    drillsRun += 1;
    const seeded = seedDeliveredSend(db!, OP_AMBIGUITY, 2, {
      status: "NEEDS_ATTENTION",
      attention: true,
    });
    const facts = buildLateLandingFacts(seeded);

    // Every non-positive observation the reconciler can be handed. Each must refuse.
    const ambiguous: readonly { readonly label: string; readonly obs: PathObservation }[] = [
      { label: "NO_SUCCESSOR → WAITING", obs: { result: "NO_SUCCESSOR" } },
      {
        label: "PROOF_INCOMPLETE → INDETERMINATE",
        obs: { result: "PROOF_INCOMPLETE", fault: "MISSING_BODY" },
      },
      {
        label: "ANOMALY → INDETERMINATE",
        obs: { result: "ANOMALY", anomaly: "CONTRADICTORY_HEAD" },
      },
      {
        label: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE",
        obs: { result: "UNATTRIBUTED_SUCCESSOR_UNDER_LEASE" },
      },
    ];

    const before = censusOf(db!, seeded);
    for (const { label, obs } of ambiguous) {
      const landingStore = new InMemoryExternalSendLandingStore();
      const proofStore = new InMemorySendLateLandingProofStore();
      const outcome = await applyLateLandingCycle(
        { facts, sourceObservation: obs },
        { landingStore, proofStore },
        { attemptTerminalClose: true },
      );
      expect(outcome.kind, `${label}: terminal close must be refused`).toBe("REFUSED_CLOSE");
      if (outcome.kind !== "REFUSED_CLOSE") continue;
      expect(outcome.sourceLeaseStillHeld, `${label}: lease held`).toBe(true);
      expect(
        outcome.classification.kind,
        `${label}: refusal came from an ambiguous classification, not a land`,
      ).not.toBe("LANDED_VERIFIED");
      // Nothing landed anywhere — including in the in-memory ports a close would use.
      expect(landingStore.records ?? [], `${label}: no landing record`).toHaveLength(0);
      expect(proofStore.byOperation.size, `${label}: no landing proof`).toBe(0);
    }

    // And the same cycles WITHOUT the close flag must still not add a row.
    for (const { label, obs } of ambiguous) {
      const outcome = await applyLateLandingCycle(
        { facts, sourceObservation: obs },
        {
          landingStore: new InMemoryExternalSendLandingStore(),
          proofStore: new InMemorySendLateLandingProofStore(),
        },
      );
      expect(outcome.kind, `${label}: stays parked`).toBe("REMAIN_ATTENTION");
      if (outcome.kind === "REMAIN_ATTENTION") {
        expect(outcome.sourceLeaseStillHeld).toBe(true);
      }
    }

    const after = censusOf(db!, seeded);
    expect(after, "ambiguity changed nothing durable").toStrictEqual(before);
    expectInvariantHolds(after, "after ambiguity sweep");
  });

  it("3. the post-expiry and late-landing modules cannot reach a SEND signing entry point", () => {
    if (skip()) return;
    drillsRun += 1;

    for (const entry of [
      join(SRC_DIR, "send/expiry-attention.ts"),
      join(SRC_DIR, "send/late-landing-reconcile.ts"),
    ]) {
      const { modules, bindings } = valueImportClosure(entry);

      // Anti-vacuity: an empty or shallow walk would pass the real assertion for free.
      expect(modules.size, `${entry}: walker must traverse a real closure`).toBeGreaterThan(5);
      expect(bindings.size, `${entry}: walker must collect real value bindings`).toBeGreaterThan(
        5,
      );

      for (const signer of SIGNING_ENTRY_POINTS) {
        expect(
          bindings.has(signer),
          `${entry} reaches signing entry point ${signer} — an ambiguous classification ` +
            "could authorize a second signature (the P0 failure)",
        ).toBe(false);
      }
    }

    // The walk is sharp, not blind: expiry-attention DOES reach the signer MODULE (through
    // send-crash-recovery) and still pulls no signing binding from it. Without this the
    // assertion above could hold merely because the walker never got there.
    const expiry = valueImportClosure(join(SRC_DIR, "send/expiry-attention.ts"));
    expect(
      [...expiry.modules].some((m) => m.endsWith("core/send-form-and-sign.ts")),
      "expiry-attention's closure must actually include the signer module",
    ).toBe(true);
    expect(
      expiry.bindings.has("recordInMemoryPartialDelivery"),
      "the only value it takes from the signer module is the delivery-counter recorder",
    ).toBe(true);
  });

  it("4. exact redelivery under concurrency: identical bytes, counters only", async () => {
    if (skip()) return;
    drillsRun += 1;
    const seeded = seedDeliveredSend(db!, OP_REDELIVER, 3);
    const query = makeAsyncQuery(db!);

    const N = 6;
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) =>
        redeliverExactPartial(query, {
          operationId: seeded.operationId,
          deliveredAt: new Date(1_784_500_000_000 + i).toISOString(),
          sourceWalletId: seeded.walletId,
        }),
      ),
    );

    for (const [i, r] of results.entries()) {
      expect(r.kind, `redelivery ${i} must return the exact stored partial`).toBe(
        "REDELIVERED",
      );
      if (r.kind !== "REDELIVERED") continue;
      expect(r.transferCodeText, `redelivery ${i} returned different bytes`).toBe(
        TRANSFER_CODE,
      );
      expect(r.transferCodeSha256).toBe(TRANSFER_SHA);
      expect(r.partialBytesBefore).toBe(EXPECTED_BYTES);
      expect(r.partialBytesAfter).toBe(EXPECTED_BYTES);
      expect(r.leaseEpochBefore).toBe(LEASE_EPOCH);
      expect(r.leaseEpochAfter).toBe(LEASE_EPOCH);
    }

    // Counters are the only thing that moved, and they moved once per redelivery.
    expect(
      psqlMust(
        db!,
        `SELECT redelivery_count::text FROM external_send_partials ` +
          `WHERE operation_id='${seeded.operationId}';`,
      ).trim(),
    ).toBe(String(N));
    expectInvariantHolds(censusOf(db!, seeded), "after concurrent redelivery");
  });

  it("5. a new send on the same source wallet is refused; the original is untouched", () => {
    if (skip()) return;
    drillsRun += 1;
    const seeded = seedDeliveredSend(db!, OP_NEW_CREATE, 4, {
      status: "NEEDS_ATTENTION",
      attention: true,
    });
    const before = censusOf(db!, seeded);

    // Same source wallet, its OWN fresh idempotency key — so the idempotency constraint
    // cannot fire and the one-in-flight-per-wallet partial index is the only possible rejector.
    const collide = runPsql(
      db!,
      `INSERT INTO send_operations (
         operation_id, implementer_id, node_id, kind, status, row_version,
         attention_required, attention_reason, attention_episode, formation_state,
         http_method, route, idempotency_key, request_sha256,
         source_wallet_id, destination_address, amount_zkz
       ) VALUES (
         '${OP_NEW_CREATE_OK}', '${IMPL_ID}', '${NODE_ID}', 'SEND_EXTERNAL', 'CREATED', 1,
         false, NULL, 0, 'APPROVAL_PENDING',
         'POST', '/v1/external-sends', 'idem-no-second-external-newcreate-1', '${"c".repeat(64)}',
         '${seeded.walletId}', '${DEST}', '0.25'
       );`,
    );
    expect(collide.ok, "a second unsettled send from a leased wallet must be rejected").toBe(
      false,
    );
    expect(extractSqlstate(collide.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(collide.stderr)).toBe(
      "send_operations_one_unsettled_per_source_wallet",
    );

    // "new operation, new approval": a genuinely independent send proceeds, and still
    // does not disturb the original's partial, bytes, or lease.
    const independent = seedDeliveredSend(db!, OP_NEW_CREATE_OK, 5);
    expect(independent.approvalId).not.toBe(seeded.approvalId);
    expectInvariantHolds(censusOf(db!, independent), "independent operation");
    expect(censusOf(db!, seeded), "original operation untouched by the new create").toStrictEqual(
      before,
    );

    // Nowhere in the database does one approval carry two partials or two sign intents.
    expect(
      psqlMust(
        db!,
        `SELECT coalesce(max(n),0)::text FROM (
           SELECT count(*) AS n FROM external_send_partials GROUP BY approval_id
         ) s;`,
      ).trim(),
    ).toBe("1");
    expect(
      psqlMust(
        db!,
        `SELECT coalesce(max(n),0)::text FROM (
           SELECT count(*) AS n FROM external_send_sign_intents GROUP BY approval_id
         ) s;`,
      ).trim(),
    ).toBe("1");
  });

  it("6. no operation anywhere carries two distinct inner preimages or signatures", () => {
    if (skip()) return;
    drillsRun += 1;

    // This property, read across every row this suite produced rather than
    // against the one operation a drill happened to be looking at.
    const divergent = psqlMust(
      db!,
      `SELECT count(*)::text FROM (
         SELECT operation_id FROM (
           SELECT operation_id, inner_sha256 FROM external_send_partials
           UNION
           SELECT operation_id, inner_sha256 FROM external_send_sign_intents
         ) u GROUP BY operation_id HAVING count(DISTINCT inner_sha256) > 1
       ) d;`,
    ).trim();
    expect(divergent, "an operation with two inner preimages is the P0").toBe("0");

    const divergentSigs = psqlMust(
      db!,
      `SELECT count(*)::text FROM (
         SELECT operation_id FROM external_send_partials
         GROUP BY operation_id HAVING count(DISTINCT step_1_signature) > 1
       ) d;`,
    ).trim();
    expect(divergentSigs).toBe("0");

    // A consumed approval cannot sign a second, different inner preimage — under a
    // BRAND-NEW operation_id, so the sign-intent PRIMARY KEY cannot fire first and
    // external_send_sign_intents_approval_id_key is the only possible rejector.
    const freshOp = "d4000000-0000-4000-8000-000000000001";
    psqlMust(db!, `INSERT INTO operations (id) VALUES ('${freshOp}') ON CONFLICT DO NOTHING;`);
    const reuse = runPsql(
      db!,
      `INSERT INTO external_send_sign_intents (
         operation_id, approval_id, source_wallet_id,
         source_t0_observation_id, destination_t0_observation_id,
         lease_group_id, lease_epoch, inner_preimage_text, inner_sha256,
         redemption_expiry_at, prepared_at
       ) VALUES (
         '${freshOp}', '${approvalFor(3)}', '${walletFor(3)}',
         '${OBS_SRC}', '${OBS_DST}', '${LEASE_GROUP_ID}', ${LEASE_EPOCH},
         'a-different-preimage', '${sha256Hex("a-different-preimage")}',
         '${T2_ISO}', now()
       );`,
    );
    expect(reuse.ok, "a consumed approval must not sign a second preimage").toBe(false);
    expect(extractSqlstate(reuse.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(reuse.stderr)).toBe(
      "external_send_sign_intents_approval_id_key",
    );
  });

  it("7. restart: durable state reloads byte-identical after every race", async () => {
    if (skip()) return;
    drillsRun += 1;
    // A boot-recovery pass reads through a brand-new connection — nothing about the
    // surviving partial may be derived from the in-process state the races built up.
    const query = makeAsyncQuery(db!);
    for (const opId of [OP_RACE, OP_AMBIGUITY, OP_REDELIVER, OP_NEW_CREATE]) {
      const facts = await loadSendExpiryOperationFacts(query, opId);
      expect(facts, `${opId} must reload`).not.toBeNull();
      if (facts === null) continue;
      expect(facts.partialExists).toBe(true);
      expect(
        fingerprintPartialImmutableBytes({
          innerSha256: facts.partialInnerSha256!,
          step1Signature: facts.step1Signature!,
          transferCodeText: facts.transferCodeText!,
          transferCodeSha256: facts.transferCodeSha256!,
        }),
        `${opId}: bytes drifted across restart`,
      ).toBe(EXPECTED_BYTES);
      expect(facts.leaseHeld, `${opId}: lease still held after restart`).toBe(true);
      expect(facts.leaseEpoch).toBe(LEASE_EPOCH);
      expect(["AWAITING_REDEMPTION", "NEEDS_ATTENTION"]).toContain(facts.status);
    }
  });
});

// Fail-closed: PG unreachable or setup incomplete under PG_REQUIRED=1 is a broken harness,
// never "no Postgres here" — a throwing beforeAll reports as skipped, not failed.
registerPgRequiredGuard({
  name: "no-second-external-partial race drills",
  databaseUrl: guardDatabaseUrl,
  isReady: () => suiteReady,
});
