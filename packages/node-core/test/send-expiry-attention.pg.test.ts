/**
 * send-expiry-attention.pg.test.ts
 *
 * Real PostgreSQL drills for SEND_EXTERNAL post-delivery expiry:
 *   1. AWAITING_REDEMPTION past T2 → NEEDS_ATTENTION; lease held; partial bytes identical
 *   2. No AWAITING_REDEMPTION → EXPIRED / REJECTED path
 *   3. CONTINUE_EXTERNAL_WAIT returns AWAITING_REDEMPTION; lease + bytes held
 *   4. REDELIVER_EXACT_PARTIAL returns identical transfer_code_text; counters only
 *   5. Restart mid-episode: durable NEEDS_ATTENTION survives re-load (no re-derive)
 *   6. Pre-delivery past-T2 does NOT release lease from this module
 *   7. Negative: module SQL set contains no second partial / sign-intent / lease DELETE
 *
 * Harness mirrors test/send-external-landing-pg.test.ts + transaction-material-store.pg.
 */
import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import {
  SEND_EXPIRY_ATTENTION_REASON,
  SEND_EXPIRY_ATTENTION_SQL,
  SEND_PARTIAL_AGING_MARGIN_SECS,
  assertNoForbiddenSqlInAllowedSet,
  continueExternalWait,
  evaluatePostDeliveryExpiry,
  fingerprintPartialImmutableBytes,
  loadSendExpiryOperationFacts,
  parkPastExpiryAwaitingRedemption,
  redeliverExactPartial,
} from "../src/send/expiry-attention.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "send_expiry_attention_send_expiry_";
const EXPECTED_DRILL_COUNT = 8;

const NODE_ID = "b0000000-0000-4000-8000-000000000001";
const IMPL_ID = "b0000000-0000-4000-8000-000000000002";
const WALLET_ID = "b0000000-0000-4000-8000-000000000003";
const KEY_ID = "b0000000-0000-4000-8000-000000000004";
const APPROVAL_ID = "b0000000-0000-4000-8000-000000000005";
const LEASE_GROUP_ID = "b0000000-0000-4000-8000-000000000006";
const OBS_SRC = "b0000000-0000-4000-8000-000000000007";
const OBS_DST = "b0000000-0000-4000-8000-000000000008";

const DEST = `${"D".repeat(43)}=`;
const PUBKEY = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;

const T2_SECS = "1784333100";
const T2_ISO = new Date(Number(T2_SECS) * 1000).toISOString();
const INNER_PREIMAGE = JSON.stringify({
  expiry__unix_time_secs: T2_SECS,
  amount__str: "1.5",
  destination: DEST,
});
const INNER_SHA = createHash("sha256").update(INNER_PREIMAGE, "utf8").digest("hex");
const TRANSFER_CODE = `zp-send-v1:${INNER_SHA}:exact-bytes-must-not-change`;
const TRANSFER_SHA = createHash("sha256").update(TRANSFER_CODE, "utf8").digest("hex");

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

/** Escape a string for single-quoted SQL literal. */
const sqlStr = (value: string): string => value.replace(/'/g, "''");

/**
 * Minimal SqlQueryFn over psql -qAt. Supports SELECT/UPDATE/INSERT … RETURNING by
 * emitting JSON rows. Good enough for the parameterized statements this module uses.
 */
function makeQuery(db: string): SqlQueryFn {
  return async (text, values) => {
    let bound = text;
    // Bind $n right-to-left so $10 is not clobbered by $1.
    for (let i = values.length; i >= 1; i -= 1) {
      const v = values[i - 1];
      let lit: string;
      if (v === null || v === undefined) lit = "NULL";
      else if (typeof v === "number" || typeof v === "bigint") lit = String(v);
      else if (typeof v === "boolean") lit = v ? "TRUE" : "FALSE";
      else lit = `'${sqlStr(String(v))}'`;
      bound = bound.replace(new RegExp(`\\$${i}(?!\\d)`, "g"), lit);
    }
    // Data-modifying WITH (park CAS co-commit) must stay top-level — nesting it inside
    // `WITH q AS (...)` raises "WITH clause containing a data-modifying statement must
    // be at the top level". Materialize via CREATE TEMP TABLE AS instead.
    const isDataModifyingCte =
      /^\s*WITH\b/i.test(bound) && /\b(UPDATE|INSERT|DELETE)\b/i.test(bound);
    const wrapped = isDataModifyingCte
      ? `BEGIN; ` +
        `CREATE TEMP TABLE _q_scratch ON COMMIT DROP AS ${bound}; ` +
        `SELECT coalesce(json_agg(row_to_json(_q_scratch)), '[]'::json)::text FROM _q_scratch; ` +
        `COMMIT;`
      : `WITH q AS (${bound}) ` +
        `SELECT coalesce(json_agg(row_to_json(q)), '[]'::json)::text FROM q`;
    const outcome = runPsql(db, wrapped);
    if (!outcome.ok) {
      throw new Error(outcome.stderr.trim() || `query failed: ${bound.slice(0, 200)}`);
    }
    const line = outcome.stdout.trim().split("\n").filter(Boolean).at(-1) ?? "[]";
    return JSON.parse(line) as Record<string, unknown>[];
  };
}

const seedNode = (db: string): void => {
  psqlMust(
    db,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
      `('${NODE_ID}', 'send-expiry-attention-expiry', '${PUBKEY}') ON CONFLICT (id) DO NOTHING;`,
  );
};

const seedWallet = (db: string, walletId: string): void => {
  // Per-wallet recovery row (recovery_verifications.wallet_id is unique in practice).
  const recoveryId = randomUUID();
  const exportSha = createHash("sha256").update(walletId, "utf8").digest("hex");
  // Distinct public_key per wallet — wallets.public_key is UNIQUE.
  const pkBody = createHash("sha256").update(`pk:${walletId}`, "utf8").digest("base64url").slice(0, 43);
  const pk = `${pkBody}=`;
  psqlMust(
    db,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
      `VALUES ('${walletId}', '${NODE_ID}', '${pk}', 'node_generated', 'AVAILABLE')
       ON CONFLICT (id) DO NOTHING; ` +
      `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `SELECT '${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${exportSha}', '${pk}', ` +
      `'${recoveryId}', now(), 'send-expiry-attention-expiry-test'
       WHERE NOT EXISTS (
         SELECT 1 FROM wallet_recovery_verifications v WHERE v.wallet_id = '${walletId}'
       ); ` +
      `UPDATE wallets SET recovery_verified_at = now(),
         recovery_verification_id = COALESCE(recovery_verification_id, '${recoveryId}')
       WHERE id = '${walletId}' AND recovery_verified_at IS NULL;`,
  );
};

/** Stub FK targets for external_send_sign_intents / partials (operations + approvals). */
const applyMaterialStubs = (db: string): void => {
  // transaction-material.sql FKs operations(id) and operation_approvals(id). The send
  // slice uses send_operations; stub minimal stand-ins so the frozen material DDL applies.
  psqlMust(
    db,
    `
CREATE TABLE IF NOT EXISTS operations (
  id uuid PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS operation_approvals (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL
);
`,
  );
  // Apply frozen material DDL with FKs retargeted? Prefer extract CREATE TABLE blocks
  // and rewrite REFERENCES operations(id) → nothing critical: we create ops rows by id.
  const material = readFileSync(join(SCHEMA_DIR, "transaction-material.sql"), "utf8");
  // Drop domain re-creates if base-enums already defined them.
  const stripped = material
    .replace(/CREATE DOMAIN sha256_hex AS text[\s\S]*?;/g, "")
    .replace(/CREATE DOMAIN padded_base64url_signature AS text[\s\S]*?;/g, "");
  psqlMust(db, stripped);
};

let artifactSeq = 0;

const seedAwaitingSend = (
  db: string,
  opId: string,
  opts: {
    readonly status?: string;
    readonly attention?: boolean;
    readonly withPartial?: boolean;
    readonly withIntent?: boolean;
    readonly delivered?: boolean;
    readonly leaseEpoch?: number;
    readonly walletId: string;
    readonly idemKey: string;
  },
): void => {
  artifactSeq += 1;
  const artifactId = `b0000000-0000-4000-8000-${String(artifactSeq).padStart(12, "0")}`;
  const status = opts.status ?? "AWAITING_REDEMPTION";
  const formation =
    status === "CREATED"
      ? "APPROVAL_PENDING"
      : status === "APPROVED"
        ? "APPROVED_UNSIGNED"
        : "PARTIAL_DELIVERED";
  const attention = opts.attention ?? false;
  const attentionReason = attention ? `'${SEND_EXPIRY_ATTENTION_REASON}'` : "NULL";
  const attentionEpisode = attention ? 1 : 0;
  const approvalId = randomUUID();
  const leaseEpoch = opts.leaseEpoch ?? 7;
  const walletId = opts.walletId;

  // One wallet per unsettled send (the one-in-flight-per-wallet rule unique index).
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
      ${attention}, ${attentionReason}, ${attentionEpisode}, '${formation}',
      'POST', '/v1/external-sends', '${sqlStr(opts.idemKey)}', '${"a".repeat(64)}',
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
      'SEND_SOURCE', ${leaseEpoch}, now(), now(), gen_random_uuid()
    ) ON CONFLICT (wallet_id) DO UPDATE SET
      lease_epoch = EXCLUDED.lease_epoch,
      operation_id = EXCLUDED.operation_id;`,
  );

  // Material FK stubs: operations + approvals rows matching the op/approval ids.
  if (opts.withIntent !== false || opts.withPartial !== false) {
    psqlMust(
      db,
      `INSERT INTO operations (id) VALUES ('${opId}') ON CONFLICT DO NOTHING;
       INSERT INTO operation_approvals (id, operation_id)
         VALUES ('${approvalId}', '${opId}') ON CONFLICT DO NOTHING;`,
    );
  }

  if (opts.withIntent !== false) {
    psqlMust(
      db,
      `INSERT INTO external_send_sign_intents (
        operation_id, approval_id, source_wallet_id,
        source_t0_observation_id, destination_t0_observation_id,
        lease_group_id, lease_epoch, inner_preimage_text, inner_sha256,
        redemption_expiry_at, prepared_at
      ) VALUES (
        '${opId}', '${approvalId}', '${walletId}',
        '${OBS_SRC}', '${OBS_DST}',
        '${LEASE_GROUP_ID}', ${leaseEpoch},
        '${sqlStr(INNER_PREIMAGE)}', '${INNER_SHA}',
        '${T2_ISO}', now()
      );`,
    );
  }

  if (opts.withPartial !== false) {
    const firstDelivered =
      opts.delivered === false ? "NULL" : `'2026-07-01T00:00:00.000Z'`;
    psqlMust(
      db,
      `INSERT INTO external_send_partials (
        operation_id, approval_id, inner_sha256, step_1_signature,
        transfer_code_text, transfer_code_sha256, persisted_at,
        first_delivered_at, last_redelivered_at, redelivery_count
      ) VALUES (
        '${opId}', '${approvalId}', '${INNER_SHA}', '${SIG}',
        '${sqlStr(TRANSFER_CODE)}', '${TRANSFER_SHA}', now(),
        ${firstDelivered}, NULL, 0
      );`,
    );
  }

  void APPROVAL_ID;
  void WALLET_ID;
};

const expectedBytes = fingerprintPartialImmutableBytes({
  innerSha256: INNER_SHA,
  step1Signature: SIG,
  transferCodeText: TRANSFER_CODE,
  transferCodeSha256: TRANSFER_SHA,
});

let db: string | null = null;
let reachable = false;
let drillsRun = 0;
let suiteReady = false;
// Prefer vitest-provisioned URL; fall back to a marker when local psql works so
// PG_REQUIRED=1 still fails closed if beforeAll never completes.
const guardDatabaseUrl =
  process.env.TEST_DATABASE_URL ??
  (probePostgres() ? "psql://local-maintenance/postgres" : undefined);

const walletFor = (n: number): string =>
  `b0000000-0000-4000-8000-${String(100 + n).padStart(12, "0")}`;

describe("SEND expiry attention PG drills", () => {
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
    applyMaterialStubs(db);
    seedNode(db);
    suiteReady = true;
  });

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `send-expiry-attention PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
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

  it("1. past-T2 AWAITING_REDEMPTION → NEEDS_ATTENTION; lease+bytes held", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000010";
    const walletId = walletFor(1);
    seedAwaitingSend(db!, opId, { idemKey: "idem-park-001-xxxxxxxx", walletId });
    const query = makeQuery(db!);

    const before = await loadSendExpiryOperationFacts(query, opId);
    expect(before?.status).toBe("AWAITING_REDEMPTION");
    expect(before?.leaseHeld).toBe(true);
    expect(before?.leaseEpoch).toBe(7);

    const result = await parkPastExpiryAwaitingRedemption(query, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 1,
    });
    expect(result.kind).toBe("PARKED");
    if (result.kind !== "PARKED") return;
    expect(result.attentionReason).toBe(SEND_EXPIRY_ATTENTION_REASON);
    expect(result.attentionEpisode).toBe(1);
    expect(result.partialBytesBefore).toBe(expectedBytes);
    expect(result.partialBytesAfter).toBe(expectedBytes);
    expect(result.leaseEpochBefore).toBe(7);
    expect(result.leaseEpochAfter).toBe(7);
    // formation_state untouched on park
    expect(result.formationState).toBe("PARTIAL_DELIVERED");

    const after = await loadSendExpiryOperationFacts(query, opId);
    expect(after?.status).toBe("NEEDS_ATTENTION");
    expect(after?.attentionRequired).toBe(true);
    expect(after?.attentionReason).toBe(SEND_EXPIRY_ATTENTION_REASON);
    expect(after?.leaseHeld).toBe(true);
    expect(after?.leaseEpoch).toBe(7);
    expect(after?.partialInnerSha256).toBe(INNER_SHA);
    expect(after?.step1Signature).toBe(SIG);
    expect(after?.transferCodeText).toBe(TRANSFER_CODE);
    expect(after?.transferCodeSha256).toBe(TRANSFER_SHA);

    const event = runPsql(
      db!,
      `SELECT event_type||'|'||attention_reason||'|'||attention_episode
       FROM external_send_attention_events WHERE operation_id='${opId}'`,
    );
    expect(event.ok).toBe(true);
    expect(event.stdout.trim()).toBe(
      `operation.needs_attention|${SEND_EXPIRY_ATTENTION_REASON}|1`,
    );
  });

  it("2. forbidden: AWAITING_REDEMPTION cannot go EXPIRED or REJECTED via this gate", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000011";
    seedAwaitingSend(db!, opId, { idemKey: "idem-forbid-002-xxxxxxx", walletId: walletFor(2) });

    // Schema CHECK on send_operations status vocabulary excludes EXPIRED entirely.
    const expired = runPsql(
      db!,
      `UPDATE send_operations SET status = '${SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_AWAITING_TO_EXPIRED_STATUS}' ` +
        `WHERE operation_id = '${opId}' AND status = 'AWAITING_REDEMPTION'`,
    );
    expect(expired.ok).toBe(false);

    // Direct REJECTED is schema-legal as a status value but the state-event reference forbids the edge
    // from AWAITING_REDEMPTION — this module must never emit that SQL in the allowed set.
    assertNoForbiddenSqlInAllowedSet();
    expect(
      evaluatePostDeliveryExpiry({
        status: "AWAITING_REDEMPTION",
        partialExists: true,
        firstDeliveredAt: "x",
        redemptionExpiryUnixSecs: T2_SECS,
        nowUnixSecs: Number(T2_SECS) + 10_000,
      }).outcome,
    ).toBe("PAST_EXPIRY_PARK_ATTENTION");

    // Status still AWAITING until park (we did not call park in this drill).
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${opId}'`).stdout.trim(),
    ).toBe("AWAITING_REDEMPTION");
  });

  it("3. CONTINUE_EXTERNAL_WAIT → AWAITING_REDEMPTION; lease+bytes held", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000012";
    seedAwaitingSend(db!, opId, { idemKey: "idem-continue-003-xxxxxx", walletId: walletFor(3) });
    const query = makeQuery(db!);

    const parked = await parkPastExpiryAwaitingRedemption(query, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 5,
    });
    expect(parked.kind).toBe("PARKED");

    const cont = await continueExternalWait(query, { operationId: opId });
    expect(cont.kind).toBe("CONTINUED");
    if (cont.kind !== "CONTINUED") return;
    expect(cont.status).toBe("AWAITING_REDEMPTION");
    expect(cont.attentionRequired).toBe(false);
    expect(cont.partialBytesBefore).toBe(expectedBytes);
    expect(cont.partialBytesAfter).toBe(expectedBytes);
    expect(cont.leaseEpochBefore).toBe(7);
    expect(cont.leaseEpochAfter).toBe(7);

    const after = await loadSendExpiryOperationFacts(query, opId);
    expect(after?.status).toBe("AWAITING_REDEMPTION");
    expect(after?.attentionRequired).toBe(false);
    expect(after?.attentionReason).toBeNull();
    // episode counter is retained (not reset) — only the open flag clears
    expect(after?.attentionEpisode).toBe(1);
    expect(after?.leaseHeld).toBe(true);
  });

  it("4. REDELIVER_EXACT_PARTIAL returns identical bytes; counters only", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000013";
    const walletId = walletFor(4);
    seedAwaitingSend(db!, opId, {
      idemKey: "idem-redeliver-004-xxxxx",
      delivered: true,
      walletId,
    });
    const query = makeQuery(db!);

    // Park then redeliver from attention (late recipient still needs the code).
    await parkPastExpiryAwaitingRedemption(query, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 1,
    });

    const red = await redeliverExactPartial(query, {
      operationId: opId,
      deliveredAt: "2026-07-20T12:00:00.000Z",
      sourceWalletId: walletId,
    });
    expect(red.kind).toBe("REDELIVERED");
    if (red.kind !== "REDELIVERED") return;
    expect(red.transferCodeText).toBe(TRANSFER_CODE);
    expect(red.transferCodeSha256).toBe(TRANSFER_SHA);
    expect(red.partialBytesBefore).toBe(expectedBytes);
    expect(red.partialBytesAfter).toBe(expectedBytes);
    expect(red.redeliveryCount).toBe(1);
    expect(red.leaseEpochBefore).toBe(7);
    expect(red.leaseEpochAfter).toBe(7);

    const row = runPsql(
      db!,
      `SELECT redelivery_count||'|'||(last_redelivered_at IS NOT NULL)||'|'||inner_sha256||'|'||transfer_code_sha256
       FROM external_send_partials WHERE operation_id='${opId}'`,
    );
    expect(row.stdout.trim()).toMatch(new RegExp(`^1\\|(t|true)\\|${INNER_SHA}\\|${TRANSFER_SHA}$`));
  });

  it("5. restart mid-episode: durable NEEDS_ATTENTION survives re-load", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000014";
    const walletId = walletFor(5);
    seedAwaitingSend(db!, opId, { idemKey: "idem-restart-005-xxxxxx", walletId });
    const query = makeQuery(db!);

    const parked = await parkPastExpiryAwaitingRedemption(query, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 1,
    });
    expect(parked.kind).toBe("PARKED");

    // Simulate process restart: new query handle, re-load facts only.
    const query2 = makeQuery(db!);
    const facts = await loadSendExpiryOperationFacts(query2, opId);
    expect(facts?.status).toBe("NEEDS_ATTENTION");
    expect(facts?.attentionRequired).toBe(true);
    expect(facts?.attentionEpisode).toBe(1);

    // Re-evaluate must not invent a terminal state from a fresh head-less clock read.
    const again = await parkPastExpiryAwaitingRedemption(query2, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + SEND_PARTIAL_AGING_MARGIN_SECS + 100,
    });
    expect(again.kind).toBe("ALREADY_ATTENTION");
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${opId}'`).stdout.trim(),
    ).toBe("NEEDS_ATTENTION");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${walletId}'`,
      ).stdout.trim(),
    ).toBe("1");
  });

  it("6. pre-delivery past-T2 does NOT release lease or terminalize", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000015";
    // APPROVED, no partial — pre-delivery boundary.
    const walletId = walletFor(6);
    seedAwaitingSend(db!, opId, {
      idemKey: "idem-pre-006-xxxxxxxxxx",
      status: "APPROVED",
      withPartial: false,
      withIntent: false,
      walletId,
    });
    const query = makeQuery(db!);

    const result = await parkPastExpiryAwaitingRedemption(query, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 9999,
    });
    expect(result.kind).toBe("NOOP");
    if (result.kind !== "NOOP") return;
    expect(result.reason).toBe("PRE_DELIVERY");

    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${opId}'`).stdout.trim(),
    ).toBe("APPROVED");
    expect(
      runPsql(
        db!,
        `SELECT lease_epoch FROM wallet_active_leases WHERE wallet_id='${walletId}'`,
      ).stdout.trim(),
    ).toBe("7");
  });

  it("7. negative: allowed SQL set forbids second partial, lease delete, EXPIRED", () => {
    if (skip()) return;
    drillsRun += 1;
    expect(() => assertNoForbiddenSqlInAllowedSet()).not.toThrow();
    const src = readFileSync(join(HERE, "../src/send/expiry-attention.ts"), "utf8");
    expect(src).not.toMatch(/DELETE\s+FROM\s+wallet_active_leases/i);
    expect(src).not.toMatch(/INSERT\s+INTO\s+external_send_partials/i);
    expect(src).not.toMatch(/INSERT\s+INTO\s+external_send_sign_intents/i);
    // Executable CAS never targets EXPIRED/REJECTED from AWAITING.
    expect(SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION).toMatch(
      /NEEDS_ATTENTION/,
    );
    expect(SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION).not.toMatch(/EXPIRED/);
    expect(SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION).not.toMatch(/REJECTED/);
  });

  it("8. park CAS+event co-commit: abort mid-path leaves neither side durable (D3)", async () => {
    if (skip()) return;
    drillsRun += 1;
    const opId = "b0000000-0000-4000-8000-000000000018";
    const walletId = walletFor(8);
    seedAwaitingSend(db!, opId, {
      idemKey: "idem-atomic-008-xxxxxxxx",
      walletId,
    });

    // Force the event INSERT half to fail while the UPDATE half would have succeeded:
    // install a temporary BEFORE INSERT trigger that raises. A non-atomic two-statement
    // park would leave NEEDS_ATTENTION without an event; the single-statement CTE must
    // roll the whole statement back (status stays AWAITING, episode stays 0, no event).
    psqlMust(
      db!,
      `CREATE OR REPLACE FUNCTION send_expiry_attention_reject_attention_event() RETURNS trigger AS $$
       BEGIN
         RAISE EXCEPTION 'SEND_EXPIRY_ATTENTION_FORCED_EVENT_INSERT_FAIL';
       END;
       $$ LANGUAGE plpgsql;
       CREATE TRIGGER send_expiry_attention_force_event_fail
         BEFORE INSERT ON external_send_attention_events
         FOR EACH ROW EXECUTE FUNCTION send_expiry_attention_reject_attention_event();`,
    );
    try {
      const query = makeQuery(db!);
      let threw = false;
      try {
        await parkPastExpiryAwaitingRedemption(query, {
          operationId: opId,
          nowUnixSecs: Number(T2_SECS) + 10,
        });
      } catch {
        threw = true;
      }
      expect(threw).toBe(true);

      // Status must still be AWAITING_REDEMPTION — UPDATE half rolled back with the INSERT.
      expect(
        runPsql(
          db!,
          `SELECT status || '|' || attention_required::text || '|' || attention_episode::text ` +
            `FROM send_operations WHERE operation_id='${opId}'`,
        ).stdout.trim(),
      ).toBe("AWAITING_REDEMPTION|false|0");
      expect(
        runPsql(
          db!,
          `SELECT count(*)::text FROM external_send_attention_events ` +
            `WHERE operation_id='${opId}'`,
        ).stdout.trim(),
      ).toBe("0");
      // Lease untouched.
      expect(
        runPsql(
          db!,
          `SELECT lease_epoch::text FROM wallet_active_leases WHERE wallet_id='${walletId}'`,
        ).stdout.trim(),
      ).toBe("7");
    } finally {
      psqlMust(
        db!,
        `DROP TRIGGER IF EXISTS send_expiry_attention_force_event_fail ON external_send_attention_events;
         DROP FUNCTION IF EXISTS send_expiry_attention_reject_attention_event();`,
      );
    }

    // After restore, the same park must succeed with event co-present.
    const query2 = makeQuery(db!);
    const parked = await parkPastExpiryAwaitingRedemption(query2, {
      operationId: opId,
      nowUnixSecs: Number(T2_SECS) + 10,
    });
    expect(parked.kind).toBe("PARKED");
    if (parked.kind !== "PARKED") return;
    expect(parked.attentionEpisode).toBe(1);
    const eventRow = runPsql(
      db!,
      `SELECT event_type || '|' || attention_episode::text || '|' || attention_reason || '|' || ` +
        `(data_text::json->>'attention_episode') ` +
        `FROM external_send_attention_events WHERE operation_id='${opId}'`,
    ).stdout.trim();
    expect(eventRow).toBe(
      `operation.needs_attention|1|${SEND_EXPIRY_ATTENTION_REASON}|1`,
    );
  });
});

registerPgRequiredGuard({
  name: "send-expiry-attention PG",
  databaseUrl: guardDatabaseUrl,
  isReady: () => suiteReady,
  readyMessage:
    "PG_REQUIRED=1 but the send-expiry-attention beforeAll never completed — expiry/attention proofs skipped, not proven",
});
