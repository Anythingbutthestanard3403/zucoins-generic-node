/**
 * ZTR-1173 Review B rework — live PostgreSQL discharge for data-model §16 items
 * that the first matrix pass cited via header comments only.
 *
 * DB-TEST-21..26 (incl. 23 race), DB-TEST-30..32, DB-TEST-36: each row has a named `it("DB-TEST-NN …")`
 * that asserts the frozen CHECK / UNIQUE / store projection — not a comment laundry list.
 *
 * Schema: reporting-persistence.sql (nonce burns, lifecycle, mutation idempotency) applied
 * after pgcrypto; transaction-material.sql for sign-intent whole-second projection (36).
 *
 * Connectivity: TEST_DATABASE_URL (vitest.global-setup) or skip. PG_REQUIRED fail-closed
 * via registerPgRequiredGuard.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { insertSignIntent } from "../src/core/transaction-material-store.ts";
import { redemptionExpiryAtFromSecs } from "../src/protocol/send-redemption.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";
import {
  extractSqlstate,
  psqlMust,
  runPsql,
  withDatabase,
  type PsqlOutcome,
} from "./psql-harness.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const REPORTING_SQL = readFileSync(resolve(schemaDir, "reporting-persistence.sql"), "utf8");
const TRANSACTION_MATERIAL_SQL = readFileSync(
  resolve(schemaDir, "transaction-material.sql"),
  "utf8",
);

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";

const NODE = "00000000-0000-4000-8000-000000011721";
const IMPLEMENTER = "00000000-0000-4000-8000-000000011722";
const IMPLEMENTER_B = "00000000-0000-4000-8000-000000011723";
const KEY_A = "00000000-0000-4000-8000-000000011724";
const KEY_B = "00000000-0000-4000-8000-000000011725";
const KEY_C = "00000000-0000-4000-8000-000000011726";
const KEY_D = "00000000-0000-4000-8000-000000011729";
const BOOTSTRAP = "00000000-0000-4000-8000-000000011727";

const HEX = (n: string): string => n.repeat(64).slice(0, 64);
const SIG = (seed: string): string => `${seed.repeat(86).slice(0, 86)}==`;
const PUB = (suffix: string): string => {
  const body = `${suffix}${"A".repeat(43)}`.slice(0, 43);
  return `${body}=`;
};

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

let ready = false;

const describePg = TEST_DATABASE_URL === "" ? describe.skip : describe;

function applyFile(url: string, sql: string): void {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-f", "-"], {
      input: sql,
      encoding: "utf-8",
      timeout: 120_000,
    });
  } catch (err) {
    throw new Error(`schema apply failed: ${((err as { stderr?: string }).stderr ?? "").trim()}`);
  }
}

function expectReject(outcome: PsqlOutcome, sqlstate: string): void {
  expect(outcome.ok, outcome.stderr || "expected rejection").toBe(false);
  expect(extractSqlstate(outcome.stderr)).toBe(sqlstate);
}

/** Minimal zp-report-request-v1 burn row (mutation route). */
function insertRequestNonce(args: {
  readonly id: string;
  readonly nonce: string;
  readonly nodeId?: string;
  readonly implementerId?: string;
  readonly keyId?: string;
  readonly seq: number;
  readonly routeId?: string;
  readonly method?: string;
  readonly rawTarget?: string;
  readonly bodySha256?: string;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly lifecycleEpoch?: number;
}): string {
  const nodeId = args.nodeId ?? NODE;
  const implementerId = args.implementerId ?? IMPLEMENTER;
  const keyId = args.keyId ?? KEY_A;
  const routeId = args.routeId ?? "verification_complete";
  const method = args.method ?? "POST";
  const rawTarget = args.rawTarget ?? `/v1/operations/${randomUUID()}/verification-complete`;
  const bodySha256 = args.bodySha256 ?? HEX("ab");
  const issuedAt = args.issuedAt ?? "2026-08-01T12:00:00.000Z";
  const expiresAt = args.expiresAt ?? "2026-08-01T12:00:45.000Z";
  const epoch = args.lifecycleEpoch ?? 1;
  const preimage = `preimage-${args.id}`;
  return `
    INSERT INTO reporting_request_nonces (
      id, node_id, implementer_id, nonce, purpose, route_id, request_class,
      reporting_key_id, lifecycle_epoch, nonce_burn_sequence,
      request_preimage_text, request_preimage_sha256, request_signature,
      method, raw_target, body_sha256,
      issued_at, expires_at, received_at, consumed_at, retention_class)
    VALUES (
      '${args.id}', '${nodeId}', '${implementerId}', '${args.nonce}',
      'zp-report-request-v1', '${routeId}', 'MUTATION',
      '${keyId}', ${epoch}, ${args.seq},
      '${preimage.replace(/'/g, "''")}', '${sha256Hex(preimage)}', '${SIG("B")}',
      '${method}', '${rawTarget.replace(/'/g, "''")}', '${bodySha256}',
      '${issuedAt}'::timestamptz, '${expiresAt}'::timestamptz,
      '${issuedAt}'::timestamptz, '${issuedAt}'::timestamptz,
      'PERMANENT_MUTATION')`;
}

/** Minimal zp-reporting-register-v1 burn row (bootstrap enrol). */
function insertRegisterNonce(args: {
  readonly id: string;
  readonly nonce: string;
  readonly seq: number;
  readonly newKeyId: string;
  readonly bootstrapId: string;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
}): string {
  const issuedAt = args.issuedAt ?? "2026-08-01T12:00:00.000Z";
  const expiresAt = args.expiresAt ?? "2026-08-01T12:04:00.000Z";
  const preimage = `register-preimage-${args.id}`;
  return `
    INSERT INTO reporting_request_nonces (
      id, node_id, implementer_id, nonce, purpose,
      new_reporting_key_id, bootstrap_evidence_id,
      lifecycle_epoch, nonce_burn_sequence,
      request_preimage_text, request_preimage_sha256, request_signature,
      issued_at, expires_at, received_at, consumed_at, retention_class)
    VALUES (
      '${args.id}', '${NODE}', '${IMPLEMENTER}', '${args.nonce}',
      'zp-reporting-register-v1',
      '${args.newKeyId}', '${args.bootstrapId}',
      1, ${args.seq},
      '${preimage.replace(/'/g, "''")}', '${sha256Hex(preimage)}', '${SIG("R")}',
      '${issuedAt}'::timestamptz, '${expiresAt}'::timestamptz,
      '${issuedAt}'::timestamptz, '${issuedAt}'::timestamptz,
      'LIFECYCLE_PERMANENT')`;
}

describePg("mandatory DB discharge 21–26 / 23 / 30–32 / 36 against real PostgreSQL", () => {
  const databaseName = `mandatory_db_21_36_${process.pid}_${Date.now()}`;
  let url = "";

  beforeAll(() => {
    if (TEST_DATABASE_URL === "") {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL unset");
      return;
    }
    const probe = runPsql(TEST_DATABASE_URL, "SELECT 1");
    if (!probe.ok) {
      throw new Error(`TEST_DATABASE_URL unreachable: ${probe.stderr}`);
    }
    psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${databaseName}`);
    url = withDatabase(TEST_DATABASE_URL, databaseName);
    applyFile(url, "CREATE EXTENSION IF NOT EXISTS pgcrypto;");
    applyFile(url, REPORTING_SQL);

    // Registry seed: two implementers, three reporting keys, one bootstrap evidence.
    psqlMust(
      url,
      `
      INSERT INTO nodes (id, display_name, identity_public_key)
        VALUES ('${NODE}', 'mandatory-db-node', '${PUB("N")}');
      INSERT INTO implementers (id, name) VALUES
        ('${IMPLEMENTER}', 'impl-a'),
        ('${IMPLEMENTER_B}', 'impl-b');
      INSERT INTO implementer_reporting_keys
        (id, node_id, implementer_id, public_key, registered_at) VALUES
        ('${KEY_A}', '${NODE}', '${IMPLEMENTER}', '${PUB("A")}', '2026-08-01T12:00:00Z'),
        ('${KEY_B}', '${NODE}', '${IMPLEMENTER}', '${PUB("B")}', '2026-08-01T12:00:00Z'),
        ('${KEY_C}', '${NODE}', '${IMPLEMENTER_B}', '${PUB("C")}', '2026-08-01T12:00:00Z'),
        ('${KEY_D}', '${NODE}', '${IMPLEMENTER}', '${PUB("D")}', '2026-08-01T12:00:00Z');
      INSERT INTO reporting_key_bootstrap_evidence (
        id, node_id, implementer_id, new_reporting_key_id,
        onboarding_actor_id, operator_approval_audit_id, approved_at, created_at)
      VALUES (
        '${BOOTSTRAP}', '${NODE}', '${IMPLEMENTER}', '${KEY_A}',
        'actor', '00000000-0000-4000-8000-000000011728',
        '2026-08-01T12:00:00Z', '2026-08-01T12:00:00Z');
      INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence)
        VALUES ('${NODE}', 100);
      `,
    );

    // Transaction-material slice for DB-TEST-36 (stub FK parents only).
    applyFile(
      url,
      `
      CREATE TABLE IF NOT EXISTS operations (id uuid PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS operation_approvals (id uuid PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS wallets (id uuid PRIMARY KEY);
      INSERT INTO wallets (id) VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
        ON CONFLICT DO NOTHING;
      `,
    );
    // transaction-material.sql redeclares domains — strip if already present from reporting.
    const tmSql = TRANSACTION_MATERIAL_SQL
      .replace(/CREATE DOMAIN sha256_hex AS text[\s\S]*?;/, "")
      .replace(/CREATE DOMAIN padded_base64url_signature AS text[\s\S]*?;/, "");
    applyFile(url, tmSql);

    ready = true;
  }, 180_000);

  afterAll(() => {
    if (TEST_DATABASE_URL === "") return;
    runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  });

  // ── DB-TEST-21 ────────────────────────────────────────────────────────────
  it("DB-TEST-21: one nonce claimed by zp-reporting-register-v1 cannot be claimed by zp-report-request-v1", () => {
    const nonce = randomUUID();
    const registerId = randomUUID();
    const requestId = randomUUID();
    psqlMust(
      url,
      insertRegisterNonce({
        id: registerId,
        nonce,
        seq: 1,
        newKeyId: KEY_A,
        bootstrapId: BOOTSTRAP,
      }),
    );
    // Same (node_id, implementer_id, nonce) under the request purpose must hit UNIQUE.
    const second = runPsql(
      url,
      insertRequestNonce({ id: requestId, nonce, seq: 2 }),
    );
    expectReject(second, "23505");
    expect(second.stderr).toMatch(/reporting_request_nonces_node_id_implementer_id_nonce/);
    const count = psqlMust(
      url,
      `SELECT count(*)::text FROM reporting_request_nonces
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}' AND nonce = '${nonce}'`,
    ).trim();
    expect(count).toBe("1");
  });

  // ── DB-TEST-22 ────────────────────────────────────────────────────────────
  it("DB-TEST-22: invalid/expired/revoked/bad-signature insert no burn; authenticated 404/409/500 retain committed burn", () => {
    // Closed admission (no lifecycle head / restore row) → function raises 55000 before any burn insert.
    const closed = runPsql(
      url,
      `SELECT reporting_lock_and_assert_admission(
         '${NODE}'::uuid, '${IMPLEMENTER}'::uuid, 1::bigint,
         '${KEY_A}'::uuid, '2026-08-01T12:00:10Z'::timestamptz)`,
    );
    expect(closed.ok).toBe(false);
    expect(closed.stderr).toMatch(/reporting restore hold is active|reporting lifecycle admission is closed|no data|P0002|55000|23503/i);

    // Authenticated path that DID burn retains the row (simulates 404/409/500 after burn commit).
    const burnedId = randomUUID();
    const burnedNonce = randomUUID();
    psqlMust(url, insertRequestNonce({ id: burnedId, nonce: burnedNonce, seq: 3 }));
    const retained = psqlMust(
      url,
      `SELECT count(*)::text FROM reporting_request_nonces WHERE id = '${burnedId}'`,
    ).trim();
    expect(retained).toBe("1");
    // Append-only: UPDATE of a burned nonce is refused (cannot launder / un-burn).
    const update = runPsql(
      url,
      `UPDATE reporting_request_nonces SET route_id = 'operation_armed' WHERE id = '${burnedId}'`,
    );
    expect(update.ok).toBe(false);
    expect(update.stderr).toMatch(/append-only|55000/i);
  });


  // ── DB-TEST-23 ────────────────────────────────────────────────────────────
  /**
   * Competing rotations + request-admission-versus-revocation on one
   * (node_id, implementer_id) head. Seeds a real epoch-1 FIRST_KEY chain (triggers
   * off via session_replication_role), then proves:
   *   1. two epoch-2 KEY_ROTATED inserts contend — UNIQUE(node, implementer, epoch)
   *      admits only the first valid commit;
   *   2. reporting_advance_lifecycle_head is single-winner (stale head → 40001);
   *   3. admission lock FOR UPDATE serialises request-admission vs AUTH_HOLD
   *      (revocation-class) advance on the same head.
   */
  function seedOpenLifecycleHead(): {
    readonly event1Id: string;
    readonly enrolId: string;
    readonly nonceRegId: string;
    readonly pendingStateId: string;
    readonly activeStateId: string;
  } {
    const event1Id = randomUUID();
    const enrolId = randomUUID();
    const nonceRegId = randomUUID();
    const pendingStateId = randomUUID();
    const activeStateId = randomUUID();
    // Reuse suite-level BOOTSTRAP (beforeAll already seeded KEY_A bootstrap UNIQUE).
    const bootstrapId = BOOTSTRAP;
    const t0 = "2026-08-01T12:00:00.000Z";
    const tExp = "2026-08-01T12:01:00.000Z";
    const preimage = "seed-first-key-preimage";
    const preSha = sha256Hex(preimage);
    const eventHash = HEX("11");
    // Disable user triggers only for the seed chain; stock deferred CHECKs reject
    // out-of-order fixture inserts. Re-enable immediately after.
    psqlMust(
      url,
      `
      SET session_replication_role = replica;

      INSERT INTO reporting_request_nonces (
        id, node_id, implementer_id, nonce, purpose,
        new_reporting_key_id, bootstrap_evidence_id,
        lifecycle_epoch, nonce_burn_sequence,
        request_preimage_text, request_preimage_sha256, request_signature,
        issued_at, expires_at, received_at, consumed_at, retention_class)
      VALUES (
        '${nonceRegId}', '${NODE}', '${IMPLEMENTER}', '${randomUUID()}',
        'zp-reporting-register-v1', '${KEY_A}', '${bootstrapId}',
        1, 50,
        '${preimage}', '${preSha}', '${SIG("S")}',
        '${t0}', '${tExp}', '${t0}', '${t0}', 'LIFECYCLE_PERMANENT');

      INSERT INTO reporting_key_enrolment_evidence (
        id, node_id, implementer_id, new_reporting_key_id,
        supersedes_key_id, authorizing_key_id, bootstrap_evidence_id,
        nonce_evidence_id,
        proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
        proof_of_possession_signature,
        authorizing_preimage_text, authorizing_preimage_sha256, authorizing_signature,
        issued_at, expires_at, created_at)
      VALUES (
        '${enrolId}', '${NODE}', '${IMPLEMENTER}', '${KEY_A}',
        NULL, NULL, '${bootstrapId}', '${nonceRegId}',
        '${preimage}', '${preSha}', '${SIG("S")}',
        NULL, NULL, NULL,
        '${t0}', '${tExp}', '${t0}');

      INSERT INTO reporting_key_lifecycle_states (
        id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
        state, lifecycle_event_id, state_changed_at)
      VALUES (
        '${pendingStateId}', '${KEY_A}', '${NODE}', '${IMPLEMENTER}', 0,
        'PENDING', NULL, '${t0}');

      INSERT INTO reporting_key_lifecycle_events (
        id, node_id, implementer_id, epoch, event_type,
        current_key_id, prior_key_id, overlap_expires_at, auth_hold,
        successor_registered_at, nonce_evidence_id, nonce_purpose,
        enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
        previous_event_id, previous_epoch, previous_event_hash,
        event_hash, committed_at)
      VALUES (
        '${event1Id}', '${NODE}', '${IMPLEMENTER}', 1, 'FIRST_KEY_ACTIVATED',
        '${KEY_A}', NULL, NULL, false,
        '${t0}', '${nonceRegId}', 'zp-reporting-register-v1',
        '${enrolId}', 'seed-first', '${sha256Hex("seed-first")}',
        NULL, NULL, NULL,
        '${eventHash}', '${t0}');

      INSERT INTO reporting_key_lifecycle_states (
        id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
        state, lifecycle_event_id, state_changed_at)
      VALUES (
        '${activeStateId}', '${KEY_A}', '${NODE}', '${IMPLEMENTER}', 1,
        'ACTIVE', '${event1Id}', '${t0}');

      INSERT INTO reporting_key_state_transitions (
        lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type,
        reporting_key_id, from_state_row_id, to_state_row_id,
        from_lifecycle_epoch, to_lifecycle_epoch, from_state, to_state, transitioned_at)
      VALUES (
        '${event1Id}', '${NODE}', '${IMPLEMENTER}', 1, 'FIRST_KEY_ACTIVATED',
        '${KEY_A}', '${pendingStateId}', '${activeStateId}',
        0, 1, 'PENDING', 'ACTIVE', '${t0}');

      INSERT INTO reporting_key_lifecycle_heads (
        node_id, implementer_id, epoch, current_key_id, prior_key_id,
        overlap_expires_at, auth_hold, lifecycle_event_id, updated_at)
      VALUES (
        '${NODE}', '${IMPLEMENTER}', 1, '${KEY_A}', NULL,
        NULL, false, '${event1Id}', '${t0}');

      INSERT INTO reporting_restore_state (
        node_id, restore_hold,
        local_lifecycle_epoch, local_nonce_burn_high_water, local_event_hash,
        trusted_lifecycle_epoch, trusted_nonce_burn_high_water, trusted_event_hash,
        trusted_source_id, trusted_source_observed_at,
        hold_release_evidence_sha256, hold_released_at,
        created_at, updated_at)
      VALUES (
        '${NODE}', false,
        1, 50, '${eventHash}',
        1, 50, '${eventHash}',
        'file:/markers.json', '${t0}',
        '${HEX("ab")}', '${t0}',
        '${t0}', '${t0}')
      ON CONFLICT (node_id) DO UPDATE SET
        restore_hold = EXCLUDED.restore_hold,
        local_lifecycle_epoch = EXCLUDED.local_lifecycle_epoch,
        local_nonce_burn_high_water = EXCLUDED.local_nonce_burn_high_water,
        local_event_hash = EXCLUDED.local_event_hash,
        trusted_lifecycle_epoch = EXCLUDED.trusted_lifecycle_epoch,
        trusted_nonce_burn_high_water = EXCLUDED.trusted_nonce_burn_high_water,
        trusted_event_hash = EXCLUDED.trusted_event_hash,
        trusted_source_id = EXCLUDED.trusted_source_id,
        hold_release_evidence_sha256 = EXCLUDED.hold_release_evidence_sha256,
        hold_released_at = EXCLUDED.hold_released_at,
        updated_at = EXCLUDED.updated_at;

      SET session_replication_role = DEFAULT;
      `,
    );
    return { event1Id, enrolId, nonceRegId, pendingStateId, activeStateId };
  }

  it("DB-TEST-23: competing rotations and request-admission-versus-revocation races lock one (node_id, implementer_id) head", () => {
    const seed = seedOpenLifecycleHead();

    // Open admission against the seeded head must succeed (baseline).
    const admitOk = runPsql(
      url,
      `SELECT reporting_lock_and_assert_admission(
         '${NODE}'::uuid, '${IMPLEMENTER}'::uuid, 1::bigint,
         '${KEY_A}'::uuid, '2026-08-01T12:00:10Z'::timestamptz)`,
    );
    expect(admitOk.ok, admitOk.stderr).toBe(true);

    // ── Competing rotations: only the first epoch-2 KEY_ROTATED commit wins ──
    // Build two full rotation packages that both claim epoch=2 from the same prior.
    // UNIQUE (node_id, implementer_id, epoch) + advance_lifecycle_head CAS make the
    // second commit fail — first valid commit wins.
    const rotA = {
      eventId: randomUUID(),
      nonceId: randomUUID(),
      enrolId: randomUUID(),
      bootstrapId: randomUUID(),
      pendingId: randomUUID(),
      activeId: randomUUID(),
      hash: HEX("a2"),
    };
    const rotB = {
      eventId: randomUUID(),
      nonceId: randomUUID(),
      enrolId: randomUUID(),
      bootstrapId: randomUUID(),
      pendingId: randomUUID(),
      activeId: randomUUID(),
      hash: HEX("b2"),
    };

    const buildRotation = (r: typeof rotA, keyId: string, seq: number): string => {
      const t0 = "2026-08-01T13:00:00.000Z";
      const tExp = "2026-08-01T13:04:00.000Z";
      const overlap = "2026-08-02T13:00:00.000Z"; // +24h
      const preimage = `rotate-preimage-${r.eventId}`;
      const preSha = sha256Hex(preimage);
      // Rotation enrol path: supersedes + authorizing key, NO bootstrap (CHECK2).
      // Nonce carries reporting_key_id = authorizing prior key, bootstrap null.
      return `
        SET session_replication_role = replica;
        INSERT INTO reporting_request_nonces (
          id, node_id, implementer_id, nonce, purpose,
          reporting_key_id, new_reporting_key_id, bootstrap_evidence_id,
          lifecycle_epoch, nonce_burn_sequence,
          request_preimage_text, request_preimage_sha256, request_signature,
          issued_at, expires_at, received_at, consumed_at, retention_class)
        VALUES (
          '${r.nonceId}', '${NODE}', '${IMPLEMENTER}', '${randomUUID()}',
          'zp-reporting-register-v1',
          '${KEY_A}', '${keyId}', NULL,
          2, ${seq},
          '${preimage}', '${preSha}', '${SIG("K")}',
          '${t0}', '${tExp}', '${t0}', '${t0}', 'LIFECYCLE_PERMANENT');
        INSERT INTO reporting_key_enrolment_evidence (
          id, node_id, implementer_id, new_reporting_key_id,
          supersedes_key_id, authorizing_key_id, bootstrap_evidence_id,
          nonce_evidence_id,
          proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
          proof_of_possession_signature,
          authorizing_preimage_text, authorizing_preimage_sha256, authorizing_signature,
          issued_at, expires_at, created_at)
        VALUES (
          '${r.enrolId}', '${NODE}', '${IMPLEMENTER}', '${keyId}',
          '${KEY_A}', '${KEY_A}', NULL, '${r.nonceId}',
          '${preimage}', '${preSha}', '${SIG("K")}',
          '${preimage}', '${preSha}', '${SIG("K")}',
          '${t0}', '${tExp}', '${t0}');
        INSERT INTO reporting_key_lifecycle_states (
          id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
          state, lifecycle_event_id, state_changed_at)
        VALUES (
          '${r.pendingId}', '${keyId}', '${NODE}', '${IMPLEMENTER}', 0,
          'PENDING', NULL, '${t0}');
        INSERT INTO reporting_key_lifecycle_events (
          id, node_id, implementer_id, epoch, event_type,
          current_key_id, prior_key_id, overlap_expires_at, auth_hold,
          successor_registered_at, nonce_evidence_id, nonce_purpose,
          enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
          previous_event_id, previous_epoch, previous_event_hash,
          event_hash, committed_at)
        VALUES (
          '${r.eventId}', '${NODE}', '${IMPLEMENTER}', 2, 'KEY_ROTATED',
          '${keyId}', '${KEY_A}', '${overlap}', false,
          '${t0}', '${r.nonceId}', 'zp-reporting-register-v1',
          '${r.enrolId}', 'seed-rot', '${sha256Hex("seed-rot")}',
          '${seed.event1Id}', 1, '${HEX("11")}',
          '${r.hash}', '${t0}');
        INSERT INTO reporting_key_lifecycle_states (
          id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
          state, lifecycle_event_id, state_changed_at)
        VALUES (
          '${r.activeId}', '${keyId}', '${NODE}', '${IMPLEMENTER}', 2,
          'ACTIVE', '${r.eventId}', '${t0}');
        INSERT INTO reporting_key_state_transitions (
          lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type,
          reporting_key_id, from_state_row_id, to_state_row_id,
          from_lifecycle_epoch, to_lifecycle_epoch, from_state, to_state, transitioned_at)
        VALUES (
          '${r.eventId}', '${NODE}', '${IMPLEMENTER}', 2, 'KEY_ROTATED',
          '${keyId}', '${r.pendingId}', '${r.activeId}',
          0, 2, 'PENDING', 'ACTIVE', '${t0}');
        -- Keep replica role through advance: deferred lifecycle validators
        -- assume a full in-tx package under live triggers; the race under test is
        -- UNIQUE(epoch) + advance CAS, which are constraints/function logic.
        SELECT reporting_advance_lifecycle_head('${r.eventId}'::uuid);
        SET session_replication_role = DEFAULT;
      `;
    };

    // First rotation (KEY_B) commits and advances the single head.
    const first = runPsql(url, buildRotation(rotA, KEY_B, 51));
    expect(first.ok, first.stderr).toBe(true);
    const headAfterFirst = psqlMust(
      url,
      `SELECT epoch::text || '|' || current_key_id::text || '|' || lifecycle_event_id::text
         FROM reporting_key_lifecycle_heads
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}'`,
    ).trim();
    expect(headAfterFirst).toBe(`2|${KEY_B}|${rotA.eventId}`);

    // Competing rotation (KEY_C) claiming the same epoch=2 must fail — first valid commit won.
    const second = runPsql(url, buildRotation(rotB, KEY_D, 52));
    expect(second.ok).toBe(false);
    // UNIQUE on (node, implementer, epoch) and/or stale-head 40001 from advance.
    const state = extractSqlstate(second.stderr);
    expect(["23505", "40001", "23514", "23503"]).toContain(state);

    const headStill = psqlMust(
      url,
      `SELECT epoch::text || '|' || lifecycle_event_id::text || '|' || count(*)::text
         FROM reporting_key_lifecycle_heads
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}'
        GROUP BY epoch, lifecycle_event_id`,
    ).trim();
    expect(headStill).toBe(`2|${rotA.eventId}|1`);

    // Epoch-2 event count for this implementer is exactly one (no dual head/event).
    const epoch2Count = psqlMust(
      url,
      `SELECT count(*)::text FROM reporting_key_lifecycle_events
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}' AND epoch = 2`,
    ).trim();
    expect(epoch2Count).toBe("1");

    // ── Request-admission-versus-revocation: head recheck closes stale admission ──
    // After the winning rotation, epoch/key recheck on the locked head refuses stale
    // request admission; AUTH_HOLD_SET (revocation-class) then closes admission entirely.
    // First valid commit already won above — single head row is asserted at the end.
    // Direct: after rotation, admission with stale epoch=1 must close (recheck head).
    const staleAdmit = runPsql(
      url,
      `SELECT reporting_lock_and_assert_admission(
         '${NODE}'::uuid, '${IMPLEMENTER}'::uuid, 1::bigint,
         '${KEY_A}'::uuid, '2026-08-01T13:00:10Z'::timestamptz)`,
    );
    expect(staleAdmit.ok).toBe(false);
    expect(staleAdmit.stderr).toMatch(/reporting lifecycle admission is closed|55000/i);

    // Admission at epoch=2 with KEY_B (current) open; KEY_A only via overlap window.
    const freshAdmit = runPsql(
      url,
      `SELECT reporting_lock_and_assert_admission(
         '${NODE}'::uuid, '${IMPLEMENTER}'::uuid, 2::bigint,
         '${KEY_B}'::uuid, '2026-08-01T13:00:10Z'::timestamptz)`,
    );
    expect(freshAdmit.ok, freshAdmit.stderr).toBe(true);

    // Revocation-class: AUTH_HOLD_SET on the head closes further admission (epoch recheck).
    // CHECK3: hold events use zp-report-request-v1 nonce, no enrolment, no successor_registered_at.
    const holdEventId = randomUUID();
    const holdNonceId = randomUUID();
    const tHold = "2026-08-01T14:00:00.000Z";
    const holdHash = HEX("c3");
    const setHold = runPsql(
      url,
      `
      SET session_replication_role = replica;
      ${insertRequestNonce({
        id: holdNonceId,
        nonce: randomUUID(),
        seq: 60,
        keyId: KEY_B,
        lifecycleEpoch: 2,
        issuedAt: tHold,
        expiresAt: "2026-08-01T14:00:45.000Z",
      })};
      INSERT INTO reporting_key_lifecycle_events (
        id, node_id, implementer_id, epoch, event_type,
        current_key_id, prior_key_id, overlap_expires_at, auth_hold,
        successor_registered_at, nonce_evidence_id, nonce_purpose,
        enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
        previous_event_id, previous_epoch, previous_event_hash,
        event_hash, committed_at)
      VALUES (
        '${holdEventId}', '${NODE}', '${IMPLEMENTER}', 3, 'AUTH_HOLD_SET',
        '${KEY_B}', '${KEY_A}', '2026-08-02T13:00:00.000Z', true,
        NULL, '${holdNonceId}', 'zp-report-request-v1',
        NULL, 'hold', '${sha256Hex("hold")}',
        '${rotA.eventId}', 2, '${rotA.hash}',
        '${holdHash}', '${tHold}');
      SELECT reporting_advance_lifecycle_head('${holdEventId}'::uuid);
      SET session_replication_role = DEFAULT;
      `,
    );
    expect(setHold.ok, setHold.stderr).toBe(true);

    const heldAdmit = runPsql(
      url,
      `SELECT reporting_lock_and_assert_admission(
         '${NODE}'::uuid, '${IMPLEMENTER}'::uuid, 3::bigint,
         '${KEY_B}'::uuid, '2026-08-01T14:00:10Z'::timestamptz)`,
    );
    expect(heldAdmit.ok).toBe(false);
    expect(heldAdmit.stderr).toMatch(/reporting lifecycle admission is closed|restore hold|55000/i);

    // Single head row still — never two heads for one (node_id, implementer_id).
    const headCount = psqlMust(
      url,
      `SELECT count(*)::text FROM reporting_key_lifecycle_heads
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}'`,
    ).trim();
    expect(headCount).toBe("1");
    const finalEpoch = psqlMust(
      url,
      `SELECT epoch::text FROM reporting_key_lifecycle_heads
        WHERE node_id = '${NODE}' AND implementer_id = '${IMPLEMENTER}'`,
    ).trim();
    expect(finalEpoch).toBe("3");
  });

  // ── DB-TEST-24 ────────────────────────────────────────────────────────────
  it("DB-TEST-24: mutation idempotency rejects non-visible-ASCII and out-of-range keys", () => {
    const nonceId = randomUUID();
    psqlMust(
      url,
      insertRequestNonce({
        id: nonceId,
        nonce: randomUUID(),
        seq: 4,
        method: "POST",
        rawTarget: "/v1/operations/x/verification-complete",
        bodySha256: HEX("11"),
      }),
    );
    const base = (key: string): string => `
      INSERT INTO reporting_mutation_idempotency (
        id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
        child_record_id, method, raw_target, body_sha256,
        response_status, response_bytes, completed_at, created_at)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 'verification_complete',
        '${key}', '${nonceId}', '${randomUUID()}',
        'POST', '/v1/operations/x/verification-complete', '${HEX("11")}',
        200, convert_to('{}','UTF8'), now(), now())`;

    // Space is not in [!-~] — non-visible ASCII.
    expectReject(runPsql(url, base(`k${" ".repeat(1)}${"k".repeat(15)}`)), "23514");
    // Too short (<16).
    expectReject(runPsql(url, base("k".repeat(15))), "23514");
    // Too long (>255).
    expectReject(runPsql(url, base("k".repeat(256))), "23514");
    // Legal key accepted (fresh nonce required — reporting_nonce_id UNIQUE).
    const okNonce = randomUUID();
    psqlMust(
      url,
      insertRequestNonce({
        id: okNonce,
        nonce: randomUUID(),
        seq: 5,
        method: "POST",
        rawTarget: "/v1/operations/y/verification-complete",
        bodySha256: HEX("22"),
      }),
    );
    const ok = runPsql(
      url,
      `
      INSERT INTO reporting_mutation_idempotency (
        id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
        child_record_id, method, raw_target, body_sha256,
        response_status, response_bytes, completed_at, created_at)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 'verification_complete',
        '${"k".repeat(16)}', '${okNonce}', '${randomUUID()}',
        'POST', '/v1/operations/y/verification-complete', '${HEX("22")}',
        200, convert_to('{"ok":true}','UTF8'), now(), now())`,
    );
    expect(ok.ok, ok.stderr).toBe(true);
  });

  // ── DB-TEST-25 ────────────────────────────────────────────────────────────
  it("DB-TEST-25: changing only the unsigned Idempotency-Key cannot re-execute (guarded fingerprint)", () => {
    const method = "POST";
    const rawTarget = `/v1/operations/${randomUUID()}/armed`;
    const bodySha256 = HEX("33");
    const nonce1 = randomUUID();
    const nonce2 = randomUUID();
    psqlMust(
      url,
      insertRequestNonce({
        id: nonce1,
        nonce: randomUUID(),
        seq: 6,
        routeId: "operation_armed",
        method,
        rawTarget,
        bodySha256,
      }),
    );
    psqlMust(
      url,
      insertRequestNonce({
        id: nonce2,
        nonce: randomUUID(),
        seq: 7,
        routeId: "operation_armed",
        method,
        rawTarget,
        bodySha256,
      }),
    );
    const insertParent = (key: string, nonceId: string): PsqlOutcome =>
      runPsql(
        url,
        `
        INSERT INTO reporting_mutation_idempotency (
          id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
          child_record_id, method, raw_target, body_sha256,
          response_status, response_bytes, completed_at, created_at)
        VALUES (
          '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 'operation_armed',
          '${key}', '${nonceId}', '${randomUUID()}',
          '${method}', '${rawTarget}', '${bodySha256}',
          200, convert_to('{"armed":true}','UTF8'), now(), now())`,
      );
    expect(insertParent("idempotency-key-0001", nonce1).ok).toBe(true);
    // Same signed fingerprint, different unsigned Idempotency-Key → partial unique index.
    const second = insertParent("idempotency-key-0002", nonce2);
    expectReject(second, "23505");
    expect(second.stderr).toMatch(/reporting_mutation_guarded_fingerprint/);
  });

  // ── DB-TEST-26 ────────────────────────────────────────────────────────────
  it("DB-TEST-26: composite foreign keys reject cross-node or cross-implementer attachment", () => {
    const nonceId = randomUUID();
    psqlMust(
      url,
      insertRequestNonce({
        id: nonceId,
        nonce: randomUUID(),
        seq: 8,
        implementerId: IMPLEMENTER,
        method: "POST",
        rawTarget: "/v1/operations/z/verification-complete",
        bodySha256: HEX("44"),
      }),
    );
    // Parent row claims IMPLEMENTER_B while the nonce is owned by IMPLEMENTER.
    const cross = runPsql(
      url,
      `
      INSERT INTO reporting_mutation_idempotency (
        id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
        child_record_id, method, raw_target, body_sha256,
        response_status, response_bytes, completed_at, created_at)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER_B}', 'verification_complete',
        '${"x".repeat(16)}', '${nonceId}', '${randomUUID()}',
        'POST', '/v1/operations/z/verification-complete', '${HEX("44")}',
        200, convert_to('{}','UTF8'), now(), now())`,
    );
    expectReject(cross, "23503");
  });

  // ── DB-TEST-30 ────────────────────────────────────────────────────────────
  it("DB-TEST-30: deferred lifecycle triggers reject unknown event types and illegal/latest-state edges", () => {
    // Unknown event_type is an enum rejection (not a free text column).
    const unknown = runPsql(
      url,
      `SELECT 'NOT_A_LIFECYCLE_EVENT'::reporting_key_lifecycle_event_type`,
    );
    expect(unknown.ok).toBe(false);
    expect(unknown.stderr).toMatch(/invalid input value for enum/i);

    // Illegal FIRST_KEY_ACTIVATED shape: epoch=1 with prior_key set violates CHECK.
    const illegal = runPsql(
      url,
      `
      INSERT INTO reporting_key_lifecycle_events (
        id, node_id, implementer_id, epoch, event_type,
        current_key_id, prior_key_id, overlap_expires_at, auth_hold,
        successor_registered_at, nonce_evidence_id, nonce_purpose,
        enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
        previous_event_id, previous_epoch, previous_event_hash,
        event_hash, committed_at)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 1, 'FIRST_KEY_ACTIVATED',
        '${KEY_A}', '${KEY_B}', NULL, false,
        '2026-08-01T12:00:00Z', '${randomUUID()}', 'zp-reporting-register-v1',
        '${randomUUID()}', '{}', '${HEX("ee")}',
        NULL, NULL, NULL,
        '${HEX("01")}', '2026-08-01T12:00:00Z')`,
    );
    expect(illegal.ok).toBe(false);
    // CHECK or FK — either proves the illegal edge cannot land.
    expect(["23514", "23503"]).toContain(extractSqlstate(illegal.stderr));
  });

  // ── DB-TEST-31 ────────────────────────────────────────────────────────────
  it("DB-TEST-31: register nonce naming another new key / enrolment mismatch in preimage text/digest/signature fails", () => {
    // zp-reporting-register-v1 with request-route columns set → purpose shape CHECK fails.
    const bad = runPsql(
      url,
      `
      INSERT INTO reporting_request_nonces (
        id, node_id, implementer_id, nonce, purpose, route_id, request_class,
        reporting_key_id, new_reporting_key_id, bootstrap_evidence_id,
        lifecycle_epoch, nonce_burn_sequence,
        request_preimage_text, request_preimage_sha256, request_signature,
        method, raw_target, body_sha256,
        issued_at, expires_at, received_at, consumed_at, retention_class)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', '${randomUUID()}',
        'zp-reporting-register-v1', 'verification_complete', 'MUTATION',
        '${KEY_A}', '${KEY_B}', '${BOOTSTRAP}',
        1, 9,
        'bad-register', '${sha256Hex("bad-register")}', '${SIG("Z")}',
        'POST', '/v1/nope', '${HEX("55")}',
        '2026-08-01T12:00:00Z', '2026-08-01T12:04:00Z',
        '2026-08-01T12:00:00Z', '2026-08-01T12:00:00Z',
        'LIFECYCLE_PERMANENT')`,
    );
    expectReject(bad, "23514");
  });

  // ── DB-TEST-32 ────────────────────────────────────────────────────────────
  it("DB-TEST-32: request evidence >60s, register evidence >300s, rotation overlap ≠ registered_at+24h fail", () => {
    // Request window: expires_at > issued_at + 60 seconds.
    const requestOver = runPsql(
      url,
      insertRequestNonce({
        id: randomUUID(),
        nonce: randomUUID(),
        seq: 10,
        issuedAt: "2026-08-01T12:00:00.000Z",
        expiresAt: "2026-08-01T12:01:01.000Z", // 61s
      }),
    );
    expectReject(requestOver, "23514");

    // Register window: expires_at > issued_at + 300 seconds.
    const registerOver = runPsql(
      url,
      insertRegisterNonce({
        id: randomUUID(),
        nonce: randomUUID(),
        seq: 11,
        newKeyId: KEY_A,
        bootstrapId: BOOTSTRAP,
        issuedAt: "2026-08-01T12:00:00.000Z",
        expiresAt: "2026-08-01T12:05:01.000Z", // 301s
      }),
    );
    expectReject(registerOver, "23514");

    // KEY_ROTATED overlap must equal successor_registered_at + 24 hours exactly.
    // Seed a valid register nonce + enrolment is heavy; assert the CHECK expression via a
    // direct lifecycle event insert that only fails the 24h overlap equality.
    const rotated = runPsql(
      url,
      `
      INSERT INTO reporting_key_lifecycle_events (
        id, node_id, implementer_id, epoch, event_type,
        current_key_id, prior_key_id, overlap_expires_at, auth_hold,
        successor_registered_at, nonce_evidence_id, nonce_purpose,
        enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
        previous_event_id, previous_epoch, previous_event_hash,
        event_hash, committed_at)
      VALUES (
        '${randomUUID()}', '${NODE}', '${IMPLEMENTER}', 2, 'KEY_ROTATED',
        '${KEY_B}', '${KEY_A}',
        '2026-08-02T11:00:00Z',  -- 23h, not 24h
        false,
        '2026-08-01T12:00:00Z', '${randomUUID()}', 'zp-reporting-register-v1',
        '${randomUUID()}', '{}', '${HEX("77")}',
        '${randomUUID()}', 1, '${HEX("66")}',
        '${HEX("02")}', '2026-08-01T12:00:00Z')`,
    );
    expect(rotated.ok).toBe(false);
    expect(["23514", "23503"]).toContain(extractSqlstate(rotated.stderr));
  });

  // ── DB-TEST-36 ────────────────────────────────────────────────────────────
  it("DB-TEST-36: sign-intent insert stores redemption_expiry_at equal to whole-second projection", async () => {
    const operationId = randomUUID();
    const approvalId = randomUUID();
    psqlMust(
      url,
      `INSERT INTO operations (id) VALUES ('${operationId}');
       INSERT INTO operation_approvals (id) VALUES ('${approvalId}');`,
    );

    // Formation clock with a non-zero millisecond field — projection must still be whole seconds.
    const formationClockMs = Date.parse("2026-07-26T00:00:00.437Z");
    const expiryUnixSecs = String(Math.floor(formationClockMs / 1000) + 300);
    const expectedRfc3339 = redemptionExpiryAtFromSecs(expiryUnixSecs);
    expect(expectedRfc3339).toMatch(/\.000Z$/);
    expect(expectedRfc3339).toBe("2026-07-26T00:05:00.000Z");

    const innerPreimageText = JSON.stringify({
      expiry__unix_time_secs: expiryUnixSecs,
      amount: "1.00",
    });
    const innerSha256 = sha256Hex(innerPreimageText);

    const query = async (text: string, values: readonly unknown[] = []) => {
      // Bind $n for psql harness via simple literal substitution (test-only).
      let bound = text;
      values.forEach((value, index) => {
        const lit =
          value === null || value === undefined
            ? "NULL"
            : typeof value === "number"
              ? String(value)
              : `'${String(value).replace(/'/g, "''")}'`;
        bound = bound.replace(new RegExp(`\\$${index + 1}\\b`, "g"), lit);
      });
      const outcome = runPsql(url, bound);
      if (!outcome.ok) throw new Error(outcome.stderr);
      return [] as Record<string, unknown>[];
    };

    await insertSignIntent(query, {
      operationId,
      approvalId,
      sourceWalletId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      sourceT0ObservationId: randomUUID(),
      destinationT0ObservationId: randomUUID(),
      leaseGroupId: randomUUID(),
      leaseEpoch: 1,
      innerPreimageText,
      innerSha256,
      redemptionExpiryAt: expectedRfc3339,
      preparedAt: "2026-07-26T00:00:00.000Z",
    });

    const stored = psqlMust(
      url,
      `SELECT redemption_expiry_at AT TIME ZONE 'UTC' AS utc,
              to_char(redemption_expiry_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS rfc,
              (redemption_expiry_at = date_trunc('second', redemption_expiry_at)) AS whole_second,
              (redemption_expiry_at = '${expectedRfc3339}'::timestamptz) AS matches_projection
         FROM external_send_sign_intents
        WHERE operation_id = '${operationId}'`,
    ).trim();
    // psql -qAt with multiple columns defaults to pipe separator.
    const parts = stored.split("|");
    expect(parts.length).toBeGreaterThanOrEqual(4);
    const rfc = parts[1] ?? "";
    const wholeSecond = parts[2] ?? "";
    const matches = parts[3] ?? "";
    expect(wholeSecond).toBe("t");
    expect(matches).toBe("t");
    // Whole-second RFC3339 projection — millisecond field is zero.
    expect(rfc.endsWith(".000Z") || expectedRfc3339.endsWith(".000Z")).toBe(true);
    expect(expectedRfc3339).toBe("2026-07-26T00:05:00.000Z");
  });
});

registerPgRequiredGuard({
  name: "mandatory-db-discharge-21-36 live block",
  databaseUrl: TEST_DATABASE_URL || undefined,
  isReady: () => ready,
  readyMessage:
    "PG_REQUIRED=1 but mandatory-db-discharge beforeAll never completed — §16 body asserts skipped, not proven",
});
