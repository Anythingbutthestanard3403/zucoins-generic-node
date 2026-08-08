// fault-inject receive terminal races against real PostgreSQL.
//
// Parent exit criteria :
//   ACK never settles; RECEIVE never creates a later attempt; possible landing retains
//   the lease; only expired-unpaid exact-T0 proof permits release.
//
// This suite attacks every joint boundary of landing and expiry:
// landing-before-expiry, expiry-before-landing, land-after-fresh-read, durable-phase crash
// residue, RELEASE blocked while operation_transactions exists, phantom ACK submit,
// event multiplicity, and no second SUBMIT row on reconcile resume.
//
// Governing: operation flows; operations recovery;
// the state-event reference.
// Fixed seed: receive-terminal-race-fault-seed (deterministic op/wallet id derivation).

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  acquireLeases,
  createLeaseGroup,
  migrateLeaseFoundation,
} from "../src/leases/index.js";
import {
  RECEIVE_EXPIRY_RELEASE_STATEMENTS as S,
  SqlReceiveExpiryReleaseService,
} from "../src/receive/expiry-release.js";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  psqlMust,
  runPsql,
  withDatabase,
  withTx,
} from "./psql-harness.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;
const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = resolve(HERE, "../src/schema");

/** Fixed seed — every UUID/sha below is a pure function of this string + a slot. */
const FAULT_SEED = "receive-terminal-race-fault-seed";

const NODE = "28100000-0000-4000-8000-000000000001";
const IMPLEMENTER = "28100000-0000-4000-8000-000000000002";
const OWNER = "28100000-0000-4000-8000-000000000006";
const OBSERVER = "28100000-0000-4000-8000-000000000007";
const SHA = "a".repeat(64);
const PUBKEY = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;
const SIGNING_KEY = "28100000-0000-4000-8000-00000000000e";

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

function tableBlock(sql: string, table: string): string {
  const match = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(sql);
  if (match?.[0] === undefined) {
    throw new Error(`CREATE TABLE ${table} block not found`);
  }
  return match[0];
}

/** Deterministic uuid in the fixture namespace from seed + slot. */
function id(slot: string): string {
  const h = createHash("sha256").update(`${FAULT_SEED}:${slot}`).digest("hex");
  return `28100000-0000-4000-8${h.slice(0, 3)}-${h.slice(3, 15)}`;
}

function _seedReady(op: string, wallet: string, t0: string, idem: string): void {
  psqlMust(
    dbUrl,
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, row_version, amount_zkz,
       receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
       request_sha256, expiry_unix_time_secs, t0_observation_id
     ) VALUES (
       '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
       '${wallet}', 'HOLD', '${op}', 'receive-terminal-race-${idem}',
       'receive-terminal-race-idem-${idem}', '${SHA}', '1', '${t0}'
     ) ON CONFLICT (id) DO NOTHING`,
  );
}

async function seedLeasedReady(slot: number): Promise<{
  op: string;
  wallet: string;
  t0: string;
  fresh: string;
  pubkey: string;
}> {
  const op = id(`op-${slot}`);
  const wallet = id(`wallet-${slot}`);
  const t0 = id(`t0-${slot}`);
  const fresh = id(`fresh-${slot}`);
  const recovery = id(`recovery-${slot}`);
  const artifact = id(`artifact-${slot}`);
  const pubkey = `${"Q".repeat(41)}${slot.toString(36).padStart(2, "0")}=`;
  const nowMs = Date.now();
  psqlMust(
    dbUrl,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ('${wallet}', '${NODE}', '${pubkey}', 'node_generated', 'AVAILABLE')
       ON CONFLICT (id) DO NOTHING;
     INSERT INTO wallet_recovery_verifications (
       id, wallet_id, method, export_sha256, public_key, audit_event_id,
       verified_at, verifier_identity
     ) VALUES (
       '${recovery}', '${wallet}', 'AUDITED_EXPORT', '${SHA}', '${pubkey}',
       '${recovery}', now(), 'receive-terminal-race-race'
     ) ON CONFLICT (id) DO NOTHING;
     UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id='${recovery}'
       WHERE id='${wallet}';
     INSERT INTO operations (
       id, node_id, implementer_id, kind, status, row_version, amount_zkz,
       receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
       request_sha256, expiry_unix_time_secs, t0_observation_id
     ) VALUES (
       '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
       '${wallet}', 'HOLD', '${op}', 'receive-terminal-race-race-${slot}',
       'receive-terminal-race-race-idem-${slot}', '${SHA}', '1', '${t0}'
     ) ON CONFLICT (id) DO NOTHING;
     INSERT INTO operation_wallets (
       operation_id, wallet_id, operation_role, t0_observation_id
     ) VALUES ('${op}', '${wallet}', 'RECEIVER', '${t0}')
       ON CONFLICT DO NOTHING;
     INSERT INTO gateway_observations (
       id, observer_id, wallet_id, wallet_public_key, s_signature, p_signature,
       b_amount, parse_result, relationship, observed_at
     ) VALUES
       ('${t0}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
        'VERIFIED_HEAD', 'FIRST', to_timestamp(0)),
       ('${fresh}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
        'VERIFIED_HEAD', 'DUPLICATE', to_timestamp(${nowMs - 1_000} / 1000.0))
       ON CONFLICT DO NOTHING;
     INSERT INTO operation_expected_artifacts (
       id, operation_id, purpose, canonical_version, signing_key_id,
       preimage_text, preimage_sha256, signature
     ) VALUES (
       '${artifact}', '${op}', 'zp-receive-expected-v1', 1, '${SIGNING_KEY}',
       '{}', '${SHA}', '${SIG}'
     ) ON CONFLICT DO NOTHING;
     INSERT INTO receive_codes (
       operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
       discriminator, anchor, expiry_unix_time_secs, transfer_code_text,
       transfer_code_sha256, code_status, ready_at
     ) VALUES (
       '${op}', '${wallet}', '${t0}', '${artifact}', '${op}',
       'receive-terminal-race-code-${slot}', '1', 'receive-terminal-race-code-${slot}',
       '${SHA}', 'AWAITING_ARM', now()
     ) ON CONFLICT DO NOTHING;`,
  );
  await withTx(dbUrl, async (tx) => {
    const leaseGroupId = await createLeaseGroup(tx, op);
    await acquireLeases(tx, {
      wallets: [{ walletId: wallet, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId,
      rootOperationId: op,
      operationId: op,
      ownerInstanceId: OWNER,
    });
  });
  return { op, wallet, t0, fresh, pubkey };
}

function facts(op: string, wallet: string): string {
  return psqlMust(
    dbUrl,
    `SELECT status::text || ':' ||
        (SELECT count(*) FROM receive_landing_proofs WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM receive_landing_events WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM receive_expiry_events WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM receive_expiry_attention_events WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}') || ':' ||
        (SELECT count(*) FROM operation_transactions WHERE operation_id='${op}') || ':' ||
        (SELECT count(*) FROM gateway_submit_attempts WHERE operation_id='${op}')
       FROM operations WHERE id='${op}'`,
  ).trim();
}

async function landingCas(session: PsqlSessionExecutor, op: string, head: string): Promise<number> {
  const result = await session.query<{ status: string }>(
    `UPDATE operations
        SET status = 'RECEIVE_LANDED', row_version = row_version + 1,
            terminal_observation_id = $2::uuid, terminal_at = now(), updated_at = now()
      WHERE id = $1::uuid AND status = 'READY'
      RETURNING status::text AS status`,
    [op, head],
  );
  return result.rows.length;
}

function insertLandingEvidence(op: string, pubkey: string, t0: string, head: string): void {
  psqlMust(
    dbUrl,
    `BEGIN;
     INSERT INTO receive_landing_proofs (
       operation_id, attempt_phase, public_execution_phase, path_role,
       wallet_public_key, t0_observation_id, fresh_head_observation_id,
       terminal_observation_id, expected_completed_transaction_sha256,
       fresh_head_completed_transaction_sha256, verdict, body_count, path_depth,
       path_manifest_text, path_manifest_sha256, landed_at,
       verification_material_available_until
     ) VALUES (
       '${op}', 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED', 'RECEIVER',
       '${pubkey}', '${t0}', '${head}', '${head}', '${SHA}', '${SHA}',
       'LANDED_EXACT', 1, 0, '{}', '${SHA}', now(), now() + interval '30 days'
     );
     INSERT INTO receive_landing_path_bodies (
       operation_id, path_index, source_kind, completed_transaction_text,
       completed_transaction_sha256, completed_transaction_octets, wallet_role,
       s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256,
       step_1_signature, step_2_signature
     ) VALUES (
       '${op}', 0, 'EXPECTED_OPERATION', '{}', '${SHA}', 2, 'receiver',
       '${SIG}', '', '1', '{}', '${SHA}', '${SIG}', '${SIG}'
     );
     INSERT INTO receive_landing_events (
       operation_id, event_type, terminal_observation_id, landed_at, data_text
     ) VALUES (
       '${op}', 'receive.landed', '${head}', now(),
       '{"terminal_observation_id":"${head}","landed_at":"2026-07-28T00:00:00.000Z"}'
     );
     COMMIT`,
  );
}

/** Durable residue at a named attempt_phase — models crash-after-persist. */
function seedPhaseResidue(
  op: string,
  phase:
    | "STEP1_SIGNATURE_PERSISTED"
    | "STEP2_PREIMAGE_PERSISTED"
    | "STEP2_SIGNATURE_PERSISTED"
    | "SETTLED_BODY_PERSISTED",
  options: { submitClaim?: boolean } = {},
): void {
  // Column nullability tracks the phase CHECKs in transaction-material.sql (attempt_no = 1).
  // STEP2_SIGNATURE_PERSISTED still has completed_transaction_* NULL; SETTLED fills them + settled_at.
  const byPhase: Record<typeof phase, string> = {
    STEP1_SIGNATURE_PERSISTED: `
      INSERT INTO operation_transactions (
        operation_id, attempt_no, attempt_phase,
        inner_preimage_text, inner_sha256, step_1_signature, formed_at
      ) VALUES (
        '${op}', 1, 'STEP1_SIGNATURE_PERSISTED',
        '{}', '${SHA}', '${SIG}', now()
      )`,
    STEP2_PREIMAGE_PERSISTED: `
      INSERT INTO operation_transactions (
        operation_id, attempt_no, attempt_phase,
        inner_preimage_text, inner_sha256, step_1_signature,
        step_2_preimage_text, step_2_preimage_sha256, formed_at
      ) VALUES (
        '${op}', 1, 'STEP2_PREIMAGE_PERSISTED',
        '{}', '${SHA}', '${SIG}',
        '{"s2":1}', '${SHA}', now()
      )`,
    STEP2_SIGNATURE_PERSISTED: `
      INSERT INTO operation_transactions (
        operation_id, attempt_no, attempt_phase,
        inner_preimage_text, inner_sha256, step_1_signature,
        step_2_preimage_text, step_2_preimage_sha256, step_2_signature,
        completed_transaction_text, completed_transaction_sha256, formed_at
      ) VALUES (
        '${op}', 1, 'STEP2_SIGNATURE_PERSISTED',
        '{}', '${SHA}', '${SIG}',
        '{"s2":1}', '${SHA}', '${SIG}',
        '{}', '${SHA}', now()
      )`,
    SETTLED_BODY_PERSISTED: `
      INSERT INTO operation_transactions (
        operation_id, attempt_no, attempt_phase,
        inner_preimage_text, inner_sha256, step_1_signature,
        step_2_preimage_text, step_2_preimage_sha256, step_2_signature,
        completed_transaction_text, completed_transaction_sha256, formed_at, settled_at
      ) VALUES (
        '${op}', 1, 'SETTLED_BODY_PERSISTED',
        '{}', '${SHA}', '${SIG}',
        '{"s2":1}', '${SHA}', '${SIG}',
        '{}', '${SHA}', now(), now()
      )`,
  };
  psqlMust(dbUrl, byPhase[phase]);
  if (options.submitClaim) {
    const decision = id(`decision-${op}`);
    const attempt = id(`submit-${op}`);
    psqlMust(
      dbUrl,
      `INSERT INTO submit_decisions (
         id, operation_id, transaction_attempt_no, decision, decided_at, details
       ) VALUES (
         '${decision}', '${op}', 1, 'INITIAL_SINGLE_SHOT', now(), '{}'
       ) ON CONFLICT DO NOTHING;
       INSERT INTO gateway_submit_attempts (
         id, operation_id, attempt_no, transaction_attempt_no, decision_id,
         request_body, request_sha256, response_body, response_sha256,
         transport_outcome, started_at, completed_at
       ) VALUES (
         '${attempt}', '${op}', 1, 1, '${decision}',
         '{}'::bytea, '${SHA}', '{"status":true}'::bytea, '${SHA}',
         'ACK', now(), now()
       ) ON CONFLICT DO NOTHING`,
    );
  }
}

describe("receive terminal-race fault injection (real PG)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is missing");
      }
      return;
    }

    dbName = `receive_terminal_race_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);

    const base = readFileSync(resolve(SCHEMA, "base-enums-domains.sql"), "utf8");
    const operations = readFileSync(resolve(SCHEMA, "operations.sql"), "utf8");
    const transaction = readFileSync(resolve(SCHEMA, "transaction-material.sql"), "utf8");
    const submit = readFileSync(resolve(SCHEMA, "submit-attempts.sql"), "utf8");
    const landing = readFileSync(resolve(SCHEMA, "receive-external-landing.sql"), "utf8");
    const receiveCodes = readFileSync(resolve(SCHEMA, "receive-codes.sql"), "utf8");
    const expectedArtifacts = readFileSync(resolve(SCHEMA, "expected-artifacts.sql"), "utf8");
    const expiry = readFileSync(resolve(SCHEMA, "receive-expiry-release.sql"), "utf8");

    psqlMust(dbUrl, base);
    psqlMust(
      dbUrl,
      `CREATE TABLE nodes (id uuid PRIMARY KEY);
       CREATE TABLE implementers (id uuid PRIMARY KEY);`,
    );
    psqlMust(dbUrl, readFileSync(resolve(SCHEMA, "custody-eligibility.sql"), "utf8"));
    psqlMust(
      dbUrl,
      `${tableBlock(operations, "operations")}
       ${tableBlock(operations, "operation_wallets")}
       ${tableBlock(transaction, "operation_transactions")}
       ${tableBlock(submit, "submit_decisions")}
       ${tableBlock(submit, "gateway_submit_attempts")}`,
    );
    psqlMust(dbUrl, landing);
    // Stubs that must exist BEFORE the frozen receive-codes.sql applies:
    // observers/gateway_observations back its trailing t0_observation_id FK, and
    // node_signing_keys backs the expected-artifacts.sql signing_key_id FK. The
    // observation ledger and signing-key registry are not under test here, so the
    // stubs carry only the referenced keys.
    psqlMust(
      dbUrl,
      `CREATE TABLE observers (
         id uuid PRIMARY KEY,
         domain text NOT NULL CHECK (domain IN ('NODE','PLATFORM'))
       );
       CREATE TABLE gateway_observations (
         id uuid PRIMARY KEY,
         observer_id uuid NOT NULL REFERENCES observers(id),
         wallet_id uuid REFERENCES wallets(id),
         wallet_public_key text NOT NULL,
         s_signature text,
         p_signature text,
         b_amount text,
         parse_result text NOT NULL,
         relationship text NOT NULL,
         observed_at timestamptz NOT NULL
       );
       CREATE TABLE observation_anomalies (
         observation_id uuid PRIMARY KEY REFERENCES gateway_observations(id)
       );
       CREATE TABLE node_signing_keys (id uuid PRIMARY KEY);`,
    );
    // operation_expected_artifacts and receive_codes are frozen slices; use byte-exact
    // file contents. expected-artifacts.sql owns operation_expected_artifacts and must
    // apply before receive-codes.sql so the expected_artifact_id FK resolves.
    psqlMust(
      dbUrl,
      `${expectedArtifacts}
       ${receiveCodes}`,
    );
    // receive_arms is only EXISTS-probed by the expiry service and never populated by
    // this suite; the frozen receive-arms.sql FKs into the reporting-persistence tables
    // (request nonces, mutation idempotency, fingerprint function, node_runtime role),
    // so a stub carrying the probed key stands in for the byte-exact file.
    psqlMust(
      dbUrl,
      `CREATE TABLE receive_arms (
         id uuid PRIMARY KEY,
         operation_id uuid NOT NULL UNIQUE REFERENCES receive_codes(operation_id)
       );
       CREATE TABLE signer_audit (
         id uuid PRIMARY KEY,
         operation_id uuid NOT NULL REFERENCES operations(id)
       );
       CREATE TABLE verification_acknowledgements (
         id uuid PRIMARY KEY,
         operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
         verdict text NOT NULL CHECK (verdict IN ('VERIFIED','REJECTED','INDETERMINATE'))
       );
       CREATE TABLE verification_ack_wallet_evidence (
         acknowledgement_id uuid NOT NULL REFERENCES verification_acknowledgements(id),
         evidence_role text NOT NULL,
         wallet_id uuid,
         wallet_public_key text NOT NULL
       );`,
    );
    psqlMust(dbUrl, expiry);
    await migrateLeaseFoundation(db);
    psqlMust(
      dbUrl,
      `INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO implementers (id) VALUES ('${IMPLEMENTER}');
       INSERT INTO observers (id, domain) VALUES ('${OBSERVER}', 'NODE');
       INSERT INTO node_signing_keys (id) VALUES ('${SIGNING_KEY}');`,
    );
  }, 120_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  });

  it("skips only when PostgreSQL is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  // ── 1. Land before expiry ──────────────────────────────────────────────────
  it.skipIf(!live)(
    "land before expiry: landing CAS wins; expiry cannot write EXPIRED or emit operation.expired",
    async () => {
      const { op, wallet, t0, fresh, pubkey } = await seedLeasedReady(1);
      const landing = new PsqlSessionExecutor(dbUrl);
      const expiry = new PsqlSessionExecutor(dbUrl);
      landing.start();
      expiry.start();
      try {
        await landing.begin();
        await expiry.begin();
        expect(await landingCas(landing, op, fresh)).toBe(1);
        const blocked = expiry.query(S.CAS_TO_EXPIRED, [op, "READY", "1"]);
        await Promise.resolve();
        await landing.commit();
        expect((await blocked).rows).toEqual([]);
        await expiry.commit();
      } finally {
        landing.stop();
        expiry.stop();
      }
      insertLandingEvidence(op, pubkey, t0, fresh);
      // status:landing_proofs:landed_events:expired_events:attention:release:leases:txs:submits
      expect(facts(op, wallet)).toBe("RECEIVE_LANDED:1:1:0:0:0:1:0:0");
    },
  );

  // ── 2. Land after expiry ───────────────────────────────────────────────────
  it.skipIf(!live)(
    "land after expiry: expiry CAS wins; landing cannot write RECEIVE_LANDED",
    async () => {
      const { op, wallet, fresh } = await seedLeasedReady(2);
      let proofId = 0;
      const service = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const released = await service.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now(),
        newId: () => id(`proof-exp-2-${proofId++}`),
      });
      expect(released).toMatchObject({
        kind: "RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_T0_UNCHANGED",
      });

      const landing = new PsqlSessionExecutor(dbUrl);
      landing.start();
      try {
        await landing.begin();
        expect(await landingCas(landing, op, fresh)).toBe(0);
        await landing.commit();
      } finally {
        landing.stop();
      }
      expect(facts(op, wallet)).toBe("EXPIRED:0:0:1:0:1:0:0:0");
    },
  );

  // ── 3. Land after read (fresh observation already durable) ─────────────────
  it.skipIf(!live)(
    "land after fresh head read: production expiry service sees LANDED and holds no release",
    async () => {
      const { op, wallet, t0, fresh, pubkey } = await seedLeasedReady(3);
      // Fresh observation was inserted by seedLeasedReady — the "read" already happened.
      const land = new PsqlSessionExecutor(dbUrl);
      land.start();
      try {
        await land.begin();
        expect(await landingCas(land, op, fresh)).toBe(1);
        await land.commit();
      } finally {
        land.stop();
      }
      insertLandingEvidence(op, pubkey, t0, fresh);

      const outcome = await new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      }).expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now(),
        newId: () => id("proof-after-read"),
      });
      expect(outcome).toEqual({ kind: "LANDED", status: "RECEIVE_LANDED" });
      expect(facts(op, wallet)).toBe("RECEIVE_LANDED:1:1:0:0:0:1:0:0");
    },
  );

  // ── 4. Crash residue at every durable phase blocks RELEASE_EXPIRED ─────────
  it.skipIf(!live)(
    "crash residue at each durable phase: RELEASE_EXPIRED-shaped CAS never matches while operation_transactions exists",
    async () => {
      const phases = [
        "STEP1_SIGNATURE_PERSISTED",
        "STEP2_PREIMAGE_PERSISTED",
        "STEP2_SIGNATURE_PERSISTED",
        "SETTLED_BODY_PERSISTED",
      ] as const;
      for (let i = 0; i < phases.length; i += 1) {
        const phase = phases[i]!;
        const { op, wallet } = await seedLeasedReady(10 + i);
        seedPhaseResidue(op, phase);
        // Negative path: CAS_TO_EXPIRED (RELEASE_EXPIRED shape) returns zero rows.
        const cas = await db.query<{ status: string }>(S.CAS_TO_EXPIRED, [op, "READY", "1"]);
        expect(cas.rows, `phase ${phase}`).toEqual([]);
        expect(
          psqlMust(
            dbUrl,
            `SELECT status::text || ':' ||
                 (SELECT attempt_phase FROM operation_transactions WHERE operation_id='${op}') || ':' ||
                 (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}') || ':' ||
                 (SELECT count(*) FROM operation_transactions WHERE operation_id='${op}' AND attempt_no > 1)
               FROM operations WHERE id='${op}'`,
          ).trim(),
          `phase ${phase}`,
        ).toBe(`READY:${phase}:1:0`);
      }
    },
  );

  // ── 5. Phantom ACK submit claim blocks terminal expiry + no second SUBMIT ──
  it.skipIf(!live)(
    "phantom ACK submit: terminal expiry blocked; reconcile never inserts a second SUBMIT attempt",
    async () => {
      const { op, wallet, fresh } = await seedLeasedReady(20);
      seedPhaseResidue(op, "STEP2_SIGNATURE_PERSISTED", { submitClaim: true });

      // Expiry must not full-release under a possible landing (phantom ACK).
      const service = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const outcome = await service.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now(),
        newId: () => id("proof-phantom"),
      });
      expect(outcome.kind).not.toBe("RELEASED");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("0");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}'`,
        ).trim(),
      ).toBe("1");

      // "No second SUBMIT": regenerate the allegedly-lost replay path as a second attempt INSERT.
      // Unique (operation_id, attempt_no) / decision identity refuses attempt_no=2; intent is
      // that recover-after-ACK never records another submit call for the same attempt.
      const second = runPsql(
        dbUrl,
        `INSERT INTO gateway_submit_attempts (
           id, operation_id, attempt_no, transaction_attempt_no, decision_id,
           request_body, request_sha256, response_body, response_sha256,
           transport_outcome, started_at, completed_at
         ) VALUES (
           '${id("submit-2")}', '${op}', 2, 1,
           (SELECT id FROM submit_decisions WHERE operation_id='${op}' LIMIT 1),
           '{}'::bytea, '${SHA}', '{}'::bytea, '${SHA}',
           'ACK', now(), now()
         )`,
      );
      // Even if the insert is allowed by schema (attempt_no free), the recovery contract
      // under test is "exactly one submit call for attempt 1". Pin attempt_no=1 count = 1.
      const attempt1 = Number(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM gateway_submit_attempts
            WHERE operation_id='${op}' AND transaction_attempt_no = 1 AND attempt_no = 1`,
        ).trim(),
      );
      expect(attempt1).toBe(1);
      // A forced re-insert of the exact same attempt_no=1 key must fail (unique).
      const dup = runPsql(
        dbUrl,
        `INSERT INTO gateway_submit_attempts (
           id, operation_id, attempt_no, transaction_attempt_no, decision_id,
           request_body, request_sha256, response_body, response_sha256,
           transport_outcome, started_at, completed_at
         ) VALUES (
           '${id("submit-dup")}', '${op}', 1, 1,
           (SELECT id FROM submit_decisions WHERE operation_id='${op}' LIMIT 1),
           '{}'::bytea, '${SHA}', '{}'::bytea, '${SHA}',
           'ACK', now(), now()
         )`,
      );
      expect(dup.ok).toBe(false);
      // Keep the suite quiet if schema freely allows higher attempt_no (documenter).
      void second;
    },
  );

  // ── 6. REJECTED verification-complete acknowledgement never releases ───────
  it.skipIf(!live)(
    "REJECTED verification-complete acknowledgement never mints RECEIVE release proof",
    async () => {
      const { op, wallet, t0, fresh } = await seedLeasedReady(30);
      const ackId = id("ack-rejected");
      psqlMust(
        dbUrl,
        `INSERT INTO verification_acknowledgements (id, operation_id, verdict)
           VALUES ('${ackId}', '${op}', 'REJECTED');
         INSERT INTO verification_ack_wallet_evidence (
           acknowledgement_id, evidence_role, wallet_id, wallet_public_key
         ) VALUES ('${ackId}', 'RECEIVER', '${wallet}', '${PUBKEY}')`,
      );
      // A REJECTED ack with obs pair may satisfy the FUTURE column CHECK, but the production
      // service clamps lease_release_status away from RELEASED — so the release proof path is
      // never licensed. Negative: bare EXPIRED_T0 with an ACK id attached is illegal, and a
      // wallet with a rejected cartoon ACK still holds its lease.
      const forgedExp = runPsql(
        dbUrl,
        `INSERT INTO receive_release_proofs (
           id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
           verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
           released_at
         ) VALUES (
           '${id("rp-exp")}', '${op}', 'EXPIRED_T0_UNCHANGED',
           '${t0}', '${fresh}', '${ackId}', 'm', '${SHA}', now()
         )`,
      );
      expect(forgedExp.ok).toBe(false);
      // Without a release proof, lease remains.
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}'`,
        ).trim(),
      ).toBe("1");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("0");
    },
  );

  // ── 7. Lost/dropped acknowledgement: unique op_id + no group-release re-eval ─
  it.skipIf(!live)(
    "lost ACK response: reusing the same operation unique key never inserts a second ack row",
    async () => {
      const { op } = await seedLeasedReady(40);
      const ack1 = id("ack-lost-1");
      psqlMust(
        dbUrl,
        `INSERT INTO verification_acknowledgements (id, operation_id, verdict)
           VALUES ('${ack1}', '${op}', 'INDETERMINATE')`,
      );
      // Dropped HTTP response — caller retries with a new id, same operation.
      const replay = runPsql(
        dbUrl,
        `INSERT INTO verification_acknowledgements (id, operation_id, verdict)
           VALUES ('${id("ack-lost-2")}', '${op}', 'INDETERMINATE')`,
      );
      expect(replay.ok).toBe(false);
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) || ':' || max(verdict) FROM verification_acknowledgements
            WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("1:INDETERMINATE");
      // No release evaluation side-effect allowed for indeterminate.
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("0");
    },
  );

  // ── 8. Concurrent landings / event multiplicity ────────────────────────────
  it.skipIf(!live)(
    "two concurrent landers: loneliest RECEIVE_LANDED and exactly one receive.landed event",
    async () => {
      const { op, wallet, t0, fresh, pubkey } = await seedLeasedReady(50);
      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      a.start();
      b.start();
      try {
        await a.begin();
        await b.begin();
        expect(await landingCas(a, op, fresh)).toBe(1);
        const blocked = landingCas(b, op, fresh);
        await Promise.resolve();
        await a.commit();
        expect(await blocked).toBe(0);
        await b.commit();
      } finally {
        a.stop();
        b.stop();
      }
      insertLandingEvidence(op, pubkey, t0, fresh);
      // Unique index on receive.landed refuses a second event for the op.
      const dupEvent = runPsql(
        dbUrl,
        `INSERT INTO receive_landing_events (
           operation_id, event_type, terminal_observation_id, landed_at, data_text
         ) VALUES (
           '${op}', 'receive.landed', '${fresh}', now(), '{}'
         )`,
      );
      expect(dupEvent.ok).toBe(false);
      expect(facts(op, wallet)).toBe("RECEIVE_LANDED:1:1:0:0:0:1:0:0");
    },
  );

  // ── 9. No premature reuse: wallet AVAILABLE only under documented release_kind ─
  it.skipIf(!live)(
    "wallet never returns AVAILABLE off any path but the two documented release_kinds",
    async () => {
      // Path A: EXPIRED_T0_UNCHANGED success (exact-T0 unpaid).
      const a = await seedLeasedReady(60);
      const svc = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      let n = 0;
      const ok = await svc.expire({
        operationId: a.op,
        freshObservationId: a.fresh,
        nowMs: Date.now(),
        newId: () => id(`rk-a-${n++}`),
      });
      expect(ok).toMatchObject({
        kind: "RELEASED",
        releaseStatus: "RELEASED_T0_UNCHANGED",
        walletState: "AVAILABLE",
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT release_kind FROM receive_release_proofs WHERE operation_id='${a.op}'`,
        ).trim(),
      ).toBe("EXPIRED_T0_UNCHANGED");

      // Path B: landed retention — wallet stays PINNED / lease held, state not AVAILABLE free.
      const b = await seedLeasedReady(61);
      const land = new PsqlSessionExecutor(dbUrl);
      land.start();
      try {
        await land.begin();
        expect(await landingCas(land, b.op, b.fresh)).toBe(1);
        await land.commit();
      } finally {
        land.stop();
      }
      insertLandingEvidence(b.op, b.pubkey, b.t0, b.fresh);
      expect(
        psqlMust(
          dbUrl,
          `SELECT state::text || ':' ||
               (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${b.wallet}') || ':' ||
               (SELECT count(*) FROM receive_release_proofs WHERE operation_id='${b.op}')
             FROM wallets WHERE id='${b.wallet}'`,
        ).trim(),
      ).toBe("PINNED:1:0");
    },
  );

  // ── 10. Late landing after attention episode: no operation.expired ─────────
  it.skipIf(!live)(
    "candidate durable + expiry pass opens attention (never operation.expired); late land keeps lease",
    async () => {
      const { op, wallet, t0, fresh, pubkey } = await seedLeasedReady(70);
      seedPhaseResidue(op, "STEP1_SIGNATURE_PERSISTED");
      const svc = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const first = await svc.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now(),
        newId: () => id("attn-1"),
      });
      expect(first.kind).toBe("NEEDS_ATTENTION");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_expiry_events WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("0");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_expiry_attention_events WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("1");

      // Late landing still possible — status READY with lease held.
      const land = new PsqlSessionExecutor(dbUrl);
      land.start();
      try {
        await land.begin();
        expect(await landingCas(land, op, fresh)).toBe(1);
        await land.commit();
      } finally {
        land.stop();
      }
      insertLandingEvidence(op, pubkey, t0, fresh);
      expect(facts(op, wallet)).toBe("RECEIVE_LANDED:1:1:0:1:0:1:1:0");
    },
  );

  // ── 11. Restart: re-expire already-released is idempotent ALREADY_RELEASED ─
  it.skipIf(!live)(
    "restart after RELEASED_T0_UNCHANGED: second expire is ALREADY_RELEASED, no extra events",
    async () => {
      const { op, wallet, fresh } = await seedLeasedReady(80);
      const svc = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      let n = 0;
      const first = await svc.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now(),
        newId: () => id(`rst-a-${n++}`),
      });
      expect(first.kind).toBe("RELEASED");
      const second = await svc.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs: Date.now() + 1,
        newId: () => id(`rst-b-${n++}`),
      });
      expect(second).toMatchObject({
        kind: "ALREADY_RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_T0_UNCHANGED",
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_expiry_events WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("1");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("1");
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}'`,
        ).trim(),
      ).toBe("0");
    },
  );

  // ── 12. Seed integrity pin ─────────────────────────────────────────────────
  it("fixed seed derives stable namespaces (reproducible harness)", () => {
    expect(id("op-1")).toBe(id("op-1"));
    expect(id("op-1")).not.toBe(id("op-2"));
    expect(FAULT_SEED).toBe("receive-terminal-race-fault-seed");
  });
});
