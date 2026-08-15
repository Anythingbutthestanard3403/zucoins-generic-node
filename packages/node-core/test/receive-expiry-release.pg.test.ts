// real-PostgreSQL expiry/landing CAS and durable evidence gates.
// Separate psql sessions overlap transactions so both landing-first and expiry-first
// orderings are decided by PostgreSQL row locks, not an in-memory model.
// Governing: operation flows; operations recovery.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fc from "fast-check";

import {
  acquireLeases,
  createLeaseGroup,
  migrateLeaseFoundation,
} from "../src/leases/index.js";
import {
  RECEIVE_EXPIRY_RELEASE_STATEMENTS as S,
  SqlReceiveExpiryReleaseService,
  loadExpiredReceiveCandidates,
} from "../src/receive/expiry-release.js";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  psqlMust,
  runPsql,
  withDatabase,
  withTx,
} from "./psql-harness.js";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;
const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = resolve(HERE, "../src/schema");

const NODE = "30000000-0000-4000-8000-000000000001";
const IMPLEMENTER = "30000000-0000-4000-8000-000000000002";
const WALLET = "30000000-0000-4000-8000-000000000003";
const T0 = "30000000-0000-4000-8000-000000000004";
const HEAD = "30000000-0000-4000-8000-000000000005";
const OWNER = "30000000-0000-4000-8000-000000000006";
const OBSERVER = "30000000-0000-4000-8000-000000000007";
const SHA = "a".repeat(64);
const PUBKEY = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;
const SIGNING_KEY = "30000000-0000-4000-8000-000000000008";

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

function tableBlock(sql: string, table: string): string {
  const match = new RegExp(`^CREATE TABLE ${table} \\([\\s\\S]*?^\\);$`, "m").exec(
    sql,
  );
  if (match?.[0] === undefined) {
    throw new Error(`CREATE TABLE ${table} block not found`);
  }
  return match[0];
}

function operationId(n: number): string {
  return `31000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
}

function seedReady(op: string): void {
  psqlMust(
    dbUrl,
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, row_version, amount_zkz,
       receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
       request_sha256, expiry_unix_time_secs, t0_observation_id
     ) VALUES (
       '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
       '${WALLET}', 'HOLD', '${op}', 'release-anchor-${op.slice(-4)}',
       'release-idem-${op}', '${SHA}', '1', '${T0}'
     )`,
  );
}

async function landingUpdate(
  session: PsqlSessionExecutor,
  op: string,
): Promise<number> {
  const result = await session.query<{ status: string }>(
    `UPDATE operations
        SET status = 'RECEIVE_LANDED', row_version = row_version + 1,
            terminal_observation_id = $2::uuid, terminal_at = now(), updated_at = now()
      WHERE id = $1::uuid AND status = 'READY' AND row_version = 1
      RETURNING status::text AS status`,
    [op, HEAD],
  );
  return result.rows.length;
}

async function expiryUpdate(
  session: PsqlSessionExecutor,
  op: string,
): Promise<number> {
  const result = await session.query<{ status: string }>(S.CAS_TO_EXPIRED, [
    op,
    "READY",
    "1",
  ]);
  return result.rows.length;
}

function statusOf(op: string): string {
  return psqlMust(
    dbUrl,
    `SELECT status::text || ':' || row_version::text FROM operations WHERE id='${op}'`,
  ).trim();
}

async function seedServiceReady(n: number): Promise<{
  op: string;
  wallet: string;
  fresh: string;
}> {
  const op = operationId(100 + n);
  const wallet = operationId(200 + n);
  const t0 = operationId(300 + n);
  const fresh = operationId(400 + n);
  const recovery = operationId(500 + n);
  const artifact = operationId(950 + n);
  const pubkey = `${"Q".repeat(41)}${n.toString(36).padStart(2, "0")}=`;
  const nowMs = Date.now();
  psqlMust(
    dbUrl,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
       VALUES ('${wallet}', '${NODE}', '${pubkey}', 'node_generated', 'AVAILABLE');
     INSERT INTO wallet_recovery_verifications (
       id, wallet_id, method, export_sha256, public_key, audit_event_id,
       verified_at, verifier_identity
     ) VALUES (
       '${recovery}', '${wallet}', 'AUDITED_EXPORT', '${SHA}', '${pubkey}',
       '${recovery}', now(), 'release-race'
     );
     UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id='${recovery}'
       WHERE id='${wallet}';
     INSERT INTO operations (
       id, node_id, implementer_id, kind, status, row_version, amount_zkz,
       receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
       request_sha256, expiry_unix_time_secs, t0_observation_id
     ) VALUES (
       '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
       '${wallet}', 'HOLD', '${op}', 'release-race-${n}',
       'release-race-idem-${n}', '${SHA}', '1', '${t0}'
     );
     INSERT INTO operation_wallets (
       operation_id, wallet_id, operation_role, t0_observation_id
     ) VALUES ('${op}', '${wallet}', 'RECEIVER', '${t0}');
     INSERT INTO gateway_observations (
       id, observer_id, wallet_id, wallet_public_key, s_signature, p_signature,
       b_amount, parse_result, relationship, observed_at
     ) VALUES
       ('${t0}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
        'VERIFIED_HEAD', 'FIRST', to_timestamp(0)),
       ('${fresh}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
        'VERIFIED_HEAD', 'DUPLICATE', to_timestamp(${nowMs - 1_000} / 1000.0));
     INSERT INTO operation_expected_artifacts (
       id, operation_id, purpose, canonical_version, signing_key_id,
       preimage_text, preimage_sha256, signature
     ) VALUES (
       '${artifact}', '${op}', 'zp-receive-expected-v1', 1, '${SIGNING_KEY}',
       '{}', '${SHA}', '${SIG}'
     );
     INSERT INTO receive_codes (
       operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
       discriminator, anchor, expiry_unix_time_secs, transfer_code_text,
       transfer_code_sha256, code_status, ready_at
     ) VALUES (
       '${op}', '${wallet}', '${t0}', '${artifact}', '${op}',
       'release-race-code-${n}', '1', 'release-race-code-${n}', '${SHA}',
       'AWAITING_ARM', now()
     );`,
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
  return { op, wallet, fresh };
}

describe("receive expiry/release PostgreSQL drills", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is missing",
        );
      }
      return;
    }

    dbName = `release_${Date.now().toString(36)}_${Math.random()
      .toString(36)
      .slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);

    const base = readFileSync(resolve(SCHEMA, "base-enums-domains.sql"), "utf8");
    const operations = readFileSync(resolve(SCHEMA, "operations.sql"), "utf8");
    const transaction = readFileSync(
      resolve(SCHEMA, "transaction-material.sql"),
      "utf8",
    );
    const submit = readFileSync(resolve(SCHEMA, "submit-attempts.sql"), "utf8");
    const landing = readFileSync(
      resolve(SCHEMA, "receive-external-landing.sql"),
      "utf8",
    );
    const receiveCodes = readFileSync(
      resolve(SCHEMA, "receive-codes.sql"),
      "utf8",
    );
    const expectedArtifacts = readFileSync(
      resolve(SCHEMA, "expected-artifacts.sql"),
      "utf8",
    );
    const expiry = readFileSync(
      resolve(SCHEMA, "receive-expiry-release.sql"),
      "utf8",
    );

    psqlMust(dbUrl, base);
    psqlMust(
      dbUrl,
      `CREATE TABLE nodes (id uuid PRIMARY KEY);
       CREATE TABLE implementers (id uuid PRIMARY KEY);`,
    );
    psqlMust(
      dbUrl,
      readFileSync(resolve(SCHEMA, "custody-eligibility.sql"), "utf8"),
    );
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
    // ZTR-1274 r2: expire SQL fixtures must load full observation-stores.sql
    // (wallet_observation_cursors). Do not JOIN the cursor as freshness evidence.
    psqlMust(
      dbUrl,
      readFileSync(resolve(SCHEMA, "observation-stores.sql"), "utf8"),
    );
    // operation_expected_artifacts and receive_codes are frozen slices; use the
    // byte-exact file contents rather than inline stubs. expected-artifacts.sql owns
    // operation_expected_artifacts and must apply before receive-codes.sql so the
    // receive_codes.expected_artifact_id FK resolves.
    psqlMust(
      dbUrl,
      `${expectedArtifacts}
       ${receiveCodes}`,
    );
    // receive_arms is only EXISTS-probed by the expiry service and never populated
    // by this suite; the frozen receive-arms.sql FKs into the reporting-persistence
    // tables (request nonces, mutation idempotency, fingerprint function,
    // node_runtime role), so a stub carrying the probed key stands in for the
    // byte-exact file.
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
       );
       `,
    );
    psqlMust(dbUrl, expiry);
    psqlMust(dbUrl, verificationModeFixtureSql());
    await migrateLeaseFoundation(db);
    psqlMust(
      dbUrl,
      `INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO implementers (id) VALUES ('${IMPLEMENTER}');
       INSERT INTO observers (id, domain) VALUES ('${OBSERVER}', 'NODE');
       INSERT INTO node_signing_keys (id) VALUES ('${SIGNING_KEY}');
       INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ('${WALLET}', '${NODE}', '${PUBKEY}', 'node_generated', 'AVAILABLE');
       INSERT INTO wallet_recovery_verifications (
         id, wallet_id, method, export_sha256, public_key, audit_event_id,
         verified_at, verifier_identity
       ) VALUES (
         '${operationId(90)}', '${WALLET}', 'AUDITED_EXPORT', '${SHA}', '${PUBKEY}',
         '${operationId(90)}', now(), 'release-pg'
       );
       UPDATE wallets
          SET recovery_verified_at = now(),
              recovery_verification_id = '${operationId(90)}'
        WHERE id = '${WALLET}';`,
    );
  }, 120_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    runPsql(
      TEST_DATABASE_URL,
      `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`,
    );
  });

  it("skips only when PostgreSQL is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  it.skipIf(!live)(
    "landing commits first: expiry CAS loses and cannot write EXPIRED",
    async () => {
      const op = operationId(1);
      seedReady(op);
      const landing = new PsqlSessionExecutor(dbUrl);
      const expiry = new PsqlSessionExecutor(dbUrl);
      landing.start();
      expiry.start();
      try {
        await landing.begin();
        await expiry.begin();
        expect(await landingUpdate(landing, op)).toBe(1);
        const blockedExpiry = expiryUpdate(expiry, op);
        await Promise.resolve();
        await landing.commit();
        expect(await blockedExpiry).toBe(0);
        await expiry.commit();
      } finally {
        landing.stop();
        expiry.stop();
      }
      expect(statusOf(op)).toBe("RECEIVE_LANDED:2");
    },
  );

  it.skipIf(!live)(
    "expiry commits first: landing CAS loses and cannot write RECEIVE_LANDED",
    async () => {
      const op = operationId(2);
      seedReady(op);
      const expiry = new PsqlSessionExecutor(dbUrl);
      const landing = new PsqlSessionExecutor(dbUrl);
      expiry.start();
      landing.start();
      try {
        await expiry.begin();
        await landing.begin();
        expect(await expiryUpdate(expiry, op)).toBe(1);
        const blockedLanding = landingUpdate(landing, op);
        await Promise.resolve();
        await expiry.commit();
        expect(await blockedLanding).toBe(0);
        await landing.commit();
      } finally {
        expiry.stop();
        landing.stop();
      }
      expect(statusOf(op)).toBe("EXPIRED:2");
    },
  );

  it.skipIf(!live)(
    "property: production expiry service and landing SQL have exactly one winner in both orderings",
    async () => {
      let caseNo = 0;
      await fc.assert(
        fc.asyncProperty(
          fc.shuffledSubarray([true, false], { minLength: 2, maxLength: 2 }),
          async (orderings) => {
          for (const landingFirst of orderings) {
          caseNo += 1;
          const { op, wallet, fresh } = await seedServiceReady(caseNo);
          let proofId = 600 + caseNo * 3;
          const service = new SqlReceiveExpiryReleaseService({
            withTransaction: (fn) => withTx(dbUrl, fn),
          });
          const expire = () =>
            service.expire({
              operationId: op,
              freshObservationId: fresh,
              nowMs: Date.now(),
              newId: () => operationId(proofId++),
            });

          if (landingFirst) {
            const landing = new PsqlSessionExecutor(dbUrl);
            landing.start();
            try {
              await landing.begin();
              expect(await landingUpdate(landing, op)).toBe(1);
              const blockedExpiry = expire();
              await Promise.resolve();
              await landing.commit();
              expect(await blockedExpiry).toEqual({
                kind: "LANDED",
                status: "RECEIVE_LANDED",
              });
            } finally {
              landing.stop();
            }
          } else {
            expect(await expire()).toMatchObject({
              kind: "RELEASED",
              status: "EXPIRED",
              releaseStatus: "RELEASED_T0_UNCHANGED",
            });
            const landing = new PsqlSessionExecutor(dbUrl);
            landing.start();
            try {
              await landing.begin();
              expect(await landingUpdate(landing, op)).toBe(0);
              await landing.commit();
            } finally {
              landing.stop();
            }
          }

          const facts = psqlMust(
            dbUrl,
            `SELECT status::text || ':' ||
              (SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}') || ':' ||
              (SELECT count(*) FROM receive_expiry_events WHERE operation_id='${op}') || ':' ||
              (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}')
             FROM operations WHERE id='${op}'`,
          ).trim();
          expect(facts).toBe(
            landingFirst ? "RECEIVE_LANDED:0:0:1" : "EXPIRED:1:1:0",
          );
          }
        }),
        { numRuns: 4 },
      );
    },
    120_000,
  );

  it.skipIf(!live)(
    "candidate, phantom ACK submit, and landing proof each block terminal expiry",
    async () => {
      const candidateOp = operationId(3);
      const submitOp = operationId(4);
      const proofOp = operationId(5);
      for (const op of [candidateOp, submitOp, proofOp]) seedReady(op);

      psqlMust(
        dbUrl,
        `INSERT INTO operation_transactions (
           operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
           step_1_signature, formed_at
         ) VALUES
           ('${candidateOp}', 1, 'STEP1_SIGNATURE_PERSISTED', '{}', '${SHA}',
            '${"A".repeat(86)}==', now()),
           ('${submitOp}', 1, 'STEP1_SIGNATURE_PERSISTED', '{}', '${SHA}',
            '${"A".repeat(86)}==', now());
         INSERT INTO submit_decisions (
           id, operation_id, transaction_attempt_no, decision, decided_at, details
         ) VALUES (
           '${operationId(40)}', '${submitOp}', 1, 'INITIAL_SINGLE_SHOT', now(), '{}'
         );
         INSERT INTO gateway_submit_attempts (
           id, operation_id, attempt_no, transaction_attempt_no, decision_id,
           request_body, request_sha256, response_body, response_sha256,
           transport_outcome, started_at, completed_at
         ) VALUES (
           '${operationId(41)}', '${submitOp}', 1, 1, '${operationId(40)}',
           '{}'::bytea, '${SHA}', '{"status":true}'::bytea, '${SHA}',
           'ACK', now(), now()
         );
         BEGIN;
         INSERT INTO receive_landing_proofs (
           operation_id, attempt_phase, public_execution_phase, path_role,
           wallet_public_key, t0_observation_id, fresh_head_observation_id,
           terminal_observation_id, expected_completed_transaction_sha256,
           fresh_head_completed_transaction_sha256, verdict, body_count, path_depth,
           path_manifest_text, path_manifest_sha256, landed_at,
           verification_material_available_until
         ) VALUES (
           '${proofOp}', 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED', 'RECEIVER',
           '${PUBKEY}', '${T0}', '${HEAD}', '${HEAD}', '${SHA}', '${SHA}',
           'LANDED_EXACT', 1, 0, '{}', '${SHA}', now(), now() + interval '30 days'
         );
         INSERT INTO receive_landing_path_bodies (
           operation_id, path_index, source_kind, completed_transaction_text,
           completed_transaction_sha256, completed_transaction_octets, wallet_role,
           s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256,
           step_1_signature, step_2_signature
         ) VALUES (
           '${proofOp}', 0, 'EXPECTED_OPERATION', '{}', '${SHA}', 2, 'receiver',
           '${"B".repeat(86)}==', '', '1', '{}', '${SHA}',
           '${"C".repeat(86)}==', '${"D".repeat(86)}=='
         );
         COMMIT`,
      );

      for (const op of [candidateOp, submitOp, proofOp]) {
        const result = await db.query<{ status: string }>(S.CAS_TO_EXPIRED, [
          op,
          "READY",
          "1",
        ]);
        expect(result.rows).toEqual([]);
        expect(statusOf(op)).toBe("READY:1");
      }
    },
  );

  it.skipIf(!live)(
    "expiry and attention ledgers dedupe and reject mutation",
    async () => {
      const op = operationId(6);
      seedReady(op);
      psqlMust(
        dbUrl,
        `INSERT INTO receive_expiry_events (operation_id, event_type, data_text)
           VALUES ('${op}', 'operation.expired', '{}')
           ON CONFLICT (operation_id) DO NOTHING;
         INSERT INTO receive_expiry_events (operation_id, event_type, data_text)
           VALUES ('${op}', 'operation.expired', '{}')
           ON CONFLICT (operation_id) DO NOTHING;`,
      );
      const attentionParams = [
        op,
        "T0_RELEASE_MISMATCH",
        '{"failed_predicates":["FRESH_VERIFIED_T0_EXACT"]}',
        "operation.needs_attention",
        '["FRESH_VERIFIED_T0_EXACT"]',
      ] as const;
      expect(
        (
          await db.query<{ event_id: string }>(
            S.OPEN_ATTENTION_EPISODE,
            attentionParams,
          )
        ).rows,
      ).toHaveLength(1);
      expect(
        (
          await db.query<{ event_id: string }>(
            S.OPEN_ATTENTION_EPISODE,
            attentionParams,
          )
        ).rows,
      ).toEqual([]);

      expect(
        psqlMust(
          dbUrl,
          `SELECT
             (SELECT count(*) FROM receive_expiry_events WHERE operation_id='${op}') ||
             ':' ||
             (SELECT count(*) FROM receive_expiry_attention_events WHERE operation_id='${op}')`,
        ).trim(),
      ).toBe("1:1");
      expect(
        psqlMust(
          dbUrl,
          `SELECT concat_ws(
                    ':',
                    (data_text::jsonb)->>'current_state',
                    (data_text::jsonb)->>'attention_reason',
                    (data_text::jsonb)->>'attention_episode',
                    (data_text::jsonb)->>'operator_action_required'
                  )
             FROM receive_expiry_attention_events
            WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("READY:T0_RELEASE_MISMATCH:1:true");
      expect(
        runPsql(
          dbUrl,
          `UPDATE receive_expiry_events SET data_text='{"mutated":true}'
            WHERE operation_id='${op}'`,
        ).ok,
      ).toBe(false);
      expect(
        runPsql(
          dbUrl,
          `DELETE FROM receive_expiry_attention_events WHERE operation_id='${op}'`,
      ).ok,
      ).toBe(false);
    },
  );

  it.skipIf(!live)(
    "service success co-commits release proof, exact-tuple lease delete, and PINNED→AVAILABLE",
    async () => {
      const op = operationId(7);
      const fresh = operationId(70);
      const nowMs = Date.now();
      seedReady(op);
      psqlMust(
        dbUrl,
        `INSERT INTO operation_wallets (
           operation_id, wallet_id, operation_role, t0_observation_id
         ) VALUES ('${op}', '${WALLET}', 'RECEIVER', '${T0}');
         INSERT INTO gateway_observations (
           id, observer_id, wallet_id, wallet_public_key,
           s_signature, p_signature, b_amount,
           parse_result, relationship, observed_at
         ) VALUES
           ('${T0}', '${OBSERVER}', '${WALLET}', '${PUBKEY}', 'S0', 'P0', '10',
            'VERIFIED_HEAD', 'FIRST', to_timestamp(0)),
           ('${fresh}', '${OBSERVER}', '${WALLET}', '${PUBKEY}', 'S0', 'P0', '10',
            'VERIFIED_HEAD', 'DUPLICATE', to_timestamp(${nowMs - 1_000} / 1000.0));
         INSERT INTO operation_expected_artifacts (
           id, operation_id, purpose, canonical_version, signing_key_id,
           preimage_text, preimage_sha256, signature
         ) VALUES (
           '${operationId(71)}', '${op}', 'zp-receive-expected-v1', 1, '${SIGNING_KEY}',
           '{}', '${SHA}', '${SIG}'
         );
         INSERT INTO receive_codes (
           operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
           discriminator, anchor, expiry_unix_time_secs, transfer_code_text,
           transfer_code_sha256, code_status, ready_at
         ) VALUES (
           '${op}', '${WALLET}', '${T0}', '${operationId(71)}', '${op}',
           'release-cocommit-code', '1', 'release-cocommit-code', '${SHA}',
           'AWAITING_ARM', now()
         );`,
      );

      await withTx(dbUrl, async (tx) => {
        const leaseGroupId = await createLeaseGroup(tx, op);
        await acquireLeases(tx, {
          wallets: [{ walletId: WALLET, leaseRole: "RECEIVE_WINDOW" }],
          leaseGroupId,
          rootOperationId: op,
          operationId: op,
          ownerInstanceId: OWNER,
        });
      });
      const material = await db.query<{
        code_exists: boolean;
        code_status: string;
        artifact_exists: boolean;
      }>(S.LOAD_MATERIAL_FACTS, [op]);
      expect(material.rows[0]).toMatchObject({
        code_exists: true,
        code_status: "AWAITING_ARM",
        artifact_exists: true,
      });

      let nextId = 80;
      const service = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const result = await service.expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs,
        newId: () => operationId(nextId++),
      });

      expect(result).toMatchObject({
        kind: "RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_T0_UNCHANGED",
        walletId: WALLET,
        walletState: "AVAILABLE",
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT
             (SELECT status::text || ':' || receive_release_status FROM operations WHERE id='${op}')
             || ':' ||
             (SELECT code_status FROM receive_codes WHERE operation_id='${op}')
             || ':' ||
             (SELECT state::text FROM wallets WHERE id='${WALLET}')
             || ':' ||
             (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${WALLET}')
             || ':' ||
             (SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}')
             || ':' ||
             (SELECT count(*) FROM lease_release_proofs WHERE operation_id='${op}')`,
        ).trim(),
      ).toBe(
        "EXPIRED:RELEASED_T0_UNCHANGED:EXPIRED:AVAILABLE:0:1:1",
      );
      expect(
        runPsql(
          dbUrl,
          `UPDATE receive_release_proofs SET proof_manifest_text='mutated'
            WHERE operation_id='${op}'`,
        ).ok,
      ).toBe(false);
    },
  );

  it.skipIf(!live)(
    "expire(t0Id) and planted-cursor-only park (ZTR-1274 r2)",
    async () => {
      const { op, wallet } = await seedServiceReady(90);
      const t0 = operationId(390); // seedServiceReady(90) T0 = operationId(300+90)
      const nowMs = Date.now();
      psqlMust(
        dbUrl,
        `INSERT INTO wallet_observation_cursors (
           observer_id, wallet_id, wallet_public_key, last_recorded_observation_id,
           last_raw_response_sha256, last_semantic_fingerprint, last_seen_at,
           consecutive_repeat_count, next_wallet_seq
         ) VALUES (
           '${OBSERVER}', '${wallet}',
           (SELECT public_key FROM wallets WHERE id='${wallet}'),
           '${t0}', '${SHA}', '${SHA}', to_timestamp(${nowMs} / 1000.0),
           1, 2
         );`,
      );
      let proofId = 790;
      const service = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const t0Only = await service.expire({
        operationId: op,
        freshObservationId: t0,
        nowMs,
        newId: () => operationId(proofId++),
      });
      expect(t0Only.kind).toBe("NEEDS_ATTENTION");
      if (t0Only.kind === "NEEDS_ATTENTION") {
        expect(t0Only.failedPredicates).toContain("FRESH_VERIFIED_T0_EXACT");
      }
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs WHERE operation_id='${op}'`,
        ).trim(),
      ).toBe("0");
    },
  );

  it.skipIf(!live)(
    "pre-code with T0 still releases via EXPIRED_T0_UNCHANGED",
    async () => {
      // Seed CREATED + T0 + lease with zero formation evidence. Do not DELETE
      // operation_expected_artifacts: the insert-only trigger raises
      // EXPECTED_ARTIFACT_INSERT_ONLY (same regime move-baseline freezes).
      const op = operationId(20);
      const wallet = operationId(220);
      const t0 = operationId(320);
      const fresh = operationId(420);
      const recovery = operationId(520);
      const pubkey = `${"Q".repeat(41)}p0=`;
      const nowMs = Date.now();
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ('${wallet}', '${NODE}', '${pubkey}', 'node_generated', 'AVAILABLE');
         INSERT INTO wallet_recovery_verifications (
           id, wallet_id, method, export_sha256, public_key, audit_event_id,
           verified_at, verifier_identity
         ) VALUES (
           '${recovery}', '${wallet}', 'AUDITED_EXPORT', '${SHA}', '${pubkey}',
           '${recovery}', now(), 'release-precode'
         );
         UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id='${recovery}'
           WHERE id='${wallet}';
         INSERT INTO operations (
           id, node_id, implementer_id, kind, status, row_version, amount_zkz,
           after_landing, discriminator, anchor, idempotency_key, request_sha256,
           created_at
         ) VALUES (
           '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED', 1, '1',
           'HOLD', '${op}', 'release-precode', 'release-precode-idem-${op}', '${SHA}',
           to_timestamp(0)
         );
         -- CREATED forbids operations.t0/expiry/receiver_wallet_id (operations_check1).
         -- T0 binding lives on operation_wallets only for this pre-code path.
         INSERT INTO operation_wallets (
           operation_id, wallet_id, operation_role, t0_observation_id
         ) VALUES ('${op}', '${wallet}', 'RECEIVER', '${t0}');
         INSERT INTO gateway_observations (
           id, observer_id, wallet_id, wallet_public_key, s_signature, p_signature,
           b_amount, parse_result, relationship, observed_at
         ) VALUES
           ('${t0}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
            'VERIFIED_HEAD', 'FIRST', to_timestamp(0)),
           ('${fresh}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
            'VERIFIED_HEAD', 'DUPLICATE', to_timestamp(${nowMs - 1_000} / 1000.0));`,
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

      let nextId = 680;
      const result = await new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      }).expire({
        operationId: op,
        freshObservationId: fresh,
        nowMs,
        queueMaxWaitMs: 30_000,
        newId: () => operationId(nextId++),
      });

      expect(result).toMatchObject({
        kind: "RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_T0_UNCHANGED",
        walletId: wallet,
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM receive_release_proofs
            WHERE operation_id='${op}' AND release_kind='EXPIRED_T0_UNCHANGED'`,
        ).trim(),
      ).toBe("1");
    },
  );

  it.skipIf(!live)(
    "operations recovery EXPIRED_PROVEN_NOT_STARTED: lease + null T0 + zero formation evidence",
    async () => {
      const op = operationId(21);
      const wallet = operationId(221);
      const recovery = operationId(521);
      const pubkey = `${"R".repeat(41)}p1=`;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ('${wallet}', '${NODE}', '${pubkey}', 'node_generated', 'AVAILABLE');
         INSERT INTO wallet_recovery_verifications (
           id, wallet_id, method, export_sha256, public_key, audit_event_id,
           verified_at, verifier_identity
         ) VALUES (
           '${recovery}', '${wallet}', 'AUDITED_EXPORT', '${SHA}', '${pubkey}',
           '${recovery}', now(), 'release-pns'
         );
         UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id='${recovery}'
           WHERE id='${wallet}';
         INSERT INTO operations (
           id, node_id, implementer_id, kind, status, row_version, amount_zkz,
           after_landing, discriminator, anchor, idempotency_key, request_sha256,
           created_at
         ) VALUES (
           '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED', 1, '1',
           'HOLD', '${op}', 'release-pns', 'release-pns-idem-${op}', '${SHA}',
           to_timestamp(0)
         );
         INSERT INTO operation_wallets (
           operation_id, wallet_id, operation_role, t0_observation_id
         ) VALUES ('${op}', '${wallet}', 'RECEIVER', NULL);`,
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

      let nextId = 710;
      const service = new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      });
      const result = await service.expire({
        operationId: op,
        freshObservationId: null,
        nowMs: 60_000,
        queueMaxWaitMs: 30_000,
        newId: () => operationId(nextId++),
      });

      expect(result).toMatchObject({
        kind: "RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_PROVEN_NOT_STARTED",
        walletId: wallet,
        walletState: "AVAILABLE",
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT
             (SELECT receive_release_status FROM operations WHERE id='${op}') || ':' ||
             (SELECT release_kind FROM receive_release_proofs WHERE operation_id='${op}') || ':' ||
             (SELECT count(*) FROM receive_release_proofs
               WHERE operation_id='${op}'
                 AND t0_observation_id IS NULL AND fresh_observation_id IS NULL
                 AND verification_acknowledgement_id IS NULL) || ':' ||
             (SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${wallet}') || ':' ||
             (SELECT state::text FROM wallets WHERE id='${wallet}')`,
        ).trim(),
      ).toBe(
        "RELEASED_PROVEN_NOT_STARTED:EXPIRED_PROVEN_NOT_STARTED:1:0:AVAILABLE",
      );

      const restart = await service.expire({
        operationId: op,
        freshObservationId: null,
        nowMs: 60_001,
        queueMaxWaitMs: 30_000,
        newId: () => operationId(nextId++),
      });
      expect(restart).toEqual({
        kind: "ALREADY_RELEASED",
        status: "EXPIRED",
        releaseStatus: "RELEASED_PROVEN_NOT_STARTED",
      });
    },
  );

  it.skipIf(!live)(
    "CHECK rejects invalid kind/ack combos and orphan observation UUIDs",
    async () => {
      const op = operationId(22);
      seedReady(op);
      const orphan = operationId(999);
      const goodProof = operationId(801);
      expect(
        runPsql(
          dbUrl,
          `INSERT INTO receive_release_proofs (
             id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
             verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
             released_at
           ) VALUES (
             '${goodProof}', '${op}', 'EXPIRED_T0_UNCHANGED', NULL, NULL, NULL,
             'm', '${SHA}', now()
           )`,
        ).ok,
      ).toBe(false); // needs both obs ids
      expect(
        runPsql(
          dbUrl,
          `INSERT INTO receive_release_proofs (
             id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
             verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
             released_at
           ) VALUES (
             '${operationId(802)}', '${op}', 'EXPIRED_PROVEN_NOT_STARTED',
             '${T0}', NULL, NULL, 'm', '${SHA}', now()
           )`,
        ).ok,
      ).toBe(false); // proven-not-started forbids observation ids
      expect(
        runPsql(
          dbUrl,
          `INSERT INTO receive_release_proofs (
             id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
             verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
             released_at
           ) VALUES (
             '${operationId(803)}', '${op}', 'VERIFICATION_COMPLETE',
             '${T0}', '${HEAD}', NULL, 'm', '${SHA}', now()
           )`,
        ).ok,
      ).toBe(false); // ack required
      // Orphan observation UUID rejected by FK (gateway_observations must exist for T0 kinds).
      psqlMust(
        dbUrl,
        `INSERT INTO gateway_observations (
           id, observer_id, wallet_id, wallet_public_key, s_signature, p_signature,
           b_amount, parse_result, relationship, observed_at
         ) VALUES (
           '${T0}', '${OBSERVER}', '${WALLET}', '${PUBKEY}', 'S0', 'P0', '0',
           'VERIFIED_HEAD', 'FIRST', now()
         ) ON CONFLICT DO NOTHING;`,
      );
      expect(
        runPsql(
          dbUrl,
          `INSERT INTO receive_release_proofs (
             id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
             verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
             released_at
           ) VALUES (
             '${operationId(804)}', '${op}', 'EXPIRED_T0_UNCHANGED',
             '${T0}', '${orphan}', NULL, 'm', '${SHA}', now()
           )`,
        ).ok,
      ).toBe(false);
      // Valid proven-not-started insert on a second op (status free for proof only).
      const opB = operationId(23);
      seedReady(opB);
      expect(
        runPsql(
          dbUrl,
          `INSERT INTO receive_release_proofs (
             id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
             verification_acknowledgement_id, proof_manifest_text, proof_manifest_sha256,
             released_at
           ) VALUES (
             '${operationId(805)}', '${opB}', 'EXPIRED_PROVEN_NOT_STARTED',
             NULL, NULL, NULL, 'manifest', '${SHA}', now()
           )`,
        ).ok,
      ).toBe(true);
    },
  );

  it.skipIf(!live)(
    "any formation evidence blocks PROVEN_NOT_STARTED (opens attention)",
    async () => {
      const op = operationId(24);
      const wallet = operationId(224);
      const recovery = operationId(524);
      const pubkey = `${"S".repeat(41)}p2=`;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ('${wallet}', '${NODE}', '${pubkey}', 'node_generated', 'AVAILABLE');
         INSERT INTO wallet_recovery_verifications (
           id, wallet_id, method, export_sha256, public_key, audit_event_id,
           verified_at, verifier_identity
         ) VALUES (
           '${recovery}', '${wallet}', 'AUDITED_EXPORT', '${SHA}', '${pubkey}',
           '${recovery}', now(), 'release-block'
         );
         UPDATE wallets SET recovery_verified_at=now(), recovery_verification_id='${recovery}'
           WHERE id='${wallet}';
         INSERT INTO operations (
           id, node_id, implementer_id, kind, status, row_version, amount_zkz,
           after_landing, discriminator, anchor, idempotency_key, request_sha256,
           created_at
         ) VALUES (
           '${op}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED', 1, '1',
           'HOLD', '${op}', 'release-block', 'release-block-idem-${op}', '${SHA}',
           to_timestamp(0)
         );
         INSERT INTO operation_wallets (
           operation_id, wallet_id, operation_role, t0_observation_id
         ) VALUES ('${op}', '${wallet}', 'RECEIVER', NULL);
         INSERT INTO gateway_observations (
           id, observer_id, wallet_id, wallet_public_key, s_signature, p_signature,
           b_amount, parse_result, relationship, observed_at
         ) VALUES (
           '${operationId(992)}', '${OBSERVER}', '${wallet}', '${pubkey}', 'S0', 'P0', '10',
           'VERIFIED_HEAD', 'FIRST', to_timestamp(0)
         );
         INSERT INTO operation_expected_artifacts (
           id, operation_id, purpose, canonical_version, signing_key_id,
           preimage_text, preimage_sha256, signature
         ) VALUES (
           '${operationId(991)}', '${op}', 'zp-receive-expected-v1', 1, '${SIGNING_KEY}',
           '{}', '${SHA}', '${SIG}'
         );
         INSERT INTO receive_codes (
           operation_id, receiver_wallet_id, t0_observation_id, expected_artifact_id,
           discriminator, anchor, expiry_unix_time_secs, transfer_code_text,
           transfer_code_sha256, code_status, ready_at
         ) VALUES (
           '${op}', '${wallet}', '${operationId(992)}', '${operationId(991)}', '${op}',
           'release-block-code', '1', 'release-block-code', '${SHA}',
           'AWAITING_ARM', now()
         );`,
      );
      // READY requires receiver triple; keep CREATED with code/artifact rows (and the
      // FK payload the frozen receive_codes columns demand) as failed-formation shape.
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

      const result = await new SqlReceiveExpiryReleaseService({
        withTransaction: (fn) => withTx(dbUrl, fn),
      }).expire({
        operationId: op,
        freshObservationId: null,
        nowMs: 60_000,
        queueMaxWaitMs: 30_000,
        newId: () => operationId(900),
      });

      expect(result.kind).toBe("NEEDS_ATTENTION");
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
    },
  );

  // regression: loadExpiredReceiveCandidates compared text < numeric
  // and failed every tick. This test drives the scan against real PG with both
  // the expiry_unix_time_secs (text) and NULL-expiry / old-created_at paths.
  it.skipIf(!live)(
    "loadExpiredReceiveCandidates scans text expiry_unix_time_secs without type error",
    async () => {
      const expiredOp = operationId(30);
      const futureOp = operationId(31);
      const nullExpiryOldOp = operationId(32);
      const alreadyReleasedOp = operationId(33);
      // ZTR-1249 ghost: walletless EXPIRED + terminal_at set must not re-enter the scan.
      const terminalizedExpiredOp = operationId(34);
      // ZTR-1277: attention-parked assigned receive must not re-enter the automatic sweep.
      const parkedAssignedOp = operationId(35);

      // The frozen operations CHECKs pin the shapes: a RECEIVE_EXTERNAL row with
      // expiry_unix_time_secs set must carry the READY receiver triple, and
      // CREATED/EXPIRED rows must carry a NULL expiry (the NULL-expiry candidates
      // exercise the old-created_at scan path instead).
      psqlMust(
        dbUrl,
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, row_version, amount_zkz,
           receiver_wallet_id, after_landing, discriminator, anchor, idempotency_key,
           request_sha256, expiry_unix_time_secs, t0_observation_id, created_at, terminal_at,
           attention_required, attention_reason
         ) VALUES
           ('${expiredOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
            '${WALLET}', 'HOLD', '${expiredOp}', 'expiryscan-expired', 'expiryscan-idem-30', '${SHA}',
            '1000000000', '${T0}', to_timestamp(0), NULL, false, NULL),
           ('${futureOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
            '${WALLET}', 'HOLD', '${futureOp}', 'expiryscan-future', 'expiryscan-idem-31', '${SHA}',
            '9999999999', '${T0}', now(), NULL, false, NULL),
           ('${nullExpiryOldOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'CREATED', 1, '1',
            NULL, 'HOLD', '${nullExpiryOldOp}', 'expiryscan-null-expiry', 'expiryscan-idem-32', '${SHA}',
            NULL, NULL, to_timestamp(0), NULL, false, NULL),
           ('${alreadyReleasedOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'EXPIRED', 1, '1',
            NULL, 'HOLD', '${alreadyReleasedOp}', 'expiryscan-released', 'expiryscan-idem-33', '${SHA}',
            NULL, NULL, to_timestamp(0), NULL, false, NULL),
           ('${terminalizedExpiredOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'EXPIRED', 1, '1',
            NULL, 'HOLD', '${terminalizedExpiredOp}', 'expiryscan-terminalized', 'expiryscan-idem-34', '${SHA}',
            NULL, NULL, to_timestamp(0), now(), false, NULL),
           ('${parkedAssignedOp}', '${NODE}', '${IMPLEMENTER}', 'RECEIVE_EXTERNAL', 'READY', 1, '1',
            '${WALLET}', 'HOLD', '${parkedAssignedOp}', 'expiryscan-parked', 'expiryscan-idem-35', '${SHA}',
            '1000000000', '${T0}', to_timestamp(0), NULL, true, 'T0_RELEASE_MISMATCH');
         UPDATE operations SET receive_release_status = 'RELEASED_T0_UNCHANGED'
          WHERE id = '${alreadyReleasedOp}';`,
      );

      const candidates = await loadExpiredReceiveCandidates(db);
      const ids = candidates.map((c) => c.operationId).sort();

      // Expired text expiry and NULL-expiry old created_at should appear;
      // future expiry, already-released, terminalized walletless EXPIRED, and
      // attention-parked assigned receives must not.
      expect(ids).toContain(expiredOp);
      expect(ids).toContain(nullExpiryOldOp);
      expect(ids).not.toContain(futureOp);
      expect(ids).not.toContain(alreadyReleasedOp);
      expect(ids).not.toContain(terminalizedExpiredOp);
      expect(ids).not.toContain(parkedAssignedOp);

      // Verify the expired-op row carries the text expiry value through.
      const expiredCandidate = candidates.find((c) => c.operationId === expiredOp);
      expect(expiredCandidate).toBeDefined();
      expect(expiredCandidate!.expiryUnixTimeSecs).toBe("1000000000");
      expect(expiredCandidate!.status).toBe("READY");

      // After operator attention retraction the parked row rejoins the sweep
      // (status may still be NEEDS_ATTENTION-path READY; flag is the gate).
      psqlMust(
        dbUrl,
        `UPDATE operations
            SET attention_required = false,
                attention_reason = NULL,
                attention_detail = NULL
          WHERE id = '${parkedAssignedOp}'`,
      );
      const afterRetract = await loadExpiredReceiveCandidates(db);
      expect(afterRetract.map((c) => c.operationId)).toContain(parkedAssignedOp);
    },
  );
});
