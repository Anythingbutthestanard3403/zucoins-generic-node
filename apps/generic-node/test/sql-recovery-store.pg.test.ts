// SQL-backed RecoveryActionStore + RecoveryInspectionStore against a real
// PostgreSQL server. The one-in-flight-per-wallet and byte-exact signing rules, 4.
//
// The store this suite drives owns the recovery-action money path: nonce single-use,
// TOTP global-burn, operation CAS via row_version, append-only audit_log, and the
// fail-closed effect-kind gate. None of that is provable against a fake SqlQueryFn — a
// prior review round found a CREATE TABLE spliced inside an unrelated ALTER TABLE, jsonb
// double-parsing, a self-referencing FK ordered before its own insert, and a CAS branch
// that ignored rowCount. This suite runs every SQL statement the store issues against the
// frozen contract DDL so that class of defect fails a test rather than a production commit.
//
// A real pg.Pool is required, not the psql-CLI-per-statement idiom some sibling .pg.test.ts
// files use: createSqlRecoveryActionStore/createSqlRecoveryInspectionStore call
// pool.connect() themselves to run genuine multi-statement transactions (BEGIN … COMMIT /
// ROLLBACK), which a bare psql-per-statement harness cannot exercise.

import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  sha256HexUtf8,
  classifyRecovery,
  migrateLeaseFoundation,
  createLeaseGroup,
  acquireLeases,
  type RecoveryActionEffect,
  type RecoveryActionCommitInput,
  type RecoveryClassification,
  type ReadFreshHead,
} from "@zucoins/node-core";

import { registerPgRequiredGuard } from "../../../packages/node-core/test/pg-required-guard.ts";
import {
  createSqlRecoveryActionStore,
  createSqlRecoveryInspectionStore,
} from "../src/operations/sql-recovery-store.js";

const SCHEMA = "recovery_store_recovery_actions";
const databaseUrl = process.env.TEST_DATABASE_URL;
const PG_TEST_TIMEOUT_MS = 180_000;

const NODE_ID = "00000000-0000-4000-8000-000000009610";
const IMPLEMENTER_ID = "00000000-0000-4000-8000-000000009611";

// ── schema composition (verbatim frozen contract text, dependency order) ───────────────────

const schemaDir = fileURLToPath(new URL("../../../packages/node-core/src/schema/", import.meta.url));
const PACK_SLICES = [
  "base-enums-domains",
  // The receive-arms' composite FKs target reporting_request_nonces /
  // reporting_mutation_idempotency, which only reporting-persistence.sql defines. It
  // also owns the real nodes/implementers tables, so it must precede any slice (e.g.
  // custody-eligibility) that references nodes(id).
  "reporting-persistence",
  "custody-eligibility",
  "signer-support",
  "operations",
  "transaction-material",
  "submit-attempts",
  "audit-log",
  "move-baseline-binding",
  // Fact-gatherer queries hit receive_codes and gateway_observations directly
  // (SQL_RECEIVE_CODE_STATUS / SQL_OBSERVATION_BY_ID) — observation-ledger creates
  // gateway_observations, which receive-codes' t0_observation_id FK requires.
  "observation-ledger",
  // LOAD_OBSERVATIONS probes observation_anomalies (EXISTS subquery).
  "observation-anomaly-indexes",
  "receive-codes",
  // SqlReceiveExpiryReleaseService's LOAD_MATERIAL_FACTS query reads receive_arms.
  "receive-arms",
  "receive-external-landing",
  // RELEASE_EXPIRED_RECEIVE writes operations.receive_release_status.
  "receive-expiry-release",
] as const;

function packSql(): string {
  const declared = new Set<string>();
  const declarations: string[] = [];
  // CREATE EXTENSION must land before any hoisted declaration below — reporting_logical_fingerprint
  // calls pgcrypto's digest(), and LANGUAGE SQL functions resolve names at CREATE FUNCTION time, not
  // call time. Extracting it first keeps it ahead of the declarations block once everything is joined.
  const extensions: string[] = [];
  const tables = PACK_SLICES.map((slice) => readFileSync(`${schemaDir}${slice}.sql`, "utf8"))
    .join("\n")
    .replace(/CREATE EXTENSION[\s\S]*?;\n/g, (statement) => {
      extensions.push(statement);
      return "";
    })
    .replace(/^CREATE (DOMAIN|TYPE) ([a-z0-9_]+)[\s\S]*?;\n/gm, (statement, _kind: string, name: string) => {
      if (!declared.has(name)) {
        declared.add(name);
        declarations.push(statement);
      }
      return "";
    })
    // reporting_reject_immutable_change is re-declared verbatim in every slice that owns an
    // append-only table so each applies standalone; combining slices
    // (audit-log + observation-ledger here) de-duplicates it the same way as the DOMAIN/TYPE
    // pass above. Scoped to this one name (rather than a generic CREATE FUNCTION sweep)
    // because other slices' functions close with `$$ LANGUAGE plpgsql;` instead of `$$;` —
    // a generic non-greedy match would run past those onto the first unrelated `$$;`.
    .replace(/CREATE FUNCTION reporting_reject_immutable_change\(\)[\s\S]*?\$\$;\n/g, (statement) => {
      const name = "reporting_reject_immutable_change";
      if (!declared.has(name)) {
        declared.add(name);
        declarations.push(statement);
      }
      return "";
    })
    // reporting_logical_fingerprint is declared identically in base-enums-domains.sql and
    // reporting-persistence.sql (both slices are pulled in here); dedupe the same way.
    .replace(/CREATE FUNCTION reporting_logical_fingerprint\([\s\S]*?\$\$;\n/g, (statement) => {
      const name = "reporting_logical_fingerprint";
      if (!declared.has(name)) {
        declared.add(name);
        declarations.push(statement);
      }
      return "";
    });
  // reporting_advance_lifecycle_head is SECURITY DEFINER SET search_path = pg_catalog, public
  // (reporting-persistence.sql) — Postgres's default check_function_bodies=on resolves that
  // pinned search_path at CREATE FUNCTION time, so it can't see this suite's isolated ${SCHEMA}
  // and fails the whole apply. Disabling the check is safe here: it only skips upfront body
  // validation, never runtime behavior, and this suite never calls that function.
  return (
    `SET check_function_bodies = off;\n` +
    `${extensions.join("\n")}\n${declarations.join("\n")}\n${tables}`
  );
}

// CREATE EXTENSION IF NOT EXISTS is not safe under concurrent DDL: two test files
// racing against the same shared TEST_DATABASE_URL can both pass the existence check
// before either commits, and the loser hits a duplicate-key error on pg_extension's
// name index. packSql() re-declares pgcrypto (via base-enums-domains.sql) every run, so
// retry once past that specific, benign collision rather than failing the whole suite.
async function applySchema(target: Pool, sql: string): Promise<void> {
  try {
    await target.query(sql);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("pg_extension_name_index")) throw error;
    await target.query(sql);
  }
}

const FK_TARGET_STUBS = ["operation_approvals"]
  .map((t) => `CREATE TABLE ${t} (id uuid PRIMARY KEY);`)
  .join("\n");

// SqlReceiveExpiryReleaseService → readGroupReleaseFacts LEFT JOINs
// verification_acknowledgements and may probe verification_ack_wallet_evidence. The full
// verification-proofs.sql slice pulls operation_landing_proofs + reporting-mutation FKs we
// do not need here — empty stubs satisfy the joins for an unacknowledged single-leg group.
const ACK_TABLE_STUBS = `
CREATE TABLE IF NOT EXISTS verification_acknowledgements (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  verdict text
);
CREATE TABLE IF NOT EXISTS verification_ack_wallet_evidence (
  acknowledgement_id uuid NOT NULL REFERENCES verification_acknowledgements(id),
  evidence_role text NOT NULL,
  wallet_id uuid,
  wallet_public_key text NOT NULL
);
`;

// ── fixture helpers ─────────────────────────────────────────────────────────────────────────

let pool: Pool;
let reachable = false;
let actionStore: ReturnType<typeof createSqlRecoveryActionStore>;
let inspectionStore: ReturnType<typeof createSqlRecoveryInspectionStore>;
let nodeObserverId: string;

// RELEASE_EXPIRED_RECEIVE's pre-BEGIN confirm-read seam. Tests that need a real
// fresh-head match register the expected observation id by wallet pubkey; any other wallet
// (e.g. the payment-evidence refusal test) gets a harmless placeholder id — its early-exit
// branch in SqlReceiveExpiryReleaseService never reaches the freshExact check.
const freshHeadByPubkey = new Map<string, string>();
const readFreshHead: ReadFreshHead = async (walletPubkey) => ({
  observationId: freshHeadByPubkey.get(walletPubkey) ?? randomUUID(),
  envelope: undefined as never,
});

function pubkey(): string {
  const hex = randomUUID().replace(/-/g, "");
  return `${hex.padEnd(43, "a")}=`;
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

let timestepCounter = 1_700_000_000;
function nextTimestep(): number {
  return timestepCounter++;
}

function idemKey(prefix: string): string {
  return `${prefix}-${randomUUID()}`;
}

async function insertWallet(): Promise<string> {
  const walletId = randomUUID();
  await pool.query(
    `INSERT INTO wallets (id, node_id, public_key, key_origin)
     VALUES ($1::uuid, $2::uuid, $3, 'node_generated')`,
    [walletId, NODE_ID, pubkey()],
  );
  return walletId;
}

async function walletState(walletId: string): Promise<string> {
  const result = await pool.query(`SELECT state::text AS state FROM wallets WHERE id = $1::uuid`, [walletId]);
  return (result.rows[0] as { state: string }).state;
}

// the custody eligibility trigger requires recovery_verified_at/recovery_verification_id
// on any wallet taking a RECEIVE_WINDOW lease — a bare insertWallet() wallet fails that gate.
async function insertVerifiedWallet(): Promise<string> {
  const walletId = await insertWallet();
  const verificationId = randomUUID();
  await pool.query(
    `INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
     VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'audited-export-test')`,
    [verificationId, walletId, pubkey(), sha256(randomUUID()), randomUUID()],
  );
  await pool.query(
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid WHERE id = $1::uuid`,
    [walletId, verificationId],
  );
  return walletId;
}

// Real lease_groups/wallet_lease_memberships/wallet_active_leases rows for the
// release path — insertLease()'s bare wallet_active_leases row has no matching membership,
// which releaseLease's internal joins require.
async function seedReleasableLease(
  operationId: string,
  walletId: string,
): Promise<{ leaseGroupId: string; membershipId: string; leaseEpoch: bigint }> {
  const leaseGroupId = await createLeaseGroup(pool, operationId);
  const [acquired] = await acquireLeases(pool, {
    wallets: [{ walletId, leaseRole: "RECEIVE_WINDOW" }],
    leaseGroupId,
    rootOperationId: operationId,
    operationId,
    ownerInstanceId: randomUUID(),
  });
  return { leaseGroupId, membershipId: acquired!.membershipId, leaseEpoch: acquired!.leaseEpoch };
}

async function insertLease(
  walletId: string,
  operationId: string,
  role: "MOVE_SOURCE" | "SEND_SOURCE" = "MOVE_SOURCE",
): Promise<{ leaseGroupId: string; membershipId: string; leaseEpoch: bigint }> {
  const leaseGroupId = await createLeaseGroup(pool, operationId);
  const [acquired] = await acquireLeases(pool, {
    wallets: [{ walletId, leaseRole: role }],
    leaseGroupId,
    rootOperationId: operationId,
    operationId,
    ownerInstanceId: randomUUID(),
  });
  return { leaseGroupId, membershipId: acquired!.membershipId, leaseEpoch: acquired!.leaseEpoch };
}

async function seedMoveOperation(opts: {
  status: string;
  attentionReason?: string;
  sourceWalletId: string;
  destinationId: string;
}): Promise<string> {
  const operationId = randomUUID();
  // row_version, amount_zkz, idempotency_key and request_sha256 are all NOT NULL with no
  // default (bar row_version's DEFAULT 1) — the recovery path never mutates any of them, so
  // any domain-valid placeholder proves nothing about recovery and is fine here.
  await pool.query(
    `INSERT INTO operations
       (id, node_id, implementer_id, kind, status, attention_required, attention_reason,
        source_wallet_id, destination_id, amount_zkz, idempotency_key, request_sha256, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'MOVE_INTERNAL', $4, $5, $6, $7::uuid, $8::uuid,
             '0.01', $9, $10, now())`,
    [
      operationId,
      NODE_ID,
      IMPLEMENTER_ID,
      opts.status,
      opts.attentionReason !== undefined,
      opts.attentionReason ?? null,
      opts.sourceWalletId,
      opts.destinationId,
      randomUUID(),
      sha256(randomUUID()),
    ],
  );
  return operationId;
}

async function seedReceiveOperation(): Promise<string> {
  const operationId = randomUUID();
  await pool.query(
    `INSERT INTO operations
       (id, node_id, implementer_id, kind, status, attention_required,
        after_landing, discriminator, anchor, amount_zkz, idempotency_key, request_sha256, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED', false,
             'HOLD', $1::uuid, 'recovery-store-anchor', '0.01', $4, $5, now())`,
    [operationId, NODE_ID, IMPLEMENTER_ID, randomUUID(), sha256(randomUUID())],
  );
  return operationId;
}

// an armed RECEIVE_EXTERNAL (receiver assigned, code issued) with a RECEIVER_T0
// binding so classifyRecovery's PROVEN_NOT_STARTED gate (no formation boundary crossed) does
// not fire — the operations CHECK requires expiry_unix_time_secs/t0_observation_id
// NOT NULL together with receiver_wallet_id once past the walletless-CREATED arm.
async function seedArmedReceiveOperation(opts: {
  expiryUnixTimeSecs: number;
  receiverWalletId?: string;
}): Promise<string> {
  const operationId = randomUUID();
  const receiverWalletId = opts.receiverWalletId ?? (await insertWallet());
  await pool.query(
    `INSERT INTO operations
       (id, node_id, implementer_id, kind, status, attention_required,
        after_landing, discriminator, anchor, amount_zkz, idempotency_key, request_sha256,
        receiver_wallet_id, expiry_unix_time_secs, t0_observation_id, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY', false,
             'HOLD', $1::uuid, 'recovery-store-anchor', '0.01', $4, $5, $6::uuid, $7, $8::uuid, now())`,
    [operationId, NODE_ID, IMPLEMENTER_ID, randomUUID(), sha256(randomUUID()),
      receiverWalletId, String(opts.expiryUnixTimeSecs), randomUUID()],
  );
  await pool.query(
    `INSERT INTO operation_observation_bindings (operation_id, observation_id, evidence_role, wallet_public_key)
     VALUES ($1::uuid, $2::uuid, 'RECEIVER_T0', $3)`,
    [operationId, randomUUID(), pubkey()],
  );
  return operationId;
}


// Route A: durable T0 + fresh gateway_observations pair that satisfies
// SqlReceiveExpiryReleaseService's freshExact window (fresh observed after expiry+margin,
// within safety margin of now, same s/p/b as T0, relationship DUPLICATE, domain NODE).
async function seedMatchingT0AndFresh(opts: {
  walletId: string;
  publicKey: string;
  expiryUnixTimeSecs: number;
}): Promise<{ t0ObservationId: string; freshObservationId: string }> {
  const t0ObservationId = randomUUID();
  const freshObservationId = randomUUID();
  const endpointFp = sha256("fixture-endpoint");
  const raw = Buffer.from("fixture-obs");
  const rawSha = sha256("fixture-obs");
  const semantic = sha256(`sem-${opts.walletId}`);
  const sig = signature();
  const inner = `inner-${randomUUID()}`;
  const completed = `completed-${randomUUID()}`;
  const completedSha = sha256(completed);
  // T0 at epoch; fresh ~5s before now (must be >= expiry+margin and within 30s of now).
  const freshObservedAt = new Date(Date.now() - 5_000);
  await pool.query(
    `INSERT INTO gateway_observations (
       id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
       observed_at, http_status, raw_response_bytes, raw_response_sha256,
       parse_result, relationship, semantic_fingerprint, state_changed,
       wallet_role, s_signature, p_signature, b_amount,
       inner_preimage_text, step_1_signature, step_2_signature,
       completed_transaction_text, completed_transaction_sha256
     ) VALUES (
       $1::uuid, $2::uuid, $3, $4::uuid, $5, 1,
       to_timestamp(0), 200, $6::bytea, $7,
       'VERIFIED_HEAD', 'FIRST', $8, true,
       'receiver', $9, '', '0.01',
       $10, $11, $11, $12, $13
     )`,
    [
      t0ObservationId, nodeObserverId, endpointFp, opts.walletId, opts.publicKey,
      raw, rawSha, semantic, sig, inner, sig, completed, completedSha,
    ],
  );
  await pool.query(
    `INSERT INTO gateway_observations (
       id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
       observed_at, http_status, raw_response_bytes, raw_response_sha256,
       parse_result, relationship, semantic_fingerprint, state_changed,
       wallet_role, s_signature, p_signature, b_amount,
       inner_preimage_text, step_1_signature, step_2_signature,
       completed_transaction_text, completed_transaction_sha256
     ) VALUES (
       $1::uuid, $2::uuid, $3, $4::uuid, $5, 2,
       $6::timestamptz, 200, $7::bytea, $8,
       'VERIFIED_HEAD', 'DUPLICATE', $9, false,
       'receiver', $10, '', '0.01',
       $11, $12, $12, $13, $14
     )`,
    [
      freshObservationId, nodeObserverId, endpointFp, opts.walletId, opts.publicKey,
      freshObservedAt.toISOString(), raw, rawSha, semantic, sig, inner, sig, completed, completedSha,
    ],
  );
  return { t0ObservationId, freshObservationId };
}

async function walletPublicKey(walletId: string): Promise<string> {
  const result = await pool.query<{ public_key: string }>(
    `SELECT public_key FROM wallets WHERE id = $1::uuid`,
    [walletId],
  );
  return result.rows[0]!.public_key;
}

/** Full Route A fixture: verified wallet + matching T0/fresh obs + armed receive + lease. */
async function seedReleaseableExpiredReceive(): Promise<{
  walletId: string;
  publicKey: string;
  operationId: string;
  t0ObservationId: string;
  freshObservationId: string;
  leaseGroupId: string;
  membershipId: string;
  leaseEpoch: bigint;
  expiryUnixTimeSecs: number;
}> {
  // freshWithinWindow: freshObservedAt >= expiry+margin AND now-fresh <= margin(30s).
  // Expiry 2 minutes ago ⇒ expiry+margin is 90s ago; fresh is stamped ~5s ago inside
  // seedMatchingT0AndFresh so the window holds even if the test is slow to reach expire().
  const expiryUnixTimeSecs = Math.floor(Date.now() / 1000) - 120;
  const walletId = await insertVerifiedWallet();
  const publicKey = await walletPublicKey(walletId);
  const { t0ObservationId, freshObservationId } = await seedMatchingT0AndFresh({
    walletId, publicKey, expiryUnixTimeSecs,
  });
  freshHeadByPubkey.set(publicKey, freshObservationId);

  const operationId = randomUUID();
  await pool.query(
    `INSERT INTO operations
       (id, node_id, implementer_id, kind, status, attention_required,
        after_landing, discriminator, anchor, amount_zkz, idempotency_key, request_sha256,
        receiver_wallet_id, expiry_unix_time_secs, t0_observation_id, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'READY', false,
             'HOLD', $1::uuid, 'landing-anchor', '0.01', $4, $5, $6::uuid, $7, $8::uuid, now())`,
    [operationId, NODE_ID, IMPLEMENTER_ID, randomUUID(), sha256(randomUUID()),
      walletId, String(expiryUnixTimeSecs), t0ObservationId],
  );
  // Wallet identity for release comes from operation_wallets + lease, not the
  // nullable operations.receiver_wallet_id projection.
  await pool.query(
    `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role, t0_observation_id)
     VALUES ($1::uuid, $2::uuid, 'RECEIVER', $3::uuid)`,
    [operationId, walletId, t0ObservationId],
  );
  await pool.query(
    `INSERT INTO operation_observation_bindings (operation_id, observation_id, evidence_role, wallet_public_key)
     VALUES ($1::uuid, $2::uuid, 'RECEIVER_T0', $3)`,
    [operationId, t0ObservationId, publicKey],
  );
  // No receive_codes / artifacts / arms / signer — noFormationEvidence path with real T0
  // still releases via EXPIRED_T0_UNCHANGED when freshExact holds (pre-code+T0).
  const lease = await seedReleasableLease(operationId, walletId);
  return {
    walletId, publicKey, operationId, t0ObservationId, freshObservationId,
    ...lease, expiryUnixTimeSecs,
  };
}

function signature(): string {
  const hex = randomUUID().replace(/-/g, "").repeat(3).slice(0, 86);
  return `${hex}==`;
}

// Minimal LANDED_EXACT receive_landing_proofs + one-body receive_landing_path_bodies
// row, inserted in a single transaction — the path-completeness constraint trigger is
// DEFERRABLE INITIALLY DEFERRED and fires at COMMIT, so header and body must share a transaction.
async function seedLandedReceiveProof(operationId: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const bodyText = `body-${randomUUID()}`;
    const bodySha = sha256(bodyText);
    const manifestText = `manifest-${randomUUID()}`;
    const innerText = `inner-${randomUUID()}`;
    await client.query(
      `INSERT INTO receive_landing_proofs
         (operation_id, attempt_phase, public_execution_phase, path_role, wallet_public_key,
          t0_observation_id, fresh_head_observation_id, terminal_observation_id,
          expected_completed_transaction_sha256, fresh_head_completed_transaction_sha256,
          verdict, body_count, path_depth, path_manifest_text, path_manifest_sha256,
          landed_at, verification_material_available_until)
       VALUES ($1::uuid, 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED', 'RECEIVER', $2,
               $3::uuid, $4::uuid, $5::uuid, $6, $6,
               'LANDED_EXACT', 1, 0, $7, $8, now(), now() + interval '1 day')`,
      [operationId, pubkey(), randomUUID(), randomUUID(), randomUUID(), bodySha, manifestText, sha256(manifestText)],
    );
    await client.query(
      `INSERT INTO receive_landing_path_bodies
         (operation_id, path_index, source_kind, completed_transaction_text,
          completed_transaction_sha256, completed_transaction_octets, wallet_role,
          s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256,
          step_1_signature, step_2_signature)
       VALUES ($1::uuid, 0, 'EXPECTED_OPERATION', $2, $3, $4, 'receiver', $5, '', '0.01', $6, $7, $8, $9)`,
      [operationId, bodyText, bodySha, Buffer.byteLength(bodyText, "utf8"),
        signature(), innerText, sha256(innerText), signature(), signature()],
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function insertDestination(walletId: string): Promise<string> {
  const destinationId = randomUUID();
  await pool.query(
    `INSERT INTO destinations (id, node_id, wallet_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
    [destinationId, NODE_ID, walletId],
  );
  return destinationId;
}

function commitInput(opts: {
  operationId: string;
  effect: RecoveryActionEffect;
  expectedRowVersion: number;
  recoveryNonce: string;
  totpTimestep: number;
  idempotencyKey?: string;
  classification?: RecoveryClassification;
  priorStatus?: string;
  operatorNote?: string | null;
}): RecoveryActionCommitInput {
  return {
    operationId: opts.operationId,
    action: opts.effect.kind,
    expectedRowVersion: opts.expectedRowVersion,
    recoveryNonce: opts.recoveryNonce,
    proofId: null,
    operatorNote: opts.operatorNote ?? null,
    operatorId: "operator-recovery-store",
    totpTimestep: opts.totpTimestep,
    effect: opts.effect,
    classification: opts.classification ?? "INDETERMINATE",
    priorStatus: opts.priorStatus ?? "NEEDS_ATTENTION",
    idempotencyKey: opts.idempotencyKey ?? idemKey("recovery-store"),
  };
}

async function auditRowsFor(operationId: string): Promise<readonly { details_text: string; details_sha256: string }[]> {
  const result = await pool.query(
    `SELECT details_text, details_sha256 FROM audit_log WHERE operation_id = $1::uuid ORDER BY seq`,
    [operationId],
  );
  return result.rows as { details_text: string; details_sha256: string }[];
}

async function nonceStatus(nonce: string): Promise<string> {
  const result = await pool.query(`SELECT status::text AS status FROM recovery_nonces WHERE nonce = $1::uuid`, [nonce]);
  return (result.rows[0] as { status: string }).status;
}

/** Unknown future kind — store must fail closed before nonce/TOTP (never silent success). */
const UNKNOWN_EFFECT = { kind: "FORCE_LANDED" } as unknown as RecoveryActionEffect;

// ── suite ────────────────────────────────────────────────────────────────────────────────────

describe.skipIf(databaseUrl === undefined)("SQL recovery-action store against a live PostgreSQL", () => {
  beforeAll(async () => {
    const url = new URL(databaseUrl as string);
    pool = new Pool({
      host: url.hostname,
      port: Number(url.port || "5432"),
      user: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
      database: url.pathname.replace(/^\//, ""),
      options: `-c search_path=${SCHEMA},public`,
    });
    await pool.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await pool.query(`CREATE SCHEMA ${SCHEMA}`);
    await pool.query(`SET search_path TO ${SCHEMA}, public`);
    await pool.query(FK_TARGET_STUBS);
    await applySchema(pool, packSql());
    await pool.query(ACK_TABLE_STUBS);
    await migrateLeaseFoundation(pool);
    // nodes/implementers are now the real reporting-persistence.sql tables (not the
    // old bare id-only stubs), so their NOT NULL columns need placeholder values.
    await pool.query(
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1::uuid, 'test-node', $2)`,
      [NODE_ID, `${"A".repeat(43)}=`],
    );
    await pool.query(`INSERT INTO implementers (id, name) VALUES ($1::uuid, 'test-implementer')`, [
      IMPLEMENTER_ID,
    ]);
    // NODE observer required by LOAD_OBSERVATIONS (observer_domain = 'NODE').
    nodeObserverId = randomUUID();
    await pool.query(
      `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
       VALUES ($1::uuid, 'NODE', $2::uuid, $3, now())`,
      [nodeObserverId, NODE_ID, sha256("fixture-observer")],
    );
    // Route A confirm-read seam — success fixtures register the fresh observation id by pubkey.
    actionStore = createSqlRecoveryActionStore(pool, readFreshHead);
    inspectionStore = createSqlRecoveryInspectionStore(pool);
    reachable = true;
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    if (reachable) await pool.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await pool?.end().catch(() => undefined);
  }, PG_TEST_TIMEOUT_MS);

  beforeEach(async () => {
    await pool.query(`SET search_path TO ${SCHEMA}, public`);
    freshHeadByPubkey.clear();
  });

  it("rotates a recovery nonce: the prior ISSUED row is SUPERSEDED by the new row's id", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });

    const first = await inspectionStore.issueRecoveryNonce(operationId);
    const second = await inspectionStore.issueRecoveryNonce(operationId);

    expect(first.nonce).not.toBe(second.nonce);
    expect(await nonceStatus(first.nonce)).toBe("SUPERSEDED");
    expect(await nonceStatus(second.nonce)).toBe("ISSUED");
    const supersededBy = await pool.query(`SELECT superseded_by::text AS id FROM recovery_nonces WHERE nonce = $1::uuid`, [
      first.nonce,
    ]);
    const secondRowId = await pool.query(`SELECT id::text AS id FROM recovery_nonces WHERE nonce = $1::uuid`, [second.nonce]);
    expect((supersededBy.rows[0] as { id: string }).id).toBe((secondRowId.rows[0] as { id: string }).id);
  });

  it("fails closed for an unknown effect kind before touching the database", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({
      status: "NEEDS_ATTENTION",
      attentionReason: "test",
      sourceWalletId,
      destinationId,
    });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: UNKNOWN_EFFECT,
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
      }),
    );

    expect(result).toMatchObject({
      ok: false,
      reason: "predicate_failed",
      detail: "effect_not_implemented:FORCE_LANDED",
    });
    expect(await nonceStatus(nonce)).toBe("ISSUED");
    const burns = await pool.query(
      `SELECT count(*)::int AS n FROM totp_timestep_burns WHERE totp_timestep = $1`,
      [timestep],
    );
    expect((burns.rows[0] as { n: number }).n).toBe(0);
    expect(await auditRowsFor(operationId)).toHaveLength(0);
    const row = await pool.query(
      `SELECT row_version::int AS row_version FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect((row.rows[0] as { row_version: number }).row_version).toBe(1);
  });

  async function seedSendOperation(opts: {
    status: string;
    formationState: string;
    attentionReason?: string;
    sourceWalletId: string;
  }): Promise<string> {
    const operationId = randomUUID();
    // destination_address is a padded_base64url_pubkey domain (44 chars ending =).
    const dest = `${"B".repeat(43)}=`;
    await pool.query(
      `INSERT INTO operations
         (id, node_id, implementer_id, kind, status, attention_required, attention_reason,
          source_wallet_id, destination_address, amount_zkz, idempotency_key, request_sha256,
          formation_state, created_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'SEND_EXTERNAL', $4, $5, $6,
               $7::uuid, $8, '0.01', $9, $10, $11, now())`,
      [
        operationId,
        NODE_ID,
        IMPLEMENTER_ID,
        opts.status,
        opts.attentionReason !== undefined,
        opts.attentionReason ?? null,
        opts.sourceWalletId,
        dest,
        randomUUID(),
        sha256(randomUUID()),
        opts.formationState,
      ],
    );
    return operationId;
  }

  async function seedApprovalAndPartial(
    operationId: string,
    opts: { delivered?: boolean } = {},
  ): Promise<{ transferCodeText: string; transferCodeSha256: string }> {
    // FK_TARGET_STUBS creates operation_approvals (id uuid PRIMARY KEY) only.
    const approvalId = randomUUID();
    const transferCodeText = `tc-${operationId.slice(0, 8)}`;
    const transferCodeSha256 = sha256(transferCodeText);
    await pool.query(`INSERT INTO operation_approvals (id) VALUES ($1::uuid)`, [approvalId]);
    const step1 = `${"A".repeat(86)}==`;
    await pool.query(
      `INSERT INTO external_send_partials
         (operation_id, approval_id, inner_sha256, step_1_signature,
          transfer_code_text, transfer_code_sha256, persisted_at,
          first_delivered_at, redelivery_count)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, now(), $7, 0)`,
      [
        operationId,
        approvalId,
        sha256(randomUUID()),
        step1,
        transferCodeText,
        transferCodeSha256,
        opts.delivered ? new Date().toISOString() : null,
      ],
    );
    return { transferCodeText, transferCodeSha256 };
  }

  it("commits CONTINUE_EXTERNAL_WAIT: status AWAITING_REDEMPTION, attention cleared, lease kept", async () => {
    const sourceWalletId = await insertWallet();
    const operationId = await seedSendOperation({
      status: "NEEDS_ATTENTION",
      formationState: "PARTIAL_DELIVERED",
      attentionReason: "UNEXPECTED_HEAD_CHANGE",
      sourceWalletId,
    });
    await seedApprovalAndPartial(operationId, { delivered: true });
    await insertLease(sourceWalletId, operationId, "SEND_SOURCE");
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: {
          kind: "CONTINUE_EXTERNAL_WAIT",
          nextStatus: "AWAITING_REDEMPTION",
          clearAttention: true,
          keepLease: true,
        },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
      }),
    );

    expect(result).toMatchObject({ ok: true, status: "AWAITING_REDEMPTION" });
    const op = await pool.query(
      `SELECT status::text AS status, attention_required, attention_reason
         FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect(op.rows[0]).toMatchObject({
      status: "AWAITING_REDEMPTION",
      attention_required: false,
      attention_reason: null,
    });
    const lease = await pool.query(
      `SELECT count(*)::int AS n FROM wallet_active_leases WHERE operation_id = $1::uuid`,
      [operationId],
    );
    expect((lease.rows[0] as { n: number }).n).toBe(1);
  });

  it("commits REDELIVER_EXACT_PARTIAL: returns identical transfer code bytes and stamps counters", async () => {
    const sourceWalletId = await insertWallet();
    const operationId = await seedSendOperation({
      status: "AWAITING_REDEMPTION",
      formationState: "PARTIAL_DELIVERED",
      sourceWalletId,
    });
    const { transferCodeText, transferCodeSha256 } = await seedApprovalAndPartial(operationId, {
      delivered: true,
    });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: { kind: "REDELIVER_EXACT_PARTIAL" },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
      }),
    );

    expect(result).toMatchObject({
      ok: true,
      transferCodeText,
      transferCodeSha256,
    });
    const partial = await pool.query(
      `SELECT transfer_code_text, transfer_code_sha256, redelivery_count::int AS n
         FROM external_send_partials WHERE operation_id = $1::uuid`,
      [operationId],
    );
    expect(partial.rows[0]).toMatchObject({
      transfer_code_text: transferCodeText,
      transfer_code_sha256: transferCodeSha256,
      n: 1,
    });
  });

  it("commits CLOSE_NEVER_STARTED_EXTERNAL_SEND: APPROVED→REJECTED when formation negatives hold", async () => {
    const sourceWalletId = await insertWallet();
    const operationId = await seedSendOperation({
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceWalletId,
    });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: {
          kind: "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
          nextStatus: "REJECTED",
          releaseSourceLease: true,
        },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
      }),
    );

    expect(result).toMatchObject({ ok: true, status: "REJECTED" });
    const op = await pool.query(
      `SELECT status::text AS status FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect((op.rows[0] as { status: string }).status).toBe("REJECTED");
  });

  it("commits REBUILD_INTERNAL_MOVE: NEEDS_ATTENTION→CREATED, attention cleared, no submit", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({
      status: "NEEDS_ATTENTION",
      attentionReason: "test",
      sourceWalletId,
      destinationId,
    });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();
    const proofId = randomUUID();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: {
          kind: "REBUILD_INTERNAL_MOVE",
          nextStatus: "CREATED",
          clearAttention: true,
          decision: "SAFE_TO_REBUILD_AFTER_POSITIVE_NON_LANDING",
          proofId,
          archiveOldAttemptUnchanged: true,
          createNextAttemptNumber: true,
          submitOldAttempt: false,
        },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
        classification: "PROVEN_NOT_LANDED",
      }),
    );

    expect(result).toMatchObject({ ok: true, status: "CREATED" });
    const op = await pool.query(
      `SELECT status::text AS status, attention_required, attention_reason
         FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect(op.rows[0]).toMatchObject({
      status: "CREATED",
      attention_required: false,
      attention_reason: null,
    });
  });

  it("commits CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED: NEEDS_ATTENTION→REJECTED", async () => {
    const sourceWalletId = await insertWallet();
    const operationId = await seedSendOperation({
      status: "NEEDS_ATTENTION",
      formationState: "PARTIAL_DELIVERED",
      attentionReason: "UNEXPECTED_HEAD_CHANGE",
      sourceWalletId,
    });
    await seedApprovalAndPartial(operationId, { delivered: true });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: {
          kind: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
          nextStatus: "REJECTED",
          releaseSourceLease: true,
        },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: timestep,
        classification: "PROVEN_NOT_LANDED",
      }),
    );

    expect(result).toMatchObject({ ok: true, status: "REJECTED" });
    const op = await pool.query(
      `SELECT status::text AS status FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    expect((op.rows[0] as { status: string }).status).toBe("REJECTED");
  });

  it("closing a send releases the source lease ONLY through a consumed lease_release_proofs row, and the wallet is re-leasable", async () => {
    const sourceWalletId = await insertWallet();
    const operationId = await seedSendOperation({
      status: "NEEDS_ATTENTION",
      formationState: "PARTIAL_DELIVERED",
      attentionReason: "UNEXPECTED_HEAD_CHANGE",
      sourceWalletId,
    });
    await seedApprovalAndPartial(operationId, { delivered: true });
    const lease = await insertLease(sourceWalletId, operationId, "SEND_SOURCE");
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);

    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: {
          kind: "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
          nextStatus: "REJECTED",
          releaseSourceLease: true,
        },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: nextTimestep(),
        classification: "PROVEN_NOT_LANDED",
      }),
    );
    expect(result).toMatchObject({ ok: true, status: "REJECTED" });

    // The active lease is gone and its membership is closed out.
    const activeLease = await pool.query(
      `SELECT 1 FROM wallet_active_leases WHERE operation_id = $1::uuid`,
      [operationId],
    );
    expect(activeLease.rowCount).toBe(0);
    const membership = await pool.query(
      `SELECT released_at FROM wallet_lease_memberships WHERE id = $1::uuid`,
      [lease.membershipId],
    );
    expect((membership.rows[0] as { released_at: Date | null }).released_at).not.toBeNull();

    // AC5 — the release went through the guarded proof path: a minted proof row for this
    // exact (wallet, operation, group, epoch), and it is CONSUMED. No other release path.
    const leaseProof = await pool.query(
      `SELECT proof_kind, proof_digest, consumed_at FROM lease_release_proofs
        WHERE wallet_id = $1::uuid AND operation_id = $2::uuid
          AND lease_group_id = $3::uuid AND lease_epoch = $4`,
      [sourceWalletId, operationId, lease.leaseGroupId, lease.leaseEpoch.toString()],
    );
    expect(leaseProof.rowCount).toBe(1);
    const proofRow = leaseProof.rows[0] as {
      proof_kind: string;
      proof_digest: string;
      consumed_at: Date | null;
    };
    expect(proofRow.proof_kind).toBe("EXTERNAL_SEND_LANDED");
    expect(proofRow.consumed_at).not.toBeNull();
    expect(proofRow.proof_digest).toMatch(/^[0-9a-f]{64}$/);

    // AC6 — the wallet is back in the pool and a fresh lease may be taken on it. That is the
    // whole point: a parked send used to hold this slot against the cap forever.
    expect(await walletState(sourceWalletId)).toBe("AVAILABLE");
    const nextOperationId = await seedSendOperation({
      status: "APPROVED",
      formationState: "APPROVED_UNSIGNED",
      sourceWalletId,
    });
    const relet = await insertLease(sourceWalletId, nextOperationId, "SEND_SOURCE");
    expect(relet.leaseEpoch).toBeGreaterThan(lease.leaseEpoch);
    const heldAgain = await pool.query(
      `SELECT 1 FROM wallet_active_leases WHERE wallet_id = $1::uuid`,
      [sourceWalletId],
    );
    expect(heldAgain.rowCount).toBe(1);
  });

  it("rejects an expired nonce with recovery_nonce_invalid", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    await pool.query(`UPDATE recovery_nonces SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE nonce = $1::uuid`, [nonce]);

    const result = await actionStore.commitRecoveryAction(
      commitInput({ operationId, effect: { kind: "RETRY_OBSERVATION" }, expectedRowVersion: 1, recoveryNonce: nonce, totpTimestep: nextTimestep() }),
    );

    expect(result).toMatchObject({ ok: false, reason: "recovery_nonce_invalid" });
  });

  it("rejects a stale row_version with operation_version_conflict, then succeeds when retried at the true row_version with the same nonce", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();

    const stale = await actionStore.commitRecoveryAction(
      commitInput({ operationId, effect: { kind: "ACKNOWLEDGE_KEEP_PINNED", protocolStateUnchanged: true, leasesUnchanged: true }, expectedRowVersion: 99, recoveryNonce: nonce, totpTimestep: timestep }),
    );
    expect(stale).toMatchObject({ ok: false, reason: "operation_version_conflict" });
    expect(await nonceStatus(nonce)).toBe("ISSUED");
    const burnsAfterStale = await pool.query(`SELECT count(*)::int AS n FROM totp_timestep_burns WHERE totp_timestep = $1`, [timestep]);
    expect((burnsAfterStale.rows[0] as { n: number }).n).toBe(0);

    const retried = await actionStore.commitRecoveryAction(
      commitInput({ operationId, effect: { kind: "ACKNOWLEDGE_KEEP_PINNED", protocolStateUnchanged: true, leasesUnchanged: true }, expectedRowVersion: 1, recoveryNonce: nonce, totpTimestep: timestep }),
    );
    expect(retried).toMatchObject({ ok: true, rowVersion: 2 });
  });

  it("commits RETRY_OBSERVATION end to end: nonce consumed, TOTP burned, audit_log row exact, idempotency round-trips, audit_log is append-only", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();
    const idempotencyKey = idemKey("happy");

    const input = commitInput({
      operationId,
      effect: { kind: "RETRY_OBSERVATION" },
      expectedRowVersion: 1,
      recoveryNonce: nonce,
      totpTimestep: timestep,
      idempotencyKey,
      classification: "WAITING",
      priorStatus: "NEEDS_ATTENTION",
      operatorNote: "recovery-store happy path",
    });
    const result = await actionStore.commitRecoveryAction(input);

    expect(result).toMatchObject({ ok: true, rowVersion: 2, status: "NEEDS_ATTENTION", releaseStatus: null });
    expect(await nonceStatus(nonce)).toBe("CONSUMED");
    const burns = await pool.query(
      `SELECT node_id::text AS node_id, purpose::text AS purpose FROM totp_timestep_burns WHERE totp_timestep = $1`,
      [timestep],
    );
    expect(burns.rows).toMatchObject([{ node_id: NODE_ID, purpose: "RECOVERY_ACTION" }]);

    const expectedDetails = `action=RETRY_OBSERVATION;operation_id=${operationId};classification=WAITING;operator_note=recovery-store happy path`;
    const auditRows = await auditRowsFor(operationId);
    expect(auditRows).toHaveLength(1);
    expect(auditRows[0]!.details_text).toBe(expectedDetails);
    expect(auditRows[0]!.details_sha256).toBe(sha256HexUtf8(expectedDetails));
    expect(auditRows[0]!.details_sha256).toBe(sha256(expectedDetails));

    await expect(pool.query(`UPDATE audit_log SET details_text = 'tampered' WHERE operation_id = $1::uuid`, [operationId])).rejects.toMatchObject({
      code: "55000",
    });
    await expect(pool.query(`DELETE FROM audit_log WHERE operation_id = $1::uuid`, [operationId])).rejects.toMatchObject({
      code: "55000",
    });
    await expect(pool.query(`TRUNCATE audit_log`)).rejects.toMatchObject({ code: "55000" });

    const replay = await actionStore.lookupIdempotency(operationId, idempotencyKey);
    expect(replay.kind).toBe("hit");
    if (replay.kind === "hit") {
      expect(replay.body).toMatchObject({
        operation_id: operationId,
        action: "RETRY_OBSERVATION",
        classification: "WAITING",
        status: "NEEDS_ATTENTION",
        row_version: 2,
        release_status: null,
        effect: "RETRY_OBSERVATION",
      });
    }
    const conflictKey = await actionStore.lookupIdempotency(randomUUID(), idempotencyKey);
    expect(conflictKey.kind).toBe("miss");
  });

  it("rejects replay of an already-CONSUMED nonce with recovery_nonce_invalid", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);
    const timestep = nextTimestep();
    const first = await actionStore.commitRecoveryAction(
      commitInput({ operationId, effect: { kind: "RETRY_OBSERVATION" }, expectedRowVersion: 1, recoveryNonce: nonce, totpTimestep: timestep }),
    );
    expect(first.ok).toBe(true);

    const replay = await actionStore.commitRecoveryAction(
      commitInput({ operationId, effect: { kind: "RETRY_OBSERVATION" }, expectedRowVersion: 1, recoveryNonce: nonce, totpTimestep: nextTimestep() }),
    );
    expect(replay).toMatchObject({ ok: false, reason: "recovery_nonce_invalid" });
  });

  it("rejects a second commit that reuses the same (node_id, totp_timestep) across two different operations, rolling back cleanly", async () => {
    const sharedTimestep = nextTimestep();

    const walletA = await insertWallet();
    const destA = await insertDestination(await insertWallet());
    const operationA = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId: walletA, destinationId: destA });
    const nonceA = await inspectionStore.issueRecoveryNonce(operationA);
    const first = await actionStore.commitRecoveryAction(
      commitInput({ operationId: operationA, effect: { kind: "RETRY_OBSERVATION" }, expectedRowVersion: 1, recoveryNonce: nonceA.nonce, totpTimestep: sharedTimestep }),
    );
    expect(first.ok).toBe(true);

    const walletB = await insertWallet();
    const destB = await insertDestination(await insertWallet());
    const operationB = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId: walletB, destinationId: destB });
    const nonceB = await inspectionStore.issueRecoveryNonce(operationB);
    const second = await actionStore.commitRecoveryAction(
      commitInput({ operationId: operationB, effect: { kind: "RETRY_OBSERVATION" }, expectedRowVersion: 1, recoveryNonce: nonceB.nonce, totpTimestep: sharedTimestep }),
    );

    expect(second).toMatchObject({ ok: false, reason: "predicate_failed", detail: "totp_timestep_already_burned" });
    expect(await nonceStatus(nonceB.nonce)).toBe("ISSUED");
    const row = await pool.query(`SELECT row_version::int AS row_version FROM operations WHERE id = $1::uuid`, [operationB]);
    expect((row.rows[0] as { row_version: number }).row_version).toBe(1);
  });

  it("QUARANTINE_WALLETS pins each wallet and tolerates an already-PINNED wallet on a second commit", async () => {
    const heldWalletA = await insertWallet();
    const heldWalletB = await insertWallet();
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    const { nonce } = await inspectionStore.issueRecoveryNonce(operationId);

    const first = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: { kind: "QUARANTINE_WALLETS", walletIds: [heldWalletA, heldWalletB] },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: nextTimestep(),
      }),
    );
    expect(first.ok).toBe(true);
    expect(await walletState(heldWalletA)).toBe("PINNED");
    expect(await walletState(heldWalletB)).toBe("PINNED");

    const { nonce: nonce2 } = await inspectionStore.issueRecoveryNonce(operationId);
    const second = await actionStore.commitRecoveryAction(
      commitInput({
        operationId,
        effect: { kind: "QUARANTINE_WALLETS", walletIds: [heldWalletA, heldWalletB] },
        expectedRowVersion: 2,
        recoveryNonce: nonce2,
        totpTimestep: nextTimestep(),
      }),
    );
    expect(second).toMatchObject({ ok: true, rowVersion: 3 });
    expect(await walletState(heldWalletA)).toBe("PINNED");
  });

  it("loadRecoveryFacts reports a landed MOVE_INTERNAL proof and its held lease", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "test", sourceWalletId, destinationId });
    await insertLease(sourceWalletId, operationId, "MOVE_SOURCE");
    await pool.query(
      `INSERT INTO move_observation_evidence
         (operation_id, source_t0_observation_id, destination_t0_observation_id,
          source_terminal_observation_id, destination_terminal_observation_id, verified_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, now())`,
      [operationId, randomUUID(), randomUUID(), randomUUID(), randomUUID()],
    );

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).toMatchObject({
      operationId,
      kind: "MOVE_INTERNAL",
      status: "NEEDS_ATTENTION",
      attentionRequired: true,
      hasLandingProof: true,
      landingProofVerdict: "LANDED_EXACT",
    });
    expect(facts?.heldLeases).toMatchObject([{ walletId: sourceWalletId, leaseEpoch: 1, role: "MOVE_SOURCE" }]);
  });

  it("loadRecoveryFacts reports no landing proof for a RECEIVE_EXTERNAL operation with an empty proofs table", async () => {
    const operationId = await seedReceiveOperation();

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).toMatchObject({ operationId, kind: "RECEIVE_EXTERNAL", status: "CREATED", hasLandingProof: false, landingProofVerdict: null });
    // No formation boundary crossed yet (no T0 binding, no code/artifact,
    // no signer audit) classifies PROVEN_NOT_STARTED, not insufficient_facts.
    expect(facts).not.toBeNull();
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "PROVEN_NOT_STARTED",
      rationale: "receive_no_formation_boundary_crossed",
    });
  });

  it("a settled RECEIVE_EXTERNAL landing proof classifies LANDED_VERIFIED", async () => {
    const operationId = await seedReceiveOperation();
    await seedLandedReceiveProof(operationId);

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(facts).toMatchObject({ hasLandingProof: true, landingProofVerdict: "LANDED_EXACT" });
    expect(facts!.evidenceManifest.length).toBeGreaterThan(0);
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "LANDED_VERIFIED",
      rationale: "landing_exact",
    });
  });

  // Regression: live staging classified RECEIVE_LANDED as INVARIANT_BREACH
  // (receive_signer_audit_without_exact_bytes) because hasMatchingExactByteRecord
  // compared T0 completed_transaction_sha256 to operation_expected_artifacts.preimage_sha256
  // — two unrelated digests. Correct match is signer_audit.preimage_sha256 against the
  // durable exact-byte home (artifact / operation_transactions preimages).
  it("settled RECEIVE with matching EXPECTED_ARTIFACT signer_audit classifies LANDED_VERIFIED", async () => {
    const operationId = await seedReceiveOperation();
    await seedLandedReceiveProof(operationId);
    const preimageText = `zp-receive-expected-v1\n${operationId}`;
    const preimageSha = sha256(preimageText);
    const artifactId = randomUUID();
    await pool.query(
      `INSERT INTO operation_expected_artifacts
         (id, operation_id, purpose, canonical_version, signing_key_id,
          preimage_text, preimage_sha256, signature, created_at)
       VALUES ($1::uuid, $2::uuid, 'zp-receive-expected-v1', 1, $3::uuid,
               $4, $5, $6, now())`,
      [artifactId, operationId, randomUUID(), preimageText, preimageSha, signature()],
    );
    await pool.query(
      `INSERT INTO signer_audit
         (id, node_id, operation_id, preimage_sha256, called_at, outcome, purpose)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now(), 'SUCCEEDED', 'EXPECTED_ARTIFACT')`,
      [randomUUID(), NODE_ID, operationId, preimageSha],
    );

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(facts!.receive).toMatchObject({
      hasSignerAudit: true,
      hasMatchingExactByteRecord: true,
      hasArtifactSignature: true,
    });
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "LANDED_VERIFIED",
      rationale: "landing_exact",
    });
  });

  it("RECEIVE with STEP_2 signer_audit and no durable preimage classifies INVARIANT_BREACH", async () => {
    const operationId = await seedArmedReceiveOperation({
      expiryUnixTimeSecs: Math.floor(Date.now() / 1000) + 3600,
    });
    await pool.query(
      `INSERT INTO signer_audit
         (id, node_id, operation_id, preimage_sha256, called_at, outcome, purpose)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4, now(), 'SUCCEEDED', 'STEP_2')`,
      [randomUUID(), NODE_ID, operationId, sha256(`orphan-step2-${operationId}`)],
    );

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(facts!.receive).toMatchObject({
      hasSignerAudit: true,
      hasMatchingExactByteRecord: false,
    });
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "INVARIANT_BREACH",
      rationale: "receive_signer_audit_without_exact_bytes",
    });
  });

  it("an expired, never-paid RECEIVE_EXTERNAL with all five predicates classifies PROVEN_NOT_LANDED", async () => {
    const expiredSecs = Math.floor(Date.now() / 1000) - 3600;
    const operationId = await seedArmedReceiveOperation({ expiryUnixTimeSecs: expiredSecs });

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(facts!.evidenceManifest.length).toBeGreaterThan(0);
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "PROVEN_NOT_LANDED",
      rationale: "receive_expired_t0_unchanged_all_five",
    });
  });

  it("an expired RECEIVE_EXTERNAL with a signed-but-unlanded operation_transactions row does NOT classify PROVEN_NOT_LANDED", async () => {
    const expiredSecs = Math.floor(Date.now() / 1000) - 3600;
    const operationId = await seedArmedReceiveOperation({ expiryUnixTimeSecs: expiredSecs });
    const innerText = `inner-${randomUUID()}`;
    await pool.query(
      `INSERT INTO operation_transactions
         (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
          step_1_signature, formed_at)
       VALUES ($1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', $2, $3, $4, now())`,
      [operationId, innerText, sha256(innerText), signature()],
    );

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(classifyRecovery(facts!).classification).not.toBe("PROVEN_NOT_LANDED");
  });

  it("an armed but unexpired RECEIVE_EXTERNAL with sparse evidence stays INDETERMINATE", async () => {
    const futureSecs = Math.floor(Date.now() / 1000) + 3600;
    const operationId = await seedArmedReceiveOperation({ expiryUnixTimeSecs: futureSecs });

    const facts = await inspectionStore.loadRecoveryFacts(operationId);

    expect(facts).not.toBeNull();
    expect(classifyRecovery(facts!)).toMatchObject({
      classification: "INDETERMINATE",
      rationale: "receive_insufficient_evidence",
    });
  });

  it("listNeedsAttention surfaces the seeded NEEDS_ATTENTION operation", async () => {
    const sourceWalletId = await insertWallet();
    const destinationId = await insertDestination(await insertWallet());
    const operationId = await seedMoveOperation({ status: "NEEDS_ATTENTION", attentionReason: "listed", sourceWalletId, destinationId });

    const facts = await inspectionStore.listNeedsAttention({ limit: 200 });

    expect(facts.map((f) => f.operationId)).toContain(operationId);
  });

  it("RELEASE_EXPIRED_RECEIVE releases via SqlReceiveExpiryReleaseService, unpins the wallet, and records dual proof rows", async () => {
    const fx = await seedReleaseableExpiredReceive();

    const { nonce } = await inspectionStore.issueRecoveryNonce(fx.operationId);
    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId: fx.operationId,
        effect: { kind: "RELEASE_EXPIRED_RECEIVE", releaseStatus: "RELEASED_T0_UNCHANGED", walletPinnedToAvailable: true },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: nextTimestep(),
        classification: "PROVEN_NOT_LANDED",
      }),
    );

    expect(result).toMatchObject({ ok: true, releaseStatus: "RELEASED_T0_UNCHANGED" });
    // store CAS (+1) + service CAS_TO_EXPIRED (+1) + SET_RELEASE_STATUS (+1) = 4
    expect(result).toMatchObject({ ok: true, rowVersion: 4 });
    expect(await walletState(fx.walletId)).toBe("AVAILABLE");
    const activeLease = await pool.query(`SELECT 1 FROM wallet_active_leases WHERE operation_id = $1::uuid`, [fx.operationId]);
    expect(activeLease.rowCount).toBe(0);
    const membership = await pool.query(`SELECT released_at FROM wallet_lease_memberships WHERE id = $1::uuid`, [fx.membershipId]);
    expect((membership.rows[0] as { released_at: Date | null }).released_at).not.toBeNull();
    const leaseProof = await pool.query(
      `SELECT proof_kind, consumed_at FROM lease_release_proofs
        WHERE wallet_id = $1::uuid AND operation_id = $2::uuid AND lease_group_id = $3::uuid AND lease_epoch = $4`,
      [fx.walletId, fx.operationId, fx.leaseGroupId, fx.leaseEpoch.toString()],
    );
    expect(leaseProof.rows).toMatchObject([{ proof_kind: "RECEIVE_EXPIRED_T0" }]);
    expect((leaseProof.rows[0] as { consumed_at: Date | null }).consumed_at).not.toBeNull();
    // D2: real receive_release_proofs row with both observation FKs (never synthetic digest).
    const recvProof = await pool.query(
      `SELECT release_kind, t0_observation_id::text AS t0, fresh_observation_id::text AS fresh
         FROM receive_release_proofs WHERE operation_id = $1::uuid`,
      [fx.operationId],
    );
    expect(recvProof.rows).toMatchObject([{
      release_kind: "EXPIRED_T0_UNCHANGED",
      t0: fx.t0ObservationId,
      fresh: fx.freshObservationId,
    }]);
    const op = await pool.query(
      `SELECT receive_release_status, attention_required, status::text AS status
         FROM operations WHERE id = $1::uuid`,
      [fx.operationId],
    );
    expect(op.rows).toMatchObject([{
      receive_release_status: "RELEASED_T0_UNCHANGED",
      attention_required: false,
      status: "EXPIRED",
    }]);
  });

  it("RELEASE_EXPIRED_RECEIVE refuses when the receive has payment evidence, leaving the lease and wallet untouched", async () => {
    const fx = await seedReleaseableExpiredReceive();
    const innerText = `inner-${randomUUID()}`;
    await pool.query(
      `INSERT INTO operation_transactions
         (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
          step_1_signature, formed_at)
       VALUES ($1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', $2, $3, $4, now())`,
      [fx.operationId, innerText, sha256(innerText), signature()],
    );

    const { nonce } = await inspectionStore.issueRecoveryNonce(fx.operationId);
    const result = await actionStore.commitRecoveryAction(
      commitInput({
        operationId: fx.operationId,
        effect: { kind: "RELEASE_EXPIRED_RECEIVE", releaseStatus: "RELEASED_T0_UNCHANGED", walletPinnedToAvailable: true },
        expectedRowVersion: 1,
        recoveryNonce: nonce,
        totpTimestep: nextTimestep(),
      }),
    );

    // Service maps candidate_exists → NEEDS_ATTENTION (POST_EXPIRY_RECONCILING); store
    // surfaces it as predicate_failed with the outcome kind (no longer the pre-lock probe's
    // receive_has_payment_evidence detail — that probe was deleted under Route A).
    expect(result).toMatchObject({ ok: false, reason: "predicate_failed", detail: "receive_release_needs_attention" });
    expect(await walletState(fx.walletId)).toBe("PINNED");
    const activeLease = await pool.query(`SELECT 1 FROM wallet_active_leases WHERE operation_id = $1::uuid`, [fx.operationId]);
    expect(activeLease.rowCount).toBe(1);
    const op = await pool.query(`SELECT receive_release_status FROM operations WHERE id = $1::uuid`, [fx.operationId]);
    expect(op.rows).toMatchObject([{ receive_release_status: null }]);
    const proofs = await pool.query(`SELECT 1 FROM receive_release_proofs WHERE operation_id = $1::uuid`, [fx.operationId]);
    expect(proofs.rowCount).toBe(0);
  });

  it("replaying RELEASE_EXPIRED_RECEIVE after the lease is already released is a no-op, never unpinning a re-allocated wallet", async () => {
    const fx = await seedReleaseableExpiredReceive();

    const { nonce: firstNonce } = await inspectionStore.issueRecoveryNonce(fx.operationId);
    const releaseEffect: RecoveryActionEffect = {
      kind: "RELEASE_EXPIRED_RECEIVE",
      releaseStatus: "RELEASED_T0_UNCHANGED",
      walletPinnedToAvailable: true,
    };
    const first = await actionStore.commitRecoveryAction(
      commitInput({ operationId: fx.operationId, effect: releaseEffect, expectedRowVersion: 1, recoveryNonce: firstNonce, totpTimestep: nextTimestep() }),
    );
    expect(first.ok).toBe(true);
    expect(first).toMatchObject({ rowVersion: 4 });
    expect(await walletState(fx.walletId)).toBe("AVAILABLE");

    // Wallet gets re-leased by an unrelated operation before the replay lands — One-in-flight forbids
    // the replay from touching it.
    const otherExpiry = Math.floor(Date.now() / 1000) - 120;
    const otherOperationId = await seedArmedReceiveOperation({
      expiryUnixTimeSecs: otherExpiry,
      receiverWalletId: fx.walletId,
    });
    await seedReleasableLease(otherOperationId, fx.walletId);
    expect(await walletState(fx.walletId)).toBe("PINNED");

    const { nonce: secondNonce } = await inspectionStore.issueRecoveryNonce(fx.operationId);
    const replay = await actionStore.commitRecoveryAction(
      commitInput({
        operationId: fx.operationId,
        effect: releaseEffect,
        // post-release row_version from the first commit
        expectedRowVersion: 4,
        recoveryNonce: secondNonce,
        totpTimestep: nextTimestep(),
      }),
    );

    expect(replay).toMatchObject({ ok: true, releaseStatus: "RELEASED_T0_UNCHANGED" });
    expect(await walletState(fx.walletId)).toBe("PINNED");
    const otherLease = await pool.query(`SELECT 1 FROM wallet_active_leases WHERE operation_id = $1::uuid`, [otherOperationId]);
    expect(otherLease.rowCount).toBe(1);
  });

  it("two-session race — concurrent operation_transactions insert while release waits on lease FOR UPDATE is refused", async () => {
    // c2 holds wallet_active_leases FOR UPDATE as a barrier; T1 blocks inside
    // SqlReceiveExpiryReleaseService at LOCK_RECEIVER_LEASE; c2 inserts payment evidence
    // and commits; T1 proceeds and must refuse (NEEDS_ATTENTION), leaving the lease.
    // Under Route A the service's post-lock LOAD_MATERIAL_FACTS is the load-bearing check
    // (the pre-lock probe was deleted). Residual unlocked settle-sign window — a known residual.
    const fx = await seedReleaseableExpiredReceive();
    const { nonce } = await inspectionStore.issueRecoveryNonce(fx.operationId);

    const c2 = await pool.connect();
    try {
      await c2.query(`SET search_path TO ${SCHEMA}, public`);
      await c2.query("BEGIN");
      await c2.query(
        `SELECT wallet_id FROM wallet_active_leases WHERE operation_id = $1::uuid FOR UPDATE`,
        [fx.operationId],
      );

      const t1Promise = actionStore.commitRecoveryAction(
        commitInput({
          operationId: fx.operationId,
          effect: {
            kind: "RELEASE_EXPIRED_RECEIVE",
            releaseStatus: "RELEASED_T0_UNCHANGED",
            walletPinnedToAvailable: true,
          },
          expectedRowVersion: 1,
          recoveryNonce: nonce,
          totpTimestep: nextTimestep(),
        }),
      );

      // Wait until T1 is blocked on a lock (not a fixed sleep).
      const deadline = Date.now() + 8_000;
      let blocked = false;
      while (Date.now() < deadline) {
        const locks = await pool.query<{ cnt: string }>(
          `SELECT count(*)::text AS cnt
             FROM pg_locks l
             JOIN pg_stat_activity a ON a.pid = l.pid
            WHERE l.granted = false
              AND a.wait_event_type = 'Lock'
              AND a.datname = current_database()`,
        );
        if (Number(locks.rows[0]?.cnt ?? 0) > 0) {
          blocked = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(blocked).toBe(true);

      const innerText = `race-inner-${randomUUID()}`;
      await c2.query(
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256,
            step_1_signature, formed_at)
         VALUES ($1::uuid, 1, 'STEP1_SIGNATURE_PERSISTED', $2, $3, $4, now())`,
        [fx.operationId, innerText, sha256(innerText), signature()],
      );
      await c2.query("COMMIT");

      const result = await t1Promise;
      expect(result).toMatchObject({
        ok: false,
        reason: "predicate_failed",
        detail: "receive_release_needs_attention",
      });
      expect(await walletState(fx.walletId)).toBe("PINNED");
      const activeLease = await pool.query(
        `SELECT 1 FROM wallet_active_leases WHERE operation_id = $1::uuid`,
        [fx.operationId],
      );
      expect(activeLease.rowCount).toBe(1);
      const proofs = await pool.query(
        `SELECT 1 FROM receive_release_proofs WHERE operation_id = $1::uuid`,
        [fx.operationId],
      );
      expect(proofs.rowCount).toBe(0);
    } finally {
      try { await c2.query("ROLLBACK"); } catch { /* already committed/rolled back */ }
      c2.release();
    }
  }, 20_000);


});

registerPgRequiredGuard({
  name: "sql-recovery-store.pg",
  databaseUrl,
  isReady: () => reachable,
});
