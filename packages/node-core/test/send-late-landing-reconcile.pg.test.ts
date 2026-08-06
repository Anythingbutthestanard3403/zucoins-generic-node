/**
 * send-late-landing-reconcile.pg.test.ts
 *
 * Real PostgreSQL drills for late-landing reconcile:
 * 1. applyLateLandingCycle depth-1 land → bodies 0..1 + head digest + lease held
 * 2. second apply after land → ALREADY_LANDED; single row; status EXTERNAL_SEND_LANDED
 *   3. Hand SQL NEEDS_ATTENTION → EXTERNAL_SEND_LANDED co-commit (landing store shape)
 *   4. Landing SQL never deletes wallet_active_leases
 *   5. applyLateLandingCycle incomplete oracle → remains NEEDS_ATTENTION; lease held
 *   6. crash between positive proof and land; fresh store recovers EXTERNAL_SEND_LANDED
 *
 * Harness mirrors test/send-external-landing-pg.test.ts.
 */
import { createHash, createPrivateKey, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  parseGatewayEnvelope,
  type ParsedSettledTransaction,
} from "../src/verifier/gateway-envelope.js";
import type { FreshHeadRead, ReadFreshHead } from "../src/verifier/landing-path-oracle.js";
import { verifySettledTransaction } from "../src/verifier/transaction-verify.js";
import type { SettledSplitChainTransaction } from "../src/protocol/inner.js";
import {
  EXTERNAL_SEND_LANDED_STATUS,
  SETTLED_BODY_PERSISTED_PHASE,
  type CommitExternalSendLandingCommand,
  type ExternalSendLandingStore,
} from "../src/send/landing-commit.js";
import type { SendLandingEvidence } from "../src/send/landing-verify.js";
import {
  applyLateLandingCycle,
  type LateLandingOperationFacts,
  type LateLandingProofProgress,
  type SendLateLandingProofStore,
} from "../src/send/late-landing-reconcile.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "../src/schema");
const MAINTENANCE_DB = "postgres";
const DB_PREFIX = "send_late_landing_late_landing_";
const EXPECTED_DRILL_COUNT = 6;

const NODE_ID = "a0000000-0000-4000-8000-000000000001";
const IMPL_ID = "a0000000-0000-4000-8000-000000000002";
const WALLET_ID = "a0000000-0000-4000-8000-000000000003";
const KEY_ID = "a0000000-0000-4000-8000-000000000004";
const OBS_ID = "a0000000-0000-4000-8000-000000000005";
const OP_A = "a0000000-0000-4000-8000-000000000010";
const OP_B = "a0000000-0000-4000-8000-000000000011";
const OP_C = "a0000000-0000-4000-8000-000000000012";
const OP_D = "a0000000-0000-4000-8000-000000000013";
const APPROVAL_ID = "a0000000-0000-4000-8000-000000000014";
const SOURCE_T0_OBS = "a0000000-0000-4000-8000-000000000015";
const DEST_T0_OBS = "a0000000-0000-4000-8000-000000000016";
const OBSERVER_ID = "a0000000-0000-4000-8000-000000000017";

const _DEST_PAD = `${"D".repeat(43)}=`;
const PUBKEY_PAD = `${"P".repeat(43)}=`;
const SIG = `${"S".repeat(86)}==`;
const SHA = "a".repeat(64);

// ─── Real crypto fixtures (same golden chain as unit suite) ─────────────────

const GEN_DIR = new URL(
  "../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: Record<string, string>;
};
const SOURCE = MANIFEST.public_keys.seed_02 as string;
const DEST = MANIFEST.public_keys.seed_03 as string;
const AMOUNT = "2.25";
const TRANSFER_CODE = "transfer-code-fixture-pg";

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const keyFromSeed = (byte: number) => {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
};

const signText = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

function headEnvelope(settledText: string, observationId?: string): FreshHeadRead {
  const bytes = new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledText}]}`,
  );
  return {
    observationId: observationId ?? `obs-${settledText.length}`,
    envelope: parseGatewayEnvelope(bytes),
  };
}

function parsedBody(settledText: string): ParsedSettledTransaction {
  const verdict = headEnvelope(settledText).envelope;
  if (verdict.classification !== "HEAD") throw new Error("expected HEAD envelope");
  return verdict.parsed;
}

const PREDECESSOR_TEXT = fixtureText("predecessor.settled.json");
const TARGET_TEXT = fixtureText("target.settled.json");
const PREDECESSOR = parsedBody(PREDECESSOR_TEXT);
const TARGET = parsedBody(TARGET_TEXT);
const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);

function buildHop(prevStep2: string, amountOut: string, remaining: string, time: string) {
  const inner = {
    type: "unique_combinable" as const,
    version: "2" as const,
    unix_time_secs: time,
    signer_steps: 2 as const,
    step_1_signer: "sender" as const,
    step_2_signer: "receiver" as const,
    step_1_key_public__base64urlsafe: SOURCE,
    step_2_key_public__base64urlsafe: DEST,
    step_1_state: { amount: remaining },
    step_2_state: { amount: amountOut },
    previous_step_1_state_signature: prevStep2,
    previous_step_2_state_signature: prevStep2,
  };
  const step1 = JSON.stringify(inner);
  const step1Sig = signText(step1, seed02);
  const step2Pre = JSON.stringify({ inner, step_1_signature: step1Sig });
  const step2Sig = signText(step2Pre, seed03);
  const text = JSON.stringify({
    inner,
    step_1_signature: step1Sig,
    step_2_signature: step2Sig,
  });
  return { text, body: parsedBody(text) };
}

const HOP3 = buildHop(TARGET.step_2_signature, "1.00", "6.75", "1784332900");

interface BuiltCandidate {
  readonly tx: SettledSplitChainTransaction;
  readonly preimage: string;
  readonly bodyText: string;
  readonly bodySha: string;
  readonly innerSha: string;
  readonly transferCodeSha256: string;
  readonly step1Signature: string;
  readonly step2Signature: string;
}

function buildCandidate(): BuiltCandidate {
  const verified = verifySettledTransaction(TARGET, SOURCE);
  if (verified.verdict !== "VERIFIED") {
    throw new Error(`TARGET must verify under SOURCE: ${verified.verdict}`);
  }
  const preimage = verified.innerPreimageText;
  return {
    tx: verified.transaction,
    preimage,
    bodyText: TARGET_TEXT,
    bodySha: sha256Hex(TARGET_TEXT),
    innerSha: sha256Hex(preimage),
    transferCodeSha256: sha256Hex(TRANSFER_CODE),
    step1Signature: verified.transaction.step_1_signature,
    step2Signature: verified.transaction.step_2_signature,
  };
}

function baseEvidence(c: BuiltCandidate, opId: string): SendLandingEvidence {
  return {
    operationId: opId,
    entryStatus: "NEEDS_ATTENTION",
    economic: {
      operationId: opId,
      sourceWalletId: WALLET_ID,
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    expectedArtifactVerified: true,
    expectedArtifact: {
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    approval: {
      approvalId: APPROVAL_ID,
      totpConsumed: true,
      deviceSignatureRequired: false,
      deviceSignatureVerified: false,
      sourcePubkey: SOURCE,
      destinationAddress: DEST,
      amountZkz: AMOUNT,
      referencesOperationId: null,
    },
    signIntent: {
      approvalId: APPROVAL_ID,
      sourceT0ObservationId: SOURCE_T0_OBS,
      destinationT0ObservationId: DEST_T0_OBS,
      innerPreimageText: c.preimage,
      innerSha256: c.innerSha,
    },
    signIntentRowCount: 1,
    partial: {
      innerSha256: c.innerSha,
      step1Signature: c.step1Signature,
      transferCodeSha256: c.transferCodeSha256,
      deliveredTransferCodeSha256: c.transferCodeSha256,
      otherDeliveredPartialSha256: [],
    },
    sourceT0: {
      observationId: SOURCE_T0_OBS,
      projection: {
        role: "sender",
        S: PREDECESSOR.step_2_signature,
        P: "",
        B: "10",
        I: "d0",
      },
    },
    destinationT0: {
      observationId: DEST_T0_OBS,
      projection: { role: "receiver", S: "", P: "", B: "0", I: "d1" },
    },
    candidate: {
      completedTransaction: c.tx,
      completedTransactionText: c.bodyText,
      completedTransactionSha256: c.bodySha,
      step1PreimageText: c.preimage,
      step1Signature: c.step1Signature,
      step2Signature: c.step2Signature,
      step2SignatureVerified: true,
    },
    sourcePathProof: null,
    sourcePathProofIncomplete: false,
    sourceLeaseActive: true,
  };
}

function facts(c: BuiltCandidate, opId: string): LateLandingOperationFacts {
  const ev = baseEvidence(c, opId);
  const { candidate, sourcePathProof, sourcePathProofIncomplete, entryStatus, ...rest } = ev;
  return {
    operationId: opId,
    sendAttemptId: opId,
    sourceWalletId: WALLET_ID,
    sourcePubkey: SOURCE,
    destinationAddress: DEST,
    amountZkz: AMOUNT,
    transferCodeSha256: c.transferCodeSha256,
    status: "NEEDS_ATTENTION",
    sourceLeaseActive: true,
    expectedBody: TARGET,
    expectedBodyText: TARGET_TEXT,
    t0Body: PREDECESSOR,
    landingEvidenceBase: rest,
    candidateFromExpected: candidate!,
    verifierObserverId: OBSERVER_ID,
  };
}

function staticReader(settledText: string, obsId?: string): ReadFreshHead {
  let calls = 0;
  return async () => {
    calls += 1;
    return headEnvelope(settledText, obsId ?? `obs-head-${calls}`);
  };
}

// ─── psql harness ───────────────────────────────────────────────────────────

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 16 * 1024 * 1024,
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

const sqlLit = (value: string): string => `'${value.replace(/'/g, "''")}'`;

const seedNode = (db: string): void => {
  psqlMust(
    db,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
      `('${NODE_ID}', 'send-late-landing-late', '${PUBKEY_PAD}') ON CONFLICT (id) DO NOTHING;`,
  );
};

// wallets(id) + full recovery columns; recovery stamped via UPDATE (FK cycle).
const seedWallet = (db: string, walletId: string): void => {
  const recoveryId = "a0000000-0000-4000-8000-000000000090";
  const exportSha = "e".repeat(64);
  psqlMust(
    db,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
      `VALUES ('${walletId}', '${NODE_ID}', ${sqlLit(SOURCE)}, 'node_generated', 'AVAILABLE'); ` +
      `INSERT INTO wallet_recovery_verifications ` +
      `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
      `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${exportSha}', ${sqlLit(SOURCE)}, ` +
      `'${recoveryId}', now(), 'send-late-landing-late-test'); ` +
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
      `WHERE id = '${walletId}';`,
  );
};

let artifactSeq = 0;

const insertOp = (
  db: string,
  opId: string,
  status: string,
  idemKey: string,
  attention: boolean,
): void => {
  artifactSeq += 1;
  const artifactId = `a0000000-0000-4000-8000-${String(artifactSeq).padStart(12, "0")}`;
  const formation = status === "CREATED" ? "APPROVAL_PENDING" : "PARTIAL_DELIVERED";
  const attentionReason = attention ? "'UNEXPECTED_HEAD_CHANGE'" : "NULL";
  const attentionEpisode = attention ? 1 : 0;
  psqlMust(
    db,
    `INSERT INTO send_operations (` +
      `operation_id, implementer_id, node_id, kind, status, row_version, ` +
      `attention_required, attention_reason, attention_episode, formation_state, ` +
      `http_method, route, idempotency_key, ` +
      `request_sha256, source_wallet_id, destination_address, amount_zkz` +
      `) VALUES (` +
      `'${opId}', '${IMPL_ID}', '${NODE_ID}', 'SEND_EXTERNAL', '${status}', 1, ` +
      `${attention}, ${attentionReason}, ${attentionEpisode}, '${formation}', ` +
      `'POST', '/v1/external-sends', '${idemKey}', ` +
      `'${SHA}', '${WALLET_ID}', ${sqlLit(DEST)}, '1.5'` +
      `); ` +
      `INSERT INTO send_operation_expected_artifacts (` +
      `artifact_id, operation_id, purpose, canonical_version, signing_key_id, ` +
      `preimage_text, preimage_sha256, signature` +
      `) VALUES (` +
      `'${artifactId}', '${opId}', 'zp-send-external-expected-v1', 1, '${KEY_ID}', ` +
      `'preimage', '${SHA}', '${SIG}'` +
      `); ` +
      `INSERT INTO wallet_active_leases (` +
      `wallet_id, membership_id, lease_group_id, root_operation_id, operation_id, ` +
      `lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id` +
      `) VALUES (` +
      `'${WALLET_ID}', gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), ` +
      `'SEND_SOURCE', 1, now(), now(), gen_random_uuid()` +
      `) ON CONFLICT (wallet_id) DO NOTHING;`,
  );
};

/**
 * Atomic land mirroring SqlExternalSendLandingStore: the status UPDATE is the
 * arbiter. Zero rows updated → abort (STATUS_GUARD_MISMATCH or ALREADY_LANDED).
 */
const atomicLandSql = (
  opId: string,
  entryStatus: string,
  bodyText: string,
  bodySha: string,
  pathKind: string,
  pathDepth: number,
  obsId: string,
): string => `
BEGIN;
CREATE TEMP TABLE _land_guard ON COMMIT DROP AS
  SELECT operation_id FROM send_operations WHERE false;
WITH u AS (
  UPDATE send_operations SET
    status = 'EXTERNAL_SEND_LANDED',
    attention_required = false,
    attention_reason = NULL,
    row_version = row_version + 1,
    verification_material_available_until = to_timestamp(1800000000000 / 1000.0),
    landed_at = to_timestamp(1700000000000 / 1000.0),
    terminal_observation_id = '${obsId}'
  WHERE operation_id = '${opId}' AND status = '${entryStatus}'
  RETURNING operation_id
),
saved AS (
  INSERT INTO _land_guard SELECT operation_id FROM u RETURNING operation_id
),
ins_rec AS (
  INSERT INTO external_send_landing_records (
    operation_id, attempt_phase, public_execution_phase,
    completed_transaction_text, completed_transaction_sha256,
    terminal_observation_id, source_path_kind, source_path_depth,
    landed_at, verification_material_available_until, entry_status
  )
  SELECT operation_id, 'SETTLED_BODY_PERSISTED', 'LANDED_VERIFIED',
    ${sqlLit(bodyText)}, '${bodySha}',
    '${obsId}', '${pathKind}', ${pathDepth},
    to_timestamp(1700000000000 / 1000.0), to_timestamp(1800000000000 / 1000.0),
    '${entryStatus}'
  FROM saved
  RETURNING operation_id
)
INSERT INTO external_send_landing_events (
  operation_id, event_type, terminal_observation_id, landed_at, data_text
)
SELECT operation_id, 'external_send.landed', '${obsId}',
  to_timestamp(1700000000000 / 1000.0),
  '{"terminal_observation_id":"${obsId}","landed_at":"2023-11-14T22:13:20.000Z"}'
FROM ins_rec;
DO $$
DECLARE
  n int;
  cur text;
BEGIN
  SELECT count(*) INTO n FROM _land_guard;
  IF n = 0 THEN
    SELECT status INTO cur FROM send_operations WHERE operation_id = '${opId}';
    IF cur = 'EXTERNAL_SEND_LANDED' THEN
      RAISE EXCEPTION 'ALREADY_LANDED';
    END IF;
    RAISE EXCEPTION 'STATUS_GUARD_MISMATCH';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM wallet_active_leases WHERE wallet_id = '${WALLET_ID}'
  ) THEN
    RAISE EXCEPTION 'LEASE_MISSING';
  END IF;
END $$;
COMMIT;
`;

/** Landing store that emits production-shaped land SQL against real PG. */
class PsqlExternalSendLandingStore implements ExternalSendLandingStore {
  constructor(private readonly db: string) {}

  async commitLanding(command: CommitExternalSendLandingCommand): Promise<{
    readonly applied: boolean;
    readonly reason?: "STATUS_GUARD_MISMATCH" | "ALREADY_LANDED" | "LEASE_MISSING";
    readonly record?: import("../src/send/landing-commit.js").ExternalSendLandingRecord;
    readonly event?: import("../src/send/landing-commit.js").ExternalSendLandedEvent;
    readonly sourceLeaseStillHeld: boolean;
  }> {
    const { buildLandingRecord, buildLandedEvent } = await import("../src/send/landing-commit.js");
    const record = buildLandingRecord(command);
    const event = buildLandedEvent(command);
    const bodyText = command.candidate.completedTransactionText ?? "";
    const bodySha = command.candidate.completedTransactionSha256;
    const sql = atomicLandSql(
      command.operationId,
      command.expectedEntryStatus,
      bodyText,
      bodySha,
      command.sourcePath.kind,
      command.sourcePath.depth,
      command.terminalObservationId,
    );
    const land = runPsql(this.db, sql);
    if (!land.ok) {
      const err = land.stderr;
      if (/ALREADY_LANDED/i.test(err)) {
        return { applied: false, reason: "ALREADY_LANDED", sourceLeaseStillHeld: true };
      }
      if (/LEASE_MISSING/i.test(err)) {
        return { applied: false, reason: "LEASE_MISSING", sourceLeaseStillHeld: false };
      }
      return { applied: false, reason: "STATUS_GUARD_MISMATCH", sourceLeaseStillHeld: true };
    }
    return {
      applied: true,
      record,
      event,
      sourceLeaseStillHeld: true,
    };
  }
}

/** proof store — production INSERT SQL; loadAttempt1 SELECTs durable PG rows as JSON. */
class PsqlSendLateLandingProofStore implements SendLateLandingProofStore {
  constructor(private readonly db: string) {}

  async loadAttempt1(operationId: string): Promise<LateLandingProofProgress | null> {
    const lpQ = runPsql(
      this.db,
      `SELECT json_build_object(` +
        `'id', id,` +
        `'operationId', operation_id,` +
        `'verifierObserverId', verifier_observer_id,` +
        `'verdict', verdict,` +
        `'requiredPathCount', required_path_count,` +
        `'declaredBodyCount', declared_body_count,` +
        `'declaredTotalBodyBytes', declared_total_body_bytes,` +
        `'proofManifestText', proof_manifest_text,` +
        `'proofManifestSha256', proof_manifest_sha256,` +
        `'verifiedAtMs', COALESCE((EXTRACT(EPOCH FROM verified_at)*1000)::bigint, 0),` +
        `'createdAtMs', COALESCE((EXTRACT(EPOCH FROM created_at)*1000)::bigint, 0)` +
        `)::text FROM operation_landing_proofs ` +
        `WHERE operation_id='${operationId}' AND expected_transaction_attempt_no = 1 LIMIT 1`,
    );
    if (!lpQ.ok || lpQ.stdout.trim() === "") return null;
    const lpRaw = JSON.parse(lpQ.stdout.trim()) as {
      id: string;
      operationId: string;
      verifierObserverId: string;
      verdict: LateLandingProofProgress["landingProof"]["verdict"];
      requiredPathCount: number;
      declaredBodyCount: number;
      declaredTotalBodyBytes: number;
      proofManifestText: string;
      proofManifestSha256: string;
      verifiedAtMs: number;
      createdAtMs: number;
    };
    const landingProof = {
      id: lpRaw.id,
      operationId: lpRaw.operationId,
      verifierObserverId: lpRaw.verifierObserverId,
      expectedTransactionAttemptNo: 1 as const,
      verdict: lpRaw.verdict,
      requiredPathCount: Number(lpRaw.requiredPathCount),
      declaredBodyCount: Number(lpRaw.declaredBodyCount),
      declaredTotalBodyBytes: Number(lpRaw.declaredTotalBodyBytes),
      proofManifestText: lpRaw.proofManifestText,
      proofManifestSha256: lpRaw.proofManifestSha256,
      verifiedAtMs: Number(lpRaw.verifiedAtMs) === 0 ? null : Number(lpRaw.verifiedAtMs),
      createdAtMs: Number(lpRaw.createdAtMs),
    };

    if (landingProof.verdict !== "LANDED_EXACT" && landingProof.verdict !== "LANDED_COMPLETE_PATH") {
      return { landingProof, pathProof: null, bodies: [] };
    }

    const ppQ = runPsql(
      this.db,
      `SELECT json_build_object(` +
        `'id', id,` +
        `'landing_proof_id', landing_proof_id,` +
        `'path_role', path_role,` +
        `'wallet_id', wallet_id,` +
        `'wallet_public_key', wallet_public_key,` +
        `'t0_observation_id', t0_observation_id,` +
        `'fresh_head_observation_id', fresh_head_observation_id,` +
        `'expected_completed_transaction_sha256', expected_completed_transaction_sha256,` +
        `'fresh_head_completed_transaction_sha256', fresh_head_completed_transaction_sha256,` +
        `'body_count', body_count,` +
        `'path_depth', path_depth` +
        `)::text FROM lineage_path_proofs WHERE landing_proof_id='${landingProof.id}' LIMIT 1`,
    );
    if (!ppQ.ok || ppQ.stdout.trim() === "") {
      return { landingProof, pathProof: null, bodies: [] };
    }
    const p = JSON.parse(ppQ.stdout.trim()) as {
      id: string;
      landing_proof_id: string;
      path_role: string;
      wallet_id: string | null;
      wallet_public_key: string;
      t0_observation_id: string;
      fresh_head_observation_id: string;
      expected_completed_transaction_sha256: string;
      fresh_head_completed_transaction_sha256: string;
      body_count: number;
      path_depth: number;
    };
    const pathProof = {
      id: p.id,
      landing_proof_id: p.landing_proof_id,
      path_role: "SOURCE" as const,
      wallet_id: p.wallet_id,
      wallet_public_key: p.wallet_public_key,
      t0_observation_id: p.t0_observation_id,
      fresh_head_observation_id: p.fresh_head_observation_id,
      expected_completed_transaction_sha256: p.expected_completed_transaction_sha256,
      fresh_head_completed_transaction_sha256: p.fresh_head_completed_transaction_sha256,
      body_count: Number(p.body_count),
      path_depth: Number(p.path_depth),
    };

    const bQ = runPsql(
      this.db,
      `SELECT COALESCE(json_agg(row_to_json(b) ORDER BY b.path_index), '[]'::json)::text FROM (` +
        `SELECT path_proof_id, path_index, source_kind, completed_transaction_text, ` +
        `completed_transaction_sha256, completed_transaction_octets, wallet_role, ` +
        `s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256, ` +
        `step_1_signature, step_2_signature, verification_manifest_text, ` +
        `verification_manifest_sha256 ` +
        `FROM lineage_path_bodies WHERE path_proof_id='${pathProof.id}'` +
        `) b`,
    );
    const bodiesRaw =
      bQ.ok && bQ.stdout.trim() !== ""
        ? (JSON.parse(bQ.stdout.trim()) as Array<Record<string, unknown>>)
        : [];
    const bodies = bodiesRaw.map((c) => ({
      path_proof_id: String(c.path_proof_id),
      path_index: Number(c.path_index),
      source_kind: c.source_kind as
        | "EXPECTED_OPERATION"
        | "PROOF_CHANNEL"
        | "FRESH_GATEWAY_HEAD",
      completed_transaction_text: String(c.completed_transaction_text),
      completed_transaction_sha256: String(c.completed_transaction_sha256),
      completed_transaction_octets: Number(c.completed_transaction_octets),
      wallet_role: c.wallet_role as "sender" | "receiver",
      s_signature: String(c.s_signature),
      p_signature: String(c.p_signature),
      b_amount: String(c.b_amount),
      inner_preimage_text: String(c.inner_preimage_text),
      inner_sha256: String(c.inner_sha256),
      step_1_signature: String(c.step_1_signature),
      step_2_signature: String(c.step_2_signature),
      verification_manifest_text: String(c.verification_manifest_text),
      verification_manifest_sha256: String(c.verification_manifest_sha256),
    }));

    return { landingProof, pathProof, bodies };
  }

  async saveIndeterminateProgress(progress: LateLandingProofProgress): Promise<void> {
    const existing = await this.loadAttempt1(progress.landingProof.operationId);
    if (
      existing !== null &&
      (existing.landingProof.verdict === "LANDED_EXACT" ||
        existing.landingProof.verdict === "LANDED_COMPLETE_PATH")
    ) {
      return;
    }
    // Harness: indeterminate is not durable-written here.
    void progress;
  }

  async savePositiveProof(
    progress: LateLandingProofProgress,
  ): Promise<
    { readonly kind: "INSERTED" } | { readonly kind: "ALREADY_POSITIVE"; readonly existingId: string }
  > {
    const existing = await this.loadAttempt1(progress.landingProof.operationId);
    if (
      existing !== null &&
      (existing.landingProof.verdict === "LANDED_EXACT" ||
        existing.landingProof.verdict === "LANDED_COMPLETE_PATH")
    ) {
      return { kind: "ALREADY_POSITIVE", existingId: existing.landingProof.id };
    }

    const lp = progress.landingProof;
    const pp = progress.pathProof;
    if (pp === null) {
      throw new Error("positive proof requires pathProof");
    }

    const verifiedAt =
      lp.verifiedAtMs === null
        ? "NULL"
        : `to_timestamp(${lp.verifiedAtMs} / 1000.0)`;
    const createdAt = `to_timestamp(${lp.createdAtMs} / 1000.0)`;

    const bodyInserts = progress.bodies
      .map((b) => {
        return (
          `INSERT INTO lineage_path_bodies (` +
          `path_proof_id, path_index, source_kind, completed_transaction_text, ` +
          `completed_transaction_sha256, completed_transaction_octets, wallet_role, ` +
          `s_signature, p_signature, b_amount, inner_preimage_text, inner_sha256, ` +
          `step_1_signature, step_2_signature, ` +
          `verification_manifest_text, verification_manifest_sha256` +
          `) VALUES (` +
          `'${b.path_proof_id}', ${b.path_index}, ${sqlLit(b.source_kind)}, ` +
          `${sqlLit(b.completed_transaction_text)}, ` +
          `${sqlLit(b.completed_transaction_sha256)}, ${b.completed_transaction_octets}, ` +
          `${sqlLit(b.wallet_role)}, ` +
          `${sqlLit(b.s_signature)}, ${sqlLit(b.p_signature)}, ${sqlLit(b.b_amount)}, ` +
          `${sqlLit(b.inner_preimage_text)}, ${sqlLit(b.inner_sha256)}, ` +
          `${sqlLit(b.step_1_signature)}, ${sqlLit(b.step_2_signature)}, ` +
          `${sqlLit(b.verification_manifest_text)}, ${sqlLit(b.verification_manifest_sha256)}` +
          `);`
        );
      })
      .join("\n");

    const sql = `
BEGIN;
INSERT INTO operation_landing_proofs (
  id, operation_id, verifier_observer_id, expected_transaction_attempt_no,
  verdict, required_path_count, declared_body_count, declared_total_body_bytes,
  proof_manifest_text, proof_manifest_sha256, verified_at, created_at
) VALUES (
  '${lp.id}', '${lp.operationId}', '${lp.verifierObserverId}', 1,
  '${lp.verdict}', ${lp.requiredPathCount}, ${lp.declaredBodyCount}, ${lp.declaredTotalBodyBytes},
  ${sqlLit(lp.proofManifestText)}, ${sqlLit(lp.proofManifestSha256)},
  ${verifiedAt}, ${createdAt}
);
INSERT INTO lineage_path_proofs (
  id, landing_proof_id, path_role, wallet_id, wallet_public_key,
  t0_observation_id, fresh_head_observation_id,
  expected_completed_transaction_sha256, fresh_head_completed_transaction_sha256,
  body_count, path_depth, verdict, proof_manifest_text, proof_manifest_sha256, created_at
) VALUES (
  '${pp.id}', '${lp.id}', 'SOURCE', ${pp.wallet_id === null ? "NULL" : `'${pp.wallet_id}'`},
  ${sqlLit(pp.wallet_public_key)},
  '${pp.t0_observation_id}', '${pp.fresh_head_observation_id}',
  ${sqlLit(pp.expected_completed_transaction_sha256)},
  ${sqlLit(pp.fresh_head_completed_transaction_sha256)},
  ${pp.body_count}, ${pp.path_depth}, '${lp.verdict}',
  ${sqlLit(lp.proofManifestText)}, ${sqlLit(lp.proofManifestSha256)}, ${createdAt}
);
${bodyInserts}
COMMIT;
`;
    const result = runPsql(this.db, sql);
    if (!result.ok) {
      if (/duplicate key|unique/i.test(result.stderr)) {
        const prior = await this.loadAttempt1(lp.operationId);
        return {
          kind: "ALREADY_POSITIVE",
          existingId: prior?.landingProof.id ?? lp.id,
        };
      }
      throw new Error(`savePositiveProof PG insert failed: ${result.stderr}`);
    }
    return { kind: "INSERTED" };
  }
}

// ─── Suite ──────────────────────────────────────────────────────────────────

describe("send late-landing PG drills", () => {
  let reachable = false;
  let db: string | null = null;
  let drillsRun = 0;

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
    // Base enums/domains + nodes, then custody, then send-external create/landing.
    applyDdlFile(db, join(SCHEMA_DIR, "base-enums-domains.sql"));
    const registry = readFileSync(join(SCHEMA_DIR, "node-implementer-registry.sql"), "utf8");
    const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry)?.[0];
    if (nodes === undefined) {
      throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
    }
    try {
      execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-c", nodes], {
        encoding: "utf-8",
        timeout: 30_000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      const e = err as { stderr?: string };
      throw new Error(`nodes DDL apply failed: ${(e.stderr ?? "").trim() || "unknown"}`);
    }
    applyDdlFile(db, join(SCHEMA_DIR, "custody-eligibility.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-create.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-landing.sql"));
    applyDdlFile(db, join(SCHEMA_DIR, "send-external-expiry.sql"));
    psqlMust(
      db,
      `
DO $$ BEGIN
  CREATE TYPE lineage_proof_verdict AS ENUM (
    'LANDED_EXACT', 'LANDED_COMPLETE_PATH', 'INDETERMINATE', 'INVARIANT_BREACH'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS operation_landing_proofs (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL,
  verifier_observer_id uuid NOT NULL,
  expected_transaction_attempt_no integer NOT NULL DEFAULT 1
    CHECK (expected_transaction_attempt_no = 1),
  verdict lineage_proof_verdict NOT NULL,
  required_path_count integer NOT NULL CHECK (required_path_count IN (1, 2)),
  declared_body_count bigint NOT NULL CHECK (declared_body_count > 0),
  declared_total_body_bytes bigint NOT NULL CHECK (declared_total_body_bytes > 0),
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 text NOT NULL CHECK (proof_manifest_sha256 ~ '^[0-9a-f]{64}$'),
  verified_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (operation_id, expected_transaction_attempt_no),
  CHECK ((verdict IN ('LANDED_EXACT', 'LANDED_COMPLETE_PATH')) = (verified_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS lineage_path_proofs (
  id uuid PRIMARY KEY,
  landing_proof_id uuid NOT NULL REFERENCES operation_landing_proofs(id),
  path_role text NOT NULL CHECK (path_role IN ('RECEIVER', 'SOURCE', 'DESTINATION')),
  wallet_id uuid,
  wallet_public_key text NOT NULL,
  t0_observation_id uuid NOT NULL,
  fresh_head_observation_id uuid NOT NULL,
  expected_completed_transaction_sha256 text NOT NULL,
  fresh_head_completed_transaction_sha256 text NOT NULL,
  body_count bigint NOT NULL CHECK (body_count > 0),
  path_depth bigint NOT NULL CHECK (path_depth >= 0 AND path_depth = body_count - 1),
  verdict lineage_proof_verdict NOT NULL,
  proof_manifest_text text NOT NULL,
  proof_manifest_sha256 text NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (landing_proof_id, path_role)
);

CREATE TABLE IF NOT EXISTS lineage_path_bodies (
  path_proof_id uuid NOT NULL REFERENCES lineage_path_proofs(id),
  path_index bigint NOT NULL CHECK (path_index >= 0),
  source_kind text NOT NULL CHECK (source_kind IN
    ('EXPECTED_OPERATION', 'CANONICAL_LEDGER', 'PROOF_CHANNEL', 'FRESH_GATEWAY_HEAD')),
  completed_transaction_text text NOT NULL,
  completed_transaction_sha256 text NOT NULL,
  completed_transaction_octets bigint NOT NULL CHECK (completed_transaction_octets > 0),
  wallet_role text NOT NULL CHECK (wallet_role IN ('sender', 'receiver')),
  s_signature text NOT NULL,
  p_signature text NOT NULL,
  b_amount text NOT NULL,
  inner_preimage_text text NOT NULL,
  inner_sha256 text NOT NULL,
  step_1_signature text NOT NULL,
  step_2_signature text NOT NULL,
  verification_manifest_text text NOT NULL,
  verification_manifest_sha256 text NOT NULL,
  PRIMARY KEY (path_proof_id, path_index),
  CHECK (octet_length(completed_transaction_text) = completed_transaction_octets)
);
`,
    );
    seedNode(db);
    seedWallet(db, WALLET_ID);
  });

  afterAll(() => {
    if (db !== null && reachable) {
      runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
    }
    if (reachable && drillsRun < EXPECTED_DRILL_COUNT) {
      throw new Error(
        `send-late-landing PG drills incomplete: ran ${drillsRun}/${EXPECTED_DRILL_COUNT}`,
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

  it("1. applyLateLandingCycle depth-1 land → complete-path bodies + head + lease", async () => {
    if (skip()) return;
    drillsRun += 1;

    insertOp(db!, OP_A, "NEEDS_ATTENTION", "idem-apply-depth1-001", true);
    const c = buildCandidate();
    const landingStore = new PsqlExternalSendLandingStore(db!);
    const proofStore = new PsqlSendLateLandingProofStore(db!);
    const hop3Sha = sha256Hex(HOP3.text);

    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c, OP_A),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_100,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("LANDED");
    if (outcome.kind !== "LANDED") return;
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(outcome.commit.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(outcome.commit.record.attemptPhase).toBe(SETTLED_BODY_PERSISTED_PHASE);
    expect(outcome.proofProgress.bodies).toHaveLength(2);
    expect(outcome.proofProgress.pathProof?.path_depth).toBe(1);
    expect(outcome.proofProgress.pathProof?.body_count).toBe(2);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).toBe(hop3Sha);
    expect(outcome.proofProgress.pathProof?.fresh_head_completed_transaction_sha256).not.toBe(
      c.bodySha,
    );
    expect(outcome.proofProgress.landingProof.declaredBodyCount).toBe(2);
    const sumBytes = outcome.proofProgress.bodies.reduce(
      (n, b) => n + b.completed_transaction_octets,
      0,
    );
    expect(outcome.proofProgress.landingProof.declaredTotalBodyBytes).toBe(sumBytes);

    // Durable PG assertions — module wrote rows.
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_A}'`).stdout.trim(),
    ).toBe("EXTERNAL_SEND_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`,
      ).stdout.trim(),
    ).toBe("SEND_SOURCE");
    expect(
      runPsql(
        db!,
        `SELECT verdict||'|'||declared_body_count::text FROM operation_landing_proofs WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("LANDED_COMPLETE_PATH|2");
    expect(
      runPsql(
        db!,
        `SELECT body_count::text||'|'||path_depth::text||'|'||fresh_head_completed_transaction_sha256 ` +
          `FROM lineage_path_proofs WHERE landing_proof_id = ` +
          `(SELECT id FROM operation_landing_proofs WHERE operation_id='${OP_A}')`,
      ).stdout.trim(),
    ).toBe(`2|1|${hop3Sha}`);
    expect(
      runPsql(
        db!,
        `SELECT count(*)::text||'|'||string_agg(path_index::text, ',' ORDER BY path_index) ` +
          `FROM lineage_path_bodies WHERE path_proof_id = ` +
          `(SELECT id FROM lineage_path_proofs WHERE landing_proof_id = ` +
          `(SELECT id FROM operation_landing_proofs WHERE operation_id='${OP_A}'))`,
      ).stdout.trim(),
    ).toBe("2|0,1");
    expect(
      runPsql(
        db!,
        `SELECT completed_transaction_sha256 FROM lineage_path_bodies ` +
          `WHERE path_index = 1 AND path_proof_id = ` +
          `(SELECT id FROM lineage_path_proofs WHERE landing_proof_id = ` +
          `(SELECT id FROM operation_landing_proofs WHERE operation_id='${OP_A}'))`,
      ).stdout.trim(),
    ).toBe(hop3Sha);
  });

    it("2. second apply after land → ALREADY_LANDED; single row; status EXTERNAL_SEND_LANDED", async () => {
    if (skip()) return;
    drillsRun += 1;

    // OP_A already landed in drill 1. Fresh stores load durable positive proof and
    // see EXTERNAL_SEND_LANDED via land CAS — never a second positive row.
    const c = buildCandidate();
    const landingStore = new PsqlExternalSendLandingStore(db!);
    const proofStore = new PsqlSendLateLandingProofStore(db!);

    const second = await applyLateLandingCycle(
      {
        facts: facts(c, OP_A),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_200,
      },
      { landingStore, proofStore },
    );

    expect(second.kind).toBe("ALREADY_LANDED");
    expect(second.sourceLeaseStillHeld).toBe(true);
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_A}'`).stdout.trim(),
    ).toBe("EXTERNAL_SEND_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM operation_landing_proofs WHERE operation_id='${OP_A}'`,
      ).stdout.trim(),
    ).toBe("1");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM lineage_path_bodies WHERE path_proof_id IN ` +
          `(SELECT id FROM lineage_path_proofs WHERE landing_proof_id IN ` +
          `(SELECT id FROM operation_landing_proofs WHERE operation_id='${OP_A}'))`,
      ).stdout.trim(),
    ).toBe("2");
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`)
        .stdout.trim(),
    ).toBe("SEND_SOURCE");
  });

it("3. NEEDS_ATTENTION → EXTERNAL_SEND_LANDED hand SQL co-commit; lease held", () => {
    if (skip()) return;
    drillsRun += 1;
    insertOp(db!, OP_B, "NEEDS_ATTENTION", "idem-late-land-001", true);
    const land = runPsql(
      db!,
      atomicLandSql(OP_B, "NEEDS_ATTENTION", '{"inner":{},"step_1_signature":"x","step_2_signature":"y"}', SHA, "LANDED_EXACT", 0, OBS_ID),
    );
    expect(land.ok, land.stderr).toBe(true);
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_B}'`).stdout.trim(),
    ).toBe("EXTERNAL_SEND_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT attempt_phase||'|'||entry_status FROM external_send_landing_records WHERE operation_id='${OP_B}'`,
      ).stdout.trim(),
    ).toBe("SETTLED_BODY_PERSISTED|NEEDS_ATTENTION");
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`)
        .stdout.trim(),
    ).toBe("SEND_SOURCE");
  });

  it("4. landing SQL never deletes wallet_active_leases; lease still SEND_SOURCE", () => {
    if (skip()) return;
    drillsRun += 1;
    const storeSrc = readFileSync(join(HERE, "../src/send/landing-sql-store.ts"), "utf8");
    const lateSrc = readFileSync(join(HERE, "../src/send/late-landing-reconcile.ts"), "utf8");
    expect(storeSrc.toUpperCase()).not.toContain("DELETE FROM WALLET_ACTIVE_LEASES");
    expect(lateSrc).not.toMatch(/query\([^)]*DELETE\s+FROM\s+wallet_active_leases/i);
    expect(
      runPsql(db!, `SELECT count(*) FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`)
        .stdout.trim(),
    ).toBe("1");
  });

  it("5. applyLateLandingCycle incomplete → NEEDS_ATTENTION; no land; lease held", async () => {
    if (skip()) return;
    drillsRun += 1;
    insertOp(db!, OP_C, "NEEDS_ATTENTION", "idem-late-indeterminate-001", true);
    const c = buildCandidate();
    const landingStore = new PsqlExternalSendLandingStore(db!);
    const proofStore = new PsqlSendLateLandingProofStore(db!);

    // Head is HOP3 but no successor body supplied → oracle incomplete.
    const outcome = await applyLateLandingCycle(
      {
        facts: facts(c, OP_C),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_500,
      },
      { landingStore, proofStore },
    );

    expect(outcome.kind).toBe("REMAIN_ATTENTION");
    expect(outcome.sourceLeaseStillHeld).toBe(true);
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_C}'`).stdout.trim(),
    ).toBe("NEEDS_ATTENTION");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM external_send_landing_records WHERE operation_id='${OP_C}'`,
      ).stdout.trim(),
    ).toBe("0");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM operation_landing_proofs WHERE operation_id='${OP_C}' AND verdict IN ('LANDED_EXACT','LANDED_COMPLETE_PATH')`,
      ).stdout.trim(),
    ).toBe("0");
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`)
        .stdout.trim(),
    ).toBe("SEND_SOURCE");
  });

  it("6. crash after positive proof before land; fresh store recovers EXTERNAL_SEND_LANDED", async () => {
    if (skip()) return;
    drillsRun += 1;

    // Drill 5 left OP_C unsettled on WALLET_ID — one-unsettled-per-source constraint.
    // Park OP_C out of the entry set so OP_D can own the wallet for this recovery drill.
    psqlMust(
      db!,
      `UPDATE send_operations SET status = 'EXTERNAL_SEND_LANDED', ` +
        `attention_required = false, attention_reason = NULL ` +
        `WHERE operation_id = '${OP_C}'`,
    );

    insertOp(db!, OP_D, "NEEDS_ATTENTION", "idem-crash-recover-001", true);
    const c = buildCandidate();
    const hop3Sha = sha256Hex(HOP3.text);

    // Cycle 1: proof store works; landing commit always fails (crash window).
    const proofStore1 = new PsqlSendLateLandingProofStore(db!);
    const failingLanding: ExternalSendLandingStore = {
      commitLanding: async () => ({
        applied: false,
        reason: "STATUS_GUARD_MISMATCH",
        sourceLeaseStillHeld: true,
      }),
    };

    const first = await applyLateLandingCycle(
      {
        facts: facts(c, OP_D),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_600,
      },
      { landingStore: failingLanding, proofStore: proofStore1 },
    );
    expect(first.kind).toBe("REMAIN_ATTENTION");
    expect(first.sourceLeaseStillHeld).toBe(true);
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_D}'`).stdout.trim(),
    ).toBe("NEEDS_ATTENTION");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM operation_landing_proofs WHERE operation_id='${OP_D}' ` +
          `AND verdict = 'LANDED_COMPLETE_PATH'`,
      ).stdout.trim(),
    ).toBe("1");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM external_send_landing_records WHERE operation_id='${OP_D}'`,
      ).stdout.trim(),
    ).toBe("0");

    // Cycle 2: brand-new store instances (empty process mem) SELECT proof and land.
    const proofStore2 = new PsqlSendLateLandingProofStore(db!);
    const landingStore2 = new PsqlExternalSendLandingStore(db!);
    const second = await applyLateLandingCycle(
      {
        facts: facts(c, OP_D),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_700,
      },
      { landingStore: landingStore2, proofStore: proofStore2 },
    );

    expect(second.kind).toBe("LANDED");
    if (second.kind !== "LANDED") return;
    expect(second.commit.status).toBe(EXTERNAL_SEND_LANDED_STATUS);
    expect(second.sourceLeaseStillHeld).toBe(true);
    expect(
      runPsql(db!, `SELECT status FROM send_operations WHERE operation_id='${OP_D}'`).stdout.trim(),
    ).toBe("EXTERNAL_SEND_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM operation_landing_proofs WHERE operation_id='${OP_D}'`,
      ).stdout.trim(),
    ).toBe("1");
    expect(
      runPsql(
        db!,
        `SELECT fresh_head_completed_transaction_sha256 FROM lineage_path_proofs WHERE landing_proof_id = ` +
          `(SELECT id FROM operation_landing_proofs WHERE operation_id='${OP_D}')`,
      ).stdout.trim(),
    ).toBe(hop3Sha);
    expect(
      runPsql(db!, `SELECT lease_role FROM wallet_active_leases WHERE wallet_id='${WALLET_ID}'`)
        .stdout.trim(),
    ).toBe("SEND_SOURCE");

    // Cycle 3: already landed → ALREADY_LANDED, still one proof row.
    const third = await applyLateLandingCycle(
      {
        facts: facts(c, OP_D),
        sourceObservation: { result: "NO_SUCCESSOR" },
        successorBodies: [HOP3.body],
        readFreshHead: staticReader(HOP3.text, OBS_ID),
        nowMs: 1_700_000_000_800,
      },
      {
        landingStore: new PsqlExternalSendLandingStore(db!),
        proofStore: new PsqlSendLateLandingProofStore(db!),
      },
    );
    expect(third.kind).toBe("ALREADY_LANDED");
    expect(
      runPsql(
        db!,
        `SELECT count(*) FROM operation_landing_proofs WHERE operation_id='${OP_D}'`,
      ).stdout.trim(),
    ).toBe("1");
  });

});
