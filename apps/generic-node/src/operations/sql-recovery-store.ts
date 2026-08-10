// SQL-backed RecoveryActionStore + RecoveryInspectionStore for admin recovery.
// Replaces the fail-closed stubs in createFailClosedAdminRouteDeps.

import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";

import {
  isOperationKind,
  isUniqueViolation,
  sha256HexUtf8,
  LEASE_STATEMENTS,
  SqlReceiveExpiryReleaseService,
  withSerializationRetry,
  DEFAULT_SERIALIZATION_RETRY_POLICY,
  redeliverExactPartialViaSql,
  createSqlRetainedPathBodySource,
  fetchRetainedBodyByObservationId,
  proveSendNonLanding,
  mintReleaseProof,
  releaseLease,
  completeGroupOperation,
  type OperationKind,
  type RecoveryActionStore,
  type RecoveryActionCommitInput,
  type RecoveryActionCommitResult,
  type RecoveryActionSuccessBody,
  type RecoveryActionEffect,
  type RecoveryFacts,
  type RecoveryInspectionStore,
  type IssuedRecoveryNonce,
  type NeedsAttentionQuery,
  type EvidenceManifestEntry,
  type PathBaseline,
  type ReadFreshHead,
  type SendNonLandingOutcome,
  type LeaseSqlExecutor,
} from "@zucoins/node-core";

function parseOperationKind(value: string): OperationKind {
  if (!isOperationKind(value)) throw new Error(`unrecognized operation kind: ${value}`);
  return value;
}

const LANDING_VERDICTS = ["LANDED_EXACT", "LANDED_COMPLETE_PATH"] as const;
type LandingVerdict = (typeof LANDING_VERDICTS)[number];
function isLandingVerdict(value: string): value is LandingVerdict {
  return (LANDING_VERDICTS as readonly string[]).includes(value);
}
function parseLandingVerdict(value: string): LandingVerdict {
  if (!isLandingVerdict(value)) throw new Error(`unrecognized landing verdict: ${value}`);
  return value;
}

// Margin added on top of expiry_unix_time_secs before treating a receive as
// expired, so a code that lapses mid-request is never raced against wall-clock skew.
const RECEIVE_EXPIRY_SAFETY_MARGIN_SECS = 30;

// Statuses under which a spawned child operation counts as "absent or terminal" for
// receiveExpiredNoPaymentAllFive's childAbsentOrTerminal predicate.
const TERMINAL_OPERATION_STATUSES: ReadonlySet<string> = new Set([
  "RECEIVE_LANDED", "INTERNAL_MOVE_LANDED", "EXTERNAL_SEND_LANDED", "EXPIRED", "REJECTED",
]);

// Closed set of effect kinds this store commits. Unknown future kinds fail closed
// (effect_not_implemented) before nonce/TOTP burn — never a silent no-op success.
// CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED and REBUILD_INTERNAL_MOVE remain RESERVED at the
// planning/admission layer (halt.contract RESERVED_RECOVERY_ACTIONS) but still have
// real commit arms so a permitted POST cannot report success without mutation.
export const IMPLEMENTED_EFFECT_KINDS: ReadonlySet<RecoveryActionEffect["kind"]> = new Set([
  "RETRY_OBSERVATION",
  "ACKNOWLEDGE_KEEP_PINNED",
  "QUARANTINE_WALLETS",
  "RELEASE_EXPIRED_RECEIVE",
  "REDELIVER_EXACT_PARTIAL",
  "CONTINUE_EXTERNAL_WAIT",
  "CLOSE_NEVER_STARTED_EXTERNAL_SEND",
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "REBUILD_INTERNAL_MOVE",
]);

function isImplementedEffect(effect: RecoveryActionEffect): boolean {
  return IMPLEMENTED_EFFECT_KINDS.has(effect.kind);
}

/** Plain-language labels for operator UI. */
export const RECOVERY_ACTION_LABELS: Readonly<Record<RecoveryActionEffect["kind"], string>> = {
  RETRY_OBSERVATION: "Retry observation",
  REDELIVER_EXACT_PARTIAL: "Re-send exact transfer code",
  CONTINUE_EXTERNAL_WAIT: "Continue waiting for redemption",
  CLOSE_NEVER_STARTED_EXTERNAL_SEND: "Close never-started send",
  CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED: "Close send (proven not landed)",
  REBUILD_INTERNAL_MOVE: "Rebuild internal transfer",
  RELEASE_EXPIRED_RECEIVE: "Release expired receive",
  QUARANTINE_WALLETS: "Quarantine wallets",
  ACKNOWLEDGE_KEEP_PINNED: "Acknowledge (keep pinned)",
};

/** Recovery actions reserved at launch — UI must not offer as live success paths. */
export const LAUNCH_RESERVED_RECOVERY_ACTIONS = [
  "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED",
  "REBUILD_INTERNAL_MOVE",
] as const;

/**
 * The single switch that would make CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED reachable at
 * runtime — and it is deliberately off.
 *
 * The non-landing exclusion oracle below is live: it reads the source head through the
 * observation service, walks the retained T0→head path, and records what it found on every
 * operation's evidence manifest. What it may NOT do yet is set the two close predicates,
 * because the action it feeds is RESERVED in the frozen contract
 * (`generic-node-contracts/operator-halt/halt.contract.ts` RESERVED_RECOVERY_ACTIONS: "they
 * cannot be granted at runtime"), and the decision register does not grant it: D9.6 ("There
 * is no generic PROVEN_NOT_LANDED oracle"), D10.21(1) (the closed determination space has no
 * PROVEN_NOT_LANDED member), and D9.15 (folding a non-landing into a release "reopens
 * landed-into-released-wallet loss"). 09-operations-recovery.md §"Allowed action values" and
 * Appendix B §5.3.1's RESERVED note both defer to D9.6.
 *
 * Flipping this to true is the whole of runtime activation, and it belongs to the reviewed
 * freeze decision that authorizes it — not to a reading of the oracle's own correctness.
 */
const SEND_NON_LANDING_CLOSE_ACTIVATED = false;

const SQL_LOOKUP_IDEMPOTENCY = `
  SELECT body FROM recovery_action_idempotency
   WHERE operation_id = $1::uuid AND idempotency_key = $2
`;

const SQL_STORE_IDEMPOTENCY = `
  INSERT INTO recovery_action_idempotency (operation_id, idempotency_key, body, created_at)
  VALUES ($1::uuid, $2, $3, now())
  ON CONFLICT (operation_id, idempotency_key) DO NOTHING
`;

const SQL_LIST_NEEDS_ATTENTION = `
  SELECT id::text AS operation_id, kind::text AS kind, status::text AS status,
         attention_required, attention_reason, row_version::int AS row_version,
         t0_observation_id::text AS t0_observation_id,
         terminal_observation_id::text AS terminal_observation_id,
         expiry_unix_time_secs, formation_state::text AS formation_state
    FROM operations
   WHERE (attention_required = true OR status = 'NEEDS_ATTENTION')
     AND ($2::text IS NULL OR kind::text = $2)
   ORDER BY created_at ASC -- contract-allow:order:frozen structural vocabulary
   LIMIT $1
`;

const SQL_LOAD_RECOVERY_FACTS = `
  SELECT o.id::text AS operation_id, o.kind::text AS kind, o.status::text AS status,
         o.attention_required, o.attention_reason, o.row_version::int AS row_version,
         o.t0_observation_id::text AS t0_observation_id,
         o.terminal_observation_id::text AS terminal_observation_id,
         o.verification_material_available_until,
         o.expiry_unix_time_secs, o.formation_state::text AS formation_state
    FROM operations o
   WHERE o.id = $1::uuid
`;

const SQL_ISSUE_RECOVERY_NONCE = `
  INSERT INTO recovery_nonces (id, node_id, operation_id, status, nonce, issued_at, expires_at)
  SELECT $1::uuid, o.node_id, o.id, 'ISSUED', $2::uuid, now(), now() + interval '5 minutes'
    FROM operations o WHERE o.id = $3::uuid
  RETURNING nonce::text, issued_at::text, expires_at::text
`;

const SQL_SUPERSEDE_PRIOR_NONCES = `
  UPDATE recovery_nonces
     SET status = 'SUPERSEDED', superseded_by = $1::uuid
   WHERE operation_id = $2::uuid AND status = 'ISSUED' AND id <> $1::uuid
`;

// expires_at check: a nonce past its 5-minute window is treated exactly like a wrong
// or already-consumed nonce (recovery_nonce_invalid), never silently accepted.
// RETURNING node_id::text sources the actor's node for the TOTP-burn and audit_log
// inserts below without requiring a second round trip or a change to the frozen
// RecoveryActionCommitInput shape (it carries no node_id field).
const SQL_CONSUME_NONCE = `
  UPDATE recovery_nonces
     SET status = 'CONSUMED', consumed_at = now()
   WHERE operation_id = $1::uuid AND nonce = $2::uuid AND status = 'ISSUED'
     AND expires_at > now()
  RETURNING node_id::text AS node_id
`;

const SQL_BURN_TOTP_TIMESTEP = `
  INSERT INTO totp_timestep_burns (id, node_id, totp_timestep, purpose, operation_id, burned_at)
  VALUES ($1::uuid, $2::uuid, $3, 'RECOVERY_ACTION', $4::uuid, now())
`;

// Simple CAS bump: RETRY_OBSERVATION and ACKNOWLEDGE_KEEP_PINNED never touch status or
// attention_required (per operations' attention_required = (attention_reason IS NOT NULL)
// CHECK, neither planRecoveryEffect output touches either column), so the only mutation
// is the row_version bump itself, gated by the CAS predicate.
const SQL_CAS_BUMP_ROW_VERSION = `
  UPDATE operations
     SET row_version = row_version + 1
   WHERE id = $1::uuid AND row_version = $2
  RETURNING row_version::int AS row_version, status::text AS status
`;

// CONTINUE_EXTERNAL_WAIT — NEEDS_ATTENTION → AWAITING_REDEMPTION with durable
// partial. formation_state forced to PARTIAL_DELIVERED (legal pair under operations CHECK).
const SQL_CAS_CONTINUE_EXTERNAL_WAIT = `
  UPDATE operations
     SET status = 'AWAITING_REDEMPTION',
         formation_state = 'PARTIAL_DELIVERED',
         attention_required = false,
         attention_reason = NULL,
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND row_version = $2
     AND kind = 'SEND_EXTERNAL'
     AND status = 'NEEDS_ATTENTION'
     AND attention_required = true
     AND EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1::uuid)
  RETURNING row_version::int AS row_version, status::text AS status
`;

// CLOSE_NEVER_STARTED — APPROVED→REJECTED only when every formation negative holds.
const SQL_CAS_CLOSE_NEVER_STARTED = `
  UPDATE operations
     SET status = 'REJECTED',
         attention_required = false,
         attention_reason = NULL,
         terminal_at = coalesce(terminal_at, now()),
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND row_version = $2
     AND kind = 'SEND_EXTERNAL'
     AND status = 'APPROVED'
     AND NOT EXISTS (SELECT 1 FROM external_send_sign_intents s WHERE s.operation_id = $1::uuid)
     AND NOT EXISTS (SELECT 1 FROM external_send_partials p WHERE p.operation_id = $1::uuid)
     AND NOT EXISTS (SELECT 1 FROM signer_audit a WHERE a.operation_id = $1::uuid)
  RETURNING row_version::int AS row_version, status::text AS status
`;

// CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED — NEEDS_ATTENTION→REJECTED (planner already
// re-proved the landing oracle). Partial/approval/audit rows are deliberately untouched.
const SQL_CAS_CLOSE_PROVEN_NOT_LANDED = `
  UPDATE operations
     SET status = 'REJECTED',
         attention_required = false,
         attention_reason = NULL,
         terminal_at = coalesce(terminal_at, now()),
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND row_version = $2
     AND kind = 'SEND_EXTERNAL'
     AND status = 'NEEDS_ATTENTION'
  RETURNING row_version::int AS row_version, status::text AS status
`;

// REBUILD_INTERNAL_MOVE — archive-and-reset to CREATED. attempt_no stays 1 in
// transaction-material (CHECK attempt_no = 1); "next attempt" is the new CREATED cycle with
// attention cleared. Old operation_transactions rows are left unchanged (never resubmitted).
const SQL_CAS_REBUILD_INTERNAL_MOVE = `
  UPDATE operations
     SET status = 'CREATED',
         attention_required = false,
         attention_reason = NULL,
         row_version = row_version + 1,
         updated_at = now()
   WHERE id = $1::uuid
     AND row_version = $2
     AND kind = 'MOVE_INTERNAL'
     AND status = 'NEEDS_ATTENTION'
  RETURNING row_version::int AS row_version, status::text AS status
`;

const SQL_LOAD_ACTIVE_LEASE_FOR_RELEASE = `
  SELECT wallet_id::text AS wallet_id,
         membership_id::text AS membership_id,
         lease_group_id::text AS lease_group_id,
         operation_id::text AS operation_id,
         lease_epoch::text AS lease_epoch,
         owner_instance_id::text AS owner_instance_id
    FROM wallet_active_leases
   WHERE operation_id = $1::uuid
   FOR UPDATE
`;

const CLOSE_SEND_RELEASE_REASON = "RECOVERY_CLOSE_SEND" as const;
const CLOSE_SEND_PROOF_KIND = "EXTERNAL_SEND_LANDED" as const;

/** Pass-through lease SqlExecutor bound to an open SERIALIZABLE client. */
function clientAsSqlExecutor(client: PoolClient): LeaseSqlExecutor {
  return {
    query: async <R>(text: string, params: readonly unknown[] = []) => {
      const result = await client.query(text, params as never[]);
      return { rows: result.rows as R[], rowCount: result.rowCount ?? 0 };
    },
  };
}

async function releaseSourceLeasesForOperation(
  client: PoolClient,
  operationId: string,
): Promise<void> {
  const db = clientAsSqlExecutor(client);
  const leases = await client.query<{
    wallet_id: string;
    membership_id: string;
    lease_group_id: string;
    operation_id: string;
    lease_epoch: string;
    owner_instance_id: string;
  }>(SQL_LOAD_ACTIVE_LEASE_FOR_RELEASE, [operationId]);

  for (const lease of leases.rows) {
    await completeGroupOperation(db, {
      leaseGroupId: lease.lease_group_id,
      operationId: lease.operation_id,
    });
    const proofId = randomUUID();
    const digest = sha256HexUtf8(
      `recovery-close:${operationId}:${lease.wallet_id}:${lease.membership_id}:${lease.lease_epoch}`,
    );
    await mintReleaseProof(db, {
      proofId,
      walletId: lease.wallet_id,
      operationId: lease.operation_id,
      membershipId: lease.membership_id,
      leaseGroupId: lease.lease_group_id,
      leaseEpoch: BigInt(lease.lease_epoch),
      proofKind: CLOSE_SEND_PROOF_KIND,
      proofDigest: digest,
    });
    await releaseLease(db, {
      walletId: lease.wallet_id,
      ownerInstanceId: lease.owner_instance_id,
      operationId: lease.operation_id,
      membershipId: lease.membership_id,
      leaseGroupId: lease.lease_group_id,
      leaseEpoch: BigInt(lease.lease_epoch),
      releaseProofId: proofId,
      releaseReason: CLOSE_SEND_RELEASE_REASON,
    });
  }
}

// Route A: pre-BEGIN, non-locking wallet identity source for the confirm-read.
// Wallet identity for release/quarantine comes from the lease + operation_wallets,
// never operations.receiver_wallet_id (a nullable projection). Unlike wallet_active_leases,
// operation_wallets is never deleted on release, so this is safe to read ahead of the lock.
const SQL_RECEIVER_WALLET_PUBLIC_KEY = `
  SELECT w.public_key
    FROM operation_wallets ow
    JOIN wallets w ON w.id = ow.wallet_id
   WHERE ow.operation_id = $1::uuid AND ow.operation_role = 'RECEIVER'
`;

// SqlReceiveExpiryReleaseService's success outcomes never carry the final
// row_version (SET_RELEASE_STATUS's RETURNING only exposes receive_release_status), so the
// store re-reads it here — same client, same still-open transaction, on a row the service
// has already locked, so this is a non-locking read of an already-settled value.
const SQL_OPERATION_ROW_VERSION = `
  SELECT row_version::int AS row_version FROM operations WHERE id = $1::uuid
`;

const SQL_INSERT_AUDIT_LOG = `
  INSERT INTO audit_log (id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
                          details_text, details_sha256, created_at)
  VALUES ($1::uuid, $2::uuid, 'OPERATOR_SESSION', $3, $4, $5::uuid, NULL, $6, $7, now())
`;

// Fact-gatherer queries. Each is a plain existence/value lookup keyed on
// operation_id (or a small batch of observation ids); none of them mutate.

const SQL_HAS_T0_BINDING = `
  SELECT 1 FROM operation_observation_bindings
   WHERE operation_id = $1::uuid AND evidence_role = 'RECEIVER_T0'
`;

const SQL_RECEIVE_CODE_STATUS = `
  SELECT code_status FROM receive_codes WHERE operation_id = $1::uuid
`;

const SQL_EXPECTED_ARTIFACT = `
  SELECT id::text AS id, preimage_sha256 FROM operation_expected_artifacts
   WHERE operation_id = $1::uuid
`;

// Money-path signing purposes whose exact preimage must have a durable home.
// EXPECTED_ARTIFACT bytes live in operation_expected_artifacts; STEP_1/STEP_2 in
// operation_transactions. REPORTING_ENVELOPE / DEVICE_APPROVAL are not measured here
// (same split as boot recovery's signer_audit_present — see sql-boot-recovery.ts).
const SQL_MONEY_PATH_SIGNER_AUDITS = `
  SELECT preimage_sha256, purpose
    FROM signer_audit
   WHERE operation_id = $1::uuid
     AND purpose IN ('STEP_1', 'STEP_2', 'EXPECTED_ARTIFACT')
`;

// Any signer_audit row (all purposes) still proves the formation boundary was crossed.
const SQL_HAS_SIGNER_AUDIT = `
  SELECT 1 FROM signer_audit WHERE operation_id = $1::uuid
`;

// Durable digests that may back a money-path signer call for this operation.
const SQL_OPERATION_TRANSACTION_PREIMAGE_DIGESTS = `
  SELECT inner_sha256, step_2_preimage_sha256
    FROM operation_transactions
   WHERE operation_id = $1::uuid
`;

const SQL_OBSERVATION_BY_ID = `
  SELECT id::text AS id, parse_result::text AS parse_result, s_signature, p_signature,
         b_amount, completed_transaction_sha256
    FROM gateway_observations WHERE id = $1::uuid
`;

const SQL_CHILD_OPERATION_STATUSES = `
  SELECT status::text AS status FROM operations WHERE spawned_from_operation_id = $1::uuid
`;

// operation_transactions IS the receive signing/submit
// ladder (INNER_PREIMAGE_PERSISTED → ... → SETTLED_BODY_PERSISTED), and gateway_submit_attempts
// is durable submit evidence. Either existing, without a landing proof, is exactly the
// "reconcile by receiver observation" case — never treat it as clean.
const SQL_HAS_OPERATION_TRANSACTION = `
  SELECT 1 FROM operation_transactions WHERE operation_id = $1::uuid
`;

// F1.2's two live inputs come from the chain, not from storage: the source wallet's public
// key to read the head under, the send's recorded Ts0 observation to compare it against, and
// the step-1 signature the exclusion walk hunts for. Read-only, one row.
const SQL_SEND_NON_LANDING_MATERIAL = `
  SELECT w.public_key AS source_pubkey,
         si.source_t0_observation_id::text AS source_t0_observation_id,
         t0.completed_transaction_text AS source_t0_body_text,
         p.step_1_signature AS step_1_signature
    FROM send_operations s
    JOIN wallets w ON w.id = s.source_wallet_id
    JOIN external_send_partials p ON p.operation_id = s.operation_id
    LEFT JOIN external_send_sign_intents si ON si.operation_id = s.operation_id
    LEFT JOIN gateway_observations t0 ON t0.id = si.source_t0_observation_id
   WHERE s.operation_id = $1::uuid
`;

/**
 * Run the non-landing exclusion oracle for one parked SEND_EXTERNAL.
 *
 * Returns the outcome plus an evidence-manifest summary of what was read. A null outcome
 * means the oracle was never asked (no Ts0 binding, no retained Ts0 body) — indistinguishable
 * from INDETERMINATE at the fact level, both leave the two predicates false.
 */
async function proveSendNonLandingForOperation(
  pool: Pool,
  operationId: string,
  readFreshHead: ReadFreshHead,
): Promise<{ readonly outcome: SendNonLandingOutcome | null; readonly summary: string }> {
  const row = (await pool.query<{
    source_pubkey: string;
    source_t0_observation_id: string | null;
    source_t0_body_text: string | null;
    step_1_signature: string;
  }>(SQL_SEND_NON_LANDING_MATERIAL, [operationId])).rows[0];

  if (row === undefined || row.source_t0_observation_id === null) {
    return { outcome: null, summary: "non-landing exclusion not attempted: no source Ts0 binding" };
  }

  let baseline: PathBaseline;
  if (row.source_t0_body_text === null) {
    baseline = { kind: "GENESIS", observation_id: row.source_t0_observation_id };
  } else {
    const t0Body = await fetchRetainedBodyByObservationId({ sql: pool }, row.source_t0_observation_id);
    if (t0Body === null) {
      return {
        outcome: null,
        summary: "non-landing exclusion not attempted: source Ts0 retained body absent",
      };
    }
    baseline = { kind: "HEAD", body: t0Body };
  }

  const outcome = await proveSendNonLanding(
    {
      walletPublicKey: row.source_pubkey,
      baseline,
      step1Signature: row.step_1_signature,
    },
    createSqlRetainedPathBodySource({ sql: pool }),
    readFreshHead,
  );
  const summary =
    outcome.kind === "INDETERMINATE"
      ? `non-landing exclusion INDETERMINATE (${outcome.fault})`
      : outcome.kind === "OWN_SEND_ON_PATH"
        ? "non-landing exclusion refused: this send is ON the source path (late landing)"
        : `non-landing exclusion ${outcome.kind}`;
  return { outcome, summary };
}

const SQL_HAS_SUBMIT_ATTEMPT = `
  SELECT 1 FROM gateway_submit_attempts WHERE operation_id = $1::uuid
`;

// `readFreshHead` is the same Route A confirm-read the action store takes. Without it the
// SEND non-landing exclusion oracle is never asked and both its predicates stay false, so a
// composition that cannot reach a gateway degrades to the pre-oracle behaviour rather than
// guessing.
export function createSqlRecoveryInspectionStore(
  pool: Pool,
  readFreshHead?: ReadFreshHead,
): RecoveryInspectionStore {
  return {
    // kind is bound into SQL before LIMIT (ZTR-1198). classification is derived at read
    // time by classifyRecovery (not a durable column), so it still filters in
    // handleNeedsAttention after the page is truncated — a short page is possible when
    // classification is set. Follow-up: denormalize classification or over-fetch+repage.
    //
    // `readFreshHead` is deliberately NOT threaded into the listing. Every parked SEND in it
    // is past T2 + the aging margin with a durable partial by construction (that is what
    // parked MEANS), so passing it would run the non-landing exclusion oracle once per row —
    // two live gateway head reads plus up to `DEFAULT_MAX_PATH_DEPTH` successor lookups per
    // send, up to `limit` (200) times, inside one synchronous operator HTTP request. The
    // oracle belongs on the single-operation paths below, which is where an operator actually
    // decides an action; a listing that omits it is fail-closed (both predicates false), never
    // wrong in the permissive direction.
    async listNeedsAttention(query: NeedsAttentionQuery): Promise<readonly RecoveryFacts[]> {
      const limit = query.limit ?? 50;
      const result = await pool.query<{
        operation_id: string; kind: string; status: string;
        attention_required: boolean; attention_reason: string | null; row_version: number;
        t0_observation_id: string | null; terminal_observation_id: string | null;
        expiry_unix_time_secs: string | null; formation_state: string | null;
      }>(SQL_LIST_NEEDS_ATTENTION, [limit, query.kind ?? null]);
      const facts: RecoveryFacts[] = [];
      for (const r of result.rows) {
        const f = await loadRecoveryFactsFromRow(pool, r.operation_id, r.kind, r.status,
          r.attention_required, r.attention_reason, r.row_version, {
            t0ObservationId: r.t0_observation_id,
            terminalObservationId: r.terminal_observation_id,
            expiryUnixTimeSecs: r.expiry_unix_time_secs,
            formationState: r.formation_state,
          });
        if (f !== null) facts.push(f);
      }
      return facts;
    },

    async loadRecoveryFacts(operationId: string): Promise<RecoveryFacts | null> {
      return loadRecoveryFactsById(pool, operationId, readFreshHead);
    },

    async issueRecoveryNonce(operationId: string): Promise<IssuedRecoveryNonce> {
      const nonceId = randomUUID();
      const nonce = randomUUID();
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        // Supersede prior ISSUED nonces for this operation before inserting the new one —
        // the partial unique index on (operation_id) WHERE status='ISSUED' is immediate
        // and non-deferrable, so this ordering (supersede, then insert) inside one
        // transaction is required; the FK on superseded_by is DEFERRABLE INITIALLY
        // DEFERRED so it validates at this transaction's COMMIT once the new row exists.
        await client.query(SQL_SUPERSEDE_PRIOR_NONCES, [nonceId, operationId]);
        const result = await client.query<{
          nonce: string; issued_at: string; expires_at: string;
        }>(SQL_ISSUE_RECOVERY_NONCE, [nonceId, nonce, operationId]);
        const row = result.rows[0];
        if (row === undefined) {
          await client.query("ROLLBACK");
          throw new Error("operation not found for recovery nonce");
        }
        await client.query("COMMIT");
        return { nonce: row.nonce, issued_at: row.issued_at, expires_at: row.expires_at };
      } catch (err) {
        try { await client.query("ROLLBACK"); } catch { /* keep original error */ }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

export function createSqlRecoveryActionStore(pool: Pool, readFreshHead?: ReadFreshHead): RecoveryActionStore {
  return {
    async lookupIdempotency(operationId: string, idempotencyKey: string) {
      const result = await pool.query<{ body: string }>(SQL_LOOKUP_IDEMPOTENCY, [operationId, idempotencyKey]);
      if (result.rowCount === 0) return { kind: "miss" };
      const row = result.rows[0]!;
      try {
        const body = JSON.parse(row.body) as RecoveryActionSuccessBody;
        if (body.operation_id !== operationId) return { kind: "conflict" };
        return { kind: "hit", body };
      } catch {
        return { kind: "conflict" };
      }
    },

    async loadRecoveryFactsLocked(operationId: string): Promise<RecoveryFacts | null> {
      return loadRecoveryFactsById(pool, operationId, readFreshHead);
    },

    async commitRecoveryAction(input: RecoveryActionCommitInput): Promise<RecoveryActionCommitResult> {
      const effect = input.effect;

      // Fail closed before touching the database at all: never consume a nonce, burn a
      // TOTP timestep, or open a transaction for an effect this store cannot commit.
      if (!isImplementedEffect(effect)) {
        return {
          ok: false,
          reason: "predicate_failed",
          detail: `effect_not_implemented:${effect.kind}`,
        };
      }

      // Route A: the real confirm-read runs once, pre-BEGIN, never inside the
      // retried transaction (withSerializationRetry's caller-discipline contract). Absent
      // reader or wallet row leaves freshObservationId null — SqlReceiveExpiryReleaseService
      // already fails closed on a null-fresh receive (same verdict as the automatic worker),
      // never fabricating fresh=t0.
      let freshObservationId: string | null = null;
      if (effect.kind === "RELEASE_EXPIRED_RECEIVE" && readFreshHead !== undefined) {
        const walletRow = (await pool.query<{ public_key: string }>(
          SQL_RECEIVER_WALLET_PUBLIC_KEY, [input.operationId],
        )).rows[0];
        if (walletRow !== undefined) {
          freshObservationId = (await readFreshHead(walletRow.public_key)).observationId;
        }
      }

      return withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, async () => {
        const client: PoolClient = await pool.connect();
        try {
          await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");

          // Consume the recovery nonce; expiry and prior-consumption are both folded into
          // the WHERE clause so both fail the same way (recovery_nonce_invalid).
          const nonceResult = await client.query<{ node_id: string }>(
            SQL_CONSUME_NONCE, [input.operationId, input.recoveryNonce],
          );
          const nonceRow = nonceResult.rows[0];
          if (nonceRow === undefined) {
            await client.query("ROLLBACK");
            return { ok: false, reason: "recovery_nonce_invalid" };
          }
          const nodeId = nonceRow.node_id;

          // Burn the TOTP timestep node-wide ("globally single-use"); a replay of
          // the same (node_id, timestep) against any purpose loses this UNIQUE race.
          try {
            await client.query(SQL_BURN_TOTP_TIMESTEP, [
              randomUUID(), nodeId, input.totpTimestep, input.operationId,
            ]);
          } catch (err) {
            if (isUniqueViolation(err)) {
              await client.query("ROLLBACK");
              return { ok: false, reason: "predicate_failed", detail: "totp_timestep_already_burned" };
            }
            throw err;
          }

          let releaseStatus: RecoveryActionSuccessBody["release_status"] = null;
          let finalRowVersion: number;
          let finalStatus: string;
          let transferCodeText: string | null = null;
          let transferCodeSha256: string | null = null;

          // Apply effect. CAS verdict comes from each UPDATE's RETURNING — never a later
          // re-SELECT that could observe a concurrent commit of a different writer.
          switch (effect.kind) {
            case "RETRY_OBSERVATION":
            case "ACKNOWLEDGE_KEEP_PINNED": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_BUMP_ROW_VERSION, [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                return { ok: false, reason: "operation_version_conflict" };
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              break;
            }
            case "QUARANTINE_WALLETS": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_BUMP_ROW_VERSION, [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                return { ok: false, reason: "operation_version_conflict" };
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              for (const walletId of effect.walletIds) {
                // PIN_WALLET's WHERE state = 'AVAILABLE' is naturally idempotent; a wallet
                // already PINNED (e.g. prior partial run) is tolerated silently. Full
                // QUARANTINED state (with quarantine_reason) is a separate custody admin
                // surface — this recovery action keeps the leased wallets pinned.
                await client.query(LEASE_STATEMENTS.PIN_WALLET, [walletId]);
              }
              break;
            }
            case "RELEASE_EXPIRED_RECEIVE": {
              // Pre-CAS bump so concurrent writers lose before the release service mutates.
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_BUMP_ROW_VERSION, [input.operationId, input.expectedRowVersion],
              );
              if (casResult.rows[0] === undefined) {
                await client.query("ROLLBACK");
                return { ok: false, reason: "operation_version_conflict" };
              }
              // Route A: delegate to the canonical release service over a
              // pass-through tx factory bound to this SERIALIZABLE client — it owns lock
              // ordering, dual-proof minting and the One-in-flight-guarded release itself.
              const releaseService = new SqlReceiveExpiryReleaseService({
                withTransaction: async (fn) =>
                  fn({
                    query: async <R>(text: string, params: readonly unknown[]) => {
                      const result = await client.query(text, params as never[]);
                      return { rows: result.rows as R[], rowCount: result.rowCount ?? 0 };
                    },
                  }),
              });
              const outcome = await releaseService.expire({
                operationId: input.operationId,
                freshObservationId,
              });
              if (outcome.kind !== "RELEASED" && outcome.kind !== "ALREADY_RELEASED") {
                await client.query("ROLLBACK");
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: `receive_release_${outcome.kind.toLowerCase()}`,
                };
              }
              if (outcome.releaseStatus !== "RELEASED_T0_UNCHANGED") {
                await client.query("ROLLBACK");
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: `receive_release_status_mismatch:${outcome.releaseStatus}`,
                };
              }
              releaseStatus = outcome.releaseStatus;
              const after = (await client.query<{ row_version: number; status: string }>(
                `SELECT row_version::int AS row_version, status::text AS status
                   FROM operations WHERE id = $1::uuid`,
                [input.operationId],
              )).rows[0]!;
              finalRowVersion = after.row_version;
              finalStatus = after.status;
              break;
            }
            case "REDELIVER_EXACT_PARTIAL": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_BUMP_ROW_VERSION, [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                return { ok: false, reason: "operation_version_conflict" };
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              const queryFn = async (text: string, values: readonly unknown[]) => {
                const result = await client.query(text, values as never[]);
                return result.rows as readonly Record<string, unknown>[];
              };
              try {
                const redelivered = await redeliverExactPartialViaSql(
                  queryFn,
                  input.operationId,
                  new Date().toISOString(),
                );
                transferCodeText = redelivered.transferCodeText;
                transferCodeSha256 = redelivered.transferCodeSha256;
              } catch (err) {
                await client.query("ROLLBACK");
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: `redeliver_failed:${err instanceof Error ? err.message : String(err)}`,
                };
              }
              break;
            }
            case "CONTINUE_EXTERNAL_WAIT": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_CONTINUE_EXTERNAL_WAIT,
                [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                // Distinguish version conflict vs predicate (no partial / wrong status).
                const cur = (await client.query<{ row_version: number }>(
                  SQL_OPERATION_ROW_VERSION, [input.operationId],
                )).rows[0];
                if (cur === undefined) {
                  return { ok: false, reason: "operation_not_found" };
                }
                if (cur.row_version !== input.expectedRowVersion) {
                  return { ok: false, reason: "operation_version_conflict" };
                }
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: "continue_external_wait_cas_miss",
                };
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              break;
            }
            case "CLOSE_NEVER_STARTED_EXTERNAL_SEND": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_CLOSE_NEVER_STARTED,
                [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                const cur = (await client.query<{ row_version: number }>(
                  SQL_OPERATION_ROW_VERSION, [input.operationId],
                )).rows[0];
                if (cur === undefined) {
                  return { ok: false, reason: "operation_not_found" };
                }
                if (cur.row_version !== input.expectedRowVersion) {
                  return { ok: false, reason: "operation_version_conflict" };
                }
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: "close_never_started_cas_miss",
                };
              }
              if (effect.releaseSourceLease) {
                await releaseSourceLeasesForOperation(client, input.operationId);
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              break;
            }
            case "CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED": {
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_CLOSE_PROVEN_NOT_LANDED,
                [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                const cur = (await client.query<{ row_version: number }>(
                  SQL_OPERATION_ROW_VERSION, [input.operationId],
                )).rows[0];
                if (cur === undefined) {
                  return { ok: false, reason: "operation_not_found" };
                }
                if (cur.row_version !== input.expectedRowVersion) {
                  return { ok: false, reason: "operation_version_conflict" };
                }
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: "close_proven_not_landed_cas_miss",
                };
              }
              if (effect.releaseSourceLease) {
                await releaseSourceLeasesForOperation(client, input.operationId);
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              break;
            }
            case "REBUILD_INTERNAL_MOVE": {
              // Spec: archive old attempt unchanged + authorize next. We never resubmit the
              // old attempt (the never-blind-retry rule). Status → CREATED, attention cleared.
              if (effect.submitOldAttempt !== false) {
                await client.query("ROLLBACK");
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: "rebuild_must_not_submit_old_attempt",
                };
              }
              const casResult = await client.query<{ row_version: number; status: string }>(
                SQL_CAS_REBUILD_INTERNAL_MOVE,
                [input.operationId, input.expectedRowVersion],
              );
              const casRow = casResult.rows[0];
              if (casRow === undefined) {
                await client.query("ROLLBACK");
                const cur = (await client.query<{ row_version: number }>(
                  SQL_OPERATION_ROW_VERSION, [input.operationId],
                )).rows[0];
                if (cur === undefined) {
                  return { ok: false, reason: "operation_not_found" };
                }
                if (cur.row_version !== input.expectedRowVersion) {
                  return { ok: false, reason: "operation_version_conflict" };
                }
                return {
                  ok: false,
                  reason: "predicate_failed",
                  detail: "rebuild_internal_move_cas_miss",
                };
              }
              finalRowVersion = casRow.row_version;
              finalStatus = casRow.status;
              break;
            }
            default: {
              // Fail closed: isImplementedEffect should have rejected unknown kinds already.
              const _exhaustive: never = effect;
              throw new Error(
                `unimplemented effect reached commit: ${(_exhaustive as RecoveryActionEffect).kind}`,
              );
            }
          }

          // Append the audit log row inside this same transaction — unlike
          // createSqlBlessingAuditAppender's fire-and-forget insert, a failure here must
          // roll back the whole recovery action; RecoveryActionStore's contract requires
          // "consume nonce + burn TOTP + apply effect + CAS + audit" as one atomic unit.
          const walletIdsNote = effect.kind === "QUARANTINE_WALLETS"
            ? `;wallet_ids=${effect.walletIds.join(",")}`
            : "";
          const details = `action=${input.action};operation_id=${input.operationId};` +
            `classification=${input.classification};operator_note=${input.operatorNote ?? ""}` +
            walletIdsNote;
          await client.query(SQL_INSERT_AUDIT_LOG, [
            randomUUID(), nodeId, input.operatorId, input.action, input.operationId,
            details, sha256HexUtf8(details),
          ]);

          const successBody: RecoveryActionSuccessBody = {
            operation_id: input.operationId,
            action: input.action,
            classification: input.classification,
            status: finalStatus,
            row_version: finalRowVersion,
            release_status: releaseStatus,
            transfer_code_text: transferCodeText,
            transfer_code_sha256: transferCodeSha256,
            effect: effect.kind,
          };
          await client.query(
            SQL_STORE_IDEMPOTENCY,
            [input.operationId, input.idempotencyKey, JSON.stringify(successBody)],
          );

          await client.query("COMMIT");
          return {
            ok: true,
            rowVersion: finalRowVersion,
            status: finalStatus,
            releaseStatus,
            transferCodeText,
            transferCodeSha256,
          };
        } catch (err) {
          // Never fabricate predicate_failed for an unexpected error — every anticipated
          // fail-closed branch above already returns explicitly from within the try.
          try { await client.query("ROLLBACK"); } catch { /* keep original error */ }
          throw err;
        } finally {
          client.release();
        }
      });
    },

    async storeIdempotency(operationId: string, idempotencyKey: string, body: RecoveryActionSuccessBody): Promise<void> {
      await pool.query(SQL_STORE_IDEMPOTENCY, [operationId, idempotencyKey, JSON.stringify(body)]);
    },
  };
}

async function loadRecoveryFactsById(
  pool: Pool,
  operationId: string,
  readFreshHead?: ReadFreshHead,
): Promise<RecoveryFacts | null> {
  const result = await pool.query<{
    operation_id: string; kind: string; status: string;
    attention_required: boolean; attention_reason: string | null; row_version: number;
    t0_observation_id: string | null; terminal_observation_id: string | null;
    verification_material_available_until: string | null;
    expiry_unix_time_secs: string | null; formation_state: string | null;
  }>(SQL_LOAD_RECOVERY_FACTS, [operationId]);
  const r = result.rows[0];
  if (r === undefined) return null;
  return loadRecoveryFactsFromRow(pool, r.operation_id, r.kind, r.status,
    r.attention_required, r.attention_reason, r.row_version, {
      t0ObservationId: r.t0_observation_id,
      terminalObservationId: r.terminal_observation_id,
      expiryUnixTimeSecs: r.expiry_unix_time_secs,
      formationState: r.formation_state,
    }, readFreshHead);
}

interface RecoveryFactsRowExtra {
  readonly t0ObservationId: string | null;
  readonly terminalObservationId: string | null;
  readonly expiryUnixTimeSecs: string | null;
  readonly formationState: string | null;
}

async function loadRecoveryFactsFromRow(
  pool: Pool, operationId: string, kind: string, status: string,
  attentionRequired: boolean, attentionReason: string | null, rowVersion: number,
  extra: RecoveryFactsRowExtra,
  readFreshHead?: ReadFreshHead,
): Promise<RecoveryFacts | null> {
  // Load active leases for this operation.
  const leaseRows = await pool.query<{
    wallet_id: string; lease_epoch: string; lease_role: string;
  }>(
    `SELECT wallet_id::text, lease_epoch::text, lease_role::text
       FROM wallet_active_leases WHERE operation_id = $1::uuid`,
    [operationId],
  );
  const heldLeases = leaseRows.rows.map((l) => ({
    walletId: l.wallet_id, leaseEpoch: Number(l.lease_epoch), role: l.lease_role,
  }));
  const maxEpoch = heldLeases.length > 0
    ? Math.max(...heldLeases.map((l) => l.leaseEpoch))
    : null;

  const parsedKind = parseOperationKind(kind);
  const manifest: EvidenceManifestEntry[] = [];

  // Check for landing proof.
  let hasLandingProof = false;
  let landingProofVerdict: LandingVerdict | null = null;
  if (parsedKind === "RECEIVE_EXTERNAL") {
    const proofRow = await pool.query<{ verdict: string }>(
      `SELECT verdict FROM receive_landing_proofs WHERE operation_id = $1::uuid`,
      [operationId],
    );
    if (proofRow.rows[0]) {
      hasLandingProof = true;
      landingProofVerdict = parseLandingVerdict(proofRow.rows[0].verdict);
      manifest.push({ kind: "receive_landing_proofs", id: null, role: null, digest_sha256: null,
        summary: `landing proof verdict ${landingProofVerdict}` });
    }
  } else if (parsedKind === "MOVE_INTERNAL") {
    const evRow = await pool.query<{
      source_term: string | null; dest_term: string | null;
    }>(
      `SELECT source_terminal_observation_id::text AS source_term,
              destination_terminal_observation_id::text AS dest_term
         FROM move_observation_evidence WHERE operation_id = $1::uuid`,
      [operationId],
    );
    if (evRow.rows[0] && evRow.rows[0].source_term && evRow.rows[0].dest_term) {
      hasLandingProof = true;
      landingProofVerdict = "LANDED_EXACT";
      manifest.push({ kind: "move_observation_evidence", id: null, role: null, digest_sha256: null,
        summary: "source and destination terminal observations both present" });
    }
  }

  // Shared across all three kinds (fact table: signer_audit keyed on operation_id).
  const hasSignerAudit = ((await pool.query(SQL_HAS_SIGNER_AUDIT, [operationId])).rowCount ?? 0) > 0;
  if (hasSignerAudit) {
    manifest.push({ kind: "signer_audit", id: null, role: null, digest_sha256: null,
      summary: "signer_audit row present for operation" });
  }

  const artifactRow = (await pool.query<{ id: string; preimage_sha256: string }>(
    SQL_EXPECTED_ARTIFACT, [operationId],
  )).rows[0] ?? null;
  if (artifactRow !== null) {
    manifest.push({ kind: "operation_expected_artifacts", id: artifactRow.id, role: null,
      digest_sha256: artifactRow.preimage_sha256, summary: "expected artifact preimage + signature present" });
  }

  // INVARIANT_BREACH when a money-path signer_audit exists without its exact-byte
  // home. Match each audit.preimage_sha256 against the durable digests for that purpose —
  // never against T0 completed_transaction_sha256 (that compared two unrelated hashes and
  // false-positive breached every armed/landed receive that had signed its expected artifact).
  const moneyPathAudits = (await pool.query<{ preimage_sha256: string; purpose: string }>(
    SQL_MONEY_PATH_SIGNER_AUDITS, [operationId],
  )).rows;
  const durableExactByteDigests = new Set<string>();
  if (artifactRow !== null) {
    durableExactByteDigests.add(artifactRow.preimage_sha256);
  }
  const txPreimageRow = (await pool.query<{
    inner_sha256: string;
    step_2_preimage_sha256: string | null;
  }>(SQL_OPERATION_TRANSACTION_PREIMAGE_DIGESTS, [operationId])).rows[0] ?? null;
  if (txPreimageRow !== null) {
    durableExactByteDigests.add(txPreimageRow.inner_sha256);
    if (txPreimageRow.step_2_preimage_sha256 !== null) {
      durableExactByteDigests.add(txPreimageRow.step_2_preimage_sha256);
    }
  }
  // Vacuous true when no money-path audits exist (breach predicate is hasSignerAudit &&
  // !hasMatching for RECEIVE; matching is only meaningful for the money-path digests).
  const hasMatchingExactByteRecord = moneyPathAudits.every((a) =>
    durableExactByteDigests.has(a.preimage_sha256),
  );

  let receive: RecoveryFacts["receive"] = null;
  let move: RecoveryFacts["move"] = null;
  let send: RecoveryFacts["send"] = null;

  if (parsedKind === "RECEIVE_EXTERNAL") {
    const hasT0Binding = ((await pool.query(SQL_HAS_T0_BINDING, [operationId])).rowCount ?? 0) > 0;
    if (hasT0Binding) {
      manifest.push({ kind: "operation_observation_bindings", id: null, role: "RECEIVER_T0",
        digest_sha256: null, summary: "RECEIVER_T0 binding present" });
    }

    const codeStatusRow = (await pool.query<{ code_status: string }>(
      SQL_RECEIVE_CODE_STATUS, [operationId],
    )).rows[0] ?? null;
    if (codeStatusRow !== null) {
      manifest.push({ kind: "receive_codes", id: null, role: null, digest_sha256: null,
        summary: `receive code status ${codeStatusRow.code_status}` });
    }

    type ObservationRow = {
      parse_result: string; s_signature: string | null; p_signature: string | null;
      b_amount: string | null; completed_transaction_sha256: string | null;
    };
    const t0Row = extra.t0ObservationId !== null
      ? (await pool.query<ObservationRow>(SQL_OBSERVATION_BY_ID, [extra.t0ObservationId])).rows[0] ?? null
      : null;

    // No terminal observation recorded yet, or it still points at T0 itself, means
    // nothing has diverged from T0 — vacuously "fresh equals T0".
    let freshObservationEqualsT0 = true;
    if (extra.terminalObservationId !== null && extra.terminalObservationId !== extra.t0ObservationId) {
      const terminalRow = (await pool.query<ObservationRow>(
        SQL_OBSERVATION_BY_ID, [extra.terminalObservationId],
      )).rows[0] ?? null;
      freshObservationEqualsT0 = t0Row !== null && terminalRow !== null
        && t0Row.s_signature === terminalRow.s_signature
        && t0Row.p_signature === terminalRow.p_signature
        && t0Row.b_amount === terminalRow.b_amount;
    }

    const childRows = (await pool.query<{ status: string }>(
      SQL_CHILD_OPERATION_STATUSES, [operationId],
    )).rows;
    const childAbsentOrTerminal = childRows.every((c) => TERMINAL_OPERATION_STATUSES.has(c.status));

    const codeExpiredPlusMargin = extra.expiryUnixTimeSecs !== null
      && Date.now() / 1000 > Number(extra.expiryUnixTimeSecs) + RECEIVE_EXPIRY_SAFETY_MARGIN_SECS;

    const hasOperationTransaction =
      ((await pool.query(SQL_HAS_OPERATION_TRANSACTION, [operationId])).rowCount ?? 0) > 0;
    if (hasOperationTransaction) {
      manifest.push({ kind: "operation_transactions", id: null, role: null, digest_sha256: null,
        summary: "operation_transactions row present for operation" });
    }
    const hasSubmitAttempt =
      ((await pool.query(SQL_HAS_SUBMIT_ATTEMPT, [operationId])).rowCount ?? 0) > 0;
    if (hasSubmitAttempt) {
      manifest.push({ kind: "gateway_submit_attempts", id: null, role: null, digest_sha256: null,
        summary: "gateway_submit_attempts row present for operation" });
    }

    receive = {
      codeExpiredPlusMargin,
      noPersistedLandedProof: !hasLandingProof,
      freshObservationEqualsT0,
      // Any operation_transactions or gateway_submit_attempts
      // row is durable submit evidence requiring reconciliation, not a clean axis.
      noAnomalyOrSubmitReconcileDebt: !hasOperationTransaction && !hasSubmitAttempt,
      childAbsentOrTerminal,
      hasT0: hasT0Binding,
      hasCodeOrArtifactPreimage: codeStatusRow?.code_status === "RELEASED" || artifactRow !== null,
      hasArtifactSignature: artifactRow !== null,
      hasSignerAudit,
      hasMatchingExactByteRecord,
    };
  } else if (parsedKind === "MOVE_INTERNAL") {
    move = {
      // ponytail: no schema table distinguishes these five predicates from "unknown" yet
      // (no captured rejection response, no per-wallet T0 snapshot, no submit-lifecycle
      // table for MOVE_INTERNAL) — hardcoded to the value that cannot fire a false
      // positive classification. Wire real detectors when those tables exist (mirrors
      // the fact-gatherer slice's own precedent for documenting an out-of-scope gap).
      deterministicPreAcceptanceRejection: false,
      expiredAndBothWalletsUnchangedAtT0: false,
      submitProvablyNeverStarted: false,
      positiveNonLandingProofId: null,
      unexpectedSuccessorOutsideLease: false,
      hasPreimage: artifactRow !== null,
      hasSignature: artifactRow !== null,
      hasSignerAudit,
      // Defaults true: no move_observation_evidence byte-diff is wired here, so this
      // never fabricates move_signer_audit_without_exact_bytes (INVARIANT_BREACH).
      hasMatchingExactByteRecord: true,
      oneWalletLandedOtherUnconnected: false,
    };
  } else {
    // SEND_EXTERNAL: prefer durable transaction-material tables (external_send_*), fall
    // back to formation_state on the operations mirror when those rows are absent.
    const signIntent = (await pool.query<{
      redemption_expiry_at: string | null;
    }>(
      `SELECT redemption_expiry_at::text AS redemption_expiry_at
         FROM external_send_sign_intents WHERE operation_id = $1::uuid`,
      [operationId],
    )).rows[0] ?? null;
    const partial = (await pool.query<{
      first_delivered_at: string | null;
      step_1_signature: string | null;
    }>(
      `SELECT first_delivered_at::text AS first_delivered_at,
              step_1_signature
         FROM external_send_partials WHERE operation_id = $1::uuid`,
      [operationId],
    )).rows[0] ?? null;

    const hasSignIntent = signIntent !== null;
    const hasDurablePartial = partial !== null
      || extra.formationState === "PARTIAL_PERSISTED"
      || extra.formationState === "PARTIAL_DELIVERED";
    const hasDelivery = (partial !== null && partial.first_delivered_at !== null)
      || extra.formationState === "PARTIAL_DELIVERED";
    const hasSignature = (partial !== null && partial.step_1_signature !== null)
      || hasDurablePartial;

    // Aging margin: T2 + SEND_PARTIAL_AGING_MARGIN_SECS (3600). Column is the
    // stored projection; never recompute from wall-clock without the stored value.
    let protocolExpiredPlusMargin = false;
    if (signIntent?.redemption_expiry_at !== null && signIntent?.redemption_expiry_at !== undefined) {
      const expiryMs = Date.parse(signIntent.redemption_expiry_at);
      if (Number.isFinite(expiryMs)) {
        protocolExpiredPlusMargin = Date.now() >= expiryMs + 3600_000;
      }
    }

    if (hasSignIntent) {
      manifest.push({
        kind: "external_send_sign_intents",
        id: null,
        role: null,
        digest_sha256: null,
        summary: "external_send_sign_intents row present",
      });
    }
    if (partial !== null) {
      manifest.push({
        kind: "external_send_partials",
        id: null,
        role: null,
        digest_sha256: null,
        summary: hasDelivery
          ? "external_send_partials delivered"
          : "external_send_partials durable",
      });
    }

    // F1.2's two live inputs. The exclusion oracle runs for real — the outcome of every read
    // is recorded on the evidence manifest — but its positives are admitted to the close
    // predicates only through SEND_NON_LANDING_CLOSE_ACTIVATED, which is false while the
    // action is RESERVED. A fault, a thrown read, an absent Ts0 binding, or a send found ON
    // the source path all leave both predicates false regardless (fail-closed).
    //
    // Two gates decide whether it is asked at all, and BOTH are needed. Past T2 + the aging
    // margin with a durable partial is the sole window in which a terminal close may even be
    // considered — but every parked send satisfies it, so that gate alone does not bound the
    // read volume. `readFreshHead` is the other: only the single-operation callers thread it,
    // so one operation costs at most one oracle run and the attention listing costs none.
    // Changing that (threading it into listNeedsAttention) puts `limit` live gateway walks
    // inside one operator HTTP request — see the comment on listNeedsAttention.
    let freshHeadEqualsSourceT0 = false;
    let completePathExclusionProved = false;
    if (protocolExpiredPlusMargin && hasDurablePartial && readFreshHead !== undefined) {
      try {
        const probe = await proveSendNonLandingForOperation(pool, operationId, readFreshHead);
        freshHeadEqualsSourceT0 =
          SEND_NON_LANDING_CLOSE_ACTIVATED && probe.outcome?.kind === "FRESH_HEAD_EQUALS_T0";
        completePathExclusionProved =
          SEND_NON_LANDING_CLOSE_ACTIVATED && probe.outcome?.kind === "COMPLETE_PATH_EXCLUSION";
        manifest.push({
          kind: "gateway_observations", id: null, role: "SOURCE_HEAD", digest_sha256: null,
          summary: SEND_NON_LANDING_CLOSE_ACTIVATED
            ? probe.summary
            : `${probe.summary} (RESERVED: not admitted to the close predicates)`,
        });
      } catch (err) {
        manifest.push({
          kind: "gateway_observations", id: null, role: "SOURCE_HEAD", digest_sha256: null,
          summary: `non-landing exclusion read failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }

    send = {
      hasSignIntent,
      hasSignerCall: hasSignerAudit,
      hasSignature,
      hasDurablePartial,
      hasDelivery,
      protocolExpiredPlusMargin,
      freshHeadEqualsSourceT0,
      completePathExclusionProved,
      hasSignerAudit,
      hasMatchingExactByteRecord: true,
    };
  }

  return {
    operationId,
    kind: parsedKind,
    status,
    attentionRequired,
    attentionReason,
    rowVersion,
    leaseEpoch: maxEpoch,
    heldLeases,
    hasLandingProof,
    landingProofVerdict,
    // hasObservationAnomaly / hasLineageGap remain hardcoded false: no anomaly/lineage
    // detector exists yet in this codebase (not merely unreachable, as the previous
    // comment here claimed — receive/move/send are populated above and DO reach
    // classifyRecovery's kind-specific branches now). invariantBreachNoted is also
    // hardcoded false; it IS checked unconditionally by classifyRecovery, so a real
    // detector would additionally gate RETRY_OBSERVATION's admission down to
    // QUARANTINE_WALLETS/ACKNOWLEDGE_KEEP_PINNED only. RETRY_OBSERVATION's own effect is
    // a row_version-only bump (no status/attention/lease/wallet-state change), so this
    // stays a classification-precision gap, not a fund-safety or The core money-path rules violation —
    // tracked as a follow-up, not fixed in this ticket (AC6).
    hasObservationAnomaly: false,
    hasLineageGap: false,
    invariantBreachNoted: false,
    evidenceManifest: manifest,
    diagnostics: [],
    receive,
    move,
    send,
    haltEngaged: false,
  };
}
