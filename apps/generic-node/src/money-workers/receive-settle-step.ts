// Receive settle worker step.
//
// This is the runtime edge that makes @zucoins/node-core's settleReceiveAttempt — and through
// it core/receive-submit-once.ts — reachable from the production graph. Before this step the
// submit-once service had no caller outside tests.
//
// The step drives rows the intake path leaves durable, and it drives them from
// whichever rung of the attempt-phase ladder they are actually on: a process death between the step-9
// commit and the step-12 submit leaves the row mid-ceremony, and a selector that admitted only
// the first rung would strand it with its receiver lease held forever. It never forms a
// candidate itself and never submits twice: an attempt whose body was already durable when this
// pass began is confirm-read against the receiver head first, and an ambiguous transport is
// reported and left to the landing observation reconcile — exactly as the never-blind-retry rule requires.

import { createPrivateKey, sign as edSign } from "node:crypto";
import { Buffer } from "node:buffer";

import {
  buildGetTransactionActionData,
  createSqlSignerAuditLog,
  makeSubmitAttemptRecorder,
  makeSubmitDecisionClaimStore,
  parseEd25519Signature,
  parseGatewayEnvelope,
  readGatewayAction,
  settleReceiveAttempt,
  type ActiveLeaseRecord,
  type EncryptedWalletKeyStore,
  type GatewayExchangeTransport,
  type GatewayLimits,
  type MoneyPathSignerGates,
  type MetricsHooks,
  type ReceiveSettleEntryPhase,
  type ReceiveSettleOutcome,
  type SignUnderLeaseTransactionFn,
  type SignerLeadershipLatch,
  type SqlQueryFn,
  type Uuid,
} from "@zucoins/node-core";

import type { MoneyWorkerLogger } from "./start-money-workers.js";
import { persistSqlObservation } from "./sql-observation-persistence.js";
import type { Pool } from "pg";

/** Max candidates advanced per tick. Settling is signer- and network-bound; a small batch keeps
 * one slow gateway exchange from stalling the rest of the money tick. The batch is deliberately
 * unsequenced: every tick re-reads durable state, so which five a tick takes changes nothing
 * about what each one does. */
const SETTLE_BATCH_LIMIT = 5;

/** The vault open() purpose string recorded on every audited unseal for this path. */
const SETTLE_UNSEAL_PURPOSE = "receive_step_2_cosign";

/** The one vault capability this step uses. The real EncryptedWalletKeyStore satisfies it. */
export type ReceiveSettleVault = Pick<EncryptedWalletKeyStore, "open">;

export interface ReceiveSettleStepDeps {
  /** The one statement seam. Driver-free so the whole step is drivable against a real server. */
  readonly query: SqlQueryFn;
  /**
   * Pool used solely by the transport-ambiguity observation recorder (same connection
   * model as T0 / fresh-head). Required so ambiguous confirm-reads leave a durable
   * TRANSPORT_ERROR pair rather than a silent no-op.
   */
  readonly pool: Pool;
  readonly vault: ReceiveSettleVault;
  readonly nodeId: string;
  readonly leadership: SignerLeadershipLatch;
  readonly moneyPathGates: MoneyPathSignerGates;
  /**
   * ZTR-1160: pin lease FOR UPDATE across vault co-sign + SIGNED audit. Production
   * start-money-workers supplies createSqlSignUnderLeaseTransaction(pool). Tests that only
   * exercise non-sign paths may omit it.
   */
  readonly withSignTransaction?: SignUnderLeaseTransactionFn;
  readonly gateway: {
    readonly endpoint: string;
    readonly limits: GatewayLimits;
    /** Test seam for the offline suites; production leaves it unset and uses real transport. */
    readonly exchange?: GatewayExchangeTransport;
    /**
     * GATEWAY_READ_RETRY_MAX_ATTEMPTS / GATEWAY_READ_BACKOFF_MAX_MS — READ-only knobs
     * (createReceiverHeadReader below). The never-blind-retry rule: never threaded into submitOptions.
     */
    readonly maxAttempts?: number;
    readonly backoffMaxMs?: number;
  };
  readonly logger: MoneyWorkerLogger;
  readonly metricsHooks?: MetricsHooks;
}

interface CandidateRow {
  readonly operationId: string;
  readonly receiveAttemptId: string;
  readonly receiverWalletId: string;
  readonly receiverPublicKey: string;
  readonly leaseEpoch: bigint;
  readonly innerPreimageText: string;
  readonly payerStep1Signature: string;
  readonly submitDecisionId: string;
  readonly attemptPhase: ReceiveSettleEntryPhase;
  readonly step2PreimageText: string | null;
  readonly step2Signature: string | null;
  readonly completedTransactionText: string | null;
}

/** The rungs a settle pass may resume from. SETTLED_BODY_PERSISTED is absent on purpose: that
 * row has landed and belongs to the landing walk, not to this step. */
const SETTLEABLE_PHASES: readonly ReceiveSettleEntryPhase[] = [
  "STEP1_SIGNATURE_PERSISTED",
  "STEP2_PREIMAGE_PERSISTED",
  "STEP2_SIGNATURE_PERSISTED",
];

// One durable attempt per operation (operation_transactions PK, attempt_no = 1), joined to the
// receiver wallet and the lease that must still be held for the co-sign to be legal.
const SELECT_SETTLEABLE = `
  SELECT o.id::text                    AS operation_id,
         ot.attempt_phase              AS attempt_phase,
         ot.inner_preimage_text        AS inner_preimage_text,
         ot.step_1_signature           AS step_1_signature,
         ot.step_2_preimage_text       AS step_2_preimage_text,
         ot.step_2_signature           AS step_2_signature,
         ot.completed_transaction_text AS completed_transaction_text,
         ow.wallet_id::text            AS wallet_id,
         w.public_key                  AS receiver_public_key,
         l.lease_epoch::text           AS lease_epoch
    FROM operations o
    JOIN operation_transactions ot
      ON ot.operation_id = o.id AND ot.attempt_no = 1
    JOIN operation_wallets ow
      ON ow.operation_id = o.id AND ow.operation_role = 'RECEIVER'
    JOIN wallets w
      ON w.id = ow.wallet_id
    JOIN wallet_active_leases l
      ON l.operation_id = o.id
     AND l.wallet_id = ow.wallet_id
     AND l.lease_role = 'RECEIVE_WINDOW'
   WHERE o.kind = 'RECEIVE_EXTERNAL'
     AND o.status = 'READY'
     AND ot.attempt_phase = ANY($1::text[])
   LIMIT ${SETTLE_BATCH_LIMIT}`;

// FOR UPDATE (ZTR-1160) — not FOR SHARE. Two concurrent signers must not both proceed under
// shared locks, and the release path (leases/repository.ts SELECT_ACTIVE_FOR_UPDATE,
// receive/expiry-release.ts LOCK_RECEIVER_LEASE) must block until the sign critical section
// commits. Production supplies withSignTransaction so this SELECT runs on a pinned client
// held open across vaultSigner.sign and the SIGNED audit append; bare autocommit still
// releases at statement end and must not be the production path.
const SELECT_ACTIVE_LEASE = `
  SELECT operation_id::text AS operation_id,
         wallet_id::text    AS wallet_id,
         lease_epoch::text  AS lease_epoch,
         lease_role         AS lease_role
    FROM wallet_active_leases
   WHERE wallet_id = $1::uuid
   LIMIT 1
     FOR UPDATE`;

/**
 * The VaultSigner port over the audited vault. The secret is opened, used, and wiped in
 * one scope; it is never returned, logged, or held past the signature (the key-custody rule).
 */
function createVaultSigner(deps: ReceiveSettleStepDeps, receiverPublicKey: string) {
  return {
    async sign(walletId: string, preimageBytes: Uint8Array): Promise<string> {
      const secret = await deps.vault.open(
        {
          nodeId: deps.nodeId as Uuid,
          walletId: walletId as Uuid,
          keyVersion: 1,
          publicKey: receiverPublicKey,
          keyOrigin: "node_generated",
        },
        SETTLE_UNSEAL_PURPOSE,
      );
      try {
        // The sealed material is the 64-byte libsodium secret key; the seed is its first half.
        // Both the seed copy and the DER envelope that embeds it are wiped: the envelope is a
        // second copy of the same 32 bytes, and leaving it to the collector would put key
        // material on the heap for an unbounded time.
        const seed = Buffer.from(secret.bytes.subarray(0, 32));
        const der = Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          seed,
        ]);
        try {
          const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
          const raw = Buffer.from(edSign(null, preimageBytes, key)).toString("base64url");
          // The frozen scalar domains pin every persisted and signed-body signature to the PADDED base64url
          // spelling (86 chars + "=="); Buffer's base64url encoder emits the unpadded one, and
          // the padded_base64url_signature domain would refuse it only after the signature had
          // already been produced. parseEd25519Signature is the frozen judge of the spelling.
          return parseEd25519Signature(raw + "=".repeat((4 - (raw.length % 4)) % 4));
        } finally {
          seed.fill(0);
          der.fill(0);
        }
      } finally {
        secret.wipe();
      }
    },
  };
}

function createLeaseReader(query: SqlQueryFn) {
  return {
    async readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
      const rows = await query(SELECT_ACTIVE_LEASE, [walletId]);
      const row = rows[0] as
        | { operation_id: string; wallet_id: string; lease_epoch: string; lease_role: string }
        | undefined;
      if (row === undefined) return null;
      return {
        walletId: row.wallet_id,
        operationId: row.operation_id,
        epoch: BigInt(row.lease_epoch),
        role: row.lease_role as ActiveLeaseRecord["role"],
        // A row in wallet_active_leases is by construction the active one; a released lease is
        // deleted from this table rather than flagged, so presence is the lifecycle answer.
        lifecycle: "ACTIVE",
      };
    },
  };
}

/**
 * Landing step 1: one bounded confirm-read of the receiver wallet's head. Read-safe by
 * construction — readGatewayAction's parameter type excludes the submit action, so this path
 * cannot become a resubmit (the never-blind-retry rule).
 *
 * Only the head body's step_2_signature is returned on success. Successful heads are NOT
 * persisted here: this is a transient confirm-read whose sole purpose is to decide submit vs
 * observe — it is not the durable terminal observation. The landing step
 * (runReceiveLandingStep) performs the durable RECEIVE_TERMINAL_CHECK via
 * sql-fresh-head-reader.ts. Transport-ambiguous attempts ARE persisted as TRANSPORT_ERROR
 * pairs so the anomaly ledger is never empty when the gateway is hostile/flaky.
 *
 * Exported for confirm-read unit test (receive-settle-step.confirm-read.test.ts).
 */
export function createReceiverHeadReader(deps: ReceiveSettleStepDeps) {
  return async (receiverPublicKey: string): Promise<string | null> => {
    const result = await readGatewayAction(
      "get_transaction__v1",
      // The canonical codec is the ONE place this shape is spelled — every
      // wallet-head read (this confirm-read, gateway-t0-observer.ts, sql-fresh-head-reader.ts,
      // sql-candidate-intake-ports.ts) routes through it so the field name cannot drift again.
      buildGetTransactionActionData(receiverPublicKey),
      {
        endpoints: [deps.gateway.endpoint],
        limits: deps.gateway.limits,
        recorder: {
          recordObservation: async (observation) => {
            if (!observation.transportAmbiguous) return;
            await persistSqlObservation({
              pool: deps.pool,
              nodeId: deps.nodeId,
              walletPublicKey: receiverPublicKey,
              endpointFingerprint: observation.endpointFingerprint,
              httpStatus: null,
              capture: {
                parseResult: "TRANSPORT_ERROR",
                rawResponseBytes: new Uint8Array(),
                isGenesis: false,
                sSignature: "",
                pSignature: "",
                semanticFingerprint: "",
              },
              projection: {
                walletRole: null,
                bAmount: null,
                innerPreimageText: null,
                step1Signature: null,
                step2Signature: null,
                completedTransactionText: null,
                completedTransactionSha256: null,
              },
            });
          },
        },
        exchange: deps.gateway.exchange,
        maxAttempts: deps.gateway.maxAttempts,
        backoffMaxMs: deps.gateway.backoffMaxMs,
      },
    );
    const envelope = parseGatewayEnvelope(result.capture.responseBytes);
    return envelope.classification === "HEAD" ? envelope.parsed.step_2_signature : null;
  };
}

async function loadSettleable(query: SqlQueryFn): Promise<readonly CandidateRow[]> {
  const rows = (await query(SELECT_SETTLEABLE, [SETTLEABLE_PHASES])) as readonly {
    operation_id: string;
    attempt_phase: ReceiveSettleEntryPhase;
    inner_preimage_text: string;
    step_1_signature: string;
    step_2_preimage_text: string | null;
    step_2_signature: string | null;
    completed_transaction_text: string | null;
    wallet_id: string;
    receiver_public_key: string;
    lease_epoch: string;
  }[];
  return rows.map((row) => ({
    operationId: row.operation_id,
    // The attempt ladder pins attempt_no = 1, so the operation id IS the one attempt's identity. Deriving it
    // rather than minting a fresh uuid is what makes the submit claim idempotent across a crash.
    receiveAttemptId: row.operation_id,
    submitDecisionId: row.operation_id,
    receiverWalletId: row.wallet_id,
    receiverPublicKey: row.receiver_public_key,
    leaseEpoch: BigInt(row.lease_epoch),
    innerPreimageText: row.inner_preimage_text,
    payerStep1Signature: row.step_1_signature,
    attemptPhase: row.attempt_phase,
    step2PreimageText: row.step_2_preimage_text,
    step2Signature: row.step_2_signature,
    completedTransactionText: row.completed_transaction_text,
  }));
}

function describeOutcome(operationId: string, outcome: ReceiveSettleOutcome): string {
  switch (outcome.kind) {
    case "SUBMITTED":
      return `money-workers: receive settle SUBMITTED op=${operationId} body_sha=${outcome.completedTransactionSha256.slice(0, 12)}…`;
    case "OBSERVED_AT_HEAD":
      // The never-blind-retry rule: the resumed attempt's one submit is on chain. No second submit is
      // possible from here; the landing commit (runReceiveLandingStep, wired into the
      // production tick) performs the durable OBSERVE + landing proof that advances
      // the row to RECEIVE_LANDED.
      return `money-workers: receive settle OBSERVED_AT_HEAD op=${operationId} body_sha=${outcome.completedTransactionSha256.slice(0, 12)}… — landing via the landing tick`;
    case "RECONCILE_REQUIRED":
      // The never-blind-retry rule: this is the only ambiguous branch and it never resubmits.
      return `money-workers: receive settle AMBIGUOUS op=${operationId} reason=${outcome.reason.source} — reconciling by observation, no resubmit`;
    case "REJECTED":
      return `money-workers: receive settle REJECTED op=${operationId} reason=${outcome.reason}`;
  }
}

/**
 * One settle pass over every durable candidate. Returns the number of attempts that
 * reached a settled decision (submitted, observed on the head, or ambiguous); rejected and
 * failed rows are logged and left for the next tick or for operator attention.
 */
export async function runReceiveSettleStep(deps: ReceiveSettleStepDeps): Promise<number> {
  const rows = await loadSettleable(deps.query);
  if (rows.length === 0) return 0;

  const claimStore = makeSubmitDecisionClaimStore(deps.query);
  const recorder = makeSubmitAttemptRecorder(deps.query);
  const leaseReader = createLeaseReader(deps.query);
  const auditLog = createSqlSignerAuditLog(deps.query);
  const readReceiverHeadStep2Signature = createReceiverHeadReader(deps);

  let decided = 0;
  for (const row of rows) {
    try {
      const outcome = await settleReceiveAttempt(
        {
          operationId: row.operationId,
          receiveAttemptId: row.receiveAttemptId,
          receiverWalletId: row.receiverWalletId,
          receiverPublicKey: row.receiverPublicKey,
          leaseEpoch: row.leaseEpoch,
          innerPreimageText: row.innerPreimageText,
          payerStep1Signature: row.payerStep1Signature,
          attemptPhase: row.attemptPhase,
          step2PreimageText: row.step2PreimageText,
          step2Signature: row.step2Signature,
          completedTransactionText: row.completedTransactionText,
        },
        {
          query: deps.query,
          signerDeps: {
            leadership: deps.leadership,
            // Fallback leaseReader/auditLog — production sign uses withSignTransaction so
            // FOR UPDATE is held across vault + audit (ZTR-1160).
            leaseReader,
            vaultSigner: createVaultSigner(deps, row.receiverPublicKey),
            auditLog,
            ...(deps.withSignTransaction !== undefined
              ? { withSignTransaction: deps.withSignTransaction }
              : {}),
            ...deps.moneyPathGates,
          },
          claimStore,
          submitOptions: {
            endpoint: deps.gateway.endpoint,
            limits: deps.gateway.limits,
            recorder,
            exchange: deps.gateway.exchange,
          },
          submitDecisionId: row.submitDecisionId,
          readReceiverHeadStep2Signature,
          metricsHooks: deps.metricsHooks,
        },
      );
      deps.logger.info(describeOutcome(row.operationId, outcome));
      if (outcome.kind !== "REJECTED") decided += 1;
    } catch (err) {
      // A throw here is a refusal (lease lost, not leader, money gate shut, phase advance
      // declined). None of those are retried inside the tick — the next tick re-reads durable
      // state, which is the only safe input after a refusal.
      deps.logger.error(`money-workers: receive settle failed op=${row.operationId}`, err);
    }
  }
  return decided;
}
