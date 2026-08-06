// Money worker loops for custody main (slice A / C1).
//
// After armMoneySurface:
//   0. mirror CREATED receive_operations → operations (pool allocator surface)
//   1. pool scale-up via runPoolScaleUp + node_generated mint (vault-sealed)
//   2. promoteQueuedReceives → assignReceiveWallet (ReceiveLeasePort)
//   3. expireQueueAgedReceives for never-assigned CREATED rows
//   4. post-assign: real gateway T0 OBSERVE (get_transaction__v1; requires gatewayUrls
//      unless explicit allowGenesisT0Stub for offline tests)
//      → formReceiveCodeAndArtifact → commitReceiveReady
//   5. intake: receiver-channel inbox → createCandidateIntakeService → STEP1 durable
//      (runReceiveCandidateIntakeStep)
//   6. settle: durable candidates on any resumable rung of the attempt ladder → co-sign →
//      submit once, or confirm-read and reconcile (runReceiveSettleStep)
//   7. land: parked STEP2_SIGNATURE_PERSISTED attempts → durable RECEIVE_TERMINAL_CHECK
//      OBSERVE + landing-proof commit → RECEIVE_LANDED (runReceiveLandingStep,
//      landing steps 1–4). Read-only — never submits, never releases the receiver lease.
//
// Workers MUST NOT invent recovery_verified_at. Freshly minted pool wallets stay
// recovery-unverified; assign returns NO_ELIGIBLE_WALLET until the operator runs the
// recovery-verification ceremony (src/ops/run-recovery-ceremony.ts).

import { generateKeyPairSync, randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  assignReceiveWallet,
  captureReceiveT0,
  commitReceiveReady,
  createMoneySignerBoundaryDeps,
  createSqlSignerAuditLog,
  expireQueueAgedReceives,
  formReceiveCodeAndArtifact,
  GENESIS_PROJECTION,
  InMemoryDeviceKeyStore,
  loadExpiredReceiveCandidates,
  promoteQueuedReceives,
  PushSubscriptionRequiredError,
  runPoolScaleUp,
  runSendPostApproveFormation,
  SqlReceiveExpiryReleaseService,
  toBase64UrlPadded,
  type DeviceKeyStore,
  type DualChainEventQuota,
  type EncryptedWalletKeyStore,
  type GatewayLimits,
  type MintWallet,
  type MoneyPathSignerGates,
  type MetricsHooks,
  type NodeEventSigner,
  type ReceiveCodeFormationStore,
  type ReceiveCodeNodeIdentitySigner,
  type ReceiveLeasePort,
  type ReceiveReadyEventAppender,
  type GatewayExchangeTransport,
  type ReceiveT0Observer,
  type SendFormationObserver,
  type SenderPreflightObserver,
  type SignerBoundaryDeps,
  type SignerLeadershipLatch,
  type SqlQueryFn,
  type Uuid,
  type WalletPublicKey,
} from "@zucoins/node-core";

import { createDurableReceiveReadyEventAppender } from "./receive-ready-event-appender.js";
import { createReceiveLeasePort } from "./receive-lease-port.js";
import { createSqlReceiveCodeFormationStore } from "./sql-code-formation-store.js";
import { createGenesisT0Observer } from "./genesis-t0-observer.js";
import { createGatewayT0Observer } from "./gateway-t0-observer.js";
import {
  createCandidateIntakeInbox,
  runReceiveCandidateIntakeStep,
  type CandidateIntakeInbox,
} from "./receive-candidate-intake-step.js";
import { createGatewaySenderPreflightObserver } from "./sql-candidate-intake-ports.js";
import { runReceiveSettleStep } from "./receive-settle-step.js";
import { runReceiveLandingStep } from "./receive-landing-step.js";
import { runReceiveChildHandoffStep } from "./receive-child-handoff-step.js";
import { createSqlFreshHeadReader } from "./sql-fresh-head-reader.js";
import { createSqlReceiveLandingStore } from "./sql-landing-store.js";

/**
 * Money gates for workers. Production ports from createMoneyPathAdmissionPorts also
 * expose required assertHaltAdmitsKind so SEND first formation
 * refuse while RECEIVE_EXTERNAL still advances under shared assertMoneyAdmitted.
 * MOVE first formation consults the same port inside signMoveStepsUnderLeases.
 */
type WorkerMoneyPathGates = MoneyPathSignerGates & {
  readonly assertHaltAdmitsKind: (kind: string) => void;
};
import { tickSendCompletionLander } from "./send-completion-lander.js";
import { createSendFormationObserverFromReceiveT0 } from "./send-formation-observer.js";
import { createSqlLeaseReader } from "./send-signer-deps.js";
import {
  createSqlApprovalIdLoader,
  createSqlApprovedSendClaimPort,
  createSqlExternalSendLandingStore,
  createSqlPartialDeliveryMarker,
  createSqlPartialPort,
  createSqlSendSourceLeasePort,
  createSqlSignIntentPort,
  loadApprovedUnsignedSendIds,
  mirrorSendOperationsToOperations,
} from "./send-sql-ports.js";
import { createPoolVaultSigner } from "./send-vault-signer.js";
import {
  createMoveInternalLeaseAndProgressPorts,
  tickMoveInternalMoneyWorkers,
} from "./move-internal-worker.js";
import type { MoveInternalMoneyWorkerPorts } from "@zucoins/node-core";

function createSqlQueryFn(pool: Pool): SqlQueryFn {
  return async (text, values) => {
    const result = await pool.query(text, values as unknown[]);
    return result.rows as readonly Record<string, unknown>[];
  };
}

export interface MoneyWorkerLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface MoneyWorkerConfig {
  readonly nodeId: string;
  readonly ownerInstanceId: string;
  readonly poolCapTotal: number;
  readonly receiveQueueCap: number;
  readonly receiveQueueMaxWaitSecs: number;
  readonly receiveTtlDefaultSecs: number;
  readonly receiveTtlMinSecs: number;
  readonly receiveTtlMaxSecs: number;
  readonly tickIntervalMs: number;
  /**
   * SPLITCHAIN_GATEWAY_URLS. When non-empty the money path uses real OBSERVE
   * (get_transaction__v1). Empty/omitted without allowGenesisT0Stub refuses start.
   */
  readonly gatewayUrls?: readonly string[];
  /**
   * Test-only: allow the genesis T0 stub when gatewayUrls is empty/omitted.
   * Default false — production money path must not silently invent genesis S/P/B.
   */
  readonly allowGenesisT0Stub?: boolean;
  /**
   * Test-only: start event-producing workers with no EVENT_SIGNING signer.
   * Default false — production refuses to arm engines that would commit custody
   * transitions whose events can never be signed (Byte-exact). Offline suites that only
   * exercise composition, leases or expiry set this explicitly.
   */
  readonly allowMissingEventSigner?: boolean;
}

export interface StartMoneyWorkersDeps {
  readonly pool: Pool;
  readonly vault: EncryptedWalletKeyStore;
  readonly config: MoneyWorkerConfig;
  readonly logger: MoneyWorkerLogger;
  readonly moneyPathGates: WorkerMoneyPathGates;
  readonly nodeIdentitySigner: () => ReceiveCodeNodeIdentitySigner | null;
  /**
   * Sealed EVENT_SIGNING signer for the durable event chains. An unsigned event
   * is never written.
   *
   * Required at start. Omitting it, or returning null, refuses the worker start
   * unless `config.allowMissingEventSigner` is explicitly set (test-only). Optionality here
   * used to mean "commit the transition, log the missing event" — the exact Byte-exact breach this
   * gate closes.
   */
  readonly eventSigner?: () => NodeEventSigner | null;
  /** Optional override of the per-implementer event-append quota (tests / tuning). */
  readonly eventQuota?: DualChainEventQuota;
  /**
   * Fired AFTER the scale-up transaction commits, with the wallet ids just
   * minted. Push provisioning is a network call to a third party, so it must never run
   * inside the DB transaction, and the wallet rows must already be visible to the
   * subscriber. Failures are swallowed by the callback itself; the boot reconcile and the
   * periodic sweep are the backstop that eventually subscribes anything missed here. // contract-allow:sweep:frozen structural vocabulary
   */
  readonly onWalletsMinted?: (walletIds: readonly string[]) => void;
  /**
   * Push subscription gate. When provided, EXTERNAL receive formation and
   * EXTERNAL send formation check that the wallet has an ACTIVE push subscription before
   * proceeding. MOVE_INTERNAL is exempt. Absence disables the gate (offline tests).
   */
  readonly requireActivePushSubscription?: (walletId: string) => Promise<void>;
  /**
   * Process-wide signer leadership latch, handed to the settle step. Omitting it disables the
   * step rather than running it unlatched.
   *
   * Presence is a wiring condition, not the enforcement: `.held` is read inside the step, by
   * signUnderLease on a first pass and by settleReceiveAttempt's own restatement on
   * the resume branch that has nothing left to sign. The tick body carries the engine-quiesce
   * barrier on top of both.
   */
  readonly leadership?: SignerLeadershipLatch;
  /** Submit endpoint + limits for the settle step's single submit. Omitted ⇒ no settle step. */
  readonly submitGateway?: {
    readonly endpoint: string;
    readonly limits: GatewayLimits;
    /** Offline fixture injection for settle + intake sender-preflight. */
    readonly exchange?: GatewayExchangeTransport;
  };
  /**
   * Production main binds stamped.runUnderLeadership so each tick is
   * observed on the inflight set and refused once engines quiesce. Unit tests
   * may omit (no leadership handle).
   */
  readonly runUnderLeadership?: <T>(work: () => Promise<T>) => Promise<T>;
  /**
   * Shutdown-contract sign windows — formation / NODE_IDENTITY (not only signUnderLease).
   * Production main binds authority.trackSigningInflight.
   */
  readonly trackSigningInflight?: (work: Promise<unknown>) => void;
  /** Offline fixture injection — synthetic gateway exchange for T0 OBSERVE tests. */
  readonly gatewayExchange?: GatewayExchangeTransport;
  /**
   * GATEWAY_READ_RETRY_MAX_ATTEMPTS / GATEWAY_READ_BACKOFF_MAX_MS — bounds for every gateway
   * READ fanned out below (T0 observe, fresh-head confirm-read, sender preflight). Golden
   * rule 4: never threaded into any submit path (submitGateway above has no such field).
   */
  readonly gatewayMaxAttempts?: number;
  readonly gatewayBackoffMaxMs?: number;
  /** Optional observer override (tests). When set, gatewayUrls/stub selection is skipped. */
  readonly t0Observer?: ReceiveT0Observer;
  /**
   * Optional full SEND formation observer (tests). Default composes source +
   * dest OBSERVE from the same gated T0 observer (gateway or allowGenesisT0Stub).
   */
  readonly sendFormationObserver?: SendFormationObserver;
  /**
   * Optional SignerBoundaryDeps for SEND form/sign. When omitted, worker builds
   * vault + leadership from pool/vault; when null, post-approve formation is skipped
   * (signer unavailable — same residual model as NODE_IDENTITY).
   */
  readonly sendSignerDeps?: SignerBoundaryDeps | null | (() => SignerBoundaryDeps | null);
  /**
   * Leadership latch for default sendSignerDeps composition (main provides stamped latch).
   */
  readonly signerLeadership?: SignerLeadershipLatch;
  /**
   * Optional full MOVE_INTERNAL money-path ports (baseline/form/sign/submit/land).
   * When omitted, lease + durable progress still run; advanced steps WAIT until bound
   * (offline composition injects the full fake set; live ≤0.01 is Wave 4).
   */
  readonly moveInternalPorts?: Partial<MoveInternalMoneyWorkerPorts>;
  /** Optional sender-preflight OBSERVE (tests). Production builds from submitGateway. */
  readonly senderPreflightObserver?: SenderPreflightObserver;
  /** Optional inbox override (tests). */
  readonly candidateIntakeInbox?: CandidateIntakeInbox;
  /**
   * Device key store for SEND landing device-signature verification (B5). When
   * omitted, an empty in-memory store is used (fail-closed: TOTP_AND_DEVICE approvals will
   * not verify). Production passes the durable store from main.
   */
  readonly deviceKeyStore?: DeviceKeyStore;
  readonly metricsHooks?: MetricsHooks;
}

export interface MoneyWorkersHandle {
  readonly stop: () => void;
  readonly leases: ReceiveLeasePort;
  readonly formationStore: ReceiveCodeFormationStore;
  /** Enqueue a payer step-1 partial for the next leadership intake drain. */ // contract-allow:drain:frozen structural vocabulary
  readonly candidateIntake: CandidateIntakeInbox;
  /**
   * Run one money tick body (same path as the interval). Offline PG and
   * boot diagnostics use this so proofs go through leadership intake, not only the bare step.
   */
  readonly tickOnce: () => Promise<void>;
  /** True only after a real tick completed without throwing and before stop. */
  readonly healthy: () => boolean;
}

type SqlTx = {
  query: <R>(
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: R[]; rowCount: number | null }>;
};

async function withTransaction<T>(pool: Pool, fn: (tx: SqlTx) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const tx: SqlTx = {
      query: async <R>(text: string, params?: readonly unknown[]) => {
        const result = await client.query(text, params as never);
        return { rows: result.rows as R[], rowCount: result.rowCount };
      },
    };
    const out = await fn(tx);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* original */
    }
    throw err;
  } finally {
    client.release();
  }
}

async function mirrorReceiveOperationsToOperations(
  pool: Pool,
  logger: MoneyWorkerLogger,
): Promise<number> {
  const result = await pool.query(
    `INSERT INTO operations (
       id, node_id, implementer_id, kind, status, amount_zkz,
       after_landing, after_landing_destination_id,
       discriminator, anchor, idempotency_key, request_sha256, formation_state
     )
     SELECT
       r.operation_id,
       r.node_id,
       r.implementer_id,
       'RECEIVE_EXTERNAL'::operation_kind,
       'CREATED'::operation_status,
       r.amount_zkz,
       r.after_landing_kind,
       CASE WHEN r.after_landing_kind = 'INTERNAL_MOVE' THEN r.destination_id ELSE NULL END,
       r.operation_id,
       r.anchor,
       r.idempotency_key,
       r.request_sha256,
       'NOT_REQUIRED'::external_formation_state
     FROM receive_operations r
     WHERE r.status = 'CREATED'
       AND r.wallet_id IS NULL
       AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.id = r.operation_id)
     ON CONFLICT DO NOTHING`,
  );
  const n = result.rowCount ?? 0;
  if (n > 0) {
    logger.info(`money-workers: mirrored ${n} receive_operations → operations`);
  }
  return n;
}

function createPoolMint(deps: {
  readonly pool: Pool;
  readonly vault: EncryptedWalletKeyStore;
  readonly nodeId: string;
}): MintWallet {
  return async (_db, _batchIndex) => {
    const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
    const spki = pubObj.export({ format: "der", type: "spki" });
    const publicKey = toBase64UrlPadded(Buffer.from(spki).subarray(-32)) as WalletPublicKey;
    const jwk = privateKey.export({ format: "jwk" });
    const d = typeof jwk.d === "string" ? jwk.d : "";
    const seed = Buffer.from(d, "base64url");
    const secret64 = Buffer.concat([seed, Buffer.from(spki).subarray(-32)]);
    const walletId = randomUUID() as Uuid;
    try {
      // Commit wallet on the pool (not the scale-up txn client) so vault.seal's
      // separate connection can see wallet_id for FK (vault insert is not on txn).
      await deps.pool.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ($1::uuid, $2::uuid, $3, 'node_generated', 'AVAILABLE')`,
        [walletId, deps.nodeId, publicKey],
      );
      // recovery_verified_at intentionally NULL — workers never stamp recovery verification.
      await deps.vault.seal(
        {
          nodeId: deps.nodeId as Uuid,
          walletId,
          keyVersion: 1,
          publicKey,
          keyOrigin: "node_generated",
        },
        secret64,
      );
      return walletId;
    } catch (err) {
      try {
        await deps.pool.query(`DELETE FROM wallets WHERE id = $1::uuid`, [walletId]);
      } catch {
        /* best-effort */
      }
      throw err;
    } finally {
      secret64.fill(0);
    }
  };
}

type AssignedRow = {
  readonly operationId: string;
  readonly walletId: string;
  readonly leaseEpoch: bigint;
  readonly implementerId: string;
  readonly amountZkz: string;
  readonly anchor: string;
  readonly afterLandingKind: string;
  readonly destinationId: string | null;
  readonly ttlMs: number | null;
};

async function loadAssignedPendingFormation(pool: Pool): Promise<readonly AssignedRow[]> {
  const result = await pool.query<{
    operation_id: string;
    wallet_id: string;
    lease_epoch: string;
    implementer_id: string;
    amount_zkz: string;
    anchor: string;
    after_landing: string | null;
    after_landing_destination_id: string | null;
    ttl_ms: string | null;
  }>(
    `SELECT o.id::text AS operation_id,
            ow.wallet_id::text AS wallet_id,
            l.lease_epoch::text AS lease_epoch,
            o.implementer_id::text AS implementer_id,
            o.amount_zkz,
            COALESCE(o.anchor, 'recv') AS anchor,
            o.after_landing,
            o.after_landing_destination_id::text AS after_landing_destination_id,
            ro.ttl_ms::text AS ttl_ms
       FROM operations o
       JOIN operation_wallets ow
         ON ow.operation_id = o.id AND ow.operation_role = 'RECEIVER'
       JOIN wallet_active_leases l
         ON l.operation_id = o.id
        AND l.wallet_id = ow.wallet_id
        AND l.lease_role = 'RECEIVE_WINDOW'
       LEFT JOIN receive_operations ro ON ro.operation_id = o.id
      WHERE o.kind = 'RECEIVE_EXTERNAL'
        AND o.status = 'CREATED'
        AND NOT EXISTS (SELECT 1 FROM receive_codes rc WHERE rc.operation_id = o.id)
      ORDER BY o.created_at ASC, o.id ASC -- contract-allow:order:frozen structural vocabulary
      LIMIT 25`,
  );
  return result.rows.map((r) => ({
    operationId: r.operation_id,
    walletId: r.wallet_id,
    leaseEpoch: BigInt(r.lease_epoch),
    implementerId: r.implementer_id,
    amountZkz: r.amount_zkz,
    anchor: r.anchor,
    afterLandingKind: r.after_landing ?? "HOLD",
    destinationId: r.after_landing_destination_id,
    ttlMs: r.ttl_ms !== null && r.ttl_ms !== undefined ? Number(r.ttl_ms) : null,
  }));
}

async function syncReceiveOperationsAfterReady(
  pool: Pool,
  params: { readonly operationId: string; readonly walletId: string; readonly responseBody: string },
): Promise<void> {
  await pool.query(
    `UPDATE receive_operations
        SET status = 'READY',
            wallet_id = $2::uuid,
            completed_at = COALESCE(completed_at, now()),
            response_status = 200,
            response_body = $3
      WHERE operation_id = $1::uuid AND status IN ('CREATED', 'READY')`,
    [params.operationId, params.walletId, params.responseBody],
  );
}

async function advanceAssignedReceive(deps: {
  readonly pool: Pool;
  readonly row: AssignedRow;
  readonly config: MoneyWorkerConfig;
  readonly observer: ReceiveT0Observer;
  readonly formationStore: ReceiveCodeFormationStore;
  readonly moneyPathGates: WorkerMoneyPathGates;
  readonly nodeIdentitySigner: () => ReceiveCodeNodeIdentitySigner | null;
  readonly logger: MoneyWorkerLogger;
  /** Built per transaction so the event row commits with the READY CAS. */
  readonly events: (tx: SqlTx) => ReceiveReadyEventAppender;
  /** Push subscription gate (optional; absent = disabled). */
  readonly requireActivePushSubscription?: (walletId: string) => Promise<void>;
}): Promise<void> {
  // Defer EXTERNAL receive formation when the wallet has no ACTIVE push
  // subscription. The periodic reconciliation repairs it; the next tick retries. // contract-allow:sweep:frozen structural vocabulary
  if (deps.requireActivePushSubscription !== undefined) {
    try {
      await deps.requireActivePushSubscription(deps.row.walletId);
    } catch (err) {
      if (err instanceof PushSubscriptionRequiredError) {
        deps.logger.info(
          `money-workers: RECEIVE DEFERRED op=${deps.row.operationId} wallet=${deps.row.walletId} — push subscription not ACTIVE (reconciliation will repair)`,
        );
        return;
      }
      throw err;
    }
  }

  const signer = deps.nodeIdentitySigner();
  if (signer === null) {
    deps.logger.info(
      `money-workers: skip form for ${deps.row.operationId} — NODE_IDENTITY signer unavailable`,
    );
    return;
  }

  const poolSql = {
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const result = await deps.pool.query(text, params as never);
      return { rows: result.rows as R[], rowCount: result.rowCount };
    },
  };

  const t0Outcome = await captureReceiveT0(poolSql, {
    operationId: deps.row.operationId,
    walletId: deps.row.walletId,
    observer: deps.observer,
    assertMoneyAdmitted: () => deps.moneyPathGates.assertMoneyAdmitted(),
  });

  let t0 = t0Outcome.kind === "CAPTURED" ? t0Outcome.t0 : null;
  let walletPublicKey = t0Outcome.kind === "CAPTURED" ? t0Outcome.walletPublicKey : null;
  const leaseEpoch = t0Outcome.kind === "CAPTURED" ? t0Outcome.leaseEpoch : deps.row.leaseEpoch;

  if (t0Outcome.kind === "ALREADY_CAPTURED") {
    const proj = await deps.pool.query<{
      public_key: string;
      s_signature: string | null;
      p_signature: string | null;
      b_amount: string | null;
    }>(
      `SELECT w.public_key, go.s_signature, go.p_signature, go.b_amount
         FROM operation_observation_bindings b
         JOIN gateway_observations go ON go.id = b.observation_id
         JOIN wallets w ON w.public_key = b.wallet_public_key
        WHERE b.operation_id = $1::uuid AND b.evidence_role = 'RECEIVER_T0'
        LIMIT 1`,
      [deps.row.operationId],
    );
    const p = proj.rows[0];
    if (p === undefined) return;
    t0 = {
      observationId: t0Outcome.t0ObservationId,
      s0: p.s_signature ?? GENESIS_PROJECTION.S,
      p0: p.p_signature ?? GENESIS_PROJECTION.P,
      b0: p.b_amount ?? GENESIS_PROJECTION.B,
    };
    walletPublicKey = p.public_key;
  }

  if (t0 === null || walletPublicKey === null) {
    deps.logger.info(
      `money-workers: T0 not ready for ${deps.row.operationId} outcome=${t0Outcome.kind}`,
    );
    return;
  }

  const afterLanding =
    deps.row.afterLandingKind === "INTERNAL_MOVE" && deps.row.destinationId !== null
      ? { kind: "INTERNAL_MOVE" as const, destination_id: deps.row.destinationId }
      : { kind: "HOLD" as const, destination_id: null };

  const requestedTtlSecs =
    deps.row.ttlMs !== null && Number.isFinite(deps.row.ttlMs)
      ? Math.max(1, Math.floor(deps.row.ttlMs / 1000))
      : undefined;

  const formed = await formReceiveCodeAndArtifact({
    nodeId: deps.config.nodeId,
    implementerId: deps.row.implementerId,
    operationId: deps.row.operationId,
    receiverWalletId: deps.row.walletId,
    receiverPubkey: walletPublicKey,
    amountZkz: deps.row.amountZkz,
    anchor: deps.row.anchor.length > 0 ? deps.row.anchor : "recv",
    afterLanding,
    t0,
    requestedTtlSecs,
    ttlBounds: {
      defaultSecs: deps.config.receiveTtlDefaultSecs,
      minSecs: deps.config.receiveTtlMinSecs,
      maxSecs: deps.config.receiveTtlMaxSecs,
    },
    nowUnixMs: Date.now(),
    artifactId: randomUUID(),
    signer,
    store: deps.formationStore,
  });

  if (!formed.ok) {
    deps.logger.info(
      `money-workers: form rejected op=${deps.row.operationId} reason=${formed.reason} detail=${formed.detail}`,
    );
    return;
  }

  const commitResult = await withTransaction(deps.pool, async (tx) =>
    commitReceiveReady({
      formed: formed.formed,
      receiverWalletId: deps.row.walletId,
      leaseEpoch,
      readyAt: new Date().toISOString(),
      destinationId: afterLanding.kind === "INTERNAL_MOVE" ? afterLanding.destination_id : null,
      sql: tx,
      events: deps.events(tx),
    }),
  );

  if (!commitResult.ok) {
    deps.logger.info(
      `money-workers: commitReceiveReady rejected op=${deps.row.operationId} reason=${commitResult.reason}: ${commitResult.detail}`,
    );
    return;
  }

  await syncReceiveOperationsAfterReady(deps.pool, {
    operationId: deps.row.operationId,
    walletId: deps.row.walletId,
    responseBody: commitResult.responseBody,
  });

  deps.logger.info(
    `money-workers: RECEIVE READY op=${deps.row.operationId} wallet=${deps.row.walletId} code_status=AWAITING_ARM`,
  );
}


async function advanceApprovedSends(deps: {
  readonly pool: Pool;
  readonly config: MoneyWorkerConfig;
  readonly logger: MoneyWorkerLogger;
  readonly moneyPathGates: WorkerMoneyPathGates;
  readonly observer: SendFormationObserver;
  readonly resolveSignerDeps: () => SignerBoundaryDeps | null;
  readonly trackSigningInflight?: (work: Promise<unknown>) => void;
  readonly stopped: () => boolean;
}): Promise<void> {
  let approved: readonly string[];
  try {
    approved = await loadApprovedUnsignedSendIds(deps.pool);
  } catch (err) {
    deps.logger.info(
      `money-workers: SEND post-approve load skipped (${err instanceof Error ? err.message : "err"})`,
    );
    return;
  }
  if (approved.length === 0) return;

  const signerDeps = deps.resolveSignerDeps();
  if (signerDeps === null) {
    deps.logger.info(
      `money-workers: skip SEND form for ${approved.length} APPROVED — signer deps unavailable (vault/leadership residual; NODE_IDENTITY sealed-store signer not armed)`,
    );
    return;
  }

  const claimPort = createSqlApprovedSendClaimPort(deps.pool);
  const leasePort = createSqlSendSourceLeasePort(deps.pool, deps.config.ownerInstanceId);
  const approvalIds = createSqlApprovalIdLoader(deps.pool);
  const signIntentPort = createSqlSignIntentPort(deps.pool);
  const partialPort = createSqlPartialPort(deps.pool);
  const delivery = createSqlPartialDeliveryMarker(deps.pool);

  for (const operationId of approved) {
    if (deps.stopped()) break;
    try {
      deps.moneyPathGates.assertMoneyAdmitted();
      // SEND first formation is halt-gated; RECEIVE is not.
      deps.moneyPathGates.assertHaltAdmitsKind("SEND_EXTERNAL");
      const now = Date.now();
      const iso = new Date(now).toISOString();
      const work = runSendPostApproveFormation({
        operationId,
        ownerInstanceId: deps.config.ownerInstanceId,
        capturedAt: now,
        nodeClockMs: now,
        preparedAt: iso,
        persistedAt: iso,
        claimPort,
        leasePort,
        observer: deps.observer,
        approvalIds,
        signIntentPort,
        partialPort,
        signerDeps,
        delivery,
        backoff: { maxAttempts: 3, baseDelayMs: 50, maxDelayMs: 200 },
      });
      deps.trackSigningInflight?.(work);
      const result = await work;
      if (result.ok) {
        deps.logger.info(
          `money-workers: SEND AWAITING_REDEMPTION op=${result.operationId} transfer_code_sha256=${result.transferCodeSha256.slice(0, 16)}… (node never submits)`,
        );
      } else {
        deps.logger.info(
          `money-workers: SEND form deferred op=${result.operationId} reason=${result.reason} detail=${result.detail}`,
        );
      }
    } catch (err) {
      deps.logger.error(`money-workers: SEND post-approve failed op=${operationId}`, err);
    }
  }
}

/**
 * Receive expiry-release worker step. Scans for RECEIVE_EXTERNAL
 * operations past their expiry (+ 30s safety margin), drives the proof-backed
 * SqlReceiveExpiryReleaseService for each. The service handles all predicate
 * evaluation, attention routing, and proof-backed lease release (One-in-flight — never
 * a raw DELETE from wallet_active_leases).
 */
async function runReceiveExpiryReleaseStep(deps: {
  readonly pool: Pool;
  readonly logger: MoneyWorkerLogger;
  readonly stopped: () => boolean;
}): Promise<{
  readonly processed: number;
  readonly released: number;
  readonly attention: number;
}> {
  const candidates = await loadExpiredReceiveCandidates({
    query: async <R>(text: string, params?: readonly unknown[]) => {
      const result = await deps.pool.query(text, params as never);
      return { rows: result.rows as R[], rowCount: result.rowCount };
    },
  });
  if (candidates.length === 0) {
    return { processed: 0, released: 0, attention: 0 };
  }

  const service = new SqlReceiveExpiryReleaseService({
    withTransaction: async <T>(fn: (tx: SqlTx) => Promise<T>): Promise<T> => {
      const client = await deps.pool.connect();
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const tx: SqlTx = {
          query: async <R>(text: string, params?: readonly unknown[]) => {
            const result = await client.query(text, params as never);
            return { rows: result.rows as R[], rowCount: result.rowCount };
          },
        };
        const out = await fn(tx);
        await client.query("COMMIT");
        return out;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          /* original */
        }
        throw err;
      } finally {
        client.release();
      }
    },
  });

  let processed = 0;
  let released = 0;
  let attention = 0;

  for (const candidate of candidates) {
    if (deps.stopped()) break;
    processed++;
    try {
      const outcome = await service.expire({
        operationId: candidate.operationId,
        freshObservationId: null,
        nowMs: Date.now(),
      });
      switch (outcome.kind) {
        case "RELEASED":
          released++;
          deps.logger.info(
            `money-workers: receive expiry RELEASED op=${candidate.operationId} ` +
              `wallet=${outcome.walletId} status=${outcome.releaseStatus} ` +
              `proof=${outcome.receiveReleaseProofId}`,
          );
          break;
        case "NEEDS_ATTENTION":
          attention++;
          deps.logger.info(
            `money-workers: receive expiry ATTENTION op=${candidate.operationId} ` +
              `reason=${outcome.attentionReason} episode=${outcome.attentionEpisode} ` +
              `failed=${outcome.failedPredicates.join(",")}`,
          );
          break;
        case "NOT_EXPIRED":
        case "NOT_FOUND":
        case "LANDED":
        case "ALREADY_RELEASED":
        case "CONFLICT":
          break;
        case "EXPIRED_UNASSIGNED":
          deps.logger.info(
            `money-workers: receive expiry UNASSIGNED op=${candidate.operationId}`,
          );
          break;
        case "INVARIANT_BREACH":
          deps.logger.info(
            `money-workers: receive expiry INVARIANT_BREACH op=${candidate.operationId} ` +
              `wallet=${outcome.walletId}`,
          );
          break;
      }
    } catch (err) {
      deps.logger.error(
        `money-workers: receive expiry failed op=${candidate.operationId}`,
        err,
      );
    }
  }

  return { processed, released, attention };
}

/**
 * Select the receive T0 observer for the money path.
 * Gateways configured → real get_transaction__v1 OBSERVE (never genesis stub).
 * Empty/omitted URLs refuse unless allowGenesisT0Stub is explicitly true (tests only).
 */
export function resolveMoneyPathT0Observer(deps: {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly gatewayUrls: readonly string[] | undefined;
  readonly gatewayExchange?: GatewayExchangeTransport;
  readonly gatewayMaxAttempts?: number;
  readonly gatewayBackoffMaxMs?: number;
  readonly t0Observer?: ReceiveT0Observer;
  readonly allowGenesisT0Stub?: boolean;
  readonly metricsHooks?: MetricsHooks;
}): { readonly observer: ReceiveT0Observer; readonly kind: "gateway" | "genesis_stub" | "injected" } {
  if (deps.t0Observer !== undefined) {
    return { observer: deps.t0Observer, kind: "injected" };
  }
  const urls = deps.gatewayUrls ?? [];
  if (urls.length > 0) {
    return {
      observer: createGatewayT0Observer({
        pool: deps.pool,
        nodeId: deps.nodeId,
        gatewayUrls: urls,
        ...(deps.gatewayExchange !== undefined
          ? { exchange: deps.gatewayExchange }
          : {}),
        ...(deps.gatewayMaxAttempts !== undefined
          ? { maxAttempts: deps.gatewayMaxAttempts }
          : {}),
        ...(deps.gatewayBackoffMaxMs !== undefined
          ? { backoffMaxMs: deps.gatewayBackoffMaxMs }
          : {}),
        ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
      }),
      kind: "gateway",
    };
  }
  if (deps.allowGenesisT0Stub === true) {
    return {
      observer: createGenesisT0Observer({ pool: deps.pool, nodeId: deps.nodeId }),
      kind: "genesis_stub",
    };
  }
  throw new Error(
    "money path T0 observer requires non-empty gatewayUrls " +
      "(set allowGenesisT0Stub only for explicit offline tests)",
  );
}

export function startMoneyWorkers(deps: StartMoneyWorkersDeps): MoneyWorkersHandle {
  // Fail closed BEFORE any loop is armed: an event-producing worker that
  // cannot sign its events would commit custody transitions with the event logged
  // away as a residual (Byte-exact). Authority gates the transition, never the reverse.
  if (deps.config.allowMissingEventSigner !== true && (deps.eventSigner?.() ?? null) === null) {
    throw new Error(
      "money workers require an available EVENT_SIGNING signer " +
        "(set allowMissingEventSigner only for explicit offline tests)",
    );
  }
  const leases = createReceiveLeasePort();
  const formationStore = createSqlReceiveCodeFormationStore(deps.pool);
  const resolved = resolveMoneyPathT0Observer({
    pool: deps.pool,
    nodeId: deps.config.nodeId,
    gatewayUrls: deps.config.gatewayUrls,
    gatewayExchange: deps.gatewayExchange,
    gatewayMaxAttempts: deps.gatewayMaxAttempts,
    gatewayBackoffMaxMs: deps.gatewayBackoffMaxMs,
    t0Observer: deps.t0Observer,
    allowGenesisT0Stub: deps.config.allowGenesisT0Stub,
    ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
  });
  const observer = resolved.observer;
  deps.logger.info(
    `money-workers: T0 observer kind=${resolved.kind}` +
      (resolved.kind === "gateway"
        ? ` endpoints=${(deps.config.gatewayUrls ?? []).length}`
        : resolved.kind === "genesis_stub"
          ? " (explicit allowGenesisT0Stub)"
          : ""),
  );
  const sendObserver =
    deps.sendFormationObserver ?? createSendFormationObserverFromReceiveT0(observer);

  const resolveSendSignerDeps = (): SignerBoundaryDeps | null => {
    if (deps.sendSignerDeps === null) return null;
    if (typeof deps.sendSignerDeps === "function") return deps.sendSignerDeps();
    if (deps.sendSignerDeps !== undefined) return deps.sendSignerDeps;
    const leadership = deps.signerLeadership;
    if (leadership === undefined || !leadership.held) {
      return null;
    }
    try {
      return createMoneySignerBoundaryDeps(
        {
          leadership,
          leaseReader: createSqlLeaseReader(deps.pool),
          vaultSigner: createPoolVaultSigner({
            pool: deps.pool,
            vault: deps.vault,
            nodeId: deps.config.nodeId,
          }),
          auditLog: createSqlSignerAuditLog(createSqlQueryFn(deps.pool)),
        },
        deps.moneyPathGates,
      );
    } catch {
      return null;
    }
  };

  const mint = createPoolMint({
    pool: deps.pool,
    vault: deps.vault,
    nodeId: deps.config.nodeId,
  });
  // Real dual-chain appender, bound per transaction to the READY CAS.
  const events = (tx: SqlTx): ReceiveReadyEventAppender =>
    createDurableReceiveReadyEventAppender({
      sql: tx,
      nodeId: deps.config.nodeId,
      eventSigner: deps.eventSigner?.() ?? null,
      logger: deps.logger,
      ...(deps.eventQuota !== undefined ? { quota: deps.eventQuota } : {}),
    });
  const limits = {
    poolCapTotal: deps.config.poolCapTotal,
    receiveQueueMaxWaitSecs: deps.config.receiveQueueMaxWaitSecs,
  };
  const queueLimits = {
    receiveQueueCap: deps.config.receiveQueueCap,
    receiveQueueMaxWaitSecs: deps.config.receiveQueueMaxWaitSecs,
  };
  const candidateIntake = deps.candidateIntakeInbox ?? createCandidateIntakeInbox();
  const senderPreflightObserver =
    deps.senderPreflightObserver ??
    (deps.submitGateway !== undefined
      ? createGatewaySenderPreflightObserver({
          endpoint: deps.submitGateway.endpoint,
          limits: deps.submitGateway.limits,
          exchange: deps.submitGateway.exchange ?? deps.gatewayExchange,
          ...(deps.gatewayMaxAttempts !== undefined
            ? { maxAttempts: deps.gatewayMaxAttempts }
            : {}),
          ...(deps.gatewayBackoffMaxMs !== undefined
            ? { backoffMaxMs: deps.gatewayBackoffMaxMs }
            : {}),
        })
      : null);

  // Landing deps, built once. The fresh-head reader and landing
  // store are stateless closures over the pool. The reader needs non-empty gatewayUrls
  // (the same SPLITCHAIN_GATEWAY_URLS that submitGateway's endpoint comes from), so it is
  // null when no gateway is configured — the tick gate then skips the landing step.
  const receiveLandingDeps =
    deps.config.gatewayUrls !== undefined && deps.config.gatewayUrls.length > 0
      ? {
          readFreshHead: createSqlFreshHeadReader({
            pool: deps.pool,
            nodeId: deps.config.nodeId,
            gatewayUrls: deps.config.gatewayUrls,
            exchange: deps.gatewayExchange,
            ...(deps.gatewayMaxAttempts !== undefined
              ? { maxAttempts: deps.gatewayMaxAttempts }
              : {}),
            ...(deps.gatewayBackoffMaxMs !== undefined
              ? { backoffMaxMs: deps.gatewayBackoffMaxMs }
              : {}),
          }),
          store: createSqlReceiveLandingStore(deps.pool, deps.eventSigner?.() ?? null),
        }
      : null;

  let stopped = false;
  let tickInFlight = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  let lastTickHealthy = false;

  const stop = (): void => {
    stopped = true;
    lastTickHealthy = false;
    if (timer !== undefined) {
      clearInterval(timer);
      timer = undefined;
    }
    deps.logger.info("boot: money surface ENGINE_QUIESCE");
  };

  const executeTickBody = async (): Promise<void> => {
    await mirrorReceiveOperationsToOperations(deps.pool, deps.logger);

    let mintedWalletIds: readonly string[] = [];
    await withTransaction(deps.pool, async (tx) => {
      const result = await runPoolScaleUp(tx, { limits, mint });
      mintedWalletIds = result.mintedWalletIds;
      if (result.mintedWalletIds.length > 0) {
        deps.logger.info(
          `money-workers: pool scale-up minted=${result.mintedWalletIds.length} capCount=${result.plan.capCount} target=${result.plan.poolTargetTotal} (recovery_verified pending ceremony — not stamped here)`,
        );
      }
    });
    // Post-commit: subscribe the freshly minted wallets to push. Outside the
    // transaction because it talks to the push service over the network.
    if (mintedWalletIds.length > 0 && deps.onWalletsMinted !== undefined) {
      deps.onWalletsMinted(mintedWalletIds);
    }

    const promote = await promoteQueuedReceives(
      {
        query: async <R>(text: string, params?: readonly unknown[]) => {
          const result = await deps.pool.query(text, params as never);
          return { rows: result.rows as R[], rowCount: result.rowCount };
        },
      },
      {
        limits: queueLimits,
        allocate: async (operationId) =>
          withTransaction(deps.pool, async (tx) =>
            assignReceiveWallet(tx, {
              operationId,
              ownerInstanceId: deps.config.ownerInstanceId,
              leases,
              requireActiveSubscription: deps.requireActivePushSubscription,
            }),
          ),
      },
    );
    if (promote.promoted.length > 0) {
      deps.logger.info(
        `money-workers: promoted assigns=${promote.promoted.length} remaining_queued=${promote.remaining.length}`,
      );
    } else if (promote.remaining.length > 0) {
      deps.logger.info(
        `money-workers: NO_ELIGIBLE_WALLET for ${promote.remaining.length} queued receive(s) — pool wallets lack recovery_verified_at until the recovery-verified ceremony runs (node dist/ops/run-recovery-ceremony.js)`,
      );
    }

    const expiredReceives = await withTransaction(deps.pool, async (tx) =>
      expireQueueAgedReceives(tx, {
        limits,
        emitExpired: async (_db, p) => {
          await deps.pool.query(
            `UPDATE receive_operations
                SET status = 'EXPIRED',
                    completed_at = COALESCE(completed_at, now()),
                    response_status = COALESCE(response_status, 410),
                    response_body = COALESCE(response_body, $2)
              WHERE operation_id = $1::uuid AND status = 'CREATED'`,
            [
              p.operationId,
              JSON.stringify({ error: "receive_queue_expired", waited_secs: p.waitedSecs }),
            ],
          );
          deps.logger.info(
            `money-workers: queue-age expired op=${p.operationId} waitedSecs=${p.waitedSecs}`,
          );
        },
      }),
    );
    if (expiredReceives.expired.length > 0) {
      // Count only after the enclosing DB transaction committed. A rollback is not a terminal
      // operation seam and must not produce a failed lifecycle metric.
      for (const _operation of expiredReceives.expired) {
        deps.metricsHooks?.onOperationFailed("RECEIVE_EXTERNAL");
      }
      deps.logger.info(
        `money-workers: expired ${expiredReceives.expired.length} queue-aged receive(s)`,
      );
    }

    const pending = await loadAssignedPendingFormation(deps.pool);
    for (const row of pending) {
      if (stopped) break;
      try {
        // Formation calls NODE_IDENTITY sign (not signUnderLease) — still drain-tracked. // contract-allow:drain:frozen structural vocabulary
        const advance = advanceAssignedReceive({
          pool: deps.pool,
          row,
          config: deps.config,
          observer,
          formationStore,
          moneyPathGates: deps.moneyPathGates,
          nodeIdentitySigner: deps.nodeIdentitySigner,
          logger: deps.logger,
          events,
        });
        deps.trackSigningInflight?.(advance);
        await advance;
      } catch (err) {
        deps.logger.error(`money-workers: advance failed op=${row.operationId}`, err);
      }
    }

    // SEND_EXTERNAL post-approve formation. Node never submits.
    await mirrorSendOperationsToOperations(deps.pool, deps.logger);
    await advanceApprovedSends({
      pool: deps.pool,
      config: deps.config,
      logger: deps.logger,
      moneyPathGates: deps.moneyPathGates,
      observer: sendObserver,
      resolveSignerDeps: resolveSendSignerDeps,
      trackSigningInflight: deps.trackSigningInflight,
      stopped: () => stopped,
    });
    // SEND completion observe-lander. Requires gateway URLs for the source-head
    // confirm-read; when none are configured (genesis stub / offline) the lander is skipped —
    // no SEND can land without a gateway OBSERVE (AC3).
    // Isolated in its own try/catch (mirrors the MOVE_INTERNAL step below) so a
    // candidate-query fault (now thrown, never laundered into empty/idle — see
    // send-completion-lander.ts) surfaces on a distinct, greppable log line and does not also
    // abort the unrelated tick steps that follow (receive intake/settle, MOVE_INTERNAL).
    if ((deps.config.gatewayUrls ?? []).length > 0) {
      try {
        await tickSendCompletionLander({
          pool: deps.pool,
          logger: deps.logger,
          readFreshHead: createSqlFreshHeadReader({
            pool: deps.pool,
            nodeId: deps.config.nodeId,
            gatewayUrls: deps.config.gatewayUrls!,
            ...(deps.gatewayExchange !== undefined ? { exchange: deps.gatewayExchange } : {}),
            ...(deps.gatewayMaxAttempts !== undefined
              ? { maxAttempts: deps.gatewayMaxAttempts }
              : {}),
            ...(deps.gatewayBackoffMaxMs !== undefined
              ? { backoffMaxMs: deps.gatewayBackoffMaxMs }
              : {}),
          }),
          store: createSqlExternalSendLandingStore(deps.pool, deps.eventSigner?.() ?? null),
          nodeId: deps.config.nodeId,
          deviceKeyStore: deps.deviceKeyStore ?? new InMemoryDeviceKeyStore(),
          ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
        });
      } catch (err) {
        deps.logger.error("money-workers: SEND completion lander tick failed", err);
      }
    }

    // Intake: inbox → STEP1_SIGNATURE_PERSISTED under leadership.
    if (!stopped && deps.leadership !== undefined && deps.leadership.held && senderPreflightObserver !== null) {
      const accepted = await runReceiveCandidateIntakeStep({
        query: async (text, values) =>
          (await deps.pool.query(text, values as unknown[])).rows as Record<string, unknown>[],
        inbox: candidateIntake,
        observeSender: senderPreflightObserver,
        logger: deps.logger,
      });
      if (accepted > 0) {
        deps.logger.info(`money-workers: candidate intake accepted ${accepted} partial(s)`);
      }
    }

    // Settle pass for candidates intake made durable. Inside the quiesce tick barrier.
    if (!stopped && deps.leadership !== undefined && deps.leadership.held && deps.submitGateway !== undefined) {
      const settled = await runReceiveSettleStep({
        query: async (text, values) =>
          (await deps.pool.query(text, values as unknown[])).rows as Record<string, unknown>[],
        vault: deps.vault,
        nodeId: deps.config.nodeId,
        leadership: deps.leadership,
        moneyPathGates: deps.moneyPathGates,
        gateway: {
          endpoint: deps.submitGateway.endpoint,
          limits: deps.submitGateway.limits,
          exchange: deps.submitGateway.exchange ?? deps.gatewayExchange,
          ...(deps.gatewayMaxAttempts !== undefined
            ? { maxAttempts: deps.gatewayMaxAttempts }
            : {}),
          ...(deps.gatewayBackoffMaxMs !== undefined
            ? { backoffMaxMs: deps.gatewayBackoffMaxMs }
            : {}),
        },
        logger: deps.logger,
        ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
      });
      if (settled > 0) {
        deps.logger.info(`money-workers: receive settle decided ${settled} attempt(s)`);
      }
    }

    // Landing walk: durable RECEIVE_TERMINAL_CHECK + landing commit for
    // attempts the settle step parked at STEP2_SIGNATURE_PERSISTED. Read-only OBSERVE —
    // never submits, never releases the receiver lease (One-in-flight). Every non-APPLIED result is
    // INDETERMINATE: the next tick re-observes, never re-submits. Co-gated with the
    // settle step (leadership + submitGateway) so the landing step only runs when the full
    // money path is active; receiveLandingDeps is non-null only when gatewayUrls is non-empty.
    if (
      !stopped &&
      receiveLandingDeps !== null &&
      deps.leadership !== undefined && deps.leadership.held &&
      deps.submitGateway !== undefined
    ) {
      const landing = await runReceiveLandingStep({
        pool: deps.pool,
        nodeId: deps.config.nodeId,
        logger: deps.logger,
        readFreshHead: receiveLandingDeps.readFreshHead,
        store: receiveLandingDeps.store,
        ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
      });
      if (landing.landed.length > 0) {
        deps.logger.info(
          `money-workers: receive landing LANDED ${landing.landed.length} op(s)`,
        );
      }
      if (landing.indeterminate.length > 0) {
        if (landing.indeterminate.some((entry) => entry.detail.includes("BUDGET_EXHAUSTED"))) deps.metricsHooks?.onProofBudgetExhaustion();
        deps.logger.info(
          `money-workers: receive landing ${landing.indeterminate.length} indeterminate ` +
            `(re-observe next tick, no resubmit)`,
        );
      }
    }

    // After RECEIVE_LANDED + INTERNAL_MOVE, spawn child MOVE and
    // continuously transfer RECEIVE_WINDOW → MOVE_SOURCE (no chain submit here).
    if (!stopped) {
      try {
        const handoff = await runReceiveChildHandoffStep({
          pool: deps.pool,
          ownerInstanceId: deps.config.ownerInstanceId,
          logger: deps.logger,
        });
        if (handoff.spawned > 0 || handoff.failed > 0) {
          deps.logger.info(
            `money-workers: receive child handoff attempted=${handoff.attempted} ` +
              `spawned=${handoff.spawned} failed=${handoff.failed}`,
          );
        }
      } catch (err) {
        deps.logger.error("money-workers: receive child handoff tick failed", err);
      }
    }

    // Receive expiry-release: past-expiry receives driven through the
    // proof-backed SqlReceiveExpiryReleaseService (One-in-flight — no raw lease DELETE).
    if (!stopped) {
      try {
        const expiryResult = await runReceiveExpiryReleaseStep({
          pool: deps.pool,
          logger: deps.logger,
          stopped: () => stopped,
        });
        if (expiryResult.released > 0) {
          deps.logger.info(
            `money-workers: receive expiry-release processed=${expiryResult.processed} ` +
              `released=${expiryResult.released} attention=${expiryResult.attention}`,
          );
        }
      } catch (err) {
        deps.logger.error("money-workers: receive expiry-release tick failed", err);
      }
    }

    // MOVE_INTERNAL: lease → OBSERVE baselines → form/sign → submit-once → land
    // Injected advanced ports drives offline LANDED composition; without
    // them lease/progress still advances and post-lease steps WAIT (no blind submit).
    if (!stopped) {
      try {
        const movePorts = createMoveInternalLeaseAndProgressPorts({
          pool: deps.pool,
          ownerInstanceId: deps.config.ownerInstanceId,
          advanced: deps.moveInternalPorts,
        });
        await tickMoveInternalMoneyWorkers({
          pool: deps.pool,
          ownerInstanceId: deps.config.ownerInstanceId,
          logger: deps.logger,
          ports: movePorts,
          moneyPathGates: deps.moneyPathGates,
          trackSigningInflight: deps.trackSigningInflight,
          ...(deps.metricsHooks !== undefined ? { metricsHooks: deps.metricsHooks } : {}),
        });
      } catch (err) {
        deps.logger.error("money-workers: MOVE_INTERNAL tick failed", err);
      }
    }
  };

  const tick = async (): Promise<void> => {
    if (stopped || tickInFlight) return;
    tickInFlight = true;
    try {
      deps.moneyPathGates.assertMoneyAdmitted();
    } catch (err) {
      tickInFlight = false;
      deps.logger.info(
        `money-workers: tick skipped — money not admitted (${err instanceof Error ? err.message : "closed"})`,
      );
      return;
    }

    try {
      if (deps.runUnderLeadership !== undefined) {
        await deps.runUnderLeadership(executeTickBody);
      } else {
        await executeTickBody();
      }
      lastTickHealthy = true;
    } catch (err) {
      lastTickHealthy = false;
      deps.logger.error("money-workers: tick failed", err);
    } finally {
      tickInFlight = false;
    }
  };

  // Production arms an interval and a startup tick. Offline tests may set
  // tickIntervalMs=0 and drive only via handle.tickOnce (PG proof).
  if (deps.config.tickIntervalMs > 0) {
    void tick();
    timer = setInterval(() => {
      void tick();
    }, deps.config.tickIntervalMs);
    if (typeof timer === "object" && "unref" in timer) {
      timer.unref();
    }
  }

  deps.logger.info(
    `boot: money workers started intervalMs=${deps.config.tickIntervalMs} owner=${deps.config.ownerInstanceId}`,
  );

  return { stop, leases, formationStore, candidateIntake, tickOnce: tick, healthy: () => !stopped && lastTickHealthy };
}
