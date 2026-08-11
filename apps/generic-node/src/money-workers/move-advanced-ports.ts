// Production composition of the 5 advanced MOVE_INTERNAL money ports
// Each port binds a node-core helper to the custody
// pool + vault + gateway + leadership, adapting the same patterns as receive-settle-step.ts
//  and the SEND signer deps.
//
// Invariants: one in-flight transaction per wallet (dual-lease acquisition enforces this),
// Byte-exact (byte-exact JSON.stringify signing — the node-core helpers construct preimages
// from persisted text, never reformatted), No-blind-retry (claim-before-submit via
// bindExecuteMoveSubmitClaimOnce; never blind-retry).

import type { Pool, PoolClient } from "pg";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";

import {
  captureAndBindMoveBaselines,
  createMoneySignerBoundaryDeps,
  formMoveInner,
  landingProofToPathObservation,
  makeSubmitAttemptRecorder,
  makeSubmitDecisionClaimStore,
  MOVE_INTERNAL_ARTIFACT_PURPOSE,
  MOVE_INTERNAL_CANONICAL_VERSION,
  appendImplementerEventLeg,
  toAttentionReason,
  parseGatewayEnvelope,
  parsePositiveZkzAmount,
  persistMoveInnerAttemptSql,
  persistMoveOutcome,
  proveExactHeadLanding,
  signMoveStepsUnderLeases,
  resumeMoveStep2FromPersistedStep1,
  verifySettledTransaction,
  bindExecuteMoveSubmitClaimOnce,
  classifyMoveReconcile,
  createSqlSignerAuditLog,
  GENESIS_PROJECTION,
  buildNodeEvent,
  computeEventLogNodeEventHash,
  LEASE_STATEMENTS,
  parseSha256Hex,
  parseUuid,
  sha256HexUtf8,
  type GatewayExchangeTransport,
  type GatewayLimits,
  type MoveBaselineBound,
  type MoveBaselineObservationOutcome,
  type MoveBaselineObserver,
  type MoveInternalMoneyWorkerPorts,
  type MoveReconcileOutcome,
  type MoveReconcileInput,
  type MoveBaselineBindingInput,
  type MoveBaselineBindingResult,
  type DestinationEligibilityReader,
  type DestinationRecheck,
  type MoveNodeIdentitySigner,
  type PersistedExpectedArtifact,
  type MoveBaselineSqlExecutor,
  type SignerLeadershipLatch,
  type EncryptedWalletKeyStore,
  type MoneyPathSignerGates,
  type SqlQueryFn,
  type ReceiveCodeNodeIdentitySigner,
  type WalletStateProjection,
  type ReconcilePathObservation as PathObservation,
  type FreshHeadRead,
  type ReadFreshHead,
  type NodeEventInput,
  type NodeEventSigner,
  type SignedNodeEvent,
  type SignedMoveSteps,
  type MetricsHooks,
  recordWalletSettledLedger,
  writeExactHeadLineagePath,
} from "@zucoins/node-core";

import { issueLandedAccessWindow } from "./issue-landed-access-window.js";

import type { MoveInternalWorkerLogger } from "./move-internal-worker.js";
import {
  createSqlLeaseReader,
  createSqlSignUnderLeaseTransaction,
} from "./send-signer-deps.js";
import { createPoolVaultSigner } from "./send-vault-signer.js";
import { createSqlFreshHeadReader } from "./sql-fresh-head-reader.js";

export interface MoveAdvancedPortsDeps {
  readonly pool: Pool;
  readonly vault: EncryptedWalletKeyStore;
  readonly nodeId: string;
  readonly ownerInstanceId: string;
  readonly leadership: SignerLeadershipLatch;
  readonly moneyPathGates: MoneyPathSignerGates & {
    readonly assertHaltAdmitsKind: (kind: string) => void;
  };
  readonly submitGateway: {
    readonly endpoint: string;
    readonly limits: GatewayLimits;
    readonly exchange?: GatewayExchangeTransport;
  };
  readonly gatewayUrls: readonly string[];
  readonly gatewayExchange?: GatewayExchangeTransport;
  /**
   * GATEWAY_READ_RETRY_MAX_ATTEMPTS / GATEWAY_READ_BACKOFF_MAX_MS — the createSqlFreshHeadReader
   * READ below only. The never-blind-retry rule: never threaded into submitOptions.
   */
  readonly gatewayMaxAttempts?: number;
  readonly gatewayBackoffMaxMs?: number;
  readonly nodeIdentitySigner: () => ReceiveCodeNodeIdentitySigner | null;
  readonly logger: MoveInternalWorkerLogger;
  /** Transaction-local money-path statement_timeout (ZTR-1156). */
  readonly moneyPathStatementTimeoutMs?: number;
  /** ZTR-1144 — duplicate-submit metric seam. */
  readonly metricsHooks?: MetricsHooks;
}

interface MoveOperationDetails {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly sourceWalletId: string;
  readonly destinationId: string;
  readonly destinationWalletId: string;
  readonly sourcePublicKey: string;
  readonly destinationPublicKey: string;
  readonly amountZkz: string;
  readonly leaseGroupId: string;
  readonly spawnedFromOperationId: string | null;
  readonly referencesOperationId: string | null;
  readonly rowVersion: number;
}

const LOAD_MOVE_DETAILS_SQL = `
  SELECT
    o.id::text AS operation_id,
    o.implementer_id::text AS implementer_id,
    o.node_id::text AS node_id,
    o.source_wallet_id::text AS source_wallet_id,
    o.destination_id::text AS destination_id,
    d.wallet_id::text AS destination_wallet_id,
    sw.public_key AS source_public_key,
    dw.public_key AS destination_public_key,
    o.amount_zkz::text AS amount_zkz,
    lgo.lease_group_id::text AS lease_group_id,
    o.spawned_from_operation_id::text AS spawned_from_operation_id,
    o.references_operation_id::text AS references_operation_id,
    o.row_version::int AS row_version
  FROM operations o
  JOIN destinations d ON d.id = o.destination_id
  JOIN wallets sw ON sw.id = o.source_wallet_id
  JOIN wallets dw ON dw.id = d.wallet_id
  JOIN lease_group_operations lgo ON lgo.operation_id = o.id
  WHERE o.id = $1::uuid AND o.kind = 'MOVE_INTERNAL'
`;

async function loadMoveDetails(pool: Pool, operationId: string): Promise<MoveOperationDetails | null> {
  const result = await pool.query<{
    operation_id: string; implementer_id: string; node_id: string;
    source_wallet_id: string; destination_id: string; destination_wallet_id: string;
    source_public_key: string; destination_public_key: string; amount_zkz: string;
    lease_group_id: string; spawned_from_operation_id: string | null;
    references_operation_id: string | null; row_version: number;
  }>(LOAD_MOVE_DETAILS_SQL, [operationId]);
  const r = result.rows[0];
  if (r === undefined) return null;
  return {
    operationId: r.operation_id, implementerId: r.implementer_id, nodeId: r.node_id,
    sourceWalletId: r.source_wallet_id, destinationId: r.destination_id,
    destinationWalletId: r.destination_wallet_id, sourcePublicKey: r.source_public_key,
    destinationPublicKey: r.destination_public_key, amountZkz: r.amount_zkz,
    leaseGroupId: r.lease_group_id, spawnedFromOperationId: r.spawned_from_operation_id,
    referencesOperationId: r.references_operation_id, rowVersion: r.row_version,
  };
}

function createSqlQueryFn(pool: Pool | PoolClient): SqlQueryFn {
  return async (text, values) => {
    const result = await pool.query(text, values as unknown[]);
    return result.rows as readonly Record<string, unknown>[];
  };
}

function createSqlExecutor(pool: Pool): MoveBaselineSqlExecutor {
  return {
    async query(text, params) {
      const result = await pool.query(text, params as never[]);
      return { rows: result.rows };
    },
  };
}

// Mirrors event-log/pg-event-store.ts's counter SQL (node_event_seq_counters), but does not
// import it: persistMoveOutcome's PERSIST_MOVE_OUTCOME CTE already inserts the node_events
// row atomically with the operation CAS, so appendBatch cannot be reused here without
// double-inserting. The counter row itself is still the single source of the next seq.
const ENSURE_EVENT_SEQ_COUNTER_SQL = `
INSERT INTO node_event_seq_counters (node_id, next_seq)
VALUES ($1::uuid, 1)
ON CONFLICT (node_id) DO NOTHING`;

// Locks the counter row for the duration of the transaction and, in the same round trip,
// reads the previous event's hash (seq = next_seq - 1) for the hash-chain link.
const LOCK_EVENT_SEQ_COUNTER_SQL = `
SELECT c.next_seq AS next_seq, e.event_hash AS last_event_hash
  FROM node_event_seq_counters c
  LEFT JOIN node_events e ON e.node_id = c.node_id AND e.seq = c.next_seq - 1
 WHERE c.node_id = $1::uuid
 FOR UPDATE OF c`;

const ADVANCE_EVENT_SEQ_COUNTER_SQL = `
UPDATE node_event_seq_counters
   SET next_seq = $2::bigint
 WHERE node_id = $1::uuid AND next_seq = $3::bigint
 RETURNING next_seq`;

interface LockedEventSeq {
  readonly seq: bigint;
  readonly previousEventHash: string | null;
}

/** Allocates the next node_events seq under a row lock held for the caller's transaction. */
async function lockNextEventSeq(txQuery: SqlQueryFn, nodeId: string): Promise<LockedEventSeq> {
  await txQuery(ENSURE_EVENT_SEQ_COUNTER_SQL, [nodeId]);
  const rows = await txQuery(LOCK_EVENT_SEQ_COUNTER_SQL, [nodeId]);
  const row = rows[0] as { next_seq: string; last_event_hash: string | null } | undefined;
  if (row === undefined) throw new Error("event seq counter missing after ensure");
  return { seq: BigInt(row.next_seq), previousEventHash: row.last_event_hash };
}

/** Advances the counter past the seq just inserted; CAS on the value locked/read above. */
async function advanceEventSeq(txQuery: SqlQueryFn, nodeId: string, lockedSeq: bigint): Promise<void> {
  const rows = await txQuery(ADVANCE_EVENT_SEQ_COUNTER_SQL, [
    nodeId,
    (lockedSeq + 1n).toString(),
    lockedSeq.toString(),
  ]);
  if (rows[0] === undefined) throw new Error("event seq counter advanced concurrently under lock");
}

/**
 * Existence-only lease-state check (One-in-flight: at most one active lease per wallet, so presence
 * of any row is enough — no need to cross-check operation_id or lease_role here).
 */
async function deriveLeaseState(query: SqlQueryFn, walletId: string): Promise<"ACTIVE" | "RELEASED"> {
  const rows = await query(LEASE_STATEMENTS.SELECT_ACTIVE, [walletId]);
  return rows.length > 0 ? "ACTIVE" : "RELEASED";
}

/** Narrows the persisted operation status before the CAS handoff to persistMoveOutcome. */
function isKnownMoveOperationStatus(status: string): status is "CREATED" | "NEEDS_ATTENTION" {
  return status === "CREATED" || status === "NEEDS_ATTENTION";
}

/**
 * The internal_move.landed event payload: both terminal
 * observation ids plus the landing instant. Field sequence is fixed for audit reproducibility
 * (Byte-exact-adjacent — dataText is independently hashed, never re-signed/reformatted downstream).
 */
function buildMoveLandedEventData(
  outcome: Extract<MoveReconcileOutcome, { kind: "LANDED_VERIFIED" }>,
  landedAtIso: string,
): string {
  return JSON.stringify({
    source_terminal_observation_id: outcome.sourcePath.freshHeadObservationId,
    destination_terminal_observation_id: outcome.destinationPath.freshHeadObservationId,
    landed_at: landedAtIso,
  });
}

/** The two non-landing verdicts persistMoveOutcome projects onto NEEDS_ATTENTION. */
type MoveParkingOutcome = Extract<
  MoveReconcileOutcome,
  { kind: "INDETERMINATE" } | { kind: "INVARIANT_BREACH" }
>;

/**
 * The operation.needs_attention event payload for a parked move. Same four keys the receive
 * and send attention paths emit (`current_state`, `attention_reason`, `operator_action_required`
 * plus the slice's own diagnostics), so one operator queue can read every kind's park.
 *
 * `attention_reason` is the SAME closed-vocabulary member persistMoveOutcome is about to write
 * to the column — both sides call toAttentionReason on the one reconcile reason, so the event
 * and the row can never disagree.
 */
function buildMoveNeedsAttentionEventData(
  outcome: MoveParkingOutcome,
  parkedAtIso: string,
): string {
  return JSON.stringify({
    current_state: "NEEDS_ATTENTION",
    attention_reason: toAttentionReason(outcome.reason),
    reconcile_outcome: outcome.kind,
    operator_action_required: true,
    parked_at: parkedAtIso,
  });
}


/**
 * Severity rank for MOVE parking verdicts while status stays NEEDS_ATTENTION (ZTR-1222
 * Option B). Higher wins; equal or lower is a no-op hold so ticks never spam events or
 * downgrade a breach classification back to indeterminate.
 */
function moveParkingSeverity(kind: MoveParkingOutcome["kind"]): number {
  switch (kind) {
    case "INDETERMINATE":
      return 1;
    case "INVARIANT_BREACH":
      return 2;
  }
}

/**
 * Recover the parked severity from the live attention columns. Prefer the kind prefix
 * stamped into attention_detail (`${kind} ${JSON.stringify(reason)}`); fall back to the
 * closed attention_reason so a breach-class reason still outranks a mild re-tick when
 * detail is missing.
 */
function storedMoveParkingSeverity(
  attentionDetail: string | null | undefined,
  attentionReason: string | null | undefined,
): number {
  if (typeof attentionDetail === "string") {
    if (attentionDetail.startsWith("INVARIANT_BREACH")) return moveParkingSeverity("INVARIANT_BREACH");
    if (attentionDetail.startsWith("INDETERMINATE")) return moveParkingSeverity("INDETERMINATE");
  }
  if (
    attentionReason === "LEASE_INVARIANT_VIOLATION" ||
    attentionReason === "EXACT_BYTES_UNAVAILABLE"
  ) {
    return moveParkingSeverity("INVARIANT_BREACH");
  }
  // Unknown / mild / missing → indeterminate floor so a later INVARIANT_BREACH can upgrade.
  return moveParkingSeverity("INDETERMINATE");
}

/** Convert a FreshHeadRead to a MoveBaselineObservationOutcome. */
function freshHeadToOutcome(read: FreshHeadRead, walletPublicKey: string): MoveBaselineObservationOutcome {
  const envelope = read.envelope;
  if (envelope.classification === "GENESIS") {
    return { kind: "VERIFIED", observationId: read.observationId, projection: GENESIS_PROJECTION };
  }
  if (envelope.classification !== "HEAD") {
    return { kind: "INDETERMINATE", detail: `envelope: ${envelope.classification}` };
  }
  // verifySettledTransaction is called inside createSqlFreshHeadReader already (it throws
  // on failure), so by the time we get here the envelope is verified. We re-derive the
  // projection to match the ObservationOutcome shape.
  const verified = verifySettledTransaction(envelope.parsed, walletPublicKey);
  if (verified.verdict === "VERIFIED") {
    return { kind: "VERIFIED", observationId: read.observationId, projection: verified.projection };
  }
  return { kind: "UNVERIFIED", detail: `verify: ${verified.verdict}` };
}

function createMoveBaselineObserver(
  readFreshHead: (walletPublicKey: string) => Promise<FreshHeadRead>,
): MoveBaselineObserver {
  return {
    async observe(walletPublicKey: string): Promise<MoveBaselineObservationOutcome> {
      try {
        const read = await readFreshHead(walletPublicKey);
        return freshHeadToOutcome(read, walletPublicKey);
      } catch (err) {
        return { kind: "INDETERMINATE", detail: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}

function createDestinationEligibilityReader(pool: Pool): DestinationEligibilityReader {
  return {
    async recheckDestination(destinationId: string): Promise<DestinationRecheck> {
      const result = await pool.query<{
        destination_state: string; wallet_state: string; recovery_verified_at: string | null;
      }>(
        // destinations has state (PENDING|BLESSED|RETIRED), not a boolean `blessed` column.
        `SELECT d.state::text AS destination_state, w.state::text AS wallet_state,
                w.recovery_verified_at::text AS recovery_verified_at
           FROM destinations d JOIN wallets w ON w.id = d.wallet_id
          WHERE d.id = $1::uuid`,
        [destinationId],
      );
      const r = result.rows[0];
      if (r === undefined) return { eligible: false, detail: "destination not found" };
      if (r.destination_state !== "BLESSED") return { eligible: false, detail: "not blessed" };
      if (r.wallet_state !== "AVAILABLE" && r.wallet_state !== "PINNED")
        return { eligible: false, detail: `wallet state: ${r.wallet_state}` };
      if (r.recovery_verified_at === null)
        return { eligible: false, detail: "recovery not verified" };
      return { eligible: true, detail: "eligible" };
    },
  };
}

function createNodeIdentitySignerAdapter(
  nodeIdentitySigner: () => ReceiveCodeNodeIdentitySigner | null,
): MoveNodeIdentitySigner {
  return {
    async signWithNodeIdentity(preimageBytes: Uint8Array): Promise<{ signature: string; signingKeyId: string }> {
      const signer = nodeIdentitySigner();
      if (signer === null) throw new Error("node identity signer unavailable");
      const signature: string = signer.sign(preimageBytes) as string;
      return { signature, signingKeyId: signer.signingKeyId };
    },
  };
}

/**
 * The same node identity key, in the synchronous shape the implementer-chain leg needs: that
 * preimage carries the implementer seq, which is only known under the counter lock, so it must
 * be signed inline rather than ahead of the append. `sign` is declared `Promise<string> | string`
 * on the identity signer; the custody signer is the synchronous one, and a promise reaching the
 * envelope would be stringified into a signature field, so this refuses instead of casting.
 */
function asSyncEventSigner(signer: ReceiveCodeNodeIdentitySigner): NodeEventSigner {
  return {
    signingKeyId: signer.signingKeyId,
    sign: (preimageBytes: Uint8Array): string => {
      const signature = signer.sign(preimageBytes);
      if (typeof signature !== "string") {
        throw new Error(
          "node identity signer returned a promise; the implementer event leg requires a synchronous signature",
        );
      }
      return signature;
    },
  };
}

/**
 * Build a PathObservation for one wallet leg of a MOVE_INTERNAL reconcile via the landing-proof rule
 * landing oracle's depth-0 exact-head case (`proveExactHeadLanding` — the only sanctioned
 * producer of a positive LandingPathProof). Reads the wallet's head
 * TWICE (anchor + confirm, per the double-read rule) rather than reusing a single earlier read, so a
 * head that moves mid-reconcile is CONFLICT, never a stale positive.
 */
async function buildPathObservation(
  walletPublicKey: string,
  expectedBodySha256: string,
  readFreshHead: ReadFreshHead,
): Promise<PathObservation> {
  const outcome = await proveExactHeadLanding(
    { walletPubkeyBase64Urlsafe: walletPublicKey, expectedBodySha256 },
    readFreshHead,
  );
  return landingProofToPathObservation(outcome);
}

export function createMoveAdvancedPorts(
  deps: MoveAdvancedPortsDeps,
): Partial<MoveInternalMoneyWorkerPorts> {
  const query = createSqlQueryFn(deps.pool);
  const sqlExecutor = createSqlExecutor(deps.pool);
  const statementTimeoutMs =
    deps.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  const readFreshHead = createSqlFreshHeadReader({
    pool: deps.pool,
    nodeId: deps.nodeId,
    gatewayUrls: deps.gatewayUrls,
    exchange: deps.gatewayExchange,
    maxAttempts: deps.gatewayMaxAttempts,
    backoffMaxMs: deps.gatewayBackoffMaxMs,
    moneyPathStatementTimeoutMs: statementTimeoutMs,
  });
  const observer = createMoveBaselineObserver(readFreshHead);
  const destinationReader = createDestinationEligibilityReader(deps.pool);
  const nodeIdentitySigner = createNodeIdentitySignerAdapter(deps.nodeIdentitySigner);

  const resolveSignerBoundaryDeps = () => {
    if (!deps.leadership.held) return null;
    try {
      return createMoneySignerBoundaryDeps(
        {
          leadership: deps.leadership,
          // Fallback reader — production sign pins FOR UPDATE via withSignTransaction (ZTR-1160).
          leaseReader: createSqlLeaseReader(deps.pool),
          vaultSigner: createPoolVaultSigner({ pool: deps.pool, vault: deps.vault, nodeId: deps.nodeId }),
          auditLog: createSqlSignerAuditLog(query),
          withSignTransaction: createSqlSignUnderLeaseTransaction(deps.pool, {
            statementTimeoutMs: statementTimeoutMs,
          }),
        },
        deps.moneyPathGates,
      );
    } catch { return null; }
  };

  const claimStore = makeSubmitDecisionClaimStore(query);
  const recorder = makeSubmitAttemptRecorder(query);
  const submitOnce = bindExecuteMoveSubmitClaimOnce({
    claimStore,
    authorizationFor: (operationId) => ({
      submitDecisionId: operationId,
      operationId,
      transactionAttemptNo: 1 as const,
    }),
    submitOptions: {
      endpoint: deps.submitGateway.endpoint,
      limits: deps.submitGateway.limits,
      recorder,
      ...(deps.submitGateway.exchange !== undefined || deps.gatewayExchange !== undefined
        ? { exchange: deps.submitGateway.exchange ?? deps.gatewayExchange }
        : {}),
    },
    onDuplicateSubmitRejection: () => deps.metricsHooks?.onDuplicateSubmitRejection(),
  });

  return {
    captureBaselines: async (operationId, _leases) => {
      const details = await loadMoveDetails(deps.pool, operationId);
      if (details === null) return { ok: false, reason: "operation not found" };
      const input: MoveBaselineBindingInput = {
        nodeId: details.nodeId,
        implementerId: details.implementerId,
        operationId,
        expectedArtifactId: crypto.randomUUID(),
        sourceWalletId: details.sourceWalletId,
        sourceWalletPublicKey: details.sourcePublicKey,
        destinationId: details.destinationId,
        destinationWalletId: details.destinationWalletId,
        destinationWalletPublicKey: details.destinationPublicKey,
        amountZkz: details.amountZkz,
        spawnedFromOperationId: details.spawnedFromOperationId,
        referencesOperationId: details.referencesOperationId,
        sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
        destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
        capturedAt: Date.now(),
        observer,
        destinations: destinationReader,
        signer: nodeIdentitySigner,
        sql: sqlExecutor,
      };
      const result: MoveBaselineBindingResult = await captureAndBindMoveBaselines(input);
      if (!result.ok) {
        // Destination retired / un-blessed mid-flight: park with the frozen vocabulary
        // value (ZTR-1147). Other baseline rejections stay WAITING for the next tick.
        if (result.reason === "destination_not_eligible") {
          const attentionReason = toAttentionReason({
            source: "DESTINATION_NO_LONGER_BLESSED",
          });
          try {
            await deps.pool.query(
              `UPDATE operations
                  SET attention_required = true,
                      attention_reason = COALESCE(attention_reason, $2),
                      attention_detail = COALESCE(
                        attention_detail,
                        $3
                      )
                WHERE id = $1::uuid AND attention_required = false`,
              [
                operationId,
                attentionReason,
                `destination_not_eligible: ${result.detail}`,
              ],
            );
          } catch (err) {
            deps.logger.error(
              `move baseline: op=${operationId} DESTINATION_NO_LONGER_BLESSED park failed`,
              err,
            );
          }
        }
        return { ok: false, reason: result.reason };
      }
      return { ok: true, bound: result.binding };
    },

    loadBaselineBound: async (operationId) => {
      const evRows = await query(
        `SELECT source_t0_observation_id::text AS s_t0,
                destination_t0_observation_id::text AS d_t0
           FROM move_observation_evidence WHERE operation_id = $1::uuid`,
        [operationId],
      );
      const ev = evRows[0] as { s_t0: string; d_t0: string } | undefined;
      if (ev === undefined || !ev.s_t0 || !ev.d_t0) return null;
      const details = await loadMoveDetails(deps.pool, operationId);
      if (details === null) return null;
      // Reload T0 projections keyed on the observation's verification classification
      // (parse_result), not on completed_transaction_text truthiness. A
      // VERIFIED_GENESIS row is durably NULL-bodied by construction — that NULL is the
      // genesis baseline itself, not missing evidence.
      const [srcRows, dstRows] = await Promise.all([
        query(
          `SELECT parse_result::text AS parse_result, completed_transaction_text
             FROM gateway_observations WHERE id = $1::uuid`,
          [ev.s_t0],
        ),
        query(
          `SELECT parse_result::text AS parse_result, completed_transaction_text
             FROM gateway_observations WHERE id = $1::uuid`,
          [ev.d_t0],
        ),
      ]);
      const srcProj = reloadBoundBaselineProjection(srcRows[0] as T0ObservationRow | undefined, details.sourcePublicKey);
      const dstProj = reloadBoundBaselineProjection(dstRows[0] as T0ObservationRow | undefined, details.destinationPublicKey);
      if (srcProj === null || dstProj === null) return null;
      // Load the expected artifact (operation_expected_artifacts; column set matches
      // STATEMENTS.INSERT_ARTIFACT in core/move-baseline-binding.ts).
      const artRows = await query(
        `SELECT id::text AS id, signing_key_id::text AS signing_key_id,
                preimage_text, preimage_sha256, signature
           FROM operation_expected_artifacts
          WHERE operation_id = $1::uuid LIMIT 1`,
        [operationId],
      );
      const ar = artRows[0] as {
        id: string; signing_key_id: string; preimage_text: string;
        preimage_sha256: string; signature: string;
      } | undefined;
      if (ar === undefined || !ar.signature || !ar.preimage_text) return null;
      const artifact: PersistedExpectedArtifact = {
        id: ar.id,
        operationId,
        purpose: MOVE_INTERNAL_ARTIFACT_PURPOSE,
        canonicalVersion: MOVE_INTERNAL_CANONICAL_VERSION,
        signingKeyId: ar.signing_key_id,
        preimageText: ar.preimage_text,
        preimageSha256: ar.preimage_sha256,
        signature: ar.signature,
      };
      return {
        capture: {
          operationId,
          sourceWalletPublicKey: details.sourcePublicKey,
          destinationWalletPublicKey: details.destinationPublicKey,
          sourceBaseline: srcProj,
          destinationBaseline: dstProj,
          amountZkz: parsePositiveZkzAmount(details.amountZkz),
          capturedAt: Date.now(),
        },
        sourceT0ObservationId: ev.s_t0,
        destinationT0ObservationId: ev.d_t0,
        artifact,
      } as MoveBaselineBound;
    },

    formInner: async (operationId, bound) => {
      try {
        const formed = await formMoveInner({
          operationId,
          capture: bound.capture,
          sourceT0ObservationId: bound.sourceT0ObservationId,
          destinationT0ObservationId: bound.destinationT0ObservationId,
          expectedArtifact: bound.artifact,
          nodeClockMs: Date.now(),
          formedAt: new Date().toISOString(),
          persistPort: { commitMoveInnerAttempt: (input) => persistMoveInnerAttemptSql(query, input) },
        });
        if (!formed.ok) return { ok: false, reason: formed.reason };
        return { ok: true, formed: { durable: formed.durable } };
      } catch (err) {
        return { ok: false, reason: err instanceof Error ? err.message : String(err) };
      }
    },

    signUnderLeases: async (operationId, leases) => {
      const signerDeps = resolveSignerBoundaryDeps();
      if (signerDeps === null)
        return { ok: false, reason: "signer boundary unavailable" };
      try {
        const phaseRows = await query(
          `SELECT attempt_phase::text AS phase FROM operation_transactions
            WHERE operation_id = $1::uuid AND attempt_no = 1`,
          [operationId],
        );
        const phase = (phaseRows[0] as { phase: string } | undefined)?.phase;
        const moveSignerDeps = { ...signerDeps, assertHaltAdmitsKind: deps.moneyPathGates.assertHaltAdmitsKind };
        let signed;
        if (phase === "STEP1_SIGNATURE_PERSISTED") {
          signed = await resumeMoveStep2FromPersistedStep1({
            operationId,
            destinationLease: { walletId: leases.destinationWalletId, leaseEpoch: leases.destinationLeaseEpoch },
            query,
            signerDeps: moveSignerDeps,
          });
        } else {
          signed = await signMoveStepsUnderLeases({
            operationId,
            leases: {
              source: { walletId: leases.sourceWalletId, leaseEpoch: leases.sourceLeaseEpoch },
              destination: { walletId: leases.destinationWalletId, leaseEpoch: leases.destinationLeaseEpoch },
            },
            query,
            signerDeps: moveSignerDeps,
          });
        }
        return { ok: true, signed: { signed } };
      } catch (err) {
        return { ok: false, reason: err instanceof Error ? err.message : String(err) };
      }
    },

    loadSignedMaterial: async (operationId) => {
      const rows = await query(
        `SELECT inner_preimage_text, step_1_signature, step_2_preimage_text,
                step_2_signature, completed_transaction_text, completed_transaction_sha256
           FROM operation_transactions
          WHERE operation_id = $1::uuid AND attempt_no = 1`,
        [operationId],
      );
      const r = rows[0] as Record<string, unknown> | undefined;
      if (r === undefined || !r.step_2_signature || !r.completed_transaction_text) return null;
      const step2PreimageText = r.step_2_preimage_text as string;
      const signed: SignedMoveSteps = {
        operationId,
        innerPreimageText: r.inner_preimage_text as string,
        step1Signature: r.step_1_signature as string,
        step2PreimageText,
        step2PreimageSha256: sha256HexUtf8(step2PreimageText),
        step2Signature: r.step_2_signature as string,
        completedTransactionText: r.completed_transaction_text as string,
        completedTransactionSha256: r.completed_transaction_sha256 as string,
      };
      return { signed };
    },

    submitOnce,

    reconcileAndLand: async (operationId, _progress) => {
      try {
        const details = await loadMoveDetails(deps.pool, operationId);
        if (details === null) return { ok: false, reason: "operation not found" };

        const attemptRows = await query(
          `SELECT completed_transaction_text, completed_transaction_sha256
             FROM operation_transactions
            WHERE operation_id = $1::uuid AND attempt_no = 1`,
          [operationId],
        );
        const attempt = attemptRows[0] as Record<string, unknown> | undefined;
        if (attempt === undefined || !attempt.completed_transaction_text) {
          return { ok: false, reason: "signed transaction not found", holdReconcile: true };
        }
        const expectedBodySha = attempt.completed_transaction_sha256 as string;

        // Build PathObservation for each wallet via the depth-0 landing oracle —
        // each leg reads and confirms its own head twice; there is no shared read to
        // observe up front.
        const [sourceObs, destObs] = await Promise.all([
          buildPathObservation(details.sourcePublicKey, expectedBodySha, readFreshHead),
          buildPathObservation(details.destinationPublicKey, expectedBodySha, readFreshHead),
        ]);

        // Lease state (One-in-flight: at most one active lease per wallet — existence-only check).
        const [sourceLeaseState, destinationLeaseState] = await Promise.all([
          deriveLeaseState(query, details.sourceWalletId),
          deriveLeaseState(query, details.destinationWalletId),
        ]);

        // Classify the reconcile outcome (oracle for MOVE).
        const reconcileInput: MoveReconcileInput = {
          boundary: "POST_SUBMIT",
          moveAttemptId: operationId,
          sourceWalletId: details.sourceWalletId,
          destinationWalletId: details.destinationWalletId,
          expectedMoveBodySha256: expectedBodySha,
          sourceLeaseState,
          destinationLeaseState,
          sourceObservation: sourceObs,
          destinationObservation: destObs,
        };
        const outcome: MoveReconcileOutcome = classifyMoveReconcile(reconcileInput);

        // PROVEN_NOT_STARTED is the operator-driven NEEDS_ATTENTION → CREATED rebuild decision,
        // not a durable write from here — move-internal-landing-store.ts project() throws on it
        // by design. Every OTHER verdict, landing and non-landing alike, goes through the one
        // persist path below so the state machine is driven from a single point of truth.
        if (outcome.kind === "PROVEN_NOT_STARTED") {
          return { ok: false, reason: `reconcile: ${outcome.kind}`, holdReconcile: true };
        }

        // Persist the outcome: the CAS + evidence attach + event append
        // commit as ONE statement inside persistMoveOutcome, but allocating the event's seq
        // and hash-chain link needs its own row lock, so the two share one transaction.
        const client = await deps.pool.connect();
        try {
          await client.query("BEGIN");
          await applyMoneyPathStatementTimeout(
            client,
            deps.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT,
          );
          const txQuery = createSqlQueryFn(client);

          const opRows = await txQuery(
            `SELECT status::text AS status, row_version::text AS rv,
                    attention_required,
                    attention_reason::text AS attention_reason,
                    attention_detail
               FROM operations WHERE id = $1::uuid`,
            [operationId],
          );
          const op = opRows[0] as
            | {
                status: string;
                rv: string;
                attention_required: boolean;
                attention_reason: string | null;
                attention_detail: string | null;
              }
            | undefined;
          if (op === undefined) {
            await client.query("ROLLBACK");
            return { ok: false, reason: "operation not found" };
          }
          if (!isKnownMoveOperationStatus(op.status)) {
            await client.query("ROLLBACK");
            return { ok: false, reason: `unexpected operation status: ${op.status}`, holdReconcile: true };
          }
          const expectedState: "CREATED" | "NEEDS_ATTENTION" = op.status;
          const attentionRequired = op.attention_required === true;

          // Re-park guard keys on attention_required (the live flag), not status
          // (ZTR-1223). Operator retraction clears attention_required while leaving
          // status='NEEDS_ATTENTION'; a subsequent ambiguous tick must be able to re-raise.
          // While the flag is still raised, equal-or-lower severity is a no-op hold (ZTR-1222
          // Option B): the frozen MOVE_INTERNAL table has no NEEDS_ATTENTION → NEEDS_ATTENTION
          // edge, so we never call persistMoveOutcome again. A *higher* parking severity
          // (INDETERMINATE → INVARIANT_BREACH) upgrades reason/detail/episode + dual-chain
          // event without a status edge — never a downgrade.
          if (outcome.kind !== "LANDED_VERIFIED" && attentionRequired) {
            const parkingOutcome = outcome as MoveParkingOutcome;
            const currentSeverity = storedMoveParkingSeverity(
              op.attention_detail,
              op.attention_reason,
            );
            const nextSeverity = moveParkingSeverity(parkingOutcome.kind);
            if (nextSeverity <= currentSeverity) {
              await client.query("ROLLBACK");
              return { ok: false, reason: `reconcile: ${outcome.kind}`, holdReconcile: true };
            }

            // Severity-monotonic attention upgrade (ZTR-1222 Option B). Status stays
            // NEEDS_ATTENTION; only attention columns + dual-chain event advance.
            const seqInfoUpgrade = await lockNextEventSeq(txQuery, deps.nodeId);
            const nowIsoUpgrade = new Date().toISOString();
            const dataTextUpgrade = buildMoveNeedsAttentionEventData(
              parkingOutcome,
              nowIsoUpgrade,
            );
            const dataSha256Upgrade = sha256HexUtf8(dataTextUpgrade);
            const nodeEventInputUpgrade: NodeEventInput = {
              node_id: parseUuid(deps.nodeId),
              event_id: parseUuid(crypto.randomUUID()),
              seq: seqInfoUpgrade.seq.toString(),
              operation_id: parseUuid(operationId),
              wallet_id: null,
              event_type: "operation.needs_attention",
              data_sha256: parseSha256Hex(dataSha256Upgrade),
              previous_event_hash:
                seqInfoUpgrade.previousEventHash === null
                  ? null
                  : parseSha256Hex(seqInfoUpgrade.previousEventHash),
              created_at: nowIsoUpgrade,
            };
            const preimageUpgrade = buildNodeEvent(nodeEventInputUpgrade);
            const signedUpgrade = await nodeIdentitySigner.signWithNodeIdentity(
              preimageUpgrade.preimageBytes,
            );
            const eventHashUpgrade = computeEventLogNodeEventHash(
              preimageUpgrade.preimageText,
              signedUpgrade.signature,
            );
            const eventUpgrade: SignedNodeEvent = {
              seq: nodeEventInputUpgrade.seq,
              eventId: nodeEventInputUpgrade.event_id,
              nodeId: nodeEventInputUpgrade.node_id,
              walletId: null,
              eventType: "operation.needs_attention",
              dataText: dataTextUpgrade,
              dataSha256: dataSha256Upgrade,
              preimageText: preimageUpgrade.preimageText,
              preimageSha256: preimageUpgrade.sha256,
              signingKeyId: signedUpgrade.signingKeyId,
              signature: signedUpgrade.signature,
              previousEventHash: seqInfoUpgrade.previousEventHash,
              eventHash: eventHashUpgrade,
            };

            const attentionReasonUpgrade = toAttentionReason(parkingOutcome.reason);
            const attentionDetailUpgrade =
              `${parkingOutcome.kind} ${JSON.stringify(parkingOutcome.reason)}`;
            const upgraded = await txQuery(
              `UPDATE operations
                  SET attention_reason = $2::attention_reason,
                      attention_detail = $3,
                      attention_episode = attention_episode + 1,
                      row_version = row_version + 1,
                      updated_at = $4::timestamptz
                WHERE id = $1::uuid
                  AND kind = 'MOVE_INTERNAL'
                  AND status = 'NEEDS_ATTENTION'
                  AND attention_required = true
                  AND row_version = $5::bigint
              RETURNING id`,
              [
                operationId,
                attentionReasonUpgrade,
                attentionDetailUpgrade,
                nowIsoUpgrade,
                Number(op.rv),
              ],
            );
            if (upgraded[0] === undefined) {
              await client.query("ROLLBACK");
              return { ok: false, reason: "persist: PRECONDITION_UNMET", holdReconcile: true };
            }

            await txQuery(
              `INSERT INTO node_events
                 (seq, event_id, canonical_version, node_id, operation_id, wallet_id, event_type,
                  data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id, signature,
                  previous_event_hash, event_hash, created_at)
               VALUES
                 ($1::bigint, $2::uuid, 1, $3::uuid, $4::uuid, NULL, $5::text,
                  $6::text, $7::text, $8::text, $9::text, $10::uuid, $11::text,
                  $12::text, $13::text, $14::timestamptz)`,
              [
                eventUpgrade.seq,
                eventUpgrade.eventId,
                eventUpgrade.nodeId,
                operationId,
                eventUpgrade.eventType,
                eventUpgrade.dataText,
                eventUpgrade.dataSha256,
                eventUpgrade.preimageText,
                eventUpgrade.preimageSha256,
                eventUpgrade.signingKeyId,
                eventUpgrade.signature,
                eventUpgrade.previousEventHash,
                eventUpgrade.eventHash,
                nowIsoUpgrade,
              ],
            );

            const identityUpgrade = deps.nodeIdentitySigner();
            if (identityUpgrade === null) throw new Error("node identity signer unavailable");
            await appendImplementerEventLeg(txQuery, {
              nodeId: deps.nodeId,
              implementerId: details.implementerId,
              eventId: eventUpgrade.eventId,
              eventType: eventUpgrade.eventType,
              operationId,
              walletId: null,
              dataSha256: dataSha256Upgrade,
              nodeEventHash: eventUpgrade.eventHash,
              createdAt: nowIsoUpgrade,
              signer: asSyncEventSigner(identityUpgrade),
            });

            await advanceEventSeq(txQuery, deps.nodeId, seqInfoUpgrade.seq);
            await client.query("COMMIT");
            // Durable INVARIANT_BREACH classification → P0 metric (ZTR-1144 dual-FAIL D1/D2).
            if (parkingOutcome.kind === "INVARIANT_BREACH") {
              deps.metricsHooks?.onInvariantBreach();
            }
            deps.logger.info(
              `move reconcile: op=${operationId} severity-upgraded attention outcome=${parkingOutcome.kind} ` +
                `reason=${attentionReasonUpgrade}`,
            );
            return { ok: false, reason: `reconcile: ${parkingOutcome.kind}`, holdReconcile: true };
          }

          const seqInfo = await lockNextEventSeq(txQuery, deps.nodeId);
          const nowIso = new Date().toISOString();
          const eventType =
            outcome.kind === "LANDED_VERIFIED" ? "internal_move.landed" : "operation.needs_attention";
          const dataText =
            outcome.kind === "LANDED_VERIFIED"
              ? buildMoveLandedEventData(outcome, nowIso)
              : buildMoveNeedsAttentionEventData(outcome as MoveParkingOutcome, nowIso);
          const dataSha256 = sha256HexUtf8(dataText);

          const nodeEventInput: NodeEventInput = {
            node_id: parseUuid(deps.nodeId),
            event_id: parseUuid(crypto.randomUUID()),
            seq: seqInfo.seq.toString(),
            operation_id: parseUuid(operationId),
            wallet_id: null,
            event_type: eventType,
            data_sha256: parseSha256Hex(dataSha256),
            previous_event_hash: seqInfo.previousEventHash === null ? null : parseSha256Hex(seqInfo.previousEventHash),
            created_at: nowIso,
          };
          const preimage = buildNodeEvent(nodeEventInput);
          const signed = await nodeIdentitySigner.signWithNodeIdentity(preimage.preimageBytes);
          const eventHash = computeEventLogNodeEventHash(preimage.preimageText, signed.signature);

          const event: SignedNodeEvent = {
            seq: nodeEventInput.seq,
            eventId: nodeEventInput.event_id,
            nodeId: nodeEventInput.node_id,
            walletId: null,
            eventType,
            dataText,
            dataSha256,
            preimageText: preimage.preimageText,
            preimageSha256: preimage.sha256,
            signingKeyId: signed.signingKeyId,
            signature: signed.signature,
            previousEventHash: seqInfo.previousEventHash,
            eventHash,
          };

          // Post-retraction re-raise (ZTR-1223): status may still be NEEDS_ATTENTION while
          // attention_required is false. There is no frozen NEEDS_ATTENTION → NEEDS_ATTENTION
          // edge, so persistMoveOutcome cannot re-park. Raise the flag + dual-chain event only
          // (same shape as receive-landing / operator-park), leave status unchanged.
          if (outcome.kind !== "LANDED_VERIFIED" && expectedState === "NEEDS_ATTENTION") {
            const parkingOutcome = outcome as MoveParkingOutcome;
            const attentionReason = toAttentionReason(parkingOutcome.reason);
            const attentionDetail = `${parkingOutcome.kind} ${JSON.stringify(parkingOutcome.reason)}`;
            const raised = await txQuery(
              `UPDATE operations
                  SET attention_required = true,
                      attention_reason = $2::attention_reason,
                      attention_detail = $3,
                      attention_episode = attention_episode + 1,
                      row_version = row_version + 1,
                      updated_at = $4::timestamptz
                WHERE id = $1::uuid
                  AND kind = 'MOVE_INTERNAL'
                  AND status = 'NEEDS_ATTENTION'
                  AND attention_required = false
                  AND row_version = $5::bigint
              RETURNING id`,
              [
                operationId,
                attentionReason,
                attentionDetail,
                nowIso,
                Number(op.rv),
              ],
            );
            if (raised[0] === undefined) {
              await client.query("ROLLBACK");
              return { ok: false, reason: "persist: PRECONDITION_UNMET", holdReconcile: true };
            }

            await txQuery(
              `INSERT INTO node_events
                 (seq, event_id, canonical_version, node_id, operation_id, wallet_id, event_type,
                  data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id, signature,
                  previous_event_hash, event_hash, created_at)
               VALUES
                 ($1::bigint, $2::uuid, 1, $3::uuid, $4::uuid, NULL, $5::text,
                  $6::text, $7::text, $8::text, $9::text, $10::uuid, $11::text,
                  $12::text, $13::text, $14::timestamptz)`,
              [
                event.seq,
                event.eventId,
                event.nodeId,
                operationId,
                event.eventType,
                event.dataText,
                event.dataSha256,
                event.preimageText,
                event.preimageSha256,
                event.signingKeyId,
                event.signature,
                event.previousEventHash,
                event.eventHash,
                nowIso,
              ],
            );

            const identity = deps.nodeIdentitySigner();
            if (identity === null) throw new Error("node identity signer unavailable");
            await appendImplementerEventLeg(txQuery, {
              nodeId: deps.nodeId,
              implementerId: details.implementerId,
              eventId: event.eventId,
              eventType: event.eventType,
              operationId,
              walletId: null,
              dataSha256,
              nodeEventHash: event.eventHash,
              createdAt: nowIso,
              signer: asSyncEventSigner(identity),
            });

            await advanceEventSeq(txQuery, deps.nodeId, seqInfo.seq);
            await client.query("COMMIT");
            // Durable INVARIANT_BREACH classification → P0 metric (ZTR-1144 dual-FAIL D1/D2).
            if (parkingOutcome.kind === "INVARIANT_BREACH") {
              deps.metricsHooks?.onInvariantBreach();
            }
            deps.logger.info(
              `move reconcile: op=${operationId} re-raised attention outcome=${parkingOutcome.kind} ` +
                `reason=${attentionReason}`,
            );
            return { ok: false, reason: `reconcile: ${parkingOutcome.kind}`, holdReconcile: true };
          }

          const persistResult = await persistMoveOutcome(txQuery, {
            operationId,
            expectedState,
            expectedRowVersion: Number(op.rv),
            outcome,
            event,
            occurredAt: nowIso,
            // New diagnostic detail belongs in attention_detail, never in a new
            // attention_reason: the column keeps the closed vocabulary, this keeps the specifics.
            ...(outcome.kind === "LANDED_VERIFIED"
              ? {}
              : { attentionDetail: `${outcome.kind} ${JSON.stringify(outcome.reason)}` }),
          });

          if (persistResult.kind !== "PERSISTED") {
            await client.query("ROLLBACK");
            return { ok: false, reason: `persist: ${persistResult.kind}`, holdReconcile: true };
          }

          if (outcome.kind !== "LANDED_VERIFIED") {
            // The park is now durable on the node-global chain (persistMoveOutcome's CTE
            // inserted the node_events row inside the same statement as the CAS). The tenant
            // must see it too — a park the implementer stream never learns about is the same
            // invisibility as no park at all — so the zp-implementer-event-v1 leg is appended
            // on THIS transaction, linked to the node row by its event hash.
            const identity = deps.nodeIdentitySigner();
            if (identity === null) throw new Error("node identity signer unavailable");
            await appendImplementerEventLeg(txQuery, {
              nodeId: deps.nodeId,
              implementerId: details.implementerId,
              eventId: event.eventId,
              eventType: event.eventType,
              operationId,
              walletId: null,
              dataSha256,
              nodeEventHash: event.eventHash,
              createdAt: nowIso,
              signer: asSyncEventSigner(identity),
            });

            await advanceEventSeq(txQuery, deps.nodeId, seqInfo.seq);
            await client.query("COMMIT");
            // Durable INVARIANT_BREACH park → P0 metric (ZTR-1144 dual-FAIL D1/D2).
            // Attention backlog alone is P1; breach classification must page P0.
            if (outcome.kind === "INVARIANT_BREACH") {
              deps.metricsHooks?.onInvariantBreach();
            }
            // Both leases stay held and no retry is licensed: an ambiguous move grants no
            // release and no non-landing conclusion. What it now also grants is visibility.
            deps.logger.info(
              `move reconcile: op=${operationId} parked NEEDS_ATTENTION outcome=${outcome.kind} ` +
                `reason=${toAttentionReason(outcome.reason)}`,
            );
            return { ok: false, reason: `reconcile: ${outcome.kind}`, holdReconcile: true };
          }

          // Derived wallet_settled_ledger SOURCE + DESTINATION rows.
          // T0 baselines come from move_observation_evidence (bound at form time).
          const t0Rows = await txQuery(
            `SELECT source_t0_observation_id::text AS s_t0,
                    destination_t0_observation_id::text AS d_t0
               FROM move_observation_evidence
              WHERE operation_id = $1::uuid`,
            [operationId],
          );
          const t0 = t0Rows[0] as { s_t0: string; d_t0: string } | undefined;
          if (t0 === undefined) {
            await client.query("ROLLBACK");
            return {
              ok: false,
              reason: "move landing: missing move_observation_evidence T0 baselines",
              holdReconcile: true,
            };
          }
          // Prefer the more-buried path depth when dual paths differ; both must already
          // be positive landing verdicts (LANDED_VERIFIED gate above).
          const src = outcome.sourcePath;
          const dst = outcome.destinationPath;
          const landingVerdict =
            src.kind === "LANDED_COMPLETE_PATH" || dst.kind === "LANDED_COMPLETE_PATH"
              ? ("LANDED_COMPLETE_PATH" as const)
              : ("LANDED_EXACT" as const);
          const pathDepth = Math.max(src.depth, dst.depth);
          const settled = await recordWalletSettledLedger(txQuery, {
            operationId,
            landingVerdict,
            pathDepth,
            t0ObservationId: t0.s_t0,
            terminalObservationId: src.freshHeadObservationId,
            requiredPathCount: 2,
            verifiedAtIso: nowIso,
          });

          // Dual lineage paths (SOURCE + DESTINATION) for verification-material.
          const pathMeta = await txQuery(
            `SELECT olp.proof_manifest_text, olp.proof_manifest_sha256,
                    o.source_wallet_id::text AS source_wallet_id,
                    sw.public_key AS source_public_key,
                    d.wallet_id::text AS dest_wallet_id,
                    dw.public_key AS dest_public_key
               FROM operation_landing_proofs olp
               INNER JOIN operations o ON o.id = olp.operation_id
               LEFT JOIN wallets sw ON sw.id = o.source_wallet_id
               LEFT JOIN destinations d ON d.id = o.destination_id
               LEFT JOIN wallets dw ON dw.id = d.wallet_id
              WHERE olp.id = $1::uuid`,
            [settled.landingProofId],
          );
          const meta = pathMeta[0] as
            | {
                proof_manifest_text: string;
                proof_manifest_sha256: string;
                source_wallet_id: string | null;
                source_public_key: string | null;
                dest_wallet_id: string | null;
                dest_public_key: string | null;
              }
            | undefined;
          if (meta?.source_public_key) {
            await writeExactHeadLineagePath(txQuery, {
              operationId,
              landingProofId: settled.landingProofId,
              pathRole: "SOURCE",
              walletId: meta.source_wallet_id,
              walletPublicKey: meta.source_public_key,
              t0ObservationId: t0.s_t0,
              freshHeadObservationId: src.freshHeadObservationId,
              verdict: src.kind === "LANDED_COMPLETE_PATH" ? "LANDED_COMPLETE_PATH" : "LANDED_EXACT",
              pathDepth: src.depth,
              proofManifestText: meta.proof_manifest_text,
              proofManifestSha256: meta.proof_manifest_sha256,
              createdAtIso: nowIso,
            });
          }
          if (meta?.dest_public_key) {
            await writeExactHeadLineagePath(txQuery, {
              operationId,
              landingProofId: settled.landingProofId,
              pathRole: "DESTINATION",
              walletId: meta.dest_wallet_id,
              walletPublicKey: meta.dest_public_key,
              t0ObservationId: t0.d_t0,
              freshHeadObservationId: dst.freshHeadObservationId,
              verdict: dst.kind === "LANDED_COMPLETE_PATH" ? "LANDED_COMPLETE_PATH" : "LANDED_EXACT",
              pathDepth: dst.depth,
              proofManifestText: meta.proof_manifest_text,
              proofManifestSha256: meta.proof_manifest_sha256,
              createdAtIso: nowIso,
            });
          }

          await issueLandedAccessWindow(
            txQuery,
            operationId,
            Date.parse(nowIso),
          );

          // Tenant stream: node_events was inserted inside persistMoveOutcome's CTE; the
          // zp-implementer-event-v1 leg must co-commit so internal_move.landed is public
          // (ZTR-1146). Same pattern as the NEEDS_ATTENTION branch above.
          {
            const identity = deps.nodeIdentitySigner();
            if (identity === null) throw new Error("node identity signer unavailable");
            await appendImplementerEventLeg(txQuery, {
              nodeId: deps.nodeId,
              implementerId: details.implementerId,
              eventId: event.eventId,
              eventType: event.eventType,
              operationId,
              walletId: null,
              dataSha256,
              nodeEventHash: event.eventHash,
              createdAt: nowIso,
              signer: asSyncEventSigner(identity),
            });
          }

          await advanceEventSeq(txQuery, deps.nodeId, seqInfo.seq);
          await client.query("COMMIT");
          return { ok: true, land: { outcome, persist: persistResult } };
        } catch (err) {
          await client.query("ROLLBACK").catch(() => {});
          throw err;
        } finally {
          client.release();
        }
      } catch (err) {
        return { ok: false, reason: err instanceof Error ? err.message : String(err), holdReconcile: true };
      }
    },
  };
}

type T0ObservationRow = { parse_result: string; completed_transaction_text: string | null };

/**
 * Reload one side's T0 baseline projection, keyed on the observation's verification
 * classification rather than body-text truthiness. `undefined` (the T0 row itself
 * is gone) is the only "truly absent" case and returns null, matching
 * MoveBaselineBound.loadBaselineBound's existing contract of null meaning "not yet
 * reloadable, keep waiting" (move-internal-money-worker.ts FORM case). Evidence that IS
 * present but cannot be reconstructed into a baseline — wrong/anomalous parse_result, or a
 * VERIFIED_HEAD body that fails re-verification — is not absent
 * (INDETERMINATE covers evidence that is "missing, invalid, contradictory, or
 * insufficient"), so it must not collapse into the same null the caller treats as
 * wait-forever. Throwing fails closed to the tick loop's existing typed FAILED/step=LOAD
 * terminal instead of silently retaining leases under an unbounded WAIT.
 */
function reloadBoundBaselineProjection(
  row: T0ObservationRow | undefined,
  walletPublicKey: string,
): WalletStateProjection | null {
  if (row === undefined) return null;
  if (row.parse_result === "VERIFIED_GENESIS") return GENESIS_PROJECTION;
  if (row.parse_result === "VERIFIED_HEAD" && row.completed_transaction_text) {
    const projected = projectionFromBodyText(row.completed_transaction_text, walletPublicKey);
    if (projected !== null) return projected;
  }
  throw new Error(
    `move baseline reload: T0 observation evidence present but unreconstructable (parse_result=${row.parse_result})`,
  );
}

/** Derive a WalletStateProjection from a persisted completed_transaction_text. */
function projectionFromBodyText(bodyText: string, walletPublicKey: string): WalletStateProjection | null {
  if (bodyText === "" || bodyText === "genesis") return GENESIS_PROJECTION;
  try {
    const envelope = parseGatewayEnvelope(
      new TextEncoder().encode(`{"status":true,"code":"ok","message":"","data":[${bodyText}]}`),
    );
    if (envelope.classification !== "HEAD") return null;
    const verified = verifySettledTransaction(envelope.parsed, walletPublicKey);
    if (verified.verdict !== "VERIFIED") return null;
    return verified.projection;
  } catch { return null; }
}
