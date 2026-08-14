// External-send wallet assignment + multi-hub internal top-up composition (ZTR-1270).
// Funding-wallet reserve hop (ZTR-1289): when the integration pins funding wallet W,
// shortfall top-up prefers MOVE W→sender; dry / ineligible W → insufficient_funding_wallet
// (no silent multi-hub substitute). When W is unset, multi-hub INTERNAL_ONLY path remains.
//
// Runtime inverse of receive-pool assign: pick a free send-capable worker, optionally
// fund it via MOVE_INTERNAL from funding W (preferred) or an INTERNAL_ONLY hub, then
// create SEND_EXTERNAL with durable references_operation_id linkage. No fourth money verb.
//
// Freeze decisions (also in the PR body):
// 1. Balance observation source — latest verified gateway_observations.b_amount for the
//    wallet (same lateral shape as admin inventory). Null observation ⇒ treat balance as
//    "0" for worker shortfall (underfunded / full-N top-up). Hubs with null observation
//    are skipped (fail closed on unknown hub liquidity). Funding W with null observation
//    is treated as dry (insufficient_funding_wallet).
// 2. Top-up amount — exact shortfall (N − worker_balance), never full N when partial
//    funds are already on the worker.
// 3. Hub pick sequence — when fundingWalletId set: lock that wallet only (must cover
//    shortfall + allow_internal_move). Else INTERNAL_ONLY only; observed balance ≥
//    shortfall; wallet id ASC; FOR UPDATE SKIP LOCKED LIMIT 1.
// 4. Lease groups — sequential separate groups: MOVE admits first (own lease group);
//    SEND is created in the same composition call with references_operation_id = move id
//    but acquires SEND_SOURCE only after the move has released wallets (formation /
//    auto-approve gate on top-up readiness). Same-group continuous transfer is not used
//    (worker cannot hold MOVE_DESTINATION and SEND_SOURCE together under one-in-flight).
// 5. Response source_wallet_id is always the sender/worker, never W (attribution).
// 6. Top-up MOVE is always NODE_VERIFIED (node-owned hop). Landing releases MOVE_* leases
//    in the same TX as INTERNAL_MOVE_LANDED — implementer verification-complete is never
//    required for the top-up. The external SEND still carries the client's verification_mode.
//
// Auto-approve / claim-and-observe MUST call assertSendTopUpReady (or the SQL probe)
// before advancing a send that references a MOVE_INTERNAL — policy still evaluates only
// after the source wallet is known (create time), which is unchanged.

import { compareAmounts, subtractAmounts } from "@zucoins/generic-node-contracts";
import { isInternalOnlyHub } from "@zucoins/generic-node-contracts/wallet-state";

import { parsePositiveZkzAmount } from "./protocol/amounts.js";
import { parseUuid, parseWalletPublicKey } from "./protocol/scalars.js";
import {
  createInternalMove,
  type MoveCreateOutcome,
  type MoveCreateStore,
  type MoveOperation,
} from "./move/create.js";
import {
  canonicalRequestSha256,
  createExternalSend,
  SEND_CANONICAL_ROUTE,
  SEND_HTTP_METHOD,
  type SendArtifactSigner,
  type SendCreateConfig,
  type SendCreateOutcome,
  type SendCreateRequest,
  type SendCreateStore,
  type SendExpectedArtifact,
  type SendOperation,
  IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
} from "./send/create.js";

// ─── frozen SQL (exported for PG text + concurrency drills) ─────────────────

/**
 * Canonical worker assignment select. Preference:
 *   1. free send-capable worker with observed balance ≥ $2 (amount)
 *   2. else free underfunded / unobserved send-capable worker
 * Within a tier: wallet id ASC. SKIP LOCKED is load-bearing (receive-pool symmetry).
 *
 * Eligibility: node_generated, AVAILABLE, recovery_verified, allow_external_send,
 * no active lease, no unsettled SEND_EXTERNAL on send_operations.
 * INTERNAL_ONLY / receive-only are excluded by allow_external_send IS TRUE.
 */
export const SELECT_SEND_WORKER_SQL = `
SELECT w.id::text AS wallet_id,
       bal.b_amount::text AS observed_balance_zkz
  FROM wallets w
  LEFT JOIN LATERAL (
        SELECT go.b_amount
          FROM gateway_observations go
         WHERE go.wallet_id = w.id
           AND go.b_amount IS NOT NULL
         ORDER BY go.observed_at DESC, go.wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
         LIMIT 1
       ) bal ON true
 WHERE w.node_id = $1::uuid
   AND w.key_origin = 'node_generated'
   AND w.state = 'AVAILABLE'
   AND w.recovery_verified_at IS NOT NULL
   AND w.allow_external_send IS TRUE
   AND NOT EXISTS (
         SELECT 1 FROM wallet_active_leases wal WHERE wal.wallet_id = w.id)
   AND NOT EXISTS (
         SELECT 1
           FROM send_operations so
          WHERE so.source_wallet_id = w.id
            AND so.status NOT IN ('EXTERNAL_SEND_LANDED', 'REJECTED'))
 ORDER BY -- contract-allow:order:frozen structural vocabulary
   CASE
     WHEN bal.b_amount IS NOT NULL
      AND bal.b_amount::numeric >= $2::numeric THEN 0
     ELSE 1
   END ASC,
   w.id ASC
 FOR UPDATE OF w SKIP LOCKED
 LIMIT 1`;


/**
 * Canonical hub pick for exact shortfall $2. INTERNAL_ONLY only (money_mode + flags).
 * Requires a known observed balance ≥ shortfall. id ASC + SKIP LOCKED.
 */
export const SELECT_TOPUP_HUB_SQL = `
SELECT w.id::text AS wallet_id,
       bal.b_amount::text AS observed_balance_zkz
  FROM wallets w
  INNER JOIN LATERAL (
        SELECT go.b_amount
          FROM gateway_observations go
         WHERE go.wallet_id = w.id
           AND go.b_amount IS NOT NULL
         ORDER BY go.observed_at DESC, go.wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
         LIMIT 1
       ) bal ON true
 WHERE w.node_id = $1::uuid
   AND w.key_origin = 'node_generated'
   AND w.state = 'AVAILABLE'
   AND w.recovery_verified_at IS NOT NULL
   AND w.money_mode = 'INTERNAL_ONLY'
   AND w.allow_external_send IS FALSE
   AND w.allow_external_receive IS FALSE
   AND w.allow_internal_move IS TRUE
   AND bal.b_amount::numeric >= $2::numeric
   AND NOT EXISTS (
         SELECT 1 FROM wallet_active_leases wal WHERE wal.wallet_id = w.id)
 ORDER BY w.id ASC -- contract-allow:order:frozen structural vocabulary
 FOR UPDATE OF w SKIP LOCKED
 LIMIT 1`;

/**
 * Lock the integration funding wallet W for a W→sender top-up hop (ZTR-1289).
 * $1 = funding wallet id, $2 = node id. Caller applies shortfall coverage +
 * allow_internal_move pure checks; null observation is dry (fail closed).
 */
// Keep multiline (do not collapse): a trailing `-- contract-allow` comment would
// swallow the rest of the statement if this were single-lined.
export const SELECT_FUNDING_WALLET_FOR_TOPUP_SQL = `
SELECT w.id::text AS wallet_id,
       bal.b_amount::text AS observed_balance_zkz,
       w.allow_internal_move,
       w.state::text AS state,
       w.key_origin::text AS key_origin,
       w.retired_at IS NOT NULL AS is_retired,
       EXISTS (
         SELECT 1 FROM wallet_active_leases wal WHERE wal.wallet_id = w.id
       ) AS has_active_lease
  FROM wallets w
  LEFT JOIN LATERAL (
        SELECT go.b_amount
          FROM gateway_observations go
         WHERE go.wallet_id = w.id
           AND go.b_amount IS NOT NULL
         ORDER BY go.observed_at DESC, go.wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
         LIMIT 1
       ) bal ON true
 WHERE w.id = $1::uuid
   AND w.node_id = $2::uuid
 FOR UPDATE OF w`;

/**
 * Resolve the BLESSED destination id for a worker wallet (MOVE sink handle).
 * Workers that can receive internal top-ups must already be registered + blessed.
 */
export const SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL = `
SELECT d.id::text AS destination_id
  FROM destinations d
  JOIN wallets w ON w.id = d.wallet_id
 WHERE d.wallet_id = $1::uuid
   AND d.state = 'BLESSED'
   AND w.allow_internal_move IS TRUE
 LIMIT 1`
  .replace(/\s+/g, " ")
  .trim();

/**
 * Top-up readiness probe for a SEND that may reference a MOVE_INTERNAL.
 * Returns one row when the send may advance (no reference, or referenced move
 * is INTERNAL_MOVE_LANDED). Zero rows ⇒ park (do not form / auto-approve yet).
 */
export const SELECT_SEND_TOPUP_READY_SQL = `
SELECT s.operation_id::text AS operation_id
  FROM send_operations s
 WHERE s.operation_id = $1::uuid
   AND (
         s.references_operation_id IS NULL
      OR EXISTS (
           SELECT 1
             FROM operations m
            WHERE m.id = s.references_operation_id
              AND m.kind = 'MOVE_INTERNAL'
              AND m.status = 'INTERNAL_MOVE_LANDED'
         )
       )`
  .replace(/\s+/g, " ")
  .trim();

/** Reverse linkage: moves that funded a send (queryable). */
export const SELECT_SEND_BY_TOPUP_MOVE_SQL = `
SELECT s.operation_id::text AS send_operation_id,
       s.references_operation_id::text AS move_operation_id,
       s.source_wallet_id::text AS source_wallet_id
  FROM send_operations s
 WHERE s.references_operation_id = $1::uuid`
  .replace(/\s+/g, " ")
  .trim();

export const SEND_ASSIGN_SQL = {
  SELECT_SEND_WORKER: SELECT_SEND_WORKER_SQL,
  SELECT_TOPUP_HUB: SELECT_TOPUP_HUB_SQL,
  SELECT_FUNDING_WALLET_FOR_TOPUP: SELECT_FUNDING_WALLET_FOR_TOPUP_SQL,
  SELECT_BLESSED_DESTINATION_FOR_WALLET: SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL,
  SELECT_SEND_TOPUP_READY: SELECT_SEND_TOPUP_READY_SQL,
  SELECT_SEND_BY_TOPUP_MOVE: SELECT_SEND_BY_TOPUP_MOVE_SQL,
} as const;

// ─── pure helpers ───────────────────────────────────────────────────────────

export type SendAssignRejectionCode =
  | "invalid_amount"
  | "invalid_tenant_id"
  | "invalid_destination_address"
  | "no_free_send_worker"
  | "worker_destination_missing"
  | "no_hub_liquidity"
  | "hub_busy"
  | "insufficient_funding_wallet"
  | "move_rejected"
  | "send_rejected"
  | "halted";

export interface ObservedBalanceRow {
  readonly walletId: string;
  /** Null when no verified observation exists. */
  readonly observedBalanceZkz: string | null;
}

/**
 * Worker funding decision. Null balance is treated as "0" (underfunded).
 * Funded ⇒ no MOVE. Underfunded ⇒ exact shortfall top-up.
 */
export function decideWorkerFunding(
  amountZkz: string,
  observedBalanceZkz: string | null,
):
  | { readonly kind: "funded"; readonly balanceZkz: string }
  | { readonly kind: "needs_topup"; readonly balanceZkz: string; readonly shortfallZkz: string } {
  const balance = observedBalanceZkz === null ? "0" : observedBalanceZkz;
  if (compareAmounts(balance, amountZkz) >= 0) {
    return { kind: "funded", balanceZkz: balance };
  }
  return {
    kind: "needs_topup",
    balanceZkz: balance,
    shortfallZkz: subtractAmounts(amountZkz, balance),
  };
}

/** Hub eligibility half — pure flag check (SQL also pins money_mode). */
export function isTopUpHubEligible(flags: {
  readonly allow_external_receive: boolean;
  readonly allow_external_send: boolean;
  readonly allow_internal_move: boolean;
}): boolean {
  return isInternalOnlyHub(flags);
}

export type TopUpReadiness =
  | { readonly ready: true; readonly reason: "no_reference" | "move_landed" }
  | {
      readonly ready: false;
      readonly reason:
        | "move_pending"
        | "move_attention"
        | "move_missing"
        | "move_wrong_kind";
      readonly moveStatus: string | null;
    };

/**
 * Pure readiness from already-loaded rows. Used by unit tests and non-SQL ports.
 */
export function evaluateTopUpReadiness(input: {
  readonly referencesOperationId: string | null;
  readonly referenced:
    | { readonly kind: string; readonly status: string }
    | null;
}): TopUpReadiness {
  if (input.referencesOperationId === null) {
    return { ready: true, reason: "no_reference" };
  }
  if (input.referenced === null) {
    return { ready: false, reason: "move_missing", moveStatus: null };
  }
  if (input.referenced.kind !== "MOVE_INTERNAL") {
    return {
      ready: false,
      reason: "move_wrong_kind",
      moveStatus: input.referenced.status,
    };
  }
  if (input.referenced.status === "INTERNAL_MOVE_LANDED") {
    return { ready: true, reason: "move_landed" };
  }
  if (input.referenced.status === "NEEDS_ATTENTION") {
    return {
      ready: false,
      reason: "move_attention",
      moveStatus: input.referenced.status,
    };
  }
  return {
    ready: false,
    reason: "move_pending",
    moveStatus: input.referenced.status,
  };
}

// ─── orchestration ports ────────────────────────────────────────────────────

export interface AssignSqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[] }>;
}

/** One BEGIN/COMMIT scope for selection locks + optional multi-step planning reads. */
export type AssignSqlTxFn = <T>(body: (tx: AssignSqlExecutor) => Promise<T>) => Promise<T>;

export interface AssignAndTopUpRequest {
  readonly implementerId: string;
  readonly nodeId: string;
  /** When set, skip pool assign and use this wallet (explicit source path). */
  readonly sourceWalletId: string | null;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly clientReference: string | null;
  readonly description: string | null;
  readonly idempotencyKey: string;
  /**
   * Optional pre-linked reference (rare). When null and a top-up MOVE is created,
   * the send binds references_operation_id to that MOVE id.
   */
  readonly referencesOperationId: string | null;
  /**
   * Integration funding wallet W (ZTR-1289). When set, top-up MOVE source is W
   * only — multi-hub INTERNAL_ONLY is not used as a silent substitute. Null/
   * undefined preserves pre-1289 multi-hub behaviour (funding pin unset).
   */
  readonly fundingWalletId?: string | null;
  /**
   * Optional admission-time verification mode (ZTR-1301). Threaded into createExternalSend
   * only. Top-up MOVE_INTERNAL is always NODE_VERIFIED (node-owned); never inherits this.
   */
  readonly verificationMode?: import("@zucoins/generic-node-contracts/operations").VerificationMode;
}

export interface AssignAndTopUpDeps {
  readonly sql: AssignSqlExecutor;
  /**
   * Optional TX wrapper for selection FOR UPDATE locks. When omitted, selection
   * runs on `sql` without an explicit transaction (tests / single-connection).
   */
  readonly withSelectionTx?: AssignSqlTxFn;
  readonly moveStore: MoveCreateStore;
  readonly sendStore: SendCreateStore;
  readonly sendSigner: SendArtifactSigner;
  readonly sendCreateConfig?: SendCreateConfig;
  /**
   * Kind-scoped operator halt (MOVE + SEND first formation). Composition refuses
   * before creating either verb when engaged. Formation paths still enforce halt
   * independently.
   */
  readonly assertHaltAdmitsKind?: (kind: string) => void;
  readonly generateId?: () => string;
  readonly now?: () => number;
  /**
   * Idempotency key for the top-up MOVE derived from the send key. Default:
   * `topup:` + send idempotency key (must stay within 16–255 ASCII).
   */
  readonly moveIdempotencyKeyFor?: (sendIdempotencyKey: string) => string;
  /**
   * Optional async resolver for funding wallet W when request.fundingWalletId is
   * omitted. Wired by the route store from implementer pin + node default.
   * Returning null means funding is unset → multi-hub fallback.
   */
  readonly resolveFundingWalletId?: (
    implementerId: string,
  ) => Promise<string | null>;
}

export type AssignAndTopUpOutcome =
  | {
      readonly outcome: "CREATED";
      readonly workerWalletId: string;
      readonly funding: "funded" | "top_up";
      readonly shortfallZkz: string | null;
      readonly hubWalletId: string | null;
      /** Present when top-up sourced from integration funding wallet W. */
      readonly fundingWalletId?: string | null;
      readonly move: MoveOperation | null;
      readonly send: SendOperation;
      readonly artifact: SendExpectedArtifact;
      readonly sendCreate: Extract<SendCreateOutcome, { outcome: "CREATED" }>;
    }
  | {
      readonly outcome: "IDEMPOTENT_REPLAY";
      readonly sendCreate: Extract<SendCreateOutcome, { outcome: "IDEMPOTENT_REPLAY" }>;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: SendAssignRejectionCode;
      readonly detail?: string;
      readonly retryAfterSeconds?: number;
      /** Nested send/move rejection when composition mapped one. */
      readonly causeCode?: string;
    };

function defaultMoveIdempotencyKey(sendKey: string): string {
  // Keep visible ASCII and length within frozen 16–255 grammar.
  const prefix = "topup:";
  const combined = prefix + sendKey;
  if (combined.length <= 255) return combined;
  return combined.slice(0, 255);
}

interface WorkerPick {
  readonly walletId: string;
  readonly observedBalanceZkz: string | null;
}

interface HubPick {
  readonly walletId: string;
  readonly observedBalanceZkz: string;
}

async function pickWorker(
  tx: AssignSqlExecutor,
  nodeId: string,
  amountZkz: string,
): Promise<WorkerPick | null> {
  const result = await tx.query<{
    wallet_id: string;
    observed_balance_zkz: string | null;
  }>(SELECT_SEND_WORKER_SQL, [nodeId, amountZkz]);
  const row = result.rows[0];
  if (row === undefined) return null;
  return {
    walletId: row.wallet_id,
    observedBalanceZkz: row.observed_balance_zkz,
  };
}

async function pickHub(
  tx: AssignSqlExecutor,
  nodeId: string,
  shortfallZkz: string,
): Promise<HubPick | null> {
  const result = await tx.query<{
    wallet_id: string;
    observed_balance_zkz: string;
  }>(SELECT_TOPUP_HUB_SQL, [nodeId, shortfallZkz]);
  const row = result.rows[0];
  if (row === undefined) return null;
  return {
    walletId: row.wallet_id,
    observedBalanceZkz: row.observed_balance_zkz,
  };
}

/**
 * Pure coverage check for funding wallet W as MOVE source for shortfall.
 * Null observation ⇒ dry. Busy / ineligible ⇒ insufficient (no hub fallback).
 */
export function evaluateFundingWalletForTopUp(input: {
  readonly shortfallZkz: string;
  readonly observedBalanceZkz: string | null;
  readonly allowInternalMove: boolean;
  readonly state: string;
  readonly keyOrigin: string;
  readonly isRetired: boolean;
  readonly hasActiveLease: boolean;
}):
  | { readonly ok: true; readonly balanceZkz: string }
  | { readonly ok: false; readonly reason: string } {
  if (input.isRetired) {
    return { ok: false, reason: "funding_wallet_retired" };
  }
  if (input.state !== "AVAILABLE") {
    return { ok: false, reason: `funding_wallet_state=${input.state}` };
  }
  if (input.keyOrigin !== "node_generated") {
    return { ok: false, reason: "funding_wallet_not_node_generated" };
  }
  if (input.allowInternalMove !== true) {
    return { ok: false, reason: "funding_wallet_no_internal_move" };
  }
  if (input.hasActiveLease) {
    return { ok: false, reason: "funding_wallet_busy" };
  }
  if (input.observedBalanceZkz === null) {
    return { ok: false, reason: "funding_wallet_unobserved" };
  }
  if (compareAmounts(input.observedBalanceZkz, input.shortfallZkz) < 0) {
    return {
      ok: false,
      reason: `funding_wallet_shortfall balance=${input.observedBalanceZkz} need=${input.shortfallZkz}`,
    };
  }
  return { ok: true, balanceZkz: input.observedBalanceZkz };
}

async function lockFundingWalletForTopUp(
  tx: AssignSqlExecutor,
  fundingWalletId: string,
  nodeId: string,
  shortfallZkz: string,
): Promise<
  | { readonly ok: true; readonly pick: HubPick }
  | { readonly ok: false; readonly reason: string }
> {
  const result = await tx.query<{
    wallet_id: string;
    observed_balance_zkz: string | null;
    allow_internal_move: boolean | string;
    state: string;
    key_origin: string;
    is_retired: boolean | string;
    has_active_lease: boolean | string;
  }>(SELECT_FUNDING_WALLET_FOR_TOPUP_SQL, [fundingWalletId, nodeId]);
  const row = result.rows[0];
  if (row === undefined) {
    return { ok: false, reason: "funding_wallet_not_found" };
  }
  const allowInternalMove =
    row.allow_internal_move === true || row.allow_internal_move === "t";
  const isRetired = row.is_retired === true || row.is_retired === "t";
  const hasActiveLease =
    row.has_active_lease === true || row.has_active_lease === "t";
  const verdict = evaluateFundingWalletForTopUp({
    shortfallZkz,
    observedBalanceZkz: row.observed_balance_zkz,
    allowInternalMove,
    state: row.state,
    keyOrigin: row.key_origin,
    isRetired,
    hasActiveLease,
  });
  if (!verdict.ok) {
    return { ok: false, reason: verdict.reason };
  }
  return {
    ok: true,
    pick: {
      walletId: row.wallet_id,
      observedBalanceZkz: verdict.balanceZkz,
    },
  };
}

async function blessedDestinationId(
  tx: AssignSqlExecutor,
  workerWalletId: string,
): Promise<string | null> {
  const result = await tx.query<{ destination_id: string }>(
    SELECT_BLESSED_DESTINATION_FOR_WALLET_SQL,
    [workerWalletId],
  );
  return result.rows[0]?.destination_id ?? null;
}

/**
 * SQL probe used by money workers before auto-approve / formation.
 * Returns true when the send may advance.
 */
export async function isSendTopUpReady(
  sql: AssignSqlExecutor,
  sendOperationId: string,
): Promise<boolean> {
  const result = await sql.query<{ operation_id: string }>(
    SELECT_SEND_TOPUP_READY_SQL,
    [sendOperationId],
  );
  return result.rows.length > 0;
}

/**
 * Compose assign (+ optional multi-hub top-up MOVE) + SEND_EXTERNAL create.
 *
 * Does NOT chain-submit SEND_EXTERNAL. Does NOT acquire SEND_SOURCE / MOVE leases —
 * existing money workers own formation after admission.
 */
/** Client-visible idempotency fingerprint for assign composition (source may be null). */
export function canonicalAssignRequestSha256(request: AssignAndTopUpRequest): string {
  const fingerprint: SendCreateRequest = {
    implementerId: request.implementerId,
    nodeId: request.nodeId,
    // Placeholder — overridden by idempotencySourceWalletId for the hash.
    sourceWalletId: request.sourceWalletId ?? "00000000-0000-4000-8000-000000000000",
    destinationAddress: request.destinationAddress,
    amountZkz: request.amountZkz,
    // Client-supplied reference only; top-up MOVE id is composition-internal and must
    // not enter the fingerprint (replay would otherwise diverge after first create).
    referencesOperationId: request.referencesOperationId,
    clientReference: request.clientReference,
    description: request.description,
    idempotencyKey: request.idempotencyKey,
    idempotencySourceWalletId: request.sourceWalletId,
    idempotencyReferencesOperationId: request.referencesOperationId,
    ...(request.verificationMode !== undefined
      ? { verificationMode: request.verificationMode }
      : {}),
  };
  return canonicalRequestSha256(fingerprint);
}

export async function assignAndTopUpExternalSend(
  deps: AssignAndTopUpDeps,
  request: AssignAndTopUpRequest,
): Promise<AssignAndTopUpOutcome> {
  // Validate scalar surfaces early (same grammar as createExternalSend).
  try {
    parseUuid(request.nodeId);
    parseUuid(request.implementerId);
  } catch {
    return { outcome: "REJECTED", code: "invalid_tenant_id" };
  }
  try {
    parsePositiveZkzAmount(request.amountZkz);
  } catch {
    return { outcome: "REJECTED", code: "invalid_amount" };
  }
  try {
    parseWalletPublicKey(request.destinationAddress);
  } catch {
    return { outcome: "REJECTED", code: "invalid_destination_address" };
  }
  if (request.sourceWalletId !== null) {
    try {
      parseUuid(request.sourceWalletId);
    } catch {
      return { outcome: "REJECTED", code: "send_rejected", detail: "invalid_source_wallet_id" };
    }
  }

  // ZTR-1271: resolve idempotent replay BEFORE worker/hub selection. Re-assign on
  // replay can fail with no_free_send_worker even when the first create succeeded.
  const requestSha256 = canonicalAssignRequestSha256(request);
  const existing = await deps.sendStore.findByIdempotency(
    request.implementerId,
    SEND_HTTP_METHOD,
    SEND_CANONICAL_ROUTE,
    request.idempotencyKey,
  );
  if (existing !== null) {
    if (existing.requestSha256 !== requestSha256) {
      return {
        outcome: "REJECTED",
        code: "send_rejected",
        detail: "idempotency_key_reused",
        causeCode: "idempotency_key_reused",
      };
    }
    if (existing.responseBody === null || existing.responseStatus === null) {
      return {
        outcome: "REJECTED",
        code: "send_rejected",
        detail: "idempotency_in_progress",
        causeCode: "idempotency_in_progress",
        retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
      };
    }
    return {
      outcome: "IDEMPOTENT_REPLAY",
      sendCreate: {
        outcome: "IDEMPOTENT_REPLAY",
        operation: existing,
        responseStatus: existing.responseStatus,
        responseBody: existing.responseBody,
      },
    };
  }

  // Halt blocks first formation of both verbs before any durable row is written.
  if (deps.assertHaltAdmitsKind !== undefined) {
    try {
      deps.assertHaltAdmitsKind("MOVE_INTERNAL");
      deps.assertHaltAdmitsKind("SEND_EXTERNAL");
    } catch (err) {
      return {
        outcome: "REJECTED",
        code: "halted",
        detail: err instanceof Error ? err.message : "halt engaged",
      };
    }
  }

  // Resolve funding wallet W once before selection (ZTR-1289). Request field wins;
  // else optional dep resolver (route store). Null ⇒ multi-hub fallback.
  let resolvedFundingWalletId: string | null =
    request.fundingWalletId === undefined ? null : request.fundingWalletId;
  if (resolvedFundingWalletId === null && deps.resolveFundingWalletId !== undefined) {
    resolvedFundingWalletId = await deps.resolveFundingWalletId(request.implementerId);
  }
  if (resolvedFundingWalletId !== null) {
    try {
      parseUuid(resolvedFundingWalletId);
    } catch {
      return {
        outcome: "REJECTED",
        code: "insufficient_funding_wallet",
        detail: "invalid_funding_wallet_id",
      };
    }
  }

  const runSelection = deps.withSelectionTx ?? (async (body) => body(deps.sql));

  type Plan =
    | {
        readonly mode: "explicit";
        readonly workerWalletId: string;
        readonly funding: ReturnType<typeof decideWorkerFunding>;
        readonly hubWalletId: string | null;
        readonly fundingWalletId: string | null;
        readonly workerDestinationId: string | null;
      }
    | {
        readonly mode: "assigned";
        readonly workerWalletId: string;
        readonly funding: ReturnType<typeof decideWorkerFunding>;
        readonly hubWalletId: string | null;
        readonly fundingWalletId: string | null;
        readonly workerDestinationId: string | null;
      }
    | { readonly mode: "reject"; readonly code: SendAssignRejectionCode; readonly detail?: string };

  const plan: Plan = await runSelection(async (tx) => {
    let workerWalletId: string;
    let observed: string | null;

    if (request.sourceWalletId !== null) {
      // Explicit source: still load observed balance for top-up decision; do not
      // re-run pool preference (caller pinned the wallet). Lock the row when free.
      const locked = await tx.query<{
        wallet_id: string;
        observed_balance_zkz: string | null;
        allow_external_send: boolean;
      }>(
        `SELECT w.id::text AS wallet_id,
                bal.b_amount::text AS observed_balance_zkz,
                w.allow_external_send
           FROM wallets w
           LEFT JOIN LATERAL (
                 SELECT go.b_amount
                   FROM gateway_observations go
                  WHERE go.wallet_id = w.id
                    AND go.b_amount IS NOT NULL
                  ORDER BY go.observed_at DESC, go.wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
                  LIMIT 1
                ) bal ON true
          WHERE w.id = $1::uuid
            AND w.node_id = $2::uuid
          FOR UPDATE OF w`,
        [request.sourceWalletId, request.nodeId],
      );
      const row = locked.rows[0];
      if (row === undefined) {
        return {
          mode: "reject",
          code: "send_rejected",
          detail: "source_wallet_not_found",
        };
      }
      if (row.allow_external_send !== true) {
        return {
          mode: "reject",
          code: "send_rejected",
          detail: "allow_external_send=false",
        };
      }
      workerWalletId = row.wallet_id;
      observed = row.observed_balance_zkz;
    } else {
      const worker = await pickWorker(tx, request.nodeId, request.amountZkz);
      if (worker === null) {
        return { mode: "reject", code: "no_free_send_worker" };
      }
      workerWalletId = worker.walletId;
      observed = worker.observedBalanceZkz;
    }

    // Funding W must not be the external-send source (reserve ≠ sender).
    if (
      resolvedFundingWalletId !== null &&
      workerWalletId === resolvedFundingWalletId
    ) {
      return {
        mode: "reject",
        code: "send_rejected",
        detail: "funding_wallet_cannot_be_send_source",
      };
    }

    const funding = decideWorkerFunding(request.amountZkz, observed);
    if (funding.kind === "funded") {
      return {
        mode: request.sourceWalletId !== null ? "explicit" : "assigned",
        workerWalletId,
        funding,
        hubWalletId: null,
        fundingWalletId: resolvedFundingWalletId,
        workerDestinationId: null,
      };
    }

    const destId = await blessedDestinationId(tx, workerWalletId);
    if (destId === null) {
      return {
        mode: "reject",
        code: "worker_destination_missing",
        detail: workerWalletId,
      };
    }

    // ZTR-1289: preferred reserve root is funding W when configured.
    if (resolvedFundingWalletId !== null) {
      const lockedW = await lockFundingWalletForTopUp(
        tx,
        resolvedFundingWalletId,
        request.nodeId,
        funding.shortfallZkz,
      );
      if (!lockedW.ok) {
        return {
          mode: "reject",
          code: "insufficient_funding_wallet",
          detail: lockedW.reason,
        };
      }
      return {
        mode: request.sourceWalletId !== null ? "explicit" : "assigned",
        workerWalletId,
        funding,
        hubWalletId: lockedW.pick.walletId,
        fundingWalletId: resolvedFundingWalletId,
        workerDestinationId: destId,
      };
    }

    const hub = await pickHub(tx, request.nodeId, funding.shortfallZkz);
    if (hub === null) {
      // Distinguish total absence of hubs vs all busy: count eligible hubs without lock.
      const anyHub = await tx.query<{ n: string }>(
        `SELECT count(*)::text AS n
           FROM wallets w
           INNER JOIN LATERAL (
                 SELECT go.b_amount
                   FROM gateway_observations go
                  WHERE go.wallet_id = w.id
                    AND go.b_amount IS NOT NULL
                  ORDER BY go.observed_at DESC, go.wallet_seq DESC -- contract-allow:order:frozen structural vocabulary
                  LIMIT 1
                ) bal ON true
          WHERE w.node_id = $1::uuid
            AND w.money_mode = 'INTERNAL_ONLY'
            AND w.allow_external_send IS FALSE
            AND w.allow_internal_move IS TRUE
            AND bal.b_amount::numeric >= $2::numeric`,
        [request.nodeId, funding.shortfallZkz],
      );
      const n = Number(anyHub.rows[0]?.n ?? "0");
      if (n > 0) {
        return {
          mode: "reject",
          code: "hub_busy",
          detail: `eligible_hubs=${n}`,
        };
      }
      return {
        mode: "reject",
        code: "no_hub_liquidity",
        detail: `shortfall=${funding.shortfallZkz}`,
      };
    }

    return {
      mode: request.sourceWalletId !== null ? "explicit" : "assigned",
      workerWalletId,
      funding,
      hubWalletId: hub.walletId,
      fundingWalletId: null,
      workerDestinationId: destId,
    };
  });

  if (plan.mode === "reject") {
    return { outcome: "REJECTED", code: plan.code, detail: plan.detail };
  }

  let moveOp: MoveOperation | null = null;
  let referencesOperationId = request.referencesOperationId;

  if (plan.funding.kind === "needs_topup") {
    if (plan.hubWalletId === null || plan.workerDestinationId === null) {
      return {
        outcome: "REJECTED",
        code:
          plan.fundingWalletId !== null
            ? "insufficient_funding_wallet"
            : "no_hub_liquidity",
      };
    }
    const moveKey =
      (deps.moveIdempotencyKeyFor ?? defaultMoveIdempotencyKey)(request.idempotencyKey);
    // Node-owned internal top-up: NODE_VERIFIED so money-workers release both MOVE_*
    // leases on land (ZTR-1304). Not implementer verification — skip allow_node_verified.
    const moveOutcome: MoveCreateOutcome = await createInternalMove(
      deps.moveStore,
      {
        implementerId: request.implementerId,
        nodeId: request.nodeId,
        sourceWalletId: plan.hubWalletId,
        destinationId: plan.workerDestinationId,
        amountZkz: plan.funding.shortfallZkz,
        clientReference: request.clientReference,
        idempotencyKey: moveKey,
        verificationMode: "NODE_VERIFIED",
      },
      {
        generateId: deps.generateId,
        now: deps.now,
        skipNodeVerifiedPolicyGate: true,
      },
    );
    if (moveOutcome.outcome === "REJECTED") {
      // Funding-W path: map MOVE failures to insufficient_funding_wallet (no silent hub).
      if (plan.fundingWalletId !== null) {
        if (moveOutcome.code === "wallet_busy") {
          return {
            outcome: "REJECTED",
            code: "insufficient_funding_wallet",
            detail: "funding_wallet_busy",
            causeCode: moveOutcome.code,
          };
        }
        return {
          outcome: "REJECTED",
          code: "insufficient_funding_wallet",
          detail: moveOutcome.detail ?? moveOutcome.code,
          causeCode: moveOutcome.code,
        };
      }
      if (moveOutcome.code === "wallet_busy") {
        return {
          outcome: "REJECTED",
          code: "hub_busy",
          detail: moveOutcome.detail,
          causeCode: moveOutcome.code,
        };
      }
      return {
        outcome: "REJECTED",
        code: "move_rejected",
        detail: moveOutcome.detail,
        causeCode: moveOutcome.code,
      };
    }
    if (moveOutcome.outcome === "IDEMPOTENT_REPLAY") {
      // Prior composition created the move; bind send to that operation id.
      // Idempotent create must not double-hop (same move key → same move id).
      referencesOperationId = moveOutcome.operation.operationId;
      moveOp = null;
    } else {
      moveOp = moveOutcome.operation;
      referencesOperationId = moveOutcome.operation.operationId;
    }
  }

  const sendOutcome = await createExternalSend(
    deps.sendStore,
    deps.sendSigner,
    {
      implementerId: request.implementerId,
      nodeId: request.nodeId,
      sourceWalletId: plan.workerWalletId,
      destinationAddress: request.destinationAddress,
      amountZkz: request.amountZkz,
      // Durable linkage may be the top-up MOVE; fingerprint stays client-stable.
      referencesOperationId,
      clientReference: request.clientReference,
      description: request.description,
      idempotencyKey: request.idempotencyKey,
      // Client-visible source (null when omitted) — not the resolved worker. ZTR-1271.
      idempotencySourceWalletId: request.sourceWalletId,
      idempotencyReferencesOperationId: request.referencesOperationId,
      ...(request.verificationMode !== undefined
        ? { verificationMode: request.verificationMode }
        : {}),
    },
    deps.sendCreateConfig ?? { generateId: deps.generateId, now: deps.now },
  );

  if (sendOutcome.outcome === "IDEMPOTENT_REPLAY") {
    return { outcome: "IDEMPOTENT_REPLAY", sendCreate: sendOutcome };
  }
  if (sendOutcome.outcome === "REJECTED") {
    return {
      outcome: "REJECTED",
      code: "send_rejected",
      detail: sendOutcome.detail ?? sendOutcome.code,
      causeCode: sendOutcome.code,
      retryAfterSeconds: sendOutcome.retryAfterSeconds,
    };
  }

  return {
    outcome: "CREATED",
    workerWalletId: plan.workerWalletId,
    funding: plan.funding.kind === "funded" ? "funded" : "top_up",
    shortfallZkz: plan.funding.kind === "needs_topup" ? plan.funding.shortfallZkz : null,
    hubWalletId: plan.hubWalletId,
    fundingWalletId: plan.fundingWalletId,
    move: moveOp,
    send: sendOutcome.operation,
    artifact: sendOutcome.artifact,
    sendCreate: sendOutcome,
  };
}
