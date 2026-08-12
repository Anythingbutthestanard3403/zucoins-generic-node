// Deterministic receive-pool scale-up, pressure metrics and queue-age expiry
// layered on the allocator in ./pool-allocator.ts.
//
// Covers the four pool limits, the scaler, admission-ladder steps 4–5, receive-pool
// pressure, sizing, backpressure, logical retirement, and the recovery_verified_at gate.
//
// This OVERRIDES the draft sizing formula, and the difference is the whole safety argument:
//
// - `POOL_TARGET_AVAILABLE` is DELETED. The target is proportional headroom over live
// demand as a TOTAL — `ceil(open_sessions * 11 / 10)` clamped to [POOL_FLOOR, pool_cap] —
// in exact integer form, never the float `open_sessions * 1.10` (autoscale headroom integer form).
// - `pool_cap` counts ALL non-hard-deleted wallets INCLUDING PINNED, QUARANTINED and
// RETIRED. This REVERSES the draft's `non_retired_pool_wallet_count`: retire→mint→retire
// against a non-retired count is unbounded permanent-key growth, and keys are never
// deleted (the key-custody rule). Retirement therefore never restores capacity.
//
// The bug class this module is built to make structurally impossible is a scaler that mints
// past the real cap because it counted a narrower "total" than the cap rule does, or because
// it computed the batch from a count read BEFORE it held the serialising lock. Both are
// closed the same way: `planPoolScaleUp` takes the advisory lock first and re-reads every
// count under it, inside the caller's transaction (rule 3).
//
// The key-custody rule holds trivially: no key material is read, derived or written here. Minting a
// keypair belongs to the composition root, injected as `MintWallet`; this module only decides
// HOW MANY and holds the lock while it happens.
//
// The one-in-flight-per-wallet rule is untouched: nothing here releases, re-states or un-pins a wallet. There is
// deliberately no statement in this module that writes `wallets.state`, so capacity pressure
// has no path back to AVAILABLE (pinned/attention wallets are never auto-released).

import {
  countUnassignedReceives,
  type SqlExecutor,
} from "./pool-allocator.js";

/**
 * rule 1 / rule 3 frozen constants. NOT operator knobs — the only free pool knob is
 * `POOL_CAP_TOTAL`. Twins of `generic-node-contracts/src/pool-policy/constants.ts` and
 * `apps/generic-node/src/config/constants.ts`; node-core restates them because `receive` is a
 * boundary leaf and the contracts package publishes no `./pool-policy` subpath. The parity
 * test in test/receive/pool-scaler.pg.test.ts imports the frozen contract source directly and
 * fails if any of the three copies drifts.
 */
export const POOL_FLOOR = 5;
export const MINT_BATCH_LIMIT = 5;
export const HEADROOM_NUMERATOR = 11;
export const HEADROOM_DENOMINATOR = 10;

/**
 * Binds the frozen `pool_scale_up` advisory-lock namespace
 * (generic-node-contracts SCALE_UP_ADVISORY_LOCK_NAMESPACE) to a concrete key. Distinct from
 * the allocator's RECEIVE_ADMISSION_LOCK_KEY: admission and scale-up must not block each
 * other, only their own concurrent selves.
 */
export const POOL_SCALE_UP_LOCK_KEY = 2650552 as const;

/** The `POOL_CAP_TOTAL` / `RECEIVE_QUEUE_MAX_WAIT` limits configures. */
export interface PoolScalerLimits {
  /** `POOL_CAP_TOTAL` — hard maximum wallets, counted RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL-rule-2 style (all states). */
  readonly poolCapTotal: number;
  /** `RECEIVE_QUEUE_MAX_WAIT` seconds — longest a receive may wait without a wallet. */
  readonly receiveQueueMaxWaitSecs: number;
  /** Defaults to the frozen `MINT_BATCH_LIMIT`; overridable only to test the bound. */
  readonly mintBatchLimit?: number;
}

export type PoolScalerErrorReason = "POOL_CAP_INVALID" | "MAX_WAIT_INVALID" | "MINT_PORT_FAILED";

export class PoolScalerError extends Error {
  readonly reason: PoolScalerErrorReason;

  constructor(reason: PoolScalerErrorReason, detail: string) {
    super(`PoolScalerError[${reason}]: ${detail}`);
    this.name = "PoolScalerError";
    this.reason = reason;
  }
}

/**
 * Canonical scaler SQL against the frozen surfaces. Exported so tests match the exact
 * strings and a silent statement drift fails loudly.
 *
 * The queue-side statements deliberately restate the allocator's queued-receive predicate
 * (`pool-allocator.ts` COUNT_UNASSIGNED_RECEIVES) rather than the naive
 * `receiver_wallet_id IS NULL` form: the operations CHECK keeps `receiver_wallet_id` NULL until
 * expiry and T0 exist, so an already-assigned pre-T0 receive still reads NULL there. Counting
 * it as queued would double-count it — once as a queue slot and once as its RECEIVE_WINDOW
 * lease — and inflate `open_sessions`, which is exactly the "scaler view disagrees with the
 * admission path" bug warns about. `countUnassignedReceives` is imported rather than
 * copied so the two can never diverge.
 */
export const POOL_SCALER_STATEMENTS = {
  /**
   * Serialises scale-up (rule 3). Transaction-scoped: released by COMMIT or ROLLBACK,
   * with no unlock path to forget. Every count below is read AFTER this, so a second scaler
   * observes the first scaler's committed mint instead of a stale pre-mint count.
   */
  LOCK_SCALE_UP: `SELECT pg_advisory_xact_lock($1) AS locked`,

  /**
   * `pool_cap` input (rule 2): ALL wallet rows, including PINNED, QUARANTINED and
   * RETIRED. No predicate, on purpose — every narrowing conjunct anyone is ever tempted to
   * add here (`state <> 'RETIRED'`, `retired_at IS NULL`) reopens the unbounded key-growth
   * vector the rule exists to close. Semantically identical to the frozen contract literal
   * CAP_COUNT_UNDER_LOCK_SQL.
   */
  COUNT_CAP_UNDER_LOCK: `SELECT count(*)::int AS cap_count FROM wallets`,

  /**
   * `available_wallet_count` (B-04): only recovery-verified AVAILABLE node-generated
   * wallets. The three conjuncts are the allocator's SELECT_ELIGIBLE_WALLET predicate
   * verbatim, so what the scaler calls "available" is exactly what the allocator can take —
   * the pg suite asserts that equivalence against a live pool rather than by text match.
   * This count is a METRIC only: RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL mints against the cap count, never against this one,
   * because a keypair is minted recovery-UNVERIFIED and only the ceremony makes it
   * available. Minting can never close an AVAILABLE deficit.
   */
  COUNT_AVAILABLE_WALLETS: `
SELECT count(*)::int AS available_count
  FROM wallets w
 WHERE w.key_origin = 'node_generated'
   AND w.recovery_verified_at IS NOT NULL
   AND w.state = 'AVAILABLE'
   AND NOT EXISTS (
         SELECT 1
           FROM receive_release_proofs rrp
           JOIN operation_wallets ow
             ON ow.operation_id = rrp.operation_id
            AND ow.operation_role = 'RECEIVER'
          WHERE ow.wallet_id = w.id)
   AND NOT EXISTS (
         SELECT 1
           FROM lease_release_proofs lrp
          WHERE lrp.wallet_id = w.id
            AND lrp.proof_kind = 'RECEIVE_EXPIRED_T0')`
    .replace(/\s+/g, " ")
    .trim(),

  /** Wallet census by state — pinned ratio, attention (QUARANTINED) count, cap utilisation. */
  COUNT_WALLETS_BY_STATE: `
SELECT state::text AS state, count(*)::int AS wallets
  FROM wallets
 GROUP BY state`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * The RECEIVE-pinned half of `open_sessions` (rule 1). Send-side source pins are
   * excluded by the lease_role filter — a SEND_SOURCE or MOVE_SOURCE pin is not receive demand
   * and must not pull the provisioning target up.
   */
  COUNT_RECEIVE_WINDOW_LEASES: `
SELECT count(*)::int AS leases,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(acquired_at)))::int, 0) AS oldest_age_secs
  FROM wallet_active_leases
 WHERE lease_role = 'RECEIVE_WINDOW'`
    .replace(/\s+/g, " ")
    .trim(),

  /** Queue depth and oldest wait, over the allocator's queued-receive predicate. */
  QUEUE_DEPTH_AND_OLDEST_AGE: `
SELECT count(*)::int AS depth,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(o.created_at)))::int, 0) AS oldest_age_secs
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'
   AND o.receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = o.id
            AND ow.operation_role = 'RECEIVER')`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Receives whose wait has exceeded `RECEIVE_QUEUE_MAX_WAIT`, in the same
   * `(created_at, operation_id)` sequence step 4 promotes by. Ordering by the total tuple is
   * what makes "queue age expiry is deterministic" true rather than aspirational:
   * receives created inside one clock tick would otherwise expire in an arbitrary sequence.
   *
   * Age predicate is strict exceed, matching frozen `isReceiveExpired`
   * (`waitedMs > RECEIVE_QUEUE_MAX_WAIT_MS`): `created_at < now - interval`. Equality at the
   * bound is NOT expired and remains eligible for wallet selection. Evaluated by the database
   * so the decision never depends on an application clock that may differ per process.
   */
  SELECT_QUEUE_EXPIRED_RECEIVES: `
SELECT o.id::text AS operation_id,
       EXTRACT(EPOCH FROM (now() - o.created_at))::int AS waited_secs
  FROM operations o
 WHERE o.kind = 'RECEIVE_EXTERNAL'
   AND o.status = 'CREATED'
   AND o.receiver_wallet_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = o.id
            AND ow.operation_role = 'RECEIVER')
   AND o.created_at < now() - make_interval(secs => $1)
 ORDER BY o.created_at, o.id /* contract-allow:order:frozen-sql-text */
 LIMIT $2`
    .replace(/\s+/g, " ")
    .trim(),

  /**
   * Step 5 / walletless-receive expiry — guarded CREATED→EXPIRED for one never-assigned receive.
   * The WHERE restates the queued-receive predicate so a concurrent assigner that won the
   * race matches zero rows (no reopen, no wallet-touch). row_version bumps once; terminal_at
   * is stamped with the same UPDATE (SPA in-flight = terminal_at IS NULL — ZTR-1249).
   */
  EXPIRE_QUEUE_AGED_RECEIVE: `
UPDATE operations
   SET status = 'EXPIRED',
       row_version = row_version + 1,
       terminal_at = COALESCE(terminal_at, now()),
       updated_at = now()
 WHERE id = $1::uuid
   AND kind = 'RECEIVE_EXTERNAL'
   AND status = 'CREATED'
   AND receiver_wallet_id IS NULL
   AND expiry_unix_time_secs IS NULL
   AND t0_observation_id IS NULL
   AND NOT EXISTS (
         SELECT 1
           FROM operation_wallets ow
          WHERE ow.operation_id = operations.id
            AND ow.operation_role = 'RECEIVER')`
    .replace(/\s+/g, " ")
    .trim(),
} as const;

// ─── pure RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL arithmetic ──────────────────────────────────────────────────

/** Exact integer ceil-division. Never the float form (autoscale headroom integer form). */
function ceilDiv(numerator: number, denominator: number): number {
  const quotient = Math.floor(numerator / denominator);
  return numerator % denominator === 0 ? quotient : quotient + 1;
}

/**
 * rule 1 — the provisioning target as a TOTAL:
 * `min(max(ceil(open_sessions * 11 / 10), POOL_FLOOR), pool_cap)`.
 */
export function poolTargetTotal(openSessions: number, poolCapTotal: number): number {
  const needed = ceilDiv(openSessions * HEADROOM_NUMERATOR, HEADROOM_DENOMINATOR);
  return Math.min(Math.max(needed, POOL_FLOOR), poolCapTotal);
}

/**
 * rule 3 — keypairs to mint this cycle:
 * `max(0, min(target - cap_count, pool_cap - cap_count, MINT_BATCH_LIMIT))`.
 *
 * `cap_count` is the rule-2 count of ALL wallets, so the cap-headroom term goes to zero the
 * moment the pool is full — including when it is full of PINNED wallets. That is the
 * "scaler never mints merely because pinned wallets are excluded from available_wallet_count"
 * rule, expressed as arithmetic rather than as a guard someone can forget to call.
 * `MINT_BATCH_LIMIT` bounds a single pass so one tick cannot itself exhaust resources.
 */
export function computeMintCount(input: {
  readonly target: number;
  readonly capCount: number;
  readonly poolCapTotal: number;
  readonly mintBatchLimit?: number;
}): number {
  const batchLimit = input.mintBatchLimit ?? MINT_BATCH_LIMIT;
  return Math.max(
    0,
    Math.min(input.target - input.capCount, input.poolCapTotal - input.capCount, batchLimit),
  );
}

// ─── scale-up ───────────────────────────────────────────────────────────────

export interface PoolScaleUpPlan {
  /** RECEIVE-pinned wallets + queued unassigned receives (rule 1). */
  readonly openSessions: number;
  /** All wallet rows, every state (rule 2), read under the advisory lock. */
  readonly capCount: number;
  readonly poolTargetTotal: number;
  readonly mintCount: number;
  readonly poolCapTotal: number;
}

/**
 * Mints ONE node-generated wallet row and returns its id, on the caller's transaction.
 * The composition root binds the keypair ceremony; no key material crosses this module
 * (the key-custody rule). A newly minted wallet is born recovery-UNVERIFIED and therefore is NOT
 * receive-eligible until the ceremony stamps it (recovery_verified_at gate).
 */
export type MintWallet = (db: SqlExecutor, batchIndex: number) => Promise<string>;

function assertLimits(limits: PoolScalerLimits): void {
  if (!Number.isInteger(limits.poolCapTotal) || limits.poolCapTotal < POOL_FLOOR) {
    throw new PoolScalerError(
      "POOL_CAP_INVALID",
      `POOL_CAP_TOTAL must be an integer >= ${POOL_FLOOR}, got ${String(limits.poolCapTotal)}`,
    );
  }
  if (
    !Number.isInteger(limits.receiveQueueMaxWaitSecs) ||
    limits.receiveQueueMaxWaitSecs <= 0
  ) {
    throw new PoolScalerError(
      "MAX_WAIT_INVALID",
      `RECEIVE_QUEUE_MAX_WAIT must be a positive integer, got ${String(limits.receiveQueueMaxWaitSecs)}`,
    );
  }
}

/**
 * rule 3 — take the scale-up lock, then read every count under it and decide.
 *
 * The sequence is the invariant: lock, THEN count. A plan computed from counts read before the
 * lock is a stale plan, and two scalers holding stale plans both mint and overshoot the cap.
 * Runs inside the caller's transaction so the lock is still held while the caller mints.
 */
export async function planPoolScaleUp(
  db: SqlExecutor,
  limits: PoolScalerLimits,
): Promise<PoolScaleUpPlan> {
  assertLimits(limits);

  await db.query(POOL_SCALER_STATEMENTS.LOCK_SCALE_UP, [POOL_SCALE_UP_LOCK_KEY]);

  const capCount = Number(
    (await db.query<{ cap_count: number }>(POOL_SCALER_STATEMENTS.COUNT_CAP_UNDER_LOCK)).rows[0]
      ?.cap_count ?? 0,
  );
  const openSessions = await countOpenSessions(db);
  const target = poolTargetTotal(openSessions, limits.poolCapTotal);

  return {
    openSessions,
    capCount,
    poolTargetTotal: target,
    mintCount: computeMintCount({
      target,
      capCount,
      poolCapTotal: limits.poolCapTotal,
      mintBatchLimit: limits.mintBatchLimit,
    }),
    poolCapTotal: limits.poolCapTotal,
  };
}

/**
 * `open_sessions` (rule 1) = live RECEIVE-pinned pool wallets + unassigned CREATED
 * receives still in the queue. Send-side source pins are excluded.
 */
export async function countOpenSessions(db: SqlExecutor): Promise<number> {
  const pinned = Number(
    (await db.query<{ leases: number }>(POOL_SCALER_STATEMENTS.COUNT_RECEIVE_WINDOW_LEASES))
      .rows[0]?.leases ?? 0,
  );
  return pinned + (await countUnassignedReceives(db));
}

export interface PoolScaleUpResult {
  readonly plan: PoolScaleUpPlan;
  readonly mintedWalletIds: readonly string[];
}

/**
 * One scaling pass: plan under the lock, then mint exactly `mintCount` wallets while still
 * holding it. Everything runs in the caller's transaction, so a crash, a deploy or any thrown
 * error mid-batch rolls the whole batch back — which is what makes "no duplicate mint and no
 * wallet minted past the cap" true across a restart rather than needing a resume protocol.
 */
export async function runPoolScaleUp(
  db: SqlExecutor,
  params: { readonly limits: PoolScalerLimits; readonly mint: MintWallet },
): Promise<PoolScaleUpResult> {
  const plan = await planPoolScaleUp(db, params.limits);
  const mintedWalletIds: string[] = [];

  for (let i = 0; i < plan.mintCount; i += 1) {
    const walletId = await params.mint(db, i);
    if (typeof walletId !== "string" || walletId.length === 0) {
      throw new PoolScalerError(
        "MINT_PORT_FAILED",
        `mint port returned no wallet id at batch index ${i}`,
      );
    }
    mintedWalletIds.push(walletId);
  }

  return { plan, mintedWalletIds };
}

// ─── queue-age expiry ────────────────────────────────────────

export interface QueueExpiredReceive {
  readonly operationId: string;
  readonly waitedSecs: number;
}

/**
 * The receives that have outlived `RECEIVE_QUEUE_MAX_WAIT`, in deterministic
 * `(created_at, operation_id)` sequence. Every row returned is by construction one that never
 * got a wallet: the predicate is the allocator's queued set, so no wallet row and no lease row
 * is ever involved, and this pass therefore only ever describes the `CREATED→EXPIRED`
 * transition, never the `READY→EXPIRED` one (whose wallet stays leased until exact T0 release
 * proof).
 *
 * Boundary matches frozen `isReceiveExpired`: age must *strictly exceed* the max wait
 * (equality at the bound is still eligible for wallet selection / promotion).
 *
 * Selection only — the terminal write and `operation.expired` emit live in
 * `expireQueueAgedReceives`. Kept separate so a caller can dry-run the selection (metrics,
 * alerts) without committing the transition.
 */
export async function selectQueueExpiredReceives(
  db: SqlExecutor,
  params: { readonly limits: PoolScalerLimits; readonly limit?: number },
): Promise<readonly QueueExpiredReceive[]> {
  assertLimits(params.limits);
  const rows = await db.query<{ operation_id: string; waited_secs: number }>(
    POOL_SCALER_STATEMENTS.SELECT_QUEUE_EXPIRED_RECEIVES,
    [params.limits.receiveQueueMaxWaitSecs, params.limit ?? params.limits.poolCapTotal],
  );
  return rows.rows.map((r) => ({
    operationId: r.operation_id,
    waitedSecs: Number(r.waited_secs),
  }));
}

/**
 * Emits one durable `operation.expired` for a queue-age expiry. Bound by the composition root
 * to the node event ledger (and/or implementer stream); this module never signs or formats the
 * event envelope (the byte-exact signing and key-custody rules). Tests inject a recorder.
 */
export type EmitOperationExpired = (
  db: SqlExecutor,
  params: { readonly operationId: string; readonly waitedSecs: number },
) => Promise<void>;

export interface ExpireQueueAgedResult {
  readonly expired: readonly QueueExpiredReceive[];
  /** Operation ids selected but not flipped (lost a race to assign / already terminal). */
  readonly skipped: readonly string[];
}

/**
 * Expire every never-assigned receive that has
 * *exceeded* `RECEIVE_QUEUE_MAX_WAIT` (strict `>`; equality still promotes), in
 * deterministic sequence, and emit `operation.expired` for each successful flip. walletless-receive expiry
 * made the walletless EXPIRED row representable; the guarded UPDATE restates the
 * queued predicate so a concurrent assigner that already took the receive causes a zero-row
 * match rather than a status fight. No wallet, lease, T0, code or artifact work runs on this
 * path (frozen contract expiryBranch).
 */
export async function expireQueueAgedReceives(
  db: SqlExecutor,
  params: {
    readonly limits: PoolScalerLimits;
    readonly emitExpired: EmitOperationExpired;
    readonly limit?: number;
  },
): Promise<ExpireQueueAgedResult> {
  const selected = await selectQueueExpiredReceives(db, {
    limits: params.limits,
    limit: params.limit,
  });
  const expired: QueueExpiredReceive[] = [];
  const skipped: string[] = [];

  for (const row of selected) {
    // The psql harness (and production adapters) report mutation success via rowCount;
    // no RETURNING payload is required — the id is already known from selection.
    const flipped = await db.query(
      POOL_SCALER_STATEMENTS.EXPIRE_QUEUE_AGED_RECEIVE,
      [row.operationId],
    );
    if ((flipped.rowCount ?? 0) === 0) {
      skipped.push(row.operationId);
      continue;
    }
    await params.emitExpired(db, {
      operationId: row.operationId,
      waitedSecs: row.waitedSecs,
    });
    expired.push(row);
  }

  return { expired, skipped };
}

// ─── pressure metrics ───────────────────────────────────────────────

/**
 * Live receive-pool pressure counters, read from the database on every call rather
 * than accumulated in process memory — a scaler that restarts must not reset its own alerting.
 *
 * Two of the seven alert inputs are NOT here and are not faked: gateway-read failure
 * rate and observation anomalies are owned by the gateway and observation concerns
 * (`gateway_observations`, `observation_anomalies`) and are merged by the composition root.
 * `receive` is a dependency-boundary leaf (test/boundaries.test.ts), so reaching into those
 * ledgers from this module would couple two concerns to save one join.
 */
export interface PoolPressureMetrics {
  readonly poolCapTotal: number;
  readonly capCount: number;
  /** Integer floor percentage — exact, deterministic, and stable to alert on. */
  readonly capUtilizationPercent: number;
  readonly availableWalletCount: number;
  readonly pinnedWalletCount: number;
  /** QUARANTINED wallets — the pressure "attention count". */
  readonly attentionWalletCount: number;
  readonly retiredWalletCount: number;
  readonly pinnedRatioPercent: number;
  readonly queueDepth: number;
  readonly oldestQueuedAgeSecs: number;
  readonly receiveWindowLeaseCount: number;
  readonly oldestReceiveLeaseAgeSecs: number;
  readonly openSessions: number;
  readonly poolTargetTotal: number;
}

export async function collectPoolPressureMetrics(
  db: SqlExecutor,
  limits: PoolScalerLimits,
): Promise<PoolPressureMetrics> {
  assertLimits(limits);

  const census = await db.query<{ state: string; wallets: number }>(
    POOL_SCALER_STATEMENTS.COUNT_WALLETS_BY_STATE,
  );
  const byState = new Map(census.rows.map((r) => [r.state, Number(r.wallets)]));
  const capCount = [...byState.values()].reduce((sum, n) => sum + n, 0);

  const available = Number(
    (await db.query<{ available_count: number }>(POOL_SCALER_STATEMENTS.COUNT_AVAILABLE_WALLETS))
      .rows[0]?.available_count ?? 0,
  );
  const leases = (
    await db.query<{ leases: number; oldest_age_secs: number }>(
      POOL_SCALER_STATEMENTS.COUNT_RECEIVE_WINDOW_LEASES,
    )
  ).rows[0];
  const queue = (
    await db.query<{ depth: number; oldest_age_secs: number }>(
      POOL_SCALER_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE,
    )
  ).rows[0];

  const pinned = byState.get("PINNED") ?? 0;
  const queueDepth = Number(queue?.depth ?? 0);
  const receiveWindowLeaseCount = Number(leases?.leases ?? 0);
  const openSessions = receiveWindowLeaseCount + queueDepth;

  return {
    poolCapTotal: limits.poolCapTotal,
    capCount,
    capUtilizationPercent: Math.floor((capCount * 100) / limits.poolCapTotal),
    availableWalletCount: available,
    pinnedWalletCount: pinned,
    attentionWalletCount: byState.get("QUARANTINED") ?? 0,
    retiredWalletCount: byState.get("RETIRED") ?? 0,
    pinnedRatioPercent: capCount === 0 ? 0 : Math.floor((pinned * 100) / capCount),
    queueDepth,
    oldestQueuedAgeSecs: Number(queue?.oldest_age_secs ?? 0),
    receiveWindowLeaseCount,
    oldestReceiveLeaseAgeSecs: Number(leases?.oldest_age_secs ?? 0),
    openSessions,
    poolTargetTotal: poolTargetTotal(openSessions, limits.poolCapTotal),
  };
}
