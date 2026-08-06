// Live MOVE_INTERNAL preflight checklist.
//
// Offline, pure function over an injected probe seam. Never touches transport, the
// filesystem, or a key. A failed check makes the plan NOT ready — the harness then
// refuses to release a runner lock for execution.
//
// Governing:
// 12
//
// Asymmetric eligibility (ticket gotcha):
//   source  — node_generated + controlled + AVAILABLE/PINNED; recovery_verified NOT required
//   dest    — full automatic_sink (B1): node_generated AND BLESSED AND recovery_verified
//             AND state in {AVAILABLE, PINNED}

import {
  verifyAutomaticSinkEligibility,
  type CustodyPredicateFacts,
} from "@zucoins/generic-node-contracts/custody";

import {
  type MoveAbortCriteria,
  moveInternalAbortCriteria,
} from "./abort-criteria.js";
import { type RunnerLock, type RunnerLockHandle } from "./runner-lock.js";
import {
  type Amount,
  type DualControlAuthorization,
  type MoveInternalPlan,
  compareAmounts,
} from "./types.js";

/**
 * Hard external bound for agent-driven acceptance moves. Callers may lower
 * `amountCeiling` but never raise it above this — effectiveCeiling = min(input, HARD).
 */
export const MOVE_AMOUNT_HARD_CAP: Amount = "0.01";

/** Default fractional ceiling for a dual-control acceptance move (external bound). */
export const DEFAULT_MOVE_AMOUNT_CEILING: Amount = MOVE_AMOUNT_HARD_CAP;

/** Canonical fractional dust amount preferred for the one authorized run. */
export const DEFAULT_MOVE_AMOUNT: Amount = "0.000001";

export type MovePreflightCheckId =
  | "dual_control_authorization"
  | "source_eligible"
  | "destination_eligible"
  | "wallets_distinct"
  | "amount_fixed_fractional"
  | "t0_capture_fresh"
  | "backups_present"
  | "no_active_lease"
  | "runner_lock_acquired"
  | "lease_uuid_order_reported"
  | "abort_criteria_bound";

export interface MovePreflightCheckResult {
  readonly id: MovePreflightCheckId;
  readonly ok: boolean;
  /** Key-free human-readable reason. Never includes private key material. */
  readonly detail: string;
}

/** Durable wallet facts read from wallets/destinations — never cached assumptions. */
export interface MoveWalletFacts {
  readonly walletId: string;
  readonly keyOrigin: unknown;
  readonly walletState: unknown;
  /** Destination row state, or null when the wallet has no destination registration. */
  readonly destinationState: unknown;
  readonly recoveryVerifiedAt: unknown;
  /** True when this node controls the wallet secret (node-generated under local vault). */
  readonly nodeControlled: boolean;
  /** True when a current backup covering this wallet exists. */
  readonly backupPresent: boolean;
}

export interface ActiveLeaseRow {
  readonly walletId: string;
  readonly leaseRole: string;
  readonly operationId: string;
}

/**
 * Injected read-only + lock seam. Live runner wires real DB/gateway reads; unit tests
 * wire in-memory fakes. Nothing here can submit.
 */
export interface MovePreflightProbe {
  loadWallet(walletId: string): Promise<MoveWalletFacts | null>;
  /** Current wallet_active_leases rows for the wallet, empty when clear. */
  activeLeases(walletId: string): Promise<readonly ActiveLeaseRow[]>;
  availableBalance(walletId: string): Promise<Amount>;
  /**
   * Whether T0 observations for this attempt will be captured fresh at run time
   * (not reused from an earlier session's snapshot).
   */
  t0CaptureWillBeFresh(attemptId: string): Promise<boolean>;
}

export interface MovePreflightInput {
  readonly attemptId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  /**
   * Optional tighter ceiling. Clamped to MOVE_AMOUNT_HARD_CAP  — callers
   * may lower the window but never raise it above 0.01 ZKZ.
   */
  readonly amountCeiling?: Amount;
  /** Defaults to a fresh createRunnerLock()-style lock supplied by the caller. */
  readonly runnerLock: RunnerLock;
  /** Holder id recorded on the serialized runner lock. */
  readonly runnerHolderId: string;
}

export interface LeaseUuidOrder {
  /** Lexicographically sorted wallet UUIDs — the order must acquire leases. */
  readonly acquireOrder: readonly [string, string];
  readonly first: string;
  readonly second: string;
}

export interface MovePreflightReport {
  readonly ready: boolean;
  readonly checks: readonly MovePreflightCheckResult[];
  readonly plan: MoveInternalPlan | null;
  readonly leaseUuidOrder: LeaseUuidOrder;
  readonly abortCriteria: MoveAbortCriteria;
  /** Non-null only when ready && lock acquired; caller must release after the run. */
  readonly runnerLockHandle: RunnerLockHandle | null;
}

function check(
  id: MovePreflightCheckId,
  ok: boolean,
  detail: string,
): MovePreflightCheckResult {
  return { id, ok, detail };
}

/** UUID-order lease acquisition pair. */
export function leaseUuidOrder(a: string, b: string): LeaseUuidOrder {
  const sorted = a <= b ? ([a, b] as const) : ([b, a] as const);
  return { acquireOrder: sorted, first: sorted[0], second: sorted[1] };
}

/**
 * Source predicate: node-generated and controlled;
 * recovery_verified is NOT required for the source role.
 */
export function evaluateMoveSourceEligibility(facts: MoveWalletFacts): {
  ok: boolean;
  detail: string;
} {
  if (!facts.nodeControlled) {
    return { ok: false, detail: `source ${facts.walletId} is not node-controlled` };
  }
  if (facts.keyOrigin !== "node_generated") {
    return {
      ok: false,
      detail: `source ${facts.walletId} key_origin=${String(facts.keyOrigin)} (require node_generated)`,
    };
  }
  const state = String(facts.walletState);
  if (state !== "AVAILABLE" && state !== "PINNED") {
    return {
      ok: false,
      detail: `source ${facts.walletId} wallet_state=${state} (require AVAILABLE|PINNED)`,
    };
  }
  return {
    ok: true,
    detail: `source ${facts.walletId} node_generated+controlled, state=${state} (recovery not required for source)`,
  };
}

/**
 * Destination predicate (step 3 + B1): full automatic_sink_eligible.
 */
export function evaluateMoveDestinationEligibility(facts: MoveWalletFacts): {
  ok: boolean;
  detail: string;
  denialReason: string | null;
} {
  if (!facts.nodeControlled) {
    return {
      ok: false,
      detail: `destination ${facts.walletId} is not node-controlled`,
      denialReason: "NOT_NODE_CONTROLLED",
    };
  }
  const custodyFacts: CustodyPredicateFacts = {
    keyOrigin: facts.keyOrigin,
    destinationState: facts.destinationState,
    recoveryVerifiedAt: facts.recoveryVerifiedAt,
    walletState: facts.walletState,
  };
  const decision = verifyAutomaticSinkEligibility(custodyFacts);
  if (!decision.eligible) {
    return {
      ok: false,
      detail: `destination ${facts.walletId} fails automatic_sink: ${decision.denialReason}`,
      denialReason: decision.denialReason,
    };
  }
  return {
    ok: true,
    detail: `destination ${facts.walletId} B1+recovery-verified (BLESSED, recovery_verified_at set, state eligible)`,
    denialReason: null,
  };
}

function checkAuthorization(
  input: MovePreflightInput,
): MovePreflightCheckResult {
  const auth = input.authorization;
  // Non-empty trimmed attemptId is required on both sides — empty-string equality
  // is not a binding (dual-control attempt identity).
  if (input.attemptId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "plan attemptId is empty — dual-control binding requires a non-empty attempt identity",
    );
  }
  if (auth.attemptId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "authorization attemptId is empty — dual-control binding requires a non-empty attempt identity",
    );
  }
  if (auth.attemptId !== input.attemptId) {
    return check(
      "dual_control_authorization",
      false,
      `authorization attemptId ${auth.attemptId} does not match plan attemptId ${input.attemptId}`,
    );
  }
  if (auth.attestationId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "dual-control attestationId is empty",
    );
  }
  if (auth.recordedAt.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "dual-control recordedAt is empty",
    );
  }
  return check(
    "dual_control_authorization",
    true,
    `dual-control attestation ${auth.attestationId} bound to attempt ${auth.attemptId}`,
  );
}

/**
 * Resolve the effective amount ceiling: caller may tighten below the hard
 * cap, but never raise it. Malformed caller ceilings fall back to the hard cap
 * after the amount check itself rejects on compare failure.
 */
export function effectiveMoveAmountCeiling(requested?: Amount): Amount {
  if (requested === undefined) return MOVE_AMOUNT_HARD_CAP;
  try {
    // min(requested, HARD_CAP) — never allow a ceiling above.
    return compareAmounts(requested, MOVE_AMOUNT_HARD_CAP) > 0
      ? MOVE_AMOUNT_HARD_CAP
      : requested;
  } catch {
    // Malformed ceiling string: refuse to honor it; hard cap still applies via
    // checkAmount's own parse (caller amount vs hard cap).
    return MOVE_AMOUNT_HARD_CAP;
  }
}

function checkAmount(
  amount: Amount,
  ceiling: Amount,
  sourceBalance: Amount,
): MovePreflightCheckResult {
  let positive: boolean;
  let withinCeiling: boolean;
  let withinHardCap: boolean;
  let balanceOk: boolean;
  try {
    positive = compareAmounts(amount, "0") > 0;
    withinCeiling = compareAmounts(amount, ceiling) <= 0;
    withinHardCap = compareAmounts(amount, MOVE_AMOUNT_HARD_CAP) <= 0;
    balanceOk = compareAmounts(sourceBalance, amount) >= 0;
  } catch (err) {
    return check(
      "amount_fixed_fractional",
      false,
      err instanceof Error ? err.message : "malformed amount",
    );
  }
  if (!positive) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount must be strictly positive (got ${amount})`,
    );
  }
  // Hard bound first so a bypassed soft ceiling cannot mint a ready plan.
  if (!withinHardCap) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount ${amount} exceeds the ${MOVE_AMOUNT_HARD_CAP} ZKZ hard cap`,
    );
  }
  if (!withinCeiling) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount ${amount} exceeds the ${ceiling} ZKZ acceptance ceiling`,
    );
  }
  if (!balanceOk) {
    return check(
      "amount_fixed_fractional",
      false,
      `source balance ${sourceBalance} < fixed amount ${amount}`,
    );
  }
  return check(
    "amount_fixed_fractional",
    true,
    `amount ${amount} ZKZ fixed within (0, ${ceiling}] (hard cap ${MOVE_AMOUNT_HARD_CAP}) and covered by source balance ${sourceBalance}`,
  );
}

/**
 * Run the full MOVE_INTERNAL preflight checklist. Read-only except for acquiring the
 * serialized runner lock on the all-green path (released by the caller after the run,
 * or immediately if a later check fails after lock acquisition — this implementation
 * acquires the lock last so no rollback is required on earlier failures).
 */
export async function runMoveInternalPreflight(
  probe: MovePreflightProbe,
  input: MovePreflightInput,
): Promise<MovePreflightReport> {
  const ceiling = effectiveMoveAmountCeiling(input.amountCeiling);
  const order = leaseUuidOrder(input.sourceWalletId, input.destinationWalletId);
  const abortCriteria = moveInternalAbortCriteria();
  const checks: MovePreflightCheckResult[] = [];

  checks.push(checkAuthorization(input));

  const source = await probe.loadWallet(input.sourceWalletId);
  if (source === null) {
    checks.push(
      check("source_eligible", false, `source wallet ${input.sourceWalletId} not found`),
    );
  } else {
    const src = evaluateMoveSourceEligibility(source);
    checks.push(check("source_eligible", src.ok, src.detail));
  }

  const destination = await probe.loadWallet(input.destinationWalletId);
  if (destination === null) {
    checks.push(
      check(
        "destination_eligible",
        false,
        `destination wallet ${input.destinationWalletId} not found`,
      ),
    );
  } else {
    const dst = evaluateMoveDestinationEligibility(destination);
    checks.push(check("destination_eligible", dst.ok, dst.detail));
  }

  const distinct = input.sourceWalletId !== input.destinationWalletId;
  checks.push(
    check(
      "wallets_distinct",
      distinct,
      distinct
        ? `source ${input.sourceWalletId} ≠ destination ${input.destinationWalletId}`
        : "source and destination must be different wallets",
    ),
  );

  const sourceBalance =
    source !== null ? await probe.availableBalance(input.sourceWalletId) : "0";
  checks.push(checkAmount(input.amount, ceiling, sourceBalance));

  const t0Fresh = await probe.t0CaptureWillBeFresh(input.attemptId);
  checks.push(
    check(
      "t0_capture_fresh",
      t0Fresh,
      t0Fresh
        ? `T0s for attempt ${input.attemptId} will be captured fresh at run time`
        : `T0 capture for attempt ${input.attemptId} would reuse a prior session snapshot — refuse`,
    ),
  );

  const srcBackup = source?.backupPresent === true;
  const dstBackup = destination?.backupPresent === true;
  const backupsOk = srcBackup && dstBackup;
  checks.push(
    check(
      "backups_present",
      backupsOk,
      backupsOk
        ? "backups present for source and destination"
        : `missing backup: source=${srcBackup} destination=${dstBackup}`,
    ),
  );

  const srcLeases = await probe.activeLeases(input.sourceWalletId);
  const dstLeases = await probe.activeLeases(input.destinationWalletId);
  const busy: string[] = [];
  if (srcLeases.length > 0) {
    busy.push(
      `source ${input.sourceWalletId} holds ${srcLeases.map((l) => `${l.leaseRole}@${l.operationId}`).join(",")}`,
    );
  }
  if (dstLeases.length > 0) {
    busy.push(
      `destination ${input.destinationWalletId} holds ${dstLeases.map((l) => `${l.leaseRole}@${l.operationId}`).join(",")}`,
    );
  }
  checks.push(
    check(
      "no_active_lease",
      busy.length === 0,
      busy.length === 0
        ? "wallet_active_leases clear for both candidate wallets"
        : `in-flight lease blocks preflight: ${busy.join("; ")}`,
    ),
  );

  checks.push(
    check(
      "lease_uuid_order_reported",
      true,
      `lease acquire order (UUID asc): first=${order.first} second=${order.second}`,
    ),
  );

  checks.push(
    check(
      "abort_criteria_bound",
      abortCriteria.blindRetryForbidden &&
        abortCriteria.rebuildRequiresPositiveNonLandingOracle,
      `abort policy ${abortCriteria.policyId}: blind-retry forbidden; rebuild only via the positive non-landing oracle`,
    ),
  );

  // Acquire the runner lock LAST so earlier failures never need to release it.
  let runnerLockHandle: RunnerLockHandle | null = null;
  const priorReady = checks.every((c) => c.ok);
  if (priorReady) {
    const handle = input.runnerLock.tryAcquire(input.runnerHolderId);
    if (handle === null) {
      checks.push(
        check(
          "runner_lock_acquired",
          false,
          `serialized runner lock held by ${input.runnerLock.holderId ?? "<unknown>"}`,
        ),
      );
    } else {
      runnerLockHandle = handle;
      checks.push(
        check(
          "runner_lock_acquired",
          true,
          `serialized runner lock acquired by ${handle.holderId} at ${handle.acquiredAt}`,
        ),
      );
    }
  } else {
    checks.push(
      check(
        "runner_lock_acquired",
        false,
        "runner lock not attempted because earlier checks failed",
      ),
    );
  }

  const ready = checks.every((c) => c.ok);
  const plan: MoveInternalPlan | null = ready
    ? {
        kind: "MOVE_INTERNAL",
        attemptId: input.attemptId,
        sourceWalletId: input.sourceWalletId,
        destinationWalletId: input.destinationWalletId,
        amount: input.amount,
        authorization: input.authorization,
      }
    : null;

  if (!ready && runnerLockHandle !== null) {
    // Defensive: should be unreachable because lock is last, but never leave a lock stranded.
    runnerLockHandle.release();
    runnerLockHandle = null;
  }

  return {
    ready,
    checks,
    plan,
    leaseUuidOrder: order,
    abortCriteria,
    runnerLockHandle,
  };
}
