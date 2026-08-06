// the named concern — pure model of the composed the named concern/.2 receive-admission surface.
// CONTRACT_FREEZE: no runtime ships from this file. It is the executable negative-proof for
// "no unrecoverable inbound exposure" against the frozen assignment SELECT, the arm recheck,
// the structural lease trigger, the expiry release, and the monotonic recovery stamp
// (the receive-gate enforcement freeze).
//
// Disposition recorded by this model (acceptance OR-branch, the named concern):
//   OUTRIGHT_PROHIBITION — arm/HOLD is rejected for every recovery-unverified wallet.
//   The alternative branch ("every such wallet carries an approved backup/recovery rule") was
//   NOT taken by the named concern/.2; see DISPOSITION below and exposure-proof.test.ts.
//
// Governing: the recovery-gate rule and the receive-gate enforcement freeze, with the node-core,
// data-model, api-contract, operation-flows, signing-custody, and operations-recovery specs.

import { isAvailableForReceive, type PoolWalletDescriptor } from "../pool-policy/eligibility.js";
import {
  selectAssignableWallet,
  type SelectableWallet,
} from "../pool-policy/selection.js";

/** Acceptance-criterion disposition actually taken by the composed the named concern/.2 design.*/
export const DISPOSITION = {
  branch: "OUTRIGHT_PROHIBITION",
  meaning:
    "arm/HOLD remains prohibited for every recovery-unverified wallet (G1 gate at assignment, arm recheck, structural RECEIVE_WINDOW/MOVE_DESTINATION backstop). Unverified wallets are not covered by a substitute whole-vault backup rule.",
  rejectedBranch: "APPROVED_BACKUP_RULE_COVERING_UNVERIFIED",
  authority: [
    "recovery-gate-rule",
    "receive-gate-enforcement-freeze",
    "recovery-gate-assignment-slice",
    "recovery-gate-arm-slice",
  ] as const,
} as const;

export type WalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";
export type LeaseRole =
  | "RECEIVE_WINDOW"
  | "MOVE_DESTINATION"
  | "MOVE_SOURCE"
  | "SEND_SOURCE"
  | "RECONCILIATION";

export type ModeledWallet = SelectableWallet & {
  readonly publicKey: string;
  readonly destinationState: "PENDING" | "BLESSED" | "RETIRED" | null;
};

export type HoldAssignOutcome =
  | {
      readonly kind: "SYNC_201";
      readonly status: 201;
      readonly receiver_pubkey: string;
      readonly transfer_code: null;
      readonly code_status: "AWAITING_ARM";
      readonly discriminator: string;
      readonly operationState: "READY";
      readonly walletId: string;
    }
  | {
      readonly kind: "DEFERRED_202";
      readonly status: 202;
      readonly receiver_pubkey: null;
      readonly transfer_code: null;
      readonly code_status: "NOT_CREATED";
      readonly discriminator: string;
      readonly operationState: "CREATED";
    }
  | {
      readonly kind: "REJECT_503";
      readonly status: 503;
      readonly reason: "receive_queue_full";
      readonly receiver_pubkey: undefined;
      readonly transfer_code: undefined;
      // No operation row is created at capacity (the api-contract capacity rule).
      readonly operationCreated: false;
    };

export type ArmOutcome =
  | {
      readonly kind: "ARMED_200";
      readonly status: 200;
      readonly transfer_code: string;
      readonly code_status: "RELEASED";
    }
  | {
      readonly kind: "NOT_ARMABLE_409";
      readonly status: 409;
      readonly error: "operation_not_armable";
      readonly transfer_code: null;
      readonly walletRemainsPinned: true;
      readonly attentionRequired: true;
    }
  | {
      readonly kind: "EXPIRED_409";
      readonly status: 409;
      readonly error: "operation_not_armable";
      readonly transfer_code: null;
    };

export type TriggerOutcome =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly exception:
        | "CUSTODY_LEASE_ORIGIN_REJECTED"
        | "CUSTODY_LEASE_RECOVERY_UNVERIFIED"
        | "CUSTODY_LEASE_WALLET_STATE_REJECTED"
        | "CUSTODY_LEASE_DESTINATION_NOT_BLESSED"
        | "CUSTODY_LEASE_ROLE_UNKNOWN";
    };

export type ExpiryReleaseOutcome =
  | {
      readonly kind: "RELEASED";
      readonly release_status: "RELEASED_T0_UNCHANGED";
      readonly walletStateAfter: "AVAILABLE";
      readonly transfer_code_ever_released: false;
    }
  | {
      readonly kind: "HELD_ATTENTION";
      readonly attentionRequired: true;
      readonly walletStateAfter: "PINNED";
      readonly transfer_code_ever_released: false;
    };

/** The arm-time recheck — deliberately NOT the assignment predicate (wallet is PINNED by arm). */
export function passesArmRecheck(wallet: PoolWalletDescriptor): boolean {
  if (wallet.recoveryVerifiedAt === null) return false;
  return wallet.state === "AVAILABLE" || wallet.state === "PINNED";
}

/**
 * Structural BEFORE INSERT on wallet_active_leases (the receive-gate enforcement freeze). Pure
 * model of the frozen plpgsql branches — no DB. Origin conjunct is unconditional (the
 * imported-wallet cutover rule); RECONCILIATION early-returns
 * before any recovery test (G0); unknown role fails closed.
 */
export function evaluateLeaseInsert(
  role: string,
  wallet: PoolWalletDescriptor & { readonly destinationState?: ModeledWallet["destinationState"] },
): TriggerOutcome {
  if (wallet.keyOrigin !== "node_generated") {
    return { ok: false, exception: "CUSTODY_LEASE_ORIGIN_REJECTED" };
  }
  if (role === "RECONCILIATION") {
    return { ok: true };
  }
  if (role === "RECEIVE_WINDOW") {
    if (wallet.recoveryVerifiedAt === null) {
      return { ok: false, exception: "CUSTODY_LEASE_RECOVERY_UNVERIFIED" };
    }
    if (wallet.state !== "AVAILABLE") {
      return { ok: false, exception: "CUSTODY_LEASE_WALLET_STATE_REJECTED" };
    }
    return { ok: true };
  }
  if (role === "MOVE_DESTINATION") {
    if (wallet.destinationState !== "BLESSED") {
      return { ok: false, exception: "CUSTODY_LEASE_DESTINATION_NOT_BLESSED" };
    }
    if (wallet.recoveryVerifiedAt === null) {
      return { ok: false, exception: "CUSTODY_LEASE_RECOVERY_UNVERIFIED" };
    }
    if (wallet.state !== "AVAILABLE" && wallet.state !== "PINNED") {
      return { ok: false, exception: "CUSTODY_LEASE_WALLET_STATE_REJECTED" };
    }
    return { ok: true };
  }
  if (role === "MOVE_SOURCE" || role === "SEND_SOURCE") {
    return { ok: true };
  }
  return { ok: false, exception: "CUSTODY_LEASE_ROLE_UNKNOWN" };
}

/**
 * Automatic routing into a wallet (MOVE_INTERNAL / after_landing=INTERNAL_MOVE destination).
 * G2 = receive-eligibility PLUS BLESSED (the recovery-gate rule automatic-sink). A recovery-unverified sink is
 * never admitted — same prohibition disposition as HOLD assignment.
 */
export function isAutomaticSinkAdmissible(
  wallet: PoolWalletDescriptor & { readonly destinationState: ModeledWallet["destinationState"] },
): boolean {
  if (wallet.destinationState !== "BLESSED") return false;
  if (wallet.keyOrigin !== "node_generated") return false;
  if (wallet.recoveryVerifiedAt === null) return false;
  return wallet.state === "AVAILABLE" || wallet.state === "PINNED";
}

export type AssignContext = {
  readonly pool: readonly ModeledWallet[];
  readonly lockedIds: ReadonlySet<string>;
  /** When false, an empty eligible pool yields 503 (at cap). When true, yields 202 deferred. */
  readonly queueHasCapacity: boolean;
  readonly operationId: string;
};

/**
 * Synchronous HOLD receive assignment under the composed gate.
 * - Eligible wallet → 201 with receiver_pubkey set, transfer_code always null (AWAITING_ARM).
 * - No eligible wallet + queue capacity → 202 deferred: receiver_pubkey stays null.
 * - No eligible wallet + at cap → 503 receive_queue_full; no operation, no pubkey.
 *
 * An unverified wallet is never selected (isAvailableForReceive / SELECT_ASSIGNABLE_WALLET_SQL).
 */
export function assignHoldReceive(ctx: AssignContext): HoldAssignOutcome {
  const chosen = selectAssignableWallet(ctx.pool, ctx.lockedIds);
  if (chosen === null) {
    if (ctx.queueHasCapacity) {
      return {
        kind: "DEFERRED_202",
        status: 202,
        receiver_pubkey: null,
        transfer_code: null,
        code_status: "NOT_CREATED",
        discriminator: ctx.operationId,
        operationState: "CREATED",
      };
    }
    return {
      kind: "REJECT_503",
      status: 503,
      reason: "receive_queue_full",
      receiver_pubkey: undefined,
      transfer_code: undefined,
      operationCreated: false,
    };
  }
  // Defensive: the selector already requires receive-eligibility; never expose without it.
  if (!isAvailableForReceive(chosen)) {
    return {
      kind: "REJECT_503",
      status: 503,
      reason: "receive_queue_full",
      receiver_pubkey: undefined,
      transfer_code: undefined,
      operationCreated: false,
    };
  }
  const modeled = chosen as ModeledWallet;
  return {
    kind: "SYNC_201",
    status: 201,
    receiver_pubkey: modeled.publicKey,
    transfer_code: null,
    code_status: "AWAITING_ARM",
    discriminator: ctx.operationId,
    operationState: "READY",
    walletId: chosen.id,
  };
}

export type ArmContext = {
  readonly operationState: "CREATED" | "READY" | "EXPIRED";
  readonly expired: boolean;
  readonly leasedWallet: PoolWalletDescriptor;
  readonly transferCodeBytes: string;
};

/**
 * Arm barrier. Code bytes release ONLY after arm recheck passes inside the
 * operation-row lock. Failure returns 409 operation_not_armable and never a transfer_code.
 */
export function armReceive(ctx: ArmContext): ArmOutcome {
  if (ctx.operationState !== "READY" || ctx.expired) {
    return {
      kind: "EXPIRED_409",
      status: 409,
      error: "operation_not_armable",
      transfer_code: null,
    };
  }
  if (!passesArmRecheck(ctx.leasedWallet)) {
    return {
      kind: "NOT_ARMABLE_409",
      status: 409,
      error: "operation_not_armable",
      transfer_code: null,
      walletRemainsPinned: true,
      attentionRequired: true,
    };
  }
  return {
    kind: "ARMED_200",
    status: 200,
    transfer_code: ctx.transferCodeBytes,
    code_status: "RELEASED",
  };
}

/**
 * The five-predicate expired release (no inbound landed) for an unarmed receive.
 * Success releases the lease without ever having exposed transfer_code.
 */
export function releaseExpiredUnarmed(input: {
  readonly expiryPassed: boolean;
  readonly landedProofExists: boolean;
  readonly t0Unchanged: boolean;
  readonly observationAnomaly: boolean;
  readonly childSafeOrAbsent: boolean;
  readonly wasArmed: boolean;
}): ExpiryReleaseOutcome {
  // transfer_code is only released via arm; an unarmed path can never have exposed it.
  const neverReleased = input.wasArmed === false;
  const all =
    input.expiryPassed &&
    !input.landedProofExists &&
    input.t0Unchanged &&
    !input.observationAnomaly &&
    input.childSafeOrAbsent &&
    neverReleased;
  if (all) {
    return {
      kind: "RELEASED",
      release_status: "RELEASED_T0_UNCHANGED",
      walletStateAfter: "AVAILABLE",
      transfer_code_ever_released: false,
    };
  }
  return {
    kind: "HELD_ATTENTION",
    attentionRequired: true,
    walletStateAfter: "PINNED",
    transfer_code_ever_released: false,
  };
}

/**
 * Monotonic recovery stamp. Restore / rotation NEVER clear a stamp.
 * Returns the next recoveryVerifiedAt, or a rejection when a clear is attempted.
 */
export function applyRecoveryStampChange(
  current: string | null,
  next: string | null,
): { readonly ok: true; readonly recoveryVerifiedAt: string | null } | { readonly ok: false; readonly reason: "RECOVERY_STAMP_CLEAR_FORBIDDEN" } {
  if (current !== null && next === null) {
    return { ok: false, reason: "RECOVERY_STAMP_CLEAR_FORBIDDEN" };
  }
  // Stamping null→value or value→value (same or later ceremony) is permitted; clear is not.
  return { ok: true, recoveryVerifiedAt: next ?? current };
}

/**
 * Serialised interleaving harness: each step mutates a single shared store under exclusive
 * "lock" ordering. Used by the race suite so outcomes are deterministic and never rely on a
 * stale read winning (mirrors the count-under-lock and before-any-key-access guards).
 */
export type RaceStore = {
  wallets: Map<string, ModeledWallet>;
  lockedIds: Set<string>;
  /** operationId → arm-relevant snapshot */
  operations: Map<
    string,
    {
      state: "CREATED" | "READY" | "EXPIRED";
      expired: boolean;
      walletId: string | null;
      transferCodeBytes: string | null;
      codeReleased: boolean;
      receiver_pubkey: string | null;
    }
  >;
};

export function createRaceStore(wallets: readonly ModeledWallet[]): RaceStore {
  return {
    wallets: new Map(wallets.map((w) => [w.id, w])),
    lockedIds: new Set(),
    operations: new Map(),
  };
}

export type RaceStep =
  | { readonly op: "stamp_recovery"; readonly walletId: string; readonly at: string }
  | { readonly op: "clear_recovery"; readonly walletId: string }
  | { readonly op: "quarantine"; readonly walletId: string }
  | { readonly op: "restore_wallet"; readonly walletId: string; readonly keepStamp: boolean }
  | {
      readonly op: "assign_hold";
      readonly operationId: string;
      readonly queueHasCapacity: boolean;
    }
  | { readonly op: "arm"; readonly operationId: string }
  | { readonly op: "expire_unarmed"; readonly operationId: string; readonly allPredicatesPass: boolean };

export type RaceStepResult = {
  readonly step: RaceStep["op"];
  readonly detail: unknown;
  /** True iff any transfer_code bytes were released to a caller by this step. */
  readonly codeExposed: boolean;
  /** True iff a receiver_pubkey was newly bound to a synchronous 201 response. */
  readonly pubkeyExposedOn201: boolean;
};

export function runRaceStep(store: RaceStore, step: RaceStep): RaceStepResult {
  switch (step.op) {
    case "stamp_recovery": {
      const w = store.wallets.get(step.walletId);
      if (w === undefined) throw new Error(`unknown wallet ${step.walletId}`);
      const next = applyRecoveryStampChange(w.recoveryVerifiedAt, step.at);
      if (!next.ok) return { step: step.op, detail: next, codeExposed: false, pubkeyExposedOn201: false };
      store.wallets.set(step.walletId, { ...w, recoveryVerifiedAt: next.recoveryVerifiedAt });
      return { step: step.op, detail: next, codeExposed: false, pubkeyExposedOn201: false };
    }
    case "clear_recovery": {
      const w = store.wallets.get(step.walletId);
      if (w === undefined) throw new Error(`unknown wallet ${step.walletId}`);
      const next = applyRecoveryStampChange(w.recoveryVerifiedAt, null);
      // Clear is forbidden when stamped; store unchanged on reject.
      return { step: step.op, detail: next, codeExposed: false, pubkeyExposedOn201: false };
    }
    case "quarantine": {
      const w = store.wallets.get(step.walletId);
      if (w === undefined) throw new Error(`unknown wallet ${step.walletId}`);
      store.wallets.set(step.walletId, { ...w, state: "QUARANTINED" });
      return { step: step.op, detail: { state: "QUARANTINED" }, codeExposed: false, pubkeyExposedOn201: false };
    }
    case "restore_wallet": {
      // Restore re-adopts the wallet row. Stamp is monotonic: keepStamp preserves it; a restore
      // that "forgets" a stamp is modeled as a clear attempt and rejected.
      const w = store.wallets.get(step.walletId);
      if (w === undefined) throw new Error(`unknown wallet ${step.walletId}`);
      if (!step.keepStamp && w.recoveryVerifiedAt !== null) {
        const rejected = applyRecoveryStampChange(w.recoveryVerifiedAt, null);
        return { step: step.op, detail: rejected, codeExposed: false, pubkeyExposedOn201: false };
      }
      // Restored wallets re-enter AVAILABLE only if not quarantined/retired by the restore probe.
      store.wallets.set(step.walletId, { ...w, state: w.state === "RETIRED" ? "RETIRED" : "AVAILABLE" });
      return {
        step: step.op,
        detail: { recoveryVerifiedAt: w.recoveryVerifiedAt, state: store.wallets.get(step.walletId)?.state },
        codeExposed: false,
        pubkeyExposedOn201: false,
      };
    }
    case "assign_hold": {
      const pool = [...store.wallets.values()];
      const outcome = assignHoldReceive({
        pool,
        lockedIds: store.lockedIds,
        queueHasCapacity: step.queueHasCapacity,
        operationId: step.operationId,
      });
      if (outcome.kind === "SYNC_201") {
        const w = store.wallets.get(outcome.walletId);
        if (w === undefined) throw new Error("assigned missing wallet");
        // Lease insert under RECEIVE_WINDOW must also pass the structural guard (still AVAILABLE).
        const guard = evaluateLeaseInsert("RECEIVE_WINDOW", w);
        if (!guard.ok) {
          // Structural backstop: assignment that slipped the SELECT still cannot lease.
          return {
            step: step.op,
            detail: { assign: outcome, guard },
            codeExposed: false,
            pubkeyExposedOn201: false,
          };
        }
        store.lockedIds.add(outcome.walletId);
        store.wallets.set(outcome.walletId, { ...w, state: "PINNED" });
        store.operations.set(step.operationId, {
          state: "READY",
          expired: false,
          walletId: outcome.walletId,
          transferCodeBytes: "TRANSFER_CODE_BYTES_WITHHELD",
          codeReleased: false,
          receiver_pubkey: outcome.receiver_pubkey,
        });
        return {
          step: step.op,
          detail: outcome,
          codeExposed: false, // transfer_code remains null on 201
          pubkeyExposedOn201: true,
        };
      }
      if (outcome.kind === "DEFERRED_202") {
        store.operations.set(step.operationId, {
          state: "CREATED",
          expired: false,
          walletId: null,
          transferCodeBytes: null,
          codeReleased: false,
          receiver_pubkey: null,
        });
      }
      return {
        step: step.op,
        detail: outcome,
        codeExposed: false,
        pubkeyExposedOn201: false,
      };
    }
    case "arm": {
      const op = store.operations.get(step.operationId);
      if (op === undefined || op.walletId === null || op.transferCodeBytes === null) {
        return {
          step: step.op,
          detail: { error: "no_armable_operation" },
          codeExposed: false,
          pubkeyExposedOn201: false,
        };
      }
      const w = store.wallets.get(op.walletId);
      if (w === undefined) throw new Error("leased wallet missing");
      const outcome = armReceive({
        operationState: op.state,
        expired: op.expired,
        leasedWallet: w,
        transferCodeBytes: op.transferCodeBytes,
      });
      if (outcome.kind === "ARMED_200") {
        op.codeReleased = true;
        return {
          step: step.op,
          detail: outcome,
          codeExposed: true,
          pubkeyExposedOn201: false,
        };
      }
      return {
        step: step.op,
        detail: outcome,
        codeExposed: false,
        pubkeyExposedOn201: false,
      };
    }
    case "expire_unarmed": {
      const op = store.operations.get(step.operationId);
      if (op === undefined) {
        return {
          step: step.op,
          detail: { error: "no_operation" },
          codeExposed: false,
          pubkeyExposedOn201: false,
        };
      }
      op.expired = true;
      op.state = "EXPIRED";
      const release = releaseExpiredUnarmed({
        expiryPassed: true,
        landedProofExists: false,
        t0Unchanged: step.allPredicatesPass,
        observationAnomaly: !step.allPredicatesPass,
        childSafeOrAbsent: true,
        wasArmed: op.codeReleased,
      });
      if (release.kind === "RELEASED" && op.walletId !== null) {
        const w = store.wallets.get(op.walletId);
        if (w !== undefined) {
          store.wallets.set(op.walletId, { ...w, state: "AVAILABLE" });
          store.lockedIds.delete(op.walletId);
        }
      }
      return {
        step: step.op,
        detail: release,
        codeExposed: false,
        pubkeyExposedOn201: false,
      };
    }
  }
}

export function runRace(store: RaceStore, steps: readonly RaceStep[]): RaceStepResult[] {
  return steps.map((s) => runRaceStep(store, s));
}

/** True when any step in a race released transfer_code or bound a 201 pubkey for an unverified wallet. */
export function exposureInvariantHolds(
  results: readonly RaceStepResult[],
  store: RaceStore,
): { readonly holds: true } | { readonly holds: false; readonly reason: string } {
  for (const r of results) {
    if (r.codeExposed) {
      // Code may only be exposed when the leased wallet still passes arm recheck at arm time.
      // Find the arm detail.
      const detail = r.detail as ArmOutcome;
      if (detail.kind !== "ARMED_200") {
        return { holds: false, reason: "codeExposed without ARMED_200" };
      }
    }
    if (r.pubkeyExposedOn201) {
      const detail = r.detail as HoldAssignOutcome;
      if (detail.kind !== "SYNC_201") {
        return { holds: false, reason: "pubkeyExposed without SYNC_201" };
      }
      // The wallet that was exposed must have been receive-eligible at assign time — which the
      // model enforces; double-check the store's post-assign PINNED wallet still carries a stamp.
      const w = store.wallets.get(detail.walletId);
      if (w === undefined || w.recoveryVerifiedAt === null) {
        return { holds: false, reason: `201 exposed unverified wallet ${detail.walletId}` };
      }
    }
  }
  // No operation may hold a released code while its wallet is recovery-unverified.
  for (const [opId, op] of store.operations) {
    if (op.codeReleased && op.walletId !== null) {
      const w = store.wallets.get(op.walletId);
      if (w === undefined || w.recoveryVerifiedAt === null) {
        return { holds: false, reason: `op ${opId} released code on unverified wallet` };
      }
    }
  }
  return { holds: true };
}
