// dual baseline capture for MOVE_INTERNAL admission.
// Lease and baseline acquisition.
//
// Requires: acquire both leases atomically by ascending UUID, OBSERVE both wallets while
// both leases remain held, require both observations verified and both balances unambiguous,
// require source B0 >= amount under exact decimal arithmetic. This module is the pure
// predicate half of that step; observation, the post-read destination recheck, and the durable
// artifact/evidence writes live in ../core/move-baseline-binding.ts.
//
// Shared parse/compare and lease-role magnitude live in baseline-validation.ts.

import { type WalletLease } from "@zucoins/generic-node-contracts/wallet-state";

import { parsePositiveZkzAmount, type PositiveZkzAmount } from "./amounts.js";
import {
  evaluateActiveLeaseRole,
  evaluatePositiveOperationAmount,
  evaluateSourceBalanceAgainstAmount,
} from "./baseline-validation.js";
import { type WalletStateProjection } from "./wallet-role.js";

export type DualBaselineRejectionReason =
  | "source_lease_not_active"
  | "destination_lease_not_active"
  | "source_lease_role_invalid"
  | "destination_lease_role_invalid"
  | "same_wallet"
  | "source_insufficient_balance"
  | "source_baseline_balance_invalid"
  | "invalid_amount";

export type DualBaselineCaptureResult =
  | { readonly ok: true; readonly capture: DualBaselineCapture }
  | { readonly ok: false; readonly reason: DualBaselineRejectionReason; readonly detail: string };

export interface DualBaselineCapture {
  readonly operationId: string;
  readonly sourceWalletPublicKey: string;
  readonly destinationWalletPublicKey: string;
  readonly sourceBaseline: WalletStateProjection;
  readonly destinationBaseline: WalletStateProjection;
  /** The canonical ZKZ amount contract operation amount, verbatim and branded. A node-authored amount is already
   * canonical shortest form, so the parser validates and brands but never rewrites — the
   * artifact is built from this exact text. */
  readonly amountZkz: PositiveZkzAmount;
  readonly capturedAt: number;
}

export interface DualBaselineInput {
  readonly operationId: string;
  readonly sourceWalletPublicKey: string;
  readonly destinationWalletPublicKey: string;
  readonly sourceLease: WalletLease;
  readonly destinationLease: WalletLease;
  readonly sourceBaseline: WalletStateProjection;
  readonly destinationBaseline: WalletStateProjection;
  readonly amountZkz: string;
  readonly capturedAt: number;
}

function reject(reason: DualBaselineRejectionReason, detail: string): DualBaselineCaptureResult {
  return { ok: false, reason, detail };
}

// Step 1 precondition, verified here rather than assumed: both leases must be ACTIVE AND
// carry this move's own role. Lifecycle alone is not enough — RECONCILIATION is observation-only
// and never pins a wallet (leases.ts), so an ACTIVE RECONCILIATION pair would let a move
// reach formation with no wallet pinned, defeating the one-in-flight-per-wallet rule. MOVE_SOURCE and MOVE_DESTINATION
// are both pinning operation roles (asserted against isOperationRole in this module's tests).
function checkLeases(input: DualBaselineInput): DualBaselineCaptureResult | null {
  const source = evaluateActiveLeaseRole(input.sourceLease, "MOVE_SOURCE", "source");
  if (!source.ok) {
    return reject(
      source.kind === "not_active" ? "source_lease_not_active" : "source_lease_role_invalid",
      source.detail,
    );
  }
  const destination = evaluateActiveLeaseRole(
    input.destinationLease,
    "MOVE_DESTINATION",
    "destination",
  );
  if (!destination.ok) {
    return reject(
      destination.kind === "not_active"
        ? "destination_lease_not_active"
        : "destination_lease_role_invalid",
      destination.detail,
    );
  }
  return null;
}

// Source and destination must be different wallets — a self-move is not representable
// in the SplitChain two-party model (sender != receiver by construction).
function checkDistinctWallets(input: DualBaselineInput): DualBaselineCaptureResult | null {
  if (input.sourceWalletPublicKey === input.destinationWalletPublicKey) {
    return reject("same_wallet", "source and destination public keys are identical");
  }
  return null;
}

// Step 3: "Require source B0 >= amount under exact decimal arithmetic."
// Shared with SEND via evaluateSourceBalanceAgainstAmount (foreign-observed path).
function checkSourceBalance(input: DualBaselineInput): DualBaselineCaptureResult | null {
  const result = evaluateSourceBalanceAgainstAmount(
    input.sourceBaseline.B,
    input.amountZkz,
    "move",
  );
  if (!result.ok) return reject(result.reason, result.detail);
  return null;
}

// The amount is a node-authored operation amount, so it is held to the frozen canonical ZKZ amount contract:
// bounded < 10^8, at most 32 fractional digits, and numerically positive. A hand-rolled decimal
// regex is strictly weaker — "0", "0.0" and "0." + 32 zeros all satisfy one while being
// mathematically zero, which is the canonical ZKZ amount contract clause-1 zero-form defect.
function checkAmountStructure(input: DualBaselineInput): DualBaselineCaptureResult | null {
  const amount = evaluatePositiveOperationAmount(input.amountZkz);
  if (!amount.ok) return reject("invalid_amount", amount.detail);
  return null;
}

export function captureDualBaselines(input: DualBaselineInput): DualBaselineCaptureResult {
  // Step 3 states only: both observations verified, both balances unambiguous, and
  // source B0 >= amount. Projection role is not a condition — S is role-independent, and
  // constructMoveInner consumes only S/B (role selects GENESIS vs HEAD only). Symmetric with
  // SEND_EXTERNAL step 5.
  const checks = [
    checkLeases,
    checkDistinctWallets,
    checkAmountStructure,
    checkSourceBalance,
  ];
  for (const check of checks) {
    const failure = check(input);
    if (failure !== null) return failure;
  }

  const capture: DualBaselineCapture = {
    operationId: input.operationId,
    sourceWalletPublicKey: input.sourceWalletPublicKey,
    destinationWalletPublicKey: input.destinationWalletPublicKey,
    sourceBaseline: input.sourceBaseline,
    destinationBaseline: input.destinationBaseline,
    amountZkz: parsePositiveZkzAmount(input.amountZkz),
    capturedAt: input.capturedAt,
  };

  return { ok: true, capture };
}
