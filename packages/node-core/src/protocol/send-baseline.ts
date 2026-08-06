// pure predicates for SEND_EXTERNAL lease + two-party baseline formation
// (steps 1–5). (exact partial only).
//
// Step 5: "Require both observations verified, source balance sufficient, and
// source/destination keys different." Observation verification itself is the observation
// service's job; this module judges the VERIFIED projections the service returned
// and the source lease the formation worker already holds. Sign-intent construction and
// signing live in — nothing here builds an inner or touches a private key.
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

export type SendBaselineRejectionReason =
  | "source_lease_not_active"
  | "source_lease_role_invalid"
  | "same_wallet"
  | "source_insufficient_balance"
  | "source_baseline_balance_invalid"
  | "invalid_amount";

export type SendBaselineCaptureResult =
  | { readonly ok: true; readonly capture: SendBaselineCapture }
  | { readonly ok: false; readonly reason: SendBaselineRejectionReason; readonly detail: string };

export interface SendBaselineCapture {
  readonly operationId: string;
  readonly sourceWalletPublicKey: string;
  /** External destination address — a public key, never a node wallet_id. */
  readonly destinationAddress: string;
  readonly sourceBaseline: WalletStateProjection;
  readonly destinationBaseline: WalletStateProjection;
  /** operation amount, verbatim and branded. */
  readonly amountZkz: PositiveZkzAmount;
  readonly capturedAt: number;
}

export interface SendBaselineInput {
  readonly operationId: string;
  readonly sourceWalletPublicKey: string;
  readonly destinationAddress: string;
  readonly sourceLease: WalletLease;
  readonly sourceBaseline: WalletStateProjection;
  readonly destinationBaseline: WalletStateProjection;
  readonly amountZkz: string;
  readonly capturedAt: number;
}

function reject(reason: SendBaselineRejectionReason, detail: string): SendBaselineCaptureResult {
  return { ok: false, reason, detail };
}

// Step 2 precondition: the source lease must be ACTIVE and carry SEND_SOURCE.
// RECONCILIATION is observation-only and never pins (recovery_verified_at gate); an ACTIVE RECONCILIATION
// lease must not authorize formation.
function checkSourceLease(input: SendBaselineInput): SendBaselineCaptureResult | null {
  const source = evaluateActiveLeaseRole(input.sourceLease, "SEND_SOURCE", "source");
  if (!source.ok) {
    return reject(
      source.kind === "not_active" ? "source_lease_not_active" : "source_lease_role_invalid",
      source.detail,
    );
  }
  return null;
}

// Step 5: source and destination keys must differ — a self-send is not representable
// in the SplitChain two-party model.
function checkDistinctKeys(input: SendBaselineInput): SendBaselineCaptureResult | null {
  if (input.sourceWalletPublicKey === input.destinationAddress) {
    return reject("same_wallet", "source and destination public keys are identical");
  }
  return null;
}

// Step 5: source B0 >= amount under exact decimal arithmetic. Shared with MOVE via
// evaluateSourceBalanceAgainstAmount (foreign-observed path).
function checkSourceBalance(input: SendBaselineInput): SendBaselineCaptureResult | null {
  const result = evaluateSourceBalanceAgainstAmount(
    input.sourceBaseline.B,
    input.amountZkz,
    "send",
  );
  if (!result.ok) return reject(result.reason, result.detail);
  return null;
}

function checkAmountStructure(input: SendBaselineInput): SendBaselineCaptureResult | null {
  const amount = evaluatePositiveOperationAmount(input.amountZkz);
  if (!amount.ok) return reject("invalid_amount", amount.detail);
  return null;
}

/**
 * Step 5 pure half. Caller must already hold the source SEND_SOURCE lease and have
 * two VERIFIED observation projections (INDETERMINATE/UNVERIFIED are rejected upstream so
 * they cannot be smuggled in as genesis).
 */
export function captureSendBaselines(input: SendBaselineInput): SendBaselineCaptureResult {
  // Step 5 states only: both observations verified, source balance sufficient, and
  // source/destination keys different. Projection role is not a condition — S is role-
  // independent (wallet-role projectRoleRelativeState), and constructSendInner consumes only
  // S/B (role selects GENESIS vs HEAD only). A wallet whose most recent settled hop was incoming projects
  // receiver and must still form SEND_EXTERNAL.
  const checks = [
    checkSourceLease,
    checkDistinctKeys,
    checkAmountStructure,
    checkSourceBalance,
  ];
  for (const check of checks) {
    const failure = check(input);
    if (failure !== null) return failure;
  }

  return {
    ok: true,
    capture: {
      operationId: input.operationId,
      sourceWalletPublicKey: input.sourceWalletPublicKey,
      destinationAddress: input.destinationAddress,
      sourceBaseline: input.sourceBaseline,
      destinationBaseline: input.destinationBaseline,
      amountZkz: parsePositiveZkzAmount(input.amountZkz),
      capturedAt: input.capturedAt,
    },
  };
}
