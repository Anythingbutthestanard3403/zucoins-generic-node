// Shared pure predicates for MOVE_INTERNAL / SEND_EXTERNAL baseline formation.
// Canonical rules: absolute post-transfer balances; the canonical ZKZ amount contract.
//
// MOVE and SEND adapters keep their own result types, rejection codes, and message wording;
// they map these predicates rather than re-implement parse/re-emit/compare or lease-role checks.

import { compareAmounts } from "@zucoins/generic-node-contracts";
import {
  isLeaseActive,
  type LeaseRole,
  type WalletLease,
} from "@zucoins/generic-node-contracts/wallet-state";

import {
  parseObservedZkzBalance,
  parsePositiveZkzAmount,
  reemitObservedZkzCanonical,
} from "./amounts.js";

/** Operation noun embedded only in the insufficient-balance detail string. */
export type BaselineOperationNoun = "move" | "send";

export type SourceBalancePredicateReason =
  | "source_baseline_balance_invalid"
  | "source_insufficient_balance";

export type SourceBalancePredicateResult =
  | { readonly ok: true; readonly balanceCanonical: string }
  | {
      readonly ok: false;
      readonly reason: SourceBalancePredicateReason;
      readonly detail: string;
    };

/**
 * Foreign-observed B0 ≥ amount under exact decimal arithmetic (absolute post-transfer balances; canonical ZKZ amount contract).
 * B0 is judged by the structural grammar and re-emitted canonically before compareAmounts;
 * never Number/parseFloat. `operationNoun` only fills the insufficient-balance detail.
 */
export function evaluateSourceBalanceAgainstAmount(
  observedBalanceB: string,
  amountZkz: string,
  operationNoun: BaselineOperationNoun,
): SourceBalancePredicateResult {
  let balance: string;
  try {
    balance = reemitObservedZkzCanonical(parseObservedZkzBalance(observedBalanceB));
  } catch {
    return {
      ok: false,
      reason: "source_baseline_balance_invalid",
      detail: `source baseline balance "${observedBalanceB}" is not a grammar-valid ZKZ amount`,
    };
  }
  if (compareAmounts(balance, amountZkz) < 0) {
    return {
      ok: false,
      reason: "source_insufficient_balance",
      detail: `source balance ${balance} is less than ${operationNoun} amount ${amountZkz}`,
    };
  }
  return { ok: true, balanceCanonical: balance };
}

export type PositiveAmountPredicateResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly detail: string };

/**
 * Node-authored operation amount held to canonical ZKZ amount contract (bounded, ≤32 dp, numerically positive).
 * Detail wording is shared byte-identical by MOVE and SEND adapters.
 */
export function evaluatePositiveOperationAmount(
  amountZkz: unknown,
): PositiveAmountPredicateResult {
  try {
    parsePositiveZkzAmount(amountZkz);
  } catch {
    return {
      ok: false,
      detail:
        typeof amountZkz === "string"
          ? `amount_zkz "${amountZkz}" is not a canonical positive ZKZ amount`
          : `amount_zkz is ${typeof amountZkz}, expected a canonical positive ZKZ amount string`,
    };
  }
  return { ok: true };
}

export type LeaseRoleSide = "source" | "destination";

export type ActiveLeaseRolePredicateResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly kind: "not_active" | "role_invalid";
      readonly detail: string;
    };

/**
 * ACTIVE lifecycle + expected operation lease role for a baseline side.
 * Side labels detail messages so MOVE source/destination and SEND source share one path.
 */
export function evaluateActiveLeaseRole(
  lease: WalletLease,
  expectedRole: LeaseRole,
  side: LeaseRoleSide,
): ActiveLeaseRolePredicateResult {
  if (!isLeaseActive(lease)) {
    return {
      ok: false,
      kind: "not_active",
      detail: `${side} lease lifecycle is ${lease.lifecycle}, expected ACTIVE`,
    };
  }
  if (lease.role !== expectedRole) {
    return {
      ok: false,
      kind: "role_invalid",
      detail: `${side} lease role is ${lease.role}, expected ${expectedRole}`,
    };
  }
  return { ok: true };
}
