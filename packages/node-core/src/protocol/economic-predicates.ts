// operation economic predicates.
//
// Economic delta rules for the chain-observable half of receive/move/send verification;
// the artifact-signature half is a separate concern.
//
// Assumed-prior step (precondition): candidate intake rejects any candidate
// transaction whose keys, states, links, optionals, and amounts do not pass STRICT SCALAR
// VALIDATION before signature verification — so every candidate `B` reaching this module is
// already a grammar-valid non-negative balance scalar. (the byte-exact signing rule) the
// foreign-signed step amounts are held to the grammar ALONE, so a legitimately non-canonical
// observed spelling such as "2.50" is admitted, not re-canonicalized. This module does not rely
// on that alone: `checkExactDelta` re-validates BOTH delta operands by the grammar alone
// (defense-in-depth), because the caller-supplied `baseline.B` does not traverse the candidate
// path, and a future composition must not be able to smuggle a signed balance scalar past
// this predicate.
//
// `T1`/`source_1`/`destination_1` below always mean the caller-supplied EXPECTED operation
// transaction body (preamble) — this module never substitutes a cached balance or a
// later fresh head for it, and never re-derives a baseline from anything but the caller's
// own `baseline` projection. That is the "no cached-balance fallback or P0/S0 substitution"
// exit criterion: every predicate below is a pure function of its exact inputs.
import {
  compareAmounts,
  inspectForeignAmount,
  subtractAmounts,
  validateOperationAmount,
} from "@zucoins/generic-node-contracts";

import { type SettledSplitChainTransaction } from "./inner.js";
import { projectRoleRelativeState, type WalletStateProjection } from "./wallet-role.js";

export type DeltaRejectionReason =
  | "invalid_operation_amount"
  | "invalid_balance_scalar"
  | "wallet_role_invalid"
  | "chain_link_mismatch"
  | "balance_delta_mismatch"
  | "artifact_binding_mismatch"
  | "same_transaction_mismatch"
  | "spawn_continuity_mismatch";

export type DeltaEvaluation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: DeltaRejectionReason; readonly detail: string };

function reject(reason: DeltaRejectionReason, detail: string): DeltaEvaluation {
  return { ok: false, reason, detail };
}

const OK: DeltaEvaluation = { ok: true };

function checkOperationAmount(amountZkz: string): DeltaEvaluation {
  const check = validateOperationAmount(amountZkz);
  if (!check.ok) {
    return reject("invalid_operation_amount", `operation.amount_zkz failed validation: ${check.reason}`);
  }
  return OK;
}

// Exact decimal equality: `subtractAmounts` never rounds (32dp, ROUND_DOWN only where the
// protocol requires it) and `compareAmounts` is the frozen numeric predicate — never a
// string comparison, so "2.50" vs "2.5" style formatting differences cannot hide a mismatch.
function checkExactDelta(
  minuend: string,
  subtrahend: string,
  expected: string,
  detail: string,
): DeltaEvaluation {
  // Defense-in-depth (see header precondition): a delta over unvalidated balance scalars can
  // approve an overspend, e.g. subtractAmounts("3", "-1") == "4" would satisfy a 4-ZKZ debit
  // from a 3-ZKZ balance. Re-validate BOTH operands by the foreign-signed GRAMMAR alone
  // (the byte-exact signing rule): the grammar guarantees a finite non-negative
  // decimal in 0 <= v < 1e8 with <=32 dp ("0" allowed for genesis/swept wallets) and rejects
  // sign/exponent/out-of-range forms, while a legitimately non-canonical OBSERVED spelling such
  // as "2.50" is admitted. Both operands are observed balances (a baseline.B projection and a
  // candidate post-state), never node-authored amounts, so canonical emit equality must not be
  // applied here — that false reject is the latent stuck-settlement gap closes.
  const minuendCheck = inspectForeignAmount(minuend);
  if (!minuendCheck.wellFormed) {
    return reject("invalid_balance_scalar", `${detail}: minuend ${minuend} failed validation: ${minuendCheck.anomaly}`);
  }
  const subtrahendCheck = inspectForeignAmount(subtrahend);
  if (!subtrahendCheck.wellFormed) {
    return reject(
      "invalid_balance_scalar",
      `${detail}: subtrahend ${subtrahend} failed validation: ${subtrahendCheck.anomaly}`,
    );
  }
  const delta = subtractAmounts(minuend, subtrahend);
  if (compareAmounts(delta, expected) !== 0) {
    return reject("balance_delta_mismatch", `${detail}: expected ${expected}, computed ${delta}`);
  }
  return OK;
}

// `RECEIVE_EXTERNAL` — the reserved wallet is the receiver.
export interface ReceiveDeltaInput {
  readonly baseline: WalletStateProjection; // T0 (genesis or a prior receiver/sender projection's S/B)
  readonly candidateTx: SettledSplitChainTransaction; // T1, the expected inbound transaction body
  readonly reservedWalletPublicKey: string;
  readonly operation: { readonly amountZkz: string; readonly receiverPubkey: string };
}

export function evaluateReceiveDelta(input: ReceiveDeltaInput): DeltaEvaluation {
  const amountCheck = checkOperationAmount(input.operation.amountZkz);
  if (!amountCheck.ok) return amountCheck;

  const projected = projectRoleRelativeState(input.candidateTx, input.reservedWalletPublicKey);
  if (!projected.ok) return reject(projected.reason, projected.detail);
  if (projected.projection.role !== "receiver") {
    return reject(
      "wallet_role_invalid",
      `reserved wallet must be step-2 receiver in the candidate transaction, was ${projected.projection.role}`,
    );
  }
  const candidate = projected.projection;

  if (candidate.P !== input.baseline.S) {
    return reject(
      "chain_link_mismatch",
      `candidate P (${candidate.P}) does not equal baseline S (${input.baseline.S})`,
    );
  }

  const deltaCheck = checkExactDelta(candidate.B, input.baseline.B, input.operation.amountZkz, "B1-B0");
  if (!deltaCheck.ok) return deltaCheck;

  if (input.candidateTx.inner.step_2_key_public__base64urlsafe !== input.operation.receiverPubkey) {
    return reject(
      "artifact_binding_mismatch",
      "candidate transaction step_2 key does not equal operation.receiver_pubkey",
    );
  }

  return OK;
}

// `MOVE_INTERNAL` — one dual-signed transaction; independent baselines for
// both leased wallets, checked against the SAME transaction.
export interface MoveLegInput {
  readonly baseline: WalletStateProjection;
  readonly candidateTx: SettledSplitChainTransaction;
  readonly walletPublicKey: string;
}

export interface MoveDeltaInput {
  readonly source: MoveLegInput;
  readonly destination: MoveLegInput;
  readonly operation: {
    readonly amountZkz: string;
    readonly sourcePubkey: string;
    readonly destinationPubkey: string;
  };
  // "If spawned by a receive, the stronger one-hop continuity predicate also holds."
  // Omitted for an ordinary (non-spawned) move.
  readonly spawnedFromReceive?: { readonly receiveTransactionStepTwoSignature: string };
}

export function evaluateInternalMoveDelta(input: MoveDeltaInput): DeltaEvaluation {
  const amountCheck = checkOperationAmount(input.operation.amountZkz);
  if (!amountCheck.ok) return amountCheck;

  const sourceProjected = projectRoleRelativeState(input.source.candidateTx, input.source.walletPublicKey);
  if (!sourceProjected.ok) return reject(sourceProjected.reason, `source: ${sourceProjected.detail}`);
  if (sourceProjected.projection.role !== "sender") {
    return reject(
      "wallet_role_invalid",
      `source wallet must be step-1 sender in the candidate transaction, was ${sourceProjected.projection.role}`,
    );
  }

  const destinationProjected = projectRoleRelativeState(
    input.destination.candidateTx,
    input.destination.walletPublicKey,
  );
  if (!destinationProjected.ok) {
    return reject(destinationProjected.reason, `destination: ${destinationProjected.detail}`);
  }
  if (destinationProjected.projection.role !== "receiver") {
    return reject(
      "wallet_role_invalid",
      `destination wallet must be step-2 receiver in the candidate transaction, was ${destinationProjected.projection.role}`,
    );
  }

  const sourceCandidate = sourceProjected.projection;
  const destinationCandidate = destinationProjected.projection;

  // "same tx": both independently-leased wallets must be observed in the one dual-signed
  // transaction — this is the dual-wallet equality predicate.
  if (input.source.candidateTx.step_2_signature !== input.destination.candidateTx.step_2_signature) {
    return reject(
      "same_transaction_mismatch",
      "source and destination candidate transactions do not share one step_2_signature",
    );
  }

  if (sourceCandidate.P !== input.source.baseline.S) {
    return reject(
      "chain_link_mismatch",
      `source candidate P (${sourceCandidate.P}) does not equal source baseline S (${input.source.baseline.S})`,
    );
  }
  if (destinationCandidate.P !== input.destination.baseline.S) {
    return reject(
      "chain_link_mismatch",
      `destination candidate P (${destinationCandidate.P}) does not equal destination baseline S (${input.destination.baseline.S})`,
    );
  }

  const sourceDeltaCheck = checkExactDelta(
    input.source.baseline.B,
    sourceCandidate.B,
    input.operation.amountZkz,
    "source B0-B1",
  );
  if (!sourceDeltaCheck.ok) return sourceDeltaCheck;

  const destinationDeltaCheck = checkExactDelta(
    destinationCandidate.B,
    input.destination.baseline.B,
    input.operation.amountZkz,
    "destination B1-B0",
  );
  if (!destinationDeltaCheck.ok) return destinationDeltaCheck;

  if (input.source.candidateTx.inner.step_1_key_public__base64urlsafe !== input.operation.sourcePubkey) {
    return reject("artifact_binding_mismatch", "source candidate transaction step_1 key does not equal operation.sourcePubkey");
  }
  if (
    input.destination.candidateTx.inner.step_2_key_public__base64urlsafe !==
    input.operation.destinationPubkey
  ) {
    return reject(
      "artifact_binding_mismatch",
      "destination candidate transaction step_2 key does not equal operation.destinationPubkey",
    );
  }

  if (input.spawnedFromReceive) {
    if (
      input.source.candidateTx.inner.previous_step_1_state_signature !==
      input.spawnedFromReceive.receiveTransactionStepTwoSignature
    ) {
      return reject(
        "spawn_continuity_mismatch",
        "spawned move's previous_step_1_state_signature does not equal the parent receive's step_2_signature",
      );
    }
  }

  return OK;
}

// `SEND_EXTERNAL` — the node-controlled source is step-1 sender.
export interface SendDeltaInput {
  readonly baseline: WalletStateProjection; // Ts0
  readonly candidateTx: SettledSplitChainTransaction; // E
  readonly sourceWalletPublicKey: string;
  readonly operation: {
    readonly amountZkz: string;
    readonly sourcePubkey: string;
    readonly destinationAddress: string;
  };
}

export function evaluateExternalSendDelta(input: SendDeltaInput): DeltaEvaluation {
  const amountCheck = checkOperationAmount(input.operation.amountZkz);
  if (!amountCheck.ok) return amountCheck;

  const projected = projectRoleRelativeState(input.candidateTx, input.sourceWalletPublicKey);
  if (!projected.ok) return reject(projected.reason, projected.detail);
  if (projected.projection.role !== "sender") {
    return reject(
      "wallet_role_invalid",
      `source wallet must be step-1 sender in the candidate transaction, was ${projected.projection.role}`,
    );
  }
  const candidate = projected.projection;

  if (candidate.P !== input.baseline.S) {
    return reject(
      "chain_link_mismatch",
      `candidate P (${candidate.P}) does not equal baseline S (${input.baseline.S})`,
    );
  }

  const deltaCheck = checkExactDelta(input.baseline.B, candidate.B, input.operation.amountZkz, "B0-B1");
  if (!deltaCheck.ok) return deltaCheck;

  if (input.candidateTx.inner.step_1_key_public__base64urlsafe !== input.operation.sourcePubkey) {
    return reject("artifact_binding_mismatch", "candidate transaction step_1 key does not equal operation.sourcePubkey");
  }
  if (input.candidateTx.inner.step_2_key_public__base64urlsafe !== input.operation.destinationAddress) {
    return reject(
      "artifact_binding_mismatch",
      "candidate transaction step_2 key does not equal operation.destinationAddress",
    );
  }

  return OK;
}
