// semantic role projection for the observation ledger.
//
//
// This module is the observation-facing surface for role-relative state. The pure role
// table lives in protocol/wallet-role.ts; this slice reuses that implementation
// so role selection, S/P/B, and I cannot diverge between the verifier path and the ledger
// projection path. It additionally carries the signed material / need on a
// VERIFIED_HEAD row (both SplitChain signatures + exact inner preimage text).
//
// Role is decided only from the already-verified inner's public keys — never from
// caller-supplied "expected role" metadata. Genesis is never inferred from an
// empty-looking transaction; it is only produced by projectGenesisState, which callers
// may invoke only after classified authoritative genesis (chain-link equals prior settled step_2_signature account_not_found
// or virgin-wallet empty history status:true empty history []).

import type { WalletObservationRole } from "@zucoins/generic-node-contracts";

import {
  type SettledSplitChainTransaction,
  type SplitChainInnerV2,
} from "../protocol/inner.js";
import {
  GENESIS_PROJECTION,
  projectRoleRelativeState,
  type WalletStateProjection,
} from "../protocol/wallet-role.js";

// VERIFIED_HEAD observation projection: role-relative S/P/B/I plus the signed material
// that populates gateway_observations (CHECK for VERIFIED_HEAD).
export interface RoleStateProjection {
  readonly role: "sender" | "receiver";
  readonly S: string;
  readonly P: string;
  readonly B: string;
  /** SHA-256 hex of exact JSON.stringify(inner); never null on a real head. */
  readonly I: string;
  readonly step_1_signature: string;
  readonly step_2_signature: string;
  /** Byte-exact reconstructed JSON.stringify(inner) used for signatures and I. */
  readonly inner_preimage_text: string;
}

// VERIFIED_GENESIS observation projection (CHECK-D): fixed S/P/B, null signed
// material. Produced only by projectGenesisState — never by projectRoleState.
export interface GenesisStateProjection {
  readonly role: "genesis";
  readonly S: "";
  readonly P: "";
  readonly B: "0";
  readonly I: null;
  readonly step_1_signature: null;
  readonly step_2_signature: null;
  readonly inner_preimage_text: null;
}

export type ProjectRoleStateResult =
  | { readonly ok: true; readonly projection: RoleStateProjection }
  | {
      readonly ok: false;
      readonly reason: "wallet_role_invalid";
      readonly detail: string;
    };

// Reconstruct the exact inner preimage text, byte for byte: JSON.stringify
// directly on the insertion-sequenced object. Shared with digest path so I and
// the verifier's inner digest cannot drift when callers pass the same verified inner.
export function reconstructInnerPreimageText(inner: SplitChainInnerV2): string {
  return JSON.stringify(inner);
}

/**
 * Derive the queried wallet's role-relative state from a signature-verified transaction.
 *
 * Role predicate (normative):
 * sender iff inner.step_1_key_public__base64urlsafe == W
 * receiver iff inner.step_2_key_public__base64urlsafe == W
 * Exactly one must hold; both (self-transfer) or neither → wallet_role_invalid.
 *
 * S is always tx.step_2_signature in either valid role. Never produces genesis.
 */
export function projectRoleState(
  verifiedTx: SettledSplitChainTransaction,
  queriedWalletPubkey: string,
): ProjectRoleStateResult {
  const roleResult = projectRoleRelativeState(verifiedTx, queriedWalletPubkey);
  if (!roleResult.ok) {
    return {
      ok: false,
      reason: "wallet_role_invalid",
      detail: roleResult.detail,
    };
  }

  const { projection } = roleResult;
  // projectRoleRelativeState only returns sender/receiver on ok; genesis is a constant
  // and is never produced from a transaction object.
  if (projection.role === "genesis" || projection.I === null) {
    return {
      ok: false,
      reason: "wallet_role_invalid",
      detail: "transaction projection produced a non-head role",
    };
  }

  const inner_preimage_text = reconstructInnerPreimageText(verifiedTx.inner);
  return {
    ok: true,
    projection: {
      role: projection.role,
      S: projection.S,
      P: projection.P,
      B: projection.B,
      I: projection.I,
      step_1_signature: verifiedTx.step_1_signature,
      step_2_signature: verifiedTx.step_2_signature,
      inner_preimage_text,
    },
  };
}

/**
 * Authoritative genesis projection.
 *
 * Callers MUST only invoke this after classified the raw envelope as
 * authoritative genesis (`account_not_found` or status:true `data:[]`). Generic HTTP
 * 404s, timeouts, and malformed bodies are not genesis and must never reach this
 * function.
 */
export function projectGenesisState(): GenesisStateProjection {
  return {
    role: "genesis",
    S: GENESIS_PROJECTION.S as "",
    P: GENESIS_PROJECTION.P as "",
    B: GENESIS_PROJECTION.B as "0",
    I: null,
    step_1_signature: null,
    step_2_signature: null,
    inner_preimage_text: null,
  };
}

/**
 * RECEIVE_EXTERNAL inbound-link predicate: the candidate receiver's
 * previous link P1 must equal the baseline's current state signature S0 — never P0.
 *
 * using P0 as the expected inbound link is a named failure mode.
 */
export function inboundReceiverLinkMatchesBaselineS(
  candidateReceiverP: string,
  baselineS: string,
): boolean {
  return candidateReceiverP === baselineS;
}

/** Map a head projection onto the WalletStateProjection shape used by economic predicates. */
export function toWalletStateProjection(head: RoleStateProjection): WalletStateProjection {
  return {
    role: head.role,
    S: head.S,
    P: head.P,
    B: head.B,
    I: head.I,
  };
}

export type { WalletObservationRole, WalletStateProjection };
