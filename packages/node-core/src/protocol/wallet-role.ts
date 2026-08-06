// role-relative wallet projection.
//
// Role-relative wallet state.
//
// Derives S, P, B, and the inner digest I for a wallet's role (sender or receiver) in one
// already-verified settled transaction, or models genesis when no prior transaction exists.
// Exactly one of "sender"/"receiver" must hold for a real transaction; self-transfer and a
// wallet absent from both positions are rejected. This module performs no
// signature or envelope verification — that is concern; it assumes the transaction
// object it is given has already passed that pipeline.
import { WALLET_OBSERVATION_ROLES, type WalletObservationRole } from "@zucoins/generic-node-contracts";

import { computeInnerDigest, type SettledSplitChainTransaction } from "./inner.js";

// The role-relative projection of one wallet against one accepted state.
// `I` is null only at genesis; every real transaction has a computable inner digest.
export interface WalletStateProjection {
  readonly role: WalletObservationRole;
  readonly S: string;
  readonly P: string;
  readonly B: string;
  readonly I: string | null;
}

// "Genesis is S="", P="", B="0", I=null." There is no transaction object for
// genesis — a wallet with no prior settled transaction has this projection by definition,
// never derived from a `SettledSplitChainTransaction`.
export const GENESIS_PROJECTION: WalletStateProjection = {
  role: "genesis",
  S: "",
  P: "",
  B: "0",
  I: null,
};

export type WalletRoleRejectionReason = "wallet_role_invalid";

export type WalletRoleProjectionResult =
  | { readonly ok: true; readonly projection: WalletStateProjection }
  | { readonly ok: false; readonly reason: WalletRoleRejectionReason; readonly detail: string };

// Role predicate: exactly one of sender/receiver must match the queried key.
// Both matching (self-transfer) or neither matching are both WALLET_ROLE_INVALID — v2 never
// distinguishes those two failure shapes because role-relative state would be ambiguous or
// undefined either way.
function determineRole(
  inner: SettledSplitChainTransaction["inner"],
  walletPublicKey: string,
): "sender" | "receiver" | null {
  const isSender = inner.step_1_key_public__base64urlsafe === walletPublicKey;
  const isReceiver = inner.step_2_key_public__base64urlsafe === walletPublicKey;
  if (isSender === isReceiver) return null; // both or neither
  return isSender ? "sender" : "receiver";
}

// Table: S is `T.step_2_signature` in either role. P and B are role-relative fields
// pulled from `inner`. Never hard-code the receiver's `previous_step_2_state_signature` for
// a sender-side observation, or vice versa (closing note) — the branch below is the
// single place that distinction is made.
export function projectRoleRelativeState(
  tx: SettledSplitChainTransaction,
  walletPublicKey: string,
): WalletRoleProjectionResult {
  const role = determineRole(tx.inner, walletPublicKey);
  if (role === null) {
    return {
      ok: false,
      reason: "wallet_role_invalid",
      detail: "queried wallet is neither or both of the transaction's step_1/step_2 keys",
    };
  }

  const projection: WalletStateProjection =
    role === "sender"
      ? {
          role: "sender",
          S: tx.step_2_signature,
          P: tx.inner.previous_step_1_state_signature,
          B: tx.inner.step_1_state.amount,
          I: computeInnerDigest(tx.inner),
        }
      : {
          role: "receiver",
          S: tx.step_2_signature,
          P: tx.inner.previous_step_2_state_signature,
          B: tx.inner.step_2_state.amount,
          I: computeInnerDigest(tx.inner),
        };

  return { ok: true, projection };
}

// Defensive re-export so callers never need to hand-roll the frozen role vocabulary check
// alongside this module's own results.
export const isWalletObservationRole = (value: string): value is WalletObservationRole =>
  (WALLET_OBSERVATION_ROLES as readonly string[]).includes(value);
