// canonical `zp-wallet-head-fingerprint-v1` constructor.
//
//
// Serializes a role-relative projection into the exact 10-field observer-independent
// tuple, then SHA-256s the suite-canonical preimage. Unsigned — never routes through a
// signing call. Transport fields (endpoint, HTTP status, observed_at, raw hash) are
// excluded by construction so node and platform can compare semantic state independently.
// Fingerprint equality never suppresses raw-evidence appending.
//
// Foreign-B policy: `b_amount` is bound via suite encodeZkzBalance →
// parseObservedZkzBalance (grammar-only, verbatim). The write path
// (`verifySettledTransaction` → computeWalletHeadFingerprint) uses the same suite
// constructor, so non-canonical legal heads (e.g. "2.50") round-trip verify→retain→
// re-read without false FINGERPRINT_DRIFT.

import {
  buildWalletHeadFingerprint,
  type WalletHeadFingerprintInput,
} from "../protocol/suite/builders.js";
import type { GenesisStateProjection, RoleStateProjection } from "./projection.js";

export const WALLET_HEAD_FINGERPRINT_PURPOSE = "zp-wallet-head-fingerprint-v1" as const;

/** A.7 payload field sequence — exhaustive and exact. */
export const WALLET_HEAD_FINGERPRINT_FIELDS = [
  "purpose",
  "canonical_version",
  "wallet_public_key",
  "state_kind",
  "s_signature",
  "p_signature",
  "b_amount",
  "inner_sha256",
  "step_1_signature",
  "step_2_signature",
] as const;

export type WalletHeadStateKind = "GENESIS" | "HEAD";

export interface WalletHeadFingerprintResult {
  readonly purpose: typeof WALLET_HEAD_FINGERPRINT_PURPOSE;
  readonly stateKind: WalletHeadStateKind;
  readonly preimageText: string;
  readonly sha256: string;
}

export type FingerprintBuildRejection =
  | { readonly ok: false; readonly reason: "UNVERIFIED_PROJECTION"; readonly detail: string }
  | { readonly ok: false; readonly reason: "INVALID_WALLET_KEY"; readonly detail: string };

export type FingerprintBuildResult =
  | { readonly ok: true; readonly fingerprint: WalletHeadFingerprintResult }
  | FingerprintBuildRejection;

/**
 * Build the A.7 fingerprint from a HEAD role projection. Call only after.3
 * pass — fingerprints arise only from verified state.
 */
export function buildWalletHeadFingerprintFromProjection(
  projection: RoleStateProjection,
  walletPublicKey: string,
): FingerprintBuildResult {
  if (typeof walletPublicKey !== "string" || walletPublicKey.length === 0) {
    return { ok: false, reason: "INVALID_WALLET_KEY", detail: "empty wallet_public_key" };
  }
  if (projection.I === null || projection.I.length === 0) {
    return {
      ok: false,
      reason: "UNVERIFIED_PROJECTION",
      detail: "HEAD projection requires a non-null inner digest",
    };
  }

  const input = asFingerprintInput({
    wallet_public_key: walletPublicKey,
    state_kind: "HEAD",
    s_signature: projection.S,
    p_signature: projection.P,
    b_amount: projection.B,
    inner_sha256: projection.I,
    step_1_signature: projection.step_1_signature,
    step_2_signature: projection.step_2_signature,
  });

  try {
    const built = buildWalletHeadFingerprint(input);
    return {
      ok: true,
      fingerprint: {
        purpose: WALLET_HEAD_FINGERPRINT_PURPOSE,
        stateKind: "HEAD",
        preimageText: built.preimageText,
        sha256: built.sha256,
      },
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "suite serialize rejected";
    return { ok: false, reason: "UNVERIFIED_PROJECTION", detail };
  }
}

/** Genesis fingerprint: empty signatures, B="0", null inner/step signatures. */
export function buildGenesisWalletHeadFingerprint(
  walletPublicKey: string,
  genesis: GenesisStateProjection = {
    role: "genesis",
    S: "",
    P: "",
    B: "0",
    I: null,
    inner_preimage_text: null,
    step_1_signature: null,
    step_2_signature: null,
  },
): FingerprintBuildResult {
  if (typeof walletPublicKey !== "string" || walletPublicKey.length === 0) {
    return { ok: false, reason: "INVALID_WALLET_KEY", detail: "empty wallet_public_key" };
  }
  if (
    genesis.role !== "genesis" ||
    genesis.S !== "" ||
    genesis.P !== "" ||
    genesis.B !== "0" ||
    genesis.I !== null
  ) {
    return {
      ok: false,
      reason: "UNVERIFIED_PROJECTION",
      detail: "genesis fingerprint requires S=\"\", P=\"\", B=\"0\", I=null",
    };
  }

  const input = asFingerprintInput({
    wallet_public_key: walletPublicKey,
    state_kind: "GENESIS",
    s_signature: "",
    p_signature: "",
    b_amount: "0",
    inner_sha256: null,
    step_1_signature: null,
    step_2_signature: null,
  });

  try {
    const built = buildWalletHeadFingerprint(input);
    return {
      ok: true,
      fingerprint: {
        purpose: WALLET_HEAD_FINGERPRINT_PURPOSE,
        stateKind: "GENESIS",
        preimageText: built.preimageText,
        sha256: built.sha256,
      },
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "suite serialize rejected";
    return { ok: false, reason: "UNVERIFIED_PROJECTION", detail };
  }
}

/**
 * Two fingerprints claim the same verified wallet state when digests match — even if raw
 * envelopes differ. Does not promote state and does not suppress raw-evidence append.
 */
export function fingerprintsSemanticallyEqual(
  leftSha256: string,
  rightSha256: string,
): boolean {
  return leftSha256.length === 64 && leftSha256 === rightSha256;
}

function asFingerprintInput(fields: {
  wallet_public_key: string;
  state_kind: WalletHeadStateKind;
  s_signature: string;
  p_signature: string;
  b_amount: string;
  inner_sha256: string | null;
  step_1_signature: string | null;
  step_2_signature: string | null;
}): WalletHeadFingerprintInput {
  // Brand casts: suite encoders re-validate every scalar at serialize time.
  return {
    wallet_public_key: fields.wallet_public_key as WalletHeadFingerprintInput["wallet_public_key"],
    state_kind: fields.state_kind as WalletHeadFingerprintInput["state_kind"],
    s_signature: fields.s_signature as WalletHeadFingerprintInput["s_signature"],
    p_signature: fields.p_signature as WalletHeadFingerprintInput["p_signature"],
    b_amount: fields.b_amount as WalletHeadFingerprintInput["b_amount"],
    inner_sha256: fields.inner_sha256 as WalletHeadFingerprintInput["inner_sha256"],
    step_1_signature: fields.step_1_signature as WalletHeadFingerprintInput["step_1_signature"],
    step_2_signature: fields.step_2_signature as WalletHeadFingerprintInput["step_2_signature"],
  };
}
