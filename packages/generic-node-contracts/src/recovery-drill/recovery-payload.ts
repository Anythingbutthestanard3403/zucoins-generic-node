/**
 * SOURCE: signing custody, the fresh-probe rules (exact form); the suite-tuple preimage
 * rule; the recovery-purposes freeze.
 *
 * The `zp-recovery-verification-v1` fresh-probe payload. Field 8 `export_sha256` is the recomputed
 * export digest — the chain link that binds the probe to the export golden. The probe is a
 * recovery-lane purpose only: it cannot parse as a SplitChain inner and no money-path capability
 * can mint it (the fresh-probe rules). Shared by the ceremony's fresh-signature probe and the recovery-drill lane golden.
 */
import { sha256Hex, utf8Bytes } from "../testkit/independentCrypto.ts";
import { RECOVERY_VERIFICATION_PURPOSE } from "./purposes.contract.ts";

export interface RecoveryVerificationInputs {
  readonly nodeId: string;
  readonly walletId: string;
  readonly publicKeyB64Url: string;
  readonly keyVersion: number;
  readonly exportId: string;
  readonly exportSha256: string;
  readonly ceremonyId: string;
  readonly ceremonyNonceB64Url: string;
  readonly issuedAt: string;
}

/** Build the 11-field probe payload in frozen sequence (the fresh-probe rules). */
export const buildRecoveryVerificationPayload = (inputs: RecoveryVerificationInputs): Record<string, unknown> => ({
  purpose: RECOVERY_VERIFICATION_PURPOSE,
  canonical_version: 1,
  node_id: inputs.nodeId,
  wallet_id: inputs.walletId,
  public_key: inputs.publicKeyB64Url,
  key_version: inputs.keyVersion,
  export_id: inputs.exportId,
  export_sha256: inputs.exportSha256,
  ceremony_id: inputs.ceremonyId,
  ceremony_nonce: inputs.ceremonyNonceB64Url,
  issued_at: inputs.issuedAt,
});

/** The suite-tuple preimage for the probe. */
export const recoveryVerificationPreimage = (payload: Record<string, unknown>): string =>
  `${RECOVERY_VERIFICATION_PURPOSE}\n${JSON.stringify(payload)}`;

/** Digest of the probe preimage (recorded in the per-wallet audit details; not a stamp input). */
export const recoveryVerificationDigest = (payload: Record<string, unknown>): string =>
  sha256Hex(utf8Bytes(recoveryVerificationPreimage(payload)));
