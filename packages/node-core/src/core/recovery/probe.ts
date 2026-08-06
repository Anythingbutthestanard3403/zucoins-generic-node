// The fresh post-restore probe payload — `zp-recovery-verification-v1`. Field sequence
// 1–11 is frozen; the preimage is `purpose + "\n" + JSON.stringify(payload)`,
// so a single `JSON.stringify` over an object literal whose keys are already in the frozen
// sequence emits the exact bytes. Never reorder or reformat these fields (the byte-exact signing rule) — the
// committed golden `packages/generic-node-contracts/goldens/recovery/
// zp-recovery-verification-v1.preimage.txt` pins them and the test asserts against it.
//
// This is a recovery-lane purpose only: it cannot parse as a SplitChain inner, and the
// money-path `WalletSigningCapability.purpose` union is unchanged.

export const RECOVERY_VERIFICATION_PURPOSE = "zp-recovery-verification-v1" as const;
export type RecoveryVerificationPurpose = typeof RECOVERY_VERIFICATION_PURPOSE;

export const RECOVERY_PROBE_FIELD_SEQUENCE = [
  "purpose",
  "canonical_version",
  "node_id",
  "wallet_id",
  "public_key",
  "key_version",
  "export_id",
  "export_sha256",
  "ceremony_id",
  "ceremony_nonce",
  "issued_at",
] as const;

export interface RecoveryProbeInputs {
  readonly nodeId: string;
  readonly walletId: string;
  readonly publicKey: string;
  readonly keyVersion: number;
  readonly exportId: string;
  readonly exportSha256: string;
  readonly ceremonyId: string;
  readonly ceremonyNonce: string;
  readonly issuedAt: string;
}

export interface RecoveryProbePayload {
  readonly purpose: RecoveryVerificationPurpose;
  readonly canonical_version: 1;
  readonly node_id: string;
  readonly wallet_id: string;
  readonly public_key: string;
  readonly key_version: number;
  readonly export_id: string;
  readonly export_sha256: string;
  readonly ceremony_id: string;
  readonly ceremony_nonce: string;
  readonly issued_at: string;
}

export function buildRecoveryProbePayload(inputs: RecoveryProbeInputs): RecoveryProbePayload {
  return {
    purpose: RECOVERY_VERIFICATION_PURPOSE,
    canonical_version: 1,
    node_id: inputs.nodeId,
    wallet_id: inputs.walletId,
    public_key: inputs.publicKey,
    key_version: inputs.keyVersion,
    export_id: inputs.exportId,
    export_sha256: inputs.exportSha256,
    ceremony_id: inputs.ceremonyId,
    ceremony_nonce: inputs.ceremonyNonce,
    issued_at: inputs.issuedAt,
  };
}

export function buildRecoveryProbePreimageText(payload: RecoveryProbePayload): string {
  return `${RECOVERY_VERIFICATION_PURPOSE}\n${JSON.stringify(payload)}`;
}
