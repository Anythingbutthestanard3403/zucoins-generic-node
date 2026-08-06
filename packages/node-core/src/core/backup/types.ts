// Types for the node backup archive. The exporter consumes a typed snapshot plus a
// signer seam and produces the canonical archive; the verifier consumes the archive text plus
// public keys only. Private keys never enter this module: signing happens in the caller-held
// signer seam, and verification uses the public keys the archive itself carries (the key-custody rule).

import type { BackupCoverageTable } from "./format.js";

// A detached Ed25519 signer over exact preimage bytes. The seam holds the secret key; this
// module only ever receives the resulting 64-byte signature.
export interface BackupSigner {
  sign(preimageBytes: Uint8Array): Uint8Array;
}

// The verbatim `vault` row, schema-declared column sequence.
// ciphertext/nonce/auth_tag are padded base64url; ciphertext_sha256 is 64 lowercase hex;
// created_at/rotated_at are UTC RFC3339 with three fractional digits (rotated_at nullable).
export interface BackupVaultRow {
  readonly wallet_id: string;
  readonly key_version: number;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly auth_tag: string;
  readonly ciphertext_sha256: string;
  readonly created_at: string;
  readonly rotated_at: string | null;
}

export interface BackupWalletInput {
  readonly walletId: string;
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly keyVersion: number;
  readonly vault: BackupVaultRow;
  readonly signer: BackupSigner;
}

export interface BackupNodeSigningKeyInput {
  readonly signingKeyId: string;
  readonly purpose: string;
  readonly publicKey: string;
  readonly vaultSecretRef: string;
  readonly sealedCiphertextSha256: string;
}

// A covered row is a flat object whose columns are already in schema-declared sequence and whose
// values are encoded as (UUID/text/base64url/hex/timestamp → string, integer → number,
// bigint → decimal string, boolean → true/false, NULL → null).
export type BackupEvidenceValue = string | number | boolean | null;
export type BackupEvidenceRow = Record<string, BackupEvidenceValue>;

// Primary-key column kinds drive the canonical row sequence: uuid/text compare by UTF-8
// byte value, integer/bigint by numeric value (never decimal-string comparison).
export type BackupPrimaryKeyKind = "uuid" | "text" | "integer";
export interface BackupPrimaryKeyColumn {
  readonly column: string;
  readonly kind: BackupPrimaryKeyKind;
}

export interface BackupEvidenceTableInput {
  readonly table: BackupCoverageTable;
  readonly primaryKey: readonly BackupPrimaryKeyColumn[];
  readonly rows: readonly BackupEvidenceRow[];
}

export interface BackupSnapshot {
  readonly nodeId: string;
  readonly exportId: string;
  readonly exportedAt: string;
  readonly wallets: readonly BackupWalletInput[];
  readonly nodeSigningKeys: readonly BackupNodeSigningKeyInput[];
  readonly evidenceTables: readonly BackupEvidenceTableInput[];
  readonly settingsValues: Record<string, string>;
  readonly identitySigner: BackupSigner;
}

// Archive output shapes (canonical JSON-ready objects).
export interface BackupArchiveVault {
  readonly wallet_id: string;
  readonly key_version: number;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly auth_tag: string;
  readonly ciphertext_sha256: string;
  readonly created_at: string;
  readonly rotated_at: string | null;
}

export interface BackupWalletSection {
  readonly purpose: "zp-backup-wallet-export-v1";
  readonly canonical_version: 1;
  readonly node_id: string;
  readonly export_id: string;
  readonly wallet_id: string;
  readonly public_key: string;
  readonly key_origin: string;
  readonly key_version: number;
  readonly vault: BackupArchiveVault;
  readonly export_proof_signature: string;
}

export interface BackupManifestWalletEntry {
  readonly wallet_id: string;
  readonly public_key: string;
  readonly key_version: number;
  readonly export_sha256: string;
}

export interface BackupManifestSigningKeyEntry {
  readonly signing_key_id: string;
  readonly purpose: string;
  readonly public_key: string;
  readonly vault_secret_ref: string;
  readonly sealed_ciphertext_sha256: string;
}

export interface BackupEvidenceIndexEntry {
  readonly table: string;
  readonly row_count: number;
  readonly table_sha256: string;
}

export interface BackupManifest {
  readonly purpose: "zp-node-backup-manifest-v1";
  readonly canonical_version: 1;
  readonly format: "zp-node-backup-v1";
  readonly node_id: string;
  readonly export_id: string;
  readonly exported_at: string;
  readonly wallets: readonly BackupManifestWalletEntry[];
  readonly node_signing_keys: readonly BackupManifestSigningKeyEntry[];
  readonly evidence_index: readonly BackupEvidenceIndexEntry[];
  readonly settings_sha256: string;
}

export interface BackupEvidenceSection {
  readonly table: string;
  readonly rows: readonly BackupEvidenceRow[];
}

export interface BackupSettingsSnapshot {
  readonly values: Record<string, string>;
}

export interface BackupArchive {
  readonly format: "zp-node-backup-v1";
  readonly manifest: BackupManifest;
  readonly manifest_signature: string;
  readonly wallet_sections: readonly BackupWalletSection[];
  readonly evidence_sections: readonly BackupEvidenceSection[];
  readonly settings_snapshot: BackupSettingsSnapshot;
}

export interface BackupExportResult {
  readonly archiveJson: string;
  readonly archive: BackupArchive;
}

export type BackupRejectionReason =
  | "malformed_json"
  | "unknown_format"
  | "field_set_mismatch"
  | "non_canonical_bytes"
  | "bad_wallet_sequence"
  | "duplicate_wallet_section"
  | "manifest_section_mismatch"
  | "bad_key_origin"
  | "public_key_mismatch"
  | "export_digest_mismatch"
  | "table_digest_mismatch"
  | "settings_digest_mismatch"
  | "row_count_mismatch"
  | "coverage_sequence_mismatch"
  | "wallet_proof_signature_invalid"
  | "manifest_signature_invalid"
  | "bad_encoding";

export interface BackupVerificationSuccess {
  readonly ok: true;
}

export interface BackupVerificationFailure {
  readonly ok: false;
  readonly reasons: readonly BackupRejectionReason[];
}

export type BackupVerificationResult = BackupVerificationSuccess | BackupVerificationFailure;

// Trust-boundary rejection for export inputs. Carries a static reason and field name only —
// never the rejected value — so logs cannot echo secret-class material.
export class BackupExportError extends Error {
  readonly code = "BACKUP_EXPORT_INVALID";

  constructor(
    readonly field: string,
    readonly reason: string,
  ) {
    super(`backup export input rejected: ${field} (${reason})`);
    this.name = "BackupExportError";
  }
}
