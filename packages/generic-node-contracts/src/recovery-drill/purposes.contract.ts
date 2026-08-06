/**
 * SOURCE: the signing-custody-security spec the wallet-export section (export
 * payload), the manifest/digest rules (manifest payload), the fresh-probe rules (recovery-verification probe payload), the drill matrix (drill
 * matrix); the archive, ceremony, and drill freezes.
 *
 * the recovery-drill lane (this lane) freezes the three Appendix A purposes registered to the recovery-drill concern backup
 * restore / recovery lane as a SEPARATE registry from `ZP_V1_PURPOSES`. `ZP_V1_PURPOSES`
 * (compat-literals.contract.ts) is frozen at exactly ten members — the A.3-A.7 signed/hashed
 * suite-tuple family — and is UNCHANGED by this lane: the recovery-drill concern purposes are recovery-lane
 * artifacts, not money-path suite tuples, so they are deliberately NOT appended there (appending
 * would mutate a frozen closed set and contaminate the signing-capability money-path union). The
 * ceremony freeze adopts `zp-recovery-verification-v1` as the THIRD recovery-lane purpose after the
 * export/manifest pair; this module is that registry's first machine freeze.
 *
 * DATA ONLY (no functions) — the byte authority for each payload's serialization is Appendix A
 * the suite-tuple preimage (`purpose + "\n" + JSON.stringify(payload)`) exactly as the archive section/the ceremony prose pins it.
 */

/** Archive top-level discriminator (the archive-envelope encoding). The only defined value; parsers reject any other. */
export const BACKUP_ARCHIVE_FORMAT = "zp-node-backup-v1" as const;

/** the wallet-export section — per-wallet export section payload purpose (signed by the wallet key). */
export const BACKUP_WALLET_EXPORT_PURPOSE = "zp-backup-wallet-export-v1" as const;

/** the manifest/digest rules — archive manifest payload purpose (signed by the node identity key). */
export const BACKUP_MANIFEST_PURPOSE = "zp-node-backup-manifest-v1" as const;

/** the fresh-probe rules — fresh post-restore probe payload purpose (signed by the restored wallet key). */
export const RECOVERY_VERIFICATION_PURPOSE = "zp-recovery-verification-v1" as const;

/**
 * The three recovery-lane purposes in registration sequence: the export/manifest pair first,
 * then the recovery-verification probe. Sequence IS a frozen fact here (registration sequence
 * into the recovery-drill concern lane), so the census test uses `assertFieldOrder`, not `assertClosedSet`.
 */
export const RECOVERY_LANE_PURPOSES = [
  BACKUP_WALLET_EXPORT_PURPOSE,
  BACKUP_MANIFEST_PURPOSE,
  RECOVERY_VERIFICATION_PURPOSE,
] as const;

export type RecoveryLanePurpose = (typeof RECOVERY_LANE_PURPOSES)[number];

/** The recovery-verification probe is a recovery-lane purpose only; the signing-capability money-path
 *  `WalletSigningCapability.purpose` union is UNCHANGED (the fresh-probe rules). This pin lets a census test
 *  prove no money-path purpose can mint or be asked for the probe signature. */
export const RECOVERY_PROBE_IS_NOT_MONEY_PATH = {
  purpose: RECOVERY_VERIFICATION_PURPOSE,
  in_wallet_signing_capability_union: false,
  parseable_as_splitchain_inner: false,
  chain_valid: false,
} as const;

/**
 * the wallet-export section signed-payload field sequence (fields 1-9 are the preimage; field 10 `export_proof_signature`
 * is never part of the preimage). Byte sequence IS the contract (Appendix A the suite-tuple preimage).
 */
export const BACKUP_WALLET_EXPORT_FIELDS = [
  "purpose",
  "canonical_version",
  "node_id",
  "export_id",
  "wallet_id",
  "public_key",
  "key_origin",
  "key_version",
  "vault",
] as const;

/** The verbatim `vault` row field sequence carried inside export field 9 (schema-declared sequence,
 *  the data model; `created_at`/`rotated_at` are evidence bytes per the named concern).*/
export const BACKUP_WALLET_EXPORT_VAULT_FIELDS = [
  "wallet_id",
  "key_version",
  "ciphertext",
  "nonce",
  "auth_tag",
  "ciphertext_sha256",
  "created_at",
  "rotated_at",
] as const;

/** the manifest/digest rules manifest field sequence (fields 1-10; `manifest_signature` is a top-level sibling, never
 *  part of the preimage). */
export const BACKUP_MANIFEST_FIELDS = [
  "purpose",
  "canonical_version",
  "format",
  "node_id",
  "export_id",
  "exported_at",
  "wallets",
  "node_signing_keys",
  "evidence_index",
  "settings_sha256",
] as const;

/** The recovery-verification probe field sequence (fields 1-11). Field 8 `export_sha256` is the
 *  recomputed export digest — the chain link to the export golden. */
export const RECOVERY_VERIFICATION_FIELDS = [
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

/** the archive-envelope encoding top-level archive field sequence (the single `JSON.stringify` insertion sequence). */
export const BACKUP_ARCHIVE_TOP_LEVEL_FIELDS = [
  "format",
  "manifest",
  "manifest_signature",
  "wallet_sections",
  "evidence_sections",
  "settings_snapshot",
] as const;

export const SOURCE =
  "signing-custody-security archive/ceremony/drill sections; the suite-tuple preimage rule; backup-archive-freeze, recovery-verification-probe-freeze, recovery-drill-matrix-freeze" as const;
