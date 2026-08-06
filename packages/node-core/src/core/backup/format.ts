// Node backup archive contract — frozen envelope, versioning, and closed coverage set
// (sealed-store backup coverage). This module owns the archive's shape and
// coverage only; the restore / recovery-verification ceremony is separate scope. The archive
// is a node-internal disaster-recovery artifact, never a wire surface: no endpoint serves it
// and it never traverses the hosted platform (the key-custody rule).
//
// Versioning discipline: any change to layout, coverage, KDF, digest rules, field sequence, or
// section semantics needs a NEW format literal plus new reviewed goldens — never an in-place
// rewrite. Only `zp-node-backup-v1` is defined here.

export const BACKUP_FORMAT = "zp-node-backup-v1" as const;
export const BACKUP_MANIFEST_PURPOSE = "zp-node-backup-manifest-v1" as const;
export const BACKUP_WALLET_EXPORT_PURPOSE = "zp-backup-wallet-export-v1" as const;
export const BACKUP_CANONICAL_VERSION = 1 as const;

// The only key_origin admitted into a wallet section: imported or externally-sourced
// key state cannot appear at launch (Wallet import and imported-wallet are deferred together), so a non-`node_generated` section is rejected.
export const BACKUP_NODE_GENERATED_ORIGIN = "node_generated" as const;

// Closed coverage set, frozen sequence. Every table is carried as a whole-table
// evidence section in exactly this sequence; an empty table is still present and hashes as
// SHA-256 of the empty string. The implementer-scoped stream artifacts join between items 40
// and 41 only via the versioning rule above — until then they cover nothing and are absent.
export const BACKUP_COVERAGE_TABLES = [
  "nodes",
  "implementers",
  "implementer_reporting_keys",
  "node_signing_keys",
  "node_signing_key_sealed_store",
  "wallets",
  "wallet_recovery_verifications",
  "destinations",
  "operations",
  "operation_wallets",
  "lease_groups",
  "lease_group_operations",
  "wallet_lease_memberships",
  "operation_observation_bindings",
  "operation_expected_artifacts",
  "receive_codes",
  "receive_arms",
  "receive_release_proofs",
  "move_observation_evidence",
  "operator_device_keys",
  "approval_challenges",
  "operation_approvals",
  "external_send_sign_intents",
  "operation_transactions",
  "external_send_partials",
  "submit_decisions",
  "gateway_submit_attempts",
  "observers",
  "gateway_observations",
  "wallet_observation_cursors",
  "observation_anomalies",
  "operation_landing_proofs",
  "lineage_path_proofs",
  "lineage_path_bodies",
  "observation_relationship_adjudications",
  "operation_verifications",
  "verification_acknowledgements",
  "verification_ack_wallet_evidence",
  "node_event_seq_counters",
  "node_events",
  "audit_log",
] as const;

export type BackupCoverageTable = (typeof BACKUP_COVERAGE_TABLES)[number];

// Top-level archive field sequence and the per-object field sequences the canonical
// serializer must emit verbatim. A parser rejects any object carrying an additional, missing,
// or re-sequenced field.
export const BACKUP_ARCHIVE_FIELD_SEQUENCE = [
  "format",
  "manifest",
  "manifest_signature",
  "wallet_sections",
  "evidence_sections",
  "settings_snapshot",
] as const;

export const BACKUP_MANIFEST_FIELD_SEQUENCE = [
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

export const BACKUP_WALLET_SECTION_FIELD_SEQUENCE = [
  "purpose",
  "canonical_version",
  "node_id",
  "export_id",
  "wallet_id",
  "public_key",
  "key_origin",
  "key_version",
  "vault",
  "export_proof_signature",
] as const;

// The signed wallet-export preimage covers fields 1–9 only; field 10 (export_proof_signature)
// is never part of the preimage.
export const BACKUP_WALLET_PREIMAGE_FIELD_SEQUENCE = [
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

export const BACKUP_VAULT_FIELD_SEQUENCE = [
  "wallet_id",
  "key_version",
  "ciphertext",
  "nonce",
  "auth_tag",
  "ciphertext_sha256",
  "created_at",
  "rotated_at",
] as const;

export const BACKUP_MANIFEST_WALLET_FIELD_SEQUENCE = [
  "wallet_id",
  "public_key",
  "key_version",
  "export_sha256",
] as const;

export const BACKUP_MANIFEST_SIGNING_KEY_FIELD_SEQUENCE = [
  "signing_key_id",
  "purpose",
  "public_key",
  "vault_secret_ref",
  "sealed_ciphertext_sha256",
] as const;

export const BACKUP_EVIDENCE_INDEX_FIELD_SEQUENCE = [
  "table",
  "row_count",
  "table_sha256",
] as const;

export const BACKUP_EVIDENCE_SECTION_FIELD_SEQUENCE = ["table", "rows"] as const;
