/**
 * SOURCE: the signing-custody-security spec the coverage table (coverage
 * — closed set, frozen sequence); the backup-archive freeze (coverage freeze).
 *
 * The whole-table evidence coverage set in its FROZEN sequence. The archive's `evidence_sections`
 * and the manifest's `evidence_index` MUST follow this exact sequence; the all-or-nothing acceptance rules rejects evidence
 * sections out of sequence. The drill fixture materializes every table (most empty) so the frozen
 * sequence is exercised end to end. When the data model's implementer-scoped stream artifacts
 * receive their schema, they join between `node_events` (40) and `audit_log` (41) via the archive-envelope encoding
 * versioning rule (NEW format literal + new decision + new goldens) — until then they cover
 * nothing and are absent.
 */

/** The 41 covered tables, in frozen evidence-section sequence (the coverage table). */
export const COVERAGE_TABLES = [
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

export type CoverageTable = (typeof COVERAGE_TABLES)[number];

/** the coverage table explicit exclusions — restoring any of these is a contract violation. The drill matrix
 *  asserts `wallet_active_leases` in particular is NEVER restored (second-signer-authority risk). */
export const COVERAGE_EXCLUSIONS = {
  wallet_active_leases: "exclusivity projection; re-derived by boot reconciliation, never archived",
  platform_observation_store: "node and platform ledgers are independent (the permanent-observation-ledger rule)",
  deferred_capability_pair_state: "none exists at launch (the wallet-import deferral); the jointly-deferred capability pair leaves no archivable state and no reachable origin-enum value",
  totp_and_session_secrets: "authentication factors, not custody material",
  master_key_and_plaintext_private_keys: "never database-resident, never archived",
  // Recording a table the backup-archive freeze never mandated, NOT amending the closed set:
  // `push_subscriptions` appears nowhere in the data model, so COVERAGE_TABLES
  // was never wrong to omit it and nothing above changes. Every field is node-regenerable —
  // `ensureRow` mints a fresh ECDH keypair and auth secret and `subscribeRow` re-registers
  // them with the gateway under a wallet-signed id-proof — and 's
  // requireActiveSubscription refuses external operations until that completes.
  push_receive_material:
    "per-wallet push receive keypair/auth secret; re-minted and re-registered by boot " +
    "reconciliation, never archived",
} as const;

/** Public-key-only tables: coverage is manifest completeness (row presence + digest), not secret
 *  recovery (the coverage table). */
export const PUBLIC_KEY_ONLY_TABLES = ["implementer_reporting_keys", "operator_device_keys"] as const;

export const SOURCE = "signing-custody-security coverage table; backup-archive-freeze" as const;
