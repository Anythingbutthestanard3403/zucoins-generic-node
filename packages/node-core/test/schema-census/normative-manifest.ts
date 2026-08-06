// Maintained manifest of normative durable-fact nouns for schema-to-specification
// traceability. Drawn from the governing specifications plus the node scope line.
// Not an NLP parse of prose — a hand-curated ledger kept in step with
// specification changes.
//
// disposition:
//   required     — must resolve to a concrete table (or table.column) in schema
//   excluded     — durable fact removed by an adopted decision (must NOT appear as a table)
//   deferred     — named store not yet landed; MUST carry named authority.
//                  Scope-line nouns stay required. Specified CREATE TABLE names
//                  must appear in SPEC_TABLE_DISPOSITIONS; silent omission of a
//                  governing CREATE TABLE is a census failure.

export type NounDisposition = "required" | "excluded" | "deferred";

export type NounSourceDoc =
  | "node-core"
  | "data-model"
  | "api-contract"
  | "operation-flows"
  | "node-scope"
  | "decision:no-network-egress";

export interface NormativeNoun {
  /** Stable id used in the machine-readable report. */
  readonly id: string;
  /** Human noun from the governing text. */
  readonly noun: string;
  readonly sources: readonly {
    readonly doc: NounSourceDoc;
    readonly section: string;
  }[];
  readonly disposition: NounDisposition;
  /**
   * Acceptable schema satisfiers. A noun is satisfied when ANY entry matches:
   *   - "table:<name>"
   *   - "column:<table>.<column>"
   *   - "index:<name>"
   * Empty for excluded/deferred nouns that intentionally have no store.
   */
  readonly satisfiers: readonly string[];
  /** Decision / ticket authority when disposition is excluded or deferred. */
  readonly authority?: string;
  /** Optional retention class from the retention matrix (informational in the report). */
  readonly retentionClass?: string;
}

/**
 * Parent scope line nouns + every durable fact the four governing sections
 * name that a flow or recovery rule depends on. Keep alphabetical by id.
 */
export const NORMATIVE_NOUNS: readonly NormativeNoun[] = [
  // --- parent scope line ---
  {
    id: "node-scope.pool-membership",
    noun: "pool membership / counters",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "node-core", section: "receive pool limits" },
    ],
    disposition: "required",
    // Structural pool membership is the wallet lease / active-lease projection plus
    // node_settings pool_cap keys. No separate pool_members table.
    satisfiers: ["table:wallet_active_leases", "table:wallet_lease_memberships", "table:node_settings"],
    retentionClass: "active lease projection / operational",
  },
  {
    id: "node-scope.reporting-nonces",
    noun: "reporting nonces",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "data-model", section: "reporting registry / operation artifacts" },
      { doc: "api-contract", section: "authentication and tenancy" },
    ],
    disposition: "required",
    satisfiers: ["table:reporting_request_nonces", "table:reporting_nonce_burn_counters"],
    retentionClass: "mutation/register burns permanent",
  },
  {
    id: "node-scope.subscription-handles",
    noun: "subscription handles",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "api-contract", section: "authentication and tenancy / receive creation / event stream" },
      { doc: "operation-flows", section: "request admission durable side effects" },
    ],
    // Handles are stored hashed (session-subscription-stores.sql), so the
    // reverse traversal fails closed.
    disposition: "required",
    satisfiers: ["table:subscription_handles"],
  },
  {
    id: "node-scope.callback-registrations",
    noun: "callback registrations / deliveries",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "operation-flows", section: "request admission durable side effects / operation lifecycle" },
      { doc: "decision:no-network-egress", section: "full decision" },
    ],
    // removes every node-initiated callback surface; must NOT gain a table.
    disposition: "excluded",
    satisfiers: [],
    authority: "no-network-egress decision: remove callback_url and every node-initiated callback surface",
  },
  {
    id: "node-scope.signer-audit",
    noun: "signer audit",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "node-core", section: "durable runtime facts" },
    ],
    disposition: "required",
    satisfiers: ["table:signer_audit"],
    retentionClass: "permanent / append-only",
  },
  {
    id: "node-scope.worker-leader-state",
    noun: "worker / leader state",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "node-core", section: "durable runtime facts" },
      { doc: "data-model", section: "retention matrix" },
    ],
    disposition: "required",
    satisfiers: ["table:worker_cursors", "table:operator_halts", "table:node_settings"],
    retentionClass: "operational",
  },
  {
    id: "node-scope.credentials",
    noun: "credentials (implementer reporting keys / node signing keys)",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "api-contract", section: "authentication and tenancy" },
      { doc: "data-model", section: "reporting registry" },
    ],
    disposition: "required",
    satisfiers: ["table:implementer_reporting_keys", "table:node_signing_keys"],
    retentionClass: "reporting key lifecycle permanent",
  },
  {
    id: "node-scope.admin-sessions",
    noun: "admin sessions",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "api-contract", section: "authentication and tenancy" },
    ],
    // Node-origin admin session + CSRF.
    disposition: "required",
    satisfiers: ["table:admin_sessions"],
  },
  {
    id: "node-scope.totp-burns",
    noun: "TOTP burns",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "api-contract", section: "authentication and tenancy" },
    ],
    disposition: "required",
    satisfiers: ["table:totp_timestep_burns"],
    retentionClass: "permanent / insert-only",
  },
  {
    id: "node-scope.blessing-artifacts",
    noun: "blessing artifacts",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "data-model", section: "custody tables" },
      { doc: "api-contract", section: "operator custody endpoints" },
    ],
    disposition: "required",
    satisfiers: [
      "table:destination_blessing_artifacts",
      "column:destinations.blessing_artifact_id",
    ],
    retentionClass: "wallet origin/blessing/recovery evidence permanent",
  },
  {
    id: "node-scope.candidate-manifests",
    noun: "candidate manifests (PROOF_CHANNEL bodies + external partial material)",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "operation-flows", section: "candidate intake" },
      { doc: "data-model", section: "transaction material / proof-channel candidate bodies" },
    ],
    disposition: "required",
    // deferred explicit validation-manifest column; partials + proof-channel
    // candidate bodies cover the durable exact-content facts requires.
    satisfiers: [
      "table:proof_channel_candidate_bodies",
      "table:external_send_partials",
      "table:operation_transactions",
    ],
    retentionClass: "permanent / verbatim",
  },
  {
    id: "node-scope.gateway-read-intents",
    noun: "gateway read intents / observation capture",
    sources: [
      { doc: "node-scope", section: "scope line" },
      { doc: "node-core", section: "durable runtime facts / idempotency" },
      { doc: "operation-flows", section: "request admission" },
    ],
    disposition: "required",
    // Covered by observation-cursor locking + gateway_observations (049).
    satisfiers: ["table:gateway_observations", "table:wallet_observation_cursors", "table:observers"],
    retentionClass: "changed raw observation permanent",
  },

  // --- Named gaps the ticket body calls out explicitly ---
  {
    id: "gap.destinations-blessing-artifact-fk-target",
    noun: "destinations.blessing_artifact_id FK target table",
    sources: [
      { doc: "data-model", section: "custody tables" },
      { doc: "node-scope", section: "named gap" },
    ],
    disposition: "required",
    satisfiers: ["table:destination_blessing_artifacts"],
    retentionClass: "permanent",
  },

  // --- durable runtime facts ---
  {
    id: "node-core.operations",
    noun: "operations (guarded mutation identity)",
    sources: [{ doc: "node-core", section: "guarded mutation identity" }],
    disposition: "required",
    satisfiers: ["table:operations"],
    retentionClass: "permanent",
  },
  {
    id: "node-core.wallet-leases",
    noun: "single active wallet lease",
    sources: [{ doc: "node-core", section: "durable runtime facts / lease discipline" }],
    disposition: "required",
    satisfiers: ["table:wallet_active_leases", "table:lease_groups"],
    retentionClass: "active lease projection",
  },
  {
    id: "node-core.node-settings",
    noun: "node settings (pool/queue constants)",
    sources: [{ doc: "node-core", section: "receive pool limits" }],
    disposition: "required",
    satisfiers: ["table:node_settings"],
    retentionClass: "operational",
  },
  {
    id: "node-core.operator-halts",
    noun: "operator halt state",
    sources: [{ doc: "node-core", section: "durable runtime facts" }],
    disposition: "required",
    satisfiers: ["table:operator_halts"],
    retentionClass: "operational",
  },

  // --- data-model core tables the surrounding sections + retention matrix name ---
  {
    id: "data-model.wallets",
    noun: "wallets",
    sources: [{ doc: "data-model", section: "custody tables" }],
    disposition: "required",
    satisfiers: ["table:wallets"],
    retentionClass: "wallet ciphertext / origin permanent",
  },
  {
    id: "data-model.destinations",
    noun: "destinations",
    sources: [{ doc: "data-model", section: "custody tables" }],
    disposition: "required",
    satisfiers: ["table:destinations"],
    retentionClass: "blessing/recovery evidence permanent",
  },
  {
    id: "data-model.wallet-recovery-verifications",
    noun: "wallet recovery verifications",
    sources: [{ doc: "data-model", section: "custody tables" }],
    disposition: "required",
    satisfiers: ["table:wallet_recovery_verifications"],
    retentionClass: "permanent",
  },
  {
    id: "data-model.operation-transactions",
    noun: "operation_transactions (SplitChain preimages/signatures)",
    sources: [{ doc: "data-model", section: "transaction material" }],
    disposition: "required",
    satisfiers: ["table:operation_transactions"],
    retentionClass: "permanent, verbatim",
  },
  {
    id: "data-model.submit-attempts",
    noun: "submit attempts / decisions",
    sources: [{ doc: "data-model", section: "submit decisions and attempts" }],
    disposition: "required",
    satisfiers: ["table:gateway_submit_attempts", "table:submit_decisions"],
    retentionClass: "permanent",
  },
  {
    id: "data-model.gateway-observations",
    noun: "gateway_observations",
    sources: [{ doc: "data-model", section: "observation ledger" }],
    disposition: "required",
    satisfiers: ["table:gateway_observations"],
    retentionClass: "changed raw observation permanent",
  },
  {
    id: "data-model.observation-anomalies",
    noun: "observation_anomalies",
    sources: [{ doc: "data-model", section: "observation ledger" }],
    disposition: "required",
    satisfiers: ["table:observation_anomalies"],
    retentionClass: "anomaly raw observation permanent",
  },
  {
    id: "data-model.node-events",
    noun: "node_events (signed event ledger)",
    sources: [{ doc: "data-model", section: "event ledger" }],
    disposition: "required",
    satisfiers: ["table:node_events", "table:node_event_seq_counters"],
    retentionClass: "signed node event permanent",
  },
  // Landed by implementer-event-stream.sql. The implementer event stream is described as
  // architecture prose with no CREATE TABLE, so SPEC_TABLE_DISPOSITIONS never sees these
  // tables and no census rule could fail on them; the nouns below make them enumerable.
  {
    id: "data-model.implementer-events",
    noun: "implementer-scoped continuity stream (zp-implementer-event-v1) + its gapless implementer_seq cursor",
    sources: [
      { doc: "data-model", section: "implementer event stream / retention matrix (implementer event)" },
      { doc: "api-contract", section: "implementer event stream" },
    ],
    disposition: "required",
    satisfiers: ["table:implementer_events", "table:implementer_event_seq_counters"],
    // "implementer event (zp-implementer-event-v1) | permanent | append-only".
    // The counter travels with the ledger it numbers, as node_event_seq_counters does.
    retentionClass: "implementer event permanent / append-only",
  },
  {
    id: "data-model.implementer-state-snapshots",
    noun: "latest implementer state snapshot (GET /v1/state/snapshot serving row)",
    sources: [{ doc: "api-contract", section: "state snapshot" }],
    // Required, but deliberately NOT permanent evidence: the row is overwritten on each
    // capture and the durable history is the event stream, so it is an operational
    // projection like the "active lease projection" row — no cascade protection.
    disposition: "required",
    satisfiers: ["table:implementer_state_snapshots"],
    retentionClass: "latest-snapshot projection / operational",
  },
  {
    id: "data-model.implementer-checkpoints",
    noun: "implementer checkpoint stream (zp-implementer-checkpoint-v1) served on GET /v1/events checkpoints[]",
    sources: [
      { doc: "data-model", section: "implementer event stream / retention matrix (implementer checkpoint)" },
      { doc: "api-contract", section: "event checkpoints" },
    ],
    disposition: "required",
    satisfiers: ["table:implementer_checkpoints"],
    retentionClass: "implementer checkpoint permanent / anti-rollback",
  },
  {
    id: "data-model.audit-log",
    noun: "audit_log",
    sources: [{ doc: "data-model", section: "audit log" }],
    disposition: "required",
    satisfiers: ["table:audit_log"],
    retentionClass: "audit log permanent",
  },
  {
    id: "data-model.vault",
    noun: "vault (wallet ciphertext)",
    sources: [{ doc: "data-model", section: "wallet vault" }],
    disposition: "required",
    satisfiers: ["table:vault"],
    retentionClass: "while wallet exists",
  },
  {
    id: "data-model.recovery-nonces",
    noun: "recovery_nonces",
    sources: [{ doc: "data-model", section: "device-key store shape / recovery" }],
    disposition: "required",
    satisfiers: ["table:recovery_nonces"],
    retentionClass: "permanent",
  },
  {
    id: "data-model.expected-artifacts",
    noun: "operation expected artifacts",
    sources: [{ doc: "data-model", section: "operation artifacts / move baseline" }],
    disposition: "required",
    satisfiers: ["table:operation_expected_artifacts", "table:send_operation_expected_artifacts"],
    retentionClass: "permanent / insert-only",
  },
  {
    id: "data-model.external-send-sign-intents",
    noun: "external_send_sign_intents",
    sources: [{ doc: "data-model", section: "transaction material" }],
    disposition: "required",
    satisfiers: ["table:external_send_sign_intents"],
    retentionClass: "permanent, verbatim",
  },
  {
    id: "data-model.external-send-partials",
    noun: "external_send_partials",
    sources: [{ doc: "data-model", section: "transaction material" }],
    disposition: "required",
    satisfiers: ["table:external_send_partials"],
    retentionClass: "permanent, verbatim",
  },
  {
    id: "data-model.reporting-mutation-idempotency",
    noun: "reporting_mutation_idempotency",
    sources: [{ doc: "data-model", section: "operation artifacts" }, { doc: "api-contract", section: "authentication and tenancy" }],
    disposition: "required",
    satisfiers: ["table:reporting_mutation_idempotency"],
    retentionClass: "permanent",
  },
  {
    id: "data-model.device-keys",
    noun: "operator_device_keys",
    sources: [{ doc: "data-model", section: "device keys and approvals" }, { doc: "api-contract", section: "authentication and tenancy" }],
    disposition: "required",
    satisfiers: ["table:operator_device_keys"],
    retentionClass: "lifecycle permanent",
  },

  // --- 05 / 06 flow-adjacent stores ---
  {
    id: "api-contract.nodes-implementers",
    noun: "nodes + implementers registry",
    sources: [{ doc: "api-contract", section: "authentication and tenancy" }, { doc: "data-model", section: "reporting registry" }],
    disposition: "required",
    satisfiers: ["table:nodes", "table:implementers"],
  },
  {
    id: "operation-flows.lease-groups",
    noun: "lease groups (receive create DB-TX)",
    sources: [{ doc: "operation-flows", section: "request admission durable side effects" }],
    disposition: "required",
    satisfiers: ["table:lease_groups", "table:lease_group_operations"],
    retentionClass: "lease group history permanent",
  },
  {
    id: "operation-flows.idempotency",
    noun: "operation idempotency key",
    sources: [{ doc: "operation-flows", section: "request admission durable side effects" }, { doc: "node-core", section: "idempotency" }],
    disposition: "required",
    satisfiers: ["column:operations.idempotency_key"],
  },
] as const;

/**
 * Every CREATE TABLE name in the governing specifications must carry a disposition here
 * (peer of migration-integrity.test.ts SCHEMA_FILES set-equality). Undispositioned
 * names fail as `undispositioned_spec_table`. Deferred rows need named authority;
 * required rows fail as missing_store when the table is absent from schema.
 *
 * Closed set of the data-model CREATE TABLE identifiers (55). A new governing
 * CREATE TABLE without a row here is a gate failure.
 */
export type SpecTableDisposition = {
  readonly table: string;
  readonly disposition: NounDisposition;
  /** Required when disposition is deferred or excluded. */
  readonly authority?: string;
  /** Spec section anchor (informational). */
  readonly section: string;
};

export const SPEC_TABLE_DISPOSITIONS: readonly SpecTableDisposition[] = [
  // --- reporting / registry ---
  { table: "nodes", disposition: "required", section: "reporting registry" },
  { table: "implementers", disposition: "required", section: "reporting registry" },
  { table: "implementer_reporting_keys", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_bootstrap_evidence", disposition: "required", section: "reporting registry" },
  { table: "reporting_nonce_burn_counters", disposition: "required", section: "reporting registry" },
  { table: "reporting_request_nonces", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_enrolment_evidence", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_lifecycle_states", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_lifecycle_events", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_state_transitions", disposition: "required", section: "reporting registry" },
  { table: "reporting_key_lifecycle_heads", disposition: "required", section: "reporting registry" },
  { table: "reporting_mutation_idempotency", disposition: "required", section: "reporting registry" },
  { table: "reporting_restore_state", disposition: "required", section: "reporting registry" },
  { table: "node_signing_keys", disposition: "required", section: "reporting registry" },
  // --- custody ---
  { table: "wallets", disposition: "required", section: "custody tables" },
  { table: "vault", disposition: "required", section: "wallet vault" },
  { table: "wallet_recovery_verifications", disposition: "required", section: "custody tables" },
  { table: "destinations", disposition: "required", section: "custody tables" },
  // --- operations / leases ---
  { table: "wallet_active_leases", disposition: "required", section: "operations and leases" },
  { table: "operations", disposition: "required", section: "operations and leases" },
  { table: "operation_wallets", disposition: "required", section: "operations and leases" },
  { table: "lease_groups", disposition: "required", section: "operations and leases" },
  { table: "lease_group_operations", disposition: "required", section: "operations and leases" },
  { table: "wallet_lease_memberships", disposition: "required", section: "operations and leases" },
  { table: "operation_observation_bindings", disposition: "required", section: "operations and leases" },
  { table: "operation_expected_artifacts", disposition: "required", section: "operation artifacts" },
  // --- durable receive material (live canon; landed) ---
  {
    table: "receive_codes",
    disposition: "required",
    section: "durable receive material",
    authority: "receive_codes frozen CREATE TABLE; expiry whole-seconds format CHECK",
  },
  {
    table: "receive_arms",
    disposition: "required",
    section: "durable receive material",
    authority: "receive_arms frozen CREATE TABLE",
  },
  {
    table: "receive_release_proofs",
    disposition: "required",
    section: "durable receive material",
    authority:
      "receive expiry release; parent operations(id) + kinds triple",
  },
  { table: "move_observation_evidence", disposition: "required", section: "operation artifacts" },
  // --- device keys / guarded approvals (landed: approval-stores.sql) ---
  { table: "operator_device_keys", disposition: "required", section: "device keys and approvals" },
  { table: "approval_challenges", disposition: "required", section: "device keys and approvals" },
  { table: "operation_approvals", disposition: "required", section: "device keys and approvals" },
  // --- transaction / submit ---
  { table: "external_send_sign_intents", disposition: "required", section: "transaction material" },
  { table: "operation_transactions", disposition: "required", section: "transaction material" },
  { table: "external_send_partials", disposition: "required", section: "transaction material" },
  { table: "submit_decisions", disposition: "required", section: "submit decisions and attempts" },
  { table: "gateway_submit_attempts", disposition: "required", section: "submit decisions and attempts" },
  // --- observation ledger ---
  { table: "observers", disposition: "required", section: "observation ledger" },
  { table: "gateway_observations", disposition: "required", section: "observation ledger" },
  { table: "wallet_observation_cursors", disposition: "required", section: "observation ledger" },
  { table: "observation_anomalies", disposition: "required", section: "observation ledger" },
  {
    table: "operation_landing_proofs",
    disposition: "required",
    section: "observation ledger",
    authority: "landing / non-landing oracle; landed in landing-proof-verifications.sql",
  },
  {
    table: "lineage_path_proofs",
    disposition: "required",
    section: "observation ledger",
    authority: "complete-path lineage; landed in lineage-path-proofs.sql",
  },
  {
    table: "lineage_path_bodies",
    disposition: "required",
    section: "observation ledger",
    authority: "complete-path lineage bodies; landed in lineage-path-proofs.sql",
  },
  {
    table: "observation_relationship_adjudications",
    disposition: "deferred",
    section: "observation ledger",
    authority: "relationship adjudication persistence",
  },
  { table: "proof_channel_candidate_bodies", disposition: "required", section: "proof-channel candidate bodies" },
  { table: "proof_body_slot_sighting_counters", disposition: "required", section: "proof-channel candidate bodies" },
  { table: "proof_body_tenant_sighting_counters", disposition: "required", section: "proof-channel candidate bodies" },
  // --- verification + acknowledgements (landed: verification-proofs.sql) ---
  { table: "operation_verifications", disposition: "required", section: "verification acknowledgements" },
  { table: "verification_acknowledgements", disposition: "required", section: "verification acknowledgements" },
  { table: "verification_ack_wallet_evidence", disposition: "required", section: "verification acknowledgements" },
  // --- events / audit ---
  { table: "node_event_seq_counters", disposition: "required", section: "event ledger" },
  { table: "node_events", disposition: "required", section: "event ledger" },
  { table: "audit_log", disposition: "required", section: "audit log" },
  // Web Push subscriptions (node-owned; 04 does not name the table;
  // dispositioned so the census drift guard stays green once the slice landed).
  {
    table: "push_subscriptions",
    disposition: "required",
    section: "push channel",
    authority: "push channel 1; landed in push-subscriptions.sql",
  },
] as const;

/**
 * Retention-matrix rows that are permanent / exact-content / evidence,
 * mapped to concrete schema table names. Operational-only rows (active lease
 * projection, sighting counters) are intentionally absent. Tables listed here
 * that do not yet exist in schema are ignored by cascade checks until landed;
 * the cascade gate still protects every listed name that is present.
 *
 * Decision-cited exclusions (not evidence for CASCADE purposes): none today.
 */
export const RETENTION_MATRIX_EVIDENCE: readonly {
  readonly matrixRow: string;
  readonly retention: string;
  readonly tables: readonly string[];
}[] = [
  {
    matrixRow: "wallet ciphertext",
    retention: "while wallet exists",
    tables: ["vault", "wallets"],
  },
  {
    matrixRow: "wallet origin/blessing/recovery evidence",
    retention: "permanent",
    tables: [
      "wallets",
      "destinations",
      "wallet_recovery_verifications",
      "destination_blessing_artifacts",
    ],
  },
  {
    matrixRow: "lease group and membership history",
    retention: "permanent",
    tables: [
      "lease_groups",
      "lease_group_operations",
      "wallet_lease_memberships",
      "lease_release_proofs",
      "lease_audit_events",
    ],
  },
  {
    matrixRow: "operation",
    retention: "permanent",
    tables: ["operations", "operation_wallets"],
  },
  {
    matrixRow: "expected artifact / approval preimage",
    retention: "permanent",
    tables: [
      "operation_expected_artifacts",
      "send_operation_expected_artifacts",
      "operation_approvals",
      "approval_challenges",
    ],
  },
  {
    matrixRow: "reporting key and enrolment/lifecycle evidence",
    retention: "permanent",
    tables: [
      "implementer_reporting_keys",
      "reporting_key_bootstrap_evidence",
      "reporting_key_enrolment_evidence",
      "reporting_key_lifecycle_states",
      "reporting_key_lifecycle_events",
      "reporting_key_state_transitions",
      "reporting_key_lifecycle_heads",
      "reporting_restore_state",
      "node_signing_keys",
    ],
  },
  {
    matrixRow: "reporting nonce burn and immutable request projections",
    retention: "mutation/register burns permanent",
    tables: ["reporting_request_nonces", "reporting_nonce_burn_counters"],
  },
  {
    matrixRow: "reporting mutation idempotency and exact response bytes",
    retention: "permanent",
    tables: ["reporting_mutation_idempotency"],
  },
  {
    matrixRow: "SplitChain preimages/signatures/full tx",
    retention: "permanent, verbatim",
    tables: ["operation_transactions"],
  },
  // The row "canonical wallet ledger | permanent, verbatim |
  // append-only": proof-access expiry
  // revokes access, it never deletes ledger bytes, which is exactly what cascade protection
  // over this table guards.
  {
    matrixRow: "canonical wallet ledger",
    retention: "permanent, verbatim; append-only",
    tables: ["wallet_settled_ledger"],
  },
  {
    matrixRow: "send sign intent incl. derived redemption_expiry_at",
    retention: "permanent, verbatim",
    tables: ["external_send_sign_intents"],
  },
  {
    matrixRow: "external partial",
    retention: "permanent, verbatim",
    tables: ["external_send_partials"],
  },
  {
    matrixRow: "submit attempt/decision",
    retention: "permanent",
    tables: ["gateway_submit_attempts", "submit_decisions"],
  },
  {
    matrixRow: "changed raw observation",
    retention: "permanent",
    tables: ["gateway_observations"],
  },
  {
    matrixRow: "anomaly raw observation + record",
    retention: "permanent",
    tables: ["observation_anomalies"],
  },
  {
    matrixRow: "complete-path bodies/manifests/adjudications",
    retention: "permanent",
    tables: [
      "operation_landing_proofs",
      "lineage_path_proofs",
      "lineage_path_bodies",
      "observation_relationship_adjudications",
      "move_observation_evidence",
    ],
  },
  {
    matrixRow: "PROOF_CHANNEL candidate proof-body",
    retention: "permanent, verbatim",
    tables: ["proof_channel_candidate_bodies"],
  },
  {
    matrixRow: "signed node event / audit log",
    retention: "permanent",
    tables: ["node_events", "audit_log", "signer_audit"],
  },
  // The implementer-event row, landed by implementer-event-stream.sql.
  // The sibling checkpoint row landed on the same fragment.
  {
    matrixRow: "implementer event (zp-implementer-event-v1)",
    retention: "permanent",
    tables: ["implementer_events"],
  },
  {
    matrixRow: "implementer checkpoint (zp-implementer-checkpoint-v1)",
    retention: "permanent",
    tables: ["implementer_checkpoints"],
  },
  {
    matrixRow: "verification-material endpoint access (underlying evidence permanent)",
    retention: "underlying evidence permanent; access window separate",
    tables: [
      "operation_verifications",
      "verification_acknowledgements",
      "verification_ack_wallet_evidence",
    ],
  },
  // Receive material is bearer/exact-content once landed (secret-class handling).
  {
    matrixRow: "receive durable material (permanent once formed)",
    retention: "permanent / bearer instrument",
    tables: ["receive_codes", "receive_arms", "receive_release_proofs"],
  },
  // TOTP burns are insert-only permanent (scope +).
  {
    matrixRow: "TOTP timestep burns",
    retention: "permanent / insert-only",
    tables: ["totp_timestep_burns"],
  },
] as const;

/** Decision-cited tables that are NOT cascade-protected despite a permanent-ish class. */
export const EVIDENCE_TABLE_EXCLUSIONS: readonly {
  readonly table: string;
  readonly authority: string;
}[] = [
  // Active lease projection is until positive safe release — not permanent evidence.
  { table: "wallet_active_leases", authority: "retention matrix: active lease projection (operational)" },
] as const;

/**
 * Derive the cascade-protected evidence table set from matrix mappings plus
 * any NORMATIVE_NOUNS retentionClass that marks permanent/exact-content/evidence.
 * Exclusions are subtracted. Callers pass the live schema table set so deferred
 * matrix tables that are not yet created do not dilute the check.
 */
export const deriveEvidenceTables = (
  schemaTables: ReadonlySet<string>,
  nouns: readonly NormativeNoun[] = NORMATIVE_NOUNS,
): readonly string[] => {
  const set = new Set<string>();
  for (const row of RETENTION_MATRIX_EVIDENCE) {
    for (const t of row.tables) set.add(t);
  }
  const permanentClass =
    /permanent|verbatim|exact-content|evidence|append-only|insert-only|blessing|recovery evidence|lease group history|wallet ciphertext/i;
  for (const n of nouns) {
    if (n.retentionClass && permanentClass.test(n.retentionClass)) {
      for (const s of n.satisfiers) {
        if (s.startsWith("table:")) set.add(s.slice("table:".length));
      }
    }
  }
  for (const ex of EVIDENCE_TABLE_EXCLUSIONS) set.delete(ex.table);
  // Only tables that exist (or are named) stay; cascade check ignores missing names
  // naturally via FK edges. Keep the full derived set so tests can assert coverage
  // against schema ∩ matrix without a hand floor.
  return [...set].sort();
};

/**
 * Default evidence set used by the live census. Prefer deriveEvidenceTables at
 * runtime so retentionClass drift is reflected without editing this list.
 */
export const EVIDENCE_TABLES: readonly string[] = deriveEvidenceTables(
  new Set<string>(), // full derived set; existence filtered at cascade-check time is unnecessary
);

/**
 * Worker / reconciliation access patterns over high-write tables.
 * Each pattern must have a supporting index (or PK/UNIQUE covering a left-prefix).
 */
export interface AccessPattern {
  readonly id: string;
  readonly table: string;
  /** Ordered equality/lookup columns the query filters on. */
  readonly columns: readonly string[];
  readonly source: string;
}

export const WORKER_ACCESS_PATTERNS: readonly AccessPattern[] = [
  {
    id: "ops.by-id",
    table: "operations",
    columns: ["id"],
    source: "operator/sql-store.ts SELECT ... FROM operations WHERE id = $1",
  },
  {
    id: "ops.idempotency",
    table: "operations",
    columns: ["implementer_id", "kind", "idempotency_key"],
    source: "operator/sql-store.ts idempotency lookup",
  },
  {
    id: "ops.spawn-parent",
    table: "operations",
    columns: ["spawned_from_operation_id"],
    source: "operator/sql-store.ts spawned_from_operation_id lookup + operations_one_spawn_per_parent_uidx",
  },
  {
    id: "obs.wallet-stream",
    table: "gateway_observations",
    columns: ["wallet_public_key", "wallet_seq"],
    source: "observation stream / gateway_observations_wallet_stream_idx",
  },
  {
    id: "obs.body-hash",
    table: "gateway_observations",
    columns: ["raw_response_sha256"],
    source: "dedup / gateway_observations_body_hash_idx",
  },
  {
    id: "events.by-seq",
    table: "node_events",
    columns: ["node_id", "seq"],
    source: "event ledger composite PK cursor (per-node chain)",
  },
  {
    id: "audit.by-id",
    table: "audit_log",
    columns: ["id"],
    source: "audit_log UNIQUE (id) / (id, node_id)",
  },
  {
    id: "signer-audit.by-operation",
    table: "signer_audit",
    columns: ["operation_id"],
    source: "signer_audit_by_operation",
  },
  {
    id: "worker-cursors.pk",
    table: "worker_cursors",
    columns: ["worker_id", "cursor_key"],
    source: "worker_cursors PRIMARY KEY",
  },
  {
    id: "settings.by-key",
    table: "node_settings",
    columns: ["setting_key"],
    source: "node_settings PRIMARY KEY",
  },
  {
    id: "halts.by-id",
    table: "operator_halts",
    columns: ["halt_id"],
    source: "operator_halts PRIMARY KEY",
  },
  {
    id: "obs-cursors.wallet",
    table: "wallet_observation_cursors",
    columns: ["wallet_id"],
    source: "wallet_observation_cursors_wallet_id_idx",
  },
] as const;

/**
 * Governing schema surface the census must open. The frozen data-model fixture
 * carries every governing CREATE TABLE (the full 56-table inventory); the other
 * historical source labels in NounSourceDoc contributed no CREATE TABLE blocks
 * and remain as per-noun source labels only.
 */
export const GOVERNING_DOCS: readonly {
  readonly id: NounSourceDoc;
  readonly relativePath: string;
}[] = [
  {
    id: "data-model",
    relativePath: "packages/node-core/test/data-model.fixture.md",
  },
] as const;
