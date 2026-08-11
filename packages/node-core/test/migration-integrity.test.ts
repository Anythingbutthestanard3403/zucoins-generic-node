// Greenfield migration integrity for the generic-node frozen schema contracts
// (generic-node-redesign-v2 the data model; the test plan greenfield posture).
//
// These .sql files are contract text, not a drizzle journal: each is executed only by the
// schema-assembly phase against a live database, and each is a SCOPED slice of the 04-data-model
// schema, not a self-contained migration. Two consequences, both proven here against a real
// PostgreSQL:
//   * A self-contained slice (proof-body-store) applies greenfield in an empty schema and
//     materializes exactly the tables/columns its CREATE TABLE blocks declare.
//   * A prerequisite-bound slice (custody-eligibility, observation-ledger, submit-attempts,
//     transaction-material) references relations, domains or types no slice in this package
//     creates ahead of it (operations / operation_approvals / operation_transactions; the 04
// reference domains). Applying it greenfield fails on that missing dependency. The
//     contracts record this as deferred reconciliation scope, so the failure is
//     the documented expected outcome, asserted here so the moment reconciliation lands, this
//     characterization flips and forces a deliberate update.
//
// moved custody-eligibility from the first bullet to the second: conforming it
// to canon data-model restored the `nodes` tenant FKs and the domain types it had collapsed
// to bare `text`, so it can no longer materialize itself alone. The wallets(id) vs
// wallets(wallet_id) split that observation-ledger and transaction-material were characterized
// against is closed by the same change — they now fail only on the relations they genuinely do
// not create.
// Re-application is single-shot: the contracts carry no IF NOT EXISTS / DROP guards, so a
// second application over an already-migrated schema fails. That is asserted too.
//
// Live-database tests are gated on TEST_DATABASE_URL and skip when the server is unreachable.
// psql runs as a child process (node:child_process), which keeps the in-process
// network-containment guard (setup-network-guard.ts) intact.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const goldenDir = resolve(here, "../../generic-node-contracts/goldens");

// Canonical greenfield inventory: the frozen schema contracts this package owns, in
// dependency order (node-implementer-registry declares the nodes/implementers root registries
// that operations FK; custody-eligibility declares wallets, which observation-ledger targets).
const SCHEMA_FILES = [
  "node-implementer-registry.sql",
  "signing-key-registry.sql",
  // NODE_SIGNING_KEYS seal-write table (private seeds). Appended after the
  // public registry; prerequisite-bound on sha256_hex (like vault.sql).
  "node-signing-key-sealed-store.sql",
  // Three walk-support indexes on the already-created gateway_observations table
  // (successor-by-backlink, completed-tx digest, own-body-by-step-1-signature). Its own
  // header documents this pack position — appended after node-signing-key-sealed-store so
  // earlier money-pack version numbers / sql_sha256 journal entries stay stable for
  // already-applied greenfield DBs (mirrors the node-signing-key-sealed-store.sql precedent
  // just above).
  "gateway-observation-successor-indexes.sql",
  "device-keys.sql",
  "custody-eligibility.sql",
  "vault.sql",
  // The operations / operation_wallets slice. Placed after the
  // nodes/implementers and wallets declarers and before audit-log / submit-attempts /
  // transaction-material, which all reference operations.
  "operations.sql",
  // Two nullable columns (response_status/response_body) previously added by a
  // runtime ALTER in start-money-workers.ts, moved into the pack. ALTER-only (no CREATE
  // TABLE), so it's also in NO_TABLE_SCHEMA_FILES below.
  "operations-response-columns.sql",
  // node_id column previously added by a runtime ALTER in
  // admin-session-sql-store.ts, moved into the pack. ALTER-only (no CREATE TABLE), so it's
  // also in NO_TABLE_SCHEMA_FILES below.
  "admin-sessions-node-id.sql",
  "event-ledger.sql",
  // The implementer-scoped continuity stream — sibling of the
  // node-global ledger event-ledger.sql. Self-contained (bare uuid ids, re-declares
  // sha256_hex, no external relations), so its position here is not dependency-forced.
  "implementer-event-stream.sql",
  "audit-log.sql",
  "implementer-credentials.sql",
  "observation-ledger.sql",
  "observation-anomaly-indexes.sql",
  "observation-stores.sql",
  "proof-body-store.sql",
  "receive-admission.sql",
  // The RECEIVE_EXTERNAL landing commit — the landing/lineage proof
  // header, the ordered complete path, and the insert-only receive.landed event. Adds no
  // columns (the operations row already carries them) but foreign-keys operations.
  "receive-external-landing.sql",
  // Extends operations with the safe-terminal release marker
  // and append-only expiry/attention episode ledgers.
  "receive-expiry-release.sql",
  // Durable receive code material (data-model receive_codes). Prerequisite-bound
  // on sha256_hex domain (base-enums-domains.sql); also targets operations(id) and
  // wallets(id) which no slice in SCHEMA_FILES creates GREENFIELD-alone.
  "receive-codes.sql",
  // Durable receive arm acknowledgement (data-model receive_arms).
  // Prerequisite-bound by construction: first FK targets receive_codes(operation_id)
  // which does not exist when applied alone.
  "receive-arms.sql",
  "send-external-create.sql",
  // The SEND_EXTERNAL landing commit — landing columns on send_operations
  // plus the external_send_landing_records / _events insert-only pair.
  "send-external-landing.sql",
  // post-delivery expiry attention columns + insert-only
  // external_send_attention_events. Extends send-external-create (send_operations).
  "send-external-expiry.sql",
  "submit-attempts.sql",
  "transaction-material.sql",
  "move-baseline-binding.sql",
  // Device enrollment challenges (has its own.contract.ts); listed once above
  // with device-keys.sql (not also in COMPANION_FILES).
  "device-enrollment-challenges.sql",
  // reporting-persistence.sql is the frozen reporting nonce/idempotency/
  // lifecycle contract. Self-contained FK closure (creates nodes/
  // implementers) but CREATE FUNCTION reporting_logical_fingerprint resolves pgcrypto
  // digest() at create time, so greenfield-alone without the extension fails on digest.
  "reporting-persistence.sql",
  // Frozen verification/acknowledgement contract.
  // Forward proof-table references intentionally make this dependency-bound.
  "verification-proofs.sql",
  // ALTER TABLE FKs for move_observation_evidence.
  // CREATE TABLE is owned by move-baseline-binding.sql  — this slice is ALTER-only.
  "move-observation-evidence.sql",
  // Full lease foundation (target DDL + proof/epoch/fence tables).
  "lease-foundation.sql",
  // Signer audit, blessing artifacts, recovery nonces, global TOTP
  // burns, rate buckets, and auth-failure state. ALTER destinations FK is
  // prerequisite-bound on custody-eligibility's destinations relation.
  "signer-support.sql",
  // Versioned node_settings, operator_halts, worker_cursors.
  // Self-contained (no external relations); greenfield-alone applies.
  "operational-stores.sql",
  // Exact expected-artifact and guarded-approval stores.
  "expected-artifacts.sql",
  "approval-stores.sql",
  // subscription_handles + admin_sessions durable shape.
  // Self-contained (re-declares sha256_hex; bare uuid ids; no external FKs);
  // greenfield-alone applies.
  "session-subscription-stores.sql",
  // per-wallet Web Push subscriptions (channel 1). References wallets(id),
  // so greenfield-alone stops on that missing relation like every other wallet-bound slice.
  "push-subscriptions.sql",
  // verification-material access-window RECORD (hashed nonce,
  // issued_at/expires_at/status). Self-contained (re-declares sha256_hex; bare uuid
  // ids; no external FKs); greenfield-alone applies. Expiry revokes access only.
  "verification-access-windows.sql",
  // The canonical per-wallet settled ledger (data-model C-10). Last in
  // the sequence — it foreign-keys wallets, operations, operation_wallets and
  // operation_transactions, and its append gate reads operation_verifications, so every
  // other declarer must already have applied.
  "wallet-settled-ledger.sql",
  // Durable, cross-instance reporting rate-limiter bucket. References nodes(id);
  // appended after the sequence closer above (mirrors MONEY_SCHEMA_PACK_ORDER's own
  // append-only placement for this slice — never renumber prior entries).
  "reporting-security-ports.sql",
  // operation_landing_proofs + operation_verifications. References operations,
  // operation_transactions, observers, gateway_observations — appended after the sequence
  // closer above (mirrors MONEY_SCHEMA_PACK_ORDER's own append-only placement).
  "landing-proof-verifications.sql",
  // fix-forward PK collapse on the table above. ALTER-only (no CREATE TABLE), so it's also in
  // NO_TABLE_SCHEMA_FILES below.
  "reporting-rate-limit-buckets-pk-collapse.sql",
  // fix-forward node_events PK from (seq) to (node_id, seq). ALTER-only
  // (no CREATE TABLE), so it's also in NO_TABLE_SCHEMA_FILES below.
  "node-events-seq-composite-pk.sql",
  // lineage_path_proofs + lineage_path_bodies. References
  // operation_landing_proofs / wallets / gateway_observations + sha256_hex domain.
  "lineage-path-proofs.sql",
  // verification_acknowledgements + ack wallet evidence. References
  // operations / nodes / reporting_request_nonces / reporting_mutation_idempotency.
  "verification-acknowledgements.sql",
  // vault_root_kdf_salt — the per-node vault root-KDF salt, persisted beside the `vault`
  // envelopes it opens. No foreign key and it re-declares the shared immutability trigger
  // function, so it has no out-of-slice reference at all.
  "vault-root-kdf-salt.sql",
  // The two correlation functions + three deferred constraint triggers. Declares no table
  // and no index (so it is also in NO_TABLE_SCHEMA_FILES below); it attaches to
  // reporting_mutation_idempotency / receive_arms / verification_acknowledgements.
  "mutation-correlation.sql",
  // One per-wallet index on the already-created wallet_settled_ledger. CREATE INDEX only (no
  // CREATE TABLE), so it's also in NO_TABLE_SCHEMA_FILES below; appended after the sequence
  // closer above (mirrors MONEY_SCHEMA_PACK_ORDER's own append-only placement).
  "wallet-settled-ledger-indexes.sql",
  // Five worker-poll partial indexes on the already-created operations table. CREATE INDEX
  // only (no CREATE TABLE), so it's also in NO_TABLE_SCHEMA_FILES below; appended after the
  // sequence closer above (mirrors MONEY_SCHEMA_PACK_ORDER's own append-only placement).
  "operations-indexes.sql",
  // observation_relationship_adjudications. References gateway_observations +
  // lineage_path_proofs. Appended after lineage-path-proofs.
  "observation-relationship-adjudications.sql",
  // destinations.label column. ALTER-only (no CREATE TABLE).
  "destinations-label.sql",
  // lease_role → wallet_lease_role enum. ALTER-only (no CREATE TABLE).
  "lease-role-enum.sql",
  // Byte-immutability triggers on the three transaction-material tables (ZTR-1138).
  // CREATE FUNCTION + CREATE TRIGGER only (no CREATE TABLE); attaches after
  // transaction-material.sql owns the base tables.
  "transaction-material-byte-immutability.sql",
  // ZTR-1139 fix-forward: preflight dangling lease ownership rows, then add the six
  // deferred NO ACTION FKs after operations + lease foundation exist. ALTER/DO only.
  "lease-operation-foreign-keys.sql",
] as const;

// SCHEMA_FILES that deliberately contain no CREATE TABLE: ALTER statements on a table owned
// by another frozen slice, CREATE INDEX-only extensions of one, or a pure constraint-trigger
// attachment onto tables other slices own.
// Exempt from the non-empty parseTables inventory.
const NO_TABLE_SCHEMA_FILES = [
  "move-observation-evidence.sql",
  "gateway-observation-successor-indexes.sql",
  "operations-response-columns.sql",
  "admin-sessions-node-id.sql",
  "reporting-rate-limit-buckets-pk-collapse.sql",
  "node-events-seq-composite-pk.sql",
  "mutation-correlation.sql",
  "wallet-settled-ledger-indexes.sql",
  "operations-indexes.sql",
  "destinations-label.sql",
  "lease-role-enum.sql",
  "transaction-material-byte-immutability.sql",
  "lease-operation-foreign-keys.sql",
] as const;

// Role/grant contracts (no CREATE TABLE) live alongside the table slices but are not part of
// the table inventory below. privileges.sql is covered by privileges.census.test.ts and
// privilege-readiness.pg.test.ts.
const PRIVILEGE_FILES = ["privileges.sql"] as const;

const BASE_FILES = ["base-enums-domains.sql"];

// Companion SQL that ships with a schema slice but has no separate .contract.ts census.
// Currently empty: device-enrollment-challenges.sql is inventoried in SCHEMA_FILES (it has a
// GREENFIELD entry and its own .contract.ts) so listing it here too would make the
// directory-inventory assertion red.
const COMPANION_FILES = [] as const;

// Greenfield outcome of applying each contract alone into an empty schema. `applies: false`
// names either:
//   * missingRelation — a relation the contract references but no slice in this package
//     creates (the documented reconciliation gap); asserted as
//     `"${name}" does not exist` (Postgres relation-missing phrasing), or
//   * missingFragment — a free-form stderr substring for non-relation prerequisites
//     (e.g. an extension function resolved at CREATE FUNCTION time under a narrowed
//     search_path). Exactly one of the two is set when applies is false.
// For missingRelation, the name is whichever dependency PostgreSQL reports FIRST, not
// necessarily the only one missing.
const GREENFIELD: Record<
  string,
  { applies: boolean; missingRelation?: string; missingFragment?: string }
> = {
  "node-implementer-registry.sql": { applies: true },
  // signing-key-registry.sql layers implementer_reporting_keys and
  // node_signing_keys on the node-implementer-registry base. Applied alone, its first table
  // implementer_reporting_keys REFERENCES nodes(id) (and implementers(id)) and it creates neither,
  // so greenfield-alone fails on nodes -- the same prerequisite-bound characterization as
  // event-ledger. The real-Postgres behavioral proof (layered on the base) is in
  // signing-key-registry.pg.test.ts.
  "signing-key-registry.sql": { applies: false, missingRelation: "nodes" },
  // sealed-store table types ciphertext_sha256 as sha256_hex (base-enums).
  "node-signing-key-sealed-store.sql": { applies: false, missingRelation: "sha256_hex" },
  // Extends observation-ledger.sql with three walk-support indexes and creates no
  // tables of its own. Its first statement indexes gateway_observations directly, so applied
  // alone it fails immediately on that missing relation — prerequisite-bound by construction,
  // like observation-anomaly-indexes.
  "gateway-observation-successor-indexes.sql": {
    applies: false,
    missingRelation: "gateway_observations",
  },
  // Device enrollment: operator_device_keys REFERENCES nodes(id) and creates none.
  "device-keys.sql": { applies: false, missingRelation: "nodes" },
  // Conforming this contract to canon data-model gave `wallets.public_key`
  // and `wallet_recovery_verifications.export_sha256` their domain types back and restored
  // the `nodes` tenant FKs, so it no longer applies alone. PostgreSQL rejects the very first
  // CREATE TABLE on the domain, before it ever reaches the nodes reference.
  "custody-eligibility.sql": { applies: false, missingRelation: "padded_base64url_pubkey" },
  // vault.sql layers the per-wallet envelope row on the custody base. Its
  // ciphertext_sha256 column takes the sha256_hex domain from base-enums-domains.sql, which no
  // slice in SCHEMA_FILES creates, so column-type resolution fails before the wallets FK is
  // even reached — the same prerequisite-bound characterization as observation-anomaly-indexes.
  // The layered real-PostgreSQL proof (custody base + sha256_hex + vault) is in
  // vault-store.pg.test.ts.
  "vault.sql": { applies: false, missingRelation: "sha256_hex" },
  "proof-body-store.sql": { applies: true },
  // operations.sql re-declares the three data-model domains and four enums
  // its two tables use, so it is self-supplying on types. It creates neither nodes nor
  // implementers, and operations.node_id REFERENCES nodes(id) is the first out-of-slice
  // reference the parser reaches, so greenfield-alone fails on nodes — same prerequisite-bound
  // characterization as event-ledger / audit-log. It ALSO carries the wallets(id) vs frozen
  // custody wallets(wallet_id) reconciliation gap this file's header describes, but
  // nodes fails first; that gap is inventoried in operations.contract.ts.
  "operations.sql": { applies: false, missingRelation: "nodes" },
  // ALTER TABLE operations ADD COLUMN — operations does not exist standalone.
  "operations-response-columns.sql": { applies: false, missingRelation: "operations" },
  // ALTER TABLE admin_sessions ADD COLUMN — admin_sessions does not exist standalone.
  "admin-sessions-node-id.sql": { applies: false, missingRelation: "admin_sessions" },
  // event-ledger.sql was in SCHEMA_FILES with no GREENFIELD entry — a latent map
  // hole that threw `GREENFIELD[file].applies` on undefined the moment a live DB was present
  // (silent while TEST_DATABASE_URL is unset). Its first table node_event_seq_counters
  // REFERENCES nodes(id) and it creates no nodes, so applied alone it fails on nodes.
  "event-ledger.sql": { applies: false, missingRelation: "nodes" },
  // Unlike event-ledger.sql, the stream carries node_id/
  // implementer_id as bare uuid (no tenant FK) and re-declares sha256_hex, so it has no
  // out-of-slice reference at all — greenfield-alone applies.
  "implementer-event-stream.sql": { applies: true },
  // audit-log.sql is the forensic audit_log trail. Its first
  // table REFERENCES nodes(id) (and optionally operations/wallets) and creates none of them,
  // so greenfield-alone fails on nodes — same prerequisite-bound characterization as
  // event-ledger / signing-key-registry.
  "audit-log.sql": { applies: false, missingRelation: "nodes" },
  "implementer-credentials.sql": {
    applies: false,
    missingRelation: "implementers",
  },
  "observation-ledger.sql": { applies: false, missingRelation: "wallets" },
  // send_operations foreign-keys the frozen custody wallets relation, which
  // custody-eligibility.sql declares. An FK needs its target relation EARLIER in the apply
  // sequence, so this slice is prerequisite-bound by construction rather than by omission.
  "send-external-create.sql": { applies: false, missingRelation: "wallets" },
  // The landing slice EXTENDS send-external-create.sql. Its first statement
  // ALTERs send_operations, which that slice owns, so greenfield-alone fails on send_operations
  // before either landing table is reached — prerequisite-bound by construction, like
  // move-observation-evidence over move-baseline-binding.
  "send-external-landing.sql": { applies: false, missingRelation: "send_operations" },
  // The expiry/attention slice EXTENDS send-external-create.sql. Its first
  // statement ALTERs send_operations, so greenfield-alone fails on send_operations before the
  // attention event table is reached — prerequisite-bound by construction, like landing.
  "send-external-expiry.sql": { applies: false, missingRelation: "send_operations" },
  // observation-anomaly-indexes.sql is an EXTENSION of observation-ledger.sql: it re-declares
  // no domains/enums/tables and depends on that slice's padded_base64url_pubkey domain (and its
  // observers/gateway_observations tables). Applied alone the CREATE TABLE hits the missing
  // domain type first — the prerequisite this slice cannot self-supply.
  "observation-anomaly-indexes.sql": { applies: false, missingRelation: "padded_base64url_pubkey" },
  "observation-stores.sql": { applies: false, missingRelation: "padded_base64url_pubkey" },
  // foreign-keys into the frozen custody wallets/destinations, which
  // custody-eligibility.sql declares. An FK needs its target relation EARLIER in the apply
  // sequence, so this slice is prerequisite-bound by construction rather than by omission.
  "receive-admission.sql": { applies: false, missingRelation: "wallets" },
  // The receive landing slice EXTENDS operations.sql. Its first CREATE
  // TABLE foreign-keys operations(id), which that slice owns, so greenfield-alone fails on
  // operations before any landing table is reached — prerequisite-bound by construction.
  "receive-external-landing.sql": { applies: false, missingRelation: "operations" },
  // The first statement ALTERs operations.
  "receive-expiry-release.sql": { applies: false, missingRelation: "operations" },
  "submit-attempts.sql": { applies: false, missingRelation: "operations" },
  "transaction-material.sql": { applies: false, missingRelation: "operations" },
  // Trigger slice on transaction-material tables; first CREATE TRIGGER needs the base relation.
  "transaction-material-byte-immutability.sql": {
    applies: false,
    missingRelation: "external_send_sign_intents",
  },
  // self-contained by construction. It re-declares the three data-model domains its
  // columns use and carries every out-of-slice reference (operations, node_signing_keys,
  // gateway_observations) as a bare uuid — the deferred FKs are inventoried in
  // move-baseline-binding.contract.ts and added by the assembly phase.
  "move-baseline-binding.sql": { applies: true },
  // device_enrollment_challenges uses approval_challenge_status (base-enums)
  // and REFERENCES nodes(id). Applied alone the first miss is the enum type (quoted
  // `"approval_challenge_status" does not exist`), not nodes.
  "device-enrollment-challenges.sql": {
    applies: false,
    missingRelation: "approval_challenge_status",
  },
  // The slice re-declares its full FK closure (nodes/implementers + reporting
  // tables) so it is not prerequisite-bound on another contract SQL. Greenfield-alone
  // still fails: reporting_logical_fingerprint() calls pgcrypto digest(), and this
  // harness sets search_path to the throwaway schema only (so even a database-level
  // CREATE EXTENSION pgcrypto in public is invisible). Production migrate.ts provisions
  // pgcrypto and keeps public on the search_path. Postgres phrases the miss as
  // `function digest(bytea, unknown) does not exist` — no relation quotes — so the
  // free-form fragment is the right characterization.
  "reporting-persistence.sql": {
    applies: false,
    missingFragment: "function digest(bytea, unknown) does not exist",
  },
  // receive_codes uses sha256_hex (not declared here) and FK-targets
  // operations(id) / wallets(id), so greenfield-alone fails on sha256_hex first.
  "receive-codes.sql": { applies: false, missingRelation: "sha256_hex" },
  // Corrects a stale characterization. Postgres resolves every column's
  // type while parsing CREATE TABLE, before it validates any FOREIGN KEY target, so the
  // request_class column's reporting_request_class enum (base-enums-domains.sql, not
  // declared here) is what greenfield-alone actually fails on first -- not the
  // operation_id FK to receive_codes, which is checked later in the same statement.
  "receive-arms.sql": { applies: false, missingRelation: "reporting_request_class" },
  // Corrects a stale characterization (same class as receive-arms.sql
  // above). This file's first CREATE TABLE (operation_verifications) resolves every
  // column type before Postgres ever reaches the later CREATE CONSTRAINT TRIGGER on
  // receive_arms, and its proof_manifest_sha256 column uses the shared sha256_hex domain,
  // which this contract does not self-declare -- greenfield-alone fails there first.
  "verification-proofs.sql": { applies: false, missingRelation: "sha256_hex" },
  // ALTER-only FKs. CREATE TABLE is owned by move-baseline-binding.sql
  // Applied alone the ALTER hits the missing relation first — not a second CREATE.
  "move-observation-evidence.sql": {
    applies: false,
    missingRelation: "move_observation_evidence",
  },
  // Bare psql -f hits wallet_lease_role (base-enums-domains / lease-role-enum) before
  // any wallets dependency: membership CREATE uses the enum, and operations FKs stay
  // deferred bare uuid so standalone migrateLeaseFoundation does not require operations
  // (ZTR-1139). The migrator installs the custody eligibility guard separately.
  "lease-foundation.sql": {
    applies: false,
    missingFragment: 'type "wallet_lease_role" does not exist',
  },
  // CREATE TABLE blocks are self-contained (bare uuid ids; local domains). The
  // closing ALTER TABLE destinations FK fails greenfield-alone on missing destinations.
  "signer-support.sql": { applies: false, missingRelation: "destinations" },
  // Three self-contained operational tables; no external relations.
  "operational-stores.sql": { applies: true },
  // prerequisite-bound on the operation/signing-key and node stores.
  "expected-artifacts.sql": { applies: false, missingRelation: "sha256_hex" },
  "approval-stores.sql": {
    applies: false,
    missingRelation: "padded_base64url_pubkey",
  },
  // subscription_handles + admin_sessions; re-declares sha256_hex;
  // no external relations — greenfield-alone applies.
  "session-subscription-stores.sql": { applies: true },
  // FK target wallets(id) is created far earlier in the pack order, so applied
  // ALONE this slice stops on that relation.
  "push-subscriptions.sql": { applies: false, missingRelation: "wallets" },
  "verification-access-windows.sql": { applies: true },
  // The slice re-declares the three data-model domains its columns use, so it
  // is self-supplying on types. Its first out-of-slice reference is wallets(id) on the second
  // column of the only CREATE TABLE, so greenfield-alone fails there — the same
  // prerequisite-bound characterization as observation-ledger / send-external-create.
  "wallet-settled-ledger.sql": { applies: false, missingRelation: "wallets" },
  // FK target nodes(id) is created far earlier in the pack order, so applied
  // ALONE this slice stops on that relation.
  "reporting-security-ports.sql": { applies: false, missingRelation: "nodes" },
  // operation_landing_proofs' proof_manifest_sha256 column uses the shared
  // sha256_hex domain (base-enums-domains.sql, not declared here), which Postgres resolves
  // while parsing CREATE TABLE columns before it validates any FOREIGN KEY target -- so
  // greenfield-alone fails on sha256_hex first, ahead of the operations(id) FK that appears
  // earlier in column order (same class as verification-proofs.sql above).
  "landing-proof-verifications.sql": { applies: false, missingRelation: "sha256_hex" },
  // ALTER TABLE reporting_rate_limit_buckets — that table does not exist standalone.
  "reporting-rate-limit-buckets-pk-collapse.sql": {
    applies: false,
    missingRelation: "reporting_rate_limit_buckets",
  },
  // ALTER TABLE node_events — that table does not exist standalone.
  "node-events-seq-composite-pk.sql": {
    applies: false,
    missingRelation: "node_events",
  },
  // padded_base64url_pubkey (wallet_public_key) is declared before the first sha256_hex
  // column, so greenfield-alone fails on it first.
  "lineage-path-proofs.sql": { applies: false, missingRelation: "padded_base64url_pubkey" },
  // reporting_request_class / reporting_logical_fingerprint / nodes etc.
  "verification-acknowledgements.sql": {
    applies: false,
    missingRelation: "reporting_request_class",
  },
  // No foreign key, no shared domain, and it re-declares the immutability trigger function
  // it attaches — the salt row must be readable at vault-unlock on a node whose `nodes` row
  // genesis writes in the same boot, so it deliberately references nothing.
  "vault-root-kdf-salt.sql": { applies: true },
  // Function-then-trigger slice. plpgsql bodies are only syntax-checked at CREATE FUNCTION,
  // so both functions create alone; the first CREATE CONSTRAINT TRIGGER then fails on its
  // attachment target — the first relation this slice cannot self-supply.
  "mutation-correlation.sql": {
    applies: false,
    missingRelation: "reporting_mutation_idempotency",
  },
  // Its only statement indexes wallet_settled_ledger directly, so applied alone it fails
  // immediately on that missing relation — prerequisite-bound by construction, like
  // gateway-observation-successor-indexes.
  "wallet-settled-ledger-indexes.sql": {
    applies: false,
    missingRelation: "wallet_settled_ledger",
  },
  // Its statements index operations (and one partial predicate reads receive_release_status
  // from receive-expiry-release.sql). Applied alone it fails immediately on the missing
  // operations relation — prerequisite-bound by construction.
  "operations-indexes.sql": {
    applies: false,
    missingRelation: "operations",
  },
  "observation-relationship-adjudications.sql": {
    applies: false,
    // Column type resolves before the gateway_observations FK when base-enums are absent.
    missingFragment: 'type "observation_relationship" does not exist',
  },
  "destinations-label.sql": {
    applies: false,
    missingRelation: "destinations",
  },
  "lease-role-enum.sql": {
    // DO block is a no-op when tables/columns are absent (IF EXISTS guards).
    // Not greenfield-alone materialising; no CREATE TABLE.
    applies: true,
  },
  // Fix-forward DO block starts by auditing wallet_active_leases; every target is owned by
  // earlier production-pack slices, so standalone application must fail on that first target.
  "lease-operation-foreign-keys.sql": {
    applies: false,
    missingRelation: "wallet_active_leases",
  },
};

const sqlText = (file: string): string => readFileSync(resolve(schemaDir, file), "utf8");

// Removes `--` line comments while respecting single-quoted string literals (a `--`
// inside a CHECK regex literal is data, not a comment). Comment text may contain commas,
// which would otherwise be mistaken for column-clause separators.
const stripComments = (sql: string): string => {
  let out = "";
  let inString = false;
  for (let i = 0; i < sql.length; i += 1) {
    const ch = sql[i];
    if (inString) {
      out += ch;
      if (ch === "'") inString = false;
    } else if (ch === "'") {
      inString = true;
      out += ch;
    } else if (ch === "-" && sql[i + 1] === "-") {
      while (i < sql.length && sql[i] !== "\n") i += 1;
      out += "\n";
    } else {
      out += ch;
    }
  }
  return out;
};

// Parses `CREATE TABLE <name> ( ... )` blocks into { table -> column[] }, skipping
// table-level constraint clauses. The contract SQL is the expected structure; the live
// database is asserted to match it exactly.
const parseTables = (rawSql: string): Record<string, string[]> => {
  const sql = stripComments(rawSql);
  const tables: Record<string, string[]> = {};
  const re = /CREATE TABLE (\w+)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(sql)) !== null) {
    const name = match[1];
    const open = match.index + match[0].length - 1;
    let depth = 0;
    let close = -1;
    for (let i = open; i < sql.length; i += 1) {
      const ch = sql[i];
      if (ch === "(") depth += 1;
      else if (ch === ")") {
        depth -= 1;
        if (depth === 0) {
          close = i;
          break;
        }
      }
    }
    if (close === -1 || name === undefined) continue;
    const body = sql.slice(open + 1, close);
    const clauses: string[] = [];
    let clauseDepth = 0;
    let start = 0;
    for (let i = 0; i < body.length; i += 1) {
      const ch = body[i];
      if (ch === "(") clauseDepth += 1;
      else if (ch === ")") clauseDepth -= 1;
      else if (ch === "," && clauseDepth === 0) {
        clauses.push(body.slice(start, i));
        start = i + 1;
      }
    }
    clauses.push(body.slice(start));
    const columns: string[] = [];
    for (const raw of clauses) {
      const clause = raw.trim();
      if (/^(CONSTRAINT|PRIMARY KEY|FOREIGN KEY|UNIQUE|CHECK|EXCLUDE|LIKE)\b/i.test(clause)) {
        continue;
      }
      const col = /^"?(\w+)"?/.exec(clause)?.[1];
      if (col !== undefined) columns.push(col);
    }
    tables[name] = columns;
  }
  return tables;
};

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

const psql = (args: string[]): { status: number; stdout: string; stderr: string } => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

let reachable = false;

describe("greenfield migration integrity — frozen schema contracts", () => {
  describe("contract inventory (no database required)", () => {
    it("the schema directory holds exactly the canonical frozen contract set", () => {
      const sqlFiles = readdirSync(schemaDir)
        .filter((f) => f.endsWith(".sql"))
        .sort();
      expect(sqlFiles).toEqual(
        [...SCHEMA_FILES, ...BASE_FILES, ...PRIVILEGE_FILES, ...COMPANION_FILES].sort(),
      );
    });

    it("the greenfield characterization is a total map of the canonical schema inventory", () => {
      expect(Object.keys(GREENFIELD).sort()).toEqual([...SCHEMA_FILES].sort());
    });

    it("every contract SQL has a matching .contract.ts that names it", () => {
      for (const file of [...SCHEMA_FILES, ...PRIVILEGE_FILES]) {
        const contractFile = resolve(schemaDir, file.replace(/\.sql$/, ".contract.ts"));
        const contract = readFileSync(contractFile, "utf8");
        expect(contract).toContain(file);
      }
    });

    it("each CREATE TABLE contract parses into a non-empty table map; no-table slices declare zero tables", () => {
      for (const file of SCHEMA_FILES) {
        const tables = parseTables(sqlText(file));
        if ((NO_TABLE_SCHEMA_FILES as readonly string[]).includes(file)) {
          expect(Object.keys(tables).length, `${file} must declare no tables`).toBe(0);
          const active = sqlText(file).replace(/--[^\n]*/g, "");
          expect(active, file).toMatch(
            /ALTER\s+TABLE\b|CREATE\s+INDEX\b|CREATE\s+CONSTRAINT\s+TRIGGER\b|CREATE\s+TRIGGER\b|CREATE\s+FUNCTION\b/i,
          );
          expect(active, `${file} must not dual-CREATE`).not.toMatch(
            /CREATE\s+TABLE\s+move_observation_evidence\b/i,
          );
          continue;
        }
        expect(Object.keys(tables).length, file).toBeGreaterThan(0);
        for (const [table, columns] of Object.entries(tables)) {
          expect(columns.length, `${file}:${table}`).toBeGreaterThan(0);
        }
      }
    });
  });

  // Live-PostgreSQL characterization. Skips when TEST_DATABASE_URL is unset or the server
  // is unreachable so the suite stays green where no database is provisioned.
  describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
    const schemas: string[] = [];

    beforeAll(() => {
      reachable = psql(["-c", "SELECT 1"]).status === 0;
    });

    afterAll(() => {
      if (!reachable) return;
      for (const schema of schemas) {
        psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
      }
    });

    const applyGreenfield = (
      file: string,
    ): { status: number; stderr: string; schema: string } => {
      const schema = `migration_${file.replace(/[^a-z0-9]/gi, "_")}`;
      schemas.push(schema);
      psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
      const result = psql([
        "-c",
        `CREATE SCHEMA ${schema}`,
        "-c",
        `SET search_path TO ${schema}`,
        "-f",
        resolve(schemaDir, file),
      ]);
      return { status: result.status, stderr: result.stderr, schema };
    };

    it("each contract applies greenfield exactly as its reconciliation state dictates", (ctx) => {
      if (!reachable) ctx.skip();
      for (const file of SCHEMA_FILES) {
        const expected = GREENFIELD[file];
        const result = applyGreenfield(file);
        if (expected.applies) {
          expect(result.stderr, `${file} should apply greenfield`).toBe("");
          expect(result.status, file).toBe(0);
        } else {
          expect(result.status, `${file} should fail greenfield`).not.toBe(0);
          if (expected.missingFragment !== undefined) {
            expect(
              result.stderr,
              `${file} should fail with fragment ${expected.missingFragment}`,
            ).toContain(expected.missingFragment);
          } else {
            expect(
              result.stderr,
              `${file} should fail on ${expected.missingRelation}`,
            ).toContain(`"${expected.missingRelation}" does not exist`);
          }
        }
      }
    });

    it("self-contained contracts materialize exactly the tables and columns they declare", (ctx) => {
      if (!reachable) ctx.skip();
      for (const file of SCHEMA_FILES) {
        if (!GREENFIELD[file].applies) continue;
        const { schema } = applyGreenfield(file);
        const expected = parseTables(sqlText(file));
        for (const [table, columns] of Object.entries(expected)) {
          const rows = psql([
            "-t",
            "-A",
            "-c",
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = '${schema}' AND table_name = '${table}'
             ORDER BY ordinal_position`,
          ]);
          expect(rows.status, `${file}: querying ${table}`).toBe(0);
          const live = rows.stdout.trim().split("\n").filter(Boolean);
          expect(live, `${file}: ${table} columns`).toEqual(columns);
        }
      }
    });

    it("re-applying a self-contained contract over its own schema fails (single-shot, no guards)", (ctx) => {
      if (!reachable) ctx.skip();
      // custody-eligibility.sql became prerequisite-bound, so the single-shot
      // property is now demonstrated on proof-body-store.sql — the remaining slice that still
      // applies alone. The property under test is the absence of IF NOT EXISTS / DROP guards,
      // which is a convention every contract shares, not a custody-specific one.
      const file = "proof-body-store.sql";
      const { schema, status } = applyGreenfield(file);
      expect(status, "first application applies").toBe(0);
      const second = psql(["-c", `SET search_path TO ${schema}`, "-f", resolve(schemaDir, file)]);
      expect(
        second.status,
        "second application must fail — contracts carry no idempotency guards",
      ).not.toBe(0);
      expect(second.stderr).toMatch(/already exists/);
    });

    it("concatenating every contract into one database fails — the slices are not a standalone journal", (ctx) => {
      if (!reachable) ctx.skip();
      const schema = "migration_combined";
      schemas.push(schema);
      psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
      const args = ["-c", `CREATE SCHEMA ${schema}`, "-c", `SET search_path TO ${schema}`];
      for (const file of SCHEMA_FILES) {
        args.push("-f", resolve(schemaDir, file));
      }
      const result = psql(args);
      expect(result.status, "combined greenfield apply is expected to fail").not.toBe(0);
    });

    // Newest authority (2026-07-26 opposed review) explicitly leaves
    // UPDATE/DELETE trigger enforcement to the assembly phase. This proof therefore covers the
    // frozen DDL only; and remain separate slices.
    it("persists all four frozen goldens and PostgreSQL rejects every store constraint violation", (ctx) => {
      if (!reachable) ctx.skip();
      const schema = "compose_composition";
      schemas.push(schema);
      psql(["-c", `DROP SCHEMA IF EXISTS ${schema} CASCADE`]);
      const sqlLiteral = (value: string): string => `'${value.replaceAll("'", "''")}'`;
      const readGolden = (
        family: "artifacts" | "approval",
        purpose: string,
        suffix: "preimage.txt" | "digest.hex" | "sig.b64",
      ): string =>
        readFileSync(resolve(goldenDir, family, `${purpose}.${suffix}`), "utf8");
      const goldens = [
        {
          purpose: "zp-receive-expected-v1",
          family: "artifacts" as const,
          operation: "00000000-0000-0000-0000-000000000011",
          id: "00000000-0000-0000-0000-000000000041",
        },
        {
          purpose: "zp-move-internal-expected-v1",
          family: "artifacts" as const,
          operation: "00000000-0000-0000-0000-000000000012",
          id: "00000000-0000-0000-0000-000000000042",
        },
        {
          purpose: "zp-send-external-expected-v1",
          family: "artifacts" as const,
          operation: "00000000-0000-0000-0000-000000000013",
          id: "00000000-0000-0000-0000-000000000043",
        },
        {
          purpose: "zp-send-external-approval-v1",
          family: "approval" as const,
          operation: "00000000-0000-0000-0000-000000000014",
          id: "00000000-0000-0000-0000-000000000071",
        },
      ].map((golden) => ({
        ...golden,
        preimage: readGolden(golden.family, golden.purpose, "preimage.txt"),
        digest: readGolden(golden.family, golden.purpose, "digest.hex").trim(),
        signature: readGolden(golden.family, golden.purpose, "sig.b64").trim(),
      }));

      const result = psql([
        "-c",
        `CREATE SCHEMA ${schema}`,
        "-c",
        `SET search_path TO ${schema}, extensions, public`,
        "-f",
        resolve(schemaDir, "base-enums-domains.sql"),
        "-c",
        "CREATE TABLE nodes (id uuid PRIMARY KEY)",
        "-c",
        "CREATE TABLE operations (id uuid PRIMARY KEY)",
        "-c",
        "CREATE TABLE node_signing_keys (id uuid PRIMARY KEY)",
        "-f",
        resolve(schemaDir, "expected-artifacts.sql"),
        "-f",
        resolve(schemaDir, "approval-stores.sql"),
        "-c",
        `INSERT INTO ${schema}.nodes VALUES ('00000000-0000-0000-0000-000000000001')`,
        "-c",
        `INSERT INTO ${schema}.operations VALUES
          ('00000000-0000-0000-0000-000000000011'),
          ('00000000-0000-0000-0000-000000000012'),
          ('00000000-0000-0000-0000-000000000013'),
          ('00000000-0000-0000-0000-000000000014'),
          ('00000000-0000-0000-0000-000000000015'),
          ('00000000-0000-0000-0000-000000000016')`,
        "-c",
        `INSERT INTO ${schema}.node_signing_keys VALUES
          ('00000000-0000-0000-0000-000000000021')`,
        "-c",
        `INSERT INTO ${schema}.operator_device_keys
          (id, node_id, public_key, label, enrolled_at) VALUES
          ('00000000-0000-0000-0000-000000000031',
           '00000000-0000-0000-0000-000000000001',
           repeat('P', 43) || '=', 'roundtrip', now())`,
        "-c",
        `INSERT INTO ${schema}.operation_expected_artifacts
          (id, operation_id, purpose, canonical_version, signing_key_id,
           preimage_text, preimage_sha256, signature) VALUES ${goldens
             .filter((golden) => golden.family === "artifacts")
             .map(
               (golden) =>
                 `('${golden.id}', '${golden.operation}', '${golden.purpose}', 1,
                   '00000000-0000-0000-0000-000000000021',
                   ${sqlLiteral(golden.preimage)}, '${golden.digest}', '${golden.signature}')`,
             )
             .join(",")}`,
        "-c",
        `INSERT INTO ${schema}.approval_challenges
          (id, node_id, operation_id, status, purpose, canonical_version,
           nonce, preimage_text, preimage_sha256, issued_at, expires_at) VALUES
          ('00000000-0000-0000-0000-000000000051',
           '00000000-0000-0000-0000-000000000001',
           '00000000-0000-0000-0000-000000000014', 'CONSUMED',
           'zp-send-external-approval-v1', 1,
           '00000000-0000-0000-0000-000000000061',
           ${sqlLiteral(goldens[3]!.preimage)}, '${goldens[3]!.digest}',
           now(), now() + interval '1 minute')`,
        "-c",
        `INSERT INTO ${schema}.operation_approvals
          (id, node_id, operation_id, challenge_id, method, purpose,
           canonical_version, preimage_text, preimage_sha256, device_key_id,
           device_signature, totp_timestep, consumed_at) VALUES
          ('${goldens[3]!.id}',
           '00000000-0000-0000-0000-000000000001',
           '${goldens[3]!.operation}',
           '00000000-0000-0000-0000-000000000051', 'TOTP_AND_DEVICE',
           'zp-send-external-approval-v1', 1, ${sqlLiteral(goldens[3]!.preimage)},
           '${goldens[3]!.digest}', '00000000-0000-0000-0000-000000000031',
           '${goldens[3]!.signature}', 1, now())`,
      ]);
      expect(result.stderr, "ordered composition should not error").not.toContain(
        "ERROR:",
      );
      expect(result.status).toBe(0);

      for (const golden of goldens) {
        const table =
          golden.family === "artifacts"
            ? "operation_expected_artifacts"
            : "operation_approvals";
        const signatureColumn =
          golden.family === "artifacts" ? "signature" : "device_signature";
        const persisted = psql([
          "-t",
          "-A",
          "-c",
          `SELECT encode(convert_to(preimage_text, 'UTF8'), 'hex')
                    || '|' || preimage_sha256 || '|' || ${signatureColumn}
             FROM ${schema}.${table} WHERE id = '${golden.id}'`,
        ]);
        expect(persisted.status, `${golden.purpose} re-read`).toBe(0);
        expect(persisted.stdout.trim()).toBe(
          `${Buffer.from(golden.preimage).toString("hex")}|${golden.digest}|${golden.signature}`,
        );
      }

      const rejectedWrites: Array<[string, string]> = [
        ["artifact operation uniqueness", `INSERT INTO ${schema}.operation_expected_artifacts SELECT gen_random_uuid(), operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature, now() FROM ${schema}.operation_expected_artifacts LIMIT 1`],
        ["artifact purpose CHECK", `INSERT INTO ${schema}.operation_expected_artifacts VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000015', 'not-a-purpose', 1, '00000000-0000-0000-0000-000000000021', 'x', repeat('a',64), repeat('A',86)||'==', now())`],
        ["artifact version CHECK", `INSERT INTO ${schema}.operation_expected_artifacts VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000015', 'zp-receive-expected-v1', 2, '00000000-0000-0000-0000-000000000021', 'x', repeat('a',64), repeat('A',86)||'==', now())`],
        ["artifact nonempty CHECK", `INSERT INTO ${schema}.operation_expected_artifacts VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000015', 'zp-receive-expected-v1', 1, '00000000-0000-0000-0000-000000000021', '', repeat('a',64), repeat('A',86)||'==', now())`],
        ["artifact operation FK", `INSERT INTO ${schema}.operation_expected_artifacts VALUES (gen_random_uuid(), gen_random_uuid(), 'zp-receive-expected-v1', 1, '00000000-0000-0000-0000-000000000021', 'x', repeat('a',64), repeat('A',86)||'==', now())`],
        ["artifact signing-key FK", `INSERT INTO ${schema}.operation_expected_artifacts VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000015', 'zp-receive-expected-v1', 1, gen_random_uuid(), 'x', repeat('a',64), repeat('A',86)||'==', now())`],
        ["device key node FK", `INSERT INTO ${schema}.operator_device_keys VALUES (gen_random_uuid(), gen_random_uuid(), repeat('Q',43)||'=', 'missing-node', now(), NULL)`],
        ["device key uniqueness", `INSERT INTO ${schema}.operator_device_keys VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', repeat('P',43)||'=', 'duplicate', now(), NULL)`],
        ["challenge node FK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),gen_random_uuid(),'00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',NULL)`],
        ["challenge operation FK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001',gen_random_uuid(),'CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',NULL)`],
        ["challenge nonce uniqueness", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000015', 'CONSUMED', 'zp-send-external-approval-v1', 1, '00000000-0000-0000-0000-000000000061', 'x', repeat('a',64), now(), now()+interval '1 minute', NULL)`],
        ["one ISSUED challenge per operation", `INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','ISSUED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute'),(gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','ISSUED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute')`],
        ["challenge purpose CHECK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','not-a-purpose',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',NULL)`],
        ["challenge version CHECK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',2,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',NULL)`],
        ["challenge expiry CHECK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()-interval '1 minute',NULL)`],
        ["challenge superseded CHECK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','SUPERSEDED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',NULL)`],
        ["challenge superseded-by FK", `INSERT INTO ${schema}.approval_challenges VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','SUPERSEDED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute',gen_random_uuid())`],
        ["approval operation uniqueness", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,operation_id,challenge_id,challenge_status,method,purpose,canonical_version,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval challenge uniqueness", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,challenge_status,method,purpose,canonical_version,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval status CHECK", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,'ISSUED',method,purpose,canonical_version,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval purpose CHECK", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,challenge_status,method,'not-a-purpose',canonical_version,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval version CHECK", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,challenge_status,method,purpose,2,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval node FK", `WITH fresh_challenge AS (INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute') RETURNING id) INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),gen_random_uuid(),'00000000-0000-0000-0000-000000000015',id,'CONSUMED','TOTP_ONLY','zp-send-external-approval-v1',1,'x',repeat('a',64),NULL,NULL,2,now() FROM fresh_challenge`],
        ["approval operation FK", `WITH fresh_challenge AS (INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000016','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute') RETURNING id) INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001',gen_random_uuid(),id,'CONSUMED','TOTP_ONLY','zp-send-external-approval-v1',1,'x',repeat('a',64),NULL,NULL,2,now() FROM fresh_challenge`],
        ["approval device-key FK", `WITH fresh_challenge AS (INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute') RETURNING id) INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015',id,'CONSUMED','TOTP_AND_DEVICE','zp-send-external-approval-v1',1,'x',repeat('a',64),gen_random_uuid(),repeat('A',86)||'==',2,now() FROM fresh_challenge`],
        ["TOTP_AND_DEVICE CHECK", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,challenge_status,'TOTP_AND_DEVICE',purpose,canonical_version,preimage_text,preimage_sha256,NULL,NULL,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["TOTP_ONLY CHECK", `INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),node_id,'00000000-0000-0000-0000-000000000015',challenge_id,challenge_status,'TOTP_ONLY',purpose,canonical_version,preimage_text,preimage_sha256,device_key_id,device_signature,totp_timestep+1,now() FROM ${schema}.operation_approvals LIMIT 1`],
        ["approval composite challenge FK", `WITH fresh_challenge AS (INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000016','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute') RETURNING id) INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015',id,'CONSUMED','TOTP_ONLY','zp-send-external-approval-v1',1,'x',repeat('a',64),NULL,NULL,2,now() FROM fresh_challenge`],
        ["approval TOTP uniqueness", `WITH fresh_challenge AS (INSERT INTO ${schema}.approval_challenges (id,node_id,operation_id,status,purpose,canonical_version,nonce,preimage_text,preimage_sha256,issued_at,expires_at) VALUES (gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015','CONSUMED','zp-send-external-approval-v1',1,gen_random_uuid(),'x',repeat('a',64),now(),now()+interval '1 minute') RETURNING id) INSERT INTO ${schema}.operation_approvals SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000015',id,'CONSUMED','TOTP_ONLY','zp-send-external-approval-v1',1,'x',repeat('a',64),NULL,NULL,1,now() FROM fresh_challenge`],
      ];
      const expectedErrors: Record<string, [string, string]> = {
        "artifact operation uniqueness": ["23505", "operation_expected_artifacts_operation_id_key"],
        "artifact purpose CHECK": ["23514", "operation_expected_artifacts_purpose_check"],
        "artifact version CHECK": ["23514", "operation_expected_artifacts_canonical_version_check"],
        "artifact nonempty CHECK": ["23514", "operation_expected_artifacts_preimage_text_check"],
        "artifact operation FK": ["23503", "operation_expected_artifacts_operation_id_fkey"],
        "artifact signing-key FK": ["23503", "operation_expected_artifacts_signing_key_id_fkey"],
        "device key node FK": ["23503", "operator_device_keys_node_id_fkey"],
        "device key uniqueness": ["23505", "operator_device_keys_node_id_public_key_key"],
        "challenge node FK": ["23503", "approval_challenges_node_id_fkey"],
        "challenge operation FK": ["23503", "approval_challenges_operation_id_fkey"],
        "challenge nonce uniqueness": ["23505", "approval_challenges_nonce_key"],
        "one ISSUED challenge per operation": ["23505", "approval_challenges_one_issued_per_operation"],
        "challenge purpose CHECK": ["23514", "approval_challenges_purpose_check"],
        "challenge version CHECK": ["23514", "approval_challenges_canonical_version_check"],
        "challenge expiry CHECK": ["23514", "approval_challenges_check"],
        "challenge superseded CHECK": ["23514", "approval_challenges_check1"],
        "challenge superseded-by FK": ["23503", "approval_challenges_superseded_by_fkey"],
        "approval operation uniqueness": ["23505", "operation_approvals_operation_id_key"],
        "approval challenge uniqueness": ["23505", "operation_approvals_challenge_id_key"],
        "approval status CHECK": ["23514", "operation_approvals_challenge_status_check"],
        "approval purpose CHECK": ["23514", "operation_approvals_purpose_check"],
        "approval version CHECK": ["23514", "operation_approvals_canonical_version_check"],
        "approval node FK": ["23503", "operation_approvals_node_id_fkey"],
        "approval operation FK": ["23503", "operation_approvals_operation_id_fkey"],
        "approval device-key FK": ["23503", "operation_approvals_device_key_id_fkey"],
        "TOTP_AND_DEVICE CHECK": ["23514", "operation_approvals_check"],
        "TOTP_ONLY CHECK": ["23514", "operation_approvals_check"],
        "approval composite challenge FK": ["23503", "operation_approvals_challenge_id_node_id_operation_id_chal_fkey"],
        "approval TOTP uniqueness": ["23505", "operation_approvals_totp_single_use"],
      };
      for (const [name, statement] of rejectedWrites) {
        const rejected = psql(["--set=VERBOSITY=verbose", "-c", statement]);
        expect(rejected.status, `${name} must be rejected by PostgreSQL`).not.toBe(0);
        const [sqlstate, constraint] = expectedErrors[name]!;
        expect(rejected.stderr, `${name} SQLSTATE`).toContain(`ERROR:  ${sqlstate}:`);
        expect(rejected.stderr, `${name} constraint identity`).toContain(
          `CONSTRAINT NAME:  ${constraint}`,
        );
      }
    });
  });
});

/* ─── fail-closed harness guard ─────────────────────────────
 * Top-level, OUTSIDE the gated describe, so it runs even when that block skips itself.
 * vitest.global-setup.ts provisions TEST_DATABASE_URL whenever a Postgres maintenance database
 * is reachable, and scripts/verify-local.sh exports PG_REQUIRED=1 only after its own pg_isready
 * probe succeeded. Under PG_REQUIRED=1, therefore, an unassigned URL or an unreachable server is
 * a BROKEN HARNESS, never "no Postgres here" — so the live characterization fails loudly instead
 * of reporting green having executed nothing. Without PG_REQUIRED the run is a standalone one
 * outside the canonical pipeline and Postgres stays genuinely optional; verify-local.sh's own
 * default-ON VERIFY_REQUIRE_PG independently fails that case at the outer-runner level. */
it("live-PostgreSQL characterization must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup.ts provisioned no test database, so the live block skipped",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — its greenfield assertions were skipped, not proven",
  ).toBe(true);
});
