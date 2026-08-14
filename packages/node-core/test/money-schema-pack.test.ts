/**
 * Money schema pack unit gate (no live DB).
 * Proves: ordered MigrationFile names, receive barrier CREATE presence,
 * catalog-strip removes redeclared domains/types/functions, pack completeness
 * vs disk, reporting-prefix ownership hand-off keeps standalone slice 0 whole.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseMigrationName } from "../src/data/migrations.ts";
import {
  MONEY_SCHEMA_DIR,
  MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING,
  MONEY_SCHEMA_PACK_ORDER,
  MONEY_SCHEMA_PACK_VERSION_BASE,
  REPORTING_PREFIX_OWNED_CATALOG,
  catalogSetsSeededFromReportingPrefix,
  collectCatalogObjectNames,
  emptyCatalogObjectSets,
  extractInlineForeignKeys,
  findCreateTableStatements,
  listSchemaSqlFiles,
  loadMoneySchemaMigrations,
  missingForeignKeys,
  registerCatalogObjects,
  stripAlreadySeenCatalogObjects,
  stripRedeclaredCatalogObjects,
} from "../src/schema/money-schema-pack.ts";

describe("money schema pack", () => {
  it("loads a densely versioned MigrationFile[] starting at VERSION_BASE", () => {
    const files = loadMoneySchemaMigrations();
    expect(files).toHaveLength(MONEY_SCHEMA_PACK_ORDER.length);
    for (let i = 0; i < files.length; i += 1) {
      const parsed = parseMigrationName(files[i].fileName);
      expect(parsed.version).toBe(MONEY_SCHEMA_PACK_VERSION_BASE + i);
      expect(files[i].sql.length).toBeGreaterThan(50);
    }
  });

  it("includes CREATE TABLE for the three receive barriers", () => {
    const corpus = MONEY_SCHEMA_PACK_ORDER.map((slice) =>
      readFileSync(join(MONEY_SCHEMA_DIR, `${slice}.sql`), "utf8"),
    ).join("\n");
    expect(corpus).toMatch(/CREATE TABLE receive_codes\b/);
    expect(corpus).toMatch(/CREATE TABLE receive_arms\b/);
    expect(corpus).toMatch(/CREATE TABLE receive_release_proofs\b/);
  });

  it("pack order places receive_codes before receive_arms and release after arms", () => {
    const iCodes = MONEY_SCHEMA_PACK_ORDER.indexOf("receive-codes");
    const iArms = MONEY_SCHEMA_PACK_ORDER.indexOf("receive-arms");
    const iRelease = MONEY_SCHEMA_PACK_ORDER.indexOf("receive-expiry-release");
    expect(iCodes).toBeGreaterThan(-1);
    expect(iArms).toBeGreaterThan(iCodes);
    expect(iRelease).toBeGreaterThan(iArms);
  });

  it("strips redeclared CREATE DOMAIN/TYPE while preserving CREATE TABLE", () => {
    const sample = `
CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE TYPE operation_kind AS ENUM (
  'RECEIVE_EXTERNAL',
  'MOVE_INTERNAL'
);
CREATE TABLE receive_codes (operation_id uuid PRIMARY KEY);
`;
    const stripped = stripRedeclaredCatalogObjects(sample);
    expect(stripped).not.toMatch(/CREATE DOMAIN/);
    expect(stripped).not.toMatch(/CREATE TYPE/);
    expect(stripped).toMatch(/CREATE TABLE receive_codes/);
  });

  it("every pack slice file exists and excluded-after-reporting are on disk but not in pack", () => {
    const onDisk = new Set(listSchemaSqlFiles());
    for (const slice of MONEY_SCHEMA_PACK_ORDER) {
      expect(onDisk.has(`${slice}.sql`)).toBe(true);
    }
    for (const excluded of MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING) {
      expect(onDisk.has(excluded)).toBe(true);
      expect(MONEY_SCHEMA_PACK_ORDER).not.toContain(excluded.replace(/\.sql$/, ""));
    }
    // signing-key-registry is pack-owned (node_signing_keys absent from reporting 0000).
    expect(MONEY_SCHEMA_PACK_ORDER).toContain("signing-key-registry");
    expect(MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING).not.toContain(
      "signing-key-registry.sql",
    );
  });

  it("contracts for receive-codes and receive-arms pin the CREATE file names", () => {
    const codes = readFileSync(join(MONEY_SCHEMA_DIR, "receive-codes.contract.ts"), "utf8");
    const arms = readFileSync(join(MONEY_SCHEMA_DIR, "receive-arms.contract.ts"), "utf8");
    expect(codes).toContain('RECEIVE_CODES_SCHEMA_FILE = "receive-codes.sql"');
    expect(arms).toContain('RECEIVE_ARMS_SCHEMA_FILE = "receive-arms.sql"');
  });
});

describe("catalog ownership + strip", () => {
  it("standalone pack keeps shared domains in slice 0 and strips later redeclares", () => {
    const files = loadMoneySchemaMigrations();
    const base = files[0].sql;
    expect(base).toMatch(/CREATE DOMAIN sha256_hex\b/);
    expect(base).toMatch(/CREATE DOMAIN zkz_balance_text\b/);
    expect(base).toMatch(/CREATE TYPE operation_kind\b/);
    expect(base).toMatch(/CREATE FUNCTION reporting_logical_fingerprint\b/);

    // Later money slices re-declare sha256_hex for greenfield-alone; must not on combined pack.
    for (let i = 1; i < files.length; i += 1) {
      expect(files[i].sql).not.toMatch(/CREATE DOMAIN sha256_hex\b/);
      expect(files[i].sql).not.toMatch(/CREATE DOMAIN padded_base64url_pubkey\b/);
    }
  });

  it("afterReportingPrefix strips reporting-owned catalog from slice 0 but keeps money-only floor", () => {
    const files = loadMoneySchemaMigrations({ afterReportingPrefix: true });
    const base = files[0].sql;
    for (const name of REPORTING_PREFIX_OWNED_CATALOG.domains) {
      expect(base).not.toMatch(new RegExp(`CREATE DOMAIN ${name}\\b`));
    }
    for (const name of REPORTING_PREFIX_OWNED_CATALOG.types) {
      expect(base).not.toMatch(new RegExp(`CREATE TYPE ${name}\\b`));
    }
    for (const name of REPORTING_PREFIX_OWNED_CATALOG.functions) {
      expect(base).not.toMatch(new RegExp(`CREATE (?:OR REPLACE )?FUNCTION ${name}\\b`));
    }
    // Money-only floor still materialises on combined boot.
    expect(base).toMatch(/CREATE DOMAIN zkz_balance_text\b/);
    expect(base).toMatch(/CREATE DOMAIN zkz_amount_positive_text\b/);
    expect(base).toMatch(/CREATE TYPE operation_kind\b/);
    expect(base).toMatch(/CREATE TYPE wallet_state\b/);

    // signing-key-registry keeps node_signing_keys; drops implementer_reporting_keys
    // (already owned by reporting 0000).
    const signingIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("signing-key-registry");
    expect(files[signingIdx].sql).toMatch(/CREATE TABLE node_signing_keys\b/);
    expect(files[signingIdx].sql).not.toMatch(/CREATE TABLE implementer_reporting_keys\b/);
  });

  it("cumulative strip drops redeclared functions across pack slices", () => {
    const files = loadMoneySchemaMigrations();
    // event-ledger is first pack owner of reporting_reject_immutable_change.
    const eventIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("event-ledger");
    expect(files[eventIdx].sql).toMatch(
      /CREATE FUNCTION reporting_reject_immutable_change\b/,
    );
    for (let i = eventIdx + 1; i < files.length; i += 1) {
      expect(files[i].sql).not.toMatch(
        /CREATE FUNCTION reporting_reject_immutable_change\b/,
      );
    }
  });

  it("AUDIT: every pack/reporting CREATE DOMAIN|TYPE|FUNCTION overlap is listed in REPORTING_PREFIX_OWNED_CATALOG", () => {
    // reporting prefix (drizzle twin on disk under node-core schema)
    const reportingSql = readFileSync(
      join(MONEY_SCHEMA_DIR, "reporting-persistence.sql"),
      "utf8",
    );
    const reporting = collectCatalogObjectNames(reportingSql);

    const packCreates = emptyCatalogObjectSets();
    for (const slice of MONEY_SCHEMA_PACK_ORDER) {
      registerCatalogObjects(
        packCreates,
        readFileSync(join(MONEY_SCHEMA_DIR, `${slice}.sql`), "utf8"),
      );
    }

    const domainOverlap = [...reporting.domains].filter((d) => packCreates.domains.has(d));
    const typeOverlap = [...reporting.types].filter((t) => packCreates.types.has(t));
    const functionOverlap = [...reporting.functions].filter((f) =>
      packCreates.functions.has(f),
    );

    expect(new Set(domainOverlap)).toEqual(
      new Set(REPORTING_PREFIX_OWNED_CATALOG.domains),
    );
    expect(new Set(typeOverlap)).toEqual(new Set(REPORTING_PREFIX_OWNED_CATALOG.types));
    // Catalog list may intentionally include reporting-only helpers that no pack
    // slice re-declares; asserted overlap ⊆ owned and every true overlap is covered.
    for (const name of functionOverlap) {
      expect(REPORTING_PREFIX_OWNED_CATALOG.functions).toContain(name);
    }
    expect(functionOverlap).toEqual(
      expect.arrayContaining([
        "reporting_logical_fingerprint",
        "reporting_reject_immutable_change",
      ]),
    );
  });

  it("stripAlreadySeenCatalogObjects is a pure projection of the seen set", () => {
    const sample = `
CREATE DOMAIN sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE DOMAIN zkz_balance_text AS text CHECK (VALUE ~ '^[0-9]+$');
CREATE TYPE reporting_key_state AS ENUM ('PENDING', 'ACTIVE');
CREATE TYPE operation_kind AS ENUM ('RECEIVE_EXTERNAL');
CREATE FUNCTION reporting_logical_fingerprint(p text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$ SELECT p; $$;
CREATE FUNCTION custody_reject_wallet_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$;
CREATE TABLE wallets (id uuid PRIMARY KEY);
`;
    const seen = catalogSetsSeededFromReportingPrefix();
    const stripped = stripAlreadySeenCatalogObjects(sample, seen);
    expect(stripped).not.toMatch(/CREATE DOMAIN sha256_hex\b/);
    expect(stripped).toMatch(/CREATE DOMAIN zkz_balance_text\b/);
    expect(stripped).not.toMatch(/CREATE TYPE reporting_key_state\b/);
    expect(stripped).toMatch(/CREATE TYPE operation_kind\b/);
    expect(stripped).not.toMatch(/CREATE FUNCTION reporting_logical_fingerprint\b/);
    expect(stripped).toMatch(/CREATE FUNCTION custody_reject_wallet_mutation\b/);
    expect(stripped).toMatch(/CREATE TABLE wallets\b/);
  });

  it("keeps the standalone active-lease body explained and appends the deferred FK upgrade", () => {
    const files = loadMoneySchemaMigrations();
    const leaseIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lease-foundation");
    const leaseSql = files[leaseIdx].sql;
    expect(leaseSql).not.toMatch(/CREATE TABLE wallet_active_leases\b/);
    // Membership/group FKs only — ops ownership FKs live solely in the fix-forward
    // slice so foundation remains loadable without operations (ZTR-1139 r2).
    for (const constraint of [
      "wallet_active_leases_membership_id_fkey",
      "wallet_active_leases_lease_group_id_fkey",
    ]) {
      expect(leaseSql).toContain(constraint);
    }
    for (const constraint of [
      "wallet_active_leases_root_operation_id_fkey",
      "wallet_active_leases_operation_id_fkey",
      "lease_groups_root_operation_id_fkey",
      "lease_group_operations_operation_id_fkey",
    ]) {
      expect(leaseSql).not.toContain(constraint);
    }

    const upgradeIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lease-operation-foreign-keys");
    const upgradeSql = files[upgradeIdx].sql;
    for (const constraint of [
      "wallet_active_leases_membership_id_fkey",
      "wallet_active_leases_lease_group_id_fkey",
      "wallet_active_leases_root_operation_id_fkey",
      "wallet_active_leases_operation_id_fkey",
      "lease_groups_root_operation_id_fkey",
      "lease_group_operations_operation_id_fkey",
    ]) {
      expect(upgradeSql).toContain(constraint);
    }
    expect(upgradeSql.match(/ON DELETE NO ACTION/g)).toHaveLength(6);
    expect(upgradeSql).toContain("dangling lease ownership rows require operator disposition");

    // ZTR-1169: no shadowed eligibility function/trigger in lease-foundation at all.
    expect(leaseSql).not.toMatch(
      /CREATE FUNCTION lease_foundation_reject_ineligible_lease\b/,
    );
    expect(leaseSql).not.toMatch(/CREATE FUNCTION custody_reject_ineligible_lease\b/);
    expect(leaseSql).not.toMatch(/CREATE TRIGGER wallet_active_leases_eligibility_guard\b/);
    const rawLease = readFileSync(
      join(MONEY_SCHEMA_DIR, "lease-foundation.sql"),
      "utf8",
    );
    expect(rawLease).toMatch(/CREATE TABLE wallet_active_leases\b/);
    expect(rawLease).not.toMatch(
      /CREATE FUNCTION lease_foundation_reject_ineligible_lease\b/,
    );
    expect(rawLease).not.toMatch(
      /CREATE TRIGGER wallet_active_leases_eligibility_guard\b/,
    );
  });

  it("pack lands adjudications, destinations.label, and lease_role enum after lineage", () => {
    const adjIdx = MONEY_SCHEMA_PACK_ORDER.indexOf(
      "observation-relationship-adjudications",
    );
    const labelIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("destinations-label");
    const roleIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lease-role-enum");
    const attentionIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("attention-reason-enum");
    const lineageIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lineage-path-proofs");
    expect(adjIdx).toBeGreaterThan(lineageIdx);
    expect(labelIdx).toBeGreaterThan(adjIdx);
    expect(roleIdx).toBeGreaterThan(labelIdx);
    expect(attentionIdx).toBeGreaterThan(roleIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[adjIdx]!.sql).toMatch(
      /CREATE TABLE observation_relationship_adjudications\b/,
    );
    expect(files[adjIdx]!.sql).toMatch(
      /observation_relationship_adjudications_no_update/,
    );
    expect(files[labelIdx]!.sql).toMatch(
      /ADD COLUMN IF NOT EXISTS label text NOT NULL DEFAULT ''/,
    );
    expect(files[roleIdx]!.sql).toMatch(
      /ALTER COLUMN lease_role TYPE wallet_lease_role/,
    );
  });

  it("appends ZTR-1249 EXPIRED terminal_at backfill after operations", () => {
    const opsIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operations");
    const backfillIdx = MONEY_SCHEMA_PACK_ORDER.indexOf(
      "operations-expired-terminal-at-backfill",
    );
    expect(backfillIdx).toBeGreaterThan(opsIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[backfillIdx]!.sql).toContain(
      "SET terminal_at = COALESCE(terminal_at, updated_at)",
    );
    expect(files[backfillIdx]!.sql).toContain("status = 'EXPIRED'");
    expect(files[backfillIdx]!.sql).toContain("terminal_at IS NULL");
    expect(files[backfillIdx]!.sql).toContain(
      "operations-expired-terminal-at-backfill requires operations",
    );
  });

  it("appends ZTR-1250 landed attention-clear backfill after operations", () => {
    const opsIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operations");
    const clearIdx = MONEY_SCHEMA_PACK_ORDER.indexOf(
      "operations-landed-attention-clear-backfill",
    );
    expect(clearIdx).toBeGreaterThan(opsIdx);
    // Append-only pack: later slices (e.g. wallet-money-capability) may follow.
    expect(clearIdx).toBeLessThan(MONEY_SCHEMA_PACK_ORDER.length);
    const files = loadMoneySchemaMigrations();
    expect(files[clearIdx]!.sql).toContain("attention_required = false");
    expect(files[clearIdx]!.sql).toContain("'RECEIVE_LANDED'");
    expect(files[clearIdx]!.sql).toContain("'EXTERNAL_SEND_LANDED'");
    expect(files[clearIdx]!.sql).toContain(
      "operations-landed-attention-clear-backfill requires operations",
    );
  });

  it("pack lands transaction-material byte-immutability triggers after the tables", () => {
    const tablesIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("transaction-material");
    const guardsIdx = MONEY_SCHEMA_PACK_ORDER.indexOf(
      "transaction-material-byte-immutability",
    );
    expect(tablesIdx).toBeGreaterThanOrEqual(0);
    expect(guardsIdx).toBeGreaterThan(tablesIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[guardsIdx]!.sql).toMatch(
      /CREATE TRIGGER external_send_sign_intents_insert_only\b/,
    );
    expect(files[guardsIdx]!.sql).toMatch(
      /CREATE TRIGGER operation_transactions_byte_immutability\b/,
    );
    expect(files[guardsIdx]!.sql).toMatch(
      /CREATE TRIGGER external_send_partials_byte_immutability\b/,
    );
    expect(files[guardsIdx]!.sql).toContain("EXTERNAL_SEND_SIGN_INTENTS_INSERT_ONLY");
    expect(files[guardsIdx]!.sql).toContain("OPERATION_TRANSACTIONS_BYTE_IMMUTABLE");
    expect(files[guardsIdx]!.sql).toContain("EXTERNAL_SEND_PARTIALS_BYTE_IMMUTABLE");
  });

  it("pack lands AUTO_POLICY enum then approval-stores amendment after approval-stores", () => {
    const storesIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("approval-stores");
    const enumIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("approval-method-auto-policy-enum");
    const autoIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("approval-stores-auto-policy");
    expect(storesIdx).toBeGreaterThanOrEqual(0);
    expect(enumIdx).toBeGreaterThan(storesIdx);
    expect(autoIdx).toBeGreaterThan(enumIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[enumIdx]!.sql).toContain("ALTER TYPE approval_method ADD VALUE 'AUTO_POLICY'");
    expect(files[autoIdx]!.sql).toContain("operation_approvals_method_arms_check");
    expect(files[autoIdx]!.sql).toContain("WHERE totp_timestep IS NOT NULL");
  });

  it("pack lands integration-requests after implementer-credentials", () => {
    const credIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("implementer-credentials");
    const reqIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("integration-requests");
    expect(credIdx).toBeGreaterThanOrEqual(0);
    expect(reqIdx).toBeGreaterThan(credIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[reqIdx]!.sql).toMatch(/CREATE TABLE integration_requests\b/);
    expect(files[reqIdx]!.sql).toContain("claim_token_hash");
    expect(files[reqIdx]!.sql).toContain("integration_requests_status_consistency");
  });

  it("pack lands wallet-money-capability after custody-eligibility (ZTR-1267)", () => {
    const custodyIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("custody-eligibility");
    const capIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("wallet-money-capability");
    expect(custodyIdx).toBeGreaterThanOrEqual(0);
    expect(capIdx).toBeGreaterThan(custodyIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[capIdx]!.sql).toContain("allow_external_receive");
    expect(files[capIdx]!.sql).toContain("allow_external_send");
    expect(files[capIdx]!.sql).toContain("allow_internal_move");
    expect(files[capIdx]!.sql).toContain("money_mode");
    expect(files[capIdx]!.sql).toContain("wallets_money_mode_flags_consistent");
    expect(files[capIdx]!.sql).toContain("DEFAULT 'FULL'");
  });

  it("pack lands wallet-money-capability-lease-guard after capability columns (ZTR-1268)", () => {
    const capIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("wallet-money-capability");
    const guardIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("wallet-money-capability-lease-guard");
    expect(capIdx).toBeGreaterThanOrEqual(0);
    expect(guardIdx).toBeGreaterThan(capIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[guardIdx]!.sql).toContain("CREATE OR REPLACE FUNCTION custody_reject_ineligible_lease");
    expect(files[guardIdx]!.sql).toContain("CUSTODY_LEASE_RECEIVE_CAPABILITY_REJECTED");
    expect(files[guardIdx]!.sql).toContain("CUSTODY_LEASE_SEND_CAPABILITY_REJECTED");
    expect(files[guardIdx]!.sql).toContain("CUSTODY_LEASE_MOVE_CAPABILITY_REJECTED");
  });

  it("pack lands implementer-funding-wallet after lease-guard (ZTR-1287)", () => {
    const guardIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("wallet-money-capability-lease-guard");
    const fundingIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("implementer-funding-wallet");
    expect(guardIdx).toBeGreaterThanOrEqual(0);
    expect(fundingIdx).toBeGreaterThan(guardIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[fundingIdx]!.sql).toContain("funding_wallet_id");
    expect(files[fundingIdx]!.sql).toContain("implementers_funding_wallet_id_fkey");
    expect(files[fundingIdx]!.sql).toContain("ON DELETE RESTRICT");
    expect(files[fundingIdx]!.sql).toContain("implementer-funding-wallet requires wallets");
  });

  it("pack lands operator-accepted-risk-release after funding-wallet (ZTR-1280)", () => {
    const fundingIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("implementer-funding-wallet");
    const riskIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operator-accepted-risk-release");
    const releaseIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("receive-expiry-release");
    const leaseIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lease-foundation");
    expect(fundingIdx).toBeGreaterThanOrEqual(0);
    expect(riskIdx).toBeGreaterThan(fundingIdx);
    expect(riskIdx).toBeGreaterThan(releaseIdx);
    expect(riskIdx).toBeGreaterThan(leaseIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[riskIdx]!.sql).toContain("OPERATOR_ACCEPTED_RISK");
    expect(files[riskIdx]!.sql).toContain("RELEASED_OPERATOR_ACCEPTED_RISK");
    expect(files[riskIdx]!.sql).toContain("RECEIVE_OPERATOR_ACCEPTED_RISK");
    expect(files[riskIdx]!.sql).toContain("operator-accepted-risk-release requires operations");
  });

  it("pack lands verification-mode after operator-accepted-risk-release (ZTR-1300)", () => {
    const riskIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operator-accepted-risk-release");
    const modeIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("verification-mode");
    const opsIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operations");
    const recvIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("receive-admission");
    const sendIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("send-external-create");
    const settingsIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("operational-stores");
    const auditIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("audit-log");
    expect(riskIdx).toBeGreaterThanOrEqual(0);
    expect(modeIdx).toBeGreaterThan(riskIdx);
    expect(modeIdx).toBeGreaterThan(opsIdx);
    expect(modeIdx).toBeGreaterThan(recvIdx);
    expect(modeIdx).toBeGreaterThan(sendIdx);
    expect(modeIdx).toBeGreaterThan(settingsIdx);
    expect(modeIdx).toBeGreaterThan(auditIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[modeIdx]!.sql).toContain("verification_mode");
    expect(files[modeIdx]!.sql).toContain("INDEPENDENT");
    expect(files[modeIdx]!.sql).toContain("NODE_VERIFIED");
    expect(files[modeIdx]!.sql).toContain("RELEASED_NODE_VERIFIED");
    expect(files[modeIdx]!.sql).toContain("verification-mode requires operations");
    expect(files[modeIdx]!.sql).toContain("VERIFICATION_MODE_IMMUTABLE");
  });

  it("pack lands destinations-pending-backfill after verification-mode (ZTR-1306)", () => {
    const modeIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("verification-mode");
    const backfillIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("destinations-pending-backfill");
    const custodyIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("custody-eligibility");
    expect(modeIdx).toBeGreaterThanOrEqual(0);
    expect(custodyIdx).toBeGreaterThanOrEqual(0);
    expect(backfillIdx).toBeGreaterThan(modeIdx);
    expect(backfillIdx).toBeGreaterThan(custodyIdx);
    expect(backfillIdx).toBe(MONEY_SCHEMA_PACK_ORDER.length - 1);
    const files = loadMoneySchemaMigrations();
    expect(files[backfillIdx]!.sql).toContain("destinations-pending-backfill requires wallets");
    expect(files[backfillIdx]!.sql).toContain("destinations-pending-backfill requires destinations");
    expect(files[backfillIdx]!.sql).toContain("key_origin = 'node_generated'");
    expect(files[backfillIdx]!.sql).toContain("'PENDING'");
    expect(files[backfillIdx]!.sql).not.toMatch(/'BLESSED'/);
  });

  it("pack includes lineage-path-proofs and verification-acknowledgements after landing-proof-verifications", () => {
    const lineageIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("lineage-path-proofs");
    const ackIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("verification-acknowledgements");
    const landingIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("landing-proof-verifications");
    expect(lineageIdx).toBeGreaterThan(landingIdx);
    expect(ackIdx).toBeGreaterThan(lineageIdx);
    const files = loadMoneySchemaMigrations();
    expect(files[lineageIdx]!.sql).toMatch(/CREATE TABLE lineage_path_proofs\b/);
    expect(files[lineageIdx]!.sql).toMatch(/CREATE TABLE lineage_path_bodies\b/);
    expect(files[ackIdx]!.sql).toMatch(/CREATE TABLE verification_acknowledgements\b/);
    expect(files[ackIdx]!.sql).toMatch(/CREATE TABLE verification_ack_wallet_evidence\b/);
    expect(files[ackIdx]!.sql).toMatch(/reporting_acks_immutable/);
  });

  // The five correlation objects were frozen in verification-proofs.sql, which the pack
  // excludes — so they never reached a deployed database. mutation-correlation.sql is the
  // shipping copy; it must survive the assembler's strip and land after all three of its
  // attachment targets.
  it("ships the five deferred correlation objects after every attachment target", () => {
    const correlationIdx = MONEY_SCHEMA_PACK_ORDER.indexOf("mutation-correlation");
    expect(correlationIdx).toBeGreaterThan(MONEY_SCHEMA_PACK_ORDER.indexOf("receive-arms"));
    expect(correlationIdx).toBeGreaterThan(
      MONEY_SCHEMA_PACK_ORDER.indexOf("verification-acknowledgements"),
    );

    // afterReportingPrefix: true is the production shape — reporting_mutation_idempotency
    // arrives from drizzle 0000, so the strip must not take the triggers attached to it.
    for (const files of [
      loadMoneySchemaMigrations(),
      loadMoneySchemaMigrations({ afterReportingPrefix: true }),
    ]) {
      const sql = files[correlationIdx]!.sql;
      for (const object of [
        "CREATE FUNCTION reporting_assert_completed_mutation",
        "CREATE FUNCTION reporting_validate_mutation_deferred",
        "CREATE CONSTRAINT TRIGGER reporting_completed_parent_has_child",
        "CREATE CONSTRAINT TRIGGER reporting_arm_has_completed_parent",
        "CREATE CONSTRAINT TRIGGER reporting_ack_has_completed_parent",
      ]) {
        expect(sql, object).toContain(object);
      }
      // On the attachment clause, not in prose: all three defer to COMMIT.
      expect(sql.match(/DEFERRABLE INITIALLY DEFERRED\n {2}FOR EACH ROW/g)).toHaveLength(3);
    }
  });

  // The shipping copy has to stay byte-equal to the frozen contract text it was split out of.
  it("mutation-correlation.sql is byte-identical to the verification-proofs.sql block", () => {
    const block = (sql: string): string => {
      const start = sql.indexOf("CREATE FUNCTION reporting_assert_completed_mutation");
      const endAnchor = "EXECUTE FUNCTION reporting_validate_mutation_deferred();";
      const end = sql.lastIndexOf(endAnchor);
      expect(start, "correlation block start").toBeGreaterThanOrEqual(0);
      expect(end, "correlation block end").toBeGreaterThan(start);
      return sql.slice(start, end + endAnchor.length);
    };
    const frozen = readFileSync(join(MONEY_SCHEMA_DIR, "verification-proofs.sql"), "utf8");
    const shipped = readFileSync(join(MONEY_SCHEMA_DIR, "mutation-correlation.sql"), "utf8");
    expect(block(shipped)).toBe(block(frozen));
  });

  it("fails on every unexplained duplicate table declaration across pack slices", () => {
    const byTable = new Map<string, { slice: string; full: string }[]>();
    for (const slice of MONEY_SCHEMA_PACK_ORDER) {
      const raw = readFileSync(join(MONEY_SCHEMA_DIR, `${slice}.sql`), "utf8");
      for (const t of findCreateTableStatements(raw)) {
        const list = byTable.get(t.name) ?? [];
        list.push({ slice, full: t.full });
        byTable.set(t.name, list);
      }
    }
    const multi = [...byTable.entries()].filter(([, v]) => v.length > 1);
    // Closed allow-list: each surviving overlap has a named compatibility owner below.
    // Any newly duplicated table changes this exact set and fails the gate.
    expect(multi.map(([n]) => n).sort()).toEqual(
      [
        "operator_device_keys",
        // Production owner is custody-eligibility; lease-foundation retains a target body
        // solely for its standalone empty-legacy expansion migrator.
        "wallet_active_leases",
      ].sort(),
    );

    const files = loadMoneySchemaMigrations();
    for (const [table, owners] of multi) {
      const first = owners[0];
      for (let i = 1; i < owners.length; i += 1) {
        const later = owners[i];
        if (first.full === later.full) continue; // byte-equal OK
        const missing = missingForeignKeys(
          extractInlineForeignKeys(first.full),
          extractInlineForeignKeys(later.full),
        );
        if (missing.length === 0) {
          // Later does not add FKs (first is FK-superset or equal refs) — OK.
          continue;
        }
        // Later owns FK wire-up: its pack slice SQL must emit the constraints.
        const sliceIdx = MONEY_SCHEMA_PACK_ORDER.indexOf(
          later.slice as (typeof MONEY_SCHEMA_PACK_ORDER)[number],
        );
        const emitted = files[sliceIdx].sql;
        for (const fk of missing) {
          for (const col of fk.columns) {
            expect(emitted).toMatch(
              new RegExp(`${table}_${col}_fkey|REFERENCES ${fk.refTable}`, "i"),
            );
          }
        }
      }
    }
  });
});
