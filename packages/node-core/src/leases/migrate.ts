// Fail-closed migrator for the persisted lease foundation.
//
// Target DDL: src/schema/lease-foundation.sql.
// Legacy: custody-eligibility.sql's three-column wallet_active_leases projection.
//
// Rules:
// * Empty legacy projection may be replaced with the full fencing-column form.
// * Populated legacy projection REFUSES — verified evacuation/quarantine required;
// never fabricate membership/epoch defaults and never silent-DELETE live rows.
// * Full form already present: ensure permanent tables + foundation FKs + receive-gate enforcement guard + fence.
// A custody-schema projection carrying the fencing columns without membership/group FKs is
// NOT already_current until those FKs are installed.
// * Mid-apply failure leaves zero foundation tables / no fence (cleanup + no writeFence).
// * Fence is never written without custody_reject_ineligible_lease +
// wallet_active_leases_eligibility_guard present (structural backstop).
// * Old writers without the fence fail closed via assertLeaseFoundationReady.

import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  LEASE_FOUNDATION_SCHEMA_FILE,
  LEASE_FOUNDATION_SCHEMA_VERSION,
} from "../schema/lease-foundation.contract.js";
import { LeaseError } from "./errors.js";
import { STATEMENTS } from "./statements.js";
import type { SqlExecutor } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));
const FULL_REQUIRED_COLUMNS = [
  "wallet_id",
  "membership_id",
  "lease_group_id",
  "root_operation_id",
  "operation_id",
  "lease_role",
  "lease_epoch",
  "acquired_at",
  "heartbeat_at",
  "owner_instance_id",
] as const;

const LEGACY_ONLY_COLUMNS = new Set(["wallet_id", "lease_role", "acquired_at"]);

// Function name lives in custody-eligibility.sql; ZTR-1268 overlays the body with
// money-capability conjuncts (wallet-money-capability-lease-guard.sql). Prefer the
// overlay when present so re-migrate never reverts capability gates.
const ELIGIBILITY_FUNCTION = "custody_reject_ineligible_lease";
const ELIGIBILITY_TRIGGER = "wallet_active_leases_eligibility_guard";
const CUSTODY_SCHEMA_FILE = "custody-eligibility.sql";
const CAPABILITY_LEASE_GUARD_SCHEMA_FILE = "wallet-money-capability-lease-guard.sql";

/** Foundation tables only — never drop shared domains (sha256_hex) or wallets. */
const FOUNDATION_TABLES_DROP_ORDER = [
  "wallet_active_leases",
  "wallet_lease_memberships",
  "lease_group_operations",
  "lease_groups",
  "lease_release_proofs",
  "lease_audit_events",
  "wallet_lease_epoch_highwater",
  "lease_schema_fence",
] as const;

export type MigrateResult =
  | { readonly status: "already_current"; readonly schemaVersion: number }
  | { readonly status: "expanded_empty_legacy"; readonly schemaVersion: number }
  | { readonly status: "applied_greenfield"; readonly schemaVersion: number };

function loadFoundationSql(): string {
  return readFileSync(resolve(here, "../schema", LEASE_FOUNDATION_SCHEMA_FILE), "utf8");
}

/**
 * Split contract SQL into executable statements. Understands:
 * - `--` line comments
 * - single-quoted string literals (with '' escapes)
 * - dollar-quoted bodies (`$$ ... $$` and `$tag$ ... $tag$`) so plpgsql
 * function bodies are not split on their internal semicolons
 */
export function splitSqlStatements(sql: string): string[] {
  const out: string[] = [];
  let buf = "";
  let inString = false;
  let dollarTag: string | null = null;
  for (let i = 0; i < sql.length; i += 1) {
    const ch = sql[i]!;

    if (dollarTag !== null) {
      buf += ch;
      if (ch === "$" && sql.startsWith(dollarTag, i)) {
        buf += dollarTag.slice(1);
        i += dollarTag.length - 1;
        dollarTag = null;
      }
      continue;
    }

    if (inString) {
      buf += ch;
      if (ch === "'") {
        if (sql[i + 1] === "'") {
          buf += "'";
          i += 1;
        } else {
          inString = false;
        }
      }
      continue;
    }

    if (ch === "'") {
      inString = true;
      buf += ch;
      continue;
    }

    if (ch === "$") {
      // Dollar-quote open: $tag$ or $$
      const rest = sql.slice(i);
      const m = /^\$[A-Za-z0-9_]*\$/.exec(rest);
      if (m) {
        dollarTag = m[0]!;
        buf += dollarTag;
        i += dollarTag.length - 1;
        continue;
      }
    }

    if (ch === "-" && sql[i + 1] === "-") {
      while (i < sql.length && sql[i] !== "\n") i += 1;
      buf += "\n";
      continue;
    }

    if (ch === ";") {
      const stmt = buf.trim();
      if (stmt.length > 0) out.push(stmt);
      buf = "";
      continue;
    }
    buf += ch;
  }
  const tail = buf.trim();
  if (tail.length > 0) out.push(tail);
  return out;
}

async function listActiveColumns(db: SqlExecutor): Promise<string[]> {
  const result = await db.query<{ column_name: string; ordinal_position: number }>(
    STATEMENTS.LIST_ACTIVE_COLUMNS,
  );
  return result.rows
    .slice()
    .sort((a, b) => a.ordinal_position - b.ordinal_position)
    .map((r) => r.column_name);
}

async function tableExists(db: SqlExecutor, name: string): Promise<boolean> {
  const result = await db.query<{ exists: boolean }>(
    `SELECT (to_regclass($1) IS NOT NULL) AS exists`,
    [name],
  );
  return result.rows[0]?.exists === true;
}

async function countActiveRows(db: SqlExecutor): Promise<number> {
  const result = await db.query<{ n: string }>(STATEMENTS.COUNT_ACTIVE);
  return Number(result.rows[0]?.n ?? "0");
}

function isFullColumnSet(columns: readonly string[]): boolean {
  const set = new Set(columns);
  return FULL_REQUIRED_COLUMNS.every((c) => set.has(c));
}

function isLegacyThreeColumn(columns: readonly string[]): boolean {
  if (columns.length !== 3) return false;
  return columns.every((c) => LEGACY_ONLY_COLUMNS.has(c));
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isAlreadyExists(err: unknown): boolean {
  return /already exists/i.test(errMessage(err));
}

/**
 * structural backstop presence: custody eligibility function + BEFORE INSERT trigger
 * on wallet_active_leases. Single owner is custody-eligibility.sql (ZTR-1169).
 */
export async function eligibilityGuardPresent(db: SqlExecutor): Promise<boolean> {
  const fn = await db.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1
         FROM pg_proc p
        WHERE pg_function_is_visible(p.oid)
          AND p.proname = $1
     ) AS exists`,
    [ELIGIBILITY_FUNCTION],
  );
  if (fn.rows[0]?.exists !== true) return false;

  const trg = await db.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1
         FROM pg_trigger t
         JOIN pg_proc p ON p.oid = t.tgfoid
        WHERE t.tgrelid = to_regclass('wallet_active_leases')
          AND t.tgname = $1
          AND NOT t.tgisinternal
          AND p.proname = $2
     ) AS exists`,
    [ELIGIBILITY_TRIGGER, ELIGIBILITY_FUNCTION],
  );
  return trg.rows[0]?.exists === true;
}

function pickStatement(
  statements: readonly string[],
  pattern: RegExp,
  label: string,
): string {
  const hit = statements.find((s) => pattern.test(s));
  if (!hit) {
    throw new LeaseError("SCHEMA_NOT_READY", `foundation SQL missing ${label} statement`);
  }
  return hit;
}

/**
 * Install (or re-install) the receive-gate enforcement eligibility function + trigger.
 * Throws SCHEMA_NOT_READY when wallets/destinations are absent or compile fails —
 * caller must not write the fence.
 */
function loadCustodyEligibilityStatements(): readonly string[] {
  const sql = readFileSync(resolve(here, "../schema", CUSTODY_SCHEMA_FILE), "utf8");
  return splitSqlStatements(sql);
}

function loadCapabilityLeaseGuardStatements(): readonly string[] | null {
  try {
    const sql = readFileSync(
      resolve(here, "../schema", CAPABILITY_LEASE_GUARD_SCHEMA_FILE),
      "utf8",
    );
    return splitSqlStatements(sql);
  } catch {
    return null;
  }
}

async function ensureEligibilityGuard(
  db: SqlExecutor,
  _foundationStatements: readonly string[],
): Promise<void> {
  // Base function + trigger: custody-eligibility.sql. Capability overlay (ZTR-1268)
  // replaces the function body when the pack slice is on disk.
  const custodyStatements = loadCustodyEligibilityStatements();
  const capabilityStatements = loadCapabilityLeaseGuardStatements();
  const fnSource =
    capabilityStatements !== null
      ? pickStatement(
          capabilityStatements,
          /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+custody_reject_ineligible_lease/i,
          ELIGIBILITY_FUNCTION,
        )
      : pickStatement(
          custodyStatements,
          /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+custody_reject_ineligible_lease/i,
          ELIGIBILITY_FUNCTION,
        );
  const trgStmt = pickStatement(
    custodyStatements,
    /CREATE TRIGGER wallet_active_leases_eligibility_guard/i,
    ELIGIBILITY_TRIGGER,
  );

  // Always CREATE OR REPLACE the function body so receive-gate repairs land on
  // re-migrate even when the trigger name already exists. Trigger is recreated
  // only when missing to avoid DROP races on a live claim path.
  const replaceFn = fnSource.replace(
    /^CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION/i,
    "CREATE OR REPLACE FUNCTION",
  );

  try {
    await db.query(replaceFn);
    if (!(await eligibilityGuardPresent(db))) {
      await db.query(
        `DROP TRIGGER IF EXISTS ${ELIGIBILITY_TRIGGER} ON wallet_active_leases`,
      );
      await db.query(trgStmt);
    }
  } catch (err) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      `lease eligibility guard cannot be installed (${errMessage(err)}); refusing fence`,
    );
  }

  if (!(await eligibilityGuardPresent(db))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "lease eligibility guard missing after install attempt; refusing fence",
    );
  }
}

/**
 * Best-effort removal of partial greenfield artifacts left by a mid-apply failure.
 * Does not touch wallets/destinations/sha256_hex (shared with other slices).
 */
async function dropPartialFoundation(db: SqlExecutor): Promise<void> {
  const drops = [
    `DROP TRIGGER IF EXISTS ${ELIGIBILITY_TRIGGER} ON wallet_active_leases`,
    `DROP FUNCTION IF EXISTS ${ELIGIBILITY_FUNCTION}()`,
    ...FOUNDATION_TABLES_DROP_ORDER.map((t) => `DROP TABLE IF EXISTS ${t} CASCADE`),
  ];
  for (const stmt of drops) {
    try {
      await db.query(stmt);
    } catch {
      // best-effort cleanup; surface the original apply error instead
    }
  }
}

async function applyStatements(db: SqlExecutor, statements: readonly string[]): Promise<void> {
  for (const stmt of statements) {
    if (/CREATE DOMAIN sha256_hex/i.test(stmt)) {
      try {
        await db.query(stmt);
      } catch (err) {
        if (!isAlreadyExists(err)) throw err;
      }
      continue;
    }
    await db.query(stmt);
  }
}

/**
 * Greenfield / full apply with fail-closed cleanup: any error leaves no foundation
 * tables and no fence. SqlExecutor may not be session-sticky (pool autocommit), so
 * cleanup is the portable atomicity equivalent of a single DB transaction.
 */
async function applyGreenfieldAtomically(
  db: SqlExecutor,
  statements: readonly string[],
): Promise<void> {
  try {
    await applyStatements(db, statements);
    await ensureEligibilityGuard(db, statements);
  } catch (err) {
    await dropPartialFoundation(db);
    throw err;
  }
}

async function writeFence(db: SqlExecutor): Promise<void> {
  await db.query(STATEMENTS.UPSERT_FENCE, [
    LEASE_FOUNDATION_SCHEMA_VERSION,
    new Date().toISOString(),
  ]);
}

/** Clear a stale fence so a prior fail-open cannot keep readiness green alone. */
async function clearFence(db: SqlExecutor): Promise<void> {
  if (!(await tableExists(db, "lease_schema_fence"))) return;
  try {
    await db.query(`DELETE FROM lease_schema_fence`);
  } catch {
    // best-effort
  }
}

async function auditMigrate(
  db: SqlExecutor,
  action: "LEASE_MIGRATE_EXPAND" | "LEASE_MIGRATE_REFUSED",
  details: Record<string, string | number | boolean | null>,
): Promise<void> {
  if (!(await tableExists(db, "lease_audit_events"))) return;
  const detailsText = JSON.stringify(details);
  const detailsSha = createHash("sha256").update(detailsText).digest("hex");
  await db.query(STATEMENTS.INSERT_AUDIT, [
    randomUUID(),
    action,
    null,
    null,
    null,
    null,
    null,
    null,
    detailsText,
    detailsSha,
    new Date().toISOString(),
  ]);
}

/**
 * Apply satellite tables/indexes for an already-full projection. Never skips the
 * eligibility function/trigger — those are handled by ensureEligibilityGuard.
 */
async function ensureSatelliteObjects(
  db: SqlExecutor,
  statements: readonly string[],
): Promise<void> {
  for (const stmt of statements) {
    if (/CREATE TABLE wallet_active_leases/i.test(stmt)) continue;
    if (/CREATE TRIGGER wallet_active_leases_eligibility_guard/i.test(stmt)) continue;
    if (/CREATE FUNCTION (?:lease_foundation_reject_ineligible_lease|custody_reject_ineligible_lease)/i.test(stmt)) continue;
    if (/CREATE DOMAIN sha256_hex/i.test(stmt)) {
      try {
        await db.query(stmt);
      } catch (err) {
        if (!isAlreadyExists(err)) throw err;
      }
      continue;
    }
    if (/^CREATE TABLE /i.test(stmt) || /^CREATE (UNIQUE )?INDEX /i.test(stmt)) {
      try {
        await db.query(stmt);
      } catch (err) {
        if (!isAlreadyExists(err)) throw err;
      }
      continue;
    }
    // Additive ALTERs / DO blocks (e.g. child_disposition on pre- foundations).
    if (/^ALTER TABLE /i.test(stmt) || /^DO\s+\$/i.test(stmt)) {
      try {
        await db.query(stmt);
      } catch (err) {
        if (!isAlreadyExists(err)) throw err;
      }
    }
  }
}

/** confrelid::regclass text → bare relation name (strip optional schema qualify). */
function bareRelation(regclass: string): string {
  const trimmed = regclass.trim().replace(/^"/, "").replace(/"$/, "");
  const parts = trimmed.split(".");
  const leaf = parts[parts.length - 1] ?? trimmed;
  return leaf.replace(/^"/, "").replace(/"$/, "");
}

/**
 * FK targets currently declared on wallet_active_leases (public schema).
 * Used to detect the custody-schema projection that ships fencing columns
 * without the foundation membership/group FKs.
 */
async function listActiveLeaseFkTargets(db: SqlExecutor): Promise<Set<string>> {
  const result = await db.query<{ ref_table: string }>(
    `SELECT c.confrelid::regclass::text AS ref_table
       FROM pg_constraint c
      WHERE c.conrelid = to_regclass('wallet_active_leases')
        AND c.contype = 'f'`,
  );
  return new Set(result.rows.map((r) => bareRelation(r.ref_table)));
}

async function hasRequiredFoundationFks(db: SqlExecutor): Promise<boolean> {
  const targets = await listActiveLeaseFkTargets(db);
  return targets.has("wallet_lease_memberships") && targets.has("lease_groups");
}

async function tryAddFk(
  db: SqlExecutor,
  constraintName: string,
  ddl: string,
): Promise<void> {
  try {
    await db.query(ddl);
  } catch (err) {
    if (isAlreadyExists(err)) return;
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      `cannot install ${constraintName} on wallet_active_leases (${errMessage(err)}); refusing fence`,
    );
  }
}

/**
 * Install foundation referential integrity on an already-full fencing-column projection.
 *
 * Custody (custody schema PK spelling) creates wallet_active_leases with full fencing columns but only a
 * wallets(id) FK. lease-foundation.sql's CREATE TABLE carries membership + group FKs;
 * ensureSatelliteObjects skips that CREATE when the table already exists. Without this
 * step the migrator would write the fence on an under-constrained projection and orphan
 * membership_id / lease_group_id inserts would succeed.
 *
 * Empty projection missing foundation FKs: DROP + recreate from foundation CREATE so the
 * live table matches lease-foundation.sql, then re-attach wallets(id) when present.
 * Populated projection: ADD CONSTRAINT only (never DROP live lease rows).
 */
async function ensureActiveLeaseFoundationFks(
  db: SqlExecutor,
  statements: readonly string[],
): Promise<void> {
  if (!(await tableExists(db, "wallet_active_leases"))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "wallet_active_leases missing while installing foundation FKs",
    );
  }

  // Satellites must exist before FK ADD (membership/group parents).
  if (!(await tableExists(db, "wallet_lease_memberships"))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "wallet_lease_memberships missing; satellites must land before foundation FKs",
    );
  }
  if (!(await tableExists(db, "lease_groups"))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "lease_groups missing; satellites must land before foundation FKs",
    );
  }

  let targets = await listActiveLeaseFkTargets(db);
  const needMembership = !targets.has("wallet_lease_memberships");
  const needGroup = !targets.has("lease_groups");
  const walletsPresent = await tableExists(db, "wallets");
  const needWallet = walletsPresent && !targets.has("wallets");

  if (!needMembership && !needGroup && !needWallet) return;

  const liveRows = await countActiveRows(db);

  if ((needMembership || needGroup) && liveRows === 0) {
    const createActive = pickStatement(
      statements,
      /CREATE TABLE wallet_active_leases/i,
      "CREATE TABLE wallet_active_leases",
    );
    await db.query(
      `DROP TRIGGER IF EXISTS ${ELIGIBILITY_TRIGGER} ON wallet_active_leases`,
    );
    await db.query(`DROP TABLE wallet_active_leases`);
    try {
      await db.query(createActive);
    } catch (err) {
      throw new LeaseError(
        "SCHEMA_NOT_READY",
        `cannot recreate wallet_active_leases from foundation SQL (${errMessage(err)}); refusing fence`,
      );
    }
    // Indexes dropped with the table — re-apply via satellite pass is caller's job when
    // they re-enter ensureSatelliteObjects; do the operation index here from statements.
    for (const stmt of statements) {
      if (/CREATE (UNIQUE )?INDEX .*wallet_active_leases/i.test(stmt)) {
        try {
          await db.query(stmt);
        } catch (err) {
          if (!isAlreadyExists(err)) throw err;
        }
      }
    }
    targets = await listActiveLeaseFkTargets(db);
  } else if (needMembership || needGroup) {
    if (needMembership) {
      await tryAddFk(
        db,
        "wallet_active_leases_membership_id_fkey",
        `ALTER TABLE wallet_active_leases
           ADD CONSTRAINT wallet_active_leases_membership_id_fkey
           FOREIGN KEY (membership_id) REFERENCES wallet_lease_memberships (id)`,
      );
    }
    if (needGroup) {
      await tryAddFk(
        db,
        "wallet_active_leases_lease_group_id_fkey",
        `ALTER TABLE wallet_active_leases
           ADD CONSTRAINT wallet_active_leases_lease_group_id_fkey
           FOREIGN KEY (lease_group_id) REFERENCES lease_groups (id)`,
      );
    }
    targets = await listActiveLeaseFkTargets(db);
  }

  if (walletsPresent && !targets.has("wallets")) {
    await tryAddFk(
      db,
      "wallet_active_leases_wallet_id_fkey",
      `ALTER TABLE wallet_active_leases
         ADD CONSTRAINT wallet_active_leases_wallet_id_fkey
         FOREIGN KEY (wallet_id) REFERENCES wallets (id)`,
    );
  }

  if (!(await hasRequiredFoundationFks(db))) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      "wallet_active_leases missing membership/group foundation FKs after install; refusing fence",
    );
  }
}

/**
 * Apply the lease foundation. Safe to re-run. Throws LeaseError LEGACY_POPULATED when the
 * three-column projection still holds rows. Throws SCHEMA_NOT_READY when the receive-gate enforcement guard
 * cannot be installed (e.g. wallets relation missing) — never fences without the guard.
 */
export async function migrateLeaseFoundation(db: SqlExecutor): Promise<MigrateResult> {
  const sql = loadFoundationSql();
  const statements = splitSqlStatements(sql);
  const hasActive = await tableExists(db, "wallet_active_leases");

  if (!hasActive) {
    await applyGreenfieldAtomically(db, statements);
    try {
      await ensureActiveLeaseFoundationFks(db, statements);
    } catch (err) {
      await clearFence(db);
      await dropPartialFoundation(db);
      throw err;
    }
    await writeFence(db);
    await auditMigrate(db, "LEASE_MIGRATE_EXPAND", {
      path: "greenfield",
      schema_version: LEASE_FOUNDATION_SCHEMA_VERSION,
    });
    return { status: "applied_greenfield", schemaVersion: LEASE_FOUNDATION_SCHEMA_VERSION };
  }

  const columns = await listActiveColumns(db);

  if (isFullColumnSet(columns)) {
    await ensureSatelliteObjects(db, statements);
    try {
      // The fencing columns alone are not enough: the custody schema ships them without
      // membership/group FKs. Install (or verify) those before any fence write.
      await ensureActiveLeaseFoundationFks(db, statements);
      await ensureEligibilityGuard(db, statements);
    } catch (err) {
      await clearFence(db);
      throw err;
    }
    if (!(await hasRequiredFoundationFks(db))) {
      await clearFence(db);
      throw new LeaseError(
        "SCHEMA_NOT_READY",
        "wallet_active_leases foundation FKs absent after full-column path; refusing fence",
      );
    }
    await writeFence(db);
    return { status: "already_current", schemaVersion: LEASE_FOUNDATION_SCHEMA_VERSION };
  }

  if (!isLegacyThreeColumn(columns)) {
    throw new LeaseError(
      "SCHEMA_NOT_READY",
      `wallet_active_leases has unrecognized columns [${columns.join(",")}]; refusing automatic reshape`,
    );
  }

  const liveRows = await countActiveRows(db);
  if (liveRows > 0) {
    await auditMigrate(db, "LEASE_MIGRATE_REFUSED", {
      path: "legacy_populated",
      live_rows: liveRows,
    });
    throw new LeaseError(
      "LEGACY_POPULATED",
      `wallet_active_leases holds ${liveRows} legacy row(s); verified evacuation/quarantine required before foundation expand`,
    );
  }

  // Empty legacy: drop projection + prior eligibility trigger, then apply full foundation.
  // Fail-closed: if apply/guard fails after DROP, restore is impossible without re-running
  // custody DDL; surface SCHEMA_NOT_READY and leave no fence. Partial satellite tables from
  // a prior attempt are absorbed by ensureSatelliteObjects / CREATE IF patterns.
  await db.query(
    `DROP TRIGGER IF EXISTS ${ELIGIBILITY_TRIGGER} ON wallet_active_leases`,
  );
  await db.query(`DROP TABLE wallet_active_leases`);

  try {
    await applyStatements(db, statements);
    await ensureActiveLeaseFoundationFks(db, statements);
    await ensureEligibilityGuard(db, statements);
  } catch (err) {
    await clearFence(db);
    // If active table is gone but satellites remain, do not leave a fence. Prefer full
    // greenfield cleanup only when wallet_active_leases is still missing so a later
    // migrate can take the greenfield path after operator repair.
    if (!(await tableExists(db, "wallet_active_leases"))) {
      await dropPartialFoundation(db);
    }
    throw err instanceof LeaseError
      ? err
      : new LeaseError(
          "SCHEMA_NOT_READY",
          `empty-legacy expand failed (${errMessage(err)}); foundation not fenced`,
        );
  }

  await writeFence(db);
  await auditMigrate(db, "LEASE_MIGRATE_EXPAND", {
    path: "empty_legacy",
    schema_version: LEASE_FOUNDATION_SCHEMA_VERSION,
  });
  return { status: "expanded_empty_legacy", schemaVersion: LEASE_FOUNDATION_SCHEMA_VERSION };
}
