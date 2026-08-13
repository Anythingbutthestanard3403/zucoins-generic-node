/**
 * ordered Layer-1 money schema pack for production migrators.
 *
 * Governing: the data model (including the receive barriers), node-core startup, and the
 * migration lock / classifier discipline;
 * schema/CONVENTIONS.md migration naming + journal rules.
 *
 * Contract `.sql` slices under this directory are the authoritative DDL. The
 * generic-node composition root feeds them into `runMigrations` as
 * `MigrationFile[]` (AC2 path b) — one production owner through
 * `schema_migrations`. Reporting 0000/0001 are the journal prefix owned by
 * apps/generic-node; this pack deliberately omits tables already materialised
 * by the reporting-persistence twin (nodes, implementers, reporting_*).
 *
 * Catalog ownership:
 * - Generic-node drizzle `0000_reporting_persistence` owns the shared reference domains
 * (`sha256_hex`, `padded_base64url_*`), the three reporting enums occupying
 * those tables, and the reporting helper functions when it is applied first
 * (production combined boot).
 * - Pack slice `base-enums-domains` owns the FULL floor foundations (those shared
 * names plus money-only domains/enums) for a standalone money-schema deploy
 * that never runs the reporting prefix.
 * - Slices after the first owner may re-declare domains/types/functions so each
 * file stays greenfield-alone readable; `loadMoneySchemaMigrations` strips any
 * CREATE that a prior unit (reporting seed and/or earlier pack slice) already
 * registered so a combined apply does not fail with SQLSTATE 42710.
 * CREATE TABLE name already registered by a prior owner is stripped (avoids
 * 42710). When a deliberately allow-listed later body declares inline REFERENCES
 * the first owner did not, the loader appends idempotent ALTER TABLE … ADD CONSTRAINT
 * wire-up. Trigger name conflicts keep the
 * first owner's attachment; a later CREATE FUNCTION that would only have been
 * attached by a stripped same-slice trigger is not emitted (no orphans).
 *
 * Multi-slice tables in this pack (closed compatibility allow-list):
 * - wallet_active_leases: custody-eligibility is the production owner; lease-foundation's
 * duplicate body is retained only for the standalone fail-closed lease migrator. Missing
 * membership/group refs are wired during assembly; operation refs are fix-forwarded by the
 * appended lease-operation-foreign-keys slice after operations exists.
 * - operation_expected_artifacts: single owner expected-artifacts.sql (stronger FKs +
 * insert-only trigger). move-baseline-binding must not re-CREATE the table.
 * - operator_device_keys: device-keys first; approval-stores CREATE stripped
 * (bodies equivalent).
 *
 * Journal identity (D3): pack versions are 100 + index into MONEY_SCHEMA_PACK_ORDER.
 * runMigrations keys schema_migrations by version integer only. GO-LIVE is cold-first;
 * any ambient DB that applied a pre- pack at the same version numbers is toxic
 * (skip colliding versions; never re-apply reordered slices). Prefer wipe + cold apply.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  formatMigrationName,
  type MigrationFile,
} from "../data/migrations.js";

const moduleDir = dirname(fileURLToPath(import.meta.url));

/**
 * Contract `.sql` files live in `src/schema`. Vitest loads this module from
 * `src/`; the compiled package loads it from `dist/schema` and must walk back
 * to `src/schema` (or每个 ship a copy beside the compiled JS).
 */
function resolveSchemaDir(): string {
  if (existsSync(join(moduleDir, "base-enums-domains.sql"))) return moduleDir;
  const srcTwin = join(moduleDir, "..", "..", "src", "schema");
  if (existsSync(join(srcTwin, "base-enums-domains.sql"))) return srcTwin;
  throw new Error(
    `money-schema-pack: cannot locate base-enums-domains.sql beside ${moduleDir}`,
  );
}

const here = resolveSchemaDir();

/**
 * Dependency order for a greenfield money-path apply AFTER reporting 0000/0001. // contract-allow:order:frozen structural vocabulary
 * Versions start at 100 so 0000–0099 remain free for the reporting journal prefix
 * owned by the generic-node composition root.
 */
export const MONEY_SCHEMA_PACK_ORDER = [
  "base-enums-domains",
  // node_signing_keys is NOT in reporting 0000 (only implementer_reporting_keys is).
  // Included so event-ledger FKs resolve after the reporting prefix; afterReportingPrefix
  // strips the co-declared implementer_reporting_keys TABLE that 0000 already owns.
  "signing-key-registry",
  "custody-eligibility",
  "vault",
  "operations",
  "event-ledger",
  "implementer-event-stream",
  "audit-log",
  "implementer-credentials",
  "observation-ledger",
  "observation-anomaly-indexes",
  "observation-stores",
  "proof-body-store",
  "expected-artifacts",
  "receive-admission",
  "receive-codes",
  "receive-arms",
  "receive-external-landing",
  "receive-expiry-release",
  "send-external-create",
  "send-external-landing",
  "send-external-expiry",
  // approval before transaction-material (operation_approvals FK); transaction-material
  // before submit-attempts (operation_transactions FK). cold-apply ordering.
  "device-keys",
  "device-enrollment-challenges",
  "approval-stores",
  "transaction-material",
  "submit-attempts",
  "move-baseline-binding",
  "move-observation-evidence",
  "lease-foundation",
  "signer-support",
  "operational-stores",
  "session-subscription-stores",
  "verification-access-windows",
  "wallet-settled-ledger",
  "privileges",
  // seal-write runtime table for NODE_SIGNING_KEYS (appended — version-stable).
  "node-signing-key-sealed-store",
  // retained-body successor-lookup indexes on gateway_observations, pure index
  // extension (appended — version-stable, no new table/column).
  "gateway-observation-successor-indexes",
  // per-wallet Web Push subscriptions (channel 1). Appended so existing
  // pack versions stay stable; FK target `wallets` is created by the custody-eligibility
  // slice far earlier in this order. // contract-allow:order:frozen structural vocabulary
  "push-subscriptions",
  // two nullable columns on the frozen operations.sql contract, moved out of a
  // runtime ALTER in start-money-workers.ts. Appended so existing pack versions stay stable.
  "operations-response-columns",
  // node_id column on the frozen admin_sessions contract
  // (session-subscription-stores.sql), moved out of a runtime ALTER in
  // admin-session-sql-store.ts. Appended so existing pack versions stay stable.
  "admin-sessions-node-id",
  // shared pre-burn reporting limiter state. Appended; never renumber prior slices.
  "reporting-security-ports",
  // operation_landing_proofs + operation_verifications
  //, unblocking wallet_settled_ledger's landed-verbatim trigger. FK targets
  // (operations, operation_transactions, observers, gateway_observations) all appear
  // earlier above. Appended so existing pack versions stay stable.
  "landing-proof-verifications",
  // fix-forward PK collapse of reporting_rate_limit_buckets (already live on main
  // in production). Appended; never renumber prior slices.
  "reporting-rate-limit-buckets-pk-collapse",
  // fix-forward node_events PK from (seq) to (node_id, seq). Greenfield
  // event-ledger.sql already emits the composite key; this ALTER rewrites already-applied
  // databases. Appended; never renumber prior slices. Deploy before multi-node landed
  // dual-chain appends on any shared-DB topology.
  "node-events-seq-composite-pk",
  // lineage_path_proofs + lineage_path_bodies — the verification-material source-sql
  // joins need them once operation_landing_proofs exists.
  // Appended; never renumber prior slices. FK target is landing-proof-verifications.
  "lineage-path-proofs",
  // verification_acknowledgements + ack wallet evidence, required by the live
  // verification-complete mount. Appended; never renumber prior slices.
  "verification-acknowledgements",
  // vault_root_kdf_salt — the per-node PBKDF2 salt the vault root key is derived under,
  // persisted beside the `vault` envelopes it opens (ZTR-1159). Self-contained (no FK,
  // re-declares the shared immutability trigger function), so its position is not
  // dependency-forced. Appended; never renumber prior slices.
  "vault-root-kdf-salt",
  // The deferred parent/child correlation guard (frozen in verification-proofs.sql, which
  // is contract-only and excluded from this pack). Attaches to reporting_mutation_idempotency,
  // receive_arms and verification_acknowledgements, so it must follow all three.
  // Appended; never renumber prior slices.
  "mutation-correlation",
  // wallet_settled_ledger's per-wallet index, a pure index extension on a table created
  // far earlier above (whose own file is already applied, so its sql_sha256 must not
  // change). Appended; never renumber prior slices.
  "wallet-settled-ledger-indexes",
  // operations worker-poll partial indexes, a pure index extension on a table created
  // far earlier above (whose own file is already applied, so its sql_sha256 must not
  // change). Appended; never renumber prior slices. Depends on receive-expiry-release
  // for the receive_release_status column used by one partial predicate.
  "operations-indexes",
  // observation_relationship_adjudications — complete-path derived relationship store
  // (doc 04 §11). Appended after lineage-path-proofs FK target; never renumber prior slices.
  "observation-relationship-adjudications",
  // destinations.label column (GN-025.2). Pure column extension on custody destinations.
  // Appended; never renumber prior slices.
  "destinations-label",
  // lease_role text→wallet_lease_role enum on active leases + memberships. Value-preserving
  // USING cast for already-applied DBs; cold CREATE already uses the enum. Appended.
  "lease-role-enum",
  // BEFORE UPDATE/DELETE/TRUNCATE byte-immutability guards on external_send_sign_intents,
  // operation_transactions, and external_send_partials (doc 04 §9 / 04:760-767). Tables are
  // created by transaction-material earlier in the pack; this slice only attaches triggers.
  // Appended so earlier money-pack version numbers stay stable. Never renumber prior slices.
  "transaction-material-byte-immutability",
  // ZTR-1139 fix-forward for databases that already journaled custody/lease-foundation
  // before the operations FKs were present. Checks all four relations for dangling rows
  // before adding any constraint, then installs explicit NO ACTION FKs. Appended only.
  "lease-operation-foreign-keys",
  // operations.attention_reason (+ send_operations) text → attention_reason enum (ZTR-1147).
  // Value-preserving USING cast after free-text purge for already-applied DBs. Appended.
  "attention-reason-enum",
  // Dual-control policy durable home (ZTR-1214). Pins pack sequence after node_settings +
  // audit_log; does not seed a default (boot env remains pre-mutation truth). Appended.
  "dual-control-policy",
  // approval_method += AUTO_POLICY (ZTR-1233). Own slice so ADD VALUE commits before
  // the three-arm CHECK references the label. Appended only.
  "approval-method-auto-policy-enum",
  // approval-stores AUTO_POLICY method arm (ZTR-1233). Greenfield CREATE already has the
  // three-arm shape; this ALTER converges already-applied DBs. Appended only.
  "approval-stores-auto-policy",
  // Platform-initiated integration request store (ZTR-1238). Durable PENDING→…→CLAIMED
  // handshake; FK targets nodes/implementers/implementer_credentials (all earlier).
  // Appended; never renumber prior slices.
  "integration-requests",
  // ZTR-1249: stamp terminal_at on EXPIRED ops left NULL by queue-age expiry.
  // Pure data fix-forward on operations; appended only.
  "operations-expired-terminal-at-backfill",
  // ZTR-1250: clear sticky attention on already-landed ops. Appended only.
  "operations-landed-attention-clear-backfill",
  // ZTR-1267: per-wallet money capability columns on wallets (allow flags + money_mode +
  // row_version). Pure ALTER on custody-eligibility wallets; defaults FULL. Appended only.
  "wallet-money-capability",
  // ZTR-1268: replace custody_reject_ineligible_lease body so lease claim re-checks
  // allow_* flags in-TX. Requires wallet-money-capability columns. Appended only.
  "wallet-money-capability-lease-guard",
] as const;

export type MoneySchemaPackSlice = (typeof MONEY_SCHEMA_PACK_ORDER)[number];

/** First pack version number (reporting prefix uses 0..). */
export const MONEY_SCHEMA_PACK_VERSION_BASE = 100 as const;

/** Schema directory absolute path (tests and runners share it). */
export const MONEY_SCHEMA_DIR = here;

/**
 * Catalog objects materialised by generic-node drizzle 0000_reporting_persistence
 * (and its node-core twin) that pack slices also re-declare for standalone apply.
 * Audited against reporting 0000 + 0001 vs all MONEY_SCHEMA_PACK_ORDER
 * CREATE DOMAIN / TYPE / FUNCTION names — table overlap is already excluded via
 * MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING.
 */
export const REPORTING_PREFIX_OWNED_CATALOG = {
  domains: [
    "sha256_hex",
    "padded_base64url_pubkey",
    "padded_base64url_signature",
  ],
  types: [
    "reporting_key_state",
    "reporting_key_lifecycle_event_type",
    "reporting_request_class",
  ],
  functions: [
    "reporting_logical_fingerprint",
    "reporting_reject_immutable_change",
    "reporting_guard_lifecycle_head_update",
    "reporting_assert_lifecycle_event",
    "reporting_validate_lifecycle_deferred",
    "reporting_advance_lifecycle_head",
    "reporting_lock_and_assert_admission",
  ],
  /** CREATE TABLE names materialised by drizzle 0000 (+ 0001 has none new). */
  tables: [
    "nodes",
    "implementers",
    "implementer_reporting_keys",
    "reporting_key_bootstrap_evidence",
    "reporting_nonce_burn_counters",
    "reporting_request_nonces",
    "reporting_key_enrolment_evidence",
    "reporting_key_lifecycle_states",
    "reporting_key_lifecycle_events",
    "reporting_key_state_transitions",
    "reporting_key_lifecycle_heads",
    "reporting_mutation_idempotency",
    "reporting_restore_state",
  ],
} as const;

export interface CatalogObjectSets {
  readonly domains: ReadonlySet<string>;
  readonly types: ReadonlySet<string>;
  readonly functions: ReadonlySet<string>;
  readonly tables: ReadonlySet<string>;
  readonly triggers: ReadonlySet<string>;
}

export interface MutableCatalogObjectSets {
  domains: Set<string>;
  types: Set<string>;
  functions: Set<string>;
  tables: Set<string>;
  triggers: Set<string>;
}

/**
 * Inline foreign key extracted from a CREATE TABLE body (column-level REFERENCES
 * or table-level FOREIGN KEY (…) REFERENCES …).
 */
export interface InlineForeignKey {
  readonly columns: readonly string[];
  readonly refTable: string;
  readonly refColumns: readonly string[];
}

/** Snapshot of catalog names already present before a pack slice runs. */
export function emptyCatalogObjectSets(): MutableCatalogObjectSets {
  return {
    domains: new Set(),
    types: new Set(),
    functions: new Set(),
    tables: new Set(),
    triggers: new Set(),
  };
}

/** Seed sets with reporting-prefix owned names (combined generic-node boot). */
export function catalogSetsSeededFromReportingPrefix(): MutableCatalogObjectSets {
  return {
    domains: new Set(REPORTING_PREFIX_OWNED_CATALOG.domains),
    types: new Set(REPORTING_PREFIX_OWNED_CATALOG.types),
    functions: new Set(REPORTING_PREFIX_OWNED_CATALOG.functions),
    tables: new Set(REPORTING_PREFIX_OWNED_CATALOG.tables),
    triggers: new Set(),
  };
}

// Fresh RegExp per call — global flags advance lastIndex across invocations.
function domainRe(): RegExp {
  return /^CREATE\s+DOMAIN\s+(\w+)\s+AS[\s\S]*?;\s*$/gim;
}
function typeEnumRe(): RegExp {
  return /^CREATE\s+TYPE\s+(\w+)\s+AS\s+ENUM\s*\([\s\S]*?\)\s*;\s*$/gim;
}
function typeOtherRe(): RegExp {
  return /^CREATE\s+TYPE\s+(\w+)\s+AS[^;]*;\s*$/gim;
}
function functionRe(): RegExp {
  // Body is $$ … $$; LANGUAGE may appear before AS $$ or after the closing $$.
  return /^CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(\w+)\s*\([\s\S]*?\$\$[\s\S]*?\$\$\s*(?:LANGUAGE\s+\w+\s*)?;\s*$/gim;
}
function triggerRe(): RegExp {
  // CREATE [CONSTRAINT] TRIGGER name ... EXECUTE {FUNCTION|PROCEDURE} ... ;
  return /^CREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+(\w+)\s+[\s\S]*?;\s*$/gim;
}

function collectMatches(sql: string, re: RegExp): string[] {
  const names: string[] = [];
  for (const match of sql.matchAll(re)) {
    names.push(match[1].toLowerCase());
  }
  return names;
}

/**
 * Walk `CREATE TABLE [IF NOT EXISTS] name (` … balanced `);` statements.
 * Returns {name, full, start} for each statement (name lowercased).
 */
export function findCreateTableStatements(
  sql: string,
): readonly { readonly name: string; readonly full: string; readonly start: number }[] {
  const out: { name: string; full: string; start: number }[] = [];
  const head = /CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(\w+)\s*\(/gi;
  let match: RegExpExecArray | null;
  while ((match = head.exec(sql)) !== null) {
    const name = match[1].toLowerCase();
    const start = match.index;
    const openParenIdx = match.index + match[0].length - 1;
    let depth = 0;
    let i = openParenIdx;
    for (; i < sql.length; i += 1) {
      const ch = sql[i];
      if (ch === "(") depth += 1;
      else if (ch === ")") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (depth !== 0) continue;
    let end = i + 1;
    while (end < sql.length && /\s/.test(sql[end])) end += 1;
    if (sql[end] === ";") end += 1;
    while (end < sql.length && (sql[end] === "\n" || sql[end] === "\r")) end += 1;
    out.push({ name, full: sql.slice(start, end), start });
    head.lastIndex = end;
  }
  return out;
}

function fkKey(fk: InlineForeignKey): string {
  return `${fk.columns.join(",")}>${fk.refTable}(${fk.refColumns.join(",")})`;
}

/**
 * Extract inline FOREIGN KEY / REFERENCES from a CREATE TABLE statement body.
 * Handles column-level `col type REFERENCES t (c)` and table-level
 * `FOREIGN KEY (cols) REFERENCES t (cols)`.
 */
export function extractInlineForeignKeys(createTableSql: string): readonly InlineForeignKey[] {
  const open = createTableSql.indexOf("(");
  const close = createTableSql.lastIndexOf(")");
  if (open < 0 || close <= open) return [];
  const body = createTableSql.slice(open + 1, close);
  const out: InlineForeignKey[] = [];

  // Table-level: [CONSTRAINT name] FOREIGN KEY (a, b) REFERENCES ref (c, d)
  const tableFkRe =
    /(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)\s*\(([^)]+)\)/gi;
  for (const m of body.matchAll(tableFkRe)) {
    out.push({
      columns: m[1].split(",").map((s) => s.trim().toLowerCase()),
      refTable: m[2].toLowerCase(),
      refColumns: m[3].split(",").map((s) => s.trim().toLowerCase()),
    });
  }

  // Column-level: <colname> <type…> REFERENCES ref [(col)]
  // Walk top-level commas so nested CHECK ( … ) does not split columns.
  let depth = 0;
  let start = 0;
  const pieces: string[] = [];
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === "(") depth += 1;
    else if (ch === ")") depth -= 1;
    else if (ch === "," && depth === 0) {
      pieces.push(body.slice(start, i));
      start = i + 1;
    }
  }
  pieces.push(body.slice(start));

  for (const piece of pieces) {
    const t = piece.trim();
    if (!t || /^(?:CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b/i.test(t)) {
      continue;
    }
    const colMatch = t.match(/^(\w+)\b/);
    if (!colMatch) continue;
    const refMatch = t.match(/\bREFERENCES\s+(\w+)(?:\s*\(([^)]+)\))?/i);
    if (!refMatch) continue;
    out.push({
      columns: [colMatch[1].toLowerCase()],
      refTable: refMatch[1].toLowerCase(),
      refColumns: (refMatch[2] ?? "id")
.split(",")
.map((s) => s.trim().toLowerCase()),
    });
  }

  // Dedupe while preserving order. // contract-allow:order:frozen structural vocabulary
  const seen = new Set<string>();
  const deduped: InlineForeignKey[] = [];
  for (const fk of out) {
    const k = fkKey(fk);
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(fk);
  }
  return deduped;
}

/**
 * Idempotent ALTER TABLE … ADD CONSTRAINT wire-up for FKs present in a later
 * CREATE TABLE body but missing from the first owner's body.
 */
export function buildMissingFkWireupSql(
  tableName: string,
  missing: readonly InlineForeignKey[],
): string {
  if (missing.length === 0) return "";
  const blocks: string[] = [];
  for (const fk of missing) {
    const conname =
      fk.columns.length === 1
        ? `${tableName}_${fk.columns[0]}_fkey`
: `${tableName}_${fk.columns.join("_")}_fkey`;
    const cols = fk.columns.join(", ");
    const refCols = fk.refColumns.join(", ");
    blocks.push(`  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
      JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
     WHERE nsp.nspname = 'public'
       AND rel.relname = '${tableName}'
       AND c.conname = '${conname}'
  ) THEN
    ALTER TABLE ${tableName}
      ADD CONSTRAINT ${conname}
      FOREIGN KEY (${cols}) REFERENCES ${fk.refTable} (${refCols});
  END IF;`);
  }
  return (
    `-- Multi-slice FK wire-up for ${tableName} (later-body REFERENCES)\n` +
    `DO $money_schema_pack_fk_${tableName}$\nBEGIN\n${blocks.join("\n")}\nEND\n$money_schema_pack_fk_${tableName}$;\n`
  );
}

/** FKs in `later` that are not present (same columns→ref) in `first`. */
export function missingForeignKeys(
  first: readonly InlineForeignKey[],
  later: readonly InlineForeignKey[],
): readonly InlineForeignKey[] {
  const firstKeys = new Set(first.map(fkKey));
  return later.filter((fk) => !firstKeys.has(fkKey(fk)));
}

/**
 * EXECUTE FUNCTION name referenced by a CREATE TRIGGER statement, lowercased.
 */
export function triggerExecuteFunctionName(triggerSql: string): string | null {
  const m = triggerSql.match(
    /\bEXECUTE\s+(?:FUNCTION|PROCEDURE)\s+(\w+)\s*\(/i,
  );
  return m ? m[1].toLowerCase() : null;
}

/**
 * Strip CREATE FUNCTION statements for functions that are only referenced by
 * CREATE TRIGGER bodies in `rawSql` whose trigger names are already in `seen.triggers`
 * (those triggers were stripped). Prevents orphan unattached functions.
 */
export function stripOrphanFunctionsForStrippedTriggers(
  sqlAfterCatalogStrip: string,
  rawSql: string,
  seen: CatalogObjectSets,
): string {
  const orphanFns = new Set<string>();
  for (const match of rawSql.matchAll(triggerRe())) {
    const triggerName = match[1].toLowerCase();
    if (!seen.triggers.has(triggerName)) continue;
    const fn = triggerExecuteFunctionName(match[0]);
    if (fn) orphanFns.add(fn);
  }
  if (orphanFns.size === 0) return sqlAfterCatalogStrip;
  // Keep a function if anything remaining in the stripped SQL still references it.
  return sqlAfterCatalogStrip.replace(functionRe(), (stmt, name: string) => {
    const n = name.toLowerCase();
    if (!orphanFns.has(n)) return stmt;
    // Still referenced by an unstripped trigger / body in this slice → keep.
    const remaining = sqlAfterCatalogStrip.replace(stmt, "");
    if (new RegExp(`\\b${n}\\b`, "i").test(remaining)) return stmt;
    return "";
  });
}

/** Collect CREATE DOMAIN / TYPE / FUNCTION / TABLE / TRIGGER names declared in a SQL body. */
export function collectCatalogObjectNames(sql: string): CatalogObjectSets {
  return {
    domains: new Set(collectMatches(sql, domainRe())),
    types: new Set([
...collectMatches(sql, typeEnumRe()),
...collectMatches(sql, typeOtherRe()),
    ]),
    functions: new Set(collectMatches(sql, functionRe())),
    tables: new Set(findCreateTableStatements(sql).map((t) => t.name)),
    triggers: new Set(collectMatches(sql, triggerRe())),
  };
}

/**
 * Register every CREATE name from `sql` into `seen` (order of discovery wins; // contract-allow:order:frozen structural vocabulary
 * later re-declares are still recorded once).
 */
export function registerCatalogObjects(
  seen: MutableCatalogObjectSets,
  sql: string,
): void {
  const found = collectCatalogObjectNames(sql);
  for (const name of found.domains) seen.domains.add(name);
  for (const name of found.types) seen.types.add(name);
  for (const name of found.functions) seen.functions.add(name);
  for (const name of found.tables) seen.tables.add(name);
  for (const name of found.triggers) seen.triggers.add(name);
}

/**
 * Strip CREATE DOMAIN / TYPE / FUNCTION / TABLE / TRIGGER whose names are already in `seen`.
 * Matches multi-line ENUM bodies, AS-text domains, `$$ … $$` function bodies,
 * balanced CREATE TABLE statements, and CREATE [CONSTRAINT] TRIGGER.
 */
export function stripAlreadySeenCatalogObjects(
  sql: string,
  seen: CatalogObjectSets,
): string {
  let out = sql;
  out = out.replace(typeEnumRe(), (stmt, name: string) =>
    seen.types.has(name.toLowerCase()) ? "" : stmt,
  );
  out = out.replace(typeOtherRe(), (stmt, name: string) =>
    seen.types.has(name.toLowerCase()) ? "" : stmt,
  );
  out = out.replace(domainRe(), (stmt, name: string) =>
    seen.domains.has(name.toLowerCase()) ? "" : stmt,
  );
  out = out.replace(functionRe(), (stmt, name: string) => {
    if (!seen.functions.has(name.toLowerCase())) return stmt;
    // Body overlays (CREATE OR REPLACE) must survive pack strip so later slices can
    // upgrade a first-owner function (ZTR-1268 custody_reject_ineligible_lease).
    // Bare re-CREATE FUNCTION remains stripped.
    if (/^CREATE\s+OR\s+REPLACE\s+FUNCTION\b/i.test(stmt.trimStart())) return stmt;
    return "";
  });
  out = out.replace(triggerRe(), (stmt, name: string) =>
    seen.triggers.has(name.toLowerCase()) ? "" : stmt,
  );
  const tables = findCreateTableStatements(out);
  for (let i = tables.length - 1; i >= 0; i -= 1) {
    const t = tables[i];
    if (!seen.tables.has(t.name)) continue;
    out = out.slice(0, t.start) + out.slice(t.start + t.full.length);
  }
  return out;
}

/**
 * Strip standalone CREATE DOMAIN / CREATE TYPE that slices re-declare for
 * greenfield-alone. Matches multi-line ENUM bodies and AS-text domains.
 * Kept for unit gates that exercise bulk strip without a seen-set.
 */
export function stripRedeclaredCatalogObjects(sql: string): string {
  let out = sql;
  out = out.replace(typeEnumRe(), "");
  out = out.replace(typeOtherRe(), "");
  out = out.replace(domainRe(), "");
  return out;
}

function packFileName(index: number): string {
  const slice = MONEY_SCHEMA_PACK_ORDER[index];
  const version = MONEY_SCHEMA_PACK_VERSION_BASE + index;
  const description = slice.replace(/-/g, "_");
  return formatMigrationName(version, description);
}

export interface LoadMoneySchemaMigrationsOptions {
  /**
   * When true, seed the seen-catalog set with REPORTING_PREFIX_OWNED_CATALOG
   * before applying pack slice 0. Production generic-node `runMigrationsOnPool`
   * always passes true (reporting drizzle 0000/0001 already applied). Standalone
   * money-pack deploys leave the default false so `base-enums-domains` still
   * materialises the shared domain/enum surface.
   */
  readonly afterReportingPrefix?: boolean;
}

/**
 * Ordered MigrationFile[] for the money path. Generic-node applies reporting
 * drizzle prefix (0, 1) first, then passes `{ afterReportingPrefix: true }`.
 *
 * After name-strip of CREATE TABLE, any REFERENCES unique to the stripped later
 * body are emitted as idempotent ALTER TABLE … ADD CONSTRAINT wire-up. Orphan
 * CREATE FUNCTIONs that would only attach via a stripped same-name trigger are
 * dropped.
 */
export function loadMoneySchemaMigrations(
  options: LoadMoneySchemaMigrationsOptions = {},
): readonly MigrationFile[] {
  const seen = options.afterReportingPrefix
    ? catalogSetsSeededFromReportingPrefix()
: emptyCatalogObjectSets();
  /** First-owner CREATE TABLE body for multi-slice FK wire-up. */
  const firstTableBodies = new Map<string, string>();

  return MONEY_SCHEMA_PACK_ORDER.map((slice, index) => {
    const raw = readFileSync(join(here, `${slice}.sql`), "utf8");
    const rawTables = findCreateTableStatements(raw);

    let sql = stripAlreadySeenCatalogObjects(raw, seen);
    sql = stripOrphanFunctionsForStrippedTriggers(sql, raw, seen);

    // For every CREATE TABLE this slice tried to declare that a prior owner already
    // registered: wire missing later-body FKs onto the existing table.
    const wireups: string[] = [];
    for (const t of rawTables) {
      if (!seen.tables.has(t.name)) {
        // First owner — record body before register so later slices can diff.
        if (!firstTableBodies.has(t.name)) firstTableBodies.set(t.name, t.full);
        continue;
      }
      const firstBody = firstTableBodies.get(t.name);
      if (!firstBody) continue;
      const missing = missingForeignKeys(
        extractInlineForeignKeys(firstBody),
        extractInlineForeignKeys(t.full),
      );
      const wire = buildMissingFkWireupSql(t.name, missing);
      if (wire) wireups.push(wire);
    }
    if (wireups.length > 0) {
      sql = `${sql.trimEnd()}\n\n${wireups.join("\n")}`;
    }

    // Register CREATE names from the unstripped body so later slices know ownership.
    // First-owner table bodies recorded above for any new tables in this raw slice.
    for (const t of rawTables) {
      if (!firstTableBodies.has(t.name)) firstTableBodies.set(t.name, t.full);
    }
    registerCatalogObjects(seen, raw);
    return {
      fileName: packFileName(index),
      sql,
    };
  });
}

/** Every on-disk `*.sql` in the schema dir (census / completeness). */
export function listSchemaSqlFiles(): readonly string[] {
  return readdirSync(here)
.filter((name) => name.endsWith(".sql"))
.sort();
}

/**
 * Slices the pack omits because reporting-persistence (or its drizzle twin)
 * already owns that surface once generic-node 0000/0001 has applied.
 */
/**
 * Slices omitted from the pack because reporting-persistence (or its drizzle twin)
 * already owns that surface once generic-node 0000/0001 has applied — OR because the
 * contract carries surface a narrower pack slice ships instead (`verification-proofs.sql` is
 * contract text only: its `operation_verifications` tables are covered by
 * `landing-proof-verifications`, its acknowledgement tables by `verification-acknowledgements`,
 * and its five deferred correlation objects by `mutation-correlation` — so excluding the file
 * no longer withholds anything from a deployed database).
 */
export const MONEY_SCHEMA_PACK_EXCLUDED_AFTER_REPORTING = [
  "reporting-persistence.sql",
  "node-implementer-registry.sql",
  // signing-key-registry is IN the pack (node_signing_keys is not in reporting 0000);
  // implementer_reporting_keys CREATE is stripped via afterReportingPrefix table seed.
  "verification-proofs.sql",
] as const;
