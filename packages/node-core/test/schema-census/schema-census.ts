// Automated schema-to-specification traceability census.
// Four failure classes:
//   1. missing_store   — normative durable fact has no table/column
//   2. orphan_fk       — FK target table/column missing, or no producer path
//   3. unsafe_cascade  — ON DELETE/UPDATE CASCADE into a evidence table
//   4. unindexed_query — worker access pattern lacks a supporting index
//
// Direction is SPECIFICATION → SCHEMA (reverse traversal); the inverse direction is a
// separate drift gate and is not reused here. Output is a machine-checkable report enumerating
// every noun checked, its satisfier (or NONE), and every failure with its class.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  GOVERNING_DOCS,
  NORMATIVE_NOUNS,
  SPEC_TABLE_DISPOSITIONS,
  WORKER_ACCESS_PATTERNS,
  deriveEvidenceTables,
  type NormativeNoun,
  type SpecTableDisposition,
} from "./normative-manifest.ts";
import {
  parseSchemaFromMap,
  parseSchemaSql,
  type ForeignKey,
  type IndexDef,
  type SchemaModel,
} from "./schema-ddl.ts";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "../..");
const repoRoot = resolve(packageRoot, "../..");
const defaultSchemaDir = resolve(packageRoot, "src/schema");

export const CENSUS_REPORT_PATH = resolve(here, "schema-census.report.json");

export type FailureClass =
  | "missing_store"
  | "orphan_fk"
  | "unsafe_cascade"
  | "unindexed_query"
  | "excluded_present"
  | "docs_unread"
  /** CREATE TABLE in a governing doc with no SPEC_TABLE_DISPOSITIONS row (A1/B1). */
  | "undispositioned_spec_table"
  /** SPEC_TABLE_DISPOSITIONS entry whose table no longer appears in governing docs. */
  | "stale_spec_disposition";

export interface NounResult {
  readonly id: string;
  readonly noun: string;
  readonly disposition: NormativeNoun["disposition"];
  readonly sources: NormativeNoun["sources"];
  /** Satisfying schema object, or "NONE". */
  readonly satisfiedBy: string;
  readonly retentionClass?: string;
  readonly authority?: string;
  readonly ok: boolean;
  readonly failureClass?: FailureClass;
  readonly detail?: string;
}

export interface CensusFailure {
  readonly class: FailureClass;
  readonly id: string;
  readonly detail: string;
}

export interface CensusReport {
  readonly schema: "generic-node-redesign-v2";
  readonly censusId: "generic-node-schema-census";
  readonly docsRead: readonly string[];
  readonly schemaFiles: readonly string[];
  readonly summary: {
    readonly nounsChecked: number;
    readonly nounsOk: number;
    readonly nounsFailed: number;
    readonly foreignKeysChecked: number;
    readonly accessPatternsChecked: number;
    readonly failureCount: number;
    readonly byClass: Record<FailureClass, number>;
  };
  readonly nouns: readonly NounResult[];
  readonly failures: readonly CensusFailure[];
  readonly foreignKeys: readonly {
    readonly source: string;
    readonly target: string;
    readonly onDelete: string;
    readonly onUpdate: string;
    readonly ok: boolean;
    readonly detail?: string;
  }[];
  readonly accessPatterns: readonly {
    readonly id: string;
    readonly table: string;
    readonly columns: readonly string[];
    readonly satisfiedBy: string;
    readonly ok: boolean;
  }[];
}

export interface BuildCensusOptions {
  readonly schemaDir?: string;
  readonly repoRoot?: string;
  /** Override schema SQL map (negative-path injection). */
  readonly sqlByFile?: ReadonlyMap<string, string>;
  /** Override nouns (negative-path injection). */
  readonly nouns?: readonly NormativeNoun[];
  /** Override access patterns. */
  readonly accessPatterns?: readonly (typeof WORKER_ACCESS_PATTERNS)[number][];
  /** Override evidence table set. */
  readonly evidenceTables?: readonly string[];
  /** Override SPEC_TABLE_DISPOSITIONS (negative-path / unit injection). */
  readonly specTableDispositions?: readonly SpecTableDisposition[];
  /**
   * When true, skip the CREATE TABLE ↔ disposition set-equality guard
   * (negative-path tests that inject partial schemas only).
   */
  readonly skipSpecTableDispositionCheck?: boolean;
  /**
   * Producer inventory: tables that any non-test code path INSERTs into.
   * When omitted, scanned from packages/node-core/src.
   */
  readonly producerTables?: ReadonlySet<string>;
  /**
   * Tables whose absence of a TypeScript INSERT path is expected (schema-only
   * slices not yet wired, or pure DDL foundations). Orphan-FK "never populated"
   * arm skips these as sources AND does not require them as producer targets
   * when they are only referenced.
   */
  readonly producerExemptTables?: ReadonlySet<string>;
  /**
   * FK target column aliases accepted when the frozen custody contract renamed
   * a PK (04 drafts wallets(id).2 freezes wallets(wallet_id)).
   * Map: "table.requestedCol" → "actualCol".
   */
  readonly columnAliases?: ReadonlyMap<string, string>;
  /** When true, deferred nouns fail if unsatisfied (negative-path mode). */
  readonly failDeferred?: boolean;
}

const DEFAULT_COLUMN_ALIASES = new Map<string, string>([
  // Custody re-shape: the draft used `id`; the frozen contract uses wallet_id / destination_id.
  ["wallets.id", "wallet_id"],
  ["destinations.id", "destination_id"],
]);

/**
 * Tables that are schema-contract-only today (DDL landed; write path is a later
 * slice) OR pure registry seeds outside packages/node-core/src. break B3:
 * money-path / evidence FK targets MUST NOT appear here — they prove producers via
 * SQL INSERT scan, store-wrapper detection, or DECLARED_PRODUCERS.
 *
 * Keep this set small. A NEW FK target without INSERT/declaration fails closed.
 */
export const DEFAULT_PRODUCER_EXEMPT = new Set<string>([
  // Support stores — DDL only; writers are later slices.
  "signer_audit",
  "destination_blessing_artifacts",
  "recovery_nonces",
  "totp_timestep_burns",
  "api_rate_buckets",
  "auth_failure_state",
  "node_settings",
  "operator_halts",
  "worker_cursors",
  // B1 session/subscription stores — shape landed; issue/refresh writers later.
  "subscription_handles",
  "admin_sessions",
  // access-window RECORD shape; issue writer is the
  // InMemoryVerificationAccessWindowStore port (api/verification-access.ts). Durable
  // INSERT lands in The durable-schema slice behind the same seam — not money-path heat.
  "verification_material_access_windows",
  // Registry / reporting foundation (wired by later GN slices; no money-path FK heat).
  "nodes",
  "implementers",
  "implementer_reporting_keys",
  "node_signing_keys",
  "reporting_request_nonces",
  "reporting_nonce_burn_counters",
  "reporting_key_bootstrap_evidence",
  "reporting_key_enrolment_evidence",
  "reporting_key_lifecycle_states",
  "reporting_key_lifecycle_events",
  "reporting_key_state_transitions",
  "reporting_key_lifecycle_heads",
  "reporting_mutation_idempotency",
  "reporting_restore_state",
  "node_event_seq_counters",
  // Observation registry row — seeded at boot, not via packages/node-core INSERT yet.
  "observers",
  // Approval + verification DDL landed (approval-stores / verification-proofs); writers
  // are approval/verification flow slices. Not money-path producer-exempt by B3 — challenges
  // and approvals are pre-lease; verification rows are post-landing evidence writers.
  "approval_challenges",
  "operation_approvals",
  "operation_verifications",
  "verification_acknowledgements",
  "verification_ack_wallet_evidence",
]);

/**
 * Explicit producer declarations for tables whose runtime writer goes through a
 * store-port / seam rather than a literal `INSERT INTO <table>` in src (or whose
 * SQL writer lands in a later slice but the table is already an FK target that
 * must not be blanket-exempt). Each entry is a fail-closed admission: removing
 * the writer without removing the declaration is a docs problem; removing the
 * declaration without a detectable INSERT fails the producer arm.
 *
 * Money-path / evidence tables listed here (wallets, destinations, audit_log,
 * operation_transactions, external_send_*, operator_device_keys, …) are the B3
 * clear condition — they are NOT in DEFAULT_PRODUCER_EXEMPT.
 */
export const DECLARED_PRODUCERS: Readonly<Record<string, string>> = {
  // Port + in-memory adapter today; durable INSERT is The durable-schema slice behind the same seam.
  wallets:
    "core/recovery + custody create path (wallets row is prerequisite of every money FK; durable INSERT in The durable-schema slice wallet-create slice)",
  destinations:
    "POST /v1/destinations create path (api route inventory); durable INSERT in The durable-schema slice destination-create slice",
  wallet_recovery_verifications:
    "core/recovery/types.ts LiveDb seam — INSERT on wallet_recovery_verifications during recovery ceremony",
  audit_log:
    "core/audit-writer.ts AuditLogStore.append (insert-only port; durable adapter INSERT under id UNIQUE)",
  operator_device_keys:
    "device/enrollment.ts → DeviceKeyStore.insert (store.ts port; durable adapter INSERT under UNIQUE(node_id, public_key))",
  device_enrollment_challenges:
    "device/challenge.ts EnrollmentChallengeStore.insert (issue path for zp-device-enrol-v1)",
  operation_transactions:
    "transaction-material / send completion path (exact-content; chaos + submit harnesses exercise INSERT)",
  external_send_sign_intents:
    "send-external create path (sign-intent formation; durable INSERT on the send-completion path)",
  external_send_partials:
    "workers/send-completion-monitor.ts reads persisted partials; writer is external-send sign completion",
  operation_wallets:
    "operator/sql-store + operations join table (operation↔wallet binding on create)",
};

/**
 * Cross-slice FK targets that the frozen contracts reference but whose CREATE TABLE
 * lives in a not-yet-landed sibling lane (e.g. operation_approvals). These are
 * emitted in the report as acknowledged_orphan_fk and do NOT fail the live gate; a NEW
 * unpinned orphan still fails. When the target table lands, remove the pin — the
 * stale-pin test goes red if the orphan disappears while the pin remains.
 */
// operation_landing_proofs landed (landing-proof-verifications.sql), so the
// verification-proofs.sql forward reference is no longer an orphan — pin removed.
export const PINNED_ORPHAN_FK_IDS: readonly string[] = [] as const;

const emptyClassCounts = (): Record<FailureClass, number> => ({
  missing_store: 0,
  orphan_fk: 0,
  unsafe_cascade: 0,
  unindexed_query: 0,
  excluded_present: 0,
  docs_unread: 0,
  undispositioned_spec_table: 0,
  stale_spec_disposition: 0,
});

/** Extract CREATE TABLE identifiers from governing-doc prose (fenced SQL blocks). */
export const extractCreateTableNames = (markdown: string): string[] => {
  const names: string[] = [];
  const re =
    /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([a-zA-Z_][a-zA-Z0-9_]*))/gi;
  for (const match of markdown.matchAll(re)) {
    const name = (match[1] ?? match[2] ?? "").toLowerCase();
    if (name) names.push(name);
  }
  return names;
};

export const loadSchemaDir = (schemaDir: string): Map<string, string> => {
  const map = new Map<string, string>();
  for (const name of readdirSync(schemaDir).filter((n) => n.endsWith(".sql")).sort()) {
    map.set(name, readFileSync(resolve(schemaDir, name), "utf8"));
  }
  return map;
};

/**
 * Detect tables any non-test code path can populate.
 * Arms:
 *   1. literal `INSERT INTO <ident>` SQL
 *   2. store-wrapper patterns: `<table>Store.insert` / `insertInto('<table>')` /
 *      `.from('<table>').insert` style markers, plus known port method names bound
 *      to a table via nearby identifier (deviceStore.insert → operator_device_keys
 *      is covered by DECLARED_PRODUCERS, not fragile name inference)
 *   3. DECLARED_PRODUCERS explicit admissions (B3)
 */
export const scanProducerTables = (srcRoot: string): Set<string> => {
  const found = new Set<string>();
  const walk = (dir: string): void => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "test" || entry.name === "dist" || entry.name === "node_modules") continue;
        walk(path);
        continue;
      }
      if (!entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
      const body = readFileSync(path, "utf8");
      for (const match of body.matchAll(/INSERT\s+INTO\s+(\w+)/gi)) {
        found.add((match[1] ?? "").toLowerCase());
      }
      // store-wrapper: fooStore.insert(...) where foo maps to a known table name token
      // appearing as `INSERT`-equivalent method on a *Store port. Also catch
      // `db.insert(tableRef)` / `.insert(row)` only when a table ident is in the same
      // statement — keep this conservative to avoid false producers.
      for (const match of body.matchAll(
        /(?:from\((['"])(\w+)\1\)\s*\.\s*insert|insertInto\(\s*(['"])(\w+)\3)/gi,
      )) {
        const name = (match[2] ?? match[4] ?? "").toLowerCase();
        if (name) found.add(name);
      }
      // AuditLogStore.append is the insert-only audit port (no SQL string in src yet).
      if (/AuditLogStore|createAuditWriter|\.append\(\s*row/.test(body) && /audit/i.test(body)) {
        if (/export (?:interface|class) \w*AuditLog|createAuditWriter|InMemoryAuditLogStore/.test(body)) {
          found.add("audit_log");
        }
      }
      // DeviceKeyStore.insert — enrollment writes operator_device_keys through the port.
      if (/DeviceKeyStore/.test(body) && /insert\(deviceKey/.test(body)) {
        found.add("operator_device_keys");
      }
      if (/EnrollmentChallengeStore|interface \w*ChallengeStore/.test(body) && /insert\(challenge/.test(body)) {
        found.add("device_enrollment_challenges");
      }
    }
  };
  walk(srcRoot);
  for (const table of Object.keys(DECLARED_PRODUCERS)) {
    found.add(table.toLowerCase());
  }
  return found;
};

const resolveColumn = (
  model: SchemaModel,
  table: string,
  column: string,
  aliases: ReadonlyMap<string, string>,
): string | null => {
  const cols = model.columnsByTable.get(table);
  if (!cols) return null;
  if (cols.has(column)) return column;
  const alias = aliases.get(`${table}.${column}`);
  if (alias && cols.has(alias)) return alias;
  return null;
};

const satisfierPresent = (model: SchemaModel, satisfier: string): boolean => {
  if (satisfier.startsWith("table:")) {
    return model.tables.has(satisfier.slice("table:".length));
  }
  if (satisfier.startsWith("column:")) {
    const rest = satisfier.slice("column:".length);
    const dot = rest.indexOf(".");
    if (dot === -1) return false;
    const table = rest.slice(0, dot);
    const column = rest.slice(dot + 1);
    return resolveColumn(model, table, column, DEFAULT_COLUMN_ALIASES) !== null;
  }
  if (satisfier.startsWith("index:")) {
    const name = satisfier.slice("index:".length);
    return model.indexes.some((idx) => idx.name === name);
  }
  return false;
};

const firstSatisfier = (model: SchemaModel, noun: NormativeNoun): string | null => {
  for (const s of noun.satisfiers) {
    if (satisfierPresent(model, s)) return s;
  }
  return null;
};

/** Index covers pattern when its column list is a left-prefix match of the pattern columns
 *  OR the pattern columns are a left-prefix of the index (planner can use the leading keys). */
export const indexCovers = (index: IndexDef, patternColumns: readonly string[]): boolean => {
  if (patternColumns.length === 0) return false;
  const idxCols = index.columns.map((c) => c.toLowerCase());
  const patCols = patternColumns.map((c) => c.toLowerCase());
  // Exact or index is left-prefix of pattern (multi-column filter using leading keys).
  const n = Math.min(idxCols.length, patCols.length);
  if (n === 0) return false;
  for (let i = 0; i < n; i += 1) {
    if (idxCols[i] !== patCols[i]) return false;
  }
  // Require the index to start with the pattern's leading column.
  return idxCols[0] === patCols[0];
};

const checkNouns = (
  model: SchemaModel,
  nouns: readonly NormativeNoun[],
  failDeferred: boolean,
): { results: NounResult[]; failures: CensusFailure[] } => {
  const results: NounResult[] = [];
  const failures: CensusFailure[] = [];

  for (const noun of nouns) {
    if (noun.disposition === "excluded") {
      const present = noun.satisfiers.some((s) => satisfierPresent(model, s)) ||
        // Also fail if a forbidden table name appears under common callback names.
        ["callback_registrations", "callback_deliveries", "webhook_endpoints"].some((t) =>
          model.tables.has(t),
        );
      if (present) {
        const detail = `${noun.id}: excluded-by-canon store is present in schema (${noun.authority ?? "no authority"})`;
        results.push({
          id: noun.id,
          noun: noun.noun,
          disposition: noun.disposition,
          sources: noun.sources,
          satisfiedBy: firstSatisfier(model, noun) ?? "FORBIDDEN_TABLE",
          authority: noun.authority,
          ok: false,
          failureClass: "excluded_present",
          detail,
        });
        failures.push({ class: "excluded_present", id: noun.id, detail });
      } else {
        results.push({
          id: noun.id,
          noun: noun.noun,
          disposition: noun.disposition,
          sources: noun.sources,
          satisfiedBy: "NONE (excluded-by-canon)",
          authority: noun.authority,
          ok: true,
        });
      }
      continue;
    }

    const hit = firstSatisfier(model, noun);
    if (hit) {
      results.push({
        id: noun.id,
        noun: noun.noun,
        disposition: noun.disposition,
        sources: noun.sources,
        satisfiedBy: hit,
        retentionClass: noun.retentionClass,
        authority: noun.authority,
        ok: true,
      });
      continue;
    }

    const isDeferred = noun.disposition === "deferred" && !failDeferred;
    if (isDeferred) {
      results.push({
        id: noun.id,
        noun: noun.noun,
        disposition: noun.disposition,
        sources: noun.sources,
        satisfiedBy: "NONE",
        retentionClass: noun.retentionClass,
        authority: noun.authority,
        ok: true,
        detail: `deferred open gap: ${noun.authority ?? "no authority"}`,
      });
      continue;
    }

    const detail = `${noun.id}: no schema object satisfies [${noun.satisfiers.join(", ")}]`;
    results.push({
      id: noun.id,
      noun: noun.noun,
      disposition: noun.disposition,
      sources: noun.sources,
      satisfiedBy: "NONE",
      retentionClass: noun.retentionClass,
      authority: noun.authority,
      ok: false,
      failureClass: "missing_store",
      detail,
    });
    failures.push({ class: "missing_store", id: noun.id, detail });
  }

  return { results, failures };
};

const checkForeignKeys = (
  model: SchemaModel,
  producers: ReadonlySet<string>,
  exempt: ReadonlySet<string>,
  aliases: ReadonlyMap<string, string>,
  pinnedOrphans: ReadonlySet<string> = new Set(PINNED_ORPHAN_FK_IDS),
): {
  rows: CensusReport["foreignKeys"];
  failures: CensusFailure[];
  /** Pins that no longer match a live orphan — caller must drop them. */
  stalePins: string[];
} => {
  const rows: CensusReport["foreignKeys"] = [];
  const failures: CensusFailure[] = [];
  const seenOrphanIds = new Set<string>();

  for (const fk of model.foreignKeys) {
    const sourceLabel = `${fk.sourceTable}(${fk.sourceColumns.join(",")})`;
    const targetLabel = `${fk.targetTable}(${fk.targetColumns.join(",")})`;
    const id = `fk:${fk.sourceFile}:${sourceLabel}->${targetLabel}`;

    if (!model.tables.has(fk.targetTable)) {
      const detail = `${id}: target table '${fk.targetTable}' does not exist`;
      if (pinnedOrphans.has(id)) {
        seenOrphanIds.add(id);
        rows.push({
          source: sourceLabel,
          target: targetLabel,
          onDelete: fk.onDelete,
          onUpdate: fk.onUpdate,
          ok: true,
          detail: `acknowledged_orphan_fk (pinned; sibling lane): ${detail}`,
        });
        continue;
      }
      rows.push({
        source: sourceLabel,
        target: targetLabel,
        onDelete: fk.onDelete,
        onUpdate: fk.onUpdate,
        ok: false,
        detail,
      });
      failures.push({ class: "orphan_fk", id, detail });
      continue;
    }

    const missingCols: string[] = [];
    for (const col of fk.targetColumns) {
      if (resolveColumn(model, fk.targetTable, col, aliases) === null) {
        missingCols.push(col);
      }
    }
    if (missingCols.length > 0) {
      const detail = `${id}: target column(s) missing on ${fk.targetTable}: ${missingCols.join(", ")}`;
      rows.push({
        source: sourceLabel,
        target: targetLabel,
        onDelete: fk.onDelete,
        onUpdate: fk.onUpdate,
        ok: false,
        detail,
      });
      failures.push({ class: "orphan_fk", id, detail });
      continue;
    }

    // "never populated" arm: target table has no INSERT producer and is not exempt.
    const target = fk.targetTable.toLowerCase();
    if (!producers.has(target) && !exempt.has(target)) {
      const detail = `${id}: target table '${fk.targetTable}' has no INSERT producer path and is not producer-exempt`;
      rows.push({
        source: sourceLabel,
        target: targetLabel,
        onDelete: fk.onDelete,
        onUpdate: fk.onUpdate,
        ok: false,
        detail,
      });
      failures.push({ class: "orphan_fk", id, detail });
      continue;
    }

    rows.push({
      source: sourceLabel,
      target: targetLabel,
      onDelete: fk.onDelete,
      onUpdate: fk.onUpdate,
      ok: true,
    });
  }

  const stalePins = [...pinnedOrphans].filter((id) => !seenOrphanIds.has(id));
  return { rows, failures, stalePins };
};

/**
 * CASCADE reachability into evidence tables. A direct ON DELETE/UPDATE CASCADE
 * edge whose target is an evidence table fails. Reachability through a chain of
 * CASCADE edges also fails (cascade fires regardless of application intent).
 */
const checkCascades = (
  model: SchemaModel,
  evidenceTables: ReadonlySet<string>,
): { failures: CensusFailure[] } => {
  const failures: CensusFailure[] = [];

  // Direct edges.
  for (const fk of model.foreignKeys) {
    if (fk.onDelete === "CASCADE" || fk.onUpdate === "CASCADE") {
      if (evidenceTables.has(fk.targetTable) || evidenceTables.has(fk.sourceTable)) {
        const which =
          fk.onDelete === "CASCADE" && fk.onUpdate === "CASCADE"
            ? "ON DELETE CASCADE + ON UPDATE CASCADE"
            : fk.onDelete === "CASCADE"
              ? "ON DELETE CASCADE"
              : "ON UPDATE CASCADE";
        const id = `cascade:${fk.sourceFile}:${fk.sourceTable}->${fk.targetTable}`;
        const detail = `${id}: ${which} touches evidence/exact-content table source=${fk.sourceTable} target=${fk.targetTable}`;
        failures.push({ class: "unsafe_cascade", id, detail });
      }
    }
  }

  // Multi-hop: build adjacency for DELETE CASCADE only (the destructive direction).
  const cascadeEdges = new Map<string, string[]>();
  for (const fk of model.foreignKeys) {
    if (fk.onDelete !== "CASCADE") continue;
    const list = cascadeEdges.get(fk.sourceTable) ?? [];
    list.push(fk.targetTable);
    cascadeEdges.set(fk.sourceTable, list);
  }
  for (const [from, tos] of cascadeEdges) {
    const stack = [...tos];
    const seen = new Set<string>();
    while (stack.length > 0) {
      const t = stack.pop() ?? "";
      if (seen.has(t)) continue;
      seen.add(t);
      if (evidenceTables.has(t) && !evidenceTables.has(from)) {
        // from itself may be non-evidence; cascading into evidence is the violation.
        const id = `cascade-reach:${from}->${t}`;
        const detail = `${id}: ON DELETE CASCADE path reaches evidence table '${t}' from '${from}'`;
        // Avoid duplicate if direct edge already reported.
        if (!failures.some((f) => f.id === `cascade:${from}` /* loose */ && f.detail.includes(t))) {
          if (!failures.some((f) => f.class === "unsafe_cascade" && f.detail.includes(`${from}`) && f.detail.includes(t))) {
            failures.push({ class: "unsafe_cascade", id, detail });
          }
        }
      }
      for (const next of cascadeEdges.get(t) ?? []) stack.push(next);
    }
  }

  return { failures };
};

const checkAccessPatterns = (
  model: SchemaModel,
  patterns: readonly (typeof WORKER_ACCESS_PATTERNS)[number][],
): {
  rows: CensusReport["accessPatterns"];
  failures: CensusFailure[];
} => {
  const rows: CensusReport["accessPatterns"] = [];
  const failures: CensusFailure[] = [];

  for (const pattern of patterns) {
    if (!model.tables.has(pattern.table)) {
      // Table itself missing — missing_store territory; still flag unindexed for the pattern.
      const detail = `${pattern.id}: table '${pattern.table}' absent; no index possible`;
      rows.push({
        id: pattern.id,
        table: pattern.table,
        columns: pattern.columns,
        satisfiedBy: "NONE",
        ok: false,
      });
      failures.push({ class: "unindexed_query", id: pattern.id, detail });
      continue;
    }
    const candidates = model.indexes.filter((idx) => idx.table === pattern.table);
    const cover = candidates.find((idx) => indexCovers(idx, pattern.columns));
    if (!cover) {
      const detail = `${pattern.id}: no index on ${pattern.table}(${pattern.columns.join(",")}) — ${pattern.source}`;
      rows.push({
        id: pattern.id,
        table: pattern.table,
        columns: pattern.columns,
        satisfiedBy: "NONE",
        ok: false,
      });
      failures.push({ class: "unindexed_query", id: pattern.id, detail });
      continue;
    }
    rows.push({
      id: pattern.id,
      table: pattern.table,
      columns: pattern.columns,
      satisfiedBy: `index:${cover.name}`,
      ok: true,
    });
  }

  return { rows, failures };
};

const readGoverningDocs = (
  root: string,
): {
  docsRead: string[];
  failures: CensusFailure[];
  /** doc relativePath → full text (for CREATE TABLE parse). */
  docTexts: Map<string, string>;
} => {
  const docsRead: string[] = [];
  const failures: CensusFailure[] = [];
  const docTexts = new Map<string, string>();
  for (const doc of GOVERNING_DOCS) {
    const path = resolve(root, doc.relativePath);
    if (!existsSync(path)) {
      failures.push({
        class: "docs_unread",
        id: doc.id,
        detail: `governing doc missing: ${doc.relativePath}`,
      });
      continue;
    }
    const text = readFileSync(path, "utf8");
    if (text.length < 100) {
      failures.push({
        class: "docs_unread",
        id: doc.id,
        detail: `governing doc unreadable or empty: ${doc.relativePath}`,
      });
      continue;
    }
    docsRead.push(doc.relativePath);
    docTexts.set(doc.relativePath, text);
  }
  if (docsRead.length !== GOVERNING_DOCS.length && failures.length === 0) {
    failures.push({
      class: "docs_unread",
      id: "docs",
      detail: `expected ${GOVERNING_DOCS.length} governing docs, read ${docsRead.length}`,
    });
  }
  return { docsRead, failures, docTexts };
};

/**
 * Peer of migration-integrity SCHEMA_FILES set-equality: every CREATE TABLE in
 * the governing docs must appear in SPEC_TABLE_DISPOSITIONS with required /
 * deferred / excluded + authority for non-required. Required + missing schema
 * → missing_store. Undispositioned → undispositioned_spec_table (Probe 2).
 */
export const checkSpecTableDispositions = (
  model: SchemaModel,
  docTexts: ReadonlyMap<string, string>,
  dispositions: readonly SpecTableDisposition[] = SPEC_TABLE_DISPOSITIONS,
): { failures: CensusFailure[]; specTables: readonly string[] } => {
  const failures: CensusFailure[] = [];
  const specTables = new Set<string>();
  for (const text of docTexts.values()) {
    for (const name of extractCreateTableNames(text)) specTables.add(name);
  }

  const byTable = new Map<string, SpecTableDisposition>();
  for (const d of dispositions) {
    const key = d.table.toLowerCase();
    if (byTable.has(key)) {
      failures.push({
        class: "undispositioned_spec_table",
        id: `dup:${key}`,
        detail: `SPEC_TABLE_DISPOSITIONS lists '${key}' more than once`,
      });
    }
    byTable.set(key, d);
  }

  for (const table of [...specTables].sort()) {
    const d = byTable.get(table);
    if (!d) {
      failures.push({
        class: "undispositioned_spec_table",
        id: `spec:${table}`,
        detail: `governing CREATE TABLE '${table}' has no SPEC_TABLE_DISPOSITIONS row (required|deferred|excluded + authority)`,
      });
      continue;
    }
    if (d.disposition === "deferred" || d.disposition === "excluded") {
      if (!d.authority || d.authority.trim().length < 8) {
        failures.push({
          class: "undispositioned_spec_table",
          id: `spec:${table}`,
          detail: `SPEC_TABLE_DISPOSITIONS '${table}' is ${d.disposition} but lacks named authority (decision id or ticket id)`,
        });
      }
    }
    if (d.disposition === "required" && !model.tables.has(table)) {
      failures.push({
        class: "missing_store",
        id: `spec:${table}`,
        detail: `spec table '${table}' (${d.section}) disposition=required but absent from schema`,
      });
    }
    if (d.disposition === "excluded" && model.tables.has(table)) {
      failures.push({
        class: "excluded_present",
        id: `spec:${table}`,
        detail: `spec table '${table}' is excluded-by-canon (${d.authority ?? "no authority"}) but present in schema`,
      });
    }
    // deferred + present is fine (store landed early); deferred + absent is the open gap.
  }

  for (const [table, d] of byTable) {
    if (!specTables.has(table)) {
      failures.push({
        class: "stale_spec_disposition",
        id: `stale:${table}`,
        detail: `SPEC_TABLE_DISPOSITIONS lists '${table}' (${d.section}) but no governing CREATE TABLE remains — remove or restore the spec block`,
      });
    }
  }

  return { failures, specTables: [...specTables].sort() };
};

export interface CensusResult {
  readonly model: SchemaModel;
  readonly report: CensusReport;
  readonly ok: boolean;
}

export const buildCensus = (options: BuildCensusOptions = {}): CensusResult => {
  const root = options.repoRoot ?? repoRoot;
  const schemaDir = options.schemaDir ?? defaultSchemaDir;
  const sqlByFile = options.sqlByFile ?? loadSchemaDir(schemaDir);
  const model = options.sqlByFile
    ? parseSchemaFromMap(sqlByFile)
    : parseSchemaSql([...sqlByFile.entries()].map(([name, sql]) => ({ name, sql })));

  const nouns = options.nouns ?? NORMATIVE_NOUNS;
  const patterns = options.accessPatterns ?? WORKER_ACCESS_PATTERNS;
  const aliases = options.columnAliases ?? DEFAULT_COLUMN_ALIASES;
  const exempt = options.producerExemptTables ?? DEFAULT_PRODUCER_EXEMPT;
  const producers =
    options.producerTables ??
    scanProducerTables(resolve(packageRoot, "src"));

  const allFailures: CensusFailure[] = [];

  const docs = readGoverningDocs(root);
  allFailures.push(...docs.failures);

  if (!options.skipSpecTableDispositionCheck) {
    const dispositionCheck = checkSpecTableDispositions(
      model,
      docs.docTexts,
      options.specTableDispositions ?? SPEC_TABLE_DISPOSITIONS,
    );
    allFailures.push(...dispositionCheck.failures);
  }

  const nounCheck = checkNouns(model, nouns, options.failDeferred === true);
  allFailures.push(...nounCheck.failures);

  const fkCheck = checkForeignKeys(model, producers, exempt, aliases);
  allFailures.push(...fkCheck.failures);
  for (const pin of fkCheck.stalePins) {
    allFailures.push({
      class: "orphan_fk",
      id: `stale_pin:${pin}`,
      detail: `pinned orphan FK no longer orphans — remove from PINNED_ORPHAN_FK_IDS: ${pin}`,
    });
  }

  const evidenceList =
    options.evidenceTables ??
    deriveEvidenceTables(new Set(model.tables.keys()), nouns);
  const evidence = new Set(evidenceList);
  const cascadeCheck = checkCascades(model, evidence);
  allFailures.push(...cascadeCheck.failures);

  const accessCheck = checkAccessPatterns(model, patterns);
  allFailures.push(...accessCheck.failures);

  const byClass = emptyClassCounts();
  for (const f of allFailures) byClass[f.class] += 1;

  const nounsOk = nounCheck.results.filter((n) => n.ok).length;

  const report: CensusReport = {
    schema: "generic-node-redesign-v2",
    censusId: "generic-node-schema-census",
    docsRead: docs.docsRead,
    schemaFiles: [...sqlByFile.keys()].sort(),
    summary: {
      nounsChecked: nounCheck.results.length,
      nounsOk,
      nounsFailed: nounCheck.results.length - nounsOk,
      foreignKeysChecked: fkCheck.rows.length,
      accessPatternsChecked: accessCheck.rows.length,
      failureCount: allFailures.length,
      byClass,
    },
    nouns: nounCheck.results,
    failures: allFailures,
    foreignKeys: fkCheck.rows,
    accessPatterns: accessCheck.rows,
  };

  return { model, report, ok: allFailures.length === 0 };
};

/** Pure helper for negative-path tests: run census against an injected schema map. */
export const buildCensusFromSql = (
  sqlByFile: ReadonlyMap<string, string>,
  overrides: Omit<BuildCensusOptions, "sqlByFile"> = {},
): CensusResult => buildCensus({ ...overrides, sqlByFile });

/** Format a human-readable pass/fail summary (also machine-grepable). */
export const formatReportText = (report: CensusReport): string => {
  const lines: string[] = [];
  lines.push(`# schema-object census — ${report.ticket}`);
  lines.push(`status: ${report.summary.failureCount === 0 ? "PASS" : "FAIL"}`);
  lines.push(`docs_read: ${report.docsRead.length}`);
  lines.push(`schema_files: ${report.schemaFiles.length}`);
  lines.push(
    `nouns: ${report.summary.nounsOk}/${report.summary.nounsChecked} ok; fks: ${report.summary.foreignKeysChecked}; access_patterns: ${report.summary.accessPatternsChecked}; failures: ${report.summary.failureCount}`,
  );
  lines.push("");
  lines.push("## nouns");
  for (const n of report.nouns) {
    const mark = n.ok ? "OK" : "FAIL";
    lines.push(
      `- [${mark}] ${n.id} disposition=${n.disposition} satisfiedBy=${n.satisfiedBy}` +
        (n.detail ? ` detail=${n.detail}` : ""),
    );
  }
  if (report.failures.length > 0) {
    lines.push("");
    lines.push("## failures");
    for (const f of report.failures) {
      lines.push(`- [${f.class}] ${f.id}: ${f.detail}`);
    }
  }
  lines.push("");
  return lines.join("\n");
};

// Re-export FK type for tests that inject cascade edges.
export type { ForeignKey, SchemaModel };
