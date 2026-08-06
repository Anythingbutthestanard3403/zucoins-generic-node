/**
 * Pending-only detect-and-refuse migration guard for generic-node
 * overlap deploys (applied to the v2 node).
 *
 * Mirrors apps/node/src/db/overlap-guard.ts with two generic-node adaptations:
 *   1. Overlap is the SIGNER_LEADERSHIP_LOCK_ID (ASCII "SLL") from
 *      @zucoins/node-core — the v2 process-wide signer leadership lock — not
 *      the v1 NODE_ALIVE id.
 *   2. One-in-flight-per-wallet backstop objects are the v2 mechanical one-in-flight
 *      enforcers (wallet_active_leases PK + unique-wallet indexes). The list is
 *      wired so a future custody migration that drops one is refused without a
 *      code change here beyond adding the object name.
 *
 * Sequence (called before drizzle's migrator):
 *   journal → pending-only tags → classify via isolated libpg_query worker →
 *   read-only pg_locks probe for the leadership lock → refuse blocking
 *   during overlap; refuse One-in-flight-backstop removals without tag-exact ack even
 *   with no overlap.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pool } from "pg";
import {
  classifyMigrationSql,
  disposeClassifier,
  type LockClass,
} from "./migration-classifier.js";

// Frozen signer-leadership advisory-lock id (ASCII "SLL"), mirrored here so
// the migration-only Stage-1 runtime does not load node-core's broad root
// barrel (which intentionally includes testkit exports for downstream tests).
const SIGNER_LEADERSHIP_LOCK_ID = 0x534c4c;

export interface ClassifiedStatement {
  migrationTag: string;
  statementIndex: number;
  sql: string;
  lockClass: LockClass;
  rule: string;
  detail: string;
  /**
   * The one-in-flight-per-wallet backstop objects this statement REMOVES. Non-empty means
   * strictest tier — see {@link INFLIGHT_BACKSTOP_OBJECTS}.
   */
  inflightBackstopObjects: string[];
}

export interface GuardResult {
  overlapDetected: boolean;
  blockingMigrations: ClassifiedStatement[];
  inflightBackstopMigrations: ClassifiedStatement[];
  shouldProceed: boolean;
}

/**
 * The operational stop-first deploy procedure. Held as one constant so the two refusal
 * messages interpolate it instead of repeating the phrase — a marker on an inlined
 * name would otherwise print into the operator's terminal.
 */
const STOP_FIRST_PROCEDURE = "the stop-first drain-and-deploy procedure"; // contract-allow:drain:names the operational procedure verbatim, not rewordable here

// ─── One-in-flight-per-wallet backstop objects (strictest tier) ──────────────────────────

/**
 * Database objects that MECHANICALLY enforce the one-in-flight-per-wallet rule for the v2 node
 * (one in-flight transaction / lease per wallet). Removing any of them opens a
 * window in which a second unsettled claim on the same wallet is no longer
 * refused by the database.
 *
 * Today the shipped 0000 reporting-persistence migration does not create these
 * objects (they land with the money-path schema). The list is still load-bearing:
 * a future DROP/RENAME of any named object is forced to blocking and
 * refuses without {@link INFLIGHT_BACKSTOP_ACK_ENV}, even with no overlap.
 */
export const INFLIGHT_BACKSTOP_OBJECTS = [
  // Primary one-lease-per-wallet enforcer (data model: custody / wallet_active_leases).
  "wallet_active_leases_wallet_public_key_key",
  "wallet_active_leases_pkey",
  // Receive-window / move source uniqueness when those tables ship.
  "idx_wallet_active_leases_one_inflight",
] as const;

/**
 * Env var naming the migration tags the operator has acknowledged. The name is the
 * operator-facing contract the stop-first runbook spells out verbatim, so it is pinned rather than reworded;
 * renaming it would silently stop honouring an acknowledgement an operator already sets.
 */
export const INFLIGHT_BACKSTOP_ACK_ENV = "ZUP_INFLIGHT_BACKSTOP_DRAIN_ACK"; // contract-allow:drain:frozen operator contract names this env var verbatim — an operator contract, not prose

/**
 * The One-in-flight backstop objects `sql` removes, if any.
 *
 * A statement that ESTABLISHES a backstop is the opposite of the hazard and must
 * not trip the tier. Removal verbs are what matter: DROP and RENAME.
 *
 * `sql` may be one statement or a whole migration file; each `;`-delimited
 * statement is judged INDEPENDENTLY so a DROP of a superseded name followed by
 * ADD of the backstop does not false-positive.
 */
export function inflightBackstopObjectsRemovedBy(sql: string): string[] {
  const removed = new Set<string>();
  for (const statement of sql.split(";")) {
    if (!/\b(DROP|RENAME)\b/i.test(statement)) continue;
    const lowered = statement.toLowerCase();
    for (const name of INFLIGHT_BACKSTOP_OBJECTS) {
      if (lowered.includes(name)) removed.add(name);
    }
  }
  return INFLIGHT_BACKSTOP_OBJECTS.filter((name) => removed.has(name));
}

/**
 * Migration tags the operator has acknowledged as running inside a deliberate
 * stop-first window. Comma-separated and tag-exact.
 */
export function acknowledgedStopFirstTags(env: NodeJS.ProcessEnv = process.env): Set<string> {
  return new Set(
    (env[INFLIGHT_BACKSTOP_ACK_ENV] ?? "")
      .split(",")
      .map((tag) => tag.trim())
      .filter((tag) => tag.length > 0),
  );
}

/** Operator-facing block naming every backstop object the pending set removes. */
function strictestTierBlock(statements: readonly ClassifiedStatement[]): string {
  const backstop = statements.filter((statement) => statement.inflightBackstopObjects.length > 0);
  if (backstop.length === 0) return "";
  const named = backstop
    .map(
      (statement) =>
        `  ${statement.migrationTag} (statement ${statement.statementIndex}) removes: ${statement.inflightBackstopObjects.join(", ")}`,
    )
    .join("\n");
  return `
STRICTEST TIER — one-in-flight-per-wallet backstop removal:
${named}
These objects are what stops a second in-flight transaction on the same wallet.
While they are absent, the one-in-flight-per-wallet rule is not enforced by the database at all.
Apply them ONLY inside a deliberately stopped single-instance window — see
${STOP_FIRST_PROCEDURE}, step "one-in-flight-backstop migrations".
`;
}

export class OverlapMigrationRefusedError extends Error {
  constructor(public readonly blockingStatements: ClassifiedStatement[]) {
    const lines = blockingStatements
      .map((statement) => {
        const oneLine = statement.sql.replace(/\s+/g, " ").trim();
        const preview = oneLine.length > 80 ? `${oneLine.slice(0, 80)}…` : oneLine;
        return `  ${statement.migrationTag} (statement ${statement.statementIndex}) [${statement.rule}]: ${preview}\n      ↳ ${statement.detail}`;
      })
      .join("\n");
    super(
      `Blocking migration(s) detected during overlap deploy. Refusing to proceed.

Blocking statements:
${lines}
${strictestTierBlock(blockingStatements)}
Use the stop-first deploy procedure:
  1. Scale the Railway service to 0 replicas (stops the live signer)
  2. Wait for in-flight requests to finish (30s is sufficient)
  3. Deploy with zero overlap (single instance, no concurrent signer)
  4. Scale back to desired replica count

See ${STOP_FIRST_PROCEDURE} for full instructions.`,
    );
    this.name = "OverlapMigrationRefusedError";
  }
}

/**
 * Refusal for the NON-overlap case: no other node holds signer leadership, yet
 * the pending set removes a one-in-flight-per-wallet backstop.
 */
export class InflightBackstopAckRequiredError extends Error {
  constructor(public readonly backstopStatements: ClassifiedStatement[]) {
    const tags = [...new Set(backstopStatements.map((s) => s.migrationTag))].join(",");
    super(
      `One-in-flight-per-wallet backstop removal pending. Refusing without an acknowledged stop-first window.
${strictestTierBlock(backstopStatements)}
No other node holds the signer leadership advisory lock, but an absent lock is not
proof of a deliberate stop-first window. Follow the stop-first procedure,
confirm exactly one instance will run, then re-run this migration with:

  ${INFLIGHT_BACKSTOP_ACK_ENV}=${tags}

The acknowledgement is per-migration (it cannot cover a later one) and NEVER
clears an overlap refusal.`,
    );
    this.name = "InflightBackstopAckRequiredError";
  }
}

// ─── Overlap Detection ────────────────────────────────────────────────────────

/**
 * PostgreSQL stores an advisory lock's 64-bit id across `pg_locks.classid` and
 * `pg_locks.objid`, in one of TWO encodings distinguished by `objsubid`:
 *
 *   objsubid = 1 — single-`bigint` form, `pg_advisory_lock(bigint)`:
 *                  classid = HIGH 32 bits of the id, objid = LOW 32 bits.
 *   objsubid = 2 — two-`integer` form, `pg_advisory_lock(int4, int4)`:
 *                  classid = first argument, objid = second argument.
 *
 * Both encodings of the same logical id are matched. Fail-closed on unknown shapes.
 */
const OBJSUBID_SINGLE_BIGINT = 1;
const OBJSUBID_TWO_INTEGER = 2;

/** One granted advisory lock row, as read from `pg_locks`. */
export interface AdvisoryLockRow {
  classid: number;
  objid: number;
  objsubid: number;
}

function toInt(value: unknown): number {
  if (typeof value === "number") return Number.isInteger(value) ? value : Number.NaN;
  if (typeof value === "string" && /^-?\d+$/.test(value)) return Number(value);
  return Number.NaN;
}

/**
 * Decide whether `lockId` is held, given every granted advisory lock row.
 * Fail-closed on unreadable / unknown shapes.
 */
export function advisoryLockHeld(rows: readonly AdvisoryLockRow[], lockId: bigint): boolean {
  const expectedClassid = Number(BigInt.asUintN(32, lockId >> 32n));
  const expectedObjid = Number(BigInt.asUintN(32, lockId));

  for (const row of rows) {
    const classid = toInt(row.classid);
    const objid = toInt(row.objid);
    const objsubid = toInt(row.objsubid);

    if (objsubid !== OBJSUBID_SINGLE_BIGINT && objsubid !== OBJSUBID_TWO_INTEGER) {
      return true;
    }
    if (Number.isNaN(classid) || Number.isNaN(objid)) {
      return true;
    }
    if (classid === expectedClassid && objid === expectedObjid) return true;
  }

  return false;
}

/**
 * Read-only probe: is `lockId` held as an advisory lock **in this database**?
 * Uses ONLY a SELECT — no writes. A query failure fails CLOSED.
 * Scope is deliberately `database = current_database()` (via oid).
 */
export async function detectAdvisoryLockHeld(pool: Pool, lockId: bigint): Promise<boolean> {
  let rows: AdvisoryLockRow[];
  try {
    const res = await pool.query<AdvisoryLockRow>(
      `SELECT classid, objid, objsubid
         FROM pg_locks
        WHERE locktype = 'advisory'
          AND granted = true
          AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
    );
    rows = res.rows;
  } catch {
    return true;
  }

  return advisoryLockHeld(rows, lockId);
}

/**
 * Returns true if another node holds the signer leadership advisory lock
 * (overlap deploy detected).
 */
export async function detectOverlap(pool: Pool): Promise<boolean> {
  return detectAdvisoryLockHeld(pool, BigInt(SIGNER_LEADERSHIP_LOCK_ID));
}

// ─── Pending Migration Discovery ──────────────────────────────────────────────

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

function readJournal(migrationsFolder: string): JournalEntry[] {
  const raw = readFileSync(join(migrationsFolder, "meta", "_journal.json"), "utf8");
  const parsed = JSON.parse(raw) as { entries: JournalEntry[] };
  return parsed.entries;
}

/**
 * Returns the tags of migrations not yet applied to the database. On a fresh
 * database (no __drizzle_migrations table), returns all journal entries.
 */
export async function readPendingMigrationTags(
  pool: Pool,
  migrationsFolder: string,
): Promise<string[]> {
  const journal = readJournal(migrationsFolder);

  let appliedWhenValues: number[] = [];
  try {
    const res = await pool.query<{ created_at: string }>(
      `SELECT created_at FROM drizzle.__drizzle_migrations`,
    );
    appliedWhenValues = res.rows.map((r) => Number(r.created_at));
  } catch (error) {
    if ((error as { code?: string }).code === "42P01") {
      return journal.map((e) => e.tag);
    }
    throw error;
  }

  return journal
    .filter((entry) => !appliedWhenValues.includes(entry.when))
    .map((entry) => entry.tag);
}

// ─── Migration Classification ─────────────────────────────────────────────────

function unreadableMigration(
  tag: string,
  reason: string,
  inflightBackstopObjects: readonly string[] = [],
  sql = `<unreadable migration ${tag}>`,
): ClassifiedStatement {
  return {
    migrationTag: tag,
    statementIndex: 0,
    sql,
    lockClass: "blocking",
    rule: "classifier-error",
    detail: `migration could not be read or parsed, refusing rather than skipping: ${reason}`,
    // Prefer any file-byte One-in-flight hits we already collected before the failure.
    inflightBackstopObjects: [...inflightBackstopObjects],
  };
}

/**
 * Classify only the journal entries that have not been applied. The isolated
 * parser process is the sole lock-class authority for online vs blocking.
 *
 * One-in-flight-per-wallet backstop detection is deliberately independent of the
 * classifier: it always scans the full migration file bytes. When the worker
 * crashes/times out, `classifyMigrationSql` returns `FAIL_CLOSED_BLOCKING` with
 * `sql: ""` — scanning only that placeholder would fail OPEN on a pending
 * One-in-flight DROP (strictest tier / the one-in-flight-per-wallet rule).
 */
export async function classifyPendingMigrations(
  migrationsFolder: string,
  pendingTags: string[],
): Promise<ClassifiedStatement[]> {
  const classified: ClassifiedStatement[] = [];

  try {
    for (const tag of pendingTags) {
      let fileContent: string | undefined;
      let fileInflightBackstopObjects: string[] = [];
      try {
        fileContent = readFileSync(join(migrationsFolder, `${tag}.sql`), "utf8");
        // File-byte One-in-flight scan — runs even when the classifier is unavailable.
        fileInflightBackstopObjects = inflightBackstopObjectsRemovedBy(fileContent);
        const result = await classifyMigrationSql(fileContent);
        if (result.statements.length === 0) {
          // Empty classification (e.g. whitespace-only file) still surfaces
          // file-level One-in-flight removals so the strictest tier cannot be skipped.
          if (fileInflightBackstopObjects.length > 0) {
            classified.push({
              migrationTag: tag,
              statementIndex: 0,
              sql: fileContent,
              lockClass: "blocking",
              rule: "inflight-backstop-file-scan",
              detail:
                "one-in-flight-per-wallet backstop removal detected by full-file scan (classifier returned no statements)",
              inflightBackstopObjects: fileInflightBackstopObjects,
            });
          }
          continue;
        }
        result.statements.forEach((statement, idx) => {
          const statementInflight = inflightBackstopObjectsRemovedBy(statement.sql);
          // Attach full-file One-in-flight hits on statement 0 so a FAIL_CLOSED_BLOCKING placeholder
          // (`sql: ""`) cannot hide a DROP/RENAME of a backstop object.
          const inflightBackstopObjects =
            idx === 0
              ? uniqueStrings([...statementInflight, ...fileInflightBackstopObjects])
              : statementInflight;
          classified.push({
            migrationTag: tag,
            statementIndex: idx,
            // Prefer real statement text; fall back to file bytes when the
            // classifier failed closed with an empty placeholder.
            sql: statement.sql.length > 0 ? statement.sql : fileContent!,
            lockClass: inflightBackstopObjects.length > 0 ? "blocking" : statement.lockClass,
            rule: statement.reason,
            detail: statement.reason,
            inflightBackstopObjects,
          });
        });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        classified.push(
          unreadableMigration(
            tag,
            reason,
            fileInflightBackstopObjects,
            fileContent ?? `<unreadable migration ${tag}>`,
          ),
        );
      }
    }
  } finally {
    await disposeClassifier();
  }

  return classified;
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}

// ─── Guard Composition ────────────────────────────────────────────────────────

/**
 * Run the overlap migration guard. Called before drizzle's migrator in the
 * pre-server boot path. Throws if blocking migrations are detected during
 * overlap, or if a one-in-flight-per-wallet backstop removal is pending without an
 * acknowledged stop-first window.
 */
export async function runOverlapGuard(
  pool: Pool,
  migrationsFolder: string,
): Promise<GuardResult> {
  const pendingTags = await readPendingMigrationTags(pool, migrationsFolder);
  const classified = await classifyPendingMigrations(migrationsFolder, pendingTags);
  const blocking = classified.filter((c) => c.lockClass === "blocking");
  const inflightBackstop = classified.filter((c) => c.inflightBackstopObjects.length > 0);
  const overlapDetected = await detectOverlap(pool);

  if (!overlapDetected) {
    const unacknowledged = inflightBackstop.filter(
      (statement) => !acknowledgedStopFirstTags().has(statement.migrationTag),
    );
    if (unacknowledged.length > 0) {
      throw new InflightBackstopAckRequiredError(unacknowledged);
    }
    return {
      overlapDetected: false,
      blockingMigrations: blocking,
      inflightBackstopMigrations: inflightBackstop,
      shouldProceed: true,
    };
  }

  if (pendingTags.length === 0) {
    return {
      overlapDetected: true,
      blockingMigrations: [],
      inflightBackstopMigrations: [],
      shouldProceed: true,
    };
  }

  if (blocking.length === 0) {
    return {
      overlapDetected: true,
      blockingMigrations: [],
      inflightBackstopMigrations: [],
      shouldProceed: true,
    };
  }

  throw new OverlapMigrationRefusedError(blocking);
}
