import { execFileSync } from "node:child_process";
import { userInfo } from "node:os";

// Nothing in this repository ever ASSIGNS TEST_DATABASE_URL. Every suite gated on it
// (packages/node-core/test/migration-integrity.test.ts and
// packages/node-core/test/node-implementer-registry.pg.test.ts) would therefore skip itself in
// every run and report green having opened no connection, which would make their real-Postgres
// acceptance criteria unfalsifiable. Global setup is the right assignment point: it runs once in
// the vitest MAIN process before any worker is forked, so the assignment is inherited by every
// test worker, and — unlike a per-project `test.env` — it also covers the standalone `projects`
// entries (packages/node-core, apps/generic-node), which inherit nothing else from the root
// config.
//
// The database is hermetic and per-run: created here, dropped in teardown. The Postgres instance
// may be shared between concurrent checkouts, so teardown is scoped to exactly the one database
// this run created and never touches another run's data (the suites themselves stay
// schema-prefixed).
//
// Under multi-lane contention, CREATE DATABASE / SELECT 1 against the shared maintenance DB can
// ETIMEDOUT (psql client kill) or hit "too many clients". Treating those as "no Postgres" made
// pg suites silently skip and the run look green (ZTR-1204). Transient failures retry with
// backoff; exhaustion (or any non-absent CREATE failure) fails the run loudly. PG_REQUIRED=1
// refuses the silent no-Postgres skip path (CI exports it); pin a non-empty TEST_DATABASE_URL
// when several lanes share one instance (see README Developing). Empty TEST_DATABASE_URL= is
// not a pin — auto-provision still runs.
const MAINTENANCE_DB = "postgres";

/** Bounded retries for lane-contention timeouts / capacity errors (probe + CREATE + DROP). */
export const PROVISION_ATTEMPTS = 5;
/** Base backoff between attempts; doubles each retry (250ms → 500 → 1000 → 2000). */
export const PROVISION_BACKOFF_MS = 250;
const PSQL_TIMEOUT_MS = 15_000;

interface PgTarget {
  readonly host: string;
  readonly port: string;
}

export type PsqlErrorClass = "absent" | "transient" | "other";

/**
 * Classify a failed psql/spawn error so callers can retry contention without mistaking it for
 * "machine has no Postgres" (which is the only path allowed to soft-skip outside CI/PG_REQUIRED).
 */
export function classifyPsqlError(err: unknown): PsqlErrorClass {
  const e = err as {
    code?: string | number | null;
    signal?: string | null;
    stderr?: string | Buffer;
    message?: string;
  };
  const stderr = `${e.stderr?.toString() ?? ""}\n${e.message ?? ""}`;
  // execFileSync timeout → code ETIMEDOUT + SIGTERM; capacity text is server-side under load.
  if (
    e.code === "ETIMEDOUT" ||
    e.signal === "SIGTERM" ||
    /too many clients already|remaining connection slots|sorry, too many clients|is being accessed by other users|the database system is (starting up|shutting down|in recovery mode)/i.test(
      stderr,
    )
  ) {
    return "transient";
  }
  if (
    e.code === "ECONNREFUSED" ||
    /connection refused|could not connect to server|no such file or directory|network is unreachable|name or service not known|server closed the connection unexpectedly/i.test(
      stderr,
    )
  ) {
    // "server closed the connection unexpectedly" can also be load-related; still treat first
    // hits as absent-ish only when not also timed out (already caught above). Prefer fail-loud
    // via retries only for explicit transient markers.
    if (/server closed the connection unexpectedly/i.test(stderr)) {
      return "transient";
    }
    return "absent";
  }
  return "other";
}

/** Sync sleep for the vitest main-process setup path (no async requirement on globalSetup). */
export function sleepSync(ms: number): void {
  if (ms <= 0) return;
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

const psqlAt = (target: PgTarget, database: string, sql: string): void => {
  execFileSync(
    "psql",
    ["-h", target.host, "-p", target.port, "-d", database, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
    { stdio: ["ignore", "pipe", "pipe"], timeout: PSQL_TIMEOUT_MS },
  );
};

/**
 * Run `fn` with bounded exponential backoff on transient psql failures. Non-transient errors
 * rethrow immediately; exhausted transient retries rethrow the last error.
 */
export function withPsqlRetries(fn: () => void, label: string): void {
  let last: unknown;
  for (let attempt = 1; attempt <= PROVISION_ATTEMPTS; attempt += 1) {
    try {
      fn();
      return;
    } catch (err) {
      last = err;
      const kind = classifyPsqlError(err);
      if (kind !== "transient" || attempt === PROVISION_ATTEMPTS) {
        if (kind === "transient") {
          const detail = err instanceof Error ? err.message : String(err);
          throw new Error(
            `${label} failed after ${PROVISION_ATTEMPTS} attempts under PostgreSQL contention ` +
              `(last error: ${detail}). Pin TEST_DATABASE_URL to a dedicated database per lane, ` +
              `or reduce concurrent pnpm test processes sharing one Postgres.`,
            { cause: err },
          );
        }
        throw err;
      }
      sleepSync(PROVISION_BACKOFF_MS * 2 ** (attempt - 1));
    }
  }
  throw last;
}

// Probe the ACTUAL maintenance database, not just `pg_isready`: a server accepting connections
// does not prove a usable database exists (psql with no -d targets a database named after the OS
// user, which is typically absent). Same reasoning as
// packages/node-core/test/custody-eligibility-lease-pk.test.ts.
type Reachability =
  | { readonly status: "ok"; readonly target: PgTarget }
  | { readonly status: "absent" }
  | { readonly status: "transient"; readonly detail: string; readonly target?: PgTarget };

const probeTarget = (target: PgTarget): Reachability => {
  try {
    withPsqlRetries(
      () => psqlAt(target, MAINTENANCE_DB, "SELECT 1"),
      `probe ${target.host}:${target.port}/${MAINTENANCE_DB}`,
    );
    return { status: "ok", target };
  } catch (err) {
    // withPsqlRetries rethrows absent/other immediately, and wraps exhausted transient in a new
    // Error({ cause }). Classify the root cause so wrapped ETIMEDOUT still counts as transient
    // (contention ≠ no Postgres → fail loud, never soft-skip).
    const root = err instanceof Error && err.cause !== undefined ? err.cause : err;
    const kind = classifyPsqlError(root);
    const detail = err instanceof Error ? err.message : String(err);
    if (kind === "absent") return { status: "absent" };
    return { status: "transient", detail, target };
  }
};

// libpq's own resolution ranking, restricted to targets expressible in a URL: an explicit
// PGHOST/PGPORT first, then the stock loopback listeners. A unix-socket DIRECTORY cannot survive
// a round-trip through a URL — the consuming suites rebuild PGHOST from `new URL(url).hostname`,
// which would hand libpq a percent-encoded path — so a socket-only server is deliberately not a
// candidate here and falls through to the fail-closed branch below.
const pgTargets = (): PgTarget[] => {
  const port = process.env.PGPORT ?? "5432";
  const explicit = process.env.PGHOST;
  return [
    ...(explicit !== undefined && explicit !== "" && !explicit.startsWith("/")
      ? [{ host: explicit, port }]
      : []),
    { host: "localhost", port },
    { host: "127.0.0.1", port },
  ];
};

const findReachableTarget = (): Reachability => {
  let lastTransient: Reachability | undefined;
  for (const target of pgTargets()) {
    const result = probeTarget(target);
    if (result.status === "ok") return result;
    if (result.status === "transient") lastTransient = result;
  }
  return lastTransient ?? { status: "absent" };
};

function provisionTestDatabase(): (() => void) | undefined {
  // An externally pinned non-empty URL (CI service container, dedicated per-lane DB) wins;
  // this only fills the hole, it never overrides a deliberate pin. Empty string is not a pin
  // (TEST_DATABASE_URL=) — treat like unset and continue auto-provision.
  const pinned = process.env.TEST_DATABASE_URL;
  if (pinned !== undefined && pinned !== "") return undefined;

  const reach = findReachableTarget();
  if (reach.status !== "ok") {
    const targets = pgTargets()
      .map((t) => `${t.host}:${t.port}`)
      .join(", ");
    // Contention/timeout after retries is NEVER "no Postgres" — failing open here is what made
    // lane evidence false-PASS (ZTR-1204). Always fail the run, independent of PG_REQUIRED.
    if (reach.status === "transient") {
      throw new Error(
        `PostgreSQL looked present but scratch-DB provisioning could not complete ` +
          `(transient/contention errors at ${targets}). ${reach.detail} ` +
          `Pin TEST_DATABASE_URL per lane on multi-lane machines (see README Developing), ` +
          `or free connection slots and re-run. DB-gated suites must not silently skip.`,
      );
    }
    // PG_REQUIRED=1 is exported only after an external probe found Postgres reachable, so
    // arriving here with it set means a broken gate or a socket-only server — never "this
    // machine has no Postgres". Fail loudly; a silent skip would make the DB-gated suites
    // vacuously green. (Bare CI=true without PG_REQUIRED still soft-skips when Postgres is
    // truly absent so a laptop without a local server can run non-pg suites.)
    if (process.env.PG_REQUIRED === "1") {
      throw new Error(
        "PG_REQUIRED=1 but no TCP-reachable PostgreSQL maintenance database was found at " +
          `${targets} — the DB-gated suites cannot run and must not silently skip. ` +
          "If this server is socket-only, export PGHOST/PGPORT for its TCP listener or set " +
          "TEST_DATABASE_URL directly.",
      );
    }
    return undefined;
  }

  const { target } = reach;
  // Name is chosen inside the retry loop: a client ETIMEDOUT can arrive AFTER Postgres has
  // already committed CREATE DATABASE, so a fixed name would fail the next attempt with
  // "already exists" (classified non-transient) and abort a healthy provision.
  let database = "";
  let createAttempt = 0;
  try {
    withPsqlRetries(() => {
      createAttempt += 1;
      database = `testdb_${process.pid}_${Date.now()}_${createAttempt}`;
      try {
        psqlAt(target, MAINTENANCE_DB, `CREATE DATABASE ${database}`);
      } catch (err) {
        // Idempotent success if a prior timed-out attempt actually created this name.
        const stderr = `${(err as { stderr?: Buffer | string }).stderr?.toString() ?? ""}\n${
          err instanceof Error ? err.message : String(err)
        }`;
        if (/already exists|duplicate key value.*pg_database/i.test(stderr)) {
          return;
        }
        throw err;
      }
    }, "CREATE DATABASE scratch");
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `vitest.global-setup failed to CREATE scratch database on ` +
        `${target.host}:${target.port}: ${detail}. ` +
        `Refusing to continue with TEST_DATABASE_URL unset (pg suites would skip silently). ` +
        `On multi-lane machines pin TEST_DATABASE_URL to a dedicated database per lane.`,
      { cause: err },
    );
  }

  const user = process.env.PGUSER ?? userInfo().username;
  const password = process.env.PGPASSWORD ?? "";
  const credentials =
    password === ""
      ? encodeURIComponent(user)
      : `${encodeURIComponent(user)}:${encodeURIComponent(password)}`;
  process.env.TEST_DATABASE_URL = `postgresql://${credentials}@${target.host}:${target.port}/${database}`;

  return () => {
    // WITH (FORCE) so a suite that leaked a connection cannot wedge the scratch database in place.
    // Retry DROP the same way as CREATE — teardown ETIMEDOUT under lane load is common and must
    // not be mistaken for a product failure, but we still try hard to clean up.
    try {
      withPsqlRetries(
        () => psqlAt(target, MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`),
        `DROP DATABASE ${database}`,
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      console.error(
        `[vitest.global-setup] failed to DROP scratch database ${database}: ${detail}. ` +
          `Manual cleanup: DROP DATABASE IF EXISTS ${database} WITH (FORCE);`,
      );
    }
  };
}

export default function setup(): (() => void) | undefined {
  return provisionTestDatabase();
}
