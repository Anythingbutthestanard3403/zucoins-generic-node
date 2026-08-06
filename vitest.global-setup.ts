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
const MAINTENANCE_DB = "postgres";

interface PgTarget {
  readonly host: string;
  readonly port: string;
}

const psqlAt = (target: PgTarget, database: string, sql: string): void => {
  execFileSync(
    "psql",
    ["-h", target.host, "-p", target.port, "-d", database, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql],
    { stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
  );
};

// Probe the ACTUAL maintenance database, not just `pg_isready`: a server accepting connections
// does not prove a usable database exists (psql with no -d targets a database named after the OS
// user, which is typically absent). Same reasoning as
// packages/node-core/test/custody-eligibility-lease-pk.test.ts.
const reachable = (target: PgTarget): boolean => {
  try {
    psqlAt(target, MAINTENANCE_DB, "SELECT 1");
    return true;
  } catch {
    return false;
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

function provisionTestDatabase(): (() => void) | undefined {
  // An externally pinned URL (a CI service container, a run targeting its own instance) wins;
  // this only fills the hole, it never overrides a deliberate choice.
  if (process.env.TEST_DATABASE_URL !== undefined) return undefined;

  const target = pgTargets().find(reachable);
  if (target === undefined) {
    // PG_REQUIRED=1 is exported only after an external probe found Postgres reachable, so
    // arriving here with it set means a broken gate or a socket-only server — never "this
    // machine has no Postgres". Fail loudly; a silent skip would make the DB-gated suites
    // vacuously green.
    if (process.env.PG_REQUIRED === "1") {
      throw new Error(
        "PG_REQUIRED=1 but no TCP-reachable PostgreSQL maintenance database was found at " +
          `${pgTargets()
            .map((t) => `${t.host}:${t.port}`)
            .join(", ")} — the DB-gated suites cannot run and must not silently skip. ` +
          "If this server is socket-only, export PGHOST/PGPORT for its TCP listener or set " +
          "TEST_DATABASE_URL directly.",
      );
    }
    return undefined;
  }

  const database = `testdb_${process.pid}_${Date.now()}`;
  psqlAt(target, MAINTENANCE_DB, `CREATE DATABASE ${database}`);

  const user = process.env.PGUSER ?? userInfo().username;
  const password = process.env.PGPASSWORD ?? "";
  const credentials =
    password === ""
      ? encodeURIComponent(user)
      : `${encodeURIComponent(user)}:${encodeURIComponent(password)}`;
  process.env.TEST_DATABASE_URL = `postgresql://${credentials}@${target.host}:${target.port}/${database}`;

  return () => {
    // WITH (FORCE) so a suite that leaked a connection cannot wedge the scratch database in place.
    psqlAt(target, MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  };
}

export default function setup(): (() => void) | undefined {
  return provisionTestDatabase();
}
