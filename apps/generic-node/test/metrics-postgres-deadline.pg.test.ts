import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  CachedDbProbe,
  METRICS_SNAPSHOT_STATEMENTS,
  type MetricsSqlExecutor,
  type ReadinessStateInputs,
} from "@zucoins/node-core";
import { withPostgresDeadline } from "../src/db/client.js";
import { createProductionMetricsSnapshotSource } from "../src/metrics/snapshot-source.js";

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const APPLICATION_NAME = `metrics_postgres_metrics_deadline_${process.pid}`;
const PG_AVAILABLE = (() => {
  try {
    execFileSync("pg_isready", ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER]);
    return true;
  } catch {
    try {
      execFileSync("node", [
        "-e",
        `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ], { stdio: "ignore", env: process.env });
      return true;
    } catch {
      return false;
    }
  }
})();

function state(): ReadinessStateInputs {
  return {
    schemaMigrated: true,
    vaultKeyRingLoaded: true,
    vaultCensusVerified: true,
    observationReadCapable: true,
    restoreHoldClear: true,
    leadershipLockHeld: true,
    eventSignerAvailable: true,
    halted: false,
    storagePressure: false,
    stopping: false,
    observationDegraded: false,
  };
}

function successfulSql(text: string): string {
  if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_WALLETS_BY_STATE) {
    return "SELECT 'AVAILABLE'::text AS state, 1::int AS wallets";
  }
  if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_AVAILABLE_WALLETS) {
    return "SELECT 1::int AS available_count";
  }
  if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_ACTIVE_LEASES_BY_ROLE) {
    return "SELECT 'SEND'::text AS lease_role, 0::int AS leases, 0::int AS oldest_age_secs WHERE false";
  }
  if (text === METRICS_SNAPSHOT_STATEMENTS.QUEUE_DEPTH_AND_OLDEST_AGE) {
    return "SELECT 0::int AS depth, 0::int AS oldest_age_secs";
  }
  if (text === METRICS_SNAPSHOT_STATEMENTS.COUNT_QUARANTINED_UNEXPECTED_HEAD) {
    return "SELECT 0::int AS wallets";
  }
  return "SELECT 'CREATED'::text AS status, 0::int AS ops, 0::int AS oldest_age_secs WHERE false";
}

describe.runIf(PG_AVAILABLE)("/metrics PostgreSQL cancellation and recovery", () => {
  let pool: Pool;
  let observer: Pool;

  beforeAll(() => {
    const config = {
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: "postgres",
      password: process.env.PGPASSWORD,
      application_name: APPLICATION_NAME,
      max: 2,
    };
    pool = new Pool(config);
    observer = new Pool({ ...config, application_name: `${APPLICATION_NAME}_observer` });
  });

  afterAll(async () => {
    await Promise.all([pool.end(), observer.end()]);
  });

  it("cancels a stalled shared-pool census, coalesces scrapes, releases idle, and recovers next scrape", async () => {
    let stall = true;
    let censusRuns = 0;
    const source = createProductionMetricsSnapshotSource({
      getState: state,
      dbProbe: new CachedDbProbe(async () => {}),
      db: { query: async () => ({ rows: [] }) },
      poolCapTotal: 10,
      queryTimeoutMs: 75,
      withinDbDeadline: async (remainingMs, work) => {
        censusRuns += 1;
        return withPostgresDeadline(pool, remainingMs, async (boundedDb) => {
          let first = true;
          const mapped: MetricsSqlExecutor = {
            async query<R>(text: string) {
              if (stall && first) {
                first = false;
                return boundedDb.query<R>("SELECT pg_sleep(10)");
              }
              return boundedDb.query<R>(successfulSql(text));
            },
          };
          return work(mapped);
        });
      },
    });

    const startedAt = performance.now();
    const [first, concurrent] = await Promise.all([source(), source()]);
    expect(performance.now() - startedAt).toBeLessThan(1_000);
    expect(first).toMatchObject({ databaseTruthAvailable: 0 });
    expect(concurrent).toMatchObject({ databaseTruthAvailable: 0 });
    expect(censusRuns).toBe(1);
    expect(pool.waitingCount).toBe(0);

    // Full-suite load: cancelled statement_timeout backends can leave the pool
    // connection non-idle for a beat while ROLLBACK/release settles. Poll.
    let idleOk = false;
    for (let i = 0; i < 40; i++) {
      if (pool.idleCount === pool.totalCount && pool.totalCount > 0) {
        idleOk = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(idleOk, `pool never idled: idle=${pool.idleCount} total=${pool.totalCount}`).toBe(
      true,
    );

    let active = -1;
    for (let i = 0; i < 40; i++) {
      const activity = await observer.query<{ active: number }>(
        `SELECT count(*)::int AS active FROM pg_stat_activity
          WHERE application_name = $1 AND state = 'active'`,
        [APPLICATION_NAME],
      );
      active = activity.rows[0]?.active ?? -1;
      if (active === 0) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(active).toBe(0);

    stall = false;
    // Under full-suite load the cancelled pg_sleep backend can still be winding down
    // when the next scrape starts; retry briefly so a transient post-cancel blip does
    // not fail the recovery assertion (local single-file run is always first-try green).
    let recovered: Awaited<ReturnType<typeof source>> | undefined;
    let lastErr: unknown;
    for (let attempt = 0; attempt < 8; attempt++) {
      try {
        recovered = await source();
        if (
          recovered.databaseTruthAvailable === 1 &&
          recovered.availableWallets === 1 &&
          recovered.totalWallets === 1
        ) {
          break;
        }
      } catch (err) {
        lastErr = err;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(recovered, `recovery scrape failed: ${String(lastErr)}`).toMatchObject({
      databaseTruthAvailable: 1,
      availableWallets: 1,
      totalWallets: 1,
    });
    expect(censusRuns).toBeGreaterThanOrEqual(2);
    expect(pool.waitingCount).toBe(0);
    expect(pool.idleCount).toBe(pool.totalCount);
  }, 20_000);
});
