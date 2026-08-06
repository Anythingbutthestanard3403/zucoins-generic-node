import { Pool, type PoolClient } from "pg";

export class PostgresDeadlineExceededError extends Error {
  constructor(budgetMs: number) {
    super(`PostgreSQL operation exceeded ${budgetMs}ms monotonic budget`);
    this.name = "PostgresDeadlineExceededError";
  }
}

export interface DeadlineSqlExecutor {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ readonly rows: R[]; readonly rowCount?: number | null }>;
}

async function acquireClientWithin(
  pool: Pool,
  budgetMs: number,
): Promise<PoolClient> {
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const connecting = pool.connect();
  connecting.then(
    (lateClient) => {
      if (timedOut) lateClient.release();
    },
    () => {},
  );
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(new PostgresDeadlineExceededError(budgetMs));
    }, budgetMs);
  });
  try {
    return await Promise.race([connecting, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Run DB work on one checked-out connection with PostgreSQL-enforced cancellation.
 * Concurrent calls made by the collector are serialized because a transaction-local
 * statement_timeout must be paired with exactly the statement it bounds. Before every
 * statement the timeout is reduced to the remaining monotonic operation budget. The
 * connection is released only after every queued statement has settled and rollback/commit
 * has completed, so a timed-out scrape cannot strand shared-pool work.
 */
export async function withPostgresDeadline<T>(
  pool: Pool,
  budgetMs: number,
  operation: (db: DeadlineSqlExecutor) => Promise<T>,
  monotonicNowMs: () => number = () => performance.now(),
): Promise<T> {
  if (!Number.isFinite(budgetMs) || budgetMs <= 0) {
    throw new RangeError("withPostgresDeadline: budgetMs must be positive and finite");
  }
  const startedAtMs = monotonicNowMs();
  const client = await acquireClientWithin(pool, Math.max(1, Math.ceil(budgetMs)));
  let tail: Promise<void> = Promise.resolve();
  let firstFailure: unknown;
  const db: DeadlineSqlExecutor = {
    query<R>(text: string, params?: readonly unknown[]) {
      const result = tail.then(async () => {
        if (firstFailure !== undefined) throw firstFailure;
        const remainingMs = budgetMs - (monotonicNowMs() - startedAtMs);
        if (remainingMs <= 0) throw new PostgresDeadlineExceededError(budgetMs);
        try {
          await client.query("SELECT set_config('statement_timeout', $1, true)", [
            `${Math.max(1, Math.ceil(remainingMs))}ms`,
          ]);
          const queryResult = await client.query(text, params as unknown[] | undefined);
          return {
            rows: queryResult.rows as R[],
            rowCount: queryResult.rowCount,
          };
        } catch (error) {
          firstFailure = error;
          throw error;
        }
      });
      tail = result.then(
        () => {},
        () => {},
      );
      return result;
    },
  };

  await client.query("BEGIN");
  try {
    const result = await operation(db);
    await tail;
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await tail;
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

// The generic-node reporting store's database access. The durable reporting store
// (src/reporting/durable-store.ts) is written against a minimal injected query client so it is
// unit-testable without a socket; this module is the production wiring that backs it with a real
// pg Pool.
//
// no env read and no Pool construction happens at import time — every composition root
// (main.ts, stage1-main.ts, db/migrate.ts) validates DATABASE_URL through its own consolidated
// config schema first, then calls createPool(databaseUrl) with the validated value. This keeps a
// bare `import` of this module (or anything that imports it) side-effect-free, so a malformed or
// missing DATABASE_URL is always reported through one canonical validation pass instead of
// whichever module happens to load first.
export function createPool(databaseUrl: string): Pool {
  const pool = new Pool({ connectionString: databaseUrl });

  // An idle client hard-dropped by the OS (container kill, network RST) emits an unhandled pool
  // 'error' event; Node's EventEmitter throws when an 'error' event has no listener, crashing the
  // process. Log-and-continue instead — pg recycles the dead client and later queries surface as
  // normal rejections.
  pool.on("error", (err) => {
    console.error(
      "generic-node database lost an idle PostgreSQL connection; the pool will replace it automatically. This is usually transient, but inspect DATABASE_URL connectivity and readiness if it repeats.",
      err,
    );
  });

  return pool;
}
