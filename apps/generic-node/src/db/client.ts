import { Pool, type PoolClient, type PoolConfig } from "pg";

import { createSafeConsoleLogger } from "../boot/safe-logger.js";

export class PostgresDeadlineExceededError extends Error {
  constructor(budgetMs: number) {
    super(`PostgreSQL operation exceeded ${budgetMs}ms monotonic budget`);
    this.name = "PostgresDeadlineExceededError";
  }
}

/**
 * Options for the production runtime pool. All knobs are validated by the
 * composition root's config schema before they reach here — this module never
 * reads env. Defaults match `apps/generic-node/src/config/constants.ts`.
 */
export interface CreatePoolOptions {
  /** Max clients in the pool (`pg` default is 10). */
  readonly max?: number;
  /** How long `pool.connect()` may wait for a free client before rejecting. */
  readonly connectionTimeoutMillis?: number;
  /** How long an idle client may sit in the pool before being closed. */
  readonly idleTimeoutMillis?: number;
  /**
   * TCP keepalive on every pooled socket. Required so a silently half-open
   * connection (NAT/firewall idle reaper) eventually surfaces as `error`/`end`
   * — the events leadership loss detection depends on (ZTR-1156).
   */
  readonly keepAlive?: boolean;
  /** Delay before the first keepalive probe (ms). */
  readonly keepAliveInitialDelayMillis?: number;
}

export const DEFAULT_CREATE_POOL_OPTIONS: Readonly<Required<CreatePoolOptions>> = {
  max: 20,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10_000,
};

/**
 * Apply a transaction-local `statement_timeout` on an already-open transaction.
 * Uses `set_config(..., true)` so the bound dies with the transaction and never
 * leaks onto a pooled connection after COMMIT/ROLLBACK. Migrations must NOT
 * call this — they use a longer session-level SET in `db/migrate.ts`.
 */
export async function applyMoneyPathStatementTimeout(
  client: Pick<PoolClient, "query">,
  timeoutMs: number,
): Promise<void> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("applyMoneyPathStatementTimeout: timeoutMs must be positive and finite");
  }
  await client.query("SELECT set_config('statement_timeout', $1, true)", [
    `${Math.max(1, Math.ceil(timeoutMs))}ms`,
  ]);
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
// config schema first, then calls createPool(databaseUrl, options?) with the validated value.
// This keeps a bare `import` of this module (or anything that imports it) side-effect-free, so a
// malformed or missing DATABASE_URL is always reported through one canonical validation pass
// instead of whichever module happens to load first.
//
// Pool timeouts/keepAlive are ALWAYS applied (defaults above). Callers may override individual
// knobs from validated config; they may not strip them by omission. Migrations share this pool
// factory for connect/idle/max/keepAlive only — money-path statement_timeout is applied
// transaction-locally via {@link applyMoneyPathStatementTimeout}, never as a pool default, so
// long DDL is not clipped by a worker-tick budget (ZTR-1156).
export function createPool(databaseUrl: string, options: CreatePoolOptions = {}): Pool {
  const resolved: Required<CreatePoolOptions> = {
    max: options.max ?? DEFAULT_CREATE_POOL_OPTIONS.max,
    connectionTimeoutMillis:
      options.connectionTimeoutMillis ?? DEFAULT_CREATE_POOL_OPTIONS.connectionTimeoutMillis,
    idleTimeoutMillis: options.idleTimeoutMillis ?? DEFAULT_CREATE_POOL_OPTIONS.idleTimeoutMillis,
    // keepAlive defaults ON and cannot be turned off via partial options — a silent half-open
    // socket is exactly the leadership split-brain failure mode this ticket closes.
    keepAlive: options.keepAlive ?? DEFAULT_CREATE_POOL_OPTIONS.keepAlive,
    keepAliveInitialDelayMillis:
      options.keepAliveInitialDelayMillis ??
      DEFAULT_CREATE_POOL_OPTIONS.keepAliveInitialDelayMillis,
  };

  const config: PoolConfig = {
    connectionString: databaseUrl,
    max: resolved.max,
    connectionTimeoutMillis: resolved.connectionTimeoutMillis,
    idleTimeoutMillis: resolved.idleTimeoutMillis,
    keepAlive: resolved.keepAlive,
    keepAliveInitialDelayMillis: resolved.keepAliveInitialDelayMillis,
  };
  const pool = new Pool(config);

  // An idle client hard-dropped by the OS (container kill, network RST) emits an unhandled pool
  // 'error' event; Node's EventEmitter throws when an 'error' event has no listener, crashing the
  // process. Log-and-continue instead — pg recycles the dead client and later queries surface as
  // normal rejections. Route through the redactor chokepoint so a driver message that quotes a
  // DSN credential cannot reach the platform log store raw (ZTR-1215).
  const poolErrorLog = createSafeConsoleLogger();
  pool.on("error", (err) => {
    poolErrorLog.error(
      "generic-node database lost an idle PostgreSQL connection; the pool will replace it automatically. This is usually transient, but inspect DATABASE_URL connectivity and readiness if it repeats.",
      err,
    );
  });

  return pool;
}
