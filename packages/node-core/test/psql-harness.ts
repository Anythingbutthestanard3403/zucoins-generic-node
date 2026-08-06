// Shared real-PostgreSQL psql harness for node-core PG suites.
//
// Lifted verbatim from test/leases/cross-operation-lease-exclusion.pg.test.ts
// so the receive pool-allocator suite races the same way: one `psql` OS process per
// contender, so concurrency is proven at the database transaction boundary rather than
// by an in-process Promise.all over shared connections. node-core carries no SQL driver
// so psql subprocesses are the only real-PG path available to tests.
//
// The end-of-statement sentinel is harness-neutral (`__PSQL_SESSION_END__`); everything
// else is unmodified.

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import type { SqlExecutor, SqlQueryResult } from "../src/leases/types.ts";

// ─── psql helpers ───────────────────────────────────────────────────────────

export interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

export const runPsql = (url: string, sql: string, timeoutMs = 30_000): PsqlOutcome => {
  try {
    const stdout = execFileSync(
      "psql",
      [url, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
      { encoding: "utf-8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

export const psqlMust = (url: string, sql: string): string => {
  const outcome = runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

export const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

export const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

// ─── SqlExecutor over a long-lived psql session (one OS process = one conn) ─

export function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
}

export function bindSql(text: string, params: readonly unknown[] = []): string {
  return text.replace(/\$(\d+)/g, (_m, n: string) => {
    const idx = Number(n) - 1;
    if (idx < 0 || idx >= params.length) {
      throw new Error(`missing sql param $${n}`);
    }
    return sqlLiteral(params[idx]);
  });
}

/**
 * Wrap a data-modifying WITH … SELECT so the result rows come back as one JSON array,
 * without nesting the modifying CTE inside a subquery (Postgres 0A000).
 * Shape: `WITH …, __result AS (<final SELECT>) SELECT json_agg(row_to_json(t)) FROM __result t`.
 */
export function wrapModifyingCteAsJson(sql: string): string {
  const marker = ") SELECT";
  const idx = sql.toUpperCase().lastIndexOf(marker);
  if (idx === -1) {
    throw new Error("wrapModifyingCteAsJson: no trailing ') SELECT' in modifying CTE");
  }
  // Preserve original casing of the head; rebuild the final SELECT from the original slice.
  const head = sql.slice(0, idx + 1);
  const selectClause = sql.slice(idx + 2).trim(); // "SELECT …"
  return (
    `${head}, __result AS (${selectClause}) ` +
    `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __result t`
  );
}

export function pgEnv(url: string): NodeJS.ProcessEnv {
  const u = new URL(url);
  return {
    ...process.env,
    PGHOST: u.hostname || "localhost",
    PGPORT: u.port === "" ? "5432" : u.port,
    PGUSER: decodeURIComponent(u.username) || process.env.USER || "postgres",
    PGPASSWORD: decodeURIComponent(u.password),
    PGDATABASE: u.pathname.replace(/^\//, ""),
  };
}

/**
 * One `psql` OS process = one DB session. Multi-statement acquire/release runs
 * under an explicit BEGIN so FOR UPDATE locks stay visible until commit.
 */
export class PsqlSessionExecutor implements SqlExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(line: string) => void> = [];
  private readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  start(): void {
    if (this.child) return;
    // No ON_ERROR_STOP: a mid-tx failure must leave the session alive so we can
    // ROLLBACK and still surface the ERROR text.
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"], {
      env: pgEnv(this.url),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      let idx = this.buffer.indexOf("__PSQL_SESSION_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__PSQL_SESSION_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__PSQL_SESSION_END__\n");
      }
    });
  }

  stop(): void {
    if (!this.child) return;
    this.child.stdin.end();
    this.child.kill("SIGTERM");
    this.child = null;
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`psql session timeout: ${sql.slice(0, 80)}`)),
        20_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          const err = new Error(payload.trim());
          (err as { code?: string }).code = extractSqlstate(payload);
          reject(err);
          return;
        }
        resolve(payload);
      });
      child.stdin.write(`${sql};\n\\echo __PSQL_SESSION_END__\n`);
    });
  }

  async begin(): Promise<void> {
    await this.send("BEGIN");
  }

  async commit(): Promise<void> {
    await this.send("COMMIT");
  }

  async rollback(): Promise<void> {
    try {
      await this.send("ROLLBACK");
    } catch {
      // session may already be aborted
    }
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    const isMut = /^(INSERT|UPDATE|DELETE)\b/i.test(trimmed);
    if (isMut) {
      // INSERT … RETURNING must surface the returned columns (e.g. operation_id for the
      // receive-admission arbiter). Stripping them to a rowCount alone makes ON CONFLICT
      // DO NOTHING indistinguishable from a successful insert. Bare mutations (no RETURNING)
      // keep the historical count-only wrap.
      if (/\bRETURNING\b/i.test(trimmed)) {
        const jsonSql =
          `WITH __m AS (${trimmed}) ` +
          `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __m t`;
        const out = await this.send(jsonSql);
        const lines = out
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.length > 0);
        const json = lines[lines.length - 1] ?? "[]";
        const rows = JSON.parse(json) as R[];
        return { rows, rowCount: rows.length };
      }
      const wrapped = `WITH __m AS (${trimmed} RETURNING 1) SELECT count(*)::int AS __rc FROM __m`;
      const out = await this.send(wrapped);
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const count = Number(lines[lines.length - 1] ?? "0");
      return { rows: [] as R[], rowCount: count };
    }
    if (/^SELECT EXISTS/i.test(trimmed)) {
      const out = await this.send(trimmed);
      const exists = out.trim() === "t" || out.trim() === "true";
      return { rows: [{ exists } as R], rowCount: 1 };
    }
    if (/^(CREATE|DROP|ALTER|TRUNCATE)\b/i.test(trimmed)) {
      await this.send(trimmed);
      return { rows: [] as R[], rowCount: 1 };
    }
    // Data-modifying WITH cannot be nested (Postgres 0A000); keep CTE at top level.
    if (/^WITH\b/i.test(trimmed) && /\b(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      const out = await this.send(wrapModifyingCteAsJson(trimmed));
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const json = lines[lines.length - 1] ?? "[]";
      const rows = JSON.parse(json) as R[];
      return { rows, rowCount: rows.length };
    }
    // Plain WITH … SELECT and bare SELECT — nest under json_agg.
    if (/^(SELECT|WITH)\b/i.test(trimmed)) {
      const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${trimmed}) t`;
      const out = await this.send(jsonSql);
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const json = lines[lines.length - 1] ?? "[]";
      const rows = JSON.parse(json) as R[];
      return { rows, rowCount: rows.length };
    }
    await this.send(trimmed);
    return { rows: [] as R[], rowCount: 1 };
  }
}

/** Autocommit executor for migrate/readiness probes. */
export class PsqlExecutor implements SqlExecutor {
  constructor(private readonly url: string) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    if (/^(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      if (/\bRETURNING\b/i.test(trimmed)) {
        const jsonSql =
          `WITH __m AS (${trimmed}) ` +
          `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __m t`;
        const outcome = runPsql(this.url, jsonSql);
        if (!outcome.ok) {
          const err = new Error(outcome.stderr.trim() || "psql mutation RETURNING failed");
          (err as { code?: string }).code = extractSqlstate(outcome.stderr);
          throw err;
        }
        const rows = JSON.parse(outcome.stdout.trim() || "[]") as R[];
        return { rows, rowCount: rows.length };
      }
      const wrapped = `WITH __m AS (${trimmed} RETURNING 1) SELECT count(*)::int AS __rc FROM __m`;
      const outcome = runPsql(this.url, wrapped);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql mutation failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      return { rows: [] as R[], rowCount: Number(outcome.stdout.trim() || "0") };
    }
    if (/^SELECT EXISTS/i.test(trimmed)) {
      const direct = runPsql(this.url, trimmed);
      if (!direct.ok) {
        const err = new Error(direct.stderr.trim() || "psql failed");
        (err as { code?: string }).code = extractSqlstate(direct.stderr);
        throw err;
      }
      const exists = direct.stdout.trim() === "t" || direct.stdout.trim() === "true";
      return { rows: [{ exists } as R], rowCount: 1 };
    }
    if (/^(CREATE|DROP|ALTER|TRUNCATE)\b/i.test(trimmed)) {
      const outcome = runPsql(this.url, trimmed);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      return { rows: [] as R[], rowCount: 1 };
    }
    if (/^WITH\b/i.test(trimmed) && /\b(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
      const outcome = runPsql(this.url, wrapModifyingCteAsJson(trimmed));
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql modifying-CTE failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      const rows = JSON.parse(outcome.stdout.trim() || "[]") as R[];
      return { rows, rowCount: rows.length };
    }
    if (/^(SELECT|WITH)\b/i.test(trimmed)) {
      const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${trimmed}) t`;
      const outcome = runPsql(this.url, jsonSql);
      if (!outcome.ok) {
        const err = new Error(outcome.stderr.trim() || "psql select failed");
        (err as { code?: string }).code = extractSqlstate(outcome.stderr);
        throw err;
      }
      const rows = JSON.parse(outcome.stdout.trim() || "[]") as R[];
      return { rows, rowCount: rows.length };
    }
    const outcome = runPsql(this.url, trimmed);
    if (!outcome.ok) {
      const err = new Error(outcome.stderr.trim() || "psql failed");
      (err as { code?: string }).code = extractSqlstate(outcome.stderr);
      throw err;
    }
    return { rows: [] as R[], rowCount: 1 };
  }
}

export async function withTx<T>(url: string, body: (db: PsqlSessionExecutor) => Promise<T>): Promise<T> {
  const session = new PsqlSessionExecutor(url);
  session.start();
  try {
    await session.begin();
    const result = await body(session);
    await session.commit();
    return result;
  } catch (err) {
    await session.rollback();
    throw err;
  } finally {
    session.stop();
  }
}
