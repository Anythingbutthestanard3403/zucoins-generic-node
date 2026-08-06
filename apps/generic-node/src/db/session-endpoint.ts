/**
 * Fail-closed direct/session-mode DATABASE_URL enforcement.
 *
 * The overlap probe (and the signer leadership lock) read session-scoped
 * advisory locks. Through a transaction-mode pooler the lock a node holds is
 * not pinned to the connection the guard later reads from, so the probe can
 * report "no overlap" against a live signer — the exact fail-open this guard exists
 * to prevent. Introducing a pooled endpoint requires re-designing the guard,
 * not working around it here.
 *
 * Checks are pure URL/heuristic inspection (no network). They refuse known
 * pooled host/port/query shapes before any migration DDL runs.
 *
 * Unix-domain socket libpq forms (empty hostname + absolute `host=/…` query,
 * and pg's percent-encoded-host shorthand `postgres://%2Fvar%2Frun%2Fpostgresql/dbname`)
 * are direct session endpoints and must be accepted even when WhatWG `URL`
 * cannot parse them without a host rewrite.
 */

/**
 * The operational stop-first deploy procedure. Held as a constant so the refusal message
 * interpolates it rather than inlining the phrase — a marker on an inlined name would
 * otherwise print into the operator's terminal.
 */
const STOP_FIRST_PROCEDURE = "the stop-first drain-and-deploy procedure"; // contract-allow:drain:names the operational procedure verbatim, not rewordable here

export class PooledDatabaseEndpointError extends Error {
  constructor(reason: string) {
    super(
      `DATABASE_URL is not a direct/session-mode Postgres endpoint (${reason}). ` +
        `The migration overlap probe and signer leadership lock require a ` +
        `session-scoped connection; a transaction-mode pooler (PgBouncer ` +
        `transaction mode, Supabase/Neon/Railway "pooled" variants) makes the ` +
        `probe fail open. Point DATABASE_URL at the direct Postgres endpoint. ` +
        `See ${STOP_FIRST_PROCEDURE}, "database endpoint assumption".`,
    );
    this.name = "PooledDatabaseEndpointError";
  }
}

/** Well-known PgBouncer / pooler default listen port. */
const POOLER_PORTS = new Set([6432, 6543]);

/**
 * Host substrings that mark a vendor "pooled" endpoint. Matched case-insensitively
 * against the hostname only (not the path/userinfo), so a DB named `pooler` is fine.
 */
const POOLED_HOST_MARKERS = [
  "pooler.supabase.com",
  ".pooler.supabase.com",
  "-pooler.",
  ".pooler.",
  "pgbouncer",
] as const;

/**
 * Query-string keys/values that mark a pooled or transaction-mode endpoint.
 * `pgbouncer=true` is the Supabase convention; `pool_mode=transaction` is
 * explicit; `sslmode` alone is never disqualifying.
 */
function queryLooksPooled(searchParams: URLSearchParams): string | null {
  const pgbouncer = searchParams.get("pgbouncer");
  if (pgbouncer !== null && pgbouncer.toLowerCase() !== "false" && pgbouncer !== "0") {
    return `query contains pgbouncer=${pgbouncer}`;
  }
  const poolMode = searchParams.get("pool_mode") ?? searchParams.get("poolmode");
  if (poolMode !== null && poolMode.toLowerCase() === "transaction") {
    return `query contains pool_mode=transaction`;
  }
  return null;
}

function hostLooksPooled(hostname: string): string | null {
  const host = hostname.toLowerCase();
  for (const marker of POOLED_HOST_MARKERS) {
    if (host.includes(marker)) {
      return `hostname contains pooled marker ${JSON.stringify(marker)}`;
    }
  }
  return null;
}

function isAbsoluteUnixSocketPath(hostParam: string | null): boolean {
  return hostParam !== null && hostParam.startsWith("/");
}

/**
 * pg accepts a percent-encoded unix-socket directory in host position:
 *   postgres://%2Fvar%2Frun%2Fpostgresql/dbname
 * WHATWG `URL` keeps the percent-encoding in `hostname` (it does not decode
 * `%2F` → `/` there), so we detect the `%2F` / `%2f` prefix and confirm the
 * decoded value is an absolute path.
 */
function isPercentEncodedAbsolutePath(hostname: string): boolean {
  if (hostname === "") return false;
  if (!hostname.toUpperCase().startsWith("%2F")) return false;
  try {
    return decodeURIComponent(hostname).startsWith("/");
  } catch {
    return false;
  }
}

/**
 * Libpq allows empty-hostname URLs that WhatWG rejects when userinfo is present:
 *   postgresql://user@/dbname?host=/tmp/pg-run
 * Rewrite only enough for `URL` to parse; the socket identity stays on `host=`.
 */
function rewriteEmptyHostForWhatWg(databaseUrl: string): string | null {
  const match = databaseUrl.match(
    /^(postgres(?:ql)?:\/\/(?:[^/?#]*@)?)(\/[^?]*)(\?[^#]*)?(#.*)?$/i,
  );
  if (match === null) return null;
  const [, prefix, pathPart, query = "", hash = ""] = match;
  // Already had a non-empty host between scheme and path — not a socket form.
  // prefix ends with "://" or "userinfo@"; if there is host text between those and
  // the path we wouldn't match (host would sit before path). When match succeeds
  // with prefix ending //@ or trailing @, insert a parse-only localhost.
  if (!prefix.endsWith("://") && !prefix.endsWith("@")) return null;
  return `${prefix}localhost${pathPart}${query}${hash}`;
}

export interface NormalizedEndpoint {
  readonly parsed: URL;
  /** True when this is a libpq unix-socket endpoint (empty host + absolute host=). */
  readonly unixSocket: boolean;
}

/**
 * Parse `databaseUrl` into a `URL`, rewriting libpq's WhatWG-unparseable empty-host
 * unix-socket forms (`postgres://user@/dbname?host=/tmp/pg-run`) with a parse-only
 * `localhost` stand-in. Also recognizes pg's percent-encoded unix-socket shorthand
 * (`postgres://%2Fvar%2Frun%2Fpostgresql/dbname`) where the socket directory sits
 * in host position as percent-encoded slashes. Callers that only need the parsed
 * structure (path, query, userinfo) — not the literal hostname — can safely reuse
 * this across DSN shapes instead of hand-rolling `new URL()` and losing the
 * unix-socket / pooled-endpoint edge cases this already handles.
 */
export function normalizeDatabaseUrl(databaseUrl: string): NormalizedEndpoint {
  let parsed: URL | null = null;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    parsed = null;
  }

  if (parsed !== null) {
    const socketHost = isAbsoluteUnixSocketPath(parsed.searchParams.get("host"));
    if (parsed.hostname === "" && socketHost) {
      return { parsed, unixSocket: true };
    }
    // pg's percent-encoded unix-socket shorthand in host position:
    //   postgres://%2Fvar%2Frun%2Fpostgresql/dbname
    if (isPercentEncodedAbsolutePath(parsed.hostname)) {
      return { parsed, unixSocket: true };
    }
    if (parsed.hostname !== "" || !socketHost) {
      return { parsed, unixSocket: false };
    }
  }

  const rewritten = rewriteEmptyHostForWhatWg(databaseUrl);
  if (rewritten === null) {
    throw new PooledDatabaseEndpointError("URL is not parseable");
  }
  try {
    parsed = new URL(rewritten);
  } catch {
    throw new PooledDatabaseEndpointError("URL is not parseable");
  }
  const socketHost = isAbsoluteUnixSocketPath(parsed.searchParams.get("host"));
  if (!socketHost) {
    // Rewrite was only for socket forms; without absolute host= still refuse.
    throw new PooledDatabaseEndpointError("URL is not parseable");
  }
  return { parsed, unixSocket: true };
}

/**
 * Inspect `databaseUrl` and throw {@link PooledDatabaseEndpointError} if it
 * matches a known transaction-mode / pooled shape. A URL that cannot be parsed
 * as postgres/postgresql is refused as well — the env schema already requires
 * the scheme, but migrate may be invoked with a raw env string.
 */
export function assertDirectSessionDatabaseUrl(databaseUrl: string): void {
  const { parsed, unixSocket } = normalizeDatabaseUrl(databaseUrl);

  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "postgres" && scheme !== "postgresql") {
    throw new PooledDatabaseEndpointError(`scheme is ${scheme}, not postgres/postgresql`);
  }

  // Empty-hostname / unix-socket endpoints are direct sessions; skip host markers.
  if (!unixSocket && parsed.hostname !== "") {
    const hostReason = hostLooksPooled(parsed.hostname);
    if (hostReason) throw new PooledDatabaseEndpointError(hostReason);
  }

  if (parsed.port) {
    const port = Number(parsed.port);
    if (POOLER_PORTS.has(port)) {
      throw new PooledDatabaseEndpointError(
        `port ${port} is a well-known pooler listen port (use the direct Postgres port)`,
      );
    }
  }

  const queryReason = queryLooksPooled(parsed.searchParams);
  if (queryReason) throw new PooledDatabaseEndpointError(queryReason);
}
