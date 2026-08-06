import { describe, expect, it } from "vitest";

import {
  assertDirectSessionDatabaseUrl,
  normalizeDatabaseUrl,
  PooledDatabaseEndpointError,
} from "../../src/db/session-endpoint.js";

describe("assertDirectSessionDatabaseUrl", () => {
  it("accepts a direct postgres URL on the standard port", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql://node:secret@db.internal:5432/zunode"),
    ).not.toThrow();
    expect(() =>
      assertDirectSessionDatabaseUrl("postgres://node@localhost/zunode"),
    ).not.toThrow();
  });

  it("accepts libpq unix-socket URLs (WhatWG-unparseable user@/ form)", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql://user@/dbname?host=/tmp/pg-run"),
    ).not.toThrow();
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql:///dbname?host=/var/run/postgresql"),
    ).not.toThrow();
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://node:secret@/zunode?host=/var/run/postgresql&sslmode=disable",
      ),
    ).not.toThrow();
  });

  it("still refuses pooled query flags on socket URLs", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://user@/dbname?host=/tmp/pg-run&pgbouncer=true",
      ),
    ).toThrow(/pgbouncer=/);
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql:///dbname?host=/var/run/postgresql&pool_mode=transaction",
      ),
    ).toThrow(/pool_mode=transaction/);
  });

  it("refuses well-known pooler ports", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql://node:secret@db.internal:6543/zunode"),
    ).toThrow(PooledDatabaseEndpointError);
    expect(() =>
      assertDirectSessionDatabaseUrl("postgresql://node:secret@db.internal:6432/zunode"),
    ).toThrow(/pooler listen port/);
  });

  it("refuses Supabase/Neon-style pooled hostnames", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://user:pass@db.project.pooler.supabase.com:5432/postgres",
      ),
    ).toThrow(PooledDatabaseEndpointError);
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://user:pass@mycluster-pooler.region.aws.neon.tech/neondb",
      ),
    ).toThrow(/pooled marker/);
  });

  it("refuses pgbouncer=true and pool_mode=transaction query flags", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://node:secret@db.internal:5432/zunode?pgbouncer=true",
      ),
    ).toThrow(/pgbouncer=/);
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://node:secret@db.internal:5432/zunode?pool_mode=transaction",
      ),
    ).toThrow(/pool_mode=transaction/);
  });

  it("refuses a non-postgres scheme and an unparseable URL", () => {
    expect(() => assertDirectSessionDatabaseUrl("mysql://db/zunode")).toThrow(
      PooledDatabaseEndpointError,
    );
    expect(() => assertDirectSessionDatabaseUrl("not a url")).toThrow(/not parseable/);
  });

  it("accepts pg's percent-encoded unix-socket shorthand in host position", () => {
    expect(() =>
      assertDirectSessionDatabaseUrl("postgres://%2Fvar%2Frun%2Fpostgresql/dbname"),
    ).not.toThrow();
    expect(() =>
      assertDirectSessionDatabaseUrl(
        "postgresql://user:secret@%2Fvar%2Frun%2Fpostgresql/zunode",
      ),
    ).not.toThrow();
    expect(() =>
      assertDirectSessionDatabaseUrl("postgres://%2Ftmp%2Fpg-run/dbname"),
    ).not.toThrow();
  });
});

describe("normalizeDatabaseUrl", () => {
  it("recognizes percent-encoded unix-socket host as a unix socket endpoint", () => {
    const result = normalizeDatabaseUrl("postgres://%2Fvar%2Frun%2Fpostgresql/dbname");
    expect(result.unixSocket).toBe(true);
    expect(result.parsed.pathname).toBe("/dbname");
  });

  it("preserves userinfo on percent-encoded unix-socket DSNs", () => {
    const result = normalizeDatabaseUrl(
      "postgresql://node:secret@%2Fvar%2Frun%2Fpostgresql/zunode",
    );
    expect(result.unixSocket).toBe(true);
    expect(result.parsed.username).toBe("node");
    expect(result.parsed.password).toBe("secret");
    expect(result.parsed.pathname).toBe("/zunode");
  });

  it("does not treat a normal hostname as a unix socket", () => {
    const result = normalizeDatabaseUrl("postgres://localhost:5432/dbname");
    expect(result.unixSocket).toBe(false);
  });

  it("still recognizes libpq ?host= query-param unix-socket form", () => {
    const result = normalizeDatabaseUrl(
      "postgresql://user@/dbname?host=/tmp/pg-run",
    );
    expect(result.unixSocket).toBe(true);
  });
});
