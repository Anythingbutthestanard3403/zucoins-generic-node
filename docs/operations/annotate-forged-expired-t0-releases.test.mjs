/**
 * ZTR-1296 — unit coverage for the annotate script's staging gate.
 * node:test so it stays free of the vitest project graph (ops script under docs/).
 *
 *   node --test docs/operations/annotate-forged-expired-t0-releases.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  INCIDENT_ID,
  assertStagingGate,
  parseExpectHost,
  resolveDatabaseHost,
} from "./annotate-forged-expired-t0-releases.mjs";

const STAGING_ENV = Object.freeze({
  STAGING_CONFIRM: INCIDENT_ID,
  PUBLIC_BASE_URL: "https://staging.example.invalid",
});

// --- parseExpectHost -------------------------------------------------------

test("parseExpectHost reads --expect-host <value>", () => {
  assert.equal(parseExpectHost(["node", "script.mjs", "--expect-host", "db.staging.example"]), "db.staging.example");
});

test("parseExpectHost reads --expect-host=value", () => {
  assert.equal(parseExpectHost(["--expect-host=db.lab.internal"]), "db.lab.internal");
});

test("parseExpectHost returns null when flag absent", () => {
  assert.equal(parseExpectHost(["node", "script.mjs", "--execute"]), null);
});

test("parseExpectHost returns empty string when flag has no value", () => {
  assert.equal(parseExpectHost(["--expect-host"]), "");
  assert.equal(parseExpectHost(["--expect-host", "--execute"]), "");
});

// --- resolveDatabaseHost ---------------------------------------------------

test("resolveDatabaseHost extracts TCP hostname", () => {
  const r = resolveDatabaseHost("postgres://user:pass@db.staging.example.com:5432/zunode");
  assert.deepEqual(r, { ok: true, host: "db.staging.example.com" });
});

test("resolveDatabaseHost handles @-in-password (last authority @)", () => {
  const r = resolveDatabaseHost("postgres://user:p@ssw0rd@db.staging.example.com/zunode");
  assert.equal(r.ok, true);
  assert.equal(r.host, "db.staging.example.com");
});

test("resolveDatabaseHost reads libpq host=/socket query", () => {
  const r = resolveDatabaseHost("postgres://user@/dbname?host=/var/run/postgresql");
  assert.deepEqual(r, { ok: true, host: "/var/run/postgresql" });
});

test("resolveDatabaseHost decodes percent-encoded socket host", () => {
  const r = resolveDatabaseHost("postgres://%2Fvar%2Frun%2Fpostgresql/dbname");
  assert.equal(r.ok, true);
  assert.equal(r.host, "/var/run/postgresql");
});

test("resolveDatabaseHost refuses empty / missing URL", () => {
  assert.equal(resolveDatabaseHost("").ok, false);
  assert.equal(resolveDatabaseHost("   ").ok, false);
});

test("resolveDatabaseHost refuses non-postgres scheme", () => {
  const r = resolveDatabaseHost("mysql://user@db.example/db");
  assert.equal(r.ok, false);
  assert.match(r.reason, /postgres/);
});

// --- assertStagingGate -----------------------------------------------------

test("assertStagingGate refuses missing STAGING_CONFIRM", () => {
  const r = assertStagingGate(
    { DATABASE_URL: "postgres://u@db.staging.example/zunode" },
    { expectHost: "db.staging.example" },
  );
  assert.equal(r.ok, false);
  assert.match(r.reason, /STAGING_CONFIRM/);
});

test("assertStagingGate refuses production ambient marker", () => {
  const r = assertStagingGate(
    {
      STAGING_CONFIRM: INCIDENT_ID,
      PUBLIC_BASE_URL: "https://prod.example.com",
      DATABASE_URL: "postgres://u@db.staging.example/zunode",
    },
    { expectHost: "db.staging.example" },
  );
  assert.equal(r.ok, false);
  assert.match(r.reason, /production/);
});

test("assertStagingGate refuses when --expect-host is absent", () => {
  const r = assertStagingGate({
    ...STAGING_ENV,
    DATABASE_URL: "postgres://u@db.staging.example/zunode",
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /--expect-host/);
});

test("assertStagingGate refuses empty --expect-host", () => {
  const r = assertStagingGate(
    {
      ...STAGING_ENV,
      DATABASE_URL: "postgres://u@db.staging.example/zunode",
    },
    { expectHost: "" },
  );
  assert.equal(r.ok, false);
  assert.match(r.reason, /non-empty/);
});

test("assertStagingGate refuses DATABASE_URL host mismatch (prod DSN + staging env)", () => {
  // The defect ZTR-1296 closes: ambient env looks staging, DSN points at prod.
  const r = assertStagingGate(
    {
      ...STAGING_ENV,
      DATABASE_URL: "postgres://u:p@db.prod.example.com:5432/zunode",
    },
    { expectHost: "db.staging.example.com" },
  );
  assert.equal(r.ok, false);
  assert.equal(r.databaseHost, "db.prod.example.com");
  assert.equal(r.expectHost, "db.staging.example.com");
  assert.match(r.reason, /does not match/);
});

test("assertStagingGate accepts matching host (case-insensitive DNS)", () => {
  const r = assertStagingGate(
    {
      ...STAGING_ENV,
      DATABASE_URL: "postgres://u:p@DB.Staging.Example.COM:5432/zunode",
    },
    { expectHost: "db.staging.example.com" },
  );
  assert.equal(r.ok, true);
  // Host is reported as resolved from the URL; comparison is case-insensitive.
  assert.equal(r.databaseHost.toLowerCase(), "db.staging.example.com");
  assert.equal(r.expectHost, "db.staging.example.com");
});

test("assertStagingGate accepts matching unix-socket host path", () => {
  const r = assertStagingGate(
    {
      ...STAGING_ENV,
      DATABASE_URL: "postgres://user@/zunode?host=/tmp/pg-run-staging",
    },
    { expectHost: "/tmp/pg-run-staging" },
  );
  assert.equal(r.ok, true);
  assert.equal(r.databaseHost, "/tmp/pg-run-staging");
});

test("assertStagingGate refuses missing DATABASE_URL", () => {
  const r = assertStagingGate({ ...STAGING_ENV }, { expectHost: "db.staging.example" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /DATABASE_URL/);
});
