// Registry isolation and rotation verification suite.
//
// Proving layer on top of nodes/implementers and signing-key registries.
// The registry DDL suites already discharge the DDL-level negatives (UNIQUE/CHECK/domain/reference and the
// both-sided active window on node_signing_keys). This suite does NOT re-assert those. It
// proves the verification-time residue that lets close:
//
//   1. Wrong tenant at verification time (scoped uniqueness permits same raw key under two
//      tenants; cross-binding verification must still fail).
//   2. Concurrent registration: racing inserts against one UNIQUE resolve to exactly one winner.
//   3. Immutable identity history: verification anchored before retired_at still resolves the
//      retired row; new activity after retired_at fails (parent exit criterion).
//   4. Overlapping rotations on the real tables — reporting keys 24h half-open
//      overlap; node_signing_keys via activated_at/retired_at only (24h on node keys is
//      SPEC SILENT — not fabricated).
//   5. Purpose separation at verification (NODE_IDENTITY ≠ EVENT_SIGNING; A.9 #10).
//   6. The six zp-reporting-register-v1-specific A.9 negatives (register surface of
//      implementer_reporting_keys enrolment).
//
// Governing: the data model; signing custody rule 8;
// canonical fields. Real PG + SigningKeyRegistry (no Map-key "isolation").
//
// Schema note: the data model's implementer_reporting_keys has registered_at only (no activated_at/
// retired_at / supersedes_key_id). Reporting-key lifecycle (overlap, revoke) lives in the
// lifecycle head consumed by reportingKeyAdmissionEligible; this suite enrols both keys in
// the real registry table and evaluates admission against that identity.

import { execFile, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  buildRegisterPreimage,
  REGISTER_GOLDEN_PAYLOAD,
  REGISTER_GOLDEN_PREIMAGE,
  REPORTING_KEY_ENROL_WINDOW_SECS,
  REPORTING_KEY_OVERLAP_MS,
  REPORTING_REGISTER_PURPOSE,
  reportingKeyMaySign,
  requestTupleMatchesBinding,
  verifyRegisterPreimage,
} from "@zucoins/generic-node-contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { admitReportingKey } from "../src/reporting/admission.ts";
import { InMemoryReportingStore } from "../src/reporting/in-memory-store.ts";
import { reportingKeyAdmissionEligible } from "../src/reporting/store.ts";
import type { SqlExecutor, SqlQueryResult } from "../src/signing-keys/registry-store.ts";
import {
  assertExactPurpose,
  NODE_SIGNING_KEY_COLUMNS,
  REPORTING_KEY_COLUMNS,
  SigningKeyRegistry,
  UnknownSigningKeyPurposeError,
} from "../src/signing-keys/registry-store.ts";

const execFileAsync = promisify(execFile);

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const basePath = resolve(schemaDir, "node-implementer-registry.sql");
const signingSqlPath = resolve(schemaDir, "signing-key-registry.sql");
const signingSql = readFileSync(signingSqlPath, "utf8");
// Layered on the base: strip the re-declared domain so it is created exactly once.
const layeredSigningSql = signingSql.replace(
  /CREATE DOMAIN padded_base64url_pubkey AS text[^;]*;/,
  "",
);

const databaseUrl = process.env.TEST_DATABASE_URL;
const SCHEMA = "registry_isolation_registry_isolation";

const pubkey = (letter: string): string => `${letter.repeat(43)}=`;
const rid = (suffix: string): string => `00000000-0000-0000-0000-0000000e${suffix}`;

const NODE_A = rid("0001");
const NODE_B = rid("0002");
const IMPL_A = rid("0010");
const IMPL_B = rid("0011");
const NODE_A_ID_KEY = pubkey("A");
const NODE_B_ID_KEY = pubkey("B");
// Same raw public-key bytes enrolled under two implementers — scoped uniqueness permits it.
const SHARED_REPORTING_KEY = pubkey("C");
const REPORTING_K1 = pubkey("D");
const REPORTING_K2 = pubkey("E");
const EVENT_K1 = pubkey("F");
const EVENT_K2 = pubkey("G");
const IDENTITY_ONLY = pubkey("H");
const RACE_KEY = pubkey("I");

const RKEY_A_ID = rid("0101");
const RKEY_B_ID = rid("0102");
const RKEY_K1_ID = rid("0103");
const RKEY_K2_ID = rid("0104");
const SKEY_K1_ID = rid("0201");
const SKEY_K2_ID = rid("0202");
const SKEY_ID_ONLY = rid("0203");

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

const seed = (statement: string): void => {
  const result = run(statement);
  expect(result.stderr, `seed must apply cleanly: ${statement}`).toBe("");
  expect(result.status, `seed must apply cleanly: ${statement}`).toBe(0);
};

// Concurrent psql sessions — PostgreSQL, not this process, arbitrates the UNIQUE winner.
const psqlAsync = async (statement: string): Promise<PsqlResult> => {
  try {
    const { stdout, stderr } = await execFileAsync(
      "psql",
      ["-v", "ON_ERROR_STOP=1", "-q", "-c", `SET search_path TO ${SCHEMA}`, "-c", statement],
      { env: pgEnv() },
    );
    return { status: 0, stdout: String(stdout), stderr: String(stderr) };
  } catch (error) {
    const err = error as { code?: number; stdout?: string; stderr?: string };
    return {
      status: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(error),
    };
  }
};

const FIELD_SEP = "|";
const NULL_TOKEN = "<PGNULL>";
const sqlLiteral = (value: unknown): string =>
  value === null || value === undefined ? "NULL" : `'${String(value).replaceAll("'", "''")}'`;

const livePsqlExecutor: SqlExecutor = {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const statement = text.replace(/\$(\d+)/g, (_match, index: string) =>
      sqlLiteral(params[Number(index) - 1]),
    );
    const result = psql([
      "-t",
      "-A",
      "-F",
      FIELD_SEP,
      "-P",
      `null=${NULL_TOKEN}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-c",
      statement,
    ]);
    if (result.status !== 0) return Promise.reject(new Error(result.stderr));
    const columns: readonly string[] = statement.includes(" FROM node_signing_keys ")
      ? NODE_SIGNING_KEY_COLUMNS
      : REPORTING_KEY_COLUMNS;
    const rows = result.stdout
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => {
        const values = line.split(FIELD_SEP);
        return Object.fromEntries(
          columns.map((column, i) => [column, values[i] === NULL_TOKEN ? null : values[i]]),
        );
      }) as R[];
    return Promise.resolve({ rows });
  },
};

const registry = new SigningKeyRegistry(livePsqlExecutor);

/**
 * Verification-time historical validity window — byte-identical to the half-open interval
 * event-verifier.ts applies: created_at ∈ [activated_at, retired_at). Anchored verification of
 * a retired key still succeeds; new activity at/after retired_at fails. This is the parent
 * exit criterion ("frozen historical verification remains possible").
 */
function keyValidAtAnchorMs(
  key: { readonly activated_at: string; readonly retired_at: string | null },
  anchorMs: number,
): boolean {
  const activatedAtMs = Date.parse(key.activated_at);
  const retiredAtMs = key.retired_at === null ? null : Date.parse(key.retired_at);
  if (Number.isNaN(activatedAtMs)) return false;
  if (retiredAtMs !== null && Number.isNaN(retiredAtMs)) return false;
  return activatedAtMs <= anchorMs && (retiredAtMs === null || anchorMs < retiredAtMs);
}

let reachable = false;

describe.skipIf(databaseUrl === undefined)("against live PostgreSQL registries", () => {
  beforeAll(() => {
    const probe = psql(["-c", "SELECT 1"]);
    if (probe.status !== 0) {
      throw new Error(`TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${probe.stderr}`);
    }
    reachable = true;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    const base = psql([
      "-c",
      `CREATE SCHEMA ${SCHEMA}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-f",
      basePath,
    ]);
    expect(base.stderr, "base apply should be clean").toBe("");
    expect(base.status).toBe(0);
    const layered = run(layeredSigningSql);
    expect(layered.stderr, "layered apply should be clean").toBe("");
    expect(layered.status).toBe(0);

    seed(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('${NODE_A}', 'node A', '${NODE_A_ID_KEY}')`,
    );
    seed(
      `INSERT INTO nodes (id, display_name, identity_public_key)
       VALUES ('${NODE_B}', 'node B', '${NODE_B_ID_KEY}')`,
    );
    seed(`INSERT INTO implementers (id, name) VALUES ('${IMPL_A}', 'impl A')`);
    seed(`INSERT INTO implementers (id, name) VALUES ('${IMPL_B}', 'impl B')`);

    // Same raw public key under two implementers on the same node — DB permits; verification must not.
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${RKEY_A_ID}', '${NODE_A}', '${IMPL_A}', '${SHARED_REPORTING_KEY}', now())`,
    );
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${RKEY_B_ID}', '${NODE_A}', '${IMPL_B}', '${SHARED_REPORTING_KEY}', now())`,
    );

    // Rotation pair for reporting-key overlap (two enrolled rows; lifecycle is separate).
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${RKEY_K1_ID}', '${NODE_A}', '${IMPL_A}', '${REPORTING_K1}', now() - interval '2 days')`,
    );
    seed(
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${RKEY_K2_ID}', '${NODE_A}', '${IMPL_A}', '${REPORTING_K2}', now() - interval '1 hour')`,
    );

    // Node event signing keys for overlap + immutable history.
    seed(
      `INSERT INTO node_signing_keys
         (id, node_id, purpose, public_key, vault_secret_ref, activated_at, retired_at)
       VALUES
         ('${SKEY_K1_ID}', '${NODE_A}', 'EVENT_SIGNING', '${EVENT_K1}', '${rid("9001")}',
          now() - interval '2 days', now() - interval '1 hour')`,
    );
    seed(
      `INSERT INTO node_signing_keys
         (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES
         ('${SKEY_K2_ID}', '${NODE_A}', 'EVENT_SIGNING', '${EVENT_K2}', '${rid("9002")}',
          now() - interval '2 hours')`,
    );
    seed(
      `INSERT INTO node_signing_keys
         (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES
         ('${SKEY_ID_ONLY}', '${NODE_A}', 'NODE_IDENTITY', '${IDENTITY_ONLY}', '${rid("9003")}',
          now() - interval '1 day')`,
    );
  });

  afterAll(() => {
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  // ---------- 1. Wrong tenant at verification time -----------------------------------------

  it("wrong tenant: same raw reporting key under two implementers never crosses at lookup", async (ctx) => {
    if (!reachable) ctx.skip();
    // DB layer permitted both rows (scoped UNIQUE). Verification-time lookup is tenant-scoped.
    const underA = await registry.findReportingKey(NODE_A, IMPL_A, SHARED_REPORTING_KEY);
    const underB = await registry.findReportingKey(NODE_A, IMPL_B, SHARED_REPORTING_KEY);
    expect(underA?.id).toBe(RKEY_A_ID);
    expect(underB?.id).toBe(RKEY_B_ID);
    expect(underA?.implementer_id).toBe(IMPL_A);
    expect(underB?.implementer_id).toBe(IMPL_B);
    // Implementer B cannot resolve implementer A's K1 enrolment through B's tenant scope.
    expect(await registry.findReportingKey(NODE_A, IMPL_B, REPORTING_K1)).toBeNull();
    // Cross-node: NODE_B has no reporting keys at all for either implementer.
    expect(await registry.findReportingKeys(NODE_B, IMPL_A)).toEqual([]);
  });

  it("wrong tenant: request tuple asserting the other implementer fails cross-binding", async (ctx) => {
    if (!reachable) ctx.skip();
    const enrolled = await registry.findReportingKey(NODE_A, IMPL_A, SHARED_REPORTING_KEY);
    expect(enrolled).not.toBeNull();

    // Binding derives from the registry row, never from request-supplied tenant fields.
    const binding = {
      reporting_key_id: enrolled!.id,
      node_id: enrolled!.node_id,
      implementer_id: enrolled!.implementer_id,
    };
    expect(
      requestTupleMatchesBinding(binding, {
        node_id: NODE_A,
        implementer_id: IMPL_B, // asserts the OTHER implementer
      }),
    ).toBe(false);
    expect(
      requestTupleMatchesBinding(binding, {
        node_id: NODE_B, // asserts the OTHER node
        implementer_id: IMPL_A,
      }),
    ).toBe(false);
    expect(
      requestTupleMatchesBinding(binding, { node_id: NODE_A, implementer_id: IMPL_A }),
    ).toBe(true);

    // admitReportingKey scopes findRegistration by (nodeId, keyId) — a key registered for A
    // is unknown when looking up B's key id under node A without B's registration seed.
    const store = new InMemoryReportingStore();
    store.seedRestoreHold(NODE_A, false);
    store.seedRegistration({
      reportingKeyId: RKEY_A_ID,
      nodeId: NODE_A,
      implementerId: IMPL_A,
      publicKeyEncoded: SHARED_REPORTING_KEY,
    });
    store.seedLifecycleHead(NODE_A, IMPL_A, {
      epoch: 1n,
      authHold: false,
      currentKeyId: RKEY_A_ID,
      priorKeyId: null,
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    store.seedReportingKeyState(NODE_A, IMPL_A, RKEY_A_ID, {
      state: "ACTIVE",
      revokedAtMs: null,
    });
    // Looking up the other implementer's key id under node A fails closed (unknown).
    const cross = await admitReportingKey(store, NODE_A, RKEY_B_ID, Date.now());
    expect(cross).toEqual({ ok: false, code: "unknown_reporting_key" });
    const own = await admitReportingKey(store, NODE_A, RKEY_A_ID, Date.now());
    expect(own.ok).toBe(true);
  });

  // ---------- 2. Concurrent registration ---------------------------------------------------

  it("concurrent registration: two racers on one UNIQUE produce exactly one winner", async (ctx) => {
    if (!reachable) ctx.skip();
    const id1 = rid("0301");
    const id2 = rid("0302");
    const insert = (id: string): string =>
      `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
       VALUES ('${id}', '${NODE_B}', '${IMPL_A}', '${RACE_KEY}', now())`;

    // Two separate psql sessions in flight — Postgres arbitrates the UNIQUE
    // (node_id, implementer_id, public_key) winner. Never two active rows.
    const [a, b] = await Promise.all([psqlAsync(insert(id1)), psqlAsync(insert(id2))]);
    const winners = [a, b].filter((r) => r.status === 0);
    const losers = [a, b].filter((r) => r.status !== 0);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(1);
    expect(losers[0]!.stderr).toMatch(/duplicate key|unique/i);

    const count = run(
      `SELECT count(*) FROM implementer_reporting_keys
       WHERE node_id = '${NODE_B}' AND implementer_id = '${IMPL_A}' AND public_key = '${RACE_KEY}'`,
    );
    expect(count.stdout).toContain("1");
    // Read layer sees exactly one enrolment.
    const rows = await registry.findReportingKeys(NODE_B, IMPL_A);
    expect(rows.filter((r) => r.public_key === RACE_KEY)).toHaveLength(1);
  });

  // ---------- 3. Immutable identity history ------------------------------------------------

  it("immutable identity history: retired key still resolves; new activity after retired_at fails", async (ctx) => {
    if (!reachable) ctx.skip();
    // Historical resolution (window-free) returns the retired predecessor.
    const historical = await registry.findNodeSigningKey(NODE_A, "EVENT_SIGNING", EVENT_K1);
    expect(historical).not.toBeNull();
    expect(historical!.id).toBe(SKEY_K1_ID);
    expect(historical!.retired_at).not.toBeNull();
    const retiredAtMs = Date.parse(historical!.retired_at!);
    const activatedAtMs = Date.parse(historical!.activated_at);
    expect(retiredAtMs).toBeLessThan(Date.now());

    // Active resolution excludes it for NEW activity (parent exit criterion, "cannot authorize
    // new activity").
    const active = await registry.findActiveNodeSigningKeys(NODE_A, "EVENT_SIGNING");
    expect(active.map((r) => r.public_key)).toEqual([EVENT_K2]);
    expect(active.map((r) => r.public_key)).not.toContain(EVENT_K1);

    // Verification anchored BEFORE retired_at still succeeds against the retired row.
    const midLifeMs = Math.floor((activatedAtMs + retiredAtMs) / 2);
    expect(keyValidAtAnchorMs(historical!, midLifeMs)).toBe(true);
    // Anchor exactly at retired_at is OUTSIDE the half-open window [activated, retired).
    expect(keyValidAtAnchorMs(historical!, retiredAtMs)).toBe(false);
    expect(keyValidAtAnchorMs(historical!, retiredAtMs + 1)).toBe(false);
    // Anchor before activation is also out.
    expect(keyValidAtAnchorMs(historical!, activatedAtMs - 1)).toBe(false);
  });

  // ---------- 4. Overlapping rotations -----------------------------------------------------

  it("overlapping rotation (node_signing_keys): both live during overlap; only successor after", async (ctx) => {
    if (!reachable) ctx.skip();
    // SPEC SILENT: no 24h constant on node_signing_keys — overlap is purely activated_at/retired_at.
    // Seed already retired K1; re-open the overlap by clearing K1's retirement, then re-retire.
    const reopen = run(
      `UPDATE node_signing_keys SET retired_at = NULL WHERE id = '${SKEY_K1_ID}'`,
    );
    expect(reopen.status).toBe(0);

    const during = await registry.findActiveNodeSigningKeys(NODE_A, "EVENT_SIGNING");
    expect(during.map((r) => r.public_key).sort()).toEqual([EVENT_K1, EVENT_K2].sort());

    const retire = run(
      `UPDATE node_signing_keys SET retired_at = now() - interval '1 second' WHERE id = '${SKEY_K1_ID}'`,
    );
    expect(retire.status).toBe(0);
    const after = await registry.findActiveNodeSigningKeys(NODE_A, "EVENT_SIGNING");
    expect(after.map((r) => r.public_key)).toEqual([EVENT_K2]);
    // Retired predecessor remains historically resolvable.
    expect(
      (await registry.findNodeSigningKey(NODE_A, "EVENT_SIGNING", EVENT_K1))?.retired_at,
    ).not.toBeNull();
  });

  it("overlapping rotation (reporting keys): both verify inside 24h; only successor after", async (ctx) => {
    if (!reachable) ctx.skip();
    // Both keys are enrolled in the real implementer_reporting_keys table.
    const k1 = await registry.findReportingKey(NODE_A, IMPL_A, REPORTING_K1);
    const k2 = await registry.findReportingKey(NODE_A, IMPL_A, REPORTING_K2);
    expect(k1?.id).toBe(RKEY_K1_ID);
    expect(k2?.id).toBe(RKEY_K2_ID);

    // Lifecycle head models supersedes_key_id=K1 → K2 with the frozen 24h half-open window.
    const successorCommittedAtMs = Date.parse("2026-07-20T12:00:00.000Z");
    const overlapExpiresAtMs = successorCommittedAtMs + REPORTING_KEY_OVERLAP_MS;
    expect(REPORTING_KEY_OVERLAP_MS).toBe(24 * 60 * 60 * 1_000);

    const base = {
      currentKeyId: RKEY_K2_ID,
      priorKeyId: RKEY_K1_ID,
      overlapExpiresAtMs,
      successorCommittedAtMs,
      presentedKeyRevokedAtMs: null as number | null,
    };

    // Inside the overlap: both current and prior admit.
    const midOverlap = successorCommittedAtMs + 1_000;
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K2_ID,
        presentedKeyState: "ACTIVE" as const,
        receivedAtMs: midOverlap,
      }),
    ).toBe(true);
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K1_ID,
        presentedKeyState: "ACTIVE" as const,
        receivedAtMs: midOverlap,
      }),
    ).toBe(true);

    // After the overlap window: only the successor.
    const afterOverlap = overlapExpiresAtMs; // half-open: expiry itself is out
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K2_ID,
        presentedKeyState: "ACTIVE" as const,
        receivedAtMs: afterOverlap,
      }),
    ).toBe(true);
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K1_ID,
        presentedKeyState: "ACTIVE" as const,
        receivedAtMs: afterOverlap,
      }),
    ).toBe(false);

    // Revocation is immediate even inside the unexpired overlap window.
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K1_ID,
        presentedKeyState: "REVOKED" as const,
        presentedKeyRevokedAtMs: midOverlap,
        receivedAtMs: midOverlap,
      }),
    ).toBe(false);
    expect(
      reportingKeyAdmissionEligible({
        ...base,
        presentedKeyId: RKEY_K1_ID,
        presentedKeyState: "RETIRED" as const,
        receivedAtMs: midOverlap,
      }),
    ).toBe(false);
  });

  it("revoking the sole active reporting key fail-closes until fresh bootstrap", async (ctx) => {
    if (!reachable) ctx.skip();
    const store = new InMemoryReportingStore();
    store.seedRestoreHold(NODE_A, false);
    // Sole active key for IMPL_A is K2 (post-rotation current).
    store.seedRegistration({
      reportingKeyId: RKEY_K2_ID,
      nodeId: NODE_A,
      implementerId: IMPL_A,
      publicKeyEncoded: REPORTING_K2,
    });
    store.seedLifecycleHead(NODE_A, IMPL_A, {
      epoch: 2n,
      authHold: false,
      currentKeyId: RKEY_K2_ID,
      priorKeyId: null, // sole key — no prior slot
      overlapExpiresAtMs: null,
      successorCommittedAtMs: null,
    });
    store.seedReportingKeyState(NODE_A, IMPL_A, RKEY_K2_ID, {
      state: "REVOKED",
      revokedAtMs: Date.now(),
    });

    const denied = await admitReportingKey(store, NODE_A, RKEY_K2_ID, Date.now());
    expect(denied).toEqual({ ok: false, code: "reporting_key_not_active" });
    // No silent auto-recovery: prior is null, so no other key admits either.
    const priorAttempt = await admitReportingKey(store, NODE_A, RKEY_K1_ID, Date.now());
    expect(priorAttempt).toEqual({ ok: false, code: "unknown_reporting_key" });
  });

  // ---------- 5. Purpose separation at verification ----------------------------------------

  it("purpose separation: NODE_IDENTITY never satisfies EVENT_SIGNING (and reverse)", async (ctx) => {
    if (!reachable) ctx.skip();
    // Active EVENT_SIGNING does not surface the NODE_IDENTITY-only key.
    const asEvent = await registry.findActiveNodeSigningKeys(NODE_A, "EVENT_SIGNING");
    expect(asEvent.map((r) => r.public_key)).not.toContain(IDENTITY_ONLY);
    // Historical lookup of the identity key as EVENT_SIGNING is null (purpose-scoped UNIQUE).
    expect(await registry.findNodeSigningKey(NODE_A, "EVENT_SIGNING", IDENTITY_ONLY)).toBeNull();
    // Correct purpose still finds it.
    const asIdentity = await registry.findNodeSigningKey(NODE_A, "NODE_IDENTITY", IDENTITY_ONLY);
    expect(asIdentity?.id).toBe(SKEY_ID_ONLY);

    // signing custody rule 8: unrecognised / near-miss purposes never reach the database.
    await expect(registry.findActiveNodeSigningKeys(NODE_A, "event_signing")).rejects.toThrow(
      UnknownSigningKeyPurposeError,
    );
    expect(assertExactPurpose("NODE_IDENTITY")).toBe("NODE_IDENTITY");
    expect(() => assertExactPurpose("DESTINATION_BLESS")).toThrow(UnknownSigningKeyPurposeError);

    // A.9 #10 — reporting key may not sign node-event / destination-bless purposes.
    expect(reportingKeyMaySign("zp-report-request-v1")).toBe(true);
    expect(reportingKeyMaySign("zp-reporting-register-v1")).toBe(true);
    expect(reportingKeyMaySign("zp-node-event-v1")).toBe(false);
    expect(reportingKeyMaySign("zp-destination-bless-v1")).toBe(false);
  });
});

// ---------- 6. A.9 zp-reporting-register-v1-specific negatives (always run) ----------------
// These are the register-surface negatives named in A.9's register paragraph + the structural
// register vectors the freeze suite inventories. They bind the enrolment tuple that writes into
// implementer_reporting_keys. No database required.

describe("A.9 zp-reporting-register-v1 negatives", () => {
  const jsonOf = (p: string): string => p.slice(p.indexOf("\n") + 1);

  it("A.9 register — supersedes_key_id omitted instead of null is rejected", () => {
    const dropped = `${REPORTING_REGISTER_PURPOSE}\n${jsonOf(REGISTER_GOLDEN_PREIMAGE).replace(
      ',"supersedes_key_id":null',
      "",
    )}`;
    expect(verifyRegisterPreimage(dropped).ok).toBe(false);
  });

  it("A.9 register — enrolment window over REPORTING_KEY_ENROL_WINDOW (300s) is rejected", () => {
    expect(REPORTING_KEY_ENROL_WINDOW_SECS).toBe(300);
    const wide = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      expires_at: "2026-07-18T00:05:00.001Z",
    });
    expect(verifyRegisterPreimage(wide)).toEqual({
      ok: false,
      reason: "enrolment window exceeds 300 seconds",
    });
  });

  it("A.9 register — unpadded new_reporting_public_key is rejected", () => {
    const unpadded = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      new_reporting_public_key: REGISTER_GOLDEN_PAYLOAD.new_reporting_public_key.replace(/=$/, ""),
    });
    expect(verifyRegisterPreimage(unpadded).ok).toBe(false);
  });

  it("A.9 register — field reorder is rejected", () => {
    const reordered =
      `${REPORTING_REGISTER_PURPOSE}\n` +
      JSON.stringify({
        canonical_version: 1,
        purpose: REPORTING_REGISTER_PURPOSE,
        node_id: REGISTER_GOLDEN_PAYLOAD.node_id,
        implementer_id: REGISTER_GOLDEN_PAYLOAD.implementer_id,
        new_reporting_key_id: REGISTER_GOLDEN_PAYLOAD.new_reporting_key_id,
        new_reporting_public_key: REGISTER_GOLDEN_PAYLOAD.new_reporting_public_key,
        supersedes_key_id: REGISTER_GOLDEN_PAYLOAD.supersedes_key_id,
        nonce: REGISTER_GOLDEN_PAYLOAD.nonce,
        issued_at: REGISTER_GOLDEN_PAYLOAD.issued_at,
        expires_at: REGISTER_GOLDEN_PAYLOAD.expires_at,
      });
    expect(verifyRegisterPreimage(reordered).ok).toBe(false);
  });

  it("A.9 register — uppercase (non-canonical) UUID is rejected", () => {
    const upper = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      new_reporting_key_id: REGISTER_GOLDEN_PAYLOAD.new_reporting_key_id.toUpperCase(),
    });
    expect(verifyRegisterPreimage(upper).ok).toBe(false);
  });

  it("A.9 #10 + register purpose mismatch: reporting key / wrong purpose rejected", () => {
    expect(
      verifyRegisterPreimage(`zp-report-request-v1\n${jsonOf(REGISTER_GOLDEN_PREIMAGE)}`).ok,
    ).toBe(false);
    expect(reportingKeyMaySign("zp-destination-bless-v1")).toBe(false);
  });

  it("A.9 register — a non-null supersedes_key_id (rotation) is structurally accepted", () => {
    const rotate = buildRegisterPreimage({
      ...REGISTER_GOLDEN_PAYLOAD,
      supersedes_key_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    });
    expect(verifyRegisterPreimage(rotate).ok).toBe(true);
  });
});
