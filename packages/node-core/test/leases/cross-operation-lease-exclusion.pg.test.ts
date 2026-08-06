// real-PostgreSQL, cross-process lease exclusion.
//
// Proves the one-in-flight-per-wallet rule against the universal wallet_active_leases
// foundation delivered by schema and services: every
// contender is a separate `psql` OS process (PsqlSessionExecutor), so the race
// is at the database transaction boundary — not an in-process Promise.all of
// shared connections.
//
// Governing: one active lease per wallet, the lease relations, the acquisition rules, and
// boot recovery. No signing-payload, submit, retry, gateway, or
// private-key code is touched. ZKZ vocabulary only.

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  acquireLeases,
  assertLeaseFoundationReady,
  assertSignCapability,
  completeGroupOperation,
  createLeaseGroup,
  migrateLeaseFoundation,
  mintReleaseProof,
  releaseLease,
  transferLeaseWithinGroup,
  joinLeaseGroupOperation,
  type AcquiredLease,
  type SqlExecutor,
  type SqlQueryResult,
} from "../../src/leases/index.ts";
import { tokenizeCustodySql } from "../custody-eligibility-sql-statements.js";

const here = dirname(fileURLToPath(import.meta.url));
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

// ─── prerequisite DDL (custody + base enums/domains + nodes) ──────────

const prerequisiteDdl = ((): string => {
  const base = readFileSync(resolve(here, "../../src/schema/base-enums-domains.sql"), "utf8");
  const registry = readFileSync(
    resolve(here, "../../src/schema/node-implementer-registry.sql"),
    "utf8",
  );
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const custodySql = tokenizeCustodySql(
  readFileSync(resolve(here, "../../src/schema/custody-eligibility.sql"), "utf8"),
)
.map((s) => s.raw)
.join("\n");

const applyCustodyBase = (url: string): void => {
  try {
    execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: `${prerequisiteDdl}${custodySql}`,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`custody apply failed: ${(e.stderr ?? "").trim()}`);
  }
};

// ─── psql helpers ───────────────────────────────────────────────────────────

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (url: string, sql: string, timeoutMs = 30_000): PsqlOutcome => {
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

const psqlMust = (url: string, sql: string): string => {
  const outcome = runPsql(url, sql);
  if (!outcome.ok) {
    throw new Error(`psql failed: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
};

const withDatabase = (url: string, database: string): string => {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
};

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

// ─── SqlExecutor over a long-lived psql session (one OS process = one conn) ─

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
}

function bindSql(text: string, params: readonly unknown[] = []): string {
  return text.replace(/\$(\d+)/g, (_m, n: string) => {
    const idx = Number(n) - 1;
    if (idx < 0 || idx >= params.length) {
      throw new Error(`missing sql param $${n}`);
    }
    return sqlLiteral(params[idx]);
  });
}

function pgEnv(url: string): NodeJS.ProcessEnv {
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
class PsqlSessionExecutor implements SqlExecutor {
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
      let idx = this.buffer.indexOf("__SQL_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__SQL_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__SQL_END__\n");
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
      child.stdin.write(`${sql};\n\\echo __SQL_END__\n`);
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
    if (/^SELECT\b/i.test(trimmed)) {
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
class PsqlExecutor implements SqlExecutor {
  constructor(private readonly url: string) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindSql(text, params);
    const trimmed = bound.trim();
    if (/^(INSERT|UPDATE|DELETE)\b/i.test(trimmed)) {
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
    if (/^SELECT\b/i.test(trimmed)) {
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

async function withTx<T>(url: string, body: (db: PsqlSessionExecutor) => Promise<T>): Promise<T> {
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

// ─── fixtures ───────────────────────────────────────────────────────────────

const NODE = "b0000000-0000-4000-8000-0000000000aa";
const OWNER_A = "c0000000-0000-4000-8000-0000000000e1";
const OWNER_B = "c0000000-0000-4000-8000-0000000000e2";

/** Deterministic wallet UUIDs — ascending binary order matches numeric suffix. */
const W = (n: number): string =>
  `a0000000-0000-4000-8000-${n.toString().padStart(12, "0")}`;

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

function digest(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// Never clear recovery_verified_at / recovery_verification_id — custody trigger
// raises CUSTODY_RECOVERY_NEVER_CLEARED.
const TRUNCATE_LEASE_STATE = `
TRUNCATE wallet_active_leases, wallet_lease_memberships, lease_group_operations,
         lease_groups, lease_release_proofs, lease_audit_events,
         wallet_lease_epoch_highwater RESTART IDENTITY CASCADE;
UPDATE wallets SET state = 'AVAILABLE';
`;

function seedNode(url: string): void {
  psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
       ('${NODE}', 'cross-operation-lease-lease', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`,
  );
}

function seedWallets(url: string, count = 12): void {
  seedNode(url);
  const rows = Array.from({ length: count }, (_, i) => {
    const id = W(i + 1);
    const pk = pubkey(`W${i + 1}`);
    return `('${id}', '${NODE}', '${pk}', 'node_generated', 'AVAILABLE', NULL, NULL)`;
  }).join(",\n  ");
  psqlMust(
    url,
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state, recovery_verified_at, recovery_verification_id)
     VALUES ${rows}
     ON CONFLICT (id) DO NOTHING;`,
  );
}

/** G1/G2 fixtures so RECEIVE_WINDOW and MOVE_DESTINATION may acquire. */
function seedReceiveChildFixtures(url: string, sourceWallet: string, destWallet: string): void {
  const recvV = randomUUID();
  const destV = randomUUID();
  const destId = randomUUID();
  const destDevice = randomUUID();
  const destArtifact = randomUUID();
  psqlMust(
    url,
    `INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
     SELECT '${recvV}', '${sourceWallet}', 'AUDITED_EXPORT', '${"e".repeat(64)}',
            (SELECT public_key FROM wallets WHERE id = '${sourceWallet}'),
            '${recvV}', now(), 'cross-operation-lease-test'
      WHERE NOT EXISTS (
        SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${sourceWallet}'
      );
     INSERT INTO wallet_recovery_verifications
       (id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity)
     SELECT '${destV}', '${destWallet}', 'AUDITED_EXPORT', '${"f".repeat(64)}',
            (SELECT public_key FROM wallets WHERE id = '${destWallet}'),
            '${destV}', now(), 'cross-operation-lease-test'
      WHERE NOT EXISTS (
        SELECT 1 FROM wallet_recovery_verifications WHERE wallet_id = '${destWallet}'
      );
     UPDATE wallets w SET
       recovery_verified_at = COALESCE(w.recovery_verified_at, now()),
       recovery_verification_id = COALESCE(
         w.recovery_verification_id,
         (SELECT id FROM wallet_recovery_verifications
           WHERE wallet_id = w.id ORDER BY verified_at LIMIT 1)
       )
       WHERE w.id IN ('${sourceWallet}', '${destWallet}');
     INSERT INTO destinations
       (id, node_id, wallet_id, state, blessed_at,
        blessed_by_device_key_id, blessing_artifact_id)
     SELECT '${destId}', '${NODE}', '${destWallet}', 'BLESSED', now(),
            '${destDevice}', '${destArtifact}'
      WHERE NOT EXISTS (
        SELECT 1 FROM destinations WHERE wallet_id = '${destWallet}'
      );`,
  );
}

type RaceOutcome<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: string; readonly code: string };

async function raceAcquire<T>(
  left: () => Promise<T>,
  right: () => Promise<T>,
): Promise<readonly [RaceOutcome<T>, RaceOutcome<T>]> {
  const wrap = async (fn: () => Promise<T>): Promise<RaceOutcome<T>> => {
    try {
      return { ok: true, value: await fn() };
    } catch (err) {
      const e = err as { reason?: string; code?: string; message?: string };
      return {
        ok: false,
        reason: e.reason ?? "",
        code: e.code ?? "",
      };
    }
  };
  return Promise.all([wrap(left), wrap(right)]);
}

function expectExactlyOneWinner<T>(results: readonly RaceOutcome<T>[]): void {
  const winners = results.filter((r) => r.ok);
  const losers = results.filter((r) => !r.ok);
  expect(winners).toHaveLength(1);
  expect(losers).toHaveLength(1);
  const loser = losers[0]!;
  // Service path: ALREADY_LEASED. Concurrent INSERT: unique_violation 23505.
  // SERIALIZABLE conflict: 40001. All three prove exclusivity.
  const exclusive =
    loser.reason === "ALREADY_LEASED" ||
    loser.code === "23505" ||
    loser.code === "40001" ||
    /ALREADY_LEASED|23505|40001|unique/i.test(loser.reason);
  expect(exclusive).toBe(true);
}

async function acquireSend(
  url: string,
  walletId: string,
  ownerInstanceId: string,
  operationId = randomUUID(),
): Promise<{ operationId: string; groupId: string; leases: AcquiredLease[] }> {
  const groupId = await withTx(url, (tx) => createLeaseGroup(tx, operationId));
  const leases = await withTx(url, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId, leaseRole: "SEND_SOURCE" }],
      leaseGroupId: groupId,
      rootOperationId: operationId,
      operationId,
      ownerInstanceId,
    }),
  );
  return { operationId, groupId, leases };
}

async function acquireMove(
  url: string,
  sourceId: string,
  destId: string,
  ownerInstanceId: string,
  operationId = randomUUID(),
): Promise<{ operationId: string; groupId: string; leases: AcquiredLease[] }> {
  seedReceiveChildFixtures(url, sourceId, destId);
  const groupId = await withTx(url, (tx) => createLeaseGroup(tx, operationId));
  const leases = await withTx(url, (tx) =>
    acquireLeases(tx, {
      wallets: [
        { walletId: sourceId, leaseRole: "MOVE_SOURCE" },
        { walletId: destId, leaseRole: "MOVE_DESTINATION" },
      ],
      leaseGroupId: groupId,
      rootOperationId: operationId,
      operationId,
      ownerInstanceId,
    }),
  );
  return { operationId, groupId, leases };
}

async function acquireReceive(
  url: string,
  walletId: string,
  ownerInstanceId: string,
  operationId = randomUUID(),
): Promise<{ operationId: string; groupId: string; leases: AcquiredLease[] }> {
  // RECEIVE_WINDOW needs recovery verification (G1).
  seedReceiveChildFixtures(url, walletId, W(12));
  const groupId = await withTx(url, (tx) =>
    createLeaseGroup(tx, { rootOperationId: operationId, childDisposition: "PENDING" }),
  );
  const leases = await withTx(url, (tx) =>
    acquireLeases(tx, {
      wallets: [{ walletId, leaseRole: "RECEIVE_WINDOW" }],
      leaseGroupId: groupId,
      rootOperationId: operationId,
      operationId,
      ownerInstanceId,
    }),
  );
  return { operationId, groupId, leases };
}

async function guardedRelease(
  url: string,
  params: {
    walletId: string;
    ownerInstanceId: string;
    operationId: string;
    membershipId: string;
    leaseGroupId: string;
    leaseEpoch: bigint;
    proofKind:
      | "EXTERNAL_SEND_LANDED"
      | "INTERNAL_MOVE_LANDED"
      | "RECEIVE_LANDED"
      | "OPERATOR_QUARANTINE_RELEASE";
  },
): Promise<void> {
  const proofId = randomUUID();
  await withTx(url, (tx) =>
    mintReleaseProof(tx, {
      proofId,
      walletId: params.walletId,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      proofKind: params.proofKind,
      proofDigest: digest(`release-${params.operationId}`),
    }),
  );
  await withTx(url, (tx) =>
    completeGroupOperation(tx, {
      leaseGroupId: params.leaseGroupId,
      operationId: params.operationId,
    }),
  );
  await withTx(url, (tx) =>
    releaseLease(tx, {
      walletId: params.walletId,
      ownerInstanceId: params.ownerInstanceId,
      operationId: params.operationId,
      membershipId: params.membershipId,
      leaseGroupId: params.leaseGroupId,
      leaseEpoch: params.leaseEpoch,
      releaseProofId: proofId,
      releaseReason: "LANDED",
    }),
  );
}

// ─── suite ──────────────────────────────────────────────────────────────────

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;

describe("cross-operation lease exclusion (real PG / separate processes)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `cross_operation_lease_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyCustodyBase(dbUrl);
    seedWallets(dbUrl, 12);
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
  }, 120_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    try {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    } catch {
      // Best-effort cleanup under shared PostgreSQL test contention.
    }
  });

  it("skips cleanly only when Postgres is absent and not required", () => {
    if (live) {
      expect(dbUrl.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  it.skipIf(!live)(
    "MOVE_INTERNAL versus SEND_EXTERNAL: only one source lease reaches signing",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(1);
      const dest = W(2);
      seedReceiveChildFixtures(dbUrl, source, dest);

      const results = await raceAcquire(
        async () => {
          const op = randomUUID();
          const groupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, op));
          return withTx(dbUrl, (tx) =>
            acquireLeases(tx, {
              wallets: [
                { walletId: source, leaseRole: "MOVE_SOURCE" },
                { walletId: dest, leaseRole: "MOVE_DESTINATION" },
              ],
              leaseGroupId: groupId,
              rootOperationId: op,
              operationId: op,
              ownerInstanceId: OWNER_A,
            }),
          );
        },
        async () => {
          const op = randomUUID();
          const groupId = await withTx(dbUrl, (tx) => createLeaseGroup(tx, op));
          return withTx(dbUrl, (tx) =>
            acquireLeases(tx, {
              wallets: [{ walletId: source, leaseRole: "SEND_SOURCE" }],
              leaseGroupId: groupId,
              rootOperationId: op,
              operationId: op,
              ownerInstanceId: OWNER_B,
            }),
          );
        },
      );
      expectExactlyOneWinner(results);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBe(1);
      // Winner holds either the dual-wallet move (2 rows) or the single-wallet send (1).
      const total = Number(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim());
      expect([1, 2]).toContain(total);
    },
    60_000,
  );

  it.skipIf(!live)(
    "two SEND_EXTERNAL approvals exclude on the same source",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(3);
      const results = await raceAcquire(
        () => acquireSend(dbUrl, source, OWNER_A).then((r) => r.leases),
        () => acquireSend(dbUrl, source, OWNER_B).then((r) => r.leases),
      );
      expectExactlyOneWinner(results);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBe(1);
    },
    60_000,
  );

  it.skipIf(!live)(
    "two worker processes cannot claim the same source",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(4);
      // Two independent worker identities (owner_instance_id) racing the same wallet.
      const results = await raceAcquire(
        () => acquireSend(dbUrl, source, OWNER_A).then((r) => r.operationId),
        () => acquireSend(dbUrl, source, OWNER_B).then((r) => r.operationId),
      );
      expectExactlyOneWinner(results);
      const winnerOp =
        results[0]!.ok === true
          ? results[0]!.value
: (results[1] as { ok: true; value: string }).value;
      expect(
        psqlMust(
          dbUrl,
          `SELECT operation_id FROM wallet_active_leases WHERE wallet_id = '${source}'`,
        ).trim(),
      ).toBe(winnerOp);
    },
    60_000,
  );

  it.skipIf(!live)(
    "stale heartbeat survives acquisition racing boot recovery",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(5);
      // Holder acquires and then ages heartbeat_at — heartbeat expiry never releases.
      const held = await acquireSend(dbUrl, source, OWNER_A);
      psqlMust(
        dbUrl,
        `UPDATE wallet_active_leases
         SET heartbeat_at = clock_timestamp() - interval '7 days'
         WHERE wallet_id = '${source}'`,
      );
      // Boot recovery contender (different owner) must be refused; lease stays with holder.
      await expect(acquireSend(dbUrl, source, OWNER_B)).rejects.toMatchObject({
        reason: "ALREADY_LEASED",
      });
      expect(
        psqlMust(
          dbUrl,
          `SELECT operation_id FROM wallet_active_leases WHERE wallet_id = '${source}'`,
        ).trim(),
      ).toBe(held.operationId);
      // Heartbeat renew by the foreign owner also fails (no silent steal).
      await expect(
        withTx(dbUrl, async (tx) => {
          const r = await tx.query(
            `UPDATE wallet_active_leases
             SET heartbeat_at = clock_timestamp()
             WHERE wallet_id = $1 AND owner_instance_id = $2`,
            [source, OWNER_B],
          );
          return r.rowCount;
        }),
      ).resolves.toBe(0);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases
             WHERE wallet_id = '${source}'
               AND heartbeat_at < clock_timestamp() - interval '1 day'`,
          ).trim(),
        ),
      ).toBe(1);
    },
    60_000,
  );

  it.skipIf(!live)(
    "signing after lease loss rejects the permanently stale capability (ABA)",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(6);
      const first = await acquireSend(dbUrl, source, OWNER_A);
      const staleEpoch = first.leases[0]!.leaseEpoch;
      const staleOp = first.operationId;
      const staleMembership = first.leases[0]!.membershipId;

      // Guarded release (terminal + positive proof) — never a bare DELETE.
      await guardedRelease(dbUrl, {
        walletId: source,
        ownerInstanceId: OWNER_A,
        operationId: staleOp,
        membershipId: staleMembership,
        leaseGroupId: first.groupId,
        leaseEpoch: staleEpoch,
        proofKind: "EXTERNAL_SEND_LANDED",
      });

      // Successor lease at epoch 2.
      const second = await acquireSend(dbUrl, source, OWNER_B);
      expect(second.leases[0]!.leaseEpoch).toBe(staleEpoch + 1n);

      // Old capability permanently invalid at the signer boundary.
      await expect(
        withTx(dbUrl, (tx) =>
          assertSignCapability(tx, {
            walletId: source,
            operationId: staleOp,
            leaseEpoch: staleEpoch,
            ownerInstanceId: OWNER_A,
          }),
        ),
      ).rejects.toMatchObject({
        reason: expect.stringMatching(/SIGN_CAPABILITY_MISMATCH|NO_ACTIVE_LEASE|LEASE_/),
      });

      // Current holder signs cleanly.
      await expect(
        withTx(dbUrl, (tx) =>
          assertSignCapability(tx, {
            walletId: source,
            operationId: second.operationId,
            leaseEpoch: second.leases[0]!.leaseEpoch,
            ownerInstanceId: OWNER_B,
          }),
        ),
      ).resolves.toMatchObject({ operation_id: second.operationId });
    },
    90_000,
  );

  it.skipIf(!live)(
    "delivery replay after process restart cannot reacquire its held source",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(7);
      const operationId = randomUUID();
      // First process acquires.
      const first = await acquireSend(dbUrl, source, OWNER_A, operationId);
      expect(first.leases).toHaveLength(1);

      // "Restarted" process — new OS session, same operation_id — cannot re-acquire.
      // A blind retry that re-inserts is the no-blind-retry failure mode this gates.
      const group2 = await withTx(dbUrl, (tx) => createLeaseGroup(tx, randomUUID()));
      await expect(
        withTx(dbUrl, (tx) =>
          acquireLeases(tx, {
            wallets: [{ walletId: source, leaseRole: "SEND_SOURCE" }],
            leaseGroupId: group2,
            rootOperationId: operationId,
            operationId,
            ownerInstanceId: OWNER_A,
          }),
        ),
      ).rejects.toMatchObject({ reason: "ALREADY_LEASED" });

      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBe(1);
      expect(
        psqlMust(
          dbUrl,
          `SELECT operation_id FROM wallet_active_leases WHERE wallet_id = '${source}'`,
        ).trim(),
      ).toBe(operationId);
    },
    60_000,
  );

  it.skipIf(!live)(
    "different source wallets proceed concurrently (no global lock)",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const results = await raceAcquire(
        () => acquireSend(dbUrl, W(8), OWNER_A).then((r) => r.leases),
        () => acquireSend(dbUrl, W(9), OWNER_B).then((r) => r.leases),
      );
      expect(results.every((r) => r.ok)).toBe(true);
      expect(Number(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim())).toBe(2);
    },
    60_000,
  );

  it.skipIf(!live)(
    "destination-only locking is insufficient; dual-wallet acquire is atomic",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      // Pre-hold the shared source so a contending MOVE that also wants a free dest
      // cannot partially lease the dest — atomic UUID-ordered dual-wallet acquire.
      const sharedSource = W(10);
      const destA = W(11);
      const destB = W(1); // free dest for the loser path
      seedReceiveChildFixtures(dbUrl, sharedSource, destA);
      seedReceiveChildFixtures(dbUrl, sharedSource, destB);

      // First contender wins both source + destA.
      const winner = await acquireMove(dbUrl, sharedSource, destA, OWNER_A);
      expect(winner.leases).toHaveLength(2);

      // Second contender wants sharedSource + destB. Source conflict must roll the
      // whole batch back — destB must remain unleased (no partial dual-lease).
      await expect(acquireMove(dbUrl, sharedSource, destB, OWNER_B)).rejects.toMatchObject({
        reason: "ALREADY_LEASED",
      });
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${destB}'`,
          ).trim(),
        ),
      ).toBe(0);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${sharedSource}'`,
          ).trim(),
        ),
      ).toBe(1);

      // Adversarial: two concurrent MOVEs sharing only the source — exactly one wins,
      // and the loser's destination is not left leased.
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      seedReceiveChildFixtures(dbUrl, sharedSource, destA);
      seedReceiveChildFixtures(dbUrl, sharedSource, destB);
      const concurrent = await raceAcquire(
        () => acquireMove(dbUrl, sharedSource, destA, OWNER_A).then((r) => r.leases),
        () => acquireMove(dbUrl, sharedSource, destB, OWNER_B).then((r) => r.leases),
      );
      expectExactlyOneWinner(concurrent);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${sharedSource}'`,
          ).trim(),
        ),
      ).toBe(1);
      // Exactly two active rows for the winner (source + its dest); loser's dest free.
      expect(Number(psqlMust(dbUrl, `SELECT count(*) FROM wallet_active_leases`).trim())).toBe(2);
    },
    90_000,
  );

  it.skipIf(!live)(
    "receive→child handoff keeps the source leased; SEND_EXTERNAL stays excluded",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(2);
      seedReceiveChildFixtures(dbUrl, source, W(3));
      const receive = await acquireReceive(dbUrl, source, OWNER_A);
      const childOp = randomUUID();
      const proofId = randomUUID();

      // Join child first (disposition → JOINED), then mint proof, then transfer.
      await withTx(dbUrl, (tx) =>
        joinLeaseGroupOperation(tx, {
          leaseGroupId: receive.groupId,
          operationId: childOp,
        }),
      );
      await withTx(dbUrl, (tx) =>
        mintReleaseProof(tx, {
          proofId,
          walletId: source,
          operationId: receive.operationId,
          membershipId: receive.leases[0]!.membershipId,
          leaseGroupId: receive.groupId,
          leaseEpoch: receive.leases[0]!.leaseEpoch,
          proofKind: "RECEIVE_LANDED",
          proofDigest: digest(`recv-${receive.operationId}`),
        }),
      );

      const [handoff, sender] = await raceAcquire(
        () =>
          withTx(dbUrl, (tx) =>
            transferLeaseWithinGroup(tx, {
              walletId: source,
              ownerInstanceId: OWNER_A,
              leaseGroupId: receive.groupId,
              fromOperationId: receive.operationId,
              toOperationId: childOp,
              membershipId: receive.leases[0]!.membershipId,
              leaseEpoch: receive.leases[0]!.leaseEpoch,
              toLeaseRole: "MOVE_SOURCE",
              releaseProofId: proofId,
              releaseReason: "RECEIVE_TO_CHILD",
            }),
          ),
        async () => {
          const op = randomUUID();
          const g = await withTx(dbUrl, (tx) => createLeaseGroup(tx, op));
          return withTx(dbUrl, (tx) =>
            acquireLeases(tx, {
              wallets: [{ walletId: source, leaseRole: "SEND_SOURCE" }],
              leaseGroupId: g,
              rootOperationId: op,
              operationId: op,
              ownerInstanceId: OWNER_B,
            }),
          );
        },
      );

      // Handoff must win (source never unleased); sender must lose.
      expect(handoff.ok).toBe(true);
      expect(sender.ok).toBe(false);
      if (sender.ok === false) {
        expect(
          sender.reason === "ALREADY_LEASED" ||
            sender.code === "23505" ||
            sender.code === "40001",
        ).toBe(true);
      }
      const held = psqlMust(
        dbUrl,
        `SELECT operation_id || '|' || lease_role
         FROM wallet_active_leases WHERE wallet_id = '${source}'`,
      ).trim();
      expect(held).toBe(`${childOp}|MOVE_SOURCE`);
      // No observable gap: still exactly one active row for the source.
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBe(1);
    },
    90_000,
  );

  it.skipIf(!live)(
    "quarantine rejects cross-process acquisition (eligibility)",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(4);
      psqlMust(
        dbUrl,
        `UPDATE wallets
         SET state = 'QUARANTINED', quarantine_reason = 'cross-operation-lease-eligibility-probe'
         WHERE id = '${source}'`,
      );
      await expect(acquireSend(dbUrl, source, OWNER_A)).rejects.toMatchObject({
        reason: "WALLET_NOT_ELIGIBLE",
      });
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBe(0);
      psqlMust(
        dbUrl,
        `UPDATE wallets
         SET state = 'AVAILABLE', quarantine_reason = NULL
         WHERE id = '${source}'`,
      );
    },
    60_000,
  );

  it.skipIf(!live)(
    "guarded release + audit is atomic against a competing acquisition",
    async () => {
      psqlMust(dbUrl, TRUNCATE_LEASE_STATE);
      const source = W(5);
      const held = await acquireSend(dbUrl, source, OWNER_A);
      const proofId = randomUUID();
      await withTx(dbUrl, (tx) =>
        mintReleaseProof(tx, {
          proofId,
          walletId: source,
          operationId: held.operationId,
          membershipId: held.leases[0]!.membershipId,
          leaseGroupId: held.groupId,
          leaseEpoch: held.leases[0]!.leaseEpoch,
          proofKind: "EXTERNAL_SEND_LANDED",
          proofDigest: digest(`race-release-${held.operationId}`),
        }),
      );
      await withTx(dbUrl, (tx) =>
        completeGroupOperation(tx, {
          leaseGroupId: held.groupId,
          operationId: held.operationId,
        }),
      );

      // Race: guarded release vs competing acquire on separate OS processes.
      const [release, acquire] = await raceAcquire(
        () =>
          withTx(dbUrl, (tx) =>
            releaseLease(tx, {
              walletId: source,
              ownerInstanceId: OWNER_A,
              operationId: held.operationId,
              membershipId: held.leases[0]!.membershipId,
              leaseGroupId: held.groupId,
              leaseEpoch: held.leases[0]!.leaseEpoch,
              releaseProofId: proofId,
              releaseReason: "LANDED",
            }),
          ),
        async () => {
          const op = randomUUID();
          const g = await withTx(dbUrl, (tx) => createLeaseGroup(tx, op));
          return withTx(dbUrl, (tx) =>
            acquireLeases(tx, {
              wallets: [{ walletId: source, leaseRole: "SEND_SOURCE" }],
              leaseGroupId: g,
              rootOperationId: op,
              operationId: op,
              ownerInstanceId: OWNER_B,
            }),
          );
        },
      );

      // Release always commits (proof-backed, terminal). Acquire may win after release
      // commits, or lose if it raced while the row was still held — never a silent double.
      expect(release.ok).toBe(true);
      const activeCount = Number(
        psqlMust(
          dbUrl,
          `SELECT count(*) FROM wallet_active_leases WHERE wallet_id = '${source}'`,
        ).trim(),
      );
      if (acquire.ok) {
        expect(activeCount).toBe(1);
        // Successor epoch is strictly greater than the released one.
        const epoch = BigInt(
          psqlMust(
            dbUrl,
            `SELECT lease_epoch FROM wallet_active_leases WHERE wallet_id = '${source}'`,
          ).trim(),
        );
        expect(epoch > held.leases[0]!.leaseEpoch).toBe(true);
      } else {
        expect(activeCount).toBe(0);
        expect(
          acquire.reason === "ALREADY_LEASED" ||
            acquire.code === "23505" ||
            acquire.code === "40001",
        ).toBe(true);
      }
      // Membership closed + proof consumed (audit of the guarded release path).
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM wallet_lease_memberships
             WHERE id = '${held.leases[0]!.membershipId}' AND released_at IS NOT NULL`,
          ).trim(),
        ),
      ).toBe(1);
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM lease_release_proofs
             WHERE proof_id = '${proofId}' AND consumed_at IS NOT NULL`,
          ).trim(),
        ),
      ).toBe(1);
      // LEASE_RELEASED audit event present (same-tx with release).
      expect(
        Number(
          psqlMust(
            dbUrl,
            `SELECT count(*) FROM lease_audit_events
             WHERE action = 'LEASE_RELEASED' AND wallet_id = '${source}'`,
          ).trim(),
        ),
      ).toBeGreaterThanOrEqual(1);
    },
    90_000,
  );
});
