/**
 * child-move-create.pg.test.ts
 *
 * Proves against REAL PostgreSQL + frozen operations DDL:
 *   1. createChildMoveAtomically produces exactly one MOVE_INTERNAL child joined to the
 *      parent lease group.
 *   2. Concurrent createChildMoveAtomically calls (N rivals, separate sessions) yield exactly
 *      one child — UNIQUE INDEX operations_one_spawn_per_parent_uidx is the arbiter.
 *   3. Destination un-blessed between receive-create and handoff blocks child creation
 *      (no child row, no lease_group_operations join).
 */
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createChildMoveAtomically } from "../src/move/child-create.js";
import { SqlChildMoveCreateStore } from "../src/move/child-create-sql.js";
import {
  MOVE_ADMISSION_EVENTS_DDL,
  type SqlExecutor,
  type SqlQueryResult,
  type SqlTxFn,
} from "../src/move/sql-store.js";

const MAINTENANCE_DB = "postgres";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdl = (db: string, ddl: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: ddl,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const litParam = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

const bindParams = (text: string, params: readonly unknown[]): string =>
  text.replace(/\$(\d+)/g, (_m, n: string) => litParam(params[Number(n) - 1]));

class MovePsqlSession implements SqlExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(payload: string) => void> = [];

  constructor(private readonly db: string) {}

  start(): void {
    if (this.child) return;
    this.child = spawn(
      "psql",
      ["-d", this.db, "-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      let idx = this.buffer.indexOf("__CHILD_PSQL_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__CHILD_PSQL_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__CHILD_PSQL_END__\n");
      }
    });
  }

  stop(): void {
    if (!this.child) return;
    const child = this.child;
    this.child = null;
    try {
      child.stdin.write("ROLLBACK;\n");
    } catch {
      /* ignore */
    }
    try {
      child.stdin.end();
    } catch {
      /* ignore */
    }
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`psql timeout: ${sql.slice(0, 80)}`)),
        20_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          reject(new Error(payload.trim()));
          return;
        }
        resolve(payload);
      });
      child.stdin.write(`${sql};\n\\echo __CHILD_PSQL_END__\n`);
    });
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindParams(text, params).trim().replace(/;+\s*$/, "");
    if (/\bRETURNING\b/i.test(bound)) {
      const jsonSql =
        `WITH t AS (${bound}) SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM t`;
      const out = await this.send(jsonSql);
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const json = lines[lines.length - 1] ?? "[]";
      const rows = JSON.parse(json) as R[];
      return { rows, rowCount: rows.length };
    }
    if (/^SELECT\b/i.test(bound)) {
      const jsonSql = `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${bound}) t`;
      const out = await this.send(jsonSql);
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const json = lines[lines.length - 1] ?? "[]";
      const rows = JSON.parse(json) as R[];
      return { rows, rowCount: rows.length };
    }
    await this.send(bound);
    return { rows: [] as R[], rowCount: 0 };
  }

  readonly withTransaction: SqlTxFn = async (body) => {
    await this.send("BEGIN");
    try {
      const result = await body(this);
      await this.send("COMMIT");
      return result;
    } catch (err) {
      try {
        await this.send("ROLLBACK");
      } catch {
        /* ignore */
      }
      throw err;
    }
  };
}

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  const implementers = /^CREATE TABLE implementers \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null || implementers === null) {
    throw new Error("node-implementer-registry.sql: nodes/implementers blocks not found");
  }
  return `${base}\n${nodes[0]}\n${implementers[0]}\n`;
})();

const CUSTODY_DDL = readSchema("custody-eligibility.sql");
const operationsDdl = ((): string => {
  const raw = readSchema("operations.sql");
  const start = raw.indexOf("CREATE TABLE operations");
  if (start < 0) throw new Error("operations.sql: CREATE TABLE operations not found");
  return raw.slice(start);
})();

const LEASE_FRAGMENT = `
CREATE TABLE lease_groups (
  id uuid PRIMARY KEY,
  root_operation_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL,
  child_disposition text NOT NULL DEFAULT 'NONE'
    CHECK (child_disposition IN ('NONE', 'PENDING', 'JOINED')),
  released_at timestamptz,
  release_proof_id uuid
);
CREATE TABLE lease_group_operations (
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  operation_id uuid NOT NULL UNIQUE,
  joined_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (lease_group_id, operation_id)
);
`;

const NODE_ID = "c2820000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "c2820000-0000-4000-8000-000000000002";
const RECEIVER_WALLET = "d2820000-0000-4000-8000-000000000001";
const DEST_WALLET = "d2820000-0000-4000-8000-000000000002";
const DESTINATION_ID = "d2820000-0000-4000-8000-000000000003";
const RECOVERY_ID = "d2820000-0000-4000-8000-000000000004";
const RECOVERY_ID_2 = "d2820000-0000-4000-8000-000000000005";
const DEVICE_KEY = "d2820000-0000-4000-8000-000000000006";
const BLESSING_ART = "d2820000-0000-4000-8000-000000000007";
const SHA_A = "a".repeat(64);
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedBase = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'child-move-create', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;` +
  `INSERT INTO implementers (id, name) VALUES ('${IMPLEMENTER_ID}', 'child-move-create') ` +
  `ON CONFLICT (id) DO NOTHING;` +
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
  `('${RECEIVER_WALLET}', '${NODE_ID}', '${pubkey("SRC")}', 'node_generated', 'PINNED'),` +
  `('${DEST_WALLET}', '${NODE_ID}', '${pubkey("DST")}', 'node_generated', 'AVAILABLE');` +
  `INSERT INTO wallet_recovery_verifications ` +
  `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) VALUES ` +
  `('${RECOVERY_ID}', '${RECEIVER_WALLET}', 'AUDITED_EXPORT', '${SHA_A}', '${pubkey("SRC")}', ` +
  `'${RECOVERY_ID}', now(), 'child-move-create'),` +
  `('${RECOVERY_ID_2}', '${DEST_WALLET}', 'AUDITED_EXPORT', '${SHA_A}', '${pubkey("DST")}', ` +
  `'${RECOVERY_ID_2}', now(), 'child-move-create');` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${RECOVERY_ID}' ` +
  `WHERE id = '${RECEIVER_WALLET}';` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${RECOVERY_ID_2}' ` +
  `WHERE id = '${DEST_WALLET}';` +
  `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
  `VALUES ('${DESTINATION_ID}', '${NODE_ID}', '${DEST_WALLET}', 'BLESSED', now(), ` +
  `'${DEVICE_KEY}', '${BLESSING_ART}');`;

const seedLandedParent = (parentId: string, leaseGroupId: string): string =>
  `INSERT INTO operations (` +
  `id, node_id, implementer_id, kind, status, amount_zkz, ` +
  `receiver_wallet_id, after_landing, after_landing_destination_id, ` +
  `discriminator, anchor, expiry_unix_time_secs, t0_observation_id, ` +
  `idempotency_key, request_sha256, formation_state` +
  `) VALUES (` +
  `'${parentId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED', '1.25', ` +
  `'${RECEIVER_WALLET}', 'INTERNAL_MOVE', '${DESTINATION_ID}', ` +
  `'${parentId}', 'anchor-282', '1784883937', '${randomUUID()}', ` +
  `'${parentId}-parent', '${SHA_A}', 'NOT_REQUIRED'` +
  `);` +
  `INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition) ` +
  `VALUES ('${leaseGroupId}', '${parentId}', now(), 'PENDING');` +
  `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at) ` +
  `VALUES ('${leaseGroupId}', '${parentId}', now());`;

const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

describeIfPg("createChildMoveAtomically — real PostgreSQL", () => {
  const scratchDb = `child_move_create_child_${Date.now()}_${process.pid}`;
  let session: MovePsqlSession;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, CUSTODY_DDL);
    applyDdl(scratchDb, operationsDdl);
    applyDdl(scratchDb, LEASE_FRAGMENT);
    applyDdl(scratchDb, MOVE_ADMISSION_EVENTS_DDL);
    // destinations may require device_keys FK — strip if needed via direct insertennian
    // If seed fails on FK, inject minimal stubs.
    const seedOutcome = runPsql(scratchDb, seedBase());
    if (!seedOutcome.ok) {
      // Some schema packs require device_keys for destinations.blessed_by_device_key_id.
      // Provide a minimal stub if the check names that table.
      if (/device_keys|destinations/.test(seedOutcome.stderr)) {
        runPsql(
          scratchDb,
          `CREATE TABLE IF NOT EXISTS device_keys (id uuid PRIMARY KEY);` +
            `INSERT INTO device_keys (id) VALUES ('${DEVICE_KEY}') ON CONFLICT DO NOTHING;`,
        );
        psqlMust(scratchDb, seedBase());
      } else {
        throw new Error(`seedBase failed: ${seedOutcome.stderr}`);
      }
    }
    session = new MovePsqlSession(scratchDb);
  });

  afterAll(() => {
    session?.stop();
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE);`);
  });

  it("creates one child joined to the parent lease group", async () => {
    const parentId = randomUUID();
    const leaseGroupId = randomUUID();
    psqlMust(scratchDb, seedLandedParent(parentId, leaseGroupId));

    const store = new SqlChildMoveCreateStore({
      sql: session,
      withTransaction: session.withTransaction,
    });
    const result = await createChildMoveAtomically(store, parentId);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.outcome).toBe("CREATED");
    expect(result.child.spawnedFromOperationId).toBe(parentId);
    expect(result.child.leaseGroupId).toBe(leaseGroupId);
    expect(result.child.idempotencyKey).toBe(parentId);
    expect(result.child.amountZkz).toBe("1.25");

    const children = runPsql(
      scratchDb,
      `SELECT count(*) FROM operations WHERE spawned_from_operation_id = '${parentId}';`,
    ).stdout.trim();
    expect(children).toBe("1");

    const group = runPsql(
      scratchDb,
      `SELECT lease_group_id::text FROM lease_group_operations ` +
        `WHERE operation_id = '${result.child.operationId}';`,
    ).stdout.trim();
    expect(group).toBe(leaseGroupId);

    const disposition = runPsql(
      scratchDb,
      `SELECT child_disposition FROM lease_groups WHERE id = '${leaseGroupId}';`,
    ).stdout.trim();
    expect(disposition).toBe("JOINED");

    const events = runPsql(
      scratchDb,
      `SELECT count(*) FROM move_admission_events WHERE operation_id = '${result.child.operationId}';`,
    ).stdout.trim();
    expect(events).toBe("1");
  });

  it("concurrent createChildMoveAtomically yields exactly one child", async () => {
    const parentId = randomUUID();
    const leaseGroupId = randomUUID();
    psqlMust(scratchDb, seedLandedParent(parentId, leaseGroupId));

    const N = 6;
    const sessions = Array.from({ length: N }, () => new MovePsqlSession(scratchDb));
    try {
      const pending = sessions.map((s) => {
        const store = new SqlChildMoveCreateStore({
          sql: s,
          withTransaction: s.withTransaction,
        });
        return createChildMoveAtomically(store, parentId);
      });
      const results = await Promise.all(pending);

      const created = results.filter((r) => r.ok && r.outcome === "CREATED");
      const already = results.filter((r) => r.ok && r.outcome === "ALREADY_EXISTS");
      const rejected = results.filter((r) => !r.ok);

      expect(rejected).toHaveLength(0);
      expect(created).toHaveLength(1);
      expect(already).toHaveLength(N - 1);

      const children = runPsql(
        scratchDb,
        `SELECT count(*) FROM operations WHERE spawned_from_operation_id = '${parentId}';`,
      ).stdout.trim();
      expect(children).toBe("1");

      const joins = runPsql(
        scratchDb,
        `SELECT count(*) FROM lease_group_operations WHERE lease_group_id = '${leaseGroupId}';`,
      ).stdout.trim();
      // parent + one child
      expect(joins).toBe("2");
    } finally {
      for (const s of sessions) s.stop();
    }
  });

  it("un-blessed destination blocks child creation (no child row)", async () => {
    const parentId = randomUUID();
    const leaseGroupId = randomUUID();
    psqlMust(scratchDb, seedLandedParent(parentId, leaseGroupId));
    psqlMust(
      scratchDb,
      `UPDATE destinations SET state = 'PENDING', blessed_at = NULL, ` +
        `blessed_by_device_key_id = NULL, blessing_artifact_id = NULL ` +
        `WHERE id = '${DESTINATION_ID}';`,
    );

    const store = new SqlChildMoveCreateStore({
      sql: session,
      withTransaction: session.withTransaction,
    });
    const result = await createChildMoveAtomically(store, parentId);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("DESTINATION_INELIGIBLE");

    const children = runPsql(
      scratchDb,
      `SELECT count(*) FROM operations WHERE spawned_from_operation_id = '${parentId}';`,
    ).stdout.trim();
    expect(children).toBe("0");

    const disposition = runPsql(
      scratchDb,
      `SELECT child_disposition FROM lease_groups WHERE id = '${leaseGroupId}';`,
    ).stdout.trim();
    expect(disposition).toBe("PENDING");

    // Restore blessed state for subsequent tests if any.
    psqlMust(
      scratchDb,
      `UPDATE destinations SET state = 'BLESSED', blessed_at = now(), ` +
        `blessed_by_device_key_id = '${DEVICE_KEY}', blessing_artifact_id = '${BLESSING_ART}' ` +
        `WHERE id = '${DESTINATION_ID}';`,
    );
  });
});

// Fail closed when PG_REQUIRED set but psql unavailable.
if (PG_REQUIRED && !PG_AVAILABLE) {
  describe("PG required", () => {
    it("requires PostgreSQL", () => {
      throw new Error("PG_REQUIRED=1 but psql is not usable");
    });
  });
}
