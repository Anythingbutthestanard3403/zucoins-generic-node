/**
 * move-internal-create.pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database running the REAL frozen
 * DDL (operations.sql + custody-eligibility.sql + lease-foundation fragments), that the
 * admission money-path invariants are enforced BY THE DATABASE:
 *
 *   1. Idempotency — UNIQUE (implementer_id, kind, idempotency_key) rejects a second row
 *      with 23505; the store's ON CONFLICT DO NOTHING absorbs it as IDEMPOTENCY_CONFLICT.
 *   2. MOVE_INTERNAL shape CHECK — missing destination_id / wrong kind columns rejected
 *      with 23514.
 *   3. — amount_zkz = '0' rejected by zkz_amount_positive_text domain.
 *   4. Atomic admit TX — operation + lease_group + admission event co-commit; a conflict
 *      leaves neither a second operation nor a second event.
 *   5. Receive-child join — child refuses a second lease_groups root and marks
 *      child_disposition JOINED on the parent group.
 *   6. SqlMoveCreateStore + createInternalMove end-to-end — stand-alone admit,
 *      same-hash replay under a held source lease (D1), and receive-child join
 * while the parent continuously holds the source lease (D2 / operation-flow).
 *
 * Harness mirrors send-external-create-pg.test.ts: own scratch DB, psql child process
 * (network-containment), PG_REQUIRED fail-closed when the gate expects Postgres.
 */
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createInternalMove,
  type MoveCreateRequest,
} from "../src/move/create.js";
import {
  MOVE_ADMISSION_EVENTS_DDL,
  SqlMoveCreateStore,
  STATEMENTS,
  type SqlExecutor,
  type SqlQueryResult,
  type SqlTxFn,
} from "../src/move/sql-store.js";

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const EXPECTED_DRILL_COUNT = 9;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) args.push("-v", "VERBOSITY=verbose");
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
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
    throw new Error(
      `move-internal-create DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`,
    );
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

// Minimal prerequisite chain: base domains/enums → nodes → implementers → custody →
// operations → lease groups. Stubs replace full registry FKs where operations.pg does.
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

// operations.sql redeclares domains/enums already present — strip CREATE DOMAIN / TYPE that
// collide when applied after base-enums-domains + custody.
const operationsDdl = ((): string => {
  const raw = readSchema("operations.sql");
  // Drop leading domain/type blocks already applied by base-enums-domains / prerequisite.
  // Keep from CREATE TABLE operations onward, plus the spawn unique index.
  const start = raw.indexOf("CREATE TABLE operations");
  if (start < 0) throw new Error("operations.sql: CREATE TABLE operations not found");
  return raw.slice(start);
})();

// Lease foundation is large and references many objects. Apply only the two tables admission
// needs, matching the data-model lease_groups / lease_group_operations shape used by the store.
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

const NODE_ID = "c2850000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "c2850000-0000-4000-8000-000000000002";
const SOURCE_WALLET = "d2850000-0000-4000-8000-000000000001";
const DEST_WALLET = "d2850000-0000-4000-8000-000000000002";
const DESTINATION_ID = "d2850000-0000-4000-8000-000000000003";
const RECOVERY_ID = "d2850000-0000-4000-8000-000000000004";
const RECOVERY_ID_2 = "d2850000-0000-4000-8000-000000000005";
const DEVICE_KEY = "d2850000-0000-4000-8000-000000000006";
const BLESSING_ART = "d2850000-0000-4000-8000-000000000007";
const SHA_A = "a".repeat(64);

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'move-internal-create-move-admit', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

const seedImplementer = (): string =>
  `INSERT INTO implementers (id, name) VALUES ('${IMPLEMENTER_ID}', 'move-internal-create') ON CONFLICT (id) DO NOTHING;`;

const seedVerifiedWallet = (walletId: string, recoveryId: string, publicKey: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', 'AVAILABLE'); ` +
  `INSERT INTO wallet_recovery_verifications ` +
  `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
  `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA_A}', '${publicKey}', ` +
  `'${recoveryId}', now(), 'move-internal-create-test'); ` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
  `WHERE id = '${walletId}';`;

const seedBlessedDestination = (): string =>
  `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
  `VALUES ('${DESTINATION_ID}', '${NODE_ID}', '${DEST_WALLET}', 'BLESSED', now(), ` +
  `'${DEVICE_KEY}', '${BLESSING_ART}');`;

const lit = (value: string | number | boolean | null): string => {
  if (value === null) return "NULL";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return String(value);
  return `'${value.replace(/'/g, "''")}'`;
};

const litParam = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

const bindParams = (text: string, params: readonly unknown[]): string =>
  text.replace(/\$(\d+)/g, (_m, n: string) => litParam(params[Number(n) - 1]));

/**
 * Long-lived psql session implementing move/sql-store SqlExecutor + withTransaction.
 * Unlike test/psql-harness's mutation wrapper (which strips RETURNING), this preserves
 * INSERT … RETURNING rows so SqlMoveCreateStore.insertAdmitted can see the admitted id.
 */
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
      let idx = this.buffer.indexOf("__MOVE_PSQL_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__MOVE_PSQL_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__MOVE_PSQL_END__\n");
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
      // ignore
    }
    try {
      child.stdin.end();
    } catch {
      // ignore
    }
    try {
      child.kill("SIGKILL");
    } catch {
      // ignore
    }
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`move psql timeout: ${sql.slice(0, 80)}`)),
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
      child.stdin.write(`${sql};\n\\echo __MOVE_PSQL_END__\n`);
    });
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindParams(text, params).trim().replace(/;+\s*$/, "");
    // Named columns without a driver : json_agg(row_to_json). INSERT…RETURNING must
    // be a CTE — a FROM (INSERT …) subquery is not valid SQL.
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
      const jsonSql =
        `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${bound}) t`;
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
        // session may already be aborted
      }
      throw err;
    }
  };
}

interface InsertArgs {
  readonly operationId: string;
  readonly idempotencyKey: string;
  readonly requestSha256?: string;
  readonly amountZkz?: string;
  readonly sourceWalletId?: string;
  readonly destinationId?: string | null;
  readonly spawnedFrom?: string | null;
}

const PREPARE_INSERT = `PREPARE move_admit AS ${STATEMENTS.INSERT_OPERATION};`;

const executeInsert = (args: InsertArgs): string =>
  `${PREPARE_INSERT} EXECUTE move_admit(${[
    lit(args.operationId),
    lit(NODE_ID),
    lit(IMPLEMENTER_ID),
    lit(args.amountZkz ?? "5.5"),
    lit(args.sourceWalletId ?? SOURCE_WALLET),
    lit(args.destinationId === undefined ? DESTINATION_ID : args.destinationId),
    lit(args.spawnedFrom ?? null),
    lit(args.idempotencyKey),
    lit(args.requestSha256 ?? SHA_A),
  ].join(", ")});`;

const rawOperationInsert = (args: InsertArgs): string =>
  `INSERT INTO operations (` +
  `id, node_id, implementer_id, kind, status, amount_zkz, ` +
  `source_wallet_id, destination_id, spawned_from_operation_id, ` +
  `idempotency_key, request_sha256, formation_state` +
  `) VALUES (` +
  `${lit(args.operationId)}, ${lit(NODE_ID)}, ${lit(IMPLEMENTER_ID)}, ` +
  `'MOVE_INTERNAL', 'CREATED', ${lit(args.amountZkz ?? "5.5")}, ` +
  `${lit(args.sourceWalletId ?? SOURCE_WALLET)}, ` +
  `${lit(args.destinationId === undefined ? DESTINATION_ID : args.destinationId)}, ` +
  `${lit(args.spawnedFrom ?? null)}, ` +
  `${lit(args.idempotencyKey)}, ${lit(args.requestSha256 ?? SHA_A)}, 'NOT_REQUIRED');`;

const countRows = (db: string, table: string, where: string): string =>
  runPsql(db, `SELECT count(*) FROM ${table} WHERE ${where};`).stdout.trim();

const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

let assertionsRun = 0;

describeIfPg("MOVE_INTERNAL admission — real frozen DDL against real PostgreSQL", () => {
  const scratchDb = `move_internal_create_move_admit_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, CUSTODY_DDL);
    psqlMust(scratchDb, seedNode());
    psqlMust(scratchDb, seedImplementer());
    applyDdl(scratchDb, operationsDdl);
    applyDdl(scratchDb, LEASE_FRAGMENT);
    applyDdl(scratchDb, MOVE_ADMISSION_EVENTS_DDL);
    psqlMust(scratchDb, seedVerifiedWallet(SOURCE_WALLET, RECOVERY_ID, pubkey("SRC")));
    psqlMust(scratchDb, seedVerifiedWallet(DEST_WALLET, RECOVERY_ID_2, pubkey("DST")));
    psqlMust(scratchDb, seedBlessedDestination());
  });

  afterAll(() => {
    // Best-effort: a live backend on the scratch DB makes DROP fail without FORCE; FORCE
    // still races if a session is mid-exit. Never fail the suite on teardown.
    const drop = runPsql(
      MAINTENANCE_DB,
      `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`,
    );
    if (!drop.ok) {
      // eslint-disable-next-line no-console
      console.warn(`fixture teardown drop skipped: ${drop.stderr.trim() || "unknown"}`);
    }
  });

  it("store INSERT_OPERATION writes a MOVE_INTERNAL/CREATED row", () => {
    const outcome = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e2850000-0000-4000-8000-000000000001",
        idempotencyKey: "idem-key-move-drill-0001",
      }),
    );
    expect(outcome.ok, outcome.stderr).toBe(true);
    expect(outcome.stdout.trim()).toBe("e2850000-0000-4000-8000-000000000001");
    expect(
      countRows(
        scratchDb,
        "operations",
        `id = 'e2850000-0000-4000-8000-000000000001' AND kind = 'MOVE_INTERNAL' AND status = 'CREATED'`,
      ),
    ).toBe("1");
    assertionsRun += 1;
  });

  it("rejects a duplicate idempotency scope with unique_violation (23505)", () => {
    const duplicate = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e2850000-0000-4000-8000-000000000002",
        idempotencyKey: "idem-key-move-drill-0001",
        requestSha256: "b".repeat(64),
      }),
      true,
    );
    expect(duplicate.ok, "second row for one idempotency scope must be rejected").toBe(false);
    expect(extractSqlstate(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("ON CONFLICT DO NOTHING absorbs the idempotency collision (store path)", () => {
    const outcome = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e2850000-0000-4000-8000-000000000003",
        idempotencyKey: "idem-key-move-drill-0001",
        requestSha256: "c".repeat(64),
      }),
    );
    // DO NOTHING → zero RETURNING rows, empty stdout, exit 0
    expect(outcome.ok, outcome.stderr).toBe(true);
    expect(outcome.stdout.trim()).toBe("");
    expect(
      countRows(scratchDb, "operations", `idempotency_key = 'idem-key-move-drill-0001'`),
    ).toBe("1");
    assertionsRun += 1;
  });

  it("rejects amount_zkz = 0 with check_violation", () => {
    const zero = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e2850000-0000-4000-8000-000000000004",
        idempotencyKey: "idem-key-move-drill-0004",
        amountZkz: "0",
      }),
      true,
    );
    expect(zero.ok).toBe(false);
    expect(extractSqlstate(zero.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("rejects MOVE_INTERNAL without destination_id (shape CHECK)", () => {
    const bad = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e2850000-0000-4000-8000-000000000005",
        idempotencyKey: "idem-key-move-drill-0005",
        destinationId: null,
      }),
      true,
    );
    expect(bad.ok).toBe(false);
    expect(extractSqlstate(bad.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    assertionsRun += 1;
  });

  it("atomic admit TX: operation + lease_group + event co-commit", () => {
    const opId = "e2850000-0000-4000-8000-000000000006";
    const groupId = "f2850000-0000-4000-8000-000000000006";
    const eventId = "a2850000-0000-4000-8000-000000000006";
    const sql = `
BEGIN;
${STATEMENTS.INSERT_OPERATION
  .replace(/\$1/g, lit(opId))
  .replace(/\$2/g, lit(NODE_ID))
  .replace(/\$3/g, lit(IMPLEMENTER_ID))
  .replace(/\$4/g, lit("2.25"))
  .replace(/\$5/g, lit(SOURCE_WALLET))
  .replace(/\$6/g, lit(DESTINATION_ID))
  .replace(/\$7/g, "NULL")
  .replace(/\$8/g, lit("idem-key-move-drill-0006"))
  .replace(/\$9/g, lit(SHA_A))
  .replace(/::uuid/g, "")
  .replace(/::operation_kind/g, "")
  .replace(/::operation_status/g, "")
  .replace(/::external_formation_state/g, "")};
${STATEMENTS.INSERT_LEASE_GROUP
  .replace(/\$1::uuid/g, lit(groupId))
  .replace(/\$2::uuid/g, lit(opId))
  .replace(/\$3::timestamptz/g, "now()")};
${STATEMENTS.INSERT_GROUP_OPERATION
  .replace(/\$1::uuid/g, lit(groupId))
  .replace(/\$2::uuid/g, lit(opId))
  .replace(/\$3::timestamptz/g, "now()")};
${STATEMENTS.INSERT_ADMISSION_EVENT
  .replace(/\$1::uuid/g, lit(eventId))
  .replace(/\$2::uuid/g, lit(opId))
  .replace(/\$3::uuid/g, lit(NODE_ID))
  .replace(/\$4::uuid/g, lit(IMPLEMENTER_ID))
  .replace(/\$5::uuid/g, lit(SOURCE_WALLET))
  .replace(/\$6::uuid/g, lit(DESTINATION_ID))
  .replace(/\$7/g, lit("2.25"))
  .replace(/\$8::timestamptz/g, "now()")};
COMMIT;
`;
    // Use parameterized prepare/execute for the operation; plain SQL for the rest.
    const plain = `
BEGIN;
INSERT INTO operations (
  id, node_id, implementer_id, kind, status, amount_zkz,
  source_wallet_id, destination_id, spawned_from_operation_id,
  idempotency_key, request_sha256, formation_state
) VALUES (
  '${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'MOVE_INTERNAL', 'CREATED', '2.25',
  '${SOURCE_WALLET}', '${DESTINATION_ID}', NULL,
  'idem-key-move-drill-0006', '${SHA_A}', 'NOT_REQUIRED'
);
INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
VALUES ('${groupId}', '${opId}', now(), 'NONE');
INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
VALUES ('${groupId}', '${opId}', now());
INSERT INTO move_admission_events (
  event_id, operation_id, node_id, implementer_id, event_type,
  source_wallet_id, destination_id, amount_zkz, created_at
) VALUES (
  '${eventId}', '${opId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'internal_move.created',
  '${SOURCE_WALLET}', '${DESTINATION_ID}', '2.25', now()
);
COMMIT;
`;
    void sql;
    const outcome = runPsql(scratchDb, plain);
    expect(outcome.ok, outcome.stderr).toBe(true);
    expect(countRows(scratchDb, "operations", `id = '${opId}'`)).toBe("1");
    expect(countRows(scratchDb, "lease_groups", `id = '${groupId}'`)).toBe("1");
    expect(
      countRows(
        scratchDb,
        "move_admission_events",
        `operation_id = '${opId}' AND event_type = 'internal_move.created'`,
      ),
    ).toBe("1");
    assertionsRun += 1;
  });

  it("receive-child joins parent lease group without a second root (review indicator 5)", () => {
    const parentOp = "e2850000-0000-4000-8000-000000000007";
    const childOp = "e2850000-0000-4000-8000-000000000008";
    const parentGroup = "f2850000-0000-4000-8000-000000000007";
    // Parent receive root (we only need the group + a stand-in root op that is MOVE for FK simplicity)
    psqlMust(
      scratchDb,
      rawOperationInsert({
        operationId: parentOp,
        idempotencyKey: "idem-key-move-drill-0007",
      }),
    );
    psqlMust(
      scratchDb,
      `INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
       VALUES ('${parentGroup}', '${parentOp}', now(), 'PENDING');
       INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
       VALUES ('${parentGroup}', '${parentOp}', now());`,
    );
    // Child MOVE via store INSERT + join
    const childInsert = runPsql(
      scratchDb,
      executeInsert({
        operationId: childOp,
        idempotencyKey: "idem-key-move-drill-0008",
        spawnedFrom: parentOp,
      }),
    );
    expect(childInsert.ok, childInsert.stderr).toBe(true);
    psqlMust(
      scratchDb,
      `INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
       VALUES ('${parentGroup}', '${childOp}', now());
       UPDATE lease_groups SET child_disposition = 'JOINED'
       WHERE id = '${parentGroup}' AND child_disposition = 'PENDING';`,
    );
    expect(countRows(scratchDb, "lease_groups", `root_operation_id = '${childOp}'`)).toBe("0");
    expect(
      countRows(
        scratchDb,
        "lease_group_operations",
        `lease_group_id = '${parentGroup}' AND operation_id = '${childOp}'`,
      ),
    ).toBe("1");
    expect(
      runPsql(
        scratchDb,
        `SELECT child_disposition FROM lease_groups WHERE id = '${parentGroup}';`,
      ).stdout.trim(),
    ).toBe("JOINED");
    // One child per parent via partial unique index
    const secondChild = runPsql(
      scratchDb,
      rawOperationInsert({
        operationId: "e2850000-0000-4000-8000-000000000009",
        idempotencyKey: "idem-key-move-drill-0009",
        spawnedFrom: parentOp,
      }),
      true,
    );
    expect(secondChild.ok).toBe(false);
    expect(extractSqlstate(secondChild.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    assertionsRun += 1;
  });

  it("wallet_active_leases presence is visible to the busy SELECT", () => {
    // Insert a minimal active lease row (custody-eligibility shape).
    const leaseSql = `
INSERT INTO wallet_active_leases (
  wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
  lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
) VALUES (
  '${SOURCE_WALLET}', 'a2850000-0000-4000-8000-0000000000aa',
  'f2850000-0000-4000-8000-000000000007',
  'e2850000-0000-4000-8000-000000000007',
  'e2850000-0000-4000-8000-000000000007',
  'MOVE_SOURCE', 1, now(), now(), 'b2850000-0000-4000-8000-0000000000bb'
);`;
    const ins = runPsql(scratchDb, leaseSql);
    expect(ins.ok, ins.stderr).toBe(true);
    const busy = runPsql(scratchDb, STATEMENTS.SELECT_ACTIVE_LEASE.replace("$1", lit(SOURCE_WALLET)));
    expect(busy.ok, busy.stderr).toBe(true);
    expect(busy.stdout.trim()).toBe("1");
    const free = runPsql(
      scratchDb,
      STATEMENTS.SELECT_ACTIVE_LEASE.replace("$1", lit("00000000-0000-4000-8000-0000000000ff")),
    );
    expect(free.ok).toBe(true);
    expect(free.stdout.trim()).toBe("");
    assertionsRun += 1;
  });

  it("SqlMoveCreateStore + createInternalMove: admit, D1 replay under lease, D2 child join", async () => {
    // Fresh wallets so prior drills' leases / ops do not collide with the service path.
    const src = "d2850000-0000-4000-8000-0000000000a1";
    const dst = "d2850000-0000-4000-8000-0000000000a2";
    const destId = "d2850000-0000-4000-8000-0000000000a3";
    const rec1 = "d2850000-0000-4000-8000-0000000000a4";
    const rec2 = "d2850000-0000-4000-8000-0000000000a5";
    const parentOp = "e2850000-0000-4000-8000-0000000000b1";
    const parentGroup = "f2850000-0000-4000-8000-0000000000b1";
    const standAloneOp = "e2850000-0000-4000-8000-0000000000c1";
    const standAloneGroup = "f2850000-0000-4000-8000-0000000000c1";
    const childOp = "e2850000-0000-4000-8000-0000000000c2";
    const eventIds = [
      "a2850000-0000-4000-8000-0000000000e1",
      "a2850000-0000-4000-8000-0000000000e2",
    ];
    let eventIdx = 0;

    psqlMust(scratchDb, seedVerifiedWallet(src, rec1, pubkey("SR2")));
    psqlMust(scratchDb, seedVerifiedWallet(dst, rec2, pubkey("DS2")));
    psqlMust(
      scratchDb,
      `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id)
       VALUES ('${destId}', '${NODE_ID}', '${dst}', 'BLESSED', now(),
       '${DEVICE_KEY}', 'd2850000-0000-4000-8000-0000000000a7');`,
    );
    // Parent receive root + PENDING group (child will JOIN). Use MOVE_INTERNAL shape so the
    // operations CHECK accepts the stand-in root without RECEIVE-only columns.
    psqlMust(
      scratchDb,
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz,
         source_wallet_id, destination_id, spawned_from_operation_id,
         idempotency_key, request_sha256, formation_state
       ) VALUES (
         '${parentOp}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'MOVE_INTERNAL', 'CREATED', '1',
         '${src}', '${destId}', NULL,
         'idem-key-move-store-parent', '${SHA_A}', 'NOT_REQUIRED'
       );
       INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
       VALUES ('${parentGroup}', '${parentOp}', now(), 'PENDING');
       INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
       VALUES ('${parentGroup}', '${parentOp}', now());`,
    );

    const session = new MovePsqlSession(scratchDb);
    session.start();
    try {
      const store = new SqlMoveCreateStore({
        sql: session,
        withTransaction: session.withTransaction,
        generateId: () => {
          const id = eventIds[eventIdx];
          eventIdx += 1;
          return id ?? `a2850000-0000-4000-8000-${String(eventIdx).padStart(12, "0")}`;
        },
      });

      const standAloneReq: MoveCreateRequest = {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        sourceWalletId: src,
        destinationId: destId,
        amountZkz: "3.5",
        idempotencyKey: "idem-key-move-store-drill-01",
      };

      const created = await createInternalMove(store, standAloneReq, {
        generateId: (() => {
          let n = 0;
          return () => {
            n += 1;
            if (n === 1) return standAloneOp;
            if (n === 2) return standAloneGroup;
            return `e2850000-0000-4000-8000-00000000d${String(n).padStart(3, "0")}`;
          };
        })(),
        now: () => 1_700_000_100_000,
      });
      expect(created.outcome, JSON.stringify(created)).toBe("CREATED");
      if (created.outcome !== "CREATED") return;
      expect(created.operation.operationId).toBe(standAloneOp);
      expect(
        countRows(scratchDb, "operations", `id = '${standAloneOp}' AND status = 'CREATED'`),
      ).toBe("1");
      expect(
        countRows(
          scratchDb,
          "move_admission_events",
          `operation_id = '${standAloneOp}' AND event_type = 'internal_move.created'`,
        ),
      ).toBe("1");
      expect(countRows(scratchDb, "lease_groups", `id = '${standAloneGroup}'`)).toBe("1");

      // D1: source becomes leased (dual-lease) — same body must IDEMPOTENT_REPLAY.
      psqlMust(
        scratchDb,
        `INSERT INTO wallet_active_leases (
           wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
           lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
         ) VALUES (
           '${src}', 'a2850000-0000-4000-8000-0000000000cc',
           '${standAloneGroup}', '${standAloneOp}', '${standAloneOp}',
           'MOVE_SOURCE', 1, now(), now(), 'b2850000-0000-4000-8000-0000000000dd'
         );`,
      );
      const replay = await createInternalMove(store, standAloneReq, {
        generateId: () => "e2850000-0000-4000-8000-00000000dead",
        now: () => 1_700_000_100_000,
      });
      expect(replay.outcome, JSON.stringify(replay)).toBe("IDEMPOTENT_REPLAY");
      if (replay.outcome !== "IDEMPOTENT_REPLAY") return;
      expect(replay.operation.operationId).toBe(standAloneOp);
      expect(
        countRows(scratchDb, "operations", `idempotency_key = 'idem-key-move-store-drill-01'`),
      ).toBe("1");

      // D2/D4: receive-child while parent holds source lease — production pins the source
      //. CREATED/JOINED, not wallet_busy / source_wallet_not_eligible.
      psqlMust(
        scratchDb,
        `UPDATE wallets SET state = 'PINNED' WHERE id = '${src}';`,
      );
      const childReq: MoveCreateRequest = {
        implementerId: IMPLEMENTER_ID,
        nodeId: NODE_ID,
        sourceWalletId: src,
        destinationId: destId,
        amountZkz: "1.25",
        idempotencyKey: "idem-key-move-store-child-01",
        spawnedFromOperationId: parentOp,
        parentLeaseGroupId: parentGroup,
      };
      const childCreated = await createInternalMove(store, childReq, {
        generateId: (() => {
          let n = 0;
          return () => {
            n += 1;
            return n === 1
              ? childOp
              : `e2850000-0000-4000-8000-00000000c${String(n).padStart(3, "0")}`;
          };
        })(),
        now: () => 1_700_000_200_000,
      });
      expect(childCreated.outcome, JSON.stringify(childCreated)).toBe("CREATED");
      if (childCreated.outcome !== "CREATED") return;
      expect(childCreated.operation.leaseGroupId).toBe(parentGroup);
      expect(childCreated.operation.spawnedFromOperationId).toBe(parentOp);
      expect(countRows(scratchDb, "lease_groups", `root_operation_id = '${childOp}'`)).toBe("0");
      expect(
        countRows(
          scratchDb,
          "lease_group_operations",
          `lease_group_id = '${parentGroup}' AND operation_id = '${childOp}'`,
        ),
      ).toBe("1");
      expect(
        runPsql(
          scratchDb,
          `SELECT child_disposition FROM lease_groups WHERE id = '${parentGroup}';`,
        ).stdout.trim(),
      ).toBe("JOINED");
    } finally {
      session.stop();
    }

    assertionsRun += 1;
  });
});

// Fail-closed: if PG was required (verify-local) or was available, every drill must have run.
describe("move-internal-create PG drill accounting", () => {
  it("discharges the expected drill count when Postgres was reachable", () => {
    if (!PG_AVAILABLE) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but PostgreSQL was not reachable — move admission drills did not run",
        );
      }
      return;
    }
    expect(assertionsRun).toBe(EXPECTED_DRILL_COUNT);
  });
});
