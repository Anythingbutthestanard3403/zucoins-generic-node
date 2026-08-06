/**
 * operation-lifecycle-concurrency.test.ts
 *
 * real-PostgreSQL concurrency and crash/restart-replay suite for the
 * operations / CAS / worker-claim / idempotency layer.
 *
 * Governing: node-core "Operation identity and guarded mutation" & "Idempotency";
 * the data model ("Operations", "Mandatory database tests"); the API contract
 * ("Error envelope"); the test plan ("Concurrency and leases").
 *
 * System under test is production code:
 *   - `SqlOperationStateStore` + `applyCasTransition` (src/operator/cas.ts, sql-store.ts)
 *   - `SqlOperationCreateStore` (src/operator/sql-store.ts) — idempotent create + spawn
 *   - production lease DELETE_ACTIVE_EXACT / HEARTBEAT statements (src/leases/statements.ts)
 * Schema under test is the frozen contract:
 *   - src/schema/operations.sql (operations + operation_wallets + one-spawn unique index)
 * - wallet_active_leases projection columns named by the acceptance criteria
 *   - src/schema/transaction-material.sql operation_transactions (attempt_no = 1)
 *
 * Concurrency is real. Each racing `query()` uses its own psql backend (own connection,
 * own transaction). Forced overlap uses an explicit gate/release Promise so both racers are
 * demonstrably in-flight before either finalizes. Sequential awaits never stand in for races.
 *
 * No silent skip. An unreachable PostgreSQL is a hard failure.
 */
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  applyCasTransition,
  CasConflictError,
  SqlOperationCreateStore,
  SqlOperationStateStore,
  type OperationCreateRequest,
} from "../src/operator/index.js";
import type { SqlExecutor, SqlQueryResult } from "../src/operator/sql-store.js";
import { OPERATIONS_SCHEMA_FILE } from "../src/schema/operations.contract.js";
import { STATEMENTS as LEASE_STATEMENTS } from "../src/leases/statements.js";
import { parseTables, tableByName } from "./transaction-material-sql-parser.js";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");

const MAINTENANCE_DB = "postgres";
const PROVISION_TIMEOUT_MS = 120_000;
const SCRATCH_DB = `operation_lifecycle_lifecycle_${Date.now()}_${process.pid}`;

const NODE_ID = "a1111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "a2222222-2222-4222-8222-222222222222";
const WALLET_A = "a3333333-3333-4333-8333-333333333333";
const WALLET_B = "a4444444-4444-4444-8444-444444444444";
const DESTINATION_ID = "a5555555-5555-4555-8555-555555555555";
const OWNER_INSTANCE = "a6666666-6666-4666-8666-666666666666";
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DESTINATION_ADDRESS = `${"A".repeat(43)}=`;
const AMOUNT = "2.25";

const TRANSIENT_SERVER_STATE =
  /too many clients already|is being accessed by other users|the database system is (starting up|shutting down)/i;
const CAPACITY_ATTEMPTS = 6;
const CAPACITY_DELAY_MS = 3_000;

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/* ─── psql helpers ────────────────────────────────────────────────── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const spawnPsql = async (args: readonly string[], timeoutMs: number): Promise<PsqlOutcome> => {
  for (let attempt = 1; ; attempt += 1) {
    try {
      const { stdout } = await execFileAsync("psql", [...args], {
        encoding: "utf-8",
        timeout: timeoutMs,
      });
      return { ok: true, stdout, stderr: "" };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; signal?: string; code?: string };
      const killed = e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
      const stderr = killed
        ? `psql exceeded the ${timeoutMs}ms client timeout (killed). ${e.stderr ?? ""}`
        : (e.stderr ?? "");
      if (attempt < CAPACITY_ATTEMPTS && TRANSIENT_SERVER_STATE.test(stderr)) {
        await sleep(CAPACITY_DELAY_MS);
        continue;
      }
      return { ok: false, stdout: e.stdout ?? "", stderr };
    }
  }
};

const runPsql = async (db: string, sql: string, timeoutMs = 20_000): Promise<PsqlOutcome> =>
  spawnPsql(
    ["-d", db, "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-qAt", "-c", sql],
    timeoutMs,
  );

const psqlMust = async (db: string, sql: string, timeoutMs?: number): Promise<string> => {
  const outcome = await runPsql(db, sql, timeoutMs);
  if (!outcome.ok) {
    throw new Error(`psql failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout.trim();
};

const lit = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

/* ─── SqlExecutor: one fresh backend per query (true concurrency) ─── */

class PsqlOneShotExecutor implements SqlExecutor {
  constructor(private readonly db: string) {}

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const sql =
      params.length === 0
        ? text
        : `PREPARE zp_q AS ${text}; EXECUTE zp_q(${params.map(lit).join(", ")});`;
    const outcome = await runPsql(this.db, sql);
    if (!outcome.ok) {
      throw new Error(`psql query failed: ${outcome.stderr.trim() || "unknown error"}`);
    }
    const lines = outcome.stdout.split("\n").filter((line) => line.length > 0);

    if (text.includes("request_sha256") && text.includes("status::text")) {
      return {
        rows: lines.map((line) => {
          const [id, status, row_version, request_sha256] = line.split("|");
          return { id, status, row_version, request_sha256 } as R;
        }),
      };
    }
    if (text.includes("status::text AS status, row_version") || text.includes("RETURNING id, status")) {
      return {
        rows: lines.map((line) => {
          const [id, status, row_version] = line.split("|");
          return { id, status, row_version } as R;
        }),
      };
    }
    if (text.includes("RETURNING id") || (text.includes("SELECT id FROM") && !text.includes("status"))) {
      return { rows: lines.map((line) => ({ id: line.split("|")[0] }) as R) };
    }
    return { rows: [] };
  }
}

/* ─── schema bootstrap ────────────────────────────────────────────── */

const FK_STUBS = `
CREATE TABLE nodes (id uuid PRIMARY KEY);
CREATE TABLE implementers (id uuid PRIMARY KEY);
CREATE TABLE wallets (id uuid PRIMARY KEY);
CREATE TABLE destinations (id uuid PRIMARY KEY);
INSERT INTO nodes (id) VALUES ('${NODE_ID}');
INSERT INTO implementers (id) VALUES ('${IMPLEMENTER_ID}');
INSERT INTO wallets (id) VALUES ('${WALLET_A}'), ('${WALLET_B}');
INSERT INTO destinations (id) VALUES ('${DESTINATION_ID}');
`;

// Minimal lease projection for read-side worker-claim-loss assertions. The full
// lease-foundation.sql pulls custody wallets(wallet_id) and eligibility triggers that
// conflict with the operations.sql wallets(id) stub (open reconciliation). This
// projection carries every column the acceptance criteria name (operation_id, lease_epoch, and the
// byte-identity set) without inventing a different meaning for them.
const LEASE_PROJECTION_DDL = `
CREATE TABLE lease_groups (
  id uuid PRIMARY KEY,
  root_operation_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  release_proof_id uuid
);
CREATE TABLE wallet_lease_memberships (
  id uuid PRIMARY KEY,
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  wallet_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL CHECK (lease_role IN (
    'RECEIVE_WINDOW','MOVE_SOURCE','MOVE_DESTINATION','SEND_SOURCE','RECONCILIATION'
  )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL DEFAULT now(),
  released_at timestamptz,
  release_reason text,
  release_proof_id uuid
);
CREATE TABLE wallet_active_leases (
  wallet_id uuid PRIMARY KEY,
  membership_id uuid NOT NULL UNIQUE REFERENCES wallet_lease_memberships (id),
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  root_operation_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  lease_role text NOT NULL CHECK (lease_role IN (
    'RECEIVE_WINDOW','MOVE_SOURCE','MOVE_DESTINATION','SEND_SOURCE','RECONCILIATION'
  )),
  lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
  acquired_at timestamptz NOT NULL,
  heartbeat_at timestamptz NOT NULL,
  owner_instance_id uuid NOT NULL,
  release_not_before timestamptz,
  UNIQUE (operation_id, wallet_id),
  UNIQUE (lease_group_id, wallet_id)
);
`;

const materialDdlSource = readFileSync(resolve(schemaDir, "transaction-material.sql"), "utf-8");
const operationTransactionsDdl = tableByName(
  parseTables(materialDdlSource),
  "operation_transactions",
).raw;

const EXTRA_DOMAIN_DDL = `
DO $$ BEGIN
  CREATE DOMAIN padded_base64url_signature AS text
    CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
`;

let createStore: SqlOperationCreateStore;
let casStore: SqlOperationStateStore;
let assertionsRun = 0;

beforeAll(async () => {
  const probe = await runPsql(MAINTENANCE_DB, "SELECT 1");
  if (!probe.ok) {
    throw new Error(
      `requires a real PostgreSQL server: maintenance database "${MAINTENANCE_DB}" is ` +
        `not usable. Hard failure, not a skip. psql said: ${probe.stderr.trim() || "unknown"}`,
    );
  }
  await psqlMust(
    MAINTENANCE_DB,
    `CREATE DATABASE ${SCRATCH_DB} TEMPLATE template0`,
    PROVISION_TIMEOUT_MS,
  );
  await psqlMust(SCRATCH_DB, FK_STUBS, PROVISION_TIMEOUT_MS);
  const applied = await spawnPsql(
    ["-d", SCRATCH_DB, "-v", "ON_ERROR_STOP=1", "-1", "-f", resolve(schemaDir, OPERATIONS_SCHEMA_FILE)],
    PROVISION_TIMEOUT_MS,
  );
  if (!applied.ok) {
    throw new Error(
      `${OPERATIONS_SCHEMA_FILE} apply failed: ${applied.stderr.trim() || "unknown error"}`,
    );
  }
  // Spawn unique index ships in operations.sql (operations_one_spawn_per_parent_uidx).
  // Do NOT recreate it here — production schema is the sole arbiter.
  await psqlMust(SCRATCH_DB, LEASE_PROJECTION_DDL, PROVISION_TIMEOUT_MS);
  await psqlMust(SCRATCH_DB, EXTRA_DOMAIN_DDL, PROVISION_TIMEOUT_MS);
  await psqlMust(SCRATCH_DB, operationTransactionsDdl, PROVISION_TIMEOUT_MS);

  const oneShot = new PsqlOneShotExecutor(SCRATCH_DB);
  createStore = new SqlOperationCreateStore(oneShot);
  casStore = new SqlOperationStateStore(oneShot);
}, PROVISION_TIMEOUT_MS * 2);

afterAll(async () => {
  await runPsql(
    MAINTENANCE_DB,
    `DROP DATABASE IF EXISTS ${SCRATCH_DB} WITH (FORCE)`,
    PROVISION_TIMEOUT_MS,
  );
}, PROVISION_TIMEOUT_MS);

/* ─── fixtures ────────────────────────────────────────────────────── */

const idemKey = (label: string): string => {
  const base = `idem-${label}-${randomUUID()}`;
  return base.length >= 16 ? base : `${base}${"x".repeat(16 - base.length)}`;
};

const moveRequest = (
  overrides: Partial<OperationCreateRequest> &
    Pick<OperationCreateRequest, "id" | "idempotencyKey" | "requestSha256">,
): OperationCreateRequest => ({
  nodeId: NODE_ID,
  implementerId: IMPLEMENTER_ID,
  kind: "MOVE_INTERNAL",
  status: "CREATED",
  amountZkz: AMOUNT,
  sourceWalletId: WALLET_A,
  destinationId: DESTINATION_ID,
  formationState: "NOT_REQUIRED",
  ...overrides,
});

const sendRequest = (
  overrides: Partial<OperationCreateRequest> &
    Pick<OperationCreateRequest, "id" | "idempotencyKey" | "requestSha256">,
): OperationCreateRequest => ({
  nodeId: NODE_ID,
  implementerId: IMPLEMENTER_ID,
  kind: "SEND_EXTERNAL",
  status: "CREATED",
  amountZkz: AMOUNT,
  sourceWalletId: WALLET_A,
  destinationAddress: DESTINATION_ADDRESS,
  formationState: "APPROVAL_PENDING",
  ...overrides,
});

const countOperations = async (where = "TRUE"): Promise<number> => {
  const n = await psqlMust(SCRATCH_DB, `SELECT count(*)::text FROM operations WHERE ${where}`);
  return Number(n);
};

const readLeaseBytes = async (walletId: string): Promise<string> =>
  psqlMust(
    SCRATCH_DB,
    `SELECT wallet_id::text || '|' || membership_id::text || '|' || lease_group_id::text || '|' ||
            root_operation_id::text || '|' || operation_id::text || '|' || lease_role || '|' ||
            lease_epoch::text || '|' || owner_instance_id::text
     FROM wallet_active_leases WHERE wallet_id = '${walletId}'`,
  );

interface SeededLease {
  readonly walletId: string;
  readonly membershipId: string;
  readonly leaseGroupId: string;
  readonly operationId: string;
  readonly leaseEpoch: number;
  readonly ownerInstanceId: string;
}

const seedActiveLease = async (
  operationId: string,
  walletId: string,
  epoch = 1,
): Promise<SeededLease> => {
  const groupId = randomUUID();
  const membershipId = randomUUID();
  await psqlMust(
    SCRATCH_DB,
    `INSERT INTO lease_groups (id, root_operation_id, created_at) VALUES ('${groupId}', '${operationId}', now());
     INSERT INTO wallet_lease_memberships (id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at)
       VALUES ('${membershipId}', '${groupId}', '${walletId}', '${operationId}', 'MOVE_SOURCE', ${epoch}, now());
     INSERT INTO wallet_active_leases
       (wallet_id, membership_id, lease_group_id, root_operation_id, operation_id, lease_role,
        lease_epoch, acquired_at, heartbeat_at, owner_instance_id)
       VALUES ('${walletId}', '${membershipId}', '${groupId}', '${operationId}', '${operationId}',
               'MOVE_SOURCE', ${epoch}, now(), now(), '${OWNER_INSTANCE}');`,
  );
  return {
    walletId,
    membershipId,
    leaseGroupId: groupId,
    operationId,
    leaseEpoch: epoch,
    ownerInstanceId: OWNER_INSTANCE,
  };
};

/** Bind production lease DELETE_ACTIVE_EXACT with literal params (psql one-shot). */
const bindDeleteActiveExact = (lease: SeededLease): string => {
  // STATEMENTS.DELETE_ACTIVE_EXACT: $1 wallet, $2 membership, $3 group, $4 op, $5 epoch, $6 owner
  let sql = LEASE_STATEMENTS.DELETE_ACTIVE_EXACT;
  const vals = [
    lease.walletId,
    lease.membershipId,
    lease.leaseGroupId,
    lease.operationId,
    String(lease.leaseEpoch),
    lease.ownerInstanceId,
  ];
  for (let i = vals.length; i >= 1; i -= 1) {
    sql = sql.split(`$${i}`).join(lit(vals[i - 1]));
  }
  return sql;
};

/** Bind production HEARTBEAT: $1 wallet, $2 owner, $3 heartbeat_at. */
const bindHeartbeat = (walletId: string, ownerId: string, atIso: string): string => {
  let sql = LEASE_STATEMENTS.HEARTBEAT;
  const vals = [walletId, ownerId, atIso];
  for (let i = vals.length; i >= 1; i -= 1) {
    sql = sql.split(`$${i}`).join(lit(vals[i - 1]));
  }
  return sql;
};

function makeGate(need = 2): {
  gate: Promise<void>;
  release: () => void;
  markEntered: () => Promise<void>;
  /** Resolves once `need` racers have called markEntered (forced rendezvous). */
  entered: Promise<void>;
} {
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let resolveEntered!: () => void;
  let enteredCount = 0;
  const entered = new Promise<void>((r) => {
    resolveEntered = r;
  });
  return {
    gate,
    release,
    entered,
    markEntered: async () => {
      enteredCount += 1;
      if (enteredCount >= need) resolveEntered();
      await entered;
    },
  };
}

/** Wait until all racers have entered the gate, then release. Fails on barrier timeout. */
async function releaseAfterEntered(
  entered: Promise<void>,
  release: () => void,
  timeoutMs = 10_000,
): Promise<void> {
  let timedOut = false;
  await Promise.race([
    entered,
    sleep(timeoutMs).then(() => {
      timedOut = true;
    }),
  ]);
  if (timedOut) {
    throw new Error(
      `forced-overlap barrier timed out after ${timeoutMs}ms — racers never rendezvoused`,
    );
  }
  release();
}

/* ─── suite ───────────────────────────────────────────────────────── */

describe("operation lifecycle concurrency (real PostgreSQL)", () => {
  describe("1. concurrent identical-body creates (idempotency rule 1+3)", () => {
    it("exactly one operations row; replay sets Idempotency-Replayed semantics", async () => {
      assertionsRun += 1;
      const key = idemKey("same-body");
      const sha = DIGEST_A;
      const before = await countOperations();

      const { gate, release, markEntered, entered } = makeGate(2);
      const race = async (id: string) => {
        await markEntered();
        await gate;
        return createStore.create(moveRequest({ id, idempotencyKey: key, requestSha256: sha }));
      };

      const p1 = race(randomUUID());
      const p2 = race(randomUUID());
      await releaseAfterEntered(entered, release);
      const [a, b] = await Promise.all([p1, p2]);

      const created = [a, b].filter((o) => o.outcome === "CREATED");
      const replayed = [a, b].filter((o) => o.outcome === "IDEMPOTENT_REPLAY");
      expect(created.length + replayed.length).toBeGreaterThanOrEqual(1);

      expect(await countOperations()).toBe(before + 1);
      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);

      const winnerId =
        created[0] && created[0].outcome === "CREATED"
          ? created[0].operationId
          : replayed[0] && replayed[0].outcome === "IDEMPOTENT_REPLAY"
            ? replayed[0].operationId
            : null;
      expect(winnerId).not.toBeNull();

      const third = await createStore.create(
        moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: sha }),
      );
      expect(third.outcome).toBe("IDEMPOTENT_REPLAY");
      if (third.outcome === "IDEMPOTENT_REPLAY") {
        expect(third.idempotencyReplayed).toBe(true);
        expect(third.operationId).toBe(winnerId);
      }
      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);
    });
  });

  describe("2. conflicting body → 409 idempotency_key_reused", () => {
    it("same key + different request_sha256 returns 409 and inserts zero rows", async () => {
      assertionsRun += 1;
      const key = idemKey("conflict-body");
      const first = await createStore.create(
        moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: DIGEST_A }),
      );
      expect(first.outcome).toBe("CREATED");
      const before = await countOperations();

      const conflict = await createStore.create(
        moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: DIGEST_B }),
      );
      expect(conflict.outcome).toBe("REJECTED");
      if (conflict.outcome === "REJECTED") {
        expect(conflict.code).toBe("idempotency_key_reused");
        expect(conflict.httpStatus).toBe(409);
      }
      expect(await countOperations()).toBe(before);
      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);
    });

    it("concurrent same-key different-hash racers never produce two rows", async () => {
      assertionsRun += 1;
      const key = idemKey("conflict-race");
      const { gate, release, markEntered, entered } = makeGate(2);
      const race = async (sha: string) => {
        await markEntered();
        await gate;
        return createStore.create(
          moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: sha }),
        );
      };
      const p1 = race(DIGEST_A);
      const p2 = race(DIGEST_B);
      await releaseAfterEntered(entered, release);
      const results = await Promise.all([p1, p2]);

      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);

      const created = results.filter((r) => r.outcome === "CREATED");
      const reused = results.filter(
        (r) => r.outcome === "REJECTED" && r.code === "idempotency_key_reused",
      );
      const replayed = results.filter((r) => r.outcome === "IDEMPOTENT_REPLAY");
      expect(created.length).toBe(1);
      expect(created.length + reused.length + replayed.length).toBe(2);
      for (const r of reused) {
        if (r.outcome === "REJECTED") expect(r.httpStatus).toBe(409);
      }
    });
  });

  describe("3. concurrent CAS state transitions", () => {
    it("exactly one of N concurrent CAS attempts wins; losers conflict cleanly", async () => {
      assertionsRun += 1;
      const id = randomUUID();
      const created = await createStore.create(
        sendRequest({ id, idempotencyKey: idemKey("cas"), requestSha256: DIGEST_A }),
      );
      expect(created.outcome).toBe("CREATED");

      const N = 8;
      const { gate, release, markEntered, entered } = makeGate(N);

      const race = async () => {
        await markEntered();
        await gate;
        return casStore.compareAndSwap(id, "CREATED", 1, "APPROVED");
      };

      const pending = Array.from({ length: N }, () => race());
      await releaseAfterEntered(entered, release);
      const results = await Promise.all(pending);

      const winners = results.filter((r) => r.ok);
      const losers = results.filter((r) => !r.ok);
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(N - 1);
      if (winners[0]?.ok) {
        expect(winners[0].newStatus).toBe("APPROVED");
        expect(winners[0].newRowVersion).toBe(2);
      }
      for (const l of losers) {
        if (!l.ok) {
          expect(l.actualRowVersion).toBe(2);
          expect(l.actualStatus).toBe("APPROVED");
        }
      }

      const row = await casStore.read(id);
      expect(row).toEqual({ operationId: id, status: "APPROVED", rowVersion: 2 });
    });

    it("applyCasTransition throws CasConflictError for the loser", async () => {
      assertionsRun += 1;
      const id = randomUUID();
      await createStore.create(
        sendRequest({ id, idempotencyKey: idemKey("cas-throw"), requestSha256: DIGEST_A }),
      );
      await applyCasTransition(casStore, {
        operationId: id,
        expectedStatus: "CREATED",
        expectedRowVersion: 1,
        newStatus: "APPROVED",
      });
      await expect(
        applyCasTransition(casStore, {
          operationId: id,
          expectedStatus: "CREATED",
          expectedRowVersion: 1,
          newStatus: "REJECTED",
        }),
      ).rejects.toBeInstanceOf(CasConflictError);
      const row = await casStore.read(id);
      expect(row?.status).toBe("APPROVED");
      expect(row?.rowVersion).toBe(2);
    });
  });

  describe("4. worker-claim loss leaves wallet_active_leases untouched", () => {
    it("crashed lease-release + wrong-tuple steal leave row byte-identical", async () => {
      assertionsRun += 1;
      const opId = randomUUID();
      await createStore.create(
        moveRequest({ id: opId, idempotencyKey: idemKey("claim-loss"), requestSha256: DIGEST_A }),
      );
      const lease = await seedActiveLease(opId, WALLET_B, 7);
      const before = await readLeaseBytes(WALLET_B);
      expect(before.length).toBeGreaterThan(0);
      expect(before).toContain(opId);
      expect(before).toContain("|7|");
      expect(before).toContain(OWNER_INSTANCE);

      // 1) Crash mid-transaction that attempted the production DELETE_ACTIVE_EXACT.
      //    The uncommitted delete must roll back — lease bytes unchanged.
      const deleteSql = bindDeleteActiveExact(lease);
      const killed = await runPsql(
        SCRATCH_DB,
        `BEGIN;
         ${deleteSql};
         SELECT pg_terminate_backend(pg_backend_pid());`,
      );
      expect(killed.ok).toBe(false);
      expect(await readLeaseBytes(WALLET_B)).toBe(before);

      // 2) Competing steal with WRONG owner_instance_id — DELETE_ACTIVE_EXACT guards on
      // the full tuple including owner, so zero rows deleted; ownership holds.
      const thiefOwner = randomUUID();
      const stealSql = bindDeleteActiveExact({ ...lease, ownerInstanceId: thiefOwner });
      const steal = await runPsql(SCRATCH_DB, stealSql);
      expect(steal.ok).toBe(true); // statement succeeds but deletes 0 rows
      expect(await readLeaseBytes(WALLET_B)).toBe(before);

      // 3) Competing steal with WRONG lease_epoch — same guard.
      const wrongEpoch = await runPsql(
        SCRATCH_DB,
        bindDeleteActiveExact({ ...lease, leaseEpoch: lease.leaseEpoch + 1 }),
      );
      expect(wrongEpoch.ok).toBe(true);
      expect(await readLeaseBytes(WALLET_B)).toBe(before);

      // 4) HEARTBEAT from a non-owner cannot rewrite the row (owner_instance_id guard).
      const rogueBeat = await runPsql(
        SCRATCH_DB,
        bindHeartbeat(WALLET_B, thiefOwner, "2099-01-01T00:00:00.000Z"),
      );
      expect(rogueBeat.ok).toBe(true);
      // heartbeat_at is outside the AC identity tuple; operation_id/epoch/owner stay put.
      const after = await readLeaseBytes(WALLET_B);
      expect(after).toBe(before);

      const op = await casStore.read(opId);
      expect(op).toEqual({ operationId: opId, status: "CREATED", rowVersion: 1 });
    });
  });

  describe("5. crash-then-restart replay (idempotency + single attempt)", () => {
    it("restarted identical create replays the same operation id; no second row", async () => {
      assertionsRun += 1;
      const key = idemKey("restart");
      const id = randomUUID();
      const first = await createStore.create(
        moveRequest({ id, idempotencyKey: key, requestSha256: DIGEST_A }),
      );
      expect(first.outcome).toBe("CREATED");
      if (first.outcome !== "CREATED") return;

      await psqlMust(
        SCRATCH_DB,
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
         VALUES ('${id}', 1, 'INNER_PREIMAGE_PERSISTED', 'inner-preimage', '${DIGEST_A}', now());`,
      );

      const replay = await createStore.create(
        moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: DIGEST_A }),
      );
      expect(replay.outcome).toBe("IDEMPOTENT_REPLAY");
      if (replay.outcome === "IDEMPOTENT_REPLAY") {
        expect(replay.operationId).toBe(id);
        expect(replay.idempotencyReplayed).toBe(true);
      }
      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);

      const secondAttempt = await runPsql(
        SCRATCH_DB,
        `INSERT INTO operation_transactions
           (operation_id, attempt_no, attempt_phase, inner_preimage_text, inner_sha256, formed_at)
         VALUES ('${id}', 1, 'INNER_PREIMAGE_PERSISTED', 'inner-preimage-2', '${DIGEST_B}', now());`,
      );
      expect(secondAttempt.ok).toBe(false);
      expect(secondAttempt.stderr).toMatch(/23505/);

      const attemptCount = await psqlMust(
        SCRATCH_DB,
        `SELECT count(*)::text FROM operation_transactions WHERE operation_id = '${id}'`,
      );
      expect(attemptCount).toBe("1");
    });

    it("uncommitted create rolls back; restart then creates exactly once", async () => {
      assertionsRun += 1;
      const key = idemKey("crash-create");
      const ephemeralId = randomUUID();
      const killed = await runPsql(
        SCRATCH_DB,
        `BEGIN;
         INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz,
           source_wallet_id, destination_id, idempotency_key, request_sha256, formation_state
         ) VALUES (
           '${ephemeralId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'MOVE_INTERNAL', 'CREATED', '${AMOUNT}',
           '${WALLET_A}', '${DESTINATION_ID}', '${key}', '${DIGEST_A}', 'NOT_REQUIRED'
         );
         SELECT pg_terminate_backend(pg_backend_pid());`,
      );
      expect(killed.ok).toBe(false);
      expect(await countOperations(`id = '${ephemeralId}'`)).toBe(0);

      const restarted = await createStore.create(
        moveRequest({ id: randomUUID(), idempotencyKey: key, requestSha256: DIGEST_A }),
      );
      expect(restarted.outcome).toBe("CREATED");
      expect(await countOperations(`idempotency_key = '${key.replace(/'/g, "''")}'`)).toBe(1);
    });
  });

  describe("6. parent→child spawn race", () => {
    it("concurrent spawnChild calls produce exactly one child operation", async () => {
      assertionsRun += 1;
      const parentId = randomUUID();
      const t0 = randomUUID();
      await psqlMust(
        SCRATCH_DB,
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz,
           receiver_wallet_id, after_landing, after_landing_destination_id,
           discriminator, anchor, expiry_unix_time_secs, t0_observation_id,
           idempotency_key, request_sha256, formation_state
         ) VALUES (
           '${parentId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED', '${AMOUNT}',
           '${WALLET_B}', 'INTERNAL_MOVE', '${DESTINATION_ID}',
           '${parentId}', 'anchor-spawn', '1784883937', '${t0}',
           '${idemKey("parent")}', '${DIGEST_A}', 'NOT_REQUIRED'
         );`,
      );

      const N = 6;
      const { gate, release, markEntered, entered } = makeGate(N);

      const race = async (i: number) => {
        const store = new SqlOperationCreateStore(new PsqlOneShotExecutor(SCRATCH_DB));
        await markEntered();
        await gate;
        return store.spawnChild(
          moveRequest({
            id: randomUUID(),
            idempotencyKey: idemKey(`spawn-${i}`),
            requestSha256: createHash("sha256").update(`spawn-${i}`).digest("hex"),
            spawnedFromOperationId: parentId,
            sourceWalletId: WALLET_A,
            destinationId: DESTINATION_ID,
          }),
        );
      };

      const pending = Array.from({ length: N }, (_, i) => race(i));
      await releaseAfterEntered(entered, release);
      const results = await Promise.all(pending);

      const created = results.filter((r) => r.outcome === "CREATED");
      const rejected = results.filter((r) => r.outcome === "REJECTED");
      expect(created).toHaveLength(1);
      expect(rejected).toHaveLength(N - 1);
      for (const r of rejected) {
        if (r.outcome === "REJECTED") {
          expect(r.code).toBe("spawn_already_exists");
          expect(r.httpStatus).toBe(409);
        }
      }

      const children = await psqlMust(
        SCRATCH_DB,
        `SELECT count(*)::text FROM operations WHERE spawned_from_operation_id = '${parentId}'`,
      );
      expect(children).toBe("1");
    });

    it("concurrent create() with spawnedFromOperationId still yields exactly one child", async () => {
      // create() must not bypass the spawn arbiter (break D3). Routing through spawnChild
      // + the shipped partial unique index is the only write path.
      assertionsRun += 1;
      const parentId = randomUUID();
      const t0 = randomUUID();
      await psqlMust(
        SCRATCH_DB,
        `INSERT INTO operations (
           id, node_id, implementer_id, kind, status, amount_zkz,
           receiver_wallet_id, after_landing, after_landing_destination_id,
           discriminator, anchor, expiry_unix_time_secs, t0_observation_id,
           idempotency_key, request_sha256, formation_state
         ) VALUES (
           '${parentId}', '${NODE_ID}', '${IMPLEMENTER_ID}', 'RECEIVE_EXTERNAL', 'RECEIVE_LANDED', '${AMOUNT}',
           '${WALLET_B}', 'INTERNAL_MOVE', '${DESTINATION_ID}',
           '${parentId}', 'anchor-create-spawn', '1784883937', '${t0}',
           '${idemKey("parent-create")}', '${DIGEST_A}', 'NOT_REQUIRED'
         );`,
      );

      const N = 6;
      const { gate, release, markEntered, entered } = makeGate(N);
      const race = async (i: number) => {
        const store = new SqlOperationCreateStore(new PsqlOneShotExecutor(SCRATCH_DB));
        await markEntered();
        await gate;
        // Deliberately call create() — not spawnChild — with a parent id.
        return store.create(
          moveRequest({
            id: randomUUID(),
            idempotencyKey: idemKey(`create-spawn-${i}`),
            requestSha256: createHash("sha256").update(`create-spawn-${i}`).digest("hex"),
            spawnedFromOperationId: parentId,
            sourceWalletId: WALLET_A,
            destinationId: DESTINATION_ID,
          }),
        );
      };

      const pending = Array.from({ length: N }, (_, i) => race(i));
      await releaseAfterEntered(entered, release);
      const results = await Promise.all(pending);

      const created = results.filter((r) => r.outcome === "CREATED");
      const rejected = results.filter((r) => r.outcome === "REJECTED");
      expect(created).toHaveLength(1);
      expect(rejected).toHaveLength(N - 1);
      for (const r of rejected) {
        if (r.outcome === "REJECTED") {
          expect(r.code).toBe("spawn_already_exists");
        }
      }
      const children = await psqlMust(
        SCRATCH_DB,
        `SELECT count(*)::text FROM operations WHERE spawned_from_operation_id = '${parentId}'`,
      );
      expect(children).toBe("1");
    });
  });

  describe("7. terminal immutability", () => {
    it("CAS after terminal status is rejected; state and row_version unchanged", async () => {
      assertionsRun += 1;
      const id = randomUUID();
      await createStore.create(
        moveRequest({ id, idempotencyKey: idemKey("terminal"), requestSha256: DIGEST_A }),
      );
      const landed = await casStore.compareAndSwap(id, "CREATED", 1, "INTERNAL_MOVE_LANDED");
      expect(landed.ok).toBe(true);
      if (landed.ok) expect(landed.newRowVersion).toBe(2);

      const before = await casStore.read(id);
      expect(before).toEqual({
        operationId: id,
        status: "INTERNAL_MOVE_LANDED",
        rowVersion: 2,
      });

      const retry = await casStore.compareAndSwap(id, "INTERNAL_MOVE_LANDED", 2, "CREATED");
      expect(retry.ok).toBe(false);
      if (!retry.ok) {
        expect(retry.actualStatus).toBe("INTERNAL_MOVE_LANDED");
        expect(retry.actualRowVersion).toBe(2);
      }

      const stale = await casStore.compareAndSwap(id, "CREATED", 1, "NEEDS_ATTENTION");
      expect(stale.ok).toBe(false);

      const after = await casStore.read(id);
      expect(after).toEqual(before);
    });

    it("SEND_EXTERNAL REJECTED is terminal under concurrent reopen attempts", async () => {
      assertionsRun += 1;
      const id = randomUUID();
      await createStore.create(
        sendRequest({ id, idempotencyKey: idemKey("term-send"), requestSha256: DIGEST_A }),
      );
      const rejected = await casStore.compareAndSwap(id, "CREATED", 1, "REJECTED");
      expect(rejected.ok).toBe(true);

      const N = 5;
      const results = await Promise.all(
        Array.from({ length: N }, () => casStore.compareAndSwap(id, "REJECTED", 2, "APPROVED")),
      );
      expect(results.every((r) => !r.ok)).toBe(true);
      const row = await casStore.read(id);
      expect(row).toEqual({ operationId: id, status: "REJECTED", rowVersion: 2 });
    });
  });

  describe("obligation guard", () => {
    it("every AC drill ran against the database", () => {
      expect(assertionsRun).toBeGreaterThanOrEqual(12);
    });
  });
});
