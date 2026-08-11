/**
 * receive-admission-pg.test.ts
 *
 * Proves, against a REAL PostgreSQL database running the REAL frozen
 * DDL (src/schema/receive-admission.sql, applied after its prerequisite
 * custody-eligibility.sql), that the two money-path invariants this slice exists to
 * guarantee are enforced BY THE DATABASE and cannot be satisfied by an in-memory fake:
 *
 * 1. Idempotency — a second row carrying the same
 *      (implementer_id, http_method, route, idempotency_key) tuple is rejected with
 *      unique_violation (SQLSTATE 23505) on receive_operations_idempotency_scope. This is
 *      the concurrency arbiter for concurrent first use of one key.
 *   2. The one-in-flight-per-wallet rule — a second UNSETTLED receive naming the same wallet is rejected with
 *      unique_violation (23505) on the partial unique indexes. A terminal predecessor does
 *      NOT block a fresh receive, proving the partial predicate is a real state test rather
 *      than a blanket uniqueness.
 *
 * Load-bearing detail: the arbiter drills run the store's OWN statement text
 * (SqlReceiveAdmissionStore's STATEMENTS.INSERT_IN_PROGRESS) through PostgreSQL PREPARE /
 * EXECUTE, not a hand-written mirror. PREPARE resolves `ON CONFLICT ON CONSTRAINT
 * receive_operations_idempotency_scope` against the live catalog, so a renamed or missing
 * constraint fails here rather than silently degrading to a swallowed conflict. It also
 * proves the ON CONFLICT clause is narrowly targeted: it absorbs the idempotency constraint
 * and does NOT absorb the one-in-flight-per-wallet indexes, whose 23505 still propagates.
 *
 * Harness: this file provisions its OWN hermetic scratch database named for this suite
 * (nothing outside the receive_admission_pg_receive_admission_ prefix is created or dropped — the server
 * is shared), applies the real DDL, runs the drills, and drops only that database. It is the
 * same shape as test/custody-eligibility-lease-pk.test.ts, deliberately: psql runs as a child
 * process, which keeps the in-process network-containment guard intact, and the
 * fail-closed guard at the bottom turns an undischarged obligation into a hard FAILURE
 * whenever PostgreSQL is reachable, so this can never silently skip itself into a no-op.
 *
 * PG_REQUIRED race guard: mirrors custody-eligibility-lease-pk.test.ts. scripts/verify-local.sh
 * exports PG_REQUIRED=1 to child processes ONLY after its own probe found Postgres reachable,
 * so PG_REQUIRED=1 with an unusable database is a race / broken gate and fails hard, never
 * skips.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  admitReceiveExternal,
  type ReceiveAdmissionOutcome,
  type ReceiveRequest,
} from "../src/receive/admission.js";
import { RECEIVE_ADMISSION_LOCK_KEY } from "../src/receive/pool-allocator.js";
import { STATEMENTS, SqlReceiveAdmissionStore } from "../src/receive/sql-store.js";
import { PsqlSessionExecutor } from "./psql-harness.js";

/* ─── constants ───────────────────────────────────────────────────── */

const MAINTENANCE_DB = "postgres";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";
const IDEMPOTENCY_CONSTRAINT = "receive_operations_idempotency_scope";
const DESTINATION_INDEX = "receive_operations_one_unsettled_per_destination";
const RECEIVER_INDEX = "receive_operations_one_unsettled_per_wallet";
const AMOUNT_DOMAIN_CONSTRAINT = "receive_operations_amount_positive";
// 7 original structural drills + locked-CTE shape + concurrent queue-cap race.
const EXPECTED_DRILL_COUNT = 9;

/* ─── psql helpers (same shape as custody-eligibility-lease-pk.test.ts) ─── */

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string, verbose = false): PsqlOutcome => {
  const args = ["-d", db, "-v", "ON_ERROR_STOP=1"];
  if (verbose) {
    args.push("-v", "VERBOSITY=verbose");
  }
  args.push("-qAt", "-c", sql);
  try {
    const stdout = execFileSync("psql", args, {
      encoding: "utf-8",
      timeout: 15_000,
      // The drills provoke intentional constraint violations; their psql ERROR output is
      // asserted on, not console noise.
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

// Setup/seed statements MUST succeed; a failure here is a real error and is thrown, never
// swallowed into a green run that tested nothing.
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
      timeout: 30_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`receive-admission DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;

const extractSqlstate = (stderr: string): string => {
  const m = /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr);
  return m === null ? "" : m[1];
};

const extractConstraint = (stderr: string): string => {
  const m = /CONSTRAINT NAME:\s+(\S+)/.exec(stderr);
  return m === null ? "" : m[1];
};

/* ─── real frozen DDL, in prerequisite sequence ───────────────────── */

// custody-eligibility.sql declares wallets and destinations; receive-admission.sql foreign-keys
// into both. An FK needs its target relation to exist EARLIER in the sequence, so the
// arrangement below is the contract, not a convenience.
// Custody is prerequisite-bound (base enums/domains + nodes).
const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const CUSTODY_DDL = readSchema("custody-eligibility.sql");
const RECEIVE_DDL = readSchema("receive-admission.sql");
/** subscription_handles only (sha256_hex already from base-enums-domains). */
const SUBSCRIPTION_HANDLES_DDL = ((): string => {
  const raw = readSchema("session-subscription-stores.sql");
  const start = raw.indexOf("CREATE TABLE subscription_handles");
  const end = raw.indexOf("CREATE TABLE admin_sessions");
  if (start < 0 || end < 0) {
    throw new Error("session-subscription-stores.sql: subscription_handles block not found");
  }
  return raw.slice(start, end);
})();

/* ─── fixtures ────────────────────────────────────────────────────── */

const NODE_ID = "c0000000-0000-4000-8000-000000000001";
const IMPLEMENTER_ID = "c0000000-0000-4000-8000-000000000002";
const DEVICE_KEY_ID = "c0000000-0000-4000-8000-000000000003";
const BLESSING_ARTIFACT_ID = "c0000000-0000-4000-8000-000000000004";

const DEST_WALLET = "d0000000-0000-4000-8000-000000000001";
const DEST_ID = "d0000000-0000-4000-8000-000000000002";
const RECEIVER_WALLET = "d0000000-0000-4000-8000-000000000003";
const RECOVERY_ID = "d0000000-0000-4000-8000-000000000004";
const RECOVERY_ID_2 = "d0000000-0000-4000-8000-000000000005";

const SHA_A = "a".repeat(64);

// public_key is padded_base64url_pubkey; export_sha256 is sha256_hex.
const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const seedNode = (): string =>
  `INSERT INTO nodes (id, display_name, identity_public_key) ` +
  `VALUES ('${NODE_ID}', 'receive-admission-pg-receive-admission', '${pubkey("NODE")}') ON CONFLICT (id) DO NOTHING;`;

// A node-generated, recovery-verified, AVAILABLE wallet. Recovery is stamped by UPDATE
// because wallets.recovery_verification_id foreign-keys wallet_recovery_verifications, which
// itself references wallets — the verification row cannot exist before its wallet.
const seedVerifiedWallet = (walletId: string, recoveryId: string, publicKey: string): string =>
  `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
  `VALUES ('${walletId}', '${NODE_ID}', '${publicKey}', 'node_generated', 'AVAILABLE'); ` +
  `INSERT INTO wallet_recovery_verifications ` +
  `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
  `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA_A}', '${publicKey}', ` +
  `'${recoveryId}', now(), 'receive-admission-pg-test'); ` +
  `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
  `WHERE id = '${walletId}';`;

const seedBlessedDestination = (): string =>
  `INSERT INTO destinations ` +
  `(id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
  `VALUES ('${DEST_ID}', '${NODE_ID}', '${DEST_WALLET}', 'BLESSED', now(), '${DEVICE_KEY_ID}', '${BLESSING_ARTIFACT_ID}');`;

/* ─── the store's OWN insert statement, driven through PREPARE/EXECUTE ─── */

interface InsertArgs {
  readonly operationId: string;
  readonly idempotencyKey: string;
  readonly requestSha256?: string;
  readonly amountZkz?: string;
  readonly status?: string;
  readonly afterLandingKind?: string;
  readonly destinationWalletId?: string | null;
  readonly destinationId?: string | null;
  readonly walletId?: string | null;
}

const lit = (value: string | number | null): string =>
  value === null ? "NULL" : typeof value === "number" ? String(value) : `'${value}'`;

// PREPARE resolves ON CONFLICT ON CONSTRAINT against the live catalog, so a missing or
// renamed constraint fails the drill outright rather than degrading to a silently swallowed
// conflict. A prepared statement is session-scoped and each psql invocation is a fresh
// session, so the PREPARE ships with every EXECUTE.
const PREPARE_INSERT = `PREPARE receive_insert AS ${STATEMENTS.INSERT_IN_PROGRESS};`;

// Argument list for STATEMENTS.INSERT_IN_PROGRESS, in OPERATION_COLUMNS sequence.
const executeInsert = (args: InsertArgs): string =>
  `${PREPARE_INSERT} EXECUTE receive_insert(${[
    lit(args.operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("RECEIVE_EXTERNAL"),
    lit(args.status ?? "CREATED"),
    lit("POST"),
    lit("/v1/receives"),
    lit(args.idempotencyKey),
    lit(args.requestSha256 ?? SHA_A),
    lit(args.amountZkz ?? "1.5"),
    lit("anchor_abc-123"),
    lit(60000),
    lit(args.afterLandingKind ?? "HOLD"),
    lit(args.destinationWalletId ?? null),
    lit(args.destinationId ?? null),
    lit(args.walletId ?? null),
    lit(1700000000000),
  ].join(", ")});`;

// The same row shape written with a plain INSERT, so the constraint — not ON CONFLICT DO
// NOTHING — is the thing observed rejecting the duplicate.
const rawInsert = (args: InsertArgs): string =>
  `INSERT INTO receive_operations (operation_id, implementer_id, node_id, kind, status, http_method, route, ` +
  `idempotency_key, request_sha256, amount_zkz, anchor, ttl_ms, after_landing_kind, destination_wallet_id, ` +
  `destination_id, wallet_id, created_at) VALUES (${[
    lit(args.operationId),
    lit(IMPLEMENTER_ID),
    lit(NODE_ID),
    lit("RECEIVE_EXTERNAL"),
    lit(args.status ?? "CREATED"),
    lit("POST"),
    lit("/v1/receives"),
    lit(args.idempotencyKey),
    lit(args.requestSha256 ?? SHA_A),
    lit(args.amountZkz ?? "1.5"),
    lit("anchor_abc-123"),
    lit(60000),
    lit(args.afterLandingKind ?? "HOLD"),
    lit(args.destinationWalletId ?? null),
    lit(args.destinationId ?? null),
    lit(args.walletId ?? null),
  ].join(", ")}, now());`;

/* ─── suite ───────────────────────────────────────────────────────── */

const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const PG_AVAILABLE = pgUsable();
const describeIfPg = PG_AVAILABLE ? describe : describe.skip;

let assertionsRun = 0;

describeIfPg("receive admission — real frozen DDL against real PostgreSQL", () => {
  const scratchDb = `receive_admission_pg_receive_admission_${Date.now()}_${process.pid}`;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    // Prerequisite first: base enums/domains + nodes, then custody, then receive-admission
    // + subscription_handles (minted in the same admit TX — ZTR-1142).
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, CUSTODY_DDL);
    applyDdl(scratchDb, RECEIVE_DDL);
    applyDdl(scratchDb, SUBSCRIPTION_HANDLES_DDL);
    psqlMust(scratchDb, seedNode());
    psqlMust(scratchDb, seedVerifiedWallet(DEST_WALLET, RECOVERY_ID, pubkey("DEST")));
    psqlMust(scratchDb, seedVerifiedWallet(RECEIVER_WALLET, RECOVERY_ID_2, pubkey("RCVR")));
    psqlMust(scratchDb, seedBlessedDestination());
  });

  afterAll(() => {
    // Scoped teardown: only the database this suite created. The server is shared.
    psqlMust(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  it("rejects a duplicate idempotency scope tuple with unique_violation (23505)", () => {
    psqlMust(scratchDb, rawInsert({ operationId: "e0000000-0000-4000-8000-000000000001", idempotencyKey: "idem-key-drill-0001" }));

    // Same (implementer_id, http_method, route, idempotency_key); different operation_id.
    const duplicate = runPsql(
      scratchDb,
      rawInsert({ operationId: "e0000000-0000-4000-8000-000000000002", idempotencyKey: "idem-key-drill-0001" }),
      true,
    );

    expect(duplicate.ok, "a second row for one idempotency scope must be rejected").toBe(false);
    expect(extractSqlstate(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(duplicate.stderr)).toBe(IDEMPOTENCY_CONSTRAINT);
    assertionsRun += 1;
  });

  it("the store's own INSERT_IN_PROGRESS absorbs the idempotency conflict and creates no second row", () => {
    const first = runPsql(
      scratchDb,
      executeInsert({ operationId: "e0000000-0000-4000-8000-000000000011", idempotencyKey: "idem-key-drill-0002" }),
    );
    expect(first.ok, first.stderr).toBe(true);
    expect(first.stdout.trim()).toBe("e0000000-0000-4000-8000-000000000011");

    const follower = runPsql(
      scratchDb,
      executeInsert({ operationId: "e0000000-0000-4000-8000-000000000012", idempotencyKey: "idem-key-drill-0002" }),
    );
    // ON CONFLICT DO NOTHING: the follower returns no row, so the store reports
    // IDEMPOTENCY_CONFLICT rather than creating a second operation.
    expect(follower.ok, follower.stderr).toBe(true);
    expect(follower.stdout.trim()).toBe("");

    const count = runPsql(
      scratchDb,
      `SELECT count(*) FROM receive_operations WHERE idempotency_key = 'idem-key-drill-0002';`,
    );
    expect(count.stdout.trim()).toBe("1");
    assertionsRun += 1;
  });

  it("The one-in-flight-per-wallet rule: a second unsettled receive for one destination wallet is rejected with 23505", () => {
    psqlMust(
      scratchDb,
      rawInsert({
        operationId: "e0000000-0000-4000-8000-000000000021",
        idempotencyKey: "idem-key-drill-0003",
        afterLandingKind: "INTERNAL_MOVE",
        destinationId: DEST_ID,
        destinationWalletId: DEST_WALLET,
      }),
    );

    // Different idempotency key, so the scope constraint cannot be what rejects it — and the
    // store's own statement is used, proving its ON CONFLICT clause does NOT swallow this.
    const second = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e0000000-0000-4000-8000-000000000022",
        idempotencyKey: "idem-key-drill-0004",
        afterLandingKind: "INTERNAL_MOVE",
        destinationId: DEST_ID,
        destinationWalletId: DEST_WALLET,
      }),
      true,
    );

    expect(second.ok, "a second in-flight receive for one wallet must be rejected").toBe(false);
    expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(second.stderr)).toBe(DESTINATION_INDEX);
    assertionsRun += 1;
  });

  it("a TERMINAL predecessor does not block a fresh receive for the same destination wallet", () => {
    // The index predicate is a real state test, not blanket uniqueness: settle the holder and
    // the wallet becomes admissible again.
    psqlMust(
      scratchDb,
      `UPDATE receive_operations SET status = 'EXPIRED' WHERE operation_id = 'e0000000-0000-4000-8000-000000000021';`,
    );

    const fresh = runPsql(
      scratchDb,
      executeInsert({
        operationId: "e0000000-0000-4000-8000-000000000023",
        idempotencyKey: "idem-key-drill-0005",
        afterLandingKind: "INTERNAL_MOVE",
        destinationId: DEST_ID,
        destinationWalletId: DEST_WALLET,
      }),
    );
    expect(fresh.ok, fresh.stderr).toBe(true);
    expect(fresh.stdout.trim()).toBe("e0000000-0000-4000-8000-000000000023");
    assertionsRun += 1;
  });

  it("The one-in-flight-per-wallet rule: a second unsettled receive for one RECEIVER wallet is rejected with 23505", () => {
    // wallet_id is only representable once the receive leaves CREATED (the
    // no-receiver-while-created CHECK), so the drill uses the assigned READY state.
    psqlMust(
      scratchDb,
      rawInsert({
        operationId: "e0000000-0000-4000-8000-000000000031",
        idempotencyKey: "idem-key-drill-0006",
        status: "READY",
        walletId: RECEIVER_WALLET,
      }),
    );

    const second = runPsql(
      scratchDb,
      rawInsert({
        operationId: "e0000000-0000-4000-8000-000000000032",
        idempotencyKey: "idem-key-drill-0007",
        status: "READY",
        walletId: RECEIVER_WALLET,
      }),
      true,
    );

    expect(second.ok, "a second in-flight receive for one receiver wallet must be rejected").toBe(false);
    expect(extractSqlstate(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(extractConstraint(second.stderr)).toBe(RECEIVER_INDEX);
    assertionsRun += 1;
  });

  it("a mathematically zero amount is rejected by the amount CHECK (23514)", () => {
    // '0.00' matches the canonical-decimal regex and is <> '0' as a string. Only NUMERIC
    // positivity rejects it, and it is rejected at rest, not merely by the app validator.
    const zero = runPsql(
      scratchDb,
      rawInsert({
        operationId: "e0000000-0000-4000-8000-000000000041",
        idempotencyKey: "idem-key-drill-0008",
        amountZkz: "0.00",
      }),
      true,
    );

    expect(zero.ok, "a mathematically zero amount_zkz must be rejected by the database").toBe(false);
    expect(extractSqlstate(zero.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(extractConstraint(zero.stderr)).toBe(AMOUNT_DOMAIN_CONSTRAINT);
    assertionsRun += 1;
  });

  it("COUNT_QUEUED counts only this node's unassigned CREATED receives", () => {
    // The store's OWN depth statement — PREPARE resolves the column/predicate against the live
    // catalog so a renamed column or widened WHERE would fail the drill, not silently lie.
    const depth = runPsql(
      scratchDb,
      `PREPARE receive_count AS ${STATEMENTS.COUNT_QUEUED}; EXECUTE receive_count('${NODE_ID}');`,
    );
    expect(depth.ok, depth.stderr).toBe(true);
    // Unassigned CREATED rows seeded above: drill-0001, drill-0002, drill-0005 (EXPIRED and
    // READY rows do not count; neither does a row with a non-null wallet_id).
    const unassignedCreated = runPsql(
      scratchDb,
      `SELECT count(*)::int FROM receive_operations WHERE node_id = '${NODE_ID}' AND status = 'CREATED' AND wallet_id IS NULL;`,
    );
    expect(depth.stdout.trim()).toBe(unassignedCreated.stdout.trim());
    expect(Number(depth.stdout.trim())).toBeGreaterThan(0);
    assertionsRun += 1;
  });

  it("LOCK_ADMISSION_QUEUE uses the shared pool-allocator advisory-lock key", () => {
    // Without the lock the count-then-insert window is TOCTOU (review D-B1). Same key as
    // pool-allocator admitReceive so dual entry points serialise together once composition
    // unifies tables.
    expect(STATEMENTS.LOCK_ADMISSION_QUEUE).toContain("pg_advisory_xact_lock");
    expect(RECEIVE_ADMISSION_LOCK_KEY).toBe(2640551);
    assertionsRun += 1;
  });

  it(
    "concurrent first-use admits: depth never exceeds cap (hard, not soft)",
    async () => {
      // Clear any prior unassigned CREATED rows so this drill starts from depth 0.
      psqlMust(
        scratchDb,
        `UPDATE receive_operations SET status = 'EXPIRED' WHERE status = 'CREATED' AND wallet_id IS NULL;`,
      );
      const baseline = runPsql(
        scratchDb,
        `SELECT count(*)::int FROM receive_operations WHERE node_id = '${NODE_ID}' AND status = 'CREATED' AND wallet_id IS NULL;`,
      );
      expect(baseline.stdout.trim()).toBe("0");

      // Cap=1, eight distinct-key first-use admits from eight OS-level psql sessions. Each
      // session owns a real BEGIN/COMMIT so pg_advisory_xact_lock spans lock→count→insert.
      // Without the lock every contender observes depth=0 and all eight insert. With the lock
      // exactly one ADMITTED and seven receive_queue_full; final depth is 1.
      const CAP = 1;
      const N = 8;
      // Peer-auth local URL — same socket path the suite's plain `psql -d` uses.
      const dbUrl = `postgresql:///${scratchDb}`;
      const sessions = Array.from({ length: N }, () => new PsqlSessionExecutor(dbUrl));
      for (const s of sessions) s.start();

      let outcomes: ReceiveAdmissionOutcome[];
      try {
        outcomes = await Promise.all(
          sessions.map(async (session, i) => {
            // One TX per admit: lock is transaction-scoped and released on COMMIT/ROLLBACK.
            // Committing QUEUE_FULL refusals is load-bearing — rolling them back would hide an
            // insert-then-refuse defect (same posture as pool-race S2).
            const store = new SqlReceiveAdmissionStore(session, {
              withTransaction: async (fn) => {
                await session.begin();
                try {
                  const result = await fn(session);
                  await session.commit();
                  return result;
                } catch (err) {
                  await session.rollback();
                  throw err;
                }
              },
            });
            const request: ReceiveRequest = {
              implementerId: IMPLEMENTER_ID,
              nodeId: NODE_ID,
              amountZkz: "1.5",
              anchor: "anchor_race-cap",
              ttlMs: 60_000,
              afterLanding: { kind: "HOLD" },
              // 16+ visible ASCII; distinct per contender so idempotency cannot collapse them.
              idempotencyKey: `race-cap-key-${i.toString().padStart(4, "0")}`,
            };
            return admitReceiveExternal(store, request, {
              queueCap: CAP,
              generateId: () => `f0000000-0000-4000-8000-${i.toString().padStart(12, "0")}`,
              now: () => 1_700_000_000_000 + i,
            });
          }),
        );
      } finally {
        for (const s of sessions) s.stop();
      }

      const admitted = outcomes.filter((o) => o.outcome === "ADMITTED");
      const full = outcomes.filter(
        (o) => o.outcome === "REJECTED" && o.code === "receive_queue_full",
      );
      expect(admitted, "exactly one contender must win the single queue slot").toHaveLength(CAP);
      expect(full, "every other contender must see receive_queue_full").toHaveLength(N - CAP);

      const depth = runPsql(
        scratchDb,
        `SELECT count(*)::int FROM receive_operations WHERE node_id = '${NODE_ID}' AND status = 'CREATED' AND wallet_id IS NULL;`,
      );
      expect(depth.ok, depth.stderr).toBe(true);
      expect(
        Number(depth.stdout.trim()),
        "queue depth must never exceed RECEIVE_QUEUE_CAP under concurrent first-use admits",
      ).toBe(CAP);

      // No refused candidate id may appear — INSERT never ran for them (create nothing).
      for (let i = 0; i < N; i++) {
        const id = `f0000000-0000-4000-8000-${i.toString().padStart(12, "0")}`;
        const won = admitted.some(
          (o) => o.outcome === "ADMITTED" && o.operation.operationId === id,
        );
        const present = runPsql(
          scratchDb,
          `SELECT count(*)::int FROM receive_operations WHERE operation_id = '${id}';`,
        );
        expect(present.stdout.trim()).toBe(won ? "1" : "0");
      }
      assertionsRun += 1;
    },
    60_000,
  );
});

/* ─── fail-closed obligation guard ────────────────────────────────────
 * Top-level (OUTSIDE the pg-gated describe) so it runs even when the suite is skipped, and
 * mirrors the guard in custody-eligibility-lease-pk.test.ts. Three cases, none of which can
 * silently pass having tested nothing:
 *   1. PG unusable AND PG_REQUIRED=1 → HARD FAILURE (race / broken gate, not absent Postgres).
 *   2. PG unusable AND PG_REQUIRED unset → Postgres is genuinely optional for a standalone
 *      run outside the canonical pipeline; verify-local.sh's own VERIFY_REQUIRE_PG step
 *      independently fails the whole run in that case.
 *   3. PG usable → the drills MUST have executed, else the obligation is undischarged
 *      and this fails hard. A green suite that never opened a connection is not evidence. */
it("obligation guard: real-PG admission drills must execute (hard fail under PG_REQUIRED=1)", () => {
  if (!PG_AVAILABLE) {
    if (PG_REQUIRED) {
      throw new Error(
        `PG_REQUIRED=1 but PostgreSQL maintenance database "${MAINTENANCE_DB}" is not usable: the ` +
          "real-PG idempotency and one-in-flight-per-wallet drills could not run and the local " +
          "verification lane must not silently skip them. The outer runner exports PG_REQUIRED=1 " +
          "only after seeing a reachable Postgres, so this is a race / broken gate, not an absent " +
          "Postgres — provision the maintenance database and re-run.",
      );
    }
    return;
  }
  expect(
    assertionsRun,
    "PostgreSQL was reachable but the real-PG receive-admission drills did not run — undischarged obligation",
  ).toBe(EXPECTED_DRILL_COUNT);
});
