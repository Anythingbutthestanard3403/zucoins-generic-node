// Deterministic scale-up and pressure policy, real PostgreSQL.
//
// Covers the scaler and admission ladder steps 4–5, receive pool pressure, and pool
// sizing / backpressure / logical retirement.
//
// The asserted arithmetic is a proportional headroom TOTAL over live demand, with a cap that
// counts every wallet row including RETIRED — not a
// `POOL_TARGET_AVAILABLE - available_wallet_count` / `non_retired_pool_wallet_count` formula.
// The parity case below pins the three in-repo copies of that arithmetic to each other.
//
// Each concurrency case runs one `psql` OS process per contender, so a race is decided at the
// database transaction boundary. Every property claimed has a paired negative that shows the
// guard produces the green: the draft's non-retired count DOES mint past the cap, a plan
// computed before the advisory lock DOES double-mint, and the naive queued-receive predicate
// DOES double-count an assigned receive.
//
// Connectivity: TEST_DATABASE_URL (root vitest.global-setup) or PG_REQUIRED fail-closed.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// The frozen contract source, imported by relative path: the contracts package
// publishes no `./pool-policy` subpath, and test/boundary-rules.ts already reaches across the
// same way for FORBIDDEN_TERMS. If either copy of the arithmetic drifts, the parity case
// below fails rather than the two silently disagreeing in production.
import {
  MINT_BATCH_LIMIT as CONTRACT_MINT_BATCH_LIMIT,
  POOL_FLOOR as CONTRACT_POOL_FLOOR,
  HEADROOM_DENOMINATOR as CONTRACT_HEADROOM_DENOMINATOR,
  HEADROOM_NUMERATOR as CONTRACT_HEADROOM_NUMERATOR,
  RECEIVE_QUEUE_MAX_WAIT_MS as CONTRACT_RECEIVE_QUEUE_MAX_WAIT_MS,
} from "../../../generic-node-contracts/src/pool-policy/constants.ts";
import {
  computeMintBatch,
  computeProvisioningTarget,
} from "../../../generic-node-contracts/src/pool-policy/sizing.ts";
import { isReceiveExpired } from "../../../generic-node-contracts/src/pool-policy/queue.ts";

import {
  assertLeaseFoundationReady,
  migrateLeaseFoundation,
} from "../../src/leases/index.ts";
import {
  RECEIVE_ALLOCATOR_STATEMENTS,
  assignReceiveWallet,
  countUnassignedReceives,
} from "../../src/receive/pool-allocator.ts";
import {
  HEADROOM_DENOMINATOR,
  HEADROOM_NUMERATOR,
  MINT_BATCH_LIMIT,
  POOL_FLOOR,
  POOL_SCALER_STATEMENTS,
  PoolScalerError,
  collectPoolPressureMetrics,
  computeMintCount,
  countOpenSessions,
  expireQueueAgedReceives,
  planPoolScaleUp,
  poolTargetTotal,
  runPoolScaleUp,
  selectQueueExpiredReceives,
  type EmitOperationExpired,
  type PoolScalerLimits,
} from "../../src/receive/pool-scaler.ts";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  psqlMust,
  runPsql,
  withDatabase,
  withTx,
} from "../psql-harness.ts";
import {
  LEASES,
  MINTED,
  OP,
  OWNER,
  RESET_POOL,
  applyPoolSchema,
  countRows,
  insertReceiveOnTx,
  mintingPort,
  seedReceive,
  seedReceives,
  seedRegistry,
  seedWallets,
  walletState,
  type SeededPool,
} from "./pool-fixture.ts";

const here = dirname(fileURLToPath(import.meta.url));
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

/**
 * Pool cap for the suite. Small enough that "fill to cap" is a handful of rows, and >= POOL_FLOOR
 * so `assertLimits` accepts it. 12 seeded wallets leaves 8 units of headroom — more than one
 * MINT_BATCH_LIMIT, so the batch bound is testable without saturating the cap first.
 */
const POOL_CAP = 20;
const ELIGIBLE = 10;
const MAX_WAIT_SECS = 30;
const LIMITS: PoolScalerLimits = {
  poolCapTotal: POOL_CAP,
  receiveQueueMaxWaitSecs: MAX_WAIT_SECS,
};
/** Seeded wallet rows: eligible + one unverified + one imported. This is the cap count at rest. */
const SEEDED_TOTAL = ELIGIBLE + 2;

let dbName = "";
let dbUrl = "";
let db: PsqlExecutor;
let pool: SeededPool;

const capCount = (): number => countRows(dbUrl, "wallets");

describe("receive-pool scale-up and pressure policy (real PG / separate processes)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error(
          "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — vitest.global-setup provisioned no test database",
        );
      }
      return;
    }
    dbName = `pool_scaler_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    pool = seedWallets(dbUrl, { eligibleCount: ELIGIBLE });
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
  }, 120_000);

  afterAll(() => {
    // Scoped to this run's own database only — a broader DROP takes out concurrent lanes
    // sharing the server.
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

  // ── 1. Arithmetic parity with the frozen pool-policy contract ─────────────
  // (The app-config copy's parity with the same contract is asserted in
  // apps/generic-node/test/config-schema.test.ts, keeping this package free of
  // upward imports into apps/.)

  it("the node-core constants equal the frozen contract constants", () => {
    expect(POOL_FLOOR).toBe(CONTRACT_POOL_FLOOR);
    expect(MINT_BATCH_LIMIT).toBe(CONTRACT_MINT_BATCH_LIMIT);
    expect(HEADROOM_NUMERATOR).toBe(CONTRACT_HEADROOM_NUMERATOR);
    expect(HEADROOM_DENOMINATOR).toBe(CONTRACT_HEADROOM_DENOMINATOR);
  });

  it("poolTargetTotal agrees with the frozen contract over the whole domain", () => {
    for (let openSessions = 0; openSessions <= 120; openSessions += 1) {
      for (const cap of [POOL_FLOOR, 20, 50, 500]) {
        const mine = poolTargetTotal(openSessions, cap);
        expect(mine).toBe(computeProvisioningTarget(openSessions, cap));
        // The exact integer form, never the float. The float `openSessions * 1.10`
        // is wrong for openSessions where the product is not exactly representable.
        expect(mine).toBeGreaterThanOrEqual(Math.min(POOL_FLOOR, cap));
        expect(mine).toBeLessThanOrEqual(cap);
      }
    }
  });

  it("rule 3: computeMintCount agrees with the frozen computeMintBatch over the whole domain", () => {
    for (let target = 0; target <= 60; target += 1) {
      for (let capCountValue = 0; capCountValue <= 60; capCountValue += 3) {
        for (const cap of [POOL_FLOOR, 20, 50]) {
          expect(computeMintCount({ target, capCount: capCountValue, poolCapTotal: cap })).toBe(
            computeMintBatch(target, capCountValue, cap),
          );
        }
      }
    }
  });

  it("queue-age boundary is strict exceed — parity with isReceiveExpired", () => {
    // Frozen contract: waitedMs > RECEIVE_QUEUE_MAX_WAIT_MS. Equality is NOT expired and may
    // still promote (queue.ts / CONTRACT.md). Suite max-wait is the operative 30s constant.
    expect(MAX_WAIT_SECS * 1000).toBe(CONTRACT_RECEIVE_QUEUE_MAX_WAIT_MS);
    const maxWaitMs = CONTRACT_RECEIVE_QUEUE_MAX_WAIT_MS;
    // Pure boundary samples across the probe set.
    expect(isReceiveExpired(maxWaitMs - 1)).toBe(false);
    expect(isReceiveExpired(maxWaitMs)).toBe(false);
    expect(isReceiveExpired(maxWaitMs + 1)).toBe(true);
    // Age-in-seconds form used by the scaler SQL param and QueueExpiredReceive.waitedSecs:
    // expire iff waitedSecs > maxWaitSecs (never >=).
    const shouldExpireSecs = (waitedSecs: number, maxWaitSecs: number): boolean =>
      waitedSecs > maxWaitSecs;
    for (const waited of [maxWaitMs / 1000 - 1, maxWaitMs / 1000, maxWaitMs / 1000 + 1]) {
      expect(shouldExpireSecs(waited, MAX_WAIT_SECS)).toBe(isReceiveExpired(waited * 1000));
    }
    // SQL form of the same rule: created_at < now() - interval (strict), never <=.
    expect(POOL_SCALER_STATEMENTS.SELECT_QUEUE_EXPIRED_RECEIVES).toContain(
      "o.created_at < now() - make_interval(secs => $1)",
    );
    expect(POOL_SCALER_STATEMENTS.SELECT_QUEUE_EXPIRED_RECEIVES).not.toContain(
      "o.created_at <= now() - make_interval(secs => $1)",
    );
    // ZTR-1249: queue-age EXPIRE stamps terminal_at in the same UPDATE as status.
    expect(POOL_SCALER_STATEMENTS.EXPIRE_QUEUE_AGED_RECEIVE).toContain(
      "terminal_at = COALESCE(terminal_at, now())",
    );
  });

  // ── 2. The cap rule, as arithmetic ────────────────────────────────────────

  it("/ rule 2: at the cap the batch is zero however large the deficit", () => {
    // A target far above the cap is exactly the "large available_deficit" of the first
    // review indicator. Cap headroom is the binding term, and it is zero.
    expect(computeMintCount({ target: 500, capCount: POOL_CAP, poolCapTotal: POOL_CAP })).toBe(0);
    // Over-cap (an operator lowered pool_cap under a pool that already exceeded it) still never
    // returns a negative or a mint.
    expect(computeMintCount({ target: 500, capCount: POOL_CAP + 7, poolCapTotal: POOL_CAP })).toBe(
      0,
    );
  });

  it("one pass never exceeds MINT_BATCH_LIMIT even when deficit and headroom are larger", () => {
    expect(computeMintCount({ target: 500, capCount: 0, poolCapTotal: 500 })).toBe(
      MINT_BATCH_LIMIT,
    );
    expect(computeMintCount({ target: 40, capCount: 0, poolCapTotal: 50 })).toBe(MINT_BATCH_LIMIT);
  });

  it("no scaler statement can write wallets.state, so pressure has no release path", () => {
    // The structural half of the pressure contract: capacity pressure cannot
    // un-pin a wallet because this module contains no statement that could. The only mutating
    // statement is the queue-age EXPIRE on operations (step 5) — never wallets.
    for (const [name, sql] of Object.entries(POOL_SCALER_STATEMENTS)) {
      if (name === "EXPIRE_QUEUE_AGED_RECEIVE") {
        expect(sql).toMatch(/^UPDATE operations\b/i);
        expect(sql).not.toMatch(/\bwallets\b/i);
        continue;
      }
      expect(`${name}:${sql}`).not.toMatch(/\b(INSERT|UPDATE|DELETE|TRUNCATE)\b/i);
    }
    // And the source itself carries no wallet-state write, however spelled.
    const source = readFileSync(resolve(here, "../../src/receive/pool-scaler.ts"), "utf8");
    expect(source).not.toMatch(/UPDATE\s+wallets/i);
    expect(source).not.toMatch(/SET\s+state\s*=/i);
  });

  it("rejects a pool cap below POOL_FLOOR and a non-positive max wait", async () => {
    await expect(
      planPoolScaleUp({ query: async () => ({ rows: [] }) }, { ...LIMITS, poolCapTotal: 4 }),
    ).rejects.toBeInstanceOf(PoolScalerError);
    await expect(
      planPoolScaleUp(
        { query: async () => ({ rows: [] }) },
        { ...LIMITS, receiveQueueMaxWaitSecs: 0 },
      ),
    ).rejects.toBeInstanceOf(PoolScalerError);
  });

  // ── 3. The cap count, against a live pool ─────────────────────────────────

  it.skipIf(!live)(
    "rule 2: the cap count includes PINNED, QUARANTINED and RETIRED wallets",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'PINNED' WHERE id = '${pool.eligible[0]}';
         UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'unexpected head movement'
          WHERE id = '${pool.eligible[1]}';
         UPDATE wallets SET state = 'RETIRED', retired_at = now()
          WHERE id = '${pool.eligible[2]}';`,
      );

      const counted = Number(
        (await db.query<{ cap_count: number }>(POOL_SCALER_STATEMENTS.COUNT_CAP_UNDER_LOCK)).rows[0]
          ?.cap_count,
      );
      expect(counted).toBe(SEEDED_TOTAL);

      // Negative control: the v2 draft's `non_retired_pool_wallet_count` — the count
      // reversed — reports fewer wallets, which is precisely the arithmetic that mints past the
      // real cap once retirement is in play.
      const draft = Number(
        psqlMust(dbUrl, `SELECT count(*)::int FROM wallets WHERE state <> 'RETIRED';`).trim(),
      );
      expect(draft).toBe(SEEDED_TOTAL - 1);
      expect(draft).toBeLessThan(counted);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "a pool pinned to the cap mints nothing however deep the queue",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Fill to the cap with wallets that are all PINNED — the "pinned-wallet pressure is high"
      // state of then pile up demand.
      const filler = Array.from({ length: POOL_CAP - SEEDED_TOTAL }, (_v, i) => MINTED(900 + i));
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ${filler
             .map(
               (id, i) =>
                 `('${id}', (SELECT node_id FROM wallets LIMIT 1), '${"A".repeat(38)}FIL${String(i).padStart(2, "0")}=', 'node_generated', 'AVAILABLE')`,
             )
             .join(",")};
         UPDATE wallets SET state = 'PINNED' WHERE state = 'AVAILABLE';`,
      );
      seedReceives(
        dbUrl,
        Array.from({ length: 15 }, (_v, i) => ({ operationId: OP(400 + i) })),
      );

      expect(capCount()).toBe(POOL_CAP);
      const plan = await withTx(dbUrl, (tx) => planPoolScaleUp(tx, LIMITS));

      // Demand is high and the target is pinned at the cap, but headroom is zero.
      expect(plan.openSessions).toBe(15);
      expect(plan.capCount).toBe(POOL_CAP);
      expect(plan.poolTargetTotal).toBe(poolTargetTotal(15, POOL_CAP));
      expect(plan.mintCount).toBe(0);

      // Negative control: recomputing with the draft's non-retired-style count — here, "only
      // wallets that are not pinned" — DOES authorise a mint, and would take the pool past cap.
      const nonPinned = Number(
        psqlMust(dbUrl, `SELECT count(*)::int FROM wallets WHERE state <> 'PINNED';`).trim(),
      );
      expect(
        computeMintCount({
          target: plan.poolTargetTotal,
          capCount: nonPinned,
          poolCapTotal: POOL_CAP,
        }),
      ).toBeGreaterThan(0);

      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
      expect(capCount()).toBe(SEEDED_TOTAL);
    },
    90_000,
  );

  // ── 4. A live scaling pass ────────────────────────────────────────────────

  it.skipIf(!live)(
    "one pass mints at most MINT_BATCH_LIMIT wallets and never crosses the cap",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Demand well above the batch limit and headroom well above it too.
      seedReceives(
        dbUrl,
        Array.from({ length: 18 }, (_v, i) => ({ operationId: OP(500 + i) })),
      );
      const port = mintingPort(1);

      const first = await withTx(dbUrl, (tx) =>
        runPoolScaleUp(tx, { limits: LIMITS, mint: port.mint }),
      );
      expect(first.plan.mintCount).toBe(MINT_BATCH_LIMIT);
      expect(first.mintedWalletIds).toHaveLength(MINT_BATCH_LIMIT);
      expect(capCount()).toBe(SEEDED_TOTAL + MINT_BATCH_LIMIT);

      // A minted wallet is born recovery-UNVERIFIED, so it counts against the cap and is
      // NOT yet allocatable. Minting cannot close an AVAILABLE deficit — only the ceremony can.
      const availableAfter = Number(
        (
          await db.query<{ available_count: number }>(
            POOL_SCALER_STATEMENTS.COUNT_AVAILABLE_WALLETS,
          )
        ).rows[0]?.available_count,
      );
      expect(availableAfter).toBe(ELIGIBLE);

      // Successive passes converge on the cap and stop there rather than overshooting.
      for (let pass = 0; pass < 5; pass += 1) {
        await withTx(dbUrl, (tx) => runPoolScaleUp(tx, { limits: LIMITS, mint: port.mint }));
        expect(capCount()).toBeLessThanOrEqual(POOL_CAP);
      }
      expect(capCount()).toBe(POOL_CAP);

      const settled = await withTx(dbUrl, (tx) => planPoolScaleUp(tx, LIMITS));
      expect(settled.mintCount).toBe(0);

      psqlMust(dbUrl, RESET_POOL);
      expect(capCount()).toBe(SEEDED_TOTAL);
    },
    120_000,
  );

  it.skipIf(!live)(
    "a failure mid-batch persists no wallet, and the retry mints the batch exactly once",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      seedReceives(
        dbUrl,
        Array.from({ length: 18 }, (_v, i) => ({ operationId: OP(600 + i) })),
      );
      const before = capCount();

      // Crash the process mid-batch: the mint port throws on its third call, exactly the way a
      // deploy or an OOM would interrupt the pass.
      const crashing = mintingPort(100);
      await expect(
        withTx(dbUrl, (tx) =>
          runPoolScaleUp(tx, {
            limits: LIMITS,
            mint: async (sql, index) => {
              if (index === 2) throw new Error("injected mid-batch crash");
              return crashing.mint(sql, index);
            },
          }),
        ),
      ).rejects.toThrow(/injected mid-batch crash/);

      // Nothing survives — the batch is one transaction, so there is no partial mint to resume
      // and no duplicate to reconcile.
      expect(capCount()).toBe(before);

      const retry = await withTx(dbUrl, (tx) =>
        runPoolScaleUp(tx, { limits: LIMITS, mint: mintingPort(200).mint }),
      );
      expect(retry.plan.mintCount).toBe(MINT_BATCH_LIMIT);
      expect(retry.mintedWalletIds).toHaveLength(MINT_BATCH_LIMIT);
      expect(capCount()).toBe(before + MINT_BATCH_LIMIT);
      expect(capCount()).toBeLessThanOrEqual(POOL_CAP);

      psqlMust(dbUrl, RESET_POOL);
    },
    90_000,
  );

  // ── 5. Two scalers, one pool ──────────────────────────────────────────────

  it.skipIf(!live)(
    "rule 3: a second scaler blocks on the advisory lock and then sees the first one's mint",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      seedReceives(
        dbUrl,
        Array.from({ length: 18 }, (_v, i) => ({ operationId: OP(700 + i) })),
      );
      // Leave room for exactly one batch, so a second unserialised batch WOULD cross the cap.
      const headroom = MINT_BATCH_LIMIT;
      const fillTo = POOL_CAP - headroom - SEEDED_TOTAL;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ${Array.from({ length: fillTo }, (_v, i) => MINTED(700 + i))
             .map(
               (id, i) =>
                 `('${id}', (SELECT node_id FROM wallets LIMIT 1), '${"A".repeat(38)}RAC${String(i).padStart(2, "0")}=', 'node_generated', 'AVAILABLE')`,
             )
             .join(",")};`,
      );
      expect(capCount()).toBe(POOL_CAP - headroom);

      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();

        const aResult = await runPoolScaleUp(a, { limits: LIMITS, mint: mintingPort(300).mint });
        expect(aResult.plan.mintCount).toBe(MINT_BATCH_LIMIT);

        // B asks for its plan while A still holds the transaction-scoped lock. It must not
        // resolve until A commits — that is the serialisation under test, so the promise is
        // deliberately not awaited yet.
        const bPlan = planPoolScaleUp(b, LIMITS);
        let bSettled = false;
        void bPlan.then(() => {
          bSettled = true;
        });
        // Long enough that "not settled" means "waiting on the lock", not "the query has not
        // reached the server yet" — a setImmediate tick would pass vacuously.
        await new Promise((r) => setTimeout(r, 400));
        expect(bSettled).toBe(false);

        await a.commit();
        const planB = await bPlan;

        // B now reads the pool INCLUDING A's five wallets, so headroom is gone.
        expect(planB.capCount).toBe(POOL_CAP);
        expect(planB.mintCount).toBe(0);
        await b.commit();
      } finally {
        a.stop();
        b.stop();
      }

      expect(capCount()).toBe(POOL_CAP);

      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
    },
    120_000,
  );

  it.skipIf(!live)(
    "negative control: two scalers planning from counts read BEFORE the lock both mint and cross the cap",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      seedReceives(
        dbUrl,
        Array.from({ length: 18 }, (_v, i) => ({ operationId: OP(800 + i) })),
      );
      const headroom = MINT_BATCH_LIMIT;
      const fillTo = POOL_CAP - headroom - SEEDED_TOTAL;
      psqlMust(
        dbUrl,
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
           VALUES ${Array.from({ length: fillTo }, (_v, i) => MINTED(800 + i))
             .map(
               (id, i) =>
                 `('${id}', (SELECT node_id FROM wallets LIMIT 1), '${"A".repeat(38)}NEG${String(i).padStart(2, "0")}=', 'node_generated', 'AVAILABLE')`,
             )
             .join(",")};`,
      );
      const start = capCount();
      expect(start).toBe(POOL_CAP - headroom);

      // Both scalers read the SAME pre-lock count — the mistake `planPoolScaleUp` forbids by
      // taking the lock before it counts.
      const staleCap = start;
      const staleTarget = poolTargetTotal(18, POOL_CAP);
      const staleBatch = computeMintCount({
        target: staleTarget,
        capCount: staleCap,
        poolCapTotal: POOL_CAP,
      });
      expect(staleBatch).toBe(MINT_BATCH_LIMIT);

      const a = new PsqlSessionExecutor(dbUrl);
      const b = new PsqlSessionExecutor(dbUrl);
      try {
        a.start();
        b.start();
        await a.begin();
        await b.begin();
        const portA = mintingPort(400);
        const portB = mintingPort(500);
        for (let i = 0; i < staleBatch; i += 1) await portA.mint(a, i);
        for (let i = 0; i < staleBatch; i += 1) await portB.mint(b, i);
        await a.commit();
        await b.commit();
      } finally {
        a.stop();
        b.stop();
      }

      // The cap IS breached — which is exactly why the lock-then-count sequence above is
      // load-bearing and not decoration.
      expect(capCount()).toBe(POOL_CAP + MINT_BATCH_LIMIT);
      expect(capCount()).toBeGreaterThan(POOL_CAP);

      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
    },
    120_000,
  );

  // ── 6. Counts the scaler and the admission path must agree on ─────────────

  it.skipIf(!live)(
    "the scaler's available count equals the set the allocator's own predicate admits",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `UPDATE wallets SET state = 'PINNED' WHERE id = '${pool.eligible[0]}';`);
      const releasedOp = OP(899);
      seedReceive(dbUrl, releasedOp);
      psqlMust(
        dbUrl,
        `INSERT INTO operation_wallets (operation_id, wallet_id, operation_role)
           VALUES ('${releasedOp}', '${pool.eligible[1]}', 'RECEIVER');
         INSERT INTO receive_release_proofs (
           id, operation_id, release_kind, t0_observation_id, fresh_observation_id,
           proof_manifest_text, proof_manifest_sha256, released_at
         ) VALUES (
           '${OP(898)}', '${releasedOp}', 'EXPIRED_T0_UNCHANGED',
           '${OP(897)}', '${OP(896)}', '{}', '${"a".repeat(64)}', now()
         );`,
      );

      const enumerated = RECEIVE_ALLOCATOR_STATEMENTS.SELECT_ELIGIBLE_WALLET.replace(
        " FOR UPDATE SKIP LOCKED LIMIT 1",
        "",
      );
      const admitted = (await db.query<{ id: string }>(enumerated)).rows.map((r) => r.id);
      const counted = Number(
        (await db.query<{ available_count: number }>(POOL_SCALER_STATEMENTS.COUNT_AVAILABLE_WALLETS))
          .rows[0]?.available_count,
      );

      expect(counted).toBe(admitted.length);
      expect(counted).toBe(ELIGIBLE - 2);
      expect(admitted).not.toContain(pool.eligible[1]);
      // The resident negatives are counted by neither, and by the cap count by both.
      expect(admitted).not.toContain(pool.unverified[0]);
      expect(admitted).not.toContain(pool.imported[0]);
      expect(capCount()).toBeGreaterThan(counted);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "open_sessions counts an assigned pre-T0 receive once, as a lease — not twice",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const assigned = OP(900);
      const queued = OP(901);
      seedReceive(dbUrl, assigned);
      seedReceive(dbUrl, queued);

      const outcome = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: assigned, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(outcome.kind).toBe("ASSIGNED");

      // The operations CHECK keeps receiver_wallet_id NULL until expiry and T0 exist, so the assigned
      // receive still reads NULL there — the trap this count has to avoid.
      expect(
        countRows(dbUrl, "operations", `id = '${assigned}' AND receiver_wallet_id IS NULL`),
      ).toBe(1);

      expect(await countUnassignedReceives(db)).toBe(1);
      expect(await countOpenSessions(db)).toBe(2); // one lease + one genuinely queued receive

      // Negative control: the naive predicate the frozen contract SQL spells counts the assigned
      // receive as queued too, inflating open_sessions to 3 and the provisioning target with it.
      const naiveQueued = Number(
        psqlMust(
          dbUrl,
          `SELECT count(*)::int FROM operations
            WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED' AND receiver_wallet_id IS NULL;`,
        ).trim(),
      );
      expect(naiveQueued).toBe(2);
      expect(1 + naiveQueued).toBe(3);
      expect(poolTargetTotal(3, POOL_CAP)).toBeGreaterThanOrEqual(poolTargetTotal(2, POOL_CAP));
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  // ── 7. Queue-age expiry (step 5) ────────────────────────────────────

  it.skipIf(!live)(
    "step 5: only receives past RECEIVE_QUEUE_MAX_WAIT are selected, in (created_at, id) sequence",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Two aged receives created in the SAME clock instant, so only the id tiebreak makes the
      // sequence total; one aged-but-younger; one fresh.
      const aged = `now() - interval '90 seconds'`;
      seedReceives(dbUrl, [
        { operationId: OP(1002), createdAtSql: aged },
        { operationId: OP(1001), createdAtSql: aged },
        { operationId: OP(1003), createdAtSql: `now() - interval '45 seconds'` },
        { operationId: OP(1004), createdAtSql: `now() - interval '5 seconds'` },
      ]);

      const expired = await selectQueueExpiredReceives(db, { limits: LIMITS });
      expect(expired.map((e) => e.operationId)).toEqual([OP(1001), OP(1002), OP(1003)]);
      // Strict exceed: selected rows must be past the bound, never merely at it.
      expect(expired.every((e) => e.waitedSecs > MAX_WAIT_SECS)).toBe(true);
      expect(expired.every((e) => isReceiveExpired(e.waitedSecs * 1000))).toBe(true);
      // Deterministic: the two same-instant receives come back in id sequence, which is NOT the
      // sequence they were inserted in.
      expect(expired[0]!.operationId).toBe(OP(1001));

      // Every selected receive is one that never got a wallet: no lease, no RECEIVER attachment.
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(0);
      expect(countRows(dbUrl, "operation_wallets")).toBe(0);
      expect(countRows(dbUrl, "wallets", "state <> 'AVAILABLE'")).toBe(0);

      // A shorter max wait selects strictly more; a longer one strictly fewer. Deterministic in
      // the parameter, not just in the sort.
      expect(
        (await selectQueueExpiredReceives(db, { limits: { ...LIMITS, receiveQueueMaxWaitSecs: 1 } }))
          .length,
      ).toBe(4);
      expect(
        (
          await selectQueueExpiredReceives(db, {
            limits: { ...LIMITS, receiveQueueMaxWaitSecs: 3600 },
          })
        ).length,
      ).toBe(0);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 5: exact max-wait bound is NOT expired; one tick past is",
    async () => {
      // At waited == RECEIVE_QUEUE_MAX_WAIT the frozen isReceiveExpired
      // returns false and promotion still assigns. The scaler SQL must agree (strict `<`
      // / age > bound), not the inclusive `<=` that would fork money-path terminal vs assign.
      //
      // Seed + select share one PG transaction so `now()` is the transaction start timestamp
      // (stable) and equality / one-tick offsets are exact against the same clock.
      psqlMust(dbUrl, RESET_POOL);
      const atBound = OP(1050);
      const oneTickPast = OP(1051);
      const oneTickUnder = OP(1052);

      const emitted: string[] = [];
      const result = await withTx(dbUrl, async (tx) => {
        await insertReceiveOnTx(
          atBound,
          `now() - make_interval(secs => ${MAX_WAIT_SECS})`,
        )(tx);
        await insertReceiveOnTx(
          oneTickPast,
          // 1ms past the bound — smallest practical tick that still exceeds max-wait.
          `now() - make_interval(secs => ${MAX_WAIT_SECS}) - interval '1 millisecond'`,
        )(tx);
        await insertReceiveOnTx(
          oneTickUnder,
          `now() - make_interval(secs => ${MAX_WAIT_SECS}) + interval '1 millisecond'`,
        )(tx);

        const selected = await selectQueueExpiredReceives(tx, { limits: LIMITS });
        expect(selected.map((e) => e.operationId)).toEqual([oneTickPast]);
        expect(selected.map((e) => e.operationId)).not.toContain(atBound);
        expect(selected.map((e) => e.operationId)).not.toContain(oneTickUnder);

        // Fractional ages (ms) under the same tx clock — parity with isReceiveExpired.
        // Note: SELECT's waited_secs is EPOCH::int (truncated); sub-second past-bound ages
        // still select correctly via timestamptz `<`, which is the load-bearing predicate.
        // (psql harness binds only scalar params — three scalar probes, not uuid[].)
        const ageMsOf = async (id: string): Promise<number> => {
          const r = await tx.query<{ age_ms: number }>(
            `SELECT (EXTRACT(EPOCH FROM (now() - created_at)) * 1000)::float8 AS age_ms
               FROM operations WHERE id = $1::uuid`,
            [id],
          );
          return Number(r.rows[0]!.age_ms);
        };
        const ageAtBound = await ageMsOf(atBound);
        const agePast = await ageMsOf(oneTickPast);
        const ageUnder = await ageMsOf(oneTickUnder);
        expect(ageAtBound).toBe(MAX_WAIT_SECS * 1000);
        expect(agePast).toBe(MAX_WAIT_SECS * 1000 + 1);
        expect(ageUnder).toBe(MAX_WAIT_SECS * 1000 - 1);
        expect(isReceiveExpired(ageAtBound)).toBe(false);
        expect(isReceiveExpired(agePast)).toBe(true);
        expect(isReceiveExpired(ageUnder)).toBe(false);
        // Selection set ≡ { id | isReceiveExpired(age_ms) } over the three seeds.
        const ageById = new Map<string, number>([
          [atBound, ageAtBound],
          [oneTickPast, agePast],
          [oneTickUnder, ageUnder],
        ]);
        const expiredByContract = [atBound, oneTickPast, oneTickUnder].filter((id) =>
          isReceiveExpired(ageById.get(id)!),
        );
        expect(selected.map((e) => e.operationId)).toEqual(expiredByContract);

        return expireQueueAgedReceives(tx, {
          limits: LIMITS,
          emitExpired: async (_db, p) => {
            emitted.push(p.operationId);
          },
        });
      });

      expect(result.expired.map((e) => e.operationId)).toEqual([oneTickPast]);
      expect(emitted).toEqual([oneTickPast]);
      expect(countRows(dbUrl, "operations", `id = '${oneTickPast}' AND status = 'EXPIRED'`)).toBe(
        1,
      );
      expect(countRows(dbUrl, "operations", `id = '${atBound}' AND status = 'CREATED'`)).toBe(1);
      expect(countRows(dbUrl, "operations", `id = '${oneTickUnder}' AND status = 'CREATED'`)).toBe(
        1,
      );
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 5: an assigned receive is never selected for queue-age expiry, however old",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const assigned = OP(1100);
      seedReceive(dbUrl, assigned, `now() - interval '900 seconds'`);
      await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: assigned, ownerInstanceId: OWNER, leases: LEASES }),
      );

      // It reads as `receiver_wallet_id IS NULL` and it is very old, so the naive predicate
      // WOULD expire a receive that holds a live lease on a pinned wallet — a one-in-flight-per-wallet
      // hazard, not merely a metric error.
      expect(await selectQueueExpiredReceives(db, { limits: LIMITS })).toEqual([]);
      const naive = Number(
        psqlMust(
          dbUrl,
          `SELECT count(*)::int FROM operations
            WHERE kind = 'RECEIVE_EXTERNAL' AND status = 'CREATED' AND receiver_wallet_id IS NULL
              AND created_at < now() - make_interval(secs => ${MAX_WAIT_SECS});`,
        ).trim(),
      );
      expect(naive).toBe(1);
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(1);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 5 / queue-age expiry flips CREATED→EXPIRED, emits operation.expired, touches no wallet",
    async () => {
      // made the walletless EXPIRED row representable. This is the full step 5
      // path: select → guarded flip → emit. No wallet/lease rows exist before or after.
      psqlMust(dbUrl, RESET_POOL);
      const aged = `now() - interval '90 seconds'`;
      seedReceives(dbUrl, [
        { operationId: OP(1201), createdAtSql: aged },
        { operationId: OP(1202), createdAtSql: aged },
        { operationId: OP(1203), createdAtSql: `now() - interval '5 seconds'` },
      ]);
      // An assigned (pre-T0) receive that is very old must never be expired by this path.
      const assigned = OP(1204);
      seedReceive(dbUrl, assigned, `now() - interval '900 seconds'`);
      await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: assigned, ownerInstanceId: OWNER, leases: LEASES }),
      );

      const emitted: { operationId: string; waitedSecs: number }[] = [];
      const emitExpired: EmitOperationExpired = async (_db, p) => {
        emitted.push({ operationId: p.operationId, waitedSecs: p.waitedSecs });
      };

      const result = await withTx(dbUrl, (tx) =>
        expireQueueAgedReceives(tx, { limits: LIMITS, emitExpired }),
      );

      expect(result.expired.map((e) => e.operationId)).toEqual([OP(1201), OP(1202)]);
      expect(result.skipped).toEqual([]);
      expect(emitted.map((e) => e.operationId)).toEqual([OP(1201), OP(1202)]);
      // Strict exceed — parity with isReceiveExpired, not inclusive >=.
      expect(emitted.every((e) => e.waitedSecs > MAX_WAIT_SECS)).toBe(true);
      expect(emitted.every((e) => isReceiveExpired(e.waitedSecs * 1000))).toBe(true);

      expect(countRows(dbUrl, "operations", `id = '${OP(1201)}' AND status = 'EXPIRED'`)).toBe(1);
      expect(countRows(dbUrl, "operations", `id = '${OP(1202)}' AND status = 'EXPIRED'`)).toBe(1);
      expect(countRows(dbUrl, "operations", `id = '${OP(1203)}' AND status = 'CREATED'`)).toBe(1);
      expect(countRows(dbUrl, "operations", `id = '${assigned}' AND status = 'CREATED'`)).toBe(1);
      // Walletless EXPIRED: no receiver_wallet_id, no expiry, no T0; terminal_at stamped (ZTR-1249).
      expect(
        countRows(
          dbUrl,
          "operations",
          `id IN ('${OP(1201)}','${OP(1202)}')
             AND receiver_wallet_id IS NULL
             AND expiry_unix_time_secs IS NULL
             AND t0_observation_id IS NULL
             AND terminal_at IS NOT NULL`,
        ),
      ).toBe(2);
      // Zero wallet/lease churn from the expiry path itself — the assigned receive's one lease
      // is the only lease row, and no scaler statement may release it.
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(1);
      expect(countRows(dbUrl, "operation_wallets")).toBe(1);

      // Idempotent: a second pass finds nothing still past-wait and CREATED.
      const again = await withTx(dbUrl, (tx) =>
        expireQueueAgedReceives(tx, { limits: LIMITS, emitExpired }),
      );
      expect(again.expired).toEqual([]);
      expect(emitted).toHaveLength(2);

      // row_version bumped exactly once per expired row (1 → 2).
      const rv = Number(
        psqlMust(dbUrl, `SELECT row_version FROM operations WHERE id = '${OP(1201)}';`).trim(),
      );
      expect(rv).toBe(2);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  it.skipIf(!live)(
    "step 5: guarded UPDATE skips a receive that left the queued set between select and flip",
    async () => {
      // The race window: select sees the receive as queue-aged, then assignment wins, then the
      // expire flip must match zero rows (queued predicate no longer holds) and must not emit.
      psqlMust(dbUrl, RESET_POOL);
      const op = OP(1210);
      seedReceive(dbUrl, op, `now() - interval '900 seconds'`);
      const selected = await selectQueueExpiredReceives(db, { limits: LIMITS });
      expect(selected.map((e) => e.operationId)).toEqual([op]);

      await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId: op, ownerInstanceId: OWNER, leases: LEASES }),
      );

      // Drive the flip statement alone — what expireQueueAgedReceives does per selected id
      // so a zero-row RETURNING is the load-bearing guard, not "select found nothing".
      const flipped = await db.query(
        POOL_SCALER_STATEMENTS.EXPIRE_QUEUE_AGED_RECEIVE,
        [op],
      );
      expect(flipped.rowCount ?? 0).toBe(0);
      expect(countRows(dbUrl, "operations", `id = '${op}' AND status = 'CREATED'`)).toBe(1);
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(1);
      // Full pass is a no-op too (select no longer returns the assigned receive).
      const emitted: string[] = [];
      const result = await withTx(dbUrl, (tx) =>
        expireQueueAgedReceives(tx, {
          limits: LIMITS,
          emitExpired: async (_db, p) => {
            emitted.push(p.operationId);
          },
        }),
      );
      expect(result.expired).toEqual([]);
      expect(emitted).toEqual([]);
      psqlMust(dbUrl, RESET_POOL);
    },
    60_000,
  );

  // ── 8. Pressure never releases a wallet ───────────────────────────────────

  it.skipIf(!live)(
    "starving the pool never returns a pinned or quarantined wallet to AVAILABLE",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      // Take real leases on two wallets, quarantine a third, and fill the rest to the cap — the
      // worst pressure the node can be under: no capacity, no available wallet, a full queue.
      const leased = [OP(1300), OP(1301)];
      seedReceives(dbUrl, leased.map((operationId) => ({ operationId })));
      const held: string[] = [];
      for (const operationId of leased) {
        const outcome = await withTx(dbUrl, (tx) =>
          assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
        );
        expect(outcome.kind).toBe("ASSIGNED");
        if (outcome.kind === "ASSIGNED") held.push(outcome.walletId);
      }
      const quarantined = pool.eligible[ELIGIBLE - 1]!;
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'observation anomaly'
          WHERE id = '${quarantined}';
         UPDATE wallets SET state = 'PINNED' WHERE state = 'AVAILABLE';`,
      );
      seedReceives(
        dbUrl,
        Array.from({ length: 12 }, (_v, i) => ({
          operationId: OP(1310 + i),
          createdAtSql: `now() - interval '600 seconds'`,
        })),
      );

      const leaseRowsBefore = countRows(dbUrl, "wallet_active_leases");
      expect(leaseRowsBefore).toBe(2);

      // Hammer every pressure-facing surface repeatedly. None of them has a release path.
      for (let pass = 0; pass < 3; pass += 1) {
        await withTx(dbUrl, (tx) =>
          runPoolScaleUp(tx, { limits: LIMITS, mint: mintingPort(600 + pass * 10).mint }),
        );
        await selectQueueExpiredReceives(db, { limits: LIMITS });
        await collectPoolPressureMetrics(db, LIMITS);
      }

      for (const walletId of held) expect(walletState(dbUrl, walletId)).toBe("PINNED");
      expect(walletState(dbUrl, quarantined)).toBe("QUARANTINED");
      expect(countRows(dbUrl, "wallet_active_leases")).toBe(leaseRowsBefore);
      expect(countRows(dbUrl, "wallets", "state = 'AVAILABLE'")).toBe(
        countRows(dbUrl, "wallets", `id::text LIKE 'f0000000-%'`),
      );
      psqlMust(dbUrl, RESET_POOL);
      psqlMust(dbUrl, `DELETE FROM wallets WHERE id::text LIKE 'f0000000-%';`);
    },
    120_000,
  );

  // ── 9. Live pressure metrics ────────────────────────────────────

  it.skipIf(!live)(
    "the pressure counters are read from the database on every call and move with it",
    async () => {
      psqlMust(dbUrl, RESET_POOL);
      const idle = await collectPoolPressureMetrics(db, LIMITS);
      expect(idle.capCount).toBe(SEEDED_TOTAL);
      expect(idle.capUtilizationPercent).toBe(Math.floor((SEEDED_TOTAL * 100) / POOL_CAP));
      expect(idle.availableWalletCount).toBe(ELIGIBLE);
      expect(idle.pinnedWalletCount).toBe(0);
      expect(idle.attentionWalletCount).toBe(0);
      expect(idle.retiredWalletCount).toBe(0);
      expect(idle.queueDepth).toBe(0);
      expect(idle.oldestQueuedAgeSecs).toBe(0);
      expect(idle.receiveWindowLeaseCount).toBe(0);
      expect(idle.openSessions).toBe(0);
      expect(idle.poolTargetTotal).toBe(POOL_FLOOR);

      // Put the pool under load: one real lease, one quarantine, one retirement, an aged queue.
      const operationId = OP(1400);
      seedReceive(dbUrl, operationId);
      const assignment = await withTx(dbUrl, (tx) =>
        assignReceiveWallet(tx, { operationId, ownerInstanceId: OWNER, leases: LEASES }),
      );
      expect(assignment.kind).toBe("ASSIGNED");
      psqlMust(
        dbUrl,
        `UPDATE wallets SET state = 'QUARANTINED', quarantine_reason = 'unexpected head movement'
          WHERE id = '${pool.eligible[1]}';
         UPDATE wallets SET state = 'RETIRED', retired_at = now() WHERE id = '${pool.eligible[2]}';`,
      );
      seedReceives(
        dbUrl,
        Array.from({ length: 4 }, (_v, i) => ({
          operationId: OP(1410 + i),
          createdAtSql: `now() - interval '${120 + i} seconds'`,
        })),
      );

      const loaded = await collectPoolPressureMetrics(db, LIMITS);
      expect(loaded.capCount).toBe(SEEDED_TOTAL);
      expect(loaded.pinnedWalletCount).toBe(1);
      expect(loaded.attentionWalletCount).toBe(1);
      expect(loaded.retiredWalletCount).toBe(1);
      expect(loaded.availableWalletCount).toBe(ELIGIBLE - 3);
      expect(loaded.pinnedRatioPercent).toBe(Math.floor((1 * 100) / SEEDED_TOTAL));
      expect(loaded.queueDepth).toBe(4);
      expect(loaded.oldestQueuedAgeSecs).toBeGreaterThanOrEqual(123);
      expect(loaded.receiveWindowLeaseCount).toBe(1);
      expect(loaded.oldestReceiveLeaseAgeSecs).toBeGreaterThanOrEqual(0);
      expect(loaded.openSessions).toBe(5);
      expect(loaded.poolTargetTotal).toBe(poolTargetTotal(5, POOL_CAP));

      // A retired wallet still occupies the cap — retirement never restores capacity (
      // rule 2 / rule 5).
      expect(loaded.capUtilizationPercent).toBe(idle.capUtilizationPercent);
      psqlMust(dbUrl, RESET_POOL);
    },
    90_000,
  );
});
